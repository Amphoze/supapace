package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// Job containers run the backup worker image for one job of a subject (a
// project or the control plane): no capability, no new privileges, the
// platform's seccomp profile, a read-only root and a private /tmp, no
// network but the backup network for the kinds that talk to the object
// store, and only the mounts of their kind. Every source is checked before
// anything is launched. A container outlives its client and the daemon, so
// a subject's leftovers are removed before its next job starts, and every
// job container is removed at each daemon start (KillJobs("")).
var (
	lstat          = os.Lstat
	ensureFetchDir = nodefs.EnsureFetchDir
)

const (
	labelJob  = "supapace.job"
	labelKind = "supapace.kind"

	jobStopGrace = 10               // seconds between the stop signal and the kill
	jobCleanup   = 60 * time.Second // bound of the removals after a job, whatever the caller's context
	jobStderrMax = 4 << 10
	// jobDNS answers nothing: the embedded resolver forwards a lookup made in
	// a networked job there instead of to the node's own resolvers.
	jobDNS = "192.0.2.1"
)

// ErrHostState: a mount source is missing, a link, of the wrong type or of
// another owner. Nothing was launched or created.
var ErrHostState = errors.New("agent: a job's mount source is not as the platform made it")

// jobKind is what the table of users, mounts, networks and secrets gives one kind.
type jobKind struct {
	mem, pids int // MiB, processes
	tmpfs     string
	network   bool // the backup network (else none) and the credential file
	pass      bool // the stanza passphrase in the environment file
	mounts    []mountKind
}

type mountKind struct {
	src    string // data, sock, spool, rspool, repo, fetch, index
	target string
	ro     bool
}

var (
	mData   = func(ro bool) mountKind { return mountKind{"data", "/var/lib/postgresql/data", ro} }
	mSock   = mountKind{"sock", "/var/run/postgresql", false}
	mSpool  = mountKind{"spool", "/spool", false}
	mRspool = mountKind{"rspool", "/rspool", false}
	mRepo   = func(ro bool) mountKind { return mountKind{"repo", "/repo", ro} }
	mFetch  = func(ro bool) mountKind { return mountKind{"fetch", "/fetch", ro} }
	mIndex  = mountKind{"index", "/index", true}

	backupMounts = []mountKind{mData(true), mSock, mSpool, mRepo(false)}

	jobKinds = map[string]jobKind{
		"push":          {512, 256, "128m", false, true, []mountKind{mSpool, mRepo(false)}},
		"stanza-create": {512, 256, "128m", false, true, backupMounts},
		"backup":        {512, 256, "128m", false, true, backupMounts},
		"check":         {512, 256, "128m", false, true, backupMounts},
		"restore":       {512, 256, "128m", false, true, []mountKind{mData(false), mRepo(true)}},
		"serve":         {512, 256, "128m", false, true, []mountKind{mData(true), mRspool, mRepo(true)}},
		"seed":          {128, 64, "16m", false, false, []mountKind{mRepo(false), mFetch(true)}},
		"replicate":     {0, 64, "64m", true, false, []mountKind{mRepo(true), mIndex}},
		"fetch":         {256, 64, "64m", true, false, []mountKind{mFetch(false)}},
		"probe":         {256, 64, "64m", true, false, nil},
	}

	// envNameRE: the caller's environment names; the launcher sets GOMEMLIMIT
	// itself, and nothing else (TMPDIR, LD_PRELOAD, PGBACKREST_*) can be passed.
	envNameRE  = regexp.MustCompile(`^SUPAPACE_[A-Z0-9_]{1,100}$`)
	envValueRE = regexp.MustCompile(`^[ -~]*$`)
	fileNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// secretWords: a networked job's program refuses an environment name
	// holding one of them; the launcher never sends one.
	secretWords = []string{"PASS", "SECRET", "KEY", "TOKEN"}
)

const passName = "PGBACKREST_REPO1_CIPHER_PASS"

// job is a checked JobSpec with what its container is called and given.
type job struct {
	JobSpec
	k         jobKind
	name, ref string // container name; its supapace.ref label
	base      string // its files under JobsDir(): <base>/, <base>.env, <base>.cred
	cmd       []string
	pd, rd    string // the subject's project and repository directories
	sock      string
	uid, gid  int    // the tree's owner
	user      string // --user
	group     string // --group-add, "" none
	memMB     int
}

// checkJob refuses a spec the table does not allow, before anything happens.
func (a *Agent) checkJob(j JobSpec) (job, error) {
	if j.Kind == "recover" {
		return job{}, errors.New("agent: recover is not a container job")
	}
	k, ok := jobKinds[j.Kind]
	if !ok {
		return job{}, fmt.Errorf("agent: unknown job kind %q", j.Kind)
	}
	x := job{JobSpec: j, k: k, uid: j.UID, gid: j.GID, memMB: k.mem}
	switch {
	case j.Kind == "probe":
		if j.Subject != "projects" && j.Subject != nodecfg.ControlPlaneSubject {
			return job{}, fmt.Errorf("agent: a probe is of the bucket projects or cp, not %q", j.Subject)
		}
		x.ref = "probe-" + j.Subject
		x.name, x.base = "job-"+x.ref, x.ref
	case j.Subject == nodecfg.ControlPlaneSubject:
		if j.UID != nodecfg.ControlPlaneUID || j.GID != nodecfg.ControlPlaneUID {
			return job{}, fmt.Errorf("agent: a control-plane job runs at %d:%d", nodecfg.ControlPlaneUID, nodecfg.ControlPlaneUID)
		}
		x.pd, x.sock = a.p.CPProjectDir(), filepath.Join(a.p.CPDir(), "sock")
	default:
		if err := checkRef(j.Subject); err != nil {
			return job{}, err
		}
		if !projectID(j.UID) || !projectID(j.GID) {
			return job{}, fmt.Errorf("agent: %s: %d:%d are not project ids", j.Subject, j.UID, j.GID)
		}
		x.pd = a.p.ProjectDir(j.Subject)
		x.sock = filepath.Join(x.pd, "sock")
	}
	if j.Kind != "probe" {
		if j.ID <= 0 {
			return job{}, errors.New("agent: a job needs its id")
		}
		x.ref, x.name, x.base = j.Subject, "job-"+j.Subject+"-"+j.Kind, strconv.FormatInt(j.ID, 10)
		x.rd = a.p.RepoDir(j.Subject)
	}
	if j.Deadline <= 0 {
		return job{}, errors.New("agent: a job needs a deadline")
	}
	in, err := jobio.ParseInput(j.Input)
	if err != nil {
		return job{}, err
	}
	// The programs take the subject and the job from the input, the launcher
	// the mounts from the spec: they must be of one job.
	if in.Kind != j.Kind || in.Subject != j.Subject || in.Job != j.ID {
		return job{}, fmt.Errorf("agent: the input is of job %d, kind %q, subject %.32q", in.Job, in.Kind, in.Subject)
	}
	x.cmd = []string{"job", j.Kind}
	if k.network {
		x.user = fmt.Sprintf("%d:%d", nodecfg.ReplicatorUID, nodecfg.ReplicatorUID)
		mode := j.Kind
		if j.Kind != "probe" {
			x.group = strconv.Itoa(j.GID)
		}
		if j.Kind == "replicate" {
			if in.Repl == nil || in.Repl.Mode != "copy" && in.Repl.Mode != "rebuild" {
				return job{}, errors.New("agent: a replication job's input names no mode copy or rebuild")
			}
			mode = in.Repl.Mode
			x.memMB = bklimit.ReplMemMB(0)
			if j.MemMB != 0 {
				x.memMB = j.MemMB
			}
		}
		x.cmd = []string{"replicate", mode}
	} else {
		x.user = fmt.Sprintf("%d:%d", j.UID, j.GID)
	}
	return x, x.checkSecrets()
}

// checkSecrets: a passphrase only for the kinds that take one, a credential
// only for the networked kinds and always for them, nothing secret-like in
// a networked job's environment, every name and value one line of
// printable ASCII.
func (x job) checkSecrets() error {
	lines := 2 // one key pair; a probe holds the write pair, then the read-only pair
	if x.Kind == "probe" {
		lines = 4
	}
	switch {
	case x.MemMB < 0 || x.MemMB != 0 && (x.Kind != "replicate" || x.MemMB < 128):
		return errors.New("agent: a memory figure is for replication jobs only, 128 MiB or more")
	case x.k.network != (len(x.Cred) > 0):
		return fmt.Errorf("agent: a %s job with the wrong credential", x.Kind)
	case x.k.network && !credShape(x.Cred, lines):
		return fmt.Errorf("agent: a %s job's credential is not %d lines", x.Kind, lines)
	}
	for n := range x.SecretEnv {
		if !x.k.pass || n != passName {
			return fmt.Errorf("agent: a %s job takes no secret %.64q", x.Kind, n)
		}
	}
	for n, v := range x.Env {
		for _, w := range secretWords {
			if x.k.network && strings.Contains(strings.ToUpper(n), w) {
				return fmt.Errorf("agent: a networked job's environment holds %.64q", n)
			}
		}
		if !envNameRE.MatchString(n) || !envValueRE.MatchString(v) {
			return fmt.Errorf("agent: environment variable %.64q is not SUPAPACE_* with one line of printable text", n)
		}
	}
	for _, v := range x.SecretEnv {
		if !envValueRE.MatchString(v) {
			return errors.New("agent: a secret is not one line of printable text")
		}
	}
	for n := range x.Files {
		if !fileNameRE.MatchString(n) || n == "input.json" {
			return fmt.Errorf("agent: job file name %.64q", n)
		}
	}
	return nil
}

// credShape: access key, newline, secret key per pair, pairs separated by a
// newline, no final newline, no empty field.
func credShape(c []byte, lines int) bool {
	f := strings.Split(string(c), "\n")
	return len(f) == lines && !slices.Contains(f, "")
}

// goMemLimitMB is the Go runtime's soft limit given to every job program:
// the container's memory limit less 32 MiB, so that the collector works
// harder before the kernel kills the job. (A tool the program starts is not
// under it; the container's limit covers both.)
func goMemLimitMB(memMB int) int { return memMB - 32 }

func projectID(id int) bool { return id >= 65536 && id <= 1<<31-1 }

// source is one bind-mount source as the platform made it.
type source struct {
	path     string
	dir      bool
	uid, gid int
}

// checkSource: the path exists, is no link, is a directory (else a regular
// file) and is owned by uid:gid.
func checkSource(s source) error {
	fi, err := lstat(s.path)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrHostState, s.path, err)
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	switch {
	case s.dir && !fi.IsDir(), !s.dir && !fi.Mode().IsRegular():
		return fmt.Errorf("%w: %s is a %v", ErrHostState, s.path, fi.Mode().Type())
	case st == nil || int(st.Uid) != s.uid || int(st.Gid) != s.gid:
		return fmt.Errorf("%w: %s is not owned by %d:%d", ErrHostState, s.path, s.uid, s.gid)
	}
	return nil
}

// sources are the kind's mounts with what each source must be, then the
// executable's; the -v values in the same order.
func (a *Agent) sources(x job, exe string) ([]source, []string) {
	root := [2]int{os.Geteuid(), os.Getegid()}
	var srcs []source
	var vs []string
	for _, m := range x.k.mounts {
		s := source{dir: true, uid: x.uid, gid: x.gid}
		switch m.src {
		case "data", "spool", "rspool":
			s.path = filepath.Join(x.pd, m.src)
		case "sock":
			s.path = x.sock
		case "repo":
			s.path = filepath.Join(x.rd, "repo")
		case "fetch":
			s.path, s.uid = filepath.Join(x.rd, "fetch"), nodecfg.ReplicatorUID
		case "index":
			s = source{path: a.p.IndexFile(x.Subject), uid: root[0], gid: root[1]}
		}
		srcs = append(srcs, s)
		v := s.path + ":" + m.target
		if m.ro {
			v += ":ro"
		}
		vs = append(vs, v)
	}
	if x.k.network {
		vs = append(vs, filepath.Join(a.p.JobsDir(), x.base+".cred")+":/cred:ro")
	}
	srcs = append(srcs, source{path: exe, uid: root[0], gid: root[1]})
	return srcs, append(vs, exe+":/supapaced:ro", filepath.Join(a.p.JobsDir(), x.base)+":/job:ro")
}

// RunJob runs one job container to its end and returns what it left. The
// spec is checked against its kind, then every mount source, before
// anything is created; then the subject's leftover job containers are
// removed, the job's files written, and the container started detached.
// It is polled every second, killed and removed at its deadline, and
// stopped gracefully (the stop signal, the kill 10 s later) when ctx ends,
// its result then read as after any exit. The environment file, which
// holds the passphrase, is removed as soon as `docker run` returns; the
// job's directory and credential file go with the container.
func (a *Agent) RunJob(ctx context.Context, j JobSpec) (JobResult, error) {
	x, err := a.checkJob(j)
	if err != nil {
		return JobResult{}, err
	}
	if x.k.network && a.ContainmentFailed() {
		return JobResult{}, refuse(nil, "no networked job while the node's containment is not shown")
	}
	exe, err := daemonExe()
	if err != nil {
		return JobResult{}, fmt.Errorf("agent: own executable: %w", err)
	}
	srcs, vs := a.sources(x, exe)
	// A fetch job's fetch/ is made by root when absent, and only once every other
	// source has passed, so that a refusal leaves nothing made.
	fetch := ""
	if x.Kind == "fetch" {
		fetch = filepath.Join(x.rd, "fetch")
	}
	for _, s := range srcs {
		if s.path == fetch {
			continue
		}
		if err := checkSource(s); err != nil {
			return JobResult{}, err
		}
	}
	if fetch != "" {
		if err := ensureFetchDir(a.p, x.Subject, nodecfg.ReplicatorUID, x.gid); err != nil {
			return JobResult{}, err
		}
		if err := checkSource(source{path: fetch, dir: true, uid: nodecfg.ReplicatorUID, gid: x.gid}); err != nil {
			return JobResult{}, err
		}
	}
	if x.k.network {
		if err := a.EnsureBackupNetwork(ctx); err != nil {
			return JobResult{}, err
		}
	}
	if err := a.removeJobs(ctx, x.ref); err != nil {
		return JobResult{}, err
	}
	env, err := a.writeJobFiles(x)
	if err != nil {
		return JobResult{}, errors.Join(err, a.removeJobFiles(x.base))
	}
	_, err = dockerRun(ctx, a.jobArgs(x, env, vs)...)
	if rerr := os.Remove(env); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		err = errors.Join(err, rerr)
	}
	if err != nil {
		return JobResult{}, errors.Join(fmt.Errorf("agent: %s: %w", x.name, err), a.removeJob(ctx, x.name, x.base))
	}
	return a.awaitJob(ctx, x)
}

// writeJobFiles writes <base>/ (root 0755) with input.json and the spec's
// files (root 0444), <base>.env (root 0600) and, for a networked kind,
// <base>.cred (the replicator's, 0400), and checks the two it mounts as it
// checks every source. It returns the environment file's path.
func (a *Agent) writeJobFiles(x job) (string, error) {
	jd := a.p.JobsDir()
	if err := a.removeJobFiles(x.base); err != nil { // left by an earlier attempt
		return "", err
	}
	dir := filepath.Join(jd, x.base)
	if err := ensureDir(jd, 0o700, 0, 0); err != nil {
		return "", err
	}
	if err := ensureDir(dir, 0o755, 0, 0); err != nil {
		return "", err
	}
	files := maps.Clone(x.Files)
	if files == nil {
		files = map[string][]byte{}
	}
	files["input.json"] = x.Input
	for _, n := range slices.Sorted(maps.Keys(files)) {
		if err := writeFile(a.p, dir, n, files[n], 0o444, 0, 0); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	for _, m := range []map[string]string{x.Env, x.SecretEnv} {
		for _, n := range slices.Sorted(maps.Keys(m)) {
			b.WriteString(n + "=" + m[n] + "\n")
		}
	}
	if err := writeFile(a.p, jd, x.base+".env", []byte(b.String()), 0o600, 0, 0); err != nil {
		return "", err
	}
	mine := []source{{path: dir, dir: true, uid: os.Geteuid(), gid: os.Getegid()}}
	if x.k.network {
		if err := writeFile(a.p, jd, x.base+".cred", x.Cred, 0o400, nodecfg.ReplicatorUID, nodecfg.ReplicatorUID); err != nil {
			return "", err
		}
		mine = append(mine, source{path: filepath.Join(jd, x.base+".cred"), uid: nodecfg.ReplicatorUID, gid: nodecfg.ReplicatorUID})
	}
	for _, s := range mine {
		if err := checkSource(s); err != nil {
			return "", err
		}
	}
	return filepath.Join(jd, x.base+".env"), nil
}

// jobArgs is the `docker run` argv: the cluster's hardening flags with the
// kind's sizes, the labels, the network, the environment file, the mounts.
func (a *Agent) jobArgs(x job, env string, vs []string) []string {
	mem := strconv.Itoa(x.memMB) + "m"
	args := []string{"run", "-d", "--name", x.name, "--user", x.user}
	if x.group != "" {
		args = append(args, "--group-add", x.group)
	}
	args = append(args, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp="+a.seccompFile(),
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size="+x.k.tmpfs, "--memory", mem, "--memory-swap", mem, "--cpus", "1",
		"--pids-limit", strconv.Itoa(x.k.pids), "--ulimit", "core=0", "--ulimit", "nofile=65536:65536", "--no-healthcheck", "--ipc", "none",
		"--label", labelJob+"="+strconv.FormatInt(x.ID, 10), "--label", labelKind+"="+x.Kind, "--label", labelRef+"="+x.ref,
		"--label", labelRole+"=job")
	if x.k.network {
		args = append(args, "--network", nodecfg.BackupNetwork, "--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
			"--sysctl", "net.ipv4.ping_group_range=1 0", "--dns", jobDNS)
	} else {
		args = append(args, "--network", "none")
	}
	args = append(args, "--env-file", env, "-e", "GOMEMLIMIT="+strconv.Itoa(goMemLimitMB(x.memMB))+"MiB")
	for _, v := range vs {
		args = append(args, "-v", v)
	}
	return append(append(args, "--entrypoint", "/supapaced", "--", nodecfg.WorkerImage), x.cmd...)
}

// awaitJob polls the started container to its end (deadline: killed; ctx
// ended: stopped gracefully), reads its result and removes it.
func (a *Agent) awaitJob(ctx context.Context, x job) (JobResult, error) {
	dctx, cancel := context.WithTimeout(ctx, x.Deadline)
	defer cancel()
	code, err := waitTask(dctx, x.name)
	// The bound of what follows the job (stop, output, removal) starts when
	// the job has ended, however long it ran.
	cctx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), jobCleanup)
	defer ccancel()
	switch {
	case err == nil:
	case ctx.Err() != nil:
		if _, serr := dockerRun(cctx, "stop", "-t", strconv.Itoa(jobStopGrace), "--", x.name); serr != nil {
			return JobResult{}, errors.Join(serr, a.removeJob(ctx, x.name, x.base))
		}
		if code, err = waitTask(cctx, x.name); err != nil {
			return JobResult{}, errors.Join(err, a.removeJob(ctx, x.name, x.base))
		}
	case dctx.Err() != nil:
		return JobResult{TimedOut: true}, a.removeJob(ctx, x.name, x.base)
	default:
		return JobResult{}, errors.Join(fmt.Errorf("agent: %s: %w", x.name, err), a.removeJob(ctx, x.name, x.base))
	}
	res := JobResult{ExitCode: code}
	out, errOut, err := dockerRunOutput(cctx, "logs", "--", x.name)
	switch {
	case errors.Is(err, dockerx.ErrOutputTooLarge): // more than a job writes: no result
	case err != nil:
		return res, errors.Join(fmt.Errorf("agent: %s: output: %w", x.name, err), a.removeJob(ctx, x.name, x.base))
	default:
		res.Result = lastLine(out)
		res.Stderr = pgsock.Sanitize(errOut[max(0, len(errOut)-jobStderrMax):], jobStderrMax)
	}
	// An exited container writes nothing more: a good result is kept. A container
	// left by a failed removal is removed with the subject's leftovers before its
	// next job (removeJobs) and by KillJobs("") at the next daemon start.
	if err := a.removeJob(ctx, x.name, x.base); err != nil {
		slog.Warn("a job container was not removed", "container", x.name, "error", pgsock.Sanitize(err.Error(), 256))
	}
	if len(res.Result) == 0 && ctx.Err() != nil {
		return res, ctx.Err()
	}
	return res, nil
}

// lastLine is the last newline-terminated line of out, without its newline;
// nil when there is none, it is empty or longer than bklimit.ResultMax.
func lastLine(out string) []byte {
	i := strings.LastIndexByte(out, '\n')
	if i < 0 {
		return nil
	}
	line := out[strings.LastIndexByte(out[:i], '\n')+1 : i]
	if line == "" || len(line) > bklimit.ResultMax {
		return nil
	}
	return []byte(line)
}

// removeJob removes the container by name, shows it is gone, and removes
// its files; on its own bounded context, so that it runs after ctx ended.
func (a *Agent) removeJob(ctx context.Context, name, base string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), jobCleanup)
	defer cancel()
	_, err := dockerRun(ctx, "rm", "-f", "-v", "--", name)
	if err == nil {
		var c *dockerx.Container
		if c, err = dockerInspectContainer(ctx, name); err == nil && c != nil {
			err = fmt.Errorf("agent: %s still exists after its removal", name)
		}
	}
	return errors.Join(err, a.removeJobFiles(base))
}

// removeJobFiles removes <base>/, <base>.env and <base>.cred; absent is done.
func (a *Agent) removeJobFiles(base string) error {
	if base == "" {
		return nil
	}
	var errs []error
	for _, n := range []string{base, base + ".env", base + ".cred"} {
		errs = append(errs, os.RemoveAll(filepath.Join(a.p.JobsDir(), n)))
	}
	return errors.Join(errs...)
}

// jobBase is the file base of a listed job container, from its labels.
func jobBase(c dockerx.Container) (string, bool) {
	if strings.HasPrefix(c.Labels[labelRef], "probe-") {
		return c.Labels[labelRef], fileNameRE.MatchString(c.Labels[labelRef])
	}
	id, err := strconv.ParseInt(c.Labels[labelJob], 10, 64)
	return strconv.FormatInt(id, 10), err == nil && id > 0
}

// removeJobs removes every job container whose supapace.ref is ref ("":
// every one), whatever its kind and state, with its files.
func (a *Agent) removeJobs(ctx context.Context, ref string) error {
	cs, err := dockerListContainers(ctx, labelRole+"=job")
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range cs {
		if ref != "" && c.Labels[labelRef] != ref {
			continue
		}
		base, ok := jobBase(c)
		if !ok {
			base = "" // labels not ours: the container goes, no file is guessed
		}
		if err := a.removeJob(ctx, c.Name, base); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// KillJobs removes the job containers of subject (a ref, "cp", or a probe's
// "probe-<bucket role>") with their files; "" removes every job container,
// every recovery cluster (supapace.phase=R) and everything under JobsDir().
// Absent is done, so it can be repeated; a container that stays is an error.
func (a *Agent) KillJobs(ctx context.Context, subject string) error {
	if subject != "" && subject != nodecfg.ControlPlaneSubject && subject != "probe-projects" && subject != "probe-cp" {
		if err := checkRef(subject); err != nil {
			return err
		}
	}
	err := a.removeJobs(ctx, subject)
	if subject != "" || err != nil {
		return err
	}
	rs, err := dockerListContainers(ctx, labelPhase+"=R")
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range rs {
		if err := a.removeJob(ctx, c.Name, ""); err != nil {
			errs = append(errs, err)
		}
	}
	ents, err := os.ReadDir(a.p.JobsDir())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	for _, e := range ents {
		errs = append(errs, os.RemoveAll(filepath.Join(a.p.JobsDir(), e.Name())))
	}
	return errors.Join(errs...)
}

// SetReplicatorQuota sets the replicator's user quota on the repository
// filesystem (what its fetch/ directories may hold); 0 clears it.
func (a *Agent) SetReplicatorQuota(ctx context.Context, quotaMB int) error {
	return repoSetQuota(a.p.RepoRoot(), nodecfg.ReplicatorUID, quotaMB)
}
