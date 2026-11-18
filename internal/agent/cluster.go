package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

// Seams of the cluster sessions (tests replace them). The database server
// is untrusted: every session goes through pgsock (peer check, SCRAM with
// the platform's parameters, bounds), and what it answers decides nothing
// but this project's own step.
var (
	pgDial             = pgsock.Dial
	pgProcStart        = pgsock.ProcStart
	bootstrapRun       = bootstrap.Run
	bootstrapAssert    = bootstrap.Assert
	bootstrapAssertHBA = bootstrap.AssertHBA
	archiverFailures   = queryArchiverFailures

	readyPoll  = time.Second       // between two login attempts while a cluster starts
	phaseAWait = 120 * time.Second // the first-boot server must answer within this
	adoptRetry = time.Second       // before the one repeat of an adoption check whose read failed
)

// clusterHealthWait is the default bound of a phase-B start's health wait
// (Spec.HealthWait zero).
const clusterHealthWait = 120 * time.Second

var clusterBaseline = sync.OnceValues(bootstrap.LoadBaseline)

// clusterSpec checks what a cluster container is built from.
func (a *Agent) clusterSpec(s Spec) error {
	if err := s.valid(a.cfg); err != nil {
		return err
	}
	if s.UID <= 0 || s.GID <= 0 || s.MemMB <= 0 || s.Pids <= 0 {
		return fmt.Errorf("agent: %s: spec lacks the project's ids or limits", s.Ref)
	}
	return nil
}

// EnsureCluster advances the project's cluster by one phase and is
// idempotent:
//
//   - no state.json: first boot, phase A, only when Spec.FirstBoot is set
//     (a create); otherwise an error and nothing is touched. In the first
//     boot any pg-<ref> is removed, the platform files rendered, data/ wiped at the project's uid, then
//     a network-less start under the image's own pg_hba, bootstrap and a
//     blocking assertion; the container is stopped and removed and only then
//     is state.json written "A-done";
//   - "A-done": the first phase-B start — the container is started on
//     proj-<ref> with the platform's pg_hba, the assertion blocks, and
//     state.json becomes "B" with the postmaster's pid and start time;
//   - "B": a running container is adopted, untouched, only when its labels
//     (generation, epoch, phase, image, configuration hash recomputed from the
//     files on disk), state.json, its pid and that pid's start time all agree
//     (then CheckAdopted; on failure it is removed at once); anything else is
//     removed (a running networked container stopped with its grace period)
//     and started again, with no bootstrap and no assertion.
//
// Every start is create, the start gate, start (startCluster).
//
// Spec.HealthWait bounds the wait for a SCRAM login after a phase-B start or
// an adoption (zero: 120 s; negative: no wait). The first phase-B start
// always waits (zero or negative: 120 s): its blocking assertion needs a
// session.
func (a *Agent) EnsureCluster(ctx context.Context, s Spec) error {
	if err := a.clusterSpec(s); err != nil {
		return err
	}
	st, have, err := a.readState(s.Ref)
	if err != nil {
		return err
	}
	if err := checkState(st, have, s); err != nil {
		return err
	}
	if have {
		return a.clusterPhaseB(ctx, s, st) // the reader admits A-done and B only
	}
	if !s.FirstBoot {
		return fmt.Errorf("agent: %s: no state file, and this is not the project's create: refusing a first boot, which would empty its data directory", s.Ref)
	}
	return a.clusterPhaseA(ctx, s)
}

func (a *Agent) clusterPhaseA(ctx context.Context, s Spec) error {
	if err := a.removeCluster(ctx, s.Ref); err != nil {
		return err
	}
	if err := a.renderCluster(s); err != nil {
		return err
	}
	if err := a.wipeData(ctx, s); err != nil {
		return err
	}
	args, err := a.clusterRunArgs(s, false)
	if err != nil {
		return err
	}
	st, err := a.startCluster(ctx, s, args)
	if err != nil {
		return err
	}
	conn, err := a.waitCluster(ctx, s, st, phaseAWait, true)
	if err != nil {
		return err
	}
	err = bootstrapRun(ctx, conn, s.Secrets)
	if err == nil {
		err = a.blockingAssert(ctx, conn, s.Ref, false)
	}
	closeSession(conn)
	if err != nil {
		return fmt.Errorf("agent: %s: first boot: %w", s.Ref, err)
	}
	if err := a.StopCluster(ctx, s.Ref); err != nil {
		return err
	}
	return a.writeState(s.Ref, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
}

func (a *Agent) clusterPhaseB(ctx context.Context, s Spec, st State) error {
	first := st.Phase == PhaseADone
	c, err := dockerInspectContainer(ctx, clusterName(s.Ref))
	if err != nil {
		return err
	}
	if c != nil {
		if !first && a.clusterAdoptable(s, st, c) {
			err := a.CheckAdopted(ctx, s)
			if err != nil && readFailed(err) && !a.ContainmentFailed() {
				// A fact could not be read (a Docker hiccup): read once more
				// before removing a running cluster. A refusal is final.
				select {
				case <-ctx.Done():
				case <-time.After(adoptRetry):
				}
				err = a.CheckAdopted(ctx, s)
			}
			if err != nil {
				// Off its networks at once, no grace period: it just failed a
				// containment check.
				return a.removeRefusedCluster(ctx, s.Ref, err)
			}
			return a.waitHealthy(ctx, s, st, s.HealthWait)
		}
		// A running networked cluster gets its grace period; a first-boot
		// leftover or a container that is not running is removed at once.
		remove := a.removeCluster
		if c.Running && c.Labels[labelPhase] == "B" {
			remove = a.StopCluster
		}
		if err := remove(ctx, s.Ref); err != nil {
			return err
		}
	}
	if err := a.renderCluster(s); err != nil {
		return err
	}
	args, err := a.clusterRunArgs(s, true)
	if err != nil {
		return err
	}
	nst, err := a.startCluster(ctx, s, args)
	if err != nil {
		return err
	}
	if !first {
		if err := a.writeState(s.Ref, nst); err != nil {
			return err
		}
		return a.waitHealthy(ctx, s, nst, s.HealthWait)
	}
	// First phase-B start: nothing is recorded as B before the assertion,
	// so a crash here re-runs this start, assertion included.
	wait := s.HealthWait
	if wait <= 0 {
		wait = clusterHealthWait
	}
	conn, err := a.waitCluster(ctx, s, nst, wait, false)
	if err != nil {
		return err
	}
	err = a.blockingAssert(ctx, conn, s.Ref, true)
	closeSession(conn)
	if err != nil {
		return fmt.Errorf("agent: %s: first start: %w", s.Ref, err)
	}
	return a.writeState(s.Ref, nst)
}

// clusterAdoptable: the running container is the one state.json (phase B,
// the desired epoch: the caller's checks) describes, at the desired
// generation, image and configuration.
func (a *Agent) clusterAdoptable(s Spec, st State, c *dockerx.Container) bool {
	if !c.Running || st.Generation != s.Generation || st.PMPid != c.Pid {
		return false
	}
	args, err := a.clusterRunArgs(s, true)
	if err != nil {
		return false
	}
	want := a.clusterLabels(s, "B")
	want[labelConfig] = labelValue(args, labelConfig)
	for k, v := range want {
		if c.Labels[k] != v {
			return false
		}
	}
	start, err := pgProcStart(c.Pid)
	return err == nil && start == st.PMStart
}

// startCluster creates the container, passes the start gate — which then
// reads the very container about to start — and starts it with no other
// Docker call in between, then reads back its init process. A refusal (the
// gate, or its address held by another container at start) removes the
// created container, so nothing refused stays behind (in the first boot its
// recorded environment holds the throwaway password); any other failed
// start keeps it for its logs until the next ensure.
func (a *Agent) startCluster(ctx context.Context, s Spec, args []string) (State, error) {
	if _, err := dockerRun(ctx, args...); err != nil {
		return State{}, err
	}
	if err := a.CheckContainment(ctx, s); err != nil {
		return State{}, a.removeRefusedCluster(ctx, s.Ref, err)
	}
	if _, err := dockerRun(ctx, "start", "--", clusterName(s.Ref)); err != nil {
		if strings.Contains(err.Error(), "Address already in use") {
			return State{}, a.removeRefusedCluster(ctx, s.Ref, refuse(err, "start %s", clusterName(s.Ref)))
		}
		return State{}, err
	}
	c, err := dockerInspectContainer(ctx, clusterName(s.Ref))
	if err != nil {
		return State{}, err
	}
	if c == nil || !c.Running || c.Pid <= 1 {
		return State{}, fmt.Errorf("agent: %s is not running after docker start", clusterName(s.Ref))
	}
	start, err := pgProcStart(c.Pid)
	if err != nil {
		return State{}, fmt.Errorf("agent: %s: start time of its init: %w", clusterName(s.Ref), err)
	}
	return State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseB, PMPid: c.Pid, PMStart: start}, nil
}

// waitHealthy waits up to wait (zero: the default; negative: not at all)
// for a SCRAM login to the recorded postmaster.
func (a *Agent) waitHealthy(ctx context.Context, s Spec, st State, wait time.Duration) error {
	if wait < 0 {
		return nil
	}
	if wait == 0 {
		wait = clusterHealthWait
	}
	conn, err := a.waitCluster(ctx, s, st, wait, false)
	closeSession(conn)
	return err
}

// waitCluster logs in as supabase_admin to the recorded postmaster, retrying
// while the server is not ready (clusterNotReady) and the container still
// runs that process, for at most bound.
func (a *Agent) waitCluster(ctx context.Context, s Spec, st State, bound time.Duration, phaseA bool) (*pgx.Conn, error) {
	deadline := time.Now().Add(bound)
	tg := a.clusterTarget(s, st, phaseA)
	for {
		conn, err := pgDial(ctx, tg)
		if err == nil {
			return conn, nil
		}
		if !clusterNotReady(err, phaseA) {
			return nil, fmt.Errorf("agent: %s: %w", s.Ref, err)
		}
		c, ierr := dockerInspectContainer(ctx, clusterName(s.Ref))
		if ierr != nil {
			return nil, ierr
		}
		if c == nil || !c.Running || c.Pid != st.PMPid {
			return nil, fmt.Errorf("agent: %s exited before it answered: %w", clusterName(s.Ref), err)
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("agent: %s did not answer within %v: %w", clusterName(s.Ref), bound, err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(readyPoll):
		}
	}
}

// clusterNotReady says whether a failed login means "not ready yet": no
// socket, or one nobody accepts on yet, or the server still starting; in
// phase A also a peer other than the init (the image's temporary server
// during initialisation). Any refusal of the platform's terms is a failure.
func clusterNotReady(err error, phaseA bool) bool {
	var se *pgsock.ServerError
	switch {
	case errors.Is(err, pgsock.ErrPeer):
		return phaseA
	case errors.Is(err, pgsock.ErrNotSocket):
		return true
	case errors.Is(err, context.Canceled), pgsock.IsBudget(err),
		errors.Is(err, pgsock.ErrCleartextRequested), errors.Is(err, pgsock.ErrNotScram),
		errors.Is(err, pgsock.ErrScramParams), errors.Is(err, pgsock.ErrEnvironment):
		return false
	case errors.As(err, &se):
		return se.Code == "57P03" // cannot_connect_now: starting up
	}
	return true // the connect itself failed: nothing listens on the socket yet
}

// clusterTarget is the platform's session as supabase_admin: the recorded
// process, the role's salt, superuser startup parameters; trust (no
// password) only in phase A.
func (a *Agent) clusterTarget(s Spec, st State, phaseA bool) pgsock.Target {
	t := pgsock.Target{ProjectsDir: a.p.ProjectsDir(), Ref: s.Ref, UID: s.UID, PostmasterPid: st.PMPid,
		PostmasterStart: st.PMStart, ListenerPid: st.ListenerPid, ListenerStart: st.ListenerStart,
		User: "supabase_admin", ScramSalt: s.Secrets.ScramSalts["supabase_admin"], Superuser: true, AllowTrust: phaseA}
	if !phaseA {
		t.Password = s.Secrets.SupabaseAdminPassword
	}
	return t
}

func closeSession(c *pgx.Conn) {
	if c != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.Close(ctx)
	}
}

// clusterAssert runs the assertion (and with hba AssertHBA) against the rendered
// files as they are on disk.
func (a *Agent) clusterAssert(ctx context.Context, conn *pgx.Conn, ref string, hba bool) ([]nodecfg.CheckResult, error) {
	bl, err := clusterBaseline()
	if err != nil {
		return nil, err
	}
	r := a.p.RenderDir(ref)
	var out []nodecfg.CheckResult
	if hba {
		rendered, err := os.ReadFile(filepath.Join(r, "pg_hba.conf"))
		if err != nil {
			return nil, err
		}
		f, err := bootstrapAssertHBA(ctx, conn, rendered)
		if err != nil {
			return nil, err
		}
		out = append(out, f...)
	}
	conf, err := os.ReadFile(filepath.Join(r, "conf.d", pgconf.OverrideFile))
	if err != nil {
		return nil, err
	}
	f, err := bootstrapAssert(ctx, conn, bl, conf)
	return append(out, f...), err
}

// blockingAssert is the create-time assertion: any finding is ErrAssertion.
func (a *Agent) blockingAssert(ctx context.Context, conn *pgx.Conn, ref string, hba bool) error {
	findings, err := a.clusterAssert(ctx, conn, ref, hba)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return nil
	}
	var b strings.Builder
	for i, f := range findings {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(f.Name + ": " + f.Detail)
	}
	return fmt.Errorf("%w: %s", bootstrap.ErrAssertion, pgsock.Sanitize(b.String(), 1024))
}

// CheckCluster runs, in one session to the recorded postmaster, the
// operational facts — the SCRAM login within its bounds and
// pg_stat_archiver.failed_count = 0 — and the assertion. The error is the
// operational verdict; the findings are the project's drift and gate
// nothing.
func (a *Agent) CheckCluster(ctx context.Context, s Spec) ([]nodecfg.CheckResult, error) {
	if err := a.clusterSpec(s); err != nil {
		return nil, err
	}
	st, have, err := a.readState(s.Ref)
	if err != nil {
		return nil, err
	}
	if err := checkState(st, have, s); err != nil {
		return nil, err
	}
	if !have || st.Phase != PhaseB {
		return nil, fmt.Errorf("agent: %s: cluster not started in phase B", s.Ref)
	}
	conn, err := pgDial(ctx, a.clusterTarget(s, st, false))
	if err != nil {
		return nil, fmt.Errorf("agent: %s: %w", s.Ref, err)
	}
	defer closeSession(conn)
	var opErr error
	n, err := archiverFailures(ctx, conn)
	if err != nil { // the session is finished: no further statement on it
		return nil, fmt.Errorf("agent: %s: archiver: %w", s.Ref, err)
	}
	if n != 0 {
		opErr = fmt.Errorf("agent: %s: pg_stat_archiver.failed_count is %d", s.Ref, n)
	}
	drift, err := a.clusterAssert(ctx, conn, s.Ref, true)
	if err != nil {
		err = fmt.Errorf("agent: %s: %w", s.Ref, err)
	}
	return drift, errors.Join(opErr, err)
}

func queryArchiverFailures(ctx context.Context, c *pgx.Conn) (int64, error) {
	sctx, cancel := pgsock.Stmt(ctx, pgsock.DefaultBudget)
	defer cancel()
	var n int64
	err := c.QueryRow(sctx, "select failed_count from pg_catalog.pg_stat_archiver").Scan(&n)
	return n, pgsock.Clean(err)
}

// VerifyCluster is CheckCluster with the drift logged (WARN, per finding):
// it fails on the operational facts only.
func (a *Agent) VerifyCluster(ctx context.Context, s Spec) error {
	drift, err := a.CheckCluster(ctx, s)
	for _, d := range drift {
		slog.Warn("cluster drift", "ref", s.Ref, "check", d.Name, "detail", d.Detail)
	}
	return err
}

// StopCluster stops pg-<ref> (45 s grace, below the Docker call bound) and
// removes it; nil when it does not exist.
func (a *Agent) StopCluster(ctx context.Context, ref string) error {
	if err := checkRef(ref); err != nil {
		return err
	}
	name := clusterName(ref)
	c, err := dockerInspectContainer(ctx, name)
	if err != nil || c == nil {
		return err
	}
	for _, args := range [][]string{{"stop", "-t", "45", "--", name}, {"rm", "-v", "--", name}} {
		if _, err := dockerRun(ctx, args...); err != nil {
			// Gone in between counts as removed.
			if c, ierr := dockerInspectContainer(ctx, name); ierr == nil && c == nil {
				return nil
			}
			return err
		}
	}
	return nil
}

// removeCluster removes pg-<ref> whatever its state; nil when absent.
func (a *Agent) removeCluster(ctx context.Context, ref string) error {
	c, err := dockerInspectContainer(ctx, clusterName(ref))
	if err != nil || c == nil {
		return err
	}
	_, err = dockerRun(ctx, "rm", "-f", "-v", "--", clusterName(ref))
	return err
}

// labelPhase carries a cluster container's phase, A or B.
const labelPhase = "supapace.phase"

// clusterLabels are the labels of a cluster container but the configuration
// hash; the image (the configured reference) only in phase B.
func (a *Agent) clusterLabels(s Spec, phase string) map[string]string {
	l := map[string]string{labelRole: "cluster", labelRef: s.Ref, labelPhase: phase,
		labelGeneration: strconv.FormatInt(s.Generation, 10), labelEpoch: strconv.FormatInt(s.Epoch, 10)}
	if phase == "B" {
		l[labelImage] = a.cfg.Images.Postgres
	}
	return l
}

// removeRefusedCluster removes a container the start or adoption refused, on a
// fresh bounded context; a removal error is joined to refusal, which stays
// matchable.
func (a *Agent) removeRefusedCluster(ctx context.Context, ref string, refusal error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	if _, err := dockerRun(ctx, "rm", "-f", "-v", "--", clusterName(ref)); err != nil {
		return errors.Join(refusal, err)
	}
	return refusal
}

// clusterRunArgs is the `docker create` argv of pg-<ref> in phase A or B; in
// phase B it carries the configuration label (clusterConfigLabel).
func (a *Agent) clusterRunArgs(s Spec, phaseB bool) ([]string, error) {
	bl, err := clusterBaseline()
	if err != nil {
		return nil, err
	}
	cmdline, err := a.imageCommandLine()
	if err != nil {
		return nil, err
	}
	name, r, pd := clusterName(s.Ref), a.p.RenderDir(s.Ref), a.p.ProjectDir(s.Ref)
	mem := strconv.Itoa(s.MemMB) + "m"
	phase := "A"
	if phaseB {
		phase = "B"
	}
	args := []string{"create", "--name", name, "--hostname", name, "--user", fmt.Sprintf("%d:%d", s.UID, s.GID),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + a.seccompFile(),
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--memory", mem, "--memory-swap", mem, "--cpus", "1", "--pids-limit", strconv.Itoa(s.Pids), "--shm-size", "64m",
		"--ulimit", "core=0", "--ulimit", "nofile=65536:65536", "--no-healthcheck", "--ipc", "private", "--stop-timeout", "45"}
	labels := a.clusterLabels(s, phase)
	for _, k := range slices.Sorted(maps.Keys(labels)) {
		args = append(args, "--label", k+"="+labels[k])
	}
	if phaseB {
		args = append(args, "--network", networkName(s.Ref), "--ip", a.cfg.ClusterAddr(s.SubnetIndex).String(),
			"--sysctl", "net.ipv6.conf.all.disable_ipv6=1", "--sysctl", "net.ipv4.ping_group_range=1 0")
	} else {
		// initdb needs a password; bootstrap replaces every password and the
		// container is removed after phase A.
		pw := make([]byte, 32)
		if _, err := rand.Read(pw); err != nil {
			return nil, err
		}
		args = append(args, "--network", "none", "-e", "POSTGRES_PASSWORD="+hex.EncodeToString(pw))
	}
	f := bl.Files
	args = append(args,
		"-v", pd+"/data:/var/lib/postgresql/data", "-v", pd+"/sock:/var/run/postgresql",
		"-v", r+"/passwd:/etc/passwd:ro", "-v", r+"/group:/etc/group:ro",
		"-v", r+"/pgsodium_root.key:"+f.PgsodiumKey+":ro",
		"-v", r+"/conf.d:"+f.IncludeDir+":ro",
		"-v", r+"/supautils.conf:"+f.SupautilsConf+":ro",
		"-v", r+"/tools:/opt/supapace/tools:ro")
	if phaseB {
		args = append(args, "-v", r+"/pg_hba.conf:"+f.HBAFile+":ro", "-v", r+"/pg_ident.conf:"+f.IdentFile+":ro")
	}
	args = append(append(args, "--", a.cfg.Images.Postgres, "postgres", "-D", "/etc/postgresql"), cmdline...)
	if !phaseB {
		return args, nil
	}
	label, err := a.clusterConfigLabel(s.Ref, args)
	if err != nil {
		return nil, err
	}
	i := slices.Index(args, "--")
	return slices.Concat(args[:i], []string{"--label", labelConfig + "=" + label}, args[i:]), nil
}

// imageFile reads a file EnsureImageFiles extracted from the cluster image.
func (a *Agent) imageFile(name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(a.p.ImageDir(a.cfg.Images.Postgres), name))
	if err != nil {
		return nil, fmt.Errorf("agent: image file %s: %w", name, err)
	}
	return b, nil
}

func (a *Agent) imageCommandLine() ([]string, error) {
	conf, err := a.imageFile("postgresql.conf")
	if err != nil {
		return nil, err
	}
	return pgconf.CommandLine(conf)
}

// renderCluster writes the project's platform files from s and the image's
// files: render directories root 0755 first, every file root 0444, the
// pgsodium key 0400 owned by the project's ids — written only when absent,
// never replaced.
func (a *Agent) renderCluster(s Spec) error {
	img := map[string][]byte{}
	for _, n := range []string{"passwd", "group", "supautils.conf"} {
		b, err := a.imageFile(n)
		if err != nil {
			return err
		}
		img[n] = b
	}
	passwd, err := pgconf.Passwd(img["passwd"], s.UID, s.GID)
	if err != nil {
		return err
	}
	group, err := pgconf.Group(img["group"], s.GID)
	if err != nil {
		return err
	}
	supa, err := pgconf.Supautils(img["supautils.conf"], false)
	if err != nil {
		return err
	}
	hba, err := pgconf.HBA(a.cfg.Slice(s.SubnetIndex))
	if err != nil {
		return err
	}
	if s.Secrets.PgsodiumRootKey == "" {
		return fmt.Errorf("agent: %s: no pgsodium root key in the spec", s.Ref)
	}
	r := a.p.RenderDir(s.Ref)
	if err := a.ensurePlatformDir(); err != nil {
		return err
	}
	for _, d := range []string{filepath.Dir(r), r, filepath.Join(r, "tools")} {
		if err := ensureDir(d, 0o755, -1, -1); err != nil {
			return err
		}
	}
	if err := a.renderConfD(filepath.Join(r, "conf.d"), s); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"passwd": passwd, "group": group, "supautils.conf": supa,
		"pg_hba.conf": hba, "pg_ident.conf": pgconf.Ident()} {
		if err := writeFile(a.p, r, name, data, 0o444, os.Geteuid(), os.Getegid()); err != nil {
			return err
		}
	}
	key := filepath.Join(r, "pgsodium_root.key")
	fi, err := os.Lstat(key)
	switch {
	case err == nil && fi.Mode().IsRegular():
		return nil
	case err == nil:
		return fmt.Errorf("agent: %s is not a regular file", key)
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	return writeFile(a.p, r, "pgsodium_root.key", []byte(s.Secrets.PgsodiumRootKey), 0o400, s.UID, s.GID)
}

// renderConfD makes dir the include directory of s: the image's files plus
// the platform's override file (which must sort after every one of them),
// all root 0444, and nothing else.
func (a *Agent) renderConfD(dir string, s Spec) error {
	src := filepath.Join(a.p.ImageDir(a.cfg.Images.Postgres), "conf.d")
	ents, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("agent: image file conf.d: %w", err)
	}
	want := map[string][]byte{}
	var names []string
	for _, e := range ents {
		if !e.Type().IsRegular() {
			return fmt.Errorf("agent: image conf.d entry %q is not a regular file", e.Name())
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		want[e.Name()] = b
		names = append(names, e.Name())
	}
	if err := pgconf.SortsLast(names); err != nil {
		return err
	}
	if want[pgconf.OverrideFile], err = pgconf.Overrides(s.GUC, s.MemMB); err != nil {
		return err
	}
	if err := ensureDir(dir, 0o755, -1, -1); err != nil {
		return err
	}
	have, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range have {
		if _, ok := want[e.Name()]; !ok {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	for name, data := range want {
		if err := writeFile(a.p, dir, name, data, 0o444, os.Geteuid(), os.Getegid()); err != nil {
			return err
		}
	}
	return nil
}

// clusterConfigLabel is the supapace.config label of a phase-B container, in
// the form of the platform's containers (configHash): its create arguments
// (options, "--", image and command; no secret is among them), then the
// digests of the rendered files as now on disk, the image's postgresql.conf
// (the source of the command-line pins) and the seccomp profile. A container
// created with other arguments, files or profile is therefore not adopted.
func (a *Agent) clusterConfigLabel(ref string, args []string) (string, error) {
	r := a.p.RenderDir(ref)
	digests, err := fileDigests(filepath.Join(r, "conf.d", pgconf.OverrideFile), filepath.Join(r, "supautils.conf"),
		filepath.Join(r, "pg_hba.conf"), filepath.Join(r, "pg_ident.conf"), filepath.Join(r, "passwd"), filepath.Join(r, "group"),
		filepath.Join(a.p.ImageDir(a.cfg.Images.Postgres), "postgresql.conf"), a.seccompFile())
	if err != nil {
		return "", err
	}
	i := slices.Index(args, "--")
	return configHash(args[:i], args[i+1:], digests...), nil
}

// labelValue is the value of the label key in a create argv, or "".
func labelValue(args []string, key string) string {
	for i := 0; i+1 < len(args) && args[i] != "--"; i++ {
		if v, ok := strings.CutPrefix(args[i+1], key+"="); ok && args[i] == "--label" {
			return v
		}
	}
	return ""
}

// readFailed: the adoption check failed because a fact could not be read
// (an error not of the gate, or a refusal carrying the read's own error),
// not because a fact it read refused the container.
func readFailed(err error) bool {
	if !errors.Is(err, ErrContainment) {
		return true
	}
	m, ok := err.(interface{ Unwrap() []error })
	return ok && len(m.Unwrap()) > 1
}
