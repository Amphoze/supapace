package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

// ───────── fixtures for the cluster and task containers ─────────

// clPG replaces the cluster-session seams of cluster.go and the task seams of
// task.go. Each call is recorded in the fake host's log, so its order against
// the Docker calls can be read from f.calls().
type clPG struct {
	f  *fakeHost
	mu sync.Mutex

	dialErrs   []error // returned by successive dials; then dialAlways
	dialAlways error
	onDial     func(pgsock.Target)
	targets    []pgsock.Target
	starts     map[int]uint64 // pid → start time; absent: pid × 10
	startErrs  map[int]error
	runErr     error
	findings   []nodecfg.CheckResult
	hbaFinds   []nodecfg.CheckResult
	archiver   int64
	assertConf []byte
	assertHBA  []byte

	taskExit map[string]string // task kind → exit code printed by the poll ("0" when absent)
	taskOut  map[string]string // task kind → logs, stdout
	taskErr  map[string]string // task kind → logs, stderr
	taskPoll map[string][]string
	logsErr  error
}

func clFakePG(t *testing.T, f *fakeHost) *clPG {
	pg := &clPG{f: f, starts: map[int]uint64{}, startErrs: map[int]error{}, taskExit: map[string]string{}, taskOut: map[string]string{}, taskErr: map[string]string{},
		taskPoll: map[string][]string{}}
	saved := []func(){
		swap(&pgDial, func(ctx context.Context, tg pgsock.Target) (*pgx.Conn, error) {
			f.record(fmt.Sprintf("dial %s pid=%d start=%d trust=%v", tg.User, tg.PostmasterPid, tg.PostmasterStart, tg.AllowTrust))
			pg.mu.Lock()
			pg.targets = append(pg.targets, tg)
			err := pg.dialAlways
			if len(pg.dialErrs) > 0 {
				err, pg.dialErrs = pg.dialErrs[0], pg.dialErrs[1:]
			}
			on := pg.onDial
			pg.mu.Unlock()
			if on != nil {
				on(tg)
			}
			return nil, err
		}),
		swap(&pgProcStart, func(pid int) (uint64, error) {
			pg.mu.Lock()
			defer pg.mu.Unlock()
			if err := pg.startErrs[pid]; err != nil {
				return 0, err
			}
			if s, ok := pg.starts[pid]; ok {
				return s, nil
			}
			return uint64(pid) * 10, nil
		}),
		swap(&bootstrapRun, func(ctx context.Context, c *pgx.Conn, s bootstrap.Secrets) error {
			f.record("bootstrap run")
			return pg.runErr
		}),
		swap(&bootstrapAssert, func(ctx context.Context, c *pgx.Conn, want bootstrap.Baseline, conf []byte) ([]nodecfg.CheckResult, error) {
			f.record("assert")
			pg.mu.Lock()
			defer pg.mu.Unlock()
			pg.assertConf = slices.Clone(conf)
			return slices.Clone(pg.findings), nil
		}),
		swap(&bootstrapAssertHBA, func(ctx context.Context, c *pgx.Conn, hba []byte) ([]nodecfg.CheckResult, error) {
			f.record("assert hba")
			pg.mu.Lock()
			defer pg.mu.Unlock()
			pg.assertHBA = slices.Clone(hba)
			return slices.Clone(pg.hbaFinds), nil
		}),
		swap(&archiverFailures, func(ctx context.Context, c *pgx.Conn) (int64, error) {
			f.record("archiver")
			return pg.archiver, nil
		}),
		swap(&readyPoll, time.Millisecond),
		swap(&taskPoll, time.Millisecond),
		swap(&daemonExe, func() (string, error) { return "/opt/test/supapaced", nil }),
		swap(&dockerRunOutput, func(ctx context.Context, args ...string) (string, string, error) {
			out, err := dockerRun(ctx, args...) // recorded and scripted like every call
			kind, _ := strings.CutPrefix(clLast(args), "task-"+testRef+"-")
			pg.mu.Lock()
			defer pg.mu.Unlock()
			return out, pg.taskErr[kind], err
		}),
		swap(&removeEmptyProjectDir, func(p nodecfg.Paths, ref string) error {
			f.record("removeEmptyProjectDir " + ref)
			return nil
		}),
	}
	t.Cleanup(func() {
		for _, r := range saved {
			r()
		}
	})
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		name := clLast(args)
		kind, isTask := strings.CutPrefix(name, "task-"+testRef+"-")
		switch {
		case !isTask:
		case args[0] == "inspect":
			pg.mu.Lock()
			defer pg.mu.Unlock()
			if q := pg.taskPoll[kind]; len(q) > 0 {
				pg.taskPoll[kind] = q[1:]
				return q[0] + "\n", nil, true
			}
			code := pg.taskExit[kind]
			if code == "" {
				code = "0"
			}
			return "exited " + code + "\n", nil, true
		case args[0] == "logs":
			pg.mu.Lock()
			defer pg.mu.Unlock()
			return pg.taskOut[kind], pg.logsErr, true
		}
		return "", nil, false
	}
	return pg
}

func clLast(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[len(args)-1]
}

// clSetup is a node on which the gate passes, the cluster image's files
// extracted, the seams faked and a spec with its secrets.
func clSetup(t *testing.T) (*Agent, *fakeHost, Spec, *clPG) {
	t.Helper()
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	pg := clFakePG(t, f)
	clImageFiles(t, a)
	s.Secrets = bootstrap.Secrets{SupabaseAdminPassword: "pw-admin-0123456789", PostgresPassword: "pw-postgres-0123456789",
		AuthenticatorPassword: "pw-authenticator-0123456789", PgsodiumRootKey: strings.Repeat("ab", 32),
		ScramSalts: map[string][]byte{"supabase_admin": []byte("salt-admin-01234"), "postgres": []byte("salt-postgres-01"),
			"authenticator": []byte("salt-authentic01")}}
	s.FirstBoot = true
	writeSeccomp(t, a)
	if !strings.HasPrefix(t.Name(), "TestEnsureCluster_WipeNeedsProjectDir") && !strings.HasPrefix(t.Name(), "TestPurgeDir_AbsentDirLaunchesNothing") {
		clProjectDir(t, a, s)
	}
	return a, f, s, pg
}

// clImageFiles writes the image fixture where EnsureImageFiles puts it.
func clImageFiles(t *testing.T, a *Agent) {
	t.Helper()
	dir := a.p.ImageDir(a.cfg.Images.Postgres)
	mkdirs(t, filepath.Dir(a.p.PlatformDir()), a.p.PlatformDir(), filepath.Dir(dir), dir, filepath.Join(dir, "conf.d"))
	os.Chmod(filepath.Dir(a.p.PlatformDir()), 0o700)
	src := "../pgconf/testdata/image"
	for _, n := range []string{"passwd", "group", "supautils.conf", "postgresql.conf"} {
		clCopy(t, filepath.Join(src, n), filepath.Join(dir, n))
	}
	ents, err := os.ReadDir(filepath.Join(src, "conf.d"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		clCopy(t, filepath.Join(src, "conf.d", e.Name()), filepath.Join(dir, "conf.d", e.Name()))
	}
}

func clCopy(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func clFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../pgconf/testdata/image", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// clState writes state.json as a previous run left it.
func clState(t *testing.T, a *Agent, s Spec, st State) {
	t.Helper()
	mkdirs(t, filepath.Dir(a.p.PlatformDir()), a.p.PlatformDir(), filepath.Dir(a.p.RenderDir(s.Ref)), a.p.RenderDir(s.Ref))
	os.Chmod(filepath.Dir(a.p.PlatformDir()), 0o700)
	if err := a.writeState(s.Ref, st); err != nil {
		t.Fatal(err)
	}
}

func clReadState(t *testing.T, a *Agent, s Spec) State {
	t.Helper()
	st, ok, err := a.readState(s.Ref)
	if err != nil || !ok {
		t.Fatalf("state.json: ok %v err %v", ok, err)
	}
	return st
}

// clToPhaseB brings the project to a running phase-B cluster (from A-done)
// and clears the log.
func clToPhaseB(t *testing.T, a *Agent, f *fakeHost, s Spec) *fakeCtr {
	t.Helper()
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatalf("first phase-B start: %v", err)
	}
	if st := clReadState(t, a, s); st.Phase != PhaseB {
		t.Fatalf("state after the first phase-B start: %+v", st)
	}
	f.resetLog()
	return clCtr(t, f, "pg-"+s.Ref)
}

func clCtr(t *testing.T, f *fakeHost, name string) *fakeCtr {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.ctrs[name]
	if !ok {
		t.Fatalf("%s does not exist", name)
	}
	return c
}

// clRuns returns the argv of every `docker run` or `docker create` of the
// named container.
func clRuns(f *fakeHost, name string) [][]string {
	var out [][]string
	for _, a := range append(f.argv("run"), f.argv("create")...) {
		if flagValue(a, "--name") == name {
			out = append(out, a)
		}
	}
	return out
}

func clOneRun(t *testing.T, f *fakeHost, name string) []string {
	t.Helper()
	r := clRuns(f, name)
	if len(r) != 1 {
		t.Fatalf("%d runs of %s, want 1", len(r), name)
	}
	return r[0]
}

// clFlags returns the options of a run argv (everything before "--").
func clFlags(args []string) []string {
	if i := slices.Index(args, "--"); i >= 0 {
		return args[:i]
	}
	return args
}

func clHasPair(args []string, flag, value string) bool {
	fl := clFlags(args)
	for i := 0; i+1 < len(fl); i++ {
		if fl[i] == flag && fl[i+1] == value {
			return true
		}
	}
	return false
}

func clWantPairs(t *testing.T, what string, args []string, pairs ...string) {
	t.Helper()
	for i := 0; i+1 < len(pairs); i += 2 {
		if !clHasPair(args, pairs[i], pairs[i+1]) {
			t.Errorf("%s: no %s %q in %q", what, pairs[i], pairs[i+1], args)
		}
	}
}

func clIndex(calls []string, pred func(string) bool) int {
	return slices.IndexFunc(calls, pred)
}

func clLastIndex(calls []string, s string) int {
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i] == s {
			return i
		}
	}
	return -1
}

func clPrefix(p string) func(string) bool {
	return func(s string) bool { return strings.HasPrefix(s, p) }
}

func clIsClusterRun(ref string) func(string) bool {
	return func(s string) bool {
		return strings.HasPrefix(s, "docker create ") && strings.Contains(s, " --name pg-"+ref+" ")
	}
}

func clIsMutation(s string) bool {
	for _, v := range []string{"docker create ", "docker run ", "docker start ", "docker stop ", "docker kill ", "docker rm ",
		"docker network create ", "docker network rm ", "docker network connect ", "docker network disconnect "} {
		if strings.HasPrefix(s, v) {
			return true
		}
	}
	return false
}

// clCommon asserts the flags every cluster run carries, in either phase.
func clCommon(t *testing.T, a *Agent, s Spec, args []string, phase string) {
	t.Helper()
	name := "pg-" + s.Ref
	r, pd := a.p.RenderDir(s.Ref), a.p.ProjectDir(s.Ref)
	clWantPairs(t, "phase "+phase, args,
		"--name", name, "--hostname", name, "--user", "700005:700005",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp="+filepath.Join(a.p.PlatformDir(), "seccomp.json"),
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--memory", "512m", "--memory-swap", "512m", "--cpus", "1", "--pids-limit", "512", "--shm-size", "64m",
		"--ulimit", "core=0", "--ulimit", "nofile=65536:65536", "--ipc", "private",
		"--label", "supapace.role=cluster", "--label", "supapace.ref="+s.Ref,
		"--label", "supapace.generation="+strconv.FormatInt(s.Generation, 10), "--label", "supapace.epoch="+strconv.FormatInt(s.Epoch, 10),
		"--label", "supapace.phase="+phase,
		"-v", pd+"/data:/var/lib/postgresql/data", "-v", pd+"/sock:/var/run/postgresql",
		"-v", r+"/passwd:/etc/passwd:ro", "-v", r+"/group:/etc/group:ro",
		"-v", r+"/pgsodium_root.key:/etc/postgresql-custom/pgsodium_root.key:ro",
		"-v", r+"/conf.d:/etc/postgresql-custom/conf.d:ro",
		"-v", r+"/supautils.conf:/etc/postgresql-custom/supautils.conf:ro",
		"-v", r+"/tools:/opt/supapace/tools:ro")
	fl := clFlags(args)
	for _, want := range []string{"--read-only", "--no-healthcheck"} {
		if !slices.Contains(fl, want) {
			t.Errorf("phase %s: no %s", phase, want)
		}
	}
	for _, bad := range []string{"--restart", "--cap-add", "--privileged", "--rm", "--entrypoint", "--network-alias", "--pid", "--userns"} {
		if slices.Contains(fl, bad) {
			t.Errorf("phase %s: %s present: %q", phase, bad, args)
		}
	}
	cl, err := pgconf.CommandLine(clFixture(t, "postgresql.conf"))
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{a.cfg.Images.Postgres, "postgres", "-D", "/etc/postgresql"}, cl...)
	if got := positional(args); !slices.Equal(got, want) {
		t.Errorf("phase %s: image and command %q, want %q", phase, got, want)
	}
}

// clHardenedTask asserts what every task container carries.
func clHardenedTask(t *testing.T, a *Agent, s Spec, args []string, kind string) {
	t.Helper()
	clWantPairs(t, kind, args, "--name", "task-"+s.Ref+"-"+kind, "--network", "none", "--user", "700005:700005",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp="+filepath.Join(a.p.PlatformDir(), "seccomp.json"),
		"--memory", "128m", "--pids-limit", "64", "--ulimit", "core=0", "--ulimit", "nofile=65536:65536",
		"--label", "supapace.role=task", "--label", "supapace.ref="+s.Ref)
	fl := clFlags(args)
	for _, want := range []string{"-d", "--read-only", "--no-healthcheck"} {
		if !slices.Contains(fl, want) {
			t.Errorf("%s: no %s in %q", kind, want, args)
		}
	}
	for _, bad := range []string{"--rm", "--restart", "--cap-add", "--privileged", "--ip", "-e"} {
		if slices.Contains(fl, bad) {
			t.Errorf("%s: %s present: %q", kind, bad, args)
		}
	}
	if pos := positional(args); len(pos) == 0 || pos[0] != a.cfg.Images.Postgres {
		t.Errorf("%s: image %q", kind, pos)
	}
}

// ───────── phase A ─────────

func TestEnsureCluster_PhaseAFlags(t *testing.T) {
	a, f, s, pg := clSetup(t)
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	run := clOneRun(t, f, "pg-"+s.Ref)
	clCommon(t, a, s, run, "A")
	clWantPairs(t, "phase A", run, "--network", "none")
	pw := ""
	for _, e := range flagValues(run, "-e") {
		if v, ok := strings.CutPrefix(e, "POSTGRES_PASSWORD="); ok {
			pw = v
		} else {
			t.Errorf("phase A: unexpected environment %q", e)
		}
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(pw) || strings.Contains(pw, s.Secrets.SupabaseAdminPassword) {
		t.Errorf("phase A: throwaway password %q", pw)
	}
	fl := clFlags(run)
	for _, bad := range []string{"--ip", "--sysctl"} {
		if slices.Contains(fl, bad) {
			t.Errorf("phase A: %s present", bad)
		}
	}
	for _, v := range flagValues(run, "-v") {
		if strings.Contains(v, "pg_hba") || strings.Contains(v, "pg_ident") {
			t.Errorf("phase A mounts %s", v)
		}
	}
	for _, l := range flagValues(run, "--label") {
		if strings.HasPrefix(l, "supapace.config=") || strings.HasPrefix(l, "supapace.image=") {
			t.Errorf("phase A carries %s", l)
		}
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "docker network connect") {
			t.Errorf("phase A: %s", c)
		}
	}
	// The session of phase A: the recorded init, no password, trust allowed.
	if len(pg.targets) == 0 {
		t.Fatal("no session")
	}
	tg := pg.targets[0]
	if !tg.AllowTrust || tg.Password != "" || tg.User != "supabase_admin" || !tg.Superuser || tg.UID != 700005 ||
		tg.ProjectsDir != a.p.ProjectsDir() || tg.Ref != s.Ref || !bytes.Equal(tg.ScramSalt, s.Secrets.ScramSalts["supabase_admin"]) {
		t.Errorf("phase-A target %v", tg)
	}
}

func TestEnsureCluster_PhaseAWipesDataFirst(t *testing.T) {
	a, f, s, _ := clSetup(t)
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	calls := f.calls()
	wipe := "task-" + s.Ref + "-wipe"
	leftover := clIndex(calls, func(c string) bool { return c == "docker rm -f -v -- "+wipe })
	wipeRun := clIndex(calls, func(c string) bool {
		return strings.HasPrefix(c, "docker run ") && strings.Contains(c, " --name "+wipe+" ")
	})
	wipeGone := slices.Index(calls[wipeRun+1:], "docker rm -f -v -- "+wipe)
	run := clIndex(calls, clIsClusterRun(s.Ref))
	if leftover < 0 || wipeRun < leftover || wipeGone < 0 || run < wipeRun+1+wipeGone {
		t.Fatalf("order: leftover %d, wipe %d, removed +%d, create %d:\n%s", leftover, wipeRun, wipeGone, run,
			strings.Join(calls, "\n"))
	}
	args := clOneRun(t, f, wipe)
	clHardenedTask(t, a, s, args, "wipe")
	clWantPairs(t, "wipe", args, "-v", "/opt/test/supapaced:/supapaced:ro", "-v", a.p.ProjectDir(s.Ref)+":/p",
		"--entrypoint", "/supapaced")
	if got := positional(args); !slices.Equal(got, []string{a.cfg.Images.Postgres, "rmtree", "--keep-root", "/p/data"}) {
		t.Errorf("wipe command %q", got)
	}
	if n := len(flagValues(args, "-v")); n != 2 {
		t.Errorf("wipe mounts %d paths, want exactly the helper and the project directory", n)
	}
	// A failing wipe starts nothing.
	a2, f2, s2, pg2 := clSetup(t)
	pg2.taskExit["wipe"] = "1"
	pg2.taskErr["wipe"] = "rmtree: /p/data: permission denied\x1b[2J"
	err := a2.EnsureCluster(context.Background(), s2)
	if err == nil || !strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("failed wipe: %v", err)
	}
	if len(clRuns(f2, "pg-"+s2.Ref)) != 0 || slices.Contains(f2.calls(), "nft check") {
		t.Fatalf("a failed wipe went on: %q", f2.calls())
	}
}

func TestEnsureCluster_PhaseARemovesContainerBeforeADone(t *testing.T) {
	a, f, s, _ := clSetup(t)
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	calls := f.calls()
	name := "pg-" + s.Ref
	boot := slices.Index(calls, "bootstrap run")
	assert := slices.Index(calls, "assert")
	stop := slices.Index(calls, "docker stop -t 45 -- "+name)
	rm := slices.Index(calls, "docker rm -v -- "+name)
	write := clIndex(calls, func(c string) bool { return strings.HasPrefix(c, "write ") && strings.Contains(c, "state.json") })
	if boot < 0 || assert < boot || stop < assert || rm < stop || write < rm {
		t.Fatalf("order: bootstrap %d, assert %d, stop %d, rm %d, state %d:\n%s", boot, assert, stop, rm, write, strings.Join(calls, "\n"))
	}
	if slices.Contains(calls, "assert hba") {
		t.Error("phase A asserted the image's pg_hba")
	}
	st := clReadState(t, a, s)
	if st != (State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone}) {
		t.Fatalf("state %+v", st)
	}
	if c, _ := dockerInspectContainer(context.Background(), name); c != nil {
		t.Fatalf("phase-A container left: %+v", c)
	}
}

func TestEnsureCluster_PhaseAWaitTreatsErrPeerAsNotReady(t *testing.T) {
	if phaseAWait != 120*time.Second {
		t.Fatalf("phase-A wait bound %v, want 120s", phaseAWait)
	}
	a, f, s, pg := clSetup(t)
	pg.dialErrs = []error{pgsock.ErrPeer, pgsock.ErrPeer, pgsock.ErrNotSocket, &pgsock.ServerError{Code: "57P03", Message: "starting up"}}
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatalf("ErrPeer, no socket and 57P03 are not ready: %v", err)
	}
	if len(pg.targets) != 5 || !slices.Contains(f.calls(), "bootstrap run") {
		t.Fatalf("%d dials", len(pg.targets))
	}
	// Bounded: a server that never answers ends the step with ErrPeer.
	swapped := swap(&phaseAWait, 50*time.Millisecond)
	defer swapped()
	a, f, s, pg = clSetup(t)
	pg.dialAlways = pgsock.ErrPeer
	start := time.Now()
	err := a.EnsureCluster(context.Background(), s)
	if !errors.Is(err, pgsock.ErrPeer) || time.Since(start) > 5*time.Second {
		t.Fatalf("never ready: %v after %v", err, time.Since(start))
	}
	if slices.Contains(f.calls(), "bootstrap run") || len(pg.targets) < 2 {
		t.Fatalf("calls %q", f.calls())
	}
	if _, ok, _ := a.readState(s.Ref); ok {
		t.Fatal("state written")
	}
	// Anything else is a failure at once.
	for _, e := range []error{pgsock.ErrScramParams, pgsock.ErrCleartextRequested, pgsock.ErrNotScram, pgsock.ErrBudget,
		&pgsock.ServerError{Code: "28P01", Message: "auth failed"}} {
		a, _, s, pg = clSetup(t)
		pg.dialAlways = e
		if err := a.EnsureCluster(context.Background(), s); err == nil || len(pg.targets) != 1 {
			t.Errorf("%v: err %v after %d dials", e, err, len(pg.targets))
		}
	}
}

func TestEnsureCluster_ExitedBeforeReady(t *testing.T) {
	a, f, s, pg := clSetup(t)
	pg.dialAlways = pgsock.ErrPeer
	pg.onDial = func(pgsock.Target) {
		f.mu.Lock()
		if c := f.ctrs["pg-"+s.Ref]; c != nil {
			c.Running, c.Pid = false, 0
		}
		f.mu.Unlock()
	}
	err := a.EnsureCluster(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "exited") || len(pg.targets) != 1 {
		t.Fatalf("exited container: %v after %d dials", err, len(pg.targets))
	}
}

func TestEnsureCluster_PhaseAAssertionBlocks(t *testing.T) {
	a, f, s, pg := clSetup(t)
	pg.findings = []nodecfg.CheckResult{{Name: "superuser", Detail: "a second superuser"}}
	err := a.EnsureCluster(context.Background(), s)
	if !errors.Is(err, bootstrap.ErrAssertion) || !strings.Contains(err.Error(), "superuser") {
		t.Fatalf("findings at phase A: %v", err)
	}
	if _, ok, _ := a.readState(s.Ref); ok {
		t.Fatal("state written despite findings")
	}
	if slices.Contains(f.calls(), "docker stop -t 45 -- pg-"+s.Ref) {
		t.Fatal("container stopped as if phase A had passed")
	}
	// A bootstrap error fails the step too.
	a, _, s, pg = clSetup(t)
	pg.runErr = errors.New("bootstrap: boom")
	if err := a.EnsureCluster(context.Background(), s); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("bootstrap error: %v", err)
	}
}

func TestEnsureCluster_ResumePhaseA_NoNetwork(t *testing.T) {
	a, f, s, _ := clSetup(t)
	f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: true, CapDrop: []string{"ALL"},
		Labels: map[string]string{"supapace.role": "cluster", "supapace.phase": "A"}})
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	m := f.mutations()
	if len(m) == 0 || m[0] != "docker rm -f -v -- pg-"+s.Ref {
		t.Fatalf("first mutation %q", m)
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "docker network connect") {
			t.Fatalf("network connect on resume: %s", c)
		}
	}
	if run := clOneRun(t, f, "pg-"+s.Ref); !clHasPair(run, "--network", "none") || flagValue(run, "--ip") != "" {
		t.Fatalf("re-run not network-less: %q", run)
	}
	if !slices.Contains(f.calls(), "bootstrap run") || clReadState(t, a, s).Phase != PhaseADone {
		t.Fatal("phase A not re-run to the end")
	}
}

func TestEnsureCluster_UnknownPhaseRefused(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseB, PMPid: 77, PMStart: 770})
	if err := os.WriteFile(filepath.Join(a.p.RenderDir(s.Ref), "state.json"), []byte(`{"epoch":1,"generation":1,"phase":"C","pm_pid":77,"pm_start":770,"listener_pid":0,"listener_start":0}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.resetLog()
	if err := a.EnsureCluster(context.Background(), s); err == nil {
		t.Fatal("unknown phase accepted")
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("mutations %q", m)
	}
}

// ───────── phase B ─────────

func TestEnsureCluster_PhaseBFlags(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	run := clOneRun(t, f, "pg-"+s.Ref)
	clCommon(t, a, s, run, "B")
	r := a.p.RenderDir(s.Ref)
	clWantPairs(t, "phase B", run, "--network", "proj-"+s.Ref, "--ip", "10.213.3.130",
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=1", "--sysctl", "net.ipv4.ping_group_range=1 0",
		"-v", r+"/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro", "-v", r+"/pg_ident.conf:/etc/postgresql/pg_ident.conf:ro",
		"--label", "supapace.image="+a.cfg.Images.Postgres)
	if v := flagValues(run, "-e"); len(v) != 0 {
		t.Errorf("phase B environment %q", v)
	}
	if strings.Contains(strings.Join(run, " "), "POSTGRES_PASSWORD") {
		t.Error("phase B carries POSTGRES_PASSWORD")
	}
	if n := len(flagValues(run, "--network")); n != 1 {
		t.Errorf("%d --network flags", n)
	}
	if !regexp.MustCompile(`^supapace\.config=[0-9a-f]{64}$`).MatchString(clLabel(run, "supapace.config")) {
		t.Errorf("config label %q", clLabel(run, "supapace.config"))
	}
	// The first phase-B start waits for a SCRAM login and blocks on the assertion.
	tg := pg.targets[len(pg.targets)-1]
	if tg.AllowTrust || tg.Password != s.Secrets.SupabaseAdminPassword || !tg.Superuser ||
		!bytes.Equal(tg.ScramSalt, s.Secrets.ScramSalts["supabase_admin"]) {
		t.Errorf("phase-B target %v", tg)
	}
	calls := f.calls()
	if slices.Contains(calls, "bootstrap run") || slices.Index(calls, "assert hba") < 0 || slices.Index(calls, "assert") < 0 {
		t.Errorf("first start: %q", calls)
	}
	if !bytes.Equal(pg.assertHBA, clRead(t, filepath.Join(r, "pg_hba.conf"))) ||
		!bytes.Equal(pg.assertConf, clRead(t, filepath.Join(r, "conf.d", pgconf.OverrideFile))) {
		t.Error("the assertion was not given the rendered files")
	}
}

func clLabel(run []string, key string) string {
	for _, l := range flagValues(run, "--label") {
		if strings.HasPrefix(l, key+"=") {
			return l
		}
	}
	return ""
}

func clRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEnsureCluster_FirstPhaseBAssertionBlocks(t *testing.T) {
	for _, hba := range []bool{false, true} {
		a, _, s, pg := clSetup(t)
		f := []nodecfg.CheckResult{{Name: "configuration", Detail: "max_connections from elsewhere"}}
		if hba {
			pg.hbaFinds = []nodecfg.CheckResult{{Name: "hba", Detail: "line 3 differs"}}
		} else {
			pg.findings = f
		}
		clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
		err := a.EnsureCluster(context.Background(), s)
		if !errors.Is(err, bootstrap.ErrAssertion) {
			t.Fatalf("hba %v: %v", hba, err)
		}
		if st := clReadState(t, a, s); st.Phase != PhaseADone {
			t.Fatalf("state moved on despite findings: %+v", st)
		}
	}
}

func TestEnsureCluster_PhaseBErrPeerIsFailure(t *testing.T) {
	a, _, s, pg := clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	pg.dialErrs = []error{pgsock.ErrPeer}
	if err := a.EnsureCluster(context.Background(), s); !errors.Is(err, pgsock.ErrPeer) || len(pg.targets) != 1 {
		t.Fatalf("ErrPeer in phase B: %v after %d dials", err, len(pg.targets))
	}
	// Not a listening socket yet is not ready, in phase B too.
	a, _, s, pg = clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	pg.dialErrs = []error{pgsock.ErrNotSocket, errors.New("pgsock: socket: connect: connection refused")}
	if err := a.EnsureCluster(context.Background(), s); err != nil || len(pg.targets) != 3 {
		t.Fatalf("socket not yet there: %v after %d dials", err, len(pg.targets))
	}
}

func TestClusterNotReady_Classification(t *testing.T) {
	for _, c := range []struct {
		err            error
		phaseA, phaseB bool
	}{
		{pgsock.ErrPeer, true, false},
		{fmt.Errorf("pgsock: x: socket: %w", pgsock.ErrNotSocket), true, true},
		{errors.New("pgsock: x: socket: connect: connection refused"), true, true},
		{&pgsock.ServerError{Code: "57P03"}, true, true},
		{&pgsock.ServerError{Code: "28P01"}, false, false},
		{pgsock.ErrCleartextRequested, false, false},
		{pgsock.ErrNotScram, false, false},
		{pgsock.ErrScramParams, false, false},
		{pgsock.ErrBudget, false, false},
		{pgsock.ErrEnvironment, false, false},
		{context.DeadlineExceeded, false, false},
		{context.Canceled, false, false},
	} {
		if got := clusterNotReady(c.err, true); got != c.phaseA {
			t.Errorf("phase A, %v: %v", c.err, got)
		}
		if got := clusterNotReady(c.err, false); got != c.phaseB {
			t.Errorf("phase B, %v: %v", c.err, got)
		}
	}
}

func TestEnsureCluster_ADoneWithPhaseAContainerPresent(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: true, CapDrop: []string{"ALL"},
		Labels: map[string]string{"supapace.role": "cluster", "supapace.ref": s.Ref, "supapace.phase": "A",
			"supapace.generation": "1", "supapace.epoch": "1"}})
	f.resetLog()
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	calls := f.calls()
	rm := slices.Index(calls, "docker rm -f -v -- pg-"+s.Ref)
	for i, c := range calls[:max(rm, 0)] {
		if clIsMutation(c) || strings.HasPrefix(c, "write ") || c == "nft check" || strings.HasPrefix(c, "dial ") {
			t.Fatalf("call %d %q before the removal of the phase-A container:\n%s", i, c, strings.Join(calls, "\n"))
		}
	}
	if rm < 0 || clIndex(calls, clIsClusterRun(s.Ref)) < rm {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	if st := clReadState(t, a, s); st.Phase != PhaseB {
		t.Fatalf("state %+v", st)
	}
}

// ───────── the gate ─────────

func TestEnsureCluster_GateBeforeEveryStart(t *testing.T) {
	a, f, s, _ := clSetup(t)
	ctx := context.Background()
	if err := a.EnsureCluster(ctx, s); err != nil { // phase A
		t.Fatal(err)
	}
	if err := a.EnsureCluster(ctx, s); err != nil { // first phase-B start
		t.Fatal(err)
	}
	f.mu.Lock()
	f.ctrs["pg-"+s.Ref].Running = false
	f.mu.Unlock()
	if err := a.EnsureCluster(ctx, s); err != nil { // a stopped container at an equal generation
		t.Fatal(err)
	}
	s.Generation = 2
	if err := a.EnsureCluster(ctx, s); err != nil { // a new generation
		t.Fatal(err)
	}
	calls := f.calls()
	runs := 0
	for i, c := range calls {
		if c == "docker start -- pg-"+s.Ref {
			runs++
			clGateThenStart(t, calls[:i+1], s.Ref)
		}
	}
	if runs != 4 {
		t.Fatalf("%d cluster runs, want 4:\n%s", runs, strings.Join(calls, "\n"))
	}
}

func TestEnsureCluster_GateFailureStartsNothing(t *testing.T) {
	for _, c := range []struct {
		name  string
		state *State
		fault func(a *Agent, f *fakeHost)
	}{
		{"phase A, nft", nil, func(a *Agent, f *fakeHost) { f.nftErr = nft.ErrDrift }},
		{"phase A, node flag", nil, func(a *Agent, f *fakeHost) { a.SetContainmentFailed(true) }},
		{"phase B, nft", &State{Phase: PhaseADone}, func(a *Agent, f *fakeHost) { f.nftErr = nft.ErrAbsent }},
		{"phase B, bridge with an address", &State{Phase: PhaseB, PMPid: 77, PMStart: 770},
			func(a *Agent, f *fakeHost) { f.ip["-j -d addr show dev spp14"] = bridgeIface("spp14", true) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, f, s, pg := clSetup(t)
			if c.state != nil {
				st := *c.state
				st.Epoch, st.Generation = s.Epoch, s.Generation
				clState(t, a, s, st)
			}
			c.fault(a, f)
			wantContainment(t, a.EnsureCluster(context.Background(), s), c.name)
			for _, call := range f.calls() {
				if strings.HasPrefix(call, "docker start ") || (strings.HasPrefix(call, "docker run ") && !strings.Contains(call, " --name task-")) {
					t.Fatalf("started after a failed gate: %s", call)
				}
			}
			if len(pg.targets) != 0 {
				t.Fatal("dialled after a failed gate")
			}
			if c.state != nil {
				if st := clReadState(t, a, s); st.Phase != c.state.Phase || st.PMPid != c.state.PMPid {
					t.Fatalf("state changed: %+v", st)
				}
			}
		})
	}
}

// ───────── state checks ─────────

func TestEnsureCluster_StaleGeneration(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: 3, Phase: PhaseB, PMPid: 77, PMStart: 770})
	f.resetLog()
	s.Generation = 2
	if err := a.EnsureCluster(context.Background(), s); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("got %v", err)
	}
	for _, c := range f.calls() {
		if clIsMutation(c) || strings.HasPrefix(c, "write ") {
			t.Fatalf("%s", c)
		}
	}
}

func TestEnsureCluster_EpochDivergence(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clState(t, a, s, State{Epoch: 2, Generation: 1, Phase: PhaseB, PMPid: 77, PMStart: 770})
	f.resetLog()
	if err := a.EnsureCluster(context.Background(), s); !errors.Is(err, ErrEpochDivergence) {
		t.Fatalf("got %v", err)
	}
	for _, c := range f.calls() {
		if clIsMutation(c) || strings.HasPrefix(c, "write ") {
			t.Fatalf("%s", c)
		}
	}
}

func TestEnsureCluster_RefusesBadSpec(t *testing.T) {
	a, f, s, _ := clSetup(t)
	for name, mod := range map[string]func(*Spec){
		"ref":    func(s *Spec) { s.Ref = "../x" },
		"uid":    func(s *Spec) { s.UID = 0 },
		"gid":    func(s *Spec) { s.GID = -1 },
		"memory": func(s *Spec) { s.MemMB = 0 },
		"pids":   func(s *Spec) { s.Pids = 0 },
		"slice":  func(s *Spec) { s.SubnetIndex = 1024 },
	} {
		bad := s
		mod(&bad)
		if err := a.EnsureCluster(context.Background(), bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if len(f.calls()) != 0 {
		t.Fatalf("calls %q", f.calls())
	}
}

// ───────── adoption at an equal generation ─────────

func TestEnsureCluster_EqualGenerationAdoptsRunning(t *testing.T) {
	a, f, s, pg := clSetup(t)
	c := clToPhaseB(t, a, f, s)
	st := clReadState(t, a, s)
	if st.PMPid != c.Pid {
		t.Fatalf("state %+v, container pid %d", st, c.Pid)
	}
	n := len(pg.targets)
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("adoption mutated: %q", m)
	}
	calls := strings.Join(f.calls(), "\n")
	for _, want := range []string{"inspect network proj-" + s.Ref, "ip -j -d addr show dev spp14", "inspect network platform"} {
		if !strings.Contains(calls, want) {
			t.Errorf("CheckAdopted not called (%q missing):\n%s", want, calls)
		}
	}
	for _, bad := range []string{"nft check", "bootstrap run", "assert", "archiver", "write "} {
		if strings.Contains(calls, bad) {
			t.Errorf("adoption ran %q:\n%s", bad, calls)
		}
	}
	if len(pg.targets) != n+1 {
		t.Errorf("HealthWait 0 must wait for a login once: %d dials", len(pg.targets)-n)
	}
	// Without a health wait (boot's host-side adoption) nothing is dialled.
	s.HealthWait = -1
	f.resetLog()
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if len(pg.targets) != n+1 || len(f.mutations()) != 0 {
		t.Fatalf("negative HealthWait: %d dials, mutations %q", len(pg.targets)-n, f.mutations())
	}
	if got := clCtr(t, f, "pg-"+s.Ref); got.ID != c.ID || got.Pid != c.Pid {
		t.Fatal("container replaced")
	}
}

func TestEnsureCluster_AdoptedFailsGate_Stops(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clToPhaseB(t, a, f, s)
	f.ip["-j -d addr show dev spp14"] = bridgeIface("spp14", true)
	wantContainment(t, a.EnsureCluster(context.Background(), s), "adoption on a bridge with an address")
	m := f.mutations()
	if !slices.Equal(m, []string{"docker rm -f -v -- pg-" + s.Ref}) {
		t.Fatalf("mutations %q, want one forced removal, no stop, nothing started", m)
	}
	// A removal that fails is joined; the refusal stays matchable.
	a, f, s, _ = clSetup(t)
	clToPhaseB(t, a, f, s)
	f.ip["-j -d addr show dev spp14"] = bridgeIface("spp14", true)
	f.failVerb["rm"] = errors.New("docker rm: daemon busy")
	err := a.EnsureCluster(context.Background(), s)
	wantContainment(t, err, "adoption refused, removal failed")
	if !strings.Contains(err.Error(), "daemon busy") {
		t.Fatalf("removal error not reported: %v", err)
	}
}

// clRemovedAndRerun wants exactly: the removal of the old container (a
// running networked one stopped with its grace period, graceful; anything
// else rm -f), the create, the gate, the start, the state written with the
// new process, and no bootstrap.
func clRemovedAndRerun(t *testing.T, a *Agent, f *fakeHost, s Spec, old *fakeCtr, graceful bool) {
	t.Helper()
	calls := f.calls()
	m := f.mutations()
	removal := []string{"docker rm -f -v -- pg-" + s.Ref}
	if graceful {
		removal = []string{"docker stop -t 45 -- pg-" + s.Ref, "docker rm -v -- pg-" + s.Ref}
	}
	if len(m) != len(removal)+2 || !slices.Equal(m[:len(removal)], removal) || !clIsClusterRun(s.Ref)(m[len(removal)]) ||
		m[len(removal)+1] != "docker start -- pg-"+s.Ref {
		t.Fatalf("mutations %q, want removal %q", m, removal)
	}
	clGateThenStart(t, calls, s.Ref)
	if slices.Contains(calls, "bootstrap run") {
		t.Fatal("bootstrap ran again")
	}
	c := clCtr(t, f, "pg-"+s.Ref)
	st := clReadState(t, a, s)
	if c.ID == old.ID || st.Phase != PhaseB || st.PMPid != c.Pid || st.PMPid == old.Pid || st.PMStart != uint64(c.Pid)*10 ||
		st.Generation != s.Generation || st.Epoch != s.Epoch {
		t.Fatalf("after re-run: state %+v, container %s pid %d (old %s pid %d)", st, c.ID, c.Pid, old.ID, old.Pid)
	}
	if run := clRuns(f, "pg-"+s.Ref); clLabel(run[0], "supapace.phase") != "supapace.phase=B" {
		t.Fatalf("re-run phase %q", clLabel(run[0], "supapace.phase"))
	}
}

func TestEnsureCluster_RunningButStateMissing_RemovedAndRerun(t *testing.T) {
	a, f, s, _ := clSetup(t)
	old := *clToPhaseB(t, a, f, s)
	// What the disk holds when the daemon died between `docker run` and the
	// state write of the first phase-B start.
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	f.resetLog()
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	clRemovedAndRerun(t, a, f, s, &old, true)
	// Even with the running process recorded, A-done is never adopted: the
	// first phase-B start always runs the blocking assertion.
	old = *clCtr(t, f, "pg-"+s.Ref)
	st := clReadState(t, a, s)
	st.Phase = PhaseADone
	clState(t, a, s, st)
	f.resetLog()
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	clRemovedAndRerun(t, a, f, s, &old, true)
	if !slices.Contains(f.calls(), "assert") {
		t.Fatal("no assertion at the first phase-B start")
	}
}

func TestEnsureCluster_RunningButPidMismatch_RemovedAndRerun(t *testing.T) {
	for _, c := range []string{"pid", "start time", "start time unreadable"} {
		t.Run(c, func(t *testing.T) {
			a, f, s, pg := clSetup(t)
			old := *clToPhaseB(t, a, f, s)
			st := clReadState(t, a, s)
			switch c {
			case "pid":
				st.PMPid++
				clState(t, a, s, st)
			case "start time":
				pg.starts[old.Pid] = st.PMStart + 1
			default:
				pg.startErrs[old.Pid] = errors.New("no such process")
			}
			f.resetLog()
			if err := a.EnsureCluster(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			clRemovedAndRerun(t, a, f, s, &old, true)
		})
	}
}

func TestEnsureCluster_EqualGenerationStartsStopped(t *testing.T) {
	a, f, s, _ := clSetup(t)
	old := *clToPhaseB(t, a, f, s)
	f.mu.Lock()
	f.ctrs["pg-"+s.Ref].Running, f.ctrs["pg-"+s.Ref].Pid = false, 0
	f.mu.Unlock()
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	clRemovedAndRerun(t, a, f, s, &old, false)
	if slices.Contains(f.calls(), "assert") {
		t.Fatal("the assertion blocked a start after create")
	}
}

func TestEnsureCluster_EqualGenerationStartsAbsent(t *testing.T) {
	a, f, s, pg := clSetup(t)
	old := *clToPhaseB(t, a, f, s)
	f.mu.Lock()
	delete(f.ctrs, "pg-"+s.Ref)
	f.mu.Unlock()
	pg.findings = []nodecfg.CheckResult{{Name: "superuser", Detail: "x"}} // advisory after create: never consulted here
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	m := f.mutations()
	if len(m) != 2 || !clIsClusterRun(s.Ref)(m[0]) || m[1] != "docker start -- pg-"+s.Ref {
		t.Fatalf("mutations %q", m)
	}
	calls := f.calls()
	clGateThenStart(t, calls, s.Ref)
	if slices.Contains(calls, "bootstrap run") || slices.Contains(calls, "assert") {
		t.Fatalf("calls %q", calls)
	}
	if st := clReadState(t, a, s); st.PMPid == old.Pid || st.PMPid != clCtr(t, f, "pg-"+s.Ref).Pid {
		t.Fatalf("state %+v", st)
	}
}

func TestEnsureCluster_NewGenerationRecreates(t *testing.T) {
	a, f, s, _ := clSetup(t)
	old := *clToPhaseB(t, a, f, s)
	s.Generation, s.HealthWait = 2, -1
	s.GUC = map[string]string{"max_connections": "150"}
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	clRemovedAndRerun(t, a, f, s, &old, true)
	if !strings.Contains(string(clRead(t, filepath.Join(a.p.RenderDir(s.Ref), "conf.d", pgconf.OverrideFile))), "max_connections = 150") {
		t.Fatal("new generation's configuration not rendered")
	}
	if n := slices.IndexFunc(f.calls(), clPrefix("dial ")); n >= 0 {
		t.Fatal("negative HealthWait dialled")
	}
}

func TestEnsureCluster_RecordsPostmasterPidAndStart(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	c := clCtr(t, f, "pg-"+s.Ref)
	st := clReadState(t, a, s)
	if st.PMPid != c.Pid || st.PMPid <= 1 || st.PMStart != uint64(c.Pid)*10 || st.ListenerPid != 0 || st.ListenerStart != 0 {
		t.Fatalf("state %+v, container pid %d", st, c.Pid)
	}
	tg := pg.targets[len(pg.targets)-1]
	if tg.PostmasterPid != st.PMPid || tg.PostmasterStart != st.PMStart {
		t.Fatalf("dialled %v, recorded %+v", tg, st)
	}
	// A container that does not report a live pid is refused, not recorded.
	a, f, s, _ = clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if args[0] == "start" {
			f.mu.Lock()
			defer f.mu.Unlock()
			c := f.ctrs["pg-"+s.Ref]
			c.Running, c.Pid = true, 1
			return "", nil, true
		}
		return "", nil, false
	}
	if err := a.EnsureCluster(context.Background(), s); err == nil {
		t.Fatal("pid 1 recorded")
	}
	if st := clReadState(t, a, s); st.Phase != PhaseADone {
		t.Fatalf("state %+v", st)
	}
}

// TestEnsureCluster_StateGenerationMustAgree: a container labelled with the
// desired generation whose process state.json records under an older one
// (no state write after its run) is not adopted.
func TestEnsureCluster_StateGenerationMustAgree(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clToPhaseB(t, a, f, s)
	s.Generation = 2
	f.mu.Lock()
	f.ctrs["pg-"+s.Ref].Labels["supapace.generation"] = "2"
	old := *f.ctrs["pg-"+s.Ref]
	f.mu.Unlock()
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	clRemovedAndRerun(t, a, f, s, &old, true)
}

func TestEnsureCluster_AdoptionComparesImageAndConfigLabels(t *testing.T) {
	for _, label := range []string{"supapace.image", "supapace.config", "supapace.generation", "supapace.epoch",
		"supapace.phase", "supapace.ref", "supapace.role"} {
		t.Run(label, func(t *testing.T) {
			a, f, s, _ := clSetup(t)
			old := *clToPhaseB(t, a, f, s)
			f.mu.Lock()
			f.ctrs["pg-"+s.Ref].Labels[label] = "other"
			f.mu.Unlock()
			if err := a.EnsureCluster(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			clRemovedAndRerun(t, a, f, s, &old, label != "supapace.phase") // not labelled networked: removed at once
		})
	}
}

// clHashFiles are the files the configuration label covers, as on disk.
func clHashFiles(a *Agent, s Spec) []string {
	r := a.p.RenderDir(s.Ref)
	return []string{filepath.Join(r, "conf.d", "zz-supapace.conf"), filepath.Join(r, "supautils.conf"),
		filepath.Join(r, "pg_hba.conf"), filepath.Join(r, "pg_ident.conf"), filepath.Join(r, "passwd"), filepath.Join(r, "group"),
		filepath.Join(a.p.ImageDir(a.cfg.Images.Postgres), "postgresql.conf"), filepath.Join(a.p.PlatformDir(), "seccomp.json")}
}

// clHash is the configuration label of a create argv, computed here
// independently: SHA-256 over each option (the label itself left out), "--",
// image and command, then "<base name> sha256=<hex>" of each file, every
// element followed by a NUL.
func clHash(t *testing.T, a *Agent, s Spec, run []string) string {
	i := slices.Index(run, "--")
	var elems []string
	for j := 0; j < i; j++ {
		if run[j] == "--label" && strings.HasPrefix(run[j+1], "supapace.config=") {
			j++
			continue
		}
		elems = append(elems, run[j])
	}
	elems = append(elems, run[i:]...)
	for _, p := range clHashFiles(a, s) {
		sum := sha256.Sum256(clRead(t, p))
		elems = append(elems, filepath.Base(p)+" sha256="+hex.EncodeToString(sum[:]))
	}
	h := sha256.New()
	for _, e := range elems {
		h.Write([]byte(e))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func clLastRun(t *testing.T, f *fakeHost, name string) []string {
	t.Helper()
	r := clRuns(f, name)
	if len(r) == 0 {
		t.Fatalf("no create of %s", name)
	}
	return r[len(r)-1]
}

func TestEnsureCluster_ConfigLabelFromDisk(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clToPhaseB(t, a, f, s)
	c := clCtr(t, f, "pg-"+s.Ref)
	if got, want := c.Labels["supapace.config"], clHash(t, a, s, c.Argv); got != want {
		t.Fatalf("label %s, files on disk hash to %s", got, want)
	}
	for _, p := range clHashFiles(a, s) {
		notRendered := strings.HasSuffix(p, "postgresql.conf") || strings.HasSuffix(p, "seccomp.json") // not re-rendered by a start
		t.Run(filepath.Base(p), func(t *testing.T) {
			old := *clCtr(t, f, "pg-"+s.Ref)
			orig := clRead(t, p)
			os.Chmod(p, 0o644)
			if err := os.WriteFile(p, append(slices.Clone(orig), "# edited\n"...), 0o644); err != nil {
				t.Fatal(err)
			}
			f.resetLog()
			if err := a.EnsureCluster(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			if notRendered { // restore it
				os.WriteFile(p, orig, 0o644)
			}
			clRemovedAndRerun(t, a, f, s, &old, true)
			if got, want := clCtr(t, f, "pg-"+s.Ref).Labels["supapace.config"], clHash(t, a, s, clLastRun(t, f, "pg-"+s.Ref)); !notRendered && got != want {
				t.Fatalf("label after re-run %s, files hash to %s", got, want)
			}
			f.resetLog()
			if err := a.EnsureCluster(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			if !notRendered && len(f.mutations()) != 0 {
				t.Fatalf("not adopted after re-run: %q", f.mutations())
			}
		})
	}
}

// ───────── rendering ─────────

func TestEnsureCluster_RendersPlatformFiles(t *testing.T) {
	a, f, s, _ := clSetup(t)
	r := a.p.RenderDir(s.Ref)
	mkdirs(t, filepath.Dir(r), r, filepath.Join(r, "conf.d"))
	os.Chmod(filepath.Dir(a.p.PlatformDir()), 0o700)
	os.WriteFile(filepath.Join(r, "conf.d", "stale.conf"), []byte("x"), 0o644)
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	passwd, _ := pgconf.Passwd(clFixture(t, "passwd"), s.UID, s.GID)
	group, _ := pgconf.Group(clFixture(t, "group"), s.GID)
	supa, _ := pgconf.Supautils(clFixture(t, "supautils.conf"), false)
	hba, _ := pgconf.HBA(a.cfg.Slice(s.SubnetIndex))
	conf, _ := pgconf.Overrides(nil, 512)
	want := map[string][]byte{"passwd": passwd, "group": group, "supautils.conf": supa, "pg_hba.conf": hba,
		"pg_ident.conf": pgconf.Ident(), "conf.d/zz-supapace.conf": conf}
	ents, _ := os.ReadDir("../pgconf/testdata/image/conf.d")
	for _, e := range ents {
		want["conf.d/"+e.Name()] = clFixture(t, "conf.d/"+e.Name())
	}
	for name, data := range want {
		p := filepath.Join(r, name)
		w, ok := f.writes[p]
		if !ok || !bytes.Equal(w.Data, data) || w.Mode != 0o444 || w.UID != os.Geteuid() || w.GID != os.Getegid() {
			t.Errorf("%s: written %v mode %o %d:%d", name, ok, w.Mode, w.UID, w.GID)
		}
	}
	got, _ := os.ReadDir(filepath.Join(r, "conf.d"))
	if len(got) != len(ents)+1 {
		t.Errorf("conf.d holds %d entries, want %d (stale file kept?)", len(got), len(ents)+1)
	}
	key := f.writes[filepath.Join(r, "pgsodium_root.key")]
	if string(key.Data) != s.Secrets.PgsodiumRootKey || key.Mode != 0o400 || key.UID != s.UID || key.GID != s.GID {
		t.Errorf("pgsodium key written mode %o owner %d:%d", key.Mode, key.UID, key.GID)
	}
	for _, d := range []string{filepath.Dir(r), r, filepath.Join(r, "conf.d"), filepath.Join(r, "tools")} {
		if fi, err := os.Lstat(d); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v %v", d, fi, err)
		}
	}
	if ents, _ := os.ReadDir(filepath.Join(r, "tools")); len(ents) != 0 {
		t.Errorf("tools not empty: %v", ents)
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "chown ") || (strings.HasPrefix(c, "write ") && strings.Contains(c, a.p.ProjectsDir())) {
			t.Errorf("root acted below the projects directory: %s", c)
		}
	}
}

func TestEnsureCluster_PgsodiumKeyNotReplaced(t *testing.T) {
	a, f, s, _ := clSetup(t)
	r := a.p.RenderDir(s.Ref)
	mkdirs(t, filepath.Dir(r), r)
	os.Chmod(filepath.Dir(a.p.PlatformDir()), 0o700)
	key := filepath.Join(r, "pgsodium_root.key")
	os.WriteFile(key, []byte("kept"), 0o400)
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if _, wrote := f.writes[key]; wrote || string(clRead(t, key)) != "kept" {
		t.Fatal("an existing pgsodium key was rewritten")
	}
	// A key that is not a regular file is refused, never followed.
	a, _, s, _ = clSetup(t)
	r = a.p.RenderDir(s.Ref)
	mkdirs(t, filepath.Dir(r), r)
	os.Chmod(filepath.Dir(a.p.PlatformDir()), 0o700)
	os.Symlink("/etc/hostname", filepath.Join(r, "pgsodium_root.key"))
	if err := a.EnsureCluster(context.Background(), s); err == nil {
		t.Fatal("a link at the key path was accepted")
	}
	// No key in the spec: refused before anything starts.
	a, f, s, _ = clSetup(t)
	s.Secrets.PgsodiumRootKey = ""
	if err := a.EnsureCluster(context.Background(), s); err == nil || len(f.mutations()) != 0 {
		t.Fatalf("empty key: %v, mutations %q", err, f.mutations())
	}
}

func TestEnsureCluster_IncludeDirMustSortLast(t *testing.T) {
	a, f, s, _ := clSetup(t)
	os.WriteFile(filepath.Join(a.p.ImageDir(a.cfg.Images.Postgres), "conf.d", "zzz.conf"), []byte("x = 1\n"), 0o644)
	if err := a.EnsureCluster(context.Background(), s); !errors.Is(err, pgconf.ErrTemplate) {
		t.Fatalf("got %v", err)
	}
	if len(clRuns(f, "pg-"+s.Ref)) != 0 {
		t.Fatal("started")
	}
}

func TestEnsureCluster_MissingImageFilesRefused(t *testing.T) {
	a, f, s, _ := clSetup(t)
	os.Remove(filepath.Join(a.p.ImageDir(a.cfg.Images.Postgres), "postgresql.conf"))
	if err := a.EnsureCluster(context.Background(), s); err == nil || len(clRuns(f, "pg-"+s.Ref)) != 0 {
		t.Fatalf("no image files: %v", err)
	}
}

// ───────── VerifyCluster, CheckCluster, StopCluster ─────────

func TestVerifyCluster_PassesRenderedConfToAssert(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clToPhaseB(t, a, f, s)
	pg.assertConf, pg.assertHBA, pg.targets = nil, nil, nil
	// The rendered files as they are on disk, not as rendered from the spec.
	r := a.p.RenderDir(s.Ref)
	conf := filepath.Join(r, "conf.d", pgconf.OverrideFile)
	os.Chmod(conf, 0o644)
	os.WriteFile(conf, append(clRead(t, conf), "# on disk\n"...), 0o444)
	if err := a.VerifyCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pg.assertConf, clRead(t, conf)) || !bytes.Equal(pg.assertHBA, clRead(t, filepath.Join(r, "pg_hba.conf"))) {
		t.Fatalf("assert got conf %q", pg.assertConf)
	}
	st := clReadState(t, a, s)
	if len(pg.targets) != 1 {
		t.Fatalf("%d sessions, want one", len(pg.targets))
	}
	tg := pg.targets[0]
	if tg.AllowTrust || tg.User != "supabase_admin" || !tg.Superuser || tg.Password != s.Secrets.SupabaseAdminPassword ||
		!bytes.Equal(tg.ScramSalt, s.Secrets.ScramSalts["supabase_admin"]) || tg.PostmasterPid != st.PMPid ||
		tg.PostmasterStart != st.PMStart || tg.UID != s.UID {
		t.Fatalf("target %v", tg)
	}
	calls := f.calls()
	if !slices.Contains(calls, "archiver") || len(f.mutations()) != 0 {
		t.Fatalf("calls %q", calls)
	}
}

func TestVerifyCluster_DriftLoggedNotFailed(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clToPhaseB(t, a, f, s)
	pg.findings = []nodecfg.CheckResult{{Name: "event-triggers", Detail: "trigger t added"}}
	pg.hbaFinds = []nodecfg.CheckResult{{Name: "hba", Detail: "line 1"}}
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)
	if err := a.VerifyCluster(context.Background(), s); err != nil {
		t.Fatalf("drift failed the verification: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, s.Ref) || !strings.Contains(out, "event-triggers") ||
		!strings.Contains(out, "hba") || strings.Contains(out, s.Secrets.SupabaseAdminPassword) {
		t.Fatalf("log %q", out)
	}
	drift, err := a.CheckCluster(context.Background(), s)
	if err != nil || len(drift) != 2 {
		t.Fatalf("CheckCluster: %v %v", drift, err)
	}
}

func TestCheckCluster_OperationalFacts(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clToPhaseB(t, a, f, s)
	pg.archiver = 3
	pg.findings = []nodecfg.CheckResult{{Name: "superuser", Detail: "x"}}
	drift, err := a.CheckCluster(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "failed_count") || len(drift) != 1 {
		t.Fatalf("archiver failures: %v %v", drift, err)
	}
	if err := a.VerifyCluster(context.Background(), s); err == nil {
		t.Fatal("VerifyCluster passed with archiver failures")
	}
	pg.archiver = 0
	pg.dialErrs = []error{pgsock.ErrPeer}
	if err := a.VerifyCluster(context.Background(), s); !errors.Is(err, pgsock.ErrPeer) {
		t.Fatalf("peer: %v", err)
	}
	// Nothing to verify before the cluster's first phase-B start.
	a, _, s, pg = clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	if _, err := a.CheckCluster(context.Background(), s); err == nil || len(pg.targets) != 0 {
		t.Fatalf("A-done: %v, %d dials", err, len(pg.targets))
	}
	a, _, s, pg = clSetup(t)
	if err := a.VerifyCluster(context.Background(), s); err == nil || len(pg.targets) != 0 {
		t.Fatalf("no state: %v, %d dials", err, len(pg.targets))
	}
}

func TestStopCluster_StopThenRemove(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clToPhaseB(t, a, f, s)
	if err := a.StopCluster(context.Background(), s.Ref); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); !slices.Equal(m, []string{"docker stop -t 45 -- pg-" + s.Ref, "docker rm -v -- pg-" + s.Ref}) {
		t.Fatalf("mutations %q", m)
	}
	f.resetLog()
	if err := a.StopCluster(context.Background(), s.Ref); err != nil || len(f.mutations()) != 0 {
		t.Fatalf("absent: %v %q", err, f.mutations())
	}
	if err := a.StopCluster(context.Background(), "../x"); err == nil {
		t.Fatal("bad ref accepted")
	}
	// Removed by someone else between the stop and the rm: still nil.
	clToPhaseB(t, a, f, s)
	f.failVerb["rm"] = errors.New("docker rm: no such container")
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if args[0] == "rm" {
			f.mu.Lock()
			delete(f.ctrs, "pg-"+s.Ref)
			f.mu.Unlock()
		}
		return "", nil, false
	}
	if err := a.StopCluster(context.Background(), s.Ref); err != nil {
		t.Fatalf("gone in between: %v", err)
	}
}

// ───────── task containers ─────────

func TestPrevalidate_FlagsAndCandidateDir(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clToPhaseB(t, a, f, s)
	r := a.p.RenderDir(s.Ref)
	live := map[string][]byte{}
	ents, _ := os.ReadDir(filepath.Join(r, "conf.d"))
	for _, e := range ents {
		live[e.Name()] = clRead(t, filepath.Join(r, "conf.d", e.Name()))
	}
	next := s
	next.Generation = 2
	next.GUC = map[string]string{"max_connections": "200"}
	pg.taskOut["prevalidate"] = "200\n"
	f.resetLog()
	if err := a.Prevalidate(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	args := clOneRun(t, f, "task-"+s.Ref+"-prevalidate")
	clHardenedTask(t, a, next, args, "prevalidate")
	cand := filepath.Join(r, "candidate", "conf.d")
	clWantPairs(t, "prevalidate", args,
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=1m,mode=0700,uid=700005,gid=700005",
		"-v", r+"/passwd:/etc/passwd:ro", "-v", r+"/group:/etc/group:ro",
		"-v", r+"/supautils.conf:/etc/postgresql-custom/supautils.conf:ro",
		"-v", cand+":/etc/postgresql-custom/conf.d:ro", "--entrypoint", "postgres")
	if n := len(flagValues(args, "-v")); n != 4 {
		t.Errorf("%d mounts, want the four platform files only", n)
	}
	for _, v := range flagValues(args, "-v") {
		if strings.Contains(v, a.p.ProjectsDir()) || strings.Contains(v, "pgsodium") || strings.HasPrefix(v, r+"/conf.d") {
			t.Errorf("prevalidate mounts %s", v)
		}
	}
	cl, _ := pgconf.CommandLine(clFixture(t, "postgresql.conf"))
	want := append(append([]string{a.cfg.Images.Postgres, "-D", "/etc/postgresql"}, cl...),
		"-C", "max_connections")
	if got := positional(args); !slices.Equal(got, want) {
		t.Errorf("command %q\nwant    %q", got, want)
	}
	if !strings.Contains(string(clRead(t, filepath.Join(cand, pgconf.OverrideFile))), "max_connections = 200") {
		t.Error("candidate not rendered from the spec")
	}
	cents, _ := os.ReadDir(cand)
	if len(cents) != len(ents) {
		t.Errorf("candidate holds %d files, live %d", len(cents), len(ents))
	}
	for name, b := range live {
		if !bytes.Equal(clRead(t, filepath.Join(r, "conf.d", name)), b) {
			t.Errorf("live %s changed", name)
		}
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "write "+filepath.Join(r, "conf.d")+"/") || c == "nft check" || strings.HasPrefix(c, "docker stop") {
			t.Errorf("prevalidate: %s", c)
		}
	}
}

func TestPrevalidate_Refusals(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clToPhaseB(t, a, f, s)
	pg.taskExit["prevalidate"] = "1"
	pg.taskErr["prevalidate"] = "FATAL: \x1b[31minvalid value\x1b[0m for max_connections\x00"
	err := a.Prevalidate(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "invalid value") || strings.ContainsAny(err.Error(), "\x1b\x00") {
		t.Fatalf("refused candidate: %v", err)
	}
	pg.taskExit["prevalidate"], pg.taskOut["prevalidate"] = "0", " \n"
	if err := a.Prevalidate(context.Background(), s); err == nil {
		t.Fatal("empty output passed")
	}
	// Only stdout carries the value: a warning on stderr with an empty stdout
	// is refused, and the warning is reported.
	pg.taskErr["prevalidate"] = "WARNING: something"
	if err := a.Prevalidate(context.Background(), s); err == nil || !strings.Contains(err.Error(), "WARNING: something") {
		t.Fatalf("stderr only: %v", err)
	}
	pg.taskErr["prevalidate"] = ""
	// A value on stdout does not make a non-zero exit pass.
	pg.taskOut["prevalidate"], pg.taskExit["prevalidate"] = "120\n", "1"
	if err := a.Prevalidate(context.Background(), s); err == nil {
		t.Fatal("a non-zero exit with a value passed")
	}
	f.resetLog()
	bad := s
	bad.GUC = map[string]string{"max_connections": "5"}
	if err := a.Prevalidate(context.Background(), bad); !errors.Is(err, pgconf.ErrGUCValue) || len(f.mutations()) != 0 {
		t.Fatalf("bad override: %v %q", err, f.mutations())
	}
	os.Remove(filepath.Join(a.p.RenderDir(s.Ref), "passwd"))
	if err := a.Prevalidate(context.Background(), s); err == nil || len(f.mutations()) != 0 {
		t.Fatalf("missing live file: %v %q", err, f.mutations())
	}
}

func TestPromoteCandidate_Rename(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clToPhaseB(t, a, f, s)
	next := s
	next.GUC = map[string]string{"max_connections": "200"}
	pg.taskOut["prevalidate"] = "200\n"
	if err := a.Prevalidate(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	r := a.p.RenderDir(s.Ref)
	want := clRead(t, filepath.Join(r, "candidate", "conf.d", pgconf.OverrideFile))
	if err := a.PromoteCandidate(context.Background(), s.Ref); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clRead(t, filepath.Join(r, "conf.d", pgconf.OverrideFile)), want) {
		t.Fatal("conf.d is not the candidate")
	}
	if _, err := os.Lstat(filepath.Join(r, "candidate")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate left: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(r, "conf.d")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("conf.d after promotion: %v %v", fi, err)
	}
	if err := a.PromoteCandidate(context.Background(), s.Ref); err != nil {
		t.Fatalf("second promotion: %v", err)
	}
	if !bytes.Equal(clRead(t, filepath.Join(r, "conf.d", pgconf.OverrideFile)), want) {
		t.Fatal("second promotion changed conf.d")
	}
	if err := a.PromoteCandidate(context.Background(), "../x"); err == nil {
		t.Fatal("bad ref accepted")
	}
	// Interrupted after the old directory was removed: resumed.
	pg.taskOut["prevalidate"] = "200\n"
	if err := a.Prevalidate(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Join(r, "conf.d"))
	if err := a.PromoteCandidate(context.Background(), s.Ref); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clRead(t, filepath.Join(r, "conf.d", pgconf.OverrideFile)), want) {
		t.Fatal("resumed promotion")
	}
}

func clProjectDir(t *testing.T, a *Agent, s Spec) {
	t.Helper()
	mkdirs(t, a.p.ProjectsDir(), filepath.Join(a.p.ProjectDir(s.Ref), "data"), filepath.Join(a.p.ProjectDir(s.Ref), "sock"))
}

func TestPurgeDir_RunsAtProjectUID(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clProjectDir(t, a, s)
	if err := a.PurgeDir(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	args := clOneRun(t, f, "task-"+s.Ref+"-purge")
	clHardenedTask(t, a, s, args, "purge")
	clWantPairs(t, "purge", args, "-v", "/opt/test/supapaced:/supapaced:ro", "-v", a.p.ProjectDir(s.Ref)+":/p",
		"--entrypoint", "/supapaced")
	if n := len(flagValues(args, "-v")); n != 2 {
		t.Errorf("purge mounts %d paths", n)
	}
	if got := positional(args); !slices.Equal(got, []string{a.cfg.Images.Postgres, "rmtree", "/p/data", "/p/sock"}) {
		t.Errorf("purge command %q", got)
	}
	calls := f.calls()
	var own []string
	for _, c := range calls {
		if !strings.HasPrefix(c, "docker ") && !strings.HasPrefix(c, "inspect ") {
			own = append(own, c)
		}
	}
	if !slices.Equal(own, []string{"setQuota 700005 0", "removeEmptyProjectDir " + s.Ref}) {
		t.Fatalf("root's own calls %q", own)
	}
	if slices.Index(calls, "setQuota 700005 0") > clIndex(calls, func(c string) bool { return strings.HasPrefix(c, "docker run -d --name task-") }) {
		t.Fatal("the quota limits were not cleared before the purge task")
	}
	if slices.Index(calls, "removeEmptyProjectDir "+s.Ref) < clLastIndex(calls, "docker rm -f -v -- task-"+s.Ref+"-purge") {
		t.Fatal("directory removed before the task was done")
	}
	if slices.Contains(calls, "nft check") {
		t.Fatal("a task container went through the gate")
	}
}

func TestPurgeDir_AbsentDirLaunchesNothing(t *testing.T) {
	a, f, s, _ := clSetup(t)
	if err := a.PurgeDir(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "docker ") || strings.HasPrefix(c, "removeEmptyProjectDir") {
			t.Fatalf("absent directory: %s", c)
		}
	}
	if !slices.Contains(f.calls(), "setQuota 700005 0") {
		t.Fatal("quota not cleared")
	}
	if err := a.PurgeDir(context.Background(), Spec{Ref: "../x", UID: 1}); err == nil {
		t.Fatal("bad ref accepted")
	}
}

func TestPurgeDir_TaskFailureKeepsDir(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clProjectDir(t, a, s)
	pg.taskExit["purge"] = "1"
	pg.taskErr["purge"] = "rmtree: /p/data: busy"
	if err := a.PurgeDir(context.Background(), s); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("got %v", err)
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "removeEmptyProjectDir") {
			t.Fatalf("went on after a failed task: %s", c)
		}
	}
	// The helper's path comes from the seam, and its failure starts nothing.
	daemonExe = func() (string, error) { return "", errors.New("no executable") }
	f.resetLog()
	if err := a.PurgeDir(context.Background(), s); err == nil || len(f.mutations()) != 0 {
		t.Fatalf("no executable: %v %q", err, f.mutations())
	}
}

func TestTask_DetachedNamedAndPolled(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clProjectDir(t, a, s)
	pg.taskPoll["purge"] = []string{"created 0", "running 0", "running 0"}
	if err := a.PurgeDir(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	name := "task-" + s.Ref + "-purge"
	var seq []string
	for _, c := range f.argv() {
		if clLast(c) == name || flagValue(c, "--name") == name {
			seq = append(seq, c[0])
			if c[0] == "inspect" && !slices.Equal(c, []string{"inspect", "--type", "container", "--format",
				"{{.State.Status}} {{.State.ExitCode}}", "--", name}) {
				t.Errorf("poll %q", c)
			}
		}
	}
	if want := []string{"rm", "run", "inspect", "inspect", "inspect", "inspect", "logs", "rm"}; !slices.Equal(seq, want) {
		t.Fatalf("task calls %q, want %q", seq, want)
	}
	if args := clOneRun(t, f, name); slices.Contains(clFlags(args), "--rm") || !slices.Contains(clFlags(args), "-d") {
		t.Fatalf("not detached: %q", args)
	}
	if c, _ := dockerInspectContainer(context.Background(), name); c != nil {
		t.Fatal("task container left")
	}
}

func TestTask_KilledByNameAtDeadline(t *testing.T) {
	for _, c := range []string{"step deadline", "task bound"} {
		t.Run(c, func(t *testing.T) {
			a, f, s, pg := clSetup(t)
			clProjectDir(t, a, s)
			name := "task-" + s.Ref + "-purge"
			pg.taskPoll["purge"] = slices.Repeat([]string{"running 0"}, 10000)
			var mu sync.Mutex
			var rmCtxErr []error
			inner := dockerRun
			dockerRun = func(ctx context.Context, args ...string) (string, error) {
				if args[0] == "rm" {
					mu.Lock()
					rmCtxErr = append(rmCtxErr, ctx.Err())
					mu.Unlock()
				}
				return inner(ctx, args...)
			}
			defer func() { dockerRun = inner }()
			ctx := context.Background()
			if c == "step deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
				defer cancel()
			} else {
				defer swap(&taskTimeout, 30*time.Millisecond)()
			}
			err := a.PurgeDir(ctx, s)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("got %v", err)
			}
			calls := f.calls()
			if calls[len(calls)-1] != "docker rm -f -v -- "+name {
				t.Fatalf("last call %q", calls[len(calls)-1])
			}
			mu.Lock()
			defer mu.Unlock()
			if len(rmCtxErr) != 2 || rmCtxErr[1] != nil {
				t.Fatalf("kill by name on a done context: %v", rmCtxErr)
			}
			if slices.Contains(calls, "removeEmptyProjectDir "+s.Ref) {
				t.Fatal("went on after the deadline")
			}
		})
	}
	if taskTimeout != 300*time.Second {
		t.Fatalf("task bound %v", taskTimeout)
	}
}

func TestTask_LeftoverRemovedFirst(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clProjectDir(t, a, s)
	name := "task-" + s.Ref + "-purge"
	f.ctr(fakeCtr{Name: name, Labels: map[string]string{"supapace.role": "task"}})
	f.resetLog()
	if err := a.PurgeDir(context.Background(), s); err != nil {
		t.Fatalf("leftover caused %v", err)
	}
	m := f.mutations()
	if len(m) < 2 || m[0] != "docker rm -f -v -- "+name || !strings.HasPrefix(m[1], "docker run -d --name "+name+" ") {
		t.Fatalf("mutations %q", m)
	}
}

func TestTask_OutputHandled(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clProjectDir(t, a, s)
	pg.logsErr = fmt.Errorf("docker logs: %w", dockerx.ErrOutputTooLarge)
	if err := a.PurgeDir(context.Background(), s); err != nil {
		t.Fatalf("a successful task with oversized output: %v", err)
	}
	pg.taskExit["purge"] = "2"
	err := a.PurgeDir(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "exit 2") || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("got %v", err)
	}
	if c, _ := dockerInspectContainer(context.Background(), "task-"+s.Ref+"-purge"); c != nil {
		t.Fatal("task container left")
	}
	// A poll that cannot be parsed or fails is an error, and the task is removed.
	pg.logsErr = nil
	for _, poll := range []string{"bogus", "exited x"} {
		pg.taskPoll["purge"] = []string{poll}
		f.resetLog()
		if err := a.PurgeDir(context.Background(), s); err == nil {
			t.Fatalf("poll %q accepted", poll)
		}
		if calls := f.calls(); calls[len(calls)-1] != "docker rm -f -v -- task-"+s.Ref+"-purge" {
			t.Fatalf("not removed after poll %q", poll)
		}
	}
}

// clGateThenStart wants, before the last call (a start of pg-<ref>): the
// container's create, then the gate, and after the gate's first condition
// nothing but the gate's own reads — no Docker call between the gate and
// the start.
func clGateThenStart(t *testing.T, calls []string, ref string) {
	t.Helper()
	start := clLastIndex(calls, "docker start -- pg-"+ref)
	gate := clLastIndex(calls[:max(start, 0)], "nft check")
	create := -1
	for i := gate - 1; i >= 0; i-- {
		if clIsClusterRun(ref)(calls[i]) {
			create = i
			break
		}
	}
	if start < 0 || gate < 0 || create < 0 || calls[gate-1] != "bridge-nf" {
		t.Fatalf("create %d, gate %d, start %d:\n%s", create, gate, start, strings.Join(calls, "\n"))
	}
	for _, c := range calls[create+1 : gate-1] {
		if strings.HasPrefix(c, "docker ") {
			t.Fatalf("%q between the create and the gate", c)
		}
	}
	for _, c := range calls[gate+1 : start] {
		if !slices.ContainsFunc([]string{"inspect container ", "inspect network ", "ip -j -d addr show dev ",
			"docker container inspect --format ", "docker network inspect --format ", "docker ps -a -q --no-trunc"},
			func(p string) bool { return strings.HasPrefix(c, p) }) {
			t.Fatalf("%q between the gate and the start", c)
		}
	}
}

// ───────── exact argument sets ─────────

// clOptionSet is the options of a run argv (before "--") as sorted
// "flag value" items, boolean flags alone, so that a test compares the whole
// set: a flag added or dropped anywhere fails it.
func clOptionSet(args []string) []string {
	boolean := map[string]bool{"-d": true, "--read-only": true, "--no-healthcheck": true, "--rm": true, "--privileged": true,
		"--init": true, "--oom-kill-disable": true}
	fl := clFlags(args)
	var out []string
	for i := 1; i < len(fl); i++ { // fl[0] is the verb
		if boolean[fl[i]] || i+1 == len(fl) {
			out = append(out, fl[i])
			continue
		}
		out = append(out, fl[i]+" "+fl[i+1])
		i++
	}
	slices.Sort(out)
	return out
}

func clWantOptions(t *testing.T, what string, args []string, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := clOptionSet(args); !slices.Equal(got, want) {
		t.Errorf("%s: options\n got  %q\n want %q", what, got, want)
	}
}

func clClusterCommon(a *Agent, s Spec, phase string) []string {
	r, pd, name := a.p.RenderDir(s.Ref), a.p.ProjectDir(s.Ref), "pg-"+s.Ref
	return []string{"--name " + name, "--hostname " + name, fmt.Sprintf("--user %d:%d", s.UID, s.GID), "--cap-drop ALL",
		"--security-opt no-new-privileges", "--security-opt seccomp=" + filepath.Join(a.p.PlatformDir(), "seccomp.json"),
		"--read-only", "--tmpfs /tmp:rw,noexec,nosuid,size=64m", fmt.Sprintf("--memory %dm", s.MemMB),
		fmt.Sprintf("--memory-swap %dm", s.MemMB), "--cpus 1", fmt.Sprintf("--pids-limit %d", s.Pids), "--shm-size 64m",
		"--ulimit core=0", "--ulimit nofile=65536:65536", "--no-healthcheck", "--ipc private", "--stop-timeout 45",
		"--label supapace.role=cluster", "--label supapace.ref=" + s.Ref, "--label supapace.phase=" + phase,
		fmt.Sprintf("--label supapace.generation=%d", s.Generation), fmt.Sprintf("--label supapace.epoch=%d", s.Epoch),
		"-v " + pd + "/data:/var/lib/postgresql/data", "-v " + pd + "/sock:/var/run/postgresql",
		"-v " + r + "/passwd:/etc/passwd:ro", "-v " + r + "/group:/etc/group:ro",
		"-v " + r + "/pgsodium_root.key:/etc/postgresql-custom/pgsodium_root.key:ro",
		"-v " + r + "/conf.d:/etc/postgresql-custom/conf.d:ro",
		"-v " + r + "/supautils.conf:/etc/postgresql-custom/supautils.conf:ro",
		"-v " + r + "/tools:/opt/supapace/tools:ro"}
}

// TestEnsureCluster_ExactOptions: every option of both phases, and nothing
// else; limits from the spec.
func TestEnsureCluster_ExactOptions(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clProjectDir(t, a, s)
	s.MemMB, s.Pids = 640, 300
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	runA := clOneRun(t, f, "pg-"+s.Ref)
	pw := ""
	for _, e := range flagValues(runA, "-e") {
		pw, _ = strings.CutPrefix(e, "POSTGRES_PASSWORD=")
	}
	clWantOptions(t, "phase A", runA, append(clClusterCommon(a, s, "A"), "--network none", "-e POSTGRES_PASSWORD="+pw)...)
	if runA[0] != "create" {
		t.Errorf("phase A verb %q", runA[0])
	}
	f.resetLog()
	f.mu.Lock()
	f.dargs = nil
	f.mu.Unlock()
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	runB := clOneRun(t, f, "pg-"+s.Ref)
	r := a.p.RenderDir(s.Ref)
	clWantOptions(t, "phase B", runB, append(clClusterCommon(a, s, "B"),
		"--network proj-"+s.Ref, "--ip "+a.cfg.ClusterAddr(s.SubnetIndex).String(),
		"--sysctl net.ipv6.conf.all.disable_ipv6=1", "--sysctl net.ipv4.ping_group_range=1 0",
		"-v "+r+"/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro", "-v "+r+"/pg_ident.conf:/etc/postgresql/pg_ident.conf:ro",
		"--label supapace.image="+a.cfg.Images.Postgres, "--label supapace.config="+clHash(t, a, s, runB))...)
}

func clTaskCommon(a *Agent, s Spec, kind string) []string {
	return []string{"-d", "--name task-" + s.Ref + "-" + kind, "--network none", fmt.Sprintf("--user %d:%d", s.UID, s.GID),
		"--cap-drop ALL", "--security-opt no-new-privileges", "--security-opt seccomp=" + filepath.Join(a.p.PlatformDir(), "seccomp.json"),
		"--read-only", "--memory 128m", "--memory-swap 128m", "--pids-limit 64", "--ulimit core=0", "--ulimit nofile=65536:65536", "--no-healthcheck",
		"--label supapace.role=task", "--label supapace.ref=" + s.Ref, fmt.Sprintf("--label supapace.generation=%d", s.Generation),
		fmt.Sprintf("--label supapace.epoch=%d", s.Epoch)}
}

// TestTask_ExactOptions: every option of the three task containers, and
// nothing else.
func TestTask_ExactOptions(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clProjectDir(t, a, s)
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	pd := a.p.ProjectDir(s.Ref)
	clWantOptions(t, "wipe", clOneRun(t, f, "task-"+s.Ref+"-wipe"), append(clTaskCommon(a, s, "wipe"),
		"-v /opt/test/supapaced:/supapaced:ro", "-v "+pd+":/p", "--entrypoint /supapaced")...)
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	pg.taskOut["prevalidate"] = "120\n"
	if err := a.Prevalidate(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	r := a.p.RenderDir(s.Ref)
	pv := clOneRun(t, f, "task-"+s.Ref+"-prevalidate")
	got := clOptionSet(pv)
	want := append(clTaskCommon(a, s, "prevalidate"), "--tmpfs /tmp:rw,noexec,nosuid,size=64m",
		fmt.Sprintf("--tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=1m,mode=0700,uid=%d,gid=%d", s.UID, s.GID),
		"-v "+r+"/passwd:/etc/passwd:ro", "-v "+r+"/group:/etc/group:ro",
		"-v "+r+"/supautils.conf:/etc/postgresql-custom/supautils.conf:ro",
		"-v "+filepath.Join(r, "candidate", "conf.d")+":/etc/postgresql-custom/conf.d:ro")
	// The entrypoint is not pinned here (a shell wrapper or postgres itself).
	got = slices.DeleteFunc(got, func(o string) bool { return strings.HasPrefix(o, "--entrypoint ") })
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("prevalidate: options\n got  %q\n want %q", got, want)
	}
	if err := a.StopCluster(context.Background(), s.Ref); err != nil {
		t.Fatal(err)
	}
	if err := a.PurgeDir(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	clWantOptions(t, "purge", clOneRun(t, f, "task-"+s.Ref+"-purge"), append(clTaskCommon(a, s, "purge"),
		"-v /opt/test/supapaced:/supapaced:ro", "-v "+pd+":/p", "--entrypoint /supapaced")...)
}

// TestEnsureCluster_GateRefusalRemovesCreated: a container the gate refused
// to start does not stay behind created.
func TestEnsureCluster_GateRefusalRemovesCreated(t *testing.T) {
	for _, st := range []*State{nil, {Phase: PhaseADone}, {Phase: PhaseB, PMPid: 77, PMStart: 770}} {
		a, f, s, _ := clSetup(t)
		clProjectDir(t, a, s)
		if st != nil {
			st.Epoch, st.Generation = s.Epoch, s.Generation
			clState(t, a, s, *st)
		}
		f.nftErr = nft.ErrDrift
		wantContainment(t, a.EnsureCluster(context.Background(), s), "gate refusal")
		if c, _ := dockerInspectContainer(context.Background(), "pg-"+s.Ref); c != nil {
			t.Errorf("state %v: refused container %s left behind", st, c.Name)
		}
		if m := f.mutations(); len(m) == 0 || m[len(m)-1] != "docker rm -f -v -- pg-"+s.Ref {
			t.Errorf("state %v: last mutation %.60q", st, m[len(m)-1])
		}
	}
}

// TestEnsureCluster_WipeNeedsProjectDir: without the project directory no
// task is launched (a bind mount of a missing path would create it as root).
func TestEnsureCluster_WipeNeedsProjectDir(t *testing.T) {
	a, f, s, _ := clSetup(t)
	if err := a.EnsureCluster(context.Background(), s); err == nil {
		t.Fatal("phase A without the project directory")
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "docker run ") || strings.HasPrefix(c, "docker create ") {
			t.Fatalf("launched without the project directory: %s", c)
		}
	}
}

// TestCheckCluster_NoStatementAfterAFailedOne: after a statement of the
// session fails, the session is not used again.
func TestCheckCluster_NoStatementAfterAFailedOne(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clToPhaseB(t, a, f, s)
	defer swap(&archiverFailures, func(ctx context.Context, c *pgx.Conn) (int64, error) {
		f.record("archiver")
		return 0, pgsock.ErrBudget
	})()
	f.resetLog()
	if _, err := a.CheckCluster(context.Background(), s); !errors.Is(err, pgsock.ErrBudget) {
		t.Fatalf("got %v", err)
	}
	if calls := f.calls(); slices.Contains(calls, "assert") || slices.Contains(calls, "assert hba") {
		t.Fatalf("the assertion ran on a failed session: %q", calls)
	}
}

// ───────── bounds and error paths ─────────

func TestEnsureCluster_HealthWaitBounds(t *testing.T) {
	if clusterHealthWait != 120*time.Second {
		t.Fatalf("default health wait %v", clusterHealthWait)
	}
	notReady := errors.New("pgsock: x: socket: connect: connection refused")
	// The first networked start waits even with a negative HealthWait.
	a, _, s, pg := clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	s.HealthWait = -1
	pg.dialErrs = []error{notReady}
	if err := a.EnsureCluster(context.Background(), s); err != nil || len(pg.targets) != 2 {
		t.Fatalf("negative HealthWait at the first start: %v after %d dials", err, len(pg.targets))
	}
	// A positive HealthWait bounds the first start's wait.
	a, _, s, pg = clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	s.HealthWait = 30 * time.Millisecond
	pg.dialAlways = notReady
	start := time.Now()
	if err := a.EnsureCluster(context.Background(), s); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("bounded first start: %v after %v", err, time.Since(start))
	}
}

// TestEnsureCluster_RecreateRecordsBeforeWaiting: a re-created container is
// recorded before the health wait, so a failed wait does not make the next
// ensure replace it again.
func TestEnsureCluster_RecreateRecordsBeforeWaiting(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clToPhaseB(t, a, f, s)
	f.mu.Lock()
	f.ctrs["pg-"+s.Ref].Running, f.ctrs["pg-"+s.Ref].Pid = false, 0
	f.mu.Unlock()
	pg.dialAlways = &pgsock.ServerError{Code: "28P01", Message: "auth failed"}
	if err := a.EnsureCluster(context.Background(), s); err == nil {
		t.Fatal("failed wait passed")
	}
	if st := clReadState(t, a, s); st.PMPid != clCtr(t, f, "pg-"+s.Ref).Pid {
		t.Fatalf("state %+v not the new container", st)
	}
}

func TestCheckCluster_AssertionErrorReported(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clToPhaseB(t, a, f, s)
	defer swap(&bootstrapAssert, func(ctx context.Context, c *pgx.Conn, want bootstrap.Baseline, conf []byte) ([]nodecfg.CheckResult, error) {
		return nil, pgsock.ErrBudget
	})()
	if _, err := a.CheckCluster(context.Background(), s); !errors.Is(err, pgsock.ErrBudget) {
		t.Fatalf("got %v", err)
	}
}

func TestEnsureCluster_FindingsSanitised(t *testing.T) {
	a, _, s, pg := clSetup(t)
	pg.findings = []nodecfg.CheckResult{{Name: "superuser", Detail: "x\x1b[2J\x00y"}}
	if err := a.EnsureCluster(context.Background(), s); err == nil || strings.ContainsAny(err.Error(), "\x1b\x00") {
		t.Fatalf("got %q", err)
	}
}

func TestTask_PollAndLaunchErrors(t *testing.T) {
	// "dead" ends the wait like "exited".
	a, _, s, pg := clSetup(t)
	pg.taskPoll["purge"] = []string{"dead 137"}
	if err := a.PurgeDir(context.Background(), s); err == nil || !strings.Contains(err.Error(), "exit 137") {
		t.Fatalf("dead task: %v", err)
	}
	// A failed poll ends the task at once.
	a, f, s, _ := clSetup(t)
	inner := dockerRun
	dockerRun = func(ctx context.Context, args ...string) (string, error) {
		if args[0] == "inspect" {
			f.record("docker inspect (failing)")
			return "", errors.New("docker inspect: daemon gone")
		}
		return inner(ctx, args...)
	}
	start := time.Now()
	if err := a.PurgeDir(context.Background(), s); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("failed poll: %v after %v", err, time.Since(start))
	}
	dockerRun = inner
	// A failed docker logs does not fail a task that succeeded.
	a, _, s, pg = clSetup(t)
	pg.logsErr = errors.New("docker logs: gone")
	if err := a.PurgeDir(context.Background(), s); err != nil {
		t.Fatalf("logs error failed the task: %v", err)
	}
	// A failed run still removes the name.
	a, f, s, _ = clSetup(t)
	f.failVerb["run"] = errors.New("docker run: refused")
	if err := a.PurgeDir(context.Background(), s); err == nil {
		t.Fatal("failed run passed")
	}
	if calls := f.calls(); calls[len(calls)-1] != "docker rm -f -v -- task-"+s.Ref+"-purge" {
		t.Fatalf("not removed after a failed run: %q", calls[len(calls)-1])
	}
}

func TestPurgeDir_Refusals(t *testing.T) {
	a, f, s, _ := clSetup(t)
	bad := s
	bad.UID = 0
	if err := a.PurgeDir(context.Background(), bad); err == nil || len(f.mutations()) != 0 {
		t.Fatalf("uid 0: %v %q", err, f.mutations())
	}
	os.RemoveAll(a.p.ProjectDir(s.Ref))
	os.WriteFile(a.p.ProjectDir(s.Ref), nil, 0o600)
	if err := a.PurgeDir(context.Background(), s); err == nil || len(f.mutations()) != 0 {
		t.Fatalf("a file at the project path: %v %q", err, f.mutations())
	}
}

func TestPrevalidate_RefusesBadSpecAndOddCandidate(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clToPhaseB(t, a, f, s)
	bad := s
	bad.Pids = 0
	if err := a.Prevalidate(context.Background(), bad); err == nil || len(f.mutations()) != 0 {
		t.Fatalf("bad spec: %v %q", err, f.mutations())
	}
	_ = pg
	r := a.p.RenderDir(s.Ref)
	mkdirs(t, filepath.Join(r, "candidate"))
	os.WriteFile(filepath.Join(r, "candidate", "conf.d"), []byte("x"), 0o600)
	if err := a.PromoteCandidate(context.Background(), s.Ref); err == nil {
		t.Fatal("a file as the candidate was promoted")
	}
	if fi, err := os.Lstat(filepath.Join(r, "conf.d")); err != nil || !fi.IsDir() {
		t.Fatalf("live conf.d: %v %v", fi, err)
	}
}

// TestEnsureCluster_FirstBootRequired: without a state file only a create
// (Spec.FirstBoot) gets a first boot; any other caller is refused and nothing
// is touched. With a state file the flag plays no part.
func TestEnsureCluster_FirstBootRequired(t *testing.T) {
	a, f, s, _ := clSetup(t)
	s.FirstBoot = false
	err := a.EnsureCluster(context.Background(), s)
	if err == nil || !strings.Contains(err.Error(), "first boot") {
		t.Fatalf("no state, not a create: %v", err)
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "docker ") || strings.HasPrefix(c, "write ") || strings.HasPrefix(c, "dial ") {
			t.Fatalf("touched: %s", c)
		}
	}
	if _, ok, _ := a.readState(s.Ref); ok {
		t.Fatal("state written")
	}
	s.FirstBoot = true
	if err := a.EnsureCluster(context.Background(), s); err != nil || len(clRuns(f, "task-"+s.Ref+"-wipe")) != 1 {
		t.Fatalf("a create: %v", err)
	}
	for _, fb := range []bool{false, true} {
		s.FirstBoot = fb
		f.resetLog()
		if err := a.EnsureCluster(context.Background(), s); err != nil { // A-done, then B
			t.Fatalf("FirstBoot %v with a state file: %v", fb, err)
		}
		if len(clRuns(f, "task-"+s.Ref+"-wipe")) != 0 || slices.Contains(f.calls(), "bootstrap run") {
			t.Fatalf("FirstBoot %v with a state file wiped or bootstrapped", fb)
		}
	}
	if st := clReadState(t, a, s); st.Phase != PhaseB {
		t.Fatalf("state %+v", st)
	}
}

// TestEnsureCluster_StartFailure: an address held by another container at
// start is a refusal (the created container is removed); any other failed
// start keeps the container for its logs.
func TestEnsureCluster_StartFailure(t *testing.T) {
	for _, c := range []struct {
		msg     string
		refusal bool
	}{{"Error response from daemon: Address already in use", true}, {"Error response from daemon: OCI runtime error", false}} {
		a, f, s, _ := clSetup(t)
		clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
		f.failVerb["start"] = errors.New("docker start: exit status 1: " + c.msg)
		err := a.EnsureCluster(context.Background(), s)
		if err == nil || errors.Is(err, ErrContainment) != c.refusal {
			t.Fatalf("%s: got %v", c.msg, err)
		}
		gone, _ := dockerInspectContainer(context.Background(), "pg-"+s.Ref)
		if (gone == nil) != c.refusal {
			t.Fatalf("%s: container left %v", c.msg, gone != nil)
		}
		if st := clReadState(t, a, s); st.Phase != PhaseADone {
			t.Fatalf("%s: state %+v", c.msg, st)
		}
	}
}

// TestEnsureCluster_RefusedRemovalOnFreshContext: the refused container is
// removed even when the caller's context ended during the gate, and a failed
// removal leaves the refusal matchable.
func TestEnsureCluster_RefusedRemovalOnFreshContext(t *testing.T) {
	a, f, s, _ := clSetup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer swap(&nftCheck, func(context.Context, nodecfg.Paths) error { cancel(); return nft.ErrDrift })()
	var rmCtxErr error
	inner := dockerRun
	dockerRun = func(c context.Context, args ...string) (string, error) {
		if args[0] == "rm" {
			rmCtxErr = c.Err()
		}
		return inner(c, args...)
	}
	defer func() { dockerRun = inner }()
	wantContainment(t, a.EnsureCluster(ctx, s), "refused, context ended")
	if rmCtxErr != nil {
		t.Fatalf("removal on a done context: %v", rmCtxErr)
	}
	if c, _ := dockerInspectContainer(context.Background(), "pg-"+s.Ref); c != nil {
		t.Fatal("refused container left")
	}
	// A removal that fails is joined; the refusal is still ErrContainment.
	f.failVerb["rm"] = errors.New("docker rm: daemon busy")
	err := a.EnsureCluster(context.Background(), s)
	wantContainment(t, err, "refused, removal failed")
	if !strings.Contains(err.Error(), "daemon busy") {
		t.Fatalf("removal error not reported: %v", err)
	}
}

// TestTask_StderrCappedAndLogsFailure: a refusal's stderr is capped; when
// docker logs itself fails, its own error text is not reported as the
// task's stderr.
func TestTask_StderrCappedAndLogsFailure(t *testing.T) {
	a, f, s, pg := clSetup(t)
	clToPhaseB(t, a, f, s)
	pg.taskExit["prevalidate"] = "1"
	pg.taskErr["prevalidate"] = strings.Repeat("e", 100<<10)
	if err := a.Prevalidate(context.Background(), s); err == nil || len(err.Error()) > 65<<10 {
		t.Fatalf("stderr not capped: %d bytes", len(err.Error()))
	}
	a, _, s, pg = clSetup(t)
	pg.taskExit["purge"] = "1"
	pg.taskErr["purge"] = "docker-logs-own-error"
	pg.logsErr = errors.New("docker logs: gone")
	err := a.PurgeDir(context.Background(), s)
	if err == nil || strings.Contains(err.Error(), "docker-logs-own-error") || !strings.Contains(err.Error(), "output unavailable") {
		t.Fatalf("got %v", err)
	}
}

// TestEnsureCluster_WipeRefusesFileAtProjectPath: a file where the project
// directory should be launches nothing either.
func TestEnsureCluster_WipeRefusesFileAtProjectPath(t *testing.T) {
	a, f, s, _ := clSetup(t)
	os.RemoveAll(a.p.ProjectDir(s.Ref))
	os.WriteFile(a.p.ProjectDir(s.Ref), nil, 0o600)
	if err := a.EnsureCluster(context.Background(), s); err == nil {
		t.Fatal("phase A with a file at the project path")
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "docker run ") || strings.HasPrefix(c, "docker create ") {
			t.Fatalf("launched: %s", c)
		}
	}
}

// TestPurgeDir_QuotaFailureLaunchesNothing: the task runs only once the
// limits are cleared.
func TestPurgeDir_QuotaFailureLaunchesNothing(t *testing.T) {
	a, f, s, _ := clSetup(t)
	defer swap(&setQuota, func(p nodecfg.Paths, uid, mb int) error { return errors.New("quota: refused") })()
	if err := a.PurgeDir(context.Background(), s); err == nil || len(f.mutations()) != 0 {
		t.Fatalf("got %v, mutations %q", err, f.mutations())
	}
}

// TestPurgeDir_RefusesWhileTenantContainerExists: the quota is lifted only
// when neither tenant container exists, in any state; a failed read is an
// error, never "absent".
func TestPurgeDir_RefusesWhileTenantContainerExists(t *testing.T) {
	for _, name := range []string{"pg-", "postgrest-"} {
		a, f, s, _ := clSetup(t)
		f.ctr(fakeCtr{Name: name + s.Ref, CapDrop: []string{"ALL"}}) // created, not running
		f.resetLog()
		err := a.PurgeDir(context.Background(), s)
		if err == nil || !strings.Contains(err.Error(), name+s.Ref) {
			t.Fatalf("%s present: %v", name, err)
		}
		for _, c := range f.calls() {
			if clIsMutation(c) || strings.HasPrefix(c, "setQuota") || strings.HasPrefix(c, "removeEmptyProjectDir") {
				t.Fatalf("%s present: %s", name, c)
			}
		}
	}
	a, f, s, _ := clSetup(t)
	f.failInspect["postgrest-"+s.Ref] = errors.New("docker: daemon gone")
	if err := a.PurgeDir(context.Background(), s); err == nil || !strings.Contains(err.Error(), "daemon gone") {
		t.Fatalf("read error: %v", err)
	}
	for _, c := range f.calls() {
		if clIsMutation(c) || strings.HasPrefix(c, "setQuota") {
			t.Fatalf("read error: %s", c)
		}
	}
}

// TestPurgeDir_GuardBeforeAbsentDirectory: with the project directory
// already gone, a remaining tenant container still blocks the quota change.
func TestPurgeDir_GuardBeforeAbsentDirectory(t *testing.T) {
	a, f, s, _ := clSetup(t)
	os.RemoveAll(a.p.ProjectDir(s.Ref))
	f.ctr(fakeCtr{Name: "pg-" + s.Ref, CapDrop: []string{"ALL"}})
	f.resetLog()
	if err := a.PurgeDir(context.Background(), s); err == nil || !strings.Contains(err.Error(), "pg-"+s.Ref) {
		t.Fatalf("got %v", err)
	}
	if slices.ContainsFunc(f.calls(), func(c string) bool { return strings.HasPrefix(c, "setQuota") }) {
		t.Fatalf("quota changed: %q", f.calls())
	}
}

// A failed read during the adoption check (Docker did not answer) is read
// once more; a check still incomplete then leaves the running cluster as it
// is. A refusal is not read again and removes it.
func TestEnsureCluster_AdoptionReadFailureRetriedOnce(t *testing.T) {
	old := adoptRetry
	adoptRetry = 0
	t.Cleanup(func() { adoptRetry = old })
	for _, fails := range []int{1, 2} {
		t.Run(fmt.Sprintf("fails=%d", fails), func(t *testing.T) {
			a, f, s, _ := clSetup(t)
			clToPhaseB(t, a, f, s)
			s.HealthWait = -1
			inner := dockerInspectNetwork
			n := 0
			dockerInspectNetwork = func(ctx context.Context, name string) (*dockerx.Network, error) {
				if name == "proj-"+s.Ref && n < fails {
					n++
					return nil, errors.New("docker network inspect: Cannot connect to the Docker daemon")
				}
				return inner(ctx, name)
			}
			t.Cleanup(func() { dockerInspectNetwork = inner })
			f.resetLog()
			err := a.EnsureCluster(context.Background(), s)
			m := f.mutations()
			if fails == 1 {
				if err != nil || len(m) != 0 {
					t.Fatalf("one failed read: err %v, mutations %q; want the running cluster adopted", err, m)
				}
				return
			}
			// Still not read: the check is incomplete, the running cluster
			// is left as it is.
			if !errors.Is(err, ErrCheckIncomplete) || len(m) != 0 {
				t.Fatalf("two failed reads: err %v, mutations %q; want an incomplete check and the cluster left running", err, m)
			}
		})
	}
	// A refusal (a fact read and wrong) is not read again.
	a, f, s, _ := clSetup(t)
	clToPhaseB(t, a, f, s)
	f.ip["-j -d addr show dev spp14"] = bridgeIface("spp14", true)
	f.resetLog()
	err := a.EnsureCluster(context.Background(), s)
	wantContainment(t, err, "refusal")
	if errors.Is(err, ErrCheckIncomplete) || !slices.Equal(f.mutations(), []string{"docker rm -f -v -- pg-" + s.Ref}) {
		t.Fatalf("refusal: err %v, mutations %q; want a completed refusal and the forced removal", err, f.mutations())
	}
	if n := strings.Count(strings.Join(f.calls(), "\n"), "inspect network proj-"+s.Ref); n != 1 {
		t.Fatalf("refusal read the project network %d times, want 1", n)
	}
}

// An `ip` call that fails once during the adoption check (the command could
// not run, or ran out of time) is a fact not read, like a Docker read: the
// running cluster is checked once more and adopted, not removed.
func TestEnsureCluster_AdoptionIPFailureRetried(t *testing.T) {
	old := adoptRetry
	adoptRetry = 0
	t.Cleanup(func() { adoptRetry = old })
	a, f, s, _ := clSetup(t)
	clToPhaseB(t, a, f, s)
	s.HealthWait = -1
	inner := runIP
	n := 0
	runIP = func(ctx context.Context, args ...string) ([]byte, error) {
		if n == 0 {
			n++
			return nil, errors.New("ip -j -d addr show dev spp14: signal: killed")
		}
		return inner(ctx, args...)
	}
	t.Cleanup(func() { runIP = inner })
	f.resetLog()
	err := a.EnsureCluster(context.Background(), s)
	if m := f.mutations(); err != nil || len(m) != 0 {
		t.Fatalf("one failed ip call: err %v, mutations %q; want the running cluster adopted", err, m)
	}
}
