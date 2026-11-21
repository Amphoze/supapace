package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
)

// The tests run against a throw-away control-plane database container (the
// pinned image, no network, a unix-socket directory) and a fake agent that
// plays the launcher. They are skipped when Docker is unavailable.
var (
	sockDir  string
	noDocker string
)

func TestMain(m *testing.M) {
	code := func() int {
		name, dir, err := startDB()
		if name != "" {
			defer exec.Command("docker", "rm", "-f", "-v", name).Run()
		}
		if dir != "" {
			defer os.RemoveAll(dir)
		}
		if err != nil {
			noDocker = err.Error()
		}
		sockDir = dir
		return m.Run()
	}()
	os.Exit(code)
}

func startDB() (name, dir string, err error) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		return "", "", fmt.Errorf("docker unavailable: %v", err)
	}
	im, err := nodecfg.LockedImages()
	if err != nil {
		return "", "", err
	}
	if dir, err = os.MkdirTemp("", "sp-backup-"); err != nil {
		return "", "", err
	}
	// The server runs as the image's postgres user and creates its socket here.
	if err := os.Chmod(dir, 0o777); err != nil {
		return "", dir, err
	}
	b := make([]byte, 6)
	rand.Read(b)
	name = "sp-test-backup-" + hex.EncodeToString(b)
	// A watchdog in its own session removes the container and the socket
	// directory once this process is gone, whatever ended it.
	w := exec.Command("sh", "-c", `while kill -0 "$1" 2>/dev/null; do sleep 1; done
		docker rm -f -v "$2" >/dev/null 2>&1; sleep 5; docker rm -f -v "$2" >/dev/null 2>&1; rm -rf "$3"`,
		"sh", strconv.Itoa(os.Getpid()), name, dir)
	w.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := w.Start(); err != nil {
		return "", dir, err
	}
	w.Process.Release()
	pw := make([]byte, 16)
	rand.Read(pw)
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "--label", "supapace.test=1",
		"--network", "none", "--user", "70:70", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--read-only",
		"--tmpfs", "/tmp", "--tmpfs", "/var/lib/postgresql/data:uid=70,gid=70,mode=0700",
		"-v", dir+":/var/run/postgresql",
		"-e", "POSTGRES_USER=supapaced", "-e", "POSTGRES_DB=supapaced",
		"-e", "POSTGRES_PASSWORD="+hex.EncodeToString(pw),
		"--entrypoint", "timeout", im.ControlPlane, "-s", "INT", "14400",
		"docker-entrypoint.sh", "postgres", "-c", "listen_addresses=", "-c", "fsync=off").CombinedOutput()
	if err != nil {
		return name, dir, fmt.Errorf("docker run: %v: %s", err, bytes.TrimSpace(out))
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if bytes.Contains(logs, []byte("PostgreSQL init process complete")) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s, err := store.Open(ctx, dir)
			cancel()
			if err == nil {
				s.Close()
				return name, dir, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return name, dir, fmt.Errorf("control-plane test database not ready")
}

// conn is a direct connection to the test database (set-up and reads only).
func conn(t *testing.T) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Host, cfg.Port, cfg.Database, cfg.User, cfg.Password = sockDir, 5432, "supapaced", "supapaced", ""
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	c, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ───────── fake clock ─────────

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Set(t time.Time)     { c.mu.Lock(); c.t = t; c.mu.Unlock() }
func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// ───────── fake agent ─────────

// fakeAgent plays the node agent. RunJob runs the job's script (by kind),
// by default an ok result of that kind; every call is recorded.
type fakeAgent struct {
	mu          sync.Mutex
	calls       []string
	specs       []agent.JobSpec
	script      map[string]func(context.Context, agent.JobSpec) (agent.JobResult, error)
	running     map[string]int // running jobs by subject
	maxRunning  map[string]int
	killErr     error
	containment bool
	quota       agent.QuotaUse
	repoFree    int64
	state       func(n int) (promoted, exited bool, err error)
	ensureErr   error
	target      pgconf.RecoveryTarget
	polls       int
	started     chan agent.JobSpec
}

func newFakeAgent() *fakeAgent {
	return &fakeAgent{script: map[string]func(context.Context, agent.JobSpec) (agent.JobResult, error){},
		running: map[string]int{}, maxRunning: map[string]int{}, repoFree: 1 << 40, started: make(chan agent.JobSpec, 1024),
		state: func(int) (bool, bool, error) { return true, false, nil }}
}

func (f *fakeAgent) call(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }

func (f *fakeAgent) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeAgent) setScript(kind string, fn func(context.Context, agent.JobSpec) (agent.JobResult, error)) {
	f.mu.Lock()
	f.script[kind] = fn
	f.mu.Unlock()
}

func (f *fakeAgent) RunJob(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, "RunJob "+j.Subject+" "+j.Kind)
	f.specs = append(f.specs, j)
	f.running[j.Subject]++
	f.maxRunning[j.Subject] = max(f.maxRunning[j.Subject], f.running[j.Subject])
	fn := f.script[j.Kind]
	f.mu.Unlock()
	select {
	case f.started <- j:
	default:
	}
	defer func() { f.mu.Lock(); f.running[j.Subject]--; f.mu.Unlock() }()
	if fn != nil {
		return fn(ctx, j)
	}
	return agent.JobResult{Result: okLine(j.Kind)}, nil
}

func (f *fakeAgent) KillJobs(_ context.Context, s string) error {
	f.call("KillJobs " + s)
	return f.killErr
}
func (f *fakeAgent) SetReplicatorQuota(_ context.Context, mb int) error {
	f.call(fmt.Sprintf("SetReplicatorQuota %d", mb))
	return nil
}
func (f *fakeAgent) EnsureRecovery(_ context.Context, s agent.Spec, t pgconf.RecoveryTarget) error {
	f.call("EnsureRecovery " + s.Ref + " " + t.LSN)
	f.mu.Lock()
	f.target = t
	f.mu.Unlock()
	return f.ensureErr
}
func (f *fakeAgent) RecoveryState(context.Context, agent.Spec) (bool, bool, error) {
	f.mu.Lock()
	f.polls++
	n := f.polls
	f.mu.Unlock()
	return f.state(n)
}
func (f *fakeAgent) QuotaUse(_ context.Context, uid int) (agent.QuotaUse, error) {
	f.call(fmt.Sprintf("QuotaUse %d", uid))
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.quota, nil
}
func (f *fakeAgent) RepoSpace(context.Context) (int64, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return 1 << 41, f.repoFree, nil
}
func (f *fakeAgent) RemoveFetch(_ context.Context, s agent.Spec) error {
	f.call("RemoveFetch " + s.Ref)
	return nil
}
func (f *fakeAgent) StopCluster(_ context.Context, ref string) error {
	f.call("StopCluster " + ref)
	return nil
}
func (f *fakeAgent) ContainmentFailed() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.containment }

func (f *fakeAgent) setContainment(b bool) { f.mu.Lock(); f.containment = b; f.mu.Unlock() }

// waitStart returns the next job the fake launched.
func (f *fakeAgent) waitStart(t *testing.T) agent.JobSpec {
	t.Helper()
	select {
	case j := <-f.started:
		return j
	case <-time.After(30 * time.Second):
		t.Fatal("no job was launched")
	}
	return agent.JobSpec{}
}

// blockUntilStopped is a script for a job that runs until its context ends.
func blockUntilStopped(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
	<-ctx.Done()
	return agent.JobResult{Result: okLine(j.Kind)}, nil
}

// ───────── fake projects ─────────

type fakeProjects struct {
	mu      sync.Mutex
	specs   map[string]agent.Spec
	adopted map[string]bool
}

func (p *fakeProjects) SpecFor(_ context.Context, ref string) (agent.Spec, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.specs[ref]
	if !ok {
		return agent.Spec{}, store.ErrNotFound
	}
	return s, nil
}

func (p *fakeProjects) Adopted(ref string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.adopted[ref]
}

func (p *fakeProjects) setAdopted(ref string, b bool) { p.mu.Lock(); p.adopted[ref] = b; p.mu.Unlock() }

// ───────── results ─────────

func line(v any) []byte {
	b, err := jobio.MarshalResult(v)
	if err != nil {
		panic(err)
	}
	return b
}

func okPush() jobio.PushResult {
	return jobio.PushResult{OK: true, Complete: true, Pushed: 1, Newest: map[string]string{"00000001": "000000010000000000000003"},
		Quarantined: []jobio.Quarantined{}, SpoolEntries: 2, SpoolBytes: 4096, Histories: []string{}}
}

func okBackup() jobio.BackupResult {
	p := okPush()
	return jobio.BackupResult{OK: true, Label: "20261118-104332F", Timeline: 1, Start: time.Unix(1_700_000_000, 0).UTC(),
		Stop: time.Unix(1_700_000_060, 0).UTC(), StartSegment: "000000010000000000000004", StopSegment: "000000010000000000000005",
		StartLSN: "0/4000028", StopLSN: "0/5000100", Push: &p}
}

func okLine(kind string) []byte {
	p := okPush()
	switch kind {
	case "push":
		return line(p)
	case "check", "stanza-create":
		return line(jobio.CheckJobResult{OK: true, Push: &p})
	case "backup":
		return line(okBackup())
	case "restore":
		return line(jobio.RestoreResult{OK: true, Mode: "none"})
	case "serve":
		return line(jobio.ServeResult{OK: true, Served: 3, None: []string{}, LastSegment: "000000010000000000000007"})
	case "seed":
		return line(jobio.SeedResult{OK: true, Files: 2, Bytes: 10})
	case "replicate":
		return line(jobio.ReplResult{OK: true, Mode: "copy", Complete: true})
	case "fetch":
		return line(jobio.FetchResult{OK: true, Files: 1, Bytes: 1})
	}
	panic("no result for " + kind)
}

func failLine(code, msg string) []byte { return line(jobio.Failure{Code: code, Message: msg}) }

// ───────── environment ─────────

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type env struct {
	t     *testing.T
	st    *store.Store
	ag    *fakeAgent
	pr    *fakeProjects
	r     *Runner
	p     nodecfg.Paths
	kek   secrets.KEK
	clock *fakeClock
	logs  *logBuf
	db    *pgx.Conn
	dbMu  sync.Mutex // job and count may run beside the test goroutine
	n     int
}

func testConfig() nodecfg.Config {
	c := nodecfg.Default("sp.test")
	c.MemAllocMB, c.PidsAlloc, c.Uplinks = 1<<20, 1<<20, nil
	return c
}

func newEnv(t *testing.T) *env {
	t.Helper()
	if noDocker != "" {
		t.Skip(noDocker)
	}
	ctx := context.Background()
	db := conn(t)
	if _, err := db.Exec(ctx, "drop schema public cascade; create schema public"); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, sockDir)
	must(t, err)
	t.Cleanup(st.Close)
	must(t, st.Migrate(ctx))
	c := testConfig()
	must(t, st.EnsureNode(ctx, c))
	e := &env{t: t, st: st, ag: newFakeAgent(), pr: &fakeProjects{specs: map[string]agent.Spec{}, adopted: map[string]bool{}},
		p: nodecfg.Paths{Root: t.TempDir()}, clock: &fakeClock{t: time.Now()}, logs: &logBuf{}, db: db}
	rand.Read(e.kek[:])
	e.r = New(st, e.ag, e.pr, e.kek, c, e.p)
	e.r.now, e.r.idle, e.r.tick, e.r.recoverPoll = e.clock.Now, 2*time.Millisecond, 2*time.Millisecond, time.Millisecond
	e.r.pushWait = func(ctx context.Context) { sleep(ctx, time.Millisecond) }
	e.r.pickDelay = func() time.Duration { return 0 }
	e.r.retry, e.r.stopPoll = 5*time.Millisecond, 5*time.Millisecond
	e.r.log = slog.New(slog.NewTextHandler(e.logs, nil))
	// Stop every job still running when the test ends and wait for its
	// record: the next test reuses the database and its job ids.
	t.Cleanup(func() {
		var waits []chan struct{}
		e.r.mu.Lock()
		for _, a := range e.r.active {
			if a.cancel != nil {
				a.code = "cancelled"
				a.cancel()
			}
			waits = append(waits, a.done)
		}
		e.r.mu.Unlock()
		for _, w := range waits {
			select {
			case <-w:
			case <-time.After(30 * time.Second):
				t.Error("a stopped job was not recorded within 30 s")
				return
			}
		}
	})
	return e
}

// project makes a layout-2 project in state with its stanza, adopted.
func (e *env) project(state string) string {
	e.t.Helper()
	ctx := context.Background()
	e.n++
	ref := fmt.Sprintf("bk%018d", e.n)
	op, err := e.st.CreateProject(ctx, store.NewProject{Ref: ref, Name: "demo",
		Config: store.ProjectConfig{DiskQuotaMB: 8192, MemMB: 512, GUC: map[string]string{}, Layout: 2}})
	must(e.t, err)
	pl, err := e.st.Place(ctx, ref)
	must(e.t, err)
	must(e.t, e.st.StartOperation(ctx, op))
	must(e.t, e.st.FinishOperation(ctx, op, "done", ""))
	must(e.t, e.st.SetProjectState(ctx, ref, state))
	must(e.t, e.st.EnsureBackupState(ctx, ref))
	must(e.t, e.st.MarkStanza(ctx, ref))
	e.pr.mu.Lock()
	e.pr.specs[ref] = agent.Spec{Ref: ref, UID: pl.UID, GID: pl.GID, DiskQuotaMB: 8192, RepoQuotaMB: 8192, Layout: 2,
		Stanza: ref + "-1", StanzaPass: "pass-" + ref}
	e.pr.adopted[ref] = true
	e.pr.mu.Unlock()
	return ref
}

// controlPlane gives the control plane its backup state, stanza and passphrase.
func (e *env) controlPlane() string {
	e.t.Helper()
	ctx := context.Background()
	must(e.t, e.st.EnsureBackupState(ctx, "cp"))
	must(e.t, e.st.MarkStanza(ctx, "cp"))
	must(e.t, os.MkdirAll(filepath.Dir(e.p.CPStanzaSealed()), 0o700))
	pass, err := offsite.EnsureControlPlanePass(e.p, e.kek)
	must(e.t, err)
	return pass
}

// submit queues a job no operation owns.
func (e *env) submit(subject, kind string) int64 {
	e.t.Helper()
	id, err := e.st.SubmitJob(context.Background(), store.NewJob{Subject: subject, Lane: laneOf(kind), Kind: kind, DeadlineS: 600})
	must(e.t, err)
	return id
}

// parked queues a job of a new running operation of ref, parking it.
func (e *env) parked(ref, kind string, params string) (op, id int64) {
	e.t.Helper()
	ctx := context.Background()
	must(e.t, e.db.QueryRow(ctx, `insert into operation (ref, kind, state, step, attempts, params, epoch, generation)
		values ($1, 'restart', 'running', 'S3', 1, '{}', 1, 1) returning id`, ref).Scan(&op))
	var p []byte
	if params != "" {
		p = []byte(params)
	}
	id, err := e.st.SubmitJobAndPark(ctx, op, store.NewJob{Subject: ref, Lane: laneOf(kind), Kind: kind, OpStep: "S3", Params: p, DeadlineS: 600})
	must(e.t, err)
	return op, id
}

type jobRow struct {
	State, Code, Message string
	Result               []byte
}

func (e *env) job(id int64) jobRow {
	e.t.Helper()
	e.dbMu.Lock()
	defer e.dbMu.Unlock()
	var j jobRow
	must(e.t, e.db.QueryRow(context.Background(), `select state, coalesce(code, ''), coalesce(message, ''), result
		from backup_job where id = $1`, id).Scan(&j.State, &j.Code, &j.Message, &j.Result))
	return j
}

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	e.dbMu.Lock()
	defer e.dbMu.Unlock()
	var n int
	must(e.t, e.db.QueryRow(context.Background(), q, args...).Scan(&n))
	return n
}

// turn takes one turn of lane in the test's goroutine.
func (e *env) turn(lane string) bool { return e.r.turn(context.Background(), lane, &errLog{}) }

// start runs the runner until the test ends.
func (e *env) start() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.r.Run(ctx) }()
	e.t.Cleanup(func() { cancel(); <-done })
}

// eventually waits for cond, failing after 30 s.
func (e *env) eventually(what string, cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			e.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// declare sets a declared off-site store on the runner.
func (e *env) declare() offsite.Declaration {
	d := offsite.Declaration{Endpoint: "https://s3.example.test", Region: "r1", PathStyle: true,
		Projects:     offsite.Bucket{Name: "projects", Prefix: "p", Write: offsite.Credential{AccessKey: "PW", SecretKey: "pw-secret"}, Read: offsite.Credential{AccessKey: "PR", SecretKey: "pr-secret"}},
		ControlPlane: offsite.Bucket{Name: "cp", Prefix: "c", Write: offsite.Credential{AccessKey: "CW", SecretKey: "cw-secret"}, Read: offsite.Credential{AccessKey: "CR", SecretKey: "cr-secret"}}}
	e.r.SetOffsite(d, offsite.StateDeclared, nil)
	return d
}

var errTest = errors.New("test failure")

// noSchedule takes every project out of the scheduler's reach (layout 1):
// tests that load the lanes themselves want no scheduled push beside theirs.
func (e *env) noSchedule() {
	e.t.Helper()
	_, err := e.db.Exec(context.Background(), `update project set config = jsonb_set(config, '{layout}', '1')`)
	must(e.t, err)
}
