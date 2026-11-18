package saga

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/routes"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
)

// The tests run the worker against the real store, on a throw-away
// postgres:17-alpine container (the control-plane image, pinned by digest)
// with no network, reached through a unix-socket directory, and against a
// fake agent that records every call. They are skipped without Docker.
var (
	sockDir   string
	noDocker  string
	issuerKey jwtx.Key
)

func TestMain(m *testing.M) {
	code := func() int {
		priv, kid, err := jwtx.GenerateKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		issuerKey = jwtx.Key{KID: kid, Class: "issuer", Pub: &priv.PublicKey}
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
	dir, err = os.MkdirTemp("", "sp-saga-")
	if err != nil {
		return "", "", err
	}
	// The server runs as the image's postgres user (70) and must create its
	// socket here; the test process must be able to remove it afterwards.
	if err := os.Chmod(dir, 0o777); err != nil {
		return "", dir, err
	}
	b := make([]byte, 6)
	rand.Read(b)
	name = "sp-test-saga-" + hex.EncodeToString(b)
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
		"--entrypoint", "timeout", im.ControlPlane, "-s", "INT", "1800",
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

// sql runs a statement directly on the test database (set-up and
// simulated crashes only).
func sql(t *testing.T, q string, args ...any) {
	t.Helper()
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Host, cfg.Port, cfg.Database, cfg.User, cfg.Password = sockDir, 5432, "supapaced", "supapaced", ""
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	ctx := context.Background()
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// ───────── fake agent ─────────

type call struct {
	Method, Ref string
	Gen         int64
	HealthWait  time.Duration
	Quota       int
	GUC         map[string]string
	State       string // SetRoute: "" = removed
	FirstBoot   bool
	Token       string
}

// fakeAgent models the node objects so that a repeated call can be told
// from one with effect. hook runs first and may block; err then decides the
// result of a call before its effect.
type fakeAgent struct {
	mu           sync.Mutex
	calls        []call
	effects      map[string]int
	dir, network map[string]bool
	cluster      map[string]int64
	pgrest       map[string]int64
	render       map[string]bool
	route        map[string]routes.Project
	routeGen     int64
	specs        []agent.Spec

	failed atomic.Bool
	err    func(c call) error
	hook   func(ctx context.Context, c call)

	inflight, maxInflight atomic.Int32

	gwLag   int   // polls that still report an older route generation
	gwAhead int64 // added to the generation the gateway reports (it may be past the one written)
}

func newFake() *fakeAgent {
	return &fakeAgent{effects: map[string]int{}, dir: map[string]bool{}, network: map[string]bool{},
		cluster: map[string]int64{}, pgrest: map[string]int64{}, render: map[string]bool{}, route: map[string]routes.Project{}}
}

func (f *fakeAgent) enter(ctx context.Context, c call, s *agent.Spec) error {
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)
	for {
		m := f.maxInflight.Load()
		if n <= m || f.maxInflight.CompareAndSwap(m, n) {
			break
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, c)
	if s != nil {
		f.specs = append(f.specs, *s)
	}
	hook, errf := f.hook, f.err
	f.mu.Unlock()
	if hook != nil {
		hook(ctx, c)
	}
	if errf != nil {
		if err := errf(c); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func sc(method string, s agent.Spec) call {
	return call{Method: method, Ref: s.Ref, Gen: s.Generation, HealthWait: s.HealthWait, Quota: s.DiskQuotaMB, GUC: s.GUC,
		FirstBoot: s.FirstBoot}
}

func (f *fakeAgent) EnsureDir(ctx context.Context, s agent.Spec) error {
	if err := f.enter(ctx, sc("EnsureDir", s), &s); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.dir[s.Ref] {
		f.dir[s.Ref] = true
		f.effects["dir "+s.Ref]++
	}
	return nil
}

func (f *fakeAgent) SetQuota(ctx context.Context, s agent.Spec) error {
	return f.enter(ctx, sc("SetQuota", s), &s)
}

func (f *fakeAgent) EnsureNetwork(ctx context.Context, s agent.Spec) error {
	if err := f.enter(ctx, sc("EnsureNetwork", s), &s); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.network[s.Ref] {
		f.network[s.Ref] = true
		f.effects["net "+s.Ref]++
	}
	return nil
}

func (f *fakeAgent) RemoveNetwork(ctx context.Context, ref string) error {
	if err := f.enter(ctx, call{Method: "RemoveNetwork", Ref: ref}, nil); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.network[ref] {
		delete(f.network, ref)
		f.effects["rmnet "+ref]++
	}
	return nil
}

func (f *fakeAgent) EnsureCluster(ctx context.Context, s agent.Spec) error {
	if err := f.enter(ctx, sc("EnsureCluster", s), &s); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.render[s.Ref] = true
	if f.cluster[s.Ref] != s.Generation {
		f.cluster[s.Ref] = s.Generation
		f.effects[fmt.Sprintf("cluster %s %d", s.Ref, s.Generation)]++
	}
	return nil
}

func (f *fakeAgent) VerifyCluster(ctx context.Context, s agent.Spec) error {
	return f.enter(ctx, sc("VerifyCluster", s), &s)
}

func (f *fakeAgent) StopCluster(ctx context.Context, ref string) error {
	if err := f.enter(ctx, call{Method: "StopCluster", Ref: ref}, nil); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cluster[ref] != 0 {
		delete(f.cluster, ref)
		f.effects["stopcluster "+ref]++
	}
	return nil
}

func (f *fakeAgent) Prevalidate(ctx context.Context, s agent.Spec) error {
	return f.enter(ctx, sc("Prevalidate", s), &s)
}

func (f *fakeAgent) PromoteCandidate(ctx context.Context, ref string) error {
	return f.enter(ctx, call{Method: "PromoteCandidate", Ref: ref}, nil)
}

func (f *fakeAgent) EnsurePostgREST(ctx context.Context, s agent.Spec) error {
	if err := f.enter(ctx, sc("EnsurePostgREST", s), &s); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.render[s.Ref] = true
	if f.pgrest[s.Ref] != s.Generation {
		f.pgrest[s.Ref] = s.Generation
		f.effects[fmt.Sprintf("postgrest %s %d", s.Ref, s.Generation)]++
	}
	return nil
}

func (f *fakeAgent) StopPostgREST(ctx context.Context, ref string) error {
	if err := f.enter(ctx, call{Method: "StopPostgREST", Ref: ref}, nil); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pgrest[ref] != 0 {
		delete(f.pgrest, ref)
		f.effects["stoppostgrest "+ref]++
	}
	return nil
}

func (f *fakeAgent) RouteFor(s agent.Spec, state string) routes.Project {
	var keys []routes.Key
	for _, k := range s.Keys {
		keys = append(keys, routes.Key{KID: k.KID, Class: string(k.Class), Kty: "RSA"})
	}
	return routes.Project{State: state, Rest: "http://10.212.6.16:3000", UserRoles: s.UserRoles, Keys: keys}
}

func (f *fakeAgent) SetRoute(ctx context.Context, ref string, r *routes.Project) (int64, error) {
	c := call{Method: "SetRoute", Ref: ref}
	if r != nil {
		c.State = r.State
	}
	if err := f.enter(ctx, c, nil); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routeGen++
	old, had := f.route[ref]
	switch {
	case r == nil && had:
		delete(f.route, ref)
		f.effects["rmroute "+ref]++
	case r != nil && (!had || old.State != r.State):
		f.route[ref] = *r
		f.effects["route "+ref+" "+r.State]++
	}
	return f.routeGen, nil
}

func (f *fakeAgent) GatewayGeneration(ctx context.Context) (int64, error) {
	if err := f.enter(ctx, call{Method: "GatewayGeneration"}, nil); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gwLag > 0 { // the gateway has not read the latest file yet
		f.gwLag--
		return f.routeGen - 1, nil
	}
	return f.routeGen + f.gwAhead, nil
}

func (f *fakeAgent) ProbeREST(ctx context.Context, ref, token string) error {
	if err := f.enter(ctx, call{Method: "ProbeREST", Ref: ref, Token: token}, nil); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.route[ref].State != "active" || f.pgrest[ref] == 0 {
		return errors.New("probe: not served")
	}
	return nil
}

func (f *fakeAgent) RemoveRender(ctx context.Context, ref string) error {
	if err := f.enter(ctx, call{Method: "RemoveRender", Ref: ref}, nil); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.render[ref] {
		delete(f.render, ref)
		f.effects["rmrender "+ref]++
	}
	return nil
}

func (f *fakeAgent) PurgeDir(ctx context.Context, s agent.Spec) error {
	if err := f.enter(ctx, sc("PurgeDir", s), &s); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dir[s.Ref] {
		delete(f.dir, s.Ref)
		f.effects["purgedir "+s.Ref]++
	}
	return nil
}

func (f *fakeAgent) ContainmentFailed() bool { return f.failed.Load() }

func (f *fakeAgent) setErr(fn func(c call) error) {
	f.mu.Lock()
	f.err = fn
	f.mu.Unlock()
}

func (f *fakeAgent) setHook(fn func(ctx context.Context, c call)) {
	f.mu.Lock()
	f.hook = fn
	f.mu.Unlock()
}

// locked runs fn under the fake's lock, for reads of its object maps.
func (f *fakeAgent) locked(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

// methods returns the methods called for ref ("" = every call), in order.
func (f *fakeAgent) methods(ref string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if ref == "" || c.Ref == ref {
			out = append(out, c.Method)
		}
	}
	return out
}

func (f *fakeAgent) callsOf(ref, method string) []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if c.Ref == ref && c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeAgent) reset() {
	f.mu.Lock()
	f.calls, f.specs = nil, nil
	f.mu.Unlock()
}

// ───────── environment ─────────

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// records returns the decoded log records with message msg.
func (l *logBuf) records(msg string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(l.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

type env struct {
	t    *testing.T
	st   *store.Store
	ag   *fakeAgent
	kek  secrets.KEK
	cfg  nodecfg.Config
	p    nodecfg.Paths
	logs *logBuf
	n    int
}

func testConfig() nodecfg.Config {
	c := nodecfg.Default("sp.test")
	c.MemAllocMB, c.PidsAlloc, c.Uplinks = 1<<20, 1<<20, nil
	c.Retention = "1ms"
	return c
}

func newEnvWith(t *testing.T, c nodecfg.Config) *env {
	t.Helper()
	if noDocker != "" {
		t.Skip(noDocker)
	}
	sql(t, "drop schema public cascade; create schema public")
	ctx := context.Background()
	st, err := store.Open(ctx, sockDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	must(t, st.Migrate(ctx))
	must(t, st.EnsureNode(ctx, c))
	e := &env{t: t, st: st, ag: newFake(), cfg: c, p: nodecfg.Paths{Root: t.TempDir()}, logs: &logBuf{}}
	rand.Read(e.kek[:])
	// A development node: the failpoint is live. In tests a failpoint ends
	// the worker's goroutine instead of the process.
	must(t, os.MkdirAll(filepath.Dir(e.p.NodeJSON()), 0o700))
	must(t, os.MkdirAll(filepath.Dir(e.p.Failpoint()), 0o700))
	must(t, os.WriteFile(filepath.Join(filepath.Dir(e.p.NodeJSON()), "dev-mode"), nil, 0o600))
	old := exit
	exit = func(int) { runtime.Goexit() }
	t.Cleanup(func() { exit = old })
	return e
}

func newEnv(t *testing.T) *env { return newEnvWith(t, testConfig()) }

// runner returns a runner with short test timings.
func (e *env) runner() *Runner {
	r := New(e.st, e.ag, e.kek, e.cfg, e.p)
	r.backoff = []time.Duration{time.Millisecond}
	r.idle = 2 * time.Millisecond
	r.probeEvery = time.Millisecond
	r.probeWindow = 200 * time.Millisecond
	r.containmentRetry = 20 * time.Millisecond
	r.log = slog.New(slog.NewJSONHandler(e.logs, nil))
	return r
}

// start runs r's worker until stop is called or the test ends.
func (e *env) start(r *Runner) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(ctx)
	}()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	e.t.Cleanup(stop)
	return stop
}

// run starts r's worker; done is closed when it ends by itself (a failpoint).
func (e *env) run(r *Runner) (done <-chan struct{}) {
	return e.startDone(r)
}

func (e *env) startDone(r *Runner) <-chan struct{} {
	ctx, cancel := context.WithCancel(context.Background())
	d := make(chan struct{})
	go func() {
		defer close(d)
		r.Run(ctx)
	}()
	e.t.Cleanup(func() { cancel(); <-d })
	return d
}

func (e *env) ref() string {
	e.n++
	return fmt.Sprintf("saga%016d", e.n)
}

func issuerJWKS(t *testing.T, keys ...jwtx.Key) json.RawMessage {
	t.Helper()
	set, err := jwtx.MarshalJWKS(keys)
	must(t, err)
	b, err := json.Marshal(map[string]json.RawMessage{"issuer_jwks": set})
	must(t, err)
	return b
}

var defaultConfig = store.ProjectConfig{DiskQuotaMB: 8192, MemMB: 512, GUC: map[string]string{}}

// create inserts a project and its create operation, as the admin API does.
func (e *env) create() (string, int64) {
	e.t.Helper()
	r := e.ref()
	id, err := e.st.CreateProject(context.Background(), store.NewProject{Ref: r, Name: "demo", Config: defaultConfig,
		UserRoles: []string{"authenticated"}, Params: issuerJWKS(e.t, issuerKey)})
	must(e.t, err)
	return r, id
}

func (e *env) op(id int64) store.Operation {
	e.t.Helper()
	op, err := e.st.GetOperation(context.Background(), id)
	must(e.t, err)
	return op
}

func (e *env) project(ref string) store.Project {
	e.t.Helper()
	p, err := e.st.GetProject(context.Background(), ref)
	must(e.t, err)
	return p
}

// wait polls operation id until cond holds.
func (e *env) wait(id int64, what string, cond func(store.Operation) bool) store.Operation {
	e.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		op := e.op(id)
		if cond(op) {
			return op
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("operation %d never %s: %+v", id, what, op)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (e *env) waitState(id int64, state string) store.Operation {
	e.t.Helper()
	return e.wait(id, state, func(op store.Operation) bool { return op.State == state })
}

// active creates a project and runs its create to done with its own runner.
func (e *env) active() string {
	e.t.Helper()
	ref, id := e.create()
	stop := e.start(e.runner())
	e.waitState(id, "done")
	stop()
	e.ag.reset()
	return ref
}

// restart submits a restart of ref with cfg as the merged configuration.
func (e *env) restart(r *Runner, ref string, cfg store.ProjectConfig) int64 {
	e.t.Helper()
	p := e.project(ref)
	params, err := json.Marshal(map[string]any{"base_generation": p.Generation, "config": cfg})
	must(e.t, err)
	id, err := r.Submit(context.Background(), "restart", ref, params)
	must(e.t, err)
	return id
}

func (e *env) failpoint(name string) {
	e.t.Helper()
	must(e.t, os.WriteFile(e.p.Failpoint(), []byte(name+"\n"), 0o600))
}

// steps returns the step ids the worker logged as done for operation id.
func (e *env) steps(id int64) []string {
	var out []string
	for _, m := range e.logs.records("step done") {
		if m["op"] == float64(id) {
			out = append(out, m["step"].(string))
		}
	}
	return out
}

func (e *env) secret(ref, name string) string {
	e.t.Helper()
	ctx := context.Background()
	n, w, err := e.st.GetDEK(ctx, ref)
	must(e.t, err)
	dek, err := secrets.UnwrapDEK(e.kek, ref, n, w)
	must(e.t, err)
	sn, ct, err := e.st.GetSecret(ctx, ref, name)
	must(e.t, err)
	plain, err := secrets.Open(dek, ref, name, sn, ct)
	must(e.t, err)
	return string(plain)
}

func (e *env) deleted(r *Runner, ref string) (del, purge int64) {
	e.t.Helper()
	del, err := r.Submit(context.Background(), "delete", ref, nil)
	must(e.t, err)
	e.waitState(del, "done")
	ops, err := e.st.ListOperations(context.Background(), ref)
	must(e.t, err)
	return del, ops[0].ID
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantSeq(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("sequence\n got %v\nwant %v", got, want)
	}
}

var errBoom = errors.New("boom")

func failOn(method string) func(c call) error {
	return func(c call) error {
		if c.Method == method {
			return errBoom
		}
		return nil
	}
}

var createIDs = []string{"2", "3", "4a", "4", "6", "7", "9", "11", "12"}

// ───────── tables ─────────

func TestStepIDs_Fixed(t *testing.T) {
	ids := func(ss []step) []string {
		var out []string
		for _, s := range ss {
			out = append(out, s.id)
		}
		return out
	}
	wantSeq(t, ids(tables["create"]), createIDs)
	wantSeq(t, ids(tables["restart"]), []string{"R0", "R1", "R2", "R3", "R4", "R5"})
	wantSeq(t, ids(tables["delete"]), []string{"D1", "D2", "D3", "D4", "D5"})
	wantSeq(t, ids(tables["purge"]), []string{"P1", "P2", "P3", "P4", "P5"})
	wantSeq(t, ids(compensation), []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7"})
	if len(tables) != 4 {
		t.Fatalf("tables %v", tables)
	}
}

// ───────── create ─────────

func TestCreate_StepOrder(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	if op := e.op(id); op.Step != "1" {
		t.Fatalf("admin API's step = %q", op.Step)
	}
	e.start(e.runner())
	op := e.waitState(id, "done")
	wantSeq(t, e.steps(id), createIDs)
	if op.Step != "12" || op.Attempts != 1 || op.LastError != "" {
		t.Fatalf("op = %+v", op)
	}
	wantSeq(t, e.ag.methods(ref), []string{"EnsureDir", "EnsureNetwork", "EnsureCluster", "EnsureCluster",
		"EnsurePostgREST", "SetRoute", "ProbeREST"})
	p := e.project(ref)
	if p.State != "active" || p.AppliedGen != 1 || p.UID == nil || p.SubnetIndex == nil {
		t.Fatalf("project = %+v", p)
	}
	for _, c := range e.ag.callsOf(ref, "EnsureCluster") {
		if c.Gen != 1 || c.HealthWait != 0 {
			t.Fatalf("EnsureCluster %+v", c)
		}
	}
	if c := e.ag.callsOf(ref, "SetRoute"); len(c) != 1 || c[0].State != "active" {
		t.Fatalf("SetRoute %+v", c)
	}
	if c := e.ag.callsOf(ref, "ProbeREST"); c[0].Token != e.secret(ref, "token.anon") {
		t.Fatal("probe not made with the anon token")
	}
	for _, s := range e.ag.specs {
		if s.Epoch != 1 || s.Generation != 1 {
			t.Fatalf("spec epoch %d generation %d", s.Epoch, s.Generation)
		}
	}
}

// Invariant (d): a project is active only after the end-to-end probe.
func TestCreate_ActiveOnlyAfterProbe(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	var mu sync.Mutex
	var stateAtProbe []string
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "ProbeREST" {
			p, _ := e.st.GetProject(ctx, ref)
			mu.Lock()
			stateAtProbe = append(stateAtProbe, p.State)
			mu.Unlock()
		}
	})
	e.ag.setErr(failOn("ProbeREST"))
	stop := e.start(e.runner())
	op := e.waitState(id, "failed")
	stop()
	if op.Step != "9" || e.project(ref).State != "provisioning" {
		t.Fatalf("op %+v, project %s", op, e.project(ref).State)
	}
	if len(stateAtProbe) == 0 || slices.ContainsFunc(stateAtProbe, func(s string) bool { return s != "provisioning" }) {
		t.Fatalf("state at probe %v", stateAtProbe)
	}
}

// Every boundary: the worker stops before step s (a failpoint), or after
// step s's effects but before recording it (the step rewound in the store);
// a new runner resumes and every node object and every secret is made once.
func TestCreate_ResumeFromEachStep(t *testing.T) {
	for i, s := range createIDs {
		for _, mode := range []string{"before", "rewound"} {
			t.Run(s+"/"+mode, func(t *testing.T) {
				e := newEnv(t)
				ref, id := e.create()
				var keep []string
				var uid int
				if mode == "before" {
					e.failpoint("create:" + s)
					<-e.run(e.runner()) // ends at the failpoint
					if op := e.op(id); op.State != "running" {
						t.Fatalf("after the failpoint: %+v", op)
					}
					if _, err := os.Stat(e.p.Failpoint()); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("failpoint file not consumed")
					}
				} else {
					stop := e.start(e.runner())
					e.waitState(id, "done")
					stop()
					prev := "1"
					if i > 0 {
						prev = createIDs[i-1]
					}
					keep = []string{e.secret(ref, "pg.postgres.password"), e.secret(ref, "jwt.anon.private"), e.secret(ref, "token.anon")}
					uid = *e.project(ref).UID
					sql(t, "update operation set state = 'running', step = $2 where id = $1", id, prev)
					// Until step 12 commits, the project is provisioning.
					sql(t, "update project set state = 'provisioning', applied_gen = 0 where ref = $1", ref)
				}
				e.start(e.runner())
				op := e.waitState(id, "done")
				if p := e.project(ref); p.State != "active" || op.Step != "12" {
					t.Fatalf("project %s, op %+v", p.State, op)
				}
				e.ag.locked(func() {
					for k, n := range e.ag.effects {
						if n != 1 {
							t.Errorf("effect %q happened %d times", k, n)
						}
					}
				})
				if keep != nil {
					got := []string{e.secret(ref, "pg.postgres.password"), e.secret(ref, "jwt.anon.private"), e.secret(ref, "token.anon")}
					if !slices.Equal(got, keep) {
						t.Fatal("a secret was generated again on resume")
					}
					if got := *e.project(ref).UID; got != uid {
						t.Fatalf("uid %d drawn again (was %d)", got, uid)
					}
				}
			})
		}
	}
}

func TestCreate_ResumeAtStep4_GateRuns(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:4")
	<-e.run(e.runner())
	if op := e.op(id); op.Step != "4a" {
		t.Fatalf("stopped at %+v", op)
	}
	e.ag.reset()
	// The resumed step 4 lands in EnsureCluster, whose start gate refuses.
	e.ag.setErr(func(c call) error {
		if c.Method == "EnsureCluster" {
			return fmt.Errorf("start gate: %w", agent.ErrContainment)
		}
		return nil
	})
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if !strings.HasPrefix(op.LastError, "containment_failed: ") || op.Step != "4a" || op.Attempts != 2 {
		t.Fatalf("op = %+v", op)
	}
	wantSeq(t, e.ag.methods(ref), []string{"EnsureCluster"})
}

// Another ref's create waits for the single worker; on one ref a purge
// queues behind its delete.
func TestCreate_SecondOperationQueues(t *testing.T) {
	e := newEnv(t)
	refA, a := e.create()
	_, b := e.create()
	inStep := make(chan struct{})
	release := make(chan struct{})
	var freed sync.Once
	free := func() { freed.Do(func() { close(release) }) }
	defer free() // a failing test must not leave the worker blocked in the hook
	var first sync.Once
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "EnsureCluster" && c.Ref == refA {
			first.Do(func() { close(inStep); <-release })
		}
	})
	r := e.runner()
	e.start(r)
	<-inStep
	time.Sleep(50 * time.Millisecond)
	if op := e.op(b); op.State != "pending" || op.Attempts != 0 {
		t.Fatalf("second create started beside the first: %+v", op)
	}
	free()
	e.waitState(a, "done")
	e.waitState(b, "done")

	del, purge := e.deleted(r, refA)
	if purge <= del || e.op(purge).Kind != "purge" {
		t.Fatalf("purge %d after delete %d", purge, del)
	}
	e.waitState(purge, "done")
	if e.op(purge).UpdatedAt.Before(e.op(del).UpdatedAt) {
		t.Fatal("purge finished before its delete")
	}
}

// Forward only: five failed attempts leave the create failed at its step,
// with nothing compensated.
func TestCreate_RetryThenFailed(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.ag.setErr(failOn("EnsureNetwork"))
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if op.Attempts != 5 || op.Step != "2" || op.LastError != "internal: boom" {
		t.Fatalf("op = %+v", op)
	}
	if got := len(e.ag.callsOf(ref, "EnsureNetwork")); got != 5 {
		t.Fatalf("%d EnsureNetwork calls", got)
	}
	if p := e.project(ref); p.State != "provisioning" || p.SubnetIndex == nil {
		t.Fatalf("project = %+v", p)
	}
	for _, m := range e.ag.methods(ref) {
		if m != "EnsureDir" && m != "EnsureNetwork" {
			t.Fatalf("compensating call %s", m)
		}
	}
	if _, _, err := e.st.GetDEK(context.Background(), ref); err != nil {
		t.Fatalf("keys touched: %v", err)
	}
}

// The default back-off between attempts: 2 s, 5 s, 15 s, 30 s.
func TestRetry_BackoffSchedule(t *testing.T) {
	e := newEnv(t)
	_, id := e.create()
	e.ag.setErr(failOn("EnsureDir"))
	r := e.runner()
	r.backoff = New(e.st, e.ag, e.kek, e.cfg, e.p).backoff
	want := []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second, 60 * time.Second}
	if !slices.Equal(r.backoff, want) {
		t.Fatalf("default backoff %v", r.backoff)
	}
	e.start(r)
	for n := 1; n <= 4; n++ {
		op := e.wait(id, "backed off", func(op store.Operation) bool { return op.State == "pending" && op.Attempts == n })
		if d := op.NotBefore.Sub(op.UpdatedAt); (d - want[n-1]).Abs() > 200*time.Millisecond {
			t.Fatalf("attempt %d: retry after %v, want %v", n, d, want[n-1])
		}
		sql(t, "update operation set not_before = now() where id = $1", id)
	}
	e.waitState(id, "failed")
}

func TestCreate_NodeFullAbortsWithoutRetry(t *testing.T) {
	c := testConfig()
	c.MemAllocMB = 100 // below one project's admission share
	e := newEnvWith(t, c)
	ref, id := e.create()
	e.start(e.runner())
	op := e.waitState(id, "aborted")
	// One attempt (attempts was reset when the create moved to aborting).
	if n := len(e.logs.records("step failed")); n != 1 || op.Attempts != 0 || !strings.HasPrefix(op.LastError, "node_full: ") {
		t.Fatalf("op = %+v", op)
	}
	wantSeq(t, e.ag.methods(ref), []string{"SetRoute", "StopPostgREST", "StopCluster", "RemoveRender", "RemoveNetwork"})
	if p := e.project(ref); p.State != "aborted" || p.UID != nil || p.SubnetIndex != nil {
		t.Fatalf("project = %+v", p)
	}
	if _, _, err := e.st.GetDEK(context.Background(), ref); !errors.Is(err, store.ErrDestroyed) {
		t.Fatalf("DEK: %v", err)
	}
}

func TestCreate_ContainmentNotRetried(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.ag.setErr(func(c call) error {
		if c.Method == "EnsureNetwork" {
			return fmt.Errorf("proj network: %w", agent.ErrContainment)
		}
		return nil
	})
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if op.Attempts != 1 || !strings.HasPrefix(op.LastError, "containment_failed: ") {
		t.Fatalf("op = %+v", op)
	}
	if n := len(e.ag.callsOf(ref, "EnsureNetwork")); n != 1 {
		t.Fatalf("%d attempts", n)
	}
}

// An issuer key with a platform key's kid fails step 6, not retried, and
// no key is written.
func TestCreate_IssuerKidCollisionRefused(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:6")
	<-e.run(e.runner())
	k, err := x509.ParsePKCS8PrivateKey([]byte(e.secret(ref, "jwt.anon.private")))
	must(t, err)
	pub := &k.(*rsa.PrivateKey).PublicKey
	params := issuerJWKS(t, issuerKey, jwtx.Key{KID: jwtx.KID(pub), Class: "issuer", Pub: pub})
	sql(t, "update operation set params = $2 where id = $1", id, string(params))
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if op.LastError != "bad_request: issuer kid collides with a platform kid" || op.Step != "4" || op.Attempts != 2 {
		t.Fatalf("op = %+v", op)
	}
	ks, err := e.st.ListKeys(context.Background(), ref)
	must(t, err)
	if len(ks) != 0 {
		t.Fatalf("keys written: %+v", ks)
	}
}

func TestTokens_ClaimsAndKids(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.start(e.runner())
	e.waitState(id, "done")
	check := func() []string {
		rows, err := e.st.ListKeys(context.Background(), ref)
		must(t, err)
		if len(rows) != 3 {
			t.Fatalf("keys %+v", rows)
		}
		var keys []jwtx.Key
		for _, row := range rows {
			k, err := keyFromRow(row)
			must(t, err)
			keys = append(keys, k)
		}
		var toks []string
		for _, class := range []string{"anon", "service_role"} {
			pk, err := x509.ParsePKCS8PrivateKey([]byte(e.secret(ref, "jwt."+class+".private")))
			must(t, err)
			tok := e.secret(ref, "token."+class)
			toks = append(toks, tok)
			k, c, err := jwtx.Verify(tok, keys, time.Now())
			must(t, err)
			if k.KID != jwtx.KID(&pk.(*rsa.PrivateKey).PublicKey) || string(k.Class) != class {
				t.Fatalf("%s token verified by %+v", class, k)
			}
			must(t, jwtx.CheckRole(k, c, nil))
			iat, _ := c.Raw["iat"].(json.Number).Int64()
			if c.Role != class || c.Raw["iss"] != "supapace" || c.Raw["ref"] != ref ||
				c.Exp != time.Unix(iat, 0).AddDate(10, 0, 0).Unix() || time.Since(time.Unix(iat, 0)) > time.Minute {
				t.Fatalf("%s claims %+v", class, c.Raw)
			}
		}
		return toks
	}
	first := check()
	// Resumed at step 6: the kids are those of the stored keys.
	sql(t, "update project set state = 'provisioning' where ref = $1", ref)
	sql(t, "update operation set state = 'running', step = '4' where id = $1", id)
	e.waitState(id, "done")
	if !slices.Equal(check(), first) {
		t.Fatal("tokens minted again")
	}
}

// ───────── worker ─────────

func TestRun_PausedWhileContainmentFailed(t *testing.T) {
	e := newEnv(t)
	_, id := e.create()
	e.ag.failed.Store(true)
	e.start(e.runner())
	time.Sleep(100 * time.Millisecond)
	if op := e.op(id); op.State != "pending" || op.Attempts != 0 || len(e.ag.methods("")) != 0 {
		t.Fatalf("operation taken while paused: %+v %v", op, e.ag.methods(""))
	}
	e.ag.failed.Store(false)
	e.waitState(id, "done")
}

func TestContainmentErrorWhileFlagSet_Requeued(t *testing.T) {
	e := newEnv(t)
	_, id := e.create()
	var n atomic.Int32
	e.ag.setErr(func(c call) error {
		if c.Method != "EnsureCluster" {
			return nil
		}
		switch k := n.Add(1); {
		case k <= 6:
			e.ag.failed.Store(true) // the node lost containment under the step
			time.AfterFunc(30*time.Millisecond, func() { e.ag.failed.Store(false) })
			return fmt.Errorf("start gate: %w", agent.ErrContainment)
		case k == 7:
			return errBoom // an ordinary failure: the requeues did not use up the attempts
		}
		return nil
	})
	r := e.runner()
	e.start(r)
	op := e.wait(id, "requeued", func(op store.Operation) bool { return op.State == "pending" && op.Attempts == 1 })
	if !strings.HasPrefix(op.LastError, "containment_failed: ") ||
		(op.NotBefore.Sub(op.UpdatedAt)-r.containmentRetry).Abs() > 15*time.Millisecond {
		t.Fatalf("op = %+v", op)
	}
	op = e.waitState(id, "done")
	if op.Attempts != 8 || n.Load() != 9 { // six requeues, one failure, then steps 4a and 4
		t.Fatalf("op = %+v, %d EnsureCluster calls", op, n.Load())
	}
	if New(e.st, e.ag, e.kek, e.cfg, e.p).containmentRetry != 10*time.Second {
		t.Fatal("default requeue delay is not 10 s")
	}
}

// Two ready operations on different refs never overlap, even with two Run
// calls on one runner.
func TestRun_SingleWorker(t *testing.T) {
	e := newEnv(t)
	_, a := e.create()
	_, b := e.create()
	// A slow step of one operation leaves time for a second worker to take
	// the other ref, were there one.
	e.ag.setHook(func(ctx context.Context, c call) {
		d := 3 * time.Millisecond
		if c.Method == "EnsureCluster" {
			d = 100 * time.Millisecond
		}
		time.Sleep(d)
	})
	r := e.runner()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); r.Run(ctx) }()
	}
	defer wg.Wait()
	defer cancel()
	e.waitState(a, "done")
	e.waitState(b, "done")
	if m := e.ag.maxInflight.Load(); m != 1 {
		t.Fatalf("%d agent calls ran at once", m)
	}
}

// Invariant (a): the ref lock is held for the whole operation, and an
// operation whose ref lock another session holds is not taken.
func TestRun_HoldsRefLock(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	refA, a := e.create()
	refB, b := e.create()
	unlock, err := e.st.LockRef(ctx, refA)
	must(t, err)
	defer unlock() // idempotent; a failing test must not keep a pool connection
	inStep := make(chan struct{})
	release := make(chan struct{})
	var freed sync.Once
	free := func() { freed.Do(func() { close(release) }) }
	defer free() // a failing test must not leave the worker blocked in the hook
	var first sync.Once
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "EnsureCluster" && c.Ref == refB {
			first.Do(func() { close(inStep); <-release })
		}
	})
	e.start(e.runner())
	<-inStep
	if u, ok, err := e.st.TryLockRef(ctx, refB); err != nil || ok {
		if ok {
			u()
		}
		t.Fatalf("B's lock free while its step runs (ok %v, err %v)", ok, err)
	}
	free()
	e.waitState(b, "done")
	if op := e.op(a); op.State != "pending" || op.Attempts != 0 {
		t.Fatalf("A taken while its lock was held: %+v", op)
	}
	unlock()
	e.waitState(a, "done")
	u, ok, err := e.st.TryLockRef(ctx, refB)
	must(t, err)
	if !ok {
		t.Fatal("B's lock still held after its operation")
	}
	u()
}

func TestRun_StepDeadlineFailsAttempt(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:3") // keys generated outside the timed attempt
	<-e.run(e.runner())
	var stall atomic.Bool
	stall.Store(true)
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "EnsureCluster" && stall.Load() {
			<-ctx.Done()
		}
	})
	r := e.runner()
	r.stepDeadline = 100 * time.Millisecond
	r.backoff = []time.Duration{time.Hour}
	e.start(r)
	op := e.wait(id, "backed off", func(op store.Operation) bool { return op.State == "pending" && op.Attempts == 2 })
	if !strings.HasPrefix(op.LastError, "timeout: ") || op.Step != "3" {
		t.Fatalf("op = %+v", op)
	}
	stall.Store(false)
	sql(t, "update operation set not_before = now() where id = $1", id)
	e.waitState(id, "done")
	if n := len(e.ag.callsOf(ref, "EnsureDir")); n != 1 {
		t.Fatalf("resumed before the step it reached: %d EnsureDir calls", n)
	}
	if New(e.st, e.ag, e.kek, e.cfg, e.p).stepDeadline != 300*time.Second {
		t.Fatal("default step deadline is not 300 s")
	}
}

func TestRun_AttemptDeadlineFailsAttempt(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:3") // keys generated outside the timed attempt
	<-e.run(e.runner())
	var slow atomic.Bool
	slow.Store(true)
	e.ag.setHook(func(ctx context.Context, c call) {
		switch c.Method {
		case "EnsureDir", "EnsureCluster", "EnsurePostgREST":
			if slow.Load() {
				select {
				case <-time.After(250 * time.Millisecond):
				case <-ctx.Done():
				}
			}
		}
	})
	r := e.runner()
	r.stepDeadline = 300 * time.Millisecond
	r.attemptDeadline = 900 * time.Millisecond
	r.backoff = []time.Duration{time.Hour}
	e.start(r)
	// Steps 3, 4a and 4 each succeed in 250 ms; step 9 hits the attempt deadline.
	op := e.wait(id, "backed off", func(op store.Operation) bool { return op.State == "pending" && op.Attempts == 2 })
	if !strings.HasPrefix(op.LastError, "timeout: ") || op.Step != "7" {
		t.Fatalf("op = %+v", op)
	}
	slow.Store(false)
	sql(t, "update operation set not_before = now() where id = $1", id)
	e.waitState(id, "done")
	if n := len(e.ag.callsOf(ref, "EnsureDir")); n != 1 {
		t.Fatalf("%d EnsureDir calls", n)
	}
	if New(e.st, e.ag, e.kek, e.cfg, e.p).attemptDeadline != 900*time.Second {
		t.Fatal("default attempt deadline is not 900 s")
	}
}

func TestRun_OtherProjectRunsWhileOneBacksOff(t *testing.T) {
	e := newEnv(t)
	refA, a := e.create()
	_, b := e.create()
	e.ag.setErr(func(c call) error {
		if c.Method == "EnsureNetwork" && c.Ref == refA {
			return errBoom
		}
		return nil
	})
	r := e.runner()
	r.backoff = []time.Duration{time.Hour}
	e.start(r)
	e.waitState(b, "done")
	if op := e.op(a); op.Attempts != 1 || op.State != "pending" {
		t.Fatalf("A = %+v", op)
	}
}

// Fairness: B's restart starts after at most one attempt of each hostile
// project's operation queued ahead of it.
func TestRun_RoundRobinPerProject(t *testing.T) {
	for _, hostile := range []bool{true, false} {
		t.Run(fmt.Sprint("hostile=", hostile), func(t *testing.T) {
			e := newEnv(t)
			h1, h2, b := e.active(), e.active(), e.active()
			r := e.runner()
			r.stepDeadline = 300 * time.Millisecond
			r.backoff = []time.Duration{0}
			if hostile {
				e.restart(r, h1, defaultConfig)
				e.restart(r, h2, defaultConfig)
			}
			bid := e.restart(r, b, defaultConfig)
			e.ag.setHook(func(ctx context.Context, c call) {
				if c.Method == "Prevalidate" && c.Ref != b {
					<-ctx.Done() // every attempt fails at the step deadline
				}
			})
			e.start(r)
			e.waitState(bid, "done")
			var before []string
			e.ag.locked(func() {
				for _, c := range e.ag.calls {
					if c.Method == "Prevalidate" {
						if c.Ref == b {
							break
						}
						before = append(before, c.Ref)
					}
				}
			})
			want := []string{}
			if hostile {
				want = []string{h1, h2}
			}
			slices.Sort(before)
			if !slices.Equal(before, want) && !(len(before) == 0 && len(want) == 0) {
				t.Fatalf("attempts before B's: %v, want %v", before, want)
			}
		})
	}
}

// ───────── abort ─────────

var compensationCalls = []string{"SetRoute", "StopPostgREST", "StopCluster", "RemoveRender", "RemoveNetwork", "PurgeDir"}

// The whole compensation list, in order, whichever step failed.
func TestAbort_RunsWholeListInOrder(t *testing.T) {
	for _, tc := range []struct{ name, method, step string }{
		{"inside 3", "EnsureNetwork", "2"},
		{"inside 4a", "EnsureCluster", "3"},
		{"after 9", "ProbeREST", "9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			ref, id := e.create()
			e.ag.setErr(failOn(tc.method))
			r := e.runner()
			e.start(r)
			if op := e.waitState(id, "failed"); op.Step != tc.step {
				t.Fatalf("failed at %+v", op)
			}
			e.ag.reset()
			e.ag.setErr(nil)
			var keysAtRender atomic.Value
			e.ag.setHook(func(ctx context.Context, c call) {
				if c.Method == "RemoveRender" {
					_, _, err := e.st.GetDEK(ctx, ref)
					keysAtRender.Store(fmt.Sprint(err))
				}
			})
			got, err := r.Abort(context.Background(), ref)
			must(t, err)
			if got != id {
				t.Fatalf("Abort returned %d, want %d", got, id)
			}
			op := e.waitState(id, "aborted")
			wantSeq(t, e.ag.methods(ref), compensationCalls)
			if c := e.ag.callsOf(ref, "SetRoute"); c[0].State != "" {
				t.Fatalf("C1 = %+v", c[0])
			}
			if keysAtRender.Load() != store.ErrDestroyed.Error() {
				t.Fatalf("keys at C5: %v", keysAtRender.Load())
			}
			if p := e.project(ref); p.State != "aborted" || op.LastError != "" {
				t.Fatalf("project %s, op %+v", p.State, op)
			}
		})
	}
}

func TestAbort_KeysDestroyedBeforePurgeDir(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:4")
	<-e.run(e.runner())
	var keysAtPurge atomic.Value
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "PurgeDir" {
			_, _, err := e.st.GetDEK(ctx, ref)
			keysAtPurge.Store(fmt.Sprint(err))
		}
	})
	e.ag.setErr(failOn("PurgeDir"))
	r := e.runner()
	r.backoff = []time.Duration{time.Hour}
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	e.start(r)
	op := e.wait(id, "backed off", func(op store.Operation) bool { return op.Attempts == 1 })
	if op.State != "aborting" || keysAtPurge.Load() != store.ErrDestroyed.Error() {
		t.Fatalf("op %+v, keys at purge %v", op, keysAtPurge.Load())
	}
	if _, _, err := e.st.GetDEK(context.Background(), ref); !errors.Is(err, store.ErrDestroyed) {
		t.Fatalf("keys after the failed purge: %v", err)
	}
	ks, err := e.st.ListKeys(context.Background(), ref)
	must(t, err)
	if len(ks) != 0 {
		t.Fatalf("keys left %+v", ks)
	}
}

func TestAbort_RemovesRenderDir(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:6")
	<-e.run(e.runner())
	e.ag.locked(func() {
		if !e.ag.render[ref] {
			t.Fatal("no render directory after step 4")
		}
	})
	r := e.runner()
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	e.start(r)
	e.waitState(id, "aborted")
	if len(e.ag.callsOf(ref, "RemoveRender")) != 1 {
		t.Fatal("no RemoveRender call")
	}
	e.ag.locked(func() {
		if e.ag.render[ref] {
			t.Fatal("render directory not removed")
		}
	})
}

func TestAbort_RetiresUIDFreesSlice(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:4a")
	<-e.run(e.runner())
	before := e.project(ref)
	r := e.runner()
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	e.start(r)
	e.waitState(id, "aborted")
	p := e.project(ref)
	if p.State != "aborted" || p.UID == nil || *p.UID != *before.UID || p.SubnetIndex != nil {
		t.Fatalf("project = %+v", p)
	}
	ref2, id2 := e.create()
	e.waitState(id2, "done")
	p2 := e.project(ref2)
	if *p2.SubnetIndex != *before.SubnetIndex || *p2.UID <= *before.UID {
		t.Fatalf("next project uid %d slice %d; aborted had %d, %d", *p2.UID, *p2.SubnetIndex, *before.UID, *before.SubnetIndex)
	}
}

// Abort while a step runs: nothing is compensated until the step returns;
// then the step's bookkeeping is refused and the worker compensates.
func abortMidStep(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	inStep := make(chan struct{})
	release := make(chan struct{})
	var freed sync.Once
	free := func() { freed.Do(func() { close(release) }) }
	defer free() // a failing test must not leave the worker blocked in the hook
	var first sync.Once
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "EnsureCluster" {
			first.Do(func() { close(inStep); <-release })
		}
	})
	r := e.runner()
	e.start(r)
	<-inStep
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	time.Sleep(50 * time.Millisecond)
	for _, m := range e.ag.methods(ref) {
		if slices.Contains(compensationCalls, m) {
			t.Fatalf("compensation call %s while the step runs", m)
		}
	}
	if op := e.op(id); op.State != "aborting" || op.Step != "3" {
		t.Fatalf("op = %+v", op)
	}
	free()
	op := e.waitState(id, "aborted")
	if op.Step != "3" || op.Attempts != 0 {
		t.Fatalf("step bookkeeping overwrote the abort, or counted a compensation run: %+v", op)
	}
	calls := e.ag.methods(ref)
	wantSeq(t, calls[slices.Index(calls, "EnsureCluster")+1:], compensationCalls)
}

func TestAbort_OnlyLockHolderCompensates(t *testing.T)      { abortMidStep(t) }
func TestAbortRequestedMidStep_NotOverwritten(t *testing.T) { abortMidStep(t) }

func TestAbort_CompensationFailureBacksOff(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:4")
	<-e.run(e.runner())
	var broken atomic.Bool
	broken.Store(true)
	e.ag.setErr(func(c call) error {
		if c.Method == "PurgeDir" && broken.Load() {
			return errBoom
		}
		return nil
	})
	r := e.runner()
	r.backoff = []time.Duration{time.Hour}
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	e.start(r)
	op := e.wait(id, "backed off", func(op store.Operation) bool { return op.Attempts == 1 })
	if op.State != "aborting" || op.LastError != "internal: boom" || op.NotBefore.Sub(op.UpdatedAt) < 59*time.Minute {
		t.Fatalf("op = %+v", op)
	}
	// The worker serves another ref meanwhile; it does not spin on this one.
	_, other := e.create()
	e.waitState(other, "done")
	if n := len(e.ag.callsOf(ref, "PurgeDir")); n != 1 {
		t.Fatalf("%d compensation runs in the back-off window", n)
	}
	broken.Store(false)
	runs := len(e.ag.callsOf(ref, "SetRoute"))
	sql(t, "update operation set not_before = now() where id = $1", id)
	e.waitState(id, "aborted")
	if got := len(e.ag.callsOf(ref, "SetRoute")); got != runs+1 {
		t.Fatalf("list not re-run from C1: %d SetRoute calls (was %d)", got, runs)
	}
	calls := e.ag.methods(ref)
	wantSeq(t, calls[len(calls)-len(compensationCalls):], compensationCalls)
}

// After 8 failed compensation runs the abort is parked failed; project
// abort re-arms it.
func compensationParks(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:4")
	<-e.run(e.runner())
	e.ag.setErr(failOn("PurgeDir"))
	r := e.runner()
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	e.start(r)
	op := e.waitState(id, "failed")
	if n := len(e.ag.callsOf(ref, "PurgeDir")); op.Attempts != 8 || op.LastError != "internal: boom" || n != 8 {
		t.Fatalf("op = %+v after %d runs", op, n)
	}
	if p := e.project(ref); p.State != "provisioning" || p.SubnetIndex == nil {
		t.Fatalf("parked project = %+v", p)
	}
	e.ag.setErr(nil)
	if _, err := r.Abort(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	e.waitState(id, "aborted")
}

func TestAbort_CompensationAttemptsBounded(t *testing.T) { compensationParks(t) }
func TestAbort_ParksAfterEighthFailAttempt(t *testing.T) { compensationParks(t) }

// ───────── restart ─────────

func withGUC(k, v string) store.ProjectConfig {
	c := defaultConfig
	c.GUC = map[string]string{k: v}
	return c
}

func TestSubmit_StoresPrevNextAndRefusesStaleBase(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	r := e.runner()
	ctx := context.Background()
	stale, _ := json.Marshal(map[string]any{"base_generation": 7, "config": defaultConfig})
	if _, err := r.Submit(ctx, "restart", ref, stale); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale base: %v", err)
	}
	for _, k := range []string{"create", "purge", "bogus"} {
		if _, err := r.Submit(ctx, k, ref, nil); err == nil {
			t.Fatalf("Submit(%s) accepted", k)
		}
	}
	if _, err := r.Submit(ctx, "restart", ref, json.RawMessage(`{"base_generation":1,"config":{},"x":1}`)); err == nil {
		t.Fatal("unknown member accepted")
	}
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	op := e.op(id)
	var got map[string]any
	must(t, json.Unmarshal(op.Params, &got))
	want := map[string]any{"base_generation": float64(1),
		"prev": map[string]any{"disk_quota_mb": float64(8192), "mem_mb": float64(512), "guc": map[string]any{}},
		"next": map[string]any{"disk_quota_mb": float64(8192), "mem_mb": float64(512), "guc": map[string]any{"max_connections": "200"}}}
	if fmt.Sprint(got) != fmt.Sprint(want) || op.Generation != 2 {
		t.Fatalf("params %s, generation %d", op.Params, op.Generation)
	}
}

func TestRestart_HappyPathOrder(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.start(r)
	op := e.waitState(id, "done")
	wantSeq(t, e.steps(id), []string{"R0", "R1", "R2", "R3", "R4", "R5"})
	wantSeq(t, e.ag.methods(ref), []string{"Prevalidate", "SetRoute", "StopPostgREST", "StopCluster",
		"PromoteCandidate", "EnsureCluster", "EnsureCluster", "VerifyCluster", "EnsurePostgREST", "SetRoute", "ProbeREST"})
	p := e.project(ref)
	if p.State != "active" || p.Generation != 2 || p.AppliedGen != 2 || p.Config.GUC["max_connections"] != "200" || op.LastError != "" {
		t.Fatalf("project %+v, op %+v", p, op)
	}
	if c := e.ag.callsOf(ref, "SetRoute"); c[0].State != "draining" || c[1].State != "active" {
		t.Fatalf("routes %+v", c)
	}
	for _, m := range []string{"Prevalidate", "EnsureCluster", "VerifyCluster", "EnsurePostgREST"} {
		for _, c := range e.ag.callsOf(ref, m) {
			if c.Gen != 2 || c.GUC["max_connections"] != "200" {
				t.Fatalf("%s %+v", m, c)
			}
		}
	}
}

func TestRestart_QuotaOnly(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	r := e.runner()
	next := defaultConfig
	next.DiskQuotaMB = 16384
	id := e.restart(r, ref, next)
	e.start(r)
	e.waitState(id, "done")
	// The quota of the bumped configuration, at R3 while the cluster is
	// stopped: after pre-validation and the bump, before the new start.
	calls := e.ag.methods(ref)
	if i := slices.Index(calls, "SetQuota"); i < 0 || calls[i-1] != "StopCluster" || calls[i+1] != "PromoteCandidate" {
		t.Fatalf("calls %v", calls)
	}
	if c := e.ag.callsOf(ref, "SetQuota"); len(c) != 1 || c[0].Quota != 16384 || c[0].Gen != 2 {
		t.Fatalf("SetQuota %+v", c)
	}
	if p := e.project(ref); p.Config.DiskQuotaMB != 16384 || p.State != "active" {
		t.Fatalf("project %+v", p)
	}
	// Without a quota change there is no SetQuota.
	e.ag.reset()
	next.GUC = map[string]string{"max_connections": "200"}
	id = e.restart(r, ref, next)
	e.waitState(id, "done")
	if len(e.ag.callsOf(ref, "SetQuota")) != 0 {
		t.Fatal("SetQuota without a quota change")
	}
}

func TestRestart_PrevalidateFailureTouchesNothing(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	e.ag.setErr(failOn("Prevalidate"))
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.start(r)
	op := e.waitState(id, "failed")
	if p := e.project(ref); p.Generation != 1 || len(p.Config.GUC) != 0 || p.State != "active" || op.Step != "R0" {
		t.Fatalf("project %+v, op %+v", p, op)
	}
	for _, m := range e.ag.methods(ref) {
		if m != "Prevalidate" {
			t.Fatalf("call %s after a failed pre-validation", m)
		}
	}
}

func TestRestart_BumpOnlyAtR2(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	var mu sync.Mutex
	var genAtPrevalidate []int64
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "Prevalidate" {
			p, _ := e.st.GetProject(ctx, ref)
			mu.Lock()
			genAtPrevalidate = append(genAtPrevalidate, p.Generation)
			mu.Unlock()
		}
	})
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.failpoint("restart:R3")
	<-e.run(r)
	mu.Lock()
	if !slices.Equal(genAtPrevalidate, []int64{1}) {
		t.Fatalf("generation at Prevalidate %v", genAtPrevalidate)
	}
	mu.Unlock()
	if p := e.project(ref); p.Generation != 2 || p.State != "restarting" {
		t.Fatalf("after R2: %+v", p)
	}
	// Resumed R2 (its effects done, the step not recorded): no second bump.
	sql(t, "update operation set step = 'R1' where id = $1", id)
	e.start(e.runner())
	e.waitState(id, "done")
	if p := e.project(ref); p.Generation != 2 || p.AppliedGen != 2 {
		t.Fatalf("project %+v", p)
	}
}

func failVerifyAt(e *env, gens ...int64) {
	e.ag.setErr(func(c call) error {
		if c.Method == "VerifyCluster" && slices.Contains(gens, c.Gen) {
			return errBoom
		}
		return nil
	})
}

func TestRestart_RollsForwardOnHealthTimeout(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	failVerifyAt(e, 2)
	var paramsAtRollback atomic.Value
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "Prevalidate" && c.Gen == 3 {
			ops, _ := e.st.ListOperations(ctx, ref)
			paramsAtRollback.Store([]byte(ops[0].Params))
		}
	})
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.start(r)
	op := e.waitState(id, "done")
	var gens []int64
	for _, c := range e.ag.callsOf(ref, "EnsureCluster") {
		gens = append(gens, c.Gen)
	}
	if !slices.Equal(gens, []int64{2, 2, 3, 3}) {
		t.Fatalf("EnsureCluster generations %v", gens)
	}
	var rp struct {
		RollbackGen int64 `json:"rollback_gen"`
	}
	b, _ := paramsAtRollback.Load().([]byte)
	must(t, json.Unmarshal(b, &rp))
	if rp.RollbackGen != 3 {
		t.Fatalf("params at the rollback's R1: %s", b)
	}
	if pv := e.ag.callsOf(ref, "Prevalidate"); len(pv) != 2 || len(pv[1].GUC) != 0 {
		t.Fatalf("rollback did not carry prev: %+v", pv)
	}
	if p := e.project(ref); p.State != "active" || p.Generation != 3 || p.AppliedGen != 3 || len(p.Config.GUC) != 0 {
		t.Fatalf("project %+v", p)
	}
	if !strings.Contains(op.LastError, "boom") {
		t.Fatalf("health failure not recorded: %+v", op)
	}
}

func TestRestart_ResumeIntoRollback(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	e.ag.setErr(func(c call) error {
		if c.Method == "VerifyCluster" && c.Gen == 2 {
			os.WriteFile(e.p.Failpoint(), []byte("restart:R1"), 0o600) // the next boundary is the rollback's R1
			return errBoom
		}
		return nil
	})
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	<-e.run(r)
	if op := e.op(id); op.State != "running" || !strings.Contains(string(op.Params), `"rollback_gen": 3`) {
		t.Fatalf("op at the failpoint %+v", op)
	}
	e.ag.reset()
	e.ag.setErr(nil)
	e.start(e.runner())
	e.waitState(id, "done")
	if c := e.ag.callsOf(ref, "Prevalidate"); len(c) != 1 || c[0].Gen != 3 || len(c[0].GUC) != 0 {
		t.Fatalf("resume did not continue the rollback: %+v", c)
	}
	for _, c := range e.ag.callsOf(ref, "EnsureCluster") {
		if c.Gen != 3 {
			t.Fatalf("generation %d applied after the rollback started", c.Gen)
		}
	}
	if p := e.project(ref); p.Generation != 3 || p.State != "active" {
		t.Fatalf("project %+v", p)
	}
}

func TestRestart_SecondFailureLeavesDraining(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	failVerifyAt(e, 2, 3)
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.start(r)
	op := e.waitState(id, "failed")
	if p := e.project(ref); p.State != "restarting" || p.Generation != 3 || op.Attempts != 1 {
		t.Fatalf("project %+v, op %+v", p, op)
	}
	e.ag.locked(func() {
		if e.ag.route[ref].State != "draining" {
			t.Fatalf("route %+v", e.ag.route[ref])
		}
	})
	for _, c := range e.ag.callsOf(ref, "EnsureCluster") {
		if c.Gen == 1 {
			t.Fatal("generation 1 re-applied")
		}
	}
}

func TestRestart_FailedIsContinuedByRetryNotResubmit(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	var broken atomic.Bool
	broken.Store(true)
	e.ag.setErr(func(c call) error {
		if c.Method == "PromoteCandidate" && broken.Load() {
			return errBoom
		}
		return nil
	})
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.start(r)
	op := e.waitState(id, "failed")
	if op.Step != "R2" || e.project(ref).State != "restarting" {
		t.Fatalf("op %+v", op)
	}
	params, _ := json.Marshal(map[string]any{"base_generation": 2, "config": defaultConfig})
	if _, err := r.Submit(context.Background(), "restart", ref, params); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second restart: %v", err)
	}
	broken.Store(false)
	must(t, e.st.RetryOperation(context.Background(), id))
	e.waitState(id, "done")
	if n := len(e.ag.callsOf(ref, "Prevalidate")); n != 1 {
		t.Fatalf("resumed before its recorded step: %d Prevalidate calls", n)
	}
	if p := e.project(ref); p.State != "active" || p.Generation != 2 {
		t.Fatalf("project %+v", p)
	}
}

func TestRestart_R4ReEnsuresWithHealthWait(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.start(r)
	e.waitState(id, "done")
	calls := e.ag.methods(ref)
	i := slices.Index(calls, "PromoteCandidate")
	wantSeq(t, calls[i+1:i+4], []string{"EnsureCluster", "EnsureCluster", "VerifyCluster"})
	ec := e.ag.callsOf(ref, "EnsureCluster")
	if ec[0].HealthWait >= 0 || ec[1].HealthWait != 0 || ec[0].Gen != 2 || ec[1].Gen != 2 {
		t.Fatalf("EnsureCluster %+v", ec)
	}
}

// The worker's own check: a restart whose merge base is not the generation
// before its target fails with code conflict, nothing touched.
func TestRestart_R0RefusesStaleBase(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	params, _ := json.Marshal(map[string]any{"base_generation": 5, "prev": defaultConfig, "next": defaultConfig})
	id, err := e.st.SubmitOperation(context.Background(), ref, "restart", params, 1, time.Now())
	must(t, err)
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if !strings.HasPrefix(op.LastError, "conflict: ") || op.Attempts != 1 || len(e.ag.methods(ref)) != 0 {
		t.Fatalf("op %+v, calls %v", op, e.ag.methods(ref))
	}
	if p := e.project(ref); p.State != "active" || p.Generation != 1 {
		t.Fatalf("project %+v", p)
	}
}

// ───────── delete and purge ─────────

func retainHour(t *testing.T) *env {
	c := testConfig()
	c.Retention = "1h"
	return newEnvWith(t, c)
}

func TestDelete_KeepsUIDAndSlice(t *testing.T) {
	e := retainHour(t)
	ref := e.active()
	before := e.project(ref)
	r := e.runner()
	e.start(r)
	del, purge := e.deleted(r, ref)
	wantSeq(t, e.steps(del), []string{"D1", "D2", "D3", "D4", "D5"})
	p := e.project(ref)
	if p.State != "deleted" || *p.UID != *before.UID || *p.SubnetIndex != *before.SubnetIndex {
		t.Fatalf("project %+v", p)
	}
	pop := e.op(purge)
	if pop.Kind != "purge" || pop.State != "pending" || !pop.NotBefore.Equal(*p.PurgeAfter) ||
		p.PurgeAfter.Sub(*p.DeletedAt) != time.Hour {
		t.Fatalf("purge %+v, project %+v", pop, p)
	}
}

func TestDelete_RouteRemovedFirst(t *testing.T) {
	e := retainHour(t)
	ref := e.active()
	var stateAtRoute atomic.Value
	e.ag.setHook(func(ctx context.Context, cl call) {
		if cl.Method == "SetRoute" {
			p, _ := e.st.GetProject(ctx, ref)
			stateAtRoute.Store(p.State)
		}
	})
	r := e.runner()
	e.start(r)
	e.deleted(r, ref)
	wantSeq(t, e.ag.methods(ref), []string{"SetRoute", "StopPostgREST", "StopCluster", "RemoveNetwork"})
	if c := e.ag.callsOf(ref, "SetRoute"); c[0].State != "" || stateAtRoute.Load() != "deleting" {
		t.Fatalf("route %+v, state %v", c, stateAtRoute.Load())
	}
	e.ag.locked(func() {
		if e.ag.network[ref] || e.ag.cluster[ref] != 0 || e.ag.pgrest[ref] != 0 {
			t.Fatal("objects left")
		}
	})
}

func TestDelete_ResumeAfterD5_OnePurge(t *testing.T) {
	e := retainHour(t)
	ref := e.active()
	r := e.runner()
	e.start(r)
	del, purge := e.deleted(r, ref)
	// The runner dropped between MarkDeleted and recording D5.
	sql(t, "update operation set state = 'running', step = 'D4' where id = $1", del)
	e.waitState(del, "done")
	ops, err := e.st.ListOperations(context.Background(), ref)
	must(t, err)
	n := 0
	for _, o := range ops {
		if o.Kind == "purge" {
			n++
			if o.ID != purge {
				t.Fatalf("another purge %d", o.ID)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d purge operations", n)
	}
}

func TestPurge_NotBefore(t *testing.T) {
	e := retainHour(t)
	ref := e.active()
	r := e.runner()
	e.start(r)
	_, purge := e.deleted(r, ref)
	time.Sleep(50 * time.Millisecond)
	if op := e.op(purge); op.State != "pending" || op.Attempts != 0 {
		t.Fatalf("purge ran inside the retention window: %+v", op)
	}
	must(t, e.st.SetPurgeNow(context.Background(), ref))
	e.waitState(purge, "done")
	wantSeq(t, e.steps(purge), []string{"P1", "P2", "P3", "P4", "P5"})
	if p := e.project(ref); p.State != "purged" || p.SubnetIndex != nil || p.UID == nil {
		t.Fatalf("project %+v", p)
	}
}

func TestPurge_OrderKeysRenderDir(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	var keysAtRender, keysAtPurge atomic.Value
	e.ag.setHook(func(ctx context.Context, c call) {
		switch c.Method {
		case "RemoveRender":
			_, _, err := e.st.GetDEK(ctx, ref)
			keysAtRender.Store(fmt.Sprint(err))
		case "PurgeDir":
			_, _, err := e.st.GetDEK(ctx, ref)
			keysAtPurge.Store(fmt.Sprint(err))
		}
	})
	e.ag.setErr(failOn("PurgeDir"))
	r := e.runner()
	e.start(r)
	_, purge := e.deleted(r, ref)
	op := e.waitState(purge, "failed")
	if op.Step != "P3" || op.Attempts != 5 {
		t.Fatalf("purge %+v", op)
	}
	calls := e.ag.methods(ref)
	i := slices.Index(calls, "RemoveRender")
	if i < 0 || calls[i+1] != "PurgeDir" || keysAtRender.Load() != store.ErrDestroyed.Error() || keysAtPurge.Load() != store.ErrDestroyed.Error() {
		t.Fatalf("calls %v, keys at render %v, at purge %v", calls, keysAtRender.Load(), keysAtPurge.Load())
	}
	e.ag.locked(func() {
		if e.ag.render[ref] {
			t.Fatal("render directory kept although PurgeDir never finished")
		}
	})
}

func TestPurge_AbsentDirIsDone(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	r := e.runner()
	e.start(r)
	_, purge := e.deleted(r, ref)
	e.waitState(purge, "done")
	// P4 again on an absent tree (a resumed step): the agent's no-op, done.
	sql(t, "update operation set state = 'running', step = 'P3' where id = $1", purge)
	e.waitState(purge, "done")
	if n := len(e.ag.callsOf(ref, "PurgeDir")); n != 2 || e.project(ref).State != "purged" {
		t.Fatalf("%d PurgeDir calls", n)
	}
	e.ag.locked(func() {
		if e.ag.effects["purgedir "+ref] != 1 {
			t.Fatalf("effects %v", e.ag.effects)
		}
	})
}

func TestPurge_P1StopsLeftoverContainers(t *testing.T) {
	e := retainHour(t)
	ref := e.active()
	r := e.runner()
	e.start(r)
	_, purge := e.deleted(r, ref)
	e.ag.reset()
	var keysAtStop atomic.Value
	keysAtStop.Store("")
	e.ag.setHook(func(ctx context.Context, c call) {
		if strings.HasPrefix(c.Method, "Stop") {
			if _, _, err := e.st.GetDEK(ctx, ref); err != nil {
				keysAtStop.Store(err.Error())
			}
		}
	})
	// A container left running since the delete.
	e.ag.locked(func() { e.ag.cluster[ref] = 1 })
	must(t, e.st.SetPurgeNow(context.Background(), ref))
	e.waitState(purge, "done")
	wantSeq(t, e.ag.methods(ref)[:2], []string{"StopPostgREST", "StopCluster"})
	if keysAtStop.Load() != "" {
		t.Fatalf("keys destroyed before P1: %v", keysAtStop.Load())
	}
	e.ag.locked(func() {
		if e.ag.cluster[ref] != 0 {
			t.Fatal("leftover cluster not stopped")
		}
	})
}

// ───────── specs, secrets, text ─────────

func TestSpecFor_DesiredStateWithSecrets(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.start(e.runner())
	e.waitState(id, "done")
	r := e.runner()
	s, err := r.SpecFor(context.Background(), ref)
	must(t, err)
	p := e.project(ref)
	if s.Ref != ref || s.Generation != p.Generation || s.Epoch != 1 || s.UID != *p.UID || s.GID != *p.UID ||
		s.SubnetIndex != *p.SubnetIndex || s.DiskQuotaMB != 8192 || s.MemMB != 512 || s.Pids != 512 ||
		!slices.Equal(s.UserRoles, []string{"authenticated"}) || len(s.Keys) != 3 {
		t.Fatalf("spec %#v", s)
	}
	if s.Secrets.PostgresPassword != e.secret(ref, "pg.postgres.password") ||
		s.Secrets.SupabaseAdminPassword != e.secret(ref, "pg.supabase_admin.password") ||
		s.Secrets.AuthenticatorPassword != e.secret(ref, "pg.authenticator.password") ||
		s.Secrets.PgsodiumRootKey != e.secret(ref, "pgsodium.root_key") || len(s.Secrets.PgsodiumRootKey) != 64 {
		t.Fatal("secrets differ from the store")
	}
	n, w, err := e.st.GetDEK(context.Background(), ref)
	must(t, err)
	dek, err := secrets.UnwrapDEK(e.kek, ref, n, w)
	must(t, err)
	for _, role := range []string{"supabase_admin", "postgres", "authenticator"} {
		want, err := pgsock.ScramSalt(dek, ref, role)
		must(t, err)
		if !bytes.Equal(s.Secrets.ScramSalts[role], want) {
			t.Fatalf("salt of %s", role)
		}
	}
	if len(s.Secrets.ScramSalts) != 3 {
		t.Fatalf("salts %v", s.Secrets.ScramSalts)
	}
	// Every spec the create handed the agent carried the same secrets.
	e.ag.locked(func() {
		if len(e.ag.specs) == 0 {
			t.Fatal("no specs recorded")
		}
		for _, got := range e.ag.specs {
			if got.Secrets.PostgresPassword != s.Secrets.PostgresPassword || len(got.Secrets.ScramSalts) != 3 ||
				!bytes.Equal(got.Secrets.ScramSalts["authenticator"], s.Secrets.ScramSalts["authenticator"]) {
				t.Fatalf("spec without secrets or salts: %#v", got)
			}
		}
	})
	if _, err := r.SpecFor(context.Background(), "saga9999999999999999"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown ref: %v", err)
	}
}

func TestLastError_SanitisedAndBounded(t *testing.T) {
	e := newEnv(t)
	_, id := e.create()
	e.ag.setErr(func(c call) error {
		if c.Method == "EnsureDir" {
			return errors.New("\x1b]0;title\x07bad\x00\u202e" + strings.Repeat("x", 4096))
		}
		return nil
	})
	r := e.runner()
	r.backoff = []time.Duration{time.Hour}
	e.start(r)
	op := e.wait(id, "backed off", func(op store.Operation) bool { return op.Attempts == 1 && op.State == "pending" })
	if len(op.LastError) > 1024 || !strings.HasPrefix(op.LastError, "internal: ]0;titlebad") ||
		strings.ContainsFunc(op.LastError, func(r rune) bool { return r < 0x20 || r == 0x7f || r == '\u202e' }) {
		t.Fatalf("last_error %q (%d bytes)", op.LastError, len(op.LastError))
	}
	if l := e.logs.String(); strings.Contains(l, `\u001b`) || strings.Contains(l, `\u202e`) || !strings.Contains(l, "titlebad") {
		t.Fatalf("log not sanitised or missing: %s", l)
	}
}

// No secret appears in operation parameters, last_error or a log line.
func TestSecrets_NeverInParamsErrorsOrLogs(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	r := e.runner()
	failVerifyAt(e, 2, 3)
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.start(r)
	e.waitState(id, "failed")
	var plain []string
	for _, n := range []string{"pg.supabase_admin.password", "pg.postgres.password", "pg.authenticator.password",
		"jwt.secret", "pgsodium.root_key", "token.anon", "token.service_role"} {
		plain = append(plain, e.secret(ref, n))
	}
	ops, err := e.st.ListOperations(context.Background(), ref)
	must(t, err)
	text := e.logs.String()
	for _, op := range ops {
		text += string(op.Params) + op.LastError
	}
	if !strings.Contains(text, "step done") {
		t.Fatal("no log captured")
	}
	for i, s := range plain {
		if len(s) < 16 {
			t.Fatalf("secret %d too short to test", i)
		}
		if strings.Contains(text, s) || strings.Contains(text, hex.EncodeToString([]byte(s))) {
			t.Fatalf("secret %d found in operation text or logs", i)
		}
	}
}

func TestResumeAll_ChangesNoState(t *testing.T) {
	e := newEnv(t)
	_, id := e.create()
	e.failpoint("create:4")
	<-e.run(e.runner())
	before := e.op(id)
	r := e.runner()
	must(t, r.ResumeAll(context.Background()))
	after := e.op(id)
	if after.State != "running" || after.Step != before.Step || after.Attempts != before.Attempts || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("ResumeAll changed %+v → %+v", before, after)
	}
	if n := len(e.logs.records("resuming")); n != 1 {
		t.Fatalf("%d resuming records: %s", n, e.logs.String())
	}
	e.start(r)
	e.waitState(id, "done")
}

// ───────── failpoint ─────────

func TestFailpoint_OneShot(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	must(t, os.MkdirAll(filepath.Dir(p.Failpoint()), 0o700))
	must(t, os.MkdirAll(filepath.Dir(p.NodeJSON()), 0o700))
	marker := filepath.Join(filepath.Dir(p.NodeJSON()), "dev-mode")
	var codes []int
	var presentAtExit []bool
	old := exit
	exit = func(code int) {
		_, err := os.Lstat(p.Failpoint())
		presentAtExit = append(presentAtExit, err == nil)
		codes = append(codes, code)
	}
	t.Cleanup(func() { exit = old })

	hitFailpoint(p, "create:4a") // absent file: inert
	must(t, os.WriteFile(p.Failpoint(), []byte("create:4a\n"), 0o600))
	// A production node (no development marker): inert, the file stays.
	hitFailpoint(p, "create:4a")
	if len(codes) != 0 {
		t.Fatal("failpoint fired on a node without the development marker")
	}
	if _, err := os.Stat(p.Failpoint()); err != nil {
		t.Fatal("production node consumed the failpoint file")
	}
	// A marker that is a link does not make a development node.
	must(t, os.Symlink(p.Failpoint(), marker))
	hitFailpoint(p, "create:4a")
	if len(codes) != 0 {
		t.Fatal("failpoint fired with a linked marker")
	}
	must(t, os.Remove(marker))
	must(t, os.WriteFile(marker, nil, 0o600))
	hitFailpoint(p, "create:4") // another name: inert
	hitFailpoint(p, "restart:4a")
	if len(codes) != 0 {
		t.Fatal("failpoint fired for another name")
	}
	hitFailpoint(p, "create:4a")
	if !slices.Equal(codes, []int{137}) || !slices.Equal(presentAtExit, []bool{false}) {
		t.Fatalf("exit codes %v, file present at exit %v", codes, presentAtExit)
	}
	hitFailpoint(p, "create:4a") // one shot
	if len(codes) != 1 {
		t.Fatal("failpoint fired twice")
	}
	// A failpoint file that is a link is not followed.
	other := filepath.Join(t.TempDir(), "name")
	must(t, os.WriteFile(other, []byte("create:4a"), 0o600))
	must(t, os.Symlink(other, p.Failpoint()))
	hitFailpoint(p, "create:4a")
	if len(codes) != 1 {
		t.Fatal("failpoint followed a link")
	}
}

// ───────── fix-pass additions ─────────

// The worker waits until the gateway reports at least the route generation
// it wrote — a later one counts (generations may be timestamps), an older
// one does not — before probing (step 11) and before stopping (D1).
func TestGateway_WaitsForAtLeastTheWrittenGeneration(t *testing.T) {
	e := retainHour(t)
	e.ag.locked(func() { e.ag.gwLag, e.ag.gwAhead = 3, 1000 })
	ref, id := e.create()
	r := e.runner()
	e.start(r)
	e.waitState(id, "done")
	polls := func(before string) int {
		n := 0
		for _, m := range e.ag.methods("") {
			switch m {
			case "GatewayGeneration":
				n++
			case before:
				return n
			}
		}
		return -1
	}
	if n := polls("ProbeREST"); n != 4 {
		t.Fatalf("step 11 probed after %d gateway polls, want 4 (3 stale, then one past the written generation)", n)
	}
	e.ag.reset()
	e.ag.locked(func() { e.ag.gwLag = 3 })
	e.deleted(r, ref)
	if n := polls("StopPostgREST"); n != 4 {
		t.Fatalf("D1 went on after %d gateway polls, want 4", n)
	}
}

// Compensation entries run under the step and the attempt deadline too.
func TestAbort_CompensationDeadlines(t *testing.T) {
	for _, tc := range []struct {
		name   string
		slow   func(ctx context.Context, c call)
		set    func(r *Runner)
		reachC string
	}{
		{"step", func(ctx context.Context, c call) {
			if c.Method == "PurgeDir" {
				<-ctx.Done()
			}
		}, func(r *Runner) { r.stepDeadline = 100 * time.Millisecond }, "PurgeDir"},
		{"attempt", func(ctx context.Context, c call) {
			select {
			case <-time.After(250 * time.Millisecond):
			case <-ctx.Done():
			}
		}, func(r *Runner) { r.stepDeadline, r.attemptDeadline = 300*time.Millisecond, 900*time.Millisecond }, "RemoveRender"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			ref, id := e.create()
			e.failpoint("create:4")
			<-e.run(e.runner())
			r := e.runner()
			tc.set(r)
			r.backoff = []time.Duration{time.Hour}
			_, err := r.Abort(context.Background(), ref)
			must(t, err)
			e.ag.reset()
			e.ag.setHook(tc.slow)
			e.start(r)
			op := e.wait(id, "backed off", func(op store.Operation) bool { return op.Attempts == 1 })
			if op.State != "aborting" || !strings.HasPrefix(op.LastError, "timeout: ") {
				t.Fatalf("op %+v", op)
			}
			calls := e.ag.methods(ref)
			if calls[len(calls)-1] != tc.reachC {
				t.Fatalf("cut at %v, want at %s", calls, tc.reachC)
			}
		})
	}
}

// A containment refusal at R4 fails the restart; it is not a health
// failure and does not roll forward.
func TestRestart_R4ContainmentFailsNotRollsForward(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	e.ag.setErr(func(c call) error {
		if c.Method == "VerifyCluster" {
			return fmt.Errorf("gate: %w", agent.ErrContainment)
		}
		return nil
	})
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.start(r)
	op := e.waitState(id, "failed")
	if !strings.HasPrefix(op.LastError, "containment_failed: ") || strings.Contains(string(op.Params), "rollback_gen") {
		t.Fatalf("op %+v", op)
	}
	for _, c := range e.ag.callsOf(ref, "Prevalidate") {
		if c.Gen != 2 {
			t.Fatalf("rolled forward to %d", c.Gen)
		}
	}
}

// The failpoint works at compensation entries: the worker stops before the
// entry; the next run starts the list again at its first entry.
func TestFailpoint_AtCompensationEntries(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:4")
	<-e.run(e.runner())
	r := e.runner()
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	e.ag.reset()
	e.failpoint("create:C3")
	<-e.run(r)
	wantSeq(t, e.ag.methods(ref), []string{"SetRoute", "StopPostgREST"})
	if _, err := os.Stat(e.p.Failpoint()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failpoint not consumed")
	}
	if op := e.op(id); op.State != "aborting" {
		t.Fatalf("op %+v", op)
	}
	e.start(e.runner())
	e.waitState(id, "aborted")
	wantSeq(t, e.ag.methods(ref)[2:], compensationCalls)
}

// The bootstrap assertion and an epoch divergence end the operation at once.
func TestCreate_AssertionAndEpochDivergenceNotRetried(t *testing.T) {
	for _, want := range []struct {
		err  error
		code string
	}{{bootstrap.ErrAssertion, "assertion"}, {agent.ErrEpochDivergence, "epoch_divergence"}} {
		t.Run(want.code, func(t *testing.T) {
			e := newEnv(t)
			_, id := e.create()
			e.ag.setErr(func(c call) error {
				if c.Method == "EnsureCluster" {
					return fmt.Errorf("first boot: %w", want.err)
				}
				return nil
			})
			e.start(e.runner())
			op := e.waitState(id, "failed")
			if op.Attempts != 1 || !strings.HasPrefix(op.LastError, want.code+": ") {
				t.Fatalf("op %+v", op)
			}
		})
	}
}

// A probe that fails sets the route back to draining, at step 11 and at R5.
func TestProbeFailure_DrainsRoute(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.ag.setErr(failOn("ProbeREST"))
	r := e.runner()
	r.backoff = []time.Duration{time.Hour}
	stop := e.start(r)
	e.wait(id, "backed off", func(op store.Operation) bool { return op.Attempts == 1 && op.State == "pending" })
	stop() // one worker per database
	e.ag.locked(func() {
		if e.ag.route[ref].State != "draining" {
			t.Fatalf("route after a failed probe at step 11: %+v", e.ag.route[ref])
		}
	})

	e2 := newEnv(t)
	ref2 := e2.active()
	e2.ag.setErr(failOn("ProbeREST"))
	r2 := e2.runner()
	r2.backoff = []time.Duration{time.Hour}
	rid := e2.restart(r2, ref2, withGUC("max_connections", "200"))
	e2.start(r2)
	e2.wait(rid, "backed off", func(op store.Operation) bool { return op.Attempts == 1 && op.State == "pending" })
	e2.ag.locked(func() {
		if e2.ag.route[ref2].State != "draining" {
			t.Fatalf("route after a failed probe at R5: %+v", e2.ag.route[ref2])
		}
	})
}

// Abort and step 12 racing, from both sides: an abort that lands before
// step 12's write wins (the write is refused, the list runs, the project
// was never active); once step 12 has committed, the abort is refused.
func TestAbort_RacesStep12(t *testing.T) {
	t.Run("abort first", func(t *testing.T) {
		e := newEnv(t)
		ref, id := e.create()
		r := e.runner()
		old := beforeFinishCreate
		t.Cleanup(func() { beforeFinishCreate = old })
		var once sync.Once
		beforeFinishCreate = func() {
			once.Do(func() {
				if _, err := r.Abort(context.Background(), ref); err != nil {
					t.Errorf("abort: %v", err)
				}
			})
		}
		e.start(r)
		op := e.waitState(id, "aborted")
		if p := e.project(ref); p.State != "aborted" || p.AppliedGen != 0 || op.Step != "11" {
			t.Fatalf("project %+v, op %+v", p, op)
		}
		calls := e.ag.methods(ref)
		wantSeq(t, calls[len(calls)-len(compensationCalls):], compensationCalls)
	})
	t.Run("step 12 first", func(t *testing.T) {
		e := newEnv(t)
		ref := e.active()
		if _, err := e.runner().Abort(context.Background(), ref); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("abort of an active project: %v", err)
		}
		if p := e.project(ref); p.State != "active" {
			t.Fatalf("project %+v", p)
		}
	})
}

// A retried parked abort compensates again from its first entry, and ends
// aborted once the failing entry recovers; it never runs a forward step.
func TestAbort_ParkedRetryResumesCompensation(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:12")
	<-e.run(e.runner())
	e.ag.setErr(failOn("PurgeDir"))
	r := e.runner()
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	e.start(r)
	e.waitState(id, "failed")
	e.ag.reset()
	e.ag.setErr(nil)
	must(t, e.st.RetryOperation(context.Background(), id))
	op := e.waitState(id, "aborted")
	wantSeq(t, e.ag.methods(ref), compensationCalls)
	if p := e.project(ref); p.State != "aborted" || !compensating(op.Params) {
		t.Fatalf("project %+v, op %+v", p, op)
	}
}

// The worker's own bump, made by a resumed R2 whose completion was not
// recorded, is recognised: the restart proceeds.
func TestRestart_ResumeAfterOwnBumpProceeds(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.failpoint("restart:R3")
	<-e.run(r)
	sql(t, "update operation set step = 'R0' where id = $1", id) // R1 and R2 not recorded
	e.start(e.runner())
	if op := e.waitState(id, "done"); op.LastError != "" {
		t.Fatalf("op %+v", op)
	}
	if p := e.project(ref); p.Generation != 2 || p.State != "active" || p.Config.GUC["max_connections"] != "200" {
		t.Fatalf("project %+v", p)
	}
}

// The agent methods that exist today satisfy the interface's signatures.
// When the cluster and task methods land this becomes
// var _ Agent = (*agent.Agent)(nil).
var _ interface {
	EnsureDir(context.Context, agent.Spec) error
	SetQuota(context.Context, agent.Spec) error
	EnsureNetwork(context.Context, agent.Spec) error
	RemoveNetwork(context.Context, string) error
	EnsurePostgREST(context.Context, agent.Spec) error
	StopPostgREST(context.Context, string) error
	RouteFor(agent.Spec, string) routes.Project
	SetRoute(context.Context, string, *routes.Project) (int64, error)
	GatewayGeneration(context.Context) (int64, error)
	ProbeREST(context.Context, string, string) error
	RemoveRender(context.Context, string) error
	ContainmentFailed() bool
} = (*agent.Agent)(nil)

// FirstBoot — the permission to initialise (and so empty) a data directory
// — is set in the specs of create steps 4a and 4 alone, while the project is
// provisioning; never in any other call's spec (restart, delete, purge,
// compensation), nor by SpecFor.
func TestFirstBoot_OnlyAtCreateSteps4aAnd4(t *testing.T) {
	e := retainHour(t)
	ref, id := e.create()
	r := e.runner()
	stop := e.start(r)
	e.waitState(id, "done")
	rid := e.restart(r, ref, withGUC("max_connections", "200"))
	e.waitState(rid, "done")
	_, purge := e.deleted(r, ref)
	must(t, e.st.SetPurgeNow(context.Background(), ref))
	e.waitState(purge, "done")
	stop()
	// A create aborted after its first boot: compensation, and SpecFor of a
	// project still provisioning.
	ref2, id2 := e.create()
	e.failpoint("create:6")
	<-e.run(e.runner())
	s, err := r.SpecFor(context.Background(), ref2)
	must(t, err)
	if s.FirstBoot {
		t.Fatal("SpecFor set FirstBoot")
	}
	_, err = r.Abort(context.Background(), ref2)
	must(t, err)
	e.start(e.runner())
	e.waitState(id2, "aborted")
	var withFirstBoot []string
	specCalls := 0
	e.ag.locked(func() {
		for _, c := range e.ag.calls {
			if c.FirstBoot {
				withFirstBoot = append(withFirstBoot, c.Method+" "+c.Ref)
			}
		}
		specCalls = len(e.ag.specs)
	})
	want := []string{"EnsureCluster " + ref, "EnsureCluster " + ref, "EnsureCluster " + ref2, "EnsureCluster " + ref2}
	wantSeq(t, withFirstBoot, want)
	if specCalls < 10 { // restart, delete, purge and compensation calls were looked at
		t.Fatalf("only %d calls with a spec", specCalls)
	}
}

// A stale restart retried after another restart's bump is refused when its
// attempt starts, before it runs anything — not by the store's guard at R2
// after a pre-validation.
func TestRestart_StaleRetryRefusedBeforeAnyStep(t *testing.T) {
	for _, otherDone := range []bool{true, false} {
		t.Run(fmt.Sprint("other done=", otherDone), func(t *testing.T) {
			e := newEnv(t)
			ref := e.active()
			e.ag.setErr(func(c call) error {
				switch {
				case c.Method == "Prevalidate" && c.GUC["max_connections"] == "300":
					return errBoom
				case c.Method == "PromoteCandidate" && !otherDone:
					return errBoom
				}
				return nil
			})
			r := e.runner()
			e.start(r)
			a := e.restart(r, ref, withGUC("max_connections", "300"))
			e.waitState(a, "failed")
			b := e.restart(r, ref, withGUC("max_connections", "200"))
			if otherDone {
				e.waitState(b, "done")
			} else {
				e.waitState(b, "failed")
			}
			e.ag.reset()
			e.ag.setErr(nil)
			must(t, e.st.RetryOperation(context.Background(), a))
			op := e.waitState(a, "failed")
			if !strings.HasPrefix(op.LastError, "conflict: ") || op.Attempts != 1 || len(e.ag.methods(ref)) != 0 {
				t.Fatalf("op %+v, calls %v", op, e.ag.methods(ref))
			}
		})
	}
}

// A compensation run whose ref lock went with its connection stops before
// its next entry: keys are not destroyed beside another lock holder.
func TestAbort_LockLostMidCompensation(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:4")
	<-e.run(e.runner())
	inEntry := make(chan struct{})
	release := make(chan struct{})
	var freed sync.Once
	free := func() { freed.Do(func() { close(release) }) }
	defer free()
	var first sync.Once
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "StopCluster" {
			first.Do(func() { close(inEntry); <-release })
		}
	})
	r := e.runner()
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	e.ag.reset()
	e.start(r)
	<-inEntry
	sql(t, "select pg_terminate_backend(pid) from pg_locks where locktype = 'advisory' and pid <> pg_backend_pid()")
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for {
		u, ok, err := e.st.TryLockRef(ctx, ref)
		must(t, err)
		if ok {
			defer u()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lock still held after its connection was terminated")
		}
		time.Sleep(10 * time.Millisecond)
	}
	free()
	time.Sleep(300 * time.Millisecond)
	wantSeq(t, e.ag.methods(ref), []string{"SetRoute", "StopPostgREST", "StopCluster"})
	if _, _, err := e.st.GetDEK(ctx, ref); err != nil {
		t.Fatalf("keys destroyed without the lock: %v", err)
	}
	if op := e.op(id); op.State != "aborting" || op.Attempts != 0 {
		t.Fatalf("op %+v", op)
	}
}

// ───────── second fix-pass additions ─────────

// A restart resumed past its bump proceeds when the project still carries
// that bump (first pass and roll-forward), and also at R5 when R5's state
// write already made it active; a restart superseded by another one is
// refused at R3, R4 and R5 with no agent call.
func TestRestart_ResumePastBump(t *testing.T) {
	for _, at := range []string{"R3", "R4", "R5"} {
		t.Run("legit "+at, func(t *testing.T) {
			e := newEnv(t)
			ref := e.active()
			r := e.runner()
			id := e.restart(r, ref, withGUC("max_connections", "200"))
			e.failpoint("restart:" + at)
			<-e.run(r)
			e.start(e.runner())
			if op := e.waitState(id, "done"); op.LastError != "" {
				t.Fatalf("op %+v", op)
			}
			if p := e.project(ref); p.Generation != 2 || p.State != "active" {
				t.Fatalf("project %+v", p)
			}
		})
		t.Run("legit roll-forward "+at, func(t *testing.T) {
			e := newEnv(t)
			ref := e.active()
			fp := "restart:" + at
			e.ag.setErr(func(c call) error {
				if c.Method == "VerifyCluster" && c.Gen == 2 {
					os.WriteFile(e.p.Failpoint(), []byte(fp), 0o600) // the next such boundary is the rollback's
					return errBoom
				}
				return nil
			})
			r := e.runner()
			id := e.restart(r, ref, withGUC("max_connections", "200"))
			<-e.run(r)
			e.ag.setErr(nil)
			e.start(e.runner())
			e.waitState(id, "done")
			if p := e.project(ref); p.Generation != 3 || p.State != "active" || len(p.Config.GUC) != 0 {
				t.Fatalf("project %+v", p)
			}
		})
		t.Run("superseded "+at, func(t *testing.T) {
			e := newEnv(t)
			ref := e.active()
			r := e.runner()
			id := e.restart(r, ref, withGUC("max_connections", "200"))
			e.failpoint("restart:" + at)
			<-e.run(r)
			sql(t, "update project set state = 'active', generation = 3 where ref = $1", ref) // a later restart finished
			e.ag.reset()
			e.start(e.runner())
			op := e.waitState(id, "failed")
			if !strings.HasPrefix(op.LastError, "conflict: ") || len(e.ag.methods(ref)) != 0 {
				t.Fatalf("op %+v, calls %v", op, e.ag.methods(ref))
			}
		})
	}
	t.Run("configuration changed under it", func(t *testing.T) {
		e := newEnv(t)
		ref := e.active()
		r := e.runner()
		id := e.restart(r, ref, withGUC("max_connections", "200"))
		e.failpoint("restart:R3")
		<-e.run(r)
		sql(t, `update project set config = '{"disk_quota_mb":8192,"mem_mb":512,"guc":{"max_connections":"300"}}' where ref = $1`, ref)
		e.ag.reset()
		e.start(e.runner())
		if op := e.waitState(id, "failed"); !strings.HasPrefix(op.LastError, "conflict: ") || len(e.ag.methods(ref)) != 0 {
			t.Fatalf("op %+v", op)
		}
	})
	t.Run("active at target before R5", func(t *testing.T) {
		e := newEnv(t)
		ref := e.active()
		r := e.runner()
		id := e.restart(r, ref, withGUC("max_connections", "200"))
		e.failpoint("restart:R5")
		<-e.run(r)
		sql(t, "update project set state = 'active' where ref = $1", ref) // R5's state write, not recorded
		e.start(e.runner())
		e.waitState(id, "done")
	})
	t.Run("active at target before R4 is refused", func(t *testing.T) {
		e := newEnv(t)
		ref := e.active()
		r := e.runner()
		id := e.restart(r, ref, withGUC("max_connections", "200"))
		e.failpoint("restart:R4")
		<-e.run(r)
		sql(t, "update project set state = 'active' where ref = $1", ref)
		e.ag.reset()
		e.start(e.runner())
		if op := e.waitState(id, "failed"); !strings.HasPrefix(op.LastError, "conflict: ") || len(e.ag.methods(ref)) != 0 {
			t.Fatalf("op %+v", op)
		}
	})
}

// resumeCompensation: a transient RequestAbort error backs off and the
// create is taken again later; a refusal because the project already left
// provisioning ends it failed with an accurate reason. Neither loops.
func TestAbort_ResumeCompensationErrors(t *testing.T) {
	marked := func(e *env) (string, int64) {
		ref, id := e.create()
		e.failpoint("create:4")
		<-e.run(e.runner())
		sql(t, `update operation set state = 'pending', params = params || '{"compensating": true}' where id = $1`, id)
		return ref, id
	}
	t.Run("transient", func(t *testing.T) {
		e := newEnv(t)
		_, id := marked(e)
		old := requestAbort
		t.Cleanup(func() { requestAbort = old })
		var calls atomic.Int32
		requestAbort = func(st *store.Store, ctx context.Context, ref string) (int64, error) {
			if calls.Add(1) == 1 {
				return 0, errors.New("connection reset by peer")
			}
			return old(st, ctx, ref)
		}
		r := e.runner()
		r.backoff = []time.Duration{time.Hour}
		e.start(r)
		op := e.wait(id, "backed off", func(op store.Operation) bool { return op.Attempts == 2 && op.State == "pending" })
		time.Sleep(100 * time.Millisecond)
		if n := calls.Load(); n != 1 || op.NotBefore.Sub(op.UpdatedAt) < 59*time.Minute || !strings.HasPrefix(op.LastError, "internal: ") {
			t.Fatalf("op %+v after %d calls", op, n)
		}
		sql(t, "update operation set not_before = now() where id = $1", id)
		e.waitState(id, "aborted")
	})
	t.Run("transient twice", func(t *testing.T) {
		e := newEnv(t)
		_, id := marked(e)
		old := requestAbort
		t.Cleanup(func() { requestAbort = old })
		var calls atomic.Int32
		requestAbort = func(st *store.Store, ctx context.Context, ref string) (int64, error) {
			if calls.Add(1) <= 2 {
				return 0, errors.New("connection reset by peer")
			}
			return old(st, ctx, ref)
		}
		r := e.runner()
		r.backoff = []time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour}
		e.start(r)
		first := e.wait(id, "backed off", func(op store.Operation) bool { return op.Attempts == 2 && op.State == "pending" })
		sql(t, "update operation set not_before = now() where id = $1", id)
		second := e.wait(id, "backed off again", func(op store.Operation) bool { return op.Attempts == 3 && op.State == "pending" })
		if d1, d2 := first.NotBefore.Sub(first.UpdatedAt), second.NotBefore.Sub(second.UpdatedAt); (d1-2*time.Hour).Abs() > time.Minute || (d2-3*time.Hour).Abs() > time.Minute {
			t.Fatalf("back-offs %v then %v, want the second and third values (2h, 3h): one per started attempt", d1, d2)
		}
		sql(t, "update operation set not_before = now() where id = $1", id)
		e.waitState(id, "aborted")
	})
	t.Run("project already released", func(t *testing.T) {
		e := newEnv(t)
		ref, id := marked(e)
		sql(t, "update project set state = 'aborted', subnet_index = null where ref = $1", ref)
		e.start(e.runner())
		op := e.waitState(id, "failed")
		time.Sleep(100 * time.Millisecond)
		if op = e.op(id); op.State != "failed" || op.Attempts != 2 ||
			op.LastError != "conflict: its compensation has run and the project is aborted; nothing is left to undo" {
			t.Fatalf("op %+v", op)
		}
	})
}

// holdProjectRow keeps the project row locked from another session until
// the returned function is called.
func holdProjectRow(t *testing.T, ref string) func() {
	t.Helper()
	cfg, err := pgx.ParseConfig("")
	must(t, err)
	cfg.Host, cfg.Port, cfg.Database, cfg.User, cfg.Password = sockDir, 5432, "supapaced", "supapaced", ""
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	ctx := context.Background()
	c, err := pgx.ConnectConfig(ctx, cfg)
	must(t, err)
	tx, err := c.Begin(ctx)
	must(t, err)
	if _, err := tx.Exec(ctx, "select 1 from project where ref = $1 for update", ref); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(func() { tx.Rollback(ctx); c.Close(ctx) }) }
	t.Cleanup(release)
	return release
}

// Step 12's write runs under the step's deadline: a control-plane write that
// hangs fails the attempt instead of holding the worker and the ref lock.
func TestCreate_FinishBounded(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:12")
	<-e.run(e.runner())
	release := holdProjectRow(t, ref)
	defer release() // idempotent; on failure the worker must not wait on the row past the test
	r := e.runner()
	r.stepDeadline = 300 * time.Millisecond
	r.backoff = []time.Duration{time.Hour}
	e.start(r)
	op := e.wait(id, "backed off", func(op store.Operation) bool { return op.State == "pending" && op.Attempts == 2 })
	if !strings.HasPrefix(op.LastError, "timeout: ") || op.Step != "11" || e.project(ref).State != "provisioning" {
		t.Fatalf("op %+v", op)
	}
	release()
	sql(t, "update operation set not_before = now() where id = $1", id)
	e.waitState(id, "done")
}

// A failing quota change at R3 is a failed step: nothing after it runs.
func TestRestart_R3QuotaFailureNotIgnored(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	e.ag.setErr(failOn("SetQuota"))
	r := e.runner()
	next := defaultConfig
	next.DiskQuotaMB = 16384
	id := e.restart(r, ref, next)
	e.start(r)
	op := e.waitState(id, "failed")
	if op.Step != "R2" || op.LastError != "internal: boom" || len(e.ag.callsOf(ref, "PromoteCandidate")) != 0 {
		t.Fatalf("op %+v, calls %v", op, e.ag.methods(ref))
	}
}

// Two configurations that differ only in their disk quota are different:
// a restart does not take another restart's bump for its own because of it.
func TestRestart_OwnBumpComparesQuota(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	e.ag.setErr(func(c call) error {
		switch {
		case c.Method == "Prevalidate" && c.Quota == 4096:
			return errBoom
		case c.Method == "PromoteCandidate":
			return errBoom
		}
		return nil
	})
	r := e.runner()
	e.start(r)
	a := withGUC("max_connections", "200")
	a.DiskQuotaMB = 4096
	aid := e.restart(r, ref, a)
	e.waitState(aid, "failed")
	b := withGUC("max_connections", "200")
	b.DiskQuotaMB = 16384
	e.waitState(e.restart(r, ref, b), "failed")
	e.ag.reset()
	e.ag.setErr(nil)
	must(t, e.st.RetryOperation(context.Background(), aid))
	op := e.waitState(aid, "failed")
	if !strings.HasPrefix(op.LastError, "conflict: ") || len(e.ag.methods(ref)) != 0 {
		t.Fatalf("op %+v, calls %v", op, e.ag.methods(ref))
	}
}

// The route is drained after a failed probe even when the step's deadline
// has already passed, both when the probe itself ran into the deadline and
// when the deadline came during the wait between probes.
func TestProbeFailure_DrainsAfterTheStepDeadline(t *testing.T) {
	for _, mode := range []string{"probe", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			ref, id := e.create()
			e.failpoint("create:11")
			<-e.run(e.runner())
			e.ag.setHook(func(ctx context.Context, c call) {
				if c.Method == "ProbeREST" && mode == "probe" {
					<-ctx.Done()
				}
			})
			e.ag.setErr(failOn("ProbeREST"))
			r := e.runner()
			r.stepDeadline = 300 * time.Millisecond
			r.probeWindow = time.Hour
			r.probeEvery = time.Hour
			r.backoff = []time.Duration{time.Hour}
			e.start(r)
			e.wait(id, "backed off", func(op store.Operation) bool { return op.State == "pending" && op.Attempts == 2 })
			e.ag.locked(func() {
				if e.ag.route[ref].State != "draining" {
					t.Fatalf("route %+v", e.ag.route[ref])
				}
			})
		})
	}
}

// A ref lock lost just before step 12's write records nothing: the project
// stays provisioning; once the lock is free again the worker finishes it.
func TestCreate_LockLostBeforeFinish(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	old := beforeFinishCreate
	t.Cleanup(func() { beforeFinishCreate = old })
	var u func()
	var once sync.Once
	locked := make(chan struct{})
	beforeFinishCreate = func() {
		once.Do(func() {
			defer close(locked)
			sql(t, "select pg_terminate_backend(pid) from pg_locks where locktype = 'advisory' and pid <> pg_backend_pid()")
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				var ok bool
				if u, ok, _ = e.st.TryLockRef(context.Background(), ref); ok {
					t.Cleanup(u) // idempotent; a failing test must not keep a pool connection
					return
				}
			}
			t.Error("lock not free after its connection was terminated")
		})
	}
	e.start(e.runner())
	<-locked
	time.Sleep(200 * time.Millisecond)
	if op := e.op(id); op.State != "running" || op.Step != "11" || e.project(ref).State != "provisioning" {
		t.Fatalf("op %+v, project %s", op, e.project(ref).State)
	}
	if u != nil {
		u()
	}
	e.waitState(id, "done")
}
