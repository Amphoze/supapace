package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/adminapi"
	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/routes"
	"github.com/Amphoze/supapace/internal/store"
)

// ───────── fakes ─────────

// calls is an ordered, shared call log.
type calls struct {
	mu  sync.Mutex
	log []string
}

func (c *calls) add(s string) {
	c.mu.Lock()
	c.log = append(c.log, s)
	c.mu.Unlock()
}

func (c *calls) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.log)
}

// index of the first entry with the prefix, -1 when none.
func (c *calls) index(prefix string) int {
	for i, s := range c.all() {
		if strings.HasPrefix(s, prefix) {
			return i
		}
	}
	return -1
}

func (c *calls) count(prefix string) int {
	n := 0
	for _, s := range c.all() {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

// fakeAgent records every call in c; per-call behaviour is set by the
// function fields (nil: success).
type fakeAgent struct {
	c      *calls
	failed atomic.Bool

	ensureCluster   func(context.Context, agent.Spec) error
	ensurePostgREST func(context.Context, agent.Spec) error
	checkCluster    func(context.Context, agent.Spec) ([]nodecfg.CheckResult, error)
	nodeCheck       func() []nodecfg.CheckResult
	nodeCheckWait   bool // NodeCheck waits for its context to end
	platformErr     error
	drainErr        error
	checkHost       func(agent.Spec) []nodecfg.CheckResult

	mu     sync.Mutex
	routes map[string]string // ref → state
	up     map[string]bool   // container name → running, as the ensures and the stop leave it
}

func newFakeAgent(c *calls) *fakeAgent {
	return &fakeAgent{c: c, routes: map[string]string{}, up: map[string]bool{}}
}

// setUp records name as running or not (a test kills a container with it).
func (a *fakeAgent) setUp(name string, running bool) {
	a.mu.Lock()
	a.up[name] = running
	a.mu.Unlock()
}

// containers is the daemon's listing seam over the model: label is a key
// (every container) or supapace.ref=<ref>.
func (a *fakeAgent) containers(_ context.Context, label string) ([]dockerx.Container, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ref, byRef := strings.CutPrefix(label, "supapace.ref=")
	var out []dockerx.Container
	for n, r := range a.up {
		if !byRef || n == "pg-"+ref || n == "postgrest-"+ref {
			out = append(out, dockerx.Container{Name: n, Running: r})
		}
	}
	return out, nil
}

func (a *fakeAgent) SetContainmentFailed(f bool) {
	a.c.add(fmt.Sprintf("SetContainmentFailed(%v)", f))
	a.failed.Store(f)
}
func (a *fakeAgent) ContainmentFailed() bool { return a.failed.Load() }
func (a *fakeAgent) EnsurePlatformNetworks(context.Context) error {
	a.c.add("EnsurePlatformNetworks")
	return a.platformErr
}
func (a *fakeAgent) EnsureImageFiles(context.Context) error {
	a.c.add("EnsureImageFiles")
	return nil
}
func (a *fakeAgent) EnsureControlPlaneDB(context.Context) error {
	a.c.add("EnsureControlPlaneDB")
	a.setUp("sp-cp-db", true)
	return nil
}
func (a *fakeAgent) EnsureGateway(context.Context) error {
	a.c.add("EnsureGateway")
	a.setUp("sp-gateway", true)
	return nil
}
func (a *fakeAgent) NodeCheck(ctx context.Context) []nodecfg.CheckResult {
	a.c.add("NodeCheck")
	if a.nodeCheckWait {
		<-ctx.Done()
	}
	if a.nodeCheck != nil {
		return a.nodeCheck()
	}
	return []nodecfg.CheckResult{{Name: "nft", OK: true}}
}
func (a *fakeAgent) DrainAllRoutes(context.Context) (int64, error) {
	a.c.add("DrainAllRoutes")
	a.mu.Lock()
	for r := range a.routes {
		a.routes[r] = "draining"
	}
	a.mu.Unlock()
	return 1, a.drainErr
}
func (a *fakeAgent) StopAllTenants(context.Context) error {
	a.c.add("StopAllTenants")
	a.mu.Lock()
	for n := range a.up {
		if strings.HasPrefix(n, "pg-") || strings.HasPrefix(n, "postgrest-") {
			a.up[n] = false
		}
	}
	a.mu.Unlock()
	return nil
}
func (a *fakeAgent) EnsureCluster(ctx context.Context, s agent.Spec) error {
	a.c.add(fmt.Sprintf("EnsureCluster:%s:%d:%v", s.Ref, s.Generation, s.HealthWait))
	if a.ensureCluster != nil {
		if err := a.ensureCluster(ctx, s); err != nil {
			return err
		}
	}
	a.setUp("pg-"+s.Ref, true)
	return nil
}
func (a *fakeAgent) EnsurePostgREST(ctx context.Context, s agent.Spec) error {
	a.c.add("EnsurePostgREST:" + s.Ref)
	if a.ensurePostgREST != nil {
		if err := a.ensurePostgREST(ctx, s); err != nil {
			return err
		}
	}
	a.setUp("postgrest-"+s.Ref, true)
	return nil
}
func (a *fakeAgent) CheckHost(_ context.Context, s agent.Spec) []nodecfg.CheckResult {
	a.c.add("CheckHost:" + s.Ref)
	if a.checkHost != nil {
		return a.checkHost(s)
	}
	return []nodecfg.CheckResult{{Name: "route", OK: true}}
}
func (a *fakeAgent) CheckCluster(ctx context.Context, s agent.Spec) ([]nodecfg.CheckResult, error) {
	a.c.add("CheckCluster:" + s.Ref)
	if a.checkCluster != nil {
		return a.checkCluster(ctx, s)
	}
	return nil, nil
}
func (a *fakeAgent) RouteFor(s agent.Spec, state string) routes.Project {
	return routes.Project{State: state, Rest: "http://10.212.0.16:3000"}
}

// SetRoute refuses an active route while the flag is set, as the agent does.
func (a *fakeAgent) SetRoute(_ context.Context, ref string, r *routes.Project) (int64, error) {
	a.c.add("SetRoute:" + ref + ":" + r.State)
	if r.State == "active" && a.failed.Load() {
		return 0, agent.ErrContainment
	}
	a.mu.Lock()
	a.routes[ref] = r.State
	a.mu.Unlock()
	return 2, nil
}

func (a *fakeAgent) route(ref string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.routes[ref]
}

// fakeStore keeps projects, operations and ref locks in memory.
type fakeStore struct {
	c        *calls
	mu       sync.Mutex
	projects map[string]store.Project
	ops      map[string][]store.Operation
	locked   map[string]bool
	lost     map[string]error // ref → error of its lock's held check
	lockErr  error            // returned by every TryLockRefChecked
}

func newFakeStore(c *calls) *fakeStore {
	return &fakeStore{c: c, projects: map[string]store.Project{}, ops: map[string][]store.Operation{}, locked: map[string]bool{}, lost: map[string]error{}}
}

func (s *fakeStore) add(ref, state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	uid := 700000 + len(s.projects)
	s.projects[ref] = store.Project{Ref: ref, State: state, Generation: 1, UID: &uid}
}

func (s *fakeStore) lock(ref string, held bool) {
	s.mu.Lock()
	s.locked[ref] = held
	s.mu.Unlock()
}

func (s *fakeStore) ListProjects(context.Context) ([]store.Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.Project
	for _, p := range s.projects {
		out = append(out, p)
	}
	return out, nil
}
func (s *fakeStore) GetProject(_ context.Context, ref string) (store.Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.projects[ref]
	if !ok {
		return p, store.ErrNotFound
	}
	return p, nil
}
func (s *fakeStore) ListOperations(_ context.Context, ref string) ([]store.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.ops[ref]), nil
}
func (s *fakeStore) TryLockRefChecked(_ context.Context, ref string) (func(), func(context.Context) error, bool, error) {
	s.c.add("TryLockRef:" + ref)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockErr != nil {
		return nil, nil, false, s.lockErr
	}
	if s.locked[ref] {
		return nil, nil, false, nil
	}
	s.locked[ref] = true
	held := func(context.Context) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.lost[ref]
	}
	return func() { s.lock(ref, false) }, held, true, nil
}

// fakeRunner builds specs from a refStore and records its calls.
type fakeRunner struct {
	c       *calls
	st      refStore
	running atomic.Bool
}

func (r *fakeRunner) ResumeAll(context.Context) error { r.c.add("ResumeAll"); return nil }
func (r *fakeRunner) Run(ctx context.Context) {
	r.c.add("Run")
	r.running.Store(true)
	<-ctx.Done()
}
func (r *fakeRunner) SpecFor(ctx context.Context, ref string) (agent.Spec, error) {
	p, err := r.st.GetProject(ctx, ref)
	if err != nil {
		return agent.Spec{}, err
	}
	return agent.Spec{Ref: ref, Generation: p.Generation, UID: *p.UID, GID: *p.UID}, nil
}
func (r *fakeRunner) Submit(_ context.Context, kind, ref string, params json.RawMessage) (int64, error) {
	r.c.add("Submit:" + kind + ":" + ref + ":" + string(params))
	return 7, nil
}
func (r *fakeRunner) Abort(_ context.Context, ref string) (int64, error) {
	r.c.add("Abort:" + ref)
	return 8, nil
}

// world is a daemon wired to fakes under a temporary root.
type world struct {
	t     *testing.T
	c     *calls
	ag    *fakeAgent
	st    *fakeStore
	rn    *fakeRunner
	d     *daemon
	rules []byte

	nftCheckErr func(n int) error // n: 1-based call number
	nftLoadErr  error
	nftChecks   atomic.Int32
	tenants     []string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	root, err := os.MkdirTemp("", "serve-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	p := nodecfg.Paths{Root: root}
	for _, dir := range []string{filepath.Dir(p.AdminSock()), filepath.Dir(p.NodeJSON())} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	c := &calls{}
	w := &world{t: t, c: c, ag: newFakeAgent(c), st: newFakeStore(c), rules: []byte("table inet supapace {}\n")}
	w.rn = &fakeRunner{c: c, st: w.st}
	if err := os.WriteFile(p.NftFile(), w.rules, 0o600); err != nil {
		t.Fatal(err)
	}
	d := newDaemon(p, w.ag)
	d.nftRender = func() ([]byte, error) { return w.rules, nil }
	d.nftLoad = func(context.Context) error { c.add("nftLoad"); return w.nftLoadErr }
	d.nftCheck = func(context.Context) error {
		n := int(w.nftChecks.Add(1))
		c.add("nftCheck")
		if w.nftCheckErr != nil {
			return w.nftCheckErr(n)
		}
		return nil
	}
	d.bridgeNF = func() error { c.add("bridgeNF"); return nil }
	d.listTenants = func(context.Context) ([]string, error) { c.add("listTenants"); return w.tenants, nil }
	d.containers = w.ag.containers
	d.connect = func(context.Context) (*backend, error) {
		c.add("connect")
		return &backend{st: w.st, rn: w.rn, api: func(o adminapi.Ops) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				fmt.Fprintf(rw, "containment_ok=%v\n", o.ContainmentOK())
			})
		}}, nil
	}
	d.budget, d.retryEvery, d.healthWait, d.checkEvery = 5*time.Second, time.Hour, 50*time.Millisecond, 5*time.Millisecond
	d.ticks = make(chan time.Time) // no drift tick unless a test sends one
	w.d = d
	return w
}

// start runs serve until the test ends; it returns the exit status channel.
func (w *world) start() (stop func() int) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- w.d.serve(ctx) }()
	var once sync.Once
	code := -1
	stop = func() int {
		once.Do(func() {
			cancel()
			select {
			case code = <-done:
			case <-time.After(10 * time.Second):
				w.t.Error("serve did not return within 10 s of its context ending")
			}
		})
		return code
	}
	w.t.Cleanup(func() { stop() })
	return stop
}

// eventually polls cond every 2 ms for at most d.
func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(d); !cond(); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("not within %v: %s", d, what)
		}
	}
}

// ask sends one request on the admin socket.
func ask(path string) (string, error) {
	c := http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}}
	resp, err := c.Get("http://admin/v1/node/check")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// logs captures slog records for the test's duration.
type logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func captureLogs(t *testing.T) *logs {
	l := &logs{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(l, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return l
}

func refN(i int) string { return fmt.Sprintf("proj%016d", i) }

// ───────── boot order ─────────

func TestBoot_Order(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	var socketUp, runStarted atomic.Bool
	w.ag.ensureCluster = func(context.Context, agent.Spec) error {
		fi, err := os.Lstat(w.d.p.AdminSock())
		socketUp.Store(err == nil && fi.Mode().Type() == fs.ModeSocket)
		for end := time.Now().Add(time.Second); !w.rn.running.Load() && time.Now().Before(end); {
			time.Sleep(time.Millisecond)
		}
		runStarted.Store(w.rn.running.Load())
		return nil
	}
	w.start()
	eventually(t, 5*time.Second, "route active", func() bool { return w.ag.route(refN(1)) == "active" })
	want := []string{"nftCheck", "EnsurePlatformNetworks", "listTenants", "NodeCheck", "EnsureImageFiles", "EnsureControlPlaneDB",
		"connect", "DrainAllRoutes", "EnsureGateway", "ResumeAll", "EnsureCluster:" + refN(1),
		"EnsurePostgREST:" + refN(1), "SetRoute:" + refN(1) + ":active"}
	last := -1
	for _, s := range want {
		i := w.c.index(s)
		if i <= last {
			t.Fatalf("%q at %d, not after the step before it (%d); calls %q", s, i, last, w.c.all())
		}
		last = i
	}
	if !socketUp.Load() || !runStarted.Load() {
		t.Fatalf("at the first EnsureCluster: admin socket up %v, worker started %v; both must be", socketUp.Load(), runStarted.Load())
	}
}

func TestBoot_AdminSocketAndWorkerBeforeProjects(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	answered := make(chan string, 1)
	w.ag.ensureCluster = func(ctx context.Context, _ agent.Spec) error {
		body, err := ask(w.d.p.AdminSock())
		if err != nil {
			body = "error: " + err.Error()
		}
		answered <- body
		<-ctx.Done() // the project never finishes: the socket was already up
		return ctx.Err()
	}
	w.start()
	select {
	case b := <-answered:
		if !strings.Contains(b, "containment_ok=true") {
			t.Fatalf("admin socket during the first adoption: %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no adoption started")
	}
	if w.c.index("Run") < 0 || w.c.index("Run") > w.c.index("EnsureCluster:") {
		eventually(t, time.Second, "worker started", w.rn.running.Load)
	}
}

func TestBoot_DrainsRoutesFirst(t *testing.T) {
	for _, nodeFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("nodeCheckFails=%v", nodeFails), func(t *testing.T) {
			w := newWorld(t)
			w.ag.routes[refN(1)] = "active" // the old route file, as the gateway still has it
			w.st.add(refN(1), "active")
			w.st.add(refN(2), "active")
			if nodeFails {
				w.ag.nodeCheck = func() []nodecfg.CheckResult { return []nodecfg.CheckResult{{Name: "kek", Detail: "mode 0644"}} }
			}
			w.start()
			if nodeFails {
				eventually(t, 5*time.Second, "tenants stopped", func() bool { return w.c.index("StopAllTenants") >= 0 })
			} else {
				eventually(t, 5*time.Second, "both adopted", func() bool { return w.c.count("SetRoute:") == 2 })
			}
			drain := w.c.index("DrainAllRoutes")
			for i, s := range w.c.all() {
				for _, p := range []string{"EnsureCluster", "EnsurePostgREST", "StopAllTenants", "SetRoute"} {
					if strings.HasPrefix(s, p) && i < drain {
						t.Fatalf("%s at %d before DrainAllRoutes at %d", s, i, drain)
					}
				}
			}
			if drain < 0 {
				t.Fatal("routes were never drained")
			}
		})
	}
}

// Boot never stops or re-creates a tenant: nodeAgent has no single-tenant
// stop at all, and StopAllTenants is reached only when containment fails.
func TestBoot_AdoptsRunningTenants(t *testing.T) {
	w := newWorld(t)
	w.tenants = []string{"pg-" + refN(1), "postgrest-" + refN(1), "pg-" + refN(2), "postgrest-" + refN(2)}
	w.st.add(refN(1), "active")
	w.st.add(refN(2), "active")
	w.start()
	// The route is restored before the project leaves the pending set: wait for both.
	eventually(t, 5*time.Second, "routes active and adoptions finished", func() bool {
		return w.ag.route(refN(1)) == "active" && w.ag.route(refN(2)) == "active" &&
			!w.d.isPending(refN(1)) && !w.d.isPending(refN(2))
	})
	if n := w.c.count("StopAllTenants"); n != 0 {
		t.Fatalf("StopAllTenants called %d times at a healthy boot", n)
	}
	for _, r := range []string{refN(1), refN(2)} {
		if w.c.index(fmt.Sprintf("EnsureCluster:%s:1:-1ns", r)) < 0 {
			t.Fatalf("%s: no host-side EnsureCluster (negative HealthWait); calls %q", r, w.c.all())
		}
		if w.d.isPending(r) {
			t.Fatalf("%s still pending after its adoption", r)
		}
	}
}

func TestBoot_StartsMissing(t *testing.T) {
	w := newWorld(t)
	w.tenants = []string{"pg-" + refN(1), "postgrest-" + refN(1)} // refN(2)'s containers are absent
	w.st.add(refN(1), "active")
	w.st.add(refN(2), "active")
	w.start()
	eventually(t, 5*time.Second, "route restored", func() bool { return w.ag.route(refN(2)) == "active" })
	if w.c.index("EnsureCluster:"+refN(2)) < 0 || w.c.index("EnsurePostgREST:"+refN(2)) < 0 {
		t.Fatalf("missing project not ensured: %q", w.c.all())
	}
}

func TestBoot_StartsOnlyActive(t *testing.T) {
	w := newWorld(t)
	states := []string{"active", "deleted", "provisioning", "restarting", "purged", "aborted", "deleting"}
	for i, s := range states {
		w.st.add(refN(i), s)
	}
	stop := w.start()
	eventually(t, 5*time.Second, "active project adopted", func() bool { return w.ag.route(refN(0)) == "active" })
	stop()
	for i := 1; i < len(states); i++ {
		if w.c.index("EnsureCluster:"+refN(i)) >= 0 || w.c.index("EnsurePostgREST:"+refN(i)) >= 0 ||
			w.c.index("SetRoute:"+refN(i)) >= 0 {
			t.Fatalf("%s project %s touched by the loop: %q", states[i], refN(i), w.c.all())
		}
	}
}

func TestBootRecord_OncePerBoot(t *testing.T) {
	w := newWorld(t)
	w.tenants = []string{"postgrest-" + refN(1), "pg-" + refN(1)}
	w.st.add(refN(1), "active")
	first := w.d.now()
	stop := w.start()
	eventually(t, 5*time.Second, "adopted", func() bool { return w.ag.route(refN(1)) == "active" })
	stop()
	if w.c.index("listTenants") > w.c.index("EnsureCluster:") {
		t.Fatalf("boot record listed after the first EnsureCluster: %q", w.c.all())
	}
	b, err := os.ReadFile(w.d.p.BootJSON())
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		StartedAt time.Time `json:"started_at"`
		NftOK     *bool     `json:"nft_ok"`
		Tenants   []string  `json:"tenants_running_at_start"`
	}
	if err := json.Unmarshal(b, &rec); err != nil || rec.NftOK == nil || !*rec.NftOK || rec.StartedAt.Before(first.Add(-time.Second)) ||
		!slices.Equal(rec.Tenants, []string{"pg-" + refN(1), "postgrest-" + refN(1)}) {
		t.Fatalf("boot record %s (%v)", b, err)
	}
	fi, _ := os.Stat(w.d.p.BootJSON())
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("boot record mode %v", fi.Mode())
	}
	// A later daemon start of the same boot leaves it byte-identical.
	w2 := newWorld(t)
	w2.d.p = w.d.p
	w2.tenants = []string{"pg-other"}
	w2.start()()
	b2, _ := os.ReadFile(w.d.p.BootJSON())
	if !bytes.Equal(b, b2) {
		t.Fatalf("boot record rewritten: %s → %s", b, b2)
	}
}

func TestBoot_NftCheckFailureStopsAndStartsNoTenant(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.nftCheckErr = func(int) error { return errors.New("table inet supapace absent") }
	w.nftLoadErr = errors.New("nft -f failed")
	w.start()
	eventually(t, 5*time.Second, "admin socket", func() bool {
		b, err := ask(w.d.p.AdminSock())
		return err == nil && strings.Contains(b, "containment_ok=false")
	})
	w.d.ensureActive(context.Background()) // even an explicit round starts nothing
	if w.c.index("StopAllTenants") < 0 {
		t.Fatal("tenants not stopped")
	}
	if i, j := w.c.index("SetContainmentFailed(true)"), w.c.index("StopAllTenants"); i < 0 || i > j {
		t.Fatalf("flag at %d, stop at %d", i, j)
	}
	if w.c.index("EnsureCluster") >= 0 || w.c.index("EnsurePostgREST") >= 0 {
		t.Fatalf("a tenant was ensured: %q", w.c.all())
	}
	if (ops{w.d}).ContainmentOK() {
		t.Fatal("ContainmentOK true")
	}
}

func TestBoot_NodeCheckFailureStopsAndStartsNoTenant(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.ag.nodeCheck = func() []nodecfg.CheckResult {
		return []nodecfg.CheckResult{{Name: "nft", OK: true}, {Name: "platform-members", Detail: "foreign member"},
			{Name: "drift-hold", OK: true, Detail: "present"}}
	}
	w.start()
	eventually(t, 5*time.Second, "admin socket", func() bool { _, err := ask(w.d.p.AdminSock()); return err == nil })
	if w.c.index("StopAllTenants") < 0 || w.c.index("EnsureCluster") >= 0 || (ops{w.d}).ContainmentOK() {
		t.Fatalf("calls %q", w.c.all())
	}
}

func TestBoot_PlatformNetworkRefusalIsContainment(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.ag.platformErr = agent.ErrContainment
	w.start()
	eventually(t, 5*time.Second, "admin socket", func() bool { _, err := ask(w.d.p.AdminSock()); return err == nil })
	if w.c.index("StopAllTenants") < 0 || w.c.index("EnsureCluster") >= 0 {
		t.Fatalf("calls %q", w.c.all())
	}
}

func TestBoot_OneProjectFailingDoesNotStopOthers(t *testing.T) {
	w := newWorld(t)
	for i := 1; i <= 3; i++ {
		w.st.add(refN(i), "active")
	}
	w.ag.ensureCluster = func(_ context.Context, s agent.Spec) error {
		if s.Ref == refN(1) {
			return errors.New("docker run: exit status 125")
		}
		return nil
	}
	w.start()
	eventually(t, 5*time.Second, "others adopted", func() bool {
		return w.ag.route(refN(2)) == "active" && w.ag.route(refN(3)) == "active"
	})
	if w.ag.route(refN(1)) == "active" || !w.d.isPending(refN(1)) || w.c.count("StopAllTenants") != 0 {
		t.Fatalf("failing project: route %q pending %v; calls %q", w.ag.route(refN(1)), w.d.isPending(refN(1)), w.c.all())
	}
}

func TestBoot_LogsAreSanitised(t *testing.T) {
	l := captureLogs(t)
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.ag.ensureCluster = func(context.Context, agent.Spec) error {
		return errors.New("docker: \x1b]0;owned\x07 line one\nline two\x00" + strings.Repeat("x", 4000))
	}
	w.start()
	eventually(t, 5*time.Second, "failure logged", func() bool { return strings.Contains(l.String(), "adoption failed") })
	for _, line := range strings.Split(l.String(), "\n") {
		if strings.ContainsAny(line, "\x1b\x07\x00") || len(line) > 2048 {
			t.Fatalf("unsanitised or unbounded log line (%d bytes): %q", len(line), line[:min(len(line), 200)])
		}
	}
}

// ───────── adoption: slots, budgets, the pending set ─────────

func TestBoot_RouteOnHostSideFactsOnly(t *testing.T) {
	l := captureLogs(t)
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.st.add(refN(2), "active")
	w.ag.checkCluster = func(ctx context.Context, s agent.Spec) ([]nodecfg.CheckResult, error) {
		if s.Ref == refN(1) {
			<-ctx.Done() // the cluster never answers
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("agent: %w", pgsock.ErrPeer) // never ready
	}
	stop := w.start()
	eventually(t, 5*time.Second, "routes active", func() bool {
		return w.ag.route(refN(1)) == "active" && w.ag.route(refN(2)) == "active"
	})
	// refN(2)'s advisory wait ends after healthWait and is reported.
	eventually(t, 5*time.Second, "advisory reported", func() bool {
		return strings.Contains(l.String(), "advisory cluster check failed") && strings.Contains(l.String(), refN(2))
	})
	if w.c.count("CheckCluster:"+refN(2)) < 2 {
		t.Fatalf("not-ready cluster checked %d times; want repeats within the wait", w.c.count("CheckCluster:"+refN(2)))
	}
	stop()
	if w.ag.route(refN(1)) != "active" || w.ag.route(refN(2)) != "active" || w.c.index("SetContainmentFailed(true)") >= 0 {
		t.Fatalf("an advisory result changed a route or the flag: %q", w.c.all())
	}
}

func TestBoot_SlowProjectDoesNotDelayOthers(t *testing.T) {
	l := captureLogs(t)
	w := newWorld(t)
	w.d.budget, w.d.retryEvery = time.Second, 100*time.Millisecond
	for i := 1; i <= 5; i++ {
		w.st.add(refN(i), "active")
	}
	othersActive := func() bool {
		for i := 2; i <= 5; i++ {
			if w.ag.route(refN(i)) != "active" {
				return false
			}
		}
		return true
	}
	// Read when the slow project's first budget ends: by then the others
	// must be active (order, not a wall-clock margin).
	var atExpiry atomic.Int32 // 0 not yet, 1 others active, 2 not
	w.ag.ensureCluster = func(ctx context.Context, s agent.Spec) error {
		if s.Ref == refN(1) {
			<-ctx.Done()
			v := int32(2)
			if othersActive() {
				v = 1
			}
			atExpiry.CompareAndSwap(0, v)
			return ctx.Err()
		}
		return nil
	}
	w.start()
	eventually(t, 10*time.Second, "slow project's budget ended", func() bool { return atExpiry.Load() != 0 })
	if atExpiry.Load() != 1 {
		t.Fatal("honest routes not active when the slow project's budget ended")
	}
	eventually(t, 5*time.Second, "slow project retried", func() bool { return w.c.count("EnsureCluster:"+refN(1)) >= 2 })
	if w.ag.route(refN(1)) == "active" || !w.d.isPending(refN(1)) || !strings.Contains(l.String(), "budget 1s") {
		t.Fatalf("slow project: route %q, pending %v; log %s", w.ag.route(refN(1)), w.d.isPending(refN(1)), l)
	}
}

func TestBoot_ConcurrencyAtMostFour(t *testing.T) {
	w := newWorld(t)
	for i := 1; i <= 10; i++ {
		w.st.add(refN(i), "active")
	}
	var in, peak atomic.Int32
	w.ag.ensureCluster = func(context.Context, agent.Spec) error {
		n := in.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		in.Add(-1)
		return nil
	}
	w.fill() // no serve needed: one round
	w.d.ensureActive(context.Background())
	if peak.Load() != 4 {
		t.Fatalf("peak concurrency %d, want 4", peak.Load())
	}
	for i := 1; i <= 10; i++ {
		if w.ag.route(refN(i)) != "active" {
			t.Fatalf("%s not adopted", refN(i))
		}
	}
}

// fill wires the store into the daemon and fills the pending set, as boot does.
func (w *world) fill() {
	w.t.Helper()
	w.d.st, w.d.rn = w.st, w.rn
	if err := w.d.refill(context.Background()); err != nil {
		w.t.Fatal(err)
	}
}

func TestBoot_NotAdoptedRefusesOps(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	release := make(chan struct{})
	w.ag.ensureCluster = func(context.Context, agent.Spec) error { <-release; return nil }
	w.start()
	eventually(t, 5*time.Second, "adoption started", func() bool { return w.c.index("EnsureCluster:") >= 0 })
	o := ops{w.d}
	for _, kind := range []string{"restart", "delete"} {
		_, err := o.Submit(context.Background(), kind, refN(1), nil)
		if !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), "not yet adopted") {
			t.Fatalf("%s of a pending project: %v", kind, err)
		}
	}
	if w.c.index("Submit:") >= 0 {
		t.Fatal("refused submission reached the runner")
	}
	// A project created after boot never enters the set.
	w.st.add(refN(2), "active")
	if _, err := o.Submit(context.Background(), "delete", refN(2), nil); err != nil {
		t.Fatalf("project created after boot: %v", err)
	}
	close(release)
	eventually(t, 5*time.Second, "adopted", func() bool { return !w.d.isPending(refN(1)) })
	if id, err := o.Submit(context.Background(), "restart", refN(1), json.RawMessage(`{"base_generation":1}`)); err != nil || id != 7 {
		t.Fatalf("after adoption: %d %v", id, err)
	}
}

func TestBoot_SkipsProjectWithOpenOperation(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.st.add(refN(2), "active")
	for _, st := range []string{"pending", "running", "aborting"} {
		t.Run(st, func(t *testing.T) {
			w.st.mu.Lock()
			w.st.ops[refN(1)] = []store.Operation{{ID: 1, Ref: refN(1), Kind: "delete", State: st}}
			w.st.mu.Unlock()
			w.fill()
			w.d.ensureActive(context.Background())
			if w.c.index("EnsureCluster:"+refN(1)) >= 0 || !w.d.isPending(refN(1)) {
				t.Fatalf("project with a %s operation adopted: %q", st, w.c.all())
			}
			if w.ag.route(refN(2)) != "active" {
				t.Fatal("other project not adopted")
			}
		})
	}
	w.st.mu.Lock()
	w.st.ops[refN(1)] = []store.Operation{{ID: 1, Ref: refN(1), Kind: "delete", State: "failed"}}
	w.st.mu.Unlock()
	w.d.ensureActive(context.Background())
	if w.ag.route(refN(1)) != "active" {
		t.Fatal("not adopted once its operation is closed")
	}
}

func TestBoot_TryLockCostsNoSlot(t *testing.T) {
	w := newWorld(t)
	w.d.slots = 1 // even one slot: locked projects do not hold it
	for i := 1; i <= 5; i++ {
		w.st.add(refN(i), "active")
	}
	for i := 1; i <= 4; i++ {
		w.st.lock(refN(i), true) // a fake worker holds them
	}
	w.fill()
	w.d.budget = time.Hour // a locked project that held the slot would hold it this long
	done := make(chan struct{})
	go func() { w.d.ensureActive(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("round blocked: a locked project held the only slot")
	}
	if w.ag.route(refN(5)) != "active" {
		t.Fatalf("free project not adopted in the first round: %q", w.c.all())
	}
	for i := 1; i <= 4; i++ {
		if w.c.index("EnsureCluster:"+refN(i)) >= 0 || !w.d.isPending(refN(i)) {
			t.Fatalf("locked project %s touched or dropped", refN(i))
		}
		w.st.lock(refN(i), false)
	}
	w.d.ensureActive(context.Background())
	for i := 1; i <= 4; i++ {
		if w.ag.route(refN(i)) != "active" {
			t.Fatalf("%s not adopted by the retry after its lock was released", refN(i))
		}
	}
}

func TestEnsureActive_TakesRefLock(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.st.add(refN(2), "active")
	w.st.lock(refN(1), true)
	w.fill()
	w.d.ensureActive(context.Background())
	if w.c.index("EnsureCluster:"+refN(1)) >= 0 || w.c.index("SetRoute:"+refN(1)) >= 0 {
		t.Fatalf("agent called for a locked project: %q", w.c.all())
	}
	if w.ag.route(refN(2)) != "active" {
		t.Fatal("unlocked project not ensured")
	}
	w.st.lock(refN(1), false)
	w.d.ensureActive(context.Background())
	if w.ag.route(refN(1)) != "active" {
		t.Fatal("not ensured after the lock was released")
	}
	// The loop holds the lock during the agent calls.
	w.ag.ensureCluster = func(_ context.Context, s agent.Spec) error {
		if _, _, ok, _ := w.st.TryLockRefChecked(context.Background(), s.Ref); ok {
			t.Error("ref lock not held during EnsureCluster")
		}
		return nil
	}
	w.fill()
	w.d.ensureActive(context.Background())
}

// The bound of the pass condition: 10 projects, 4 slots, host-side time
// tHost each; 6 whose cluster never answers, 2 whose locks a worker holds,
// 2 honest. Honest routes are active within ⌈10/4⌉ × tHost + 1 s.
func TestBoot_ManyHostileProjectsDoNotDelayOthers(t *testing.T) {
	const tHost = 100 * time.Millisecond
	bound := 3*tHost + time.Second
	for _, control := range []bool{false, true} {
		t.Run(fmt.Sprintf("control=%v", control), func(t *testing.T) {
			w := newWorld(t)
			w.d.retryEvery = 200 * time.Millisecond
			hostile, locked := map[string]bool{}, map[string]bool{}
			for i := 0; i < 10; i++ {
				w.st.add(refN(i), "active")
				switch {
				case control:
				case i < 6:
					hostile[refN(i)] = true
				case i < 8:
					locked[refN(i)] = true
					w.st.lock(refN(i), true)
				}
			}
			w.ag.ensureCluster = func(context.Context, agent.Spec) error { time.Sleep(tHost); return nil }
			w.ag.checkCluster = func(ctx context.Context, s agent.Spec) ([]nodecfg.CheckResult, error) {
				if hostile[s.Ref] {
					<-ctx.Done()
				}
				return nil, ctx.Err()
			}
			start := time.Now()
			w.start()
			stopAsking := make(chan struct{})
			askErr := make(chan error, 1)
			go func() { // the admin socket answers throughout, once it has first answered
				defer close(askErr)
				answered := false
				for {
					select {
					case <-stopAsking:
						return
					default:
					}
					_, err := ask(w.d.p.AdminSock())
					answered = answered || err == nil
					if err != nil && (answered || time.Since(start) > bound) {
						askErr <- err
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}()
			eventually(t, bound+time.Second, "unlocked routes active", func() bool {
				for i := 0; i < 10; i++ {
					if !locked[refN(i)] && w.ag.route(refN(i)) != "active" {
						return false
					}
				}
				return true
			})
			if el := time.Since(start); el > bound {
				t.Fatalf("routes active after %v, bound %v", el, bound)
			}
			for r := range locked {
				if w.c.index("EnsureCluster:"+r) >= 0 {
					t.Fatalf("locked %s ensured", r)
				}
				w.st.lock(r, false)
			}
			eventually(t, 5*time.Second, "locked projects adopted after release", func() bool {
				for r := range locked {
					if w.ag.route(r) != "active" {
						return false
					}
				}
				return true
			})
			close(stopAsking)
			if err := <-askErr; err != nil {
				t.Fatalf("admin socket stopped answering: %v", err)
			}
		})
	}
}

// ───────── ops ─────────

func TestOps_VerifyProjectMapsCodes(t *testing.T) {
	w := newWorld(t)
	w.fill()
	w.st.add(refN(1), "active")
	o := ops{w.d}
	for _, c := range []struct {
		err  error
		code string
	}{
		{nil, ""},
		{fmt.Errorf("agent: x: %w", pgsock.ErrPeer), "peer"},
		{fmt.Errorf("agent: x: %w", pgsock.ErrBudget), "timeout"},
		{context.DeadlineExceeded, "timeout"},
		{fmt.Errorf("agent: x: %w", bootstrap.ErrAssertion), "internal"},
		{fmt.Errorf("agent: x: %w", pgsock.ErrNotSocket), "internal"},
		{errors.New("pg_stat_archiver.failed_count is 3 \x1b[2J"), "internal"},
	} {
		w.ag.checkCluster = func(context.Context, agent.Spec) ([]nodecfg.CheckResult, error) {
			return []nodecfg.CheckResult{{Name: "superuser", Detail: "x"}}, c.err
		}
		code, msg, drift := o.VerifyProject(context.Background(), refN(1))
		if code != c.code || len(drift) != 2 || drift[1].Name != "superuser" || strings.ContainsAny(msg, "\x1b") || (c.err == nil) != (msg == "") {
			t.Fatalf("%v → %q %q %v; want %q", c.err, code, msg, drift, c.code)
		}
	}
	if code, _, _ := o.VerifyProject(context.Background(), "absent00000000000000"); code != "internal" {
		t.Fatalf("unknown project: %q", code)
	}
	// Bounded: a check that never returns ends at verifyMax with timeout.
	w.d.verifyMax = 50 * time.Millisecond
	w.ag.checkCluster = func(ctx context.Context, _ agent.Spec) ([]nodecfg.CheckResult, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if code, _, _ := o.VerifyProject(context.Background(), refN(1)); code != "timeout" {
		t.Fatalf("stalled check: %q", code)
	}
}

func TestOps_WiresRunnerAndAgent(t *testing.T) {
	w := newWorld(t)
	w.fill()
	w.st.add(refN(1), "active")
	o := ops{w.d}
	ctx := context.Background()
	if id, err := o.Submit(ctx, "restart", refN(1), json.RawMessage(`{"a":1}`)); id != 7 || err != nil ||
		w.c.index(`Submit:restart:`+refN(1)+`:{"a":1}`) < 0 {
		t.Fatalf("Submit: %d %v %q", id, err, w.c.all())
	}
	if id, err := o.Abort(ctx, refN(1)); id != 8 || err != nil || w.c.index("Abort:"+refN(1)) < 0 {
		t.Fatalf("Abort: %d %v", id, err)
	}
	if rows := o.NodeCheck(ctx); len(rows) != 1 || w.c.index("NodeCheck") < 0 {
		t.Fatalf("NodeCheck: %v", rows)
	}
	o.VerifyProject(ctx, refN(1))
	if w.c.index("CheckCluster:"+refN(1)) < 0 {
		t.Fatal("VerifyProject did not run CheckCluster")
	}
	if !o.ContainmentOK() {
		t.Fatal("ContainmentOK false with the flag clear")
	}
	w.ag.failed.Store(true)
	if o.ContainmentOK() {
		t.Fatal("ContainmentOK true with the flag set")
	}
}

// ───────── socket, rules, exit codes ─────────

func TestAdminSocket_ModeAndStalePath(t *testing.T) {
	dir, err := os.MkdirTemp("", "serve-sock-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	run := filepath.Join(dir, "run")
	path := filepath.Join(run, "admin.sock")

	ln, err := listenAdmin(path) // creates the directory 0700
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Lstat(path)
	di, _ := os.Lstat(run)
	if fi.Mode().Type() != fs.ModeSocket || fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("socket %v, directory %v", fi.Mode(), di.Mode())
	}
	go http.Serve(ln, http.NotFoundHandler())
	if _, err := listenAdmin(path); err == nil || !strings.Contains(err.Error(), "another daemon") {
		t.Fatalf("live socket: %v", err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close() // a stale socket: the file stays, nobody answers
	ln, err = listenAdmin(path)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	ln.Close()

	for name, mk := range map[string]func() error{
		"regular file": func() error { return os.WriteFile(path, []byte("keep"), 0o600) },
		"directory":    func() error { return os.Mkdir(path, 0o700) },
		"symlink":      func() error { return os.Symlink("/dev/null", path) },
	} {
		os.RemoveAll(path)
		if err := mk(); err != nil {
			t.Fatal(err)
		}
		if _, err := listenAdmin(path); err == nil || !strings.Contains(err.Error(), "not a socket") {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("%s removed: %v", name, err)
		}
	}
	os.RemoveAll(path)
	os.Chmod(run, 0o755)
	if _, err := listenAdmin(path); err == nil {
		t.Fatal("socket directory 0755 accepted")
	}
}

func TestServe_RulesFileFollowsBinary(t *testing.T) {
	w := newWorld(t)
	newRules := []byte("table inet supapace { # newer binary\n}\n")
	w.rules = newRules
	if err := w.d.ensureRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(w.d.p.NftFile())
	fi, _ := os.Stat(w.d.p.NftFile())
	if !bytes.Equal(b, newRules) || fi.Mode().Perm() != 0o600 {
		t.Fatalf("rules file %q mode %v", b, fi.Mode())
	}
	if i, j := w.c.index("nftLoad"), w.c.index("nftCheck"); i < 0 || i > j {
		t.Fatalf("load %d check %d: the new file must be loaded before the check", i, j)
	}
	// Unchanged: no load.
	w2 := newWorld(t)
	if err := w2.d.ensureRules(context.Background()); err != nil || w2.c.index("nftLoad") >= 0 {
		t.Fatalf("unchanged rules: %v %q", err, w2.c.all())
	}
	// A failing check is reloaded once, then checked again.
	w3 := newWorld(t)
	w3.nftCheckErr = func(n int) error {
		if n == 1 {
			return errors.New("drift")
		}
		return nil
	}
	if err := w3.d.ensureRules(context.Background()); err != nil || !slices.Equal(w3.c.all(), []string{"bridgeNF", "nftCheck", "nftLoad", "nftCheck"}) {
		t.Fatalf("%v %q", err, w3.c.all())
	}
}

func TestServe_ExitCodes(t *testing.T) {
	if got := serveCmd([]string{"extra"}); got != 2 {
		t.Fatalf("usage: %d", got)
	}
	w := newWorld(t)
	if code := w.start()(); code != 0 {
		t.Fatalf("after its context ended: %d", code)
	}
	w2 := newWorld(t)
	w2.d.connect = func(context.Context) (*backend, error) { return nil, errors.New("no store") }
	if code := w2.d.serve(context.Background()); code != 1 {
		t.Fatalf("no store: %d", code)
	}
	if _, err := os.Lstat(w2.d.p.AdminSock()); err == nil {
		t.Fatal("admin socket created without a store")
	}
}

// A signal during start-up ends it with exit 0 and is never read as a
// containment finding.
func TestServe_SignalDuringStartup(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	ctx, cancel := context.WithCancel(context.Background())
	w.ag.nodeCheck = func() []nodecfg.CheckResult {
		cancel() // the signal lands during the node check
		return []nodecfg.CheckResult{{Name: "docker-version", Detail: "context canceled"}}
	}
	if code := w.d.serve(ctx); code != 0 {
		t.Fatalf("exit %d after a signal during start-up, want 0", code)
	}
	for _, c := range []string{"SetContainmentFailed(true)", "StopAllTenants", "EnsureCluster"} {
		if w.c.index(c) >= 0 {
			t.Fatalf("%s after a signal: %q", c, w.c.all())
		}
	}
}

// A drain that fails at start is a containment failure: the flag is set and
// every tenant stopped.
func TestBoot_DrainFailureIsContainment(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.ag.drainErr = errors.New("route file: input/output error")
	w.start()
	eventually(t, 5*time.Second, "serving", func() bool { _, err := ask(w.d.p.AdminSock()); return err == nil })
	f, st := w.c.index("SetContainmentFailed(true)"), w.c.index("StopAllTenants")
	if f < 0 || st < f || w.c.index("EnsureCluster") >= 0 || (ops{w.d}).ContainmentOK() {
		t.Fatalf("calls %q", w.c.all())
	}
}

// A ref lock that cannot be tried (a store error) makes no agent call.
func TestEnsureActive_TryLockErrorMakesNoCall(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.fill()
	w.st.lockErr = errors.New("store: connection refused")
	w.d.ensureActive(context.Background())
	for _, c := range []string{"EnsureCluster", "EnsurePostgREST", "SetRoute"} {
		if w.c.index(c) >= 0 {
			t.Fatalf("%s without the ref lock: %q", c, w.c.all())
		}
	}
	if !w.d.isPending(refN(1)) {
		t.Fatal("project dropped from the pending set")
	}
}

// The ref lock's connection died during the adoption: no activation beside
// whatever took the lock since; the project stays pending.
func TestEnsureActive_LostLockNoActivation(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.fill()
	w.ag.ensurePostgREST = func(context.Context, agent.Spec) error {
		w.st.mu.Lock()
		w.st.lost[refN(1)] = errors.New("conn closed")
		w.st.mu.Unlock()
		return nil
	}
	w.d.ensureActive(context.Background())
	if w.c.index("SetRoute:"+refN(1)) >= 0 || !w.d.isPending(refN(1)) {
		t.Fatalf("activated without its lock: %q", w.c.all())
	}
}

// Every project counts as pending until a refill has succeeded.
func TestBoot_RefillFailureRefusesOpsUntilListed(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	fs := &flakyStore{fakeStore: w.st}
	fs.listFail.Store(1)
	w.d.st, w.d.rn = fs, w.rn
	w.d.markRefill()
	if _, err := (ops{w.d}).Submit(context.Background(), "delete", refN(2), nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("submission while the set is unknown: %v", err)
	}
	w.d.ensureActive(context.Background()) // the listing fails
	if w.ag.route(refN(1)) == "active" {
		t.Fatal("adopted without a listing")
	}
	w.d.ensureActive(context.Background())
	if w.ag.route(refN(1)) != "active" {
		t.Fatalf("not adopted once the listing worked: %q", w.c.all())
	}
	if _, err := (ops{w.d}).Submit(context.Background(), "delete", refN(2), nil); err != nil {
		t.Fatalf("after the listing: %v", err)
	}
}

// A path at the admin socket that is not a socket refuses the start before
// anything is touched: no restart loop that drains every route each second.
func TestBoot_SocketPathCheckedFirst(t *testing.T) {
	w := newWorld(t)
	if err := os.WriteFile(w.d.p.AdminSock(), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := w.d.serve(context.Background()); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if c := w.c.all(); len(c) != 0 {
		t.Fatalf("calls before refusing: %q", c)
	}
}

func TestOps_NodeCheckBounded(t *testing.T) {
	w := newWorld(t)
	w.d.verifyMax = 50 * time.Millisecond
	w.ag.nodeCheckWait = true
	done := make(chan struct{})
	go func() { (ops{w.d}).NodeCheck(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("node check of the admin API unbounded")
	}
}

// A request still running when the shutdown grace ends is cut (its context
// cancelled), so nothing it holds keeps the daemon from closing the store.
func TestServe_ShutdownCutsStalledRequests(t *testing.T) {
	w := newWorld(t)
	w.d.grace = 50 * time.Millisecond
	started, cut := make(chan struct{}), make(chan struct{})
	inner := w.d.connect
	w.d.connect = func(ctx context.Context) (*backend, error) {
		be, err := inner(ctx)
		be.api = func(adminapi.Ops) http.Handler {
			return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				close(started)
				<-r.Context().Done()
				close(cut)
			})
		}
		return be, err
	}
	stop := w.start()
	// The socket file exists from bind, before listen: only a dial that
	// succeeds shows the server accepting.
	var c net.Conn // a client that never gives up
	eventually(t, 10*time.Second, "admin socket accepting", func() bool {
		var err error
		c, err = net.Dial("unix", w.d.p.AdminSock())
		return err == nil
	})
	defer c.Close()
	fmt.Fprint(c, "GET /v1/node/check HTTP/1.1\r\nHost: admin\r\n\r\n")
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the request never reached the handler")
	}
	stop()
	select {
	case <-cut:
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled request outlived the shutdown")
	}
}
