package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/store"
)

// adoptedWorld is a world whose projects 1..n are adopted by a first round:
// their containers run, their routes are active, none is pending.
func adoptedWorld(t *testing.T, n int) *world {
	t.Helper()
	w := newWorld(t)
	for i := 1; i <= n; i++ {
		w.st.add(refN(i), "active")
	}
	w.fill()
	w.d.ensureActive(context.Background())
	w.d.bg.Wait()
	for i := 1; i <= n; i++ {
		if w.ag.route(refN(i)) != "active" || w.d.isPending(refN(i)) {
			t.Fatalf("control: %s not adopted", refN(i))
		}
	}
	return w
}

// round runs one round and returns the calls it made.
func (w *world) round() []string {
	before := len(w.c.all())
	w.d.ensureActive(context.Background())
	w.d.bg.Wait()
	return w.c.all()[before:]
}

func has(calls []string, prefix string) bool {
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// A dead cluster, a dead PostgREST, a dead gateway and a dead control-plane
// database are started by the next round, each with one INFO line; the
// other project is not touched and no route changes.
func TestRepair_DeadContainersStartedNextRound(t *testing.T) {
	w := adoptedWorld(t, 2)
	l := captureLogs(t)
	for _, c := range []struct {
		kill, ensure, log string
	}{
		{"pg-" + refN(1), "EnsureCluster:" + refN(1), "repair: started\" ref=" + refN(1) + " containers=pg-" + refN(1)},
		{"postgrest-" + refN(2), "EnsurePostgREST:" + refN(2), "repair: started\" ref=" + refN(2) + " containers=postgrest-" + refN(2)},
		{"sp-gateway", "EnsureGateway", "repair: started\" container=sp-gateway"},
		{"sp-cp-db", "EnsureControlPlaneDB", "repair: started\" container=sp-cp-db"},
	} {
		w.ag.setUp(c.kill, false)
		calls := w.round()
		if !has(calls, c.ensure) || !strings.Contains(l.String(), c.log) {
			t.Fatalf("%s killed: calls %q; log:\n%s", c.kill, calls, l)
		}
		touched := func(ref string) bool { return has(calls, "EnsureCluster:"+ref) || has(calls, "EnsurePostgREST:"+ref) }
		if has(calls, "SetRoute") || touched(refN(1)) != strings.HasSuffix(c.kill, refN(1)) ||
			touched(refN(2)) != strings.HasSuffix(c.kill, refN(2)) {
			t.Fatalf("%s killed: the round also touched %q", c.kill, calls)
		}
		if w.ag.route(refN(1)) != "active" || w.ag.route(refN(2)) != "active" || w.d.isPending(refN(1)) || w.d.isPending(refN(2)) {
			t.Fatalf("%s killed: routes %q %q, pending %v %v", c.kill, w.ag.route(refN(1)), w.ag.route(refN(2)),
				w.d.isPending(refN(1)), w.d.isPending(refN(2)))
		}
	}
	// The restarted cluster gets the advisory check; a restarted PostgREST does not.
	if n := strings.Count(strings.Join(w.c.all(), "\n"), "CheckCluster:"+refN(1)); n != 2 {
		t.Fatalf("advisory checks of %s: %d, want 2 (adoption and repair)", refN(1), n)
	}
	if n := strings.Count(strings.Join(w.c.all(), "\n"), "CheckCluster:"+refN(2)); n != 1 {
		t.Fatalf("advisory checks of %s: %d, want 1 (adoption only; its repair restarted only PostgREST)", refN(2), n)
	}
}

// A healthy node: the round ensures the platform services (left untouched by
// the agent) and touches no project: no lock, no ensure, no route, no log.
func TestRepair_HealthyUntouched(t *testing.T) {
	w := adoptedWorld(t, 3)
	l := captureLogs(t)
	calls := w.round()
	for _, bad := range []string{"TryLockRef", "EnsureCluster", "EnsurePostgREST", "SetRoute", "StopAllTenants", "DrainAllRoutes"} {
		if has(calls, bad) {
			t.Fatalf("healthy round called %s: %q", bad, calls)
		}
	}
	if !has(calls, "EnsureControlPlaneDB") || !has(calls, "EnsureGateway") {
		t.Fatalf("platform services not ensured: %q", calls)
	}
	if l.String() != "" {
		t.Fatalf("healthy round logged:\n%s", l)
	}
}

// A project with an open operation, or whose lock an operation holds, is
// left to that operation even when its containers are down.
func TestRepair_OpenOperationUntouched(t *testing.T) {
	w := adoptedWorld(t, 2)
	w.ag.setUp("pg-"+refN(1), false)
	w.ag.setUp("pg-"+refN(2), false)
	w.st.mu.Lock()
	w.st.ops[refN(1)] = []store.Operation{{ID: 3, Kind: "restart", State: "running"}}
	w.st.mu.Unlock()
	w.st.lock(refN(2), true)
	calls := w.round()
	if has(calls, "EnsureCluster") || has(calls, "SetRoute") {
		t.Fatalf("a project owned by an operation was touched: %q", calls)
	}
	if o := (ops{w.d}); func() error { _, err := o.Submit(context.Background(), "restart", refN(1), nil); return err }() != nil {
		t.Fatal("a repair candidate is refused: it must never enter the pending set")
	}
}

// No round while the node is containment_failed: not even the platform
// services.
func TestRepair_NoRoundWhileFlagged(t *testing.T) {
	w := adoptedWorld(t, 1)
	w.ag.setUp("pg-"+refN(1), false)
	w.ag.setUp("sp-gateway", false)
	w.ag.failed.Store(true)
	if calls := w.round(); len(calls) != 0 {
		t.Fatalf("round while flagged: %q", calls)
	}
}

// A project whose repair fails gets its route drained (the defined 503) and
// one WARN per round; another project is repaired in the same round; the
// round ends within the budget; a later successful round restores the route.
func TestRepair_FailingProjectDrainsOthersUnaffected(t *testing.T) {
	w := adoptedWorld(t, 2)
	w.d.budget = 200 * time.Millisecond
	l := captureLogs(t)
	w.ag.setUp("pg-"+refN(1), false)
	w.ag.setUp("pg-"+refN(2), false)
	fail := true
	w.ag.ensureCluster = func(ctx context.Context, s agent.Spec) error {
		if s.Ref == refN(1) && fail {
			<-ctx.Done() // a Docker call that hangs until the budget ends
			return ctx.Err()
		}
		return nil
	}
	start := time.Now()
	w.round()
	if el := time.Since(start); el > 10*time.Second { // the hanging call never ends on its own
		t.Fatalf("round took %v with a hanging project (budget %v)", el, w.d.budget)
	}
	if w.ag.route(refN(1)) != "draining" || w.ag.route(refN(2)) != "active" {
		t.Fatalf("routes after the failed repair: %q %q", w.ag.route(refN(1)), w.ag.route(refN(2)))
	}
	if n := strings.Count(l.String(), "level=WARN msg=\"repair failed"); n != 1 || !strings.Contains(l.String(), "ref="+refN(1)) {
		t.Fatalf("%d WARN lines for one failing round:\n%s", n, l)
	}
	if !strings.Contains(l.String(), "repair: started\" ref="+refN(2)) {
		t.Fatalf("the other project was not repaired:\n%s", l)
	}
	// Still failing: one more WARN, the route is not written again.
	if calls := w.round(); has(calls, "SetRoute") || strings.Count(l.String(), "repair failed") != 2 {
		t.Fatalf("second failing round: calls %q\n%s", calls, l)
	}
	fail = false
	w.round()
	if w.ag.route(refN(1)) != "active" || w.d.isDrained(refN(1)) {
		t.Fatalf("route after the repair succeeded: %q", w.ag.route(refN(1)))
	}
	if calls := w.round(); has(calls, "SetRoute") || has(calls, "EnsureCluster") {
		t.Fatalf("a repaired project is touched again: %q", calls)
	}
}

// A cluster that exits right after an adoption: the advisory check says so
// at WARN with the ref without waiting out its whole bound, and the next
// round starts the cluster.
func TestAdvisory_ClusterExitedAfterAdoption(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.fill()
	w.d.healthWait = time.Hour
	l := captureLogs(t)
	w.ag.checkCluster = func(context.Context, agent.Spec) ([]nodecfg.CheckResult, error) {
		w.ag.setUp("pg-"+refN(1), false) // it died
		return nil, fmt.Errorf("agent: x: %w", pgsock.Clean(fmt.Errorf("%w: %w", pgsock.ErrConnect, syscall.ECONNREFUSED)))
	}
	done := make(chan struct{})
	go func() { w.d.ensureActive(context.Background()); w.d.bg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the advisory check waited although the cluster container is gone")
	}
	if !strings.Contains(l.String(), "level=WARN") || !strings.Contains(l.String(), "cluster container is not running") ||
		!strings.Contains(l.String(), "ref="+refN(1)) {
		t.Fatalf("log:\n%s", l)
	}
	w.ag.checkCluster = nil
	if calls := w.round(); !has(calls, "EnsureCluster:"+refN(1)) {
		t.Fatalf("the exited cluster was not started by the next round: %q", calls)
	}
}

// Containment at start no longer waits for the store: a failing blocking
// node-check row stops the tenants although the store never comes up.
func TestBoot_NodeCheckBeforeStore(t *testing.T) {
	w := newWorld(t)
	w.ag.nodeCheck = func() []nodecfg.CheckResult { return []nodecfg.CheckResult{{Name: "kek", Detail: "mode 0644"}} }
	w.d.connect = func(context.Context) (*backend, error) {
		w.c.add("connect")
		return nil, errors.New("store never comes up")
	}
	if _, ok := w.d.boot(context.Background()); ok {
		t.Fatal("boot without a store succeeded")
	}
	if i, j := w.c.index("StopAllTenants"), w.c.index("connect"); i < 0 || i > j || !w.ag.ContainmentFailed() {
		t.Fatalf("tenants not stopped before the store wait: %q", w.c.all())
	}
}

// The platform services' rows fail without blocking: at start they set no
// flag, and while flagged they do not keep the flag set.
func TestNodeCheck_PlatformRowsNotBlocking(t *testing.T) {
	gwDown := func() []nodecfg.CheckResult {
		return []nodecfg.CheckResult{{Name: "nft", OK: true}, {Name: "gateway", Detail: "sp-gateway not running"},
			{Name: "control-plane-db", Detail: "sp-cp-db not running"}}
	}
	w := newWorld(t)
	w.ag.nodeCheck = gwDown
	w.st.add(refN(1), "active")
	w.start()
	eventually(t, 5*time.Second, "adopted", func() bool { return w.ag.route(refN(1)) == "active" })
	if w.ag.ContainmentFailed() || w.c.index("StopAllTenants") >= 0 {
		t.Fatalf("a dead gateway contained the node: %q", w.c.all())
	}
	w.ag.failed.Store(true)
	w.d.driftTick(context.Background())
	if w.ag.ContainmentFailed() {
		t.Fatal("the flag stayed set on a dead gateway alone")
	}
}

// While flagged, a tick whose firewall check is unverifiable stops the
// tenants again (one may have been started since).
func TestDrift_UnverifiedWhileFlaggedStopsAgain(t *testing.T) {
	w := newWorld(t)
	w.fill()
	w.nftCheckErr = func(int) error { return fmt.Errorf("x: %w", nft.ErrUnverified) }
	w.ag.failed.Store(true)
	w.d.driftTick(context.Background())
	if w.c.count("StopAllTenants") != 1 || w.c.index("nftLoad") >= 0 {
		t.Fatalf("calls %q", w.c.all())
	}
	w.ag.failed.Store(false)
	w.d.strikes = 0
	w.d.driftTick(context.Background())
	if w.c.count("StopAllTenants") != 1 {
		t.Fatal("an unverifiable tick on a contained node stopped the tenants")
	}
}

// project check reads the host-side facts first and independently of the
// session: a failing row is reported in the drift by name; with a passing
// session it fails the check (code internal, the rows in the message); a
// failing session keeps its own code.
func TestOps_VerifyProjectHostSide(t *testing.T) {
	w := newWorld(t)
	w.fill()
	w.st.add(refN(1), "active")
	o := ops{w.d}
	w.ag.checkHost = func(agent.Spec) []nodecfg.CheckResult {
		return []nodecfg.CheckResult{{Name: "cluster-container", OK: true}, {Name: "rest-container", Detail: "postgrest-x not running"},
			{Name: "route", OK: true}}
	}
	code, msg, drift := o.VerifyProject(context.Background(), refN(1))
	if code != "internal" || !strings.Contains(msg, "rest-container: postgrest-x not running") || len(drift) != 3 || drift[1].OK {
		t.Fatalf("dead PostgREST, cluster answering: %q %q %v", code, msg, drift)
	}
	if i, j := w.c.index("CheckHost:"), w.c.index("CheckCluster:"); i < 0 || i > j {
		t.Fatalf("host-side facts not read before the session: %q", w.c.all())
	}
	w.ag.checkCluster = func(context.Context, agent.Spec) ([]nodecfg.CheckResult, error) {
		return nil, fmt.Errorf("agent: x: %w", syscall.ECONNREFUSED)
	}
	if code, _, drift := o.VerifyProject(context.Background(), refN(1)); code != "internal" || len(drift) != 3 {
		t.Fatalf("both failing: %q %v", code, drift)
	}
	w.ag.checkHost = nil
	w.ag.checkCluster = nil
	if code, msg, _ := o.VerifyProject(context.Background(), refN(1)); code != "" || msg != "" {
		t.Fatalf("healthy: %q %q", code, msg)
	}
}

// A cluster that answers "starting up" (57P03) right after its start is
// waited for, not reported as failed.
func TestAdvisory_StartingUpIsNotReady(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.fill()
	w.d.healthWait = time.Hour
	l := captureLogs(t)
	n := 0
	w.ag.checkCluster = func(context.Context, agent.Spec) ([]nodecfg.CheckResult, error) {
		if n++; n < 3 {
			return nil, fmt.Errorf("agent: x: login: %w", &pgsock.ServerError{Code: "57P03", Message: "the database system is starting up"})
		}
		return nil, nil
	}
	w.round()
	if n != 3 || !strings.Contains(l.String(), "advisory cluster check passed") || strings.Contains(l.String(), "level=WARN") {
		t.Fatalf("%d checks; log:\n%s", n, l)
	}
}

// What the advisory check waits for, on errors as the agent wraps the socket
// package's (cleaned) errors.
func TestAdvisory_NotReady(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("agent: x: %w", pgsock.Clean(err)) }
	for _, c := range []struct {
		err  error
		want bool
	}{
		{wrap(fmt.Errorf("%w: %w", pgsock.ErrConnect, syscall.ECONNREFUSED)), true},
		{wrap(pgsock.ErrPeer), true},
		{wrap(pgsock.ErrNotSocket), true},
		{wrap(&pgsock.ServerError{Code: "57P03"}), true},
		{wrap(&pgsock.ServerError{Code: "28P01"}), false},
		// A server's words never read as not ready.
		{wrap(errors.New("login: server error: FATAL: x: socket: connect: connection refused")), false},
		{wrap(fmt.Errorf("%w: connect: i/o timeout", pgsock.ErrBudget)), false},
		{errors.New("agent: x: pg_stat_archiver.failed_count is 3"), false},
	} {
		if got := notReady(c.err); got != c.want {
			t.Errorf("%v: not ready %v, want %v", c.err, got, c.want)
		}
	}
}

// A route that a failed repair drained is restored by the next successful
// round even when both containers run again by then (the trigger is the
// drained mark, not a container that is down).
func TestRepair_DrainedRouteRestoredWithContainersRunning(t *testing.T) {
	w := adoptedWorld(t, 1)
	w.d.budget = 200 * time.Millisecond
	w.ag.setUp("pg-"+refN(1), false)
	w.ag.ensureCluster = func(ctx context.Context, _ agent.Spec) error {
		<-ctx.Done()
		return ctx.Err()
	}
	w.round()
	if w.ag.route(refN(1)) != "draining" {
		t.Fatalf("control: route after the failed repair: %q", w.ag.route(refN(1)))
	}
	w.ag.ensureCluster = nil
	w.ag.setUp("pg-"+refN(1), true) // running again, started by something else
	if calls := w.round(); !has(calls, "SetRoute:"+refN(1)+":active") || w.ag.route(refN(1)) != "active" {
		t.Fatalf("drained route not restored: route %q, calls %q", w.ag.route(refN(1)), calls)
	}
}

// A repair whose ref lock was lost writes no route: an operation may own the
// project by then.
func TestRepair_LockLostWritesNoRoute(t *testing.T) {
	w := adoptedWorld(t, 1)
	w.ag.setUp("postgrest-"+refN(1), false)
	w.st.mu.Lock()
	w.st.lost[refN(1)] = errors.New("conn closed")
	w.st.mu.Unlock()
	if calls := w.round(); has(calls, "SetRoute:"+refN(1)) {
		t.Fatalf("a repair without its lock wrote the route: %q", calls)
	}
}

// A drift hold younger than its limit pauses the project repairs of the
// round, with one INFO line; the platform services are still ensured and a
// pending project is still adopted. A stale or future-dated hold pauses
// nothing.
func TestRepair_DriftHoldPausesRepairs(t *testing.T) {
	w := adoptedWorld(t, 1)
	w.st.add(refN(2), "active")
	w.fill() // refN(2) pending; refN(1) already adopted
	w.d.adopted(refN(1), w.d.generation())
	w.ag.setUp("pg-"+refN(1), false)
	w.ag.setUp("sp-gateway", false)
	hold(t, w, time.Minute)
	l := captureLogs(t)
	calls := w.round()
	if has(calls, "EnsureCluster:"+refN(1)) || !has(calls, "EnsureCluster:"+refN(2)) || !has(calls, "EnsureGateway") ||
		strings.Count(l.String(), "project repairs paused this round") != 1 {
		t.Fatalf("hold present: calls %q\n%s", calls, l)
	}
	for _, age := range []time.Duration{16 * time.Minute, -time.Hour} {
		hold(t, w, age)
		w.ag.setUp("pg-"+refN(1), false)
		if calls := w.round(); !has(calls, "EnsureCluster:"+refN(1)) {
			t.Fatalf("hold aged %v: dead cluster not repaired: %q", age, calls)
		}
	}
}
