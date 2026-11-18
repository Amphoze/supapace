package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// driftWorld is a world whose daemon is wired (store, pending set) without
// serve; ticks are run directly.
func driftWorld(t *testing.T) *world {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.fill()
	w.d.adopted(refN(1), w.d.generation())
	w.c.log = nil
	return w
}

func failFrom(from int, err error) func(int) error {
	return func(n int) error {
		if n >= from {
			return err
		}
		return nil
	}
}

func TestDrift_ReloadRestores(t *testing.T) {
	w := driftWorld(t)
	w.nftCheckErr = func(n int) error {
		if n == 1 {
			return nft.ErrDrift
		}
		return nil
	}
	w.d.driftTick(context.Background())
	if w.c.count("nftLoad") != 1 || w.c.index("StopAllTenants") >= 0 || w.c.index("DrainAllRoutes") >= 0 ||
		w.ag.ContainmentFailed() {
		t.Fatalf("calls %q", w.c.all())
	}
}

func TestDrift_ReloadThenStop(t *testing.T) {
	w := driftWorld(t)
	w.nftCheckErr = failFrom(1, nft.ErrAbsent)
	w.d.driftTick(context.Background())
	if w.c.count("nftLoad") != 1 || w.c.index("DrainAllRoutes") < 0 || w.c.index("StopAllTenants") < 0 || (ops{w.d}).ContainmentOK() {
		t.Fatalf("calls %q", w.c.all())
	}
	if !w.d.isPending(refN(1)) {
		t.Fatal("containment failure did not refill the pending set")
	}
	// Later failing ticks load again and stop again; the flag and the drain
	// happen once.
	w.d.driftTick(context.Background())
	if w.c.count("nftLoad") != 2 || w.c.count("StopAllTenants") != 2 || w.c.count("DrainAllRoutes") != 1 ||
		w.c.count("SetContainmentFailed(true)") != 1 {
		t.Fatalf("second failing tick: %q", w.c.all())
	}
}

func TestDrift_FlagSetBeforeDrain(t *testing.T) {
	w := driftWorld(t)
	w.nftCheckErr = failFrom(1, nft.ErrDrift)
	w.d.driftTick(context.Background())
	var seq []string
	for _, s := range w.c.all() {
		switch s {
		case "SetContainmentFailed(true)", "DrainAllRoutes", "StopAllTenants":
			seq = append(seq, s)
		}
	}
	if strings.Join(seq, ",") != "SetContainmentFailed(true),DrainAllRoutes,StopAllTenants" {
		t.Fatalf("order %q", seq)
	}
}

func hold(t *testing.T, w *world, age time.Duration) {
	t.Helper()
	f := w.d.p.DriftHold()
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m := time.Now().Add(-age)
	if err := os.Chtimes(f, m, m); err != nil {
		t.Fatal(err)
	}
}

func TestDrift_HoldFile(t *testing.T) {
	w := driftWorld(t)
	w.nftCheckErr = failFrom(1, nft.ErrDrift)
	hold(t, w, 0)
	w.d.driftTick(context.Background())
	if w.c.index("nftLoad") >= 0 || w.c.index("StopAllTenants") >= 0 || w.c.index("nftCheck") >= 0 {
		t.Fatalf("held tick acted: %q", w.c.all())
	}
	os.Remove(w.d.p.DriftHold())
	w.d.driftTick(context.Background())
	if w.c.count("nftLoad") != 1 {
		t.Fatalf("tick after the hold: %q", w.c.all())
	}
}

func TestDrift_HoldFileExpires(t *testing.T) {
	w := driftWorld(t)
	w.nftCheckErr = failFrom(1, nft.ErrDrift)
	hold(t, w, 15*time.Minute+time.Second)
	w.d.driftTick(context.Background())
	if w.c.count("nftLoad") != 1 || !w.ag.ContainmentFailed() {
		t.Fatalf("an expired hold was honoured: %q", w.c.all())
	}
	// Just under the bound it still holds.
	w2 := driftWorld(t)
	w2.nftCheckErr = failFrom(1, nft.ErrDrift)
	hold(t, w2, 15*time.Minute-time.Minute)
	w2.d.driftTick(context.Background())
	if w2.c.index("nftCheck") >= 0 {
		t.Fatal("a 14-minute hold was ignored")
	}
}

func TestDrift_HoldLogsWarnEachTick(t *testing.T) {
	l := captureLogs(t)
	w := driftWorld(t)
	hold(t, w, 5*time.Second)
	w.d.driftTick(context.Background())
	w.d.driftTick(context.Background())
	n := 0
	for _, line := range strings.Split(l.String(), "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "drift check skipped: hold file present, age 5s") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d WARN records for two skipped ticks:\n%s", n, l)
	}
}

func TestDrift_UnverifiedThreeStrikes(t *testing.T) {
	w := driftWorld(t)
	w.nftCheckErr = failFrom(1, fmt.Errorf("%w: nft: exit status 1", nft.ErrUnverified))
	w.d.driftTick(context.Background())
	w.d.driftTick(context.Background())
	if w.c.index("nftLoad") >= 0 || w.ag.ContainmentFailed() {
		t.Fatalf("acted before the third unverifiable check: %q", w.c.all())
	}
	w.d.driftTick(context.Background())
	if w.c.count("nftLoad") != 1 || !w.ag.ContainmentFailed() || w.c.index("StopAllTenants") < 0 {
		t.Fatalf("third unverifiable check: %q", w.c.all())
	}

	// Strikes count consecutive checks only: a verified one resets them.
	w2 := driftWorld(t)
	seq := []error{nft.ErrUnverified, nft.ErrUnverified, nil, nft.ErrUnverified, nft.ErrUnverified}
	w2.nftCheckErr = func(n int) error { return seq[min(n, len(seq))-1] }
	for range seq {
		w2.d.driftTick(context.Background())
	}
	if w2.ag.ContainmentFailed() || w2.c.index("nftLoad") >= 0 {
		t.Fatalf("non-consecutive strikes acted: %q", w2.c.all())
	}
	// Drift, absence and bridge-nf act at once.
	for _, e := range []error{nft.ErrDrift, nft.ErrAbsent, nft.ErrBridgeNF} {
		w3 := driftWorld(t)
		w3.nftCheckErr = failFrom(1, e)
		w3.d.driftTick(context.Background())
		if !w3.ag.ContainmentFailed() {
			t.Fatalf("%v did not fail closed at once", e)
		}
	}
}

func TestDrift_ClearsFlagSignalsEnsure(t *testing.T) {
	w := driftWorld(t)
	w.nftCheckErr = failFrom(1, nft.ErrDrift)
	w.d.driftTick(context.Background())
	if (ops{w.d}).ContainmentOK() {
		t.Fatal("flag not set")
	}
	// While the node check fails the flag stays.
	w.nftCheckErr = nil
	nodeOK := false
	w.ag.nodeCheck = func() []nodecfg.CheckResult { return []nodecfg.CheckResult{{Name: "nft", OK: nodeOK}} }
	w.d.driftTick(context.Background())
	if (ops{w.d}).ContainmentOK() {
		t.Fatal("cleared with a failing node check")
	}
	// The ensure loop would block forever: the clearing tick must not wait on it.
	w.ag.ensureCluster = func(ctx context.Context, _ agent.Spec) error { <-ctx.Done(); return ctx.Err() }
	nodeOK = true
	done := make(chan struct{})
	go func() { w.d.driftTick(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("clearing tick blocked")
	}
	if !(ops{w.d}).ContainmentOK() {
		t.Fatal("flag not cleared")
	}
	select {
	case <-w.d.wake:
	default:
		t.Fatal("ensure loop not signalled")
	}
	// The signalled loop runs ensureActive once for the pending project.
	w.ag.ensureCluster = nil
	w.d.retryEvery = time.Hour
	w.d.signalEnsure()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A round at start, then one per signal: drain the start round first.
	go w.d.ensureLoop(ctx)
	eventually(t, 5*time.Second, "re-ensured", func() bool { return w.ag.route(refN(1)) == "active" })
}

// Every error a cluster call can return leaves the flag alone; only the
// firewall check and the node check move it.
func TestDrift_NoClusterInputReachesContainmentFlag(t *testing.T) {
	errs := []error{agent.ErrContainment, pgsock.ErrPeer, pgsock.ErrBudget, bootstrap.ErrAssertion,
		agent.ErrEpochDivergence, agent.ErrStaleGeneration, context.DeadlineExceeded, errors.New("garbage \x1b[0m")}
	w := newWorld(t)
	for i := range errs {
		w.st.add(refN(i), "active")
	}
	pick := func(s agent.Spec) error {
		var i int
		fmt.Sscanf(s.Ref, "proj%016d", &i)
		return errs[i]
	}
	w.ag.ensureCluster = func(_ context.Context, s agent.Spec) error {
		if s.Ref == refN(0) {
			return nil
		}
		return pick(s)
	}
	w.ag.ensurePostgREST = func(_ context.Context, s agent.Spec) error { return pick(s) }
	w.ag.checkCluster = func(_ context.Context, s agent.Spec) ([]nodecfg.CheckResult, error) {
		return []nodecfg.CheckResult{{Name: "superuser", Detail: "two"}}, pick(s)
	}
	w.fill()
	for range 3 {
		w.d.ensureActive(context.Background())
		w.d.driftTick(context.Background())
		for i := range errs {
			(ops{w.d}).VerifyProject(context.Background(), refN(i))
		}
	}
	w.d.bg.Wait()
	if w.c.index("SetContainmentFailed") >= 0 {
		t.Fatalf("a cluster result moved the flag: %q", w.c.all())
	}
	// Control: the firewall check does move it.
	w.nftCheckErr = failFrom(1, nft.ErrDrift)
	w.d.driftTick(context.Background())
	if w.c.index("SetContainmentFailed(true)") < 0 {
		t.Fatal("control: a failing firewall check did not set the flag")
	}
}

// The drift timer keeps its cadence while every adoption and cluster check
// stalls: 5 ticks are 5 checks, and a failure on tick 3 sets the flag on
// tick 3.
func TestDrift_CadenceWhileEnsureStalls(t *testing.T) {
	for _, stall := range []bool{true, false} {
		t.Run(fmt.Sprintf("stall=%v", stall), func(t *testing.T) {
			w := newWorld(t)
			for i := range 6 {
				w.st.add(refN(i), "active")
			}
			if stall {
				block := func(ctx context.Context, _ agent.Spec) error { <-ctx.Done(); return ctx.Err() }
				w.ag.ensureCluster = block
				w.ag.checkCluster = func(ctx context.Context, s agent.Spec) ([]nodecfg.CheckResult, error) {
					return nil, block(ctx, s)
				}
			}
			ticks := make(chan time.Time)
			w.d.ticks = ticks
			// nft.Check calls: 1 at boot, then one per tick; tick 3 is calls 4
			// and 5 (the check after the reload).
			w.nftCheckErr = func(n int) error {
				if n == 4 || n == 5 {
					return nft.ErrDrift
				}
				return nil
			}
			w.ag.nodeCheck = func() []nodecfg.CheckResult {
				return []nodecfg.CheckResult{{Name: "nft", OK: !w.ag.ContainmentFailed()}}
			}
			stop := w.start()
			eventually(t, 5*time.Second, "serving", func() bool { return w.c.index("Run") >= 0 && w.c.index("EnsureCluster:") >= 0 })
			for k := 1; k <= 5; k++ {
				select {
				case ticks <- time.Now():
				case <-time.After(5 * time.Second):
					t.Fatalf("tick %d not taken: the timer waits on something", k)
				}
			}
			stop()                  // returns after the drift loop finished its tick
			flagAt, ticked := 0, -1 // the boot's own check is not a tick
			for _, s := range w.c.all() {
				switch {
				case s == "bridgeNF":
					ticked++
				case s == "SetContainmentFailed(true)" && flagAt == 0:
					flagAt = ticked
				}
			}
			if ticked != 5 {
				t.Fatalf("%d checks for 5 ticks", ticked)
			}
			if flagAt != 3 {
				t.Fatalf("flag set on tick %d, want 3; calls %q", flagAt, w.c.all())
			}
		})
	}
}

// While the firewall is fine but the node check still fails, each tick stops
// the tenants again.
func TestDrift_StopsAgainWhileNodeCheckFails(t *testing.T) {
	w := driftWorld(t)
	w.ag.failed.Store(true)
	w.ag.nodeCheck = func() []nodecfg.CheckResult { return []nodecfg.CheckResult{{Name: "kek", Detail: "mode 0644"}} }
	w.d.driftTick(context.Background())
	w.d.driftTick(context.Background())
	if n := w.c.count("StopAllTenants"); n != 2 || !w.ag.ContainmentFailed() {
		t.Fatalf("StopAllTenants %d times over two ticks with a failing node check: %q", n, w.c.all())
	}
}
