package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/routes"
	"github.com/Amphoze/supapace/internal/store"
)

// A second `serve` on a node whose daemon is running must leave that
// daemon's routes, tenants and hold file alone: it may only refuse.
func TestBoot_SecondDaemonTouchesNothing(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.start()
	eventually(t, 5*time.Second, "first daemon adopted", func() bool { return w.ag.route(refN(1)) == "active" })

	w2 := newWorld(t)
	w2.d.p = w.d.p
	w2.ag.routes[refN(1)] = "active"
	w2.st.add(refN(1), "active")
	hold(t, w2, 0)
	if code := w2.d.serve(context.Background()); code != 1 {
		t.Fatalf("second daemon: exit %d, want 1", code)
	}
	for _, c := range []string{"DrainAllRoutes", "StopAllTenants", "nftLoad", "SetRoute", "EnsureCluster"} {
		if w2.c.index(c) >= 0 {
			t.Fatalf("second daemon called %s before refusing: %q", c, w2.c.all())
		}
	}
	if _, err := os.Lstat(w.d.p.DriftHold()); err != nil {
		t.Fatalf("second daemon removed the running daemon's drift hold: %v", err)
	}
}

// /run is empty after a reboot: the first start must still write the boot
// record.
func TestBoot_RecordWithoutRunDirectory(t *testing.T) {
	w := newWorld(t)
	if err := os.RemoveAll(filepath.Dir(w.d.p.BootJSON())); err != nil {
		t.Fatal(err)
	}
	w.start()
	eventually(t, 5*time.Second, "serving", func() bool { _, err := ask(w.d.p.AdminSock()); return err == nil })
	if _, err := os.Lstat(w.d.p.BootJSON()); err != nil {
		t.Fatalf("boot record not written on a fresh /run: %v", err)
	}
}

// Containment not shown and the store unreachable: the daemon exits 1 and
// is started again every second, so the stop cannot wait for the store.
func TestBoot_ContainmentFailureStopsBeforeStoreWait(t *testing.T) {
	w := newWorld(t)
	w.nftCheckErr = func(int) error { return nft.ErrAbsent }
	w.nftLoadErr = errors.New("nft -f failed")
	w.d.connect = func(context.Context) (*backend, error) { return nil, errors.New("no store") }
	if code := w.d.serve(context.Background()); code != 1 {
		t.Fatalf("exit %d", code)
	}
	f, dr, st := w.c.index("SetContainmentFailed(true)"), w.c.index("DrainAllRoutes"), w.c.index("StopAllTenants")
	if f < 0 || dr < f || st < dr {
		t.Fatalf("flag %d, drain %d, stop %d before the exit: %q", f, dr, st, w.c.all())
	}
}

// A hold whose mtime lies in the future (clock stepped back, touch -d)
// must not disable the check for longer than holdMax.
func TestDrift_FutureHoldDoesNotSkipForever(t *testing.T) {
	w := driftWorld(t)
	w.nftCheckErr = failFrom(1, nft.ErrDrift)
	hold(t, w, -24*time.Hour)
	w.d.driftTick(context.Background())
	if w.c.index("nftCheck") < 0 {
		t.Fatal("a hold dated a day ahead skipped the check")
	}
}

// A tenant started by a step that passed the gate just before the flag was
// set (adoption or worker) is still stopped by a later failing tick.
func TestDrift_StopsAgainWhileFlagged(t *testing.T) {
	w := driftWorld(t)
	w.nftCheckErr = failFrom(1, nft.ErrAbsent)
	w.d.driftTick(context.Background())
	w.d.driftTick(context.Background())
	if n := w.c.count("StopAllTenants"); n < 2 {
		t.Fatalf("StopAllTenants %d times over two failing ticks; a tenant started in between keeps running", n)
	}
}

// flakyStore fails or stalls ListProjects / TryLockRef on demand.
type flakyStore struct {
	*fakeStore
	listFail  atomic.Int32 // ListProjects calls still to fail
	listStall atomic.Bool  // ListProjects waits for its context
	lockStall atomic.Bool  // TryLockRef waits for its context
}

func (s *flakyStore) ListProjects(ctx context.Context) ([]store.Project, error) {
	if s.listStall.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if s.listFail.Add(-1) >= 0 {
		return nil, errors.New("store unreachable")
	}
	return s.fakeStore.ListProjects(ctx)
}

func (s *flakyStore) TryLockRefChecked(ctx context.Context, ref string) (func(), func(context.Context) error, bool, error) {
	if s.lockStall.Load() {
		<-ctx.Done()
		return nil, nil, false, ctx.Err()
	}
	return s.fakeStore.TryLockRefChecked(ctx, ref)
}

// The refill at a containment failure fails once (store unreachable): the
// project whose tenants were stopped is still adopted after the flag clears.
func TestDrift_RefillFailureIsRetried(t *testing.T) {
	w := driftWorld(t)
	fs := &flakyStore{fakeStore: w.st}
	w.d.st = fs
	fs.listFail.Store(1)
	w.nftCheckErr = func(n int) error {
		if n <= 2 {
			return nft.ErrAbsent
		}
		return nil
	}
	w.d.driftTick(context.Background()) // flag, drain, stop; refill fails
	w.d.driftTick(context.Background()) // clears
	if !(ops{w.d}).ContainmentOK() {
		t.Fatal("flag not cleared")
	}
	w.d.ensureActive(context.Background())
	if w.ag.route(refN(1)) != "active" {
		t.Fatalf("project stopped by the containment failure never re-adopted: %q", w.c.all())
	}
}

// A store that stops answering must not stall the drift tick.
func TestDrift_TickBoundedWhenStoreHangs(t *testing.T) {
	w := driftWorld(t)
	fs := &flakyStore{fakeStore: w.st}
	w.d.st = fs
	fs.listStall.Store(true)
	w.nftCheckErr = failFrom(1, nft.ErrAbsent)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { w.d.driftTick(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("drift tick blocked on the store for 30 s")
	}
}

// A ref lock that cannot be tried (store hung) costs at most the budget.
func TestEnsureActive_TryLockWithinBudget(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.fill()
	fs := &flakyStore{fakeStore: w.st}
	fs.lockStall.Store(true)
	w.d.st = fs
	w.d.budget = 100 * time.Millisecond
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { w.d.ensureActive(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("round blocked on the ref lock past the budget")
	}
}

// refillingAgent completes a containment failure (flag and refill) right
// after an adoption's SetRoute succeeded and before the adoption records
// itself.
type refillingAgent struct {
	*fakeAgent
	d *daemon
}

func (a *refillingAgent) SetRoute(ctx context.Context, ref string, r *routes.Project) (int64, error) {
	g, err := a.fakeAgent.SetRoute(ctx, ref, r)
	if err == nil && r.State == "active" {
		a.fakeAgent.SetContainmentFailed(true)
		a.d.refill(ctx)
	}
	return g, err
}

func TestEnsureActive_RefillDuringAdoptionKeepsPending(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.fill()
	w.d.ag = &refillingAgent{fakeAgent: w.ag, d: w.d}
	w.d.ensureActive(context.Background())
	if !w.d.isPending(refN(1)) {
		t.Fatal("a refill that raced the adoption was undone: the stopped project would never be adopted again")
	}
}

// Adoption never asks for a first boot: a missing state file must stay an
// error, never an initialisation of a live project's data.
func TestBoot_AdoptionNeverFirstBoot(t *testing.T) {
	w := newWorld(t)
	w.st.add(refN(1), "active")
	w.fill()
	var first atomic.Bool
	w.ag.ensureCluster = func(_ context.Context, s agent.Spec) error {
		first.Store(first.Load() || s.FirstBoot)
		return nil
	}
	w.d.ensureActive(context.Background())
	if w.ag.route(refN(1)) != "active" || first.Load() {
		t.Fatalf("adopted %q, FirstBoot set %v", w.ag.route(refN(1)), first.Load())
	}
}

// A hold left by a test never survives a daemon start.
func TestBoot_RemovesDriftHold(t *testing.T) {
	w := newWorld(t)
	hold(t, w, 0)
	w.start()
	eventually(t, 5*time.Second, "serving", func() bool { _, err := ask(w.d.p.AdminSock()); return err == nil })
	if _, err := os.Lstat(w.d.p.DriftHold()); err == nil {
		t.Fatal("drift hold kept across a start")
	}
}
