package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// boot runs the start-up steps that precede the admin socket. A daemon
// start adopts: it stops tenants only when containment cannot be shown, and
// then in the order flag, drain, stop, at once, before any step that can
// fail or wait. ok is false when the daemon cannot serve (no store) or ctx
// ended; everything else is logged and served.
func (d *daemon) boot(ctx context.Context) (nftOK, ok bool) {
	// 1. Our tables, before anything is touched. The hold file of a test
	// never survives a start.
	if err := os.Remove(d.p.DriftHold()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error("boot: removing the drift hold", "err", clean(err))
	}
	failed := false
	contain := func(why string, err error) {
		if ctx.Err() != nil {
			return // a signal, not a finding
		}
		slog.Error("boot: containment not shown: "+why, "err", clean(err))
		if failed {
			return
		}
		failed = true
		d.ag.SetContainmentFailed(true)
		if _, err := d.ag.DrainAllRoutes(ctx); err != nil {
			slog.Error("boot: draining routes", "err", clean(err))
		}
		if err := d.ag.StopAllTenants(ctx); err != nil {
			slog.Error("boot: stopping tenants", "err", clean(err))
		}
	}
	if err := d.ensureRules(ctx); err != nil {
		contain("firewall tables", err)
	} else {
		nftOK = true
	}

	// 2. The platform networks; the per-boot record, before any container is
	// started; the node check, which needs nothing the steps after it create
	// (its rows read the firewall, Docker, the networks above, the host and
	// the key; the platform services' rows do not block), so a failing row
	// stops the tenants even when the store never comes up.
	if err := d.ag.EnsurePlatformNetworks(ctx); err != nil {
		contain("platform networks", err)
	}
	d.bootRecord(ctx, nftOK)
	// A node whose dashboard is not configured keeps none of the dashboard's
	// containers: the node check's member rows refuse them.
	if r, ok := d.ag.(interface{ RemoveDashboard(context.Context) error }); ok {
		if err := r.RemoveDashboard(ctx); err != nil {
			slog.Error("boot: removing the dashboard's containers", "err", clean(err))
		}
	}
	for _, r := range d.ag.NodeCheck(ctx) {
		if agent.Blocking(r) {
			contain("node check "+r.Name, errors.New(r.Detail))
		}
	}

	// 3. The image files, the control-plane database and the store.
	if err := d.ag.EnsureImageFiles(ctx); err != nil {
		slog.Error("serve: image files", "err", clean(err))
		return nftOK, false
	}
	if err := d.ag.EnsureControlPlaneDB(ctx); err != nil {
		slog.Error("serve: control-plane database", "err", clean(err))
		return nftOK, false
	}
	be, err := d.connect(ctx)
	if err != nil {
		slog.Error("serve: control-plane store", "err", clean(err))
		return nftOK, false
	}
	d.be, d.st, d.rn = be, be.st, be.rn

	// 4. Every route draining before any tenant container is touched.
	if _, err := d.ag.DrainAllRoutes(ctx); err != nil {
		contain("draining the routes", err)
	}
	if ctx.Err() != nil {
		d.close()
		return nftOK, false
	}

	// Every active project is pending adoption before the socket accepts;
	// until a listing succeeds, every project counts as pending.
	d.markRefill()
	rctx, cancel := context.WithTimeout(ctx, refillMax)
	defer cancel()
	if err := d.refill(rctx); err != nil {
		slog.Error("boot: listing projects; retried by the adoption loop", "err", clean(err))
	}
	return nftOK, true
}

// ensureRules renders the ruleset; when the installed file differs (a newer
// binary) it is rewritten and loaded. Then bridge-nf off and the check; on
// failure one load and the check again.
func (d *daemon) ensureRules(ctx context.Context) error {
	want, err := d.nftRender()
	if err != nil {
		return err
	}
	if have, err := os.ReadFile(d.p.NftFile()); err != nil || !bytes.Equal(have, want) {
		slog.Info("boot: rules file differs from this binary's ruleset; writing and loading it")
		f := d.p.NftFile()
		if err := nodefs.WriteFile(d.p, filepath.Dir(f), filepath.Base(f), want, 0o600, os.Geteuid(), os.Getegid()); err != nil {
			return err
		}
		if err := d.nftLoad(ctx); err != nil {
			return err
		}
	}
	if err := d.bridgeNF(); err != nil {
		slog.Warn("boot: bridge-nf switches", "err", clean(err))
	}
	if err := d.nftCheck(ctx); err != nil {
		slog.Warn("boot: firewall check failed; loading the tables", "err", clean(err))
		if err := d.nftLoad(ctx); err != nil {
			return err
		}
		return d.nftCheck(ctx)
	}
	return nil
}

// bootRecord writes boot.json once per boot: only when it is absent (/run is
// fresh at every boot), listing the tenant containers found running.
func (d *daemon) bootRecord(ctx context.Context, nftOK bool) {
	path := d.p.BootJSON()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		return
	}
	names, err := d.listTenants(ctx)
	if err != nil {
		slog.Error("boot: listing running tenants; boot record not written", "err", clean(err))
		return
	}
	slices.Sort(names)
	b, err := json.Marshal(struct {
		StartedAt time.Time `json:"started_at"`
		NftOK     bool      `json:"nft_ok"`
		Tenants   []string  `json:"tenants_running_at_start"`
	}{d.now().UTC(), nftOK, append([]string{}, names...)})
	if err == nil {
		err = writeOnce(path, append(b, '\n'))
	}
	if err != nil {
		slog.Error("boot: boot record", "err", clean(err))
		return
	}
	slog.Info("boot record written", "tenants_running", len(names))
}

// writeOnce creates path with data, mode 0600, complete or not at all; an
// existing path is left alone.
func writeOnce(path string, data []byte) error {
	tmp := path + ".tmp"
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Link(tmp, path)
	}
	os.Remove(tmp)
	return err
}

// ───────── adoption ─────────

// refillMax bounds one listing of the projects for the pending set.
const refillMax = 5 * time.Second

// markRefill records that the pending set must be filled again (boot, a
// containment failure): until a refill succeeds every project counts as
// pending, and an adoption that started before it cannot remove its ref.
func (d *daemon) markRefill() {
	d.mu.Lock()
	d.refillDue = true
	d.gen++
	d.mu.Unlock()
}

// refill puts every active project in the pending-adoption set.
func (d *daemon) refill(ctx context.Context) error {
	ps, err := d.st.ListProjects(ctx)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range ps {
		if p.State == "active" {
			d.pending[p.Ref] = true
		}
	}
	d.refillDue = false
	d.gen++
	return nil
}

func (d *daemon) isPending(ref string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pending[ref] || d.refillDue
}

// generation is the pending set's refill count, read when an adoption starts.
func (d *daemon) generation() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gen
}

// adopted removes ref from the set, unless a refill happened (or is due)
// since the adoption started at gen: the refill's verdict stands.
func (d *daemon) adopted(ref string, gen uint64) {
	d.mu.Lock()
	if d.gen == gen && !d.refillDue {
		delete(d.pending, ref)
	}
	d.mu.Unlock()
}

// signalEnsure asks the ensure loop for a round now, never waiting.
func (d *daemon) signalEnsure() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// ensureLoop runs the rounds: one at start, then on every signal of the
// drift timer and every retryEvery. One round at a time.
func (d *daemon) ensureLoop(ctx context.Context) {
	for {
		d.ensureActive(ctx)
		select {
		case <-ctx.Done():
			return
		case <-d.wake:
		case <-time.After(d.retryEvery):
		}
	}
}

// ensureActive runs one round; it does nothing while the node is not
// contained. The control-plane database and the gateway are ensured first
// (a healthy one is left untouched). Then, in ref order, at most d.slots
// projects at a time, each within its budget: the pending set (a refill
// that is due comes first), then every other active project one of whose
// containers is not running or whose route a failed repair drained. It
// returns when each has finished or used its budget; the advisory checks it
// starts run on. An honoured drift hold (see hold) pauses the project
// repairs, not the platform ensures or the pending adoptions.
func (d *daemon) ensureActive(ctx context.Context) {
	if d.ag.ContainmentFailed() {
		return // the gate would refuse every start; the drift timer signals when it clears
	}
	running, lerr := d.runningNames(ctx, "supapace.role")
	if lerr != nil {
		slog.Warn("repair: listing containers; only pending projects this round", "err", clean(lerr))
	}
	d.ensurePlatform(ctx, running)
	d.mu.Lock()
	due := d.refillDue
	d.mu.Unlock()
	if due {
		rctx, cancel := context.WithTimeout(ctx, refillMax)
		err := d.refill(rctx)
		cancel()
		if err != nil {
			slog.Error("adoption: listing projects; retried at the next round", "err", clean(err))
			return
		}
	}
	d.mu.Lock()
	refs := make([]string, 0, len(d.pending))
	for r := range d.pending {
		refs = append(refs, r)
	}
	d.mu.Unlock()
	slices.Sort(refs)
	npending := len(refs)
	if honoured, age, _ := d.hold(); lerr == nil && honoured {
		slog.Info(fmt.Sprintf("repair: drift hold present (age %ds); project repairs paused this round", int64(age/time.Second)))
	} else if lerr == nil {
		refs = append(refs, d.repairs(ctx, running)...)
	}
	slots := make(chan struct{}, d.slots)
	var wg sync.WaitGroup
	for i, ref := range refs {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			d.adoptOne(ctx, ref, i >= npending)
		}()
	}
	wg.Wait()
}

// runningNames lists the containers carrying label (a key, or key=value):
// name → running.
func (d *daemon) runningNames(ctx context.Context, label string) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, refillMax)
	defer cancel()
	cs, err := d.containers(ctx, label)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(cs))
	for _, c := range cs {
		m[c.Name] = c.Running
	}
	return m, nil
}

// Names of the platform's own containers and of a project's.
const (
	cpContainer      = "sp-cp-db"
	gatewayContainer = "sp-gateway"
)

func clusterOf(ref string) string   { return "pg-" + ref }
func postgrestOf(ref string) string { return "postgrest-" + ref }

// ensurePlatform ensures the control-plane database and the gateway, each
// within the budget; running is the round's listing (nil when it failed).
func (d *daemon) ensurePlatform(ctx context.Context, running map[string]bool) {
	for _, p := range []struct {
		name   string
		ensure func(context.Context) error
	}{{cpContainer, d.ag.EnsureControlPlaneDB}, {gatewayContainer, d.ag.EnsureGateway}} {
		pctx, cancel := context.WithTimeout(ctx, d.budget)
		err := p.ensure(pctx)
		cancel()
		switch {
		case err != nil:
			slog.Warn("repair: ensure failed; retried at the next round", "container", p.name, "err", clean(err))
		case running != nil && !running[p.name]:
			slog.Info("repair: started", "container", p.name)
		}
	}
}

// repairs lists, in ref order, the active projects outside the pending set
// that need the host-side ensure: a container not running (or absent), or a
// route that a failed repair drained. A healthy project costs nothing here.
func (d *daemon) repairs(ctx context.Context, running map[string]bool) []string {
	rctx, cancel := context.WithTimeout(ctx, refillMax)
	ps, err := d.st.ListProjects(rctx)
	cancel()
	if err != nil {
		slog.Warn("repair: listing projects; retried at the next round", "err", clean(err))
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var refs []string
	for _, p := range ps {
		if p.State == "active" && !d.pending[p.Ref] && !d.refillDue &&
			(!running[clusterOf(p.Ref)] || !running[postgrestOf(p.Ref)] || d.drained[p.Ref]) {
			refs = append(refs, p.Ref)
		}
	}
	slices.Sort(refs)
	return refs
}

func (d *daemon) setDrained(ref string, v bool) {
	d.mu.Lock()
	if v {
		d.drained[ref] = true
	} else {
		delete(d.drained, ref)
	}
	d.mu.Unlock()
}

func (d *daemon) isDrained(ref string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.drained[ref]
}

// adoptOne is the host-side ensure of one project under its ref lock,
// within its budget: the cluster and PostgREST adopted or started behind
// the gate, with no cluster session, then its route active. The lock is
// only tried: an operation that holds it owns the project, which keeps its
// place and frees the slot at once.
//
// A pending project leaves the set on success. A repair (an adopted project
// whose container is down) never enters the set: on success its route is
// left as it is unless a failed repair drained it; on failure it is logged at
// WARN and its route drained, so requests answer the defined 503 instead of
// waiting for an upstream that is down.
func (d *daemon) adoptOne(ctx context.Context, ref string, repair bool) {
	gen := d.generation()
	actx, cancel := context.WithTimeout(ctx, d.budget)
	defer cancel()
	var spec *agent.Spec // set once known: a failed repair drains its route
	fail := func(what string, err error) {
		if actx.Err() != nil {
			err = fmt.Errorf("%w (budget %v)", err, d.budget)
		}
		if !repair {
			slog.Error("adoption failed; route stays draining, retried in the background", "ref", ref, "step", what, "err", clean(err))
			return
		}
		if what == "ref lock lost" { // without the lock an operation may own the project: no route write
			slog.Warn("repair failed; retried at the next round", "ref", ref, "step", what, "err", clean(err))
			return
		}
		slog.Warn("repair failed; route draining, retried at the next round", "ref", ref, "step", what, "err", clean(err))
		if spec != nil && !d.isDrained(ref) {
			sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), refillMax)
			r := d.ag.RouteFor(*spec, "draining")
			if _, err := d.ag.SetRoute(sctx, ref, &r); err != nil {
				slog.Error("repair: draining the route", "ref", ref, "err", clean(err))
			} else {
				d.setDrained(ref, true)
			}
			scancel()
		}
	}
	unlock, held, ok, err := d.st.TryLockRefChecked(actx, ref)
	if err != nil {
		fail("ref lock", err)
		return
	}
	if !ok {
		slog.Info("adoption deferred: an operation holds the project", "ref", ref)
		return
	}
	defer unlock()
	p, err := d.st.GetProject(actx, ref)
	if err != nil {
		fail("reading the project", err)
		return
	}
	if p.State != "active" {
		d.setDrained(ref, false)
		if !repair {
			d.adopted(ref, gen) // its operation brings it forward or tears it down
			slog.Info("adoption: project no longer active", "ref", ref, "state", p.State)
		}
		return
	}
	opsOf, err := d.st.ListOperations(actx, ref)
	if err != nil {
		fail("reading its operations", err)
		return
	}
	for _, o := range opsOf {
		if o.State == "pending" || o.State == "running" || o.State == "aborting" {
			slog.Info("adoption deferred: an open operation owns the project", "ref", ref, "op", o.ID, "kind", o.Kind)
			return
		}
	}
	s, err := d.rn.SpecFor(actx, ref)
	if err != nil {
		fail("desired state", err)
		return
	}
	spec = &s
	s.HealthWait = -1 // host-side only: no cluster session here
	// What is down now, under the lock (for the log line only).
	running, lerr := d.runningNames(actx, "supapace.ref="+ref)
	var down []string
	for _, n := range []string{clusterOf(ref), postgrestOf(ref)} {
		if lerr == nil && !running[n] {
			down = append(down, n)
		}
	}
	drained := d.isDrained(ref)
	if err := d.ag.EnsureCluster(actx, s); err != nil {
		fail("cluster", err)
		return
	}
	if err := d.ag.EnsurePostgREST(actx, s); err != nil {
		fail("PostgREST", err)
		return
	}
	// The lock's connection may have died (the server then released the
	// lock and an operation may hold it now): no activation beside it.
	if err := held(actx); err != nil {
		fail("ref lock lost", err)
		return
	}
	if !repair || drained {
		r := d.ag.RouteFor(s, "active")
		if _, err := d.ag.SetRoute(actx, ref, &r); err != nil {
			fail("route", err)
			return
		}
		d.setDrained(ref, false)
	}
	if len(down) > 0 {
		slog.Info("repair: started", "ref", ref, "containers", strings.Join(down, ","))
	}
	if !repair {
		d.adopted(ref, gen)
		slog.Info("adopted", "ref", ref, "generation", s.Generation)
	} else if !slices.Contains(down, clusterOf(ref)) {
		return // the cluster ran on: nothing to check
	}
	d.bg.Add(1)
	go func() {
		defer d.bg.Done()
		d.advisory(ctx, s)
	}()
}

// advisory is the in-cluster check after an adoption or a repair that
// started the cluster: no slot, no lock. It waits up to healthWait for a
// cluster that does not answer yet, then reports one check. A cluster
// container that is not running (it exited after its start) ends the wait
// with a WARN at once; the next round starts it again. Its outcome changes
// no route, no flag and no other project.
func (d *daemon) advisory(ctx context.Context, spec agent.Spec) {
	deadline := d.now().Add(d.healthWait)
	for {
		drift, err := d.ag.CheckCluster(ctx, spec)
		if err != nil && ctx.Err() == nil {
			if running, lerr := d.runningNames(ctx, "supapace.ref="+spec.Ref); lerr == nil && !running[clusterOf(spec.Ref)] {
				slog.Warn("advisory cluster check: the cluster container is not running (it exited after its start); the next round starts it again",
					"ref", spec.Ref, "err", clean(err))
				return
			}
		}
		if err == nil || !notReady(err) || !d.now().Before(deadline) || ctx.Err() != nil {
			for _, f := range drift {
				if !f.OK {
					slog.Warn("cluster drift", "ref", spec.Ref, "check", pgsock.Sanitize(f.Name, 64), "detail", pgsock.Sanitize(f.Detail, 256))
				}
			}
			if err != nil {
				slog.Warn("advisory cluster check failed", "ref", spec.Ref, "err", clean(err))
			} else {
				slog.Info("advisory cluster check passed", "ref", spec.Ref, "drift", len(drift))
			}
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(d.checkEvery):
		}
	}
}

// notReady: the cluster has not answered yet (read so for the advisory wait
// only): the peer is not the recorded process yet, the socket is absent, the
// connect itself failed (nothing listens on the socket yet, or a stale one
// is left from before the start), or the server answers that it is still
// starting up (57P03). A connect that ran out of time is a budget error, not
// ErrConnect.
func notReady(err error) bool {
	var se *pgsock.ServerError
	return errors.Is(err, pgsock.ErrPeer) || errors.Is(err, pgsock.ErrNotSocket) || errors.Is(err, pgsock.ErrConnect) ||
		errors.As(err, &se) && se.Code == "57P03"
}
