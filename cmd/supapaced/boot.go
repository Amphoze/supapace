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

	// 2. Platform objects, then the store.
	if err := d.ag.EnsurePlatformNetworks(ctx); err != nil {
		contain("platform networks", err)
	}
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

	// 3. Every route draining before any tenant container is touched.
	if _, err := d.ag.DrainAllRoutes(ctx); err != nil {
		contain("draining the routes", err)
	}

	// 4. The per-boot record, before any container is started.
	d.bootRecord(ctx, nftOK)

	// 5. The node check; on any failure: flag, drain, stop.
	for _, r := range d.ag.NodeCheck(ctx) {
		if !r.OK {
			contain("node check "+r.Name, errors.New(r.Detail))
		}
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

// ensureLoop adopts the pending set: a round at start, then on every signal
// of the drift timer and every retryEvery. One round at a time.
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

// ensureActive runs one round over the pending set, in ref order, at most
// d.slots projects at a time, and returns when each has finished or used
// its budget; it does nothing while the node is not contained. A refill
// that is due comes first. The advisory checks it starts run on.
func (d *daemon) ensureActive(ctx context.Context) {
	if d.ag.ContainmentFailed() {
		return // the gate would refuse every start; the drift timer signals when it clears
	}
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
	slots := make(chan struct{}, d.slots)
	var wg sync.WaitGroup
	for _, ref := range refs {
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
			d.adoptOne(ctx, ref)
		}()
	}
	wg.Wait()
}

// adoptOne is the host-side adoption of one project under its ref lock,
// within its budget: the cluster and PostgREST adopted or started behind
// the gate, with no cluster session, then its route active. The lock is
// only tried: an operation that holds it owns the project, which keeps its
// place in the set and frees the slot at once.
func (d *daemon) adoptOne(ctx context.Context, ref string) {
	gen := d.generation()
	actx, cancel := context.WithTimeout(ctx, d.budget)
	defer cancel()
	unlock, held, ok, err := d.st.TryLockRefChecked(actx, ref)
	if err != nil {
		d.adoptFailed(actx, ref, "ref lock", err)
		return
	}
	if !ok {
		slog.Info("adoption deferred: an operation holds the project", "ref", ref)
		return
	}
	defer unlock()
	p, err := d.st.GetProject(actx, ref)
	if err != nil {
		d.adoptFailed(actx, ref, "reading the project", err)
		return
	}
	if p.State != "active" {
		d.adopted(ref, gen) // its operation brings it forward or tears it down
		slog.Info("adoption: project no longer active", "ref", ref, "state", p.State)
		return
	}
	opsOf, err := d.st.ListOperations(actx, ref)
	if err != nil {
		d.adoptFailed(actx, ref, "reading its operations", err)
		return
	}
	for _, o := range opsOf {
		if o.State == "pending" || o.State == "running" || o.State == "aborting" {
			slog.Info("adoption deferred: an open operation owns the project", "ref", ref, "op", o.ID, "kind", o.Kind)
			return
		}
	}
	spec, err := d.rn.SpecFor(actx, ref)
	if err != nil {
		d.adoptFailed(actx, ref, "desired state", err)
		return
	}
	spec.HealthWait = -1 // host-side only: no cluster session here
	if err := d.ag.EnsureCluster(actx, spec); err != nil {
		d.adoptFailed(actx, ref, "cluster", err)
		return
	}
	if err := d.ag.EnsurePostgREST(actx, spec); err != nil {
		d.adoptFailed(actx, ref, "PostgREST", err)
		return
	}
	// The lock's connection may have died (the server then released the
	// lock and an operation may hold it now): no activation beside it.
	if err := held(actx); err != nil {
		d.adoptFailed(actx, ref, "ref lock lost", err)
		return
	}
	r := d.ag.RouteFor(spec, "active")
	if _, err := d.ag.SetRoute(actx, ref, &r); err != nil {
		d.adoptFailed(actx, ref, "route", err)
		return
	}
	d.adopted(ref, gen)
	slog.Info("adopted", "ref", ref, "generation", spec.Generation)
	d.bg.Add(1)
	go func() {
		defer d.bg.Done()
		d.advisory(ctx, spec)
	}()
}

func (d *daemon) adoptFailed(ctx context.Context, ref, what string, err error) {
	if ctx.Err() != nil {
		err = fmt.Errorf("%w (budget %v)", err, d.budget)
	}
	slog.Error("adoption failed; route stays draining, retried in the background", "ref", ref, "step", what, "err", clean(err))
}

// advisory is the in-cluster check after an adoption: no slot, no lock. It
// waits up to healthWait for a cluster that does not answer yet, then
// reports one check. Its outcome changes no route, no flag and no other
// project.
func (d *daemon) advisory(ctx context.Context, spec agent.Spec) {
	deadline := d.now().Add(d.healthWait)
	for {
		drift, err := d.ag.CheckCluster(ctx, spec)
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

// notReady: the cluster has not answered yet (read so for the advisory
// wait only).
func notReady(err error) bool {
	return errors.Is(err, pgsock.ErrPeer) || errors.Is(err, pgsock.ErrNotSocket) ||
		errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}
