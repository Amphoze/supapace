package backup

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/store"
)

// tickStore is the store as the scheduler's tick reads it.
type tickStore interface {
	ListProjects(context.Context) ([]store.Project, error)
	GetBackupState(context.Context, string) (store.BackupState, error)
	ListOperations(context.Context, string) ([]store.Operation, error)
	LastJob(ctx context.Context, subject, kind string) (store.Job, bool, error)
	SubmitJob(context.Context, store.NewJob) (int64, error)
}

// schedule runs the scheduler's tick until ctx ends.
func (r *Runner) schedule(ctx context.Context) {
	el := &errLog{what: "backup scheduler"}
	for ctx.Err() == nil {
		el.report(r.log, r.tickOnce(ctx))
		sleep(ctx, r.tick)
	}
}

// tickOnce is one tick: while the node's containment is failed, every
// running replicate and fetch job is stopped (interrupted); once an hour the
// hourly work; then, for every subject served, its push. Its store reads are
// a fixed number per subject, whatever the job table retains (the
// replication after a push or a backup is queued when that job is recorded).
// One subject's store error skips that subject; the errors are returned
// together.
func (r *Runner) tickOnce(ctx context.Context) error {
	if r.ag.ContainmentFailed() {
		r.stopKinds("interrupted", "replicate", "fetch")
	}
	if now := r.now(); now.Sub(r.lastHourly) >= bklimit.PruneEvery { // a zero time: the first tick
		r.lastHourly = now
		if err := r.hourly(ctx); err != nil {
			r.log.Error("hourly backup work", "err", clean(err.Error()))
		}
	}
	subs, errs := r.served(ctx)
	for _, s := range subs {
		errs = append(errs, r.schedulePush(ctx, s))
	}
	return errors.Join(errs...)
}

// served lists the subjects the scheduler serves: the control plane once its
// stanza exists, and every layout-2 project that is active — or restarting
// with its restart still open — adopted on this node and whose stanza exists.
//
// A project whose slot a restore holds is restoring and so not among them in
// every store path today; what guarantees that none of its foreign jobs runs
// is the store's pick statement, which admits a slot-held project's jobs
// only for the slot's operation.
func (r *Runner) served(ctx context.Context) ([]subject, []error) {
	var subs []subject
	var errs []error
	if ok, err := r.stanza(ctx, nodecfg.ControlPlaneSubject); err != nil {
		errs = append(errs, err)
	} else if ok {
		disk, repo := nodecfg.CPQuotas(r.cfg, r.p)
		subs = append(subs, subject{name: nodecfg.ControlPlaneSubject, diskMB: disk, repoMB: repo})
	}
	ps, err := r.ts.ListProjects(ctx)
	if err != nil {
		return subs, append(errs, err)
	}
	for _, p := range ps {
		if p.Config.Layout != 2 || !r.pr.Adopted(p.Ref) {
			continue
		}
		switch p.State {
		case "active":
		case "restarting":
			open, err := r.openOp(ctx, p.Ref, "restart")
			if err != nil || !open {
				errs = append(errs, err)
				continue
			}
		default:
			continue
		}
		if ok, err := r.stanza(ctx, p.Ref); err != nil {
			errs = append(errs, err)
		} else if ok {
			subs = append(subs, subject{name: p.Ref, diskMB: p.Config.DiskQuotaMB, repoMB: p.Config.DiskQuotaMB})
		}
	}
	return subs, errs
}

// stanza: the subject has a backup state whose stanza exists.
func (r *Runner) stanza(ctx context.Context, subj string) (bool, error) {
	bs, err := r.ts.GetBackupState(ctx, subj)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil && bs.StanzaCreated, err
}

// openStates are the store's open operation states.
var openStates = []string{"pending", "running", "waiting_job", "aborting"}

// openOp: ref has an open operation of kind.
func (r *Runner) openOp(ctx context.Context, ref, kind string) (bool, error) {
	ops, err := r.ts.ListOperations(ctx, ref)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(ops, func(o store.Operation) bool {
		return o.Kind == kind && slices.Contains(openStates, o.State)
	}), nil
}

func busy(j store.Job) bool { return j.State == "queued" || j.State == "running" }

// schedulePush queues a push when none is queued or running and the last
// was created 60 s ago or more.
func (r *Runner) schedulePush(ctx context.Context, s subject) error {
	last, ok, err := r.ts.LastJob(ctx, s.name, "push")
	if err != nil {
		return err
	}
	if !ok || !busy(last) && r.now().Sub(last.CreatedAt) >= bklimit.PushInterval {
		_, err = r.submit(ctx, s.name, "push", s.diskMB, s.repoMB)
	}
	return err
}

// hourly prunes finished job rows (repeating while a delete removes its
// limit), checks the control plane's use against half of its quotas and the
// repository filesystem's free space against the control plane's unused
// repository quota, and removes the fetch directory of every layout-2
// project with no open restore.
func (r *Runner) hourly(ctx context.Context) error {
	var errs []error
	for {
		n, err := r.st.PruneJobs(ctx, r.now().Add(-bklimit.JobRowAge), bklimit.PruneBatch)
		if err != nil {
			errs = append(errs, err)
		}
		if err != nil || n < bklimit.PruneBatch {
			break
		}
	}
	errs = append(errs, r.cpSpace(ctx), r.removeFetches(ctx))
	return errors.Join(errs...)
}

func (r *Runner) cpSpace(ctx context.Context) error {
	if _, err := r.st.GetBackupState(ctx, nodecfg.ControlPlaneSubject); errors.Is(err, store.ErrNotFound) {
		return nil // no control-plane backups on this node yet
	}
	disk, repo := nodecfg.CPQuotas(r.cfg, r.p)
	q, err := r.ag.QuotaUse(ctx, nodecfg.ControlPlaneUID)
	if err != nil {
		return err
	}
	cp := nodecfg.ControlPlaneSubject
	if q.DiskUsedKB*2 >= int64(disk)*1024 || q.RepoUsedKB*2 >= int64(repo)*1024 {
		if err := r.st.Notice(ctx, cp, "cp-quota-half", fmt.Sprintf("data %d of %d KiB, repository %d of %d KiB",
			q.DiskUsedKB, int64(disk)*1024, q.RepoUsedKB, int64(repo)*1024)); err != nil {
			return err
		}
	}
	_, free, err := r.ag.RepoSpace(ctx)
	if err != nil {
		return err
	}
	if unused := int64(repo) - q.RepoUsedKB/1024; free < unused {
		return r.st.Notice(ctx, cp, "repo-space-low", fmt.Sprintf("%d MiB free, the control plane's repository quota has %d MiB unused", free, unused))
	}
	return nil
}

func (r *Runner) removeFetches(ctx context.Context) error {
	ps, err := r.st.ListProjects(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range ps {
		if p.Config.Layout != 2 || !slices.Contains([]string{"active", "restarting", "restoring"}, p.State) || !r.pr.Adopted(p.Ref) {
			continue
		}
		open, err := r.openOp(ctx, p.Ref, "restore")
		if err != nil || open {
			errs = append(errs, err)
			continue
		}
		sp, err := r.pr.SpecFor(ctx, p.Ref)
		if err == nil {
			err = r.ag.RemoveFetch(ctx, sp)
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
