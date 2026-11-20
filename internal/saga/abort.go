package saga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Amphoze/supapace/internal/store"
)

// The compensation list of an aborted create, always whole and in this
// order, whichever step failed: each entry is idempotent and a no-op when
// its object is absent. Keys die (C4) before the render tree (C5) and the
// directory purge (C6).
var compensation = []step{
	{id: "C0", do: (*job).cancelJobs},
	{id: "C1", do: func(x *job, ctx context.Context) error { _, err := x.r.ag.SetRoute(ctx, x.op.Ref, nil); return err }},
	{id: "C2", do: func(x *job, ctx context.Context) error { return x.r.ag.StopPostgREST(ctx, x.op.Ref) }},
	{id: "C3", do: func(x *job, ctx context.Context) error { return x.r.ag.StopCluster(ctx, x.op.Ref) }},
	{id: "C4", do: func(x *job, ctx context.Context) error { return x.r.st.DestroyKeys(ctx, x.op.Ref) }},
	{id: "C5", do: func(x *job, ctx context.Context) error { return x.r.ag.RemoveRender(ctx, x.op.Ref) }},
	{id: "C6", do: func(x *job, ctx context.Context) error {
		if err := x.r.ag.RemoveNetwork(ctx, x.op.Ref); err != nil {
			return err
		}
		if err := x.purgeDir(ctx); err != nil {
			return err
		}
		return x.purgeRepo(ctx)
	}},
	{id: "C7", do: func(x *job, ctx context.Context) error { return x.r.st.MarkAborted(ctx, x.op.Ref) }},
}

// C0: a layout-2 create's queued jobs cancelled and its running one ended
// before anything is removed (a layout-1 project has no job).
func (x *job) cancelJobs(ctx context.Context) error {
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil || p.Config.Layout != 2 {
		return err
	}
	jobs, err := x.jobRunner()
	if err != nil {
		return err
	}
	return jobs.Cancel(ctx, x.op.ID)
}

// compensate runs the whole list for an aborting create, under the ref lock
// the attempt holds, and ends it aborted with lastError. A failing entry
// leaves it aborting, backed off (the next run starts again at C1); after the
// eighth failed run it is parked failed until `project abort` re-arms it.
// The first run marks the create's parameters: from then on it never goes
// forward again. Before each entry and each write it checks the lock is
// still held; a lost lock ends the run with nothing more done.
func (x *job) compensate(ctx context.Context, lastError string) {
	r, op := x.r, x.op
	if x.record(ctx) != nil {
		return
	}
	if !compensating(op.Params) {
		if err := r.patchParams(ctx, &x.op, "compensating", true); err != nil {
			r.log.Error("marking a create compensating", "op", op.ID, "ref", op.Ref, "err", r.text(err))
			return
		}
	}
	actx, cancel := context.WithTimeout(ctx, r.attemptDeadline)
	defer cancel()
	for _, c := range compensation {
		hitFailpoint(r.p, op.Kind+":"+c.id)
		if x.record(ctx) != nil {
			return
		}
		sctx, scancel := context.WithTimeout(actx, r.stepDeadline)
		err := c.do(x, sctx)
		scancel()
		if err != nil {
			if ctx.Err() == nil && x.record(ctx) == nil {
				x.compensationFailed(ctx, c.id, err)
			}
			return
		}
	}
	if x.record(ctx) != nil {
		return
	}
	if err := r.st.FinishOperation(ctx, op.ID, "aborted", lastError); err != nil {
		r.log.Error("finishing an abort", "op", op.ID, "ref", op.Ref, "err", r.text(err))
		return
	}
	x.finished("aborted")
}

// compensating reports whether a create's compensation has started.
func compensating(params json.RawMessage) bool {
	var p struct {
		Compensating bool `json:"compensating"`
	}
	json.Unmarshal(params, &p)
	return p.Compensating
}

// resumeCompensation takes a create whose compensation has started but which
// is queued to go forward (a retried parked abort) back to aborting, and
// compensates.
func (x *job) resumeCompensation(ctx context.Context) {
	r := x.r
	if _, err := requestAbort(r.st, ctx, x.op.Ref); err != nil {
		// It must not go forward, nor be picked again at once: the attempt is
		// started so that it can be ended or backed off.
		r.log.Error("resuming a compensation", "op", x.op.ID, "ref", x.op.Ref, "err", r.text(err))
		if r.st.StartOperation(ctx, x.op.ID) != nil || x.record(ctx) != nil {
			return
		}
		x.op.Attempts++
		if errors.Is(err, store.ErrConflict) {
			// The project left provisioning: its compensation went as far as
			// releasing it (C7) before the finish was recorded.
			state := "unknown"
			if p, perr := r.st.GetProject(ctx, x.op.Ref); perr == nil {
				state = p.State
			}
			x.finishFailed(ctx, final("conflict", fmt.Errorf("its compensation has run and the project is %s; nothing is left to undo", state)))
			return
		}
		if err := r.st.FailAttempt(ctx, x.op.ID, r.lastError(err), time.Now().Add(r.backoffAfter(x.op.Attempts))); err != nil {
			r.log.Error("backing off a compensation", "op", x.op.ID, "ref", x.op.Ref, "err", r.text(err))
		}
		return
	}
	cur, err := r.st.GetOperation(ctx, x.op.ID)
	if err != nil || cur.State != "aborting" {
		return
	}
	x.op = cur
	x.compensate(ctx, "")
}

func (x *job) compensationFailed(ctx context.Context, id string, err error) {
	r, op := x.r, x.op
	msg := r.lastError(err)
	r.log.Warn("compensation failed", "op", op.ID, "ref", op.Ref, "entry", id, "run", op.Attempts+1, "err", msg)
	if err := r.st.FailAttempt(ctx, op.ID, msg, time.Now().Add(r.backoffAfter(op.Attempts+1))); err != nil {
		r.log.Error("recording a failed compensation", "op", op.ID, "ref", op.Ref, "err", r.text(err))
		return
	}
	cur, err := r.st.GetOperation(ctx, op.ID)
	if err != nil || cur.State != "aborting" || cur.Attempts < maxCompensationRuns {
		return
	}
	if err := r.st.ParkAbort(ctx, op.ID, msg); err != nil {
		r.log.Error("parking an abort", "op", op.ID, "ref", op.Ref, "err", r.text(err))
		return
	}
	r.log.Warn("abort parked failed; `project abort` re-arms it", "op", op.ID, "ref", op.Ref)
	x.op = cur
	x.finished("failed")
}

// requestAbort is store.RequestAbort; tests replace it to make it fail.
var requestAbort = (*store.Store).RequestAbort

// purgeRepo (abort C6, every layout): the project's repository directories
// emptied and removed and both quotas cleared — the cluster, PostgREST and
// the create's jobs are gone by then (C0, C2, C3) — then the off-site
// objects recorded as owed a purge. A project never placed has nothing.
func (x *job) purgeRepo(ctx context.Context) error {
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil || p.UID == nil {
		return err
	}
	s, err := bareSpec(p, x.op.Epoch, p.Generation, p.Config)
	if err != nil {
		return err
	}
	if err := x.r.ag.PurgeRepo(ctx, s); err != nil {
		return err
	}
	if err := x.r.st.SetOffsitePurge(ctx, x.op.Ref); !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}
