package backup

import (
	"context"
	"errors"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/store"
)

// laneOf is a kind's lane, the one place the runner decides it: push and
// replicate in the push lane, every other kind in the backup lane.
func laneOf(kind string) string {
	if kind == "push" || kind == "replicate" {
		return "push"
	}
	return "backup"
}

// lane is one worker of lane: it takes a turn, and after a turn that picked
// nothing it pauses before the next. Backup-lane picks are delayed by a
// random 0–2 s.
func (r *Runner) lane(ctx context.Context, lane string) {
	el := &errLog{what: lane + " lane"}
	for ctx.Err() == nil {
		if lane == "backup" {
			sleep(ctx, r.pickDelay())
		}
		if !r.turn(ctx, lane, el) {
			sleep(ctx, r.idle)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// turn picks one job of lane and runs it to its record. It picks nothing
// while the node's containment is failed. "Nothing picked" — an empty lane,
// or a clash with the other lane's pick of the same subject — is answered
// false: the caller asks again on its next turn, never in a loop.
func (r *Runner) turn(ctx context.Context, lane string, el *errLog) bool {
	if r.ag.ContainmentFailed() {
		return false
	}
	j, ok, err := r.st.NextJob(ctx, lane)
	el.report(r.log, err)
	if !ok {
		return false
	}
	r.run(ctx, j)
	return true
}

// run takes a picked job to its record. A job stopped by Cancel or by
// containment is recorded with that code whatever it left. When ctx ends
// (the daemon stops) without such a stop, nothing is recorded: the job stays
// running until the next Start interrupts it.
func (r *Runner) run(ctx context.Context, j store.Job) {
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	r.mu.Lock()
	a := r.entry(j.ID)
	a.kind, a.cancel = j.Kind, cancel
	stopped := a.code != ""
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.active, j.ID)
		r.mu.Unlock()
		close(a.done)
	}()
	var out outcome
	if !stopped {
		out = r.execute(jctx, j)
	}
	r.mu.Lock()
	code := a.code
	r.mu.Unlock()
	if code != "" {
		out = failed(code, "the job was stopped: "+code)
	} else if ctx.Err() != nil {
		return
	}
	if out.state == "failed" && out.code == "" {
		out.code = "internal" // the store takes no failure without a code
	}
	r.finish(ctx, j, out)
	if out.state == "failed" {
		r.log.Warn("backup job failed", "job", j.ID, "subject", j.Subject, "kind", j.Kind, "code", out.code, "message", clean(out.msg))
	}
}

// finish records the job's end. A failed record is tried again — after
// retry, doubling up to 30 s — until it is written, the store answers that
// the job is not running (conflict, not found), or the daemon stops: a row
// left running holds its subject's slot until the next Start.
func (r *Runner) finish(ctx context.Context, j store.Job, out outcome) {
	for delay := r.retry; ; delay = min(2*delay, 30*time.Second) {
		err := r.st.FinishJob(context.WithoutCancel(ctx), j.ID, out.state, out.code, clean(out.msg), out.result)
		if err == nil || errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			return
		}
		r.log.Error("recording a backup job", "job", j.ID, "subject", j.Subject, "kind", j.Kind, "err", clean(err.Error()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// clean is a text from a job or from a refusal, as the store keeps it.
func clean(s string) string { return pgsock.Sanitize(s, 256) }

// execute checks a picked job, launches it and records what its end says.
func (r *Runner) execute(ctx context.Context, j store.Job) outcome {
	ok, err := r.admit(ctx, j)
	if err != nil {
		return failed("interrupted", "the pick-time check could not read the store: "+err.Error())
	}
	if !ok {
		return failed("cancelled", "the job's project or operation no longer takes it")
	}
	if (j.Kind == "replicate" || j.Kind == "fetch") && r.ag.ContainmentFailed() {
		return failed("interrupted", "the node's containment is not proven")
	}
	if j.Kind == "replicate" && r.Offsite() != "declared" {
		return outcome{state: "done", result: []byte(`{"ok":true,"skipped":"undeclared"}`)}
	}
	s, err := r.subjectOf(ctx, j.Subject)
	if err != nil {
		return failed("internal", err.Error())
	}
	if j.Kind == "recover" {
		return r.recoverJob(ctx, j, s)
	}
	spec, err := r.jobSpec(ctx, j, s)
	if err != nil {
		return specFailure(err)
	}
	res, err := r.ag.RunJob(ctx, spec)
	return r.record(ctx, j, s, res, err)
}

// admit is the pick-time check, one function of the job row: a job no
// operation owns runs only for an active or restarting project adopted on
// this node (the control plane is exempt); an operation's job only while
// that operation waits for it.
func (r *Runner) admit(ctx context.Context, j store.Job) (bool, error) {
	if j.OpID != 0 {
		op, err := r.st.GetOperation(ctx, j.OpID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return err == nil && op.State == "waiting_job", err
	}
	if j.Subject == nodecfg.ControlPlaneSubject {
		return true, nil
	}
	p, err := r.st.GetProject(ctx, j.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return (p.State == "active" || p.State == "restarting") && r.pr.Adopted(j.Subject), nil
}
