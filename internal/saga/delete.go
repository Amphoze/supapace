package saga

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/store"
)

// Delete steps: the route goes first, nothing may route to a container that
// is going away; the slice index stays allocated until the purge. At layout 2
// the project's jobs are cancelled with the route (D1), and three best-effort
// job steps take a final backup while the cluster runs (Db), then push the
// stopped cluster's spool (Dp) and replicate (Dr): each outcome is written
// into the operation's result and none fails the delete. The data directory
// and the repository stay until the purge.
var deleteSteps = []step{
	{"D1", (*job).unroute},
	{"D2", func(x *job, ctx context.Context) error { return x.r.ag.StopPostgREST(ctx, x.op.Ref) }},
	{"Db", func(x *job, ctx context.Context) error { return x.finalJob(ctx, "final_backup", x.finalBackup) }},
	{"D3", func(x *job, ctx context.Context) error { return x.r.ag.StopCluster(ctx, x.op.Ref) }},
	{"Dp", func(x *job, ctx context.Context) error { return x.finalJob(ctx, "final_push", x.finalPush) }},
	{"Dr", func(x *job, ctx context.Context) error {
		return x.finalJob(ctx, "final_replication", x.finalReplication)
	}},
	{"D4", func(x *job, ctx context.Context) error { return x.r.ag.RemoveNetwork(ctx, x.op.Ref) }},
	{"D5", (*job).markDeleted},
}

// deleteLayout2 are the delete steps of a layout-2 project only.
var deleteLayout2 = map[string]bool{"Db": true, "Dp": true, "Dr": true}

// D1: deleting (from then on the job runner queues nothing for the project
// and runs none of its jobs that no operation owns), the project's jobs
// cancelled and its running one stopped, the route removed, the gateway at
// that route file. A restoring project is accepted: a delete may follow a
// failed restore.
func (x *job) unroute(ctx context.Context) error {
	if err := x.r.st.SetProjectState(ctx, x.op.Ref, "deleting"); err != nil {
		return err
	}
	if err := x.cancelSubject(ctx); err != nil {
		return err
	}
	gen, err := x.r.ag.SetRoute(ctx, x.op.Ref, nil)
	if err != nil {
		return err
	}
	return x.r.waitGateway(ctx, gen)
}

// cancelSubject (delete D1, purge P1 and P4): a layout-2 project's queued
// jobs cancelled and its running one stopped; a layout-1 project has none.
func (x *job) cancelSubject(ctx context.Context) error {
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil || p.Config.Layout != 2 {
		return err
	}
	jobs, err := x.jobRunner()
	if err != nil {
		return err
	}
	return jobs.CancelSubject(ctx, x.op.Ref)
}

// finalJob runs one best-effort job step and records its outcome under key
// in the result: ok, skipped (no stanza; for Dr, no declared store), or the
// code of the job that failed — interrupted_limit and a push loop at its
// bound ("incomplete") among them. An interrupted job is submitted again; a
// step error that is not a job's (the store) is the step's.
func (x *job) finalJob(ctx context.Context, key string, run func(context.Context, store.Job, bool) (string, error)) error {
	bs, err := x.r.st.GetBackupState(ctx, x.op.Ref)
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && !bs.StanzaCreated:
		return x.recordOutcome(ctx, key, "skipped")
	case err != nil:
		return err
	}
	j, ok, err := x.latestJob(ctx)
	switch {
	case isFinal(err):
		return x.recordOutcome(ctx, key, code(err))
	case err != nil:
		return err
	case ok && j.State == "failed" && j.Code != "interrupted":
		return x.recordOutcome(ctx, key, j.Code)
	}
	out, err := run(ctx, j, ok && j.State == "done")
	var pk *parked
	switch {
	case errors.As(err, &pk):
		return err
	case isFinal(err):
		return x.recordOutcome(ctx, key, code(err))
	case err != nil:
		return err
	}
	return x.recordOutcome(ctx, key, out)
}

// Db: one full backup while the cluster still runs.
func (x *job) finalBackup(ctx context.Context, _ store.Job, done bool) (string, error) {
	if done {
		return "ok", nil
	}
	return "", x.submit(ctx, "backup")
}

// Dp: push jobs until one reports the spool empty, at most
// bklimit.PushLoopMax of them.
func (x *job) finalPush(ctx context.Context, j store.Job, done bool) (string, error) {
	if done {
		var res struct {
			Complete bool `json:"complete"`
		}
		if json.Unmarshal(j.Result, &res) == nil && res.Complete {
			return "ok", nil
		}
	}
	n, err := x.r.st.CountJobs(ctx, x.op.ID, x.step, jobFloor(x.op.Params))
	if err != nil {
		return "", err
	}
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil {
		return "", err
	}
	if n >= bklimit.PushLoopMax(p.Config.DiskQuotaMB) {
		return "incomplete", nil
	}
	return "", x.submit(ctx, "push")
}

// Dr: the replicate step's loop, with the off-site store declared.
func (x *job) finalReplication(ctx context.Context, _ store.Job, _ bool) (string, error) {
	jobs, err := x.jobRunner()
	if err != nil {
		return "", err
	}
	if jobs.Offsite() != "declared" {
		return "skipped", nil
	}
	return "ok", x.replicate(ctx)
}

// recordOutcome writes one member of the operation's result document.
func (x *job) recordOutcome(ctx context.Context, key, outcome string) error {
	m := map[string]json.RawMessage{}
	if len(x.op.Result) > 0 {
		if err := json.Unmarshal(x.op.Result, &m); err != nil {
			return err
		}
	}
	m[key], _ = json.Marshal(outcome)
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := x.r.st.SetOperationResult(ctx, x.op.ID, b); err != nil {
		return err
	}
	x.op.Result = b
	if outcome != "ok" && outcome != "skipped" {
		x.r.log.Warn("final job of a delete not done", "op", x.op.ID, "ref", x.op.Ref, "step", x.step, "outcome", outcome)
	}
	return nil
}

// D5: deleted, with the purge queued at now + retention (idempotent: a
// resumed step gets the same purge operation back).
func (x *job) markDeleted(ctx context.Context) error {
	retention, err := time.ParseDuration(x.r.cfg.Retention)
	if err != nil {
		return err
	}
	_, err = x.r.st.MarkDeleted(ctx, x.op.Ref, retention)
	return err
}
