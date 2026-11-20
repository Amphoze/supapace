package saga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/store"
)

// A step that needs a job parks on it: the operation waits, holding no
// worker and no ref lock, until the job's end puts it back in the queue; the
// step then reads the job of its own pass (one whose id is above the
// operation's job floor) and consumes it, or submits a fresh one.

// maxInterrupted is the number of interrupted jobs of one step's pass after
// which the operation fails, final: a retry would count the same jobs.
const maxInterrupted = 5

// parked is returned by a step to park on a new job.
type parked struct{ job store.NewJob }

func (p *parked) Error() string { return "parked on a " + p.job.Kind + " job" }

// later is returned by a step that waits without a job: the operation is
// taken again after d, its attempt given back and its last_error kept. first
// is set on the wait's first round, which alone is logged.
type later struct {
	d     time.Duration
	first bool
}

func (l *later) Error() string { return "waiting " + l.d.String() }

// rewind is returned by a step that sends its operation back to step to.
// counted: cause is a job whose failure FinishJob has already counted.
type rewind struct {
	to      string
	cause   error
	counted bool
}

func (r *rewind) Error() string { return "rewind to " + r.to + ": " + r.cause.Error() }

// Test seams (no-ops otherwise): around the park's one transaction and
// between the rewind's two writes.
var (
	beforePark      = func() {}
	afterPark       = func() {}
	afterRaiseFloor = func() {}
)

// jobFloor is the operation's job floor: a job belongs to the current pass
// of its step only if its id is above it.
func jobFloor(params json.RawMessage) int64 {
	var p struct {
		Floor int64 `json:"job_floor"`
	}
	json.Unmarshal(params, &p)
	return p.Floor
}

func (x *job) jobRunner() (Jobs, error) {
	if x.r.jobs == nil {
		return nil, final("internal", errors.New("this node runs no backup jobs"))
	}
	return x.r.jobs, nil
}

func (x *job) recoverer() (Recoverer, error) {
	if x.r.rc == nil {
		return nil, final("internal", errors.New("this node has no re-key for a restore"))
	}
	return x.r.rc, nil
}

// latestJob is the newest job of the running step's pass. Five of its jobs
// ended interrupted fail the operation, final (code interrupted_limit). A job
// still queued or running belongs to a parked operation and cannot be seen
// by a running one: an error.
func (x *job) latestJob(ctx context.Context) (store.Job, bool, error) {
	floor := jobFloor(x.op.Params)
	n, err := x.r.st.CountInterruptedJobs(ctx, x.op.ID, x.step, floor)
	if err != nil {
		return store.Job{}, false, err
	}
	if n >= maxInterrupted {
		return store.Job{}, false, final("interrupted_limit", fmt.Errorf("%d jobs of step %s were interrupted", n, x.step))
	}
	j, ok, err := x.r.st.LatestJob(ctx, x.op.ID, x.step, floor)
	if err == nil && ok && j.State != "done" && j.State != "failed" {
		err = fmt.Errorf("job %d of step %s is %s", j.ID, x.step, j.State)
	}
	return j, ok, err
}

// submit parks the operation on a fresh job of kind for the running step.
func (x *job) submit(ctx context.Context, kind string) error {
	if _, err := x.jobRunner(); err != nil {
		return err
	}
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil {
		return err
	}
	d, err := bklimit.Deadline(kind, p.Config.DiskQuotaMB, p.Config.DiskQuotaMB)
	if err != nil {
		return err
	}
	lane := "backup"
	if kind == "push" || kind == "replicate" {
		lane = "push"
	}
	return &parked{store.NewJob{Subject: x.op.Ref, Lane: lane, Kind: kind, OpID: x.op.ID, OpStep: x.step,
		DeadlineS: int(d / time.Second)}}
}

// awaitJob is a step whose job is submitted again after any failure: the
// done job of this pass, or a park on a fresh one.
func (x *job) awaitJob(ctx context.Context, kind string) (store.Job, error) {
	j, ok, err := x.latestJob(ctx)
	if err != nil || ok && j.State == "done" {
		return j, err
	}
	return store.Job{}, x.submit(ctx, kind)
}

// jobCause is a failed job as a rewind's cause, and whether FinishJob counted
// it.
func jobCause(j store.Job) (cause error, counted bool) {
	return &failure{code: j.Code, err: errors.New(j.Message)}, j.Code != "interrupted" && j.Code != "cancelled"
}

// park submits the job and parks the operation in one transaction; the
// attempt ends and the ref lock is released by the caller.
func (x *job) park(ctx context.Context, nj store.NewJob) error {
	if err := x.record(ctx); err != nil {
		return err
	}
	beforePark()
	id, err := x.r.st.SubmitJobAndPark(ctx, x.op.ID, nj)
	if err != nil {
		return err
	}
	afterPark()
	x.r.log.Info("step waits for its job", "op", x.op.ID, "ref", x.op.Ref, "kind", x.op.Kind, "step", nj.OpStep,
		"job", id, "job_kind", nj.Kind)
	return nil
}

// requeue ends the attempt of a step that waits without a job.
func (x *job) requeue(ctx context.Context, l *later) error {
	if err := x.record(ctx); err != nil {
		return err
	}
	if err := x.r.st.Requeue(ctx, x.op.ID, time.Now().Add(l.d)); err != nil {
		return err
	}
	if l.first {
		x.r.log.Info("waiting without a job", "op", x.op.ID, "ref", x.op.Ref, "kind", x.op.Kind, "step", x.step)
	}
	return nil
}

// reload re-reads the operation after a store call that changed its
// parameters in SQL, so that the attempt reads and patches the stored ones.
func (x *job) reload(ctx context.Context) error {
	op, err := x.r.st.GetOperation(ctx, x.op.ID)
	if err != nil {
		return err
	}
	x.op = op
	return nil
}

// rewind raises the job floor (and, when no counted job caused it, counts
// an attempt) first, then records the step before rw.to; the attempt then
// continues at rw.to with the raised floor. Past the attempts' limit the
// operation fails at once with the cause's code and message.
func (x *job) rewind(ctx context.Context, table []step, rw *rewind) error {
	if err := x.record(ctx); err != nil {
		return err
	}
	i := indexOf(table, rw.to)
	if i < 0 {
		return final("internal", fmt.Errorf("rewind to unknown step %q", rw.to))
	}
	_, attempts, err := x.r.st.RaiseJobFloor(ctx, x.op.ID, !rw.counted)
	if err != nil {
		return err
	}
	afterRaiseFloor()
	if attempts-requeues(x.op.Params) > maxAttempts {
		var f *failure
		if errors.As(rw.cause, &f) {
			return final(f.code, f.err)
		}
		return final(code(rw.cause), rw.cause)
	}
	prev := ""
	if i > 0 {
		prev = table[i-1].id
	}
	if err := x.r.st.AdvanceStep(ctx, x.op.ID, prev); err != nil {
		return err
	}
	if err := x.reload(ctx); err != nil {
		return err
	}
	x.r.log.Info("rewound", "op", x.op.ID, "ref", x.op.Ref, "kind", x.op.Kind, "from", x.step, "to", rw.to,
		"cause", x.r.lastError(rw.cause))
	return nil
}

// count is a replication result's list, stored by the runner as its length.
type count int

func (c *count) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*c = count(n)
		return nil
	}
	var l []json.RawMessage
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	*c = count(len(l))
	return nil
}

// replFree counts, for one step's pass, the done jobs that do not count
// against the copy bound: rebuild pages and copies that only adopted rows.
// last is the newest job counted, so that a repeated read counts it once.
type replFree struct {
	Step  string `json:"step"`
	Floor int64  `json:"floor"`
	Last  int64  `json:"last"`
	N     int    `json:"n"`
}

// replicate is a replicate step: entered and done at once unless the
// off-site store is declared; else replication jobs until a copy is
// complete, at most bklimit.ReplLoopMax counted copies and
// bklimit.RebuildMaxPages rebuild pages.
func (x *job) replicate(ctx context.Context) error {
	jobs, err := x.jobRunner()
	if err != nil {
		return err
	}
	if jobs.Offsite() != "declared" {
		return nil
	}
	j, ok, err := x.latestJob(ctx)
	if err != nil {
		return err
	}
	floor := jobFloor(x.op.Params)
	var free replFree
	json.Unmarshal(paramRaw(x.op.Params, "repl_free"), &free)
	if free.Step != x.step || free.Floor != floor {
		free = replFree{Step: x.step, Floor: floor}
	}
	if ok && j.State == "done" {
		var res struct {
			Mode, Stopped, Skipped string
			Complete               bool
			Uploaded, Adopted      count
		}
		if err := json.Unmarshal(j.Result, &res); err != nil {
			return fmt.Errorf("replication job %d: its result does not parse: %v", j.ID, err)
		}
		rebuild := res.Mode == "rebuild"
		switch {
		case res.Skipped != "" || res.Complete && res.Stopped == "" && !rebuild:
			return nil
		case rebuild || res.Stopped == "caps":
		default:
			return final("replication_stopped", fmt.Errorf("replication job %d stopped: %q", j.ID, res.Stopped))
		}
		if rebuild {
			bs, err := x.r.st.GetBackupState(ctx, x.op.Ref)
			if err != nil {
				return err
			}
			if bs.RebuildPages >= bklimit.RebuildMaxPages {
				return final("replication_incomplete", fmt.Errorf("the record's rebuild took %d pages", bs.RebuildPages))
			}
		}
		if (rebuild || res.Uploaded == 0 && res.Adopted > 0) && j.ID > free.Last {
			free.Last, free.N = j.ID, free.N+1
			if err := x.r.patchParams(ctx, &x.op, "repl_free", free); err != nil {
				return err
			}
		}
	}
	n, err := x.r.st.CountJobs(ctx, x.op.ID, x.step, floor)
	if err != nil {
		return err
	}
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil {
		return err
	}
	if n-free.N >= bklimit.ReplLoopMax(p.Config.DiskQuotaMB) {
		return final("replication_incomplete", fmt.Errorf("replication not complete after %d copy jobs", n-free.N))
	}
	return x.submit(ctx, "replicate")
}

// paramRaw is one member of an operation's parameters, nil when absent.
func paramRaw(params json.RawMessage, key string) json.RawMessage {
	var m map[string]json.RawMessage
	json.Unmarshal(params, &m)
	return m[key]
}
