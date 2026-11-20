package saga

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/Amphoze/supapace/internal/store"
)

// finalState waits until operation id has ended and returns it.
func (e *env) finalState(id int64) store.Operation {
	e.t.Helper()
	return e.wait(id, "ended", func(op store.Operation) bool {
		return op.State == "done" || op.State == "failed" || op.State == "aborted"
	})
}

// The three final jobs of a delete are best effort: their failures cost the
// delete no attempt. With four attempts spent by failures of its own steps,
// a delete whose final backup, push and replication all fail still ends done.
func TestDelete_FailedFinalJobsCostNoAttempt(t *testing.T) {
	e := retainHour(t)
	e.declared()
	codes := map[string]string{"backup": "pgbackrest", "push": "repository_quota", "replicate": "upload_failed"}
	e.lanes(func(j store.Job) jobEnd {
		if c := codes[j.Kind]; c != "" && e.opKind(j) == "delete" {
			return jobEnd{state: "failed", code: c, msg: j.Kind + " failed"}
		}
		return defaultEnd(j)
	})
	ref := e.activeWith(layout2)
	var stops atomic.Int32
	e.ag.setErr(func(c call) error {
		if c.Method == "StopPostgREST" && stops.Add(1) <= 4 {
			return errBoom
		}
		return nil
	})
	r := e.runner()
	e.start(r)
	id, err := r.Submit(context.Background(), "delete", ref, nil)
	must(t, err)
	op := e.finalState(id)
	res := e.resultOf(id)
	if op.State != "done" || res["final_backup"] != "pgbackrest" || res["final_push"] != "repository_quota" ||
		res["final_replication"] != "upload_failed" {
		t.Fatalf("op %+v, result %v", op, res)
	}
	if p := e.project(ref); p.State != "deleted" {
		t.Fatalf("project %+v", p)
	}
}

// A failure of S1 (made before the cluster is touched) leaves the project
// served at its previous configuration, as a failure of R1 does.
func TestSwitch_FailingS1LeavesTheProjectServing(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref := e.activeWith(layout1)
	e.ag.setErr(failOn("EnsureSpoolDirs"))
	r := e.runner()
	id := e.restart(r, ref, to2(layout1))
	e.start(r)
	op := e.finalState(id)
	p := e.project(ref)
	var route string
	e.ag.locked(func() { route = e.ag.route[ref].State })
	if p.State != "active" || route != "active" {
		t.Fatalf("op %+v; project %s at layout %d, route %q", op, p.State, p.Config.Layout, route)
	}
}

// D1 cancels the project's jobs only once the project is deleting: from
// then on the job runner admits none of its jobs that no operation owns, so
// one the scheduler queues after the cancel never runs.
func TestDelete_D1CancelsOnceDeleting(t *testing.T) {
	e := retainHour(t)
	e.lanes(nil)
	ref := e.activeWith(layout2)
	var state atomic.Value
	jc := &stateAtCancel{jobsCalls: &jobsCalls{fakeJobs: e.jobs}, at: func() { state.Store(e.project(ref).State) }}
	r := e.runner()
	r.SetJobs(jc)
	e.start(r)
	e.deleteOf(r, ref)
	if s, _ := state.Load().(string); s != "deleting" {
		t.Fatalf("the project was %q when its jobs were cancelled", s)
	}
}

type stateAtCancel struct {
	*jobsCalls
	at func()
}

func (j *stateAtCancel) CancelSubject(ctx context.Context, s string) error {
	if j.at != nil {
		j.at()
		j.at = nil
	}
	return j.jobsCalls.CancelSubject(ctx, s)
}
