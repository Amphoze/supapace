package saga

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/store"
)

var deleteSteps2 = []string{"D1", "D2", "Db", "D3", "Dp", "Dr", "D4", "D5"}

// resultOf is operation id's result document as strings.
func (e *env) resultOf(id int64) map[string]string {
	e.t.Helper()
	m := map[string]string{}
	if r := e.op(id).Result; len(r) > 0 {
		must(e.t, json.Unmarshal(r, &m))
	}
	return m
}

// pushEnd is a push job's result.
func pushEnd(complete bool) jobEnd {
	if complete {
		return jobEnd{state: "done", result: `{"ok":true,"complete":true,"pushed":3}`}
	}
	return jobEnd{state: "done", result: `{"ok":true,"complete":false,"pushed":56}`}
}

// deleteOf submits a delete of ref and waits until it is done.
func (e *env) deleteOf(r *Runner, ref string) int64 {
	e.t.Helper()
	id, err := r.Submit(context.Background(), "delete", ref, nil)
	must(e.t, err)
	e.waitState(id, "done")
	return id
}

// jobsCalls records every call of the job runner's interface.
type jobsCalls struct {
	*fakeJobs
	mu    sync.Mutex
	calls []string
}

func (j *jobsCalls) add(c string) {
	j.mu.Lock()
	j.calls = append(j.calls, c)
	j.mu.Unlock()
}
func (j *jobsCalls) Cancel(ctx context.Context, op int64) error {
	j.add("Cancel")
	return j.fakeJobs.Cancel(ctx, op)
}
func (j *jobsCalls) CancelSubject(ctx context.Context, s string) error {
	j.add("CancelSubject " + s)
	return j.fakeJobs.CancelSubject(ctx, s)
}
func (j *jobsCalls) PushNow(ctx context.Context, s string, w time.Duration) (string, error) {
	j.add("PushNow " + s)
	return j.fakeJobs.PushNow(ctx, s, w)
}
func (j *jobsCalls) Offsite() string { j.add("Offsite"); return j.fakeJobs.Offsite() }

func (j *jobsCalls) list() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return slices.Clone(j.calls)
}

// ───────── delete ─────────

func TestDelete_Order_DbD3DpDr(t *testing.T) {
	e := retainHour(t)
	e.declared()
	var clusterAt sync.Map // job kind → the cluster ran when the job ran
	e.lanes(func(j store.Job) jobEnd {
		if j.OpID != 0 && e.op(j.OpID).Kind == "delete" {
			var running bool
			e.ag.locked(func() { running = e.ag.cluster[j.Subject] != 0 })
			clusterAt.Store(j.Kind, running)
		}
		if j.Kind == "replicate" {
			return replDone
		}
		return defaultEnd(j)
	})
	ref := e.activeWith(layout2)
	r := e.runner()
	e.start(r)
	id := e.deleteOf(r, ref)
	wantSeq(t, e.steps(id), deleteSteps2)
	wantSeq(t, e.jobSteps(id), []string{"Db/backup", "Dp/push", "Dr/replicate"})
	wantSeq(t, e.ag.methods(ref), []string{"Jobs.CancelSubject", "SetRoute", "StopPostgREST", "StopCluster", "RemoveNetwork"})
	for kind, want := range map[string]bool{"backup": true, "push": false, "replicate": false} {
		if v, ok := clusterAt.Load(kind); !ok || v.(bool) != want {
			t.Errorf("%s job ran with the cluster running %v (seen %v), want %v", kind, v, ok, want)
		}
	}
	res := e.resultOf(id)
	if res["final_backup"] != "ok" || res["final_push"] != "ok" || res["final_replication"] != "ok" {
		t.Fatalf("result %v", res)
	}
	if p := e.project(ref); p.State != "deleted" {
		t.Fatalf("project %+v", p)
	}
}

// opKind is the kind of the operation a job belongs to ("" for none); for
// the fake lanes' goroutine.
func (e *env) opKind(j store.Job) string {
	if j.OpID == 0 {
		return ""
	}
	op, err := e.st.GetOperation(context.Background(), j.OpID)
	if err != nil {
		e.t.Error(err)
	}
	return op.Kind
}

// drive ends the queue's jobs done, as the lanes would, until operation id
// is done: for tests that keep the queue in their own hands.
func (e *env) drive(id int64) {
	e.t.Helper()
	ctx := context.Background()
	e.wait(id, "done", func(op store.Operation) bool {
		for _, lane := range []string{"push", "backup"} {
			j, ok, err := e.st.NextJob(ctx, lane)
			must(e.t, err)
			if !ok {
				continue
			}
			res := defaultEnd(j).result
			if j.Kind == "stanza-create" {
				must(e.t, e.st.MarkStanza(ctx, j.Subject))
			}
			must(e.t, e.st.FinishJob(ctx, j.ID, "done", "", "", json.RawMessage(res)))
		}
		return op.State == "done"
	})
}

// schedulerJob queues a job of subject that no operation owns, as the
// runner's scheduler does.
func (e *env) schedulerJob(subject, lane, kind string) int64 {
	e.t.Helper()
	id, err := e.st.SubmitJob(context.Background(), store.NewJob{Subject: subject, Lane: lane, Kind: kind, DeadlineS: 300})
	must(e.t, err)
	return id
}

func jobState(t *testing.T, id int64) string {
	t.Helper()
	n := sqlInt(t, `select case when state = 'queued' then 0 when state = 'running' then 1
		when state = 'failed' and code = 'cancelled' then 2 else 3 end from backup_job where id = $1`, id)
	return []string{"queued", "running", "cancelled", "other"}[n]
}

func TestDelete_D1CancelsSubjectJobs(t *testing.T) {
	e := retainHour(t)
	ref, create := e.create2(layout2)
	other, create2 := e.create2(layout2)
	r := e.runner()
	e.start(r)
	e.drive(create)
	e.drive(create2)
	ctx := context.Background()
	running := e.schedulerJob(ref, "push", "push")
	if j, ok, err := e.st.NextJob(ctx, "push"); err != nil || !ok || j.ID != running {
		t.Fatalf("pick %+v %v %v", j, ok, err)
	}
	queued := e.schedulerJob(ref, "push", "replicate")
	keep := e.schedulerJob(other, "backup", "backup")
	e.ag.reset()
	e.failpoint("delete:D2")
	del, err := r.Submit(ctx, "delete", ref, nil)
	must(t, err)
	e.wait(del, "past D1", func(op store.Operation) bool { return op.Step == "D1" })
	if s := jobState(t, running); s != "cancelled" {
		t.Fatalf("running job %s", s)
	}
	if s := jobState(t, queued); s != "cancelled" {
		t.Fatalf("queued job %s", s)
	}
	if s := jobState(t, keep); s != "queued" {
		t.Fatalf("another project's job %s", s)
	}
	if m := e.ag.methods(ref); len(m) == 0 || m[0] != "Jobs.CancelSubject" {
		t.Fatalf("calls %v", m)
	}
	if n := sqlInt(t, "select count(*) from project where ref = $1 and slot_op is not null", ref); n != 0 {
		t.Fatal("the delete took the slot")
	}
	e.start(e.runner())
	e.drive(del)
	if p := e.project(ref); p.State != "deleted" {
		t.Fatalf("project %+v", p)
	}
}

func TestDelete_FinalPushRepeatsUntilTheSpoolIsEmpty(t *testing.T) {
	limit := bklimit.PushLoopMax(layout2.DiskQuotaMB)
	for _, c := range []struct {
		name     string
		complete func(n int32) bool
		jobs     int
		outcome  string
	}{
		{"empties", func(n int32) bool { return n == 3 }, 3, "ok"},
		{"bound", func(int32) bool { return false }, limit, "incomplete"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := retainHour(t)
			var n atomic.Int32
			e.lanes(func(j store.Job) jobEnd {
				if j.Kind == "push" {
					return pushEnd(c.complete(n.Add(1)))
				}
				return defaultEnd(j)
			})
			ref := e.activeWith(layout2)
			r := e.runner()
			e.start(r)
			id := e.deleteOf(r, ref)
			var pushes int
			for _, s := range e.jobSteps(id) {
				if s == "Dp/push" {
					pushes++
				}
			}
			if pushes != c.jobs || e.resultOf(id)["final_push"] != c.outcome {
				t.Fatalf("%d push jobs, result %v", pushes, e.resultOf(id))
			}
			if e.op(id).Attempts != 1 {
				t.Fatalf("op %+v", e.op(id))
			}
		})
	}
}

func TestDelete_FailedFinalBackupContinues_Recorded(t *testing.T) {
	e := retainHour(t)
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "backup" && e.opKind(j) == "delete" {
			return jobEnd{state: "failed", code: "pgbackrest", msg: "backup failed"}
		}
		return defaultEnd(j)
	})
	ref := e.activeWith(layout2)
	r := e.runner()
	e.start(r)
	id := e.deleteOf(r, ref)
	wantSeq(t, e.jobSteps(id), []string{"Db/backup", "Dp/push"})
	res := e.resultOf(id)
	if res["final_backup"] != "pgbackrest" || res["final_push"] != "ok" || res["final_replication"] != "skipped" {
		t.Fatalf("result %v", res)
	}
}

func TestDelete_FiveInterruptionsRecordedNotFailed(t *testing.T) {
	e := retainHour(t)
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "backup" && e.opKind(j) == "delete" {
			return jobEnd{state: "failed", code: "interrupted", msg: "the daemon stopped while the job ran"}
		}
		return defaultEnd(j)
	})
	ref := e.activeWith(layout2)
	r := e.runner()
	e.start(r)
	id := e.deleteOf(r, ref)
	wantSeq(t, e.jobSteps(id), []string{"Db/backup", "Db/backup", "Db/backup", "Db/backup", "Db/backup", "Dp/push"})
	if res := e.resultOf(id); res["final_backup"] != "interrupted_limit" || res["final_push"] != "ok" {
		t.Fatalf("result %v", res)
	}
}

func TestDelete_BestEffortNeverFailsTheDelete(t *testing.T) {
	e := retainHour(t)
	e.declared()
	codes := map[string]string{"backup": "pgbackrest", "push": "repository_quota", "replicate": "upload_failed"}
	e.lanes(func(j store.Job) jobEnd {
		if c := codes[j.Kind]; c != "" && e.opKind(j) == "delete" {
			return jobEnd{state: "failed", code: c, msg: j.Kind + " failed"}
		}
		if j.Kind == "replicate" {
			return replDone
		}
		return defaultEnd(j)
	})
	ref := e.activeWith(layout2)
	r := e.runner()
	e.start(r)
	id := e.deleteOf(r, ref)
	wantSeq(t, e.steps(id), deleteSteps2)
	wantSeq(t, e.jobSteps(id), []string{"Db/backup", "Dp/push", "Dr/replicate"})
	res := e.resultOf(id)
	if res["final_backup"] != "pgbackrest" || res["final_push"] != "repository_quota" || res["final_replication"] != "upload_failed" {
		t.Fatalf("result %v", res)
	}
	if p := e.project(ref); p.State != "deleted" {
		t.Fatalf("project %+v", p)
	}
}

// A delete whose final backup's job failed and which then ran out of
// attempts at Db (the worker stopped there every time it took the
// operation) is retried: Db submits a fresh job, and the earlier pass's
// failure is not its outcome.
func TestDelete_OpRetrySubmitsFreshJobs(t *testing.T) {
	e := retainHour(t)
	var fail atomic.Bool
	fail.Store(true)
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "backup" && e.opKind(j) == "delete" && fail.Load() {
			e.failpoint("delete:Db") // the worker stops when it takes the operation again
			return jobEnd{state: "failed", code: "pgbackrest", msg: "backup failed"}
		}
		return defaultEnd(j)
	})
	ref := e.activeWith(layout2)
	ctx := context.Background()
	r := e.runner()
	id, err := r.Submit(ctx, "delete", ref, nil)
	must(t, err)
	done := e.run(r)
	for i := 0; ; i++ {
		deadline := time.Now().Add(30 * time.Second)
		for e.op(id).State != "failed" && time.Now().Before(deadline) {
			select {
			case <-done:
				deadline = time.Time{}
			case <-time.After(2 * time.Millisecond):
			}
		}
		if e.op(id).State == "failed" || i == 10 {
			break
		}
		e.failpoint("delete:Db")
		done = e.run(e.runner())
	}
	must(t, os.Remove(e.p.Failpoint()))
	op := e.op(id)
	old := e.jobsOf(id)
	if op.State != "failed" || op.Step != "D2" || len(old) != 1 || old[0].State != "failed" {
		t.Fatalf("op %+v, jobs %v", op, e.jobSteps(id))
	}
	fail.Store(false)
	e.start(e.runner())
	must(t, e.st.RetryOperation(ctx, id))
	e.waitState(id, "done")
	fresh := e.jobsOf(id)[1:]
	if len(fresh) != 2 || fresh[0].OpStep != "Db" || fresh[0].State != "done" || fresh[0].ID <= old[0].ID {
		t.Fatalf("after the retry %+v", fresh)
	}
	if res := e.resultOf(id); res["final_backup"] != "ok" {
		t.Fatalf("result %v", res)
	}
}

func TestDelete_InterruptedFinalJobSubmittedAgain(t *testing.T) {
	e := retainHour(t)
	var n atomic.Int32
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "push" && n.Add(1) == 1 {
			return jobEnd{state: "failed", code: "interrupted", msg: "the daemon stopped while the job ran"}
		}
		if j.Kind == "push" {
			return pushEnd(true)
		}
		return defaultEnd(j)
	})
	ref := e.activeWith(layout2)
	r := e.runner()
	e.start(r)
	id := e.deleteOf(r, ref)
	wantSeq(t, e.jobSteps(id), []string{"Db/backup", "Dp/push", "Dp/push"})
	if res := e.resultOf(id); res["final_push"] != "ok" || e.op(id).Attempts != 1 {
		t.Fatalf("result %v, op %+v", res, e.op(id))
	}
}

// restoring leaves ref restoring with a failed restore as its newest
// operation, and a recovery start of the cluster running.
func (e *env) restoring(ref string) int64 {
	e.t.Helper()
	ctx := context.Background()
	id, _, err := e.st.SubmitRestore(ctx, ref, json.RawMessage(`{}`))
	must(e.t, err)
	must(e.t, e.st.SetProjectRestoring(ctx, ref, id))
	sql(e.t, "update operation set state = 'failed', last_error = 'recover: replay stopped' where id = $1", id)
	e.ag.locked(func() { e.ag.cluster[ref] = 99 })
	return id
}

func TestDelete_OfARestoringProject_StopsTheRecoveryStart(t *testing.T) {
	e := retainHour(t)
	e.lanes(nil)
	ref := e.activeWith(layout2)
	restore := e.restoring(ref)
	r := e.runner()
	e.start(r)
	e.deleteOf(r, ref)
	if n := len(e.ag.callsOf(ref, "StopCluster")); n != 1 {
		t.Fatalf("%d stops", n)
	}
	e.ag.locked(func() {
		if e.ag.cluster[ref] != 0 {
			t.Fatal("the recovery start still runs")
		}
	})
	if op := e.op(restore); op.State != "superseded" {
		t.Fatalf("restore %+v", op)
	}
	if p := e.project(ref); p.State != "deleted" {
		t.Fatalf("project %+v", p)
	}
}

func TestDelete_D1AcceptsARestoringProject(t *testing.T) {
	e := retainHour(t)
	e.lanes(nil)
	ref := e.activeWith(layout2)
	e.restoring(ref)
	ctx := context.Background()
	r := e.runner()
	del, err := r.Submit(ctx, "delete", ref, nil)
	must(t, err)
	// The delete failed before the project became deleting.
	sql(t, "update operation set state = 'failed', last_error = 'internal: boom' where id = $1", del)
	if p := e.project(ref); p.State != "restoring" {
		t.Fatalf("project %+v", p)
	}
	if _, err := r.Submit(ctx, "delete", ref, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second delete: %v", err)
	}
	must(t, e.st.RetryOperation(ctx, del))
	e.start(r)
	e.waitState(del, "done")
	if p := e.project(ref); p.State != "deleted" {
		t.Fatalf("project %+v", p)
	}
}

func TestDelete_Layout1SkipsJobs(t *testing.T) {
	e := retainHour(t)
	ref := e.activeWith(layout1)
	r := e.runner()
	r.SetJobs(nil) // no job runner: a layout-1 delete needs none
	e.start(r)
	id := e.deleteOf(r, ref)
	wantSeq(t, e.steps(id), []string{"D1", "D2", "D3", "D4", "D5"})
	if len(e.jobsOf(id)) != 0 || len(e.op(id).Result) != 0 {
		t.Fatalf("jobs %v, result %s", e.jobSteps(id), e.op(id).Result)
	}
	// Its purge needs none either.
	ops, err := e.st.ListOperations(context.Background(), ref)
	must(t, err)
	purge := ops[0].ID
	must(t, e.st.SetPurgeNow(context.Background(), ref))
	e.waitState(purge, "done")
}

// ───────── purge ─────────

// deletedHeld deletes ref with a runner that is then stopped, its purge
// held by the hour's retention; it returns the purge's id.
func (e *env) deletedHeld(ref string) int64 {
	e.t.Helper()
	r := e.runner()
	stop := e.start(r)
	_, purge := e.deleted(r, ref)
	stop()
	e.ag.reset()
	return purge
}

func TestPurge_CancelsQueuedJobsFirst(t *testing.T) {
	e := retainHour(t)
	e.lanes(nil)
	ref := e.activeWith(layout2)
	purge := e.deletedHeld(ref)
	// The lanes are not to run what this test queues: the slot is held by
	// the purge, which submits no job.
	sql(t, "update project set slot_op = $2 where ref = $1", ref, purge)
	atP1 := e.schedulerJob(ref, "push", "push")
	var atP4 atomic.Int64
	var p1Done atomic.Value
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "RemoveRender" && atP4.Load() == 0 {
			p1Done.Store(jobState(t, atP1))
			id, err := e.st.SubmitJob(ctx, store.NewJob{Subject: ref, Lane: "backup", Kind: "backup", DeadlineS: 300})
			if err != nil {
				t.Error(err)
			}
			atP4.Store(id)
		}
	})
	must(t, e.st.SetPurgeNow(context.Background(), ref))
	e.start(e.runner())
	e.waitState(purge, "done")
	wantSeq(t, e.ag.methods(ref), []string{"Jobs.CancelSubject", "StopPostgREST", "StopCluster", "RemoveRender",
		"Jobs.CancelSubject", "PurgeDir", "PurgeRepo"})
	if p1Done.Load() != "cancelled" || jobState(t, atP1) != "cancelled" || jobState(t, atP4.Load()) != "cancelled" {
		t.Fatalf("at P3 %v; jobs %s, %s", p1Done.Load(), jobState(t, atP1), jobState(t, atP4.Load()))
	}
}

func TestPurge_KeysBeforeTrees_RepoRemoved_ObligationSet(t *testing.T) {
	e := retainHour(t)
	e.lanes(nil)
	ref := e.activeWith(layout2)
	purge := e.deletedHeld(ref)
	var bad atomic.Value
	bad.Store("")
	r, spy := e.spyRunner()
	spy.at = func(method string, s agent.Spec) {
		if _, _, err := e.st.GetDEK(context.Background(), ref); !errors.Is(err, store.ErrDestroyed) {
			bad.Store(method + ": keys " + errString(err))
		}
	}
	must(t, e.st.SetPurgeNow(context.Background(), ref))
	e.start(r)
	e.waitState(purge, "done")
	if s := bad.Load().(string); s != "" {
		t.Fatal(s)
	}
	m := e.ag.methods(ref)
	if i := slices.Index(m, "PurgeDir"); i < 0 || slices.Index(m, "PurgeRepo") != i+1 {
		t.Fatalf("calls %v", m)
	}
	uid := *e.project(ref).UID
	for _, method := range []string{"PurgeDir", "PurgeRepo"} {
		if ss := spy.of(method); len(ss) != 1 || ss[0].Ref != ref || ss[0].UID != uid || ss[0].Layout != 2 {
			t.Fatalf("%s specs %+v", method, ss)
		}
	}
	e.ag.locked(func() {
		if e.ag.repo[ref] || e.ag.dir[ref] {
			t.Fatal("trees kept")
		}
	})
	bs, err := e.st.GetBackupState(context.Background(), ref)
	if err != nil || !bs.OffsitePurge {
		t.Fatalf("backup state %+v, %v", bs, err)
	}
	if p := e.project(ref); p.State != "purged" {
		t.Fatalf("project %+v", p)
	}
}

func errString(err error) string {
	if err == nil {
		return "present"
	}
	return err.Error()
}

func TestPurge_NothingDeletedOffsite(t *testing.T) {
	e := retainHour(t)
	e.declared()
	e.lanes(nil)
	ref := e.activeWith(layout2)
	purge := e.deletedHeld(ref)
	jc := &jobsCalls{fakeJobs: e.jobs}
	r := e.runner()
	r.SetJobs(jc)
	must(t, e.st.SetPurgeNow(context.Background(), ref))
	e.start(r)
	e.waitState(purge, "done")
	wantSeq(t, jc.list(), []string{"CancelSubject " + ref, "CancelSubject " + ref})
	if n := sqlInt(t, "select count(*) from backup_job where op_id = $1", purge); n != 0 {
		t.Fatalf("%d jobs of the purge", n)
	}
}

// A purge task that never returns is ended by the step deadline: the purge
// fails after its attempts and holds nothing.
func TestPurge_AHangingTaskIsBounded(t *testing.T) {
	e := retainHour(t)
	e.lanes(nil)
	ref := e.activeWith(layout2)
	purge := e.deletedHeld(ref)
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "PurgeRepo" {
			<-ctx.Done()
		}
	})
	r := e.runner()
	r.stepDeadline = time.Second
	must(t, e.st.SetPurgeNow(context.Background(), ref))
	e.start(r)
	op := e.waitState(purge, "failed")
	if op.Step != "P3" || op.Attempts != 5 || len(e.ag.callsOf(ref, "PurgeRepo")) != 5 {
		t.Fatalf("op %+v", op)
	}
	if p := e.project(ref); p.State != "deleted" {
		t.Fatalf("project %+v", p)
	}
}

// defaultEnd is how the fake lanes end a job of kind by default: done, a
// push and a copy complete.
func defaultEnd(j store.Job) jobEnd {
	switch j.Kind {
	case "replicate":
		return replDone
	case "push":
		return pushEnd(true)
	}
	return okEnd
}

// A layout-2 project without a stanza (a switch that stopped before its
// first backup) has nothing to back up, push or copy: the three steps are
// recorded skipped and submit nothing.
func TestDelete_WithoutAStanzaSkipsTheJobs(t *testing.T) {
	e := retainHour(t)
	e.declared()
	e.lanes(nil)
	ref := e.activeWith(layout2)
	sql(t, "update backup_state set stanza_created = false where subject = $1", ref)
	r := e.runner()
	e.start(r)
	id := e.deleteOf(r, ref)
	wantSeq(t, e.steps(id), deleteSteps2)
	res := e.resultOf(id)
	if len(e.jobsOf(id)) != 0 || res["final_backup"] != "skipped" || res["final_push"] != "skipped" || res["final_replication"] != "skipped" {
		t.Fatalf("jobs %v, result %v", e.jobSteps(id), res)
	}
}

// finalWords are the outcome words a delete's final steps write besides a
// failed job's code; the operator documentation lists them.
var finalWords = []string{"ok", "skipped", "incomplete"}

// Every outcome a delete's result can hold is one of finalWords or the code
// of the step's failed job: one delete per way a final step can end.
func TestDelete_OutcomeWordsAreClosed(t *testing.T) {
	e := retainHour(t)
	e.declared()
	var mode atomic.Value
	mode.Store("")
	e.lanes(func(j store.Job) jobEnd {
		if e.opKind(j) != "delete" {
			return defaultEnd(j)
		}
		switch m := mode.Load().(string); {
		case m == "bound" && j.Kind == "push":
			return pushEnd(false)
		case m == "fail" && j.Kind == "backup":
			return jobEnd{state: "failed", code: "pgbackrest", msg: "backup failed"}
		case m == "interrupt" && j.Kind == "replicate":
			return jobEnd{state: "failed", code: "interrupted", msg: "the daemon stopped while the job ran"}
		}
		return defaultEnd(j)
	})
	r := e.runner()
	e.start(r)
	seen := map[string]bool{}
	for _, m := range []string{"", "bound", "fail", "interrupt", "nostanza"} {
		mode.Store(m)
		ref := e.activeWith(layout2)
		if m == "nostanza" {
			sql(t, "update backup_state set stanza_created = false where subject = $1", ref)
		}
		id := e.deleteOf(r, ref)
		res := e.resultOf(id)
		if len(res) != 3 {
			t.Fatalf("%s: result %v", m, res)
		}
		for _, v := range res {
			seen[v] = true
		}
	}
	var got []string
	for v := range seen {
		got = append(got, v)
	}
	slices.Sort(got)
	wantSeq(t, got, []string{"incomplete", "interrupted_limit", "ok", "pgbackrest", "skipped"})
	for _, v := range got {
		if !slices.Contains(finalWords, v) && v != "pgbackrest" && v != "interrupted_limit" {
			t.Fatalf("outcome %q is neither a word nor a job's code", v)
		}
	}
}

// Dr's copy loop keeps its own bound without the attempt count: at
// ReplLoopMax counted copies the step records replication_incomplete and
// the delete goes on.
func TestDelete_ReplicateLoopBoundRecorded(t *testing.T) {
	e := retainHour(t)
	e.declared()
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "replicate" && e.opKind(j) == "delete" {
			return jobEnd{state: "done", result: `{"ok":true,"mode":"copy","complete":false,"stopped":"caps","uploaded":2,"adopted":0}`}
		}
		return defaultEnd(j)
	})
	ref := e.activeWith(small)
	r := e.runner()
	e.start(r)
	id := e.deleteOf(r, ref)
	n := 0
	for _, s := range e.jobSteps(id) {
		if s == "Dr/replicate" {
			n++
		}
	}
	if n != bklimit.ReplLoopMax(small.DiskQuotaMB) || e.resultOf(id)["final_replication"] != "replication_incomplete" {
		t.Fatalf("%d copies, result %v", n, e.resultOf(id))
	}
}
