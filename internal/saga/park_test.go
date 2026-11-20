package saga

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/store"
)

// sqlInt runs a query that returns one integer on the test database.
func sqlInt(t *testing.T, q string, args ...any) int64 {
	t.Helper()
	cfg, err := pgx.ParseConfig("")
	must(t, err)
	cfg.Host, cfg.Port, cfg.Database, cfg.User = sockDir, 5432, "supapaced", "supapaced"
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	ctx := context.Background()
	c, err := pgx.ConnectConfig(ctx, cfg)
	must(t, err)
	defer c.Close(ctx)
	var n int64
	must(t, c.QueryRow(ctx, q, args...).Scan(&n))
	return n
}

func floorOf(op store.Operation) int64 {
	n, _ := strconv.ParseInt(paramOf(op, "job_floor"), 10, 64)
	return n
}

// ───────── parking ─────────

func TestPark_ReleasesRefLockAndWorker(t *testing.T) {
	e := newEnv(t)
	refA, a := e.create2(layout2) // no lanes: its first job never runs
	e.start(e.runner())
	op := e.waitState(a, "waiting_job")
	if op.Step != "4" {
		t.Fatalf("parked %+v", op)
	}
	refB, b := e.create()
	e.waitState(b, "done")
	if e.project(refB).State != "active" || e.op(a).State != "waiting_job" {
		t.Fatalf("B %s, A %+v", e.project(refB).State, e.op(a))
	}
	// Nobody holds A's ref lock; no session of the pool holds an advisory lock.
	unlock, ok, err := e.st.TryLockRef(context.Background(), refA)
	must(t, err)
	if !ok {
		t.Fatal("the parked operation's ref lock is still held")
	}
	unlock()
	if n := sqlInt(t, "select count(*) from pg_locks where locktype = 'advisory' and granted"); n != 0 {
		t.Fatalf("%d advisory locks held", n)
	}
	if n := len(e.jobsOf(a)); n != 1 {
		t.Fatalf("%d jobs", n)
	}
}

// Twelve parks in one create (three jobs of step 5 and nine copies): the
// operation never counts more than the attempt that runs.
func TestPark_ResumeAfterDoneIsNotAnAttempt(t *testing.T) {
	e := newEnv(t)
	e.declared()
	var mu sync.Mutex
	var seen []int
	var copies atomic.Int32
	e.lanes(func(j store.Job) jobEnd {
		op, err := e.st.GetOperation(context.Background(), j.OpID)
		mu.Lock()
		if err == nil {
			seen = append(seen, op.Attempts)
			if op.State != "waiting_job" {
				seen = append(seen, 99)
			}
		}
		mu.Unlock()
		if j.Kind == "replicate" && copies.Add(1) < 9 {
			return jobEnd{state: "done", result: `{"ok":true,"mode":"copy","complete":false,"stopped":"caps","uploaded":2,"adopted":0}`}
		}
		if j.Kind == "replicate" {
			return replDone
		}
		return okEnd
	})
	_, id := e.create2(layout2)
	e.start(e.runner())
	op := e.waitState(id, "done")
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 12 || op.Attempts != 1 {
		t.Fatalf("attempts at each job %v, at the end %d", seen, op.Attempts)
	}
	for _, n := range seen {
		if n != 0 {
			t.Fatalf("attempts at each job %v", seen)
		}
	}
}

func TestPark_FailedJobCounts_FiveFail(t *testing.T) {
	e := newEnv(t)
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "backup" {
			return jobEnd{state: "failed", code: "pgbackrest", msg: "backup failed: job " + strconv.FormatInt(j.ID, 10)}
		}
		return okEnd
	})
	_, id := e.create2(layout2)
	e.start(e.runner())
	op := e.waitState(id, "failed")
	jobs := e.jobsOf(id)
	last := jobs[len(jobs)-1]
	if len(jobs) != 6 || last.OpStep != "5b" || op.Step != "5a" {
		t.Fatalf("jobs %v, op %+v", e.jobSteps(id), op)
	}
	if want := "pgbackrest: backup failed: job " + strconv.FormatInt(last.ID, 10); op.LastError != want {
		t.Fatalf("last_error %q, want %q", op.LastError, want)
	}
}

func TestPark_InterruptedDoesNotCount(t *testing.T) {
	e := newEnv(t)
	var n atomic.Int32
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "backup" && n.Add(1) <= 4 {
			return jobEnd{state: "failed", code: "interrupted", msg: "the daemon stopped while the job ran"}
		}
		if j.Kind == "check" && n.Add(1) <= 7 {
			return jobEnd{state: "failed", code: "cancelled", msg: "cancelled"}
		}
		return okEnd
	})
	_, id := e.create2(layout2)
	e.start(e.runner())
	op := e.waitState(id, "done")
	if op.Attempts != 1 || len(e.jobsOf(id)) != 1+5+3 {
		t.Fatalf("op %+v, jobs %v", op, e.jobSteps(id))
	}
}

func TestPark_FiveInterruptionsFailWithInterruptedLimit(t *testing.T) {
	e := newEnv(t)
	var interrupt atomic.Int32
	interrupt.Store(1 << 20)
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "backup" && interrupt.Add(-1) >= 0 {
			return jobEnd{state: "failed", code: "interrupted", msg: "the daemon stopped while the job ran"}
		}
		return okEnd
	})
	_, id := e.create2(layout2)
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if !strings.HasPrefix(op.LastError, "interrupted_limit: ") || op.Attempts != 1 || len(e.jobsOf(id)) != 6 {
		t.Fatalf("op %+v, jobs %v", op, e.jobSteps(id))
	}
	// Final whatever the attempts: a high count changes nothing about it.
	// Jobs below the floor do not count: after op retry four more
	// interruptions leave the step going.
	interrupt.Store(4)
	must(t, e.st.RetryOperation(context.Background(), id))
	op = e.waitState(id, "done")
	if n := len(e.jobsOf(id)); n != 6+5+1 {
		t.Fatalf("%d jobs: %v", n, e.jobSteps(id))
	}
}

// The park is one transaction: a worker that stops before it leaves no job
// (the step submits again); one that stops after it leaves a parked
// operation (nothing is submitted again).
func TestPark_CrashBetweenSubmitAndPark(t *testing.T) {
	for _, when := range []string{"before", "after"} {
		t.Run(when, func(t *testing.T) {
			e := newEnv(t)
			_, id := e.create2(layout2)
			seam := &beforePark
			if when == "after" {
				seam = &afterPark
			}
			var once atomic.Bool
			*seam = func() {
				if once.CompareAndSwap(false, true) {
					runtime.Goexit()
				}
			}
			t.Cleanup(func() { *seam = func() {} })
			<-e.run(e.runner())
			op := e.op(id)
			switch when {
			case "before":
				if op.State != "running" || len(e.jobsOf(id)) != 0 {
					t.Fatalf("op %+v, jobs %v", op, e.jobSteps(id))
				}
			case "after":
				if op.State != "waiting_job" || len(e.jobsOf(id)) != 1 {
					t.Fatalf("op %+v, jobs %v", op, e.jobSteps(id))
				}
			}
			e.lanes(nil)
			e.start(e.runner())
			e.waitState(id, "done")
			wantSeq(t, e.jobSteps(id), []string{"5a/stanza-create", "5b/backup", "5c/check"})
		})
	}
}

// ───────── the floor and the rewind ─────────

// rewindTable runs a test step table as the restore kind (whose own table
// is empty) on an active project with a backup state row.
func (e *env) rewindTable(table []step) (string, int64) {
	e.t.Helper()
	old := tables["restore"]
	tables["restore"] = table
	e.t.Cleanup(func() { tables["restore"] = old })
	ref := e.active()
	must(e.t, e.st.EnsureBackupState(context.Background(), ref))
	id, _, err := e.st.SubmitRestore(context.Background(), ref, nil)
	must(e.t, err)
	return ref, id
}

func jobStep(kind string) func(*job, context.Context) error {
	return func(x *job, ctx context.Context) error { _, err := x.awaitJob(ctx, kind); return err }
}

func seamAt(t *testing.T, fn func()) {
	afterRaiseFloor = fn
	t.Cleanup(func() { afterRaiseFloor = func() {} })
}

func TestRewind_RaisesFloorThenStep(t *testing.T) {
	e := newEnv(t)
	_, id := e.rewindTable([]step{
		{id: "X1", do: jobStep("check")},
		{id: "X2", do: func(x *job, ctx context.Context) error {
			if paramOf(x.op, "rewound") != "" {
				return nil
			}
			if err := x.r.patchParams(ctx, &x.op, "rewound", true); err != nil {
				return err
			}
			return &rewind{to: "X1", cause: final("test", errors.New("again"))}
		}},
	})
	var between store.Operation
	seamAt(t, func() { between = e.op(id) })
	e.lanes(nil)
	e.start(e.runner())
	op := e.waitState(id, "done")
	first := e.jobsOf(id)[0]
	if floorOf(between) < first.ID || between.Step != "X1" {
		t.Fatalf("between the writes: step %q floor %d (first job %d)", between.Step, floorOf(between), first.ID)
	}
	wantSeq(t, e.jobSteps(id), []string{"X1/check", "X1/check"})
	wantSeq(t, e.steps(id), []string{"X1", "X1", "X2"})
	if floorOf(op) != floorOf(between) {
		t.Fatalf("floor %d, raised to %d", floorOf(op), floorOf(between))
	}
}

func TestRewind_CrashBetweenTheTwoWritesSubmitsAFreshJob(t *testing.T) {
	e := newEnv(t)
	_, id := e.rewindTable([]step{
		{id: "X1", do: jobStep("check")},
		{id: "X2", do: func(x *job, ctx context.Context) error {
			if _, err := x.awaitJob(ctx, "backup"); err != nil || paramOf(x.op, "rewound") != "" {
				return err
			}
			if err := x.r.patchParams(ctx, &x.op, "rewound", true); err != nil {
				return err
			}
			return &rewind{to: "X1", cause: final("test", errors.New("again"))}
		}},
	})
	var once atomic.Bool
	seamAt(t, func() {
		if once.CompareAndSwap(false, true) {
			runtime.Goexit()
		}
	})
	e.lanes(nil)
	<-e.run(e.runner())
	if op := e.op(id); op.State != "running" || op.Step != "X1" || floorOf(op) == 0 {
		t.Fatalf("after the stop %+v", op)
	}
	e.start(e.runner())
	e.waitState(id, "done")
	wantSeq(t, e.jobSteps(id), []string{"X1/check", "X2/backup", "X2/backup"})
}

func TestRewind_AfterAFailedJobCostsNothingMore(t *testing.T) {
	for _, failed := range []bool{true, false} {
		t.Run(strconv.FormatBool(failed), func(t *testing.T) {
			e := newEnv(t)
			_, id := e.rewindTable([]step{
				{id: "X1", do: jobStep("check")},
				{id: "X2", do: func(x *job, ctx context.Context) error {
					j, ok, err := x.latestJob(ctx)
					switch {
					case err != nil:
						return err
					case ok && j.State == "done":
						return nil
					case ok && j.State == "failed":
						cause, counted := jobCause(j)
						return &rewind{to: "X1", cause: cause, counted: counted}
					}
					return x.submit(ctx, "backup")
				}},
			})
			var at []int
			seamAt(t, func() { at = append(at, e.op(id).Attempts) })
			var n atomic.Int32
			e.lanes(func(j store.Job) jobEnd {
				if j.Kind == "backup" && n.Add(1) == 1 {
					if failed {
						return jobEnd{state: "failed", code: "pgbackrest", msg: "no"}
					}
					return jobEnd{state: "failed", code: "interrupted", msg: "stopped"}
				}
				return okEnd
			})
			e.start(e.runner())
			op := e.waitState(id, "done")
			// pick 1, park 0, pick 1, park 0, the job's end (+1 if counted),
			// pick: 2 or 1; the rewind adds one only when nothing counted.
			want := 2
			if len(at) != 1 || at[0] != want {
				t.Fatalf("attempts after the rewind %v, want %d", at, want)
			}
			wantSeq(t, e.jobSteps(id), []string{"X1/check", "X2/backup", "X1/check", "X2/backup"})
			if op.State != "done" {
				t.Fatalf("op %+v", op)
			}
		})
	}
}

func TestRewind_SameAttemptUsesTheNewFloor_AndAPatchKeepsIt(t *testing.T) {
	e := newEnv(t)
	_, id := e.rewindTable([]step{
		{id: "X1", do: jobStep("check")},
		{id: "X2", do: func(x *job, ctx context.Context) error {
			if paramOf(x.op, "rewound") == "" {
				if err := x.r.patchParams(ctx, &x.op, "rewound", true); err != nil {
					return err
				}
				return &rewind{to: "X1", cause: final("test", errors.New("again"))}
			}
			return x.r.patchParams(ctx, &x.op, "after", 1)
		}},
	})
	e.lanes(nil)
	e.start(e.runner())
	op := e.waitState(id, "done")
	jobs := e.jobsOf(id)
	wantSeq(t, e.jobSteps(id), []string{"X1/check", "X1/check"})
	if floorOf(op) < jobs[0].ID || floorOf(op) >= jobs[1].ID || paramOf(op, "after") != "1" {
		t.Fatalf("params %s, jobs %d %d", op.Params, jobs[0].ID, jobs[1].ID)
	}
}

func TestRewind_WithoutFailedJobCountsAnAttempt(t *testing.T) {
	e := newEnv(t)
	_, id := e.rewindTable([]step{
		{id: "X1", do: jobStep("check")},
		{id: "X2", do: func(x *job, ctx context.Context) error {
			return &rewind{to: "X1", cause: final("rekey", errors.New("re-key refused"))}
		}},
	})
	e.lanes(nil)
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if op.LastError != "rekey: re-key refused" || op.Attempts != 6 || len(e.jobsOf(id)) != 5 {
		t.Fatalf("op %+v, jobs %v", op, e.jobSteps(id))
	}
}

// ───────── the replicate step's bound ─────────

var small = store.ProjectConfig{DiskQuotaMB: 1280, MemMB: 512, GUC: map[string]string{}, Layout: 2} // ReplLoopMax 6

func replEnd(uploaded, adopted int, complete bool) jobEnd {
	stopped := `"caps"`
	if complete {
		stopped = `""`
	}
	b, _ := json.Marshal(map[string]any{"ok": true, "mode": "copy", "complete": complete, "uploaded": uploaded, "adopted": adopted})
	return jobEnd{state: "done", result: strings.TrimSuffix(string(b), "}") + `,"stopped":` + stopped + "}"}
}

func countKind(jobs []store.Job, kind string) int {
	n := 0
	for _, j := range jobs {
		if j.Kind == kind {
			n++
		}
	}
	return n
}

func TestReplicateStep_CountsOnlyJobsAboveTheFloor(t *testing.T) {
	e := newEnv(t)
	e.declared()
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "replicate" {
			return replEnd(1, 0, false)
		}
		return okEnd
	})
	_, id := e.create2(small)
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if n := countKind(e.jobsOf(id), "replicate"); n != 6 || !strings.HasPrefix(op.LastError, "replication_incomplete: ") || op.Step != "5c" {
		t.Fatalf("%d copies, op %+v", n, op)
	}
	must(t, e.st.RetryOperation(context.Background(), id))
	e.wait(id, "failed again", func(op store.Operation) bool { return op.State == "failed" && op.Attempts > 0 })
	if n := countKind(e.jobsOf(id), "replicate"); n != 12 {
		t.Fatalf("%d copies after the retry", n)
	}
}

func TestReplicateStep_AdoptionOnlyJobsAreNotCounted(t *testing.T) {
	for _, uploaded := range []int{0, 1} {
		t.Run(strconv.Itoa(uploaded), func(t *testing.T) {
			e := newEnv(t)
			e.declared()
			var n atomic.Int32
			e.lanes(func(j store.Job) jobEnd {
				if j.Kind != "replicate" {
					return okEnd
				}
				if n.Add(1) <= 8 {
					return replEnd(uploaded, 3, false)
				}
				return replEnd(1, 0, true)
			})
			_, id := e.create2(small)
			e.start(e.runner())
			if uploaded == 0 {
				e.waitState(id, "done")
				if n := countKind(e.jobsOf(id), "replicate"); n != 9 {
					t.Fatalf("%d copies", n)
				}
				return
			}
			op := e.waitState(id, "failed")
			if n := countKind(e.jobsOf(id), "replicate"); n != 6 || !strings.HasPrefix(op.LastError, "replication_incomplete: ") {
				t.Fatalf("%d copies, op %+v", n, op)
			}
		})
	}
}

// Rebuild pages are bounded by the runner's count in the backup state.
func TestReplicateStep_RebuildPagesBounded(t *testing.T) {
	e := newEnv(t)
	e.declared()
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "replicate" {
			sql(t, "update backup_state set rebuild_pages = 2048 where subject = $1", j.Subject)
			return jobEnd{state: "done", result: `{"ok":true,"mode":"rebuild","complete":false,"stopped":"rebuild"}`}
		}
		return okEnd
	})
	_, id := e.create2(layout2)
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if n := countKind(e.jobsOf(id), "replicate"); n != 1 || !strings.HasPrefix(op.LastError, "replication_incomplete: ") {
		t.Fatalf("%d pages, op %+v", n, op)
	}
}

// ───────── abort ─────────

func TestAbort_ParkedCreate_CancelsJobBeforeC1(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create2(layout2)
	r := e.runner()
	stop := e.start(r)
	e.waitState(id, "waiting_job")
	stop()
	e.ag.reset()
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	if op := e.op(id); op.State != "aborting" || op.Attempts != 0 {
		t.Fatalf("after the abort %+v", op)
	}
	e.start(e.runner())
	e.waitState(id, "aborted")
	calls := e.ag.methods("")
	if len(calls) < 2 || calls[0] != "Jobs.Cancel" || calls[1] != "SetRoute" {
		t.Fatalf("calls %v", calls)
	}
	if c := e.ag.callsOf("", "Jobs.Cancel"); c[0].Op != id {
		t.Fatalf("cancelled %+v", c)
	}
	jobs := e.jobsOf(id)
	if len(jobs) != 1 || jobs[0].State != "failed" || jobs[0].Code != "cancelled" {
		t.Fatalf("jobs %+v", jobs)
	}
}

func TestAbort_C6PurgesRepo(t *testing.T) {
	e := newEnv(t)
	e.lanes(nil)
	ref, id := e.create2(layout2)
	e.ag.setErr(failOn("EnsurePostgREST"))
	r := e.runner()
	e.start(r)
	e.waitState(id, "failed")
	e.ag.reset()
	e.ag.setErr(nil)
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	e.waitState(id, "aborted")
	wantSeq(t, e.ag.methods(ref), compensationCalls)
	if c := e.ag.callsOf(ref, "PurgeRepo"); len(c) != 1 {
		t.Fatalf("PurgeRepo %+v", c)
	}
	e.ag.locked(func() {
		if e.ag.repo[ref] {
			t.Fatal("repository left")
		}
	})
	bs, err := e.st.GetBackupState(context.Background(), ref)
	must(t, err)
	if !bs.OffsitePurge {
		t.Fatal("off-site purge not recorded")
	}
	if calls := e.ag.methods(""); calls[0] != "Jobs.Cancel" {
		t.Fatalf("calls %v", calls)
	}
}

// ───────── submit and wiring ─────────

func TestSubmit_RestartRefusedWhileRestoreParked(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	r := e.runner()
	if _, err := r.Submit(context.Background(), "restore", ref, json.RawMessage(`{"to":"latest"}`)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("restore submit: %v", err)
	}
	p := e.project(ref)
	sql(t, "insert into operation (ref, kind, state, epoch, generation) values ($1, 'restore', 'waiting_job', 1, $2)", ref, p.Generation)
	ops, err := e.st.ListOperations(context.Background(), ref)
	must(t, err)
	parked := ops[0]
	if parked.Kind != "restore" {
		t.Fatalf("ops %+v", ops)
	}
	_, err = r.Submit(context.Background(), "restart", ref, mustJSON(t, map[string]any{"base_generation": p.Generation, "config": defaultConfig}))
	if !errors.Is(err, store.ErrConflict) || !strings.Contains(err.Error(), strconv.FormatInt(parked.ID, 10)) {
		t.Fatalf("restart: %v", err)
	}
	if _, err := r.Submit(context.Background(), "delete", ref, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("delete: %v", err)
	}
	// The worker never takes the parked operation.
	stop := e.start(r)
	_, cid := e.create()
	e.waitState(cid, "done")
	stop()
	if op := e.op(parked.ID); op.State != "waiting_job" || op.Attempts != 0 {
		t.Fatalf("parked %+v", op)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	b, err := json.Marshal(v)
	must(t, err)
	return b
}

func TestRunner_NilRecovererOrJobsIsCodeInternal(t *testing.T) {
	e := newEnv(t)
	_, id := e.create2(layout2)
	r := e.runner()
	r.SetJobs(nil)
	e.start(r)
	op := e.waitState(id, "failed")
	if op.Step != "4" || op.Attempts != 1 || !strings.HasPrefix(op.LastError, "internal: ") {
		t.Fatalf("op %+v", op)
	}
	x := &job{r: e.runner()}
	if rc, err := x.recoverer(); err != nil || rc == nil {
		t.Fatalf("recoverer %v %v", rc, err)
	}
	x.r.SetRecoverer(nil)
	if _, err := x.recoverer(); err == nil || code(err) != "internal" {
		t.Fatalf("nil recoverer: %v", err)
	}
	if _, err := x.jobRunner(); err != nil {
		t.Fatalf("jobs: %v", err)
	}
	x.r.SetJobs(nil)
	if _, err := x.jobRunner(); err == nil || code(err) != "internal" {
		t.Fatalf("nil jobs: %v", err)
	}
}

// A copy job that only adopted rows is counted free once, however often the
// step reads it: a worker that stops after the step recorded it, before the
// park, reads the same job again on resume.
func TestReplicateStep_FreeJobCountedOnceAcrossAResume(t *testing.T) {
	e := newEnv(t)
	e.declared()
	var n atomic.Int32
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind != "replicate" {
			return okEnd
		}
		if n.Add(1) == 1 {
			return replEnd(0, 3, false)
		}
		return replEnd(1, 0, false)
	})
	_, id := e.create2(small)
	var once atomic.Bool
	beforePark = func() {
		if countKind(e.jobsOf(id), "replicate") == 1 && once.CompareAndSwap(false, true) {
			runtime.Goexit()
		}
	}
	t.Cleanup(func() { beforePark = func() {} })
	<-e.run(e.runner())
	if !once.Load() || paramOf(e.op(id), "repl_free") == "" {
		t.Fatalf("no stop after the free job: %+v", e.op(id))
	}
	e.start(e.runner())
	op := e.waitState(id, "failed")
	// One free job and ReplLoopMax (6) counted copies.
	if n := countKind(e.jobsOf(id), "replicate"); n != 7 || !strings.HasPrefix(op.LastError, "replication_incomplete: ") {
		t.Fatalf("%d copies, op %+v", n, op)
	}
}

// The free count belongs to one pass: after op retry raises the floor, the
// earlier pass's free jobs give the new pass no extra copies.
func TestReplicateStep_FreeCountStartsAgainAboveANewFloor(t *testing.T) {
	e := newEnv(t)
	e.declared()
	var n atomic.Int32
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind != "replicate" {
			return okEnd
		}
		switch k := n.Add(1); {
		case k <= 4:
			return replEnd(0, 3, false)
		case k == 5:
			return jobEnd{state: "done", result: `{"ok":true,"mode":"copy","complete":false,"stopped":"budget","uploaded":0,"adopted":0}`}
		}
		return replEnd(1, 0, false)
	})
	_, id := e.create2(small)
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if !strings.HasPrefix(op.LastError, "replication_stopped: ") || countKind(e.jobsOf(id), "replicate") != 5 {
		t.Fatalf("first pass: op %+v, jobs %v", op, e.jobSteps(id))
	}
	must(t, e.st.RetryOperation(context.Background(), id))
	op = e.wait(id, "failed again", func(op store.Operation) bool { return op.State == "failed" && op.Attempts > 0 })
	if n := countKind(e.jobsOf(id), "replicate"); n != 5+6 || !strings.HasPrefix(op.LastError, "replication_incomplete: ") {
		t.Fatalf("%d copies in all, op %+v", n, op)
	}
}

// A worker stopped after the rewind's second write, before the step it
// rewound to ran, resumes at that step: the recorded step is the one before.
func TestRewind_StopAfterTheStepWriteResumesAtTheTarget(t *testing.T) {
	e := newEnv(t)
	_, id := e.rewindTable([]step{
		{id: "X0", do: func(*job, context.Context) error { return nil }},
		{id: "X1", do: jobStep("check")},
		{id: "X2", do: func(x *job, ctx context.Context) error {
			if paramOf(x.op, "rewound") != "" {
				return nil
			}
			if err := x.r.patchParams(ctx, &x.op, "rewound", true); err != nil {
				return err
			}
			e.failpoint("restore:X1")
			return &rewind{to: "X1", cause: final("test", errors.New("again"))}
		}},
	})
	e.lanes(nil)
	<-e.run(e.runner())
	if op := e.op(id); op.State != "running" || op.Step != "X0" {
		t.Fatalf("after the stop %+v", op)
	}
	e.start(e.runner())
	e.waitState(id, "done")
	wantSeq(t, e.jobSteps(id), []string{"X1/check", "X1/check"})
}

// Each job carries its kind's lane and deadline at the project's quotas.
func TestSubmit_JobLaneAndDeadline(t *testing.T) {
	e := newEnv(t)
	e.declared()
	e.lanes(nil)
	_, id := e.create2(small)
	e.start(e.runner())
	e.waitState(id, "done")
	for _, kind := range []string{"stanza-create", "backup", "check", "replicate"} {
		lane := "backup"
		if kind == "replicate" {
			lane = "push"
		}
		d, err := bklimit.Deadline(kind, small.DiskQuotaMB, small.DiskQuotaMB)
		must(t, err)
		if n := sqlInt(t, "select count(*) from backup_job where op_id = $1 and kind = $2 and lane = $3 and deadline_s = $4",
			id, kind, lane, int(d/time.Second)); n != 1 {
			t.Fatalf("%s: %d jobs in lane %s with deadline %v", kind, n, lane, d)
		}
	}
}

// A replication the runner skipped (the store left declared after the job
// was queued) completes the step.
func TestReplicateStep_SkippedJobCompletesTheStep(t *testing.T) {
	e := newEnv(t)
	e.declared()
	e.lanes(func(j store.Job) jobEnd {
		if j.Kind == "replicate" {
			return jobEnd{state: "done", result: `{"ok":true,"skipped":"undeclared"}`}
		}
		return okEnd
	})
	_, id := e.create2(layout2)
	e.start(e.runner())
	e.waitState(id, "done")
	if n := countKind(e.jobsOf(id), "replicate"); n != 1 {
		t.Fatalf("%d replication jobs", n)
	}
}

// The rewind's limit, like the start check's, leaves out the attempts given
// back for containment refusals.
func TestRewind_LimitLeavesOutGivenBackAttempts(t *testing.T) {
	e := newEnv(t)
	_, id := e.rewindTable([]step{
		{id: "X1", do: jobStep("check")},
		{id: "X2", do: func(x *job, ctx context.Context) error {
			return &rewind{to: "X1", cause: final("rekey", errors.New("re-key refused"))}
		}},
	})
	sql(t, `update operation set params = '{"requeued":2}' where id = $1`, id)
	e.lanes(nil)
	e.start(e.runner())
	op := e.waitState(id, "failed")
	if op.LastError != "rekey: re-key refused" || op.Attempts != 8 || len(e.jobsOf(id)) != 7 {
		t.Fatalf("op %+v, jobs %v", op, e.jobSteps(id))
	}
}
