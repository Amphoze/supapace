package store

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- helpers ---

// stateRows inserts the backup_state rows a job's subject references.
func stateRows(t *testing.T, s *Store, subjects ...string) {
	t.Helper()
	for _, sub := range subjects {
		sqlExec(t, s, "insert into backup_state (subject) values ($1) on conflict do nothing", sub)
	}
}

func pushJ(subject string) NewJob {
	return NewJob{Subject: subject, Lane: "push", Kind: "push", DeadlineS: 120}
}

func backupJ(subject string) NewJob {
	return NewJob{Subject: subject, Lane: "backup", Kind: "backup", DeadlineS: 710}
}

func jobSubj(n int) string { return fmt.Sprintf("subj%016d", n) }

func submitJ(t *testing.T, s *Store, j NewJob) int64 {
	t.Helper()
	id, err := s.SubmitJob(context.Background(), j)
	must(t, err)
	return id
}

// mustNext picks the next job of lane and requires it to be want.
func mustNext(t *testing.T, s *Store, lane string, want int64) Job {
	t.Helper()
	j, ok, err := s.NextJob(context.Background(), lane)
	must(t, err)
	if !ok {
		t.Fatalf("NextJob(%s): nothing picked, want job %d", lane, want)
	}
	if j.ID != want {
		t.Fatalf("NextJob(%s) = job %d (%s), want %d", lane, j.ID, j.Subject, want)
	}
	return j
}

func noNext(t *testing.T, s *Store, lane string) {
	t.Helper()
	j, ok, err := s.NextJob(context.Background(), lane)
	must(t, err)
	if ok {
		t.Fatalf("NextJob(%s) = job %d (%s), want nothing", lane, j.ID, j.Subject)
	}
}

func jobFinish(t *testing.T, s *Store, id int64, state, code, message string) {
	t.Helper()
	must(t, s.FinishJob(context.Background(), id, state, code, message, nil))
}

// runningOp returns an active project n with a running restore and the
// backup_state row of its subject.
func runningOp(t *testing.T, s *Store, n int) (string, int64) {
	t.Helper()
	ctx := context.Background()
	r := newActive(t, s, n)
	id, _, err := s.SubmitRestore(ctx, r, json.RawMessage(`{"to":"latest"}`))
	must(t, err)
	must(t, s.StartOperation(ctx, id))
	must(t, s.SetProjectRestoring(ctx, r, id))
	stateRows(t, s, r)
	return r, id
}

func jobPark(t *testing.T, s *Store, op int64, j NewJob, step string) int64 {
	t.Helper()
	j.OpStep = step
	id, err := s.SubmitJobAndPark(context.Background(), op, j)
	must(t, err)
	return id
}

// cycle runs one parked pass of op: start, park a push job at step, pick it,
// end it done. It returns the job's id. No other push job may be queued.
func cycle(t *testing.T, s *Store, op int64, subject, step string) int64 {
	t.Helper()
	must(t, s.StartOperation(context.Background(), op))
	id := jobPark(t, s, op, pushJ(subject), step)
	mustNext(t, s, "push", id)
	jobFinish(t, s, id, "done", "", "")
	return id
}

// parkedRunning returns a project n whose restore is parked on a push job
// that a lane has picked.
func parkedRunning(t *testing.T, s *Store, n int) (r string, op, job int64) {
	t.Helper()
	r, op = runningOp(t, s, n)
	job = jobPark(t, s, op, pushJ(r), "T4p")
	mustNext(t, s, "push", job)
	return r, op, job
}

func getJob(t *testing.T, s *Store, id int64) Job {
	t.Helper()
	j, err := scanJob(s.pool.QueryRow(context.Background(), "select "+jobCols+" from backup_job where id = $1", id))
	must(t, err)
	return j
}

func wantAttempts(t *testing.T, s *Store, op int64, state string, attempts int, lastError string) {
	t.Helper()
	o := wantOpState(t, s, op, state)
	if o.Attempts != attempts || o.LastError != lastError {
		t.Fatalf("operation %d: attempts %d, last_error %q; want %d, %q", op, o.Attempts, o.LastError, attempts, lastError)
	}
}

// --- submit and park ---

func TestSubmitJob_Unowned(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	stateRows(t, s, "cp")
	id := submitJ(t, s, NewJob{Subject: "cp", Lane: "push", Kind: "replicate", DeadlineS: 300})
	j := getJob(t, s, id)
	if j.State != "queued" || j.OpID != 0 || j.OpStep != "" || string(j.Params) != "{}" || j.Runs != 0 || j.StartedAt != nil {
		t.Fatalf("job = %+v", j)
	}
	// A job owned by an operation is submitted only by parking it.
	j2 := pushJ("cp")
	j2.OpID = 1
	if _, err := s.SubmitJob(ctx, j2); err == nil {
		t.Fatal("SubmitJob with an operation accepted")
	}
	// A subject without a backup_state row.
	_, err := s.SubmitJob(ctx, pushJ(jobSubj(1)))
	wantErr(t, err, ErrNotFound)
}

func TestSubmitJob_LaneOfKind(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	stateRows(t, s, "cp")
	for _, c := range []struct {
		lane, kind string
		ok         bool
	}{
		{"push", "push", true}, {"push", "replicate", true}, {"backup", "backup", true}, {"backup", "fetch", true},
		{"backup", "push", false}, {"backup", "replicate", false}, {"push", "backup", false}, {"push", "seed", false},
	} {
		_, err := s.SubmitJob(ctx, NewJob{Subject: "cp", Lane: c.lane, Kind: c.kind, DeadlineS: 60})
		if (err == nil) != c.ok {
			t.Errorf("lane %s kind %s: err = %v, want ok %v", c.lane, c.kind, err, c.ok)
		}
	}
}

func TestSubmitJobAndPark_Atomic(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op := runningOp(t, s, 1)
	wantAttempts(t, s, op, "running", 1, "")
	id := jobPark(t, s, op, pushJ(r), "T4p")
	wantAttempts(t, s, op, "waiting_job", 0, "")
	j := getJob(t, s, id)
	if j.State != "queued" || j.OpID != op || j.OpStep != "T4p" || j.Subject != r || j.DeadlineS != 120 {
		t.Fatalf("job = %+v", j)
	}
	// Not running any more: refused, nothing inserted.
	_, err := s.SubmitJobAndPark(ctx, op, pushJ(r))
	wantErr(t, err, ErrConflict)
	if n := count(t, s, "select count(*) from backup_job where op_id = $1", op); n != 1 {
		t.Fatalf("%d jobs of the operation, want 1", n)
	}
	wantAttempts(t, s, op, "waiting_job", 0, "")
	// The insert fails (no backup_state row): the operation stays running.
	r2 := newActive(t, s, 2)
	op2, _, err := s.SubmitRestore(ctx, r2, nil)
	must(t, err)
	must(t, s.StartOperation(ctx, op2))
	_, err = s.SubmitJobAndPark(ctx, op2, pushJ(r2))
	wantErr(t, err, ErrNotFound)
	wantAttempts(t, s, op2, "running", 1, "")
	// No such operation.
	_, err = s.SubmitJobAndPark(ctx, op2+100, pushJ(r))
	wantErr(t, err, ErrNotFound)
}

// --- finish ---

func TestFinishJob_DoneResumesWithoutCount(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	_, op, job := parkedRunning(t, s, 1)
	sqlExec(t, s, "update operation set last_error = 'earlier: e', not_before = now() + interval '1 hour' where id = $1", op)
	must(t, s.FinishJob(ctx, job, "done", "", "", json.RawMessage(`{"complete": true}`)))
	wantAttempts(t, s, op, "pending", 0, "earlier: e")
	if o := opState(t, s, op); o.NotBefore.After(time.Now()) {
		t.Fatalf("not_before %v is in the future", o.NotBefore)
	}
	j := getJob(t, s, job)
	if j.State != "done" || j.Code != "" || j.FinishedAt == nil || string(j.Result) != `{"complete": true}` {
		t.Fatalf("job = %+v, result %s", j, j.Result)
	}
	// Only a running job ends, only as done or failed.
	wantErr(t, s.FinishJob(ctx, job, "failed", "deadline", "", nil), ErrConflict)
	wantAttempts(t, s, op, "pending", 0, "earlier: e")
	wantErr(t, s.FinishJob(ctx, job+100, "done", "", "", nil), ErrNotFound)
	// A bad final state, refused before anything is written.
	_, op2, job2 := parkedRunning(t, s, 2)
	if err := s.FinishJob(ctx, job2, "queued", "", "", nil); err == nil {
		t.Fatal("FinishJob to queued accepted")
	}
	if st, _ := jobState(t, s, job2); st != "running" {
		t.Fatalf("job is %s", st)
	}
	wantOpState(t, s, op2, "waiting_job")
}

func TestFinishJob_FailedCountsOne(t *testing.T) {
	s := newStore(t, testConfig())
	_, op, job := parkedRunning(t, s, 1)
	jobFinish(t, s, job, "failed", "stanza_mismatch", "the stanza is not this project's")
	wantAttempts(t, s, op, "pending", 1, "stanza_mismatch: the stanza is not this project's")
	if j := getJob(t, s, job); j.State != "failed" || j.Code != "stanza_mismatch" || j.Result != nil {
		t.Fatalf("job = %+v, result %q", j, j.Result)
	}
}

func TestFinishJob_DeadlineCountsOne(t *testing.T) {
	s := newStore(t, testConfig())
	_, op, job := parkedRunning(t, s, 1)
	jobFinish(t, s, job, "failed", "deadline", "ran past 120 s")
	wantAttempts(t, s, op, "pending", 1, "deadline: ran past 120 s")
}

func TestFinishJob_InterruptedDoesNotCount(t *testing.T) {
	s := newStore(t, testConfig())
	for i, code := range []string{"interrupted", "cancelled"} {
		_, op, job := parkedRunning(t, s, 1+i)
		sqlExec(t, s, "update operation set last_error = 'earlier: e' where id = $1", op)
		jobFinish(t, s, job, "failed", code, "x")
		wantAttempts(t, s, op, "pending", 0, "earlier: e")
	}
	// Control, same path: any other failure counts.
	_, op, job := parkedRunning(t, s, 3)
	jobFinish(t, s, job, "failed", "crashed", "x")
	wantAttempts(t, s, op, "pending", 1, "crashed: x")
}

// A delete's jobs are its final, best-effort ones: a failure costs the
// delete no attempt and leaves its last_error; the control, the same path
// with another kind, counts one.
func TestFinishJob_DeleteJobFailureCountsNone(t *testing.T) {
	s := newStore(t, testConfig())
	_, op, job := parkedRunning(t, s, 1)
	sqlExec(t, s, "update operation set kind = 'delete', last_error = 'earlier: e' where id = $1", op)
	jobFinish(t, s, job, "failed", "pgbackrest", "backup failed")
	wantAttempts(t, s, op, "pending", 0, "earlier: e")
	_, op, job = parkedRunning(t, s, 2)
	jobFinish(t, s, job, "failed", "pgbackrest", "backup failed")
	wantAttempts(t, s, op, "pending", 1, "pgbackrest: backup failed")
}

func TestFinishJob_CountsOnlyOnTheWaitingJobTransition(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()

	// An aborting create.
	rc := ref(1)
	create := mustCreate(t, s, rc)
	must(t, s.StartOperation(ctx, create))
	stateRows(t, s, rc)
	jc := jobPark(t, s, create, backupJ(rc), "5")
	mustNext(t, s, "backup", jc)
	_, err := s.RequestAbort(ctx, rc)
	must(t, err)
	before := opState(t, s, create)
	jobFinish(t, s, jc, "failed", "deadline", "x")
	after := wantOpState(t, s, create, "aborting")
	if after.Attempts != before.Attempts || after.LastError != before.LastError || !after.NotBefore.Equal(before.NotBefore) {
		t.Fatalf("aborting create changed: %+v -> %+v", before, after)
	}

	// A superseded restore.
	rr, restore, jr := parkedRunning(t, s, 2)
	sqlExec(t, s, "update operation set state = 'failed' where id = $1", restore)
	_, sup, err := s.SubmitRestore(ctx, rr, nil)
	must(t, err)
	if sup != restore {
		t.Fatalf("superseded %d, want %d", sup, restore)
	}
	before = opState(t, s, restore)
	jobFinish(t, s, jr, "failed", "deadline", "x")
	after = wantOpState(t, s, restore, "superseded")
	if after.Attempts != before.Attempts || after.LastError != before.LastError {
		t.Fatalf("superseded restore changed: %+v -> %+v", before, after)
	}

	// Control: a parked one is resumed and counted.
	_, op, job := parkedRunning(t, s, 3)
	jobFinish(t, s, job, "failed", "deadline", "x")
	wantAttempts(t, s, op, "pending", 1, "deadline: x")
}

func TestFiveFailedJobsFailOperation(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op := runningOp(t, s, 1)
	rDone, opDone := runningOp(t, s, 2)
	must(t, s.FinishOperation(ctx, op, "failed", "")) // both start from StartOperation below
	must(t, s.RetryOperation(ctx, op))
	must(t, s.FinishOperation(ctx, opDone, "failed", ""))
	must(t, s.RetryOperation(ctx, opDone))
	for i := 1; i <= 5; i++ {
		must(t, s.StartOperation(ctx, op))
		id := jobPark(t, s, op, pushJ(r), "T4p")
		mustNext(t, s, "push", id)
		jobFinish(t, s, id, "failed", "backup_failed", fmt.Sprintf("run %d", i))
		wantAttempts(t, s, op, "pending", i, fmt.Sprintf("backup_failed: run %d", i))

		cycle(t, s, opDone, rDone, "T4p")
		wantAttempts(t, s, opDone, "pending", 0, "")
	}
	// The next start is the sixth counted attempt: the worker ends the
	// operation with the stored cause.
	must(t, s.StartOperation(ctx, op))
	o := opState(t, s, op)
	if o.Attempts <= 5 {
		t.Fatalf("attempts %d after five failed jobs", o.Attempts)
	}
	must(t, s.FinishOperation(ctx, op, "failed", o.LastError))
	wantAttempts(t, s, op, "failed", 6, "backup_failed: run 5")
	// Control: jobs that ended done never add up.
	must(t, s.StartOperation(ctx, opDone))
	wantAttempts(t, s, opDone, "running", 1, "")
}

// --- pick ---

func TestNextJob_OnePerSubject(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for i := 0; i < 40; i++ {
		sub := jobSubj(i)
		stateRows(t, s, sub)
		lanes := [2]string{"push", "backup"}
		if i%2 == 0 { // two workers of one lane
			lanes[1] = "push"
			submitJ(t, s, pushJ(sub))
			submitJ(t, s, pushJ(sub))
		} else { // one worker of each lane
			submitJ(t, s, pushJ(sub))
			submitJ(t, s, backupJ(sub))
		}
		got := make([]Job, 2)
		oks := make([]bool, 2)
		errs := race(2, func(k int) (err error) {
			got[k], oks[k], err = s.NextJob(ctx, lanes[k])
			return err
		})
		for _, err := range errs {
			must(t, err)
		}
		if oks[0] == oks[1] {
			t.Fatalf("round %d (%v): picked %v, want exactly one", i, lanes, oks)
		}
		if n := count(t, s, "select count(*) from backup_job where subject = $1 and state = 'running'", sub); n != 1 {
			t.Fatalf("round %d: %d running jobs of the subject", i, n)
		}
		for k := range got {
			if oks[k] {
				jobFinish(t, s, got[k].ID, "done", "", "")
			}
		}
		sqlExec(t, s, "update backup_job set state = 'failed', code = 'cancelled', finished_at = now() where subject = $1 and state = 'queued'", sub)
	}
}

// The other lane's pick of the same subject, not yet committed when this
// lane's pick reaches the slot index: this lane picks nothing, without an
// error, and the subject has one running job. Control: when that pick rolls
// back, this lane's job is picked.
func TestNextJob_SlotViolationIsNothingPicked(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for _, commit := range []bool{true, false} {
		sub := jobSubj(1)
		if !commit {
			sub = jobSubj(2)
		}
		stateRows(t, s, sub)
		pj := submitJ(t, s, pushJ(sub))
		bj := submitJ(t, s, backupJ(sub))
		tx, err := s.pool.Begin(ctx)
		must(t, err)
		if _, err := scanJob(tx.QueryRow(ctx, pickJob, "push")); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		type res struct {
			j   Job
			ok  bool
			err error
		}
		done := make(chan res, 1)
		go func() {
			j, ok, err := s.NextJob(ctx, "backup")
			done <- res{j, ok, err}
		}()
		// Wait until the backup lane's pick waits on the uncommitted slot.
		deadline := time.Now().Add(60 * time.Second)
		for count(t, s, `select count(*) from pg_stat_activity where wait_event_type = 'Lock'
			and query like 'update backup_job set state = ''running''%'`) == 0 {
			if time.Now().After(deadline) {
				tx.Rollback(ctx)
				t.Fatal("the second pick never waited on the slot")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if commit {
			must(t, tx.Commit(ctx))
		} else {
			must(t, tx.Rollback(ctx))
		}
		r := <-done
		must(t, r.err)
		switch {
		case commit && r.ok:
			t.Fatalf("picked job %d beside the other lane's running job", r.j.ID)
		case !commit && (!r.ok || r.j.ID != bj):
			t.Fatalf("after the rollback: picked %v job %d, want %d", r.ok, r.j.ID, bj)
		}
		if n := count(t, s, "select count(*) from backup_job where subject = $1 and state = 'running'", sub); n != 1 {
			t.Fatalf("%d running jobs of the subject, want 1", n)
		}
		if st, _ := jobState(t, s, map[bool]int64{true: bj, false: pj}[commit]); st != "queued" {
			t.Fatalf("the losing job is %s, want queued", st)
		}
	}
}

// A pick never waits for another worker's pick in flight: it passes over
// the job that pick holds.
func TestNextJob_PassesOverAPickInFlight(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	stateRows(t, s, jobSubj(1), jobSubj(2))
	submitJ(t, s, pushJ(jobSubj(1)))
	other := submitJ(t, s, pushJ(jobSubj(2)))
	tx, err := s.pool.Begin(ctx)
	must(t, err)
	defer tx.Rollback(ctx)
	if _, err := scanJob(tx.QueryRow(ctx, pickJob, "push")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		j, ok, err := s.NextJob(ctx, "push")
		if err == nil && (!ok || j.ID != other) {
			err = fmt.Errorf("picked %v job %d, want %d", ok, j.ID, other)
		}
		done <- err
	}()
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(60 * time.Second):
		t.Fatal("the pick waited for the pick in flight")
	}
}

func TestNextJob_ControlPlaneFirst(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	stateRows(t, s, "cp", jobSubj(1), jobSubj(2))
	p1 := submitJ(t, s, pushJ(jobSubj(1)))
	cp1 := submitJ(t, s, pushJ("cp"))
	mustNext(t, s, "push", cp1)
	jobFinish(t, s, cp1, "done", "", "")
	// The control plane has just run and the others never have: cp still first.
	p2 := submitJ(t, s, pushJ(jobSubj(2)))
	cp2 := submitJ(t, s, pushJ("cp"))
	mustNext(t, s, "push", cp2)
	mustNext(t, s, "push", p1)
	mustNext(t, s, "push", p2)
	if _, ok, err := s.NextJob(ctx, "push"); err != nil || ok {
		t.Fatalf("a fourth pick: %v %v", ok, err)
	}
}

func TestNextJob_RoundRobin(t *testing.T) {
	s := newStore(t, testConfig())
	const k, per = 4, 5
	for i := 0; i < k; i++ {
		stateRows(t, s, jobSubj(i))
		for n := 0; n < per; n++ { // subject 0 holds the lowest ids
			submitJ(t, s, pushJ(jobSubj(i)))
		}
	}
	for round := 0; round < per; round++ {
		seen := map[string]bool{}
		for n := 0; n < k; n++ {
			j, ok, err := s.NextJob(context.Background(), "push")
			must(t, err)
			if !ok {
				t.Fatalf("round %d: nothing picked", round)
			}
			if seen[j.Subject] {
				t.Fatalf("round %d: %s served twice before every subject once (%v)", round, j.Subject, seen)
			}
			seen[j.Subject] = true
			jobFinish(t, s, j.ID, "done", "", "")
		}
	}
	noNext(t, s, "push")
}

func TestNextJob_SlotOwnerOnly(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op := runningOp(t, s, 1)
	must(t, s.SetSlot(ctx, r, op))
	scheduled := submitJ(t, s, pushJ(r))
	owned := jobPark(t, s, op, pushJ(r), "T4p")
	mustNext(t, s, "push", owned)
	jobFinish(t, s, owned, "done", "", "")
	noNext(t, s, "push")
	// Control: the slot freed, the scheduled job is picked.
	must(t, s.ClearSlot(ctx, r, op))
	mustNext(t, s, "push", scheduled)
}

func TestNextJob_LanesIndependent(t *testing.T) {
	s := newStore(t, testConfig())
	a, b, c := jobSubj(1), jobSubj(2), jobSubj(3)
	stateRows(t, s, a, b, c)
	pa := submitJ(t, s, pushJ(a))
	pb := submitJ(t, s, pushJ(b))
	bc := submitJ(t, s, backupJ(c))
	// Each lane takes only its own jobs, whatever the other has queued.
	mustNext(t, s, "backup", bc)
	noNext(t, s, "backup")
	mustNext(t, s, "push", pa)
	mustNext(t, s, "push", pb)
	noNext(t, s, "push")
	if j := getJob(t, s, pa); j.State != "running" || j.Runs != 1 || j.StartedAt == nil {
		t.Fatalf("picked job = %+v", j)
	}
	// The subject's slot spans both lanes.
	ba := submitJ(t, s, backupJ(a))
	jobFinish(t, s, bc, "done", "", "")
	noNext(t, s, "backup")
	jobFinish(t, s, pa, "done", "", "")
	mustNext(t, s, "backup", ba)
}

func TestInterruptJobs(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op, _ := parkedRunning(t, s, 1)
	stateRows(t, s, "cp", jobSubj(9))
	free := submitJ(t, s, backupJ("cp"))
	mustNext(t, s, "backup", free)
	queued := submitJ(t, s, backupJ(jobSubj(9)))
	sqlExec(t, s, "update operation set last_error = 'earlier: e' where id = $1", op)
	n, err := s.InterruptJobs(ctx)
	must(t, err)
	if n != 2 {
		t.Fatalf("interrupted %d jobs, want 2", n)
	}
	wantAttempts(t, s, op, "pending", 0, "earlier: e")
	if st, code := jobState(t, s, free); st != "failed" || code != "interrupted" {
		t.Fatalf("unowned job %s %s", st, code)
	}
	if st, _ := jobState(t, s, queued); st != "queued" {
		t.Fatalf("queued job is %s", st)
	}
	// No limit of its own: interrupted again and again, never counted, never failed.
	for i := 0; i < 6; i++ {
		must(t, s.StartOperation(ctx, op))
		id := jobPark(t, s, op, pushJ(r), "T4p")
		mustNext(t, s, "push", id)
		n, err := s.InterruptJobs(ctx)
		must(t, err)
		if n != 1 {
			t.Fatalf("interrupted %d jobs, want 1", n)
		}
		wantAttempts(t, s, op, "pending", 0, "earlier: e")
	}
	if n := count(t, s, "select count(*) from backup_job where state = 'running'"); n != 0 {
		t.Fatalf("%d running jobs left", n)
	}
	if n := count(t, s, "select count(*) from backup_job where runs <> 1 and state <> 'queued'"); n != 0 {
		t.Fatalf("%d jobs ran more than once", n)
	}
}

// --- which job belongs to a step ---

func TestLatestJob_IgnoresJobsAtOrBelowFloor(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op := runningOp(t, s, 1)
	must(t, s.FinishOperation(ctx, op, "failed", ""))
	must(t, s.RetryOperation(ctx, op))
	j1 := cycle(t, s, op, r, "T4p")
	must(t, s.StartOperation(ctx, op))
	floor, _, err := s.RaiseJobFloor(ctx, op, false)
	must(t, err)
	if floor != j1 {
		t.Fatalf("floor %d, want %d", floor, j1)
	}
	if j, ok, err := s.LatestJob(ctx, op, "T4p", floor); err != nil || ok {
		t.Fatalf("LatestJob at the floor = %d %v %v, want none", j.ID, ok, err)
	}
	// Control: below the floor it is found.
	if j, ok, err := s.LatestJob(ctx, op, "T4p", floor-1); err != nil || !ok || j.ID != j1 {
		t.Fatalf("LatestJob below the floor = %d %v %v, want %d", j.ID, ok, err, j1)
	}
	j2 := jobPark(t, s, op, pushJ(r), "T4p")
	if j, ok, err := s.LatestJob(ctx, op, "T4p", floor); err != nil || !ok || j.ID != j2 || j.State != "queued" {
		t.Fatalf("LatestJob = %+v %v %v, want %d", j, ok, err, j2)
	}
}

func TestLatestJob_NewestOfStepAboveFloor(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op := runningOp(t, s, 1)
	must(t, s.FinishOperation(ctx, op, "failed", ""))
	must(t, s.RetryOperation(ctx, op))
	r2, op2 := runningOp(t, s, 2)
	must(t, s.FinishOperation(ctx, op2, "failed", ""))
	must(t, s.RetryOperation(ctx, op2))
	cycle(t, s, op, r, "T4p")
	t5 := cycle(t, s, op, r, "T5")
	t4 := cycle(t, s, op, r, "T4p")
	cycle(t, s, op2, r2, "T4p") // another operation's, newer
	for _, c := range []struct {
		step string
		want int64
	}{{"T4p", t4}, {"T5", t5}} {
		j, ok, err := s.LatestJob(ctx, op, c.step, 0)
		if err != nil || !ok || j.ID != c.want || j.OpID != op || j.OpStep != c.step || j.State != "done" {
			t.Fatalf("LatestJob(%s) = %+v %v %v, want %d", c.step, j, ok, err, c.want)
		}
	}
	if _, ok, err := s.LatestJob(ctx, op, "T6", 0); err != nil || ok {
		t.Fatalf("LatestJob of a step without jobs: %v %v", ok, err)
	}
}

func TestCountJobs_AboveFloorOnly(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op := runningOp(t, s, 1)
	must(t, s.FinishOperation(ctx, op, "failed", ""))
	must(t, s.RetryOperation(ctx, op))
	r2, op2 := runningOp(t, s, 2)
	must(t, s.FinishOperation(ctx, op2, "failed", ""))
	must(t, s.RetryOperation(ctx, op2))
	j1 := cycle(t, s, op, r, "T4p")
	cycle(t, s, op, r, "T4p")
	cycle(t, s, op, r, "T5")
	j3 := cycle(t, s, op, r, "T4p")
	cycle(t, s, op2, r2, "T4p")
	for _, c := range []struct {
		floor int64
		want  int
	}{{0, 3}, {j1 - 1, 3}, {j1, 2}, {j3 - 1, 1}, {j3, 0}} {
		n, err := s.CountJobs(ctx, op, "T4p", c.floor)
		must(t, err)
		if n != c.want {
			t.Errorf("CountJobs(T4p, floor %d) = %d, want %d", c.floor, n, c.want)
		}
	}
}

func TestLastJob_NewestOfKindAnyState(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	stateRows(t, s, "cp", jobSubj(1))
	submitJ(t, s, pushJ("cp"))
	b1 := submitJ(t, s, backupJ("cp"))
	submitJ(t, s, pushJ(jobSubj(1)))
	p2 := submitJ(t, s, pushJ("cp"))
	mustNext(t, s, "backup", b1)
	jobFinish(t, s, b1, "failed", "deadline", "x")
	if j, ok, err := s.LastJob(ctx, "cp", "push"); err != nil || !ok || j.ID != p2 || j.State != "queued" {
		t.Fatalf("LastJob(cp, push) = %+v %v %v, want %d", j, ok, err, p2)
	}
	if j, ok, err := s.LastJob(ctx, "cp", "backup"); err != nil || !ok || j.ID != b1 || j.Code != "deadline" || j.Message != "x" {
		t.Fatalf("LastJob(cp, backup) = %+v %v %v, want %d", j, ok, err, b1)
	}
	if _, ok, err := s.LastJob(ctx, "cp", "seed"); err != nil || ok {
		t.Fatalf("LastJob of a kind never submitted: %v %v", ok, err)
	}
}

// --- cancel and prune ---

func TestCancelJobs_QueuedCancelled_RunningReturnedUntouched(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op := runningOp(t, s, 1)
	r2, op2 := runningOp(t, s, 2)
	running := addJob(t, s, r, op, "running")
	queued := addJob(t, s, r, op, "queued")
	other := addJob(t, s, r2, op2, "queued")
	got, err := s.CancelJobs(ctx, op)
	must(t, err)
	if len(got) != 1 || got[0].ID != running || got[0].State != "running" {
		t.Fatalf("returned %+v, want job %d running", got, running)
	}
	if st, _ := jobState(t, s, running); st != "running" {
		t.Fatalf("running job is %s", st)
	}
	if st, code := jobState(t, s, queued); st != "failed" || code != "cancelled" {
		t.Fatalf("queued job %s %s", st, code)
	}
	if j := getJob(t, s, queued); j.FinishedAt == nil {
		t.Fatal("cancelled job has no finished_at")
	}
	if st, _ := jobState(t, s, other); st != "queued" {
		t.Fatalf("another operation's job is %s", st)
	}
	wantOpState(t, s, op, "running")
}

func TestCancelSubjectJobs_EverySubmitter(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op := runningOp(t, s, 1)
	stateRows(t, s, "cp")
	scheduled := submitJ(t, s, backupJ(r))
	owned := addJob(t, s, r, op, "queued")
	running := addJob(t, s, r, 0, "running")
	cp := submitJ(t, s, pushJ("cp"))
	cpOwned := addJob(t, s, "cp", op, "queued") // the operation's job of another subject
	got, err := s.CancelSubjectJobs(ctx, r)
	must(t, err)
	if len(got) != 1 || got[0].ID != running {
		t.Fatalf("returned %+v, want job %d", got, running)
	}
	for _, id := range []int64{scheduled, owned} {
		if st, code := jobState(t, s, id); st != "failed" || code != "cancelled" {
			t.Fatalf("job %d %s %s", id, st, code)
		}
	}
	for id, want := range map[int64]string{running: "running", cp: "queued", cpOwned: "queued"} {
		if st, _ := jobState(t, s, id); st != want {
			t.Fatalf("job %d is %s, want %s", id, st, want)
		}
	}
}

func TestPruneJobs_KeepsSetJobsAndOpenOperations_AtMostLimit(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, open := runningOp(t, s, 1)
	r2, closed := runningOp(t, s, 2)
	must(t, s.FinishOperation(ctx, closed, "failed", ""))
	old := time.Now().Add(-72 * time.Hour)
	end := func(id int64, state string, at time.Time) int64 {
		sqlExec(t, s, "update backup_job set state = $2, finished_at = $3 where id = $1", id, state, at)
		return id
	}
	var gone []int64
	for i := 0; i < 4; i++ {
		gone = append(gone, end(submitJ(t, s, pushJ(r)), "done", old))
	}
	gone = append(gone, end(addJob(t, s, r2, closed, "queued"), "failed", old))
	setJob := end(submitJ(t, s, backupJ(r)), "done", old)
	sqlExec(t, s, `insert into backup_set (subject, label, tli, start_segment, stop_segment, start_lsn, stop_lsn, start_at, stop_at, job_id)
		values ($1, '20261119-120000F', 1, '000000010000000000000001', '000000010000000000000002', '0/1000000', '0/2000000', now(), now(), $2)`, r, setJob)
	openJob := end(addJob(t, s, r, open, "queued"), "failed", old)
	recent := end(submitJ(t, s, pushJ(r)), "done", time.Now())
	queued := submitJ(t, s, pushJ(r2))
	sqlExec(t, s, "update backup_job set created_at = $2 where id = $1", queued, old)
	cutoff := time.Now().Add(-48 * time.Hour)

	n, err := s.PruneJobs(ctx, cutoff, 3)
	must(t, err)
	if n != 3 {
		t.Fatalf("pruned %d, want 3 (the limit)", n)
	}
	n, err = s.PruneJobs(ctx, cutoff, 3)
	must(t, err)
	if n != 2 {
		t.Fatalf("pruned %d, want the 2 left", n)
	}
	if n, err := s.PruneJobs(ctx, cutoff, 3); err != nil || n != 0 {
		t.Fatalf("third prune: %d %v", n, err)
	}
	for _, id := range gone {
		if count(t, s, "select count(*) from backup_job where id = $1", id) != 0 {
			t.Fatalf("job %d kept", id)
		}
	}
	for _, id := range []int64{setJob, openJob, recent, queued} {
		if count(t, s, "select count(*) from backup_job where id = $1", id) != 1 {
			t.Fatalf("job %d pruned", id)
		}
	}
	// The open operation ends: its job goes at the next prune.
	must(t, s.FinishOperation(ctx, open, "failed", ""))
	if n, err := s.PruneJobs(ctx, cutoff, 3); err != nil || n != 1 {
		t.Fatalf("prune after the operation ended: %d %v", n, err)
	}
}

// Eight workers, four per lane, race over 50 subjects and 3,000 jobs: every
// job is picked exactly once and ends done, no subject ever has two jobs
// running at once, and no pick fails.
func TestNextJob_RaceManyWorkersManySubjects(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	const subjects, jobs, perLane = 50, 3000, 4
	subs := []string{"cp"}
	for i := 1; i < subjects; i++ {
		subs = append(subs, jobSubj(i))
	}
	stateRows(t, s, subs...)
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < jobs; i++ {
		sub := subs[rng.Intn(len(subs))]
		if rng.Intn(2) == 0 {
			submitJ(t, s, pushJ(sub))
		} else {
			submitJ(t, s, backupJ(sub))
		}
	}
	var (
		mu       sync.Mutex
		busy     = map[string]int64{}
		picked   = map[int64]bool{}
		finished atomic.Int64
		empty    atomic.Int64
	)
	deadline := time.Now().Add(20 * time.Minute)
	errs := race(2*perLane, func(w int) error {
		lane := map[bool]string{true: "push", false: "backup"}[w < perLane]
		for finished.Load() < jobs && time.Now().Before(deadline) {
			j, ok, err := s.NextJob(ctx, lane)
			if err != nil {
				return err
			}
			if !ok {
				empty.Add(1)
				time.Sleep(time.Millisecond)
				continue
			}
			mu.Lock()
			if other, held := busy[j.Subject]; held {
				mu.Unlock()
				t.Errorf("job %d of %s picked while job %d of it runs", j.ID, j.Subject, other)
				return nil
			}
			if picked[j.ID] || j.Lane != lane {
				mu.Unlock()
				t.Errorf("job %d picked twice or by lane %s", j.ID, lane)
				return nil
			}
			busy[j.Subject], picked[j.ID] = j.ID, true
			mu.Unlock()
			time.Sleep(time.Duration(rand.Intn(500)) * time.Microsecond)
			// The subject is marked free before its job ends, so a pick
			// seen while it is marked busy is a real overlap.
			mu.Lock()
			delete(busy, j.Subject)
			mu.Unlock()
			if err := s.FinishJob(ctx, j.ID, "done", "", "", nil); err != nil {
				return err
			}
			finished.Add(1)
		}
		return nil
	})
	for _, err := range errs {
		must(t, err)
	}
	if n := count(t, s, "select count(*) from backup_job where state = 'done' and runs = 1"); n != jobs || len(picked) != jobs {
		t.Fatalf("%d jobs done once, %d picked, want %d", n, len(picked), jobs)
	}
	t.Logf("%d picks, %d empty answers", jobs, empty.Load())
}

// Two workers of one lane asking at the same moment, with several subjects
// queued: the second takes another subject's job instead of colliding on the
// first subject's slot and picking nothing.
func TestNextJob_SameLaneWorkersDoNotCollide(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	const subjects, per, rounds = 20, 6, 40
	for i := 0; i < subjects; i++ {
		stateRows(t, s, jobSubj(i))
		for n := 0; n < per; n++ {
			submitJ(t, s, pushJ(jobSubj(i)))
		}
	}
	lost := 0
	for r := 0; r < rounds; r++ {
		got := make([]Job, 2)
		oks := make([]bool, 2)
		for _, err := range race(2, func(k int) (err error) {
			got[k], oks[k], err = s.NextJob(ctx, "push")
			return err
		}) {
			must(t, err)
		}
		for k := range got {
			if oks[k] {
				jobFinish(t, s, got[k].ID, "done", "", "")
			} else {
				lost++
			}
		}
	}
	if lost != 0 {
		t.Fatalf("%d of %d picks found nothing while %d subjects had queued jobs", lost, 2*rounds, subjects)
	}
}

// A parked operation is open: its finished jobs are kept, however old.
func TestPruneJobs_KeepsJobsOfAParkedOperation(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op := runningOp(t, s, 1)
	first := cycle(t, s, op, r, "T4p")
	must(t, s.StartOperation(ctx, op))
	jobPark(t, s, op, pushJ(r), "T4p")
	wantOpState(t, s, op, "waiting_job")
	sqlExec(t, s, "update backup_job set finished_at = now() - interval '72 hours' where id = $1", first)
	if n, err := s.PruneJobs(ctx, time.Now().Add(-48*time.Hour), 10); err != nil || n != 0 {
		t.Fatalf("pruned %d (%v) while the operation is parked", n, err)
	}
	if count(t, s, "select count(*) from backup_job where id = $1", first) != 1 {
		t.Fatalf("job %d of the parked operation pruned", first)
	}
}

func TestCountInterruptedJobs_ThatCodeStepAndOperationAboveFloor(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op := runningOp(t, s, 1)
	r2, op2 := runningOp(t, s, 2)
	end := func(id int64, state, code, step string) int64 {
		sqlExec(t, s, "update backup_job set state = $2, code = nullif($3, ''), op_step = $4, finished_at = now() where id = $1",
			id, state, code, step)
		return id
	}
	a := end(addJob(t, s, r, op, "queued"), "failed", "interrupted", "T4p")
	end(addJob(t, s, r, op, "queued"), "failed", "deadline", "T4p")
	end(addJob(t, s, r, op, "queued"), "failed", "cancelled", "T4p")
	end(addJob(t, s, r, op, "queued"), "done", "", "T4p")
	b := end(addJob(t, s, r, op, "queued"), "failed", "interrupted", "T4p")
	end(addJob(t, s, r, op, "queued"), "failed", "interrupted", "T5")
	end(addJob(t, s, r2, op2, "queued"), "failed", "interrupted", "T4p")
	for _, c := range []struct {
		op    int64
		step  string
		floor int64
		want  int
	}{{op, "T4p", 0, 2}, {op, "T4p", a - 1, 2}, {op, "T4p", a, 1}, {op, "T4p", b, 0}, {op, "T5", 0, 1}, {op2, "T4p", 0, 1}, {op2, "T5", 0, 0}} {
		n, err := s.CountInterruptedJobs(ctx, c.op, c.step, c.floor)
		must(t, err)
		if n != c.want {
			t.Errorf("CountInterruptedJobs(%d, %s, %d) = %d, want %d", c.op, c.step, c.floor, n, c.want)
		}
	}
}

func TestFinishJob_FailedNeedsACode(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	_, op, job := parkedRunning(t, s, 1)
	if err := s.FinishJob(ctx, job, "failed", "", "no code", nil); err == nil {
		t.Fatal("a failure without a code accepted")
	}
	if st, _ := jobState(t, s, job); st != "running" {
		t.Fatalf("job is %s", st)
	}
	wantAttempts(t, s, op, "waiting_job", 0, "")
	// Control: with a code it is recorded.
	jobFinish(t, s, job, "failed", "crashed", "x")
	wantAttempts(t, s, op, "pending", 1, "crashed: x")
}

func TestFinishJob_InvalidResultRecordedCrashed(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, op, job := parkedRunning(t, s, 1)
	err := s.FinishJob(ctx, job, "done", "", "", json.RawMessage(`{"complete": tru`))
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("job %d", job)) {
		t.Fatalf("error = %v, want one naming job %d", err, job)
	}
	j := getJob(t, s, job)
	if j.State != "failed" || j.Code != "crashed" || j.Result != nil || j.FinishedAt == nil {
		t.Fatalf("job = %+v, result %q", j, j.Result)
	}
	o := wantOpState(t, s, op, "pending")
	if o.Attempts != 1 || !strings.HasPrefix(o.LastError, "crashed: ") {
		t.Fatalf("operation: attempts %d, last_error %q", o.Attempts, o.LastError)
	}
	// The subject's slot is free.
	next := submitJ(t, s, pushJ(r))
	mustNext(t, s, "push", next)
	// A job no longer running is refused as before, whatever its result.
	wantErr(t, s.FinishJob(ctx, job, "done", "", "", json.RawMessage(`{`)), ErrConflict)
}

// Within one subject the lowest id goes first.
func TestNextJob_LowestIDWithinASubject(t *testing.T) {
	s := newStore(t, testConfig())
	stateRows(t, s, jobSubj(1))
	a := submitJ(t, s, pushJ(jobSubj(1)))
	b := submitJ(t, s, pushJ(jobSubj(1)))
	c := submitJ(t, s, pushJ(jobSubj(1)))
	for _, want := range []int64{a, b, c} {
		mustNext(t, s, "push", want)
		jobFinish(t, s, want, "done", "", "")
	}
}
