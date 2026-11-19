package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// emptyStore returns a store on an empty database, not migrated.
func emptyStore(t *testing.T) *Store {
	t.Helper()
	if noDocker != "" {
		t.Skip(noDocker)
	}
	ctx := context.Background()
	s, err := Open(ctx, sockDir)
	must(t, err)
	t.Cleanup(s.Close)
	_, err = s.pool.Exec(ctx, "drop schema public cascade; create schema public")
	must(t, err)
	return s
}

// v1Store returns a store on a database exactly as a version-1 Migrate left
// it: the base schema and cp_meta at schema version 1.
func v1Store(t *testing.T) *Store {
	t.Helper()
	s := emptyStore(t)
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, schemaSQL)
	must(t, err)
	_, err = s.pool.Exec(ctx, "insert into cp_meta (epoch, schema_ver) values (1, 1)")
	must(t, err)
	must(t, s.EnsureNode(ctx, testConfig()))
	return s
}

func schemaVer(t *testing.T, s *Store) int {
	t.Helper()
	return count(t, s, "select schema_ver from cp_meta")
}

func sqlExec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	_, err := s.pool.Exec(context.Background(), q, args...)
	must(t, err)
}

func opState(t *testing.T, s *Store, id int64) Operation {
	t.Helper()
	op, err := s.GetOperation(context.Background(), id)
	must(t, err)
	return op
}

func wantOpState(t *testing.T, s *Store, id int64, state string) Operation {
	t.Helper()
	op := opState(t, s, id)
	if op.State != state {
		t.Fatalf("operation %d (%s) is %s, want %s", id, op.Kind, op.State, state)
	}
	return op
}

func slotOf(t *testing.T, s *Store, r string) int64 {
	t.Helper()
	var slot *int64
	must(t, s.pool.QueryRow(context.Background(), "select slot_op from project where ref = $1", r).Scan(&slot))
	if slot == nil {
		return 0
	}
	return *slot
}

// addJob inserts a job of subject r owned by opID (0: none) in state.
func addJob(t *testing.T, s *Store, r string, opID int64, state string) int64 {
	t.Helper()
	ctx := context.Background()
	sqlExec(t, s, "insert into backup_state (subject) values ($1) on conflict do nothing", r)
	var op *int64
	if opID != 0 {
		op = &opID
	}
	var id int64
	must(t, s.pool.QueryRow(ctx, `insert into backup_job (subject, lane, kind, state, op_id, op_step, deadline_s)
		values ($1, 'push', 'push', $2, $3, 'T4p', 60) returning id`, r, state, op).Scan(&id))
	return id
}

func jobState(t *testing.T, s *Store, id int64) (state, code string) {
	t.Helper()
	var c *string
	must(t, s.pool.QueryRow(context.Background(), "select state, code from backup_job where id = $1", id).Scan(&state, &c))
	if c != nil {
		code = *c
	}
	return state, code
}

// failRestart leaves the active project r restarting at generation gen+1
// with its restart failed, and returns the restart's id.
func failRestart(t *testing.T, s *Store, r string, gen int64) int64 {
	t.Helper()
	ctx := context.Background()
	id, err := s.SubmitOperation(ctx, r, "restart", nil, gen, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, id))
	must(t, s.BeginRestart(ctx, r, gen+1, ProjectConfig{DiskQuotaMB: 1024, MemMB: 512, GUC: map[string]string{}}))
	must(t, s.FinishOperation(ctx, id, "failed", "internal: boom"))
	return id
}

// failRestore submits a restore of r and ends it failed; with restoring the
// project is moved to restoring first, as the restore's second step does.
func failRestore(t *testing.T, s *Store, r string, restoring bool) int64 {
	t.Helper()
	ctx := context.Background()
	id, _, err := s.SubmitRestore(ctx, r, json.RawMessage(`{"to":"latest"}`))
	must(t, err)
	must(t, s.StartOperation(ctx, id))
	if restoring {
		must(t, s.SetProjectRestoring(ctx, r, id))
	}
	must(t, s.FinishOperation(ctx, id, "failed", "internal: boom"))
	return id
}

func newActive(t *testing.T, s *Store, n int) string {
	t.Helper()
	r := ref(n)
	op := mustCreate(t, s, r)
	mustPlace(t, s, r)
	activate(t, s, r, op)
	return r
}

func wantState(t *testing.T, s *Store, r, state string) Project {
	t.Helper()
	p, err := s.GetProject(context.Background(), r)
	must(t, err)
	if p.State != state {
		t.Fatalf("project %s is %s, want %s", r, p.State, state)
	}
	return p
}

// --- migrations ---

func TestMigrate_V1ToV2(t *testing.T) {
	s := v1Store(t)
	ctx := context.Background()
	r := newActive(t, s, 1)
	rid, err := s.SubmitOperation(ctx, r, "restart", json.RawMessage(`{"base_generation":1}`), 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, rid))
	if schemaVer(t, s) != 1 {
		t.Fatal("fixture is not version 1")
	}
	// Version 1 refuses what version 2 admits.
	if _, err := s.pool.Exec(ctx, "update project set state = 'restoring' where ref = $1", r); err == nil {
		t.Fatal("version 1 admitted state restoring")
	}
	must(t, s.Migrate(ctx))
	if v := schemaVer(t, s); v != schemaVersion {
		t.Fatalf("schema version %d, want %d", v, schemaVersion)
	}
	// Rows kept.
	op := wantOpState(t, s, rid, "running")
	if op.Attempts != 1 || string(op.Params) != `{"base_generation": 1}` || op.Result != nil {
		t.Fatalf("operation after migration: %+v", op)
	}
	wantState(t, s, r, "active")
	if n := nextUID(t, s); n != testConfig().UIDBase+1 {
		t.Fatalf("next_uid %d", n)
	}
	// Version 2's states, kinds, column and index.
	sqlExec(t, s, "update operation set state = 'waiting_job' where id = $1", rid)
	sqlExec(t, s, "update project set state = 'restoring', slot_op = $2 where ref = $1", r, rid)
	sqlExec(t, s, "update operation set kind = 'restore', state = 'superseded', result = '{}' where id = $1", rid)
	if n := count(t, s, "select count(*) from pg_indexes where indexname = 'operation_open' and indexdef like '%waiting_job%'"); n != 1 {
		t.Fatal("operation_open does not cover waiting_job")
	}
	for _, tbl := range []string{"backup_state", "backup_job", "backup_set", "backup_timeline", "backup_gap", "backup_notice",
		"offsite_object", "offsite_info_version"} {
		if n := count(t, s, "select count(*) from information_schema.tables where table_schema = 'public' and table_name = $1", tbl); n != 1 {
			t.Fatalf("table %s missing", tbl)
		}
	}
	if _, err := s.pool.Exec(ctx, "update project set state = 'bogus' where ref = $1", r); err == nil {
		t.Fatal("version 2 admitted an unknown state")
	}
	// A second run changes nothing.
	must(t, s.Migrate(ctx))
	if v := schemaVer(t, s); v != schemaVersion {
		t.Fatalf("schema version %d after a second run", v)
	}
	wantOpState(t, s, rid, "superseded")
}

func TestMigrate_FreshIsV2(t *testing.T) {
	s := newStore(t, testConfig())
	if v := schemaVer(t, s); v != schemaVersion {
		t.Fatalf("schema version %d, want %d", v, schemaVersion)
	}
	if n := count(t, s, "select count(*) from information_schema.columns where table_name = 'project' and column_name = 'slot_op'"); n != 1 {
		t.Fatal("project.slot_op missing")
	}
	e, err := s.Epoch(context.Background())
	must(t, err)
	if e != 1 {
		t.Fatalf("epoch %d", e)
	}
}

// The names the migration drops exist on a version-1 database.
func TestMigrate_ConstraintNamesOnV1(t *testing.T) {
	s := v1Store(t)
	for _, c := range []struct{ table, name string }{
		{"project", "project_state_check"}, {"operation", "operation_kind_check"}, {"operation", "operation_state_check"},
	} {
		if n := count(t, s, "select count(*) from pg_constraint where conrelid = $1::regclass and conname = $2 and contype = 'c'",
			c.table, c.name); n != 1 {
			t.Errorf("check constraint %s on %s: %d", c.name, c.table, n)
		}
	}
	if n := count(t, s, "select count(*) from pg_indexes where tablename = 'operation' and indexname = 'operation_open'"); n != 1 {
		t.Error("index operation_open missing")
	}
}

func TestMigrate_NewerVersionRefused(t *testing.T) {
	s := newStore(t, testConfig())
	sqlExec(t, s, "update cp_meta set schema_ver = $1", schemaVersion+1)
	err := s.Migrate(context.Background())
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("schema version %d, this build knows %d", schemaVersion+1, schemaVersion)) {
		t.Fatalf("Migrate on a newer version: %v", err)
	}
	if v := schemaVer(t, s); v != schemaVersion+1 {
		t.Fatalf("schema version changed to %d", v)
	}
}

// --- open and ready states ---

// The submit path's check: a parked operation is open for a restart, a
// delete, a restore and a retry.
func TestSubmit_WaitingJobIsOpenForEveryKind(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	refused := func(t *testing.T, err error, parked int64) {
		t.Helper()
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), fmt.Sprintf("operation %d", parked)) ||
			!strings.Contains(err.Error(), "is waiting_job") {
			t.Fatalf("beside parked operation %d: %v", parked, err)
		}
	}
	// An active project with a failed restart and a parked restore.
	r := newActive(t, s, 1)
	failed, err := s.SubmitOperation(ctx, r, "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, failed))
	must(t, s.FinishOperation(ctx, failed, "failed", "internal: x")) // the project stays active
	parked, _, err := s.SubmitRestore(ctx, r, nil)
	must(t, err)
	sqlExec(t, s, "update operation set state = 'waiting_job' where id = $1", parked)
	for _, k := range []string{"restart", "delete"} {
		_, err := s.SubmitOperation(ctx, r, k, nil, 1, time.Now())
		refused(t, err, parked)
	}
	_, _, err = s.SubmitRestore(ctx, r, nil)
	refused(t, err, parked)
	refused(t, s.RetryOperation(ctx, failed), parked)
	// Control: the parked operation ended, each is accepted again.
	sqlExec(t, s, "update operation set state = 'done' where id = $1", parked)
	must(t, s.RetryOperation(ctx, failed))

	// The state a failed restart leaves, where a restart or a delete is
	// accepted: a parked delete of it is open too.
	r2 := newActive(t, s, 2)
	failRestart(t, s, r2, 1)
	del, err := s.SubmitOperation(ctx, r2, "delete", nil, 2, time.Now())
	must(t, err)
	sqlExec(t, s, "update operation set state = 'waiting_job' where id = $1", del)
	for _, k := range []string{"restart", "delete"} {
		_, err := s.SubmitOperation(ctx, r2, k, nil, 2, time.Now())
		refused(t, err, del)
	}
	_, _, err = s.SubmitRestore(ctx, r2, nil)
	refused(t, err, del)
	sqlExec(t, s, "update operation set state = 'failed' where id = $1", del)
	_, err = s.SubmitOperation(ctx, r2, "restart", nil, 2, time.Now())
	must(t, err)
}

func TestNextOperation_SkipsWaitingJob(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	id, err := s.SubmitOperation(ctx, r, "restart", nil, 1, time.Now().Add(-time.Second))
	must(t, err)
	sqlExec(t, s, "update operation set state = 'waiting_job' where id = $1", id)
	if op, ok, err := s.NextOperation(ctx); err != nil || ok {
		t.Fatalf("NextOperation offered %+v (%v, %v) while it waits for its job", op, ok, err)
	}
	sqlExec(t, s, "update operation set state = 'pending' where id = $1", id)
	if op, ok, err := s.NextOperation(ctx); err != nil || !ok || op.ID != id {
		t.Fatalf("control: %+v, %v, %v", op, ok, err)
	}
}

// The worker's check: a parked operation blocks a younger one of its ref and
// no other ref's.
func TestNextOperation_WaitingJobBlocksYoungerOfSameRef(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	parked, err := s.SubmitOperation(ctx, r, "delete", nil, 1, time.Now())
	must(t, err)
	sqlExec(t, s, "update operation set state = 'waiting_job' where id = $1", parked)
	var younger int64
	must(t, s.pool.QueryRow(ctx, `insert into operation (ref, kind, state, epoch, generation, not_before)
		values ($1, 'purge', 'pending', 1, 1, now() - interval '1 second') returning id`, r).Scan(&younger))
	if op, ok, err := s.NextOperation(ctx); err != nil || ok {
		t.Fatalf("NextOperation offered %+v (%v, %v) behind a parked operation of its ref", op, ok, err)
	}
	r2 := newActive(t, s, 2)
	other, err := s.SubmitOperation(ctx, r2, "restart", nil, 1, time.Now().Add(-time.Second))
	must(t, err)
	if op, ok, err := s.NextOperation(ctx); err != nil || !ok || op.ID != other {
		t.Fatalf("another ref: %+v, %v, %v; want %d", op, ok, err, other)
	}
	must(t, s.StartOperation(ctx, other))
	must(t, s.FinishOperation(ctx, other, "done", ""))
	sqlExec(t, s, "update operation set state = 'done' where id = $1", parked)
	if op, ok, err := s.NextOperation(ctx); err != nil || !ok || op.ID != younger {
		t.Fatalf("after the parked one ended: %+v, %v, %v; want %d", op, ok, err, younger)
	}
}

// --- restore submit ---

func TestSubmitRestore_Active(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	must(t, s.BumpGeneration(ctx, r, 3, defaultConfig))
	id, sup, err := s.SubmitRestore(ctx, r, json.RawMessage(`{"to":"latest"}`))
	must(t, err)
	if sup != 0 {
		t.Fatalf("superseded %d on an active project", sup)
	}
	op := wantOpState(t, s, id, "pending")
	if op.Kind != "restore" || op.Generation != 3 || op.Epoch != 1 || string(op.Params) != `{"to": "latest"}` || op.Attempts != 0 {
		t.Fatalf("restore %+v", op)
	}
	wantState(t, s, r, "active")
}

func TestSubmitRestore_SupersedesFailedRestore(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	old := failRestore(t, s, r, true)
	attempts := opState(t, s, old).Attempts
	id, sup, err := s.SubmitRestore(ctx, r, nil)
	must(t, err)
	if sup != old {
		t.Fatalf("superseded %d, want %d", sup, old)
	}
	if op := wantOpState(t, s, old, "superseded"); op.Attempts != attempts {
		t.Fatalf("superseded attempts %d, want %d", op.Attempts, attempts)
	}
	wantOpState(t, s, id, "pending")
	wantState(t, s, r, "restoring")
	wantErr(t, s.RetryOperation(ctx, old), ErrConflict) // final
}

func TestSubmitRestore_SupersedesFailedRestart(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	old := failRestart(t, s, r, 1)
	id, sup, err := s.SubmitRestore(ctx, r, nil)
	must(t, err)
	if sup != old {
		t.Fatalf("superseded %d, want %d", sup, old)
	}
	wantOpState(t, s, old, "superseded")
	if op := wantOpState(t, s, id, "pending"); op.Generation != 2 {
		t.Fatalf("generation %d", op.Generation)
	}
	wantState(t, s, r, "restarting")
}

func TestSubmitRestore_SupersedeClearsSlotAndCancelsQueuedJobs(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	old := failRestore(t, s, r, true)
	must(t, s.SetSlot(ctx, r, old))
	queued := addJob(t, s, r, old, "queued")
	running := addJob(t, s, r, old, "running")
	foreign := addJob(t, s, r, 0, "queued")
	_, sup, err := s.SubmitRestore(ctx, r, nil)
	must(t, err)
	if sup != old || slotOf(t, s, r) != 0 {
		t.Fatalf("superseded %d, slot %d", sup, slotOf(t, s, r))
	}
	if st, code := jobState(t, s, queued); st != "failed" || code != "cancelled" {
		t.Fatalf("queued job: %s %s", st, code)
	}
	if st, _ := jobState(t, s, running); st != "running" {
		t.Fatalf("running job: %s", st) // the runner ends it
	}
	if st, _ := jobState(t, s, foreign); st != "queued" {
		t.Fatalf("another operation's job: %s", st)
	}
}

func TestSubmitRestore_RefusedWhileOpen(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	rid, err := s.SubmitOperation(ctx, r, "restart", nil, 1, time.Now())
	must(t, err)
	_, _, err = s.SubmitRestore(ctx, r, nil)
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), fmt.Sprintf("operation %d (restart) of the project is pending", rid)) {
		t.Fatalf("beside a pending restart: %v", err)
	}
	// A failed restore whose project is restoring, with a retry of it open.
	r2 := newActive(t, s, 2)
	old := failRestore(t, s, r2, true)
	must(t, s.RetryOperation(ctx, old))
	_, _, err = s.SubmitRestore(ctx, r2, nil)
	wantErr(t, err, ErrConflict)
	wantOpState(t, s, old, "pending")
}

func TestSubmitRestore_RefusedAfterFailedCreate(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	id := mustCreate(t, s, ref(1))
	must(t, s.StartOperation(ctx, id))
	must(t, s.FinishOperation(ctx, id, "failed", "internal: x"))
	_, _, err := s.SubmitRestore(ctx, ref(1), nil)
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "it is provisioning") {
		t.Fatalf("after a failed create: %v", err)
	}
	wantOpState(t, s, id, "failed")
}

func TestSubmitRestore_RefusedAfterFailedDelete(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	del, err := s.SubmitOperation(ctx, r, "delete", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, del))
	must(t, s.SetProjectState(ctx, r, "deleting"))
	must(t, s.FinishOperation(ctx, del, "failed", "internal: x"))
	_, _, err = s.SubmitRestore(ctx, r, nil)
	wantErr(t, err, ErrConflict)
	wantOpState(t, s, del, "failed")
	// Also a restoring project whose newest operation is a failed delete.
	r2 := newActive(t, s, 2)
	failRestore(t, s, r2, true)
	del2, err := s.SubmitOperation(ctx, r2, "delete", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, del2))
	must(t, s.FinishOperation(ctx, del2, "failed", "internal: x")) // before it moved the project to deleting
	_, _, err = s.SubmitRestore(ctx, r2, nil)
	wantErr(t, err, ErrConflict)
	// Nor a second delete: the failed one is retried, not superseded.
	_, err = s.SubmitOperation(ctx, r2, "delete", nil, 1, time.Now())
	wantErr(t, err, ErrConflict)
	wantOpState(t, s, del2, "failed")
	must(t, s.RetryOperation(ctx, del2))
}

func TestSubmitRestore_RefusedDeleted(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	purge := markDeleted(t, s, r)
	_, _, err := s.SubmitRestore(ctx, r, nil)
	wantErr(t, err, ErrConflict)
	must(t, s.StartOperation(ctx, purge))
	must(t, s.FinishOperation(ctx, purge, "done", ""))
	must(t, s.MarkPurged(ctx, r))
	_, _, err = s.SubmitRestore(ctx, r, nil)
	wantErr(t, err, ErrConflict)
	_, _, err = s.SubmitRestore(ctx, ref(9), nil)
	wantErr(t, err, ErrNotFound)
}

func TestSubmitDelete_SupersedesFailedRestore(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	old := failRestore(t, s, r, true)
	must(t, s.SetSlot(ctx, r, old))
	queued := addJob(t, s, r, old, "queued")
	del, err := s.SubmitOperation(ctx, r, "delete", nil, 1, time.Now())
	must(t, err)
	wantOpState(t, s, old, "superseded")
	wantOpState(t, s, del, "pending")
	if slotOf(t, s, r) != 0 {
		t.Fatal("slot kept")
	}
	if st, code := jobState(t, s, queued); st != "failed" || code != "cancelled" {
		t.Fatalf("queued job: %s %s", st, code)
	}
}

func TestSubmitDelete_RefusedWhileRestoreOpen(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	id, _, err := s.SubmitRestore(ctx, r, nil)
	must(t, err)
	for _, state := range []string{"pending", "running", "waiting_job"} {
		sqlExec(t, s, "update operation set state = $2 where id = $1", id, state)
		for _, ps := range []string{"active", "restoring"} {
			sqlExec(t, s, "update project set state = $2 where ref = $1", r, ps)
			_, err := s.SubmitOperation(ctx, r, "delete", nil, 1, time.Now())
			if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), fmt.Sprintf("operation %d (restore)", id)) {
				t.Fatalf("delete beside a %s restore of a %s project: %v", state, ps, err)
			}
		}
	}
	wantOpState(t, s, id, "waiting_job")
}

func TestSubmitRestart_RefusedForRestoringProject(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	old := failRestore(t, s, r, true)
	_, err := s.SubmitOperation(ctx, r, "restart", nil, 1, time.Now())
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "it is restoring") {
		t.Fatalf("restart of a restoring project: %v", err)
	}
	wantOpState(t, s, old, "failed")
	// Control: a delete of it is accepted.
	_, err = s.SubmitOperation(ctx, r, "delete", nil, 1, time.Now())
	must(t, err)
}

// A restart or a delete of a project left restarting by a failed restart is
// as built: that restart stays failed, no slot or job is touched.
func TestSubmit_RestartOrDeleteAfterAFailedRestartSupersedesNothing(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for i, kind := range []string{"restart", "delete"} {
		r := newActive(t, s, i+1)
		old := failRestart(t, s, r, 1)
		sqlExec(t, s, "update project set slot_op = $2 where ref = $1", r, old)
		job := addJob(t, s, r, old, "queued")
		_, err := s.SubmitOperation(ctx, r, kind, nil, 2, time.Now())
		must(t, err)
		wantOpState(t, s, old, "failed")
		if slotOf(t, s, r) != old {
			t.Fatalf("%s: slot changed", kind)
		}
		if st, _ := jobState(t, s, job); st != "queued" {
			t.Fatalf("%s: job %s", kind, st)
		}
	}
}

// The way out of a failed restart survives a restore that superseded it and
// failed before the project became restoring: the project is restarting,
// its newest restart superseded, and a restart, a delete or a restore is
// accepted.
func TestSubmit_WayOutAfterSupersededRestartAndFailedRestore(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for i, kind := range []string{"restart", "delete", "restore"} {
		r := newActive(t, s, i+1)
		restart := failRestart(t, s, r, 1)
		restore := failRestore(t, s, r, false)
		wantOpState(t, s, restart, "superseded")
		wantState(t, s, r, "restarting")
		var id, sup int64
		var err error
		if kind == "restore" {
			id, sup, err = s.SubmitRestore(ctx, r, nil)
		} else {
			id, err = s.SubmitOperation(ctx, r, kind, nil, 2, time.Now())
		}
		must(t, err)
		wantOpState(t, s, id, "pending")
		// Only a restore supersedes the failed restore.
		want := "failed"
		if kind == "restore" {
			want = "superseded"
			if sup != restore {
				t.Fatalf("restore superseded %d, want %d", sup, restore)
			}
		}
		wantOpState(t, s, restore, want)
	}
	// Control: a restarting project whose newest restart is superseded by a
	// restore still open is refused.
	r := newActive(t, s, 9)
	failRestart(t, s, r, 1)
	open, _, err := s.SubmitRestore(ctx, r, nil)
	must(t, err)
	for _, kind := range []string{"restart", "delete"} {
		_, err := s.SubmitOperation(ctx, r, kind, nil, 2, time.Now())
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), fmt.Sprintf("operation %d (restore)", open)) {
			t.Fatalf("%s beside the open restore: %v", kind, err)
		}
	}
}

// --- floors, requeue, abort, slot, finish ---

func TestRetryOperation_RaisesJobFloor(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	id, err := s.SubmitOperation(ctx, r, "restart", json.RawMessage(`{"rollback_step":"R3","job_floor":1}`), 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, id))
	must(t, s.FinishOperation(ctx, id, "failed", "internal: x"))
	must(t, s.RetryOperation(ctx, id))
	var p map[string]any
	must(t, json.Unmarshal(opState(t, s, id).Params, &p))
	if p["job_floor"] != float64(0) || p["rollback_step"] != "R3" {
		t.Fatalf("params with no job: %v", p)
	}
	must(t, s.StartOperation(ctx, id))
	must(t, s.FinishOperation(ctx, id, "failed", "internal: x"))
	addJob(t, s, r, id, "done")
	last := addJob(t, s, ref(1), 0, "queued")
	must(t, s.RetryOperation(ctx, id))
	must(t, json.Unmarshal(opState(t, s, id).Params, &p))
	if p["job_floor"] != float64(last) || p["rollback_step"] != "R3" {
		t.Fatalf("params: %v, want job_floor %d", p, last)
	}
}

func TestRequeue_GivesAttemptBack_KeepsLastError(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	id, err := s.SubmitOperation(ctx, r, "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, id))
	must(t, s.FailAttempt(ctx, id, "internal: earlier", time.Now()))
	must(t, s.StartOperation(ctx, id))
	nb := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	must(t, s.Requeue(ctx, id, nb))
	op := wantOpState(t, s, id, "pending")
	if op.Attempts != 1 || op.LastError != "internal: earlier" || !op.NotBefore.Equal(nb) {
		t.Fatalf("after requeue: %+v", op)
	}
	wantErr(t, s.Requeue(ctx, id, nb), ErrConflict) // not running
	wantErr(t, s.Requeue(ctx, 999999, nb), ErrNotFound)
}

func TestRaiseJobFloor_FloorAndAttemptInOneStatement(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	id, err := s.SubmitOperation(ctx, r, "restart", json.RawMessage(`{"rollback_step":"R3"}`), 1, time.Now())
	must(t, err)
	wantErr(t, func() error { _, _, err := s.RaiseJobFloor(ctx, id, true); return err }(), ErrConflict) // pending
	must(t, s.StartOperation(ctx, id))
	floor, att, err := s.RaiseJobFloor(ctx, id, false)
	must(t, err)
	if floor != 0 || att != 1 {
		t.Fatalf("no job, no count: floor %d attempts %d", floor, att)
	}
	j := addJob(t, s, r, id, "failed")
	floor, att, err = s.RaiseJobFloor(ctx, id, true)
	must(t, err)
	if floor != j || att != 2 {
		t.Fatalf("with count: floor %d attempts %d, want %d 2", floor, att, j)
	}
	op := opState(t, s, id)
	var p map[string]any
	must(t, json.Unmarshal(op.Params, &p))
	if op.Attempts != 2 || p["job_floor"] != float64(j) || p["rollback_step"] != "R3" {
		t.Fatalf("stored %+v %v", op, p)
	}
	floor, att, err = s.RaiseJobFloor(ctx, id, false)
	must(t, err)
	if floor != j || att != 2 {
		t.Fatalf("without count: floor %d attempts %d", floor, att)
	}
	_, _, err = s.RaiseJobFloor(ctx, 999999, false)
	wantErr(t, err, ErrNotFound)
}

func TestRequestAbort_FromWaitingJob(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	id := mustCreate(t, s, ref(1))
	must(t, s.StartOperation(ctx, id))
	sqlExec(t, s, "update operation set state = 'waiting_job' where id = $1", id)
	got, err := s.RequestAbort(ctx, ref(1))
	must(t, err)
	if got != id {
		t.Fatalf("aborted %d, want %d", got, id)
	}
	if op := wantOpState(t, s, id, "aborting"); op.Attempts != 0 {
		t.Fatalf("attempts %d", op.Attempts)
	}
}

func TestSetSlot_Exclusive(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	must(t, s.SetSlot(ctx, r, 10))
	must(t, s.SetSlot(ctx, r, 10))
	wantErr(t, s.SetSlot(ctx, r, 11), ErrConflict)
	must(t, s.ClearSlot(ctx, r, 11)) // not its slot: nothing changes
	if slotOf(t, s, r) != 10 {
		t.Fatalf("slot %d", slotOf(t, s, r))
	}
	must(t, s.ClearSlot(ctx, r, 10))
	if slotOf(t, s, r) != 0 {
		t.Fatal("slot not cleared")
	}
	must(t, s.SetSlot(ctx, r, 11))
	wantErr(t, s.SetSlot(ctx, ref(9), 1), ErrNotFound)
	wantErr(t, s.ClearSlot(ctx, ref(9), 1), ErrNotFound)
	r3 := newActive(t, s, 3)
	errs := race(2, func(i int) error { return s.SetSlot(ctx, r3, int64(20+i)) })
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("two takers: %v", errs)
	}
}

func TestSetProjectRestoring_GuardedByOpenRestore(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	rid, err := s.SubmitOperation(ctx, r, "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, rid))
	wantErr(t, s.SetProjectRestoring(ctx, r, rid), ErrConflict) // not a restore
	must(t, s.FinishOperation(ctx, rid, "failed", "internal: x"))
	id, _, err := s.SubmitRestore(ctx, r, nil)
	must(t, err)
	must(t, s.StartOperation(ctx, id))
	must(t, s.SetProjectRestoring(ctx, r, id))
	must(t, s.SetProjectRestoring(ctx, r, id)) // restoring → restoring
	wantState(t, s, r, "restoring")
	must(t, s.FinishOperation(ctx, id, "failed", "internal: x"))
	sqlExec(t, s, "update project set state = 'active' where ref = $1", r)
	wantErr(t, s.SetProjectRestoring(ctx, r, id), ErrConflict) // not open
	wantState(t, s, r, "active")
	// From restarting; never from deleting.
	r2 := newActive(t, s, 2)
	failRestart(t, s, r2, 1)
	id2, _, err := s.SubmitRestore(ctx, r2, nil)
	must(t, err)
	must(t, s.StartOperation(ctx, id2))
	must(t, s.SetProjectRestoring(ctx, r2, id2))
	sqlExec(t, s, "update project set state = 'deleting' where ref = $1", r2)
	wantErr(t, s.SetProjectRestoring(ctx, r2, id2), ErrConflict)
	wantErr(t, s.SetProjectRestoring(ctx, r, id2), ErrConflict) // another ref's restore
}

func TestFinishRestore_OneTransaction(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	id, _, err := s.SubmitRestore(ctx, r, nil)
	must(t, err)
	must(t, s.StartOperation(ctx, id))
	must(t, s.SetProjectRestoring(ctx, r, id))
	must(t, s.SetSlot(ctx, r, id))
	// The project no longer restoring: nothing is written.
	sqlExec(t, s, "update project set state = 'deleting' where ref = $1", r)
	wantErr(t, s.FinishRestore(ctx, id, json.RawMessage(`{"ok":true}`)), ErrConflict)
	if op := wantOpState(t, s, id, "running"); op.Result != nil || slotOf(t, s, r) != id {
		t.Fatalf("after a refused finish: %+v, slot %d", op, slotOf(t, s, r))
	}
	sqlExec(t, s, "update project set state = 'restoring' where ref = $1", r)
	// Only a running restore.
	sqlExec(t, s, "update operation set state = 'waiting_job' where id = $1", id)
	wantErr(t, s.FinishRestore(ctx, id, json.RawMessage(`{"ok":true}`)), ErrConflict)
	wantState(t, s, r, "restoring")
	sqlExec(t, s, "update operation set state = 'running' where id = $1", id)
	errs := race(2, func(int) error { return s.FinishRestore(ctx, id, json.RawMessage(`{"ok":true}`)) })
	if (errs[0] == nil) == (errs[1] == nil) || !errors.Is(errors.Join(errs...), ErrConflict) {
		t.Fatalf("two finishes: %v", errs)
	}
	op := wantOpState(t, s, id, "done")
	if string(op.Result) != `{"ok": true}` || op.LastError != "" {
		t.Fatalf("finished %+v", op)
	}
	wantState(t, s, r, "active")
	if slotOf(t, s, r) != 0 {
		t.Fatal("slot kept")
	}
	// Only a restore.
	r2 := newActive(t, s, 2)
	rid, err := s.SubmitOperation(ctx, r2, "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, rid))
	sqlExec(t, s, "update project set state = 'restoring' where ref = $1", r2)
	wantErr(t, s.FinishRestore(ctx, rid, nil), ErrConflict)
	wantErr(t, s.FinishRestore(ctx, 999999, nil), ErrNotFound)
}

// --- the new epoch ---

// snapshot is every row the new-epoch step may touch, as text.
func snapshot(t *testing.T, s *Store) string {
	t.Helper()
	var out string
	must(t, s.pool.QueryRow(context.Background(), `select concat_ws('|',
		(select json_agg(x order by x.singleton)::text from cp_meta x),
		(select json_agg(x order by x.id)::text from node x),
		(select json_agg(x order by x.ref)::text from project x),
		(select json_agg(x order by x.id)::text from operation x),
		(select json_agg(x order by x.id)::text from backup_job x),
		(select json_agg(x order by x.subject)::text from backup_state x))`).Scan(&out))
	return out
}

func TestEnterNewEpoch_AllEffects(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	// An open restart.
	r1 := newActive(t, s, 1)
	running, err := s.SubmitOperation(ctx, r1, "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, running))
	// A parked restore with its slot and two jobs.
	r2 := newActive(t, s, 2)
	parked, _, err := s.SubmitRestore(ctx, r2, nil)
	must(t, err)
	must(t, s.StartOperation(ctx, parked))
	sqlExec(t, s, "update operation set state = 'waiting_job' where id = $1", parked)
	must(t, s.SetSlot(ctx, r2, parked))
	q := addJob(t, s, r2, parked, "queued")
	rj := addJob(t, s, r2, 0, "running")
	done := addJob(t, s, r2, 0, "done")
	// Final operations stay as they are.
	r3 := newActive(t, s, 3)
	finished := failRestart(t, s, r3, 1)
	before := map[int64]Operation{running: opState(t, s, running), parked: opState(t, s, parked)}

	floor := nextUID(t, s) + 100
	epoch, err := s.EnterNewEpoch(ctx, floor)
	must(t, err)
	if e, _ := s.Epoch(ctx); epoch != 2 || e != 2 {
		t.Fatalf("epoch %d, stored %d", epoch, e)
	}
	if n := nextUID(t, s); n != floor {
		t.Fatalf("next_uid %d, want the floor %d", n, floor)
	}
	for _, id := range []int64{running, parked} {
		op := wantOpState(t, s, id, "failed")
		if op.LastError != "recovered: the node was recovered while this operation was open" || op.Attempts != before[id].Attempts {
			t.Fatalf("operation %d: %+v", id, op)
		}
	}
	if op := wantOpState(t, s, finished, "failed"); op.LastError != "internal: boom" {
		t.Fatalf("final operation changed: %+v", op)
	}
	for _, j := range []int64{q, rj} {
		if st, code := jobState(t, s, j); st != "failed" || code != "recovered" {
			t.Fatalf("job %d: %s %s", j, st, code)
		}
	}
	if st, code := jobState(t, s, done); st != "done" || code != "" {
		t.Fatalf("finished job: %s %s", st, code)
	}
	if slotOf(t, s, r2) != 0 {
		t.Fatal("slot kept")
	}
	for r, st := range map[string]string{r1: "active", r2: "active", r3: "restarting"} {
		wantState(t, s, r, st)
	}
	// The counter is never lowered, and rises above every recorded uid.
	epoch, err = s.EnterNewEpoch(ctx, 0)
	must(t, err)
	if n := nextUID(t, s); epoch != 3 || n != floor {
		t.Fatalf("epoch %d, next_uid %d after a lower floor", epoch, n)
	}
	sqlExec(t, s, "update node set next_uid = 0")
	_, err = s.EnterNewEpoch(ctx, 0)
	must(t, err)
	if n, max := nextUID(t, s), count(t, s, "select max(uid) from project"); n != max+1 {
		t.Fatalf("next_uid %d, highest uid %d", n, max)
	}
}

func TestEnterNewEpoch_ProvisioningAborted_SliceReleased_PrefixObligation(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		mustCreate(t, s, ref(i))
		mustPlace(t, s, ref(i))
	}
	sqlExec(t, s, "insert into backup_state (subject) values ($1)", ref(1))
	sqlExec(t, s, "update operation set state = 'aborting' where ref = $1", ref(2))
	sqlExec(t, s, "update operation set state = 'failed' where ref = $1", ref(3)) // not open: left as it is
	uid := wantState(t, s, ref(1), "provisioning").UID
	_, err := s.EnterNewEpoch(ctx, 0)
	must(t, err)
	for i := 1; i <= 3; i++ {
		p := wantState(t, s, ref(i), "aborted")
		if p.SubnetIndex != nil || p.UID == nil {
			t.Fatalf("project %d: slice %v, uid %v", i, p.SubnetIndex, p.UID)
		}
	}
	if p, _ := s.GetProject(ctx, ref(1)); *p.UID != *uid {
		t.Fatal("uid changed")
	}
	ops, err := s.ListOperations(ctx, "")
	must(t, err)
	for _, o := range ops {
		want := "aborted"
		if o.Ref == ref(3) {
			want = "failed"
		}
		if o.State != want {
			t.Fatalf("create of %s is %s, want %s", o.Ref, o.State, want)
		}
		if want == "aborted" && o.LastError != "recovered: the node was recovered while this operation was open" {
			t.Fatalf("last_error %q", o.LastError)
		}
	}
	var purge bool
	must(t, s.pool.QueryRow(ctx, "select offsite_purge from backup_state where subject = $1", ref(1)).Scan(&purge))
	if !purge {
		t.Fatal("prefix obligation not recorded")
	}
	if n := count(t, s, "select count(*) from backup_state"); n != 1 {
		t.Fatalf("backup_state rows %d", n) // none created for the others
	}
}

func TestEnterNewEpoch_PurgesStayQueued(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r1 := newActive(t, s, 1)
	must(t, s.SetProjectState(ctx, r1, "deleting"))
	pending, err := s.MarkDeleted(ctx, r1, 24*time.Hour)
	must(t, err)
	r2 := newActive(t, s, 2)
	running := markDeleted(t, s, r2)
	must(t, s.StartOperation(ctx, running))
	nb := opState(t, s, pending).NotBefore
	_, err = s.EnterNewEpoch(ctx, 0)
	must(t, err)
	if op := wantOpState(t, s, pending, "pending"); !op.NotBefore.Equal(nb) || op.LastError != "" {
		t.Fatalf("pending purge: %+v", op)
	}
	if op := wantOpState(t, s, running, "pending"); op.LastError != "" {
		t.Fatalf("running purge: %+v", op)
	}
	wantState(t, s, r1, "deleted")
}

func TestEnterNewEpoch_OneTransaction(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	id, _, err := s.SubmitRestore(ctx, r, nil)
	must(t, err)
	must(t, s.StartOperation(ctx, id))
	must(t, s.SetSlot(ctx, r, id))
	addJob(t, s, r, id, "queued")
	mustCreate(t, s, ref(2))
	mustPlace(t, s, ref(2))
	sqlExec(t, s, "insert into backup_state (subject) values ($1)", ref(2))
	before := snapshot(t, s)
	// The last statement clears the slots: make it fail.
	sqlExec(t, s, `create function sp_fail() returns trigger language plpgsql as $$ begin raise exception 'forced'; end $$`)
	sqlExec(t, s, "create trigger sp_fail before update of slot_op on project for each statement execute function sp_fail()")
	if _, err := s.EnterNewEpoch(ctx, 1<<20); err == nil || !strings.Contains(err.Error(), "forced") {
		t.Fatalf("EnterNewEpoch with its last statement failing: %v", err)
	}
	if after := snapshot(t, s); after != before {
		t.Fatalf("rows changed:\nbefore %s\nafter  %s", before, after)
	}
	sqlExec(t, s, "drop trigger sp_fail on project")
	_, err = s.EnterNewEpoch(ctx, 0)
	must(t, err)
	if snapshot(t, s) == before {
		t.Fatal("control: nothing changed")
	}
}

// --- admission, pool, WAL, configuration ---

func TestAdmit_CountsRestoring(t *testing.T) {
	c := testConfig()
	c.MemAllocMB = 768
	s := newStore(t, c)
	ctx := context.Background()
	r := newActive(t, s, 1)
	sqlExec(t, s, "update project set state = 'restoring' where ref = $1", r)
	mustCreate(t, s, ref(2))
	_, err := s.Place(ctx, ref(2))
	wantErr(t, err, ErrNodeFull) // restoring: it holds its cluster's memory
	wantErr(t, s.CheckAdmission(ctx, 512), ErrNodeFull)
	sqlExec(t, s, "update project set state = 'aborted', subnet_index = null where ref = $1", r)
	mustPlace(t, s, ref(2)) // control
}

// Four adoption locks, an index-file stream and the worker's lock leave ten
// connections for everything else.
func TestPool_FourLocksAStreamAndTheWorkerLeaveHeadroom(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	if got := s.pool.Config().MaxConns; got != 16 {
		t.Fatalf("pool size %d, want 16", got)
	}
	for i := 1; i <= 5; i++ {
		u, err := s.LockRef(ctx, ref(i))
		must(t, err)
		defer u()
	}
	stream, err := s.pool.Acquire(ctx)
	must(t, err)
	defer stream.Release()
	actx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for range 10 {
		c, err := s.pool.Acquire(actx)
		if err != nil {
			t.Fatalf("headroom: %v", err)
		}
		defer c.Release()
	}
	// Control: the pool is now exhausted.
	short, cancel2 := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel2()
	if c, err := s.pool.Acquire(short); err == nil {
		c.Release()
		t.Fatal("a seventeenth connection was handed out")
	}
}

func TestSwitchWAL_ReturnsSegmentOfPosition(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	sqlExec(t, s, "create table sp_wal_probe (x int); insert into sp_wal_probe values (1)")
	lsn, err := s.WALPosition(ctx)
	must(t, err)
	var want string
	must(t, s.pool.QueryRow(ctx, "select pg_walfile_name($1::pg_lsn)", lsn).Scan(&want))
	seg, err := s.SwitchWAL(ctx, lsn)
	must(t, err)
	if seg != want || len(seg) != 24 {
		t.Fatalf("segment %q, want %q", seg, want)
	}
	var now string
	must(t, s.pool.QueryRow(ctx, "select pg_walfile_name(pg_current_wal_insert_lsn())").Scan(&now))
	if now <= seg {
		t.Fatalf("after the switch the current segment is %s, not after %s", now, seg)
	}
	if _, err := s.SwitchWAL(ctx, "not-a-position"); err == nil {
		t.Fatal("a malformed position was accepted")
	}
}

func TestProjectConfig_LayoutOmitted(t *testing.T) {
	b, err := json.Marshal(ProjectConfig{DiskQuotaMB: 8192, MemMB: 512, GUC: map[string]string{}})
	must(t, err)
	if string(b) != `{"disk_quota_mb":8192,"mem_mb":512,"guc":{}}` {
		t.Fatalf("layout-1 configuration %s", b)
	}
	b, err = json.Marshal(ProjectConfig{DiskQuotaMB: 1, MemMB: 2, Layout: 2, UploadMBPerDay: 3, UploadObjectsPerDay: 4})
	must(t, err)
	if string(b) != `{"disk_quota_mb":1,"mem_mb":2,"guc":null,"layout":2,"upload_mb_per_day":3,"upload_objects_per_day":4}` {
		t.Fatalf("layout-2 configuration %s", b)
	}
	// Stored and read back.
	s := newStore(t, testConfig())
	_, err = s.CreateProject(context.Background(), NewProject{Ref: ref(1), Name: "x", Config: ProjectConfig{DiskQuotaMB: 1, MemMB: 2, Layout: 2}})
	must(t, err)
	if p := wantState(t, s, ref(1), "provisioning"); p.Config.Layout != 2 {
		t.Fatalf("layout %d", p.Config.Layout)
	}
	if n := count(t, s, "select count(*) from project where config ? 'layout'"); n != 1 {
		t.Fatal("layout not stored")
	}
}

func TestWindowError(t *testing.T) {
	from := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	to := from.Add(time.Hour)
	err := fmt.Errorf("restore: %w", &WindowError{From: from, To: to})
	var we *WindowError
	if !errors.As(err, &we) || !we.From.Equal(from) || !we.To.Equal(to) {
		t.Fatalf("errors.As: %v", err)
	}
	if !strings.Contains(err.Error(), from.Format(time.RFC3339)) || !strings.Contains(err.Error(), to.Format(time.RFC3339)) {
		t.Fatalf("message %q", err)
	}
}

// A failed restore is retried only while it is the ref's newest operation:
// its set and target were chosen at its submit, and an operation accepted
// after it may have restored, restarted or let the tenant write since.
func TestRetryOperation_RestoreOnlyWhileNewest(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	// Restore A fails before the project's state changed; restore B from
	// active finishes.
	r := newActive(t, s, 1)
	a := failRestore(t, s, r, false)
	wantState(t, s, r, "active")
	b, sup, err := s.SubmitRestore(ctx, r, nil)
	must(t, err)
	if sup != 0 {
		t.Fatalf("B superseded %d", sup)
	}
	must(t, s.StartOperation(ctx, b))
	must(t, s.SetProjectRestoring(ctx, r, b))
	must(t, s.FinishRestore(ctx, b, json.RawMessage(`{}`)))
	err = s.RetryOperation(ctx, a)
	if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), fmt.Sprintf("operation %d", b)) {
		t.Fatalf("retry of a restore older than restore %d: %v", b, err)
	}
	wantOpState(t, s, a, "failed")
	// A takeover restart accepted after the failed restore.
	r2 := newActive(t, s, 2)
	failRestart(t, s, r2, 1)
	a2 := failRestore(t, s, r2, false) // supersedes the restart; the project stays restarting
	rs, err := s.SubmitOperation(ctx, r2, "restart", nil, 2, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, rs))
	must(t, s.FinishOperation(ctx, rs, "failed", "internal: x"))
	wantErr(t, s.RetryOperation(ctx, a2), ErrConflict)
	wantOpState(t, s, a2, "failed")
	// Control: a failed restore that is the newest is retried.
	r3 := newActive(t, s, 3)
	a3 := failRestore(t, s, r3, true)
	newActive(t, s, 5) // another ref's newer operations do not count
	must(t, s.RetryOperation(ctx, a3))
	wantOpState(t, s, a3, "pending")
	// Other kinds keep the as-built rule: a failed restart older than a
	// finished restore is retried (the saga's base check decides).
	r4 := newActive(t, s, 4)
	rst, err := s.SubmitOperation(ctx, r4, "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, rst))
	must(t, s.FinishOperation(ctx, rst, "failed", "internal: x"))
	b4, _, err := s.SubmitRestore(ctx, r4, nil)
	must(t, err)
	must(t, s.StartOperation(ctx, b4))
	must(t, s.SetProjectRestoring(ctx, r4, b4))
	must(t, s.FinishRestore(ctx, b4, json.RawMessage(`{}`)))
	must(t, s.RetryOperation(ctx, rst))
}

func TestSetOperationResult_OnlyWhileRunning(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	id, err := s.SubmitOperation(ctx, r, "delete", nil, 1, time.Now())
	must(t, err)
	wantErr(t, s.SetOperationResult(ctx, id, json.RawMessage(`{"a":1}`)), ErrConflict) // pending
	must(t, s.StartOperation(ctx, id))
	must(t, s.SetOperationResult(ctx, id, json.RawMessage(`{"a":1}`)))
	must(t, s.FinishOperation(ctx, id, "done", ""))
	wantErr(t, s.SetOperationResult(ctx, id, json.RawMessage(`{"a":2}`)), ErrConflict)
	if op := opState(t, s, id); string(op.Result) != `{"a": 1}` {
		t.Fatalf("result %s", op.Result)
	}
}

// A restoring project whose newest operation is a failed delete: the refusal
// names that delete and its retry.
func TestSubmit_RefusalNamesTheFailedDeleteToRetry(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	failRestore(t, s, r, true)
	del, err := s.SubmitOperation(ctx, r, "delete", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, del))
	must(t, s.FinishOperation(ctx, del, "failed", "internal: x"))
	for _, kind := range []string{"delete", "restore", "restart"} {
		var err error
		if kind == "restore" {
			_, _, err = s.SubmitRestore(ctx, r, nil)
		} else {
			_, err = s.SubmitOperation(ctx, r, kind, nil, 1, time.Now())
		}
		want := fmt.Sprintf("operation %d (delete) failed; op retry %d", del, del)
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v, want it to contain %q", kind, err, want)
		}
	}
}
