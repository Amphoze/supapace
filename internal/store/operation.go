package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const opCols = `id, ref, kind, state, step, attempts, params, epoch, generation, not_before, coalesce(last_error, ''),
	created_at, updated_at, result`

// openStates own their ref: while one of its operations is in them, nothing
// else of the ref is submitted, retried, picked or adopted. readyStates are
// the open states the worker picks; an operation waiting for its job is open
// but not ready.
const (
	openStates  = `('pending', 'running', 'waiting_job', 'aborting')`
	readyStates = `('pending', 'running', 'aborting')`
)

func scanOp(row pgx.Row) (Operation, error) {
	var o Operation
	var params, result []byte
	err := row.Scan(&o.ID, &o.Ref, &o.Kind, &o.State, &o.Step, &o.Attempts, &params, &o.Epoch, &o.Generation, &o.NotBefore, &o.LastError,
		&o.CreatedAt, &o.UpdatedAt, &result)
	o.Params, o.Result = params, result
	return o, err
}

func orEmpty(params json.RawMessage) json.RawMessage {
	if len(params) == 0 {
		return json.RawMessage("{}")
	}
	return params
}

// openOperation refuses with ErrConflict, naming the operation, when ref has
// an open operation other than except.
func openOperation(ctx context.Context, tx pgx.Tx, ref string, except int64) error {
	var id int64
	var kind, state string
	err := tx.QueryRow(ctx, "select id, kind, state from operation where ref = $1 and id <> $2 and state in "+openStates+
		" order by id limit 1", ref, except).Scan(&id, &kind, &state)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil
	case err != nil:
		return err
	}
	return fmt.Errorf("%w: operation %d (%s) of the project is %s; wait for it to end", ErrConflict, id, kind, state)
}

// submitRule says, for each kind a caller may submit, which projects take it.
var submitRule = map[string]string{
	"restart": "an active project, or one left restarting by a failed restart or restore",
	"delete":  "an active project, one left restarting by a failed restart or restore, or one left restoring by a failed restore",
	"restore": "an active project, or one left restoring or restarting by a failed restore or restart",
}

// admitSubmit decides, under the project's row lock, whether an operation of
// kind may follow what ref has done. The rule: one open operation per ref; an
// operation that ended failed is not open, and what may follow it depends on
// the project's state and that operation's kind:
//   - an active project takes each kind;
//   - a project left restarting takes a restart or a delete when the newest of
//     its restarts and restores is failed — a restart that a restore
//     superseded, followed by that restore's failure before the project became
//     restoring, keeps this way out — and supersedes nothing;
//   - a restore of a restoring or restarting project, and a delete of a
//     restoring project, follow a failed restore (for a restore also a failed
//     restart) that is the ref's newest operation, which they supersede.
//
// It returns the project's generation and the id of the operation to
// supersede (0: none). The open-operation test is the caller's.
func admitSubmit(ctx context.Context, tx pgx.Tx, ref, kind string) (gen, supersede int64, err error) {
	var state, lastKind, lastState string
	var lastID int64
	var takeover bool
	if err := tx.QueryRow(ctx, `select p.state, p.generation, coalesce(o.id, 0), coalesce(o.kind, ''), coalesce(o.state, ''),
			coalesce((select r.state = 'failed' from operation r where r.ref = p.ref and r.kind in ('restart', 'restore')
				order by r.id desc limit 1), false)
		from project p left join lateral (select id, kind, state from operation where ref = p.ref order by id desc limit 1) o on true
		where p.ref = $1 for update of p`, ref).Scan(&state, &gen, &lastID, &lastKind, &lastState, &takeover); err != nil {
		return 0, 0, err
	}
	failedRestore := lastState == "failed" && lastKind == "restore"
	failedRestart := lastState == "failed" && lastKind == "restart"
	switch {
	case state == "active":
		return gen, 0, nil
	case state == "restarting" && kind != "restore" && takeover:
		return gen, 0, nil
	case kind == "restore" && (state == "restoring" || state == "restarting") && (failedRestore || failedRestart),
		kind == "delete" && state == "restoring" && failedRestore:
		return gen, lastID, nil
	}
	if err := openOperation(ctx, tx, ref, 0); err != nil {
		return 0, 0, err
	}
	hint := ""
	if lastState == "failed" {
		hint = fmt.Sprintf("; operation %d (%s) failed; op retry %d continues it", lastID, lastKind, lastID)
	}
	return 0, 0, fmt.Errorf("%w: %s needs %s; it is %s%s", ErrConflict, kind, submitRule[kind], state, hint)
}

// supersedeOp ends the failed operation id of ref superseded, frees the
// project's slot and cancels the operation's queued jobs.
func supersedeOp(ctx context.Context, tx pgx.Tx, ref string, id int64) error {
	tag, err := tx.Exec(ctx, "update operation set state = 'superseded', updated_at = now() where id = $1 and state = 'failed'", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: operation %d is no longer failed", ErrConflict, id)
	}
	if _, err := tx.Exec(ctx, "update project set slot_op = null where ref = $1", ref); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `update backup_job set state = 'failed', code = 'cancelled', message = 'the operation was superseded',
		finished_at = now() where op_id = $1 and state = 'queued'`, id)
	return err
}

// SubmitOperation queues a restart or delete, by admitSubmit's rule,
// provided the project is still at generation base — the generation the
// caller read when it built params, so two restarts merged from the same
// base cannot drop each other's settings. A restart targets generation + 1,
// a delete the current generation; project.generation itself is not touched.
func (s *Store) SubmitOperation(ctx context.Context, ref, kind string, params json.RawMessage, base int64, notBefore time.Time) (int64, error) {
	if kind != "restart" && kind != "delete" {
		return 0, fmt.Errorf("%w: operation kind %q cannot be submitted", ErrConflict, kind)
	}
	var id int64
	err := s.tx(ctx, func(tx pgx.Tx) error {
		gen, sup, err := admitSubmit(ctx, tx, ref, kind)
		if err != nil {
			return err
		}
		if gen != base {
			return fmt.Errorf("%w: the project is at generation %d, not %d; read it again", ErrConflict, gen, base)
		}
		// Two open restarts would both target generation + 1.
		if err := openOperation(ctx, tx, ref, 0); err != nil {
			return err
		}
		if sup != 0 {
			if err := supersedeOp(ctx, tx, ref, sup); err != nil {
				return err
			}
		}
		if kind == "restart" {
			gen++
		}
		return tx.QueryRow(ctx, `insert into operation (ref, kind, state, params, epoch, generation, not_before)
			values ($1, $2, 'pending', $3, (select epoch from cp_meta), $4, $5) returning id`,
			ref, kind, orEmpty(params), gen, notBefore).Scan(&id)
	})
	return id, err
}

// SubmitRestore queues a restore at the project's generation, by
// admitSubmit's rule, and returns its id and that of the operation it
// superseded (0: none). The project's state is not changed here.
func (s *Store) SubmitRestore(ctx context.Context, ref string, params json.RawMessage) (id, superseded int64, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		gen, sup, err := admitSubmit(ctx, tx, ref, "restore")
		if err != nil {
			return err
		}
		if err := openOperation(ctx, tx, ref, 0); err != nil {
			return err
		}
		if sup != 0 {
			if err := supersedeOp(ctx, tx, ref, sup); err != nil {
				return err
			}
		}
		superseded = sup
		return tx.QueryRow(ctx, `insert into operation (ref, kind, state, params, epoch, generation)
			values ($1, 'restore', 'pending', $2, (select epoch from cp_meta), $3) returning id`,
			ref, orEmpty(params), gen).Scan(&id)
	})
	if err != nil {
		return 0, 0, err
	}
	return id, superseded, nil
}

// NextOperation returns the open operation that is due, is the oldest open
// operation of its ref, and whose ref lock nobody holds — of those, the one
// least recently written (every attempt and every FailAttempt refreshes
// updated_at), so the project least recently run goes first and a backed-off
// operation never pre-empts another project's ready one.
func (s *Store) NextOperation(ctx context.Context) (op Operation, ok bool, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "select "+opCols+" from operation o where state in "+readyStates+` and not_before <= now()
			and not exists (select 1 from operation p where p.ref = o.ref and p.id < o.id and p.state in `+openStates+`)
			order by updated_at, id`)
		if err != nil {
			return err
		}
		ops, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Operation, error) { return scanOp(r) })
		if err != nil {
			return err
		}
		for _, o := range ops {
			// A transaction-level try fails while another session holds the
			// ref's session lock, and is released again at commit.
			var free bool
			if err := tx.QueryRow(ctx, "select pg_try_advisory_xact_lock($1, hashtext($2))", lockClassRef, o.Ref).Scan(&free); err != nil {
				return err
			}
			if free {
				op, ok = o, true
				return nil
			}
		}
		return nil
	})
	return op, ok, err
}

func (s *Store) GetOperation(ctx context.Context, id int64) (Operation, error) {
	o, err := scanOp(s.pool.QueryRow(ctx, "select "+opCols+" from operation where id = $1", id))
	return o, wrap(err)
}

// ListOperations returns the newest 200 operations, of one ref or ("") of all.
func (s *Store) ListOperations(ctx context.Context, ref string) ([]Operation, error) {
	rows, err := s.pool.Query(ctx, "select "+opCols+" from operation where $1 = '' or ref = $1 order by id desc limit 200", ref)
	if err != nil {
		return nil, err
	}
	ops, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Operation, error) { return scanOp(r) })
	return ops, wrap(err)
}

// opUpdate runs a guarded update of one operation: no row matched is
// ErrNotFound when the operation does not exist, ErrConflict when its state
// did not admit the write.
func (s *Store) opUpdate(ctx context.Context, q string, args ...any) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, q, args...)
		if err != nil || tag.RowsAffected() > 0 {
			return err
		}
		var state string
		if err := tx.QueryRow(ctx, "select state from operation where id = $1", args[0]).Scan(&state); err != nil {
			return err
		}
		return fmt.Errorf("%w: operation is %s", ErrConflict, state)
	})
}

// StartOperation: pending or running → running, attempts + 1.
func (s *Store) StartOperation(ctx context.Context, id int64) error {
	return s.opUpdate(ctx, `update operation set state = 'running', attempts = attempts + 1, updated_at = now()
		where id = $1 and state in ('pending', 'running')`, id)
}

// AdvanceStep records the last completed step of a running operation.
func (s *Store) AdvanceStep(ctx context.Context, id int64, step string) error {
	return s.opUpdate(ctx, "update operation set step = $2, updated_at = now() where id = $1 and state = 'running'", id, step)
}

func (s *Store) SetOperationParams(ctx context.Context, id int64, params json.RawMessage) error {
	return s.opUpdate(ctx, "update operation set params = $2, updated_at = now() where id = $1", id, orEmpty(params))
}

// FailAttempt backs an operation off until retryAt: a running one goes back to
// pending; an aborting one stays aborting and counts one more attempt (the
// worker never starts an aborting operation, so there attempts counts failed
// compensation runs).
func (s *Store) FailAttempt(ctx context.Context, id int64, lastError string, retryAt time.Time) error {
	return s.opUpdate(ctx, `update operation set state = case state when 'running' then 'pending' else state end,
		attempts = case state when 'aborting' then attempts + 1 else attempts end,
		last_error = $2, not_before = $3, updated_at = now() where id = $1 and state in ('running', 'aborting')`,
		id, lastError, retryAt)
}

// FinishOperation ends a running operation as done or failed, or an aborting
// one as aborted. A running restart may also end aborted: it was rolled back
// to its previous configuration, which is final (RetryOperation takes only a
// failed operation) and not open.
func (s *Store) FinishOperation(ctx context.Context, id int64, state, lastError string) error {
	from := map[string]string{"done": "running", "failed": "running", "aborted": "aborting"}[state]
	if from == "" {
		return fmt.Errorf("%w: %q is not a final state", ErrConflict, state)
	}
	return s.opUpdate(ctx, `update operation set state = $2, last_error = nullif($3, ''), updated_at = now()
		where id = $1 and (state = $4 or $2 = 'aborted' and kind = 'restart' and state = 'running')`, id, state, lastError, from)
}

// RetryOperation puts a failed operation back to pending with attempts 0,
// unless its ref has another open operation, and a restore only while it is
// the ref's newest operation. It also raises params.job_floor
// to the highest job id, so the retried steps never take an earlier pass's job.
func (s *Store) RetryOperation(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var ref, state string
		if err := tx.QueryRow(ctx, "select ref, state from operation where id = $1", id).Scan(&ref, &state); err != nil {
			return err
		}
		// The project row lock serialises this against SubmitOperation.
		if _, err := lockProject(ctx, tx, ref); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "select state from operation where id = $1 for update", id).Scan(&state); err != nil {
			return err
		}
		if state != "failed" {
			return fmt.Errorf("%w: operation is %s; only a failed operation can be retried", ErrConflict, state)
		}
		if err := openOperation(ctx, tx, ref, id); err != nil {
			return err
		}
		// A restore's set and target were chosen at its submit; an operation
		// accepted after it may have restored, restarted or let the tenant
		// write since, and restores keep the generation, so no later check
		// would see it.
		var kind string
		var newer int64
		if err := tx.QueryRow(ctx, "select kind, coalesce((select max(id) from operation where ref = $2 and id > $1), 0) from operation where id = $1",
			id, ref).Scan(&kind, &newer); err != nil {
			return err
		}
		if kind == "restore" && newer != 0 {
			return fmt.Errorf("%w: operation %d was accepted after this restore; a restore is retried only while it is the project's newest operation", ErrConflict, newer)
		}
		_, err := tx.Exec(ctx, "update operation set state = 'pending', attempts = 0, params = "+raiseFloor+", not_before = now(), updated_at = now() where id = $1", id)
		return err
	})
}

// RequestAbort marks the open or failed create of a provisioning project
// aborting and returns its id; a create already aborting is returned as is.
// Every move to aborting resets attempts, which then counts compensation
// runs; a create parked failed after its compensation runs is re-armed. A
// project that is not provisioning (an active one included) is refused:
// step 12 makes it active and finishes the create in one transaction.
func (s *Store) RequestAbort(ctx context.Context, ref string) (opID int64, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		state, err := lockProject(ctx, tx, ref)
		if err != nil {
			return err
		}
		if state != "provisioning" {
			return fmt.Errorf("%w: project is %s", ErrConflict, state)
		}
		var opState string
		if err := tx.QueryRow(ctx, "select id, state from operation where ref = $1 and kind = 'create' order by id desc limit 1 for update", ref).
			Scan(&opID, &opState); err != nil {
			return fmt.Errorf("%w: no create operation", ErrConflict)
		}
		switch {
		case opState == "aborting":
			return nil
		case opState == "failed" || opState == "pending" || opState == "running" || opState == "waiting_job":
			_, err := tx.Exec(ctx, "update operation set state = 'aborting', attempts = 0, not_before = now(), updated_at = now() where id = $1", opID)
			return err
		}
		return fmt.Errorf("%w: create operation is %s", ErrConflict, opState)
	})
	return opID, err
}

// SetPurgeNow makes the ref's pending purge due now.
func (s *Store) SetPurgeNow(ctx context.Context, ref string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		state, err := lockProject(ctx, tx, ref)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `update operation set not_before = now(), updated_at = now()
			where ref = $1 and kind = 'purge' and state = 'pending'`, ref)
		if err == nil && tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: no pending purge; project is %s", ErrConflict, state)
		}
		return err
	})
}

// ParkAbort ends an aborting create whose compensation has failed in 8 runs
// as failed, so it stops costing the worker; RequestAbort re-arms it.
func (s *Store) ParkAbort(ctx context.Context, id int64, lastError string) error {
	return s.opUpdate(ctx, `update operation set state = 'failed', last_error = $2, updated_at = now()
		where id = $1 and state = 'aborting' and attempts >= 8`, id, lastError)
}

// FinishCreate is a create's step 12 in one transaction: the operation done
// at step 12 and the project active at the operation's generation, only while
// the operation is a running create and the project provisioning. An abort
// that won leaves both as they were (ErrConflict).
func (s *Store) FinishCreate(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		// The project row first, then the operation row: the order of
		// RequestAbort, so the two cannot deadlock.
		var ref string
		if err := tx.QueryRow(ctx, "select ref from operation where id = $1", id).Scan(&ref); err != nil {
			return err
		}
		if _, err := lockProject(ctx, tx, ref); err != nil {
			return err
		}
		var gen int64
		err := tx.QueryRow(ctx, `update operation set state = 'done', step = '12', last_error = null, updated_at = now()
			where id = $1 and kind = 'create' and state = 'running' returning generation`, id).Scan(&gen)
		if errors.Is(err, pgx.ErrNoRows) {
			var state string
			if err := tx.QueryRow(ctx, "select state from operation where id = $1", id).Scan(&state); err != nil {
				return err
			}
			return fmt.Errorf("%w: operation is %s", ErrConflict, state)
		}
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "update project set state = 'active', applied_gen = $2 where ref = $1 and state = 'provisioning'", ref, gen)
		if err == nil && tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: project is no longer provisioning", ErrConflict)
		}
		return err
	})
}

// raiseFloor is the operation's params with job_floor set to the highest job
// id (0 when there is none): a job belongs to the current pass of a step only
// if its id is above the floor.
const raiseFloor = `jsonb_set(params, '{job_floor}', to_jsonb((select coalesce(max(id), 0) from backup_job)))`

// RaiseJobFloor sets params.job_floor of a running operation to the highest
// job id and, when count is set, counts one attempt, in one statement; it
// returns the floor and the attempts now stored.
func (s *Store) RaiseJobFloor(ctx context.Context, id int64, count bool) (floor int64, attempts int, err error) {
	add := 0
	if count {
		add = 1
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "update operation set params = "+raiseFloor+`, attempts = attempts + $2::int, updated_at = now()
			where id = $1 and state = 'running' returning (params->>'job_floor')::bigint, attempts`, id, add).
			Scan(&floor, &attempts)
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var state string
		if err := tx.QueryRow(ctx, "select state from operation where id = $1", id).Scan(&state); err != nil {
			return err
		}
		return fmt.Errorf("%w: operation is %s", ErrConflict, state)
	})
	return floor, attempts, err
}

// Requeue puts a running operation back to pending until notBefore and gives
// back the attempt it started with; last_error is kept. It is a wait, not a
// failure.
func (s *Store) Requeue(ctx context.Context, id int64, notBefore time.Time) error {
	return s.opUpdate(ctx, `update operation set state = 'pending', attempts = attempts - 1, not_before = $2, updated_at = now()
		where id = $1 and state = 'running'`, id, notBefore)
}

// SetOperationResult stores a running operation's result document.
func (s *Store) SetOperationResult(ctx context.Context, id int64, result json.RawMessage) error {
	return s.opUpdate(ctx, "update operation set result = $2, updated_at = now() where id = $1 and state = 'running'", id, result)
}

// SetProjectRestoring moves an active, restarting or restoring project to
// restoring, only while opID is an open restore of it.
func (s *Store) SetProjectRestoring(ctx context.Context, ref string, opID int64) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		state, err := lockProject(ctx, tx, ref)
		if err != nil {
			return err
		}
		var open bool
		if err := tx.QueryRow(ctx, "select exists (select 1 from operation where id = $1 and ref = $2 and kind = 'restore' and state in "+
			openStates+")", opID, ref).Scan(&open); err != nil {
			return err
		}
		if !open {
			return fmt.Errorf("%w: operation %d is not an open restore of the project", ErrConflict, opID)
		}
		if state != "active" && state != "restarting" && state != "restoring" {
			return fmt.Errorf("%w: project is %s", ErrConflict, state)
		}
		_, err = tx.Exec(ctx, "update project set state = 'restoring' where ref = $1", ref)
		return err
	})
}

// FinishRestore ends a running restore done with its result, makes its
// restoring project active and frees the project's slot, in one transaction.
// Anything else changes nothing (ErrConflict).
func (s *Store) FinishRestore(ctx context.Context, id int64, result json.RawMessage) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		// The project row first, then the operation row, as the submit path.
		var ref string
		if err := tx.QueryRow(ctx, "select ref from operation where id = $1", id).Scan(&ref); err != nil {
			return err
		}
		state, err := lockProject(ctx, tx, ref)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `update operation set state = 'done', result = $2, last_error = null, updated_at = now()
			where id = $1 and kind = 'restore' and state = 'running'`, id, result)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var opState, kind string
			if err := tx.QueryRow(ctx, "select state, kind from operation where id = $1", id).Scan(&opState, &kind); err != nil {
				return err
			}
			return fmt.Errorf("%w: operation %d (%s) is %s", ErrConflict, id, kind, opState)
		}
		if state != "restoring" {
			return fmt.Errorf("%w: project is %s", ErrConflict, state)
		}
		_, err = tx.Exec(ctx, "update project set state = 'active', slot_op = null where ref = $1", ref)
		return err
	})
}

// WindowError: a restore target outside the backups' window.
type WindowError struct{ From, To time.Time }

func (e *WindowError) Error() string {
	return fmt.Sprintf("the target is outside the restorable window from %s to %s",
		e.From.UTC().Format(time.RFC3339), e.To.UTC().Format(time.RFC3339))
}
