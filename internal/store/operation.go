package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const opCols = `id, ref, kind, state, step, attempts, params, epoch, generation, not_before, coalesce(last_error, ''),
	created_at, updated_at`

const openStates = `('pending', 'running', 'aborting')`

func scanOp(row pgx.Row) (Operation, error) {
	var o Operation
	var params []byte
	err := row.Scan(&o.ID, &o.Ref, &o.Kind, &o.State, &o.Step, &o.Attempts, &params, &o.Epoch, &o.Generation, &o.NotBefore, &o.LastError, &o.CreatedAt, &o.UpdatedAt)
	o.Params = params
	return o, err
}

func orEmpty(params json.RawMessage) json.RawMessage {
	if len(params) == 0 {
		return json.RawMessage("{}")
	}
	return params
}

// hasOpenOperation reports whether ref has an open operation other than except.
func hasOpenOperation(ctx context.Context, tx pgx.Tx, ref string, except int64) (bool, error) {
	var open bool
	err := tx.QueryRow(ctx, "select exists (select 1 from operation where ref = $1 and id <> $2 and state in "+openStates+")",
		ref, except).Scan(&open)
	return open, err
}

// SubmitOperation queues a restart or delete of an active project with no
// other open operation. A restart targets generation + 1, anything else the
// current generation; project.generation itself is not touched.
func (s *Store) SubmitOperation(ctx context.Context, ref, kind string, params json.RawMessage, notBefore time.Time) (int64, error) {
	if kind != "restart" && kind != "delete" {
		return 0, fmt.Errorf("%w: operation kind %q cannot be submitted", ErrConflict, kind)
	}
	var id int64
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var state string
		var gen int64
		if err := tx.QueryRow(ctx, "select state, generation from project where ref = $1 for update", ref).Scan(&state, &gen); err != nil {
			return err
		}
		if state != "active" {
			return fmt.Errorf("%w: %s needs an active project; it is %s", ErrConflict, kind, state)
		}
		// Two open restarts would both target generation + 1.
		open, err := hasOpenOperation(ctx, tx, ref, 0)
		if err != nil {
			return err
		}
		if open {
			return fmt.Errorf("%w: the project has an open operation", ErrConflict)
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

// NextOperation returns the lowest-id open operation that is due, is the
// oldest open operation of its ref, and whose ref lock nobody holds.
func (s *Store) NextOperation(ctx context.Context) (op Operation, ok bool, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "select "+opCols+" from operation o where state in "+openStates+` and not_before <= now()
			and not exists (select 1 from operation p where p.ref = o.ref and p.id < o.id and p.state in `+openStates+`)
			order by id`)
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
// pending; an aborting one stays aborting.
func (s *Store) FailAttempt(ctx context.Context, id int64, lastError string, retryAt time.Time) error {
	return s.opUpdate(ctx, `update operation set state = case state when 'running' then 'pending' else state end,
		last_error = $2, not_before = $3, updated_at = now() where id = $1 and state in ('running', 'aborting')`,
		id, lastError, retryAt)
}

// FinishOperation ends a running operation as done or failed, or an aborting
// one as aborted.
func (s *Store) FinishOperation(ctx context.Context, id int64, state, lastError string) error {
	from := map[string]string{"done": "running", "failed": "running", "aborted": "aborting"}[state]
	if from == "" {
		return fmt.Errorf("%w: %q is not a final state", ErrConflict, state)
	}
	return s.opUpdate(ctx, `update operation set state = $2, last_error = nullif($3, ''), updated_at = now()
		where id = $1 and state = $4`, id, state, lastError, from)
}

// RetryOperation puts a failed operation back to pending with attempts 0,
// unless its ref has another open operation.
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
			return fmt.Errorf("%w: operation is %s", ErrConflict, state)
		}
		open, err := hasOpenOperation(ctx, tx, ref, id)
		if err != nil {
			return err
		}
		if open {
			return fmt.Errorf("%w: the project has another open operation", ErrConflict)
		}
		_, err = tx.Exec(ctx, "update operation set state = 'pending', attempts = 0, not_before = now(), updated_at = now() where id = $1", id)
		return err
	})
}

// RequestAbort marks the open or failed create of a provisioning project
// aborting and returns its id; a create already aborting is returned as is.
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
		switch opState {
		case "aborting":
			return nil
		case "pending", "running", "failed":
			_, err := tx.Exec(ctx, "update operation set state = 'aborting', not_before = now(), updated_at = now() where id = $1", opID)
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
