package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// NewJob is a job to queue. Lane is "push" for the kinds push and replicate
// and "backup" for every other kind.
type NewJob struct {
	Subject, Lane, Kind string
	OpID                int64
	OpStep              string
	Params              json.RawMessage
	DeadlineS           int
}

type Job struct {
	ID                         int64
	Subject, Lane, Kind, State string
	OpID                       int64 // 0: submitted by the scheduler
	OpStep                     string
	Params, Result             json.RawMessage
	Code, Message              string
	Runs, DeadlineS            int
	CreatedAt                  time.Time
	StartedAt, FinishedAt      *time.Time
}

const jobCols = `id, subject, lane, kind, state, coalesce(op_id, 0), op_step, params, result, coalesce(code, ''),
	coalesce(message, ''), runs, deadline_s, created_at, started_at, finished_at`

func scanJob(row pgx.Row) (Job, error) {
	var j Job
	var params, result []byte
	err := row.Scan(&j.ID, &j.Subject, &j.Lane, &j.Kind, &j.State, &j.OpID, &j.OpStep, &params, &result, &j.Code,
		&j.Message, &j.Runs, &j.DeadlineS, &j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	j.Params, j.Result = params, result
	return j, err
}

func collectJobs(rows pgx.Rows, err error) ([]Job, error) {
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Job, error) { return scanJob(r) })
}

// insertJob queues j, owned by opID (0: none). The lane must be the kind's,
// so that each lane's bound holds.
func insertJob(ctx context.Context, tx pgx.Tx, opID int64, j NewJob) (id int64, err error) {
	lane := "backup"
	if j.Kind == "push" || j.Kind == "replicate" {
		lane = "push"
	}
	if j.Lane != lane {
		return 0, fmt.Errorf("store: a %s job runs in the %s lane, not %q", j.Kind, lane, j.Lane)
	}
	var op *int64
	if opID != 0 {
		op = &opID
	}
	err = tx.QueryRow(ctx, `insert into backup_job (subject, lane, kind, state, op_id, op_step, params, deadline_s)
		values ($1, $2, $3, 'queued', $4, $5, $6, $7) returning id`,
		j.Subject, j.Lane, j.Kind, op, j.OpStep, orEmpty(j.Params), j.DeadlineS).Scan(&id)
	return id, err
}

// SubmitJob queues a job that no operation owns (j.OpID must be 0: an
// operation's job is submitted by SubmitJobAndPark).
func (s *Store) SubmitJob(ctx context.Context, j NewJob) (id int64, err error) {
	if j.OpID != 0 {
		return 0, fmt.Errorf("store: a job of operation %d is submitted by parking the operation", j.OpID)
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		id, err = insertJob(ctx, tx, 0, j)
		return err
	})
	return id, err
}

// SubmitJobAndPark queues j for operation opID and parks the operation, in
// one transaction: running → waiting_job, giving back the attempt that parks
// it. j.OpID is ignored. A operation that is not running is ErrConflict.
func (s *Store) SubmitJobAndPark(ctx context.Context, opID int64, j NewJob) (id int64, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `update operation set state = 'waiting_job', attempts = attempts - 1, updated_at = now()
			where id = $1 and state = 'running'`, opID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var state string
			if err := tx.QueryRow(ctx, "select state from operation where id = $1", opID).Scan(&state); err != nil {
				return err
			}
			return fmt.Errorf("%w: operation is %s", ErrConflict, state)
		}
		id, err = insertJob(ctx, tx, opID, j)
		return err
	})
	return id, err
}

// pickJob makes the next job of lane running, in one statement: among the
// queued jobs whose subject has no running job and whose project's slot is
// free or held by the job's operation, the control plane's first, then the
// subject whose last job started longest ago (never: first), then the lowest
// id. Each subject offers only its lowest eligible queued job (f), so two
// workers of one lane never go for the same subject: the second passes over
// the job the first holds to another subject.
//
// ponytail: the last-start order groups every job row of the lane's queued
// subjects (no index on subject); pruning keeps that to 48 h of jobs. Add an
// index on (subject, started_at) if a pick shows up in measurements.
const pickJob = `update backup_job set state = 'running', runs = runs + 1, started_at = now()
	where id = (
		select q.id from backup_job q
		join (select m.subject, min(m.id) as id from backup_job m left join project mp on mp.ref = m.subject
			where m.state = 'queued' and m.lane = $1 and (mp.slot_op is null or mp.slot_op = m.op_id)
			group by m.subject) f on f.id = q.id
		left join project p on p.ref = q.subject
		left join (select subject, max(started_at) as at from backup_job
			where subject in (select subject from backup_job where state = 'queued' and lane = $1) group by subject) l
			on l.subject = q.subject
		where q.state = 'queued' and q.lane = $1
			and not exists (select 1 from backup_job r where r.subject = q.subject and r.state = 'running')
			and (p.slot_op is null or p.slot_op = q.op_id)
		order by q.subject = 'cp' desc, l.at nulls first, q.id
		limit 1
		for update of q skip locked)
	and state = 'queued'
	returning ` + jobCols

// NextJob picks the next job of lane by the pick rule (pickJob) and returns
// it running, its runs counted. ok is false when no job was picked; the
// caller asks again on its next turn.
func (s *Store) NextJob(ctx context.Context, lane string) (j Job, ok bool, err error) {
	j, err = scanJob(s.pool.QueryRow(ctx, pickJob, lane))
	var pe *pgconn.PgError
	switch {
	case err == nil:
		return j, true, nil
	case errors.Is(err, pgx.ErrNoRows),
		// The unique index on a subject's running job is the slot: another
		// worker picked a job of the same subject at the same moment.
		errors.As(err, &pe) && pe.Code == "23505" && pe.ConstraintName == "backup_job_slot":
		return Job{}, false, nil
	}
	return Job{}, false, err
}

// FinishJob ends a running job done or failed. When its operation is
// waiting_job, that operation becomes pending, due now; a failure counts one
// attempt and becomes last_error ("<code>: <message>"), unless its code is
// interrupted or cancelled. An operation in any other state is not touched.
// A failure needs a code. A result that is not valid JSON ends the job failed
// with code crashed instead, and the call returns an error naming the job.
func (s *Store) FinishJob(ctx context.Context, id int64, state, code, message string, result json.RawMessage) error {
	if state != "done" && state != "failed" {
		return fmt.Errorf("%w: %q is not a final job state", ErrConflict, state)
	}
	if state == "failed" && code == "" {
		return fmt.Errorf("%w: job %d: a failure needs a code", ErrConflict, id)
	}
	if result != nil && !json.Valid(result) {
		if err := s.finishJob(ctx, id, "failed", "crashed", "the job's result is not valid JSON", nil); err != nil {
			return err
		}
		return fmt.Errorf("store: job %d: the result is not valid JSON; recorded failed with code crashed", id)
	}
	return s.finishJob(ctx, id, state, code, message, result)
}

func (s *Store) finishJob(ctx context.Context, id int64, state, code, message string, result json.RawMessage) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var op *int64
		err := tx.QueryRow(ctx, `update backup_job set state = $2, code = nullif($3, ''), message = nullif($4, ''), result = $5,
			finished_at = now() where id = $1 and state = 'running' returning op_id`, id, state, code, message, result).Scan(&op)
		if errors.Is(err, pgx.ErrNoRows) {
			var cur string
			if err := tx.QueryRow(ctx, "select state from backup_job where id = $1", id).Scan(&cur); err != nil {
				return err
			}
			return fmt.Errorf("%w: job is %s", ErrConflict, cur)
		}
		if err != nil || op == nil {
			return err
		}
		return resumeOp(ctx, tx, *op, state == "failed" && code != "interrupted" && code != "cancelled", code+": "+message)
	})
}

// resumeOp moves a waiting_job operation to pending, due now; count adds one
// attempt and sets last_error.
func resumeOp(ctx context.Context, tx pgx.Tx, op int64, count bool, lastError string) error {
	_, err := tx.Exec(ctx, `update operation set state = 'pending', not_before = now(), updated_at = now(),
		attempts = attempts + case when $2 then 1 else 0 end,
		last_error = case when $2 then $3 else last_error end
		where id = $1 and state = 'waiting_job'`, op, count, lastError)
	return err
}

// LatestJob is the newest job of op's step with an id above floor.
func (s *Store) LatestJob(ctx context.Context, opID int64, step string, floor int64) (Job, bool, error) {
	j, err := scanJob(s.pool.QueryRow(ctx, "select "+jobCols+` from backup_job
		where op_id = $1 and op_step = $2 and id > $3 order by id desc limit 1`, opID, step, floor))
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, false, nil
	}
	return j, err == nil, err
}

// CountJobs counts op's jobs of step with an id above floor.
func (s *Store) CountJobs(ctx context.Context, opID int64, step string, floor int64) (n int, err error) {
	err = s.pool.QueryRow(ctx, "select count(*) from backup_job where op_id = $1 and op_step = $2 and id > $3",
		opID, step, floor).Scan(&n)
	return n, err
}

// CountInterruptedJobs counts op's jobs of step with an id above floor that
// ended failed with code interrupted.
func (s *Store) CountInterruptedJobs(ctx context.Context, opID int64, step string, floor int64) (n int, err error) {
	err = s.pool.QueryRow(ctx, `select count(*) from backup_job where op_id = $1 and op_step = $2 and id > $3
		and state = 'failed' and code = 'interrupted'`, opID, step, floor).Scan(&n)
	return n, err
}

// InterruptJobs ends every running job failed with code interrupted, with
// FinishJob's effect on its operation (resumed, not counted). The caller has
// removed every job container first.
func (s *Store) InterruptJobs(ctx context.Context) (n int, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		ops, err := collectJobs(tx.Query(ctx, `update backup_job set state = 'failed', code = 'interrupted',
			message = 'the daemon stopped while the job ran', finished_at = now() where state = 'running' returning `+jobCols))
		if err != nil {
			return err
		}
		n = len(ops)
		for _, j := range ops {
			if j.OpID != 0 {
				if err := resumeOp(ctx, tx, j.OpID, false, ""); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return n, err
}

// cancelJobs ends the queued jobs matching cond failed with code cancelled
// and returns the running ones untouched: their containers are the caller's
// to stop, and the lane that runs each records its end.
func (s *Store) cancelJobs(ctx context.Context, cond string, arg any) (running []Job, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `update backup_job set state = 'failed', code = 'cancelled', message = 'cancelled',
			finished_at = now() where state = 'queued' and `+cond, arg); err != nil {
			return err
		}
		running, err = collectJobs(tx.Query(ctx, "select "+jobCols+" from backup_job where state = 'running' and "+cond+" order by id", arg))
		return err
	})
	return running, err
}

// CancelJobs cancels the jobs of operation opID (cancelJobs).
func (s *Store) CancelJobs(ctx context.Context, opID int64) (running []Job, err error) {
	return s.cancelJobs(ctx, "op_id = $1", opID)
}

// CancelSubjectJobs cancels every job of subject, whoever submitted it
// (cancelJobs).
func (s *Store) CancelSubjectJobs(ctx context.Context, subject string) (running []Job, err error) {
	return s.cancelJobs(ctx, "subject = $1", subject)
}

// LastJob is the newest job of subject and kind, in any state.
func (s *Store) LastJob(ctx context.Context, subject, kind string) (Job, bool, error) {
	j, err := scanJob(s.pool.QueryRow(ctx, "select "+jobCols+` from backup_job
		where subject = $1 and kind = $2 order by id desc limit 1`, subject, kind))
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, false, nil
	}
	return j, err == nil, err
}

// PruneJobs deletes at most limit finished jobs that ended before olderThan,
// that no backup set references and whose operation, if any, is not open.
func (s *Store) PruneJobs(ctx context.Context, olderThan time.Time, limit int) (int, error) {
	tag, err := s.pool.Exec(ctx, `delete from backup_job where id in (
		select j.id from backup_job j
		where j.state in ('done', 'failed') and j.finished_at < $1
			and not exists (select 1 from backup_set b where b.job_id = j.id)
			and not exists (select 1 from operation o where o.id = j.op_id and o.state in `+openStates+`)
		order by j.finished_at limit $2)`, olderThan, limit)
	return int(tag.RowsAffected()), err
}
