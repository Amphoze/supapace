package bootstrap

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// The clean-up of the read-only role's sessions and scheduled jobs. One pass
// is one transaction of seven statements sent as one query: the role's
// backends ended (every session and every background worker of the role,
// and with them any lock one of them holds), the job table locked under the
// session's lock timeout, the role's rows deleted, the activity snapshot
// cleared (the server reads the activity view once in a transaction, so the
// second ending would otherwise list the first's backends again), the role's
// backends ended again, commit. Ending a backend is not undone by a rollback.
const (
	sqlBegin              = "begin"
	sqlEndReadOnly        = "select backend_type, pg_catalog.pg_terminate_backend(pid) from pg_catalog.pg_stat_activity where usename = 'supabase_read_only_user'"
	sqlLockJobs           = "lock table cron.job in exclusive mode"
	sqlDeleteReadOnlyJobs = "delete from cron.job where username = 'supabase_read_only_user'"
	sqlClearActivity      = "select pg_catalog.pg_stat_clear_snapshot()"
	sqlCommit             = "commit"
	sqlRollback           = "rollback"
	sqlReadOnlyJobsPass   = sqlBegin + ";\n" + sqlEndReadOnly + ";\n" + sqlLockJobs + ";\n" + sqlDeleteReadOnlyJobs + ";\n" +
		sqlClearActivity + ";\n" + sqlEndReadOnly + ";\n" + sqlCommit

	// The read-only login's stored verifier, at most 512 characters of it.
	sqlReadOnlyVerifier = "select pg_catalog.left(rolpassword, 512) from pg_catalog.pg_authid where rolname = 'supabase_read_only_user' limit 2"
)

const (
	passEvery = 100 * time.Millisecond // between two passes of a run
	// workerQuiet: a clean pass begins this long after the last pass that ended
	// a worker or deleted a row. The scheduler takes a deleted row into account
	// only at the top of its loop, whose wait is capped at 1 s, and a worker it
	// launched from its old list is listed under the role once its start-up has
	// finished: one loop plus the launch, with about 2 s of margin.
	workerQuiet = 3 * time.Second
	passAnswers = 7 // the statements of a pass
	lockAnswer  = 2 // the lock's place among them
	endAnswer2  = 5 // the second ending's
)

// The reasons a pass was not clean.
const (
	reasonLock    = "the lock was not granted"
	reasonWorker  = "a worker was ended"
	reasonDeleted = "a row was deleted"
	reasonQuiet   = "a worker was ended or a row deleted less than 3 s before"
)

// DeleteReadOnlyJobs ends the read-only role's sessions and workers and
// deletes its scheduled jobs (c: a session as supabase_admin with the
// clean-up's lock and statement timeouts, triggers on). It repeats the pass,
// passEvery apart, until a clean one: the lock granted, no row deleted, no
// backend other than a client session ended at either ending, and begun at
// least workerQuiet after the answers of the last pass of the run that ended
// one or deleted a row were read: until its commit a pass's rows are still
// in the scheduler's cache, which can launch a worker that the next pass
// does not list yet. A lock not granted (55P03) is repeated; the transaction is
// closed before the next pass. No such table or no such schema (42P01,
// 3F000: the extension is not there) at the lock: the first ending has run,
// the transaction is rolled back and the run is done. Any other error ends
// the run at once. A ctx that ends first is an error with the last pass's
// reason. What the cluster answers decides only whether to repeat.
func DeleteReadOnlyJobs(ctx context.Context, c *pgx.Conn) error {
	var lastFound time.Time // when the answers of the last pass that ended a worker or deleted a row were read
	reason := "none answered"
	for {
		start := time.Now()
		ans, status, err := pipeSQL(ctx, c, sqlReadOnlyJobsPass)
		if err == nil && status != 'I' {
			err = execSQL(ctx, c, sqlRollback)
		}
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("bootstrap: read-only jobs: last pass: %s: %w", reason, ctx.Err())
			}
			return fmt.Errorf("bootstrap: read-only jobs: %w", err)
		}
		r, worker, err := judgePass(ans)
		switch {
		case errors.Is(err, errNoTable):
			return nil
		case err != nil:
			return fmt.Errorf("bootstrap: read-only jobs: %w", err)
		}
		if worker || r == reasonDeleted {
			lastFound = time.Now()
		}
		if r == "" && !lastFound.IsZero() && start.Sub(lastFound) < workerQuiet {
			r = reasonQuiet
		}
		if r == "" {
			return nil
		}
		reason = r
		if err := sleep(ctx, passEvery); err != nil {
			return fmt.Errorf("bootstrap: read-only jobs: last pass: %s: %w", reason, err)
		}
	}
}

var errNoTable = errors.New("no job table")

// judgePass reads one pass's answers: why it was not clean ("" when it
// found nothing) and whether an ending ended a backend other than a client
// session; errNoTable, or the error that ends the run.
func judgePass(ans []answer) (reason string, worker bool, err error) {
	for i, a := range ans {
		if i == 1 || i == endAnswer2 {
			for _, ty := range a.first {
				worker = worker || ty != "client backend"
			}
		}
		if a.err == nil {
			continue
		}
		var se *pgsock.ServerError
		switch {
		case i == lockAnswer && errors.As(a.err, &se) && se.Code == "55P03":
			return reasonLock, worker, nil
		case i == lockAnswer && errors.As(a.err, &se) && (se.Code == "42P01" || se.Code == "3F000"):
			return "", worker, errNoTable
		}
		return "", worker, a.err
	}
	switch {
	case len(ans) != passAnswers:
		return "", worker, fmt.Errorf("%d answers to a pass of %d statements", len(ans), passAnswers)
	case worker:
		return reasonWorker, true, nil
	case pgconn.NewCommandTag(ans[3].tag).RowsAffected() != 0:
		return reasonDeleted, false, nil
	}
	return "", false, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// answer is the server's answer to one statement of a pipelined query: the
// first column of its rows and its command tag, or its refusal.
type answer struct {
	first []string
	tag   string
	err   error
}

// pipeSQL sends sql, constant statements separated by semicolons, as one
// query under one statement budget: every statement is written before any
// answer is read. It returns each statement's answer, in order, as far as
// the server answered, and the transaction status the server reported last.
// A refusal is the answer of its statement; err is reserved for the session.
func pipeSQL(ctx context.Context, c *pgx.Conn, sql string) (ans []answer, status byte, err error) {
	sctx, cancel := pgsock.Stmt(ctx, pgsock.DefaultBudget)
	defer cancel()
	pc := c.PgConn()
	pc.Frontend().Send(&pgproto3.Query{String: sql})
	if err := pc.Frontend().Flush(); err != nil {
		return nil, 0, pgsock.Clean(err)
	}
	var cur answer
	for {
		msg, err := pc.ReceiveMessage(sctx)
		if err != nil {
			pc.Close(context.Background()) // the session's state is unknown: it is not used again
			return nil, 0, pgsock.Clean(err)
		}
		switch m := msg.(type) {
		case *pgproto3.RowDescription:
			cur = answer{}
		case *pgproto3.DataRow:
			if len(m.Values) > 0 {
				cur.first = append(cur.first, string(m.Values[0]))
			}
		case *pgproto3.CommandComplete:
			cur.tag = string(m.CommandTag)
			ans, cur = append(ans, cur), answer{}
		case *pgproto3.EmptyQueryResponse:
			ans, cur = append(ans, answer{}), answer{}
		case *pgproto3.ErrorResponse:
			ans, cur = append(ans, answer{err: pgsock.Clean(pgconn.ErrorResponseToPgError(m))}), answer{}
		case *pgproto3.ReadyForQuery:
			return ans, m.TxStatus, nil
		}
	}
}

// SetReadOnlyVerifier sets the read-only login's password to the verifier
// of s.ReadOnlyPassword as the session's first statement: the verifier is
// computed first (the four passwords must differ) and sent through
// setVerifier, in the one form of the platform's password statements.
func SetReadOnlyVerifier(ctx context.Context, c *pgx.Conn, s Secrets) error {
	if s.ReadOnlyPassword == "" {
		return errors.New("bootstrap: no password for supabase_read_only_user")
	}
	vs, err := verifiers(s)
	if err != nil {
		return err
	}
	v := vs[len(vs)-1]
	if err := setVerifier(ctx, c, v.prefix, v.verifier); err != nil {
		return fmt.Errorf("bootstrap: password of %s: %w", v.role, err)
	}
	return nil
}

// AssertReadOnlyVerifier reports, under the check service-passwords, a
// verifier of the read-only login that is not the platform's: one stored
// while s.ReadOnlyPassword is empty, or one that differs from the verifier of
// that password with the platform's salt and count. No verifier passes.
// Nothing read is parsed: at most 512 characters are compared, in constant
// time, with the expected verifier. No verifier, salt or password reaches a
// finding.
func AssertReadOnlyVerifier(ctx context.Context, c *pgx.Conn, s Secrets) ([]nodecfg.CheckResult, error) {
	var want string
	if s.ReadOnlyPassword != "" {
		v, err := pgsock.ScramVerifier(s.ReadOnlyPassword, s.ScramSalts["supabase_read_only_user"])
		if err != nil {
			return nil, fmt.Errorf("bootstrap: verifier for supabase_read_only_user: %w", err)
		}
		want = v
	}
	r := &report{n: map[string]int{}}
	err := querySQL(ctx, c, sqlReadOnlyVerifier, nil, func(rows pgx.Rows) error {
		var got *string
		if err := rows.Scan(&got); err != nil || got == nil {
			return err
		}
		switch {
		case want == "":
			r.add(checkServicePasswords, "role supabase_read_only_user has a password, present without a platform secret")
		case subtle.ConstantTimeCompare([]byte(*got), []byte(want)) != 1:
			r.add(checkServicePasswords, "role supabase_read_only_user has a password that differs from the platform's")
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: assert %s: %w", checkServicePasswords, err)
	}
	return r.out, nil
}
