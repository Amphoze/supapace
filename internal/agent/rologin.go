package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// Seams of the read-only login's sessions (tests replace them).
var (
	bootstrapSetReadOnlyVerifier = bootstrap.SetReadOnlyVerifier
	bootstrapDeleteReadOnlyJobs  = bootstrap.DeleteReadOnlyJobs
)

// The clean-up's session: its own deadline whatever the caller's, and the
// two timeouts it sends at startup, so that a lock or a statement of the
// tenant's cannot hold it. dropJobsDeadline is a variable for tests only.
var dropJobsDeadline = 15 * time.Second

const (
	dropJobsLock      = 2 * time.Second
	dropJobsStatement = 10 * time.Second
)

// phaseBTarget is the platform's SCRAM session as supabase_admin to the
// recorded postmaster of a cluster started in phase B.
func (a *Agent) phaseBTarget(s Spec) (pgsock.Target, error) {
	if err := a.clusterSpec(s); err != nil {
		return pgsock.Target{}, err
	}
	st, have, err := a.readState(s.Ref)
	if err != nil {
		return pgsock.Target{}, err
	}
	if err := checkState(st, have, s); err != nil {
		return pgsock.Target{}, err
	}
	if !have || st.Phase != PhaseB {
		return pgsock.Target{}, fmt.Errorf("agent: %s: cluster not started in phase B", s.Ref)
	}
	return a.clusterTarget(s, st, false), nil
}

// SetReadOnlyLogin gives the read-only login the platform's verifier of
// s.Secrets.ReadOnlyPassword in one SCRAM session as the platform's
// superuser (the superuser startup list): the password statement first, then
// the reset of the statement statistics, best effort and logged.
func (a *Agent) SetReadOnlyLogin(ctx context.Context, s Spec) error {
	tg, err := a.phaseBTarget(s)
	if err != nil {
		return err
	}
	conn, err := pgDial(ctx, tg)
	if err != nil {
		return fmt.Errorf("agent: %s: %w", s.Ref, err)
	}
	defer closeSession(conn)
	if err := bootstrapSetReadOnlyVerifier(ctx, conn, s.Secrets); err != nil {
		return fmt.Errorf("agent: %s: read-only login: %w", s.Ref, pgsock.Clean(err))
	}
	switch reset, err := bootstrapResetStatementStats(ctx, conn); {
	case err != nil:
		slog.Warn("statement statistics not reset", "ref", s.Ref, "error", pgsock.Sanitize(err.Error(), 256))
	case !reset:
		slog.Info("statement statistics not reset: the function is not there", "ref", s.Ref)
	}
	return nil
}

// DropReadOnlyJobs ends the read-only role's sessions and workers and
// deletes its scheduled jobs (bootstrap.DeleteReadOnlyJobs) in one SCRAM
// session as the platform's superuser, under dropJobsDeadline of its own: the
// superuser startup list with lock_timeout and statement_timeout set, and
// nothing that turns triggers off. A deadline is worded by its cause: the
// run's own (no clean pass within 15 s, with the last pass's reason), the
// caller's shorter one, or one pass's statement budget with time left.
func (a *Agent) DropReadOnlyJobs(caller context.Context, s Spec) error {
	ctx, cancel := context.WithTimeout(caller, dropJobsDeadline)
	defer cancel()
	tg, err := a.phaseBTarget(s)
	if err != nil {
		return err
	}
	tg.LockTimeout, tg.StatementTimeout = dropJobsLock, dropJobsStatement
	conn, err := pgDial(ctx, tg)
	if err != nil {
		return fmt.Errorf("agent: %s: %w", s.Ref, err)
	}
	defer closeSession(conn)
	err = pgsock.Clean(bootstrapDeleteReadOnlyJobs(ctx, conn))
	switch {
	case !errors.Is(err, context.DeadlineExceeded):
	case caller.Err() != nil:
		return fmt.Errorf("agent: %s: the caller's deadline passed before a clean pass: %w", s.Ref, err)
	case ctx.Err() != nil:
		return fmt.Errorf("agent: %s: no clean pass within %d s: %w", s.Ref, int(dropJobsDeadline/time.Second), err)
	default:
		return fmt.Errorf("agent: %s: a pass ran out of its statement budget: %w", s.Ref, err)
	}
	if err != nil {
		return fmt.Errorf("agent: %s: %w", s.Ref, err)
	}
	return nil
}
