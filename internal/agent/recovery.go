package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// Seams of the recovery start's sessions (tests replace them).
var (
	bootstrapRekey        = bootstrap.Rekey
	bootstrapInRecovery   = bootstrap.InRecovery
	bootstrapReadTimeline = bootstrap.ReadTimeline
)

// EnsureRecovery starts pg-<ref> on a restored data directory as a recovery
// start: the layout-2 argv of a first boot without its password variable
// (no network, the image's own access files), labelled phase R, its command
// ending with the extension pins and then the recovery pins, the chosen
// target last. The pins are rendered before anything is touched. Any pg-<ref>
// is removed first, so one directory never has two servers; the start passes
// the gate as every start does. It never wipes and never bootstraps. state.json
// then records phase R with the init's pid and start time.
//
// Everything in the data directory is the tenant's: nothing of it is read here.
func (a *Agent) EnsureRecovery(ctx context.Context, s Spec, t pgconf.RecoveryTarget) error {
	if err := a.clusterSpec(s); err != nil {
		return err
	}
	if s.Layout != 2 {
		return fmt.Errorf("agent: %s: a recovery start needs layout 2, the project is at layout %d", s.Ref, s.Layout)
	}
	pins, err := pgconf.RecoveryPins(t)
	if err != nil {
		return fmt.Errorf("agent: %s: %w", s.Ref, err)
	}
	st, have, err := a.readState(s.Ref)
	if err != nil {
		return err
	}
	if err := checkState(st, have, s); err != nil {
		return err
	}
	if err := a.removeCluster(ctx, s.Ref); err != nil {
		return err
	}
	if err := a.renderCluster(s); err != nil {
		return err
	}
	args, err := a.recoveryRunArgs(s, pins)
	if err != nil {
		return err
	}
	nst, err := a.startCluster(ctx, s, args)
	if err != nil {
		return err
	}
	nst.Phase = PhaseR
	return a.writeState(s.Ref, nst)
}

// recoveryRunArgs is the first boot's argv (clusterRunArgs: the same flags
// and mounts, no network, no access-file mounts) with its password variable
// removed, phase label R, and the pins appended: nothing follows them.
func (a *Agent) recoveryRunArgs(s Spec, pins []string) ([]string, error) {
	args, err := a.clusterRunArgs(s, false)
	if err != nil {
		return nil, err
	}
	i := slices.Index(args, "--")
	pw := slices.IndexFunc(args[:i], func(v string) bool { return strings.HasPrefix(v, "POSTGRES_PASSWORD=") })
	ph := slices.Index(args[:i], labelPhase+"=A")
	if pw < 1 || args[pw-1] != "-e" || ph < 1 || args[ph-1] != "--label" {
		return nil, fmt.Errorf("agent: %s: the first boot's argv is not as the recovery start expects", s.Ref)
	}
	args[ph] = labelPhase + "=" + PhaseR
	args = slices.Delete(args, pw-1, pw+1)
	return slices.Concat(args, pgconf.RecoveryExtensionPins(), recoveryStartPins, pins), nil
}

// recoveryStartPins keep restored code from running beside the re-key, and a
// restored system file from delaying its session, in the recovery start only:
// between promotion and the re-key the background workers of the image's
// preloaded libraries would otherwise act on the restored database. The
// ordinary start after it carries none of them. An empty database name is
// one no database can have: the two workers fail to connect and are started
// again every second, two log lines each, for the life of the recovery start.
var recoveryStartPins = []string{
	"-c", "pre_auth_delay=0", // a delay before authentication set in the system file
	"-c", "pg_net.database_name=", // the HTTP extension's worker runs triggers of its tables at once
	"-c", "cron.database_name=", // the scheduler's launcher reads its tables, which the restored database defines
	"-c", "autovacuum=off", // an automatic analyze evaluates restored index expressions as their owner
	"-c", "max_logical_replication_workers=0", // a restored subscription gets no apply worker, whatever slot the set holds
}

// RecoveryState reads the recovery start of state.json: exited from Docker's
// record of pg-<ref> alone; promoted from a bounded trust session that asks
// the server whether it is still in recovery. A server that is not answering
// yet — no socket, nothing accepting on it, still starting up, or out of the
// session's budget — is not promoted, without an error; any other failure is
// an error. The answer is the restored cluster's word about itself.
func (a *Agent) RecoveryState(ctx context.Context, s Spec) (promoted, exited bool, err error) {
	st, err := a.recoveryStateFile(s)
	if err != nil {
		return false, false, err
	}
	c, err := dockerInspectContainer(ctx, clusterName(s.Ref))
	if err != nil {
		return false, false, err
	}
	if c == nil || !c.Running {
		return false, true, nil
	}
	conn, err := pgDial(ctx, a.clusterTarget(s, st, true))
	if err != nil {
		var se *pgsock.ServerError
		if errors.Is(err, pgsock.ErrConnect) || errors.Is(err, pgsock.ErrNotSocket) || pgsock.IsBudget(err) ||
			(errors.As(err, &se) && se.Code == "57P03") {
			return false, false, nil
		}
		return a.pollFailed(ctx, s, err)
	}
	defer closeSession(conn)
	in, err := bootstrapInRecovery(ctx, conn)
	if err != nil {
		if pgsock.IsBudget(err) {
			return false, false, nil
		}
		return a.pollFailed(ctx, s, fmt.Errorf("recovery state: %w", pgsock.Clean(err)))
	}
	return !in, false, nil
}

// Rekey gives the restored cluster the platform's verifiers in one trust
// session to the recorded recovery start: the verifier statements first
// (bootstrap.Rekey), then the timeline read, then the statistics reset, which
// is best effort and logged. It never asks whether the server is still in
// recovery (RecoveryState does, in a session of its own). It can be repeated:
// the session needs no password, so a re-key cut short never locks the
// platform out.
func (a *Agent) Rekey(ctx context.Context, s Spec) (timeline int, err error) {
	st, err := a.recoveryStateFile(s)
	if err != nil {
		return 0, err
	}
	conn, err := pgDial(ctx, a.clusterTarget(s, st, true))
	if err != nil {
		return 0, fmt.Errorf("agent: %s: %w", s.Ref, err)
	}
	defer closeSession(conn)
	if err := bootstrapRekey(ctx, conn, s.Secrets); err != nil {
		return 0, fmt.Errorf("agent: %s: re-key: %w", s.Ref, pgsock.Clean(err))
	}
	if timeline, err = bootstrapReadTimeline(ctx, conn); err != nil {
		return 0, fmt.Errorf("agent: %s: timeline: %w", s.Ref, pgsock.Clean(err))
	}
	switch reset, err := bootstrapResetStatementStats(ctx, conn); {
	case err != nil:
		slog.Warn("statement statistics not reset", "ref", s.Ref, "error", pgsock.Sanitize(err.Error(), 256))
	case !reset:
		slog.Info("statement statistics not reset: the function is not there", "ref", s.Ref)
	}
	return timeline, nil
}

// recoveryStateFile is state.json of a recovery start: phase R at the desired
// epoch, not of a newer generation.
func (a *Agent) recoveryStateFile(s Spec) (State, error) {
	if err := a.clusterSpec(s); err != nil {
		return State{}, err
	}
	st, have, err := a.readState(s.Ref)
	if err != nil {
		return State{}, err
	}
	if err := checkState(st, have, s); err != nil {
		return State{}, err
	}
	if !have || st.Phase != PhaseR {
		return State{}, fmt.Errorf("agent: %s: no recovery start recorded", s.Ref)
	}
	return st, nil
}

// pollFailed is a poll's failure: exited when the container stopped meanwhile
// (a session cut by the server's own exit), else the error.
func (a *Agent) pollFailed(ctx context.Context, s Spec, err error) (promoted, exited bool, _ error) {
	if c, ierr := dockerInspectContainer(ctx, clusterName(s.Ref)); ierr == nil && (c == nil || !c.Running) {
		return false, true, nil
	}
	return false, false, fmt.Errorf("agent: %s: %w", s.Ref, err)
}
