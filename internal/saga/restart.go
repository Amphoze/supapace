package saga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/store"
)

// Restart steps. The operation targets generation g+1 with params.next; the
// project's desired generation stays g until R2, after the candidate passed
// pre-validation. If R3 or R4 fails, the restart rolls forward to g+2 with
// params.prev (the configuration of g, as stored), from R1.
var restartSteps = []step{
	{"R0", (*job).checkBase},
	{"R1", (*job).prevalidate},
	{"R2", (*job).drain},
	{"R3", (*job).restartCluster},
	{"R4", (*job).health},
	{"R5", (*job).resume},
}

type restartParams struct {
	BaseGeneration int64               `json:"base_generation"`
	Prev           store.ProjectConfig `json:"prev"`
	Next           store.ProjectConfig `json:"next"`
	RollbackGen    int64               `json:"rollback_gen,omitempty"`
	RollbackError  string              `json:"rollback_error,omitempty"`
	RollbackStep   string              `json:"rollback_step,omitempty"` // "R3" when the stop/start step failed; absent after R4
}

func (x *job) restartParams() (restartParams, error) {
	var p restartParams
	if err := json.Unmarshal(x.op.Params, &p); err != nil {
		return p, final("internal", errors.New("restart parameters do not parse"))
	}
	return p, nil
}

// target is the generation and configuration this pass applies: g+1 with
// next, or, once a rollback started, its generation with prev.
func (x *job) target() (int64, store.ProjectConfig, error) {
	p, err := x.restartParams()
	if p.RollbackGen != 0 {
		return p.RollbackGen, p.Prev, err
	}
	return x.op.Generation, p.Next, err
}

// candidate is the spec of the target before R2: the project as stored, at
// the target generation and configuration.
func (x *job) candidate(ctx context.Context) (agent.Spec, error) {
	gen, cfg, err := x.target()
	if err != nil {
		return agent.Spec{}, err
	}
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil {
		return agent.Spec{}, err
	}
	return x.r.spec(ctx, p, x.op.Epoch, gen, cfg)
}

// restartStart resumes after the recorded step, except that a rollback whose
// own R2 has not yet bumped the project starts again at R1. Every pick checks
// that the project is still this operation's before any agent call; a
// restart superseded by another one is a conflict.
func (x *job) restartStart(ctx context.Context, table []step) (int, error) {
	rp, err := x.restartParams()
	if err != nil {
		return 0, err
	}
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil {
		return 0, err
	}
	i := indexOf(table, x.op.Step) + 1
	if rp.RollbackGen != 0 && p.Generation < rp.RollbackGen {
		// The rollback's own bump is still to come: the first pass's must be
		// in place.
		if p.Generation != x.op.Generation || p.State != "restarting" || !sameConfig(p.Config, rp.Next) {
			return 0, final("conflict", fmt.Errorf("rollback to generation %d: the project is %s at generation %d, not by this restart",
				rp.RollbackGen, p.State, p.Generation))
		}
		return indexOf(table, "R1"), nil
	}
	if i > indexOf(table, "R2") || rp.RollbackGen != 0 && i == indexOf(table, "R2") {
		// Past this pass's bump: the project must carry it — the target
		// generation, restarting, the target's configuration; from R5 on it
		// may already be active at that target (R5's state write happened).
		gen, cfg, err := x.target()
		if err != nil {
			return 0, err
		}
		ours := p.Generation == gen && sameConfig(p.Config, cfg) &&
			(p.State == "restarting" || p.State == "active" && i >= indexOf(table, "R5"))
		if !ours {
			return 0, final("conflict", fmt.Errorf("restart targets generation %d; the project is %s at generation %d, not by this restart",
				gen, p.State, p.Generation))
		}
		if i == indexOf(table, "R4") {
			// R4 waits only for a cluster this attempt started. One that an
			// earlier attempt started may never answer (its server can wait
			// at start on a file of the tenant's), and adopting it again would
			// only repeat the wait: R3 stops it and starts the target afresh.
			i = indexOf(table, "R3")
		}
		return i, nil
	}
	// Before the first bump the project must still be at the generation the
	// restart was merged onto — active, or restarting when this restart was
	// admitted after a failed one (the store admits that only while no other
	// operation is open) — or already carry this operation's own bump (a
	// resumed R2 whose completion was not recorded): its target generation,
	// restarting, with this operation's configuration. Another restart's bump,
	// or one applied since, is a conflict.
	base := p.Generation == rp.BaseGeneration && (p.State == "active" || p.State == "restarting")
	own := p.Generation == x.op.Generation && p.State == "restarting" && sameConfig(p.Config, rp.Next)
	if !base && !own {
		return 0, final("conflict", fmt.Errorf("restart was merged onto generation %d; the project is %s at generation %d",
			rp.BaseGeneration, p.State, p.Generation))
	}
	return i, nil
}

func sameConfig(a, b store.ProjectConfig) bool {
	return a.DiskQuotaMB == b.DiskQuotaMB && a.MemMB == b.MemMB && maps.Equal(a.GUC, b.GUC)
}

// R0: the merge base must be the generation just below the target (a second
// line behind the admission check). Nothing is touched here.
func (x *job) checkBase(ctx context.Context) error {
	rp, err := x.restartParams()
	if err != nil {
		return err
	}
	if rp.BaseGeneration != x.op.Generation-1 {
		return final("conflict", fmt.Errorf("restart was merged onto generation %d; it targets %d", rp.BaseGeneration, x.op.Generation))
	}
	return nil
}

// R1: a changed disk quota checked against the project's usage (the user
// quota's accounting, a host-side figure; it may have grown since the admin
// API checked it), then the candidate configuration checked in a task
// container; nothing live is touched. A roll-forward restores the previous
// quota unchecked.
func (x *job) prevalidate(ctx context.Context) error {
	s, err := x.candidate(ctx)
	if err != nil {
		return err
	}
	rp, err := x.restartParams()
	if err != nil {
		return err
	}
	if rp.RollbackGen == 0 && rp.Next.DiskQuotaMB != rp.Prev.DiskQuotaMB {
		used, err := x.r.ag.DiskUsage(ctx, s)
		if err != nil {
			return err
		}
		if err := store.CheckQuota(rp.Next.DiskQuotaMB, used); err != nil {
			return final("quota_below_usage", errors.New(strings.TrimPrefix(err.Error(), store.ErrQuotaBelowUsage.Error()+": ")))
		}
	}
	return x.r.ag.Prevalidate(ctx, s)
}

// R2: the desired generation and configuration, and the state restarting, in
// one statement (a no-op when resumed); the route draining and the gateway at
// that route file; PostgREST stopped.
func (x *job) drain(ctx context.Context) error {
	gen, cfg, err := x.target()
	if err != nil {
		return err
	}
	if err := x.r.st.BeginRestart(ctx, x.op.Ref, gen, cfg); errors.Is(err, store.ErrConflict) {
		return final("conflict", err) // another restart's bump, or a newer generation
	} else if err != nil {
		return err
	}
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	rt := x.r.ag.RouteFor(s, "draining")
	rgen, err := x.r.ag.SetRoute(ctx, x.op.Ref, &rt)
	if err != nil {
		return err
	}
	if err := x.r.waitGateway(ctx, rgen); err != nil {
		return err
	}
	return x.r.ag.StopPostgREST(ctx, x.op.Ref)
}

// R3: the cluster stopped; the disk quota of the bumped configuration set
// (limits only, on every pass; a roll-forward restores the previous one); the
// candidate promoted; the new generation started behind the gate
// (no health wait here). A failure rolls the restart forward as R4's does
// (the previous configuration may start where the new one does not, as with
// a quota below the usage); a failure of the rollback, the node's
// containment and a final failure are retried or failed as usual.
func (x *job) restartCluster(ctx context.Context) error {
	err := x.stopAndStart(ctx)
	rp, perr := x.restartParams()
	switch {
	case err == nil || perr != nil:
		return errors.Join(err, perr)
	case rp.RollbackGen != 0, errors.Is(err, agent.ErrContainment), errors.Is(err, bootstrap.ErrAssertion),
		errors.Is(err, agent.ErrEpochDivergence), isFinal(err):
		return err
	}
	return &rollForward{err: err, step: "R3"}
}

func isFinal(err error) bool {
	var f *failure
	return errors.As(err, &f) && f.final
}

func (x *job) stopAndStart(ctx context.Context) error {
	if err := x.r.ag.StopCluster(ctx, x.op.Ref); err != nil {
		return err
	}
	// The stored quota is set on every pass, changed or not (SetQuota is
	// idempotent and reads the limit back): a restart that takes over from a
	// failed one whose rollback stopped before restoring the previous quota
	// leaves no filesystem limit apart from the stored configuration.
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	if err := x.r.ag.SetQuota(ctx, s); err != nil {
		return err
	}
	if err := x.r.ag.PromoteCandidate(ctx, x.op.Ref); err != nil {
		return err
	}
	s.HealthWait = -1
	return x.r.ag.EnsureCluster(ctx, s)
}

// rollForward asks the step loop to roll a restart forward after R3 or R4
// failed; step is "R3" for R3 and empty for R4.
type rollForward struct {
	err  error
	step string
}

func (r *rollForward) Error() string { return r.err.Error() }

// R4: the same generation ensured again with the default health wait (it
// adopts R3's container), then the operational facts. A failure rolls the
// restart forward; a failure of the rollback fails the operation, leaving
// the project restarting with its route draining.
func (x *job) health(ctx context.Context) error {
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	s.HealthWait = 0
	err = x.r.ag.EnsureCluster(ctx, s)
	if err == nil {
		err = x.r.ag.VerifyCluster(ctx, s)
	}
	rp, perr := x.restartParams()
	switch {
	case err == nil || perr != nil:
		return errors.Join(err, perr)
	case errors.Is(err, agent.ErrContainment):
		return err
	case rp.RollbackGen == 0:
		return &rollForward{err: err}
	}
	return final(code(err), fmt.Errorf("rollback to generation %d: %w", rp.RollbackGen, err))
}

// rollForward records the rollback target g+2 (and why) in the parameters.
func (x *job) rollForward(ctx context.Context, rf *rollForward) error {
	rp, err := x.restartParams()
	if err != nil {
		return err
	}
	rp.RollbackGen = x.op.Generation + 1
	rp.RollbackError = x.r.lastError(rf.err)
	rp.RollbackStep = rf.step
	b, err := json.Marshal(rp)
	if err != nil {
		return err
	}
	if err := x.r.st.SetOperationParams(ctx, x.op.ID, b); err != nil {
		return err
	}
	x.op.Params = b
	x.r.log.Warn("restart rolls forward", "op", x.op.ID, "ref", x.op.Ref, "generation", rp.RollbackGen, "err", rp.RollbackError)
	return nil
}

// R5: PostgREST, the active route and the end-to-end probe, then active at
// the applied generation.
func (x *job) resume(ctx context.Context) error {
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	if err := x.r.ag.EnsurePostgREST(ctx, s); err != nil {
		return err
	}
	if err := x.expose(ctx, s); err != nil {
		return err
	}
	if err := x.r.st.SetProjectState(ctx, x.op.Ref, "active"); err != nil {
		return err
	}
	return x.r.st.SetApplied(ctx, x.op.Ref, s.Generation)
}

// outcome is how an operation whose steps all ran ends: done, or, for a
// restart that rolled forward to its previous configuration, aborted with
// code rolled_back. The setting asked for is not in force, so it is not a
// success; and it is not failed, which `op retry` would take up again.
func (x *job) outcome() (state, lastError string) {
	if x.op.Kind != "restart" {
		return "done", ""
	}
	rp, _ := x.restartParams()
	if rp.RollbackGen == 0 {
		return "done", ""
	}
	why := "its health check failed"
	if rp.RollbackStep == "R3" {
		why = "its stop/start step failed"
	}
	return "aborted", pgsock.Sanitize(fmt.Sprintf("rolled_back: the project runs its previous configuration at generation %d; "+
		"the restart to generation %d was rolled back because %s: %s",
		rp.RollbackGen, x.op.Generation, why, rp.RollbackError), maxLastError)
}

// stranded adds to the last_error of a restart that ends failed with its
// project restarting by its own bump (route draining, not served) that state
// and the commands that leave it.
func (x *job) stranded(ctx context.Context, msg string) string {
	if x.op.Kind != "restart" {
		return msg
	}
	rp, err := x.restartParams()
	if err != nil {
		return msg
	}
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil || p.State != "restarting" || p.Generation != x.op.Generation && p.Generation != rp.RollbackGen {
		return msg
	}
	note := fmt.Sprintf("; the project stays restarting at generation %d with its route draining: once the cause is removed, "+
		"'supapace op retry %d' continues this restart; 'supapace project restart %s --set KEY=VALUE' replaces it with "+
		"other settings; 'supapace project delete %s' removes the project", p.Generation, x.op.ID, x.op.Ref, x.op.Ref)
	return pgsock.Sanitize(msg, maxLastError-len(note)) + note
}
