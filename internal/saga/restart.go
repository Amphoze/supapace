package saga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/store"
)

// Restart steps. The operation targets generation g+1 with params.next; the
// project's desired generation stays g until R2, after the candidate passed
// pre-validation. If R4 fails, the restart rolls forward to g+2 with
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
	// restart was merged onto — or already carry this operation's own bump
	// (a resumed R2 whose completion was not recorded): its target
	// generation, restarting, with this operation's configuration. Another
	// restart's bump, or one applied since, is a conflict.
	base := p.Generation == rp.BaseGeneration && p.State == "active"
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

// R1: the candidate configuration checked in a task container; nothing live
// is touched.
func (x *job) prevalidate(ctx context.Context) error {
	s, err := x.candidate(ctx)
	if err != nil {
		return err
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

// R3: the cluster stopped; the disk quota of the bumped configuration, when
// the restart changes it (limits only; a roll-forward restores the previous
// one); the candidate promoted; the new generation started behind the gate
// (no health wait here).
func (x *job) restartCluster(ctx context.Context) error {
	if err := x.r.ag.StopCluster(ctx, x.op.Ref); err != nil {
		return err
	}
	rp, err := x.restartParams()
	if err != nil {
		return err
	}
	if rp.Next.DiskQuotaMB != rp.Prev.DiskQuotaMB {
		s, err := x.current(ctx)
		if err != nil {
			return err
		}
		if err := x.r.ag.SetQuota(ctx, s); err != nil {
			return err
		}
	}
	if err := x.r.ag.PromoteCandidate(ctx, x.op.Ref); err != nil {
		return err
	}
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	s.HealthWait = -1
	return x.r.ag.EnsureCluster(ctx, s)
}

// rollForward asks the step loop to roll a restart forward after R4 failed.
type rollForward struct{ err error }

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
		return &rollForward{err}
	}
	return final(code(err), fmt.Errorf("rollback to generation %d: %w", rp.RollbackGen, err))
}

// rollForward records the rollback target g+2 (and why) in the parameters.
func (x *job) rollForward(ctx context.Context, cause error) error {
	rp, err := x.restartParams()
	if err != nil {
		return err
	}
	rp.RollbackGen = x.op.Generation + 1
	rp.RollbackError = x.r.lastError(cause)
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
	return "aborted", pgsock.Sanitize(fmt.Sprintf("rolled_back: the project runs its previous configuration at generation %d; "+
		"the restart to generation %d was rolled back because its health check failed: %s",
		rp.RollbackGen, x.op.Generation, rp.RollbackError), maxLastError)
}
