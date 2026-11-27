package saga

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/store"
)

// Restart steps. The operation targets generation g+1 with params.next; the
// project's desired generation stays g until R2, after the candidate passed
// pre-validation. If R3 or R4 fails, the restart rolls forward to g+2 with
// params.prev (the configuration of g, as stored), from R1.
//
// The S steps run only when the pass's target is at layout 2. S1 makes what
// a layout-2 cluster needs before R2 bumps the generation and drains the
// route, so its failure leaves the project serving. S2-S6 (the backup
// role's grant and the project's first backup) run after the project is
// served again, and only while it has no backup set, so a layout-1
// project's restart to layout 2 (the switch) is completed by any later
// restart. R6, last and at every layout, gives a project made before the
// read-only login's secret existed its verifier and secret.
var restartSteps = []step{
	{"R0", (*job).checkBase},
	{"R1", (*job).prevalidate},
	{"S1", (*job).prepareBackups},
	{"R2", (*job).drain},
	{"R3", (*job).restartCluster},
	{"R4", (*job).health},
	{"R5", (*job).resume},
	{"S2", (*job).grantBackup},
	{"S3", firstBackup((*job).stanzaCreate)},
	{"S4", firstBackup(func(x *job, ctx context.Context) error { _, err := x.awaitJob(ctx, "backup"); return err })},
	{"S5", firstBackup(func(x *job, ctx context.Context) error { _, err := x.awaitJob(ctx, "check"); return err })},
	{"S6", firstBackup((*job).replicate)},
	{"R6", (*job).readOnlyLogin},
}

// restartLayout2 are the restart steps of a pass whose target is at layout 2.
var restartLayout2 = map[string]bool{"S1": true, "S2": true, "S3": true, "S4": true, "S5": true, "S6": true}

// toLayout2 reports whether this pass's target is at layout 2.
func (x *job) toLayout2() bool {
	_, cfg, err := x.target()
	return err == nil && cfg.Layout == 2
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
	if i > indexOf(table, "R2") || rp.RollbackGen != 0 && i > indexOf(table, "R1") {
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

// sameConfig compares every field of two configurations; a nil and an empty
// GUC map are the same.
func sameConfig(a, b store.ProjectConfig) bool {
	if !maps.Equal(a.GUC, b.GUC) {
		return false
	}
	a.GUC, b.GUC = nil, nil
	x, errx := json.Marshal(a)
	y, erry := json.Marshal(b)
	return errx == nil && erry == nil && bytes.Equal(x, y)
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
// that route file; PostgREST stopped; then, for a project that archives
// (previous layout 2), push jobs until the spool is empty or DrainPushWait
// is over — its outcome recorded as drain_push (skipped without a stanza),
// never a failure of the step.
func (x *job) drain(ctx context.Context) error {
	if err := x.bumpAndDrain(ctx); err != nil {
		return err
	}
	rp, err := x.restartParams()
	if err != nil || rp.Prev.Layout != 2 {
		return err
	}
	jobs, err := x.jobRunner()
	if err != nil {
		return err
	}
	bs, err := x.r.st.GetBackupState(ctx, x.op.Ref)
	if errors.Is(err, store.ErrNotFound) || err == nil && !bs.StanzaCreated {
		return x.r.patchParams(ctx, &x.op, "drain_push", "skipped") // nothing can be pushed yet
	} else if err != nil {
		return err
	}
	out, err := jobs.PushNow(ctx, x.op.Ref, bklimit.DrainPushWait)
	if err != nil {
		x.r.log.Warn("drain push failed", "op", x.op.ID, "ref", x.op.Ref, "err", x.r.text(err))
		out = "failed"
	}
	return x.r.patchParams(ctx, &x.op, "drain_push", out)
}

func (x *job) bumpAndDrain(ctx context.Context) error {
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

// rollForward records the rollback target g+2 (and why) in the parameters,
// in one write that keeps every other member (job_floor, requeued,
// drain_push and whatever else a step or the store wrote there).
func (x *job) rollForward(ctx context.Context, rf *rollForward) error {
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(x.op.Params, &m); err != nil {
		return final("internal", errors.New("restart parameters do not parse"))
	}
	gen, msg := x.op.Generation+1, x.r.lastError(rf.err)
	for k, v := range map[string]any{"rollback_gen": gen, "rollback_error": msg, "rollback_step": rf.step} {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		m[k] = b
	}
	if rf.step == "" {
		delete(m, "rollback_step") // absent after R4, as before
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := x.r.st.SetOperationParams(ctx, x.op.ID, b); err != nil {
		return err
	}
	x.op.Params = b
	x.r.log.Warn("restart rolls forward", "op", x.op.ID, "ref", x.op.Ref, "generation", gen, "err", msg)
	return nil
}

// S1, on the candidate's spec before R2: what a layout-2 cluster needs —
// the spool directories (made by a task at the project's uid), the
// repository directory with its quota, the backup state and the stanza
// passphrase; each is left as it is when it exists. A failure leaves the
// project serving, as one of R1's.
func (x *job) prepareBackups(ctx context.Context) error {
	s, err := x.candidate(ctx)
	if err != nil {
		return err
	}
	if err := x.r.ag.EnsureSpoolDirs(ctx, s); err != nil {
		return err
	}
	if err := x.r.ag.EnsureRepoDir(ctx, s); err != nil {
		return err
	}
	if err := x.r.st.EnsureBackupState(ctx, x.op.Ref); err != nil {
		return err
	}
	if _, _, err := x.r.st.GetSecret(ctx, x.op.Ref, stanzaPassName); !errors.Is(err, store.ErrNotFound) {
		return err
	}
	dek, err := x.r.dek(ctx, x.op.Ref, false)
	if err != nil {
		return err
	}
	defer clear(dek)
	plain, err := password()
	if err != nil {
		return err
	}
	defer clear(plain)
	return x.r.putSecret(ctx, dek, x.op.Ref, stanzaPassName, plain)
}

// S2: decides once, into first_backup, whether this restart takes the
// project's first backup — no roll-forward recorded and no backup set —
// and, if so, grants the backup role its membership. The project is
// served again by then, so a failing grant leaves it serving.
func (x *job) grantBackup(ctx context.Context) error {
	if paramRaw(x.op.Params, "first_backup") == nil {
		rp, err := x.restartParams()
		if err != nil {
			return err
		}
		sets, err := x.r.st.ListSets(ctx, x.op.Ref)
		if err != nil {
			return err
		}
		if err := x.r.patchParams(ctx, &x.op, "first_backup", rp.RollbackGen == 0 && len(sets) == 0); err != nil {
			return err
		}
	}
	return firstBackup(func(x *job, ctx context.Context) error {
		s, err := x.current(ctx)
		if err != nil {
			return err
		}
		return x.r.ag.GrantBackupRole(ctx, s)
	})(x, ctx)
}

// firstBackup is a step that runs only when S2 decided on the first backup.
func firstBackup(do func(*job, context.Context) error) func(*job, context.Context) error {
	return func(x *job, ctx context.Context) error {
		var on bool
		json.Unmarshal(paramRaw(x.op.Params, "first_backup"), &on)
		if !on {
			return nil
		}
		return do(x, ctx)
	}
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

// R6: the read-only login's platform password, once. A project that has its
// secret completes the step at once. One that has none gets a new password:
// the verifier first (SetReadOnlyLogin), then the secret. Nothing is written
// to the parameters: the secret's existence is the record, and a stop
// between the two leaves no secret, so the next restart sets a fresh one.
func (x *job) readOnlyLogin(ctx context.Context) error {
	if _, _, err := x.r.st.GetSecret(ctx, x.op.Ref, dashcfg.SecretROPassword); !errors.Is(err, store.ErrNotFound) {
		return err
	}
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	plain, err := password()
	if err != nil {
		return err
	}
	defer clear(plain)
	s.Secrets.ReadOnlyPassword = string(plain)
	if err := x.r.ag.SetReadOnlyLogin(ctx, s); err != nil {
		return err
	}
	dek, err := x.r.dek(ctx, x.op.Ref, false)
	if err != nil {
		return err
	}
	defer clear(dek)
	return x.r.putSecret(ctx, dek, x.op.Ref, dashcfg.SecretROPassword, plain)
}
