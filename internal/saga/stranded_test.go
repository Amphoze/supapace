package saga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/store"
)

// errNoStart is how a cluster that exits at start fails R3 (at a quota below
// its usage it cannot create its lock file; with a damaged data directory it
// stops at once).
var errNoStart = errors.New("pg-x is not running after docker start")

// failStart makes every start of R3 (no health wait) fail while cond holds
// for its call.
func failStart(e *env, cond func(c call) bool) {
	e.ag.setErr(func(c call) error {
		if c.Method == "EnsureCluster" && c.HealthWait < 0 && cond(c) {
			return errNoStart
		}
		return nil
	})
}

func quota(mb int) store.ProjectConfig {
	c := defaultConfig
	c.DiskQuotaMB = mb
	return c
}

func (e *env) submit(r *Runner, kind, ref string, base int64, cfg store.ProjectConfig) (int64, error) {
	var params json.RawMessage
	if kind == "restart" {
		params, _ = json.Marshal(map[string]any{"base_generation": base, "config": cfg})
	}
	return r.Submit(context.Background(), kind, ref, params)
}

// A quota below the usage plus the headroom is refused at R1, under the ref
// lock, before anything is touched — also when the usage grew after the
// restart was admitted. The bound itself is accepted.
func TestRestart_QuotaBelowUsageRefusedAtR1(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	r := e.runner()
	e.ag.used.Store(1 << 30) // 1 GiB when the restart is admitted
	id := e.restart(r, ref, quota(2048))
	e.ag.used.Store(2300 << 20) // grown before the worker takes it
	stop := e.start(r)
	op := e.waitState(id, "failed")
	want := fmt.Sprintf("quota_below_usage: disk_quota_mb 2048 is below the project's usage of 2300 MiB plus the %d MiB "+
		"a clean cluster start needs; the smallest accepted value is %d", store.QuotaHeadroomMB, 2300+store.QuotaHeadroomMB)
	if op.Step != "R0" || op.Attempts != 1 || op.LastError != want {
		t.Fatalf("op %s", brief(op))
	}
	wantSeq(t, e.ag.methods(ref), []string{"DiskUsage"})
	if p := e.project(ref); p.State != "active" || p.Generation != 1 || p.Config.DiskQuotaMB != 8192 {
		t.Fatalf("project %+v", p)
	}
	stop()

	// The bound is accepted; a restart that keeps the quota reads no usage.
	e.ag.reset()
	id = e.restart(r, ref, quota(2300+store.QuotaHeadroomMB))
	e.start(r)
	e.waitState(id, "done")
	if c := e.ag.callsOf(ref, "SetQuota"); len(c) != 1 || c[0].Quota != 2300+store.QuotaHeadroomMB {
		t.Fatalf("SetQuota %+v", c)
	}
	e.ag.reset()
	e.ag.used.Store(1 << 40)
	keep := quota(2300 + store.QuotaHeadroomMB)
	keep.GUC = map[string]string{"max_connections": "200"}
	e.waitState(e.restart(r, ref, keep), "done")
	if len(e.ag.callsOf(ref, "DiskUsage")) != 0 {
		t.Fatal("usage read for a restart that keeps the quota")
	}
}

// A usage that cannot be read is a failed attempt, never a pass.
func TestRestart_UsageUnreadableIsNoPass(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	e.ag.setErr(failOn("DiskUsage"))
	r := e.runner()
	id := e.restart(r, ref, quota(16384))
	e.start(r)
	op := e.waitState(id, "failed")
	if op.Step != "R0" || op.Attempts != 5 || len(e.ag.callsOf(ref, "Prevalidate")) != 0 {
		t.Fatalf("op %s, calls %v", brief(op), e.ag.methods(ref))
	}
}

// A new cluster that does not start rolls the restart forward to the
// previous configuration, quota included: the project serves again and the
// restart ends aborted, rolled_back, saying why.
func TestRestart_StartFailureRollsBack(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	failStart(e, func(c call) bool { return c.Quota == 1024 })
	r := e.runner()
	id := e.restart(r, ref, quota(1024))
	e.start(r)
	op := e.waitState(id, "aborted")
	want := "rolled_back: the project runs its previous configuration at generation 3; the restart to generation 2 was " +
		"rolled back because its stop/start step failed: internal: " + errNoStart.Error()
	if op.LastError != want || op.Step != "R6" || op.Attempts != 1 {
		t.Fatalf("op %s", brief(op))
	}
	var quotas []int
	for _, c := range e.ag.callsOf(ref, "SetQuota") {
		quotas = append(quotas, c.Quota)
	}
	if !slices.Equal(quotas, []int{1024, 8192}) {
		t.Fatalf("quotas set %v", quotas)
	}
	if p := e.project(ref); p.State != "active" || p.Generation != 3 || p.AppliedGen != 3 || p.Config.DiskQuotaMB != 8192 {
		t.Fatalf("project %+v", p)
	}
	e.ag.locked(func() {
		if e.ag.route[ref].State != "active" {
			t.Fatalf("route %+v", e.ag.route[ref])
		}
	})
	if !strings.Contains(string(e.op(id).Params), `"rollback_step": "R3"`) {
		t.Fatalf("params %s", e.op(id).Params)
	}
	// The node's containment is not the configuration's fault: no rollback.
	e.ag.setErr(func(c call) error {
		if c.Method == "EnsureCluster" && c.HealthWait < 0 {
			return fmt.Errorf("start gate: %w", agent.ErrContainment)
		}
		return nil
	})
	op = e.waitState(e.restart(r, ref, withGUC("max_connections", "200")), "failed")
	if strings.Contains(string(op.Params), "rollback_gen") || !strings.HasPrefix(op.LastError, "containment_failed: ") {
		t.Fatalf("containment refusal %s %s", brief(op), op.Params)
	}
}

// Whichever call of the stop/start step fails (stop, quota, promote, start),
// the rollback's reason names that step, not one of its calls.
func TestRestart_R3RollbackNamesTheStep(t *testing.T) {
	for _, m := range []string{"StopCluster", "SetQuota", "PromoteCandidate", "EnsureCluster"} {
		t.Run(m, func(t *testing.T) {
			e := newEnv(t)
			ref := e.active()
			var n atomic.Int32
			e.ag.setErr(func(c call) error {
				if c.Method == m && c.HealthWait <= 0 && n.Add(1) == 1 {
					return errBoom // the forward pass only
				}
				return nil
			})
			r := e.runner()
			id := e.restart(r, ref, withGUC("max_connections", "200"))
			e.start(r)
			op := e.waitState(id, "aborted")
			want := "the restart to generation 2 was rolled back because its stop/start step failed: internal: " + errBoom.Error()
			if !strings.HasSuffix(op.LastError, want) || !strings.Contains(string(op.Params), `"rollback_step": "R3"`) {
				t.Fatalf("op %s %s", brief(op), op.Params)
			}
		})
	}
}

// strand leaves ref restarting after a restart whose new cluster and whose
// rollback both do not start (a damaged data directory); repair lets every
// start succeed again.
func strand(t *testing.T, e *env, r *Runner, ref string) (id int64, repair func()) {
	t.Helper()
	var broken atomic.Bool
	broken.Store(true)
	failStart(e, func(call) bool { return broken.Load() })
	id = e.restart(r, ref, withGUC("max_connections", "200"))
	op := e.waitState(id, "failed")
	p := e.project(ref)
	if p.State != "restarting" || p.Generation != 3 || op.Step != "R2" {
		t.Fatalf("not stranded: project %s at %d, op %s", p.State, p.Generation, brief(op))
	}
	note := fmt.Sprintf("; the project stays restarting at generation 3 with its route draining: once the cause is removed, "+
		"'supapace op retry %d' continues this restart; 'supapace project restart %s --set KEY=VALUE' replaces it with "+
		"other settings; 'supapace project delete %s' removes the project", id, ref, ref)
	if op.LastError != "internal: "+errNoStart.Error()+note {
		t.Fatalf("last_error %q", op.LastError)
	}
	e.ag.locked(func() {
		if e.ag.route[ref].State != "draining" {
			t.Fatalf("route %+v", e.ag.route[ref])
		}
	})
	return id, func() { broken.Store(false) }
}

// A project left restarting by a failed restart leaves that state by a new
// restart with its own settings, by a delete, or by `op retry` (which ends
// the rollback); nothing runs beside an open operation.
func TestRestart_StrandedProjectExits(t *testing.T) {
	t.Run("restart", func(t *testing.T) {
		e := newEnv(t)
		ref := e.active()
		r := e.runner()
		e.start(r)
		failed, repair := strand(t, e, r, ref)
		// Merged onto the generation before the failed bump: stale.
		if _, err := e.submit(r, "restart", ref, 2, defaultConfig); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("stale takeover: %v", err)
		}
		repair()
		e.ag.reset()
		next := withGUC("max_connections", "300")
		next.DiskQuotaMB = 16384
		id, err := e.submit(r, "restart", ref, 3, next)
		must(t, err)
		op := e.waitState(id, "done")
		wantSeq(t, e.steps(id), []string{"R0", "R1", "R2", "R3", "R4", "R5", "R6"})
		p := e.project(ref)
		if p.State != "active" || p.Generation != 4 || p.AppliedGen != 4 || p.Config.GUC["max_connections"] != "300" ||
			p.Config.DiskQuotaMB != 16384 || op.Generation != 4 {
			t.Fatalf("project %+v, op %s", p, brief(op))
		}
		if c := e.ag.callsOf(ref, "SetQuota"); len(c) != 1 || c[0].Quota != 16384 || c[0].Gen != 4 {
			t.Fatalf("SetQuota %+v", c)
		}
		// The failed restart is superseded: a retry of it is a conflict.
		must(t, e.st.RetryOperation(context.Background(), failed))
		if op := e.waitState(failed, "failed"); !strings.HasPrefix(op.LastError, "conflict: ") {
			t.Fatalf("superseded retry %s", brief(op))
		}
	})
	t.Run("open operation blocks", func(t *testing.T) {
		e := newEnv(t)
		ref := e.active()
		r := e.runner()
		stop := e.start(r)
		failed, _ := strand(t, e, r, ref)
		stop()
		id, err := e.submit(r, "restart", ref, 3, defaultConfig)
		must(t, err)
		for _, k := range []string{"restart", "delete"} {
			if _, err := e.submit(r, k, ref, 3, defaultConfig); !errors.Is(err, store.ErrConflict) ||
				!strings.Contains(err.Error(), fmt.Sprintf("operation %d (restart)", id)) {
				t.Fatalf("%s beside the open takeover: %v", k, err)
			}
		}
		if err := e.st.RetryOperation(context.Background(), failed); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("retry beside the open takeover: %v", err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		e := newEnv(t)
		ref := e.active()
		r := e.runner()
		e.start(r)
		strand(t, e, r, ref) // the cluster never starts again: delete needs none
		id, err := e.submit(r, "delete", ref, 3, store.ProjectConfig{})
		must(t, err)
		e.waitState(id, "done")
		if p := e.project(ref); p.State != "deleted" && p.State != "purged" { // retention is 1 ms here
			t.Fatalf("project %+v", p)
		}
	})
	t.Run("retry", func(t *testing.T) {
		e := newEnv(t)
		ref := e.active()
		r := e.runner()
		e.start(r)
		failed, repair := strand(t, e, r, ref)
		repair()
		must(t, e.st.RetryOperation(context.Background(), failed))
		op := e.waitState(failed, "aborted")
		if !strings.HasPrefix(op.LastError, "rolled_back: the project runs its previous configuration at generation 3;") {
			t.Fatalf("op %s", brief(op))
		}
		if p := e.project(ref); p.State != "active" || p.Generation != 3 || len(p.Config.GUC) != 0 {
			t.Fatalf("project %+v", p)
		}
	})
}

// The escape is for a stranded project only: a restarting project whose
// restart is still open is refused (naming that operation), an active one
// is unchanged.
func TestRestart_TakeoverOnlyWhenStranded(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	r := e.runner()
	id := e.restart(r, ref, withGUC("max_connections", "200"))
	e.failpoint("restart:R3") // stops the worker after the bump: restarting, restart running
	<-e.run(r)
	if p := e.project(ref); p.State != "restarting" {
		t.Fatalf("project %+v", p)
	}
	for _, k := range []string{"restart", "delete"} {
		if _, err := e.submit(r, k, ref, 2, defaultConfig); !errors.Is(err, store.ErrConflict) ||
			!strings.Contains(err.Error(), fmt.Sprintf("operation %d (restart) of the project is running", id)) {
			t.Fatalf("%s of a restarting project with its restart open: %v", k, err)
		}
	}
}

// Resume at the new boundaries: after R3's roll-forward was recorded, and in
// a takeover before its bump (the project restarting at the takeover's
// merge base).
func TestRestart_ResumeAtNewBoundaries(t *testing.T) {
	t.Run("after R3 rolled forward", func(t *testing.T) {
		e := newEnv(t)
		ref := e.active()
		e.ag.setErr(func(c call) error {
			if c.Method == "EnsureCluster" && c.HealthWait < 0 && c.Gen == 2 {
				os.WriteFile(e.p.Failpoint(), []byte("restart:R1"), 0o600) // the rollback's R1
				return errNoStart
			}
			return nil
		})
		r := e.runner()
		id := e.restart(r, ref, withGUC("max_connections", "200"))
		<-e.run(r)
		if op := e.op(id); op.State != "running" || op.Step != "R2" || !strings.Contains(string(op.Params), `"rollback_gen": 3`) {
			t.Fatalf("op at the failpoint %s %s", brief(op), op.Params)
		}
		e.ag.reset()
		e.start(e.runner())
		op := e.waitState(id, "aborted")
		if !strings.Contains(op.LastError, "because its stop/start step failed") {
			t.Fatalf("op %s", brief(op))
		}
		if c := e.ag.callsOf(ref, "Prevalidate"); len(c) != 1 || c[0].Gen != 3 || len(c[0].GUC) != 0 {
			t.Fatalf("resume did not continue the rollback: %+v", c)
		}
		for _, c := range e.ag.callsOf(ref, "EnsureCluster") {
			if c.Gen != 3 {
				t.Fatalf("generation %d applied after the rollback started", c.Gen)
			}
		}
	})
	for _, fp := range []string{"R1", "R2"} {
		t.Run("takeover before its bump, at "+fp, func(t *testing.T) {
			e := newEnv(t)
			ref := e.active()
			r := e.runner()
			stop := e.start(r)
			_, repair := strand(t, e, r, ref)
			stop()
			repair()
			id, err := e.submit(r, "restart", ref, 3, withGUC("max_connections", "300"))
			must(t, err)
			e.failpoint("restart:" + fp)
			<-e.run(e.runner())
			if p := e.project(ref); p.State != "restarting" || p.Generation != 3 {
				t.Fatalf("project at the failpoint %+v", p)
			}
			e.start(e.runner())
			e.waitState(id, "done")
			if p := e.project(ref); p.State != "active" || p.Generation != 4 || p.Config.GUC["max_connections"] != "300" {
				t.Fatalf("project %+v", p)
			}
		})
	}
}

// The note is the project's own restart's only: a failed restart retried
// after another restart has stranded the project at a later generation ends
// in a conflict that names no way on as if it were still its own.
func TestRestart_SupersededFailureCarriesNoNote(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	r := e.runner()
	e.start(r)
	first, _ := strand(t, e, r, ref) // generation 3; starts still fail
	second, err := e.submit(r, "restart", ref, 3, withGUC("max_connections", "300"))
	must(t, err)
	if op := e.waitState(second, "failed"); !strings.Contains(op.LastError, "'supapace op retry "+fmt.Sprint(second)+"'") {
		t.Fatalf("second %s", brief(op))
	}
	must(t, e.st.RetryOperation(context.Background(), first))
	op := e.waitState(first, "failed")
	if !strings.HasPrefix(op.LastError, "conflict: ") || strings.Contains(op.LastError, "supapace") {
		t.Fatalf("superseded %s", brief(op))
	}
}
