package saga

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bootstrap"
)

// A rollback restores the previous quota without the usage check: a usage
// that grew past it while the new cluster ran does not refuse the rollback
// at its R1 (it is attempted; it may fail at its start).
func TestRestart_RollbackQuotaNotChecked(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	e.ag.setErr(func(c call) error {
		if c.Method == "EnsureCluster" && c.HealthWait < 0 && c.Gen == 2 {
			e.ag.used.Store(1 << 40)
			return errNoStart
		}
		return nil
	})
	r := e.runner()
	id := e.restart(r, ref, quota(16384))
	e.start(r)
	op := e.waitState(id, "aborted")
	if !strings.Contains(op.LastError, "because its stop/start step failed") {
		t.Fatalf("op %s", brief(op))
	}
	if n := len(e.ag.callsOf(ref, "DiskUsage")); n != 1 {
		t.Fatalf("%d usage reads, want only the forward pass's", n)
	}
}

// An assertion or an epoch divergence at R3 fails the restart as before: no
// rollback is started for a cluster that differs from what the platform
// expects, or for a node whose applied state belongs to another epoch.
func TestRestart_R3ExclusionsDoNotRollBack(t *testing.T) {
	for name, cause := range map[string]error{"assertion": bootstrap.ErrAssertion, "epoch": agent.ErrEpochDivergence} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			ref := e.active()
			e.ag.setErr(func(c call) error {
				if c.Method == "EnsureCluster" && c.HealthWait < 0 {
					return fmt.Errorf("start: %w", cause)
				}
				return nil
			})
			r := e.runner()
			id := e.restart(r, ref, withGUC("max_connections", "200"))
			e.start(r)
			op := e.waitState(id, "failed")
			if strings.Contains(string(op.Params), "rollback_gen") || op.Attempts != 1 {
				t.Fatalf("op %s %s", brief(op), op.Params)
			}
		})
	}
}

// A takeover applies its own quota at R3 even when it keeps
// the stored one. A forward R3 that set the new quota and then failed, whose
// rollback then failed before restoring the old quota, leaves the project's
// stored configuration (the old quota) and the filesystem's limit (the new
// one) apart; a takeover that keeps the stored quota must still set it.
func TestRestart_TakeoverSetsStoredQuota(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	var broken atomic.Bool
	broken.Store(true)
	var stops atomic.Int32
	e.ag.setErr(func(c call) error {
		switch {
		case !broken.Load():
			return nil
		case c.Method == "EnsureCluster" && c.HealthWait < 0:
			return errNoStart
		case c.Method == "StopCluster" && stops.Add(1) > 1:
			return errBoom // the rollback's R3 never gets past its stop
		}
		return nil
	})
	r := e.runner()
	e.start(r)
	id := e.restart(r, ref, quota(4096))
	op := e.waitState(id, "failed")
	p := e.project(ref)
	if p.State != "restarting" || p.Config.DiskQuotaMB != 8192 {
		t.Fatalf("project %+v, op %s", p, brief(op))
	}
	q := e.ag.callsOf(ref, "SetQuota")
	if len(q) != 1 || q[0].Quota != 4096 {
		t.Fatalf("SetQuota %+v: the filesystem limit is not the new quota", q)
	}
	broken.Store(false)
	e.ag.reset()
	id, err := e.submit(r, "restart", ref, p.Generation, withGUC("max_connections", "300"))
	must(t, err)
	e.waitState(id, "done")
	if q := e.ag.callsOf(ref, "SetQuota"); len(q) != 1 || q[0].Quota != 8192 {
		t.Fatalf("takeover SetQuota %+v: the limit stays 4096 while the project shows 8192", q)
	}
}
