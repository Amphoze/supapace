package saga

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Amphoze/supapace/internal/agent"
)

// A restart failed after its own bump (R2 recorded) and retried once another
// restart has finished at that generation must not resume: R3 would stop the
// cluster of an active project whose route is active.
func TestRestart_RetryPastR2RefusedOnceSuperseded(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	var prevalidates atomic.Int32
	var promoteBroken atomic.Bool
	promoteBroken.Store(true)
	e.ag.setErr(func(c call) error {
		switch {
		case c.Method == "Prevalidate" && prevalidates.Add(1) <= 5:
			return errBoom // restart A fails pre-validation
		case c.Method == "PromoteCandidate" && promoteBroken.Load():
			// restart B fails after its bump, with an error that does not
			// roll it back (a start failure would)
			return fmt.Errorf("gate: %w", agent.ErrContainment)
		}
		return nil
	})
	r := e.runner()
	e.start(r)
	same := withGUC("max_connections", "200")
	a := e.restart(r, ref, same)
	e.waitState(a, "failed")
	b := e.restart(r, ref, same)
	if op := e.waitState(b, "failed"); op.Step != "R2" {
		t.Fatalf("b %s", brief(op))
	}
	promoteBroken.Store(false)
	// A carries the same target configuration: it takes B's bump as its own.
	must(t, e.st.RetryOperation(context.Background(), a))
	e.waitState(a, "done")
	if p := e.project(ref); p.State != "active" || p.Generation != 2 {
		t.Fatalf("project %+v", p)
	}
	e.ag.reset()
	must(t, e.st.RetryOperation(context.Background(), b))
	op := e.settled(b)
	if n := len(e.ag.callsOf(ref, "StopCluster")); n != 0 || op.State != "failed" || !strings.HasPrefix(op.LastError, "conflict: ") {
		t.Fatalf("superseded restart resumed past its bump: %s, %d StopCluster calls on an active project, calls %v",
			brief(op), n, e.ag.methods(ref))
	}
}
