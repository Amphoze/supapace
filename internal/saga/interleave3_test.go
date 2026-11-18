package saga

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
)

// A restart that failed inside its roll-forward, before the rollback's own
// bump, must not resume the rollback once another restart has since finished
// on the project: it would bump an active project to g+2 and undo that
// restart.
func TestRestart_RollbackResumeRefusedOnceSuperseded(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	var failFirst, failVerify, failRollback atomic.Bool
	e.ag.setErr(func(c call) error {
		switch {
		case c.Method == "Prevalidate" && c.Gen == 2 && failFirst.Load():
			return errBoom
		case c.Method == "VerifyCluster" && c.Gen == 2 && failVerify.Load():
			return errBoom
		case c.Method == "Prevalidate" && c.Gen == 3 && failRollback.Load():
			return errBoom
		}
		return nil
	})
	r := e.runner()
	e.start(r)
	same := withGUC("max_connections", "200")
	failFirst.Store(true)
	c := e.restart(r, ref, same) // fails pre-validation, nothing bumped
	e.waitState(c, "failed")
	failFirst.Store(false)
	failVerify.Store(true)
	failRollback.Store(true)
	a := e.restart(r, ref, same) // bumps to 2, fails health, its rollback fails before bumping to 3
	e.waitState(a, "failed")
	if p := e.project(ref); p.State != "restarting" || p.Generation != 2 {
		t.Fatalf("after a: %+v", p)
	}
	failVerify.Store(false)
	failRollback.Store(false)
	must(t, e.st.RetryOperation(context.Background(), c)) // takes a's bump as its own and finishes
	e.waitState(c, "done")
	if p := e.project(ref); p.State != "active" || p.Generation != 2 {
		t.Fatalf("after c: %+v", p)
	}
	e.ag.reset()
	must(t, e.st.RetryOperation(context.Background(), a))
	op := e.settled(a)
	p := e.project(ref)
	if op.State != "failed" || !strings.HasPrefix(op.LastError, "conflict: ") || len(e.ag.methods(ref)) != 0 || p.Generation != 2 {
		t.Fatalf("stale rollback resumed: %s; project %s at generation %d; calls %v", brief(op), p.State, p.Generation, e.ag.methods(ref))
	}
}
