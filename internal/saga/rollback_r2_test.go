package saga

import (
	"sync/atomic"
	"testing"

	"github.com/Amphoze/supapace/internal/store"
)

// A rollback pass whose R2 fails after its bump is retried from R2.
func TestRestart_RollbackR2FailureAfterBumpResumes(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  func(e *env) (string, store.ProjectConfig)
	}{
		{"layout1", func(e *env) (string, store.ProjectConfig) { return e.active(), withGUC("max_connections", "200") }},
		{"switch", func(e *env) (string, store.ProjectConfig) { e.lanes(nil); return e.activeWith(layout1), to2(layout1) }},
		{"layout2", func(e *env) (string, store.ProjectConfig) { e.lanes(nil); return e.activeWith(layout2), to2(layout2) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			ref, cfg := c.cfg(e)
			var stops atomic.Int32
			e.ag.setErr(func(cl call) error {
				if cl.Method == "VerifyCluster" && cl.Gen == 2 {
					return errBoom
				}
				if cl.Method == "StopPostgREST" && stops.Add(1) == 2 {
					return errBoom
				}
				return nil
			})
			r := e.runner()
			id := e.restart(r, ref, cfg)
			e.start(r)
			op := e.wait(id, "ended", func(op store.Operation) bool {
				return op.State == "done" || op.State == "failed" || op.State == "aborted"
			})
			if op.State != "aborted" || e.project(ref).State != "active" {
				t.Fatalf("op %+v; project %+v", op, e.project(ref))
			}
		})
	}
}
