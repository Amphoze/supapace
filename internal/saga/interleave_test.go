package saga

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/store"
)

// createOp returns the id of ref's create operation.
func (e *env) createOp(ref string) int64 {
	e.t.Helper()
	ops, err := e.st.ListOperations(context.Background(), ref)
	must(e.t, err)
	for _, o := range ops {
		if o.Kind == "create" {
			return o.ID
		}
	}
	e.t.Fatal("no create operation")
	return 0
}

// brief is an operation without its parameters, for failure messages.
func brief(op store.Operation) string {
	return fmt.Sprintf("{%s %s step %s attempts %d last_error %q}", op.Kind, op.State, op.Step, op.Attempts, op.LastError)
}

// settled waits until operation id is in a final state.
func (e *env) settled(id int64) store.Operation {
	e.t.Helper()
	return e.wait(id, "final", func(op store.Operation) bool {
		return op.State == "done" || op.State == "failed" || op.State == "aborted"
	})
}

// A crash at every compensation entry resumes the list and ends aborted,
// with the keys destroyed and the slice freed.
func TestAbort_CrashAtEveryEntry(t *testing.T) {
	for _, c := range []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7"} {
		t.Run(c, func(t *testing.T) {
			e := newEnv(t)
			ref, id := e.create()
			e.failpoint("create:11")
			<-e.run(e.runner())
			r := e.runner()
			_, err := r.Abort(context.Background(), ref)
			must(t, err)
			e.failpoint("create:" + c)
			<-e.run(r)
			if op := e.op(id); op.State != "aborting" {
				t.Fatalf("after the failpoint: %+v", op)
			}
			e.start(e.runner())
			e.waitState(id, "aborted")
			if p := e.project(ref); p.State != "aborted" || p.SubnetIndex != nil || p.UID == nil {
				t.Fatalf("project %+v", p)
			}
			if _, _, err := e.st.GetDEK(context.Background(), ref); !errors.Is(err, store.ErrDestroyed) {
				t.Fatalf("DEK: %v", err)
			}
			e.ag.locked(func() {
				if e.ag.dir[ref] || e.ag.network[ref] || e.ag.render[ref] || e.ag.cluster[ref] != 0 || e.ag.pgrest[ref] != 0 {
					t.Fatal("objects left after the abort")
				}
			})
		})
	}
}

// A crash at every restart boundary, in the first pass and in the
// rollback, resumes to the right generation and never re-applies an older one.
func TestRestart_CrashAtEveryBoundary(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		for _, s := range []string{"R0", "R1", "R2", "R3", "R4", "R5", "R6"} {
			if rollback && s == "R0" {
				continue // the rollback starts at R1
			}
			name := s
			if rollback {
				name = "rollback-" + s
			}
			t.Run(name, func(t *testing.T) {
				e := newEnv(t)
				ref := e.active()
				r := e.runner()
				if rollback {
					e.ag.setErr(func(c call) error {
						if c.Method == "VerifyCluster" && c.Gen == 2 {
							e.failpoint("restart:" + s)
							return errBoom
						}
						return nil
					})
				} else {
					e.failpoint("restart:" + s)
				}
				id := e.restart(r, ref, withGUC("max_connections", "200"))
				<-e.run(r)
				e.ag.reset()
				e.ag.setErr(nil)
				e.start(e.runner())
				end := "done"
				if rollback {
					end = "aborted" // rolled back
				}
				e.waitState(id, end)
				want, guc := int64(2), "200"
				if rollback {
					want, guc = 3, ""
				}
				p := e.project(ref)
				if p.State != "active" || p.Generation != want || p.AppliedGen != want || p.Config.GUC["max_connections"] != guc {
					t.Fatalf("project %+v", p)
				}
				for _, c := range e.ag.callsOf(ref, "EnsureCluster") {
					if c.Gen != want {
						t.Fatalf("generation %d applied on resume", c.Gen)
					}
				}
				e.ag.locked(func() {
					if e.ag.route[ref].State != "active" {
						t.Fatalf("route %+v", e.ag.route[ref])
					}
				})
			})
		}
	}
}

// A crash at every delete and purge boundary ends purged with one purge
// operation.
func TestDeletePurge_CrashAtEveryBoundary(t *testing.T) {
	for _, s := range []string{"delete:D1", "delete:D2", "delete:D3", "delete:D4", "delete:D5",
		"purge:P1", "purge:P2", "purge:P3", "purge:P4", "purge:P5"} {
		t.Run(s, func(t *testing.T) {
			e := newEnv(t)
			ref := e.active()
			r := e.runner()
			e.failpoint(s)
			_, err := r.Submit(context.Background(), "delete", ref, nil)
			must(t, err)
			<-e.run(r)
			e.start(e.runner())
			deadline := time.Now().Add(30 * time.Second)
			for e.project(ref).State != "purged" {
				if time.Now().After(deadline) {
					t.Fatalf("never purged: %+v", e.project(ref))
				}
				time.Sleep(5 * time.Millisecond)
			}
			ops, err := e.st.ListOperations(context.Background(), ref)
			must(t, err)
			n := 0
			for _, o := range ops {
				if o.Kind == "purge" {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("%d purge operations", n)
			}
			if _, _, err := e.st.GetDEK(context.Background(), ref); !errors.Is(err, store.ErrDestroyed) {
				t.Fatalf("DEK: %v", err)
			}
		})
	}
}

// Two runners on one store by mistake: the ref lock still keeps every
// effect single.
func TestRun_TwoRunnersOneStore(t *testing.T) {
	e := newEnv(t)
	var ids []int64
	for range 4 {
		_, id := e.create()
		ids = append(ids, id)
	}
	e.ag.setHook(func(ctx context.Context, c call) { time.Sleep(2 * time.Millisecond) })
	e.start(e.runner())
	e.start(e.runner())
	for _, id := range ids {
		if op := e.waitState(id, "done"); op.Attempts != 1 {
			t.Fatalf("op %+v", op)
		}
	}
	e.ag.locked(func() {
		for k, n := range e.ag.effects {
			if n != 1 {
				t.Errorf("effect %q happened %d times", k, n)
			}
		}
	})
}

// A second abort while the compensation runs changes nothing.
func TestAbort_SecondAbortDuringCompensation(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:6")
	<-e.run(e.runner())
	r := e.runner()
	var once sync.Once
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "StopCluster" {
			once.Do(func() {
				got, err := r.Abort(ctx, ref)
				if err != nil || got != id {
					t.Errorf("second abort: %d, %v", got, err)
				}
			})
		}
	})
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	e.start(r)
	if op := e.waitState(id, "aborted"); op.Attempts != 0 {
		t.Fatalf("op %+v", op)
	}
	wantSeq(t, e.ag.methods(ref)[len(e.ag.methods(ref))-len(compensationCalls):], compensationCalls)
}

// ───────── interleavings that expose defects (fail until fixed) ─────────

// A parked abort retried with `op retry` must not run the create forward:
// its compensation already removed the route and destroyed the keys, so
// step 12 would mark an empty project active.
func TestAbort_ParkedRetryNeverActivates(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:12") // steps up to 11 done: the route is active
	<-e.run(e.runner())
	e.ag.setErr(failOn("PurgeDir"))
	r := e.runner()
	_, err := r.Abort(context.Background(), ref)
	must(t, err)
	e.start(r)
	e.waitState(id, "failed") // parked after 8 runs
	e.ag.setErr(nil)
	if err := e.st.RetryOperation(context.Background(), id); err != nil {
		return // refusing the retry is a fix
	}
	op := e.settled(id)
	if p := e.project(ref); p.State == "active" || op.State == "done" {
		t.Fatalf("parked abort run forward: project %s, op %s (keys destroyed, no route)", p.State, brief(op))
	}
}

// A healthy active project whose create was finished failed after step 12's
// state change (its bookkeeping failed) must not be destroyed by `project
// abort`.
func TestAbort_RefusedOnHealthyActiveProject(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	id := e.createOp(ref)
	// What five failures of step 12's writes after the state change leave.
	sql(t, "update operation set state = 'failed', step = '11', last_error = 'internal: x' where id = $1", id)
	r := e.runner()
	if _, err := r.Abort(context.Background(), ref); errors.Is(err, store.ErrConflict) {
		return
	}
	e.start(r)
	e.settled(id)
	t.Fatalf("abort accepted on an active project: project %s, keys %v", e.project(ref).State,
		func() error { _, _, err := e.st.GetDEK(context.Background(), ref); return err }())
}

// A failed restart retried after another restart from the same base was
// applied must be refused before it touches anything (its quota included).
func TestRestart_RetriedStaleRestartRefused(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	e.ag.setErr(func(c call) error {
		if c.Method == "Prevalidate" && c.GUC["max_connections"] == "300" {
			return errBoom
		}
		return nil
	})
	r := e.runner()
	e.start(r)
	stale := withGUC("max_connections", "300")
	stale.DiskQuotaMB = 4096
	a := e.restart(r, ref, stale)
	e.waitState(a, "failed")
	b := e.restart(r, ref, withGUC("max_connections", "200"))
	e.waitState(b, "done")
	e.ag.reset()
	e.ag.setErr(nil)
	must(t, e.st.RetryOperation(context.Background(), a))
	op := e.settled(a)
	if q := e.ag.callsOf(ref, "SetQuota"); len(q) != 0 {
		t.Errorf("stale restart applied its quota: %+v", q)
	}
	if op.State != "failed" || !strings.HasPrefix(op.LastError, "conflict: ") || op.Attempts != 1 {
		t.Errorf("stale restart not refused at once: %s", brief(op))
	}
}

// A failed restart retried while another restart from the same base left
// the project restarting at the same target must not adopt that bump as its
// own and finish done.
func TestRestart_RetriedStaleRestartOverFailedRestart(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	e.ag.setErr(func(c call) error {
		switch {
		case c.Method == "Prevalidate" && c.GUC["max_connections"] == "300":
			return errBoom
		case c.Method == "PromoteCandidate":
			return errBoom
		}
		return nil
	})
	r := e.runner()
	e.start(r)
	a := e.restart(r, ref, withGUC("max_connections", "300"))
	e.waitState(a, "failed")
	b := e.restart(r, ref, withGUC("max_connections", "200"))
	if op := e.waitState(b, "failed"); op.Step != "R2" {
		t.Fatalf("b %+v", op)
	}
	e.ag.setErr(nil)
	must(t, e.st.RetryOperation(context.Background(), a))
	op := e.settled(a)
	p := e.project(ref)
	if op.State == "done" {
		t.Fatalf("stale restart finished done on another restart's bump: project gen %d guc %v, op %+v",
			p.Generation, p.Config.GUC, brief(op))
	}
}

// A restart whose candidate fails pre-validation leaves the live quota as
// the stored configuration says.
func TestRestart_PrevalidateFailureLeavesQuota(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	e.ag.setErr(failOn("Prevalidate"))
	r := e.runner()
	next := defaultConfig
	next.DiskQuotaMB = 4096
	id := e.restart(r, ref, next)
	e.start(r)
	e.waitState(id, "failed")
	if q := e.ag.callsOf(ref, "SetQuota"); len(q) != 0 {
		t.Fatalf("quota set to %d before pre-validation; stored quota %d", q[0].Quota, e.project(ref).Config.DiskQuotaMB)
	}
}

// The rollback to g+2 restores the quota of g, as it restores the rest of
// its configuration.
func TestRestart_RollbackRestoresQuota(t *testing.T) {
	e := newEnv(t)
	ref := e.active()
	failVerifyAt(e, 2)
	r := e.runner()
	next := defaultConfig
	next.DiskQuotaMB = 4096
	id := e.restart(r, ref, next)
	e.start(r)
	e.waitState(id, "aborted") // rolled back
	var quotas []int
	for _, c := range e.ag.callsOf(ref, "SetQuota") {
		quotas = append(quotas, c.Quota)
	}
	if p := e.project(ref); !slices.Equal(quotas, []int{4096, 8192}) || p.Config.DiskQuotaMB != 8192 {
		t.Fatalf("quota calls %v; project quota %d", quotas, p.Config.DiskQuotaMB)
	}
}

// An operation the daemon keeps dying in (every attempt ends in a crash, so
// no failure is ever recorded) is failed once its attempts are used up.
func TestRun_CrashLoopBounded(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	e.failpoint("create:4")
	<-e.run(e.runner())
	sql(t, "update operation set attempts = 5 where id = $1", id) // five crashed attempts
	e.ag.reset()
	e.start(e.runner())
	op := e.settled(id)
	if op.State != "failed" || len(e.ag.methods(ref)) != 0 {
		t.Fatalf("sixth attempt ran: %s, calls %v", brief(op), e.ag.methods(ref))
	}
}

// Invariant (a) when the lock's connection dies under a step: the worker
// must not go on recording steps while another session holds the ref lock.
func TestRun_LockLostMidStep(t *testing.T) {
	e := newEnv(t)
	ref, id := e.create()
	inStep := make(chan struct{})
	release := make(chan struct{})
	var freed sync.Once
	free := func() { freed.Do(func() { close(release) }) }
	defer free()
	var first sync.Once
	e.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "EnsureCluster" {
			first.Do(func() { close(inStep); <-release })
		}
	})
	e.start(e.runner())
	<-inStep
	sql(t, "select pg_terminate_backend(pid) from pg_locks where locktype = 'advisory' and pid <> pg_backend_pid()")
	ctx := context.Background()
	var u func()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var ok bool
		var err error
		u, ok, err = e.st.TryLockRef(ctx, ref)
		must(t, err)
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lock still held after its connection was terminated")
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer u()
	free()
	time.Sleep(300 * time.Millisecond)
	if op := e.op(id); op.Step != "3" || op.State == "done" {
		t.Fatalf("worker went on without its ref lock while another session holds it: %s", brief(op))
	}
}
