package backup

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Amphoze/supapace/internal/store"
)

// countingStore counts the tick's store calls and fails one subject's reads.
type countingStore struct {
	tickStore
	mu   sync.Mutex
	n    int
	fail string // the subject whose reads fail
	only string // "": all of its reads; else only the method of that name
}

func (c *countingStore) count(subject, method string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	if subject != "" && subject == c.fail && (c.only == "" || c.only == method) {
		return errTest
	}
	return nil
}

func (c *countingStore) calls() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

func (c *countingStore) ListProjects(ctx context.Context) ([]store.Project, error) {
	c.count("", "ListProjects")
	return c.tickStore.ListProjects(ctx)
}

func (c *countingStore) GetBackupState(ctx context.Context, s string) (store.BackupState, error) {
	if err := c.count(s, "GetBackupState"); err != nil {
		return store.BackupState{}, err
	}
	return c.tickStore.GetBackupState(ctx, s)
}

func (c *countingStore) ListOperations(ctx context.Context, ref string) ([]store.Operation, error) {
	if err := c.count(ref, "ListOperations"); err != nil {
		return nil, err
	}
	return c.tickStore.ListOperations(ctx, ref)
}

func (c *countingStore) LastJob(ctx context.Context, s, kind string) (store.Job, bool, error) {
	if err := c.count(s, "LastJob"); err != nil {
		return store.Job{}, false, err
	}
	return c.tickStore.LastJob(ctx, s, kind)
}

func (c *countingStore) SubmitJob(ctx context.Context, j store.NewJob) (int64, error) {
	if err := c.count(j.Subject, "SubmitJob"); err != nil {
		return 0, err
	}
	return c.tickStore.SubmitJob(ctx, j)
}

// A tick reads the store a fixed number of times per subject, whatever the
// job table retains: the replication after a push or backup is decided when
// that job is recorded, not by walking the table at each tick.
func TestScheduler_TickCostIndependentOfRows(t *testing.T) {
	e := newEnv(t)
	e.declare()
	const n = 5
	var refs []string
	for range n {
		refs = append(refs, e.project("active"))
	}
	cs := &countingStore{tickStore: e.r.ts}
	e.r.ts = cs
	e.tick() // queues each subject's push
	for range n {
		e.turn("push") // pushes done, replications queued
	}
	for range n {
		e.turn("push") // replications done
	}
	before := cs.calls()
	e.tick()
	base := cs.calls() - before
	// 1 project list + the control plane's state + per subject its state
	// and its last push.
	if want := 2 + 2*n; base != want {
		t.Fatalf("%d store calls for %d subjects, want %d", base, n, want)
	}
	for _, ref := range refs {
		_, err := e.db.Exec(context.Background(), `insert into backup_job (subject, lane, kind, state, deadline_s, finished_at)
			select $1, 'push', k, 'done', 120, now() from generate_series(1, 4000), unnest(array['push', 'replicate', 'backup']) k`, ref)
		must(t, err)
	}
	before = cs.calls()
	e.tick()
	if got := cs.calls() - before; got != base {
		t.Fatalf("%d store calls with 60,000 more rows, %d without", got, base)
	}
}

// One subject's store error skips that subject; the others are served.
func TestScheduler_OneSubjectsErrorSkipsOnlyIt(t *testing.T) {
	for _, only := range []string{"GetBackupState", "LastJob"} {
		t.Run(only, func(t *testing.T) {
			e := newEnv(t)
			bad, good := e.project("active"), e.project("active") // bad comes first
			cs := &countingStore{tickStore: e.r.ts, fail: bad, only: only}
			e.r.ts = cs
			e.r.lastHourly = e.clock.Now()
			if err := e.r.tickOnce(context.Background()); !errors.Is(err, errTest) {
				t.Fatalf("tick error %v, want the subject's", err)
			}
			if e.jobs(good, "push") != 1 || e.jobs(bad, "push") != 0 {
				t.Fatalf("pushes: good %d, bad %d", e.jobs(good, "push"), e.jobs(bad, "push"))
			}
		})
	}
}
