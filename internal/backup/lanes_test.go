package backup

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/store"
)

// gate is a script whose jobs run until released, counting how many run.
type gate struct {
	mu      sync.Mutex
	running map[string]int // by lane
	max     map[string]int
	release chan struct{}
}

func newGate() *gate {
	return &gate{running: map[string]int{}, max: map[string]int{}, release: make(chan struct{})}
}

func (g *gate) script(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
	l := laneOf(j.Kind)
	g.mu.Lock()
	g.running[l]++
	g.max[l] = max(g.max[l], g.running[l])
	g.mu.Unlock()
	select {
	case <-g.release:
	case <-ctx.Done():
	}
	g.mu.Lock()
	g.running[l]--
	g.mu.Unlock()
	return agent.JobResult{Result: okLine(j.Kind)}, nil
}

func (g *gate) count(lane string) int { g.mu.Lock(); defer g.mu.Unlock(); return g.running[lane] }

func TestLanes_TwoPlusTwo(t *testing.T) {
	e := newEnv(t)
	g := newGate()
	e.ag.setScript("push", g.script)
	e.ag.setScript("check", g.script)
	for range 4 {
		ref := e.project("active")
		e.submit(ref, "push")
		e.submit(ref, "check")
	}
	e.r.tick = time.Hour // no scheduler pushes beside the test's
	e.noSchedule()
	e.start()
	e.eventually("two jobs in each lane", func() bool { return g.count("push") == 2 && g.count("backup") == 2 })
	// The lanes keep turning (2 ms apart) while eligible jobs wait: never a
	// third job in a lane.
	time.Sleep(50 * time.Millisecond)
	close(g.release)
	e.eventually("every job done", func() bool { return e.count("select count(*) from backup_job where state <> 'done'") == 0 })
	if g.max["push"] != 2 || g.max["backup"] != 2 {
		t.Fatalf("at most %d push and %d backup jobs at once, want 2 and 2", g.max["push"], g.max["backup"])
	}
}

func TestLanes_OnePerSubject(t *testing.T) {
	e := newEnv(t)
	g := newGate()
	e.ag.setScript("push", g.script)
	e.ag.setScript("check", g.script)
	ref := e.project("active")
	e.submit(ref, "push")
	e.submit(ref, "check")
	e.submit(ref, "check")
	e.r.tick = time.Hour
	e.noSchedule()
	e.start()
	e.ag.waitStart(t)
	// Lanes keep turning; the subject's other jobs wait for its slot.
	e.eventually("turns", func() bool { return e.count("select count(*) from backup_job where state = 'queued'") == 2 })
	time.Sleep(50 * time.Millisecond)
	if n := e.count("select count(*) from backup_job where state = 'running'"); n != 1 {
		t.Fatalf("%d running jobs of one subject", n)
	}
	close(g.release)
	e.eventually("every job done", func() bool { return e.count("select count(*) from backup_job where state <> 'done'") == 0 })
	if m := e.ag.maxRunning[ref]; m != 1 {
		t.Fatalf("%d jobs of one subject ran at once", m)
	}
}

func TestLanes_NothingPickedIsRetriedOnTheNextTurn(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	if e.turn("backup") {
		t.Fatal("an empty lane picked a job")
	}
	// A clash: the subject's slot is taken (by the other lane) at the pick.
	e.ag.setScript("push", blockUntilStopped)
	e.submit(ref, "push")
	go e.turn("push")
	e.ag.waitStart(t)
	id := e.submit(ref, "check")
	if e.turn("backup") {
		t.Fatal("a job beside its subject's running job was picked")
	}
	must(t, e.r.CancelSubject(bounded(t), ref))
	id = e.submit(ref, "check")
	if !e.turn("backup") || e.job(id).State != "done" {
		t.Fatalf("the next turn did not take the job: %+v", e.job(id))
	}
}

func TestLanes_PickNothingWhileContainmentFailed(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	id := e.submit(ref, "check")
	e.ag.setContainment(true)
	if e.turn("backup") || e.job(id).State != "queued" {
		t.Fatalf("picked while containment failed: %+v", e.job(id))
	}
	e.ag.setContainment(false)
	if !e.turn("backup") {
		t.Fatal("not picked once contained (control)")
	}
}

func TestContainment_KillsRunningReplicateAndFetch_CodeInterrupted(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, nil)
	e.declare()
	for _, k := range []string{"push", "replicate", "fetch"} {
		e.ag.setScript(k, blockUntilStopped)
	}
	a, b := e.project("active"), e.project("active")
	push := e.submit(a, "push")
	repl := e.submit(b, "replicate")
	_, fetch := e.parked(e.project("restoring"), "fetch", `{}`)
	go e.turn("push")
	go e.turn("push")
	go e.turn("backup")
	for range 3 {
		e.ag.waitStart(t)
	}
	e.ag.setContainment(true)
	e.r.lastHourly = e.clock.Now()
	must(t, e.r.tickOnce(context.Background()))
	e.eventually("both networked jobs recorded", func() bool { return e.job(repl).State == "failed" && e.job(fetch).State == "failed" })
	for _, id := range []int64{repl, fetch} {
		if got := e.job(id); got.Code != "interrupted" {
			t.Fatalf("job %d = %+v", id, got)
		}
	}
	if got := e.job(push); got.State != "running" {
		t.Fatalf("the push = %+v, want left running", got)
	}
}

// A networked job picked while containment fails is not launched.
func TestContainment_NetworkedJobNotLaunchedAfterPick(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, nil)
	e.declare()
	ref := e.project("active")
	id := e.submit(ref, "replicate")
	j, _, err := e.st.NextJob(context.Background(), "push")
	must(t, err)
	e.ag.setContainment(true)
	e.r.run(context.Background(), j)
	if got := e.job(id); got.Code != "interrupted" || len(e.ag.specs) != 0 {
		t.Fatalf("job = %+v, launches %d", got, len(e.ag.specs))
	}
}

// ───────── pick-time ─────────

func TestPick_JobOfInactiveOrUnadoptedProjectCancelledWithoutLaunch(t *testing.T) {
	e := newEnv(t)
	inactive := e.project("deleting")
	unadopted := e.project("active")
	e.pr.setAdopted(unadopted, false)
	restarting := e.project("restarting")
	for _, ref := range []string{inactive, unadopted} {
		id := e.submit(ref, "check")
		e.turn("backup")
		if got := e.job(id); got.State != "failed" || got.Code != "cancelled" {
			t.Fatalf("%s: job = %+v", ref, got)
		}
	}
	if len(e.ag.specs) != 0 {
		t.Fatalf("launched %v", e.ag.specs)
	}
	id := e.submit(restarting, "check")
	e.turn("backup")
	if got := e.job(id); got.State != "done" {
		t.Fatalf("a restarting project's job = %+v (control)", got)
	}
}

func TestPick_JobOfClosedOperationCancelledWithoutLaunch(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	op, id := e.parked(ref, "check", "")
	_, err := e.db.Exec(context.Background(), "update operation set state = 'failed' where id = $1", op)
	must(t, err)
	e.turn("backup")
	if got := e.job(id); got.Code != "cancelled" || len(e.ag.specs) != 0 {
		t.Fatalf("job = %+v, launches %d", got, len(e.ag.specs))
	}
	// Control: an operation's job runs while it waits, whatever its project's state.
	_, id = e.parked(e.project("restoring"), "check", "")
	e.turn("backup")
	if got := e.job(id); got.State != "done" {
		t.Fatalf("a waiting operation's job = %+v", got)
	}
}

func TestPick_ControlPlaneExempt(t *testing.T) {
	e := newEnv(t)
	e.controlPlane()
	id := e.submit("cp", "push")
	e.turn("push")
	if got := e.job(id); got.State != "done" || len(e.ag.specs) != 1 || e.ag.specs[0].UID != 70 {
		t.Fatalf("job = %+v", got)
	}
}

// ───────── a job's end ─────────

func (e *env) runWith(kind string, res agent.JobResult, err error) jobRow {
	e.t.Helper()
	ref := e.project("active")
	e.ag.setScript(kind, func(context.Context, agent.JobSpec) (agent.JobResult, error) { return res, err })
	id := e.submit(ref, kind)
	if !e.turn(laneOf(kind)) {
		e.t.Fatal("not picked")
	}
	return e.job(id)
}

func TestRun_DeadlineKills_CodeDeadline(t *testing.T) {
	e := newEnv(t)
	if got := e.runWith("check", agent.JobResult{ExitCode: 137, TimedOut: true}, nil); got.Code != "deadline" {
		t.Fatalf("job = %+v", got)
	}
}

func TestRun_EmptyResultIsCrashed(t *testing.T) {
	e := newEnv(t)
	if got := e.runWith("check", agent.JobResult{}, nil); got.State != "failed" || got.Code != "crashed" || got.Result != nil || !strings.Contains(got.Message, "no result line") {
		t.Fatalf("job = %+v", got)
	}
}

func TestRun_ResultNotJSONIsCrashed(t *testing.T) {
	for _, l := range []string{"not json\n", `{"ok":true,"complete":true` + "\n", `{"ok":true}` + "\n" + `{"ok":true}` + "\n"} {
		e := newEnv(t)
		got := e.runWith("push", agent.JobResult{Result: []byte(l)}, nil)
		if got.Code != "crashed" || got.Result != nil {
			t.Fatalf("%q: job = %+v", l, got)
		}
		// The runner parsed it, not the store's backstop.
		if !strings.Contains(got.Message, "result refused") {
			t.Fatalf("%q: message %q", l, got.Message)
		}
	}
}

func TestRun_ExitCodeMustMatchTheResult(t *testing.T) {
	e := newEnv(t)
	if got := e.runWith("check", agent.JobResult{ExitCode: 1, Result: okLine("check")}, nil); got.Code != "crashed" {
		t.Fatalf("ok document with exit 1: %+v", got)
	}
	if got := e.runWith("check", agent.JobResult{ExitCode: 0, Result: failLine("login", "x")}, nil); got.Code != "crashed" {
		t.Fatalf("failure with exit 0: %+v", got)
	}
	if got := e.runWith("check", agent.JobResult{ExitCode: 1, Result: failLine("login", "x")}, nil); got.Code != "login" {
		t.Fatalf("failure with exit 1 (control): %+v", got)
	}
}

func TestRun_HostStateRefusalRecorded(t *testing.T) {
	e := newEnv(t)
	hs := errors.New("agent: a job's mount source is not as the platform made it")
	if got := e.runWith("check", agent.JobResult{}, fmt.Errorf("job 3: %w", hs)); got.Code != "host_state" {
		t.Fatalf("job = %+v", got)
	}
	if got := e.runWith("check", agent.JobResult{}, errTest); got.Code != "internal" {
		t.Fatalf("another launch error: %+v (control)", got)
	}
}

func TestRun_TextSanitisedBeforeStore(t *testing.T) {
	e := newEnv(t)
	msg := "bad\x1b[31m‮\xffend " + strings.Repeat("y", 200)
	got := e.runWith("check", agent.JobResult{ExitCode: 1, Result: failLine("pgbackrest", msg)}, nil)
	// The decoder has already replaced the invalid byte; the escape and the
	// direction override are removed before the store.
	if got.Code != "pgbackrest" || strings.Contains(got.Message, "\x1b") || strings.Contains(got.Message, "\u202e") || !strings.HasPrefix(got.Message, "bad[31m") || len(got.Message) > 256 {
		t.Fatalf("message %q", got.Message)
	}
}

// ───────── fairness ─────────

// simClock is a fake clock that the fairness driver advances: each fake job
// runs until the clock reaches its start plus its deadline.
type simClock struct {
	mu      sync.Mutex
	now     time.Time
	ends    map[int64]simJob // running jobs
	starts  map[string][]time.Time
	changed chan struct{}
}

type simJob struct {
	end           time.Time
	lane, subject string
}

// running counts the running jobs of lane, and of subject in it ("" any).
func (c *simClock) running(lane, subject string) int {
	n := 0
	for _, j := range c.ends {
		if j.lane == lane && (subject == "" || j.subject == subject) {
			n++
		}
	}
	return n
}

func storeJob(ref, kind string, deadlineS int) store.NewJob {
	return store.NewJob{Subject: ref, Lane: laneOf(kind), Kind: kind, DeadlineS: deadlineS}
}

func (c *simClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *simClock) notify() { close(c.changed); c.changed = make(chan struct{}) }

func (c *simClock) run(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
	c.mu.Lock()
	end := c.now.Add(j.Deadline)
	c.ends[j.ID] = simJob{end, laneOf(j.Kind), j.Subject}
	c.starts[j.Subject+" "+laneOf(j.Kind)] = append(c.starts[j.Subject+" "+laneOf(j.Kind)], c.now)
	c.notify()
	for c.now.Before(end) && ctx.Err() == nil {
		ch := c.changed
		c.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
		}
		c.mu.Lock()
	}
	delete(c.ends, j.ID)
	c.notify()
	c.mu.Unlock()
	return agent.JobResult{Result: okLine(j.Kind)}, nil
}

// advance waits until running jobs fill the slots want asks for, none of them
// at its end, then (with move) moves the clock to the earliest end.
func (c *simClock) advance(t *testing.T, want func() bool, move bool) {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		c.mu.Lock()
		ch := c.changed
		// Jobs whose end has come must be gone first (recorded and replaced).
		ok := want()
		for _, j := range c.ends {
			ok = ok && j.end.After(c.now)
		}
		if ok && len(c.ends) > 0 && !move {
			c.mu.Unlock()
			return
		}
		if ok && len(c.ends) > 0 {
			var first time.Time
			for _, e := range c.ends {
				if first.IsZero() || e.end.Before(first) {
					first = e.end
				}
			}
			c.now = first
			c.notify()
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		select {
		case <-ch:
		case <-time.After(2 * time.Millisecond): // a lane's next turn
		case <-deadline:
			t.Fatal("the lanes did not fill their slots")
		}
	}
}

func TestFairness_ManyBusySubjects(t *testing.T) {
	for _, k := range []int{2, 6} {
		t.Run(fmt.Sprintf("k=%d", k), func(t *testing.T) { fairness(t, k, false, false) })
	}
	t.Run("busy push lane", func(t *testing.T) { fairness(t, 2, true, false) })
	// The worst order: the honest subject started a job just before its
	// submit, so every busy subject's last start precedes its own.
	t.Run("honest ran just before", func(t *testing.T) { fairness(t, 6, false, true) })
}

// fairness: k subjects keep a check job queued in the backup lane at all
// times, each running to its deadline; an honest subject's one check must
// start within ⌈k/2⌉ backup deadlines of its submit. With pushBusy, one more
// subject always has a push queued: its own backup-lane job may wait (logged,
// not bounded) while the honest subject's bound still holds.
func fairness(t *testing.T, k int, pushBusy, ranBefore bool) {
	e := newEnv(t)
	c := &simClock{now: time.Now(), ends: map[int64]simJob{}, starts: map[string][]time.Time{}, changed: make(chan struct{})}
	e.r.now = c.Now
	e.r.tick = time.Hour
	const deadlineS = 710
	submit := func(ref, kind string, d int) {
		_, err := e.st.SubmitJob(context.Background(), storeJob(ref, kind, d))
		must(t, err)
	}
	var busy []string
	for range k {
		busy = append(busy, e.project("active"))
	}
	honest := e.project("active")
	var hog string
	if pushBusy {
		hog = e.project("active")
	}
	// Each finished job of a busy subject is followed by the next one.
	var subMu sync.Mutex
	var submitted time.Time
	refill := func(ctx context.Context, j agent.JobSpec) (agent.JobResult, error) {
		res, err := c.run(ctx, j)
		if j.Subject == honest && j.Deadline == 10*time.Second { // its first job ends: the measured one is submitted
			subMu.Lock()
			submitted = c.Now()
			subMu.Unlock()
			submit(honest, "check", deadlineS)
		}
		if slices.Contains(busy, j.Subject) || j.Subject == hog && j.Kind == "push" {
			d := deadlineS
			if j.Kind == "push" {
				d = 120
			}
			submit(j.Subject, j.Kind, d)
		}
		return res, err
	}
	e.ag.setScript("check", refill)
	e.ag.setScript("push", refill)
	for _, ref := range busy {
		submit(ref, "check", deadlineS)
	}
	if pushBusy {
		submit(hog, "push", 120)
	}
	e.noSchedule()
	e.start()
	// Called with c.mu held: both backup slots busy and, with a busy push
	// lane, its push running unless that subject holds a backup slot.
	slots := func() bool {
		return c.running("backup", "") >= 2 && (!pushBusy || c.running("push", "") >= 1 || c.running("backup", hog) > 0)
	}
	t0 := c.Now()
	for c.Now().Before(t0.Add(time.Duration(2*k*deadlineS) * time.Second)) { // the busy subjects hold the lane
		c.advance(t, slots, true)
	}
	if pushBusy {
		submit(hog, "check", deadlineS)
	}
	c.advance(t, slots, false) // both backup slots taken: the honest job must wait
	first := 0
	if ranBefore {
		submit(honest, "check", 10)
		first = 1
	} else {
		submitted = c.Now()
		submit(honest, "check", deadlineS)
	}
	started := func() bool { return len(c.starts[honest+" backup"]) > first }
	bound := time.Duration((k+1)/2*deadlineS) * time.Second
	for end := c.Now().Add(4 * bound); c.Now().Before(end); {
		c.mu.Lock()
		ok := started()
		c.mu.Unlock()
		if ok {
			break
		}
		c.advance(t, func() bool { return slots() || started() }, true)
	}
	subMu.Lock()
	defer subMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !started() || submitted.IsZero() {
		t.Fatalf("the honest subject's job never started (starts %v, submitted %v)", c.starts[honest+" backup"], submitted)
	}
	wait := c.starts[honest+" backup"][first].Sub(submitted)
	if wait > bound {
		t.Fatalf("the honest subject waited %v, above ⌈k/2⌉ × the backup deadline = %v", wait, bound)
	}
	for _, ref := range busy {
		if len(c.starts[ref+" backup"]) < 2 {
			t.Fatalf("busy subject %s ran %d jobs: the lane was not loaded", ref, len(c.starts[ref+" backup"]))
		}
	}
	t.Logf("k=%d: honest wait %v (bound %v; it ran just before: %v)", k, wait, bound, ranBefore)
	if pushBusy {
		// Stated, not bounded: the subject's own backup-lane job waits for its slot.
		t.Logf("subject with a busy push lane: %d pushes, its own backup-lane job started %d times",
			len(c.starts[hog+" push"]), len(c.starts[hog+" backup"]))
	}
}

// A replication job of a store that is not declared ends done, skipped,
// without a container.
func TestRun_ReplicateSkippedUnlessDeclared(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, nil)
	ref := e.project("active")
	e.r.SetOffsite(offsite.Declaration{}, offsite.StatePartial, nil)
	id := e.submit(ref, "replicate")
	e.turn("push")
	if got := e.job(id); got.State != "done" || !strings.Contains(string(got.Result), `"skipped": "undeclared"`) || len(e.ag.specs) != 0 {
		t.Fatalf("job = %+v %s, launches %d", got, got.Result, len(e.ag.specs))
	}
	e.declare()
	id = e.submit(ref, "replicate")
	e.turn("push")
	if len(e.ag.specs) != 1 {
		t.Fatal("not launched once declared (control)")
	}
}
