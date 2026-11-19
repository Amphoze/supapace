package backup

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/jobio"
)

// A push result is written inside a container that handles the project's
// data. Whatever it says, the stored document stays small, holds no control
// character, and no negative figure reaches the backup state: the result is
// refused (crashed) or its members are bounded.
func TestRecord_HostilePushResultsAreRefusedOrBounded(t *testing.T) {
	cases := map[string]func(*jobio.PushResult){
		"oversized first": func(p *jobio.PushResult) { p.First = strings.Repeat("0", 512<<10) },
		"oversized last":  func(p *jobio.PushResult) { p.Last = strings.Repeat("A", 512<<10) },
		"many histories":  func(p *jobio.PushResult) { p.Histories = make([]string, 40000) },
		"long quarantined name": func(p *jobio.PushResult) {
			p.Quarantined = []jobio.Quarantined{{Name: strings.Repeat("n", 64<<10), Reason: "shape"}}
		},
		"escape in a name": func(p *jobio.PushResult) {
			p.Quarantined = []jobio.Quarantined{{Name: "x\x1b]0;title\x07", Reason: "shape"}}
		},
		"negative spool entries": func(p *jobio.PushResult) { p.SpoolEntries = -1 },
		"negative spool bytes":   func(p *jobio.PushResult) { p.SpoolBytes = -4096 },
		"negative pushed":        func(p *jobio.PushResult) { p.Pushed = -1 },
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			ref := e.project("active")
			p := okPush()
			bad(&p)
			got := e.push(ref, agent.JobResult{Result: line(p)})
			if got.Code == "crashed" {
				if bs := e.state(ref); bs.SpoolEntries != nil {
					t.Fatalf("refused, yet recorded: %+v", bs)
				}
				return
			}
			if got.State != "done" {
				t.Fatalf("job %+v", got)
			}
			if len(got.Result) > 16<<10 || strings.Contains(string(got.Result), `\u00`) {
				t.Fatalf("stored a result of %d bytes: %.200s", len(got.Result), got.Result)
			}
			if bs := e.state(ref); bs.SpoolEntries == nil || *bs.SpoolEntries < 0 || bs.SpoolBytes == nil || *bs.SpoolBytes < 0 {
				t.Fatalf("spool figures stored: entries %d, bytes %d", deref(bs.SpoolEntries), deref(bs.SpoolBytes))
			}
		})
	}
	t.Run("figure beyond the column", func(t *testing.T) { // control: refused by the store, nothing written
		e := newEnv(t)
		ref := e.project("active")
		p := okPush()
		p.SpoolEntries = 1 << 40
		if got := e.push(ref, agent.JobResult{Result: line(p)}); got.Code != "crashed" || e.state(ref).SpoolEntries != nil {
			t.Fatalf("job %+v", got)
		}
	})
}

// The newest segment recorded is that of the highest ADMITTED timeline; a
// result naming a timeline the project has not admitted does not set it.
func TestRecord_NewestOfATimelineNotAdmittedIsNeverRecorded(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active") // admits timeline 1 only
	p := okPush()
	p.Newest = map[string]string{"00000001": "000000010000000000000003", "00000007": "000000070000000000000009"}
	got := e.push(ref, agent.JobResult{Result: line(p)})
	if seg := e.state(ref).NewestSegment; got.Code != "crashed" && seg != "000000010000000000000003" {
		t.Fatalf("job %+v, newest segment %q", got, seg)
	}
}

// A job whose record fails once (the store briefly unreachable) is recorded
// later: its running row would hold the subject's slot until the next start.
func TestRun_AFailedRecordIsRetriedAndFreesTheSlot(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, err := e.db.Exec(ctx, `create sequence review_fail;
		create function review_fail() returns trigger language plpgsql as $$
		begin if nextval('review_fail') = 1 then raise exception 'injected store failure'; end if; return new; end $$;
		create trigger review_fail before update on backup_job for each row
			when (old.state = 'running' and new.state in ('done', 'failed')) execute function review_fail()`)
	must(t, err)
	ref := e.project("active")
	id := e.submit(ref, "check")
	e.r.tick = 1 << 62
	e.noSchedule()
	e.start()
	e.eventually("the job recorded after its first record failed", func() bool { return e.job(id).State == "done" })
}

// A pick-time check that cannot read the store ends the job with a code the
// step's interrupted limit counts — never with cancelled, which nothing counts.
func TestPick_StoreErrorEndsTheJobInterrupted(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	id := e.submit(ref, "check")
	_, err := e.db.Exec(context.Background(), `update project set config = jsonb_set(config, '{disk_quota_mb}', '"x"') where ref = $1`, ref)
	must(t, err)
	e.turn("backup")
	if got := e.job(id); got.State != "failed" || got.Code != "interrupted" || len(e.ag.specs) != 0 {
		t.Fatalf("job %+v, launches %d", got, len(e.ag.specs))
	}
}

// When the daemon stops, a running job is left running in the store; the
// next Start ends it interrupted once its container is gone.
func TestRun_DaemonStopLeavesTheJobForTheNextStart(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	e.ag.setScript("check", blockUntilStopped)
	id := e.submit(ref, "check")
	e.r.tick = 1 << 62
	e.noSchedule()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.r.Run(ctx) }()
	e.ag.waitStart(t)
	cancel()
	<-done
	if got := e.job(id); got.State != "running" {
		t.Fatalf("job %+v after the daemon stopped, want still running", got)
	}
	must(t, e.r.Start(context.Background()))
	if got := e.job(id); got.Code != "interrupted" {
		t.Fatalf("job %+v after Start", got)
	}
}

// The undeclared skip is the runner's own document, stored as JSON.
func TestRun_SkippedReplicationIsADocument(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, nil)
	ref := e.project("active")
	id := e.submit(ref, "replicate")
	e.turn("push")
	var v map[string]any
	if err := json.Unmarshal(e.job(id).Result, &v); err != nil || v["skipped"] != "undeclared" || v["ok"] != true {
		t.Fatalf("stored %s (%v)", e.job(id).Result, err)
	}
}

func deref[T int | int64](p *T) T {
	if p == nil {
		return -1
	}
	return *p
}

// A job's own failure code never takes one the runner or the store assigns:
// cancelled and interrupted count no attempt, so a job that could claim them
// would make its operation retry for ever. Such a document is crashed.
func TestRecord_AJobCannotClaimARunnersCode(t *testing.T) {
	e := newEnv(t)
	for _, code := range []string{"cancelled", "interrupted", "deadline", "crashed", "host_state", "internal", "recovered"} {
		if got := e.runWith("check", agent.JobResult{ExitCode: 1, Result: failLine(code, "x")}, nil); got.Code != "crashed" {
			t.Fatalf("a job claiming %q was recorded %+v", code, got)
		}
	}
	if got := e.runWith("check", agent.JobResult{ExitCode: 1, Result: failLine("login", "x")}, nil); got.Code != "login" {
		t.Fatalf("the job's own code (control): %+v", got)
	}
}

// Only the backup lane delays its picks by the random 0–2 s.
func TestLanes_OnlyBackupLanePicksAreDelayed(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	n := 0
	e.r.pickDelay = func() time.Duration { mu.Lock(); n++; mu.Unlock(); return 0 }
	delays := func() int { mu.Lock(); defer mu.Unlock(); return n }
	for _, lane := range []string{"push", "backup"} {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); e.r.lane(ctx, lane) }()
		if lane == "push" {
			time.Sleep(50 * time.Millisecond)
		} else {
			e.eventually("a delayed backup-lane pick", func() bool { return delays() > 0 })
		}
		cancel()
		<-done
		if lane == "push" && delays() != 0 {
			t.Fatalf("the push lane delayed %d picks", delays())
		}
	}
}

// PushNow queues no push beside one that is running.
func TestPushNow_NoSecondPushBesideARunningOne(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	e.ag.setScript("push", blockUntilStopped)
	e.submit(ref, "push")
	go e.turn("push")
	e.ag.waitStart(t)
	if out, err := e.r.PushNow(context.Background(), ref, 0); err != nil || out != "timeout" {
		t.Fatalf("PushNow = %q, %v", out, err)
	}
	if n := e.jobs(ref, "push"); n != 1 {
		t.Fatalf("%d push jobs, want the running one only", n)
	}
}

// The hourly prune keeps finished jobs younger than 48 h.
func TestScheduler_PruneKeepsFinishedJobsYoungerThan48h(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	_, err := e.db.Exec(context.Background(), `insert into backup_job (subject, lane, kind, state, deadline_s, finished_at)
		select $1, 'push', 'push', 'done', 120, now() - interval '47 hours' from generate_series(1, 3)`, ref)
	must(t, err)
	e.r.lastHourly = time.Time{}
	must(t, e.r.tickOnce(context.Background()))
	if n := e.count("select count(*) from backup_job where kind = 'push' and state = 'done'"); n != 3 {
		t.Fatalf("%d of 3 finished jobs younger than 48 h left", n)
	}
}

// The control plane is served once its stanza exists.
func TestScheduler_ControlPlaneIsServed(t *testing.T) {
	e := newEnv(t)
	e.tick()
	if n := e.jobs("cp", "push"); n != 0 {
		t.Fatalf("%d control-plane pushes before its backup state exists", n)
	}
	e.controlPlane()
	e.tick()
	if n := e.jobs("cp", "push"); n != 1 {
		t.Fatalf("%d control-plane pushes, want 1", n)
	}
}
