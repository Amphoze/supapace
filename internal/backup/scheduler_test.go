package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/store"
)

// tick runs one scheduler tick without the hourly work.
func (e *env) tick() {
	e.t.Helper()
	e.r.lastHourly = e.clock.Now()
	must(e.t, e.r.tickOnce(context.Background()))
}

func (e *env) jobs(subject, kind string) int {
	return e.count("select count(*) from backup_job where subject = $1 and kind = $2", subject, kind)
}

func TestScheduler_PushEvery60s(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	e.tick()
	e.tick()
	if n := e.jobs(ref, "push"); n != 1 {
		t.Fatalf("%d pushes, want one: none while one is queued", n)
	}
	e.turn("push")
	last, _, err := e.st.LastJob(context.Background(), ref, "push")
	must(t, err)
	e.clock.Set(last.CreatedAt.Add(59 * time.Second))
	e.tick()
	if n := e.jobs(ref, "push"); n != 1 {
		t.Fatalf("%d pushes 59 s after the last", n)
	}
	e.clock.Set(last.CreatedAt.Add(60 * time.Second))
	e.tick()
	if n := e.jobs(ref, "push"); n != 2 {
		t.Fatalf("%d pushes 60 s after the last, want 2", n)
	}
}

func TestScheduler_SkipsSlotOwnedAndInactive(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	restoring := e.project("restoring")
	must(t, e.st.SetSlot(ctx, restoring, 1))
	var skipped []string
	skipped = append(skipped, restoring)
	for _, st := range []string{"provisioning", "deleting", "restoring"} {
		skipped = append(skipped, e.project(st))
	}
	layout1 := e.project("active")
	_, err := e.db.Exec(ctx, `update project set config = jsonb_set(config, '{layout}', '1') where ref = $1`, layout1)
	must(t, err)
	noStanza := e.project("active")
	_, err = e.db.Exec(ctx, "update backup_state set stanza_created = false where subject = $1", noStanza)
	must(t, err)
	served := e.project("active")
	e.declare()
	e.tick()
	for _, ref := range append(skipped, layout1, noStanza) {
		if n := e.count("select count(*) from backup_job where subject = $1", ref); n != 0 {
			t.Fatalf("%s got %d jobs", ref, n)
		}
	}
	if e.jobs(served, "push") != 1 {
		t.Fatal("the served project got no push (control)")
	}
}

func TestScheduler_SkipsUnadoptedProject(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	e.pr.setAdopted(ref, false)
	for range 3 {
		e.tick()
		e.clock.Add(time.Minute)
	}
	if n := e.count("select count(*) from backup_job where subject = $1", ref); n != 0 {
		t.Fatalf("%d jobs for a project listed active but not adopted", n)
	}
	e.pr.setAdopted(ref, true)
	e.tick()
	if e.jobs(ref, "push") != 1 {
		t.Fatal("no push once adopted (control)")
	}
}

func (e *env) op(ref, kind, state string) int64 {
	var id int64
	must(e.t, e.db.QueryRow(context.Background(), `insert into operation (ref, kind, state, epoch, generation)
		values ($1, $2, $3, 1, 1) returning id`, ref, kind, state).Scan(&id))
	return id
}

func TestScheduler_RestartingOnlyWhileItsRestartIsOpen(t *testing.T) {
	e := newEnv(t)
	left := e.project("restarting")
	e.op(left, "restart", "failed")
	open := e.project("restarting")
	e.op(open, "restart", "running")
	e.tick()
	if n := e.jobs(left, "push"); n != 0 {
		t.Fatalf("%d pushes for a project left restarting", n)
	}
	if n := e.jobs(open, "push"); n != 1 {
		t.Fatalf("%d pushes for a project whose restart is open, want 1", n)
	}
}

func TestScheduler_ReplicateAfterPushAndBackup(t *testing.T) {
	e := newEnv(t)
	withSeams(t, nil, func(store.Job, any) (json.RawMessage, error) { return json.RawMessage(`{"ok":true}`), nil })
	ref := e.project("active")
	e.submit(ref, "push")
	e.turn("push") // undeclared: no replication
	if n := e.jobs(ref, "replicate"); n != 0 {
		t.Fatalf("%d replications while undeclared", n)
	}
	e.declare()
	// The replication is queued as the push is recorded done, without a tick.
	e.submit(ref, "push")
	e.turn("push")
	if n := e.jobs(ref, "replicate"); n != 1 {
		t.Fatalf("%d replications after a done push, want 1", n)
	}
	e.turn("push") // the replication runs
	for _, l := range [][]byte{failLine("repository", "x"), okLine("check")} {
		kind := "push"
		if bytes.Contains(l, []byte(`"push":`)) {
			kind = "check"
		}
		res := agent.JobResult{Result: l}
		if kind == "push" {
			res.ExitCode = 1
		}
		e.ag.setScript(kind, func(context.Context, agent.JobSpec) (agent.JobResult, error) { return res, nil })
		e.submit(ref, kind)
		e.turn(laneOf(kind))
		if n := e.jobs(ref, "replicate"); n != 1 {
			t.Fatalf("%d replications after a %s (a failed push, a check)", n, kind)
		}
	}
	e.submit(ref, "backup")
	e.turn("backup")
	if n := e.jobs(ref, "replicate"); n != 2 {
		t.Fatalf("%d replications after a done backup, want 2", n)
	}
	// Another backup ends while that replication is still queued: no third.
	e.submit(ref, "backup")
	e.turn("backup")
	if n := e.jobs(ref, "replicate"); n != 2 {
		t.Fatalf("%d replications while one is queued", n)
	}
}

func quarantining(e *env) {
	e.ag.setScript("push", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		p := okPush()
		p.Quarantined = []jobio.Quarantined{{Name: "000000030000000000000001", Reason: "timeline"}}
		return agent.JobResult{Result: line(p)}, nil
	})
}

func TestScheduler_ForcedFullOncePerDay(t *testing.T) {
	e := newEnv(t)
	quarantining(e)
	ref := e.project("active")
	day := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	e.clock.Set(day)
	for range 2 {
		e.submit(ref, "push")
		e.turn("push")
	}
	if n := e.jobs(ref, "backup"); n != 1 {
		t.Fatalf("%d forced fulls on one day, want 1", n)
	}
	e.clock.Set(day.Add(14 * time.Hour)) // the next UTC day
	e.submit(ref, "push")
	e.turn("push")
	if n := e.jobs(ref, "backup"); n != 2 {
		t.Fatalf("%d forced fulls after two days, want 2", n)
	}
}

func TestScheduler_PrunesJobRowsHourly(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	old := func(n int) {
		_, err := e.db.Exec(context.Background(), `insert into backup_job (subject, lane, kind, state, deadline_s, finished_at)
			select $1, 'push', 'push', 'done', 120, now() - interval '49 hours' from generate_series(1, $2)`, ref, n)
		must(t, err)
	}
	old(25000)
	recent := e.submit(ref, "check")
	e.r.lastHourly = time.Time{}
	must(t, e.r.tickOnce(context.Background()))
	if n := e.count("select count(*) from backup_job where kind = 'push' and state = 'done'"); n != 0 {
		t.Fatalf("%d prunable rows left after one hourly pass (one delete takes at most 10,000)", n)
	}
	if e.job(recent).State == "" {
		t.Fatal("a recent job was pruned")
	}
	old(5)
	e.clock.Add(59 * time.Minute)
	must(t, e.r.tickOnce(context.Background()))
	if n := e.count("select count(*) from backup_job where kind = 'push' and state = 'done'"); n != 5 {
		t.Fatalf("%d rows: pruned within the hour", n)
	}
	e.clock.Add(time.Minute)
	must(t, e.r.tickOnce(context.Background()))
	if n := e.count("select count(*) from backup_job where kind = 'push' and state = 'done'"); n != 0 {
		t.Fatalf("%d rows after the hour", n)
	}
}

func (e *env) notices(subject, code string) int {
	return e.count("select coalesce(sum(count), 0)::int from backup_notice where subject = $1 and code = $2", subject, code)
}

func (e *env) hourly() {
	e.t.Helper()
	must(e.t, e.r.hourly(context.Background()))
}

func TestHourly_ControlPlaneQuotaHalfNotice(t *testing.T) {
	e := newEnv(t)
	e.controlPlane()
	disk, repo := nodecfg.CPQuotas(e.r.cfg, e.p)
	e.ag.quota = agent.QuotaUse{DiskUsedKB: int64(disk)*512 - 1, RepoUsedKB: int64(repo)*512 - 1}
	e.hourly()
	if n := e.notices("cp", "cp-quota-half"); n != 0 {
		t.Fatalf("notice below half (%d)", n)
	}
	if !slices.Contains(e.ag.called(), "QuotaUse 70") {
		t.Fatalf("calls %q", e.ag.called())
	}
	e.ag.quota.RepoUsedKB = int64(repo) * 512
	e.hourly()
	if n := e.notices("cp", "cp-quota-half"); n != 1 {
		t.Fatalf("%d notices at half the repository quota", n)
	}
}

func TestHourly_RepoSpaceLowNotice(t *testing.T) {
	e := newEnv(t)
	e.controlPlane()
	_, repo := nodecfg.CPQuotas(e.r.cfg, e.p)
	e.ag.quota = agent.QuotaUse{RepoUsedKB: 1024 * 1024} // 1 GiB used
	e.ag.repoFree = int64(repo) - 1024
	e.hourly()
	if n := e.notices("cp", "repo-space-low"); n != 0 {
		t.Fatalf("notice with the unused quota free (%d)", n)
	}
	e.ag.repoFree--
	e.hourly()
	if n := e.notices("cp", "repo-space-low"); n != 1 {
		t.Fatalf("%d notices with less free than the unused quota", n)
	}
}

func TestHourly_RemovesFetchOfProjectsWithoutAnOpenRestore(t *testing.T) {
	e := newEnv(t)
	failed := e.project("restoring")
	e.op(failed, "restore", "failed")
	open := e.project("restoring")
	e.op(open, "restore", "waiting_job")
	active := e.project("active")
	e.hourly()
	calls := e.ag.called()
	if !slices.Contains(calls, "RemoveFetch "+failed) || !slices.Contains(calls, "RemoveFetch "+active) || slices.Contains(calls, "RemoveFetch "+open) {
		t.Fatalf("calls %q", calls)
	}
}
