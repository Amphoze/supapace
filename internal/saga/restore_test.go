package saga

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/store"
)

var restoreIDs = []string{"T1", "T2", "T3", "T4p", "T4r", "T5a", "T5b", "T5", "T6", "T7", "T8", "T9",
	"T10p", "T10r", "T10c", "T10b", "T10s", "T11"}

// ───────── restore: the path ─────────

func TestRestore_LocalTimeTarget_StepOrder(t *testing.T) {
	x := newRx(t)
	to := x.base.Add(90 * time.Minute).Format(time.RFC3339)
	op := x.run(to, 0, "")
	if op.State != "done" {
		t.Fatalf("%+v", op)
	}
	wantSeq(t, x.e.steps(op.ID), restoreIDs)
	wantSeq(t, x.kinds(op.ID), []string{"T4p/push", "T6/restore", "T7/recover", "T10p/push", "T10c/check", "T10b/backup"})
	var seq []string
	for _, m := range x.calls() {
		if !strings.HasPrefix(m, "job:") && m != "GatewayGeneration" {
			seq = append(seq, m)
		}
	}
	wantSeq(t, seq, []string{"HostState", "HostState", "SetRoute", "StopPostgREST", "StopCluster", "WipeData", "Rekey", "StopCluster",
		"EnsureCluster", "VerifyCluster", "EnsurePostgREST", "SetRoute", "ProbeREST", "RemoveFetch"})
	if p := x.e.project(x.ref); p.State != "active" || x.slot() != "" {
		t.Fatalf("project %s slot %q", p.State, x.slot())
	}
	if j := x.jobs(op.ID, "T7")[0]; fmt.Sprint(j.Params["target"]) != fmt.Sprint(map[string]any{"time": to, "timeline": "1"}) {
		t.Fatalf("recover target %v", j.Params)
	}
	if j := x.jobs(op.ID, "T6")[0]; j.Params["set"] != x.sets[1] || j.Params["mode"] != "none" {
		t.Fatalf("restore job %v", j.Params)
	}
	if tl := x.timelines()[2]; tl.State != "recorded" || tl.OpID != op.ID {
		t.Fatalf("timeline 2 %+v", tl)
	}
}

func TestRestore_Offsite_FetchBeforeWipe(t *testing.T) {
	x := newRx(t)
	x.declare()
	op := x.run("latest", 0, "offsite")
	if op.State != "done" {
		t.Fatalf("%+v", op)
	}
	wantSeq(t, x.kinds(op.ID)[:5], []string{"T4p/push", "T4r/replicate", "T5a/fetch", "T5b/seed", "T6/restore"})
	c := x.calls()
	if !before(c, "job:T5b:seed", "WipeData") || !before(c, "RemoveFetch", "job:T5a:fetch") {
		t.Fatalf("order %v", c)
	}
	if j := x.jobs(op.ID, "T5a")[0]; fmt.Sprint(j.Params) != fmt.Sprint(map[string]any{"set": x.sets[2], "to": "latest", "timeline": float64(0), "extra": float64(0)}) {
		t.Fatalf("fetch params %v", j.Params)
	}
	if r := x.result(op.ID); raw(r, "seeded") != "true" || raw(r, "from") != `"offsite"` {
		t.Fatalf("result %s", x.e.op(op.ID).Result)
	}
}

func TestRestore_SlotOwnedT4pToT11(t *testing.T) {
	x := newRx(t)
	slots := map[string]string{}
	x.ag.setHook(func(ctx context.Context, c call) {
		if c.Ref == x.ref && (c.Method == "StopPostgREST" || c.Method == "WipeData" || c.Method == "EnsurePostgREST") {
			s := x.slot()
			x.set(func() { slots[c.Method] = s })
		}
	})
	op := x.run("latest", 0, "")
	id := fmt.Sprint(op.ID)
	x.set(func() {})
	if slots["StopPostgREST"] != "" || slots["WipeData"] != id || slots["EnsurePostgREST"] != id || x.slot() != "" {
		t.Fatalf("slots %v, after %q", slots, x.slot())
	}
}

func TestRestore_HistoriesFromThePlanAfterASeed(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.timeline(2, "abandoned", 0)
	x.set(func() { x.fetchH = []string{"00000002.history"}; x.hist = []string{"00000002.history"} })
	held := ""
	x.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "WipeData" {
			h := raw(x.params(x.restoreOps()[0].ID), "histories")
			x.set(func() { held = h })
		}
	})
	op := x.run("latest", 0, "offsite")
	x.set(func() {})
	if op.State != "done" || held != `["00000002.history"]` {
		t.Fatalf("%s held %s", op.State, held)
	}
	if tl := x.timelines(); tl[3].State != "recorded" || tl[2].State != "abandoned" {
		t.Fatalf("timelines %+v", tl)
	}
}

func TestRestore_T4pPushesUntilComplete(t *testing.T) {
	x := newRx(t)
	// A spool of 150 entries: 56 a job.
	x.on("T4p", "push", func(n int) jobEnd {
		return jobEnd{state: "done", result: pushRes(n == 3, map[string]string{"00000001": fmt.Sprintf("00000001000000000000000%d", n)}, []string{})}
	})
	x.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "WipeData" && len(x.jobs(x.restoreOps()[0].ID, "T4p")) != 3 {
			t.Errorf("wiped before the third push")
		}
	})
	op := x.run("latest", 0, "")
	if op.State != "done" || len(x.jobs(op.ID, "T4p")) != 3 {
		t.Fatalf("%s %v", op.State, x.kinds(op.ID))
	}
	if p := x.params(op.ID); raw(p, "n_newest_segment") != `"000000010000000000000003"` {
		t.Fatalf("newest %s", raw(p, "n_newest_segment"))
	}

	// Past the bound: failed, nothing wiped.
	x2 := newRx(t)
	x2.on("T4p", "push", func(n int) jobEnd { return jobEnd{state: "done", result: pushRes(false, x2.newest, nil)} })
	op = x2.run("latest", 0, "")
	wantCode(t, op, "failed", "push_incomplete")
	if n := len(x2.jobs(op.ID, "T4p")); n != bklimit.PushLoopMax(layout2.DiskQuotaMB) || slices.Contains(x2.calls(), "WipeData") {
		t.Fatalf("%d pushes, calls %v", n, x2.calls())
	}
}

func TestRestore_T10pPushesUntilComplete(t *testing.T) {
	x := newRx(t)
	x.on("T10p", "push", func(n int) jobEnd { return jobEnd{state: "done", result: pushRes(n == 2, x.newest, nil)} })
	op := x.run("latest", 0, "")
	if op.State != "done" || len(x.jobs(op.ID, "T10p")) != 2 {
		t.Fatalf("%s %v", op.State, x.kinds(op.ID))
	}
}

// ───────── restore: the restore type ─────────

// forked: timelines 1 and 2 recorded, the sets on 1.
func forked(t *testing.T) *rx {
	x := newRx(t)
	x.recordedBy(2, 0) // timeline 2 was made by a restore of set A: its lineage on timeline 1
	x.set(func() {
		x.hist = []string{"00000002.history"}
		x.newest = map[string]string{"00000001": seg8, "00000002": "000000020000000000000009"}
		x.reach = "000000020000000000000009"
	})
	return x
}

func modes(x *rx, id int64) []string {
	var out []string
	for _, j := range x.jobs(id, "T6") {
		out = append(out, fmt.Sprintf("%v %v", j.Params["mode"], j.Params["target_timeline"]))
	}
	return out
}

func TestRestore_ReturnBeforeForkUsesNone(t *testing.T) {
	x := forked(t)
	op := x.run(x.base.Add(90*time.Minute).Format(time.RFC3339), 1, "")
	if op.State != "done" || fmt.Sprint(modes(x, op.ID)) != "[none 0]" || raw(x.result(op.ID), "mode") != `"none"` {
		t.Fatalf("%s %v", op.State, modes(x, op.ID))
	}
}

func TestRestore_ReturnAfterForkUsesStandby(t *testing.T) {
	x := forked(t)
	x.on("T6", "restore", func(n int) jobEnd {
		if n == 1 {
			return failEnd("history_mismatch")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"standby"}`}
	})
	op := x.run(x.base.Add(90*time.Minute).Format(time.RFC3339), 1, "")
	if op.State != "done" || fmt.Sprint(modes(x, op.ID)) != "[none 0 standby 1]" {
		t.Fatalf("%s %v", op.State, modes(x, op.ID))
	}
	c := x.calls()
	if countOf(c, "WipeData") != 2 || slices.Contains(x.kinds(op.ID), "T5a/fetch") || raw(x.result(op.ID), "mode") != `"standby"` {
		t.Fatalf("calls %v jobs %v", c, x.kinds(op.ID))
	}
	// After the wipe: the second restore job follows a second WipeData.
	if i := slices.Index(c, "job:T6:restore"); !slices.Contains(c[i+1:], "WipeData") {
		t.Fatalf("calls %v", c)
	}
}

func TestRestore_StandbyRefusedTooGoesOffsite(t *testing.T) {
	x := forked(t)
	x.declare()
	x.on("T6", "restore", func(n int) jobEnd {
		if n <= 2 {
			return failEnd("history_mismatch")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"none"}`}
	})
	op := x.run(x.base.Add(90*time.Minute).Format(time.RFC3339), 1, "")
	if op.State != "done" || fmt.Sprint(modes(x, op.ID)) != "[none 0 standby 1 none 0]" {
		t.Fatalf("%s %v", op.State, modes(x, op.ID))
	}
	k := x.kinds(op.ID)
	if i := slices.Index(k, "T5a/fetch"); i < 0 || slices.Index(k[i:], "T6/restore") < 0 || raw(x.params(op.ID), "from") != `"offsite"` {
		t.Fatalf("jobs %v", k)
	}
}

func TestRestore_HistoryMismatchWithoutTimelineGoesOffsite(t *testing.T) {
	x := forked(t)
	x.declare()
	x.on("T6", "restore", func(n int) jobEnd {
		if n == 1 {
			return failEnd("history_mismatch")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"none"}`}
	})
	op := x.run("latest", 0, "")
	if op.State != "done" || fmt.Sprint(modes(x, op.ID)) != "[none 0 none 0]" || !slices.Contains(x.kinds(op.ID), "T5a/fetch") {
		t.Fatalf("%s %v %v", op.State, modes(x, op.ID), x.kinds(op.ID))
	}
	// Already off-site: a refusal is an ordinary failed step (back to T5, no third source).
	x2 := forked(t)
	x2.declare()
	x2.on("T6", "restore", func(n int) jobEnd {
		if n == 1 {
			return failEnd("history_mismatch")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"none"}`}
	})
	op = x2.run("latest", 0, "offsite")
	if op.State != "done" || len(x2.jobs(op.ID, "T5a")) != 1 || countOf(x2.calls(), "WipeData") != 2 {
		t.Fatalf("%s %v", op.State, x2.kinds(op.ID))
	}
}

func TestRestore_RewindToT3ClearsStandbyTried(t *testing.T) {
	x := forked(t)
	x.on("T6", "restore", func(n int) jobEnd {
		if n%2 == 1 {
			return failEnd("history_mismatch")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"standby"}`}
	})
	x.on("T7", "recover", func(n int) jobEnd {
		if n == 1 {
			return failEnd("recovery_failed")
		}
		return jobEnd{state: "done", result: recoverRes("000000020000000000000009")}
	})
	op := x.run(x.base.Add(90*time.Minute).Format(time.RFC3339), 1, "")
	if op.State != "done" || fmt.Sprint(modes(x, op.ID)) != "[none 0 standby 1 none 0 standby 1]" {
		t.Fatalf("%s %v", op.State, modes(x, op.ID))
	}
	if slices.Contains(x.kinds(op.ID), "T5a/fetch") {
		t.Fatalf("went off-site: %v", x.kinds(op.ID))
	}
}

// ───────── restore: every rewind and retry submits fresh jobs ─────────

// freshAfter asserts that every job of the steps after the job with id
// cause has a higher id than it, that each step has a job from before and
// after it, and that the step's consumed job is the later one.
func freshAfter(t *testing.T, x *rx, id, cause int64, steps ...string) {
	t.Helper()
	for _, s := range steps {
		js := x.jobs(id, s)
		if len(js) < 2 || js[len(js)-1].ID <= cause || js[len(js)-1].State != "done" {
			t.Fatalf("step %s after job %d: %+v", s, cause, js)
		}
	}
}

func failedJob(x *rx, id int64, step string) int64 {
	for _, j := range x.jobs(id, step) {
		if j.State == "failed" {
			return j.ID
		}
	}
	x.e.t.Fatalf("no failed job at %s", step)
	return 0
}

func TestRestore_RewindFromT7SubmitsFreshJobs(t *testing.T) {
	for _, from := range []string{"local", "offsite"} {
		t.Run(from, func(t *testing.T) {
			x := newRx(t)
			x.declare()
			x.on("T7", "recover", func(n int) jobEnd {
				if n == 1 {
					return failEnd("recovery_failed")
				}
				return jobEnd{state: "done", result: recoverRes(seg9)}
			})
			// The second pass's push names another newest segment: it is the one consumed.
			x.on("T4p", "push", func(n int) jobEnd {
				return jobEnd{state: "done", result: pushRes(true, map[string]string{"00000001": []string{seg8, seg9}[min(n, 2)-1]}, nil)}
			})
			op := x.run("latest", 0, from)
			if op.State != "done" {
				t.Fatalf("%+v", op)
			}
			steps := []string{"T4p", "T4r", "T6", "T7"}
			if from == "offsite" {
				steps = append(steps, "T5a", "T5b")
			}
			freshAfter(t, x, op.ID, failedJob(x, op.ID, "T7"), steps...)
			if p := x.params(op.ID); raw(p, "n_newest_segment") != `"`+seg9+`"` {
				t.Fatalf("an earlier push was consumed: %s", raw(p, "n_newest_segment"))
			}
		})
	}
}

func TestRestore_RewindFromT8SubmitsFreshJobs(t *testing.T) {
	x := newRx(t)
	n := 0
	x.set(func() {
		x.rekey = func(ctx context.Context, s agent.Spec, pending int) (int, error) {
			if n++; n == 1 {
				return 0, errBoom
			}
			return pending, nil
		}
	})
	op := x.run("latest", 0, "")
	if op.State != "done" {
		t.Fatalf("%+v", op)
	}
	first := x.jobs(op.ID, "T7")[0].ID
	freshAfter(t, x, op.ID, first, "T4p", "T6", "T7")
}

func TestRestore_RewindOnHistoryMismatchSubmitsFreshJobs(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.on("T6", "restore", func(n int) jobEnd {
		if n <= 2 { // none, then the standby retry (the set lies on the timeline followed)
			return failEnd("history_mismatch")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"none"}`}
	})
	op := x.run("latest", 0, "")
	if op.State != "done" {
		t.Fatalf("%+v", op)
	}
	cause := x.jobs(op.ID, "T6")[1].ID // the standby refusal sent it off-site
	for _, s := range []string{"T5a", "T5b", "T6", "T7"} {
		js := x.jobs(op.ID, s)
		if js[len(js)-1].ID <= cause || js[len(js)-1].State != "done" {
			t.Fatalf("%s: %+v", s, js)
		}
	}
}

func TestRestore_RewindOnTargetNotReachedSubmitsAWiderFetch(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.on("T7", "recover", func(n int) jobEnd {
		if n == 1 {
			return failEnd("target_not_reached")
		}
		return jobEnd{state: "done", result: recoverRes(seg9)}
	})
	op := x.run(x.base.Add(90*time.Minute).Format(time.RFC3339), 0, "offsite")
	f := x.jobs(op.ID, "T5a")
	if op.State != "done" || len(f) != 2 || f[0].Params["extra"] != float64(0) || f[1].Params["extra"] != float64(1) {
		t.Fatalf("%s %+v", op.State, f)
	}
	freshAfter(t, x, op.ID, failedJob(x, op.ID, "T7"), "T5a", "T5b", "T6", "T7")
}

func TestRestore_RewindFromT5bSubmitsAFreshFetch(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.on("T5b", "seed", func(n int) jobEnd {
		if n == 1 {
			return failEnd("host_state")
		}
		return okEnd
	})
	op := x.run("latest", 0, "offsite")
	if op.State != "done" {
		t.Fatalf("%+v", op)
	}
	freshAfter(t, x, op.ID, failedJob(x, op.ID, "T5b"), "T5a")
}

func TestRestore_StandbyRetrySubmitsAFreshRestoreJob(t *testing.T) {
	x := forked(t)
	x.on("T6", "restore", func(n int) jobEnd {
		if n == 1 {
			return failEnd("history_mismatch")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"standby"}`}
	})
	op := x.run(x.base.Add(90*time.Minute).Format(time.RFC3339), 1, "")
	js := x.jobs(op.ID, "T6")
	if op.State != "done" || len(js) != 2 || js[0].State != "failed" || js[1].ID <= js[0].ID || js[1].Params["mode"] != "standby" {
		t.Fatalf("%s %+v", op.State, js)
	}
}

func TestRestore_T6FailedJobWipesThenSubmitsAgain(t *testing.T) {
	x := newRx(t)
	x.on("T6", "restore", func(n int) jobEnd {
		if n == 1 {
			return failEnd("pgbackrest")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"none"}`}
	})
	op := x.run("latest", 0, "")
	c := x.calls()
	i := slices.Index(c, "job:T6:restore")
	if op.State != "done" || len(x.jobs(op.ID, "T6")) != 2 || !before(c[i+1:], "WipeData", "job:T6:restore") {
		t.Fatalf("%s %v", op.State, c)
	}
	// Interrupted (a daemon restart): the same.
	x2 := newRx(t)
	x2.on("T6", "restore", func(n int) jobEnd {
		if n == 1 {
			return failEnd("interrupted")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"none"}`}
	})
	op = x2.run("latest", 0, "")
	if op.State != "done" || countOf(x2.calls(), "WipeData") != 2 {
		t.Fatalf("%s %v", op.State, x2.calls())
	}
}

func TestRestore_OpRetrySubmitsFreshJobs(t *testing.T) {
	x := newRx(t)
	stuck := true
	x.on("T4p", "push", func(n int) jobEnd { return jobEnd{state: "done", result: pushRes(!stuck, x.newest, nil)} })
	op := x.run("latest", 0, "")
	wantCode(t, op, "failed", "push_incomplete")
	last := x.jobs(op.ID, "T4p")
	x.set(func() { stuck = false })
	must(t, x.e.st.RetryOperation(context.Background(), op.ID))
	op = x.e.waitState(op.ID, "done")
	js := x.jobs(op.ID, "T4p")
	if len(js) != len(last)+1 || js[len(js)-1].ID <= last[len(last)-1].ID {
		t.Fatalf("pushes %+v", js)
	}
}

func TestRestore_ReplicateLoopAfterARewindCountsFromZero(t *testing.T) {
	cfg := layout2
	cfg.DiskQuotaMB = 1024 // ReplLoopMax 6
	x := newRxWith(t, cfg)
	x.declare()
	max := bklimit.ReplLoopMax(cfg.DiskQuotaMB)
	capped := jobEnd{state: "done", result: `{"ok":true,"mode":"copy","complete":false,"stopped":"caps","uploaded":2,"adopted":0}`}
	x.on("T4r", "replicate", func(n int) jobEnd {
		if (n-1)%max == max-1 { // the bound's last job of each pass completes
			return replDone
		}
		return capped
	})
	x.on("T7", "recover", func(n int) jobEnd {
		if n == 1 {
			return failEnd("recovery_failed")
		}
		return jobEnd{state: "done", result: recoverRes(seg9)}
	})
	op := x.run("latest", 0, "")
	if op.State != "done" || len(x.jobs(op.ID, "T4r")) != 2*max {
		t.Fatalf("%s %v", op.State, x.kinds(op.ID))
	}
}

// ───────── restore: the recovery container ─────────

func TestRestore_T7FailureGoesToT3(t *testing.T) {
	x := newRx(t)
	x.on("T7", "recover", func(n int) jobEnd {
		if n == 1 {
			return failEnd("recovery_failed")
		}
		return jobEnd{state: "done", result: recoverRes(seg9)}
	})
	op := x.run("latest", 0, "")
	c := x.calls()
	i := slices.Index(c, "job:T7:recover")
	if op.State != "done" || !before(c[i+1:], "StopCluster", "job:T4p:push") {
		t.Fatalf("%s %v", op.State, c)
	}
	if !slices.Contains(x.e.steps(op.ID), "T3") || countOf(x.e.steps(op.ID), "T3") != 2 {
		t.Fatalf("steps %v", x.e.steps(op.ID))
	}
}

func TestRestore_T8FailureStopsRecoveryFirst(t *testing.T) {
	x := newRx(t)
	n := 0
	x.set(func() {
		x.rekey = func(ctx context.Context, s agent.Spec, pending int) (int, error) {
			if n++; n == 1 {
				return 0, errBoom
			}
			return pending, nil
		}
	})
	op := x.run("latest", 0, "")
	c := x.calls()
	i := slices.Index(c, "Rekey")
	if op.State != "done" || c[i+1] != "StopCluster" {
		t.Fatalf("%s %v", op.State, c)
	}
	for _, m := range []string{"job:T4p:push", "WipeData", "job:T6:restore"} {
		if !before(c[i+1:], "StopCluster", m) {
			t.Fatalf("%s before the stop: %v", m, c)
		}
	}
}

func TestRestore_T8ReentryAfterConfirmOnlyStops(t *testing.T) {
	x := newRx(t)
	id := x.mustSubmit("latest", 0, "")
	// The worker dies after the confirm, inside T8's stop.
	crashed := false
	x.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "StopCluster" && !crashed && raw(x.params(id), "t8_done") == "true" {
			crashed = true
			runtime.Goexit()
		}
	})
	done := x.e.run(x.r)
	<-done
	if op := x.e.op(id); op.Step != "T7" || raw(x.params(id), "t8_done") != "true" {
		t.Fatalf("not at T8: %+v %s", op, op.Params)
	}
	x.e.start(x.r)
	op := x.e.waitState(id, "done")
	if n := countOf(x.calls(), "Rekey"); n != 1 {
		t.Fatalf("%d re-keys", n)
	}
	tl := x.timelines()
	if len(tl) != 2 || tl[2].State != "recorded" {
		t.Fatalf("timelines %+v (%s)", tl, op.State)
	}
}

// ───────── restore: no loop ─────────

func TestRestore_RekeyFailingEveryTimeFailsAfterFiveRewinds(t *testing.T) {
	x := newRx(t)
	x.set(func() {
		x.rekey = func(context.Context, agent.Spec, int) (int, error) {
			return 0, fmt.Errorf("re-key: %w", pgsock.ErrPeer)
		}
	})
	op := x.run("latest", 0, "")
	wantCode(t, op, "failed", "peer")
	if n := len(x.jobs(op.ID, "T7")); n != 5 {
		t.Fatalf("%d recover jobs", n)
	}
	// Superseded by a new restore, or deleted.
	x.set(func() { x.rekey = nil })
	id := x.mustSubmit("latest", 0, "")
	if x.e.op(op.ID).State != "superseded" {
		t.Fatal("not superseded")
	}
	if op := x.finish(id); op.State != "done" {
		t.Fatalf("%+v", op)
	}
}

func TestRestore_TimelineMismatchEveryTimeFailsAfterFiveRewinds(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.set(func() {
		x.rekey = func(context.Context, agent.Spec, int) (int, error) { return 99, nil }
	})
	op := x.run("latest", 0, "")
	wantCode(t, op, "failed", "timeline_mismatch")
	if n := len(x.jobs(op.ID, "T7")); n != 5 {
		t.Fatalf("%d recover jobs", n)
	}
	if n, ok := x.notice("timeline-mismatch"); !ok || n.Count != 5 {
		t.Fatalf("notice %+v", n)
	}
	// It can be deleted.
	del, err := x.r.Submit(context.Background(), "delete", x.ref, nil)
	must(t, err)
	if x.e.op(op.ID).State != "superseded" || x.e.op(del).Kind != "delete" {
		t.Fatal("delete not accepted")
	}
}

func TestRestore_RewindAfterAFailedRecoverJobIsNotCountedTwice(t *testing.T) {
	// Four failed recover jobs (each counted once, by its job) and a fifth
	// that ends done: counted twice, the rewinds would exhaust the attempts.
	x := newRx(t)
	x.on("T7", "recover", func(n int) jobEnd {
		if n <= 4 {
			return failEnd("recovery_failed")
		}
		return jobEnd{state: "done", result: recoverRes(seg9)}
	})
	op := x.run("latest", 0, "")
	if op.State != "done" || len(x.jobs(op.ID, "T7")) != 5 {
		t.Fatalf("%+v %v", op, x.kinds(op.ID))
	}
}

// ───────── restore: re-entry ─────────

func TestRestore_T9OnRetriesTheStep(t *testing.T) {
	x := newRx(t)
	n := 0
	x.ag.setErr(func(c call) error {
		if c.Method == "EnsureCluster" {
			if n++; n == 1 {
				return errBoom
			}
		}
		return nil
	})
	op := x.run("latest", 0, "")
	if op.State != "done" || len(x.jobs(op.ID, "T7")) != 1 || countOf(x.calls(), "EnsureCluster") != 2 {
		t.Fatalf("%s %v", op.State, x.calls())
	}
}

func TestRestore_T5bWithoutFetchGoesToT5a(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.on("T5b", "seed", func(n int) jobEnd {
		if n == 1 {
			return failEnd("host_state")
		}
		return okEnd
	})
	op := x.run("latest", 0, "offsite")
	c := x.calls()
	if op.State != "done" || countOf(c, "RemoveFetch") != 3 || len(x.jobs(op.ID, "T5a")) != 2 || countOf(c, "WipeData") != 1 {
		t.Fatalf("%s %v", op.State, c)
	}
}

func TestRestore_T5aEmptiesFetchFirst(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.on("T5a", "fetch", func(n int) jobEnd {
		if n == 1 {
			return failEnd("mismatch")
		}
		return jobEnd{state: "done", result: fetchRes(nil)}
	})
	op := x.run("latest", 0, "offsite")
	c := x.calls()
	var seq []string
	for _, m := range c {
		if m == "RemoveFetch" || m == "job:T5a:fetch" {
			seq = append(seq, m)
		}
	}
	wantSeq(t, seq, []string{"RemoveFetch", "job:T5a:fetch", "RemoveFetch", "job:T5a:fetch", "RemoveFetch"})
	if op.State != "done" {
		t.Fatalf("%+v", op)
	}
}

func TestRestore_TargetNotReachedWidensFetch_ThreeTimesThenAll(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.on("T7", "recover", func(n int) jobEnd {
		if n <= 4 {
			return failEnd("target_not_reached")
		}
		return jobEnd{state: "done", result: recoverRes(seg9)}
	})
	op := x.run(x.base.Add(90*time.Minute).Format(time.RFC3339), 0, "offsite")
	var extra []string
	for _, j := range x.jobs(op.ID, "T5a") {
		extra = append(extra, fmt.Sprint(j.Params["extra"]))
	}
	if op.State != "done" || fmt.Sprint(extra) != "[0 1 2 3 4]" {
		t.Fatalf("%s %v", op.State, extra)
	}
	if bklimit.FetchMargin(300*time.Second, 4) != bklimit.WholeArchive || bklimit.FetchMargin(300*time.Second, 3) == bklimit.WholeArchive {
		t.Fatal("the fourth fetch is not the whole archive")
	}
}

func TestRestore_FetchTooLargeFailsTheStep(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.on("T5a", "fetch", func(n int) jobEnd { return failEnd("fetch_too_large") })
	op := x.run("latest", 0, "offsite")
	wantCode(t, op, "failed", "fetch_too_large")
	if len(x.jobs(op.ID, "T5a")) != 1 || slices.Contains(x.calls(), "WipeData") {
		t.Fatalf("%v %v", x.kinds(op.ID), x.calls())
	}
}

// ───────── restore: timelines ─────────

func TestRestore_PendingBeforeEachT7(t *testing.T) {
	x := newRx(t)
	var seen []string
	x.on("T7", "recover", func(n int) jobEnd {
		tl := x.timelines()[2]
		seen = append(seen, tl.State)
		if n == 1 {
			return failEnd("recovery_failed")
		}
		return jobEnd{state: "done", result: recoverRes(seg9)}
	})
	op := x.run("latest", 0, "")
	x.set(func() {})
	if op.State != "done" || fmt.Sprint(seen) != "[pending pending]" || x.timelines()[2].OpID != op.ID {
		t.Fatalf("%s %v", op.State, seen)
	}
}

func TestRestore_T8ConfirmsOrFails_MismatchGoesOffsite(t *testing.T) {
	x := newRx(t)
	x.declare()
	n := 0
	x.set(func() {
		x.rekey = func(ctx context.Context, s agent.Spec, pending int) (int, error) {
			if n++; n == 1 {
				return pending + 1, nil
			}
			return pending, nil
		}
	})
	op := x.run("latest", 0, "")
	if op.State != "done" || raw(x.params(op.ID), "from") != `"offsite"` || len(x.jobs(op.ID, "T5a")) != 1 {
		t.Fatalf("%s %v", op.State, x.kinds(op.ID))
	}
	if nt, ok := x.notice("timeline-mismatch"); !ok || nt.Count != 1 {
		t.Fatalf("notice %+v", nt)
	}
	if tl := x.timelines()[2]; tl.State != "recorded" || raw(x.result(op.ID), "new_timeline") != "2" {
		t.Fatalf("%+v %s", tl, x.e.op(op.ID).Result)
	}
}

func TestRestore_UnrecordedHistoryAtT4GoesOffsite(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.set(func() { x.hist = []string{"00000005.history"} })
	op := x.run("latest", 0, "")
	if op.State != "done" || len(x.jobs(op.ID, "T5a")) != 1 {
		t.Fatalf("%s %v", op.State, x.kinds(op.ID))
	}
	// Control: a held history of an admitted (pending) timeline is not extra.
	x2 := newRx(t)
	x2.declare()
	x2.timeline(2, "pending", x2.create)
	x2.set(func() { x2.hist = []string{"00000002.history"} })
	op = x2.run("latest", 0, "")
	if op.State != "done" || len(x2.jobs(op.ID, "T5a")) != 0 {
		t.Fatalf("%s %v", op.State, x2.kinds(op.ID))
	}
}

func TestRestore_MissingRecordedHistoryAtT4GoesOffsite(t *testing.T) {
	for _, state := range []string{"recorded", "abandoned"} {
		t.Run(state, func(t *testing.T) {
			x := newRx(t)
			x.declare()
			x.timeline(2, state, 0)
			x.set(func() { x.hist = []string{} }) // repo/ lacks its history
			op := x.run("latest", 1, "")
			if op.State != "done" || len(x.jobs(op.ID, "T5a")) != 1 {
				t.Fatalf("%s %v", op.State, x.kinds(op.ID))
			}
		})
	}
}

func TestRestore_SupersedingAfterAPromotedFailureStaysLocal(t *testing.T) {
	x := newRx(t)
	x.set(func() {
		x.rekey = func(context.Context, agent.Spec, int) (int, error) { return 0, errBoom }
	})
	op := x.run("latest", 0, "")
	if op.State != "failed" || x.timelines()[2].State != "pending" {
		t.Fatalf("%+v %+v", op, x.timelines())
	}
	// The promoted cluster archived its history: the next push holds it.
	x.set(func() { x.rekey, x.hist = nil, []string{"00000002.history"} })
	var at7 store.Timeline
	x.on("T7", "recover", func(n int) jobEnd {
		at7 = x.timelines()[2]
		return jobEnd{state: "done", result: recoverRes(seg9)}
	})
	id := x.mustSubmit("latest", 0, "")
	op2 := x.finish(id)
	x.set(func() {})
	tl := x.timelines()
	if op2.State != "done" || raw(x.params(id), "from") != `"local"` || at7.State != "abandoned" ||
		tl[3].State != "recorded" || tl[3].OpID != id {
		t.Fatalf("%s %s at7 %+v %+v", op2.State, raw(x.params(id), "from"), at7, tl)
	}
}

func TestRestore_TimelineConflictGoesOffsiteAndRewinds(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.timeline(2, "pending", x.create) // a superseded attempt's, its history uploaded but not held
	x.recordKey("00000002.history")
	x.set(func() { x.fetchH = []string{"00000002.history"} })
	op := x.run("latest", 0, "")
	if op.State != "done" || raw(x.params(op.ID), "from") != `"offsite"` {
		t.Fatalf("%s %v", op.State, x.kinds(op.ID))
	}
	// The conflict came before the first recover job, which then ran once, off-site.
	if n := len(x.jobs(op.ID, "T7")); n != 1 || len(x.jobs(op.ID, "T5a")) != 1 || countOf(x.e.steps(op.ID), "T3") != 2 {
		t.Fatalf("%v %v", x.kinds(op.ID), x.e.steps(op.ID))
	}
	if tl := x.timelines(); tl[2].State != "abandoned" || tl[3].State != "recorded" {
		t.Fatalf("%+v", tl)
	}
}

// ───────── restore: replaced node ─────────

func replacedRx(t *testing.T) *rx {
	x := newRx(t)
	x.declare()
	x.replaced()
	return x
}

func TestRestore_Replaced_MaterialisesWithoutFirstBoot(t *testing.T) {
	x := replacedRx(t)
	op := x.run("latest", 0, "")
	if op.State != "done" || raw(x.params(op.ID), "replaced") != "true" || raw(x.params(op.ID), "from") != `"offsite"` {
		t.Fatalf("%+v", op)
	}
	c := x.calls()
	i := slices.Index(c, "SetRoute")
	wantSeq(t, c[:i], []string{"HostState", "HostState", "EnsureDir", "EnsureRepoDir", "EnsureNetwork", "RenderCluster"})
	for _, cl := range x.ag.callsOf(x.ref, "EnsureCluster") {
		if cl.FirstBoot {
			t.Fatal("a first boot")
		}
	}
}

func TestRestore_Replaced_RebuildBeforeFetch(t *testing.T) {
	x := replacedRx(t)
	page := jobEnd{state: "done", result: `{"ok":true,"mode":"rebuild","complete":false,"stopped":"rebuild","rows":4000}`}
	x.on("T4r", "replicate", func(n int) jobEnd {
		switch n {
		case 1, 2:
			return page
		case 3:
			return jobEnd{state: "done", result: `{"ok":true,"mode":"rebuild","complete":true,"stopped":"","rows":12}`}
		}
		return replDone
	})
	op := x.run("latest", 0, "")
	k := x.kinds(op.ID)
	if op.State != "done" || fmt.Sprint(k[:5]) != "[T4r/replicate T4r/replicate T4r/replicate T4r/replicate T5a/fetch]" {
		t.Fatalf("%s %v", op.State, k)
	}
}

func TestRestore_Replaced_SkipsT3T4pT5OnFirstPassOnly(t *testing.T) {
	x := replacedRx(t)
	x.on("T7", "recover", func(n int) jobEnd {
		if n == 1 {
			return failEnd("recovery_failed")
		}
		return jobEnd{state: "done", result: recoverRes(seg9)}
	})
	op := x.run("latest", 0, "")
	c := x.calls()
	i := slices.Index(c, "job:T7:recover")
	if op.State != "done" || slices.Contains(c[:i], "StopCluster") || slices.Contains(c[:i], "WipeData") || slices.Contains(c[:i], "job:T4p:push") {
		t.Fatalf("first pass %v", c[:i])
	}
	for _, m := range []string{"StopCluster", "job:T4p:push", "WipeData"} {
		if !slices.Contains(c[i:], m) {
			t.Fatalf("second pass lacks %s: %v", m, c[i:])
		}
	}
}

func TestRestore_Replaced_NAndHistoriesFromTheRecord(t *testing.T) {
	x := replacedRx(t)
	x.recordedBy(2, 2)
	x.set(func() { x.fetchH = []string{"00000002.history"} })
	x.timeline(3, "abandoned", 0)
	x.recordKey("00000002.history")
	x.recordKey("0000000200000000/000000020000000000000007-" + strings.Repeat("b", 40) + ".zst")
	x.recordKey("0000000200000000/00000002000000000000000B-" + strings.Repeat("c", 40) + ".zst")
	var at map[string]json.RawMessage
	x.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "RemoveFetch" && at == nil {
			p := x.params(x.restoreOps()[0].ID)
			x.set(func() { at = p })
		}
	})
	op := x.run("latest", 0, "")
	x.set(func() {})
	if op.State != "done" || raw(at, "n") != "2" || raw(at, "n_newest_segment") != `"00000002000000000000000B"` ||
		raw(at, "histories") != `["00000002.history"]` {
		t.Fatalf("%s at T5a: n %s newest %s histories %s", op.State, at["n"], at["n_newest_segment"], at["histories"])
	}
}

func TestRestore_Replaced_T11CreatesPostgRESTAndRoute(t *testing.T) {
	x := replacedRx(t)
	op := x.run("latest", 0, "")
	var rt string
	x.ag.locked(func() { rt = x.ag.route[x.ref].State })
	if op.State != "done" || rt != "active" || len(x.ag.callsOf(x.ref, "EnsurePostgREST")) != 1 || x.e.project(x.ref).State != "active" {
		t.Fatalf("%s route %q", op.State, rt)
	}
}

// ───────── restore: the result ─────────

func TestRestore_ResultDocument(t *testing.T) {
	x := newRx(t)
	op := x.run("latest", 0, "")
	var r struct {
		To, From, Set, Mode string
		Reached             string `json:"reached_segment"`
		New                 int    `json:"new_timeline"`
		Prev                int    `json:"previous_timeline"`
		PrevNewest          string `json:"previous_newest_segment"`
		Seeded              bool
		Shortfall           json.RawMessage
		Steps               []struct {
			Step    string
			Seconds int
		}
	}
	must(t, strictJSON(x.e.op(op.ID).Result, &r))
	if r.To != "latest" || r.From != "local" || r.Set != x.sets[2] || r.Mode != "none" || r.Reached != seg9 || r.New != 2 ||
		r.Prev != 1 || r.PrevNewest != seg9 || r.Seeded || string(r.Shortfall) != "null" || len(r.Steps) != len(restoreIDs)-1 {
		t.Fatalf("%s", x.e.op(op.ID).Result)
	}
	for i, s := range r.Steps {
		if s.Step != restoreIDs[i] || s.Seconds < 0 {
			t.Fatalf("steps %+v", r.Steps)
		}
	}
}

func TestRestore_ShortfallAgainstTheLastPushsNewestSegment(t *testing.T) {
	x := newRx(t)
	x.set(func() { x.newest, x.reach = map[string]string{"00000001": segA}, seg8 })
	op := x.run("latest", 0, "")
	if op.State != "done" || !sameJSON(raw(x.result(op.ID), "shortfall"), `{"expected":"`+segA+`","reached":"`+seg8+`","segments":2}`) {
		t.Fatalf("%s %s", op.State, x.e.op(op.ID).Result)
	}
	if n, ok := x.notice("restore-shortfall"); !ok || !strings.Contains(n.Detail, segA) || !strings.Contains(n.Detail, seg8) {
		t.Fatalf("notice %+v", n)
	}
}

func TestRestore_ShortfallCheckedOnEveryEndOfArchiveRestore(t *testing.T) {
	sf := func(x *rx, op store.Operation) string {
		x.e.t.Helper()
		if op.State != "done" {
			x.e.t.Fatalf("%+v", op)
		}
		return raw(x.result(op.ID), "shortfall")
	}
	t.Run("below", func(t *testing.T) {
		x := newRx(t)
		x.set(func() { x.reach = seg8 })
		if s := sf(x, x.run("latest", 0, "")); !sameJSON(s, `{"expected":"`+seg9+`","reached":"`+seg8+`","segments":1}`) {
			t.Fatal(s)
		}
	})
	t.Run("equal", func(t *testing.T) {
		x := newRx(t)
		if s := sf(x, x.run("latest", 0, "")); s != "null" {
			t.Fatal(s)
		}
		if _, ok := x.notice("restore-shortfall"); ok {
			t.Fatal("a notice")
		}
	})
	t.Run("replaced", func(t *testing.T) {
		x := replacedRx(t)
		x.recordKey("0000000100000000/" + segA + "-" + strings.Repeat("d", 40) + ".zst")
		if s := sf(x, x.run("latest", 0, "")); !sameJSON(s, `{"expected":"`+segA+`","reached":"`+seg9+`","segments":1}`) {
			t.Fatal(s)
		}
	})
	t.Run("other-timeline", func(t *testing.T) {
		x := forked(t)
		x.set(func() { x.reach = seg8 }) // the expected figure is timeline 1's, not 2's
		if s := sf(x, x.run("latest", 1, "")); s != "null" {
			t.Fatal(s)
		}
		x2 := forked(t)
		x2.set(func() { x2.reach = "000000020000000000000008" })
		if s := sf(x2, x2.run("latest", 2, "")); !sameJSON(s, `{"expected":"000000020000000000000009","reached":"000000020000000000000008","segments":1}`) {
			t.Fatal(s)
		}
	})
	t.Run("no-figure", func(t *testing.T) {
		x := newRx(t)
		x.set(func() { x.newest = map[string]string{} })
		if s := sf(x, x.run("latest", 0, "")); s != `"not checked"` {
			t.Fatal(s)
		}
		if _, ok := x.notice("restore-shortfall"); !ok {
			t.Fatal("no notice")
		}
	})
	t.Run("time-target", func(t *testing.T) {
		x := newRx(t)
		x.set(func() { x.reach = seg2 })
		for _, to := range []string{x.base.Add(90 * time.Minute).Format(time.RFC3339), "lsn:0/7000100"} {
			op := x.run(to, 0, "")
			if s := sf(x, op); s != "null" {
				t.Fatal(to, s)
			}
		}
		if _, ok := x.notice("restore-shortfall"); ok {
			t.Fatal("a notice")
		}
	})
}

func TestRestore_ShortfallWhenTheLastPushPushedNothing(t *testing.T) {
	// An idle spool at T3: the one push pushes nothing and still names the
	// newest segment in the repository.
	x := newRx(t)
	x.set(func() { x.newest, x.reach = map[string]string{"00000001": segA}, seg9 })
	op := x.run("latest", 0, "")
	if len(x.jobs(op.ID, "T4p")) != 1 || !sameJSON(raw(x.result(op.ID), "shortfall"), `{"expected":"`+segA+`","reached":"`+seg9+`","segments":1}`) {
		t.Fatalf("%s %s", op.State, x.e.op(op.ID).Result)
	}
}

func TestRestore_NoServeResultIsReportedNotChecked(t *testing.T) {
	x := newRx(t)
	x.on("T7", "recover", func(int) jobEnd { return jobEnd{state: "done", result: `{"ok":true,"promoted":true,"serve":null}`} })
	op := x.run("latest", 0, "")
	if op.State != "done" || raw(x.result(op.ID), "shortfall") != `"not checked"` {
		t.Fatalf("%s %s", op.State, x.e.op(op.ID).Result)
	}
	if n, ok := x.notice("restore-shortfall"); !ok || !strings.Contains(n.Detail, "not checked") {
		t.Fatalf("notice %+v", n)
	}
}

func TestRestore_FailedStaysRestoringAndDraining(t *testing.T) {
	x := newRx(t)
	x.ag.setErr(failOn("VerifyCluster"))
	op := x.run("latest", 0, "")
	var rt string
	x.ag.locked(func() { rt = x.ag.route[x.ref].State })
	if op.State != "failed" || x.e.project(x.ref).State != "restoring" || rt != "draining" {
		t.Fatalf("%s %s route %s", op.State, x.e.project(x.ref).State, rt)
	}
	for _, s := range []string{"stays restoring", "not served", fmt.Sprintf("op retry %d", op.ID), "project restore " + x.ref,
		"project delete " + x.ref} {
		if !strings.Contains(op.LastError, s) {
			t.Fatalf("last_error %q lacks %q", op.LastError, s)
		}
	}
	// Failed before the wipe: the data directory is said to be unchanged; after it, not.
	if strings.Contains(op.LastError, "unchanged") {
		t.Fatalf("%q", op.LastError)
	}
	x2 := newRx(t)
	x2.on("T4p", "push", func(int) jobEnd { return failEnd("repository") })
	op = x2.run("latest", 0, "")
	if op.State != "failed" || !strings.Contains(op.LastError, "unchanged") || !strings.HasPrefix(op.LastError, "repository:") {
		t.Fatalf("%q", op.LastError)
	}
	// Failed at T6, after the wipe and before any recovery: not unchanged.
	x4 := newRx(t)
	x4.on("T6", "restore", func(int) jobEnd { return failEnd("pgbackrest") })
	op = x4.run("latest", 0, "")
	if op.State != "failed" || strings.Contains(op.LastError, "unchanged") || !strings.Contains(op.LastError, "stays restoring") {
		t.Fatalf("%q", op.LastError)
	}
	// Failed before the project stopped being served: said so.
	x3 := newRx(t)
	id := x3.mustSubmit("latest", 0, "")
	sql(t, `update operation set params = jsonb_set(params, '{to}', '"lsn:0/0"') where id = $1`, id)
	op = x3.finish(id)
	if op.State != "failed" || x3.e.project(x3.ref).State != "active" || !strings.Contains(op.LastError, "still served") {
		t.Fatalf("%+v", op)
	}
}

func TestRestore_RetryContinues(t *testing.T) {
	x := newRx(t)
	x.ag.setErr(failOn("VerifyCluster"))
	op := x.run("latest", 0, "")
	if op.State != "failed" || op.Step != "T8" {
		t.Fatalf("%+v", op)
	}
	x.ag.setErr(nil)
	must(t, x.e.st.RetryOperation(context.Background(), op.ID))
	op = x.e.waitState(op.ID, "done")
	if len(x.jobs(op.ID, "T7")) != 1 || countOf(x.calls(), "Rekey") != 1 || x.e.project(x.ref).State != "active" {
		t.Fatalf("%v %v", x.kinds(op.ID), x.calls())
	}
}

func TestRestore_Superseded(t *testing.T) {
	x := newRx(t)
	x.ag.setErr(failOn("VerifyCluster"))
	op := x.run("latest", 0, "")
	x.ag.setErr(nil)
	id := x.mustSubmit("latest", 0, "")
	old := x.e.op(op.ID)
	if old.State != "superseded" || old.Attempts != op.Attempts {
		t.Fatalf("%+v", old)
	}
	if err := x.e.st.RetryOperation(context.Background(), op.ID); err == nil {
		t.Fatal("a superseded restore was retried")
	}
	if op := x.finish(id); op.State != "done" || x.e.project(x.ref).State != "active" {
		t.Fatalf("%+v", op)
	}
}

// ───────── restore: failpoints, the target, the parameters, T11 ─────────

func TestRestore_FailpointsResume(t *testing.T) {
	for _, s := range restoreIDs {
		t.Run(s, func(t *testing.T) {
			x := newRx(t)
			x.declare()
			id := x.mustSubmit("latest", 0, "offsite")
			x.e.failpoint("restore:" + s)
			<-x.e.run(x.r)
			if op := x.e.op(id); op.State == "done" {
				t.Fatal("the failpoint did not fire")
			}
			x.e.start(x.r)
			if op := x.e.waitState(id, "done"); x.e.project(x.ref).State != "active" || x.slot() != "" {
				t.Fatalf("%+v", op)
			}
		})
	}
}

func TestRestore_T1RendersTheTargetBeforeT5Wipes(t *testing.T) {
	x := newRx(t)
	id := x.mustSubmit("lsn:0/7000100", 0, "")
	sql(t, `update operation set params = jsonb_set(params, '{to}', '"lsn:0/0"') where id = $1`, id)
	op := x.finish(id)
	wantCode(t, op, "failed", "invalid_target")
	if op.Attempts != 1 || slices.Contains(x.calls(), "WipeData") || slices.Contains(x.calls(), "SetRoute") || x.e.project(x.ref).State != "active" {
		t.Fatalf("%+v %v", op, x.calls())
	}
}

func TestRestore_ParamsKeepMembersTheyDoNotOwn(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.on("T7", "recover", func(n int) jobEnd {
		if n == 1 {
			return failEnd("recovery_failed")
		}
		return jobEnd{state: "done", result: recoverRes(seg9)}
	})
	id := x.mustSubmit("latest", 0, "")
	sql(t, `update operation set params = params || '{"requeued":0,"repl_free":{"step":"x","floor":0,"last":0,"n":0},"x_kept":"v"}' where id = $1`, id)
	op := x.finish(id)
	p := x.params(id)
	if op.State != "done" || raw(p, "x_kept") != `"v"` || raw(p, "requeued") != "0" || raw(p, "job_floor") == "" || raw(p, "job_floor") == "0" ||
		!strings.Contains(raw(p, "repl_free"), `"step"`) {
		t.Fatalf("%s %s", op.State, op.Params)
	}
}

func TestRestore_T11RetryTakesADoneRestoreAsFinished(t *testing.T) {
	x := newRx(t)
	id := x.mustSubmit("latest", 0, "")
	x.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "RemoveFetch" { // T11, before its own FinishRestore: an earlier one committed
			if err := x.e.st.FinishRestore(ctx, id, json.RawMessage(`{"to":"latest"}`)); err != nil {
				t.Error(err)
			}
		}
	})
	op := x.finish(id) // done already by the hook's FinishRestore
	// The worker takes it as finished: its summary line, done, and no failure.
	finished := func() bool {
		for _, m := range x.e.logs.records("operation finished") {
			if m["op"] == float64(id) {
				return m["outcome"] == "done"
			}
		}
		return false
	}
	for deadline := time.Now().Add(10 * time.Second); !finished(); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no finished line: %s", x.e.logs.String())
		}
	}
	if op = x.e.op(id); op.State != "done" || op.LastError != "" || len(x.e.logs.records("step failed")) != 0 {
		t.Fatalf("%+v %s", op, x.e.logs.String())
	}
}

// A stored result out of shape — a figure the job's side could steer — is
// never used: the step fails, final, and nothing after it runs.
func TestRestore_OutOfShapeJobResultsAreRefused(t *testing.T) {
	for _, c := range []struct {
		name, step, kind string
		end              jobEnd
		wiped            bool
	}{
		{"newest-of-another-timeline", "T4p", "push", jobEnd{state: "done", result: pushRes(true, map[string]string{"00000002": seg9}, nil)}, false},
		{"newest-not-a-segment", "T4p", "push", jobEnd{state: "done", result: pushRes(true, map[string]string{"00000001": "../" + seg9}, nil)}, false},
		{"history-not-a-history", "T4p", "push", jobEnd{state: "done", result: pushRes(true, map[string]string{"00000001": seg9}, []string{"x.history"})}, false},
		{"restore-mode", "T6", "restore", jobEnd{state: "done", result: `{"ok":true,"mode":"delta"}`}, true},
		{"restore-mode-not-asked", "T6", "restore", jobEnd{state: "done", result: `{"ok":true,"mode":"standby"}`}, true},
		{"serve-segment", "T7", "recover", jobEnd{state: "done", result: recoverRes(`0000000100000000000000\n9`)}, true},
		{"not-promoted", "T7", "recover", jobEnd{state: "done", result: `{"ok":true,"promoted":false,"serve":null}`}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newRx(t)
			x.on(c.step, c.kind, func(int) jobEnd { return c.end })
			op := x.run("latest", 0, "")
			wantCode(t, op, "failed", "internal")
			if op.Attempts != 1 || slices.Contains(x.calls(), "WipeData") != c.wiped || slices.Contains(x.calls(), "Rekey") {
				t.Fatalf("%+v %v", op, x.calls())
			}
		})
	}
}

// A cancelled job is not counted by its end, so the rewind it causes counts
// the attempt: cancelled for ever, the restore fails after five recover jobs
// with the job's code, instead of rewinding without a bound; four, and it
// completes.
func TestRestore_RewindAfterACancelledJobCostsAnAttempt(t *testing.T) {
	for _, c := range []struct {
		cancelled int
		state     string
	}{{4, "done"}, {100, "failed"}} {
		t.Run(c.state, func(t *testing.T) {
			x := newRx(t)
			x.on("T7", "recover", func(n int) jobEnd {
				if n <= c.cancelled {
					return failEnd("cancelled")
				}
				return jobEnd{state: "done", result: recoverRes(seg9)}
			})
			op := x.run("latest", 0, "")
			if op.State != c.state || len(x.jobs(op.ID, "T7")) != min(c.cancelled+1, 5) {
				t.Fatalf("%+v %v", op, x.kinds(op.ID))
			}
			if c.state == "failed" {
				wantCode(t, op, "failed", "cancelled")
			}
		})
	}
}

// ───────── fix round: the submit's refusals of what T4p and T4r cannot pass ─────────

func TestRestoreSubmit_RepositoryQuotaFullRefused(t *testing.T) {
	x := newRx(t)
	sql(t, "update backup_state set repo_used_kb = 8388606, repo_hard_kb = 8388608 where subject = $1", x.ref)
	_, err := x.submit("latest", 0, "")
	wantConflict(t, err, "repository quota full; restart the project with a larger quota first")
	if len(x.restoreOps()) != 0 {
		t.Fatal("submitted")
	}
	sql(t, "update backup_state set repo_used_kb = 1024 where subject = $1", x.ref)
	x.mustSubmit("latest", 0, "")
}

func TestRestoreSubmit_ReplicationPausedRefused(t *testing.T) {
	x := newRx(t)
	x.declare()
	must(t, x.e.st.PauseReplication(context.Background(), x.ref, time.Now().Add(time.Hour)))
	_, err := x.submit("latest", 0, "")
	wantConflict(t, err, "replication is paused for the project's daily upload budget until")
	// Not declared: no replication runs, nothing to wait for.
	x.e.jobs.offsite.Store("undeclared")
	id := x.mustSubmit("latest", 0, "")
	sql(t, "update operation set state = 'failed' where id = $1", id)
	// A pause that has ended does not refuse.
	x.e.jobs.offsite.Store("declared")
	sql(t, "update backup_state set repl_paused_until = now() - interval '1 minute' where subject = $1", x.ref)
	x.mustSubmit("latest", 0, "")
}

// The seeding is recorded before the seed runs: a seed that fails part-way
// leaves older sets off-site only.
func TestRestore_SeedingRecordedBeforeTheSeedRuns(t *testing.T) {
	x := newRx(t)
	x.declare()
	var at *time.Time
	x.on("T5b", "seed", func(int) jobEnd {
		bs, err := x.e.st.GetBackupState(context.Background(), x.ref)
		if err == nil {
			at = bs.SeededAt
		}
		return failEnd("seed")
	})
	op := x.run("latest", 0, "offsite")
	x.set(func() {})
	if op.State != "failed" || at == nil {
		t.Fatalf("%s seeded_at at the seed %v", op.State, at)
	}
	// A restore of a set older than the seed now defaults to off-site.
	id := x.mustSubmit(x.base.Add(time.Hour).Format(time.RFC3339), 0, "")
	if raw(x.params(id), "from") != `"offsite"` {
		t.Fatalf("%s", x.e.op(id).Params)
	}
}

// A check or backup of the restored cluster refused for a tablespace or a
// link is final: the restored data holds it, no retry changes it.
func TestRestore_RestoredTablespaceFailsTheCheckAtOnce(t *testing.T) {
	for _, step := range []struct{ id, kind, code string }{{"T10c", "check", "tablespace"}, {"T10b", "backup", "symlink"}} {
		t.Run(step.id, func(t *testing.T) {
			x := newRx(t)
			x.on(step.id, step.kind, func(int) jobEnd { return failEnd(step.code) })
			op := x.run("latest", 0, "")
			wantCode(t, op, "failed", step.code)
			if len(x.jobs(op.ID, step.id)) != 1 || !strings.Contains(op.LastError, "restore to a target before it") {
				t.Fatalf("%v %q", x.kinds(op.ID), op.LastError)
			}
		})
	}
}

// The source switched by a refusal: the failure text keeps that first cause.
func TestRestore_FailureNoteKeepsTheFirstCause(t *testing.T) {
	x := newRx(t)
	x.on("T6", "restore", func(int) jobEnd { return failEnd("history_mismatch") })
	op := x.run("latest", 0, "")
	for _, s := range []string{"(read from the off-site store because the repository's history does not lead to the target (history_mismatch))", "replaced by this restore",
		"--to latest --timeline 1"} {
		if !strings.Contains(op.LastError, s) {
			t.Fatalf("%q lacks %q", op.LastError, s)
		}
	}
}

// A skipped replication (the runner's own skip) is no copy: the fetch waits
// for one that ran.
func TestRestore_SkippedCopyIsNotACopyOfThePass(t *testing.T) {
	x := newRx(t)
	x.declare()
	x.on("T4r", "replicate", func(n int) jobEnd {
		if n == 1 {
			return jobEnd{state: "done", result: `{"skipped":"undeclared"}`}
		}
		return replDone
	})
	op := x.run("latest", 0, "offsite")
	k := x.kinds(op.ID)
	// The skipped one is followed by a copy that ran, and only then the fetch.
	if i := slices.Index(k, "T5a/fetch"); op.State != "done" || i < 1 || k[i-1] != "T4r/replicate" || len(x.jobs(op.ID, "T4r")) < 2 {
		t.Fatalf("%s %v", op.State, k)
	}
}

// A second restore after a failed first one on a replaced node: T1 made the
// directory, the node still has no state file — the second is replaced too.
func TestRestore_Replaced_SecondRestoreSkipsTheLocalSteps(t *testing.T) {
	x := replacedRx(t)
	x.on("T5a", "fetch", func(int) jobEnd { return failEnd("fetch_too_large") })
	first := x.run("latest", 0, "")
	wantCode(t, first, "failed", "fetch_too_large")
	x.set(func() { x.onJob = nil })
	x.ag.reset()
	id := x.mustSubmit("latest", 0, "")
	op := x.finish(id)
	if op.State != "done" || raw(x.params(id), "replaced") != "true" {
		t.Fatalf("%+v", op)
	}
	c := x.calls()
	i := slices.Index(c, "job:T7:recover")
	if slices.Contains(c[:i], "WipeData") || slices.Contains(c[:i], "job:T4p:push") {
		t.Fatalf("the local steps ran: %v", c[:i])
	}
}

// The standby retry targets the timeline followed — the newest recorded when
// none is named, here 2.
func TestRestore_StandbyTargetsTheNewestRecordedTimeline(t *testing.T) {
	x := newRx(t)
	x.recordedBy(2, 0)
	must(t, x.e.st.RecordSet(context.Background(), store.BackupSet{Subject: x.ref, Label: x.base.Add(150*time.Minute).Format("20060102-150405") + "F",
		TLI: 2, StartSegment: "000000020000000000000008", StopSegment: "000000020000000000000009", StartLSN: "0/8000028", StopLSN: "0/9000100",
		StartAt: x.base.Add(140 * time.Minute), StopAt: x.base.Add(150 * time.Minute), JobID: x.bjob}))
	x.set(func() {
		x.hist = []string{"00000002.history"}
		x.newest = map[string]string{"00000001": seg8, "00000002": "000000020000000000000009"}
		x.reach = "000000020000000000000009"
	})
	x.on("T6", "restore", func(n int) jobEnd {
		if n == 1 {
			return failEnd("history_mismatch")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"standby"}`}
	})
	op := x.run("latest", 0, "")
	if op.State != "done" || fmt.Sprint(modes(x, op.ID)) != "[none 0 standby 2]" {
		t.Fatalf("%s %v", op.State, modes(x, op.ID))
	}
}

// A pass that is off-site and not seeded when T6 is entered (a stop between a
// rewind's floor write and its step write) fetches and seeds first: the
// restore job never reads the local repository for an off-site source.
func TestRestore_OffsiteWithoutASeedGoesBackToTheFetch(t *testing.T) {
	x := newRx(t)
	x.declare()
	id := x.mustSubmit("latest", 0, "")
	sql(t, `update operation set step = 'T5', params = params || '{"from":"offsite","t7_started":false}' where id = $1`, id)
	sql(t, "update project set state = 'restoring' where ref = $1", x.ref) // T2 ran
	op := x.finish(id)
	k := x.kinds(id)
	if op.State != "done" || slices.Index(k, "T5b/seed") < 0 || slices.Index(k, "T5b/seed") > slices.Index(k, "T6/restore") {
		t.Fatalf("%s %v %q", op.State, k, op.LastError)
	}
}

// ───────── fix round 2 ─────────

// A failed push that found the repository full refuses the restore, as the
// quota report does; a push done after it lifts it.
func TestRestoreSubmit_RepositoryFullByTheNewestPushRefused(t *testing.T) {
	x := newRx(t)
	full := true
	x.on("", "push", func(int) jobEnd {
		if full {
			return failEnd("repository_quota")
		}
		return jobEnd{state: "done", result: pushRes(true, x.newest, nil)}
	})
	push := func() {
		t.Helper()
		id, err := x.e.st.SubmitJob(context.Background(), store.NewJob{Subject: x.ref, Lane: "push", Kind: "push", DeadlineS: 60})
		must(t, err)
		for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(2 * time.Millisecond) {
			if j, ok, _ := x.e.st.LastJob(context.Background(), x.ref, "push"); ok && j.ID == id && (j.State == "done" || j.State == "failed") {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("the push did not end")
			}
		}
	}
	push()
	_, err := x.submit("latest", 0, "")
	wantConflict(t, err, "repository quota full")
	x.set(func() { full = false })
	push()
	x.mustSubmit("latest", 0, "")
}

// On a node that never started the project the repository figure is not
// this node's: a replaced node's restore is not refused for it.
func TestRestoreSubmit_RepositoryFigureIgnoredOnAReplacedNode(t *testing.T) {
	x := replacedRx(t)
	sql(t, "update backup_state set repo_used_kb = 8388606, repo_hard_kb = 8388608 where subject = $1", x.ref)
	if id := x.mustSubmit("latest", 0, ""); raw(x.params(id), "from") != `"offsite"` {
		t.Fatalf("%s", x.e.op(id).Params)
	}
}

// completeCopy is true for a done copy that ended complete, and for nothing
// else the runner can store at a replicate step.
func TestCompleteCopy(t *testing.T) {
	copyDone := `{"ok":true,"mode":"copy","complete":true,"stopped":"","uploaded":1,"adopted":0}`
	for _, c := range []struct {
		state, result string
		want          bool
	}{
		{"done", copyDone, true},
		{"failed", copyDone, false},
		{"done", `{"ok":true,"mode":"copy","complete":false,"stopped":"caps","uploaded":1,"adopted":0}`, false},
		{"done", `{"ok":true,"mode":"copy","complete":true,"stopped":"held","uploaded":1,"adopted":0}`, false},
		{"done", `{"ok":true,"mode":"rebuild","complete":true,"stopped":"","rows":12}`, false},
		{"done", `{"ok":true,"mode":"copy","complete":true,"stopped":"","skipped":"undeclared"}`, false},
		{"done", `{"skipped":"undeclared"}`, false},
		{"done", `{"ok":true,"complete":true,"stopped":""}`, false},
		{"done", `not json`, false},
	} {
		if got := completeCopy(store.Job{State: c.state, Result: json.RawMessage(c.result)}); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.state, c.result, got, c.want)
		}
	}
}

// The stop after a re-key is bounded by what is left of the step's deadline:
// a re-key that ran out of time does not hold the worker two minutes more.
func TestRestore_StopAfterTheRekeyWithinTheStepDeadline(t *testing.T) {
	x := newRx(t)
	x.r.stepDeadline = 2 * time.Second
	x.set(func() {
		x.rekey = func(ctx context.Context, s agent.Spec, pending int) (int, error) {
			<-ctx.Done() // the re-key runs out of the step's time
			return 0, ctx.Err()
		}
	})
	var left []time.Duration
	x.ag.setHook(func(ctx context.Context, c call) {
		if c.Method == "StopCluster" {
			if dl, ok := ctx.Deadline(); ok {
				l := time.Until(dl)
				x.set(func() { left = append(left, l) })
			}
		}
	})
	id := x.mustSubmit("latest", 0, "")
	x.e.start(x.r)
	x.e.wait(id, "re-keyed twice", func(op store.Operation) bool { return len(x.jobs(id, "T7")) >= 2 })
	x.set(func() {
		if len(left) < 3 { // T3, T8's stop, T3 again
			t.Fatalf("stops %v", left)
		}
		if l := left[1]; l > 10*time.Second {
			t.Fatalf("T8's stop may take %s", l)
		}
	})
}
