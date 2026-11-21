package saga

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/store"
)

// A crash between a decision's write and the rewind's first write: the step
// is entered again with the same failed job and repeats the decision it
// stored, instead of deciding a second time on the members it has changed.
func TestRestore_StoredDecisionIsRepeatedNotTakenAgain(t *testing.T) {
	x := forked(t)
	stop := x.e.start(x.r)
	x.on("T6", "restore", func(n int) jobEnd {
		if n == 1 {
			stop() // the daemon ends before the worker sees the failed job
			return failEnd("history_mismatch")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"standby"}`}
	})
	id := x.mustSubmit(x.base.Add(90*time.Minute).Format(time.RFC3339), 1, "")
	// Pending after T5 is the failed restore job's doing alone: T6 parks in the attempt that completes T5.
	op := x.e.wait(id, "back in the queue after its restore job", func(op store.Operation) bool { return op.State == "pending" && op.Step == "T5" })
	if js := x.jobs(id, "T6"); len(js) != 1 || js[0].State != "failed" {
		t.Fatalf("%+v %+v", op, js)
	}
	// What the step wrote before the rewind it then did not reach.
	sql(t, `update operation set params = params || jsonb_build_object('standby_tried', true, 'decided', jsonb_build_object('job', $2::bigint, 'to', 'T5'))
		where id = $1`, id, x.jobs(id, "T6")[0].ID)
	op = x.finish(id)
	if op.State != "done" || fmt.Sprint(modes(x, id)) != "[none 0 standby 1]" || slices.Contains(x.kinds(id), "T5a/fetch") {
		t.Fatalf("%s %q: restore jobs %v, jobs %v", op.State, op.LastError, modes(x, id), x.kinds(id))
	}
}

// The source switches to the off-site store after the wipe: a set that is
// not recorded as replicated and listed ends the restore there, final.
func TestRestore_SourceSwitchNeedsTheSetOffsite(t *testing.T) {
	x := newRx(t)
	x.e.jobs.offsite.Store("declared") // declared, the sets not replicated
	x.on("T6", "restore", func(int) jobEnd { return failEnd("history_mismatch") })
	op := x.run("latest", 0, "")
	wantCode(t, op, "failed", "set_not_offsite")
	if slices.Contains(x.kinds(op.ID), "T5a/fetch") {
		t.Fatalf("%+v %v", op, x.kinds(op.ID))
	}
}

// The histories a seed leaves are the fetch's stored ones: a name that is
// not a history, or more names than the bound, is never held.
func TestRestore_OutOfShapeFetchAndPushListsAreRefused(t *testing.T) {
	t.Run("fetch-history", func(t *testing.T) {
		x := newRx(t)
		x.declare()
		x.set(func() { x.fetchH = []string{"000000010000000000000002"} })
		op := x.run("latest", 0, "offsite")
		wantCode(t, op, "failed", "internal")
		if slices.Contains(x.calls(), "WipeData") {
			t.Fatalf("wiped: %v", x.calls())
		}
	})
	t.Run("push-newest-count", func(t *testing.T) {
		x := newRx(t)
		many := map[string]string{}
		for i := 1; i <= 65; i++ {
			many[fmt.Sprintf("%08X", i)] = fmt.Sprintf("%08X0000000000000009", i)
		}
		x.set(func() { x.newest = many })
		op := x.run("latest", 0, "")
		wantCode(t, op, "failed", "internal")
		if slices.Contains(x.calls(), "WipeData") {
			t.Fatalf("wiped: %v", x.calls())
		}
	})
}

// op retry of a restore that failed at the seed raises the job floor above
// its fetch: the step goes back for a fresh one instead of holding a list
// no fetch of this pass stored.
func TestRestore_OpRetryAtT5bFetchesAgain(t *testing.T) {
	x := newRx(t)
	x.declare()
	bad := true
	x.on("T5b", "seed", func(int) jobEnd {
		if bad {
			return failEnd("seed")
		}
		return okEnd
	})
	op := x.run("latest", 0, "offsite")
	wantCode(t, op, "failed", "seed")
	x.set(func() { bad = false })
	must(t, x.e.st.RetryOperation(context.Background(), op.ID))
	op = x.e.wait(op.ID, "ended", func(op store.Operation) bool { return op.State == "done" || op.State == "failed" })
	if op.State != "done" || len(x.jobs(op.ID, "T5a")) != 2 {
		t.Fatalf("%s %q %v", op.State, op.LastError, x.kinds(op.ID))
	}
	c := x.calls()
	if i := lastIndexOf(c, "job:T5a:fetch"); i < 0 || !slices.Contains(c[i:], "job:T5b:seed") || slices.Contains(c[:i], "WipeData") {
		t.Fatalf("order %v", c)
	}
}

func lastIndexOf(seq []string, s string) int {
	for i := len(seq) - 1; i >= 0; i-- {
		if seq[i] == s {
			return i
		}
	}
	return -1
}

// A recovery that was handed no segment at all replayed nothing of the
// archive: the shortfall counts from the set's start segment.
func TestRestore_ShortfallWhenNothingWasServed(t *testing.T) {
	x := newRx(t)
	x.set(func() { x.reach = "" })
	op := x.run("latest", 0, "")
	// The set starts at segment 6, the repository holds through 9: 6, 7, 8, 9.
	if op.State != "done" || !sameJSON(raw(x.result(op.ID), "shortfall"), `{"expected":"`+seg9+`","reached":"","segments":4}`) {
		t.Fatalf("%s %s", op.State, x.e.op(op.ID).Result)
	}
}

// A wipe that fails may have removed part of the data directory: the failure
// note does not call it unchanged.
func TestRestore_FailureNoteWhenTheWipeFails(t *testing.T) {
	x := newRx(t)
	x.ag.setErr(failOn("WipeData"))
	op := x.run("latest", 0, "")
	if op.State != "failed" || op.Step != "T5b" || !strings.Contains(op.LastError, "stays restoring") || strings.Contains(op.LastError, "unchanged") {
		t.Fatalf("%+v", op)
	}
}

// A restore that a refusal sends to the off-site store, with no store
// declared, ends there: nothing is fetched and it does not go round.
func TestRestore_SourceSwitchNeedsTheStoreDeclared(t *testing.T) {
	x := newRx(t)
	x.on("T6", "restore", func(int) jobEnd { return failEnd("history_mismatch") })
	op := x.run("latest", 0, "")
	wantCode(t, op, "failed", "offsite_not_declared")
	if slices.Contains(x.kinds(op.ID), "T5a/fetch") || len(x.jobs(op.ID, "T6")) > 2 {
		t.Fatalf("%v", x.kinds(op.ID))
	}
}

// The standby retry is for a set that lies on the timeline named: a set of
// an older timeline goes to the off-site store instead.
func TestRestore_NoStandbyForASetOfAnotherTimeline(t *testing.T) {
	x := forked(t) // timelines 1 and 2 recorded, the sets on 1
	x.declare()
	x.timeline(3, "recorded", 0)
	x.set(func() {
		x.hist = []string{"00000002.history", "00000003.history"}
		x.fetchH = x.hist
	})
	x.on("T6", "restore", func(n int) jobEnd {
		if n == 1 {
			return failEnd("history_mismatch")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"none"}`}
	})
	op := x.run(x.base.Add(90*time.Minute).Format(time.RFC3339), 2, "")
	if op.State != "done" || fmt.Sprint(modes(x, op.ID)) != "[none 0 none 0]" || !slices.Contains(x.kinds(op.ID), "T5a/fetch") {
		t.Fatalf("%s %q: restore jobs %v, jobs %v", op.State, op.LastError, modes(x, op.ID), x.kinds(op.ID))
	}
}

// Parameters out of their bounds are refused with a fixed text, whoever calls.
func TestSubmitRestore_ParametersOutOfBoundsRefused(t *testing.T) {
	x := newRx(t)
	for _, c := range []struct {
		to       string
		timeline int
		from     string
	}{{"latest", -1, ""}, {"latest", 1 << 31, ""}, {"latest", 0, "elsewhere"}} {
		_, err := x.submit(c.to, c.timeline, c.from)
		wantConflict(t, err, "restore parameters")
	}
	if len(x.restoreOps()) != 0 {
		t.Fatal("submitted")
	}
}
