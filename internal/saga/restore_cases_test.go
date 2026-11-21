package saga

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/store"
)

// targetTimeline is the timeline the newest recover job of id was given.
func targetTimeline(x *rx, id int64) string {
	js := x.jobs(id, "T7")
	if len(js) == 0 {
		return ""
	}
	t, _ := js[len(js)-1].Params["target"].(map[string]any)
	return fmt.Sprint(t["timeline"])
}

// An end-of-archive restore follows the timeline the operator named, and
// without one the newest recorded timeline: with "latest" the server follows
// the newest history the archive holds, whoever made it.
func TestRestore_EndOfArchiveFollowsTheTimelineAsked(t *testing.T) {
	t.Run("named", func(t *testing.T) {
		x := forked(t)
		op := x.run("latest", 1, "")
		if got := targetTimeline(x, op.ID); op.State != "done" || got != "1" {
			t.Fatalf("%s: the recovery follows timeline %q, want 1", op.State, got)
		}
	})
	t.Run("newest-recorded", func(t *testing.T) {
		// Timeline 2 is a branch no restore finished (its history is held).
		x := newRx(t)
		x.timeline(2, "abandoned", 0)
		x.set(func() { x.hist = []string{"00000002.history"} })
		op := x.run("latest", 0, "")
		if got := targetTimeline(x, op.ID); op.State != "done" || got != "1" {
			t.Fatalf("%s: the recovery follows timeline %q, want 1", op.State, got)
		}
	})
}

// A refusal 58 caused by a branch no restore finished: the set lies on the
// timeline followed, so the one standby retry applies; the off-site store
// holds the same history and would refuse alike.
func TestRestore_RefusalOverAnUnrecordedBranchUsesStandby(t *testing.T) {
	x := newRx(t)
	x.timeline(2, "abandoned", 0)
	x.set(func() { x.hist = []string{"00000002.history"} })
	x.on("T6", "restore", func(n int) jobEnd {
		if n == 1 {
			return failEnd("history_mismatch")
		}
		return jobEnd{state: "done", result: `{"ok":true,"mode":"standby"}`}
	})
	op := x.run("latest", 0, "")
	if op.State != "done" || fmt.Sprint(modes(x, op.ID)) != "[none 0 standby 1]" {
		t.Fatalf("%s %q: restore jobs %v", op.State, op.LastError, modes(x, op.ID))
	}
}

// op retry of a restore that failed at T4r raises the job floor above its
// T4p push: the step must not wait for a push of this pass that no step
// will submit.
func TestRestore_OpRetryAtT4rContinues(t *testing.T) {
	x := newRx(t)
	x.declare()
	stopped := true
	x.on("T4r", "replicate", func(int) jobEnd {
		if stopped {
			return jobEnd{state: "done", result: `{"ok":true,"mode":"copy","complete":false,"stopped":"budget","uploaded":0,"adopted":0}`}
		}
		return replDone
	})
	op := x.run("latest", 0, "")
	wantCode(t, op, "failed", "replication_stopped")
	if op.Step != "T4p" {
		t.Fatalf("failed after %s", op.Step)
	}
	x.set(func() { stopped = false })
	must(t, x.e.st.RetryOperation(context.Background(), op.ID))
	op = x.e.wait(op.ID, "ended", func(op store.Operation) bool { return op.State == "done" || op.State == "failed" })
	if op.State != "done" {
		t.Fatalf("after op retry: %s %q", op.State, op.LastError)
	}
}

// A node that holds nothing of the project stays so until a recovery has
// started there: a restore that follows a failed one must not take the
// directories the first one made for a repository.
func TestRestore_Replaced_ARestoreAfterAFailedOneIsStillOffsite(t *testing.T) {
	x := replacedRx(t)
	x.on("T5a", "fetch", func(int) jobEnd { return failEnd("fetch_too_large") })
	op := x.run("latest", 0, "")
	wantCode(t, op, "failed", "fetch_too_large")
	x.set(func() { x.onJob = nil })
	id := x.mustSubmit("latest", 0, "")
	if from := raw(x.params(id), "from"); from != `"offsite"` {
		t.Fatalf("the second restore reads from %s: the node's repository is empty", from)
	}
	op = x.finish(id)
	if op.State != "done" || !slices.Contains(x.kinds(id), "T5a/fetch") {
		t.Fatalf("%s %q %v", op.State, op.LastError, x.kinds(id))
	}
}

// A set that records a tablespace or a link is refused by every restore job
// alike: one job, not five wipes.
func TestRestore_TablespaceSetFailsAtOnce(t *testing.T) {
	x := newRx(t)
	x.on("T6", "restore", func(int) jobEnd { return failEnd("tablespace") })
	op := x.run("latest", 0, "")
	wantCode(t, op, "failed", "tablespace")
	if n := len(x.jobs(op.ID, "T6")); n != 1 || countOf(x.calls(), "WipeData") != 1 {
		t.Fatalf("%d restore jobs, calls %v", n, x.calls())
	}
}

// After the wipe the failure note never says the data directory is unchanged,
// whichever step the restore went back to.
func TestRestore_FailureNoteAfterAWipeAndARewind(t *testing.T) {
	x := newRx(t) // the off-site store is not declared
	x.on("T6", "restore", func(int) jobEnd { return failEnd("history_mismatch") })
	op := x.run("latest", 0, "")
	if op.State != "failed" || countOf(x.calls(), "WipeData") == 0 {
		t.Fatalf("%+v %v", op, x.calls())
	}
	if strings.Contains(op.LastError, "unchanged") {
		t.Fatalf("the data directory was wiped: %q", op.LastError)
	}
}

// A restore that ends failed at T8 leaves no recovery start running: it is
// promoted and holds the restored passwords.
func TestRestore_FailedAtT8StopsTheRecoveryStart(t *testing.T) {
	x := newRx(t)
	x.set(func() {
		x.rekey = func(context.Context, agent.Spec, int) (int, error) {
			return 0, fmt.Errorf("re-key refused in the test")
		}
	})
	op := x.run("latest", 0, "")
	if op.State != "failed" {
		t.Fatalf("%+v", op)
	}
	c := x.calls()
	if i := lastIndexOf(c, "Rekey"); i < 0 || !slices.Contains(c[i:], "StopCluster") {
		t.Fatalf("nothing stopped the recovery start after the last re-key: %v", c)
	}
}

// The newest set on the lineage of the timeline followed: a set taken on an
// older timeline after the point the followed one left it does not lead to
// it, and the restore job refuses it only after the wipe.
func TestRestoreSubmit_ASetAfterTheForkIsNotOnTheLineage(t *testing.T) {
	x := newRx(t)
	// A restore to a time between the second and the third set records
	// timeline 2 and fails before its own full backup.
	x.on("T10b", "backup", func(int) jobEnd { return failEnd("pgbackrest") })
	op := x.run(x.base.Add(90*time.Minute).Format(time.RFC3339), 0, "")
	if op.State != "failed" || x.timelines()[2].State != "recorded" {
		t.Fatalf("%+v %+v", op, x.timelines())
	}
	x.set(func() { x.onJob = nil })
	id := x.mustSubmit("latest", 0, "")
	if set := raw(x.params(id), "set"); set != `"`+x.sets[1]+`"` {
		t.Fatalf("set %s, want %q: the third set lies on timeline 1 after timeline 2 left it", set, x.sets[1])
	}
}

// The seed empties the project's repository: it may run only after a copy
// of the same pass ended complete. Here the store's declaration is not whole
// while T4r runs (no copy), the repository's histories send the restore
// off-site, and the declaration is completed before the retry: the local archive that was
// never copied must not be emptied on the strength of an older copy.
func TestRestore_SeedOnlyAfterACopyOfThisPass(t *testing.T) {
	x := newRx(t)
	x.declare() // the sets were replicated and listed earlier
	x.e.jobs.offsite.Store("partial")
	x.timeline(2, "abandoned", 0)
	x.set(func() { x.hist = []string{} }) // the repository lacks its history: off-site at T4r
	op := x.run("latest", 0, "")
	wantCode(t, op, "failed", "offsite_not_declared")
	if slices.Contains(x.calls(), "job:T4r:replicate") || slices.Contains(x.calls(), "job:T5b:seed") {
		t.Fatalf("calls %v", x.calls())
	}
	x.e.jobs.offsite.Store("declared")
	must(t, x.e.st.RetryOperation(context.Background(), op.ID))
	op = x.e.wait(op.ID, "ended", func(op store.Operation) bool { return op.State == "done" || op.State == "failed" })
	c := x.calls()
	if i := slices.Index(c, "job:T5b:seed"); i >= 0 && !slices.Contains(c[:i], "job:T4r:replicate") {
		t.Fatalf("the repository was emptied by a seed with no copy of this pass before it: %v", c)
	}
	if op.State != "done" {
		t.Fatalf("%s %q", op.State, op.LastError)
	}
}
