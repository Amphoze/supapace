package backup

import (
	"context"
	"testing"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/store"
)

// rebuildAt gives subject's record an unfinished rebuild.
func (e *env) rebuildAt(subject, key, version string, pages int) {
	e.t.Helper()
	_, err := e.db.Exec(context.Background(), `update backup_state set rebuild_key_marker = $2, rebuild_version_marker = $3,
		rebuild_pages = $4 where subject = $1`, subject, key, version, pages)
	must(e.t, err)
}

// pageAlert is subject's open alert of the page cap, nil when there is none.
func (e *env) pageAlert(subject string) *store.Alert {
	e.t.Helper()
	as, err := e.st.OpenAlerts(context.Background(), subject)
	must(e.t, err)
	for _, a := range as {
		if a.Code == "rebuild-page-cap" {
			return &a
		}
	}
	return nil
}

func TestRebuild_PastThePageCapRaisesANoticeAndLaunchesNothing(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	// Control, one page below the cap: a job is launched, nothing is raised.
	e.rebuildAt(ref, "k", "v", bklimit.RebuildMaxPages-1)
	e.replicateWith(jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", NextKeyMarker: "l"})
	if got := e.replicate(ref); got.State != "done" || len(e.ag.specs) != 1 {
		t.Fatalf("below the cap: job %+v, launches %d", got, len(e.ag.specs))
	}
	if e.notices(ref, "rebuild-page-cap") != 0 || e.pageAlert(ref) != nil {
		t.Fatal("raised below the cap")
	}
	// That page was the cap's last: the next launch is refused.
	if got := e.replicate(ref); got.State != "failed" || got.Code != "internal" || len(e.ag.specs) != 1 {
		t.Fatalf("at the cap: job %+v, launches %d", got, len(e.ag.specs))
	}
	ns, err := e.st.ListNotices(context.Background(), ref)
	must(t, err)
	if len(ns) != 1 || ns[0].Code != "rebuild-page-cap" || ns[0].Detail != "2048 pages merged" {
		t.Fatalf("notices %+v", ns)
	}
	a := e.pageAlert(ref)
	if a == nil || a.Severity != "page" || len(a.Figures) != 1 || a.Figures["pages"] != bklimit.RebuildMaxPages {
		t.Fatalf("alert %+v", a)
	}
	// The markers are kept for the continuation.
	if bs := e.state(ref); bs.RebuildKeyMarker != "l" || bs.RebuildPages != bklimit.RebuildMaxPages {
		t.Fatalf("state %+v", bs)
	}

	// The guarded reset is the way on: the next job lists from the stored markers.
	if _, err := e.st.ContinueRebuild(context.Background(), ref, bklimit.RebuildMaxPages); err != nil {
		t.Fatal(err)
	}
	e.replicateWith(jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", NextKeyMarker: "m"})
	if got := e.replicate(ref); got.State != "done" || len(e.ag.specs) != 2 {
		t.Fatalf("after the reset: job %+v, launches %d", got, len(e.ag.specs))
	}
	if in := e.lastInput(); in.Repl == nil || in.Repl.Mode != "rebuild" || in.Repl.KeyMarker != "l" {
		t.Fatalf("the continued rebuild's input %+v", in.Repl)
	}
}

func TestEnterNewEpoch_RestartsAnyRebuildFromTheFirstPage(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	// As restored from a backup taken while a rebuild was under way.
	e.rebuildAt(ref, "archive/"+ref+"-1/17-1/0000000100000000/x", "v9", 7)
	// Control: without a new epoch the next page starts at those markers.
	e.replicateWith(jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", NextKeyMarker: "b"})
	e.replicate(ref)
	if in := e.lastInput(); in.Repl == nil || in.Repl.KeyMarker == "" || in.Repl.VersionMarker != "v9" {
		t.Fatalf("control: input %+v", in.Repl)
	}
	if _, err := e.st.EnterNewEpoch(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if bs := e.state(ref); bs.RebuildKeyMarker != "" || bs.RebuildVersionMarker != "" || bs.RebuildPages != 0 {
		t.Fatalf("state after the new epoch %+v", bs)
	}
	e.replicateWith(jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", NextKeyMarker: "a"})
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("job %+v", got)
	}
	if in := e.lastInput(); in.Repl == nil || in.Repl.Mode != "rebuild" || in.Repl.KeyMarker != "" || in.Repl.VersionMarker != "" {
		t.Fatalf("the new epoch's first page starts at %+v", in.Repl)
	}
}
