package backup

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/store"
)

// A rebuild page recorded with a job row that carries no launch number is
// refused by the store: crashed, nothing merged, the markers unchanged.
func TestRebuild_APageWithoutALaunchNumberIsCrashed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ref := e.project("active")
	st := ref + "-1"
	page := jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", NextKeyMarker: "m1",
		Rows: []jobio.Row{{Key: segKey(st, 1, 3), Size: 1, VersionID: "a", At: time.Now()}}}
	j := store.Job{ID: 1, Subject: ref, Kind: "replicate"}
	if _, err := recordReplicateJob(ctx, e.r, j, page); !errors.Is(err, store.ErrNoLaunch) {
		t.Fatalf("a page without a launch number: %v", err)
	}
	bs, err := e.st.GetBackupState(ctx, ref)
	must(t, err)
	if e.count("select count(*) from offsite_object where subject = $1", ref) != 0 || bs.RebuildKeyMarker != "" || bs.RebuildPages != 0 {
		t.Fatalf("written without a launch number: state %+v", bs)
	}
	// Control: the same page with a number is merged.
	j.Launch = 7
	if _, err := recordReplicateJob(ctx, e.r, j, page); err != nil {
		t.Fatal(err)
	}
	var n int64
	must(t, e.db.QueryRow(ctx, "select launch from offsite_object where subject = $1", ref).Scan(&n))
	if n != 7 {
		t.Fatalf("launch %d, want 7", n)
	}
}

// An index file whose line count is right but which the job could not read
// (left 0600 by a stop between the two mode changes of an append) is made
// 0444 again at the next launch.
func TestIndex_AFileOfAnotherModeIsRebuilt(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ref := e.project("active")
	e.object(ref, segKey(ref+"-1", 1, 3), 10, h32(1), "v1", time.Now())
	_, err := e.r.ensureIndex(ctx, ref)
	must(t, err)
	path := e.p.IndexFile(ref)
	must(t, os.Chmod(path, 0o600))
	_, err = e.r.ensureIndex(ctx, ref)
	must(t, err)
	if fi, err := os.Lstat(path); err != nil || fi.Mode().Perm() != 0o444 {
		t.Fatalf("index mode %v (%v), want 0444", fi.Mode(), err)
	}
}

// A FIFO at the index path never blocks a launch: it is replaced.
func TestIndex_AFIFOAtThePathDoesNotBlock(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ref := e.project("active")
	path := e.p.IndexFile(ref)
	must(t, os.MkdirAll(filepath.Dir(path), 0o700))
	must(t, syscall.Mkfifo(path, 0o600))
	done := make(chan error, 1)
	go func() { _, err := e.r.ensureIndex(ctx, ref); done <- err }()
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(10 * time.Second):
		// Unblock the reader so the goroutine ends.
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
		<-done
		t.Fatal("ensureIndex blocked on a FIFO")
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("index %v (%v), want a regular file", fi.Mode(), err)
	}
}

// Sizes the record holds without a bound (rows rebuilt from a listing) cannot
// wrap the plan's sum below the quota.
func TestPlan_SizesThatWouldOverflowAreTooLarge(t *testing.T) {
	e := newEnv(t)
	ref, st := e.plannedProject()
	e.object(ref, setKey(st, planSet, "pg_data/base/1"), math.MaxInt64/2+1, nil, "a", listed)
	e.object(ref, setKey(st, planSet, "pg_data/base/2"), math.MaxInt64/2+1, nil, "b", listed)
	if _, err := e.planOf(ref, planSet, "latest", 0, nil); codeOf(err) != "fetch_too_large" {
		t.Fatalf("plan above the quota by wrap-around: %v", err)
	}
}

// While the record is rebuilt page by page the index file is not rewritten
// at every launch (the rebuild job does not read it; the last page rebuilds
// it): the cost would grow with the square of the page count.
func TestRebuild_PagesDoNotRewriteTheIndexEachLaunch(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	keys := make([]string, 3*4000+1)
	for i := range keys {
		keys[i] = segKey(ref+"-1", 1, uint32(i+1))
	}
	var inputs []jobio.ReplInput
	e.pager(keys, &inputs)
	ino := func() uint64 {
		fi, err := os.Lstat(e.p.IndexFile(ref))
		must(t, err)
		return fi.Sys().(*syscall.Stat_t).Ino
	}
	e.replicate(ref)
	first := ino()
	e.replicate(ref)
	e.replicate(ref)
	if got := ino(); got != first {
		t.Fatalf("the index file was rewritten during the rebuild (inode %d → %d)", first, got)
	}
}

// The times a copy reports are not used: its rows and info versions are
// recorded at the record's own time, so a result cannot move a file or an
// info version out of (or into) a restore's plan by its clock.
func TestRecordReplicate_TimesAreTheRecordsOwn(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	far := e.clock.Now().Add(1000 * time.Hour).UTC()
	up := row(segKey(ref+"-1", 1, 4), 1, 1)
	up.At = far
	v := copyResult(up)
	v.Info = []jobio.InfoVersion{{Name: "backup.info", VersionID: "iv", SHA256: sum(9), At: far}}
	e.replicateWith(v)
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("job %+v", got)
	}
	var at time.Time
	must(t, e.db.QueryRow(ctx, "select uploaded_at from offsite_object where subject = $1", ref).Scan(&at))
	vs, err := e.st.ListInfoVersions(ctx, ref, 1)
	must(t, err)
	now := e.clock.Now()
	if at.Sub(now).Abs() > time.Millisecond || len(vs) != 1 || vs[0].UploadedAt.Sub(now).Abs() > time.Millisecond {
		t.Fatalf("row at %v, info %+v, want the record's time %v", at, vs, e.clock.Now())
	}
}

// A budget already overspent today (an override lowered during the day) is
// handed to the copy as none left, never as a negative figure: -1 means no
// budget at all.
func TestReplication_AnOverspentBudgetIsNoneLeft(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	_, err := e.db.Exec(ctx, "update backup_state set budget_day = $2::date, bytes_today = 1125899906842624, objects_today = 1 << 30 where subject = $1",
		ref, e.clock.Now().UTC().Format(time.DateOnly))
	must(t, err)
	e.replicateWith(copyResult())
	e.replicate(ref)
	if in := e.lastInput(); in.Repl.BudgetBytes != 0 || in.Repl.BudgetObjects != 0 {
		t.Fatalf("budget left %d bytes, %d objects", in.Repl.BudgetBytes, in.Repl.BudgetObjects)
	}
}

// The next copy is handed each info file's newest recorded hash.
func TestReplication_InfoHashIsTheNewestVersions(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref, _ := e.plannedProject()
	e.infoVersion(ref, "backup.info", "old", 1, listed.Add(-time.Hour))
	e.infoVersion(ref, "backup.info", "new", 2, listed)
	_, err := e.db.Exec(context.Background(), "update project set state = 'active' where ref = $1", ref)
	must(t, err)
	e.replicateWith(copyResult())
	e.replicate(ref)
	if in := e.lastInput(); in.Repl.InfoSHA256["backup.info"] != sum(2) {
		t.Fatalf("info hash %q, want the newest version's", in.Repl.InfoSHA256["backup.info"])
	}
}

// A fetch result is recorded only against the plan built for that job: an
// entry left by an earlier job of the subject is no plan of this one.
func TestFetchRecord_APlanOfAnotherJobIsNone(t *testing.T) {
	e := newEnv(t)
	ref := e.project("restoring")
	plans.Lock()
	plans.m[plannedKey{e.r, ref}] = planned{job: 41, files: 9, maxBytes: 1 << 30, histories: []string{"00000002.history"}}
	plans.Unlock()
	j := store.Job{ID: 42, Subject: ref, Kind: "fetch", Launch: 1}
	if _, err := recordFetchJob(context.Background(), e.r, j, jobio.FetchResult{OK: true, Files: 1, Bytes: 1}); err == nil {
		t.Fatal("recorded against another job's plan")
	}
	plans.Lock()
	_, kept := plans.m[plannedKey{e.r, ref}]
	plans.Unlock()
	if !kept {
		t.Fatal("another job's plan was dropped")
	}
}
