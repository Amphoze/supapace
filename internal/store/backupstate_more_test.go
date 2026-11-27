package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
)

// A row rebuilt from a listing that gave no version id has no stored version:
// an adoption that reports none proves nothing about which version it read,
// so the hash is not filled and offsite-differs is raised.
func TestRecordUploads_AnUnknownVersionIDNeverAdopts(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	k := bsSegKey(st, "17-1", bsSeg(1, 1))
	must(t, s.MergeListing(ctx, r, ListingPage{Launch: 1, Rows: []ObjectRow{{Key: k, Size: 10, UploadedAt: bsT0}}, Last: true}, 2))
	bsUpload(t, s, r, Uploads{Launch: 1, Rows: []ObjectRow{{Key: k, Size: 10, SHA256: bsHash(0xaa), Ino: 1, CtimeNS: 2, UploadedAt: bsT0}}, At: bsT0})
	if got, _, _ := bsObject(t, s, r, k); got.SHA256 != nil {
		t.Fatalf("an adoption without a version id filled the hash of a row without one: %+v", got)
	}
	if _, ok := bsNotice(t, s, r, "offsite-differs"); !ok {
		t.Fatal("no offsite-differs notice")
	}
}

// Adoptions of one row racing each other and a listing page: one hash is
// kept, and nothing raises offsite-differs (every report names the stored
// version id).
func TestRecordUploads_ConcurrentAdoptionsKeepOneHashAndRaiseNothing(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	const rounds, writers = 20, 6
	var keys []string
	for i := 0; i < rounds; i++ {
		keys = append(keys, bsSegKey(st, "17-1", bsSeg(1, i+1)))
	}
	var listed []ObjectRow
	for _, k := range keys {
		listed = append(listed, ObjectRow{Key: k, Size: 10, VersionID: "v1", UploadedAt: bsT0})
	}
	must(t, s.MergeListing(ctx, r, ListingPage{Launch: 1, Rows: listed, NextKeyMarker: keys[rounds-1]}, 2))
	for i, k := range keys {
		var wg sync.WaitGroup
		errs := make(chan error, writers+1)
		start := make(chan struct{})
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				<-start
				_, err := s.RecordUploads(ctx, r, Uploads{Launch: 1, Rows: []ObjectRow{{Key: k, Size: 10, SHA256: bsHash(byte(w + 1)),
					Ino: int64(w), CtimeNS: 1, VersionID: "v1", UploadedAt: bsT0}}, At: bsT0})
				errs <- err
			}(w)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.MergeListing(ctx, r, ListingPage{Launch: 1, Rows: []ObjectRow{{Key: k, Size: 10, VersionID: "v1", UploadedAt: bsT0}},
				NextKeyMarker: k, NextVersionMarker: fmt.Sprint(i)}, 2)
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			must(t, err)
		}
		got, _, _ := bsObject(t, s, r, k)
		if len(got.SHA256) != 32 || !bytes.Equal(got.SHA256, bsHash(got.SHA256[0])) || got.Ino != int64(got.SHA256[0]-1) ||
			got.VersionID != "v1" {
			t.Fatalf("round %d: row = %+v", i, got)
		}
	}
	if n, ok := bsNotice(t, s, r, "offsite-differs"); ok {
		t.Fatalf("concurrent adoptions of the stored version raised %+v", n)
	}
}

// ObjectRows streams in byte order of the key, whatever the database's
// collation: a listing may hold any key.
func TestObjectRows_ByteOrderOfTheKey(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	want := []string{"B", "a", "a-b", "a.b", "ab", "z", "é"} // byte order
	var rows []ObjectRow
	for i := len(want) - 1; i >= 0; i-- {
		rows = append(rows, ObjectRow{Key: want[i], Size: 1, VersionID: "v", UploadedAt: time.Unix(0, 0)})
	}
	must(t, s.MergeListing(ctx, r, ListingPage{Launch: 1, Rows: rows, NextKeyMarker: "k"}, 2))
	var got []string
	must(t, s.ObjectRows(ctx, r, func(o ObjectRow) error { got = append(got, o.Key); return nil }))
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order = %q, want %q", got, want)
	}
}

// A replication that completed at the very time of the upload counts ("at or
// after").
func TestSegmentReplicated_ACompleteReplicationAtTheUploadTimeCounts(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	seg := bsSeg(1, 1)
	bsUpload(t, s, r, Uploads{Launch: 1, Rows: []ObjectRow{bsRow(bsSegKey(st, "17-1", seg), 1, "v", bsT0)}, Complete: true, At: bsT0})
	if ok, err := s.SegmentReplicated(ctx, r, seg); err != nil || !ok {
		t.Fatalf("SegmentReplicated = %v, %v", ok, err)
	}
}

// A job whose time lies on an earlier UTC day than the stored budget day
// neither moves the day back nor lets the next job reset today's counters.
func TestRecordUploads_AnEarlierDayNeverMovesTheBudgetDayBack(t *testing.T) {
	s := newStore(t, testConfig())
	r, st := bsProject(t, s, 1)
	day2 := bsT0.Add(24 * time.Hour)
	for i, at := range []time.Time{day2, bsT0, day2} {
		bsUpload(t, s, r, Uploads{Launch: 1, Rows: []ObjectRow{bsRow(bsSegKey(st, "17-1", bsSeg(1, i+1)), 1, "v", at)}, At: at})
	}
	if b := bsState(t, s, r); b.ObjectsToday != 3 || b.BudgetDay.Format(time.DateOnly) != "2026-11-11" {
		t.Fatalf("%d objects, day %v", b.ObjectsToday, b.BudgetDay)
	}
}

// Info versions uploaded by this job list a complete set even when their own
// time is before the set's stop (the job's clock against the backup's).
func TestRecordUploads_InfoInTheSameJobListsTheSet(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	job := addJob(t, s, r, 0, "done")
	must(t, s.RecordSet(ctx, BackupSet{Subject: r, Label: "20261110-130000F", TLI: 1, StartSegment: bsSeg(1, 1),
		StopSegment: bsSeg(1, 2), StartLSN: "0/1000000", StopLSN: "0/2000000", StartAt: bsT0, StopAt: bsT0.Add(time.Hour), JobID: job}))
	at := bsT0.Add(2 * time.Hour)
	bsUpload(t, s, r, Uploads{Launch: 1, SetsComplete: []string{"20261110-130000F"}, At: at,
		Info: []InfoVersion{{Name: "backup.info", VersionID: "i1", SHA256: bsHash(1), UploadedAt: bsT0}}})
	sets, err := s.ListSets(ctx, r)
	must(t, err)
	if len(sets) != 1 || !sets[0].Replicated {
		t.Fatalf("sets = %+v", sets)
	}
	timeIs(t, "listed_at", sets[0].ListedAt, at)
}

// bsRebuildAt gives subject's row an unfinished rebuild: its markers and page count.
func bsRebuildAt(t *testing.T, s *Store, subject, key, version string, pages int) {
	t.Helper()
	sqlExec(t, s, `update backup_state set rebuild_key_marker = $2, rebuild_version_marker = $3, rebuild_pages = $4
		where subject = $1`, subject, key, version, pages)
}

// bsRowText is every column of subject's backup_state row, as text.
func bsRowText(t *testing.T, s *Store, subject string) string {
	t.Helper()
	var row string
	must(t, s.pool.QueryRow(context.Background(), "select b::text from backup_state b where subject = $1", subject).Scan(&row))
	return row
}

func TestEnterNewEpoch_RestartsAnyRebuildFromTheFirstPage(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r1, _ := bsProject(t, s, 1)
	r2, _ := bsProject(t, s, 2)
	must(t, s.EnsureBackupState(ctx, "cp"))
	// As restored: an earlier rebuild was under way for two subjects.
	bsRebuildAt(t, s, r1, "archive/x/17-1/0000000100000000/k", "v7", 3)
	bsRebuildAt(t, s, "cp", "backup/cp-1/backup.info", "v2", bklimit.RebuildMaxPages)
	untouched := bsRowText(t, s, r2)

	// The clearing is part of the one transaction: a failure of its last
	// statement leaves the markers as they were.
	sqlExec(t, s, `create function sp_fail() returns trigger language plpgsql as $$ begin raise exception 'forced'; end $$`)
	sqlExec(t, s, "create trigger sp_fail before update of slot_op on project for each statement execute function sp_fail()")
	if _, err := s.EnterNewEpoch(ctx, 0); err == nil {
		t.Fatal("the forced failure did not fail the call")
	}
	if b := bsState(t, s, r1); b.RebuildKeyMarker == "" || b.RebuildVersionMarker != "v7" || b.RebuildPages != 3 {
		t.Fatalf("a failed transaction changed the markers: %+v", b)
	}
	sqlExec(t, s, "drop trigger sp_fail on project")

	epoch, err := s.EnterNewEpoch(ctx, 0)
	must(t, err)
	for _, subject := range []string{r1, "cp"} {
		b := bsState(t, s, subject)
		if b.RebuildKeyMarker != "" || b.RebuildVersionMarker != "" || b.RebuildPages != 0 {
			t.Fatalf("%s after the new epoch: markers %q %q, pages %d", subject, b.RebuildKeyMarker, b.RebuildVersionMarker, b.RebuildPages)
		}
		if b.RebuildEpoch >= epoch {
			t.Fatalf("%s: rebuild_epoch %d is not below the new epoch %d", subject, b.RebuildEpoch, epoch)
		}
	}
	if got := bsRowText(t, s, r2); got != untouched {
		t.Fatalf("a row without a rebuild changed:\n%s\n%s", untouched, got)
	}
}

func TestContinueRebuild_ResetsOnlyTheCountOfASubjectAtTheCap(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r1, _ := bsProject(t, s, 1)
	r2, _ := bsProject(t, s, 2)
	const cap = 8
	bsRebuildAt(t, s, r1, "k1", "v1", cap+3)
	bsRebuildAt(t, s, r2, "k2", "v2", cap+3)
	other := bsRowText(t, s, r2)
	before := bsState(t, s, r1)

	pages, err := s.ContinueRebuild(ctx, r1, cap)
	must(t, err)
	if pages != cap+3 {
		t.Fatalf("pages replaced %d, want %d", pages, cap+3)
	}
	after := bsState(t, s, r1)
	if after.RebuildPages != 0 {
		t.Fatalf("pages %d after the reset", after.RebuildPages)
	}
	after.RebuildPages = before.RebuildPages
	if fmt.Sprintf("%+v", after) != fmt.Sprintf("%+v", before) {
		t.Fatalf("another column changed:\n%+v\n%+v", before, after)
	}
	if got := bsRowText(t, s, r2); got != other {
		t.Fatalf("another subject's row changed:\n%s\n%s", other, got)
	}
	// Reset once: the subject is no longer at the cap.
	if _, err := s.ContinueRebuild(ctx, r1, cap); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second reset: %v", err)
	}
}

func TestContinueRebuild_Refusals(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	const cap = 8
	refused := func(what, subject string, want error) {
		t.Helper()
		before := ""
		if want != ErrNotFound {
			before = bsRowText(t, s, subject)
		}
		if n, err := s.ContinueRebuild(ctx, subject, cap); !errors.Is(err, want) || n != 0 {
			t.Fatalf("%s: %d, %v; want %v", what, n, err, want)
		}
		if want != ErrNotFound && bsRowText(t, s, subject) != before {
			t.Fatalf("%s: the row changed", what)
		}
	}
	bsRebuildAt(t, s, r, "k", "v", cap-1)
	refused("one page below the cap", r, ErrConflict)
	// At the cap, but the record is rebuilt for the epoch: nothing is stuck.
	bsRebuildAt(t, s, r, "k", "v", cap)
	sqlExec(t, s, "update backup_state set rebuild_epoch = (select epoch from cp_meta) where subject = $1", r)
	refused("a record already rebuilt", r, ErrConflict)
	refused("an unknown subject", ref(9), ErrNotFound)
	// Control: the same row, its record behind the epoch, is reset.
	sqlExec(t, s, "update backup_state set rebuild_epoch = 0 where subject = $1", r)
	if n, err := s.ContinueRebuild(ctx, r, cap); err != nil || n != cap {
		t.Fatalf("control: %d, %v", n, err)
	}
	if _, err := s.ContinueRebuild(ctx, r, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("a cap of 0 must never match: %v", err)
	}
}
