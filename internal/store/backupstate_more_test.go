package store

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
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
