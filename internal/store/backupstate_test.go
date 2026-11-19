package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
)

var bsT0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// bsProject returns an active project with its backup state row and its
// stanza created (timeline 1 recorded), and the project's stanza.
func bsProject(t *testing.T, s *Store, n int) (r, stanza string) {
	t.Helper()
	r = newActive(t, s, n)
	must(t, s.EnsureBackupState(context.Background(), r))
	must(t, s.MarkStanza(context.Background(), r))
	return r, r + "-1"
}

// bsOp inserts an operation of r as a restore's id stands in the timeline rows.
func bsOp(t *testing.T, s *Store, r string) int64 {
	t.Helper()
	var id int64
	must(t, s.pool.QueryRow(context.Background(), `insert into operation (ref, kind, state, epoch, generation)
		values ($1, 'restore', 'running', 1, 1) returning id`, r).Scan(&id))
	return id
}

func bsSeg(tli, n int) string { return fmt.Sprintf("%08X%016X", tli, n) }

func bsSegKey(stanza, arch, seg string) string {
	return fmt.Sprintf("archive/%s/%s/%s/%s-%040x.zst", stanza, arch, seg[:16], seg, 7)
}

func bsHistKey(stanza, arch string, tli int) string {
	return fmt.Sprintf("archive/%s/%s/%08X.history", stanza, arch, tli)
}

func bsHash(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func bsRow(key string, h byte, ver string, at time.Time) ObjectRow {
	return ObjectRow{Key: key, Size: 10, SHA256: bsHash(h), Ino: 11, CtimeNS: 12, VersionID: ver, UploadedAt: at}
}

func bsUpload(t *testing.T, s *Store, subject string, u Uploads) bool {
	t.Helper()
	over, err := s.RecordUploads(context.Background(), subject, u)
	must(t, err)
	return over
}

// bsObject reads one record row as stored; ok is false when absent.
func bsObject(t *testing.T, s *Store, subject, key string) (r ObjectRow, seen int64, ok bool) {
	t.Helper()
	err := s.pool.QueryRow(context.Background(), `select key, size, sha256, coalesce(ino, 0), coalesce(ctime_ns, 0),
		coalesce(version_id, ''), uploaded_at, seen_epoch from offsite_object where subject = $1 and key = $2`, subject, key).
		Scan(&r.Key, &r.Size, &r.SHA256, &r.Ino, &r.CtimeNS, &r.VersionID, &r.UploadedAt, &seen)
	if errors.Is(wrap(err), ErrNotFound) {
		return r, 0, false
	}
	must(t, err)
	return r, seen, true
}

func bsState(t *testing.T, s *Store, subject string) BackupState {
	t.Helper()
	b, err := s.GetBackupState(context.Background(), subject)
	must(t, err)
	return b
}

func bsNotice(t *testing.T, s *Store, subject, code string) (Notice, bool) {
	t.Helper()
	ns, err := s.ListNotices(context.Background(), subject)
	must(t, err)
	for _, n := range ns {
		if n.Code == code {
			return n, true
		}
	}
	return Notice{}, false
}

func bsTimelines(t *testing.T, s *Store, subject string) string {
	t.Helper()
	ts, err := s.Timelines(context.Background(), subject)
	must(t, err)
	var b strings.Builder
	for _, tl := range ts {
		fmt.Fprintf(&b, "%d:%s:%d ", tl.TLI, tl.State, tl.OpID)
	}
	return strings.TrimSpace(b.String())
}

func wantTimelines(t *testing.T, s *Store, subject, want string) {
	t.Helper()
	if got := bsTimelines(t, s, subject); got != want {
		t.Fatalf("timelines = %q, want %q", got, want)
	}
}

func timeIs(t *testing.T, what string, got *time.Time, want time.Time) {
	t.Helper()
	if got == nil || !got.Equal(want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

// --- push records and notices ---

func TestRecordPush_LagOnlyWhenComplete(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	oldest := bsT0.Add(-time.Hour)
	must(t, s.RecordPush(ctx, r, PushRecord{Complete: false, Pushed: 3, SpoolEntries: 7, SpoolBytes: 700, SpoolOldest: &oldest, At: bsT0}))
	b := bsState(t, s, r)
	if b.LastPushOK != nil {
		t.Fatalf("an incomplete push set last_push_ok to %v", b.LastPushOK)
	}
	if b.SpoolEntries == nil || *b.SpoolEntries != 7 || b.SpoolBytes == nil || *b.SpoolBytes != 700 {
		t.Fatalf("spool figures not stored: %+v", b)
	}
	timeIs(t, "spool_oldest", b.SpoolOldest, oldest)

	t2 := bsT0.Add(time.Minute)
	must(t, s.RecordPush(ctx, r, PushRecord{Complete: true, NewestSegment: bsSeg(1, 4), At: t2}))
	b = bsState(t, s, r)
	timeIs(t, "last_push_ok", b.LastPushOK, t2)
	if b.NewestSegment != bsSeg(1, 4) || b.SpoolEntries == nil || *b.SpoolEntries != 0 || b.SpoolOldest != nil {
		t.Fatalf("complete push: %+v", b)
	}

	must(t, s.RecordPush(ctx, r, PushRecord{Complete: false, At: t2.Add(time.Minute)}))
	b = bsState(t, s, r)
	timeIs(t, "last_push_ok after an incomplete push", b.LastPushOK, t2)
	if b.NewestSegment != bsSeg(1, 4) {
		t.Fatalf("a push without a newest segment cleared it: %q", b.NewestSegment)
	}
}

func TestRecordPush_GapAndNotice(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	must(t, s.RecordPush(ctx, r, PushRecord{Complete: true, At: bsT0}))
	if gaps, _, err := s.ListGaps(ctx, r); err != nil || len(gaps) != 0 {
		t.Fatalf("a push without gaps recorded %v (%v)", gaps, err)
	}
	if _, ok := bsNotice(t, s, r, "quarantine"); ok {
		t.Fatal("a push without gaps raised a notice")
	}
	g1 := Gap{Cause: "quarantine", First: bsSeg(1, 2), Last: bsSeg(1, 2), Detail: "timeline"}
	g2 := Gap{Cause: "quarantine", First: bsSeg(1, 5), Last: bsSeg(1, 6), Detail: "shape"}
	must(t, s.RecordPush(ctx, r, PushRecord{Complete: true, Gaps: []Gap{g1}, At: bsT0.Add(time.Minute)}))
	must(t, s.RecordPush(ctx, r, PushRecord{Complete: true, Gaps: []Gap{g2}, At: bsT0.Add(2 * time.Minute)}))
	gaps, ats, err := s.ListGaps(ctx, r)
	must(t, err)
	if len(gaps) != 2 || gaps[0] != g2 || gaps[1] != g1 || !ats[0].Equal(bsT0.Add(2*time.Minute)) {
		t.Fatalf("gaps = %+v at %v, want newest first", gaps, ats)
	}
	n, ok := bsNotice(t, s, r, "quarantine")
	if !ok || n.Count != 2 || n.Detail != "shape" {
		t.Fatalf("quarantine notice = %+v, %v", n, ok)
	}

	// A name the push quarantined for its shape is stored cleaned and bounded.
	hostile := Gap{Cause: "quarantine", First: "\x00\x1b" + strings.Repeat("x", 300), Last: "\xff", Detail: strings.Repeat("d", 300)}
	must(t, s.RecordPush(ctx, r, PushRecord{Gaps: []Gap{hostile}, At: bsT0.Add(3 * time.Minute)}))
	gaps, _, _ = s.ListGaps(ctx, r)
	if g := gaps[0]; g.First != strings.Repeat("x", 256) || g.Last != "" || len(g.Detail) != 256 {
		t.Fatalf("hostile gap stored as %q %q %d", g.First, g.Last, len(g.Detail))
	}

	for i := 0; i < 70; i++ {
		must(t, s.RecordPush(ctx, r, PushRecord{Gaps: []Gap{g1}, At: bsT0}))
	}
	if gaps, ats, _ := s.ListGaps(ctx, r); len(gaps) != 64 || len(ats) != 64 {
		t.Fatalf("ListGaps returned %d, want the newest 64", len(gaps))
	}
}

func TestRecordPush_RefusesAnotherCauseAndAMalformedSegment(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	for _, p := range []PushRecord{
		{Complete: true, Gaps: []Gap{{Cause: "spool-drop", First: bsSeg(1, 1), Last: bsSeg(1, 1)}}, At: bsT0},
		{Complete: true, NewestSegment: bsSeg(1, 1) + "\n", At: bsT0},
		{Complete: true, NewestSegment: strings.ToLower(bsSeg(10, 10)), At: bsT0},
	} {
		if err := s.RecordPush(ctx, r, p); err == nil {
			t.Fatalf("RecordPush(%+v) accepted", p)
		}
	}
	if b := bsState(t, s, r); b.LastPushOK != nil || b.NewestSegment != "" || count(t, s, "select count(*) from backup_gap") != 0 {
		t.Fatalf("a refused push wrote: %+v", b)
	}
	// Control: the same push without the fault is recorded.
	must(t, s.RecordPush(ctx, r, PushRecord{Complete: true, NewestSegment: bsSeg(10, 10), At: bsT0}))
	wantErr(t, s.RecordPush(ctx, ref(99), PushRecord{At: bsT0}), ErrNotFound)
}

func TestRecordPush_StoresQuotaUse(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	must(t, s.RecordPush(ctx, r, PushRecord{Complete: true, At: bsT0}))
	if b := bsState(t, s, r); b.QuotaAt != nil || b.DiskUsedKB != nil {
		t.Fatalf("a push without a quota report stored one: %+v", b)
	}
	q := QuotaUse{DiskUsedKB: 1, DiskHardKB: 2, RepoUsedKB: 3, RepoHardKB: 4}
	t2 := bsT0.Add(time.Minute)
	must(t, s.RecordPush(ctx, r, PushRecord{Quota: &q, At: t2}))
	check := func() {
		t.Helper()
		b := bsState(t, s, r)
		timeIs(t, "quota_at", b.QuotaAt, t2)
		if b.DiskUsedKB == nil || *b.DiskUsedKB != 1 || *b.DiskHardKB != 2 || *b.RepoUsedKB != 3 || *b.RepoHardKB != 4 {
			t.Fatalf("quota = %v %v %v %v", b.DiskUsedKB, b.DiskHardKB, b.RepoUsedKB, b.RepoHardKB)
		}
	}
	check()
	must(t, s.RecordPush(ctx, r, PushRecord{At: t2.Add(time.Minute)}))
	check() // a later push without a report keeps the last one
}

func TestNotice_UpsertCounts(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	must(t, s.Notice(ctx, r, "unlisted-entry", "first"))
	first, _ := bsNotice(t, s, r, "unlisted-entry")
	must(t, s.Notice(ctx, r, "unlisted-entry", "second"))
	must(t, s.Notice(ctx, r, "unlisted-entry", "third\x00\x1b[31m"+strings.Repeat("é", 200)))
	must(t, s.Notice(ctx, r, "walk-truncated", ""))
	n, _ := bsNotice(t, s, r, "unlisted-entry")
	if n.Count != 3 || !n.FirstAt.Equal(first.FirstAt) || n.LastAt.Before(n.FirstAt) {
		t.Fatalf("notice = %+v, first %+v", n, first)
	}
	if !strings.HasPrefix(n.Detail, "third[31m") || len(n.Detail) > 256 || strings.ContainsAny(n.Detail, "\x00\x1b") {
		t.Fatalf("detail not bounded and cleaned: %q (%d bytes)", n.Detail, len(n.Detail))
	}
	if w, ok := bsNotice(t, s, r, "walk-truncated"); !ok || w.Count != 1 {
		t.Fatalf("second code = %+v", w)
	}
	if c := count(t, s, "select count(*) from backup_notice where subject = $1", r); c != 2 {
		t.Fatalf("%d notice rows, want one per code", c)
	}
	wantErr(t, s.Notice(ctx, ref(99), "unlisted-entry", ""), ErrNotFound)
}

// --- the uploaded-key record ---

func TestRecordUploads_BudgetDayRollover(t *testing.T) {
	s := newStore(t, testConfig())
	r, st := bsProject(t, s, 1)
	rows := func(n int) []ObjectRow {
		var out []ObjectRow
		for i := 0; i < 2; i++ {
			out = append(out, bsRow(bsSegKey(st, "17-1", bsSeg(1, n+i)), 1, "v", bsT0))
		}
		return out
	}
	bsUpload(t, s, r, Uploads{Rows: rows(1), At: bsT0})
	bsUpload(t, s, r, Uploads{Rows: rows(3), At: bsT0.Add(11 * time.Hour)}) // 23:00 UTC, same day
	b := bsState(t, s, r)
	if b.BytesToday != 40 || b.ObjectsToday != 4 || b.BudgetDay == nil || b.BudgetDay.Format(time.DateOnly) != "2026-11-10" {
		t.Fatalf("same day: %d bytes, %d objects, day %v", b.BytesToday, b.ObjectsToday, b.BudgetDay)
	}
	// 00:30 on the next UTC day, given in another zone: the counters start again.
	next := time.Date(2026, 11, 11, 0, 30, 0, 0, time.UTC).In(time.FixedZone("west", -5*3600))
	bsUpload(t, s, r, Uploads{Rows: rows(5)[:1], At: next})
	b = bsState(t, s, r)
	if b.BytesToday != 10 || b.ObjectsToday != 1 || b.BudgetDay.Format(time.DateOnly) != "2026-11-11" {
		t.Fatalf("next day: %d bytes, %d objects, day %v", b.BytesToday, b.ObjectsToday, b.BudgetDay)
	}
}

func TestRecordUploads_OverBudgetReported(t *testing.T) {
	s := newStore(t, testConfig())
	r, st := bsProject(t, s, 1)
	row := func(n int) ObjectRow { return bsRow(bsSegKey(st, "17-1", bsSeg(1, n)), 1, "v", bsT0) }
	if bsUpload(t, s, r, Uploads{Rows: []ObjectRow{row(1), row(2)}, BudgetBytes: 20, BudgetObjects: 2, At: bsT0}) {
		t.Fatal("reaching the budget exactly reported over budget")
	}
	if !bsUpload(t, s, r, Uploads{Rows: []ObjectRow{row(3)}, BudgetBytes: 25, At: bsT0}) {
		t.Fatal("30 bytes against 25 not reported")
	}
	if !bsUpload(t, s, r, Uploads{BudgetObjects: 2, At: bsT0}) {
		t.Fatal("3 objects against 2 not reported")
	}
	if bsUpload(t, s, r, Uploads{Rows: []ObjectRow{row(4)}, At: bsT0}) {
		t.Fatal("budgets of 0 reported over budget")
	}
	if bsUpload(t, s, r, Uploads{BudgetBytes: 1 << 40, BudgetObjects: 1 << 20, At: bsT0}) {
		t.Fatal("under both budgets reported over budget")
	}
}

func TestRecordUploads_DuplicateKeyKeepsFirst(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	k := bsSegKey(st, "17-1", bsSeg(1, 1))
	first := bsRow(k, 0xaa, "v1", bsT0)
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{first}, At: bsT0})
	// The same version id and another one, other hashes, inodes, sizes, times.
	for _, ver := range []string{"v1", "v2", ""} {
		again := ObjectRow{Key: k, Size: 99, SHA256: bsHash(0xbb), Ino: 77, CtimeNS: 78, VersionID: ver, UploadedAt: bsT0.Add(time.Hour)}
		bsUpload(t, s, r, Uploads{Rows: []ObjectRow{again}, At: bsT0.Add(time.Hour)})
	}
	got, _, _ := bsObject(t, s, r, k)
	if !bytes.Equal(got.SHA256, first.SHA256) || got.Size != 10 || got.Ino != 11 || got.CtimeNS != 12 || got.VersionID != "v1" ||
		!got.UploadedAt.Equal(bsT0) {
		t.Fatalf("a row with a hash changed: %+v", got)
	}
	if _, ok := bsNotice(t, s, r, "offsite-differs"); ok {
		t.Fatal("a conflict with a row that has a hash raised a notice")
	}
	// Twice in one call: the first is recorded.
	k2 := bsSegKey(st, "17-1", bsSeg(1, 2))
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(k2, 0x01, "a", bsT0), bsRow(k2, 0x02, "b", bsT0)}, At: bsT0})
	if got, _, _ := bsObject(t, s, r, k2); !bytes.Equal(got.SHA256, bsHash(0x01)) || got.VersionID != "a" {
		t.Fatalf("a key twice in one call recorded %+v", got)
	}
	if n, _ := s.ObjectCount(ctx, r); n != 2 {
		t.Fatalf("ObjectCount = %d", n)
	}
}

func TestRecordUploads_ARepeatedInfoVersionIsOneRow(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	v := InfoVersion{Name: "backup.info", VersionID: "ver-1", SHA256: bsHash(1), UploadedAt: bsT0}
	other := v
	other.SHA256, other.UploadedAt = bsHash(2), bsT0.Add(time.Hour)
	bsUpload(t, s, r, Uploads{Info: []InfoVersion{v, v}, At: bsT0})
	bsUpload(t, s, r, Uploads{Info: []InfoVersion{other}, At: bsT0.Add(time.Hour)})
	vs, err := s.ListInfoVersions(ctx, r, 16)
	must(t, err)
	if len(vs) != 1 || !bytes.Equal(vs[0].SHA256, v.SHA256) || !vs[0].UploadedAt.Equal(bsT0) {
		t.Fatalf("info versions = %+v, want the first one only", vs)
	}
	// Control: another version id is another row; newest first, at most limit.
	bsUpload(t, s, r, Uploads{Info: []InfoVersion{{Name: "backup.info", VersionID: "ver-2", SHA256: bsHash(3), UploadedAt: bsT0.Add(2 * time.Hour)}}, At: bsT0})
	vs, _ = s.ListInfoVersions(ctx, r, 16)
	if len(vs) != 2 || vs[0].VersionID != "ver-2" {
		t.Fatalf("info versions = %+v", vs)
	}
	if vs, _ = s.ListInfoVersions(ctx, r, 1); len(vs) != 1 {
		t.Fatalf("limit 1 returned %d", len(vs))
	}
}

func TestRecordUploads_ListedAtOnlyWithInfo(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	job := addJob(t, s, r, 0, "done")
	set := func(label string, stop time.Time) {
		must(t, s.RecordSet(ctx, BackupSet{Subject: r, Label: label, TLI: 1, StartSegment: bsSeg(1, 1), StopSegment: bsSeg(1, 2),
			StartLSN: "0/1000000", StopLSN: "0/2000000", StartAt: stop.Add(-time.Minute), StopAt: stop, JobID: job}))
	}
	get := func(label string) BackupSet {
		sets, err := s.ListSets(ctx, r)
		must(t, err)
		for _, b := range sets {
			if b.Label == label {
				return b
			}
		}
		t.Fatalf("set %s not found", label)
		return BackupSet{}
	}
	set("20261110-110000F", bsT0.Add(-time.Hour))
	bsUpload(t, s, r, Uploads{SetsComplete: []string{"20261110-110000F"}, At: bsT0})
	if b := get("20261110-110000F"); !b.Replicated || b.ListedAt != nil {
		t.Fatalf("without info: %+v", b)
	}
	t1 := bsT0.Add(time.Minute)
	bsUpload(t, s, r, Uploads{SetsComplete: []string{"20261110-110000F"}, At: t1,
		Info: []InfoVersion{{Name: "backup.info", VersionID: "i1", SHA256: bsHash(1), UploadedAt: t1}}})
	timeIs(t, "listed_at with info", get("20261110-110000F").ListedAt, t1)

	// An info version already at or after the set's stop lists it; one before does not.
	set("20261110-115900F", t1.Add(-time.Second))
	set("20261110-130000F", bsT0.Add(time.Hour))
	t2 := bsT0.Add(2 * time.Minute)
	bsUpload(t, s, r, Uploads{SetsComplete: []string{"20261110-115900F", "20261110-130000F"}, At: t2})
	timeIs(t, "listed_at from an earlier info version", get("20261110-115900F").ListedAt, t2)
	if b := get("20261110-130000F"); !b.Replicated || b.ListedAt != nil {
		t.Fatalf("a set newer than every info version: %+v", b)
	}
	// archive.info lists no set: a version of it after the stop does not count;
	// a backup.info.copy version does.
	late := bsT0.Add(2 * time.Hour)
	bsUpload(t, s, r, Uploads{At: late, Info: []InfoVersion{{Name: "archive.info", VersionID: "a1", SHA256: bsHash(3), UploadedAt: late}}})
	bsUpload(t, s, r, Uploads{SetsComplete: []string{"20261110-130000F"}, At: late.Add(time.Minute)})
	if b := get("20261110-130000F"); b.ListedAt != nil {
		t.Fatalf("an archive.info version listed a set: %+v", b)
	}
	bsUpload(t, s, r, Uploads{At: late, Info: []InfoVersion{{Name: "backup.info.copy", VersionID: "c1", SHA256: bsHash(4), UploadedAt: late}}})
	bsUpload(t, s, r, Uploads{SetsComplete: []string{"20261110-130000F"}, At: late.Add(2 * time.Minute)})
	timeIs(t, "listed_at from a backup.info.copy version", get("20261110-130000F").ListedAt, late.Add(2*time.Minute))
	// Once set, listed_at stays.
	bsUpload(t, s, r, Uploads{SetsComplete: []string{"20261110-110000F"}, At: t2.Add(time.Hour),
		Info: []InfoVersion{{Name: "backup.info", VersionID: "i2", SHA256: bsHash(2), UploadedAt: t2.Add(time.Hour)}}})
	timeIs(t, "listed_at after a later upload", get("20261110-110000F").ListedAt, t1)
}

func TestRecordSet_FirstRecordKept_MalformedRefused(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	job := addJob(t, s, r, 0, "done")
	b := BackupSet{Subject: r, Label: "20261110-110000F", TLI: 1, StartSegment: bsSeg(1, 1), StopSegment: bsSeg(1, 2),
		StartLSN: "0/1000000", StopLSN: "0/2000000", StartAt: bsT0, StopAt: bsT0.Add(time.Minute), JobID: job}
	must(t, s.RecordSet(ctx, b))
	b2 := b
	b2.TLI, b2.StopSegment = 2, bsSeg(2, 9)
	must(t, s.RecordSet(ctx, b2))
	sets, _ := s.ListSets(ctx, r)
	if len(sets) != 1 || sets[0].TLI != 1 || sets[0].StopSegment != bsSeg(1, 2) || sets[0].StartLSN != "0/1000000" {
		t.Fatalf("sets = %+v", sets)
	}
	for _, bad := range []BackupSet{
		{Label: "20261110-110000D"}, {Label: "x"}, {StartSegment: "00000001"}, {StopSegment: bsSeg(1, 1) + " "},
	} {
		c := b
		c.Label = "20261111-110000F"
		if bad.Label != "" {
			c.Label = bad.Label
		}
		if bad.StartSegment != "" {
			c.StartSegment = bad.StartSegment
		}
		if bad.StopSegment != "" {
			c.StopSegment = bad.StopSegment
		}
		if err := s.RecordSet(ctx, c); err == nil {
			t.Fatalf("RecordSet(%+v) accepted", c)
		}
	}
}

func TestRecordUploads_RefusesRowsThatDoNotFit(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	good := bsRow(bsSegKey(st, "17-1", bsSeg(1, 1)), 1, "v", bsT0)
	mod := func(f func(*ObjectRow)) ObjectRow { c := good; f(&c); return c }
	cases := map[string]Uploads{
		"empty key":            {Rows: []ObjectRow{mod(func(o *ObjectRow) { o.Key = "" })}},
		"1025-byte key":        {Rows: []ObjectRow{mod(func(o *ObjectRow) { o.Key = strings.Repeat("k", 1025) })}},
		"control byte":         {Rows: []ObjectRow{mod(func(o *ObjectRow) { o.Key += "\n" })}},
		"invalid utf-8":        {Rows: []ObjectRow{mod(func(o *ObjectRow) { o.Key += "\xff" })}},
		"no hash":              {Rows: []ObjectRow{mod(func(o *ObjectRow) { o.SHA256 = nil })}},
		"short hash":           {Rows: []ObjectRow{mod(func(o *ObjectRow) { o.SHA256 = o.SHA256[:31] })}},
		"negative size":        {Rows: []ObjectRow{mod(func(o *ObjectRow) { o.Size = -1 })}},
		"oversize":             {Rows: []ObjectRow{mod(func(o *ObjectRow) { o.Size = bklimit.SetFileMax + 1 })}},
		"negative inode":       {Rows: []ObjectRow{mod(func(o *ObjectRow) { o.Ino = -1 })}},
		"version control":      {Rows: []ObjectRow{mod(func(o *ObjectRow) { o.VersionID = "v\x1b" })}},
		"too many rows":        {Rows: bsRows(st, bklimit.ReplMaxFiles+1, true)},
		"info no version":      {Info: []InfoVersion{{Name: "backup.info", SHA256: bsHash(1)}}},
		"info version control": {Info: []InfoVersion{{Name: "backup.info", VersionID: "v\x1b", SHA256: bsHash(1)}}},
		"info short hash":      {Info: []InfoVersion{{Name: "backup.info", VersionID: "v", SHA256: bsHash(1)[:5]}}},
		"info bad name":        {Info: []InfoVersion{{Name: "other.info", VersionID: "v", SHA256: bsHash(1)}}},
		"five infos":           {Info: bsInfos(5)},
		"bad label":            {SetsComplete: []string{"20261110-110000F' or true"}},
		"too many sets":        {SetsComplete: slices.Repeat([]string{"20261110-110000F"}, bklimit.ReplMaxFiles+1)},
	}
	for name, u := range cases {
		u.Complete, u.At = true, bsT0
		if _, err := s.RecordUploads(ctx, r, u); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if b := bsState(t, s, r); b.LastReplOK != nil || b.ObjectsToday != 0 || count(t, s, "select count(*) from offsite_object") != 0 ||
		count(t, s, "select count(*) from offsite_info_version") != 0 {
		t.Fatalf("a refused record wrote: %+v", b)
	}
	// Control: the fitting row, and a key of 1,024 bytes.
	long := mod(func(o *ObjectRow) { o.Key = strings.Repeat("k", 1024) })
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{good, long}, Complete: true, At: bsT0})
	if n, _ := s.ObjectCount(ctx, r); n != 2 {
		t.Fatalf("ObjectCount = %d", n)
	}
	_, err := s.RecordUploads(ctx, ref(99), Uploads{At: bsT0})
	wantErr(t, err, ErrNotFound)
}

func TestRecordUploads_AnAdoptionFillsANullHashAndChangesNoRowThatHasOne(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	k1, k2 := bsSegKey(st, "17-1", bsSeg(1, 1)), bsSegKey(st, "17-1", bsSeg(1, 2))
	long := "backup/" + st + "/20261110-110000F/pg_data/"
	long += strings.Repeat("d", 1024-len(long))
	listed := []ObjectRow{
		{Key: k1, Size: 10, VersionID: "v1", UploadedAt: bsT0},
		{Key: k2, Size: 10, VersionID: "v1", UploadedAt: bsT0},
		{Key: long, Size: 10, VersionID: "v1", UploadedAt: bsT0},
	}
	must(t, s.MergeListing(ctx, r, ListingPage{Rows: listed, Last: true}, 2))

	// The same version id: the hash, inode and ctime are filled; nothing else changes.
	adopt := ObjectRow{Key: k1, Size: 55, SHA256: bsHash(0xaa), Ino: 5, CtimeNS: 6, VersionID: "v1", UploadedAt: bsT0.Add(time.Hour)}
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{adopt}, At: bsT0.Add(time.Hour)})
	got, _, _ := bsObject(t, s, r, k1)
	if !bytes.Equal(got.SHA256, adopt.SHA256) || got.Ino != 5 || got.CtimeNS != 6 || got.Size != 10 || got.VersionID != "v1" || !got.UploadedAt.Equal(bsT0) {
		t.Fatalf("adopted row = %+v", got)
	}
	if _, ok := bsNotice(t, s, r, "offsite-differs"); ok {
		t.Fatal("an adoption with the stored version id raised offsite-differs")
	}
	// Now it has a hash: a second adoption changes nothing and raises nothing.
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{{Key: k1, Size: 10, SHA256: bsHash(0xcc), Ino: 9, CtimeNS: 9, VersionID: "v1", UploadedAt: bsT0}}, At: bsT0})
	if got, _, _ := bsObject(t, s, r, k1); !bytes.Equal(got.SHA256, adopt.SHA256) || got.Ino != 5 {
		t.Fatalf("a row with a hash changed: %+v", got)
	}
	if _, ok := bsNotice(t, s, r, "offsite-differs"); ok {
		t.Fatal("a conflict with a row that has a hash raised offsite-differs")
	}

	// Another version id: the row is left as it is and offsite-differs is raised.
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{{Key: k2, Size: 10, SHA256: bsHash(0xbb), Ino: 7, CtimeNS: 8, VersionID: "v2", UploadedAt: bsT0}}, At: bsT0})
	if got, _, _ := bsObject(t, s, r, k2); got.SHA256 != nil || got.Ino != 0 || got.VersionID != "v1" {
		t.Fatalf("an adoption under another version id changed the row: %+v", got)
	}
	n, ok := bsNotice(t, s, r, "offsite-differs")
	if !ok || n.Count != 1 || n.Detail != k2 {
		t.Fatalf("notice = %+v, %v", n, ok)
	}
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{{Key: long, Size: 10, SHA256: bsHash(0xbb), VersionID: "", UploadedAt: bsT0}}, At: bsT0})
	if got, _, _ := bsObject(t, s, r, long); got.SHA256 != nil {
		t.Fatalf("an adoption without a version id filled the hash: %+v", got)
	}
	n, _ = bsNotice(t, s, r, "offsite-differs")
	if n.Count != 2 || n.Detail != long[:256] {
		t.Fatalf("notice for the 1,024-byte key = %d, %q", n.Count, n.Detail)
	}
}

func TestObjectRows_Streams(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	const n = 100000
	pad := strings.Repeat("p", 150)
	sqlExec(t, s, `insert into offsite_object (subject, key, size, sha256, ino, ctime_ns, version_id, uploaded_at)
		select $1, $2 || lpad(to_hex(i * 7919 % $3), 8, '0'), i, sha256(int4send(i)), i, i, 'v', now() from generate_series(0, $3 - 1) i`, r, pad, n)
	if c, _ := s.ObjectCount(ctx, r); c != n {
		t.Fatalf("ObjectCount = %d", c)
	}
	var base, mid runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&base)
	seen, prev := 0, ""
	must(t, s.ObjectRows(ctx, r, func(o ObjectRow) error {
		if o.Key <= prev || len(o.SHA256) != 32 || o.VersionID != "v" {
			return fmt.Errorf("row %d: %q after %q", seen, o.Key, prev)
		}
		prev = o.Key
		seen++
		if seen == n-1 {
			runtime.GC()
			runtime.ReadMemStats(&mid)
		}
		return nil
	}))
	if seen != n {
		t.Fatalf("streamed %d rows", seen)
	}
	// 100,000 rows of about 200 bytes held at once would be about 20 MB.
	if grew := int64(mid.HeapAlloc) - int64(base.HeapAlloc); grew > 4<<20 {
		t.Fatalf("heap grew by %d bytes while streaming", grew)
	}
	stop := errors.New("stop")
	calls := 0
	if err := s.ObjectRows(ctx, r, func(ObjectRow) error { calls++; return stop }); !errors.Is(err, stop) || calls != 1 {
		t.Fatalf("callback error: %v after %d calls", err, calls)
	}
	// The pool is not left short of the stream's connection.
	if _, err := s.ObjectCount(ctx, r); err != nil {
		t.Fatal(err)
	}
}

func TestRepoQuotaTotals(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	if sum, mx, err := s.RepoQuotaTotals(ctx); err != nil || sum != 0 || mx != 0 {
		t.Fatalf("empty: %d %d %v", sum, mx, err)
	}
	for i, mb := range []int{1024, 4096, 2048, 9999, 8888} {
		_, err := s.CreateProject(ctx, NewProject{Ref: ref(i), Name: "demo", Config: ProjectConfig{DiskQuotaMB: mb, MemMB: 512, GUC: map[string]string{}}})
		must(t, err)
	}
	sqlExec(t, s, "update project set state = 'active' where ref = $1", ref(1))
	sqlExec(t, s, "update project set state = 'deleted' where ref = $1", ref(2))
	sqlExec(t, s, "update project set state = 'purged' where ref = $1", ref(3))
	sqlExec(t, s, "update project set state = 'aborted' where ref = $1", ref(4))
	sum, mx, err := s.RepoQuotaTotals(ctx)
	if err != nil || sum != 1024+4096+2048 || mx != 4096 {
		t.Fatalf("RepoQuotaTotals = %d, %d, %v", sum, mx, err)
	}
}

func TestRecordLookups_MatchAnyArchiveID(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	other := r + "-12" // a stanza whose name starts with this one's
	segA, segB, segC := bsSeg(1, 3), bsSeg(1, 4), bsSeg(1, 9)
	label := bsSeg(1, 3) + ".00000028.backup"
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{
		bsRow(bsSegKey(st, "17-1", segA), 1, "v", bsT0),
		bsRow(bsSegKey(st, "17-2", segB), 1, "v", bsT0),
		bsRow(bsHistKey(st, "17-2", 2), 1, "v", bsT0),
		bsRow(fmt.Sprintf("archive/%s/17-1/%s/%s", st, label[:16], label), 1, "v", bsT0),
		bsRow(bsSegKey(other, "17-1", segC), 1, "v", bsT0),
		bsRow(bsHistKey(other, "17-1", 3), 1, "v", bsT0),
	}, Complete: true, At: bsT0.Add(time.Minute)})
	for name, want := range map[string]bool{segA: true, segB: true, "00000002.history": true, label: true,
		segC: false, "00000003.history": false, bsSeg(2, 3): false} {
		got, err := s.HasArchiveObject(ctx, r, st, name)
		if err != nil || got != want {
			t.Fatalf("HasArchiveObject(%s) = %v, %v; want %v", name, got, err, want)
		}
		if k := len(name); k == 24 {
			if got, err := s.SegmentReplicated(ctx, r, name); err != nil || got != want {
				t.Fatalf("SegmentReplicated(%s) = %v, %v; want %v", name, got, err, want)
			}
		}
	}
	if got, err := s.NewestRecordedSegment(ctx, r, 1); err != nil || got != segB {
		t.Fatalf("NewestRecordedSegment = %q, %v; want %s", got, err, segB)
	}
	for _, bad := range []string{"", "00000002.HISTORY", segA + ".partial", "../" + segA, "%", segA[:23] + "%"} {
		if _, err := s.HasArchiveObject(ctx, r, st, bad); err == nil {
			t.Fatalf("HasArchiveObject(%q) accepted", bad)
		}
	}
	if _, err := s.SegmentReplicated(ctx, r, segA[:23]+"_"); err == nil {
		t.Fatal("SegmentReplicated accepted a pattern character")
	}
}

// --- the rebuild ---

func TestMergeListing_PagedAcrossCalls(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	const pages, per = 25, 4000
	for p := 0; p < pages; p++ {
		rows := make([]ObjectRow, per)
		for i := range rows {
			rows[i] = ObjectRow{Key: bsSegKey(st, "17-1", bsSeg(1, p*per+i)), Size: 100, VersionID: "v" + strconv.Itoa(i), UploadedAt: bsT0}
		}
		pg := ListingPage{Rows: rows, NextKeyMarker: rows[per-1].Key, NextVersionMarker: "m" + strconv.Itoa(p), Last: p == pages-1}
		must(t, s.MergeListing(ctx, r, pg, 2))
		b := bsState(t, s, r)
		if !pg.Last && (b.RebuildKeyMarker != pg.NextKeyMarker || b.RebuildVersionMarker != pg.NextVersionMarker || b.RebuildPages != p+1 || b.RebuildEpoch != 0) {
			t.Fatalf("after page %d: %q %q pages %d epoch %d", p, b.RebuildKeyMarker, b.RebuildVersionMarker, b.RebuildPages, b.RebuildEpoch)
		}
		if pg.Last && (b.RebuildKeyMarker != "" || b.RebuildVersionMarker != "" || b.RebuildPages != 0 || b.RebuildEpoch != 2) {
			t.Fatalf("after the last page: %q %q pages %d epoch %d", b.RebuildKeyMarker, b.RebuildVersionMarker, b.RebuildPages, b.RebuildEpoch)
		}
	}
	if n, _ := s.ObjectCount(ctx, r); n != pages*per {
		t.Fatalf("ObjectCount = %d", n)
	}
	if _, ok := bsNotice(t, s, r, "record-not-in-store"); ok {
		t.Fatal("a rebuild that listed every row raised record-not-in-store")
	}
}

func TestMergeListing_KeepsHashes_AddsMissing(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	k1, k2, k3 := bsSegKey(st, "17-1", bsSeg(1, 1)), bsSegKey(st, "17-1", bsSeg(1, 2)), bsSegKey(st, "17-1", bsSeg(1, 3))
	k4 := bsSegKey(st, "17-1", bsSeg(1, 4))
	up := bsRow(k1, 0xaa, "v1", bsT0)
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{up}, At: bsT0})
	// Versions are listed newest first, so a rebuilt row takes the last listed:
	// k3 across two pages, k4 twice in one.
	must(t, s.MergeListing(ctx, r, ListingPage{Rows: []ObjectRow{
		{Key: k1, Size: 999, VersionID: "planted", UploadedAt: bsT0.Add(time.Hour)},
		{Key: k2, Size: 20, VersionID: "v2", UploadedAt: bsT0.Add(time.Minute)},
		{Key: k3, Size: 1, VersionID: "newer", UploadedAt: bsT0.Add(2 * time.Hour)},
	}, NextKeyMarker: k3, NextVersionMarker: "newer"}, 2))
	must(t, s.MergeListing(ctx, r, ListingPage{Rows: []ObjectRow{
		{Key: k3, Size: 30, VersionID: "oldest", UploadedAt: bsT0},
		{Key: k4, Size: 2, VersionID: "newer", UploadedAt: bsT0.Add(time.Hour)},
		{Key: k4, Size: 40, VersionID: "oldest", UploadedAt: bsT0},
	}, Last: true}, 2))
	got, seen, _ := bsObject(t, s, r, k1)
	if !bytes.Equal(got.SHA256, up.SHA256) || got.Ino != 11 || got.CtimeNS != 12 || got.Size != 10 || got.VersionID != "v1" ||
		!got.UploadedAt.Equal(bsT0) || seen != 2 {
		t.Fatalf("a row with a hash after the merge: %+v seen %d", got, seen)
	}
	got, seen, ok := bsObject(t, s, r, k2)
	if !ok || got.SHA256 != nil || got.Ino != 0 || got.CtimeNS != 0 || got.Size != 20 || got.VersionID != "v2" || seen != 2 {
		t.Fatalf("a missing row after the merge: %+v seen %d", got, seen)
	}
	if got, _, _ := bsObject(t, s, r, k3); got.VersionID != "oldest" || got.Size != 30 || !got.UploadedAt.Equal(bsT0) {
		t.Fatalf("a key across two pages: %+v", got)
	}
	if got, _, _ := bsObject(t, s, r, k4); got.VersionID != "oldest" || got.Size != 40 {
		t.Fatalf("a key twice in one page: %+v", got)
	}
}

func TestMergeListing_FlagsRowsNoPageListed(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	var rows []ObjectRow
	for i := 1; i <= 4; i++ {
		rows = append(rows, bsRow(bsSegKey(st, "17-1", bsSeg(1, i)), 1, "v", bsT0))
	}
	bsUpload(t, s, r, Uploads{Rows: rows, At: bsT0})
	must(t, s.MergeListing(ctx, r, ListingPage{Rows: rows[:1], NextKeyMarker: rows[0].Key}, 2))
	if _, ok := bsNotice(t, s, r, "record-not-in-store"); ok {
		t.Fatal("flagged before the last page")
	}
	must(t, s.MergeListing(ctx, r, ListingPage{Rows: rows[1:2], Last: true}, 2))
	n, ok := bsNotice(t, s, r, "record-not-in-store")
	if !ok || !strings.HasPrefix(n.Detail, "2 ") {
		t.Fatalf("notice = %+v, %v; want a count of 2", n, ok)
	}
	if c, _ := s.ObjectCount(ctx, r); c != 4 {
		t.Fatalf("the merge removed rows: %d", c)
	}
}

func TestRebuild_ListedHistoryBecomesAbandoned(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op := bsOp(t, s, r)
	sqlExec(t, s, "insert into backup_timeline (subject, tli, state, op_id) values ($1, 3, 'pending', $2)", r, op)
	must(t, s.MergeListing(ctx, r, ListingPage{Rows: []ObjectRow{
		{Key: bsHistKey(st, "17-1", 2), Size: 1, VersionID: "v", UploadedAt: bsT0},
		{Key: bsHistKey(st, "17-2", 3), Size: 1, VersionID: "v", UploadedAt: bsT0},
		{Key: bsHistKey(st, "17-1", 1), Size: 1, VersionID: "v", UploadedAt: bsT0},
		{Key: bsHistKey(r+"-12", "17-1", 5), Size: 1, VersionID: "v", UploadedAt: bsT0},                         // another stanza
		{Key: fmt.Sprintf("archive/%s/17-1/00000006.history.x", st), Size: 1, VersionID: "v", UploadedAt: bsT0}, // not a history
		{Key: bsHistKey(st, "17-1", 0x7fffffff+1), Size: 1, VersionID: "v", UploadedAt: bsT0},                   // no timeline row can hold it
		{Key: bsHistKey(st, "17-1", 0), Size: 1, VersionID: "v", UploadedAt: bsT0},
	}, Last: true}, 2))
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:abandoned:0 3:pending:%d", op))

	must(t, s.EnsureBackupState(ctx, "cp"))
	must(t, s.MarkStanza(ctx, "cp"))
	cp := "cp-" + bsState(t, s, "cp").Incarnation
	must(t, s.MergeListing(ctx, "cp", ListingPage{Rows: []ObjectRow{{Key: bsHistKey(cp, "17-1", 2), Size: 1, VersionID: "v", UploadedAt: bsT0}}, Last: true}, 2))
	wantTimelines(t, s, "cp", "")
}

func TestMergeListing_RefusedOnceRebuilt(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	page := ListingPage{Rows: []ObjectRow{{Key: bsSegKey(st, "17-1", bsSeg(1, 1)), Size: 1, VersionID: "v", UploadedAt: bsT0}}, Last: true}
	must(t, s.MergeListing(ctx, r, page, 2))
	wantErr(t, s.MergeListing(ctx, r, page, 2), ErrConflict)
	wantErr(t, s.MergeListing(ctx, r, ListingPage{NextKeyMarker: "k"}, 2), ErrConflict)
	wantErr(t, s.MergeListing(ctx, r, page, 1), ErrConflict)
	if b := bsState(t, s, r); b.RebuildPages != 0 || b.RebuildKeyMarker != "" {
		t.Fatalf("a refused page wrote: %+v", b)
	}
	must(t, s.MergeListing(ctx, r, page, 3)) // the next epoch's rebuild
	wantErr(t, s.MergeListing(ctx, ref(99), page, 3), ErrNotFound)
}

func TestMergeListing_RefusesPagesThatDoNotFit(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	row := ObjectRow{Key: bsSegKey(st, "17-1", bsSeg(1, 1)), Size: 1, VersionID: "v", UploadedAt: bsT0}
	for name, p := range map[string]ListingPage{
		"too many rows":  {Rows: bsRows(st, bklimit.RebuildPageRows+1, false)},
		"empty key":      {Rows: []ObjectRow{{Size: 1}}},
		"control byte":   {Rows: []ObjectRow{{Key: row.Key + "\r", Size: 1}}},
		"negative size":  {Rows: []ObjectRow{{Key: row.Key, Size: -1}}},
		"bad version":    {Rows: []ObjectRow{{Key: row.Key, VersionID: "v\x1f"}}},
		"bad key marker": {Rows: []ObjectRow{row}, NextKeyMarker: "a\x00"},
		"long marker":    {Rows: []ObjectRow{row}, NextVersionMarker: strings.Repeat("m", 1025)},
	} {
		if err := s.MergeListing(ctx, r, p, 2); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if b := bsState(t, s, r); b.RebuildPages != 0 || count(t, s, "select count(*) from offsite_object") != 0 {
		t.Fatalf("a refused page wrote: %+v", b)
	}
	must(t, s.MergeListing(ctx, r, ListingPage{Rows: []ObjectRow{row}, NextKeyMarker: row.Key}, 2))
}

func TestSegmentReplicated_ThatSegmentAndACompleteReplicationAfterIt(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	repl := func(seg string) bool {
		t.Helper()
		ok, err := s.SegmentReplicated(ctx, r, seg)
		must(t, err)
		return ok
	}
	s1, s2, s3 := bsSeg(1, 1), bsSeg(1, 2), bsSeg(1, 3)
	t1, t2, t3, t4 := bsT0, bsT0.Add(time.Minute), bsT0.Add(2*time.Minute), bsT0.Add(3*time.Minute)
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(bsSegKey(st, "17-1", s2), 1, "v", t1)}, At: t1})
	if repl(s2) {
		t.Fatal("replicated without any complete replication")
	}
	bsUpload(t, s, r, Uploads{Complete: true, At: t2})
	if !repl(s2) {
		t.Fatal("recorded and a complete replication after it: not replicated")
	}
	if repl(s1) {
		t.Fatal("a later segment alone counted for an earlier one")
	}
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(bsSegKey(st, "17-1", s3), 1, "v", t3)}, At: t3})
	if repl(s3) {
		t.Fatal("a key without a complete replication after it counted")
	}
	bsUpload(t, s, r, Uploads{Complete: true, At: t4})
	if !repl(s3) {
		t.Fatal("not replicated after a complete replication")
	}
	if repl(bsSeg(2, 3)) {
		t.Fatal("another timeline's segment counted")
	}
	if _, err := s.SegmentReplicated(ctx, ref(99), s1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown subject: %v", err)
	}
}

func TestNewestRecordedSegment(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	newest := func(tli int) string {
		t.Helper()
		seg, err := s.NewestRecordedSegment(ctx, r, tli)
		must(t, err)
		return seg
	}
	if got := newest(1); got != "" {
		t.Fatalf("empty record: %q", got)
	}
	var rows []ObjectRow
	for _, sg := range []string{bsSeg(1, 1), bsSeg(1, 5), bsSeg(1, 3), bsSeg(2, 2), bsSeg(2, 0x100000000)} {
		rows = append(rows, bsRow(bsSegKey(st, "17-1", sg), 1, "v", bsT0))
	}
	rows = append(rows, bsRow(bsHistKey(st, "17-1", 1), 1, "v", bsT0))
	bsUpload(t, s, r, Uploads{Rows: rows, At: bsT0})
	// Keys no allow-list admits, each sorting above the real ones: a listing can hold them.
	planted := []ObjectRow{
		{Key: fmt.Sprintf("archive/%s/17-1/0000000100000009/%s-%040x.zst", st, bsSeg(1, 9), 1), Size: 1, VersionID: "v"}, // directory mismatch
		{Key: fmt.Sprintf("archive/%s/17-1/%s/%s-%040X.zst", st, bsSeg(1, 8)[:16], bsSeg(1, 8), 0xabc), Size: 1, VersionID: "v"},
		{Key: bsSegKey(r+"-12", "17-1", bsSeg(1, 7)), Size: 1, VersionID: "v"},
		{Key: bsSegKey(st, "x7-1", bsSeg(1, 6)), Size: 1, VersionID: "v"},
	}
	must(t, s.MergeListing(ctx, r, ListingPage{Rows: planted, NextKeyMarker: "k"}, 2))
	for tli, want := range map[int]string{1: bsSeg(1, 5), 2: bsSeg(2, 0x100000000), 3: ""} {
		if got := newest(tli); got != want {
			t.Fatalf("timeline %d: %q, want %q", tli, got, want)
		}
	}
	if _, err := s.NewestRecordedSegment(ctx, r, 0); err == nil {
		t.Fatal("timeline 0 accepted")
	}
}

func TestEnsureBackupState_ControlPlaneIncarnationIsTheDatabasesOwnIdentifier(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	must(t, s.EnsureBackupState(ctx, "cp"))
	var want string
	must(t, s.pool.QueryRow(ctx, `select (system_identifier::numeric + case when system_identifier < 0 then 18446744073709551616 else 0 end)::text
		from pg_control_system()`).Scan(&want))
	b := bsState(t, s, "cp")
	if b.Incarnation != want || strings.HasPrefix(b.Incarnation, "-") {
		t.Fatalf("incarnation = %q, want %q", b.Incarnation, want)
	}
	sqlExec(t, s, "update backup_state set incarnation = '12345' where subject = 'cp'")
	must(t, s.EnsureBackupState(ctx, "cp"))
	if b := bsState(t, s, "cp"); b.Incarnation != "12345" {
		t.Fatalf("a second call changed the incarnation to %q", b.Incarnation)
	}
	r := newActive(t, s, 1)
	must(t, s.EnsureBackupState(ctx, r))
	must(t, s.EnsureBackupState(ctx, r))
	if b := bsState(t, s, r); b.Incarnation != "1" || b.StanzaCreated {
		t.Fatalf("project row = %+v", b)
	}
	if err := s.EnsureBackupState(ctx, "CP"); err == nil {
		t.Fatal("a subject outside the pattern accepted")
	}
	if _, err := s.GetBackupState(ctx, ref(99)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetBackupState of an unknown subject: %v", err)
	}
}

func TestSetSeeded(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	if b := bsState(t, s, r); b.SeededAt != nil {
		t.Fatal("seeded before any seed")
	}
	must(t, s.SetSeeded(ctx, r, bsT0))
	timeIs(t, "seeded_at", bsState(t, s, r).SeededAt, bsT0)
	wantErr(t, s.SetSeeded(ctx, ref(99), bsT0), ErrNotFound)
}

func TestBackupState_PauseForcedFullAndPurge(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	must(t, s.PauseReplication(ctx, r, bsT0))
	timeIs(t, "repl_paused_until", bsState(t, s, r).ReplPausedUntil, bsT0)
	must(t, s.SetOffsitePurge(ctx, r))
	if !bsState(t, s, r).OffsitePurge {
		t.Fatal("offsite_purge not set")
	}
	day1, day2 := bsT0, bsT0.Add(24*time.Hour)
	for i, c := range []struct {
		day  time.Time
		want bool
	}{{day1, true}, {day1.Add(10 * time.Hour), false}, {day2, true}, {day1, false}} {
		got, err := s.MarkForcedFull(ctx, r, c.day)
		if err != nil || got != c.want {
			t.Fatalf("MarkForcedFull #%d(%v) = %v, %v", i, c.day, got, err)
		}
	}
	for _, err := range []error{s.PauseReplication(ctx, ref(99), bsT0), s.SetOffsitePurge(ctx, ref(99)), s.MarkStanza(ctx, ref(99))} {
		wantErr(t, err, ErrNotFound)
	}
}

// --- timelines ---

func TestTimeline_CleanRestore(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op := bsOp(t, s, r)
	wantTimelines(t, s, r, "1:recorded:0")
	n, err := s.BeginRecoveryAttempt(ctx, r, st, op, nil)
	if err != nil || n != 2 {
		t.Fatalf("BeginRecoveryAttempt = %d, %v", n, err)
	}
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:pending:%d", op))
	must(t, s.ConfirmTimeline(ctx, r, op, 2))
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:recorded:%d", op))
}

func TestTimeline_CrashBeforePromotion_ReusesNumber(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op := bsOp(t, s, r)
	for i := 0; i < 2; i++ {
		if n, err := s.BeginRecoveryAttempt(ctx, r, st, op, []int{}); err != nil || n != 2 {
			t.Fatalf("attempt %d: %d, %v", i, n, err)
		}
	}
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:pending:%d", op))
}

func TestTimeline_CrashAfterPromotion_AbandonsAndAdvances(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op := bsOp(t, s, r)
	_, err := s.BeginRecoveryAttempt(ctx, r, st, op, nil)
	must(t, err)
	// The attempt promoted: its history is in the repository now.
	n, err := s.BeginRecoveryAttempt(ctx, r, st, op, []int{2})
	if err != nil || n != 3 {
		t.Fatalf("second attempt: %d, %v", n, err)
	}
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:abandoned:%d 3:pending:%d", op, op))
}

func TestTimeline_TwoRestoresInARow(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op1, op2 := bsOp(t, s, r), bsOp(t, s, r)
	_, err := s.BeginRecoveryAttempt(ctx, r, st, op1, nil)
	must(t, err)
	must(t, s.ConfirmTimeline(ctx, r, op1, 2))
	n, err := s.BeginRecoveryAttempt(ctx, r, st, op2, []int{2})
	if err != nil || n != 3 {
		t.Fatalf("second restore: %d, %v", n, err)
	}
	must(t, s.ConfirmTimeline(ctx, r, op2, 3))
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:recorded:%d 3:recorded:%d", op1, op2))
}

func TestTimeline_SupersededPendingHeld(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	old, op := bsOp(t, s, r), bsOp(t, s, r)
	_, err := s.BeginRecoveryAttempt(ctx, r, st, old, nil)
	must(t, err)
	n, err := s.BeginRecoveryAttempt(ctx, r, st, op, []int{2})
	if err != nil || n != 3 {
		t.Fatalf("BeginRecoveryAttempt = %d, %v", n, err)
	}
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:abandoned:%d 3:pending:%d", old, op))
}

func TestTimeline_SupersededPendingNotHeld(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	old, op := bsOp(t, s, r), bsOp(t, s, r)
	_, err := s.BeginRecoveryAttempt(ctx, r, st, old, nil)
	must(t, err)
	n, err := s.BeginRecoveryAttempt(ctx, r, st, op, nil)
	if err != nil || n != 2 {
		t.Fatalf("BeginRecoveryAttempt = %d, %v", n, err)
	}
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:pending:%d", op))

	// A pending row above N that is not held is left as it is.
	must(t, s.ConfirmTimeline(ctx, r, op, 2))
	sqlExec(t, s, "insert into backup_timeline (subject, tli, state, op_id) values ($1, 4, 'pending', $2)", r, old)
	op3 := bsOp(t, s, r)
	n, err = s.BeginRecoveryAttempt(ctx, r, st, op3, []int{2})
	if err != nil || n != 3 {
		t.Fatalf("BeginRecoveryAttempt = %d, %v", n, err)
	}
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:recorded:%d 3:pending:%d 4:pending:%d", op, op3, old))
}

func TestTimeline_HeldNamesWithoutARowDoNotCount(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op := bsOp(t, s, r)
	n, err := s.BeginRecoveryAttempt(ctx, r, st, op, []int{7, 1, -3, 0, 1 << 40})
	if err != nil || n != 2 {
		t.Fatalf("BeginRecoveryAttempt = %d, %v", n, err)
	}
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:pending:%d", op))
	must(t, s.EnsureBackupState(ctx, "cp"))
	if _, err := s.BeginRecoveryAttempt(ctx, "cp", "cp-1", op, nil); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("the control plane accepted")
	}
	if _, err := s.BeginRecoveryAttempt(ctx, ref(99), ref(99)+"-1", op, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown subject: %v", err)
	}
}

func TestTimeline_RecordedNotOffsiteIsRetaken(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op1, op2 := bsOp(t, s, r), bsOp(t, s, r)
	_, err := s.BeginRecoveryAttempt(ctx, r, st, op1, nil)
	must(t, err)
	must(t, s.ConfirmTimeline(ctx, r, op1, 2))
	// Neither held nor in the record: the number is taken again.
	n, err := s.BeginRecoveryAttempt(ctx, r, st, op2, nil)
	if err != nil || n != 2 {
		t.Fatalf("re-take: %d, %v", n, err)
	}
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:pending:%d", op2))
	// An abandoned row likewise.
	sqlExec(t, s, "update backup_timeline set state = 'abandoned' where subject = $1 and tli = 2", r)
	op3 := bsOp(t, s, r)
	if n, err := s.BeginRecoveryAttempt(ctx, r, st, op3, nil); err != nil || n != 2 {
		t.Fatalf("re-take of an abandoned row: %d, %v", n, err)
	}
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:pending:%d", op3))
}

func TestTimeline_OffsiteButNotHeldConflicts(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op1, op2, op3 := bsOp(t, s, r), bsOp(t, s, r), bsOp(t, s, r)
	sqlExec(t, s, "insert into backup_timeline (subject, tli, state, op_id) values ($1, 2, 'pending', $2), ($1, 3, 'recorded', $3)", r, op1, op2)
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(bsHistKey(st, "17-3", 3), 1, "v", bsT0)}, At: bsT0})
	before := bsTimelines(t, s, r)
	_, err := s.BeginRecoveryAttempt(ctx, r, st, op3, []int{2})
	wantErr(t, err, ErrTimelineConflict)
	// Step 1's abandon of timeline 2 is not kept either.
	wantTimelines(t, s, r, before)
	// Control: once the repository holds history 3 too, the attempt goes on.
	if n, err := s.BeginRecoveryAttempt(ctx, r, st, op3, []int{2, 3}); err != nil || n != 4 {
		t.Fatalf("with history 3 held: %d, %v", n, err)
	}
}

func TestConfirmTimeline_MismatchConflicts(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op, other := bsOp(t, s, r), bsOp(t, s, r)
	_, err := s.BeginRecoveryAttempt(ctx, r, st, op, nil)
	must(t, err)
	wantErr(t, s.ConfirmTimeline(ctx, r, op, 3), ErrConflict)
	wantErr(t, s.ConfirmTimeline(ctx, r, other, 2), ErrConflict)
	wantErr(t, s.ConfirmTimeline(ctx, r, op, 1), ErrConflict)
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:pending:%d", op))
	if p := opState(t, s, op).Params; strings.Contains(string(p), "t8_done") {
		t.Fatalf("a refused confirmation wrote t8_done: %s", p)
	}
	must(t, s.ConfirmTimeline(ctx, r, op, 2))
	wantErr(t, s.ConfirmTimeline(ctx, r, op, 2), ErrConflict)
}

func TestConfirmTimeline_SetsT8DoneInTheSameTransaction(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op := bsOp(t, s, r)
	sqlExec(t, s, `update operation set params = '{"from":"local"}' where id = $1`, op)
	_, err := s.BeginRecoveryAttempt(ctx, r, st, op, nil)
	must(t, err)
	must(t, s.ConfirmTimeline(ctx, r, op, 2))
	var p map[string]any
	must(t, json.Unmarshal(opState(t, s, op).Params, &p))
	if p["t8_done"] != true || p["from"] != "local" {
		t.Fatalf("params = %v", p)
	}
	wantTimelines(t, s, r, fmt.Sprintf("1:recorded:0 2:recorded:%d", op))

	// The operation's half fails (the operation is another project's): the
	// timeline stays pending.
	r2, st2 := bsProject(t, s, 2)
	_, err = s.BeginRecoveryAttempt(ctx, r2, st2, op, nil)
	must(t, err)
	wantErr(t, s.ConfirmTimeline(ctx, r2, op, 2), ErrConflict)
	wantTimelines(t, s, r2, fmt.Sprintf("1:recorded:0 2:pending:%d", op))
}

func TestTimelines_ControlPlaneHasNone(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	must(t, s.EnsureBackupState(ctx, "cp"))
	must(t, s.MarkStanza(ctx, "cp"))
	ts, err := s.Timelines(ctx, "cp")
	if err != nil || ts == nil || len(ts) != 0 {
		t.Fatalf("Timelines(cp) = %#v, %v; want an empty, non-nil list", ts, err)
	}
	if !bsState(t, s, "cp").StanzaCreated {
		t.Fatal("stanza not marked")
	}
	// A project before its stanza: also an empty, non-nil list (admits none).
	r := newActive(t, s, 1)
	must(t, s.EnsureBackupState(ctx, r))
	if ts, err := s.Timelines(ctx, r); err != nil || ts == nil || len(ts) != 0 {
		t.Fatalf("Timelines(project) = %#v, %v", ts, err)
	}
	must(t, s.MarkStanza(ctx, r))
	must(t, s.MarkStanza(ctx, r))
	wantTimelines(t, s, r, "1:recorded:0")
}

func TestLagCounts(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	now := time.Now()
	old, fresh := now.Add(-20*time.Minute), now.Add(-time.Minute)
	must(t, s.EnsureBackupState(ctx, "cp"))
	must(t, s.RecordPush(ctx, "cp", PushRecord{Complete: true, At: old}))
	a, _ := bsProject(t, s, 1) // push old, replication fresh
	must(t, s.RecordPush(ctx, a, PushRecord{Complete: true, At: old}))
	bsUpload(t, s, a, Uploads{Complete: true, At: fresh})
	b, _ := bsProject(t, s, 2) // both fresh
	must(t, s.RecordPush(ctx, b, PushRecord{Complete: true, At: fresh}))
	bsUpload(t, s, b, Uploads{Complete: true, At: fresh})
	c, _ := bsProject(t, s, 3) // replication old, never a complete push
	bsUpload(t, s, c, Uploads{Complete: true, At: old})
	d, _ := bsProject(t, s, 4) // old, but deleted: not expected to push
	must(t, s.RecordPush(ctx, d, PushRecord{Complete: true, At: old}))
	bsUpload(t, s, d, Uploads{Complete: true, At: old})
	sqlExec(t, s, "update project set state = 'deleted' where ref = $1", d)
	e, _ := bsProject(t, s, 5) // restarting counts
	must(t, s.RecordPush(ctx, e, PushRecord{Complete: true, At: old}))
	sqlExec(t, s, "update project set state = 'restarting' where ref = $1", e)

	p, r, err := s.LagCounts(ctx, bklimit.PushLagShown, bklimit.ReplLagShown)
	if err != nil || p != 3 || r != 1 {
		t.Fatalf("LagCounts = %d, %d, %v; want 3 (cp, a, e) and 1 (c)", p, r, err)
	}
	if p, r, _ := s.LagCounts(ctx, time.Hour, time.Hour); p != 0 || r != 0 {
		t.Fatalf("LagCounts(1h) = %d, %d", p, r)
	}
}

// --- the statements that insert record and timeline rows ---

// TestBackupState_OnlyTheListedFunctionsInsertObjectOrTimelineRows scans the
// package's SQL texts: an object row or a timeline row is inserted only by
// these functions, each by one statement with an explicit column list.
func TestBackupState_OnlyTheListedFunctionsInsertObjectOrTimelineRows(t *testing.T) {
	want := []string{
		"BeginRecoveryAttempt backup_timeline",
		"MarkStanza backup_timeline",
		"MergeListing backup_timeline",
		"MergeListing offsite_object",
		"RecordUploads offsite_object",
	}
	// Every statement that writes rows into a table: its target as written
	// (schema-qualified or quoted), and whether a column list follows.
	stmt := regexp.MustCompile(`(?i)\b(insert\s+into|merge\s+into|copy)\s+([^\s(]*)(\s*\()?`)
	table := regexp.MustCompile(`(?i)^(?:public\.)?"?(offsite_object|backup_timeline)"?$`)
	var got []string
	scan := func(pos, fn, text string) {
		if table.MatchString(strings.TrimSpace(text)) {
			t.Errorf("%s: the table name %q stands alone (a copy or a built statement)", pos, text)
		}
		for _, ix := range stmt.FindAllStringSubmatchIndex(text, -1) {
			verb, target := strings.ToLower(strings.Fields(text[ix[2]:ix[3]])[0]), text[ix[4]:ix[5]]
			if verb != "copy" && (ix[5] == len(text) || strings.ContainsAny(target, "%$+")) {
				t.Errorf("%s: %s builds the target of a statement from parts: %q", pos, fn, text)
				continue
			}
			m := table.FindStringSubmatch(target)
			if m == nil {
				continue
			}
			if verb != "insert" || ix[6] < 0 {
				t.Errorf("%s: %s writes into %s other than by an insert with a column list", pos, fn, m[1])
			}
			got = append(got, fn+" "+strings.ToLower(m[1]))
		}
	}
	files, err := filepath.Glob("*.go")
	must(t, err)
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		must(t, err)
		f, err := parser.ParseFile(fset, name, src, 0)
		must(t, err)
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			must(t, err)
			scan(fset.Position(lit.Pos()).String(), enclosingFunc(f, lit.Pos()), text)
			return true
		})
	}
	// The schema files: nothing in them inserts either (a trigger would).
	sqls, err := filepath.Glob("*.sql")
	must(t, err)
	for _, name := range sqls {
		src, err := os.ReadFile(name)
		must(t, err)
		scan(name, name, string(src))
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("inserts of object or timeline rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// enclosingFunc names the function declaration that holds pos.
func enclosingFunc(f *ast.File, pos token.Pos) string {
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Pos() <= pos && pos < fd.End() {
			return fd.Name.Name
		}
	}
	return "(package level)"
}

// bsRows returns n fitting rows of distinct keys, with hashes when hashed.
func bsRows(stanza string, n int, hashed bool) []ObjectRow {
	rows := make([]ObjectRow, n)
	for i := range rows {
		rows[i] = ObjectRow{Key: bsSegKey(stanza, "17-1", bsSeg(1, i)), Size: 1, VersionID: "v", UploadedAt: bsT0}
		if hashed {
			rows[i].SHA256 = bsHash(1)
		}
	}
	return rows
}

// bsInfos returns n fitting info versions of distinct version ids.
func bsInfos(n int) []InfoVersion {
	vs := make([]InfoVersion, n)
	for i := range vs {
		vs[i] = InfoVersion{Name: "backup.info", VersionID: "v" + strconv.Itoa(i), SHA256: bsHash(1), UploadedAt: bsT0}
	}
	return vs
}
