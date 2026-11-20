package backup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/store"
)

// ───────── helpers ─────────

func segKey(stanza string, tli, n uint32) string {
	return fmt.Sprintf("archive/%s/16-1/%08X00000000/%08X00000000%08X-%040x.zst", stanza, tli, tli, n, n)
}

func labelKey(stanza string, tli, n uint32) string {
	return fmt.Sprintf("archive/%s/16-1/%08X00000000/%08X00000000%08X.00000028.backup", stanza, tli, tli, n)
}

func histKey(stanza string, tli uint32) string {
	return fmt.Sprintf("archive/%s/16-1/%08X.history", stanza, tli)
}

func setKey(stanza, label, file string) string { return "backup/" + stanza + "/" + label + "/" + file }

func sum(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 32) }

func row(key string, size int64, h byte) jobio.Row {
	return jobio.Row{Key: key, Size: size, SHA256: sum(h), Ino: int64(h) + 100, CtimeNS: int64(h) + 1000, VersionID: "v-" + key[len(key)-8:],
		At: time.Unix(1_700_000_000, 0).UTC()}
}

// rebuilt marks the subject's record rebuilt for the current epoch.
func (e *env) rebuilt(subj string) {
	e.t.Helper()
	_, err := e.db.Exec(context.Background(), "update backup_state set rebuild_epoch = (select epoch from cp_meta) where subject = $1", subj)
	must(e.t, err)
}

// object inserts a record row directly.
func (e *env) object(subj, key string, size int64, sha []byte, version string, at time.Time) {
	e.t.Helper()
	_, err := e.db.Exec(context.Background(), `insert into offsite_object (subject, key, size, sha256, version_id, uploaded_at, launch)
		values ($1, $2, $3, $4, nullif($5, ''), $6, 0)`, subj, key, size, sha, version, at)
	must(e.t, err)
}

// replicateWith makes every replicate job end with v.
func (e *env) replicateWith(v jobio.ReplResult) {
	e.ag.setScript("replicate", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		return agent.JobResult{Result: line(v)}, nil
	})
}

// replicate runs one replicate job of subj and returns its row.
func (e *env) replicate(subj string) jobRow {
	e.t.Helper()
	id := e.submit(subj, "replicate")
	if !e.turn("push") {
		e.t.Fatal("no replicate job picked")
	}
	return e.job(id)
}

func (e *env) lastInput() jobio.Input {
	e.t.Helper()
	in, err := jobio.ParseInput(e.ag.specs[len(e.ag.specs)-1].Input)
	must(e.t, err)
	return in
}

func indexLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	must(t, err)
	if len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func copyResult(up ...jobio.Row) jobio.ReplResult {
	return jobio.ReplResult{OK: true, Mode: "copy", Complete: true, Uploaded: up, Objects: len(up)}
}

// ───────── index ─────────

func TestIndex_AppendedAfterRecord_RebuiltWhenCountDiffers(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	st := ref + "-1"
	a, b := row(segKey(st, 1, 3), 100, 1), row(segKey(st, 1, 4), 200, 2)
	e.replicateWith(copyResult(a, b))
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("job %+v", got)
	}
	path := e.p.IndexFile(ref)
	lines := indexLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("index %q", lines)
	}
	for i, x := range []jobio.Row{a, b} {
		got, err := jobio.ParseIndexRow([]byte(lines[i]))
		if err != nil || got != (jobio.IndexRow{Key: x.Key, Size: x.Size, Ino: x.Ino, CtimeNS: x.CtimeNS, SHA256: x.SHA256}) {
			t.Fatalf("line %d %q (%v)", i, lines[i], err)
		}
	}
	// A row recorded behind the runner's back: the file is stale until the
	// next launch, which rebuilds it.
	c := store.ObjectRow{Key: segKey(st, 1, 5), Size: 1, SHA256: bytes.Repeat([]byte{3}, 32), VersionID: "v3", UploadedAt: time.Now()}
	_, err := e.st.RecordUploads(context.Background(), ref, store.Uploads{Rows: []store.ObjectRow{c}, At: time.Now(), Launch: 1})
	must(t, err)
	if n := len(indexLines(t, path)); n != 2 {
		t.Fatalf("index has %d lines before the launch", n)
	}
	e.replicateWith(copyResult())
	e.replicate(ref)
	if lines := indexLines(t, path); len(lines) != 3 || !strings.HasPrefix(lines[2], c.Key+"\t") {
		t.Fatalf("index after the launch %q", lines)
	}
}

func TestIndex_RootOwned0444(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	check := func(when string) {
		path := e.p.IndexFile(ref)
		fi, err := os.Lstat(path)
		must(t, err)
		di, err := os.Lstat(filepath.Dir(path))
		must(t, err)
		if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o444 || !di.IsDir() || di.Mode().Perm() != 0o700 ||
			int(fi.Sys().(*syscall.Stat_t).Uid) != os.Getuid() || int(di.Sys().(*syscall.Stat_t).Uid) != os.Getuid() {
			t.Fatalf("%s: file %v uid %d, directory %v (the daemon's uid %d)", when, fi.Mode(), fi.Sys().(*syscall.Stat_t).Uid, di.Mode(), os.Getuid())
		}
	}
	e.replicateWith(copyResult())
	e.replicate(ref) // made at the launch
	check("made")
	e.replicateWith(copyResult(row(segKey(ref+"-1", 1, 3), 1, 1)))
	e.replicate(ref) // appended to
	check("appended")
	if n := len(indexLines(t, e.p.IndexFile(ref))); n != 1 {
		t.Fatalf("%d lines (control)", n)
	}
	must(t, e.r.rebuildIndex(context.Background(), ref))
	check("rebuilt")
}

func TestIndex_ARowThatWouldNotReadBackIsAnErrorNotADrop(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ref := e.project("active")
	e.object(ref, segKey(ref+"-1", 1, 3), 10, bytes.Repeat([]byte{1}, 32), "v1", time.Now())
	_, err := e.r.ensureIndex(ctx, ref)
	must(t, err)
	path := e.p.IndexFile(ref)
	before, err := os.ReadFile(path)
	must(t, err)
	good := jobio.IndexRow{Key: segKey(ref+"-1", 1, 4), Size: 1, SHA256: sum(2)}
	bad := jobio.IndexRow{Key: "a\nb", Size: 1}
	if _, err := jobio.AppendIndexRow(nil, bad); err == nil {
		t.Fatal("jobio wrote a row that does not read back")
	}
	// Control: the good row alone is appended (it is not in the record).
	must(t, e.r.appendIndex(ctx, ref, []jobio.IndexRow{good}))
	if n := len(indexLines(t, path)); n != 2 {
		t.Fatalf("%d lines after a good append", n)
	}
	// The append fails whole and the file is rebuilt from the record: neither
	// row is appended, nothing is half written.
	must(t, e.r.appendIndex(ctx, ref, []jobio.IndexRow{good, bad}))
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Fatalf("index %q, want the record's %q", after, before)
	}
	// A record row that would not read back fails the rebuild and leaves the
	// file as it was.
	before, _ = os.ReadFile(path)
	e.object(ref, "bad\tkey", 1, nil, "", time.Now())
	if err := e.r.rebuildIndex(ctx, ref); err == nil {
		t.Fatal("a rebuild over a row that does not read back succeeded")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Fatalf("index written short: %q", after)
	}
	if ents, _ := os.ReadDir(filepath.Dir(path)); len(ents) != 1 {
		t.Fatalf("temporaries left: %v", ents)
	}
}

func TestIndex_RebuiltAfterAnAdoption(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	k := segKey(ref+"-1", 1, 3)
	e.object(ref, k, 100, nil, "v-0000.zst", time.Now()) // rebuilt from a listing: no hash
	e.replicateWith(copyResult())
	e.replicate(ref)
	if lines := indexLines(t, e.p.IndexFile(ref)); len(lines) != 1 || !strings.HasSuffix(lines[0], "\t-") {
		t.Fatalf("index %q", lines)
	}
	adopted := row(k, 100, 7)
	adopted.VersionID = "v-0000.zst"
	v := copyResult()
	v.Adopted = []jobio.Row{adopted}
	e.replicateWith(v)
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("job %+v", got)
	}
	// The count is unchanged; the line is the adopted row's.
	if lines := indexLines(t, e.p.IndexFile(ref)); len(lines) != 1 || !strings.HasSuffix(lines[0], "\t"+sum(7)) {
		t.Fatalf("index after the adoption %q", lines)
	}
}

// ───────── replication ─────────

// backupSetOf records a set of ref (its job row is a done backup job).
func (e *env) backupSetOf(ref, label string, tli int, start string, listed *time.Time) {
	e.t.Helper()
	ctx := context.Background()
	id := e.submit(ref, "backup")
	_, err := e.db.Exec(ctx, "update backup_job set state = 'done', started_at = now(), finished_at = now() where id = $1", id)
	must(e.t, err)
	stop := time.Unix(1_700_000_000, 0).UTC()
	must(e.t, e.st.RecordSet(ctx, store.BackupSet{Subject: ref, Label: label, TLI: tli, StartSegment: start, StopSegment: start,
		StartLSN: "0/1", StopLSN: "0/2", StartAt: stop.Add(-time.Minute), StopAt: stop, JobID: id}))
	if listed != nil {
		_, err := e.db.Exec(ctx, "update backup_set set replicated = true, listed_at = $3 where subject = $1 and label = $2", ref, label, *listed)
		must(e.t, err)
	}
}

func TestReplication_RecordsRowsInfoListedAt(t *testing.T) {
	e := newEnv(t)
	e.clock.Set(time.Unix(1_700_000_500, 0))
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	st := ref + "-1"
	e.backupSetOf(ref, "20261118-104332F", 1, "000000010000000000000004", nil)
	v := copyResult(row(setKey(st, "20261118-104332F", "backup.manifest"), 500, 1), row(segKey(st, 1, 4), 100, 2))
	v.Info = []jobio.InfoVersion{{Name: "backup.info", VersionID: "iv1", SHA256: sum(9), At: time.Unix(1_700_000_100, 0).UTC()}}
	v.SetsComplete = []string{"20261118-104332F"}
	e.replicateWith(v)
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("job %+v", got)
	}
	if n := e.count("select count(*) from offsite_object where subject = $1 and sha256 is not null and version_id like 'v-%'", ref); n != 2 {
		t.Fatalf("%d object rows", n)
	}
	vs, err := e.st.ListInfoVersions(context.Background(), ref, 10)
	must(t, err)
	if len(vs) != 1 || vs[0].Name != "backup.info" || vs[0].VersionID != "iv1" || hex.EncodeToString(vs[0].SHA256) != sum(9) {
		t.Fatalf("info versions %+v", vs)
	}
	sets, err := e.st.ListSets(context.Background(), ref)
	must(t, err)
	if !sets[0].Replicated || sets[0].ListedAt == nil || !sets[0].ListedAt.Equal(e.clock.Now()) {
		t.Fatalf("set %+v, want listed at %v", sets[0], e.clock.Now())
	}
	bs, err := e.st.GetBackupState(context.Background(), ref)
	must(t, err)
	if bs.LastReplOK == nil {
		t.Fatal("a complete replication left no replication time")
	}
	// The next copy is handed the recorded info hash.
	e.replicateWith(copyResult())
	e.replicate(ref)
	if in := e.lastInput(); in.Repl.Mode != "copy" || in.Repl.InfoSHA256["backup.info"] != sum(9) || len(in.Repl.InfoSHA256) != 1 {
		t.Fatalf("input %+v", in.Repl)
	}
}

func TestReplication_StoredResultHasCountsNotRows(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	st := ref + "-1"
	v := copyResult(row(segKey(st, 1, 4), 100, 2), row(segKey(st, 1, 5), 100, 3))
	v.Bytes, v.Walked = 200, 9
	e.replicateWith(v)
	got := e.replicate(ref)
	if bytes.Contains(got.Result, []byte(st)) {
		t.Fatalf("stored rows: %s", got.Result)
	}
	var doc map[string]any
	must(t, json.Unmarshal(got.Result, &doc))
	if doc["uploaded"] != 2.0 || doc["adopted"] != 0.0 || doc["bytes"] != 200.0 || doc["walked"] != 9.0 {
		t.Fatalf("stored %s", got.Result)
	}
}

func TestRecordReplicate_StoredDocumentKeepsCompleteAndMode(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	page := jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", Rows: []jobio.Row{{Key: "k1", Size: 1, VersionID: "a", At: time.Now()}},
		NextKeyMarker: "k1", NextVersionMarker: "a"}
	e.replicateWith(page)
	var doc map[string]any
	must(t, json.Unmarshal(e.replicate(ref).Result, &doc))
	if doc["mode"] != "rebuild" || doc["complete"] != false || doc["stopped"] != "rebuild" || doc["rows"] != 1.0 {
		t.Fatalf("stored %v", doc)
	}
	e.rebuilt(ref)
	e.replicateWith(copyResult())
	must(t, json.Unmarshal(e.replicate(ref).Result, &doc))
	if doc["mode"] != "copy" || doc["complete"] != true {
		t.Fatalf("stored %v", doc)
	}
}

func TestReplication_NoticesSanitised(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	v := copyResult()
	v.Notices = []jobio.Notice{{Code: "unlisted-entry", Count: 3, Detail: "\x1b[2J\x07" + strings.Repeat("é", 400)}}
	e.replicateWith(v)
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("job %+v", got)
	}
	ns, err := e.st.ListNotices(context.Background(), ref)
	must(t, err)
	if len(ns) != 1 || ns[0].Code != "unlisted-entry" || len(ns[0].Detail) > 256 || strings.ContainsAny(ns[0].Detail, "\x1b\x07") ||
		!strings.Contains(ns[0].Detail, ": 3: ") {
		t.Fatalf("notices %+v", ns)
	}
	// A code no copy raises is refused whole, nothing recorded.
	v = copyResult(row(segKey(ref+"-1", 1, 4), 1, 1))
	v.Notices = []jobio.Notice{{Code: "budget-exceeded", Count: 1}}
	e.replicateWith(v)
	if got := e.replicate(ref); got.Code != "crashed" || e.count("select count(*) from offsite_object where subject = $1", ref) != 0 {
		t.Fatalf("job %+v", got)
	}
}

func TestReplication_HeldSegmentsNoticed_NotComplete(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	v := copyResult()
	v.Held, v.Stopped = 4, "held" // a job that still claims completeness
	e.replicateWith(v)
	got := e.replicate(ref)
	var doc map[string]any
	must(t, json.Unmarshal(got.Result, &doc))
	bs, err := e.st.GetBackupState(context.Background(), ref)
	must(t, err)
	ns, err := e.st.ListNotices(context.Background(), ref)
	must(t, err)
	if doc["complete"] != false || bs.LastReplOK != nil || len(ns) != 1 || ns[0].Code != "segment-without-history" {
		t.Fatalf("stored %s, last ok %v, notices %+v", got.Result, bs.LastReplOK, ns)
	}
	// Control: nothing held.
	e.replicateWith(copyResult())
	e.replicate(ref)
	if bs, _ := e.st.GetBackupState(context.Background(), ref); bs.LastReplOK == nil {
		t.Fatal("no replication time without held segments")
	}
}

func TestReplication_BudgetPauseAndProjection(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ctx := context.Background()
	e.clock.Set(time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC))
	small, big := e.project("active"), e.project("active")
	_, err := e.db.Exec(ctx, `update project set config = jsonb_set(config, '{upload_objects_per_day}', '1') where ref = $1`, small)
	must(t, err)
	for _, ref := range []string{small, big} {
		e.rebuilt(ref)
		must(t, e.st.RecordPush(ctx, ref, store.PushRecord{Quota: &store.QuotaUse{RepoUsedKB: 1024, RepoHardKB: 1024 + 43200*4}, At: e.clock.Now()}))
		st := ref + "-1"
		// 43,200 s since midnight, 4 KiB a second, 172,800 KiB free: 12 hours.
		e.replicateWith(copyResult(row(setKey(st, "20261118-104332F", "pg_data/base/1"), 43200*4096/2, 1),
			row(setKey(st, "20261118-104332F", "pg_data/base/2"), 43200*4096/2, 2)))
		if got := e.replicate(ref); got.State != "done" {
			t.Fatalf("job %+v", got)
		}
	}
	bs, err := e.st.GetBackupState(ctx, small)
	must(t, err)
	ns, err := e.st.ListNotices(ctx, small)
	must(t, err)
	if bs.ReplPausedUntil == nil || !bs.ReplPausedUntil.Equal(time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)) ||
		len(ns) != 1 || ns[0].Code != "budget-exceeded" || !strings.Contains(ns[0].Detail, "fills in 12h0m0s") {
		t.Fatalf("paused until %v, notices %+v", bs.ReplPausedUntil, ns)
	}
	// Control: the project within its budget is not paused.
	if bs, _ := e.st.GetBackupState(ctx, big); bs.ReplPausedUntil != nil {
		t.Fatal("paused within the budget")
	}
	// What is left of today's budget is what the next copy is given.
	e.replicateWith(copyResult())
	e.replicate(big)
	bb, bo := bklimit.Budgets(8192, 0, 0)
	if in := e.lastInput(); in.Repl.BudgetBytes != bb-43200*4096 || in.Repl.BudgetObjects != bo-2 {
		t.Fatalf("budget left %d bytes %d objects", in.Repl.BudgetBytes, in.Repl.BudgetObjects)
	}
	// The next day the whole budget again.
	e.clock.Add(24 * time.Hour)
	e.replicate(big)
	if in := e.lastInput(); in.Repl.BudgetBytes != bb || in.Repl.BudgetObjects != bo {
		t.Fatalf("budget the next day %d bytes %d objects", in.Repl.BudgetBytes, in.Repl.BudgetObjects)
	}
}

func TestReplication_PausedSubjectNotScheduled(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	must(t, e.st.PauseReplication(context.Background(), ref, e.clock.Now().Add(time.Hour)))
	// A done push of a paused subject queues no replication.
	e.submit(ref, "push")
	e.turn("push")
	if n := e.jobs(ref, "replicate"); n != 0 {
		t.Fatalf("%d replications queued while paused", n)
	}
	// Once the pause has passed, the next done push queues one.
	e.clock.Add(time.Hour + time.Second)
	e.submit(ref, "push")
	e.turn("push")
	if n := e.jobs(ref, "replicate"); n != 1 {
		t.Fatalf("%d replications queued after the pause, want 1", n)
	}
}

// A copy queued before the pause (or by an operation's step) is refused at
// its launch while the pause lasts: no container, code budget.
func TestReplication_PausedSubjectNotLaunched(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	must(t, e.st.PauseReplication(context.Background(), ref, e.clock.Now().Add(time.Hour)))
	if got := e.replicate(ref); got.State != "failed" || got.Code != "budget" || len(e.ag.specs) != 0 {
		t.Fatalf("job %+v, launches %d", got, len(e.ag.specs))
	}
	e.clock.Add(time.Hour + time.Second)
	if got := e.replicate(ref); got.State != "done" || len(e.ag.specs) != 1 {
		t.Fatalf("after the pause: job %+v, launches %d", got, len(e.ag.specs))
	}
}

func TestReplication_UndeclaredAndPartialSkip(t *testing.T) {
	e := newEnv(t)
	ref := e.project("active")
	e.rebuilt(ref)
	for _, st := range []offsite.State{offsite.StateUndeclared, offsite.StatePartial} {
		e.r.SetOffsite(offsite.Declaration{}, st, nil)
		if got := e.replicate(ref); got.State != "done" || !strings.Contains(string(got.Result), "undeclared") || len(e.ag.specs) != 0 {
			t.Fatalf("%s: job %+v %s, launches %d", st, got, got.Result, len(e.ag.specs))
		}
	}
	e.declare()
	if got := e.replicate(ref); got.State != "done" || len(e.ag.specs) != 1 {
		t.Fatalf("declared: job %+v, launches %d", got, len(e.ag.specs))
	}
}

func TestReplication_ControlPlaneUsesItsBucketAndNoBudget(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ctx := context.Background()
	e.controlPlane()
	e.rebuilt("cp")
	bs, err := e.st.GetBackupState(ctx, "cp")
	must(t, err)
	// Today far above any project's object budget already.
	_, err = e.db.Exec(ctx, "update backup_state set budget_day = $1::date, objects_today = 1000000 where subject = 'cp'", e.clock.Now().UTC().Format(time.DateOnly))
	must(t, err)
	st := "cp-" + bs.Incarnation
	var up []jobio.Row
	for i := range 2048 { // far above any project's object budget of a day
		up = append(up, row(segKey(st, 1, uint32(i+1)), 1<<20, byte(i)))
	}
	e.replicateWith(copyResult(up...))
	if got := e.replicate("cp"); got.State != "done" {
		t.Fatalf("job %+v", got)
	}
	s := e.ag.specs[0]
	in := e.lastInput()
	if s.Env["SUPAPACE_S3_BUCKET"] != "cp" || string(s.Cred) != "CW\ncw-secret" || in.Repl.BudgetBytes != -1 || in.Repl.BudgetObjects != -1 {
		t.Fatalf("env %v, budgets %d %d", s.Env, in.Repl.BudgetBytes, in.Repl.BudgetObjects)
	}
	bs, err = e.st.GetBackupState(ctx, "cp")
	must(t, err)
	if bs.ReplPausedUntil != nil || bs.ObjectsToday != 1002048 {
		t.Fatalf("paused %v, objects today %d", bs.ReplPausedUntil, bs.ObjectsToday)
	}
	// Control: a project is handed its budget.
	ref := e.project("active")
	e.rebuilt(ref)
	e.replicateWith(copyResult())
	e.replicate(ref)
	if in := e.lastInput(); in.Repl.BudgetBytes <= 0 || e.ag.specs[1].Env["SUPAPACE_S3_BUCKET"] != "projects" {
		t.Fatalf("project budget %d", in.Repl.BudgetBytes)
	}
}

func TestReplication_MemoryFromTheRecordCount(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ctx := context.Background()
	ref := e.project("active")
	e.rebuilt(ref)
	e.replicateWith(copyResult())
	e.replicate(ref)
	if m := e.ag.specs[0].MemMB; m != 256 {
		t.Fatalf("memory %d for an empty record", m)
	}
	// 2,580,001 rows need 128 + ⌈2,580,001 ÷ 20,000⌉ = 258 MiB. The index file
	// is written to match, so the launch does not rebuild it.
	const n = 2_580_001
	// The rows are set up without their per-row reference check (the subject's
	// row exists), which would take most of a minute.
	tx, err := e.db.Begin(ctx)
	must(t, err)
	_, err = tx.Exec(ctx, "set local session_replication_role = replica")
	must(t, err)
	_, err = tx.Exec(ctx, `insert into offsite_object (subject, key, size, uploaded_at, launch)
		select $1, 'k' || lpad(g::text, 8, '0'), 1, now(), 0 from generate_series(1, $2) g`, ref, n)
	must(t, err)
	must(t, tx.Commit(ctx))
	must(t, os.Chmod(e.p.IndexFile(ref), 0o600))
	must(t, os.WriteFile(e.p.IndexFile(ref), bytes.Repeat([]byte("k\t1\t0\t0\t-\n"), n), 0o444))
	e.replicate(ref)
	if m := e.ag.specs[1].MemMB; m != 258 || m != bklimit.ReplMemMB(n) {
		t.Fatalf("memory %d for %d rows", m, n)
	}
}

// ───────── rebuild ─────────

// pager plays a store holding keys (in order): each job lists the page after
// its input's key marker.
func (e *env) pager(keys []string, inputs *[]jobio.ReplInput) {
	e.ag.setScript("replicate", func(_ context.Context, s agent.JobSpec) (agent.JobResult, error) {
		in, err := jobio.ParseInput(s.Input)
		if err != nil {
			return agent.JobResult{}, err
		}
		*inputs = append(*inputs, *in.Repl)
		i := sort.SearchStrings(keys, in.Repl.KeyMarker)
		if i < len(keys) && keys[i] == in.Repl.KeyMarker {
			i++
		}
		end := min(i+in.Repl.PageRows, len(keys))
		v := jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild"}
		for _, k := range keys[i:end] {
			v.Rows = append(v.Rows, jobio.Row{Key: k, Size: 7, VersionID: "v" + k[len(k)-6:], At: time.Unix(1_700_000_000, 0).UTC()})
		}
		if end == len(keys) {
			v.Last, v.Complete, v.Stopped = true, true, ""
		} else {
			v.NextKeyMarker, v.NextVersionMarker = keys[end-1], "v"+keys[end-1][len(keys[end-1])-6:]
		}
		return agent.JobResult{Result: line(v)}, nil
	})
}

func TestRebuild_PagedAcrossJobs(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ctx := context.Background()
	ref := e.project("active")
	keys := make([]string, 100_000)
	for i := range keys {
		keys[i] = fmt.Sprintf("backup/%s-1/20261118-104332F/pg_data/base/%06d", ref, i)
	}
	var inputs []jobio.ReplInput
	e.pager(keys, &inputs)
	var stored []store.BackupState
	for n := range 25 {
		bs, err := e.st.GetBackupState(ctx, ref)
		must(t, err)
		stored = append(stored, bs)
		var id, op int64
		if n%2 == 0 { // whoever submitted it: the scheduler, or an operation's step
			id = e.submit(ref, "replicate")
		} else {
			op, id = e.parked(ref, "replicate", "")
		}
		e.turn("push")
		if got := e.job(id); got.State != "done" {
			t.Fatalf("page %d: %+v", n, got)
		}
		if op != 0 {
			_, err := e.db.Exec(ctx, "update operation set state = 'done' where id = $1", op)
			must(t, err)
		}
	}
	if len(inputs) != 25 {
		t.Fatalf("%d jobs", len(inputs))
	}
	for n, in := range inputs {
		if in.Mode != "rebuild" || in.PageRows != 4000 || in.KeyMarker != stored[n].RebuildKeyMarker ||
			in.VersionMarker != stored[n].RebuildVersionMarker || n > 0 && in.KeyMarker == "" {
			t.Fatalf("job %d input %+v, stored markers %q %q", n, in, stored[n].RebuildKeyMarker, stored[n].RebuildVersionMarker)
		}
	}
	bs, err := e.st.GetBackupState(ctx, ref)
	must(t, err)
	epoch, err := e.st.Epoch(ctx)
	must(t, err)
	if c, _ := e.st.ObjectCount(ctx, ref); c != 100_000 || bs.RebuildEpoch != epoch || bs.RebuildPages != 0 || bs.RebuildKeyMarker != "" {
		t.Fatalf("count %d, state %+v", c, bs)
	}
	if n := len(indexLines(t, e.p.IndexFile(ref))); n != 100_000 {
		t.Fatalf("index of %d lines after the last page", n)
	}
	// The next job copies.
	e.replicateWith(copyResult())
	e.replicate(ref)
	if in := e.lastInput(); in.Repl.Mode != "copy" {
		t.Fatalf("after the rebuild: %+v", in.Repl)
	}
}

func TestRebuild_EachJobIsBuiltFromTheMarkersStoredAtItsLaunch(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ctx := context.Background()
	ref := e.project("active")
	page := func(next string) jobio.ReplResult {
		return jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", Rows: []jobio.Row{{Key: "k" + next, Size: 1, VersionID: "a", At: time.Now()}},
			NextKeyMarker: next, NextVersionMarker: "vm-" + next}
	}
	e.replicateWith(page("m1"))
	e.replicate(ref)
	bs, err := e.st.GetBackupState(ctx, ref)
	must(t, err)
	// A page the store refuses (a marker above 1,024 bytes): crashed.
	e.replicateWith(page(strings.Repeat("x", 1025)))
	if got := e.replicate(ref); got.Code != "crashed" {
		t.Fatalf("job %+v", got)
	}
	if in := e.lastInput(); in.Repl.KeyMarker != "m1" || in.Repl.VersionMarker != "vm-m1" || bs.RebuildKeyMarker != "m1" {
		t.Fatalf("second job input %+v, stored %q", in.Repl, bs.RebuildKeyMarker)
	}
	// Listed again from the same markers.
	e.replicateWith(page("m2"))
	e.replicate(ref)
	if in := e.lastInput(); in.Repl.KeyMarker != "m1" || in.Repl.VersionMarker != "vm-m1" {
		t.Fatalf("third job input %+v", in.Repl)
	}
	e.replicate(ref)
	if in := e.lastInput(); in.Repl.KeyMarker != "m2" {
		t.Fatalf("fourth job input %+v", in.Repl)
	}
}

func TestRebuild_BeforeAnyUploadInNewEpoch(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active") // a new record lags the epoch
	e.replicateWith(copyResult(row(segKey(ref+"-1", 1, 4), 1, 1)))
	got := e.replicate(ref)
	if in := e.lastInput(); in.Repl.Mode != "rebuild" || got.Code != "crashed" || e.count("select count(*) from offsite_object where subject = $1", ref) != 0 {
		t.Fatalf("input %+v, job %+v", in.Repl, got)
	}
	e.replicateWith(jobio.ReplResult{OK: true, Mode: "rebuild", Complete: true, Last: true})
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("last page %+v", got)
	}
	// Control: now the copy is launched and recorded.
	e.replicateWith(copyResult(row(segKey(ref+"-1", 1, 4), 1, 1)))
	if got := e.replicate(ref); got.State != "done" || e.lastInput().Repl.Mode != "copy" || e.count("select count(*) from offsite_object where subject = $1", ref) != 1 {
		t.Fatalf("copy %+v", got)
	}
}

func TestRebuild_NoticeForRowsNotInStore(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.object(ref, segKey(ref+"-1", 1, 3), 1, bytes.Repeat([]byte{1}, 32), "v", time.Now())
	e.replicateWith(jobio.ReplResult{OK: true, Mode: "rebuild", Complete: true, Last: true,
		Rows: []jobio.Row{{Key: segKey(ref+"-1", 1, 4), Size: 1, VersionID: "w", At: time.Now()}}})
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("job %+v", got)
	}
	ns, err := e.st.ListNotices(context.Background(), ref)
	must(t, err)
	if len(ns) != 1 || ns[0].Code != "record-not-in-store" || !strings.HasPrefix(ns[0].Detail, "1 ") {
		t.Fatalf("notices %+v", ns)
	}
}

func TestRebuild_StopsAtMaxPages(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	_, err := e.db.Exec(context.Background(), "update backup_state set rebuild_pages = $2 where subject = $1", ref, bklimit.RebuildMaxPages)
	must(t, err)
	if got := e.replicate(ref); got.State != "failed" || got.Code != "internal" || len(e.ag.specs) != 0 {
		t.Fatalf("job %+v, launches %d", got, len(e.ag.specs))
	}
	_, err = e.db.Exec(context.Background(), "update backup_state set rebuild_pages = $2 where subject = $1", ref, bklimit.RebuildMaxPages-1)
	must(t, err)
	e.replicateWith(jobio.ReplResult{OK: true, Mode: "rebuild", Complete: true, Last: true})
	if got := e.replicate(ref); got.State != "done" || len(e.ag.specs) != 1 {
		t.Fatalf("below the cap: job %+v, launches %d", got, len(e.ag.specs))
	}
}

func TestRebuild_ALatePageAfterTheLastIsDone(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	e.replicateWith(jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", NextKeyMarker: "z",
		Rows: []jobio.Row{{Key: "late", Size: 1, VersionID: "a", At: time.Now()}}})
	if got := e.replicate(ref); got.State != "done" || e.count("select count(*) from offsite_object where subject = $1", ref) != 0 {
		t.Fatalf("job %+v", got)
	}
}

// A page that is not what it says it is never reaches the record: without a
// next marker the next job would list from the start again.
func TestRebuild_PageOutOfShapeIsCrashed(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	rows := []jobio.Row{{Key: "k", Size: 1, VersionID: "a", At: time.Now()}}
	for name, v := range map[string]jobio.ReplResult{
		"no next marker":   {OK: true, Mode: "rebuild", Stopped: "rebuild", Rows: rows},
		"last, incomplete": {OK: true, Mode: "rebuild", Last: true, Rows: rows},
		"copy lists":       {OK: true, Mode: "rebuild", Complete: true, Last: true, Uploaded: rows},
	} {
		e.replicateWith(v)
		if got := e.replicate(ref); got.Code != "crashed" || e.count("select count(*) from offsite_object where subject = $1", ref) != 0 {
			t.Fatalf("%s: job %+v", name, got)
		}
	}
	e.replicateWith(jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", Rows: rows, NextKeyMarker: "k"})
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("control: %+v", got)
	}
}

// ───────── recording bounds ─────────

func TestRecordReplicate_CountsBeyondTheirBoundsAreCrashed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ref := e.project("active")
	e.rebuilt(ref)
	st := ref + "-1"
	rows := func(n int) []jobio.Row {
		r := make([]jobio.Row, n)
		for i := range r {
			r[i] = row(segKey(st, 1, uint32(i+1)), 1, byte(i))
		}
		return r
	}
	j := store.Job{ID: 1, Subject: ref, Kind: "replicate"}
	for name, c := range map[string]struct{ over, at jobio.ReplResult }{
		"probe rows":       {jobio.ReplResult{ProbeRows: make([]jobio.ProbeRow, 33)}, jobio.ReplResult{ProbeRows: make([]jobio.ProbeRow, 32)}},
		"notices":          {jobio.ReplResult{Notices: make([]jobio.Notice, 17)}, jobio.ReplResult{Notices: slices.Repeat([]jobio.Notice{{Code: "walk-truncated"}}, 16)}},
		"info versions":    {jobio.ReplResult{Info: make([]jobio.InfoVersion, 5)}, jobio.ReplResult{Info: slices.Repeat([]jobio.InfoVersion{{Name: "archive.info", VersionID: "x", SHA256: sum(1)}}, 4)}},
		"uploaded":         {jobio.ReplResult{Uploaded: rows(2049)}, jobio.ReplResult{Uploaded: rows(2048)}},
		"uploaded+adopted": {jobio.ReplResult{Uploaded: rows(1024), Adopted: rows(1025)}, jobio.ReplResult{Uploaded: rows(1024), Adopted: rows(1024)}},
	} {
		c.over.Mode, c.at.Mode = "copy", "copy"
		if _, err := recordReplicateJob(ctx, e.r, j, c.over); err == nil || !strings.Contains(err.Error(), "above the job's bounds") {
			t.Fatalf("%s above its bound: %v", name, err)
		}
		if _, err := recordReplicateJob(ctx, e.r, j, c.at); err != nil && strings.Contains(err.Error(), "above the job's bounds") {
			t.Fatalf("%s at its bound refused: %v", name, err)
		}
	}
	// Through the runner: a result the job writes with 17 notices is crashed,
	// nothing recorded.
	e.declare()
	v := copyResult(row(segKey(st, 1, 99999), 1, 1))
	v.Notices = slices.Repeat([]jobio.Notice{{Code: "walk-truncated"}}, 17)
	e.replicateWith(v)
	if got := e.replicate(ref); got.Code != "crashed" || e.count("select count(*) from offsite_object where subject = $1 and key = $2", ref, segKey(st, 1, 99999)) != 0 {
		t.Fatalf("job %+v", got)
	}
}

func TestRecordReplicate_AResultTheStoreRefusesIsCrashed(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	st := ref + "-1"
	nohash := row(segKey(st, 1, 5), 1, 2)
	nohash.SHA256 = ""
	e.replicateWith(copyResult(row(segKey(st, 1, 4), 1, 1), nohash))
	if got := e.replicate(ref); got.Code != "crashed" || e.count("select count(*) from offsite_object where subject = $1", ref) != 0 {
		t.Fatalf("job %+v", got)
	}
	if bs, _ := e.st.GetBackupState(context.Background(), ref); bs.LastReplOK != nil {
		t.Fatal("a refused result set the replication time")
	}
}

// A copy reports only paths of the subject's own repository, of timelines it
// admits, within their kind's size.
func TestRecordReplicate_KeysOutsideTheRepositoryAreCrashed(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	st := ref + "-1"
	for name, r := range map[string]jobio.Row{
		"another stanza":    row(segKey("other-1", 1, 4), 1, 1),
		"not a repo path":   row("archive/"+st+"/notes.txt", 1, 1),
		"timeline 2":        row(segKey(st, 2, 4), 1, 1),
		"history too large": row(histKey(st, 1), bklimit.SmallMax+1, 1),
		"segment too large": row(segKey(st, 1, 4), bklimit.SegmentMax+1, 1),
	} {
		e.replicateWith(copyResult(r))
		if got := e.replicate(ref); got.Code != "crashed" {
			t.Fatalf("%s: job %+v", name, got)
		}
	}
	e.replicateWith(copyResult(row(segKey(st, 1, 4), bklimit.SegmentMax, 1)))
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("control: %+v", got)
	}
}

// Figures, stops and notice counts out of shape are refused whole; an info
// file of another name is refused by the record's own check.
func TestRecordReplicate_FiguresOutOfShapeAreCrashed(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	up := row(segKey(ref+"-1", 1, 4), 1, 1)
	for name, mut := range map[string]func(*jobio.ReplResult){
		"negative bytes":  func(v *jobio.ReplResult) { v.Bytes = -1 },
		"negative held":   func(v *jobio.ReplResult) { v.Held = -1 },
		"unknown stop":    func(v *jobio.ReplResult) { v.Stopped = "rebuild" },
		"negative notice": func(v *jobio.ReplResult) { v.Notices = []jobio.Notice{{Code: "walk-truncated", Count: -1}} },
		"long notice": func(v *jobio.ReplResult) {
			v.Notices = []jobio.Notice{{Code: "walk-truncated", Detail: strings.Repeat("d", 1025)}}
		},
		"unknown info file": func(v *jobio.ReplResult) {
			v.Info = []jobio.InfoVersion{{Name: "pg_hba.conf", VersionID: "x", SHA256: sum(1), At: time.Now()}}
		},
	} {
		v := copyResult(up)
		mut(&v)
		e.replicateWith(v)
		if got := e.replicate(ref); got.Code != "crashed" || e.count("select count(*) from offsite_object where subject = $1", ref) != 0 {
			t.Fatalf("%s: job %+v", name, got)
		}
	}
	e.replicateWith(copyResult(up))
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("control: %+v", got)
	}
}

// A copy that stopped at its budget pauses the subject's replication too.
func TestReplication_StoppedAtTheBudgetPauses(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	v := copyResult()
	v.Stopped, v.Complete = "budget", false
	e.replicateWith(v)
	e.replicate(ref)
	if bs, _ := e.st.GetBackupState(context.Background(), ref); bs.ReplPausedUntil == nil {
		t.Fatal("not paused")
	}
}

// An index file that ends inside a line is rebuilt at the next launch.
func TestIndex_AFileEndingInsideALineIsRebuilt(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ref := e.project("active")
	e.object(ref, segKey(ref+"-1", 1, 3), 10, h32(1), "v1", time.Now())
	_, err := e.r.ensureIndex(ctx, ref)
	must(t, err)
	path := e.p.IndexFile(ref)
	good, _ := os.ReadFile(path)
	must(t, os.Chmod(path, 0o600))
	must(t, os.WriteFile(path, []byte("x\t1\t0\t0\t-\nhalf"), 0o444)) // one line and a part
	_, err = e.r.ensureIndex(ctx, ref)
	must(t, err)
	if b, _ := os.ReadFile(path); !bytes.Equal(b, good) {
		t.Fatalf("index %q", b)
	}
}

// A row recorded for a job carries that job's launch number, from the job
// row the recorder is handed: a result recorded with the row of an older
// launch keeps the older number. A job row without a number (launched
// before the numbers existed) is refused by the store, and the job ends
// crashed with nothing written.
func TestRecordReplicate_RowsCarryTheJobRowsLaunchNumber(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.declare()
	ref := e.project("active")
	st := ref + "-1"
	launch := func(key string) int64 {
		var n int64
		must(t, e.db.QueryRow(ctx, "select launch from offsite_object where subject = $1 and key = $2", ref, key).Scan(&n))
		return n
	}
	// A rebuild page and a copy, each through the runner.
	e.replicateWith(jobio.ReplResult{OK: true, Mode: "rebuild", Complete: true, Last: true,
		Rows: []jobio.Row{{Key: segKey(st, 1, 3), Size: 1, VersionID: "a", At: time.Now()}}})
	page := e.submit(ref, "replicate")
	e.turn("push")
	e.replicateWith(copyResult(row(segKey(st, 1, 4), 1, 1)))
	cp := e.submit(ref, "replicate")
	e.turn("push")
	var lp, lc int64
	must(t, e.db.QueryRow(ctx, "select launch from backup_job where id = $1", page).Scan(&lp))
	must(t, e.db.QueryRow(ctx, "select launch from backup_job where id = $1", cp).Scan(&lc))
	if lp <= 0 || lc <= lp || launch(segKey(st, 1, 3)) != lp || launch(segKey(st, 1, 4)) != lc {
		t.Fatalf("job launches %d %d, rows %d %d", lp, lc, launch(segKey(st, 1, 3)), launch(segKey(st, 1, 4)))
	}
	// The result of an older launch of the same job is recorded with that
	// launch's number, not the newer one's.
	old := store.Job{ID: cp, Subject: ref, Kind: "replicate", Launch: lp}
	_, err := recordReplicateJob(ctx, e.r, old, copyResult(row(segKey(st, 1, 5), 1, 2)))
	must(t, err)
	if n := launch(segKey(st, 1, 5)); n != lp {
		t.Fatalf("row of the older launch carries %d, want %d", n, lp)
	}
	// Without a number: refused, crashed, nothing written.
	none := store.Job{ID: cp, Subject: ref, Kind: "replicate"}
	if _, err := recordReplicateJob(ctx, e.r, none, copyResult(row(segKey(st, 1, 6), 1, 3))); !errors.Is(err, store.ErrNoLaunch) {
		t.Fatalf("copy without a launch number: %v", err)
	}
	e.ag.setScript("replicate", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		return agent.JobResult{Result: line(copyResult(row(segKey(st, 1, 6), 1, 3)))}, nil
	})
	j := store.Job{ID: cp, Subject: ref, Kind: "replicate"}
	s, err := e.r.subjectOf(ctx, ref)
	must(t, err)
	res, _ := e.ag.RunJob(ctx, agent.JobSpec{Subject: ref, Kind: "replicate"})
	if out := e.r.record(ctx, j, s, res, nil); out.code != "crashed" || !strings.Contains(out.msg, "launch") {
		t.Fatalf("outcome %+v", out)
	}
	if e.count("select count(*) from offsite_object where subject = $1 and key = $2", ref, segKey(st, 1, 6)) != 0 {
		t.Fatal("a row was written without a launch number")
	}
}

// A page that does not advance past the markers it was launched with — one
// that sorts before them, or repeats them — is a failure, never a loop.
func TestRebuild_APageThatDoesNotAdvanceIsCrashed(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	page := func(key, version string) jobio.ReplResult {
		return jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", Rows: []jobio.Row{{Key: "k", Size: 1, VersionID: "a", At: time.Now()}},
			NextKeyMarker: key, NextVersionMarker: version}
	}
	e.replicateWith(page("m", "v1"))
	e.replicate(ref) // stored markers m, v1
	for name, v := range map[string]jobio.ReplResult{"before": page("a", "v9"), "the same": page("m", "v1")} {
		e.replicateWith(v)
		if got := e.replicate(ref); got.Code != "crashed" {
			t.Fatalf("%s: job %+v", name, got)
		}
	}
	// Controls: the same key at another version (a key with many versions),
	// and a later key.
	for _, v := range []jobio.ReplResult{page("m", "v2"), page("n", "v0")} {
		e.replicateWith(v)
		if got := e.replicate(ref); got.State != "done" {
			t.Fatalf("%+v: job %+v", v, got)
		}
	}
}

// Held segments with no other stop are stored as stopped "held" — a stop a
// replicate step fails on — never as an incomplete result without a stop.
func TestRecordReplicate_HeldWithoutAStopIsStoppedHeld(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	for stop, want := range map[string]string{"": "held", "caps": "caps", "budget": "budget"} {
		v := copyResult()
		v.Held, v.Stopped, v.Complete = 2, stop, stop == ""
		e.replicateWith(v)
		var doc map[string]any
		must(t, json.Unmarshal(e.replicate(ref).Result, &doc))
		if doc["stopped"] != want || doc["complete"] != false {
			t.Fatalf("stopped %q: stored %v", stop, doc)
		}
		must(t, e.st.PauseReplication(context.Background(), ref, e.clock.Now())) // the budget case pauses
	}
}

// A temporary a stop left behind is removed at the subject's next rebuild;
// another subject's is not.
func TestIndex_StaleTemporariesRemovedAtTheNextRebuild(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, b := e.project("active"), e.project("active")
	must(t, e.r.rebuildIndex(ctx, a))
	dir := filepath.Dir(e.p.IndexFile(a))
	mine, theirs := filepath.Join(dir, "."+a+".idx-123"), filepath.Join(dir, "."+b+".idx-456")
	must(t, os.WriteFile(mine, []byte("x"), 0o600))
	must(t, os.WriteFile(theirs, []byte("x"), 0o600))
	must(t, e.r.rebuildIndex(ctx, a))
	if _, err := os.Lstat(mine); err == nil {
		t.Fatal("the subject's stale temporary is still there")
	}
	if _, err := os.Lstat(theirs); err != nil {
		t.Fatal("another subject's temporary was removed")
	}
}

// An index file of another owner is rebuilt (root only: nobody else can make one).
func TestIndex_AFileOfAnotherOwnerIsRebuilt(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give a file another owner")
	}
	e := newEnv(t)
	ctx := context.Background()
	ref := e.project("active")
	e.object(ref, segKey(ref+"-1", 1, 3), 10, h32(1), "v1", time.Now())
	_, err := e.r.ensureIndex(ctx, ref)
	must(t, err)
	path := e.p.IndexFile(ref)
	must(t, os.Chown(path, 65530, 65530))
	_, err = e.r.ensureIndex(ctx, ref)
	must(t, err)
	if fi, err := os.Lstat(path); err != nil || fi.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatalf("index owner after the check: %v %v", fi.Sys(), err)
	}
}

// A rebuild page may carry notices of the one code unlisted-entry (a key
// outside the layout in the listing): recorded as a copy's notices are — one
// row per subject, its count raised by each page — and the page advances.
func TestRebuild_AnUnlistedEntryNoticeIsRecordedAndThePageAdvances(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.declare()
	ref := e.project("active")
	page := func(next string, ns ...jobio.Notice) jobio.ReplResult {
		return jobio.ReplResult{OK: true, Mode: "rebuild", Stopped: "rebuild", Rows: []jobio.Row{{Key: "k" + next, Size: 1, VersionID: "a", At: time.Now()}},
			NextKeyMarker: next, NextVersionMarker: "v", Notices: ns}
	}
	for _, next := range []string{"m1", "m2"} {
		e.replicateWith(page(next, jobio.Notice{Code: "unlisted-entry", Count: 1, Detail: "folder/\x1b[0m"}))
		if got := e.replicate(ref); got.State != "done" {
			t.Fatalf("page %s: %+v", next, got)
		}
		if bs, _ := e.st.GetBackupState(ctx, ref); bs.RebuildKeyMarker != next {
			t.Fatalf("markers %q after page %s", bs.RebuildKeyMarker, next)
		}
	}
	ns, err := e.st.ListNotices(ctx, ref)
	must(t, err)
	if len(ns) != 1 || ns[0].Code != "unlisted-entry" || ns[0].Count != 2 || strings.Contains(ns[0].Detail, "\x1b") {
		t.Fatalf("notices %+v", ns)
	}
	// Any other code, too many notices, or an over-long detail: refused, the
	// markers stay.
	for name, v := range map[string]jobio.ReplResult{
		"another code": page("m3", jobio.Notice{Code: "offsite-differs", Count: 1}),
		"17 notices":   page("m3", slices.Repeat([]jobio.Notice{{Code: "unlisted-entry", Count: 1}}, 17)...),
		"long detail":  page("m3", jobio.Notice{Code: "unlisted-entry", Count: 1, Detail: strings.Repeat("d", 1025)}),
		"negative":     page("m3", jobio.Notice{Code: "unlisted-entry", Count: -1}),
	} {
		e.replicateWith(v)
		if got := e.replicate(ref); got.Code != "crashed" {
			t.Fatalf("%s: job %+v", name, got)
		}
		if bs, _ := e.st.GetBackupState(ctx, ref); bs.RebuildKeyMarker != "m2" {
			t.Fatalf("%s: markers %q", name, bs.RebuildKeyMarker)
		}
	}
	e.replicateWith(page("m3", jobio.Notice{Code: "unlisted-entry", Count: 1, Detail: strings.Repeat("d", 1024)}))
	if got := e.replicate(ref); got.State != "done" {
		t.Fatalf("control, a detail of 1,024 bytes: %+v", got)
	}
}

// A replication that failed with code index (the program found the index file
// malformed) is followed by a launch with a rebuilt, well-formed file — even
// when the damage left the line count right.
func TestIndex_AJobFailedWithCodeIndexRebuildsTheFile(t *testing.T) {
	e := newEnv(t)
	e.declare()
	ref := e.project("active")
	e.rebuilt(ref)
	e.replicateWith(copyResult(row(segKey(ref+"-1", 1, 3), 1, 1)))
	e.replicate(ref)
	path := e.p.IndexFile(ref)
	good, err := os.ReadFile(path)
	must(t, err)
	must(t, os.Chmod(path, 0o600))
	must(t, os.WriteFile(path, bytes.Replace(good, []byte("\t"+sum(1)), []byte("\tnot-a-hash"), 1), 0o600))
	must(t, os.Chmod(path, 0o444))
	e.ag.setScript("replicate", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		return agent.JobResult{ExitCode: 1, Result: failLine("index", "line 1: not a SHA-256")}, nil
	})
	if got := e.replicate(ref); got.Code != "index" {
		t.Fatalf("job %+v", got)
	}
	var seen []byte
	e.ag.setScript("replicate", func(context.Context, agent.JobSpec) (agent.JobResult, error) {
		seen, _ = os.ReadFile(path) // what the next job would load
		return agent.JobResult{Result: line(copyResult())}, nil
	})
	e.replicate(ref)
	if !bytes.Equal(seen, good) {
		t.Fatalf("the next job's index %q, want %q", seen, good)
	}
}

// Every code a copy or a rebuild page may report is raised as a notice.
func TestReplication_EveryAllowedNoticeCodeIsRaised(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ref := e.project("active")
	for _, codes := range []map[string]bool{copyNotices, rebuildNotices} {
		for c := range codes {
			e.r.raiseNotices(ctx, store.Job{ID: 1, Subject: ref}, []jobio.Notice{{Code: c, Count: 1, Detail: "d"}})
		}
	}
	ns, err := e.st.ListNotices(ctx, ref)
	must(t, err)
	if len(ns) != len(copyNotices) {
		t.Fatalf("notices %+v, want one of each of %v", ns, copyNotices)
	}
	for _, n := range ns {
		if !copyNotices[n.Code] {
			t.Fatalf("notice %q raised", n.Code)
		}
	}
	for c := range rebuildNotices {
		if !copyNotices[c] {
			t.Fatalf("rebuild code %q is not a copy code: this test misses it", c)
		}
	}
}
