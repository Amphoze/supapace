package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/store"
)

// bkT0 is the fixed time of the backup fixtures; the API's clock reads
// bkT0 + 42 s, so every lag figure is exact.
var bkT0 = time.Date(2026, 11, 18, 10, 43, 32, 0, time.UTC)

// withLayout sets DefaultLayout for one test.
func withLayout(t *testing.T, l int) {
	t.Helper()
	old := DefaultLayout
	DefaultLayout = l
	t.Cleanup(func() { DefaultLayout = old })
}

func withClock(t *testing.T, at time.Time) {
	t.Helper()
	old := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = old })
}

// sql runs statements on the control-plane test database as its owner.
func (e *env) sql(t *testing.T, q string) {
	t.Helper()
	out, err := exec.Command("docker", "exec", dbName, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "supapaced",
		"-d", "supapaced", "-c", q).CombinedOutput()
	if err != nil {
		t.Fatalf("sql: %v: %s", err, out)
	}
}

// offsiteOps is an Ops that also tells the off-site declaration's state.
type offsiteOps struct {
	*fakeOps
	state string
}

func (o offsiteOps) Offsite() string { return o.state }

func seg(tli, n int) string { return fmt.Sprintf("%08X%016X", tli, n) }

// layout2 creates an active layout-2 project with its backup state row.
func (e *env) layout2(t *testing.T, ref string) {
	t.Helper()
	old := DefaultLayout
	DefaultLayout = 2
	e.active(t, ref)
	DefaultLayout = old
	ctx := context.Background()
	must(t, e.st.EnsureBackupState(ctx, ref))
	must(t, e.st.MarkStanza(ctx, ref))
}

// backupFixture records one push with its quota and a gap, one full set,
// its upload with one info version, a notice and one finished restore.
func (e *env) backupFixture(t *testing.T, ref string) {
	t.Helper()
	ctx := context.Background()
	e.layout2(t, ref)
	must(t, e.st.RecordPush(ctx, ref, store.PushRecord{Complete: true, Pushed: 3, NewestSegment: seg(1, 9),
		SpoolEntries: 0, SpoolBytes: 0, At: bkT0,
		Quota: &store.QuotaUse{DiskUsedKB: 412 << 10, DiskHardKB: 8192 << 10, RepoUsedKB: 37 << 10, RepoHardKB: 8192 << 10},
		Gaps:  []store.Gap{{Cause: "quarantine", First: seg(1, 4), Last: seg(1, 5), Detail: "two segments quarantined"}}}))
	job, err := e.st.SubmitJob(ctx, store.NewJob{Subject: ref, Lane: "backup", Kind: "backup", DeadlineS: 60})
	must(t, err)
	must(t, e.st.RecordSet(ctx, store.BackupSet{Subject: ref, Label: "20261118-104332F", TLI: 1,
		StartSegment: seg(1, 6), StopSegment: seg(1, 7), StartLSN: "0/6000028", StopLSN: "0/7000050",
		StartAt: bkT0.Add(-10 * time.Minute), StopAt: bkT0.Add(-9 * time.Minute), JobID: job}))
	_, err = e.st.RecordUploads(ctx, ref, store.Uploads{
		Rows: []store.ObjectRow{{Key: "archive/" + ref + "-1/16-1/0000000100000000/" + seg(1, 6), Size: 100,
			SHA256: bytes.Repeat([]byte{1}, 32), VersionID: "v-seg", UploadedAt: bkT0.Add(-8 * time.Minute)}},
		Info: []store.InfoVersion{{Name: "backup.info", VersionID: "v-info", SHA256: bytes.Repeat([]byte{0xab}, 32),
			UploadedAt: bkT0.Add(-8 * time.Minute)}},
		SetsComplete: []string{"20261118-104332F"}, Complete: true, BudgetBytes: 1 << 34, BudgetObjects: 32768,
		At: bkT0.Add(-8 * time.Minute)})
	must(t, err)
	must(t, e.st.Notice(ctx, ref, "unlisted-entry", "an entry no record lists"))
	e.sql(t, fmt.Sprintf(`update backup_notice set first_at = '%s', last_at = '%s' where subject = '%[3]s';
		update backup_notice set count = 3 where subject = '%[3]s' and code = 'unlisted-entry'`,
		bkT0.Add(-time.Hour).Format(time.RFC3339), bkT0.Format(time.RFC3339), ref))
	id, _, err := e.st.SubmitRestore(ctx, ref, json.RawMessage(`{"to":"latest","timeline":0,"from":"local"}`))
	must(t, err)
	must(t, e.st.SetProjectRestoring(ctx, ref, id))
	must(t, e.st.StartOperation(ctx, id))
	must(t, e.st.FinishRestore(ctx, id, json.RawMessage(`{"to":"latest","from":"local","set":"20261118-104332F","mode":"none",`+
		`"reached_segment":"`+seg(2, 9)+`","new_timeline":2,"previous_timeline":1,"previous_newest_segment":"`+seg(1, 9)+`",`+
		`"seeded":false,"shortfall":null,"steps":[{"step":"T4p","seconds":3}]}`)))
}

// backupsShape is the backups document as a reader that knows only the
// contract decodes it.
type backupsShape struct {
	Ref         string  `json:"ref"`
	Stanza      *string `json:"stanza"`
	Incarnation *string `json:"incarnation"`
	Layout      int     `json:"layout"`
	Sets        []struct {
		Label        string  `json:"label"`
		Timeline     int     `json:"timeline"`
		Start        string  `json:"start"`
		Stop         string  `json:"stop"`
		StartSegment string  `json:"start_segment"`
		StopSegment  string  `json:"stop_segment"`
		Replicated   bool    `json:"replicated"`
		ListedAt     *string `json:"listed_at"`
	} `json:"sets"`
	Window struct {
		Earliest *string `json:"from"`
		Latest   *string `json:"to"`
	} `json:"window"`
	Push *struct {
		LastOK        *string `json:"last_ok"`
		LagSeconds    *int64  `json:"lag_seconds"`
		SpoolEntries  *int    `json:"spool_entries"`
		SpoolBytes    *int64  `json:"spool_bytes"`
		SpoolOldest   *string `json:"spool_oldest"`
		NewestSegment *string `json:"newest_segment"`
	} `json:"push"`
	Quota *struct {
		Taken       string `json:"at"`
		DiskUsedMB  int64  `json:"disk_used_mb"`
		DiskQuotaMB int64  `json:"disk_quota_mb"`
		RepoUsedMB  int64  `json:"repo_used_mb"`
		RepoQuotaMB int64  `json:"repo_quota_mb"`
	} `json:"quota"`
	Replication *struct {
		Declared        string  `json:"declared"`
		LastOK          *string `json:"last_ok"`
		LagSeconds      *int64  `json:"lag_seconds"`
		PausedUntil     *string `json:"paused_until"`
		Rebuilding      bool    `json:"rebuilding"`
		BytesToday      int64   `json:"bytes_today"`
		BytesBudget     int64   `json:"bytes_budget"`
		ObjectsToday    int64   `json:"objects_today"`
		ObjectsBudget   int64   `json:"objects_budget"`
		ObjectsRecorded int64   `json:"objects_recorded"`
	} `json:"replication"`
	InfoVersions []struct {
		Name      string `json:"name"`
		VersionID string `json:"version_id"`
		At        string `json:"at"`
		SHA256    string `json:"sha256"`
	} `json:"info_versions"`
	Timelines []struct {
		Timeline    int    `json:"timeline"`
		State       string `json:"state"`
		OperationID *int64 `json:"operation_id"`
	} `json:"timelines"`
	Gaps []struct {
		Cause        string `json:"cause"`
		FirstSegment string `json:"first_segment"`
		LastSegment  string `json:"last_segment"`
		At           string `json:"at"`
		Detail       string `json:"detail"`
	} `json:"gaps"`
	Notices []struct {
		Code    string `json:"code"`
		Count   int64  `json:"count"`
		FirstAt string `json:"first_at"`
		LastAt  string `json:"last_at"`
		Detail  string `json:"detail"`
	} `json:"notices"`
	Restores []struct {
		OperationID int64   `json:"operation_id"`
		State       string  `json:"state"`
		To          string  `json:"to"`
		From        string  `json:"from"`
		NewTimeline *int    `json:"new_timeline"`
		FinishedAt  *string `json:"finished_at"`
	} `json:"restores"`
}

// checkGolden decodes b strictly into v, the golden file likewise, and
// compares them member by member.
func checkGolden(t *testing.T, name string, b []byte, v any) {
	t.Helper()
	strict(t, b, v)
	golden, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	must(t, err)
	strict(t, golden, reflect.New(reflect.TypeOf(v).Elem()).Interface())
	sameShape(t, name, b)
}

func TestBackups_Golden(t *testing.T) {
	e := newEnv(t)
	withClock(t, bkT0.Add(42*time.Second))
	e.backupFixture(t, demoRef)
	b := e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200)
	checkGolden(t, "backups", b, &backupsShape{})

	// A layout-1 project: the layout and empty lists; the store's backup
	// tables are not read for it.
	other := "lay10000000000000000"
	e.active(t, other)
	checkGolden(t, "backups_layout1", e.wantOK(t, "GET", "/v1/projects/"+other+"/backups", "", 200), &backupsShape{})
	e.wantCode(t, "GET", "/v1/projects/zzzz0000000000000000/backups", "", 404, "not_found")
	e.wantCode(t, "GET", "/v1/projects/NOTAREF/backups", "", 400, "bad_ref")
}

// TestBackups_ServedInEveryState: a deleted project still answers, and
// reads go on while containment is failed.
func TestBackups_ServedInEveryState(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	e.ops.failed = true
	e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200)
	e.deleted(t, demoRef)
	var d backupsShape
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200), &d)
	if d.Layout != 2 || d.Stanza == nil || *d.Stanza != demoRef+"-1" {
		t.Fatalf("deleted project: %+v", d)
	}
}

func TestBackups_EmptyListsNotNull(t *testing.T) {
	e := newEnv(t)
	// A layout-2 project before its backup state row, and one with the row
	// but nothing recorded yet.
	withLayout(t, 2)
	e.active(t, demoRef)
	b := e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200)
	for _, l := range []string{"sets", "info_versions", "timelines", "gaps", "notices", "restores"} {
		if !bytes.Contains(b, []byte(`"`+l+`":[]`)) {
			t.Errorf("no state row: %s is not []: %s", l, b)
		}
	}
	must(t, e.st.EnsureBackupState(context.Background(), demoRef))
	b = e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200)
	for _, l := range []string{"sets", "info_versions", "timelines", "gaps", "notices", "restores"} {
		if !bytes.Contains(b, []byte(`"`+l+`":[]`)) {
			t.Errorf("empty row: %s is not []: %s", l, b)
		}
	}
	var d backupsShape
	strict(t, b, &d)
	if d.Push == nil || d.Push.LastOK != nil || d.Push.LagSeconds != nil || d.Quota != nil || d.Window.Earliest != nil ||
		d.Window.Latest != nil || d.Replication == nil || d.Replication.Declared != "undeclared" || d.Replication.LagSeconds != nil {
		t.Fatalf("nothing recorded yet: %s", b)
	}
}

func TestBackups_Caps(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	ctx := context.Background()
	job, err := e.st.SubmitJob(ctx, store.NewJob{Subject: demoRef, Lane: "backup", Kind: "backup", DeadlineS: 60})
	must(t, err)
	e.sql(t, fmt.Sprintf(`
insert into backup_set (subject, label, tli, start_segment, stop_segment, start_lsn, stop_lsn, start_at, stop_at, job_id)
  select '%[1]s', to_char(timestamp '2026-01-01' + i * interval '1 hour', 'YYYYMMDD-HH24MISS') || 'F', 1,
    '000000010000000000000001', '000000010000000000000002', '0/1000000', '0/2000000',
    timestamptz '2026-01-01Z' + i * interval '1 hour', timestamptz '2026-01-01Z' + i * interval '1 hour' + interval '1 minute', %[2]d
  from generate_series(1, 70) i;
insert into offsite_info_version (subject, name, version_id, sha256, uploaded_at)
  select '%[1]s', 'backup.info', 'v' || i, sha256(i::text::bytea), timestamptz '2026-01-01Z' + i * interval '1 hour'
  from generate_series(1, 20) i;
insert into backup_gap (subject, cause, first_segment, last_segment, detail, at)
  select '%[1]s', 'quarantine', 'f' || i, 'l' || i, 'gap ' || i, timestamptz '2026-01-01Z' + i * interval '1 hour'
  from generate_series(1, 70) i;
insert into backup_notice (subject, code, detail, first_at, last_at)
  select '%[1]s', 'code-' || i, 'notice ' || i, timestamptz '2026-01-01Z', timestamptz '2026-01-01Z' + i * interval '1 hour'
  from generate_series(1, 40) i;
insert into operation (ref, kind, state, epoch, generation, params)
  select '%[1]s', 'restore', 'failed', 1, 1, jsonb_build_object('to', 'latest', 'timeline', 0, 'from', 'restore-' || i)
  from generate_series(1, 20) i;`, demoRef, job))
	var d backupsShape
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200), &d)
	if len(d.Sets) != 64 || d.Sets[0].Label != "20260103-220000F" || d.Sets[63].Label != "20260101-070000F" {
		t.Errorf("sets: %d, first %+v", len(d.Sets), d.Sets[0])
	}
	// The window starts at the oldest set's stop, also when that set is
	// beyond the cap.
	if d.Window.Earliest == nil || *d.Window.Earliest != "2026-01-01T01:01:00Z" {
		t.Errorf("window from %v", d.Window.Earliest)
	}
	if len(d.InfoVersions) != 16 || d.InfoVersions[0].VersionID != "v20" {
		t.Errorf("info versions: %d %+v", len(d.InfoVersions), d.InfoVersions[0])
	}
	if len(d.Gaps) != 64 || d.Gaps[0].Detail != "gap 70" {
		t.Errorf("gaps: %d %+v", len(d.Gaps), d.Gaps[0])
	}
	if len(d.Notices) != 32 || d.Notices[0].Code != "code-40" {
		t.Errorf("notices: %d %+v", len(d.Notices), d.Notices[0])
	}
	if len(d.Restores) != 16 || d.Restores[0].From != "restore-20" || d.Restores[15].From != "restore-5" {
		t.Errorf("restores: %d %+v", len(d.Restores), d.Restores[0])
	}
}

func TestBackups_TextSanitised(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	e.sql(t, fmt.Sprintf(`insert into backup_notice (subject, code, detail) values
		('%[1]s', E'c\x1bode', E'line one\nline two \x1b[31mred\x07 ‮evil'),
		('%[1]s', 'long', repeat('x', 600));
		insert into backup_gap (subject, cause, first_segment, last_segment, detail)
		values ('%[1]s', 'quarantine', E'f\x01', E'l\x7f', E'gap\r\n')`, demoRef))
	b := e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200)
	var d backupsShape
	strict(t, b, &d)
	if len(d.Notices) != 2 || len(d.Gaps) != 1 {
		t.Fatalf("%s", b)
	}
	for _, s := range []string{d.Notices[0].Code, d.Notices[0].Detail, d.Notices[1].Code, d.Notices[1].Detail,
		d.Gaps[0].FirstSegment, d.Gaps[0].LastSegment, d.Gaps[0].Detail} {
		if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r == 0x202e }) {
			t.Errorf("control byte in %q", s)
		}
		if len(s) > maxDetail {
			t.Errorf("%d bytes: %q", len(s), s)
		}
	}
	// The control: the text around the removed bytes is kept.
	for _, n := range d.Notices {
		if n.Code == "code" && !strings.Contains(n.Detail, "line one") {
			t.Errorf("detail lost its text: %q", n.Detail)
		}
	}
}

// TestBackups_QuotaFromTheStoreOnly: the quota member is the report the
// store holds from the last push; the API never asks the host for usage.
func TestBackups_QuotaFromTheStoreOnly(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	e.ops.used = 999 << 30
	var d backupsShape
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200), &d)
	if d.Quota != nil {
		t.Fatalf("quota before the first report: %+v", d.Quota)
	}
	must(t, e.st.RecordPush(context.Background(), demoRef, store.PushRecord{At: bkT0,
		Quota: &store.QuotaUse{DiskUsedKB: 1025, DiskHardKB: 2048 << 10, RepoUsedKB: 3 << 10, RepoHardKB: 4096 << 10}}))
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200), &d)
	if d.Quota == nil || d.Quota.Taken != "2026-11-18T10:43:32Z" || d.Quota.DiskUsedMB != 2 || d.Quota.DiskQuotaMB != 2048 ||
		d.Quota.RepoUsedMB != 3 || d.Quota.RepoQuotaMB != 4096 {
		t.Fatalf("quota: %+v", d.Quota)
	}
	if len(e.ops.usedUIDs) != 0 {
		t.Fatalf("DiskUsage asked for %v", e.ops.usedUIDs)
	}
	// The control: show does ask.
	e.wantOK(t, "GET", "/v1/projects/"+demoRef, "", 200)
	if len(e.ops.usedUIDs) != 1 {
		t.Fatalf("show did not ask for usage")
	}
}

// TestBackups_DeclaredFromOps: replication.declared is the Ops' answer when
// it has the method, else undeclared; an answer outside the three states is
// undeclared.
func TestBackups_DeclaredFromOps(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	for state, want := range map[string]string{"declared": "declared", "partial": "partial", "undeclared": "undeclared",
		"bogus": "undeclared"} {
		e.h = New(e.st, e.kek, offsiteOps{e.ops, state}, "sp.test", e.p)
		var d backupsShape
		strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200), &d)
		if d.Replication.Declared != want {
			t.Errorf("%s: %q", state, d.Replication.Declared)
		}
	}
}

// TestBackups_DayCountersOfAnotherDayAreZero: yesterday's upload counters
// are not today's.
func TestBackups_DayCountersOfAnotherDayAreZero(t *testing.T) {
	e := newEnv(t)
	withClock(t, bkT0.Add(42*time.Second))
	e.backupFixture(t, demoRef)
	var d backupsShape
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200), &d)
	if d.Replication.BytesToday != 100 || d.Replication.ObjectsToday != 1 {
		t.Fatalf("today: %+v", d.Replication)
	}
	withClock(t, bkT0.Add(24*time.Hour))
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200), &d)
	if d.Replication.BytesToday != 0 || d.Replication.ObjectsToday != 0 {
		t.Fatalf("next day: %+v", d.Replication)
	}
}

// ───────── restore ─────────

func TestRestore_BodyStrict(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	path := "/v1/projects/" + demoRef + "/restore"
	for _, c := range []struct{ name, body string }{
		{"empty body", ``},
		{"not an object", `[]`},
		{"no to", `{}`},
		{"null to", `{"to":null}`},
		{"unknown member", `{"to":"latest","set":"20261118-104332F"}`},
		{"to empty", `{"to":""}`},
		{"to a word", `{"to":"now"}`},
		{"to latest upper case", `{"to":"LATEST"}`},
		{"to a time without offset", `{"to":"2026-11-18T10:43:32"}`},
		{"to a date", `{"to":"2026-11-18"}`},
		{"to a position without slash", `{"to":"16B3748"}`},
		{"to a position too long", `{"to":"0/123456789"}`},
		{"to a position with a sign", `{"to":"lsn:-1/0"}`},
		{"to a number", `{"to":7}`},
		{"to with a control byte", `{"to":"latest\u001b"}`},
		{"to over 64 bytes", `{"to":"2026-11-18T10:43:32.` + strings.Repeat("1", 60) + `Z"}`},
		{"timeline 0", `{"to":"latest","timeline":0}`},
		{"timeline negative", `{"to":"latest","timeline":-1}`},
		{"timeline too large", `{"to":"latest","timeline":2147483648}`},
		{"timeline a fraction", `{"to":"latest","timeline":1.5}`},
		{"timeline a string", `{"to":"latest","timeline":"1"}`},
		{"from other", `{"to":"latest","from":"remote"}`},
		{"from empty", `{"to":"latest","from":""}`},
		{"trailing data", `{"to":"latest"} {}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			eb := e.wantCode(t, "POST", path, c.body, 400, "bad_request")
			if strings.ContainsRune(eb.Message, 0x1b) {
				t.Errorf("message carries the input raw: %q", eb.Message)
			}
		})
	}
	if calls := e.ops.Calls(); len(calls) != 0 {
		t.Fatalf("Submit reached: %v", calls)
	}
	// The controls on the same path: each target form, with and without the
	// optional members, reaches Submit with the three members.
	for body, want := range map[string]string{
		`{"to":"latest"}`: `{"to":"latest","timeline":0,"from":""}`,
		`{"to":"2026-11-18T10:43:32Z","timeline":2,"from":"offsite"}`: `{"to":"2026-11-18T10:43:32Z","timeline":2,"from":"offsite"}`,
		`{"to":"2026-11-18T10:43:32.5+05:30","from":"local"}`:         `{"to":"2026-11-18T10:43:32.5+05:30","timeline":0,"from":"local"}`,
		`{"to":"0/16B3748"}`: `{"to":"lsn:0/16B3748","timeline":0,"from":""}`,
		`{"to":"lsn:FFFFFFFF/ffffffff","timeline":2147483647}`: `{"to":"lsn:FFFFFFFF/ffffffff","timeline":2147483647,"from":""}`,
	} {
		e.ops.submitErr = errors.New("stop here")
		e.wantCode(t, "POST", path, body, 500, "internal")
		if got := string(e.ops.params); got != want {
			t.Errorf("%s: params %s, want %s", body, got, want)
		}
	}
	if calls := e.ops.Calls(); len(calls) != 5 || calls[0] != "submit restore "+demoRef {
		t.Fatalf("calls %v", calls)
	}
}

// TestRestore_Accepted: an accepted restore answers 202 with its operation,
// which the store holds with the parameters Submit was given.
func TestRestore_Accepted(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	var m mutation
	strict(t, e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/restore", `{"to":"latest"}`, 202), &m)
	if m.Ref != demoRef || m.OperationID <= 0 {
		t.Fatalf("%+v", m)
	}
	if o := e.op(t, m.OperationID); o.Kind != "restore" || o.State != "pending" {
		t.Fatalf("%+v", o)
	}
	// One open operation per ref: a second restore is a conflict.
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/restore", `{"to":"latest"}`, 409, "conflict")
}

func TestRestore_MapsWindowError(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	from, to := bkT0.Add(-time.Hour), bkT0
	e.ops.submitErr = fmt.Errorf("restore: %w", &store.WindowError{From: from, To: to})
	_, b := e.do(t, "POST", "/v1/projects/"+demoRef+"/restore", `{"to":"2020-01-01T00:00:00Z"}`)
	var eb struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Window  struct {
			Earliest string `json:"from"`
			Latest   string `json:"to"`
		} `json:"window"`
	}
	strict(t, b, &eb)
	if eb.Code != "out_of_window" || eb.Window.Earliest != "2026-11-18T09:43:32Z" || eb.Window.Latest != "2026-11-18T10:43:32Z" ||
		!strings.Contains(eb.Message, "supapace project backups "+demoRef) {
		t.Fatalf("%s", b)
	}
	sameShape(t, "out_of_window", b)
	got, _ := e.do(t, "POST", "/v1/projects/"+demoRef+"/restore", `{"to":"2020-01-01T00:00:00Z"}`)
	if got != http.StatusConflict {
		t.Fatalf("status %d", got)
	}
	// The control: a plain conflict keeps its code and passes its reason.
	e.ops.submitErr = fmt.Errorf("%w: no completed backup", store.ErrConflict)
	if eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/restore", `{"to":"latest"}`, 409, "conflict"); eb.Message != "no completed backup" {
		t.Fatalf("%q", eb.Message)
	}
}

func TestRestore_ContainmentFailed503(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	e.ops.failed = true
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/restore", `{"to":"latest"}`, 503, "containment_failed")
	if calls := e.ops.Calls(); len(calls) != 0 {
		t.Fatalf("Submit reached: %v", calls)
	}
	e.ops.failed = false
	e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/restore", `{"to":"latest"}`, 202)
}

// TestOperation_ResultGolden: a finished restore's operation carries its
// result; an operation without one has "result": null.
func TestOperation_ResultGolden(t *testing.T) {
	e := newEnv(t)
	e.backupFixture(t, demoRef)
	ops, err := e.st.ListOperations(context.Background(), demoRef)
	must(t, err)
	b := e.wantOK(t, "GET", "/v1/operations/"+strconv.FormatInt(ops[0].ID, 10), "", 200)
	sameShape(t, "operation_result", b)
	b = e.wantOK(t, "GET", "/v1/operations/"+strconv.FormatInt(ops[len(ops)-1].ID, 10), "", 200)
	if !bytes.Contains(b, []byte(`"result":null`)) {
		t.Fatalf("create without result: %s", b)
	}
}

func TestOperation_ResultTextSanitised(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	e.sql(t, `update operation set result = jsonb_build_object(E'k‮', E'a\u001bb', 'n', 12345678901234567890,
		'l', jsonb_build_array(E'x\u0007y', 1.5, null, true))`)
	b := e.wantOK(t, "GET", "/v1/operations/1", "", 200)
	if !bytes.Contains(b, []byte(`"result":{"k":"ab","l":["xy",1.5,null,true],"n":12345678901234567890}`)) {
		t.Fatalf("%s", b)
	}
}

// ───────── create, restart and delete ─────────

// storedConfig is the project's configuration as the store holds it, byte
// for byte.
func (e *env) storedConfig(t *testing.T, ref string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", dbName, "psql", "-X", "-q", "-A", "-t", "-U", "supapaced", "-d", "supapaced",
		"-c", "select config::text from project where ref = '"+ref+"'").CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestCreate_LayoutFollowsDefaultLayout(t *testing.T) {
	e := newEnv(t)
	withLayout(t, 1)
	e.create(t, demoRef)
	if c := e.storedConfig(t, demoRef); c != `{"guc": {}, "mem_mb": 512, "disk_quota_mb": 8192}` {
		t.Fatalf("layout 1: stored %s", c)
	}
	if p := e.project(t, demoRef); p.Config.Layout != 0 {
		t.Fatalf("layout 1: %+v", p.Config)
	}
	DefaultLayout = 2
	other := "lay20000000000000000"
	e.create(t, other)
	if c := e.storedConfig(t, other); c != `{"guc": {}, "layout": 2, "mem_mb": 512, "disk_quota_mb": 8192}` {
		t.Fatalf("layout 2: stored %s", c)
	}
}

func TestCreate_UploadSettings(t *testing.T) {
	e := newEnv(t)
	one := jwks(t, 1)
	for _, body := range []string{
		`{"name":"demo","issuer_jwks":` + one + `,"upload_mb_per_day":-1}`,
		`{"name":"demo","issuer_jwks":` + one + `,"upload_mb_per_day":16777217}`,
		`{"name":"demo","issuer_jwks":` + one + `,"upload_objects_per_day":-1}`,
		`{"name":"demo","issuer_jwks":` + one + `,"upload_objects_per_day":16777217}`,
		`{"name":"demo","issuer_jwks":` + one + `,"upload_objects_per_day":1.5}`,
	} {
		e.wantCode(t, "POST", "/v1/projects", body, 400, "bad_request")
	}
	var m mutation
	strict(t, e.wantOK(t, "POST", "/v1/projects", `{"name":"demo","issuer_jwks":`+one+
		`,"upload_mb_per_day":16777216,"upload_objects_per_day":5000}`, 202), &m)
	if c := e.project(t, m.Ref).Config; c.UploadMBPerDay != 16777216 || c.UploadObjectsPerDay != 5000 {
		t.Fatalf("%+v", c)
	}
}

func TestCreate_Layout1OnlyOnDevelopmentNode(t *testing.T) {
	e := newEnv(t)
	withLayout(t, 2)
	one := jwks(t, 1)
	body := func(l string) string { return `{"name":"demo","issuer_jwks":` + one + `,"layout":` + l + `}` }
	eb := e.wantCode(t, "POST", "/v1/projects", body("1"), 400, "bad_request")
	if !strings.Contains(eb.Message, "development node") {
		t.Errorf("message %q", eb.Message)
	}
	must(t, os.MkdirAll(filepath.Dir(e.p.NodeJSON()), 0o755))
	marker := filepath.Join(filepath.Dir(e.p.NodeJSON()), "dev-mode")
	// A marker that is not a regular file does not count.
	must(t, os.Symlink("/dev/null", marker))
	e.wantCode(t, "POST", "/v1/projects", body("1"), 400, "bad_request")
	must(t, os.Remove(marker))
	must(t, os.WriteFile(marker, nil, 0o644))
	for _, l := range []string{"2", "0", "3", "-1", "1.0e0", `"1"`} {
		e.wantCode(t, "POST", "/v1/projects", body(l), 400, "bad_request")
	}
	var m mutation
	strict(t, e.wantOK(t, "POST", "/v1/projects", body("1"), 202), &m)
	if c := e.storedConfig(t, m.Ref); strings.Contains(c, "layout") {
		t.Fatalf("layout 1 stored %s", c)
	}
	// The control: without the member the default applies.
	strict(t, e.wantOK(t, "POST", "/v1/projects", createBody(t, ""), 202), &m)
	if e.project(t, m.Ref).Config.Layout != 2 {
		t.Fatalf("default not applied")
	}
}

func TestCreate_RefusedWhilePartlyDeclared(t *testing.T) {
	e := newEnv(t)
	e.h = New(e.st, e.kek, offsiteOps{e.ops, "partial"}, "sp.test", e.p)
	eb := e.wantCode(t, "POST", "/v1/projects", createBody(t, demoRef), 409, "conflict")
	if eb.Message != "off-site store partly declared; run 'supapaced offsite set' on this node to give the projects' bucket its credentials" {
		t.Fatalf("%q", eb.Message)
	}
	if _, err := e.st.GetProject(context.Background(), demoRef); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("project created: %v", err)
	}
	for _, s := range []string{"declared", "undeclared"} {
		e.h = New(e.st, e.kek, offsiteOps{e.ops, s}, "sp.test", e.p)
		e.create(t, "")
	}
}

func TestCreate_OpsWithoutOffsiteMethodCountsAsUndeclared(t *testing.T) {
	e := newEnv(t)
	if _, ok := any(e.ops).(interface{ Offsite() string }); ok {
		t.Fatal("the fake has the method")
	}
	e.create(t, demoRef)
	var d backupsShape
	e.layout2(t, "lay20000000000000000")
	strict(t, e.wantOK(t, "GET", "/v1/projects/lay20000000000000000/backups", "", 200), &d)
	if d.Replication.Declared != "undeclared" {
		t.Fatalf("%q", d.Replication.Declared)
	}
}

func restartConfig(t *testing.T, e *env) store.ProjectConfig {
	t.Helper()
	var rp restartShape
	dec := json.NewDecoder(bytes.NewReader(e.ops.params))
	dec.DisallowUnknownFields()
	must(t, dec.Decode(&rp))
	return rp.Config
}

func TestRestart_RaisesLayoutToTheDefault(t *testing.T) {
	e := newEnv(t)
	withLayout(t, 1)
	e.active(t, demoRef)
	e.ops.submitErr = errors.New("stop here")
	e.do(t, "POST", "/v1/projects/"+demoRef+"/restart", `{}`)
	if !bytes.Equal(e.ops.params, []byte(`{"base_generation":1,"config":{"disk_quota_mb":8192,"mem_mb":512,"guc":{}}}`)) {
		t.Fatalf("layout 1: %s", e.ops.params)
	}
	DefaultLayout = 2
	e.do(t, "POST", "/v1/projects/"+demoRef+"/restart", `{}`)
	if c := restartConfig(t, e); c.Layout != 2 {
		t.Fatalf("layout 2: %s", e.ops.params)
	}
	// A layout-2 project stays at 2 whatever the default.
	other := "lay20000000000000000"
	e.layout2(t, other)
	DefaultLayout = 1
	e.do(t, "POST", "/v1/projects/"+other+"/restart", `{}`)
	if c := restartConfig(t, e); c.Layout != 2 {
		t.Fatalf("layout 2 lowered: %s", e.ops.params)
	}
}

func TestRestart_KeepsUploadOverrides(t *testing.T) {
	e := newEnv(t)
	one := jwks(t, 1)
	var m mutation
	strict(t, e.wantOK(t, "POST", "/v1/projects", `{"name":"demo","ref":"`+demoRef+`","issuer_jwks":`+one+
		`,"upload_mb_per_day":100,"upload_objects_per_day":9000}`, 202), &m)
	e.activate(t, demoRef, m.OperationID)
	e.ops.submitErr = errors.New("stop here")
	e.do(t, "POST", "/v1/projects/"+demoRef+"/restart", `{"set":{"work_mem":"8MB"}}`)
	if c := restartConfig(t, e); c.UploadMBPerDay != 100 || c.UploadObjectsPerDay != 9000 || c.GUC["work_mem"] != "8MB" {
		t.Fatalf("kept: %s", e.ops.params)
	}
	e.do(t, "POST", "/v1/projects/"+demoRef+"/restart", `{"upload_mb_per_day":200}`)
	if c := restartConfig(t, e); c.UploadMBPerDay != 200 || c.UploadObjectsPerDay != 9000 {
		t.Fatalf("changed one: %s", e.ops.params)
	}
	e.do(t, "POST", "/v1/projects/"+demoRef+"/restart", `{"upload_mb_per_day":0,"upload_objects_per_day":0}`)
	if c := restartConfig(t, e); c.UploadMBPerDay != 0 || c.UploadObjectsPerDay != 0 {
		t.Fatalf("back to the defaults: %s", e.ops.params)
	}
	e.ops.submitErr = nil
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/restart", `{"upload_objects_per_day":-5}`, 400, "bad_request")
}

func TestDelete_OfRestoringProjectReachesSubmit(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	ctx := context.Background()
	id, _, err := e.st.SubmitRestore(ctx, demoRef, json.RawMessage(`{"to":"latest","timeline":0,"from":"local"}`))
	must(t, err)
	must(t, e.st.SetProjectRestoring(ctx, demoRef, id))
	e.failed(t, id, "deadline: x")
	if p := e.project(t, demoRef); p.State != "restoring" {
		t.Fatalf("state %s", p.State)
	}
	var m mutation
	strict(t, e.wantOK(t, "DELETE", "/v1/projects/"+demoRef, "", 202), &m)
	if calls := e.ops.Calls(); len(calls) != 1 || calls[0] != "submit delete "+demoRef {
		t.Fatalf("calls %v", calls)
	}
	if o := e.op(t, id); o.State != "superseded" {
		t.Fatalf("failed restore: %s", o.State)
	}
	// A restoring project is listed by its state.
	var l struct{ Projects []struct{ Ref string } }
	must(t, json.Unmarshal(e.wantOK(t, "GET", "/v1/projects?state=restoring", "", 200), &l))
	if len(l.Projects) != 1 {
		t.Fatalf("%+v", l)
	}
}

// TestDecode_AmbiguousBodiesOnEveryRoute: a repeated member at any depth and
// a top-level member not in lower case are refused on every route that takes
// a body; names inside set (setting names) keep their case.
func TestDecode_AmbiguousBodiesOnEveryRoute(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	restart := "/v1/projects/" + demoRef + "/restart"
	for _, c := range []struct{ path, body string }{
		{restart, `{"set":{"work_mem":"1MB"},"set":{}}`},
		{restart, `{"set":{"work_mem":"1MB","work_mem":"2MB"}}`},
		{restart, `{"set":{"work_mem":"x","work_mem":"y"},"disk_quota_mb":8192}`},
		{restart, `{"Disk_quota_mb":8192}`},
		{"/v1/projects", `{"name":"demo","Name":"other","issuer_jwks":` + jwks(t, 1) + `}`},
	} {
		eb := e.wantCode(t, "POST", c.path, c.body, 400, "bad_request")
		if !strings.Contains(eb.Message, "repeated or not in lower case") {
			t.Errorf("%s: %q", c.body, eb.Message)
		}
	}
	if calls := e.ops.Calls(); len(calls) != 0 {
		t.Fatalf("Submit reached: %v", calls)
	}
	// The controls: a setting name in another case is judged as a setting,
	// and the same body without the repeat is accepted.
	if eb := e.wantCode(t, "POST", restart, `{"set":{"Work_Mem":"1MB"}}`, 400, "bad_request"); !strings.Contains(eb.Message, "cannot be set") {
		t.Errorf("set key: %q", eb.Message)
	}
	e.wantOK(t, "POST", restart, `{"set":{"work_mem":"1MB"}}`, 202)
	// The refusal of an unknown source says what to do instead.
	e.layout2(t, "lay20000000000000000")
	if eb := e.wantCode(t, "POST", "/v1/projects/lay20000000000000000/restore", `{"to":"latest","from":"x"}`, 400, "bad_request"); eb.Message != "from must be local or offsite; omit it for the default" {
		t.Errorf("%q", eb.Message)
	}
}

// TestRestore_WindowWithoutStartIsNull: a missing lower bound is null too.
func TestRestore_WindowWithoutStartIsNull(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	e.ops.submitErr = &store.WindowError{To: bkT0}
	_, b := e.do(t, "POST", "/v1/projects/"+demoRef+"/restore", `{"to":"2020-01-01T00:00:00Z"}`)
	if !strings.Contains(string(b), `"window":{"from":null,"to":"2026-11-18T10:43:32Z"}`) {
		t.Fatalf("%s", b)
	}
}
