package adminapi

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/store"
)

// TestRestore_DuplicateOrCaseVariantMembersRefused: a body whose members are
// repeated, or named in another case, is ambiguous; the restore refuses it
// before Submit. Red until decode refuses them.
func TestRestore_DuplicateOrCaseVariantMembersRefused(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	path := "/v1/projects/" + demoRef + "/restore"
	for _, body := range []string{
		`{"to":"latest","to":"0/1"}`,
		`{"TO":"0/1"}`,
		`{"to":"latest","To":"0/1"}`,
		`{"to":"latest","timeline":1,"timeline":2}`,
		`{"to":"latest","From":"offsite"}`,
	} {
		e.wantCode(t, "POST", path, body, 400, "bad_request")
	}
	if calls := e.ops.Calls(); len(calls) != 0 {
		t.Fatalf("Submit reached: %v", calls)
	}
	// The control: the same members once each, in their own case.
	e.ops.submitErr = errors.New("stop here")
	e.wantCode(t, "POST", path, `{"to":"0/1","timeline":2,"from":"offsite"}`, 500, "internal")
	if got := string(e.ops.params); got != `{"to":"lsn:0/1","timeline":2,"from":"offsite"}` {
		t.Fatalf("params %s", got)
	}
}

// TestRestore_TargetForms pins the target forms the API passes on: the
// window (past or future) is the saga's to judge, not the API's.
func TestRestore_TargetForms(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	path := "/v1/projects/" + demoRef + "/restore"
	for _, body := range []string{`{"to":"2026-11-18t10:43:32z"}`, `{"to":"LSN:0/1"}`, `{"to":" latest"}`,
		`{"to":"0/1 "}`, `{"to":"2026-11-18T10:43:60Z"}`, `{"to":"lsn:"}`} {
		e.wantCode(t, "POST", path, body, 400, "bad_request")
	}
	e.ops.submitErr = errors.New("stop here")
	for body, want := range map[string]string{
		`{"to":"9999-12-31T23:59:59Z"}`: `{"to":"9999-12-31T23:59:59Z","timeline":0,"from":""}`,
		`{"to":"0000-01-01T00:00:00Z"}`: `{"to":"0000-01-01T00:00:00Z","timeline":0,"from":""}`,
		`{"to":"lsn:0/0"}`:              `{"to":"lsn:0/0","timeline":0,"from":""}`,
	} {
		e.wantCode(t, "POST", path, body, 500, "internal")
		if got := string(e.ops.params); got != want {
			t.Errorf("%s: %s", body, got)
		}
	}
}

// TestRestore_WindowWithoutEndIsNull: a window bound the store does not have
// is null, never year 1. Red until toError maps a zero bound to null.
func TestRestore_WindowWithoutEndIsNull(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	e.ops.submitErr = &store.WindowError{From: bkT0}
	_, b := e.do(t, "POST", "/v1/projects/"+demoRef+"/restore", `{"to":"2020-01-01T00:00:00Z"}`)
	if !strings.Contains(string(b), `"window":{"from":"2026-11-18T10:43:32Z","to":null}`) {
		t.Fatalf("%s", b)
	}
}

// TestBackups_HostileTextInEveryStoredString: every string the document
// shows that a job, a listing or a request put into the store is cleaned and
// bounded.
func TestBackups_HostileTextInEveryStoredString(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	bad := `E'\x1b]0;t\x07\x1b[2J‮x⁦' || repeat('y', 3000)`
	e.sql(t, fmt.Sprintf(`
update backup_state set incarnation = %[2]s where subject = '%[1]s';
insert into offsite_info_version (subject, name, version_id, sha256, uploaded_at)
  values ('%[1]s', 'backup.info', %[2]s, sha256('a'), now());
insert into operation (ref, kind, state, epoch, generation, params)
  values ('%[1]s', 'restore', 'failed', 1, 1, jsonb_build_object('to', %[2]s, 'timeline', 0, 'from', %[2]s));`,
		demoRef, bad))
	_, b := e.do(t, "GET", "/v1/projects/"+demoRef+"/backups", "")
	var d backupsShape
	strict(t, b, &d)
	if d.Stanza == nil || d.Incarnation == nil || len(d.InfoVersions) != 1 || len(d.Restores) != 1 {
		t.Fatalf("%s", b)
	}
	for _, s := range []string{*d.Stanza, *d.Incarnation, d.InfoVersions[0].VersionID, d.Restores[0].To, d.Restores[0].From} {
		if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r == 0x202e || r == 0x2066 }) {
			t.Errorf("control or bidi rune in %q", s)
		}
		if len(s) > maxMessage+21 {
			t.Errorf("%d bytes", len(s))
		}
		if !strings.Contains(s, "yyy") {
			t.Errorf("text lost: %.40q", s)
		}
	}
}

// TestBackups_OpenRestoreAndRebuildMarker: an open restore has no
// finished_at; a rebuild with a stored marker but no page counted yet is
// rebuilding.
func TestBackups_OpenRestoreAndRebuildMarker(t *testing.T) {
	e := newEnv(t)
	e.layout2(t, demoRef)
	e.sql(t, fmt.Sprintf(`
update backup_state set rebuild_key_marker = 'archive/x', rebuild_pages = 0 where subject = '%[1]s';
insert into operation (ref, kind, state, epoch, generation, params)
  values ('%[1]s', 'restore', 'running', 1, 1, '{"to":"latest","timeline":0,"from":""}');`, demoRef))
	var d backupsShape
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/backups", "", 200), &d)
	if len(d.Restores) != 1 || d.Restores[0].FinishedAt != nil || d.Restores[0].State != "running" {
		t.Errorf("restores %+v", d.Restores)
	}
	if d.Replication == nil || !d.Replication.Rebuilding {
		t.Errorf("replication %+v", d.Replication)
	}
}
