//go:build reach

package reach

// Restores: the rules a restore request meets, the recovery start, a daemon
// killed between promotion and re-key, the spool pushed empty before the
// wipe, the shortfall, the settings and the content a restored cluster
// brings, failed restores and the ways out of them, the off-site source; the
// restore drill; the switch of a project made before backups existed. The
// restored data directory, its configuration file and the repository are
// tenant-written: nothing they say is taken on their word. After every
// restore to a time or a position the archiver has no failure and pg_wal/
// holds no .partial file (archiveClean). Each test runs at layout 2 only
// (needBackups); every case that reads or writes the object store is inside
// the sub-test offsite (needStandin).

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/store"
)

// ───────── shared ─────────

// restoreWait bounds one restore: five passes of a restore that keeps
// failing, with their back-offs, on a small project.
var restoreWait = 45 * time.Minute

// refusalJSON is a synchronous refusal of the admin API; window only for
// out_of_window.
type refusalJSON struct {
	Code    string  `json:"code"`
	Message string  `json:"message"`
	Window  *bounds `json:"window"`
}

// bounds is a restore window: its first and last instant, null when unknown.
type bounds struct {
	First *string `json:"from"`
	Last  *string `json:"to"`
}

// shortfallJSON is a restore result's shortfall object.
type shortfallJSON struct {
	Expected string `json:"expected"`
	Reached  string `json:"reached"`
	Segments int64  `json:"segments"`
}

// submitRestore sends `project restore REF ARGS… --no-wait`: the operation id
// on acceptance, else 0 and the refusal.
func submitRestore(t testing.TB, ref string, args ...string) (int64, refusalJSON) {
	t.Helper()
	out, code := cli(t, append([]string{"project", "restore", ref, "--no-wait"}, args...)...)
	if code == 0 {
		var m mutationJSON
		decode(t, "project restore", out, &m)
		if m.Ref != ref || m.OperationID <= 0 {
			t.Fatalf("project restore %s: accepted without an operation", ref)
		}
		return m.OperationID, refusalJSON{}
	}
	var e refusalJSON
	decode(t, "project restore", out, &e)
	if code != 1 || e.Code == "" {
		t.Fatalf("project restore %s %v: exit %d without an error code", ref, args, code)
	}
	return 0, e
}

// wantRefused requires the restore to be refused with code and a message
// holding text.
func wantRefused(t testing.TB, ref, code, text string, args ...string) refusalJSON {
	t.Helper()
	id, e := submitRestore(t, ref, args...)
	if id != 0 {
		t.Fatalf("restore %v was accepted (operation %d), want %s %q", args, id, code, text)
	}
	if e.Code != code || !strings.Contains(e.Message, text) {
		t.Fatalf("restore %v: %s %q, want %s with %q", args, e.Code, hide(e.Message), code, text)
	}
	return e
}

// endOf polls the operation until it is done, failed, aborted or superseded
// (a restore can be replaced), within; it returns it with its result.
func endOf(t testing.TB, id int64, within time.Duration) resultOp {
	t.Helper()
	var op resultOp
	for deadline := time.Now().Add(within); ; time.Sleep(2 * time.Second) {
		out, _ := cli(t, "op", "show", strconv.FormatInt(id, 10))
		op = resultOp{}
		decode(t, "op show", out, &op)
		if op.ID != id {
			t.Fatalf("op show %d returned operation %d", id, op.ID)
		}
		switch op.State {
		case "done", "failed", "aborted", "superseded":
			return op
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation %d still %s at step %q after %v: %s", id, op.State, op.Step, within, hide(op.LastError))
		}
	}
}

// resultOf decodes a done restore's result and logs its duration and steps.
func resultOf(t testing.TB, op resultOp, took time.Duration) restoreResultJSON {
	t.Helper()
	if op.State != "done" {
		t.Fatalf("restore %d: %s at step %q: %s", op.ID, op.State, op.Step, hide(op.LastError))
	}
	var r restoreResultJSON
	if err := json.Unmarshal(op.Result, &r); err != nil {
		t.Fatalf("restore %d: result: %v", op.ID, err)
	}
	var steps []string
	for _, s := range r.Steps {
		steps = append(steps, fmt.Sprintf("%s %ds", s.Step, s.Seconds))
	}
	t.Logf("restore %d (to %s, from %s, set %s, mode %s): %v; timeline %d → %d; steps %s",
		op.ID, r.To, r.From, r.Set, r.Mode, took.Round(time.Second), r.PreviousTimeline, r.NewTimeline, strings.Join(steps, ", "))
	return r
}

// restoreScratch is fixtureScratch for a project a restore may leave
// restoring: before the scratch cleanup runs, leaveRestoring takes it out of
// that state, so the next test finds no scratch project.
func restoreScratch(t testing.TB, args ...string) Project {
	t.Helper()
	p := fixtureScratch(t, args...)
	t.Cleanup(func() { leaveRestoring(t, p.Ref) })
	return p
}

// leaveRestoring: a restore of ref still open is waited for; a project it
// left restoring is deleted (the delete supersedes the failed restore).
// A restore that has not reached T2 leaves the project active, yet the
// delete of the scratch cleanup would be refused while it is open: it is
// waited for whatever the project's state.
func leaveRestoring(t testing.TB, ref string) {
	t.Helper()
	out, code := cli(t, "op", "list", ref)
	var ops opsJSON
	if code != 0 || json.Unmarshal([]byte(out), &ops) != nil || len(ops.Operations) == 0 {
		t.Errorf("project %s: no operation listed (exit %d)", ref, code)
		return
	}
	if op := ops.Operations[0]; op.Kind == "restore" { // newest first
		endOf(t, op.ID, restoreWait)
	}
	if projectState(t, ref) == "restoring" {
		if _, code := cli(t, "project", "delete", ref); code != 0 {
			t.Errorf("deleting project %s left restoring: exit %d", ref, code)
		}
	}
}

// verifierRE is a password verifier; hide removes it, and what redact
// removes, from a line a failure message shows.
var verifierRE = regexp.MustCompile(`SCRAM-SHA-256\$[^\s'"]*`)

func hide(s string) string { return verifierRE.ReplaceAllString(redact(s), "<verifier>") }

// restoreDone submits a restore of p, waits for it and requires it done.
func restoreDone(t testing.TB, p Project, args ...string) restoreResultJSON {
	t.Helper()
	start := time.Now()
	id, e := submitRestore(t, p.Ref, args...)
	if id == 0 {
		t.Fatalf("restore %v refused: %s %q", args, e.Code, hide(e.Message))
	}
	return resultOf(t, endOf(t, id, restoreWait), time.Since(start))
}

// stepSeconds is the time a result records for step, -1 when none.
func stepSeconds(r restoreResultJSON, step string) int64 {
	for _, s := range r.Steps {
		if s.Step == step {
			return s.Seconds
		}
	}
	return -1
}

// archiveClean is the assertion after every restore to a time or a position:
// the archiver of the restored cluster has never failed, and pg_wal/ holds no
// .partial file once a checkpoint followed a segment switch — a .partial the
// archive binary refused stays marked ready and is never removed. Fails on an
// archive binary that refuses the old timeline's .partial segment.
func archiveClean(t testing.TB, p Project) {
	t.Helper()
	wal := filepath.Join(paths.ProjectDir(p.Ref), "data", "pg_wal")
	var partial []string
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(2 * time.Second) {
		fc, err := adminSQL(t, p, "select failed_count from pg_stat_archiver")
		if err != nil {
			t.Fatalf("archiver of %s: %v", p.Ref, err)
		}
		if fc != "0" {
			t.Errorf("archiver of %s after the restore: failed_count %s, want 0", p.Ref, fc)
			return
		}
		partial, _ = filepath.Glob(filepath.Join(wal, "*.partial"))
		if len(partial) == 0 {
			return
		}
		if time.Now().After(deadline) {
			ready, _ := filepath.Glob(filepath.Join(wal, "archive_status", "*.partial.ready"))
			t.Errorf("pg_wal of %s holds %v two minutes after the restore (still marked ready: %v)", p.Ref, partial, ready)
			return
		}
		switchWAL(t, p)
		if _, err := adminSQL(t, p, "checkpoint"); err != nil {
			t.Fatalf("checkpoint in %s: %v", p.Ref, err)
		}
	}
}

// withStore runs fn on the control-plane store, as the daemon reaches it.
func withStore(t testing.TB, fn func(context.Context, *store.Store)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(paths.CPDir(), "sock"))
	if err != nil {
		t.Fatalf("control-plane store: %v", err)
	}
	defer st.Close()
	fn(ctx, st)
}

// segNo is a segment's number within its timeline (its last 16 hex digits).
func segNo(t testing.TB, seg string) uint64 {
	t.Helper()
	if len(seg) != 24 {
		t.Fatalf("%q is not a segment name", seg)
	}
	n, err := strconv.ParseUint(seg[8:], 16, 64)
	if err != nil {
		t.Fatalf("%q is not a segment name", seg)
	}
	return n
}

// timelineRows lists b's timelines in state.
func timelineRows(b backupsJSON, state string) []tliJSON {
	return slices.DeleteFunc(slices.Clone(b.Timelines), func(x tliJSON) bool { return x.State != state })
}

// newestRecorded is the highest recorded timeline of b.
func newestRecorded(t testing.TB, b backupsJSON) int {
	t.Helper()
	n := 0
	for _, x := range timelineRows(b, "recorded") {
		n = max(n, x.Timeline)
	}
	if n == 0 {
		t.Fatalf("project %s has no recorded timeline", b.Ref)
	}
	return n
}

// repoArchive is the repository's archive directory of stanza
// (archive/<stanza>/<archive id>), read from an archived segment's path.
func repoArchive(t testing.TB, ref, stanza string) string {
	t.Helper()
	for _, f := range repoFiles(t, ref) {
		p := strings.Split(f, "/")
		if len(p) == 5 && p[0] == "archive" && p[1] == stanza && strings.HasSuffix(p[4], ".zst") {
			return strings.Join(p[:3], "/")
		}
	}
	t.Fatalf("no archived segment of %s in the repository", ref)
	return ""
}

// phaseR is the id of p's recovery start (pg-<ref> labelled phase R), "" when
// there is none.
func phaseR(t testing.TB, p Project) string {
	t.Helper()
	return strings.TrimSpace(docker(t, "ps", "-aq", "--no-trunc", "--filter", "name=^"+pgName(p)+"$", "--filter", "label=supapace.phase=R"))
}

// exists says whether a container with this id is still on the node.
func exists(t testing.TB, id string) bool {
	t.Helper()
	r, err := run(cmdTimeout, nil, "docker", "inspect", "-f", "{{.Id}}", id)
	if err != nil {
		t.Fatal(err)
	}
	return r.code == 0
}

// waitReplicated waits until p's newest set is replicated and listed.
func waitReplicated(t testing.TB, p Project) setJSON {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Minute); ; time.Sleep(5 * time.Second) {
		b := backups(t, p.Ref)
		if len(b.Sets) > 0 && b.Sets[0].Replicated && b.Sets[0].ListedAt != "" {
			return b.Sets[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("the newest set of %s is not completely off-site within 15 minutes: %+v", p.Ref, b.Sets)
		}
	}
}

// holdQuiet is holdDaemon at a moment when no push of p is queued or
// running: a job container outlives the daemon and would take spool entries
// during the hold, and a queued one runs as soon as the hold ends. Up to five
// tries, each after the push in flight has been recorded.
func holdQuiet(t testing.TB, p Project) (release func()) {
	t.Helper()
	for attempt := 1; ; attempt++ {
		release := holdDaemon(t)
		var busy string
		withStore(t, func(ctx context.Context, st *store.Store) {
			j, ok, err := st.LastJob(ctx, p.Ref, "push")
			if err != nil {
				t.Fatalf("last push job of %s: %v", p.Ref, err)
			}
			if ok && (j.State == "queued" || j.State == "running") {
				busy = j.State
			}
		})
		if busy == "" {
			return release
		}
		release()
		if attempt == 5 {
			t.Fatalf("a push of %s was %s at each of five holds", p.Ref, busy)
		}
		waitPush(t, p.Ref)
	}
}

// forceFull makes the backup runner take a full backup of p now: a spool
// entry the repository refuses is quarantined and one forced full follows (at
// most one a UTC day for a project). It returns the new set, newest first.
func forceFull(t testing.TB, p Project) setJSON {
	t.Helper()
	n := len(backups(t, p.Ref).Sets)
	mustUID(t, p, `head -c 65536 /dev/urandom > /tmp/reach-q && cd `+spoolInPG+` && cp /tmp/reach-q .reach-q && mv .reach-q 0000000100000000000000F0`)
	for deadline := time.Now().Add(10 * time.Minute); ; time.Sleep(5 * time.Second) {
		if b := backups(t, p.Ref); len(b.Sets) > n {
			return b.Sets[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no forced full backup of %s within 10 minutes of a quarantine", p.Ref)
		}
	}
}

// utc is a time as a restore target: RFC 3339, whole seconds, UTC.
func utc(tm time.Time) string { return tm.UTC().Format(time.RFC3339) }

// between waits so that the instant returned lies strictly after everything
// committed before the call and strictly before everything committed after it.
func between() time.Time {
	time.Sleep(1500 * time.Millisecond)
	at := time.Now().Truncate(time.Second)
	time.Sleep(1500 * time.Millisecond)
	return at
}

// rowsPath reads public.reach_rows through the gateway.
const rowsPath = "/rest/v1/reach_rows?select=v"

// rows is the values of public.reach_rows in p, in order, read as postgres.
func rows(t testing.TB, p Project) string {
	t.Helper()
	return strings.Join(strings.Fields(mustSQL(t, p, "postgres", "select v from public.reach_rows order by v")), ",")
}

func addRow(t testing.TB, p Project, v string) {
	t.Helper()
	mustSQL(t, p, "postgres", "create table if not exists public.reach_rows(v text); grant select on public.reach_rows to anon, service_role; "+
		"insert into public.reach_rows values ('"+v+"'); notify pgrst, 'reload schema'")
}

// archivedOn: after a segment switch and a push, the new segment lies on
// timeline tli and is in p's repository — archiving goes on after a restore.
func archivedOn(t testing.TB, p Project, tli int) {
	t.Helper()
	seg := switchWAL(t, p)
	if seg[:8] != fmt.Sprintf("%08X", tli) {
		t.Errorf("after the restore %s writes segment %s, not on timeline %d", p.Ref, seg, tli)
	}
	b := waitPush(t, p.Ref)
	if archived(repoFiles(t, p.Ref), b.Stanza, seg) == "" {
		t.Errorf("segment %s written after the restore is not in the repository of %s", seg, p.Ref)
	}
}

// pwStatement matches a statement that sets a role's password, or a password
// verifier, in a log or the statement statistics.
var pwStatement = regexp.MustCompile(`(?i)\b(alter|create)\s+(role|user)\b[^\n]*\bpassword\b|SCRAM-SHA-256\$`)

// statementsWithPassword are the statements of the statistics, read as
// postgres, that set a role's password (the reading statement left out).
func statementsWithPassword(t testing.TB, p Project) []string {
	t.Helper()
	out := mustSQL(t, p, "postgres", `select replace(query, E'\n', ' ') from extensions.pg_stat_statements
 where query ~* '(alter|create)\s+(role|user)' and query not like '%pg_stat_statements%'`)
	var hit []string
	for line := range strings.Lines(out) {
		if pwStatement.MatchString(line) {
			l := hide(strings.TrimSpace(line))
			hit = append(hit, l[:min(80, len(l))])
		}
	}
	return hit
}

// listed: a statement holding mark is in p's statement statistics (as postgres).
func listed(t testing.TB, p Project, mark string) bool {
	t.Helper()
	return mustSQL(t, p, "postgres", "select count(*) from extensions.pg_stat_statements where query like '%"+mark+"%' and query not like '%pg_stat_statements%'") != "0"
}

// recoveries is the number of recover jobs (step T7) restore id ran.
func recoveries(t testing.TB, id int64) int {
	t.Helper()
	var n int
	withStore(t, func(ctx context.Context, st *store.Store) {
		var err error
		if n, err = st.CountJobs(ctx, id, "T7", 0); err != nil {
			t.Fatalf("recover jobs of restore %d: %v", id, err)
		}
	})
	return n
}

// dropAuthenticator removes the platform's PostgREST login role from p's
// database and gets that change into the repository: no re-key of a restore
// to the end of the archive can then succeed.
func dropAuthenticator(t testing.TB, p Project) {
	t.Helper()
	if _, err := adminSQL(t, p, "reassign owned by authenticator to postgres; drop owned by authenticator; drop role authenticator"); err != nil {
		t.Fatalf("dropping authenticator in %s: %v", p.Ref, err)
	}
	switchWAL(t, p)
	waitPush(t, p.Ref)
}

// failingRestore is a restore of p to the end of the archive after
// dropAuthenticator: it ends failed within its five attempts — at most five
// recoveries, not looping — with the re-key's own error and the project left
// restoring. It returns the operation.
func failingRestore(t testing.TB, p Project) resultOp {
	t.Helper()
	dropAuthenticator(t, p)
	id, e := submitRestore(t, p.Ref, "--to", "latest")
	if id == 0 {
		t.Fatalf("restore refused: %s %q", e.Code, hide(e.Message))
	}
	op := endOf(t, id, restoreWait)
	if op.State != "failed" || !strings.Contains(op.LastError, "password of authenticator") {
		t.Fatalf("a restore whose re-key cannot succeed: %s after %d attempts at step %q: %s; want failed with the re-key's error",
			op.State, op.Attempts, op.Step, hide(op.LastError))
	}
	// Each pass's failed re-key costs one attempt; a parked wait gives its
	// attempt back. So five passes, each with its recovery — not one, not more.
	if n := recoveries(t, id); n != 5 {
		t.Errorf("the failed restore ran %d recoveries, want 5 (one a pass, five attempts)", n)
	}
	if !strings.Contains(op.LastError, "the project stays restoring") {
		t.Errorf("its last error does not say the state it leaves: %s", hide(op.LastError))
	}
	if s := projectState(t, p.Ref); s != "restoring" {
		t.Errorf("after the failed restore the project is %s, want restoring", s)
	}
	return op
}

// ───────── test 30 ─────────

// TestReach30_Restore: the rules of a restore request, the recovery start,
// the kill between promotion and re-key, targets of each kind, the spool
// pushed empty before the wipe and the shortfall, a restored configuration
// file, the re-key on restored content, failed restores and the ways out of
// them, and (with the stand-in) the off-site source. Each sub-test says what
// makes it fail.
func TestReach30_Restore(t *testing.T) {
	needBackups(t)
	t.Run("refusals", restoreRefusals)
	t.Run("recovery_start", recoveryStart)
	for _, fp := range []string{"T7", "T8"} {
		t.Run("killed_at_"+fp, func(t *testing.T) { killedAt(t, fp, false) })
	}
	t.Run("time_and_position", timeAndPosition)
	t.Run("spool_and_shortfall", spoolAndShortfall)
	t.Run("restored_settings_file", restoredSettingsFile)
	t.Run("rekey_on_restored_content", rekeyOnRestoredContent)
	t.Run("failed_restore_restart_and_delete", failedRestoreDelete)
	t.Run("failed_restore_retry_and_supersede", failedRestoreSupersede)
	t.Run("offsite", func(t *testing.T) {
		needStandin(t)
		t.Run("killed_at_T8", func(t *testing.T) { killedAt(t, "T8", true) })
		t.Run("stray_history_and_source_rule", strayHistoryAndSource)
		t.Run("concurrent_fetches", concurrentFetches)
	})
}

// restoreRefusals: a target before the window and one in the future are
// out_of_window with the window's bounds; a project at its disk quota is
// refused, and accepted after a restart with a larger quota (the control of
// both refusals: the same project's restore then completes). Fails if a
// target outside the window, or a full disk, is accepted.
func restoreRefusals(t *testing.T) {
	S := restoreScratch(t, "--disk-quota", "1g")
	waitPush(t, S.Ref) // the window's end is the last complete push
	out, _ := cli(t, "project", "backups", S.Ref)
	var b struct {
		Window bounds `json:"window"`
	}
	decode(t, "project backups", out, &b)
	w := b.Window
	if w.First == nil || w.Last == nil {
		t.Fatalf("window of %s: %+v, want both bounds", S.Ref, w)
	}
	from, err := time.Parse(time.RFC3339Nano, *w.First)
	if err != nil {
		t.Fatalf("window from %q: %v", *w.First, err)
	}
	for _, to := range []time.Time{from.Add(-time.Minute), time.Now().Add(time.Hour)} {
		e := wantRefused(t, S.Ref, "out_of_window", "; see 'supapace project backups "+S.Ref+"'", "--to", utc(to))
		if e.Window == nil || e.Window.First == nil || *e.Window.First != *w.First || e.Window.Last == nil {
			t.Errorf("out_of_window for %s: window %+v, want from %s and a known end", utc(to), e.Window, *w.First)
		}
	}

	// The project at its disk quota: the server may stop on a full disk; the
	// restart with a larger quota brings it back.
	asUID(t, S, `dd if=/dev/zero of=/var/lib/postgresql/data/reach-fill bs=1M 2>/dev/null; sync`)
	wantRefused(t, S.Ref, "conflict", "disk quota full; restart the project with a larger quota first", "--to", "latest")
	restartWait(t, S.Ref, "disk_quota_mb=2048")
	restoreDone(t, S, "--to", "latest")
	if _, err := os.Lstat(filepath.Join(paths.ProjectDir(S.Ref), "data", "reach-fill")); err == nil {
		t.Error("the file written after the backup is still in the restored data directory")
	}
}

// recoveryStart: while a restore recovers, its cluster container is the
// recovery start — labelled phase R, no network but loopback; a second
// restore meanwhile is a conflict; a daemon restart removes that container
// (the next attempt makes its own) and the restore still completes on a new
// timeline. Fails if the recovery start has a network, if a second restore
// is accepted while one is open, or if the container survives the restart.
func recoveryStart(t *testing.T) {
	S := restoreScratch(t)
	tl0 := newestRecorded(t, backups(t, S.Ref))
	start := time.Now()
	id, e := submitRestore(t, S.Ref, "--to", "latest")
	if id == 0 {
		t.Fatalf("restore refused: %s %q", e.Code, hide(e.Message))
	}
	wantRefused(t, S.Ref, "conflict", fmt.Sprintf("operation %d (restore) of the project is ", id), "--to", "latest")
	var c string
	for deadline := time.Now().Add(20 * time.Minute); c == ""; time.Sleep(500 * time.Millisecond) {
		c = phaseR(t, S)
		if time.Now().After(deadline) {
			op := opListing(t)[id]
			t.Fatalf("no recovery start of %s seen within 20 minutes (the restore is %s at %q)", S.Ref, op.State, op.Step)
		}
	}
	if nm := strings.TrimSpace(docker(t, "inspect", "-f", "{{.HostConfig.NetworkMode}}", c)); nm != "none" {
		t.Errorf("the recovery start's network mode is %q, want none", nm)
	}
	for _, a := range nsAddrs(t, c) {
		if a.Ifname != "lo" {
			t.Errorf("the recovery start has %s on %s", a.Addr, a.Ifname)
		}
	}
	old := killDaemon(t)
	waitDaemonBack(t, old, 2*time.Minute)
	for deadline := time.Now().Add(2 * time.Minute); exists(t, c); time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			t.Fatalf("the recovery start %s is still on the node 2 minutes after the daemon restarted", c[:12])
		}
	}
	r := resultOf(t, endOf(t, id, restoreWait), time.Since(start))
	if r.NewTimeline <= tl0 || r.PreviousTimeline != tl0 {
		t.Errorf("after the restart the restore ended on timeline %d from %d, want above %d", r.NewTimeline, r.PreviousTimeline, tl0)
	}
	if c := phaseR(t, S); c != "" {
		t.Errorf("a recovery start of %s is left after the restore: %s", S.Ref, c[:12])
	}
	archivedOn(t, S, r.NewTimeline)
}

// killedAt: the daemon is killed at the failpoint restore:fp — before the
// recovery (T7) or between promotion and re-key (T8). After the restart the
// restore completes, no recovery start is left, archiving continues on the
// new timeline. At T8 the promoted recovery start is gone with the daemon's
// restart, so the next attempt promotes the following timeline and the first
// one's is abandoned; at T7 nothing was promoted. Off-site (from the
// stand-in): the history files go up and none is refused by the store (no
// notice offsite-differs or history-rewritten; control: the new timeline's
// history is in the store). Fails if the restore does not complete, if the
// old recovery start is re-keyed, or if a history upload is refused.
func killedAt(t *testing.T, fp string, offsite bool) {
	S := restoreScratch(t)
	args := []string{"--to", "latest"}
	b0 := backups(t, S.Ref)
	if offsite {
		waitReplicated(t, S)
		args = append(args, "--from", "offsite")
	}
	tl0 := newestRecorded(t, b0)
	t.Cleanup(func() { os.Remove(paths.Failpoint()) })
	old := daemonPid(t)
	if err := os.WriteFile(paths.Failpoint(), []byte("restore:"+fp), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	id, e := submitRestore(t, S.Ref, args...)
	if id == 0 {
		t.Fatalf("restore refused: %s %q", e.Code, hide(e.Message))
	}
	waitDaemonBack(t, old, restoreWait)
	if _, err := os.Stat(paths.Failpoint()); !os.IsNotExist(err) {
		t.Fatalf("the failpoint file is still present (%v): the daemon restarted for another reason", err)
	}
	r := resultOf(t, endOf(t, id, restoreWait), time.Since(start))
	b := backups(t, S.Ref)
	n := recoveries(t, id)
	switch {
	case fp == "T8" && (n < 2 || r.NewTimeline <= tl0 || slices.ContainsFunc(timelineRows(b, "abandoned"), func(x tliJSON) bool {
		return x.OperationID != nil && *x.OperationID == id && x.Timeline >= r.NewTimeline
	})):
		t.Errorf("killed between promotion and re-key: %d recoveries, new timeline %d, timelines %+v; want the promoted recovery start not re-keyed — a second recovery, on a timeline above any the first promoted",
			n, r.NewTimeline, b.Timelines)
	case fp == "T7" && (n != 1 || r.NewTimeline != tl0+1):
		t.Errorf("killed before the recovery: %d recoveries, new timeline %d; want one, and timeline %d", n, r.NewTimeline, tl0+1)
	}
	if c := phaseR(t, S); c != "" {
		t.Errorf("a recovery start of %s is left after the restore: %s", S.Ref, c[:12])
	}
	archivedOn(t, S, r.NewTimeline)
	if !offsite {
		return
	}
	if r.From != "offsite" {
		t.Errorf("restore --from offsite reports from %q", r.From)
	}
	key := S.Ref + "/" + repoArchive(t, S.Ref, b.Stanza) + "/" + fmt.Sprintf("%08X.history", r.NewTimeline)
	for deadline := time.Now().Add(10 * time.Minute); ; time.Sleep(5 * time.Second) {
		if _, code := s3(t, "projects-read", "head", key); code == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("control: the history of timeline %d is not in the store within 10 minutes (%s)", r.NewTimeline, key)
		}
	}
	b = backups(t, S.Ref)
	for _, code := range []string{"offsite-differs", "history-rewritten"} {
		if n := noticeCount(b, code); n != noticeCount(b0, code) {
			t.Errorf("notice %s: %d before the restore, %d after: the store refused a history", code, noticeCount(b0, code), n)
		}
	}
}

// timeAndPosition: a restore to a time between two rows has the first only;
// a restore of the earlier timeline to a WAL position after the second row
// has both and not the third. Fails if a target is not honoured.
func timeAndPosition(t *testing.T) {
	S := restoreScratch(t)
	tl0 := newestRecorded(t, backups(t, S.Ref))
	addRow(t, S, "a")
	at := between()
	addRow(t, S, "b")
	lsn, err := adminSQL(t, S, "select pg_current_wal_lsn()")
	if err != nil {
		t.Fatal(err)
	}
	addRow(t, S, "c")
	switchWAL(t, S)
	waitPush(t, S.Ref)

	restoreDone(t, S, "--to", utc(at))
	archiveClean(t, S)
	if got := rows(t, S); got != "a" {
		t.Errorf("restore to %s: rows %q, want a", utc(at), got)
	}
	restoreDone(t, S, "--to", lsn, "--timeline", strconv.Itoa(tl0))
	archiveClean(t, S)
	if got := rows(t, S); got != "a,b" {
		t.Errorf("restore to position %s on timeline %d: rows %q, want a,b", lsn, tl0, got)
	}
}

// spoolAndShortfall: (1) more segments than two push jobs take are spooled
// while the daemon is held; an end-of-archive restore pushes them all before
// the wipe — it reaches the newest and reports no shortfall; control: its
// step T4p ran more than one push job. (2) A spooled segment's body is
// altered before the push and later segments are archived: the end-of-archive
// restore completes with a shortfall naming the newest pushed segment, the
// last one handed to the recovery and the count, and the notice is listed;
// the control is (1), the same restore without the alteration. Fails if the
// spool is not pushed empty before the wipe, or a shortfall goes unreported.
func spoolAndShortfall(t *testing.T) {
	S := restoreScratch(t, "--disk-quota", "3g")
	spooled := func(segs []string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Minute); ; time.Sleep(time.Second) {
			es := spool(t, S.Ref)
			if !slices.ContainsFunc(segs, func(s string) bool { return !spoolHas(es, s) }) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("the switched segments did not all reach the spool within 5 minutes")
			}
		}
	}

	// The scheduler pushes an active project once a minute; the project stops
	// being served at T2. With no push of S queued or running at the hold and
	// T2 less than a minute after the hold ended, at most one scheduled push
	// (56 entries) can run before T2: T4p then finds at least 64 of the 120,
	// more than one job takes. A pass that misses that window is told apart
	// (not counted against the product) and run again.
	for attempt := 1; ; attempt++ {
		release := holdQuiet(t, S)
		var segs []string
		for range 2*bklimit.PushMaxEntries + 8 {
			segs = append(segs, switchWAL(t, S))
		}
		spooled(segs)
		released := time.Now()
		release()
		id, e := submitRestore(t, S.Ref, "--to", "latest")
		if id == 0 {
			t.Fatalf("restore refused: %s %q", e.Code, hide(e.Message))
		}
		inTime := false
		for deadline := released.Add(bklimit.PushInterval); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			if projectState(t, S.Ref) == "restoring" {
				inTime = true
				break
			}
		}
		r := resultOf(t, endOf(t, id, restoreWait), time.Since(released))
		last := segs[len(segs)-1]
		if segNo(t, r.ReachedSegment) < segNo(t, last) || r.ReachedSegment[:8] != last[:8] || string(r.Shortfall) != "null" {
			t.Errorf("end-of-archive restore after %d spooled segments: reached %q, shortfall %s; want at least %s and null",
				len(segs), r.ReachedSegment, r.Shortfall, last)
		}
		if !inTime {
			if attempt == 3 {
				t.Fatalf("control: in %d passes the project never stopped being served within %v of the hold's end", attempt, bklimit.PushInterval)
			}
			t.Logf("pass %d: T2 came later than %v after the hold's end; scheduled pushes may have drained the spool; again", attempt, bklimit.PushInterval)
			continue
		}
		withStore(t, func(ctx context.Context, st *store.Store) {
			if n, err := st.CountJobs(ctx, id, "T4p", 0); err != nil || n < 2 {
				t.Errorf("control: step T4p ran %d push jobs (%v); the spool held more than one job's worth when it began", n, err)
			}
		})
		break
	}

	b0 := backups(t, S.Ref)
	release := holdQuiet(t, S)
	var alt []string
	for range 4 {
		alt = append(alt, switchWAL(t, S))
	}
	spooled(alt)
	// The page header (the first 40 bytes) intact, the first record's bytes not.
	mustUID(t, S, `f=`+spoolInPG+`/"$1"; chmod u+w "$f" && head -c 64 /dev/urandom | dd of="$f" bs=1 seek=48 conv=notrunc 2>/dev/null`, alt[1])
	release()
	r := restoreDone(t, S, "--to", "latest")
	var sf shortfallJSON
	if err := json.Unmarshal(r.Shortfall, &sf); err != nil {
		t.Fatalf("restore after an altered segment: shortfall %s, want an object", r.Shortfall)
	}
	if segNo(t, sf.Expected) < segNo(t, alt[3]) || sf.Expected[:8] != alt[3][:8] || segNo(t, sf.Reached) < segNo(t, alt[0]) ||
		segNo(t, sf.Reached) >= segNo(t, alt[3]) || sf.Segments != int64(segNo(t, sf.Expected)-segNo(t, sf.Reached)) {
		t.Errorf("shortfall %+v: want expected at least %s, reached from %s up to before %s, and the count between them", sf, alt[3], alt[0], alt[3])
	}
	if b := backups(t, S.Ref); noticeCount(b, "restore-shortfall") <= noticeCount(b0, "restore-shortfall") {
		t.Error("the shortfall is not listed as a notice")
	}
}

// restoredSettingsFile: the data directory's postgresql.auto.conf of the
// backed-up set holds a recovery delay of an hour, an end command that sleeps
// an hour and max_connections=3. The restore of that set completes within
// minutes and the project serves. Control: the restored file holds the three
// lines. Fails if a setting of the restored file delays or stops the
// recovery, or keeps the platform from its cluster.
func restoredSettingsFile(t *testing.T) {
	S := restoreScratch(t)
	addRow(t, S, "x")
	const lines = "recovery_min_apply_delay = '1h'\nrecovery_end_command = 'sleep 3600'\nmax_connections = 3\n"
	mustUID(t, S, `printf %s "$1" >> /var/lib/postgresql/data/postgresql.auto.conf`, lines)
	set := forceFull(t, S)
	waitPush(t, S.Ref)
	r := restoreDone(t, S, "--to", "latest")
	if r.Set != set.Label {
		t.Fatalf("the restore used set %s, not the set %s taken with the settings", r.Set, set.Label)
	}
	b, err := os.ReadFile(filepath.Join(paths.ProjectDir(S.Ref), "data", "postgresql.auto.conf"))
	if err != nil || !strings.Contains(string(b), lines) {
		t.Fatalf("control: the restored postgresql.auto.conf does not hold the planted settings (%v)", err)
	}
	if s := stepSeconds(r, "T7") + stepSeconds(r, "T8"); s > 900 {
		t.Errorf("recovery and re-key took %d s with a recovery delay of an hour in the restored file", s)
	}
	if c, _ := checkProject(t, S.Ref); !c.OK {
		t.Errorf("project check after the restore: %s %s", c.Code, hide(c.Message))
	}
	waitREST(t, S, rowsPath, hdr("apikey", S.AnonKey))
}

// rekeyOnRestoredContent: before the archive's end the database gets
// statement logging and full statement tracking on the platform's login role,
// a login trigger and a password check that log what they see, a scheduled
// job, and changed expiry and connection limits of the service roles. The
// restore to the end completes; neither the server log since the restore nor
// the statement statistics (read as postgres) hold a statement that sets a
// role's password; postgres and the PostgREST role log in. Controls: a marked
// statement of the platform's role sent after the restore without the
// platform's session parameters is logged and tracked. Fails if the re-key's
// statements are logged or kept, or if a service role cannot log in.
func rekeyOnRestoredContent(t *testing.T) {
	S := restoreScratch(t)
	addRow(t, S, "x")
	for _, q := range []string{
		"alter role supabase_admin set log_statement = 'all'",
		"alter role supabase_admin set log_min_duration_statement = 0",
		"alter role supabase_admin set pg_stat_statements.track = 'all'",
		"create table public.reach_rk(t timestamptz default pg_catalog.clock_timestamp(), who text, ev text, q text)",
		"grant all on public.reach_rk to public",
		`create function public.reach_rk_login() returns event_trigger language plpgsql as $f$
begin insert into public.reach_rk(who, ev, q) values (session_user, 'login', current_query()); end $f$`,
		"create event trigger reach_rk_login on login execute function public.reach_rk_login()",
		"create extension if not exists pg_tle",
		`create function public.reach_rk_pass(username text, shadow_pass text, password_types pgtle.password_types, validuntil_time timestamptz, validuntil_null boolean)
returns void language plpgsql as $f$
begin
  insert into public.reach_rk(who, ev, q) values (username, 'passcheck', shadow_pass);
  perform pg_catalog.set_config('log_statement', 'all', false);
end $f$`,
		"select pgtle.register_feature('public.reach_rk_pass', 'passcheck')",
		// A system-file setting: not in the WAL, so in the set by forceFull below.
		"alter system set pgtle.enable_password_check = 'on'",
		"alter role authenticator valid until '2000-01-01' connection limit 0",
		"alter role postgres valid until '2000-01-01' connection limit 0",
	} {
		if _, err := adminSQL(t, S, q); err != nil {
			t.Fatalf("restored content: %s: %v", strings.Fields(q)[0]+" "+strings.Fields(q)[1], err)
		}
	}
	if _, err := adminSQL(t, S, "create extension if not exists pg_cron; select cron.schedule('reach_rk', '1 seconds', $$insert into public.reach_rk(ev) values ('cron')$$)"); err != nil {
		t.Fatalf("scheduled job: %v", err)
	}
	set := forceFull(t, S)
	switchWAL(t, S)
	waitPush(t, S.Ref)
	since := time.Now()
	id, e := submitRestore(t, S.Ref, "--to", "latest")
	if id == 0 {
		t.Fatalf("restore refused: %s %q", e.Code, hide(e.Message))
	}
	// The re-key runs in the recovery start, whose log goes with its container:
	// it is read while the container lives.
	var c string
	for deadline := time.Now().Add(20 * time.Minute); c == ""; time.Sleep(200 * time.Millisecond) {
		if c = phaseR(t, S); c == "" && time.Now().After(deadline) {
			t.Fatal("no recovery start seen within 20 minutes")
		}
	}
	follow := inBackground(t, func() result { r, _ := run(restoreWait, nil, "docker", "logs", "-f", c); return r })
	if r := resultOf(t, endOf(t, id, restoreWait), time.Since(since)); r.Set != set.Label {
		t.Fatalf("the restore used set %s, not the set %s that holds the system-file setting", r.Set, set.Label)
	}
	rl, ok := follow(time.Minute)
	if !ok || !strings.Contains(rl.stdout+rl.stderr, "LOG:") {
		t.Fatalf("control: the recovery start's log was not read (ended %v)", ok)
	}

	mark := "reach_rk_mark_" + randHex(6)
	if _, err := sqlAs(t, S, "supabase_admin", "create schema "+mark); err != nil {
		t.Fatal(err)
	}
	nl, err := run(cmdTimeout, nil, "docker", "logs", "--since", strconv.FormatInt(since.Unix()-1, 10), pgName(S))
	if err != nil || nl.code != 0 {
		t.Fatalf("server log of %s: %v", S.Ref, err)
	}
	log := rl.stdout + rl.stderr + nl.stdout + nl.stderr
	if !strings.Contains(log, mark) {
		t.Error("control: a statement of the platform's role is not logged; the log proves nothing")
	}
	if !listed(t, S, mark) {
		t.Error("control: a statement of the platform's role is not tracked; the statistics prove nothing")
	}
	for line := range strings.Lines(log) {
		if pwStatement.MatchString(line) {
			t.Errorf("the server log holds a statement that sets a password: %.80s", hide(line))
		}
	}
	if hits := statementsWithPassword(t, S); len(hits) != 0 {
		t.Errorf("the statement statistics hold statements that set a password: %q", hits)
	}
	// The restored system file turns the password check on; the re-key's
	// statements must not have gone through it. Control (after the log and
	// statistics checks: it is a password statement): one now does.
	passchecks := "select count(*) from public.reach_rk where ev = 'passcheck'"
	if n := mustSQL(t, S, "postgres", passchecks); n != "0" {
		t.Errorf("the re-key's password statements went through the restored password check (%s rows)", n)
	}
	ctl := "reach_rk_ctl_" + randHex(6)
	if _, err := adminSQL(t, S, "create role "+ctl+" password '"+randHex(12)+"'; drop role "+ctl); err != nil {
		t.Fatalf("control statement: %v", err)
	}
	if n := mustSQL(t, S, "postgres", passchecks+" and who = '"+ctl+"'"); n == "0" {
		t.Error("control: the restored password check is not in force; the case proves nothing")
	}
	if got := mustSQL(t, S, "postgres", "select 1"); got != "1" {
		t.Errorf("postgres after the restore: %q", got)
	}
	if got := mustSQL(t, S, "authenticator", "select 1"); got != "1" {
		t.Errorf("authenticator after the restore: %q", got)
	}
	waitREST(t, S, rowsPath, hdr("apikey", S.AnonKey))
}

// failedRestoreDelete: a restore whose re-key can never succeed (the PostgREST
// role dropped before the archive's end) ends failed after its five attempts
// with the re-key's own error; a timeline its attempts promoted is abandoned
// and a restore following it is refused; the project, left restoring,
// refuses a restart and accepts a delete. Fails if the restore loops or ends
// otherwise, if an abandoned timeline is followed, if a restart is accepted,
// or if the delete is refused.
func failedRestoreDelete(t *testing.T) {
	S := restoreScratch(t)
	failingRestore(t, S)
	ab := timelineRows(backups(t, S.Ref), "abandoned")
	if len(ab) == 0 {
		t.Fatal("no abandoned timeline after five promoted attempts")
	}
	n := strconv.Itoa(ab[0].Timeline)
	wantRefused(t, S.Ref, "conflict", "timeline "+n+" is not a recorded timeline", "--to", "latest", "--timeline", n)
	out, code := cli(t, "project", "restart", S.Ref)
	var e errorJSON
	decode(t, "project restart", out, &e)
	if code != 1 || e.Code != "conflict" || !strings.Contains(e.Message, "it is restoring") {
		t.Errorf("restart of a project left restoring: exit %d, %s %q; want a conflict", code, e.Code, hide(e.Message))
	}
	deleteResult(t, S)
}

// failedRestoreSupersede: a second such failed restore is continued by op
// retry (it runs again, and fails again); a restore of the recorded timeline
// to a time before the drop then supersedes it — not held by the failed
// restore's slot, read locally although the failed attempts promoted
// timelines whose histories the repository holds — and brings the row and the
// PostgREST role back. Fails if op retry does not run the restore again, or
// if the superseding restore fails, waits on the slot or goes off-site.
func failedRestoreSupersede(t *testing.T) {
	S := restoreScratch(t)
	tl0 := newestRecorded(t, backups(t, S.Ref))
	addRow(t, S, "before")
	at := between()
	first := failingRestore(t, S)
	out, code := cli(t, "op", "retry", strconv.FormatInt(first.ID, 10), "--no-wait")
	if code != 0 {
		t.Fatalf("op retry %d: exit %d %s", first.ID, code, hide(out))
	}
	ran := false
	for deadline := time.Now().Add(2 * time.Minute); !ran; time.Sleep(time.Second) {
		o := opListing(t)[first.ID]
		ran = o.State == "running" || o.State == "pending" || o.State == "waiting_job"
		if time.Now().After(deadline) {
			t.Fatalf("after op retry the restore is still %s", o.State)
		}
	}
	if again := endOf(t, first.ID, restoreWait); again.State != "failed" {
		t.Fatalf("the retried restore ended %s, want failed again: %s", again.State, hide(again.LastError))
	}
	r := restoreDone(t, S, "--to", utc(at), "--timeline", strconv.Itoa(tl0))
	archiveClean(t, S)
	if old := endOf(t, first.ID, time.Second); old.State != "superseded" {
		t.Errorf("the failed restore is %s after a new restore, want superseded", old.State)
	}
	ab := timelineRows(backups(t, S.Ref), "abandoned")
	if len(ab) == 0 {
		t.Fatal("control: the failed restore left no abandoned timeline; nothing could have sent the new one off-site")
	}
	if r.From != "local" || r.Seeded || r.NewTimeline <= slices.MaxFunc(ab, func(a, b tliJSON) int { return a.Timeline - b.Timeline }).Timeline {
		t.Errorf("superseding restore: from %q, seeded %v, timeline %d; want local, not seeded, above the abandoned %v", r.From, r.Seeded, r.NewTimeline, ab)
	}
	if got := rows(t, S); got != "before" {
		t.Errorf("rows after the superseding restore: %q, want before", got)
	}
	waitREST(t, S, rowsPath, hdr("apikey", S.AnonKey))
}

// strayHistoryAndSource: a history file of a timeline the store does not
// record, planted in the repository, sends the restore off-site (control:
// every other restore of this test reads locally). After that restore, which
// seeded the repository, a restore of the older set is read from off-site
// without being asked and refused with --from local. Fails if the stray
// history is trusted, or if a set older than the seeding is read locally.
func strayHistoryAndSource(t *testing.T) {
	S := restoreScratch(t)
	waitReplicated(t, S)
	b := backups(t, S.Ref)
	tl0 := newestRecorded(t, b)
	// A commit on tl0 after the second restore's target (the set's stop + 2 s):
	// a restore to a time no commit follows does not reach its target.
	set0 := b.Sets[0]
	stop0, err := time.Parse(time.RFC3339Nano, set0.Stop)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(stop0.Add(3 * time.Second)))
	addRow(t, S, "x")
	switchWAL(t, S)
	stray := filepath.Join(repoDir(S.Ref), repoArchive(t, S.Ref, b.Stanza), fmt.Sprintf("%08X.history", tl0+5))
	if err := os.WriteFile(stray, []byte(fmt.Sprintf("%d\t0/3000000\tno recovery target specified\n", tl0)), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(stray, S.UID, S.UID); err != nil {
		t.Fatal(err)
	}
	r := restoreDone(t, S, "--to", "latest")
	if r.From != "offsite" || !r.Seeded {
		t.Fatalf("restore with a stray history in the repository: from %q, seeded %v; want offsite, seeded", r.From, r.Seeded)
	}
	if r.Set != set0.Label {
		t.Fatalf("the restore used set %s, not %s, the one a commit follows", r.Set, set0.Label)
	}

	sets := backups(t, S.Ref).Sets
	i := slices.IndexFunc(sets, func(s setJSON) bool { return s.Label == r.Set })
	if i < 0 {
		t.Fatalf("set %s is not listed", r.Set)
	}
	stop, err := time.Parse(time.RFC3339Nano, sets[i].Stop)
	if err != nil {
		t.Fatal(err)
	}
	to, tli := utc(stop.Add(2*time.Second)), strconv.Itoa(sets[i].Timeline)
	wantRefused(t, S.Ref, "conflict", "this backup set is restorable from the off-site store only; restore without --from local",
		"--to", to, "--timeline", tli, "--from", "local")
	if r := restoreDone(t, S, "--to", to, "--timeline", tli); r.From != "offsite" {
		t.Errorf("a restore of a set older than the seeding read from %q, want offsite", r.From)
	}
	archiveClean(t, S)
}

// concurrentFetches: two restores with --from offsite at once; one project's
// off-site record holds forged rows of valid segment names past its
// repository quota. That restore ends failed with fetch_too_large before its
// data directory is touched, with the notice; the other completes. Fails if a
// fetch larger than the quota is started, or one project's refusal stops the
// other's restore.
//
// As built the record grows only by replication and by a rebuild after a
// control-plane recovery, so the forged rows are recorded here the way a
// replication job's result is (store.RecordUploads), with budgets that pause
// nothing.
func concurrentFetches(t *testing.T) {
	quota := []string{"--disk-quota", "1g", "--upload-per-day", "16g", "--upload-objects-per-day", "1000000"}
	S := restoreScratch(t, quota...)
	E, eid := extraProject(t, quota...)
	t.Cleanup(func() { leaveRestoring(t, E.Ref) }) // before extraProject's own
	waitDone(t, "second project", eid)
	E = loadProject(t, E.Ref, E.Issuer, E.IssuerKID)
	waitReplicated(t, S)
	waitReplicated(t, E)

	b := backups(t, S.Ref)
	dir := repoArchive(t, S.Ref, b.Stanza)
	var forged []store.ObjectRow
	for i := range 1024/16 + 8 {
		seg := fmt.Sprintf("00000001%08X%08X", 0x40, i)
		sum := make([]byte, 32)
		rand.Read(sum)
		forged = append(forged, store.ObjectRow{Key: dir + "/" + seg[:16] + "/" + seg + "-" + randHex(20) + ".zst",
			Size: bklimit.SegmentMax, SHA256: sum, VersionID: randHex(16), UploadedAt: time.Now().UTC()})
	}
	withStore(t, func(ctx context.Context, st *store.Store) {
		j, ok, err := st.LastJob(ctx, S.Ref, "replicate")
		if err != nil || !ok || j.Launch <= 0 {
			t.Fatalf("no replication job of %s with a launch number (%v)", S.Ref, err)
		}
		over, err := st.RecordUploads(ctx, S.Ref, store.Uploads{Rows: forged, BudgetBytes: 1 << 50, BudgetObjects: 1 << 30,
			At: time.Now().UTC(), Launch: j.Launch})
		if err != nil || over {
			t.Fatalf("recording the forged rows: over budget %v, %v", over, err)
		}
	})

	b0 := backups(t, S.Ref)
	start := time.Now()
	sid, e1 := submitRestore(t, S.Ref, "--to", "latest", "--from", "offsite")
	xid, e2 := submitRestore(t, E.Ref, "--to", "latest", "--from", "offsite")
	if sid == 0 || xid == 0 {
		t.Fatalf("restores refused: %s %q; %s %q", e1.Code, hide(e1.Message), e2.Code, hide(e2.Message))
	}
	inflated := endOf(t, sid, restoreWait)
	if inflated.State != "failed" || !strings.HasPrefix(inflated.LastError, "fetch_too_large: ") || !strings.Contains(inflated.LastError, "data directory unchanged") {
		t.Errorf("restore of the inflated record: %s at %q: %s; want failed with fetch_too_large and the data directory unchanged",
			inflated.State, inflated.Step, hide(inflated.LastError))
	}
	if noticeCount(backups(t, S.Ref), "fetch-too-large") <= noticeCount(b0, "fetch-too-large") {
		t.Error("the refused fetch raised no notice")
	}
	if r := resultOf(t, endOf(t, xid, restoreWait), time.Since(start)); r.From != "offsite" || !r.Seeded {
		t.Errorf("the other project's restore: from %q, seeded %v; want offsite, seeded", r.From, r.Seeded)
	}
}

// ───────── test 31 ─────────

// drillPoll restores p with args while polling its API: once the project
// stops serving it answers the gateway's project_restarting until the restore
// ends — never a row in between — and after it both keys work.
func drillPoll(t testing.TB, p Project, args ...string) restoreResultJSON {
	t.Helper()
	const path = rowsPath
	stop := pollHost(t, p, path, hdr("apikey", p.AnonKey), 1)
	start := time.Now()
	id, e := submitRestore(t, p.Ref, args...)
	if id == 0 {
		t.Fatalf("drill restore %v refused: %s %q", args, e.Code, hide(e.Message))
	}
	op := endOf(t, id, restoreWait)
	took := time.Since(start)
	got := stop()
	r := resultOf(t, op, took)
	t.Logf("drill: restore %v took %v", args, took.Round(time.Second))
	// 200 … 200, then 503 project_restarting …, then (after the end) 200 ….
	phase, restarting := 0, 0
	for i, g := range got {
		var body struct {
			Code string `json:"code"`
		}
		json.Unmarshal([]byte(g.body), &body)
		switch {
		case g.status == 200 && phase != 1:
		case g.status == 200:
			phase = 2
		case g.status == http.StatusServiceUnavailable && body.Code == "project_restarting" && phase < 2:
			phase, restarting = 1, restarting+1
		default:
			t.Errorf("answer %d of %d during the restore: status %d %q after %d project_restarting answers", i+1, len(got), g.status, redact(brief(g.body)), restarting)
			return r
		}
	}
	if restarting == 0 {
		t.Error("control: no project_restarting answer was seen during the restore")
	}
	for _, k := range []string{p.AnonKey, p.ServiceKey} {
		waitREST(t, p, path, hdr("apikey", k))
	}
	return r
}

// TestReach31_RestoreDrill (drill 1, durations logged): rows before and after
// a target time on timeline L, a Vault secret and a changed password of the
// PostgREST role before it, a forced full on L after the target. Restored to
// the target from the repository: the row before is present, the one after
// absent, the secret decrypts, the platform's login and PostgREST work, the
// API answers project_restarting throughout. A second restore takes a new
// timeline and archiving continues. --timeline L returns to the state before
// the first restore: to a time before the further full (the set before the
// fork, mode none) and to the end (the full taken after the fork, mode
// standby). The newest set is the last restore's full. Off-site: the target
// again with --from offsite, and the full replicated at the end. Fails if a
// target, a secret, a key or a mode is not as stated.
func TestReach31_RestoreDrill(t *testing.T) {
	needBackups(t)
	S := restoreScratch(t)
	L := newestRecorded(t, backups(t, S.Ref))
	secret := "reach-vault-" + randHex(12)
	if _, err := adminSQL(t, S, "select vault.create_secret('"+secret+"', 'reach_drill')"); err != nil {
		t.Fatalf("vault secret: %v", err)
	}
	if _, err := adminSQL(t, S, "alter role authenticator password '"+randHex(16)+"'"); err != nil {
		t.Fatal(err)
	}
	addRow(t, S, "before")
	at := between()
	addRow(t, S, "after")
	mid := between()
	forceFull(t, S)
	switchWAL(t, S)
	waitPush(t, S.Ref)
	checks := func(what, want string) {
		t.Helper()
		if got := rows(t, S); got != want {
			t.Errorf("%s: rows %q, want %q", what, got, want)
		}
		if got, err := adminSQL(t, S, "select decrypted_secret from vault.decrypted_secrets where name = 'reach_drill'"); err != nil || got != secret {
			t.Errorf("%s: the Vault secret does not decrypt (%v)", what, err)
		}
		if c, _ := checkProject(t, S.Ref); !c.OK {
			t.Errorf("%s: the platform's login: %s %s", what, c.Code, hide(c.Message))
		}
	}

	r1 := drillPoll(t, S, "--to", utc(at))
	archiveClean(t, S)
	checks("restore to the target", "before")
	if r1.From != "local" || r1.PreviousTimeline != L {
		t.Errorf("first restore: from %q, previous timeline %d; want local from %d", r1.From, r1.PreviousTimeline, L)
	}

	r2 := drillPoll(t, S, "--to", "latest")
	if r2.NewTimeline <= r1.NewTimeline {
		t.Errorf("second restore: timeline %d, want above %d", r2.NewTimeline, r1.NewTimeline)
	}
	archivedOn(t, S, r2.NewTimeline)

	r3 := drillPoll(t, S, "--to", utc(mid), "--timeline", strconv.Itoa(L))
	archiveClean(t, S)
	checks("--timeline L to a time before the further full", "after,before")
	if r3.Mode != "none" {
		t.Errorf("return with the set before the fork: mode %q, want none", r3.Mode)
	}
	r4 := drillPoll(t, S, "--to", "latest", "--timeline", strconv.Itoa(L))
	checks("--timeline L to its end", "after,before")
	if r4.Mode != "standby" {
		t.Errorf("return with the full taken after the fork: mode %q, want standby", r4.Mode)
	}
	if b := backups(t, S.Ref); len(b.Sets) == 0 || b.Sets[0].Timeline != r4.NewTimeline {
		t.Errorf("the newest set is not a full of the last restore's timeline %d: %+v", r4.NewTimeline, b.Sets)
	}

	t.Run("offsite", func(t *testing.T) {
		needStandin(t)
		r := drillPoll(t, S, "--to", utc(at), "--timeline", strconv.Itoa(L), "--from", "offsite")
		archiveClean(t, S)
		checks("restore to the target from the off-site store", "before")
		if r.From != "offsite" {
			t.Errorf("restore --from offsite reports from %q", r.From)
		}
		start := time.Now()
		set := waitReplicated(t, S)
		if set.Timeline != r.NewTimeline {
			t.Errorf("the replicated newest set lies on timeline %d, want the last restore's %d", set.Timeline, r.NewTimeline)
		}
		t.Logf("drill: the last restore's full was off-site %v after the restore", time.Since(start).Round(time.Second))
	})
}

// ───────── test 32 ─────────

// TestReach32_Switch: a project made as before backups (fixture: project
// create --layout 1 on a development node; the grant a cluster of that
// release lacked is revoked) is adopted unchanged by a daemon restart, then
// switched by one restart. Each sub-test says what makes it fail.
func TestReach32_Switch(t *testing.T) {
	needBackups(t)

	// Fails if the daemon re-creates the project's cluster, if the switch
	// leaves no stanza, set or push, if the API stays down until the first
	// backup ends, if the grant finding stays, if a second restart takes a
	// second first backup, or if the statement statistics keep a password
	// statement (control: a marked one was listed before the switch).
	t.Run("switch", func(t *testing.T) {
		S := fixtureScratch(t, "--layout", "1")
		addRow(t, S, "x")
		if l := layoutOf(t, S.Ref); l != 1 {
			t.Fatalf("control: the fixture is at layout %d", l)
		}
		if _, err := adminSQL(t, S, "revoke pg_read_all_settings from "+backupRole); err != nil {
			t.Fatal(err)
		}
		finding := func() bool {
			c, _ := checkProject(t, S.Ref)
			return slices.ContainsFunc(c.Drift, func(d driftJSON) bool {
				return d.Name == "memberships-reserved" && strings.Contains(d.Detail, "pg_read_all_settings")
			})
		}
		if !finding() {
			t.Fatal("control: project check lists no finding for the missing grant")
		}
		mark := "reach_pw_" + randHex(6)
		if _, err := sqlAs(t, S, "supabase_admin", "create role "+mark+" password '"+randHex(12)+"'"); err != nil {
			t.Fatal(err)
		}
		if !listed(t, S, mark) {
			t.Fatal("control: a password statement of the platform's role is not in the statement statistics")
		}

		id := strings.Fields(containerState(t, pgName(S)))[0]
		old := killDaemon(t)
		waitDaemonBack(t, old, 2*time.Minute)
		// Watched for a minute, past the adoption round: a check that answers
		// says nothing about a re-creation the round makes after it.
		for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
			if strings.Fields(containerState(t, pgName(S)))[0] != id {
				t.Fatal("the daemon restart re-created the cluster of a layout-1 project")
			}
		}
		if c, _ := checkProject(t, S.Ref); !c.OK {
			t.Errorf("project check after the daemon restart: %s %s", c.Code, hide(c.Message))
		}
		if l := layoutOf(t, S.Ref); l != 1 {
			t.Errorf("after the daemon restart the project is at layout %d, want 1 until a restart", l)
		}

		out, code := cli(t, "project", "restart", S.Ref, "--no-wait")
		var m mutationJSON
		decode(t, "project restart", out, &m)
		if code != 0 {
			t.Fatalf("project restart: exit %d", code)
		}
		sawBackup, servedDuring := false, false
		for deadline := time.Now().Add(restoreWait); ; time.Sleep(500 * time.Millisecond) {
			if jobRunning(t, jobName(S.Ref, "backup")) != "" {
				sawBackup = true
				resp, err := gatewayRoundTrip(t, S, "GET", rowsPath, hdr("apikey", S.AnonKey), nil, netip.Addr{})
				servedDuring = servedDuring || err == nil && resp.StatusCode == 200
			}
			if o := opListing(t)[m.OperationID]; o.State == "done" || o.State == "failed" || o.State == "aborted" {
				if o.State != "done" {
					t.Fatalf("the switching restart ended %s at %q: %s", o.State, o.Step, hide(o.LastError))
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the switching restart did not end")
			}
		}
		if !sawBackup {
			t.Error("control: no backup job of the switch was seen running")
		} else if !servedDuring {
			t.Error("the project's API did not answer while its first backup ran")
		}
		if l := layoutOf(t, S.Ref); l != 2 {
			t.Fatalf("after the restart the project is at layout %d, want 2", l)
		}
		b := waitPush(t, S.Ref)
		if b.Stanza == "" || len(b.Sets) != 1 || b.Push.LastOK == nil {
			t.Errorf("after the switch: stanza %q, %d sets, last push %v; want a stanza, one set, pushes", b.Stanza, len(b.Sets), b.Push.LastOK)
		}
		if finding() {
			t.Error("the grant finding is still listed after the switch")
		}
		if hits := statementsWithPassword(t, S); len(hits) != 0 {
			t.Errorf("after the switch the statement statistics hold %q", hits)
		}
		restartWait(t, S.Ref)
		if b2 := backups(t, S.Ref); b2.Stanza != b.Stanza || len(b2.Sets) != len(b.Sets) {
			t.Errorf("a second restart: stanza %q → %q, sets %d → %d; want nothing made twice", b.Stanza, b2.Stanza, len(b.Sets), len(b2.Sets))
		}
	})

	// Fails if a switch whose first backup failed is not completed by the next
	// restart, or if the failure stops the project from serving.
	t.Run("first_backup_failed", func(t *testing.T) {
		S := fixtureScratch(t, "--layout", "1")
		addRow(t, S, "x")
		mustUID(t, S, `ln -s /proc/self/environ /var/lib/postgresql/data/reach-link`)
		out, code := cli(t, "project", "restart", S.Ref, "--no-wait")
		var m mutationJSON
		decode(t, "project restart", out, &m)
		if code != 0 {
			t.Fatalf("project restart: exit %d", code)
		}
		if op := endOf(t, m.OperationID, restoreWait); op.State != "failed" {
			t.Fatalf("a switch whose first backup cannot be taken ended %s", op.State)
		}
		if b := backups(t, S.Ref); len(b.Sets) != 0 || projectState(t, S.Ref) != "active" {
			t.Fatalf("after the failed switch: %d sets, project %s; want none, active", len(b.Sets), projectState(t, S.Ref))
		}
		waitREST(t, S, rowsPath, hdr("apikey", S.AnonKey))
		mustUID(t, S, `rm -f /var/lib/postgresql/data/reach-link`)
		restartWait(t, S.Ref)
		if b := waitPush(t, S.Ref); b.Stanza == "" || len(b.Sets) != 1 {
			t.Errorf("after the next restart: stanza %q, %d sets; want the switch completed", b.Stanza, len(b.Sets))
		}
	})
}
