package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Raises of new codes racing for a subject's last rows: the bound holds.
func TestRaiseAlert_ConcurrentRaisesKeepTheSubjectBound(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for i := 0; i < maxAlertsPerSubject-4; i++ {
		must(t, s.RaiseAlert(ctx, "node", fmt.Sprintf("old-%d", i), "warn", nil))
	}
	errs := race(16, func(i int) error { return s.RaiseAlert(ctx, "node", fmt.Sprintf("new-%d", i), "warn", nil) })
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrConflict):
			t.Fatal(err)
		}
	}
	if n := count(t, s, "select count(*) from alert where subject = 'node'"); ok != 4 || n != maxAlertsPerSubject {
		t.Fatalf("%d raises accepted, %d rows", ok, n)
	}
	// Control: a raise of a code the subject holds is accepted at the bound.
	must(t, s.RaiseAlert(ctx, "node", "old-0", "page", nil))
}

// At most 16 logins wait for a re-key; a login already waiting is still
// "queued" at the bound.
func TestSubmitRekey_SixteenLoginsWaitAtMost(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r := newActive(t, s, 1)
	sqlExec(t, s, "insert into operation (ref, kind, state, epoch, generation) values ($1, 'restart', 'running', 1, 1)", r)
	for i := 0; i < maxPendingLogin; i++ {
		if _, queued, err := s.SubmitRekey(ctx, r, fmt.Sprintf("login_%d", i)); err != nil || !queued {
			t.Fatalf("login %d: %v %v", i, queued, err)
		}
	}
	if _, _, err := s.SubmitRekey(ctx, r, "one_more"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a 17th login: %v", err)
	}
	if _, queued, err := s.SubmitRekey(ctx, r, "login_3"); err != nil || !queued {
		t.Fatalf("a waiting login at the bound: %v %v", queued, err)
	}
	if l, _ := s.PendingRekeys(ctx); len(l) != maxPendingLogin {
		t.Fatalf("%d pending", len(l))
	}
}

// A job dated exactly at now is not ahead of it.
func TestPurgeAllowed_AJobDatedAtNowIsNoClockError(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	now := memberDBNow(t, s).Truncate(time.Microsecond)
	p := newActive(t, s, 1)
	must(t, s.EnsureBackupState(ctx, p))
	markDeleted(t, s, p)
	must(t, s.MarkPurged(ctx, p))
	sqlExec(t, s, "update backup_state set rebuild_epoch = 1, offsite_purge = true, offsite_purge_seen_at = $2 where subject = $1", p, now.Add(-30*day))
	j := opsJob(t, s, p, "push", "done", 5, now, `{}`)
	sqlExec(t, s, "update backup_job set started_at = $2, finished_at = $2, created_at = $2 where id = $1", j, now)
	if ok, reason, err := s.PurgeAllowed(ctx, p, 7*day, now); err != nil || !ok || reason != "" {
		t.Fatalf("a job at now: %v %q %v", ok, reason, err)
	}
	if _, _, err := s.PurgeAllowed(ctx, p, 7*day, now.Add(-time.Microsecond)); !errors.Is(err, ErrClock) {
		t.Fatalf("a job a microsecond after now: %v", err)
	}
}

// The operator's --now waives the wait of a flag that is set. Given before
// the flag exists, it waives nothing: the flag set later waits its window.
// Red until SetPurgeWait's --now requires the flag.
func TestSetPurgeWait_NowWithoutTheFlagWaivesNoLaterWait(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	now := memberDBNow(t, s)
	p := newActive(t, s, 1)
	must(t, s.EnsureBackupState(ctx, p))
	sqlExec(t, s, "update backup_state set rebuild_epoch = 1 where subject = $1", p)
	_ = s.SetPurgeWait(ctx, p, false, true) // no flag: nothing to waive
	markDeleted(t, s, p)
	must(t, s.MarkPurged(ctx, p))
	sqlExec(t, s, "update backup_state set offsite_purge = true where subject = $1", p)
	must(t, s.MarkPurgeSeen(ctx, p, now))
	if ok, reason, err := s.PurgeAllowed(ctx, p, 7*day, now); err != nil || ok || reason != "wait" {
		t.Fatalf("a flag first seen now: %v %q %v, want the wait", ok, reason, err)
	}
}

// Migration 4 is additive: every line of a version-3 schema is there after
// it, but the two kind checks it replaces; every new line is a column, a
// constraint or a table it names.
func TestMigration4_ChangesOnlyWhatItNames(t *testing.T) {
	s := v3Store(t)
	newActive(t, s, 1)
	before := strings.Split(migrationSchemaText(t, s), "\n")
	must(t, s.Migrate(context.Background()))
	after := strings.Split(migrationSchemaText(t, s), "\n")
	replaced := regexp.MustCompile(`^constraint (operation operation|backup_job backup_job)_kind_check `)
	had, has := map[string]bool{}, map[string]bool{}
	for _, l := range before {
		had[l] = true
	}
	for _, l := range after {
		has[l] = true
	}
	for _, l := range before {
		if !has[l] && !replaced.MatchString(l) {
			t.Errorf("removed or changed: %s", l)
		}
	}
	columns := map[string]bool{}
	for _, c := range []string{"backup_job launch", "offsite_object launch", "backup_timeline launch", "node conn_alloc",
		"node desc_alloc", "node pass_at", "node clock_hold_until", "project conns", "project settings",
		"project read_only_since", "project rekey_pending", "backup_state full_due", "backup_state last_check_ok",
		"backup_state last_verify_at", "backup_state verify_ok", "backup_state last_expire_at",
		"backup_state last_offsite_expire_at", "backup_state spool_dropped_at", "backup_state canary_at",
		"backup_state deadman_at", "backup_state offsite_purge_seen_at", "backup_set expired_local_at",
		"backup_set offsite_removed_at", "backup_notice sent_count", "backup_notice sent_at"} {
		columns[c] = true
	}
	added := 0
	for _, l := range after {
		if had[l] {
			continue
		}
		added++
		f := strings.Fields(l)
		switch {
		case len(f) < 3:
			t.Errorf("unexpected line: %s", l)
		case f[1] == "restore_point" || f[1] == "alert" || f[1] == "issuance":
		case f[0] == "column" && columns[f[1]+" "+f[2]]:
			delete(columns, f[1]+" "+f[2])
		case f[0] == "constraint" && (replaced.MatchString(l) || f[2] == "backup_timeline_launch_check"):
		default:
			t.Errorf("not named by the migration: %s", l)
		}
	}
	if len(columns) != 0 {
		t.Errorf("columns missing: %v", columns)
	}
	if added == 0 {
		t.Fatal("nothing added")
	}
}

// A pooler member without a pool size runs the default size: at a
// max_connections that cannot hold it, the document is refused as an
// explicit size of five would be. Red until Validate checks the effective
// size.
func TestValidate_TheDefaultPoolSizeMustFitToo(t *testing.T) {
	c := testConfig()
	low := 70 // holds pool size 3 (MaxPoolSize of 20), not the default 5
	if err := (ProjectSettings{Pooler: &PoolerSettings{PoolSize: 3}}).Validate(c, nil, low); err != nil {
		t.Fatalf("control: %v", err)
	}
	if err := (ProjectSettings{Pooler: &PoolerSettings{PoolSize: 5}}).Validate(c, nil, low); !errors.Is(err, ErrConflict) {
		t.Fatalf("an explicit 5: %v", err)
	}
	if err := (ProjectSettings{Pooler: &PoolerSettings{MaxClients: 10}}).Validate(c, nil, low); !errors.Is(err, ErrConflict) {
		t.Fatalf("the default size at max_connections %d: %v", low, err)
	}
}

// The descriptor term at its exact edge: the memory admission of three
// projects, times 2^20, divided by 230.
func TestAdmit_DescriptorTermAtItsEdge(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	newActive(t, s, 1)
	newActive(t, s, 2)
	edge := int64(3*(defaultConfig.MemMB+postgrestMemMB)) << 20 / 230
	mustCreate(t, s, ref(3))
	must(t, s.SetNodeAllocs(ctx, 1<<20, edge-1))
	if _, err := s.Place(ctx, ref(3)); !errors.Is(err, ErrNodeFull) {
		t.Fatalf("one descriptor short: %v", err)
	}
	must(t, s.SetNodeAllocs(ctx, 1<<20, edge))
	mustPlace(t, s, ref(3))
}

// A delivery recorded with an older count never lowers the count sent: the
// row is not pending again for what was already delivered.
func TestMarkAlertSent_AnOlderCountNeverLowersTheCountSent(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		must(t, s.RaiseAlert(ctx, "node", "disk-half", "warn", nil))
	}
	must(t, s.MarkAlertSent(ctx, Alert{Subject: "node", Code: "disk-half", Count: 3}))
	must(t, s.MarkAlertSent(ctx, Alert{Subject: "node", Code: "disk-half", Count: 1}))
	if n := count(t, s, "select sent_count::int from alert where subject = 'node' and code = 'disk-half'"); n != 3 {
		t.Fatalf("sent_count %d", n)
	}
}

// The plan's clock rule: a job dated exactly at now is not ahead of it.
func TestOffsiteExpirePlan_AJobDatedAtNowIsNoClockError(t *testing.T) {
	s := newStore(t, testConfig())
	f := newPlanFix(t, s)
	now := f.now.Truncate(time.Microsecond)
	j := opsJob(t, s, f.r, "check", "done", 2000, now, `{}`)
	sqlExec(t, s, "update backup_job set started_at = $2, finished_at = $2, created_at = $2 where id = $1", j, now)
	if _, err := s.OffsiteExpirePlan(context.Background(), f.r, f.stanza, 7*day, 72*time.Hour, now, 6, 2000); err != nil {
		t.Fatalf("a job at now: %v", err)
	}
	_, err := s.OffsiteExpirePlan(context.Background(), f.r, f.stanza, 7*day, 72*time.Hour, now.Add(-time.Microsecond), 6, 2000)
	wantErr(t, err, ErrClock)
}

// The version uploaded while a set was still at the same location is kept
// for its own sake, not because it is another set's listing or the newest.
func TestPruneInfoVersions_KeepsTheWhileLocalCandidateOfItsOwn(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, _ := bsProject(t, s, 1)
	for i, d := range []time.Duration{0, day, 3 * day, 5 * day} {
		infoRow(t, s, r, "backup.info", fmt.Sprintf("v%d", i), bsT0.Add(d))
	}
	j := opsJob(t, s, r, "backup", "done", 1, bsT0, `{}`)
	sqlExec(t, s, `insert into backup_set (subject, label, tli, start_segment, stop_segment, start_lsn, stop_lsn, start_at, stop_at,
		job_id, replicated, listed_at, expired_local_at) values ($1, '20261110-120000F', 1, $2, $2, '0/1', '0/2', $3, $3, $4, true, $3, $5)`,
		r, bsSeg(1, 1), bsT0, j, bsT0.Add(2*day))
	n, err := s.PruneInfoVersions(ctx, r, bsT0.Add(365*day))
	must(t, err)
	if got := infoVers(t, s, r); n != 1 || fmt.Sprint(got) != "[backup.info:v0 backup.info:v1 backup.info:v3]" {
		t.Fatalf("pruned %d, kept %v", n, got)
	}
}

// An adoption fills a rebuilt row's hash and leaves its number: an existing
// row keeps its own launch.
func TestRecordUploads_AnAdoptionKeepsTheRowsLaunch(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	k := bsSegKey(st, "17-1", bsSeg(1, 1))
	must(t, s.MergeListing(ctx, r, ListingPage{Launch: 5, Rows: []ObjectRow{{Key: k, Size: 10, VersionID: "v1", UploadedAt: bsT0}}, Last: true}, 2))
	bsUpload(t, s, r, Uploads{Launch: 9, Rows: []ObjectRow{bsRow(k, 0xaa, "v1", bsT0)}, At: bsT0})
	var launch int64
	var hashed bool
	must(t, s.pool.QueryRow(ctx, "select launch, sha256 is not null from offsite_object where subject = $1 and key = $2", r, k).Scan(&launch, &hashed))
	if !hashed || launch != 5 {
		t.Fatalf("adopted row: hash %v, launch %d", hashed, launch)
	}
}
