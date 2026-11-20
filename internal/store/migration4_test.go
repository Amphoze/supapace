package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// v3Store returns a store on a database exactly as a version-3 Migrate left
// it, with its node row.
func v3Store(t *testing.T) *Store {
	t.Helper()
	s := v1Store(t)
	for _, name := range migrations[:2] {
		b, err := migrationFiles.ReadFile(name)
		must(t, err)
		sqlExec(t, s, string(b))
	}
	sqlExec(t, s, "update cp_meta set schema_ver = 3")
	return s
}

// checkKinds reads the kinds a check constraint of the form "kind in (…)"
// admits.
func checkKinds(t *testing.T, s *Store, table, name string) []string {
	t.Helper()
	var def string
	must(t, s.pool.QueryRow(context.Background(), "select pg_get_constraintdef(oid) from pg_constraint where conrelid = $1::regclass and conname = $2",
		table, name).Scan(&def))
	var kinds []string
	for _, part := range strings.Split(def, "'")[1:] {
		if part != "" && !strings.ContainsAny(part, "():,= ") {
			kinds = append(kinds, part)
		}
	}
	return kinds
}

// At version 3 both kind checks still hold migration_2.sql's lists, which
// migration_4.sql rewrites with its additions.
func TestMigration4_ConstraintsAtVersion3AreAsExpected(t *testing.T) {
	s := v3Store(t)
	for _, c := range []struct {
		table, name string
		want        []string
	}{
		{"operation", "operation_kind_check", []string{"create", "restart", "delete", "purge", "restore"}},
		{"backup_job", "backup_job_kind_check", []string{"push", "replicate", "stanza-create", "backup", "check", "fetch", "seed", "restore", "recover"}},
	} {
		if got := checkKinds(t, s, c.table, c.name); !slices.Equal(got, c.want) {
			t.Errorf("%s at version 3 admits %v; migration_2.sql's list is %v: a migration after it changed the check, "+
				"and migration_4.sql, which rewrites it from that list, must follow", c.name, got, c.want)
		}
	}
}

// migration4Tables is every table migration_4.sql changes or creates.
var migration4Tables = []string{"operation", "backup_job", "offsite_object", "backup_timeline", "node", "project",
	"backup_state", "backup_set", "backup_notice", "restore_point", "alert", "issuance"}

func TestMigrate_V3ToV4(t *testing.T) {
	s := v3Store(t)
	ctx := context.Background()
	r := newActive(t, s, 1)
	before := migrationSchemaText(t, s, migration4Tables...)
	must(t, s.Migrate(ctx))
	if v := schemaVer(t, s); v != schemaVersion {
		t.Fatalf("schema version %d, want %d", v, schemaVersion)
	}
	if after := migrationSchemaText(t, s, migration4Tables...); after != before {
		t.Fatalf("tables migration 4 does not name changed:\nbefore\n%s\nafter\n%s", before, after)
	}
	for _, tbl := range migration4Tables[9:] {
		if n := count(t, s, "select count(*) from information_schema.tables where table_schema = 'public' and table_name = $1", tbl); n != 1 {
			t.Fatalf("table %s missing", tbl)
		}
	}
	for _, c := range [][2]string{{"backup_job", "launch"}, {"offsite_object", "launch"}, {"backup_timeline", "launch"},
		{"node", "conn_alloc"}, {"node", "desc_alloc"}, {"node", "pass_at"}, {"node", "clock_hold_until"},
		{"project", "conns"}, {"project", "settings"}, {"project", "read_only_since"}, {"project", "rekey_pending"},
		{"backup_state", "full_due"}, {"backup_state", "offsite_purge_seen_at"}, {"backup_set", "expired_local_at"},
		{"backup_set", "offsite_removed_at"}, {"backup_notice", "sent_count"}, {"backup_notice", "sent_at"}} {
		if n := count(t, s, "select count(*) from information_schema.columns where table_name = $1 and column_name = $2", c[0], c[1]); n != 1 {
			t.Fatalf("column %s.%s missing", c[0], c[1])
		}
	}
	if got := checkKinds(t, s, "operation", "operation_kind_check"); !slices.Contains(got, "settings") || !slices.Contains(got, "rekey-login") {
		t.Fatalf("operation kinds %v", got)
	}
	if got := checkKinds(t, s, "backup_job", "backup_job_kind_check"); !slices.Contains(got, "offsite-expire") || len(got) != 13 {
		t.Fatalf("job kinds %v", got)
	}
	p := wantState(t, s, r, "active")
	if p.Config.MemMB != defaultConfig.MemMB {
		t.Fatalf("project after migration: %+v", p)
	}
	var conns, alloc int
	must(t, s.pool.QueryRow(ctx, "select p.conns, n.conn_alloc from project p join node n on n.id = p.node_id where ref = $1", r).Scan(&conns, &alloc))
	if conns != 72 || alloc != 2128 {
		t.Fatalf("conns %d, conn_alloc %d", conns, alloc)
	}
	// A second run changes nothing.
	must(t, s.Migrate(ctx))
}

func TestMigration4_ConnsBackfilledFromStoredSettings(t *testing.T) {
	s := v3Store(t)
	ctx := context.Background()
	want := map[string]int{}
	for i, mc := range []string{"", "200", "40", "51"} {
		r := newActive(t, s, i+1)
		if mc != "" {
			sqlExec(t, s, `update project set config = jsonb_set(config, '{guc,max_connections}', to_jsonb($2::text)) where ref = $1`, r, mc)
		}
		want[r] = map[string]int{"": 72, "200": 152, "40": 2, "51": 3}[mc]
	}
	must(t, s.Migrate(ctx))
	for r, w := range want {
		if got := count(t, s, "select conns from project where ref = $1", r); got != w {
			t.Errorf("%s: conns %d, want %d", r, got, w)
		}
	}
	// A project created after the migration takes its share from its configuration.
	c := defaultConfig
	c.GUC = map[string]string{"max_connections": "300"}
	_, err := s.CreateProject(ctx, NewProject{Ref: ref(9), Name: "demo", Config: c})
	must(t, err)
	if got := count(t, s, "select conns from project where ref = $1", ref(9)); got != 252 {
		t.Fatalf("created at 300: conns %d, want 252", got)
	}
}

func TestMigration4_ExistingObjectRowsTakeZero_RestoreTimelinesANumber(t *testing.T) {
	s := v3Store(t)
	ctx := context.Background()
	r := newActive(t, s, 1)
	must(t, s.EnsureBackupState(ctx, r))
	op := bsOp(t, s, r)
	sqlExec(t, s, `insert into offsite_object (subject, key, size, uploaded_at) values ($1, 'a', 1, now()), ($1, 'b', 1, now())`, r)
	sqlExec(t, s, `insert into backup_timeline (subject, tli, state, op_id) values ($1, 1, 'recorded', null), ($1, 2, 'recorded', $2),
		($1, 3, 'pending', $2)`, r, op)
	must(t, s.Migrate(ctx))
	if n := count(t, s, "select count(*) from offsite_object where subject = $1 and launch = 0", r); n != 2 {
		t.Fatalf("%d object rows at 0, want 2", n)
	}
	tl := count(t, s, "select launch from backup_timeline where subject = $1 and tli = 2", r)
	if tl <= 0 || count(t, s, "select launch from backup_timeline where subject = $1 and tli = 1", r) != 0 ||
		count(t, s, "select launch from backup_timeline where subject = $1 and tli = 3", r) != 0 {
		t.Fatalf("timeline launches: tli 2 at %d", tl)
	}
	stateRows(t, s, jobSubj(1))
	id := submitJ(t, s, pushJ(jobSubj(1)))
	if j := mustNext(t, s, "push", id); j.Launch <= int64(tl) {
		t.Fatalf("first launch after the migration %d, the restore's timeline %d", j.Launch, tl)
	}
	// The default is gone.
	if _, err := s.pool.Exec(ctx, `insert into offsite_object (subject, key, size, uploaded_at) values ($1, 'c', 1, now())`, r); err == nil {
		t.Fatal("an object row without a launch was inserted")
	}
}

func TestNextJob_StampsLaunchInRunOrder(t *testing.T) {
	s := newStore(t, testConfig())
	stateRows(t, s, jobSubj(1), jobSubj(2))
	a := submitJ(t, s, pushJ(jobSubj(1)))
	b := submitJ(t, s, backupJ(jobSubj(2)))
	jb := mustNext(t, s, "backup", b)
	ja := mustNext(t, s, "push", a)
	if jb.Launch <= 0 || ja.Launch <= jb.Launch {
		t.Fatalf("launches: created first %d, picked first %d", ja.Launch, jb.Launch)
	}
	if got := getJob(t, s, a); got.Launch != ja.Launch {
		t.Fatalf("stored launch %d, returned %d", got.Launch, ja.Launch)
	}
	// A queued job has none.
	c := submitJ(t, s, pushJ(jobSubj(1)))
	if got := getJob(t, s, c); got.Launch != 0 {
		t.Fatalf("queued job carries launch %d", got.Launch)
	}
}

// The other lane's pick of the same subject wins the slot: the refused pick
// is "nothing picked", its drawn number is a gap nobody carries, and the next
// pick draws above it.
func TestNextJob_ARefusedPickIsNothingPickedAndCostsOnlyANumber(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	sub := jobSubj(1)
	stateRows(t, s, sub, jobSubj(2))
	submitJ(t, s, pushJ(sub))
	submitJ(t, s, backupJ(sub))
	tx, err := s.pool.Begin(ctx)
	must(t, err)
	won, err := scanJob(tx.QueryRow(ctx, pickJob, "push"))
	if err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, ok, err := s.NextJob(ctx, "backup")
		if err == nil && ok {
			err = errors.New("picked beside the other lane's running job")
		}
		done <- err
	}()
	deadline := time.Now().Add(60 * time.Second)
	for count(t, s, `select count(*) from pg_stat_activity where wait_event_type = 'Lock'
		and query like 'update backup_job set state = ''running''%'`) == 0 {
		if time.Now().After(deadline) {
			tx.Rollback(ctx)
			t.Fatal("the second pick never waited on the slot")
		}
		time.Sleep(20 * time.Millisecond)
	}
	must(t, tx.Commit(ctx))
	must(t, <-done)
	drawn := int64(count(t, s, "select last_value from backup_job_launch"))
	if drawn <= won.Launch {
		t.Fatalf("the refused pick drew %d, the winner holds %d", drawn, won.Launch)
	}
	if n := count(t, s, "select count(*) from backup_job where launch = $1", drawn); n != 0 {
		t.Fatalf("%d job rows carry the refused pick's number", n)
	}
	next := mustNext(t, s, "push", submitJ(t, s, pushJ(jobSubj(2))))
	if next.Launch <= drawn {
		t.Fatalf("next pick %d, not above %d", next.Launch, drawn)
	}
}

func TestTimeline_RecordedDrawsANumber(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op := bsOp(t, s, r)
	_, err := s.BeginRecoveryAttempt(ctx, r, st, op, nil)
	must(t, err)
	if n := count(t, s, "select launch from backup_timeline where subject = $1 and tli = 2", r); n != 0 {
		t.Fatalf("pending timeline at %d", n)
	}
	stateRows(t, s, jobSubj(1))
	before := mustNext(t, s, "push", submitJ(t, s, pushJ(jobSubj(1))))
	must(t, s.ConfirmTimeline(ctx, r, op, 2))
	got := int64(count(t, s, "select launch from backup_timeline where subject = $1 and tli = 2", r))
	if got <= before.Launch {
		t.Fatalf("recorded timeline at %d, a job launched before it at %d", got, before.Launch)
	}
	if n := count(t, s, "select launch from backup_timeline where subject = $1 and tli = 1", r); n != 0 {
		t.Fatalf("timeline 1 at %d", n)
	}
}

func TestTimeline_RecordedWithoutANumberFails(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	op := bsOp(t, s, r)
	_, err := s.BeginRecoveryAttempt(ctx, r, st, op, nil)
	must(t, err)
	_, err = s.pool.Exec(ctx, "update backup_timeline set state = 'recorded' where subject = $1 and tli = 2", r)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.ConstraintName != "backup_timeline_launch_check" {
		t.Fatalf("recorded without a number: %v", err)
	}
	// Accepted at 0: timeline 1, a pending and an abandoned row.
	sqlExec(t, s, "insert into backup_timeline (subject, tli, state, launch) values ($1, 5, 'abandoned', 0), ($1, 6, 'pending', 0)", r)
	if n := count(t, s, "select count(*) from backup_timeline where subject = $1 and launch = 0", r); n != 4 {
		t.Fatalf("%d rows at 0, want 4", n)
	}
	// Control: with a number it is recorded.
	sqlExec(t, s, "update backup_timeline set state = 'recorded', launch = nextval('backup_job_launch') where subject = $1 and tli = 2", r)
}

func TestOffsiteObject_InsertWithoutALaunchFails(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	if _, err := s.pool.Exec(ctx, `insert into offsite_object (subject, key, size, uploaded_at) values ($1, 'k', 1, now())`, r); err == nil {
		t.Fatal("inserted without a launch")
	}
	row := bsRow(bsSegKey(st, "17-1", bsSeg(1, 1)), 1, "v1", bsT0)
	for _, l := range []int64{0, -1} {
		_, err := s.RecordUploads(ctx, r, Uploads{Rows: []ObjectRow{row}, At: bsT0, Launch: l})
		wantErr(t, err, ErrNoLaunch)
		wantErr(t, s.MergeListing(ctx, r, ListingPage{Rows: []ObjectRow{row}, Launch: l}, 1), ErrNoLaunch)
	}
	queued := submitJ(t, s, NewJob{Subject: r, Lane: "backup", Kind: "offsite-expire", DeadlineS: 300})
	wantErr(t, s.MergeUnrecorded(ctx, r, []UnrecordedRow{{Key: row.Key, VersionID: "v1", At: bsT0, Size: 1}}, queued), ErrNoLaunch)
	if n := count(t, s, "select count(*) from offsite_object where subject = $1", r); n != 0 {
		t.Fatalf("%d rows written by refused calls", n)
	}
	if n := count(t, s, "select rebuild_pages from backup_state where subject = $1", r); n != 0 {
		t.Fatal("a refused page moved the markers")
	}
	// Control: with a number each writes its row.
	_, err := s.RecordUploads(ctx, r, Uploads{Rows: []ObjectRow{row}, At: bsT0, Launch: 7})
	must(t, err)
	r2, st2 := bsProject(t, s, 2)
	must(t, s.MergeListing(ctx, r2, ListingPage{Rows: []ObjectRow{{Key: bsSegKey(st2, "17-1", bsSeg(1, 1)), Size: 1, VersionID: "v", UploadedAt: bsT0}}, Last: true, Launch: 8}, 1))
	j := mustNext(t, s, "backup", queued)
	must(t, s.MergeUnrecorded(ctx, r, []UnrecordedRow{{Key: bsSegKey(st, "17-1", bsSeg(1, 2)), VersionID: "v2", At: bsT0, Size: 1}}, queued))
	for _, c := range []struct {
		subject string
		launch  int64
	}{{r, 7}, {r2, 8}, {r, j.Launch}} {
		if n := count(t, s, "select count(*) from offsite_object where subject = $1 and launch = $2", c.subject, c.launch); n != 1 {
			t.Fatalf("%s: %d rows at %d", c.subject, n, c.launch)
		}
	}
}

// Rows take the number of the job whose result recorded them; a row already
// recorded keeps its own.
func TestObjectRows_TakeTheLaunchOfTheJobThatRecordedThem(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	r, st := bsProject(t, s, 1)
	k1, k2, k3 := bsSegKey(st, "17-1", bsSeg(1, 1)), bsSegKey(st, "17-1", bsSeg(1, 2)), bsSegKey(st, "17-1", bsSeg(1, 3))
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(k1, 1, "v1", bsT0)}, At: bsT0, Launch: 10})
	bsUpload(t, s, r, Uploads{Rows: []ObjectRow{bsRow(k1, 1, "v1", bsT0), bsRow(k2, 2, "v2", bsT0)}, At: bsT0, Launch: 11})
	must(t, s.MergeListing(ctx, r, ListingPage{Rows: []ObjectRow{{Key: k2, Size: 10, VersionID: "v2", UploadedAt: bsT0},
		{Key: k3, Size: 10, VersionID: "v3", UploadedAt: bsT0}}, Last: true, Launch: 12}, 1))
	for k, want := range map[string]int{k1: 10, k2: 11, k3: 12} {
		if got := count(t, s, "select launch from offsite_object where subject = $1 and key = $2", r, k); got != want {
			t.Errorf("%s: launch %d, want %d", k, got, want)
		}
	}
}
