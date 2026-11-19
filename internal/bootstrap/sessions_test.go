package bootstrap

import (
	"context"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// TestWriteCanary_MakesTheTableWhenAbsentAndTakesOverAForeignSchema: Run made
// the table; with it gone and a schema supapace made and owned by postgres,
// the write takes the schema over, makes the table and writes row 1; a table
// given to postgres is made again; a second write updates the one row.
func TestWriteCanary_MakesTheTableWhenAbsentAndTakesOverAForeignSchema(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	const state = `select pg_catalog.pg_get_userbyid(n.nspowner)::text || ' ' || coalesce(n.nspacl::text, '-') || ' ' ||
	  coalesce((select pg_catalog.pg_get_userbyid(relowner)::text from pg_catalog.pg_class where oid = pg_catalog.to_regclass('supapace._backup_canary')), '-')
	  from pg_catalog.pg_namespace n where n.nspname = 'supapace'`
	const defined = "supabase_admin {supabase_admin=UC/supabase_admin} supabase_admin"
	if got := c.str(adm, state); got != defined {
		t.Fatalf("after Run: %s", got)
	}
	c.exec(adm, "drop schema supapace cascade")
	pg := c.dial("postgres")
	c.exec(pg, "create schema supapace")
	c.exec(pg, "grant usage on schema supapace to public")
	if got := c.str(adm, state); !strings.HasPrefix(got, "postgres ") || !strings.HasSuffix(got, " -") {
		t.Fatalf("control: %s", got)
	}
	if err := WriteCanary(context.Background(), adm); err != nil {
		t.Fatal(err)
	}
	if got := c.str(adm, state); got != defined {
		t.Fatalf("after the write: %s", got)
	}
	c.exec(adm, "alter table supapace._backup_canary owner to postgres")
	if err := WriteCanary(context.Background(), adm); err != nil {
		t.Fatal(err)
	}
	if got := c.str(adm, state); got != defined {
		t.Fatalf("after the second write: %s", got)
	}
	if got := c.str(adm, `select count(*)::text || ' ' || bool_and(id = 1 and written_at > pg_catalog.now() - interval '1 minute')::text
	  from supapace._backup_canary`); got != "1 true" {
		t.Fatalf("rows: %s", got)
	}
}

// newVerifier returns a password and its verifier for role with a new salt.
func newVerifier(t *testing.T, role string) string {
	t.Helper()
	salt, err := pgsock.ScramSalt([]byte(rnd(32)), rnd(10), role)
	if err != nil {
		t.Fatal(err)
	}
	v, err := pgsock.ScramVerifier(rnd(32), salt)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestRekeyLogin_VerifierFirstThenTerminates: the role's verifier is the first
// statement, then its sessions are ended; another session of the platform
// stays. Another role or a malformed verifier sends nothing.
func TestRekeyLogin_VerifierFirstThenTerminates(t *testing.T) {
	v := newVerifier(t, "postgres")
	stmt, err := verifierStatement(sqlPasswordPostgres, v)
	if err != nil {
		t.Fatal(err)
	}
	conn, rec := recordingConn(t, func(sql string) ([]uint32, [][]string) {
		if sql == sqlTerminateRole {
			return []uint32{16}, [][]string{{"t"}, {"f"}}
		}
		return nil, nil
	})
	res, err := RekeyLogin(context.Background(), conn, "postgres", v)
	if err != nil || res != (RekeyResult{Terminated: 1}) {
		t.Fatalf("%+v %v", res, err)
	}
	if got := rec.statements(); !slices.Equal(got, []string{stmt, sqlTerminateRole}) {
		t.Fatalf("sent %q", got)
	}
	if k := rec.messageKinds(); k[0] != "*pgproto3.Query" {
		t.Fatalf("first message %s", k[0])
	}
	for _, bad := range []struct{ role, v string }{{"supabase_admin", v}, {"authenticator", v}, {"supapace_pooler", v},
		{"postgres", v + "'"}, {"postgres", ""}} {
		conn, rec := recordingConn(t, func(string) ([]uint32, [][]string) { return nil, nil })
		if _, err := RekeyLogin(context.Background(), conn, bad.role, bad.v); err == nil || len(rec.statements()) != 0 {
			t.Errorf("%s %q: %v, sent %q", bad.role, bad.v, err, rec.statements())
		}
	}

	c := startCluster(t)
	adm := c.dial("supabase_admin")
	pg := c.dial("postgres")
	other := c.dial("supabase_admin")
	n, _ := strconv.Atoi(c.str(adm, "select count(*)::text from pg_catalog.pg_stat_activity where usename = 'postgres'"))
	res, err = RekeyLogin(context.Background(), adm, "postgres", v)
	if err != nil || n < 1 || res.Terminated != n || res.LargeObjects != 0 || res.LargeObjectsLeft {
		t.Fatalf("%+v %v", res, err)
	}
	if got := c.str(adm, "select rolpassword from pg_catalog.pg_authid where rolname = 'postgres'"); got != v {
		t.Fatal("the stored verifier is not the new one")
	}
	if _, err := pg.Exec(context.Background(), "select 1"); err == nil {
		t.Fatal("the postgres session was not ended")
	}
	if got := c.str(other, "select current_user::text"); got != "supabase_admin" {
		t.Fatalf("control: the other role's session answers %q", got)
	}
}

// TestRekeyLogin_ReadOnlyLargeObjectsUnlinked: the re-key of the read-only
// login removes the two large objects that role made; a large object of
// postgres and a scheduled job under the read-only role's name stay. For
// postgres no large object is removed.
func TestRekeyLogin_ReadOnlyLargeObjectsUnlinked(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	// A session acting as the read-only role, read-write.
	ro := c.dial("supabase_admin")
	c.exec(ro, "set role supabase_read_only_user")
	c.exec(ro, "set default_transaction_read_only = off")
	c.exec(ro, "select pg_catalog.lo_create(0)")
	c.exec(ro, "select pg_catalog.lo_create(0)")
	pg := c.dial("postgres")
	c.exec(pg, "select pg_catalog.lo_create(0)")
	c.exec(adm, "create extension if not exists pg_cron")
	c.exec(adm, `insert into cron.job (schedule, command, nodename, nodeport, database, username)
	  values ('0 0 1 1 *', 'select 1', '', 5432, 'postgres', 'supabase_read_only_user')`)
	const los = `select string_agg(pg_catalog.pg_get_userbyid(lomowner)::text, ',' order by pg_catalog.pg_get_userbyid(lomowner)::text) from pg_catalog.pg_largeobject_metadata`
	const jobs = "select count(*)::text from cron.job where username = 'supabase_read_only_user'"
	if got := c.str(adm, los); got != "postgres,supabase_read_only_user,supabase_read_only_user" {
		t.Fatalf("control: large objects of %s", got)
	}
	res, err := RekeyLogin(context.Background(), adm, "postgres", newVerifier(t, "postgres"))
	if err != nil || res.LargeObjects != 0 {
		t.Fatalf("postgres: %+v %v", res, err)
	}
	if got := c.str(adm, los); got != "postgres,supabase_read_only_user,supabase_read_only_user" {
		t.Fatalf("after the re-key of postgres: large objects of %s", got)
	}
	res, err = RekeyLogin(context.Background(), adm, "supabase_read_only_user", newVerifier(t, "supabase_read_only_user"))
	if err != nil || res != (RekeyResult{LargeObjects: 2}) {
		t.Fatalf("read-only: %+v %v", res, err)
	}
	if got := c.str(adm, los); got != "postgres" {
		t.Fatalf("after the re-key: large objects of %s", got)
	}
	if got := c.str(adm, jobs); got != "1" {
		t.Fatalf("scheduled jobs of the read-only role: %s", got)
	}

	// Over a recording connection: postgres sends no removal; the removal is
	// repeated while a batch is full, at most ten times.
	for _, tc := range []struct {
		role   string
		batch  int
		runs   int // statements run with parameters or a result: the termination, then each removal
		result RekeyResult
	}{
		{"postgres", 0, 1, RekeyResult{}},
		{"supabase_read_only_user", 3, 2, RekeyResult{LargeObjects: 3}},
		{"supabase_read_only_user", loBatch, 1 + loRounds, RekeyResult{LargeObjects: loRounds * loBatch, LargeObjectsLeft: true}},
		{"supabase_read_only_user", loBatch + 1, 2, RekeyResult{LargeObjectsLeft: true, LargeObjectsError: "bootstrap: large objects of supabase_read_only_user: more than 10000 rows"}},
	} {
		conn, rec := recordingConn(t, func(sql string) ([]uint32, [][]string) {
			if sql == sqlUnlinkReadOnlyLargeObjects {
				return []uint32{25}, slices.Repeat([][]string{{"1"}}, tc.batch)
			}
			return nil, nil
		})
		res, err := RekeyLogin(context.Background(), conn, tc.role, newVerifier(t, tc.role))
		got := rec.statements()
		if err != nil || res != tc.result || binds(rec) != tc.runs {
			t.Fatalf("%s, batch %d: %+v %v, ran %d", tc.role, tc.batch, res, err, binds(rec))
		}
		for _, s := range got[2:] {
			if s != sqlUnlinkReadOnlyLargeObjects {
				t.Fatalf("sent %q", s)
			}
		}
	}
}

// TestSetReadOnlySignal_OnAndOff: a session made after the signal reads it;
// after its removal a new session does not.
func TestSetReadOnlySignal_OnAndOff(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	show := func() string { return c.str(c.rawDial("postgres", nil), "show default_transaction_read_only") }
	if got := show(); got != "off" {
		t.Fatalf("control: %s", got)
	}
	for _, on := range []bool{true, false} {
		if err := SetReadOnlySignal(context.Background(), adm, on); err != nil {
			t.Fatal(err)
		}
		if got, want := show(), map[bool]string{true: "on", false: "off"}[on]; got != want {
			t.Fatalf("signal %t: a new session reads %s", on, got)
		}
	}
}

// TestCreateRestorePoint: the server's WAL location in the form X/X; an answer
// of no row, two rows or another form is an error.
func TestCreateRestorePoint(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	lsn, err := CreateRestorePoint(context.Background(), adm, "t-point")
	if err != nil || !lsnRE.MatchString(lsn) {
		t.Fatalf("%q %v", lsn, err)
	}
	if _, err := ReadTimeline(context.Background(), adm); err != nil {
		t.Fatal(err)
	}
	for i, rows := range [][][]string{nil, {{"0/1"}, {"0/2"}}, {{"0/1x"}}, {{"1"}}} {
		conn, _ := recordingConn(t, func(string) ([]uint32, [][]string) { return []uint32{25}, rows })
		if got, err := CreateRestorePoint(context.Background(), conn, "x"); err == nil {
			t.Errorf("answer %d: %q accepted", i, got)
		}
	}
}

// TestBaselineFor_KnownAndUnknownVersion: the locked version's baseline is
// LoadBaseline's; another version is an error naming the versions there are.
func TestBaselineFor_KnownAndUnknownVersion(t *testing.T) {
	want, err := LoadBaseline()
	if err != nil {
		t.Fatal(err)
	}
	known, err := nodecfg.LockedPostgresVersion()
	if err != nil {
		t.Fatal(err)
	}
	got, err := BaselineFor(known)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("known version: %v", err)
	}
	for _, v := range []string{known + "9", "", "../" + known, known + ".json", "*"} {
		if _, err := BaselineFor(v); err == nil || !strings.Contains(err.Error(), "there are: "+known) {
			t.Errorf("version %s: %v", strconv.Quote(v), err)
		}
	}
}

// binds counts the statements the recording connection was asked to run in
// the extended protocol (a prepared statement is parsed once).
func binds(r *recorder) int {
	n := 0
	for _, k := range r.messageKinds() {
		if k == "*pgproto3.Bind" {
			n++
		}
	}
	return n
}

// TestWriteCanary_RefusesARelationOfAnotherKind: a view of the canary's name
// made by a project role is not written through and stays as it was.
func TestWriteCanary_RefusesARelationOfAnotherKind(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "drop schema supapace cascade")
	pg := c.dial("postgres")
	c.exec(pg, "create schema supapace")
	c.exec(pg, "create table supapace.t_rows (id smallint, written_at timestamptz)")
	c.exec(pg, "create view supapace._backup_canary as select * from supapace.t_rows")
	if err := WriteCanary(context.Background(), adm); err == nil {
		t.Fatal("the write went through a view")
	}
	if got := c.str(adm, "select count(*)::text || ' ' || (select relkind::text from pg_catalog.pg_class where oid = 'supapace._backup_canary'::regclass) from supapace.t_rows"); got != "0 v" {
		t.Fatalf("after the write: %s", got)
	}
}
