package bootstrap

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

// withPooler gives the cluster's secrets a manager password and its salt.
func (c *cluster) withPooler() {
	c.t.Helper()
	salt, err := pgsock.ScramSalt([]byte(rnd(32)), c.ref, "supapace_pooler")
	if err != nil {
		c.t.Fatal(err)
	}
	c.secrets.PoolerPassword = rnd(32)
	c.secrets.ScramSalts["supapace_pooler"] = salt
}

// startPoolerCluster is startCluster with a manager password: Run makes the
// manager role and its helper.
func startPoolerCluster(t *testing.T) *cluster {
	c := newCluster(t, 1)
	c.withPooler()
	c.run()
	if err := Run(context.Background(), c.dial("supabase_admin"), c.secrets); err != nil {
		c.logs()
		t.Fatalf("run: %v", err)
	}
	return c
}

func (c *cluster) assertServices(conn *pgx.Conn) []nodecfg.CheckResult {
	c.t.Helper()
	r, err := AssertServices(context.Background(), conn, true)
	if err != nil {
		c.t.Fatalf("assert services: %v", err)
	}
	return r
}

// tcpLogin logs in over TCP to 127.0.0.1 inside the cluster's container as
// user with password, requiring SCRAM, and runs sql there.
func (c *cluster) tcpLogin(user, password, sql string) (string, error) {
	out, err := exec.Command("docker", "exec", "-e", "PGPASSWORD="+password, c.name, "psql", "-XAt",
		"host=127.0.0.1 port=5432 dbname=postgres sslmode=disable require_auth=scram-sha-256 user="+user,
		"-c", sql).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// recordedPoolerHelper is the helper's definition as the pooler's lookup was
// verified with, written out as a create-or-replace.
const recordedPoolerHelper = `create or replace function supapace_pooler.get_auth(p_usename text) returns table (username text, password text)
  language sql stable security definer set search_path = '' as $f$
  select a.rolname::pg_catalog.text, a.rolpassword::pg_catalog.text from pg_catalog.pg_authid a
  where a.rolname = p_usename and a.rolcanlogin and not a.rolsuper
    and (a.rolvaliduntil is null or a.rolvaliduntil > pg_catalog.now())
    and a.rolpassword like 'SCRAM-SHA-256$%'
    and a.rolname not in ('supabase_admin','supabase_auth_admin','supabase_storage_admin',
      'supabase_realtime_admin','supabase_replication_admin','supabase_etl_admin','supabase_privileged_role',
      'dashboard_user','pgbouncer','authenticator','supapace_backup','anon','authenticated','service_role')
    and a.rolname !~ '^pg_' $f$`

func TestPoolerHelper_TextIsTheRecordedDefinition(t *testing.T) {
	if sqlCreatePoolerHelper != recordedPoolerHelper {
		t.Fatalf("helper\n%s\nrecorded\n%s", sqlCreatePoolerHelper, recordedPoolerHelper)
	}
}

// helperExcluded parses the names the helper's definition excludes.
func helperExcluded(t *testing.T) []string {
	t.Helper()
	m := regexp.MustCompile(`not in \(([^)]*)\)`).FindAllStringSubmatch(sqlCreatePoolerHelper, -1)
	if len(m) != 1 {
		t.Fatalf("%d exclusion lists", len(m))
	}
	var got []string
	for _, n := range strings.Split(m[0][1], ",") {
		got = append(got, strings.Trim(strings.TrimSpace(n), "'"))
	}
	return got
}

// TestPoolerHelper_ExclusionListIsTheReservedList: the helper excludes the
// reserved roles, authenticator and the three API roles, but not
// supabase_read_only_user (it has a pooled login).
func TestPoolerHelper_ExclusionListIsTheReservedList(t *testing.T) {
	want := []string{"authenticator", "anon", "authenticated", "service_role"}
	for _, r := range reservedMembers {
		if r != "supabase_read_only_user" {
			want = append(want, r)
		}
	}
	got := helperExcluded(t)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("excluded %v, want %v", got, want)
	}
}

// TestEnsurePoolerLogin_FreshCluster: on a cluster bootstrapped without a
// manager, the call makes it; the manager logs in over TCP by SCRAM and the
// helper returns its own row; postgres may not execute the helper.
func TestEnsurePoolerLogin_FreshCluster(t *testing.T) {
	c := startCluster(t)
	c.withPooler()
	adm := c.dial("supabase_admin")
	if err := EnsurePoolerLogin(context.Background(), adm, c.secrets); err != nil {
		t.Fatal(err)
	}
	c.wantServices(c.assertServices(adm))
	c.wantFindings(c.assert(adm))
	pg := c.dial("postgres")
	var se *pgsock.ServerError
	if _, err := pg.Exec(context.Background(), "select * from supapace_pooler.get_auth('postgres')"); !errors.As(pgsock.Clean(err), &se) || se.Code != "42501" {
		t.Fatalf("postgres executes the helper: %v", err)
	}
	if got := c.str(adm, "select string_agg(username, ',') from supapace_pooler.get_auth('postgres')"); got != "postgres" {
		t.Fatalf("control: the helper as its owner returns %q", got)
	}
	c.phaseB() // the platform's pg_hba: SCRAM over TCP from loopback
	got, err := c.tcpLogin("supapace_pooler", c.secrets.PoolerPassword,
		"select username || ' ' || left(password, 19) from supapace_pooler.get_auth('supapace_pooler')")
	if err != nil || got != "supapace_pooler SCRAM-SHA-256$4096:" {
		t.Fatalf("manager login: %v %q", err, got)
	}
	if out, err := c.tcpLogin("supapace_pooler", "wrong-"+rnd(8), "select 1"); err == nil {
		t.Fatalf("control: a wrong password logs in: %q", out)
	}
}

// wantServices requires the service report to hold exactly the findings
// whose details contain subs (none when no sub is given).
func (c *cluster) wantServices(r []nodecfg.CheckResult, subs ...string) {
	c.t.Helper()
	for _, f := range r {
		if f.OK || f.Name != "service-logins" || f.Detail == "" || len(f.Detail) > 256 {
			c.t.Errorf("malformed finding %+v", f)
		}
	}
	if len(r) != len(subs) {
		c.t.Fatalf("findings %+v, want %q", r, subs)
	}
	for _, s := range subs {
		if !hasDetail(r, "service-logins", s) {
			c.t.Fatalf("no finding with %q in %+v", s, r)
		}
	}
}

// TestHelper_ReturnsNothingForSuperusersReservedAndPlatformRoles: each
// excluded role, given a login and a SCRAM password, and a superuser are not
// returned; postgres and supabase_read_only_user are.
func TestHelper_ReturnsNothingForSuperusersReservedAndPlatformRoles(t *testing.T) {
	c := startPoolerCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "create role t_super superuser")
	rows := func(c *cluster, role string) string {
		c.exec(adm, "alter role "+role+" login password '"+rnd(12)+"'")
		if c.str(adm, "select left(rolpassword, 14) from pg_catalog.pg_authid where rolname = $1", role) != "SCRAM-SHA-256$" {
			c.t.Fatalf("%s has no SCRAM verifier", role)
		}
		return c.str(adm, "select count(*)::text from supapace_pooler.get_auth($1)", role)
	}
	for _, role := range append(helperExcluded(t), "supabase_admin", "t_super") {
		t.Run(role, func(t *testing.T) {
			if n := rows(c.in(t), role); n != "0" {
				t.Fatalf("%s rows", n)
			}
		})
	}
	for _, role := range []string{"postgres", "supabase_read_only_user"} {
		t.Run("control_"+role, func(t *testing.T) {
			if n := rows(c.in(t), role); n != "1" {
				t.Fatalf("%s rows", n)
			}
		})
	}
}

const poolerSnap = `select string_agg(x, E'\n' order by x) from (
  select a.rolname || ' ' || coalesce(a.rolpassword, '-') || ' ' || coalesce(a.rolvaliduntil::text, '-') || ' ' ||
         row(a.rolsuper, a.rolinherit, a.rolcreaterole, a.rolcreatedb, a.rolcanlogin, a.rolreplication, a.rolbypassrls, a.rolconnlimit)::text
    as x from pg_catalog.pg_authid a where a.rolname = 'supapace_pooler'
  union all select n.nspname || ' ' || n.nspowner::regrole || ' ' || coalesce(n.nspacl::text, '-') from pg_catalog.pg_namespace n
    where n.nspname = 'supapace_pooler'
  union all select p.oid::regprocedure || ' ' || p.proowner::regrole || ' ' || p.prosecdef || ' ' || coalesce(p.proconfig::text, '-') || ' ' ||
         coalesce(p.proacl::text, '-') || ' ' || md5(p.prosrc) from pg_catalog.pg_proc p
    where p.pronamespace = 'supapace_pooler'::regnamespace) s`

// TestEnsurePoolerLogin_Idempotent_SetsAttributesBack: a manager made
// superuser with a connection limit and an expiry, a helper replaced and given
// to another owner, the schema given to a project role: after the call, all
// as defined; a second call changes nothing.
func TestEnsurePoolerLogin_Idempotent_SetsAttributesBack(t *testing.T) {
	c := startPoolerCluster(t)
	adm := c.dial("supabase_admin")
	defined := c.str(adm, poolerSnap)
	for _, s := range []string{
		"alter role supapace_pooler superuser inherit createdb createrole replication bypassrls nologin connection limit 3 valid until '2000-01-01'",
		"alter role supapace_pooler password 't-other-" + rnd(8) + "'",
		`create or replace function supapace_pooler.get_auth(p_usename text) returns table (username text, password text)
		  language sql security invoker as $$ select 'x'::text, 'y'::text $$`,
		"alter function supapace_pooler.get_auth(text) owner to postgres",
		"alter schema supapace_pooler owner to postgres",
		"grant usage on schema supapace_pooler to public",
	} {
		c.exec(adm, s)
	}
	if got := c.assertServices(adm); len(got) < 5 {
		t.Fatalf("control: findings %+v", got)
	}
	for i := range 2 {
		if err := EnsurePoolerLogin(context.Background(), adm, c.secrets); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if got := c.str(adm, poolerSnap); got != defined {
			t.Fatalf("call %d:\n%s\nas defined:\n%s", i, got, defined)
		}
	}
	c.wantServices(c.assertServices(adm))
}

// TestEnsurePoolerLogin_VerifierIsTheSecondStatementAndNothingReadsBeforeIt:
// over a recording connection the call sends the role's creation, then its
// password statement, each one simple query, then the schema and helper
// statements in order, then the two reads.
func TestEnsurePoolerLogin_VerifierIsTheSecondStatementAndNothingReadsBeforeIt(t *testing.T) {
	s := testSecrets(t)
	s.PoolerPassword = rnd(32)
	salt, err := pgsock.ScramSalt([]byte(rnd(32)), rnd(10), "supapace_pooler")
	if err != nil {
		t.Fatal(err)
	}
	s.ScramSalts["supapace_pooler"] = salt
	v, err := pgsock.ScramVerifier(s.PoolerPassword, salt)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := verifierStatement(sqlPasswordPooler, v)
	if err != nil {
		t.Fatal(err)
	}
	conn, rec := recordingConn(t, func(sql string) ([]uint32, [][]string) {
		switch sql {
		case sqlPoolerRole:
			return []uint32{16, 16, 16, 16, 16, 16, 16, 16, 25}, [][]string{{"f", "f", "f", "f", "f", "t", "t", "t", poolerSchemaACL}}
		case sqlPoolerHelper:
			return []uint32{25, 16, 16, 16, 25}, [][]string{{"supabase_admin", "t", "t", "t", poolerHelperGrantees}}
		}
		return nil, nil
	})
	if err := EnsurePoolerLogin(context.Background(), conn, s); err != nil {
		t.Fatal(err)
	}
	want := []string{sqlCreatePooler, verifier, sqlPoolerSchema, sqlPoolerSchemaOwner, sqlPoolerSchemaRevoke,
		sqlPoolerSchemaGrant, sqlCreatePoolerHelper, sqlPoolerHelperOwner, sqlPoolerHelperRevoke, sqlPoolerHelperGrant,
		sqlPoolerRole, sqlPoolerHelper}
	if got := rec.statements(); !slices.Equal(got, want) {
		t.Fatalf("sent\n%q\nwant\n%q", got, want)
	}
	if k := rec.messageKinds(); len(k) < 2 || k[0] != "*pgproto3.Query" || k[1] != "*pgproto3.Query" {
		t.Fatalf("first messages %q", k)
	}
	// Without a password, or with one of another role, nothing is sent.
	for name, bad := range map[string]func(*Secrets){
		"empty":   func(s *Secrets) { s.PoolerPassword = "" },
		"shared":  func(s *Secrets) { s.PoolerPassword = s.PostgresPassword },
		"no salt": func(s *Secrets) { delete(s.ScramSalts, "supapace_pooler") },
	} {
		b := s
		b.ScramSalts = map[string][]byte{}
		for k, v := range s.ScramSalts {
			b.ScramSalts[k] = v
		}
		bad(&b)
		conn, rec := recordingConn(t, func(string) ([]uint32, [][]string) { return nil, nil })
		if err := EnsurePoolerLogin(context.Background(), conn, b); err == nil || len(rec.statements()) != 0 {
			t.Errorf("%s: %v, sent %q", name, err, rec.statements())
		}
	}
	// A read-back that differs is an error.
	conn, _ = recordingConn(t, func(sql string) ([]uint32, [][]string) {
		if sql == sqlPoolerRole {
			return []uint32{16, 16, 16, 16, 16, 16, 16, 16, 25}, [][]string{{"t", "f", "f", "f", "f", "t", "t", "t", poolerSchemaACL}}
		}
		if sql == sqlPoolerHelper {
			return []uint32{25, 16, 16, 16, 25}, [][]string{{"supabase_admin", "t", "t", "t", poolerHelperGrantees}}
		}
		return nil, nil
	})
	if err := EnsurePoolerLogin(context.Background(), conn, s); err == nil || !strings.Contains(err.Error(), "super=true") {
		t.Fatalf("a superuser manager read back: %v", err)
	}
}

// TestAssertServices_ReportsEachDifference: each difference of the manager or
// the helper is one finding; EnsurePoolerLogin sets it back.
func TestAssertServices_ReportsEachDifference(t *testing.T) {
	c := startPoolerCluster(t)
	adm := c.dial("supabase_admin")
	c.wantServices(c.assertServices(adm))
	rc, rec := recordingConn(t, func(string) ([]uint32, [][]string) { return nil, nil })
	if r, err := AssertServices(context.Background(), rc, false); err != nil || r != nil || len(rec.statements()) != 0 {
		t.Fatalf("without a pooler: %+v %v, sent %q", r, err, rec.statements())
	}
	for _, tc := range []struct {
		name  string
		stmts []string
		want  []string
	}{
		{"role absent", []string{"drop owned by supapace_pooler", "drop role supapace_pooler"},
			[]string{"role supapace_pooler is absent", "executed by \"supabase_admin\""}},
		{"role attribute", []string{"alter role supapace_pooler createdb"}, []string{"createdb=true"}},
		{"role limit", []string{"alter role supapace_pooler connection limit 5"}, []string{"unlimited=false"}},
		{"helper absent", []string{"drop function supapace_pooler.get_auth(text)"}, []string{"get_auth is absent"}},
		{"helper owner", []string{"alter function supapace_pooler.get_auth(text) owner to postgres"}, []string{"owned by \"postgres\"", "executed by \"postgres,supapace_pooler\""}},
		{"helper body", []string{`create or replace function supapace_pooler.get_auth(p_usename text) returns table (username text, password text)
		  language sql stable security definer set search_path = '' as $f$ select 'x'::text, 'y'::text $f$`}, []string{"another body"}},
		{"helper invoker", []string{"alter function supapace_pooler.get_auth(text) security invoker"}, []string{"not security definer"}},
		{"helper setting", []string{"alter function supapace_pooler.get_auth(text) reset search_path"}, []string{"another SET clause"}},
		{"helper public", []string{"grant execute on function supapace_pooler.get_auth(text) to public"}, []string{"executed by \"public,supabase_admin,supapace_pooler\""}},
		{"helper postgres", []string{"grant execute on function supapace_pooler.get_auth(text) to postgres"}, []string{"executed by \"postgres,supabase_admin,supapace_pooler\""}},
		{"membership of the manager", []string{"grant supapace_pooler to postgres"}, []string{"has a membership"}},
		{"membership in the manager", []string{"grant anon to supapace_pooler"}, []string{"has a membership"}},
		{"schema entry", []string{"grant create on schema supapace_pooler to postgres"}, []string{"schema supapace_pooler has the access list"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := c.in(t)
			for _, s := range tc.stmts {
				c.exec(adm, s)
			}
			c.wantServices(c.assertServices(adm), tc.want...)
			if err := EnsurePoolerLogin(context.Background(), adm, c.secrets); err != nil {
				// A grant to another role or a membership is not taken back: the
				// call says so.
				undo, ok := map[string]string{
					"helper postgres":           "revoke execute on function supapace_pooler.get_auth(text) from postgres",
					"membership of the manager": "revoke supapace_pooler from postgres",
					"membership in the manager": "revoke anon from supapace_pooler",
					"schema entry":              "revoke create on schema supapace_pooler from postgres",
				}[tc.name]
				if !ok {
					t.Fatal(err)
				}
				c.exec(adm, undo)
			}
			c.wantServices(c.assertServices(adm))
		})
	}
}

// TestRun_EmptyPoolerPasswordCreatesNothingOfIt: without a manager password
// Run makes no manager role and no helper schema, and the canary table
// always; with one, a second Run makes both.
func TestRun_EmptyPoolerPasswordCreatesNothingOfIt(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	const objs = `select (select count(*) from pg_catalog.pg_roles where rolname = 'supapace_pooler')::text || ' ' ||
	  (select count(*) from pg_catalog.pg_namespace where nspname = 'supapace_pooler')::text || ' ' ||
	  (pg_catalog.to_regclass('supapace._backup_canary') is not null)::text`
	if got := c.str(adm, objs); got != "0 0 true" {
		t.Fatalf("without a manager password: %s", got)
	}
	c.withPooler()
	if err := Run(context.Background(), adm, c.secrets); err != nil {
		t.Fatal(err)
	}
	if got := c.str(adm, objs); got != "1 1 true" {
		t.Fatalf("control, with a manager password: %s", got)
	}
	c.wantServices(c.assertServices(adm))
}

// in returns the cluster with its helpers reporting to t (a sub-test).
func (c *cluster) in(t *testing.T) *cluster {
	cc := *c
	cc.t = t
	return &cc
}
