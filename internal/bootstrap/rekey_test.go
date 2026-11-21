package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
)

// ---- the reset of the statement statistics ----

// TestResetStatementStats_NarrowFormAcceptedByThePinnedImage: the reset
// statement runs on the pinned image without error and reports a reset.
func TestResetStatementStats_NarrowFormAcceptedByThePinnedImage(t *testing.T) {
	c := startCluster(t)
	reset, err := ResetStatementStats(context.Background(), c.dial("supabase_admin"))
	if err != nil || !reset {
		t.Fatalf("reset %t: %v", reset, err)
	}
}

// TestResetStatementStats_OnlyThePlatformRolesRowsAreGone: a marked utility
// statement of the platform's login role, sent by a session without the
// platform's startup list, is in the statement statistics and gone after the
// reset; a statement run as postgres is still there.
func TestResetStatementStats_OnlyThePlatformRolesRowsAreGone(t *testing.T) {
	c := startCluster(t)
	mark := "t_mark_" + rnd(4)
	c.exec(c.rawDial("supabase_admin", nil), "create schema "+mark+"_a")
	pg := c.dial("postgres")
	c.exec(pg, "create schema "+mark+"_p")
	listed := func(role, schema string) bool {
		t.Helper()
		return c.str(pg, `select count(*)::text from extensions.pg_stat_statements
		  where userid = (select oid from pg_catalog.pg_roles where rolname = $1) and query like $2`, role, "%"+schema+"%") != "0"
	}
	if !listed("supabase_admin", mark+"_a") || !listed("postgres", mark+"_p") {
		t.Fatal("control: the marked statements are not in the statement statistics")
	}
	reset, err := ResetStatementStats(context.Background(), c.dial("supabase_admin"))
	if err != nil || !reset {
		t.Fatalf("reset %t: %v", reset, err)
	}
	if listed("supabase_admin", mark+"_a") {
		t.Error("the platform role's statement is still listed")
	}
	if !listed("postgres", mark+"_p") {
		t.Error("the statement of postgres is gone")
	}
}

// TestResetStatementStats_ExtensionNotAtItsPlaceIsNotAnError: the extension
// moved to another schema, or its schema renamed, gives no reset and no
// error; another server error is returned.
func TestResetStatementStats_ExtensionNotAtItsPlaceIsNotAnError(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	want := func(label string, wantReset bool) {
		t.Helper()
		reset, err := ResetStatementStats(context.Background(), adm)
		if err != nil || reset != wantReset {
			t.Fatalf("%s: reset %t: %v", label, reset, err)
		}
	}
	c.exec(adm, "alter extension pg_stat_statements set schema public")
	want("moved", false)
	c.exec(adm, "alter extension pg_stat_statements set schema extensions")
	want("control: back in place", true)
	c.exec(adm, "alter schema extensions rename to t_ext")
	want("schema renamed", false)
	c.exec(adm, "alter schema t_ext rename to extensions")
	want("control: schema back", true)
	c.exec(adm, `create or replace function extensions.pg_stat_statements_reset(userid oid default 0, dbid oid default 0,
	  queryid bigint default 0, minmax_only boolean default false)
	  returns timestamptz language plpgsql as $$ begin raise exception 't_refused'; end $$`)
	reset, err := ResetStatementStats(context.Background(), adm)
	var se *pgsock.ServerError
	if reset || !errors.As(err, &se) || se.Code != "P0001" {
		t.Fatalf("another error: reset %t: %v", reset, err)
	}
}

// ---- the re-key ----

// platformLogins are the three roles whose passwords the platform holds.
var platformLogins = []string{"supabase_admin", "postgres", "authenticator"}

func (c *cluster) password(role string) string {
	return map[string]string{"supabase_admin": c.secrets.SupabaseAdminPassword,
		"postgres": c.secrets.PostgresPassword, "authenticator": c.secrets.AuthenticatorPassword}[role]
}

// storedIsPlatforms reports whether each of the three roles stores the
// verifier of the platform's password.
func (c *cluster) storedIsPlatforms(conn *pgx.Conn) bool {
	c.t.Helper()
	for _, r := range platformLogins {
		v, _ := pgsock.ScramVerifier(c.password(r), c.secrets.ScramSalts[r])
		if c.str(conn, "select coalesce(rolpassword, '') from pg_catalog.pg_authid where rolname = $1", r) != v {
			return false
		}
	}
	return true
}

// scramLogins restarts the cluster under a pg_hba that admits every role by
// SCRAM over the socket and logs in as each of the three roles with the
// platform's password. It returns the first failure.
func (c *cluster) scramLogins() error {
	c.t.Helper()
	hba := filepath.Join(c.render, "pg_hba.conf")
	os.Chmod(hba, 0o644)
	if err := os.WriteFile(hba, []byte("local all all scram-sha-256\n"), 0o644); err != nil {
		c.t.Fatal(err)
	}
	c.phaseB()
	for _, r := range platformLogins {
		conn, err := pgsock.Dial(context.Background(), c.target(r))
		if err != nil {
			return fmt.Errorf("login as %s: %w", r, err)
		}
		got := c.str(conn, "select current_user::text")
		conn.Close(context.Background())
		if got != r {
			return fmt.Errorf("logged in as %q, not %s", got, r)
		}
	}
	return nil
}

// rawDial opens a session over the socket as user, without a password, that
// sends only params as startup parameters, not the platform's list. The
// socket is reached through a short link: its own path is too long for a
// socket address.
func (c *cluster) rawDial(user string, params map[string]string) *pgx.Conn {
	c.t.Helper()
	dir, err := os.MkdirTemp("", "sp")
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Symlink(filepath.Join(c.root, c.ref, "sock"), filepath.Join(dir, "s")); err != nil {
		c.t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig("host=" + filepath.Join(dir, "s") + " user=" + user + " dbname=postgres sslmode=disable")
	if err != nil {
		c.t.Fatal(err)
	}
	for k, v := range params {
		cfg.RuntimeParams[k] = v
	}
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		c.t.Fatalf("raw dial %s: %v", user, err)
	}
	c.t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

func TestRekey_SetsThreeVerifiers(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	for _, r := range platformLogins {
		c.exec(adm, "alter role "+r+" password 't-other-"+rnd(8)+"'")
	}
	if c.storedIsPlatforms(adm) {
		t.Fatal("control: the passwords were not changed")
	}
	if err := Rekey(context.Background(), adm, c.secrets); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if !c.storedIsPlatforms(adm) {
		t.Fatal("the stored verifiers are not the platform's")
	}
	if err := c.scramLogins(); err != nil {
		t.Fatal(err)
	}
}

func TestRekey_RecreatesBackupRole(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "drop owned by supapace_backup")
	c.exec(adm, "drop role supapace_backup")
	if c.str(adm, "select count(*)::text from pg_catalog.pg_roles where rolname = 'supapace_backup'") != "0" {
		t.Fatal("control: the role is still there")
	}
	if err := Rekey(context.Background(), adm, c.secrets); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	c.wantBackupRole(adm)
	c.wantFindings(c.assert(adm))
}

// wantBackupRole requires the backup role with its inheriting membership and
// the four backup functions.
func (c *cluster) wantBackupRole(conn *pgx.Conn) {
	c.t.Helper()
	if got := c.str(conn, `select string_agg(a.inherit_option::text, ',') from pg_catalog.pg_auth_members a
	  where a.member = 'supapace_backup'::pg_catalog.regrole and a.roleid = 'pg_read_all_settings'::pg_catalog.regrole`); got != "true" {
		c.t.Errorf("inherit options of the membership: %s", got)
	}
	for _, fn := range []string{"pg_catalog.pg_backup_start(text, boolean)", "pg_catalog.pg_backup_stop(boolean)",
		"pg_catalog.pg_switch_wal()", "pg_catalog.pg_create_restore_point(text)"} {
		if got := c.str(conn, "select pg_catalog.has_function_privilege('supapace_backup', $1, 'EXECUTE')::text", fn); got != "true" {
			c.t.Errorf("supapace_backup may not execute %s", fn)
		}
	}
}

// catalogSnap is the state the re-key may touch: the roles with their
// passwords and attributes, memberships and the backup functions' grants.
const catalogSnap = `select string_agg(x, E'\n' order by x) from (
  select a.rolname || ' ' || coalesce(a.rolpassword, '-') || ' ' || coalesce(a.rolvaliduntil::text, '-') || ' ' ||
         row(a.rolsuper, a.rolinherit, a.rolcreaterole, a.rolcreatedb, a.rolcanlogin, a.rolreplication, a.rolbypassrls, a.rolconnlimit)::text as x from pg_catalog.pg_authid a
  union all select m.member::regrole || ' in ' || m.roleid::regrole || ' ' || m.inherit_option || m.admin_option || m.set_option from pg_catalog.pg_auth_members m
  union all select 'acl ' || p.oid::regprocedure || coalesce(p.proacl::text, '-') from pg_catalog.pg_proc p where p.proname in ('pg_backup_start', 'pg_backup_stop', 'pg_switch_wal', 'pg_create_restore_point')) s`

func TestRekey_Idempotent(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	before := c.str(adm, catalogSnap)
	for i := range 2 {
		if err := Rekey(context.Background(), adm, c.secrets); err != nil {
			t.Fatalf("rekey %d: %v", i, err)
		}
		if after := c.str(adm, catalogSnap); after != before {
			t.Fatalf("rekey %d changed the catalog:\nbefore\n%s\nafter\n%s", i, before, after)
		}
	}
	c.wantFindings(c.assert(adm))
}

// TestRekey_OnlyAllowedStatements: rekey.go is covered by the static test of
// the statements, and the statements the re-key can reach — through every
// package function it calls — are the three verifier statements and the
// backup role's read, creation and two grants.
func TestRekey_OnlyAllowedStatements(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	if !slices.Contains(files, "rekey.go") {
		t.Fatal("rekey.go is not among the files the static test reads")
	}
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	consts := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					funcs[d.Name.Name] = d
				}
			case *ast.GenDecl:
				if d.Tok == token.CONST {
					for _, s := range d.Specs {
						for _, n := range s.(*ast.ValueSpec).Names {
							consts[n.Name] = true
						}
					}
				}
			}
		}
	}
	reached := map[string]bool{}
	stmts := map[string]bool{}
	var walk func(name string)
	walk = func(name string) {
		if reached[name] || funcs[name] == nil {
			return
		}
		reached[name] = true
		ast.Inspect(funcs[name].Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if f, ok := call.Fun.(*ast.Ident); ok && (f.Name == "execSQL" || f.Name == "querySQL") && len(call.Args) > 2 {
					if _, lit := call.Args[2].(*ast.BasicLit); lit {
						t.Errorf("%s: %s sends a literal statement", name, fset.Position(call.Pos()))
					}
				}
			}
			if id, ok := n.(*ast.Ident); ok {
				if consts[id.Name] && strings.HasPrefix(id.Name, "sql") {
					stmts[id.Name] = true
				}
				walk(id.Name)
			}
			return true
		})
	}
	walk("Rekey")
	// The pooler manager's statement is the re-key's; the read-only login's
	// prefix is reached through verifierStatement, which admits it.
	allowed := []string{"sqlPasswordSupabaseAdmin", "sqlPasswordPostgres", "sqlPasswordAuthenticator",
		"sqlPasswordPooler", "sqlPasswordReadOnly",
		"sqlRoleExists", "sqlCreateBackup", "sqlGrantBackupSettings", "sqlGrantBackupFuncs"}
	got := slices.Sorted(func(yield func(string) bool) {
		for s := range stmts {
			if !yield(s) {
				return
			}
		}
	})
	slices.Sort(allowed)
	if !slices.Equal(got, allowed) {
		t.Fatalf("statements the re-key reaches: %v, allowed %v", got, allowed)
	}
	if !reached["setVerifier"] {
		t.Fatal("the re-key does not set the verifiers through setVerifier")
	}
}

// TestRekey_WithLoginAndDDLTriggers: login and DDL event triggers that raise
// an error refuse a non-superuser's login, and the re-key's session completes
// (also creating the backup role and granting it EXECUTE on the backup functions).
func TestRekey_WithLoginAndDDLTriggers(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	for _, s := range []string{
		"drop owned by supapace_backup",
		"drop role supapace_backup",
		"create function public.t_fail() returns event_trigger language plpgsql as $$ begin raise exception 't_fail'; end $$",
		"create event trigger t_login on login execute function public.t_fail()",
		"create event trigger t_start on ddl_command_start execute function public.t_fail()",
		"create event trigger t_end on ddl_command_end execute function public.t_fail()",
		"create event trigger t_drop on sql_drop execute function public.t_fail()",
	} {
		c.exec(adm, s)
	}
	if conn, err := pgsock.Dial(context.Background(), c.target("postgres")); err == nil {
		conn.Close(context.Background())
		t.Fatal("control: a non-superuser logs in past the failing login trigger")
	}
	conn := c.dial("supabase_admin")
	if err := Rekey(context.Background(), conn, c.secrets); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	c.wantBackupRole(conn)
}

func TestRekey_LoginWorksAfterExpiryLimitAndLoginWereChanged(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	for _, s := range []string{
		"alter role authenticator valid until '2000-01-01'",
		"alter role supabase_admin valid until '2000-01-01'",
		"alter role authenticator connection limit 0",
		"alter role supabase_admin connection limit 0",
		"alter role authenticator nologin",
	} {
		c.exec(adm, s)
	}
	const state = `select string_agg(rolname::text || ' ' || rolcanlogin::text || ' ' || rolconnlimit::text || ' ' ||
	  coalesce(rolvaliduntil < pg_catalog.now(), false)::text, ',' order by rolname) from pg_catalog.pg_authid
	  where rolname in ('supabase_admin', 'authenticator')`
	if got := c.str(adm, state); got != "authenticator false 0 true,supabase_admin true 0 true" {
		t.Fatalf("control: %s", got)
	}
	if err := Rekey(context.Background(), adm, c.secrets); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if err := c.scramLogins(); err != nil {
		t.Fatal(err)
	}
}

// TestRekey_VerifierStatementsAreTheFirstThree: over a recording connection
// the re-key sends exactly the three verifier statements first, in the order
// supabase_admin, postgres, authenticator, then the backup role's read, its
// creation when absent and its two grants — and never the recovery read or
// the timeline read.
func TestRekey_VerifierStatementsAreTheFirstThree(t *testing.T) {
	s := testSecrets(t)
	var verifiers []string
	for i, p := range []string{sqlPasswordSupabaseAdmin, sqlPasswordPostgres, sqlPasswordAuthenticator} {
		pw := []string{s.SupabaseAdminPassword, s.PostgresPassword, s.AuthenticatorPassword}[i]
		v, err := pgsock.ScramVerifier(pw, s.ScramSalts[platformLogins[i]])
		if err != nil {
			t.Fatal(err)
		}
		st, err := verifierStatement(p, v)
		if err != nil {
			t.Fatal(err)
		}
		verifiers = append(verifiers, st)
	}
	for _, exists := range []bool{false, true} {
		conn, rec := recordingConn(t, func(sql string) ([]uint32, [][]string) {
			if sql == sqlRoleExists {
				return []uint32{16}, [][]string{{map[bool]string{false: "f", true: "t"}[exists]}}
			}
			return nil, nil
		})
		if err := Rekey(context.Background(), conn, s); err != nil {
			t.Fatalf("exists %t: %v", exists, err)
		}
		want := append(slices.Clone(verifiers), sqlRoleExists)
		if !exists {
			want = append(want, sqlCreateBackup)
		}
		want = append(want, sqlGrantBackupSettings, sqlGrantBackupFuncs)
		got := rec.statements()
		if !slices.Equal(got, want) {
			t.Fatalf("exists %t: sent\n%q\nwant\n%q", exists, got, want)
		}
		if slices.Contains(got, sqlInRecovery) || slices.Contains(got, sqlTimeline) {
			t.Fatal("a recovery or timeline read was sent")
		}
	}
	// Refused secrets: nothing is sent.
	conn, rec := recordingConn(t, func(string) ([]uint32, [][]string) { return nil, nil })
	bad := s
	bad.PostgresPassword = bad.SupabaseAdminPassword
	if err := Rekey(context.Background(), conn, bad); err == nil || len(rec.statements()) != 0 {
		t.Fatalf("same passwords: %v, sent %q", err, rec.statements())
	}
}

// TestVerifierStatement_AlsoSetsLoginLimitAndExpiry: the three password
// statements also restore the login right, an unlimited connection limit and
// no expiry; the forms without them are refused.
func TestVerifierStatement_AlsoSetsLoginLimitAndExpiry(t *testing.T) {
	for role, p := range map[string]string{"supabase_admin": sqlPasswordSupabaseAdmin, "postgres": sqlPasswordPostgres,
		"authenticator": sqlPasswordAuthenticator} {
		if want := "alter role " + role + " with login connection limit -1 valid until 'infinity' password '"; p != want {
			t.Errorf("%s: %q, want %q", role, p, want)
		}
	}
	v, err := pgsock.ScramVerifier("secret-password", make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"alter role postgres password '", "alter role postgres with login password '",
		"alter role postgres with login connection limit -1 password '"} {
		if _, err := verifierStatement(p, v); err == nil {
			t.Errorf("prefix %q accepted", p)
		}
	}
}

func TestRun_FreshClusterAttributesUnchanged(t *testing.T) {
	c := newCluster(t, 1)
	c.run()
	conn := c.dial("supabase_admin")
	const attrs = `select string_agg(rolname::text || ' ' || rolcanlogin::text || ' ' || rolconnlimit::text || ' ' ||
	  coalesce(rolvaliduntil, 'infinity')::text, ',' order by rolname) from pg_catalog.pg_authid
	  where rolname in ('supabase_admin', 'postgres', 'authenticator')`
	before := c.str(conn, attrs)
	if before != "authenticator true -1 infinity,postgres true -1 infinity,supabase_admin true -1 infinity" {
		t.Fatalf("control: the image's attributes %s", before)
	}
	if err := Run(context.Background(), conn, c.secrets); err != nil {
		t.Fatal(err)
	}
	if after := c.str(conn, attrs); after != before {
		t.Fatalf("attributes %s, before %s", after, before)
	}
}

// ---- the backup role and the drift check ----

func TestRun_BackupRoleReadsDataDirectory(t *testing.T) {
	c := startCluster(t)
	c.exec(c.dial("postgres"), "create table public.t_user(x int)")
	c.phaseB() // the platform's pg_hba admits the backup role by peer
	b := c.rawDial("supapace_backup", nil)
	if got := result(b, "select pg_catalog.current_setting('data_directory')"); got != "/var/lib/postgresql/data" {
		t.Fatalf("data_directory: %s", got)
	}
	if got := result(b, "select count(*)::text from public.t_user"); !strings.Contains(got, "42501") {
		t.Fatalf("a user table: %s", got)
	}
}

func TestAssert_CleanAfterRun(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	c.wantBackupRole(adm)
	c.wantFindings(c.assert(adm))
}

func TestAssert_ReportsPlainGrant(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "revoke pg_read_all_settings from supapace_backup")
	c.exec(adm, "grant pg_read_all_settings to supapace_backup")
	if got := c.str(adm, `select string_agg(inherit_option::text, ',') from pg_catalog.pg_auth_members
	  where member = 'supapace_backup'::pg_catalog.regrole and roleid = 'pg_read_all_settings'::pg_catalog.regrole`); got != "false" {
		t.Fatalf("control: inherit options %s", got)
	}
	r := c.assert(adm)
	c.wantFindings(r, "memberships-reserved")
	if len(r) != 1 || !strings.Contains(r[0].Detail, "inherit") {
		t.Fatalf("findings %+v", r)
	}
}

func TestAssertPins_Layout2Clean(t *testing.T) {
	c := newCluster(t, 2)
	c.run()
	adm := c.dial("supabase_admin")
	if err := Run(context.Background(), adm, c.secrets); err != nil {
		t.Fatal(err)
	}
	if got := c.str(adm, "select setting || ' ' || source from pg_catalog.pg_settings where name = 'archive_mode'"); got != "on command line" {
		t.Fatalf("control: archive_mode %s", got)
	}
	r, err := AssertPins(context.Background(), adm, c.baseline, c.conf, pgconf.PinnedNames(2))
	if err != nil {
		t.Fatal(err)
	}
	c.wantFindings(r)
}

func TestAssertPins_Layout1ReportsExtraPins(t *testing.T) {
	c := newCluster(t, 2)
	c.run()
	adm := c.dial("supabase_admin")
	if err := Run(context.Background(), adm, c.secrets); err != nil {
		t.Fatal(err)
	}
	r, err := AssertPins(context.Background(), adm, c.baseline, c.conf, pgconf.PinnedNames(1))
	if err != nil {
		t.Fatal(err)
	}
	c.wantFindings(r, "source-file")
	extra := slices.DeleteFunc(pgconf.PinnedNames(2), func(n string) bool { return slices.Contains(pgconf.PinnedNames(1), n) })
	if len(r) != len(extra) || len(extra) != 6 {
		t.Fatalf("findings %+v for %v", r, extra)
	}
	for _, n := range extra {
		if !hasDetail(r, "source-file", strconv.Quote(n)+" is set on the command line") {
			t.Errorf("no finding for %s", n)
		}
	}
	// Assert checks with the same two names.
	r2, err := Assert(context.Background(), adm, c.baseline, c.conf)
	if err != nil || !slices.Equal(r2, r) {
		t.Fatalf("Assert %+v, %v", r2, err)
	}
}

// ---- the image's settings ----

// extendedSuperuserNames are the settings the superuser startup list sets for the
// platform's sessions once extended; the baseline must list each one that
// the comparison covers.
var extendedSuperuserNames = []string{"event_triggers", "session_preload_libraries", "log_statement", "log_min_duration_statement",
	"log_min_duration_sample", "log_transaction_sample_rate", "log_duration", "log_min_messages", "log_min_error_statement",
	"debug_print_parse", "debug_print_rewritten", "debug_print_plan", "track_activities", "pgaudit.log", "pgaudit.role",
	"auto_explain.log_min_duration", "pg_stat_statements.track", "pg_stat_statements.track_utility",
	"plan_filter.statement_cost_limit"}

func TestBaseline_ListsEverySettingTheSessionListNames(t *testing.T) {
	bl, err := LoadBaseline()
	if err != nil {
		t.Fatal(err)
	}
	names := slices.Clone(extendedSuperuserNames)
	for _, su := range []bool{false, true} {
		for n := range pgsock.StartupParams(su) {
			names = append(names, n)
		}
	}
	n := 0
	for _, name := range names {
		if !imageSetting(name) {
			continue
		}
		n++
		if !slices.Contains(bl.SessionSettings, name) {
			t.Errorf("%s is set by the session list but not in the baseline", name)
		}
	}
	if n < 17 {
		t.Fatalf("only %d names covered", n)
	}
}

func TestBaseline_ParsesWithItsTwoNewMembers(t *testing.T) {
	bl, err := LoadBaseline()
	if err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile("../pgconf/testdata/image/postgresql.conf")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^shared_preload_libraries = '([^']*)'`).FindSubmatch(conf)
	if m == nil {
		t.Fatal("no preload line in the image fixture")
	}
	if want := strings.Split(string(m[1]), ", "); !slices.Equal(bl.Preload, want) {
		t.Fatalf("preload %v, fixture %v", bl.Preload, want)
	}
	if !slices.IsSorted(bl.SessionSettings) || len(bl.SessionSettings) < 100 {
		t.Fatalf("session_settings %d, sorted %t", len(bl.SessionSettings), slices.IsSorted(bl.SessionSettings))
	}
	for _, n := range bl.SessionSettings {
		if !imageSetting(n) || strings.HasPrefix(n, "supautils.") {
			t.Errorf("session setting %s", n)
		}
	}
	for _, r := range [][2]string{
		{`"log_duration",`, ``},                                // control: the edit applies; still valid
		{`"log_duration",`, `"log_duration", "log_duration",`}, // duplicate
		{`"log_duration",`, `"work_mem", "log_duration",`},     // not a setting the comparison covers
		{`"log_duration",`, `"zz.x", "log_duration",`},         // out of order
		{`"preload": [`, `"preload": ["Bad", `},                // malformed library name
		{`"preload": [`, `"preload": ["pgaudit", `},            // a library twice
	} {
		if !strings.Contains(string(baselineJSON), r[0]) {
			t.Fatalf("control: %s not in the baseline", r[0])
		}
		_, err := parseBaseline([]byte(strings.Replace(string(baselineJSON), r[0], r[1], 1)))
		if (err == nil) != (r[1] == "") {
			t.Errorf("%q: %v", r[1], err)
		}
	}
	for _, member := range []string{"preload", "session_settings"} {
		re := regexp.MustCompile(`"` + member + `": \[[^\]]*\]`)
		if _, err := parseBaseline(re.ReplaceAll(baselineJSON, []byte(`"`+member+`": []`))); err == nil {
			t.Errorf("empty %s accepted", member)
		}
	}
}

// imageAnswer answers the two reads of the image's settings, and the canary's read, as a cluster of
// the given lists would.
func imageAnswer(preload, settings []string) func(string) ([]uint32, [][]string) {
	return func(sql string) ([]uint32, [][]string) {
		switch sql {
		case sqlPreload:
			return []uint32{25, 25}, [][]string{{strings.Join(preload, ", "), "supautils"}}
		case sqlImageSettings:
			var rows [][]string
			for _, s := range settings {
				rows = append(rows, []string{s})
			}
			return []uint32{25}, rows
		case sqlCanaryRelation:
			// No relation under the canary's name yet; the schema as the platform made it.
			return []uint32{25, 16, 25}, [][]string{{"", "f", canarySchemaACL}}
		}
		return nil, nil
	}
}

func TestRun_FailsWhenTheImagesSettingsDifferFromTheBaseline(t *testing.T) {
	bl, err := LoadBaseline()
	if err != nil {
		t.Fatal(err)
	}
	s := testSecrets(t)
	// Control: the baseline's own lists pass, and the verifier statements follow.
	conn, rec := recordingConn(t, imageAnswer(bl.Preload, bl.SessionSettings))
	if err := run(context.Background(), conn, s, bl); err != nil {
		t.Fatalf("control: %v", err)
	}
	if got := rec.statements(); len(got) < 3 || got[0] != sqlPreload || got[1] != sqlImageSettings ||
		!strings.HasPrefix(got[2], sqlPasswordSupabaseAdmin) {
		t.Fatalf("control: sent %q", got)
	}
	lacking := bl
	lacking.SessionSettings = slices.DeleteFunc(slices.Clone(bl.SessionSettings), func(n string) bool { return n == "pg_stat_statements.track_utility" })
	extra := bl
	extra.Preload = append(slices.Clone(bl.Preload), "t_extra")
	many := bl
	many.SessionSettings = slices.Clone(bl.SessionSettings[12:])
	for name, tc := range map[string]struct {
		bl   Baseline
		want string
	}{
		"lacking a name": {lacking, `"pg_stat_statements.track_utility"`},
		"extra preload":  {extra, `"t_extra"`},
		"twelve names":   {many, "and 4 more"},
	} {
		conn, rec := recordingConn(t, imageAnswer(bl.Preload, bl.SessionSettings))
		err := run(context.Background(), conn, s, tc.bl)
		if !errors.Is(err, ErrImageSettings) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
		if got := rec.statements(); !slices.Equal(got, []string{sqlPreload, sqlImageSettings}) {
			t.Errorf("%s: sent %q", name, got)
		}
	}
	// A name read from the server is quoted and sanitised in the error.
	conn, _ = recordingConn(t, imageAnswer(bl.Preload, append(slices.Clone(bl.SessionSettings), "t.\x1b[31m\nx")))
	if err := run(context.Background(), conn, s, bl); !errors.Is(err, ErrImageSettings) || strings.ContainsAny(err.Error(), "\x1b\n") {
		t.Errorf("unsanitised: %q", err)
	}
}

// TestRun_RefusesOnTheClusterWhenTheBaselineDiffers: on the pinned image, a
// baseline lacking one recorded name stops Run before the passwords are set.
func TestRun_RefusesOnTheClusterWhenTheBaselineDiffers(t *testing.T) {
	c := newCluster(t, 1)
	c.run()
	conn := c.dial("supabase_admin")
	bl := c.baseline
	bl.SessionSettings = slices.DeleteFunc(slices.Clone(bl.SessionSettings), func(n string) bool { return n == "pgaudit.role" })
	if err := run(context.Background(), conn, c.secrets, bl); !errors.Is(err, ErrImageSettings) || !strings.Contains(err.Error(), "pgaudit.role") {
		t.Fatalf("run: %v", err)
	}
	if c.storedIsPlatforms(conn) || c.str(conn, "select count(*)::text from pg_catalog.pg_roles where rolname = 'supapace_backup'") != "0" {
		t.Fatal("Run changed the cluster")
	}
}

// TestImageSettings_SameWithoutSessionPreload: the image's settings read as
// the platform's session reads them, and read by a session that loads no
// session preload library, are the same, and are the baseline's.
func TestImageSettings_SameWithoutSessionPreload(t *testing.T) {
	c := newCluster(t, 1)
	c.run()
	for label, conn := range map[string]*pgx.Conn{"platform session": c.dial("supabase_admin"),
		"no session preload": c.rawDial("supabase_admin", map[string]string{"session_preload_libraries": ""})} {
		preload, settings, err := readImageSettings(context.Background(), conn)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if d := imageDiff(c.baseline, preload, settings); len(d) != 0 {
			t.Errorf("%s: differs from the baseline: %v", label, d)
		}
	}
}

// ---- timeline and recovery reads ----

func TestReadTimeline(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want int
	}{{"00000001", 1}, {"0000000A", 10}, {"FFFFFFFF", 1<<32 - 1}, {"00000000", 0}, {"0000000a", 0}, {"0000000G", 0},
		{"", 0}, {"0000001", 0}, {"000000010", 0}, {"+0000001", 0}} {
		conn, _ := recordingConn(t, func(sql string) ([]uint32, [][]string) {
			if sql == sqlTimeline {
				return []uint32{25}, [][]string{{tc.v}}
			}
			return nil, nil
		})
		got, err := ReadTimeline(context.Background(), conn)
		if tc.want == 0 && err == nil || tc.want != 0 && (err != nil || got != tc.want) {
			t.Errorf("%q: %d, %v", tc.v, got, err)
		}
	}
	c := startCluster(t)
	if tl, err := ReadTimeline(context.Background(), c.dial("supabase_admin")); err != nil || tl != 1 {
		t.Fatalf("fresh cluster: %d, %v", tl, err)
	}
}

func TestInRecovery(t *testing.T) {
	c := startCluster(t)
	if in, err := InRecovery(context.Background(), c.dial("supabase_admin")); err != nil || in {
		t.Fatalf("fresh cluster: %t, %v", in, err)
	}
	f, err := os.OpenFile(filepath.Join(c.data, "standby.signal"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	os.Chown(filepath.Join(c.data, "standby.signal"), c.uid, c.gid)
	c.extraArgs = []string{"-c", "hot_standby=on"} // the image turns it off
	c.restartRecreate()
	if in, err := InRecovery(context.Background(), c.dial("supabase_admin")); err != nil || !in {
		t.Fatalf("standby: %t, %v", in, err)
	}
}

// ---- a recording connection ----

func testSecrets(t *testing.T) Secrets {
	t.Helper()
	s := Secrets{SupabaseAdminPassword: rnd(32), PostgresPassword: rnd(32), AuthenticatorPassword: rnd(32),
		PgsodiumRootKey: rnd(32), ScramSalts: map[string][]byte{}}
	for _, r := range platformLogins {
		salt, err := pgsock.ScramSalt([]byte(rnd(32)), rnd(10), r)
		if err != nil {
			t.Fatal(err)
		}
		s.ScramSalts[r] = salt
	}
	return s
}

type recorder struct {
	mu    sync.Mutex
	sent  []string
	kinds []string // the type of every message after the startup, in order
}

func (r *recorder) statements() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.sent)
}

func (r *recorder) messageKinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.kinds)
}

// recordingConn returns a client connection to an in-process server that
// records the text of every statement it is sent, in order, and answers each
// with the column types and rows answer gives (text values; type 16 is a
// boolean "t"/"f"), or with no rows.
func recordingConn(t *testing.T, answer func(sql string) ([]uint32, [][]string)) (*pgx.Conn, *recorder) {
	t.Helper()
	cli, srv := net.Pipe()
	rec := &recorder{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer srv.Close()
		serveRecording(srv, rec, answer)
	}()
	cfg, err := pgx.ParseConfig("postgres://t@127.0.0.1:5432/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg.DialFunc = func(context.Context, string, string) (net.Conn, error) { return cli, nil }
	cfg.LookupFunc = func(_ context.Context, h string) ([]string, error) { return []string{h}, nil }
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()); <-done })
	return conn, rec
}

func serveRecording(srv net.Conn, rec *recorder, answer func(string) ([]uint32, [][]string)) {
	be := pgproto3.NewBackend(srv, srv)
	for {
		m, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		if _, ok := m.(*pgproto3.StartupMessage); ok {
			break
		}
		srv.Write([]byte("N")) // no encryption
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.6"})
	be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	be.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if be.Flush() != nil {
		return
	}
	prepared := map[string]string{}
	var portal string
	var formats []int16
	desc := func(oids []uint32) pgproto3.BackendMessage {
		if len(oids) == 0 {
			return &pgproto3.NoData{}
		}
		rd := &pgproto3.RowDescription{}
		for i, o := range oids {
			rd.Fields = append(rd.Fields, pgproto3.FieldDescription{Name: []byte("c" + strconv.Itoa(i)), DataTypeOID: o, DataTypeSize: -1, TypeModifier: -1})
		}
		return rd
	}
	rows := func(oids []uint32, data [][]string, formats []int16) {
		for _, row := range data {
			dr := &pgproto3.DataRow{}
			for i, v := range row {
				f := int16(0)
				if len(formats) == 1 {
					f = formats[0]
				} else if i < len(formats) {
					f = formats[i]
				}
				b := []byte(v)
				if f == 1 && oids[i] == 16 {
					b = []byte{map[string]byte{"t": 1}[v]}
				}
				dr.Values = append(dr.Values, b)
			}
			be.Send(dr)
		}
		be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT " + strconv.Itoa(len(data)))})
	}
	params := regexp.MustCompile(`\$[0-9]+`)
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		rec.mu.Lock()
		rec.kinds = append(rec.kinds, fmt.Sprintf("%T", msg))
		switch m := msg.(type) {
		case *pgproto3.Query:
			rec.sent = append(rec.sent, m.String)
		case *pgproto3.Parse:
			rec.sent = append(rec.sent, m.Query)
		}
		rec.mu.Unlock()
		switch m := msg.(type) {
		case *pgproto3.Query:
			oids, data := answer(m.String)
			if len(oids) > 0 {
				be.Send(desc(oids))
				rows(oids, data, nil)
			} else {
				be.Send(&pgproto3.CommandComplete{CommandTag: []byte("OK")})
			}
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Parse:
			prepared[m.Name] = m.Query
			be.Send(&pgproto3.ParseComplete{})
		case *pgproto3.Describe:
			q := prepared[m.Name]
			if m.ObjectType == 'P' {
				q = prepared[portal]
			} else {
				pd := &pgproto3.ParameterDescription{}
				for range params.FindAllString(q, -1) {
					pd.ParameterOIDs = append(pd.ParameterOIDs, 25)
				}
				be.Send(pd)
			}
			oids, _ := answer(q)
			be.Send(desc(oids))
		case *pgproto3.Bind:
			portal, formats = m.PreparedStatement, slices.Clone(m.ResultFormatCodes)
			be.Send(&pgproto3.BindComplete{})
		case *pgproto3.Execute:
			oids, data := answer(prepared[portal])
			rows(oids, data, formats)
		case *pgproto3.Sync:
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case *pgproto3.Terminate:
			return
		}
		if be.Flush() != nil {
			return
		}
	}
}

// TestRun_RefusesMoreSettingsThanItReads: a cluster listing more settings than
// the read examines fails Run with nothing changed.
func TestRun_RefusesMoreSettingsThanItReads(t *testing.T) {
	bl, err := LoadBaseline()
	if err != nil {
		t.Fatal(err)
	}
	settings := slices.Clone(bl.SessionSettings)
	for i := range maxSettings {
		settings = append(settings, "t_other_"+strconv.Itoa(i))
	}
	conn, rec := recordingConn(t, imageAnswer(bl.Preload, settings))
	if err := run(context.Background(), conn, testSecrets(t), bl); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("run: %v", err)
	}
	if got := rec.statements(); !slices.Equal(got, []string{sqlPreload, sqlImageSettings}) {
		t.Fatalf("sent %q", got)
	}
}

// TestRekey_VerifierStatementsAreSimpleQueries: each password statement is one
// simple query message and the first three messages of the session are those;
// nothing is prepared under a name that would stay in the session, and no
// message of another kind is sent.
func TestRekey_VerifierStatementsAreSimpleQueries(t *testing.T) {
	conn, rec := recordingConn(t, func(sql string) ([]uint32, [][]string) {
		if sql == sqlRoleExists {
			return []uint32{16}, [][]string{{"t"}}
		}
		return nil, nil
	})
	if err := Rekey(context.Background(), conn, testSecrets(t)); err != nil {
		t.Fatal(err)
	}
	kinds, sent := rec.messageKinds(), rec.statements()
	if len(kinds) < 3 || len(sent) < 3 {
		t.Fatalf("sent %q", kinds)
	}
	for i := range 3 {
		if kinds[i] != "*pgproto3.Query" || !strings.Contains(sent[i], "password 'SCRAM-SHA-256$4096:") {
			t.Fatalf("message %d: %s %q", i, kinds[i], sent[i])
		}
	}
	for _, k := range kinds {
		if !slices.Contains([]string{"*pgproto3.Query", "*pgproto3.Parse", "*pgproto3.Describe", "*pgproto3.Bind",
			"*pgproto3.Execute", "*pgproto3.Sync"}, k) {
			t.Errorf("message of kind %s sent", k)
		}
	}
}

// TestRekey_LeavesNoPreparedPasswordStatement: on the pinned image, after the
// re-key the session holds no prepared statement naming a verifier.
func TestRekey_LeavesNoPreparedPasswordStatement(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	if err := Rekey(context.Background(), adm, c.secrets); err != nil {
		t.Fatal(err)
	}
	if n := c.str(adm, "select count(*)::text from pg_catalog.pg_prepared_statements where statement like $1", "%SCRAM%"); n != "0" {
		t.Fatalf("%s prepared statements name a verifier", n)
	}
	if n := c.str(adm, "select count(*)::text from pg_catalog.pg_prepared_statements"); n == "0" {
		t.Fatal("control: the existence read was not prepared")
	}
}

// TestGrantBackup_MakesAPlainGrantInheriting: a cluster whose backup role
// holds the membership without the inherit option is reported; after
// GrantBackup the membership inherits and the check is clean.
func TestGrantBackup_MakesAPlainGrantInheriting(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "revoke pg_read_all_settings from supapace_backup")
	c.exec(adm, "grant pg_read_all_settings to supapace_backup")
	c.wantFindings(c.assert(adm), "memberships-reserved")
	if err := GrantBackup(context.Background(), adm); err != nil {
		t.Fatal(err)
	}
	c.wantBackupRole(adm)
	c.wantFindings(c.assert(adm))
}

// TestRecoveryAndTimelineReads_OneRow: a read answered by no row or by two
// rows is an error.
func TestRecoveryAndTimelineReads_OneRow(t *testing.T) {
	for _, n := range []int{0, 2} {
		conn, _ := recordingConn(t, func(sql string) ([]uint32, [][]string) {
			var rows [][]string
			for range n {
				switch sql {
				case sqlInRecovery:
					rows = append(rows, []string{"f"})
				case sqlTimeline:
					rows = append(rows, []string{"00000001"})
				}
			}
			if sql == sqlInRecovery {
				return []uint32{16}, rows
			}
			return []uint32{25}, rows
		})
		if _, err := InRecovery(context.Background(), conn); err == nil {
			t.Errorf("recovery read, %d rows: no error", n)
		}
		if _, err := ReadTimeline(context.Background(), conn); err == nil {
			t.Errorf("timeline read, %d rows: no error", n)
		}
	}
}

// TestRekey_PoolerEntrySkippedWhenRoleAbsent: with a manager password and no
// manager role, the re-key sets the three verifiers and creates no role; with
// the role present, it sets the manager's verifier as well.
func TestRekey_PoolerEntrySkippedWhenRoleAbsent(t *testing.T) {
	c := startCluster(t)
	c.withPooler()
	adm := c.dial("supabase_admin")
	for _, r := range platformLogins {
		c.exec(adm, "alter role "+r+" password 't-other-"+rnd(8)+"'")
	}
	if err := Rekey(context.Background(), adm, c.secrets); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if !c.storedIsPlatforms(adm) {
		t.Fatal("the stored verifiers are not the platform's")
	}
	const manager = "select coalesce(string_agg(coalesce(rolpassword, '-'), ','), 'absent') from pg_catalog.pg_authid where rolname = 'supapace_pooler'"
	if got := c.str(adm, manager); got != "absent" {
		t.Fatalf("the re-key made the manager: %s", got)
	}
	c.wantBackupRole(adm)
	if err := EnsurePoolerLogin(context.Background(), adm, c.secrets); err != nil {
		t.Fatal(err)
	}
	c.exec(adm, "alter role supapace_pooler password 't-other-"+rnd(8)+"'")
	if err := Rekey(context.Background(), adm, c.secrets); err != nil {
		t.Fatalf("control rekey: %v", err)
	}
	want, _ := pgsock.ScramVerifier(c.secrets.PoolerPassword, c.secrets.ScramSalts["supapace_pooler"])
	if got := c.str(adm, manager); got != want {
		t.Fatalf("control: the manager stores %q", got)
	}
}

// TestRekey_EmptyPoolerPasswordSendsExactlyTheEarlierList: without a manager
// password the re-key sends the three verifier statements and the backup
// role's statements, nothing else; with one, the manager's statement follows
// the three.
func TestRekey_EmptyPoolerPasswordSendsExactlyTheEarlierList(t *testing.T) {
	s := testSecrets(t)
	var want []string
	for i, p := range []string{sqlPasswordSupabaseAdmin, sqlPasswordPostgres, sqlPasswordAuthenticator} {
		pw := []string{s.SupabaseAdminPassword, s.PostgresPassword, s.AuthenticatorPassword}[i]
		v, _ := pgsock.ScramVerifier(pw, s.ScramSalts[platformLogins[i]])
		st, err := verifierStatement(p, v)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, st)
	}
	tail := []string{sqlRoleExists, sqlGrantBackupSettings, sqlGrantBackupFuncs}
	answer := func(sql string) ([]uint32, [][]string) {
		if sql == sqlRoleExists {
			return []uint32{16}, [][]string{{"t"}}
		}
		return nil, nil
	}
	conn, rec := recordingConn(t, answer)
	if err := Rekey(context.Background(), conn, s); err != nil {
		t.Fatal(err)
	}
	if got := rec.statements(); !slices.Equal(got, append(slices.Clone(want), tail...)) {
		t.Fatalf("sent\n%q", got)
	}
	s.PoolerPassword = rnd(32)
	s.ScramSalts["supapace_pooler"] = make([]byte, 16)
	v, _ := pgsock.ScramVerifier(s.PoolerPassword, s.ScramSalts["supapace_pooler"])
	pst, err := verifierStatement(sqlPasswordPooler, v)
	if err != nil {
		t.Fatal(err)
	}
	conn, rec = recordingConn(t, answer)
	if err := Rekey(context.Background(), conn, s); err != nil {
		t.Fatal(err)
	}
	if got := rec.statements(); !slices.Equal(got, append(append(want, pst), tail...)) {
		t.Fatalf("control, with a manager password: sent\n%q", got)
	}
}

// TestAssertPins_SessionSetNameNotReportedFromCommandLine: a pinned name the
// platform's superuser session itself sets at startup reads source "client"
// in that session; it is not reported as missing from the command line.
func TestAssertPins_SessionSetNameNotReportedFromCommandLine(t *testing.T) {
	c := newCluster(t, 2)
	c.run()
	adm := c.dial("supabase_admin")
	if err := Run(context.Background(), adm, c.secrets); err != nil {
		t.Fatal(err)
	}
	if got := c.str(adm, "select source from pg_catalog.pg_settings where name = 'session_preload_libraries'"); got != "client" {
		t.Fatalf("control: session_preload_libraries from %s in the platform session", got)
	}
	r, err := AssertPins(context.Background(), adm, c.baseline, c.conf, pgconf.PinnedNames(2))
	if err != nil {
		t.Fatal(err)
	}
	c.wantFindings(r)
}

// TestAssertPins_NameNotInTheStartupListStillReported: a pinned name the
// session does not set itself and the command line lacks is reported.
func TestAssertPins_NameNotInTheStartupListStillReported(t *testing.T) {
	c := newCluster(t, 2)
	c.run()
	adm := c.dial("supabase_admin")
	if err := Run(context.Background(), adm, c.secrets); err != nil {
		t.Fatal(err)
	}
	if _, own := pgsock.StartupParams(true)["work_mem"]; own {
		t.Fatal("work_mem is in the startup list")
	}
	r, err := AssertPins(context.Background(), adm, c.baseline, c.conf, append(pgconf.PinnedNames(2), "work_mem"))
	if err != nil {
		t.Fatal(err)
	}
	c.wantFindings(r, "source-file")
	if len(r) != 1 || !hasDetail(r, "source-file", "work_mem is not set on the command line") {
		t.Fatalf("findings %+v", r)
	}
}
