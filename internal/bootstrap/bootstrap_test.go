package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

// frozenNames is the closed set of check names a report may carry.
var frozenNames = []string{"presence", "superuser", "attributes", "memberships-reserved",
	"memberships-dangerous", "role-settings", "schema-acl", "event-triggers", "auth-functions",
	"configuration", "source-file", "hba", "service-passwords"}

func TestLoadBaseline_Schema(t *testing.T) {
	b, err := LoadBaseline()
	if err != nil {
		t.Fatal(err)
	}
	im, err := nodecfg.LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(im.Postgres, "@"+b.Digest) {
		t.Fatalf("baseline digest %s is not the locked image %s", b.Digest, im.Postgres)
	}
	if b.Image != "supabase/postgres:17.6.1.166" || b.PGVersion != "17.6" {
		t.Fatalf("image %q version %q", b.Image, b.PGVersion)
	}
	if len(b.Roles) != 14 || len(b.Memberships) != 18 || len(b.EventTriggers) != 6 || len(b.RoleSettings) != 8 {
		t.Fatalf("roles %d memberships %d event triggers %d role settings %d",
			len(b.Roles), len(b.Memberships), len(b.EventTriggers), len(b.RoleSettings))
	}
	var supers []string
	for _, r := range b.Roles {
		if strings.HasPrefix(r.Name, "pg_") {
			t.Fatalf("baseline role %s starts pg_", r.Name)
		}
		if r.Super {
			supers = append(supers, r.Name)
		}
	}
	if !slices.Equal(supers, []string{"supabase_admin"}) {
		t.Fatalf("superusers %v", supers)
	}
	var schemas []string
	for _, s := range b.Schemas {
		schemas = append(schemas, s.Name)
	}
	if !slices.Equal(schemas, []string{"auth", "extensions", "realtime", "storage"}) {
		t.Fatalf("schemas %v", schemas)
	}
	f := b.Files
	if f.IncludeDir != "/etc/postgresql-custom/conf.d" || f.HBAFile != "/etc/postgresql/pg_hba.conf" ||
		f.IdentFile != "/etc/postgresql/pg_ident.conf" || f.SupautilsConf != "/etc/postgresql-custom/supautils.conf" ||
		f.PgsodiumKey != "/etc/postgresql-custom/pgsodium_root.key" {
		t.Fatalf("files %+v", f)
	}
	if len(b.AutoConf) != 0 || b.FreshClusterMB != 60 {
		t.Fatalf("auto_conf %v fresh_cluster_mb %d", b.AutoConf, b.FreshClusterMB)
	}
	// The parser is strict: an unknown member or trailing data is refused.
	if _, err := parseBaseline(bytes.Replace(baselineJSON, []byte(`"auto_conf"`), []byte(`"extra": 1, "auto_conf"`), 1)); err == nil {
		t.Fatal("unknown member accepted")
	}
	if _, err := parseBaseline(append(slices.Clone(baselineJSON), []byte("{}")...)); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, err := parseBaseline(bytes.Replace(baselineJSON, []byte(`"name": "realtime"`), []byte(`"name": "public"`), 1)); err == nil {
		t.Fatal("schema set other than auth, extensions, realtime, storage accepted")
	}
}

func TestForbidden_CoversBaseline(t *testing.T) {
	b, err := LoadBaseline()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, r := range b.Roles {
		names = append(names, r.Name)
	}
	for _, r := range platformRoles {
		names = append(names, r.Name)
	}
	for _, n := range names {
		if n != "authenticated" && !jwtx.ForbiddenUserRole(n) {
			t.Errorf("role %s of the baseline is not a forbidden user role", n)
		}
	}
	if jwtx.ForbiddenUserRole("authenticated") {
		t.Error("authenticated is forbidden")
	}
}

func TestAssert_NamesAreFrozen(t *testing.T) {
	if !slices.Equal(checkNames, frozenNames) {
		t.Fatalf("check names %v, frozen %v", checkNames, frozenNames)
	}
	// Every name constant the package declares is in the set, and every
	// report goes through one of them.
	fset := token.NewFileSet()
	for _, f := range []string{"assert.go"} {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "add" && len(call.Args) > 0 {
				id, ok := call.Args[0].(*ast.Ident)
				if !ok || !strings.HasPrefix(id.Name, "check") {
					t.Errorf("%s: report name is not a check constant", fset.Position(call.Pos()))
				}
			}
			return true
		})
	}
}

// TestAssert_AllowListMatchesImageFixture: the image's main file, its include
// lines, its include directory's files and the platform's override file are
// exactly the source files the assertion admits.
func TestAssert_AllowListMatchesImageFixture(t *testing.T) {
	conf, err := os.ReadFile("../pgconf/testdata/image/postgresql.conf")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/etc/postgresql/postgresql.conf"}
	incRE := regexp.MustCompile(`^include\s*=?\s*'([^']+)'`)
	dirRE := regexp.MustCompile(`^include_dir\s*=?\s*'([^']+)'`)
	dir := ""
	for _, l := range strings.Split(string(conf), "\n") {
		if m := incRE.FindStringSubmatch(l); m != nil {
			want = append(want, m[1])
		}
		if m := dirRE.FindStringSubmatch(l); m != nil {
			dir = m[1]
		}
	}
	if dir == "" {
		t.Fatal("no include_dir in the fixture")
	}
	ents, err := os.ReadDir("../pgconf/testdata/image/conf.d")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		want = append(want, dir+"/"+e.Name())
	}
	want = append(want, dir+"/"+pgconf.OverrideFile)
	if !slices.Equal(allowedSourceFiles, want) {
		t.Fatalf("allowedSourceFiles\n%v\nfixture gives\n%v", allowedSourceFiles, want)
	}
}

// TestStatements_AreConstants: every statement text the package sends is a
// constant. The client library's statement methods are called only inside
// execSQL and querySQL; every call of those passes a constant (or a literal),
// except the one in setVerifier, which sends a verifier checked by
// verifierStatement.
func TestStatements_AreConstants(t *testing.T) {
	fset := token.NewFileSet()
	consts := map[string]bool{}
	var files []*ast.File
	ents, _ := filepath.Glob("*.go")
	for _, f := range ents {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
		for _, d := range file.Decls {
			if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.CONST {
				for _, s := range g.Specs {
					for _, n := range s.(*ast.ValueSpec).Names {
						consts[n.Name] = true
					}
				}
			}
		}
	}
	raw := map[string]bool{"Exec": true, "Query": true, "QueryRow": true, "SendBatch": true, "CopyFrom": true,
		"Prepare": true, "PgConn": true, "LoadType": true}
	calls, exceptions := 0, 0
	for _, file := range files {
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				pos := fset.Position(call.Pos())
				switch f := call.Fun.(type) {
				case *ast.SelectorExpr:
					if raw[f.Sel.Name] && fn.Name.Name != "execSQL" && fn.Name.Name != "querySQL" {
						t.Errorf("%s: %s called outside execSQL/querySQL", pos, f.Sel.Name)
					}
				case *ast.Ident:
					if f.Name != "execSQL" && f.Name != "querySQL" {
						return true
					}
					calls++
					if len(call.Args) < 3 {
						t.Errorf("%s: short call", pos)
						return true
					}
					switch a := call.Args[2].(type) {
					case *ast.BasicLit:
					case *ast.Ident:
						if !consts[a.Name] {
							if fn.Name.Name == "setVerifier" && f.Name == "execSQL" {
								exceptions++
								return true
							}
							t.Errorf("%s: statement %s is not a constant", pos, a.Name)
						}
					default:
						t.Errorf("%s: statement is an expression", pos)
					}
				}
				return true
			})
		}
	}
	if calls < 20 || exceptions != 1 {
		t.Fatalf("%d statement calls, %d verifier exceptions", calls, exceptions)
	}
}

func TestVerifierStatement_Validates(t *testing.T) {
	salt := make([]byte, 16)
	v, err := pgsock.ScramVerifier("secret-password", salt)
	if err != nil {
		t.Fatal(err)
	}
	s, err := verifierStatement(sqlPasswordPostgres, v)
	if err != nil || s != sqlPasswordPostgres+v+"'" {
		t.Fatalf("statement %q, %v", s, err)
	}
	for _, bad := range []string{"", "x", v + "'; drop table x; --", strings.Replace(v, "4096", "1", 1),
		"SCRAM-SHA-256$4096:abc$def", v + "\n", "md5" + strings.Repeat("0", 32), strings.Replace(v, "$", "' $", 1)} {
		if _, err := verifierStatement(sqlPasswordPostgres, bad); err == nil {
			t.Errorf("verifier %q accepted", bad)
		}
	}
}

func TestRun_RefusesBadSecrets(t *testing.T) {
	salts := map[string][]byte{"supabase_admin": make([]byte, 16), "postgres": make([]byte, 16), "authenticator": make([]byte, 16)}
	for name, s := range map[string]Secrets{
		"same passwords": {SupabaseAdminPassword: "a1", PostgresPassword: "a1", AuthenticatorPassword: "b1", ScramSalts: salts},
		"empty password": {SupabaseAdminPassword: "a1", PostgresPassword: "", AuthenticatorPassword: "b1", ScramSalts: salts},
		"missing salt": {SupabaseAdminPassword: "a1", PostgresPassword: "c1", AuthenticatorPassword: "b1",
			ScramSalts: map[string][]byte{"supabase_admin": make([]byte, 16)}},
	} {
		// A nil connection: the secrets are refused before any statement.
		if err := Run(context.Background(), nil, s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRun_AuthFunctionsQualified_Static(t *testing.T) {
	for name, body := range authBodies {
		if err := unqualified(body); err != nil {
			t.Errorf("auth.%s: %v", name, err)
		}
	}
	for _, bad := range []string{"select current_setting('x')", "select '1'::uuid", "select a->>'b'",
		"select pg_catalog.coalesce(1)", "select x = y", "select nullif(a, '')", "select pg_catalog.nullif(a, '')",
		"select case a when '' then null else a end", "select a in ('x')", "select a between 1 and 2",
		"select a like 'x'", "select a is distinct from b", "select a = any(b)", "select a operator(public.=) b",
		"select a operator(=) b"} {
		if unqualified(bad) == nil {
			t.Errorf("%q passes", bad)
		}
	}
}

// unqualified returns an error for the first function, type or operator in
// body that is not written pg_catalog-qualified, and for any construct that
// looks an operator up by name through the caller's search path (nullif, IN,
// BETWEEN, LIKE, IS DISTINCT FROM, ANY/SOME/ALL, a simple CASE). coalesce
// looks up no operator.
func unqualified(body string) error {
	s := regexp.MustCompile(`'(?:[^']|'')*'`).ReplaceAllString(body, "''")
	s = regexp.MustCompile(`operator\(pg_catalog\.[^()\s.]+\)`).ReplaceAllString(s, " ")
	words := regexp.MustCompile(`[A-Za-z_][A-Za-z_0-9.]*`).FindAllString(strings.ToLower(s), -1)
	for i, w := range words {
		switch w {
		case "nullif", "in", "between", "like", "ilike", "similar", "distinct", "any", "some", "all", "operator":
			return errors.New("construct " + w)
		case "case":
			if i+1 == len(words) || words[i+1] != "when" {
				return errors.New("simple case")
			}
		}
	}
	for _, m := range regexp.MustCompile(`([A-Za-z_][A-Za-z_0-9.]*)\s*\(`).FindAllStringSubmatch(s, -1) {
		if m[1] == "coalesce" || strings.HasPrefix(m[1], "pg_catalog.") && strings.Count(m[1], ".") == 1 &&
			m[1] != "pg_catalog.coalesce" && m[1] != "pg_catalog.nullif" {
			continue
		}
		return errors.New("function " + m[1])
	}
	for _, m := range regexp.MustCompile(`::\s*([A-Za-z_][A-Za-z_0-9.]*)`).FindAllStringSubmatch(s, -1) {
		if !strings.HasPrefix(m[1], "pg_catalog.") {
			return errors.New("type " + m[1])
		}
	}
	rest := regexp.MustCompile(`::`).ReplaceAllString(s, " ")
	if i := strings.IndexAny(rest, "+-*/<>=~!@#%^&|`?"); i >= 0 {
		return errors.New("operator at " + strconv.Itoa(i))
	}
	return nil
}

// ---- tests against the pinned cluster image ----

func TestRun_PasswordsAreVerifiers(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	for role, pw := range map[string]string{"supabase_admin": c.secrets.SupabaseAdminPassword,
		"postgres": c.secrets.PostgresPassword, "authenticator": c.secrets.AuthenticatorPassword} {
		want, _ := pgsock.ScramVerifier(pw, c.secrets.ScramSalts[role])
		if got := c.str(conn, "select rolpassword from pg_catalog.pg_authid where rolname = $1", role); got != want {
			t.Errorf("%s: stored %q, want %q", role, got, want)
		}
	}
	if n := c.str(conn, "select count(*)::text from pg_catalog.pg_authid where rolname = any($1) and rolpassword is null", servicePasswordRoles); n != "6" {
		t.Errorf("%s of the six service roles without a password", n)
	}
	// Phase B: the platform's administrative role logs in with its password.
	c.phaseB()
	conn = c.dial("supabase_admin")
	if got := c.str(conn, "select current_user::text"); got != "supabase_admin" {
		t.Fatalf("logged in as %q", got)
	}
}

func TestRun_NoPasswordsForServiceRoles(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	if n := c.str(conn, "select count(*)::text from pg_catalog.pg_authid where rolname = any($1) and rolpassword is not null", servicePasswordRoles); n != "0" {
		t.Fatalf("%s service roles with a password", n)
	}
	c.exec(conn, "alter role pgbouncer password 'x-1234'")
	c.wantFindings(c.assert(conn), "service-passwords")
}

func TestRun_Idempotent(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	const snap = `select string_agg(x, E'\n' order by x) from (
	  select a.rolname || ' ' || coalesce(a.rolpassword, '-') || ' ' ||
	         row(a.rolsuper, a.rolinherit, a.rolcreaterole, a.rolcreatedb, a.rolcanlogin, a.rolreplication, a.rolbypassrls, a.rolconnlimit)::text as x from pg_catalog.pg_authid a
	  union all select distinct m.member::regrole || ' in ' || m.roleid::regrole from pg_catalog.pg_auth_members m
	  union all select p.oid::regprocedure || ' ' || p.proowner::regrole || ' ' || p.prosrc || p.prosecdef from pg_catalog.pg_proc p where p.pronamespace = 'auth'::regnamespace
	  union all select 'acl ' || p.oid::regprocedure || coalesce(p.proacl::text, '-') from pg_catalog.pg_proc p where p.proname in ('pg_backup_start', 'pg_backup_stop', 'pg_switch_wal', 'pg_create_restore_point')) s`
	before := c.str(conn, snap)
	if err := Run(context.Background(), conn, c.secrets); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if after := c.str(conn, snap); after != before {
		t.Fatalf("second run changed the catalog:\nbefore\n%s\nafter\n%s", before, after)
	}
	c.wantFindings(c.assert(conn))
}

func TestRun_AuthUIDReadsJSONClaims(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("postgres")
	const uid = "4f7ab3c2-9d1e-4c55-8a1b-2e3f4a5b6c7d"
	c.exec(conn, `select pg_catalog.set_config('request.jwt.claims', '{"sub":"`+uid+`","role":"authenticated","email":"tester"}', false)`)
	got := c.str(conn, "select auth.uid()::text || ' ' || auth.role() || ' ' || auth.email() || ' ' || (auth.jwt() ->> 'sub')")
	if got != uid+" authenticated tester "+uid {
		t.Fatalf("JSON claims: %q", got)
	}
	// The legacy per-claim setting is read first.
	const other = "00000000-0000-4000-8000-000000000001"
	c.exec(conn, `select pg_catalog.set_config('request.jwt.claim.sub', '`+other+`', false)`)
	if got := c.str(conn, "select auth.uid()::text"); got != other {
		t.Fatalf("legacy claim: %q", got)
	}
	c.exec(conn, `select pg_catalog.set_config('request.jwt.claim.sub', '', false), pg_catalog.set_config('request.jwt.claims', '', false)`)
	if got := c.str(conn, "select coalesce(auth.uid()::text, 'null')"); got != "null" {
		t.Fatalf("no claims: %q", got)
	}
}

func TestRun_FunctionsNotSecurityDefiner(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	got := c.str(conn, `select string_agg(proname || ' ' || prosecdef || ' ' || proowner::regrole, ',' order by proname)
	  from pg_catalog.pg_proc where pronamespace = 'auth'::regnamespace and proname in ('uid', 'role', 'email', 'jwt')`)
	if got != "email false supabase_auth_admin,jwt false supabase_auth_admin,role false supabase_auth_admin,uid false supabase_auth_admin" {
		t.Fatalf("auth functions: %s", got)
	}
	c.exec(conn, "alter function auth.uid() security definer")
	c.wantFindings(c.assert(conn), "auth-functions")
}

func TestRun_AuthFunctionsQualified(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	// The bodies stored in the cluster are the platform's and are qualified.
	for name, body := range authBodies {
		got := c.str(conn, "select prosrc from pg_catalog.pg_proc where pronamespace = 'auth'::regnamespace and proname = $1", name)
		if got != body {
			t.Errorf("auth.%s body differs", name)
		}
		if err := unqualified(got); err != nil {
			t.Errorf("auth.%s: %v", name, err)
		}
	}
	// A caller's search_path naming a schema with its own current_setting
	// does not change what the functions return.
	pg := c.dial("postgres")
	c.exec(pg, "create schema hostile")
	c.exec(pg, "create function hostile.current_setting(text, boolean) returns text language sql as $$ select '{\"sub\":\"00000000-0000-4000-8000-0000000000ff\",\"role\":\"service_role\",\"email\":\"other\"}' $$")
	c.exec(pg, "create function hostile.current_setting(text) returns text language sql as $$ select 'other' $$")
	// An equality operator for text that never holds, ahead of pg_catalog.
	c.exec(pg, "create function hostile.never(text, text) returns boolean language sql as $$ select false $$")
	c.exec(pg, "create operator hostile.= (leftarg = text, rightarg = text, function = hostile.never)")
	c.exec(pg, "set search_path = hostile, pg_catalog, public")
	if got := c.str(pg, "select current_setting('request.jwt.claims', true)"); !strings.Contains(got, "service_role") {
		t.Fatalf("control: the hostile function is not reached unqualified: %q", got)
	}
	const uid = "4f7ab3c2-9d1e-4c55-8a1b-2e3f4a5b6c7d"
	// Empty per-claim settings: only a working equality test falls through to
	// the JSON claims.
	c.exec(pg, "select pg_catalog.set_config('request.jwt.claim.sub', '', false), pg_catalog.set_config('request.jwt.claim.role', '', false), pg_catalog.set_config('request.jwt.claim.email', '', false), pg_catalog.set_config('request.jwt.claim', '', false)")
	c.exec(pg, `select pg_catalog.set_config('request.jwt.claims', '{"sub":"`+uid+`","role":"authenticated","email":"tester"}', false)`)
	got := c.str(pg, "select auth.uid()::pg_catalog.text || ' ' || auth.role() || ' ' || auth.email() || ' ' || (auth.jwt() operator(pg_catalog.->>) 'role')")
	if got != uid+" authenticated tester authenticated" {
		t.Fatalf("with a hostile search_path: %q", got)
	}
}

func TestAssert_PassesOnFreshCluster(t *testing.T) {
	c := startCluster(t)
	c.wantFindings(c.assert(c.dial("supabase_admin")))
	// Phase B adds the platform's pg_hba, which AssertHBA accepts.
	c.phaseB()
	conn := c.dial("supabase_admin")
	c.wantFindings(c.assert(conn))
	c.wantFindings(c.assertHBA(conn))
}

func TestAssert_PassesAfterOrdinaryTenantActivity(t *testing.T) {
	c := startCluster(t)
	pg := c.dial("postgres")
	for _, s := range []string{
		"create role t_app nologin", // granted back to postgres with admin
		"grant t_app to authenticator",
		"grant authenticated to t_app",
		"create role t_rls nologin bypassrls",
		"create role t_login login replication password 'x-1234'",
		"alter role authenticated set statement_timeout = '5s'",
		"alter role authenticator set statement_timeout = '9s'",
		"alter role anon set work_mem = '8MB'",
		"create table public.t(x int)",
		"create function public.t_evt() returns event_trigger language plpgsql as $$ begin end $$",
		"create event trigger t_evt on ddl_command_end execute function public.t_evt()",
		"create table public.t2(x int)",
	} {
		c.exec(pg, s)
	}
	if n := c.str(pg, "select count(*)::text from pg_catalog.pg_auth_members m join pg_catalog.pg_roles r on r.oid = m.roleid where r.rolname = 't_app' and m.member = 'postgres'::regrole and m.admin_option"); n != "1" {
		t.Fatalf("control: t_app granted back to postgres with admin: %s", n)
	}
	c.wantFindings(c.assert(c.dial("supabase_admin")))
}

func TestAssert_ReportsExtraSuperuser(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	c.exec(conn, "create role t_root superuser nologin")
	c.wantFindings(c.assert(conn), "superuser")
	c.exec(conn, "alter role t_root nosuperuser")
	c.exec(conn, "alter role postgres superuser")
	c.wantFindings(c.assert(conn), "superuser") // postgres's attributes are not compared, the superuser set is
}

func TestAssert_ReportsReservedMembership(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	c.exec(conn, "grant supabase_storage_admin to postgres")
	c.wantFindings(c.assert(conn), "memberships-dangerous")
	c.exec(conn, "revoke supabase_storage_admin from postgres")
	c.exec(conn, "grant pg_monitor to supabase_auth_admin")
	c.wantFindings(c.assert(conn), "memberships-reserved")
	c.exec(conn, "revoke pg_monitor from supabase_auth_admin")
	c.exec(conn, "revoke pg_read_all_settings from supapace_backup")
	c.wantFindings(c.assert(conn), "memberships-reserved")
}

func TestAssert_DistinctMembershipPairs(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	// A second grant of the same pair by another grantor.
	c.exec(conn, "grant pg_read_all_settings to postgres with admin option")
	c.exec(conn, "grant pg_read_all_settings to supapace_backup granted by postgres")
	if n := c.str(conn, "select count(*)::text from pg_catalog.pg_auth_members where member = 'supapace_backup'::regrole and roleid = 'pg_read_all_settings'::regrole"); n != "2" {
		t.Fatalf("control: %s grants of the pair", n)
	}
	c.wantFindings(c.assert(conn))
}

func TestAssert_ReportsPlatformRoleAttributeDrift(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	c.exec(conn, "alter role supabase_storage_admin createdb")
	c.wantFindings(c.assert(conn), "attributes")
	c.exec(conn, "alter role supabase_storage_admin nocreatedb")
	c.exec(conn, "alter role supapace_backup connection limit 1")
	c.wantFindings(c.assert(conn), "attributes")
	c.exec(conn, "alter role supapace_backup connection limit -1")
	c.exec(conn, "alter role supabase_auth_admin set search_path = public")
	c.wantFindings(c.assert(conn), "role-settings")
}

func TestAssert_ReportsSchemaACLDrift(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	c.exec(conn, "grant create on schema storage to anon")
	c.wantFindings(c.assert(conn), "schema-acl")
	c.exec(conn, "revoke create on schema storage from anon")
	c.wantFindings(c.assert(conn))
	c.exec(conn, "alter schema auth owner to postgres")
	r := c.assert(conn)
	c.wantFindings(r, "schema-acl")
	if !slices.ContainsFunc(r, func(f nodecfg.CheckResult) bool { return strings.Contains(f.Detail, "owned by") }) {
		t.Fatalf("no owner finding: %+v", r)
	}
}

func TestAssert_ReportsSuperuserOwnedEventTrigger(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	c.exec(conn, "create function public.t_evt() returns event_trigger language plpgsql as $$ begin end $$")
	c.exec(conn, "create event trigger t_login on login execute function public.t_evt()")
	c.wantFindings(c.assert(conn), "event-triggers")
}

func TestAssert_ReportsMissingRoleAndSchema(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	c.exec(conn, "alter role dashboard_user rename to t_dash")
	c.exec(conn, "alter schema realtime rename to t_realtime")
	c.wantFindings(c.assert(conn), "presence", "attributes", "schema-acl")
}

func TestAssert_ConfigByFileAndLine(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	if got := c.str(conn, "select setting from pg_catalog.pg_settings where name = 'shared_buffers'"); got != "16384" {
		t.Fatalf("control: shared_buffers reads %q in base units", got)
	}
	c.wantFindings(c.assert(conn))
	// A setting at another line of the platform's file: the two swapped lines are reported.
	lines := strings.SplitAfter(string(c.conf), "\n")
	lines[0], lines[1] = lines[1], lines[0]
	r, err := Assert(context.Background(), conn, c.baseline, []byte(strings.Join(lines, "")))
	if err != nil {
		t.Fatal(err)
	}
	c.wantFindings(r, "configuration")
	if len(r) != 2 {
		t.Fatalf("findings %+v", r)
	}
	// A later file of the include directory overrides one setting.
	if err := os.WriteFile(filepath.Join(c.render, "conf.d", "zzz-later.conf"), []byte("work_mem = 8MB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.restart()
	conn = c.dial("supabase_admin")
	if got := c.str(conn, "select setting from pg_catalog.pg_settings where name = 'work_mem'"); got != "8192" {
		t.Fatalf("control: the later file applies: work_mem %q", got)
	}
	r = c.assert(conn)
	c.wantFindings(r, "configuration", "source-file")
	if !strings.Contains(r[0].Detail, "work_mem") {
		t.Fatalf("finding %+v", r[0])
	}
}

func TestAssert_ReportsAutoConfOverride(t *testing.T) {
	c := startCluster(t)
	c.appendAutoConf("max_connections = 50\n")
	c.restart()
	conn := c.dial("supabase_admin")
	if got := c.str(conn, "select setting from pg_catalog.pg_settings where name = 'max_connections'"); got != "50" {
		t.Fatalf("control: max_connections %q", got)
	}
	c.wantFindings(c.assert(conn), "configuration", "source-file")
}

// TestAssert_ReportsSettingFromChangedFile: a setting still in force from a
// file outside the allowed ones is reported after its line has been removed
// from that file without a reload.
func TestAssert_ReportsSettingFromChangedFile(t *testing.T) {
	c := startCluster(t)
	auto := filepath.Join(c.data, "postgresql.auto.conf")
	orig, err := os.ReadFile(auto)
	if err != nil {
		t.Fatal(err)
	}
	c.appendAutoConf("deadlock_timeout = 2s\n")
	c.restart()
	if err := os.WriteFile(auto, orig, 0); err != nil {
		t.Fatal(err)
	}
	conn := c.dial("supabase_admin")
	if got := c.str(conn, "select setting from pg_catalog.pg_settings where name = 'deadlock_timeout'"); got != "2000" {
		t.Fatalf("control: deadlock_timeout %q", got)
	}
	r := c.assert(conn)
	c.wantFindings(r, "source-file")
	if len(r) != 1 || !strings.Contains(r[0].Detail, `"deadlock_timeout" is in force from`) {
		t.Fatalf("findings %+v", r)
	}
}

func TestAssert_ReportsAnyAutoConfSetting(t *testing.T) {
	c := startCluster(t)
	c.appendAutoConf("log_min_duration_statement = 1000\n")
	c.restart()
	conn := c.dial("supabase_admin")
	if got := c.str(conn, "select setting from pg_catalog.pg_settings where name = 'log_min_duration_statement'"); got != "1000" {
		t.Fatalf("control: log_min_duration_statement %q", got)
	}
	c.wantFindings(c.assert(conn), "source-file")
}

func TestAssert_ReportsIncludeFromAutoConf(t *testing.T) {
	c := startCluster(t)
	extra := filepath.Join(c.data, "extra.conf")
	if err := os.WriteFile(extra, []byte("log_min_duration_statement = 2000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(extra, c.uid, c.gid); err != nil { // as root, the server runs at the project uid
		t.Fatal(err)
	}
	c.appendAutoConf("include '/var/lib/postgresql/data/extra.conf'\n")
	c.restart()
	conn := c.dial("supabase_admin")
	if got := c.str(conn, "select setting from pg_catalog.pg_settings where name = 'log_min_duration_statement'"); got != "2000" {
		t.Fatalf("control: the included file applies: %q", got)
	}
	r := c.assert(conn)
	c.wantFindings(r, "source-file")
	if !strings.Contains(r[0].Detail, "extra.conf") {
		t.Fatalf("finding %+v", r[0])
	}
}

func TestAssert_ReportsCommandLineDrift(t *testing.T) {
	c := startCluster(t)
	c.extraArgs = []string{"-c", "work_mem=8MB"}
	c.restartRecreate()
	conn := c.dial("supabase_admin")
	c.wantFindings(c.assert(conn), "configuration", "source-file")
}

func TestAssertHBA_ReportsExtraLine(t *testing.T) {
	c := startCluster(t)
	c.phaseB()
	conn := c.dial("supabase_admin")
	c.wantFindings(c.assertHBA(conn))
	hbaPath := filepath.Join(c.render, "pg_hba.conf")
	os.Chmod(hbaPath, 0o644)
	f, err := os.OpenFile(hbaPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("local   all  postgres                       trust\n")
	f.Close()
	c.exec(conn, "select pg_catalog.pg_reload_conf()")
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := c.assertHBA(c.dial("supabase_admin"))
		if len(r) > 0 {
			c.wantFindings(r, "hba")
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no finding after the extra line")
		}
		time.Sleep(200 * time.Millisecond)
	}
	// A line that does not parse is reported too.
	if err := os.WriteFile(hbaPath, append(slices.Clone(c.hba), "local all all nosuchmethod\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	c.exec(c.dial("supabase_admin"), "select pg_catalog.pg_reload_conf()")
	deadline = time.Now().Add(10 * time.Second)
	for {
		r := c.assertHBA(c.dial("supabase_admin"))
		if len(r) > 0 {
			c.wantFindings(r, "hba")
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no finding after the bad line")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ---- the cluster harness ----

var clusterSlots = make(chan struct{}, 4) // clusters running at once

type cluster struct {
	t                    *testing.T
	name, ref, image     string
	root, data, render   string
	uid, gid             int
	pid                  int
	start                uint64
	phase                string
	secrets              Secrets
	conf, hba, imageConf []byte
	baseline             Baseline
	extraArgs            []string
}

func requireDocker(t *testing.T) string {
	t.Helper()
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skip("docker not reachable")
	}
	im, err := nodecfg.LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("docker", "image", "inspect", im.Postgres).Run(); err != nil {
		t.Skipf("image %s not present", im.Postgres)
	}
	return im.Postgres
}

func rnd(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// startCluster runs the pinned image as the platform's first boot does (no
// network, the image's own pg_hba, the platform's rendered files), runs Run
// over the socket and returns the cluster.
func startCluster(t *testing.T) *cluster {
	c := newCluster(t, 1)
	c.run()
	conn := c.dial("supabase_admin")
	if err := Run(context.Background(), conn, c.secrets); err != nil {
		c.logs()
		t.Fatalf("run: %v", err)
	}
	return c
}

// newCluster prepares a cluster's directories, rendered files and secrets
// without starting it. Layout 2 renders the override file without the pinned
// settings and passes those on the command line.
func newCluster(t *testing.T, layout int) *cluster {
	img := requireDocker(t)
	t.Parallel()
	clusterSlots <- struct{}{}
	t.Cleanup(func() { <-clusterSlots })
	c := &cluster{t: t, image: img, ref: rnd(10), name: "sp-test-bootstrap-" + rnd(6), phase: "A",
		uid: os.Getuid(), gid: os.Getgid()}
	var err error
	if c.baseline, err = LoadBaseline(); err != nil {
		t.Fatal(err)
	}
	c.root = t.TempDir()
	c.data = filepath.Join(c.root, c.ref, "data")
	sock := filepath.Join(c.root, c.ref, "sock")
	c.render = filepath.Join(t.TempDir(), "render")
	// Registered after the temporary directories, so it runs before their
	// removal: the server must be gone before its data directory is removed.
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", c.name).Run() })
	for _, d := range []string{c.data, sock, filepath.Join(c.render, "conf.d"), filepath.Join(c.render, "tools")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if c.uid == 0 { // as root (on a node): an unprivileged project uid
		c.uid, c.gid = 700621, 700621
		for _, d := range []string{filepath.Join(c.root, c.ref), c.data, sock} {
			os.Chown(d, c.uid, c.gid)
		}
		os.Chmod(c.render, 0o755)
		os.Chmod(filepath.Join(c.render, "conf.d"), 0o755)
	}
	fix := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("../pgconf/testdata/image", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	passwd, err := pgconf.Passwd(fix("passwd"), c.uid, c.gid)
	if err != nil {
		t.Fatal(err)
	}
	group, err := pgconf.Group(fix("group"), c.gid)
	if err != nil {
		t.Fatal(err)
	}
	supa, err := pgconf.Supautils(fix("supautils.conf"), false)
	if err != nil {
		t.Fatal(err)
	}
	if layout == 2 {
		if c.conf, err = pgconf.OverridesPinned(nil, 512); err != nil {
			t.Fatal(err)
		}
		if c.extraArgs, err = pgconf.Pins(nil); err != nil {
			t.Fatal(err)
		}
	} else if c.conf, err = pgconf.Overrides(nil, 512); err != nil {
		t.Fatal(err)
	}
	if c.hba, err = pgconf.HBA(nodecfg.Default("sp.test").Slice(0)); err != nil {
		t.Fatal(err)
	}
	c.imageConf = fix("postgresql.conf")
	files := map[string][]byte{"passwd": passwd, "group": group, "supautils.conf": supa,
		"pg_hba.conf": c.hba, "pg_ident.conf": pgconf.Ident(), "pgsodium_root.key": []byte(rnd(32)),
		"conf.d/" + pgconf.OverrideFile: c.conf}
	ents, _ := os.ReadDir("../pgconf/testdata/image/conf.d")
	var names []string
	for _, e := range ents {
		files["conf.d/"+e.Name()] = fix("conf.d/" + e.Name())
		names = append(names, e.Name())
	}
	if err := pgconf.SortsLast(names); err != nil {
		t.Fatal(err)
	}
	for n, b := range files {
		mode := os.FileMode(0o444)
		if n == "pgsodium_root.key" {
			mode = 0o400
		}
		p := filepath.Join(c.render, n)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if os.Getuid() == 0 && n == "pgsodium_root.key" {
			os.Chown(p, c.uid, c.gid)
		}
		os.Chmod(p, mode)
	}
	dek := []byte(rnd(32))
	c.secrets = Secrets{SupabaseAdminPassword: rnd(32), PostgresPassword: rnd(32), AuthenticatorPassword: rnd(32),
		PgsodiumRootKey: rnd(32), ScramSalts: map[string][]byte{}}
	for _, r := range []string{"supabase_admin", "postgres", "authenticator"} {
		if c.secrets.ScramSalts[r], err = pgsock.ScramSalt(dek, c.ref, r); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// run starts the container for the current phase and waits until the
// platform can log in to it.
func (c *cluster) run() {
	c.t.Helper()
	cl, err := pgconf.CommandLine(c.imageConf)
	if err != nil {
		c.t.Fatal(err)
	}
	r := c.render
	args := []string{"run", "-d", "--name", c.name, "--hostname", c.name, "--label", "supapace.test=1",
		"--user", strconv.Itoa(c.uid) + ":" + strconv.Itoa(c.gid), "--network", "none",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--memory", "512m", "--memory-swap", "512m", "--cpus", "1",
		"--pids-limit", "512", "--shm-size", "64m", "--ulimit", "core=0", "--no-healthcheck", "--ipc", "private",
		"-v", c.data + ":/var/lib/postgresql/data", "-v", filepath.Join(c.root, c.ref, "sock") + ":/var/run/postgresql",
		"-v", r + "/passwd:/etc/passwd:ro", "-v", r + "/group:/etc/group:ro",
		"-v", r + "/pgsodium_root.key:" + c.baseline.Files.PgsodiumKey + ":ro",
		"-v", r + "/conf.d:" + c.baseline.Files.IncludeDir + ":ro",
		"-v", r + "/supautils.conf:" + c.baseline.Files.SupautilsConf + ":ro",
		"-v", r + "/tools:/opt/supapace/tools:ro"}
	if c.phase == "A" {
		args = append(args, "-e", "POSTGRES_PASSWORD="+rnd(32))
	} else {
		args = append(args, "-v", r+"/pg_hba.conf:"+c.baseline.Files.HBAFile+":ro",
			"-v", r+"/pg_ident.conf:"+c.baseline.Files.IdentFile+":ro")
	}
	args = append(append(append(args, c.image, "postgres", "-D", "/etc/postgresql"), cl...), c.extraArgs...)
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		c.t.Fatalf("docker run: %v %s", err, out)
	}
	c.waitReady()
}

func (c *cluster) waitReady() {
	c.t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", c.name).Output()
	if err != nil {
		c.t.Fatal(err)
	}
	if c.pid, err = strconv.Atoi(strings.TrimSpace(string(out))); err != nil || c.pid <= 1 {
		c.logs()
		c.t.Fatalf("container pid %q", out)
	}
	if c.start, err = pgsock.ProcStart(c.pid); err != nil {
		c.t.Fatal(err)
	}
	// While the image initialises, its temporary server is another process
	// and is refused as a peer; the login succeeds once the init is the server.
	deadline := time.Now().Add(180 * time.Second)
	for {
		conn, err := pgsock.Dial(context.Background(), c.target("supabase_admin"))
		if err == nil {
			conn.Close(context.Background())
			return
		}
		if time.Now().After(deadline) {
			c.logs()
			c.t.Fatalf("cluster not reachable: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func (c *cluster) logs() {
	out, _ := exec.Command("docker", "logs", "--tail", "30", c.name).CombinedOutput()
	c.t.Logf("container log:\n%s", out)
}

func (c *cluster) target(user string) pgsock.Target {
	tg := pgsock.Target{ProjectsDir: c.root, Ref: c.ref, UID: c.uid, PostmasterPid: c.pid, PostmasterStart: c.start,
		User: user, Superuser: user == "supabase_admin", AllowTrust: c.phase == "A"}
	if c.phase == "B" {
		tg.Password = map[string]string{"supabase_admin": c.secrets.SupabaseAdminPassword,
			"postgres": c.secrets.PostgresPassword, "authenticator": c.secrets.AuthenticatorPassword}[user]
		tg.ScramSalt = c.secrets.ScramSalts[user]
	}
	return tg
}

func (c *cluster) dial(user string) *pgx.Conn {
	c.t.Helper()
	conn, err := pgsock.Dial(context.Background(), c.target(user))
	if err != nil {
		c.t.Fatalf("dial %s: %v", user, err)
	}
	c.t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// restart restarts the same container (same data and mounts).
func (c *cluster) restart() {
	c.t.Helper()
	if out, err := exec.Command("docker", "restart", "-t", "30", c.name).CombinedOutput(); err != nil {
		c.t.Fatalf("docker restart: %v %s", err, out)
	}
	c.waitReady()
}

// restartRecreate stops and removes the container and runs it again.
func (c *cluster) restartRecreate() {
	c.t.Helper()
	if out, err := exec.Command("docker", "stop", "-t", "30", c.name).CombinedOutput(); err != nil {
		c.t.Fatalf("docker stop: %v %s", err, out)
	}
	if out, err := exec.Command("docker", "rm", "-v", c.name).CombinedOutput(); err != nil {
		c.t.Fatalf("docker rm: %v %s", err, out)
	}
	c.run()
}

// phaseB restarts the cluster under the platform's pg_hba and pg_ident.
func (c *cluster) phaseB() {
	c.phase = "B"
	c.restartRecreate()
}

func (c *cluster) appendAutoConf(s string) {
	f, err := os.OpenFile(filepath.Join(c.data, "postgresql.auto.conf"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		c.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		c.t.Fatal(err)
	}
}

func (c *cluster) exec(conn *pgx.Conn, sql string, args ...any) {
	c.t.Helper()
	ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
	defer cancel()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		c.t.Fatalf("%s: %v", sql, pgsock.Clean(err))
	}
}

func (c *cluster) str(conn *pgx.Conn, sql string, args ...any) string {
	c.t.Helper()
	ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
	defer cancel()
	var s *string
	if err := conn.QueryRow(ctx, sql, args...).Scan(&s); err != nil {
		c.t.Fatalf("%s: %v", sql, pgsock.Clean(err))
	}
	if s == nil {
		return "<null>"
	}
	return *s
}

func (c *cluster) assert(conn *pgx.Conn) []nodecfg.CheckResult {
	c.t.Helper()
	r, err := Assert(context.Background(), conn, c.baseline, c.conf)
	if err != nil {
		c.t.Fatalf("assert: %v", err)
	}
	return r
}

func (c *cluster) assertHBA(conn *pgx.Conn) []nodecfg.CheckResult {
	c.t.Helper()
	r, err := AssertHBA(context.Background(), conn, c.hba)
	if err != nil {
		c.t.Fatalf("assert hba: %v", err)
	}
	return r
}

// wantFindings requires the report to hold findings of exactly the named
// checks (none when no name is given), each well formed.
func (c *cluster) wantFindings(r []nodecfg.CheckResult, names ...string) {
	c.t.Helper()
	for _, f := range r {
		c.t.Logf("finding %s: %s", f.Name, f.Detail)
	}
	var got []string
	for _, f := range r {
		if f.OK || !slices.Contains(frozenNames, f.Name) || f.Detail == "" || len(f.Detail) > 256 {
			c.t.Errorf("malformed finding %+v", f)
		}
		if !slices.Contains(got, f.Name) {
			got = append(got, f.Name)
		}
	}
	slices.Sort(got)
	names = slices.Clone(names)
	slices.Sort(names)
	if !slices.Equal(got, names) {
		c.t.Fatalf("findings %v, want checks %v:\n%+v", got, names, r)
	}
}

// TestStatements_AreConstantsStrict: as TestStatements_AreConstants, over
// every declaration (package-level function literals too). Neither the client
// library's statement methods nor execSQL and querySQL may be taken as
// values; a statement argument must be a package constant (a local variable of
// the same name does not count); the one verifier exception must come
// directly from verifierStatement.
func TestStatements_AreConstantsStrict(t *testing.T) {
	fset := token.NewFileSet()
	consts := map[string]bool{}
	var files []*ast.File
	ents, _ := filepath.Glob("*.go")
	for _, f := range ents {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
		for _, d := range file.Decls {
			if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.CONST {
				for _, s := range g.Specs {
					for _, n := range s.(*ast.ValueSpec).Names {
						consts[n.Name] = true
					}
				}
			}
		}
	}
	raw := map[string]bool{"Exec": true, "Query": true, "QueryRow": true, "SendBatch": true, "CopyFrom": true,
		"Prepare": true, "PgConn": true, "LoadType": true, "LoadTypes": true, "Begin": true, "BeginTx": true,
		"Deallocate": true, "DeallocateAll": true, "WaitForNotification": true, "Ping": true}
	wrapper := map[string]bool{"execSQL": true, "querySQL": true}
	fromVerifierStatement := func(id *ast.Ident) bool {
		as, ok := id.Obj.Decl.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return false
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return false
		}
		fn, ok := call.Fun.(*ast.Ident)
		first, _ := as.Lhs[0].(*ast.Ident)
		return ok && fn.Name == "verifierStatement" && first != nil && first.Obj == id.Obj
	}
	calls, exceptions := 0, 0
	for _, file := range files {
		for _, d := range file.Decls {
			encl := ""
			var name *ast.Ident
			if fn, ok := d.(*ast.FuncDecl); ok {
				encl, name = fn.Name.Name, fn.Name
			}
			called := map[ast.Expr]bool{}
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					called[x.Fun] = true
					f, ok := x.Fun.(*ast.Ident)
					if !ok || !wrapper[f.Name] {
						return true
					}
					calls++
					pos := fset.Position(x.Pos())
					if len(x.Args) < 3 {
						t.Errorf("%s: short call", pos)
						return true
					}
					switch a := x.Args[2].(type) {
					case *ast.BasicLit:
					case *ast.Ident:
						switch {
						case a.Obj == nil && consts[a.Name], a.Obj != nil && a.Obj.Kind == ast.Con:
						case encl == "setVerifier" && f.Name == "execSQL" && a.Obj != nil && fromVerifierStatement(a):
							exceptions++
						default:
							t.Errorf("%s: statement %s is not a package constant", pos, a.Name)
						}
					default:
						t.Errorf("%s: statement is an expression", pos)
					}
				case *ast.AssignStmt:
					// The verifier statement is used as verifierStatement returned it.
					for _, l := range x.Lhs {
						if id, ok := l.(*ast.Ident); ok && id.Obj != nil && id.Obj.Decl != x && fromVerifierStatement(id) {
							t.Errorf("%s: statement %s changed after verifierStatement", fset.Position(x.Pos()), id.Name)
						}
					}
				case *ast.SelectorExpr:
					if raw[x.Sel.Name] && !wrapper[encl] {
						t.Errorf("%s: %s used outside execSQL/querySQL", fset.Position(x.Pos()), x.Sel.Name)
					}
				case *ast.Ident:
					if wrapper[x.Name] && x != name && !called[x] {
						t.Errorf("%s: %s taken as a value", fset.Position(x.Pos()), x.Name)
					}
				}
				return true
			})
		}
	}
	if calls < 20 || exceptions != 1 {
		t.Fatalf("%d statement calls, %d verifier exceptions", calls, exceptions)
	}
}

// TestRun_AuthFunctionsIgnoreCallerOperators: a caller's search_path naming a
// schema with its own = operator for text, ahead of pg_catalog, does not
// change what the functions return.
func TestRun_AuthFunctionsIgnoreCallerOperators(t *testing.T) {
	c := startCluster(t)
	pg := c.dial("postgres")
	for _, s := range []string{
		"create schema t_ops",
		"create function t_ops.never(text, text) returns boolean language sql as $$ select false $$",
		"create operator t_ops.= (leftarg = text, rightarg = text, function = t_ops.never)",
		`select pg_catalog.set_config('request.jwt.claims', '{"sub":"4f7ab3c2-9d1e-4c55-8a1b-2e3f4a5b6c7d","role":"authenticated","email":"tester"}', false)`,
		"select pg_catalog.set_config('request.jwt.claim.role', '', false)",
	} {
		c.exec(pg, s)
	}
	if got := c.str(pg, "select auth.role()"); got != "authenticated" {
		t.Fatalf("control: %q", got)
	}
	c.exec(pg, "set search_path = t_ops, pg_catalog")
	if got := c.str(pg, "select coalesce(auth.role(), 'null')"); got != "authenticated" {
		t.Fatalf("with an = operator earlier in the search path: %q", got)
	}
}

// TestRun_RestoresSessionRoleOnError: a Run that fails while defining the
// functions leaves the session in its own role.
func TestRun_RestoresSessionRoleOnError(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	c.exec(conn, "revoke create on schema auth from supabase_auth_admin")
	if err := Run(context.Background(), conn, c.secrets); err == nil {
		t.Fatal("control: Run succeeded without the right to create in auth")
	}
	if got := c.str(conn, "select current_user::text"); got != "supabase_admin" {
		t.Fatalf("session left as %q", got)
	}
}

// TestAssert_PassesAfterMoreTenantActivity: further ordinary activity as
// postgres (roles granted among themselves, settings of its own roles,
// extensions the image offers, a scheduled job, a stored secret, event
// triggers of its own) still passes.
func TestAssert_PassesAfterMoreTenantActivity(t *testing.T) {
	c := startCluster(t)
	pg := c.dial("postgres")
	for _, s := range []string{
		"create role t_admin nologin createrole",
		"create role t_a nologin",
		"create role t_b nologin",
		"grant t_a to t_b",
		"grant t_b to authenticated",
		"alter role t_a set statement_timeout = '1s'",
		"alter role postgres set statement_timeout = '30s'",
		"alter role service_role set work_mem = '8MB'",
		"create schema t_schema",
		"grant usage on schema t_schema to anon",
		"create extension if not exists pgcrypto with schema extensions",
		"create extension if not exists pg_trgm with schema extensions",
		"create extension if not exists vector with schema extensions",
		"create extension if not exists pg_cron",
		"select cron.schedule('t_job', '* * * * *', 'select 1')",
		"create extension if not exists pgmq",
		"create extension if not exists pg_jsonschema",
		"create extension if not exists pg_hashids",
		"create extension if not exists plpgsql_check",
		"select vault.create_secret('t-value', 't_secret')",
		"select decrypted_secret from vault.decrypted_secrets limit 1",
		"create function public.t_evt() returns event_trigger language plpgsql as $$ begin end $$",
		"create event trigger t_drop on sql_drop execute function public.t_evt()",
		"create event trigger t_login on login execute function public.t_evt()",
	} {
		c.exec(pg, s)
	}
	c.wantFindings(c.assert(c.dial("supabase_admin")))
}

// TestAssert_PassesAfterTenantSchemaGrant: postgres holds usage on storage
// with grant option and passes it to a role of its own.
func TestAssert_PassesAfterTenantSchemaGrant(t *testing.T) {
	c := startCluster(t)
	pg := c.dial("postgres")
	c.exec(pg, "create role t_app nologin")
	c.exec(pg, "grant usage on schema storage to t_app")
	c.wantFindings(c.assert(c.dial("supabase_admin")))
}

// TestAssert_PassesAfterTenantExtension: postgres creates pg_tle, an
// extension the image offers.
func TestAssert_PassesAfterTenantExtension(t *testing.T) {
	c := startCluster(t)
	c.exec(c.dial("postgres"), "create extension pg_tle")
	c.wantFindings(c.assert(c.dial("supabase_admin")))
}

// TestAssert_PassesAfterDatabaseSetting: postgres, owner of the database,
// sets work_mem (also a line of the platform's file) for the database.
func TestAssert_PassesAfterDatabaseSetting(t *testing.T) {
	c := startCluster(t)
	c.exec(c.dial("postgres"), "alter database postgres set work_mem = '16MB'")
	c.wantFindings(c.assert(c.dial("supabase_admin")))
}

// TestAssert_ReportsMaskedAutoConfSetting: a postgresql.auto.conf line for a
// setting the platform session itself sets at startup is reported too.
func TestAssert_ReportsMaskedAutoConfSetting(t *testing.T) {
	c := startCluster(t)
	c.appendAutoConf("statement_timeout = 1234\n")
	c.restart()
	conn := c.dial("supabase_admin")
	if got := c.str(conn, "select setting from pg_catalog.pg_file_settings where name = 'statement_timeout'"); got != "1234" {
		t.Fatalf("control: %q", got)
	}
	c.wantFindings(c.assert(conn), "source-file")
}

// TestAssert_BoundsLargeFunctionBody: an auth function whose body exceeds the
// session's message cap is a finding, not a failed assertion.
func TestAssert_BoundsLargeFunctionBody(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	c.exec(conn, "create or replace function auth.uid() returns pg_catalog.uuid language sql stable as $$ select null::pg_catalog.uuid /*"+
		strings.Repeat("x", 1100000)+"*/ $$")
	r, err := Assert(context.Background(), c.dial("supabase_admin"), c.baseline, c.conf)
	if err != nil {
		t.Fatalf("assert: %v", err)
	}
	c.wantFindings(r, "auth-functions")
}

// TestAssert_SanitisesServerNames: names read from an untrusted server with
// control, escape and bidirectional characters, and more rows than are
// examined, give bounded, sanitised findings.
func TestAssert_SanitisesServerNames(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	c.exec(conn, "create role \"t\x1b[31m\nq'\\‮\" superuser nologin")
	for i := range 300 {
		c.exec(conn, "create role t_su_"+strconv.Itoa(1000+i)+" superuser nologin")
	}
	r := c.assert(conn)
	n := 0
	for _, f := range r {
		if f.Name == "superuser" {
			n++
		}
		if strings.ContainsAny(f.Detail, "\x1b\n‮") || !utf8.ValidString(f.Detail) {
			t.Errorf("unsanitised detail %q", f.Detail)
		}
	}
	if n != maxFindings+1 {
		t.Errorf("%d superuser findings", n)
	}
	if !hasDetail(r, "superuser", "more than") {
		t.Error("no finding for the rows beyond those examined")
	}
	c.wantFindings(r, "superuser")
}

// TestRun_PlatformRolesAsSpecified: the platform's two roles do not inherit,
// the backup role may execute the four backup functions and read all
// settings, and the auth functions are stable.
func TestRun_PlatformRolesAsSpecified(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	if got := c.str(conn, `select string_agg(rolname::text || '=' || rolinherit::text, ',' order by rolname)
	  from pg_catalog.pg_roles where rolname in ('supabase_realtime_admin', 'supapace_backup')`); got != "supabase_realtime_admin=false,supapace_backup=false" {
		t.Errorf("inherit: %s", got)
	}
	for _, fn := range []string{"pg_catalog.pg_backup_start(text, boolean)", "pg_catalog.pg_backup_stop(boolean)",
		"pg_catalog.pg_switch_wal()", "pg_catalog.pg_create_restore_point(text)"} {
		if got := c.str(conn, "select pg_catalog.has_function_privilege('supapace_backup', $1, 'EXECUTE')::text", fn); got != "true" {
			t.Errorf("supapace_backup may not execute %s", fn)
		}
	}
	if got := c.str(conn, "select pg_catalog.pg_has_role('supapace_backup', 'pg_read_all_settings', 'MEMBER')::text"); got != "true" {
		t.Error("supapace_backup is not a member of pg_read_all_settings")
	}
	if got := c.str(conn, `select string_agg(proname::text || '=' || provolatile::text, ',' order by proname) from pg_catalog.pg_proc
	  where pronamespace = 'auth'::pg_catalog.regnamespace and proname in ('uid', 'role', 'email', 'jwt')`); got != "email=s,jwt=s,role=s,uid=s" {
		t.Errorf("volatility: %s", got)
	}
}

// hasDetail reports whether r holds a finding of check name whose detail
// contains sub.
func hasDetail(r []nodecfg.CheckResult, name, sub string) bool {
	return slices.ContainsFunc(r, func(f nodecfg.CheckResult) bool { return f.Name == name && strings.Contains(f.Detail, sub) })
}

// TestAssert_ReportsEachDifference: each kind of difference gives its own
// finding, named and described.
func TestAssert_ReportsEachDifference(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	assertWith := func(want Baseline, conf []byte) []nodecfg.CheckResult {
		t.Helper()
		r, err := Assert(context.Background(), conn, want, conf)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// A baseline listing a second superuser.
	want := c.baseline
	want.Roles = slices.Clone(want.Roles)
	for i := range want.Roles {
		if want.Roles[i].Name == "dashboard_user" {
			want.Roles[i].Super = true
		}
	}
	r := assertWith(want, c.conf)
	c.wantFindings(r, "superuser", "attributes")
	if !hasDetail(r, "superuser", "dashboard_user lacks") {
		t.Errorf("no finding for the missing superuser: %+v", r)
	}
	// Other pinned paths.
	want = c.baseline
	want.Files.HBAFile = "/etc/postgresql/other_hba.conf"
	c.wantFindings(assertWith(want, c.conf), "source-file")
	// A rendered file with a line that is not a setting, and one the
	// cluster does not know.
	r = assertWith(c.baseline, append(slices.Clone(c.conf), "not a setting\nno_such_setting = 1\n"...))
	c.wantFindings(r, "configuration")
	if !hasDetail(r, "configuration", "is not a setting of the cluster") || !hasDetail(r, "configuration", "of the rendered file is not a setting") {
		t.Errorf("findings %+v", r)
	}
	// The image's own pg_hba against the platform's, from the same first
	// line: every difference is reported, each detail within its cap.
	first := c.str(conn, "select min(line_number)::text from pg_catalog.pg_hba_file_rules")
	n, _ := strconv.Atoi(first)
	r, err := AssertHBA(context.Background(), conn, append([]byte(strings.Repeat("\n", n-1)), c.hba...))
	if err != nil {
		t.Fatal(err)
	}
	if len(r) == 0 || !hasDetail(r, "hba", "; rendered: ") || !hasDetail(r, "hba", "is not in force") {
		t.Errorf("hba findings %+v", r)
	}
	for _, f := range r {
		if f.Name != "hba" || len(f.Detail) > maxDetail {
			t.Errorf("finding %+v", f)
		}
	}
	// Role settings for one database, and settings removed.
	c.exec(conn, "alter role supabase_auth_admin in database postgres set work_mem = '1MB'")
	c.exec(conn, "alter role supabase_storage_admin reset all")
	r = c.assert(conn)
	c.wantFindings(r, "role-settings")
	if !hasDetail(r, "role-settings", "one database") || !hasDetail(r, "role-settings", "supabase_storage_admin lacks") {
		t.Errorf("findings %+v", r)
	}
	// A role and a schema renamed: presence names each.
	c.exec(conn, "alter role supabase_auth_admin in database postgres reset all")
	c.exec(conn, "alter role supabase_storage_admin set search_path = storage")
	c.exec(conn, "alter role supabase_storage_admin set log_statement = none")
	c.exec(conn, "alter role anon rename to t_anon")
	c.exec(conn, "alter schema extensions rename to t_extensions")
	r = c.assert(conn)
	if !hasDetail(r, "presence", "role anon is absent") || !hasDetail(r, "presence", "schema extensions is absent") {
		t.Errorf("findings %+v", r)
	}
}

// TestAssertHBA_ReportsRuleError: a rule the server cannot use is reported
// with the server's reason.
func TestAssertHBA_ReportsRuleError(t *testing.T) {
	c := startCluster(t)
	c.phaseB()
	hbaPath := filepath.Join(c.render, "pg_hba.conf")
	if err := os.Chmod(hbaPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hbaPath, append(slices.Clone(c.hba), "local all all nosuchmethod\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	c.exec(c.dial("supabase_admin"), "select pg_catalog.pg_reload_conf()")
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := c.assertHBA(c.dial("supabase_admin"))
		if hasDetail(r, "hba", "nosuchmethod") && slices.ContainsFunc(r, func(f nodecfg.CheckResult) bool {
			return strings.HasPrefix(f.Detail, "line ") && strings.Contains(f.Detail, ": \"")
		}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no finding with the server's reason: %+v", r)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestAssert_ReportsEventTriggerAndFunctionDrift: a baseline event trigger
// removed, and each property of the auth functions changed, give their own
// findings.
func TestAssert_ReportsEventTriggerAndFunctionDrift(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	for _, s := range []string{
		"drop event trigger pgrst_ddl_watch",
		"alter function auth.role() owner to postgres",
		"set role supabase_auth_admin",
		"create or replace function auth.email() returns pg_catalog.text language sql stable as $$ select null::pg_catalog.text $$",
		"revoke execute on function auth.jwt() from public, authenticated",
		"reset role",
		"drop function auth.uid() cascade",
	} {
		c.exec(conn, s)
	}
	r := c.assert(conn)
	c.wantFindings(r, "event-triggers", "auth-functions")
	for name, sub := range map[string]string{"event-triggers": "pgrst_ddl_watch ddl_command_end extensions.pgrst_ddl_watch of the baseline is absent",
		"auth-functions": "auth.role is owned by"} {
		if !hasDetail(r, name, sub) {
			t.Errorf("no %s finding %q", name, sub)
		}
	}
	for _, sub := range []string{"auth.email has another body", "authenticated may not execute auth.jwt", "auth.uid is absent"} {
		if !hasDetail(r, "auth-functions", sub) {
			t.Errorf("no finding %q", sub)
		}
	}
}

// TestLoadBaseline_RefusesMalformedValues: a role named pg_…, a malformed
// digest or a relative file path is refused.
func TestLoadBaseline_RefusesMalformedValues(t *testing.T) {
	for _, r := range [][2]string{
		{`"name": "pgbouncer"`, `"name": "pg_bouncer"`},
		{`"digest": "sha256:`, `"digest": "sha256:x`},
		{`"hba_file": "/etc/postgresql/pg_hba.conf"`, `"hba_file": "etc/postgresql/pg_hba.conf"`},
	} {
		if !bytes.Contains(baselineJSON, []byte(r[0])) {
			t.Fatalf("control: %s not in the baseline", r[0])
		}
		if _, err := parseBaseline(bytes.Replace(baselineJSON, []byte(r[0]), []byte(r[1]), 1)); err == nil {
			t.Errorf("%s accepted", r[1])
		}
	}
}

// Role settings are compared as sets: the same settings in another order are
// not a finding.
func TestAssert_RoleSettingsAsSets(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	before := c.str(conn, "select setconfig::text from pg_catalog.pg_db_role_setting where setrole = 'supabase_auth_admin'::regrole and setdatabase = 0")
	c.exec(conn, "alter role supabase_auth_admin reset search_path")
	c.exec(conn, "alter role supabase_auth_admin set search_path = auth")
	if after := c.str(conn, "select setconfig::text from pg_catalog.pg_db_role_setting where setrole = 'supabase_auth_admin'::regrole and setdatabase = 0"); after == before {
		t.Fatalf("control: order unchanged %s", after)
	}
	c.wantFindings(c.assert(conn))
}

// An access entry added by the schema's baseline owner or a platform role is
// reported; one added by another grantor is not.
func TestAssert_SchemaEntriesByGrantor(t *testing.T) {
	c := startCluster(t)
	conn := c.dial("supabase_admin")
	c.exec(conn, "create role t_reader nologin")
	c.exec(conn, "grant usage on schema realtime to t_reader")
	c.wantFindings(c.assert(conn), "schema-acl")
	c.exec(conn, "revoke usage on schema realtime from t_reader")
	c.exec(conn, "set role supabase_storage_admin") // holds a grant option on storage
	c.exec(conn, "grant usage on schema storage to t_reader")
	c.exec(conn, "reset role")
	c.wantFindings(c.assert(conn), "schema-acl")
	c.exec(conn, "set role supabase_storage_admin")
	c.exec(conn, "revoke usage on schema storage from t_reader")
	c.exec(conn, "reset role")
	c.exec(c.dial("postgres"), "grant usage on schema storage to t_reader")
	c.wantFindings(c.assert(conn))
	// A baseline entry removed, with nothing added.
	c.exec(conn, "revoke usage on schema realtime from postgres")
	r := c.assert(conn)
	c.wantFindings(r, "schema-acl")
	if len(r) != 1 || !strings.Contains(r[0].Detail, "missing or changed") {
		t.Fatalf("findings %+v", r)
	}
}

// TestVerifierStatement_RefusesOtherPrefix: only the three password
// statements of the package may be completed with a verifier.
func TestVerifierStatement_RefusesOtherPrefix(t *testing.T) {
	v, err := pgsock.ScramVerifier("secret-password", make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{sqlPasswordSupabaseAdmin, sqlPasswordPostgres, sqlPasswordAuthenticator} {
		if _, err := verifierStatement(p, v); err != nil {
			t.Errorf("%q refused: %v", p, err)
		}
	}
	for _, p := range []string{"", "select 1; " + sqlPasswordPostgres, "alter role anon password '"} {
		if _, err := verifierStatement(p, v); err == nil {
			t.Errorf("prefix %q accepted", p)
		}
	}
}

// TestAssert_SchemaEntryGrantorQuoted: an entry granted by a role of the
// tenant whose quoted name contains a platform role's name after a / or
// before a quote is ordinary use.
func TestAssert_SchemaEntryGrantorQuoted(t *testing.T) {
	c := startCluster(t)
	adm, pg := c.dial("supabase_admin"), c.dial("postgres")
	c.exec(pg, "create role t_reader nologin")
	for _, gr := range []string{`"t/supabase_admin"`, `"supabase_admin"""`} {
		c.exec(pg, "create role "+gr+" nologin")
		c.exec(pg, "grant usage on schema storage to "+gr+" with grant option")
		c.exec(adm, "set role "+gr)
		c.exec(adm, "grant usage on schema storage to t_reader")
		c.exec(adm, "reset role")
		c.wantFindings(c.assert(adm))
		c.exec(adm, "set role "+gr)
		c.exec(adm, "revoke usage on schema storage from t_reader")
		c.exec(adm, "reset role")
	}
	// A grantee whose quoted name ends like a tenant grantor does not hide an
	// entry granted by the schema's owner.
	c.exec(pg, `create role "q""=U/t_reader" nologin`)
	c.exec(adm, `grant usage on schema storage to "q""=U/t_reader"`)
	c.wantFindings(c.assert(adm), "schema-acl")
}

// TestACLGrantor: the grantor is read from the front of the entry, so names
// in quotes holding "/", "=", quotes or a platform role's name are not taken
// for another role, in either direction.
func TestACLGrantor(t *testing.T) {
	for _, tc := range []struct{ e, want string }{
		{"=U/postgres", "postgres"},
		{"t_reader=UC*/supabase_admin", "supabase_admin"},
		{`t_reader=U/"t/supabase_admin"`, "t/supabase_admin"},
		{`t_reader=U/"supabase_admin"""`, `supabase_admin"`},
		{`t_reader=U/"x=U/supabase_admin"`, "x=U/supabase_admin"},
		{`"t/supabase_admin"=U/postgres`, "postgres"},
		{`"q""=U/t_reader"=U/supabase_storage_admin`, "supabase_storage_admin"},
		{`"a b"=U/"c d"`, "c d"},
		{`t_reader=U/"x`, ""},
		{`"t_reader=U/postgres`, ""},
		{"t_reader=U", ""},
		{`t_reader=U/x"/postgres`, ""},
		{"t_reader/supabase_admin", ""},
		{`"t_reader"U/supabase_admin`, ""},
	} {
		if got := aclGrantor(tc.e); got != tc.want {
			t.Errorf("aclGrantor(%s) = %q, want %q", tc.e, got, tc.want)
		}
	}
}

// TestAssert_ReportsMaskedAutoConfSettingsOnce: several postgresql.auto.conf
// lines for settings the platform session sets at startup, and one setting on
// two lines, give one finding per setting.
func TestAssert_ReportsMaskedAutoConfSettingsOnce(t *testing.T) {
	c := startCluster(t)
	c.appendAutoConf("statement_timeout = 1234\nsearch_path = 'x'\ndefault_transaction_isolation = 'serializable'\n" +
		"log_min_duration_statement = 1000\nlog_min_duration_statement = 2000\n")
	c.restart()
	r := c.assert(c.dial("supabase_admin"))
	c.wantFindings(r, "source-file")
	for _, n := range []string{"statement_timeout", "search_path", "default_transaction_isolation", "log_min_duration_statement"} {
		k := 0
		for _, f := range r {
			if strings.Contains(f.Detail, strconv.Quote(n)) {
				k++
			}
		}
		if k != 1 {
			t.Errorf("%s: %d findings", n, k)
		}
	}
	if len(r) != 4 {
		t.Errorf("findings %+v", r)
	}
}

// TestAssert_FileSettingsBoundedByBudget: an include of a FIFO costs one
// statement and ends in the budget error.
func TestAssert_FileSettingsBoundedByBudget(t *testing.T) {
	c := startCluster(t)
	if err := syscall.Mkfifo(filepath.Join(c.data, "t_fifo.conf"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(c.data, "t_fifo.conf"), c.uid, c.gid); err != nil {
		t.Fatal(err)
	}
	c.appendAutoConf("include '/var/lib/postgresql/data/t_fifo.conf'\n")
	start := time.Now()
	_, err := Assert(context.Background(), c.dial("supabase_admin"), c.baseline, c.conf)
	if !pgsock.IsBudget(err) || time.Since(start) > pgsock.DefaultBudget.Statement+5*time.Second {
		t.Fatalf("after %v: %v", time.Since(start), err)
	}
}

// claimsMatrix sets each combination of absent, empty, valid and invalid
// per-claim and JSON claim settings in a new session and calls fn.
func claimsMatrix(c *cluster, fn func(label string, conn *pgx.Conn)) {
	per := map[string]string{"absent": "", "empty": "''", "uuid": "'00000000-0000-4000-8000-000000000001'", "text": "'abc'"}
	js := map[string]string{"absent": "", "empty": "''", "full": `'{"sub":"4f7ab3c2-9d1e-4c55-8a1b-2e3f4a5b6c7d","role":"r1","email":"e1"}'`,
		"partial": `'{"role":"r1"}'`, "invalid": `'{'`, "text-sub": `'{"sub":"xyz"}'`, "array": `'[1]'`}
	for pk, pv := range per {
		for jk, jv := range js {
			conn := c.dial("postgres")
			if pv != "" {
				for _, k := range []string{"sub", "role", "email"} {
					c.exec(conn, "select pg_catalog.set_config('request.jwt.claim."+k+"', "+pv+", false)")
				}
				c.exec(conn, "select pg_catalog.set_config('request.jwt.claim', "+strings.ReplaceAll(pv, "abc", "{x")+", false)")
			}
			if jv != "" {
				c.exec(conn, "select pg_catalog.set_config('request.jwt.claims', "+jv+", false)")
			}
			fn("per-claim "+pk+", claims "+jk, conn)
		}
	}
}

// result returns a query's single text value, "NULL", or the cleaned error.
func result(conn *pgx.Conn, sql string) string {
	ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
	defer cancel()
	var s *string
	if err := conn.QueryRow(ctx, sql).Scan(&s); err != nil {
		return "error: " + pgsock.Clean(err).Error()
	}
	if s == nil {
		return "NULL"
	}
	return *s
}

// TestRun_AuthFunctionsMatchNullifForm: for absent, empty, valid and invalid
// claims the functions return what the same bodies written with nullif
// return, errors included.
func TestRun_AuthFunctionsMatchNullifForm(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "create schema t_ref")
	c.exec(adm, "grant usage on schema t_ref to postgres")
	for _, f := range []struct{ name, ret, claim, json string }{
		{"uid", "uuid", "request.jwt.claim.sub", "sub"}, {"role", "text", "request.jwt.claim.role", "role"},
		{"email", "text", "request.jwt.claim.email", "email"}} {
		c.exec(adm, "create function t_ref."+f.name+"() returns pg_catalog."+f.ret+" language sql stable as $$ select coalesce("+
			"nullif(pg_catalog.current_setting('"+f.claim+"', true), ''), (nullif(pg_catalog.current_setting('request.jwt.claims', true), '')"+
			"::pg_catalog.jsonb operator(pg_catalog.->>) '"+f.json+"'))::pg_catalog."+f.ret+" $$")
	}
	c.exec(adm, "create function t_ref.jwt() returns pg_catalog.jsonb language sql stable as $$ select coalesce("+
		"nullif(pg_catalog.current_setting('request.jwt.claim', true), ''), nullif(pg_catalog.current_setting('request.jwt.claims', true), ''))::pg_catalog.jsonb $$")
	n := 0
	claimsMatrix(c, func(label string, conn *pgx.Conn) {
		for _, f := range []string{"uid()::text", "role()", "email()", "jwt()::text"} {
			n++
			if got, want := result(conn, "select auth."+f), result(conn, "select t_ref."+f); got != want {
				t.Errorf("%s, %s: %q, nullif form %q", label, f, got, want)
			}
		}
	})
	if n != 112 {
		t.Fatalf("%d cases", n)
	}
}

// TestRun_AuthFunctionsIgnoreCallerObjects: operators, functions, types and
// domains of the same names in schemas ahead of pg_catalog, pg_temp included,
// do not change what the functions return.
func TestRun_AuthFunctionsIgnoreCallerObjects(t *testing.T) {
	c := startCluster(t)
	pg := c.dial("postgres")
	for _, s := range []string{
		"create schema t_h",
		"create function t_h.never(text, text) returns boolean language sql as $$ select false $$",
		"create operator t_h.= (leftarg = text, rightarg = text, function = t_h.never)",
		"create function t_h.other(pg_catalog.jsonb, text) returns text language sql as $$ select 'other' $$",
		"create operator t_h.->> (leftarg = pg_catalog.jsonb, rightarg = text, function = t_h.other)",
		"create function t_h.current_setting(text, boolean) returns text language sql as $$ select '{\"role\":\"other\"}' $$",
		"create function t_h.current_setting(text) returns text language sql as $$ select 'other' $$",
		"create function t_h.coalesce(text, text) returns text language sql as $$ select 'other' $$",
		"create function t_h.uuid(text) returns uuid language sql as $$ select '00000000-0000-4000-8000-0000000000ff'::pg_catalog.uuid $$",
		"create function t_h.jsonb(text) returns jsonb language sql as $$ select '{\"role\":\"other\"}'::pg_catalog.jsonb $$",
		"create domain t_h.text as pg_catalog.text check (false)",
		"create type t_h.jsonb as (x int)",
		"create type t_h.uuid as (x int)",
	} {
		c.exec(pg, s)
	}
	const want = "4f7ab3c2-9d1e-4c55-8a1b-2e3f4a5b6c7d authenticated tester authenticated"
	sets := []string{
		"select pg_catalog.set_config('request.jwt.claim.sub', '', false), pg_catalog.set_config('request.jwt.claim.role', '', false), " +
			"pg_catalog.set_config('request.jwt.claim.email', '', false), pg_catalog.set_config('request.jwt.claim', '', false), " +
			`pg_catalog.set_config('request.jwt.claims', '{"sub":"4f7ab3c2-9d1e-4c55-8a1b-2e3f4a5b6c7d","role":"authenticated","email":"tester"}', false)`,
		"select pg_catalog.set_config('request.jwt.claim.sub', '4f7ab3c2-9d1e-4c55-8a1b-2e3f4a5b6c7d', false), " +
			"pg_catalog.set_config('request.jwt.claim.role', 'authenticated', false), pg_catalog.set_config('request.jwt.claim.email', 'tester', false), " +
			`pg_catalog.set_config('request.jwt.claim', '{"role":"authenticated"}', false), pg_catalog.set_config('request.jwt.claims', '{"role":"x"}', false)`,
	}
	for _, path := range []string{"t_h, pg_catalog", "pg_temp, t_h, pg_catalog"} {
		for i, set := range sets {
			conn := c.dial("postgres")
			for _, s := range []string{
				"create function pg_temp.never(text, text) returns boolean language sql as $$ select false $$",
				"create operator pg_temp.= (leftarg = text, rightarg = text, function = pg_temp.never)",
				"create function pg_temp.current_setting(text, boolean) returns text language sql as $$ select 'other' $$",
				"create type pg_temp.jsonb as (x int)",
				"create domain pg_temp.text as pg_catalog.text check (false)",
				set, "set search_path = " + path,
			} {
				c.exec(conn, s)
			}
			if got := result(conn, "select (current_setting('x', true) = current_setting('x', true))::pg_catalog.text"); got != "false" {
				t.Fatalf("control: the objects are not reached unqualified: %q", got)
			}
			got := result(conn, "select pg_catalog.concat_ws(' ', auth.uid(), auth.role(), auth.email(), auth.jwt() operator(pg_catalog.->>) 'role')")
			if got != want {
				t.Errorf("search_path %q, settings %d: %q", path, i, got)
			}
		}
	}
}

// TestRun_AuthFunctionsInlined: in a policy-style filter the planner inlines
// the functions; the plan shows their expression, not a call.
func TestRun_AuthFunctionsInlined(t *testing.T) {
	c := startCluster(t)
	pg := c.dial("postgres")
	c.exec(pg, "create table public.t_docs(id int, owner uuid, who text, claims jsonb)")
	for _, w := range []string{"owner = auth.uid()", "who = auth.role()", "who = auth.email()", "claims = auth.jwt()"} {
		ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
		rows, err := pg.Query(ctx, "explain verbose select id from public.t_docs where "+w)
		var plan []string
		for err == nil && rows.Next() {
			var l string
			if err = rows.Scan(&l); err == nil {
				plan = append(plan, l)
			}
		}
		rows.Close()
		cancel()
		if err == nil {
			err = rows.Err()
		}
		if err != nil {
			t.Fatal(pgsock.Clean(err))
		}
		p := strings.Join(plan, "\n")
		if strings.Contains(p, "auth.") || !strings.Contains(p, "COALESCE(CASE WHEN") {
			t.Errorf("%s not inlined:\n%s", w, p)
		}
	}
}

// serverACLName writes a role name as the server does in an access entry:
// in double quotes, a quote doubled, unless it has only ASCII letters,
// digits and underscores.
func serverACLName(n string) string {
	for i := 0; i < len(n); i++ {
		if c := n[i]; !(c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return `"` + strings.ReplaceAll(n, `"`, `""`) + `"`
		}
	}
	return n
}

// FuzzACLGrantor: an entry written as the server writes it gives back its
// grantor; any other text gives "" or the name written, quoted or not, at
// its very end.
func FuzzACLGrantor(f *testing.F) {
	for _, s := range []string{"", "t_reader", "a b", `"`, "=U/x", "t/supabase_admin", "supabase_admin\"", "\xff\n"} {
		f.Add(s, "UC*", "supabase_admin", s)
		f.Add("", "U", s, s+"=U/"+s)
	}
	f.Fuzz(func(t *testing.T, grantee, privs, grantor, raw string) {
		if g := aclGrantor(raw); g != "" && !strings.HasSuffix(raw, `/"`+strings.ReplaceAll(g, `"`, `""`)+`"`) &&
			(strings.ContainsAny(g, `=/"`) || !strings.HasSuffix(raw, "/"+g)) {
			t.Fatalf("aclGrantor(%q) = %q", raw, g)
		}
		if grantor == "" || strings.ContainsRune(grantee+grantor, 0) {
			return
		}
		privs = strings.Map(func(r rune) rune {
			if strings.ContainsRune("arwdDxtmXUCcTsAm*", r) {
				return r
			}
			return -1
		}, privs)
		e := serverACLName(grantee) + "=" + privs + "/" + serverACLName(grantor)
		if g := aclGrantor(e); g != grantor {
			t.Fatalf("aclGrantor(%q) = %q, want %q", e, g, grantor)
		}
	})
}

// TestACLGrantor_MatchesServer: for roles whose names hold quotes, "=", "/",
// backslashes, spaces, newlines and multi-byte characters, the grantor read
// from each entry the server writes is the one the server reports, and only
// entries granted by the schema's owner are findings.
func TestACLGrantor_MatchesServer(t *testing.T) {
	c := startCluster(t)
	conn, pg := c.dial("supabase_admin"), c.dial("postgres")
	names := []string{"t/supabase_admin", `supabase_admin"`, "x=U/supabase_admin", "a b", `"`, `""`, "=", "/",
		"=U/supabase_admin", `\`, `b\"/supabase_admin`, "nl\nsupabase_admin", "tab\tx", "\u00e9", "\u65e5/supabase_admin",
		"supabase_admin ", " supabase_admin", "Supabase_admin", "supabase_admin=", `"supabase_admin"`,
		`x"/supabase_admin`, "a*", "=UC*/postgres", ",{}", "\U0001F600", strings.Repeat(`x"`, 31) + "y"}
	c.exec(conn, "create schema t_acl")
	for _, n := range names {
		id := pgx.Identifier{n}.Sanitize()
		c.exec(conn, "create role "+id+" nologin")
		c.exec(conn, "grant usage on schema t_acl to "+id+" with grant option")
		c.exec(pg, "grant usage on schema storage to "+id+" with grant option")
	}
	for i, n := range names {
		next := pgx.Identifier{names[(i+1)%len(names)]}.Sanitize()
		as := c.dial("supabase_admin") // a session per role: each role change is reported to the client
		c.exec(as, "set role "+pgx.Identifier{n}.Sanitize())
		c.exec(as, "grant usage, create on schema t_acl to "+next)
		c.exec(as, "grant usage on schema t_acl to public")
		c.exec(as, "grant usage on schema storage to "+next)
		as.Close(context.Background())
	}
	var got [][2]*string
	if err := json.Unmarshal([]byte(c.str(conn, `select pg_catalog.json_agg(pg_catalog.json_build_array(a::text,
	    (select r.rolname from pg_catalog.aclexplode(array[a]) x join pg_catalog.pg_roles r on r.oid = x.grantor limit 1)))
	  from pg_catalog.pg_namespace n, pg_catalog.unnest(n.nspacl) a where n.nspname in ('t_acl', 'storage')`)), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) < 3*len(names) {
		t.Fatalf("%d entries", len(got))
	}
	for _, e := range got {
		if g := aclGrantor(*e[0]); e[1] == nil || g != *e[1] {
			t.Errorf("aclGrantor(%q) = %q, server %v", *e[0], g, *e[1])
		}
	}
	c.wantFindings(c.assert(conn))
	// Granted by the schema's owner: one finding per grantee.
	for _, n := range names[:20] {
		c.exec(conn, "grant usage on schema storage to "+pgx.Identifier{n}.Sanitize())
	}
	r := c.assert(conn)
	c.wantFindings(r, "schema-acl")
	if len(r) != 20 {
		t.Fatalf("%d findings", len(r))
	}
}

// TestReport_DetailSanitisedAndCapped: a finding's detail is sanitised and
// at most maxDetail bytes whatever its arguments.
func TestReport_DetailSanitisedAndCapped(t *testing.T) {
	r := &report{n: map[string]int{}}
	r.add(checkHBA, "line %d in force: %s", 1, strings.Repeat("a\x1b\n\u202e\xff", 400))
	if d := r.out[0].Detail; len(d) > maxDetail || len(d) < maxDetail-4 || strings.ContainsAny(d, "\x1b\n\u202e") || !utf8.ValidString(d) {
		t.Fatalf("detail %d bytes %q", len(d), d)
	}
}
