package bootstrap

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/pgsock"
)

// TestPoolerHelper_NamesEverythingWithItsSchema: in the helper's body every
// type, relation and function is written pg_catalog-qualified. Its empty
// search_path settles operators only: a type or relation without a schema is
// looked up among the calling session's objects first.
func TestPoolerHelper_NamesEverythingWithItsSchema(t *testing.T) {
	s := regexp.MustCompile(`'(?:[^']|'')*'`).ReplaceAllString(bodyPoolerHelper, "''")
	for _, m := range regexp.MustCompile(`::\s*([A-Za-z_][A-Za-z_0-9.]*)`).FindAllStringSubmatch(s, -1) {
		if !strings.HasPrefix(m[1], "pg_catalog.") {
			t.Errorf("type %s without its schema", m[1])
		}
	}
	for _, m := range regexp.MustCompile(`\b(?:from|join)\s+([a-z_][a-z0-9_.]*)`).FindAllStringSubmatch(s, -1) {
		if !strings.HasPrefix(m[1], "pg_catalog.") {
			t.Errorf("relation %s without its schema", m[1])
		}
	}
	for _, m := range regexp.MustCompile(`([a-z_][a-z0-9_.]*)\s*\(`).FindAllStringSubmatch(s, -1) {
		if !strings.HasPrefix(m[1], "pg_catalog.") && m[1] != "in" && m[1] != "and" {
			t.Errorf("function %s without its schema", m[1])
		}
	}
	if !strings.Contains(sqlCreatePoolerHelper, " security definer set search_path = '' as ") {
		t.Error("the helper's search_path is not the empty one")
	}
}

// TestHelper_IgnoresTheCallingSessionsObjects: a domain named as a type the
// helper uses, in the calling session's temporary schema, does not change
// what the helper returns to the manager.
func TestHelper_IgnoresTheCallingSessionsObjects(t *testing.T) {
	c := startPoolerCluster(t)
	conn := c.dial("supabase_admin")
	for _, s := range []string{
		"set session authorization supapace_pooler",
		"create domain pg_temp.text as pg_catalog.text check (false)",
		"set search_path = ''",
	} {
		c.exec(conn, s)
	}
	ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
	defer cancel()
	if _, err := conn.Exec(ctx, "select 'x'::text"); err == nil {
		t.Fatal("control: the session's own domain is not reached without a schema")
	}
	for _, role := range []string{"postgres", "supapace_pooler"} {
		var got *string
		err := conn.QueryRow(ctx, "select pg_catalog.string_agg(username, ',') from supapace_pooler.get_auth($1)", role).Scan(&got)
		if err != nil || got == nil || *got != role {
			t.Errorf("the helper for %s, called from a session with objects of its own: %v", role, pgsock.Clean(err))
		}
	}
}

// TestWriteCanary_KeepsNothingOfATableAnotherRoleMade: when a table of the
// canary's name was made by a project role first, with a trigger of its own,
// the write either fails or writes into a table that carries nothing of that
// role; the trigger does not run in the platform's session.
func TestWriteCanary_KeepsNothingOfATableAnotherRoleMade(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "drop schema supapace cascade")
	pg := c.dial("postgres")
	for _, s := range []string{
		"create schema supapace",
		"create table supapace._backup_canary (id smallint primary key check (id = 1), written_at timestamptz not null)",
		`create function supapace.t_made() returns trigger language plpgsql as
		  $$ begin perform pg_catalog.set_config('t.ran', 'yes', false); return new; end $$`,
		"create trigger t_made before insert or update on supapace._backup_canary for each row execute function supapace.t_made()",
	} {
		c.exec(pg, s)
	}
	err := WriteCanary(context.Background(), adm)
	if got := c.str(adm, "select coalesce(pg_catalog.current_setting('t.ran', true), '')"); got != "" {
		t.Fatalf("the write (%v) ran the other role's trigger in the platform's session", err)
	}
	if err != nil {
		return // refused: nothing of the other role's table is used
	}
	const left = `select (select count(*) from pg_catalog.pg_trigger g where g.tgrelid = c.oid and not g.tgisinternal)::text || ' ' ||
	  pg_catalog.pg_get_userbyid(c.relowner)::text || ' ' || c.relkind::text
	  from pg_catalog.pg_class c where c.oid = pg_catalog.to_regclass('supapace._backup_canary')`
	if got := c.str(adm, left); got != "0 supabase_admin r" {
		t.Fatalf("the table after the write: %s", got)
	}
}

// TestEnsurePoolerLogin_KeepsNothingOfARoleAndSchemaAnotherRoleMade: when the
// manager's role and the helper's schema were made by a project role first,
// the call either fails or leaves a manager no role holds a membership in and
// a schema with the platform's two access entries alone; the drift check
// agrees.
func TestEnsurePoolerLogin_KeepsNothingOfARoleAndSchemaAnotherRoleMade(t *testing.T) {
	c := startCluster(t)
	c.withPooler()
	adm := c.dial("supabase_admin")
	pg := c.dial("postgres")
	for _, s := range []string{
		"create role supapace_pooler",
		"create schema supapace_pooler",
		"grant all on schema supapace_pooler to anon",
	} {
		c.exec(pg, s)
	}
	const state = `select (select count(*) from pg_catalog.pg_auth_members m join pg_catalog.pg_roles r on r.oid in (m.roleid, m.member)
	    where r.rolname = 'supapace_pooler')::text || ' ' ||
	  (select nspacl::text from pg_catalog.pg_namespace where nspname = 'supapace_pooler')`
	if got := c.str(adm, state); !strings.HasPrefix(got, "1 ") {
		t.Fatalf("control: %s", got)
	}
	if err := EnsurePoolerLogin(context.Background(), adm, c.secrets); err != nil {
		if len(c.assertServices(adm)) == 0 {
			t.Fatalf("the call fails (%v) and the drift check reports nothing", err)
		}
		return // refused
	}
	if got := c.str(adm, state); got != "0 {supabase_admin=UC/supabase_admin,supapace_pooler=U/supabase_admin}" {
		t.Errorf("after the call: %s", got)
	}
	c.wantServices(c.assertServices(adm))
}

// TestHelper_SameAnswersWhateverTheCallingSessionDefines: with a table, types,
// domains, functions, operators and a collation of the names the helper uses
// in the calling session's temporary schema, and session settings of the
// caller's choice, the helper answers the manager as before for every kind of
// role.
func TestHelper_SameAnswersWhateverTheCallingSessionDefines(t *testing.T) {
	c := startPoolerCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "create role t_high superuser login password 't-pw-"+rnd(8)+"'")
	c.exec(adm, "alter role supabase_auth_admin login password 't-pw-"+rnd(8)+"'")
	const answers = `select pg_catalog.string_agg(r || ':' || (select pg_catalog.count(*) from supapace_pooler.get_auth(r))::pg_catalog.text, ' ' order by r)
	  from pg_catalog.unnest(array['postgres','supapace_pooler','supabase_admin','supabase_auth_admin','authenticator','anon','t_high','t_listed']::pg_catalog.text[]) r`
	const want = "anon:0 authenticator:0 postgres:1 supabase_admin:0 supabase_auth_admin:0 supapace_pooler:1 t_high:0 t_listed:0"
	conn := c.dial("supabase_admin")
	c.exec(conn, "set session authorization supapace_pooler")
	if got := c.str(conn, answers); got != want {
		t.Fatalf("control: %s", got)
	}
	for _, s := range []string{
		"create domain pg_temp.text as pg_catalog.text check (false)",
		"create domain pg_temp.name as pg_catalog.name check (false)",
		"create domain pg_temp.bool as pg_catalog.bool check (false)",
		"create domain pg_temp.timestamptz as pg_catalog.timestamptz check (false)",
		`create temp table pg_authid (rolname pg_catalog.name, rolpassword pg_catalog.text, rolcanlogin pg_catalog.bool,
		  rolsuper pg_catalog.bool, rolvaliduntil pg_catalog.timestamptz)`,
		"insert into pg_temp.pg_authid values ('supabase_admin', 'SCRAM-SHA-256$4096:t', true, false, null), ('t_listed', 'SCRAM-SHA-256$4096:t', true, false, null)",
		"create function pg_temp.now() returns pg_catalog.timestamptz language sql as $$ select '1900-01-01'::pg_catalog.timestamptz $$",
		"create function pg_temp.t_always(pg_catalog.name, pg_catalog.text) returns pg_catalog.bool language sql as $$ select true $$",
		"create operator pg_temp.= (leftarg = pg_catalog.name, rightarg = pg_catalog.text, function = pg_temp.t_always)",
		"create operator pg_temp.!~ (leftarg = pg_catalog.name, rightarg = pg_catalog.text, function = pg_temp.t_always)",
		"create function pg_temp.t_always2(pg_catalog.text, pg_catalog.text) returns pg_catalog.bool language sql as $$ select true $$",
		"create operator pg_temp.~~ (leftarg = pg_catalog.text, rightarg = pg_catalog.text, function = pg_temp.t_always2)",
		`create collation pg_temp."default" (provider = libc, locale = 'C')`,
		`create function pg_temp.get_auth(pg_catalog.text) returns table (username pg_catalog.text, password pg_catalog.text)
		  language sql as $$ select 'supabase_admin'::pg_catalog.text, 't'::pg_catalog.text $$`,
		"set standard_conforming_strings = off",
		"set transform_null_equals = on",
		"set search_path = ''",
	} {
		c.exec(conn, s)
	}
	ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
	defer cancel()
	if _, err := conn.Exec(ctx, "select 'x'::text"); err == nil {
		t.Fatal("control: the session's own domain is not reached without a schema")
	}
	if got := c.str(conn, "select pg_catalog.count(*)::pg_catalog.text from pg_authid"); got != "2" {
		t.Fatalf("control: the session's own table is not reached without a schema: %s", got)
	}
	for _, path := range []string{"''", "pg_temp, pg_catalog", "pg_temp, supapace_pooler, pg_catalog"} {
		c.exec(conn, "set search_path = "+path)
		if got := c.str(conn, answers); got != want {
			t.Errorf("search_path %s: %s", path, got)
		}
	}
	// Called without its schema it is still the platform's function.
	if got := c.str(conn, "select pg_catalog.string_agg(username, ',') from get_auth('postgres')"); got != "postgres" {
		t.Errorf("without a schema: %s", got)
	}
	// The manager can change nothing of it.
	for _, s := range []string{
		"alter function supapace_pooler.get_auth(pg_catalog.text) set search_path = pg_temp",
		`create or replace function supapace_pooler.get_auth(p_usename pg_catalog.text) returns table (username pg_catalog.text, password pg_catalog.text)
		  language sql as $$ select 'x'::pg_catalog.text, 'y'::pg_catalog.text $$`,
		"create function supapace_pooler.get_auth(pg_catalog.name) returns pg_catalog.text language sql as $$ select 'x'::pg_catalog.text $$",
		"drop function supapace_pooler.get_auth(pg_catalog.text)",
	} {
		var se *pgsock.ServerError
		if _, err := conn.Exec(ctx, s); !errors.As(pgsock.Clean(err), &se) || se.Code != "42501" {
			t.Errorf("%.60s: %v", s, pgsock.Clean(err))
		}
	}
	c.wantServices(c.assertServices(adm))
}

// TestWriteCanary_ReplacesAnotherRolesTableWithWhatHangsOnIt: a table of the
// canary's name another role made is replaced even when that role's view and
// foreign key hang on it; the role's other table and its rows stay.
func TestWriteCanary_ReplacesAnotherRolesTableWithWhatHangsOnIt(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "drop schema supapace cascade")
	pg := c.dial("postgres")
	for _, s := range []string{
		"create schema supapace",
		"create table supapace._backup_canary (id smallint primary key check (id = 1), written_at timestamptz not null)",
		"insert into supapace._backup_canary values (1, '2000-01-01')",
		"create view public.t_over as select * from supapace._backup_canary",
		"create table public.t_kept (id smallint references supapace._backup_canary (id), note text)",
		"insert into public.t_kept values (1, 'kept')",
	} {
		c.exec(pg, s)
	}
	if err := WriteCanary(context.Background(), adm); err != nil {
		t.Fatal(err)
	}
	const state = `select pg_catalog.pg_get_userbyid(c.relowner)::text || ' ' || c.relkind::text || ' ' ||
	  (select count(*) from supapace._backup_canary where written_at > pg_catalog.now() - interval '1 minute')::text || ' ' ||
	  coalesce(pg_catalog.to_regclass('public.t_over')::text, '-') || ' ' || (select pg_catalog.string_agg(note, ',') from public.t_kept) || ' ' ||
	  (select count(*) from pg_catalog.pg_constraint where conrelid = 'public.t_kept'::regclass)::text
	  from pg_catalog.pg_class c where c.oid = 'supapace._backup_canary'::regclass`
	if got := c.str(adm, state); got != "supabase_admin r 1 - kept 0" {
		t.Fatalf("after the write: %s", got)
	}
	// A type of the canary's name, no relation: refused, nothing made.
	c.exec(adm, "drop schema supapace cascade")
	c.exec(pg, "create schema supapace")
	c.exec(pg, "create type supapace._backup_canary as enum ('t')")
	if err := WriteCanary(context.Background(), adm); err == nil {
		t.Fatal("a type of the canary's name: the write succeeds")
	}
	if got := c.str(adm, "select coalesce(pg_catalog.to_regclass('supapace._backup_canary')::text, '-')"); got != "-" {
		t.Fatalf("a relation was made: %s", got)
	}
}

// TestEnsurePoolerLogin_SchemaListIsExactlyTheTwoEntries: an entry of the
// helper's schema for PUBLIC is taken away by the call; a grant option, a
// further right for the manager or an entry for another role is a difference
// the call refuses and the drift check reports, until the entry is gone.
func TestEnsurePoolerLogin_SchemaListIsExactlyTheTwoEntries(t *testing.T) {
	c := startPoolerCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "grant usage on schema supapace_pooler to public")
	if err := EnsurePoolerLogin(context.Background(), adm, c.secrets); err != nil {
		t.Fatalf("an entry for PUBLIC: %v", err)
	}
	c.wantServices(c.assertServices(adm))
	for _, tc := range []struct{ grant, undo string }{
		{"grant usage on schema supapace_pooler to supapace_pooler with grant option", "revoke grant option for usage on schema supapace_pooler from supapace_pooler"},
		{"grant create on schema supapace_pooler to supapace_pooler", "revoke create on schema supapace_pooler from supapace_pooler"},
		{"grant usage on schema supapace_pooler to anon", "revoke usage on schema supapace_pooler from anon"},
		{"grant create on schema supapace_pooler to postgres with grant option", "revoke all on schema supapace_pooler from postgres"},
	} {
		c.exec(adm, tc.grant)
		c.wantServices(c.assertServices(adm), "schema supapace_pooler has the access list")
		if err := EnsurePoolerLogin(context.Background(), adm, c.secrets); err == nil || !strings.Contains(err.Error(), "access list") {
			t.Errorf("%s: %v", tc.grant, err)
		}
		c.exec(adm, tc.undo)
		if err := EnsurePoolerLogin(context.Background(), adm, c.secrets); err != nil {
			t.Fatalf("after %s: %v", tc.undo, err)
		}
		c.wantServices(c.assertServices(adm))
	}
}
