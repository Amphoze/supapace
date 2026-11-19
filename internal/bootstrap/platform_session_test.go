package bootstrap

import (
	"context"
	"testing"
)

// TestSessionCalls_UnderSettingsOfTheRoleAndTheDatabase: settings of the
// database and of the platform's role that put another schema first, turn
// writes off and bound statements do not reach a platform session; every call
// of the package does there what it does without them. The schema holds
// objects named as the types and the function the statements use.
func TestSessionCalls_UnderSettingsOfTheRoleAndTheDatabase(t *testing.T) {
	c := startCluster(t)
	c.withPooler()
	adm := c.dial("supabase_admin")
	pg := c.dial("postgres")
	for _, s := range []string{
		"create schema t_first",
		"create domain t_first.text as pg_catalog.text check (false)",
		"create domain t_first.oid as pg_catalog.int4 check (false)",
		"create type t_first.timestamptz as (t_x int)",
		"create function t_first.now() returns pg_catalog.timestamptz language sql as $$ select '1900-01-01'::pg_catalog.timestamptz $$",
		"alter database postgres set search_path = t_first, pg_temp, pg_catalog",
		"alter database postgres set default_transaction_read_only = on",
	} {
		c.exec(pg, s)
	}
	for _, s := range []string{
		"alter role supabase_admin set search_path = t_first, pg_temp, pg_catalog",
		"alter role supabase_admin in database postgres set search_path = t_first, pg_temp, pg_catalog",
		"alter role supabase_admin set statement_timeout = 1",
		"alter role supabase_admin set lock_timeout = 1",
		"alter role supabase_admin set role = 'postgres'",
	} {
		c.exec(adm, s)
	}
	raw := c.rawDial("supabase_admin", nil)
	if got := c.str(raw, "select pg_catalog.current_setting('search_path') || ' ' || current_user::pg_catalog.text"); got != "t_first, pg_temp, pg_catalog postgres" {
		t.Fatalf("control: a session without the platform's startup list has %s", got)
	}
	conn := c.dial("supabase_admin")
	if got := c.str(conn, "select pg_catalog.current_setting('search_path') || ' ' || current_user::pg_catalog.text || ' ' || 'x'::text"); got != "pg_catalog,pg_temp supabase_admin x" {
		t.Fatalf("a platform session has %s", got)
	}
	// An object the session makes in its own temporary schema does not come
	// before the catalog's either.
	c.exec(conn, "create domain pg_temp.text as pg_catalog.text check (false)")
	ctx := context.Background()
	if err := EnsurePoolerLogin(ctx, conn, c.secrets); err != nil {
		t.Fatalf("EnsurePoolerLogin: %v", err)
	}
	c.wantServices(c.assertServices(conn))
	if err := WriteCanary(ctx, conn); err != nil {
		t.Fatalf("WriteCanary: %v", err)
	}
	if got := c.str(conn, "select (written_at > pg_catalog.now() - interval '1 minute')::text from supapace._backup_canary"); got != "true" {
		t.Fatalf("the canary's time is not the server's: %s", got)
	}
	if err := SetReadOnlySignal(ctx, conn, true); err != nil {
		t.Fatalf("SetReadOnlySignal: %v", err)
	}
	if lsn, err := CreateRestorePoint(ctx, conn, "t-point"); err != nil || !lsnRE.MatchString(lsn) {
		t.Fatalf("CreateRestorePoint: %q %v", lsn, err)
	}
	if err := Rekey(ctx, c.dial("supabase_admin"), c.secrets); err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	res, err := RekeyLogin(ctx, c.dial("supabase_admin"), "postgres", newVerifier(t, "postgres"))
	if err != nil || res.Terminated < 1 || res.LargeObjectsLeft {
		t.Fatalf("RekeyLogin: %+v %v", res, err)
	}
	if err := Run(ctx, c.dial("supabase_admin"), c.secrets); err != nil {
		t.Fatalf("Run: %v", err)
	}
	c.wantFindings(c.assert(c.dial("supabase_admin")), "role-settings")
}
