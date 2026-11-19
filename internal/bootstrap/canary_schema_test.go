package bootstrap

import (
	"context"
	"testing"
)

// TestWriteCanary_RefusesASchemaAnotherRoleHoldsAnEntryOn: when a schema of the
// canary's name was made by a project role that gave another role an access
// entry on it, the write either fails or leaves the schema with the platform's
// entry alone: the table is made only where no other role may make one.
func TestWriteCanary_RefusesASchemaAnotherRoleHoldsAnEntryOn(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "drop schema supapace cascade")
	pg := c.dial("postgres")
	for _, s := range []string{
		"create role t_second",
		"create schema supapace",
		"grant all on schema supapace to t_second",
	} {
		c.exec(pg, s)
	}
	const list = "select nspacl::text from pg_catalog.pg_namespace where nspname = 'supapace'"
	err := WriteCanary(context.Background(), adm)
	got := c.str(adm, list)
	if err == nil && got != "{supabase_admin=UC/supabase_admin}" {
		t.Fatalf("the write succeeds in a schema with the access list %s", got)
	}
	if err != nil {
		// Refused: with the entry gone the write succeeds.
		c.exec(adm, "revoke all on schema supapace from t_second")
		if err := WriteCanary(context.Background(), adm); err != nil {
			t.Fatalf("after the entry was taken away: %v", err)
		}
	}
	if got := c.str(adm, list); got != "{supabase_admin=UC/supabase_admin}" {
		t.Fatalf("the schema's access list: %s", got)
	}
}
