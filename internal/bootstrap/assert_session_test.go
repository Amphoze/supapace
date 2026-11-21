package bootstrap

import (
	"context"
	"fmt"
	"testing"

	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// The drift check runs in a platform session, which sets some names in its
// startup packet. These tests pin what the check still reports for such a
// name. They need Docker and the pinned image.

// TestAssert_ReportsAutoConfLineOfANameTheSessionSets: a line of the system
// file for a name the platform session sets at startup is not in force in
// that session, and is reported all the same: the files are read, not only
// the settings in force.
func TestAssert_ReportsAutoConfLineOfANameTheSessionSets(t *testing.T) {
	const name = "log_min_duration_statement"
	if _, own := pgsock.StartupParams(true)[name]; !own {
		t.Fatalf("%s is not in the startup list", name)
	}
	c := startCluster(t)
	c.appendAutoConf(name + " = 1000\n")
	c.restart()
	conn := c.dial("supabase_admin")
	if got := c.str(conn, "select setting || ' ' || source from pg_catalog.pg_settings where name = '"+name+"'"); got != "-1 client" {
		t.Fatalf("control: the session's own value is not in force: %q", got)
	}
	r := c.assert(conn)
	c.wantFindings(r, "source-file")
	if !hasDetail(r, "source-file", name) || !hasDetail(r, "source-file", "postgresql.auto.conf") {
		t.Fatalf("the line is not named: %+v", r)
	}
}

// TestAssertPins_DatabaseLevelPreloadListReported: a value of the session
// preload list set for the whole database reaches every session that does
// not set the name itself. The platform session sets it, so the list reads
// "client" there; the check reports the database-level value all the same.
func TestAssertPins_DatabaseLevelPreloadListReported(t *testing.T) {
	c := newCluster(t, 2)
	c.run()
	adm := c.dial("supabase_admin")
	if err := Run(context.Background(), adm, c.secrets); err != nil {
		t.Fatal(err)
	}
	r, err := AssertPins(context.Background(), adm, c.baseline, c.conf, pgconf.PinnedNames(2))
	if err != nil {
		t.Fatal(err)
	}
	c.wantFindings(r) // control: nothing to report before
	c.exec(adm, "alter database postgres set session_preload_libraries = 'auto_explain'")
	// Control: the value reaches a session that does not set the name.
	if got := c.str(c.rawDial("postgres", nil), "select setting || ' ' || source from pg_catalog.pg_settings where name = 'session_preload_libraries'"); got != "auto_explain database" {
		t.Fatalf("control: the database-level value is not in force for another role: %q", got)
	}
	fresh := c.dial("supabase_admin")
	r, err = AssertPins(context.Background(), fresh, c.baseline, c.conf, pgconf.PinnedNames(2))
	if err != nil {
		t.Fatal(err)
	}
	if len(r) == 0 {
		t.Fatal("a database-level value of the session preload list is not reported")
	}
	for _, f := range r {
		t.Logf("finding %s: %s", f.Name, f.Detail)
	}
}

// TestRekey_CutAfterEachPasswordStatementThenRepeatedConverges: a re-key that
// ends after its first, second or third password statement (the session
// lost) leaves some roles with the new password and some with the old one.
// The session of a re-key needs no password, so the repeat is not locked
// out: after it the three roles log in with the new passwords and none with
// an old one.
func TestRekey_CutAfterEachPasswordStatementThenRepeatedConverges(t *testing.T) {
	for cut := 1; cut <= 3; cut++ {
		t.Run(fmt.Sprintf("after %d", cut), func(t *testing.T) {
			c := startCluster(t)
			old := c.secrets
			next := c.secrets // the next generation's passwords, the same salts
			next.SupabaseAdminPassword, next.PostgresPassword, next.AuthenticatorPassword = rnd(32), rnd(32), rnd(32)
			vs, err := verifiers(next)
			if err != nil {
				t.Fatal(err)
			}
			first := c.dial("supabase_admin")
			if err := setVerifiers(context.Background(), first, vs[:cut]); err != nil {
				t.Fatal(err)
			}
			first.Close(context.Background()) // the cut
			// Mixed state: the roles before the cut hold the new verifier, the others the old one.
			again := c.dial("supabase_admin") // a trust session: no password of either generation is needed
			for i, r := range platformLogins {
				want, _ := pgsock.ScramVerifier(c.password(r), old.ScramSalts[r])
				if i < cut {
					want = vs[i].verifier
				}
				if got := c.str(again, "select coalesce(rolpassword, '') from pg_catalog.pg_authid where rolname = $1", r); got != want {
					t.Fatalf("control: %s after the cut does not hold the expected verifier", r)
				}
			}
			if err := Rekey(context.Background(), again, next); err != nil {
				t.Fatalf("repeated re-key: %v", err)
			}
			again.Close(context.Background())
			c.secrets = next
			if err := c.scramLogins(); err != nil {
				t.Fatalf("after the repeat: %v", err)
			}
			c.secrets = old
			for _, r := range platformLogins {
				if conn, err := pgsock.Dial(context.Background(), c.target(r)); err == nil {
					conn.Close(context.Background())
					t.Errorf("%s still logs in with the previous password", r)
				}
			}
		})
	}
}
