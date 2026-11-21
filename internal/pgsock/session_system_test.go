package pgsock_test

// Settings of the system file that no role or database setting can carry and
// that stop a session before or at its first statement. They are start-time
// facts of a cluster started from restored or tenant-changed files. The tests
// need Docker and the pinned image and skip without either.

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/pgsock"
)

// system sets one line of the system file and reloads; it is undone at the
// end. Its own session neither waits for a standby nor for a delay.
func (c *pgc) system(kv string) {
	c.t.Helper()
	m := pgsock.StartupParams(true)
	m["synchronous_commit"], m["post_auth_delay"] = "local", "0"
	adm, err := c.raw("supabase_admin", m)
	if err != nil {
		c.t.Fatal(err)
	}
	c.exec(adm, "alter system set "+kv)
	c.exec(adm, "select pg_catalog.pg_reload_conf()")
	c.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if adm, err := c.raw("supabase_admin", m); err == nil {
			adm.Exec(ctx, "alter system reset all")
			adm.Exec(ctx, "select pg_catalog.pg_reload_conf()")
		}
	})
}

// TestDial_DelayAfterAuthenticationInTheSystemFile: a delay after
// authentication set in the system file holds every new session for that
// long before its first statement. Control: a session that does not set the
// name waits. The platform session logs in within its connect budget.
func TestDial_DelayAfterAuthenticationInTheSystemFile(t *testing.T) {
	c := newPG(t)
	c.system("post_auth_delay = 12") // seconds; the connect budget is 5
	// The reload reaches new sessions a moment later: the control is repeated
	// until one is held.
	plain := pgsock.StartupParams(false)
	delete(plain, "post_auth_delay")
	held := false
	for deadline := time.Now().Add(60 * time.Second); !held && time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		t0 := time.Now()
		ctl, err := c.raw("supabase_admin", plain) // gives up after 15 s
		if err == nil {
			ctl.Close(context.Background())
		}
		held = time.Since(t0) >= 10*time.Second
	}
	if !held {
		t.Fatal("control: no session without the name was held")
	}
	t0 := time.Now()
	conn, err := pgsock.Dial(context.Background(), c.target(true))
	if err != nil {
		t.Fatalf("the platform session was held by the delay (%v): %v", time.Since(t0).Round(time.Millisecond), err)
	}
	conn.Close(context.Background())
}

// TestDial_SynchronousStandbyNamedInTheSystemFile: a synchronous standby
// named in the system file, where none exists, makes every commit that wrote
// something wait for ever in a session that asks for it. Control: such a
// session's statement does not return. A platform session's write returns
// within its statement budget.
func TestDial_SynchronousStandbyNamedInTheSystemFile(t *testing.T) {
	c := newPG(t)
	c.system("synchronous_standby_names = 'nobody'")
	m := pgsock.StartupParams(true)
	m["synchronous_commit"] = "on"
	held := false
	for i := 0; i < 20 && !held; i++ {
		ctl, err := c.raw("supabase_admin", m)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = ctl.Exec(ctx, fmt.Sprintf("create role x_waits_%d", i))
		held = err != nil && ctx.Err() != nil
		cancel()
	}
	if !held {
		t.Fatal("control: every commit that should wait for the named standby returned")
	}
	conn := c.platform()
	ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
	defer cancel()
	t0 := time.Now()
	if _, err := conn.Exec(ctx, "create role x_waits_platform"); err != nil {
		t.Fatalf("the platform session's write did not return (%v): %v", time.Since(t0).Round(time.Millisecond), pgsock.Clean(err))
	}
}

// TestDial_KilledSessionLeavesNoStatementInTheLog: when a session's server
// process is killed while a statement runs, the server names the statement
// it was running in its log — read from what the session publishes about its
// activity. The platform session publishes nothing, so the line is not
// written. Control: the same session without that one parameter is named.
func TestDial_KilledSessionLeavesNoStatementInTheLog(t *testing.T) {
	c := newPG(t)
	killed := func(conn *pgx.Conn) (named bool) {
		t.Helper()
		marker := "mk_" + rndHex(8)
		pid := c.str(conn, "select pg_catalog.pg_backend_pid()::text")
		from := c.logLines()
		done := make(chan struct{})
		go func() {
			defer close(done)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			conn.Exec(ctx, "select pg_catalog.pg_sleep(45), 1 as "+marker)
		}()
		// The statement is running once the process sleeps in it: the kill is
		// sent when another session sees the process waiting, or after 5 s.
		adm := c.platform()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			if c.str(adm, "select coalesce(pg_catalog.max(wait_event), '') from pg_catalog.pg_stat_activity where pid = $1::int", pid) == "PgSleep" {
				break
			}
		}
		adm.Close(context.Background())
		if out, err := exec.Command("docker", "exec", c.name, "kill", "-9", pid).CombinedOutput(); err != nil {
			t.Fatalf("kill: %v %s", err, out)
		}
		<-done
		var lines []string
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(200 * time.Millisecond) {
			lines = c.logSince(from)
			if slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, "ready to accept connections") }) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the server did not come back after the kill:\n%s", strings.Join(lines, "\n"))
			}
		}
		if !slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, "(PID "+pid+") was terminated by signal 9") }) {
			t.Fatalf("the kill is not in the log:\n%s", strings.Join(lines, "\n"))
		}
		c.ready()
		return slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, marker) })
	}
	conn, err := pgsock.Dial(context.Background(), c.target(true))
	if err != nil {
		t.Fatal(err)
	}
	if killed(conn) {
		t.Error("the log names the statement of a killed platform session")
	}
	ctl, err := c.raw("supabase_admin", without("track_activities"))
	if err != nil {
		t.Fatal(err)
	}
	if !killed(ctl) {
		t.Error("control: without the parameter the killed session's statement was not named")
	}
}
