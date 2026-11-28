//go:build reach

package reach

// The cluster and the saga: what the platform's own sessions into a project's
// database server rely on and what they do not, the socket the platform dials
// and an untrusted server behind it, refs, the disk quota, resumable
// operations and identity release, and the route of each project's PostgREST.
// The database server of a project is untrusted: the tests act at the
// project's uid inside its container, acting as the platform's administrative
// role where a test needs one, and with a container whose init is a fake
// backend for a hostile init. Every negative stands next to a control on the
// same path; each test says what makes it fail.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/store"
	"github.com/jackc/pgx/v5"
)

// ───────── shared ─────────

const (
	sockInPG   = "/var/run/postgresql/.s.PGSQL.5432" // the cluster's socket as the container sees it
	dataInPG   = "/var/lib/postgresql/data"
	fakeLogIn  = "/tmp/fake.log" // in the container's size-limited tmpfs
	sockName   = ".s.PGSQL.5432"
	markerPath = "/rest/v1/marker?select=ref"
)

// checkProject runs `supapace project check REF` and returns its document and
// how long it took. The exit status must agree with "ok".
func checkProject(t testing.TB, ref string) (checkJSON, time.Duration) {
	t.Helper()
	start := time.Now()
	out, code := cli(t, "project", "check", ref)
	el := time.Since(start)
	var c checkJSON
	decode(t, "project check", out, &c)
	if (code == 0) != c.OK {
		t.Fatalf("project check %s: exit %d with \"ok\":%v", ref, code, c.OK)
	}
	return c, el
}

// wantCheck requires `project check` to report ok with exactly the drift names
// given (none when none is given).
func wantCheck(t testing.TB, what string, c checkJSON, drift ...string) {
	t.Helper()
	slices.Sort(drift)
	if !c.OK || !slices.Equal(c.driftNames(), drift) {
		t.Fatalf("%s: check ok %v (code %q), drift %v; want ok with drift %v", what, c.OK, c.Code, c.driftNames(), drift)
	}
}

// asUID runs a shell script inside p's cluster container at p's uid and gid,
// the identity a tenant with operating-system access has there.
func asUID(t testing.TB, p Project, script string, args ...string) result {
	t.Helper()
	return inAt(t, pgName(p), p.UID, script, args...)
}

// inAt runs a shell script inside container at uid and gid uid.
func inAt(t testing.TB, container string, uid int, script string, args ...string) result {
	t.Helper()
	r, err := run(cmdTimeout, nil, slices.Concat([]string{"docker", "exec", "--user", fmt.Sprintf("%d:%d", uid, uid),
		container, "sh", "-c", script, "sh"}, args)...)
	if err != nil {
		t.Fatalf("in %s at uid %d: %v", container, uid, err)
	}
	return r
}

func mustUID(t testing.TB, p Project, script string, args ...string) string {
	t.Helper()
	r := asUID(t, p, script, args...)
	if r.code != 0 {
		t.Fatalf("in %s at its uid: exit %d: %s", pgName(p), r.code, brief(r.stderr))
	}
	return r.stdout
}

// neutral are startup options that undo database-level session settings a
// tenant may set, for the suite's own recovery sessions.
const neutral = "PGOPTIONS=-c role=none -c default_transaction_read_only=off -c statement_timeout=0 -c local_preload_libraries= -c search_path=pg_catalog"

// adminSQL runs sql as the platform's administrative role over the socket with
// the neutral startup options.
func adminSQL(t testing.TB, p Project, sql string) (string, error) {
	t.Helper()
	pw := string(platformSecret(t, p, "pg.supabase_admin.password"))
	r, err := run(cmdTimeout, []string{"PGPASSWORD=" + pw, neutral}, psqlArgv(p.Ref, "supabase_admin", sql, neutral)...)
	if err != nil {
		t.Fatalf("admin sql in %s: %v", p.Ref, err)
	}
	if r.code != 0 {
		return "", fmt.Errorf("psql exit %d: %s", r.code, redact(brief(r.stderr)))
	}
	return strings.TrimSpace(r.stdout), nil
}

func mustSQL(t testing.TB, p Project, role, sql string) string {
	t.Helper()
	out, err := sqlAs(t, p, role, sql)
	if err != nil {
		t.Fatalf("as %s in %s: %v", role, p.Ref, err)
	}
	return out
}

func showPlacement(t testing.TB, ref string) placementJSON {
	t.Helper()
	out, code := cli(t, "project", "show", ref)
	var pj placementJSON
	decode(t, "project show", out, &pj)
	if code != 0 || pj.Ref != ref {
		t.Fatalf("project show %s: exit %d", ref, code)
	}
	return pj
}

// restartWait runs `project restart REF [--set …]` and requires it to end done;
// it returns how long it took.
func restartWait(t testing.TB, ref string, sets ...string) time.Duration {
	t.Helper()
	args := []string{"project", "restart", ref}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	start := time.Now()
	out, code := cli(t, args...)
	var op Op
	decode(t, "project restart", out, &op)
	if code != 0 || op.State != "done" {
		t.Fatalf("project restart %s: exit %d, operation %s at step %q: %s", ref, code, op.State, op.Step, op.LastError)
	}
	return time.Since(start)
}

// daemonPids lists the running `supapaced serve` processes (node or host
// install path). A process the daemon is starting shows the daemon's
// executable and command line between its fork and its exec; one whose parent
// is listed is such a child, not a second daemon, and is left out.
func daemonPids() []int {
	ps := slices.Concat(procsOf(daemonBin, "serve"), procsOf("/usr/local/bin/supapaced", "serve"))
	return slices.DeleteFunc(slices.Clone(ps), func(p int) bool { return slices.Contains(ps, ppidOf(p)) })
}

func daemonPid(t testing.TB) int {
	t.Helper()
	ps := daemonPids()
	if len(ps) != 1 {
		t.Fatalf("supapaced serve processes: %v, want exactly one", ps)
	}
	return ps[0]
}

// killDaemon sends SIGKILL to the daemon and returns its pid.
func killDaemon(t testing.TB) int {
	t.Helper()
	pid := daemonPid(t)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill -9 supapaced: %v", err)
	}
	return pid
}

// waitDaemonBack waits until a daemon other than old runs and its admin socket
// accepts a connection, and returns that moment.
func waitDaemonBack(t testing.TB, old int, within time.Duration) time.Time {
	t.Helper()
	for deadline := time.Now().Add(within); ; time.Sleep(200 * time.Millisecond) {
		if ps := daemonPids(); len(ps) == 1 && ps[0] != old {
			if c, err := net.DialTimeout("unix", paths.AdminSock(), time.Second); err == nil {
				c.Close()
				return time.Now()
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the daemon did not come back within %v (killed pid %d; running %v)", within, old, daemonPids())
		}
	}
}

// tenants is the id and start time of A's and B's four containers.
func tenants(t testing.TB, A, B Project) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, p := range []Project{A, B} {
		for _, c := range []string{pgName(p), restName(p)} {
			m[c] = containerState(t, c)
		}
	}
	return m
}

func wantSameTenants(t testing.TB, what string, before, after map[string]string) {
	t.Helper()
	for c, s := range before {
		if after[c] != s {
			t.Errorf("%s: %s was replaced or restarted (%s → %s)", what, c, s, after[c])
		}
	}
}

// extraProject creates a further project (named like the scratch project, so
// a later run removes a leftover) besides the one fixtureScratch holds, for
// the tests that need two at once; removed in cleanup. With --no-wait only
// Ref is set.
func extraProject(t testing.TB, args ...string) (Project, int64) {
	t.Helper()
	priv, kid, jwks := newIssuer(t)
	out, code := cli(t, append([]string{"project", "create", "--name", scratchName, "--issuer-jwks", jwks, "--no-wait"}, args...)...)
	var m mutationJSON
	if json.Unmarshal([]byte(out), &m) != nil || m.Ref == "" || code != 0 {
		t.Fatalf("extra project create --no-wait: exit %d, no ref", code)
	}
	t.Cleanup(func() { removeProject(t, m.Ref) })
	return Project{Ref: m.Ref, Issuer: priv, IssuerKID: kid}, m.OperationID
}

func waitDone(t testing.TB, what string, id int64) Op {
	t.Helper()
	op := waitOp(t, id)
	if op.State != "done" {
		t.Fatalf("%s: operation %d %s at step %q: %s", what, id, op.State, op.Step, op.LastError)
	}
	return op
}

// ───────── test 7 ─────────

// TestReach07_Roles: (7a) the image's own refusals for the tenant role are
// unchanged — parity with the upstream image, not a containment claim; (7b)
// the create-time assertion passed, ordinary tenant activity leaves no drift,
// drift made acting as the platform's administrative role is reported by its
// frozen check name while `project check` stays ok and a restart completes,
// the platform's session is untouched by a superuser-owned login trigger and
// by database-level session settings; (7c) a job the tenant role schedules
// with pg_cron runs.
func TestReach07_Roles(t *testing.T) {
	A, _ := fixtureAB(t)
	t.Run("7a_image_parity", func(t *testing.T) { imageParity(t, A) })
	t.Run("7b_bootstrap", func(t *testing.T) {
		S := fixtureScratch(t)
		bootstrapDrift(t, S,
			func() checkJSON { c, _ := checkProject(t, S.Ref); return c },
			func() { restartWait(t, S.Ref) })
	})
	t.Run("7c_scheduled_job", func(t *testing.T) { scheduledJob(t, A) })
}

// scheduledJob: as postgres, pg_cron is created and a job scheduled every
// second; within 60 s a run of it has succeeded and its row is in the table.
// Fails on a failed run (the reason is in the message) or when no run
// succeeds in time.
func scheduledJob(t *testing.T, p Project) {
	// A is kept between runs: a killed run may have left the extension.
	clean := func() {
		sqlAs(t, p, "postgres", "drop extension if exists pg_cron; drop table if exists public.reach_t7c")
	}
	clean()
	t.Cleanup(clean)
	mustSQL(t, p, "postgres", `create extension pg_cron; create table public.reach_t7c(who text);
select cron.schedule('reach_t7c', '1 seconds', $$insert into public.reach_t7c values (current_user)$$)`)
	last := func() string {
		return mustSQL(t, p, "postgres", `select d.status || ': ' || coalesce(d.return_message, '') from cron.job_run_details d join cron.job j using (jobid)
where j.jobname = 'reach_t7c' and d.status in ('succeeded', 'failed') order by d.runid desc limit 1`)
	}
	var got string
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(time.Second) {
		if got = last(); got != "" || time.Now().After(deadline) {
			break
		}
	}
	if !strings.HasPrefix(got, "succeeded: ") {
		t.Fatalf("scheduled job: last run %q, want succeeded", got)
	}
	if who := mustSQL(t, p, "postgres", "select string_agg(distinct who, ',') from public.reach_t7c"); who != "postgres" {
		t.Fatalf("scheduled job wrote rows as %q, want postgres", who)
	}
}

// paritySQL are the nine statements of the image-parity check, each with the
// error text the pinned image answers the tenant role with.
var paritySQL = []struct{ sql, fragment string }{
	{"alter role postgres superuser", "permission denied to alter role"},
	{"grant pg_execute_server_program to postgres", "role memberships are reserved"},
	{"grant supabase_admin to postgres", "role memberships are reserved"},
	{"copy (select 1) to program 'id'", "permission denied to COPY to or from an external program"},
	{"select pg_read_file('/etc/passwd')", "permission denied for function pg_read_file"},
	{"alter role supabase_admin password 'x'", "is a reserved role"},
	{"alter system set archive_command = 'id'", "permission denied to set parameter"},
	{"create role reach_t7_su superuser", "permission denied to create role"},
	{"create table storage.reach_t7_tbl(x int)", "permission denied for schema storage"},
	{"create function auth.reach_t7_fn() returns int language sql as 'select 1'", "permission denied for schema auth"},
}

// imageParity: as postgres over loopback the two controls succeed in the same
// session path, then each statement fails with its fragment. Fails if any
// statement succeeds or fails otherwise (the image changed), or if the
// controls fail (the path is dead and the refusals prove nothing).
func imageParity(t *testing.T, p Project) {
	// A is kept between runs: a killed run may have left the control objects.
	clean := func() { sqlAs(t, p, "postgres", "drop table if exists public.t7; drop role if exists t7_app") }
	clean()
	t.Cleanup(clean)
	mustSQL(t, p, "postgres", "create table public.t7(x int)")
	mustSQL(t, p, "postgres", "create role t7_app nologin")
	if got := mustSQL(t, p, "postgres", "select count(*) from pg_roles where rolname = 't7_app'"); got != "1" {
		t.Fatalf("control: t7_app not created (%q)", got)
	}
	for _, s := range paritySQL {
		_, err := sqlAs(t, p, "postgres", s.sql)
		if err == nil {
			// Undo what can be undone before failing (A is kept between runs).
			adminSQL(t, p, `alter role postgres nosuperuser; revoke pg_execute_server_program, supabase_admin from postgres;
drop role if exists reach_t7_su; drop table if exists storage.reach_t7_tbl; drop function if exists auth.reach_t7_fn()`)
			adminSQL(t, p, "alter system reset archive_command")
			t.Errorf("%q succeeded as the tenant role", s.sql)
			continue
		}
		if !strings.Contains(err.Error(), s.fragment) {
			t.Errorf("%q: %v; want %q", s.sql, err, s.fragment)
		}
	}
}

// bootstrapDrift: on project S (created, so its create-time assertion
// passed), check is ok with no drift; ordinary tenant activity keeps it so;
// each drift made as the administrative role or at the project's uid shows
// under its frozen name, with ok:true, and is gone once reverted; restart
// completes with drift present; a superuser-owned login trigger fires for a
// plain login of that role and not for the platform's session; tenant
// database-level session settings leave the check ok, and a check statement
// that waits on a lock is bounded by the platform's statement bound, not by
// the database's statement_timeout.
func bootstrapDrift(t *testing.T, S Project, check func() checkJSON, restart func()) {
	wantCheck(t, "control: a fresh project", check())

	t.Run("ordinary_tenant_activity", func(t *testing.T) {
		t.Cleanup(func() {
			sqlAs(t, S, "postgres", `drop event trigger if exists reach_ddl; drop function if exists public.reach_ddl_fn();
drop table if exists public.reach_ddl_log, public.reach_t7b, public.reach_t7b2; drop function if exists public.reach_t7b_f();
drop schema if exists reach_s cascade; drop role if exists reach_app`)
		})
		mustSQL(t, S, "postgres", `create table public.reach_ddl_log(tag text, usr text, app text);
create function public.reach_ddl_fn() returns event_trigger language plpgsql as $$
begin insert into public.reach_ddl_log select tg_tag, session_user, current_setting('application_name'); end $$;
create event trigger reach_ddl on ddl_command_end execute function public.reach_ddl_fn();
create table public.reach_t7b(id int primary key, v text);
create role reach_app nologin; grant reach_app to authenticator; grant select on public.reach_t7b to reach_app;
create function public.reach_t7b_f() returns int language sql as 'select 1';
create schema reach_s; alter default privileges in schema reach_s grant select on tables to anon;`)
		// Control: the tenant's own DDL fires its trigger.
		mustSQL(t, S, "postgres", "create table public.reach_t7b2(x int)")
		if n := mustSQL(t, S, "postgres", "select count(*) from public.reach_ddl_log where usr = 'postgres'"); n == "0" {
			t.Fatal("control: the tenant's own DDL did not fire its ddl_command_end trigger")
		}
		wantCheck(t, "after ordinary tenant activity", check())
		restart()
		wantCheck(t, "after a restart", check())
		// No platform session fired the tenant's trigger. The image does not
		// run a tenant-owned trigger for the administrative role in any case,
		// so this cannot show event_triggers=off; the login-trigger sub-test
		// is the one that fails without it.
		if n := mustSQL(t, S, "postgres", "select count(*) from public.reach_ddl_log where usr <> 'postgres' or app = 'supapace-agent'"); n != "0" {
			t.Fatalf("the tenant's ddl_command_end trigger fired for %s statements of another session", n)
		}
	})

	t.Run("login_trigger", func(t *testing.T) {
		t.Cleanup(func() {
			if _, err := adminSQL(t, S, "drop event trigger if exists reach_login; drop function if exists public.reach_login_fn(); drop table if exists public.reach_login_log"); err != nil {
				t.Errorf("dropping the login trigger: %v", err)
			}
		})
		if _, err := sqlAs(t, S, "supabase_admin", `create table public.reach_login_log(usr text, app text, at timestamptz default now());
create function public.reach_login_fn() returns event_trigger language plpgsql security definer set search_path = pg_catalog as $$
begin insert into public.reach_login_log(usr, app) values (session_user, current_setting('application_name')); end $$;
create event trigger reach_login on login execute function public.reach_login_fn();`); err != nil {
			t.Fatalf("creating a login trigger owned by the administrative role: %v", err)
		}
		count := func() int {
			// This login is itself counted: each call adds exactly one row.
			n, err := strconv.Atoi(mustSQL(t, S, "supabase_admin", "select count(*) from public.reach_login_log where usr = 'supabase_admin'"))
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		c0 := count()
		mustSQL(t, S, "supabase_admin", "select 1")
		if c1 := count(); c1 != c0+2 {
			t.Fatalf("control: a plain login of the administrative role added %d rows, want 1 (the trigger must fire for that role)", c1-c0-1)
		}
		c1 := count()
		res := check()
		// Fails if the platform's session carries no event_triggers=off.
		if c2 := count(); c2 != c1+1 {
			t.Fatalf("the platform's check session fired the login trigger (%d extra rows)", c2-c1-1)
		}
		wantCheck(t, "with a superuser-owned login trigger", res, "event-triggers")
	})

	t.Run("second_superuser", func(t *testing.T) {
		t.Cleanup(func() { adminSQL(t, S, "drop role if exists reach_su") })
		mustSQL(t, S, "supabase_admin", "create role reach_su superuser nologin")
		wantCheck(t, "with a second superuser", check(), "superuser")
		restart() // the finding is drift: a restart still completes
		wantCheck(t, "after a restart with a second superuser", check(), "superuser")
		mustSQL(t, S, "supabase_admin", "drop role reach_su")
		wantCheck(t, "after the second superuser is dropped", check())
	})

	t.Run("include_in_auto_conf", func(t *testing.T) {
		undo := func() {
			asUID(t, S, `f=`+dataInPG+`/postgresql.auto.conf; grep -v reach-inc "$f" > "$f.reach" && cat "$f.reach" > "$f"; rm -f "$f.reach" `+dataInPG+`/reach-inc.conf`)
			adminSQL(t, S, "select pg_reload_conf()")
		}
		t.Cleanup(undo)
		mustUID(t, S, `printf 'log_min_duration_statement = 123456\n' > `+dataInPG+`/reach-inc.conf && printf "include 'reach-inc.conf'\n" >> `+dataInPG+`/postgresql.auto.conf`)
		mustSQL(t, S, "supabase_admin", "select pg_reload_conf()")
		applied := func() bool {
			return mustSQL(t, S, "postgres", "select setting from pg_settings where name = 'log_min_duration_statement'") == "123456"
		}
		for deadline := time.Now().Add(10 * time.Second); !applied(); time.Sleep(500 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("control: the setting of the included file is not in force")
			}
		}
		wantCheck(t, "with an include in postgresql.auto.conf", check(), "source-file")
		restart()
		if !applied() {
			t.Fatal("control: the included setting is not in force after the restart")
		}
		wantCheck(t, "after a restart with the include", check(), "source-file")
		undo()
		for deadline := time.Now().Add(10 * time.Second); applied(); time.Sleep(500 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the included setting is still in force after the include was removed and the configuration reloaded")
			}
		}
		wantCheck(t, "after the include is removed", check())
	})

	t.Run("database_level_settings", func(t *testing.T) {
		t.Cleanup(func() {
			if _, err := adminSQL(t, S, "alter database postgres reset all"); err != nil {
				t.Errorf("resetting database-level settings: %v", err)
			}
		})
		want := []string{"search_path=reach_t7_path", "statement_timeout=1ms", "role=anon",
			"default_transaction_read_only=on", "local_preload_libraries=reach_missing"}
		argv := []string{"docker", "exec", "-e", "PGPASSWORD", pgName(S), "psql", "-X", "-w", "-q", "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres"}
		for _, w := range want {
			k, v, _ := strings.Cut(w, "=")
			argv = append(argv, "-c", fmt.Sprintf("alter database postgres set %s = '%s'", k, v))
		}
		r, err := run(cmdTimeout, []string{"PGPASSWORD=" + S.PostgresPassword}, argv...)
		if err != nil {
			t.Fatal(err)
		}
		got, err := adminSQL(t, S, "select coalesce(array_to_string(setconfig, ' '), '') from pg_db_role_setting s join pg_database d on d.oid = s.setdatabase where d.datname = 'postgres' and s.setrole = 0")
		if err != nil {
			t.Fatal(err)
		}
		var set []string
		for _, w := range want {
			if slices.Contains(strings.Fields(got), w) {
				set = append(set, w)
			} else {
				t.Logf("the tenant role could not set %s (outcome recorded: %s)", w, redact(brief(r.stderr)))
			}
		}
		// Fails as vacuous if the tenant could set none of them.
		if !slices.Contains(set, "search_path=reach_t7_path") || !slices.Contains(set, "statement_timeout=1ms") {
			t.Fatalf("control: the tenant's database-level settings were not stored (%v)", set)
		}
		wantCheck(t, "with database-level settings "+strings.Join(set, ", "), check())
		// The check's statements end within 1 ms on an idle catalog, so the
		// stored statement_timeout is shown by a statement that waits: a session
		// holds an exclusive lock on pg_event_trigger, which the check reads
		// after its login. Under the platform's own statement_timeout the
		// statement waits until the platform's statement bound (timeout); under
		// the database's 1 ms it would be cancelled at once (internal).
		release := holdLock(t, S, "begin; lock table pg_catalog.pg_event_trigger in access exclusive mode;", "LOCK TABLE")
		c := check()
		release()
		if c.OK || c.Code != "timeout" {
			t.Fatalf("with database-level statement_timeout=1ms and a check statement waiting on a lock: ok %v code %q, want timeout", c.OK, c.Code)
		}
		wantCheck(t, "after the lock is released", check())
	})
}

// ───────── test 9 ─────────

// TestReach09_HBAAndSocket: loopback without a password is refused for every
// baseline role; the socket admits the administrative role by password and
// the backup role by peer only; on a scratch project a planted link, a fake
// backend in the container and a container whose init is a fake backend are
// each refused by the platform's session in their bound, with nothing derived
// from a password sent; and nothing sent to one cluster is valid at another.
func TestReach09_HBAAndSocket(t *testing.T) {
	A, B := fixtureAB(t)
	t.Run("loopback_and_socket_rules", func(t *testing.T) {
		hbaRules(t, A, string(platformSecret(t, A, "pg.supabase_admin.password")))
	})
	t.Run("socket_replaced", func(t *testing.T) {
		S := fixtureScratch(t)
		// The fake backend reaches the container through its read-only tools mount.
		placeProbe(t, filepath.Join(paths.RenderDir(S.Ref), "tools"))
		check := func() (checkJSON, time.Duration) { return checkProject(t, S.Ref) }
		c, _ := check()
		wantCheck(t, "control: before the socket is replaced", c)
		t.Run("planted_link", func(t *testing.T) { plantedLink(t, S, check) })
		t.Run("fake_backend_in_container", func(t *testing.T) { fakeInCluster(t, S, check) })
		t.Run("hostile_init", func(t *testing.T) { hostileInits(t, S, B, check) })
	})
	t.Run("secrets_project_local", func(t *testing.T) { secretsProjectLocal(t, A, B) })
}

// hbaRules: for every role of the baseline and the platform's two roles, a
// loopback login with no password is refused (the server asks for one or
// rejects); over the socket every role but the administrative and the backup
// role is rejected — the tenant role even with its right password, which the
// same login over loopback accepts; the administrative role over the socket
// needs its password and gets in with it; the backup role gets in by peer at
// the project's uid. Fails on any trust line, on a socket line for another
// role, or if the controls fail.
func hbaRules(t *testing.T, p Project, adminPW string) {
	bl, err := bootstrap.LoadBaseline()
	if err != nil {
		t.Fatal(err)
	}
	roles := []string{"supabase_realtime_admin", "supapace_backup"}
	for _, r := range bl.Roles {
		roles = append(roles, r.Name)
	}
	login := func(host, role, pw string) result {
		r, err := run(cmdTimeout, []string{"PGPASSWORD=" + pw}, "docker", "exec", "-e", "PGPASSWORD", pgName(p),
			"psql", "-X", "-w", "-q", "-t", "-A", "-h", host, "-U", role, "-d", "postgres", "-c", "select current_user")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	refused := func(r result) bool {
		return r.code != 0 && (strings.Contains(r.stderr, "no password supplied") || strings.Contains(r.stderr, "rejects connection") ||
			strings.Contains(r.stderr, "password authentication failed"))
	}
	if r := login("127.0.0.1", "postgres", p.PostgresPassword); r.code != 0 || strings.TrimSpace(r.stdout) != "postgres" {
		t.Fatalf("control: postgres with its password over loopback: exit %d %s", r.code, redact(brief(r.stderr)))
	}
	for _, role := range roles {
		if r := login("127.0.0.1", role, ""); !refused(r) {
			t.Errorf("%s over loopback without a password: exit %d %q, want a refusal", role, r.code, redact(brief(r.stdout+r.stderr)))
		}
		if role == "supabase_admin" || role == "supapace_backup" {
			continue
		}
		if r := login("/var/run/postgresql", role, ""); r.code == 0 || !strings.Contains(r.stderr, "rejects connection") {
			t.Errorf("%s over the socket: exit %d %q, want the socket's reject line", role, r.code, redact(brief(r.stdout+r.stderr)))
		}
	}
	if r := login("/var/run/postgresql", "postgres", p.PostgresPassword); r.code == 0 || !strings.Contains(r.stderr, "rejects connection") {
		t.Errorf("postgres with its password over the socket: exit %d %q, want the socket's reject line", r.code, redact(brief(r.stderr)))
	}
	if r := login("/var/run/postgresql", "supabase_admin", ""); r.code == 0 || !strings.Contains(r.stderr, "no password supplied") {
		t.Errorf("the administrative role over the socket without its password: exit %d %q, want a password demanded", r.code, redact(brief(r.stderr)))
	}
	if r := login("/var/run/postgresql", "supabase_admin", adminPW); r.code != 0 || strings.TrimSpace(r.stdout) != "supabase_admin" {
		t.Errorf("control: the administrative role with its password over the socket: exit %d %s", r.code, redact(brief(r.stderr)))
	}
	if r := login("/var/run/postgresql", "supapace_backup", ""); r.code != 0 || strings.TrimSpace(r.stdout) != "supapace_backup" {
		t.Errorf("control: the backup role by peer at the project's uid: exit %d %s", r.code, redact(brief(r.stderr)))
	}
	// Peer, not trust: the same login from another uid is refused.
	r, err := run(cmdTimeout, nil, "docker", "exec", "--user", "65534:65534", pgName(p), "psql", "-X", "-w", "-q", "-t", "-A",
		"-h", "/var/run/postgresql", "-U", "supapace_backup", "-d", "postgres", "-c", "select current_user")
	if err != nil {
		t.Fatal(err)
	}
	if r.code == 0 || !strings.Contains(r.stderr, "Peer authentication failed") {
		t.Errorf("the backup role over the socket from another uid: exit %d %q, want the peer check's refusal", r.code, redact(brief(r.stdout+r.stderr)))
	}
	// The administrative role's loopback line rejects, also with its password
	// (the same path admits postgres with its password, above).
	if r := login("127.0.0.1", "supabase_admin", adminPW); r.code == 0 || !strings.Contains(r.stderr, "rejects connection") {
		t.Errorf("the administrative role with its password over loopback: exit %d %q, want the loopback reject line", r.code, redact(brief(r.stdout+r.stderr)))
	}
}

// sockDir is S's socket directory on the node.
func sockDir(S Project) string { return filepath.Join(paths.ProjectDir(S.Ref), "sock") }

// sendStartup connects to a Unix socket path on the node (following links, as
// a careless client would) and sends a startup packet; reached is whether the
// connection was accepted.
func sendStartup(t testing.TB, path string) bool {
	t.Helper()
	c, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(startupPacket("reach-control"))
	time.Sleep(200 * time.Millisecond)
	return true
}

// fakeConns waits a moment and parses what the fake whose log is at path in
// container received.
func fakeConns(t testing.TB, container, path string) map[int][]byte {
	t.Helper()
	time.Sleep(200 * time.Millisecond) // a record still being written
	conns, err := parseFakeLog(fileIn(t, container, path))
	if err != nil {
		t.Fatalf("fake log %s in %s: %v", path, container, err)
	}
	return conns
}

// plantedLink: the socket's name is replaced by a symbolic link to another
// socket (a fake backend listening in the same directory); the check fails
// and that listener received no bytes. Control: connecting through the link
// the way a client that follows it would reaches the listener, which logs
// what it got. Fails if the platform's dial follows the link (the fake logs
// the startup packet, or the check reports peer) or if the check passes.
func plantedLink(t *testing.T, S Project, check func() (checkJSON, time.Duration)) {
	user := fmt.Sprintf("%d:%d", S.UID, S.UID)
	other := "/var/run/postgresql/.reach-other.s"
	log := "/tmp/reach-other.log"
	t.Cleanup(func() {
		asUID(t, S, `cd /var/run/postgresql && if [ -L .s.PGSQL.5432 ]; then rm -f .s.PGSQL.5432; fi; [ -e .reach-real ] && mv .reach-real .s.PGSQL.5432; rm -f .reach-other.s /tmp/reach-other.log`)
	})
	fakeInContainer(t, pgName(S), user, "--socket", other, "--log", log)
	mustUID(t, S, `cd /var/run/postgresql && mv .s.PGSQL.5432 .reach-real && ln -s .reach-other.s .s.PGSQL.5432`)
	res, _ := check()
	// The link itself is refused when the socket is opened (internal). A dial
	// that followed it would meet the listener, whose process is not the
	// recorded postmaster (peer), so peer means the link was followed.
	if res.OK || res.Code != "internal" {
		t.Errorf("project check with the socket replaced by a link: ok %v code %q, want internal", res.OK, res.Code)
	}
	if conns := fakeConns(t, pgName(S), log); len(conns) != 0 {
		t.Errorf("the link's target received %d connection(s) with data from the platform's dial", len(conns))
	}
	if !sendStartup(t, filepath.Join(sockDir(S), sockName)) || len(fakeConns(t, pgName(S), log)) == 0 {
		t.Fatal("control: a client following the link does not reach the listener behind it; the refusal proves nothing")
	}
	mustUID(t, S, `cd /var/run/postgresql && rm .s.PGSQL.5432 && mv .reach-real .s.PGSQL.5432`)
	c, _ := check()
	wantCheck(t, "control: the real socket back in place", c)
}

// fakeInCluster: the real socket's name is moved away and the fake backend,
// run inside the cluster container at the project's uid, binds the socket
// path, first answering with a SCRAM request, then asking for a cleartext
// password; the check reports peer and the fake received no bytes. Control:
// a client connecting to the same path reaches the fake, which logs it.
// Fails if the platform writes a byte before checking its peer.
func fakeInCluster(t *testing.T, S Project, check func() (checkJSON, time.Duration)) {
	user := fmt.Sprintf("%d:%d", S.UID, S.UID)
	t.Cleanup(func() {
		asUID(t, S, `cd /var/run/postgresql && [ -e .reach-real ] && { rm -f .s.PGSQL.5432; mv .reach-real .s.PGSQL.5432; }; rm -f /tmp/fake-*.log`)
	})
	mustUID(t, S, `cd /var/run/postgresql && mv .s.PGSQL.5432 .reach-real`)
	for _, mode := range []string{"sasl", "cleartext"} {
		log := "/tmp/fake-" + mode + ".log"
		stop := fakeInContainer(t, pgName(S), user, "--socket", sockInPG, "--log", log, "--mode", mode)
		res, _ := check()
		if res.OK || res.Code != "peer" {
			t.Errorf("fake %s backend in the container: check ok %v code %q, want code peer", mode, res.OK, res.Code)
		}
		if conns := fakeConns(t, pgName(S), log); len(conns) != 0 {
			t.Errorf("fake %s backend in the container received data from the platform on %d connection(s)", mode, len(conns))
		}
		if !sendStartup(t, filepath.Join(sockDir(S), sockName)) || len(fakeConns(t, pgName(S), log)) == 0 {
			t.Fatalf("control: a client at the socket path does not reach the fake %s backend; the empty log proves nothing", mode)
		}
		stop()
		mustUID(t, S, `rm -f /var/run/postgresql/.s.PGSQL.5432`)
	}
	mustUID(t, S, `cd /var/run/postgresql && mv .reach-real .s.PGSQL.5432`)
	c, _ := check()
	wantCheck(t, "control: the real socket back in place", c)
}

// hostileInits: S's cluster container is replaced, mode by mode, by a
// container with the cluster's own flags, mounts and labels whose init is the
// fake backend; the suite records the fake's pid and start time as the
// postmaster's, so the peer check passes and the fake is the server the
// platform talks to. For post-authentication modes the fake holds S's
// administrative password and the platform's salt for that role; sasl-iter
// gets that salt too. Each mode's
// verdict and bound are in hostileModes; meanwhile the daemon's resident set
// grows by less than 64 MiB and a restart of B completes in its normal time.
// Fails on a missed bound, a passing check, a password sent in any form but
// SCRAM, control characters relayed, or a daemon the fake can stall or bloat.
func hostileInits(t *testing.T, S, B Project, check func() (checkJSON, time.Duration)) {
	dek := projectDEK(t, S)
	salt, err := pgsock.ScramSalt(dek, S.Ref, "supabase_admin")
	clear(dek)
	if err != nil {
		t.Fatal(err)
	}
	normal := restartWait(t, B.Ref) // B's normal restart time, the control for "in its normal time"
	// Hold the daemon's project repairs while the cluster is replaced by a
	// stand-in: taken before the stand-in exists, released after it is gone,
	// refreshed by every mode so it never ages past its limit.
	driftHold(t)
	h := replaceInit(t, S, platformSecret(t, S, "pg.supabase_admin.password"))
	for _, m := range hostileModes {
		t.Run(m.mode, func(t *testing.T) {
			driftHold(t) // refresh: the stand-in is removed and run again below
			pid := h.start(t, m, hex.EncodeToString(salt))
			if err := setStatePeer(filepath.Join(paths.RenderDir(S.Ref), "state.json"), pid, procStartOf(t, pid)); err != nil {
				t.Fatalf("recording the fake as the postmaster: %v", err)
			}
			d := daemonPid(t)
			rss0, err := rssKiB(d)
			if err != nil {
				t.Fatal(err)
			}
			// Waited for on every exit path (inBackground's cleanup), so a failed
			// mode never leaves B restarting into the next one.
			restarted := inBackground(t, func() time.Duration { return restartB(B) })
			res, el := check()
			for _, p := range hostileProblems(m, res, el, fakeConns(t, pgName(S), fakeLogIn)) {
				t.Error(p)
			}
			if rss1, err := rssKiB(d); err != nil || rss1-rss0 > 64<<10 {
				t.Errorf("the daemon's resident set grew from %d to %d KiB (%v)", rss0, rss1, err)
			}
			if got, ok := restarted(cliTimeout); !ok || got < 0 || got > 2*normal+30*time.Second {
				t.Errorf("a restart of B beside the check took %v (failed if negative); normal %v", got, normal)
			}
		})
	}
}

// replacedInit holds what a hostile-init container is built from.
type replacedInit struct {
	S      Project
	image  string
	flags  runFlags
	labels map[string]string
}

// restartB runs `project restart` of B and returns how long it took, or -1
// if it failed; for inBackground (it calls no testing method).
func restartB(B Project) time.Duration {
	start := time.Now()
	if r, err := run(cliTimeout, nil, cliBin, "project", "restart", B.Ref); err != nil || r.code != 0 {
		return -1
	}
	return time.Since(start)
}

// replaceInit stops S's cluster, keeps its configuration, removes it and
// places pw at <render>/tools/pw (0400, the project's uid) for the fake's
// post-authentication modes; cleanup removes the fake and the file.
func replaceInit(t testing.TB, S Project, pw []byte) *replacedInit {
	t.Helper()
	name := pgName(S)
	h := &replacedInit{S: S, image: imageOf(t, name), flags: containerFlags(t, name)}
	if err := json.Unmarshal([]byte(docker(t, "inspect", "-f", "{{json .Config.Labels}}", name)), &h.labels); err != nil {
		t.Fatal(err)
	}
	pwFile := filepath.Join(paths.RenderDir(S.Ref), "tools", "pw")
	t.Cleanup(func() {
		rmIgnoringAbsent(t, "rm", "-f", "-v", name)
		os.Remove(pwFile)
	})
	docker(t, "stop", "-t", "30", name)
	docker(t, "rm", "-v", name)
	if err := os.WriteFile(pwFile, pw, 0o400); err != nil {
		t.Fatal(err)
	}
	clear(pw)
	if err := os.Chown(pwFile, S.UID, S.UID); err != nil {
		t.Fatal(err)
	}
	return h
}

// start runs the fake in mode m as the container's init (replacing the
// previous one), waits for its listening line and returns its pid.
func (h *replacedInit) start(t testing.TB, m hostileMode, saltHex string) int {
	t.Helper()
	name := pgName(h.S)
	rmIgnoringAbsent(t, "rm", "-f", "-v", name)
	args := []string{"run", "-d", "--name", name, "--label", testLabel, "--network", "none"}
	for _, k := range slices.Sorted(maps.Keys(h.labels)) {
		args = append(args, "--label", k+"="+h.labels[k])
	}
	args = append(append(args, h.flags.args()...), "--entrypoint", toolsInPG, h.image,
		"fakepg", "--mode", m.mode, "--socket", sockInPG, "--log", fakeLogIn)
	switch {
	case m.postAuth:
		args = append(args, "--password-file", "/opt/supapace/tools/pw", "--salt", saltHex)
	case m.mode == "sasl-iter": // the platform's salt: only the iteration count differs
		args = append(args, "--salt", saltHex)
	}
	docker(t, args...)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		if strings.HasPrefix(docker(t, "logs", name), "listening ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fake init %s: no listening line within 10 s", m.mode)
		}
	}
	pid, _ := containerPid(t, name)
	return pid
}

func procStartOf(t testing.TB, pid int) uint64 {
	t.Helper()
	s, err := pgsock.ProcStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// secretNames are the platform's secrets of a project.
var secretNames = []string{"pg.supabase_admin.password", "pg.postgres.password", "pg.authenticator.password",
	"jwt.anon.private", "jwt.service_role.private", "jwt.secret", "pgsodium.root_key", "token.anon", "token.service_role"}

// secretsProjectLocal: from postgrest-B's namespace a login to pg-B as
// authenticator with A's password fails and with B's succeeds; over B's
// socket the administrative role with A's password fails and with B's
// succeeds; no secret value of A equals one of B, each read back equal.
// Fails if any secret is shared between projects or if the controls fail.
func secretsProjectLocal(t *testing.T, A, B Project) {
	addr := netip.AddrPortFrom(nodeConf(t).ClusterAddr(B.SubnetIndex), 5432).String()
	aAuth, bAuth := string(platformSecret(t, A, "pg.authenticator.password")), string(platformSecret(t, B, "pg.authenticator.password"))
	if err := loginFrom(t, restName(B), addr, "authenticator", bAuth); err != nil {
		t.Fatalf("control: authenticator with B's password from postgrest-B: %v", err)
	}
	if err := loginFrom(t, restName(B), addr, "authenticator", aAuth); err == nil {
		t.Error("authenticator with A's password was accepted by pg-B")
	}
	for _, c := range []struct {
		who  Project
		want bool
	}{{B, true}, {A, false}} {
		pw := string(platformSecret(t, c.who, "pg.supabase_admin.password"))
		r, err := run(cmdTimeout, []string{"PGPASSWORD=" + pw}, psqlArgv(B.Ref, "supabase_admin", "select 1")...)
		if err != nil {
			t.Fatal(err)
		}
		if (r.code == 0) != c.want {
			t.Errorf("the administrative role over B's socket with %s's password: exit %d, want success %v", c.who.Ref, r.code, c.want)
		}
	}
	values := map[string][]byte{}
	for _, p := range []Project{A, B} {
		for _, n := range secretNames {
			v := platformSecret(t, p, n)
			if again := platformSecret(t, p, n); !bytes.Equal(v, again) {
				t.Errorf("control: %s of %s does not read back equal", n, p.Ref)
			}
			if len(v) == 0 {
				t.Errorf("control: %s of %s is empty", n, p.Ref)
			}
			for k, w := range values {
				if !strings.HasPrefix(k, p.Ref) && bytes.Equal(v, w) {
					t.Errorf("%s of %s equals %s", n, p.Ref, k)
				}
			}
			values[p.Ref+" "+n] = v
		}
	}
}

// loginFrom logs in to addr as user with password by SCRAM from container's
// network namespace (dialled there by the node, as postgrest does) and runs
// select 1.
func loginFrom(t testing.TB, container, addr, user, password string) error {
	t.Helper()
	pid, _ := containerPid(t, container)
	cfg, err := pgx.ParseConfig("host=127.0.0.1 port=5432 dbname=postgres sslmode=disable connect_timeout=10")
	if err != nil {
		t.Fatal(err)
	}
	cfg.User, cfg.Password = user, password
	cfg.Fallbacks = nil
	cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		var c net.Conn
		var derr error
		if err := inNetns(pid, func() { c, derr = net.DialTimeout("tcp", addr, 5*time.Second) }); err != nil {
			return nil, err
		}
		return c, derr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, "select 1")
	return err
}

// ───────── test 10 ─────────

// TestReach10_NetExtensionsAbsent: outbound extensions are off by default
// (product behaviour): as the tenant role the five network-capable extensions
// cannot be created and none is installed; pg_trgm can (control). Fails if
// any of the five is created or present, or if the control fails.
func TestReach10_NetExtensionsAbsent(t *testing.T) {
	A, _ := fixtureAB(t)
	netExtensions(t, A)
}

var networkExtensions = []string{"pg_net", "http", "dblink", "postgres_fdw", "wrappers"}

func netExtensions(t *testing.T, p Project) {
	// A is kept between runs: a killed run may have left the control extension.
	clean := func() { sqlAs(t, p, "postgres", "drop extension if exists pg_trgm") }
	clean()
	t.Cleanup(clean)
	installed := func(name string) bool {
		return mustSQL(t, p, "postgres", fmt.Sprintf("select count(*) from pg_extension where extname = '%s'", name)) != "0"
	}
	if installed("pg_trgm") {
		t.Fatal("pg_trgm cannot be removed before the control")
	}
	mustSQL(t, p, "postgres", "create extension pg_trgm")
	if !installed("pg_trgm") {
		t.Fatal("control: create extension pg_trgm did not install it")
	}
	for _, e := range networkExtensions {
		if _, err := sqlAs(t, p, "postgres", "create extension "+e); err == nil {
			t.Errorf("create extension %s succeeded as the tenant role", e)
			sqlAs(t, p, "supabase_admin", "drop extension if exists "+e+" cascade")
		}
		if installed(e) {
			t.Errorf("extension %s is installed", e)
		}
	}
}

// ───────── test 11 ─────────

// TestReach11_Refs: a create with a chosen valid ref succeeds (the accepted
// twin); refs of 19 characters, with upper case or with a dash are refused
// with bad_ref and create nothing; the ref of a deleted and of a purged
// project is refused with ref_exists. Fails on an accepted bad ref, on a
// reused ref, or on another code.
func TestReach11_Refs(t *testing.T) {
	fixtureAB(t)
	ref := randomRef(t)
	S := fixtureScratch(t, "--ref", ref)
	if S.Ref != ref {
		t.Fatalf("control: the chosen ref %s came back as %s", ref, S.Ref)
	}
	refused := func(what, r, code string) {
		t.Helper()
		_, _, jwks := newIssuer(t)
		out, exit := cli(t, "project", "create", "--name", scratchName, "--issuer-jwks", jwks, "--ref", r, "--no-wait")
		var e errorJSON
		json.Unmarshal([]byte(out), &e)
		if exit == 0 {
			var m mutationJSON
			if json.Unmarshal([]byte(out), &m) == nil && m.Ref != "" {
				t.Cleanup(func() { removeProject(t, m.Ref) })
			}
		}
		if exit != 1 || e.Code != code {
			t.Errorf("create with %s: exit %d code %q, want exit 1 and %q", what, exit, e.Code, code)
		}
	}
	// "A" and not ToUpper(ref[:1]): a ref may start with a digit, and the
	// upper-cased ref would then be the valid ref itself (ref_exists).
	bad := map[string]string{"19 characters": ref[:19], "upper case": "A" + ref[1:], "a dash": ref[:10] + "-" + ref[11:]}
	for what, r := range bad {
		refused(what, r, "bad_ref")
	}
	out, _ := cli(t, "project", "list")
	var list projectsJSON
	decode(t, "project list", out, &list)
	for _, p := range list.Projects {
		for what, r := range bad {
			if p.Ref == r {
				t.Errorf("a project with the ref with %s exists", what)
			}
		}
	}
	out, code := cli(t, "project", "delete", ref)
	var op Op
	decode(t, "project delete", out, &op)
	if code != 0 || op.State != "done" || showPlacement(t, ref).State != "deleted" {
		t.Fatalf("project delete: exit %d, operation %s: %s", code, op.State, op.LastError)
	}
	refused("the ref of a deleted project", ref, "ref_exists")
	out, code = cli(t, "project", "purge", ref)
	decode(t, "project purge", out, &op)
	if code != 0 || op.State != "done" || showPlacement(t, ref).State != "purged" {
		t.Fatalf("project purge: exit %d, operation %s: %s", code, op.State, op.LastError)
	}
	refused("the ref of a purged project", ref, "ref_exists")
}

// ───────── test 13 ─────────

// TestReach13_Quota: a scratch project with a disk quota stops taking blocks
// and inodes at its user limits while B keeps writing; a log flood of at
// least 100 MiB from it leaves B and the control-plane database writable and
// its container's log files within the configured bound and under 31 MiB;
// at its block limit `project show` carries its usage and a restart below
// that usage plus the start headroom is refused (quotaRefusal); after the
// runbook (a restart with twice the quota) it is active and writes again. The
// fills run at its uid in a filler container (see filler), are bounded by
// the quota and are removed in cleanup. Fails if a write past either limit
// succeeds, if B or the control plane stops taking writes, if the log grows
// past the bound, if the refusal or the usage is wrong, or if the controls
// (writes below the limit, the flood reaching the log) fail.
func TestReach13_Quota(t *testing.T) {
	_, B := fixtureAB(t)
	bl, err := bootstrap.LoadBaseline()
	if err != nil {
		t.Fatal(err)
	}
	// The admin API's floor is 1024 MiB; the fresh cluster plus 128 MiB is less.
	quotaMB := max(bl.FreshClusterMB+128, 1024)
	S := fixtureScratch(t, "--disk-quota", fmt.Sprintf("%dm", quotaMB))
	stopB := writesThroughout(t, B)

	t.Run("inode_limit", func(t *testing.T) { inodeLimit(t, S, quotaMB) })
	t.Run("log_flood", func(t *testing.T) { logFlood(t, S, B) })
	t.Run("block_limit_and_runbook", func(t *testing.T) {
		blockLimit(t, S, quotaMB)
		quotaRefusal(t, S, quotaMB)
		restartWait(t, S.Ref, fmt.Sprintf("disk_quota_mb=%d", 2*quotaMB))
		if st := projectState(t, S.Ref); st != "active" {
			t.Fatalf("after the runbook the project is %s, want active", st)
		}
		if q := quotaOf(t, S.UID); q.BlocksHard != int64(2*quotaMB)<<10 {
			t.Fatalf("after the runbook: block limit %d KiB, want %d", q.BlocksHard, 2*quotaMB<<10)
		}
		mustSQL(t, S, "postgres", "insert into public.reach_q select repeat('x', 1000) from generate_series(1, 1000)")
	})
	stopB()
}

// filler is a container of S's cluster image at S's uid with S's data
// directory at the same path, its own memory limit, no network and no
// capabilities, removed in cleanup. The fills of test 13 run there: they are
// charged to the same user quota, while the pages and inodes they create are
// charged to the filler's memory, not to the cluster container's (inodes
// alone reach some 280 MiB at the limit, beside the cluster's 512 MiB).
func filler(t testing.TB, S Project) string {
	t.Helper()
	return imageContainer(t, "reach-fill-"+S.Ref, imageOf(t, pgName(S)), "--network", "none",
		"--user", fmt.Sprintf("%d:%d", S.UID, S.UID), "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--read-only", "--memory", "512m", "--pids-limit", "64",
		"-v", filepath.Join(paths.ProjectDir(S.Ref), "data")+":"+dataInPG)
}

// inodeLimit: the user's inode limit is max(65536, 256 × MiB); empty files
// are created at the project's uid until a create fails, and that happens
// with the user's inodes at the limit (the quota report, not the shell's
// wording, says why). The creates before it are the accepted twin, and once
// one file is removed a create succeeds again. The loop stops at 1,024
// creates past the limit whatever happens. Fails if every create succeeds,
// if creates stop short of the limit, or if a create fails after a removal.
func inodeLimit(t *testing.T, S Project, quotaMB int) {
	q := quotaOf(t, S.UID)
	if want := int64(max(65536, 256*quotaMB)); q.InodesHard != want {
		t.Fatalf("inode limit %d, want %d", q.InodesHard, want)
	}
	f := filler(t, S)
	dir := dataInPG + "/reach-inodes"
	t.Cleanup(func() { inAt(t, f, S.UID, `rm -rf "$1"`, dir) })
	most := q.InodesHard - q.InodesUsed + 1024
	// `true` is a regular built-in: a failed redirection on it ends the loop,
	// not the shell (as it would on `:`).
	r := inAt(t, f, S.UID, `mkdir "$1" && cd "$1" && i=0
while [ $i -lt "$2" ] && true 2>/dev/null >f$i; do i=$((i+1)); done
echo $i`, dir, strconv.FormatInt(most, 10))
	made, err := strconv.ParseInt(strings.TrimSpace(r.stdout), 10, 64)
	if r.code != 0 || err != nil {
		t.Fatalf("file creation: exit %d %q %s", r.code, brief(r.stdout), brief(r.stderr))
	}
	at := quotaOf(t, S.UID)
	t.Logf("%d files created; inodes used %d → %d, limit %d", made, q.InodesUsed, at.InodesUsed, q.InodesHard)
	if made >= most {
		t.Fatalf("%d files created at the project's uid, %d past the inode limit %d: no limit enforced", made, made-(q.InodesHard-q.InodesUsed), q.InodesHard)
	}
	if at.InodesUsed < q.InodesHard-64 || made < q.InodesHard-q.InodesUsed-64 {
		t.Fatalf("file creation stopped after %d files with %d inodes used, limit %d: not at the limit", made, at.InodesUsed, q.InodesHard)
	}
	if r := inAt(t, f, S.UID, `cd "$1" && rm f0 && true >again`, dir); r.code != 0 {
		t.Fatalf("control: a create after removing one file failed: exit %d %s", r.code, brief(r.stderr))
	}
}

// logFlood: as the administrative role the scratch project emits at least
// 100 MiB of log lines (counted: 1,700 lines of 64 KiB); the container's
// stored log stays within its log driver's configured bound and under 31
// MiB, and three writes each into the control-plane database and into B
// (whose writer table writesThroughout made) succeed while the flood runs.
// Control: a marker logged after the flood is in the container's log within
// a tail window of that bound, with flood lines before it (the flood reached
// the log). Fails if the log grows past either bound, if a write during the
// flood fails, or if the control fails.
func logFlood(t *testing.T, S, B Project) {
	const line, lines = 64 << 10, 1700
	if lines*line < 100<<20 {
		t.Fatal("the flood is smaller than 100 MiB")
	}
	var lc struct {
		Type   string
		Config map[string]string
	}
	if err := json.Unmarshal([]byte(docker(t, "inspect", "-f", "{{json .HostConfig.LogConfig}}", pgName(S))), &lc); err != nil {
		t.Fatalf("log configuration of %s: %v", pgName(S), err)
	}
	bound, err := logBound(lc.Config)
	if err != nil {
		t.Fatalf("%s: %v", pgName(S), err)
	}
	// Rotated files are compressed and the flood compresses well, so the
	// stored size alone can stay small under a larger bound.
	if bound >= 31<<20 {
		t.Errorf("%s: configured log bound %d bytes, want under 31 MiB", pgName(S), bound)
	}
	// The flood runs until the control below has finished, so the control
	// overlaps it whatever the machine's speed: the flood's first nextval says
	// it has begun, and it ends only after its counted lines and the setval
	// that follows the control (or fails 30 s after it began: a bound in time,
	// not in lines, so a fast log and slow commands cannot end it early).
	const seq = "public.reach_flood_seq"
	mustSQL(t, S, "supabase_admin", "drop sequence if exists "+seq+"; create sequence "+seq)
	t.Cleanup(func() { sqlAs(t, S, "supabase_admin", "drop sequence if exists "+seq) })
	pw := string(platformSecret(t, S, "pg.supabase_admin.password"))
	flood := fmt.Sprintf(`set log_min_messages = debug5;
do $$ declare i int := 0; begin
  perform nextval('%[1]s');
  loop
    raise log '%%', repeat('f', %[3]d);
    i := i + 1;
    exit when i >= %[2]d and (select last_value from %[1]s) >= 2;
    if clock_timestamp() > statement_timestamp() + interval '30 s' then raise exception 'reach-flood: not released'; end if;
  end loop;
end $$;
do $$ begin raise log 'reach-flood-marker'; end $$;`, seq, lines, line)
	flooded := inBackground(t, func() error {
		r, err := run(cmdTimeout, []string{"PGPASSWORD=" + pw}, psqlArgv(S.Ref, "supabase_admin", flood)...)
		if err == nil && r.code != 0 {
			err = fmt.Errorf("psql exit %d: %s", r.code, redact(brief(r.stderr)))
		}
		return err
	})
	for deadline := time.Now().Add(time.Minute); mustSQL(t, S, "supabase_admin", "select is_called from "+seq) != "t"; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the flood did not begin within a minute")
		}
	}
	writeB := commandOK([]string{"PGPASSWORD=" + B.PostgresPassword},
		psqlArgv(B.Ref, "postgres", "insert into public.reach_writes(pad) values ('flood')")...)
	for i := range 3 {
		if err := cpWrite(); err != nil {
			t.Errorf("write %d into the control-plane database during the flood: %s", i+1, redact(brief(err.Error())))
		}
		if err := writeB(); err != nil {
			t.Errorf("write %d into %s during the flood: %s", i+1, B.Ref, redact(brief(err.Error())))
		}
	}
	mustSQL(t, S, "supabase_admin", "select setval('"+seq+"', 2)")
	if err, ok := flooded(cmdTimeout + time.Minute); !ok || err != nil {
		t.Fatalf("flood: ended %v: %v", ok, err)
	}
	t.Logf("flood: %d MiB of log lines; %s's log bound %d MiB (%s)", lines*line>>20, pgName(S), bound>>20, lc.Type)
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(time.Second) {
		found, after, long := containerLogTail(t, pgName(S), "reach-flood-marker", line/4, 2*bound)
		if found && after <= bound && long > 0 {
			t.Logf("marker found %d bytes before the end of the log, after %d flood lines", after, long)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("control: marker found %v with %d bytes after it (window %d), %d flood lines: the flood did not reach the log", found, after, bound, long)
		}
	}
	n := dockerLogBytes(t, pgName(S))
	t.Logf("%s stores %d bytes of log", pgName(S), n)
	if n > bound || n >= 31<<20 {
		t.Errorf("%s's log files hold %d bytes after the flood; configured bound %d, at most 31 MiB", pgName(S), n, bound)
	}
}

// containerLogTail streams `docker logs` of container (both streams, at most
// limit bytes, within cmdTimeout) through logTail.
func containerLogTail(t testing.TB, container, marker string, long int, limit int64) (found bool, after int64, longLines int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "logs", container)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("docker logs %s: %v", container, err)
	}
	found, after, longLines, err = logTail(io.LimitReader(out, limit), marker, long)
	io.Copy(io.Discard, out)
	if werr := cmd.Wait(); err == nil && werr != nil {
		err = werr
	}
	if err != nil {
		t.Fatalf("docker logs %s: %v", container, err)
	}
	return found, after, longLines
}

// blockLimit: writes below the limit succeed (a database write and a 64 MiB
// file on the same path as the fill, both from the filler); a file written at the project's uid
// fails with the user's blocks at the limit (the quota report says why); the
// database's own writes then fail too. The fill writes at most the quota plus
// 256 MiB, the quota bounds what lands on disk, and the file is removed in
// cleanup. Fails if the fill succeeds, if it stops short of the limit, or if
// the database still takes a large write.
func blockLimit(t *testing.T, S Project, quotaMB int) {
	q := quotaOf(t, S.UID)
	if q.BlocksHard != int64(quotaMB)<<10 {
		t.Fatalf("block limit %d KiB, want %d", q.BlocksHard, quotaMB<<10)
	}
	f, fill := filler(t, S), dataInPG+"/reach-fill"
	t.Cleanup(func() { inAt(t, f, S.UID, `rm -f "$1"`, fill) })
	mustSQL(t, S, "postgres", "create table if not exists public.reach_q(pad text); insert into public.reach_q select repeat('x', 1000) from generate_series(1, 1000)")
	if r := inAt(t, f, S.UID, `dd if=/dev/zero of="$1" bs=1M count=64 oflag=direct 2>/dev/null && rm "$1"`, fill); r.code != 0 {
		t.Fatalf("control: a 64 MiB file below the limit: exit %d %s", r.code, brief(r.stderr))
	}
	// In 64 MiB pieces, each flushed: on the harness's loop-backed file system
	// the written pages are charged to the writer, and an unflushed fill of
	// the whole quota exhausts the filler's memory before the quota.
	r := inAt(t, f, S.UID, `i=0; while [ $i -lt "$2" ]; do
dd if=/dev/zero of="$1" bs=1M count=64 seek=$i conv=notrunc,fsync oflag=direct || exit 1; i=$((i+64)); done`,
		fill, strconv.Itoa(quotaMB+256))
	at := quotaOf(t, S.UID)
	t.Logf("fill: exit %d; blocks used %d → %d KiB, limit %d KiB", r.code, q.BlocksUsed, at.BlocksUsed, q.BlocksHard)
	if r.code == 0 {
		t.Fatalf("a write of %d MiB past a %d MiB quota succeeded", quotaMB+256, quotaMB)
	}
	if at.BlocksUsed < q.BlocksHard-1024 {
		t.Fatalf("the write failed at %d KiB used, limit %d KiB: not at the limit (%s)", at.BlocksUsed, q.BlocksHard, brief(r.stderr))
	}
	if _, err := sqlAs(t, S, "postgres", "insert into public.reach_q select repeat(md5(i::text), 64) from generate_series(1, 200000) i"); err == nil {
		t.Fatal("a database write of 200,000 rows succeeded with the quota exhausted")
	}
}

// quotaRefusal: with S at its block limit, `project show` carries the usage
// the quota charges (non-null for an active project, within 64 MiB of the
// quota report), and a restart to a quota below that usage plus the start
// headroom is refused at once with 409 quota_below_usage naming the smallest
// accepted value (the usage in MiB plus the headroom, again within 64 MiB);
// nothing changes. Control: the runbook's quota that follows is at least that
// value. Fails if the member is null or off, if the restart is not refused
// with that code and value, or if the project's state or generation moved.
func quotaRefusal(t *testing.T, S Project, quotaMB int) {
	var sh struct {
		State         string `json:"state"`
		Generation    int64  `json:"generation"`
		DiskUsedBytes *int64 `json:"disk_used_bytes"`
	}
	show := func() {
		out, code := cli(t, "project", "show", S.Ref)
		decode(t, "project show", out, &sh)
		if code != 0 {
			t.Fatalf("project show: exit %d", code)
		}
	}
	show()
	report := quotaOf(t, S.UID).BlocksUsed << 10
	if sh.State != "active" || sh.DiskUsedBytes == nil {
		t.Fatalf("project show: state %s, disk_used_bytes %v", sh.State, sh.DiskUsedBytes)
	}
	if d := *sh.DiskUsedBytes - report; d > 64<<20 || d < -64<<20 {
		t.Fatalf("disk_used_bytes %d, the quota report says %d bytes", *sh.DiskUsedBytes, report)
	}
	used, gen := *sh.DiskUsedBytes, sh.Generation
	out, code := cli(t, "project", "restart", S.Ref, "--set", fmt.Sprintf("disk_quota_mb=%d", quotaMB+1))
	var e errorJSON
	decode(t, "project restart below the usage", out, &e)
	const tag = "the smallest accepted value is "
	i := strings.LastIndex(e.Message, tag)
	least, err := strconv.ParseInt(e.Message[max(i, 0)+len(tag):], 10, 64)
	if code != 1 || e.Code != "quota_below_usage" || i < 0 || err != nil {
		t.Fatalf("restart to %d MiB at %d bytes used: exit %d %s %q, want quota_below_usage", quotaMB+1, used, code, e.Code, e.Message)
	}
	want := (used+1<<20-1)>>20 + store.QuotaHeadroomMB
	if least < want-64 || least > want+64 || least > int64(2*quotaMB) {
		t.Fatalf("smallest accepted value %d, want about %d and at most the runbook's %d", least, want, 2*quotaMB)
	}
	if show(); sh.State != "active" || sh.Generation != gen {
		t.Fatalf("after the refusal the project is %s at generation %d, want active at %d", sh.State, sh.Generation, gen)
	}
}

// ───────── test 14 ─────────

// createSteps are the worker's steps of a create of layout; step 1 is the
// admin API's own transaction and has no boundary to stop at. Layout 2 adds
// the first backup's steps after 4 and the control plane's catch-up before 12.
func createSteps(layout int) []string {
	if layout == 2 {
		return []string{"2", "3", "4a", "4", "5a", "5b", "5c", "5d", "6", "7", "7a", "9", "11", "12a", "12b", "12"}
	}
	return []string{"2", "3", "4a", "4", "6", "7", "7a", "9", "11", "12"}
}

// TestReach14_SagaAndIdentity: a daemon killed at each step boundary of a
// create comes back and the create ends done with exactly one of each object;
// throughout, A's and B's containers are adopted, never restarted; a second
// create waits for the single worker; delete keeps uid and slice; a create in
// the retention window gets neither; a create on a full node is refused at
// once with node_full and leaves no row; purge frees the slice only; uids
// only grow, across daemon restarts too; a purge clears a hostile tree
// without touching B; a restart against an include of a FIFO fails cleanly
// and its retry, once the include is gone, rolls back. Each sub-test says
// what makes it fail.
func TestReach14_SagaAndIdentity(t *testing.T) {
	A, B := fixtureAB(t)
	before := tenants(t, A, B)
	t.Cleanup(func() { wantSameTenants(t, "at the end of test 14", before, tenants(t, A, B)) })
	lastUID := max(A.UID, B.UID)

	// Fails if the failpoint is never hit (no restart), if the create does not
	// end done after the restart, if any object is missing or doubled, if a
	// uid is reused or lower, or if A's or B's containers were restarted.
	layout := nodeLayout(t)
	for _, step := range createSteps(layout) {
		t.Run("failpoint_create_"+step, func(t *testing.T) {
			t.Cleanup(func() { os.Remove(paths.Failpoint()) })
			old := daemonPid(t)
			if err := os.WriteFile(paths.Failpoint(), []byte("create:"+step), 0o600); err != nil {
				t.Fatal(err)
			}
			S := fixtureScratch(t, "--no-wait")
			waitDaemonBack(t, old, 5*time.Minute)
			if _, err := os.Stat(paths.Failpoint()); !os.IsNotExist(err) {
				t.Fatalf("the failpoint file is still present (%v): the daemon restarted for another reason", err)
			}
			waitDone(t, "create after the restart at create:"+step, newestOp(t, S.Ref).ID)
			for _, f := range []struct{ kind, name string }{{"ps", pgName(S)}, {"ps", restName(S)}, {"network", "proj-" + S.Ref}} {
				args := []string{"ps", "-aq", "--filter", "name=^" + f.name + "$"}
				if f.kind == "network" {
					args = []string{"network", "ls", "-q", "--filter", "name=^" + f.name + "$"}
				}
				if n := len(strings.Fields(docker(t, args...))); n != 1 {
					t.Errorf("%s: %d objects, want exactly one", f.name, n)
				}
			}
			if n := len(strings.Fields(docker(t, "ps", "-aq", "--filter", "name=^task-"+S.Ref+"-"))); n != 0 {
				t.Errorf("%d task containers of %s remain", n, S.Ref)
			}
			pl := showPlacement(t, S.Ref)
			if pl.UID == nil || *pl.UID <= lastUID {
				t.Fatalf("uid after a daemon restart: %v, want > %d", pl.UID, lastUID)
			}
			lastUID = *pl.UID
			wantSameTenants(t, "after the daemon restart at create:"+step, before, tenants(t, A, B))
		})
	}

	t.Run("queue_retention_and_release", func(t *testing.T) {
		// S1 is the scratch project; S2 is created right after it and must wait
		// for the single worker: pending at step 1 while S1's create runs. No
		// single listing shows both running. A create parked on a job
		// (waiting_job) gives the worker back, so at layout 2 S2 may run then;
		// at layout 1 nothing parks and S2 starts only once S1 is done.
		S1 := fixtureScratch(t, "--no-wait")
		op1 := newestOp(t, S1.Ref)
		_, op2id := extraProject(t)
		sawQueued, started := false, false
		final := func(o Op) bool { return o.State == "done" || o.State == "failed" || o.State == "aborted" }
		for deadline := time.Now().Add(2 * cliTimeout); ; time.Sleep(500 * time.Millisecond) {
			ops := opListing(t)
			o1, o2 := ops[op1.ID], ops[op2id]
			if o1.State == "running" && o2.State == "running" {
				t.Fatalf("one listing shows both creates running (steps %q and %q)", o1.Step, o2.Step)
			}
			if o2.State == "pending" && o2.Step == "1" {
				sawQueued = sawQueued || o1.State == "running"
			} else if !started {
				started = true
				if layout != 2 && o1.State != "done" {
					t.Fatalf("the second create ran (%s, step %q) while the first was %s", o2.State, o2.Step, o1.State)
				}
			}
			if final(o1) && final(o2) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the two creates still %s and %s after %v", o1.State, o2.State, 2*cliTimeout)
			}
		}
		if !sawQueued {
			t.Fatal("control: the first create was never seen running while the second waited")
		}
		waitDone(t, "first create", op1.ID)
		waitDone(t, "second create", op2id)
		p1 := showPlacement(t, S1.Ref)
		if p1.UID == nil || p1.SubnetIndex == nil {
			t.Fatalf("S1 placement %+v", p1)
		}
		out, code := cli(t, "project", "delete", S1.Ref)
		var op Op
		decode(t, "project delete", out, &op)
		if code != 0 || op.State != "done" {
			t.Fatalf("delete S1: %s %s", op.State, op.LastError)
		}
		if d := showPlacement(t, S1.Ref); d.State != "deleted" || d.UID == nil || *d.UID != *p1.UID || d.SubnetIndex == nil || *d.SubnetIndex != *p1.SubnetIndex {
			t.Fatalf("deleted S1: %+v, want uid %d and slice %d kept", d, *p1.UID, *p1.SubnetIndex)
		}
		S3, op3 := extraProject(t)
		waitDone(t, "create inside the retention window", op3)
		p3 := showPlacement(t, S3.Ref)
		if *p3.UID == *p1.UID || *p3.SubnetIndex == *p1.SubnetIndex {
			t.Fatalf("a create inside the retention window got uid %d slice %d; the deleted project holds uid %d slice %d", *p3.UID, *p3.SubnetIndex, *p1.UID, *p1.SubnetIndex)
		}
		out, code = cli(t, "project", "purge", S1.Ref)
		decode(t, "project purge", out, &op)
		if code != 0 || op.State != "done" {
			t.Fatalf("purge S1: %s %s", op.State, op.LastError)
		}
		if g := showPlacement(t, S1.Ref); g.State != "purged" || g.UID == nil || *g.UID != *p1.UID || g.SubnetIndex != nil {
			t.Fatalf("purged S1: %+v, want uid %d kept and no slice", g, *p1.UID)
		}
		// Admission: A, B, S2 and S3, and scratch projects up to the node's
		// own ceiling, fill its memory, so a create is refused at once with
		// node_full and writes no row (no tombstone, no ref burned). Control:
		// after the scratch projects are removed and S3 is deleted a further
		// project fits (S4 below); S3's slice stays held.
		// A 4 GiB test node holds four projects of 768 MiB (its ceiling is
		// three quarters of its memory) and needs no scratch project; the
		// 6 GiB node of a dashboard holds six. A host install has the
		// machine's own memory, so there the refusal is not asserted.
		if os.Getenv("SUPAPACE_HOST") == "1" {
			t.Log("host install: four projects do not fill this machine; the full-node refusal is asserted in the test node")
		} else {
			const projectMemMB = 512 + 256 // a cluster and its PostgREST, as admission counts them
			live := 0
			for _, p := range listPlacements(t) {
				if slices.Contains([]string{"provisioning", "active", "restarting", "restoring", "deleting"}, p.State) {
					live++
				}
			}
			var fill []string
			for range nodeConf(t).MemAllocMB/projectMemMB - live {
				P, id := extraProject(t)
				waitDone(t, "a create below the node's admission ceiling", id)
				fill = append(fill, P.Ref)
			}
			if nodeConf(t).StudioDomain == "" && len(fill) != 0 {
				t.Fatalf("a 4 GiB test node admits %d more projects than A, B, S2 and S3", len(fill))
			}
			rows := len(listPlacements(t))
			_, _, jwks := newIssuer(t)
			out, code = cli(t, "project", "create", "--name", scratchName, "--issuer-jwks", jwks, "--no-wait")
			var full errorJSON
			json.Unmarshal([]byte(out), &full)
			if code == 0 {
				var m mutationJSON
				if json.Unmarshal([]byte(out), &m) == nil && m.Ref != "" {
					t.Cleanup(func() { removeProject(t, m.Ref) })
				}
			}
			if code != 1 || full.Code != "node_full" {
				t.Fatalf("a create on a full node: exit %d code %q, want exit 1 and node_full", code, full.Code)
			}
			if n := len(listPlacements(t)); n != rows {
				t.Fatalf("a create refused with node_full changed the project list from %d to %d rows", rows, n)
			}
			for _, ref := range fill {
				if !removeProject(t, ref) {
					t.Fatalf("the scratch project %s that filled the node cannot be removed", ref)
				}
			}
		}
		out, code = cli(t, "project", "delete", S3.Ref)
		decode(t, "project delete", out, &op)
		if code != 0 || op.State != "done" {
			t.Fatalf("delete S3: %s %s", op.State, op.LastError)
		}
		lowest := lowestFreeSlice(t)
		S4, op4 := extraProject(t)
		waitDone(t, "create after the purge", op4)
		p4 := showPlacement(t, S4.Ref)
		maxUID := 0
		for _, p := range listPlacements(t) {
			if p.Ref != S4.Ref && p.UID != nil {
				maxUID = max(maxUID, *p.UID)
			}
		}
		if *p4.UID <= maxUID {
			t.Errorf("uid %d after the purge; the highest uid ever placed is %d", *p4.UID, maxUID)
		}
		// S1 received the lowest free slice and nothing below it was released
		// since, so the purge is what makes it the lowest free one again.
		if lowest != *p1.SubnetIndex || *p4.SubnetIndex != lowest {
			t.Errorf("after the purge the lowest free slice is %d and the next create got %d; want the purged project's %d",
				lowest, *p4.SubnetIndex, *p1.SubnetIndex)
		}
	})

	t.Run("purge_of_a_hostile_tree", func(t *testing.T) { purgeHostileTree(t, B) })
	t.Run("restart_with_fifo_include", func(t *testing.T) { fifoInclude(t, B) })
}

// waitState reads an operation once.
func waitState(t testing.TB, id int64) Op {
	t.Helper()
	out, _ := cli(t, "op", "show", strconv.FormatInt(id, 10))
	var op Op
	decode(t, "op show", out, &op)
	return op
}

func listPlacements(t testing.TB) []placementJSON {
	t.Helper()
	out, code := cli(t, "project", "list")
	var l struct {
		Projects []placementJSON `json:"projects"`
	}
	decode(t, "project list", out, &l)
	if code != 0 {
		t.Fatalf("project list: exit %d", code)
	}
	return l.Projects
}

// lowestFreeSlice is the lowest subnet index no project holds.
func lowestFreeSlice(t testing.TB) int {
	t.Helper()
	held := map[int]bool{}
	for _, p := range listPlacements(t) {
		if p.SubnetIndex != nil {
			held[*p.SubnetIndex] = true
		}
	}
	i := 0
	for held[i] {
		i++
	}
	return i
}

// purgeHostileTree: B's canary is written by B's uid; acting at the scratch
// project's uid, links to the canary (host path and in-container path), a
// FIFO, mode-000 directories, 2,000 nested directories and names with escape
// sequences are made in its data directory; delete and purge end done within
// the step deadline, the project directory is gone, B's canary is unchanged
// and no operation's error carries a control character. Fails if the purge
// follows a link, hangs on the FIFO or leaves the tree; the control is the
// tree counted before and the canary read before and after.
func purgeHostileTree(t *testing.T, B Project) {
	S := fixtureScratch(t)
	canary := filepath.Join(paths.ProjectDir(B.Ref), "data", "reach-canary")
	t.Cleanup(func() { asUID(t, B, "rm -f "+dataInPG+"/reach-canary") })
	mustUID(t, B, "echo canary > "+dataInPG+"/reach-canary")
	sum := func() string {
		b, err := os.ReadFile(canary)
		if err != nil {
			t.Fatalf("B's canary: %v", err)
		}
		s := sha256.Sum256(b)
		return hex.EncodeToString(s[:])
	}
	before := sum()
	hostileTree(t, S, canary)
	for _, verb := range []string{"delete", "purge"} {
		start := time.Now()
		out, code := cli(t, "project", verb, S.Ref)
		var op Op
		decode(t, "project "+verb, out, &op)
		if code != 0 || op.State != "done" {
			t.Fatalf("%s: exit %d, operation %s at step %q", verb, code, op.State, op.Step)
		}
		if el := time.Since(start); verb == "purge" && el > 300*time.Second {
			t.Errorf("the purge took %v, beyond the step deadline", el)
		}
	}
	// Every operation of the project, failed attempts' errors included. The
	// daemon's own log lines are not readable from inside the node (they are
	// the node container's output), so they are not checked here.
	out, code := cli(t, "op", "list", S.Ref)
	var ops opsJSON
	decode(t, "op list", out, &ops)
	if code != 0 || len(ops.Operations) < 3 {
		t.Fatalf("op list %s: exit %d, %d operations, want create, delete and purge", S.Ref, code, len(ops.Operations))
	}
	for _, o := range ops.Operations {
		if hasControl(o.LastError) {
			t.Errorf("operation %d (%s) carries a control character in its error", o.ID, o.Kind)
		}
	}
	if _, err := os.Lstat(paths.ProjectDir(S.Ref)); !os.IsNotExist(err) {
		t.Errorf("%s still exists after the purge (%v)", paths.ProjectDir(S.Ref), err)
	}
	if after := sum(); after != before {
		t.Error("B's canary changed during the purge")
	}
}

// hostileTree makes, at S's uid in its data directory, the tree a tenant
// could leave for the purge: links to target (a node path) and to the same
// name inside the container, a FIFO, a mode-000 directory with a file in it,
// names with terminal escape sequences and 2,000 nested directories; then
// counts it from the node (the control that it exists).
func hostileTree(t testing.TB, S Project, target string) {
	t.Helper()
	// The shell's cd fails past PATH_MAX, so the 2,000 levels are made as ten
	// chains of 200, each moved under the next: no command names the bottom.
	mustUID(t, S, `cd `+dataInPG+` && mkdir reach-tree && cd reach-tree &&
ln -s "$1" host-link && ln -s `+dataInPG+`/reach-canary in-link && mkfifo fifo &&
mkdir locked && : > locked/f && chmod 000 locked &&
mkdir "$(printf 'esc\033[2Jname\007')" && : > "$(printf 'x\033]0;t\007y')" &&
c=$(i=1; while [ $i -lt 200 ]; do printf deep/; i=$((i+1)); done)deep && mkdir -p "$c" &&
k=1; while [ $k -lt 10 ]; do mkdir -p "n/$c" && mv deep "n/$c/" && mv n/deep deep && rmdir n || exit 1; k=$((k+1)); done`, target)
	// reach-tree, 2 links, the FIFO, locked and its file, 2 escaped names, 2,000 levels.
	if n, err := countTree(filepath.Join(paths.ProjectDir(S.Ref), "data", "reach-tree")); err != nil || n != 2008 {
		t.Fatalf("control: the hostile tree holds %d entries (%v), want 2008", n, err)
	}
}

// fifoInclude: a restart of the unchanged project completes (control); acting at the
// project's uid, a FIFO in the data directory and an include of it in
// postgresql.auto.conf; a restart passes its pre-validation within 60 s
// (which reads no tenant data), ends failed within 10 minutes with the
// project restarting, leaves no task container, and B is served throughout.
// Then the include is removed through a scratch container at the project's
// uid and the operation retried: the rollback completes, the operation ends
// aborted with a rolled_back error and exit 1, and the project is active on
// its previous setting at a newer generation. Fails if pre-validation reads
// the FIFO (hangs), the worker never finishes, or the retry reports anything
// but the rollback.
func fifoInclude(t *testing.T, B Project) {
	S := fixtureScratch(t)
	restartWait(t, S.Ref, "max_connections=125")
	gen0 := showProject(t, S.Ref).Generation
	// Idempotent; the scratch cleanup then retries whatever is left and removes the project.
	t.Cleanup(func() {
		if err := dropFifoInclude(t, S.Ref, S.UID); err != nil {
			t.Error(err)
		}
	})
	mustUID(t, S, `mkfifo `+dataInPG+`/reach-fifo && printf "include '`+dataInPG+`/reach-fifo'\n" >> `+dataInPG+`/postgresql.auto.conf`)
	stopB := servedThroughout(t, B)
	out, code := cli(t, "project", "restart", S.Ref, "--set", "max_connections=130", "--no-wait")
	var m mutationJSON
	decode(t, "project restart", out, &m)
	if code != 0 || m.OperationID == 0 {
		t.Fatalf("project restart --no-wait: exit %d", code)
	}
	start := time.Now()
	// The step field names the last completed step (the CLI prints "after
	// step X"); a step beyond R1 is past pre-validation whichever way it is
	// read.
	pastR1 := false
	for time.Since(start) < 60*time.Second {
		op := waitState(t, m.OperationID)
		if pastR1 = !slices.Contains([]string{"", "R0", "R1"}, op.Step); pastR1 || op.State == "failed" {
			break
		}
		time.Sleep(time.Second)
	}
	if !pastR1 {
		t.Errorf("the restart did not complete its pre-validation within 60 s")
	}
	op, ok := pollOp(t, m.OperationID, start.Add(10*time.Minute))
	if !ok || op.State != "failed" {
		t.Fatalf("the restart against the FIFO include: %s at step %q after %v, want failed within 10 minutes", op.State, op.Step, time.Since(start).Round(time.Second))
	}
	if st := projectState(t, S.Ref); st != "restarting" {
		t.Errorf("project %s after the failed restart, want restarting", st)
	}
	if n := len(strings.Fields(docker(t, "ps", "-aq", "--filter", "name=^task-"+S.Ref+"-"))); n != 0 {
		t.Errorf("%d task containers of %s remain", n, S.Ref)
	}
	stopB()

	if err := dropFifoInclude(t, S.Ref, S.UID); err != nil {
		t.Fatal(err)
	}
	out, code = cli(t, "op", "retry", strconv.FormatInt(m.OperationID, 10))
	var r Op
	decode(t, "op retry", out, &r)
	if code != 1 || r.ID != m.OperationID || r.State != "aborted" || !strings.HasPrefix(r.LastError, "rolled_back:") {
		t.Fatalf("op retry after the include was removed: exit %d, operation %d %s at step %q (%s); want exit 1, aborted, rolled_back",
			code, r.ID, r.State, r.Step, redact(brief(r.LastError)))
	}
	pj := showProject(t, S.Ref)
	if pj.State != "active" || pj.Generation <= gen0 || pj.Generation == r.Generation || pj.AppliedGen != pj.Generation {
		t.Fatalf("after the rollback: project %s at generation %d (applied %d); before the restart %d, its target %d; want active at a newer generation than before, not the target",
			pj.State, pj.Generation, pj.AppliedGen, gen0, r.Generation)
	}
	if v := mustSQL(t, S, "postgres", "show max_connections"); v != "125" {
		t.Fatalf("after the rollback max_connections is %s, want the previous 125", v)
	}
}

// showProject is `project show REF`, which must exit 0.
func showProject(t testing.TB, ref string) projectJSON {
	t.Helper()
	out, code := cli(t, "project", "show", ref)
	var pj projectJSON
	decode(t, "project show", out, &pj)
	if code != 0 || pj.Ref != ref {
		t.Fatalf("project show %s: exit %d", ref, code)
	}
	return pj
}

// dropFifoInclude removes the FIFO include of fifoInclude from a project's
// postgresql.auto.conf, and the FIFO, through a scratch container of the
// cluster image at the project's uid (the cluster may be down; the node never
// writes in a tenant's directory as root). Idempotent; a no-op when the
// project has no data directory. It lets a restart left failed by the
// include be retried, for the test's cleanup and for the removal of a
// scratch project a killed run left behind.
func dropFifoInclude(t testing.TB, ref string, uid int) error {
	t.Helper()
	data := filepath.Join(paths.ProjectDir(ref), "data")
	if _, err := os.Lstat(data); os.IsNotExist(err) {
		return nil
	}
	r, err := run(cmdTimeout, nil, "docker", "run", "--rm", "--label", testLabel, "--network", "none", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--user", fmt.Sprintf("%d:%d", uid, uid),
		"-v", data+":/d", "--entrypoint", "sh", clusterImage(t),
		"-c", `f=/d/postgresql.auto.conf; if [ -f "$f" ] && grep -q reach-fifo "$f"; then { grep -v reach-fifo "$f" > /d/.reach; [ $? -le 1 ]; } && cat /d/.reach > "$f" || s=1; fi; rm -f /d/.reach /d/reach-fifo; exit ${s:-0}`)
	if err != nil || r.code != 0 {
		return fmt.Errorf("removing the FIFO include of %s: %v exit %d %s", ref, err, r.code, brief(r.stderr))
	}
	return nil
}

// clusterImage is the pinned cluster image.
func clusterImage(t testing.TB) string {
	t.Helper()
	return nodeConf(t).Images.Postgres
}

// ───────── test 16, route and adoption ─────────

// TestReach16_RouteAddressAndAdoption: each PostgREST holds its deterministic
// platform address across restart and daemon restart and idles at no more
// than 12 threads; while A's PostgREST is down and B restarts, neither host
// serves the other's data; a daemon restart adopts running tenants (same id, start time and
// postmaster start) and starts a stopped one; a tenant's pgrst.* setting
// changes nothing PostgREST enforces; and with one cluster stalling every
// platform session, the node answers and routes every project after a daemon
// restart. Each sub-test says what makes it fail.
func TestReach16_RouteAddressAndAdoption(t *testing.T) {
	A, B := fixtureAB(t)
	restAgain(t, A) // a killed run may have left a container of A or B stopped
	restAgain(t, B)
	conf := nodeConf(t)
	wantAddr := func(what string) {
		t.Helper()
		for _, p := range []Project{A, B} {
			if got := platformIP(t, restName(p)); got != conf.PlatformAddr(p.SubnetIndex) {
				t.Fatalf("%s: %s on platform at %v, want %v", what, restName(p), got, conf.PlatformAddr(p.SubnetIndex))
			}
		}
	}

	t.Run("address_and_threads", func(t *testing.T) {
		wantAddr("before")
		pid, _ := containerPid(t, restName(A))
		n, err := strconv.Atoi(procStatus(t, pid)["Threads"])
		if err != nil || n <= 0 || n > 12 {
			t.Errorf("postgrest-A idles at %d threads (%v), want 1 to 12", n, err)
		}
		restartWait(t, A.Ref)
		wantAddr("after project restart A")
		waitServed(t, A)
	})

	t.Run("down_never_serves_other", func(t *testing.T) {
		// Hold the daemon's project repairs while postgrest-A is stopped on
		// purpose; released after A is restarted.
		driftHold(t)
		markers(t, A, B)
		t.Cleanup(func() { restAgain(t, A) })
		docker(t, "stop", "-t", "10", restName(A))
		// Each request to A's host waits for the gateway's upstream dial
		// timeout, so several pollers keep requests in flight through B's
		// restart. B's host is polled as well: it must never serve A's
		// marker, and serving its own marker is the poll's control.
		stopA := pollHost(t, A, markerPath, hdr("apikey", A.AnonKey), 8)
		stopB := pollHost(t, B, markerPath, hdr("apikey", B.AnonKey), 1)
		restartWait(t, B.Ref)
		got, gotB := stopA(), stopB()
		t.Logf("%d requests to A's host and %d to B's during B's restart", len(got), len(gotB))
		if len(got) < 5 {
			t.Fatalf("only %d requests to A's host during the window", len(got))
		}
		for _, g := range got {
			if strings.Contains(g.body, B.Ref) {
				t.Fatalf("A's host served B's marker while postgrest-A was down")
			}
			var e struct {
				Code string `json:"code"`
			}
			json.Unmarshal([]byte(g.body), &e)
			if want := map[int]string{502: "upstream_unavailable", 503: "project_restarting", 504: "upstream_timeout"}[g.status]; want == "" || e.Code != want {
				t.Errorf("A's host answered %d %q while postgrest-A was down, want the gateway's 502, 503 or 504", g.status, e.Code)
			}
		}
		served := 0
		for _, g := range gotB {
			if strings.Contains(g.body, A.Ref) {
				t.Fatalf("B's host served A's marker during its restart")
			}
			if g.status == 200 && strings.Contains(g.body, B.Ref) {
				served++
			}
		}
		if served == 0 {
			t.Fatalf("control: B's host never served its own marker in %d requests during the window", len(gotB))
		}
		restartWait(t, A.Ref)
		wantMarker(t, A)
		wantMarker(t, B)
		wantAddr("after the crash and restarts")
	})

	t.Run("daemon_restart_adopts", func(t *testing.T) {
		before := tenants(t, A, B)
		pm := map[string]uint64{}
		for _, p := range []Project{A, B} {
			_, s, err := statePeer(filepath.Join(paths.RenderDir(p.Ref), "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			pm[p.Ref] = s
		}
		waitDaemonBack(t, killDaemon(t), 2*time.Minute)
		waitServed(t, A)
		waitServed(t, B)
		wantSameTenants(t, "after kill -9 of the daemon", before, tenants(t, A, B))
		for _, p := range []Project{A, B} {
			if _, s, err := statePeer(filepath.Join(paths.RenderDir(p.Ref), "state.json")); err != nil || s != pm[p.Ref] {
				t.Errorf("postmaster start of %s %d → %d (%v)", p.Ref, pm[p.Ref], s, err)
			}
		}
		wantAddr("after the daemon restart")
		// Control: a stopped tenant is started by the daemon's return, so the
		// unchanged ones above were adopted, not ignored.
		// Hold the daemon's project repairs between the stop and the kill, so
		// only the daemon's return can start pg-B (its boot drops the hold).
		driftHold(t)
		t.Cleanup(func() { restAgain(t, B) })
		docker(t, "stop", "-t", "30", pgName(B))
		waitDaemonBack(t, killDaemon(t), 2*time.Minute)
		for deadline := time.Now().Add(3 * time.Minute); !running(t, pgName(B)); time.Sleep(time.Second) {
			if time.Now().After(deadline) {
				t.Fatal("pg-B was not started after the daemon came back")
			}
		}
		if containerState(t, pgName(B)) == before[pgName(B)] {
			t.Error("control: pg-B reports its old start time after it was stopped and started")
		}
		waitServed(t, B)
	})

	t.Run("db_config_off", func(t *testing.T) { dbConfigOff(t, A) })
	t.Run("fairness", func(t *testing.T) { fairness(t, A, B) })
}

// restAgain restarts p if its cluster or PostgREST container is not running
// (a stop the test made, or one a killed run left), so p is served again.
func restAgain(t testing.TB, p Project) {
	t.Helper()
	if !running(t, pgName(p)) || !running(t, restName(p)) {
		restartWait(t, p.Ref)
	}
}

// platformIP is a container's address on the platform network.
func platformIP(t testing.TB, c string) netip.Addr {
	t.Helper()
	s := strings.TrimSpace(docker(t, "inspect", "-f", `{{with index .NetworkSettings.Networks "platform"}}{{.IPAddress}}{{end}}`, c))
	ip, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("%s: no platform address (%q)", c, s)
	}
	return ip
}

// markers gives A and B a one-row table marker(ref) readable by anon.
func markers(t testing.TB, ps ...Project) {
	t.Helper()
	for _, p := range ps {
		mustSQL(t, p, "postgres", fmt.Sprintf(`create table if not exists public.marker(ref text);
truncate public.marker; insert into public.marker values ('%s'); grant select on public.marker to anon;
notify pgrst, 'reload schema';`, p.Ref))
		wantMarker(t, p)
	}
}

func wantMarker(t testing.TB, p Project) {
	t.Helper()
	resp := waitREST(t, p, markerPath, hdr("apikey", p.AnonKey))
	var rows []struct{ Ref string }
	if json.Unmarshal(bodyOf(resp), &rows) != nil || len(rows) != 1 || rows[0].Ref != p.Ref {
		t.Fatalf("%s's host does not serve its own marker", p.Ref)
	}
}

type polled struct {
	status int
	body   string
}

// pollHost requests path on p's host from workers pollers, started 200 ms
// apart, each sending its next request 200 ms after its last answer, until the
// returned function is called; that function waits for the requests in flight
// and returns every answer (transport errors as status 0). Several pollers keep
// requests in flight through a window even when each answer takes the
// gateway's upstream dial timeout.
func pollHost(t testing.TB, p Project, path string, h http.Header, workers int) func() []polled {
	t.Helper()
	conf, dst := gatewayTLS(t, p)
	tr := &http.Transport{TLSClientConfig: conf, DisableKeepAlives: true, DialContext: dialer(netip.Addr{}).DialContext}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	var mu sync.Mutex
	var got []polled
	var wg sync.WaitGroup
	quit := make(chan struct{})
	for w := range workers {
		wg.Go(func() {
			for wait := time.Duration(w) * 200 * time.Millisecond; ; wait = 200 * time.Millisecond {
				select {
				case <-quit:
					return
				case <-time.After(wait):
				}
				req, _ := http.NewRequest("GET", "https://"+dst.String()+path, nil)
				req.Host = conf.ServerName
				req.Header = h.Clone()
				resp, err := client.Do(req)
				g := polled{}
				if err == nil {
					b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
					resp.Body.Close()
					g = polled{resp.StatusCode, string(b)}
				}
				mu.Lock()
				got = append(got, g)
				mu.Unlock()
			}
		})
	}
	var once sync.Once
	stop := func() []polled {
		once.Do(func() { close(quit); wg.Wait(); tr.CloseIdleConnections() })
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
	t.Cleanup(func() { stop() })
	return stop
}

// dbConfigOff: as the tenant role, a pgrst.* role setting on authenticator
// that would move the role claim to another claim; the setting is stored
// (control), and a token whose role claim is authenticated and whose other
// claim says service_role still runs as authenticated — before and after a
// configuration reload requested from the database. current_user is read,
// not the role claim, since the claim is the same either way. Fails if
// PostgREST follows the tenant's setting.
func dbConfigOff(t *testing.T, A Project) {
	// A is kept between runs: a killed run may have left the setting.
	sqlAs(t, A, "postgres", "alter role authenticator reset pgrst.jwt_role_claim_key")
	t.Cleanup(func() {
		sqlAs(t, A, "postgres", "alter role authenticator reset pgrst.jwt_role_claim_key; drop function if exists public.reach_current_role(); notify pgrst, 'reload schema'")
	})
	mustSQL(t, A, "postgres", `create or replace function public.reach_current_role() returns text language sql stable as $$ select current_user::text $$;
grant execute on function public.reach_current_role() to anon, authenticated, service_role; notify pgrst, 'reload schema';`)
	path := "/rest/v1/rpc/reach_current_role"
	tok := A.UserToken("authenticated", map[string]any{"fake": "service_role"})
	h := hdr("apikey", A.AnonKey, "Authorization", bearer(tok))
	wantRole(t, "control: the token before any setting", waitREST(t, A, path, h), "authenticated")
	wantRole(t, "control: the service key", waitREST(t, A, path, hdr("apikey", A.ServiceKey)), "service_role")
	if _, err := sqlAs(t, A, "postgres", "alter role authenticator set pgrst.jwt_role_claim_key = '.fake'"); err != nil {
		if !strings.Contains(err.Error(), "is a reserved role") && !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("the tenant's setting on authenticator failed, and not as a refusal: %v", err)
		}
		t.Logf("the image refuses the tenant's setting on authenticator (%v): the tenant has no lever; outcome recorded", err)
		return
	}
	if got := mustSQL(t, A, "postgres", "select coalesce(array_to_string(rolconfig, ' '), '') from pg_roles where rolname = 'authenticator'"); !strings.Contains(got, "pgrst.jwt_role_claim_key=.fake") {
		t.Fatalf("control: the setting is not stored (rolconfig %q)", got)
	}
	wantRole(t, "with the tenant's pgrst setting", gatewayDo(t, A, "GET", path, h, nil), "authenticated")
	mustSQL(t, A, "postgres", "notify pgrst, 'reload config'")
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(time.Second) {
		wantRole(t, "after a configuration reload requested from the database", gatewayDo(t, A, "GET", path, h, nil), "authenticated")
	}
}

// fairness: on the scratch project, acting as the administrative role, a
// session holds an exclusive lock on pg_authid (every login there waits);
// the daemon is killed; from its return the node check answers within 5 s,
// A's, B's and the scratch project's routes are active within 60 s, the
// scratch project's check fails with timeout within 75 s, and a restart of B
// submitted while that check stalls completes in its normal time. Control:
// after the lock is released the scratch check is ok. Fails if one stalled
// cluster delays the node, other projects or the worker.
func fairness(t *testing.T, A, B Project) {
	S := fixtureScratch(t)
	normal := restartWait(t, B.Ref)
	release := holdLock(t, S, "begin; lock table pg_catalog.pg_authid in access exclusive mode;", "LOCK TABLE")
	back := waitDaemonBack(t, killDaemon(t), 2*time.Minute)
	if _, code := cliWithin(t, 5*time.Second-time.Since(back), "node", "check"); code > 1 {
		t.Errorf("node check after the daemon's return: exit %d", code)
	}
	if el := time.Since(back); el > 5*time.Second {
		t.Errorf("node check answered %v after the daemon's return, bound 5 s", el)
	}
	for {
		st := routeStates(t)
		if st[A.Ref] == "active" && st[B.Ref] == "active" && st[S.Ref] == "active" {
			break
		}
		if time.Since(back) > 60*time.Second {
			t.Fatalf("routes 60 s after the daemon's return: A %q, B %q, scratch %q; want all active", st[A.Ref], st[B.Ref], st[S.Ref])
		}
		time.Sleep(500 * time.Millisecond)
	}
	// Both are waited for on every exit path (inBackground's cleanup).
	checked := inBackground(t, func() checkJSON {
		r, _ := run(cliTimeout, nil, cliBin, "project", "check", S.Ref)
		var c checkJSON
		json.Unmarshal([]byte(r.stdout), &c)
		return c
	})
	time.Sleep(2 * time.Second) // the check is under way
	restarted := inBackground(t, func() time.Duration { return restartB(B) })
	if c, ok := checked(75*time.Second - time.Since(back) + time.Second); !ok {
		t.Error("the scratch project's check did not answer within 75 s of the daemon's return")
	} else {
		if c.OK || c.Code != "timeout" {
			t.Errorf("the scratch project's check with every login stalled: ok %v code %q, want timeout", c.OK, c.Code)
		}
		if el := time.Since(back); el > 75*time.Second {
			t.Errorf("the scratch project's check answered %v after the daemon's return, bound 75 s", el)
		}
	}
	if got, ok := restarted(cliTimeout); !ok || got < 0 || got > 2*normal+30*time.Second {
		t.Errorf("a restart of B beside the stalled check took %v (failed if negative); normal %v", got, normal)
	}
	release()
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(2 * time.Second) {
		if c, _ := checkProject(t, S.Ref); c.OK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control: the scratch project's check is not ok after the lock is released")
		}
	}
}

// holdLock opens a session in p's cluster as the administrative role over the
// socket with the neutral startup options, sends sql and waits for the line
// ready; the session stays open until the returned function (also a cleanup)
// closes its input.
func holdLock(t testing.TB, p Project, sql, ready string) func() {
	t.Helper()
	pw := string(platformSecret(t, p, "pg.supabase_admin.password"))
	cmd := exec.Command("docker", "exec", "-i", "-e", "PGPASSWORD", "-e", "PGOPTIONS", pgName(p), "psql", "-X", "-w", "-h", "/var/run/postgresql",
		"-U", "supabase_admin", "-d", "postgres")
	cmd.Env = append(os.Environ(), "PGPASSWORD="+pw, neutral)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			io.WriteString(in, "rollback;\n")
			in.Close()
			done := make(chan struct{})
			go func() { cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
		})
	}
	t.Cleanup(release)
	io.WriteString(in, sql+"\n")
	got := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) == ready {
				got <- true
				io.Copy(io.Discard, out)
				return
			}
		}
		got <- false
	}()
	select {
	case ok := <-got:
		if !ok {
			release()
			t.Fatalf("the session in %s ended before %q", p.Ref, ready)
		}
	case <-time.After(30 * time.Second):
		release()
		t.Fatalf("the session in %s: no %q within 30 s", p.Ref, ready)
	}
	return release
}

// ───────── a fake backend inside a running cluster container ─────────

// fakeInContainer starts `sp-probe fakepg` from the tools mount inside
// container at user (uid:gid) and waits for its "listening" line. stop (also
// a cleanup) ends it: the docker exec client does not carry a signal into the
// container, so the fake is killed by pid from the node.
func fakeInContainer(t testing.TB, container, user string, args ...string) (stop func()) {
	t.Helper()
	argv := slices.Concat([]string{"docker", "exec", "--user", user, container, toolsInPG, "fakepg"}, args)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	var errb capped
	cmd.Stderr = &errb
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("fake backend in %s: %v", container, err)
	}
	pid, _ := containerPid(t, container)
	ns, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	var once sync.Once
	stop = func() {
		once.Do(func() {
			for _, p := range procsByArgv(toolsInPG, "fakepg") {
				if other, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", p)); other == ns {
					syscall.Kill(p, syscall.SIGKILL)
				}
			}
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			cmd.Wait()
		})
	}
	t.Cleanup(stop)
	got := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(out).ReadString('\n')
		got <- line
		io.Copy(io.Discard, out)
	}()
	select {
	case line := <-got:
		if !strings.HasPrefix(line, "listening ") {
			stop()
			t.Fatalf("fake backend in %s did not start: %q %s", container, line, brief(errb.String()))
		}
	case <-time.After(10 * time.Second):
		stop()
		t.Fatalf("fake backend in %s: no listening line within 10 s", container)
	}
	return stop
}

// fileIn reads a file of a container's mount namespace through its init.
func fileIn(t testing.TB, container, path string) []byte {
	t.Helper()
	pid, _ := containerPid(t, container)
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/root%s", pid, path))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("%s in %s: %v", path, container, err)
	}
	return b
}

// procsByArgv lists the pids whose argv[0] is arg0 and whose arguments
// include arg ("" any), sorted: for processes of another mount namespace,
// whose executable path the node cannot compare.
func procsByArgv(arg0, arg string) []int {
	var out []int
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cl, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		a := strings.Split(string(cl), "\x00")
		if a[0] == arg0 && (arg == "" || slices.Contains(a[1:], arg)) {
			out = append(out, pid)
		}
	}
	slices.Sort(out)
	return out
}
