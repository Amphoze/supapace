package pgsock_test

// The superuser startup parameters against the pinned cluster image: what a
// role, database or system setting of the restored or tenant-changed
// database does to a platform session with them, and without one of them.
// The tests need Docker and the pinned image and skip without either.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// imageUID is the uid of the image's postgres user, the owner of its socket.
const imageUID = 100

var pgSlots = make(chan struct{}, 3) // clusters running at once

type pgc struct {
	t                *testing.T
	image, name, ref string
	root, sock, hba  string
	pid              int
	start            uint64
}

func rndHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// newPG starts a fresh cluster of the pinned image (the image's own first
// boot, no network) whose access file trusts every local login, so that a
// control session can be opened as any role with any parameters.
func newPG(t *testing.T) *pgc {
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
	t.Parallel()
	pgSlots <- struct{}{}
	t.Cleanup(func() { <-pgSlots })
	c := &pgc{t: t, image: im.Postgres, name: "sp-test-session-" + rndHex(6), ref: rndHex(10)}
	if c.root, err = os.MkdirTemp("", "pgs-"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		exec.Command("docker", "rm", "-f", "-v", c.name).Run()
		exec.Command("docker", "run", "--rm", "--network", "none", "--label", "supapace.test=1", "-v", c.root+":/r",
			"--entrypoint", "rm", c.image, "-rf", "/r/"+c.ref).Run()
		os.RemoveAll(c.root)
	})
	c.sock = filepath.Join(c.root, c.ref, "sock")
	for _, d := range []string{c.sock, filepath.Join(c.root, c.ref, "data")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.Chmod(c.sock, 0o777)
	c.hba = filepath.Join(c.root, "pg_hba.conf")
	if err := os.WriteFile(c.hba, []byte("local all all trust\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.run("-e", "POSTGRES_PASSWORD="+rndHex(16))
	return c
}

// run creates and starts the container on the cluster's directories, with
// extra options and the command after the image (the image's own when none).
func (c *pgc) run(args ...string) {
	c.t.Helper()
	exec.Command("docker", "rm", "-f", "-v", c.name).Run()
	opts, cmd := args, []string(nil)
	if i := slices.Index(args, "--"); i >= 0 {
		opts, cmd = args[:i], args[i+1:]
	}
	a := slices.Concat([]string{"run", "-d", "--name", c.name, "--label", "supapace.test=1", "--network", "none",
		"--memory", "512m", "--memory-swap", "512m", "--shm-size", "64m",
		"-v", filepath.Join(c.root, c.ref, "data") + ":/var/lib/postgresql/data", "-v", c.sock + ":/var/run/postgresql",
		"-v", c.hba + ":/etc/postgresql/pg_hba.conf:ro"}, opts, []string{c.image}, cmd)
	if out, err := exec.Command("docker", a...).CombinedOutput(); err != nil {
		c.t.Fatalf("docker run: %v %s", err, out)
	}
	c.ready()
}

// ready reads the container's init and waits until a platform session to it
// logs in.
func (c *pgc) ready() {
	c.t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", c.name).Output()
	if err != nil {
		c.t.Fatal(err)
	}
	if c.pid, _ = strconv.Atoi(strings.TrimSpace(string(out))); c.pid <= 1 {
		c.logs()
		c.t.Fatalf("pid %q", out)
	}
	if c.start, err = pgsock.ProcStart(c.pid); err != nil {
		c.t.Fatal(err)
	}
	// The image's temporary server during its initialisation is another
	// process and is refused as a peer; the login succeeds once the init
	// process is the server.
	deadline := time.Now().Add(240 * time.Second)
	for {
		conn, err := pgsock.Dial(context.Background(), c.target(true))
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

func (c *pgc) logs() {
	out, _ := exec.Command("docker", "logs", "--tail", "40", c.name).CombinedOutput()
	c.t.Logf("container log:\n%s", out)
}

func (c *pgc) target(super bool) pgsock.Target {
	return pgsock.Target{ProjectsDir: c.root, Ref: c.ref, UID: imageUID, PostmasterPid: c.pid, PostmasterStart: c.start,
		User: "supabase_admin", AllowTrust: true, Superuser: super}
}

// platform is a platform session: pgsock.Dial with the superuser list.
func (c *pgc) platform() *pgx.Conn {
	c.t.Helper()
	conn, err := pgsock.Dial(context.Background(), c.target(true))
	if err != nil {
		c.t.Fatalf("platform session: %v", err)
	}
	c.t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// raw is a session as user with exactly these startup parameters (pgx over
// the socket directory, not pgsock): the control.
func (c *pgc) raw(user string, params map[string]string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig("host=" + c.sock + " port=5432 dbname=postgres sslmode=disable user=" + user)
	if err != nil {
		return nil, err
	}
	cfg.RuntimeParams = params
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err == nil {
		c.t.Cleanup(func() { conn.Close(context.Background()) })
	}
	return conn, err
}

// without is the superuser list without the named parameters.
func without(names ...string) map[string]string {
	m := pgsock.StartupParams(true)
	for _, n := range names {
		delete(m, n)
	}
	return m
}

func (c *pgc) exec(conn *pgx.Conn, sql string, args ...any) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		c.t.Fatalf("%s: %v", sql, pgsock.Clean(err))
	}
}

func (c *pgc) str(conn *pgx.Conn, sql string, args ...any) string {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var s string
	if err := conn.QueryRow(ctx, sql, args...).Scan(&s); err != nil {
		c.t.Fatalf("%s: %v", sql, pgsock.Clean(err))
	}
	return s
}

// logLines is the number of lines of the server log so far.
func (c *pgc) logLines() int { return len(c.logSince(0)) }

func (c *pgc) logSince(n int) []string {
	c.t.Helper()
	out, err := exec.Command("docker", "logs", c.name).CombinedOutput()
	if err != nil {
		c.t.Fatalf("docker logs: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if n > len(lines) {
		return nil
	}
	return lines[n:]
}

// watchActivity samples, from a platform session, the statement texts other
// sessions show in pg_stat_activity until stop is called, and returns how
// many samples held marker.
func (c *pgc) watchActivity(marker string) (stop func() int) {
	c.t.Helper()
	obs := c.platform()
	first := make(chan struct{})
	done := make(chan struct{})
	var hits int
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			var n int
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := obs.QueryRow(ctx, "select count(*)::int from pg_catalog.pg_stat_activity where pid <> pg_catalog.pg_backend_pid() "+
				"and pg_catalog.strpos(query, $1) > 0", marker).Scan(&n)
			cancel()
			if err == nil && n > 0 {
				hits++
			}
			if i == 0 {
				close(first)
			}
			select {
			case <-done:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()
	<-first
	return func() int { close(done); wg.Wait(); return hits }
}

// statsRows is the number of statement-statistics rows that hold marker.
func (c *pgc) statsRows(adm *pgx.Conn, marker string) int {
	n, _ := strconv.Atoi(c.str(adm, "select count(*)::text from extensions.pg_stat_statements where pg_catalog.strpos(query, $1) > 0", marker))
	return n
}

// roleSettings is supabase_admin's own role settings, to restore after a case.
func (c *pgc) roleSettings(adm *pgx.Conn) []string {
	s := c.str(adm, "select coalesce(pg_catalog.array_to_string(setconfig, e'\\n'), '') from pg_catalog.pg_db_role_setting "+
		"where setrole = 'supabase_admin'::pg_catalog.regrole and setdatabase = 0 union all select '' limit 1")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func (c *pgc) restoreRole(adm *pgx.Conn, saved []string) {
	c.exec(adm, "alter role supabase_admin reset all")
	for _, kv := range saved {
		k, v, _ := strings.Cut(kv, "=")
		c.exec(adm, fmt.Sprintf("alter role supabase_admin set %s = %s", pgx.Identifier{k}.Sanitize(), quote(v)))
	}
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// leakCase: one hostile setting, the statement the session runs, and what of
// it the server log, the statement statistics or the activity view show.
type leakCase struct {
	param   string   // the startup parameter under test
	also    []string // further parameters left out of both sessions (an overlap)
	setup   []string // run by a platform session before; undone by undo
	undo    []string
	stmt    string // "%s" is the marker; may fail
	sink    string // log, stats, activity, loaded
	timeout time.Duration
}

var leakCases = []leakCase{
	{param: "event_triggers", sink: "log", stmt: "select 1 as %s",
		setup: []string{`create function public.x_on_login() returns event_trigger language plpgsql as $f$ begin
		  if session_user = 'supabase_admin' then perform pg_catalog.set_config('log_statement', 'all', false); end if; end $f$`,
			"create event trigger x_on_login on login execute function public.x_on_login()"},
		undo: []string{"drop event trigger x_on_login", "drop function public.x_on_login()"}},
	{param: "session_preload_libraries", sink: "loaded", stmt: "select count(*) as %s from pg_catalog.pg_settings where name like 'pg_prewarm.%%'",
		setup: []string{"alter role supabase_admin set session_preload_libraries = 'pg_prewarm'"}},
	{param: "log_statement", sink: "log", stmt: "select 1 as %s", setup: []string{"alter role supabase_admin set log_statement = 'all'"}},
	{param: "log_min_duration_statement", sink: "log", stmt: "select 1 as %s",
		setup: []string{"alter role supabase_admin set log_min_duration_statement = 0"}},
	{param: "log_min_duration_sample", sink: "log", stmt: "select 1 as %s",
		setup: []string{"alter role supabase_admin set log_min_duration_sample = 0", "alter role supabase_admin set log_statement_sample_rate = 1"}},
	{param: "log_transaction_sample_rate", sink: "log", stmt: "select 1 as %s",
		setup: []string{"alter role supabase_admin set log_transaction_sample_rate = 1"}},
	{param: "log_duration", sink: "duration", stmt: "select 1 as %s", setup: []string{"alter role supabase_admin set log_duration = on"}},
	{param: "log_min_messages", sink: "log", stmt: "select 1 as %s", setup: []string{"alter role supabase_admin set log_min_messages = debug5"}},
	{param: "log_min_error_statement", sink: "log", stmt: "select 1 / 0 as %s",
		setup: []string{"alter role supabase_admin set log_min_error_statement = debug5"}},
	{param: "debug_print_parse", sink: "log", stmt: "select 1 as %s", setup: []string{"alter role supabase_admin set debug_print_parse = on"}},
	{param: "debug_print_rewritten", sink: "log", stmt: "select 1 as %s", setup: []string{"alter role supabase_admin set debug_print_rewritten = on"}},
	{param: "debug_print_plan", sink: "log", stmt: "select 1 as %s", setup: []string{"alter role supabase_admin set debug_print_plan = on"}},
	{param: "track_activities", sink: "activity", stmt: "select pg_catalog.pg_sleep(1.5), 1 as %s",
		setup: []string{"alter role supabase_admin set track_activities = on"}},
	{param: "pgaudit.log", sink: "log", stmt: "select 1 as %s", setup: []string{"alter role supabase_admin set pgaudit.log = 'all'"}},
	{param: "pgaudit.role", sink: "log", stmt: "select 1 as %s from public.x_audited",
		setup: []string{"create role x_auditor", "create table public.x_audited(i int)", "grant select on public.x_audited to x_auditor",
			"alter role supabase_admin set pgaudit.role = 'x_auditor'"},
		undo: []string{"drop table public.x_audited", "drop role x_auditor"}},
	{param: "auto_explain.log_min_duration", sink: "log", stmt: "select 1 as %s",
		setup: []string{"alter role supabase_admin set auto_explain.log_min_duration = 0"}},
	{param: "pg_stat_statements.track", sink: "stats", stmt: "select 1 as %s",
		setup: []string{"alter role supabase_admin set pg_stat_statements.track = 'all'"}},
	// Under track=none nothing is kept, utility statements included: the
	// utility setting is shown with the statement setting left out of both.
	{param: "pg_stat_statements.track_utility", also: []string{"pg_stat_statements.track"}, sink: "stats", stmt: "listen %s",
		setup: []string{"alter role supabase_admin set pg_stat_statements.track_utility = on"}},
}

// leaked runs stmt with the marker in session conn and reports what it left.
func (c *pgc) leaked(adm, conn *pgx.Conn, lc leakCase, marker string) (n int, detail string) {
	c.t.Helper()
	c.exec(adm, "select extensions.pg_stat_statements_reset()")
	from := c.logLines()
	var stop func() int
	if lc.sink == "activity" {
		stop = c.watchActivity(marker)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	var answer string
	rows, err := conn.Query(ctx, fmt.Sprintf(lc.stmt, marker))
	if err == nil {
		if rows.Next() {
			if v, verr := rows.Values(); verr == nil && len(v) > 0 {
				answer = fmt.Sprint(v[len(v)-1])
			}
		}
		rows.Close()
		err = rows.Err()
	}
	cancel()
	if err != nil && !strings.Contains(lc.stmt, "1 / 0") {
		c.t.Fatalf("%s: statement: %v", lc.param, pgsock.Clean(err))
	}
	switch lc.sink {
	case "log", "duration":
		// The session wrote its lines before its answer; Docker's log reader
		// lags, so read up to a fence line the platform session writes next.
		fence := "x-fence " + marker + "f"
		c.exec(adm, "do $$ begin raise warning '"+fence+"'; end $$")
		lines := c.waitLog(from, fence)
		for _, l := range lines {
			if strings.Contains(l, "x-fence") {
				continue
			}
			if strings.Contains(l, marker) || (lc.sink == "duration" && strings.Contains(l, "duration:")) {
				n++
				detail = l
			}
		}
	case "stats":
		n = c.statsRows(adm, marker)
	case "activity":
		n = stop()
	case "loaded":
		n, _ = strconv.Atoi(answer)
	}
	return n, detail
}

// waitLog returns the log lines after from up to the fence line, waiting
// for the fence (Docker's log reader lags the server's write).
func (c *pgc) waitLog(from int, fence string) []string {
	c.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		lines := c.logSince(from)
		if i := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, fence) }); i >= 0 {
			return lines[:i+1]
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("fence %q not in the log", fence)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestDial_SessionStatementsNotLoggedNorKept_OneSettingAtATime: each hostile
// setting on the platform's login role alone, then all of them at once with
// their database-level and system-level forms: a platform session leaves
// nothing of its statements in the server log, the statement statistics or
// the activity view. Control for each: the same session without that one
// parameter shows it.
func TestDial_SessionStatementsNotLoggedNorKept_OneSettingAtATime(t *testing.T) {
	c := newPG(t)
	adm := c.platform()
	saved := c.roleSettings(adm)
	covered := map[string]bool{"plan_filter.statement_cost_limit": true} // its own test
	for _, lc := range leakCases {
		covered[lc.param] = true
		for _, s := range lc.setup {
			c.exec(adm, s)
		}
		var with *pgx.Conn
		var err error
		if len(lc.also) == 0 {
			with = c.platform()
		} else if with, err = c.raw("supabase_admin", without(lc.also...)); err != nil {
			t.Fatalf("%s: session: %v", lc.param, err)
		}
		marker := "mk_" + rndHex(8)
		if n, d := c.leaked(adm, with, lc, marker); n != 0 {
			t.Errorf("%s: the platform session left %d trace(s) (%s): %.200s", lc.param, n, lc.sink, d)
		}
		with.Close(context.Background())
		ctl, err := c.raw("supabase_admin", without(append(slices.Clone(lc.also), lc.param)...))
		if err != nil {
			t.Fatalf("%s: control session: %v", lc.param, err)
		}
		marker = "mk_" + rndHex(8)
		if n, _ := c.leaked(adm, ctl, lc, marker); n == 0 {
			t.Errorf("%s: control: without the parameter nothing showed (%s)", lc.param, lc.sink)
		}
		ctl.Close(context.Background())
		for _, s := range lc.undo {
			c.exec(adm, s)
		}
		c.restoreRole(adm, saved)
	}
	for k := range pgsock.StartupParams(true) {
		if _, common := pgsock.StartupParams(false)[k]; !common && !covered[k] {
			t.Errorf("superuser parameter %s has no case", k)
		}
	}

	// All at once: the role's, the database's and the system file's forms.
	var role []string
	for _, lc := range leakCases {
		for _, s := range lc.setup {
			if strings.HasPrefix(s, "alter role supabase_admin set ") {
				role = append(role, strings.TrimPrefix(s, "alter role supabase_admin set "))
			} else {
				c.exec(adm, s)
			}
		}
	}
	for _, kv := range role {
		c.exec(adm, "alter role supabase_admin set "+kv)
		c.exec(adm, "alter database postgres set "+kv)
		if !strings.HasPrefix(kv, "log_min_messages") {
			c.exec(adm, "alter system set "+kv)
		}
	}
	c.exec(adm, "alter role supabase_admin set plan_filter.statement_cost_limit = 0.001")
	c.exec(adm, "alter database postgres set plan_filter.statement_cost_limit = 0.001")
	c.exec(adm, "alter system set log_min_messages = debug1")
	c.exec(adm, "select pg_catalog.pg_reload_conf()")
	t.Cleanup(func() {
		ctx := context.Background()
		for _, s := range []string{"alter system reset all", "select pg_catalog.pg_reload_conf()"} {
			adm.Exec(ctx, s)
		}
	})
	for _, lc := range leakCases {
		conn := c.platform()
		marker := "mk_" + rndHex(8)
		if n, d := c.leaked(adm, conn, lc, marker); n != 0 {
			t.Errorf("all settings, %s statement: %d trace(s) (%s): %.200s", lc.param, n, lc.sink, d)
		}
		conn.Close(context.Background())
	}
	// Control: a session without the logging parameters is logged.
	m := pgsock.StartupParams(false)
	m["plan_filter.statement_cost_limit"], m["event_triggers"] = "0", "off"
	ctl, err := c.raw("supabase_admin", m)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := c.leaked(adm, ctl, leakCases[2], "mk_"+rndHex(8)); n == 0 {
		t.Error("control: a session without the list was not logged")
	}
}

// TestDial_CostLimitOnTheLoginRoleDoesNotStopTheSession: a statement cost
// limit set on the login role refuses every planned statement of a session
// without the parameter (control), not of the platform's.
func TestDial_CostLimitOnTheLoginRoleDoesNotStopTheSession(t *testing.T) {
	c := newPG(t)
	adm := c.platform()
	c.exec(adm, "alter role supabase_admin set plan_filter.statement_cost_limit = 0.001")
	conn := c.platform()
	if n := c.str(conn, "select count(*)::text from pg_catalog.pg_class"); n == "0" {
		t.Fatal("no rows")
	}
	ctl, err := c.raw("supabase_admin", without("plan_filter.statement_cost_limit"))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	err = ctl.QueryRow(context.Background(), "select count(*)::int from pg_catalog.pg_class").Scan(&n)
	var se *pgsock.ServerError
	if !errors.As(pgsock.Clean(err), &se) || se.Code != "54001" {
		t.Fatalf("control: %v", err)
	}
}

// settingsInForce is name → (setting, source) of the names in a session.
func (c *pgc) settingsInForce(conn *pgx.Conn, names []string) map[string][2]string {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rows, err := conn.Query(ctx, "select name, setting, source from pg_catalog.pg_settings where name = any($1)", names)
	if err != nil {
		c.t.Fatal(pgsock.Clean(err))
	}
	got := map[string][2]string{}
	for rows.Next() {
		var n, s, src string
		if err := rows.Scan(&n, &s, &src); err != nil {
			c.t.Fatal(pgsock.Clean(err))
		}
		got[n] = [2]string{s, src}
	}
	if err := rows.Err(); err != nil {
		c.t.Fatal(pgsock.Clean(err))
	}
	return got
}

// TestDial_ParamsAcceptedInEveryStartKind: the image's first boot, a normal
// start and a recovery start accept the nineteen, each in force as sent.
func TestDial_ParamsAcceptedInEveryStartKind(t *testing.T) {
	c := newPG(t)
	want := pgsock.StartupParams(true)
	for k := range pgsock.StartupParams(false) {
		delete(want, k)
	}
	names := slices.Sorted(maps.Keys(want))
	check := func(kind string) {
		got := c.settingsInForce(c.platform(), names)
		for _, n := range names {
			if g := got[n]; g != [2]string{want[n], "client"} {
				t.Errorf("%s: %s = %q (source %q), want %q from the client", kind, n, g[0], g[1], want[n])
			}
		}
	}
	check("first boot")
	if out, err := exec.Command("docker", "restart", "-t", "30", c.name).CombinedOutput(); err != nil {
		t.Fatalf("restart: %v %s", err, out)
	}
	c.ready()
	check("normal start")
	if out, err := exec.Command("docker", "exec", "-u", "postgres", c.name, "touch", "/var/lib/postgresql/data/recovery.signal").CombinedOutput(); err != nil {
		t.Fatalf("recovery.signal: %v %s", err, out)
	}
	if out, err := exec.Command("docker", "stop", "-t", "30", c.name).CombinedOutput(); err != nil {
		t.Fatalf("stop: %v %s", err, out)
	}
	rec, err := pgconf.RecoveryPins(pgconf.RecoveryTarget{Timeline: "latest"})
	if err != nil {
		t.Fatal(err)
	}
	c.run(slices.Concat([]string{"--", "postgres", "-D", "/etc/postgresql", "-c", "restore_command=/bin/false"},
		pgconf.RecoveryExtensionPins(), rec)...)
	if log := strings.Join(c.logSince(0), "\n"); !strings.Contains(log, "starting archive recovery") {
		t.Fatalf("not a recovery start:\n%s", log)
	}
	check("recovery start")
	ext := c.settingsInForce(c.platform(), []string{"pgtle.enable_clientauth", "pgtle.enable_password_check", "cron.launch_active_jobs"})
	for n, g := range ext {
		if g != [2]string{"off", "command line"} {
			t.Errorf("recovery start: %s = %v", n, g)
		}
	}
	if len(ext) != 3 {
		t.Errorf("extension pins %v", ext)
	}
}

// TestDial_FirstBootStatementsAreNotKeptInTheStatistics: a cluster whose
// first boot ran with the list keeps no statement that sets a role's
// password in the statement statistics, as the project's own postgres role
// reads them. Control: the same first boot in a session without the
// superuser parameters keeps them.
func TestDial_FirstBootStatementsAreNotKeptInTheStatistics(t *testing.T) {
	for _, super := range []bool{true, false} {
		t.Run(fmt.Sprintf("superuser=%v", super), func(t *testing.T) {
			c := newPG(t)
			dek := []byte(rndHex(32))
			s := bootstrap.Secrets{SupabaseAdminPassword: rndHex(32), PostgresPassword: rndHex(32), AuthenticatorPassword: rndHex(32),
				PgsodiumRootKey: rndHex(32), ScramSalts: map[string][]byte{}}
			for _, r := range []string{"supabase_admin", "postgres", "authenticator"} {
				var err error
				if s.ScramSalts[r], err = pgsock.ScramSalt(dek, c.ref, r); err != nil {
					t.Fatal(err)
				}
			}
			conn, err := pgsock.Dial(context.Background(), c.target(super))
			if err != nil {
				t.Fatal(err)
			}
			if err := bootstrap.Run(context.Background(), conn, s); err != nil {
				t.Fatalf("first boot: %v", err)
			}
			conn.Close(context.Background())
			pg, err := c.raw("postgres", nil)
			if err != nil {
				t.Fatal(err)
			}
			n := c.str(pg, "select count(*)::text from extensions.pg_stat_statements where query ~* 'password|SCRAM-SHA-256'")
			if super && n != "0" {
				t.Fatalf("%s password statements kept", n)
			}
			if !super && n == "0" {
				t.Fatal("control: nothing kept without the superuser parameters")
			}
		})
	}
}

// TestDial_NonSuperuserSessionRefusedWithASuperuserParameter: a login of a
// role that is not a superuser fails with the superuser list and succeeds
// with the common one; each parameter the server reserves to superusers
// refuses the session alone.
func TestDial_NonSuperuserSessionRefusedWithASuperuserParameter(t *testing.T) {
	c := newPG(t)
	tg := c.target(true)
	tg.User = "postgres"
	_, err := pgsock.Dial(context.Background(), tg)
	var se *pgsock.ServerError
	if !errors.As(err, &se) || se.Code != "42501" {
		t.Fatalf("superuser list as postgres: %v", err)
	}
	tg.Superuser = false
	conn, err := pgsock.Dial(context.Background(), tg)
	if err != nil {
		t.Fatalf("control: common list as postgres: %v", err)
	}
	conn.Close(context.Background())
	adm := c.platform()
	refused := 0
	var accepted []string
	for k, v := range pgsock.StartupParams(true) {
		if _, common := pgsock.StartupParams(false)[k]; common {
			continue
		}
		ctx := c.str(adm, "select context from pg_catalog.pg_settings where name = $1", k)
		m := pgsock.StartupParams(false)
		m[k] = v
		_, err := c.raw("postgres", m)
		switch {
		case ctx == "user" && err != nil:
			t.Errorf("%s (context user) refused: %v", k, err)
		case ctx != "user" && err == nil:
			t.Errorf("%s (context %s) accepted from a non-superuser", k, ctx)
		case err != nil:
			refused++
		default:
			accepted = append(accepted, k)
		}
	}
	slices.Sort(accepted)
	if refused != 16 || !slices.Equal(accepted, []string{"debug_print_parse", "debug_print_plan", "debug_print_rewritten"}) {
		t.Fatalf("%d refused; accepted from a non-superuser: %v", refused, accepted)
	}
}
