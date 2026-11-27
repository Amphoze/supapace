package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgconn/ctxwatch"
	"github.com/jackc/pgx/v5/pgproto3"
)

const roRole = "supabase_read_only_user"

// ───────── on the pinned image ─────────

// cronCluster is startCluster with the scheduler's extension created by the
// project's owner, and a session as supabase_admin.
func cronCluster(t *testing.T) (*cluster, *pgx.Conn) {
	t.Helper()
	c := startCluster(t)
	c.exec(c.dial("postgres"), "create extension pg_cron")
	return c, c.dial("supabase_admin")
}

// withReadOnly gives the cluster's secrets a read-only password and its salt.
func (c *cluster) withReadOnly() {
	c.t.Helper()
	salt, err := pgsock.ScramSalt([]byte(rnd(32)), c.ref, roRole)
	if err != nil {
		c.t.Fatal(err)
	}
	c.secrets.ReadOnlyPassword = rnd(32)
	c.secrets.ScramSalts[roRole] = salt
}

// psqlAs runs sql as user over TCP inside the container (trust on loopback
// before the platform's access file is in force). The role's sessions default
// to read-only; that default is not a barrier, and these tests use a writing
// session of the role to plant rows.
func (c *cluster) psqlAs(user, sql string) (string, error) {
	out, err := exec.Command("docker", "exec", "-e", "PGOPTIONS=-c default_transaction_read_only=off", c.name, "psql", "-XAtq",
		"-v", "ON_ERROR_STOP=1", "host=127.0.0.1 port=5432 dbname=postgres sslmode=disable user="+user, "-c", sql).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (c *cluster) mustAs(user, sql string) string {
	c.t.Helper()
	out, err := c.psqlAs(user, sql)
	if err != nil {
		c.t.Fatalf("as %s: %s: %v: %s", user, sql, err, out)
	}
	return out
}

// loopAs keeps a session of user open in the container: each runs sql and
// the next connects 50 ms after the last ended. It returns a function that
// stops the loop and returns how many of its sessions were terminated.
func (c *cluster) loopAs(user, sql string) func() int {
	c.t.Helper()
	cmd := exec.Command("docker", "exec", c.name, "sh", "-c", "while [ ! -e /tmp/stop-loop ]; do psql -XAtq "+
		"'host=127.0.0.1 port=5432 dbname=postgres sslmode=disable user="+user+"' -c \""+sql+"\" 2>&1; sleep 0.05; done")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		c.t.Fatal(err)
	}
	var once sync.Once
	n := 0
	stop := func() int {
		once.Do(func() {
			exec.Command("docker", "exec", c.name, "touch", "/tmp/stop-loop").Run()
			c.exec(c.dial("supabase_admin"), "select pg_catalog.pg_terminate_backend(pid) from pg_catalog.pg_stat_activity where usename = $1", user)
			cmd.Wait()
			exec.Command("docker", "exec", c.name, "rm", "-f", "/tmp/stop-loop").Run()
			n = strings.Count(out.String(), "terminating connection due to administrator command")
		})
		return n
	}
	c.t.Cleanup(func() { stop() })
	return stop
}

// roBackend is a row of pg_stat_activity of the read-only role.
type roBackend struct {
	pid                    int
	typ, app, state, query string
}

func (c *cluster) roleBackends(conn *pgx.Conn) []roBackend {
	c.t.Helper()
	ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
	defer cancel()
	rows, err := conn.Query(ctx, `select pid, coalesce(backend_type, ''), coalesce(application_name, ''), coalesce(state, ''),
	  coalesce(left(query, 80), '') from pg_catalog.pg_stat_activity where usename = $1 order by pid`, roRole)
	if err != nil {
		c.t.Fatal(pgsock.Clean(err))
	}
	var out []roBackend
	for rows.Next() {
		var b roBackend
		if err := rows.Scan(&b.pid, &b.typ, &b.app, &b.state, &b.query); err != nil {
			c.t.Fatal(err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		c.t.Fatal(pgsock.Clean(err))
	}
	return out
}

// workers are the role's backends that are not client sessions.
func (c *cluster) workers(conn *pgx.Conn) []roBackend {
	return slices.DeleteFunc(c.roleBackends(conn), func(b roBackend) bool { return b.typ == "client backend" })
}

// waitWorkers waits up to d for at least n workers of the role and returns them.
func (c *cluster) waitWorkers(conn *pgx.Conn, n int, d time.Duration) []roBackend {
	c.t.Helper()
	for deadline := time.Now().Add(d); ; time.Sleep(50 * time.Millisecond) {
		if w := c.workers(conn); len(w) >= n {
			return w
		}
		if time.Now().After(deadline) {
			// Show what runs instead: the columns a fallback would select by.
			ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
			rows, _ := conn.Query(ctx, `select pid::text || ' ' || coalesce(usename::text, '-') || ' ' || coalesce(backend_type, '-') || ' ' ||
			  coalesce(left(query, 60), '-') from pg_catalog.pg_stat_activity where backend_type <> 'client backend'`)
			for rows != nil && rows.Next() {
				var s string
				rows.Scan(&s)
				c.t.Logf("not a client session: %s", s)
			}
			cancel()
			c.t.Fatalf("fewer than %d workers of the role within %s", n, d)
		}
	}
}

func pids(bs []roBackend) []int {
	var out []int
	for _, b := range bs {
		out = append(out, b.pid)
	}
	return out
}

func (c *cluster) endRole(conn *pgx.Conn) {
	c.t.Helper()
	c.exec(conn, "select pg_catalog.pg_terminate_backend(pid) from pg_catalog.pg_stat_activity where usename = $1", roRole)
}

// launched polls the role's workers for d and returns those not in old.
func (c *cluster) launched(conn *pgx.Conn, old []int, d time.Duration) []int {
	c.t.Helper()
	var seen []int
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		for _, p := range pids(c.workers(conn)) {
			if !slices.Contains(old, p) && !slices.Contains(seen, p) {
				seen = append(seen, p)
			}
		}
	}
	return seen
}

// count is a count(*) as an int.
func (c *cluster) count(conn *pgx.Conn, sql string, args ...any) int {
	c.t.Helper()
	n, err := strconv.Atoi(c.str(conn, sql, args...))
	if err != nil {
		c.t.Fatal(err)
	}
	return n
}

// jobsSession is the clean-up's session: the superuser list with the
// clean-up's lock and statement timeouts, triggers on. It counts the passes
// it sends (the times they were written) through a reader of the client's
// messages.
func (c *cluster) jobsSession() (*pgx.Conn, func() []time.Time) {
	c.t.Helper()
	dir, err := os.MkdirTemp("", "sp")
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	if err := os.Symlink(filepath.Join(c.root, c.ref, "sock"), sock); err != nil {
		c.t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig("host=" + sock + " user=supabase_admin dbname=postgres sslmode=disable")
	if err != nil {
		c.t.Fatal(err)
	}
	for k, v := range pgsock.StartupParams(true) {
		cfg.RuntimeParams[k] = v
	}
	cfg.RuntimeParams["lock_timeout"], cfg.RuntimeParams["statement_timeout"] = "2000ms", "10000ms"
	cfg.BuildContextWatcherHandler = func(pc *pgconn.PgConn) ctxwatch.Handler {
		return &pgconn.DeadlineContextWatcherHandler{Conn: pc.Conn()}
	}
	pc := &passCounter{}
	cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		nc, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		pc.Conn = nc
		return pc, nil
	}
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { conn.Close(context.Background()) })
	return conn, pc.passes
}

// passCounter reads the client's messages after the startup and records when
// each pass of the clean-up was written.
type passCounter struct {
	net.Conn
	mu      sync.Mutex
	buf     []byte
	started bool
	at      []time.Time
}

func (p *passCounter) Write(b []byte) (int, error) {
	p.mu.Lock()
	p.buf = append(p.buf, b...)
	for {
		if !p.started {
			if len(p.buf) < 4 {
				break
			}
			n := int(binary.BigEndian.Uint32(p.buf))
			if len(p.buf) < n {
				break
			}
			p.buf, p.started = p.buf[n:], true
			continue
		}
		if len(p.buf) < 5 {
			break
		}
		n := int(binary.BigEndian.Uint32(p.buf[1:]))
		if len(p.buf) < 1+n {
			break
		}
		if p.buf[0] == 'Q' && strings.HasPrefix(string(p.buf[5:1+n]), sqlReadOnlyJobsPass) {
			p.at = append(p.at, time.Now())
		}
		p.buf = p.buf[1+n:]
	}
	p.mu.Unlock()
	return p.Conn.Write(b)
}

func (p *passCounter) passes() []time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.at)
}

// startTime is the postmaster's start time and the container's process: the
// same before and after means the cluster was not restarted.
func (c *cluster) startTime(conn *pgx.Conn) string {
	return c.str(conn, "select pg_catalog.pg_postmaster_start_time()::text") + " " + strconv.Itoa(c.pid)
}

// TestReadOnlyJobs_RunningJobIsListedUnderItsRoleAndEnded: on the pinned
// image with the platform's configuration (jobs in background workers), a
// running job of the read-only role is listed under that role and is not a
// client session; ending it ends it; once its row is deleted (triggers on)
// the scheduler starts it no more. Recorded: whether the scheduler launches a
// worker while the table is locked, and between a pass's second ending and
// its commit. Asserted: with more runs waiting than slots, ending the running
// ones is followed by a launch within two seconds, and with none waiting by
// none. Then the clean-up on those jobs, and no restart of the cluster.
func TestReadOnlyJobs_RunningJobIsListedUnderItsRoleAndEnded(t *testing.T) {
	c, adm := cronCluster(t)
	obs := c.dial("supabase_admin")
	before := c.startTime(adm)
	t.Logf("scheduler: cron.use_background_workers=%s cron.max_running_jobs=%s max_prepared_transactions=%s",
		c.str(adm, "show cron.use_background_workers"), c.str(adm, "show cron.max_running_jobs"), c.str(adm, "show max_prepared_transactions"))

	// A running job is listed under its role, and is not a client session.
	c.mustAs(roRole, "select cron.schedule('ro-listed', '1 second', 'select pg_catalog.pg_sleep(5)')")
	w := c.waitWorkers(obs, 1, 20*time.Second)
	for _, b := range c.roleBackends(obs) {
		t.Logf("listed: pid=%d usename=%s backend_type=%q application_name=%q state=%q query=%q", b.pid, roRole, b.typ, b.app, b.state, b.query)
	}
	if w[0].typ == "client backend" {
		t.Fatal("a scheduled job's worker reports itself as a client session: the stop rule would not count it")
	}
	// Ending it ends it.
	c.endRole(adm)
	for deadline := time.Now().Add(5 * time.Second); slices.Contains(pids(c.workers(obs)), w[0].pid); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("worker %d still listed after it was ended", w[0].pid)
		}
	}
	// Its row deleted, triggers on: the scheduler starts it no more.
	c.exec(adm, "delete from cron.job where jobname = 'ro-listed'")
	c.endRole(adm)
	if l := c.launched(obs, nil, 5*time.Second); len(l) != 0 {
		t.Fatalf("after the delete the job still runs: workers %v", l)
	}

	// Recorded, not asserted: launches in the pass's two windows.
	c.mustAs(roRole, "select cron.schedule('ro-window', '1 second', 'select pg_catalog.pg_sleep(5)')")
	old := pids(c.waitWorkers(obs, 1, 20*time.Second))
	c.exec(adm, "begin")
	c.exec(adm, sqlLockJobs)
	c.endRole(adm)
	inLock := c.launched(obs, old, 3*time.Second)
	c.exec(adm, "rollback")
	t.Logf("recorded: workers launched while the table was locked: %d", len(inLock))
	old = pids(c.waitWorkers(obs, 1, 20*time.Second))
	c.exec(adm, "begin")
	c.endRole(adm)
	c.exec(adm, sqlLockJobs)
	c.exec(adm, "delete from cron.job where jobname = 'ro-window'")
	c.endRole(adm)
	beforeCommit := c.launched(obs, old, 3*time.Second)
	c.exec(adm, "commit")
	c.endRole(adm)
	t.Logf("recorded: workers launched between the second ending and the commit: %d", len(beforeCommit))

	// The fourth fact. Control: two running jobs, none waiting (inactive):
	// ending them launches nothing.
	for i := range 2 {
		c.mustAs(roRole, fmt.Sprintf("select cron.schedule('ro-busy-%d', '1 second', 'select pg_catalog.pg_sleep(30)')", i))
	}
	busy := c.waitWorkers(obs, 2, 20*time.Second)
	c.exec(adm, "update cron.job set active = false where username = $1", roRole)
	c.endRole(adm)
	if l := c.launched(obs, pids(busy), 3*time.Second); len(l) != 0 {
		t.Fatalf("control: with no run waiting, %d workers were launched", len(l))
	}
	c.exec(adm, "delete from cron.job where username = $1", roRole)
	// Twenty per-second jobs of five seconds each, more than the slots: the
	// ending of the running ones is followed by a launch of waiting ones.
	var q strings.Builder
	for i := range 20 {
		fmt.Fprintf(&q, "select cron.schedule('ro-wait-%d', '1 second', 'select pg_catalog.pg_sleep(5)');", i)
	}
	c.mustAs(roRole, q.String())
	running := pids(c.waitWorkers(obs, 2, 20*time.Second))
	time.Sleep(time.Second) // runs are waiting for a slot by now
	running = append(running, pids(c.workers(obs))...)
	c.endRole(adm)
	t0 := time.Now()
	var first time.Duration
	for deadline := t0.Add(10 * time.Second); first == 0 && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, p := range pids(c.workers(obs)) {
			if !slices.Contains(running, p) {
				first = time.Since(t0)
			}
		}
	}
	t.Logf("fourth fact: a waiting run was launched %v after the running ones were ended", first.Round(time.Millisecond))
	switch {
	case first == 0:
		t.Fatal("no launch followed the ending within 10 s")
	case first > 2*time.Second:
		t.Fatalf("the launch followed after %v, later than the two seconds the stop rule's 3 s rests on", first)
	}

	// The clean-up on the same jobs: a worker is ended, so it ends on a pass
	// at least 3 s later; ten seconds after it nothing of the role remains.
	js, passes := c.jobsSession()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	t1 := time.Now()
	if err := DeleteReadOnlyJobs(ctx, js); err != nil {
		t.Fatalf("clean-up: %v", err)
	}
	took := time.Since(t1)
	ps := passes()
	t.Logf("clean-up: %d passes in %v", len(ps), took.Round(time.Millisecond))
	if took < 3*time.Second || len(ps) < 2 {
		t.Fatalf("the clean-up ended after %v and %d passes: it ended a worker, so it ends on a pass 3 s later at the soonest", took, len(ps))
	}
	time.Sleep(10 * time.Second)
	if n := c.count(adm, "select count(*)::text from cron.job where username = $1", roRole); n != 0 {
		t.Fatalf("%d rows of the role left", n)
	}
	if w := c.workers(obs); len(w) != 0 {
		t.Fatalf("workers of the role ten seconds later: %+v", w)
	}
	if after := c.startTime(adm); after != before {
		t.Fatalf("the cluster was restarted: %s, before %s", after, before)
	}
}

// lockHolder is a job command that holds a lock on the job table that the
// pass's lock waits for, for a minute, in an open transaction.
const lockHolder = "set transaction read write; select cron.schedule('ro-inner', '59 seconds', 'select 1'); select pg_catalog.pg_sleep(60)"

// waitLockHeld waits until a worker of the role holds a granted lock on the table.
func (c *cluster) waitLockHeld(conn *pgx.Conn) {
	c.t.Helper()
	const held = `select count(*)::text from pg_catalog.pg_locks l join pg_catalog.pg_stat_activity a on a.pid = l.pid
	  where l.relation = 'cron.job'::regclass and l.granted and a.usename = $1 and a.backend_type <> 'client backend'`
	for deadline := time.Now().Add(20 * time.Second); c.count(conn, held, roRole) == 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			c.t.Fatal("no job of the role holds the table's lock")
		}
	}
}

// TestReadOnlyJobs_LockHeldByTheRolesOwnJob_CleanUpCompletes: a scheduled
// job of the read-only role holds the table's lock in an open transaction;
// the clean-up completes, the job and its row are gone and do not come back
// ten seconds later. Control: the same run with the pass's first ending left
// out fails at its deadline.
func TestReadOnlyJobs_LockHeldByTheRolesOwnJob_CleanUpCompletes(t *testing.T) {
	c, adm := cronCluster(t)
	c.mustAs(roRole, "select cron.schedule('ro-holder', '1 second', $c$"+lockHolder+"$c$)")
	c.waitLockHeld(adm)

	// Control: without the first ending the lock is never granted.
	const noFirstEnding = sqlBegin + ";\n" + sqlLockJobs + ";\n" + sqlDeleteReadOnlyJobs + ";\n" + sqlEndReadOnly + ";\n" + sqlCommit
	js, _ := c.jobsSession()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	var cerr error
	for ctx.Err() == nil {
		if _, cerr = js.Exec(ctx, noFirstEnding); cerr == nil {
			break
		}
		js.Exec(ctx, sqlRollback)
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	if cerr == nil || ctx.Err() == nil {
		t.Fatalf("control: without the first ending the run did not fail at its deadline: %v", cerr)
	}
	t.Logf("control: %v", pgsock.Clean(cerr))

	js, passes := c.jobsSession()
	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := DeleteReadOnlyJobs(ctx, js); err != nil {
		t.Fatalf("clean-up: %v", err)
	}
	t.Logf("clean-up: %d passes", len(passes()))
	time.Sleep(10 * time.Second)
	if n := c.count(adm, "select count(*)::text from cron.job where username = $1", roRole); n != 0 {
		t.Fatalf("%d rows of the role left", n)
	}
	if w := c.workers(adm); len(w) != 0 {
		t.Fatalf("workers of the role ten seconds later: %+v", w)
	}
}

// TestReadOnlyJobs_ActiveReadOnlySessionsDoNotPreventCompletion: a remaining
// member's session reconnects every 50 ms throughout; the clean-up completes
// in one or two passes and ends those sessions; no pass ended a worker, so
// the 3 s of the stop rule do not arise.
func TestReadOnlyJobs_ActiveReadOnlySessionsDoNotPreventCompletion(t *testing.T) {
	c, adm := cronCluster(t)
	stop := c.loopAs(roRole, "select pg_catalog.pg_sleep(30)")
	for deadline := time.Now().Add(10 * time.Second); len(c.roleBackends(adm)) == 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no session of the role")
		}
	}
	js, passes := c.jobsSession()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	t0 := time.Now()
	if err := DeleteReadOnlyJobs(ctx, js); err != nil {
		t.Fatalf("clean-up: %v", err)
	}
	took, n := time.Since(t0), len(passes())
	ended := stop()
	t.Logf("clean-up: %d passes in %v; %d sessions of the role ended", n, took.Round(time.Millisecond), ended)
	if n < 1 || n > 2 || took >= 3*time.Second {
		t.Fatalf("%d passes in %v", n, took)
	}
	if ended < 1 {
		t.Fatal("the role's session was not ended")
	}
}

// selfScheduling is a job command that, after a short sleep, schedules
// itself again under name: format(t, t) with t its own text.
func selfScheduling(name string) string {
	tmpl := "set transaction read write; select pg_catalog.pg_sleep(0.2); select cron.schedule('" + name +
		"', '1 second', pg_catalog.format(t, t)) from (select %L::text as t) s"
	return strings.Replace(tmpl, "%L", "'"+strings.ReplaceAll(tmpl, "'", "''")+"'", 1)
}

// TestReadOnlyJobs_SelfReschedulingJobDoesNotSurvive: fifty per-second jobs
// of the read-only role whose command schedules itself again after a short
// sleep: after one clean-up no row and no worker of the role remain ten
// seconds later. Control: the same jobs under the owner's name all remain.
func TestReadOnlyJobs_SelfReschedulingJobDoesNotSurvive(t *testing.T) {
	c, adm := cronCluster(t)
	var ro, own strings.Builder
	for i := range 50 {
		fmt.Fprintf(&ro, "select cron.schedule('ro-self-%d', '1 second', $c$%s$c$);", i, selfScheduling(fmt.Sprintf("ro-self-%d", i)))
		fmt.Fprintf(&own, "select cron.schedule('own-self-%d', '1 second', $c$%s$c$);", i, selfScheduling(fmt.Sprintf("own-self-%d", i)))
	}
	c.mustAs(roRole, ro.String())
	c.mustAs("postgres", own.String())
	c.waitWorkers(adm, 1, 20*time.Second)
	time.Sleep(3 * time.Second) // the jobs have rescheduled themselves by now
	const rescheduled = `select count(*)::text from cron.job_run_details d join cron.job j using (jobid)
	  where j.username = $1 and d.status = 'succeeded'`
	if c.count(adm, rescheduled, roRole) == 0 {
		t.Log(c.str(adm, "select coalesce(string_agg(status || ' ' || left(return_message, 160), E'\n'), '-') from (select * from cron.job_run_details order by runid desc limit 4) d"))
		t.Fatal("control: no job of the role ran to its end")
	}
	js, passes := c.jobsSession()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	t0 := time.Now()
	if err := DeleteReadOnlyJobs(ctx, js); err != nil {
		t.Fatalf("clean-up: %v", err)
	}
	t.Logf("clean-up: %d passes in %v", len(passes()), time.Since(t0).Round(time.Millisecond))
	time.Sleep(10 * time.Second)
	if n := c.count(adm, "select count(*)::text from cron.job where username = $1", roRole); n != 0 {
		t.Fatalf("%d rows of the role ten seconds later", n)
	}
	if w := c.workers(adm); len(w) != 0 {
		t.Fatalf("workers of the role ten seconds later: %+v", w)
	}
	if n := c.count(adm, "select count(*)::text from cron.job where username = 'postgres' and jobname like 'own-self-%'"); n != 50 {
		t.Fatalf("control: %d of the owner's 50 jobs remain", n)
	}
}

// TestDeleteReadOnlyJobs_ThatRolesRowsOnly: a job row under the read-only
// role's name is gone and a session of that role ended; a row under the
// owner's name stays and the owner's session lives.
func TestDeleteReadOnlyJobs_ThatRolesRowsOnly(t *testing.T) {
	c, adm := cronCluster(t)
	c.mustAs(roRole, "select cron.schedule('ro-row', '59 seconds', 'select 1')")
	c.mustAs("postgres", "select cron.schedule('own-row', '59 seconds', 'select 1')")
	own := c.dial("postgres")
	stop := c.loopAs(roRole, "select pg_catalog.pg_sleep(30)")
	for deadline := time.Now().Add(10 * time.Second); len(c.roleBackends(adm)) == 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no session of the role")
		}
	}
	js, _ := c.jobsSession()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := DeleteReadOnlyJobs(ctx, js); err != nil {
		t.Fatalf("clean-up: %v", err)
	}
	if n := stop(); n < 1 {
		t.Fatal("the role's session was not ended")
	}
	if got := c.str(adm, "select coalesce(string_agg(jobname || ' ' || username, ',' order by jobname), '') from cron.job"); got != "own-row postgres" {
		t.Fatalf("rows left: %q", got)
	}
	if got := c.str(own, "select current_user::text"); got != "postgres" {
		t.Fatalf("the owner's session: %q", got)
	}
}

// TestReadOnlyJobs_EveryRowOfTheRoleCarriesItsName: as the read-only role,
// each way the extension offers to schedule or change a job is refused or
// leaves a row under the role's own name, so a delete by that name misses
// no job of the role.
func TestReadOnlyJobs_EveryRowOfTheRoleCarriesItsName(t *testing.T) {
	c, adm := cronCluster(t)
	c.mustAs(roRole, "select cron.schedule('ro-own', '59 seconds', 'select 1')")
	for _, way := range []string{
		"select cron.schedule('59 * * * *', 'select 1')",
		"select cron.schedule('ro-named', '59 seconds', 'select 1')",
		"select cron.schedule_in_database('ro-db', '59 seconds', 'select 1', 'postgres', 'postgres', true)",
		"select cron.schedule_in_database('ro-db2', '59 seconds', 'select 1', 'postgres')",
		"select cron.alter_job((select jobid from cron.job where jobname = 'ro-own'), username := 'postgres')",
		"select cron.alter_job((select jobid from cron.job where jobname = 'ro-own'), schedule := '58 seconds')",
		"insert into cron.job (schedule, command, nodename, nodeport, database, username) values ('59 seconds', 'select 1', 'localhost', 5432, 'postgres', 'postgres')",
		"insert into cron.job (schedule, command, nodename, nodeport, database) values ('59 seconds', 'select 1', 'localhost', 5432, 'postgres')",
		"update cron.job set username = 'postgres' where jobname = 'ro-own'",
		"update cron.job set command = 'select 2' where jobname = 'ro-own'",
	} {
		out, err := c.psqlAs(roRole, way)
		t.Logf("%s → %v %s", way, err, out)
	}
	if n := c.count(adm, "select count(*)::text from cron.job where username = $1", roRole); n < 3 {
		t.Fatalf("control: %d rows of the role", n)
	}
	if got := c.str(adm, "select coalesce(string_agg(jobid::text || ' ' || username, ','), '') from cron.job where username <> $1", roRole); got != "" {
		t.Fatalf("a row of the role carries another name: %s", got)
	}
}

// TestDeleteReadOnlyJobs_NoExtension_IsNotAnError: on a cluster without the
// extension the run returns nil after one pass, and the role's sessions
// were ended by its first ending.
func TestDeleteReadOnlyJobs_NoExtension_IsNotAnError(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	stop := c.loopAs(roRole, "select pg_catalog.pg_sleep(30)")
	for deadline := time.Now().Add(10 * time.Second); len(c.roleBackends(adm)) == 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no session of the role")
		}
	}
	js, passes := c.jobsSession()
	if err := DeleteReadOnlyJobs(context.Background(), js); err != nil {
		t.Fatalf("clean-up: %v", err)
	}
	if n := len(passes()); n != 1 {
		t.Fatalf("%d passes", n)
	}
	if st := js.PgConn().TxStatus(); st != 'I' {
		t.Fatalf("the session is in transaction state %c", st)
	}
	if n := stop(); n < 1 {
		t.Fatal("the role's session was not ended")
	}
}

// TestDropReadOnlyJobs_LockedTable_BoundedError: an owner's session holds the
// table in access exclusive mode; every pass ends at the lock timeout, the
// run errors at its 15 s deadline and not later, with the reason that the
// lock was not granted; the role's sessions were ended in each pass and the
// owner's session lives.
func TestDropReadOnlyJobs_LockedTable_BoundedError(t *testing.T) {
	c, adm := cronCluster(t)
	holder := c.dial("supabase_admin")
	c.exec(holder, "begin")
	c.exec(holder, "lock table cron.job in access exclusive mode")
	stop := c.loopAs(roRole, "select pg_catalog.pg_sleep(30)")
	for deadline := time.Now().Add(10 * time.Second); len(c.roleBackends(adm)) == 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no session of the role")
		}
	}
	js, passes := c.jobsSession()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	t0 := time.Now()
	err := DeleteReadOnlyJobs(ctx, js)
	took := time.Since(t0)
	ended := stop()
	ps := passes()
	t.Logf("%v after %v and %d passes; %d sessions of the role ended", err, took.Round(time.Millisecond), len(ps), ended)
	if err == nil || !strings.Contains(err.Error(), "the lock was not granted") {
		t.Fatalf("error %v", err)
	}
	if took < 15*time.Second || took >= 16*time.Second {
		t.Fatalf("the run ended after %v", took)
	}
	for i := 1; i < len(ps); i++ {
		if d := ps[i].Sub(ps[i-1]); d < 2*time.Second {
			t.Fatalf("pass %d began %v after the one before: not at the lock timeout", i, d)
		}
	}
	if len(ps) < 6 || ended < len(ps)-1 {
		t.Fatalf("%d passes ended %d sessions of the role", len(ps), ended)
	}
	if got := c.str(holder, "select current_user::text"); got != "supabase_admin" {
		t.Fatalf("the holder's session: %q", got)
	}
}

// TestDropReadOnlyJobs_StartupParameters: the clean-up's session (the
// superuser list with the two timeouts through pgsock) has lock_timeout 2s
// and statement_timeout 10s in force and replication role origin: a trigger
// of the table fires during the delete.
func TestDropReadOnlyJobs_StartupParameters(t *testing.T) {
	c, adm := cronCluster(t)
	c.exec(adm, "create table public.t_seen (jobid bigint)")
	c.exec(adm, "create function public.t_seen() returns trigger language plpgsql as $$ begin insert into public.t_seen values (old.jobid); return old; end $$")
	c.exec(adm, "create trigger t_seen before delete on cron.job for each row execute function public.t_seen()")
	id := c.mustAs(roRole, "select cron.schedule('ro-trig', '59 seconds', 'select 1')")
	tg := c.target("supabase_admin")
	tg.LockTimeout, tg.StatementTimeout = 2*time.Second, 10*time.Second
	js, err := pgsock.Dial(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	defer js.Close(context.Background())
	if got := c.str(js, "select current_setting('lock_timeout') || ' ' || current_setting('statement_timeout') || ' ' || current_setting('session_replication_role')"); got != "2s 10s origin" {
		t.Fatalf("settings %q", got)
	}
	if err := DeleteReadOnlyJobs(context.Background(), js); err != nil {
		t.Fatal(err)
	}
	if got := c.str(adm, "select coalesce(string_agg(jobid::text, ','), '') from public.t_seen"); got != id {
		t.Fatalf("the trigger saw %q, want %q", got, id)
	}
}

// TestReadOnlyLogin_OverTCPFromTheSlice: under the platform's access file,
// the read-only login logs in with SCRAM over TCP from an address in the
// project's slice, with the platform's password, and its transactions are
// read-only by default; a wrong password is refused.
func TestReadOnlyLogin_OverTCPFromTheSlice(t *testing.T) {
	c := newCluster(t, 1)
	c.withReadOnly()
	var slice netip.Prefix
	var network string
	for try := 0; ; try++ {
		slice = nodecfg.Default("sp.test").Slice(500 + int(time.Now().UnixNano()%500))
		network = "sp-test-rologin-" + rnd(4)
		out, err := exec.Command("docker", "network", "create", "--label", "supapace.test=1", "--subnet", slice.String(), network).CombinedOutput()
		if err == nil {
			break
		}
		if try == 4 {
			t.Fatalf("network: %v %s", err, out)
		}
	}
	t.Cleanup(func() {
		exec.Command("docker", "network", "disconnect", "-f", network, c.name).Run()
		exec.Command("docker", "network", "rm", network).Run()
	})
	hba, err := pgconf.HBA(slice)
	if err != nil {
		t.Fatal(err)
	}
	c.hba = hba
	p := filepath.Join(c.render, "pg_hba.conf")
	os.Chmod(p, 0o644)
	if err := os.WriteFile(p, hba, 0o444); err != nil {
		t.Fatal(err)
	}
	c.run()
	if err := Run(context.Background(), c.dial("supabase_admin"), c.secrets); err != nil {
		t.Fatal(err)
	}
	c.phaseB()
	host := func(n byte) string { a := slice.Masked().Addr().As4(); a[3] += n; return netip.AddrFrom4(a).String() }
	srv, cli := host(2), host(4)
	exec.Command("docker", "network", "disconnect", "none", c.name).Run()
	if out, err := exec.Command("docker", "network", "connect", "--ip", srv, network, c.name).CombinedOutput(); err != nil {
		t.Fatalf("connect: %v %s", err, out)
	}
	login := func(pw string) (string, error) {
		out, err := exec.Command("docker", "run", "--rm", "--label", "supapace.test=1", "--network", network, "--ip", cli,
			"-e", "PGPASSWORD="+pw, "--entrypoint", "psql", c.image, "-XAt",
			"host="+srv+" port=5432 dbname=postgres sslmode=disable require_auth=scram-sha-256 user="+roRole,
			"-c", "select current_user || ' ' || current_setting('transaction_read_only')").CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if out, err := login(c.secrets.ReadOnlyPassword); err != nil || out != roRole+" on" {
		t.Fatalf("login: %v %q", err, out)
	}
	if out, err := login("t-wrong-" + rnd(8)); err == nil {
		t.Fatalf("control: a wrong password logged in: %q", out)
	}
}

// ───────── over a recording connection ─────────

// passStatements are the seven statements of one pass, in order.
var passStatements = []string{sqlBegin, sqlEndReadOnly, sqlLockJobs, sqlDeleteReadOnlyJobs, sqlClearActivity, sqlEndReadOnly, sqlCommit}

// passReply is how the fake server answers one pass: the backend types of
// the two endings' rows, the delete's row count, and a refusal (code at
// statement failAt, -1 for none). After a refusal, with refuseRest every
// later statement is refused (25P02) and the commit answered ROLLBACK, the
// transaction closed; without it nothing more is answered and the
// transaction is left failed. hangup closes the connection at failAt.
type passReply struct {
	ended1, ended2 []string
	deleted        int
	failAt         int
	code           string
	refuseRest     bool
	hangup         bool
	short          bool          // answer the begin alone, then ready, idle
	delay          time.Duration // before the first answer
}

var cleanPass = passReply{failAt: -1}

// passLog is what the fake server received: every query's text and time.
type passLog struct {
	mu      sync.Mutex
	queries []string
	at      []time.Time
	kinds   []string
}

func (l *passLog) passes() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []time.Time
	for i, q := range l.queries {
		if q == sqlReadOnlyJobsPass {
			out = append(out, l.at[i])
		}
	}
	return out
}

func (l *passLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.queries)
}

// passConn is a client connection to an in-process server that answers the
// pass as script says for the pass of that index, and a rollback.
func passConn(t *testing.T, script func(i int) passReply) (*pgx.Conn, *passLog) {
	t.Helper()
	cli, srv := net.Pipe()
	log := &passLog{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer srv.Close()
		servePasses(srv, log, script)
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
	t.Cleanup(func() { conn.Close(context.Background()); cli.Close(); <-done })
	return conn, log
}

func servePasses(srv net.Conn, log *passLog, script func(int) passReply) {
	be := pgproto3.NewBackend(bufio.NewReader(srv), srv)
	for {
		m, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		if _, ok := m.(*pgproto3.StartupMessage); ok {
			break
		}
		srv.Write([]byte("N"))
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
	ending := func(types []string) {
		be.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
			{Name: []byte("backend_type"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1},
			{Name: []byte("pg_terminate_backend"), DataTypeOID: 16, DataTypeSize: 1, TypeModifier: -1}}})
		for _, ty := range types {
			be.Send(&pgproto3.DataRow{Values: [][]byte{[]byte(ty), []byte("t")}})
		}
		be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT " + strconv.Itoa(len(types)))})
	}
	refuse := func(code string) {
		be.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: code, Message: "t-refused"})
	}
	n := 0
	for {
		msg, err := be.Receive()
		if err != nil {
			return
		}
		log.mu.Lock()
		log.kinds = append(log.kinds, fmt.Sprintf("%T", msg))
		if q, ok := msg.(*pgproto3.Query); ok {
			log.queries = append(log.queries, q.String)
			log.at = append(log.at, time.Now())
		}
		log.mu.Unlock()
		q, ok := msg.(*pgproto3.Query)
		switch {
		case !ok:
			if _, end := msg.(*pgproto3.Terminate); end {
				return
			}
			continue
		case q.String == sqlRollback:
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("ROLLBACK")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		case q.String == sqlReadOnlyJobsPass:
			r := script(n)
			n++
			time.Sleep(r.delay)
			status := byte('I')
			if r.short {
				be.Send(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")})
				be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				be.Flush()
				continue
			}
			for i := range passStatements {
				if i == r.failAt {
					if r.hangup {
						return
					}
					refuse(r.code)
					status = 'E'
					if r.refuseRest {
						for j := i + 1; j < len(passStatements)-1; j++ {
							refuse("25P02")
						}
						be.Send(&pgproto3.CommandComplete{CommandTag: []byte("ROLLBACK")})
						status = 'I'
					}
					break
				}
				switch i {
				case 0:
					be.Send(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")})
				case 1:
					ending(r.ended1)
				case 2:
					be.Send(&pgproto3.CommandComplete{CommandTag: []byte("LOCK TABLE")})
				case 3:
					be.Send(&pgproto3.CommandComplete{CommandTag: []byte("DELETE " + strconv.Itoa(r.deleted))})
				case 4:
					be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
				case 5:
					ending(r.ended2)
				case 6:
					be.Send(&pgproto3.CommandComplete{CommandTag: []byte("COMMIT")})
				}
			}
			be.Send(&pgproto3.ReadyForQuery{TxStatus: status})
		default:
			refuse("42601")
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		}
		if be.Flush() != nil {
			return
		}
	}
}

// TestDeleteReadOnlyJobs_PassStatements pins the seven statements' texts.
func TestDeleteReadOnlyJobs_PassStatements(t *testing.T) {
	want := []string{"begin",
		"select backend_type, pg_catalog.pg_terminate_backend(pid) from pg_catalog.pg_stat_activity where usename = 'supabase_read_only_user'",
		"lock table cron.job in exclusive mode",
		"delete from cron.job where username = 'supabase_read_only_user'",
		"select pg_catalog.pg_stat_clear_snapshot()",
		"select backend_type, pg_catalog.pg_terminate_backend(pid) from pg_catalog.pg_stat_activity where usename = 'supabase_read_only_user'",
		"commit"}
	if !slices.Equal(passStatements, want) || sqlReadOnlyJobsPass != strings.Join(want, ";\n") || sqlRollback != "rollback" {
		t.Fatalf("pass %q", sqlReadOnlyJobsPass)
	}
}

// TestDeleteReadOnlyJobs_OnePassIsOneTransaction: a clean run is one pass:
// begin, the ending, the lock, the delete, the activity snapshot cleared, the
// ending again and commit, in that order and nothing else, all seven in one
// message (written before any answer is read); nothing is sent before it.
func TestDeleteReadOnlyJobs_OnePassIsOneTransaction(t *testing.T) {
	conn, log := passConn(t, func(int) passReply { return cleanPass })
	if err := DeleteReadOnlyJobs(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	if got := log.all(); !slices.Equal(got, []string{sqlReadOnlyJobsPass}) {
		t.Fatalf("sent %q", got)
	}
	if got := strings.Split(log.all()[0], ";\n"); !slices.Equal(got, passStatements) {
		t.Fatalf("statements %q", got)
	}
	log.mu.Lock()
	kinds := slices.Clone(log.kinds)
	log.mu.Unlock()
	if !slices.Equal(kinds, []string{"*pgproto3.Query"}) {
		t.Fatalf("messages %v", kinds)
	}
}

// TestDeleteReadOnlyJobs_RepeatsUntilACleanPass: a deleted row, then a worker
// ended at the first ending, then at the second, then only client sessions:
// the run goes on, a tenth of a second apart, and ends on the first pass
// that begins at least 3 s after the third. A deleted row and never a worker:
// the first pass at least 3 s after the deleting one is the clean one; one
// that finds nothing is clean at once. Never a clean pass: the error at
// the deadline carries the last pass's reason, and every pass was committed.
func TestDeleteReadOnlyJobs_RepeatsUntilACleanPass(t *testing.T) {
	t.Run("worker ended", func(t *testing.T) {
		conn, log := passConn(t, func(i int) passReply {
			switch i {
			case 0:
				return passReply{failAt: -1, deleted: 1}
			case 1:
				return passReply{failAt: -1, ended1: []string{"pg_cron", "client backend"}}
			case 2:
				return passReply{failAt: -1, ended2: []string{"pg_cron"}}
			}
			return passReply{failAt: -1, ended1: []string{"client backend"}, ended2: []string{"client backend"}}
		})
		if err := DeleteReadOnlyJobs(context.Background(), conn); err != nil {
			t.Fatal(err)
		}
		ps := log.passes()
		if len(ps) < 4 {
			t.Fatalf("%d passes", len(ps))
		}
		last, third := ps[len(ps)-1], ps[2]
		if d := last.Sub(third); d < 3*time.Second || d > 4*time.Second {
			t.Fatalf("the last pass began %v after the third", d)
		}
		if d := ps[len(ps)-2].Sub(third); d >= 3*time.Second {
			t.Fatalf("a pass %v after the third was not the last", d)
		}
		for i := 1; i < len(ps); i++ {
			if d := ps[i].Sub(ps[i-1]); d < 100*time.Millisecond {
				t.Fatalf("pass %d began %v after the one before", i, d)
			}
		}
		if n := len(ps); n < 4+25 {
			t.Fatalf("only %d passes in the 3 s", n)
		}
	})
	t.Run("row deleted, no worker", func(t *testing.T) {
		conn, log := passConn(t, func(i int) passReply {
			if i == 0 {
				return passReply{failAt: -1, deleted: 3}
			}
			return cleanPass
		})
		t0 := time.Now()
		if err := DeleteReadOnlyJobs(context.Background(), conn); err != nil {
			t.Fatal(err)
		}
		// The deleting pass's rows were in the scheduler's cache until its
		// commit: the run ends on the first pass 3 s after it.
		ps := log.passes()
		if d := ps[len(ps)-1].Sub(ps[0]); d < 3*time.Second || d > 4*time.Second || ps[len(ps)-2].Sub(ps[0]) >= 3*time.Second {
			t.Fatalf("%d passes, the last %v after the first", len(ps), d)
		}
		if d := time.Since(t0); d > 5*time.Second {
			t.Fatalf("run of %v", d)
		}
	})
	t.Run("nothing found", func(t *testing.T) {
		conn, log := passConn(t, func(int) passReply { return passReply{failAt: -1, ended1: []string{"client backend"}} })
		t0 := time.Now()
		if err := DeleteReadOnlyJobs(context.Background(), conn); err != nil {
			t.Fatal(err)
		}
		if n, d := len(log.passes()), time.Since(t0); n != 1 || d > time.Second {
			t.Fatalf("%d passes in %v", n, d)
		}
	})
	for reason, r := range map[string]passReply{
		"a row was deleted":  {failAt: -1, deleted: 1},
		"a worker was ended": {failAt: -1, ended2: []string{"pg_cron"}},
	} {
		t.Run("never clean: "+reason, func(t *testing.T) {
			conn, log := passConn(t, func(int) passReply { return r })
			ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
			defer cancel()
			err := DeleteReadOnlyJobs(ctx, conn)
			if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), reason) {
				t.Fatalf("error %v", err)
			}
			if got := log.all(); len(got) < 3 || slices.Contains(got, sqlRollback) {
				t.Fatalf("sent %d queries, rollback among them: %v", len(got), slices.Contains(got, sqlRollback))
			}
		})
	}
}

// TestDeleteReadOnlyJobs_OnlyALockNotGrantedIsRepeated: 55P03 at the lock
// twice, then granted: three passes, the first two closed, and the run
// succeeds — whether the server refuses each later statement or answers
// nothing more. Always 55P03: the run ends at its deadline, not before. Any
// other error ends the run at once with that error and no second pass.
func TestDeleteReadOnlyJobs_OnlyALockNotGrantedIsRepeated(t *testing.T) {
	for _, refuseRest := range []bool{true, false} {
		t.Run(fmt.Sprintf("refuse rest %t", refuseRest), func(t *testing.T) {
			conn, log := passConn(t, func(i int) passReply {
				if i < 2 {
					return passReply{failAt: 2, code: "55P03", refuseRest: refuseRest}
				}
				return cleanPass
			})
			if err := DeleteReadOnlyJobs(context.Background(), conn); err != nil {
				t.Fatal(err)
			}
			want := []string{sqlReadOnlyJobsPass, sqlReadOnlyJobsPass, sqlReadOnlyJobsPass}
			if !refuseRest {
				// The answers left the transaction open: closed by a rollback.
				want = []string{sqlReadOnlyJobsPass, sqlRollback, sqlReadOnlyJobsPass, sqlRollback, sqlReadOnlyJobsPass}
			}
			if got := log.all(); !slices.Equal(got, want) {
				t.Fatalf("sent %q", got)
			}
		})
	}
	t.Run("never granted", func(t *testing.T) {
		conn, _ := passConn(t, func(int) passReply { return passReply{failAt: 2, code: "55P03"} })
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		t0 := time.Now()
		err := DeleteReadOnlyJobs(ctx, conn)
		if d := time.Since(t0); d < 700*time.Millisecond {
			t.Fatalf("ended after %v", d)
		}
		if err == nil || !strings.Contains(err.Error(), "the lock was not granted") || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error %v", err)
		}
	})
	t.Run("deadline inside a pass", func(t *testing.T) {
		conn, log := passConn(t, func(i int) passReply {
			if i == 0 {
				return passReply{failAt: 2, code: "55P03"}
			}
			return passReply{failAt: 2, code: "55P03", delay: 2 * time.Second}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		err := DeleteReadOnlyJobs(ctx, conn)
		if err == nil || !strings.Contains(err.Error(), "the lock was not granted") || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error %v", err)
		}
		if n := len(log.passes()); n != 2 {
			t.Fatalf("%d passes", n)
		}
	})
	for name, r := range map[string]passReply{
		"statement timeout at the delete": {failAt: 3, code: "57014", refuseRest: true},
		"unknown SQLSTATE at the lock":    {failAt: 2, code: "XX000"},
		"lock timeout at the delete":      {failAt: 3, code: "55P03"},
		"refused begin":                   {failAt: 0, code: "25001"},
		"refused ending":                  {failAt: 1, code: "42501"},
		"refused commit":                  {failAt: 6, code: "40001"},
		"refused second ending":           {failAt: 5, code: "42501"},
		"lost connection":                 {failAt: 2, hangup: true},
		"fewer answers than statements":   {failAt: -1, short: true},
	} {
		t.Run(name, func(t *testing.T) {
			conn, log := passConn(t, func(int) passReply { return r })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			t0 := time.Now()
			err := DeleteReadOnlyJobs(ctx, conn)
			var se *pgsock.ServerError
			switch {
			case err == nil:
				t.Fatal("no error")
			case time.Since(t0) > time.Second:
				t.Fatalf("ended after %v", time.Since(t0))
			case r.code != "" && (!errors.As(err, &se) || se.Code != r.code):
				t.Fatalf("error %v, want code %s", err, r.code)
			}
			if n := len(log.passes()); n != 1 {
				t.Fatalf("%d passes", n)
			}
		})
	}
}

// TestDeleteReadOnlyJobs_NoTable: 42P01 or 3F000 (no table, no schema) at the
// lock is no error: the
// transaction is rolled back and no second pass follows; the first ending
// was sent before the lock, in the same pass.
func TestDeleteReadOnlyJobs_NoTable(t *testing.T) {
	for _, refuseRest := range []bool{true, false} {
		code := map[bool]string{true: "42P01", false: "3F000"}[refuseRest]
		conn, log := passConn(t, func(int) passReply { return passReply{failAt: 2, code: code, refuseRest: refuseRest} })
		if err := DeleteReadOnlyJobs(context.Background(), conn); err != nil {
			t.Fatalf("refuse rest %t: %v", refuseRest, err)
		}
		want := []string{sqlReadOnlyJobsPass}
		if !refuseRest {
			want = append(want, sqlRollback)
		}
		if got := log.all(); !slices.Equal(got, want) {
			t.Fatalf("refuse rest %t: sent %q", refuseRest, got)
		}
	}
}
