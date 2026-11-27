package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

// platformJobsSession is the clean-up's session as the agent opens it: the
// platform's dial with its session budget, and the two timeouts.
func (c *cluster) platformJobsSession(ctx context.Context) *pgx.Conn {
	c.t.Helper()
	tg := c.target("supabase_admin")
	tg.LockTimeout, tg.StatementTimeout = 2*time.Second, 10*time.Second
	conn, err := pgsock.Dial(ctx, tg)
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// TestDropReadOnlyJobs_PlatformSession_ManySessionsOfTheRole: the clean-up
// through the platform's own session (its budget included) completes while a
// job of the role runs and twelve sessions of the role reconnect throughout,
// as a dashboard in use does.
func TestDropReadOnlyJobs_PlatformSession_ManySessionsOfTheRole(t *testing.T) {
	c, adm := cronCluster(t)
	for range 12 {
		c.loopAs(roRole, "select pg_catalog.pg_sleep(30)")
	}
	c.mustAs(roRole, "select cron.schedule('ro-busy', '1 second', 'select pg_catalog.pg_sleep(5)')")
	c.waitWorkers(adm, 1, 20*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	js := c.platformJobsSession(ctx)
	t0 := time.Now()
	if err := DeleteReadOnlyJobs(ctx, js); err != nil {
		t.Fatalf("clean-up after %v: %v", time.Since(t0).Round(time.Millisecond), err)
	}
	if n := c.count(adm, "select count(*)::text from cron.job where username = $1", roRole); n != 0 {
		t.Fatalf("%d rows of the role left", n)
	}
}

// TestReadOnlyJobs_SecondEndingEndsASessionOpenedAfterTheFirst: a session of
// the role opened while the pass is at its delete — after the first ending —
// is ended by the pass's second ending. The delete is held by a trigger of
// the test's until that session is there.
func TestReadOnlyJobs_SecondEndingEndsASessionOpenedAfterTheFirst(t *testing.T) {
	c, adm := cronCluster(t)
	c.exec(adm, `create function public.t_wait() returns trigger language plpgsql as $$ begin
	  for i in 1..80 loop
	    exit when exists (select 1 from pg_catalog.pg_locks where locktype = 'advisory' and objid = 4107 and granted);
	    perform pg_catalog.pg_sleep(0.1);
	  end loop;
	  return null; end $$`)
	c.exec(adm, "create trigger t_wait before delete on cron.job for each statement execute function public.t_wait()")
	js, passes := c.jobsSession()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- DeleteReadOnlyJobs(ctx, js) }()
	// The pass is at its delete: its first ending has run.
	const atDelete = "select count(*)::text from pg_catalog.pg_stat_activity where wait_event = 'PgSleep' and usename = 'supabase_admin'"
	for deadline := time.Now().Add(5 * time.Second); c.count(adm, atDelete) == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the pass did not reach its delete")
		}
	}
	late := make(chan string, 1)
	go func() {
		out, _ := c.psqlAs(roRole, "select pg_catalog.pg_advisory_lock(4107), pg_catalog.pg_sleep(30)")
		late <- out
	}()
	if err := <-done; err != nil {
		t.Fatalf("clean-up: %v", err)
	}
	if n := len(passes()); n != 1 {
		t.Fatalf("%d passes: the session is to be ended by the first", n)
	}
	select {
	case out := <-late:
		if !strings.Contains(out, "terminating connection due to administrator command") {
			t.Fatalf("the late session ended otherwise: %s", out)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a session of the role opened after the pass's first ending outlived the pass")
	}
}

// TestReadOnlyLogin_GroupRolesCannotLogIn: every role the read-only login is
// a member of, directly or not, is a group role: none can log in.
func TestReadOnlyLogin_GroupRolesCannotLogIn(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	const q = `select coalesce(string_agg(rolname, ',' order by rolname) filter (where rolcanlogin), ''), count(*)::text
	  from pg_catalog.pg_roles where rolname <> $1 and pg_catalog.pg_has_role($1, oid, 'member')`
	ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
	defer cancel()
	var login, n string
	if err := adm.QueryRow(ctx, q, roRole).Scan(&login, &n); err != nil {
		t.Fatal(pgsock.Clean(err))
	}
	if n == "0" {
		t.Fatal("control: the read-only login is a member of no role")
	}
	if login != "" {
		t.Fatalf("the read-only login is a member of roles that can log in: %s", login)
	}
}

// TestDeleteReadOnlyJobs_WorkerAtTheFirstEndingAlone: a worker ended at the
// first ending — no row deleted, nothing at the second ending — keeps the run
// going for the quiet time, and is the reason of a run that never gets clean.
func TestDeleteReadOnlyJobs_WorkerAtTheFirstEndingAlone(t *testing.T) {
	conn, log := passConn(t, func(i int) passReply {
		if i == 0 {
			return passReply{failAt: -1, ended1: []string{"pg_cron"}}
		}
		return cleanPass
	})
	if err := DeleteReadOnlyJobs(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	ps := log.passes()
	if len(ps) < 2 || ps[len(ps)-1].Sub(ps[0]) < 3*time.Second {
		t.Fatalf("%d passes, the last %v after the one that ended a worker", len(ps), ps[len(ps)-1].Sub(ps[0]))
	}
	conn, _ = passConn(t, func(int) passReply { return passReply{failAt: -1, ended1: []string{"pg_cron"}} })
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	err := DeleteReadOnlyJobs(ctx, conn)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "a worker was ended") {
		t.Fatalf("error %v", err)
	}
}

// TestDeleteReadOnlyJobs_NoTableAnswerElsewhereIsAnError: "no such table" and
// "no such schema" mean that the extension is absent only as the lock's
// answer; from any other statement of the pass (a trigger's error at the
// delete, say) they end the run with that error.
func TestDeleteReadOnlyJobs_NoTableAnswerElsewhereIsAnError(t *testing.T) {
	for _, code := range []string{"42P01", "3F000"} {
		for _, at := range []int{1, 3, 4} {
			conn, log := passConn(t, func(int) passReply { return passReply{failAt: at, code: code} })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := DeleteReadOnlyJobs(ctx, conn)
			cancel()
			var se *pgsock.ServerError
			if err == nil || !errors.As(err, &se) || se.Code != code {
				t.Fatalf("%s at statement %d: %v", code, at, err)
			}
			if n := len(log.passes()); n != 1 {
				t.Fatalf("%s at statement %d: %d passes", code, at, n)
			}
		}
	}
}

// TestDropReadOnlyJobs_TimeoutsOverrideRoleAndDatabaseSettings: the two
// timeouts of the clean-up's session are in force whatever the login role
// and the database set for them.
func TestDropReadOnlyJobs_TimeoutsOverrideRoleAndDatabaseSettings(t *testing.T) {
	c := startCluster(t)
	adm := c.dial("supabase_admin")
	c.exec(adm, "alter role supabase_admin set lock_timeout = 0")
	c.exec(adm, "alter role supabase_admin set statement_timeout = 0")
	c.exec(adm, "alter database postgres set lock_timeout = '1h'")
	c.exec(adm, "alter role supabase_admin in database postgres set statement_timeout = '1h'")
	js := c.platformJobsSession(context.Background())
	if got := c.str(js, "select current_setting('lock_timeout') || ' ' || current_setting('statement_timeout')"); got != "2s 10s" {
		t.Fatalf("settings %q", got)
	}
}

// TestDeleteReadOnlyJobs_QuietTimeCountsFromTheAnswers: the quiet time runs
// from when the answers of the pass that ended a worker were read, not from
// when that pass was sent — a pass can wait two seconds at its lock.
func TestDeleteReadOnlyJobs_QuietTimeCountsFromTheAnswers(t *testing.T) {
	const held = 1500 * time.Millisecond
	conn, log := passConn(t, func(i int) passReply {
		if i == 0 {
			return passReply{failAt: -1, ended1: []string{"pg_cron"}, delay: held}
		}
		return cleanPass
	})
	if err := DeleteReadOnlyJobs(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	ps := log.passes()
	if d := ps[len(ps)-1].Sub(ps[0]); d < held+3*time.Second {
		t.Fatalf("the clean pass began %v after the pass that ended a worker was sent: less than 3 s after its answers", d)
	}
}

// TestDeleteReadOnlyJobs_LostConnectionIsNotADeadline: a connection lost
// inside a pass, with time left, ends the run with the connection's error:
// not a deadline, and not worded as a run that found no clean pass.
func TestDeleteReadOnlyJobs_LostConnectionIsNotADeadline(t *testing.T) {
	conn, _ := passConn(t, func(int) passReply { return passReply{failAt: 2, hangup: true} })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := DeleteReadOnlyJobs(ctx, conn)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "last pass") ||
		strings.Contains(err.Error(), "%!") {
		t.Fatalf("error %v", err)
	}
}

// TestAssertReadOnlyVerifier_WholeValueAndBoundedRead: the stored value
// passes only when it equals the platform's verifier as a whole — a part of
// it, or it with something appended, is the finding — and the statement
// reads at most 512 characters of what is stored.
func TestAssertReadOnlyVerifier_WholeValueAndBoundedRead(t *testing.T) {
	if !strings.Contains(sqlReadOnlyVerifier, "pg_catalog.left(rolpassword, 512)") {
		t.Fatalf("the read is not bounded: %s", sqlReadOnlyVerifier)
	}
	s, _ := roSecrets(t)
	mine, err := pgsock.ScramVerifier(s.ReadOnlyPassword, s.ScramSalts[roRole])
	if err != nil {
		t.Fatal(err)
	}
	for name, stored := range map[string]string{
		"its first half": mine[:len(mine)/2],
		"its scheme":     mine[:strings.IndexByte(mine, '$')+1],
		"empty":          "",
		"with a suffix":  mine + "A",
		"twice":          mine + mine,
	} {
		conn, _ := recordingConn(t, func(sql string) ([]uint32, [][]string) {
			if sql != sqlReadOnlyVerifier {
				return nil, nil
			}
			return []uint32{25}, [][]string{{stored}}
		})
		r, err := AssertReadOnlyVerifier(context.Background(), conn, s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(r) != 1 || r[0].Name != "service-passwords" || !strings.Contains(r[0].Detail, "differs") {
			t.Errorf("%s: findings %+v", name, r)
		}
	}
}
