//go:build reach

package agent

// The recovery start and the re-key on a bare node, as root: real Docker, the
// pinned cluster image, the backup worker image (supapace-worker:local), the
// repository filesystem and, for the retry test, the object-store stand-in.
// Build with go test -c -tags reach ./internal/agent and run in the node with
// CL_SUPAPACED naming the daemon binary (supapace-arch beside it), as the
// other reach tests of this package. The jobs here are written by hand
// (pgBackRest by environment, as the jobs' environment is specified); they
// stand in for the job programs, which these tests do not exercise.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

const rrWorkerImage = "supapace-worker:local"

// rrLeak matches what of a re-key session a log line or a captured
// statement may not show: its statement texts and the verifiers.
var rrLeak = regexp.MustCompile(`(?i)SCRAM-SHA-256|alter role|pg_read_all_settings|pg_is_in_recovery|pg_walfile_name|supapace_backup|create role|pg_stat_statements_reset`)

func rrSecrets(t *testing.T, ref string, dek []byte) bootstrap.Secrets {
	s := bootstrap.Secrets{SupabaseAdminPassword: clRandom(t, 32), PostgresPassword: clRandom(t, 32),
		AuthenticatorPassword: clRandom(t, 32), PgsodiumRootKey: clRandom(t, 32), ScramSalts: map[string][]byte{},
		ReadOnlyPassword: clRandom(t, 32)}
	for _, r := range []string{"supabase_admin", "postgres", "authenticator", "supabase_read_only_user"} {
		var err error
		if s.ScramSalts[r], err = pgsock.ScramSalt(dek, ref, r); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// rrProject is a layout-2 project on the node after its create: first boot
// and first networked start done, cluster running in phase B. Everything is
// removed at cleanup.
func rrProject(t *testing.T, slice, uid int) (*Agent, Spec) {
	t.Helper()
	a := nodeAgent(t)
	if err := exec.Command("docker", "image", "inspect", rrWorkerImage).Run(); err != nil {
		t.Skipf("%s not loaded", rrWorkerImage)
	}
	ctx := context.Background()
	exe := os.Getenv("CL_SUPAPACED")
	if _, err := os.Stat(filepath.Join(filepath.Dir(exe), archBinary)); err != nil {
		t.Fatalf("CL_SUPAPACED must name the daemon binary, %s beside it: %v", archBinary, err)
	}
	t.Cleanup(swap(&daemonExe, func() (string, error) { return exe, nil }))
	rules, err := nft.Render(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(a.p.NftFile()), 0o700)
	if err := os.WriteFile(a.p.NftFile(), rules, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := nft.Load(ctx, a.p); err != nil {
		t.Fatal(err)
	}
	ref := "rcvr" + clRandom(t, 8)
	s := Spec{Ref: ref, Epoch: 1, Generation: 1, UID: uid, GID: uid, SubnetIndex: slice, DiskQuotaMB: 2048, MemMB: 512, Pids: 512,
		FirstBoot: true, Layout: 2, RepoQuotaMB: 2048, Stanza: ref + "-1", Secrets: rrSecrets(t, ref, []byte(clRandom(t, 32)))}
	s.StanzaPass = "lab-" + clRandom(t, 24)
	t.Cleanup(func() {
		ctx := context.Background()
		out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=supapace.test=1", "--filter", "name=-"+ref+"$").Output()
		for _, id := range strings.Fields(string(out)) {
			nodeDockerQuiet("rm", "-f", "-v", id)
		}
		a.StopCluster(ctx, ref)
		for _, k := range []string{"wipe", "prevalidate", "purge", "spool"} {
			nodeDockerQuiet("rm", "-f", "task-"+ref+"-"+k)
		}
		a.RemoveNetwork(ctx, ref)
		os.RemoveAll(a.p.ProjectDir(ref)) // the harness, as root; the daemon never does this
		os.RemoveAll(a.p.RepoDir(ref))
		setQuota(a.p, uid, 0)
		repoSetQuota(a.p.RepoRoot(), uid, 0)
		a.RemoveRender(ctx, ref)
		nodeDockerQuiet("network", "rm", platformNet, ingressNet)
		exec.Command("nft", "delete", "table", "inet", "supapace").Run()
		exec.Command("nft", "delete", "table", "bridge", "supapace").Run()
		os.Remove(a.p.NftFile())
		os.Remove(a.p.NftSum())
	})
	for _, step := range []func(context.Context) error{a.EnsurePlatformNetworks, a.EnsureImageFiles} {
		if err := step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, step := range []func(context.Context, Spec) error{a.EnsureDir, a.EnsureRepoDir, a.SetQuota, a.EnsureNetwork} {
		if err := step(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.EnsureCluster(ctx, s); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	s.FirstBoot = false
	if err := a.EnsureCluster(ctx, s); err != nil {
		t.Fatalf("first networked start: %v", err)
	}
	return a, s
}

// The jobs' programs, mounted at /x.
var rrScripts = map[string]string{
	// push every spool entry of an admitted timeline ($ADMIT), oldest first.
	"push.sh": `cd /spool || exit 1
n=0
for f in $(ls -tr | grep -E '^([0-9A-F]{24}(\.[0-9A-F]{8}\.backup)?|[0-9A-F]{8}\.history)$'); do
	case " $ADMIT " in *" $(echo "$f" | cut -c1-8) "*) ;; *) continue ;; esac
	pgbackrest archive-push "/spool/$f" && rm -f "/spool/$f" && n=$((n + 1)) || { echo "push: failed $f"; exit 1; }
done
echo "push: pushed $n"
`,
	// one pgBackRest command while the spool is pushed, then a final push.
	"job.sh": `rm -f /tmp/stop
( while [ ! -e /tmp/stop ]; do sh /x/push.sh >/dev/null 2>&1; sleep 0.5; done ) & lp=$!
pgbackrest "$@"; rc=$?
touch /tmp/stop; wait $lp
sh /x/push.sh >&2
exit $rc
`,
	// answer the restore spool's requests until /rspool/stop exists.
	"serve.sh": `while [ ! -e /rspool/stop ]; do
	for r in /rspool/req/*; do
		[ -f "$r" ] || continue
		f=${r##*/}
		echo "$f" | grep -qE '^([0-9A-F]{24}|[0-9A-F]{8}\.history)$' || { rm -f "$r"; continue; }
		rm -f "$r" "/tmp/$f.part"
		pgbackrest --log-level-console=error archive-get "$f" "/tmp/$f.part"; rc=$?
		if [ $rc = 0 ]; then cp "/tmp/$f.part" "/rspool/out/.tmp-$f" && rm "/tmp/$f.part" && mv "/rspool/out/.tmp-$f" "/rspool/out/$f"
		elif [ $rc = 1 ]; then : >"/rspool/out/.tmp-$f.none"; mv "/rspool/out/.tmp-$f.none" "/rspool/out/$f.none"
		else : >"$r"; fi
	done
	sleep 0.1
done
`,
}

// rrPGOptions is the jobs' PGOPTIONS from the non-superuser list.
func rrPGOptions() string {
	m := pgsock.StartupParams(false)
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("-c " + k + "=")
		for _, r := range m[k] {
			if r == ' ' || r == '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// rrJob runs one worker container at the project's ids, no network: kind
// push (spool, repo), db (data ro, socket, spool, repo), restore (data, repo
// ro) or serve (data ro, rspool, repo ro; detached). repo "" is the
// project's repository. It returns the combined output and the exit error.
func rrJob(t *testing.T, a *Agent, s Spec, kind, repo, admit string, cmd ...string) (string, error) {
	t.Helper()
	x := filepath.Join(os.TempDir(), "sp-recovery-x")
	os.MkdirAll(x, 0o755)
	os.Chmod(x, 0o755) // whatever the umask
	for n, body := range rrScripts {
		p := filepath.Join(x, n)
		if err := os.WriteFile(p, []byte(body), 0o444); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, 0o444)
	}
	if repo == "" {
		repo = filepath.Join(a.p.RepoDir(s.Ref), "repo")
	}
	pd := a.p.ProjectDir(s.Ref)
	env := []string{"PGBACKREST_STANZA=" + s.Stanza, "PGBACKREST_REPO1_PATH=/repo", "PGBACKREST_REPO1_CIPHER_TYPE=aes-256-cbc",
		"PGBACKREST_REPO1_CIPHER_PASS=" + s.StanzaPass, "PGBACKREST_LOCK_PATH=/tmp/lock", "PGBACKREST_LOG_PATH=/tmp/log",
		"PGBACKREST_SPOOL_PATH=/tmp/spool", "PGBACKREST_LOG_LEVEL_FILE=off", "PGBACKREST_LOG_LEVEL_CONSOLE=warn",
		"PGBACKREST_COMPRESS_TYPE=zst", "PGBACKREST_PROCESS_MAX=1", "PGBACKREST_START_FAST=y", "PGBACKREST_REPO1_BUNDLE=n",
		"PGBACKREST_REPO1_BLOCK=n", "PGBACKREST_RESUME=n", "PGBACKREST_REPO1_HARDLINK=n", "PGBACKREST_ARCHIVE_COPY=n",
		"PGBACKREST_NEUTRAL_UMASK=y", "PGBACKREST_CONFIG=/dev/null", "ADMIT=" + admit}
	var mounts []string
	switch kind {
	case "push":
		mounts = []string{pd + "/spool:/spool", repo + ":/repo"}
	case "db":
		mounts = []string{pd + "/data:/var/lib/postgresql/data:ro", pd + "/sock:/var/run/postgresql", pd + "/spool:/spool", repo + ":/repo"}
		env = append(env, "PGBACKREST_PG1_SOCKET_PATH=/var/run/postgresql", "PGBACKREST_PG1_USER=supapace_backup", "PGOPTIONS="+rrPGOptions())
	case "restore":
		mounts = []string{pd + "/data:/var/lib/postgresql/data", repo + ":/repo:ro"}
	case "serve":
		mounts = []string{pd + "/data:/var/lib/postgresql/data:ro", pd + "/rspool:/rspool", repo + ":/repo:ro"}
	}
	if kind != "push" {
		env = append(env, "PGBACKREST_PG1_PATH=/var/lib/postgresql/data")
	}
	ef := filepath.Join(t.TempDir(), "job.env")
	if err := os.WriteFile(ef, []byte(strings.Join(env, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	name := "sp-test-recovery-" + kind + "-" + s.Ref
	nodeDockerQuiet("rm", "-f", name)
	args := []string{"run", "--name", name, "--label", "supapace.test=1", "--user", fmt.Sprintf("%d:%d", s.UID, s.GID),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + a.seccompFile(), "--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=128m", "--cpus", "1", "--ulimit", "core=0", "--ulimit", "nofile=65536:65536",
		"--no-healthcheck", "--ipc", "private", "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "256",
		"--network", "none", "--env-file", ef, "-v", x + ":/x:ro"}
	for _, m := range mounts {
		args = append(args, "-v", m)
	}
	if kind == "serve" {
		args = append(args, "-d")
	} else {
		args = append(args, "--rm")
	}
	args = append(append(args, rrWorkerImage), cmd...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(out), err
}

const rrAdmitAll = "00000001 00000002 00000003 00000004 00000005 00000006"

func rrMust(t *testing.T, what string, out string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v\n%s", what, err, out)
	}
}

// rrBackedUp is rrProject with its stanza, a marker table holding 1 and a
// full backup, the cluster stopped and its spool pushed.
func rrBackedUp(t *testing.T, slice, uid int, before func(conn *pgx.Conn)) (*Agent, Spec) {
	t.Helper()
	a, s := rrProject(t, slice, uid)
	out, err := rrJob(t, a, s, "db", "", rrAdmitAll, "sh", "/x/job.sh", "stanza-create")
	rrMust(t, "stanza-create", out, err)
	conn := clSession(t, a, s)
	clExec(t, conn, "create table public.marker(n int primary key)")
	clExec(t, conn, "insert into public.marker values (1)")
	if before != nil {
		before(conn)
	}
	closeSession(conn)
	out, err = rrJob(t, a, s, "db", "", rrAdmitAll, "sh", "/x/job.sh", "backup", "--type=full")
	rrMust(t, "backup", out, err)
	rrStopAndPush(t, a, s)
	return a, s
}

func rrStopAndPush(t *testing.T, a *Agent, s Spec) {
	t.Helper()
	if err := a.StopCluster(context.Background(), s.Ref); err != nil {
		t.Fatal(err)
	}
	out, err := rrJob(t, a, s, "push", "", rrAdmitAll, "sh", "/x/push.sh")
	rrMust(t, "push", out, err)
}

// rrRecover restores the project's files from repo ("" its own), then runs
// the recovery start to t with the restore spool served, until promoted. The
// promoted recovery start keeps running.
func rrRecover(t *testing.T, a *Agent, s Spec, tgt pgconf.RecoveryTarget, repo string) {
	t.Helper()
	ctx := context.Background()
	if err := a.StopCluster(ctx, s.Ref); err != nil {
		t.Fatal(err)
	}
	if err := a.WipeData(ctx, s); err != nil {
		t.Fatal(err)
	}
	out, err := rrJob(t, a, s, "restore", repo, "", "sh", "-c", "pgbackrest --type=none restore && touch /var/lib/postgresql/data/recovery.signal")
	rrMust(t, "restore", out, err)
	rspool := filepath.Join(a.p.ProjectDir(s.Ref), "rspool")
	os.Remove(filepath.Join(rspool, "stop"))
	out, err = rrJob(t, a, s, "serve", repo, "", "sh", "/x/serve.sh")
	rrMust(t, "serve", out, err)
	defer func() {
		os.WriteFile(filepath.Join(rspool, "stop"), nil, 0o644)
		wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		exec.CommandContext(wctx, "docker", "wait", "sp-test-recovery-serve-"+s.Ref).Run()
		nodeDockerQuiet("rm", "-f", "sp-test-recovery-serve-"+s.Ref)
		os.Remove(filepath.Join(rspool, "stop"))
	}()
	if err := a.EnsureRecovery(ctx, s, tgt); err != nil {
		t.Fatalf("recovery start: %v", err)
	}
	rrPromoted(t, a, s)
}

func rrPromoted(t *testing.T, a *Agent, s Spec) {
	t.Helper()
	deadline := time.Now().Add(180 * time.Second)
	for {
		promoted, exited, err := a.RecoveryState(context.Background(), s)
		if err != nil {
			t.Fatalf("recovery state: %v", err)
		}
		if promoted {
			return
		}
		if exited || time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "30", clusterName(s.Ref)).CombinedOutput()
			t.Fatalf("not promoted (exited %v):\n%s", exited, logs)
		}
		time.Sleep(time.Second)
	}
}

// rrTrust is a trust session with the superuser list to the recorded
// recovery start.
func rrTrust(t *testing.T, a *Agent, s Spec) *pgx.Conn {
	t.Helper()
	st, ok, err := a.readState(s.Ref)
	if err != nil || !ok || st.Phase != PhaseR {
		t.Fatalf("state %+v %v %v", st, ok, err)
	}
	conn, err := pgsock.Dial(context.Background(), a.clusterTarget(s, st, true))
	if err != nil {
		t.Fatalf("trust session: %v", err)
	}
	t.Cleanup(func() { closeSession(conn) })
	return conn
}

func rrStr(t *testing.T, c *pgx.Conn, sql string, args ...any) string {
	t.Helper()
	ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
	defer cancel()
	var v string
	if err := c.QueryRow(ctx, sql, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", sql, pgsock.Clean(err))
	}
	return v
}

// rrLog is the server log of pg-<ref> from line from on.
func rrLog(t *testing.T, s Spec, from int) []string {
	t.Helper()
	out, err := exec.Command("docker", "logs", clusterName(s.Ref)).CombinedOutput()
	if err != nil {
		t.Fatalf("docker logs: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	return lines[min(from, len(lines)):]
}

// rrFenced is the log from line from on up to a fence line that conn (a
// platform session) writes now: the cluster wrote every earlier line before
// it, and Docker's log reader lags.
func rrFenced(t *testing.T, conn *pgx.Conn, s Spec, from int) []string {
	t.Helper()
	fence := "x-fence-" + clRandom(t, 6)
	clExec(t, conn, "do $$ begin raise warning '"+fence+"'; end $$")
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		lines := rrLog(t, s, from)
		if i := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, fence) }); i >= 0 {
			return lines[:i]
		}
	}
	t.Fatal("fence not in the log")
	return nil
}

// rrLeaks is what of lines shows a re-key statement.
func rrLeaks(lines []string) []string {
	var hits []string
	for _, l := range lines {
		if rrLeak.MatchString(l) {
			hits = append(hits, l)
		}
	}
	return hits
}

func rrMarkers(t *testing.T, c *pgx.Conn) string {
	return rrStr(t, c, "select coalesce(pg_catalog.string_agg(n::text, ',' order by n), '') from public.marker")
}

// TestRecoveryStart_TimeAndPositionTargetsBothStart: on restored files, a
// recovery start to the end of the archive, to a time and to a position each
// promote, hold exactly the markers their target reaches, take the next
// timeline, and the normal start afterwards logs in with the platform's
// password.
func TestRecoveryStart_TimeAndPositionTargetsBothStart(t *testing.T) {
	var at time.Time
	var lsn string
	a, s := rrBackedUp(t, 3, 700763, nil)
	ctx := context.Background()
	if err := a.EnsureCluster(ctx, s); err != nil {
		t.Fatal(err)
	}
	conn := clSession(t, a, s)
	ctxs, cancel := pgsock.Stmt(ctx, pgsock.DefaultBudget)
	if err := conn.QueryRow(ctxs, "select pg_catalog.clock_timestamp(), pg_catalog.pg_current_wal_lsn()::text").Scan(&at, &lsn); err != nil {
		t.Fatal(pgsock.Clean(err))
	}
	cancel()
	clExec(t, conn, "insert into public.marker values (2)")
	clExec(t, conn, "insert into public.marker values (3)")
	clExec(t, conn, "select pg_catalog.pg_switch_wal()")
	closeSession(conn)
	rrStopAndPush(t, a, s)
	for i, c := range []struct {
		name    string
		t       pgconf.RecoveryTarget
		markers string
	}{
		{"end of the archive", pgconf.RecoveryTarget{Timeline: "latest"}, "1,2,3"},
		{"time", pgconf.RecoveryTarget{Time: at, Timeline: "current"}, "1"},
		{"position", pgconf.RecoveryTarget{LSN: lsn, Timeline: "current"}, "1"},
	} {
		rrRecover(t, a, s, c.t, "")
		tl, err := a.Rekey(ctx, s)
		if err != nil {
			t.Fatalf("%s: re-key: %v", c.name, err)
		}
		if tl != i+2 {
			t.Errorf("%s: timeline %d, want %d", c.name, tl, i+2)
		}
		if err := a.EnsureCluster(ctx, s); err != nil {
			t.Fatalf("%s: normal start: %v", c.name, err)
		}
		conn := clSession(t, a, s)
		if got := rrMarkers(t, conn); got != c.markers {
			t.Errorf("%s: markers %q, want %q", c.name, got, c.markers)
		}
		closeSession(conn)
		t.Logf("%s: promoted, timeline %d, markers %s", c.name, tl, c.markers)
		rrStopAndPush(t, a, s)
	}
}

// Content a restored database may hold, placed before the backup.
var rrHostile = []string{
	"create table public.x_log(t timestamptz default pg_catalog.clock_timestamp(), who text, ev text, q text)",
	"create table public.x_spy(t timestamptz default pg_catalog.clock_timestamp(), pid int, who text, st text, q text)",
	"grant all on public.x_log, public.x_spy to public",
	"create role x_root superuser login",
	`create function public.x_login() returns event_trigger language plpgsql as $f$
begin
  if session_user = 'supabase_admin' then
    insert into public.x_log(who, ev, q) values (session_user, 'login', current_query());
    perform pg_sleep(20);
    raise exception 'tenant login trigger refuses %', session_user;
  end if;
end $f$`,
	"create event trigger x_login on login execute function public.x_login()",
	`create function public.x_ddl() returns event_trigger language plpgsql as $f$
begin insert into public.x_log(who, ev, q) values (session_user, tg_event || ' ' || tg_tag, current_query()); end $f$`,
	"create event trigger x_ddl_s on ddl_command_start execute function public.x_ddl()",
	"create event trigger x_ddl_e on ddl_command_end execute function public.x_ddl()",
	"create event trigger x_drop on sql_drop execute function public.x_ddl()",
	"create extension if not exists pg_cron",
	`select cron.schedule_in_database('x_spy', '1 seconds', $c$insert into public.x_spy(pid, who, st, q) select pid, usename::text, state, query from pg_catalog.pg_stat_activity where usename = 'supabase_admin' and pid <> pg_catalog.pg_backend_pid()$c$, 'postgres', 'x_root')`,
	"create extension if not exists pg_tle",
	`create function public.x_pass(username text, shadow_pass text, password_types pgtle.password_types, validuntil_time timestamptz, validuntil_null boolean)
returns void language plpgsql as $f$
begin
  insert into public.x_log(who, ev, q) values (username, 'passcheck', shadow_pass);
  perform pg_catalog.set_config('log_statement', 'all', false);
  perform pg_catalog.set_config('log_min_duration_statement', '0', false);
end $f$`,
	"select pgtle.register_feature('public.x_pass', 'passcheck')",
	`create function public.x_auth(port pgtle.clientauth_port_subset, status integer) returns void language plpgsql as $f$
begin
  if port.user_name = 'supabase_admin' then
    perform pg_sleep(3);
    raise exception 'tenant clientauth refuses %', port.user_name;
  end if;
end $f$`,
	"select pgtle.register_feature('public.x_auth', 'clientauth')",
	"create role x_auditor",
	"grant select on pg_catalog.pg_authid to x_auditor",
	"grant select on pg_catalog.pg_roles to x_auditor",
	"create function public.pg_is_in_recovery() returns boolean language sql as 'select false'",
	"create function pg_catalog.pg_walfile_name(text) returns text language sql as 'select ''FFFFFFFF'''",
	// A replaced built-in whose body runs tenant code in the calling session
	// and answers truthfully.
	`create function public.x_flip() returns boolean language plpgsql as $f$
begin
  begin
    perform pg_catalog.set_config('log_statement', 'all', false);
    perform pg_catalog.set_config('log_min_duration_statement', '0', false);
  exception when others then null; -- a role that may not set them: the tenant's own backups keep working
  end;
  begin perform pg_catalog.pg_is_wal_replay_paused(); return true; exception when others then return false; end;
end $f$`,
	"create or replace function pg_catalog.pg_is_in_recovery() returns boolean language sql as 'select public.x_flip()'",
	"insert into public.marker values (2)",
}

var rrRoleSet = strings.Fields(`log_statement=all log_min_duration_statement=0 log_min_duration_sample=0 log_statement_sample_rate=1
log_duration=on log_transaction_sample_rate=1 debug_print_parse=on debug_print_rewritten=on debug_print_plan=on
log_min_error_statement=debug5 log_min_messages=debug5 pgaudit.log=all pgaudit.role=x_auditor auto_explain.log_min_duration=0
session_preload_libraries=auto_explain pg_stat_statements.track_utility=on pg_stat_statements.track=all track_activities=on
search_path=public,pg_catalog statement_timeout=1ms default_transaction_read_only=on plan_filter.statement_cost_limit=0.001`)
var rrDBSet = strings.Fields(`log_statement=all log_min_duration_statement=0 session_preload_libraries=auto_explain
auto_explain.log_min_duration=0 pgaudit.log=all debug_print_parse=on log_transaction_sample_rate=1`)
var rrSysSet = strings.Fields(`log_statement=all log_min_duration_statement=0 debug_print_parse=on log_min_error_statement=debug1
log_min_messages=debug1 log_transaction_sample_rate=1 pgaudit.log=all session_preload_libraries=auto_explain
auto_explain.log_min_duration=0 shared_preload_libraries=auto_explain track_activities=on pgtle.enable_password_check=on`)

func rrSettings(kind string, kvs []string) []string {
	var out []string
	for _, kv := range kvs {
		k, v, _ := strings.Cut(kv, "=")
		out = append(out, fmt.Sprintf("%s set %s = '%s'", kind, k, v))
	}
	return out
}

// TestRekey_OnRestoredContentWithEverySettingOfTheExperiment: a backup with
// the experiment's content restored to the end of the archive: the recovery
// start promotes, the re-key completes, and nothing of it is in the server
// log, the statement statistics, the activity view (as the tenant's own job
// copies it) or the tenant's capture tables; the normal start's login works
// with the new password and the old one is refused, the read-only login's
// (the fourth statement) as the platform's. Controls: without the
// three extension pins a registered login check refuses the platform's
// login; with the recovery read sent first, the statements after it are
// logged.
func TestRekey_OnRestoredContentWithEverySettingOfTheExperiment(t *testing.T) {
	a, s := rrBackedUp(t, 4, 700764, func(conn *pgx.Conn) {
		for _, q := range rrHostile {
			clExec(t, conn, q)
		}
		for _, q := range slices.Concat(rrSettings("alter role supabase_admin", rrRoleSet), rrSettings("alter database postgres", rrDBSet),
			rrSettings("alter system", rrSysSet)) {
			clExec(t, conn, q)
		}
		clExec(t, conn, "select pg_catalog.pg_reload_conf()")
		// Last, the platform's passwords changed by the tenant.
		for _, r := range []string{"supabase_admin", "postgres", "authenticator"} {
			clExec(t, conn, "alter role "+r+" password 'tenant-changed-"+r+"'")
		}
	})
	ctx := context.Background()
	old := s
	s.Secrets.SupabaseAdminPassword, s.Secrets.PostgresPassword, s.Secrets.AuthenticatorPassword, s.Secrets.ReadOnlyPassword =
		clRandom(t, 32), clRandom(t, 32), clRandom(t, 32), clRandom(t, 32) // the next generation's passwords, the same salts
	rrRecover(t, a, s, pgconf.RecoveryTarget{Timeline: "latest"}, "")

	from := len(rrLog(t, s, 0))
	conn := rrTrust(t, a, s)
	start := rrStr(t, conn, "select pg_catalog.clock_timestamp()::text")
	if n := rrStr(t, conn, "select count(*)::text from pg_catalog.pg_db_role_setting where setrole = 'supabase_admin'::pg_catalog.regrole"); n == "0" {
		t.Fatal("the restored role settings are not there")
	}
	t0 := time.Now()
	tl, err := a.Rekey(ctx, s)
	if err != nil {
		t.Fatalf("re-key: %v", err)
	}
	t.Logf("re-key in %v, timeline %d", time.Since(t0).Round(time.Millisecond), tl)
	// Room for a scheduled job to run and copy the activity view, had one
	// been launched: the capture tables are read after it.
	time.Sleep(3 * time.Second)
	if l := rrLeaks(rrFenced(t, conn, s, from)); len(l) != 0 {
		t.Errorf("server log: %d lines of the re-key, first %.200q", len(l), l[0])
	}
	for _, q := range []string{
		"select count(*)::text from public.x_log where t >= $1::timestamptz and q ~* $2",
		"select count(*)::text from public.x_spy where t >= $1::timestamptz and q ~* $2",
		"select count(*)::text from extensions.pg_stat_statements where $1 <> '' and query ~* $2",
	} {
		if n := rrStr(t, conn, q, start, rrLeak.String()); n != "0" {
			t.Errorf("%s: %s rows", q, n)
		}
	}
	if n := rrStr(t, conn, "select count(*)::text from public.x_log where ev = 'passcheck' and t >= $1::timestamptz", start); n != "0" {
		t.Errorf("the password check ran %s times", n)
	}

	// Control: the recovery read first in a session with the list: the
	// replaced built-in turns logging on and the statements after it show.
	from = len(rrLog(t, s, 0))
	ctxs, cancel := pgsock.Stmt(ctx, pgsock.DefaultBudget)
	var in bool
	if err := conn.QueryRow(ctxs, "select pg_catalog.pg_is_in_recovery()").Scan(&in); err != nil {
		t.Fatal(pgsock.Clean(err))
	}
	cancel()
	if err := bootstrap.Rekey(ctx, conn, s.Secrets); err != nil {
		t.Fatalf("control re-key: %v", err)
	}
	if l := rrLeaks(rrFenced(t, conn, s, from)); len(l) == 0 {
		t.Error("control: with the recovery read first nothing was logged")
	}
	closeSession(conn)

	// The normal start: the new password logs in, the old one does not.
	if err := a.EnsureCluster(ctx, s); err != nil {
		t.Fatalf("normal start: %v", err)
	}
	conn = clSession(t, a, s)
	if got := rrMarkers(t, conn); got != "1,2" {
		t.Errorf("markers %q", got)
	}
	st, _, _ := a.readState(s.Ref)
	if c, err := pgsock.Dial(ctx, a.clusterTarget(old, st, false)); err == nil {
		closeSession(c)
		t.Error("the previous password logs in")
	}
	// The read-only login over TCP: the current password, not the backup's.
	if out, err := rrReadOnlyLogin(s, s.Secrets.ReadOnlyPassword); err != nil || out != "supabase_read_only_user on" {
		t.Errorf("read-only login with the current password: %v %q", err, out)
	}
	if out, err := rrReadOnlyLogin(s, old.Secrets.ReadOnlyPassword); err == nil {
		t.Errorf("the read-only login logs in with the password of the backup's time: %q", out)
	}

	// Control: a login check enabled in the system file refuses the platform's
	// login in a recovery start without the extension pins, not with them.
	clExec(t, conn, "alter system set pgtle.enable_clientauth = 'on'")
	closeSession(conn)
	if err := a.EnsureRecovery(ctx, s, pgconf.RecoveryTarget{Timeline: "latest"}); err != nil {
		t.Fatal(err)
	}
	rrPromoted(t, a, s)
	if _, err := a.Rekey(ctx, s); err != nil {
		t.Fatalf("with the extension pins: %v", err)
	}
	nst := rrStartWithout(t, a, s, "pgtle.enable_clientauth", "pgtle.enable_password_check", "cron.launch_active_jobs")
	var lerr error
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		var c *pgx.Conn
		if c, lerr = pgsock.Dial(ctx, a.clusterTarget(s, nst, true)); lerr == nil {
			closeSession(c)
			continue
		}
		if rrLoginCheckRefused(lerr) {
			break
		}
	}
	t.Logf("without the extension pins: %v", lerr)
	if !rrLoginCheckRefused(lerr) {
		t.Fatalf("control: without the extension pins the login was not refused by the login check: %v", lerr)
	}
}

// TestRecoveryStart_KeyScriptSetInTheRestoredSystemFile: a key script set in
// the restored system file (a start-time setting the command line does not
// pin) runs the project's own code in its own container. The recovery start
// and the re-key complete, or fail for that project only; either way the
// server log and the statement statistics hold nothing of the re-key.
func TestRecoveryStart_KeyScriptSetInTheRestoredSystemFile(t *testing.T) {
	var names []string
	a, s := rrBackedUp(t, 5, 700765, func(conn *pgx.Conn) {
		v := rrStr(t, conn, "select pg_catalog.string_agg(name, ' ' order by name) from pg_catalog.pg_settings where name like '%getkey_script'")
		names = strings.Fields(v)
	})
	if len(names) == 0 {
		t.Fatal("no key-script setting in the image")
	}
	ctx := context.Background()
	if err := a.StopCluster(ctx, s.Ref); err != nil {
		t.Fatal(err)
	}
	if err := a.WipeData(ctx, s); err != nil {
		t.Fatal(err)
	}
	out, err := rrJob(t, a, s, "restore", "", "", "sh", "-c", "pgbackrest --type=none restore && touch /var/lib/postgresql/data/recovery.signal")
	rrMust(t, "restore", out, err)
	// What the tenant's own code and ALTER SYSTEM would have left in the
	// restored directory: a script of its own, named in the system file.
	data := filepath.Join(a.p.ProjectDir(s.Ref), "data")
	script := filepath.Join(data, "x-key.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho tenant-key-script-ran >&2\nprintf %064d 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(script, s.UID, s.GID); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(data, "postgresql.auto.conf"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		fmt.Fprintf(f, "%s = '/var/lib/postgresql/data/x-key.sh'\n", n)
	}
	f.Close()
	rspool := filepath.Join(a.p.ProjectDir(s.Ref), "rspool")
	out, err = rrJob(t, a, s, "serve", "", "", "sh", "/x/serve.sh")
	rrMust(t, "serve", out, err)
	t.Cleanup(func() { os.WriteFile(filepath.Join(rspool, "stop"), nil, 0o644) })
	if err := a.EnsureRecovery(ctx, s, pgconf.RecoveryTarget{Timeline: "latest"}); err != nil {
		t.Fatalf("recovery start: %v", err)
	}
	var outcome string
	deadline := time.Now().Add(120 * time.Second)
	for outcome == "" {
		promoted, exited, err := a.RecoveryState(ctx, s)
		switch {
		case err != nil:
			outcome = "recovery state failed: " + err.Error()
		case exited:
			outcome = "the recovery start exited"
		case promoted:
			if tl, err := a.Rekey(ctx, s); err != nil {
				outcome = "re-key failed: " + err.Error()
			} else {
				outcome = fmt.Sprintf("re-key completed, timeline %d", tl)
			}
		case time.Now().After(deadline):
			outcome = "not promoted within 120 s"
		default:
			time.Sleep(time.Second)
		}
	}
	t.Logf("outcome: %s", outcome)
	var all []string
	if strings.HasPrefix(outcome, "re-key completed") {
		conn := rrTrust(t, a, s)
		all = rrFenced(t, conn, s, 0)
		if n := rrStr(t, conn, "select count(*)::text from extensions.pg_stat_statements where query ~* $1", rrLeak.String()); n != "0" {
			t.Errorf("statement statistics: %s rows", n)
		}
	} else {
		exec.Command("docker", "stop", "-t", "45", clusterName(s.Ref)).Run() // its log is then complete
		all = rrLog(t, s, 0)
	}
	ran := slices.ContainsFunc(all, func(l string) bool { return strings.Contains(l, "tenant-key-script-ran") })
	named := slices.ContainsFunc(all, func(l string) bool { return strings.Contains(l, "x-key.sh") })
	t.Logf("the key script ran: %v; named in the log: %v", ran, named)
	if !ran && !named {
		t.Fatalf("no sign of the key script in the log:\n%s", strings.Join(all[max(0, len(all)-20):], "\n"))
	}
	if l := rrLeaks(all); len(l) != 0 {
		t.Errorf("server log: %d lines of the re-key, first %.200q", len(l), l[0])
	}
}

// TestBackupRoleSession_DatabaseLevelCostLimit: a cost limit set at database
// level reaches the backup role's sessions (not superuser sessions: no list
// can override it), and its check ends as a failed job inside its deadline.
// Control: the same check before the setting passes.
func TestBackupRoleSession_DatabaseLevelCostLimit(t *testing.T) {
	a, s := rrProject(t, 6, 700766)
	out, err := rrJob(t, a, s, "db", "", rrAdmitAll, "sh", "/x/job.sh", "stanza-create")
	rrMust(t, "stanza-create", out, err)
	out, err = rrJob(t, a, s, "db", "", rrAdmitAll, "sh", "/x/job.sh", "check")
	rrMust(t, "control: check", out, err)
	conn := clSession(t, a, s)
	clExec(t, conn, "alter database postgres set plan_filter.statement_cost_limit = 0.001")
	closeSession(conn)
	t0 := time.Now()
	out, err = rrJob(t, a, s, "db", "", rrAdmitAll, "sh", "/x/job.sh", "check")
	took := time.Since(t0)
	t.Logf("check with the cost limit: %v after %v: %s", err, took.Round(time.Second), strings.TrimSpace(out))
	if err == nil {
		t.Fatal("the check passed under a database-level cost limit")
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) || took > 4*time.Minute {
		t.Fatalf("not a failed job inside its deadline: %v after %v", err, took)
	}
	// The platform's own session is not stopped by it.
	conn = clSession(t, a, s)
	if n := rrStr(t, conn, "select count(*)::text from pg_catalog.pg_class"); n == "0" {
		t.Fatal("no rows")
	}
}

// TestDial_StatisticsLoggingSettingsShowNoStatementText: the statistics
// logging settings and lock-wait logging on the platform's login role: the
// server log shows their lines (the settings took hold) and no statement
// text of the session.
func TestDial_StatisticsLoggingSettingsShowNoStatementText(t *testing.T) {
	a, s := rrProject(t, 7, 700767)
	ctx := context.Background()
	adm := clSession(t, a, s)
	clExec(t, adm, "create table public.lk(i int)")
	for _, round := range [][]string{
		{"log_parser_stats = on", "log_planner_stats = on", "log_executor_stats = on", "log_lock_waits = on", "deadlock_timeout = '100ms'"},
		{"log_statement_stats = on", "log_lock_waits = on", "deadlock_timeout = '100ms'"},
	} {
		clExec(t, adm, "alter role supabase_admin reset all")
		for _, kv := range round {
			clExec(t, adm, "alter role supabase_admin set "+kv)
		}
		from := len(rrLog(t, s, 0))
		marker := "mk_" + clRandom(t, 8)
		conn := clSession(t, a, s)
		clExec(t, conn, "select 1 as "+marker)
		if _, err := conn.Exec(ctx, "select 1 / 0 as "+marker); err == nil {
			t.Fatal("no error")
		}
		// A lock wait longer than the deadlock timeout.
		hold, err := pgsock.Dial(ctx, a.clusterTarget(s, mustState(t, a, s), false))
		if err != nil {
			t.Fatal(err)
		}
		tx, err := hold.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "lock table public.lk in access exclusive mode"); err != nil {
			t.Fatal(pgsock.Clean(err))
		}
		done := make(chan error, 1)
		go func() {
			c2, cancel := pgsock.Stmt(ctx, pgsock.DefaultBudget)
			defer cancel()
			_, err := conn.Exec(c2, "select count(*) as "+marker+" from public.lk")
			done <- err
		}()
		var waited bool
		// Shorter than the blocked statement's 10 s budget, so a slow log
		// reader ends here with this test's own message.
		for deadline := time.Now().Add(8 * time.Second); !waited && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			waited = slices.ContainsFunc(rrLog(t, s, from), func(l string) bool { return strings.Contains(l, "still waiting for") })
		}
		tx.Commit(ctx)
		closeSession(hold)
		if err := <-done; err != nil {
			t.Fatal(pgsock.Clean(err))
		}
		closeSession(conn)
		lines := rrFenced(t, adm, s, from)
		stats := slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, "STATISTICS") })
		if !stats || !waited {
			t.Fatalf("%v: the settings did not take hold (statistics %v, lock wait %v):\n%s", round, stats, waited, strings.Join(lines, "\n"))
		}
		for _, l := range lines {
			if strings.Contains(l, marker) {
				t.Errorf("%v: statement text in the log: %.200q", round, l)
			}
		}
	}
}

func mustState(t *testing.T, a *Agent, s Spec) State {
	t.Helper()
	st, ok, err := a.readState(s.Ref)
	if err != nil || !ok {
		t.Fatalf("state %v %v", ok, err)
	}
	return st
}

// rrS3 runs sp-probe s3 with the write identity of the projects' bucket.
func rrS3(t *testing.T, stdin []byte, args ...string) (string, error) {
	t.Helper()
	const d = "/var/lib/sp/s3"
	ep, err := os.ReadFile(d + "/endpoint")
	if err != nil {
		if os.Getenv("SUPAPACE_STANDIN") == "1" {
			t.Fatalf("stand-in: %v", err)
		}
		t.Skip("no object-store stand-in beside this node")
	}
	endpoint := strings.TrimSpace(string(ep))
	port := endpoint[strings.LastIndexByte(endpoint, ':')+1:]
	addrs, err := os.ReadFile(d + "/addrs")
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, "--endpoint", endpoint, "--bucket", "sp-projects", "--timeout", "60s",
		"--keys", d+"/projects-write.keys", "--ca", d+"/ca.pem")
	for _, ad := range strings.Fields(string(addrs)) {
		args = append(args, "--addr", ad+":"+port)
	}
	cmd := exec.Command(filepath.Join(filepath.Dir(os.Getenv("CL_SUPAPACED")), "sp-probe"), append([]string{"s3"}, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// rrHistory is the repository's copy of a timeline's history file.
func rrHistory(t *testing.T, repo string, s Spec, tl int) []byte {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(repo, "archive", s.Stanza, "*", fmt.Sprintf("%08X.history", tl)))
	if len(m) != 1 {
		t.Fatalf("timeline %d history in the repository: %q", tl, m)
	}
	b, err := os.ReadFile(m[0])
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRecoveryRetry_ConditionalCreateAcceptsBothHistories: a stop between
// promotion and the re-key, the abandoned timeline's history pushed, then a
// second attempt: it takes the next timeline, and both history files are
// created in the store with a conditional create — neither refused. Control:
// a second attempt restored without the abandoned history takes the number
// again, and its conditional create answers "exists" with other content.
func TestRecoveryRetry_ConditionalCreateAcceptsBothHistories(t *testing.T) {
	a, s := rrBackedUp(t, 8, 700768, nil)
	rrS3(t, nil, "versions", "recovery-none/") // skips without the stand-in
	ctx := context.Background()
	repo := filepath.Join(a.p.RepoDir(s.Ref), "repo")
	prefix := "recovery-" + clRandom(t, 6) + "/archive/" + s.Stanza + "/"
	put := func(tl int, body []byte) string {
		out, _ := rrS3(t, body, "put", prefix+fmt.Sprintf("%08X.history", tl), "--if-absent")
		return out
	}
	// The repository as it was before the first attempt, for the control.
	before := filepath.Join(a.p.RepoDir(s.Ref), "before")
	if out, err := exec.Command("cp", "-a", repo, before).CombinedOutput(); err != nil {
		t.Fatalf("copy: %v %s", err, out)
	}

	rrRecover(t, a, s, pgconf.RecoveryTarget{Timeline: "latest"}, "")
	// Stopped between promotion and the re-key, once the promotion's history
	// file is in the spool.
	spooled := filepath.Join(a.p.ProjectDir(s.Ref), "spool", "00000002.history")
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if _, err := os.Stat(spooled); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no history file in the spool after the promotion")
		}
	}
	nodeDocker(t, "kill", clusterName(s.Ref))
	rrStopAndPush(t, a, s)
	h2 := rrHistory(t, repo, s, 2)
	if out := put(2, h2); !strings.HasPrefix(out, "version") {
		t.Fatalf("history 2: %q", out)
	}

	rrRecover(t, a, s, pgconf.RecoveryTarget{Timeline: "latest"}, "")
	tl, err := a.Rekey(ctx, s)
	if err != nil || tl != 3 {
		t.Fatalf("second attempt: timeline %d, %v", tl, err)
	}
	rrStopAndPush(t, a, s)
	if out := put(3, rrHistory(t, repo, s, 3)); !strings.HasPrefix(out, "version") {
		t.Fatalf("history 3: %q", out)
	}

	// Control: without the abandoned history the number 2 is taken again.
	rrRecover(t, a, s, pgconf.RecoveryTarget{Timeline: "latest"}, before)
	tl, err = a.Rekey(ctx, s)
	if err != nil || tl != 2 {
		t.Fatalf("control: timeline %d, %v", tl, err)
	}
	if err := a.StopCluster(ctx, s.Ref); err != nil {
		t.Fatal(err)
	}
	out, err := rrJob(t, a, s, "push", before, rrAdmitAll, "sh", "/x/push.sh")
	rrMust(t, "control push", out, err)
	again := rrHistory(t, before, s, 2)
	if bytes.Equal(again, h2) {
		t.Fatal("control: the reused number's history equals the abandoned one")
	}
	if out := put(2, again); out != "exists" {
		t.Fatalf("control: conditional create of the reused number: %q", out)
	}
}

// rrLoginCheckRefused: the login failed in the registered login check — its
// own refusal, or any error its body raised, which the extension reports as
// SQLSTATE 08000 (here the role's cost limit stops the check's own statement).
func rrLoginCheckRefused(err error) bool {
	var se *pgsock.ServerError
	return errors.As(err, &se) && (se.Code == "08000" || strings.Contains(se.Message, "clientauth"))
}

// rrStartWithout starts the recovery start's argv without the pins of the
// named settings (each must be there) and records it as the recovery start:
// the controls of the pins.
func rrStartWithout(t *testing.T, a *Agent, s Spec, names ...string) State {
	t.Helper()
	ctx := context.Background()
	rec, _ := pgconf.RecoveryPins(pgconf.RecoveryTarget{Timeline: "latest"})
	args, err := a.recoveryRunArgs(s, rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		i := slices.IndexFunc(args, func(v string) bool { return strings.HasPrefix(v, n+"=") })
		if i < 1 || args[i-1] != "-c" {
			t.Fatalf("no pin of %s in %q", n, args)
		}
		args = slices.Delete(args, i-1, i+1)
	}
	if err := a.removeCluster(ctx, s.Ref); err != nil {
		t.Fatal(err)
	}
	nst, err := a.startCluster(ctx, s, args)
	if err != nil {
		t.Fatal(err)
	}
	nst.Phase = PhaseR
	if err := a.writeState(s.Ref, nst); err != nil {
		t.Fatal(err)
	}
	return nst
}

// TestRekey_HTTPWorkerRunsNoRestoredCodeBesideTheRekey: a statement trigger
// the project's ordinary role placed on a table of the image's HTTP extension,
// restored with the backup. The extension's worker would delete from that
// table as soon as the cluster is promoted and run the trigger, whose body
// holds that role's row in the role catalogue. The recovery start keeps the
// worker out: the re-key completes. Control: without that pin the worker runs
// the trigger and the re-key meets its budget.
func TestRekey_HTTPWorkerRunsNoRestoredCodeBesideTheRekey(t *testing.T) {
	a, s := rrBackedUp(t, 10, 700770, func(conn *pgx.Conn) {
		for _, q := range []string{
			"create extension if not exists pg_net",
			"set role postgres",
			"create table public.x_net(t timestamptz default pg_catalog.clock_timestamp())",
			`create function public.x_net_hold() returns trigger language plpgsql as $f$
begin
  if not pg_catalog.pg_is_in_recovery() then
    insert into public.x_net default values;
    alter role postgres password 'held-by-restored-code';
    perform pg_catalog.pg_sleep(30);
  end if;
  return null;
end $f$`,
			"create trigger x_net_hold before delete on net._http_response for each statement execute function public.x_net_hold()",
			"reset role",
		} {
			clExec(t, conn, q)
		}
	})
	ctx := context.Background()
	rrRecover(t, a, s, pgconf.RecoveryTarget{Timeline: "latest"}, "")
	// Room for the worker's first loop, had it started.
	time.Sleep(5 * time.Second)
	if _, err := a.Rekey(ctx, s); err != nil {
		t.Fatalf("re-key: %v", err)
	}
	if !slices.ContainsFunc(rrLog(t, s, 0), func(l string) bool { return strings.Contains(l, `database "" does not exist`) }) {
		t.Error("no sign of the worker's refused connection in the log")
	}

	// Control: the same start without the worker's pin.
	nst := rrStartWithout(t, a, s, "pg_net.database_name")
	running := false
	for deadline := time.Now().Add(60 * time.Second); !running && time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		c, err := pgsock.Dial(ctx, a.clusterTarget(s, nst, true))
		if err != nil {
			continue
		}
		running = rrStr(t, c, "select (count(*) > 0)::text from pg_catalog.pg_stat_activity where backend_type like 'pg_net%' and wait_event = 'PgSleep'") == "true"
		closeSession(c)
	}
	if !running {
		t.Fatal("control: the worker never ran the trigger")
	}
	if _, err := a.Rekey(ctx, s); !pgsock.IsBudget(err) {
		t.Fatalf("control: without the pin the re-key gave %v, want a budget error", err)
	}
}

// TestRekey_ScheduledJobDoesNotRunBesideTheRekey: a scheduled job restored
// with the backup that holds the role catalogue's lock for 30 s every 5 s.
// The recovery start's scheduler pins keep it from running: the re-key
// completes, also after the scheduler's interval. Control: without the two
// pins, once the job holds the catalogue, the re-key meets its budget.
func TestRekey_ScheduledJobDoesNotRunBesideTheRekey(t *testing.T) {
	a, s := rrBackedUp(t, 11, 700771, func(conn *pgx.Conn) {
		for _, q := range []string{
			"create role x_root superuser login",
			"create extension if not exists pg_cron",
			`select cron.schedule_in_database('x_lock', '5 seconds', $c$begin; lock table pg_catalog.pg_authid in access exclusive mode; select pg_catalog.pg_sleep(30); commit$c$, 'postgres', 'x_root')`,
		} {
			clExec(t, conn, q)
		}
	})
	ctx := context.Background()
	rrRecover(t, a, s, pgconf.RecoveryTarget{Timeline: "latest"}, "")
	time.Sleep(10 * time.Second) // two of the job's intervals, had the scheduler run
	if _, err := a.Rekey(ctx, s); err != nil {
		t.Fatalf("re-key: %v", err)
	}

	nst := rrStartWithout(t, a, s, "cron.launch_active_jobs", "cron.database_name")
	held := false
	for deadline := time.Now().Add(90 * time.Second); !held && time.Now().Before(deadline); time.Sleep(time.Second) {
		c, err := pgsock.Dial(ctx, a.clusterTarget(s, nst, true))
		if err == nil {
			closeSession(c)
			continue
		}
		held = pgsock.IsBudget(err) // the login reads the role catalogue
	}
	if !held {
		l := rrLog(t, s, 0)
		t.Fatalf("control: the job never held the role catalogue:\n%s", strings.Join(l[max(0, len(l)-15):], "\n"))
	}
	if _, err := a.Rekey(ctx, s); !pgsock.IsBudget(err) {
		t.Fatalf("control: without the scheduler's pins the re-key gave %v, want a budget error", err)
	}
}

// rrReadOnlyLogin logs in as the read-only login over TCP inside the cluster's
// container, requiring SCRAM, and reports the user and its default
// transaction mode.
func rrReadOnlyLogin(s Spec, password string) (string, error) {
	out, err := exec.Command("docker", "exec", "-e", "PGPASSWORD="+password, clusterName(s.Ref), "psql", "-XAt",
		"host=127.0.0.1 port=5432 dbname=postgres sslmode=disable require_auth=scram-sha-256 user=supabase_read_only_user",
		"-c", "select current_user || ' ' || current_setting('transaction_read_only')").CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
