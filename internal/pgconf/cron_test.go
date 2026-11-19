package pgconf

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- scheduled jobs, against the pinned cluster image ----

func cronName() string {
	b := make([]byte, 5)
	rand.Read(b)
	return "sp-test-cron-" + hex.EncodeToString(b)
}

// cronCluster is a data directory initialised by the pinned image's own first
// boot, which sets supabase_admin's password to pw.
type cronCluster struct {
	img, data, pw string
}

func newCronCluster(t *testing.T) cronCluster {
	img := pinnedImage(t)
	c := cronCluster{img: img, data: cronName(), pw: cronName()}
	docker(t, "volume", "create", "--label", "supapace.test=1", c.data)
	t.Cleanup(func() { exec.Command("docker", "volume", "rm", "-f", c.data).Run() })
	name := cronName()
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", name).Run() })
	docker(t, "run", "-d", "--name", name, "--label", "supapace.test=1", "--network", "none", "--memory", "512m",
		"-e", "POSTGRES_PASSWORD="+c.pw, "-v", c.data+":/var/lib/postgresql/data", img)
	if !until(t, name, 5*time.Minute, func() bool {
		return exec.Command("docker", "exec", name, "psql", "-XAtq", "-h", "/var/run/postgresql", "-U", "supabase_admin",
			"-d", "postgres", "-c", "select 1").Run() == nil && strings.Contains(logs(name), "init process complete")
	}) {
		t.Fatalf("cluster did not initialise:\n%s", logs(name))
	}
	docker(t, "stop", "-t", "60", name)
	return c
}

// start runs the server on c's data with the platform's rendered files —
// conf as the override file in the image's include directory, supautils.conf,
// pg_hba.conf, pg_ident.conf — and the command-line pins, and returns the
// container's name once supabase_admin can log in.
func (c cronCluster) start(t *testing.T, conf []byte) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]byte{filepath.Join("conf.d", OverrideFile): conf, "pg_ident.conf": Ident()}
	ents, err := os.ReadDir(filepath.Join("testdata", "image", "conf.d"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		files[filepath.Join("conf.d", e.Name())] = image(t, filepath.Join("conf.d", e.Name()))
	}
	if files["supautils.conf"], err = Supautils(image(t, "supautils.conf"), false); err != nil {
		t.Fatal(err)
	}
	if files["pg_hba.conf"], err = HBA(netip.MustParsePrefix("10.213.3.64/26")); err != nil {
		t.Fatal(err)
	}
	cl, err := CommandLine(image(t, "postgresql.conf"))
	if err != nil {
		t.Fatal(err)
	}
	// The server runs as the image's postgres user: the tree must be readable.
	if err := os.Mkdir(filepath.Join(dir, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	name := cronName()
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", name).Run() })
	docker(t, append([]string{"run", "-d", "--name", name, "--label", "supapace.test=1", "--network", "none", "--memory", "512m",
		"-v", c.data + ":/var/lib/postgresql/data",
		"-v", filepath.Join(dir, "conf.d") + ":/etc/postgresql-custom/conf.d:ro",
		"-v", filepath.Join(dir, "supautils.conf") + ":/etc/postgresql-custom/supautils.conf:ro",
		"-v", filepath.Join(dir, "pg_hba.conf") + ":" + hbaFile + ":ro",
		"-v", filepath.Join(dir, "pg_ident.conf") + ":" + identFile + ":ro",
		c.img, "postgres", "-D", "/etc/postgresql"}, cl...)...)
	if !until(t, name, 2*time.Minute, func() bool { _, err := c.sql(name, "supabase_admin", "select 1"); return err == nil }) {
		t.Fatalf("server did not start:\n%s", logs(name))
	}
	return name
}

// sql runs q as role with password c.pw: supabase_admin over the socket,
// every other role over loopback (the lines pg_hba.conf admits them on).
func (c cronCluster) sql(name, role, q string) (string, error) {
	host := "127.0.0.1"
	if role == "supabase_admin" {
		host = "/var/run/postgresql"
	}
	out, err := exec.Command("docker", "exec", "-e", "PGPASSWORD="+c.pw, name, "psql", "-XAtq", "-v", "ON_ERROR_STOP=1",
		"-h", host, "-U", role, "-d", "postgres", "-c", q).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func (c cronCluster) must(t *testing.T, name, role, q string) string {
	t.Helper()
	out, err := c.sql(name, role, q)
	if err != nil {
		t.Fatalf("as %s: %s: %v", role, q, err)
	}
	return out
}

// lastRun is "status|return_message" of the latest run of the job named job,
// or "" before its first run ends.
func (c cronCluster) lastRun(name, job string) string {
	out, _ := c.sql(name, "supabase_admin", "select d.status || '|' || coalesce(d.return_message, '') "+
		"from cron.job_run_details d join cron.job j using (jobid) where j.jobname = '"+job+
		"' and d.status in ('succeeded', 'failed') order by d.runid desc limit 1")
	return out
}

// A job the project owner schedules runs, as the owner, on a server started
// with the platform's rendered configuration; a job of a second role runs
// with that role's rights only. Control: the same configuration without
// cron.use_background_workers, every run fails to connect.
func TestCron_JobsRunInBackgroundWorkers(t *testing.T) {
	c := newCronCluster(t)
	conf, err := Overrides(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	const setting = "cron.use_background_workers = on\n"
	if !bytes.Contains(conf, []byte("\n"+setting)) {
		t.Fatalf("rendered file lacks %q:\n%s", setting, conf)
	}

	name := c.start(t, bytes.Replace(conf, []byte(setting), nil, 1))
	c.must(t, name, "supabase_admin", "alter role postgres password '"+c.pw+"'")
	c.must(t, name, "postgres", `create extension pg_cron; create table public.t(who text);
select cron.schedule('owner', '1 seconds', $$insert into public.t values (current_user)$$)`)
	var got string
	if !until(t, name, time.Minute, func() bool { got = c.lastRun(name, "owner"); return got != "" }) ||
		got != "failed|connection failed" {
		t.Fatalf("control: last run %q, want a failed connection", got)
	}
	if n := c.must(t, name, "postgres", "select count(*) from public.t"); n != "0" {
		t.Fatalf("control: %s rows", n)
	}
	docker(t, "stop", "-t", "60", name)

	name = c.start(t, conf)
	if src := c.must(t, name, "supabase_admin", "select setting || ' ' || sourcefile from pg_catalog.pg_settings "+
		"where name = 'cron.use_background_workers'"); src != "on /etc/postgresql-custom/conf.d/"+OverrideFile {
		t.Fatalf("cron.use_background_workers: %q", src)
	}
	if !until(t, name, time.Minute, func() bool { got = c.lastRun(name, "owner"); return strings.HasPrefix(got, "succeeded|") }) {
		t.Fatalf("owner's job: last run %q, want succeeded", got)
	}
	if who := c.must(t, name, "postgres", "select string_agg(distinct who, ',') from public.t"); who != "postgres" {
		t.Fatalf("rows written by %q, want postgres", who)
	}

	// The largest cap Overrides accepts fits pg_cron's own bound and the
	// background workers the server has left once the image's own are up.
	if v := c.must(t, name, "supabase_admin", "select max_val from pg_catalog.pg_settings where name = 'cron.max_running_jobs'"); mustAtoi(t, v) < 32 {
		t.Errorf("cron.max_running_jobs may be at most %s here, Overrides allows 32", v)
	}
	free := c.must(t, name, "supabase_admin", `select current_setting('max_worker_processes')::int - count(*) from pg_catalog.pg_stat_activity
where backend_type not in ('client backend', 'checkpointer', 'background writer', 'walwriter', 'autovacuum launcher',
'autovacuum worker', 'archiver', 'startup', 'walsender', 'walreceiver', 'walsummarizer', 'pg_cron')`)
	if mustAtoi(t, free) < 32 {
		t.Errorf("%s background workers left for 32 running jobs", free)
	}

	c.must(t, name, "postgres", `create role r2 login password '`+c.pw+`'; grant usage on schema cron to r2;
create table public.r2t(who text); grant insert on public.r2t to r2`)
	c.must(t, name, "r2", `select cron.schedule('r2-own', '1 seconds', $$insert into public.r2t values (current_user)$$);
select cron.schedule('r2-owner', '1 seconds', $$insert into public.t values (current_user)$$)`)
	if !until(t, name, time.Minute, func() bool { got = c.lastRun(name, "r2-own"); return strings.HasPrefix(got, "succeeded|") }) {
		t.Fatalf("second role's job on its own table: last run %q, want succeeded", got)
	}
	if !until(t, name, time.Minute, func() bool { got = c.lastRun(name, "r2-owner"); return got != "" }) ||
		got != "failed|ERROR: permission denied for table t" {
		t.Fatalf("second role's job on the owner's table: last run %q, want permission denied", got)
	}
	if n := c.must(t, name, "postgres", "select count(*) from public.t where who <> 'postgres'"); n != "0" {
		t.Fatalf("%s rows in the owner's table written by another role", n)
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return n
}
