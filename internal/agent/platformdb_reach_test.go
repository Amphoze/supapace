//go:build reach

package agent

// The platform database against a real Docker and the control-plane image on
// a bare node, as root (make node-proof PKG=internal/agent
// RUN='TestPlatformDB_|TestNode_PlatformDB').

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nsdial"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/poolcfg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const pdbClientName = "sp-test-pdb-client"

// pdbOnNode is a node agent with a pooler label, the platform network, the
// profile and sp-platform-db ensured; everything is removed at cleanup.
func pdbOnNode(t *testing.T) (*Agent, poolcfg.Addrs) {
	t.Helper()
	a := nodeAgent(t)
	a.cfg.PoolerLabel = "db"
	ad, err := poolcfg.For(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		nodeDockerQuiet("rm", "-f", pdbClientName)
		nodeDockerQuiet("rm", "-f", poolcfg.PlatformDBName)
		os.RemoveAll(a.pdbDir())
		os.RemoveAll(a.p.PoolerSecrets())
	})
	// A bare node has had no init, which makes /etc/supapace.
	if err := os.MkdirAll(filepath.Dir(a.p.PoolerSecrets()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsurePlatformNetworks(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.ensurePlatformDir(); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(a.p, a.p.PlatformDir(), "seccomp.json", seccompProfile, 0o444, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsurePlatformDB(ctx); err != nil {
		logs, _ := exec.Command("docker", "logs", "--tail", "30", poolcfg.PlatformDBName).CombinedOutput()
		t.Fatalf("EnsurePlatformDB: %v\n%s", err, logs)
	}
	return a, ad
}

// pdbRoot is a session over the socket as postgres (root maps to it).
func pdbRoot(t *testing.T, a *Agent) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Host, cfg.Port, cfg.Database, cfg.User = filepath.Join(a.pdbDir(), "sock"), 5432, "postgres", "postgres"
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("root over the socket: %v", err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

// inspectPDB returns the parts of the container's inspection the tests read.
type pdbInspect struct {
	State struct {
		Running bool
		Pid     int
	}
	Config          struct{ User string }
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress string }
	}
}

func inspectPDB(t *testing.T, name string) pdbInspect {
	t.Helper()
	var insp []pdbInspect
	if err := json.Unmarshal([]byte(nodeDocker(t, "container", "inspect", name)), &insp); err != nil || len(insp) != 1 {
		t.Fatalf("inspect %s: %v", name, err)
	}
	return insp[0]
}

// The control-plane image initialises its data directory and serves as
// PlatformDBUID, a uid its own account file does not hold.
func TestPlatformDB_RunsAsItsOwnUid(t *testing.T) {
	a, _ := pdbOnNode(t)
	passwd := nodeDocker(t, "run", "--rm", "--network", "none", "--entrypoint", "cat", a.cfg.Images.ControlPlane, "/etc/passwd")
	for _, l := range strings.Split(passwd, "\n") {
		if f := strings.Split(l, ":"); len(f) > 3 && (f[2] == "65525" || f[3] == "65525") {
			t.Fatalf("fixture: the image's account file holds the uid: %q", l)
		}
	}
	insp := inspectPDB(t, poolcfg.PlatformDBName)
	if !insp.State.Running || insp.Config.User != "65525:65525" {
		t.Fatalf("container: %+v", insp)
	}
	st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", insp.State.Pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(st), "\n") {
		if k, v, _ := strings.Cut(l, ":"); (k == "Uid" || k == "Gid") && strings.Join(strings.Fields(v), " ") != "65525 65525 65525 65525" {
			t.Errorf("server process %s: %q", k, v)
		}
	}
	fi, err := os.Stat(filepath.Join(a.pdbDir(), "data", "PG_VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if s := fi.Sys().(*syscall.Stat_t); s.Uid != 65525 || s.Gid != 65525 {
		t.Errorf("data directory owned by %d:%d", s.Uid, s.Gid)
	}
	var user, sock string
	if err := pdbRoot(t, a).QueryRow(context.Background(), "select current_user, current_setting('unix_socket_directories')").Scan(&user, &sock); err != nil {
		t.Fatal(err)
	}
	if user != "postgres" {
		t.Errorf("root over the socket is %q", user)
	}
	// Its log: the stream it is written to, its longest line, and a log
	// driver that `docker logs` reads.
	var stdout, stderr strings.Builder
	logs := exec.Command("docker", "logs", poolcfg.PlatformDBName)
	logs.Stdout, logs.Stderr = &stdout, &stderr
	if err := logs.Run(); err != nil {
		t.Fatal(err)
	}
	longest := 0
	for _, l := range strings.Split(stdout.String()+stderr.String(), "\n") {
		longest = max(longest, len(l))
	}
	driver := nodeDocker(t, "inspect", "--format", "{{.HostConfig.LogConfig.Type}}", poolcfg.PlatformDBName)
	t.Logf("log: %d bytes on stdout, %d on stderr, longest line %d bytes, driver %s", stdout.Len(), stderr.Len(), longest, driver)
	t.Logf("stdout, last lines:\n%s", lastLines(stdout.String(), 4))
	t.Logf("stderr, last lines:\n%s", lastLines(stderr.String(), 6))
	if stderr.Len() == 0 || (driver != "local" && driver != "json-file" && driver != "journald") {
		t.Errorf("log: stderr %d bytes, driver %q", stderr.Len(), driver)
	}
	// Initialised beforehand: the entrypoint only started the server, once,
	// and nothing was refused.
	restarts := nodeDocker(t, "inspect", "--format", "{{.RestartCount}}", poolcfg.PlatformDBName)
	if all := stdout.String() + stderr.String(); restarts != "0" || strings.Contains(all, "FATAL") || !strings.Contains(all, "Skipping initialization") {
		t.Errorf("start: %s restarts; log:\n%s", restarts, all)
	}
	// A second ensure adopts the running container.
	before := nodeDocker(t, "inspect", "--format", "{{.Id}}", poolcfg.PlatformDBName)
	if err := a.EnsurePlatformDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after := nodeDocker(t, "inspect", "--format", "{{.Id}}", poolcfg.PlatformDBName); after != before {
		t.Errorf("second ensure made the container again")
	}
	if r := a.CheckPlatformDB(context.Background()); len(r) != 1 || !r[0].OK {
		t.Errorf("row: %+v", r)
	}
}

// pdbClient runs a sleeping container at the pooler's address on platform
// and returns a dial from inside its network namespace.
func pdbClient(t *testing.T, a *Agent, ip netip.Addr) func(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	t.Helper()
	nodeDocker(t, "run", "-d", "--name", pdbClientName, "--label", "supapace.test=1", "--network", platformNet, "--ip", ip.String(),
		"--cap-drop", "ALL", "--user", "70:70", "--entrypoint", "sleep", a.cfg.Images.ControlPlane, "900")
	return nsDialer(t, pdbClientName)
}

func nsDialer(t *testing.T, name string) func(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	t.Helper()
	pid := func() (nsdial.Target, error) {
		out, err := exec.Command("docker", "inspect", "--format", "{{.State.Pid}}", name).Output()
		if err != nil {
			return nsdial.Target{}, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(out)))
		if err != nil {
			return nsdial.Target{}, err
		}
		return nsdial.TargetOf(n)
	}
	target, err := pid()
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
		return nsdial.DialTCP(ctx, target, func(context.Context) (nsdial.Target, error) { return pid() }, to)
	}
}

// pdbLogin opens a session over TCP through dial as role to db with password.
func pdbLogin(dial func(context.Context, netip.AddrPort) (net.Conn, error), to netip.AddrPort, role, db, password string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.Host, cfg.Port, cfg.Database, cfg.User, cfg.Password = to.Addr().String(), to.Port(), db, role, password
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, to) }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgx.ConnectConfig(ctx, cfg)
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// On the real image: the role's attributes, connection limit and verifier;
// the database and its owner; CONNECT revoked from PUBLIC; the access file
// the server reads is the mounted one with its two rules. supavisor_meta
// cannot connect to postgres; a second role cannot connect to supavisor;
// the role's 31st connection is refused (control: 30 are open).
func TestPlatformDB_RegistryRoleAndRevokes(t *testing.T) {
	a, ad := pdbOnNode(t)
	ctx := context.Background()
	root := pdbRoot(t, a)
	var login, super, createdb, createrole, repl bool
	var limit int
	var verifier, owner, hbaFile string
	var rules, badRules int
	if err := root.QueryRow(ctx, `select r.rolcanlogin, r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication, r.rolconnlimit,
		r.rolpassword, (select pg_catalog.pg_get_userbyid(datdba) from pg_catalog.pg_database where datname = 'supavisor'),
		current_setting('hba_file'), (select count(*) from pg_catalog.pg_hba_file_rules where error is null),
		(select count(*) from pg_catalog.pg_hba_file_rules where error is not null)
		from pg_catalog.pg_authid r where r.rolname = 'supavisor_meta'`).Scan(&login, &super, &createdb, &createrole, &repl, &limit,
		&verifier, &owner, &hbaFile, &rules, &badRules); err != nil {
		t.Fatal(err)
	}
	if !login || super || createdb || createrole || repl || limit != 30 || !strings.HasPrefix(verifier, "SCRAM-SHA-256$4096:") ||
		owner != "supavisor_meta" || hbaFile != "/etc/sp/pg_hba.conf" || rules != 2 || badRules != 0 {
		t.Fatalf("role %v %v %v %v %v %d %q, owner %q, hba %q %d %d", login, super, createdb, createrole, repl, limit,
			verifier[:min(len(verifier), 20)], owner, hbaFile, rules, badRules)
	}
	// A second role, with a password of its own.
	salt := make([]byte, 16)
	rand.Read(salt)
	otherPW := "a-second-role-test-password"
	ov, err := pgsock.ScramVerifier(otherPW, salt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Exec(ctx, "create role sp_test_other login password '"+ov+"'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Exec(context.Background(), "drop role if exists sp_test_other") })
	var pubSupavisor, pubPostgres bool
	if err := root.QueryRow(ctx, "select has_database_privilege('sp_test_other', 'supavisor', 'connect'), "+
		"has_database_privilege('supavisor_meta', 'postgres', 'connect')").Scan(&pubSupavisor, &pubPostgres); err != nil {
		t.Fatal(err)
	}
	if pubSupavisor || pubPostgres {
		t.Errorf("CONNECT through PUBLIC: second role on supavisor %v, supavisor_meta on postgres %v", pubSupavisor, pubPostgres)
	}

	pw, err := os.ReadFile(filepath.Join(a.p.PoolerSecrets(), "meta.password"))
	if err != nil {
		t.Fatal(err)
	}
	dial := pdbClient(t, a, ad.Pooler)
	to := netip.AddrPortFrom(ad.PlatformDB, 5432)
	var held []*pgx.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close(context.Background())
		}
	})
	for i := range 30 {
		c, err := pdbLogin(dial, to, "supavisor_meta", "supavisor", string(pw))
		if err != nil {
			t.Fatalf("connection %d of the role: %v", i+1, err)
		}
		held = append(held, c)
	}
	_, err = pdbLogin(dial, to, "supavisor_meta", "supavisor", string(pw))
	if sqlState(err) != "53300" {
		t.Errorf("31st connection: %v (%s), want too many connections for role", err, sqlState(err))
	}
	held[29].Close(ctx)
	held = held[:29]
	if _, err := pdbLogin(dial, to, "supavisor_meta", "postgres", string(pw)); sqlState(err) != "28000" {
		t.Errorf("supavisor_meta to postgres: %v (%s), want refused by the access file", err, sqlState(err))
	}
	if _, err := pdbLogin(dial, to, "sp_test_other", "supavisor", otherPW); sqlState(err) != "28000" {
		t.Errorf("second role to supavisor: %v (%s), want refused by the access file", err, sqlState(err))
	}
	if _, err := pdbLogin(dial, to, "supavisor_meta", "supavisor", "wrong"+string(pw)); sqlState(err) != "28P01" {
		t.Errorf("wrong password: %v (%s), want refused", err, sqlState(err))
	}
	// Control: the slot freed above takes a connection again.
	c, err := pdbLogin(dial, to, "supavisor_meta", "supavisor", string(pw))
	if err != nil {
		t.Fatalf("control after a close: %v", err)
	}
	held = append(held, c)
}

// The node proof's last point: the container is on platform alone, and only
// its platform address answers its port — not the container's loopback.
func TestNode_PlatformDBListensOnOneAddress(t *testing.T) {
	a, ad := pdbOnNode(t)
	insp := inspectPDB(t, poolcfg.PlatformDBName)
	if len(insp.NetworkSettings.Networks) != 1 || insp.NetworkSettings.Networks[platformNet].IPAddress != ad.PlatformDB.String() {
		t.Fatalf("networks: %+v", insp.NetworkSettings.Networks)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := pdbClient(t, a, ad.Pooler)
	c, err := client(ctx, netip.AddrPortFrom(ad.PlatformDB, 5432))
	if err != nil {
		t.Fatalf("control: the platform address does not answer: %v", err)
	}
	c.Close()
	inside := nsDialer(t, poolcfg.PlatformDBName)
	for _, to := range []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:5432"), netip.MustParseAddrPort("[::1]:5432")} {
		if c, err := inside(ctx, to); err == nil {
			c.Close()
			t.Errorf("%s answers inside the container", to)
		}
	}
	if _, err := os.Lstat(filepath.Join(a.pdbDir(), "sock", ".s.PGSQL.5432")); err != nil {
		t.Errorf("socket: %v", err)
	}
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(l[max(0, len(l)-n):], "\n")
}
