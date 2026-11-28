//go:build reach

package agent

// More of the platform database on a bare node, as root (make node-proof
// PKG=internal/agent RUN='TestNode_PlatformDB|TestPlatformDB_').

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/poolcfg"
	"github.com/jackc/pgx/v5"
)

const pdbOtherName = "sp-test-pdb-other"

// The access files as the server reads them are the two rules and the one
// mapping, and nothing but the pooler's address as the registry role to the
// registry database gets a session over TCP: not that role from another
// platform address, not the superuser, not a replication session, not the
// node's own namespace. No secret is in what Docker records of the container.
func TestNode_PlatformDBAccessAsTheServerReadsIt(t *testing.T) {
	a, ad := pdbOnNode(t)
	ctx := context.Background()
	root := pdbRoot(t, a)
	rows, err := root.Query(ctx, `select type, array_to_string(database, ','), array_to_string(user_name, ','), coalesce(address, ''),
		coalesce(netmask, ''), auth_method, coalesce(array_to_string(options, ','), ''), coalesce(error, '')
		from pg_catalog.pg_hba_file_rules order by rule_number`)
	if err != nil {
		t.Fatal(err)
	}
	var rules []string
	for rows.Next() {
		f := make([]string, 8)
		if err := rows.Scan(&f[0], &f[1], &f[2], &f[3], &f[4], &f[5], &f[6], &f[7]); err != nil {
			t.Fatal(err)
		}
		rules = append(rules, strings.Join(f, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"local|all|postgres|||peer|map=agent|",
		"host|supavisor|supavisor_meta|" + ad.Pooler.String() + "|255.255.255.255|scram-sha-256||"}
	if !slices.Equal(rules, want) {
		t.Errorf("rules as read:\n got %q\nwant %q", rules, want)
	}
	var maps string
	if err := root.QueryRow(ctx, `select string_agg(map_name || ' ' || sys_name || ' ' || pg_username || ' ' || coalesce(error, ''), ';')
		from pg_catalog.pg_ident_file_mappings`).Scan(&maps); err != nil || maps != "agent root postgres " {
		t.Errorf("mappings as read: %q, %v", maps, err)
	}

	pw, err := os.ReadFile(filepath.Join(a.p.PoolerSecrets(), "meta.password"))
	if err != nil {
		t.Fatal(err)
	}
	to := netip.AddrPortFrom(ad.PlatformDB, 5432)
	pooler := pdbClient(t, a, ad.Pooler)
	c, err := pdbLogin(pooler, to, "supavisor_meta", "supavisor", string(pw))
	if err != nil {
		t.Fatalf("control: the role from the pooler's address: %v", err)
	}
	c.Close(ctx)
	for what, try := range map[string][3]string{
		"the superuser to postgres":      {"postgres", "postgres", string(pw)},
		"the superuser to the registry":  {"postgres", "supavisor", string(pw)},
		"the role to template1":          {"supavisor_meta", "template1", string(pw)},
		"the role with the keyword all":  {"supavisor_meta", "all", string(pw)},
		"a role that does not exist":     {"sp_test_absent", "supavisor", string(pw)},
		"the role, upper case, unquoted": {"SUPAVISOR_META", "supavisor", string(pw)},
	} {
		if _, err := pdbLogin(pooler, to, try[0], try[1], try[2]); sqlState(err) != "28000" {
			t.Errorf("%s: %v (%s), want refused by the access file", what, err, sqlState(err))
		}
	}
	// A replication session of the role.
	cfg, _ := pgx.ParseConfig("")
	cfg.Host, cfg.Port, cfg.Database, cfg.User, cfg.Password = to.Addr().String(), to.Port(), "supavisor", "supavisor_meta", string(pw)
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	cfg.RuntimeParams = map[string]string{"replication": "true"}
	cfg.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) { return pooler(ctx, to) }
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	if _, err := pgx.ConnectConfig(rctx, cfg); sqlState(err) != "28000" {
		t.Errorf("replication session: %v (%s), want refused by the access file", err, sqlState(err))
	}
	cancel()

	// The same role and password from another platform address.
	other := netip.MustParseAddr(a.cfg.GatewayIP) // free on a bare node
	t.Cleanup(func() { nodeDockerQuiet("rm", "-f", pdbOtherName) })
	nodeDocker(t, "run", "-d", "--name", pdbOtherName, "--label", "supapace.test=1", "--network", platformNet, "--ip", other.String(),
		"--cap-drop", "ALL", "--user", "70:70", "--entrypoint", "sleep", a.cfg.Images.ControlPlane, "900")
	if _, err := pdbLogin(nsDialer(t, pdbOtherName), to, "supavisor_meta", "supavisor", string(pw)); sqlState(err) != "28000" {
		t.Errorf("the role from %s: %v (%s), want refused by the access file", other, err, sqlState(err))
	}

	// The node's own namespace: the platform address, and the node's loopback.
	for _, addr := range []string{to.String(), "127.0.0.1:5432", "[::1]:5432"} {
		if c, err := net.DialTimeout("tcp", addr, 3*time.Second); err == nil {
			c.Close()
			t.Errorf("%s answers from the node's own namespace", addr)
		}
	}

	// The superuser has no password, and the access file the initialisation
	// left in the data directory, which the server is never given, admits nobody.
	var noPW bool
	if err := root.QueryRow(ctx, "select rolpassword is null from pg_catalog.pg_authid where rolname = 'postgres'").Scan(&noPW); err != nil || !noPW {
		t.Errorf("the superuser has a password (%v)", err)
	}
	left, err := os.ReadFile(filepath.Join(a.pdbDir(), "data", "pg_hba.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(left), "\n") {
		if f := strings.Fields(l); len(f) > 0 && !strings.HasPrefix(f[0], "#") && f[len(f)-1] != "reject" {
			t.Errorf("the data directory's own access file admits: %q", l)
		}
	}

	insp, err := exec.Command("docker", "inspect", poolcfg.PlatformDBName).CombinedOutput()
	if err != nil || strings.Contains(string(insp), string(pw)) || strings.Contains(string(insp), "POSTGRES_PASSWORD") {
		t.Errorf("what Docker records of the container holds a secret or a password variable (%v)", err)
	}
}

// An initialisation that was killed part-way leaves a directory the server
// cannot start on; the next ensure must make the database again, not start
// the server on what is left.
func TestPlatformDB_InterruptedInitialisationIsMadeAgain(t *testing.T) {
	a := nodeAgent(t)
	a.cfg.PoolerLabel = "db"
	ad, err := poolcfg.For(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const initName = "sp-test-pdb-init"
	t.Cleanup(func() {
		nodeDockerQuiet("rm", "-f", initName)
		nodeDockerQuiet("rm", "-f", poolcfg.PlatformDBName)
		os.RemoveAll(a.pdbDir())
		os.RemoveAll(a.p.PoolerSecrets())
	})
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
	if _, err := a.ensurePDBDirs(ad); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(a.pdbDir(), "data")
	// The product's own initialisation, killed as soon as its first file is there.
	killed := false
	for try := 0; try < 5 && !killed; try++ {
		nodeDockerQuiet("rm", "-f", initName)
		if err := emptyDir(data); err != nil {
			t.Fatal(err)
		}
		nodeDocker(t, "run", "-d", "--name", initName, "--label", "supapace.test=1", "--network", "none", "--user", "65525:65525",
			"--cap-drop", "ALL", "--read-only", "--tmpfs", "/tmp", "-v", data+":/var/lib/postgresql/data",
			"--entrypoint", "sh", a.cfg.Images.ControlPlane, "-c", pdbInitScript)
		for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
			if _, err := os.Lstat(filepath.Join(data, "PG_VERSION")); err == nil {
				break
			}
		}
		nodeDockerQuiet("kill", initName)
		logs, _ := exec.Command("docker", "logs", initName).CombinedOutput()
		_, verr := os.Lstat(filepath.Join(data, "PG_VERSION"))
		killed = verr == nil && !strings.Contains(string(logs), "Success")
	}
	nodeDockerQuiet("rm", "-f", initName)
	if !killed {
		t.Skip("the initialisation ended before it could be killed, five times")
	}
	t.Cleanup(swap(&pdbAnswerWait, 45*time.Second))
	if err := a.EnsurePlatformDB(ctx); err != nil {
		logs, _ := exec.Command("docker", "logs", "--tail", "6", poolcfg.PlatformDBName).CombinedOutput()
		t.Fatalf("the ensure after a killed initialisation: %v\n%s", err, logs)
	}
	var one int
	if err := pdbRoot(t, a).QueryRow(ctx, "select 1").Scan(&one); err != nil {
		t.Fatal(err)
	}
}
