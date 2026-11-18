//go:build reach

package agent

// Cluster and task containers against a real Docker, the pinned cluster
// image, XFS quotas and the loaded firewall tables of a bare node, as root:
// go test -c -tags reach ./internal/agent, copy the binary and the daemon
// binary into the node, run there with CL_SUPAPACED naming the daemon binary
// (the tree-removal helper the task containers mount).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

func clRandom(t *testing.T, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// clNode prepares the node for one project: our tables loaded (the gate's
// condition 1), the platform networks, the image files, the project's
// directory and network. Everything is removed at cleanup.
func clNode(t *testing.T, ref string, slice, uid int) (*Agent, Spec) {
	t.Helper()
	a := nodeAgent(t)
	ctx := context.Background()
	exe := os.Getenv("CL_SUPAPACED")
	if fi, err := os.Stat(exe); err != nil || fi.Mode()&0o111 == 0 {
		t.Fatalf("CL_SUPAPACED must name the daemon binary: %q %v", exe, err)
	}
	restore := swap(&daemonExe, func() (string, error) { return exe, nil })
	t.Cleanup(restore)

	rules, err := nft.Render(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(a.p.NftFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.p.NftFile(), rules, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := nft.Load(ctx, a.p); err != nil {
		t.Fatal(err)
	}

	dek := []byte(clRandom(t, 32))
	s := Spec{Ref: ref, Epoch: 1, Generation: 1, UID: uid, GID: uid, SubnetIndex: slice, DiskQuotaMB: 1024, MemMB: 512, Pids: 512, FirstBoot: true,
		Secrets: bootstrap.Secrets{SupabaseAdminPassword: clRandom(t, 32), PostgresPassword: clRandom(t, 32),
			AuthenticatorPassword: clRandom(t, 32), PgsodiumRootKey: clRandom(t, 32), ScramSalts: map[string][]byte{}}}
	for _, r := range []string{"supabase_admin", "postgres", "authenticator"} {
		if s.Secrets.ScramSalts[r], err = pgsock.ScramSalt(dek, ref, r); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		ctx := context.Background()
		a.StopCluster(ctx, ref)
		for _, k := range []string{"wipe", "prevalidate", "purge"} {
			nodeDockerQuiet("rm", "-f", "task-"+ref+"-"+k)
		}
		a.RemoveNetwork(ctx, ref)
		os.RemoveAll(a.p.ProjectDir(ref)) // the harness, as root; the daemon never does this
		setQuota(a.p, uid, 0)
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
	if err := a.EnsureDir(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureNetwork(ctx, s); err != nil {
		t.Fatal(err)
	}
	return a, s
}

// clSession logs in as supabase_admin to the postmaster state.json records.
func clSession(t *testing.T, a *Agent, s Spec) *pgx.Conn {
	t.Helper()
	st, ok, err := a.readState(s.Ref)
	if err != nil || !ok || st.Phase != PhaseB {
		t.Fatalf("state %+v %v %v", st, ok, err)
	}
	conn, err := pgsock.Dial(context.Background(), a.clusterTarget(s, st, false))
	if err != nil {
		t.Fatalf("SCRAM login: %v", err)
	}
	t.Cleanup(func() { closeSession(conn) })
	return conn
}

func clExec(t *testing.T, c *pgx.Conn, sql string) {
	t.Helper()
	ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
	defer cancel()
	if _, err := c.Exec(ctx, sql); err != nil {
		t.Fatalf("%s: %v", sql, pgsock.Clean(err))
	}
}

func clInt(t *testing.T, c *pgx.Conn, sql string) int64 {
	t.Helper()
	ctx, cancel := pgsock.Stmt(context.Background(), pgsock.DefaultBudget)
	defer cancel()
	var n int64
	if err := c.QueryRow(ctx, sql).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, pgsock.Clean(err))
	}
	return n
}

type clInspect struct {
	ID    string
	State struct {
		Running   bool
		StartedAt string
		Pid       int
	}
	Config struct {
		User        string
		Healthcheck *struct{ Test []string }
	}
	HostConfig struct {
		NetworkMode    string
		ReadonlyRootfs bool
		CapDrop        []string
		CapAdd         []string
		SecurityOpt    []string
		RestartPolicy  struct{ Name string }
		IpcMode        string
		Sysctls        map[string]string
		Ulimits        []struct {
			Name       string
			Soft, Hard int64
		}
		Memory    int64
		PidsLimit int64
	}
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress string }
	}
}

func clInspectCtr(t *testing.T, name string) clInspect {
	t.Helper()
	var out []clInspect
	if err := json.Unmarshal([]byte(nodeDocker(t, "container", "inspect", name)), &out); err != nil || len(out) != 1 {
		t.Fatalf("inspect %s: %v", name, err)
	}
	return out[0]
}

func clTwoPhases(t *testing.T, a *Agent, s Spec) {
	t.Helper()
	ctx := context.Background()
	start := time.Now()
	if err := a.EnsureCluster(ctx, s); err != nil {
		t.Fatalf("phase A: %v", err)
	}
	if st, _, _ := a.readState(s.Ref); st.Phase != PhaseADone {
		t.Fatalf("after phase A: %+v", st)
	}
	if out := nodeDocker(t, "ps", "-aq", "--filter", "name=^pg-"+s.Ref+"$"); out != "" {
		t.Fatalf("phase-A container left: %s", out)
	}
	t.Logf("phase A: %v", time.Since(start))
	start = time.Now()
	if err := a.EnsureCluster(ctx, s); err != nil {
		t.Fatalf("phase B: %v", err)
	}
	t.Logf("first phase-B start: %v", time.Since(start))
}

// TestAgent_CreatesOneCluster: phase A then phase B bring one cluster up
// under the full hardening; the platform logs in by SCRAM; a second
// EnsureCluster at the same generation adopts it (StartedAt unchanged); the
// restart check passes a candidate; the purge leaves nothing behind.
func TestAgent_CreatesOneCluster(t *testing.T) {
	a, s := clNode(t, "nodetestcluster00001", 9, 700901)
	ctx := context.Background()
	// What an interrupted first boot leaves: initdb refuses a non-empty data
	// directory, so phase A passes only if the wipe emptied it (and kept it:
	// the cluster's data mount needs it).
	left := filepath.Join(a.p.ProjectDir(s.Ref), "data", "half", "initialised")
	if err := os.MkdirAll(left, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{left, filepath.Dir(left)} {
		os.Chown(p, s.UID, s.GID)
	}
	os.Chmod(filepath.Dir(left), 0) // the owner regains access by descriptor
	clTwoPhases(t, a, s)
	conn := clSession(t, a, s)
	if n := clInt(t, conn, "select count(*) from pg_catalog.pg_roles where rolname = 'supapace_backup'"); n != 1 {
		t.Fatalf("bootstrap did not run: %d", n)
	}
	closeSession(conn)

	name := clusterName(s.Ref)
	before := clInspectCtr(t, name)
	h := before.HostConfig
	nofile := false
	for _, u := range h.Ulimits {
		nofile = nofile || (u.Name == "nofile" && u.Soft == 65536 && u.Hard == 65536)
	}
	seccomp := false
	for _, o := range h.SecurityOpt {
		seccomp = seccomp || (strings.HasPrefix(o, "seccomp=") && strings.Contains(o, "SCMP_ACT_ERRNO"))
	}
	if !before.State.Running || before.Config.User != "700901:700901" || !h.ReadonlyRootfs || len(h.CapDrop) != 1 ||
		h.CapDrop[0] != "ALL" || len(h.CapAdd) != 0 || (h.RestartPolicy.Name != "" && h.RestartPolicy.Name != "no") ||
		h.IpcMode != "private" || h.Sysctls["net.ipv6.conf.all.disable_ipv6"] != "1" ||
		h.Sysctls["net.ipv4.ping_group_range"] != "1 0" || !nofile || !seccomp || h.Memory != 512<<20 || h.PidsLimit != 512 ||
		before.Config.Healthcheck == nil || len(before.Config.Healthcheck.Test) != 1 || before.Config.Healthcheck.Test[0] != "NONE" {
		t.Fatalf("cluster configuration: %+v", before)
	}
	if ip := before.NetworkSettings.Networks[networkName(s.Ref)].IPAddress; ip != a.cfg.ClusterAddr(s.SubnetIndex).String() ||
		len(before.NetworkSettings.Networks) != 1 {
		t.Fatalf("cluster networks: %+v", before.NetworkSettings.Networks)
	}

	if err := a.EnsureCluster(ctx, s); err != nil {
		t.Fatalf("second EnsureCluster: %v", err)
	}
	after := clInspectCtr(t, name)
	if after.ID != before.ID || after.State.StartedAt != before.State.StartedAt || after.State.Pid != before.State.Pid {
		t.Fatalf("adoption bounced the cluster: %s %s → %s %s", before.ID, before.State.StartedAt, after.ID, after.State.StartedAt)
	}
	if err := a.VerifyCluster(ctx, s); err != nil {
		t.Fatalf("VerifyCluster: %v", err)
	}
	drift, err := a.CheckCluster(ctx, s)
	if err != nil || len(drift) != 0 {
		t.Fatalf("CheckCluster: %v %+v", err, drift)
	}

	next := s
	next.Generation = 2
	next.GUC = map[string]string{"max_connections": "150"}
	if err := a.Prevalidate(ctx, next); err != nil {
		t.Fatalf("Prevalidate: %v", err)
	}
	if c := clInspectCtr(t, name); c.State.StartedAt != before.State.StartedAt {
		t.Fatal("the check touched the running cluster")
	}
	if out := nodeDocker(t, "ps", "-aq", "--filter", "label=supapace.role=task"); out != "" {
		t.Fatalf("task container left: %s", out)
	}

	if err := a.StopCluster(ctx, s.Ref); err != nil {
		t.Fatal(err)
	}
	if err := a.PurgeDir(ctx, s); err != nil {
		t.Fatalf("PurgeDir: %v", err)
	}
	if _, err := os.Lstat(a.p.ProjectDir(s.Ref)); !os.IsNotExist(err) {
		t.Fatalf("project directory after purge: %v", err)
	}
	if err := a.PurgeDir(ctx, s); err != nil {
		t.Fatalf("second PurgeDir: %v", err)
	}
}

// TestAgent_ResumeAfterKillBetweenRunAndStateWrite: with the cluster at
// phase B, state.json is put back to what the disk holds when the daemon
// dies between `docker run` and the state write; EnsureCluster removes the
// running container, runs a new one and records it; the data survives.
func TestAgent_ResumeAfterKillBetweenRunAndStateWrite(t *testing.T) {
	a, s := clNode(t, "nodetestcluster00002", 10, 700902)
	ctx := context.Background()
	clTwoPhases(t, a, s)
	conn := clSession(t, a, s)
	clExec(t, conn, "create table public.cl_resume (x int)")
	clExec(t, conn, "insert into public.cl_resume values (42)")
	closeSession(conn)
	old := clInspectCtr(t, clusterName(s.Ref))

	if err := a.writeState(s.Ref, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone}); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureCluster(ctx, s); err != nil {
		t.Fatalf("resume: %v", err)
	}
	now := clInspectCtr(t, clusterName(s.Ref))
	if now.ID == old.ID || !now.State.Running {
		t.Fatalf("old container %s, now %s running %v", old.ID, now.ID, now.State.Running)
	}
	if out := nodeDocker(t, "ps", "-aq", "--filter", "id="+old.ID); out != "" {
		t.Fatalf("old container still exists: %s", out)
	}
	st, _, _ := a.readState(s.Ref)
	if st.Phase != PhaseB || st.PMPid != now.State.Pid {
		t.Fatalf("state %+v, container pid %d", st, now.State.Pid)
	}
	conn = clSession(t, a, s)
	if n := clInt(t, conn, "select x from public.cl_resume"); n != 42 {
		t.Fatalf("data after the resume: %d", n)
	}
	if n := clInt(t, conn, "select count(*) from pg_catalog.pg_roles where rolname = 'supapace_backup'"); n != 1 {
		t.Fatalf("roles after the resume: %d", n)
	}
}

// TestAgent_StopAllTenants_SigtermIgnoringInit: two tenant containers whose
// init ignores SIGTERM (a pid 1 without a handler) are off every network and
// not running within 5 s.
func TestAgent_StopAllTenants_SigtermIgnoringInit(t *testing.T) {
	a := nodeAgent(t)
	net := "cl-stoptest"
	names := []string{"cl-stoptest-cluster", "cl-stoptest-postgrest"}
	cleanup := func() {
		for _, n := range names {
			nodeDockerQuiet("rm", "-f", n)
		}
		nodeDockerQuiet("network", "rm", net)
	}
	cleanup()
	t.Cleanup(cleanup)
	nodeDocker(t, "network", "create", "--internal", net)
	for i, role := range []string{"cluster", "postgrest"} {
		nodeDocker(t, "run", "-d", "--name", names[i], "--network", net, "--cap-drop", "ALL", "--label", "supapace.role="+role,
			"--entrypoint", "sleep", a.cfg.Images.ControlPlane, "600")
	}
	// Control: SIGTERM alone does not stop them.
	for _, n := range names {
		nodeDocker(t, "kill", "-s", "TERM", n)
	}
	time.Sleep(time.Second)
	for _, n := range names {
		if !clInspectCtr(t, n).State.Running {
			t.Fatalf("control: %s stopped on SIGTERM", n)
		}
	}
	start := time.Now()
	if err := a.StopAllTenants(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		for {
			c := clInspectCtr(t, n)
			if !c.State.Running && len(c.NetworkSettings.Networks) == 0 {
				break
			}
			if time.Since(start) > 5*time.Second {
				t.Fatalf("%s after 5 s: running %v networks %v", n, c.State.Running, c.NetworkSettings.Networks)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	t.Logf("stopped in %v", time.Since(start))
}

// TestAgent_TaskFailureReportsHelperMessage: a purge and a wipe that the
// tree-removal helper refuses report the helper's own message.
func TestAgent_TaskFailureReportsHelperMessage(t *testing.T) {
	a, s := clNode(t, "nodetestcluster00003", 11, 700903)
	ctx := context.Background()
	d := filepath.Join(a.p.ProjectDir(s.Ref), "data")
	if err := os.Remove(d); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", d); err != nil { // a link where the helper expects a directory
		t.Fatal(err)
	}
	os.Lchown(d, s.UID, s.GID)
	for name, run := range map[string]func() error{
		"purge": func() error { return a.PurgeDir(ctx, s) },
		"wipe":  func() error { return a.wipeData(ctx, s) },
	} {
		err := run()
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Lstat(a.p.ProjectDir(s.Ref)); err != nil {
		t.Fatalf("project directory: %v", err)
	}
}

// TestAgent_RefusesFirstBootOutsideCreate: a project directory with data and
// no state file is not given a first boot unless the caller is a create; the
// data stays as it was and nothing is started.
func TestAgent_RefusesFirstBootOutsideCreate(t *testing.T) {
	a, s := clNode(t, "nodetestcluster00004", 12, 700904)
	f := filepath.Join(a.p.ProjectDir(s.Ref), "data", "PG_VERSION")
	if err := os.WriteFile(f, []byte("17\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chown(f, s.UID, s.GID)
	s.FirstBoot = false
	if err := a.EnsureCluster(context.Background(), s); err == nil || !strings.Contains(err.Error(), "first boot") {
		t.Fatalf("got %v", err)
	}
	if b, err := os.ReadFile(f); err != nil || string(b) != "17\n" {
		t.Fatalf("data touched: %q %v", b, err)
	}
	if out := nodeDocker(t, "ps", "-aq", "--filter", "name="+s.Ref); out != "" {
		t.Fatalf("containers: %s", out)
	}
}

// TestAgent_PurgeAtFullQuota: a deep tree (deeper than PATH_MAX) written by
// the project's uid up to its block quota is purged: the limits are cleared
// before the task runs.
func TestAgent_PurgeAtFullQuota(t *testing.T) {
	a, s := clNode(t, "nodetestcluster00005", 13, 700905)
	s.DiskQuotaMB = 64
	if err := a.SetQuota(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	fill := func(script string) string {
		out, _ := exec.Command("docker", "run", "--rm", "--network", "none", "--user", fmt.Sprintf("%d:%d", s.UID, s.GID),
			"-v", a.p.ProjectDir(s.Ref)+":/p", "--entrypoint", "/bin/sh", a.cfg.Images.Postgres, "-c", script).CombinedOutput()
		return string(out)
	}
	// Built bottom-up by moves, so no path ever grows long.
	out := fill(`cd /p/data && mkdir x && i=0; while [ $i -lt 2500 ]; do mkdir t && mv x t/x && mv t x || exit 1; i=$((i+1)); done; ` +
		`dd if=/dev/zero of=fill bs=1M count=200 2>&1; echo depth=$i`)
	if !strings.Contains(out, "depth=2500") || !strings.Contains(strings.ToLower(out), "quota") {
		t.Fatalf("fill: %s", out)
	}
	if out := fill(`echo x > /p/data/more 2>&1 || echo refused`); !strings.Contains(out, "refused") {
		t.Fatalf("the uid is not at its quota: %s", out)
	}
	if err := a.PurgeDir(context.Background(), s); err != nil {
		t.Fatalf("PurgeDir at a full quota: %v", err)
	}
	if _, err := os.Lstat(a.p.ProjectDir(s.Ref)); !os.IsNotExist(err) {
		t.Fatalf("project directory after purge: %v", err)
	}
}

// TestAgent_AdoptionRefusalRemovesAtOnce: a running cluster that fails the
// adoption check (another container shares its network namespace with a
// capability added) is removed at once, not stopped with a grace period.
func TestAgent_AdoptionRefusalRemovesAtOnce(t *testing.T) {
	a, s := clNode(t, "nodetestcluster00006", 14, 700906)
	ctx := context.Background()
	clTwoPhases(t, a, s)
	sharer := "cl-sharer-" + s.Ref
	t.Cleanup(func() { nodeDockerQuiet("rm", "-f", sharer) })
	nodeDocker(t, "run", "-d", "--name", sharer, "--network", "container:"+clusterName(s.Ref), "--cap-drop", "ALL",
		"--cap-add", "NET_RAW", "--entrypoint", "sleep", a.cfg.Images.ControlPlane, "600")
	start := time.Now()
	err := a.EnsureCluster(ctx, s)
	took := time.Since(start)
	if !errors.Is(err, ErrContainment) {
		t.Fatalf("got %v", err)
	}
	if out := nodeDocker(t, "ps", "-aq", "--filter", "name=^"+clusterName(s.Ref)+"$"); out != "" {
		t.Fatalf("refused cluster still exists: %s", out)
	}
	if took > 10*time.Second {
		t.Fatalf("removal took %v", took)
	}
	t.Logf("refused and removed in %v", took)
}

// TestAgent_PurgeRefusedWhileClusterExists: a stopped pg-<ref> blocks the
// purge before the quota is lifted; once it is removed the purge succeeds.
func TestAgent_PurgeRefusedWhileClusterExists(t *testing.T) {
	a, s := clNode(t, "nodetestcluster00007", 15, 700907)
	ctx := context.Background()
	nodeDocker(t, "create", "--name", clusterName(s.Ref), "--network", "none", "--cap-drop", "ALL", a.cfg.Images.ControlPlane)
	if err := a.PurgeDir(ctx, s); err == nil || !strings.Contains(err.Error(), clusterName(s.Ref)) {
		t.Fatalf("purge with a stopped cluster: %v", err)
	}
	if _, err := os.Lstat(a.p.ProjectDir(s.Ref)); err != nil {
		t.Fatalf("project directory: %v", err)
	}
	if out := nodeDocker(t, "ps", "-aq", "--filter", "name=task-"+s.Ref); out != "" {
		t.Fatalf("task launched: %s", out)
	}
	nodeDocker(t, "rm", clusterName(s.Ref))
	if err := a.PurgeDir(ctx, s); err != nil {
		t.Fatalf("purge after removal: %v", err)
	}
	if _, err := os.Lstat(a.p.ProjectDir(s.Ref)); !os.IsNotExist(err) {
		t.Fatalf("project directory after purge: %v", err)
	}
}
