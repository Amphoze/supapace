//go:build reach

package agent

// Tests against a real Docker, real interfaces and the real image store of a
// bare node, as root: go test -c -tags reach ./internal/agent, copy the binary
// into the node, run it there. They change the node's networks and
// /var/lib/supapace and clean up after themselves.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

func nodeAgent(t *testing.T) *Agent {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root on a bare node")
	}
	c := nodecfg.Default("sp.test")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return New(c, nodecfg.Paths{})
}

func nodeDocker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func nodeDockerQuiet(args ...string) { exec.Command("docker", args...).Run() }

// TestNode_PlatformNetworks: platform's bridge spl0 exists and holds no IPv4
// address (the same check on the ingress bridge, which has one, fails); a
// project network passes conditions 2 to 6 for real, and real containers
// (running and created) fail conditions 3, 4 and 6 from their configuration;
// a foreign network is refused and still removed; the gate refuses on a node
// without our tables.
func TestNode_PlatformNetworks(t *testing.T) {
	a := nodeAgent(t)
	ctx := context.Background()
	s := Spec{Ref: "nodetest0agent000001", Epoch: 1, Generation: 1, SubnetIndex: 7}
	foreign := "nodetest0agent000002"
	cleanup := func() {
		for _, n := range []string{networkName(s.Ref), networkName(foreign), platformNet, ingressNet} {
			nodeDockerQuiet("network", "rm", n)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	if err := a.EnsurePlatformNetworks(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsurePlatformNetworks(ctx); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if err := a.checkBridgeIface(ctx, nodecfg.PlatformBridge); err != nil {
		t.Fatalf("spl0: %v", err)
	}
	if out, _ := exec.Command("ip", "-4", "-o", "addr", "show", "dev", nodecfg.PlatformBridge).Output(); len(out) != 0 {
		t.Fatalf("spl0 has an IPv4 address: %s", out)
	}
	if err := a.checkBridgeIface(ctx, nodecfg.IngressBridge); !errors.Is(err, ErrContainment) {
		t.Fatalf("control: spi0 has the host's address, the check must see it: %v", err)
	}
	if out, _ := exec.Command("ip", "-4", "-o", "addr", "show", "dev", nodecfg.IngressBridge).Output(); !strings.Contains(string(out), "10.212.8.1/24") {
		t.Fatalf("control: spi0 lacks the expected address: %s", out)
	}

	if err := a.EnsureNetwork(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureNetwork(ctx, s); err != nil {
		t.Fatalf("second EnsureNetwork: %v", err)
	}

	// The node check reads real Docker, ip and /proc output. On a bare node
	// these rows hold; nft fails (no tables loaded), the rest depend on init.
	got := map[string]nodecfg.CheckResult{}
	for _, r := range a.NodeCheck(ctx) {
		got[r.Name] = r
		t.Logf("node check: %s ok=%v %s", r.Name, r.OK, r.Detail)
	}
	for _, name := range []string{"docker-version", "docker-seccomp", "live-restore", "docker-networks", "uplinks",
		"quota-accounting", "quota-enforcement", "platform-members", "docker-firewall-backend"} {
		if !got[name].OK {
			t.Errorf("bare node: row %s = %+v", name, got[name])
		}
	}
	if got["nft"].OK || got["kek"].OK {
		t.Errorf("bare node: nft %+v kek %+v, want both failing", got["nft"], got["kek"])
	}
	if err := a.CheckAdopted(ctx, s); err != nil {
		t.Fatalf("conditions 2-6 on a real project network: %v", err)
	}

	// Conditions 3, 4 and 6 read Docker's record of real containers, running
	// and created: each fault refuses, each control passes.
	img := a.cfg.Images.ControlPlane
	member := "nodetest-member"
	pg, pr := clusterName(s.Ref), postgrestName(s.Ref)
	rmCtrs := func() {
		for _, n := range []string{member, member + "-raw", pg, pr} {
			nodeDockerQuiet("rm", "-f", n)
		}
	}
	rmCtrs()
	defer rmCtrs()
	adopted := func(want bool, what string) {
		t.Helper()
		err := a.CheckAdopted(ctx, s)
		if want && err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if !want && !errors.Is(err, ErrContainment) {
			t.Fatalf("%s: got %v, want ErrContainment", what, err)
		}
	}
	nodeDocker(t, "run", "-d", "--name", member, "--network", networkName(s.Ref), "--cap-drop", "ALL", "--entrypoint", "sleep", img, "300")
	adopted(true, "hardened member")
	nodeDocker(t, "network", "connect", "--ip", a.cfg.PlatformAddr(s.SubnetIndex).String(), platformNet, member)
	adopted(false, "a member holding the project's platform address")
	nodeDocker(t, "network", "disconnect", platformNet, member)
	adopted(true, "member disconnected from platform")
	nodeDocker(t, "run", "-d", "--name", member+"-raw", "--network", networkName(s.Ref), "--cap-drop", "ALL", "--cap-add", "NET_RAW",
		"--entrypoint", "sleep", img, "300")
	adopted(false, "a member configured with NET_RAW")
	nodeDocker(t, "rm", "-f", member+"-raw")
	nodeDocker(t, "create", "--name", pg, "--network", "none", "--cap-drop", "ALL", "--restart", "always", img)
	adopted(false, "a created cluster with a restart policy")
	nodeDocker(t, "rm", "-f", pg)
	nodeDocker(t, "create", "--name", pr, "--network", networkName(s.Ref), "--cap-drop", "ALL", img)
	nodeDocker(t, "network", "connect", "--ip", a.cfg.PlatformAddr(s.SubnetIndex+1).String(), platformNet, pr)
	adopted(false, "a created PostgREST at another project's platform address")
	nodeDocker(t, "network", "disconnect", platformNet, pr)
	nodeDocker(t, "network", "connect", "--ip", a.cfg.PlatformAddr(s.SubnetIndex).String(), platformNet, pr)
	adopted(true, "a created PostgREST at its own platform address")
	rmCtrs()

	if err := a.CheckContainment(ctx, s); !errors.Is(err, ErrContainment) {
		t.Fatalf("a bare node has no tables loaded; the gate must refuse: %v", err)
	}

	nodeDocker(t, "network", "create", "--internal", "--subnet", "10.214.0.64/26", networkName(foreign))
	if err := a.EnsureNetwork(ctx, Spec{Ref: foreign, SubnetIndex: 8}); !errors.Is(err, ErrContainment) {
		t.Fatalf("foreign network: %v", err)
	}
	if out := nodeDocker(t, "network", "ls", "-q", "--filter", "name=^"+networkName(foreign)+"$"); out == "" {
		t.Fatal("EnsureNetwork removed the foreign network")
	}
	for _, ref := range []string{foreign, s.Ref} {
		if err := a.RemoveNetwork(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if out := nodeDocker(t, "network", "ls", "-q", "--filter", "name=^"+networkName(ref)+"$"); out != "" {
			t.Fatalf("%s still there", networkName(ref))
		}
		if err := a.RemoveNetwork(ctx, ref); err != nil {
			t.Fatalf("absent: %v", err)
		}
	}
}

// TestNode_ImageFilesAndControlPlaneDB: the files taken out of the pinned
// cluster image equal what the image itself prints; the control-plane
// database starts with its hardened flags and the explicit seccomp profile
// and opens its socket.
func TestNode_ImageFilesAndControlPlaneDB(t *testing.T) {
	a := nodeAgent(t)
	ctx := context.Background()
	t.Cleanup(func() {
		nodeDockerQuiet("rm", "-f", cpName)
		os.RemoveAll(a.p.CPDir())
		os.RemoveAll(a.p.PlatformDir())
	})

	if err := a.EnsureImageFiles(ctx); err != nil {
		t.Fatal(err)
	}
	dir := a.p.ImageDir(a.cfg.Images.Postgres)
	check := func(local, inImage string) {
		b, err := os.ReadFile(filepath.Join(dir, local))
		if err != nil {
			t.Fatal(err)
		}
		want, err := exec.Command("docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", a.cfg.Images.Postgres, inImage).Output()
		if err != nil {
			t.Fatalf("cat %s in the image: %v", inImage, err)
		}
		if string(b) != string(want) {
			t.Errorf("%s differs from the image's %s", local, inImage)
		}
		if fi, _ := os.Lstat(filepath.Join(dir, local)); fi.Mode() != 0o444 {
			t.Errorf("%s mode %v", local, fi.Mode())
		}
	}
	check("passwd", "/etc/passwd")
	check("group", "/etc/group")
	check("supautils.conf", "/etc/postgresql-custom/supautils.conf")
	check("postgresql.conf", "/etc/postgresql/postgresql.conf")
	ents, err := os.ReadDir(filepath.Join(dir, "conf.d"))
	if err != nil || len(ents) == 0 {
		t.Fatalf("conf.d: %v %v", ents, err)
	}
	for _, e := range ents {
		check("conf.d/"+e.Name(), "/etc/postgresql-custom/conf.d/"+e.Name())
	}
	if out := nodeDocker(t, "ps", "-aq", "--filter", "label=supapace.role=task"); out != "" {
		t.Fatalf("extract container left: %s", out)
	}

	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(a.p.CPDir(), "sock", ".s.PGSQL.5432")
	// The socket file exists from the bind, before the server listens: wait
	// for a dial that succeeds.
	deadline := time.Now().Add(90 * time.Second)
	for {
		c, err := net.DialTimeout("unix", sock, time.Second)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "20", cpName).CombinedOutput()
			t.Fatalf("nothing listens at %s: %v: %s", sock, err, logs)
		}
		time.Sleep(time.Second)
	}
	var insp []struct {
		State      struct{ Running bool }
		Config     struct{ User string }
		HostConfig struct {
			NetworkMode    string
			ReadonlyRootfs bool
			CapDrop        []string
			CapAdd         []string
			SecurityOpt    []string
			RestartPolicy  struct{ Name string }
			Memory         int64
			PidsLimit      int64
		}
	}
	if err := json.Unmarshal([]byte(nodeDocker(t, "container", "inspect", cpName)), &insp); err != nil || len(insp) != 1 {
		t.Fatal(err)
	}
	h := insp[0].HostConfig
	seccomp := false
	for _, o := range h.SecurityOpt {
		seccomp = seccomp || (strings.HasPrefix(o, "seccomp=") && strings.Contains(o, "SCMP_ACT_ERRNO"))
	}
	if !insp[0].State.Running || insp[0].Config.User != "70:70" || h.NetworkMode != "none" || !h.ReadonlyRootfs ||
		len(h.CapDrop) != 1 || h.CapDrop[0] != "ALL" || len(h.CapAdd) != 0 || h.RestartPolicy.Name != "unless-stopped" ||
		h.Memory != 256<<20 || h.PidsLimit != 128 || !seccomp {
		t.Fatalf("sp-cp-db configuration: %+v %+v", insp[0], h)
	}
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatalf("second call: %v", err)
	}
}

// TestNode_QuotaEnforcementRow: the quota rows follow XFS's live state, not
// only the mount options given at mount time: turning user-quota enforcement
// off at run time fails quota-enforcement (accounting still holds), turning
// it on again passes.
func TestNode_QuotaEnforcementRow(t *testing.T) {
	a := nodeAgent(t)
	ctx := context.Background()
	xq := func(cmd string) {
		t.Helper()
		out, err := exec.Command("xfs_quota", "-x", "-c", cmd, a.p.ProjectsDir()).CombinedOutput()
		if err != nil || len(out) != 0 {
			t.Fatalf("xfs_quota %s: %v %s", cmd, err, out)
		}
	}
	rows := func() map[string]nodecfg.CheckResult {
		m := map[string]nodecfg.CheckResult{}
		for _, r := range a.NodeCheck(ctx) {
			m[r.Name] = r
		}
		return m
	}
	if r := rows(); !r["quota-enforcement"].OK || !r["quota-accounting"].OK {
		t.Fatalf("control: %+v %+v", r["quota-enforcement"], r["quota-accounting"])
	}
	xq("disable -u")
	t.Cleanup(func() { exec.Command("xfs_quota", "-x", "-c", "enable -u", a.p.ProjectsDir()).Run() })
	if r := rows(); r["quota-enforcement"].OK || !r["quota-accounting"].OK {
		t.Fatalf("enforcement off: %+v %+v", r["quota-enforcement"], r["quota-accounting"])
	}
	xq("enable -u")
	if r := rows(); !r["quota-enforcement"].OK {
		t.Fatalf("enforcement on again: %+v", r["quota-enforcement"])
	}
}
