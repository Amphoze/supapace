//go:build reach

package reach

// Containment: what a project's containers cannot reach, and the posture they
// run under. The database server of a project is untrusted: every probe runs
// inside the real container's namespace at its uid, and every negative stands
// next to a control on the same path that turns positive when exactly one
// barrier is removed.

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

const (
	preDockerd   = "/var/lib/sp/boot/pre-dockerd.txt" // written by the harness node between the rules load and dockerd
	toolsInPG    = "/opt/supapace/tools/sp-probe"     // the probe as a cluster sees it (read-only tools mount)
	probeInREST  = "/etc/postgrest/sp-probe"          // the probe as PostgREST sees it (its read-only config mount)
	includeDir   = "/etc/postgresql-custom/conf.d"
	externalName = "example.com" // the reserved documentation domain: resolvable wherever upstream DNS works
	rebootEnv    = "SUPAPACE_REBOOT"
	bootCount    = "/var/lib/sp/boot/count" // the harness node's boot counter, rewritten first at every boot
)

// phaseBMounts are the mount targets the platform gives a running cluster.
var phaseBMounts = []string{
	"/var/lib/postgresql/data", "/var/run/postgresql", "/etc/passwd", "/etc/group",
	"/etc/postgresql-custom/pgsodium_root.key", includeDir, "/etc/postgresql-custom/supautils.conf",
	"/etc/postgresql/pg_hba.conf", "/etc/postgresql/pg_ident.conf", "/opt/supapace/tools",
}

func pgName(p Project) string   { return "pg-" + p.Ref }
func restName(p Project) string { return "postgrest-" + p.Ref }

func gatewayIP(t testing.TB) netip.Addr {
	t.Helper()
	ip, err := netip.ParseAddr(nodeConf(t).GatewayIP)
	if err != nil {
		t.Fatalf("node config: gateway_ip: %v", err)
	}
	return ip
}

// placeProbe copies sp-probe into a root-owned directory a container mounts
// read-only (a project's tools or PostgREST directory) for the test's duration.
func placeProbe(t testing.TB, dir string) {
	t.Helper()
	b, err := os.ReadFile(probeBin)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "sp-probe")
	t.Cleanup(func() {
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			t.Errorf("removing %s: %v", dst, err)
		}
	})
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		t.Fatal(err)
	}
}

// topology asserts the network attachments of A's and B's containers and of
// the gateway — each container on exactly its networks, at its addresses —
// and returns them by container name. Sweep expectations come from these.
func topology(t testing.TB, A, B Project) map[string][]link {
	t.Helper()
	conf := nodeConf(t)
	ingress, err := netip.ParseAddr(conf.GatewayIngressIP)
	if err != nil {
		t.Fatalf("node config: gateway_ingress_ip: %v", err)
	}
	out := map[string][]link{
		gatewayName: assertTopology(t, gatewayName, map[string]netip.Addr{"ingress": ingress, "platform": gatewayIP(t)}),
	}
	for _, p := range []Project{A, B} {
		out[pgName(p)] = assertTopology(t, pgName(p), map[string]netip.Addr{"proj-" + p.Ref: conf.ClusterAddr(p.SubnetIndex)})
		out[restName(p)] = assertTopology(t, restName(p), map[string]netip.Addr{
			"proj-" + p.Ref: conf.PostgRESTAddr(p.SubnetIndex), "platform": conf.PlatformAddr(p.SubnetIndex)})
	}
	return out
}

// probeIn places the probe where container sees it and returns that path.
func probeIn(t testing.TB, p Project, container string) string {
	t.Helper()
	if container == restName(p) {
		placeProbe(t, filepath.Join(paths.RenderDir(p.Ref), "postgrest"))
		return probeInREST
	}
	placeProbe(t, filepath.Join(paths.RenderDir(p.Ref), "tools"))
	return toolsInPG
}

// ───────── test 3 ─────────

// TestReach03_ClusterEgress: from pg-A's namespace at its uid nothing opens to
// the node's listeners and canaries, the other members of its bridge, pg-B, the
// platform network, the metadata endpoints or the private ranges; an external
// name does not resolve; no ICMP socket can be created. The second ring repeats
// the sweep from postgrest-A. Each rule is shown to be the barrier on a
// scratch bridge of the same class that has the route the real one lacks.
func TestReach03_ClusterEgress(t *testing.T) {
	A, B := fixtureAB(t)
	clusterEgress(t, A, B)
}

func clusterEgress(t *testing.T, A, B Project) {
	conf := nodeConf(t)
	pgA, restA := pgName(A), restName(A)
	brA := nodecfg.BridgeName(A.SubnetIndex)
	clusterA := netip.AddrPortFrom(conf.ClusterAddr(A.SubnetIndex), 5432)

	topo := topology(t, A, B)
	wantVerdict(t, "control (a): postgrest-A → pg-A:5432", restA, "connected", "tcp", clusterA.String())

	// Canaries: every host address and both wildcards, LLMNR and mDNS, and the
	// fe80:: of A's project bridge (always present on an isolated bridge) and of
	// the platform bridge.
	groups := canaries(t, []string{brA, nodecfg.PlatformBridge})
	ring := slices.Concat(hostTargets(t, nsListeners(t, "")), groups, fixedTargets())

	t.Run("from_pg_A", func(t *testing.T) {
		gw := gatewayIP(t)
		sweep(t, pgA, topo[pgA], slices.Concat(ring, []target{
			{"pg-B", "tcp", netip.AddrPortFrom(conf.ClusterAddr(B.SubnetIndex), 5432)},
			{"postgrest-B on its project bridge", "tcp", netip.AddrPortFrom(conf.PostgRESTAddr(B.SubnetIndex), 3000)},
			{"the gateway on the platform bridge", "tcp", netip.AddrPortFrom(gw, 8443)},
			{"postgrest-A on the platform bridge", "tcp", netip.AddrPortFrom(conf.PlatformAddr(A.SubnetIndex), 3000)},
			{"postgrest-B on the platform bridge", "tcp", netip.AddrPortFrom(conf.PlatformAddr(B.SubnetIndex), 3000)},
		}))
	})

	t.Run("bridge_members_d", func(t *testing.T) {
		// Every other member of A's bridge, on every TCP port it listens on: dropped
		// by the bridge policy (B3 admits only the cluster's 5432), reached once an
		// accept for that bridge is inserted.
		var dsts []string
		members := networkMembers(t, "proj-"+A.Ref)
		if !slices.Equal(members, []string{pgA, restA}) {
			t.Fatalf("members of proj-%s: %v, want exactly %s and %s", A.Ref, members, pgA, restA)
		}
		for _, m := range members {
			if m == pgA {
				continue
			}
			var own netip.Addr
			for _, l := range topo[m] {
				if l.Bridge == brA {
					own = l.Prefix.Addr()
				}
			}
			for _, l := range nsListeners(t, m) {
				ip := l.Addr.Addr()
				switch {
				case ip.IsLoopback() || ip.Is6():
				case l.Proto == "udp":
					t.Logf("%s listens on udp %v: not probed (no echo behind it to show a control)", m, l.Addr)
				case ip.IsUnspecified():
					dsts = append(dsts, netip.AddrPortFrom(own, l.Addr.Port()).String())
				case ip == own:
					dsts = append(dsts, l.Addr.String())
				}
			}
		}
		if len(dsts) == 0 {
			t.Fatalf("no other member of %s listens on TCP: the member probe would have nothing to reach", brA)
		}
		for _, d := range dsts {
			wantVerdict(t, "pg-A → bridge member", pgA, "timeout", "tcp", d)
		}
		withRuleInserted(t, "bridge supapace", "forward", fmt.Sprintf(`meta ibrname %q ether type ip accept`, brA), func() {
			for _, d := range dsts {
				wantVerdict(t, "control (d): pg-A → bridge member with an accept inserted for "+brA, pgA, "connected", "tcp", d)
			}
		})
	})

	t.Run("dns_e", func(t *testing.T) {
		driftHold(t) // before the scratch bridge exists, released after it is gone
		// Docker's resolver may take more than a second for its first upstream answer.
		got := probeVerdict(t, pgA, "dns", pgA, "--server", "127.0.0.11", "--timeout", "5s")
		if !strings.HasPrefix(got, "answered ") || !slices.Contains(strings.Fields(got), conf.ClusterAddr(A.SubnetIndex).String()) {
			t.Fatalf("control (e): the resolver in pg-A answered %q for %s, want its address", got, pgA)
		}
		wantVerdict(t, "external name from pg-A", pgA, "negative SERVFAIL", "dns", externalName, "--server", "127.0.0.11", "--timeout", "5s")
		// The same question from a member of a bridge that differs only in not
		// being internal is answered: the name exists and Docker's resolver would
		// forward it.
		net8, _ := scratchBridge(t, "spp9998", false)
		m := member(t, "sp-test-dns", net8)
		if got := probeVerdict(t, m, "dns", externalName, "--server", "127.0.0.11", "--timeout", "5s"); !strings.HasPrefix(got, "answered ") {
			t.Fatalf("control: the external name from a member of a non-internal bridge: %q, want an answer (has the node upstream DNS?)", got)
		}
	})

	t.Run("second_ring_from_postgrest_A", func(t *testing.T) {
		sweep(t, restA, topo[restA], ring)
	})

	t.Run("icmp", func(t *testing.T) {
		for _, c := range []string{pgA, restA} {
			rep := execSys(t, c, probeIn(t, A, c))
			if rep.Calls["socket-icmp"] != "errno 13 EACCES" || rep.Calls["socket-raw"] != "errno 1 EPERM" {
				t.Errorf("%s: socket-icmp %q, socket-raw %q; want errno 13 EACCES and errno 1 EPERM", c, rep.Calls["socket-icmp"], rep.Calls["socket-raw"])
			}
			img := imageOf(t, c)
			// The ping-socket sysctl removed: an ICMP datagram socket opens.
			f := containerFlags(t, c)
			f.Binds = nil // the probe reads no file; a root control gets none of the project's
			delete(f.Sysctls, "net.ipv4.ping_group_range")
			if got := imageSys(t, "sp-test-icmp", img, append([]string{"--network", "none"}, f.args()...)...).Calls["socket-icmp"]; got != "ok" {
				t.Errorf("control: %s's image without the ping sysctl: socket-icmp %q, want ok", c, got)
			}
			// Root (explicitly: the PostgREST image's own user is not root) with
			// Docker's default capabilities: a raw socket opens; the same
			// container with every capability dropped cannot.
			f = containerFlags(t, c)
			f.User, f.CapDrop, f.CapAdd, f.Binds = "0:0", nil, nil, nil
			if got := imageSys(t, "sp-test-raw", img, append([]string{"--network", "none"}, f.args()...)...).Calls["socket-raw"]; got != "ok" {
				t.Errorf("control: %s's image as root with default capabilities: socket-raw %q, want ok", c, got)
			}
			f.CapDrop = []string{"ALL"}
			if got := imageSys(t, "sp-test-raw-drop", img, append([]string{"--network", "none"}, f.args()...)...).Calls["socket-raw"]; got != "errno 1 EPERM" {
				t.Errorf("control: the same as root with every capability dropped: socket-raw %q, want errno 1 EPERM", got)
			}
		}
	})

	t.Run("control_c_g_input_rule_and_ipv6", func(t *testing.T) { controlI2AndIPv6(t) })
	t.Run("control_f_routed", func(t *testing.T) { controlRouted(t) })
}

// ───────── test 4 ─────────

// TestReach04_UnknownBridge: a project network created without the
// bridge-name option is refused by the start gate (the create fails with
// containment_failed and no cluster container exists); with the gate bypassed,
// two members of a non-internal unnamed bridge and two of docker0 reach
// neither the host, nor each other, nor a routed address until both of our
// tables are deleted.
func TestReach04_UnknownBridge(t *testing.T) {
	fixtureAB(t)
	t.Run("gate", func(t *testing.T) {
		driftHold(t) // before the unnamed network exists, released after it is gone
		ref := randomRef(t)
		scratchNet(t, "proj-"+ref, "--internal")
		fixtureScratch(t, "--ref", ref, "--no-wait")
		op := waitOp(t, newestOp(t, ref).ID)
		if op.State != "failed" || !strings.HasPrefix(op.LastError, "containment_failed") {
			t.Fatalf("create on an unnamed project bridge: operation %s at step %q (%q), want failed with containment_failed", op.State, op.Step, op.LastError)
		}
		for _, c := range []string{"pg-", "postgrest-"} {
			if ids := strings.Fields(docker(t, "ps", "-aq", "--filter", "name=^"+c+ref+"$")); len(ids) != 0 {
				t.Errorf("%s%s exists although the gate refused", c, ref)
			}
		}
	})
	t.Run("bypass", func(t *testing.T) { bypassUnknownBridges(t) })
}

func randomRef(t testing.TB) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 20)
	for i := range b {
		var r [1]byte
		for {
			rand.Read(r[:])
			if int(r[0]) < 252 { // 252 = 7 × 36: no modulo bias
				break
			}
		}
		b[i] = alphabet[int(r[0])%len(alphabet)]
	}
	return string(b)
}

// newestOp is the newest operation of ref.
func newestOp(t testing.TB, ref string) Op {
	t.Helper()
	out, code := cli(t, "op", "list", ref)
	var ops opsJSON
	decode(t, "op list", out, &ops)
	if code != 0 || len(ops.Operations) == 0 {
		t.Fatalf("op list %s: exit %d, %d operations", ref, code, len(ops.Operations))
	}
	return ops.Operations[0]
}

// ───────── test 5 ─────────

// TestReach05_BootRestartReload: no tenant container has a restart policy;
// after `project restart A` test 3 passes again and pg-A keeps its address; a
// reload leaves Docker's rules byte-identical; with one rule deleted the
// presence check fails and a restart of A ends failed with containment_failed
// while A's containers stay down, and once the tables are reloaded a retry of
// that same operation completes.
func TestReach05_BootRestartReload(t *testing.T) {
	A, B := fixtureAB(t)
	conf := nodeConf(t)

	t.Run("no_restart_policy", func(t *testing.T) {
		policy := func(c string) string {
			return strings.TrimSpace(docker(t, "inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", c))
		}
		if got := policy(gatewayName); got != "unless-stopped" {
			t.Fatalf("control: %s's restart policy reads %q, want unless-stopped", gatewayName, got)
		}
		for _, p := range []Project{A, B} {
			for _, c := range []string{pgName(p), restName(p)} {
				if got := policy(c); got != "" && got != "no" {
					t.Errorf("%s has restart policy %q", c, got)
				}
			}
		}
	})

	t.Run("restart_then_egress", func(t *testing.T) {
		out, code := cli(t, "project", "restart", A.Ref)
		var op Op
		decode(t, "project restart", out, &op)
		if code != 0 || op.State != "done" {
			t.Fatalf("project restart A: exit %d, operation %s at step %q: %s", code, op.State, op.Step, op.LastError)
		}
		if got := containerLinks(t, pgName(A))[nodecfg.BridgeName(A.SubnetIndex)].Addr; got != conf.ClusterAddr(A.SubnetIndex) {
			t.Fatalf("pg-A came back at %v, want %v", got, conf.ClusterAddr(A.SubnetIndex))
		}
		waitServed(t, A)
		clusterEgress(t, A, B)
	})

	t.Run("reload_keeps_docker_rules", func(t *testing.T) {
		before := dockerRules(t)
		must(t, cmdTimeout, daemonBin, "nft", "load")
		if after := dockerRules(t); after != before {
			t.Fatalf("Docker's rules changed across a reload of ours (%d → %d bytes)", len(before), len(after))
		}
	})

	var failed int64
	t.Cleanup(func() { recoverRestart(t, A, failed) })
	t.Run("gate_refuses_with_a_rule_deleted", func(t *testing.T) {
		withRuleDeleted(t, "bridge supapace", "forward", "B3", func() {
			if r, err := run(cmdTimeout, nil, daemonBin, "nft", "check"); err != nil || r.code == 0 {
				t.Fatalf("supapaced nft check with B3 deleted: %v exit %d, want a failure", err, r.code)
			}
			out, _ := cli(t, "project", "restart", A.Ref)
			var op Op
			decode(t, "project restart", out, &op)
			failed = op.ID
			if op.State != "failed" || !strings.HasPrefix(op.LastError, "containment_failed") {
				t.Fatalf("project restart A with B3 deleted: operation %s at step %q (%q), want failed with containment_failed", op.State, op.Step, op.LastError)
			}
			for _, c := range []string{pgName(A), restName(A)} {
				if running(t, c) {
					t.Errorf("%s runs although the gate refused", c)
				}
			}
		})
	})
	if failed == 0 {
		t.Fatal("no refused restart to retry")
	}
	// The hold is gone and the tables are reloaded and checked (withRuleDeleted).
	out, code := cli(t, "op", "retry", strconv.FormatInt(failed, 10))
	var op Op
	decode(t, "op retry", out, &op)
	if code != 0 || op.ID != failed || op.State != "done" {
		t.Fatalf("op retry %d: exit %d, operation %d %s at step %q: %s", failed, code, op.ID, op.State, op.Step, op.LastError)
	}
	failed = 0
	if st := projectState(t, A.Ref); st != "active" {
		t.Fatalf("A is %s after the retried restart, want active", st)
	}
	waitServed(t, A)
}

// recoverRestart retries a refused restart of p left behind by a failed test,
// so later tests find p active.
func recoverRestart(t testing.TB, p Project, id int64) {
	if id == 0 || projectState(t, p.Ref) == "active" {
		return
	}
	if _, code := cli(t, "op", "retry", strconv.FormatInt(id, 10)); code != 0 || projectState(t, p.Ref) != "active" {
		t.Errorf("project %s left %s after retrying operation %d", p.Ref, projectState(t, p.Ref), id)
	}
}

func projectState(t testing.TB, ref string) string {
	t.Helper()
	out, code := cli(t, "project", "show", ref)
	var pj projectJSON
	decode(t, "project show", out, &pj)
	if code != 0 {
		t.Fatalf("project show %s: exit %d", ref, code)
	}
	return pj.State
}

// dockerRules is every rule on the node except our two tables: `nft -s list
// ruleset` without them, plus the legacy iptables dumps (comment lines, which
// carry a time, removed) where those tools exist. It fails the test unless our
// tables were in the listing and something of Docker's remains.
func dockerRules(t testing.TB) string {
	t.Helper()
	var keep []string
	skip, ours := false, 0
	for line := range strings.Lines(must(t, cmdTimeout, "nft", "-s", "list", "ruleset")) {
		switch {
		case line == "table inet supapace {\n" || line == "table bridge supapace {\n":
			skip = true
			ours++
		case skip && line == "}\n":
			skip = false
		case !skip:
			keep = append(keep, line)
		}
	}
	for _, tool := range []string{"iptables-legacy-save", "ip6tables-legacy-save"} {
		if _, err := exec.LookPath(tool); err == nil {
			for line := range strings.Lines(must(t, cmdTimeout, tool)) {
				if !strings.HasPrefix(line, "#") {
					keep = append(keep, tool+": "+line)
				}
			}
		}
	}
	rest := strings.Join(keep, "")
	if ours != 2 || !strings.Contains(strings.ToUpper(rest), "DOCKER") {
		t.Fatalf("ruleset listing: %d of our tables found, Docker's chains present: %v", ours, strings.Contains(strings.ToUpper(rest), "DOCKER"))
	}
	return rest
}

// TestReach05_AfterReboot (run by make reach-reboot): the rules were loaded
// before dockerd in this boot, and no tenant container ran when the daemon's
// first serve of the boot started. Meaningful only when A and B existed before
// the last boot; otherwise it skips and says so — and fails instead when the
// reboot target selected it (SUPAPACE_REBOOT=1).
func TestReach05_AfterReboot(t *testing.T) {
	if os.Getenv("SUPAPACE_HOST") == "1" {
		t.Skip("on a host the boot order is the host tests' subject")
	}
	skip := t.Skipf
	if os.Getenv(rebootEnv) == "1" {
		skip = t.Fatalf
	}
	A, B := fixtureAB(t)
	var boot struct {
		StartedAt time.Time `json:"started_at"`
		NftOK     *bool     `json:"nft_ok"`
		Tenants   *[]string `json:"tenants_running_at_start"`
	}
	b, err := os.ReadFile(paths.BootJSON())
	if err != nil {
		t.Fatalf("boot record: %v", err)
	}
	if err := json.Unmarshal(b, &boot); err != nil || boot.StartedAt.IsZero() || boot.NftOK == nil || boot.Tenants == nil {
		t.Fatalf("boot record %s: %v (a member missing)", paths.BootJSON(), err)
	}
	for _, p := range []Project{A, B} {
		if created := createdAt(t, p.Ref); !created.Before(boot.StartedAt) {
			skip("project %s was created after the last boot (%v ≥ %v): no tenant could have run before it; run make reach-reboot", p.Ref, created, boot.StartedAt)
		}
	}
	// The pre-dockerd record belongs to this boot: written after the boot
	// counter (the boot's first write) and before the first serve.
	counted, err := os.Stat(bootCount)
	if err != nil {
		t.Fatalf("boot counter: %v", err)
	}
	preInfo, err := os.Stat(preDockerd)
	if err != nil {
		t.Fatalf("pre-dockerd record: %v", err)
	}
	if preInfo.ModTime().Before(counted.ModTime()) || preInfo.ModTime().After(boot.StartedAt) {
		t.Fatalf("pre-dockerd record written %v, outside this boot (counter %v, first serve %v)", preInfo.ModTime(), counted.ModTime(), boot.StartedAt)
	}
	pre, err := os.ReadFile(preDockerd)
	if err != nil {
		t.Fatalf("pre-dockerd record: %v", err)
	}
	lines := strings.Split(string(pre), "\n")
	for _, tb := range []string{"table inet supapace", "table bridge supapace"} {
		if !slices.Contains(lines, tb) {
			t.Errorf("%s was not listed before dockerd started", tb)
		}
	}
	if !*boot.NftOK {
		t.Error("the boot record says the rules check failed at the first serve")
	}
	if len(*boot.Tenants) != 0 {
		t.Errorf("tenant containers ran before the daemon started them: %v", *boot.Tenants)
	}
	// Control: the tenants that existed before the boot run now — the empty list
	// is not an empty node.
	for _, p := range []Project{A, B} {
		for _, c := range []string{pgName(p), restName(p)} {
			if !running(t, c) {
				t.Errorf("control: %s is not running after the boot", c)
			}
		}
	}
}

func createdAt(t testing.TB, ref string) time.Time {
	t.Helper()
	out, code := cli(t, "project", "show", ref)
	var pj struct {
		CreatedAt time.Time `json:"created_at"`
	}
	decode(t, "project show", out, &pj)
	if code != 0 || pj.CreatedAt.IsZero() {
		t.Fatalf("project show %s: exit %d, no created_at", ref, code)
	}
	return pj.CreatedAt
}

// ───────── test 6 ─────────

// TestReach06_Container: identity and directories, configuration, the posture
// seen from inside both containers with its unconfined control, no NET_RAW or
// NET_ADMIN on any project, platform or ingress bridge, no healthcheck, private
// IPC, the open-files limit, and only the project's files mounted.
func TestReach06_Container(t *testing.T) {
	A, B := fixtureAB(t)
	conf := nodeConf(t)
	pgA, restA := pgName(A), restName(A)
	topology(t, A, B)

	t.Run("identity", func(t *testing.T) {
		_, uidA, gidA := containerIdentity(t, pgA)
		_, uidB, gidB := containerIdentity(t, pgName(B))
		if uidA != A.UID || uidB != B.UID || uidA == uidB || gidA == gidB {
			t.Fatalf("pg-A runs as %d:%d, pg-B as %d:%d (projects %d, %d): want each its own uid and gid", uidA, gidA, uidB, gidB, A.UID, B.UID)
		}
		for _, id := range []int{uidA, gidA, uidB, gidB} {
			if id < conf.UIDBase || id >= conf.UIDBase+conf.UIDCount {
				t.Errorf("id %d outside the reserved range [%d, %d)", id, conf.UIDBase, conf.UIDBase+conf.UIDCount)
			}
		}
		if err := readDirAs(uidA, gidA, paths.ProjectDir(A.Ref)); err != nil {
			t.Fatalf("control: A's uid cannot read its own directory: %v", err)
		}
		if err := readDirAs(uidA, gidA, paths.ProjectDir(B.Ref)); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("A's uid reading B's directory: %v, want permission denied", err)
		}
	})

	t.Run("configuration", func(t *testing.T) {
		profile, err := os.ReadFile(filepath.Join(paths.PlatformDir(), "seccomp.json"))
		if err != nil {
			t.Fatalf("the platform's seccomp profile: %v", err)
		}
		for _, c := range []string{pgA, restA} {
			f := containerFlags(t, c)
			if f.Privileged || !hasCap(f.CapDrop, "ALL") || len(f.CapAdd) != 0 {
				t.Errorf("%s: privileged %v, cap-drop %v, cap-add %v; want cap-drop ALL and nothing added", c, f.Privileged, f.CapDrop, f.CapAdd)
			}
			if !f.NoNewPrivs || !f.ReadOnly {
				t.Errorf("%s: no-new-privileges %v, read-only root %v", c, f.NoNewPrivs, f.ReadOnly)
			}
			if f.SeccompJSON == nil || !sameJSON(f.SeccompJSON, profile) {
				t.Errorf("%s: not created with the platform's seccomp profile", c)
			}
		}
		// IPv6 disabled in every container of A and B: configured, and in effect
		// in its namespace.
		for _, p := range []Project{A, B} {
			for _, c := range []string{pgName(p), restName(p)} {
				if v := containerFlags(t, c).Sysctls["net.ipv6.conf.all.disable_ipv6"]; v != "1" {
					t.Errorf("%s: net.ipv6.conf.all.disable_ipv6 configured %q, want 1", c, v)
				}
				cpid, _ := containerPid(t, c)
				got := strings.TrimSpace(must(t, cmdTimeout, append(nsenterArgv(fmt.Sprintf("/proc/%d/ns/net", cpid), 0, 0), "cat", "/proc/sys/net/ipv6/conf/all/disable_ipv6")...))
				if got != "1" {
					t.Errorf("%s: disable_ipv6 reads %q in its namespace", c, got)
				}
			}
		}
		pid, _ := containerPid(t, pgA)
		mounts := containerMounts(t, pgA)
		for _, dst := range []string{"/etc/passwd", "/etc/group", "/etc/postgresql-custom/pgsodium_root.key"} {
			if m, ok := mounts[dst]; !ok || m.RW {
				t.Errorf("pg-A: %s mounted %v, read-write %v; want a read-only mount", dst, ok, m.RW)
			}
		}
		// The postmaster (the container's init): empty sets, no_new_privs, filter mode.
		st := procStatus(t, pid)
		if st["CapEff"] != "0000000000000000" || st["CapBnd"] != "0000000000000000" || st["NoNewPrivs"] != "1" || st["Seccomp"] != "2" {
			t.Errorf("pg-A's postmaster: CapEff %s CapBnd %s NoNewPrivs %s Seccomp %s", st["CapEff"], st["CapBnd"], st["NoNewPrivs"], st["Seccomp"])
		}
	})

	t.Run("posture_from_inside", func(t *testing.T) {
		for _, c := range []string{pgA, restA} {
			rep := execSys(t, c, probeIn(t, A, c))
			if rep.Seccomp != 2 || rep.NoNewPrivs != 1 || rep.CapEff != 0 || rep.CapBnd != 0 {
				t.Errorf("%s: seccomp %d nonewprivs %d capeff %016x capbnd %016x; want 2 1 0 0", c, rep.Seccomp, rep.NoNewPrivs, rep.CapEff, rep.CapBnd)
			}
			for _, p := range sysConfinedProblems(rep.Calls) {
				t.Errorf("%s: %s", c, p)
			}
			// Control: the same image and flags with seccomp unconfined, and none
			// of the real container's mounts.
			f := containerFlags(t, c)
			f.Seccomp, f.Binds = "unconfined", nil
			un := imageSys(t, "sp-test-unconfined", imageOf(t, c), append([]string{"--network", "none"}, f.args()...)...)
			if un.Seccomp != 0 {
				t.Errorf("control %s: the unconfined run reports seccomp mode %d", c, un.Seccomp)
			}
			for _, p := range sysDifferProblems(rep.Calls, un.Calls, []string{"keyctl", "add_key", "request_key", "unshare-user"}) {
				t.Errorf("control %s: %s", c, p)
			}
		}
	})

	t.Run("bridge_members_capabilities", func(t *testing.T) {
		driftHold(t) // before the scratch bridge and its root member exist, released after they are gone
		// Control: a member run as root with Docker's default capabilities on a
		// scratch project-class bridge is found by the same sweep.
		net9, _ := scratchBridge(t, "spp9999", true)
		ctl := scratchContainer(t, "sp-test-caps", "--network", net9)
		got, examined := capViolations(t)
		want := []string{ctl + ": bounding set", ctl + ": configuration"}
		if !slices.Equal(got, want) {
			t.Fatalf("members of spp*, spl0 and spi0 holding NET_RAW or NET_ADMIN: %v, want exactly the control's %v", got, want)
		}
		// Coverage: the platform's own members on each class of bridge were examined.
		brA := nodecfg.BridgeName(A.SubnetIndex)
		for br, must := range map[string][]string{
			brA:                    {pgA, restA},
			nodecfg.PlatformBridge: {restA, gatewayName},
			nodecfg.IngressBridge:  {gatewayName},
			"spp9999":              {ctl},
		} {
			for _, m := range must {
				if !slices.Contains(examined[br], m) {
					t.Errorf("the sweep did not examine %s on bridge %s (examined there: %v)", m, br, examined[br])
				}
			}
		}
	})

	t.Run("healthcheck_ipc_nofile", func(t *testing.T) {
		nodeIPC, err := os.Readlink("/proc/self/ns/ipc")
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []string{pgA, restA} {
			f := containerFlags(t, c)
			if !slices.Equal(f.HealthcheckTests, []string{"NONE"}) {
				t.Errorf("%s: healthcheck %v, want [NONE]", c, f.HealthcheckTests)
			}
			if f.IpcMode != "private" {
				t.Errorf("%s: IPC mode %q, want private", c, f.IpcMode)
			}
			pid, _ := containerPid(t, c)
			if ns, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/ipc", pid)); ns == "" || ns == nodeIPC {
				t.Errorf("%s: IPC namespace %q is the node's", c, ns)
			}
			if got := nofile(t, pid); got != "65536 65536" {
				t.Errorf("%s: open files limit %q, want 65536 65536", c, got)
			}
		}
		// Controls: the cluster image started without --no-healthcheck shows its
		// declared healthcheck; a container sharing the node's IPC namespace is
		// seen as sharing it.
		name := "sp-test-hc"
		t.Cleanup(func() { rmIgnoringAbsent(t, "rm", "-f", "-v", name) })
		docker(t, "create", "--label", testLabel, "--name", name, "--network", "none", imageOf(t, pgA))
		if hc := containerFlags(t, name).HealthcheckTests; len(hc) == 0 || hc[0] != "CMD-SHELL" {
			t.Errorf("control: the cluster image's declared healthcheck reads %v, want CMD-SHELL", hc)
		}
		pid, _ := containerPid(t, scratchContainer(t, "sp-test-ipc", "--network", "none", "--ipc", "host", "--cap-drop", "ALL"))
		if ns, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/ipc", pid)); ns != nodeIPC {
			t.Errorf("control: a container run with --ipc host reads IPC namespace %q, not the node's %q", ns, nodeIPC)
		}
	})

	t.Run("read_write_mounts", func(t *testing.T) {
		writableMounts(t, pgA, []string{"/var/lib/postgresql/data", "/var/run/postgresql"})
		writableMounts(t, restA, nil)
	})

	t.Run("mounts_and_canaries", func(t *testing.T) { onlyProjectFiles(t, A, B) })
}

func nofile(t testing.TB, pid int) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", pid))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(b)) {
		if rest, ok := strings.CutPrefix(line, "Max open files"); ok {
			f := strings.Fields(rest)
			if len(f) >= 2 {
				return f[0] + " " + f[1]
			}
		}
	}
	return ""
}

// onlyProjectFiles: pg-A's mount points are a scratch container's of the same
// image and flags (without the platform's mounts) plus exactly the platform's
// mount targets; as A's uid every read-only file mount refuses opening for
// writing and every read-only directory mount refuses creating a file, while
// the data mount takes a write; /dev is the scratch container's; and the byte
// search of pg-A and postgrest-A finds none of the node's or B's secrets.
func onlyProjectFiles(t *testing.T, A, B Project) {
	pgA := pgName(A)
	pid, user := containerPid(t, pgA)
	f := containerFlags(t, pgA)
	f.Binds = nil
	scratch := imageContainer(t, "sp-test-mounts", imageOf(t, pgA), append([]string{"--network", "none"}, f.args()...)...)
	spid, _ := containerPid(t, scratch)

	want := slices.DeleteFunc(mountPoints(t, spid), func(m string) bool { return m == probeInImage })
	for _, m := range phaseBMounts { // as the container's own links resolve them
		r, err := resolveIn(fmt.Sprintf("/proc/%d/root", pid), m)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, r)
	}
	slices.Sort(want)
	want = slices.Compact(want)
	if got := mountPoints(t, pid); !slices.Equal(got, want) {
		extra := slices.DeleteFunc(slices.Clone(got), func(m string) bool { return slices.Contains(want, m) })
		missing := slices.DeleteFunc(slices.Clone(want), func(m string) bool { return slices.Contains(got, m) })
		t.Errorf("pg-A's mount points: unexpected %v, missing %v", extra, missing)
	}
	if got, want := devEntries(t, pid), devEntries(t, spid); !slices.Equal(got, want) {
		t.Errorf("pg-A's /dev %v, the scratch container's %v", got, want)
	}

	// Writes as A's uid, inside the container.
	try := func(path string) string {
		r, err := run(cmdTimeout, nil, "docker", "exec", "--user", user, pgA, "sh", "-c", ": >> \"$1\"", "sh", path)
		if err != nil {
			t.Fatal(err)
		}
		if r.code == 0 {
			return "ok"
		}
		return r.stderr
	}
	if got := try("/var/lib/postgresql/data/.reach-write"); got != "ok" {
		t.Fatalf("control: A's uid cannot write into its data mount: %s", brief(got))
	}
	docker(t, "exec", "--user", user, pgA, "rm", "-f", "/var/lib/postgresql/data/.reach-write")
	ro := 0
	for dst, m := range containerMounts(t, pgA) {
		if m.RW || m.Type != "bind" {
			continue
		}
		ro++
		fi, err := os.Stat(m.Source)
		if err != nil {
			t.Fatalf("source of %s: %v", dst, err)
		}
		if fi.IsDir() {
			if got := try(filepath.Join(dst, ".reach-create")); !strings.Contains(got, "Read-only file system") {
				t.Errorf("creating a file in the read-only directory mount %s: %s, want EROFS", dst, brief(got))
			}
		} else if got := try(dst); !strings.Contains(got, "Permission denied") && !strings.Contains(got, "Read-only file system") {
			t.Errorf("opening the read-only file mount %s for writing: %s, want EACCES or EROFS", dst, brief(got))
		}
	}
	if ro == 0 {
		t.Error("pg-A has no read-only bind mount: nothing was tried")
	}

	// The byte search. Every root must be visited: the empty tools directory
	// and /tmp get a marker file first.
	visit := filepath.Join(paths.RenderDir(A.Ref), "tools", ".reach-visit")
	t.Cleanup(func() { os.Remove(visit) })
	if err := os.WriteFile(visit, []byte("visit\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	docker(t, "exec", "--user", user, pgA, "sh", "-c", "echo visit > /tmp/.reach-visit")
	t.Cleanup(func() { run(cmdTimeout, nil, "docker", "exec", "--user", user, pgA, "rm", "-f", "/tmp/.reach-visit") })

	fileNeedle := func(name, path string) needle {
		b, err := os.ReadFile(path)
		if err != nil || len(bytes.TrimSpace(b)) == 0 {
			t.Fatalf("%s (%s): %v", name, path, err)
		}
		return needle{name, keyForms(b)}
	}
	forbidden := []needle{
		fileNeedle("the KEK", paths.KEK()),
		fileNeedle("the CA key", filepath.Join(paths.CADir(), "ca.key")),
		fileNeedle("the gateway's TLS key", filepath.Join(paths.GatewayDir(), "tls", "key.pem")),
		{"B's authenticator password", keyForms(platformSecret(t, B, "pg.authenticator.password"))},
		fileNeedle("B's pgsodium key", filepath.Join(paths.RenderDir(B.Ref), "pgsodium_root.key")),
	}
	searchContainer(t, pgA, forbidden, fileNeedle("A's own pgsodium key", filepath.Join(paths.RenderDir(A.Ref), "pgsodium_root.key")))
	searchContainer(t, restName(A), forbidden, needle{"A's own authenticator password", keyForms(platformSecret(t, A, "pg.authenticator.password"))})
}

// ───────── test 16, platform half ─────────

// TestReach16_PlatformBridge: another platform member cannot open PostgREST's
// ports (B8), the gateway can; postgrest-A opens nothing new on the platform
// bridge — neither the gateway's platform address nor postgrest-B.
func TestReach16_PlatformBridge(t *testing.T) {
	A, B := fixtureAB(t)
	conf := nodeConf(t)
	topology(t, A, B)
	restA := restName(A)
	a3000 := netip.AddrPortFrom(conf.PlatformAddr(A.SubnetIndex), 3000).String()
	a3001 := netip.AddrPortFrom(conf.PlatformAddr(A.SubnetIndex), 3001).String()
	b3000 := netip.AddrPortFrom(conf.PlatformAddr(B.SubnetIndex), 3000).String()
	gw8443 := netip.AddrPortFrom(gatewayIP(t), 8443).String()

	t.Run("platform_member_to_postgrest_ports", func(t *testing.T) {
		driftHold(t) // before the foreign member exists, released after it is gone
		m := member(t, "sp-test-platform", "platform")
		wantVerdict(t, "control: the gateway → postgrest-A:3000", gatewayName, "connected", "tcp", a3000)
		wantVerdict(t, "platform member → postgrest-A:3000", m, "timeout", "tcp", a3000)
		wantVerdict(t, "platform member → postgrest-A:3001", m, "timeout", "tcp", a3001)
		withRuleDeleted(t, "bridge supapace", "forward", "B8", func() {
			wantVerdict(t, "control: platform member → postgrest-A:3000 with B8 deleted", m, "connected", "tcp", a3000)
			wantVerdict(t, "control: platform member → postgrest-A:3001 with B8 deleted (nothing listens)", m, "refused", "tcp", a3001)
		})
	})

	t.Run("postgrest_opens_nothing", func(t *testing.T) {
		wantVerdict(t, "postgrest-A → the gateway's platform address :8443", restA, "timeout", "tcp", gw8443)
		wantVerdict(t, "postgrest-A → postgrest-B:3000", restA, "timeout", "tcp", b3000)
		withRuleDeleted(t, "bridge supapace", "forward", "B8", func() {
			wantVerdict(t, "control: postgrest-A → the gateway :8443 with B8 deleted", restA, "connected", "tcp", gw8443)
			wantVerdict(t, "control: postgrest-A → postgrest-B:3000 with B8 deleted", restA, "connected", "tcp", b3000)
		})
	})
}

// ───────── host-only ─────────

func hostOnly(t *testing.T) {
	if os.Getenv("SUPAPACE_HOST") != "1" {
		t.Skip("host-only: set by make reach-host on a host prepared by scripts/install-node.sh")
	}
}

func ourTables(t testing.TB) (inet, bridge bool) {
	t.Helper()
	out := must(t, cmdTimeout, "nft", "list", "tables")
	lines := strings.Split(out, "\n")
	return slices.Contains(lines, "table inet supapace"), slices.Contains(lines, "table bridge supapace")
}

// recoverHost brings Docker and the daemon back and waits until A and B are
// served: stopping Docker or flushing its rules stops or cuts every tenant, and
// only a daemon start brings them back.
func recoverHost(t testing.TB, A, B Project) {
	for _, argv := range [][]string{{"systemctl", "start", "docker"}, {"systemctl", "restart", "docker"}, {"systemctl", "restart", "supapaced"}} {
		if r, err := run(cmdTimeout, nil, argv...); err != nil || r.code != 0 {
			t.Errorf("%s: %v exit %d %s", strings.Join(argv, " "), err, r.code, brief(r.stderr))
		}
	}
	deadline := time.Now().Add(5 * time.Minute)
	for _, p := range []Project{A, B} {
		for {
			resp, err := gatewayRoundTrip(t, p, "GET", whoamiPath, hdr("apikey", p.AnonKey), nil, netip.Addr{})
			if err == nil && resp.StatusCode == 200 {
				break
			}
			if time.Now().After(deadline) {
				t.Errorf("project %s not served within 5 minutes of the recovery: %s", p.Ref, outcome(resp, err))
				return
			}
			time.Sleep(2 * time.Second)
		}
	}
}

// TestHost_DockerStartPullsRules: with Docker stopped and our tables deleted,
// starting Docker loads them first — both are present when the start returns
// and the presence check passes.
func TestHost_DockerStartPullsRules(t *testing.T) {
	hostOnly(t)
	A, B := fixtureAB(t)
	driftHold(t)
	restore := restoreRules(t)
	t.Cleanup(restore)
	t.Cleanup(func() { recoverHost(t, A, B) })
	if i, b := ourTables(t); !i || !b {
		t.Fatal("control: our tables are not loaded before the test")
	}
	must(t, cmdTimeout, "systemctl", "stop", "docker.service", "docker.socket")
	must(t, cmdTimeout, "nft", "delete table inet supapace; delete table bridge supapace")
	if i, b := ourTables(t); i || b {
		t.Fatal("our tables are still listed after their deletion")
	}
	must(t, cmdTimeout, "systemctl", "start", "docker.service")
	if i, b := ourTables(t); !i || !b {
		t.Fatalf("after systemctl start docker: inet table %v, bridge table %v; want both", i, b)
	}
	must(t, cmdTimeout, daemonBin, "nft", "check")
}

// TestHost_FirewallRestartReloadsRules: a restart of the distribution's
// nftables service (which flushes the whole ruleset) is followed by our load:
// a marker table of the test is gone afterwards, ours are back and checked.
func TestHost_FirewallRestartReloadsRules(t *testing.T) {
	hostOnly(t)
	A, B := fixtureAB(t)
	if r, err := run(cmdTimeout, nil, "systemctl", "is-active", "nftables.service"); err != nil || strings.TrimSpace(r.stdout) != "active" {
		t.Fatalf("nftables.service is not active (%v %q): there is no firewall restart to test", err, strings.TrimSpace(r.stdout))
	}
	driftHold(t)
	restore := restoreRules(t)
	t.Cleanup(restore)
	t.Cleanup(func() { recoverHost(t, A, B) })
	t.Cleanup(func() { run(cmdTimeout, nil, "nft", "delete", "table", "inet", "sp_test_marker") })
	must(t, cmdTimeout, "nft", "add", "table", "inet", "sp_test_marker")
	must(t, cmdTimeout, "systemctl", "restart", "nftables.service")
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		i, b := ourTables(t)
		r, err := run(cmdTimeout, nil, daemonBin, "nft", "check")
		if i && b && err == nil && r.code == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("30 s after the firewall restart: inet table %v, bridge table %v, nft check exit %d", i, b, r.code)
		}
	}
	if out := must(t, cmdTimeout, "nft", "list", "tables"); slices.Contains(strings.Split(out, "\n"), "table inet sp_test_marker") {
		t.Fatal("control: the marker table survived the restart, so the ruleset was not flushed")
	}
}
