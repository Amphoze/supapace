//go:build reach

package agent

// The wire proxy on a bare node, as root, with the proxy's image loaded and
// the node's ruleset in force (make node-proof PKG=internal/agent
// RUN=TestNode_Proxy). The agent itself makes the proxy, its table and its
// attachments; the clusters are scratch containers at the clusters'
// addresses, and every probe runs as root inside a namespace entered with
// nsenter — the worst case of a cluster: root in its own network namespace.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

const (
	pxProbe    = "/opt/supapace/bin/sp-probe"
	pxLabel    = "supapace.test=1"
	pxExternal = "example.com" // the reserved documentation domain
	// pxResolverEnv names, in the proof's environment, a public resolver (a
	// host name, resolved at run time from the node's own namespace). Unset,
	// the leg that asks a public resolver is not run.
	pxResolverEnv = "SUPAPACE_PUBLIC_RESOLVER"
)

// pxNode is a bare node made a dashboard node, with the platform networks, the
// node's ruleset loaded and one project network per spec.
type pxNode struct {
	a  *Agent
	ad dashcfg.Addrs
	s  []Spec
}

func pxSetup(t *testing.T, idx ...int) *pxNode {
	t.Helper()
	a := nodeAgent(t)
	a.cfg.StudioDomain = dashNodeDomain
	ad, err := dashcfg.For(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	n := &pxNode{a: a, ad: ad}
	for k, i := range idx {
		n.s = append(n.s, Spec{Ref: fmt.Sprintf("nodetest0proxy%06d", k+1), Epoch: 1, Generation: 1, SubnetIndex: i})
	}
	d := dashcfg.PathsFor(a.p)
	cleanup := func() {
		exec.Command("pkill", "-x", "-f", pxProbe+" listen .*").Run()
		if out, err := exec.Command("docker", "ps", "-aq", "--filter", "label="+pxLabel).Output(); err == nil {
			for _, id := range strings.Fields(string(out)) {
				nodeDockerQuiet("rm", "-f", id)
			}
		}
		nodeDockerQuiet("rm", "-f", dashcfg.PgcapName)
		for _, s := range n.s {
			nodeDockerQuiet("network", "rm", networkName(s.Ref))
		}
		nodeDockerQuiet("network", "rm", platformNet, ingressNet)
		for _, tb := range []string{"inet", "bridge"} {
			exec.Command("nft", "delete", "table", tb, "supapace").Run()
		}
		os.RemoveAll(d.DashDir())
	}
	cleanup()
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := a.ensurePlatformDir(); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(a.p, a.p.PlatformDir(), "seccomp.json", seccompProfile, 0o444, 0, 0); err != nil {
		t.Fatal(err)
	}
	// The node's own ruleset, from a scratch root: the bridge policy of every
	// project bridge and the platform bridge's closed list.
	rules, err := nft.Render(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := nodecfg.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(filepath.Dir(p.NftFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.NftFile(), rules, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := nft.Load(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsurePlatformNetworks(ctx); err != nil {
		t.Fatal(err)
	}
	for _, s := range n.s {
		if err := a.EnsureNetwork(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	return n
}

// pxMember starts a sleeping container without capabilities on network at ip
// and returns the pid that holds its network namespace.
func pxMember(t *testing.T, name, network, ip string, extra ...string) int {
	t.Helper()
	im, err := nodecfg.LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	args := slices.Concat([]string{"run", "-d", "--name", name, "--label", pxLabel, "--network", network, "--ip", ip, "--cap-drop", "ALL"},
		extra, []string{"--entrypoint", "sleep", im.ControlPlane, "86400"})
	nodeDocker(t, args...)
	return pxPid(t, name)
}

func pxPid(t *testing.T, name string) int {
	t.Helper()
	pid, err := strconv.Atoi(nodeDocker(t, "inspect", "-f", "{{.State.Pid}}", name))
	if err != nil || pid <= 0 {
		t.Fatalf("pid of %s: %v", name, err)
	}
	return pid
}

// pxIn runs argv as root inside pid's network namespace and returns its
// standard output, trimmed, and whether it exited 0.
func pxIn(pid int, argv ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nsenter", append([]string{"--net=/proc/" + strconv.Itoa(pid) + "/ns/net"}, argv...)...)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err == nil
}

func pxMust(t *testing.T, pid int, argv ...string) string {
	t.Helper()
	out, ok := pxIn(pid, argv...)
	if !ok {
		t.Fatalf("in the namespace of pid %d: %q failed: %s", pid, argv, out)
	}
	return out
}

// pxVerdict is the probe's verdict line for one TCP connect from pid's
// namespace (pid 0: the node's own).
func pxVerdict(t *testing.T, pid int, args ...string) string {
	t.Helper()
	argv := append([]string{pxProbe}, args...)
	var out string
	if pid == 0 {
		b, _ := exec.Command(argv[0], argv[1:]...).Output()
		out = strings.TrimSpace(string(b))
	} else {
		out, _ = pxIn(pid, argv...)
	}
	if out == "" || strings.HasPrefix(out, "error") {
		t.Fatalf("probe %q from pid %d: %q", args, pid, out)
	}
	return out
}

func pxTCP(t *testing.T, pid int, addr string) string {
	t.Helper()
	return strings.Fields(pxVerdict(t, pid, "tcp", addr, "--timeout", "2s"))[0]
}

// pxListen starts an echo listener at addr inside pid's namespace.
func pxListen(t *testing.T, pid int, addr string) {
	t.Helper()
	cmd := exec.Command("nsenter", "--net=/proc/"+strconv.Itoa(pid)+"/ns/net", pxProbe, "listen", "tcp", addr)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(out).ReadString('\n')
		line <- s
	}()
	select {
	case s := <-line:
		if !strings.HasPrefix(s, "listening") {
			t.Fatalf("listener %s: %q", addr, s)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("listener %s did not start", addr)
	}
}

// pxWait polls cond once a second until it holds, at most a minute.
func pxWait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(time.Minute); !cond(); time.Sleep(time.Second) {
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "20", dashcfg.PgcapName).CombinedOutput()
			t.Fatalf("%s: not within a minute\n%s", what, logs)
		}
	}
}

// pxListeners is every listening TCP socket of pid's namespace that is not on
// its loopback (where Docker's resolver listens in every container), as ss
// prints its local address.
func pxListeners(t *testing.T, pid int) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(pxMust(t, pid, "ss", "-Htln"), "\n") {
		if f := strings.Fields(l); len(f) >= 4 && !strings.HasPrefix(f[3], "127.") {
			out = append(out, f[3])
		}
	}
	slices.Sort(out)
	return out
}

func pxInode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func pxNetworks(t *testing.T) string {
	t.Helper()
	return nodeDocker(t, "inspect", "-f", `{{range $n, $e := .NetworkSettings.Networks}}{{$n}}={{$e.IPAddress}} {{end}}`, dashcfg.PgcapName)
}

// TestNode_ProxyHostileClusterCannotReachItOrThroughIt: the proxy has an
// interface on every project network. From a cluster's namespace, as root and
// with whatever routes it likes through the proxy's address: (a) no port of
// the proxy answers, on either slice's address or on its platform address;
// (b) the cluster of another slice is not reached through it, and the four
// settings that make it so are read inside the proxy's namespace; (c) the
// same probe over the same routes does reach that cluster when a container
// that forwards holds the proxy's place; (d) from the proxy's namespace no
// resolver answers for an outside name.
func TestNode_ProxyHostileClusterCannotReachItOrThroughIt(t *testing.T) {
	n := pxSetup(t, 21, 22)
	a, ctx, cfg := n.a, context.Background(), n.a.cfg
	s1, s2 := n.s[0], n.s[1]
	net1, net2 := networkName(s1.Ref), networkName(s2.Ref)
	cluster1, cluster2 := cfg.ClusterAddr(21).String(), cfg.ClusterAddr(22).String()
	proxy1, proxy2 := dashcfg.ProxyAddr(cfg, 21).String(), dashcfg.ProxyAddr(cfg, 22).String()
	pg1 := pxMember(t, "sp-test-proxy-pg1", net1, cluster1)
	pg2 := pxMember(t, "sp-test-proxy-pg2", net2, cluster2)
	meta := pxMember(t, "sp-test-proxy-meta", platformNet, n.ad.PgMeta0.String())
	pxListen(t, pg2, cluster2+":5432")

	// The agent attaches as a create's step does: no round has run before.
	for _, s := range n.s {
		if err := a.AttachProxy(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	px := pxPid(t, dashcfg.PgcapName)
	wantNets := fmt.Sprintf("platform=%s %s=%s %s=%s", n.ad.Pgcap, net1, proxy1, net2, proxy2)
	if got := pxNetworks(t); got != wantNets {
		t.Fatalf("the proxy is on %q, want %q", got, wantNets)
	}
	tb, have, err := a.readProxyTable()
	if err != nil || !have || len(tb.Slices) != 2 || tb.Slices["21"][proxyClass] != 5 || tb.Slices["22"][proxyClass] != 5 {
		t.Fatalf("the table: %+v, %v, %v", tb.Slices, have, err)
	}
	// A second attach changes nothing: the same container, the same file.
	id, before := nodeDocker(t, "inspect", "-f", "{{.Id}}", dashcfg.PgcapName), pxInode(t, a.proxyTablePath())
	if err := a.AttachProxy(ctx, s1); err != nil {
		t.Fatal(err)
	}
	if nodeDocker(t, "inspect", "-f", "{{.Id}}", dashcfg.PgcapName) != id || pxInode(t, a.proxyTablePath()) != before {
		t.Error("a second attach made the container or the file again")
	}

	port1, port2 := strconv.Itoa(dashcfg.MetaPort(21)), strconv.Itoa(dashcfg.MetaPort(22))
	onPlatform := func(port string) string { return n.ad.Pgcap.String() + ":" + port }
	// Control of every "does not answer" below: the proxy listens, and the
	// one peer the ruleset lists reaches both ports.
	pxWait(t, "the proxy's two ports open to postgres-meta's address", func() bool {
		return pxTCP(t, meta, onPlatform(port1)) == "connected" && pxTCP(t, meta, onPlatform(port2)) == "connected"
	})
	listeners := pxListeners(t, px)
	if want := []string{onPlatform(port1), onPlatform(port2)}; !slices.Equal(listeners, want) {
		t.Fatalf("the proxy listens on %q, want exactly %q", listeners, want)
	}
	if err := pxRows(a, n.ad); err != nil {
		t.Errorf("the row for the proxy as attached: %v", err)
	}

	// (b), first half: the settings, inside the namespace, for the namespace
	// and for each interface — two of them attached after the start.
	for _, s := range [][2]string{{"ipv4/ip_forward", "0"}, {"ipv4/conf/all/forwarding", "0"}, {"ipv4/conf/all/rp_filter", "1"},
		{"ipv4/conf/all/arp_ignore", "1"}, {"ipv6/conf/all/disable_ipv6", "1"}} {
		if got := pxMust(t, px, "cat", "/proc/sys/net/"+s[0]); got != s[1] {
			t.Errorf("in the proxy's namespace %s is %s, want %s", s[0], got, s[1])
		}
	}
	ifaces := strings.Fields(pxMust(t, px, "ls", "/proc/sys/net/ipv4/conf"))
	if len(ifaces) != 6 { // all, default, lo and one per network
		t.Errorf("the proxy's interfaces: %q", ifaces)
	}
	for _, ifc := range ifaces {
		if got := pxMust(t, px, "cat", "/proc/sys/net/ipv4/conf/"+ifc+"/forwarding"); got != "0" {
			t.Errorf("forwarding on %s is %s", ifc, got)
		}
		if ifc == "lo" {
			continue
		}
		// Each interface's own value, the one made at the start and the two
		// attached after it: the strict reverse-path filter, not the host's.
		for _, key := range []string{"rp_filter", "arp_ignore"} {
			if got := pxMust(t, px, "cat", "/proc/sys/net/ipv4/conf/"+ifc+"/"+key); got != "1" {
				t.Errorf("%s on %s is %s, want 1", key, ifc, got)
			}
		}
	}
	if routes := pxMust(t, px, "ip", "-4", "route", "show", "default"); routes != "" {
		t.Errorf("the proxy has a default route: %s", routes)
	}

	// The cluster's own routes: everything it might want goes to the proxy's
	// address on its bridge. The second cluster knows the way back, so that a
	// forwarded connection could complete.
	pxMust(t, pg1, "ip", "route", "add", cfg.Slice(22).String(), "via", proxy1)
	pxMust(t, pg1, "ip", "route", "add", cfg.PlatformSubnet, "via", proxy1)
	pxMust(t, pg2, "ip", "route", "add", cfg.Slice(21).String(), "via", proxy2)

	// (a) no port of the proxy answers the cluster: its listening ports, the
	// database port and a port beside them, at each of its three addresses.
	for _, host := range []string{proxy1, proxy2, n.ad.Pgcap.String()} {
		for _, port := range []string{port1, port2, "5432", "20000"} {
			if v := pxTCP(t, pg1, host+":"+port); v == "connected" {
				t.Errorf("(a) from the cluster's namespace %s:%s answered", host, port)
			} else {
				t.Logf("(a) %s:%s from the cluster: %s", host, port, v)
			}
		}
	}
	// (b) the other slice's cluster is not reached through the proxy.
	if v := pxTCP(t, pg1, cluster2+":5432"); v == "connected" {
		t.Errorf("(b) the second slice's cluster was reached through the proxy")
	} else {
		t.Logf("(b) %s:5432 through the proxy: %s", cluster2, v)
	}
	// Control on the cluster's own bridge: its port is reachable there, so
	// the listener behind (b) and (c) is up.
	rest2 := pxMember(t, "sp-test-proxy-rest2", net2, cfg.PostgRESTAddr(22).String())
	if v := pxTCP(t, rest2, cluster2+":5432"); v != "connected" {
		t.Fatalf("control: the second cluster's port from its own bridge: %s", v)
	}

	// (d) from the proxy's namespace no resolver answers for an outside name.
	dns := func(pid int, server string) string {
		return pxVerdict(t, pid, "dns", pxExternal, "--server", server, "--timeout", "3s")
	}
	if v := dns(px, "127.0.0.11"); strings.HasPrefix(v, "answered") {
		t.Errorf("(d) Docker's resolver in the proxy's namespace answered: %s", v)
	} else {
		t.Logf("(d) Docker's resolver in the proxy's namespace: %s", v)
	}
	var resolvers []string
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "nameserver" {
				resolvers = append(resolvers, f[1])
			}
		}
	}
	if len(resolvers) == 0 {
		t.Fatal("(d) the node has no resolver to try")
	}
	// A public resolver, found through the node's own: its control is the
	// same query from the node's namespace.
	if name := os.Getenv(pxResolverEnv); name == "" {
		t.Logf("(d) %s is not set: the leg that asks a public resolver is not run (the node's own resolver is asked)", pxResolverEnv)
	} else if f := strings.Fields(pxVerdict(t, 0, "dns", name, "--server", resolvers[0], "--timeout", "5s")); f[0] == "answered" && len(f) > 1 {
		resolvers = append(resolvers, f[1])
	} else {
		t.Logf("(d) no address of the public resolver from this node (%q): that leg is not run", f)
	}
	for _, r := range resolvers {
		control := dns(0, r)
		if !strings.HasPrefix(control, "answered") {
			t.Logf("(d) resolver %s does not answer the node itself (%s): not a control, leg not run", r, control)
			continue
		}
		if v := dns(px, r); strings.HasPrefix(v, "answered") {
			t.Errorf("(d) resolver %s answered the proxy's namespace: %s", r, v)
		} else {
			t.Logf("(d) resolver %s: the node gets %q, the proxy's namespace %q", r, control, v)
		}
	}

	// (c) the same probe, the same routes, a forwarding container in the
	// proxy's place: the agent detaches the proxy first, slice by slice.
	for _, s := range n.s {
		if err := a.DetachProxy(ctx, s.Ref); err != nil {
			t.Fatal(err)
		}
	}
	if got := pxNetworks(t); got != fmt.Sprintf("platform=%s", n.ad.Pgcap) {
		t.Fatalf("after the detach the proxy is on %q", got)
	}
	if tb, _, err := a.readProxyTable(); err != nil || len(tb.Slices) != 0 {
		t.Fatalf("after the detach the table holds %v (%v)", tb.Slices, err)
	}
	pxWait(t, "the detached slices' ports closed", func() bool { return len(pxListeners(t, px)) == 0 })
	pxMember(t, "sp-test-proxy-fwd", net1, proxy1, "--sysctl", "net.ipv4.ip_forward=1")
	nodeDocker(t, "network", "connect", "--ip", proxy2, net2, "sp-test-proxy-fwd")
	if v := pxTCP(t, pg1, cluster2+":5432"); v != "connected" {
		t.Errorf("(c) control: with a forwarding container at the proxy's addresses the second cluster is %s, want connected: (b) proves nothing", v)
	} else {
		t.Logf("(c) %s:5432 through a forwarding container at %s: %s", cluster2, proxy1, v)
	}
}

// TestNode_ProxyRowSeesAnUnopenedPort: the proxy says nothing of its ports
// but in its log. With a slice's port taken, the row fails within seconds of
// the slice entering the table, names it, and clears within seconds of the
// port coming free — read from the runtime's log with its timestamps.
func TestNode_ProxyRowSeesAnUnopenedPort(t *testing.T) {
	n := pxSetup(t, 23, 24)
	a, ctx := n.a, context.Background()
	if err := a.AttachProxy(ctx, n.s[0]); err != nil {
		t.Fatal(err)
	}
	px := pxPid(t, dashcfg.PgcapName)
	taken := n.ad.Pgcap.String() + ":" + strconv.Itoa(dashcfg.MetaPort(24))
	pxWait(t, "the row passing for the first slice", func() bool { return pxRows(a, n.ad) == nil })

	// Something else holds the second slice's port in the proxy's namespace.
	hold := exec.Command("nsenter", "--net=/proc/"+strconv.Itoa(px)+"/ns/net", pxProbe, "listen", "tcp", taken)
	out, err := hold.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := hold.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hold.Process.Kill(); hold.Wait() })
	if s, _ := bufio.NewReader(out).ReadString('\n'); !strings.HasPrefix(s, "listening") {
		t.Fatalf("the port's holder: %q", s)
	}
	if err := a.AttachProxy(ctx, n.s[1]); err != nil {
		t.Fatal(err)
	}
	var row error
	pxWait(t, "the row failing for the unopened port", func() bool { row = pxRows(a, n.ad); return row != nil })
	t.Logf("the row: %v", row)
	if !strings.Contains(row.Error(), "slice 24") {
		t.Errorf("the row does not name the slice: %v", row)
	}
	for range 5 { // it stays failing while the port stays taken
		time.Sleep(time.Second)
		if err := pxRows(a, n.ad); err == nil {
			t.Error("the row passed while the port was still taken")
		}
	}
	hold.Process.Kill()
	hold.Wait()
	start := time.Now()
	pxWait(t, "the row clearing once the port is free", func() bool { return pxRows(a, n.ad) == nil })
	t.Logf("the row cleared %s after the port came free", time.Since(start).Round(time.Second))
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("the row took %s to clear", d)
	}
	if got := pxListeners(t, px); len(got) != 2 {
		t.Errorf("the proxy listens on %q, want both slices' ports", got)
	}
}

// TestNode_DashboardRemovedWhereItIsNotConfigured: a node that loses its
// dashboard configuration keeps the proxy on its project networks, and with
// it every start of those projects is refused and the node check's member
// rows fail. The agent's removal takes the proxy and its attachments away,
// and both pass again; a container of that name without the platform's role
// label is not touched.
func TestNode_DashboardRemovedWhereItIsNotConfigured(t *testing.T) {
	n := pxSetup(t, 25)
	a, ctx, s := n.a, context.Background(), n.s[0]
	if err := a.AttachProxy(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := a.RemoveDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	if got := pxNetworks(t); !strings.Contains(got, networkName(s.Ref)) {
		t.Fatalf("on a configured node the removal took the proxy off its network: %q", got)
	}
	members := func() error {
		nets, err := dockerNetworks(ctx)
		if err != nil {
			return err
		}
		return a.checkProjectAddresses(ctx, nets)
	}
	if err := members(); err != nil {
		t.Fatalf("control: project-addresses on the configured node: %v", err)
	}
	// The node loses its studio domain.
	a.cfg.StudioDomain = ""
	err := members()
	if err == nil || !strings.Contains(err.Error(), "member rule") {
		t.Fatalf("control: project-addresses with the proxy left attached: %v", err)
	}
	t.Logf("before the removal, project-addresses: %v", err)
	if err := a.checkPlatformMembers(ctx); err == nil || !strings.Contains(err.Error(), "foreign member "+dashcfg.PgcapName) {
		t.Fatalf("control: platform-members with the proxy left: %v", err)
	}
	if err := a.RemoveDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "name=^"+dashcfg.PgcapName+"$").Output(); strings.TrimSpace(string(out)) != "" {
		t.Errorf("the proxy is still there: %s", out)
	}
	if got := nodeDocker(t, "network", "inspect", "-f", "{{len .Containers}}", networkName(s.Ref)); got != "0" {
		t.Errorf("the project network still has %s members", got)
	}
	if _, err := os.Lstat(a.proxyTablePath()); !os.IsNotExist(err) {
		t.Errorf("the proxy's table is still there (%v)", err)
	}
	if err := members(); err != nil {
		t.Errorf("project-addresses after the removal: %v", err)
	}
	if err := a.checkPlatformMembers(ctx); err != nil {
		t.Errorf("platform-members after the removal: %v", err)
	}
	if err := a.RemoveNetwork(ctx, s.Ref); err != nil {
		t.Errorf("the project network cannot be removed afterwards: %v", err)
	}
	// On a configured node the proxy alone can be taken away, attachments
	// with it, the table left for the ensure; with none there, nothing.
	a.cfg.StudioDomain = dashNodeDomain
	if err := a.EnsureNetwork(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := a.AttachProxy(ctx, s); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := a.RemoveProxy(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "name=^"+dashcfg.PgcapName+"$").Output(); strings.TrimSpace(string(out)) != "" {
		t.Errorf("RemoveProxy left the proxy: %s", out)
	}
	if got := nodeDocker(t, "network", "inspect", "-f", "{{len .Containers}}", networkName(s.Ref)); got != "0" {
		t.Errorf("after RemoveProxy the project network has %s members", got)
	}
	if tb, have, err := a.readProxyTable(); err != nil || !have || len(tb.Slices) != 1 {
		t.Errorf("after RemoveProxy the table: %v, %v, %v; want it left as it was", tb.Slices, have, err)
	}
	if _, nets := a.checkProxy(ctx, n.ad); nets != nil {
		t.Errorf("with no proxy the blocking row: %v", nets)
	}
	a.cfg.StudioDomain = ""
	os.Remove(a.proxyTablePath())
	if err := a.RemoveNetwork(ctx, s.Ref); err != nil {
		t.Fatal(err)
	}
	// A container of the proxy's name that lacks the platform's role label
	// is somebody else's: left where it is, for the rows to report.
	pxMember(t, dashcfg.PgcapName, platformNet, n.ad.Pgcap.String())
	if err := a.RemoveDashboard(ctx); err == nil || !strings.Contains(err.Error(), dashcfg.PgcapName) {
		t.Errorf("a container of the proxy's name that is not the platform's: %v, want it named as left", err)
	}
	if err := a.RemoveProxy(ctx); err == nil {
		t.Error("RemoveProxy reported nothing of it")
	}
	if out, _ := exec.Command("docker", "ps", "-q", "--filter", "name=^"+dashcfg.PgcapName+"$").Output(); strings.TrimSpace(string(out)) == "" {
		t.Error("a container without the role label was removed")
	}
}

// pxRows is the node check's two rows of the proxy, as one error.
func pxRows(a *Agent, ad dashcfg.Addrs) error {
	live, nets := a.checkProxy(context.Background(), ad)
	return errors.Join(live, nets)
}
