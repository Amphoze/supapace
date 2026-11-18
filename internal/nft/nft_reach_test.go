//go:build reach

// Bare-node component tests: run as root on a node started with `make node-bare`
// (a bare dockerd, none of our tables), where these tests own the bridge names.
// Each test loads the rendered default ruleset, builds its own scratch objects
// and removes them, and our tables, when it ends.
//
// Every "blocked" probe is paired with a control on the same path that connects
// once exactly the named rules are deleted (found by their comment), and every
// listener is first reached by a peer the ruleset allows. A probe's verdict is
// its sp-probe line and its exit code, which must agree. Probes from any
// namespace but the node's run at an unprivileged uid with no capabilities.
package nft

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

const (
	probeBin   = "/opt/supapace/bin/sp-probe"
	cmdTimeout = 2 * time.Minute
	testLabel  = "supapace.test=1"
	gatewayIP  = "10.212.0.2"
	restIP     = "10.212.0.16" // PostgREST of slice 0
	thirdIP    = "10.212.0.20"
	secondIP   = "10.212.6.10" // inside the allocator range, like any other member
)

// exe runs a command (argv, no shell) with a deadline and returns its stdout,
// stderr and exit code; err is set only when it could not run at all.
func exe(stdin []byte, args ...string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return o.String(), e.String(), ee.ExitCode(), nil
	}
	return o.String(), e.String(), 0, err
}

func must(t testing.TB, args ...string) string {
	t.Helper()
	o, e, code, err := exe(nil, args...)
	if err != nil || code != 0 {
		t.Fatalf("%s: %v exit %d: %s", strings.Join(args, " "), err, code, strings.TrimSpace(e))
	}
	return o
}

// try runs a cleanup command and reports a failure other than "already gone".
func try(t testing.TB, args ...string) {
	_, e, code, err := exe(nil, args...)
	if err != nil || code != 0 && !strings.Contains(e, "No such") && !strings.Contains(e, "not found") && !strings.Contains(e, "Cannot find") {
		t.Errorf("cleanup %s: %v exit %d: %s", strings.Join(args, " "), err, code, strings.TrimSpace(e))
	}
}

// deleteOurTables removes both tables if present.
func deleteOurTables(t testing.TB) {
	for _, tb := range ourTables {
		f := strings.Fields(tb)
		try(t, "nft", "delete", "table", f[0], f[1])
	}
}

// node renders the default ruleset into a temporary root, loads it and removes
// our tables when the test ends.
func node(t *testing.T) nodecfg.Paths {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("component tests run as root on a bare node")
	}
	c := nodecfg.Default("sp.test")
	b, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	p := nodecfg.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(filepath.Dir(p.NftFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.NftFile(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteOurTables(t) })
	load(t, p)
	return p
}

func load(t testing.TB, p nodecfg.Paths) {
	t.Helper()
	if err := Load(context.Background(), p); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := Check(context.Background(), p); err != nil {
		t.Fatalf("Check after Load: %v", err)
	}
}

// ruleRef names one rule: family, chain and the comment that labels it.
type ruleRef struct{ family, chain, label string }

func (r ruleRef) String() string { return r.label }

var (
	F2 = ruleRef{"inet", "forward", "F2"}
	F4 = ruleRef{"inet", "forward", "F4"}
	B8 = ruleRef{"bridge", "forward", "B8"}
)

// labels returns comment → handles of the rules of one chain of our table.
func labels(t testing.TB, family, chain string) map[string][]int {
	t.Helper()
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Handle  int    `json:"handle"`
				Comment string `json:"comment"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(must(t, "nft", "-j", "-a", "list", "chain", family, "supapace", chain)), &doc); err != nil {
		t.Fatalf("nft -j list chain %s supapace %s: %v", family, chain, err)
	}
	m := map[string][]int{}
	for _, o := range doc.Nftables {
		if o.Rule != nil {
			m[o.Rule.Comment] = append(m[o.Rule.Comment], o.Rule.Handle)
		}
	}
	return m
}

// deleteRule deletes the one rule carrying r's comment, by its handle.
func deleteRule(t testing.TB, r ruleRef) {
	t.Helper()
	hs := labels(t, r.family, r.chain)[r.label]
	if len(hs) != 1 {
		t.Fatalf("%s supapace %s: %d rules with comment %q, want 1", r.family, r.chain, len(hs), r.label)
	}
	must(t, "nft", "delete", "rule", r.family, "supapace", r.chain, "handle", strconv.Itoa(hs[0]))
}

// withDeleted deletes the named rules, runs fn and reloads the tables.
func withDeleted(t *testing.T, p nodecfg.Paths, rs []ruleRef, fn func()) {
	t.Helper()
	defer load(t, p)
	for _, r := range rs {
		deleteRule(t, r)
	}
	fn()
}

// ───────── namespaces, containers, probes ─────────

func image(t testing.TB) string {
	im, err := nodecfg.LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	return im.ControlPlane
}

func network(t *testing.T, name string, args ...string) {
	t.Helper()
	t.Cleanup(func() { try(t, "docker", "network", "rm", name) })
	must(t, append(append([]string{"docker", "network", "create", "--label", testLabel, "--ipv6=false"}, args...), name)...)
}

// member starts a sleeping container on net at ip, with no capabilities, and
// returns the pid of its network namespace's holder.
func member(t *testing.T, name, net, ip string) int {
	t.Helper()
	t.Cleanup(func() { try(t, "docker", "rm", "-f", name) })
	must(t, "docker", "run", "-d", "--name", name, "--label", testLabel, "--network", net, "--ip", ip,
		"--cap-drop", "ALL", "--entrypoint", "sleep", image(t), "86400")
	pid, err := strconv.Atoi(strings.TrimSpace(must(t, "docker", "inspect", "-f", "{{.State.Pid}}", name)))
	if err != nil || pid <= 0 {
		t.Fatalf("pid of %s: %v", name, err)
	}
	return pid
}

// hostNS is the node's own network namespace.
const hostNS = 0

func inNS(pid int, args ...string) []string {
	if pid == hostNS {
		return args
	}
	return append([]string{"nsenter", "--net=/proc/" + strconv.Itoa(pid) + "/ns/net"}, args...)
}

// listen starts an sp-probe TCP listener at addr in pid's namespace and waits
// until it reports listening.
func listen(t *testing.T, pid int, addr string) {
	t.Helper()
	args := inNS(pid, probeBin, "listen", "tcp", addr)
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
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

// probe connects from pid's namespace (at the tenant uid unless pid is the
// node's) to addr and returns the verdict word.
func probe(t *testing.T, pid int, addr string) string {
	t.Helper()
	return verdictOf(t, addr, asTenant(pid, probeBin, "tcp", addr, "--timeout", "1s"))
}

// verdictOf runs a probe and returns its verdict word. The verdict line and the
// exit code must agree; anything but connected, refused or timeout fails the test.
func verdictOf(t *testing.T, addr string, argv []string) string {
	t.Helper()
	o, e, code, err := exe(nil, argv...)
	if err != nil {
		t.Fatalf("probe %s: %v", addr, err)
	}
	v := strings.Fields(o + " ")[0]
	switch v + ":" + strconv.Itoa(code) {
	case "connected:0", "refused:1", "timeout:2":
		return v
	}
	t.Fatalf("probe %s %q: verdict %q with exit %d (stderr %q)", addr, argv, strings.TrimSpace(o), code, strings.TrimSpace(e))
	return ""
}

func expect(t *testing.T, what string, pid int, addr, want string) {
	t.Helper()
	if got := probe(t, pid, addr); got != want {
		t.Errorf("%s (%s): %s, want %s", what, addr, got, want)
	}
}

// neighbour is a network namespace behind a veth pair, standing in for an
// uplink neighbour: 10.215.250.2 there, 10.215.250.1 on the node, with a route
// to the platform subnet through the node. It returns the namespace's pid.
func neighbour(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("unshare", "--net", "sleep", "86400")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	pid := cmd.Process.Pid
	// unshare execs sleep once the namespace exists.
	deadline := time.Now().Add(10 * time.Second)
	for {
		self, _ := os.Readlink("/proc/self/ns/net")
		ns, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/net")
		if ns != "" && ns != self {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("neighbour namespace did not appear")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Cleanup(func() { try(t, "ip", "link", "del", "spnfth") })
	must(t, "ip", "link", "add", "spnfth", "type", "veth", "peer", "name", "spnftp")
	must(t, "ip", "link", "set", "spnftp", "netns", strconv.Itoa(pid))
	must(t, "ip", "addr", "add", "10.215.250.1/30", "dev", "spnfth")
	must(t, "ip", "link", "set", "spnfth", "up")
	must(t, inNS(pid, "ip", "addr", "add", "10.215.250.2/30", "dev", "spnftp")...)
	must(t, inNS(pid, "ip", "link", "set", "spnftp", "up")...)
	must(t, inNS(pid, "ip", "link", "set", "lo", "up")...)
	must(t, inNS(pid, "ip", "route", "add", "10.212.0.0/21", "via", "10.215.250.1")...)
	if v := strings.TrimSpace(must(t, "cat", "/proc/sys/net/ipv4/ip_forward")); v != "1" {
		t.Fatalf("the node does not forward IPv4 (ip_forward %s)", v)
	}
	return pid
}

// routedPlatform is a scratch non-internal network whose bridge is named spl0,
// with routing into it allowed by Docker, so only our tables decide.
func routedPlatform(t *testing.T) {
	network(t, "spnft-plat", "--subnet", "10.212.0.0/21", "--ip-range", "10.212.6.0/23", "--gateway", "10.212.0.1",
		"-o", "com.docker.network.bridge.name="+nodecfg.PlatformBridge,
		"-o", "com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected")
}

// isolatedPlatform is the platform network as the agent creates it.
func isolatedPlatform(t *testing.T) {
	network(t, "spnft-plat", "--internal", "--subnet", "10.212.0.0/21", "--ip-range", "10.212.6.0/23",
		"-o", "com.docker.network.bridge.name="+nodecfg.PlatformBridge,
		"-o", "com.docker.network.bridge.gateway_mode_ipv4=isolated")
}

// ───────── load and check ─────────

func TestLoad_ThenCheckPasses(t *testing.T) {
	ctx := context.Background()
	p := node(t)
	deleteOurTables(t)
	if err := Check(ctx, p); !errors.Is(err, ErrAbsent) {
		t.Fatalf("Check without our tables: %v, want ErrAbsent", err)
	}
	load(t, p)
	// Every rule is installed with its label, once.
	for _, c := range []struct{ family, chain, labels string }{
		{"inet", "input", "I1 I2"}, {"inet", "forward", "F1 F2 F3 F4"}, {"bridge", "forward", "B1 B2 B3 B4 B8 B6 B9"},
	} {
		m := labels(t, c.family, c.chain)
		var got []string
		for l, hs := range m {
			if len(hs) != 1 {
				t.Errorf("%s %s: comment %q on %d rules", c.family, c.chain, l, len(hs))
			}
			got = append(got, l)
		}
		want := strings.Fields(c.labels)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s %s: installed labels %q, want %q", c.family, c.chain, got, want)
		}
	}
	must(t, "nft", "delete", "table", "bridge", "supapace")
	if err := Check(ctx, p); !errors.Is(err, ErrAbsent) {
		t.Fatalf("Check without the bridge table: %v, want ErrAbsent", err)
	}
	load(t, p)
}

func TestCheck_FailsAfterRuleDeleted(t *testing.T) {
	ctx := context.Background()
	p := node(t)
	for _, r := range []ruleRef{
		{"inet", "input", "I1"}, {"inet", "input", "I2"},
		{"inet", "forward", "F1"}, F2, {"inet", "forward", "F3"}, F4,
		{"bridge", "forward", "B1"}, {"bridge", "forward", "B2"}, {"bridge", "forward", "B3"}, {"bridge", "forward", "B4"},
		B8, {"bridge", "forward", "B6"}, {"bridge", "forward", "B9"},
	} {
		withDeleted(t, p, []ruleRef{r}, func() {
			if err := Check(ctx, p); !errors.Is(err, ErrDrift) {
				t.Errorf("Check with %s deleted: %v, want ErrDrift", r, err)
			}
		})
	}
	// A rule added to a chain of ours is drift as well.
	must(t, "nft", "insert", "rule", "bridge", "supapace", "forward", "accept")
	if err := Check(ctx, p); !errors.Is(err, ErrDrift) {
		t.Errorf("Check with an inserted accept: %v, want ErrDrift", err)
	}
	load(t, p)
}

func TestCheck_FailsWhenFileEditedWithoutReload(t *testing.T) {
	ctx := context.Background()
	p := node(t)
	orig, err := os.ReadFile(p.NftFile())
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(orig, []byte(`ether type ip accept comment "B6"`), []byte(`ether type ip drop comment "B6"`), 1)
	if bytes.Equal(edited, orig) {
		t.Fatal("B6 not found in the rendered file")
	}
	if err := os.WriteFile(p.NftFile(), edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Check(ctx, p); !errors.Is(err, ErrDrift) {
		t.Fatalf("Check with the file edited and not loaded: %v, want ErrDrift", err)
	}
	if err := os.WriteFile(p.NftFile(), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Check(ctx, p); err != nil {
		t.Fatalf("Check with the file restored: %v", err)
	}
	if err := os.Remove(p.NftSum()); err != nil {
		t.Fatal(err)
	}
	if err := Check(ctx, p); !errors.Is(err, ErrDrift) {
		t.Fatalf("Check without a sum file: %v, want ErrDrift", err)
	}
	load(t, p)
}

var counterRE = regexp.MustCompile(`\[[0-9]+:[0-9]+\]`)

// foreignState is every table but ours (stateless listing), plus the legacy
// iptables state when those tools exist, without counters and comment lines.
func foreignState(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	for _, l := range strings.Split(must(t, "nft", "list", "tables"), "\n") {
		f := strings.Fields(l)
		if len(f) != 3 || slices.Contains(ourTables, f[1]+" "+f[2]) {
			continue
		}
		sb.WriteString(must(t, "nft", "-s", "list", "table", f[1], f[2]))
	}
	for _, tool := range []string{"iptables-legacy-save", "ip6tables-legacy-save"} {
		if _, err := exec.LookPath(tool); err != nil {
			continue
		}
		for _, l := range strings.Split(must(t, tool), "\n") {
			if !strings.HasPrefix(l, "#") {
				sb.WriteString(counterRE.ReplaceAllString(l, "") + "\n")
			}
		}
	}
	return sb.String()
}

func TestLoad_LeavesDockerTablesIntact(t *testing.T) {
	// Give Docker's own chains something to hold: a routed and an internal network.
	network(t, "spnft-routed", "--subnet", "10.214.1.0/26")
	network(t, "spnft-internal", "--internal", "--subnet", "10.214.1.64/26")
	deleteOurTables(t)
	before := foreignState(t)
	if !strings.Contains(before, "DOCKER") {
		t.Fatalf("no Docker chains on this node to compare:\n%s", before)
	}
	p := node(t) // our tables absent → loaded
	if after := foreignState(t); after != before {
		t.Fatalf("first Load changed other tables:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	load(t, p) // present → replaced
	if after := foreignState(t); after != before {
		t.Fatalf("second Load changed other tables:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestLoad_Twice_Atomic(t *testing.T) {
	ctx := context.Background()
	p := node(t)
	first, err := listTables(ctx)
	if err != nil {
		t.Fatal(err)
	}
	load(t, p)
	second, err := listTables(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("a second Load installed different tables:\n%s\n---\n%s", first, second)
	}
	// A file whose last rule does not parse: nothing of it applies, not even the
	// deletion of the tables at its top.
	orig, _ := os.ReadFile(p.NftFile())
	sum, _ := os.ReadFile(p.NftSum())
	bad := bytes.Replace(orig, []byte("\tdrop comment \"B9\""), []byte("\tdorp comment \"B9\""), 1)
	if bytes.Equal(bad, orig) {
		t.Fatal("B9 not found in the rendered file")
	}
	if err := os.WriteFile(p.NftFile(), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Load(ctx, p); err == nil {
		t.Fatal("Load of a broken file: nil error")
	}
	after, err := listTables(ctx)
	if err != nil {
		t.Fatalf("after a failed Load: %v", err)
	}
	if !bytes.Equal(after, first) {
		t.Fatalf("a failed Load changed the installed tables:\n%s", after)
	}
	if now, _ := os.ReadFile(p.NftSum()); !bytes.Equal(now, sum) {
		t.Fatal("a failed Load rewrote the sum file")
	}
	if err := os.WriteFile(p.NftFile(), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Check(ctx, p); err != nil {
		t.Fatalf("Check after a failed Load and the file restored: %v", err)
	}
}

// ───────── packet paths ─────────

// A TCP exchange crosses F2 and F4 in opposite directions, so each is shown
// deciding on the opening packet's direction with the other one deleted; the
// control deletes both.

func TestForward_RoutedIntoPlatformBridgeDropped(t *testing.T) {
	p := node(t)
	routedPlatform(t)
	gw := member(t, "spnft-gw", "spnft-plat", gatewayIP)
	rest := member(t, "spnft-rest", "spnft-plat", restIP)
	nb := neighbour(t)
	target := restIP + ":3000"
	listen(t, rest, target)
	expect(t, "gateway -> member (allowed peer)", gw, target, "connected")
	expect(t, "neighbour -> platform member, routed", nb, target, "timeout")
	withDeleted(t, p, []ruleRef{F2}, func() {
		expect(t, "neighbour -> platform member with F2 deleted (F4 drops the SYN)", nb, target, "timeout")
	})
	withDeleted(t, p, []ruleRef{F2, F4}, func() {
		expect(t, "neighbour -> platform member with F2 and F4 deleted", nb, target, "connected")
	})
	expect(t, "neighbour -> platform member, restored", nb, target, "timeout")
}

func TestForward_PlatformMemberHasNoRoutedEgress(t *testing.T) {
	p := node(t)
	routedPlatform(t)
	rest := member(t, "spnft-rest", "spnft-plat", restIP)
	nb := neighbour(t)
	target := "10.215.250.2:7002"
	listen(t, nb, target)
	expect(t, "node -> neighbour (allowed peer)", hostNS, target, "connected")
	expect(t, "platform member -> neighbour, routed", rest, target, "timeout")
	withDeleted(t, p, []ruleRef{F4}, func() {
		expect(t, "platform member -> neighbour with F4 deleted (F2 drops the SYN)", rest, target, "timeout")
	})
	withDeleted(t, p, []ruleRef{F2, F4}, func() {
		expect(t, "platform member -> neighbour with F2 and F4 deleted", rest, target, "connected")
	})
	expect(t, "platform member -> neighbour, restored", rest, target, "timeout")
}

func TestBridge_PlatformPorts(t *testing.T) {
	p := node(t)
	isolatedPlatform(t)
	gw := member(t, "spnft-gw", "spnft-plat", gatewayIP)
	rest := member(t, "spnft-rest", "spnft-plat", restIP)
	second := member(t, "spnft-second", "spnft-plat", secondIP)
	api, admin := restIP+":3000", restIP+":3001" // nothing listens on 3001
	listen(t, rest, api)
	expect(t, "gateway -> :3000", gw, api, "connected")
	expect(t, "gateway -> :3001 (closed: refused, not dropped)", gw, admin, "refused")
	expect(t, "second member -> :3000", second, api, "timeout")
	expect(t, "second member -> :3001", second, admin, "timeout")
	withDeleted(t, p, []ruleRef{B8}, func() {
		expect(t, "second member -> :3000 with B8 deleted", second, api, "connected")
		expect(t, "second member -> :3001 with B8 deleted", second, admin, "refused")
	})
	expect(t, "second member -> :3000, restored", second, api, "timeout")
}

func TestBridge_PlatformMemberInitiatesNothing(t *testing.T) {
	p := node(t)
	isolatedPlatform(t)
	gw := member(t, "spnft-gw", "spnft-plat", gatewayIP)
	third := member(t, "spnft-third", "spnft-plat", thirdIP)
	second := member(t, "spnft-second", "spnft-plat", secondIP)
	gwPort, thirdPort := gatewayIP+":8443", thirdIP+":4000"
	listen(t, gw, gwPort)
	listen(t, third, thirdPort)
	// No other member may open the gateway's port, so its listener is proven
	// from the gateway's own namespace.
	expect(t, "gateway -> its own :8443", gw, gwPort, "connected")
	expect(t, "gateway -> third member :4000 (allowed peer)", gw, thirdPort, "connected")
	expect(t, "second member -> gateway :8443", second, gwPort, "timeout")
	expect(t, "second member -> third member :4000", second, thirdPort, "timeout")
	withDeleted(t, p, []ruleRef{B8}, func() {
		expect(t, "second member -> gateway :8443 with B8 deleted", second, gwPort, "connected")
		expect(t, "second member -> third member :4000 with B8 deleted", second, thirdPort, "connected")
	})
	expect(t, "second member -> third member :4000, restored", second, thirdPort, "timeout")
}

const (
	tenantUID   = "70000"
	slice0      = "10.213.0.0/26"
	clusterIP   = "10.213.0.2"
	restSliceIP = "10.213.0.3"
	ingressGW   = "10.212.8.2"
	ingressHost = "10.212.8.1"
	helperEnv   = "SPNFT_HELPER"
)

// ───────── helper modes of this binary (re-executed in a tenant namespace) ─────────

func init() {
	if os.Getenv(helperEnv) == "" {
		return
	}
	os.Exit(helperMain(os.Args[1:]))
}

// bindDev returns a dialer Control that binds the socket to dev (unprivileged
// since Linux 5.7 on an unbound socket) and allows broadcast.
func bindDev(dev string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			if dev != "-" {
				if serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev); serr != nil {
					return
				}
			}
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// helperMain: dial tcp ADDR DEV | send udp ADDR DEV COUNT | recv udp ADDR |
// hold tcp ADDR DURATION | ctflush. dial prints a verdict like sp-probe (connected 0,
// refused 1, timeout 2, error 3).
func helperMain(a []string) int {
	switch {
	case len(a) == 4 && a[0] == "dial" && a[1] == "tcp":
		d := net.Dialer{Timeout: time.Second, Control: bindDev(a[3])}
		c, err := d.Dial("tcp", a[2])
		if err == nil {
			c.Close()
			fmt.Println("connected")
			return 0
		}
		var ne net.Error
		switch {
		case strings.Contains(err.Error(), "refused"):
			fmt.Println("refused")
			return 1
		case strings.Contains(err.Error(), "unreachable"):
			fmt.Println("unreachable")
			return 1
		case asTimeout(err, &ne):
			fmt.Println("timeout")
			return 2
		}
		fmt.Println("error", err)
		return 3
	case len(a) == 5 && a[0] == "send" && a[1] == "udp":
		n, _ := strconv.Atoi(a[4])
		lc := net.ListenConfig{Control: bindDev(a[3])}
		c, err := lc.ListenPacket(nil, "udp4", ":0")
		if err != nil {
			fmt.Println("error", err)
			return 3
		}
		ua, err := net.ResolveUDPAddr("udp4", a[2])
		if err != nil {
			fmt.Println("error", err)
			return 3
		}
		sent := 0
		for i := 0; i < n; i++ {
			if _, err := c.WriteTo([]byte("spnft "+rand.Text()), ua); err == nil {
				sent++
			} else if i == 0 {
				fmt.Println("error", err)
				return 3
			}
			time.Sleep(time.Millisecond)
		}
		fmt.Println("sent", sent)
		return 0
	case len(a) == 3 && a[0] == "recv" && a[1] == "udp":
		ua, err := net.ResolveUDPAddr("udp4", a[2])
		if err != nil {
			fmt.Println("error", err)
			return 3
		}
		c, err := net.ListenUDP("udp4", ua)
		if err != nil {
			fmt.Println("error", err)
			return 3
		}
		fmt.Println("listening", c.LocalAddr())
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return 3
			}
			if strings.HasPrefix(string(buf[:n]), "spnft ") {
				fmt.Println("got", from)
			}
		}
	case len(a) == 4 && a[0] == "hold" && a[1] == "tcp":
		dur, _ := time.ParseDuration(a[3])
		c, err := net.DialTimeout("tcp", a[2], time.Second)
		if err != nil {
			fmt.Println("error", err)
			return 3
		}
		defer c.Close()
		r := bufio.NewReader(c)
		n := 0
		for end := time.Now().Add(dur); time.Now().Before(end); n++ {
			c.SetDeadline(time.Now().Add(3 * time.Second))
			msg := fmt.Sprintf("line %d\n", n)
			if _, err := c.Write([]byte(msg)); err != nil {
				fmt.Println("broken", n, err)
				return 1
			}
			got, err := r.ReadString('\n')
			if err != nil || got != msg {
				fmt.Println("broken", n, err)
				return 1
			}
			time.Sleep(20 * time.Millisecond)
		}
		fmt.Println("held", n)
		return 0
	case len(a) == 4 && a[0] == "spoof" && a[1] == "tcp":
		// Source address not ours, bound with IP_FREEBIND (no capability needed).
		d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(a[3])},
			Control: func(_, _ string, rc syscall.RawConn) error {
				var serr error
				rc.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_FREEBIND, 1) })
				return serr
			}}
		c, err := d.Dial("tcp", a[2])
		if err == nil {
			c.Close()
			fmt.Println("connected")
			return 0
		}
		fmt.Println("error", err)
		return 3
	case len(a) == 4 && a[0] == "dialn" && a[1] == "tcp":
		// N connection attempts, 64 at a time, 100 ms each.
		n, _ := strconv.Atoi(a[3])
		var ok, next atomic.Int64
		var wg sync.WaitGroup
		for w := 0; w < 64; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for next.Add(1) <= int64(n) {
					if c, err := net.DialTimeout("tcp", a[2], 100*time.Millisecond); err == nil {
						c.Close()
						ok.Add(1)
					}
				}
			}()
		}
		wg.Wait()
		fmt.Println("connected", ok.Load(), "of", n)
		return 0
	case len(a) == 1 && a[0] == "ctflush":
		if err := ctFlush(); err != nil {
			fmt.Println("error", err)
			return 3
		}
		fmt.Println("flushed")
		return 0
	}
	fmt.Println("error usage", a)
	return 3
}

func asTimeout(err error, ne *net.Error) bool {
	e, ok := err.(net.Error)
	if ok {
		*ne = e
	}
	return ok && e.Timeout()
}

// ctFlush deletes every IPv4 conntrack entry of this namespace (conntrack -F).
func ctFlush() error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, 12) // NETLINK_NETFILTER
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	msg := make([]byte, 20)
	binary.NativeEndian.PutUint32(msg[0:], 20)
	binary.NativeEndian.PutUint16(msg[4:], 1<<8|2) // NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_DELETE
	binary.NativeEndian.PutUint16(msg[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:], 1)
	msg[16] = syscall.AF_INET
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	if n >= 20 && binary.NativeEndian.Uint16(buf[4:]) == syscall.NLMSG_ERROR {
		if e := int32(binary.NativeEndian.Uint32(buf[16:])); e != 0 {
			return syscall.Errno(-e)
		}
	}
	return nil
}

// ───────── test-side wrappers ─────────

func self(t testing.TB) string {
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// asTenant runs argv in pid's network namespace at the tenant uid (no capabilities).
func asTenant(pid int, args ...string) []string {
	if pid == hostNS {
		return args
	}
	return append([]string{"nsenter", "--net=/proc/" + strconv.Itoa(pid) + "/ns/net", "--setuid", tenantUID, "--setgid", tenantUID, "--"}, args...)
}

// tdial is a TCP connect at the tenant uid with the socket bound to dev.
func tdial(t *testing.T, pid int, addr, dev string) string {
	t.Helper()
	return verdictOf(t, addr, append([]string{"env", helperEnv + "=1"}, asTenant(pid, self(t), "dial", "tcp", addr, dev)...))
}

func texpect(t *testing.T, what string, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: %s, want %s", what, got, want)
	}
}

// receiver starts a UDP receiver at addr in pid's namespace (as root, it is
// the target) and returns a function reporting whether a datagram arrived
// since the last call, waiting up to wait.
func receiver(t *testing.T, pid int, addr string) func(wait time.Duration) bool {
	t.Helper()
	args := append([]string{"env", helperEnv + "=1"}, inNS(pid, self(t), "recv", "udp", addr)...)
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	lines := make(chan string, 1024)
	go func() {
		s := bufio.NewScanner(out)
		for s.Scan() {
			lines <- s.Text()
		}
		close(lines)
	}()
	select {
	case l := <-lines:
		if !strings.HasPrefix(l, "listening") {
			t.Fatalf("receiver %s: %q", addr, l)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("receiver %s did not start", addr)
	}
	return func(wait time.Duration) bool {
		got := false
		deadline := time.After(wait)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("receiver %s exited", addr)
				}
				if strings.HasPrefix(l, "got ") {
					got = true
				}
			case <-deadline:
				return got
			}
		}
	}
}

// tsend sends n datagrams to addr from pid at the tenant uid, socket bound to dev.
func tsend(t *testing.T, pid int, addr, dev string, n int) {
	t.Helper()
	argv := append([]string{"env", helperEnv + "=1"}, asTenant(pid, self(t), "send", "udp", addr, dev, strconv.Itoa(n))...)
	o, e, code, err := exe(nil, argv...)
	if err != nil || code != 0 {
		t.Fatalf("send %s: %v exit %d: %s %s", addr, err, code, o, e)
	}
}

// project is one slice as the agent builds it: network spp0 (internal,
// isolated), cluster at .2, PostgREST at .3 and on the platform bridge.
func project(t *testing.T) (cluster, rest int) {
	t.Helper()
	network(t, "spnft-proj0", "--internal", "--subnet", slice0,
		"-o", "com.docker.network.bridge.name=spp0",
		"-o", "com.docker.network.bridge.gateway_mode_ipv4=isolated")
	cluster = member(t, "spnft-pg", "spnft-proj0", clusterIP)
	rest = member(t, "spnft-rest", "spnft-proj0", restSliceIP)
	return cluster, rest
}

// ingress is the ingress network as the agent creates it, with the gateway on it.
func ingress(t *testing.T) int {
	t.Helper()
	network(t, "spnft-ingress", "--subnet", "10.212.8.0/24", "-o", "com.docker.network.bridge.name=spi0")
	return member(t, "spnft-gw", "spnft-ingress", ingressGW)
}

func ruleRefs(labels ...string) []ruleRef {
	var rs []ruleRef
	for _, l := range labels {
		switch l[0] {
		case 'I':
			rs = append(rs, ruleRef{"inet", "input", l})
		case 'F':
			rs = append(rs, ruleRef{"inet", "forward", l})
		default:
			rs = append(rs, ruleRef{"bridge", "forward", l})
		}
	}
	return rs
}

// ───────── project bridge ─────────

func TestBridge_ProjectBridge(t *testing.T) {
	p := node(t)
	cluster, rest := project(t)
	pg := clusterIP + ":5432"
	listen(t, cluster, pg)
	listen(t, cluster, clusterIP+":5433")
	listen(t, rest, restSliceIP+":3000")
	listen(t, rest, restSliceIP+":5432")
	texpect(t, "PostgREST -> cluster:5432", probe(t, rest, pg), "connected")
	for _, l := range []string{"B1", "B2", "B3"} {
		// Fresh neighbour caches, so ARP must cross the bridge again.
		must(t, inNS(rest, "ip", "neigh", "flush", "all")...)
		must(t, inNS(cluster, "ip", "neigh", "flush", "all")...)
		withDeleted(t, p, ruleRefs(l), func() {
			texpect(t, "PostgREST -> cluster:5432 with "+l+" deleted", probe(t, rest, pg), "timeout")
		})
	}
	texpect(t, "PostgREST -> cluster:5433", probe(t, rest, clusterIP+":5433"), "timeout")
	texpect(t, "cluster -> PostgREST:3000", probe(t, cluster, restSliceIP+":3000"), "timeout")
	texpect(t, "cluster -> PostgREST:5432", probe(t, cluster, restSliceIP+":5432"), "timeout")
	texpect(t, "cluster -> PostgREST:3000, bound to eth0", tdial(t, cluster, restSliceIP+":3000", "eth0"), "timeout")
	withPolicyAccept(t, p, func() {
		texpect(t, "PostgREST -> cluster:5433 with policy accept", probe(t, rest, clusterIP+":5433"), "connected")
		texpect(t, "cluster -> PostgREST:3000 with policy accept", probe(t, cluster, restSliceIP+":3000"), "connected")
		texpect(t, "cluster -> PostgREST:5432 with policy accept", probe(t, cluster, restSliceIP+":5432"), "connected")
	})
}

// withPolicyAccept deletes B9 and turns the bridge chain's policy to accept
// (the control of a path that only the chain's final drop stops), runs fn and
// reloads.
func withPolicyAccept(t *testing.T, p nodecfg.Paths, fn func()) {
	t.Helper()
	defer load(t, p)
	deleteRule(t, ruleRef{"bridge", "forward", "B9"})
	must(t, "nft", "chain", "bridge", "supapace", "forward", "{ policy accept; }")
	fn()
}

// ───────── host input from a tenant that names its interface ─────────

// rpFilterOff sets rp_filter 0 in the node's namespace for the test: with
// strict or loose filtering the kernel already discards IPv4 arriving on a
// bridge that has no IPv4 address, which would mask I2. A host may run with 0.
func rpFilterOff(t *testing.T, ifaces ...string) {
	t.Helper()
	for _, k := range append([]string{"all", "default"}, ifaces...) {
		f := "/proc/sys/net/ipv4/conf/" + k + "/rp_filter"
		old, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.WriteFile(f, old, 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("restoring %s: %v", f, err)
			}
		})
		if err := os.WriteFile(f, []byte("0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// nodeAddr gives the node an extra address on a dummy interface: a host
// address that is not on any bridge.
func nodeAddr(t *testing.T, cidr string) {
	t.Helper()
	t.Cleanup(func() { try(t, "ip", "link", "del", "spnftd") })
	must(t, "ip", "link", "add", "spnftd", "type", "dummy")
	must(t, "ip", "addr", "add", cidr, "dev", "spnftd")
	must(t, "ip", "link", "set", "spnftd", "up")
}

// No route is needed to reach the host: a socket bound to its interface treats
// every destination as on-link, and the host answers ARP for any address it owns.
func TestInput_TenantBoundToItsInterface(t *testing.T) {
	p := node(t)
	nodeAddr(t, "10.215.251.1/32")
	cluster, _ := project(t)
	isolatedPlatform(t)
	plat := member(t, "spnft-plat-member", "spnft-plat", thirdIP)
	rpFilterOff(t, "spp0", "spl0")
	got := receiver(t, hostNS, "0.0.0.0:7200")
	send := func() {
		for _, src := range []int{cluster, plat} {
			tsend(t, src, "10.215.251.1:7200", "eth0", 5)
			tsend(t, src, "255.255.255.255:7200", "eth0", 5)
		}
	}
	send()
	if got(time.Second) {
		t.Error("a tenant bound to its interface reached a host listener")
	}
	withDeleted(t, p, ruleRefs("I2"), func() {
		tsend(t, cluster, "10.215.251.1:7200", "eth0", 5)
		if !got(time.Second) {
			t.Error("control: with I2 deleted the cluster's datagrams to a host address did not arrive")
		}
		tsend(t, plat, "255.255.255.255:7200", "eth0", 5)
		if !got(time.Second) {
			t.Error("control: with I2 deleted the platform member's broadcast did not arrive")
		}
	})
	// Only the bridge table: the host is open.
	must(t, "nft", "delete", "table", "inet", "supapace")
	if err := Check(t.Context(), p); !errors.Is(err, ErrAbsent) {
		t.Errorf("Check without the inet table: %v, want ErrAbsent", err)
	}
	tsend(t, cluster, "10.215.251.1:7200", "eth0", 5)
	if !got(time.Second) {
		t.Error("without the inet table the cluster's datagrams did not arrive")
	}
	load(t, p)
	send()
	if got(time.Second) {
		t.Error("after reload a tenant reached a host listener")
	}
}

// PostgREST's kernel answers ARP for its platform address on the project bridge
// too, so the cluster can address it there (bound to its interface; the
// cluster's own reverse-path filter would drop a TCP reply, so the receiving
// side is watched).
func TestBridge_ClusterToPostgRESTPlatformAddress(t *testing.T) {
	p := node(t)
	cluster, rest := project(t)
	isolatedPlatform(t)
	must(t, "docker", "network", "connect", "--ip", restIP, "spnft-plat", "spnft-rest")
	t.Cleanup(func() { try(t, "docker", "network", "disconnect", "-f", "spnft-plat", "spnft-rest") })
	got := receiver(t, rest, "0.0.0.0:3000")
	tsend(t, cluster, restIP+":3000", "eth0", 5)
	if got(time.Second) {
		t.Error("cluster reached PostgREST's platform address over the project bridge")
	}
	withPolicyAccept(t, p, func() {
		tsend(t, cluster, restIP+":3000", "eth0", 5)
		if !got(time.Second) {
			t.Error("control: with policy accept the datagrams did not arrive")
		}
	})
}

// ───────── ingress bridge: host, published port, gateway egress ─────────

// ingressWithGateway is the ingress network with the gateway publishing
// 0.0.0.0:18443 → 8443 and listening, a second member, and a neighbour.
func ingressWithGateway(t *testing.T) (gw, other, nb int) {
	t.Helper()
	network(t, "spnft-ingress", "--subnet", "10.212.8.0/24", "-o", "com.docker.network.bridge.name="+nodecfg.IngressBridge)
	t.Cleanup(func() { try(t, "docker", "rm", "-f", "spnft-gw") })
	must(t, "docker", "run", "-d", "--name", "spnft-gw", "--label", testLabel, "--network", "spnft-ingress", "--ip", ingressGW,
		"-p", "0.0.0.0:18443:8443", "--cap-drop", "ALL", "--entrypoint", "sleep", image(t), "86400")
	gw, _ = strconv.Atoi(strings.TrimSpace(must(t, "docker", "inspect", "-f", "{{.State.Pid}}", "spnft-gw")))
	other = member(t, "spnft-ingress-2", "spnft-ingress", "10.212.8.3")
	nb = neighbour(t)
	listen(t, gw, ingressGW+":8443")
	return gw, other, nb
}

const published = "10.215.250.1:18443" // the published port, from the neighbour

func TestIngress_Paths(t *testing.T) {
	p := node(t)
	gw, _, nb := ingressWithGateway(t)
	gwPort := ingressGW + ":8443"
	listen(t, hostNS, ingressHost+":7100")
	listen(t, nb, "10.215.250.2:7002")

	texpect(t, "host -> gateway (I1)", probe(t, hostNS, gwPort), "connected")
	texpect(t, "neighbour -> published port (F3, F1)", probe(t, nb, published), "connected")
	texpect(t, "gateway -> host on the ingress bridge", probe(t, gw, ingressHost+":7100"), "timeout")
	texpect(t, "gateway -> outside", probe(t, gw, "10.215.250.2:7002"), "timeout")
	withDeleted(t, p, ruleRefs("I1"), func() {
		texpect(t, "host -> gateway with I1 deleted", probe(t, hostNS, gwPort), "timeout")
	})
	withDeleted(t, p, ruleRefs("I2"), func() {
		texpect(t, "gateway -> host with I2 deleted", probe(t, gw, ingressHost+":7100"), "connected")
	})
	withDeleted(t, p, ruleRefs("F1"), func() {
		texpect(t, "neighbour -> published port with F1 deleted", probe(t, nb, published), "timeout")
	})
	withDeleted(t, p, ruleRefs("F3"), func() {
		texpect(t, "neighbour -> published port with F3 deleted", probe(t, nb, published), "timeout")
	})
	withDeleted(t, p, ruleRefs("F2"), func() {
		texpect(t, "gateway -> outside with F2 deleted", probe(t, gw, "10.215.250.2:7002"), "connected")
	})
}

// Members of the ingress bridge cannot reach each other; the host's and the
// published port's paths to the gateway do not cross the bridge chain.
func TestIngress_MembersIsolated(t *testing.T) {
	p := node(t)
	gw, other, nb := ingressWithGateway(t)
	gwPort := ingressGW + ":8443"
	listen(t, other, "10.212.8.3:4000")
	texpect(t, "host -> gateway", probe(t, hostNS, gwPort), "connected")
	texpect(t, "neighbour -> published port", probe(t, nb, published), "connected")
	texpect(t, "second ingress member -> gateway", probe(t, other, gwPort), "timeout")
	texpect(t, "gateway -> second ingress member", probe(t, gw, "10.212.8.3:4000"), "timeout")
	withPolicyAccept(t, p, func() {
		texpect(t, "second ingress member -> gateway with the chain open", probe(t, other, gwPort), "connected")
		texpect(t, "gateway -> second ingress member with the chain open", probe(t, gw, "10.212.8.3:4000"), "connected")
	})
}

// ───────── platform bridge: a forged source address ─────────

func TestBridge_PlatformMemberCannotForgeGateway(t *testing.T) {
	node(t)
	isolatedPlatform(t)
	third := member(t, "spnft-third", "spnft-plat", thirdIP)
	second := member(t, "spnft-second", "spnft-plat", secondIP)
	listen(t, third, thirdIP+":4000")
	o, _, code, err := exe(nil, append([]string{"env", helperEnv + "=1"}, asTenant(second, self(t), "spoof", "tcp", thirdIP+":4000", gatewayIP)...)...)
	if err != nil || code == 0 || strings.HasPrefix(o, "connected") {
		t.Errorf("second member with the gateway's source address -> third: %q exit %d %v", o, code, err)
	}
	t.Logf("forged source: %s", strings.TrimSpace(o))
}

// ───────── reload and conntrack flush under traffic ─────────

func TestLoad_ReloadUnderTraffic(t *testing.T) {
	p := node(t)
	cluster, rest := project(t)
	isolatedPlatform(t)
	third := member(t, "spnft-third", "spnft-plat", thirdIP)
	second := member(t, "spnft-second", "spnft-plat", secondIP)
	listen(t, cluster, clusterIP+":5432")
	listen(t, rest, restSliceIP+":3001")
	toRest := receiver(t, rest, restSliceIP+":3000")
	toThird := receiver(t, third, thirdIP+":4000")
	flood := func(n int) {
		tsend(t, cluster, restSliceIP+":3000", "-", n)
		tsend(t, second, thirdIP+":4000", "-", n)
	}
	// Control: without our bridge table both floods arrive.
	must(t, "nft", "delete", "table", "bridge", "supapace")
	flood(5)
	if !toRest(time.Second) || !toThird(time.Second) {
		t.Fatal("control: without the bridge table a flood did not arrive")
	}
	load(t, p)
	flood(5)
	if toRest(time.Second) || toThird(time.Second) {
		t.Fatal("flood arrived with the tables loaded")
	}

	type res struct {
		name, out string
		code      int
	}
	done := make(chan res, 4)
	run := func(name string, argv ...string) {
		go func() {
			o, e, code, _ := exe(nil, append([]string{"env", helperEnv + "=1"}, argv...)...)
			done <- res{name, strings.TrimSpace(o + " " + e), code}
		}()
	}
	// Continuous reloads under 60,000 datagrams and 50,000 connection attempts.
	// The project flood and the connection attempts fall to the bridge chain's
	// final drop; the platform flood to rule B8.
	run("hold", asTenant(rest, self(t), "hold", "tcp", clusterIP+":5432", "60s")...)
	run("flood-project", asTenant(cluster, self(t), "send", "udp", restSliceIP+":3000", "-", "30000")...)
	run("flood-platform", asTenant(second, self(t), "send", "udp", thirdIP+":4000", "-", "30000")...)
	run("dialn", asTenant(cluster, self(t), "dialn", "tcp", restSliceIP+":3001", "50000")...)
	loads := 0
	var results []res
	for len(results) < 4 {
		select {
		case r := <-done:
			results = append(results, r)
		default:
			if err := Load(t.Context(), p); err != nil {
				t.Fatalf("Load %d: %v", loads, err)
			}
			loads++
		}
	}
	t.Logf("%d loads during the traffic", loads)
	for _, r := range results {
		t.Logf("%s: %s (exit %d)", r.name, r.out, r.code)
		switch {
		case r.name == "hold" && (r.code != 0 || !strings.HasPrefix(r.out, "held")):
			t.Errorf("open allowed flow broke during reloads: %s", r.out)
		case r.name == "dialn" && !strings.HasPrefix(r.out, "connected 0 of"):
			t.Errorf("cluster -> PostgREST:3001 connected during reloads: %s", r.out)
		}
	}
	if toRest(time.Second) {
		t.Error("cluster -> PostgREST UDP arrived during reloads")
	}
	if toThird(time.Second) {
		t.Error("platform member -> third UDP arrived during reloads")
	}

	// A conntrack flush in the middle of an open allowed flow: the client speaks
	// first, so the flow is picked up again as new and B3 accepts it.
	run("hold", asTenant(rest, self(t), "hold", "tcp", clusterIP+":5432", "3s")...)
	time.Sleep(time.Second)
	must(t, "env", helperEnv+"=1", self(t), "ctflush")
	if r := <-done; r.code != 0 || !strings.HasPrefix(r.out, "held") {
		t.Errorf("open allowed flow broke after a conntrack flush: %s", r.out)
	}
	texpect(t, "cluster -> PostgREST:3001 after the flush", probe(t, cluster, restSliceIP+":3001"), "timeout")
}

// The inet table's chains accept by policy and drop by rules (I2, F2, F4):
// reloading must not lose those drops for a moment either.
func TestLoad_ReloadUnderTrafficInet(t *testing.T) {
	p := node(t)
	nodeAddr(t, "10.215.251.1/32")
	routedPlatform(t)
	m := member(t, "spnft-rest", "spnft-plat", restIP)
	nb := neighbour(t)
	toHost := receiver(t, hostNS, "10.215.251.1:7200")
	toNb := receiver(t, nb, "10.215.250.2:7002")
	toMember := receiver(t, m, restIP+":4000")
	listen(t, hostNS, "10.215.251.1:7201")
	flood := func(n int) {
		tsend(t, m, "10.215.251.1:7200", "-", n)
		tsend(t, m, "10.215.250.2:7002", "-", n)
		tsend(t, nb, restIP+":4000", "-", n)
	}
	// Control: without our inet table every flood arrives.
	must(t, "nft", "delete", "table", "inet", "supapace")
	flood(5)
	if !toHost(time.Second) || !toNb(time.Second) || !toMember(time.Second) {
		t.Fatal("control: without the inet table a flood did not arrive")
	}
	load(t, p)
	flood(5)
	if toHost(time.Second) || toNb(time.Second) || toMember(time.Second) {
		t.Fatal("a flood arrived with the tables loaded")
	}
	type res struct {
		name, out string
		code      int
	}
	done := make(chan res, 4)
	run := func(name string, argv ...string) {
		go func() {
			o, e, code, _ := exe(nil, append([]string{"env", helperEnv + "=1"}, argv...)...)
			done <- res{name, strings.TrimSpace(o + " " + e), code}
		}()
	}
	run("flood-host (I2)", asTenant(m, self(t), "send", "udp", "10.215.251.1:7200", "-", "20000")...)
	run("flood-out (F2)", asTenant(m, self(t), "send", "udp", "10.215.250.2:7002", "-", "20000")...)
	run("flood-in (F4)", asTenant(nb, self(t), "send", "udp", restIP+":4000", "-", "20000")...)
	run("dialn-host (I2)", asTenant(m, self(t), "dialn", "tcp", "10.215.251.1:7201", "50000")...)
	loads := 0
	var results []res
	for len(results) < 4 {
		select {
		case r := <-done:
			results = append(results, r)
		default:
			if err := Load(t.Context(), p); err != nil {
				t.Fatalf("Load %d: %v", loads, err)
			}
			loads++
		}
	}
	t.Logf("%d loads during the traffic", loads)
	for _, r := range results {
		t.Logf("%s: %s (exit %d)", r.name, r.out, r.code)
		if r.code != 0 {
			t.Errorf("%s failed: %s", r.name, r.out)
		}
		if strings.HasPrefix(r.name, "dialn") && !strings.HasPrefix(r.out, "connected 0 of") {
			t.Errorf("member -> host TCP connected during reloads: %s", r.out)
		}
	}
	if toHost(time.Second) {
		t.Error("member -> host UDP arrived during reloads")
	}
	if toNb(time.Second) {
		t.Error("member -> neighbour UDP arrived during reloads")
	}
	if toMember(time.Second) {
		t.Error("neighbour -> member UDP arrived during reloads")
	}
}

// ───────── Check: drift classes ─────────

func TestCheck_DriftClasses(t *testing.T) {
	ctx := t.Context()
	p := node(t)
	handle := func(label string) string {
		hs := labels(t, "bridge", "forward")[label]
		if len(hs) != 1 {
			t.Fatalf("%d rules labelled %s", len(hs), label)
		}
		return strconv.Itoa(hs[0])
	}
	for _, c := range []struct {
		what string
		argv []string
	}{
		{"policy accept", []string{"nft", "chain", "bridge", "supapace", "forward", "{ policy accept; }"}},
		{"chain flushed", []string{"nft", "flush", "chain", "bridge", "supapace", "forward"}},
		{"chain added", []string{"nft", "add", "chain", "bridge", "supapace", "extra"}},
		{"set added", []string{"nft", "add", "set", "inet", "supapace", "extra", "{ type ipv4_addr; }"}},
		{"accept at the top", []string{"nft", "insert", "rule", "inet", "supapace", "input", "accept"}},
		{"comment only", []string{"nft", "replace", "rule", "bridge", "supapace", "forward", "handle", "B6",
			`meta ibrname "spl0" ether type ip accept comment "B6x"`}},
		{"counter added", []string{"nft", "replace", "rule", "bridge", "supapace", "forward", "handle", "B6",
			`meta ibrname "spl0" ether type ip counter accept comment "B6"`}},
	} {
		argv := c.argv
		for i, a := range argv {
			if a == "B6" && i > 0 && argv[i-1] == "handle" {
				argv[i] = handle("B6")
			}
		}
		must(t, argv...)
		if err := Check(ctx, p); !errors.Is(err, ErrDrift) {
			t.Errorf("Check after %s: %v, want ErrDrift", c.what, err)
		}
		load(t, p)
	}
	// Another table cannot undo a drop of ours by accepting first; Check does
	// not look at it and passes.
	if _, e, code, err := exe([]byte("table bridge spnftzz {\n chain f {\n  type filter hook forward priority -300; policy accept;\n  accept\n }\n}\n"), "nft", "-f", "-"); err != nil || code != 0 {
		t.Fatalf("foreign table: %v %s", err, e)
	}
	t.Cleanup(func() { try(t, "nft", "delete", "table", "bridge", "spnftzz") })
	if err := Check(ctx, p); err != nil {
		t.Errorf("Check with a foreign table: %v", err)
	}
}

// TestMain refuses to run where br_netfilter would send bridged frames through
// the routed chains: the bridge tests would then measure the wrong path.
func TestMain(m *testing.M) {
	if b, err := os.ReadFile("/proc/sys/net/bridge/bridge-nf-call-iptables"); err == nil && strings.TrimSpace(string(b)) != "0" {
		fmt.Fprintln(os.Stderr, "bridge-nf-call-iptables is on in this namespace; refusing to run")
		os.Exit(1)
	}
	os.Exit(m.Run())
}
