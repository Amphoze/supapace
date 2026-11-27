//go:build reach

package agent

// The forwarding settings of a container on two networks, against real
// Docker and the kernel of a bare node, as root.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/nsdial"
	"github.com/Amphoze/supapace/internal/testdocker"
)

// fwNS runs a command inside the network namespace of the container's init
// process pid.
func fwNS(t *testing.T, pid int, args ...string) string {
	t.Helper()
	out, err := exec.Command("nsenter", append([]string{"--net=/proc/" + strconv.Itoa(pid) + "/ns/net", "--"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("in the namespace of pid %d: %s: %v: %s", pid, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// fwPid is the pid of the container's init process.
func fwPid(t *testing.T, name string) int {
	t.Helper()
	pid, err := strconv.Atoi(nodeDocker(t, "container", "inspect", "--format", "{{.State.Pid}}", "--", name))
	if err != nil || pid <= 0 {
		t.Fatalf("%s has no process: %v", name, err)
	}
	return pid
}

// fwDial makes one TCP connection attempt from inside the namespace of pid
// to a port nothing listens on: "refused" when the destination answered,
// "timeout" when nothing came back within wait.
func fwDial(t *testing.T, pid int, to string, wait time.Duration) string {
	t.Helper()
	target, err := nsdial.TargetOf(pid)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	conn, err := nsdial.DialTCP(ctx, target, func(context.Context) (nsdial.Target, error) { return nsdial.TargetOf(pid) },
		netip.MustParseAddrPort(to))
	switch {
	case err == nil:
		conn.Close()
		return "connected"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	}
	return err.Error()
}

// TestNode_ForwardingDefaultsAndApplied: what a container on this node
// starts with is recorded (a new namespace takes the host's values). A
// container created with the settings of dashcfg.NoForwardArgs on one
// bridge, to which a second network is attached after it started, has them
// inside its namespace, before and after the attach; on its first interface
// and on the one attached later nothing is forwarded, IPv6 is off, the
// reverse-path filter is the strict one and arp_ignore is 1; and nothing is
// forwarded between the two networks. The same holds on both interfaces of a
// container whose second network is connected before its start.
// Controls on the same path: its own address on the second network answers
// through the same route, and a container with forwarding on does forward.
func TestNode_ForwardingDefaultsAndApplied(t *testing.T) {
	a := nodeAgent(t)
	img := a.cfg.Images.ControlPlane
	const (
		netA, netB     = "sp-test-fwd-a", "sp-test-fwd-b"
		subA, subB     = "10.214.255.0/26", "10.214.255.64/26"
		client, server = "10.214.255.10", "10.214.255.74"
		closedPort     = ":7099" // nothing listens: an answer is a reset
	)
	names := []string{"sp-test-fwd-client", "sp-test-fwd-server", "sp-test-fwd-default", "sp-test-fwd-off", "sp-test-fwd-on", "sp-test-fwd-pre"}
	cleanup := func() {
		for _, n := range names {
			nodeDockerQuiet("rm", "-f", n)
		}
		nodeDockerQuiet("network", "rm", netA)
		nodeDockerQuiet("network", "rm", netB)
	}
	cleanup()
	t.Cleanup(cleanup)
	// Two bridges like the platform's: internal, and no address of the node on
	// them, so that nothing but a member routes between them.
	for n, sub := range map[string]string{netA: subA, netB: subB} {
		nodeDocker(t, "network", "create", "--internal", "--ipv6=false", "--subnet", sub, "-o", optGatewayMode+"=isolated",
			"--label", "supapace.test=1", n)
	}
	run := func(name, net, ip string, args ...string) int {
		t.Helper()
		nodeDocker(t, slices.Concat([]string{"run", "-d", "--name", name}, testdocker.Labels(t), []string{"--cap-drop", "ALL",
			"--network", net, "--ip", ip}, args, []string{"--entrypoint", "sleep", img, "600"})...)
		return fwPid(t, name)
	}
	cpid := run(names[0], netA, client)
	spid := run(names[1], netB, server)

	// The settings as name and value, and the file each is read from.
	type setting struct{ key, want, file string }
	var settings []setting
	for _, kv := range dashcfg.NoForwardArgs() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			settings = append(settings, setting{k, v, "/proc/sys/" + strings.ReplaceAll(k, ".", "/")})
		}
	}
	read := func(pid int, files ...string) []string {
		return strings.Fields(fwNS(t, pid, append([]string{"cat"}, files...)...))
	}
	wide := func(pid int) []string {
		var files []string
		for _, s := range settings {
			files = append(files, s.file)
		}
		return read(pid, files...)
	}
	// ifaceOf is the interface of the namespace of pid that holds addr.
	ifaceOf := func(pid int, addr string) string {
		t.Helper()
		for _, l := range strings.Split(fwNS(t, pid, "ip", "-o", "-4", "addr", "show"), "\n") {
			if f := strings.Fields(l); len(f) > 3 && strings.HasPrefix(f[3], addr+"/") {
				return f[1]
			}
		}
		t.Fatalf("no interface of pid %d holds %s", pid, addr)
		return ""
	}
	// inEffect reads what holds on one interface: forwarding and IPv6 are the
	// interface's own; for the reverse-path filter and arp_ignore the kernel
	// takes the larger of the interface's value and conf/all's (one digit each).
	type effect struct{ forwarding, v6off, rp, arp string }
	inEffect := func(pid int, ifc string) effect {
		v4, v6 := "/proc/sys/net/ipv4/conf/", "/proc/sys/net/ipv6/conf/"
		v := read(pid, v4+ifc+"/forwarding", v6+ifc+"/disable_ipv6", v4+ifc+"/rp_filter", v4+"all/rp_filter",
			v4+ifc+"/arp_ignore", v4+"all/arp_ignore")
		return effect{v[0], v[1], max(v[2], v[3]), max(v[4], v[5])}
	}
	// strict is what the settings come to on every interface: no forwarding,
	// IPv6 off, the strict reverse-path filter (1; 2 is the loose one, 0 none),
	// arp_ignore 1.
	strict := effect{"0", "1", "1", "1"}
	var keys []string
	for _, s := range settings {
		keys = append(keys, s.key)
	}
	routers := []struct {
		name     string
		host     int // its host address on both networks
		args     []string
		settings bool   // created with the settings
		want     string // what the client's dial to the server must give; "" records it
	}{
		{names[2], 2, nil, false, ""},
		{names[3], 3, dashcfg.NoForwardArgs(), true, "timeout"},
		{names[4], 4, []string{"--sysctl", "net.ipv4.ip_forward=1"}, false, "refused"},
	}
	for _, r := range routers {
		onA, onB := fmt.Sprintf("10.214.255.%d", r.host), fmt.Sprintf("10.214.255.%d", 64+r.host)
		pid := run(r.name, netA, onA, r.args...)
		before := wide(pid)
		// The second network, attached after the start.
		nodeDocker(t, "network", "connect", "--ip", onB, netB, r.name)
		first, late := ifaceOf(pid, onA), ifaceOf(pid, onB)
		after := wide(pid)
		e1, e2 := inEffect(pid, first), inEffect(pid, late)
		t.Logf("%s (%s): %v at start %v, after the attach %v; in effect (forwarding, disable_ipv6, rp_filter, arp_ignore) "+
			"on its first interface %s %v, on %s attached later %v", r.name, strings.Join(r.args, " "), keys, before, after, first, e1, late, e2)
		if r.settings {
			for i, s := range settings {
				if before[i] != s.want || after[i] != s.want {
					t.Errorf("%s: %s is %s at start and %s after the attach, want %s", r.name, s.key, before[i], after[i], s.want)
				}
			}
			if e1 != strict || e2 != strict {
				t.Errorf("%s: in effect on its first interface %v, on the one attached later %v; want %v on both", r.name, e1, e2, strict)
			}
		}
		// The route of each side to the other network goes through this container.
		fwNS(t, cpid, "ip", "route", "replace", subB, "via", onA)
		fwNS(t, spid, "ip", "route", "replace", subA, "via", onB)
		// Control on the same route: the container's own address on the second
		// network answers the client.
		if got := fwDial(t, cpid, onB+closedPort, 20*time.Second); got != "refused" {
			t.Fatalf("%s: control: the client does not reach %s through its route: %s", r.name, onB, got)
		}
		wait := 20 * time.Second
		if r.want == "timeout" {
			wait = 4 * time.Second
		}
		got := fwDial(t, cpid, server+closedPort, wait)
		t.Logf("%s: the client's connection to the server on the other network: %s", r.name, got)
		if r.want != "" && got != r.want {
			t.Errorf("%s: the client's connection to the server: %s, want %s", r.name, got, r.want)
		}
		nodeDocker(t, "rm", "-f", r.name)
	}
	// As the platform makes its containers on two networks: created with the
	// settings, the second network connected, then started.
	nodeDocker(t, slices.Concat([]string{"create", "--name", names[5]}, testdocker.Labels(t), []string{"--cap-drop", "ALL",
		"--network", netA, "--ip", "10.214.255.5"}, dashcfg.NoForwardArgs(), []string{"--entrypoint", "sleep", img, "600"})...)
	nodeDocker(t, "network", "connect", "--ip", "10.214.255.69", netB, names[5])
	nodeDocker(t, "start", names[5])
	pid := fwPid(t, names[5])
	for _, addr := range []string{"10.214.255.5", "10.214.255.69"} {
		if e := inEffect(pid, ifaceOf(pid, addr)); e != strict {
			t.Errorf("%s, both networks connected before its start: in effect on the interface at %s %v, want %v", names[5], addr, e, strict)
		}
	}
}
