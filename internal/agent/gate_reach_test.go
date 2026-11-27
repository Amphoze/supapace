//go:build reach

package agent

// The start gate and the platform objects against real Docker in a bare
// node, as root. Each case logs what Docker recorded and what the agent
// concluded, and fails when the agent accepts what it must refuse.

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/testdocker"
)

func gnCase(t *testing.T) (*Agent, Spec, func(args ...string) string) {
	a := nodeAgent(t)
	ctx := context.Background()
	s := Spec{Ref: "gatecase000000000001", Epoch: 1, Generation: 1, SubnetIndex: 9}
	var made []string
	run := func(args ...string) string {
		t.Helper()
		if args[0] == "run" || args[0] == "create" { // removed by the watchdog should this process be killed
			args = slices.Concat(args[:1], testdocker.Labels(t), args[1:])
		}
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, out)
		}
		if len(args) > 3 && (args[0] == "run" || args[0] == "create") {
			for i, x := range args {
				if x == "--name" {
					made = append(made, args[i+1])
				}
			}
		}
		return strings.TrimSpace(string(out))
	}
	t.Cleanup(func() {
		for i := len(made) - 1; i >= 0; i-- {
			nodeDockerQuiet("rm", "-f", made[i])
		}
		for _, n := range []string{networkName(s.Ref), platformNet, ingressNet} {
			nodeDockerQuiet("network", "rm", n)
		}
	})
	if err := a.EnsurePlatformNetworks(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureNetwork(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := a.CheckAdopted(ctx, s); err != nil {
		t.Fatalf("control: %v", err)
	}
	return a, s, run
}

func gnHostConfig(t *testing.T, name string) string {
	out, _ := exec.Command("docker", "container", "inspect", "--format",
		`{{json .HostConfig.Privileged}} {{json .HostConfig.CapAdd}} {{json .HostConfig.CapDrop}} {{json .HostConfig.NetworkMode}}`, "--", name).CombinedOutput()
	return strings.TrimSpace(string(out))
}

// A container that shares a project member's network namespace
// (--network container:NAME) holds NET_RAW in that namespace, yet it is not
// a member of any network.
func TestNode_GateSeesNetworkNamespaceSharer(t *testing.T) {
	a, s, run := gnCase(t)
	img := a.cfg.Images.ControlPlane
	run("run", "-d", "--name", "sp-test-gate-member", "--label", "supapace.test=1", "--network", networkName(s.Ref),
		"--cap-drop", "ALL", "--entrypoint", "sleep", img, "300")
	run("run", "-d", "--name", "sp-test-gate-sharer", "--label", "supapace.test=1", "--network", "container:sp-test-gate-member",
		"--entrypoint", "sleep", img, "300")
	t.Logf("sharer: %s", gnHostConfig(t, "sp-test-gate-sharer"))
	n, _ := dockerInspectNetwork(context.Background(), networkName(s.Ref))
	t.Logf("network members: %v", n.Containers)
	err := a.CheckAdopted(context.Background(), s)
	t.Logf("gate with a NET_RAW namespace sharer: %v", err)
	if !errors.Is(err, ErrContainment) {
		t.Errorf("gate passes while a container with default capabilities shares a member's network namespace")
	}
}

// A created, never started container configured on platform with the
// project's platform address.
func TestNode_StoppedHolderOfPlatformAddr(t *testing.T) {
	a, s, run := gnCase(t)
	img := a.cfg.Images.ControlPlane
	addr := a.cfg.PlatformAddr(s.SubnetIndex).String()
	run("create", "--name", "sp-test-gate-holder", "--label", "supapace.test=1", "--network", platformNet, "--ip", addr,
		"--cap-drop", "ALL", "--entrypoint", "sleep", img, "300")
	err := a.CheckAdopted(context.Background(), s)
	t.Logf("gate with a created foreign holder of %s: %v", addr, err)
	// Our PostgREST stand-in, created, connected at the same address, gated, started.
	pr := postgrestName(s.Ref)
	run("create", "--name", pr, "--label", "supapace.test=1", "--network", networkName(s.Ref), "--cap-drop", "ALL",
		"--entrypoint", "sleep", img, "300")
	out, cerr := exec.Command("docker", "network", "connect", "--ip", addr, platformNet, pr).CombinedOutput()
	t.Logf("connect ours at the same address while the foreign one is created: %v %s", cerr, out)
	t.Logf("gate before our start: %v", a.CheckAdopted(context.Background(), s))
	out, serr := exec.Command("docker", "start", pr).CombinedOutput()
	t.Logf("start ours: %v %s", serr, out)
	out, ferr := exec.Command("docker", "start", "sp-test-gate-holder").CombinedOutput()
	t.Logf("start the foreign holder after ours: %v %s", ferr, out)
	if ferr == nil {
		t.Errorf("two running holders of %s", addr)
	}
	t.Logf("gate after: %v", a.CheckAdopted(context.Background(), s))
	// Reverse order: the foreign one runs first, ours is gated.
	exec.Command("docker", "stop", "-t", "0", pr).Run()
	if out, err := exec.Command("docker", "start", "sp-test-gate-holder").CombinedOutput(); err != nil {
		t.Fatalf("start foreign: %v %s", err, out)
	}
	if err := a.CheckAdopted(context.Background(), s); !errors.Is(err, ErrContainment) {
		t.Errorf("a running foreign holder passes the gate: %v", err)
	}
	out, serr = exec.Command("docker", "start", pr).CombinedOutput()
	t.Logf("start ours while the foreign one runs: %v %s", serr, out)
}

// Every way of asking for a capability at create time: what Docker
// records, and the gate's verdict for a project member so configured.
func TestNode_GateCapabilitySpellings(t *testing.T) {
	a, s, run := gnCase(t)
	img := a.cfg.Images.ControlPlane
	cases := []struct {
		name  string
		flags []string
		bad   bool
	}{
		{"lower net_raw", []string{"--cap-drop", "ALL", "--cap-add", "net_raw"}, true},
		{"cap_ prefix", []string{"--cap-drop", "ALL", "--cap-add", "CAP_NET_ADMIN"}, true},
		{"equals all", []string{"--cap-drop=ALL", "--cap-add=all"}, true},
		{"drop lower all", []string{"--cap-drop", "all"}, false},
		{"drop cap_all", []string{"--cap-drop", "CAP_ALL"}, false},
		{"drop all then add", []string{"--cap-drop", "ALL", "--cap-add", "NET_RAW", "--cap-drop", "NET_RAW"}, true},
		{"privileged=true", []string{"--cap-drop", "ALL", "--privileged=true"}, true},
		{"default caps", nil, true},
		{"drop net_raw only", []string{"--cap-drop", "NET_RAW", "--cap-drop", "NET_ADMIN"}, true},
		{"sys_admin added", []string{"--cap-drop", "ALL", "--cap-add", "SYS_ADMIN"}, true},
		{"device net tun", []string{"--cap-drop", "ALL", "--device", "/dev/net/tun"}, false},
	}
	for i, c := range cases {
		name := "sp-test-gate-cap" + string(rune('a'+i))
		args := slices.Concat([]string{"run", "-d", "--name", name}, testdocker.Labels(t), []string{"--network", networkName(s.Ref)}, c.flags)
		args = append(args, "--entrypoint", "sleep", img, "300")
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			t.Logf("%s: docker refused: %v %s", c.name, err, out)
			continue
		}
		capeff, _ := exec.Command("docker", "exec", name, "sh", "-c", "grep CapEff /proc/1/status").CombinedOutput()
		gerr := a.CheckAdopted(context.Background(), s)
		t.Logf("%s: recorded %s; %s; gate: %v", c.name, gnHostConfig(t, name), strings.TrimSpace(string(capeff)), gerr)
		if c.bad && !errors.Is(gerr, ErrContainment) {
			t.Errorf("%s: gate passes", c.name)
		}
		if !c.bad && gerr != nil {
			t.Errorf("%s: gate refuses a container that drops every capability and adds none: %v", c.name, gerr)
		}
		exec.Command("docker", "rm", "-f", name).Run()
	}
	_ = run
}

// Labels are tenant-independent but arbitrary text; the gate's
// line-per-record parse must not be confused by one.
func TestNode_GateHostileLabel(t *testing.T) {
	a, s, run := gnCase(t)
	img := a.cfg.Images.ControlPlane
	hostile := "x\"}\n{\"id\":\"y\",\"name\":\"/z\",\"privileged\":false,\"cap_drop\":[\"ALL\"]}\n"
	run("run", "-d", "--name", "sp-test-gate-label", "--label", "supapace.test=1", "--label", "evil="+hostile,
		"--network", networkName(s.Ref), "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--entrypoint", "sleep", img, "300")
	err := a.CheckAdopted(context.Background(), s)
	t.Logf("gate with a NET_RAW member carrying a hostile label: %v", err)
	if !errors.Is(err, ErrContainment) || !strings.Contains(err.Error(), "NET_RAW") {
		t.Errorf("hostile label changed the verdict: %v", err)
	}
	run("rm", "-f", "sp-test-gate-label")
	run("run", "-d", "--name", "sp-test-gate-label2", "--label", "supapace.test=1", "--label", "evil="+hostile,
		"--network", networkName(s.Ref), "--cap-drop", "ALL", "--entrypoint", "sleep", img, "300")
	if err := a.CheckAdopted(context.Background(), s); err != nil {
		t.Errorf("hardened member with a hostile label refused: %v", err)
	}
}

// A foreign proj-<ref> with every option the platform checks plus IPv6: is
// it adopted, and does the gate see the bridge's global IPv6 address?
func TestNode_IPv6ProjectNetworkRefused(t *testing.T) {
	a := nodeAgent(t)
	ctx := context.Background()
	s := Spec{Ref: "gatecase000000000002", Epoch: 1, Generation: 1, SubnetIndex: 10}
	t.Cleanup(func() {
		nodeDockerQuiet("network", "rm", networkName(s.Ref))
		for _, n := range []string{platformNet, ingressNet} {
			nodeDockerQuiet("network", "rm", n)
		}
	})
	if err := a.EnsurePlatformNetworks(ctx); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("docker", "network", "create", "--internal", "--ipv6", "--subnet", a.cfg.Slice(s.SubnetIndex).String(),
		"--subnet", "2001:db8:9::/64", "-o", "com.docker.network.bridge.name="+nodecfg.BridgeName(s.SubnetIndex),
		"-o", "com.docker.network.bridge.gateway_mode_ipv4=isolated", "--label", "supapace.test=1", networkName(s.Ref)).CombinedOutput()
	if err != nil {
		t.Fatalf("create: %v %s", err, out)
	}
	addrs, _ := exec.Command("ip", "-o", "addr", "show", "dev", nodecfg.BridgeName(s.SubnetIndex)).CombinedOutput()
	t.Logf("bridge addresses:\n%s", addrs)
	if err := a.EnsureNetwork(ctx, s); !errors.Is(err, ErrContainment) {
		t.Errorf("EnsureNetwork adopts a project network with IPv6 on: %v", err)
	}
	gerr := a.CheckAdopted(ctx, s)
	t.Logf("gate: %v", gerr)
	if strings.Contains(string(addrs), "scope global") && gerr == nil {
		t.Errorf("gate passes with a global IPv6 address on the project bridge")
	}
}

// A control-plane container left by an older build (no hardening, on the
// default bridge) is not adopted as it is. (The gateway's case is a unit
// test: its image is not in the node's cache.)
func TestNode_PlatformContainersWithOtherArgumentsRecreated(t *testing.T) {
	a := nodeAgent(t)
	ctx := context.Background()
	img := a.cfg.Images.ControlPlane
	t.Cleanup(func() {
		nodeDockerQuiet("rm", "-f", cpName)
		exec.Command("rm", "-rf", "/var/lib/supapace/cp", "/var/lib/supapace/projects/cp", "/var/lib/supapace/repo/cp", "/var/lib/supapace/platform").Run()
	})
	if out, err := exec.Command("docker", "run", "-d", "--name", cpName, "--label", "supapace.test=1", "--network", "bridge",
		"--entrypoint", "sleep", img, "300").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if err := a.EnsureImageFiles(ctx); err != nil { // the seccomp file a re-created container needs
		t.Fatal(err)
	}
	t.Logf("EnsureControlPlaneDB: %v", a.EnsureControlPlaneDB(ctx))
	out, _ := exec.Command("docker", "container", "inspect", "--format",
		`{{json .HostConfig.CapDrop}} {{.HostConfig.NetworkMode}} user={{json .Config.User}}`, "--", cpName).CombinedOutput()
	t.Logf("%s after EnsureControlPlaneDB: %s", cpName, out)
	if !strings.Contains(string(out), `["ALL"] none user="70:70"`) {
		t.Errorf("%s left running with other arguments: %s", cpName, out)
	}
}
