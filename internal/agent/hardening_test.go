package agent

// Refusals the start gate and the platform objects need beyond the cases in
// agent_test.go. Each test fails on the current code until the matching
// check is added.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
)

// A project bridge may carry only an IPv6 link-local address; a global (or
// unique-local) IPv6 address is a host address on the bridge like an IPv4 one.
func TestCheckContainment_FailsOnGlobalIPv6OnBridge(t *testing.T) {
	br := nodecfg.BridgeName(14)
	out := strings.Replace(bridgeIface(br, false), `]}]`,
		`,{"family":"inet6","local":"2001:db8:9::1","prefixlen":64,"scope":"global"}]}]`, 1)
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) { f.ip["-j -d addr show dev "+br] = out }, true)
}

// A gateway container left from an older build at the right addresses but
// created with weaker arguments is not adopted: it is removed and created
// with the current ones.
func TestEnsureGateway_RecreatesContainerWithOtherArguments(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	writeTLS(t, a)
	gw := f.ctrs["sp-gateway"]
	gw.Argv = []string{"create", "--name", "sp-gateway", "--user", "65532:65532", "--memory", "128m",
		"--network", "ingress", "--ip", a.cfg.GatewayIngressIP, "--", "supapace-gateway:local"}
	gw.CapDrop = nil
	f.resetLog()
	if err := a.EnsureGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := f.mutations()
	if len(m) == 0 || m[0] != "docker rm -f -- sp-gateway" || len(f.argv("create")) != 1 {
		t.Fatalf("an older gateway was adopted as it is: %q", m)
	}
}

// A container named sp-cp-db that the agent did not create with its
// arguments (here: on the default bridge, default capabilities) is not
// adopted.
func TestEnsureControlPlaneDB_RecreatesContainerWithOtherArguments(t *testing.T) {
	a, f, _ := newTestAgent(t)
	cpSeams(t, a, f)
	cpStamped(t, a)
	writeSeccomp(t, a)
	f.ctr(fakeCtr{Name: "sp-cp-db", Running: true, Labels: map[string]string{"supapace.role": "cp-db"},
		Nets: map[string]string{"bridge": "198.51.100.7"}, Argv: []string{"run", "-d", "--name", "sp-cp-db", "--", "postgres"}})
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.argv("run")) != 1 {
		t.Fatalf("a foreign control-plane container was adopted: %q", f.mutations())
	}
}

// "null" is not a State.
func TestState_RefusesNull(t *testing.T) {
	a, _, s := newTestAgent(t)
	mkdirs(t, a.p.PlatformDir(), filepath.Dir(a.p.RenderDir(s.Ref)), a.p.RenderDir(s.Ref))
	path := filepath.Join(a.p.RenderDir(s.Ref), "state.json")
	for _, body := range []string{"null", `{"epoch":1,"generation":1,"phase":"C"}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := a.readState(s.Ref); err == nil {
			t.Errorf("%s read as a state (ok %v)", body, ok)
		}
	}
}

// The fake must refuse what Docker refuses, or tests built on it pass for
// code that fails on a node.
func TestFakeDocker_RefusesLikeDocker(t *testing.T) {
	ctx := context.Background()
	f := fakeDocker(t)
	f.ctr(fakeCtr{Name: "x", Running: true, Nets: map[string]string{"n": "10.213.0.2"}})
	f.net(fakeNet{Network: dockerx.Network{Name: "n"}})
	for name, args := range map[string][]string{
		"rm of a running container without -f": {"rm", "--", "x"},
		"network rm with a running member":     {"network", "rm", "--", "n"},
		"connect to an absent network":         {"network", "connect", "--", "absent", "x"},
		"connect twice":                        {"network", "connect", "--", "n", "x"},
	} {
		if _, err := dockerRun(ctx, args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dockerRun(ctx, "stop", "--", "x")
	if _, err := dockerRun(ctx, "kill", "--", "x"); err == nil {
		t.Error("kill of a stopped container: accepted")
	}
	// Two configured holders of one address: the second start fails.
	f.ctr(fakeCtr{Name: "y", Nets: map[string]string{"n": "10.213.0.2"}})
	if _, err := dockerRun(ctx, "start", "--", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := dockerRun(ctx, "start", "--", "y"); err == nil || !strings.Contains(err.Error(), "Address already in use") {
		t.Errorf("second holder started: %v", err)
	}
	if c := f.ctrs["y"]; c.Running {
		t.Error("second holder running")
	}
}

// The re-read after a failed batch read fails closed: a member whose
// inspect errors (rather than reporting it absent) is a refusal, never
// skipped like a member that has gone.
func TestCheckContainment_RecheckErrorRefuses(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	flaky := f.ctr(fakeCtr{Name: "flaky", Running: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_RAW"},
		Nets: map[string]string{"platform": "10.212.6.20"}})
	batch := 0
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if args[0] == "container" && args[1] == "inspect" {
			batch++
			if batch == 1 {
				return "", errors.New("daemon busy"), true
			}
		}
		return "", nil, false
	}
	f.failInspect[flaky.ID] = errors.New("re-check refused") // members are read by id
	err := a.CheckContainment(context.Background(), s)
	wantContainment(t, err, "inspect error on re-check")
	if !strings.Contains(err.Error(), "read container configuration: re-check refused") {
		t.Fatalf("refused for another reason than the failed re-check: %v", err)
	}
}

// state.json with trailing data, or a link to a well-formed state file, is
// an error.
func TestState_RefusesTrailingDataAndLink(t *testing.T) {
	a, _, s := newTestAgent(t)
	mkdirs(t, a.p.PlatformDir(), filepath.Dir(a.p.RenderDir(s.Ref)), a.p.RenderDir(s.Ref))
	path := filepath.Join(a.p.RenderDir(s.Ref), "state.json")
	good := `{"epoch":1,"generation":1,"phase":"B","pm_pid":1,"pm_start":1,"listener_pid":0,"listener_start":0}`
	os.WriteFile(path, []byte(good+`{"epoch":2}`), 0o600)
	if _, _, err := a.readState(s.Ref); err == nil {
		t.Error("trailing data accepted")
	}
	other := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(other, []byte(good), 0o600)
	os.Remove(path)
	os.Symlink(other, path)
	if _, _, err := a.readState(s.Ref); err == nil {
		t.Error("a link to a well-formed state file was followed")
	}
}

// An image file larger than 1 MiB is refused.
func TestEnsureImageFiles_RefusesLargeEntry(t *testing.T) {
	a, f, _ := newTestAgent(t)
	imageCp(t, f, tarOf(t, [3]string{"./", "d", ""}, [3]string{"./big.conf", "f", strings.Repeat("x", 1<<20+1)}))
	if err := a.EnsureImageFiles(context.Background()); err == nil {
		t.Fatal("accepted")
	}
}

// daemon.json without an ipv6 key leaves Docker's default in force; the row
// requires the key, set to false.
func TestNodeCheck_DaemonJSONRequiresIPv6Key(t *testing.T) {
	a, _ := goodNode(t)
	p := filepath.Join(a.p.Root, "etc/docker/daemon.json")
	os.WriteFile(p, []byte(`{"default-address-pools":[{"base":"10.214.0.0/16","size":26}],"log-driver":"local","log-opts":{"max-file":"3","max-size":"10m"}}`), 0o644)
	if r := rows(t, a)["daemon.json"]; r.OK {
		t.Fatalf("row passes without an ipv6 key: %+v", r)
	}
}

// ipCommand bounds what it reads: a command that prints without end is
// killed and refused well before its time-out; a normal answer is returned.
func TestIPCommand_OutputBounded(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	write := func(script string) {
		if err := os.WriteFile(filepath.Join(bin, "ip"), []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write(`echo '[]'`)
	if out, err := ipCommand(context.Background(), "-j", "link", "show"); err != nil || strings.TrimSpace(string(out)) != "[]" {
		t.Fatalf("normal answer: %q %v", out, err)
	}
	write(`exec yes`)
	start := time.Now()
	out, err := ipCommand(context.Background(), "-j", "link", "show")
	if err == nil || !strings.Contains(err.Error(), "larger than") || out != nil {
		t.Fatalf("endless output: %d bytes, %v", len(out), err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v: not killed at the bound", d)
	}
}

// Condition 6 also judges every container that shares the network namespace
// of a member, by id or by name, in turn, or the host's; a tenant container
// itself may share neither.
func TestCheckContainment_NetworkNamespaceSharers(t *testing.T) {
	member := func(a *Agent, f *fakeHost, s Spec) *fakeCtr {
		return f.ctr(fakeCtr{Name: "member", Running: true, CapDrop: []string{"ALL"},
			Nets: map[string]string{"platform": "10.212.6.20"}})
	}
	for name, fault := range map[string]func(a *Agent, f *fakeHost, s Spec){
		"sharer by id": func(a *Agent, f *fakeHost, s Spec) {
			f.ctr(fakeCtr{Name: "sharer", Running: true, NetMode: "container:" + member(a, f, s).ID})
		},
		"sharer by name": func(a *Agent, f *fakeHost, s Spec) {
			member(a, f, s)
			f.ctr(fakeCtr{Name: "sharer", Running: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_RAW"}, NetMode: "container:member"})
		},
		"sharer of a tenant": func(a *Agent, f *fakeHost, s Spec) {
			f.ctr(fakeCtr{Name: "sharer", NetMode: "container:" + f.ctrs["pg-"+s.Ref].ID})
		},
		"sharer of a sharer": func(a *Agent, f *fakeHost, s Spec) {
			m := member(a, f, s)
			mid := f.ctr(fakeCtr{Name: "middle", Running: true, CapDrop: []string{"ALL"}, NetMode: "container:" + m.ID})
			f.ctr(fakeCtr{Name: "last", Running: true, Privileged: true, CapDrop: []string{"ALL"}, NetMode: "container:" + mid.ID})
		},
		"host network": func(a *Agent, f *fakeHost, s Spec) {
			f.ctr(fakeCtr{Name: "hostnet", NetMode: "host", CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"}})
		},
		"tenant on the host network": func(a *Agent, f *fakeHost, s Spec) {
			pg := f.ctrs["pg-"+s.Ref]
			pg.NetMode, pg.Nets = "host", map[string]string{}
		},
		"tenant sharing a namespace": func(a *Agent, f *fakeHost, s Spec) {
			f.ctrs["postgrest-"+s.Ref].NetMode = "container:sp-gateway"
		},
	} {
		t.Run(name, func(t *testing.T) { gateRefuses(t, fault, true) })
	}
	// Controls: hardened sharers and a sharer of a container that is no member pass.
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	m := member(a, f, s)
	f.ctr(fakeCtr{Name: "hardened", Running: true, CapDrop: []string{"ALL"}, NetMode: "container:" + m.ID})
	f.ctr(fakeCtr{Name: "hosthardened", CapDrop: []string{"ALL"}, NetMode: "host"})
	other := f.ctr(fakeCtr{Name: "other", Running: true, NetMode: "none"})
	f.ctr(fakeCtr{Name: "sharer-of-other", Running: true, NetMode: "container:" + other.ID})
	if err := a.CheckAdopted(context.Background(), s); err != nil {
		t.Fatalf("hardened sharers: %v", err)
	}
	// The same hardened container on the project network is refused by the
	// member rule, whatever its capabilities.
	f.ctr(fakeCtr{Name: "stranger", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{"proj-" + s.Ref: "10.213.3.140"}})
	err := a.CheckAdopted(context.Background(), s)
	wantContainment(t, err, "a hardened stranger on the project network")
	if !strings.Contains(err.Error(), memberRule) || !strings.Contains(err.Error(), "stranger") {
		t.Fatalf("got %v, want the member rule naming the stranger", err)
	}
}

// Every way the namespace listing can fail is a refusal; one failed read is
// retried with a fresh listing (a container may go in between).
func TestCheckContainment_NamespaceListingFailsClosed(t *testing.T) {
	boom := errors.New("daemon busy")
	modeRead := func(args []string) bool {
		return args[0] == "container" && args[1] == "inspect" && flagValue(args, "--format") == modeFormat
	}
	for name, script := range map[string]func(args []string, _ []byte) (string, error, bool){
		"listing fails":    func(args []string, _ []byte) (string, error, bool) { return "", boom, args[0] == "ps" },
		"read fails twice": func(args []string, _ []byte) (string, error, bool) { return "", boom, modeRead(args) },
		"short read": func(args []string, _ []byte) (string, error, bool) {
			return `"x" "/x" "host"` + "\n", nil, modeRead(args)
		},
		"garbage": func(args []string, _ []byte) (string, error, bool) { return "{\n", nil, modeRead(args) },
	} {
		t.Run(name, func(t *testing.T) {
			a, f, s := newTestAgent(t)
			healthy(a, f, s)
			tenants(a, f, s)
			f.onRun = script
			wantContainment(t, a.CheckAdopted(context.Background(), s), name)
		})
	}
	// One failed read, then a good one: passes.
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	reads := 0
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if modeRead(args) {
			reads++
			return "", boom, reads == 1
		}
		return "", nil, false
	}
	if err := a.CheckAdopted(context.Background(), s); err != nil || reads != 2 {
		t.Fatalf("one failed read: %v after %d reads", err, reads)
	}
}

// A network that Docker records with IPv6 enabled is refused by the gate,
// by EnsureNetwork and by EnsurePlatformNetworks, and so is an unreadable flag.
func TestIPv6EnabledNetworkRefused(t *testing.T) {
	for _, n := range []string{"proj-" + testRef, "platform"} {
		gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) { f.nets[n].IPv6 = true }, true)
	}
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		f.onRun = func(args []string, _ []byte) (string, error, bool) {
			return "maybe\n", nil, flagValue(args, "--format") == "{{json .EnableIPv6}}"
		}
	}, true)
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	f.nets["proj-"+s.Ref].IPv6 = true
	f.resetLog()
	wantContainment(t, a.EnsureNetwork(context.Background(), s), "EnsureNetwork")
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("touched: %q", m)
	}
	for _, n := range []string{"platform", "ingress"} {
		a, f, s := newTestAgent(t)
		healthy(a, f, s)
		f.nets[n].IPv6 = true
		f.resetLog()
		wantContainment(t, a.EnsurePlatformNetworks(context.Background()), "EnsurePlatformNetworks "+n)
		if m := f.mutations(); len(m) != 0 {
			t.Fatalf("touched: %q", m)
		}
	}
	// A network the agent creates has IPv6 off, and is adopted again.
	a, f, s = newTestAgent(t)
	for _, call := range []func() error{
		func() error { return a.EnsurePlatformNetworks(context.Background()) },
		func() error { return a.EnsureNetwork(context.Background(), s) },
	} {
		if err := call(); err != nil {
			t.Fatal(err)
		}
		if err := call(); err != nil {
			t.Fatalf("second call: %v", err)
		}
	}
}

// The platform bridge's interface is checked like a project bridge's.
func TestCheckContainment_FailsOnPlatformInterface(t *testing.T) {
	for name, out := range map[string]string{
		"ipv4":        bridgeIface("spl0", true),
		"global ipv6": strings.Replace(bridgeIface("spl0", false), `"scope":"link"`, `"scope":"global"`, 1),
		"not bridge":  strings.Replace(bridgeIface("spl0", false), `"info_kind":"bridge"`, `"info_kind":"dummy"`, 1),
		"absent":      "",
	} {
		t.Run(name, func(t *testing.T) {
			gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
				if out == "" {
					delete(f.ip, "-j -d addr show dev spl0")
				} else {
					f.ip["-j -d addr show dev spl0"] = out
				}
			}, true)
		})
	}
}

// The configuration label of a platform container: equal for equal
// arguments whatever the random initdb password, never holding it; a
// container whose label differs or is missing is removed and created again.
func TestPlatformContainers_ConfigLabel(t *testing.T) {
	label := func(argv []string) string {
		for _, l := range flagValues(argv, "--label") {
			if v, ok := strings.CutPrefix(l, "supapace.config="); ok {
				return v
			}
		}
		return ""
	}
	a, f, _ := newTestAgent(t)
	cpSeams(t, a, f)
	writeTLS(t, a)
	healthy(a, f, Spec{Ref: testRef, SubnetIndex: 14})
	delete(f.ctrs, "sp-gateway")
	ctx := context.Background()
	for _, ensure := range []func(context.Context) error{a.EnsureControlPlaneDB, a.EnsureGateway} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var pws []string
	password := func(argv []string) {
		for _, e := range flagValues(argv, "-e") {
			if v, ok := strings.CutPrefix(e, "POSTGRES_PASSWORD="); ok {
				if strings.Contains(label(argv), v) {
					t.Fatal("the password is in the label")
				}
				pws = append(pws, v)
			}
		}
	}
	// A fresh node: the first start carries the password, the start after
	// the stamp none.
	for _, r := range f.argv("run") {
		if flagValue(r, "--name") == cpName {
			password(r)
		}
	}
	for _, name := range []string{"sp-cp-db", "sp-gateway"} {
		c := f.ctrs[name]
		conf := label(c.Argv)
		if len(conf) != 64 || strings.Trim(conf, "0123456789abcdef") != "" || c.Labels["supapace.config"] != conf {
			t.Fatalf("%s: label %q", name, conf)
		}
		// Equal arguments: nothing to do.
		f.resetLog()
		ensure := a.EnsureControlPlaneDB
		if name == "sp-gateway" {
			ensure = a.EnsureGateway
		}
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
		if m := f.mutations(); len(m) != 0 {
			t.Fatalf("%s with equal arguments touched: %q", name, m)
		}
		// A differing label, then none: removed and created again with the same label.
		for _, l := range []string{"0000", ""} {
			if l == "" {
				delete(c.Labels, "supapace.config")
			} else {
				c.Labels["supapace.config"] = l
			}
			f.resetLog()
			if err := ensure(ctx); err != nil {
				t.Fatal(err)
			}
			m := f.mutations()
			if len(m) == 0 || m[0] != firstRemoval(name) {
				t.Fatalf("%s label %q: %q", name, l, m)
			}
			c = f.ctrs[name]
			password(c.Argv)
			if label(c.Argv) != conf {
				t.Fatalf("%s re-created with label %q, want %q", name, label(c.Argv), conf)
			}
		}
	}
	// The password: random, out of the hash, and only in the start before
	// the node is stamped — none of the re-creations carries one.
	if len(pws) != 1 || len(pws[0]) != 64 || strings.Trim(pws[0], "0123456789abcdef") != "" {
		t.Fatalf("passwords %q: want one random value, in the first start only", pws)
	}
	if h := configHash([]string{"a", "b"}, []string{"c"}); h == configHash([]string{"a"}, []string{"b", "c"}) || h == configHash([]string{"ab"}, []string{"c"}) {
		t.Fatal("the hash does not separate arguments")
	}
}

// state.json larger than the read limit (here: a valid object padded with
// spaces) is refused, and an unknown phase is never written.
func TestState_RefusesOversizeAndUnknownPhase(t *testing.T) {
	a, _, s := newTestAgent(t)
	mkdirs(t, a.p.PlatformDir(), filepath.Dir(a.p.RenderDir(s.Ref)), a.p.RenderDir(s.Ref))
	path := filepath.Join(a.p.RenderDir(s.Ref), "state.json")
	good := `{"epoch":1,"generation":1,"phase":"B","pm_pid":1,"pm_start":1,"listener_pid":0,"listener_start":0}`
	os.WriteFile(path, []byte(good+strings.Repeat(" ", 4096)), 0o600)
	if _, _, err := a.readState(s.Ref); err == nil {
		t.Error("oversize file accepted")
	}
	os.WriteFile(path, []byte(good+strings.Repeat(" ", 4096-len(good))), 0o600)
	if _, ok, err := a.readState(s.Ref); err != nil || !ok {
		t.Errorf("a file of exactly the limit: %v", err)
	}
	for _, ph := range []string{"", "C"} {
		if err := a.writeState(s.Ref, State{Epoch: 1, Generation: 1, Phase: ph}); err == nil {
			t.Errorf("phase %q written", ph)
		}
	}
}

// A duplicate entry in an image archive is refused.
func TestEnsureImageFiles_RefusesDuplicateEntry(t *testing.T) {
	a, f, _ := newTestAgent(t)
	imageCp(t, f, tarOf(t, [3]string{"./", "d", ""}, [3]string{"./a.conf", "f", "x"}, [3]string{"./a.conf", "f", "y"}))
	if err := a.EnsureImageFiles(context.Background()); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("duplicate entry: %v", err)
	}
}

// The firewall-backend row stays informational when docker info fails.
func TestNodeCheck_FirewallRowWhenInfoFails(t *testing.T) {
	a, f := goodNode(t)
	f.failVerb["info"] = errors.New("no daemon")
	if r := rows(t, a)["docker-firewall-backend"]; !r.OK || !strings.Contains(r.Detail, "no daemon") {
		t.Fatalf("row %+v", r)
	}
}

// Reading the configuration of a namespace sharer, or the IPv6 flag of a
// network, fails closed.
func TestCheckContainment_SharerAndFlagReadErrorsRefuse(t *testing.T) {
	boom := errors.New("daemon busy")
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		sh := f.ctr(fakeCtr{Name: "sharer", Running: true, CapDrop: []string{"ALL"}, NetMode: "host"})
		f.failInspect[sh.ID], f.failInspect["sharer"] = boom, boom
		f.onRun = func(args []string, _ []byte) (string, error, bool) {
			return "", boom, flagValue(args, "--format") == confFormat && slices.Contains(args, sh.ID)
		}
	}, true)
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		f.onRun = func(args []string, _ []byte) (string, error, bool) {
			return "", boom, flagValue(args, "--format") == "{{json .EnableIPv6}}"
		}
	}, true)
}

// The gateway loads its certificate once, at start: a gateway started with
// another certificate (same arguments) is re-created; with the same
// certificate it is adopted untouched. The key never enters the label.
func TestEnsureGateway_CertificateChangeRecreates(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	delete(f.ctrs, "sp-gateway")
	writeTLS(t, a)
	ctx := context.Background()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	first := f.ctrs["sp-gateway"].Labels["supapace.config"]
	// Another key alone changes nothing.
	os.WriteFile(filepath.Join(a.p.TLSDir(), "key.pem"), []byte("OTHER KEY"), 0o600)
	f.resetLog()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("same certificate: %q", m)
	}
	os.WriteFile(filepath.Join(a.p.TLSDir(), "cert.pem"), []byte("RENEWED CERT"), 0o600)
	f.resetLog()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	m := f.mutations()
	if len(m) == 0 || m[0] != "docker rm -f -- sp-gateway" || len(f.argv("create")) != 1 {
		t.Fatalf("a new certificate did not re-create the gateway: %q", m)
	}
	if got := f.ctrs["sp-gateway"].Labels["supapace.config"]; got == first || got == "" {
		t.Fatalf("label %q after the certificate changed (was %q)", got, first)
	}
}

// A member named exactly like another container's id: Docker resolves the
// id first, so a read "by name" judges the other container. Members are to
// be read by their endpoint ids.
func TestCheckContainment_MemberNamedLikeAnID(t *testing.T) {
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		other := f.ctr(fakeCtr{Name: "hardened", CapDrop: []string{"ALL"}, NetMode: "none"})
		f.ctr(fakeCtr{Name: other.ID, Running: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_RAW"},
			Nets: map[string]string{"platform": "10.212.6.20"}})
	}, true)
}

// The seccomp profile a platform container was created with is part of its
// configuration: a different profile on disk (a re-pin) re-creates it.
func TestPlatformContainers_SeccompProfileInLabel(t *testing.T) {
	a, f, s := newTestAgent(t)
	cpSeams(t, a, f)
	healthy(a, f, s)
	delete(f.ctrs, "sp-gateway")
	writeTLS(t, a)
	mkdirs(t, filepath.Dir(a.p.PlatformDir()), a.p.PlatformDir())
	ctx := context.Background()
	sec := filepath.Join(a.p.PlatformDir(), "seccomp.json")
	if err := nodefs.WriteFile(a.p, a.p.PlatformDir(), "seccomp.json", []byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`), 0o444, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	for name, ensure := range map[string]func(context.Context) error{"sp-cp-db": a.EnsureControlPlaneDB, "sp-gateway": a.EnsureGateway} {
		os.Remove(sec)
		if err := nodefs.WriteFile(a.p, a.p.PlatformDir(), "seccomp.json", []byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`), 0o444, os.Geteuid(), os.Getegid()); err != nil {
			t.Fatal(err)
		}
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
		os.Remove(sec)
		if err := nodefs.WriteFile(a.p, a.p.PlatformDir(), "seccomp.json", []byte(`{"defaultAction":"SCMP_ACT_KILL"}`), 0o444, os.Geteuid(), os.Getegid()); err != nil {
			t.Fatal(err)
		}
		f.resetLog()
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
		if m := f.mutations(); len(m) == 0 || m[0] != firstRemoval(name) {
			t.Errorf("%s kept after the profile changed: %q", name, m)
		}
	}
}

// Every field the gate judges is in the template it reads: the fake answers
// with every field whatever the template says, so the template is pinned
// here.
func TestConfFormat_ReadsEveryJudgedField(t *testing.T) {
	for _, f := range []string{".Id", ".Name", ".State.Running", ".HostConfig.Privileged", ".HostConfig.CapAdd", ".HostConfig.CapDrop",
		".HostConfig.RestartPolicy.Name", ".HostConfig.NetworkMode", ".Config.Labels", ".NetworkSettings.Networks"} {
		if !strings.Contains(confFormat, "{{json "+f+"}}") {
			t.Errorf("confFormat lacks %s", f)
		}
	}
	// Docker leaves Sysctls out of the record of a container that has none; a
	// field reference would then fail the read of every container.
	if !strings.Contains(confFormat, `{{json (index .HostConfig "Sysctls")}}`) || strings.Contains(confFormat, ".HostConfig.Sysctls") {
		t.Error("confFormat does not read the sysctls by index")
	}
	for _, f := range []string{".Id", ".Name", ".HostConfig.NetworkMode"} {
		if !strings.Contains(modeFormat, "{{json "+f+"}}") {
			t.Errorf("modeFormat lacks %s", f)
		}
	}
}

// A different argument gives a different label: here the image.
func TestEnsureControlPlaneDB_OtherArgumentOtherLabel(t *testing.T) {
	a, f, _ := newTestAgent(t)
	cpSeams(t, a, f)
	writeSeccomp(t, a)
	ctx := context.Background()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	before := f.ctrs["sp-cp-db"].Labels["supapace.config"]
	a.cfg.Images.ControlPlane = "postgres@sha256:" + strings.Repeat("0", 64)
	f.resetLog()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) == 0 || m[0] != firstRemoval("sp-cp-db") || f.ctrs["sp-cp-db"].Labels["supapace.config"] == before {
		t.Fatalf("another image kept the container or its label: %q", m)
	}
}

// When the old control-plane container cannot be removed, nothing is run.
func TestEnsureControlPlaneDB_RemoveFailureRunsNothing(t *testing.T) {
	a, f, _ := newTestAgent(t)
	cpSeams(t, a, f)
	writeSeccomp(t, a)
	f.ctr(fakeCtr{Name: "sp-cp-db", Running: true, Labels: map[string]string{"supapace.role": "cp-db"}})
	f.failVerb["rm"] = errors.New("daemon busy")
	if err := a.EnsureControlPlaneDB(context.Background()); err == nil {
		t.Fatal("no error")
	}
	if len(f.argv("run")) != 0 {
		t.Fatal("ran a container although the old one is still there")
	}
}

// The label covers every argument the container is created with, the
// password value and the label itself left out.
func TestPlatformContainers_LabelCoversEveryArgument(t *testing.T) {
	a, f, s := newTestAgent(t)
	cpSeams(t, a, f)
	healthy(a, f, s)
	delete(f.ctrs, "sp-gateway")
	writeTLS(t, a)
	ctx := context.Background()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	argv := f.argv("run")[0]
	var opts []string
	for i := 0; i < len(argv); i++ {
		if argv[i] == "--" {
			break
		}
		if i+1 < len(argv) && (strings.HasPrefix(argv[i+1], "POSTGRES_PASSWORD=") || strings.HasPrefix(argv[i+1], "supapace.config=")) {
			i++
			continue
		}
		opts = append(opts, argv[i])
	}
	if got, want := f.ctrs["sp-cp-db"].Labels["supapace.config"], configHash(opts, positional(argv), cpExtra(t, a)...); got != want {
		t.Fatalf("label %s, want the hash of the argv %q", got, opts)
	}
}

// firstRemoval is the first call that removes a platform container being
// re-created: the running control-plane database is stopped gracefully
// first, the gateway removed at once.
func firstRemoval(name string) string {
	if name == cpName {
		return "docker stop -t 30 -- " + cpName
	}
	return "docker rm -f -- " + name
}

// cpExtra is what the control-plane label covers besides the arguments.
func cpExtra(t *testing.T, a *Agent) []string {
	etc := filepath.Join(a.p.CPDir(), "etc")
	extra, err := fileDigests(a.seccompFile(), filepath.Join(etc, "pg_hba.conf"), filepath.Join(etc, "pg_ident.conf"),
		filepath.Join(a.p.ToolsDir(), archBinary))
	if err != nil {
		t.Fatal(err)
	}
	_, serr := os.Lstat(a.cpStampPath())
	return append(extra, "stamped="+strconv.FormatBool(serr == nil))
}

// Members are read by their endpoint ids; every way that read can fail is a
// refusal, and the platform-members row reads the same way.
func TestMemberIDs_FailClosed(t *testing.T) {
	boom := errors.New("daemon busy")
	members := func(args []string) bool { return flagValue(args, "--format") == "{{json .Containers}}" }
	for name, script := range map[string]func(args []string, _ []byte) (string, error, bool){
		"read fails": func(args []string, _ []byte) (string, error, bool) { return "", boom, members(args) },
		"garbage":    func(args []string, _ []byte) (string, error, bool) { return "{\n", nil, members(args) },
		"trailing":   func(args []string, _ []byte) (string, error, bool) { return "{} {}\n", nil, members(args) },
		"not an id": func(args []string, _ []byte) (string, error, bool) {
			return `{"lb-endpoint":{"Name":"x"}}` + "\n", nil, members(args)
		},
		"short id": func(args []string, _ []byte) (string, error, bool) {
			return `{"0123456789ab":{"Name":"x"}}` + "\n", nil, members(args)
		},
	} {
		t.Run(name, func(t *testing.T) {
			gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) { f.onRun = script }, true)
			a, f := goodNode(t)
			f.onRun = script
			if r := rows(t, a)["platform-members"]; r.OK {
				t.Fatalf("platform-members passes: %+v", r)
			}
		})
	}
	// The row judges the member itself, not a container whose id is its name.
	a, f := goodNode(t)
	other := f.ctrs["sp-gateway"] // a member that passes the row
	f.ctr(fakeCtr{Name: other.ID, Running: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_RAW"},
		Nets: map[string]string{"platform": "10.212.0.250"}})
	if r := rows(t, a)["platform-members"]; r.OK {
		t.Fatalf("platform-members passes a member named like another container's id: %+v", r)
	}
}

// The gateway's label covers the image id its tag names now: a rebuilt image
// under the same tag re-creates it; an unchanged one is adopted; an
// unreadable image id is an error, not an adoption.
func TestEnsureGateway_ImageIDInLabel(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	delete(f.ctrs, "sp-gateway")
	writeTLS(t, a)
	ctx := context.Background()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	f.resetLog()
	if err := a.EnsureGateway(ctx); err != nil || len(f.mutations()) != 0 {
		t.Fatalf("same image: %v %q", err, f.mutations())
	}
	f.images[a.cfg.Images.Gateway] = "sha256:" + strings.Repeat("2", 64)
	f.resetLog()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) == 0 || m[0] != "docker rm -f -- sp-gateway" || len(f.argv("create")) != 1 {
		t.Fatalf("a rebuilt image did not re-create the gateway: %q", m)
	}
	for name, id := range map[string]string{"absent": "", "not an id": "latest"} {
		if id == "" {
			delete(f.images, a.cfg.Images.Gateway)
		} else {
			f.images[a.cfg.Images.Gateway] = id
		}
		f.resetLog()
		if err := a.EnsureGateway(ctx); err == nil || len(f.mutations()) != 0 {
			t.Fatalf("image id %s: %v %q", name, err, f.mutations())
		}
	}
}

// Re-creating the control-plane database: a running one is stopped with
// the server's grace period, then removed; one that cannot be stopped is
// left as it is and nothing is run; a stopped one is removed at once.
func TestEnsureControlPlaneDB_RecreationStopsGracefully(t *testing.T) {
	setup := func(t *testing.T, running bool) (*Agent, *fakeHost) {
		a, f, _ := newTestAgent(t)
		cpSeams(t, a, f)
		cpStamped(t, a)
		writeSeccomp(t, a)
		f.ctr(fakeCtr{Name: "sp-cp-db", Running: running, Labels: map[string]string{"supapace.role": "cp-db"}})
		f.resetLog()
		return a, f
	}
	ctx := context.Background()
	a, f := setup(t, true)
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 3 || m[0] != "docker stop -t 30 -- sp-cp-db" || m[1] != "docker rm -- sp-cp-db" || !strings.HasPrefix(m[2], "docker run ") {
		t.Fatalf("running: %q", m)
	}
	a, f = setup(t, false)
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 2 || m[0] != "docker rm -f -- sp-cp-db" || !strings.HasPrefix(m[1], "docker run ") {
		t.Fatalf("stopped: %q", m)
	}
	// The stop fails and the server still runs: the error, nothing removed.
	a, f = setup(t, true)
	boom := errors.New("daemon busy")
	f.failVerb["stop"] = boom
	if err := a.EnsureControlPlaneDB(ctx); !errors.Is(err, boom) {
		t.Fatalf("stop failure: %v", err)
	}
	if m := f.mutations(); len(m) != 1 || !f.ctrs["sp-cp-db"].Running {
		t.Fatalf("stop failure: %q", m)
	}
	// The stop fails because the container went meanwhile: created anew.
	a, f = setup(t, true)
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if args[0] != "stop" {
			return "", nil, false
		}
		f.mu.Lock()
		delete(f.ctrs, "sp-cp-db")
		f.mu.Unlock()
		return "", errors.New("docker: no such container"), true
	}
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 2 || !strings.HasPrefix(m[1], "docker run ") {
		t.Fatalf("gone during the stop: %q", m)
	}
	// The stop fails, the container is there but no longer running: removed.
	a, f = setup(t, true)
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if args[0] != "stop" {
			return "", nil, false
		}
		f.mu.Lock()
		f.ctrs["sp-cp-db"].Running = false
		f.mu.Unlock()
		return "", errors.New("docker: container is not running"), true
	}
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 3 || m[1] != "docker rm -- sp-cp-db" {
		t.Fatalf("stopped during the stop: %q", m)
	}
}

// Without the profile on disk neither platform container is created or
// adopted: what its label would describe cannot be read.
func TestPlatformContainers_MissingProfileIsAnError(t *testing.T) {
	a, f, s := newTestAgent(t)
	cpSeams(t, a, f)
	healthy(a, f, s)
	delete(f.ctrs, "sp-gateway")
	writeTLS(t, a)
	os.Remove(a.seccompFile())
	f.resetLog()
	for _, ensure := range []func(context.Context) error{a.EnsureControlPlaneDB, a.EnsureGateway} {
		if err := ensure(context.Background()); err == nil {
			t.Error("no error without the profile")
		}
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("mutated: %q", m)
	}
}

// The stop fails and the container cannot be read back: the error, nothing
// removed or run.
func TestEnsureControlPlaneDB_StopFailureUnreadable(t *testing.T) {
	a, f, _ := newTestAgent(t)
	cpSeams(t, a, f)
	writeSeccomp(t, a)
	f.ctr(fakeCtr{Name: "sp-cp-db", Running: true, Labels: map[string]string{"supapace.role": "cp-db"}})
	boom := errors.New("daemon busy")
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if args[0] != "stop" {
			return "", nil, false
		}
		f.mu.Lock()
		f.failInspect["sp-cp-db"] = boom
		f.mu.Unlock()
		return "", boom, true
	}
	f.resetLog()
	if err := a.EnsureControlPlaneDB(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if m := f.mutations(); len(m) != 1 {
		t.Fatalf("calls after the failed stop: %q", m)
	}
}

// An image id that is not exactly sha256 and 64 hex digits is refused.
func TestEnsureGateway_ImageIDStrict(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	delete(f.ctrs, "sp-gateway")
	writeTLS(t, a)
	for _, id := range []string{"sha256:abc", "sha256:" + strings.Repeat("0", 64) + "0", " sha256:" + strings.Repeat("0", 64), "SHA256:" + strings.Repeat("0", 64)} {
		f.images[a.cfg.Images.Gateway] = id
		f.resetLog()
		if err := a.EnsureGateway(context.Background()); err == nil || len(f.mutations()) != 0 {
			t.Errorf("image id %q: %v %q", id, err, f.mutations())
		}
	}
}

// listedAsEndpoint makes Docker list the container name on platform under
// "ep-<endpoint id>" for the first reads member reads of platform, as while
// it starts or stops, and under its id from then on. It returns the count of
// platform member reads so far.
func listedAsEndpoint(f *fakeHost, name string, reads int) (platformReads func() int) {
	return listedAsEndpointOn(f, platformNet, name, reads)
}

// listedAsEndpointOn is listedAsEndpoint for the member reads of network net.
func listedAsEndpointOn(f *fakeHost, net, name string, reads int) (netReads func() int) {
	f.mu.Lock()
	c := f.ctrs[name]
	id := c.ID
	c.ID = "ep-" + strings.Repeat("7e", 32)
	f.mu.Unlock()
	n := 0
	f.before = func(args []string) {
		if flagValue(args, "--format") == "{{json .Containers}}" && args[len(args)-1] == net {
			f.mu.Lock()
			if n++; n > reads {
				c.ID = id
			}
			f.mu.Unlock()
		}
	}
	return func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return n
	}
}

// fastReread makes the re-reads of a member listing immediate for one test.
func fastReread(t *testing.T) {
	old := memberReread
	memberReread = time.Millisecond
	t.Cleanup(func() { memberReread = old })
}

// A healthy adoption costs exactly the Docker calls it cost before
// endpoint keys were re-read: one member read per network.
func TestCheckAdopted_HealthyCost(t *testing.T) {
	a, f, s := prAgent(t, 14)
	prRunning(t, a, f, s)
	if err := a.EnsurePostgREST(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	log := f.calls()
	if n := len(log); n != 19 {
		t.Fatalf("healthy adoption made %d calls, want 19:\n%s", n, strings.Join(log, "\n"))
	}
	if n := strings.Count(strings.Join(log, "\n"), "{{json .Containers}}"); n != 3 {
		t.Fatalf("healthy adoption read members %d times, want 3", n)
	}
}

// A container that starts on platform while a running PostgREST is adopted
// is listed under its endpoint key for a moment: the listing is read again,
// the member is judged by its id, nothing is stopped.
func TestMemberIDs_TransientEndpointResolves(t *testing.T) {
	fastReread(t)
	for _, reads := range []int{1, memberRereads} {
		a, f, s := prAgent(t, 14)
		prRunning(t, a, f, s)
		f.ctr(fakeCtr{Name: "postgrest-otherref0123456789ab", Running: true, CapDrop: []string{"ALL"},
			Nets: map[string]string{platformNet: "10.212.0.250"}})
		platformReads := listedAsEndpoint(f, "postgrest-otherref0123456789ab", reads)
		f.resetLog()
		if err := a.EnsurePostgREST(context.Background(), s); err != nil {
			t.Fatalf("reads=%d: %v", reads, err)
		}
		if m := f.mutations(); len(m) != 0 {
			t.Fatalf("reads=%d: mutations %q", reads, m)
		}
		if n := platformReads(); n != reads+1 {
			t.Fatalf("reads=%d: platform members read %d times, want %d", reads, n, reads+1)
		}
	}
	// Once resolved, the member is judged by its id like any other.
	a, f, s := prAgent(t, 14)
	prRunning(t, a, f, s)
	f.ctr(fakeCtr{Name: "starting", Running: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_RAW"},
		Nets: map[string]string{platformNet: "10.212.0.250"}})
	listedAsEndpoint(f, "starting", 1)
	err := a.EnsurePostgREST(context.Background(), s)
	wantContainment(t, err, "a resolved member that adds a capability")
	if errors.Is(err, ErrCheckIncomplete) || !strings.Contains(err.Error(), "adds capabilities NET_RAW") {
		t.Fatalf("got %v, want the member's own violation", err)
	}
	// The node check's platform-members row reads the same way.
	a, f = goodNode(t)
	listedAsEndpoint(f, "sp-gateway", 1)
	if r := rows(t, a)["platform-members"]; !r.OK {
		t.Fatalf("platform-members fails on a transient endpoint: %+v", r)
	}
}

// An endpoint key that outlives every re-read is an unidentified member: a
// completed check that refuses (the adopted container is stopped). Any other
// key that is not a container id, and a foreign member, are refused at once.
func TestMemberIDs_PersistentEndpointRefused(t *testing.T) {
	fastReread(t)
	a, f, s := prAgent(t, 14)
	prRunning(t, a, f, s)
	f.ctr(fakeCtr{Name: "stuck", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{platformNet: "10.212.0.250"}})
	platformReads := listedAsEndpoint(f, "stuck", 1<<30)
	f.resetLog()
	err := a.EnsurePostgREST(context.Background(), s)
	wantContainment(t, err, "persistent endpoint")
	if errors.Is(err, ErrCheckIncomplete) {
		t.Fatalf("a persistent endpoint reads as an incomplete check: %v", err)
	}
	for _, w := range []string{`member key "ep-7e7e`, "endpoint without a container", `"stuck"`} {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("message %q lacks %q", err, w)
		}
	}
	if n := platformReads(); n != 1+memberRereads {
		t.Fatalf("platform members read %d times, want %d", n, 1+memberRereads)
	}
	prOrder(t, f.calls(), "docker stop -t 10 -- postgrest-"+s.Ref, "docker rm -- postgrest-"+s.Ref)

	a, f = goodNode(t)
	listedAsEndpoint(f, "sp-gateway", 1<<30)
	if r := rows(t, a)["platform-members"]; r.OK || !strings.Contains(r.Detail, "endpoint without a container") {
		t.Fatalf("platform-members on a persistent endpoint: %+v", r)
	}

	// No re-read for anything else.
	for name, arrange := range map[string]func(a *Agent, f *fakeHost){
		"foreign member": func(a *Agent, f *fakeHost) {
			f.ctr(fakeCtr{Name: "intruder", Running: true, Nets: map[string]string{platformNet: "10.212.0.250"}})
		},
		"other key": func(a *Agent, f *fakeHost) {
			f.onRun = func(args []string, _ []byte) (string, error, bool) {
				return `{"lb-platform":{"Name":"x"}}` + "\n", nil,
					flagValue(args, "--format") == "{{json .Containers}}" && args[len(args)-1] == platformNet
			}
		},
		"endpoint key not hex": func(a *Agent, f *fakeHost) {
			f.onRun = func(args []string, _ []byte) (string, error, bool) {
				return `{"ep-xyz":{"Name":"x"}}` + "\n", nil,
					flagValue(args, "--format") == "{{json .Containers}}" && args[len(args)-1] == platformNet
			}
		},
	} {
		a, f, s := prAgent(t, 14)
		prRunning(t, a, f, s)
		arrange(a, f)
		err := a.EnsurePostgREST(context.Background(), s)
		wantContainment(t, err, name)
		if errors.Is(err, ErrCheckIncomplete) {
			t.Fatalf("%s reads as an incomplete check: %v", name, err)
		}
		if n := strings.Count(strings.Join(f.calls(), "\n"), "{{json .Containers}} -- "+platformNet); n != 1 {
			t.Fatalf("%s: platform members read %d times, want 1", name, n)
		}
	}
}

// The re-reads end with the caller's context: the check is then incomplete,
// and the adopted container is left as it is.
func TestMemberIDs_RereadBoundedByContext(t *testing.T) {
	old := memberReread
	memberReread = time.Hour
	t.Cleanup(func() { memberReread = old })
	a, f, s := prAgent(t, 14)
	prRunning(t, a, f, s)
	f.ctr(fakeCtr{Name: "starting", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{platformNet: "10.212.0.250"}})
	listedAsEndpoint(f, "starting", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := a.EnsurePostgREST(ctx, s)
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %v after its context ended", d)
	}
	if !errors.Is(err, ErrCheckIncomplete) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want an incomplete check carrying the deadline", err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("mutations %q after an incomplete check", m)
	}
}

// Every fact of the adoption check that could not be read gives an incomplete
// check: the error is returned, the running PostgREST is left as it is. The
// `ip` case stays red until a failed `ip` call is marked as a fact not read.
func TestCheckAdopted_EveryUnreadFactIncomplete(t *testing.T) {
	boom := errors.New("Cannot connect to the Docker daemon")
	members := func(f *fakeHost, out string) {
		f.onRun = func(args []string, _ []byte) (string, error, bool) {
			return out, nil, flagValue(args, "--format") == "{{json .Containers}}"
		}
	}
	for name, fault := range map[string]func(f *fakeHost, s Spec){
		"project network": func(f *fakeHost, s Spec) { f.failInspect[networkName(s.Ref)] = boom },
		"ingress network": func(f *fakeHost, s Spec) { f.failInspect[ingressNet] = boom },
		"cluster":         func(f *fakeHost, s Spec) { f.failInspect[clusterName(s.Ref)] = boom },
		"member parse":    func(f *fakeHost, s Spec) { members(f, "{\n") },
		"member trailing": func(f *fakeHost, s Spec) { members(f, "{} {}\n") },
		"endpoint value":  func(f *fakeHost, s Spec) { members(f, `{"ep-`+strings.Repeat("7e", 32)+`":[]}`+"\n") },
		"IPv6 flag": func(f *fakeHost, s Spec) {
			f.onRun = func(args []string, _ []byte) (string, error, bool) {
				return "", boom, flagValue(args, "--format") == "{{json .EnableIPv6}}"
			}
		},
		"member configuration": func(f *fakeHost, s Spec) {
			f.onRun = func(args []string, _ []byte) (string, error, bool) {
				return "", boom, flagValue(args, "--format") == confFormat && len(args) > 6
			}
		},
		"ip": func(f *fakeHost, s Spec) {
			inner := runIP
			runIP = func(context.Context, ...string) ([]byte, error) { return nil, errors.New("ip: signal: killed") }
			t.Cleanup(func() { runIP = inner })
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, f, s := prAgent(t, 14)
			prRunning(t, a, f, s)
			id := f.ctrs[postgrestName(s.Ref)].ID
			fault(f, s)
			err := a.EnsurePostgREST(context.Background(), s)
			if !errors.Is(err, ErrCheckIncomplete) {
				t.Fatalf("got %v, want an incomplete check", err)
			}
			if m := f.mutations(); len(m) != 0 {
				t.Fatalf("mutations %q after an incomplete check", m)
			}
			if c := f.ctrs[postgrestName(s.Ref)]; c.ID != id || !c.Running {
				t.Fatal("container not left as it was")
			}
		})
	}
}

// Containers starting one after another keep some endpoint key in every
// listing, each for one read only: the check waits for the keys of its first
// read, not for a listing without any, and adopts.
func TestMemberIDs_StaggeredEndpointsResolve(t *testing.T) {
	fastReread(t)
	a, f, s := prAgent(t, 14)
	prRunning(t, a, f, s)
	f.ctr(fakeCtr{Name: "starting", Running: true, CapDrop: []string{"ALL"},
		Nets: map[string]string{platformNet: "10.212.0.250"}})
	c := f.ctrs["starting"]
	n := 0
	f.before = func(args []string) {
		if flagValue(args, "--format") == "{{json .Containers}}" && args[len(args)-1] == platformNet {
			f.mu.Lock()
			n++
			c.ID = fmt.Sprintf("ep-%064x", n) // a new endpoint in every read
			f.mu.Unlock()
		}
	}
	if err := a.EnsurePostgREST(context.Background(), s); err != nil {
		t.Fatalf("staggered endpoint keys: %v", err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("mutations %q", m)
	}
}

// ───────── node check: the repository filesystem, hard links, the backup network ─────────

// statDevSame puts the repository root on the projects filesystem.
var statDevSame bool

// repoMount adds the repository filesystem to goodNode's mount table.
func repoMount(t *testing.T, a *Agent, line string) {
	t.Helper()
	// The repository root on a device of its own.
	t.Cleanup(swap(&statDev, func(path string) (uint64, error) {
		if path == a.p.RepoRoot() && !statDevSame {
			return 2, nil
		}
		return 1, nil
	}))
	p := filepath.Join(a.p.Root, "proc/mounts")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(b, line+"\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNodeCheck_RepoFilesystemRowBlocks(t *testing.T) {
	statDevSame = false
	t.Cleanup(func() { statDevSame = false })
	good := func(a *Agent) string {
		return "/dev/loop4 " + a.p.RepoRoot() + " xfs rw,nosuid,nodev,noexec,relatime,attr2,inode64,logbufs=8,logbsize=32k,usrquota 0 0"
	}
	a, _ := goodNode(t)
	repoMount(t, a, good(a))
	if r := rows(t, a)["repo-filesystem"]; !r.OK {
		t.Fatalf("control: %+v", r)
	}
	for name, c := range map[string]struct {
		line func(a *Agent) string
		hint string
	}{
		"absent": {func(a *Agent) string { return "" }, "not a mount point: mount an XFS filesystem there"},
		"not xfs": {func(a *Agent) string {
			return "/dev/sdb1 " + a.p.RepoRoot() + " ext4 rw,nosuid,nodev,noexec,usrquota 0 0"
		}, "is ext4, not XFS: mount an XFS filesystem there"},
		"quota accounting": {func(a *Agent) string { return strings.Replace(good(a), "usrquota", "uqnoenforce", 1) }, "without usrquota"},
		"no quota":         {func(a *Agent) string { return strings.Replace(good(a), ",usrquota", "", 1) }, "without usrquota"},
		"suid":             {func(a *Agent) string { return strings.Replace(good(a), "nosuid,", "", 1) }, "without nosuid"},
		"dev":              {func(a *Agent) string { return strings.Replace(good(a), "nodev,", "", 1) }, "without nodev"},
		"exec":             {func(a *Agent) string { return strings.Replace(good(a), "noexec,", "", 1) }, "without noexec"},
		"shadowed": {func(a *Agent) string {
			return good(a) + "\ntmpfs " + a.p.RepoRoot() + " tmpfs rw,nosuid,nodev,noexec 0 0"
		}, "is tmpfs, not XFS"},
		"the projects filesystem": {func(a *Agent) string {
			statDevSame = true
			return good(a)
		}, "is the projects filesystem: mount an XFS filesystem there"},
		"hostile type": {func(a *Agent) string {
			return "x " + a.p.RepoRoot() + " \x1b[2J" + strings.Repeat("y", 300) + " rw 0 0"
		}, "not XFS"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, dev := range []bool{false, true} {
				a, _ := goodNode(t)
				if dev {
					os.WriteFile(filepath.Join(filepath.Dir(a.p.NodeJSON()), "dev-mode"), nil, 0o600)
				}
				statDevSame = false
				if l := c.line(a); l != "" {
					repoMount(t, a, l)
				}
				r := rows(t, a)["repo-filesystem"]
				if r.OK || !Blocking(r) || !strings.Contains(r.Detail, c.hint) {
					t.Fatalf("dev %v: %+v, want blocking with %q", dev, r, c.hint)
				}
				if strings.ContainsAny(r.Detail, "\x1b\n") || len(r.Detail) > 400 {
					t.Fatalf("detail not bounded or not sanitised: %q", r.Detail)
				}
				if !strings.Contains(r.Detail, "usrquota,nosuid,nodev,noexec") {
					t.Fatalf("detail names no remedy: %q", r.Detail)
				}
			}
		})
	}
	// The projects filesystem's rows read their own mount point only.
	a, _ = goodNode(t)
	if r := rows(t, a); !r["quota-enforcement"].OK || r["repo-filesystem"].OK {
		t.Fatalf("rows read each other's mount: %+v %+v", r["quota-enforcement"], r["repo-filesystem"])
	}
}

func TestNodeCheck_ProtectedHardlinks_InformationalOnDevelopmentNode(t *testing.T) {
	put := func(a *Agent, v string) {
		os.WriteFile(filepath.Join(a.p.Root, "proc/sys/fs/protected_hardlinks"), []byte(v), 0o644)
	}
	a, _ := goodNode(t)
	put(a, "1\n")
	if r := rows(t, a)["protected-hardlinks"]; !r.OK || r.Detail != "" {
		t.Fatalf("control: %+v", r)
	}
	for v, hint := range map[string]string{"0\n": "fs.protected_hardlinks is 0, want 1", "": "unreadable", "\x1b[2J" + strings.Repeat("9", 500): "unreadable"} {
		a, _ := goodNode(t)
		put(a, v)
		r := rows(t, a)["protected-hardlinks"]
		if r.OK || !Blocking(r) || !strings.Contains(r.Detail, hint) || !strings.Contains(r.Detail, "sysctl") ||
			strings.ContainsAny(r.Detail, "\x1b\n") || len(r.Detail) > 400 {
			t.Fatalf("%q: %+v", v, r)
		}
		os.WriteFile(filepath.Join(filepath.Dir(a.p.NodeJSON()), "dev-mode"), nil, 0o600)
		r = rows(t, a)["protected-hardlinks"]
		if !r.OK || !strings.HasPrefix(r.Detail, "informational (dev-mode): ") || !strings.Contains(r.Detail, hint) {
			t.Fatalf("%q, dev mode: %+v", v, r)
		}
	}
	a, _ = goodNode(t)
	os.Remove(filepath.Join(a.p.Root, "proc/sys/fs/protected_hardlinks"))
	if r := rows(t, a)["protected-hardlinks"]; r.OK {
		t.Fatalf("absent: %+v", r)
	}
}

func TestNodeCheck_BackupNetworkAllowed(t *testing.T) {
	a, f := goodNode(t)
	if r := rows(t, a)["docker-networks"]; !r.OK {
		t.Fatalf("control: %+v", r)
	}
	if err := a.EnsureBackupNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := rows(t, a)["docker-networks"]; !r.OK {
		t.Fatalf("with the backup network: %+v", r)
	}
	f.net(fakeNet{Network: dockerx.Network{Name: "backup2"}})
	if r := rows(t, a)["docker-networks"]; r.OK || !strings.Contains(r.Detail, "backup2") {
		t.Fatalf("another network: %+v", r)
	}
	delete(f.nets, "backup2")
	f.nets["backup"].Driver = "macvlan"
	if r := rows(t, a)["docker-networks"]; r.OK {
		t.Fatalf("backup with another driver: %+v", r)
	}
}

// ───────── the members of a project network; forwarding ─────────

// memberRule is how a refusal by the member rule names it.
const memberRule = "member rule"

// noForward is the settings of dashcfg.NoForwardArgs as Docker records them.
func noForward() map[string]string {
	m := map[string]string{}
	for _, kv := range dashcfg.NoForwardArgs() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

// proxyCtr adds sp-pgcap as the platform runs it: on platform at its address
// and on s's project network at the proxy's address there.
func proxyCtr(a *Agent, f *fakeHost, s Spec) *fakeCtr {
	return f.ctr(fakeCtr{Name: dashcfg.PgcapName, Running: true, Restart: "unless-stopped", CapDrop: []string{"ALL"},
		Labels: map[string]string{"supapace.role": "pgcap"}, Sysctls: noForward(),
		Nets: map[string]string{"platform": dashcfg.Static(a.cfg).Pgcap.String(),
			"proj-" + s.Ref: dashcfg.ProxyAddr(a.cfg, s.SubnetIndex).String()}})
}

// A project network holds at most the cluster, the PostgREST and, on a node
// with a studio domain, the wire proxy, each at its address: anything else,
// and any of the three elsewhere, refuses the start whatever its
// capabilities. A network with fewer members is not refused.
func TestGate_ProjectNetworkMembers(t *testing.T) {
	const domain = "studio.test"
	proj := "proj-" + testRef
	at := func(a *Agent, host uint32) string { // an address of slice 14
		b := a.cfg.Slice(14).Addr().As4()
		b[3] += byte(host)
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	}
	cases := []struct {
		name, domain string
		arrange      func(a *Agent, f *fakeHost, s Spec)
		refused      string // what the refusal must name; "" for a start that passes
	}{
		{"the cluster and the PostgREST", "", func(a *Agent, f *fakeHost, s Spec) {}, ""},
		{"the cluster alone", "", func(a *Agent, f *fakeHost, s Spec) { delete(f.ctrs, "postgrest-"+s.Ref) }, ""},
		{"no member", "", func(a *Agent, f *fakeHost, s Spec) {
			delete(f.ctrs, "postgrest-"+s.Ref)
			delete(f.ctrs, "pg-"+s.Ref)
		}, ""},
		{"no proxy on a node with a studio domain", domain, func(a *Agent, f *fakeHost, s Spec) {}, ""},
		{"the proxy at its address", domain, func(a *Agent, f *fakeHost, s Spec) { proxyCtr(a, f, s) }, ""},
		{"the proxy on a node without a studio domain", "", func(a *Agent, f *fakeHost, s Spec) { proxyCtr(a, f, s) }, dashcfg.PgcapName},
		{"the proxy at another address", domain, func(a *Agent, f *fakeHost, s Spec) {
			proxyCtr(a, f, s).Nets[proj] = at(a, 12)
		}, dashcfg.PgcapName},
		{"the proxy at the reserved address", domain, func(a *Agent, f *fakeHost, s Spec) {
			proxyCtr(a, f, s).Nets[proj] = at(a, dashcfg.ReservedHost)
		}, dashcfg.PgcapName},
		{"a hardened fourth member", domain, func(a *Agent, f *fakeHost, s Spec) {
			proxyCtr(a, f, s)
			f.ctr(fakeCtr{Name: "fourth", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{proj: at(a, 12)}})
		}, "fourth"},
		{"a hardened stranger", "", func(a *Agent, f *fakeHost, s Spec) {
			f.ctr(fakeCtr{Name: "stranger", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{proj: at(a, 12)}})
		}, "stranger"},
		{"a stranger at the reserved address", "", func(a *Agent, f *fakeHost, s Spec) {
			f.ctr(fakeCtr{Name: "stranger", Running: true, CapDrop: []string{"ALL"},
				Nets: map[string]string{proj: at(a, dashcfg.ReservedHost)}})
		}, "stranger"},
		{"a stranger at the proxy's address", domain, func(a *Agent, f *fakeHost, s Spec) {
			f.ctr(fakeCtr{Name: "stranger", Running: true, CapDrop: []string{"ALL"},
				Nets: map[string]string{proj: at(a, dashcfg.ProxyHost)}})
		}, "stranger"},
		{"another project's cluster", "", func(a *Agent, f *fakeHost, s Spec) {
			f.ctr(fakeCtr{Name: "pg-" + prRef(15), Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{proj: at(a, 12)}})
		}, "pg-" + prRef(15)},
		{"the cluster at another address", "", func(a *Agent, f *fakeHost, s Spec) { f.ctrs["pg-"+s.Ref].Nets[proj] = at(a, 12) }, "pg-" + testRef},
		{"the cluster at the reserved address", "", func(a *Agent, f *fakeHost, s Spec) {
			f.ctrs["pg-"+s.Ref].Nets[proj] = at(a, dashcfg.ReservedHost)
		}, "pg-" + testRef},
		{"the PostgREST at another address", "", func(a *Agent, f *fakeHost, s Spec) {
			f.ctrs["postgrest-"+s.Ref].Nets[proj] = at(a, 12)
		}, "postgrest-" + testRef},
		{"the cluster and the PostgREST at each other's address", "", func(a *Agent, f *fakeHost, s Spec) {
			pg, pr := f.ctrs["pg-"+s.Ref], f.ctrs["postgrest-"+s.Ref]
			pg.Nets[proj], pr.Nets[proj] = pr.Nets[proj], pg.Nets[proj]
		}, testRef},
		{"a created PostgREST without an address", "", func(a *Agent, f *fakeHost, s Spec) {
			pr := f.ctrs["postgrest-"+s.Ref]
			pr.Running, pr.Nets[proj] = false, ""
		}, "postgrest-" + testRef},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, f, s := newTestAgent(t)
			a.cfg.StudioDomain = c.domain
			healthy(a, f, s)
			tenants(a, f, s)
			ctx := context.Background()
			if err := a.CheckContainment(ctx, s); err != nil {
				t.Fatalf("control: %v", err)
			}
			c.arrange(a, f, s)
			for name, gate := range map[string]func(context.Context, Spec) error{"start": a.CheckContainment, "adoption": a.CheckAdopted} {
				err := gate(ctx, s)
				if c.refused == "" {
					if err != nil {
						t.Errorf("%s refused: %v", name, err)
					}
					continue
				}
				wantContainment(t, err, name)
				if errors.Is(err, ErrCheckIncomplete) {
					t.Errorf("%s: a finding reads as an incomplete check: %v", name, err)
				}
				for _, w := range []string{memberRule, proj, c.refused} {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("%s: refusal %q lacks %q", name, err, w)
					}
				}
			}
		})
	}
	// A studio domain on a configuration the dashboard refuses counts as none.
	a, f, s := newTestAgent(t)
	a.cfg.StudioDomain, a.cfg.UIDBase, a.cfg.UIDCount = domain, 65000, 700000 // the project uids would hold the dashboard's
	if _, err := dashcfg.For(a.cfg); err == nil || !dashcfg.Static(a.cfg).Pgcap.IsValid() {
		t.Fatalf("fixture: a configuration refused for another reason than its addresses: %v", err)
	}
	healthy(a, f, s)
	tenants(a, f, s)
	proxyCtr(a, f, s)
	if err := a.CheckAdopted(context.Background(), s); !errors.Is(err, ErrContainment) || !strings.Contains(err.Error(), memberRule) ||
		!strings.Contains(err.Error(), dashcfg.PgcapName) {
		t.Fatalf("the proxy on a refused configuration: got %v, want the member rule", err)
	}
	// What the refusal says: the member and where it is, and what the network
	// may hold — nothing of any other network.
	a, f, s = newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	f.ctr(fakeCtr{Name: "stranger", Running: true, CapDrop: []string{"ALL"}, Labels: map[string]string{"secret": "label-value"},
		Nets: map[string]string{proj: at(a, 12), "ingress": "10.212.8.77"}})
	err := a.CheckAdopted(context.Background(), s)
	wantContainment(t, err, "stranger")
	for _, w := range []string{at(a, 12), "pg-" + testRef, at(a, dashcfg.ClusterHost), "postgrest-" + testRef, at(a, dashcfg.RestHost)} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal %q lacks %q", err, w)
		}
	}
	for _, w := range []string{"label-value", "10.212.8.77", dashcfg.PgcapName} {
		if strings.Contains(err.Error(), w) {
			t.Errorf("refusal %q carries %q", err, w)
		}
	}
}

// Each of the dashboard's four addresses on platform belongs to one
// container by name: another member holding one refuses the start. A
// stranger elsewhere on platform is the node check's to report.
func TestGate_FixedPlatformAddressUnderAnotherName(t *testing.T) {
	for _, domain := range []string{"", "studio.test"} {
		a, f, s := newTestAgent(t)
		a.cfg.StudioDomain = domain
		healthy(a, f, s)
		tenants(a, f, s)
		ad := dashcfg.Static(a.cfg)
		owners := map[string]string{ad.Studio.String(): dashcfg.StudioName, ad.PgMeta0.String(): dashcfg.PgMeta0Name,
			ad.PgMeta1.String(): dashcfg.PgMeta1Name, ad.Pgcap.String(): dashcfg.PgcapName}
		if len(owners) != 4 {
			t.Fatalf("the default node has no four dashboard addresses: %+v", ad)
		}
		ctx := context.Background()
		for addr, owner := range owners {
			f.ctr(fakeCtr{Name: "squatter", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{"platform": addr}})
			err := a.CheckAdopted(ctx, s)
			wantContainment(t, err, "another name at "+addr)
			if errors.Is(err, ErrCheckIncomplete) || !strings.Contains(err.Error(), "squatter holds "+addr) || !strings.Contains(err.Error(), owner) {
				t.Errorf("domain %q, %s: got %v, want a finding naming the holder, the address and %s", domain, addr, err, owner)
			}
			// Created, not started: its configured address counts, as for a
			// PostgREST address.
			delete(f.ctrs, "squatter")
			f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: false, CapDrop: []string{"ALL"}, Nets: map[string]string{"platform": addr}})
			wantContainment(t, a.CheckAdopted(ctx, s), "a created tenant container configured at "+addr)
			tenants(a, f, s)
			// Control: its owner there passes.
			f.ctr(fakeCtr{Name: owner, Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{"platform": addr}})
			if err := a.CheckAdopted(ctx, s); err != nil {
				t.Errorf("domain %q: %s at %s refused: %v", domain, owner, addr, err)
			}
			delete(f.ctrs, owner)
		}
		f.ctr(fakeCtr{Name: "squatter", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{"platform": "10.212.6.20"}})
		if err := a.CheckAdopted(ctx, s); err != nil {
			t.Errorf("domain %q: a hardened stranger elsewhere on platform refused by the gate: %v", domain, err)
		}
	}
}

// A member of the project network listed under its endpoint key for a
// moment is read again and then judged by the member rule like any other; a
// key that stays is refused; a context that ends meanwhile leaves the check
// incomplete.
func TestGate_TransientEndpointIsReadAgain(t *testing.T) {
	fastReread(t)
	proj := "proj-" + testRef
	ctx := context.Background()
	for _, reads := range []int{1, memberRereads} {
		a, f, s := newTestAgent(t)
		healthy(a, f, s)
		tenants(a, f, s)
		netReads := listedAsEndpointOn(f, proj, "pg-"+s.Ref, reads)
		if err := a.CheckAdopted(ctx, s); err != nil {
			t.Fatalf("reads=%d: a starting cluster refused: %v", reads, err)
		}
		if n := netReads(); n != reads+1 {
			t.Fatalf("reads=%d: members of the project network read %d times, want %d", reads, n, reads+1)
		}
	}
	// Resolved, a stranger is the member rule's finding.
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	f.ctr(fakeCtr{Name: "starting", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{proj: "10.213.3.140"}})
	listedAsEndpointOn(f, proj, "starting", 1)
	err := a.CheckAdopted(ctx, s)
	wantContainment(t, err, "a resolved stranger")
	if errors.Is(err, ErrCheckIncomplete) || !strings.Contains(err.Error(), memberRule) {
		t.Fatalf("got %v, want the member rule", err)
	}
	// A key that stays: refused, a completed check.
	a, f, s = newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	netReads := listedAsEndpointOn(f, proj, "pg-"+s.Ref, 1<<30)
	err = a.CheckAdopted(ctx, s)
	wantContainment(t, err, "a persistent endpoint key")
	if errors.Is(err, ErrCheckIncomplete) || !strings.Contains(err.Error(), "endpoint without a container") {
		t.Fatalf("got %v, want an unidentified member", err)
	}
	if n := netReads(); n != 1+memberRereads {
		t.Fatalf("members read %d times, want %d", n, 1+memberRereads)
	}
	// The context ends during the re-reads: incomplete, not a finding.
	a, f, s = newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	listedAsEndpointOn(f, proj, "pg-"+s.Ref, 1<<30)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := a.CheckAdopted(cctx, s); !errors.Is(err, ErrContainment) || !errors.Is(err, ErrCheckIncomplete) {
		t.Fatalf("an ended context: got %v, want an incomplete check", err)
	}
}

// pairs counts how often flag is directly followed by value before "--".
func pairs(args []string, flag, value string) int {
	n := 0
	for i := 0; i+1 < len(args) && args[i] != "--"; i++ {
		if args[i] == flag && args[i+1] == value {
			n++
		}
	}
	return n
}

// without returns args without each flag-value pair of drop.
func without(args []string, drop ...string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if i+1 < len(args) && args[i] == "--sysctl" && slices.Contains(drop, args[i+1]) {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// The gateway is on two networks: it is created with the forwarding settings, its
// label covers them, and a gateway created without them is made again once.
func TestGatewayArgs_ForwardingSettings(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	delete(f.ctrs, "sp-gateway")
	writeTLS(t, a)
	ctx := context.Background()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	opts, cmd, conf, err := a.gatewayConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(noForward()) != 6 {
		t.Fatalf("settings: %v", noForward())
	}
	for k, v := range noForward() {
		if n := pairs(opts, "--sysctl", k+"="+v); n != 1 {
			t.Errorf("--sysctl %s=%s is %d times in the gateway's options", k, v, n)
		}
	}
	// The label of the arguments without the settings, as an older daemon
	// computed it.
	extra, err := fileDigests(filepath.Join(a.p.GatewayDir(), "tls", "cert.pem"), a.seccompFile())
	if err != nil {
		t.Fatal(err)
	}
	extra = append(extra, "image id="+f.images[a.cfg.Images.Gateway])
	if got := configHash(opts, cmd, extra...); got != conf {
		t.Fatalf("the label is not the hash of the options: %s, %s", got, conf)
	}
	var drop []string
	for k, v := range noForward() {
		drop = append(drop, k+"="+v)
	}
	older := configHash(without(opts, drop...), cmd, extra...)
	if older == conf {
		t.Fatal("the label does not cover the settings")
	}
	gw := f.ctrs["sp-gateway"]
	if !maps.Equal(gw.Sysctls, noForward()) || gw.Labels["supapace.config"] != conf {
		t.Fatalf("created with %v and label %s", gw.Sysctls, gw.Labels["supapace.config"])
	}
	// A gateway of the older arguments: made again once, then left alone.
	gw.Labels["supapace.config"], gw.Sysctls = older, nil
	f.resetLog()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 4 || m[0] != "docker rm -f -- sp-gateway" {
		t.Fatalf("a gateway created without the settings: %q", m)
	}
	if gw := f.ctrs["sp-gateway"]; !maps.Equal(gw.Sysctls, noForward()) || gw.Labels["supapace.config"] != conf {
		t.Fatalf("made again with %v and label %s", gw.Sysctls, gw.Labels["supapace.config"])
	}
	for range 2 {
		f.resetLog()
		if err := a.EnsureGateway(ctx); err != nil {
			t.Fatal(err)
		}
		if m := f.mutations(); len(m) != 0 {
			t.Fatalf("the gateway made again a second time: %q", m)
		}
	}
}

// dashCtrOn adds one of the dashboard's containers on platform.
func dashCtrOn(f *fakeHost, name, role, addr string) *fakeCtr {
	return f.ctr(fakeCtr{Name: name, Running: true, Restart: "unless-stopped", CapDrop: []string{"ALL"},
		Labels: map[string]string{"supapace.role": role}, Nets: map[string]string{"platform": addr}})
}

// The row platform-members accepts the dashboard's four containers, each
// with its role label at its address, on a node with a studio domain only.
func TestNodeCheck_PlatformMembers_AcceptsTheFour_OnlyWithAStudioDomain(t *testing.T) {
	type member struct{ name, role, addr string }
	four := func(a *Agent) []member {
		ad := dashcfg.Static(a.cfg)
		return []member{{dashcfg.StudioName, "studio", ad.Studio.String()}, {dashcfg.PgMeta0Name, "pgmeta", ad.PgMeta0.String()},
			{dashcfg.PgMeta1Name, "pgmeta", ad.PgMeta1.String()}, {dashcfg.PgcapName, "pgcap", ad.Pgcap.String()}}
	}
	node := func(t *testing.T, domain string) (*Agent, *fakeHost) {
		a, f := goodNode(t)
		a.cfg.StudioDomain = domain
		for _, m := range four(a) {
			dashCtrOn(f, m.name, m.role, m.addr)
		}
		return a, f
	}
	a, _ := node(t, "studio.test")
	if r := rows(t, a)["platform-members"]; !r.OK {
		t.Fatalf("the four on a node with a studio domain: %+v", r)
	}
	fails := func(t *testing.T, a *Agent, name string) {
		t.Helper()
		r := rows(t, a)["platform-members"]
		if r.OK || !Blocking(r) || !strings.Contains(r.Detail, name) {
			t.Fatalf("row %+v (blocking %v), want a blocking failure naming %s", r, Blocking(r), name)
		}
	}
	for i, m := range four(a) {
		t.Run(m.name, func(t *testing.T) {
			// Alone, on a node with a studio domain: accepted.
			a, f := goodNode(t)
			a.cfg.StudioDomain = "studio.test"
			c := dashCtrOn(f, m.name, m.role, m.addr)
			if r := rows(t, a)["platform-members"]; !r.OK {
				t.Fatalf("alone: %+v", r)
			}
			// Without a studio domain, and on a configuration the dashboard
			// refuses: a foreign member.
			a.cfg.StudioDomain = ""
			fails(t, a, m.name)
			a.cfg.StudioDomain = "studio.test"
			a.cfg.UIDBase, a.cfg.UIDCount = 65000, 700000 // the project uids would hold the dashboard's
			if _, err := dashcfg.For(a.cfg); err == nil || dashcfg.Static(a.cfg).Pgcap.String() != four(a)[3].addr {
				t.Fatalf("fixture: a configuration refused for another reason than its addresses: %v", err)
			}
			fails(t, a, m.name)
			a.cfg.UIDBase, a.cfg.UIDCount = nodecfg.Default("sp.test").UIDBase, nodecfg.Default("sp.test").UIDCount
			// Another role label, none, or another address.
			c.Labels["supapace.role"] = "postgrest"
			fails(t, a, m.name)
			delete(c.Labels, "supapace.role")
			fails(t, a, m.name)
			c.Labels["supapace.role"] = m.role
			c.Nets["platform"] = four(a)[(i+1)%4].addr
			fails(t, a, m.name)
			c.Nets["platform"] = "10.212.6.20"
			fails(t, a, m.name)
			c.Nets["platform"] = m.addr
			// A capability.
			c.CapAdd = []string{"NET_RAW"}
			fails(t, a, m.name)
			c.CapAdd = nil
			if r := rows(t, a)["platform-members"]; !r.OK {
				t.Fatalf("restored: %+v", r)
			}
			// Another container at its address, under another name or as a
			// project's PostgREST.
			delete(f.ctrs, m.name)
			dashCtrOn(f, "squatter", m.role, m.addr)
			fails(t, a, "squatter")
		})
	}
	// Every other member is still refused beside the four.
	a, f := node(t, "studio.test")
	dashCtrOn(f, "sp-pgmeta-2", "pgmeta", "10.212.0.7")
	fails(t, a, "sp-pgmeta-2")
}

// fwdNode is a good node with a gateway and one PostgREST as this agent
// creates them.
func fwdNode(t *testing.T) (*Agent, *fakeHost, Spec) {
	a, f := goodNode(t)
	s := Spec{Ref: testRef, Epoch: 1, Generation: 1, UID: 700005, GID: 700005, SubnetIndex: 14, DiskQuotaMB: 8192, MemMB: 512, Pids: 512,
		Keys: prKeys(t), UserRoles: []string{"authenticated"}}
	s.Secrets.AuthenticatorPassword = "pw"
	writeSeccomp(t, a)
	writeTLS(t, a)
	delete(f.ctrs, "sp-gateway")
	delete(f.ctrs, "postgrest-"+s.Ref)
	ctx := context.Background()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	f.nftErr = nil
	if err := a.EnsurePostgREST(ctx, s); err != nil {
		t.Fatal(err)
	}
	return a, f, s
}

// The row forwarding reads Docker's record of the gateway, of every
// PostgREST and of the proxy: each setting, at its value. A gateway or a
// PostgREST of another configuration label is the next ensure's to make
// again and is not judged here.
func TestNodeCheck_Forwarding(t *testing.T) {
	a, f, s := fwdNode(t)
	if r := rows(t, a)["forwarding"]; !r.OK {
		t.Fatalf("a gateway and a PostgREST as created: %+v", r)
	}
	fails := func(t *testing.T, a *Agent, wants ...string) {
		t.Helper()
		r := rows(t, a)["forwarding"]
		if r.OK || !Blocking(r) {
			t.Fatalf("row %+v (blocking %v), want a blocking failure", r, Blocking(r))
		}
		for _, w := range wants {
			if !strings.Contains(r.Detail, w) {
				t.Fatalf("detail %q lacks %q", r.Detail, w)
			}
		}
	}
	proxyCtr(a, f, s)
	if r := rows(t, a)["forwarding"]; !r.OK {
		t.Fatalf("with the proxy: %+v", r)
	}
	for _, name := range []string{"sp-gateway", "postgrest-" + s.Ref, dashcfg.PgcapName} {
		c := f.ctrs[name]
		for k, v := range noForward() {
			delete(c.Sysctls, k)
			fails(t, a, name, k)
			c.Sysctls[k] = "2"
			fails(t, a, name, k)
			c.Sysctls[k] = v
		}
		saved := c.Sysctls
		c.Sysctls = nil
		fails(t, a, name)
		c.Sysctls = saved
		if r := rows(t, a)["forwarding"]; !r.OK {
			t.Fatalf("%s restored: %+v", name, r)
		}
	}
	// A second PostgREST, of another project, is read too.
	s2 := s
	s2.Ref, s2.SubnetIndex = prRef(15), 15
	prNet(a, f, s2.Ref, 15)
	f.ip["-j -d addr show dev "+nodecfg.BridgeName(15)] = bridgeIface(nodecfg.BridgeName(15), false)
	if err := a.EnsurePostgREST(context.Background(), s2); err != nil {
		t.Fatal(err)
	}
	if r := rows(t, a)["forwarding"]; !r.OK {
		t.Fatalf("two PostgRESTs: %+v", r)
	}
	delete(f.ctrs["postgrest-"+s2.Ref].Sysctls, "net.ipv4.ip_forward")
	fails(t, a, "postgrest-"+s2.Ref, "net.ipv4.ip_forward")
	// Stopped, it is still Docker's record of what its next start runs with.
	f.ctrs["postgrest-"+s2.Ref].Running = false
	fails(t, a, "postgrest-"+s2.Ref)
	delete(f.ctrs, "postgrest-"+s2.Ref)

	// Another configuration label (an older daemon's container, a changed
	// file): not adopted, made again at the next ensure, not this row's.
	for _, name := range []string{"sp-gateway", "postgrest-" + s.Ref} {
		c := f.ctrs[name]
		label, saved := c.Labels["supapace.config"], c.Sysctls
		c.Labels["supapace.config"], c.Sysctls = strings.Repeat("0", 64), nil
		if r := rows(t, a)["forwarding"]; !r.OK {
			t.Fatalf("%s of another configuration fails the row: %+v", name, r)
		}
		// The proxy has no such grace: it never existed without the settings.
		c.Labels["supapace.config"], c.Sysctls = label, saved
	}
	px := f.ctrs[dashcfg.PgcapName]
	px.Labels["supapace.config"], px.Sysctls = strings.Repeat("0", 64), nil
	fails(t, a, dashcfg.PgcapName)
	delete(f.ctrs, dashcfg.PgcapName)

	// None of the three exists: nothing to read.
	delete(f.ctrs, "sp-gateway")
	delete(f.ctrs, "postgrest-"+s.Ref)
	if r := rows(t, a)["forwarding"]; !r.OK {
		t.Fatalf("no container: %+v", r)
	}
	// Docker does not answer: the row fails, whichever read it is.
	for _, what := range []string{"sp-gateway", dashcfg.PgcapName, "list supapace.role=postgrest"} {
		a, f, _ = fwdNode(t)
		f.failInspect[what] = errors.New("daemon busy")
		fails(t, a, "daemon busy")
	}
	a, f, _ = fwdNode(t)
	f.failVerb["container inspect"] = errors.New("daemon busy")
	fails(t, a, "daemon busy")

	// The gateway's own label cannot be computed (its certificate is gone):
	// nothing says the container is this daemon's, and the row gateway reports
	// it.
	a, f, _ = fwdNode(t)
	f.ctrs["sp-gateway"].Sysctls = nil
	if err := os.Remove(filepath.Join(a.p.GatewayDir(), "tls", "cert.pem")); err != nil {
		t.Fatal(err)
	}
	if all := rows(t, a); !all["forwarding"].OK || all["gateway"].OK {
		t.Fatalf("no gateway label: forwarding %+v, gateway %+v", all["forwarding"], all["gateway"])
	}

	// A container whose labels and address give this daemon's label is read,
	// whatever made it; one whose ref label is no ref is not, and no file is
	// looked up by that label.
	for _, ref := range []string{prRef(20), "../evil"} {
		a, f, _ = fwdNode(t)
		other := Spec{Ref: ref, SubnetIndex: 20, Generation: 1, Epoch: 1}
		dir := a.postgrestDir(ref)
		mkdirs(t, dir)
		if err := os.WriteFile(filepath.Join(dir, postgrestConf), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		hash, err := renderedHash(dir, postgrestConf)
		if err != nil {
			t.Fatal(err)
		}
		flags, tail := a.postgrestArgs(other)
		f.ctr(fakeCtr{Name: "postgrest-other", Running: true, CapDrop: []string{"ALL"},
			Labels: map[string]string{"supapace.role": "postgrest", "supapace.ref": ref, "supapace.generation": "1", "supapace.epoch": "1",
				"supapace.config": prLabel(t, a, hash, slices.Concat(flags, tail))},
			Nets: map[string]string{"platform": a.cfg.PlatformAddr(20).String()}})
		if r := rows(t, a)["forwarding"]; r.OK != (ref == "../evil") {
			t.Fatalf("ref label %q: %+v", ref, r)
		}
	}
}

// A PostgREST of a later generation or epoch is this daemon's as much as the
// first: the row forwarding computes the label from the container's own
// generation and epoch labels, so such a container is judged too.
func TestNodeCheck_Forwarding_LaterGenerationAndEpoch(t *testing.T) {
	a, f, s := fwdNode(t)
	for _, later := range [][2]int64{{2, 1}, {1, 2}, {7, 3}} {
		s.Generation, s.Epoch = later[0], later[1]
		if err := a.EnsurePostgREST(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		c := f.ctrs["postgrest-"+s.Ref]
		if c.Labels["supapace.generation"] != fmt.Sprint(later[0]) || c.Labels["supapace.epoch"] != fmt.Sprint(later[1]) {
			t.Fatalf("fixture: labels %v", c.Labels)
		}
		if r := rows(t, a)["forwarding"]; !r.OK {
			t.Fatalf("generation %d, epoch %d, as created: %+v", later[0], later[1], r)
		}
		delete(c.Sysctls, "net.ipv4.ip_forward")
		if r := rows(t, a)["forwarding"]; r.OK || !Blocking(r) || !strings.Contains(r.Detail, "postgrest-"+s.Ref) {
			t.Fatalf("generation %d, epoch %d, without a setting: row %+v, want a blocking failure naming it", later[0], later[1], r)
		}
	}
}

// The row project-addresses holds every project network to its members: an
// extra or a misplaced one fails it, a missing one does not.
func TestNodeCheck_ProjectAddresses(t *testing.T) {
	proj := "proj-" + testRef
	s := Spec{Ref: testRef, SubnetIndex: 14}
	other := Spec{Ref: prRef(15), SubnetIndex: 15}
	cases := []struct {
		name, domain string
		arrange      func(a *Agent, f *fakeHost)
		fails        string // what the detail must name; "" for a passing row
	}{
		{"the cluster and the PostgREST", "", func(a *Agent, f *fakeHost) {}, ""},
		{"the cluster alone", "", func(a *Agent, f *fakeHost) { delete(f.ctrs, "postgrest-"+testRef) }, ""},
		{"no member", "", func(a *Agent, f *fakeHost) {
			delete(f.ctrs, "postgrest-"+testRef)
			delete(f.ctrs, "pg-"+testRef)
		}, ""},
		{"no project network", "", func(a *Agent, f *fakeHost) {
			delete(f.ctrs, "postgrest-"+testRef)
			delete(f.ctrs, "pg-"+testRef)
			delete(f.nets, proj)
		}, ""},
		{"the proxy at its address", "studio.test", func(a *Agent, f *fakeHost) { proxyCtr(a, f, s) }, ""},
		{"the proxy missing on a node with a studio domain", "studio.test", func(a *Agent, f *fakeHost) {}, ""},
		{"the proxy on a node without a studio domain", "", func(a *Agent, f *fakeHost) { proxyCtr(a, f, s) }, dashcfg.PgcapName},
		{"the proxy at another address", "studio.test", func(a *Agent, f *fakeHost) {
			proxyCtr(a, f, s).Nets[proj] = "10.213.3.140"
		}, dashcfg.PgcapName},
		{"a hardened stranger", "", func(a *Agent, f *fakeHost) {
			f.ctr(fakeCtr{Name: "stranger", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{proj: "10.213.3.140"}})
		}, "stranger"},
		{"a stranger at the reserved address", "", func(a *Agent, f *fakeHost) {
			f.ctr(fakeCtr{Name: "stranger", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{proj: "10.213.3.133"}})
		}, "stranger"},
		{"the cluster at another address", "", func(a *Agent, f *fakeHost) { f.ctrs["pg-"+testRef].Nets[proj] = "10.213.3.140" }, "pg-" + testRef},
		{"the PostgREST at the cluster's address", "", func(a *Agent, f *fakeHost) {
			delete(f.ctrs, "pg-"+testRef)
			f.ctrs["postgrest-"+testRef].Nets[proj] = a.cfg.ClusterAddr(14).String()
		}, "postgrest-" + testRef},
		{"a second project network as it should be", "studio.test", func(a *Agent, f *fakeHost) {
			prNet(a, f, other.Ref, 15)
			tenants(a, f, other)
			proxyCtr(a, f, s).Nets["proj-"+other.Ref] = dashcfg.ProxyAddr(a.cfg, 15).String()
		}, ""},
		{"a stranger on a second project network", "", func(a *Agent, f *fakeHost) {
			prNet(a, f, other.Ref, 15)
			tenants(a, f, other)
			f.ctr(fakeCtr{Name: "stranger", Running: true, CapDrop: []string{"ALL"},
				Nets: map[string]string{"proj-" + other.Ref: "10.213.3.204"}})
		}, "proj-" + other.Ref},
		{"this project's cluster on another project's network", "", func(a *Agent, f *fakeHost) {
			prNet(a, f, other.Ref, 15)
			f.ctrs["pg-"+testRef].Nets["proj-"+other.Ref] = a.cfg.ClusterAddr(15).String()
		}, "pg-" + testRef},
		{"a member on a network whose subnet is no slice of its bridge", "", func(a *Agent, f *fakeHost) {
			f.nets[proj].Subnet = a.cfg.Slice(15).String()
		}, "not a slice of this node"},
		{"no member on a network whose subnet is no slice of its bridge", "", func(a *Agent, f *fakeHost) {
			delete(f.ctrs, "postgrest-"+testRef)
			delete(f.ctrs, "pg-"+testRef)
			f.nets[proj].Subnet = a.cfg.Slice(15).String()
		}, ""},
		{"the members cannot be read", "", func(a *Agent, f *fakeHost) {
			f.onRun = func(args []string, _ []byte) (string, error, bool) {
				return "", errors.New("daemon busy"), flagValue(args, "--format") == "{{json .Containers}}" && args[len(args)-1] == proj
			}
		}, "daemon busy"},
		{"the network cannot be read", "", func(a *Agent, f *fakeHost) { f.failInspect[proj] = errors.New("daemon busy") }, "daemon busy"},
		{"the members' configuration cannot be read", "", func(a *Agent, f *fakeHost) {
			f.failVerb["container inspect"] = errors.New("daemon busy")
		}, "daemon busy"},
		{"a persistent endpoint key", "", func(a *Agent, f *fakeHost) { listedAsEndpointOn(f, proj, "pg-"+testRef, 1<<30) }, "endpoint without a container"},
		{"a transient endpoint key", "", func(a *Agent, f *fakeHost) { listedAsEndpointOn(f, proj, "pg-"+testRef, 1) }, ""},
		{"a network removed since the listing", "", func(a *Agent, f *fakeHost) {
			f.onRun = func(args []string, _ []byte) (string, error, bool) {
				return proj + " bridge\nproj-" + other.Ref + " bridge\n", nil, args[0] == "network" && args[1] == "ls"
			}
		}, ""},
		{"the networks cannot be listed", "", func(a *Agent, f *fakeHost) { f.failVerb["network ls"] = errors.New("daemon busy") }, "daemon busy"},
		{"a member on a network named like a project's, with no ref in its name", "", func(a *Agent, f *fakeHost) {
			prNet(a, f, "x", 15)
			f.ctr(fakeCtr{Name: "stranger", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{"proj-x": "10.213.3.204"}})
		}, "proj-x"},
	}
	fastReread(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, f := goodNode(t)
			a.cfg.StudioDomain = c.domain
			if r := rows(t, a)["project-addresses"]; !r.OK {
				t.Fatalf("control: %+v", r)
			}
			c.arrange(a, f)
			r := rows(t, a)["project-addresses"]
			switch {
			case c.fails == "" && !r.OK:
				t.Fatalf("row fails: %+v", r)
			case c.fails != "" && (r.OK || !Blocking(r) || !strings.Contains(r.Detail, c.fails)):
				t.Fatalf("row %+v (blocking %v), want a blocking failure naming %q", r, Blocking(r), c.fails)
			}
		})
	}
}
