package agent

// Refusals the start gate and the platform objects need beyond the cases in
// agent_test.go. Each test fails on the current code until the matching
// check is added.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
	f.ctr(fakeCtr{Name: "flaky", Running: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_RAW"},
		Nets: map[string]string{"proj-" + s.Ref: "10.213.3.140"}})
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
	f.failInspect["flaky"] = errors.New("daemon busy")
	wantContainment(t, a.CheckContainment(context.Background(), s), "inspect error on re-check")
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
			Nets: map[string]string{"proj-" + s.Ref: "10.213.3.140"}})
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
	password := func(c *fakeCtr) {
		for _, e := range flagValues(c.Argv, "-e") {
			if v, ok := strings.CutPrefix(e, "POSTGRES_PASSWORD="); ok {
				if strings.Contains(label(c.Argv), v) {
					t.Fatal("the password is in the label")
				}
				pws = append(pws, v)
			}
		}
	}
	password(f.ctrs["sp-cp-db"])
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
			password(c)
			if label(c.Argv) != conf {
				t.Fatalf("%s re-created with label %q, want %q", name, label(c.Argv), conf)
			}
		}
	}
	// The password is random per run and stays out of the hash.
	if len(pws) < 3 || pws[0] == pws[1] || pws[1] == pws[2] {
		t.Fatalf("passwords %q: want distinct random values over the re-creations", pws)
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
			Nets: map[string]string{"proj-" + s.Ref: "10.213.3.140"}})
	}, true)
}

// The seccomp profile a platform container was created with is part of its
// configuration: a different profile on disk (a re-pin) re-creates it.
func TestPlatformContainers_SeccompProfileInLabel(t *testing.T) {
	a, f, s := newTestAgent(t)
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
	for _, f := range []string{".Id", ".Name", ".HostConfig.NetworkMode"} {
		if !strings.Contains(modeFormat, "{{json "+f+"}}") {
			t.Errorf("modeFormat lacks %s", f)
		}
	}
}

// A different argument gives a different label: here the image.
func TestEnsureControlPlaneDB_OtherArgumentOtherLabel(t *testing.T) {
	a, f, _ := newTestAgent(t)
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
	extra, err := fileDigests(a.seccompFile(), filepath.Join(etc, "pg_hba.conf"), filepath.Join(etc, "pg_ident.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return extra
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
	f.mu.Lock()
	c := f.ctrs[name]
	id := c.ID
	c.ID = "ep-" + strings.Repeat("7e", 32)
	f.mu.Unlock()
	n := 0
	f.before = func(args []string) {
		if flagValue(args, "--format") == "{{json .Containers}}" && args[len(args)-1] == platformNet {
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
