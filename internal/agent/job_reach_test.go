//go:build reach

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// Job containers on a bare node with the object-store stand-in, as root.
// The test binary is the job's program: started as /supapaced with
// SUPAPACE_JOBPROBE in its environment it acts as one of the probes below
// instead of running tests.
//
//	hold    print nothing; on the stop signal print a result line, exit 0
//	dial    dial each address of SUPAPACE_JOBPROBE_DIAL (3 s each), look a
//	        name up, print the outcomes as one line; with
//	        SUPAPACE_JOBPROBE_HOLD=1 then wait for the stop signal
//	line    (after SUPAPACE_JOBPROBE_SLEEP seconds) print a result line, exit 0
//	listen  accept TCP connections on port 7075 for ever
func init() {
	mode := os.Getenv("SUPAPACE_JOBPROBE")
	if mode == "" {
		return
	}
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	switch mode {
	case "hold":
		<-term
		fmt.Println(`{"ok":true,"stopped":true}`)
	case "line":
		if s, _ := strconv.Atoi(os.Getenv("SUPAPACE_JOBPROBE_SLEEP")); s > 0 {
			time.Sleep(time.Duration(s) * time.Second)
		}
		fmt.Println(`{"ok":true}`)
	case "dial":
		out := map[string]string{}
		for _, a := range strings.Split(os.Getenv("SUPAPACE_JOBPROBE_DIAL"), ",") {
			if c, err := net.DialTimeout("tcp", a, 3*time.Second); err == nil {
				c.Close()
				out[a] = "connected"
			} else {
				out[a] = "failed"
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if _, err := net.DefaultResolver.LookupHost(ctx, "jobprobe.example"); err == nil {
			out["dns"] = "answered"
		} else if de, ok := err.(*net.DNSError); ok && de.IsNotFound {
			out["dns"] = "answered" // an answer, if a negative one
		} else {
			out["dns"] = "no answer"
		}
		cancel()
		b, _ := json.Marshal(map[string]any{"ok": true, "dial": out})
		fmt.Println(string(b))
		if os.Getenv("SUPAPACE_JOBPROBE_HOLD") == "1" {
			<-term
		}
	case "listen":
		ln, err := net.Listen("tcp", ":7075")
		if err != nil {
			os.Exit(3)
		}
		for {
			if c, err := ln.Accept(); err == nil {
				c.Close()
			}
		}
	}
	os.Exit(0)
}

const reachRef = "jobreach000000000001"

type reachNode struct {
	a     *Agent
	p     nodecfg.Paths
	c     nodecfg.Config
	s     Spec
	exe   string
	addrs []string // the stand-in's two addresses
	port  string   // its endpoint's port
}

// jobNode prepares a temporary root with every mount source of a project,
// the seccomp profile, and an agent on it.
func jobNode(t *testing.T, root string) *reachNode {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("the job containers' node proof runs as root on a bare node")
	}
	n := &reachNode{c: nodecfg.Default("sp.test"), p: nodecfg.Paths{Root: root}}
	n.s = Spec{Ref: reachRef, UID: 700005, GID: 700005, SubnetIndex: 2}
	n.a = New(n.c, n.p)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	n.exe = exe
	mk := func(path string, mode os.FileMode, uid, gid int) {
		if err := os.MkdirAll(path, mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(path, mode)
		if err := os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	mk(n.p.PlatformDir(), 0o755, 0, 0)
	if err := os.WriteFile(n.a.seccompFile(), seccompProfile, 0o644); err != nil {
		t.Fatal(err)
	}
	pd := n.p.ProjectDir(reachRef)
	mk(pd, 0o755, 0, 0)
	for _, d := range []string{"data", "sock", "spool", "rspool"} {
		mk(filepath.Join(pd, d), 0o700, n.s.UID, n.s.GID)
	}
	mk(n.p.RepoDir(reachRef), 0o755, 0, 0)
	mk(filepath.Join(n.p.RepoDir(reachRef), "repo"), 0o750, n.s.UID, n.s.GID)
	mk(filepath.Dir(n.p.IndexFile(reachRef)), 0o700, 0, 0)
	if err := os.WriteFile(n.p.IndexFile(reachRef), nil, 0o444); err != nil {
		t.Fatal(err)
	}
	mk(filepath.Dir(n.p.NftFile()), 0o700, 0, 0)
	if b, err := os.ReadFile("/var/lib/sp/s3/addrs"); err == nil {
		n.addrs = strings.Fields(string(b))
		e, _ := os.ReadFile("/var/lib/sp/s3/endpoint")
		u, _ := url.Parse(strings.TrimSpace(string(e)))
		n.port = u.Port()
	}
	return n
}

func (n *reachNode) job(t *testing.T, kind string, id int64, env map[string]string) JobSpec {
	t.Helper()
	in := jobio.Input{Job: id, Kind: kind, Subject: reachRef, Stanza: reachRef + "-1", UID: n.s.UID, Timelines: []uint32{1}}
	j := JobSpec{ID: id, Subject: reachRef, Kind: kind, UID: n.s.UID, GID: n.s.GID, Deadline: 5 * time.Minute, Env: env}
	switch kind {
	case "push", "restore":
		j.SecretEnv = map[string]string{passName: "a-passphrase-for-the-node-proof"}
	case "replicate":
		j.Cred = []byte("AKIDNODEPROOF000\nnot-a-real-secret-key-0123456789")
		in.Repl = &jobio.ReplInput{Mode: "copy", InfoSHA256: map[string]string{}}
	}
	b, err := jobio.MarshalInput(in)
	if err != nil {
		t.Fatal(err)
	}
	j.Input = b
	return j
}

// started waits until name runs and returns its pid.
func started(t *testing.T, name string) int {
	t.Helper()
	for end := time.Now().Add(90 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		out, err := exec.Command("docker", "inspect", "--format", "{{.State.Running}} {{.State.Pid}}", "--", name).Output()
		if f := strings.Fields(string(out)); err == nil && len(f) == 2 && f[0] == "true" {
			pid, _ := strconv.Atoi(f[1])
			return pid
		}
	}
	t.Fatalf("%s did not start within 90 s", name)
	return 0
}

// status is /proc/<pid>/status as field → value.
func status(t *testing.T, pid int) map[string]string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(l, ":")
		m[k] = strings.Join(strings.Fields(v), " ")
	}
	return m
}

type inspected struct {
	Config struct {
		User string
		Env  []string
	}
	HostConfig struct {
		NetworkMode    string
		ReadonlyRootfs bool
		Sysctls        map[string]string
		Dns            []string
		CapDrop        []string
		SecurityOpt    []string
		PidsLimit      int64
		Memory         int64
		GroupAdd       []string
	}
	Mounts []struct {
		Source, Destination string
		RW                  bool
	}
}

func inspectCtr(t *testing.T, name string) inspected {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "--type", "container", "--", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	var v []inspected
	if err := json.Unmarshal(out, &v); err != nil || len(v) != 1 {
		t.Fatalf("inspect %s: %v", name, err)
	}
	return v[0]
}

// mounts is "source:destination:rw|ro", sorted.
func (i inspected) mounts() []string {
	var out []string
	for _, m := range i.Mounts {
		rw := "ro"
		if m.RW {
			rw = "rw"
		}
		out = append(out, m.Source+":"+m.Destination+":"+rw)
	}
	slices.Sort(out)
	return out
}

// checkProcess asserts what every job's process is: no capability in any
// set, no new privileges, the seccomp filter.
func checkProcess(t *testing.T, name string, st map[string]string, uid, gid string, groups string) {
	t.Helper()
	t.Logf("%s: Uid %s Gid %s Groups %q CapInh %s CapPrm %s CapEff %s CapBnd %s CapAmb %s NoNewPrivs %s Seccomp %s", name,
		st["Uid"], st["Gid"], st["Groups"], st["CapInh"], st["CapPrm"], st["CapEff"], st["CapBnd"], st["CapAmb"], st["NoNewPrivs"], st["Seccomp"])
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if st[k] != "0000000000000000" {
			t.Errorf("%s: %s %s", name, k, st[k])
		}
	}
	if st["NoNewPrivs"] != "1" || st["Seccomp"] != "2" {
		t.Errorf("%s: NoNewPrivs %s Seccomp %s", name, st["NoNewPrivs"], st["Seccomp"])
	}
	if st["Uid"] != strings.Repeat(uid+" ", 3)+uid || st["Gid"] != strings.Repeat(gid+" ", 3)+gid || st["Groups"] != groups {
		t.Errorf("%s: Uid %q Gid %q Groups %q", name, st["Uid"], st["Gid"], st["Groups"])
	}
}

// counter reads the packets of the rule commented c in table ip sptest.
func counter(t *testing.T, c string) int {
	t.Helper()
	out, err := exec.Command("nft", "list", "table", "ip", "sptest").Output()
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`packets (\d+) bytes \d+ comment "` + c + `"`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("no counter %s in %s", c, out)
	}
	v, _ := strconv.Atoi(string(m[1]))
	return v
}

func nftRun(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
		t.Fatalf("nft %q: %v: %s", args, err, out)
	}
}

// dialFromNode dials addr from the node's root namespace.
func dialFromNode(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err == nil {
		c.Close()
	}
	return err == nil
}

func TestJobReach_PushAndReplicateFromOutside(t *testing.T) {
	n := jobNode(t, t.TempDir())
	if len(n.addrs) != 2 || n.port == "" {
		t.Fatal("no object-store stand-in on this node (/var/lib/sp/s3)")
	}
	ctx := context.Background()
	t.Cleanup(func() { n.a.KillJobs(context.Background(), "") })

	// ── push: no network, the spool and the repository ──
	pctx, stop := context.WithCancel(ctx)
	type ran struct {
		res JobResult
		err error
	}
	done := make(chan ran, 1)
	go func() {
		r, err := n.a.RunJob(pctx, n.job(t, "push", 1, map[string]string{"SUPAPACE_JOBPROBE": "hold"}))
		done <- ran{r, err}
	}()
	name := "job-" + reachRef + "-push"
	st := status(t, started(t, name))
	checkProcess(t, name, st, "700005", "700005", "700005")
	in := inspectCtr(t, name)
	pd, rd, jd := n.p.ProjectDir(reachRef), n.p.RepoDir(reachRef), n.p.JobsDir()
	want := []string{pd + "/spool:/spool:rw", rd + "/repo:/repo:rw", n.exe + ":/supapaced:ro", jd + "/1:/job:ro"}
	slices.Sort(want)
	t.Logf("%s: user %s network %s read-only %v sysctls %v dns %v mounts %q", name, in.Config.User, in.HostConfig.NetworkMode,
		in.HostConfig.ReadonlyRootfs, in.HostConfig.Sysctls, in.HostConfig.Dns, in.mounts())
	if in.HostConfig.NetworkMode != "none" || !in.HostConfig.ReadonlyRootfs || len(in.HostConfig.Sysctls) != 0 || !slices.Equal(in.mounts(), want) {
		t.Errorf("%s: %+v", name, in)
	}
	if _, err := os.Lstat(jd + "/1.env"); !os.IsNotExist(err) {
		t.Errorf("the environment file exists while the job runs: %v", err)
	}
	pass := slices.ContainsFunc(in.Config.Env, func(e string) bool { return strings.HasPrefix(e, passName+"=") })
	t.Logf("%s: the passphrase is in Docker's root-only record of the container: %v", name, pass)
	stop()
	r := <-done
	if r.err != nil || string(r.res.Result) != `{"ok":true,"stopped":true}` || r.res.TimedOut {
		t.Fatalf("push stopped: %q %v", r.res.Result, r.err)
	}
	if out, _ := exec.Command("docker", "ps", "-a", "-q", "--filter", "name="+name).Output(); len(out) != 0 {
		t.Fatalf("%s left", name)
	}

	// Another project's network with a listener on it.
	other := Spec{Ref: "jobreach000000000002", SubnetIndex: 3}
	if err := n.a.EnsureNetwork(ctx, other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { exec.Command("docker", "network", "rm", "proj-"+other.Ref).Run() })
	peer := n.c.ClusterAddr(3).String() + ":7075"
	worker := func(name string, args ...string) *exec.Cmd {
		return exec.Command("docker", slices.Concat([]string{"run", "--name", name, "--label", "supapace.test=1", "--network", "proj-" + other.Ref},
			args, []string{"-v", n.exe + ":/supapaced:ro", "--entrypoint", "/supapaced", nodecfg.WorkerImage})...)
	}
	if out, err := worker("sp-test-wp75-listen", "-d", "--ip", n.c.ClusterAddr(3).String(), "-e", "SUPAPACE_JOBPROBE=listen").CombinedOutput(); err != nil {
		t.Fatalf("listener: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "sp-test-wp75-listen").Run() })
	// Control, before the ruleset is loaded: a member of that network reaches it.
	out, err := worker("sp-test-wp75-peer", "--rm", "-e", "SUPAPACE_JOBPROBE=dial", "-e", "SUPAPACE_JOBPROBE_DIAL="+peer).Output()
	if err != nil || !strings.Contains(string(out), `"`+peer+`":"connected"`) {
		t.Fatalf("control: a member of the project network does not reach its peer: %v %s", err, out)
	}

	// ── replicate: the backup network, the declared address only ──
	declared := netip.MustParseAddrPort(n.addrs[0] + ":" + n.port)
	if err := nft.InstallSet(ctx, n.p, n.c, []netip.AddrPort{declared}); err != nil {
		t.Fatalf("InstallSet: %v", err)
	}
	t.Cleanup(func() {
		exec.Command("nft", "delete", "table", "inet", "supapace").Run()
		exec.Command("nft", "delete", "table", "bridge", "supapace").Run()
	})
	if err := n.a.EnsureBackupNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { exec.Command("docker", "network", "rm", "backup").Run() })
	// A listener of the node's own, on every address of its root namespace.
	ln, err := net.Listen("tcp", ":7076")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	// The stand-in's other ports: the first the node itself reaches.
	otherPort := ""
	for _, p := range []string{"8333", "9333", "8888"} {
		if dialFromNode(n.addrs[0] + ":" + p) {
			otherPort = n.addrs[0] + ":" + p
			break
		}
	}
	lab := func() string { // the node's own address on the stand-in's first network
		out, _ := exec.Command("ip", "-4", "-o", "route", "get", n.addrs[0]).Output()
		f := strings.Fields(string(out))
		if i := slices.Index(f, "src"); i >= 0 && i+1 < len(f) {
			return f[i+1]
		}
		return ""
	}()
	gw := netip.MustParsePrefix(n.c.BackupSubnet).Addr().Next().String()
	targets := map[string]string{
		declared.String():         "connected", // the declared address and port
		n.addrs[1] + ":" + n.port: "failed",    // the stand-in's other address, not declared
		otherPort:                 "failed",    // another port of the declared address
		gw + ":7076":              "failed",    // the node, at the backup bridge
		lab + ":7076":             "failed",    // the node, at its lab address
		peer:                      "failed",    // another project's network
	}
	// Controls on the same paths: the node reaches each of the node's and
	// the stand-in's; a member of the other project's network reaches its peer.
	for _, a := range []string{n.addrs[1] + ":" + n.port, otherPort, gw + ":7076", lab + ":7076"} {
		if a == ":7076" || strings.HasPrefix(a, ":") || !dialFromNode(a) {
			t.Fatalf("control: the node does not reach %q", a)
		}
	}

	// Lookups toward the node's own resolvers, counted before any address
	// translation, and toward the job's resolver address.
	conf, _ := os.ReadFile("/etc/resolv.conf")
	var ns []string
	for _, l := range strings.Split(string(conf), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "nameserver" {
			ns = append(ns, f[1])
		}
	}
	if len(ns) == 0 {
		t.Fatal("the node has no resolver")
	}
	nftRun(t, "add", "table", "ip", "sptest")
	t.Cleanup(func() { exec.Command("nft", "delete", "table", "ip", "sptest").Run() })
	nftRun(t, "add", "chain", "ip", "sptest", "c_out", "{ type filter hook output priority -300; }")
	nftRun(t, "add", "chain", "ip", "sptest", "c_fwd", "{ type filter hook forward priority -300; }")
	nftRun(t, "add", "chain", "ip", "sptest", "c_pre", "{ type filter hook prerouting priority -300; }")
	set := "{ " + strings.Join(ns, ", ") + " }"
	for _, ch := range []string{"c_out", "c_fwd", "c_pre"} {
		nftRun(t, "add", "rule", "ip", "sptest", ch, "ip", "daddr", set, "meta", "l4proto", "{ tcp, udp }", "th", "dport", "53", "counter", "comment", "resolvers-"+ch[2:])
		nftRun(t, "add", "rule", "ip", "sptest", ch, "ip", "daddr", jobDNS, "meta", "l4proto", "{ tcp, udp }", "th", "dport", "53", "counter", "comment", "jobdns-"+ch[2:])
	}
	resolved := func() int {
		return counter(t, "resolvers-out") + counter(t, "resolvers-fwd") + counter(t, "resolvers-pre")
	}

	var dial []string
	for a := range targets {
		dial = append(dial, a)
	}
	rctx, rstop := context.WithCancel(ctx)
	before := resolved()
	go func() {
		r, err := n.a.RunJob(rctx, n.job(t, "replicate", 2, map[string]string{"SUPAPACE_JOBPROBE": "dial",
			"SUPAPACE_JOBPROBE_DIAL": strings.Join(dial, ","), "SUPAPACE_JOBPROBE_HOLD": "1"}))
		done <- ran{r, err}
	}()
	name = "job-" + reachRef + "-replicate"
	st = status(t, started(t, name))
	checkProcess(t, name, st, "65530", "65530", "65530 700005")
	in = inspectCtr(t, name)
	want = []string{rd + "/repo:/repo:ro", n.p.IndexFile(reachRef) + ":/index:ro", jd + "/2.cred:/cred:ro", n.exe + ":/supapaced:ro", jd + "/2:/job:ro"}
	slices.Sort(want)
	t.Logf("%s: user %s groups %v network %s read-only %v sysctls %v dns %v mounts %q", name, in.Config.User, in.HostConfig.GroupAdd,
		in.HostConfig.NetworkMode, in.HostConfig.ReadonlyRootfs, in.HostConfig.Sysctls, in.HostConfig.Dns, in.mounts())
	if in.HostConfig.NetworkMode != nodecfg.BackupNetwork || !in.HostConfig.ReadonlyRootfs || !slices.Equal(in.HostConfig.Dns, []string{jobDNS}) ||
		in.HostConfig.Sysctls["net.ipv6.conf.all.disable_ipv6"] != "1" || in.HostConfig.Sysctls["net.ipv4.ping_group_range"] != "1 0" ||
		!slices.Equal(in.mounts(), want) {
		t.Errorf("%s: %+v", name, in)
	}
	for _, e := range in.Config.Env {
		if strings.Contains(e, "not-a-real-secret-key") || strings.Contains(e, "AKIDNODEPROOF") {
			t.Errorf("a key in the job's environment: %q", e)
		}
	}
	if _, err := os.Lstat(jd + "/2.env"); !os.IsNotExist(err) {
		t.Errorf("the environment file exists while the job runs: %v", err)
	}
	if fi, err := os.Lstat(jd + "/2.cred"); err != nil || fi.Mode().Perm() != 0o400 || fi.Sys().(*syscall.Stat_t).Uid != 65530 {
		t.Errorf("the credential file while the job runs: %v %v", fi, err)
	}
	// The result line is written once the dials are done; then stop it.
	var res struct{ Dial map[string]string }
	for end := time.Now().Add(120 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		logs, _ := exec.Command("docker", "logs", "--", name).Output()
		if json.Unmarshal(logs, &res) == nil {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("no dial result within 120 s: %s", logs)
		}
	}
	rstop()
	if r := <-done; r.err != nil || len(r.res.Result) == 0 {
		t.Fatalf("replicate stopped: %q %v", r.res.Result, r.err)
	}
	t.Logf("from inside the replication job: %v", res.Dial)
	for a, w := range targets {
		if res.Dial[a] != w {
			t.Errorf("job -> %s: %s, want %s", a, res.Dial[a], w)
		}
	}
	if _, err := os.Lstat(jd + "/2.cred"); !os.IsNotExist(err) {
		t.Errorf("the credential file outlived the container: %v", err)
	}
	afterJob := resolved()
	t.Logf("lookup with the job's resolver: %s; packets toward the node's resolvers %d -> %d; toward %s %d",
		res.Dial["dns"], before, afterJob, jobDNS, counter(t, "jobdns-out")+counter(t, "jobdns-fwd")+counter(t, "jobdns-pre"))
	if res.Dial["dns"] != "no answer" || afterJob != before {
		t.Errorf("a lookup inside the job: %s, %d packets toward the node's resolvers", res.Dial["dns"], afterJob-before)
	}

	// Control: the same job without --dns reaches the node's resolvers.
	x, err := n.a.checkJob(n.job(t, "replicate", 3, map[string]string{"SUPAPACE_JOBPROBE": "dial", "SUPAPACE_JOBPROBE_DIAL": declared.String()}))
	if err != nil {
		t.Fatal(err)
	}
	_, vs := n.a.sources(x, n.exe)
	env, err := n.a.writeJobFiles(x)
	if err != nil {
		t.Fatal(err)
	}
	args := n.a.jobArgs(x, env, vs)
	i := slices.Index(args, "--dns")
	args = slices.Delete(args, i, i+2)
	args[slices.Index(args, x.name)] = "sp-test-wp75-nodns"
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("control run: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "sp-test-wp75-nodns").Run() })
	var cres struct{ Dial map[string]string }
	for end := time.Now().Add(60 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		logs, _ := exec.Command("docker", "logs", "--", "sp-test-wp75-nodns").Output()
		if json.Unmarshal(logs, &cres) == nil {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("control: no result within 60 s: %s", logs)
		}
	}
	t.Logf("control without --dns: lookup %s; packets toward the node's resolvers %d -> %d", cres.Dial["dns"], afterJob, resolved())
	if resolved() == afterJob {
		t.Error("control: the job without --dns sent nothing toward the node's resolvers")
	}
}

// TestJobReach_Launcher is the launcher a test kills: it runs a held push
// job under the root SUPAPACE_JOBREACH_ROOT names.
func TestJobReach_Launcher(t *testing.T) {
	root := os.Getenv("SUPAPACE_JOBREACH_ROOT")
	if root == "" {
		t.Skip("run by TestJobReach_LeftoverOfAKilledLauncherRemovedFirst")
	}
	n := jobNode(t, root)
	n.a.RunJob(context.Background(), n.job(t, "push", 5, map[string]string{"SUPAPACE_JOBPROBE": "hold"}))
}

func TestJobReach_LeftoverOfAKilledLauncherRemovedFirst(t *testing.T) {
	root := t.TempDir()
	n := jobNode(t, root)
	t.Cleanup(func() { n.a.KillJobs(context.Background(), "") })
	cmd := exec.Command(os.Args[0], "-test.run=^TestJobReach_Launcher$", "-test.v")
	cmd.Env = append(os.Environ(), "SUPAPACE_JOBREACH_ROOT="+root)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	left := "job-" + reachRef + "-push"
	started(t, left)
	cmd.Process.Kill()
	cmd.Wait()
	if out, _ := exec.Command("docker", "inspect", "--format", "{{.State.Running}}", "--", left).Output(); strings.TrimSpace(string(out)) != "true" {
		t.Fatalf("control: the leftover is not running after its launcher was killed: %q", out)
	}
	if _, err := os.Lstat(filepath.Join(n.p.JobsDir(), "5")); err != nil {
		t.Fatalf("control: the leftover's job directory: %v", err)
	}
	// The subject's next job, of another kind: the leftover is gone before it starts.
	inner := dockerRun
	var atRun []string
	dockerRun = func(ctx context.Context, args ...string) (string, error) {
		if args[0] == "run" {
			out, _ := exec.Command("docker", "ps", "-a", "--format", "{{.Names}}", "--filter", "label=supapace.ref="+reachRef).Output()
			atRun = strings.Fields(string(out))
		}
		return inner(ctx, args...)
	}
	defer func() { dockerRun = inner }()
	r, err := n.a.RunJob(context.Background(), n.job(t, "restore", 6, map[string]string{"SUPAPACE_JOBPROBE": "line"}))
	if err != nil || string(r.Result) != `{"ok":true}` {
		t.Fatalf("restore: %q %v", r.Result, err)
	}
	t.Logf("the subject's job containers when the restore was started: %q", atRun)
	if len(atRun) != 0 {
		t.Fatalf("started beside %q", atRun)
	}
	if _, err := os.Lstat(filepath.Join(n.p.JobsDir(), "5")); !os.IsNotExist(err) {
		t.Fatalf("the leftover's job directory stays: %v", err)
	}
}

// Jobs longer than the bound of the calls after a job: one that ends by
// itself after 90 s keeps its result; one stopped after 95 s ends by the stop
// signal (it prints its line on the signal only), not by a kill.
func TestJobReach_JobsLongerThanTheCleanupBound(t *testing.T) {
	n := jobNode(t, t.TempDir())
	t.Cleanup(func() { n.a.KillJobs(context.Background(), "") })
	t0 := time.Now()
	r, err := n.a.RunJob(context.Background(), n.job(t, "restore", 1, map[string]string{"SUPAPACE_JOBPROBE": "line", "SUPAPACE_JOBPROBE_SLEEP": "90"}))
	t.Logf("a job of %v: result %q, exit %d, err %v", time.Since(t0).Round(time.Second), r.Result, r.ExitCode, err)
	if err != nil || string(r.Result) != `{"ok":true}` || time.Since(t0) < jobCleanup+20*time.Second {
		t.Fatalf("long job: %q %v", r.Result, err)
	}
	ctx, stop := context.WithCancel(context.Background())
	time.AfterFunc(95*time.Second, stop)
	t0 = time.Now()
	r, err = n.a.RunJob(ctx, n.job(t, "push", 2, map[string]string{"SUPAPACE_JOBPROBE": "hold"}))
	t.Logf("a held job stopped after %v: result %q, exit %d, err %v", time.Since(t0).Round(time.Second), r.Result, r.ExitCode, err)
	if err != nil || string(r.Result) != `{"ok":true,"stopped":true}` || r.ExitCode != 0 || r.TimedOut {
		t.Fatalf("stopped long job: %q exit %d %v", r.Result, r.ExitCode, err)
	}
}

// The node's daemon binary (installed root-owned by the harness) is
// accepted as the job's executable, and the real program runs; a copy of it
// owned by another uid is refused before anything is launched.
func TestJobReach_TheDaemonsExecutableAndItsOwner(t *testing.T) {
	const real = "/opt/supapace/bin/supapaced"
	n := jobNode(t, t.TempDir())
	t.Cleanup(func() { n.a.KillJobs(context.Background(), "") })
	inner := daemonExe
	t.Cleanup(func() { daemonExe = inner })
	fi, err := os.Lstat(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: %v uid %d", real, fi.Mode(), fi.Sys().(*syscall.Stat_t).Uid)
	daemonExe = func() (string, error) { return real, nil }
	r, err := n.a.RunJob(context.Background(), n.job(t, "push", 1, nil))
	t.Logf("the real push with an empty spool: exit %d, result %s, err %v", r.ExitCode, r.Result, err)
	if err != nil || len(r.Result) == 0 {
		t.Fatalf("the real program: %v", err)
	}
	if _, _, perr := jobio.ParseResult("push", r.Result); perr != nil {
		t.Fatalf("its result: %v", perr)
	}
	other := filepath.Join(t.TempDir(), "supapaced")
	b, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(other, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	daemonExe = func() (string, error) { return other, nil }
	_, err = n.a.RunJob(context.Background(), n.job(t, "push", 2, nil))
	t.Logf("a daemon binary owned by 1000:1000: %v", err)
	if !errors.Is(err, ErrHostState) {
		t.Fatalf("not refused: %v", err)
	}
	if out, _ := exec.Command("docker", "ps", "-a", "-q", "--filter", "label=supapace.ref="+reachRef).Output(); len(out) != 0 {
		t.Fatal("a container was made")
	}
}
