package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nft"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
)

// TestMain runs the package's tests under the daemon's umask (0077), so a
// file or directory that relies on the umask for its mode shows up.
func TestMain(m *testing.M) {
	syscall.Umask(0o077)
	os.Exit(m.Run())
}

// ───────── the recording fake ─────────

// fakeHost replaces every seam of agent.go (Docker, ip, nft, nodefs, chown)
// for one test. It records each call as one line in log, keeps a small model
// of containers and networks that the Docker verbs this package and its
// callers use act on, and answers the inspect calls from that model. Tests of
// later files in this package reuse it: script answers with onRun, fail a
// verb with failVerb or an inspect with failInspect, read the log with
// calls/argv/mutations (resetLog clears it), and arrange state with ctr/net.
// Container ids and pids are never reused: run and start give a running
// container a new pid, stop and kill clear it, as Docker does.
type fakeHost struct {
	t  testing.TB
	mu sync.Mutex

	log      []string
	dargs    [][]string // the argv of every dockerRun/dockerRunInput call, in order
	seq      int        // source of container ids and pids, never reused
	ctrs     map[string]*fakeCtr
	nets     map[string]*fakeNet
	ip       map[string]string // "ip <args>" → stdout; a missing key fails like an absent device
	version  string
	info     string // `docker info --format {{json .}}`
	writes   map[string]fakeWrite
	nftErr   error
	bnfErr   error
	failVerb map[string]error // docker verb ("start", "network create", …) → error returned instead of acting
	// failInspect: object name → error returned by dockerInspectContainer or
	// dockerInspectNetwork for that name.
	failInspect map[string]error
	// images: image reference → the id it resolves to (`image inspect`).
	images map[string]string

	// onRun, when set, is asked first about every dockerRun/dockerRunInput
	// call; handled=false falls through to the model.
	onRun func(args []string, stdin []byte) (out string, err error, handled bool)
	// before, when set, runs before every docker call is handled (outside the
	// lock), e.g. to hold calls until all of a parallel batch have arrived.
	before func(args []string)
}

type fakeCtr struct {
	Name, ID, Image string
	Running         bool
	Pid             int
	Restart         string
	Privileged      bool
	CapAdd, CapDrop []string
	Labels          map[string]string
	Nets            map[string]string // network → configured address
	NetMode         string            // HostConfig.NetworkMode; "" reads as Docker's default, "bridge"
	Argv            []string          // the create/run argv that made it
}

type fakeNet struct {
	dockerx.Network
	Driver  string
	IPRange string
	IPv6    bool // EnableIPv6
}

type fakeWrite struct {
	Mode     os.FileMode
	UID, GID int
	Data     []byte
}

// fakeDocker installs a fake host for the test; the seams are restored at
// cleanup.
func fakeDocker(t testing.TB) *fakeHost {
	f := &fakeHost{t: t, ctrs: map[string]*fakeCtr{}, nets: map[string]*fakeNet{}, ip: map[string]string{},
		writes: map[string]fakeWrite{}, failVerb: map[string]error{}, failInspect: map[string]error{}, version: "29.10.0",
		images: map[string]string{nodecfg.GatewayImage: "sha256:" + strings.Repeat("1", 64)}}
	for _, n := range []struct{ name, driver string }{{"bridge", "bridge"}, {"host", "host"}, {"none", "null"}} {
		f.nets[n.name] = &fakeNet{Network: dockerx.Network{Name: n.name, BridgeName: "docker0", Options: map[string]string{}}, Driver: n.driver}
	}
	saved := []func(){
		swap(&dockerRun, func(ctx context.Context, args ...string) (string, error) { return f.run(args, nil) }),
		swap(&dockerRunInput, func(ctx context.Context, in []byte, args ...string) (string, error) { return f.run(args, in) }),
		swap(&dockerInspectContainer, f.inspectContainer),
		swap(&dockerInspectNetwork, f.inspectNetwork),
		swap(&dockerListContainers, f.listContainers),
		swap(&dockerServerVersion, func(context.Context) (string, error) {
			f.record("docker version")
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.version, f.failVerb["version"]
		}),
		swap(&runIP, f.runIP),
		swap(&nftCheck, func(context.Context, nodecfg.Paths) error { f.record("nft check"); return f.nftErr }),
		swap(&ensureBridgeNF, func() error { f.record("bridge-nf"); return f.bnfErr }),
		swap(&createProjectDir, func(p nodecfg.Paths, ref string, uid, gid, mb int) error {
			f.record(fmt.Sprintf("createProjectDir %s %d:%d %d", ref, uid, gid, mb))
			return nil
		}),
		swap(&setQuota, func(p nodecfg.Paths, uid, mb int) error { f.record(fmt.Sprintf("setQuota %d %d", uid, mb)); return nil }),
		swap(&writeFile, f.writeFile),
		swap(&chown, func(path string, uid, gid int) error {
			f.record(fmt.Sprintf("chown %s %d:%d", path, uid, gid))
			return nil
		}),
	}
	t.Cleanup(func() {
		for _, restore := range saved {
			restore()
		}
	})
	return f
}

func swap[T any](v *T, fake T) func() {
	old := *v
	*v = fake
	return func() { *v = old }
}

func (f *fakeHost) record(s string) {
	f.mu.Lock()
	f.log = append(f.log, s)
	f.mu.Unlock()
}

// calls returns a copy of the log.
func (f *fakeHost) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.log)
}

// argv returns the argument lists of the docker calls whose arguments start
// with prefix, in order, exactly as passed (an argument may hold spaces).
func (f *fakeHost) argv(prefix ...string) [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]string
	for _, args := range f.dargs {
		if len(args) >= len(prefix) && slices.Equal(args[:len(prefix)], prefix) {
			out = append(out, slices.Clone(args))
		}
	}
	return out
}

// resetLog forgets the calls recorded so far.
func (f *fakeHost) resetLog() {
	f.mu.Lock()
	f.log, f.dargs = nil, nil
	f.mu.Unlock()
}

// mutations returns the docker calls that change something.
func (f *fakeHost) mutations() []string {
	var out []string
	for _, c := range f.calls() {
		a, ok := strings.CutPrefix(c, "docker ")
		if !ok {
			continue
		}
		for _, v := range []string{"create ", "run ", "start ", "stop ", "kill ", "rm ", "network create ", "network rm ",
			"network connect ", "network disconnect "} {
			if strings.HasPrefix(a, v) {
				out = append(out, c)
			}
		}
	}
	return out
}

// nextSeq returns a number never handed out before; f.mu is held.
func (f *fakeHost) nextSeq() int {
	f.seq++
	return f.seq
}

// recordShare records "container:<name>" as Docker does, with the full id
// of the container it names; f.mu is held.
func (f *fakeHost) recordShare(c *fakeCtr) {
	if target, ok := strings.CutPrefix(c.NetMode, "container:"); ok {
		if t, found := f.resolve(target); found {
			c.NetMode = "container:" + t.ID
		}
	}
}

// ctr adds or replaces a container in the state given; a running one without
// a pid gets a fresh one.
func (f *fakeHost) ctr(c fakeCtr) *fakeCtr {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c.ID == "" {
		c.ID = fmt.Sprintf("%064x", f.nextSeq())
	}
	f.recordShare(&c)
	if c.Running && c.Pid == 0 {
		c.Pid = 1000 + f.nextSeq()
	}
	if c.Labels == nil {
		c.Labels = map[string]string{}
	}
	if c.Nets == nil {
		c.Nets = map[string]string{}
	}
	if c.Restart == "" {
		c.Restart = "no"
	}
	f.ctrs[c.Name] = &c
	return &c
}

func (f *fakeHost) net(n fakeNet) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n.Options == nil {
		n.Options = map[string]string{}
	}
	if n.Driver == "" {
		n.Driver = "bridge"
	}
	f.nets[n.Name] = &n
}

func (f *fakeHost) inspectContainer(ctx context.Context, name string) (*dockerx.Container, error) {
	f.record("inspect container " + name)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failInspect[name]; err != nil {
		return nil, err
	}
	c, ok := f.resolve(name)
	if !ok {
		return nil, nil
	}
	return c.typed(), nil
}

// resolve finds a container as Docker does: a full id first, then a name;
// f.mu is held.
func (f *fakeHost) resolve(ref string) (*fakeCtr, bool) {
	for _, x := range f.ctrs {
		if x.ID == ref {
			return x, true
		}
	}
	c, ok := f.ctrs[ref]
	return c, ok
}

func (c *fakeCtr) typed() *dockerx.Container {
	d := &dockerx.Container{ID: c.ID, Name: c.Name, Image: c.Image, Running: c.Running, RestartPolicy: c.Restart,
		Labels: map[string]string{}, IPs: map[string]string{}}
	for k, v := range c.Labels {
		d.Labels[k] = v
	}
	if c.Running { // Docker reports addresses of running containers only
		d.Pid = c.Pid
		for n, a := range c.Nets {
			d.IPs[n] = a
		}
	}
	return d
}

func (f *fakeHost) inspectNetwork(ctx context.Context, name string) (*dockerx.Network, error) {
	f.record("inspect network " + name)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failInspect[name]; err != nil {
		return nil, err
	}
	n, ok := f.nets[name]
	if !ok {
		return nil, nil
	}
	out := n.Network
	out.Options = map[string]string{}
	for k, v := range n.Options {
		out.Options[k] = v
	}
	out.Containers = nil
	for _, c := range f.ctrs { // Docker lists only containers with an endpoint, i.e. running ones
		if _, on := c.Nets[name]; on && c.Running {
			out.Containers = append(out.Containers, c.Name)
		}
	}
	slices.Sort(out.Containers)
	return &out, nil
}

func (f *fakeHost) listContainers(ctx context.Context, label string) ([]dockerx.Container, error) {
	f.record("list " + label)
	f.mu.Lock()
	defer f.mu.Unlock()
	k, v, withValue := strings.Cut(label, "=")
	var out []dockerx.Container
	for _, c := range f.ctrs {
		if have, ok := c.Labels[k]; ok && (!withValue || have == v) {
			out = append(out, *c.typed())
		}
	}
	slices.SortFunc(out, func(a, b dockerx.Container) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (f *fakeHost) runIP(ctx context.Context, args ...string) ([]byte, error) {
	key := strings.Join(args, " ")
	f.record("ip " + key)
	f.mu.Lock()
	defer f.mu.Unlock()
	out, ok := f.ip[key]
	if !ok {
		return nil, errors.New("ip: device does not exist")
	}
	return []byte(out), nil
}

func (f *fakeHost) writeFile(p nodecfg.Paths, dir, name string, data []byte, mode os.FileMode, uid, gid int) error {
	f.record(fmt.Sprintf("write %s %o %d:%d", filepath.Join(dir, name), mode, uid, gid))
	f.mu.Lock()
	f.writes[filepath.Join(dir, name)] = fakeWrite{Mode: mode, UID: uid, GID: gid, Data: slices.Clone(data)}
	f.mu.Unlock()
	// The real write, with the test's own ids (the owner is recorded above).
	return nodefs.WriteFile(p, dir, name, data, mode, os.Geteuid(), os.Getegid())
}

// run is the model behind dockerRun.
func (f *fakeHost) run(args []string, stdin []byte) (string, error) {
	f.record("docker " + strings.Join(args, " "))
	f.mu.Lock()
	f.dargs = append(f.dargs, slices.Clone(args))
	f.mu.Unlock()
	if f.before != nil {
		f.before(args)
	}
	if f.onRun != nil {
		if out, err, ok := f.onRun(args, stdin); ok {
			return out, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	verb := args[0]
	if verb == "network" || verb == "container" || verb == "image" {
		verb += " " + args[1]
	}
	if err := f.failVerb[verb]; err != nil {
		return "", err
	}
	pos := positional(args)
	switch verb {
	case "create", "run":
		c := parseRun(args)
		f.recordShare(c)
		if _, dup := f.ctrs[c.Name]; dup {
			return "", errors.New("docker: name in use")
		}
		c.ID = fmt.Sprintf("%064x", f.nextSeq())
		if verb == "run" {
			c.Running, c.Pid = true, 1000+f.nextSeq()
		}
		f.ctrs[c.Name] = c
		return c.ID + "\n", nil
	case "start", "stop", "kill", "rm":
		// `kill -s SIG` with a signal other than KILL leaves the container running.
		if sig := flagValue(args, "-s"); verb == "kill" && sig != "" && sig != "KILL" && sig != "SIGKILL" && sig != "9" {
			return "", nil
		}
		for _, n := range pos {
			c, ok := f.ctrs[n]
			switch {
			case !ok && verb == "rm" && slices.Contains(args, "-f"):
			case !ok:
				return "", errors.New("docker: no such container")
			case verb == "rm" && c.Running && !slices.Contains(args, "-f"):
				return "", errors.New("docker: cannot remove a running container; stop it first or use -f")
			case verb == "rm":
				delete(f.ctrs, n)
			case verb == "kill" && !c.Running:
				return "", errors.New("docker: container is not running")
			case verb == "start":
				if !c.Running {
					for net, addr := range c.Nets {
						for _, o := range f.ctrs {
							if o != c && o.Running && addr != "" && o.Nets[net] == addr {
								return "", errors.New("docker: failed to set up container networking: Address already in use")
							}
						}
					}
					c.Running, c.Pid = true, 1000+f.nextSeq()
				}
			default:
				c.Running, c.Pid = false, 0
			}
		}
		return "", nil
	case "network create":
		n := parseNetCreate(args)
		f.nets[n.Name] = n
		return "", nil
	case "network rm":
		for _, c := range f.ctrs {
			if _, on := c.Nets[pos[0]]; on && c.Running {
				return "", errors.New("docker: error while removing network: network has active endpoints")
			}
		}
		delete(f.nets, pos[0])
		return "", nil
	case "network connect":
		c, ok := f.ctrs[pos[1]]
		if !ok {
			return "", errors.New("docker: no such container")
		}
		if _, ok := f.nets[pos[0]]; !ok {
			return "", errors.New("docker: network " + pos[0] + " not found")
		}
		if _, on := c.Nets[pos[0]]; on {
			return "", errors.New("docker: endpoint with name " + c.Name + " already exists in network " + pos[0])
		}
		c.Nets[pos[0]] = flagValue(args, "--ip")
		return "", nil
	case "network disconnect":
		if c, ok := f.ctrs[pos[1]]; ok {
			delete(c.Nets, pos[0])
		}
		return "", nil
	case "network ls":
		var b strings.Builder
		for _, name := range sortedKeys(f.nets) {
			fmt.Fprintf(&b, "%s %s\n", name, f.nets[name].Driver)
		}
		return b.String(), nil
	case "network inspect":
		var b strings.Builder
		for _, name := range pos {
			n, ok := f.nets[name]
			if !ok {
				return b.String(), errors.New("docker: network not found")
			}
			switch format := flagValue(args, "--format"); {
			case strings.Contains(format, "IPAM"):
				fmt.Fprintf(&b, `[{"Subnet":%q,"IPRange":%q,"Gateway":"invalid IP"}]`+"\n", n.Subnet, n.IPRange)
			case format == "{{json .Containers}}": // endpoint keys are container ids
				m := map[string]map[string]string{}
				for _, c := range f.ctrs {
					if _, on := c.Nets[name]; on && c.Running {
						m[c.ID] = map[string]string{"Name": c.Name}
					}
				}
				j, _ := json.Marshal(m)
				fmt.Fprintf(&b, "%s\n", j)
			case format == "{{json .EnableIPv6}}":
				fmt.Fprintf(&b, "%t\n", n.IPv6)
			case strings.Contains(format, "enable_icc"): // name and the inter-container option
				fmt.Fprintf(&b, "%s %s\n", name, n.Options["com.docker.network.bridge.enable_icc"])
			default:
				f.t.Errorf("fake docker: network inspect with an unmodelled format %q (script it with onRun)", format)
				return "", errors.New("fake: unmodelled format")
			}
		}
		return b.String(), nil
	case "container inspect":
		format := flagValue(args, "--format")
		if format != confFormat && format != modeFormat {
			f.t.Errorf("fake docker: container inspect with an unmodelled format %q (script it with onRun)", format)
			return "", errors.New("fake: unmodelled format")
		}
		var b strings.Builder
		for _, name := range pos {
			c, ok := f.resolve(name)
			if !ok {
				return b.String(), errors.New("docker: no such container")
			}
			if format == modeFormat {
				fmt.Fprintf(&b, "%q %q %q", c.ID, "/"+c.Name, c.mode())
			} else {
				b.WriteString(c.configJSON())
			}
			b.WriteByte('\n')
		}
		return b.String(), nil
	case "image inspect":
		if flagValue(args, "--format") != "{{json .Id}}" || len(pos) != 1 {
			break
		}
		id, ok := f.images[pos[0]]
		if !ok {
			return "", errors.New("docker: no such image")
		}
		return fmt.Sprintf("%q\n", id), nil
	case "info":
		return f.info, nil
	case "ps":
		if !slices.Equal(args, []string{"ps", "-a", "-q", "--no-trunc"}) {
			break
		}
		var b strings.Builder
		for _, name := range sortedKeys(f.ctrs) {
			fmt.Fprintln(&b, f.ctrs[name].ID)
		}
		return b.String(), nil
	case "cp":
		f.t.Errorf("fake docker: unscripted cp %v", args)
		return "", errors.New("fake: cp not scripted")
	}
	f.t.Errorf("fake docker: unmodelled call %q (script it with onRun)", args)
	return "", errors.New("fake: unmodelled call")
}

func (c *fakeCtr) configJSON() string {
	nets := map[string]any{}
	for n, a := range c.Nets {
		e := map[string]any{"IPAMConfig": nil, "IPAddress": ""}
		if a != "" {
			e["IPAMConfig"] = map[string]string{"IPv4Address": a}
		}
		if c.Running {
			e["IPAddress"] = a
		}
		nets[n] = e
	}
	b, _ := json.Marshal(map[string]any{"id": c.ID, "name": "/" + c.Name, "running": c.Running, "privileged": c.Privileged,
		"cap_add": c.CapAdd, "cap_drop": c.CapDrop, "restart": c.Restart, "netmode": c.mode(), "labels": c.Labels, "networks": nets})
	return string(b)
}

// mode is the network mode Docker records.
func (c *fakeCtr) mode() string {
	if c.NetMode == "" {
		return "bridge"
	}
	return c.NetMode
}

// positional returns the arguments after "--".
func positional(args []string) []string {
	if i := slices.Index(args, "--"); i >= 0 {
		return args[i+1:]
	}
	return nil
}

func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == "--" {
			break
		}
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func flagValues(args []string, name string) []string {
	var out []string
	for i, a := range args {
		if a == "--" {
			break
		}
		if a == name && i+1 < len(args) {
			out = append(out, args[i+1])
		}
	}
	return out
}

func parseRun(args []string) *fakeCtr {
	c := &fakeCtr{Name: flagValue(args, "--name"), Restart: "no", Labels: map[string]string{}, Nets: map[string]string{},
		CapAdd: flagValues(args, "--cap-add"), CapDrop: flagValues(args, "--cap-drop"), Argv: slices.Clone(args),
		Privileged: slices.Contains(args, "--privileged")}
	if r := flagValue(args, "--restart"); r != "" {
		c.Restart = r
	}
	for _, l := range flagValues(args, "--label") {
		k, v, _ := strings.Cut(l, "=")
		c.Labels[k] = v
	}
	switch n := flagValue(args, "--network"); {
	case n == "none" || n == "host" || strings.HasPrefix(n, "container:"):
		c.NetMode = n
	case n != "":
		c.NetMode = n
		c.Nets[n] = flagValue(args, "--ip")
	}
	if pos := positional(args); len(pos) > 0 {
		c.Image = pos[0]
	}
	return c
}

func parseNetCreate(args []string) *fakeNet {
	pos := positional(args)
	n := &fakeNet{Network: dockerx.Network{Name: pos[0], Internal: slices.Contains(args, "--internal"),
		Subnet: flagValue(args, "--subnet"), Options: map[string]string{}}, Driver: "bridge", IPRange: flagValue(args, "--ip-range"),
		IPv6: slices.Contains(args, "--ipv6") || slices.Contains(args, "--ipv6=true")}
	for _, o := range flagValues(args, "-o") {
		k, v, _ := strings.Cut(o, "=")
		n.Options[k] = v
	}
	n.BridgeName = n.Options["com.docker.network.bridge.name"]
	if n.BridgeName == "" {
		n.BridgeName = "br-0123456789ab"
	}
	return n
}

func sortedKeys[V any](m map[string]V) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// ───────── fixtures ─────────

const testRef = "abcdefghij0123456789"

// newTestAgent returns an agent under a temporary root, with the fake
// installed, and a spec for slice 14.
func newTestAgent(t testing.TB) (*Agent, *fakeHost, Spec) {
	t.Helper()
	f := fakeDocker(t)
	root := t.TempDir()
	for _, d := range []string{"etc/supapace", "var/lib", "run/supapace", "proc/sys/kernel/yama", "proc/sys/fs", "sys/module", "etc/docker", "etc/modprobe.d"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	c := nodecfg.Default("sp.test")
	c.Uplinks = []string{"eth0"}
	a := New(c, nodecfg.Paths{Root: root})
	s := Spec{Ref: testRef, Epoch: 1, Generation: 1, UID: 700005, GID: 700005, SubnetIndex: 14, DiskQuotaMB: 8192, MemMB: 512, Pids: 512}
	return a, f, s
}

// healthy arranges a node on which the start gate passes for s: the three
// networks with our options, the project bridge without an address, the
// gateway on platform and ingress, nft verified.
func healthy(a *Agent, f *fakeHost, s Spec) {
	c := a.cfg
	f.net(fakeNet{Network: dockerx.Network{Name: "proj-" + s.Ref, Internal: true, Subnet: c.Slice(s.SubnetIndex).String(),
		BridgeName: nodecfg.BridgeName(s.SubnetIndex), Options: map[string]string{
			"com.docker.network.bridge.name":              nodecfg.BridgeName(s.SubnetIndex),
			"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}}})
	f.net(fakeNet{Network: dockerx.Network{Name: "platform", Internal: true, Subnet: c.PlatformSubnet, BridgeName: "spl0",
		Options: map[string]string{"com.docker.network.bridge.name": "spl0", "com.docker.network.bridge.gateway_mode_ipv4": "isolated"}},
		IPRange: c.PlatformIPRange})
	f.net(fakeNet{Network: dockerx.Network{Name: "ingress", Subnet: c.IngressSubnet, BridgeName: "spi0",
		Options: map[string]string{"com.docker.network.bridge.name": "spi0"}}})
	f.ip["-j -d addr show dev "+nodecfg.BridgeName(s.SubnetIndex)] = bridgeIface(nodecfg.BridgeName(s.SubnetIndex), false)
	f.ip["-j -d addr show dev spl0"] = bridgeIface("spl0", false)
	f.ctr(fakeCtr{Name: "sp-gateway", Running: true, Restart: "unless-stopped", CapDrop: []string{"ALL"},
		Labels: map[string]string{"supapace.role": "gateway"},
		Nets:   map[string]string{"ingress": c.GatewayIngressIP, "platform": c.GatewayIP}})
}

// bridgeIface is `ip -j -d addr show dev NAME` of a bridge, with or without
// an IPv4 address (it always has an IPv6 link-local one).
func bridgeIface(name string, v4 bool) string {
	addrs := `{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}`
	if v4 {
		addrs = `{"family":"inet","local":"10.213.3.129","prefixlen":26,"scope":"global"},` + addrs
	}
	return fmt.Sprintf(`[{"ifindex":7,"ifname":%q,"flags":["BROADCAST","MULTICAST","UP"],"mtu":1500,"linkinfo":{"info_kind":"bridge","info_data":{"stp_state":0}},"addr_info":[%s]}]`, name, addrs)
}

// tenants adds pg-<ref> and postgrest-<ref> as the agent creates them.
func tenants(a *Agent, f *fakeHost, s Spec) (pg, pr *fakeCtr) {
	pg = f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: true, CapDrop: []string{"ALL"},
		Labels: map[string]string{"supapace.role": "cluster", "supapace.ref": s.Ref},
		Nets:   map[string]string{"proj-" + s.Ref: a.cfg.ClusterAddr(s.SubnetIndex).String()}})
	pr = f.ctr(fakeCtr{Name: "postgrest-" + s.Ref, Running: true, CapDrop: []string{"ALL"},
		Labels: map[string]string{"supapace.role": "postgrest", "supapace.ref": s.Ref},
		Nets: map[string]string{"proj-" + s.Ref: a.cfg.PostgRESTAddr(s.SubnetIndex).String(),
			"platform": a.cfg.PlatformAddr(s.SubnetIndex).String()}})
	return pg, pr
}

// mkdirs creates each directory 0755 whatever the umask (nodefs.WriteFile
// refuses a group-writable render directory).
func mkdirs(t testing.TB, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func wantContainment(t testing.TB, err error, what string) {
	t.Helper()
	if !errors.Is(err, ErrContainment) {
		t.Fatalf("%s: got %v, want ErrContainment", what, err)
	}
}

// TestFakeDocker_Model pins the parts of the fake that later tests rely on.
func TestFakeDocker_Model(t *testing.T) {
	f := fakeDocker(t)
	ctx := context.Background()
	if _, err := dockerRun(ctx, "run", "-d", "--name", "x", "--sysctl", "net.ipv4.ping_group_range=1 0", "--", "img"); err != nil {
		t.Fatal(err)
	}
	if got := f.argv("run"); len(got) != 1 || !slices.Contains(got[0], "net.ipv4.ping_group_range=1 0") {
		t.Fatalf("argv split an argument: %q", got)
	}
	first, _ := dockerInspectContainer(ctx, "x")
	if first == nil || !first.Running || first.Pid == 0 {
		t.Fatalf("after run: %+v", first)
	}
	dockerRun(ctx, "kill", "-s", "SIGUSR2", "--", "x")
	if c, _ := dockerInspectContainer(ctx, "x"); !c.Running || c.Pid != first.Pid {
		t.Fatalf("a reload signal stopped the container: %+v", c)
	}
	dockerRun(ctx, "kill", "--", "x")
	if c, _ := dockerInspectContainer(ctx, "x"); c.Running || c.Pid != 0 {
		t.Fatalf("after kill: %+v", c)
	}
	dockerRun(ctx, "start", "--", "x")
	if c, _ := dockerInspectContainer(ctx, "x"); !c.Running || c.Pid == 0 || c.Pid == first.Pid {
		t.Fatalf("after start: %+v, first pid %d", c, first.Pid)
	}
	dockerRun(ctx, "rm", "-f", "--", "x")
	f.ctr(fakeCtr{Name: "y"})
	dockerRun(ctx, "create", "--name", "x", "--", "img")
	again, _ := dockerInspectContainer(ctx, "x")
	other, _ := dockerInspectContainer(ctx, "y")
	if again.ID == first.ID || again.ID == other.ID || again.Running {
		t.Fatalf("ids reused or created running: %s %s %s %v", first.ID, again.ID, other.ID, again.Running)
	}
	boom := errors.New("boom")
	f.failInspect["x"] = boom
	if _, err := dockerInspectContainer(ctx, "x"); !errors.Is(err, boom) {
		t.Fatalf("failInspect: %v", err)
	}
	f.resetLog()
	if len(f.calls()) != 0 || len(f.argv()) != 0 {
		t.Fatal("resetLog")
	}
}

// ───────── state.json ─────────

func TestState_RoundTripAndAtomicWrite(t *testing.T) {
	a, f, s := newTestAgent(t)
	mkdirs(t, a.p.PlatformDir(), filepath.Dir(a.p.RenderDir(s.Ref)), a.p.RenderDir(s.Ref))
	if _, ok, err := a.readState(s.Ref); err != nil || ok {
		t.Fatalf("absent state: ok %v err %v, want false nil", ok, err)
	}
	want := State{Epoch: 1, Generation: 3, Phase: PhaseB, PMPid: 4242, PMStart: 987654321}
	if err := a.writeState(s.Ref, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := a.readState(s.Ref)
	if err != nil || !ok || got != want {
		t.Fatalf("read back %+v ok %v err %v, want %+v", got, ok, err, want)
	}
	path := filepath.Join(a.p.RenderDir(s.Ref), "state.json")
	w := f.writes[path]
	if w.Mode != 0o600 || w.UID != os.Geteuid() || w.GID != os.Getegid() {
		t.Fatalf("state.json written %o %d:%d, want 0600 owned by the daemon", w.Mode, w.UID, w.GID)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state.json on disk: %v %v", fi, err)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"epoch", "generation", "phase", "pm_pid", "pm_start", "listener_pid", "listener_start"} {
		if _, ok := m[k]; !ok {
			t.Errorf("state.json lacks %q: %s", k, w.Data)
		}
	}
	// Atomic: no temporary file stays behind and a second write replaces the first.
	want.Generation = 4
	if err := a.writeState(s.Ref, want); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(a.p.RenderDir(s.Ref))
	if len(ents) != 1 || ents[0].Name() != "state.json" {
		t.Fatalf("render dir after two writes: %v", ents)
	}
	if got, _, _ := a.readState(s.Ref); got.Generation != 4 {
		t.Fatalf("second write not read back: %+v", got)
	}
	// A damaged file or a link is an error, never an empty state.
	for name, setup := range map[string]func(){
		"garbage":       func() { os.WriteFile(path, []byte("{"), 0o600) },
		"unknown field": func() { os.WriteFile(path, []byte(`{"epoch":1,"extra":1}`), 0o600) },
		"link":          func() { os.Remove(path); os.Symlink("/etc/hostname", path) },
	} {
		setup()
		if _, _, err := a.readState(s.Ref); err == nil {
			t.Errorf("%s: read succeeded", name)
		}
	}
}

func TestState_EpochDivergence(t *testing.T) {
	_, _, s := newTestAgent(t)
	s.Epoch, s.Generation = 2, 5
	for _, c := range []struct {
		st   State
		have bool
		want error
	}{
		{State{}, false, nil},
		{State{Epoch: 2, Generation: 5}, true, nil},
		{State{Epoch: 2, Generation: 4}, true, nil},
		{State{Epoch: 2, Generation: 6}, true, ErrStaleGeneration},
		{State{Epoch: 1, Generation: 5}, true, ErrEpochDivergence},
		{State{Epoch: 3, Generation: 1}, true, ErrEpochDivergence},
	} {
		if err := checkState(c.st, c.have, s); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("state %+v: got %v, want %v", c.st, err, c.want)
		}
	}
}

// ───────── the start gate ─────────

func TestCheckContainment_PassesOnHealthyNode(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	if err := a.CheckContainment(context.Background(), s); err != nil {
		t.Fatalf("healthy node: %v", err)
	}
	log := strings.Join(f.calls(), "\n")
	for _, want := range []string{"bridge-nf", "nft check", "inspect network proj-" + s.Ref, "ip -j -d addr show dev spp14",
		"inspect network platform", "inspect network ingress"} {
		if !strings.Contains(log, want) {
			t.Errorf("the gate did not call %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "/proc") {
		t.Errorf("the gate read a tenant process:\n%s", log)
	}
}

// gateRefuses arranges a healthy node, checks that both calls pass on it
// (the control), applies fault, and wants CheckContainment and (unless only
// condition 1 is broken) CheckAdopted to refuse.
func gateRefuses(t *testing.T, fault func(a *Agent, f *fakeHost, s Spec), adopted bool) {
	t.Helper()
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	if err := a.CheckContainment(context.Background(), s); err != nil {
		t.Fatalf("control: CheckContainment on a healthy node: %v", err)
	}
	if err := a.CheckAdopted(context.Background(), s); err != nil {
		t.Fatalf("control: CheckAdopted on a healthy node: %v", err)
	}
	fault(a, f, s)
	wantContainment(t, a.CheckContainment(context.Background(), s), "CheckContainment")
	if adopted {
		wantContainment(t, a.CheckAdopted(context.Background(), s), "CheckAdopted")
	}
}

func TestCheckContainment_FailsOnNftDrift(t *testing.T) {
	for _, e := range []error{nft.ErrDrift, nft.ErrAbsent, nft.ErrUnverified} {
		gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) { f.nftErr = e }, false)
	}
}

func TestCheckContainment_FailsOnBridgeNF(t *testing.T) {
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) { f.bnfErr = errors.New("read-only") }, false)
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) { f.nftErr = nft.ErrBridgeNF }, false)
}

func TestCheckContainment_FailsOnMissingProjectNetwork(t *testing.T) {
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		delete(f.nets, "proj-"+s.Ref)
		f.ctrs["pg-"+s.Ref].Nets = map[string]string{}
		delete(f.ctrs["postgrest-"+s.Ref].Nets, "proj-"+s.Ref)
	}, true)
}

func TestCheckContainment_FailsOnWrongBridgeName(t *testing.T) {
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		n := f.nets["proj-"+s.Ref]
		n.BridgeName = "br-0123456789ab"
		delete(n.Options, "com.docker.network.bridge.name")
	}, true)
}

func TestCheckContainment_FailsOnWrongSubnet(t *testing.T) {
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) { f.nets["proj-"+s.Ref].Subnet = a.cfg.Slice(15).String() }, true)
}

func TestCheckContainment_FailsOnNonInternalNetwork(t *testing.T) {
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) { f.nets["proj-"+s.Ref].Internal = false }, true)
}

func TestCheckContainment_FailsOnNonIsolatedGateway(t *testing.T) {
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		delete(f.nets["proj-"+s.Ref].Options, "com.docker.network.bridge.gateway_mode_ipv4")
	}, true)
}

func TestCheckContainment_FailsOnInterfaceWithAddress(t *testing.T) {
	br := nodecfg.BridgeName(14)
	for name, out := range map[string]string{
		"ipv4 address": bridgeIface(br, true),
		"not a bridge": strings.Replace(bridgeIface(br, false), `"info_kind":"bridge"`, `"info_kind":"veth"`, 1),
		"other name":   bridgeIface("spp15", false),
		"empty":        `[]`,
		"garbage":      `{`,
	} {
		t.Run(name, func(t *testing.T) {
			gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) { f.ip["-j -d addr show dev "+br] = out }, true)
		})
	}
	t.Run("absent", func(t *testing.T) {
		gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) { delete(f.ip, "-j -d addr show dev "+br) }, true)
	})
}

func TestCheckContainment_FailsOnRestartPolicy(t *testing.T) {
	for _, p := range []string{"always", "unless-stopped", "on-failure"} {
		gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) { f.ctrs["pg-"+s.Ref].Restart = p }, true)
	}
	// A stopped container with a policy counts too.
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		f.ctrs["pg-"+s.Ref].Running = false
		f.ctrs["pg-"+s.Ref].Restart = "always"
	}, true)
}

func TestCheckContainment_FailsOnPlatformAddrHeldByAnother(t *testing.T) {
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		delete(f.ctrs, "postgrest-"+s.Ref)
		f.ctr(fakeCtr{Name: "postgrest-zzzzzzzzzzzzzzzzzzzz", Running: true, CapDrop: []string{"ALL"},
			Nets: map[string]string{"platform": a.cfg.PlatformAddr(s.SubnetIndex).String()}})
	}, true)
	// Our own PostgREST attached at another address (created but not started:
	// only its configuration knows the address).
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		pr := f.ctrs["postgrest-"+s.Ref]
		pr.Running = false
		pr.Nets["platform"] = a.cfg.PlatformAddr(15).String()
	}, true)
}

func TestCheckContainment_FailsOnPlatformNetwork(t *testing.T) {
	for name, fault := range map[string]func(a *Agent, f *fakeHost, s Spec){
		"absent":       func(a *Agent, f *fakeHost, s Spec) { delete(f.nets, "platform") },
		"not internal": func(a *Agent, f *fakeHost, s Spec) { f.nets["platform"].Internal = false },
		"bridge name":  func(a *Agent, f *fakeHost, s Spec) { f.nets["platform"].BridgeName = "br-0123456789ab" },
		"not isolated": func(a *Agent, f *fakeHost, s Spec) {
			delete(f.nets["platform"].Options, "com.docker.network.bridge.gateway_mode_ipv4")
		},
	} {
		t.Run(name, func(t *testing.T) { gateRefuses(t, fault, true) })
	}
}

func TestCheckContainment_WhenNodeContainmentFailed(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	a.SetContainmentFailed(true)
	if !a.ContainmentFailed() {
		t.Fatal("flag not set")
	}
	wantContainment(t, a.CheckContainment(context.Background(), s), "flag set")
	wantContainment(t, a.CheckAdopted(context.Background(), s), "flag set, adopted")
	a.SetContainmentFailed(false)
	if err := a.CheckContainment(context.Background(), s); err != nil {
		t.Fatalf("flag cleared: %v", err)
	}
	if err := a.CheckAdopted(context.Background(), s); err != nil {
		t.Fatalf("flag cleared, adopted: %v", err)
	}
}

func TestCheckContainment_ChecksBothContainers(t *testing.T) {
	// A policy on postgrest-<ref> refuses a cluster start (pg-<ref> absent,
	// about to be run), and one on pg-<ref> a PostgREST start (postgrest-<ref>
	// created, not started).
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		delete(f.ctrs, "pg-"+s.Ref)
		f.ctrs["postgrest-"+s.Ref].Restart = "always"
	}, true)
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		f.ctrs["pg-"+s.Ref].Restart = "on-failure"
		f.ctrs["postgrest-"+s.Ref].Running = false
	}, true)
	// A foreign holder of PlatformAddr refuses both starts.
	for _, absent := range []string{"pg-", "postgrest-"} {
		gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
			delete(f.ctrs, absent+s.Ref)
			if absent == "pg-" {
				f.ctrs["postgrest-"+s.Ref].Nets["platform"] = a.cfg.PlatformAddr(16).String()
			}
			f.ctr(fakeCtr{Name: "intruder", Running: true, CapDrop: []string{"ALL"},
				Nets: map[string]string{"platform": a.cfg.PlatformAddr(s.SubnetIndex).String()}})
		}, true)
	}
}

func TestCheckAdopted_Conditions2to5(t *testing.T) {
	faults := map[string]func(a *Agent, f *fakeHost, s Spec){
		"bridge name":  func(a *Agent, f *fakeHost, s Spec) { f.nets["proj-"+s.Ref].BridgeName = "spp15" },
		"subnet":       func(a *Agent, f *fakeHost, s Spec) { f.nets["proj-"+s.Ref].Subnet = a.cfg.Slice(15).String() },
		"not internal": func(a *Agent, f *fakeHost, s Spec) { f.nets["proj-"+s.Ref].Internal = false },
		"foreign": func(a *Agent, f *fakeHost, s Spec) {
			f.ctrs["sp-gateway"].Nets["platform"] = a.cfg.PlatformAddr(s.SubnetIndex).String()
		},
		"restart":       func(a *Agent, f *fakeHost, s Spec) { f.ctrs["postgrest-"+s.Ref].Restart = "always" },
		"node flag":     func(a *Agent, f *fakeHost, s Spec) { a.SetContainmentFailed(true) },
		"net_raw":       func(a *Agent, f *fakeHost, s Spec) { f.ctrs["pg-"+s.Ref].CapAdd = []string{"NET_RAW"} },
		"iface address": func(a *Agent, f *fakeHost, s Spec) { f.ip["-j -d addr show dev spp14"] = bridgeIface("spp14", true) },
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			a, f, s := newTestAgent(t)
			healthy(a, f, s)
			tenants(a, f, s)
			if err := a.CheckAdopted(context.Background(), s); err != nil {
				t.Fatalf("control: %v", err)
			}
			fault(a, f, s)
			f.resetLog()
			wantContainment(t, a.CheckAdopted(context.Background(), s), name)
			for _, c := range f.calls() {
				if c == "nft check" || c == "bridge-nf" {
					t.Fatalf("CheckAdopted called %q: condition 1 is the caller's", c)
				}
			}
		})
	}
	// Condition 1 alone broken: CheckAdopted passes.
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	f.nftErr = nft.ErrDrift
	if err := a.CheckAdopted(context.Background(), s); err != nil {
		t.Fatalf("nft drift is not CheckAdopted's: %v", err)
	}
}

func TestCheckContainment_CapabilitiesFromConfig(t *testing.T) {
	faults := map[string]func(a *Agent, f *fakeHost, s Spec){
		"cap_add NET_RAW":         func(a *Agent, f *fakeHost, s Spec) { f.ctrs["postgrest-"+s.Ref].CapAdd = []string{"NET_RAW"} },
		"cap_add cap_net_admin":   func(a *Agent, f *fakeHost, s Spec) { f.ctrs["pg-"+s.Ref].CapAdd = []string{"cap_net_admin"} },
		"cap_add all":             func(a *Agent, f *fakeHost, s Spec) { f.ctrs["pg-"+s.Ref].CapAdd = []string{"all"} },
		"privileged":              func(a *Agent, f *fakeHost, s Spec) { f.ctrs["pg-"+s.Ref].Privileged = true },
		"no cap_drop ALL":         func(a *Agent, f *fakeHost, s Spec) { f.ctrs["postgrest-"+s.Ref].CapDrop = []string{"NET_RAW"} },
		"platform member net_raw": func(a *Agent, f *fakeHost, s Spec) { f.ctrs["sp-gateway"].CapAdd = []string{"CAP_NET_RAW"} },
		"project member privileged": func(a *Agent, f *fakeHost, s Spec) {
			f.ctr(fakeCtr{Name: "stranger", Running: true, Privileged: true, CapDrop: []string{"ALL"},
				Nets: map[string]string{"proj-" + s.Ref: "10.213.3.140"}})
		},
		"cap_add any other": func(a *Agent, f *fakeHost, s Spec) { f.ctrs["pg-"+s.Ref].CapAdd = []string{"CHOWN"} },
		"cap_add sys_admin": func(a *Agent, f *fakeHost, s Spec) { f.ctrs["sp-gateway"].CapAdd = []string{"SYS_ADMIN"} },
		"stopped tenant net_admin": func(a *Agent, f *fakeHost, s Spec) {
			f.ctrs["postgrest-"+s.Ref].Running = false
			f.ctrs["postgrest-"+s.Ref].CapAdd = []string{"NET_ADMIN"}
		},
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) { gateRefuses(t, fault, true) })
	}
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	if err := a.CheckContainment(context.Background(), s); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, c := range f.calls() {
		if strings.Contains(c, "/proc") || strings.HasPrefix(c, "docker exec") {
			t.Fatalf("capabilities read from a process: %q", c)
		}
	}
}

func TestCheckContainment_MemberGoneIsSkipped(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	leaving := f.ctr(fakeCtr{Name: "leaving", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{"platform": "10.212.0.200"}})
	// The member is listed by the network, then gone when its configuration is read.
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if len(args) > 1 && args[0] == "container" && args[1] == "inspect" && slices.Contains(args, leaving.ID) {
			f.mu.Lock()
			delete(f.ctrs, "leaving")
			f.mu.Unlock()
		}
		return "", nil, false
	}
	if err := a.CheckContainment(context.Background(), s); err != nil {
		t.Fatalf("a member that left is not a failure: %v", err)
	}
	n := 0
	for _, c := range f.argv("container", "inspect") {
		if slices.Contains(c, confFormat) {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("configuration read %d times, want 2 (once, then once again without the gone member)", n)
	}
}

func TestCheckContainment_IngressMembersChecked(t *testing.T) {
	gateRefuses(t, func(a *Agent, f *fakeHost, s Spec) {
		f.ctr(fakeCtr{Name: "edge", Running: true, CapAdd: []string{"NET_RAW"}, CapDrop: []string{"ALL"},
			Nets: map[string]string{"ingress": "10.212.8.9"}})
	}, true)
}

func TestCheckContainment_DockerErrorIsContainment(t *testing.T) {
	boom := errors.New("daemon unreachable")
	for name, fault := range map[string]func(f *fakeHost, s Spec){
		"configuration read": func(f *fakeHost, s Spec) { f.failVerb["container inspect"] = boom },
		"project network":    func(f *fakeHost, s Spec) { f.failInspect["proj-"+s.Ref] = boom },
		"platform network":   func(f *fakeHost, s Spec) { f.failInspect["platform"] = boom },
		"ingress network":    func(f *fakeHost, s Spec) { f.failInspect["ingress"] = boom },
		"cluster":            func(f *fakeHost, s Spec) { f.failInspect["pg-"+s.Ref] = boom },
		"postgrest":          func(f *fakeHost, s Spec) { f.failInspect["postgrest-"+s.Ref] = boom },
	} {
		t.Run(name, func(t *testing.T) {
			a, f, s := newTestAgent(t)
			healthy(a, f, s)
			tenants(a, f, s)
			fault(f, s)
			for _, err := range []error{a.CheckContainment(context.Background(), s), a.CheckAdopted(context.Background(), s)} {
				wantContainment(t, err, "docker failure")
				if !errors.Is(err, boom) {
					t.Fatalf("the cause is not kept: %v", err)
				}
			}
		})
	}
	// An answer that is not one record per container is a refusal too.
	for name, out := range map[string]string{"garbage": "{\n", "short": `{"name":"/x","cap_drop":["ALL"],"restart":"no"}` + "\n"} {
		t.Run(name, func(t *testing.T) {
			a, f, s := newTestAgent(t)
			healthy(a, f, s)
			tenants(a, f, s)
			f.onRun = func(args []string, _ []byte) (string, error, bool) {
				return out, nil, args[0] == "container" && args[1] == "inspect" && flagValue(args, "--format") == confFormat
			}
			wantContainment(t, a.CheckContainment(context.Background(), s), name)
		})
	}
}

func TestCheckContainment_RefusesBadSpec(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	for name, mut := range map[string]func(*Spec){
		"ref":   func(s *Spec) { s.Ref = "../etc" },
		"index": func(s *Spec) { s.SubnetIndex = 1024 },
		"neg":   func(s *Spec) { s.SubnetIndex = -1 },
	} {
		bad := s
		mut(&bad)
		f.resetLog()
		if err := a.CheckContainment(context.Background(), bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if err := a.CheckAdopted(context.Background(), bad); err == nil {
			t.Errorf("%s: accepted by CheckAdopted", name)
		}
		if c := f.calls(); len(c) != 0 {
			t.Errorf("%s: refused only after asking the host: %q", name, c)
		}
	}
}

// ───────── project networks and directories ─────────

func TestEnsureNetwork_CreateArgs(t *testing.T) {
	a, f, s := newTestAgent(t)
	if err := a.EnsureNetwork(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	got := f.argv("network", "create")
	want := []string{"network", "create", "--internal", "--ipv6=false", "--subnet", "10.213.3.128/26",
		"-o", "com.docker.network.bridge.name=spp14", "-o", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
		"--", "proj-" + testRef}
	if len(got) != 1 || !slices.Equal(got[0], want) {
		t.Fatalf("network create argv:\n got %q\nwant %q", got, want)
	}
	// Idempotent: a second call finds the network and creates nothing.
	f.resetLog()
	if err := a.EnsureNetwork(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("second EnsureNetwork mutated: %v", m)
	}
}

func TestEnsureNetwork_RefusesForeignNetwork(t *testing.T) {
	for name, mut := range map[string]func(n *fakeNet){
		"unnamed bridge": func(n *fakeNet) {
			n.BridgeName = "br-0123456789ab"
			delete(n.Options, "com.docker.network.bridge.name")
		},
		"other subnet": func(n *fakeNet) { n.Subnet = "10.214.0.64/26" },
		"not internal": func(n *fakeNet) { n.Internal = false },
		"not isolated": func(n *fakeNet) { delete(n.Options, "com.docker.network.bridge.gateway_mode_ipv4") },
	} {
		t.Run(name, func(t *testing.T) {
			a, f, s := newTestAgent(t)
			healthy(a, f, s)
			mut(f.nets["proj-"+s.Ref])
			f.resetLog()
			wantContainment(t, a.EnsureNetwork(context.Background(), s), name)
			if m := f.mutations(); len(m) != 0 {
				t.Fatalf("a foreign network was touched: %v", m)
			}
		})
	}
}

func TestRemoveNetwork_AnyOptions(t *testing.T) {
	a, f, s := newTestAgent(t)
	f.net(fakeNet{Network: dockerx.Network{Name: "proj-" + s.Ref, Subnet: "10.214.0.64/26", BridgeName: "br-0123456789ab"}})
	if err := a.RemoveNetwork(context.Background(), s.Ref); err != nil {
		t.Fatal(err)
	}
	if got := f.argv("network", "rm"); len(got) != 1 || !slices.Equal(got[0], []string{"network", "rm", "--", "proj-" + s.Ref}) {
		t.Fatalf("network rm: %q", got)
	}
	f.resetLog()
	if err := a.RemoveNetwork(context.Background(), s.Ref); err != nil {
		t.Fatalf("absent: %v", err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("absent network: %v", m)
	}
	if err := a.RemoveNetwork(context.Background(), "../x"); err == nil {
		t.Fatal("bad ref accepted")
	}
	// rm fails: gone in between is removed; still there is the error.
	boom := errors.New("network has active endpoints")
	for _, gone := range []bool{true, false} {
		f.net(fakeNet{Network: dockerx.Network{Name: "proj-" + s.Ref}})
		f.onRun = func(args []string, _ []byte) (string, error, bool) {
			if args[0] != "network" || args[1] != "rm" {
				return "", nil, false
			}
			if gone {
				f.mu.Lock()
				delete(f.nets, "proj-"+s.Ref)
				f.mu.Unlock()
			}
			return "", boom, true
		}
		if err := a.RemoveNetwork(context.Background(), s.Ref); gone != (err == nil) || (!gone && !errors.Is(err, boom)) {
			t.Fatalf("rm failed, network gone %v: %v", gone, err)
		}
	}
}

func TestEnsureDir_DelegatesToNodefs(t *testing.T) {
	a, f, s := newTestAgent(t)
	if err := a.EnsureDir(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if err := a.SetQuota(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	want := []string{"createProjectDir abcdefghij0123456789 700005:700005 8192", "setQuota 700005 8192"}
	if got := f.calls(); !slices.Equal(got, want) {
		t.Fatalf("calls %q, want %q", got, want)
	}
	bad := s
	bad.Ref = "ABC"
	if a.EnsureDir(context.Background(), bad) == nil || a.SetQuota(context.Background(), bad) == nil {
		t.Fatal("bad ref accepted")
	}
}

// A link where a platform directory belongs is refused, never followed.
func TestEnsureDir_RefusesLink(t *testing.T) {
	f := fakeDocker(t)
	root := t.TempDir()
	target := filepath.Join(root, "elsewhere")
	mkdirs(t, target)
	os.Chmod(target, 0o700)
	link := filepath.Join(root, "dir")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureDir(link, 0o755, 70, 70); err == nil {
		t.Fatal("a link was accepted as a directory")
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o700 {
		t.Fatalf("the link's target was changed: %v", fi.Mode())
	}
	if c := f.calls(); len(c) != 0 {
		t.Fatalf("calls: %q", c)
	}
}

func TestRemoveRender(t *testing.T) {
	a, _, s := newTestAgent(t)
	dir := a.p.RenderDir(s.Ref)
	os.MkdirAll(filepath.Join(dir, "conf.d"), 0o755)
	os.WriteFile(filepath.Join(dir, "conf.d", "x.conf"), nil, 0o444)
	outside := filepath.Join(t.TempDir(), "keep")
	os.WriteFile(outside, nil, 0o600)
	os.Symlink(filepath.Dir(outside), filepath.Join(dir, "link"))
	if err := a.RemoveRender(context.Background(), s.Ref); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("render dir still there: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("a link was followed: %v", err)
	}
	if err := a.RemoveRender(context.Background(), s.Ref); err != nil {
		t.Fatalf("absent: %v", err)
	}
	if err := a.RemoveRender(context.Background(), ".."); err == nil {
		t.Fatal("bad ref accepted")
	}
}

// ───────── tenants stop ─────────

func TestStopAllTenants_ByRoleLabel(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	f.ctr(fakeCtr{Name: "sp-cp-db", Running: true, Labels: map[string]string{"supapace.role": "cp-db"}})
	f.ctr(fakeCtr{Name: "task-x", Running: true, Labels: map[string]string{"supapace.role": "task"}})
	f.ctr(fakeCtr{Name: "pg-exited00000000000000", Labels: map[string]string{"supapace.role": "cluster"}})
	if err := a.StopAllTenants(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"pg-" + s.Ref, "postgrest-" + s.Ref} {
		if f.ctrs[n].Running || len(f.ctrs[n].Nets) != 0 {
			t.Errorf("%s: running %v, networks %v", n, f.ctrs[n].Running, f.ctrs[n].Nets)
		}
	}
	for _, n := range []string{"sp-gateway", "sp-cp-db", "task-x"} {
		if !f.ctrs[n].Running {
			t.Errorf("%s was stopped", n)
		}
	}
	for _, m := range f.mutations() {
		if strings.Contains(m, "sp-gateway") || strings.Contains(m, "sp-cp-db") || strings.Contains(m, "task-x") ||
			strings.Contains(m, "exited") {
			t.Errorf("unexpected call %q", m)
		}
	}
}

// Containment waits on no tenant: the three disconnects (pg: 1 network,
// postgrest: 2) are all issued, in parallel, and all return before any stop
// or kill is issued. Then, in parallel, the cluster is stopped with its grace
// period and PostgREST is killed, all within a bounded context.
func TestStopAllTenants_DisconnectAllThenStopClusterKillREST(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	barrier := func(want int) func() {
		var mu sync.Mutex
		n, all := 0, make(chan struct{})
		return func() {
			mu.Lock()
			if n++; n == want {
				close(all)
			}
			mu.Unlock()
			select {
			case <-all:
			case <-time.After(5 * time.Second):
				t.Errorf("a call waited for the other %d in vain: not issued in parallel", want-1)
			}
		}
	}
	disc, end := barrier(3), barrier(2)
	var mu sync.Mutex
	var order []string
	f.before = func(args []string) {
		mu.Lock()
		order = append(order, args[0])
		mu.Unlock()
		switch {
		case args[0] == "network" && args[1] == "disconnect":
			disc()
		case args[0] == "stop" || args[0] == "kill":
			end()
		}
	}
	var noDeadline atomic.Bool
	inner := dockerRun
	t.Cleanup(swap(&dockerRun, func(ctx context.Context, args ...string) (string, error) {
		if d, ok := ctx.Deadline(); !ok || time.Until(d) > stopAllMax {
			noDeadline.Store(true)
		}
		return inner(ctx, args...)
	}))
	if err := a.StopAllTenants(context.Background()); err != nil {
		t.Fatal(err)
	}
	if noDeadline.Load() {
		t.Error("a call ran without a bound")
	}
	last := slices.Index(order, "network")
	for i, o := range order {
		if o == "network" {
			last = i
		}
	}
	if first := slices.IndexFunc(order, func(o string) bool { return o != "network" }); first < 0 || first < last {
		t.Fatalf("a stop or kill was issued before every disconnect: %q", order)
	}
	for _, d := range f.argv("network", "disconnect") {
		if !slices.Contains(d, "-f") {
			t.Errorf("disconnect without -f: %v", d)
		}
	}
	st, k := f.argv("stop"), f.argv("kill")
	if !slices.EqualFunc(st, [][]string{{"stop", "-t", "45", "--", "pg-" + s.Ref}}, slices.Equal) ||
		!slices.EqualFunc(k, [][]string{{"kill", "--", "postgrest-" + s.Ref}}, slices.Equal) {
		t.Fatalf("stops %q, kills %q; want the cluster stopped with 45 s and PostgREST killed", st, k)
	}
	for _, n := range []string{"pg-" + s.Ref, "postgrest-" + s.Ref} {
		if f.ctrs[n].Running || len(f.ctrs[n].Nets) != 0 {
			t.Errorf("%s: running %v, networks %v", n, f.ctrs[n].Running, f.ctrs[n].Nets)
		}
	}
}

// A cluster whose disconnect failed is killed at once, not given a grace
// period on a network it may still hold, and the kill runs on its own bound
// even when the call's context has ended meanwhile.
func TestStopAllTenants_DisconnectFailureKills(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	tenants(a, f, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var killCtxDone atomic.Bool
	inner := dockerRun
	t.Cleanup(swap(&dockerRun, func(c context.Context, args ...string) (string, error) {
		if args[0] == "network" && args[1] == "disconnect" && args[len(args)-1] == "pg-"+s.Ref {
			cancel() // the bound ran out while this disconnect hung
			return "", errors.New("docker: daemon busy")
		}
		if args[0] == "kill" && c.Err() != nil {
			killCtxDone.Store(true)
		}
		return inner(c, args...)
	}))
	if err := a.StopAllTenants(ctx); err == nil {
		t.Fatal("a failed disconnect was not reported")
	}
	k, st := f.argv("kill"), f.argv("stop")
	slices.SortFunc(k, func(x, y []string) int { return strings.Compare(x[2], y[2]) })
	if len(st) != 0 || !slices.EqualFunc(k, [][]string{{"kill", "--", "pg-" + s.Ref}, {"kill", "--", "postgrest-" + s.Ref}}, slices.Equal) {
		t.Fatalf("kills %q, stops %q; want both killed, nothing stopped", k, st)
	}
	if killCtxDone.Load() || f.ctrs["pg-"+s.Ref].Running {
		t.Fatal("the kill ran on the call's ended context")
	}
}

// ───────── platform objects ─────────

func TestEnsurePlatformNetworks_Args(t *testing.T) {
	a, f, _ := newTestAgent(t)
	if err := a.EnsurePlatformNetworks(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := f.argv("network", "create")
	want := [][]string{
		{"network", "create", "--internal", "--ipv6=false", "--subnet", "10.212.0.0/21", "--ip-range", "10.212.6.0/23",
			"-o", "com.docker.network.bridge.name=spl0", "-o", "com.docker.network.bridge.gateway_mode_ipv4=isolated", "--", "platform"},
		{"network", "create", "--ipv6=false", "--subnet", "10.212.8.0/24", "-o", "com.docker.network.bridge.name=spi0", "--", "ingress"},
	}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("network create argv:\n got %q\nwant %q", got, want)
	}
	f.resetLog()
	if err := a.EnsurePlatformNetworks(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("second call mutated: %v", m)
	}
	for name, mut := range map[string]func(){
		"platform not internal": func() { f.nets["platform"].Internal = false },
		"platform ip range":     func() { f.nets["platform"].IPRange = "" },
		"platform not isolated": func() { delete(f.nets["platform"].Options, "com.docker.network.bridge.gateway_mode_ipv4") },
		"platform subnet":       func() { f.nets["platform"].Subnet = "10.212.0.0/22" },
		"ingress internal":      func() { f.nets["ingress"].Internal = true },
		"ingress bridge":        func() { f.nets["ingress"].BridgeName = "br-0123456789ab" },
		"ingress subnet":        func() { f.nets["ingress"].Subnet = "10.212.9.0/24" },
		"platform bridge":       func() { f.nets["platform"].BridgeName = "br-0123456789ab" },
	} {
		t.Run(name, func(t *testing.T) {
			saved := map[string]fakeNet{"platform": *f.nets["platform"], "ingress": *f.nets["ingress"]}
			for k := range saved {
				n := saved[k]
				n.Options = map[string]string{}
				for ok, ov := range f.nets[k].Options {
					n.Options[ok] = ov
				}
				saved[k] = n
			}
			defer func() {
				for k, n := range saved {
					f.nets[k] = &n
				}
			}()
			mut()
			f.resetLog()
			wantContainment(t, a.EnsurePlatformNetworks(context.Background()), name)
			if m := f.mutations(); len(m) != 0 {
				t.Fatalf("mutated: %v", m)
			}
		})
	}
}

func TestEnsureControlPlaneDB_Args(t *testing.T) {
	a, f, _ := newTestAgent(t)
	writeSeccomp(t, a)
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	runs := f.argv("run")
	if len(runs) != 1 {
		t.Fatalf("docker run calls: %q", runs)
	}
	argv := strings.Join(runs[0], " ")
	cp := a.p.CPDir()
	for _, want := range []string{
		"run -d --name sp-cp-db ", "--network none", "--user 70:70", "--cap-drop ALL", "--security-opt no-new-privileges",
		"--security-opt seccomp=" + filepath.Join(a.p.PlatformDir(), "seccomp.json"), "--read-only", "--tmpfs /tmp",
		"--memory 256m", "--pids-limit 128", "--ulimit core=0", "--restart unless-stopped", "--label supapace.role=cp-db",
		"-e POSTGRES_USER=supapaced", "-e POSTGRES_DB=supapaced",
		"-v " + cp + "/data:/var/lib/postgresql/data", "-v " + cp + "/sock:/var/run/postgresql", "-v " + cp + "/etc:/etc/sp:ro",
		"-- " + a.cfg.Images.ControlPlane + " postgres -c listen_addresses= -c hba_file=/etc/sp/pg_hba.conf -c ident_file=/etc/sp/pg_ident.conf",
	} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv lacks %q:\n%s", want, argv)
		}
	}
	if !regexp.MustCompile(` -e POSTGRES_PASSWORD=[0-9a-f]{64} `).MatchString(argv) {
		t.Errorf("no 32-byte random POSTGRES_PASSWORD:\n%s", argv)
	}
	for _, bad := range []string{"--cap-add", "--privileged", "-p ", "--ip "} {
		if strings.Contains(argv, bad) {
			t.Errorf("argv carries %q", bad)
		}
	}
	// Directories, owners and the two files.
	for path, mode := range map[string]os.FileMode{filepath.Dir(cp): 0o700, cp: 0o700, cp + "/data": 0o700, cp + "/sock": 0o700, cp + "/etc": 0o755} {
		if fi, err := os.Lstat(path); err != nil || !fi.IsDir() || fi.Mode().Perm() != mode {
			t.Errorf("%s: %v %v, want directory %o", path, fi, err, mode)
		}
	}
	log := strings.Join(f.calls(), "\n")
	for _, want := range []string{"chown " + cp + "/data 70:70", "chown " + cp + "/sock 70:70"} {
		if !strings.Contains(log, want) {
			t.Errorf("no %q", want)
		}
	}
	for name, want := range map[string]string{
		"pg_hba.conf":   "local all supapaced peer map=cp\nlocal all all reject\n",
		"pg_ident.conf": "cp root supapaced\ncp postgres supapaced\n",
	} {
		path := filepath.Join(cp, "etc", name)
		b, err := os.ReadFile(path)
		fi, _ := os.Lstat(path)
		if err != nil || string(b) != want || fi.Mode().Perm() != 0o444 {
			t.Errorf("%s: %q %v mode %v", name, b, err, fi.Mode())
		}
	}
	// Running: nothing more. Stopped: started, not re-run.
	f.resetLog()
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("running database touched: %v", m)
	}
	f.ctrs["sp-cp-db"].Running = false
	f.resetLog()
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); !slices.Equal(m, []string{"docker start -- sp-cp-db"}) {
		t.Fatalf("stopped database: %v", m)
	}
}

// writeSeccomp puts the profile in place as EnsureImageFiles does.
func writeSeccomp(t testing.TB, a *Agent) {
	t.Helper()
	if err := a.ensurePlatformDir(); err != nil {
		t.Fatal(err)
	}
	if err := nodefs.WriteFile(a.p, a.p.PlatformDir(), "seccomp.json", seccompProfile, 0o444, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
}

// writeTLS puts the operator's certificate files, a dev CA key and the
// seccomp profile in place.
func writeTLS(t *testing.T, a *Agent) {
	writeSeccomp(t, a)
	for _, d := range []string{a.p.TLSDir(), a.p.CADir()} {
		os.MkdirAll(d, 0o700)
	}
	os.WriteFile(filepath.Join(a.p.TLSDir(), "cert.pem"), []byte("CERT"), 0o600)
	os.WriteFile(filepath.Join(a.p.TLSDir(), "key.pem"), []byte("KEY"), 0o600)
	os.WriteFile(filepath.Join(a.p.CADir(), "ca.key"), []byte("CAKEY"), 0o400)
}

func TestEnsureGateway_Args(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	delete(f.ctrs, "sp-gateway")
	writeTLS(t, a)
	if err := a.EnsureGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	gw := a.p.GatewayDir()
	creates := f.argv("create")
	if len(creates) != 1 {
		t.Fatalf("docker create calls: %q", creates)
	}
	argv := strings.Join(creates[0], " ")
	for _, want := range []string{
		"create --name sp-gateway ", "--user 65531:65531", "--cap-drop ALL", "--security-opt no-new-privileges",
		"--security-opt seccomp=" + filepath.Join(a.p.PlatformDir(), "seccomp.json"), "--read-only",
		"--memory 768m", "--memory-swap 768m", "--pids-limit 256", "--ulimit core=0", "--stop-timeout 15",
		"--restart unless-stopped", "--label supapace.role=gateway", "--network ingress --ip 10.212.8.2",
		"-p 0.0.0.0:443:8443", "-p 0.0.0.0:80:8080", "-v " + gw + ":/etc/supapace/gateway:ro", "-- supapace-gateway:local",
	} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv lacks %q:\n%s", want, argv)
		}
	}
	for _, bad := range []string{"--cap-add", "--privileged", a.p.CADir(), "-p 443", "-p 80", "65532"} {
		if strings.Contains(argv, bad) {
			t.Errorf("argv carries %q", bad)
		}
	}
	m := f.mutations()
	want := []string{"docker " + strings.Join(creates[0], " "), "docker network connect --ip 10.212.0.2 -- platform sp-gateway", "docker start -- sp-gateway"}
	if !slices.Equal(m, want) {
		t.Fatalf("calls:\n got %q\nwant %q", m, want)
	}
	cert, key := f.writes[filepath.Join(gw, "tls", "cert.pem")], f.writes[filepath.Join(gw, "tls", "key.pem")]
	if string(cert.Data) != "CERT" || cert.Mode != 0o444 || cert.UID != os.Geteuid() {
		t.Errorf("cert.pem copy: %+v", cert)
	}
	if string(key.Data) != "KEY" || key.Mode != 0o400 || key.UID != 65531 || key.GID != 65531 {
		t.Errorf("key.pem copy: mode %o owner %d:%d, want 0400 65531:65531", key.Mode, key.UID, key.GID)
	}
	for _, d := range []string{gw, filepath.Join(gw, "tls")} {
		if fi, err := os.Lstat(d); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v %v, want a 0755 directory", d, fi, err)
		}
	}
	for p := range f.writes {
		if strings.Contains(p, "ca.key") || strings.Contains(p, "ca.pem") {
			t.Errorf("CA file copied: %s", p)
		}
	}
	err := filepath.Walk(a.p.PlatformDir(), func(p string, fi os.FileInfo, err error) error {
		if err == nil && strings.HasPrefix(fi.Name(), "ca.") {
			t.Errorf("CA file under the platform tree: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Running at both addresses: nothing to do.
	f.resetLog()
	if err := a.EnsureGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("running gateway touched: %v", m)
	}
	// Resumed after a crash between create and connect: connect, then start.
	f.ctrs["sp-gateway"].Running = false
	delete(f.ctrs["sp-gateway"].Nets, "platform")
	f.resetLog()
	if err := a.EnsureGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); !slices.Equal(m, want[1:]) {
		t.Fatalf("resume: %q", m)
	}
	// At a wrong address: removed and created again.
	f.ctrs["sp-gateway"].Nets["platform"] = "10.212.0.3"
	f.resetLog()
	if err := a.EnsureGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 4 || m[0] != "docker rm -f -- sp-gateway" {
		t.Fatalf("wrong address: %q", m)
	}
	// At a wrong ingress address, or not on ingress at all: the same.
	for name, nets := range map[string]map[string]string{
		"ingress address": {"ingress": "10.212.8.3", "platform": a.cfg.GatewayIP},
		"no ingress":      {"platform": a.cfg.GatewayIP},
	} {
		f.ctrs["sp-gateway"].Nets = nets
		f.resetLog()
		if err := a.EnsureGateway(context.Background()); err != nil {
			t.Fatal(err)
		}
		if m := f.mutations(); len(m) != 4 || m[0] != "docker rm -f -- sp-gateway" {
			t.Fatalf("%s: %q", name, m)
		}
	}
}

func TestEnsureGateway_NoTLSFiles(t *testing.T) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	delete(f.ctrs, "sp-gateway")
	if err := a.EnsureGateway(context.Background()); err == nil {
		t.Fatal("started without TLS files")
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("mutated: %v", m)
	}
}

// tarOf builds a `docker cp … -` stream.
func tarOf(t testing.TB, entries ...[3]string) string { // name, type ("f", "d", "l"), content or link target
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		h := &tar.Header{Name: e[0], Mode: 0o644, ModTime: time.Unix(0, 0)}
		switch e[1] {
		case "d":
			h.Typeflag, h.Mode = tar.TypeDir, 0o755
		case "l":
			h.Typeflag, h.Linkname = tar.TypeSymlink, e[2]
		default:
			h.Typeflag, h.Size = tar.TypeReg, int64(len(e[2]))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e[1] == "f" {
			tw.Write([]byte(e[2]))
		}
	}
	tw.Close()
	return b.String()
}

// imageCp scripts the five copies out of the image.
func imageCp(t testing.TB, f *fakeHost, confd string) {
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if args[0] != "cp" {
			return "", nil, false
		}
		src := args[len(args)-2]
		_, path, _ := strings.Cut(src, ":")
		switch path {
		case "/etc/passwd", "/etc/group", "/etc/postgresql-custom/supautils.conf", "/etc/postgresql/postgresql.conf":
			return tarOf(t, [3]string{filepath.Base(path), "f", "content of " + path}), nil, true
		case "/etc/postgresql-custom/conf.d/.":
			return confd, nil, true
		}
		t.Errorf("unexpected cp source %q", src)
		return "", errors.New("unexpected"), true
	}
}

func TestEnsureImageFiles_OncePerDigest(t *testing.T) {
	a, f, _ := newTestAgent(t)
	imageCp(t, f, tarOf(t, [3]string{"./", "d", ""}, [3]string{"./pg_cron.conf", "f", "cron"}, [3]string{"./empty.conf", "f", ""}))
	if err := a.EnsureImageFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := a.p.ImageDir(a.cfg.Images.Postgres)
	if filepath.Base(dir) != "b3bfedb10741" {
		t.Fatalf("image dir %s", dir)
	}
	for name, want := range map[string]string{
		"passwd": "content of /etc/passwd", "group": "content of /etc/group", "supautils.conf": "content of /etc/postgresql-custom/supautils.conf",
		"postgresql.conf": "content of /etc/postgresql/postgresql.conf", "conf.d/pg_cron.conf": "cron", "conf.d/empty.conf": "",
	} {
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil || string(b) != want {
			t.Errorf("%s: %q %v", name, b, err)
		}
		if w := f.writes[path]; w.Mode != 0o444 || w.UID != os.Geteuid() {
			t.Errorf("%s written %o %d", name, w.Mode, w.UID)
		}
	}
	if fi, err := os.Lstat(filepath.Dir(a.p.PlatformDir())); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("%s: %v %v, want 0700", filepath.Dir(a.p.PlatformDir()), fi, err)
	}
	for _, d := range []string{dir, filepath.Join(dir, "conf.d"), filepath.Dir(dir), a.p.PlatformDir()} {
		if fi, err := os.Lstat(d); err != nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v %v", d, fi, err)
		}
	}
	m := f.mutations()
	if len(m) != 3 || !strings.HasPrefix(m[0], "docker rm -f -- sp-extract-b3bfedb10741") ||
		m[1] != "docker create --name sp-extract-b3bfedb10741 --network none --label supapace.role=task -- "+a.cfg.Images.Postgres ||
		m[2] != "docker rm -f -- sp-extract-b3bfedb10741" {
		t.Fatalf("calls: %q", m)
	}
	// The seccomp profile is the embedded one, 0444, and is written on every call.
	sec := filepath.Join(a.p.PlatformDir(), "seccomp.json")
	if w := f.writes[sec]; w.Mode != 0o444 || !bytes.Equal(w.Data, seccompProfile) || !json.Valid(w.Data) {
		t.Errorf("seccomp.json: mode %o, %d bytes", w.Mode, len(w.Data))
	}
	f.resetLog()
	os.Remove(sec)
	if err := a.EnsureImageFiles(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "docker ") {
			t.Fatalf("second call ran docker: %q", c)
		}
	}
	if _, err := os.Stat(sec); err != nil {
		t.Fatalf("seccomp.json not rewritten: %v", err)
	}
}

// TestSeccompProfile_Pinned: the embedded profile is the unmodified upstream
// file (a change must be a deliberate re-pin) and denies by default.
func TestSeccompProfile_Pinned(t *testing.T) {
	if sum := fmt.Sprintf("%x", sha256.Sum256(seccompProfile)); sum != "6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6" {
		t.Fatalf("seccomp/default.json changed: sha256 %s", sum)
	}
	var p struct {
		DefaultAction string
		Syscalls      []json.RawMessage
	}
	if err := json.Unmarshal(seccompProfile, &p); err != nil || p.DefaultAction != "SCMP_ACT_ERRNO" || len(p.Syscalls) == 0 {
		t.Fatalf("profile: %v, default %q, %d rules", err, p.DefaultAction, len(p.Syscalls))
	}
}

func TestEnsureImageFiles_RefusesOddArchive(t *testing.T) {
	for name, confd := range map[string][][3]string{
		"symlink": {{"./", "d", ""}, {"./x.conf", "l", "/etc/shadow"}},
		"subdir":  {{"./", "d", ""}, {"./sub/", "d", ""}},
		"nested":  {{"./", "d", ""}, {"./sub/x.conf", "f", "x"}},
		"escape":  {{"./", "d", ""}, {"../x.conf", "f", "x"}},
	} {
		t.Run(name, func(t *testing.T) {
			a, f, _ := newTestAgent(t)
			imageCp(t, f, tarOf(t, confd...))
			if err := a.EnsureImageFiles(context.Background()); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(filepath.Join(a.p.ImageDir(a.cfg.Images.Postgres), "postgresql.conf")); err == nil {
				t.Fatal("marked complete")
			}
			if m := f.mutations(); m[len(m)-1] != "docker rm -f -- sp-extract-b3bfedb10741" {
				t.Fatalf("extract container left behind: %q", m)
			}
		})
	}
	// A single file that is a link, or not alone in its archive, is refused too.
	for name, passwd := range map[string][][3]string{
		"link":  {{"passwd", "l", "/etc/shadow"}},
		"extra": {{"passwd", "f", "x"}, {"shadow", "f", "y"}},
		"other": {{"group", "f", "x"}},
	} {
		t.Run("passwd "+name, func(t *testing.T) {
			a, f, _ := newTestAgent(t)
			imageCp(t, f, tarOf(t, [3]string{"./", "d", ""}))
			scripted := f.onRun
			f.onRun = func(args []string, in []byte) (string, error, bool) {
				if args[0] == "cp" && strings.HasSuffix(args[len(args)-2], ":/etc/passwd") {
					return tarOf(t, passwd...), nil, true
				}
				return scripted(args, in)
			}
			if err := a.EnsureImageFiles(context.Background()); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Lstat(filepath.Join(a.p.ImageDir(a.cfg.Images.Postgres), "passwd")); err == nil {
				t.Fatal("written")
			}
		})
	}
}

// ───────── node check ─────────

// goodNode arranges a node on which every node-check row passes.
func goodNode(t *testing.T) (*Agent, *fakeHost) {
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	_, pr := tenants(a, f, s)
	_ = pr
	root := a.p.Root
	put := func(rel, content string, mode os.FileMode) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
	}
	put("etc/docker/daemon.json", `{"default-address-pools":[{"base":"10.214.0.0/16","size":26}],"ipv6":false,"log-driver":"local","log-opts":{"max-file":"3","max-size":"10m"}}`, 0o644)
	put("proc/sys/kernel/yama/ptrace_scope", "1\n", 0o644)
	put("proc/sys/kernel/core_pattern", "core\n", 0o644)
	put("proc/sys/fs/file-max", "9223372036854775807\n", 0o644)
	put("etc/modprobe.d/supapace.conf", "install br_netfilter /bin/false\n", 0o644)
	put("etc/supapace/kek", strings.Repeat("k", 32), 0o400)
	put("proc/mounts", "overlay / overlay rw 0 0\n/dev/loop3 "+a.p.ProjectsDir()+" xfs rw,relatime,attr2,inode64,usrquota,prjquota 0 0\n", 0o644)
	f.info = `{"ServerVersion":"29.10.0","SecurityOptions":["name=seccomp,profile=builtin","name=cgroupns"],"LiveRestoreEnabled":false,"FirewallBackend":{"Driver":"iptables"}}`
	f.ip["-j -d link show"] = `[{"ifname":"lo"},{"ifname":"eth0"},{"ifname":"spl0","linkinfo":{"info_kind":"bridge"}},{"ifname":"veth1","linkinfo":{"info_kind":"veth"}}]`
	f.ip["-j route show default"] = `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0"}]`
	f.ip["-j -6 route show default"] = `[]`
	return a, f
}

func rows(t *testing.T, a *Agent) map[string]nodecfg.CheckResult {
	t.Helper()
	m := map[string]nodecfg.CheckResult{}
	for _, r := range a.NodeCheck(context.Background()) {
		if _, dup := m[r.Name]; dup {
			t.Fatalf("row %q twice", r.Name)
		}
		m[r.Name] = r
	}
	return m
}

var blockingRows = []string{"nft", "docker-version", "daemon.json", "live-restore", "docker-networks", "docker-seccomp",
	"uplinks", "quota-accounting", "quota-enforcement", "ptrace_scope", "kek", "platform-members", "core_pattern",
	"br_netfilter", "file-max"}

func TestNodeCheck_Rows(t *testing.T) {
	a, _ := goodNode(t)
	all := rows(t, a)
	for _, name := range append(blockingRows, "docker-firewall-backend") {
		r, ok := all[name]
		if !ok || !r.OK {
			t.Errorf("good node: row %q = %+v (present %v)", name, r, ok)
		}
	}
	if _, ok := all["drift-hold"]; ok {
		t.Error("drift-hold row without a hold file")
	}
	put := func(a *Agent, rel, content string) {
		p := filepath.Join(a.p.Root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.Remove(p)
		os.WriteFile(p, []byte(content), 0o644)
	}
	pr := "postgrest-" + testRef
	faults := []struct {
		name, row string
		fault     func(a *Agent, f *fakeHost)
	}{
		{"nft drift", "nft", func(a *Agent, f *fakeHost) { f.nftErr = nft.ErrDrift }},
		{"old docker", "docker-version", func(a *Agent, f *fakeHost) { f.version = "26.1.2" }},
		{"unparsable docker version", "docker-version", func(a *Agent, f *fakeHost) { f.version = "dev" }},
		{"docker unreachable", "docker-version", func(a *Agent, f *fakeHost) { f.failVerb["version"] = errors.New("no daemon") }},
		{"daemon.json missing", "daemon.json", func(a *Agent, f *fakeHost) { os.Remove(filepath.Join(a.p.Root, "etc/docker/daemon.json")) }},
		{"daemon.json other pool", "daemon.json", func(a *Agent, f *fakeHost) {
			put(a, "etc/docker/daemon.json", `{"default-address-pools":[{"base":"198.51.100.0/24","size":26}],"ipv6":false,"log-driver":"local","log-opts":{"max-file":"3","max-size":"10m"}}`)
		}},
		{"daemon.json ipv6", "daemon.json", func(a *Agent, f *fakeHost) {
			put(a, "etc/docker/daemon.json", `{"default-address-pools":[{"base":"10.214.0.0/16","size":26}],"ipv6":true,"log-driver":"local","log-opts":{"max-file":"3","max-size":"10m"}}`)
		}},
		{"daemon.json log driver", "daemon.json", func(a *Agent, f *fakeHost) {
			put(a, "etc/docker/daemon.json", `{"default-address-pools":[{"base":"10.214.0.0/16","size":26}],"ipv6":false,"log-driver":"json-file","log-opts":{"max-file":"3","max-size":"10m"}}`)
		}},
		{"daemon.json log size", "daemon.json", func(a *Agent, f *fakeHost) {
			put(a, "etc/docker/daemon.json", `{"default-address-pools":[{"base":"10.214.0.0/16","size":26}],"ipv6":false,"log-driver":"local","log-opts":{"max-file":"3"}}`)
		}},
		{"daemon.json userland-proxy", "daemon.json", func(a *Agent, f *fakeHost) {
			put(a, "etc/docker/daemon.json", `{"default-address-pools":[{"base":"10.214.0.0/16","size":26}],"ipv6":false,"log-driver":"local","log-opts":{"max-file":"3","max-size":"10m"},"userland-proxy":false}`)
		}},
		{"daemon.json icc", "daemon.json", func(a *Agent, f *fakeHost) {
			put(a, "etc/docker/daemon.json", `{"default-address-pools":[{"base":"10.214.0.0/16","size":26}],"ipv6":false,"log-driver":"local","log-opts":{"max-file":"3","max-size":"10m"},"icc":false}`)
		}},
		{"network with icc off", "daemon.json", func(a *Agent, f *fakeHost) {
			f.nets["ingress"].Options["com.docker.network.bridge.enable_icc"] = "false"
		}},
		{"live-restore on", "live-restore", func(a *Agent, f *fakeHost) {
			f.info = strings.Replace(f.info, `"LiveRestoreEnabled":false`, `"LiveRestoreEnabled":true`, 1)
		}},
		{"foreign network", "docker-networks", func(a *Agent, f *fakeHost) { f.net(fakeNet{Network: dockerx.Network{Name: "sp-test-unnamed"}}) }},
		{"macvlan driver", "docker-networks", func(a *Agent, f *fakeHost) {
			f.net(fakeNet{Network: dockerx.Network{Name: "proj-zzzzzzzzzzzzzzzzzzzz"}, Driver: "macvlan"})
		}},
		{"ipvlan interface", "docker-networks", func(a *Agent, f *fakeHost) {
			f.ip["-j -d link show"] = strings.Replace(f.ip["-j -d link show"], `]`, `,{"ifname":"ipv0","linkinfo":{"info_kind":"ipvlan"}}]`, 1)
		}},
		{"seccomp unconfined", "docker-seccomp", func(a *Agent, f *fakeHost) {
			f.info = strings.Replace(f.info, "profile=builtin", "profile=unconfined", 1)
		}},
		{"seccomp absent", "docker-seccomp", func(a *Agent, f *fakeHost) {
			f.info = strings.Replace(f.info, `"name=seccomp,profile=builtin",`, "", 1)
		}},
		{"uplink is a bridge", "uplinks", func(a *Agent, f *fakeHost) {
			f.ip["-j -d link show"] = strings.Replace(f.ip["-j -d link show"], `{"ifname":"eth0"}`, `{"ifname":"eth0","linkinfo":{"info_kind":"bridge"}}`, 1)
		}},
		{"default route over a bridge", "uplinks", func(a *Agent, f *fakeHost) {
			f.ip["-j -6 route show default"] = `[{"dst":"default","dev":"spl0"}]`
		}},
		{"recorded uplink gone", "uplinks", func(a *Agent, f *fakeHost) { a.cfg.Uplinks = []string{"eth0", "eth9"} }},
		{"quota off", "quota-accounting,quota-enforcement", func(a *Agent, f *fakeHost) {
			put(a, "proc/mounts", "/dev/loop3 "+a.p.ProjectsDir()+" xfs rw,relatime 0 0\n")
		}},
		{"project quota off", "quota-accounting", func(a *Agent, f *fakeHost) {
			put(a, "proc/mounts", "/dev/loop3 "+a.p.ProjectsDir()+" xfs rw,relatime,usrquota 0 0\n")
		}},
		{"projects not mounted", "quota-accounting,quota-enforcement", func(a *Agent, f *fakeHost) { put(a, "proc/mounts", "overlay / overlay rw 0 0\n") }},
		{"projects not xfs", "quota-accounting,quota-enforcement", func(a *Agent, f *fakeHost) {
			put(a, "proc/mounts", "/dev/loop3 "+a.p.ProjectsDir()+" ext4 rw,usrquota,prjquota 0 0\n")
		}},
		{"projects shadowed by a later mount", "quota-accounting,quota-enforcement", func(a *Agent, f *fakeHost) {
			put(a, "proc/mounts", "/dev/loop3 "+a.p.ProjectsDir()+" xfs rw,usrquota,prjquota 0 0\ntmpfs "+a.p.ProjectsDir()+" tmpfs rw 0 0\n")
		}},
		{"user quota not enforced", "quota-enforcement", func(a *Agent, f *fakeHost) {
			put(a, "proc/mounts", "/dev/loop3 "+a.p.ProjectsDir()+" xfs rw,uqnoenforce,prjquota 0 0\n")
		}},
		{"user quota off", "quota-accounting,quota-enforcement", func(a *Agent, f *fakeHost) {
			put(a, "proc/mounts", "/dev/loop3 "+a.p.ProjectsDir()+" xfs rw,prjquota 0 0\n")
		}},
		{"ptrace_scope 0", "ptrace_scope", func(a *Agent, f *fakeHost) { put(a, "proc/sys/kernel/yama/ptrace_scope", "0\n") }},
		{"no yama", "ptrace_scope", func(a *Agent, f *fakeHost) { os.Remove(filepath.Join(a.p.Root, "proc/sys/kernel/yama/ptrace_scope")) }},
		{"loose kek mode", "kek", func(a *Agent, f *fakeHost) { os.Chmod(a.p.KEK(), 0o440) }},
		{"kek a link", "kek", func(a *Agent, f *fakeHost) {
			os.Rename(a.p.KEK(), a.p.KEK()+".real")
			os.Symlink(a.p.KEK()+".real", a.p.KEK())
		}},
		{"kek short", "kek", func(a *Agent, f *fakeHost) {
			os.Chmod(a.p.KEK(), 0o600)
			put(a, "etc/supapace/kek", "x")
			os.Chmod(a.p.KEK(), 0o400)
		}},
		{"foreign platform member", "platform-members", func(a *Agent, f *fakeHost) {
			f.ctr(fakeCtr{Name: "intruder", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{"platform": "10.212.0.250"}})
		}},
		{"postgrest at another address", "platform-members", func(a *Agent, f *fakeHost) {
			f.ctrs[pr].Nets["platform"] = a.cfg.PlatformAddr(15).String()
		}},
		{"postgrest without its network", "platform-members", func(a *Agent, f *fakeHost) {
			delete(f.nets, "proj-"+testRef)
			delete(f.ctrs[pr].Nets, "proj-"+testRef)
			delete(f.ctrs["pg-"+testRef].Nets, "proj-"+testRef)
		}},
		{"postgrest with NET_RAW", "platform-members", func(a *Agent, f *fakeHost) { f.ctrs[pr].CapAdd = []string{"NET_RAW"} }},
		{"postgrest without its labels", "platform-members", func(a *Agent, f *fakeHost) { f.ctrs[pr].Labels = map[string]string{} }},
		{"postgrest's network not the platform's", "platform-members", func(a *Agent, f *fakeHost) {
			f.nets["proj-"+testRef].Internal = false
		}},
		{"gateway at another address", "platform-members", func(a *Agent, f *fakeHost) { f.ctrs["sp-gateway"].Nets["platform"] = "10.212.0.3" }},
		{"platform absent", "platform-members", func(a *Agent, f *fakeHost) {
			delete(f.nets, "platform")
			delete(f.ctrs["sp-gateway"].Nets, "platform")
			delete(f.ctrs[pr].Nets, "platform")
		}},
		{"core_pattern pipe", "core_pattern", func(a *Agent, f *fakeHost) { put(a, "proc/sys/kernel/core_pattern", "|/usr/lib/crash %p\n") }},
		{"br_netfilter loaded", "br_netfilter", func(a *Agent, f *fakeHost) { os.MkdirAll(filepath.Join(a.p.Root, "sys/module/br_netfilter"), 0o755) }},
		{"br_netfilter not blocked", "br_netfilter", func(a *Agent, f *fakeHost) { put(a, "etc/modprobe.d/supapace.conf", "# nothing\n") }},
		{"file-max low", "file-max", func(a *Agent, f *fakeHost) { put(a, "proc/sys/fs/file-max", "4194304\n") }},
	}
	for _, c := range faults {
		t.Run(c.name, func(t *testing.T) {
			a, f := goodNode(t)
			c.fault(a, f)
			got := rows(t, a)
			want := strings.Split(c.row, ",")
			for _, name := range blockingRows {
				r := got[name]
				if slices.Contains(want, name) && (r.OK || r.Detail == "") {
					t.Errorf("row %q passes: %+v", name, r)
				}
				if !slices.Contains(want, name) && !r.OK {
					t.Errorf("row %q fails too: %+v", name, r)
				}
			}
		})
	}
	// Owned by another uid: only root can arrange it (the node run covers it).
	t.Run("kek not root-owned", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("needs root to chown")
		}
		a, _ := goodNode(t)
		if err := os.Lchown(a.p.KEK(), 1, 1); err != nil {
			t.Fatal(err)
		}
		if r := rows(t, a)["kek"]; r.OK {
			t.Fatalf("row passes: %+v", r)
		}
	})
}

func TestNodeCheck_FirewallBackendInformational(t *testing.T) {
	a, f := goodNode(t)
	f.info = strings.Replace(f.info, `,"FirewallBackend":{"Driver":"iptables"}`, "", 1)
	r := rows(t, a)["docker-firewall-backend"]
	if !r.OK || r.Detail == "" {
		t.Fatalf("row %+v", r)
	}
	if r := rows(t, a)["docker-firewall-backend"]; !r.OK {
		t.Fatal(r)
	}
	f.info = `{"ServerVersion":"29.10.0","SecurityOptions":["name=seccomp,profile=builtin"],"FirewallBackend":{"Driver":"nftables"}}`
	if r := rows(t, a)["docker-firewall-backend"]; !r.OK || !strings.Contains(r.Detail, "nftables") {
		t.Fatalf("row %+v", r)
	}
}

func TestNodeCheck_DriftHoldRowIsInformational(t *testing.T) {
	a, _ := goodNode(t)
	hold := a.p.DriftHold()
	if err := os.WriteFile(hold, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-125 * time.Second)
	os.Chtimes(hold, old, old)
	got := rows(t, a)
	r, ok := got["drift-hold"]
	if !ok || !r.OK || !regexp.MustCompile(`age 12[5-9]s`).MatchString(r.Detail) {
		t.Fatalf("drift-hold row %+v (present %v)", r, ok)
	}
	for _, name := range blockingRows {
		if !got[name].OK {
			t.Errorf("row %q fails with a hold file", name)
		}
	}
	if a.ContainmentFailed() {
		t.Fatal("a hold file made the node containment_failed")
	}
}

func TestNodeCheck_DevModeHostGlobalRowsInformational(t *testing.T) {
	a, _ := goodNode(t)
	put := func(rel, content string) { os.WriteFile(filepath.Join(a.p.Root, rel), []byte(content), 0o644) }
	put("proc/sys/kernel/core_pattern", "|/usr/lib/crash %p\n")
	put("proc/sys/fs/file-max", "4194304\n")
	os.MkdirAll(filepath.Join(a.p.Root, "sys/module/br_netfilter"), 0o755)
	put("proc/sys/kernel/yama/ptrace_scope", "0\n")
	before := rows(t, a)
	for _, n := range []string{"core_pattern", "file-max", "br_netfilter", "ptrace_scope"} {
		if before[n].OK {
			t.Fatalf("control: %q passes without dev mode", n)
		}
	}
	marker := filepath.Join(filepath.Dir(a.p.NodeJSON()), "dev-mode")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	after := rows(t, a)
	for _, n := range []string{"core_pattern", "file-max", "br_netfilter"} {
		if !after[n].OK || !strings.Contains(after[n].Detail, "dev-mode") {
			t.Errorf("dev mode: %q = %+v, want informational", n, after[n])
		}
	}
	if after["ptrace_scope"].OK {
		t.Error("dev mode made ptrace_scope informational")
	}
}

// ───────── platform services' rows, stale hold, host-side project facts ─────────

// The gateway and control-plane rows pass for the containers the ensures
// made and fail, without blocking, when one is absent, stopped or created
// with another configuration.
func TestNodeCheck_PlatformServiceRows(t *testing.T) {
	a, f := goodNode(t)
	delete(f.ctrs, "sp-gateway")
	writeTLS(t, a)
	ctx := context.Background()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"gateway", "control-plane-db"} {
		if r := rows(t, a)[n]; !r.OK {
			t.Fatalf("control: %s row %+v after its ensure", n, r)
		}
	}
	for name, ctr := range map[string]string{"gateway": "sp-gateway", "control-plane-db": "sp-cp-db"} {
		c := f.ctrs[ctr]
		for what, change := range map[string]func(){
			"not running":   func() { c.Running = false },
			"configuration": func() { c.Labels["supapace.config"] = "other" },
			"absent":        func() { delete(f.ctrs, ctr) },
		} {
			saved := *c
			saved.Labels = maps.Clone(c.Labels)
			change()
			r := rows(t, a)[name]
			if r.OK || Blocking(r) {
				t.Errorf("%s %s: row %+v blocking %v; want failing, not blocking", name, what, r, Blocking(r))
			}
			f.ctrs[ctr] = c
			*c = saved
		}
	}
	if !Blocking(nodecfg.CheckResult{Name: "kek"}) || Blocking(nodecfg.CheckResult{Name: "kek", OK: true}) {
		t.Fatal("Blocking does not follow the other rows")
	}
	f.ctrs["sp-gateway"].Nets["platform"] = "10.212.0.9"
	if r := rows(t, a)["gateway"]; r.OK {
		t.Fatal("gateway at another platform address passes")
	}
}

func TestNodeCheck_DriftHoldStale(t *testing.T) {
	a, _ := goodNode(t)
	hold := a.p.DriftHold()
	if err := os.WriteFile(hold, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for age, want := range map[time.Duration]string{
		-time.Hour:       "stale, ignored",
		16 * time.Minute: "stale, ignored: age 96",
		time.Minute:      "present, age 6",
	} {
		ts := time.Now().Add(-age)
		os.Chtimes(hold, ts, ts)
		if r := rows(t, a)["drift-hold"]; !r.OK || !strings.HasPrefix(r.Detail, want) {
			t.Errorf("hold aged %v: row %+v, want detail %q…", age, r, want)
		}
	}
}

// CheckHost reads the project's containers and route from the host: all
// pass for adopted containers and an active route; a stopped or absent
// container, one off its networks, and a draining route fail by name.
func TestCheckHost(t *testing.T) {
	a, f, s, _ := clSetup(t)
	pg := clToPhaseB(t, a, f, s)
	s.FirstBoot = false
	s.Keys = prKeys(t)
	if err := a.EnsurePostgREST(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	r := a.RouteFor(s, "active")
	if _, err := a.SetRoute(context.Background(), s.Ref, &r); err != nil {
		t.Fatal(err)
	}
	failing := func() []string {
		var out []string
		for _, r := range a.CheckHost(context.Background(), s) {
			if !r.OK {
				out = append(out, r.Name)
			}
		}
		return out
	}
	if got := failing(); len(got) != 0 {
		t.Fatalf("control: healthy project fails %q: %+v", got, a.CheckHost(context.Background(), s))
	}
	for what, c := range map[string]struct {
		change func()
		want   string
	}{
		"rest stopped": {func() { f.ctrs["postgrest-"+s.Ref].Running = false }, "rest-container"},
		"rest off platform": {func() {
			f.ctrs["postgrest-"+s.Ref].Nets = map[string]string{"proj-" + s.Ref: a.cfg.PostgRESTAddr(s.SubnetIndex).String()}
		}, "rest-container"},
		"cluster stopped":  {func() { pg.Running = false }, "cluster-container"},
		"cluster absent":   {func() { delete(f.ctrs, "pg-"+s.Ref) }, "cluster-container"},
		"cluster off-net":  {func() { pg.Nets = map[string]string{} }, "cluster-container"},
		"other generation": {func() { pg.Labels["supapace.generation"] = "9" }, "cluster-container"},
		"route draining": {func() {
			r := a.RouteFor(s, "draining")
			a.SetRoute(context.Background(), s.Ref, &r)
		}, "route"},
	} {
		saved, savedPR := *pg, *f.ctrs["postgrest-"+s.Ref]
		saved.Labels, saved.Nets = maps.Clone(pg.Labels), maps.Clone(pg.Nets)
		savedPR.Nets = maps.Clone(savedPR.Nets)
		c.change()
		if got := failing(); !slices.Equal(got, []string{c.want}) {
			t.Errorf("%s: failing %q, want [%s]", what, got, c.want)
		}
		if what == "rest stopped" {
			if r := a.CheckHost(context.Background(), s)[1]; !strings.HasSuffix(r.Detail, " not running") {
				t.Errorf("rest stopped: detail %q, want it to say not running", r.Detail)
			}
		}
		*pg, *f.ctrs["postgrest-"+s.Ref] = saved, savedPR
		f.ctrs["pg-"+s.Ref] = pg
		r := a.RouteFor(s, "active")
		a.SetRoute(context.Background(), s.Ref, &r)
	}
}

// A platform container re-created by an ensure is announced first, in
// neutral words; one left untouched is not.
func TestEnsurePlatform_RecreationLogged(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	delete(f.ctrs, "sp-gateway")
	writeTLS(t, a)
	ctx := context.Background()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureGateway(ctx); err != nil { // healthy: untouched
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("logged without a re-creation:\n%s", &buf)
	}
	f.ctrs["sp-gateway"].Labels["supapace.config"] = "older"
	f.ctrs["sp-cp-db"].Labels["supapace.config"] = "older"
	f.ctrs["sp-cp-db"].Running = false
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	f.ctrs["sp-gateway"].Nets["platform"] = "10.212.0.9"
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`msg="re-creating sp-gateway: its configuration changed" was=running`,
		`msg="re-creating sp-cp-db: its configuration changed" was=stopped`,
		`msg="re-creating sp-gateway: its addresses changed" was=running`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("log lacks %s:\n%s", want, &buf)
		}
	}
	if strings.Contains(buf.String(), "--") || strings.Contains(buf.String(), "POSTGRES") {
		t.Errorf("arguments in the log:\n%s", &buf)
	}
}
