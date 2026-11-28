package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
)

// NodeCheck reports one row per node-wide condition containment rests on.
// Every row is blocking (OK false makes the caller set containment_failed)
// except docker-firewall-backend and drift-hold, which are always OK; on a
// development node (the dev-mode marker) the host-global rows core_pattern,
// br_netfilter, file-max and protected-hardlinks are informational too. The rows gateway and
// control-plane-db report the platform services (running, with this
// daemon's configuration): they fail but do not block (Blocking). On a node
// whose dashboard is configured the wire proxy has two rows: proxy, its
// liveness, which does not block either, and proxy-networks, which does.
// Only host-side facts are read.
func (a *Agent) NodeCheck(ctx context.Context) []nodecfg.CheckResult {
	var rows []nodecfg.CheckResult
	add := func(name string, err error) {
		r := nodecfg.CheckResult{Name: name, OK: err == nil}
		if err != nil {
			r.Detail = err.Error()
		}
		rows = append(rows, r)
	}
	dev := isRegular(filepath.Join(filepath.Dir(a.p.NodeJSON()), "dev-mode"))
	hostGlobal := func(name string, err error) {
		if err != nil && dev {
			rows = append(rows, nodecfg.CheckResult{Name: name, OK: true, Detail: "informational (dev-mode): " + err.Error()})
			return
		}
		add(name, err)
	}

	add("nft", nftCheck(ctx, a.p))
	add("docker-version", checkDockerVersion(ctx))
	info, infoErr := dockerInfo(ctx)
	nets, netsErr := dockerNetworks(ctx)
	links, linksErr := a.links(ctx)
	add("daemon.json", a.checkDaemonJSON(ctx, nets, netsErr))
	add("live-restore", orErr(infoErr, func() error {
		if info.LiveRestoreEnabled {
			return errors.New("Docker live-restore is on")
		}
		return nil
	}))
	add("docker-seccomp", orErr(infoErr, info.checkSeccomp))
	add("docker-networks", orErr(errors.Join(netsErr, linksErr), func() error { return a.checkNetworks(nets, links) }))
	add("uplinks", orErr(linksErr, func() error { return a.checkUplinks(ctx, links) }))
	acct, enf := a.checkQuota()
	add("quota-accounting", acct)
	add("quota-enforcement", enf)
	add("repo-filesystem", a.checkRepoFS())
	add("ptrace_scope", a.checkPtrace())
	add("kek", a.checkKEK())
	add("platform-members", a.checkPlatformMembers(ctx))
	add("project-addresses", orErr(netsErr, func() error { return a.checkProjectAddresses(ctx, nets) }))
	add("forwarding", a.checkForwarding(ctx))
	// The wire proxy, where the node has one: where it sits and what its table
	// serves (blocking), and below, with the platform's services, its liveness.
	ad, dash, _ := a.dashAddrs()
	var proxyLive error
	if dash {
		var proxyNets error
		proxyLive, proxyNets = a.checkProxy(ctx, ad)
		add(rowProxyNetworks, proxyNets)
	}
	hostGlobal("core_pattern", a.checkCorePattern())
	hostGlobal("br_netfilter", a.checkBrNetfilter())
	hostGlobal("file-max", a.checkFileMax())
	hostGlobal("protected-hardlinks", a.checkProtectedHardlinks())

	fw := "not reported"
	if infoErr != nil {
		fw = infoErr.Error()
	} else if info.FirewallBackend != nil && info.FirewallBackend.Driver != "" {
		fw = info.FirewallBackend.Driver
	}
	rows = append(rows, nodecfg.CheckResult{Name: "docker-firewall-backend", OK: true, Detail: fw})
	if fi, err := os.Lstat(a.p.DriftHold()); err == nil {
		age := time.Since(fi.ModTime())
		d := fmt.Sprintf("present, age %ds: drift check and project repairs paused", age/time.Second)
		if age < 0 || age >= DriftHoldMax {
			d = fmt.Sprintf("stale, ignored: age %ds, honoured below %ds", age/time.Second, DriftHoldMax/time.Second)
		}
		rows = append(rows, nodecfg.CheckResult{Name: "drift-hold", OK: true, Detail: d})
	}
	add(rowControlPlane, a.checkPlatformContainer(ctx, cpName, nil, func() (string, error) {
		_, _, conf, err := a.cpConfig()
		return conf, err
	}))
	add(rowGateway, a.checkPlatformContainer(ctx, gatewayName,
		map[string]string{ingressNet: a.cfg.GatewayIngressIP, platformNet: a.cfg.GatewayIP}, func() (string, error) {
			_, _, conf, err := a.gatewayConfig(ctx)
			return conf, err
		}))
	if dash {
		add(rowProxy, proxyLive)
	}
	return rows
}

// DriftHoldMax: the drift timer honours a hold file younger than this.
const DriftHoldMax = 15 * time.Minute

// The node-check rows of the platform's own services. They fail while the
// service is not running as configured, which the daemon repairs; they are
// not containment.
const (
	rowControlPlane = "control-plane-db"
	rowGateway      = "gateway"
)

// Blocking reports whether r is a failing row that makes the node
// containment_failed: every failing row except the platform services' — the
// control-plane database, the gateway and the wire proxy's liveness (a proxy
// that is down, or between an ensure's removal and creation, is an outage;
// where it sits is the row proxy-networks, which blocks).
func Blocking(r nodecfg.CheckResult) bool {
	return !r.OK && r.Name != rowControlPlane && r.Name != rowGateway && r.Name != rowProxy
}

// checkPlatformContainer: name exists, runs, carries the configuration label
// this daemon would create it with, and holds the given addresses.
func (a *Agent) checkPlatformContainer(ctx context.Context, name string, addrs map[string]string, conf func() (string, error)) error {
	c, err := dockerInspectContainer(ctx, name)
	switch {
	case err != nil:
		return err
	case c == nil:
		return fmt.Errorf("%s absent", name)
	case !c.Running:
		return fmt.Errorf("%s not running", name)
	}
	want, err := conf()
	if err != nil {
		return err
	}
	if c.Labels[labelConfig] != want {
		return fmt.Errorf("%s runs with another configuration than this daemon's", name)
	}
	for n, ip := range addrs {
		if c.IPs[n] != ip {
			return fmt.Errorf("%s at %q on %s, want %s", name, c.IPs[n], n, ip)
		}
	}
	return nil
}

// CheckHost reports the host-side facts of s's project, read from Docker,
// state.json and the route file, never from a tenant process: its cluster
// and PostgREST containers exist, run, carry the labels and addresses an
// adoption requires, and its route is active. Rows: cluster-container,
// rest-container, route.
func (a *Agent) CheckHost(ctx context.Context, s Spec) []nodecfg.CheckResult {
	var rows []nodecfg.CheckResult
	add := func(name string, err error) {
		r := nodecfg.CheckResult{Name: name, OK: err == nil}
		if err != nil {
			r.Detail = err.Error()
		}
		rows = append(rows, r)
	}
	if err := a.clusterSpec(s); err != nil {
		add("cluster-container", err)
		return rows
	}
	add("cluster-container", a.checkClusterHost(ctx, s))
	add("rest-container", a.checkRESTHost(ctx, s))
	add("route", a.checkRouteHost(s.Ref))
	return rows
}

func (a *Agent) checkClusterHost(ctx context.Context, s Spec) error {
	name := clusterName(s.Ref)
	c, err := dockerInspectContainer(ctx, name)
	switch {
	case err != nil:
		return err
	case c == nil:
		return fmt.Errorf("%s absent", name)
	case !c.Running:
		return fmt.Errorf("%s not running", name)
	}
	st, have, err := a.readState(s.Ref)
	if err != nil {
		return err
	}
	if !have || st.Phase != PhaseB || st.Epoch != s.Epoch || !a.clusterAdoptable(s, st, c) {
		return fmt.Errorf("%s is not the container state.json records at generation %d", name, s.Generation)
	}
	want := map[string]string{networkName(s.Ref): a.cfg.ClusterAddr(s.SubnetIndex).String()}
	if !maps.Equal(c.IPs, want) {
		return fmt.Errorf("%s on networks %v, want %v", name, c.IPs, want)
	}
	return nil
}

func (a *Agent) checkRESTHost(ctx context.Context, s Spec) error {
	name := postgrestName(s.Ref)
	confs, err := a.existing(ctx, name)
	switch {
	case err != nil:
		return err
	case len(confs) == 0:
		return fmt.Errorf("%s absent", name)
	case !confs[0].Running:
		return fmt.Errorf("%s not running", name)
	}
	fileHash, err := renderedHash(a.postgrestDir(s.Ref), postgrestConf)
	if err != nil {
		return err
	}
	flags, tail := a.postgrestArgs(s)
	label, err := a.configLabel(fileHash, slices.Concat(flags, tail))
	if err != nil {
		return err
	}
	if !a.adoptable(confs[0], s, label) {
		return fmt.Errorf("%s does not carry the desired labels or is not on exactly %s and %s at its addresses", name, networkName(s.Ref), platformNet)
	}
	return nil
}

func (a *Agent) checkRouteHost(ref string) error {
	f, err := a.readRoutes()
	if err != nil {
		return err
	}
	r, ok := f.Projects[ref]
	switch {
	case !ok:
		return errors.New("no route: requests answer 404")
	case r.State != "active":
		return fmt.Errorf("route %s: requests answer 503", r.State)
	}
	return nil
}

// orErr is err when set, else check().
func orErr(err error, check func() error) error {
	if err != nil {
		return err
	}
	return check()
}

func isRegular(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().IsRegular()
}

var versionRE = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)

// checkDockerVersion requires Docker 26.1.3 or later.
func checkDockerVersion(ctx context.Context) error {
	v, err := dockerServerVersion(ctx)
	if err != nil {
		return err
	}
	m := versionRE.FindStringSubmatch(v)
	if m == nil {
		return fmt.Errorf("Docker version %q not understood", v)
	}
	have := [3]int{}
	for i := range have {
		have[i], _ = strconv.Atoi(m[i+1])
	}
	for i, min := range [3]int{26, 1, 3} {
		if have[i] != min {
			if have[i] < min {
				return fmt.Errorf("Docker %s is older than 26.1.3", v)
			}
			break
		}
	}
	return nil
}

type dockerInfoJSON struct {
	SecurityOptions    []string
	LiveRestoreEnabled bool
	FirewallBackend    *struct{ Driver string }
}

func dockerInfo(ctx context.Context) (dockerInfoJSON, error) {
	var info dockerInfoJSON
	out, err := dockerRun(ctx, "info", "--format", "{{json .}}")
	if err != nil {
		return info, err
	}
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return info, fmt.Errorf("docker info: parse: %w", err)
	}
	return info, nil
}

// checkSeccomp requires Docker's seccomp support with a profile other than unconfined.
func (info dockerInfoJSON) checkSeccomp() error {
	for _, o := range info.SecurityOptions {
		kv := map[string]string{}
		for _, f := range strings.Split(o, ",") {
			k, v, _ := strings.Cut(f, "=")
			kv[k] = v
		}
		if kv["name"] == "seccomp" {
			if p := kv["profile"]; p == "" || p == "unconfined" {
				return fmt.Errorf("Docker seccomp profile %q", p)
			}
			return nil
		}
	}
	return errors.New("Docker reports no seccomp support")
}

type dockerNet struct{ name, driver string }

func dockerNetworks(ctx context.Context) ([]dockerNet, error) {
	out, err := dockerRun(ctx, "network", "ls", "--format", "{{.Name}} {{.Driver}}")
	if err != nil {
		return nil, err
	}
	var nets []dockerNet
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			nets = append(nets, dockerNet{f[0], f[1]})
		} else if l != "" {
			return nil, fmt.Errorf("docker network ls: unexpected line %q", l)
		}
	}
	return nets, nil
}

// checkDaemonJSON requires daemon.json to carry the node's address pool,
// ipv6 off and the local log driver with size limits, and no userland-proxy
// or icc key; and no network to turn inter-container traffic off.
func (a *Agent) checkDaemonJSON(ctx context.Context, nets []dockerNet, netsErr error) error {
	path := a.host("/etc/docker/daemon.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var d struct {
		Pools []struct {
			Base string
			Size int
		} `json:"default-address-pools"`
		IPv6      *bool             `json:"ipv6"`
		LogDriver string            `json:"log-driver"`
		LogOpts   map[string]string `json:"log-opts"`
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	pool := false
	for _, p := range d.Pools {
		pool = pool || (p.Base == a.cfg.DockerPool && p.Size == a.cfg.DockerPoolSize)
	}
	switch {
	case !pool:
		return fmt.Errorf("%s: no address pool %s/%d", path, a.cfg.DockerPool, a.cfg.DockerPoolSize)
	case d.IPv6 == nil || *d.IPv6:
		return fmt.Errorf("%s: ipv6 is not false", path)
	case d.LogDriver != "local" || d.LogOpts["max-size"] == "" || d.LogOpts["max-file"] == "":
		return fmt.Errorf("%s: log driver is not local with max-size and max-file", path)
	}
	for _, k := range []string{"userland-proxy", "icc"} {
		if _, ok := keys[k]; ok {
			return fmt.Errorf("%s: carries %q", path, k)
		}
	}
	if netsErr != nil {
		return netsErr
	}
	names := []string{"inspect", "--format", `{{.Name}} {{index .Options "com.docker.network.bridge.enable_icc"}}`, "--"}
	for _, n := range nets {
		names = append(names, n.name)
	}
	out, err := dockerRun(ctx, append([]string{"network"}, names...)...)
	if err != nil {
		return err
	}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[1] == "false" {
			return fmt.Errorf("network %s turns inter-container traffic off", f[0])
		}
	}
	return nil
}

// links maps every interface to its kind ("" for a physical one).
func (a *Agent) links(ctx context.Context) (map[string]string, error) {
	out, err := runIP(ctx, "-j", "-d", "link", "show")
	if err != nil {
		return nil, err
	}
	var ls []struct {
		IfName   string `json:"ifname"`
		LinkInfo struct {
			InfoKind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(out, &ls); err != nil {
		return nil, fmt.Errorf("ip link: parse: %w", err)
	}
	m := map[string]string{}
	for _, l := range ls {
		m[l.IfName] = l.LinkInfo.InfoKind
	}
	return m, nil
}

// checkNetworks: only the platform's networks (the backup network among them)
// and Docker's defaults exist,
// all with the bridge, host or null driver, and no macvlan or ipvlan
// interface besides the uplinks.
func (a *Agent) checkNetworks(nets []dockerNet, links map[string]string) error {
	for _, n := range nets {
		ref, isProject := strings.CutPrefix(n.name, "proj-")
		known := n.name == "bridge" || n.name == "host" || n.name == "none" || n.name == platformNet ||
			n.name == ingressNet || n.name == nodecfg.BackupNetwork || (isProject && refRE.MatchString(ref))
		if !known {
			return fmt.Errorf("network %s is not the platform's", n.name)
		}
		if n.driver != "bridge" && n.driver != "host" && n.driver != "null" {
			return fmt.Errorf("network %s has driver %s", n.name, n.driver)
		}
	}
	for name, kind := range links {
		if (kind == "macvlan" || kind == "ipvlan") && !slices.Contains(a.cfg.Uplinks, name) {
			return fmt.Errorf("interface %s is of kind %s", name, kind)
		}
	}
	return nil
}

// checkUplinks: every interface recorded in node.json, and every one that
// carries a default route now, exists and is not a bridge.
func (a *Agent) checkUplinks(ctx context.Context, links map[string]string) error {
	ifs := append([]string(nil), a.cfg.Uplinks...)
	for _, fam := range [][]string{{"-j", "route", "show", "default"}, {"-j", "-6", "route", "show", "default"}} {
		out, err := runIP(ctx, fam...)
		if err != nil {
			return err
		}
		var routes []struct{ Dev string }
		if err := json.Unmarshal(out, &routes); err != nil {
			return fmt.Errorf("ip route: parse: %w", err)
		}
		for _, r := range routes {
			if r.Dev != "" && !slices.Contains(ifs, r.Dev) {
				ifs = append(ifs, r.Dev)
			}
		}
	}
	for _, name := range ifs {
		kind, ok := links[name]
		switch {
		case !ok:
			return fmt.Errorf("uplink %s does not exist", name)
		case kind == "bridge":
			return fmt.Errorf("uplink %s is a bridge", name)
		}
	}
	return nil
}

// checkQuota reads the topmost mount of the projects directory: user and
// project quota accounting on (accounting), user quota enforced (enforcement).
func (a *Agent) checkQuota() (accounting, enforcement error) {
	fstype, opts, err := a.topMount(a.p.ProjectsDir())
	if err != nil {
		return err, err
	}
	if fstype == "" {
		err := fmt.Errorf("%s is not a mount point", a.p.ProjectsDir())
		return err, err
	}
	if fstype != "xfs" {
		err := fmt.Errorf("%s is %s, not xfs", a.p.ProjectsDir(), fstype)
		return err, err
	}
	user := slices.Contains(opts, "usrquota") || slices.Contains(opts, "uqnoenforce")
	project := slices.Contains(opts, "prjquota") || slices.Contains(opts, "pqnoenforce")
	if !user || !project {
		accounting = fmt.Errorf("%s: user and project quota accounting not both on", a.p.ProjectsDir())
	}
	if !slices.Contains(opts, "usrquota") {
		enforcement = fmt.Errorf("%s: user quota not enforced", a.p.ProjectsDir())
	}
	return accounting, enforcement
}

// topMount reads /proc/mounts for the topmost mount at dir: its type and
// options; "" when dir is not a mount point.
func (a *Agent) topMount(dir string) (fstype string, opts []string, err error) {
	b, err := os.ReadFile(a.host("/proc/mounts"))
	if err != nil {
		return "", nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 4 && unescapeMount(f[1]) == dir {
			fstype, opts = f[2], strings.Split(f[3], ",")
		}
	}
	return fstype, opts, sc.Err()
}

// statDev is the device number of the filesystem holding path (a seam).
var statDev = func(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil
}

// repoMountOpts are what the repository filesystem must be mounted with.
var repoMountOpts = []string{"usrquota", "nosuid", "nodev", "noexec"}

// checkRepoFS: the repository root is the topmost mount at its path, XFS,
// with user quotas enforced and mounted nosuid, nodev and noexec. Every
// failure says how to make it so.
func (a *Agent) checkRepoFS() error {
	root := a.p.RepoRoot()
	fix := "mount an XFS filesystem there with the options " + strings.Join(repoMountOpts, ",")
	fstype, opts, err := a.topMount(root)
	switch {
	case err != nil:
		return fmt.Errorf("the mount table is unreadable (%s): %s", pgsock.Sanitize(err.Error(), 128), fix)
	case fstype == "":
		return fmt.Errorf("%s is not a mount point: %s", root, fix)
	case fstype != "xfs":
		return fmt.Errorf("%s is %s, not XFS: %s", root, pgsock.Sanitize(fstype, 32), fix)
	}
	var missing []string
	for _, o := range repoMountOpts {
		if !slices.Contains(opts, o) {
			missing = append(missing, o)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s is mounted without %s: remount it with %s (user quotas are enforced only with usrquota, set at mount time)",
			root, strings.Join(missing, ","), strings.Join(repoMountOpts, ","))
	}
	// By device, not by mount source: one device can be mounted under two names.
	rd, err := statDev(root)
	if err == nil {
		var pd uint64
		if pd, err = statDev(a.p.ProjectsDir()); err == nil && pd == rd {
			return fmt.Errorf("%s is the projects filesystem: %s, a filesystem of its own", root, fix)
		}
	}
	if err != nil {
		return fmt.Errorf("the device of %s is unreadable (%s): %s", root, pgsock.Sanitize(err.Error(), 128), fix)
	}
	return nil
}

// checkProtectedHardlinks: fs.protected_hardlinks is 1, so no process can
// link a file it does not own into a directory it can write.
func (a *Agent) checkProtectedHardlinks() error {
	const fix = "set fs.protected_hardlinks = 1 in /etc/sysctl.d/90-supapace.conf and run sysctl --system"
	v, err := a.readInt("/proc/sys/fs/protected_hardlinks")
	if err != nil {
		return fmt.Errorf("fs.protected_hardlinks unreadable (%s): %s", pgsock.Sanitize(err.Error(), 128), fix)
	}
	if v != 1 {
		return fmt.Errorf("fs.protected_hardlinks is %d, want 1: %s", v, fix)
	}
	return nil
}

// unescapeMount undoes the octal escapes of /proc/mounts (\040 for a space).
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (a *Agent) readInt(path string) (int64, error) {
	b, err := os.ReadFile(a.host(path))
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}

// checkPtrace: at 0 a process could attach to another of the same uid.
func (a *Agent) checkPtrace() error {
	v, err := a.readInt("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return err
	}
	if v < 1 {
		return fmt.Errorf("kernel.yama.ptrace_scope is %d, want at least 1", v)
	}
	return nil
}

// checkKEK: the key-encryption key is a regular 32-byte file, mode 0400,
// owned by the daemon's uid (root).
func (a *Agent) checkKEK() error {
	fi, err := os.Lstat(a.p.KEK())
	if err != nil {
		return err
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", a.p.KEK())
	case fi.Mode() != 0o400:
		return fmt.Errorf("%s has mode %v, want 0400", a.p.KEK(), fi.Mode())
	case st == nil || int(st.Uid) != os.Geteuid():
		return fmt.Errorf("%s is not owned by uid %d", a.p.KEK(), os.Geteuid())
	case fi.Size() != 32:
		return fmt.Errorf("%s holds %d bytes, want 32", a.p.KEK(), fi.Size())
	}
	return nil
}

// checkPlatformMembers: every container on platform is sp-gateway at the
// gateway's address, the PostgREST of a project at PlatformAddr of its
// project network's slice or, on a node whose dashboard is configured, one of
// the dashboard's four with its role label at its address; and none could
// hold a capability.
func (a *Agent) checkPlatformMembers(ctx context.Context) error {
	plat, err := dockerInspectNetwork(ctx, platformNet)
	if err != nil {
		return err
	}
	if plat == nil {
		return fmt.Errorf("network %s absent", platformNet)
	}
	ids, err := memberIDs(ctx, platformNet) // by id, never by name
	if err != nil {
		return err
	}
	confs, err := inspectConfigs(ctx, ids)
	if err != nil {
		return err
	}
	var dash []dashMember
	if ad, ok, _ := a.dashAddrs(); ok {
		dash = dashMembers(ad)
	}
	for _, c := range confs {
		if why := c.capViolation(); why != "" {
			return fmt.Errorf("%s: %s", c.name(), why)
		}
		addr, _ := c.addr(platformNet)
		if c.name() == gatewayName {
			if addr != a.cfg.GatewayIP {
				return fmt.Errorf("%s at %s, want %s", gatewayName, addr, a.cfg.GatewayIP)
			}
			continue
		}
		if i := slices.IndexFunc(dash, func(m dashMember) bool { return m.name == c.name() }); i >= 0 {
			if m := dash[i]; addr != m.addr || c.Labels[labelRole] != m.role {
				return fmt.Errorf("%s at %s: not at %s with the role label %s", c.name(), addr, m.addr, m.role)
			}
			continue
		}
		if err := a.checkPostgRESTMember(ctx, c, addr); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) checkPostgRESTMember(ctx context.Context, c ctrConf, addr string) error {
	ref, ok := strings.CutPrefix(c.name(), "postgrest-")
	if !ok || !refRE.MatchString(ref) || c.Labels[labelRole] != "postgrest" || c.Labels["supapace.ref"] != ref {
		return fmt.Errorf("foreign member %s", c.name())
	}
	pn, err := dockerInspectNetwork(ctx, networkName(ref))
	if err != nil {
		return err
	}
	if pn == nil {
		return fmt.Errorf("%s: no project network", c.name())
	}
	i, ok := a.sliceOf(pn)
	if !ok {
		return fmt.Errorf("%s: project network is not the platform's", c.name())
	}
	if want := a.cfg.PlatformAddr(i).String(); addr != want {
		return fmt.Errorf("%s at %s, want %s", c.name(), addr, want)
	}
	return nil
}

func (a *Agent) checkCorePattern() error {
	b, err := os.ReadFile(a.host("/proc/sys/kernel/core_pattern"))
	if err != nil {
		return err
	}
	if strings.HasPrefix(string(b), "|") {
		return errors.New("kernel.core_pattern pipes core dumps to a helper")
	}
	return nil
}

// modprobeDirs are where a modprobe `install` line may live.
var modprobeDirs = []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"}

// checkBrNetfilter: the module is not loaded and is kept from loading.
func (a *Agent) checkBrNetfilter() error {
	if _, err := os.Lstat(a.host("/sys/module/br_netfilter")); err == nil {
		return errors.New("br_netfilter is loaded")
	}
	for _, d := range modprobeDirs {
		files, _ := filepath.Glob(filepath.Join(a.host(d), "*.conf"))
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, l := range strings.Split(string(b), "\n") {
				if strings.Join(strings.Fields(l), " ") == "install br_netfilter /bin/false" {
					return nil
				}
			}
		}
	}
	return errors.New("no modprobe line keeps br_netfilter from loading")
}

func (a *Agent) checkFileMax() error {
	b, err := os.ReadFile(a.host("/proc/sys/fs/file-max"))
	if err != nil {
		return err
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return err
	}
	if v < 1<<30 {
		return fmt.Errorf("fs.file-max is %d, want at least %d", v, 1<<30)
	}
	return nil
}

// checkProjectAddresses holds the members of every network named like a
// project's to the start gate's member rule (memberViolation): an extra or a
// misplaced member fails the row, a missing one does not. Members are read as
// the gate reads them (by id; an endpoint key is read again).
// Cost: three Docker calls per project network; read the networks in one
// call if a full node's check takes too long.
func (a *Agent) checkProjectAddresses(ctx context.Context, nets []dockerNet) error {
	for _, n := range nets {
		ref, ok := strings.CutPrefix(n.name, "proj-")
		if !ok {
			continue
		}
		pn, err := dockerInspectNetwork(ctx, n.name)
		if err != nil {
			return err
		}
		if pn == nil { // removed since the listing
			continue
		}
		ids, err := memberIDs(ctx, n.name)
		if err != nil {
			return err
		}
		confs, err := inspectConfigs(ctx, ids)
		if err != nil {
			return err
		}
		i, slice := a.sliceOf(pn)
		for _, c := range confs {
			if !slice {
				return fmt.Errorf("%s: member rule: %s is on it, and it is not a slice of this node", n.name, c.name())
			}
			if why := a.memberViolation(c, ref, i); why != "" {
				return errors.New(why)
			}
		}
	}
	return nil
}

// checkForwarding: Docker's record of every platform container with
// interfaces on two networks — sp-gateway, every PostgREST and, where it
// exists, sp-pgcap — holds the settings of dashcfg.NoForwardArgs, each at
// its value. The gateway and a PostgREST are judged when they carry the
// configuration label this daemon gives them now: one with another label
// (an older daemon's, or of a file that changed since) is never adopted and
// is made again at its next ensure, and the rows gateway and rest-container
// report it meanwhile.
func (a *Agent) checkForwarding(ctx context.Context) error {
	var ids []string
	for _, name := range []string{gatewayName, dashcfg.PgcapName} {
		c, err := dockerInspectContainer(ctx, name)
		if err != nil {
			return err
		}
		if c != nil {
			ids = append(ids, c.ID)
		}
	}
	rest, err := dockerListContainers(ctx, labelRole+"=postgrest")
	if err != nil {
		return err
	}
	for _, c := range rest {
		ids = append(ids, c.ID)
	}
	slices.Sort(ids)
	confs, err := inspectConfigs(ctx, slices.Compact(ids))
	if err != nil {
		return err
	}
	for _, c := range confs {
		switch c.name() {
		case dashcfg.PgcapName:
		case gatewayName:
			if _, _, conf, err := a.gatewayConfig(ctx); err != nil || c.Labels[labelConfig] != conf {
				continue
			}
		default:
			if !a.ownPostgREST(c) {
				continue
			}
		}
		for _, kv := range dashcfg.NoForwardArgs() {
			if k, v, ok := strings.Cut(kv, "="); ok && c.Sysctls[k] != v {
				return fmt.Errorf("%s was not created with %s", c.name(), kv)
			}
		}
	}
	return nil
}

// ownPostgREST reports whether c carries the configuration label this daemon
// gives the PostgREST of c's own ref, generation and epoch at c's platform
// address, with postgrest.conf as now rendered.
func (a *Agent) ownPostgREST(c ctrConf) bool {
	ref := c.Labels[labelRef]
	if checkRef(ref) != nil { // a path is built from it
		return false
	}
	// A label that is no number gives arguments, and so a label, of its own.
	gen, _ := strconv.ParseInt(c.Labels[labelGeneration], 10, 64)
	epoch, _ := strconv.ParseInt(c.Labels[labelEpoch], 10, 64)
	addr, _ := c.addr(platformNet)
	i := 0
	for i < a.cfg.Slices() && a.cfg.PlatformAddr(i).String() != addr {
		i++
	}
	fileHash, err := renderedHash(a.postgrestDir(ref), postgrestConf)
	if err != nil {
		return false
	}
	flags, tail := a.postgrestArgs(Spec{Ref: ref, SubnetIndex: i, Generation: gen, Epoch: epoch})
	label, err := a.configLabel(fileHash, slices.Concat(flags, tail))
	return err == nil && c.Labels[labelConfig] == label
}
