package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// NodeCheck reports one row per node-wide condition containment rests on.
// Every row is blocking (OK false makes the caller set containment_failed)
// except docker-firewall-backend and drift-hold, which are always OK; on a
// development node (the dev-mode marker) the host-global rows core_pattern,
// br_netfilter and file-max are informational too. Only host-side facts are
// read.
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
	add("ptrace_scope", a.checkPtrace())
	add("kek", a.checkKEK())
	add("platform-members", a.checkPlatformMembers(ctx))
	hostGlobal("core_pattern", a.checkCorePattern())
	hostGlobal("br_netfilter", a.checkBrNetfilter())
	hostGlobal("file-max", a.checkFileMax())

	fw := "not reported"
	if infoErr != nil {
		fw = infoErr.Error()
	} else if info.FirewallBackend != nil && info.FirewallBackend.Driver != "" {
		fw = info.FirewallBackend.Driver
	}
	rows = append(rows, nodecfg.CheckResult{Name: "docker-firewall-backend", OK: true, Detail: fw})
	if fi, err := os.Lstat(a.p.DriftHold()); err == nil {
		age := time.Since(fi.ModTime()) / time.Second
		rows = append(rows, nodecfg.CheckResult{Name: "drift-hold", OK: true, Detail: fmt.Sprintf("present, age %ds", age)})
	}
	return rows
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

// checkNetworks: only the platform's networks and Docker's defaults exist,
// all with the bridge, host or null driver, and no macvlan or ipvlan
// interface besides the uplinks.
func (a *Agent) checkNetworks(nets []dockerNet, links map[string]string) error {
	for _, n := range nets {
		ref, isProject := strings.CutPrefix(n.name, "proj-")
		known := n.name == "bridge" || n.name == "host" || n.name == "none" || n.name == platformNet ||
			n.name == ingressNet || (isProject && refRE.MatchString(ref))
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
	b, err := os.ReadFile(a.host("/proc/mounts"))
	if err != nil {
		return err, err
	}
	var fstype string
	var opts []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 4 && unescapeMount(f[1]) == a.p.ProjectsDir() {
			fstype, opts = f[2], strings.Split(f[3], ",")
		}
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
// gateway's address or the PostgREST of a project at PlatformAddr of its
// project network's slice, and none could hold a capability.
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
	s, _ := strings.CutPrefix(pn.BridgeName, "spp")
	i, err := strconv.Atoi(s)
	if err != nil || nodecfg.BridgeName(i) != pn.BridgeName || a.projectNetMismatch(pn, i) != "" {
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
