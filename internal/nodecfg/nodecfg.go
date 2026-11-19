// Package nodecfg holds a node's configuration (node.json), its fixed defaults,
// the project-slice arithmetic and every on-disk path. It is shared by the daemon,
// the agent, the CLI and the test suite.
package nodecfg

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	NodeID           string   `json:"node_id"`
	Domain           string   `json:"domain"`
	ProjectBlock     string   `json:"project_block"`
	SlicePrefix      int      `json:"slice_prefix"`
	PlatformSubnet   string   `json:"platform_subnet"`
	PlatformIPRange  string   `json:"platform_ip_range"`
	GatewayIP        string   `json:"gateway_ip"`
	IngressSubnet    string   `json:"ingress_subnet"`
	GatewayIngressIP string   `json:"gateway_ingress_ip"`
	DockerPool       string   `json:"docker_pool"`
	DockerPoolSize   int      `json:"docker_pool_size"`
	UIDBase          int      `json:"uid_base"`
	UIDCount         int      `json:"uid_count"`
	MemAllocMB       int      `json:"mem_alloc_mb"`
	PidsAlloc        int      `json:"pids_alloc"`
	Retention        string   `json:"retention"`
	Uplinks          []string `json:"uplinks"`
	Images           Images   `json:"images"`
	BackupSubnet     string   `json:"backup_subnet"`              // an older node.json without it loads with the default
	CPDiskQuotaMB    int      `json:"cp_disk_quota_mb,omitempty"` // 0: not set, resolved at use by CPQuotas
	CPRepoQuotaMB    int      `json:"cp_repo_quota_mb,omitempty"` // likewise
}

type Images struct {
	Postgres     string `json:"postgres"` // name@sha256:…
	PostgREST    string `json:"postgrest"`
	ControlPlane string `json:"control_plane"`
	Gateway      string `json:"gateway"` // always GatewayImage
	Worker       string `json:"worker"`  // always WorkerImage
}

// GatewayImage is the locally built gateway image (make images).
const GatewayImage = "supapace-gateway:local"

const PlatformBridge, IngressBridge = "spl0", "spi0"

const (
	ReplicatorUID       = 65530 // also its gid
	ControlPlaneUID     = 70    // also its gid
	BackupBridge        = "spb0"
	BackupNetwork       = "backup"
	WorkerImage         = "supapace-worker:local" // the locally built backup worker image
	ControlPlaneSubject = "cp"                    // the control plane's name among backup subjects
)

// defaultBackupSubnet is the backup network, also of a node.json that predates it.
const defaultBackupSubnet = "10.212.9.0/24"

// CheckResult is one row of a node check; shared by the agent and the admin API.
type CheckResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// platformAddrOffset: PostgREST of slice i sits at platform subnet base + 16 + i.
const platformAddrOffset = 16

// Default returns the fixed node configuration for domain. The admission
// ceilings and the uplinks are computed from the running system.
func Default(domain string) Config { return defaultAt(domain, "") }

// defaultAt reads /proc and the cgroup tree below root ("" in production).
func defaultAt(domain, root string) Config {
	im, _ := LockedImages() // the embedded lock is tested; Validate refuses an empty set
	return Config{
		NodeID:           "local",
		Domain:           domain,
		ProjectBlock:     "10.213.0.0/16",
		SlicePrefix:      26,
		PlatformSubnet:   "10.212.0.0/21",
		PlatformIPRange:  "10.212.6.0/23",
		GatewayIP:        "10.212.0.2",
		IngressSubnet:    "10.212.8.0/24",
		GatewayIngressIP: "10.212.8.2",
		DockerPool:       "10.214.0.0/16",
		DockerPoolSize:   26,
		UIDBase:          700000,
		UIDCount:         65536,
		MemAllocMB:       memAllocMB(root),
		PidsAlloc:        pidsAlloc(root),
		Retention:        "168h",
		Uplinks:          uplinks(root),
		Images:           im,
		BackupSubnet:     defaultBackupSubnet,
	}
}

// Defaults is Default without a domain and without validation: what a node
// that has no node.json yet (the recovery of the control plane) runs with.
func Defaults() Config { return Default("") }

// CPQuotas resolves the control plane's disk and repository quotas in MiB: a
// value set in node.json as it is; else 32,768, or 2,048 on a development node
// (the dev-mode marker, a regular file beside node.json, exists).
func CPQuotas(c Config, p Paths) (diskMB, repoMB int) {
	def := 32768
	if fi, err := os.Lstat(filepath.Join(filepath.Dir(p.NodeJSON()), "dev-mode")); err == nil && fi.Mode().IsRegular() {
		def = 2048
	}
	diskMB, repoMB = c.CPDiskQuotaMB, c.CPRepoQuotaMB
	if diskMB <= 0 {
		diskMB = def
	}
	if repoMB <= 0 {
		repoMB = def
	}
	return diskMB, repoMB
}

// memAllocMB is 75 % of min(MemTotal, the smallest numeric memory.max of the
// process's cgroup and every ancestor up to the cgroup-namespace root), in MiB.
func memAllocMB(root string) int {
	limit := int64(-1)
	if b, err := os.ReadFile(filepath.Join(root, "/proc/meminfo")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
				if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					limit = kb * 1024
				}
			}
		}
	}
	cgRoot := filepath.Join(root, "/sys/fs/cgroup")
	if b, err := os.ReadFile(filepath.Join(root, "/proc/self/cgroup")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			rel, ok := strings.CutPrefix(line, "0::")
			if !ok {
				continue
			}
			for dir := filepath.Join(cgRoot, rel); ; dir = filepath.Dir(dir) {
				if v, err := os.ReadFile(filepath.Join(dir, "memory.max")); err == nil {
					if n, err := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64); err == nil && (limit < 0 || n < limit) {
						limit = n
					}
				}
				if dir == cgRoot || !strings.HasPrefix(dir, cgRoot) {
					break
				}
			}
		}
	}
	if limit < 0 {
		return 0
	}
	return int(limit / (1 << 20) * 3 / 4)
}

// pidsAlloc is 75 % of kernel.pid_max.
func pidsAlloc(root string) int {
	b, err := os.ReadFile(filepath.Join(root, "/proc/sys/kernel/pid_max"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n * 3 / 4
}

// uplinks lists, in order and without repeats, the interfaces carrying an IPv4 or
// IPv6 default route.
func uplinks(root string) []string {
	var out []string
	add := func(name string) {
		for _, n := range out {
			if n == name {
				return
			}
		}
		out = append(out, name)
	}
	scan := func(rel string, pick func(f []string) string) {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return
		}
		s := bufio.NewScanner(bytes.NewReader(b))
		for s.Scan() {
			if name := pick(strings.Fields(s.Text())); name != "" && name != "lo" {
				add(name)
			}
		}
	}
	scan("/proc/net/route", func(f []string) string { // Iface Destination Gateway Flags … Mask
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			return f[0]
		}
		return ""
	})
	scan("/proc/net/ipv6_route", func(f []string) string { // dest destlen src srclen nexthop metric refcnt use flags iface
		if len(f) >= 10 && f[1] == "00" && strings.Trim(f[0], "0") == "" {
			return f[9]
		}
		return ""
	})
	return out
}

// Load reads node.json strictly (unknown fields are an error) and validates it.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	// Fields added after the first release take their defaults when absent.
	c := Config{BackupSubnet: defaultBackupSubnet, Images: Images{Worker: WorkerImage}}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Config{}, fmt.Errorf("%s: trailing data", path)
	}
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Validate checks that the configuration is internally consistent: every subnet
// parses, the four networks are disjoint, the reserved addresses lie where the
// layout needs them, the uid range fits and covers every slice, the domain is
// lowercase DNS labels, and the images are pinned.
func (c Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	prefix := func(name, s string) netip.Prefix {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() || p != p.Masked() {
			bad("%s: %q is not an IPv4 network", name, s)
			return netip.Prefix{}
		}
		return p
	}
	addr := func(name, s string, in netip.Prefix) {
		a, err := netip.ParseAddr(s)
		if err != nil || !in.Contains(a) {
			bad("%s: %q is not an address inside %s", name, s, in)
		}
	}
	if c.NodeID == "" {
		bad("node_id: empty")
	}
	if !ValidDomain(c.Domain) {
		bad("domain: %q is not a domain name", c.Domain)
	}
	block := prefix("project_block", c.ProjectBlock)
	if block.IsValid() && (c.SlicePrefix < block.Bits() || c.SlicePrefix > 30) {
		bad("slice_prefix: %d does not fit project_block %s", c.SlicePrefix, block)
	}
	platform := prefix("platform_subnet", c.PlatformSubnet)
	ipRange := prefix("platform_ip_range", c.PlatformIPRange)
	if platform.IsValid() {
		addr("gateway_ip", c.GatewayIP, platform)
		if ipRange.IsValid() && (!platform.Contains(ipRange.Addr()) || ipRange.Bits() < platform.Bits()) {
			bad("platform_ip_range: %s is not inside %s", ipRange, platform)
		}
		// Docker allocates from the range, so no fixed address may lie in it.
		if gw, err := netip.ParseAddr(c.GatewayIP); err == nil && ipRange.IsValid() && ipRange.Contains(gw) {
			bad("gateway_ip: %s lies in platform_ip_range %s", gw, ipRange)
		}
		if n := c.Slices(); n > 0 && block.IsValid() {
			first, last := c.PlatformAddr(0), c.PlatformAddr(n-1)
			gw, _ := netip.ParseAddr(c.GatewayIP)
			switch {
			case !first.IsValid() || !last.IsValid():
				bad("platform_subnet: %s cannot hold %d fixed PostgREST addresses", platform, n)
			case ipRange.IsValid() && (ipRange.Contains(first) || ipRange.Contains(last) ||
				(first.Less(ipRange.Addr()) && ipRange.Addr().Less(last))):
				bad("platform_ip_range: %s overlaps the fixed PostgREST addresses %s–%s", ipRange, first, last)
			case gw.IsValid() && !gw.Less(first) && !last.Less(gw):
				bad("gateway_ip: %s is one of the fixed PostgREST addresses", gw)
			}
		}
	}
	ingress := prefix("ingress_subnet", c.IngressSubnet)
	if ingress.IsValid() {
		addr("gateway_ingress_ip", c.GatewayIngressIP, ingress)
	}
	pool := prefix("docker_pool", c.DockerPool)
	if pool.IsValid() && (c.DockerPoolSize < pool.Bits() || c.DockerPoolSize > 30) {
		bad("docker_pool_size: %d does not fit docker_pool %s", c.DockerPoolSize, pool)
	}
	backup := prefix("backup_subnet", c.BackupSubnet)
	// The five networks are separate bridges and address pools; none may share an address.
	nets := []struct {
		name string
		p    netip.Prefix
	}{{"project_block", block}, {"platform_subnet", platform}, {"ingress_subnet", ingress}, {"docker_pool", pool}, {"backup_subnet", backup}}
	for i, a := range nets {
		for _, b := range nets[i+1:] {
			if a.p.IsValid() && b.p.IsValid() && a.p.Overlaps(b.p) {
				bad("%s: %s overlaps %s %s", a.name, a.p, b.name, b.p)
			}
		}
	}
	// The last uid, base + count − 1, must not pass maxUID; tested without the sum, which can overflow.
	if c.UIDBase <= 0 || c.UIDBase > maxUID || c.UIDCount <= 0 || c.UIDCount > maxUID-c.UIDBase+1 {
		bad("uid_base/uid_count: %d/%d out of range", c.UIDBase, c.UIDCount)
	} else if n := c.Slices(); c.UIDCount < n {
		bad("uid_count: %d is fewer than the %d project slices", c.UIDCount, n)
	}
	if c.MemAllocMB <= 0 || c.PidsAlloc <= 0 {
		bad("mem_alloc_mb/pids_alloc: %d/%d must be positive", c.MemAllocMB, c.PidsAlloc)
	}
	if d, err := time.ParseDuration(c.Retention); err != nil || d <= 0 {
		bad("retention: %q is not a positive duration", c.Retention)
	}
	for _, u := range c.Uplinks {
		if u == "" {
			bad("uplinks: empty interface name")
		}
	}
	for name, ref := range map[string]string{"postgres": c.Images.Postgres, "postgrest": c.Images.PostgREST, "control_plane": c.Images.ControlPlane} {
		if i := strings.Index(ref, "@"); i <= 0 || !digestRE.MatchString(ref[i+1:]) {
			bad("images.%s: %q is not pinned by digest", name, ref)
		}
	}
	if c.Images.Gateway != GatewayImage {
		bad("images.gateway: %q, want %q", c.Images.Gateway, GatewayImage)
	}
	if c.CPDiskQuotaMB < 0 || c.CPRepoQuotaMB < 0 {
		bad("cp_disk_quota_mb/cp_repo_quota_mb: %d/%d must not be negative", c.CPDiskQuotaMB, c.CPRepoQuotaMB)
	}
	if c.Images.Worker != WorkerImage {
		bad("images.worker: %q, want %q", c.Images.Worker, WorkerImage)
	}
	return errors.Join(errs...)
}

// Slices is the number of project slices in the project block.
func (c Config) Slices() int {
	block, err := netip.ParsePrefix(c.ProjectBlock)
	if err != nil || !block.Addr().Is4() || c.SlicePrefix < block.Bits() || c.SlicePrefix > 32 {
		return 0
	}
	return 1 << (c.SlicePrefix - block.Bits())
}

// Slice is project network i: block base + i·2^(32−slice_prefix). The zero Prefix
// when i is out of range.
func (c Config) Slice(i int) netip.Prefix {
	if i < 0 || i >= c.Slices() {
		return netip.Prefix{}
	}
	block := netip.MustParsePrefix(c.ProjectBlock)
	return netip.PrefixFrom(addOffset(block.Masked().Addr(), uint32(i)<<(32-c.SlicePrefix)), c.SlicePrefix)
}

// ClusterAddr is slice base + 2.
func (c Config) ClusterAddr(i int) netip.Addr { return c.sliceAddr(i, 2) }

// PostgRESTAddr is slice base + 3.
func (c Config) PostgRESTAddr(i int) netip.Addr { return c.sliceAddr(i, 3) }

func (c Config) sliceAddr(i int, off uint32) netip.Addr {
	s := c.Slice(i)
	if !s.IsValid() {
		return netip.Addr{}
	}
	return addOffset(s.Addr(), off)
}

// PlatformAddr is PostgREST's fixed address on the platform network: platform
// subnet base + 16 + i. The zero Addr when i is out of range or the address would
// fall outside the subnet.
func (c Config) PlatformAddr(i int) netip.Addr {
	if i < 0 || i >= c.Slices() {
		return netip.Addr{}
	}
	p, err := netip.ParsePrefix(c.PlatformSubnet)
	if err != nil || !p.Addr().Is4() {
		return netip.Addr{}
	}
	a := addOffset(p.Masked().Addr(), uint32(platformAddrOffset+i))
	if !p.Contains(a) {
		return netip.Addr{}
	}
	return a
}

// BridgeName is the Linux bridge of project slice i.
func BridgeName(i int) string { return "spp" + strconv.Itoa(i) }

func addOffset(a netip.Addr, off uint32) netip.Addr {
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v += off
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// maxUID is the largest uid handed out: 2^31 − 1 stays positive in every uid_t consumer.
const maxUID = 1<<31 - 1

// domainRE: two or more lowercase DNS labels of 1 to 63 characters.
var domainRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// ValidDomain reports whether s is a base domain: lowercase DNS labels, at
// most 253 bytes. Shared with the route file.
func ValidDomain(s string) bool { return len(s) <= 253 && domainRE.MatchString(s) }
