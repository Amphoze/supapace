package nodecfg

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestDefault_Golden(t *testing.T) {
	c := Default("sp.test")
	fixed := []struct{ name, got, want string }{
		{"node_id", c.NodeID, "local"},
		{"domain", c.Domain, "sp.test"},
		{"project_block", c.ProjectBlock, "10.213.0.0/16"},
		{"platform_subnet", c.PlatformSubnet, "10.212.0.0/21"},
		{"platform_ip_range", c.PlatformIPRange, "10.212.6.0/23"},
		{"gateway_ip", c.GatewayIP, "10.212.0.2"},
		{"ingress_subnet", c.IngressSubnet, "10.212.8.0/24"},
		{"gateway_ingress_ip", c.GatewayIngressIP, "10.212.8.2"},
		{"docker_pool", c.DockerPool, "10.214.0.0/16"},
		{"retention", c.Retention, "168h"},
		{"images.gateway", c.Images.Gateway, "supapace-gateway:local"},
		{"GatewayImage", GatewayImage, "supapace-gateway:local"},
		{"PlatformBridge", PlatformBridge, "spl0"},
		{"IngressBridge", IngressBridge, "spi0"},
	}
	for _, f := range fixed {
		if f.got != f.want {
			t.Errorf("%s = %q, want %q", f.name, f.got, f.want)
		}
	}
	ints := []struct {
		name      string
		got, want int
	}{
		{"slice_prefix", c.SlicePrefix, 26},
		{"docker_pool_size", c.DockerPoolSize, 26},
		{"uid_base", c.UIDBase, 700000},
		{"uid_count", c.UIDCount, 65536},
		{"Slices", c.Slices(), 1024},
	}
	for _, f := range ints {
		if f.got != f.want {
			t.Errorf("%s = %d, want %d", f.name, f.got, f.want)
		}
	}
	locked, err := LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	if c.Images != locked {
		t.Errorf("images = %+v, want the locked set %+v", c.Images, locked)
	}
	if c.MemAllocMB <= 0 || c.PidsAlloc <= 0 {
		t.Errorf("computed ceilings not positive: mem %d, pids %d", c.MemAllocMB, c.PidsAlloc)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate(Default) = %v", err)
	}
}

// The admission ceilings and uplinks are read from /proc and the cgroup tree; a
// fixture root shows the walk takes the smallest limit up to the namespace root.
func TestDefault_ComputedFromRoot(t *testing.T) {
	root := t.TempDir()
	write := func(rel, s string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proc/meminfo", "MemTotal:       16777216 kB\nMemFree:        1 kB\n")
	write("proc/self/cgroup", "0::/a/b\n")
	write("sys/fs/cgroup/memory.max", "4294967296\n") // 4 GiB at the namespace root
	write("sys/fs/cgroup/a/memory.max", "max\n")
	write("sys/fs/cgroup/a/b/memory.max", "max\n")
	write("proc/sys/kernel/pid_max", "4194304\n")
	write("proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
		"eth0\t00000000\t0102000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"+
		"eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")
	write("proc/net/ipv6_route",
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000001 00000400 00000001 00000000 00000003 eth1\n"+
			"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n")

	c := defaultAt("sp.test", root)
	if c.MemAllocMB != 3072 {
		t.Errorf("mem_alloc_mb = %d, want 3072 (75%% of the 4 GiB ancestor limit)", c.MemAllocMB)
	}
	if c.PidsAlloc != 3145728 {
		t.Errorf("pids_alloc = %d, want 3145728", c.PidsAlloc)
	}
	if strings.Join(c.Uplinks, ",") != "eth0,eth1" {
		t.Errorf("uplinks = %v, want [eth0 eth1]", c.Uplinks)
	}

	write("sys/fs/cgroup/memory.max", "max\n") // no limit anywhere: MemTotal wins
	if got := defaultAt("sp.test", root).MemAllocMB; got != 12288 {
		t.Errorf("mem_alloc_mb without a cgroup limit = %d, want 12288", got)
	}
}

func TestSlice_Arithmetic(t *testing.T) {
	c := Default("sp.test")
	for _, tc := range []struct {
		i                         int
		slice, cluster, postgrest string
	}{
		{0, "10.213.0.0/26", "10.213.0.2", "10.213.0.3"},
		{1, "10.213.0.64/26", "10.213.0.66", "10.213.0.67"},
		{1023, "10.213.255.192/26", "10.213.255.194", "10.213.255.195"},
	} {
		if got := c.Slice(tc.i).String(); got != tc.slice {
			t.Errorf("Slice(%d) = %s, want %s", tc.i, got, tc.slice)
		}
		if got := c.ClusterAddr(tc.i).String(); got != tc.cluster {
			t.Errorf("ClusterAddr(%d) = %s, want %s", tc.i, got, tc.cluster)
		}
		if got := c.PostgRESTAddr(tc.i).String(); got != tc.postgrest {
			t.Errorf("PostgRESTAddr(%d) = %s, want %s", tc.i, got, tc.postgrest)
		}
		if b := c.ClusterAddr(tc.i).As4(); b[3]&63 != 2 {
			t.Errorf("ClusterAddr(%d) & 63 = %d, want 2", tc.i, b[3]&63)
		}
	}
	if BridgeName(0) != "spp0" || BridgeName(1023) != "spp1023" {
		t.Errorf("BridgeName = %q, %q", BridgeName(0), BridgeName(1023))
	}
}

func TestPlatformAddr_Arithmetic(t *testing.T) {
	c := Default("sp.test")
	for i, want := range map[int]string{0: "10.212.0.16", 14: "10.212.0.30", 1023: "10.212.4.15"} {
		if got := c.PlatformAddr(i).String(); got != want {
			t.Errorf("PlatformAddr(%d) = %s, want %s", i, got, want)
		}
	}
	subnet := netip.MustParsePrefix(c.PlatformSubnet)
	ipRange := netip.MustParsePrefix(c.PlatformIPRange)
	gw := netip.MustParseAddr(c.GatewayIP)
	seen := map[netip.Addr]bool{}
	for i := 0; i < c.Slices(); i++ {
		a := c.PlatformAddr(i)
		if !subnet.Contains(a) || ipRange.Contains(a) || a == gw || seen[a] {
			t.Fatalf("PlatformAddr(%d) = %s: outside subnet, inside ip range, the gateway, or repeated", i, a)
		}
		seen[a] = true
	}
}

func TestSlice_OutOfRange(t *testing.T) {
	c := Default("sp.test")
	for _, i := range []int{-1, 1024, 1 << 20} {
		if c.Slice(i).IsValid() || c.ClusterAddr(i).IsValid() || c.PostgRESTAddr(i).IsValid() || c.PlatformAddr(i).IsValid() {
			t.Errorf("index %d: want zero prefix and addresses", i)
		}
	}
	if (Config{}).Slice(0).IsValid() {
		t.Error("zero Config: want zero prefix")
	}
}

func TestPaths_UnderRoot(t *testing.T) {
	root := t.TempDir()
	p, prod := Paths{Root: root}, Paths{}
	ref := "abcdefghij0123456789"
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pairs := []struct{ got, prod, want string }{
		{p.NodeJSON(), prod.NodeJSON(), "/etc/supapace/node.json"},
		{p.KEK(), prod.KEK(), "/etc/supapace/kek"},
		{p.NftFile(), prod.NftFile(), "/etc/supapace/nftables.nft"},
		{p.NftSum(), prod.NftSum(), "/etc/supapace/nft.sha256"},
		{p.TLSDir(), prod.TLSDir(), "/etc/supapace/tls"},
		{p.CADir(), prod.CADir(), "/etc/supapace/ca"},
		{p.AdminSock(), prod.AdminSock(), "/run/supapace/admin.sock"},
		{p.Failpoint(), prod.Failpoint(), "/run/supapace/failpoint"},
		{p.BootJSON(), prod.BootJSON(), "/run/supapace/boot.json"},
		{p.DriftHold(), prod.DriftHold(), "/run/supapace/drift-hold"},
		{p.CPDir(), prod.CPDir(), "/var/lib/supapace/cp"},
		{p.PlatformDir(), prod.PlatformDir(), "/var/lib/supapace/platform"},
		{p.ImageDir(digest), prod.ImageDir(digest), "/var/lib/supapace/platform/image/0123456789ab"},
		{p.GatewayDir(), prod.GatewayDir(), "/var/lib/supapace/platform/gateway"},
		{p.RenderDir(ref), prod.RenderDir(ref), "/var/lib/supapace/platform/projects/" + ref},
		{p.ProjectsDir(), prod.ProjectsDir(), "/var/lib/supapace/projects"},
		{p.ProjectDir(ref), prod.ProjectDir(ref), "/var/lib/supapace/projects/" + ref},
	}
	for _, pr := range pairs {
		if pr.prod != pr.want {
			t.Errorf("production path %q, want %q", pr.prod, pr.want)
		}
		if pr.got != root+pr.want {
			t.Errorf("rooted path %q, want %q", pr.got, root+pr.want)
		}
	}
}

func TestLoad_RejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	good, err := json.Marshal(Default("sp.test"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "node.json")
	if err := os.WriteFile(path, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(path); err != nil || c.Domain != "sp.test" {
		t.Fatalf("Load(good) = %+v, %v", c, err)
	}
	bad := strings.Replace(string(good), `"node_id"`, `"surprise":1,"node_id"`, 1)
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted an unknown field")
	}
}

func TestLockedImages_Parses(t *testing.T) {
	im, err := LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	ref := regexp.MustCompile(`^[a-z0-9]+(/[a-z0-9._-]+)*@sha256:[0-9a-f]{64}$`)
	for name, v := range map[string]string{"postgres": im.Postgres, "postgrest": im.PostgREST, "control_plane": im.ControlPlane} {
		if !ref.MatchString(v) {
			t.Errorf("%s = %q, want name@sha256:<64 hex>", name, v)
		}
	}
	if !strings.HasPrefix(im.Postgres, "supabase/postgres@") || !strings.HasPrefix(im.PostgREST, "postgrest/postgrest@") ||
		!strings.HasPrefix(im.ControlPlane, "postgres@") {
		t.Errorf("unexpected repositories: %+v", im)
	}
	if im.Gateway != GatewayImage {
		t.Errorf("gateway = %q, want %q", im.Gateway, GatewayImage)
	}
	node, err := NodeImage()
	if err != nil {
		t.Fatal(err)
	}
	if !ref.MatchString(node) || !strings.HasPrefix(node, "docker@") {
		t.Errorf("node image = %q", node)
	}
}

// A node.json written before the backup fields existed (today's init) loads:
// the backup subnet and the worker image take their defaults, the control
// plane's quotas stay unset and resolve at use.
func TestLoad_OldNodeJSONGetsDefaults(t *testing.T) {
	c := Default("sp.test")
	c.MemAllocMB, c.PidsAlloc = 1, 1
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "backup_subnet")
	delete(m["images"].(map[string]any), "worker")
	old, _ := json.Marshal(m)
	if strings.Contains(string(old), "backup") || strings.Contains(string(old), "worker") || strings.Contains(string(old), "cp_") {
		t.Fatalf("fixture still names a new field: %s", old)
	}
	p := filepath.Join(t.TempDir(), "node.json")
	if err := os.WriteFile(p, old, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatalf("an old node.json does not load: %v", err)
	}
	if got.BackupSubnet != "10.212.9.0/24" || got.Images.Worker != WorkerImage || got.CPDiskQuotaMB != 0 || got.CPRepoQuotaMB != 0 {
		t.Errorf("defaults not applied: backup_subnet %q, worker %q, cp quotas %d/%d", got.BackupSubnet, got.Images.Worker, got.CPDiskQuotaMB, got.CPRepoQuotaMB)
	}
	if !reflect.DeepEqual(got, c) {
		t.Errorf("loaded %+v\nwant Default %+v", got, c)
	}
	// A value that is present is kept, not replaced by the default.
	m["backup_subnet"] = "10.212.10.0/24"
	set, _ := json.Marshal(m)
	os.WriteFile(p, set, 0o600)
	if got, err := Load(p); err != nil || got.BackupSubnet != "10.212.10.0/24" {
		t.Errorf("explicit backup_subnet: %q, %v", got.BackupSubnet, err)
	}
	// A worker image other than the local one is refused, as for the gateway.
	m["images"].(map[string]any)["worker"] = "alpine@sha256:" + strings.Repeat("a", 64)
	set, _ = json.Marshal(m)
	os.WriteFile(p, set, 0o600)
	if _, err := Load(p); err == nil {
		t.Error("a foreign worker image was accepted")
	}
}

func TestValidate_BackupSubnetOverlap(t *testing.T) {
	c := Default("sp.test")
	c.MemAllocMB, c.PidsAlloc = 1, 1
	if err := c.Validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, s := range map[string]string{
		"platform":       "10.212.0.0/24",
		"inside ingress": "10.212.8.128/25",
		"over ingress":   "10.212.8.0/23",
		"project block":  "10.213.4.0/24",
		"docker pool":    "10.214.0.0/24",
		"covers all":     "10.212.0.0/14",
		"not a network":  "10.212.9.1/24",
		"ipv6":           "2001:db8::/64",
		"garbage":        "spb0",
		"empty":          "",
	} {
		d := c
		d.BackupSubnet = s
		if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "backup_subnet") {
			t.Errorf("%s (%q): Validate = %v, want a backup_subnet error", name, s, err)
		}
	}
	d := c
	d.BackupSubnet = "10.212.10.0/24"
	if err := d.Validate(); err != nil {
		t.Errorf("a free subnet refused: %v", err)
	}
}

func TestPaths_New(t *testing.T) {
	root := t.TempDir()
	p, prod := Paths{Root: root}, Paths{}
	ref := "abcdefghij0123456789"
	for _, pr := range []struct{ got, prod, want string }{
		{p.RepoRoot(), prod.RepoRoot(), "/var/lib/supapace/repo"},
		{p.RepoDir(ref), prod.RepoDir(ref), "/var/lib/supapace/repo/" + ref},
		{p.RepoDir(ControlPlaneSubject), prod.RepoDir(ControlPlaneSubject), "/var/lib/supapace/repo/cp"},
		{p.CPProjectDir(), prod.CPProjectDir(), "/var/lib/supapace/projects/cp"},
		{p.CPRestoring(), prod.CPRestoring(), "/var/lib/supapace/cp/restoring"},
		{p.ToolsDir(), prod.ToolsDir(), "/var/lib/supapace/platform/tools"},
		{p.JobsDir(), prod.JobsDir(), "/var/lib/supapace/platform/jobs"},
		{p.IndexFile(ref), prod.IndexFile(ref), "/var/lib/supapace/platform/replica/" + ref + ".idx"},
		{p.OffsiteSealed(), prod.OffsiteSealed(), "/etc/supapace/offsite.sealed"},
		{p.OffsiteAddrs(), prod.OffsiteAddrs(), "/etc/supapace/offsite.addrs"},
		{p.NftLock(), prod.NftLock(), "/etc/supapace/nft.lock"},
		{p.CPStanzaSealed(), prod.CPStanzaSealed(), "/etc/supapace/cp-stanza.sealed"},
		{p.EscrowAcked(), prod.EscrowAcked(), "/etc/supapace/escrow.acked"},
		{p.OffsiteCheck(), prod.OffsiteCheck(), "/etc/supapace/offsite.check"},
	} {
		if pr.prod != pr.want || pr.got != root+pr.want {
			t.Errorf("path %q (rooted %q), want %q", pr.prod, pr.got, pr.want)
		}
	}
	// The constants other packages build names from.
	if ReplicatorUID != 65530 || ControlPlaneUID != 70 || BackupBridge != "spb0" || BackupNetwork != "backup" ||
		WorkerImage != "supapace-worker:local" || ControlPlaneSubject != "cp" {
		t.Error("a backup constant changed")
	}
}

func TestCPQuotas_SetValueElseDefaultElseDevFigure(t *testing.T) {
	p := Paths{Root: t.TempDir()}
	c := Default("sp.test")
	if d, r := CPQuotas(c, p); d != 32768 || r != 32768 {
		t.Errorf("unset, production node: %d/%d, want 32768/32768", d, r)
	}
	c.CPDiskQuotaMB = 4096
	if d, r := CPQuotas(c, p); d != 4096 || r != 32768 {
		t.Errorf("disk set: %d/%d, want 4096/32768", d, r)
	}
	marker := filepath.Join(filepath.Dir(p.NodeJSON()), "dev-mode")
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatal(err)
	}
	// Only a regular file is the marker.
	if err := os.Symlink("/dev/null", marker); err != nil {
		t.Fatal(err)
	}
	if d, r := CPQuotas(c, p); d != 4096 || r != 32768 {
		t.Errorf("a link at the marker: %d/%d, want 4096/32768", d, r)
	}
	os.Remove(marker)
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if d, r := CPQuotas(c, p); d != 4096 || r != 2048 {
		t.Errorf("development node, disk set: %d/%d, want 4096/2048", d, r)
	}
	c.CPRepoQuotaMB = 10000
	if d, r := CPQuotas(c, p); d != 4096 || r != 10000 {
		t.Errorf("both set: %d/%d, want 4096/10000", d, r)
	}
	c.CPDiskQuotaMB, c.CPRepoQuotaMB = 0, 0
	if d, r := CPQuotas(c, p); d != 2048 || r != 2048 {
		t.Errorf("development node, unset: %d/%d, want 2048/2048", d, r)
	}
}

// init writes a node.json equal to Default, also with --dev: the quota fields
// stay unset and are omitted from the file.
func TestDefault_LeavesTheControlPlaneQuotasUnset(t *testing.T) {
	c := Default("sp.test")
	if c.CPDiskQuotaMB != 0 || c.CPRepoQuotaMB != 0 {
		t.Errorf("cp quotas %d/%d, want unset", c.CPDiskQuotaMB, c.CPRepoQuotaMB)
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "cp_disk_quota_mb") || strings.Contains(string(b), "cp_repo_quota_mb") {
		t.Errorf("unset quotas written: %s", b)
	}
	if c.BackupSubnet != "10.212.9.0/24" || c.Images.Worker != WorkerImage {
		t.Errorf("backup subnet %q, worker %q", c.BackupSubnet, c.Images.Worker)
	}
	c.CPDiskQuotaMB = 1
	if b, _ := json.Marshal(c); !strings.Contains(string(b), `"cp_disk_quota_mb":1`) {
		t.Errorf("a set quota not written: %s", b)
	}
}

func TestDefaults_NeedsNoDomain(t *testing.T) {
	d := Defaults()
	if d.Domain != "" {
		t.Errorf("domain %q, want none", d.Domain)
	}
	want := Default("x.test")
	want.Domain = ""
	if !reflect.DeepEqual(d, want) {
		t.Errorf("Defaults = %+v\nwant Default without its domain %+v", d, want)
	}
	if d.BackupSubnet == "" || d.ProjectBlock == "" || d.Images.Worker != WorkerImage || d.Images.ControlPlane == "" {
		t.Errorf("a value recover needs is missing: %+v", d)
	}
}

func TestValidate_ControlPlaneQuotasNotNegative(t *testing.T) {
	c := Default("sp.test")
	c.MemAllocMB, c.PidsAlloc = 1, 1
	c.CPDiskQuotaMB, c.CPRepoQuotaMB = 0, 1
	if err := c.Validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, q := range [][2]int{{-1, 0}, {0, -1}} {
		d := c
		d.CPDiskQuotaMB, d.CPRepoQuotaMB = q[0], q[1]
		if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "cp_") {
			t.Errorf("quotas %v: Validate = %v", q, err)
		}
	}
}
