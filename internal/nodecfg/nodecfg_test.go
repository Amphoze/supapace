package nodecfg

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
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
