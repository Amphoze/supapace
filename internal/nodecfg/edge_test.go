package nodecfg

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSlice_Boundaries(t *testing.T) {
	c := Default("sp.test")
	if c.Slices() != 1024 {
		t.Fatalf("Slices = %d", c.Slices())
	}
	for _, i := range []int{-1, -1 << 31, 1024, 1025, 1 << 40} {
		if c.Slice(i).IsValid() || c.ClusterAddr(i).IsValid() || c.PostgRESTAddr(i).IsValid() || c.PlatformAddr(i).IsValid() {
			t.Errorf("index %d accepted", i)
		}
	}
	want := map[int][4]string{
		0:    {"10.213.0.0/26", "10.213.0.2", "10.213.0.3", "10.212.0.16"},
		1:    {"10.213.0.64/26", "10.213.0.66", "10.213.0.67", "10.212.0.17"},
		1023: {"10.213.255.192/26", "10.213.255.194", "10.213.255.195", "10.212.4.15"},
	}
	for i, w := range want {
		got := [4]string{c.Slice(i).String(), c.ClusterAddr(i).String(), c.PostgRESTAddr(i).String(), c.PlatformAddr(i).String()}
		if got != w {
			t.Errorf("i=%d got %v want %v", i, got, w)
		}
	}
}

// Every index: unique, contained, non-overlapping, masked-rule property, platform address constraints.
func TestSlice_AllIndexesUniqueAndContained(t *testing.T) {
	c := Default("sp.test")
	plat := netip.MustParsePrefix(c.PlatformSubnet)
	rng := netip.MustParsePrefix(c.PlatformIPRange)
	gw := netip.MustParseAddr(c.GatewayIP)
	seen := map[string]int{}
	note := func(kind, v string, i int) {
		k := kind + v
		if j, ok := seen[k]; ok {
			t.Fatalf("%s %s collides: %d and %d", kind, v, j, i)
		}
		seen[k] = i
	}
	var prev netip.Prefix
	for i := 0; i < c.Slices(); i++ {
		s := c.Slice(i)
		if s.Bits() != 26 || s != s.Masked() {
			t.Fatalf("slice %d = %v", i, s)
		}
		if i > 0 && (prev.Overlaps(s) || !prev.Addr().Less(s.Addr())) {
			t.Fatalf("slice %d overlaps/out of order: %v %v", i, prev, s)
		}
		prev = s
		cl, pr, pa := c.ClusterAddr(i), c.PostgRESTAddr(i), c.PlatformAddr(i)
		if !s.Contains(cl) || !s.Contains(pr) || cl == pr {
			t.Fatalf("addr outside slice %d", i)
		}
		if cl.As4()[3]&63 != 2 || pr.As4()[3]&63 != 3 {
			t.Fatalf("mask property broken at %d", i)
		}
		if !plat.Contains(pa) || rng.Contains(pa) || pa == gw {
			t.Fatalf("platform addr %v of %d is outside the layout", pa, i)
		}
		br := BridgeName(i)
		if len(br) > 7 || br != "spp"+strconv.Itoa(i) {
			t.Fatalf("bridge %q", br)
		}
		note("slice", s.String(), i)
		note("cluster", cl.String(), i)
		note("pr", pr.String(), i)
		note("plat", pa.String(), i)
		note("br", br, i)
	}
	if got := c.PlatformAddr(14).String(); got != "10.212.0.30" {
		t.Errorf("PlatformAddr(14) = %s", got)
	}
}

func TestSlice_EdgeConfigs(t *testing.T) {
	c := Default("sp.test")
	// wrap-around at the top of the address space must not yield a valid wrong address
	c.PlatformSubnet = "255.255.255" + ".128/25"
	if a := c.PlatformAddr(1023); a.IsValid() {
		t.Errorf("wrapped platform address accepted: %v", a)
	}
	// unparsable / IPv6 / unmasked configuration: no panic, zero results
	for _, blk := range []string{"", "garbage", "fd00:" + ":/64", "10.213.0.5/16", "10.213.0.0/33"} {
		c := Default("sp.test")
		c.ProjectBlock = blk
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("block %q panics: %v", blk, r)
				}
			}()
			_ = c.Slices()
			_ = c.Slice(0)
			_ = c.ClusterAddr(0)
			_ = c.PlatformAddr(0)
			_ = c.Validate()
		}()
	}
	// slice_prefix 0 / 32 against a /16 block
	for _, sp := range []int{0, 15, 31, 32, 33, -1, 64} {
		c := Default("sp.test")
		c.SlicePrefix = sp
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("slice_prefix %d panics: %v", sp, r)
				}
			}()
			c.Slices()
			c.Slice(0)
		}()
		if err := c.Validate(); err == nil {
			t.Errorf("slice_prefix %d passes Validate", sp)
		}
	}
	// unmasked block and platform subnet must be refused by Validate
	c = Default("sp.test")
	c.ProjectBlock = "10.213.0.5/16"
	if c.Validate() == nil {
		t.Error("unmasked project_block accepted")
	}
}

func TestValidate_Rejects(t *testing.T) {
	mut := map[string]func(*Config){
		"empty node_id":                      func(c *Config) { c.NodeID = "" },
		"empty domain":                       func(c *Config) { c.Domain = "" },
		"domain newline":                     func(c *Config) { c.Domain = "sp.test\nevil" },
		"domain space":                       func(c *Config) { c.Domain = "sp .test" },
		"domain slash":                       func(c *Config) { c.Domain = "sp.test/x" },
		"gateway outside":                    func(c *Config) { c.GatewayIP = "10.213.0.2" },
		"gateway ipv6":                       func(c *Config) { c.GatewayIP = "::1" },
		"gateway = plataddr":                 func(c *Config) { c.GatewayIP = "10.212.0.16" },
		"gateway = last plat":                func(c *Config) { c.GatewayIP = "10.212.4.15" },
		"range overlaps fixed":               func(c *Config) { c.PlatformIPRange = "10.212.4.0/23" },
		"range outside":                      func(c *Config) { c.PlatformIPRange = "10.215.6.0/23" },
		"range wider":                        func(c *Config) { c.PlatformIPRange = "10.212.0.0/20" },
		"ingress gw outside":                 func(c *Config) { c.GatewayIngressIP = "10.212.9.2" },
		"pool size small":                    func(c *Config) { c.DockerPoolSize = 8 },
		"uid zero":                           func(c *Config) { c.UIDBase = 0 },
		"uid negative":                       func(c *Config) { c.UIDBase = -5 },
		"uid count zero":                     func(c *Config) { c.UIDCount = 0 },
		"uid overflow int32":                 func(c *Config) { c.UIDBase = 1<<31 - 100; c.UIDCount = 65536 },
		"uid huge":                           func(c *Config) { c.UIDBase = 1 << 62; c.UIDCount = 1 << 62 },
		"mem zero":                           func(c *Config) { c.MemAllocMB = 0 },
		"pids neg":                           func(c *Config) { c.PidsAlloc = -1 },
		"retention bad":                      func(c *Config) { c.Retention = "a week" },
		"retention zero":                     func(c *Config) { c.Retention = "0s" },
		"retention neg":                      func(c *Config) { c.Retention = "-1h" },
		"image tag only":                     func(c *Config) { c.Images.Postgres = "supabase/postgres:17.6.1.166" },
		"image short digest":                 func(c *Config) { c.Images.PostgREST = "postgrest/postgrest@sha256:abc" },
		"image upper digest":                 func(c *Config) { c.Images.ControlPlane = "postgres@sha256:" + strings.Repeat("A", 64) },
		"image trailing nl":                  func(c *Config) { c.Images.Postgres += "\n" },
		"gateway image":                      func(c *Config) { c.Images.Gateway = "x@sha256:" + strings.Repeat("a", 64) },
		"empty uplink":                       func(c *Config) { c.Uplinks = []string{""} },
		"bad project_block":                  func(c *Config) { c.ProjectBlock = "10.213.0.0/33" },
		"bad platform_subnet":                func(c *Config) { c.PlatformSubnet = "garbage" },
		"bad ingress_subnet":                 func(c *Config) { c.IngressSubnet = "10.212.8.1/24" },
		"bad docker_pool":                    func(c *Config) { c.DockerPool = "2001:db8::/64" },
		"domain upper case":                  func(c *Config) { c.Domain = "SP.test" },
		"domain empty label":                 func(c *Config) { c.Domain = "sp..test" },
		"domain trailing dot":                func(c *Config) { c.Domain = "sp.test." },
		"domain hyphen edge":                 func(c *Config) { c.Domain = "-sp.test" },
		"domain tab":                         func(c *Config) { c.Domain = "sp\t.test" },
		"domain too long":                    func(c *Config) { c.Domain = strings.Repeat("a.", 127) + "test" },
		"domain label > 63":                  func(c *Config) { c.Domain = strings.Repeat("a", 64) + ".test" },
		"uid count max int":                  func(c *Config) { c.UIDBase = 1; c.UIDCount = 1<<63 - 1 },
		"uid base max int":                   func(c *Config) { c.UIDBase = 1<<63 - 1; c.UIDCount = 65536 },
		"ingress = platform":                 func(c *Config) { c.IngressSubnet = c.PlatformSubnet; c.GatewayIngressIP = "10.212.0.3" },
		"pool inside platform":               func(c *Config) { c.DockerPool = "10.212.0.0/16" },
		"block over ingress":                 func(c *Config) { c.ProjectBlock = "10.212.0.0/16" },
		"pool = ingress":                     func(c *Config) { c.DockerPool = "10.212.8.0/24" },
		"gateway inside platform_ip_range":   func(c *Config) { c.GatewayIP = "10.212.6.2" },
		"ingress overlaps platform":          func(c *Config) { c.IngressSubnet = "10.212.0.0/24"; c.GatewayIngressIP = "10.212.0.99" },
		"docker_pool overlaps project_block": func(c *Config) { c.DockerPool = "10.213.0.0/16" },
		"uid_count < slices":                 func(c *Config) { c.UIDCount = 10 },
		"domain with @":                      func(c *Config) { c.Domain = "a" + "@sp.test" },
		"domain with ..":                     func(c *Config) { c.Domain = "sp..test" },
		"domain with quote":                  func(c *Config) { c.Domain = `sp".test` },
	}
	c := Default("sp.test")
	c.MemAllocMB, c.PidsAlloc = 1, 1 // computed from the host; may be 0 in a sandbox
	if err := c.Validate(); err != nil {
		t.Fatalf("Default does not validate: %v", err)
	}
	for name, f := range mut {
		c := c
		c.Uplinks = append([]string(nil), c.Uplinks...)
		f(&c)
		if c.Validate() == nil {
			t.Errorf("%s: Validate accepted", name)
		}
	}
}

func TestLoad_RejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	good, _ := json.Marshal(Default("sp.test"))
	gs := string(good)
	// Accepted limit: encoding/json matches keys case-insensitively and keeps the last
	// of duplicate keys; node.json is written only by supapaced init.
	cases := map[string]string{
		"empty file":       "",
		"whitespace":       "  \n",
		"null":             "null",
		"empty object":     "{}",
		"array":            "[]",
		"truncated":        gs[:len(gs)/2],
		"trailing object":  gs + gs,
		"trailing brace":   gs + "}",
		"trailing bracket": gs + "]",
		"trailing garbage": gs + " x",
		"wrong type":       strings.Replace(gs, `"slice_prefix":26`, `"slice_prefix":"26"`, 1),
		"float int":        strings.Replace(gs, `"slice_prefix":26`, `"slice_prefix":26.5`, 1),
		"missing field":    strings.Replace(gs, `"retention":"168h",`, ``, 1),
		"missing images":   strings.Replace(gs, `"images":`, `"imagez":`, 1),
		"null uplinks":     strings.Replace(gs, `"uplinks":`, `"uplinks":null,"zz":`, 1),
	}
	for name, body := range cases {
		p := filepath.Join(dir, "n.json")
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: Load accepted", name)
		}
	}
	if _, err := Load(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := Load(dir); err == nil {
		t.Error("directory accepted")
	}
}

func TestLoad_RoundTrip(t *testing.T) {
	root := t.TempDir()
	c := defaultAt("sp.test", fakeRoot(t, root, "16777216", "0::/", ""))
	b, _ := json.MarshalIndent(c, "", "  ")
	p := filepath.Join(root, "node.json")
	os.WriteFile(p, b, 0o600)
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := json.Marshal(got)
	b1, _ := json.Marshal(c)
	if string(b1) != string(b2) {
		t.Errorf("round trip differs:\n%s\n%s", b1, b2)
	}
}

func fakeRoot(t *testing.T, root, memKB, cgroup, rootMax string) string {
	t.Helper()
	w := func(rel, s string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(s), 0o644)
	}
	w("proc/meminfo", "MemTotal: "+memKB+" kB\n")
	w("proc/self/cgroup", cgroup)
	if rootMax != "" {
		w("sys/fs/cgroup/memory.max", rootMax)
	}
	w("proc/sys/kernel/pid_max", "4194304\n")
	return root
}

func TestMemAlloc_OddInputs(t *testing.T) {
	type tc struct {
		name, meminfo, cgroup string
		files                 map[string]string
		want                  int
	}
	cases := []tc{
		{"no files at all", "", "", nil, 0},
		{"meminfo only", "MemTotal: 1048576 kB\n", "", nil, 768},
		{"meminfo garbage value", "MemTotal: lots kB\n", "", nil, 0},
		{"meminfo missing field", "MemFree: 1 kB\n", "", nil, 0},
		{"cgroup v1 line ignored", "MemTotal: 1048576 kB\n", "4:memory:/x\n", map[string]string{"sys/fs/cgroup/x/memory.max": "1\n"}, 768},
		{"limit lower than meminfo", "MemTotal: 1048576 kB\n", "0::/a\n", map[string]string{"sys/fs/cgroup/a/memory.max": "536870912\n"}, 384},
		{"limit higher than meminfo", "MemTotal: 1048576 kB\n", "0::/a\n", map[string]string{"sys/fs/cgroup/a/memory.max": "99999999999\n"}, 768},
		{"parent lower than child", "MemTotal: 1048576 kB\n", "0::/a/b\n", map[string]string{"sys/fs/cgroup/a/b/memory.max": "max\n", "sys/fs/cgroup/a/memory.max": "268435456\n"}, 192},
		{"non numeric limit", "MemTotal: 1048576 kB\n", "0::/a\n", map[string]string{"sys/fs/cgroup/a/memory.max": "banana\n"}, 768},
		{"empty limit file", "MemTotal: 1048576 kB\n", "0::/a\n", map[string]string{"sys/fs/cgroup/a/memory.max": ""}, 768},
		{"limit zero", "MemTotal: 1048576 kB\n", "0::/a\n", map[string]string{"sys/fs/cgroup/a/memory.max": "0\n"}, 0},
		{"limit below 1MiB", "MemTotal: 1048576 kB\n", "0::/a\n", map[string]string{"sys/fs/cgroup/a/memory.max": "1048575\n"}, 0},
		{"cgroup root path", "MemTotal: 1048576 kB\n", "0::/\n", map[string]string{"sys/fs/cgroup/memory.max": "268435456\n"}, 192},
		{"deleted suffix", "MemTotal: 1048576 kB\n", "0::/a (deleted)\n", map[string]string{"sys/fs/cgroup/a (deleted)/memory.max": "268435456\n"}, 192},
		{"dotdot escape must not read outside root", "MemTotal: 1048576 kB\n", "0::/../../../../etc\n", map[string]string{"etc/memory.max": "1048576\n"}, 768},
	}
	for _, c := range cases {
		root := t.TempDir()
		if c.meminfo != "" {
			os.MkdirAll(filepath.Join(root, "proc"), 0o755)
			os.WriteFile(filepath.Join(root, "proc/meminfo"), []byte(c.meminfo), 0o644)
		}
		if c.cgroup != "" {
			os.MkdirAll(filepath.Join(root, "proc/self"), 0o755)
			os.WriteFile(filepath.Join(root, "proc/self/cgroup"), []byte(c.cgroup), 0o644)
		}
		for rel, s := range c.files {
			os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o755)
			os.WriteFile(filepath.Join(root, rel), []byte(s), 0o644)
		}
		if got := memAllocMB(root); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

func TestPidsAndUplinks_OddInputs(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "proc/sys/kernel"), 0o755)
	for in, want := range map[string]int{"": 0, "abc": 0, "-4": -3, "0": 0, "4194304\n": 3145728, "  100  ": 75} {
		os.WriteFile(filepath.Join(root, "proc/sys/kernel/pid_max"), []byte(in), 0o644)
		if got := pidsAlloc(root); got != want {
			t.Errorf("pid_max %q: %d want %d", in, got, want)
		}
	}
	if pidsAlloc(t.TempDir()) != 0 {
		t.Error("missing pid_max")
	}
	if len(uplinks(t.TempDir())) != 0 {
		t.Error("uplinks of empty root")
	}
	os.MkdirAll(filepath.Join(root, "proc/net"), 0o755)
	os.WriteFile(filepath.Join(root, "proc/net/route"), []byte("short\n\n\t\neth0\t00000000\n"+
		"eth0\t00000000\t0\t0003\t0\t0\t0\t00000000\n"+
		"eth0\t00000000\t0\t0003\t0\t0\t0\t00000000\n"+
		"lo\t00000000\t0\t0003\t0\t0\t0\t00000000\n"+
		"wg0\t00000000\t0\t0003\t0\t0\t0\t00000001\n"), 0o644)
	if got := strings.Join(uplinks(root), ","); got != "eth0" {
		t.Errorf("uplinks = %q", got)
	}
}

func TestLockedRef_Entries(t *testing.T) {
	for _, k := range []string{"postgres", "postgrest", "control_plane", "node"} {
		if _, err := lockedRef(k); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	if _, err := lockedRef("nope"); err == nil {
		t.Error("unknown key accepted")
	}
	if _, err := lockedRef(""); err == nil {
		t.Error("empty key accepted")
	}
	// tag with registry port must keep the port
	saved := imagesLock
	defer func() { imagesLock = saved }()
	d := "sha256:" + strings.Repeat("a", 64)
	imagesLock = []byte(`{"k":{"tag":"reg.test:5000/x/y","digest":"` + d + `"}}`)
	if r, err := lockedRef("k"); err != nil || r != "reg.test:5000/x/y@"+d {
		t.Errorf("port-bearing tag: %q %v", r, err)
	}
	for name, body := range map[string]string{
		"bad digest":     `{"k":{"tag":"a:b","digest":"sha256:zz"}}`,
		"empty tag":      `{"k":{"tag":"","digest":"` + d + `"}}`,
		"colon only tag": `{"k":{"tag":":1","digest":"` + d + `"}}`,
		"unknown field":  `{"k":{"tag":"a:b","digest":"` + d + `","x":1}}`,
		"empty":          ``,
	} {
		imagesLock = []byte(body)
		if _, err := lockedRef("k"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	imagesLock = []byte(`{"k":{"tag":"a:b","digest":"` + d + `"}}`)
	if _, err := LockedImages(); err == nil {
		t.Error("LockedImages with missing keys succeeded")
	}
}

func TestValidDomain_LengthBoundary(t *testing.T) {
	ok := strings.Repeat("a.", 124) + "tests" // 253 bytes
	if len(ok) != 253 || !ValidDomain(ok) {
		t.Errorf("%d-byte domain rejected", len(ok))
	}
	if long := "b" + ok; ValidDomain(long) {
		t.Errorf("%d-byte domain accepted", len(long))
	}
}
