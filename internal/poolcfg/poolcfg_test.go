package poolcfg

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// defaultCfg is nodecfg.Default's fixed part, written out so that no test reads
// the running system.
func defaultCfg() nodecfg.Config {
	return nodecfg.Config{
		NodeID: "local", Domain: "sp.test",
		ProjectBlock: "10.213.0.0/16", SlicePrefix: 26,
		PlatformSubnet: "10.212.0.0/21", PlatformIPRange: "10.212.6.0/23", GatewayIP: "10.212.0.2",
		IngressSubnet: "10.212.8.0/24", GatewayIngressIP: "10.212.8.2",
		DockerPool: "10.214.0.0/16", DockerPoolSize: 26,
		UIDBase: 700000, UIDCount: 65536, BackupSubnet: "10.212.9.0/24",
	}
}

// slicesCfg has 2^(prefix−15) slices on a platform subnet large enough for
// every fixed PostgREST address up to 32,768 slices.
func slicesCfg(prefix int) nodecfg.Config {
	c := defaultCfg()
	c.ProjectBlock, c.SlicePrefix = "10.214.0.0/15", prefix
	c.PlatformSubnet, c.PlatformIPRange = "10.212.0.0/16", "10.212.200.0/23"
	c.IngressSubnet, c.GatewayIngressIP = "10.213.8.0/24", "10.213.8.2"
	c.DockerPool, c.BackupSubnet = "10.213.64.0/18", "10.213.9.0/24"
	return c
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// offset is the address off places after the base of the network s.
func offset(s string, off int) netip.Addr {
	a := netip.MustParsePrefix(s).Masked().Addr()
	for range off {
		a = a.Next()
	}
	return a
}

func TestFor_AddressesDistinctFromEveryFixedMember(t *testing.T) {
	c := defaultCfg()
	a, err := For(c)
	if err != nil {
		t.Fatal(err)
	}
	want := Addrs{PlatformDB: ip("10.212.0.7"), Pooler: ip("10.212.0.8"), PoolerIngress: ip("10.212.8.3"), PoolPortLo: 24096, PoolPortHi: 25119}
	if a != want {
		t.Fatalf("For = %+v\nwant  %+v", a, want)
	}
	if a.PlatformDB != offset(c.PlatformSubnet, 7) || a.Pooler != offset(c.PlatformSubnet, 8) || a.PoolerIngress != offset(c.IngressSubnet, 3) {
		t.Fatalf("addresses are not base+7, base+8 and ingress base+3: %+v", a)
	}
	// The seven fixed platform-side addresses: the gateway's two, the dashboard's four
	// (platform base + 3 to 6) and ours, plus the fixed PostgREST range.
	seen := map[netip.Addr]string{ip(c.GatewayIP): "gateway", ip(c.GatewayIngressIP): "gateway ingress"}
	for off := 3; off <= 6; off++ {
		seen[offset(c.PlatformSubnet, off)] = "dashboard"
	}
	for i := range c.Slices() {
		seen[c.PlatformAddr(i)] = "postgrest"
	}
	if len(seen) != 6+c.Slices() {
		t.Fatalf("the fixed members themselves collide: %d", len(seen))
	}
	rng, pool := netip.MustParsePrefix(c.PlatformIPRange), netip.MustParsePrefix(c.DockerPool)
	for _, m := range []netip.Addr{a.PlatformDB, a.Pooler, a.PoolerIngress} {
		if who, ok := seen[m]; ok {
			t.Errorf("%s is also the %s address", m, who)
		}
		seen[m] = "pooler"
		if rng.Contains(m) || pool.Contains(m) {
			t.Errorf("%s lies in a range Docker allocates from", m)
		}
	}
	if len(seen) != 9+c.Slices() {
		t.Errorf("not distinct: %d", len(seen))
	}
	if s := Static(c); s != a {
		t.Errorf("Static = %+v, want For's %+v", s, a)
	}
}

func TestFor_RefusesAddressCollisions(t *testing.T) {
	cases := []struct {
		name, want string
		mod        func(*nodecfg.Config)
	}{
		{"gateway at the platform database", "gateway_ip", func(c *nodecfg.Config) { c.GatewayIP = "10.212.0.7" }},
		{"gateway at the pooler", "gateway_ip", func(c *nodecfg.Config) { c.GatewayIP = "10.212.0.8" }},
		{"gateway ingress at the pooler's ingress", "gateway_ingress_ip", func(c *nodecfg.Config) { c.GatewayIngressIP = "10.212.8.3" }},
		{"allocation range over the platform database", "platform_ip_range", func(c *nodecfg.Config) { c.PlatformIPRange = "10.212.0.6/31" }},
		{"allocation range over the pooler", "platform_ip_range", func(c *nodecfg.Config) { c.PlatformIPRange = "10.212.0.8/29" }},
		{"ingress subnet without base+3", "ingress_subnet", func(c *nodecfg.Config) { c.IngressSubnet, c.GatewayIngressIP = "10.212.8.0/31", "10.212.8.1" }},
		{"platform subnet not IPv4", "platform_subnet", func(c *nodecfg.Config) { c.PlatformSubnet = "2001:db8::/64" }},
		{"ingress subnet not IPv4", "ingress_subnet", func(c *nodecfg.Config) { c.IngressSubnet = "2001:db8:1::/64" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := defaultCfg()
			tc.mod(&c)
			_, err := For(c)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("For: %v, want an error naming %q", err, tc.want)
			}
		})
	}
	// Controls: neighbours of the three are accepted.
	for _, mod := range []func(*nodecfg.Config){
		func(c *nodecfg.Config) { c.GatewayIP = "10.212.0.9" },
		func(c *nodecfg.Config) { c.GatewayIngressIP = "10.212.8.4" },
		func(c *nodecfg.Config) { c.PlatformIPRange = "10.212.0.9/32" },
		func(c *nodecfg.Config) { c.PlatformIPRange = "10.212.0.4/31" },
	} {
		c := defaultCfg()
		mod(&c)
		if _, err := For(c); err != nil {
			t.Errorf("%+v refused: %v", c, err)
		}
	}
	// Every refusal is reported, joined.
	c := defaultCfg()
	c.GatewayIP, c.GatewayIngressIP = "10.212.0.8", "10.212.8.3"
	if _, err := For(c); err == nil || !strings.Contains(err.Error(), "gateway_ip") || !strings.Contains(err.Error(), "gateway_ingress_ip") {
		t.Errorf("two collisions: %v", err)
	}
}

func TestFor_RefusesProjectUidRangeOverThePoolersUids(t *testing.T) {
	for _, r := range []struct{ base, count int }{
		{PlatformDBUID, 1}, {PoolerUID, 1}, {65000, 600}, {65520, 6}, {65526, 10}, {1, 1 << 20},
	} {
		c := defaultCfg()
		c.UIDBase, c.UIDCount = r.base, r.count
		if _, err := For(c); err == nil || !strings.Contains(err.Error(), "uid") {
			t.Errorf("uid range %d+%d: %v", r.base, r.count, err)
		}
	}
	for _, r := range []struct{ base, count int }{{700000, 65536}, {65520, 5}, {65527, 10}, {1, 65524}} {
		c := defaultCfg()
		c.UIDBase, c.UIDCount = r.base, r.count
		if _, err := For(c); err != nil {
			t.Errorf("uid range %d+%d refused: %v", r.base, r.count, err)
		}
	}
}

func TestFor_RefusesPoolPortsPast65535(t *testing.T) {
	// The line, on the slice count itself (a node file can only give powers of two).
	last := 65535 - PoolPortBase + 1
	if last != 41440 {
		t.Fatalf("the largest slice count is %d", last)
	}
	if lo, hi, err := portRange(last); err != nil || lo != PoolPortBase || hi != 65535 {
		t.Errorf("41,440 slices: %d-%d %v", lo, hi, err)
	}
	if lo, hi, err := portRange(last + 1); err == nil || !strings.Contains(err.Error(), "65535") || lo != 0 || hi != 0 {
		t.Errorf("41,441 slices: %d-%d %v", lo, hi, err)
	}
	// Through For: 32,768 slices pass, 65,536 are refused.
	c := slicesCfg(30)
	if c.Slices() != 32768 {
		t.Fatal(c.Slices())
	}
	if a, err := For(c); err != nil || a.PoolPortHi != PoolPortBase+32767 {
		t.Errorf("32,768 slices: %+v %v", a, err)
	}
	c = slicesCfg(31)
	if _, err := For(c); err == nil || !strings.Contains(err.Error(), "65535") {
		t.Errorf("65,536 slices: %v", err)
	}
	// A slice prefix of 30 under a /8 block.
	c = defaultCfg()
	c.ProjectBlock, c.SlicePrefix = "0.0.0.0/8", 30
	if _, err := For(c); err == nil || !strings.Contains(err.Error(), "65535") {
		t.Errorf("/30 under /8: %v", err)
	}
}

func TestStatic_NeverFailsAndEqualsForWhereForAccepts(t *testing.T) {
	def := defaultCfg()
	arith := Addrs{PlatformDB: ip("10.212.0.7"), Pooler: ip("10.212.0.8"), PoolerIngress: ip("10.212.8.3"), PoolPortLo: 24096, PoolPortHi: 25119}
	// Each configuration For refuses: the member it refuses is zero, the
	// others keep their arithmetic.
	cases := []struct {
		name string
		mod  func(*nodecfg.Config)
		want func(Addrs) Addrs
	}{
		{"gateway at the platform database", func(c *nodecfg.Config) { c.GatewayIP = "10.212.0.7" },
			func(a Addrs) Addrs { a.PlatformDB = netip.Addr{}; return a }},
		{"gateway at the pooler", func(c *nodecfg.Config) { c.GatewayIP = "10.212.0.8" },
			func(a Addrs) Addrs { a.Pooler = netip.Addr{}; return a }},
		{"gateway ingress at the pooler's ingress", func(c *nodecfg.Config) { c.GatewayIngressIP = "10.212.8.3" },
			func(a Addrs) Addrs { a.PoolerIngress = netip.Addr{}; return a }},
		{"gateway ingress at a platform address", func(c *nodecfg.Config) { c.GatewayIngressIP = "10.212.0.8" },
			func(a Addrs) Addrs { a.Pooler = netip.Addr{}; return a }},
		{"allocation range over both", func(c *nodecfg.Config) { c.PlatformIPRange = "10.212.0.0/28" },
			func(a Addrs) Addrs { a.PlatformDB, a.Pooler = netip.Addr{}, netip.Addr{}; return a }},
		{"allocation range over the pooler", func(c *nodecfg.Config) { c.PlatformIPRange = "10.212.0.8/29" },
			func(a Addrs) Addrs { a.Pooler = netip.Addr{}; return a }},
		{"ingress subnet without base+3", func(c *nodecfg.Config) { c.IngressSubnet, c.GatewayIngressIP = "10.212.8.0/31", "10.212.8.1" },
			func(a Addrs) Addrs { a.PoolerIngress = netip.Addr{}; return a }},
		{"ports past 65535", func(c *nodecfg.Config) { c.ProjectBlock, c.SlicePrefix = "0.0.0.0/8", 30 },
			func(a Addrs) Addrs { a.PoolPortLo, a.PoolPortHi = 0, 0; return a }},
		{"uid range (no member)", func(c *nodecfg.Config) { c.UIDBase, c.UIDCount = 65000, 1000 },
			func(a Addrs) Addrs { return a }},
	}
	for _, tc := range cases {
		c := def
		tc.mod(&c)
		if _, err := For(c); err == nil {
			t.Fatalf("%s: For accepted", tc.name)
		}
		if s, want := Static(c), tc.want(arith); s != want {
			t.Errorf("%s: Static = %+v\nwant %+v", tc.name, s, want)
		}
	}
	if s := Static(def); s != arith { // control
		t.Errorf("default: Static = %+v", s)
	}
	// Every slice count a node file can give: the ports are For's, or 0-0
	// where For refuses them.
	for _, block := range []string{"0.0.0.0/0", "0.0.0.0/8", "10.214.0.0/15", "10.213.0.0/16"} {
		bits := netip.MustParsePrefix(block).Bits()
		for prefix := bits; prefix <= 32; prefix++ {
			c := def
			c.ProjectBlock, c.SlicePrefix = block, prefix
			n := c.Slices()
			fits := PoolPortBase+n-1 <= 65535
			s := Static(c)
			if fits && (s.PoolPortLo != PoolPortBase || s.PoolPortHi != PoolPortBase+n-1) || !fits && (s.PoolPortLo != 0 || s.PoolPortHi != 0) {
				t.Errorf("%s /%d (%d slices): ports %d-%d", block, prefix, n, s.PoolPortLo, s.PoolPortHi)
			}
			a, err := For(c)
			if (err == nil) != fits {
				t.Errorf("%s /%d (%d slices): For %v", block, prefix, n, err)
			}
			if err == nil && a != s {
				t.Errorf("%s /%d: For %+v, Static %+v", block, prefix, a, s)
			}
		}
	}
	// Unusable configurations: no panic, nothing past 65535, no arithmetic
	// without an IPv4 network.
	for _, c := range []nodecfg.Config{{}, {PlatformSubnet: "x", IngressSubnet: "y", ProjectBlock: "10.213.0.0/16", SlicePrefix: 99},
		{PlatformSubnet: "2001:db8::/64", IngressSubnet: "2001:db8:1::/64", ProjectBlock: "10.213.0.0/16", SlicePrefix: 26},
		{PlatformSubnet: "255.255.255.255/32", IngressSubnet: "255.255.255.254/31", ProjectBlock: "0.0.0.0/0", SlicePrefix: 32}} {
		s := Static(c)
		if s.PoolPortHi > 65535 || s.PoolPortLo > s.PoolPortHi || (c.Slices() == 0 && s.PoolPortHi != 0) {
			t.Errorf("Static(%+v) ports %d-%d", c, s.PoolPortLo, s.PoolPortHi)
		}
		if p, err := netip.ParsePrefix(c.PlatformSubnet); (err != nil || !p.Addr().Is4()) && (s.PlatformDB.IsValid() || s.Pooler.IsValid()) {
			t.Errorf("Static(%+v) = %+v", c, s)
		}
		if _, err := For(c); err == nil {
			t.Errorf("For(%+v) accepted", c)
		}
	}
}

// The dashboard admits at most a fixed number of slices; within it the two
// classes' port ranges never meet. The bound is read from dashcfg's own
// behaviour, so that a change of it fails here.
func TestPoolPorts_ClearOfTheMetaRangeAtEverySliceCount(t *testing.T) {
	bound := 0
	for prefix := 15; prefix <= 31; prefix++ { // 1 to 65,536 slices
		c := slicesCfg(prefix)
		m, err := dashcfg.For(c)
		if err != nil {
			break
		}
		bound = c.Slices()
		p := Static(c)
		if m.MetaPortHi >= p.PoolPortLo || m.MetaPortLo != dashcfg.MetaPortBase {
			t.Errorf("%d slices: meta %d-%d, pooler %d-%d", bound, m.MetaPortLo, m.MetaPortHi, p.PoolPortLo, p.PoolPortHi)
		}
	}
	if bound != 4096 {
		t.Fatalf("dashcfg admits up to %d slices; the pooler's base assumes 4096", bound)
	}
	if PoolPortBase != dashcfg.MetaPortBase+bound {
		t.Errorf("PoolPortBase %d, want MetaPortBase + %d", PoolPortBase, bound)
	}
	for n := 1; n <= bound; n++ {
		if metaHi := dashcfg.MetaPortBase + n - 1; metaHi >= PoolPortBase || PoolPort(n-1) > 65535 {
			t.Fatalf("%d slices: meta ends at %d, pooler starts at %d", n, metaHi, PoolPortBase)
		}
	}
	if PoolPort(0) != PoolPortBase || PoolPort(4095) != 28191 {
		t.Errorf("PoolPort: %d %d", PoolPort(0), PoolPort(4095))
	}
}

func TestValidLabel_RefusesTheRefShape(t *testing.T) {
	for _, l := range []string{"abcdefghij0123456789", "01234567890123456789", "aaaaaaaaaaaaaaaaaaaa"} {
		if ValidLabel(l) == nil {
			t.Errorf("%q (a ref) accepted", l)
		}
	}
	for _, l := range []string{"", "-pool", "pool-", "Pool", "po_ol", "po.ol", "pöol", strings.Repeat("a", 64)} {
		if ValidLabel(l) == nil {
			t.Errorf("%q accepted", l)
		}
	}
	// Controls: 19 and 21 characters of the ref's alphabet, a dash, 1 and 63 characters.
	for _, l := range []string{"abcdefghij012345678", "abcdefghij0123456789a", "abcdefghij-123456789", "pool", "p", "db-pool", strings.Repeat("a", 63)} {
		if err := ValidLabel(l); err != nil {
			t.Errorf("%q refused: %v", l, err)
		}
	}
}

// tierRows are the connection budget's rows at the default tier, all but the pooler's: Realtime,
// Storage, PostgREST, postgres-meta, pg_cron, the backup worker, the agent,
// reserved, and 2.
var tierRows = []int{14, 10, 11, 5, 0, 2, 3, 3, 2}

// The default max_connections, and the projects a node is sized for.
const defaultMaxConnections, nodeProjects = 120, 28

func tierReserved() int {
	n := 0
	for _, r := range tierRows {
		n += r
	}
	return n
}

// maxPool is the rule itself, by search: the largest P ≥ 1 with
// 2 × (2P + 3) ≤ allowance, or 0.
func maxPool(allowance int) int {
	p := 0
	for 2*(2*(p+1)+3) <= allowance {
		p++
	}
	return p
}

func TestAllowance_Table(t *testing.T) {
	if TierReserved != tierReserved() {
		t.Fatalf("TierReserved %d, the rows sum to %d", TierReserved, tierReserved())
	}
	for m := -10; m <= 400; m++ {
		if got, want := Allowance(m), m-tierReserved(); got != want {
			t.Fatalf("Allowance(%d) = %d, want %d", m, got, want)
		}
	}
	for _, r := range []struct{ m, want int }{{120, 70}, {60, 10}} {
		if got := Allowance(r.m); got != r.want {
			t.Errorf("Allowance(%d) = %d, want %d", r.m, got, r.want)
		}
	}
	if Allowance(16) >= 0 {
		t.Errorf("Allowance(16) = %d, want negative", Allowance(16))
	}
}

func TestMaxPoolSize_Table(t *testing.T) {
	for a := -100; a <= 1000; a++ {
		if got, want := MaxPoolSize(a), maxPool(a); got != want {
			t.Fatalf("MaxPoolSize(%d) = %d, want %d", a, got, want)
		}
	}
	for _, r := range []struct{ a, want int }{{70, 16}, {69, 15}, {10, 1}, {9, 0}} {
		if got := MaxPoolSize(r.a); got != r.want {
			t.Errorf("MaxPoolSize(%d) = %d, want %d", r.a, got, r.want)
		}
	}
	if MaxPoolSize(-1<<62) != 0 {
		t.Error("a very negative allowance")
	}
}

func TestMinMaxConnections_Table(t *testing.T) {
	for p := 1; p <= 500; p++ {
		want := tierReserved() + 2*(2*p+3)
		if got := MinMaxConnections(p); got != want {
			t.Fatalf("MinMaxConnections(%d) = %d, want %d", p, got, want)
		}
		// It is the threshold of MaxPoolSize: the least max_connections that fits p.
		if MaxPoolSize(Allowance(want)) < p || MaxPoolSize(Allowance(want-1)) >= p {
			t.Fatalf("MinMaxConnections(%d) = %d is not the threshold", p, want)
		}
	}
	for _, r := range []struct{ p, want int }{{5, 76}, {1, 60}, {16, 120}} {
		if got := MinMaxConnections(r.p); got != r.want {
			t.Errorf("MinMaxConnections(%d) = %d, want %d", r.p, got, r.want)
		}
	}
	for _, low := range []int{-1 << 61, -1 << 62, math.MinInt} {
		if got := MinMaxConnections(low); got != math.MinInt {
			t.Errorf("MinMaxConnections(%d) = %d, want it saturated", low, got)
		}
	}
	if err := Fits(120, math.MinInt); err == nil || !strings.Contains(err.Error(), "needs max_connections "+fmt.Sprint(math.MinInt)) {
		t.Errorf("Fits(120, MinInt) = %v", err)
	}
	for _, huge := range []int{1 << 61, 1 << 62, math.MaxInt} {
		if got := MinMaxConnections(huge); got != math.MaxInt {
			t.Errorf("MinMaxConnections(%d) = %d, want it saturated", huge, got)
		}
	}
}

func TestFits_RefusesWithFigures(t *testing.T) {
	for m := 0; m <= 300; m++ {
		for p := 1; p <= 70; p++ {
			want := 2*(2*p+3) <= m-tierReserved()
			if err := Fits(m, p); (err == nil) != want {
				t.Fatalf("Fits(%d, %d) = %v, want fits=%v", m, p, err, want)
			}
		}
	}
	for _, r := range []struct {
		m, p  int
		names []string
	}{
		{75, 5, []string{"75", "pool size 5", "76", "largest pool size that fits is 4"}},
		{120, 17, []string{"120", "17", "largest pool size that fits is 16", "124"}},
	} {
		err := Fits(r.m, r.p)
		if err == nil || !errors.Is(err, ErrBudget) {
			t.Fatalf("Fits(%d, %d) = %v", r.m, r.p, err)
		}
		for _, n := range r.names {
			if !strings.Contains(err.Error(), n) {
				t.Errorf("Fits(%d, %d) = %q, does not name %q", r.m, r.p, err, n)
			}
		}
	}
	for _, r := range []struct{ m, p int }{{76, 5}, {60, 1}, {120, 16}, {120, 5}} {
		if err := Fits(r.m, r.p); err != nil {
			t.Errorf("Fits(%d, %d) = %v", r.m, r.p, err)
		}
	}
	for _, r := range []struct{ m, p int }{{59, 1}, {120, 0}, {120, -1}, {120, 1 << 62}, {math.MinInt, 1}, {-1 << 62, 1}, {1 << 62, 1 << 61}} {
		if err := Fits(r.m, r.p); err == nil || !errors.Is(err, ErrBudget) {
			t.Errorf("Fits(%d, %d) = %v, want ErrBudget", r.m, r.p, err)
		}
	}
}

func TestCeiling_IsTwentyEightSharesAndTheFixedTerms(t *testing.T) {
	// The wire proxy's fixed terms: class "meta" 32 and its cancels 16, the two
	// pools of refusals in flight, 16 (meta) and 48 (pooler).
	const metaConns, metaCancels, metaRefusals, poolRefusals = 32, 16, 16, 48
	if ProxyFixedConns != metaConns+metaCancels+metaRefusals+poolRefusals {
		t.Errorf("ProxyFixedConns %d", ProxyFixedConns)
	}
	allowance := Allowance(defaultMaxConnections)
	if ProjectConns(allowance) != allowance+CancelsPerProject {
		t.Errorf("ProjectConns(%d) = %d", allowance, ProjectConns(allowance))
	}
	ceiling := nodeProjects*ProjectConns(allowance) + ProxyFixedConns
	if DefaultProxyMaxConns != ceiling {
		t.Errorf("DefaultProxyMaxConns %d, 28 shares and the fixed terms are %d", DefaultProxyMaxConns, ceiling)
	}
	if PoolClass.ConnsBurst != allowance {
		t.Errorf("the class's burst %d, the default allowance %d", PoolClass.ConnsBurst, allowance)
	}
	if PoolClass.RefusalsMax != poolRefusals || PoolClass.CancelsPerProject != CancelsPerProject || PoolClass.ScramIterMax != ScramIterMax {
		t.Errorf("PoolClass disagrees with the constants: %+v", PoolClass)
	}
	// The largest pool at the default fills its allowance exactly.
	if MaxPoolSize(allowance) != 16 || MinMaxConnections(16) != defaultMaxConnections {
		t.Errorf("largest pool %d", MaxPoolSize(allowance))
	}
	// The figures as written (spot checks).
	if TierReserved != 50 || allowance != 70 || ProjectConns(allowance) != 72 || ProxyFixedConns != 112 ||
		DefaultProxyMaxConns != 2128 || PoolClass.ConnsBurst != 70 {
		t.Errorf("figures: %d %d %d %d %d %d", TierReserved, allowance, ProjectConns(allowance), ProxyFixedConns, DefaultProxyMaxConns, PoolClass.ConnsBurst)
	}
}

func TestProxyWanted_Table(t *testing.T) {
	for _, r := range []struct {
		studio, label string
		want          bool
	}{{"", "", false}, {"studio.sp.test", "", true}, {"", "db", true}, {"studio.sp.test", "db", true}} {
		if got := ProxyWanted(r.studio, r.label); got != r.want {
			t.Errorf("ProxyWanted(%q, %q) = %v", r.studio, r.label, got)
		}
	}
}
