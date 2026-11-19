package dashcfg

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

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
		UIDBase: 700000, UIDCount: 65536,
	}
}

// wideCfg has 65,536 slices, which takes the meta port range past 65535, on a
// platform subnet large enough for every fixed PostgREST address.
func wideCfg() nodecfg.Config {
	c := defaultCfg()
	c.ProjectBlock, c.SlicePrefix = "10.214.0.0/15", 31
	c.PlatformSubnet, c.PlatformIPRange = "10.212.0.0/15", "10.213.128.0/23"
	return c
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestFor_DefaultNode(t *testing.T) {
	c := defaultCfg()
	a, err := For(c)
	if err != nil {
		t.Fatal(err)
	}
	want := Addrs{
		Studio: ip("10.212.0.3"), PgMeta0: ip("10.212.0.4"), PgMeta1: ip("10.212.0.5"), Pgcap: ip("10.212.0.6"),
		MetaPortLo: 20000, MetaPortHi: 21023,
		RestLo: ip("10.212.0.16"), RestHi: ip("10.212.4.15"),
	}
	if a != want {
		t.Fatalf("For = %+v\nwant  %+v", a, want)
	}
	if s := Static(c); s != a {
		t.Fatalf("Static = %+v, want For's %+v", s, a)
	}
	if got := ProxyAddr(c, 3); got != ip("10.213.0.196") {
		t.Errorf("ProxyAddr(3) = %v", got)
	}
	if got := ProxyAddr(c, 1024); got.IsValid() {
		t.Errorf("ProxyAddr(out of range) = %v, want zero", got)
	}
	if MetaPort(7) != 20007 || PgMetaIndex(7) != 1 || PgMetaIndex(6) != 0 {
		t.Error("MetaPort/PgMetaIndex")
	}
	if c.ClusterAddr(3) != netip.MustParsePrefix("10.213.0.192/26").Addr().Next().Next() || ClusterHost != 2 || RestHost != 3 {
		t.Error("host offsets disagree with nodecfg")
	}
}

func TestStatic_RefusedMembersAreZero_NoPortAbove65535(t *testing.T) {
	def, _ := For(defaultCfg())
	cases := []struct {
		name string
		mod  func(*nodecfg.Config)
		want func(Addrs) Addrs // def with exactly the refused members zeroed
	}{
		{"gateway at studio", func(c *nodecfg.Config) { c.GatewayIP = "10.212.0.3" },
			func(a Addrs) Addrs { a.Studio = netip.Addr{}; return a }},
		{"gateway at pgcap", func(c *nodecfg.Config) { c.GatewayIP = "10.212.0.6" },
			func(a Addrs) Addrs { a.Pgcap = netip.Addr{}; return a }},
		{"allocation range over all four", func(c *nodecfg.Config) { c.PlatformIPRange = "10.212.0.0/29" },
			func(a Addrs) Addrs {
				a.Studio, a.PgMeta0, a.PgMeta1, a.Pgcap = netip.Addr{}, netip.Addr{}, netip.Addr{}, netip.Addr{}
				return a
			}},
		{"allocation range over the two pgmeta", func(c *nodecfg.Config) { c.PlatformIPRange = "10.212.0.4/31" },
			func(a Addrs) Addrs { a.PgMeta0, a.PgMeta1 = netip.Addr{}, netip.Addr{}; return a }},
		{"port range past 65535", func(c *nodecfg.Config) { *c = wideCfg() },
			func(a Addrs) Addrs {
				a.MetaPortLo, a.MetaPortHi = 0, 0
				a.RestHi = ip("10.213.0.15") // 16 + 65535 on the wider subnet
				return a
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := defaultCfg()
			tc.mod(&c)
			s := Static(c)
			if want := tc.want(def); s != want {
				t.Fatalf("Static = %+v\nwant     %+v", s, want)
			}
			if s.MetaPortLo > 65535 || s.MetaPortHi > 65535 || s.MetaPortLo > s.MetaPortHi {
				t.Fatalf("ports %d-%d", s.MetaPortLo, s.MetaPortHi)
			}
			if _, err := For(c); err == nil {
				t.Fatal("For accepted what Static omitted")
			}
		})
	}
	// Control: the default node omits nothing.
	if s := Static(defaultCfg()); s != def || !s.Studio.IsValid() || s.MetaPortHi == 0 {
		t.Fatalf("default Static = %+v", s)
	}
	// Static never fails or panics on an unusable configuration.
	for _, c := range []nodecfg.Config{{}, {PlatformSubnet: "x", ProjectBlock: "10.213.0.0/16", SlicePrefix: 99},
		{PlatformSubnet: "10.212.0.0/30", PlatformIPRange: "bad", ProjectBlock: "10.213.0.0/16", SlicePrefix: 26},
		{PlatformSubnet: "2001:db8::/64", PlatformIPRange: "2001:db8::/120", ProjectBlock: "10.213.0.0/16", SlicePrefix: 26}} {
		s := Static(c)
		if s.Studio.IsValid() || s.Pgcap.IsValid() || s.MetaPortLo > s.MetaPortHi || s.MetaPortHi > 65535 ||
			c.Slices() == 0 && s.MetaPortHi != 0 {
			t.Errorf("Static(%+v) = %+v", c, s)
		}
	}
	// A platform subnet too small for the four: what lies outside it is zero.
	c := defaultCfg()
	c.PlatformSubnet, c.PlatformIPRange = "10.212.0.0/30", "10.212.0.0/31"
	c.GatewayIP = "10.212.0.2"
	if s := Static(c); s.Studio != ip("10.212.0.3") || s.PgMeta0.IsValid() || s.PgMeta1.IsValid() || s.Pgcap.IsValid() {
		t.Errorf("small subnet: %+v", s)
	}
	if _, err := For(c); err == nil {
		t.Error("For accepted a subnet too small for the four")
	}
}

func TestFor_RefusesCollisions(t *testing.T) {
	cases := []struct {
		name, want string
		mod        func(*nodecfg.Config)
	}{
		{"gateway at pgmeta-1", "gateway_ip", func(c *nodecfg.Config) { c.GatewayIP = "10.212.0.5" }},
		{"allocation range over pgcap", "platform_ip_range", func(c *nodecfg.Config) { c.PlatformIPRange = "10.212.0.6/31" }},
		{"port range past 65535", "65535", func(c *nodecfg.Config) { *c = wideCfg() }},
		{"no room for the PostgREST range", "PostgREST", func(c *nodecfg.Config) { c.PlatformSubnet, c.PlatformIPRange = "10.212.0.0/27", "10.212.0.24/29" }},
		{"more than 4096 slices", "4096", func(c *nodecfg.Config) {
			c.ProjectBlock, c.SlicePrefix, c.PlatformSubnet, c.PlatformIPRange = "10.214.0.0/15", 28, "10.212.0.0/16", "10.212.128.0/23"
		}},
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
	// Controls: exactly 4096 slices pass; so does a gateway next to the four.
	c := defaultCfg()
	c.ProjectBlock, c.SlicePrefix, c.PlatformSubnet, c.PlatformIPRange = "10.214.0.0/15", 27, "10.212.0.0/16", "10.212.128.0/23"
	if c.Slices() != 4096 {
		t.Fatal(c.Slices())
	}
	if _, err := For(c); err != nil {
		t.Fatalf("4096 slices: %v", err)
	}
	c = defaultCfg()
	c.GatewayIP = "10.212.0.7"
	if _, err := For(c); err != nil {
		t.Fatalf("gateway at .7: %v", err)
	}
}

func TestFor_RefusesUidRangeOverPlatformUids(t *testing.T) {
	for _, r := range []struct{ base, count int }{
		{1, 100},       // 70
		{70, 1},        // 70 exactly
		{65527, 1},     // StudioUID
		{65000, 600},   // 65527 to 65532 inside
		{65532, 10},    // 65532, the first value
		{65530, 3},     // ends at 65532
		{60000, 10000}, // all of them
	} {
		c := defaultCfg()
		c.UIDBase, c.UIDCount = r.base, r.count
		if _, err := For(c); err == nil || !strings.Contains(err.Error(), "uid") {
			t.Errorf("uid range %d+%d: %v", r.base, r.count, err)
		}
	}
	for _, r := range []struct{ base, count int }{{700000, 65536}, {71, 65456}, {65533, 1000}} {
		c := defaultCfg()
		c.UIDBase, c.UIDCount = r.base, r.count
		if _, err := For(c); err != nil {
			t.Errorf("uid range %d+%d refused: %v", r.base, r.count, err)
		}
	}
}

func TestPaths_AllUnderTheRoot(t *testing.T) {
	root := t.TempDir()
	p := PathsFor(nodecfg.Paths{Root: root})
	for _, c := range []struct{ got, want string }{
		{p.KeyDir(), "etc/supapace/dash"},
		{p.StudioTLS(), "etc/supapace/tls-studio"},
		{p.GatewayDash(), "var/lib/supapace/platform/gateway/dash"},
		{p.GatewayStudioTLS(), "var/lib/supapace/platform/gateway/tls-studio"},
		{p.DashboardFile(), "var/lib/supapace/platform/gateway/dashboard.json"},
		{p.DashDir(), "var/lib/supapace/platform/dash"},
		{p.SocketDir(), "var/lib/supapace/platform/dash/sock"},
		{p.StudioKeys(), "var/lib/supapace/platform/dash/keys"},
		{p.ProxyConf(), "var/lib/supapace/platform/dash/pgcap"},
		{p.DataDir(), "var/lib/supapace/projects/dash"},
	} {
		if c.got != filepath.Join(root, c.want) {
			t.Errorf("%s, want %s under the root", c.got, c.want)
		}
	}
	if PathsFor(nodecfg.Paths{}).KeyDir() != "/etc/supapace/dash" {
		t.Error("production root")
	}
}

func TestDSN_RoundTripAndPgxReadsIt(t *testing.T) {
	a, _ := For(defaultCfg())
	pw := "a b@c:d/e%f?g&h#i~j.k-l_m+n"
	s := DSN(a, LoginRW, pw, 5)
	if s != "postgresql://postgres:a%20b%40c%3Ad%2Fe%25f%3Fg%26h%23i~j.k-l_m%2Bn@10.212.0.6:20005/postgres?sslmode=disable" {
		t.Fatal(s)
	}
	login, idx, err := ParseDSN(a, s)
	if err != nil || login != LoginRW || idx != 5 {
		t.Fatalf("ParseDSN = %q %d %v", login, idx, err)
	}
	// The client library reads the same string as the same target.
	cfg, err := pgconn.ParseConfig(s)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != "postgres" || cfg.Password != pw || cfg.Host != "10.212.0.6" || cfg.Port != 20005 || cfg.Database != "postgres" || cfg.TLSConfig != nil {
		t.Fatalf("pgconn read %+v", cfg)
	}
}
