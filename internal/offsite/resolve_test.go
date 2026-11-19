package offsite

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// testConfig is the default node configuration with a domain (its address
// blocks are what the refusals read).
func testConfig() nodecfg.Config { return nodecfg.Default("sp.test") }

// fakeNet replaces the resolver and the interface list for one test. The
// lookup records the network asked for.
func fakeNet(t *testing.T, answer []string, ifs []iface) *string {
	t.Helper()
	var network string
	oldL, oldI := lookupIP, interfaces
	lookupIP = func(_ context.Context, nw, host string) ([]netip.Addr, error) {
		network = nw
		if host != "s3.example.test" {
			t.Errorf("looked up %q", host)
		}
		var out []netip.Addr
		for _, a := range answer {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
	interfaces = func() ([]iface, error) { return ifs, nil }
	t.Cleanup(func() { lookupIP, interfaces = oldL, oldI })
	return &network
}

func decl(endpoint string) Declaration { return Declaration{Endpoint: endpoint} }

func TestResolve_IPv4Only(t *testing.T) {
	nw := fakeNet(t, []string{"198.51.100.20", "198.51.100.7", "198.51.100.20"}, nil)
	got, err := Resolve(context.Background(), decl("https://s3.example.test:9443"), testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if *nw != "ip4" {
		t.Errorf("looked up network %q, want ip4", *nw)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:9443"), netip.MustParseAddrPort("198.51.100.20:9443")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v (sorted, deduplicated, the endpoint's port)", got, want)
	}

	// No port: 443.
	got, err = Resolve(context.Background(), decl("https://s3.example.test"), testConfig())
	if err != nil || got[0].Port() != 443 {
		t.Fatalf("default port: %v %v", got, err)
	}

	// An IPv6 address in the answer refuses the whole answer; a mapped IPv4
	// address counts as IPv4.
	fakeNet(t, []string{"198.51.100.7", "2001:db8::1"}, nil)
	if got, err := Resolve(context.Background(), decl("https://s3.example.test"), testConfig()); err == nil {
		t.Fatalf("an IPv6 address was accepted: %v", got)
	}
	fakeNet(t, []string{"::ffff:198.51.100.7"}, nil)
	if got, err := Resolve(context.Background(), decl("https://s3.example.test"), testConfig()); err != nil || got[0].Addr() != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("mapped address: %v %v", got, err)
	}

	// An empty answer is an error, not an empty set.
	fakeNet(t, nil, nil)
	if got, err := Resolve(context.Background(), decl("https://s3.example.test"), testConfig()); err == nil {
		t.Fatalf("empty answer: %v", got)
	}

	// More than 16 addresses: the 16 lowest.
	var many []string
	for i := 40; i > 10; i-- {
		many = append(many, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}).String())
	}
	fakeNet(t, many, nil)
	got, err = Resolve(context.Background(), decl("https://s3.example.test"), testConfig())
	if err != nil || len(got) != 16 || got[0].Addr().String() != "198.51.100.11" || got[15].Addr().String() != "198.51.100.26" {
		t.Fatalf("many: %v %v", got, err)
	}

	// A lookup error is returned; a bad endpoint is refused before a lookup.
	oldL := lookupIP
	lookupIP = func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	if _, err := Resolve(context.Background(), decl("https://s3.example.test"), testConfig()); err == nil {
		t.Error("lookup error swallowed")
	}
	lookupIP = func(context.Context, string, string) ([]netip.Addr, error) { t.Error("looked up"); return nil, nil }
	if _, err := Resolve(context.Background(), decl("http://s3.example.test"), testConfig()); err == nil {
		t.Error("http endpoint resolved")
	}
	lookupIP = oldL
}

// refusedCases are answers each of which must refuse the whole answer, with
// the node configuration of testConfig.
var refusedCases = map[string]string{
	"project block":           "10.213.4.2",
	"platform":                "10.212.1.9",
	"ingress":                 "10.212.8.2",
	"backup":                  "10.212.9.7",
	"docker pool":             "10.214.3.3",
	"loopback":                "127.0.0.53",
	"link-local":              "169.254.169.254",
	"multicast":               "224.0.0.251",
	"documentation multicast": "233.252.0.1",
	"this network":            "0.1.2.3",
	"reserved":                "240.0.0.1",
	"broadcast":               "255.255.255.255",
	"unspecified":             "0.0.0.0",
	"local bridge":            "192.0.2.77",
	"another bridge":          "203.0.113.200",
}

var testIfs = []iface{
	{Name: "br-lab", Bridge: true, Nets: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
	{Name: "virbr0", Bridge: true, Nets: []netip.Prefix{netip.MustParsePrefix("203.0.113.128/25")}},
	{Name: "eth1", Nets: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
}

func TestResolve_RefusesNodeBlocks(t *testing.T) {
	for name, addr := range refusedCases {
		fakeNet(t, []string{"198.51.100.7", addr}, testIfs)
		if got, err := Resolve(context.Background(), decl("https://s3.example.test"), testConfig()); err == nil || got != nil {
			t.Errorf("%s (%s): got %v, %v; want the whole answer refused", name, addr, got, err)
		}
	}
	// Control: the good address alone passes the same path.
	fakeNet(t, []string{"198.51.100.7"}, testIfs)
	if _, err := Resolve(context.Background(), decl("https://s3.example.test"), testConfig()); err != nil {
		t.Fatalf("control: %v", err)
	}
	// The blocks come from the configuration given, not from the defaults.
	c := testConfig()
	c.BackupSubnet = "10.215.9.0/24"
	fakeNet(t, []string{"10.215.9.5"}, nil)
	if _, err := Resolve(context.Background(), decl("https://s3.example.test"), c); err == nil {
		t.Error("an address in the configured backup subnet was accepted")
	}
	fakeNet(t, []string{"10.212.9.7"}, nil)
	if _, err := Resolve(context.Background(), decl("https://s3.example.test"), c); err != nil {
		t.Errorf("the default backup subnet was used instead of the configured one: %v", err)
	}
}

func TestResolve_RefusesAnAddressInsideALocalBridgeSubnet(t *testing.T) {
	fakeNet(t, []string{"192.0.2.77"}, testIfs)
	if _, err := Resolve(context.Background(), decl("https://s3.example.test"), testConfig()); err == nil {
		t.Fatal("an address inside a bridge's subnet was accepted")
	}
	// Control: an address inside the subnet of a non-bridge interface (an
	// uplink, a lab network) is accepted.
	fakeNet(t, []string{"198.51.100.9"}, testIfs)
	if _, err := Resolve(context.Background(), decl("https://s3.example.test"), testConfig()); err != nil {
		t.Fatalf("an address on a non-bridge interface's subnet was refused: %v", err)
	}
	// The interface list is read at the call, not once.
	fakeNet(t, []string{"198.51.100.9"}, []iface{{Name: "br-new", Bridge: true, Nets: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/25")}}})
	if _, err := Resolve(context.Background(), decl("https://s3.example.test"), testConfig()); err == nil {
		t.Fatal("a bridge that appeared later was not seen")
	}
	// An interface list that cannot be read refuses (unknown is not clean).
	old := interfaces
	interfaces = func() ([]iface, error) { return nil, errors.New("netlink") }
	if _, err := Resolve(context.Background(), decl("https://s3.example.test"), testConfig()); err == nil {
		t.Error("accepted without the interface list")
	}
	interfaces = old
}

func TestCheckAddrs_TheSameRefusalsWithoutALookup(t *testing.T) {
	fakeNet(t, nil, testIfs)
	lookupIP = func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("CheckAddrs looked up")
		return nil, nil
	}
	good := netip.MustParseAddrPort("198.51.100.7:443")
	for name, addr := range refusedCases {
		if err := CheckAddrs(testConfig(), []netip.AddrPort{good, netip.AddrPortFrom(netip.MustParseAddr(addr), 443)}); err == nil {
			t.Errorf("%s (%s) accepted", name, addr)
		}
	}
	for name, a := range map[string]netip.AddrPort{
		"ipv6":    netip.MustParseAddrPort("[2001:db8::1]:443"),
		"port 0":  netip.MustParseAddrPort("198.51.100.8:0"),
		"invalid": {},
	} {
		if err := CheckAddrs(testConfig(), []netip.AddrPort{good, a}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := CheckAddrs(testConfig(), []netip.AddrPort{good, netip.MustParseAddrPort("198.51.100.9:9443")}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if err := CheckAddrs(testConfig(), nil); err != nil {
		t.Errorf("an empty saved set: %v", err)
	}
	bad := testConfig()
	bad.DockerPool = "not a prefix"
	if err := CheckAddrs(bad, []netip.AddrPort{good}); err == nil {
		t.Error("a configuration whose blocks do not parse was accepted")
	}
}

// The real interface list: readable, the loopback is not a bridge, and a
// Docker bridge (when the host has one) is.
func TestInterfaces_ReadFromTheKernel(t *testing.T) {
	ifs, err := interfaces()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, i := range ifs {
		seen[i.Name] = i.Bridge
		for _, n := range i.Nets {
			if !n.Addr().Is4() || n != n.Masked() {
				t.Errorf("%s: %v is not a masked IPv4 network", i.Name, n)
			}
		}
	}
	if b, ok := seen["lo"]; !ok || b {
		t.Errorf("loopback: listed %v, bridge %v", ok, b)
	}
	if _, err := os.Stat("/sys/class/net/docker0/bridge"); err == nil && !seen["docker0"] {
		t.Error("docker0 is a bridge in sysfs but not listed as one")
	}
}
