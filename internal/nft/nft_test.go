package nft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// goldenRuleset is the rendered default ruleset, byte for byte.
const goldenRuleset = `# supapace node tables, loaded as one transaction before Docker starts. Only the
# two tables below are replaced; every other table is left as it is. Both base
# chains hook at priority filter - 10, ahead of Docker's own chains: a drop here
# is final, an accept only hands the packet on. Every rule carries its label as
# its comment.
table inet supapace
delete table inet supapace
table bridge supapace
delete table bridge supapace

define GATEWAY_IP = 10.212.0.2
define REST_ADDRS = 10.212.0.16-10.212.4.15
define STUDIO_IP = 10.212.0.3
define PGMETA_IPS = { 10.212.0.4, 10.212.0.5 }
define PGCAP_IP = 10.212.0.6
define META_PORTS = 20000-21023

table inet supapace {
	# the declared off-site endpoint's addresses and port, as the agent last
	# resolved them; possibly none
	set offsite4 {
		type ipv4_addr . inet_service
	}
	# traffic addressed to the host itself, IPv4 and IPv6
	chain input {
		type filter hook input priority filter - 10; policy accept;
		# replies to connections the host opened to the gateway
		iifname "spi0" ct state established,related accept comment "I1"
		# every bridge, named or not: no member opens anything on the host
		meta iifkind "bridge" drop comment "I2"
	}
	# routed traffic
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		# the gateway's replies to clients of its published ports
		iifname "spi0" ct state established,related accept comment "F1"
		# replication jobs: new TCP connections to the declared endpoint only
		iifname "spb0" ct state new ip daddr . tcp dport @offsite4 accept comment "F5"
		# replication jobs: the rest of a connection F5 accepted, also after its
		# address has left the set
		iifname "spb0" ct state established,related accept comment "F7"
		# nothing is routed out of any bridge
		meta iifkind "bridge" drop comment "F2"
		# clients to the gateway's published ports
		oifname "spi0" accept comment "F3"
		# replies to replication jobs
		oifname "spb0" ct state established,related accept comment "F6"
		# nothing is routed into any other bridge
		meta oifkind "bridge" drop comment "F4"
	}
}

table bridge supapace {
	# frames between members of one bridge. Bridges named nowhere below (other
	# software's, Docker's default) get nothing: their members cannot reach each
	# other while these tables are loaded
	chain forward {
		type filter hook forward priority filter - 10; policy drop;
		# project bridges: ARP, replies, and new connections to the cluster's port only
		meta ibrname "spp*" ether type arp accept comment "B1"
		meta ibrname "spp*" ether type ip ct state established,related accept comment "B2"
		meta ibrname "spp*" ether type ip ip daddr & 0.0.0.63 == 0.0.0.2 tcp dport 5432 ct state new accept comment "B3"
		# platform bridge: ARP, then a closed list of new connections (the gateway
		# to a PostgREST's and to Studio's port, Studio to postgres-meta,
		# postgres-meta to the proxy's meta ports); every other new connection is
		# dropped, whatever its source
		meta ibrname "spl0" ether type arp accept comment "B4"
		meta ibrname "spl0" ether type ip ip saddr $GATEWAY_IP ip daddr $REST_ADDRS tcp dport 3000 ct state new accept comment "B11"
		meta ibrname "spl0" ether type ip ip saddr $GATEWAY_IP ip daddr $STUDIO_IP tcp dport 3000 ct state new accept comment "B12"
		meta ibrname "spl0" ether type ip ip saddr $STUDIO_IP ip daddr $PGMETA_IPS tcp dport 8080 ct state new accept comment "B13"
		meta ibrname "spl0" ether type ip ip saddr $PGMETA_IPS ip daddr $PGCAP_IP tcp dport $META_PORTS ct state new accept comment "B14"
		meta ibrname "spl0" ether type ip ct state != { established, related } drop comment "B8"
		meta ibrname "spl0" ether type ip accept comment "B6"
		# backup bridge: replication jobs never reach each other
		meta ibrname "spb0" drop comment "B10"
		# everything else, including while a reload installs this chain before its policy
		drop comment "B9"
	}
}
`

func defaultConfig(t *testing.T) nodecfg.Config {
	t.Helper()
	c := nodecfg.Default("sp.test")
	if err := c.Validate(); err != nil {
		t.Fatalf("default config: %v", err)
	}
	return c
}

func render(t *testing.T, c nodecfg.Config) string {
	t.Helper()
	b, err := Render(c)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return string(b)
}

func TestRender_Golden(t *testing.T) {
	got := render(t, defaultConfig(t))
	if got != goldenRuleset {
		gl, wl := strings.Split(got, "\n"), strings.Split(goldenRuleset, "\n")
		for i := 0; i < len(gl) || i < len(wl); i++ {
			var g, w string
			if i < len(gl) {
				g = gl[i]
			}
			if i < len(wl) {
				w = wl[i]
			}
			if g != w {
				t.Fatalf("rendered ruleset differs from the golden text at line %d:\n got: %q\nwant: %q", i+1, g, w)
			}
		}
	}
	again := render(t, defaultConfig(t))
	if again != got {
		t.Fatal("two renderings of one configuration differ")
	}
	c := defaultConfig(t)
	c.GatewayIP = "10.212.0.9"
	if other := render(t, c); other != strings.Replace(goldenRuleset, "GATEWAY_IP = 10.212.0.2\n", "GATEWAY_IP = 10.212.0.9\n", 1) {
		t.Fatal("the gateway address is not the only input of the rendering")
	}
}

var (
	quadRE   = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`)
	ipv6RE   = regexp.MustCompile(`[0-9A-Fa-f]*::?[0-9A-Fa-f]+|[0-9A-Fa-f]+::`)
	sppIdxRE = regexp.MustCompile(`spp[0-9]`)
)

func TestRender_NoProjectIndexNoContainerAddress(t *testing.T) {
	got := render(t, defaultConfig(t))
	if m := sppIdxRE.FindString(got); m != "" {
		t.Errorf("ruleset names a project bridge by index: %q", m)
	}
	// The masked match of the cluster's address is the one place two dotted quads
	// appear that are not addresses.
	const mask = "ip daddr & 0.0.0.63 == 0.0.0.2 "
	if strings.Count(got, mask) != 1 {
		t.Fatalf("ruleset holds the masked cluster match %d times, want 1", strings.Count(got, mask))
	}
	rest := strings.Replace(got, mask, "", 1)
	// The node's static platform addresses, each once: the gateway, the two ends
	// of the PostgREST range, Studio, the two postgres-meta instances, the proxy.
	quads := quadRE.FindAllString(rest, -1)
	want := []string{"10.212.0.2", "10.212.0.16", "10.212.4.15", "10.212.0.3", "10.212.0.4", "10.212.0.5", "10.212.0.6"}
	if !slices.Equal(quads, want) {
		t.Errorf("addresses in the ruleset: %q, want the static platform addresses %q, each once", quads, want)
	}
	for _, l := range strings.Split(rest, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		if m := ipv6RE.FindString(l); m != "" {
			t.Errorf("IPv6 literal %q in rule line %q", m, l)
		}
	}
	t.Run("gateway address must be IPv4", func(t *testing.T) {
		for _, gw := range []string{"", "10.212.0.2; flush ruleset", "fe80::2", "10.212.0.2\n"} {
			c := defaultConfig(t)
			c.GatewayIP = gw
			if b, err := Render(c); err == nil {
				t.Errorf("Render with gateway_ip %q: no error, rendered %d bytes", gw, len(b))
			}
		}
	})
}

func TestRender_NeverFlushesRuleset(t *testing.T) {
	got := render(t, defaultConfig(t))
	if strings.Contains(got, "flush") {
		t.Error("ruleset contains a flush statement")
	}
	// Every table statement names one of our two tables.
	for i, l := range strings.Split(got, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || f[0] == "#" {
			continue
		}
		if f[0] == "delete" {
			f = f[1:]
		}
		if f[0] != "table" {
			continue
		}
		if len(f) < 3 || f[2] != "supapace" || (f[1] != "inet" && f[1] != "bridge") {
			t.Errorf("line %d names a foreign table: %q", i+1, l)
		}
	}
	for _, want := range []string{"\ndelete table inet supapace\n", "\ndelete table bridge supapace\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("ruleset does not replace its own table with %q", strings.TrimSpace(want))
		}
	}
}

// rule is one rule line of the rendered ruleset.
type rule struct{ table, chain, label, text string }

var commentRE = regexp.MustCompile(` comment "([^"]*)"$`)

// rules parses the rule lines of a rendered ruleset: every line inside a chain
// block that is neither the chain's type line nor a comment.
func rules(t *testing.T, s string) []rule {
	t.Helper()
	var out []rule
	var table, chain string
	var inSet bool
	for i, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) == 0 || f[0] == "#":
		case f[0] == "table" && len(f) == 4 && f[3] == "{":
			table = f[1] + " " + f[2]
		case f[0] == "set" && len(f) == 3 && f[2] == "{":
			inSet = true
		case inSet:
			inSet = f[0] != "}"
		case f[0] == "chain" && len(f) == 3 && f[2] == "{":
			chain = f[1]
		case f[0] == "}":
			if chain != "" {
				chain = ""
			} else {
				table = ""
			}
		case f[0] == "type" && chain != "":
		case chain != "":
			m := commentRE.FindStringSubmatch(strings.TrimSpace(l))
			if m == nil {
				t.Errorf("line %d: rule without a trailing comment: %q", i+1, l)
				continue
			}
			out = append(out, rule{table, chain, m[1], strings.TrimSpace(l)})
		}
	}
	return out
}

func TestRender_EveryRuleHasUniqueComment(t *testing.T) {
	rs := rules(t, render(t, defaultConfig(t)))
	want := map[string]string{ // label → table/chain
		"I1": "inet supapace/input", "I2": "inet supapace/input",
		"F1": "inet supapace/forward", "F5": "inet supapace/forward", "F6": "inet supapace/forward", "F7": "inet supapace/forward", "F2": "inet supapace/forward", "F3": "inet supapace/forward", "F4": "inet supapace/forward",
	}
	for _, l := range []string{"B1", "B2", "B3", "B4", "B11", "B12", "B13", "B14", "B6", "B8", "B9", "B10"} {
		want[l] = "bridge supapace/forward"
	}
	seen := map[string]bool{}
	var order []string
	for _, r := range rs {
		key := r.table + "/" + r.chain + "/" + r.label
		if seen[key] {
			t.Errorf("label %q twice in %s %s", r.label, r.table, r.chain)
		}
		seen[key] = true
		if w, ok := want[r.label]; !ok || w != r.table+"/"+r.chain {
			t.Errorf("rule %q: label %q in %s/%s, want %q", r.text, r.label, r.table, r.chain, w)
		}
		order = append(order, r.label)
	}
	if len(rs) != len(want) {
		t.Errorf("%d rules, want %d", len(rs), len(want))
	}
	// The closed list B11–B14 sits before B8, which drops every other new
	// connection; B8 before B6, which accepts the rest of the platform bridge; B9
	// is last.
	if got := strings.Join(order, " "); got != closedListOrder {
		t.Errorf("rule order %q", got)
	}
}

func ruleText(t *testing.T, label string) string {
	t.Helper()
	for _, r := range rules(t, render(t, defaultConfig(t))) {
		if r.label == label {
			return r.text
		}
	}
	t.Fatalf("no rule labelled %s", label)
	return ""
}

func TestRender_B8MatchesNotEstablishedOrRelated(t *testing.T) {
	b8 := ruleText(t, "B8")
	// "new" alone would let invalid and untracked frames fall through to B6.
	if !strings.Contains(b8, "ct state != { established, related } drop") || strings.Contains(b8, "ct state new") {
		t.Errorf("B8 = %q, want a drop of every state but established and related", b8)
	}
	if !strings.HasPrefix(b8, `meta ibrname "spl0" ether type ip ct state`) {
		t.Errorf("B8 = %q, want it limited to the platform bridge, on every source", b8)
	}
	if strings.Contains(b8, "dport") {
		t.Errorf("B8 = %q, want it on every port", b8)
	}
}

// closedListOrder is the label order of the whole ruleset.
const closedListOrder = "I1 I2 F1 F5 F7 F2 F3 F6 F4 B1 B2 B3 B4 B11 B12 B13 B14 B8 B6 B10 B9"

// closedListRecorded are the defines and the four flow rules of the default node.
var closedListRecorded = []string{
	"define REST_ADDRS = 10.212.0.16-10.212.4.15",
	"define STUDIO_IP = 10.212.0.3",
	"define PGMETA_IPS = { 10.212.0.4, 10.212.0.5 }",
	"define PGCAP_IP = 10.212.0.6",
	"define META_PORTS = 20000-21023",
	`		meta ibrname "spl0" ether type ip ip saddr $GATEWAY_IP ip daddr $REST_ADDRS tcp dport 3000 ct state new accept comment "B11"`,
	`		meta ibrname "spl0" ether type ip ip saddr $GATEWAY_IP ip daddr $STUDIO_IP tcp dport 3000 ct state new accept comment "B12"`,
	`		meta ibrname "spl0" ether type ip ip saddr $STUDIO_IP ip daddr $PGMETA_IPS tcp dport 8080 ct state new accept comment "B13"`,
	`		meta ibrname "spl0" ether type ip ip saddr $PGMETA_IPS ip daddr $PGCAP_IP tcp dport $META_PORTS ct state new accept comment "B14"`,
}

func labelOrder(t *testing.T, s string) string {
	t.Helper()
	var order []string
	for _, r := range rules(t, s) {
		order = append(order, r.label)
	}
	return strings.Join(order, " ")
}

func TestRender_ClosedList_Recorded(t *testing.T) {
	c := defaultConfig(t)
	got := render(t, c)
	if o := labelOrder(t, got); o != closedListOrder {
		t.Errorf("rule order %q, want %q", o, closedListOrder)
	}
	if dashcfg.StudioPort != 3000 || dashcfg.PgMetaPort != 8080 {
		t.Errorf("B12 and B13 name ports 3000 and 8080; dashcfg has Studio at %d, postgres-meta at %d", dashcfg.StudioPort, dashcfg.PgMetaPort)
	}
	for _, l := range closedListRecorded {
		if n := strings.Count(got, "\n"+l+"\n"); n != 1 {
			t.Errorf("line %q appears %d times, want 1", l, n)
		}
	}
	// The inputs are dashcfg.Static's: another platform subnet and project block
	// move every one.
	o := defaultConfig(t)
	o.PlatformSubnet, o.PlatformIPRange, o.GatewayIP = "10.215.208.0/21", "10.215.214.0/23", "10.215.208.2"
	o.ProjectBlock = "10.213.0.0/17"
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	a := dashcfg.Static(o)
	other := render(t, o)
	for _, l := range []string{
		fmt.Sprintf("define REST_ADDRS = %s-%s", a.RestLo, a.RestHi),
		fmt.Sprintf("define STUDIO_IP = %s", a.Studio),
		fmt.Sprintf("define PGMETA_IPS = { %s, %s }", a.PgMeta0, a.PgMeta1),
		fmt.Sprintf("define PGCAP_IP = %s", a.Pgcap),
		fmt.Sprintf("define META_PORTS = %d-%d", a.MetaPortLo, a.MetaPortHi),
	} {
		if !strings.Contains(other, "\n"+l+"\n") || strings.Contains(got, "\n"+l+"\n") {
			t.Errorf("define %q does not follow dashcfg.Static", l)
		}
	}
	// The same text on a node with and without a studio domain: the closed list
	// is static.
	d := defaultConfig(t)
	d.StudioDomain = "studio.test"
	if err := d.Validate(); err != nil {
		t.Fatalf("a node with a studio domain: %v", err)
	}
	if render(t, d) != got {
		t.Error("the ruleset depends on the studio domain")
	}
}

func TestRender_B8MatchesEverySource(t *testing.T) {
	b8 := ruleText(t, "B8")
	for _, m := range []string{"saddr", "daddr", "dport", "$"} {
		if strings.Contains(b8, m) {
			t.Errorf("B8 = %q matches %q, want every source, destination and port", b8, m)
		}
	}
	// Every rule of the platform bridge that accepts a new connection is before
	// B8 and names a source, a destination and a port: the list is closed.
	var spl0 []string
	for _, r := range rules(t, render(t, defaultConfig(t))) {
		if strings.HasPrefix(r.text, `meta ibrname "spl0" `) {
			spl0 = append(spl0, r.label)
			if r.label == "B4" || r.label == "B8" || r.label == "B6" {
				continue
			}
			if !strings.Contains(r.text, " ip saddr $") || !strings.Contains(r.text, " ip daddr $") ||
				!strings.Contains(r.text, " tcp dport ") || !strings.HasSuffix(r.text, ` ct state new accept comment "`+r.label+`"`) {
				t.Errorf("platform rule %q is not one flow: a source, a destination, a port, new connections", r.text)
			}
		}
	}
	if got := strings.Join(spl0, " "); got != "B4 B11 B12 B13 B14 B8 B6" {
		t.Errorf("platform bridge rules %q, want B4, the list, B8, B6", got)
	}
}

// zeroCase is a set of zero dashboard inputs and the rules and defines that the
// rendering must then leave out; sets maps a define to its remaining text.
type zeroCase struct {
	name    string
	zero    func(*dashcfg.Addrs)
	gone    []string // labels
	defines []string // define names left out
	sets    map[string]string
}

var zeroCases = []zeroCase{
	{"studio", func(a *dashcfg.Addrs) { a.Studio = netip.Addr{} }, []string{"B12", "B13"}, []string{"STUDIO_IP"}, nil},
	{"postgres-meta 0", func(a *dashcfg.Addrs) { a.PgMeta0 = netip.Addr{} }, nil, nil, map[string]string{"PGMETA_IPS": "{ 10.212.0.5 }"}},
	{"postgres-meta 1", func(a *dashcfg.Addrs) { a.PgMeta1 = netip.Addr{} }, nil, nil, map[string]string{"PGMETA_IPS": "{ 10.212.0.4 }"}},
	{"both postgres-meta", func(a *dashcfg.Addrs) { a.PgMeta0, a.PgMeta1 = netip.Addr{}, netip.Addr{} }, []string{"B13", "B14"}, []string{"PGMETA_IPS"}, nil},
	{"proxy", func(a *dashcfg.Addrs) { a.Pgcap = netip.Addr{} }, []string{"B14"}, []string{"PGCAP_IP"}, nil},
	{"meta ports", func(a *dashcfg.Addrs) { a.MetaPortLo, a.MetaPortHi = 0, 0 }, []string{"B14"}, []string{"META_PORTS"}, nil},
	{"postgrest range", func(a *dashcfg.Addrs) { a.RestLo, a.RestHi = netip.Addr{}, netip.Addr{} }, []string{"B11"}, []string{"REST_ADDRS"}, nil},
	{"postgrest range end", func(a *dashcfg.Addrs) { a.RestHi = netip.Addr{} }, []string{"B11"}, []string{"REST_ADDRS"}, nil},
	{"postgrest range start", func(a *dashcfg.Addrs) { a.RestLo = netip.Addr{} }, []string{"B11"}, []string{"REST_ADDRS"}, nil},
	{"studio and both postgres-meta", func(a *dashcfg.Addrs) { a.Studio, a.PgMeta0, a.PgMeta1 = netip.Addr{}, netip.Addr{}, netip.Addr{} },
		[]string{"B12", "B13", "B14"}, []string{"STUDIO_IP", "PGMETA_IPS"}, nil},
	{"every input", func(a *dashcfg.Addrs) { *a = dashcfg.Addrs{} }, []string{"B11", "B12", "B13", "B14"},
		[]string{"REST_ADDRS", "STUDIO_IP", "PGMETA_IPS", "PGCAP_IP", "META_PORTS"}, nil},
	{"one slice", func(a *dashcfg.Addrs) { a.RestHi, a.MetaPortHi = a.RestLo, a.MetaPortLo }, nil, nil,
		map[string]string{"REST_ADDRS": "10.212.0.16", "META_PORTS": "20000"}},
}

// zeroRender renders the default node with zc's inputs zeroed.
func zeroRender(t testing.TB, zc zeroCase) []byte {
	t.Helper()
	c := nodecfg.Default("sp.test")
	a := dashcfg.Static(c)
	zc.zero(&a)
	b, err := renderAddrs(netip.MustParseAddr(c.GatewayIP), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var emptySetRE = regexp.MustCompile(`\{\s*\}`)

func TestRender_ZeroInputOmitsTheRule(t *testing.T) {
	full := map[string]string{}
	for _, r := range rules(t, render(t, defaultConfig(t))) {
		full[r.label] = r.text
	}
	for _, zc := range zeroCases {
		t.Run(zc.name, func(t *testing.T) {
			got := string(zeroRender(t, zc))
			left := map[string]bool{}
			for _, r := range rules(t, got) {
				left[r.label] = true
				if r.text != full[r.label] {
					t.Errorf("rule %s = %q, want it as on the default node", r.label, r.text)
				}
			}
			for l := range full {
				if left[l] == slices.Contains(zc.gone, l) {
					t.Errorf("rule %s present %v, want %v", l, left[l], !left[l])
				}
			}
			for _, d := range zc.defines {
				if strings.Contains(got, "define "+d+" ") || strings.Contains(got, "$"+d+" ") {
					t.Errorf("%s still defined or named", d)
				}
			}
			for d, v := range zc.sets {
				if !strings.Contains(got, "\ndefine "+d+" = "+v+"\n") {
					t.Errorf("define %s is not %q", d, v)
				}
			}
			if strings.Contains(got, "invalid IP") || emptySetRE.MatchString(got) || strings.Contains(got, " = \n") {
				t.Errorf("the text holds an invalid address or an empty set:\n%s", got)
			}
			nftCheck(t, []byte(got))
		})
	}
	// Through the configuration: a gateway at Studio's address leaves Studio zero.
	c := defaultConfig(t)
	c.GatewayIP = "10.212.0.3"
	if dashcfg.Static(c).Studio.IsValid() {
		t.Fatal("dashcfg.Static kept a Studio address equal to the gateway's")
	}
	got := render(t, c)
	if strings.Contains(got, `"B12"`) || strings.Contains(got, `"B13"`) || strings.Contains(got, "STUDIO_IP") || !strings.Contains(got, `"B11"`) {
		t.Errorf("gateway at Studio's address: the rendering keeps a Studio rule or loses B11:\n%s", got)
	}
	nftCheck(t, []byte(got))
}

// nftCheck parses text with nft -c in a network namespace of an unprivileged
// user namespace, where the host allows one; the bare-node proof loads the
// same renderings as root.
func nftCheck(t *testing.T, text []byte) {
	t.Helper()
	bin := "/usr/sbin/nft"
	if _, err := os.Stat(bin); err != nil {
		if bin, err = exec.LookPath("nft"); err != nil {
			t.Log("nft is not installed: the text is not parsed here")
			return
		}
	}
	if exec.Command("unshare", "-rn", bin, "list", "tables").Run() != nil {
		t.Log("no unprivileged network namespace with nft here: the text is not parsed here")
		return
	}
	f := filepath.Join(t.TempDir(), "ruleset.nft")
	if err := os.WriteFile(f, text, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("unshare", "-rn", bin, "-c", "-f", f).CombinedOutput(); err != nil {
		t.Errorf("nft -c: %v: %s", err, out)
	}
}

// While Load replaces the bridge table the new chain can be in force before
// its policy is: its own last rule must drop whatever no rule accepted.
func TestRender_BridgeForwardEndsInDrop(t *testing.T) {
	var last rule
	for _, r := range rules(t, render(t, defaultConfig(t))) {
		if r.table == "bridge supapace" && r.chain == "forward" {
			last = r
		}
	}
	if last.text != `drop comment "B9"` {
		t.Errorf("last rule of the bridge forward chain is %q, want an unconditional drop labelled B9", last.text)
	}
	if !strings.Contains(render(t, defaultConfig(t)), "type filter hook forward priority filter - 10; policy drop;") {
		t.Error("the bridge forward chain's policy is not drop")
	}
}

// unitDirectives parses a unit file into section.key → values, in order; a key
// given twice keeps both values.
func unitDirectives(t *testing.T, name string, text []byte) map[string][]string {
	t.Helper()
	d := map[string][]string{}
	section := ""
	for i, l := range strings.Split(string(text), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "" || l[0] == '#' || l[0] == ';':
		case l[0] == '[' && l[len(l)-1] == ']':
			section = l[1 : len(l)-1]
		default:
			k, v, ok := strings.Cut(l, "=")
			if !ok || section == "" {
				t.Fatalf("%s line %d: %q is not a directive", name, i+1, l)
			}
			d[section+"."+k] = append(d[section+"."+k], strings.Fields(v)...)
		}
	}
	return d
}

func TestUnits_Ordering(t *testing.T) {
	u := Units()
	var names []string
	for n := range u {
		names = append(names, n)
	}
	slices.Sort(names)
	if got := strings.Join(names, " "); got != "docker-10-supapace.conf supapace-nft.service supapaced.service" {
		t.Fatalf("Units() files: %s", got)
	}
	expect := func(file, key string, want ...string) {
		t.Helper()
		got := unitDirectives(t, file, u[file])[key]
		if !slices.Equal(got, want) {
			t.Errorf("%s %s = %q, want %q", file, key, got, want)
		}
	}
	nftUnit := "supapace-nft.service"
	expect(nftUnit, "Unit.Before", "docker.service")
	expect(nftUnit, "Unit.After", "nftables.service", "firewalld.service")
	expect(nftUnit, "Unit.PartOf", "docker.service", "nftables.service")
	expect(nftUnit, "Service.Type", "oneshot")
	expect(nftUnit, "Service.RemainAfterExit", "yes")
	expect(nftUnit, "Service.ExecStart", "/usr/local/bin/supapaced", "nft", "load")
	// A reload of the distribution's firewall replaces the whole ruleset.
	expect(nftUnit, "Unit.ReloadPropagatedFrom", "nftables.service")
	expect(nftUnit, "Service.ExecReload", "/usr/local/bin/supapaced", "nft", "load")

	dropIn := "docker-10-supapace.conf"
	expect(dropIn, "Unit.Requires", "supapace-nft.service")
	expect(dropIn, "Unit.After", "supapace-nft.service")
	// A stop and a later start of Docker bring the daemon back.
	expect(dropIn, "Unit.Wants", "supapaced.service")
	if d := unitDirectives(t, dropIn, u[dropIn]); len(d) != 3 {
		t.Errorf("%s holds %d directives, want exactly Requires, After and Wants: %q", dropIn, len(d), d)
	}
	if bytes.Contains(u[dropIn], []byte("BR_NETFILTER")) {
		t.Errorf("%s overrides Docker's bridge-netfilter check", dropIn)
	}

	daemon := "supapaced.service"
	expect(daemon, "Unit.After", "docker.service", "supapace-nft.service")
	expect(daemon, "Service.Restart", "always")
	expect(daemon, "Service.RestartSec", "1")
	// Without this, five quick failures would stop systemd from restarting it.
	expect(daemon, "Unit.StartLimitIntervalSec", "0")
	expect(daemon, "Service.ExecStart", "/usr/local/bin/supapaced", "serve")
	// The daemon restarts with Docker; its start-up brings the projects back.
	expect(daemon, "Unit.PartOf", "docker.service")
	expect(daemon, "Service.UMask", "0077")
	// /run/supapace exists before the daemon starts, root 0700, and is kept
	// across daemon restarts (the boot record is written once per boot).
	expect(daemon, "Service.RuntimeDirectory", "supapace")
	expect(daemon, "Service.RuntimeDirectoryMode", "0700")
	expect(daemon, "Service.RuntimeDirectoryPreserve", "yes")
}

// Stopping the tables unit must leave the tables in place: a stop of Docker or
// of the distribution's firewall propagates to it.
func TestUnits_StopLeavesTables(t *testing.T) {
	d := unitDirectives(t, "supapace-nft.service", Units()["supapace-nft.service"])
	for _, k := range []string{"Service.ExecStop", "Service.ExecStopPost"} {
		if v, ok := d[k]; ok {
			t.Errorf("supapace-nft.service %s = %q: stopping the unit must not touch the tables", k, v)
		}
	}
}

// fakeProcSys points procSys at a temporary tree holding the given bridge-nf
// switches (name → content); a nil map leaves net/bridge absent.
func fakeProcSys(t *testing.T, keys map[string]string) string {
	t.Helper()
	root := t.TempDir()
	old := procSys
	procSys = root
	t.Cleanup(func() { procSys = old })
	if keys == nil {
		return root
	}
	dir := filepath.Join(root, "net", "bridge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range keys {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestEnsureBridgeNF_WritesZeroWhenPresent(t *testing.T) {
	all := []string{"bridge-nf-call-iptables", "bridge-nf-call-ip6tables", "bridge-nf-call-arptables"}
	t.Run("all three on", func(t *testing.T) {
		keys := map[string]string{}
		for _, k := range all {
			keys[k] = "1\n"
		}
		dir := fakeProcSys(t, keys)
		if err := EnsureBridgeNF(); err != nil {
			t.Fatal(err)
		}
		for _, k := range all {
			if b, _ := os.ReadFile(filepath.Join(dir, k)); string(b) != "0\n" {
				t.Errorf("%s = %q after EnsureBridgeNF, want \"0\\n\"", k, b)
			}
		}
	})
	t.Run("module absent", func(t *testing.T) {
		root := fakeProcSys(t, nil)
		if err := EnsureBridgeNF(); err != nil {
			t.Fatalf("no bridge-nf switches: %v, want nil", err)
		}
		if _, err := os.Stat(filepath.Join(root, "net")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("EnsureBridgeNF created files under a missing net/bridge: %v", err)
		}
	})
	t.Run("one switch present", func(t *testing.T) {
		dir := fakeProcSys(t, map[string]string{"bridge-nf-call-iptables": "1\n"})
		if err := EnsureBridgeNF(); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "bridge-nf-call-iptables")); string(b) != "0\n" {
			t.Errorf("bridge-nf-call-iptables = %q", b)
		}
		for _, k := range all[1:] {
			if _, err := os.Stat(filepath.Join(dir, k)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("EnsureBridgeNF created %s", k)
			}
		}
	})
	t.Run("unwritable switch", func(t *testing.T) {
		dir := fakeProcSys(t, map[string]string{})
		// A directory in place of the switch cannot be opened for writing, as root either.
		if err := os.Mkdir(filepath.Join(dir, "bridge-nf-call-iptables"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := EnsureBridgeNF(); err == nil {
			t.Error("a switch that cannot be written: nil error")
		}
	})
}

// fakeNft puts an nft on PATH that lists the given tables: `list tables` prints
// one line per table, `-s list table F N` prints listing[F N] or fails like nft
// does for a missing table.
func fakeNft(t *testing.T, listing map[string]string) {
	t.Helper()
	dir := t.TempDir()
	var sb strings.Builder
	sb.WriteString("#!/bin/sh\necho \"$*\" >>\"${0%/*}/calls\"\ncase \"$*\" in\n\"-f -\") cat >\"${0%/*}/loaded\" ;;\n\"list tables\")\n")
	var tables []string
	for k := range listing {
		tables = append(tables, k)
	}
	slices.Sort(tables)
	for _, k := range tables {
		fmt.Fprintf(&sb, "echo 'table %s'\n", k)
	}
	sb.WriteString(";;\n")
	for _, k := range tables {
		fmt.Fprintf(&sb, "\"-s list table %s\") printf '%%s' '%s' ;;\n", k, listing[k])
	}
	sb.WriteString("*) echo 'Error: No such file or directory' >&2; exit 1 ;;\nesac\n")
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(sb.String()), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// fakeNftScript puts an nft on PATH whose body is script.
func fakeNftScript(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// loadedNode writes the rendered file and a sum file matching the fake tables,
// as Load would leave them.
func loadedNode(t *testing.T) nodecfg.Paths {
	t.Helper()
	listing := map[string]string{"inet supapace": "table inet supapace {\n}\n", "bridge supapace": "table bridge supapace {\n}\n"}
	fakeNft(t, listing)
	p := nodecfg.Paths{Root: t.TempDir()}
	file := []byte(render(t, defaultConfig(t)))
	if err := os.MkdirAll(filepath.Dir(p.NftFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.NftFile(), file, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.NftSum(), sums(file, []byte(listing["inet supapace"]+listing["bridge supapace"])), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheck_ErrBridgeNFWhenStillOne(t *testing.T) {
	ctx := context.Background()
	t.Run("switch on", func(t *testing.T) {
		p := loadedNode(t)
		fakeProcSys(t, map[string]string{"bridge-nf-call-iptables": "0\n", "bridge-nf-call-ip6tables": "1\n", "bridge-nf-call-arptables": "0\n"})
		if err := Check(ctx, p); !errors.Is(err, ErrBridgeNF) {
			t.Fatalf("Check with bridge-nf-call-ip6tables = 1: %v, want ErrBridgeNF", err)
		}
	})
	t.Run("all off", func(t *testing.T) {
		p := loadedNode(t)
		fakeProcSys(t, map[string]string{"bridge-nf-call-iptables": "0\n", "bridge-nf-call-ip6tables": "0\n", "bridge-nf-call-arptables": "0\n"})
		if err := Check(ctx, p); err != nil {
			t.Fatalf("Check with every switch 0: %v", err)
		}
	})
	t.Run("module absent", func(t *testing.T) {
		p := loadedNode(t)
		fakeProcSys(t, nil)
		if err := Check(ctx, p); err != nil {
			t.Fatalf("Check without bridge-nf switches: %v, want nil", err)
		}
	})
	t.Run("table absent", func(t *testing.T) {
		p := loadedNode(t)
		fakeProcSys(t, nil)
		fakeNft(t, map[string]string{"inet supapace": "table inet supapace {\n}\n"})
		if err := Check(ctx, p); !errors.Is(err, ErrAbsent) {
			t.Fatalf("Check without the bridge table: %v, want ErrAbsent", err)
		}
	})
	t.Run("listing changed", func(t *testing.T) {
		p := loadedNode(t)
		fakeProcSys(t, nil)
		fakeNft(t, map[string]string{"inet supapace": "table inet supapace {\n}\n", "bridge supapace": "table bridge supapace {\n\tchain forward {\n\t}\n}\n"})
		if err := Check(ctx, p); !errors.Is(err, ErrDrift) {
			t.Fatalf("Check with a changed bridge table: %v, want ErrDrift", err)
		}
	})
}

// Every failure to examine the tables is ErrUnverified, never one of the
// verdicts on their content.
func TestCheck_ErrUnverifiedWhenNftFails(t *testing.T) {
	verdicts := []error{ErrAbsent, ErrDrift, ErrBridgeNF}
	for _, c := range []struct {
		name, script string
		timeout      time.Duration
	}{
		{"exit with other text", "echo 'Error: Operation not permitted' >&2; exit 1", 0},
		{"listing fails", `case "$*" in "list tables") echo 'table inet supapace'; echo 'table bridge supapace';; *) echo 'Error: netlink: Operation not permitted' >&2; exit 1;; esac`, 0},
		{"timed out", "exec /bin/sleep 5", 200 * time.Millisecond},
		{"not runnable", "", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := loadedNode(t)
			fakeProcSys(t, nil)
			if c.script == "" {
				t.Setenv("PATH", t.TempDir())
			} else {
				fakeNftScript(t, c.script)
			}
			ctx := context.Background()
			if c.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, c.timeout)
				defer cancel()
			}
			err := Check(ctx, p)
			if !errors.Is(err, ErrUnverified) {
				t.Fatalf("Check: %v, want ErrUnverified", err)
			}
			for _, v := range verdicts {
				if errors.Is(err, v) {
					t.Errorf("Check: %v is also %v", err, v)
				}
			}
			if err := Load(ctx, p); !errors.Is(err, ErrUnverified) {
				t.Errorf("Load: %v, want ErrUnverified", err)
			}
		})
	}
}

// Load puts the tables in place first; a bridge-nf switch it cannot write is
// reported afterwards.
func TestLoad_TablesBeforeBridgeNF(t *testing.T) {
	p := loadedNode(t)
	if err := os.Remove(p.NftSum()); err != nil {
		t.Fatal(err)
	}
	dir := fakeProcSys(t, map[string]string{})
	if err := os.Mkdir(filepath.Join(dir, "bridge-nf-call-iptables"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := Load(context.Background(), p)
	if err == nil || errors.Is(err, ErrUnverified) {
		t.Fatalf("Load with an unwritable switch: %v, want the switch's error", err)
	}
	calls, _ := os.ReadFile(filepath.Join(filepath.Dir(lookPath(t, "nft")), "calls"))
	if !strings.HasPrefix(string(calls), "-f -\n") {
		t.Errorf("nft calls %q, want the load first", calls)
	}
	loaded, _ := os.ReadFile(filepath.Join(filepath.Dir(lookPath(t, "nft")), "loaded"))
	if file, _ := os.ReadFile(p.NftFile()); !bytes.Equal(loaded, file) {
		t.Error("the ruleset file was not loaded")
	}
	if _, err := os.Stat(p.NftSum()); err != nil {
		t.Errorf("sum file not written: %v", err)
	}
}

func lookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRender_EmptySet(t *testing.T) {
	got := render(t, defaultConfig(t))
	if !strings.Contains(got, "\tset offsite4 {\n\t\ttype ipv4_addr . inet_service\n\t}\n") {
		t.Error("without elements the set is not declared empty")
	}
}

func TestRender_Elements_SortedStable(t *testing.T) {
	c := defaultConfig(t)
	a, b := netip.MustParseAddrPort("192.0.2.20:443"), netip.MustParseAddrPort("192.0.2.3:9443")
	x, err := RenderWith(c, []netip.AddrPort{a, b, a})
	if err != nil {
		t.Fatal(err)
	}
	y, _ := RenderWith(c, []netip.AddrPort{b, a})
	if !bytes.Equal(x, y) {
		t.Error("the same set in another order renders other bytes")
	}
	if !strings.Contains(string(x), "\t\telements = { 192.0.2.3 . 9443, 192.0.2.20 . 443 }\n") {
		t.Errorf("elements not sorted and deduplicated:\n%s", x)
	}
	if want := strings.Replace(render(t, c), "\t\ttype ipv4_addr . inet_service\n", "\t\ttype ipv4_addr . inet_service\n\t\telements = { 192.0.2.3 . 9443, 192.0.2.20 . 443 }\n", 1); string(x) != want {
		t.Error("the elements are not the only difference to the empty rendering")
	}
	for _, bad := range []netip.AddrPort{{}, netip.MustParseAddrPort("[2001:db8::1]:443"), netip.MustParseAddrPort("192.0.2.1:0")} {
		if _, err := RenderWith(c, []netip.AddrPort{bad}); err == nil {
			t.Errorf("element %q accepted", bad)
		}
	}
}

// The meta ports the template names are a valid range or nothing, for every
// slice count: dashcfg.Static gives 0–0 or MetaPortBase ≤ lo ≤ hi ≤ 65535, and
// the rendering has no reversed or out-of-range ports (the renderer keeps no
// check of its own; this test is what guards a change of Static).
func TestRender_MetaPortsAlwaysAValidRange(t *testing.T) {
	re := regexp.MustCompile(`(?m)^define META_PORTS = (\d+)(?:-(\d+))?$`)
	for _, block := range []string{"10.212.0.0/14", "10.213.0.0/16", "10.213.0.0/20", "10.213.0.0/24"} {
		bits := netip.MustParsePrefix(block).Bits()
		for prefix := bits; prefix <= 30; prefix++ {
			c := defaultConfig(t)
			c.ProjectBlock, c.SlicePrefix = block, prefix
			a := dashcfg.Static(c)
			if a.MetaPortLo != 0 && (a.MetaPortLo != dashcfg.MetaPortBase || a.MetaPortHi < a.MetaPortLo || a.MetaPortHi > 65535) ||
				a.MetaPortLo == 0 && a.MetaPortHi != 0 {
				t.Errorf("block /%d slices /%d: meta ports %d-%d", bits, prefix, a.MetaPortLo, a.MetaPortHi)
			}
			got := render(t, c)
			m := re.FindStringSubmatch(got)
			if m == nil {
				if a.MetaPortLo != 0 || strings.Contains(got, "META_PORTS") {
					t.Errorf("block /%d slices /%d: META_PORTS %v, Static %d-%d", bits, prefix, m, a.MetaPortLo, a.MetaPortHi)
				}
				continue
			}
			lo, _ := strconv.Atoi(m[1])
			hi := lo
			if m[2] != "" {
				hi, _ = strconv.Atoi(m[2])
				if hi <= lo {
					t.Errorf("block /%d slices /%d: range %s-%s", bits, prefix, m[1], m[2])
				}
			}
			if lo != a.MetaPortLo || hi != a.MetaPortHi || hi > 65535 {
				t.Errorf("block /%d slices /%d: rendered %d-%d, Static %d-%d", bits, prefix, lo, hi, a.MetaPortLo, a.MetaPortHi)
			}
		}
	}
}
