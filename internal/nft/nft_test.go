package nft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

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

table inet supapace {
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
		# nothing is routed out of any bridge
		meta iifkind "bridge" drop comment "F2"
		# clients to the gateway's published ports
		oifname "spi0" accept comment "F3"
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
		# platform bridge: only the gateway opens connections
		meta ibrname "spl0" ether type arp accept comment "B4"
		meta ibrname "spl0" ether type ip ip saddr != $GATEWAY_IP ct state != { established, related } drop comment "B8"
		meta ibrname "spl0" ether type ip accept comment "B6"
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
	quads := quadRE.FindAllString(rest, -1)
	if len(quads) != 1 || quads[0] != "10.212.0.2" {
		t.Errorf("addresses in the ruleset: %q, want only the gateway's 10.212.0.2, once", quads)
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
	for i, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) == 0 || f[0] == "#":
		case f[0] == "table" && len(f) == 4 && f[3] == "{":
			table = f[1] + " " + f[2]
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
		"F1": "inet supapace/forward", "F2": "inet supapace/forward", "F3": "inet supapace/forward", "F4": "inet supapace/forward",
	}
	for _, l := range []string{"B1", "B2", "B3", "B4", "B6", "B8", "B9"} {
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
	// B8 sits before B6, which accepts the rest of the platform bridge; B9 is last.
	if got := strings.Join(order, " "); got != "I1 I2 F1 F2 F3 F4 B1 B2 B3 B4 B8 B6 B9" {
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
	if !strings.HasPrefix(b8, `meta ibrname "spl0" ether type ip ip saddr != $GATEWAY_IP ct state`) {
		t.Errorf("B8 = %q, want it limited to the platform bridge and to sources other than the gateway", b8)
	}
	if strings.Contains(b8, "dport") {
		t.Errorf("B8 = %q, want it on every port", b8)
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
