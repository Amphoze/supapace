package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// poolerArgs names the pooler label and the pair in in/pooler-*.
func poolerArgs(n *node, label string) []string {
	return []string{"--pooler-label", label, "--pooler-tls-cert", n.path("in/pooler-cert.pem"), "--pooler-tls-key", n.path("in/pooler-key.pem")}
}

// nodeFile is node.json as written.
func nodeFile(t *testing.T, n *node) nodecfg.Config {
	t.Helper()
	c, err := nodecfg.Load(n.p.NodeJSON())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// onlyNodeFileChanged fails the test when anything but node.json (and
// directories in dirs, which may gain entries) changed or went away.
func onlyNodeFileChanged(t *testing.T, n *node, before map[string]string, dirs ...string) {
	t.Helper()
	after := snapshot(t, n.root)
	for k, v := range before {
		if k != n.p.NodeJSON() && k != filepath.Dir(n.p.NodeJSON()) && !slices.Contains(dirs, k) && after[k] != v {
			t.Errorf("changed: %s", k)
		}
	}
}

// leaf is the certificate of the pair in dir, which must match its key.
func leaf(t *testing.T, n *node, dir string) *x509.Certificate {
	t.Helper()
	pair, err := tls.X509KeyPair(n.read(dir+"/cert.pem"), n.read(dir+"/key.pem"))
	if err != nil {
		t.Fatalf("%s: %v", dir, err)
	}
	return pair.Leaf
}

func TestInit_PoolerLabelNeedsItsPair(t *testing.T) {
	t.Run("usage", func(t *testing.T) {
		n := newNode(t)
		validPair(t, n, "", "*.sp.test")
		validPair(t, n, "pooler-", "*.db.sp.test")
		for name, c := range map[string]struct {
			args []string
			word string
		}{
			"label without the pair": {append(baseArgs(n, "sp.test"), "--pooler-label", "db"), "--pooler-tls-cert"},
			"pair without a label":   {append(baseArgs(n, "sp.test"), poolerArgs(n, "db")[2:]...), "--pooler-label"},
			"certificate alone":      {append(baseArgs(n, "sp.test"), poolerArgs(n, "db")[:4]...), "--pooler-tls-key"},
			"a pair with --dev":      {append(append([]string{"init"}, devArgs...), poolerArgs(n, "db")...), "--pooler-tls-cert"},
		} {
			code, _, errs := n.run("", c.args...)
			if code != 2 || !strings.Contains(errs, c.word) {
				t.Errorf("%s: exit %d, stderr %q; want 2 naming %s", name, code, errs, c.word)
			}
			absent(t, n.p.NodeJSON())
		}
		// Control on the same path: the label with its pair.
		if code, _, errs := n.run("", append(baseArgs(n, "sp.test"), poolerArgs(n, "db")...)...); code != 0 {
			t.Fatalf("control: exit %d, %s", code, errs)
		}
		n.wantMode("etc/supapace/tls-pooler", fs.ModeDir|0o700)
		n.wantMode("etc/supapace/tls-pooler/cert.pem", 0o600)
		n.wantMode("etc/supapace/tls-pooler/key.pem", 0o600)
		if !bytes.Equal(n.read("etc/supapace/tls-pooler/cert.pem"), n.read("in/pooler-cert.pem")) ||
			!bytes.Equal(n.read("etc/supapace/tls-pooler/key.pem"), n.read("in/pooler-key.pem")) {
			t.Error("the pair is not the one given")
		}
		if c := nodeFile(t, n); c.PoolerLabel != "db" {
			t.Errorf("pooler_label %q", c.PoolerLabel)
		}
		// Later runs keep the stored pair without the pair's flags.
		before := snapshot(t, n.root)
		for _, extra := range [][]string{nil, {"--pooler-label", "db"}} {
			if code, out, errs := n.run("", append(baseArgs(n, "sp.test"), extra...)...); code != 0 || !strings.Contains(out, "nothing to change") {
				t.Errorf("rerun %v: exit %d, %q %q", extra, code, out, errs)
			}
		}
		unchanged(t, n, before)
	})
	t.Run("a node file naming a label with no stored pair", func(t *testing.T) {
		n := operatorNode(t, "sp.test")
		editNode(t, n, func(c *nodecfg.Config) { c.PoolerLabel = "db" })
		before := snapshot(t, n.root)
		code, _, errs := n.run("", baseArgs(n, "sp.test")...)
		if code != 1 || !strings.Contains(errs, "pooler") || !strings.Contains(errs, "--pooler-tls-cert") {
			t.Fatalf("exit %d, stderr %q", code, errs)
		}
		unchanged(t, n, before)
	})
}

func TestInit_PoolerPairMustNameTheZoneWildcardAlone(t *testing.T) {
	day := 24 * time.Hour
	nowT := time.Now()
	for name, write := range map[string]func(t *testing.T, n *node){
		"also the base domain's wildcard": func(t *testing.T, n *node) { validPair(t, n, "pooler-", "*.db.sp.test", "*.sp.test") },
		"also the zone itself":            func(t *testing.T, n *node) { validPair(t, n, "pooler-", "*.db.sp.test", "db.sp.test") },
		"another zone":                    func(t *testing.T, n *node) { validPair(t, n, "pooler-", "*.other.sp.test") },
		"the base domain's wildcard only": func(t *testing.T, n *node) { validPair(t, n, "pooler-", "*.sp.test") },
		"expired": func(t *testing.T, n *node) {
			pairFiles(t, n, "pooler-", nowT.Add(-90*day), nowT.Add(-day), nil, "*.db.sp.test")
		},
		"not yet valid": func(t *testing.T, n *node) {
			pairFiles(t, n, "pooler-", nowT.Add(day), nowT.Add(90*day), nil, "*.db.sp.test")
		},
		"client authentication only": func(t *testing.T, n *node) {
			pairFiles(t, n, "pooler-", nowT.Add(-day), nowT.Add(90*day), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "*.db.sp.test")
		},
		"key of another certificate": func(t *testing.T, n *node) {
			validPair(t, n, "pooler-", "*.db.sp.test")
			key := n.read("in/pooler-key.pem")
			validPair(t, n, "pooler-", "*.db.sp.test")
			n.write("in/pooler-key.pem", string(key), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := operatorNode(t, "sp.test")
			write(t, n)
			before := snapshot(t, n.root)
			code, _, errs := n.run("", append(baseArgs(n, "sp.test"), poolerArgs(n, "db")...)...)
			if code != 1 || !strings.Contains(errs, "--pooler-tls") {
				t.Fatalf("exit %d, stderr %q; want 1 naming the pair", code, errs)
			}
			unchanged(t, n, before)
		})
	}
	t.Run("an address besides the wildcard", func(t *testing.T) {
		n := operatorNode(t, "sp.test")
		validPair(t, n, "pooler-", "*.db.sp.test")
		// pairFiles has no address argument: replace the pair with one that carries an IP name too.
		ipPair(t, n, "*.db.sp.test", net.ParseIP("192.0.2.1"))
		before := snapshot(t, n.root)
		if code, _, errs := n.run("", append(baseArgs(n, "sp.test"), poolerArgs(n, "db")...)...); code != 1 || !strings.Contains(errs, "nothing else") {
			t.Fatalf("exit %d, stderr %q", code, errs)
		}
		unchanged(t, n, before)
	})
	// Control on the same path: the zone's wildcard alone.
	n := operatorNode(t, "sp.test")
	validPair(t, n, "pooler-", "*.db.sp.test")
	if code, _, errs := n.run("", append(baseArgs(n, "sp.test"), poolerArgs(n, "db")...)...); code != 0 {
		t.Fatalf("control: exit %d, %s", code, errs)
	}
}

func TestInit_DevIssuesTheZonePairFromTheNodeCA(t *testing.T) {
	n := newNode(t)
	n.mustInit(append(devArgs, "--pooler-label", "db")...)
	ca := devCA(t, n)
	if !reflect.DeepEqual(ca.PermittedDNSDomains, []string{"sp.test"}) {
		t.Errorf("CA constraint %v, want the base domain alone: the zone lies under it", ca.PermittedDNSDomains)
	}
	n.wantMode("etc/supapace/tls-pooler", fs.ModeDir|0o700)
	n.wantMode("etc/supapace/tls-pooler/cert.pem", 0o600)
	n.wantMode("etc/supapace/tls-pooler/key.pem", 0o600)
	l := leaf(t, n, "etc/supapace/tls-pooler")
	if !reflect.DeepEqual(l.DNSNames, []string{"*.db.sp.test"}) || len(l.IPAddresses) != 0 || l.IsCA {
		t.Errorf("pooler certificate names %v %v, CA %v; want *.db.sp.test alone", l.DNSNames, l.IPAddresses, l.IsCA)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := l.Verify(x509.VerifyOptions{Roots: roots, DNSName: "abcdefghij0123456789.db.sp.test"}); err != nil {
		t.Errorf("pooler certificate for a project's pooler host: %v", err)
	}
	for _, host := range []string{"abcdefghij0123456789.sp.test", "db.sp.test", "a.b.db.sp.test"} {
		if _, err := l.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err == nil {
			t.Errorf("pooler certificate verifies for %s", host)
		}
	}
	if c := nodeFile(t, n); c.PoolerLabel != "db" {
		t.Errorf("pooler_label %q", c.PoolerLabel)
	}
	// Reissued from the same CA when it is gone; the base pair stays.
	basePEM, caPEM := n.read("etc/supapace/tls/cert.pem"), n.read("etc/supapace/ca/ca.pem")
	os.Remove(n.path("etc/supapace/tls-pooler/cert.pem"))
	n.mustInit(devArgs...)
	if !bytes.Equal(basePEM, n.read("etc/supapace/tls/cert.pem")) || !bytes.Equal(caPEM, n.read("etc/supapace/ca/ca.pem")) {
		t.Error("the base pair or the CA changed")
	}
	if _, err := leaf(t, n, "etc/supapace/tls-pooler").Verify(x509.VerifyOptions{Roots: roots, DNSName: "abcdefghij0123456789.db.sp.test"}); err != nil {
		t.Errorf("reissued pooler pair: %v", err)
	}
	// Without a label nothing of the pooler is written.
	m := newNode(t)
	m.mustInit(devArgs...)
	absent(t, m.path("etc/supapace/tls-pooler"))
	if b := m.read("etc/supapace/node.json"); bytes.Contains(b, []byte("pooler")) {
		t.Errorf("node.json names a pooler: %s", b)
	}
}

func TestInit_LabelCannotChange(t *testing.T) {
	n := newNode(t)
	n.mustInit(append(devArgs, "--pooler-label", "db")...)
	before := snapshot(t, n.root)
	code, _, errs := n.run("", append(append([]string{"init"}, devArgs...), "--pooler-label", "pool")...)
	if code != 1 || !strings.Contains(errs, `"db"`) {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	unchanged(t, n, before)
	// Without the flag the label stays.
	if out := n.mustInit(devArgs...); !strings.Contains(out, "nothing to change") {
		t.Errorf("rerun: %q", out)
	}
	unchanged(t, n, before)
}

func TestInit_LabelGivenToANodeThatHadNone(t *testing.T) {
	t.Run("development node", func(t *testing.T) {
		n := newNode(t)
		n.mustInit(devArgs...)
		old := nodeFile(t, n)
		before := snapshot(t, n.root)
		n.mustInit(append(devArgs, "--pooler-label", "db")...)
		onlyNodeFileChanged(t, n, before)
		old.PoolerLabel = "db"
		if got := nodeFile(t, n); !reflect.DeepEqual(got, old) {
			t.Errorf("node.json %+v\nwant the old one with the label %+v", got, old)
		}
		leaf(t, n, "etc/supapace/tls-pooler")
		// A third run with another label is refused.
		before = snapshot(t, n.root)
		if code, _, errs := n.run("", append(append([]string{"init"}, devArgs...), "--pooler-label", "pool")...); code != 1 {
			t.Fatalf("third run: exit %d, %s", code, errs)
		}
		unchanged(t, n, before)
	})
	t.Run("operator node", func(t *testing.T) {
		n := operatorNode(t, "sp.test")
		old := nodeFile(t, n)
		validPair(t, n, "pooler-", "*.db.sp.test")
		before := snapshot(t, n.root)
		if code, _, errs := n.run("", append(baseArgs(n, "sp.test"), poolerArgs(n, "db")...)...); code != 0 {
			t.Fatalf("exit %d, %s", code, errs)
		}
		onlyNodeFileChanged(t, n, before)
		old.PoolerLabel = "db"
		if got := nodeFile(t, n); !reflect.DeepEqual(got, old) {
			t.Errorf("node.json %+v\nwant %+v", got, old)
		}
		if !bytes.Equal(n.read("etc/supapace/tls-pooler/cert.pem"), n.read("in/pooler-cert.pem")) {
			t.Error("pair not installed")
		}
	})
}

func TestInit_RefusesALabelWhoseHostNamePasses253(t *testing.T) {
	domain := strings.Repeat("d", 60) + "." + strings.Repeat("e", 60) + "." + strings.Repeat("f", 60) + ".test" // 188 characters
	room := 253 - len("abcdefghij0123456789..") - len(domain)
	args := func(label string) []string {
		return []string{"--domain", domain, "--dev", "--no-systemd", "--ack-escrow", "--pooler-label", label}
	}
	n := newNode(t)
	code, _, errs := n.run("", append([]string{"init"}, args(strings.Repeat("a", room+1))...)...)
	if code != 1 || !strings.Contains(errs, "253") {
		t.Fatalf("254 characters: exit %d, stderr %q", code, errs)
	}
	absent(t, n.p.NodeJSON())
	absent(t, n.p.KEK())
	absent(t, n.path("etc/supapace/tls-pooler"))
	m := newNode(t)
	m.mustInit(args(strings.Repeat("a", room))...)
	if c := nodeFile(t, m); len("abcdefghij0123456789."+c.PoolerLabel+"."+c.Domain) != 253 {
		t.Errorf("control: label %q", c.PoolerLabel)
	}
}

func TestInit_PublicAddrs(t *testing.T) {
	addr := func(a ...string) []string {
		var out []string
		for _, s := range a {
			out = append(out, "--public-addr", s)
		}
		return out
	}
	for name, a := range map[string][]string{
		"inside the platform subnet": {"192.0.2.10", "10.212.0.40"},
		"multicast":                  {"233.252.0.1"},
		"IPv6":                       {"2001:db8::10"},
		"a repeat":                   {"192.0.2.10", "192.0.2.10"},
		"not an address":             {"node.example.test"},
	} {
		n := newNode(t)
		code, _, errs := n.run("", append(append([]string{"init"}, devArgs...), addr(a...)...)...)
		if code != 1 || !strings.Contains(errs, "public") {
			t.Errorf("%s: exit %d, stderr %q", name, code, errs)
		}
		absent(t, n.p.NodeJSON())
		absent(t, n.p.KEK())
	}
	n := newNode(t)
	n.mustInit(append(devArgs, addr("192.0.2.10", "198.51.100.20")...)...)
	if c := nodeFile(t, n); !slices.Equal(c.PublicAddrs, []string{"192.0.2.10", "198.51.100.20"}) {
		t.Errorf("public_addrs %v", c.PublicAddrs)
	}
	// Without the flag the member stays.
	before := snapshot(t, n.root)
	if out := n.mustInit(devArgs...); !strings.Contains(out, "nothing to change") {
		t.Errorf("rerun: %q", out)
	}
	unchanged(t, n, before)
	// A run that adds one and removes another changes that member alone.
	old := nodeFile(t, n)
	n.mustInit(append(devArgs, addr("192.0.2.10", "203.0.113.30")...)...)
	onlyNodeFileChanged(t, n, before)
	old.PublicAddrs = []string{"192.0.2.10", "203.0.113.30"}
	if got := nodeFile(t, n); !reflect.DeepEqual(got, old) {
		t.Errorf("node.json %+v\nwant %+v", got, old)
	}
	// A refused change leaves it as it was.
	before = snapshot(t, n.root)
	if code, _, _ := n.run("", append(append([]string{"init"}, devArgs...), addr("10.213.0.2")...)...); code != 1 {
		t.Errorf("an address inside the project block: exit %d", code)
	}
	unchanged(t, n, before)
	// The help names both kinds of address.
	_, _, help := n.run("", "init", "-h")
	for _, s := range []string{"every address the node's names resolve to", "every source address the provider gives the node's outbound traffic", "declares none"} {
		if !strings.Contains(strings.Join(strings.Fields(help), " "), s) {
			t.Errorf("help does not say %q:\n%s", s, help)
		}
	}
	// A node file without the member writes none.
	m := newNode(t)
	m.mustInit(devArgs...)
	if b := m.read("etc/supapace/node.json"); bytes.Contains(b, []byte("public_addrs")) {
		t.Errorf("node.json names public_addrs: %s", b)
	}
}

func TestInit_RefusesAUidRangeOverThePoolersUids(t *testing.T) {
	for name, c := range map[string]struct {
		edit func(*nodecfg.Config)
		word string
	}{
		"the pooler's uids": {func(c *nodecfg.Config) { c.UIDBase, c.UIDCount = 65536-1024, 1024 }, "pooler uid 65526"},
		"a pooler address":  {func(c *nodecfg.Config) { c.GatewayIP = "10.212.0.8" }, "is a pooler address"},
	} {
		t.Run(name, func(t *testing.T) {
			n := newNode(t)
			n.mustInit(devArgs...)
			// No host id near the pooler's uids: the range itself is what is refused.
			n.write("etc/passwd", "root:x:0:0:root:/root:/bin/sh\n", 0o644)
			n.write("etc/group", "root:x:0:\n", 0o644)
			editNode(t, n, c.edit)
			before := snapshot(t, n.root)
			code, _, errs := n.run("", append(append([]string{"init"}, devArgs...), "--pooler-label", "db")...)
			if code != 1 || !strings.Contains(errs, c.word) {
				t.Fatalf("exit %d, stderr %q; want 1 naming %q", code, errs, c.word)
			}
			unchanged(t, n, before)
			// Control on the same path: the same node without a label is not refused for it.
			if _, _, errs := n.run("", append([]string{"init"}, devArgs...)...); strings.Contains(errs, "pooler") {
				t.Errorf("without a label: %q", errs)
			}
		})
	}
}

func TestInit_OffsiteWindowOnlyWithDev(t *testing.T) {
	for _, member := range []string{"offsite_window_s", "rekey_settle_s"} {
		t.Run(member, func(t *testing.T) {
			set := func(c *nodecfg.Config) {
				if member == "offsite_window_s" {
					c.OffsiteWindowS = 60
				} else {
					c.RekeySettleS = 5
				}
			}
			n := operatorNode(t, "sp.test")
			editNode(t, n, set)
			before := snapshot(t, n.root)
			code, _, errs := n.run("", baseArgs(n, "sp.test")...)
			if code != 1 || !strings.Contains(errs, member) || !strings.Contains(errs, "--dev") {
				t.Fatalf("exit %d, stderr %q", code, errs)
			}
			unchanged(t, n, before)
			// Control on the same path: a development node keeps it.
			m := newNode(t)
			m.mustInit(devArgs...)
			editNode(t, m, set)
			b, _ := json.Marshal(nodeFile(t, m))
			if out := m.mustInit(devArgs...); !strings.Contains(out, "nothing to change") || !bytes.Contains(b, []byte(member)) {
				t.Errorf("development node: %q", out)
			}
		})
	}
}

func TestInstallScript_WritesTheModuleListAndLoadsNothing(t *testing.T) {
	script := installScript(t)
	b, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	// No line runs modprobe: each that names it is a comment, the modprobe.d
	// path, or the printed command.
	for i, l := range strings.Split(string(b), "\n") {
		s := strings.TrimSpace(l)
		if !strings.Contains(s, "modprobe") || strings.HasPrefix(s, "#") || strings.Contains(s, "modprobe.d/") {
			continue
		}
		if !strings.HasPrefix(s, "log ") {
			t.Errorf("line %d runs modprobe: %s", i+1, s)
		}
	}
	root, calls, env := installEnv(t, goodMount)
	// A modprobe on PATH would record its call; the script must never make one.
	// The stand-ins' directory is the first of the script's PATH, as installEnv sets it.
	var fake string
	for _, kv := range env {
		if p, ok := strings.CutPrefix(kv, "PATH="); ok {
			fake, _, _ = strings.Cut(p, ":")
		}
	}
	if fake == "" {
		t.Fatal("installEnv set no PATH")
	}
	if err := os.WriteFile(filepath.Join(fake, "modprobe"), []byte("#!/bin/sh\necho \"modprobe $*\" >>"+calls+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, out := runInstall(t, script, env, "--domain", "sp.test", "--dev", "--pooler-label", "db", "--public-addr", "192.0.2.10")
	if code != 0 {
		t.Fatalf("install: exit %d\n%s", code, out)
	}
	p := filepath.Join(root, "etc/modules-load.d/supapace.conf")
	if got, _ := os.ReadFile(p); string(got) != "nf_conntrack_bridge\nnft_connlimit\n" {
		t.Errorf("module list %q", got)
	}
	if fi, err := os.Lstat(p); err != nil || fi.Mode() != 0o644 {
		t.Errorf("module list: %v %v", fi, err)
	}
	if !strings.Contains(out, "modprobe -a nf_conntrack_bridge nft_connlimit") {
		t.Errorf("the command is not printed:\n%s", out)
	}
	got, _ := os.ReadFile(calls)
	if strings.Contains(string(got), "modprobe") {
		t.Errorf("modprobe was run:\n%s", got)
	}
	if !strings.Contains(string(got), "supapaced init --domain sp.test --dev --pooler-label db --public-addr 192.0.2.10\n") {
		t.Errorf("the flags are not passed to init:\n%s", got)
	}
	// With both modules present nothing is printed, and a rerun writes nothing.
	for _, m := range []string{"nf_conntrack_bridge", "nft_connlimit"} {
		os.MkdirAll(filepath.Join(root, "sys/module", m), 0o755)
	}
	code, out = runInstall(t, script, env)
	if code != 0 || strings.Contains(out, "modprobe -a") || strings.Contains(out, "wrote") {
		t.Errorf("rerun: exit %d\n%s", code, out)
	}
	// One absent module: the command is printed again.
	os.Remove(filepath.Join(root, "sys/module/nft_connlimit"))
	if _, out = runInstall(t, script, env); !strings.Contains(out, "modprobe -a nf_conntrack_bridge nft_connlimit") {
		t.Errorf("one module absent, no command printed:\n%s", out)
	}
}

// ipPair writes a currently valid pair in in/pooler-* for name and ip.
func ipPair(t *testing.T, n *node, name string, ip net.IP) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name}, IPAddresses: []net.IP{ip},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	p8, _ := x509.MarshalPKCS8PrivateKey(k)
	n.write("in/pooler-cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
	n.write("in/pooler-key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8})), 0o600)
}

// A development CA removed by itself: the next init issues a new one and,
// with it, every pair again — none in place is the new CA's.
func TestInit_DevEveryPairFollowsANewCA(t *testing.T) {
	n := newNode(t)
	n.mustInit(append(devArgs, "--studio-domain", "studio.test", "--pooler-label", "db")...)
	if err := os.RemoveAll(n.p.CADir()); err != nil {
		t.Fatal(err)
	}
	n.mustInit(devArgs...)
	roots := x509.NewCertPool()
	roots.AddCert(devCA(t, n))
	for dir, host := range map[string]string{
		"etc/supapace/tls":        "abcdefghij0123456789.sp.test",
		"etc/supapace/tls-studio": "sign-in.studio.test",
		"etc/supapace/tls-pooler": "abcdefghij0123456789.db.sp.test",
	} {
		if _, err := leaf(t, n, dir).Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Errorf("%s under the new CA: %v", dir, err)
		}
	}
}

// With both development members in an operator's node file, the refusal names
// the same one every time.
func TestInit_DevelopmentMembersRefusedInAFixedOrder(t *testing.T) {
	n := operatorNode(t, "sp.test")
	editNode(t, n, func(c *nodecfg.Config) { c.OffsiteWindowS, c.RekeySettleS = 60, 5 })
	for range 20 {
		if code, _, errs := n.run("", baseArgs(n, "sp.test")...); code != 1 || !strings.Contains(errs, "offsite_window_s") || strings.Contains(errs, "rekey_settle_s") {
			t.Fatalf("exit %d, stderr %q", code, errs)
		}
	}
}

// The help says how a node returns to declaring no address, and so does the
// installation document.
func TestInit_PublicAddrHelpSaysHowToDeclareNone(t *testing.T) {
	n := newNode(t)
	_, _, help := n.run("", "init", "-h")
	doc, err := os.ReadFile("../../docs/node-install.md")
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"help": help, "docs/node-install.md": string(doc)} {
		if !strings.Contains(strings.Join(strings.Fields(text), " "), "To return to declaring none, remove public_addrs from the node file") &&
			!strings.Contains(strings.Join(strings.Fields(text), " "), "To return to declaring none, remove `public_addrs` from the node file") {
			t.Errorf("%s does not say how to return to declaring none", name)
		}
	}
}
