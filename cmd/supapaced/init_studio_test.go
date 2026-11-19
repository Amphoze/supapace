package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// signedPair writes in/studio-cert.pem (the leaf for names, signed by a fresh
// issuer, then the issuer) and in/studio-key.pem with a key of kind.
func signedPair(t *testing.T, n *node, kind string, names ...string) {
	t.Helper()
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	it := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ider, err := x509.CreateCertificate(rand.Reader, it, it, ik.Public(), ik)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(ider)
	var k crypto.Signer
	switch kind {
	case "rsa":
		k, _ = rsa.GenerateKey(rand.Reader, 2048)
	case "ed25519":
		_, k, _ = ed25519.GenerateKey(rand.Reader)
	default:
		k, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	lt := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: names, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	lder, err := x509.CreateCertificate(rand.Reader, lt, issuer, k.Public(), ik)
	if err != nil {
		t.Fatal(err)
	}
	p8, _ := x509.MarshalPKCS8PrivateKey(k)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: lder})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ider})...)
	n.write("in/studio-cert.pem", string(chain), 0o644)
	n.write("in/studio-key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8})), 0o600)
}

// studioRun runs init without --dev for sp.test with the studio domain and
// the pair in in/studio-*.
func studioRun(t *testing.T, n *node, studio string) (int, string) {
	t.Helper()
	code, _, errs := n.run("", append(baseArgs(n, "sp.test"), studioArgs(n, studio)...)...)
	return code, errs
}

// The pair is kept as given, the issuer behind the leaf included, for each key
// type the base pair accepts.
func TestInit_StudioPair_ChainKeptAndKeyTypes(t *testing.T) {
	for _, kind := range []string{"ecdsa", "rsa", "ed25519"} {
		t.Run(kind, func(t *testing.T) {
			n := newNode(t)
			validPair(t, n, "", "*.sp.test")
			signedPair(t, n, kind, "studio.test", "*.studio.test")
			if code, errs := studioRun(t, n, "studio.test"); code != 0 {
				t.Fatalf("exit %d, %s", code, errs)
			}
			if got := strings.Count(string(n.read("etc/supapace/tls-studio/cert.pem")), "BEGIN CERTIFICATE"); got != 2 {
				t.Errorf("stored chain holds %d certificates, want 2", got)
			}
		})
	}
	// The issuer first and the leaf second: the key matches no first
	// certificate, so the pair is refused.
	n := newNode(t)
	validPair(t, n, "", "*.sp.test")
	signedPair(t, n, "ecdsa", "studio.test", "*.studio.test")
	blocks := strings.SplitAfter(string(n.read("in/studio-cert.pem")), "-----END CERTIFICATE-----\n")
	n.write("in/studio-cert.pem", blocks[1]+blocks[0], 0o644)
	if code, errs := studioRun(t, n, "studio.test"); code != 1 || !strings.Contains(errs, "--studio-tls-cert/--studio-tls-key") {
		t.Fatalf("issuer first: exit %d, %s", code, errs)
	}
}

// What init accepts, the gateway loads: its loader requires the leaf to name
// the studio domain and its wildcard, literally. A certificate that covers the
// three hosts some other way is refused here, not at the gateway's start.
func TestInit_StudioPair_NamesTheDomainAndItsWildcard(t *testing.T) {
	for name, names := range map[string][]string{
		"a parent wildcard for the domain": {"*.example.test", "*.studio.example.test"},
		"the hosts without the wildcard": {"studio.example.test", "sign-in.studio.example.test",
			strings.Repeat("a", 20) + ".studio.example.test"},
	} {
		t.Run(name, func(t *testing.T) {
			n := newNode(t)
			validPair(t, n, "", "*.sp.test")
			validPair(t, n, "studio-", names...)
			if code, errs := studioRun(t, n, "studio.example.test"); code != 1 {
				t.Fatalf("exit %d, stderr %q; want 1", code, errs)
			}
			absent(t, n.path("etc/supapace/tls-studio"))
		})
	}
}

// A node file that names a studio domain while no studio pair is stored — a
// first run stopped between node.json and the pair, or a hand edit — is not
// accepted by a run without the pair: the dashboard could never load.
func TestInit_StudioDomainWithoutAStoredPair_Refused(t *testing.T) {
	n := operatorNode(t, "sp.test")
	editNode(t, n, func(c *nodecfg.Config) { c.StudioDomain = "studio.test" })
	code, _, errs := n.run("", baseArgs(n, "sp.test")...)
	if code == 0 || !strings.Contains(errs, "--studio-tls-cert") {
		t.Fatalf("exit %d, stderr %q; want a refusal naming --studio-tls-cert", code, errs)
	}
	// The rerun with the pair converges.
	validPair(t, n, "studio-", "studio.test", "*.studio.test")
	if code, errs := studioRun(t, n, "studio.test"); code != 0 {
		t.Fatalf("rerun with the pair: exit %d, %s", code, errs)
	}
}

// The operator's paths may be links, as an ACME client's current files are;
// what is stored is a regular file init wrote. A link to a FIFO is still
// refused without blocking.
func TestInit_StudioPair_OperatorLinksFollowed(t *testing.T) {
	n := newNode(t)
	validPair(t, n, "", "*.sp.test")
	validPair(t, n, "studio-", "studio.test", "*.studio.test")
	for _, f := range []string{"cert", "key"} {
		if err := os.Rename(n.path("in/studio-"+f+".pem"), n.path("in/real-"+f+".pem")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real-"+f+".pem", n.path("in/studio-"+f+".pem")); err != nil {
			t.Fatal(err)
		}
	}
	if code, errs := studioRun(t, n, "studio.test"); code != 0 {
		t.Fatalf("linked pair: exit %d, %s", code, errs)
	}
	n.wantMode("etc/supapace/tls-studio/cert.pem", 0o600)
	n.wantMode("etc/supapace/tls-studio/key.pem", 0o600)

	m := newNode(t)
	validPair(t, m, "", "*.sp.test")
	validPair(t, m, "studio-", "studio.test", "*.studio.test")
	os.Remove(m.path("in/studio-key.pem"))
	if err := syscall.Mkfifo(m.path("in/fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("fifo", m.path("in/studio-key.pem")); err != nil {
		t.Fatal(err)
	}
	if code, errs := studioRun(t, m, "studio.test"); code != 1 || !strings.Contains(errs, "regular file") {
		t.Fatalf("link to a FIFO: exit %d, %s", code, errs)
	}
}

// A development node made without a studio domain gains one, keeping its node
// file, when its CA and server pair are removed: init makes a CA constrained
// to both domains and issues both pairs from it.
func TestInit_Dev_StudioDomainAddedByReplacingTheCA(t *testing.T) {
	n := newNode(t)
	n.mustInit(devArgs...)
	old, err := nodecfg.Load(n.p.NodeJSON())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"etc/supapace/ca", "etc/supapace/tls"} {
		if err := os.RemoveAll(n.path(d)); err != nil {
			t.Fatal(err)
		}
	}
	n.mustInit(append(devArgs, "--studio-domain", "studio.test")...)
	ca := devCA(t, n)
	if !reflect.DeepEqual(ca.PermittedDNSDomains, []string{"sp.test", "studio.test"}) {
		t.Errorf("CA constraint %v", ca.PermittedDNSDomains)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for dir, host := range map[string]string{"etc/supapace/tls": "abcdefghij0123456789.sp.test", "etc/supapace/tls-studio": "sign-in.studio.test"} {
		block, _ := pem.Decode(n.read(dir + "/cert.pem"))
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Errorf("%s: %v", dir, err)
		}
	}
	got, err := nodecfg.Load(n.p.NodeJSON())
	if err != nil {
		t.Fatal(err)
	}
	old.StudioDomain = "studio.test"
	if !reflect.DeepEqual(got, old) {
		t.Errorf("node.json changed beyond the studio domain")
	}
}

// A node file whose studio domain came from an earlier run is held to
// dashcfg.For on every run, with or without the flag.
func TestInit_KeptStudioDomain_StillCheckedByFor(t *testing.T) {
	n := operatorNode(t, "sp.test")
	validPair(t, n, "studio-", "studio.test", "*.studio.test")
	if code, errs := studioRun(t, n, "studio.test"); code != 0 {
		t.Fatalf("exit %d, %s", code, errs)
	}
	editNode(t, n, func(c *nodecfg.Config) { c.GatewayIP = "10.212.0.3" })
	before := snapshot(t, n.root)
	code, _, errs := n.run("", "init", "--domain", "sp.test", "--no-systemd", "--ack-escrow")
	if code != 1 || !strings.Contains(errs, "is a dashboard address") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	unchanged(t, n, before)
}
