package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// A development node that has a pooler label is given a studio domain later:
// init says to remove the CA and the base pair and to run again, and issues a
// new CA. The pooler pair must then be one the new CA vouches for — the
// node's clients trust that CA alone.
func TestInit_DevPoolerPairFollowsANewCA(t *testing.T) {
	n := newNode(t)
	n.mustInit(append(devArgs, "--pooler-label", "db")...)
	code, _, errs := n.run("", append(append([]string{"init"}, devArgs...), "--studio-domain", "studio.test")...)
	if code != 1 || !strings.Contains(errs, "re-initialise") {
		t.Fatalf("adding a studio domain under the first CA: exit %d, %q", code, errs)
	}
	// What the message tells the operator to remove.
	for _, d := range []string{n.p.CADir(), n.p.TLSDir()} {
		if !strings.Contains(errs, d) {
			t.Fatalf("the message does not name %s: %q", d, errs)
		}
		if err := os.RemoveAll(d); err != nil {
			t.Fatal(err)
		}
	}
	n.mustInit(append(devArgs, "--studio-domain", "studio.test")...)
	roots := x509.NewCertPool()
	roots.AddCert(devCA(t, n))
	for dir, host := range map[string]string{
		"etc/supapace/tls":        "abcdefghij0123456789.sp.test",
		"etc/supapace/tls-pooler": "abcdefghij0123456789.db.sp.test",
	} {
		if _, err := leaf(t, n, dir).Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Errorf("%s under the node's CA: %v", dir, err)
		}
	}
}

// A pooler certificate that carries an e-mail or a URI name beside the zone's
// wildcard names something else and is refused, as one with an address is.
func TestInit_PoolerPairWithAnEmailOrURINameIsRefused(t *testing.T) {
	u, _ := url.Parse("spiffe://sp.test/pooler")
	for name, edit := range map[string]func(*x509.Certificate){
		"e-mail": func(c *x509.Certificate) { c.EmailAddresses = []string{"ops" + "@" + "sp.test"} },
		"URI":    func(c *x509.Certificate) { c.URIs = []*url.URL{u} },
	} {
		t.Run(name, func(t *testing.T) {
			n := operatorNode(t, "sp.test")
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"*.db.sp.test"},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
			edit(tmpl)
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
			if err != nil {
				t.Fatal(err)
			}
			p8, _ := x509.MarshalPKCS8PrivateKey(k)
			n.write("in/pooler-cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
			n.write("in/pooler-key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8})), 0o600)
			before := snapshot(t, n.root)
			if code, _, errs := n.run("", append(baseArgs(n, "sp.test"), poolerArgs(n, "db")...)...); code != 1 || !strings.Contains(errs, "nothing else") {
				t.Fatalf("exit %d, stderr %q", code, errs)
			}
			unchanged(t, n, before)
		})
	}
}

// A temporary file an interrupted write left in the pooler pair's directory
// goes at the next run, as in init's other directories.
func TestInit_RemovesLeftoversInThePoolerPairDirectory(t *testing.T) {
	n := newNode(t)
	n.mustInit(append(devArgs, "--pooler-label", "db")...)
	left := "etc/supapace/tls-pooler/.key.pem.tmp-123456"
	n.write(left, "partial", 0o600)
	n.mustInit(devArgs...)
	absent(t, n.path(left))
	leaf(t, n, "etc/supapace/tls-pooler")
}

// An operator's node never gets a development CA or an issued pair: its runs
// leave the supplied pairs byte for byte, and --dev is refused on it before
// anything is written.
func TestInit_OperatorNodeIssuesNoPair(t *testing.T) {
	n := operatorNode(t, "sp.test")
	validPair(t, n, "pooler-", "*.db.sp.test")
	if code, _, errs := n.run("", append(baseArgs(n, "sp.test"), poolerArgs(n, "db")...)...); code != 0 {
		t.Fatalf("exit %d, %s", code, errs)
	}
	before := snapshot(t, n.root)
	for range 2 {
		if code, out, errs := n.run("", baseArgs(n, "sp.test")...); code != 0 || !strings.Contains(out, "nothing to change") {
			t.Fatalf("rerun: exit %d, %q %q", code, out, errs)
		}
	}
	if code, _, _ := n.run("", append([]string{"init"}, devArgs...)...); code != 1 {
		t.Errorf("--dev on an operator's node: exit %d", code)
	}
	unchanged(t, n, before)
	absent(t, n.p.CADir())
}

// A development node whose CA is in place and whose pairs are valid: a run
// issues nothing, whatever the node has of a studio domain and a pooler label.
func TestInit_DevPairsStayUnderTheCAInPlace(t *testing.T) {
	n := newNode(t)
	args := append(slices.Clone(devArgs), "--studio-domain", "studio.test", "--pooler-label", "db")
	n.mustInit(args...)
	before := snapshot(t, n.root)
	for range 2 {
		if out := n.mustInit(args...); !strings.Contains(out, "nothing to change") {
			t.Errorf("rerun: %q", out)
		}
	}
	unchanged(t, n, before)
}
