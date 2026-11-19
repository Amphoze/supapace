package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/routes"
)

const (
	tRef    = "aaaaaaaaaaaaaaaaaaa1"
	tStudio = "studio.test"
)

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writePair writes a certificate for names and its key as dir/cert.pem and
// dir/key.pem.
func writePair(t *testing.T, dir string, names ...string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

// gatewayDir lays out a gateway directory with every file in order: the first
// pair, a route table of one project, and the dashboard's files.
func gatewayDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writePair(t, filepath.Join(dir, "tls"), "*.sp.test")
	key := func(class string) routes.Key {
		priv, kid, err := jwtx.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		return routes.Key{KID: kid, Class: class, Kty: "RSA", N: base64.RawURLEncoding.EncodeToString(priv.N.Bytes()), E: "AQAB"}
	}
	rb, err := routes.File{Generation: 1, Domain: "sp.test", Projects: map[string]routes.Project{tRef: {
		State: "active", Rest: "http://10.212.0.16:3000", UserRoles: []string{"authenticated"},
		Keys: []routes.Key{key("anon"), key("service_role")}}}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "routes.json"), rb)
	writeFile(t, filepath.Join(dir, "dash", "domain"), []byte(tStudio+"\n"))
	pk, _, err := dashtok.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "dash", "assert.key"), pk)
	writePair(t, filepath.Join(dir, "tls-studio"), tStudio, "*."+tStudio)
	db, err := dashfile.File{Generation: 1, Node: "local", StudioDomain: tStudio, Studio: "http://10.212.0.3:3000",
		Projects: map[string]dashfile.Project{tRef: {Name: "A"}}}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "dashboard.json"), db)
	return dir
}

func serve(h http.Handler, method, host, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestStudioPairBroken_ProjectAPIServed: a studio pair or an assertion key
// that does not load leaves the gateway serving the project API as built,
// with no studio class and the health answer saying so; the first pair still
// stops the process.
func TestStudioPairBroken_ProjectAPIServed(t *testing.T) {
	breaks := map[string]func(t *testing.T, dir string){
		"unreadable studio key": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "tls-studio", "key.pem")
			os.Remove(p)
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"key of another certificate": func(t *testing.T, dir string) {
			other := t.TempDir()
			writePair(t, other, tStudio, "*."+tStudio)
			b, _ := os.ReadFile(filepath.Join(other, "key.pem"))
			writeFile(t, filepath.Join(dir, "tls-studio", "key.pem"), b)
		},
		"certificate for another name": func(t *testing.T, dir string) {
			writePair(t, filepath.Join(dir, "tls-studio"), "other.test", "*.other.test")
		},
		"certificate without the wildcard": func(t *testing.T, dir string) {
			writePair(t, filepath.Join(dir, "tls-studio"), tStudio)
		},
		"certificate without the domain": func(t *testing.T, dir string) {
			writePair(t, filepath.Join(dir, "tls-studio"), "*."+tStudio)
		},
		"unparsable assertion key": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "dash", "assert.key"), []byte("not a key\n"))
		},
		"missing assertion key": func(t *testing.T, dir string) {
			os.Remove(filepath.Join(dir, "dash", "assert.key"))
		},
		"domain file not a domain": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "dash", "domain"), []byte("Studio.Test\n"))
		},
		"single-label domain, with a pair naming it": func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "dash", "domain"), []byte("studio\n"))
			writePair(t, filepath.Join(dir, "tls-studio"), "studio", "*.studio")
		},
	}
	for name, brk := range breaks {
		t.Run(name, func(t *testing.T) {
			dir := gatewayDir(t)
			brk(t, dir)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g, _, err := start(ctx, dir)
			if err != nil {
				t.Fatalf("the gateway did not start: %v", err)
			}
			if w := serve(g, "GET", tRef+".sp.test", "/rest/v1/x"); w.Code != 401 || !strings.Contains(w.Body.String(), "no_apikey") {
				t.Errorf("project API: %d %s", w.Code, w.Body)
			}
			for _, host := range []string{tRef + "." + tStudio, tStudio} {
				w := serve(g, "GET", host, "/api/x")
				if w.Code != 404 || !strings.Contains(w.Body.String(), "not_found") || w.Header().Get("Content-Security-Policy") != "sandbox" {
					t.Errorf("%s is not an unknown host: %d %s %v", host, w.Code, w.Body, w.Header())
				}
			}
			h := serve(g, "GET", tRef+".sp.test", "/-/health")
			if h.Code != 200 || h.Header().Get("X-Supapace-Dashboard") != "unavailable" || h.Body.String() != `{"generation":1}` {
				t.Errorf("health: %d %s %v", h.Code, h.Body, h.Header())
			}
			if c, _ := g.Certificate(&tls.ClientHelloInfo{ServerName: tStudio}); c != nil {
				t.Error("a studio certificate is handed out")
			}
		})
	}

	t.Run("control", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g, _, err := start(ctx, gatewayDir(t))
		if err != nil {
			t.Fatal(err)
		}
		if h := serve(g, "GET", tStudio, "/-/health"); h.Header().Get("X-Supapace-Dashboard") != "ok" {
			t.Errorf("health: %v", h.Header())
		}
		if w := serve(g, "GET", tRef+"."+tStudio, "/api/x"); w.Code != 401 || !strings.Contains(w.Body.String(), "login_required") {
			t.Errorf("dashboard host not classified: %d %s", w.Code, w.Body)
		}
		if c, _ := g.Certificate(&tls.ClientHelloInfo{ServerName: tStudio}); c == nil {
			t.Error("no studio certificate")
		}
	})

	t.Run("first pair unreadable", func(t *testing.T) {
		dir := gatewayDir(t)
		os.Remove(filepath.Join(dir, "tls", "key.pem"))
		if _, _, err := start(context.Background(), dir); err == nil {
			t.Error("started without the first pair (main exits 1 on this error)")
		}
	})
}
