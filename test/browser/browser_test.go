//go:build browser

// Package browser holds the browser harness's own proofs: Chromium, Firefox
// and WebKit trust the node's development CA, treat the listed studio domain
// as a public suffix while keeping __Host- cookies one label below it, and
// complete the dashboard's sign-in and log-out on the model of the flow
// (sp-dashstub flow). They need neither the daemon nor a project: run as root
// in a node started bare with supapace-browsers:local loaded, after
// go test -c -tags browser -o bin/browser.test ./test/browser. The model
// listens on the node's loopback port 443; the browser container shares the
// node's network namespace with every capability dropped.
package browser

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	image = "supapace-browsers:local"
	// The second configuration's studio domain: an entry of the Public Suffix
	// List's private section, absent from the HSTS preload list.
	listedDomain = "dyndns.org"
	issuerHost   = "issuer.test"
	// A resolver address nothing answers on: only the names mapped into the
	// container's hosts file resolve.
	deadResolver = "127.0.0.9"
	authorize    = "https://" + issuerHost + "/authorize"
)

var (
	engines = []string{"chromium", "firefox", "webkit"}
	configs = []struct{ name, domain string }{{"unlisted", "studio.test"}, {"listed", listedDomain}}
	// The principal's projects: seventeen, so that a log-out from a project
	// origin runs the chain at its cap of sixteen hops; most scenarios use
	// the first three.
	refs = func() []string {
		r := []string{"aaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccc"}
		for i := range 14 {
			r = append(r, fmt.Sprintf("d%019d", i))
		}
		return r
	}()
)

type step map[string]any

type scenario struct {
	Engine  string            `json:"engine"`
	Hosts   map[string]string `json:"hosts"`
	CA      string            `json:"ca,omitempty"`
	Timeout int               `json:"timeout_ms"`
	Script  *bool             `json:"script,omitempty"`
	Steps   []step            `json:"steps"`
	caFile  string            // the CA certificate on the node, mounted at CA
	resolv  string            // a resolver configuration naming no server that answers
}

type request struct {
	Tab                       int
	Method, URL, ResourceType string
	Site, Referer             string
	Cookies                   []string
}

type result struct {
	Engine, Playwright, Error string
	Resolv                    []string
	Steps                     []map[string]any
	Secure                    map[string]bool
	Tabs                      []string
	Trail                     []request
}

// runScenario runs one scenario in a fresh browser container and returns its
// result. A container that does not answer in time is removed.
func runScenario(t *testing.T, sc scenario) result {
	t.Helper()
	name := fmt.Sprintf("sp-test-browser-%s-%d", sc.Engine, time.Now().UnixNano())
	args := []string{"run", "--rm", "-i", "--name", name, "--label", "supapace.test=1", "--network", "host",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/tmp:size=512m", "--memory", "2g"}
	for h, a := range sc.Hosts {
		args = append(args, "--add-host", h+":"+a)
	}
	// Names resolve from the host map alone: the engines' own proxy bypass
	// lists match the subdomains of an entry (Firefox, WebKit), so the
	// studio domain's entry would exempt every name under it; with no
	// resolver such a name still goes nowhere.
	if sc.resolv == "" {
		t.Fatal("scenario without the resolver configuration")
	}
	args = append(args, "-v", sc.resolv+":/etc/resolv.conf:ro")
	if sc.caFile != "" {
		sc.CA = "/ca/ca.pem"
		args = append(args, "-v", sc.caFile+":"+sc.CA+":ro")
	}
	if sc.Timeout == 0 {
		sc.Timeout = 45000 // a loaded machine
	}
	in, _ := json.Marshal(sc)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append(args, image)...)
	cmd.Stdin = strings.NewReader(string(in))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		exec.Command("docker", "rm", "-f", name).Run()
	}
	var r result
	if jerr := json.Unmarshal(out, &r); jerr != nil {
		t.Fatalf("%s: %v: %v; stdout %q; stderr %s", sc.Engine, err, jerr, out, stderr.String())
	}
	if !slices.Equal(r.Resolv, []string{"nameserver " + deadResolver}) {
		t.Fatalf("%s resolved with %q, not the resolver that answers nothing", sc.Engine, r.Resolv)
	}
	t.Logf("%s (playwright %s): error %q, secure %v", r.Engine, r.Playwright, r.Error, r.Secure)
	return r
}

// model is one configuration's node: the CA and the flow model serving its
// hosts on the loopback port 443.
type model struct {
	domain, signIn, caFile, resolv string
	hosts                          map[string]string
	client                         *http.Client
}

func (m model) host(ref string) string { return ref + "." + m.domain }

func (m model) scenario(engine string, trusted bool, steps ...step) scenario {
	sc := scenario{Engine: engine, Hosts: m.hosts, Steps: steps, resolv: m.resolv}
	if trusted {
		sc.caFile = m.caFile
	}
	return sc
}

// count reads and resets the model's request counters: requests to the
// dashboard's hosts, and to the issuer's authorisation endpoint.
func (m model) count(t *testing.T) (int, int) {
	t.Helper()
	resp, err := m.client.Get("https://" + issuerHost + "/-/count")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var c struct{ Dashboard, Issuer int }
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		t.Fatal(err)
	}
	return c.Dashboard, c.Issuer
}

// startModel issues a development CA constrained to the studio domain and the
// issuer host, as a node's is to its names, and a server certificate under it;
// then starts sp-dashstub flow until the test ends.
func startModel(t *testing.T, domain string) model {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("needs root in a node started bare")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ca, caKey := issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "test development CA"}, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{domain, issuerHost},
	}, nil, nil, filepath.Join(dir, "ca.pem"), "")
	issue(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain, "*." + domain, issuerHost}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, caKey, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))

	bin := os.Getenv("SP_DASHSTUB")
	if bin == "" {
		bin = "/opt/supapace/bin/sp-dashstub"
	}
	cmd := exec.Command(bin, "flow", "--listen", "127.0.0.1:443", "--cert", filepath.Join(dir, "cert.pem"),
		"--key", filepath.Join(dir, "key.pem"), "--studio-domain", domain, "--issuer-host", issuerHost,
		"--refs", strings.Join(refs, ","))
	cmd.Stderr = os.Stderr
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || !strings.HasPrefix(line, "listening") {
		t.Fatalf("flow model did not start: %q %v", line, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if err := os.WriteFile(filepath.Join(dir, "resolv.conf"), []byte("nameserver "+deadResolver+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := model{domain: domain, signIn: "sign-in." + domain, caFile: filepath.Join(dir, "ca.pem"), resolv: filepath.Join(dir, "resolv.conf"),
		hosts: map[string]string{domain: "127.0.0.1", "sign-in." + domain: "127.0.0.1", issuerHost: "127.0.0.1"},
		client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:443")
			},
		}}}
	for _, r := range refs {
		m.hosts[m.host(r)] = "127.0.0.1"
	}
	return m
}

func issue(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if parent == nil {
		parent, parentKey = tmpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, k.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if keyPath != "" {
		b, _ := x509.MarshalPKCS8PrivateKey(k)
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

// each runs f for every configuration and engine, one browser at a time.
func each(t *testing.T, f func(t *testing.T, m model, engine string)) {
	for _, c := range configs {
		t.Run(c.name, func(t *testing.T) {
			m := startModel(t, c.domain)
			for _, e := range engines {
				t.Run(e, func(t *testing.T) { f(t, m, e) })
			}
		})
	}
}

func secureStep(tab int) step {
	return step{"op": "eval", "tab": tab, "expr": "window.isSecureContext"}
}

func textStep(tab int) step {
	return step{"op": "eval", "tab": tab, "expr": `document.getElementById("text").textContent`}
}

// mustPass fails unless the scenario ran to its end; every secure-context
// value it saw, evaluated or recorded, is true.
func mustPass(t *testing.T, r result) {
	t.Helper()
	if r.Error != "" {
		for _, q := range r.Trail {
			t.Logf("  tab %d %s %s", q.Tab, q.Method, q.URL)
		}
		t.Fatalf("%s: %s; tabs at %q; steps %v", r.Engine, r.Error, r.Tabs, r.Steps)
	}
	for i, s := range r.Steps {
		if v, ok := s["value"].(bool); ok && !v && s["op"] == "eval" {
			t.Fatalf("step %d: window.isSecureContext is false", i)
		}
	}
	for o, v := range r.Secure {
		if !v {
			t.Fatalf("%s is not a secure context", o)
		}
	}
}

type cookie struct {
	Name, Value, Domain, Path, SameSite string
	HTTPOnly                            bool `json:"httpOnly"`
	Secure                              bool
}

func (c cookie) host() string { return strings.TrimPrefix(c.Domain, ".") }

func cookiesOf(t *testing.T, s map[string]any) []cookie {
	t.Helper()
	b, _ := json.Marshal(s["cookies"])
	var cs []cookie
	if err := json.Unmarshal(b, &cs); err != nil {
		t.Fatal(err)
	}
	return cs
}

func requestsOf(t *testing.T, s map[string]any) []request {
	t.Helper()
	b, _ := json.Marshal(s["requests"])
	var rs []request
	if err := json.Unmarshal(b, &rs); err != nil {
		t.Fatal(err)
	}
	return rs
}

// noCookieOnS: the browser holds no cookie for the studio domain itself, and
// no login cookie anywhere.
func noCookieOnS(t *testing.T, m model, cs []cookie) {
	t.Helper()
	for _, c := range cs {
		if c.host() == m.domain {
			t.Errorf("cookie on the studio domain itself: %+v", c)
		}
		if strings.HasPrefix(c.Name, "__Host-sp-login-") {
			t.Errorf("login cookie left on %s", c.host())
		}
	}
}

// checkSession: the one session cookie of host is host-only, Secure,
// HttpOnly, SameSite=Strict, Path=/.
func checkSession(t *testing.T, cs []cookie, host string) {
	t.Helper()
	n := 0
	for _, c := range cs {
		if c.Name != "__Host-sp-session" || c.host() != host {
			continue
		}
		n++
		if c.Domain != host || !c.Secure || !c.HTTPOnly || c.SameSite != "Strict" || c.Path != "/" {
			t.Errorf("session cookie of %s: %+v", host, c)
		}
	}
	if n != 1 {
		t.Errorf("%d session cookies for %s in %+v", n, host, cs)
	}
}

// logins counts the requests to a login endpoint, by tab.
func logins(rs []request) map[int]int {
	n := map[int]int{}
	for _, q := range rs {
		if u, _ := url.Parse(q.URL); u != nil && u.Path == "/-/auth/login" {
			n[q.Tab]++
		}
	}
	return n
}

// tail appends the steps every scenario ends with: the jar and the requests.
func tail(steps ...step) []step { return append(steps, step{"op": "cookies"}, step{"op": "requests"}) }

func ends(t *testing.T, m model, r result) ([]cookie, []request) {
	t.Helper()
	mustPass(t, r)
	n := len(r.Steps)
	cs, rs := cookiesOf(t, r.Steps[n-2]), requestsOf(t, r.Steps[n-1])
	noCookieOnS(t, m, cs)
	return cs, rs
}

func TestBrowsers_TrustTheNodeCA_SecureContext(t *testing.T) {
	each(t, func(t *testing.T, m model, engine string) {
		pages := []string{"https://" + m.domain + "/none", "https://" + m.signIn + "/-/auth/none",
			"https://" + issuerHost + "/link?to=" + url.QueryEscape("https://"+m.signIn+"/")}
		for _, r := range refs {
			pages = append(pages, "https://"+m.host(r)+"/-/auth/none")
		}
		var steps []step
		for _, p := range pages {
			steps = append(steps, step{"op": "goto", "url": p}, secureStep(0))
		}
		r := runScenario(t, m.scenario(engine, true, tail(steps...)...))
		ends(t, m, r)
		for i := 1; i < 2*len(pages); i += 2 {
			if r.Steps[i]["value"] != true {
				t.Errorf("%s: window.isSecureContext = %v", steps[i-1]["url"], r.Steps[i]["value"])
			}
		}
		// Control: the same first navigation without the CA installed fails.
		r = runScenario(t, m.scenario(engine, false, steps[:2]...))
		if r.Error == "" || len(r.Steps) != 1 || r.Steps[0]["error"] == nil {
			t.Fatalf("without the CA the navigation did not fail: %v", r.Steps)
		}
		t.Logf("without the CA: %v", r.Steps[0]["error"])
	})
}

// The gate's first question: the listed name is a suffix (a cookie with
// Domain= it is refused), and a __Host- cookie is kept one label below it, on
// the sign-in host and on a project host. What the studio domain itself keeps
// is logged, not asserted: nothing asks it to keep anything.
func TestBrowsers_SuffixControl(t *testing.T) {
	each(t, func(t *testing.T, m model, engine string) {
		r := runScenario(t, m.scenario(engine, true, tail(
			step{"op": "goto", "url": "https://" + m.host(refs[0]) + "/-/auth/none"}, secureStep(0),
			step{"op": "setCookie", "name": "sp_suffix", "cookie": "sp_suffix=1; Domain=" + m.domain + "; Path=/; Secure"},
			step{"op": "setCookie", "name": "__Host-sp_project", "cookie": "__Host-sp_project=1; Path=/; Secure"},
			step{"op": "goto", "url": "https://" + m.signIn + "/-/auth/none"}, secureStep(0),
			step{"op": "setCookie", "name": "__Host-sp_signin", "cookie": "__Host-sp_signin=1; Path=/; Secure"},
			step{"op": "goto", "url": "https://" + m.domain + "/none"}, secureStep(0),
			step{"op": "setCookie", "name": "sp_apex", "cookie": "sp_apex=1; Path=/; Secure"},
			step{"op": "clearCookies", "prefix": "sp_apex"},
		)...))
		mustPass(t, r)
		listed := m.domain == listedDomain
		if r.Steps[2]["kept"] != !listed {
			t.Errorf("cookie with Domain=%s kept = %v, want %v", m.domain, r.Steps[2]["kept"], !listed)
		}
		if r.Steps[3]["kept"] != true || r.Steps[6]["kept"] != true {
			t.Errorf("__Host- cookie kept: project host %v, sign-in host %v", r.Steps[3]["kept"], r.Steps[6]["kept"])
		}
		t.Logf("a host-only cookie on %s itself kept: %v", m.domain, r.Steps[9]["kept"])
	})
}

// signIn is one sign-in by navigation to start, ending at page.
func signIn(t *testing.T, m model, engine string, wantDash int, first []step, page string) {
	t.Helper()
	m.count(t)
	steps := append(first, step{"op": "wait", "url": page}, secureStep(0), textStep(0))
	r := runScenario(t, m.scenario(engine, true, tail(steps...)...))
	cs, rs := ends(t, m, r)
	u, _ := url.Parse(page)
	checkSession(t, cs, u.Host)
	if c := logins(rs); c[0] != 1 {
		t.Errorf("login requests %v, want one", c)
	}
	d, i := m.count(t)
	t.Logf("requests: %d to the dashboard's hosts, %d to the issuer", d, i)
	if d != wantDash || i != 1 {
		t.Errorf("requests: %d and %d, want %d and 1", d, i, wantDash)
	}
	if got := r.Steps[len(r.Steps)-3]["value"]; got == nil {
		t.Errorf("no page text")
	} else {
		t.Logf("page: %v", got)
	}
}

func TestBrowsers_FlowModel_SignIn(t *testing.T) {
	each(t, func(t *testing.T, m model, engine string) {
		page := "https://" + m.host(refs[0]) + "/project/x?tab=a"
		picker := "https://" + m.signIn + "/"
		t.Run("cold_start", func(t *testing.T) {
			signIn(t, m, engine, 5, []step{{"op": "goto", "url": page}}, page)
		})
		t.Run("cross_site_link", func(t *testing.T) {
			signIn(t, m, engine, 5, []step{
				{"op": "goto", "url": "https://" + issuerHost + "/link?to=" + url.QueryEscape(page)}, secureStep(0),
				{"op": "click", "selector": "#go"}}, page)
		})
		t.Run("sign_in_host", func(t *testing.T) {
			signIn(t, m, engine, 5, []step{{"op": "goto", "url": picker}}, picker)
		})
		t.Run("from_the_studio_domain", func(t *testing.T) {
			signIn(t, m, engine, 6, []step{{"op": "goto", "url": "https://" + m.domain + "/"}}, picker)
		})
	})
}

func TestBrowsers_FlowModel_ConcurrentAttempts(t *testing.T) {
	each(t, func(t *testing.T, m model, engine string) {
		pageOf := func(i int) string { return fmt.Sprintf("https://%s/p%d", m.host(refs[0]), i) }
		// n tabs at once (pages[i] for tab i): every tab's attempt is held at
		// the issuer before any is released, so the attempts overlap whatever
		// the engine's speed; each then ends on its own page with one login.
		tabs := func(t *testing.T, pages []string) {
			steps := []step{{"op": "goto", "url": "https://" + issuerHost + "/link?to=" + url.QueryEscape(pages[0])},
				{"op": "setCookie", "name": "hold", "cookie": "hold=1; Path=/; Secure"}}
			for range pages[1:] {
				steps = append(steps, step{"op": "newTab"})
			}
			for i, p := range pages {
				steps = append(steps, step{"op": "goto", "tab": i, "url": p}, step{"op": "wait", "tab": i, "contains": authorize})
			}
			steps = append(steps, step{"op": "clearCookies", "prefix": "hold"})
			for i := range pages {
				steps = append(steps, step{"op": "click", "tab": i, "selector": "button"})
			}
			for i, p := range pages {
				steps = append(steps, step{"op": "wait", "tab": i, "url": p}, secureStep(i))
			}
			cs, rs := ends(t, m, runScenario(t, m.scenario(engine, true, tail(steps...)...)))
			c := logins(rs)
			for i, p := range pages {
				u, _ := url.Parse(p)
				checkSession(t, cs, u.Host)
				if c[i] != 1 {
					t.Errorf("tab %d: %d login requests, want 1 (no retry)", i, c[i])
				}
			}
		}
		t.Run("two_tabs", func(t *testing.T) { tabs(t, []string{pageOf(1), pageOf(2)}) })
		t.Run("two_tabs_one_on_the_sign_in_host", func(t *testing.T) { tabs(t, []string{pageOf(1), "https://" + m.signIn + "/"}) })
		t.Run("ten_tabs", func(t *testing.T) {
			var p []string
			for i := range 10 {
				p = append(p, pageOf(i))
			}
			tabs(t, p)
		})
		// Seventeen attempts held open at the issuer: the seventeenth's login
		// clears the sixteen cookies before it; each of the sixteen, released
		// one at a time, ends on its own page after one retry.
		t.Run("seventeen_attempts", func(t *testing.T) {
			steps := []step{{"op": "goto", "url": "https://" + issuerHost + "/link?to=" + url.QueryEscape(pageOf(0))},
				{"op": "setCookie", "name": "hold", "cookie": "hold=1; Path=/; Secure"}}
			for i := range 17 {
				if i > 0 {
					steps = append(steps, step{"op": "newTab"})
				}
				steps = append(steps, step{"op": "goto", "tab": i, "url": pageOf(i)}, step{"op": "wait", "tab": i, "contains": authorize})
			}
			steps = append(steps, step{"op": "cookies"}, step{"op": "clearCookies", "prefix": "hold"})
			for i := range 17 {
				steps = append(steps, step{"op": "click", "tab": i, "selector": "button"}, step{"op": "wait", "tab": i, "url": pageOf(i)}, secureStep(i))
			}
			r := runScenario(t, m.scenario(engine, true, tail(steps...)...))
			cs, rs := ends(t, m, r)
			held := 0
			for _, c := range cookiesOf(t, r.Steps[2+17*2+16]) {
				if strings.HasPrefix(c.Name, "__Host-sp-login-") {
					held++
				}
			}
			if held != 1 {
				t.Errorf("%d login cookies after the seventeenth login, want 1", held)
			}
			checkSession(t, cs, m.host(refs[0]))
			c := logins(rs)
			for i := range 16 {
				if c[i] != 2 {
					t.Errorf("tab %d: %d login requests, want 2 (one retry)", i, c[i])
				}
			}
			if c[16] != 1 {
				t.Errorf("tab 16: %d login requests, want 1", c[16])
			}
		})
	})
}

func TestBrowsers_FlowModel_CookieRefusedOrExpired(t *testing.T) {
	each(t, func(t *testing.T, m model, engine string) {
		host := m.host(refs[0])
		page := "https://" + host + "/one"
		// A browser that keeps no login cookie: one retry, then the final page
		// that names the cookie, 7 and 2 requests, and nothing after it. The
		// harness holds each attempt at the issuer and removes its login
		// cookie there, before anything could send it (an engine routes no
		// redirect hop, and WebKit fulfils no redirect, so the cookie is not
		// stripped from the response itself). The retry's authorisation URL
		// is the one whose state carries n=1 and the path /one (".1.L29uZQ").
		t.Run("no_cookie_kept", func(t *testing.T) {
			m.count(t)
			r := runScenario(t, m.scenario(engine, true, tail(
				step{"op": "goto", "url": "https://" + issuerHost + "/link?to=" + url.QueryEscape(page)},
				step{"op": "setCookie", "name": "hold", "cookie": "hold=1; Path=/; Secure"},
				step{"op": "goto", "url": page}, step{"op": "wait", "contains": authorize},
				step{"op": "clearCookies", "prefix": "__Host-sp-login-"}, step{"op": "click", "selector": "button"},
				step{"op": "wait", "contains": ".1.L29uZQ"},
				step{"op": "clearCookies", "prefix": "__Host-sp-login-"}, step{"op": "click", "selector": "button"},
				step{"op": "wait", "contains": "https://" + host + "/-/auth/session?at=", "text": "did not keep"},
				secureStep(0), textStep(0), step{"op": "requests"}, step{"op": "clearCookies", "prefix": "hold"},
				step{"op": "pause", "ms": 5000})...))
			_, after := ends(t, m, r)
			if txt, _ := r.Steps[11]["value"].(string); !strings.Contains(txt, "did not keep the sign-in cookie") {
				t.Errorf("final page text %q", txt)
			}
			before := requestsOf(t, r.Steps[12])
			if c := logins(before); c[0] != 2 {
				t.Errorf("login requests %v, want 2", c)
			}
			for _, q := range after {
				t.Errorf("a request after the final page: %s %s", q.Method, q.URL)
			}
			d, i := m.count(t)
			t.Logf("requests: %d to the dashboard's hosts, %d to the issuer", d, i)
			if d != 7 || i != 2 {
				t.Errorf("requests %d and %d, want 7 and 2", d, i)
			}
		})
		// The cookie expires while the attempt waits at the issuer: one retry,
		// then the page; 8 and 2 requests.
		t.Run("cookie_expired_at_the_issuer", func(t *testing.T) {
			m.count(t)
			r := runScenario(t, m.scenario(engine, true, tail(
				step{"op": "goto", "url": "https://" + issuerHost + "/link?to=" + url.QueryEscape(page)},
				step{"op": "setCookie", "name": "hold", "cookie": "hold=1; Path=/; Secure"},
				step{"op": "goto", "url": page}, step{"op": "wait", "contains": authorize},
				step{"op": "clearCookies", "prefix": "__Host-sp-login-"}, step{"op": "clearCookies", "prefix": "hold"},
				step{"op": "click", "selector": "button"}, step{"op": "wait", "url": page}, secureStep(0))...))
			cs, rs := ends(t, m, r)
			checkSession(t, cs, host)
			if c := logins(rs); c[0] != 2 {
				t.Errorf("login requests %v, want 2", c)
			}
			d, i := m.count(t)
			t.Logf("requests: %d to the dashboard's hosts, %d to the issuer", d, i)
			if d != 8 || i != 2 {
				t.Errorf("requests %d and %d, want 8 and 2", d, i)
			}
		})
	})
}

func TestBrowsers_FlowModel_LogOut(t *testing.T) {
	each(t, func(t *testing.T, m model, engine string) {
		signedOut := "https://" + m.signIn + "/-/auth/signed-out"
		all := []string{m.signIn, m.host(refs[0]), m.host(refs[1]), m.host(refs[2])}
		signInAll := func() []step {
			var steps []step
			for _, h := range all {
				p := "https://" + h + "/"
				steps = append(steps, step{"op": "goto", "url": p}, step{"op": "wait", "url": p}, secureStep(0))
			}
			return append(steps, step{"op": "cookies"})
		}
		// The log-out starts as a person starts it: from a page of the
		// starting origin (Studio's menu, or the picker), by a same-origin
		// navigation. A navigation the harness types (page.goto) is not
		// same-origin in every engine — WebKit sends no Strict cookie on it
		// once the tab is on another site — and would start without a session.
		// From a project origin the chain visits the sixteen other projects and
		// ends bare; from the sign-in host it has seventeen others, visits the
		// first sixteen and ends with more=1.
		for _, c := range []struct{ start, end string }{{m.host(refs[1]), signedOut}, {m.signIn, signedOut + "?more=1"}} {
			start, end := c.start, c.end
			t.Run("from_"+strings.SplitN(start, ".", 2)[0], func(t *testing.T) {
				p := "https://" + start + "/"
				steps := append(signInAll(), // the jar at 12
					step{"op": "goto", "url": p}, step{"op": "wait", "url": p}, step{"op": "requests"},
					step{"op": "eval", "expr": `location.assign("/-/auth/logout")`},
					step{"op": "wait", "url": end}, secureStep(0), textStep(0), step{"op": "cookies"}, step{"op": "requests"})
				jar := len(steps) - 2
				for _, h := range all {
					steps = append(steps, step{"op": "goto", "url": "https://" + h + "/"}, step{"op": "wait", "url": "https://" + h + "/"})
				}
				r := runScenario(t, m.scenario(engine, true, tail(steps...)...))
				ends(t, m, r)
				for _, h := range all {
					checkSession(t, cookiesOf(t, r.Steps[12]), h)
				}
				for _, q := range requestsOf(t, r.Steps[15]) {
					if q.URL != p {
						continue
					}
					t.Logf("typed navigation back to %s: %s %s (Sec-Fetch-Site %q)", start, q.Method, q.URL, q.Site)
				}
				for _, c := range cookiesOf(t, r.Steps[jar]) {
					if c.Name == "__Host-sp-session" || strings.HasPrefix(c.Name, "__Host-sp-login-") {
						t.Errorf("after log-out the browser still holds %s on %s", c.Name, c.Domain)
					}
				}
				if n := logins(requestsOf(t, r.Steps[len(r.Steps)-1]))[0]; n != len(all) {
					t.Errorf("after log-out %d of %d hosts asked for a login: a session was still sent", n, len(all))
				}
			})
		}
		t.Run("without_a_session", func(t *testing.T) {
			r := runScenario(t, m.scenario(engine, true, tail(
				step{"op": "goto", "url": "https://" + m.host(refs[0]) + "/-/auth/logout"},
				step{"op": "wait", "url": signedOut + "?ended=0"}, secureStep(0), textStep(0))...))
			ends(t, m, r)
			if txt, _ := r.Steps[3]["value"].(string); !strings.HasPrefix(txt, "No dashboard session was shown with this log-out, so none was ended.") {
				t.Errorf("page %v", txt)
			}
		})
		// Reached by a navigation from another site, log-out leaves the
		// session in place: no Strict cookie is sent, so none is cleared.
		t.Run("from_another_site_keeps_the_session", func(t *testing.T) {
			p := "https://" + m.host(refs[0]) + "/"
			r := runScenario(t, m.scenario(engine, true, tail(
				step{"op": "goto", "url": p}, step{"op": "wait", "url": p},
				step{"op": "goto", "url": "https://" + issuerHost + "/link?to=" + url.QueryEscape(p+"-/auth/logout")},
				step{"op": "click", "selector": "#go"}, step{"op": "wait", "url": signedOut + "?ended=0"}, secureStep(0))...))
			cs, _ := ends(t, m, r)
			checkSession(t, cs, m.host(refs[0]))
		})
	})
}

func noScript(sc scenario) scenario {
	off := false
	sc.Script = &off
	return sc
}

// dashRequests counts the requests to the dashboard's hosts and to the
// authorisation endpoint in rs.
func dashRequests(m model, rs []request) (int, int) {
	d, i := 0, 0
	for _, q := range rs {
		u, _ := url.Parse(q.URL)
		switch {
		case u.Host == m.domain || strings.HasSuffix(u.Host, "."+m.domain):
			if u.Path != "/favicon.ico" {
				d++
			}
		case strings.HasPrefix(q.URL, authorize):
			i++
		}
	}
	return d, i
}

// A valid sign-in with script disabled: the issuer's and the relay's pages
// show a button, and the session page's refresh lands on the page.
func TestBrowsers_FlowModel_NoScript(t *testing.T) {
	each(t, func(t *testing.T, m model, engine string) {
		page := "https://" + m.host(refs[0]) + "/one"
		m.count(t)
		r := runScenario(t, noScript(m.scenario(engine, true, tail(
			step{"op": "goto", "url": page}, step{"op": "wait", "contains": authorize},
			step{"op": "click", "selector": "button"}, step{"op": "wait", "contains": "/-/auth/callback"},
			step{"op": "click", "selector": "button"}, step{"op": "wait", "url": page}, secureStep(0), textStep(0))...)))
		cs, rs := ends(t, m, r)
		checkSession(t, cs, m.host(refs[0]))
		if got := r.Steps[7]["value"]; got != "page "+refs[0]+" /one" {
			t.Errorf("page %v", got)
		}
		if d, i := dashRequests(m, rs); d != 5 || i != 1 {
			t.Errorf("requests %d and %d, want 5 and 1", d, i)
		}
	})
}

// A session cookie that is set and not presented (the model sets none for
// the first sign-in): with the session page's Referer the navigation gets
// the final page after 5 requests and one to the issuer; a reload within the
// minute and after it, and the same with script disabled. What each engine
// sends is recorded; what the design claims is asserted.
func TestBrowsers_FlowModel_SessionNotPresented(t *testing.T) {
	each(t, func(t *testing.T, m model, engine string) {
		for _, script := range []bool{true, false} {
			t.Run(map[bool]string{true: "script", false: "no_script"}[script], func(t *testing.T) {
				page := "https://" + m.host(refs[0]) + "/one?x=1"
				sc := m.scenario(engine, true, tail(
					step{"op": "goto", "url": "https://" + issuerHost + "/-/drop-session?n=1"},
					step{"op": "goto", "url": page}, step{"op": "wait", "url": page}, step{"op": "requests"}, // 3
					step{"op": "eval", "expr": `document.getElementById("text").textContent`}, // 4
					step{"op": "reload"}, step{"op": "wait", "url": page}, step{"op": "requests"}, // 7
					step{"op": "eval", "expr": `document.getElementById("text").textContent`}, // 8
					step{"op": "newTab"}, step{"op": "goto", "tab": 1, "url": "https://" + issuerHost + "/-/clock?add=61"},
					step{"op": "reload"}, step{"op": "wait", "url": page}, step{"op": "requests"}, // 13
					step{"op": "eval", "expr": `document.getElementById("text").textContent`}, // 14
				)...)
				if !script {
					// Without script the issuer's and the relay's pages wait for
					// their button: every wait for the page drives there.
					sc = noScript(sc)
					for _, st := range sc.Steps {
						if st["op"] == "wait" && st["url"] == page {
							st["op"] = "drive"
						}
					}
				}
				r := runScenario(t, sc)
				mustPass(t, r)
				off := 0
				first, firstText := requestsOf(t, r.Steps[3+off]), r.Steps[4+off]["value"]
				reload, reloadText := requestsOf(t, r.Steps[7+off]), r.Steps[8+off]["value"]
				late, lateText := requestsOf(t, r.Steps[13+off]), r.Steps[14+off]["value"]
				referer := ""
				for i, q := range first {
					if q.Method == "POST" && strings.Contains(q.URL, "/-/auth/session?at=") && i+1 < len(first) {
						referer = first[i+1].Referer
						t.Logf("FACT %s: the session page's navigation (%s) sent Referer %q", map[bool]string{true: "script", false: "refresh"}[script], first[i+1].URL, referer)
					}
				}
				refused := func(v any) bool {
					s, _ := v.(string)
					return strings.Contains(s, "did not send back the session cookie")
				}
				marked := strings.Contains(referer, "/-/auth/session?at=")
				t.Logf("FACT first answer: %q", firstText)
				switch {
				case script && !refused(firstText):
					t.Errorf("the script's navigation was not refused (Referer %q)", referer)
				case marked != refused(firstText):
					t.Errorf("Referer %q, yet the answer was %q", referer, firstText)
				case !marked && firstText != "page "+refs[0]+" /one?x=1":
					t.Errorf("outside the guard the second sign-in should end on the page: %q", firstText)
				}
				if marked {
					if d, i := dashRequests(m, first); d != 5 || i != 1 {
						t.Errorf("requests %d and %d, want 5 and 1", d, i)
					}
				}
				if refused(firstText) {
					rr := ""
					if len(reload) > 0 {
						rr = reload[0].Referer
					}
					t.Logf("FACT reload within the minute: Referer %q, answer %q", rr, reloadText)
					if strings.Contains(rr, "/-/auth/session?at=") != refused(reloadText) {
						t.Errorf("reload: Referer %q, answer %q", rr, reloadText)
					}
				}
				t.Logf("FACT reload after the minute: answer %q (%d requests)", lateText, len(late))
				if lateText != "page "+refs[0]+" /one?x=1" {
					t.Errorf("after the minute: %q, want the page", lateText)
				}
			})
		}
	})
}

// A link from another site to the login endpoint whose return path is one of
// the gateway's own endpoints or an API route, plain or by dot segments,
// lands on / and leaves the session in place.
func TestBrowsers_FlowModel_ReturnPathFromAnotherSite(t *testing.T) {
	// Shut out, each landing on /: the gateway's own endpoints and API routes,
	// plain, by dot segments, and with a raw trailing space (which a browser
	// would request without it).
	refused := []string{"/-/auth/logout", "/x/../-/auth/logout", "/./-/auth/logout", "/%2e/-/auth/logout",
		"/x/%2e%2e/api/v1/projects?reveal=true", "/api ", "/- "}
	// Kept: an encoded space is a byte of the segment, so "api " and "- " are
	// neither "api" nor "-"; the browser ends on that path, signed in.
	kept := []string{"/api%20", "/-%20"}
	each(t, func(t *testing.T, m model, engine string) {
		host := m.host(refs[0])
		steps := []step{{"op": "goto", "url": "https://" + host + "/p"}, {"op": "wait", "url": "https://" + host + "/p"}}
		follow := func(v, end string) {
			link := "https://" + host + "/-/auth/login?return=" + url.QueryEscape(v)
			steps = append(steps, step{"op": "goto", "url": "https://" + issuerHost + "/link?to=" + url.QueryEscape(link)},
				step{"op": "click", "selector": "#go"}, step{"op": "wait", "url": "https://" + host + end}, secureStep(0))
		}
		for _, v := range refused {
			follow(v, "/")
		}
		for _, v := range kept {
			follow(v, v)
			steps = append(steps, textStep(0))
		}
		r := runScenario(t, m.scenario(engine, true, tail(steps...)...))
		cs, rs := ends(t, m, r)
		checkSession(t, cs, host)
		for i, v := range kept {
			if got := r.Steps[len(r.Steps)-3-5*(len(kept)-1-i)]["value"]; got != "page "+refs[0]+" "+v {
				t.Errorf("kept %q: page %v", v, got)
			}
		}
		for _, q := range rs {
			u, _ := url.Parse(q.URL)
			first, _, _ := strings.Cut(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
			first, _ = url.PathUnescape(first)
			if u.Path == "/-/auth/logout" || strings.ToLower(first) == "api" || strings.Contains(u.Path, "..") {
				t.Errorf("a request reached %s", q.URL)
			}
		}
	})
}

// Off the list a project origin can set a Domain=S cookie that the sign-in
// host and every sibling receive: under a __Host- name, with the prefix in
// another case, or as the value of a nameless cookie, none may arrive under a
// name the gateway reads.
// (On the list no host can set such a cookie: the suffix control.)
func TestBrowsers_DomainCookiesUnderGatewayNames(t *testing.T) {
	m := startModel(t, configs[0].domain)
	for _, engine := range engines {
		t.Run(engine, func(t *testing.T) { domainCookies(t, m, engine) })
	}
}

func domainCookies(t *testing.T, m model, engine string) {
	{
		attrs := "; Domain=" + m.domain + "; Path=/; Secure"
		tries := []struct{ name, cookie string }{
			{"__Host-sp-session", "__Host-sp-session=s." + refs[1] + attrs},
			{"__host-sp-session", "__host-sp-session=s." + refs[1] + attrs},
			{"__HOST-sp-session", "__HOST-sp-session=s." + refs[1] + attrs},
			{"__Host-sp-login-AAAAAAAAAAA", "__Host-sp-login-AAAAAAAAAAA=x" + attrs},
			{"__host-sp-login-AAAAAAAAAAA", "__host-sp-login-AAAAAAAAAAA=x" + attrs},
			{"", "=__Host-sp-session=s." + refs[1] + attrs},
			{"", "=__Host-sp-login-AAAAAAAAAAA=x" + attrs},
			{"sp_ctrl", "sp_ctrl=1" + attrs}, // control: an ordinary name is kept and arrives
		}
		steps := []step{{"op": "goto", "url": "https://" + m.host(refs[0]) + "/-/auth/none"}}
		for _, c := range tries {
			steps = append(steps, step{"op": "setCookie", "name": c.name, "cookie": c.cookie})
		}
		steps = append(steps, step{"op": "cookies"}, step{"op": "requests"},
			step{"op": "goto", "url": "https://" + m.signIn + "/-/auth/none"},
			step{"op": "goto", "url": "https://" + m.host(refs[1]) + "/-/auth/none"}, step{"op": "requests"})
		r := runScenario(t, m.scenario(engine, true, steps...))
		mustPass(t, r)
		for i, c := range tries {
			t.Logf("FACT document.cookie = %q: kept %v", c.cookie, r.Steps[1+i]["kept"])
		}
		for _, cookie := range cookiesOf(t, r.Steps[1+len(tries)]) {
			t.Logf("FACT jar: %q=%q on %s", cookie.Name, cookie.Value, cookie.Domain)
		}
		if r.Steps[len(tries)]["kept"] != true {
			t.Errorf("control: the ordinary Domain cookie was not kept")
		}
		for _, q := range requestsOf(t, r.Steps[len(r.Steps)-1]) {
			t.Logf("FACT %s sent cookie names %q", q.URL, q.Cookies)
			if !slices.Contains(q.Cookies, "sp_ctrl") {
				t.Errorf("control: %s did not receive the ordinary Domain cookie", q.URL)
			}
			for _, n := range q.Cookies {
				if n == "__Host-sp-session" || regexp.MustCompile(`^__Host-sp-login-[A-Za-z0-9_-]{11}$`).MatchString(n) {
					t.Errorf("%s received %q from a sibling", q.URL, n)
				}
			}
		}
	}
}

// A name the scenario does not map (here one under the listed suffix) can be
// neither resolved nor reached: the engines go through a proxy that does not
// exist for every name but the mapped ones. Control: a mapped name loads on
// the same run, so the bypass list is honoured.
func TestBrowsers_UnmappedNameUnreachable(t *testing.T) {
	each(t, func(t *testing.T, m model, engine string) {
		unmapped := "https://unmapped-" + refs[0] + "." + listedDomain + "/"
		mapped := "https://" + m.host(refs[0]) + "/-/auth/none"
		r := runScenario(t, m.scenario(engine, true, step{"op": "goto", "url": mapped}, secureStep(0), step{"op": "goto", "url": unmapped}))
		if len(r.Steps) != 3 || r.Steps[0]["error"] != nil || r.Steps[1]["value"] != true {
			t.Fatalf("control: the mapped name did not load: %v", r.Steps)
		}
		if r.Steps[2]["error"] == nil {
			t.Fatalf("the unmapped name %s loaded: %v", unmapped, r.Steps[2])
		}
		t.Logf("FACT unmapped name: %v", r.Steps[2]["error"])
		// A loopback literal: Chromium sends it to the dead proxy as well
		// (<-loopback>); the other engines are recorded.
		r = runScenario(t, m.scenario(engine, true, step{"op": "goto", "url": "https://127.0.0.1/"}))
		msg, _ := r.Steps[0]["error"].(string)
		t.Logf("FACT loopback literal: %q", msg)
		if engine == "chromium" && !strings.Contains(msg, "ERR_PROXY_CONNECTION_FAILED") {
			t.Errorf("Chromium reached a loopback literal without the proxy: %q", msg)
		}
	})
}
