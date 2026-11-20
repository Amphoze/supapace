package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/routes"
)

const (
	studioDom = "studio.test"
	issuer    = "https://issuer.test"
	dhostA    = refA + "." + studioDom
	dhostB    = refB + "." + studioDom
	signInH   = "sign-in." + studioDom
	// principals of the fixture table
	subOwnerA, subDevA, subROA, subOwnerB = "user-1", "user-2", "user-3", "user-4"
)

// pairPEM writes a self-signed certificate for names and its key under dir as
// cert.pem and key.pem; it returns the certificate's DER bytes.
func pairPEM(t *testing.T, dir string, names ...string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	put(t, filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	return der
}

func put(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

var issuerSigner = newSigner()

func issuerKey(s signer) dashfile.IssuerKey {
	return dashfile.IssuerKey{Kid: s.kid, Kty: "RSA", N: base64.RawURLEncoding.EncodeToString(s.priv.N.Bytes()), E: "AQAB"}
}

// dfile is the fixture table: project A with an owner, a developer and a
// read-only member; project B with an owner.
func dfile(gen int64) dashfile.File {
	m := func(sub, role string) dashfile.Member { return dashfile.Member{Iss: issuer, Sub: sub, Role: role} }
	return dashfile.File{Generation: gen, Node: "local", StudioDomain: studioDom, Studio: "http://10.212.0.3:3000",
		Issuer: &dashfile.Issuer{Iss: issuer, ClientID: "supapace", AuthorizeURL: issuer + "/authorize",
			SessionSeconds: 28800, Keys: []dashfile.IssuerKey{issuerKey(issuerSigner)}},
		Projects: map[string]dashfile.Project{
			refA: {Name: "A", Members: []dashfile.Member{m(subOwnerA, "owner"), m(subDevA, "developer"), m(subROA, "read_only")}},
			refB: {Name: "B", Members: []dashfile.Member{m(subOwnerB, "owner")}},
		}}
}

func writeDashFile(t *testing.T, path string, f dashfile.File) {
	t.Helper()
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, path, b)
}

// dashDir lays out a gateway directory with the dashboard's files: the domain
// file, the assertion key and the studio pair (no dashboard file).
func dashDir(t *testing.T) (dir string, priv ed25519.PrivateKey) {
	t.Helper()
	dir = t.TempDir()
	put(t, filepath.Join(dir, "dash", "domain"), []byte(studioDom+"\n"))
	pk, _, err := dashtok.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(dir, "dash", "assert.key"), pk)
	if priv, err = dashtok.ParsePrivate(pk); err != nil {
		t.Fatal(err)
	}
	pairPEM(t, filepath.Join(dir, "tls-studio"), studioDom, "*."+studioDom)
	return dir, priv
}

type dashEnv struct {
	*env
	dir  string
	d    *Dashboard
	priv ed25519.PrivateKey

	fwd, auth []*dashRequest // what reached each seam
	authHeld  int            // slots held when the sign-in seam was last entered
	hold      chan struct{}  // when set, the forward seam waits on it
	entered   chan struct{}  // signalled when the forward seam is entered
	readBody  bool           // the forward seam reads the body and records the error
	bodyErr   error
}

func (e *dashEnv) path() string { return filepath.Join(e.dir, "dashboard.json") }

// newDashEnv serves routes and the fixture dashboard table (loaded when
// table is true) through one gateway. Both seams are replaced by recorders
// that answer 200.
func newDashEnv(t *testing.T, routesFile *routes.File, table bool) *dashEnv {
	t.Helper()
	e := &dashEnv{env: newEnv(t, routesFile)}
	e.dir, e.priv = dashDir(t)
	if table {
		writeDashFile(t, e.path(), dfile(1))
	}
	e.d = LoadDashboard(e.dir)
	if e.d == nil || e.d.broken != nil {
		t.Fatalf("dashboard not loaded: %+v", e.d)
	}
	if table {
		if err := e.d.table.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	e.gw.SetDashboard(e.d)
	oldF, oldA := dashForward, dashAuth
	t.Cleanup(func() { stopServers(t); dashForward, dashAuth = oldF, oldA })
	dashForward = func(w http.ResponseWriter, r *http.Request, dr *dashRequest) {
		e.mu.Lock()
		e.fwd = append(e.fwd, dr)
		hold, entered := e.hold, e.entered
		e.mu.Unlock()
		if e.readBody {
			_, err := io.ReadAll(r.Body)
			e.mu.Lock()
			e.bodyErr = err
			e.mu.Unlock()
		}
		if entered != nil {
			entered <- struct{}{}
		}
		if hold != nil {
			<-hold
		}
		w.WriteHeader(http.StatusOK)
	}
	dashAuth = func(w http.ResponseWriter, r *http.Request, dr *dashRequest) {
		e.mu.Lock()
		e.auth = append(e.auth, dr)
		e.authHeld = len(e.gw.inflight) + len(e.d.slots)
		e.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}
	return e
}

func (e *dashEnv) resetSeams() {
	e.mu.Lock()
	e.fwd, e.auth = nil, nil
	e.mu.Unlock()
}

func (e *dashEnv) seams() (fwd, auth int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.fwd), len(e.auth)
}

func (e *dashEnv) lastFwd(t *testing.T) *dashRequest {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.fwd) == 0 {
		t.Fatal("nothing forwarded")
	}
	return e.fwd[len(e.fwd)-1]
}

// rawReq builds a request whose target is exactly raw, as the server hands a
// request over (RequestURI as sent; the parsed URL is not what the rules read).
func rawReq(method, host, raw string) *http.Request {
	r := httptest.NewRequest(method, "/", nil)
	r.RequestURI = raw
	r.Host = host
	r.RemoteAddr = peerIP + ":4321"
	return r
}

func (e *dashEnv) session(t *testing.T, ref, iss, sub string, iat, life int64) string {
	t.Helper()
	tok, err := dashtok.SignSession(e.priv, dashtok.Session{Iss: iss, Sub: sub, Name: "N", Ref: ref, Iat: iat, Exp: iat + life})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// as adds a fresh session cookie of sub for ref.
func (e *dashEnv) as(t *testing.T, r *http.Request, ref, sub string) *http.Request {
	t.Helper()
	r.AddCookie(&http.Cookie{Name: "__Host-sp-session", Value: e.session(t, ref, issuer, sub, time.Now().Unix()-10, 3600)})
	return r
}

var dashWant = map[string]string{
	"X-Content-Type-Options":       "nosniff",
	"Content-Security-Policy":      "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Referrer-Policy":              "same-origin",
	"Strict-Transport-Security":    "max-age=31536000",
}

// dashHeadersOK reports what is wrong with a gateway answer on a dashboard
// host: each dashboard header exactly once with its value, no sandbox,
// no-store.
func dashHeadersWrong(h http.Header) string {
	for k, v := range dashWant {
		if vs := h.Values(k); len(vs) != 1 || vs[0] != v {
			return k + ": " + strings.Join(vs, " | ")
		}
	}
	for _, v := range h.Values("Content-Security-Policy") {
		if strings.Contains(v, "sandbox") {
			return "sandbox"
		}
	}
	if h.Get("Cache-Control") != "no-store" {
		return "Cache-Control: " + h.Get("Cache-Control")
	}
	return ""
}

// dexpect checks a refusal on a dashboard host: status, code, the dashboard
// headers, and that neither seam was reached.
func (e *dashEnv) dexpect(t *testing.T, name string, r *http.Request, status int, code string) *httptest.ResponseRecorder {
	t.Helper()
	e.resetSeams()
	w := e.do(r)
	if w.Code != status {
		t.Errorf("%s: status %d, want %d (body %s)", name, w.Code, status, w.Body)
		return w
	}
	if code != "" {
		var b struct{ Code string }
		if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || b.Code != code {
			t.Errorf("%s: body %s, want code %q", name, w.Body, code)
		}
	}
	if s := dashHeadersWrong(w.Header()); s != "" {
		t.Errorf("%s: dashboard headers wrong: %s", name, s)
	}
	if f, a := e.seams(); f+a != 0 {
		t.Errorf("%s: refused request reached a seam (forward %d, auth %d)", name, f, a)
	}
	return w
}

// passes checks that r reached the forward seam and returns what it saw.
func (e *dashEnv) passes(t *testing.T, name string, r *http.Request) *dashRequest {
	t.Helper()
	e.resetSeams()
	w := e.do(r)
	if f, _ := e.seams(); w.Code != http.StatusOK || f != 1 {
		t.Errorf("%s: status %d, forwarded %d, want 200 and 1 (body %s)", name, w.Code, f, w.Body)
		return &dashRequest{}
	}
	return e.lastFwd(t)
}

func TestDashHostClasses(t *testing.T) {
	// No domain file: the studio hosts are unknown hosts, answered as built.
	plain := newEnv(t, active())
	plain.expect(t, "no domain file, dashboard host", req("GET", dhostA, "/", nil), 404, "not_found")
	plain.expect(t, "no domain file, studio domain", req("GET", studioDom, "/", nil), 404, "not_found")
	if w := plain.do(req("GET", hostA, "/-/health", nil)); w.Header()["X-Supapace-Dashboard"] != nil {
		t.Errorf("health carries the dashboard header without a domain file: %v", w.Header())
	}

	// A domain, no table: the dashboard and sign-in hosts 503; the studio
	// domain still redirects.
	e := newDashEnv(t, active(), false)
	e.dexpect(t, "no table, dashboard host", e.as(t, rawReq("GET", dhostA, "/"), refA, subOwnerA), 503, "unavailable")
	e.dexpect(t, "no table, sign-in host", rawReq("GET", signInH, "/"), 503, "unavailable")
	e.dexpect(t, "no table, studio domain", rawReq("GET", studioDom, "/"), 302, "")
	// Two labels under the domain are no dashboard host: unknown, as built.
	e.expect(t, "two labels", req("GET", "www."+dhostA, "/", nil), 404, "not_found")
	if w := e.do(req("GET", hostA, "/-/health", nil)); w.Header().Get("X-Supapace-Dashboard") != "ok" {
		t.Errorf("health: %v", w.Header())
	}

	writeDashFile(t, e.path(), dfile(1))
	if err := e.d.table.Reload(); err != nil {
		t.Fatal(err)
	}
	e.dexpect(t, "unknown label", rawReq("GET", "cccccccccccccccccccc."+studioDom, "/"), 404, "not_found")
	e.dexpect(t, "label not a ref", rawReq("GET", "www."+studioDom, "/"), 404, "not_found")
	e.passes(t, "member, port in host", e.as(t, rawReq("GET", dhostA+":8443", "/"), refA, subOwnerA))
	e.resetSeams()
	if w := e.do(rawReq("GET", signInH, "/")); w.Code != 200 {
		t.Errorf("sign-in host: %d", w.Code)
	} else if _, a := e.seams(); a != 1 {
		t.Errorf("sign-in host did not reach the sign-in seam")
	}
	e.dexpect(t, "studio domain", rawReq("GET", studioDom, "/"), 302, "")

	r := e.as(t, rawReq("GET", dhostA, "/"), refA, subOwnerA)
	r.TLS = &tls.ConnectionState{ServerName: dhostB}
	e.dexpect(t, "wrong server name", r, 421, "misdirected")
	r = rawReq("GET", studioDom, "/")
	r.TLS = &tls.ConnectionState{ServerName: dhostA}
	e.dexpect(t, "wrong server name, studio domain", r, 421, "misdirected")
	r = rawReq("GET", signInH, "/")
	r.TLS = &tls.ConnectionState{ServerName: studioDom}
	e.dexpect(t, "wrong server name, sign-in host", r, 421, "misdirected")
	r = e.as(t, rawReq("GET", dhostA, "/"), refA, subOwnerA)
	r.TLS = &tls.ConnectionState{ServerName: strings.ToUpper(dhostA)}
	e.passes(t, "server name in capitals", r)

	// Project hosts are untouched by the switch.
	e.expect(t, "project host", req("GET", hostA, "/rest/v1/x", nil), 401, "no_apikey")

	// A dashboard host is classified with no route table loaded.
	nr := newDashEnv(t, nil, true)
	nr.passes(t, "no route table, dashboard host", nr.as(t, rawReq("GET", dhostA, "/"), refA, subOwnerA))
	nr.expect(t, "no route table, project host", req("GET", hostA, "/rest/v1/x", nil), 503, "unavailable")
}

func TestDashTable_BadKeepsLastGood_MissingUnloads_DomainMustAgree(t *testing.T) {
	e := newDashEnv(t, active(), true)
	gen := func() int64 {
		if dt := e.d.table.cur.Load(); dt != nil {
			return dt.file.Generation
		}
		return 0
	}
	ok := e.as(t, rawReq("GET", dhostA, "/"), refA, subOwnerA)
	ok2 := func() *http.Request { return e.as(t, rawReq("GET", dhostA, "/"), refA, subOwnerA) }

	writeRaw(t, e.path(), []byte(`{"generation": 2`))
	if err := e.d.table.Reload(); err == nil || gen() != 1 {
		t.Fatalf("bad file: err %v, generation %d", err, gen())
	}
	e.passes(t, "after a bad file", ok)

	other := dfile(3)
	other.StudioDomain = "other.test"
	writeDashFile(t, e.path(), other)
	if err := e.d.table.Reload(); err == nil || gen() != 1 {
		t.Fatalf("other domain: err %v, generation %d", err, gen())
	}

	writeDashFile(t, e.path(), dfile(4))
	if err := e.d.table.Reload(); err != nil || gen() != 4 {
		t.Fatalf("good file: err %v, generation %d", err, gen())
	}

	if err := os.Remove(e.path()); err != nil {
		t.Fatal(err)
	}
	if err := e.d.table.Reload(); err != nil || gen() != 0 {
		t.Fatalf("missing file: err %v, generation %d", err, gen())
	}
	e.dexpect(t, "unloaded", ok2(), 503, "unavailable")
	e.dexpect(t, "unloaded, sign-in host", rawReq("GET", signInH, "/"), 503, "unavailable")
	e.dexpect(t, "unloaded, studio domain", rawReq("GET", studioDom, "/"), 302, "")

	writeDashFile(t, e.path(), dfile(5))
	if err := e.d.table.Reload(); err != nil || gen() != 5 {
		t.Fatalf("file back: err %v, generation %d", err, gen())
	}
	e.passes(t, "file back", ok2())
}

func TestDashTable_IssuerKeysBecomeDashboardKeys(t *testing.T) {
	e := newDashEnv(t, active(), false)
	f := dfile(1)
	second := newSigner()
	f.Issuer.Keys = append(f.Issuer.Keys, issuerKey(second))
	writeDashFile(t, e.path(), f)
	if err := e.d.table.Reload(); err != nil {
		t.Fatal(err)
	}
	dr := e.passes(t, "member", e.as(t, rawReq("GET", dhostA, "/"), refA, subOwnerA))
	if len(dr.Keys) != 2 {
		t.Fatalf("keys: %d", len(dr.Keys))
	}
	for i, want := range []string{issuerSigner.kid, second.kid} {
		if k := dr.Keys[i]; k.KID != want || k.Class != jwtx.ClassDashboard || k.Pub == nil {
			t.Errorf("key %d: kid %q class %q", i, k.KID, k.Class)
		}
	}

	// A key the dashboard-key check refuses makes the file a bad file.
	bad := dfile(2)
	bad.Issuer.Keys[0].E = "Aw" // exponent 3
	writeDashFile(t, e.path(), bad)
	if err := e.d.table.Reload(); err == nil {
		t.Error("a refused key loaded")
	}
	if g := e.d.table.cur.Load().file.Generation; g != 1 {
		t.Errorf("generation %d after a bad key", g)
	}

	// The loader refuses a key that is not RSA itself, not trusting the parser.
	ec := dfile(3)
	ec.Issuer.Keys[0].Kty = "EC"
	if _, err := buildDash(ec, studioDom); err == nil {
		t.Error("a key of kty EC was accepted by the loader")
	}
	if _, err := buildDash(dfile(3), studioDom); err != nil {
		t.Errorf("control: %v", err)
	}
}

func TestDashTable_ReadBound(t *testing.T) {
	if maxDashFile != 64<<20 {
		t.Errorf("read bound %d, want 64 MiB", maxDashFile)
	}
	e := newDashEnv(t, active(), true)
	// padded is a valid file of exactly n bytes: trailing white space is
	// valid JSON.
	padded := func(gen int64, n int) []byte {
		b, err := dfile(gen).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return append(b, bytes.Repeat([]byte(" "), n-len(b))...)
	}
	writeRaw(t, e.path(), padded(2, maxDashFile))
	if err := e.d.table.Reload(); err != nil || e.d.table.cur.Load().file.Generation != 2 {
		t.Fatalf("file of exactly the bound: %v", err)
	}
	writeRaw(t, e.path(), padded(3, maxDashFile+1))
	if err := e.d.table.Reload(); err == nil {
		t.Error("a file one byte above the bound was read")
	}
	if g := e.d.table.cur.Load().file.Generation; g != 2 {
		t.Errorf("generation %d after an oversize file", g)
	}
}

func TestDashAnswers_CarryTheDashboardHeaders_NeverSandbox(t *testing.T) {
	e := newDashEnv(t, active(), false)
	e.dexpect(t, "503 no table", rawReq("GET", dhostA, "/"), 503, "unavailable")
	writeDashFile(t, e.path(), dfile(1))
	if err := e.d.table.Reload(); err != nil {
		t.Fatal(err)
	}
	r := rawReq("GET", dhostA, "/")
	r.TLS = &tls.ConnectionState{ServerName: studioDom}
	e.dexpect(t, "421", r, 421, "misdirected")
	e.dexpect(t, "404 label", rawReq("GET", "cccccccccccccccccccc."+studioDom, "/"), 404, "not_found")
	e.dexpect(t, "400 rule 0", rawReq("GET", dhostA, "/a//b"), 400, "bad_request")
	e.dexpect(t, "400 rule 0, sign-in host", rawReq("GET", signInH, "/a//b"), 400, "bad_request")
	e.dexpect(t, "404 studio domain", rawReq("GET", studioDom, "/a//b"), 404, "not_found")
	e.dexpect(t, "404 rule 2", rawReq("GET", dhostA, "/x/"+refB), 404, "not_found")
	e.dexpect(t, "401", rawReq("GET", dhostA, "/api/x"), 401, "login_required")
	nav := rawReq("GET", dhostA, "/x")
	nav.Header.Set("Sec-Fetch-Mode", "navigate")
	e.dexpect(t, "302", nav, 302, "")
	e.dexpect(t, "403 member", e.as(t, rawReq("GET", dhostA, "/"), refA, subOwnerB), 403, "not_a_member")
	e.dexpect(t, "403 read_only", e.as(t, rawReq("DELETE", dhostA, "/x"), refA, subROA), 403, "read_only")
	up := e.as(t, rawReq("GET", dhostA, "/x"), refA, subOwnerA)
	up.Header.Set("Upgrade", "websocket")
	e.dexpect(t, "400 upgrade", up, 400, "upgrade_not_supported")
	big := e.as(t, rawReq("POST", dhostA, "/x"), refA, subOwnerA)
	big.ContentLength = 3 << 20
	e.dexpect(t, "413", big, 413, "body_too_large")

	dashForward, dashAuth = nil, nil
	e.dexpect(t, "503 no forwarder", e.as(t, rawReq("GET", dhostA, "/"), refA, subOwnerA), 503, "unavailable")
	e.dexpect(t, "503 no sign-in", rawReq("GET", dhostA, "/-/auth/login"), 503, "unavailable")
	e.dexpect(t, "503 no sign-in, sign-in host", rawReq("GET", signInH, "/"), 503, "unavailable")
	e.dexpect(t, "302 studio domain, no seam needed", rawReq("GET", studioDom, "/"), 302, "")
}

func TestDashRefusals_CountedNotLoggedPerRequest(t *testing.T) {
	e := newDashEnv(t, active(), true)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(io.Discard) })
	owner := func(target string) *http.Request { return e.as(t, rawReq("GET", dhostA, target), refA, subOwnerA) }
	for i := 0; i < 50; i++ {
		sw := owner("/sw.js") // ServeHTTP drops a request's header when it returns
		sw.Header.Set("Service-Worker", "script")
		e.do(owner("/a//b"))      // rule 0
		e.do(owner("/x/" + refB)) // rule 2
		e.do(owner("/api/ai/x"))  // rule 3
		e.do(sw)                  // rule 4
		e.do(rawReq("GET", signInH, "/a/../b"))
		e.do(rawReq("GET", dhostA, "/api/x")) // rule 5: not counted here, an access line
	}
	perRequest := strings.Split(strings.TrimSpace(buf.String()), "\n")
	for _, l := range perRequest {
		if !strings.Contains(l, `"path":"/api/x","status":401,`) {
			t.Fatalf("refusals of rules 0-4 logged per request: %q", l)
		}
	}
	if len(perRequest) != 50 {
		t.Fatalf("%d access lines for 50 refusals of rule 5", len(perRequest))
	}
	buf.Reset()
	e.d.logRefusals()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want one line per ref, got %q", buf.String())
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{"ref " + refA + ": rule0 50 rule2 50 rule3 50 rule4 50", "ref _: rule0 50 rule2 0 rule3 0 rule4 0"} {
		if !strings.Contains(got, want) {
			t.Errorf("no line %q in %q", want, got)
		}
	}
	buf.Reset()
	e.d.logRefusals()
	if buf.Len() != 0 {
		t.Errorf("counts not reset: %q", buf.String())
	}
}

// TestProjectAPI_ByteForByte: the project API's answers are the same with
// and without the dashboard, with and without a dashboard table.
func TestProjectAPI_ByteForByte(t *testing.T) {
	a, b, _ := keys()
	reqs := []func() *http.Request{
		func() *http.Request { return req("GET", hostA, "/rest/v1/items", nil) },
		func() *http.Request {
			return withKey(req("GET", hostA, "/rest/v1/items?x=1", nil), a.anon.token(t, "anon"))
		},
		func() *http.Request {
			return withKey(req("GET", hostA, "/rest/v1/items", nil), b.anon.token(t, "anon"))
		},
		func() *http.Request {
			return withKey(req("POST", hostA, "/graphql/v1", strings.NewReader("{}")), a.anon.token(t, "anon"))
		},
		func() *http.Request { return withKey(req("GET", hostA, "/nope", nil), a.anon.token(t, "anon")) },
		func() *http.Request { return req("GET", "x.sp.test", "/rest/v1/items", nil) },
		func() *http.Request { return req("GET", "evil.example", "/rest/v1/items", nil) },
		func() *http.Request {
			r := withKey(req("GET", hostA, "/rest/v1/items", nil), a.anon.token(t, "anon"))
			r.Header.Set("Upgrade", "h2c")
			return r
		},
		func() *http.Request {
			r := req("GET", hostA, "/rest/v1/items", nil)
			r.TLS = &tls.ConnectionState{ServerName: "x." + studioDom}
			return r
		},
	}
	type answer struct {
		Code   int
		Header http.Header
		Body   string
	}
	record := func(gw http.Handler, routesLoaded bool) []answer {
		var out []answer
		for _, mk := range reqs {
			w := httptest.NewRecorder()
			gw.ServeHTTP(w, mk())
			w.Header().Del("Date") // the upstream's clock, not the gateway's answer
			out = append(out, answer{w.Code, w.Header(), w.Body.String()})
		}
		w := httptest.NewRecorder()
		gw.ServeHTTP(w, req("GET", hostA, "/-/health", nil))
		w.Header().Del("X-Supapace-Dashboard") // the one difference, asserted elsewhere
		return append(out, answer{w.Code, w.Header(), w.Body.String()})
	}
	for _, routesLoaded := range []bool{true, false} {
		var rf *routes.File
		if routesLoaded {
			rf = active()
		}
		want := record(newEnv(t, rf).gw, routesLoaded)
		noTable := newDashEnv(t, rf, false)
		withTable := newDashEnv(t, rf, true)
		for name, gw := range map[string]http.Handler{"no table": noTable.gw, "table": withTable.gw} {
			got := record(gw, routesLoaded)
			for i := range want {
				wj, _ := json.Marshal(want[i])
				gj, _ := json.Marshal(got[i])
				if !bytes.Equal(wj, gj) {
					t.Errorf("routes %v, %s, request %d:\n got %s\nwant %s", routesLoaded, name, i, gj, wj)
				}
			}
		}
	}
}

func TestCertificateByServerName(t *testing.T) {
	e := newDashEnv(t, active(), true)
	studio := e.d.cert
	for name, want := range map[string]*tls.Certificate{
		studioDom: studio, dhostA: studio, "a.b." + studioDom: studio, strings.ToUpper(dhostA): studio,
		hostA: nil, "": nil, "x" + studioDom: nil, studioDom + ".evil": nil,
	} {
		got, err := e.gw.Certificate(&tls.ClientHelloInfo{ServerName: name})
		if err != nil || got != want {
			t.Errorf("%q: got studio=%v, want studio=%v (%v)", name, got == studio, want == studio, err)
		}
	}

	// Through a real handshake: the studio pair for the studio names, the
	// first pair for every other name.
	firstDir := t.TempDir()
	firstDER := pairPEM(t, firstDir, "*.sp.test")
	first, err := tls.LoadX509KeyPair(filepath.Join(firstDir, "cert.pem"), filepath.Join(firstDir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{first}, GetCertificate: e.gw.Certificate}
	srv.StartTLS()
	defer srv.Close()
	leaf := func(sni string) []byte {
		c, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].Raw
	}
	if !bytes.Equal(leaf(dhostA), studio.Certificate[0]) {
		t.Error("studio host did not get the studio certificate")
	}
	if !bytes.Equal(leaf(hostA), firstDER) {
		t.Error("project host did not get the first certificate")
	}

	// A gateway whose dashboard did not load never hands out the studio pair.
	broken := LoadDashboard(e.dir)
	broken.broken = os.ErrInvalid
	gw := New(NewTable(filepath.Join(t.TempDir(), "routes.json")))
	gw.SetDashboard(broken)
	if c, _ := gw.Certificate(&tls.ClientHelloInfo{ServerName: dhostA}); c != nil {
		t.Error("broken dashboard handed out a certificate")
	}
}

// paddedTable is a valid dashboard file of exactly n bytes: trailing white
// space is valid JSON.
func paddedTable(t *testing.T, gen int64, n int) []byte {
	t.Helper()
	b, err := dfile(gen).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return append(b, bytes.Repeat([]byte(" "), n-len(b))...)
}

// TestDashTable_ReadAllocatesTheFileOnce: loading a table file of the bound
// allocates about the file once, not a doubling series of buffers. What is
// allocated during the load bounds the live heap's growth from above.
func TestDashTable_ReadAllocatesTheFileOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("writes and loads a 64 MiB file")
	}
	e := newDashEnv(t, active(), true)
	writeRaw(t, e.path(), paddedTable(t, 2, maxDashFile))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := e.d.table.Reload()
	runtime.ReadMemStats(&after)
	if err != nil || e.d.table.cur.Load().file.Generation != 2 {
		t.Fatalf("load: %v", err)
	}
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("allocated during the load of a %d-byte file: %d bytes (%.1f MiB)", maxDashFile, alloc, float64(alloc)/(1<<20))
	if alloc >= 128<<20 {
		t.Errorf("the load allocated %.1f MiB, want well under 128 MiB", float64(alloc)/(1<<20))
	}
}

// TestDashTable_FileGrowingPastTheBoundRefused: a file that was within the
// bound at its stat and holds more than the bound when it is read is refused.
// readBounded takes the stat's size, so the grown file is a 5-byte file read
// as one stated at 4 bytes.
func TestDashTable_FileGrowingPastTheBoundRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	put(t, p, []byte("12345"))
	read := func(size, max int64) ([]byte, error) {
		fh, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		defer fh.Close()
		return readBounded(fh, size, max)
	}
	if b, err := read(4, 4); err == nil {
		t.Errorf("a file stated at the bound that grew past it was read: %q", b)
	}
	if b, err := read(4, 5); err != nil || string(b) != "12345" {
		t.Errorf("control, grown within the bound: %q %v", b, err)
	}
}

// TestDashTable_NotARegularFileRefused: a device, a directory or a FIFO at
// the table's path is refused at once, nothing is allocated for it, and the
// table in force stays. A FIFO with no writer must not block the reload.
func TestDashTable_NotARegularFileRefused(t *testing.T) {
	e := newDashEnv(t, active(), true)
	place := map[string]func(p string) error{
		"symlink to /dev/zero": func(p string) error { return os.Symlink("/dev/zero", p) },
		"directory":            func(p string) error { return os.Mkdir(p, 0o755) },
		"fifo":                 func(p string) error { return syscall.Mkfifo(p, 0o644) },
	}
	for name, mk := range place {
		if err := os.Remove(e.path()); err != nil {
			t.Fatal(err)
		}
		if err := mk(e.path()); err != nil {
			t.Fatal(err)
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		done := make(chan error, 1)
		go func() { done <- e.d.table.Reload() }()
		select {
		case err := <-done:
			runtime.ReadMemStats(&after)
			if err == nil {
				t.Errorf("%s: loaded", name)
			}
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc >= 1<<20 {
				t.Errorf("%s: refusing it allocated %d bytes", name, alloc)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: the reload blocked", name)
		}
		if dt := e.d.table.cur.Load(); dt == nil || dt.file.Generation != 1 {
			t.Errorf("%s: the table in force did not stay", name)
		}
		if err := os.Remove(e.path()); err != nil {
			t.Fatal(err)
		}
		writeDashFile(t, e.path(), dfile(1)) // the next case replaces a regular file
	}
}

// TestDashTable_OversizeRefusedUnread: a file larger than the bound is
// refused by its size, before a buffer for it is allocated.
func TestDashTable_OversizeRefusedUnread(t *testing.T) {
	e := newDashEnv(t, active(), true)
	tmp := e.path() + ".big"
	fh, err := os.Create(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if err := fh.Truncate(4 * maxDashFile); err != nil { // sparse: nothing is written
		t.Fatal(err)
	}
	fh.Close()
	if err := os.Rename(tmp, e.path()); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err = e.d.table.Reload()
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Error("a file four times the bound was read")
	}
	if g := e.d.table.cur.Load().file.Generation; g != 1 {
		t.Errorf("generation %d, want the table in force (1)", g)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc >= 1<<20 {
		t.Errorf("refusing an oversize file allocated %d bytes", alloc)
	}
}

// TestDashHostClasses_SignInHostAndStudioDomain: the studio domain answers a
// fixed redirect or 404 with or without a table; the sign-in host is
// classified before the table is consulted and hands every request that
// passes rule 0 to the sign-in seam.
func TestDashHostClasses_SignInHostAndStudioDomain(t *testing.T) {
	e := newDashEnv(t, active(), false)
	withCookies := func(r *http.Request) *http.Request {
		r.AddCookie(&http.Cookie{Name: "__Host-sp-session", Value: e.session(t, "_", issuer, subOwnerA, time.Now().Unix()-10, 3600)})
		r.AddCookie(&http.Cookie{Name: "__Host-sp-login-AAAAAAAAAAA", Value: "x"})
		r.AddCookie(&http.Cookie{Name: "other", Value: "y"})
		return r
	}
	const loc = "https://" + signInH + "/"
	var body404 string
	studio := func(table string) {
		for _, m := range []string{"GET", "HEAD"} {
			for _, target := range []string{"/", "/?x=1", "/?return=https://evil.example/&next=//evil.example", "/?#x"} {
				for _, host := range []string{studioDom, studioDom + ":8443", studioDom + ":0"} {
					r := withCookies(rawReq(m, host, target))
					r.Header.Set("X-Forwarded-Host", "evil.example")
					r.Header.Set("Referer", "https://evil.example/")
					name := table + " " + m + " " + host + target
					w := e.dexpect(t, name, r, 302, "")
					if got := w.Header().Values("Location"); len(got) != 1 || got[0] != loc {
						t.Errorf("%s: Location %q", name, got)
					}
					if c := w.Header().Values("Set-Cookie"); len(c) != 0 || w.Body.Len() != 0 {
						t.Errorf("%s: Set-Cookie %q, body %q", name, c, w.Body)
					}
				}
			}
		}
		for _, c := range []struct{ m, target string }{
			{"GET", "/x"}, {"GET", "/-/auth/login"}, {"GET", "/-/auth/callback"}, {"POST", "/"}, {"PUT", "/"},
			{"OPTIONS", "/"}, {"DELETE", "/"}, {"get", "/"}, {"GET", "//"}, {"GET", "/a/../b"}, {"GET", "/%zz"},
			{"GET", "/#"}, {"GET", "/x#/../"}, {"GET", "/%2F"}, {"GET", "/" + refA}, {"GET", "/api/mcp"}, {"GET", "*"}, {"GET", ""},
		} {
			name := table + " " + c.m + " " + c.target
			w := e.dexpect(t, name, withCookies(rawReq(c.m, studioDom, c.target)), 404, "not_found")
			if len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("Location") != "" {
				t.Errorf("%s: %v", name, w.Header())
			}
			if body404 == "" {
				body404 = w.Body.String()
			} else if w.Body.String() != body404 {
				t.Errorf("%s: body %q, want the constant %q", name, w.Body, body404)
			}
		}
	}
	studio("no table")

	// The sign-in host: no table, 503.
	e.dexpect(t, "sign-in host, no table", rawReq("GET", signInH, "/"), 503, "unavailable")
	e.dexpect(t, "sign-in host, no table, rule-0 path", rawReq("GET", signInH, "/a//b"), 503, "unavailable")

	writeDashFile(t, e.path(), dfile(1))
	if err := e.d.table.Reload(); err != nil {
		t.Fatal(err)
	}
	studio("table")

	// The sign-in host: rule 0, then the seam with ref "_", holding no slot.
	// The table has no project "sign-in", so reaching the seam shows the label
	// was not looked up.
	e.dexpect(t, "sign-in host, rule 0", rawReq("GET", signInH, "/a/../b"), 400, "bad_request")
	sw := rawReq("GET", signInH, "/sw.js")
	sw.Header.Set("Service-Worker", "script")
	for _, r := range []*http.Request{
		rawReq("GET", signInH, "/"), rawReq("GET", signInH, "/project/x"), rawReq("GET", signInH, "/project/"+refB),
		rawReq("GET", signInH, "/api/mcp"), rawReq("POST", signInH, "/-/auth/callback"), rawReq("DELETE", signInH, "/x"),
		rawReq("GET", signInH+":443", "/"), sw, e.as(t, rawReq("GET", signInH, "/x"), refA, subOwnerA),
	} {
		name := r.Method + " " + r.Host + r.RequestURI
		e.resetSeams()
		w := e.do(r)
		f, a := e.seams()
		if w.Code != 200 || f != 0 || a != 1 {
			t.Errorf("%s: %d, forward %d, auth %d", name, w.Code, f, a)
			continue
		}
		e.mu.Lock()
		dr, held := e.auth[0], e.authHeld
		e.mu.Unlock()
		if dr.Ref != "_" || dr.Table == nil || dr.Dash != e.d || dr.Unpresented || held != 0 {
			t.Errorf("%s: ref %q, table %v, unpresented %v, slots held %d", name, dr.Ref, dr.Table != nil, dr.Unpresented, held)
		}
	}

	// A wrong server name is 421 on both.
	for _, h := range []string{studioDom, signInH} {
		r := rawReq("GET", h, "/")
		r.TLS = &tls.ConnectionState{ServerName: dhostA}
		e.dexpect(t, "wrong server name, "+h, r, 421, "misdirected")
	}
	r := rawReq("GET", signInH, "/")
	r.TLS = &tls.ConnectionState{ServerName: signInH}
	e.resetSeams()
	if w := e.do(r); w.Code != 200 {
		t.Errorf("server name equal to the sign-in host: %d", w.Code)
	}

	// Host matching is exact: none of these is the sign-in host or the studio
	// domain, and none is redirected or reaches a seam.
	for _, h := range []string{
		"Sign-In." + studioDom, "SIGN-IN." + studioDom, "xsign-in." + studioDom, "sign-inx." + studioDom, "sign-in-." + studioDom,
		"sign-in." + refA + "." + studioDom, "sign-in." + dhostA, signInH + ".", signInH + ":x", signInH + ":",
		"sign-in", "sign_in." + studioDom, "signin." + studioDom, "[" + signInH + "]",
		studioDom + ".", strings.ToUpper(studioDom), "x" + studioDom, studioDom + ":x", "[::1]", "[::1]:443", "[::ffff:192.0.2.1]",
	} {
		e.resetSeams()
		w := e.do(rawReq("GET", h, "/"))
		if f, a := e.seams(); w.Code != 404 || f+a != 0 || w.Header().Get("Location") != "" {
			t.Errorf("host %q: %d, forward %d, auth %d, Location %q", h, w.Code, f, a, w.Header().Get("Location"))
		}
	}
}

// TestDashHeaders_TransportSecurityOnEveryStudioHost: every answer of the
// studio domain, the sign-in host and a dashboard host carries exactly
// max-age=31536000; no project-API answer carries it.
func TestDashHeaders_TransportSecurityOnEveryStudioHost(t *testing.T) {
	const want = "max-age=31536000"
	e := newDashEnv(t, active(), false)
	check := func(name string, r *http.Request, status int) {
		t.Helper()
		w := e.do(r)
		if w.Code != status {
			t.Errorf("%s: status %d, want %d", name, w.Code, status)
		}
		if v := w.Header().Values("Strict-Transport-Security"); len(v) != 1 || v[0] != want {
			t.Errorf("%s: Strict-Transport-Security %q", name, v)
		}
	}
	sni := func(r *http.Request, name string) *http.Request {
		r.TLS = &tls.ConnectionState{ServerName: name}
		return r
	}
	owner := func(m, target string) *http.Request { return e.as(t, rawReq(m, dhostA, target), refA, subOwnerA) }

	check("studio domain 302, no table", rawReq("GET", studioDom, "/"), 302)
	check("sign-in host 503, no table", rawReq("GET", signInH, "/"), 503)
	check("dashboard host 503, no table", owner("GET", "/"), 503)

	writeDashFile(t, e.path(), dfile(1))
	if err := e.d.table.Reload(); err != nil {
		t.Fatal(err)
	}
	check("studio domain 302", rawReq("HEAD", studioDom, "/"), 302)
	check("studio domain 404", rawReq("GET", studioDom, "/x"), 404)
	check("studio domain 421", sni(rawReq("GET", studioDom, "/"), signInH), 421)
	check("sign-in host 400", rawReq("GET", signInH, "/a//b"), 400)
	check("sign-in host 421", sni(rawReq("GET", signInH, "/"), studioDom), 421)
	check("dashboard host 404 label", rawReq("GET", "cccccccccccccccccccc."+studioDom, "/"), 404)
	check("dashboard host 400", owner("GET", "/a//b"), 400)
	check("dashboard host 421", sni(owner("GET", "/"), dhostB), 421)
	check("dashboard host 404 rule 2", owner("GET", "/x/"+refB), 404)
	check("dashboard host 404 rule 3", owner("GET", "/api/mcp"), 404)
	nav := rawReq("GET", dhostA, "/x")
	nav.Header.Set("Sec-Fetch-Mode", "navigate")
	check("dashboard host 302 rule 5", nav, 302)
	check("dashboard host 401 rule 5", rawReq("GET", dhostA, "/api/x"), 401)
	check("dashboard host 403 rule 6", e.as(t, rawReq("GET", dhostA, "/"), refA, subOwnerB), 403)
	check("dashboard host 403 rule 8", e.as(t, rawReq("POST", dhostA, "/x"), refA, subROA), 403)
	big := owner("POST", "/x")
	big.ContentLength = 3 << 20
	check("dashboard host 413 rule 10", big, 413)
	e.d.mu.Lock()
	e.d.byRef[refA] = e.d.projects
	e.d.mu.Unlock()
	check("dashboard host 429", owner("GET", "/"), 429)
	e.d.mu.Lock()
	delete(e.d.byRef, refA)
	e.d.mu.Unlock()
	for i := 0; i < cap(e.d.slots); i++ {
		e.d.slots <- struct{}{}
	}
	check("dashboard host 503 slots", owner("GET", "/"), 503)
	for len(e.d.slots) > 0 {
		<-e.d.slots
	}
	dashForward, dashAuth = nil, nil
	check("dashboard host 503 no forwarder", owner("GET", "/"), 503)
	check("sign-in host 503 no sign-in", rawReq("GET", signInH, "/"), 503)

	// Never on the project API, nor on an unknown host.
	for name, r := range map[string]*http.Request{
		"project 401":     req("GET", hostA, "/rest/v1/x", nil),
		"project health":  req("GET", hostA, "/-/health", nil),
		"unknown host":    req("GET", "evil.example", "/", nil),
		"trailing dot":    req("GET", studioDom+".", "/", nil),
		"project via sni": sni(req("GET", hostA, "/rest/v1/x", nil), dhostA),
	} {
		if v := e.do(r).Header().Values("Strict-Transport-Security"); len(v) != 0 {
			t.Errorf("%s: Strict-Transport-Security %q", name, v)
		}
	}
}

// TestDashRefusals_SignInHostCountedUnderItsOwnKey: rule-0 refusals on the
// sign-in host are counted under "_", a dashboard host's under its ref; the
// studio domain counts nothing.
func TestDashRefusals_SignInHostCountedUnderItsOwnKey(t *testing.T) {
	e := newDashEnv(t, active(), true)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(io.Discard) })
	for i := 0; i < 3; i++ {
		e.do(rawReq("GET", signInH, "/a/../b"))
	}
	for i := 0; i < 5; i++ {
		e.do(rawReq("GET", studioDom, "/a/../b"))
		e.do(rawReq("GET", studioDom, "/x"))
	}
	e.do(e.as(t, rawReq("GET", dhostA, "/a//b"), refA, subOwnerA))
	e.d.mu.Lock()
	keys := make([]string, 0, len(e.d.refused))
	for k := range e.d.refused {
		keys = append(keys, k)
	}
	e.d.mu.Unlock()
	if len(keys) != 2 {
		t.Errorf("counted under %q, want only _ and %s", keys, refA)
	}
	e.d.logRefusals()
	got := buf.String()
	for _, want := range []string{"ref _: rule0 3 rule2 0 rule3 0 rule4 0", "ref " + refA + ": rule0 1 "} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in %q", want, got)
		}
	}
	if strings.Contains(got, studioDom) || strings.Contains(got, "sign-in") {
		t.Errorf("a host name used as a key: %q", got)
	}
}
