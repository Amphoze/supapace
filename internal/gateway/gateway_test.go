package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/routes"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

const (
	refA   = "aaaaaaaaaaaaaaaaaaa1"
	refB   = "bbbbbbbbbbbbbbbbbbb2"
	hostA  = refA + ".sp.test"
	restA  = "http://10.212.0.16:3000"
	restB  = "http://10.212.0.17:3000"
	upA    = "10.212.0.16:3000"
	peerIP = "192.0.2.10"
)

type signer struct {
	priv *rsa.PrivateKey
	kid  string
}

func (s signer) jwk(class string) routes.Key {
	return routes.Key{KID: s.kid, Class: class, Kty: "RSA",
		N: base64.RawURLEncoding.EncodeToString(s.priv.N.Bytes()), E: "AQAB"}
}

// token signs a token for role that expires in five minutes.
func (s signer) token(t *testing.T, role string) string {
	t.Helper()
	tok, err := jwtx.Sign(s.priv, s.kid, map[string]any{"role": role, "exp": time.Now().Unix() + 300})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type keyset struct{ anon, svc, iss signer }

var (
	fxOnce     sync.Once
	fxA, fxB   keyset
	fxStranger signer
)

func newSigner() signer {
	priv, kid, err := jwtx.GenerateKey()
	if err != nil {
		panic(err)
	}
	return signer{priv, kid}
}

// keys returns the projects' keys, generated once per test run.
func keys() (a, b keyset, stranger signer) {
	fxOnce.Do(func() {
		fxA = keyset{newSigner(), newSigner(), newSigner()}
		fxB = keyset{newSigner(), newSigner(), newSigner()}
		fxStranger = newSigner()
	})
	return fxA, fxB, fxStranger
}

func routeOf(p keyset, rest, state string) routes.Project {
	return routes.Project{State: state, Rest: rest, UserRoles: []string{"authenticated"},
		Keys: []routes.Key{p.anon.jwk("anon"), p.svc.jwk("service_role"), p.iss.jwk("issuer")}}
}

func file(gen int64, stateA string) routes.File {
	a, b, _ := keys()
	return routes.File{Generation: gen, Domain: "sp.test", Projects: map[string]routes.Project{
		refA: routeOf(a, restA, stateA), refB: routeOf(b, restB, "active")}}
}

func writeFile(t *testing.T, path string, f routes.File) {
	t.Helper()
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, path, b)
}

// writeRaw replaces path atomically and moves its mtime forward, so a reload
// sees a change even on a coarse clock.
func writeRaw(t *testing.T, path string, b []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o444); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(time.Duration(len(b)%7+1) * time.Second)
	if fi, err := os.Stat(path); err == nil && !mt.After(fi.ModTime()) {
		mt = fi.ModTime().Add(time.Second)
	}
	if err := os.Chtimes(tmp, mt, mt); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

type seen struct {
	Method, Path, RawPath, RawQuery, Host string
	Header                                http.Header
	Body                                  []byte
}

type env struct {
	gw   *Gateway
	path string

	mu     sync.Mutex
	got    []seen
	dialed []string
}

// newEnv serves f through a gateway whose upstream connections all land on
// an echo server that records each request it receives in full.
func newEnv(t *testing.T, f *routes.File) *env {
	t.Helper()
	e := &env{path: filepath.Join(t.TempDir(), "routes.json")}
	if f != nil {
		writeFile(t, e.path, *f)
	}
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d := r.Header.Get("X-Test-Sleep"); d != "" {
			time.Sleep(time.Second)
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		e.mu.Lock()
		e.got = append(e.got, seen{r.Method, r.URL.Path, r.URL.RawPath, r.URL.RawQuery, r.Host, r.Header.Clone(), b})
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(echo.Close)
	tbl := NewTable(e.path)
	err := tbl.Reload()
	if f != nil && err != nil {
		t.Fatal(err)
	}
	e.gw = New(tbl)
	e.gw.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		e.mu.Lock()
		e.dialed = append(e.dialed, addr)
		e.mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echo.Listener.Addr().String())
	}
	return e
}

func (e *env) requests() []seen {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]seen(nil), e.got...)
}

func (e *env) reset() {
	e.mu.Lock()
	e.got, e.dialed = nil, nil
	e.mu.Unlock()
}

// req builds a request as the server hands it over: origin-form target, the
// given Host, a fixed peer address.
func req(method, host, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.Host = host
	r.RemoteAddr = peerIP + ":4321"
	return r
}

func withKey(r *http.Request, apikey string) *http.Request {
	r.Header.Set("apikey", apikey)
	return r
}

func (e *env) do(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.gw.ServeHTTP(w, r)
	return w
}

// expect checks status and, when code is set, the JSON error code; a refusal
// must not have reached any upstream.
func (e *env) expect(t *testing.T, name string, r *http.Request, status int, code string) {
	t.Helper()
	e.reset()
	w := e.do(r)
	if w.Code != status {
		t.Errorf("%s: status %d, want %d (body %s)", name, w.Code, status, w.Body)
		return
	}
	if code != "" {
		var b struct{ Code string }
		if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || b.Code != code {
			t.Errorf("%s: body %s, want code %q", name, w.Body, code)
		}
		if h := w.Header(); h.Get("Content-Security-Policy") != "sandbox" || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: refusal without the sandbox headers: %v", name, h)
		}
	}
	if status != http.StatusOK && len(e.requests()) != 0 {
		t.Errorf("%s: refused request reached the upstream", name)
	}
	if status == http.StatusOK && len(e.requests()) != 1 {
		t.Errorf("%s: upstream saw %d requests, want 1", name, len(e.requests()))
	}
}

func (e *env) last(t *testing.T) seen {
	t.Helper()
	g := e.requests()
	if len(g) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(g))
	}
	return g[0]
}

func active() *routes.File { f := file(1, "active"); return &f }

func TestResolve_HostShapes(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	for _, c := range []struct {
		host   string
		status int
	}{
		{hostA, 200},
		{hostA + ":443", 200},
		{hostA + ":8443", 200},
		{strings.ToUpper(hostA), 404},
		{refA + ".SP.test", 404},
		{hostA + ".", 404},
		{hostA + ".:443", 404},
		{hostA + ":", 404},
		{hostA + ":x", 404},
		{refA + ".other.test", 404},
		{refA + ".sp.test.other.test", 404},
		{"x." + hostA, 404},
		{refA[:19] + ".sp.test", 404},
		{refA + "a.sp.test", 404},
		{"cccccccccccccccccccc.sp.test", 404},
		{"sp.test", 404},
		{"", 404},
		{"10.212.8.2", 404},
	} {
		e.expect(t, "host "+c.host, withKey(req("GET", c.host, "/rest/v1/", nil), anon), c.status, map[int]string{404: "not_found"}[c.status])
		if c.status == 200 && e.last(t).Host != upA {
			t.Errorf("host %s: upstream Host %q", c.host, e.last(t).Host)
		}
	}
	// The project resolved from the host is the one whose upstream is dialled.
	e.reset()
	_, b, _ := keys()
	e.expect(t, "project B", withKey(req("GET", refB+".sp.test", "/rest/v1/", nil), b.anon.token(t, "anon")), 200, "")
	if e.dialed[0] != "10.212.0.17:3000" {
		t.Errorf("project B dialled %q", e.dialed[0])
	}
}

func TestResolve_SNIMismatch421(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	tlsReq := func(sni string) *http.Request {
		r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
		r.TLS = &tls.ConnectionState{HandshakeComplete: true, ServerName: sni}
		return r
	}
	e.expect(t, "same host", tlsReq(hostA), 200, "")
	e.expect(t, "no SNI", tlsReq(""), 200, "")
	e.expect(t, "other project", tlsReq(refB+".sp.test"), 421, "misdirected")
	e.expect(t, "other domain", tlsReq(refA+".other.test"), 421, "misdirected")

	// End to end over TLS, HTTP/2 and HTTP/1.1, through the server's own config.
	addr := e.serve(t, true, nil)
	for _, h2 := range []bool{true, false} {
		for _, c := range []struct {
			sni    string
			status int
		}{{hostA, 200}, {refB + ".sp.test", 421}} {
			tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: c.sni, InsecureSkipVerify: true}, ForceAttemptHTTP2: h2}
			if !h2 {
				tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
			}
			r, _ := http.NewRequest("GET", "https://"+addr+"/rest/v1/", nil)
			r.Host = hostA
			r.Header.Set("apikey", anon)
			resp, err := (&http.Client{Transport: tr}).Do(r)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			tr.CloseIdleConnections()
			if resp.StatusCode != c.status || (resp.ProtoMajor == 2) != h2 {
				t.Errorf("TLS sni %q h2 %v: status %d proto %s, want %d", c.sni, h2, resp.StatusCode, resp.Proto, c.status)
			}
		}
	}
}

func TestUpgradeRejected400(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	r := withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon"))
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	e.expect(t, "websocket", r, 400, "upgrade_not_supported")
	r = withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon"))
	r.Header.Set("Upgrade", "h2c")
	e.expect(t, "upgrade without connection", r, 400, "upgrade_not_supported")
	e.expect(t, "connect", withKey(req("CONNECT", hostA, "/rest/v1/", nil), a.anon.token(t, "anon")), 400, "")
}

func TestAuth_NoAPIKey(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	r := req("GET", hostA, "/rest/v1/", nil)
	r.Header.Set("Authorization", "Bearer "+a.iss.token(t, "authenticated"))
	e.expect(t, "bearer only", r, 401, "no_apikey")
	e.expect(t, "nothing", req("GET", hostA, "/rest/v1/", nil), 401, "no_apikey")
	e.expect(t, "other parameter", req("GET", hostA, "/rest/v1/?apikeyx=1", nil), 401, "no_apikey")
}

func TestAuth_HeaderQueryDisagree(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon, svc := a.anon.token(t, "anon"), a.svc.token(t, "service_role")
	e.expect(t, "header anon, query service", withKey(req("GET", hostA, "/rest/v1/?apikey="+svc, nil), anon), 401, "invalid_apikey")
	e.expect(t, "header service, query anon", withKey(req("GET", hostA, "/rest/v1/?apikey="+anon, nil), svc), 401, "invalid_apikey")
	e.expect(t, "same key in both", withKey(req("GET", hostA, "/rest/v1/?apikey="+anon, nil), anon), 200, "")
	e.expect(t, "query only", req("GET", hostA, "/rest/v1/?apikey="+anon, nil), 200, "")
	e.expect(t, "semicolon separator", withKey(req("GET", hostA, "/rest/v1/?a=1;apikey="+svc, nil), anon), 400, "bad_request")
}

func TestAuth_DuplicateHeaders(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon, svc := a.anon.token(t, "anon"), a.svc.token(t, "service_role")
	user := a.iss.token(t, "authenticated")

	r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Add("apikey", anon)
	e.expect(t, "two equal apikey headers", r, 401, "invalid_apikey")
	r = withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Add("apikey", svc)
	e.expect(t, "two apikey headers", r, 401, "invalid_apikey")
	r = withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header["APIKEY"] = []string{svc}
	e.expect(t, "case-variant apikey header", r, 401, "invalid_apikey")
	e.expect(t, "two apikey parameters", req("GET", hostA, "/rest/v1/?apikey="+anon+"&apikey="+anon, nil), 401, "invalid_apikey")
	e.expect(t, "encoded parameter name", req("GET", hostA, "/rest/v1/?apikey="+anon+"&api%6Bey="+svc, nil), 401, "invalid_apikey")

	r = withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Add("Authorization", "Bearer "+user)
	r.Header.Add("Authorization", "Bearer "+user)
	e.expect(t, "two Authorization headers", r, 401, "invalid_token")
	r = withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("Authorization", "Bearer "+user+", Bearer "+svc)
	e.expect(t, "two bearers in one header", r, 401, "invalid_token")
	r = withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("Authorization", "Basic "+user)
	e.expect(t, "not a bearer", r, 401, "invalid_token")
	r = withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("Authorization", "Bearer "+user)
	e.expect(t, "control", r, 200, "")
}

func TestAuth_APIKeyMustBePlatformClass(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	user := a.iss.token(t, "authenticated")
	e.expect(t, "issuer token as apikey", withKey(req("GET", hostA, "/rest/v1/", nil), user), 401, "invalid_apikey")
	e.expect(t, "issuer token as query apikey", req("GET", hostA, "/rest/v1/?apikey="+user, nil), 401, "invalid_apikey")
	e.expect(t, "anon", withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon")), 200, "")
	e.expect(t, "service_role", withKey(req("GET", hostA, "/rest/v1/", nil), a.svc.token(t, "service_role")), 200, "")
}

// TestAuth_RoleBoundToKeyClass fails when a verified token is accepted
// without its role being bound to the class of the key that signed it.
func TestAuth_RoleBoundToKeyClass(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	e.expect(t, "anon key, role service_role", withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "service_role")), 401, "invalid_apikey")
	e.expect(t, "service key, role anon", withKey(req("GET", hostA, "/rest/v1/", nil), a.svc.token(t, "anon")), 401, "invalid_apikey")
	for _, c := range []struct {
		name string
		tok  string
	}{
		{"bearer: anon key, role service_role", a.anon.token(t, "service_role")},
		{"bearer: service key, role authenticated", a.svc.token(t, "authenticated")},
		{"bearer: issuer key, role service_role", a.iss.token(t, "service_role")},
		{"bearer: issuer key, role postgres", a.iss.token(t, "postgres")},
		{"bearer: issuer key, role not listed", a.iss.token(t, "editor")},
	} {
		r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
		r.Header.Set("Authorization", "Bearer "+c.tok)
		e.expect(t, c.name, r, 401, "invalid_token")
	}
}

func TestAuth_APIKeyOfOtherProject(t *testing.T) {
	a, b, stranger := keys()
	e := newEnv(t, active())
	user := a.iss.token(t, "authenticated")
	for _, c := range []struct{ name, key string }{
		{"B anon", b.anon.token(t, "anon")}, {"B service", b.svc.token(t, "service_role")},
		{"unknown kid", stranger.token(t, "anon")},
	} {
		r := withKey(req("GET", hostA, "/rest/v1/", nil), c.key)
		r.Header.Set("Authorization", "Bearer "+user)
		e.expect(t, c.name, r, 401, "invalid_apikey")
	}
	r := withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon"))
	r.Header.Set("Authorization", "Bearer "+b.iss.token(t, "authenticated"))
	e.expect(t, "bearer of B", r, 401, "invalid_token")
	r = withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon"))
	r.Header.Set("Authorization", "Bearer "+user)
	e.expect(t, "control", r, 200, "")
}

func TestAuth_BearerDefaultsToAPIKey(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	e.expect(t, "header", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 200, "")
	if got := e.last(t).Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+anon {
		t.Errorf("Authorization %q", got)
	}
	e.expect(t, "query", req("GET", hostA, "/rest/v1/?apikey="+anon, nil), 200, "")
	if got := e.last(t).Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+anon {
		t.Errorf("Authorization %q", got)
	}
}

func TestForward_ExactlyOneAuthorization(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon, user := a.anon.token(t, "anon"), a.iss.token(t, "authenticated")
	r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("authorization", "bearer "+user)
	e.expect(t, "bearer", r, 200, "")
	h := e.last(t).Header
	n := 0
	for k, v := range h {
		if strings.EqualFold(k, "Authorization") {
			n += len(v)
		}
	}
	if n != 1 || h.Get("Authorization") != "Bearer "+user {
		t.Errorf("upstream Authorization %q (%d values)", h.Values("Authorization"), n)
	}
}

func TestForward_StripsAndSetsHeaders(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	for k, v := range map[string]string{
		"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Host": "evil.test", "X-Forwarded-Proto": "http",
		"X-Forwarded-Port": "1", "X-Forwarded-Prefix": "/x", "Forwarded": "for=203.0.113.9",
		"X-Connection-Encrypted": "true", "X-Pg-Application-Name": "spoof", "Accept-Profile": "public",
		"X-Real-Ip": "203.0.113.9", "True-Client-Ip": "203.0.113.9",
	} {
		r.Header.Set(k, v)
	}
	e.expect(t, "headers", r, 200, "")
	got := e.last(t)
	want := map[string]string{
		"Authorization": "Bearer " + anon, "X-Forwarded-Host": hostA, "X-Forwarded-Proto": "https",
		"X-Forwarded-For": peerIP, "X-Pg-Application-Name": "supapace-gateway", "Accept-Profile": "public",
	}
	for k, v := range want {
		if vs := got.Header.Values(k); len(vs) != 1 || vs[0] != v {
			t.Errorf("upstream %s = %q, want %q", k, vs, v)
		}
	}
	if got.Host != upA {
		t.Errorf("upstream Host %q", got.Host)
	}
	for _, k := range []string{"Apikey", "X-Connection-Encrypted", "Forwarded", "X-Forwarded-Port", "X-Forwarded-Prefix", "X-Real-Ip", "True-Client-Ip"} {
		if v := got.Header.Values(k); len(v) != 0 {
			t.Errorf("upstream still has %s: %q", k, v)
		}
	}
}

func TestForward_StripsAPIKeyQuery(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	for _, c := range []struct{ query, want string }{
		{"select=*&apikey=" + anon + "&id=eq.1", "select=*&id=eq.1"},
		{"apikey=" + anon, ""},
		{"api%6Bey=" + anon + "&order=id.desc", "order=id.desc"},
		{"name=eq.a%20b&apikey=" + anon, "name=eq.a%20b"},
	} {
		e.expect(t, c.query, req("GET", hostA, "/rest/v1/items?"+c.query, nil), 200, "")
		if got := e.last(t); got.RawQuery != c.want || got.Path != "/items" {
			t.Errorf("%s: upstream %s?%s, want /items?%s", c.query, got.Path, got.RawQuery, c.want)
		}
	}
}

func TestForward_ConnectionHeaderCannotStrip(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon, user := a.anon.token(t, "anon"), a.iss.token(t, "authenticated")
	r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("Authorization", "Bearer "+user)
	r.Header.Set("Connection", "Authorization, X-Forwarded-Host, X-Forwarded-For, X-Forwarded-Proto, X-Pg-Application-Name")
	e.expect(t, "connection", r, 200, "")
	h := e.last(t).Header
	for k, v := range map[string]string{"Authorization": "Bearer " + user, "X-Forwarded-Host": hostA,
		"X-Forwarded-For": peerIP, "X-Forwarded-Proto": "https", "X-Pg-Application-Name": "supapace-gateway"} {
		if h.Get(k) != v {
			t.Errorf("upstream %s = %q, want %q", k, h.Get(k), v)
		}
	}
	// The Content-Profile the GraphQL route sets survives as well.
	r = withKey(req("POST", hostA, "/graphql/v1", strings.NewReader(`{}`)), anon)
	r.Header.Set("Connection", "Content-Profile")
	e.expect(t, "graphql", r, 200, "")
	if got := e.last(t).Header.Get("Content-Profile"); got != "graphql_public" {
		t.Errorf("Content-Profile %q", got)
	}
}

func TestRoute_GraphQLRewrite(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	r := withKey(req("POST", hostA, "/graphql/v1", strings.NewReader(`{"query":"{x}"}`)), anon)
	r.Header.Set("Content-Profile", "public")
	e.expect(t, "graphql", r, 200, "")
	got := e.last(t)
	if got.Method != "POST" || got.Path != "/rpc/graphql" || got.Header.Values("Content-Profile")[0] != "graphql_public" ||
		len(got.Header.Values("Content-Profile")) != 1 || string(got.Body) != `{"query":"{x}"}` {
		t.Errorf("upstream %s %s profile %q body %q", got.Method, got.Path, got.Header.Values("Content-Profile"), got.Body)
	}
	e.expect(t, "rest", withKey(req("GET", hostA, "/rest/v1/a%2Fb/c", nil), anon), 200, "")
	if got := e.last(t); got.Path != "/a/b/c" || got.RawPath != "/a%2Fb/c" {
		t.Errorf("rest path %q raw %q", got.Path, got.RawPath)
	}
}

func TestRoute_Unknown404(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	for _, m := range [][2]string{
		{"GET", "/graphql/v1"}, {"POST", "/graphql/v1/"}, {"GET", "/auth/v1/user"}, {"GET", "/rest/v1"},
		{"GET", "/rest/v2/"}, {"GET", "/"}, {"GET", "/rest%2Fv1/"}, {"GET", "/storage/v1/object"},
	} {
		e.expect(t, m[0]+" "+m[1], withKey(req(m[0], hostA, m[1], nil), anon), 404, "not_found")
	}
}

func TestDraining_503(t *testing.T) {
	a, _, _ := keys()
	f := file(1, "draining")
	e := newEnv(t, &f)
	w := e.do(withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon")))
	if w.Code != 503 || w.Header().Get("Retry-After") != "5" || strings.TrimSpace(w.Body.String()) != `{"code":"project_restarting"}` {
		t.Errorf("draining: %d %q %s", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
	if len(e.dialed) != 0 {
		t.Error("draining project dialled")
	}
}

func TestTable_ReloadsOnChange(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.gw.table.Watch(ctx, 10*time.Millisecond)

	// Requests run while the table is swapped underneath them.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				w := httptest.NewRecorder()
				e.gw.ServeHTTP(w, withKey(req("GET", hostA, "/rest/v1/", nil), anon))
				if w.Code != 200 && w.Code != 503 {
					t.Errorf("during reload: %d", w.Code)
					return
				}
			}
		}
	}()
	f := file(2, "draining")
	writeFile(t, e.path, f)
	waitGen(t, e, 2)
	if w := e.do(withKey(req("GET", hostA, "/rest/v1/", nil), anon)); w.Code != 503 {
		t.Errorf("after reload to draining: %d", w.Code)
	}
	f = file(3, "active")
	writeFile(t, e.path, f)
	waitGen(t, e, 3)
	close(stop)
	wg.Wait()
	e.expect(t, "active again", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 200, "")
}

func waitGen(t *testing.T, e *env, gen int64) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if e.gw.table.Generation() == gen {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("generation %d not reached (have %d)", gen, e.gw.table.Generation())
}

func TestTable_KeepsLastGoodOnBadFile(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	good, _ := file(2, "active").Marshal()
	for _, bad := range [][]byte{
		good[:len(good)/2],             // half written
		[]byte(""),                     // empty
		[]byte(`{"generation":5}`),     // no domain
		append(good, []byte(" {}")...), // trailing data
		bytes.Replace(good, []byte(restA), []byte("http://10.212.0.16:80"), 1), // fails validation
	} {
		writeRaw(t, e.path, bad)
		if err := e.gw.table.Reload(); err == nil {
			t.Errorf("bad file %.40q accepted", bad)
		}
		if g := e.gw.table.Generation(); g != 1 {
			t.Errorf("generation %d after bad file", g)
		}
		e.expect(t, "served from last good", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 200, "")
	}
	if err := os.Remove(e.path); err != nil {
		t.Fatal(err)
	}
	if err := e.gw.table.Reload(); err == nil {
		t.Error("missing file: no error")
	}
	e.expect(t, "file removed", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 200, "")
	writeRaw(t, e.path, good)
	if err := e.gw.table.Reload(); err != nil || e.gw.table.Generation() != 2 {
		t.Errorf("good file after bad ones: %v, generation %d", err, e.gw.table.Generation())
	}
}

func TestTable_RejectsOversizeKey(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	big := make([]byte, 4096/8+1) // a 4097-bit odd modulus
	big[0], big[len(big)-1] = 1, 1
	for name, k := range map[string]routes.Key{
		"oversize": {KID: "big", Class: "issuer", Kty: "RSA", N: base64.RawURLEncoding.EncodeToString(big), E: "AQAB"},
		"small":    {KID: "small", Class: "issuer", Kty: "RSA", N: base64.RawURLEncoding.EncodeToString(big[:128]), E: "AQAB"},
		"exponent": {KID: "exp", Class: "issuer", Kty: "RSA", N: a.iss.jwk("issuer").N, E: "Aw"},
	} {
		f := file(2, "active")
		p := f.Projects[refB]
		p.Keys = append(p.Keys, k)
		f.Projects[refB] = p
		writeFile(t, e.path, f)
		if err := e.gw.table.Reload(); err == nil {
			t.Errorf("%s key accepted", name)
		}
		if g := e.gw.table.Generation(); g != 1 {
			t.Errorf("%s: generation %d, want the last good 1", name, g)
		}
	}
	e.expect(t, "last good still served", withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon")), 200, "")
}

func TestTable_EmptyAtStartServes503(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, nil)
	r := withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon"))
	w := e.do(r)
	if w.Code != 503 || w.Header().Get("Retry-After") != "5" || strings.TrimSpace(w.Body.String()) != `{"code":"unavailable"}` {
		t.Errorf("empty table: %d %s", w.Code, w.Body)
	}
	if len(e.dialed) != 0 {
		t.Error("empty table dialled an upstream")
	}
	// A bad first file leaves the table empty.
	writeRaw(t, e.path, []byte("{"))
	if err := e.gw.table.Reload(); err == nil {
		t.Error("bad first file accepted")
	}
	if w := e.do(withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon"))); w.Code != 503 {
		t.Errorf("bad first file: %d", w.Code)
	}
	// A valid table without the project is a 404, not a wrong upstream.
	f := file(1, "active")
	delete(f.Projects, refA)
	writeFile(t, e.path, f)
	if err := e.gw.table.Reload(); err != nil {
		t.Fatal(err)
	}
	e.expect(t, "unknown project", withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon")), 404, "not_found")
}

func TestHealth_ReportsGenerationWithoutAuth(t *testing.T) {
	e := newEnv(t, nil)
	for _, want := range []int64{0, 7} {
		if want != 0 {
			writeFile(t, e.path, file(want, "draining"))
			if err := e.gw.table.Reload(); err != nil {
				t.Fatal(err)
			}
		}
		for _, host := range []string{"", "anything.test", hostA} {
			w := e.do(req("GET", host, "/-/health", nil))
			if w.Code != 200 || strings.TrimSpace(w.Body.String()) != fmt.Sprintf(`{"generation":%d}`, want) {
				t.Errorf("health host %q: %d %s, want generation %d", host, w.Code, w.Body, want)
			}
			if w.Header().Get("Content-Security-Policy") != "sandbox" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("health host %q: no sandbox headers: %v", host, w.Header())
			}
		}
	}
	if len(e.requests()) != 0 {
		t.Error("health reached an upstream")
	}
}

func TestServer_Timeouts(t *testing.T) {
	s := NewServer(nil)
	if s.ReadHeaderTimeout != 10*time.Second || s.ReadTimeout != 60*time.Second || s.WriteTimeout != 60*time.Second ||
		s.IdleTimeout != 120*time.Second || s.MaxHeaderBytes != 32<<10 {
		t.Errorf("server limits %v %v %v %v %d", s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout, s.MaxHeaderBytes)
	}
	if s.TLSConfig == nil || s.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Error("TLS minimum is not 1.2")
	}
	if s.HTTP2 == nil || s.HTTP2.MaxConcurrentStreams != maxH2Streams || maxH2Streams != 8 || maxInformational != 8 {
		t.Error("HTTP/2 stream limit is not 8")
	}
	if s.HTTP2 == nil || maxH2StreamWindow != 128<<10 || maxH2ConnWindow != 128<<10 ||
		s.HTTP2.MaxReceiveBufferPerStream != maxH2StreamWindow || s.HTTP2.MaxReceiveBufferPerConnection != maxH2ConnWindow {
		t.Error("HTTP/2 receive windows are not 128 KiB")
	}
	if s.HTTP2 == nil || s.HTTP2.MaxReadFrameSize != maxH2Frame || maxH2Frame != 16<<10 || sockBuf != 32<<10 {
		t.Error("HTTP/2 frame size is not 16 KiB or socket buffers are not 32 KiB")
	}
	if MaxConns != 2048 || MaxConnsPerSource != 64 || maxBody != 8<<20 || maxInFlight != 2048 || cap(New(nil).inflight) != maxInFlight ||
		maxProjectInFlight != 128 || New(nil).projectCap != maxProjectInFlight {
		t.Errorf("caps %d %d %d %d %d", MaxConns, MaxConnsPerSource, maxBody, maxInFlight, maxProjectInFlight)
	}
	// The header cap is enforced: 70 KiB of header is refused before any upstream call.
	a, _, _ := keys()
	e := newEnv(t, active())
	addr := e.serve(t, false, nil)
	anon := a.anon.token(t, "anon")
	for _, c := range []struct {
		size int
		want string
	}{{16 << 10, " 200 "}, {40 << 10, " 431 "}} {
		e.reset()
		out := raw(t, addr, "GET /rest/v1/ HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+anon+"\r\nX-Pad: "+strings.Repeat("a", c.size)+"\r\nConnection: close\r\n\r\n")
		if !strings.Contains(firstLine(out), c.want) {
			t.Errorf("%d-byte header: %q", c.size, firstLine(out))
		}
		if n, want := len(e.requests()), map[string]int{" 200 ": 1}[c.want]; n != want {
			t.Errorf("%d-byte header: upstream saw %d requests, want %d", c.size, n, want)
		}
	}
}

func TestRedirect_ToHTTPS(t *testing.T) {
	w := httptest.NewRecorder()
	Redirect().ServeHTTP(w, req("POST", hostA+":80", "/rest/v1/items?id=eq.1", nil))
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "https://"+hostA+"/rest/v1/items?id=eq.1" {
		t.Errorf("redirect %d %q", w.Code, w.Header().Get("Location"))
	}
	if w.Header().Get("Content-Security-Policy") != "sandbox" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("redirect: no sandbox headers: %v", w.Header())
	}
}

func TestServer_SlowBodyCut(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	const readTimeout, size = 300 * time.Millisecond, 400
	addr := e.serve(t, false, func(s *http.Server) { s.ReadTimeout = readTimeout })
	head := "POST /rest/v1/rpc/whoami HTTP/1.1\r\nHost: " + hostA + "\r\napikey: " + a.anon.token(t, "anon") +
		"\r\nContent-Length: " + fmt.Sprint(size) + "\r\nConnection: close\r\n\r\n"

	if out := raw(t, addr, head+strings.Repeat("x", size)); !strings.Contains(firstLine(out), " 200 ") {
		t.Fatalf("control: %q", firstLine(out))
	}
	e.reset()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, head)
	// Trickle one byte at a time, far slower than the read timeout allows,
	// until the server closes the connection.
	var sent atomic.Int32
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for sent.Load() < size {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			if _, err := c.Write([]byte("x")); err != nil {
				return
			}
			sent.Add(1)
		}
	}()
	c.SetReadDeadline(time.Now().Add(30 * time.Second)) // a safety net, not the measurement
	// EOF or a reset both mean the server closed it; only our deadline does not.
	if _, err := io.Copy(io.Discard, c); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connection not closed by the server: %v", err)
	}
	if n := sent.Load(); n >= size {
		t.Errorf("server waited for the whole trickled body (%d bytes)", n)
	}
	if len(e.requests()) != 0 {
		t.Error("upstream received the trickled body")
	}
}

// dropUpstream points every upstream dial of e at a server that reads a
// request's header and n bytes of its body, then closes the connection, as a
// server guarding against slow senders does. It returns the count of
// connections it has closed.
func dropUpstream(t *testing.T, e *env, n int64) *atomic.Int32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	closed := new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer closed.Add(1)
				defer c.Close()
				if r, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
					io.CopyN(io.Discard, r.Body, n)
				}
			}()
		}
	}()
	e.gw.transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}
	return closed
}

// TestServer_StalledBodyNotBlamedOnUpstream: a client that sends its header
// and part of its body, then stalls, is cut when the read timeout fires, also
// when the upstream gave up on the body first: over HTTP/1.1 the connection
// closes with no response, over HTTP/2 the stream is reset; no 5xx, nothing
// logged as an upstream fault, slots returned, upstream connection closed.
func TestServer_StalledBodyNotBlamedOnUpstream(t *testing.T) {
	var buf syncBuf
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(io.Discard) })
	a, _, _ := keys()
	tok := a.anon.token(t, "anon")
	const timeout = 500 * time.Millisecond
	for _, mode := range []string{"plain", "tls", "h2"} {
		for _, drop := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/upstream_drops=%v", mode, drop), func(t *testing.T) {
				buf.Reset()
				e := newEnv(t, active())
				var closed *atomic.Int32
				if drop {
					closed = dropUpstream(t, e, 2)
				}
				addr := e.serve(t, mode != "plain", func(s *http.Server) { s.ReadTimeout, s.WriteTimeout = timeout, timeout })
				start := time.Now()
				// The body comes one byte per 100 ms, far slower than the read
				// timeout allows, as a slow sender's would.
				var send func() error
				result := make(chan string, 1)
				if mode == "h2" {
					h := h2open(t, addr)
					h.headers(1, [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", hostA},
						{":path", "/rest/v1/t"}, {"apikey", tok}, {"content-length", "1048576"}}, false, maxH2Frame)
					h.frame(0, 0, 1, []byte("xxxx"))
					send = func() error { return h.frame(0, 0, 1, []byte("x")) }
					go func() {
						if got := h.wait(t, 1, 5*time.Second); !strings.HasPrefix(got, "reset:") {
							result <- got + ", want a reset"
						}
						close(result)
					}()
				} else {
					var c net.Conn
					var err error
					if mode == "tls" {
						c, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: hostA})
					} else {
						c, err = net.Dial("tcp", addr)
					}
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					io.WriteString(c, "POST /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+tok+"\r\nContent-Length: 1048576\r\n\r\nxxxx")
					send = func() error { _, err := c.Write([]byte("x")); return err }
					c.SetReadDeadline(time.Now().Add(5 * time.Second))
					go func() {
						b, err := io.ReadAll(c)
						switch {
						case errors.Is(err, os.ErrDeadlineExceeded):
							result <- "connection not closed by the server"
						case len(b) != 0:
							result <- fmt.Sprintf("answered %q (%v), want the connection closed", firstLine(string(b)), err)
						}
						close(result)
					}()
				}
			feed:
				for {
					select {
					case msg, ok := <-result:
						if ok {
							t.Error("slow body: " + msg)
						}
						break feed
					case <-time.After(100 * time.Millisecond):
						send() // fails once the server has given up; the reader reports
					}
				}
				if d := time.Since(start); d < timeout || d > 3*time.Second {
					t.Errorf("cut after %v, want the read timeout", d)
				}
				eventually(t, func() bool { return idle(e) }, "slots not returned")
				if drop {
					eventually(t, func() bool { return closed.Load() == 1 }, "upstream connection not closed")
				}
				if s := buf.String(); strings.Contains(s, "upstream") {
					t.Errorf("logged as an upstream fault: %s", s)
				}
			})
		}
	}
}

// TestServer_UpstreamDropsMidBodyFastClient: when the upstream closes while a
// client that keeps sending is still uploading, the gateway reads the rest of
// the body and answers its 502, which the client then reads whole.
func TestServer_UpstreamDropsMidBodyFastClient(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	closed := dropUpstream(t, e, 2)
	addr := e.serve(t, false, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+a.anon.token(t, "anon")+"\r\nContent-Length: 100\r\n\r\nxxxx")
	eventually(t, func() bool { return closed.Load() == 1 }, "upstream did not close")
	io.WriteString(c, strings.Repeat("x", 96))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 502 || strings.TrimSpace(string(b)) != `{"code":"upstream_unavailable"}` {
		t.Errorf("got %d %s", resp.StatusCode, b)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
func (s *syncBuf) Reset()                      { s.mu.Lock(); defer s.mu.Unlock(); s.b.Reset() }

func TestServer_BodyLimit413(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	e.expect(t, "declared length over the cap", withKey(req("POST", hostA, "/rest/v1/t", bytes.NewReader(make([]byte, maxBody+1))), anon), 413, "body_too_large")
	if len(e.dialed) != 0 {
		t.Error("declared length over the cap: upstream dialled before refusing")
	}
	r := withKey(req("POST", hostA, "/rest/v1/t", io.MultiReader(bytes.NewReader(make([]byte, maxBody+1)))), anon)
	r.ContentLength = -1 // chunked: no declared length
	e.expect(t, "streamed body over the cap", r, 413, "body_too_large")
	e.expect(t, "1 MiB", withKey(req("POST", hostA, "/rest/v1/t", bytes.NewReader(make([]byte, 1<<20))), anon), 200, "")
	r = withKey(req("POST", hostA, "/rest/v1/t", io.MultiReader(bytes.NewReader(make([]byte, maxBody)))), anon)
	r.ContentLength = -1
	e.expect(t, "streamed body at the cap", r, 200, "")
}

// TestServer_BodyLimitExpectContinue: a client that asks before sending gets
// the 413 and no 100 Continue, so it never sends the body.
func TestServer_BodyLimitExpectContinue(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	addr := e.serve(t, false, nil)
	out := raw(t, addr, "POST /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+a.anon.token(t, "anon")+
		"\r\nExpect: 100-continue\r\nContent-Length: "+fmt.Sprint(maxBody+1)+"\r\n\r\n")
	if !strings.HasPrefix(out, "HTTP/1.1 413 ") || strings.Contains(out, " 100 ") || !strings.Contains(out, `{"code":"body_too_large"}`) {
		t.Errorf("got %q", out)
	}
}

// TestServer_RequestShapes covers the framing a front proxy must not pass on
// ambiguously: HTTP/1.0, absolute-form and authority-form targets, conflicting
// lengths and Transfer-Encoding beside Content-Length.
func TestServer_RequestShapes(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	addr := e.serve(t, false, nil)
	anon := a.anon.token(t, "anon")
	hdr := "Host: " + hostA + "\r\napikey: " + anon + "\r\n"
	for _, c := range []struct{ name, raw, want string }{
		{"HTTP/1.0", "GET /rest/v1/ HTTP/1.0\r\n" + hdr + "\r\n", " 505 "},
		{"absolute form", "GET http://" + hostA + "/rest/v1/ HTTP/1.1\r\n" + hdr + "Connection: close\r\n\r\n", " 400 "},
		{"absolute form, other host", "GET http://other.test/rest/v1/ HTTP/1.1\r\n" + hdr + "Connection: close\r\n\r\n", " 400 "},
		{"authority form", "CONNECT " + hostA + ":443 HTTP/1.1\r\n" + hdr + "Connection: close\r\n\r\n", " 400 "},
		{"conflicting lengths", "POST /rest/v1/t HTTP/1.1\r\n" + hdr + "Content-Length: 3\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd", " 400 "},
		{"unknown transfer coding", "POST /rest/v1/t HTTP/1.1\r\n" + hdr + "Transfer-Encoding: gzip\r\nConnection: close\r\n\r\n", " 501 "},
		{"two transfer codings", "POST /rest/v1/t HTTP/1.1\r\n" + hdr + "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n", " 501 "},
	} {
		e.reset()
		if out := raw(t, addr, c.raw); !strings.Contains(firstLine(out), c.want) {
			t.Errorf("%s: %q, want%s", c.name, firstLine(out), c.want)
		}
		if len(e.requests()) != 0 {
			t.Errorf("%s: reached the upstream", c.name)
		}
	}

	// Equal duplicate lengths are folded into one.
	e.reset()
	out := raw(t, addr, "POST /rest/v1/t HTTP/1.1\r\n"+hdr+"Content-Length: 4\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd")
	if got := e.requests(); !strings.Contains(firstLine(out), " 200 ") || len(got) != 1 || string(got[0].Body) != "abcd" {
		t.Errorf("equal lengths: %q", firstLine(out))
	}

	// Transfer-Encoding wins over Content-Length; what follows the last chunk
	// is a request of its own, authenticated on its own.
	e.reset()
	smuggled := "GET /rest/v1/smuggled HTTP/1.1\r\nHost: " + hostA + "\r\nConnection: close\r\n\r\n"
	body := "0\r\n\r\n" + smuggled
	out = raw(t, addr, "POST /rest/v1/t HTTP/1.1\r\n"+hdr+"Content-Length: "+fmt.Sprint(len(body))+"\r\nTransfer-Encoding: chunked\r\n\r\n"+body)
	got := e.requests()
	if len(got) != 1 || got[0].Path != "/t" || len(got[0].Body) != 0 || strings.Count(out, "HTTP/1.1 ") != 2 ||
		!strings.Contains(out, "HTTP/1.1 200 ") || !strings.Contains(out, "HTTP/1.1 401 ") {
		t.Errorf("TE with CL: upstream %d requests, client saw %q", len(got), out)
	}
}

func TestLimitListener_Caps(t *testing.T) {
	addr := limited(t, NewLimiter(2, 100))
	c1, c2 := hold(t, addr, ""), hold(t, addr, "")
	if !closedAtAccept(t, addr, "") {
		t.Error("third connection served over a total cap of 2")
	}
	for _, c := range []net.Conn{c1, c2} {
		if !served(c) {
			t.Error("connection under the cap no longer served")
		}
	}
	c1.Close()
	eventually(t, func() bool { return !closedAtAccept(t, addr, "") }, "slot not released after close")
}

func TestLimitListener_PerSource(t *testing.T) {
	addr := limited(t, NewLimiter(100, 1))
	c1 := hold(t, addr, "127.0.0.1")
	if !closedAtAccept(t, addr, "127.0.0.1") {
		t.Error("second connection from one source served over a per-source cap of 1")
	}
	c2 := hold(t, addr, "127.0.0.2")
	if !served(c1) || !served(c2) {
		t.Error("held connections not served")
	}
	c1.Close()
	eventually(t, func() bool { return !closedAtAccept(t, addr, "127.0.0.1") }, "source slot not released after close")
}

func TestTransport_ResponseHeaderTimeout(t *testing.T) {
	tr := newTransport()
	if tr.ResponseHeaderTimeout != 30*time.Second || tr.MaxConnsPerHost != maxProjectInFlight ||
		maxUpstreamHeader != 32<<10 || tr.MaxResponseHeaderBytes != maxUpstreamHeader || tr.MaxIdleConnsPerHost != 16 ||
		tr.Proxy != nil || dialer.Timeout != 5*time.Second {
		t.Errorf("transport %v %d %d proxy %v dial %v", tr.ResponseHeaderTimeout, tr.MaxConnsPerHost, tr.MaxIdleConnsPerHost, tr.Proxy != nil, dialer.Timeout)
	}
	a, _, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	e.gw.transport.ResponseHeaderTimeout = 100 * time.Millisecond
	r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("X-Test-Sleep", "1")
	start := time.Now()
	w := e.do(r)
	if w.Code != 504 || strings.TrimSpace(w.Body.String()) != `{"code":"upstream_timeout"}` || time.Since(start) > 900*time.Millisecond {
		t.Errorf("slow upstream: %d %s after %v", w.Code, w.Body, time.Since(start))
	}
	// An unreachable upstream: the client learns nothing about its address.
	e.gw.transport.DialContext = func(ctx context.Context, n, addr string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: n, Err: errors.New("connection refused")}
	}
	w = e.do(withKey(req("GET", hostA, "/rest/v1/", nil), anon))
	if w.Code != 502 || strings.TrimSpace(w.Body.String()) != `{"code":"upstream_unavailable"}` {
		t.Errorf("unreachable upstream: %d %s", w.Code, w.Body)
	}
}

// TestLog_NoTokens fails when anything the gateway logs carries a token.
func TestLog_NoTokens(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(io.Discard) })
	a, _, _ := keys()
	e := newEnv(t, active())
	anon, user := a.anon.token(t, "anon"), a.iss.token(t, "authenticated")
	e.gw.transport.DialContext = func(ctx context.Context, n, addr string) (net.Conn, error) {
		return nil, errors.New("refused")
	}
	r := withKey(req("GET", hostA, "/rest/v1/?apikey="+anon, nil), anon)
	r.Header.Set("Authorization", "Bearer "+user)
	e.do(r)
	r = withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("Authorization", "Bearer "+user+"x")
	e.do(r)
	writeRaw(t, e.path, []byte(`{"generation":2,"domain":"sp.test","projects":{"`+anon+`":{}}}`))
	e.gw.table.Reload()
	if buf.Len() == 0 {
		t.Fatal("nothing logged: the test exercises nothing")
	}
	for _, tok := range []string{anon, user, strings.Split(anon, ".")[2], strings.Split(user, ".")[1]} {
		if strings.Contains(buf.String(), tok) {
			t.Errorf("log carries a token: %s", buf.String())
		}
	}
}

// serve runs the gateway behind NewServer on a loopback listener.
func (e *env) serve(t *testing.T, withTLS bool, mod func(*http.Server)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(e.gw)
	s.ErrorLog = log.New(io.Discard, "", 0)
	if mod != nil {
		mod(s)
	}
	if withTLS {
		s.TLSConfig.Certificates = []tls.Certificate{testCert(t)}
		go s.ServeTLS(ln, "", "")
	} else {
		go s.Serve(ln)
	}
	t.Cleanup(func() { s.Close() })
	return ln.Addr().String()
}

// testCert is a self-signed certificate for *.sp.test, made per run.
func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"*.sp.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// raw writes s on a new connection and returns everything read until the
// server closes it (or two seconds pass).
func raw(t *testing.T, addr, s string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, s)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

func firstLine(s string) string { l, _, _ := strings.Cut(s, "\r\n"); return l }

func limited(t *testing.T, l *Limiter) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	go s.Serve(l.Listen(ln))
	t.Cleanup(func() { s.Close() })
	return ln.Addr().String()
}

func dialFrom(t *testing.T, addr, src string) net.Conn {
	t.Helper()
	d := net.Dialer{}
	if src != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(src)}
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// served sends one request on c and reports whether a response came back.
func served(c net.Conn) bool {
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: x.test\r\n\r\n"); err != nil {
		return false
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// hold opens a connection that has completed one request and stays open.
func hold(t *testing.T, addr, src string) net.Conn {
	t.Helper()
	c := dialFrom(t, addr, src)
	t.Cleanup(func() { c.Close() })
	if !served(c) {
		t.Fatal("connection under the cap not served")
	}
	return c
}

func closedAtAccept(t *testing.T, addr, src string) bool {
	t.Helper()
	c := dialFrom(t, addr, src)
	defer c.Close()
	return !served(c)
}

func eventually(t *testing.T, f func() bool, msg string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error(msg)
}

const hostB = refB + ".sp.test"

// TestAuth_CrossTenantMatrix tries every pairing of host, SNI, apikey and
// bearer drawn from two projects. A request is forwarded only when every
// credential belongs to the host's project, the apikey is platform-class and
// the SNI is absent or names the host; then it goes to the host's upstream
// with the expected Authorization.
func TestAuth_CrossTenantMatrix(t *testing.T) {
	a, b, _ := keys()
	e := newEnv(t, active())
	e.gw.transport.DisableKeepAlives = true // every request dials, so the dial shows the upstream
	type cred struct {
		name, tok, proj string
		platform        bool
	}
	apikeys := []cred{
		{"A.anon", a.anon.token(t, "anon"), "A", true}, {"A.svc", a.svc.token(t, "service_role"), "A", true},
		{"B.anon", b.anon.token(t, "anon"), "B", true}, {"B.svc", b.svc.token(t, "service_role"), "B", true},
		{"A.iss", a.iss.token(t, "authenticated"), "A", false}, {"B.iss", b.iss.token(t, "authenticated"), "B", false},
	}
	bearers := append([]cred{{"none", "", "", true}}, apikeys...)
	hosts := map[string]string{"A": hostA, "B": hostB}
	ups := map[string]string{"A": upA, "B": "10.212.0.17:3000"}
	for _, hp := range []string{"A", "B"} {
		for _, sni := range []string{"", hostA, hostB} {
			for _, k := range apikeys {
				for _, br := range bearers {
					r := withKey(req("GET", hosts[hp], "/rest/v1/", nil), k.tok)
					if br.tok != "" {
						r.Header.Set("Authorization", "Bearer "+br.tok)
					}
					if sni != "" {
						r.TLS = &tls.ConnectionState{HandshakeComplete: true, ServerName: sni}
					}
					ok := k.platform && k.proj == hp && (br.tok == "" || br.proj == hp) && (sni == "" || sni == hosts[hp])
					name := fmt.Sprintf("host %s sni %q apikey %s bearer %s", hp, sni, k.name, br.name)
					e.reset()
					w := e.do(r)
					if (w.Code == 200) != ok {
						t.Errorf("%s: status %d, want ok=%v", name, w.Code, ok)
						continue
					}
					if !ok {
						if len(e.requests()) != 0 || len(e.dialed) != 0 {
							t.Errorf("%s: refused request reached an upstream", name)
						}
						continue
					}
					want := k.tok
					if br.tok != "" {
						want = br.tok
					}
					g := e.last(t)
					if len(e.dialed) != 1 || e.dialed[0] != ups[hp] || g.Header.Get("Authorization") != "Bearer "+want {
						t.Errorf("%s: dialled %v, Authorization %.30q", name, e.dialed, g.Header.Get("Authorization"))
					}
				}
			}
		}
	}
}

// TestAuth_ForgedAndCollidingKeys: a token carrying A's kid but signed by
// B's key, and a project that registers another project's public key as its
// own issuer key under the same kid.
func TestAuth_ForgedAndCollidingKeys(t *testing.T) {
	a, b, _ := keys()
	e := newEnv(t, active())
	forged := signer{b.anon.priv, a.anon.kid}.token(t, "anon")
	e.expect(t, "A kid, B signature", withKey(req("GET", hostA, "/rest/v1/", nil), forged), 401, "invalid_apikey")
	forged = signer{a.iss.priv, a.svc.kid}.token(t, "service_role")
	e.expect(t, "A svc kid, A issuer signature", withKey(req("GET", hostA, "/rest/v1/", nil), forged), 401, "invalid_apikey")

	// A registers B's anon and issuer public keys as issuer keys of its own.
	f := file(2, "active")
	pa := f.Projects[refA]
	pa.Keys = append(pa.Keys, b.anon.jwk("issuer"), b.iss.jwk("issuer"))
	f.Projects[refA] = pa
	writeFile(t, e.path, f)
	if err := e.gw.table.Reload(); err != nil {
		t.Fatal(err)
	}
	anonA := a.anon.token(t, "anon")
	e.expect(t, "B anon token as A apikey", withKey(req("GET", hostA, "/rest/v1/", nil), b.anon.token(t, "anon")), 401, "invalid_apikey")
	r := withKey(req("GET", hostA, "/rest/v1/", nil), anonA)
	r.Header.Set("Authorization", "Bearer "+b.anon.token(t, "anon"))
	e.expect(t, "B anon token as A bearer", r, 401, "invalid_token")
	r = withKey(req("GET", hostA, "/rest/v1/", nil), anonA)
	r.Header.Set("Authorization", "Bearer "+b.svc.token(t, "service_role"))
	e.expect(t, "B service token as A bearer", r, 401, "invalid_token")
	// B is unaffected by what A registered.
	r = withKey(req("GET", hostB, "/rest/v1/", nil), b.anon.token(t, "anon"))
	r.Header.Set("Authorization", "Bearer "+a.iss.token(t, "authenticated"))
	e.expect(t, "A user at B", r, 401, "invalid_token")
}

// TestAuth_PrivilegeBinding covers role claims a token may carry.
func TestAuth_PrivilegeBinding(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon, svc := a.anon.token(t, "anon"), a.svc.token(t, "service_role")
	for _, c := range []struct{ name, apikey, auth string }{
		{"svc apikey, issuer bearer service_role", svc, "Bearer " + a.iss.token(t, "service_role")},
		{"svc apikey, issuer bearer anon", svc, "Bearer " + a.iss.token(t, "anon")},
		{"issuer bearer authenticator", anon, "Bearer " + a.iss.token(t, "authenticator")},
		{"issuer bearer pg_read_all_data", anon, "Bearer " + a.iss.token(t, "pg_read_all_data")},
		{"issuer bearer supabase_admin", anon, "Bearer " + a.iss.token(t, "supabase_admin")},
		{"issuer bearer Authenticated", anon, "Bearer " + a.iss.token(t, "Authenticated")},
		{"empty Authorization", anon, ""},
		{"Bearer with nothing", anon, "Bearer "},
		{"Bearer only", anon, "Bearer"},
		{"Token scheme", anon, "Token " + a.iss.token(t, "authenticated")},
		{"Digest scheme, same length as Bearer", anon, "Digest " + a.iss.token(t, "authenticated")},
		{"two spaces", anon, "Bearer  " + a.iss.token(t, "authenticated")},
		{"tab", anon, "Bearer\t" + a.iss.token(t, "authenticated")},
		{"trailing space", anon, "Bearer " + a.iss.token(t, "authenticated") + " "},
		{"comma-joined", anon, "Bearer " + a.iss.token(t, "authenticated") + ",Bearer " + svc},
	} {
		r := withKey(req("GET", hostA, "/rest/v1/", nil), c.apikey)
		r.Header["Authorization"] = []string{c.auth}
		e.expect(t, c.name, r, 401, "invalid_token")
	}
	// Bearer that a hop-by-hop listing would remove downstream is still checked.
	r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("Authorization", "Bearer "+a.iss.token(t, "postgres"))
	r.Header.Set("Connection", "Authorization")
	e.expect(t, "Connection: Authorization with a bad bearer", r, 401, "invalid_token")
	// An apikey named in Connection is still the one checked, and the bearer forwarded is the apikey.
	r = withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("Connection", "apikey")
	e.expect(t, "Connection: apikey", r, 200, "")
	if g := e.last(t).Header.Values("Authorization"); len(g) != 1 || g[0] != "Bearer "+anon {
		t.Errorf("Connection: apikey: upstream Authorization %.40q", g)
	}
	// Lower-case scheme is accepted (RFC 9110: case-insensitive) and normalised.
	r = withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	user := a.iss.token(t, "authenticated")
	r.Header.Set("Authorization", "bEaReR "+user)
	e.expect(t, "mixed-case scheme", r, 200, "")
	if g := e.last(t).Header.Get("Authorization"); g != "Bearer "+user {
		t.Errorf("forwarded %.30q", g)
	}
}

// TestAuth_QueryAPIKeyShapes: names a server might decode as apikey.
func TestAuth_QueryAPIKeyShapes(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	anon, svc := a.anon.token(t, "anon"), a.svc.token(t, "service_role")
	e.expect(t, "%61pikey and header disagree", withKey(req("GET", hostA, "/rest/v1/?%61pikey="+svc, nil), anon), 401, "invalid_apikey")
	e.expect(t, "empty apikey", req("GET", hostA, "/rest/v1/?apikey=", nil), 401, "invalid_apikey")
	e.expect(t, "apikey without =", req("GET", hostA, "/rest/v1/?apikey", nil), 401, "invalid_apikey")
	e.expect(t, "encoded ; separator", withKey(req("GET", hostA, "/rest/v1/?a=1%3Bapikey="+svc, nil), anon), 200, "")
	for _, q := range []string{"APIKEY=" + svc, "apikey[]=" + svc, "api+key=" + svc, "apikey%00=" + svc} {
		e.expect(t, q, withKey(req("GET", hostA, "/rest/v1/?"+q, nil), anon), 200, "")
		if g := e.last(t); g.Header.Get("Authorization") != "Bearer "+anon {
			t.Errorf("%s: a query name other than apikey changed the forwarded bearer", q)
		}
	}
}

// TestRoute_PathTricks: every path either 404s or reaches the host's own
// upstream with Host the upstream's.
func TestRoute_PathTricks(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	e.gw.transport.DisableKeepAlives = true
	addr := e.serve(t, false, nil)
	anon := a.anon.token(t, "anon")
	for _, c := range []struct {
		target string
		ok     bool
	}{
		{"/rest/v1//evil.test/x", true}, {"/rest/v1/http://evil.test/", true}, {"/rest/v1/../../x", true},
		{"/rest/v1/%2e%2e/%2e%2e/x", true}, {"/rest/v1/%00", true}, {"/rest/v1/@evil.test/", true},
		{"/rest/v1/" + strings.Repeat("a", 30000), true},
		{"/REST/v1/", false}, {"//rest/v1/", false}, {"/./rest/v1/", false}, {"/rest/./v1/", false},
		{"/x/../rest/v1/", false}, {"/rest/v1%2F", false}, {"/rest%2fv1/", false}, {"/rest/v1", false},
		{"*", false}, {"/-/health/../rest/v1/", false},
	} {
		e.reset()
		out := raw(t, addr, "GET "+c.target+" HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+anon+"\r\nConnection: close\r\n\r\n")
		got := e.requests()
		if c.ok {
			if !strings.Contains(firstLine(out), " 200 ") || len(got) != 1 || got[0].Host != upA || len(e.dialed) != 1 || e.dialed[0] != upA {
				t.Errorf("%.60s: %q, upstream %d", c.target, firstLine(out), len(got))
			}
		} else if strings.Contains(firstLine(out), " 200 ") || len(got) != 0 {
			t.Errorf("%.60s: %q reached upstream (%d)", c.target, firstLine(out), len(got))
		}
	}
}

// TestForward_HeaderSpoofing sends every forwarding and platform header in odd
// spellings over a real HTTP/1.1 connection.
func TestForward_HeaderSpoofing(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	addr := e.serve(t, false, nil)
	anon := a.anon.token(t, "anon")
	spoof := []string{"x-forwarded-for: 203.0.113.1", "X-FORWARDED-HOST: evil.test", "x-Forwarded-Proto: http",
		"X-Forwarded-Server: evil.test", "FORWARDED: for=203.0.113.1", "x-connection-encrypted: 1",
		"X-PG-APPLICATION-NAME: spoof", "x-pg-application-name: spoof2", "APIKEY: " + anon,
		"x-real-ip: 203.0.113.1", "TRUE-CLIENT-IP: 203.0.113.1"}
	out := raw(t, addr, "GET /rest/v1/ HTTP/1.1\r\nHost: "+hostA+"\r\n"+strings.Join(spoof, "\r\n")+"\r\nConnection: close\r\n\r\n")
	if !strings.Contains(firstLine(out), " 200 ") {
		t.Fatalf("%q", firstLine(out))
	}
	h := e.last(t).Header
	for k, vs := range h {
		lk := strings.ToLower(k)
		if lk == "apikey" || lk == "forwarded" || lk == "x-connection-encrypted" || lk == "x-forwarded-server" ||
			lk == "x-real-ip" || lk == "true-client-ip" {
			t.Errorf("upstream has %s: %q", k, vs)
		}
	}
	for k, v := range map[string]string{"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": hostA,
		"X-Forwarded-Proto": "https", "X-Pg-Application-Name": "supapace-gateway"} {
		if vs := h.Values(k); len(vs) != 1 || vs[0] != v {
			t.Errorf("upstream %s = %q, want %q", k, vs, v)
		}
	}
	// Request trailers are not forwarded with client values.
	var tr http.Header
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		mu.Lock()
		tr = r.Trailer.Clone()
		mu.Unlock()
	}))
	defer up.Close()
	e.gw.transport.DialContext = func(ctx context.Context, n, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	raw(t, addr, "POST /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+anon+"\r\nTrailer: Authorization, X-Forwarded-For\r\n"+
		"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\nAuthorization: Bearer forged\r\nX-Forwarded-For: 203.0.113.1\r\n\r\n")
	mu.Lock()
	defer mu.Unlock()
	for k, vs := range tr {
		for _, v := range vs {
			if v != "" {
				t.Errorf("client trailer %s reached the upstream: %q", k, v)
			}
		}
	}
}

// TestServer_Smuggling: framing a desyncing front end might pass on. The
// upstream must see exactly the authenticated requests.
func TestServer_Smuggling(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	addr := e.serve(t, false, nil)
	anon := a.anon.token(t, "anon")
	auth := "Host: " + hostA + "\r\napikey: " + anon + "\r\n"
	noauth := "GET /rest/v1/smuggled HTTP/1.1\r\nHost: " + hostA + "\r\nConnection: close\r\n\r\n"
	for _, c := range []struct {
		name, raw string
		max       int
	}{
		{"pipelined, second unauthenticated", "GET /rest/v1/one HTTP/1.1\r\n" + auth + "\r\n" + noauth, 1},
		{"bare LF", "GET /rest/v1/one HTTP/1.1\n" + auth + "\n" + noauth, 1},
		// Go folds obs-fold continuation lines into the value; the folded apikey is
		// then verified as usual and the gateway re-serialises headers upstream.
		{"obs-fold apikey", "GET /rest/v1/one HTTP/1.1\r\nHost: " + hostA + "\r\napikey:\r\n " + anon + "\r\nConnection: close\r\n\r\n", 1},
		{"space before colon", "POST /rest/v1/one HTTP/1.1\r\n" + auth + "Transfer-Encoding : chunked\r\nContent-Length: 0\r\n\r\n" + noauth, 1},
		{"chunk extension", "POST /rest/v1/one HTTP/1.1\r\n" + auth + "Transfer-Encoding: chunked\r\n\r\n3;x=\"a\r\nb\"\r\nabc\r\n0\r\n\r\n" + noauth, 1},
		{"chunked, identity", "POST /rest/v1/one HTTP/1.1\r\n" + auth + "Transfer-Encoding: chunked, identity\r\nContent-Length: 5\r\n\r\n0\r\n\r\n" + noauth, 0},
		{"CL with plus", "POST /rest/v1/one HTTP/1.1\r\n" + auth + "Content-Length: +5\r\n\r\nabcde" + noauth, 0},
		{"chunk size overflow", "POST /rest/v1/one HTTP/1.1\r\n" + auth + "Transfer-Encoding: chunked\r\n\r\n10000000000000001\r\na\r\n0\r\n\r\n" + noauth, 1},
		{"expect 100, unauthenticated", "POST /rest/v1/one HTTP/1.1\r\nHost: " + hostA + "\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nabcde", 0},
		{"HTTP/1.0 keep-alive", "GET /rest/v1/one HTTP/1.0\r\n" + auth + "Connection: keep-alive\r\n\r\n" + noauth, 0},
	} {
		e.reset()
		out := raw(t, addr, c.raw)
		got := e.requests()
		if len(got) > c.max {
			t.Errorf("%s: upstream saw %d requests (client %q)", c.name, len(got), firstLine(out))
		}
		for _, g := range got {
			if g.Path != "/one" || g.Header.Get("Authorization") != "Bearer "+anon {
				t.Errorf("%s: upstream saw %s %.20q", c.name, g.Path, g.Header.Get("Authorization"))
			}
		}
	}

	// An upstream that answers before reading the body: the rest of the body is
	// never taken as a request.
	var paths []string
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
	}))
	defer up.Close()
	e.gw.transport.DialContext = func(ctx context.Context, n, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	body := strings.Repeat("GET /rest/v1/smuggled HTTP/1.1\r\nHost: "+hostA+"\r\n\r\n", 20000)
	raw(t, addr, "POST /rest/v1/early HTTP/1.1\r\n"+auth+"Content-Length: "+fmt.Sprint(len(body))+"\r\n\r\n"+body+noauth)
	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if p != "/early" {
			t.Errorf("early response: upstream saw %s", p)
		}
	}
}

// --- HTTP/2 with hand-built frames, so pseudo-headers and Host can disagree.

func hpackStr(b *bytes.Buffer, s string) {
	hpackInt(b, 0, 7, len(s))
	b.WriteString(s)
}

func hpackInt(b *bytes.Buffer, first byte, bits uint, v int) {
	max := 1<<bits - 1
	if v < max {
		b.WriteByte(first | byte(v))
		return
	}
	b.WriteByte(first | byte(max))
	for v -= max; v >= 128; v >>= 7 {
		b.WriteByte(byte(v&127) | 128)
	}
	b.WriteByte(byte(v))
}

func h2frame(w io.Writer, typ, flags byte, stream uint32, p []byte) {
	h := []byte{byte(len(p) >> 16), byte(len(p) >> 8), byte(len(p)), typ, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[5:], stream)
	w.Write(append(h, p...))
}

// h2do sends one request (literal header fields, in order) and returns the
// response DATA, or "reset" / "goaway" when the stream or connection was
// refused.
func h2do(t *testing.T, addr, sni string, fields [][2]string) string {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: sni, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("h2 not negotiated")
	}
	io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	h2frame(c, 4, 0, 0, nil)
	var hb bytes.Buffer
	for _, f := range fields {
		hb.WriteByte(0)
		hpackStr(&hb, f[0])
		hpackStr(&hb, f[1])
	}
	h2frame(c, 1, 5, 1, hb.Bytes())
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var data []byte
	for {
		h := make([]byte, 9)
		if _, err := io.ReadFull(c, h); err != nil {
			return "eof:" + string(data)
		}
		p := make([]byte, int(h[0])<<16|int(h[1])<<8|int(h[2]))
		io.ReadFull(c, p)
		sid := binary.BigEndian.Uint32(h[5:]) & 0x7fffffff
		switch h[3] {
		case 4:
			if h[4]&1 == 0 {
				h2frame(c, 4, 1, 0, nil)
			}
		case 3:
			if sid == 1 {
				return "reset"
			}
		case 7:
			return "goaway"
		case 0:
			if sid == 1 {
				data = append(data, p...)
				if h[4]&1 != 0 {
					return string(data)
				}
			}
		case 1:
			if sid == 1 && h[4]&1 != 0 {
				return string(data)
			}
		}
	}
}

func TestHTTP2_Authority(t *testing.T) {
	a, b, _ := keys()
	e := newEnv(t, active())
	e.gw.transport.DisableKeepAlives = true
	addr := e.serve(t, true, nil)
	anonA, anonB := a.anon.token(t, "anon"), b.anon.token(t, "anon")
	base := func(auth string) [][2]string {
		return [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", auth}, {":path", "/rest/v1/"}}
	}
	for _, c := range []struct {
		name, sni string
		fields    [][2]string
		ok        bool
	}{
		{"control", hostA, append(base(hostA), [2]string{"apikey", anonA}), true},
		{"authority A, Host B, A key", hostA, append(base(hostA), [2]string{"host", hostB}, [2]string{"apikey", anonA}), true},
		{"authority B, Host A, SNI A, B key", hostA, append(base(hostB), [2]string{"host", hostA}, [2]string{"apikey", anonB}), false},
		{"authority A, Host B, B key", hostA, append(base(hostA), [2]string{"host", hostB}, [2]string{"apikey", anonB}), false},
		{"authority B on SNI A", hostA, append(base(hostB), [2]string{"apikey", anonB}), false},
		{"no authority, host B on SNI A", hostA, [][2]string{{":method", "GET"}, {":scheme", "https"}, {":path", "/rest/v1/"}, {"host", hostB}, {"apikey", anonB}}, false},
		{"two authorities", hostA, append(base(hostA), [2]string{":authority", hostB}, [2]string{"apikey", anonB}), false},
		{"absolute path to B", hostA, [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", hostA}, {":path", "https://" + hostB + "/rest/v1/"}, {"apikey", anonB}}, false},
		{"connection header", hostA, append(base(hostA), [2]string{"connection", "authorization"}, [2]string{"apikey", anonA}), false},
		{"upper-case name", hostA, append(base(hostA), [2]string{"Apikey", anonA}), false},
		{"two authorization", hostA, append(base(hostA), [2]string{"apikey", anonA}, [2]string{"authorization", "Bearer " + anonA}, [2]string{"authorization", "Bearer " + anonA}), false},
		{"extended CONNECT", hostA, [][2]string{{":method", "CONNECT"}, {":protocol", "websocket"}, {":scheme", "https"}, {":authority", hostA}, {":path", "/rest/v1/"}, {"apikey", anonA}}, false},
	} {
		e.reset()
		out := h2do(t, addr, c.sni, c.fields)
		t.Logf("%s: %q", c.name, out)
		got := e.requests()
		if c.ok {
			if len(got) != 1 || len(e.dialed) != 1 || e.dialed[0] != upA {
				t.Errorf("%s: %q, upstream %d", c.name, out, len(got))
			}
			continue
		}
		if len(got) != 0 {
			t.Errorf("%s: reached upstream %v (client %q)", c.name, e.dialed, out)
		}
	}
}

// TestHTTP2_StreamsBounded: the server advertises a small stream limit, so
// the per-source connection cap also bounds the requests one source holds.
func TestHTTP2_StreamsBounded(t *testing.T) {
	e := newEnv(t, active())
	addr := e.serve(t, true, nil)
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: hostA, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	h2frame(c, 4, 0, 0, nil)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	h := make([]byte, 9)
	io.ReadFull(c, h)
	p := make([]byte, int(h[0])<<16|int(h[1])<<8|int(h[2]))
	io.ReadFull(c, p)
	streams, frame := uint32(0), uint32(0)
	for i := 0; i+6 <= len(p); i += 6 {
		switch binary.BigEndian.Uint16(p[i:]) {
		case 3:
			streams = binary.BigEndian.Uint32(p[i+2:])
		case 5:
			frame = binary.BigEndian.Uint32(p[i+2:])
		}
	}
	if streams != 8 {
		t.Errorf("HTTP/2 max concurrent streams %d: one source holds %d requests in flight", streams, streams*MaxConnsPerSource)
	}
	// The read buffer of a connection grows to the largest frame it accepts.
	if frame != 16<<10 {
		t.Errorf("HTTP/2 max frame size %d, want %d", frame, 16<<10)
	}
}

// TestLimitListener_Accounting: every close path gives the slot back, and a
// stalled TLS handshake is timed out while counted.
func TestLimitListener_Accounting(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	lim := NewLimiter(100, 100)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(e.gw)
	s.ErrorLog = log.New(io.Discard, "", 0)
	s.ReadHeaderTimeout = 300 * time.Millisecond
	s.TLSConfig.Certificates = []tls.Certificate{testCert(t)}
	go s.ServeTLS(lim.Listen(ln), "", "")
	t.Cleanup(func() { s.Close() })
	addr := ln.Addr().String()
	count := func() int { lim.mu.Lock(); defer lim.mu.Unlock(); return lim.n }

	// Garbage instead of a ClientHello.
	c, _ := net.Dial("tcp", addr)
	io.WriteString(c, "GET / HTTP/1.1\r\n\r\n")
	io.ReadAll(c)
	c.Close()
	// A handshake stall: the server must close it, not wait for the client.
	c, _ = net.Dial("tcp", addr)
	start := time.Now()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = io.ReadAll(c)
	if err != nil || time.Since(start) > 2*time.Second {
		t.Errorf("stalled handshake not closed by the server: %v after %v", err, time.Since(start))
	}
	c.Close()
	// Client abort mid-request, HTTP/1.1 and HTTP/2 completed requests.
	tc, _ := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: hostA, NextProtos: []string{"http/1.1"}})
	io.WriteString(tc, "POST /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+a.anon.token(t, "anon")+"\r\nContent-Length: 100\r\n\r\nab")
	tc.Close()
	for _, h2 := range []bool{true, false} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: hostA, InsecureSkipVerify: true}, ForceAttemptHTTP2: h2}
		if !h2 {
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		r, _ := http.NewRequest("GET", "https://"+addr+"/rest/v1/", nil)
		r.Host = hostA
		r.Header.Set("apikey", a.anon.token(t, "anon"))
		if resp, err := (&http.Client{Transport: tr}).Do(r); err == nil {
			resp.Body.Close()
		}
		tr.CloseIdleConnections()
	}
	eventually(t, func() bool { return count() == 0 }, "connection slots not all released")
	if n := count(); n != 0 {
		t.Errorf("%d slots still held", n)
	}
}

// TestTable_UnderLoad: while the route file flips A's upstream between
// two addresses, A's requests never reach B's upstream.
func TestTable_UnderLoad(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	e.gw.transport.DisableKeepAlives = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.gw.table.Watch(ctx, time.Millisecond)
	anon := a.anon.token(t, "anon")
	var bad atomic.Int32
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				w := httptest.NewRecorder()
				e.gw.ServeHTTP(w, withKey(req("GET", hostA, "/rest/v1/", nil), anon))
				if w.Code != 200 {
					bad.Add(1)
				}
			}
		}()
	}
	for g := int64(2); g < 30; g++ {
		f := file(g, "active")
		if g%2 == 0 {
			p := f.Projects[refA]
			p.Rest = "http://10.212.0.18:3000"
			f.Projects[refA] = p
		}
		writeFile(t, e.path, f)
		time.Sleep(3 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, d := range e.dialed {
		if d != upA && d != "10.212.0.18:3000" {
			t.Fatalf("A's request dialled %s", d)
		}
	}
	if bad.Load() != 0 {
		t.Errorf("%d requests failed during reloads", bad.Load())
	}
}

// TestTable_FileShapes: symlink swap, in-place partial write, lower
// generation, and a file swapped back to identical content.
func TestTable_FileShapes(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "routes.json")
	g1, g2 := filepath.Join(dir, "g1"), filepath.Join(dir, "g2")
	writeFile(t, g1, file(5, "active"))
	writeFile(t, g2, file(6, "active"))
	os.Symlink(g1, link)
	tbl := NewTable(link)
	if err := tbl.Reload(); err != nil || tbl.Generation() != 5 {
		t.Fatal(err, tbl.Generation())
	}
	os.Symlink(g2, link+".new")
	os.Rename(link+".new", link)
	if err := tbl.Reload(); err != nil || tbl.Generation() != 6 {
		t.Errorf("symlink swap: %v, generation %d", err, tbl.Generation())
	}
	// In-place write in two steps: the half file is refused, the whole one read.
	p := filepath.Join(dir, "inplace.json")
	good, _ := file(7, "active").Marshal()
	os.WriteFile(p, good[:len(good)/2], 0o644)
	tbl = NewTable(p)
	if tbl.Reload() == nil {
		t.Error("half file accepted")
	}
	os.WriteFile(p, good, 0o644)
	if err := tbl.Reload(); err != nil || tbl.Generation() != 7 {
		t.Errorf("completed in-place write: %v, generation %d", err, tbl.Generation())
	}
	// A lower generation is accepted (logged).
	writeFile(t, p, file(3, "active"))
	tbl.Reload()
	t.Logf("lower generation after 7: table now at %d", tbl.Generation())
}

// TestForward_UpstreamResponse: redirects are passed back, not followed;
// hop-by-hop response headers are dropped; a client disconnect cancels the
// upstream request.
func TestForward_UpstreamResponse(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	var hits atomic.Int32
	cancelled := make(chan struct{}, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Connection", "X-Secret")
			w.Header().Set("X-Secret", "1")
			w.Header().Set("Keep-Alive", "timeout=1")
			w.Header().Set("Server", "postgrest/12.2.3")
			w.Header().Set("Set-Cookie", "s=1; Secure")
			http.Redirect(w, r, "http://10.212.0.17:3000/other", http.StatusFound)
		case "/hang":
			select {
			case <-r.Context().Done():
				cancelled <- struct{}{}
			case <-time.After(5 * time.Second):
			}
		}
	}))
	defer up.Close()
	e.gw.transport.DialContext = func(ctx context.Context, n, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	anon := a.anon.token(t, "anon")
	w := e.do(withKey(req("GET", hostA, "/rest/v1/redirect", nil), anon))
	if w.Code != 302 || hits.Load() != 1 || w.Header().Get("X-Secret") != "" || w.Header().Get("Keep-Alive") != "" ||
		w.Header().Values("Server") != nil || w.Header().Get("Set-Cookie") != "s=1; Secure" {
		t.Errorf("redirect: %d, upstream hits %d, headers %v", w.Code, hits.Load(), w.Header())
	}
	addr := e.serve(t, false, nil)
	c, _ := net.Dial("tcp", addr)
	io.WriteString(c, "GET /rest/v1/hang HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+anon+"\r\n\r\n")
	time.Sleep(200 * time.Millisecond)
	c.Close()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Error("client disconnect did not cancel the upstream request")
	}
}

// TestErrors_BodiesCarryNothing: every refusal body is {"code":…}, with a
// "message" only for a refused credential, taken from the fixed list.
func TestErrors_BodiesCarryNothing(t *testing.T) {
	a, b, _ := keys()
	e := newEnv(t, active())
	anon := a.anon.token(t, "anon")
	fixed := map[string]bool{}
	for _, m := range tokenMessages {
		fixed[m] = true
	}
	for _, r := range []*http.Request{
		withKey(req("GET", hostA, "/rest/v1/?a;b", nil), anon),
		withKey(req("GET", hostA, "/nope", nil), anon),
		withKey(req("GET", hostA, "/rest/v1/", nil), b.anon.token(t, "anon")),
		withKey(req("GET", "cccccccccccccccccccc.sp.test", "/rest/v1/", nil), anon),
	} {
		w := e.do(r)
		var m map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &m)
		msg, hasMsg := m["message"].(string)
		if err != nil || m["code"] == nil || len(m) != 1 && !(len(m) == 2 && hasMsg && fixed[msg]) {
			t.Errorf("body %s", w.Body)
		}
		for _, s := range []string{"10.212.", "sp.test", refA, "eyJ"} {
			if strings.Contains(w.Body.String(), s) || strings.Contains(fmt.Sprint(w.Header()), s) {
				t.Errorf("refusal carries %q: %s %v", s, w.Body, w.Header())
			}
		}
	}
}

// TestAuth_RefusalMessages: each refused credential names its cause with a
// fixed message; status and code are unchanged.
func TestAuth_RefusalMessages(t *testing.T) {
	a, b, stranger := keys()
	e := newEnv(t, active())
	anon, user := a.anon.token(t, "anon"), a.iss.token(t, "authenticated")
	expired, err := jwtx.Sign(a.iss.priv, a.iss.kid, map[string]any{"role": "authenticated", "exp": time.Now().Unix() - 1})
	if err != nil {
		t.Fatal(err)
	}
	early, err := jwtx.Sign(a.iss.priv, a.iss.kid, map[string]any{"role": "authenticated", "exp": time.Now().Unix() + 300, "nbf": time.Now().Unix() + 300})
	if err != nil {
		t.Fatal(err)
	}
	noRole, err := jwtx.Sign(a.iss.priv, a.iss.kid, map[string]any{"exp": time.Now().Unix() + 300})
	if err != nil {
		t.Fatal(err)
	}
	seg := strings.Split(user, ".")
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"`+a.iss.kid+`"}`)) + "." + seg[1] + "." + seg[2]
	noKID := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + seg[1] + "." + seg[2]
	dup := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"`+a.iss.kid+`","kid":"x"}`)) + "." + seg[1] + "." + seg[2]
	badSig := seg[0] + "." + seg[1] + "." + strings.Repeat("A", len(seg[2]))
	for _, c := range []struct{ name, apikey, query, auth, code, msg string }{
		{"no apikey", "", "", "", "no_apikey", ""},
		{"two query apikeys", "", "apikey=" + anon + "&apikey=" + anon, "", "invalid_apikey", "more than one apikey"},
		{"header and query differ", anon, "apikey=" + a.svc.token(t, "service_role"), "", "invalid_apikey", "apikey header and query parameter differ"},
		{"issuer token as apikey", user, "", "", "invalid_apikey", "apikey is not an anon or service_role key"},
		{"other project's apikey", b.anon.token(t, "anon"), "", "", "invalid_apikey", "token kid is not a key of this project"},
		{"malformed apikey", "abc", "", "", "invalid_apikey", "token is malformed"},
		{"expired", anon, "", "Bearer " + expired, "invalid_token", "token is expired or has no exp"},
		{"not yet valid", anon, "", "Bearer " + early, "invalid_token", "token is not yet valid"},
		{"unknown issuer", anon, "", "Bearer " + stranger.token(t, "authenticated"), "invalid_token", "token kid is not a key of this project"},
		{"role not allowed", anon, "", "Bearer " + a.iss.token(t, "service_role"), "invalid_token", "token role is not allowed for its key"},
		{"no role", anon, "", "Bearer " + noRole, "invalid_token", "token has no role"},
		{"alg none", anon, "", "Bearer " + none, "invalid_token", "token algorithm is not RS256"},
		{"no kid", anon, "", "Bearer " + noKID, "invalid_token", "token has no kid"},
		{"duplicate member", anon, "", "Bearer " + dup, "invalid_token", "token has a duplicate member name"},
		{"bad signature", anon, "", "Bearer " + badSig, "invalid_token", "token signature is invalid"},
		{"malformed bearer", anon, "", "Bearer x.y", "invalid_token", "token is malformed"},
		{"not Bearer", anon, "", "Basic " + user, "invalid_token", `Authorization is not "Bearer <token>"`},
		{"two Authorization", anon, "", "two", "invalid_token", "more than one Authorization header"},
	} {
		r := req("GET", hostA, "/rest/v1/?"+c.query, nil)
		if c.apikey != "" {
			withKey(r, c.apikey)
		}
		switch c.auth {
		case "":
		case "two":
			r.Header["Authorization"] = []string{"Bearer " + user, "Bearer " + user}
		default:
			r.Header.Set("Authorization", c.auth)
		}
		w := e.do(r)
		var got struct{ Code, Message string }
		json.Unmarshal(w.Body.Bytes(), &got)
		if w.Code != 401 || got.Code != c.code || got.Message != c.msg {
			t.Errorf("%s: %d %s, want 401 %q %q", c.name, w.Code, w.Body, c.code, c.msg)
		}
	}
}

// TestTable_ReloadsOnNewInode: a file renamed over the old one is read even
// when its size and mtime are identical.
func TestTable_ReloadsOnNewInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	put := func(gen int64) {
		b, err := file(gen, "active").Marshal()
		if err != nil {
			t.Fatal(err)
		}
		mt := time.Unix(1_800_000_000, 0)
		if err := os.WriteFile(path+".tmp", b, 0o444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path+".tmp", mt, mt); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			t.Fatal(err)
		}
	}
	put(2)
	tbl := NewTable(path)
	if err := tbl.Reload(); err != nil || tbl.Generation() != 2 {
		t.Fatal(err, tbl.Generation())
	}
	put(3)
	if err := tbl.Reload(); err != nil || tbl.Generation() != 3 {
		t.Errorf("same size and mtime, new inode: %v, generation %d", err, tbl.Generation())
	}
}

// holdEnv is an env whose upstream holds every request to /hold until
// release is closed and answers anything else at once.
func holdEnv(t *testing.T) (e *env, arrived, release chan struct{}, dials *atomic.Int32) {
	t.Helper()
	e = newEnv(t, active())
	arrived, release = make(chan struct{}, 8), make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			arrived <- struct{}{}
			<-release
		}
	}))
	t.Cleanup(up.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	dials = new(atomic.Int32)
	e.gw.transport.DisableKeepAlives = true
	e.gw.transport.DialContext = func(ctx context.Context, n, _ string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	return e, arrived, release, dials
}

// within runs r through the gateway and fails the test if it does not
// answer in two seconds (a request admitted over a cap would hang).
func within(t *testing.T, e *env, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	c := make(chan *httptest.ResponseRecorder, 1)
	go func() { c <- e.do(r) }()
	select {
	case w := <-c:
		return w
	case <-time.After(2 * time.Second):
		t.Fatal("request not answered: admitted over a cap")
		return nil
	}
}

// refusedBeforeSlots checks, while the slots are held, that a bad key and an
// unknown route are refused as such: slots are taken only after both checks.
func refusedBeforeSlots(t *testing.T, e *env) {
	t.Helper()
	a, b, _ := keys()
	if w := within(t, e, withKey(req("GET", hostA, "/rest/v1/hold", nil), b.anon.token(t, "anon"))); w.Code != 401 {
		t.Errorf("other project's key at the cap: %d, want 401", w.Code)
	}
	if w := within(t, e, withKey(req("GET", hostA, "/auth/v1/user", nil), a.anon.token(t, "anon"))); w.Code != 404 {
		t.Errorf("unknown route at the cap: %d, want 404", w.Code)
	}
	if w := within(t, e, req("GET", hostA, "/-/health", nil)); w.Code != 200 {
		t.Errorf("health at the cap: %d", w.Code)
	}
}

// TestServer_InFlightCap: proxied requests beyond the gateway-wide cap are
// refused with 503 before any upstream dial.
func TestServer_InFlightCap(t *testing.T) {
	a, b, _ := keys()
	e, arrived, release, dials := holdEnv(t)
	e.gw.inflight = make(chan struct{}, 1)
	anonA := a.anon.token(t, "anon")
	done := make(chan int)
	go func() { done <- e.do(withKey(req("GET", hostA, "/rest/v1/hold", nil), anonA)).Code }()
	<-arrived
	w := within(t, e, withKey(req("GET", hostB, "/rest/v1/", nil), b.anon.token(t, "anon")))
	if w.Code != 503 || w.Header().Get("Retry-After") != "5" || strings.TrimSpace(w.Body.String()) != `{"code":"unavailable"}` {
		t.Errorf("over the cap: %d %s", w.Code, w.Body)
	}
	// With both caps reached, the project's is checked first.
	e.gw.projectCap = 1
	if w := within(t, e, withKey(req("GET", hostA, "/rest/v1/", nil), anonA)); w.Code != 429 {
		t.Errorf("project and gateway at their caps: %d, want 429", w.Code)
	}
	e.gw.mu.Lock()
	e.gw.projectCap = maxProjectInFlight
	e.gw.mu.Unlock()
	if w := within(t, e, withKey(req("GET", hostA, "/rest/v1/", nil), anonA)); w.Code != 503 {
		t.Errorf("project under its cap, gateway at its cap: %d, want 503", w.Code)
	}
	refusedBeforeSlots(t, e)
	if dials.Load() != 1 {
		t.Errorf("%d dials, want 1", dials.Load())
	}
	if n := len(e.gw.byProject); n != 1 {
		t.Errorf("refused requests left %d project counts", n)
	}
	close(release)
	if c := <-done; c != 200 {
		t.Errorf("held request: %d", c)
	}
	if w := within(t, e, withKey(req("GET", hostA, "/rest/v1/", nil), anonA)); w.Code != 200 {
		t.Errorf("after release: %d", w.Code)
	}
}

// TestServer_ProjectInFlightCap: one project at its cap gets 429 and takes no
// global slot; another project is still served; the count survives a
// reload and is gone once the requests finish.
func TestServer_ProjectInFlightCap(t *testing.T) {
	a, b, _ := keys()
	e, arrived, release, dials := holdEnv(t)
	e.gw.projectCap = 1
	anonA := a.anon.token(t, "anon")
	done := make(chan int)
	go func() { done <- e.do(withKey(req("GET", hostA, "/rest/v1/hold", nil), anonA)).Code }()
	<-arrived
	over := func(name string) {
		t.Helper()
		w := within(t, e, withKey(req("GET", hostA, "/rest/v1/", nil), anonA))
		if w.Code != 429 || w.Header().Get("Retry-After") != "1" || strings.TrimSpace(w.Body.String()) != `{"code":"too_many_requests"}` {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		if n := len(e.gw.inflight); n != 1 {
			t.Errorf("%s: %d global slots held, want 1", name, n)
		}
	}
	over("project at its cap")
	if w := within(t, e, withKey(req("GET", hostB, "/rest/v1/", nil), b.anon.token(t, "anon"))); w.Code != 200 {
		t.Errorf("other project while A is at its cap: %d", w.Code)
	}
	refusedBeforeSlots(t, e)
	if dials.Load() != 2 {
		t.Errorf("%d dials, want 2", dials.Load())
	}
	// A reload, also one that drops A, keeps A's count.
	writeFile(t, e.path, file(2, "active"))
	if err := e.gw.table.Reload(); err != nil {
		t.Fatal(err)
	}
	over("after reload")
	f := file(3, "active")
	delete(f.Projects, refA)
	writeFile(t, e.path, f)
	if err := e.gw.table.Reload(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if c := <-done; c != 200 {
		t.Errorf("held request: %d", c)
	}
	if n := len(e.gw.byProject); n != 0 || len(e.gw.inflight) != 0 {
		t.Errorf("after the last request: %d project counts, %d global slots", n, len(e.gw.inflight))
	}
	writeFile(t, e.path, file(4, "active"))
	if err := e.gw.table.Reload(); err != nil {
		t.Fatal(err)
	}
	if w := within(t, e, withKey(req("GET", hostA, "/rest/v1/", nil), anonA)); w.Code != 200 {
		t.Errorf("after release: %d", w.Code)
	}
}

// TestTable_UnchangedNotReread: polling an unchanged file reads it once.
func TestTable_UnchangedNotReread(t *testing.T) {
	e := newEnv(t, active())
	ctx, cancel := context.WithCancel(context.Background())
	go e.gw.table.Watch(ctx, time.Millisecond)
	time.Sleep(100 * time.Millisecond) // about a hundred polls
	cancel()
	e.gw.table.mu.Lock()
	n := e.gw.table.reads
	e.gw.table.mu.Unlock()
	if n != 1 {
		t.Errorf("unchanged file read %d times", n)
	}
}

type failingBody struct{ n int }

func (f *failingBody) Read(p []byte) (int, error) {
	if f.n == 0 {
		return 0, errors.New("client went away")
	}
	f.n--
	p[0] = 'x'
	return 1, nil
}

// TestServer_ClientBodyFailureAborts: a body that breaks off is the client's
// fault, not the upstream's: nothing is answered, the handler aborts, the
// slots come back.
func TestServer_ClientBodyFailureAborts(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	r := withKey(req("POST", hostA, "/rest/v1/t", nil), a.anon.token(t, "anon"))
	r.Body, r.ContentLength = io.NopCloser(&failingBody{n: 3}), 100
	w := httptest.NewRecorder()
	func() {
		defer func() {
			if p := recover(); p != http.ErrAbortHandler {
				t.Errorf("broken body: recovered %v, want http.ErrAbortHandler", p)
			}
		}()
		e.gw.ServeHTTP(w, r)
	}()
	if w.Body.Len() != 0 || len(e.requests()) != 0 || !idle(e) {
		t.Errorf("broken body: answered %d %s, upstream saw %d, idle %v", w.Code, w.Body, len(e.requests()), idle(e))
	}
}

// TestShutdown_DrainsInFlight: Shutdown lets a running request finish, stops
// accepting, and gives up at the grace deadline.
func TestShutdown_DrainsInFlight(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	arrived, release := make(chan struct{}, 2), make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release
	}))
	defer up.Close()
	defer close(release)
	e.gw.transport.DialContext = func(ctx context.Context, n, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, other := NewServer(e.gw), NewServer(Redirect())
	go s.Serve(ln)
	addr, anon := ln.Addr().String(), a.anon.token(t, "anon")
	get := func() (int, error) {
		r, _ := http.NewRequest("GET", "http://"+addr+"/rest/v1/", nil)
		r.Host = hostA
		r.Header.Set("apikey", anon)
		resp, err := (&http.Client{Transport: &http.Transport{}}).Do(r)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	got := make(chan int, 1)
	go func() { c, _ := get(); got <- c }()
	<-arrived
	shut := make(chan error, 1)
	go func() { shut <- Shutdown(5*time.Second, s, other) }()
	time.Sleep(100 * time.Millisecond)
	if _, err := get(); err == nil {
		t.Error("new connection accepted during shutdown")
	}
	release <- struct{}{}
	if c := <-got; c != 200 {
		t.Errorf("in-flight request: %d", c)
	}
	if err := <-shut; err != nil {
		t.Errorf("shutdown: %v", err)
	}

	// A request that outlives the grace period: Shutdown returns at the deadline.
	ln, _ = net.Listen("tcp", "127.0.0.1:0")
	s = NewServer(e.gw)
	go s.Serve(ln)
	addr = ln.Addr().String()
	go get()
	<-arrived
	start := time.Now()
	if err := Shutdown(200*time.Millisecond, s); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Errorf("grace exceeded: %v after %v", err, time.Since(start))
	}
	s.Close()
}

// TestServer_ClientGivesUpDuringBodyRead: after the upstream dropped a
// partial body, the gateway reads the rest; a client that then closes its
// connection (HTTP/1.1) or resets its stream (HTTP/2) ends that read at once,
// not at the read timeout, and the slots come back.
func TestServer_ClientGivesUpDuringBodyRead(t *testing.T) {
	a, _, _ := keys()
	tok := a.anon.token(t, "anon")
	for _, mode := range []string{"h1", "h2"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t, active())
			closed := dropUpstream(t, e, 2)
			addr := e.serve(t, mode == "h2", func(s *http.Server) { s.ReadTimeout, s.WriteTimeout = 10*time.Second, 10*time.Second })
			var giveUp func()
			if mode == "h2" {
				h := h2open(t, addr)
				h.headers(1, [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", hostA},
					{":path", "/rest/v1/t"}, {"apikey", tok}, {"content-length", "1048576"}}, false, maxH2Frame)
				h.frame(0, 0, 1, []byte("xxxx"))
				giveUp = func() { h.frame(3, 0, 1, []byte{0, 0, 0, 8}) } // RST_STREAM CANCEL
			} else {
				c, err := net.Dial("tcp", addr)
				if err != nil {
					t.Fatal(err)
				}
				io.WriteString(c, "POST /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+tok+"\r\nContent-Length: 1048576\r\n\r\nxxxx")
				giveUp = func() { c.Close() }
			}
			eventually(t, func() bool { return closed.Load() == 1 }, "upstream did not drop the body")
			time.Sleep(100 * time.Millisecond) // the error handler is now reading the rest
			if idle(e) {
				t.Fatal("slots already back: the rest of the body is not being read")
			}
			start := time.Now()
			giveUp()
			eventually(t, func() bool { return idle(e) }, "slots not returned")
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("slots back %v after the client gave up, want at once", d)
			}
		})
	}
}
