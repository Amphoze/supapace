package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/jwtx"
)

const (
	refC     = "ccccccccccccccccccc3"
	refD     = "ddddddddddddddddddd4" // never a ref of the table
	signInO  = "https://" + signInH
	clientID = "supapace"
)

// signInTable is testdata/signin.json: the cases that need no signature,
// which the tests of the sign-in model read too.
type signInTable struct {
	Comment     string                      `json:"comment"`
	ReturnPaths []struct{ In, Want string } `json:"return_paths"`
	Forged      []string                    `json:"forged_return_paths"`
	Callback    []struct {
		Name   string
		Form   url.Values
		Status int
		Target string
	} `json:"callback"`
	Fields []struct {
		Name, Body        string
		Callback, Session int
	} `json:"fields"`
	OtherMethods []string `json:"other_methods"`
	Referers     []struct {
		Referer string
		Marked  bool
	} `json:"session_page_referers"`
	CookieNames []struct {
		Name  string
		Login bool
	} `json:"login_cookie_names"`
	CookieCounts []struct{ Shown, Cleared int } `json:"login_cookie_counts"`
}

func loadSignIn(t *testing.T) signInTable {
	t.Helper()
	b, err := os.ReadFile("testdata/signin.json")
	if err != nil {
		t.Fatal(err)
	}
	var v signInTable
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if len(v.ReturnPaths) == 0 || len(v.Forged) == 0 || len(v.Callback) == 0 || len(v.Fields) == 0 ||
		len(v.OtherMethods) == 0 || len(v.Referers) == 0 || len(v.CookieNames) == 0 || len(v.CookieCounts) == 0 {
		t.Fatal("testdata/signin.json: an empty section")
	}
	return v
}

var (
	repeatRE = regexp.MustCompile(`\{(.)\*([0-9]+)\}`)
	clockRE  = regexp.MustCompile(`\{now(?:([+-])([0-9]+))?\}`)
)

// expand fills the placeholders of a string of the table file.
func expand(s string, now int64) string {
	s = repeatRE.ReplaceAllStringFunc(s, func(m string) string {
		p := repeatRE.FindStringSubmatch(m)
		n, _ := strconv.Atoi(p[2])
		return strings.Repeat(p[1], n)
	})
	s = clockRE.ReplaceAllStringFunc(s, func(m string) string {
		p := clockRE.FindStringSubmatch(m)
		d, _ := strconv.ParseInt(p[1]+p[2], 10, 64)
		return strconv.FormatInt(now+d, 10)
	})
	return strings.NewReplacer("{A}", refA, "{B}", refB, "{D}", refD, "{S}", studioDom).Replace(s)
}

func expandForm(f url.Values, now int64) url.Values {
	out := url.Values{}
	for k, vs := range f {
		for _, v := range vs {
			out.Add(k, expand(v, now))
		}
	}
	return out
}

// authEnv is a gateway with the fixture dashboard table and the real sign-in
// handler; the forwarder stays the recorder.
type authEnv struct {
	*dashEnv
	gen int64
}

func newAuthEnv(t *testing.T) *authEnv {
	t.Helper()
	e := &authEnv{dashEnv: newDashEnv(t, active(), true), gen: 1}
	dashAuth = serveSignIn // newDashEnv puts the seams back when the test ends
	return e
}

// setTable replaces the dashboard table with the fixture as mod changes it.
func (e *authEnv) setTable(t *testing.T, mod func(*dashfile.File)) {
	t.Helper()
	e.gen++
	f := dfile(e.gen)
	if mod != nil {
		mod(&f)
	}
	writeDashFile(t, e.path(), f)
	if err := e.d.table.Reload(); err != nil {
		t.Fatal(err)
	}
}

// member adds sub to each of refs, creating the project where needed.
func member(f *dashfile.File, sub string, refs ...string) {
	for _, ref := range refs {
		p := f.Projects[ref]
		if p.Name == "" {
			p.Name = "P " + ref[:3]
		}
		p.Members = append(p.Members, dashfile.Member{Iss: issuer, Sub: sub, Role: "developer"})
		f.Projects[ref] = p
	}
}

// refsN returns n refs in order, none of them a ref of the fixture.
func refsN(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("p%019d", i)
	}
	return out
}

// hdr adds header pairs to r.
func hdr(r *http.Request, pairs ...string) *http.Request {
	for i := 0; i+1 < len(pairs); i += 2 {
		r.Header.Add(pairs[i], pairs[i+1])
	}
	return r
}

func get(host, target string, pairs ...string) *http.Request {
	return hdr(rawReq("GET", host, target), pairs...)
}

// post is a form post of body, as a browser sends one.
func post(host, target, body string, pairs ...string) *http.Request {
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.RequestURI, r.Host, r.RemoteAddr = target, host, peerIP+":4321"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return hdr(r, pairs...)
}

// navTo is the header pairs of a top-level navigation; site is its
// Sec-Fetch-Site.
func navTo(site string) []string {
	return []string{"Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document", "Sec-Fetch-Site", site, "Accept", "text/html"}
}

var (
	scriptRE = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	styleRE  = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	actionRE = regexp.MustCompile(`<form method="post" action="([^"]*)">`)
	hiddenRE = regexp.MustCompile(`<input type="hidden" name="([a-z_]+)" value="([^"]*)">`)
	nextRE   = regexp.MustCompile(`<a id="next" href="([^"]*)">`)
	metaRE   = regexp.MustCompile(`<meta http-equiv="refresh" content="([^"]*)">`)
	linkRE   = regexp.MustCompile(`<a href="([^"]*)">`)
	// an attribute that would run or style something from inside a tag
	inlineRE = regexp.MustCompile(`(?i)<[^>]*\s(on[a-z]+|style)\s*=|(href|action|content)="[^"]*javascript:`)
)

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// policyWrong says what is wrong with an answer of the sign-in handler on
// host: the dashboard headers, no-store, the gateway-pages policy with the
// hash of the script and of the style the body really holds, form-action
// formAction, and Origin-Agent-Cluster on the sign-in host alone.
func policyWrong(host string, w *httptest.ResponseRecorder, formAction string) string {
	h := w.Header()
	for k, v := range dashWant {
		if k == "Content-Security-Policy" {
			continue
		}
		if vs := h.Values(k); len(vs) != 1 || vs[0] != v {
			return k + ": " + strings.Join(vs, " | ")
		}
	}
	if vs := h.Values("Cache-Control"); len(vs) != 1 || vs[0] != "no-store" {
		return "Cache-Control: " + strings.Join(vs, " | ")
	}
	oac := h.Values("Origin-Agent-Cluster")
	if host == signInH && (len(oac) != 1 || oac[0] != "?1") || host != signInH && len(oac) != 0 {
		return "Origin-Agent-Cluster: " + strings.Join(oac, " | ")
	}
	body := w.Body.String()
	script, style := "'none'", ""
	if m := scriptRE.FindAllStringSubmatch(body, -1); len(m) == 1 {
		script = hashOf(m[0][1])
	} else if len(m) > 1 || strings.Count(body, "<script") != len(m) {
		return "more than one script"
	}
	if m := styleRE.FindAllStringSubmatch(body, -1); len(m) == 1 {
		style = hashOf(m[0][1])
	} else if len(m) > 1 {
		return "more than one style"
	} else {
		style = hashOf(pageStyle) // an answer without a page: the policy is the pages' all the same
	}
	want := "default-src 'none'; script-src " + script + "; style-src " + style +
		"; frame-ancestors 'none'; base-uri 'none'; form-action " + formAction
	if vs := h.Values("Content-Security-Policy"); len(vs) != 1 || vs[0] != want {
		return "Content-Security-Policy: " + strings.Join(vs, " | ") + "\nwant " + want
	}
	if m := inlineRE.FindString(body); m != "" {
		return "inline handler, inline style or script address in the body: " + m
	}
	return ""
}

// ask sends r to the gateway and checks the policy of the answer, which
// every answer of the sign-in handler carries.
func (e *authEnv) ask(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	return e.askAction(t, r, "'none'")
}

func (e *authEnv) askAction(t *testing.T, r *http.Request, formAction string) *httptest.ResponseRecorder {
	t.Helper()
	host, method, target := r.Host, r.Method, r.RequestURI
	w := e.do(r)
	if s := policyWrong(host, w, formAction); s != "" {
		t.Errorf("%s %s%s (%d): %s", method, host, target, w.Code, s)
	}
	return w
}

// code is the gateway's error code of a JSON refusal, "" for anything else.
func code(w *httptest.ResponseRecorder) string {
	var b struct{ Code string }
	if w.Header().Get("Content-Type") != "application/json" || json.Unmarshal(w.Body.Bytes(), &b) != nil {
		return ""
	}
	return b.Code
}

// isPage reports whether w is one of the gateway's HTML pages.
func isPage(w *httptest.ResponseRecorder) bool {
	return w.Header().Get("Content-Type") == "text/html; charset=utf-8" && strings.HasPrefix(w.Body.String(), "<!doctype html>")
}

func cookies(w *httptest.ResponseRecorder) []string { return w.Header().Values("Set-Cookie") }

func clearLoginLine(name string) string {
	return name + "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None"
}

const clearSessionLine = "__Host-sp-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"

var (
	loginLineRE   = regexp.MustCompile(`^(__Host-sp-login-([A-Za-z0-9_-]{11}))=([A-Za-z0-9_-]{43}); Path=/; Max-Age=600; HttpOnly; Secure; SameSite=None$`)
	sessionLineRE = regexp.MustCompile(`^__Host-sp-session=(v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86}); Path=/; Max-Age=([0-9]+); HttpOnly; Secure; SameSite=Strict$`)
)

// attemptT is what a login answer started: its cookie and its redirect.
type attemptT struct {
	name, a, r string // the cookie's name, the attempt's id, the secret
	cookie     string // name=value
	loc        *url.URL
	state      string
	nonce      string
}

// login starts an attempt on host and reads the answer's cookie and state.
func (e *authEnv) login(t *testing.T, host, query string, pairs ...string) attemptT {
	t.Helper()
	w := e.ask(t, get(host, "/-/auth/login"+query, pairs...))
	sc := cookies(w)
	if w.Code != 302 || len(sc) == 0 {
		t.Fatalf("login on %s%s: %d, Set-Cookie %q, body %s", host, query, w.Code, sc, w.Body)
	}
	m := loginLineRE.FindStringSubmatch(sc[len(sc)-1])
	if m == nil {
		t.Fatalf("login cookie %q", sc[len(sc)-1])
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return attemptT{name: m[1], a: m[2], r: m[3], cookie: m[1] + "=" + m[3], loc: loc,
		state: loc.Query().Get("state"), nonce: loc.Query().Get("nonce")}
}

// statePath is the return path a state carries.
func statePath(t *testing.T, state string) string {
	t.Helper()
	p := strings.Split(state, ".")
	if len(p) != 5 {
		t.Fatalf("state %q", state)
	}
	b, err := base64.RawURLEncoding.DecodeString(p[4])
	if err != nil {
		t.Fatalf("state %q: %v", state, err)
	}
	return string(b)
}

// withPath is state with its return path replaced, as a forger writes one.
func withPath(state, path string) string {
	p := strings.Split(state, ".")
	p[4] = base64.RawURLEncoding.EncodeToString([]byte(path))
	return strings.Join(p, ".")
}

// idClaims are the claims of an ID token the fixture's issuer gives sub for
// nonce.
func idClaims(sub, nonce string) map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": issuer, "aud": clientID, "sub": sub, "name": "Ada", "nonce": nonce, "iat": now, "exp": now + 300}
}

func idToken(t *testing.T, s signer, claims map[string]any) string {
	t.Helper()
	tok, err := jwtx.Sign(s.priv, s.kid, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// goodToken is the issuer's token for the owner of project A, bound to at.
func goodToken(t *testing.T, at attemptT) string {
	t.Helper()
	return idToken(t, issuerSigner, idClaims(subOwnerA, at.nonce))
}

func form(tok, state string) string {
	return url.Values{"id_token": {tok}, "state": {state}}.Encode()
}

// sessionPost posts the pair to host's session endpoint with the cookie
// header given.
func (e *authEnv) sessionPost(t *testing.T, host, tok, state, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	r := post(host, "/-/auth/session?at="+strconv.FormatInt(time.Now().Unix(), 10), form(tok, state), "Sec-Fetch-Site", "cross-site", "Origin", "null")
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	return e.ask(t, r)
}

// nextOf is where a session or retry page navigates: its link, which the
// script follows, and its refresh, which must name the same address.
func nextOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	body := w.Body.String()
	a, m := nextRE.FindStringSubmatch(body), metaRE.FindStringSubmatch(body)
	if a == nil || m == nil || !isPage(w) {
		t.Fatalf("not a navigating page (%d): %s", w.Code, body)
	}
	script := scriptRE.FindStringSubmatch(body)
	if script == nil || script[1] != nextScript {
		t.Fatalf("the page's script is %q", script)
	}
	// The link is written as a URL (characters outside the URL syntax
	// percent-encoded), the refresh as text: the two name one address.
	next := html.UnescapeString(a[1])
	refresh, ok := strings.CutPrefix(html.UnescapeString(m[1]), "0;url=")
	nu, err1 := url.Parse(next)
	ru, err2 := url.Parse(refresh)
	if !ok || err1 != nil || err2 != nil || nu.Path != ru.Path || nu.Query().Encode() != ru.Query().Encode() || nu.Fragment != ru.Fragment ||
		nu.Host != "" || ru.Host != "" || !strings.HasPrefix(next, "/") || !strings.HasPrefix(refresh, "/") || strings.HasPrefix(refresh, "//") {
		t.Errorf("refresh %q does not name the link's address %q", m[1], next)
	}
	return next
}

// linkOf is the one link of a refusal page, "" when it has none.
func linkOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	m := linkRE.FindAllStringSubmatch(w.Body.String(), -1)
	switch len(m) {
	case 0:
		return ""
	case 1:
		return html.UnescapeString(m[0][1])
	}
	t.Fatalf("more than one link: %s", w.Body)
	return ""
}

// refusal checks one of the refusal pages: its status and words, nothing
// that redirects, and returns its link.
func refusal(t *testing.T, name string, w *httptest.ResponseRecorder, status int, text string) string {
	t.Helper()
	body := w.Body.String()
	if w.Code != status || !isPage(w) || !strings.Contains(body, "<p>"+html.EscapeString(text)+"</p>") {
		t.Errorf("%s: %d %q, want the page %d %q", name, w.Code, body, status, text)
	}
	if w.Header().Get("Location") != "" || w.Header().Get("Refresh") != "" || strings.Contains(body, "http-equiv") || strings.Contains(body, "<script") || strings.Contains(body, "<form") {
		t.Errorf("%s: the refusal page leads somewhere: %q %s", name, w.Header().Get("Location"), body)
	}
	return linkOf(t, w)
}

// retried checks the retry page and returns where it navigates.
func retried(t *testing.T, name string, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != 200 || w.Header().Get("Location") != "" {
		t.Fatalf("%s: %d %s, want the retry page", name, w.Code, w.Body)
	}
	for _, c := range cookies(w) {
		if strings.HasPrefix(c, sessionCookie+"=v1.") {
			t.Fatalf("%s: a session was set", name)
		}
	}
	return nextOf(t, w)
}

func TestLogin_CookieStateAndRedirect(t *testing.T) {
	e := newAuthEnv(t)
	const page = "/project/x?a=b&c=d#e"
	at := e.login(t, dhostA, "?return="+url.QueryEscape(page), navTo("none")...)
	q := at.loc.Query()
	sum := sha256.Sum256([]byte(at.r))
	want := map[string]string{"response_type": "id_token", "response_mode": "form_post", "client_id": clientID,
		"redirect_uri": signInO + "/-/auth/callback", "scope": "openid",
		"nonce": base64.RawURLEncoding.EncodeToString(sum[:]),
		"state": "v1." + refA + "." + at.a + ".0." + base64.RawURLEncoding.EncodeToString([]byte(page))}
	if at.loc.Scheme != "https" || at.loc.Host != "issuer.test" || at.loc.Path != "/authorize" || len(q) != len(want) {
		t.Fatalf("authorize address %q", at.loc)
	}
	for k, v := range want {
		if vs := q[k]; len(vs) != 1 || vs[0] != v {
			t.Errorf("authorize %s = %q, want %q", k, vs, v)
		}
	}
	if strings.Contains(at.loc.String(), at.r) {
		t.Error("the attempt's secret is in the redirect")
	}
	if len(at.state) > 1404 {
		t.Errorf("state of %d characters", len(at.state))
	}

	// Each attempt has an id and a secret of its own.
	if b := e.login(t, dhostA, ""); b.a == at.a || b.r == at.r || b.nonce == at.nonce {
		t.Error("two attempts share an id, a secret or a nonce")
	}

	// The fixed vector: the nonce of a secret, and with the random source
	// giving 00 01 02 … to each read, the cookie, the nonce and the state.
	const vecR, vecNonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "6oZqdX5MOLq_qBJ8vppAnT4fk6AP8UiP9zX8-Rev_9A"
	if got := nonceOf(vecR); got != vecNonce {
		t.Errorf("nonce of the vector secret: %q", got)
	}
	const vecRef = "abcdefghij0123456789"
	e.setTable(t, func(f *dashfile.File) { member(f, subOwnerA, vecRef) })
	old := rand.Reader
	rand.Reader = counting{}
	v := e.login(t, vecRef+"."+studioDom, "")
	rand.Reader = old
	if v.cookie != "__Host-sp-login-AAECAwQFBgc="+vecR || v.nonce != vecNonce || v.state != "v1."+vecRef+".AAECAwQFBgc.0.Lw" {
		t.Errorf("vector attempt: cookie %q, nonce %q, state %q", v.cookie, v.nonce, v.state)
	}

	// The sign-in host's target is "_", the default return path "/"; retry=1,
	// exactly so and once, makes n 1; the redirect URI is the sign-in host's
	// whatever host the login began on.
	for _, c := range []struct{ host, query, target, n, path string }{
		{signInH, "", "_", "0", "/"},
		{signInH, "?retry=1", "_", "1", "/"},
		{dhostB, "?return=%2Fp&retry=1", refB, "1", "/p"},
		{dhostB, "?retry=1&return=%2Fp", refB, "1", "/p"},
		{dhostA, "?retry=2", refA, "0", "/"},
		{dhostA, "?retry=01", refA, "0", "/"},
		{dhostA, "?retry=true", refA, "0", "/"},
		{dhostA, "?retry", refA, "0", "/"},
		{dhostA, "?RETRY=1", refA, "0", "/"},
		{dhostA, "?retry=1&retry=1", refA, "0", "/"},
		{dhostA, "?retry=1&retry=0", refA, "0", "/"},
		{dhostA, "?return=%2Fp&return=%2Fq", refA, "0", "/"},
		{dhostA, "?return=%2Fp&x=%zz", refA, "0", "/"},
		{dhostA, "?return=%2Fp;retry=1", refA, "0", "/"},
		{dhostA, "?other=1", refA, "0", "/"},
	} {
		at := e.login(t, c.host, c.query)
		s := strings.Split(at.state, ".")
		if len(s) != 5 || s[0] != "v1" || s[1] != c.target || s[2] != at.a || s[3] != c.n || statePath(t, at.state) != c.path {
			t.Errorf("%s%s: state %q, want target %s, n %s, path %s", c.host, c.query, at.state, c.target, c.n, c.path)
		}
		if got := at.loc.Query().Get("redirect_uri"); got != signInO+"/-/auth/callback" {
			t.Errorf("%s%s: redirect_uri %q", c.host, c.query, got)
		}
	}

	// Only GET.
	for _, m := range []string{"HEAD", "POST", "PUT", "DELETE"} {
		w := e.ask(t, hdr(rawReq(m, dhostA, "/-/auth/login")))
		if w.Code != 404 || code(w) != "not_found" || len(cookies(w)) != 0 || w.Header().Get("Location") != "" {
			t.Errorf("%s login: %d %s %q", m, w.Code, w.Body, cookies(w))
		}
	}

	// The authorisation address keeps a query of its own; one that is not an
	// HTTPS address with a host starts no attempt.
	e.setTable(t, func(f *dashfile.File) {
		f.Issuer.AuthorizeURL = "https://issuer.test/o/authorize?tenant=t1&scope=other"
	})
	at = e.login(t, dhostA, "")
	if q := at.loc.Query(); at.loc.Path != "/o/authorize" || q.Get("tenant") != "t1" || len(q["scope"]) != 1 || q.Get("scope") != "openid" || q.Get("state") != at.state {
		t.Errorf("authorize address with a query: %q", at.loc)
	}
	for _, bad := range []string{"http://issuer.test/authorize", "//issuer.test/authorize", "/authorize", "https:///authorize",
		"javascript:alert(1)", "https://issuer.test/authorize#frag", "https://issuer.test/%zz", "issuer.test/authorize"} {
		e.setTable(t, func(f *dashfile.File) { f.Issuer.AuthorizeURL = bad })
		w := e.ask(t, get(dhostA, "/-/auth/login"))
		if w.Code != 503 || code(w) != "unavailable" || len(cookies(w)) != 0 || w.Header().Get("Location") != "" {
			t.Errorf("authorize_url %q: %d %s, Location %q, Set-Cookie %q", bad, w.Code, w.Body, w.Header().Get("Location"), cookies(w))
		}
	}
}

// counting is a random source that gives 00 01 02 … to every read.
type counting struct{}

func (counting) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(i)
	}
	return len(b), nil
}

func TestLogin_SixteenCookiesClearedFirst(t *testing.T) {
	e := newAuthEnv(t)
	tb := loadSignIn(t)
	names := func(n int) (hdr []string, list []string) {
		for i := range n {
			name := fmt.Sprintf("__Host-sp-login-x%010d", i)
			list = append(list, name)
			hdr = append(hdr, name+"=v")
		}
		return hdr, list
	}
	for _, c := range tb.CookieCounts {
		pairs, list := names(c.Shown)
		for _, host := range []string{dhostA, signInH} {
			w := e.ask(t, get(host, "/-/auth/login", "Cookie", strings.Join(append(pairs, "other=1", "__Host-sp-session=x"), "; ")))
			sc := cookies(w)
			if w.Code != 302 || len(sc) != c.Cleared+1 {
				t.Fatalf("%s, %d login cookies: %d, %d Set-Cookie lines, want %d cleared and one set", host, c.Shown, w.Code, len(sc), c.Cleared)
			}
			for i := range c.Cleared {
				if sc[i] != clearLoginLine(list[i]) {
					t.Errorf("%s, %d login cookies: line %d is %q", host, c.Shown, i, sc[i])
				}
			}
			if !loginLineRE.MatchString(sc[len(sc)-1]) {
				t.Errorf("%s, %d login cookies: the last line is %q", host, c.Shown, sc[len(sc)-1])
			}
		}
	}

	// A name one character longer or shorter after the prefix, and every
	// other name of the table that is no login cookie, is neither counted
	// nor cleared: sixteen of them and fifteen login cookies clear nothing.
	pairs, _ := names(15)
	for i := range 16 {
		pairs = append(pairs, fmt.Sprintf("__Host-sp-login-x%09d=v", i), fmt.Sprintf("__Host-sp-login-x%011d=v", i))
	}
	for _, c := range tb.CookieNames {
		if !c.Login {
			pairs = append(pairs, c.Name+"=v")
		}
	}
	if sc := cookies(e.ask(t, get(dhostA, "/-/auth/login", "Cookie", strings.Join(pairs, "; ")))); len(sc) != 1 {
		t.Errorf("names that are no login cookies were counted or cleared: %q", sc)
	}
	// Control: one more login cookie, and the sixteen are cleared — they alone.
	sc := cookies(e.ask(t, get(dhostA, "/-/auth/login", "Cookie", strings.Join(append(pairs, "__Host-sp-login-AAAAAAAAAAA=v"), "; "))))
	if len(sc) != 17 || sc[15] != clearLoginLine("__Host-sp-login-AAAAAAAAAAA") {
		t.Errorf("sixteen login cookies among other names: %q", sc)
	}

	// A name is counted once however often it is sent, and cleared once.
	pairs, _ = names(15)
	if sc := cookies(e.ask(t, get(dhostA, "/-/auth/login", "Cookie", strings.Join(append(pairs, pairs[0], pairs[1]), "; ")))); len(sc) != 1 {
		t.Errorf("fifteen names, two of them twice: %q", sc)
	}
	pairs, _ = names(16)
	if sc := cookies(e.ask(t, get(dhostA, "/-/auth/login", "Cookie", strings.Join(append(pairs, pairs[0]), "; ")))); len(sc) != 17 {
		t.Errorf("sixteen names, one of them twice: %d lines", len(sc))
	}
}

// relayOf reads the relay page: where it posts and its fields.
func relayOf(t *testing.T, w *httptest.ResponseRecorder) (action string, fields url.Values) {
	t.Helper()
	body := w.Body.String()
	a := actionRE.FindAllStringSubmatch(body, -1)
	script := scriptRE.FindStringSubmatch(body)
	if w.Code != 200 || !isPage(w) || len(a) != 1 || script == nil || script[1] != relayScript || !strings.Contains(body, "<button>") {
		t.Fatalf("not the relay page (%d): %s", w.Code, body)
	}
	fields = url.Values{}
	for _, m := range hiddenRE.FindAllStringSubmatch(body, -1) {
		fields.Add(m[1], html.UnescapeString(m[2]))
	}
	if strings.Count(body, "<input") != len(fields) {
		t.Fatalf("relay page inputs: %s", body)
	}
	return html.UnescapeString(a[0][1]), fields
}

func TestCallback_VerifiesNothing_RelaysOnce(t *testing.T) {
	e := newAuthEnv(t)
	tb := loadSignIn(t)
	relayed := 0
	for _, c := range tb.Callback {
		if c.Status != 200 {
			continue
		}
		relayed++
		f := expandForm(c.Form, 0)
		target := expand(c.Target, 0)
		origin := signInO
		if target != "_" {
			origin = "https://" + target + "." + studioDom
		}
		before := time.Now().Unix()
		r := post(signInH, "/-/auth/callback", f.Encode(), "Sec-Fetch-Site", "cross-site", "Origin", "https://issuer.test",
			"Cookie", "__Host-sp-login-AAAAAAAAAAA=x; __Host-sp-session="+e.session(t, "_", issuer, subOwnerA, before-10, 3600))
		w := e.askAction(t, r, origin)
		after := time.Now().Unix()
		action, fields := relayOf(t, w)
		at, ok := strings.CutPrefix(action, origin+"/-/auth/session?at=")
		n, err := strconv.ParseInt(at, 10, 64)
		if !ok || err != nil || strconv.FormatInt(n, 10) != at || n < before || n > after {
			t.Errorf("%s: the relay posts to %q, want %s/-/auth/session?at=<%d to %d>", c.Name, action, origin, before, after)
		}
		if len(fields) != 2 || !slices.Equal(fields["id_token"], f["id_token"]) || !slices.Equal(fields["state"], f["state"]) {
			t.Errorf("%s: the relay's fields are %v", c.Name, fields)
		}
		if len(cookies(w)) != 0 || w.Header().Get("Location") != "" {
			t.Errorf("%s: Set-Cookie %q, Location %q", c.Name, cookies(w), w.Header().Get("Location"))
		}
		// It reads no cookie: without any the answer is the same.
		bare := e.askAction(t, post(signInH, "/-/auth/callback", f.Encode()), origin)
		strip := regexp.MustCompile(`at=[0-9]+`)
		if a, b := strip.ReplaceAllString(w.Body.String(), ""), strip.ReplaceAllString(bare.Body.String(), ""); a != b {
			t.Errorf("%s: the answer differs with cookies", c.Name)
		}
	}
	if relayed < 4 {
		t.Fatalf("%d relayed cases in the table", relayed)
	}

	// It verifies nothing: a token no issuer signed, a state whose attempt
	// never began and whose path is not one, are relayed unchanged.
	tok := "not.a-token_at.all"
	state := withPath("v1."+refA+".zzzzzzzzzzz.1.Lw", "//evil.test/")
	action, fields := relayOf(t, e.askAction(t, post(signInH, "/-/auth/callback", form(tok, state)), "https://"+dhostA))
	if fields.Get("id_token") != tok || fields.Get("state") != state || !strings.HasPrefix(action, "https://"+dhostA+"/-/auth/session?at=") {
		t.Errorf("relay: %q %v", action, fields)
	}

	// The target is a host of the studio domain whatever the request says
	// of itself.
	r := post(signInH, "/-/auth/callback?at=1&state=v1."+refB+".AAAAAAAAAAA.0.Lw&id_token=q", form(tok, state),
		"X-Forwarded-Host", "evil.test", "Origin", "https://evil.test", "Referer", "https://evil.test/x")
	if action, fields := relayOf(t, e.askAction(t, r, "https://"+dhostA)); !strings.HasPrefix(action, "https://"+dhostA+"/-/auth/session?at=") || fields.Get("id_token") != tok {
		t.Errorf("relay with a hostile request: %q %v", action, fields)
	}
}

func TestCallback_Refusals_400_NoRedirect(t *testing.T) {
	e := newAuthEnv(t)
	tb := loadSignIn(t)
	want := e.ask(t, post(signInH, "/-/auth/callback", "")).Body.String()
	check := func(name string, w *httptest.ResponseRecorder, sent string) {
		t.Helper()
		if link := refusal(t, name, w, 400, textDidNotComplete); link != "" {
			t.Errorf("%s: link %q", name, link)
		}
		if len(cookies(w)) != 0 {
			t.Errorf("%s: Set-Cookie %q", name, cookies(w))
		}
		// The page is one fixed text: nothing of the request is in it.
		if w.Body.String() != want {
			t.Errorf("%s: the refusal page differs from the fixed one: %s", name, w.Body)
		}
	}
	refused := 0
	for _, c := range tb.Callback {
		if c.Status != 400 {
			continue
		}
		refused++
		body := expandForm(c.Form, 0).Encode()
		check(c.Name, e.ask(t, post(signInH, "/-/auth/callback", body, "Sec-Fetch-Site", "cross-site", "Cookie", "__Host-sp-login-AAAAAAAAAAA=x")), body)
	}
	for _, c := range tb.Fields {
		if c.Callback == 400 {
			refused++
			check(c.Name, e.ask(t, post(signInH, "/-/auth/callback", expand(c.Body, 0))), c.Body)
		}
	}
	if refused < 30 {
		t.Fatalf("%d refused cases in the table", refused)
	}
	// A path whose encoding leaves bits unused is not the encoding of a path.
	for name, state := range map[string]string{"unused bits set": "v1." + refA + ".AAAAAAAAAAA.0.Lx", "unused bits set, longer": "v1." + refA + ".AAAAAAAAAAA.0.L2F"} {
		check(name, e.ask(t, post(signInH, "/-/auth/callback", form("x", state))), state)
	}
	if w := e.askAction(t, post(signInH, "/-/auth/callback", form("x", "v1."+refA+".AAAAAAAAAAA.0.L2E")), "https://"+dhostA); w.Code != 200 {
		t.Errorf("control, a path of two bytes: %d", w.Code)
	}
	good := form("idt.x", "v1."+refA+".AAAAAAAAAAA.0.Lw")
	// The fields come from a form body and from nowhere else.

	for name, r := range map[string]*http.Request{
		"fields in the query": post(signInH, "/-/auth/callback?"+good, ""),
		"no content type": func() *http.Request {
			r := post(signInH, "/-/auth/callback", good)
			r.Header.Del("Content-Type")
			return r
		}(),
		"a text body":          hdr(post(signInH, "/-/auth/callback", good), "X", "y"),
		"a multipart body":     post(signInH, "/-/auth/callback", good),
		"a JSON body":          post(signInH, "/-/auth/callback", `{"id_token":"idt.x","state":"v1.`+refA+`.AAAAAAAAAAA.0.Lw"}`),
		"a broken type":        post(signInH, "/-/auth/callback", good),
		"the type in capitals": post(signInH, "/-/auth/callback", good),
	} {
		switch name {
		case "a text body":
			r.Header.Set("Content-Type", "text/plain")
		case "a multipart body":
			r.Header.Set("Content-Type", "multipart/form-data; boundary=x")
		case "a JSON body":
			r.Header.Set("Content-Type", "application/json")
		case "a broken type":
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset")
		case "the type in capitals":
			r.Header.Set("Content-Type", "APPLICATION/X-WWW-FORM-URLENCODED; charset=UTF-8")
			if w := e.askAction(t, r, "https://"+dhostA); w.Code != 200 {
				t.Errorf("%s (control): %d", name, w.Code)
			}
			continue
		}
		check(name, e.ask(t, r), good)
	}
	// Control: the same pair in a form body is relayed.
	if w := e.askAction(t, post(signInH, "/-/auth/callback", good), "https://"+dhostA); w.Code != 200 {
		t.Fatalf("control: %d %s", w.Code, w.Body)
	}
}

func TestAuth_OtherMethods_405_NoLocation(t *testing.T) {
	e := newAuthEnv(t)
	tb := loadSignIn(t)
	at := e.login(t, dhostA, "")
	for _, m := range tb.OtherMethods {
		for _, c := range [][2]string{{signInH, "/-/auth/callback"}, {signInH, "/-/auth/session"}, {dhostA, "/-/auth/session"},
			{signInH, "/-/auth/callback?id_token=x&state=" + at.state}, {dhostA, "/-/auth/session?at=1"}} {
			for _, site := range []string{"", "cross-site", "same-origin"} {
				r := hdr(rawReq(m, c[0], c[1]), "Cookie", at.cookie)
				if site != "" {
					r.Header.Set("Sec-Fetch-Site", site)
				}
				w := e.ask(t, r)
				name := m + " " + c[0] + c[1] + " " + site
				if link := refusal(t, name, w, 405, textMethod); link != "" || len(cookies(w)) != 0 {
					t.Errorf("%s: link %q, Set-Cookie %q", name, link, cookies(w))
				}
			}
		}
	}
	// The callback exists on the sign-in host alone.
	for _, m := range append([]string{"POST"}, tb.OtherMethods...) {
		r := hdr(rawReq(m, dhostA, "/-/auth/callback"), "Content-Type", "application/x-www-form-urlencoded")
		if w := e.ask(t, r); w.Code != 404 || code(w) != "not_found" || w.Header().Get("Location") != "" {
			t.Errorf("%s /-/auth/callback on a dashboard host: %d %s", m, w.Code, w.Body)
		}
	}
	// Control: the post is taken on each.
	if w := e.askAction(t, post(signInH, "/-/auth/callback", form("x", at.state)), "https://"+dhostA); w.Code != 200 {
		t.Errorf("control, callback: %d", w.Code)
	}
	if w := e.sessionPost(t, dhostA, goodToken(t, at), at.state, at.cookie); w.Code != 200 {
		t.Errorf("control, session: %d", w.Code)
	}
}

// signedIn checks a successful session answer for sub on ref and returns
// the session and where the page navigates.
func (e *authEnv) signedIn(t *testing.T, name string, w *httptest.ResponseRecorder, at attemptT, ref, sub string) (dashtok.Session, string) {
	t.Helper()
	sc := cookies(w)
	if w.Code != 200 || w.Header().Get("Location") != "" || len(sc) != 2 || sc[0] != clearLoginLine(at.name) {
		t.Fatalf("%s: %d, Location %q, Set-Cookie %q, body %s", name, w.Code, w.Header().Get("Location"), sc, w.Body)
	}
	m := sessionLineRE.FindStringSubmatch(sc[1])
	if m == nil {
		t.Fatalf("%s: session cookie %q", name, sc[1])
	}
	max := e.d.table.cur.Load().file.Issuer.SessionSeconds
	s, err := dashtok.VerifySession(e.d.pub, m[1], max, time.Now())
	if err != nil {
		t.Fatalf("%s: the session does not verify: %v", name, err)
	}
	if now := time.Now().Unix(); s.Iss != issuer || s.Sub != sub || s.Ref != ref || s.Exp-s.Iat != max || s.Iat > now || s.Iat < now-30 ||
		m[2] != strconv.FormatInt(max, 10) {
		t.Errorf("%s: session %+v, Max-Age %s", name, s, m[2])
	}
	return s, nextOf(t, w)
}

func TestSession_ChecksInOrder(t *testing.T) {
	e := newAuthEnv(t)
	a, _, _ := keys()
	other := newSigner()

	// 1. The state's form, then its target: 400, and the attempt's cookie is
	// not read — it is not cleared, though the request carries it and a
	// token that would sign in.
	at := e.login(t, dhostA, "")
	tok := goodToken(t, at)
	onSignIn := e.login(t, signInH, "")
	for name, c := range map[string]struct{ host, state string }{
		"a state of another project":       {dhostB, at.state},
		"a state of a project, sign-in":    {signInH, at.state},
		"a state of the sign-in host":      {dhostA, strings.Replace(at.state, refA, "_", 1)},
		"a state of a ref outside":         {dhostA, strings.Replace(at.state, refA, refD, 1)},
		"another version":                  {dhostA, "v2" + at.state[2:]},
		"a sixth part":                     {dhostA, at.state + ".x"},
		"not a state":                      {dhostA, "v1.x"},
		"n of 2":                           {dhostA, strings.Replace(at.state, ".0.", ".2.", 1)},
		"a path not base64url":             {dhostA, at.state + "="},
		"an empty path":                    {dhostA, strings.TrimSuffix(at.state, "Lw")},
		"too long":                         {dhostA, at.state + strings.Repeat("A", 1404)},
		"the sign-in host's on a project":  {dhostA, onSignIn.state},
		"a trailing line end":              {dhostA, at.state + "\n"},
		"the attempt's id one byte longer": {dhostA, strings.Replace(at.state, at.a, at.a+"A", 1)},
	} {
		w := e.sessionPost(t, c.host, tok, c.state, at.cookie+"; "+onSignIn.cookie)
		if link := refusal(t, name, w, 400, textDidNotComplete); link != "" || len(cookies(w)) != 0 {
			t.Errorf("%s: link %q, Set-Cookie %q", name, link, cookies(w))
		}
	}

	// 2. The attempt's cookie, exactly once. Absent or twice is a binding
	// failure and the token is not verified: one with a bad signature, and
	// no token at all, give the answer a good one gives.
	bad := flipSig(tok)
	for name, cookie := range map[string]string{
		"no cookie":                         "",
		"another attempt's cookie":          onSignIn.cookie,
		"the cookie twice":                  at.cookie + "; " + at.cookie,
		"the cookie twice, values differ":   at.cookie + "; " + at.name + "=" + onSignIn.r,
		"a value that is no secret":         at.name + "=short",
		"a value one character longer":      at.cookie + "A",
		"a value outside the alphabet":      at.name + "=" + at.r[:42] + ".",
		"the name one character longer":     at.name + "A=" + at.r,
		"the name in other case":            strings.ToLower(at.name) + "=" + at.r,
		"the cookie under a prefixed name ": "x" + at.cookie,
	} {
		var bodies []string
		for _, tk := range []string{tok, bad, "x", idToken(t, other, idClaims(subOwnerA, at.nonce))} {
			w := e.sessionPost(t, dhostA, tk, at.state, cookie)
			if next := retried(t, name, w); next != "/-/auth/login?return=%2F&retry=1" {
				t.Errorf("%s: the retry page navigates to %q", name, next)
			}
			wantClear := 0
			if strings.Contains(cookie, at.name+"=") && !strings.HasPrefix(cookie, "x") {
				wantClear = 1 // read, so cleared — once, however often it came
			}
			if sc := cookies(w); len(sc) != wantClear || wantClear == 1 && sc[0] != clearLoginLine(at.name) {
				t.Errorf("%s: Set-Cookie %q", name, sc)
			}
			bodies = append(bodies, w.Body.String())
		}
		if slices.ContainsFunc(bodies, func(b string) bool { return b != bodies[0] }) {
			t.Errorf("%s: the answer depends on the token, which is not to be verified", name)
		}
	}

	// 3. The token. One that fails anything before its nonce is 401 at once,
	// whatever its nonce and whatever n; the cookie it was checked against
	// is cleared, and no session is set.
	now := time.Now().Unix()
	before := map[string]func(c map[string]any) (signer, map[string]any){
		"a wrong audience":             func(c map[string]any) (signer, map[string]any) { c["aud"] = "other"; return issuerSigner, c },
		"an audience array without it": func(c map[string]any) (signer, map[string]any) { c["aud"] = []string{"a", "b"}; return issuerSigner, c },
		"two audiences, no azp": func(c map[string]any) (signer, map[string]any) {
			c["aud"] = []string{clientID, "b"}
			return issuerSigner, c
		},
		"a wrong authorised party":  func(c map[string]any) (signer, map[string]any) { c["azp"] = "other"; return issuerSigner, c },
		"a wrong issuer":            func(c map[string]any) (signer, map[string]any) { c["iss"] = issuer + "/"; return issuerSigner, c },
		"expired":                   func(c map[string]any) (signer, map[string]any) { c["exp"] = now - 61; return issuerSigner, c },
		"issued too long ago":       func(c map[string]any) (signer, map[string]any) { c["iat"] = now - 700; return issuerSigner, c },
		"issued in the future":      func(c map[string]any) (signer, map[string]any) { c["iat"] = now + 120; return issuerSigner, c },
		"a nonce that is no string": func(c map[string]any) (signer, map[string]any) { c["nonce"] = 7; return issuerSigner, c },
		"a project's issuer key":    func(c map[string]any) (signer, map[string]any) { return a.iss, c },
		"a project's service key":   func(c map[string]any) (signer, map[string]any) { return a.svc, c },
		"an unknown key":            func(c map[string]any) (signer, map[string]any) { return other, c },
	}
	raw := map[string]func(at attemptT) string{
		"a bad signature": func(at attemptT) string { return flipSig(goodToken(t, at)) },
		"not a token":     func(at attemptT) string { return "x.y.z" },
		"an empty token":  func(at attemptT) string { return "" },
		"over 8 KiB":      func(at attemptT) string { return goodToken(t, at) + strings.Repeat("A", 8<<10) },
		"outside the alphabet": func(at attemptT) string {
			return strings.Replace(goodToken(t, at), ".", "+", 1)
		},
	}
	for _, retry := range []string{"", "?retry=1"} {
		for _, rightNonce := range []bool{true, false} {
			try := func(name string, tk func(at attemptT, nonce string) string) {
				t.Helper()
				at := e.login(t, dhostA, retry)
				nonce := at.nonce
				if !rightNonce {
					nonce = "x" + nonce
				}
				name = fmt.Sprintf("%s (retry %q, right nonce %v)", name, retry, rightNonce)
				w := e.sessionPost(t, dhostA, tk(at, nonce), at.state, at.cookie+"; __Host-sp-login-BBBBBBBBBBB=x")
				if link := refusal(t, name, w, 401, textFailed); link != "/-/auth/login?return=%2F" {
					t.Errorf("%s: link %q", name, link)
				}
				if sc := cookies(w); len(sc) != 1 || sc[0] != clearLoginLine(at.name) {
					t.Errorf("%s: Set-Cookie %q", name, sc)
				}
			}
			for name, mod := range before {
				try(name, func(at attemptT, nonce string) string {
					s, c := mod(idClaims(subOwnerA, nonce))
					return idToken(t, s, c)
				})
			}
			for name, mk := range raw {
				try(name, func(at attemptT, nonce string) string { return mk(at) })
			}
		}
	}
	// The subject and the name are read before the nonce too: each is a
	// refusal at once, at n 0, whatever the nonce.
	for name, mod := range map[string]func(c map[string]any){
		"no subject":         func(c map[string]any) { delete(c, "sub") },
		"an empty subject":   func(c map[string]any) { c["sub"] = "" },
		"a subject of 256":   func(c map[string]any) { c["sub"] = strings.Repeat("a", 256) },
		"a subject not text": func(c map[string]any) { c["sub"] = "a\nb" },
		"a name not text":    func(c map[string]any) { c["name"] = 7 },
	} {
		for _, nonce := range []string{"", "x"} {
			at := e.login(t, dhostA, "")
			c := idClaims(subOwnerA, nonce+at.nonce)
			mod(c)
			w := e.sessionPost(t, dhostA, idToken(t, issuerSigner, c), at.state, at.cookie)
			if link := refusal(t, name, w, 401, textFailed); link != "/-/auth/login?return=%2F" || len(cookies(w)) != 1 {
				t.Errorf("%s (nonce prefix %q): link %q, Set-Cookie %q", name, nonce, link, cookies(w))
			}
		}
	}
	// A dashboard key that left the table signs no one in.
	at = e.login(t, dhostA, "")
	tok = goodToken(t, at)
	e.setTable(t, func(f *dashfile.File) { f.Issuer.Keys = []dashfile.IssuerKey{issuerKey(other)} })
	if w := e.sessionPost(t, dhostA, tok, at.state, at.cookie); w.Code != 401 {
		t.Errorf("a key that left the table: %d", w.Code)
	}
	e.setTable(t, nil)

	// Control: the pair with its cookie signs in, on a project host and on
	// the sign-in host; the cookie is cleared and the session set.
	at = e.login(t, dhostA, "")
	e.signedIn(t, "control", e.sessionPost(t, dhostA, goodToken(t, at), at.state, at.cookie+"; "+onSignIn.cookie), at, refA, subOwnerA)
	e.signedIn(t, "control, sign-in host", e.sessionPost(t, signInH, goodToken(t, onSignIn), onSignIn.state, onSignIn.cookie), onSignIn, "_", subOwnerA)
}

// flipSig changes one bit of a token's signature.
func flipSig(tok string) string {
	i := strings.LastIndexByte(tok, '.') + 1
	c := byte('A')
	if tok[i] == 'A' {
		c = 'B'
	}
	return tok[:i] + string(c) + tok[i+1:]
}

func TestSession_BindingFailure_RetriesOnceThenRefuses(t *testing.T) {
	e := newAuthEnv(t)
	const page = "/project/x?a=b&c=d"
	ret := "?return=" + url.QueryEscape(page)
	again := "/-/auth/login?return=" + url.QueryEscape(page)
	wrongNonce := func(at attemptT) string { return idToken(t, issuerSigner, idClaims(subOwnerA, "x"+at.nonce)) }
	noNonce := func(at attemptT) string {
		c := idClaims(subOwnerA, at.nonce)
		delete(c, "nonce")
		return idToken(t, issuerSigner, c)
	}
	otherAttempt := e.login(t, dhostA, "")

	// n 0: the retry page, a 200 that navigates to the login with retry=1 —
	// for a token good in everything but its nonce, for the cookie's absence
	// and for its doubling.
	for name, c := range map[string]struct {
		tok    func(at attemptT) string
		cookie func(at attemptT) string
	}{
		"another nonce":        {wrongNonce, func(at attemptT) string { return at.cookie }},
		"no nonce":             {noNonce, func(at attemptT) string { return at.cookie }},
		"another attempt's":    {func(attemptT) string { return goodToken(t, otherAttempt) }, func(at attemptT) string { return at.cookie + "; " + otherAttempt.cookie }},
		"no cookie":            {func(at attemptT) string { return goodToken(t, at) }, func(attemptT) string { return "" }},
		"the cookie twice":     {func(at attemptT) string { return goodToken(t, at) }, func(at attemptT) string { return at.cookie + "; " + at.cookie }},
		"only another's there": {func(at attemptT) string { return goodToken(t, at) }, func(attemptT) string { return otherAttempt.cookie }},
	} {
		at := e.login(t, dhostA, ret)
		w := e.sessionPost(t, dhostA, c.tok(at), at.state, c.cookie(at))
		if next := retried(t, name, w); next != again+"&retry=1" {
			t.Errorf("%s: the retry page navigates to %q", name, next)
		}
		// The retry it asks for is an attempt marked as one.
		if s := strings.Split(e.login(t, dhostA, strings.TrimPrefix(nextOf(t, w), "/-/auth/login")).state, "."); s[3] != "1" || s[4] != base64.RawURLEncoding.EncodeToString([]byte(page)) {
			t.Errorf("%s: the retry's state %v", name, s)
		}
	}

	// n 1: the final page, 401, nothing that navigates. It names the cookie
	// when the request carried no login cookie at all, and not otherwise.
	for name, c := range map[string]struct {
		tok    func(at attemptT) string
		cookie func(at attemptT) string
		text   string
	}{
		"another nonce":            {wrongNonce, func(at attemptT) string { return at.cookie }, textFailed},
		"no nonce":                 {noNonce, func(at attemptT) string { return at.cookie }, textFailed},
		"the cookie twice":         {func(at attemptT) string { return goodToken(t, at) }, func(at attemptT) string { return at.cookie + "; " + at.cookie }, textFailed},
		"another attempt's cookie": {func(at attemptT) string { return goodToken(t, at) }, func(attemptT) string { return otherAttempt.cookie }, textFailed},
		"no cookie at all":         {func(at attemptT) string { return goodToken(t, at) }, func(attemptT) string { return "" }, textNoCookie},
		"only other names":         {func(at attemptT) string { return goodToken(t, at) }, func(at attemptT) string { return "other=1; __Host-sp-session=x; " + at.name + "A=" + at.r }, textNoCookie},
	} {
		at := e.login(t, dhostA, ret+"&retry=1")
		w := e.sessionPost(t, dhostA, c.tok(at), at.state, c.cookie(at))
		if link := refusal(t, name, w, 401, c.text); link != again {
			t.Errorf("%s: link %q, want %q", name, link, again)
		}
		for _, sc := range cookies(w) {
			if sc != clearLoginLine(at.name) {
				t.Errorf("%s: Set-Cookie %q", name, sc)
			}
		}
	}
	if textNoCookie == textFailed || !strings.Contains(textNoCookie, "cookie") || strings.Contains(textFailed, "cookie") {
		t.Errorf("the two wordings: %q and %q", textNoCookie, textFailed)
	}

	// The retry is for the binding and for nothing else: any other failure
	// of the token is refused at n 0.
	at := e.login(t, dhostA, ret)
	c := idClaims(subOwnerA, at.nonce)
	c["exp"] = time.Now().Unix() - 61
	if link := refusal(t, "expired at n 0", e.sessionPost(t, dhostA, idToken(t, issuerSigner, c), at.state, at.cookie), 401, textFailed); link != again {
		t.Errorf("expired at n 0: link %q", link)
	}

	// A retry that binds signs in.
	at = e.login(t, dhostA, ret+"&retry=1")
	if _, next := e.signedIn(t, "retry", e.sessionPost(t, dhostA, goodToken(t, at), at.state, at.cookie), at, refA, subOwnerA); next != page {
		t.Errorf("after the retry the page navigates to %q", next)
	}
}

func TestSession_SetsTheStrictHostCookie_AnswersAPage(t *testing.T) {
	e := newAuthEnv(t)
	const page = "/project/x?a=b&c=d#e"
	at := e.login(t, dhostA, "?return="+url.QueryEscape(page))
	w := e.sessionPost(t, dhostA, goodToken(t, at), at.state, at.cookie)
	s, next := e.signedIn(t, "project host", w, at, refA, subOwnerA)
	if next != page || s.Name != "Ada" {
		t.Errorf("the page navigates to %q; session %+v", next, s)
	}
	if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy %q", got)
	}
	// The cookie is this host's session: the rules accept it.
	tok := sessionLineRE.FindStringSubmatch(cookies(w)[1])[1]
	if dr := e.passes(t, "the session", get(dhostA, "/project/x", "Cookie", sessionCookie+"="+tok)); dr.Session != s || dr.Role != "owner" {
		t.Errorf("forwarded as %+v, role %q", dr.Session, dr.Role)
	}
	e.dexpect(t, "the session on another project", get(dhostB, "/api/x", "Cookie", sessionCookie+"="+tok), 401, "login_required")

	// A second post of the pair, the cookie gone, signs no one in.
	if next := retried(t, "second post", e.sessionPost(t, dhostA, goodToken(t, at), at.state, "")); !strings.HasSuffix(next, "&retry=1") {
		t.Errorf("second post navigates to %q", next)
	}

	// The lifetime is the table's; on the sign-in host the ref is "_", for a
	// principal who is no member of anything.
	e.setTable(t, func(f *dashfile.File) { f.Issuer.SessionSeconds = 900 })
	at = e.login(t, signInH, "")
	stranger := idToken(t, issuerSigner, idClaims("someone-else", at.nonce))
	w = e.sessionPost(t, signInH, stranger, at.state, at.cookie)
	if s, next := e.signedIn(t, "sign-in host", w, at, "_", "someone-else"); next != "/" || s.Exp-s.Iat != 900 {
		t.Errorf("sign-in host: %+v, next %q", s, next)
	}
	if got := sessionLineRE.FindStringSubmatch(cookies(w)[1])[2]; got != "900" {
		t.Errorf("Max-Age %s", got)
	}

	// What the return path holds is an address and nothing else: markup in
	// it reaches the page as text of the two attributes.
	hostile := `/p?q="><script>alert(1)</script>&r='><meta/http-equiv=refresh>#"x`
	at = e.login(t, dhostA, "?return="+url.QueryEscape(hostile))
	if statePath(t, at.state) != hostile {
		t.Fatalf("the path was not kept: %q", statePath(t, at.state))
	}
	w = e.sessionPost(t, dhostA, goodToken(t, at), at.state, at.cookie)
	body := w.Body.String()
	if strings.Count(body, "<script>") != 1 || strings.Count(body, "<meta") != 2 || strings.Count(body, "<a ") != 1 || strings.Contains(body, "alert(1)<") {
		t.Errorf("markup of the return path is in the page: %s", body)
	}
	if u, err := url.Parse(nextOf(t, w)); err != nil || u.Path != "/p" || u.Host != "" || u.Query().Get("q") != `"><script>alert(1)</script>` {
		t.Errorf("the page navigates to %q", nextOf(t, w))
	}
}

func TestSession_NameCleanedAndCutBeforeSigning(t *testing.T) {
	e := newAuthEnv(t)
	for name, c := range map[string]struct{ given, want string }{
		"controls and separators, cut": {"A\x00d" + string(rune(0x2028)) + "a" + string(rune(0x2029)) + "\x1f" + string(rune(0x85)) + "\x7f" + strings.Repeat("é", 150), "Ada" + strings.Repeat("é", 62)},
		"cut inside a four-byte rune":  {strings.Repeat("a", 126) + "😀", strings.Repeat("a", 126)},
		"128 bytes are kept":           {strings.Repeat("a", 124) + "😀", strings.Repeat("a", 124) + "😀"},
		"129 bytes":                    {strings.Repeat("a", 129), strings.Repeat("a", 128)},
		"markup stays, as text":        {`<b>&"x"</b>`, `<b>&"x"</b>`},
		"only controls":                {"\r\n\t", ""},
		"empty":                        {"", ""},
	} {
		at := e.login(t, dhostA, "")
		claims := idClaims(subOwnerA, at.nonce)
		claims["name"] = c.given
		s, _ := e.signedIn(t, name, e.sessionPost(t, dhostA, idToken(t, issuerSigner, claims), at.state, at.cookie), at, refA, subOwnerA)
		if s.Name != c.want {
			t.Errorf("%s: name %q, want %q", name, s.Name, c.want)
		}
		if len(s.Name) > 128 || !utf8.ValidString(s.Name) || strings.ContainsFunc(s.Name, func(r rune) bool { return unicode.IsControl(r) || r == 0x2028 || r == 0x2029 }) {
			t.Errorf("%s: name %q is not a clean one", name, s.Name)
		}
	}
	// No name at all signs in with an empty one.
	at := e.login(t, dhostA, "")
	claims := idClaims(subOwnerA, at.nonce)
	delete(claims, "name")
	if s, _ := e.signedIn(t, "no name", e.sessionPost(t, dhostA, idToken(t, issuerSigner, claims), at.state, at.cookie), at, refA, subOwnerA); s.Name != "" {
		t.Errorf("no name: %q", s.Name)
	}
	// Bytes that are not UTF-8 never reach a token.
	if got := displayName("a\xffb\xc3"); got != "ab" {
		t.Errorf("invalid bytes: %q", got)
	}
	if got := displayName(strings.Repeat("a", 127) + "\xc3\xa9"); got != strings.Repeat("a", 127) {
		t.Errorf("a rune across the cut: %q", got)
	}
}

func TestSession_NotPresented_RefusalPage(t *testing.T) {
	e := newAuthEnv(t)
	tb := loadSignIn(t)
	now := time.Now().Unix()
	mark := func(host string) string {
		return "https://" + host + "/-/auth/session?at=" + strconv.FormatInt(now-5, 10)
	}
	nav := func(host, target, referer string, pairs ...string) *http.Request {
		r := get(host, target, append(navTo("same-origin"), pairs...)...)
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		return r
	}
	// On a dashboard path that is not under /-/auth/: the page, never 404.
	const target = "/project/x?y=1"
	w := e.ask(t, nav(dhostA, target, mark(dhostA)))
	if link := refusal(t, "dashboard", w, 401, textUnpresented); link != "/-/auth/login?return=%2Fproject%2Fx%3Fy%3D1" {
		t.Errorf("link %q", link)
	}
	if len(cookies(w)) != 0 {
		t.Errorf("Set-Cookie %q", cookies(w))
	}
	if f, _ := e.seams(); f != 0 {
		t.Error("forwarded")
	}
	if textUnpresented == textNoCookie || textUnpresented == textFailed || !strings.Contains(textUnpresented, "session cookie") {
		t.Errorf("the page's own words: %q", textUnpresented)
	}
	// It reads and clears no cookie, and shows nothing of the request but
	// the path and query in its link.
	hostile := nav(dhostA, "/project/x?y=<script>alert(1)</script>", mark(dhostA), "Cookie",
		"__Host-sp-login-AAAAAAAAAAA=x; __Host-sp-session=garbage", "X-Forwarded-Host", "evil.test", "User-Agent", "<b>agent</b>")
	w = e.ask(t, hostile)
	if link := refusal(t, "hostile", w, 401, textUnpresented); link != "/-/auth/login?return=%2Fproject%2Fx%3Fy%3D%3Cscript%3Ealert%281%29%3C%2Fscript%3E" {
		t.Errorf("hostile: link %q", link)
	}
	if b := w.Body.String(); len(cookies(w)) != 0 || strings.Contains(b, "alert(1)<") || strings.Contains(b, "evil") || strings.Contains(b, "agent") {
		t.Errorf("hostile: Set-Cookie %q, body %s", cookies(w), b)
	}
	// A path and query that is no return path gives the link to "/".
	if link := refusal(t, "no return path", e.ask(t, nav(dhostA, "/project/x?u=//evil.test", mark(dhostA))), 401, textUnpresented); link != "/-/auth/login?return=%2F" {
		t.Errorf("no return path: link %q", link)
	}
	// Control: without the mark the rules redirect, and with a session the
	// request is forwarded.
	if w := e.do(nav(dhostA, target, "")); w.Code != 302 || w.Header().Get("Location") != "/-/auth/login?return="+url.QueryEscape(target) {
		t.Errorf("control, no mark: %d %q", w.Code, w.Header().Get("Location"))
	}
	e.passes(t, "control, a session", e.as(t, nav(dhostA, target, mark(dhostA)), refA, subOwnerA))

	// The sign-in host's picker is guarded the same way, by its own address.
	w = e.ask(t, nav(signInH, "/", mark(signInH)))
	if link := refusal(t, "picker", w, 401, textUnpresented); link != "/-/auth/login?return=%2F" {
		t.Errorf("picker: link %q", link)
	}
	for name, referer := range map[string]string{"no mark": "", "a project's mark": mark(dhostA), "the studio domain's": mark(studioDom),
		"an old mark": "https://" + signInH + "/-/auth/session?at=" + strconv.FormatInt(now-600, 10)} {
		if w := e.ask(t, nav(signInH, "/", referer)); w.Code != 302 || w.Header().Get("Location") != "/-/auth/login" {
			t.Errorf("picker, %s: %d %q", name, w.Code, w.Header().Get("Location"))
		}
	}
	// Not a navigation: the mark changes nothing.
	if w := e.ask(t, get(signInH, "/", "Referer", mark(signInH), "Sec-Fetch-Mode", "cors", "Sec-Fetch-Site", "same-origin")); w.Code != 401 || code(w) != "login_required" {
		t.Errorf("picker, a fetch with the mark: %d %s", w.Code, w.Body)
	}

	// The forms of the mark, by a fixed clock: the table the model reads too.
	at := time.Unix(now, 0)
	for _, c := range tb.Referers {
		r := nav(dhostA, "/p", expand(c.Referer, now))
		if got := e.d.unpresented(r, refA, at); got != c.Marked {
			t.Errorf("Referer %q: marked %v, want %v", c.Referer, got, c.Marked)
		}
	}
}

func TestReturnPath_BothEnds(t *testing.T) {
	e := newAuthEnv(t)
	tb := loadSignIn(t)
	follow := func(name, path string) string {
		t.Helper()
		at := e.login(t, dhostA, "")
		state := withPath(at.state, path)
		if len(state) > 1404 {
			t.Fatalf("%s: a state of %d characters", name, len(state))
		}
		w := e.sessionPost(t, dhostA, goodToken(t, at), state, at.cookie)
		_, next := e.signedIn(t, name, w, at, refA, subOwnerA)
		return next
	}
	kept := 0
	for _, c := range tb.ReturnPaths {
		in, want := expand(c.In, 0), expand(c.Want, 0)
		if in == want {
			kept++
		}
		if got := returnPath(in); got != want {
			t.Errorf("returnPath(%q) = %q, want %q", in, got, want)
		}
		// At the login endpoint, before it goes into the state.
		if got := statePath(t, e.login(t, dhostA, "?return="+url.QueryEscape(in)).state); got != want {
			t.Errorf("login: return %q written as %q, want %q", in, got, want)
		}
		// At the session endpoint, in a state forged after the login. An
		// empty path is no state at all, and neither is one whose path makes
		// it longer than a state can be: both are refused as states.
		if at := e.login(t, dhostA, ""); in == "" || len(withPath(at.state, in)) > 1404 {
			w := e.sessionPost(t, dhostA, goodToken(t, at), withPath(at.state, in), at.cookie)
			if link := refusal(t, c.In, w, 400, textDidNotComplete); link != "" || len(cookies(w)) != 0 {
				t.Errorf("session: a state with %q: link %q, Set-Cookie %q", c.In, link, cookies(w))
			}
			continue
		}

		u, err := url.Parse(follow(c.In, in))
		w, werr := url.Parse(want)
		if err != nil || werr != nil || u.Host != "" || u.Scheme != "" || u.Path != w.Path || u.Query().Encode() != w.Query().Encode() || u.Fragment != w.Fragment {
			t.Errorf("session: a state with %q is followed to %q, want %q", in, u, want)
		}
	}
	if kept < 15 || len(tb.ReturnPaths)-kept < 40 {
		t.Fatalf("%d kept and %d refused paths in the table", kept, len(tb.ReturnPaths)-kept)
	}
	for _, bad := range tb.Forged {
		if got := follow(bad, expand(bad, 0)); got != "/" {
			t.Errorf("a forged state with %q is followed to %q", bad, got)
		}
	}
	// What is kept is kept byte for byte.
	const page = "/project/x?a=b#c"
	if got := follow("kept", page); got != page {
		t.Errorf("%q followed to %q", page, got)
	}
	// The retry page and the refusal's link carry the validated path too.
	at := e.login(t, dhostA, "")
	if next := retried(t, "forged, retry", e.sessionPost(t, dhostA, "x", withPath(at.state, "//evil.test/"), "")); next != "/-/auth/login?return=%2F&retry=1" {
		t.Errorf("retry page of a forged state navigates to %q", next)
	}
	at = e.login(t, dhostA, "?retry=1")
	if link := refusal(t, "forged, final", e.sessionPost(t, dhostA, "x", withPath(at.state, "https://evil.test/"), ""), 401, textNoCookie); link != "/-/auth/login?return=%2F" {
		t.Errorf("final page of a forged state links to %q", link)
	}
}

func TestPicker_OnlyThePrincipalsProjects_NamesEscaped(t *testing.T) {
	e := newAuthEnv(t)
	const markup = `<img src=x onerror=alert(1)>"'&`
	e.setTable(t, func(f *dashfile.File) {
		member(f, subOwnerA, refC)
		p := f.Projects[refC]
		p.Name = markup
		f.Projects[refC] = p
		f.Projects[refD] = dashfile.Project{Name: "Theirs", Members: []dashfile.Member{{Iss: "https://other.test", Sub: subOwnerA, Role: "owner"}}}
	})
	now := time.Now().Unix()
	picker := func(sub, name string) *httptest.ResponseRecorder {
		tok, err := dashtok.SignSession(e.priv, dashtok.Session{Iss: issuer, Sub: sub, Name: name, Ref: "_", Iat: now - 10, Exp: now + 3590})
		if err != nil {
			t.Fatal(err)
		}
		return e.ask(t, get(signInH, "/", append(navTo("none"), "Cookie", sessionCookie+"="+tok)...))
	}
	links := func(w *httptest.ResponseRecorder) []string {
		var out []string
		for _, m := range linkRE.FindAllStringSubmatch(w.Body.String(), -1) {
			out = append(out, html.UnescapeString(m[1]))
		}
		return out
	}
	w := picker(subOwnerA, `<i>Ada</i> & "co"`)
	body := w.Body.String()
	want := []string{"https://" + dhostA + "/", "https://" + refC + "." + studioDom + "/", "/-/auth/logout"}
	if w.Code != 200 || !isPage(w) || !slices.Equal(links(w), want) {
		t.Fatalf("picker: %d, links %q, want %q\n%s", w.Code, links(w), want, body)
	}
	if strings.Contains(body, refB) || strings.Contains(body, refD) || strings.Contains(body, "Theirs") {
		t.Errorf("another principal's project is on the page: %s", body)
	}
	if strings.Contains(body, "<img") || strings.Contains(body, "<i>") || !strings.Contains(body, html.EscapeString(markup)) ||
		!strings.Contains(body, html.EscapeString(`<i>Ada</i> & "co"`)) || strings.Contains(body, "<script") {
		t.Errorf("names are not escaped: %s", body)
	}
	if len(cookies(w)) != 0 {
		t.Errorf("Set-Cookie %q", cookies(w))
	}
	// A member of one project sees one; a principal of none sees none.
	if got := links(picker(subOwnerB, "")); !slices.Equal(got, []string{"https://" + dhostB + "/", "/-/auth/logout"}) {
		t.Errorf("the owner of B: %q", got)
	}
	if got := links(picker("nobody", "")); !slices.Equal(got, []string{"/-/auth/logout"}) {
		t.Errorf("a principal of no project: %q", got)
	}
	// The table is read on every request.
	e.setTable(t, func(f *dashfile.File) { member(f, "nobody", refB) })
	if got := links(picker("nobody", "")); !slices.Equal(got, []string{"https://" + dhostB + "/", "/-/auth/logout"}) {
		t.Errorf("after the table changed: %q", got)
	}
}

func TestPicker_NoSession_NavigationRedirected_Other401(t *testing.T) {
	e := newAuthEnv(t)
	now := time.Now().Unix()
	e.setTable(t, func(f *dashfile.File) {
		f.Revoked = []dashfile.Revocation{{Iss: issuer, Sub: subDevA, NotBefore: now - 100}}
	})
	other, _ := dashtok.SignSession(otherKey(t), dashtok.Session{Iss: issuer, Sub: subOwnerA, Ref: "_", Iat: now - 10, Exp: now + 100})
	good := e.session(t, "_", issuer, subOwnerA, now-10, 3600)
	for name, cookie := range map[string]string{
		"no cookie":                "",
		"a project's session":      sessionCookie + "=" + e.session(t, refA, issuer, subOwnerA, now-10, 3600),
		"expired":                  sessionCookie + "=" + e.session(t, "_", issuer, subOwnerA, now-7200, 3600),
		"revoked":                  sessionCookie + "=" + e.session(t, "_", issuer, subDevA, now-101, 3600),
		"another issuer":           sessionCookie + "=" + e.session(t, "_", "https://other.test", subOwnerA, now-10, 3600),
		"another key":              sessionCookie + "=" + other,
		"twice":                    sessionCookie + "=" + good + "; " + sessionCookie + "=" + good,
		"garbage":                  sessionCookie + "=x",
		"longer than the table's":  sessionCookie + "=" + e.session(t, "_", issuer, subOwnerA, now-10, 28801),
		"under another name":       "__Host-sp-sessions=" + good,
		"under the unprefixed one": "sp-session=" + good,
	} {
		with := func(r *http.Request) *http.Request {
			if cookie != "" {
				r.Header.Set("Cookie", cookie)
			}
			return r
		}
		// A navigation is sent to sign-in on this host.
		for _, pairs := range [][]string{navTo("none"), navTo("cross-site"), {"Sec-Fetch-Mode", "navigate"}, {"Accept", "text/html,*/*"},
			{"Accept", "application/xhtml+xml, Text/HTML;q=0.9"}} {
			for _, target := range []string{"/", "/?x=1"} {
				w := e.ask(t, with(get(signInH, target, pairs...)))
				if w.Code != 302 || w.Header().Get("Location") != "/-/auth/login" || len(cookies(w)) != 0 || w.Body.Len() != 0 {
					t.Errorf("%s, navigation %v to %s: %d %q %s", name, pairs, target, w.Code, w.Header().Get("Location"), w.Body)
				}
			}
		}
		// Anything else is 401.
		for _, pairs := range [][]string{nil, {"Accept", "application/json"}, {"Sec-Fetch-Mode", "cors", "Sec-Fetch-Site", "same-origin"},
			{"Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Site", "same-origin", "Sec-Fetch-Dest", "image"}} {
			w := e.ask(t, with(get(signInH, "/", pairs...)))
			if w.Code != 401 || code(w) != "login_required" || w.Header().Get("Location") != "" || len(cookies(w)) != 0 {
				t.Errorf("%s, %v: %d %s", name, pairs, w.Code, w.Body)
			}
		}
	}
	// Controls: the session shows the picker; one issued at the revocation's
	// second does too.
	for name, tok := range map[string]string{"control": good, "issued at the revocation": e.session(t, "_", issuer, subDevA, now-100, 3600)} {
		if w := e.ask(t, get(signInH, "/", append(navTo("none"), "Cookie", sessionCookie+"="+tok)...)); w.Code != 200 || !isPage(w) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	// Only GET.
	for _, m := range []string{"HEAD", "POST", "PUT", "DELETE"} {
		if w := e.ask(t, hdr(rawReq(m, signInH, "/"), "Cookie", sessionCookie+"="+good)); w.Code != 404 || code(w) != "not_found" {
			t.Errorf("%s /: %d %s", m, w.Code, w.Body)
		}
	}
}

func TestAuth_SameOriginRuleExceptTheTwoPosts(t *testing.T) {
	e := newAuthEnv(t)
	good := e.session(t, "_", issuer, subOwnerA, time.Now().Unix()-10, 3600)
	type c struct {
		method, host, target string
		pairs                []string
		status               int
		code                 string
	}
	xo := func(method, host, target string, pairs ...string) c {
		return c{method, host, target, pairs, 403, "cross_origin"}
	}
	for _, c := range []c{
		xo("GET", dhostA, "/-/auth/login", "Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "cors"),
		xo("GET", dhostA, "/-/auth/login", "Sec-Fetch-Site", "same-site", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "iframe"),
		xo("GET", dhostA, "/-/auth/login", "Sec-Fetch-Site", "same-site", "Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Dest", "document"),
		xo("GET", dhostA, "/-/auth/login", "Sec-Fetch-Site", "cross-site"),
		xo("GET", dhostA, "/-/auth/login", "Sec-Fetch-Site", "same-origin", "Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "cors"),
		xo("GET", dhostA, "/-/auth/login", "Sec-Fetch-Site", "Same-Origin"),
		xo("GET", dhostA, "/-/auth/login", "Sec-Fetch-Site", ""),
		xo("GET", dhostA, "/-/auth/logout", "Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Dest", "image"),
		xo("POST", dhostA, "/-/auth/logout", "Sec-Fetch-Site", "cross-site"),
		xo("POST", dhostA, "/-/auth/login", append(navTo("cross-site"), "Content-Type", "application/x-www-form-urlencoded")...),
		xo("POST", dhostA, "/-/auth/callback", "Sec-Fetch-Site", "cross-site"),
		xo("GET", signInH, "/", "Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "cors", "Cookie", sessionCookie+"="+good),
		xo("GET", signInH, "/", "Sec-Fetch-Site", "same-site", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "iframe", "Cookie", sessionCookie+"="+good),
		xo("POST", signInH, "/", "Sec-Fetch-Site", "cross-site"),
		xo("GET", signInH, "/-/auth/signed-out", "Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Dest", "image"),
		xo("GET", signInH, "/api/x", navTo("cross-site")...),
		xo("GET", signInH, "/API/x", navTo("cross-site")...),
		xo("GET", signInH, "/x", "Sec-Fetch-Site", "cross-site"),
		// A top-level navigation by GET to a page from another site is let in.
		{"GET", dhostA, "/-/auth/login", navTo("cross-site"), 302, ""},
		{"GET", dhostA, "/-/auth/login", navTo("same-site"), 302, ""},
		{"GET", dhostA, "/-/auth/logout", navTo("cross-site"), 302, ""},
		{"GET", signInH, "/-/auth/signed-out", navTo("cross-site"), 200, ""},
		{"GET", signInH, "/", append(navTo("cross-site"), "Cookie", sessionCookie+"="+good), 200, ""},
		{"GET", signInH, "/x", navTo("cross-site"), 404, "not_found"},
		// The same origin, a request the user typed, and no header at all.
		{"GET", dhostA, "/-/auth/login", []string{"Sec-Fetch-Site", "same-origin", "Sec-Fetch-Mode", "cors"}, 302, ""},
		{"GET", dhostA, "/-/auth/login", []string{"Sec-Fetch-Site", "none"}, 302, ""},
		{"GET", dhostA, "/-/auth/login", nil, 302, ""},
		{"GET", signInH, "/api/x", navTo("same-origin"), 404, "not_found"},
		// The two posts are exempt: they are judged by their own checks.
		{"POST", signInH, "/-/auth/callback", []string{"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document"}, 400, ""},
		{"POST", signInH, "/-/auth/session", []string{"Sec-Fetch-Site", "cross-site"}, 400, ""},
		{"POST", dhostA, "/-/auth/session", []string{"Sec-Fetch-Site", "cross-site", "Origin", "null"}, 400, ""},
		{"POST", dhostA, "/-/auth/session", []string{"Sec-Fetch-Site", "same-site", "Origin", "https://evil.test"}, 400, ""},
	} {
		r := hdr(rawReq(c.method, c.host, c.target), c.pairs...)
		w := e.ask(t, r)
		if w.Code != c.status || code(w) != c.code {
			t.Errorf("%s %s%s %v: %d %s, want %d %q", c.method, c.host, c.target, c.pairs, w.Code, w.Body, c.status, c.code)
		}
		if c.status == 403 && (len(cookies(w)) != 0 || w.Header().Get("Location") != "") {
			t.Errorf("%s %s%s %v: Set-Cookie %q, Location %q", c.method, c.host, c.target, c.pairs, cookies(w), w.Header().Get("Location"))
		}
	}
	// A relay from another origin that carries the pair is taken: the
	// session endpoint makes no Origin check.
	at := e.login(t, dhostA, "")
	r := post(dhostA, "/-/auth/session?at=1", form(goodToken(t, at), at.state), "Sec-Fetch-Site", "cross-site", "Origin", "null", "Cookie", at.cookie)
	e.signedIn(t, "cross-site relay", e.ask(t, r), at, refA, subOwnerA)
}

func TestAuth_NoIssuer_503(t *testing.T) {
	e := newAuthEnv(t)
	at := e.login(t, dhostA, "")
	tok := goodToken(t, at)
	now := time.Now().Unix()
	good := e.session(t, "_", issuer, subOwnerA, now-10, 3600)
	mark := "https://" + dhostA + "/-/auth/session?at=" + strconv.FormatInt(now-5, 10)
	reqs := func() map[string]*http.Request {
		return map[string]*http.Request{
			"login":           get(dhostA, "/-/auth/login", "Cookie", at.cookie),
			"login, sign-in":  get(signInH, "/-/auth/login"),
			"callback":        post(signInH, "/-/auth/callback", form(tok, at.state)),
			"session":         post(dhostA, "/-/auth/session", form(tok, at.state), "Cookie", at.cookie),
			"logout":          get(dhostA, "/-/auth/logout", "Cookie", at.cookie+"; "+sessionCookie+"=x"),
			"logout, sign-in": get(signInH, "/-/auth/logout", "Cookie", sessionCookie+"="+good),
			"signed-out":      get(signInH, "/-/auth/signed-out", "Cookie", at.cookie),
			"picker":          get(signInH, "/", append(navTo("none"), "Cookie", sessionCookie+"="+good)...),
			"another path":    get(signInH, "/x"),
			"other method":    get(signInH, "/-/auth/callback"),
			"not presented":   get(dhostA, "/p", append(navTo("same-origin"), "Referer", mark)...),
		}
	}
	// Control: with an issuer none of them is 503.
	for name, r := range reqs() {
		if w := e.do(r); w.Code == 503 {
			t.Fatalf("control, %s: 503", name)
		}
	}
	e.setTable(t, func(f *dashfile.File) { f.Issuer = nil })
	for name, r := range reqs() {
		w := e.ask(t, r)
		if w.Code != 503 || code(w) != "unavailable" || w.Header().Get("Retry-After") != "5" || len(cookies(w)) != 0 || w.Header().Get("Location") != "" {
			t.Errorf("%s: %d %s, Set-Cookie %q, Location %q", name, w.Code, w.Body, cookies(w), w.Header().Get("Location"))
		}
	}
	// A table that went away, or lost the host's project, after the request
	// was classified: 503 and 404, as the class switch answers them.
	dr := func(ref string) *dashRequest {
		return &dashRequest{Ref: ref, Dash: e.d, Path: []string{"-", "auth", "login"}}
	}
	e.setTable(t, func(f *dashfile.File) { delete(f.Projects, refB) })
	w := httptest.NewRecorder()
	serveSignIn(w, get(dhostB, "/-/auth/login"), dr(refB))
	if w.Code != 404 || code(w) != "not_found" || len(cookies(w)) != 0 {
		t.Errorf("a project that left the table: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	serveSignIn(w, get(dhostA, "/-/auth/login"), dr(refA))
	if w.Code != 302 {
		t.Errorf("control, a project of the table: %d %s", w.Code, w.Body)
	}
	if err := os.Remove(e.path()); err != nil {
		t.Fatal(err)
	}
	if err := e.d.table.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{refA, "_"} {
		w = httptest.NewRecorder()
		serveSignIn(w, get(dhostA, "/-/auth/login"), dr(ref))
		if w.Code != 503 || code(w) != "unavailable" || len(cookies(w)) != 0 {
			t.Errorf("no table, ref %s: %d %s", ref, w.Code, w.Body)
		}
	}
}

// failing is a body that must not be read.
type failing struct{ t *testing.T }

func (f failing) Read([]byte) (int, error) {
	f.t.Error("the body of a request over the cap was read")
	return 0, io.EOF
}

func TestAuth_BodyCap(t *testing.T) {
	e := newAuthEnv(t)
	at := e.login(t, dhostA, "")
	const limit = 16 << 10
	pair := form("x", at.state)
	sized := func(n int) string { return pair + "&pad=" + strings.Repeat("p", n-len(pair)-len("&pad=")) }
	for _, c := range []struct {
		name string
		size int
		ok   bool
	}{{"at the cap", limit, true}, {"one byte over", limit + 1, false}, {"far over", 1 << 20, false}} {
		body := sized(c.size)
		if len(body) != c.size {
			t.Fatal("size")
		}
		// The callback relays what fits; the session endpoint, without the
		// cookie, answers the retry page for it.
		for _, ep := range []struct{ host, path, action string }{{signInH, "/-/auth/callback", "https://" + dhostA}, {dhostA, "/-/auth/session", "'none'"}} {
			for _, declared := range []bool{true, false} {
				r := post(ep.host, ep.path, body)
				if !declared {
					r.ContentLength = -1 // a body of unknown length is cut at the cap
				}
				name := fmt.Sprintf("%s, %s, declared %v", c.name, ep.path, declared)
				if c.ok {
					if w := e.askAction(t, r, ep.action); w.Code != 200 {
						t.Errorf("%s: %d", name, w.Code)
					}
					continue
				}
				w := e.ask(t, r)
				if link := refusal(t, name, w, 400, textDidNotComplete); link != "" || len(cookies(w)) != 0 {
					t.Errorf("%s: link %q, Set-Cookie %q", name, link, cookies(w))
				}
			}
		}
	}
	// A declared length over the cap is refused unread.
	for _, ep := range [][2]string{{signInH, "/-/auth/callback"}, {dhostA, "/-/auth/session"}} {
		r := post(ep[0], ep[1], "")
		r.Body = io.NopCloser(failing{t})
		r.ContentLength = limit + 1
		if w := e.ask(t, r); w.Code != 400 {
			t.Errorf("%s, declared over the cap: %d", ep[1], w.Code)
		}
	}
}

func TestSignInHost_UnknownPath_404(t *testing.T) {
	e := newAuthEnv(t)
	good := sessionCookie + "=" + e.session(t, "_", issuer, subOwnerA, time.Now().Unix()-10, 3600)
	for _, c := range [][2]string{
		{signInH, "/x"}, {signInH, "/project/" + refA}, {signInH, "/api/x"}, {signInH, "/api"}, {signInH, "/-"}, {signInH, "/-/auth"},
		{signInH, "/-/auth/unknown"}, {signInH, "/-/auth/login/x"}, {signInH, "/-/auth/Login"}, {signInH, "/-/auth/log%69n"},
		{signInH, "/-/auth/signed-out/x"}, {signInH, "/-/Auth/login"}, {signInH, "/%2d/auth/login"}, {signInH, "/favicon.ico"},
		{signInH, "/index.html"}, {signInH, "/-/auth/session/x"}, {signInH, "/-/auth/callback/x"},
		{dhostA, "/-/auth/unknown"}, {dhostA, "/-/auth/signed-out"}, {dhostA, "/-/auth/signed-out?more=1"}, {dhostA, "/-/auth/Login"},
		{dhostA, "/-/auth/login/x"}, {dhostA, "/-/auth/logout/" + refB}, {dhostA, "/-/auth/log%6fut"},
	} {
		for _, pairs := range [][]string{nil, navTo("none"), {"Cookie", good + "; __Host-sp-login-AAAAAAAAAAA=x"}} {
			w := e.ask(t, get(c[0], c[1], pairs...))
			if w.Code != 404 || code(w) != "not_found" || len(cookies(w)) != 0 || w.Header().Get("Location") != "" {
				t.Errorf("%s%s %v: %d %s, Set-Cookie %q", c[0], c[1], pairs, w.Code, w.Body, cookies(w))
			}
		}
	}
	if f, _ := e.seams(); f != 0 {
		t.Errorf("%d requests were forwarded", f)
	}
}

// tBrowser follows a top-level navigation through the gateway as a browser
// does: redirects, the relay's form, the navigating pages, the issuer's page
// (played here: it signs a token for sub with the request's nonce and posts
// it with the state and one further field). It keeps cookies by host —
// unless told to drop a kind — and sends a SameSite=Strict cookie only on a
// navigation that stayed on its origin or that the user typed.
type tBrowser struct {
	e                      *authEnv
	jar                    map[string]map[string]string
	sub                    string
	dropLogin, dropSession int // answers whose login or session cookie is not kept
	dash, issuer           int // requests to the dashboard's hosts and to the issuer
	seen                   []string
}

func (e *authEnv) browser(sub string) *tBrowser {
	return &tBrowser{e: e, jar: map[string]map[string]string{}, sub: sub}
}

func (b *tBrowser) open(t *testing.T, start string) (final string, w *httptest.ResponseRecorder) {
	t.Helper()
	method, u, body, site, referer := "GET", start, "", "none", ""
	for range 40 {
		pu, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		b.seen = append(b.seen, method+" "+u)
		if pu.Host == "issuer.test" {
			b.issuer++
			q := pu.Query()
			if q.Get("redirect_uri") != signInO+"/-/auth/callback" || q.Get("response_mode") != "form_post" || q.Get("response_type") != "id_token" || q.Get("client_id") != clientID {
				t.Fatalf("authorisation request %q", u)
			}
			tok := idToken(t, issuerSigner, idClaims(b.sub, q.Get("nonce")))
			method, u, site, referer = "POST", q.Get("redirect_uri"), "cross-site", ""
			body = url.Values{"id_token": {tok}, "state": {q.Get("state")}, "session_state": {"s"}}.Encode()
			continue
		}
		b.dash++
		target := pu.RequestURI()
		var r *http.Request
		if method == "POST" {
			r = post(pu.Host, target, body, navTo(site)...)
		} else {
			r = get(pu.Host, target, navTo(site)...)
		}
		var cs []string
		for n, v := range b.jar[pu.Host] {
			if n == sessionCookie && site != "same-origin" && site != "none" {
				continue // SameSite=Strict
			}
			cs = append(cs, n+"="+v)
		}
		if len(cs) > 0 {
			r.Header.Set("Cookie", strings.Join(cs, "; "))
		}
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		w = b.e.do(r)
		for _, l := range cookies(w) {
			nv, attrs, _ := strings.Cut(l, ";")
			n, v, _ := strings.Cut(nv, "=")
			if b.jar[pu.Host] == nil {
				b.jar[pu.Host] = map[string]string{}
			}
			switch {
			case strings.Contains(attrs, "Max-Age=0"):
				delete(b.jar[pu.Host], n)
			case n == sessionCookie && b.dropSession > 0:
				b.dropSession--
			case n != sessionCookie && b.dropLogin > 0:
				b.dropLogin--
			default:
				b.jar[pu.Host][n] = v
			}
		}
		page := w.Body.String()
		referer = ""
		switch {
		case w.Code == 302:
			loc, err := pu.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if loc.Host != pu.Host && site != "none" || site == "cross-site" {
				site = "cross-site"
			} else if loc.Host != pu.Host {
				site = "cross-site"
			}
			method, u, body = "GET", loc.String(), ""
		case actionRE.MatchString(page):
			action, fields := relayOf(t, w)
			au, _ := url.Parse(action)
			site = "cross-site"
			if au.Host == pu.Host {
				site = "same-origin"
			}
			method, u, body = "POST", action, fields.Encode()
		case nextRE.MatchString(page):
			loc, _ := pu.Parse(nextOf(t, w))
			method, u, body, site, referer = "GET", loc.String(), "", "same-origin", u
		default:
			return u, w
		}
	}
	t.Fatalf("no end after 40 requests: %v", b.seen)
	return "", nil
}

func (b *tBrowser) counts() (dash, issuer int) {
	d, i := b.dash, b.issuer
	b.dash, b.issuer = 0, 0
	return d, i
}

// TestSignIn_EndToEnd_RequestCounts: whole sign-ins through the gateway, as
// a browser follows them, with what each costs in requests.
func TestSignIn_EndToEnd_RequestCounts(t *testing.T) {
	e := newAuthEnv(t)
	pageA := "https://" + dhostA + "/project/x?a=b"

	// From a project origin: 5 requests to the dashboard's hosts, one to
	// the issuer, ending on the page asked for with the principal's session.
	b := e.browser(subOwnerA)
	e.resetSeams()
	final, w := b.open(t, pageA)
	if d, i := b.counts(); final != pageA || w.Code != 200 || d != 5 || i != 1 {
		t.Fatalf("sign-in from a project origin: %s %d, %d and %d requests: %v", final, w.Code, d, i, b.seen)
	}
	if dr := e.lastFwd(t); dr.Session.Sub != subOwnerA || dr.Session.Ref != refA || dr.Role != "owner" {
		t.Errorf("forwarded as %+v, role %q", dr.Session, dr.Role)
	}
	if len(b.jar[studioDom]) != 0 || len(b.jar[dhostA]) != 1 || len(b.jar[signInH]) != 0 {
		t.Errorf("cookies after the sign-in: %v", b.jar)
	}
	// Signed in, the page is one request.
	if final, w := b.open(t, pageA); final != pageA || w.Code != 200 || b.dash != 1 {
		t.Errorf("with the session: %s %d, %d requests", final, w.Code, b.dash)
	}
	b.counts()

	// At the sign-in host: 5 and one, ending on the picker; from the studio
	// domain itself one more.
	b = e.browser(subOwnerA)
	final, w = b.open(t, signInO+"/")
	if d, i := b.counts(); final != signInO+"/" || w.Code != 200 || !strings.Contains(w.Body.String(), "https://"+dhostA+"/") || d != 5 || i != 1 {
		t.Fatalf("sign-in at the sign-in host: %s %d, %d and %d requests: %v", final, w.Code, d, i, b.seen)
	}
	b = e.browser(subOwnerA)
	final, w = b.open(t, "https://"+studioDom+"/")
	if d, i := b.counts(); final != signInO+"/" || w.Code != 200 || d != 6 || i != 1 || len(b.jar[studioDom]) != 0 {
		t.Fatalf("sign-in from the studio domain: %s %d, %d and %d requests: %v", final, w.Code, d, i, b.seen)
	}

	// A browser that keeps no login cookie: one retry, 7 and two, ending on
	// the page that names the cookie.
	b = e.browser(subOwnerA)
	b.dropLogin = 1 << 20
	final, w = b.open(t, pageA)
	if d, i := b.counts(); w.Code != 401 || !strings.Contains(w.Body.String(), html.EscapeString(textNoCookie)) || d != 7 || i != 2 {
		t.Fatalf("no login cookie kept: %s %d, %d and %d requests: %v", final, w.Code, d, i, b.seen)
	}

	// The login cookie lost once: one retry, then the page, 8 and two.
	b = e.browser(subOwnerA)
	b.dropLogin = 1
	final, w = b.open(t, pageA)
	if d, i := b.counts(); final != pageA || w.Code != 200 || d != 8 || i != 2 {
		t.Fatalf("login cookie lost once: %s %d, %d and %d requests: %v", final, w.Code, d, i, b.seen)
	}

	// The session cookie set and not kept: 5 and one, ending on the page of
	// its own, never back at the issuer.
	b = e.browser(subOwnerA)
	b.dropSession = 1 << 20
	final, w = b.open(t, pageA)
	if d, i := b.counts(); final != pageA || w.Code != 401 || !strings.Contains(w.Body.String(), html.EscapeString(textUnpresented)) || d != 5 || i != 1 {
		t.Fatalf("session cookie not kept: %s %d, %d and %d requests: %v", final, w.Code, d, i, b.seen)
	}

	// A principal who is no member signs in and is refused by the rules.
	b = e.browser("stranger")
	if final, w := b.open(t, pageA); w.Code != 403 || code(w) != "not_a_member" {
		t.Errorf("a stranger: %s %d %s", final, w.Code, w.Body)
	}
}

// TestSession_AnotherPrincipalsAttemptNeverSignsIn: a pair another party
// obtained for itself — its own token, bound to its own attempt — posted by a
// browser that never held that attempt's secret signs that browser in as no
// one, whatever state is written around the token.
func TestSession_AnotherPrincipalsAttemptNeverSignsIn(t *testing.T) {
	e := newAuthEnv(t)
	theirs := e.login(t, dhostA, "")
	token := idToken(t, issuerSigner, idClaims(subDevA, theirs.nonce)) // a valid token of another member
	mine := e.login(t, dhostA, "")
	mineRetry := e.login(t, dhostA, "?retry=1")
	noSession := func(name string, w *httptest.ResponseRecorder) {
		t.Helper()
		for _, c := range cookies(w) {
			if strings.HasPrefix(c, sessionCookie+"=") {
				t.Errorf("%s: a session was set: %q", name, c)
			}
		}
	}
	// Their pair as it is: this browser has no cookie of their attempt.
	w := e.sessionPost(t, dhostA, token, theirs.state, mine.cookie)
	retried(t, "their pair", w)
	noSession("their pair", w)
	// Their token under this browser's own state: the nonce is not this
	// attempt's.
	w = e.sessionPost(t, dhostA, token, mine.state, mine.cookie)
	retried(t, "their token, my state", w)
	noSession("their token, my state", w)
	// The same on the retry: refused for good.
	w = e.sessionPost(t, dhostA, token, mineRetry.state, mineRetry.cookie)
	refusal(t, "their token, my retry", w, 401, textFailed)
	noSession("their token, my retry", w)
	// A state that names their attempt on another host is no state of it.
	w = e.sessionPost(t, dhostB, token, theirs.state, theirs.cookie)
	refusal(t, "their pair on another host", w, 400, textDidNotComplete)
	noSession("their pair on another host", w)
	// Control: with their cookie, on their host, the pair is theirs.
	e.signedIn(t, "control", e.sessionPost(t, dhostA, token, theirs.state, theirs.cookie), theirs, refA, subDevA)
}
