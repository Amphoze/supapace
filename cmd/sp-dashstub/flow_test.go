package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	tStudio = "studio.test"

	tSignIn = "sign-in." + tStudio
	tIssuer = "issuer.test"
	tA      = "aaaaaaaaaaaaaaaaaaaa"
	tB      = "bbbbbbbbbbbbbbbbbbbb"
	tC      = "cccccccccccccccccccc"
)

func tFlow() *flowModel { return newFlow(tStudio, tIssuer, []string{tC, tA, tB}) }

// signInTable is the gateway's table of sign-in cases that need no
// signature: this model's tests and the gateway's read the one file.
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
	b, err := os.ReadFile("../../internal/gateway/testdata/signin.json")
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
		t.Fatal("the sign-in table has an empty section")
	}
	return v
}

var (
	repeatRE = regexp.MustCompile(`\{(.)\*([0-9]+)\}`)
	clockRE  = regexp.MustCompile(`\{now(?:([+-])([0-9]+))?\}`)
)

// expand fills the placeholders of a string of the table: {A} and {B} refs of
// the model, {D} a ref it does not have, {S} the studio domain, {c*N} a
// character N times, {now}, {now+N} and {now-N} the clock.
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
	return strings.NewReplacer("{A}", tA, "{B}", tB, "{D}", "dddddddddddddddddddd", "{S}", tStudio).Replace(s)
}

// jar is a minimal cookie jar keyed by host: what a browser that keeps every
// cookie would send.
type jar map[string]map[string]string

func (j jar) take(host string, r *http.Response) {
	for _, l := range r.Header.Values("Set-Cookie") {
		nv, attrs, _ := strings.Cut(l, ";")
		n, v, _ := strings.Cut(nv, "=")
		if j[host] == nil {
			j[host] = map[string]string{}
		}
		if strings.Contains(attrs, "Max-Age=0") {
			delete(j[host], n)
		} else {
			j[host][n] = v
		}
	}
}

func (j jar) header(host string) string {
	var p []string
	for n, v := range j[host] {
		p = append(p, n+"="+v)
	}
	return strings.Join(p, "; ")
}

// tReq sends one request; hdr holds header pairs, a "Cookie" pair included.
func tReq(h http.Handler, method, rawURL string, form url.Values, hdr ...string) *http.Response {
	body := strings.NewReader("")
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, rawURL, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

func tBody(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var (
	hiddenRE = regexp.MustCompile(`name="([a-z_]+)" value="([^"]*)"`)
	actionRE = regexp.MustCompile(`action="([^"]*)"`)
	nextRE   = regexp.MustCompile(`id="next" href="([^"]*)"`)
)

// tForm reads the auto-submitted form of a page: its action and fields.
func tForm(t *testing.T, page string) (string, url.Values) {
	t.Helper()
	a := actionRE.FindStringSubmatch(page)
	if a == nil {
		t.Fatalf("no form in %q", page)
	}
	v := url.Values{}
	for _, m := range hiddenRE.FindAllStringSubmatch(page, -1) {
		v.Set(m[1], strings.ReplaceAll(m[2], "&#43;", "+"))
	}
	return a[1], v
}

func nav(site string) []string {
	return []string{"Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document", "Sec-Fetch-Site", site, "Accept", "text/html"}
}

// browser follows a top-level navigation like a browser that keeps every
// cookie (or none, with keep false), through redirects, auto-submitted forms
// and navigating pages, until a page that does neither. It returns the
// final URL, status and body and the URLs requested.
type browser struct {
	h           http.Handler
	j           jar
	keep        bool
	dropSession bool // keeps login cookies but never the session cookie
	seen        []string
}

func (b *browser) open(t *testing.T, method, u string, form url.Values) (string, int, string) {
	t.Helper()
	referer := ""
	for range 30 {
		pu, _ := url.Parse(u)
		b.seen = append(b.seen, method+" "+u)
		hdr := nav("same-origin")
		if c := b.j.header(pu.Host); c != "" {
			hdr = append(hdr, "Cookie", c)
		}
		if referer != "" {
			hdr = append(hdr, "Referer", referer)
		}
		referer = ""
		r := tReq(b.h, method, u, form, hdr...)
		if b.keep {
			b.j.take(pu.Host, r)
			if b.dropSession {
				delete(b.j[pu.Host], "__Host-sp-session")
			}
		}
		body := tBody(t, r)
		switch {
		case r.StatusCode == 302:
			loc, _ := pu.Parse(r.Header.Get("Location"))
			u, method, form = loc.String(), "GET", nil
		case actionRE.MatchString(body):
			a, f := tForm(t, body)
			u, method, form = a, "POST", f
		case nextRE.MatchString(body):
			m := nextRE.FindStringSubmatch(body)
			loc, _ := pu.Parse(strings.ReplaceAll(m[1], "&amp;", "&"))
			referer = u // the page navigates within its origin: the full address
			u, method, form = loc.String(), "GET", nil
		default:
			return u, r.StatusCode, body
		}
	}
	t.Fatalf("no end after 30 requests: %v", b.seen)
	return "", 0, ""
}

func newBrowser(keep bool) *browser { return &browser{h: tFlow(), j: jar{}, keep: keep} }

func (b *browser) count(t *testing.T) (int, int) {
	t.Helper()
	r := tReq(b.h, "GET", "https://"+tIssuer+"/-/count", nil)
	var c struct{ Dashboard, Issuer int }
	if err := json.Unmarshal([]byte(tBody(t, r)), &c); err != nil {
		t.Fatal(err)
	}
	return c.Dashboard, c.Issuer
}

func TestFlow_SignIn_FromAProjectOrigin(t *testing.T) {
	b := newBrowser(true)
	host := tA + "." + tStudio
	page := "https://" + host + "/project/x?tab=a%20b"
	u, st, body := b.open(t, "GET", page, nil)
	if u != page || st != 200 || !strings.Contains(body, "page "+tA+" /project/x?tab=a%20b") {
		t.Fatalf("ended on %s %d %q; %v", u, st, body, b.seen)
	}
	if d, i := b.count(t); d != 5 || i != 1 {
		t.Fatalf("requests: %d to the dashboard's hosts, %d to the issuer; %v", d, i, b.seen)
	}
	// The session cookie and no login cookie on the host; nothing on S or the sign-in host.
	if len(b.j[host]) != 1 || b.j[host]["__Host-sp-session"] == "" || len(b.j[tStudio]) != 0 || len(b.j[tSignIn]) != 0 {
		t.Fatalf("cookies %v", b.j)
	}
	// The order of hosts.
	want := []string{"GET https://" + host, "GET https://" + host + "/-/auth/login", "GET https://" + tIssuer + "/authorize",
		"POST https://" + tSignIn + "/-/auth/callback", "POST https://" + host + "/-/auth/session", "GET " + page}
	for i, w := range want {
		if !strings.HasPrefix(b.seen[i], w) {
			t.Errorf("request %d: %s, want %s…", i, b.seen[i], w)
		}
	}
}

func TestFlow_Login_CookieStateAndRedirect(t *testing.T) {
	h := tFlow()
	host := tA + "." + tStudio
	page := "/p?x=1"
	r := tReq(h, "GET", "https://"+host+"/-/auth/login?return="+url.QueryEscape(page), nil, nav("none")...)
	if r.StatusCode != 302 || len(r.Header.Values("Set-Cookie")) != 1 {
		t.Fatalf("login: %d %q", r.StatusCode, r.Header.Values("Set-Cookie"))
	}
	m := regexp.MustCompile(`^__Host-sp-login-([A-Za-z0-9_-]{11})=([A-Za-z0-9_-]{43}); Path=/; Max-Age=600; HttpOnly; Secure; SameSite=None$`).
		FindStringSubmatch(r.Header.Get("Set-Cookie"))
	if m == nil {
		t.Fatalf("login cookie %q", r.Header.Get("Set-Cookie"))
	}
	loc, _ := url.Parse(r.Header.Get("Location"))
	q := loc.Query()
	sum := sha256.Sum256([]byte(m[2]))
	want := map[string]string{"response_type": "id_token", "response_mode": "form_post", "client_id": flowClientID,
		"redirect_uri": "https://" + tSignIn + "/-/auth/callback", "scope": "openid",
		"nonce": base64.RawURLEncoding.EncodeToString(sum[:]),
		"state": "v1." + tA + "." + m[1] + ".0." + base64.RawURLEncoding.EncodeToString([]byte(page))}
	if loc.Scheme != "https" || loc.Host != tIssuer || loc.Path != "/authorize" || len(q) != len(want) {
		t.Fatalf("authorize URL %q", loc)
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("authorize %s = %q, want %q", k, q.Get(k), v)
		}
	}
	if strings.Contains(loc.String(), m[2]) {
		t.Error("R in a URL")
	}
	if r.Header.Get("Cache-Control") != "no-store" || !strings.HasSuffix(r.Header.Get("Content-Security-Policy"), "; form-action 'none'") {
		t.Errorf("gateway-pages policy: %q", r.Header)
	}
	// retry=1 makes n 1; the sign-in host's target is "_".
	r = tReq(h, "GET", "https://"+tSignIn+"/-/auth/login?retry=1", nil)
	loc, _ = url.Parse(r.Header.Get("Location"))
	if s := strings.Split(loc.Query().Get("state"), "."); len(s) != 5 || s[1] != "_" || s[3] != "1" || s[4] != "Lw" {
		t.Fatalf("sign-in host retry state %q", loc.Query().Get("state"))
	}
}

func TestFlow_Login_SixteenCookiesClearedFirst(t *testing.T) {
	h := tFlow()
	host := "https://" + tA + "." + tStudio
	// The table's counts: fifteen are kept, sixteen and more cleared first.
	for _, c := range loadSignIn(t).CookieCounts {
		var cookies []string
		for i := range c.Shown {
			cookies = append(cookies, fmt.Sprintf("__Host-sp-login-x%010d=v", i))
		}
		r := tReq(h, "GET", host+"/-/auth/login", nil, "Cookie", strings.Join(append(cookies, "other=1"), "; "))
		sc := r.Header.Values("Set-Cookie")
		if len(sc) != c.Cleared+1 {
			t.Fatalf("%d login cookies: Set-Cookie %q", c.Shown, sc)
		}
		for i, l := range sc[:c.Cleared] {
			if l != fmt.Sprintf("__Host-sp-login-x%010d=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None", i) {
				t.Errorf("%d login cookies, clear %d: %q", c.Shown, i, l)
			}
		}
		if !strings.Contains(sc[c.Cleared], "Max-Age=600") {
			t.Errorf("%d login cookies: new cookie %q", c.Shown, sc[c.Cleared])
		}
	}
}

func TestFlow_TwoAttempts_EachEndsOnItsOwnPage(t *testing.T) {
	b := newBrowser(true)
	host := tA + "." + tStudio
	// Both logins before either post, as two tabs at once.
	one := tReq(b.h, "GET", "https://"+host+"/-/auth/login?return=%2Fone", nil)
	two := tReq(b.h, "GET", "https://"+host+"/-/auth/login?return=%2Ftwo", nil)
	b.j.take(host, one)
	b.j.take(host, two)
	for _, c := range []struct {
		r    *http.Response
		page string
	}{{one, "/one"}, {two, "/two"}} {
		u, st, _ := b.open(t, "GET", c.r.Header.Get("Location"), nil)
		if u != "https://"+host+c.page || st != 200 {
			t.Errorf("ended on %s %d, want %s", u, st, c.page)
		}
	}
	if n := len(b.j[host]); n != 1 {
		t.Errorf("cookies left: %v", b.j[host])
	}
}

func TestFlow_NoCookieKept_OneRetryThenTheFinalPage(t *testing.T) {
	b := newBrowser(false)
	u, st, body := b.open(t, "GET", "https://"+tA+"."+tStudio+"/one", nil)
	if st != 401 || !strings.Contains(u, "/-/auth/session?at=") || !strings.Contains(body, "did not keep the sign-in cookie") {
		t.Fatalf("ended on %s %d %q; %v", u, st, body, b.seen)
	}
	if d, i := b.count(t); d != 7 || i != 2 {
		t.Fatalf("requests %d and %d; %v", d, i, b.seen)
	}
	if !strings.Contains(strings.Join(b.seen, " "), "login?retry=1&return=%2Fone") && !strings.Contains(strings.Join(b.seen, " "), "return=%2Fone&retry=1") {
		t.Errorf("retry lost the return path: %v", b.seen)
	}
}

func TestFlow_CookieExpiredAtTheIssuer_RetryCompletes(t *testing.T) {
	b := newBrowser(true)
	host := tA + "." + tStudio
	r := tReq(b.h, "GET", "https://"+host+"/-/auth/login?return=%2Fone", nil)
	b.j.take(host, r) // and then lost
	b.j[host] = nil
	u, st, _ := b.open(t, "GET", r.Header.Get("Location"), nil)
	if u != "https://"+host+"/one" || st != 200 {
		t.Fatalf("ended on %s %d; %v", u, st, b.seen)
	}
	if d, i := b.count(t); d != 7 || i != 2 { // 8 and 2 with the first GET of the page, which this case skips
		t.Fatalf("requests %d and %d; %v", d, i, b.seen)
	}
}

func TestFlow_Session_Refusals(t *testing.T) {
	h := tFlow()
	host := tA + "." + tStudio
	login := func(retry string) (string, url.Values) {
		r := tReq(h, "GET", "https://"+host+"/-/auth/login?return=%2Fp"+retry, nil)
		c := strings.SplitN(r.Header.Get("Set-Cookie"), ";", 2)[0]
		_, f := tForm(t, tBody(t, tReq(h, "GET", r.Header.Get("Location"), nil)))
		return c, f
	}
	c, f := login("")
	other, f2 := login("")
	post := func(form url.Values, cookie string) *http.Response {
		return tReq(h, "POST", "https://"+host+"/-/auth/session", form, "Cookie", cookie)
	}
	// A wrong nonce: the cookie named is cleared, retry page.
	wrong := url.Values{"id_token": f2["id_token"], "state": f["state"]}
	r := post(wrong, c+"; "+other)
	b := tBody(t, r)
	if r.StatusCode != 200 || !strings.Contains(b, "retry=1") || !strings.Contains(b, "return=%2Fp") ||
		r.Header.Get("Set-Cookie") != strings.Split(c, "=")[0]+"=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None" {
		t.Fatalf("wrong nonce: %d %q %s", r.StatusCode, r.Header.Values("Set-Cookie"), b)
	}
	// The retry's own failure is final; with other login cookies the text is not the cookie's.
	cr, fr := login("&retry=1")
	r = post(url.Values{"id_token": f2["id_token"], "state": fr["state"]}, cr)
	if b := tBody(t, r); r.StatusCode != 401 || r.Header.Get("Location") != "" || strings.Contains(b, "did not keep") || !strings.Contains(b, "/-/auth/login?return=%2Fp") {
		t.Fatalf("final refusal: %d %s", r.StatusCode, b)
	}
	// A token that is not a token of the issuer: 401 at once, n 0.
	if r := post(url.Values{"id_token": {"forged.x"}, "state": f["state"]}, c); r.StatusCode != 401 {
		t.Errorf("forged token: %d", r.StatusCode)
	}
	// A state for another host, or of another form: 400.
	for _, s := range []string{strings.Replace(f.Get("state"), tA, tB, 1), "v2" + f.Get("state")[2:], f.Get("state") + ".x", "v1.x"} {
		if r := post(url.Values{"id_token": f["id_token"], "state": {s}}, c); r.StatusCode != 400 {
			t.Errorf("state %q: %d", s, r.StatusCode)
		}
	}
	// Control: the right pair passes, and is refused a second time (the R is used).
	r = post(f, c)
	if r.StatusCode != 200 || !strings.Contains(tBody(t, r), `href="/p"`) {
		t.Fatalf("control: %d", r.StatusCode)
	}
	if r := post(f, ""); r.StatusCode == 200 && strings.Contains(r.Header.Get("Set-Cookie"), "sp-session=s") {
		t.Fatal("second post signed in")
	}
}

func TestFlow_ReturnPath_BothEnds(t *testing.T) {
	h := tFlow()
	host := tA + "." + tStudio
	tb := loadSignIn(t)
	for _, c := range tb.ReturnPaths {
		in, want := expand(c.In, 0), expand(c.Want, 0)
		r := tReq(h, "GET", "https://"+host+"/-/auth/login?return="+url.QueryEscape(in), nil)
		loc, _ := url.Parse(r.Header.Get("Location"))
		s := strings.Split(loc.Query().Get("state"), ".")
		got, _ := base64.RawURLEncoding.DecodeString(s[4])
		if string(got) != want {
			t.Errorf("return %q written as %q, want %q", in, got, want)
		}
	}
	// A hand-made state whose path is bad: followed as "/".
	for _, c := range tb.Forged {
		bad := expand(c, 0)
		r := tReq(h, "GET", "https://"+host+"/-/auth/login", nil)
		c := strings.SplitN(r.Header.Get("Set-Cookie"), ";", 2)[0]
		_, f := tForm(t, tBody(t, tReq(h, "GET", r.Header.Get("Location"), nil)))
		s := strings.Split(f.Get("state"), ".")
		s[4] = base64.RawURLEncoding.EncodeToString([]byte(bad))
		f.Set("state", strings.Join(s, "."))
		r = tReq(h, "POST", "https://"+host+"/-/auth/session", f, "Cookie", c)
		if b := tBody(t, r); r.StatusCode != 200 || !strings.Contains(b, `id="next" href="/"`) {
			t.Errorf("hand-made path %q followed: %s", bad, b)
		}
	}
}

func TestFlow_Callback_RelaysAndRefuses(t *testing.T) {
	h := tFlow()
	cb := "https://" + tSignIn + "/-/auth/callback"
	st := "v1." + tA + ".AAAAAAAAAAA.0.Lw"
	r := tReq(h, "POST", cb, url.Values{"id_token": {"idt.x"}, "state": {st}}, "Cookie", "__Host-sp-login-AAAAAAAAAAA=x", "Sec-Fetch-Site", "cross-site")
	action, f := tForm(t, tBody(t, r))
	if r.StatusCode != 200 || !regexp.MustCompile(`^https://`+tA+`\.`+tStudio+`/-/auth/session\?at=[0-9]+$`).MatchString(action) || f.Get("state") != st || f.Get("id_token") != "idt.x" || len(f) != 2 {
		t.Fatalf("relay: %d %q %v", r.StatusCode, action, f)
	}
	if len(r.Header.Values("Set-Cookie")) != 0 {
		t.Errorf("callback sets a cookie")
	}
	// The table's cases: what is relayed, and to which host, and what is refused.
	for _, c := range loadSignIn(t).Callback {
		form := url.Values{}
		for k, vs := range c.Form {
			for _, v := range vs {
				form.Add(k, expand(v, 0))
			}
		}
		r := tReq(h, "POST", cb, form)
		if r.StatusCode != c.Status || r.Header.Get("Location") != "" {
			t.Errorf("%s: %d, want %d", c.Name, r.StatusCode, c.Status)
			continue
		}
		if c.Status != 200 {
			continue
		}
		origin := "https://" + tSignIn
		if target := expand(c.Target, 0); target != "_" {
			origin = "https://" + target + "." + tStudio
		}
		action, f := tForm(t, tBody(t, r))
		if !strings.HasPrefix(action, origin+"/-/auth/session?at=") || f.Get("id_token") != form.Get("id_token") || f.Get("state") != form.Get("state") || len(f) != 2 {
			t.Errorf("%s: the relay posts %v to %q", c.Name, f, action)
		}
	}
	if r := tReq(h, "POST", "https://"+tA+"."+tStudio+"/-/auth/callback", url.Values{"id_token": {"x"}, "state": {st}}); r.StatusCode != 404 {
		t.Errorf("callback on a project host: %d", r.StatusCode)
	}
}

func TestFlow_StudioDomain_OneRedirect(t *testing.T) {
	h := tFlow()
	for _, m := range []string{"GET", "HEAD"} {
		r := tReq(h, m, "https://"+tStudio+"/", nil, "Cookie", "__Host-sp-session=s._")
		if r.StatusCode != 302 || r.Header.Get("Location") != "https://"+tSignIn+"/" || r.Header.Get("Set-Cookie") != "" ||
			r.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
			t.Errorf("%s /: %d %q", m, r.StatusCode, r.Header)
		}
	}
	for _, c := range [][2]string{{"POST", "/"}, {"GET", "/-/auth/login"}, {"GET", "/x"}} {
		r := tReq(h, c[0], "https://"+tStudio+c[1], nil)
		if r.StatusCode != 404 || r.Header.Get("Set-Cookie") != "" || r.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
			t.Errorf("%v: %d", c, r.StatusCode)
		}
	}
	b := newBrowser(true)
	u, st, body := b.open(t, "GET", "https://"+tStudio+"/", nil)
	if u != "https://"+tSignIn+"/" || st != 200 || !strings.Contains(body, `href="https://`+tA+`.`+tStudio+`/"`) {
		t.Fatalf("from S: %s %d", u, st)
	}
	if d, i := b.count(t); d != 6 || i != 1 {
		t.Fatalf("requests %d and %d", d, i)
	}
	if len(b.j[tStudio]) != 0 {
		t.Fatalf("cookie on S: %v", b.j[tStudio])
	}
}

func TestFlow_SignInHost_PickerAndPages(t *testing.T) {
	h := tFlow()
	r := tReq(h, "GET", "https://"+tSignIn+"/", nil, nav("none")...)
	if r.StatusCode != 302 || r.Header.Get("Location") != "/-/auth/login" {
		t.Fatalf("picker without session: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	// Not a navigation: 401, as on a project host (no redirect).
	if r := tReq(h, "GET", "https://"+tSignIn+"/", nil, "Sec-Fetch-Mode", "cors", "Sec-Fetch-Site", "same-origin"); r.StatusCode != 401 {
		t.Errorf("picker, not a navigation: %d", r.StatusCode)
	}
	if r := tReq(h, "GET", "https://"+tSignIn+"/x", nil, "Cookie", "__Host-sp-session=s._"); r.StatusCode != 404 {
		t.Errorf("other path: %d", r.StatusCode)
	}
	b := newBrowser(true)
	if _, st, body := b.open(t, "GET", "https://"+tSignIn+"/", nil); st != 200 || !strings.Contains(body, "projects") {
		t.Fatalf("picker %d", st)
	}
	if b.j[tSignIn]["__Host-sp-session"] != "s._" {
		t.Fatalf("sign-in host cookies %v", b.j[tSignIn])
	}
}

func TestFlow_Session_Pages(t *testing.T) {
	h := tFlow()
	host := "https://" + tA + "." + tStudio
	ok := "__Host-sp-session=s." + tA
	for _, c := range []struct {
		cookie string
		hdr    []string
		want   int
	}{
		{ok, nav("same-origin"), 200},
		{"__Host-sp-session=s." + tB, nav("same-origin"), 302},
		{ok + "; " + ok, nav("same-origin"), 302},
		{"", []string{"Sec-Fetch-Mode", "navigate"}, 302},
		{"", []string{"Accept", "text/html,*/*"}, 302},
		{"", []string{"Sec-Fetch-Mode", "cors", "Sec-Fetch-Site", "same-origin"}, 401},
	} {
		if r := tReq(h, "GET", host+"/p", nil, append(c.hdr, "Cookie", c.cookie)...); r.StatusCode != c.want {
			t.Errorf("%q %v: %d, want %d", c.cookie, c.hdr, r.StatusCode, c.want)
		}
	}
	for _, u := range []string{"https://dddddddddddddddddddd." + tStudio + "/", "https://other.test/", "https://x." + tA + "." + tStudio + "/"} {
		if r := tReq(h, "GET", u, nil, nav("none")...); r.StatusCode != 404 {
			t.Errorf("%s: %d", u, r.StatusCode)
		}
	}
}

// logout follows a log-out chain and returns the hosts visited and every
// Set-Cookie line, by host.
func logout(t *testing.T, h http.Handler, start, cookie string) ([]string, map[string][]string) {
	t.Helper()
	u := "https://" + start + "/-/auth/logout"
	hdr := append(nav("same-origin"), "Cookie", cookie)
	var hosts []string
	set := map[string][]string{}
	for range 20 {
		r := tReq(h, "GET", u, nil, hdr...)
		pu, _ := url.Parse(u)
		hosts = append(hosts, pu.Host)
		set[pu.Host] = append(set[pu.Host], r.Header.Values("Set-Cookie")...)
		if r.StatusCode == 200 {
			return hosts, set
		}
		if r.StatusCode != 302 {
			t.Fatalf("%s: %d", u, r.StatusCode)
		}
		u = r.Header.Get("Location")
		hdr = append(nav("cross-site"), "Cookie", "__Host-sp-login-AAAAAAAAAAA=x") // no session on a hop
	}
	t.Fatal("log-out chain does not end")
	return nil, nil
}

func TestFlow_LogOut_Chains(t *testing.T) {
	h := tFlow()
	clear := "__Host-sp-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
	clearLogin := "__Host-sp-login-AAAAAAAAAAA=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None"
	a, b, c := tA+"."+tStudio, tB+"."+tStudio, tC+"."+tStudio
	for _, tc := range []struct {
		start, ref string
		want       []string
	}{
		{a, tA, []string{a, b, c, tSignIn}},
		{c, tC, []string{c, a, b, tSignIn}},
		{tSignIn, "_", []string{tSignIn, a, b, c, tSignIn}},
	} {
		hosts, set := logout(t, h, tc.start, "__Host-sp-session=s."+tc.ref)
		if strings.Join(hosts, " ") != strings.Join(tc.want, " ") {
			t.Errorf("from %s: hops %v, want %v", tc.start, hosts, tc.want)
		}
		for i, host := range tc.want {
			if !strings.Contains(strings.Join(set[host], "|"), clear) {
				t.Errorf("from %s: %s sets %q", tc.start, host, set[host])
			}
			if i > 0 && !strings.Contains(strings.Join(set[host], "|"), clearLogin) {
				t.Errorf("from %s: %s does not clear the login cookie it was shown: %q", tc.start, host, set[host])
			}
		}
	}
	// Without a session: the cookies shown are cleared, and the signed-out page; no chain.
	r := tReq(h, "GET", "https://"+a+"/-/auth/logout", nil, append(nav("cross-site"), "Cookie", "__Host-sp-login-AAAAAAAAAAA=x")...)
	if r.StatusCode != 302 || r.Header.Get("Location") != "https://"+tSignIn+"/-/auth/signed-out?ended=0" ||
		strings.Join(r.Header.Values("Set-Cookie"), "|") != clearLogin {
		t.Errorf("no session: %d %q %q", r.StatusCode, r.Header.Get("Location"), r.Header.Values("Set-Cookie"))
	}
	// A wrong session cookie is shown, so it is cleared; still no chain.
	r = tReq(h, "GET", "https://"+a+"/-/auth/logout", nil, "Cookie", "__Host-sp-session=s."+tB)
	if r.StatusCode != 302 || r.Header.Get("Location") != "https://"+tSignIn+"/-/auth/signed-out?ended=0" || strings.Join(r.Header.Values("Set-Cookie"), "|") != clear {
		t.Errorf("foreign session: %d %q", r.StatusCode, r.Header.Values("Set-Cookie"))
	}
	// Tickets naming another host, a ref outside the table, too many refs, or on the sign-in host.
	var long []string
	for range 17 {
		long = append(long, tA)
	}
	now := time.Now().Unix()
	h.now = func() time.Time { return time.Unix(now, 0) } // the controls below are exact to the second
	tk := func(refs string) string { return fmt.Sprintf("%d.0.%s", now, refs) }
	for _, q := range []string{"t=" + tk(tB), "t=" + tk(tA+",dddddddddddddddddddd"), "t=" + tk(""), "t=" + tk(strings.Join(long, ",")),
		"t=" + tA, fmt.Sprintf("t=%d.0.%s", now-61, tA), fmt.Sprintf("t=%d.%s", now, tA), "t=" + tk(tA) + "&t=" + tk(tA), "t=x." + tA, "%zz", "t=" + tk(tA) + "&%zz"} {
		r := tReq(h, "GET", "https://"+a+"/-/auth/logout?"+q, nil, nav("cross-site")...)
		if r.StatusCode != 400 || r.Header.Get("Location") != "" {
			t.Errorf("ticket %q: %d", q, r.StatusCode)
		}
	}
	if r := tReq(h, "GET", "https://"+tSignIn+"/-/auth/logout?t="+tk(tA), nil); r.StatusCode != 400 {
		t.Errorf("ticket on the sign-in host: %d", r.StatusCode)
	}
	if r := tReq(h, "GET", "https://"+a+"/-/auth/logout?t="+fmt.Sprintf("%d.0.%s", now+5, tA), nil); r.StatusCode != 400 {
		t.Errorf("ticket from the future: %d", r.StatusCode)
	}
	early := func(refs string) string { return fmt.Sprintf("%d.0.%s", now-30, refs) }
	r = tReq(h, "GET", "https://"+a+"/-/auth/logout?t="+early(tA+","+tB), nil)
	if r.StatusCode != 302 || r.Header.Get("Location") != "https://"+b+"/-/auth/logout?t="+url.QueryEscape(early(tB)) {
		t.Errorf("control: %d %q (the next ticket keeps the first one's time)", r.StatusCode, r.Header.Get("Location"))
	}
}

// Seventeen projects: from one, the chain visits the sixteen others and
// more stays false.
func TestFlow_LogOut_ChainCappedAt16(t *testing.T) {
	refs := manyRefs(17)
	h := newFlow(tStudio, tIssuer, refs)
	r := tReq(h, "GET", "https://"+refs[0]+"."+tStudio+"/-/auth/logout", nil, "Cookie", "__Host-sp-session=s."+refs[0])
	loc, _ := url.Parse(r.Header.Get("Location"))
	p := strings.SplitN(loc.Query().Get("t"), ".", 3)
	if got := strings.Split(p[len(p)-1], ","); len(p) != 3 || p[1] != "0" || len(got) != 16 || got[0] != refs[1] || got[15] != refs[16] {
		t.Fatalf("ticket %q", loc.Query().Get("t"))
	}
	if hosts, end := follow(t, h, refs[0]+"."+tStudio, "__Host-sp-session=s."+refs[0]); len(hosts) != 17 || end != "https://"+tSignIn+"/-/auth/signed-out" {
		t.Fatalf("hops %v, end %q", hosts, end)
	}
}

func TestFlow_SignedOut(t *testing.T) {
	h := tFlow()
	r := tReq(h, "GET", "https://"+tSignIn+"/-/auth/signed-out", nil, nav("cross-site")...)
	if r.StatusCode != 200 || r.Header.Get("Set-Cookie") != "__Host-sp-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict" ||
		!strings.Contains(tBody(t, r), wSignedOut) {
		t.Fatalf("signed-out: %d %q", r.StatusCode, r.Header.Values("Set-Cookie"))
	}
	if r := tReq(h, "GET", "https://"+tA+"."+tStudio+"/-/auth/signed-out", nil); r.StatusCode != 404 {
		t.Errorf("signed-out on a project host: %d", r.StatusCode)
	}
}

func TestFlow_SameOriginRule(t *testing.T) {
	h := tFlow()
	a := "https://" + tA + "." + tStudio
	for _, c := range []struct {
		method, url string
		hdr         []string
		want        int
	}{
		{"GET", a + "/-/auth/login", []string{"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "cors"}, 403},
		{"GET", a + "/-/auth/login", []string{"Sec-Fetch-Site", "same-site", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "iframe"}, 403},
		{"GET", a + "/api/x", append(nav("cross-site"), "Cookie", "__Host-sp-session=s."+tA), 403},
		{"GET", a + "/api/x", nav("cross-site"), 302}, // the session first, as rule 5 comes before rule 7
		{"GET", a + "/-/auth/login", nav("cross-site"), 302},
		{"GET", a + "/-/auth/login", nil, 302},
		{"POST", a + "/-/auth/logout", []string{"Sec-Fetch-Site", "cross-site"}, 403},
		{"POST", "https://" + tSignIn + "/-/auth/session", []string{"Sec-Fetch-Site", "cross-site"}, 400},
		{"POST", "https://" + tSignIn + "/-/auth/callback", []string{"Sec-Fetch-Site", "cross-site"}, 400},
		{"POST", "https://" + tSignIn + "/", []string{"Sec-Fetch-Site", "cross-site"}, 403},
	} {
		if r := tReq(h, c.method, c.url, url.Values{}, c.hdr...); r.StatusCode != c.want {
			t.Errorf("%s %s %v: %d, want %d", c.method, c.url, c.hdr, r.StatusCode, c.want)
		}
	}
}

func TestFlow_IssuerHoldAndLinkPage(t *testing.T) {
	h := tFlow()
	q := url.Values{"response_type": {"id_token"}, "response_mode": {"form_post"}, "client_id": {flowClientID},
		"redirect_uri": {"https://" + tSignIn + "/-/auth/callback"}, "nonce": {"n"}, "state": {"s"}}
	auth := "https://" + tIssuer + "/authorize?" + q.Encode()
	if b := tBody(t, tReq(h, "GET", auth, nil)); !strings.Contains(b, "hold=1") || !strings.Contains(b, `value="idt.n"`) {
		t.Fatalf("issuer page %s", b)
	}
	q.Set("redirect_uri", "https://"+tStudio+"/-/auth/callback")
	if r := tReq(h, "GET", "https://"+tIssuer+"/authorize?"+q.Encode(), nil); r.StatusCode != 400 {
		t.Errorf("another redirect URI: %d", r.StatusCode)
	}
	target := "https://" + tA + "." + tStudio + "/p?q=1"
	if b := tBody(t, tReq(h, "GET", "https://"+tIssuer+"/link?to="+url.QueryEscape(target), nil)); !strings.Contains(b, `<a id="go" href="https://`+tA+`.`+tStudio+`/p?q=1">`) {
		t.Fatalf("link page: %s", b)
	}
	for _, to := range []string{"javascript:alert(1)", "https://evil.test/", "http://" + tA + "." + tStudio + "/"} {
		if r := tReq(h, "GET", "https://"+tIssuer+"/link?to="+url.QueryEscape(to), nil); r.StatusCode != 400 {
			t.Errorf("link to %q: %d", to, r.StatusCode)
		}
	}
	// The counter reads and resets; it counts no request of its own.
	tReq(h, "GET", "https://"+tA+"."+tStudio+"/favicon.ico", nil)
	b := &browser{h: h}
	if d, i := b.count(t); d != 0 || i != 2 {
		t.Fatalf("count %d %d", d, i)
	}
	if d, i := b.count(t); d != 0 || i != 0 {
		t.Fatalf("count after read %d %d", d, i)
	}
}

func TestFlow_Usage(t *testing.T) {
	base := []string{"flow", "--listen", "127.0.0.1:0", "--cert", "c", "--key", "k"}
	with := func(studio, issuer, refs string) []string {
		return append(append([]string{}, base...), "--studio-domain", studio, "--issuer-host", issuer, "--refs", refs)
	}
	for _, args := range [][]string{
		{"flow"}, {"flow", "extra"},
		with(tStudio, tIssuer, "BAD"), with(tStudio, tIssuer, tA+","+tA), with(tStudio, tIssuer, ""),
		with(tStudio, "x."+tStudio, tA), with(tStudio, tStudio, tA), with("", tIssuer, tA),
		append(with(tStudio, tIssuer, tA), "--bogus"),
	} {
		if code, out, _ := runOut(args...); code != 2 || out != "" {
			t.Errorf("%q: exit %d, stdout %q", args, code, out)
		}
	}
	// Control: valid flags reach the listener, which fails on the missing files.
	if code, _, errs := runOut(with(tStudio, tIssuer, tA)...); code != 1 || !strings.Contains(errs, "flow:") {
		t.Errorf("valid flags: exit %d, %q", code, errs)
	}
}

// The relay posts to the target's session endpoint with the relay's clock in
// at; the session endpoint answers the same with any at or none.
func TestFlow_Relay_PostsWithTheClock(t *testing.T) {
	m := tFlow()
	m.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	st := "v1." + tA + ".AAAAAAAAAAA.0.Lw"
	action, _ := tForm(t, tBody(t, tReq(m, "POST", "https://"+tSignIn+"/-/auth/callback", url.Values{"id_token": {"idt.x"}, "state": {st}})))
	if action != "https://"+tA+"."+tStudio+"/-/auth/session?at=1800000000" {
		t.Fatalf("relay action %q", action)
	}
	r := tReq(m, "POST", "https://"+tSignIn+"/-/auth/callback", url.Values{"id_token": {"idt.x"}, "state": {st}})
	if csp := r.Header.Get("Content-Security-Policy"); !strings.HasSuffix(csp, "; form-action https://"+tA+"."+tStudio) {
		t.Errorf("relay form-action: %q", csp)
	}
	for _, q := range []string{"", "?at=1", "?at=x", "?at=1&at=2"} {
		r := tReq(m, "POST", "https://"+tA+"."+tStudio+"/-/auth/session"+q, url.Values{"id_token": {"idt.x"}, "state": {st}})
		if r.StatusCode != 200 || !strings.Contains(tBody(t, r), "retry=1") {
			t.Errorf("session%s: %d", q, r.StatusCode)
		}
	}
}

// Every answer of the sign-in host and of a project host carries the
// transport-security header; the sign-in host's also Origin-Agent-Cluster;
// every gateway page but the relay has form-action 'none'.
func TestFlow_HeadersOnEveryAnswer(t *testing.T) {
	h := tFlow()
	a := "https://" + tA + "." + tStudio
	si := "https://" + tSignIn
	for _, c := range []struct{ method, url string }{
		{"GET", si + "/"}, {"GET", si + "/x"}, {"GET", si + "/-/auth/login"}, {"POST", si + "/-/auth/callback"},
		{"GET", si + "/-/auth/callback"}, {"POST", si + "/-/auth/session"}, {"GET", si + "/-/auth/signed-out"},
		{"GET", a + "/p"}, {"GET", a + "/-/auth/login"}, {"GET", a + "/-/auth/session"}, {"POST", a + "/-/auth/session"},
		{"GET", a + "/-/auth/logout"}, {"GET", a + "/api/x"},
	} {
		r := tReq(h, c.method, c.url, url.Values{}, "Cookie", "__Host-sp-session=s."+tA)
		if r.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
			t.Errorf("%s %s (%d): HSTS %q", c.method, c.url, r.StatusCode, r.Header.Get("Strict-Transport-Security"))
		}
		if oac := r.Header.Get("Origin-Agent-Cluster"); (oac == "?1") != strings.HasPrefix(c.url, si) {
			t.Errorf("%s %s: Origin-Agent-Cluster %q", c.method, c.url, oac)
		}
		if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'none'") {
			t.Errorf("%s %s: %q", c.method, c.url, csp)
		}
		for k, v := range map[string]string{"Referrer-Policy": "same-origin", "Cache-Control": "no-store",
			"X-Content-Type-Options": "nosniff", "Cross-Origin-Resource-Policy": "same-origin"} {
			if r.Header.Get(k) != v {
				t.Errorf("%s %s: %s %q", c.method, c.url, k, r.Header.Get(k))
			}
		}
	}
	if r := tReq(h, "GET", "https://"+tStudio+"/", nil); r.Header.Get("Origin-Agent-Cluster") != "" {
		t.Error("Origin-Agent-Cluster on S")
	}
}

// A session cookie that is set and not presented: the session page's own
// navigation, marked by its Referer with an at of the last minute, gets the
// final page; anything else the ordinary redirect.
func TestFlow_SessionNotPresented(t *testing.T) {
	b := newBrowser(true)
	b.dropSession = true
	host := tA + "." + tStudio
	u, st, body := b.open(t, "GET", "https://"+host+"/p?x=1", nil)
	if st != 401 || u != "https://"+host+"/p?x=1" || !strings.Contains(body, "did not send back the session cookie") ||
		!strings.Contains(body, `href="/-/auth/login?return=%2Fp%3Fx%3D1"`) {
		t.Fatalf("ended on %s %d %q; %v", u, st, body, b.seen)
	}
	if d, i := b.count(t); d != 5 || i != 1 {
		t.Fatalf("requests %d and %d; %v", d, i, b.seen)
	}
	m := b.h.(*flowModel)
	now := time.Now().Unix()
	m.now = func() time.Time { return time.Unix(now, 0) }
	ref := func(at string) []string {
		return append(nav("same-origin"), "Referer", "https://"+host+"/-/auth/session"+at)
	}
	// The table's forms of the mark: 401 for the session page's own address
	// of the last minute, the redirect to sign-in for every other.
	for _, c := range loadSignIn(t).Referers {
		want, hdr := 302, nav("same-origin")
		if c.Marked {
			want = 401
		}
		if referer := expand(c.Referer, now); referer != "" {
			hdr = append(hdr, "Referer", referer)
		}
		if r := tReq(m, "GET", "https://"+host+"/p", nil, hdr...); r.StatusCode != want {
			t.Errorf("Referer %q: %d, want %d", c.Referer, r.StatusCode, want)
		}
	}

	// The sign-in host's picker the same way; and a valid session is served whatever the Referer.
	if r := tReq(m, "GET", "https://"+tSignIn+"/", nil, append(nav("same-origin"), "Referer", fmt.Sprintf("https://%s/-/auth/session?at=%d", tSignIn, now))...); r.StatusCode != 401 {
		t.Errorf("picker: %d", r.StatusCode)
	}
	if r := tReq(m, "GET", "https://"+host+"/p", nil, append(ref(fmt.Sprintf("?at=%d", now)), "Cookie", "__Host-sp-session=s."+tA)...); r.StatusCode != 200 {
		t.Errorf("with a session: %d", r.StatusCode)
	}
	// The clock can be advanced for the browser tests.
	tReq(m, "GET", "https://"+tIssuer+"/-/clock?add=61", nil)
	if r := tReq(m, "GET", "https://"+host+"/p", nil, ref(fmt.Sprintf("?at=%d", now))...); r.StatusCode != 302 {
		t.Errorf("after the clock moved: %d", r.StatusCode)
	}
}

func TestFlow_FieldsExactlyOnce_OtherMethods405(t *testing.T) {
	h := tFlow()
	tb := loadSignIn(t)
	cb := "https://" + tSignIn + "/-/auth/callback"
	// The table's bodies, at the callback and at a project host's session
	// endpoint (where, without the attempt's cookie, a body that is taken
	// gives the retry page).
	for _, c := range tb.Fields {
		for u, want := range map[string]int{cb: c.Callback, "https://" + tA + "." + tStudio + "/-/auth/session": c.Session} {
			r := httptest.NewRequest("POST", u, strings.NewReader(expand(c.Body, 0)))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || w.Header().Get("Location") != "" {
				t.Errorf("%s, %s: %d, want %d", c.Name, u, w.Code, want)
			}
		}
	}
	for _, m := range tb.OtherMethods {
		for _, u := range []string{cb, "https://" + tSignIn + "/-/auth/session", "https://" + tA + "." + tStudio + "/-/auth/session"} {
			if r := tReq(h, m, u, nil); r.StatusCode != 405 || r.Header.Get("Location") != "" {
				t.Errorf("%s %s: %d", m, u, r.StatusCode)
			}
		}
	}
}

func TestFlow_Session_OrderAndDuplicates(t *testing.T) {
	h := tFlow()
	host := tA + "." + tStudio
	login := func(retry string) (string, string, url.Values) {
		r := tReq(h, "GET", "https://"+host+"/-/auth/login?return=%2Fp"+retry, nil)
		c := strings.SplitN(r.Header.Get("Set-Cookie"), ";", 2)[0]
		_, f := tForm(t, tBody(t, tReq(h, "GET", r.Header.Get("Location"), nil)))
		return c, strings.Split(c, "=")[0], f
	}
	post := func(form url.Values, cookie string) *http.Response {
		return tReq(h, "POST", "https://"+host+"/-/auth/session", form, "Cookie", cookie)
	}
	clearOf := func(name string) string { return name + "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None" }
	// A token that fails before its nonce, with the cookie: 401 at once, and the cookie cleared.
	c, name, f := login("")
	bad := url.Values{"id_token": {"exp.wrongnonce"}, "state": f["state"]}
	if r := post(bad, c); r.StatusCode != 401 || r.Header.Get("Set-Cookie") != clearOf(name) {
		t.Errorf("failing token with the cookie: %d %q", r.StatusCode, r.Header.Values("Set-Cookie"))
	}
	// Without the cookie the token is not verified: a binding failure, the retry page.
	if r := post(bad, ""); r.StatusCode != 200 || !strings.Contains(tBody(t, r), "retry=1") {
		t.Errorf("failing token without the cookie: %d", r.StatusCode)
	}
	// The attempt's cookie twice: a binding failure at n 0 (retry), final at n 1; cleared.
	c, name, f = login("")
	if r := post(f, c+"; "+c); r.StatusCode != 200 || !strings.Contains(tBody(t, r), "retry=1") || r.Header.Get("Set-Cookie") != clearOf(name) {
		t.Errorf("cookie twice, n 0: %d %q", r.StatusCode, r.Header.Values("Set-Cookie"))
	}
	c, _, f = login("&retry=1")
	if r := post(f, c+"; "+c); r.StatusCode != 401 {
		t.Errorf("cookie twice, n 1: %d", r.StatusCode)
	}
	// The order: a bad state is 400 before anything reads the cookie.
	c, _, f = login("")
	if r := post(url.Values{"id_token": f["id_token"], "state": {"v1.x"}}, c); r.StatusCode != 400 || r.Header.Get("Set-Cookie") != "" {
		t.Errorf("bad state: %d %q", r.StatusCode, r.Header.Values("Set-Cookie"))
	}
	// Control: the pair passes, the cookie cleared and the session set.
	if r := post(f, c); r.StatusCode != 200 || len(r.Header.Values("Set-Cookie")) != 2 ||
		r.Header.Values("Set-Cookie")[1] != "__Host-sp-session=s."+tA+"; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Strict" {
		t.Errorf("control: %d %q", r.StatusCode, r.Header.Values("Set-Cookie"))
	}
}

// Only __Host-sp-login- with exactly 11 base64url characters is a login
// cookie: counted toward sixteen, cleared, read.
func TestFlow_LoginCookieNames(t *testing.T) {
	h := tFlow()
	host := "https://" + tA + "." + tStudio
	tb := loadSignIn(t)
	var cookies, others, want []string
	for i := range 16 {
		others = append(others, fmt.Sprintf("__Host-sp-login-x%09d=v", i)) // 10 characters
	}
	for _, c := range tb.CookieNames {
		cookies = append(cookies, c.Name+"=v")
		if c.Login {
			want = append(want, c.Name+"=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None")
		} else {
			others = append(others, c.Name+"=v")
		}
	}
	// Sixteen and more names that are no login cookies: none counted, none cleared.
	r := tReq(h, "GET", host+"/-/auth/login", nil, "Cookie", strings.Join(others, "; "))
	if n := len(r.Header.Values("Set-Cookie")); n != 1 {
		t.Errorf("names that are not login cookies were counted or cleared: %q", r.Header.Values("Set-Cookie"))
	}
	// A log-out clears the table's login cookies and no other name.
	r = tReq(h, "GET", host+"/-/auth/logout", nil, "Cookie", strings.Join(append(others, cookies...), "; "))
	if got := r.Header.Values("Set-Cookie"); len(want) == 0 || strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("log-out cleared %q, want %q", got, want)
	}
}

// The model's stand-in for a browser that does not keep the session cookie:
// the next n sign-ins set none; then they set it again.
func TestFlow_DropSessionHook(t *testing.T) {
	b := newBrowser(true)
	tReq(b.h, "GET", "https://"+tIssuer+"/-/drop-session?n=1", nil)
	host := tA + "." + tStudio
	if _, st, _ := b.open(t, "GET", "https://"+host+"/p", nil); st != 401 {
		t.Fatalf("first sign-in: %d", st)
	}
	if u, st, _ := b.open(t, "GET", "https://"+host+"/p", nil); st != 200 || u != "https://"+host+"/p" {
		t.Fatalf("second sign-in: %s %d", u, st)
	}
	if r := tReq(b.h, "GET", "https://"+tIssuer+"/-/drop-session?n=-1", nil); r.StatusCode != 400 {
		t.Errorf("negative n: %d", r.StatusCode)
	}
}

// The ticket expires 60 s after its issue time, as the token package
// verifies it (exp = iat + 60, refused when exp <= now): 59 s old is
// accepted, 60 s refused.
func TestFlow_LogOut_TicketWindow(t *testing.T) {
	m := tFlow()
	now := time.Now().Unix()
	m.now = func() time.Time { return time.Unix(now, 0) }
	a := "https://" + tA + "." + tStudio
	for age, want := range map[int64]int{0: 302, 59: 302, 60: 400, 61: 400} {
		if r := tReq(m, "GET", a+"/-/auth/logout?t="+fmt.Sprintf("%d.0.%s", now-age, tA), nil); r.StatusCode != want {
			t.Errorf("ticket %d s old: %d, want %d", age, r.StatusCode, want)
		}
	}
}

// A host under the studio domain that is not a ref of the table is answered
// 404 with the transport-security header, as every host the gateway serves.
func TestFlow_UnknownRefHost_HSTS(t *testing.T) {
	r := tReq(tFlow(), "GET", "https://dddddddddddddddddddd."+tStudio+"/", nil)
	if r.StatusCode != 404 || r.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatalf("%d %q", r.StatusCode, r.Header.Get("Strict-Transport-Security"))
	}
}

// The gateway's words, which the model's pages show as the gateway's do.
const (
	wSignedOut = "Log out from a dashboard ends the session of that dashboard, of up to sixteen other projects of yours, and of this sign-in page."
	wEnded     = "No dashboard session was shown with this log-out, so none was ended. The session of this sign-in page is ended. A session still open on a dashboard is ended by Log out from a page of that dashboard."
	wMore      = "Sessions on further projects stay valid until they expire or your access is revoked."
	wUnpresent = "Sign-in completed, and this browser did not send back the session cookie it was given. Allow cookies for this site, then start again."
)

// refusalCode is the code of a JSON refusal as the gateway writes one, ""
// for any other answer.
func refusalCode(t *testing.T, r *http.Response) string {
	t.Helper()
	body := tBody(t, r)
	m := regexp.MustCompile(`^\{"code":"([a-z_]+)"\}$`).FindStringSubmatch(body)
	if r.Header.Get("Content-Type") != "application/json" || m == nil {
		return ""
	}
	return m[1]
}

func TestFlow_LogOut_WithoutASession_EndedZero(t *testing.T) {
	h := tFlow()
	ended := "https://" + tSignIn + "/-/auth/signed-out?ended=0"
	for _, c := range []struct{ host, cookie string }{
		{tA + "." + tStudio, ""}, {tA + "." + tStudio, "__Host-sp-session=s." + tB}, {tA + "." + tStudio, "__Host-sp-session=s." + tA + "; __Host-sp-session=s." + tA},
		{tSignIn, ""}, {tSignIn, "__Host-sp-session=s." + tA},
	} {
		r := tReq(h, "GET", "https://"+c.host+"/-/auth/logout", nil, append(nav("same-origin"), "Cookie", c.cookie)...)
		if r.StatusCode != 302 || r.Header.Get("Location") != ended {
			t.Errorf("%s %q: %d %q", c.host, c.cookie, r.StatusCode, r.Header.Get("Location"))
		}
	}
	// Control: with this host's session the chain starts, no ended=0.
	r := tReq(h, "GET", "https://"+tA+"."+tStudio+"/-/auth/logout", nil, "Cookie", "__Host-sp-session=s."+tA)
	if loc := r.Header.Get("Location"); r.StatusCode != 302 || !strings.HasPrefix(loc, "https://"+tB+"."+tStudio+"/-/auth/logout?t=") {
		t.Errorf("control: %d %q", r.StatusCode, loc)
	}
}

// follow runs a log-out chain from start with cookie and returns the hosts
// it visits and the address the last hop redirects to.
func follow(t *testing.T, h http.Handler, start, cookie string) (hosts []string, end string) {
	t.Helper()
	u := "https://" + start + "/-/auth/logout"
	hdr := append(nav("same-origin"), "Cookie", cookie)
	for range 40 {
		pu, _ := url.Parse(u)
		if pu.Path != "/-/auth/logout" {
			return hosts, u
		}
		hosts = append(hosts, pu.Host)
		r := tReq(h, "GET", u, nil, hdr...)
		if r.StatusCode != 302 {
			t.Fatalf("%s: %d", u, r.StatusCode)
		}
		u, hdr = r.Header.Get("Location"), nav("cross-site")
	}
	t.Fatal("the chain does not end")
	return nil, ""
}

func manyRefs(n int) []string {
	var refs []string
	for i := range n {
		refs = append(refs, fmt.Sprintf("r%019d", i))
	}
	return refs
}

func TestFlow_LogOut_EighteenRefs_MoreAfterSixteen(t *testing.T) {
	refs := manyRefs(18)
	h := newFlow(tStudio, tIssuer, refs)
	r := tReq(h, "GET", "https://"+refs[0]+"."+tStudio+"/-/auth/logout", nil, "Cookie", "__Host-sp-session=s."+refs[0])
	loc, _ := url.Parse(r.Header.Get("Location"))
	if p := strings.SplitN(loc.Query().Get("t"), ".", 3); len(p) != 3 || p[1] != "1" || len(strings.Split(p[2], ",")) != 16 {
		t.Fatalf("the first ticket %q: more and sixteen refs wanted", loc.Query().Get("t"))
	}
	hosts, end := follow(t, h, refs[0]+"."+tStudio, "__Host-sp-session=s."+refs[0])
	if len(hosts) != 17 || hosts[16] != refs[16]+"."+tStudio || end != "https://"+tSignIn+"/-/auth/signed-out?more=1" {
		t.Fatalf("hops %v, end %q", hosts, end)
	}
	// The seventeenth other project is never visited: its session stays.
	for _, host := range hosts {
		if host == refs[17]+"."+tStudio {
			t.Fatalf("the seventeenth visited: %v", hosts)
		}
	}
	// The sign-in host has seventeen others too: the same.
	if hosts, end := follow(t, newFlow(tStudio, tIssuer, refs[:17]), tSignIn, "__Host-sp-session=s._"); len(hosts) != 17 || end != "https://"+tSignIn+"/-/auth/signed-out?more=1" {
		t.Errorf("from the sign-in host: hops %v, end %q", hosts, end)
	}
	// A hop passes more on; a ticket whose more is not 0 or 1 is refused.
	now := time.Now().Unix()
	h.now = func() time.Time { return time.Unix(now, 0) }
	a := "https://" + refs[1] + "." + tStudio + "/-/auth/logout?t="
	if r := tReq(h, "GET", a+fmt.Sprintf("%d.1.%s,%s", now, refs[1], refs[2]), nil); r.Header.Get("Location") != "https://"+refs[2]+"."+tStudio+"/-/auth/logout?t="+url.QueryEscape(fmt.Sprintf("%d.1.%s", now, refs[2])) {
		t.Errorf("hop: %q", r.Header.Get("Location"))
	}
	if r := tReq(h, "GET", a+fmt.Sprintf("%d.1.%s", now, refs[1]), nil); r.Header.Get("Location") != "https://"+tSignIn+"/-/auth/signed-out?more=1" {
		t.Errorf("last hop: %q", r.Header.Get("Location"))
	}
	for _, m := range []string{"2", "", "true", "01"} {
		if r := tReq(h, "GET", a+fmt.Sprintf("%d.%s.%s", now, m, refs[1]), nil); r.StatusCode != 400 {
			t.Errorf("more %q: %d", m, r.StatusCode)
		}
	}
}

func TestFlow_SignedOut_ThreeSentences(t *testing.T) {
	h := tFlow()
	type words struct{ plain, ended, more bool }
	pages := map[words]string{}
	for q, want := range map[string]words{
		"": {true, false, false}, "ended=0": {false, true, false}, "more=1": {true, false, true},
		"ended=0&more=1": {false, true, true}, "more=1&ended=0&x=1": {false, true, true}, "x=1&more=1": {true, false, true},
		"&more=1&": {true, false, true}, "ended=0&x=<script>": {false, true, false}, "ended=0&more=2": {false, true, false},
		"ended=1": {true, false, false}, "more=0": {true, false, false}, "more=1&more=1": {true, false, false},
		"ended=0&ended=0": {true, false, false}, "MORE=1": {true, false, false}, "more=1;ended=0": {true, false, false},
		"more%3D1": {true, false, false}, "mor%65=1": {true, false, false}, "more=%31": {true, false, false},
		"more=01": {true, false, false}, "more": {true, false, false}, "ended": {true, false, false},
		"ended=0&more=1&more=1": {false, true, false}, "more=1&ended=0&ended=00": {true, false, true},
	} {
		u := "https://" + tSignIn + "/-/auth/signed-out"
		if q != "" {
			u += "?" + q
		}
		r := tReq(h, "GET", u, nil, append(nav("cross-site"), "Cookie", "__Host-sp-session=s._; __Host-sp-login-AAAAAAAAAAA=x")...)
		body := tBody(t, r)
		has := func(s string) bool { return strings.Contains(body, ">"+s+"</p>") }
		if got := (words{has(wSignedOut), has(wEnded), has(wMore)}); r.StatusCode != 200 || got != want {
			t.Errorf("?%s: %d, sentences %+v, want %+v", q, r.StatusCode, got, want)
		}
		if p, ok := pages[want]; ok && p != body {
			t.Errorf("?%s: not the fixed page of %+v", q, want)
		}
		pages[want] = body
		if got := strings.Join(r.Header.Values("Set-Cookie"), "|"); got != "__Host-sp-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict|__Host-sp-login-AAAAAAAAAAA=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None" {
			t.Errorf("?%s: Set-Cookie %q", q, got)
		}
	}
	if len(pages) != 4 {
		t.Fatalf("%d pages, want the four fixed ones", len(pages))
	}
}

var (
	scriptsRE = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	stylesRE  = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
)

func quotedHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func TestFlow_Policy_OneScriptHashPerPage(t *testing.T) {
	h := tFlow()
	a := "https://" + tA + "." + tStudio
	si := "https://" + tSignIn
	st := "v1." + tA + ".AAAAAAAAAAA.0.Lw"
	login := tReq(h, "GET", a+"/-/auth/login", nil)
	cookie := strings.SplitN(login.Header.Get("Set-Cookie"), ";", 2)[0]
	_, f := tForm(t, tBody(t, tReq(h, "GET", login.Header.Get("Location"), nil)))
	scripted := 0
	for _, c := range []struct {
		name, method, url, formAction string
		form                          url.Values
		hdr                           []string
	}{
		{"relay", "POST", si + "/-/auth/callback", a, url.Values{"id_token": {"idt.x"}, "state": {st}}, nil},
		{"session", "POST", a + "/-/auth/session", "'none'", f, []string{"Cookie", cookie}},
		{"retry", "POST", a + "/-/auth/session", "'none'", url.Values{"id_token": {"idt.x"}, "state": {st}}, nil},
		{"400 page", "POST", si + "/-/auth/callback", "'none'", url.Values{}, nil},
		{"405 page", "GET", a + "/-/auth/session", "'none'", nil, nil},
		{"401 page", "GET", a + "/p", "'none'", nil, append(nav("same-origin"), "Referer", fmt.Sprintf("%s/-/auth/session?at=%d", a, time.Now().Unix()))},
		{"login redirect", "GET", a + "/-/auth/login", "'none'", nil, nil},
		{"logout redirect", "GET", a + "/-/auth/logout", "'none'", nil, nil},
		{"signed out", "GET", si + "/-/auth/signed-out", "'none'", nil, nil},
		{"picker", "GET", si + "/", "'none'", nil, []string{"Cookie", "__Host-sp-session=s._"}},
		{"not found", "GET", si + "/x", "'none'", nil, nil},
		{"login required", "GET", a + "/p", "'none'", nil, []string{"Sec-Fetch-Mode", "cors"}},
		{"cross origin", "GET", a + "/-/auth/login", "'none'", nil, []string{"Sec-Fetch-Site", "cross-site"}},
	} {
		r := tReq(h, c.method, c.url, c.form, c.hdr...)
		body := tBody(t, r)
		script, style := "'none'", quotedHash(flowStyle)
		if m := scriptsRE.FindAllStringSubmatch(body, -1); len(m) == 1 {
			script = quotedHash(m[0][1])
			scripted++
		} else if len(m) > 1 || strings.Count(body, "<script") != len(m) {
			t.Errorf("%s: more than one script: %s", c.name, body)
		}
		if m := stylesRE.FindAllStringSubmatch(body, -1); len(m) > 1 || len(m) == 1 && m[0][1] != flowStyle {
			t.Errorf("%s: the style %q", c.name, m)
		} else if len(m) == 0 && strings.HasPrefix(body, "<!doctype") {
			t.Errorf("%s: a page without the style", c.name)
		}
		want := "default-src 'none'; script-src " + script + "; style-src " + style + "; frame-ancestors 'none'; base-uri 'none'; form-action " + c.formAction
		if got := r.Header.Values("Content-Security-Policy"); len(got) != 1 || got[0] != want {
			t.Errorf("%s (%d): policy %q, want %q", c.name, r.StatusCode, got, want)
		}
	}
	if scripted != 3 {
		t.Errorf("%d answers with a script, want the relay, the session and the retry page", scripted)
	}
}

func TestFlow_SignInHost_OtherMethods404(t *testing.T) {
	h := tFlow()
	si := "https://" + tSignIn
	session := "__Host-sp-session=s._"
	if r := tReq(h, "POST", si+"/", url.Values{}, "Cookie", session, "Sec-Fetch-Site", "same-origin"); r.StatusCode != 404 || refusalCode(t, r) != "not_found" {
		t.Errorf("POST / with a session: %d", r.StatusCode)
	}
	for _, p := range []string{"/-/auth/login", "/-/auth/logout", "/-/auth/signed-out", "/"} {
		if r := tReq(h, "HEAD", si+p, nil, "Cookie", session); r.StatusCode != 404 || r.Header.Get("Location") != "" || len(r.Header.Values("Set-Cookie")) != 0 {
			t.Errorf("HEAD %s: %d %q", p, r.StatusCode, r.Header.Values("Set-Cookie"))
		}
	}
	a := "https://" + tA + "." + tStudio
	for _, p := range []string{"/-/auth/login", "/-/auth/logout"} {
		if r := tReq(h, "HEAD", a+p, nil, "Cookie", "__Host-sp-session=s."+tA); r.StatusCode != 404 {
			t.Errorf("HEAD %s on a project host: %d", p, r.StatusCode)
		}
	}
	// Control: GET of each.
	for p, want := range map[string]int{"/-/auth/login": 302, "/-/auth/logout": 302, "/-/auth/signed-out": 200, "/": 200} {
		if r := tReq(h, "GET", si+p, nil, "Cookie", session); r.StatusCode != want {
			t.Errorf("GET %s: %d, want %d", p, r.StatusCode, want)
		}
	}
}

func TestFlow_Posts_ReadTheBodyAlone(t *testing.T) {
	h := tFlow()
	a := "https://" + tA + "." + tStudio
	login := tReq(h, "GET", a+"/-/auth/login?return=%2Fp", nil)
	cookie := strings.SplitN(login.Header.Get("Set-Cookie"), ";", 2)[0]
	_, f := tForm(t, tBody(t, tReq(h, "GET", login.Header.Get("Location"), nil)))
	r := tReq(h, "POST", a+"/-/auth/session?at=%zz", f, "Cookie", cookie)
	if r.StatusCode != 200 || !strings.Contains(strings.Join(r.Header.Values("Set-Cookie"), "|"), "__Host-sp-session=s."+tA+";") {
		t.Fatalf("session with ?at=%%zz: %d %q", r.StatusCode, r.Header.Values("Set-Cookie"))
	}
	st := "v1." + tA + ".AAAAAAAAAAA.0.Lw"
	if r := tReq(h, "POST", "https://"+tSignIn+"/-/auth/callback?%zz", url.Values{"id_token": {"idt.x"}, "state": {st}}); r.StatusCode != 200 {
		t.Errorf("callback with ?%%zz: %d", r.StatusCode)
	}
	// The fields in the address and not in the body are not read.
	q := url.Values{"id_token": {"idt.x"}, "state": {st}}.Encode()
	for _, u := range []string{"https://" + tSignIn + "/-/auth/callback?" + q, a + "/-/auth/session?" + q} {
		if r := tReq(h, "POST", u, url.Values{}); r.StatusCode != 400 {
			t.Errorf("%s: %d", u, r.StatusCode)
		}
	}
	// A body that is not a form, or over 16 KiB, is refused.
	big := url.Values{"id_token": {"idt.x"}, "state": {st}, "x": {strings.Repeat("a", 16<<10)}}
	if r := tReq(h, "POST", "https://"+tSignIn+"/-/auth/callback", big); r.StatusCode != 400 {
		t.Errorf("over 16 KiB: %d", r.StatusCode)
	}
	// A declared length over the bound is refused unread.
	decl := httptest.NewRequest("POST", "https://"+tSignIn+"/-/auth/callback", strings.NewReader(q))
	decl.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	decl.ContentLength = 16<<10 + 1
	dw := httptest.NewRecorder()
	h.ServeHTTP(dw, decl)
	if dw.Code != 400 {
		t.Errorf("a declared length over 16 KiB: %d", dw.Code)
	}
	rq := httptest.NewRequest("POST", "https://"+tSignIn+"/-/auth/callback", strings.NewReader(q))
	rq.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, rq)
	if w.Code != 400 {
		t.Errorf("a text body: %d", w.Code)
	}
}

func TestFlow_NotPresented_LinkIsAReturnPath(t *testing.T) {
	h := tFlow()
	a := tA + "." + tStudio
	for target, want := range map[string]string{
		"/p?x=1":           "/-/auth/login?return=%2Fp%3Fx%3D1",
		"/api/v1/x?y=1":    "/-/auth/login?return=%2F",
		"/API/x":           "/-/auth/login?return=%2F",
		"/p?u=//evil.test": "/-/auth/login?return=%2F",
	} {
		r := tReq(h, "GET", "https://"+a+target, nil, append(nav("same-origin"), "Referer", fmt.Sprintf("https://%s/-/auth/session?at=%d", a, time.Now().Unix()))...)
		body := tBody(t, r)
		m := regexp.MustCompile(`<a href="([^"]*)">`).FindAllStringSubmatch(body, -1)
		if r.StatusCode != 401 || !strings.Contains(body, wUnpresent) || len(m) != 1 || strings.ReplaceAll(m[0][1], "&amp;", "&") != want {
			t.Errorf("%s: %d, links %q, want %q", target, r.StatusCode, m, want)
		}
	}
}

func TestFlow_Refusals_AsTheGateway(t *testing.T) {
	h := tFlow()
	a := "https://" + tA + "." + tStudio
	si := "https://" + tSignIn
	for _, c := range []struct {
		name, url, code string
		status          int
		hdr             []string
	}{
		{"cross origin, sign-in seam", a + "/-/auth/login", "cross_origin", 403, []string{"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "cors"}},
		{"cross origin, a project's API", a + "/api/x", "cross_origin", 403, append(nav("cross-site"), "Cookie", "__Host-sp-session=s."+tA)},
		{"cross origin, the API in capitals", a + "/API/x", "cross_origin", 403, append(nav("cross-site"), "Cookie", "__Host-sp-session=s."+tA)},
		{"cross origin, the picker", si + "/", "cross_origin", 403, []string{"Sec-Fetch-Site", "same-site", "Cookie", "__Host-sp-session=s._"}},
		{"not found, sign-in host", si + "/x", "not_found", 404, nil},
		{"not found, under /-/auth/", a + "/-/auth/none", "not_found", 404, nil},
		{"not found, the callback on a project host", a + "/-/auth/callback", "not_found", 404, nil},
		{"not found, a ref outside the table", "https://dddddddddddddddddddd." + tStudio + "/", "not_found", 404, nil},
		{"not found, the studio domain", "https://" + tStudio + "/x", "not_found", 404, nil},
		{"login required, a project host", a + "/p", "login_required", 401, []string{"Sec-Fetch-Mode", "cors"}},
		{"login required, the picker", si + "/", "login_required", 401, []string{"Accept", "application/json"}},
	} {
		r := tReq(h, "GET", c.url, nil, c.hdr...)
		if got := refusalCode(t, r); r.StatusCode != c.status || got != c.code {
			t.Errorf("%s: %d %q, want %d %q", c.name, r.StatusCode, got, c.status, c.code)
		}
	}
	// Without a session a project page is first a sign-in, whatever the site.
	if r := tReq(h, "GET", a+"/api/x", nil, nav("cross-site")...); r.StatusCode != 302 {
		t.Errorf("cross-site navigation without a session: %d", r.StatusCode)
	}
	// Accept is read in any letter case.
	for _, accept := range []string{"text/html", "TEXT/HTML", "Text/Html;q=0.9"} {
		if r := tReq(h, "GET", a+"/p", nil, "Accept", accept); r.StatusCode != 302 {
			t.Errorf("Accept %q: %d", accept, r.StatusCode)
		}
	}
	// A state whose path is not written in its one spelling is refused, at the
	// callback and at the session endpoint.
	pre := "v1." + tA + ".AAAAAAAAAAA.0."
	for _, st := range []string{pre + "Lx", pre + "L2F", pre + "Lw\n", pre + "Lw\r", pre, pre + "Lw=", pre + "L w"} {
		f := url.Values{"id_token": {"idt.x"}, "state": {st}}
		if r := tReq(h, "POST", si+"/-/auth/callback", f); r.StatusCode != 400 {
			t.Errorf("callback, state %q: %d", st, r.StatusCode)
		}
		if r := tReq(h, "POST", a+"/-/auth/session", f); r.StatusCode != 400 {
			t.Errorf("session, state %q: %d", st, r.StatusCode)
		}
	}
	// The attempt's cookie counts only holding a secret of 43 characters:
	// another value is a binding failure, whatever the token.
	st := pre + "Lw"
	if r := tReq(h, "POST", a+"/-/auth/session", url.Values{"id_token": {"idt." + nonceOf("short")}, "state": {st}}, "Cookie", loginPrefix+"AAAAAAAAAAA=short"); r.StatusCode != 200 || !strings.Contains(tBody(t, r), "retry=1") {
		t.Errorf("a cookie that holds no secret: %d", r.StatusCode)
	}

	// Control: the spelling that is the path's.
	if r := tReq(h, "POST", si+"/-/auth/callback", url.Values{"id_token": {"idt.x"}, "state": {pre + "L2E"}}); r.StatusCode != 200 {
		t.Errorf("control: %d", r.StatusCode)
	}
}
