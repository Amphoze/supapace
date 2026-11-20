package main

// sp-dashstub flow: a model of the dashboard's sign-in and log-out for browser
// tests. On one TLS listener it serves the studio domain S (one redirect),
// the sign-in host sign-in.S, the project hosts <ref>.S and an issuer host,
// with the gateway's endpoints, cookie names and attributes, state, statuses,
// pages-policy headers and order of requests. It checks no signature: the ID
// token is "idt." and the nonce, and a session cookie is "s." and the host's
// ref ("_" on the sign-in host). One principal is a member of every ref given.
//
// For the tests, the issuer host also serves /link?to=URL (a page on another
// site with a link to a dashboard URL) and /-/count, which answers
// {"dashboard": n, "issuer": m} — the requests to the dashboard's hosts (S,
// the sign-in host, the project hosts; /favicon.ico not counted) and to the
// authorisation endpoint since the last read — and resets both — and
// /-/clock?add=N, which moves the model's clock N seconds ahead, and
// /-/drop-session?n=N, after which the next N successful sign-ins answer
// without the session cookie (a browser that did not keep it). The
// authorisation page submits itself unless the issuer host holds the cookie
// hold=1, which keeps an attempt open at the issuer until its button is
// pressed.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func init() { subcommands["flow"] = flow }

const (
	flowClientID    = "dashboard"
	flowSessionSecs = 28800
	loginPrefix     = "__Host-sp-login-"
	sessionCookie   = "__Host-sp-session"
	maxLoginCookies = 16
	maxTicketRefs   = 16
	maxStateLen     = 1404
	maxReturnLen    = 1024
	signInLabel     = "sign-in"
	hsts            = "max-age=31536000"
	markSecs        = 60 // how long the session page's Referer marks a navigation
	ticketSecs      = 60
)

var (
	flowRefRE   = regexp.MustCompile(`^[a-z0-9]{20}$`)
	flowTokenRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`) // and at most 8 KiB
	flowHostRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	stateRE     = regexp.MustCompile(`^v1\.(_|[a-z0-9]{20})\.([A-Za-z0-9_-]{11})\.([01])\.([A-Za-z0-9_-]+)$`)
	secretRE    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	loginNameRE = regexp.MustCompile(`^__Host-sp-login-[A-Za-z0-9_-]{11}$`)
	secondsRE   = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
)

func flow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("flow", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "", "TLS listen address")
	cert := fs.String("cert", "", "certificate PEM file covering every host")
	key := fs.String("key", "", "key PEM file")
	studio := fs.String("studio-domain", "", "studio domain")
	issuer := fs.String("issuer-host", "", "the issuer's host, another site")
	refsArg := fs.String("refs", "", "comma-separated refs of the principal's projects")
	usage := func() int {
		fmt.Fprintln(stderr, "usage: sp-dashstub flow --listen ADDR --cert FILE --key FILE --studio-domain NAME --issuer-host NAME --refs REF[,REF...]")
		return 2
	}
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *listen == "" || *cert == "" || *key == "" {
		return usage()
	}
	refs := strings.Split(*refsArg, ",")
	slices.Sort(refs)
	switch {
	case !flowHostRE.MatchString(*studio), !flowHostRE.MatchString(*issuer),
		*issuer == *studio, strings.HasSuffix(*issuer, "."+*studio), strings.HasSuffix(*studio, "."+*issuer),
		len(slices.Compact(slices.Clone(refs))) != len(refs),
		slices.ContainsFunc(refs, func(r string) bool { return !flowRefRE.MatchString(r) }):
		return usage()
	}
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fmt.Fprintln(stderr, "flow:", err)
		return 1
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(stderr, "flow:", err)
		return 1
	}
	fmt.Fprintln(stdout, "listening", ln.Addr())
	srv := &http.Server{
		Handler:           newFlow(*studio, *issuer, refs),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Fprintln(stderr, "flow:", srv.ServeTLS(ln, "", ""))
	return 1
}

type flowModel struct {
	studio, signIn, issuer string
	refs                   []string // sorted
	policy                 map[string]string
	dashN, issuerN         atomic.Int64
	now                    func() time.Time
	ahead                  atomic.Int64 // seconds added to now by /-/clock
	dropSessions           atomic.Int64 // successful sign-ins whose session cookie is not set (/-/drop-session)
}

func newFlow(studio, issuer string, refs []string) *flowModel {
	return &flowModel{studio: studio, signIn: signInLabel + "." + studio, issuer: issuer, now: time.Now,
		refs: slices.Sorted(slices.Values(refs)), policy: map[string]string{
			"Content-Security-Policy":      pagesPolicy("'none'", "'none'"),
			"X-Content-Type-Options":       "nosniff",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cross-Origin-Resource-Policy": "same-origin",
			"Referrer-Policy":              "same-origin",
			"Cache-Control":                "no-store",
		}}
}

func (m *flowModel) clock() int64 { return m.now().Unix() + m.ahead.Load() }

// pagesPolicy is the gateway-pages policy: script is the hash of the
// answer's one script or 'none', the style the one constant style's.
func pagesPolicy(script, formAction string) string {
	return "default-src 'none'; script-src " + script + "; style-src " + hashOf(flowStyle) +
		"; frame-ancestors 'none'; base-uri 'none'; form-action " + formAction
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// The page scripts and style, constant so that the policy admits them by hash.
const (
	relayScript   = `document.forms[0].submit()`
	sessionScript = `location.replace(document.getElementById("next").getAttribute("href"))`
	issuerScript  = `if (!document.cookie.split("; ").includes("hold=1")) document.forms[0].submit()`
	flowStyle     = `body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem}`
)

// The gateway's words.
const (
	textDidNotComplete = "Sign-in did not complete."
	textFailed         = "Sign-in could not be completed."
	textNoCookie       = "This browser did not keep the sign-in cookie. Allow cookies for this site, then start again."
	textUnpresented    = "Sign-in completed, and this browser did not send back the session cookie it was given. Allow cookies for this site, then start again."
	textMethod         = "This address takes the sign-in form and nothing else."
	textBadTicket      = "Log out did not complete: this log-out address is not valid or is no longer valid."
	textSignedOut      = "Log out from a dashboard ends the session of that dashboard, of up to sixteen other projects of yours, and of this sign-in page."
	textEnded          = "No dashboard session was shown with this log-out, so none was ended. The session of this sign-in page is ended. A session still open on a dashboard is ended by Log out from a page of that dashboard."
	textMore           = "Sessions on further projects stay valid until they expire or your access is revoked."
)

var flowPages = template.Must(template.New("").Parse(`
{{define "head"}}<!doctype html><title>{{.}}</title><style>` + flowStyle + `</style>{{end}}
{{define "form"}}{{template "head" .Title}}<form method="post" action="{{.Action}}">{{range $k, $v := .Fields}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}<button>Continue</button></form><script>{{.Script}}</script>{{end}}
{{define "next"}}{{template "head" .Title}}<noscript><meta http-equiv="refresh" content="0;url={{.Next}}"></noscript><a id="next" href="{{.Next}}">Continue</a><script>` + sessionScript + `</script>{{end}}
{{define "text"}}{{template "head" .Title}}<p id="text">{{.Text}}</p>{{range .Links}}<a href="{{.}}">{{.}}</a>{{end}}{{end}}
{{define "signedout"}}{{template "head" "Log out"}}<p id="text">{{if .Ended}}` + textEnded + `{{else}}` + textSignedOut + `{{end}}</p>{{if .More}}<p>` + textMore + `</p>{{end}}{{end}}
{{define "link"}}<!doctype html><title>link</title><a id="go" href="{{.}}">open</a>{{end}}
`))

func (m *flowModel) page(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	flowPages.ExecuteTemplate(w, name, data)
}

func (m *flowModel) text(w http.ResponseWriter, status int, text string, links ...string) {
	m.page(w, status, "text", map[string]any{"Title": text, "Text": text, "Links": links})
}

// next is the page that navigates to next: the session page and the retry
// page, with the hash of their one script.
func (m *flowModel) next(w http.ResponseWriter, title, next string) {
	w.Header().Set("Content-Security-Policy", pagesPolicy(hashOf(sessionScript), "'none'"))
	m.page(w, http.StatusOK, "next", map[string]any{"Title": title, "Next": template.URL(next)})
}

// refuse is a refusal that is not a page, as the gateway writes one.
func refuse(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"code":%q}`, code)
}

// navigation is the gateway's reading of one: Sec-Fetch-Mode navigate, or a
// GET that accepts text/html in any letter case.
func navigation(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Mode") == "navigate" ||
		r.Method == http.MethodGet && strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// crossOrigin is the gateway's same-origin rule: a Sec-Fetch-Site that is
// present and neither same-origin nor none, unless the request is a
// top-level navigation by GET to something that is not an API path.
func crossOrigin(r *http.Request, path string) bool {
	first, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	for _, v := range r.Header.Values("Sec-Fetch-Site") {
		if v != "same-origin" && v != "none" && !(r.Method == http.MethodGet && strings.ToLower(first) != "api" &&
			r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document") {
			return true
		}
	}
	return false
}

// origin is the host of a target: a ref's host, or the sign-in host for "_".
func (m *flowModel) origin(ref string) string {
	if ref == "_" {
		return "https://" + m.signIn
	}
	return "https://" + ref + "." + m.studio
}

func (m *flowModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch {
	case host == m.issuer:
		m.serveIssuer(w, r)
		return
	case host == m.studio:
		m.dashN.Add(1)
		w.Header().Set("Strict-Transport-Security", hsts)
		if r.URL.Path == "/" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			http.Redirect(w, r, "https://"+m.signIn+"/", http.StatusFound)
			return
		}
		refuse(w, http.StatusNotFound, "not_found")
		return
	}
	ref := "_"
	if host != m.signIn {
		label, ok := strings.CutSuffix(host, "."+m.studio)
		if !ok || !slices.Contains(m.refs, label) {
			if ok {
				w.Header().Set("Strict-Transport-Security", hsts) // a host the gateway serves
			}
			refuse(w, http.StatusNotFound, "not_found")
			return
		}
		ref = label
	}
	p := r.URL.Path
	if p != "/favicon.ico" {
		m.dashN.Add(1)
	}
	for k, v := range m.policy {
		w.Header().Set(k, v)
	}
	w.Header().Set("Strict-Transport-Security", hsts)
	if ref == "_" {
		w.Header().Set("Origin-Agent-Cluster", "?1")
	}
	isGet, isPost := r.Method == http.MethodGet, r.Method == http.MethodPost
	// The sign-in seam: the sign-in host and /-/auth/ on a project host.
	// The two posts are cross-site by design; every other answer of the
	// seam is under the same-origin rule first.
	seam := ref == "_" || strings.HasPrefix(p, "/-/auth/")
	posts := p == "/-/auth/session" || p == "/-/auth/callback" && ref == "_"
	switch {
	case posts && !isPost:
		m.text(w, http.StatusMethodNotAllowed, textMethod)
		return
	case seam && !posts && crossOrigin(r, p):
		refuse(w, http.StatusForbidden, "cross_origin")
		return
	}
	switch {
	case p == "/-/auth/login" && isGet:
		m.login(w, r, ref)
	case p == "/-/auth/callback" && ref == "_":
		m.callback(w, r)
	case p == "/-/auth/session":
		m.session(w, r, ref)
	case p == "/-/auth/logout" && isGet:
		m.logout(w, r, ref)
	case p == "/-/auth/signed-out" && isGet && ref == "_":
		m.signedOut(w, r)
	case strings.HasPrefix(p, "/-/auth/"), ref == "_" && (p != "/" || !isGet): // a path or a method the seam does not name
		refuse(w, http.StatusNotFound, "not_found")
	case !m.hasSession(r, ref):
		switch {
		case navigation(r) && m.markedBySessionPage(r, host):
			m.text(w, http.StatusUnauthorized, textUnpresented, "/-/auth/login?return="+url.QueryEscape(returnPath(r.URL.RequestURI())))
		case navigation(r) && ref == "_":
			http.Redirect(w, r, "/-/auth/login", http.StatusFound)
		case navigation(r):
			http.Redirect(w, r, "/-/auth/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		default:
			refuse(w, http.StatusUnauthorized, "login_required")
		}
	case !seam && crossOrigin(r, p): // a project page: the session first, as the gateway's rules
		refuse(w, http.StatusForbidden, "cross_origin")
	case ref == "_":
		var links []string
		for _, x := range m.refs {
			links = append(links, m.origin(x)+"/")
		}
		m.text(w, http.StatusOK, "projects", links...)
	default:
		m.text(w, http.StatusOK, "page "+ref+" "+r.URL.RequestURI())
	}
}

// markedBySessionPage: the Referer is exactly this host's session endpoint
// with an at of the last minute, in plain decimal seconds.
func (m *flowModel) markedBySessionPage(r *http.Request, host string) bool {
	at, ok := strings.CutPrefix(r.Header.Get("Referer"), "https://"+host+"/-/auth/session?at=")
	if !ok || !secondsRE.MatchString(at) {
		return false
	}
	n, err := strconv.ParseInt(at, 10, 64)
	now := m.clock()
	if err != nil {
		return false
	}
	return n <= now && n >= now-markSecs
}

// hasSession: the session cookie exactly once, and it is this host's.
func (m *flowModel) hasSession(r *http.Request, ref string) bool {
	vals := cookieValues(r, sessionCookie)
	return len(vals) == 1 && vals[0] == "s."+ref
}

func cookieValues(r *http.Request, name string) []string {
	var vals []string
	for _, c := range r.Cookies() {
		if c.Name == name {
			vals = append(vals, c.Value)
		}
	}
	return vals
}

func (m *flowModel) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	same := "Strict"
	if strings.HasPrefix(name, loginPrefix) {
		same = "None"
	}
	w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=%s", name, value, maxAge, same))
}

func (m *flowModel) clear(w http.ResponseWriter, name string) { m.setCookie(w, name, "", 0) }

// loginCookies: the names of the login cookies the request carries, in
// order; a name that is not __Host-sp-login- and 11 base64url characters is
// not one.
func loginCookies(r *http.Request) []string {
	var names []string
	for _, c := range r.Cookies() {
		if loginNameRE.MatchString(c.Name) && !slices.Contains(names, c.Name) {
			names = append(names, c.Name)
		}
	}
	return names
}

func (m *flowModel) clearShownLogins(w http.ResponseWriter, r *http.Request) {
	for _, n := range loginCookies(r) {
		m.clear(w, n)
	}
}

// returnPath keeps a path of this origin and makes anything else "/": one
// leading "/", no "//", no backslash, no byte 0x00-0x20 or 0x7f, at most
// 1,024 bytes; its path (before any "?" or "#") passes rule 0, and its first segment,
// decoded once and lower-cased, is neither "-" nor "api". Query and fragment
// are kept.
func returnPath(s string) string {
	if !strings.HasPrefix(s, "/") || len(s) > maxReturnLen || strings.Contains(s, "//") || strings.Contains(s, `\`) ||
		strings.ContainsFunc(s, func(c rune) bool { return c <= 0x20 || c == 0x7f }) {
		return "/"
	}
	path := s
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		path = s[:i]
	}
	if !ruleZero(path) {
		return "/"
	}
	first, _, _ := strings.Cut(path[1:], "/")
	first, _ = url.PathUnescape(first)
	if f := strings.ToLower(first); f == "-" || f == "api" {
		return "/"
	}
	return s
}

// ruleZero is the gateway's rule 0 for a path: no empty segment (but the
// root), no "." or ".." segment after decoding, no backslash, control byte or
// byte above 0x7e raw or decoded, no malformed "%", no encoded "/".
func ruleZero(path string) bool {
	if path == "/" {
		return true
	}
	bad := func(s string) bool {
		return strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 || c > 0x7e || c == '\\' })
	}
	for _, seg := range strings.Split(path[1:], "/") {
		d, err := url.PathUnescape(seg)
		if seg == "" || err != nil || d == "." || d == ".." || strings.Contains(d, "/") || bad(d) {
			return false
		}
	}
	return true
}

func nonceOf(r string) string {
	sum := sha256.Sum256([]byte(r))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randB64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

type attempt struct {
	target, a string
	retry     bool
	ret       string // validated
}

// parseState reads v1.<target>.<a>.<n>.<p>; target must be "_" or a ref of
// the table, and p the return path in its one spelling (strict unpadded
// base64url, not empty). The return path is validated as it is read.
func (m *flowModel) parseState(s string) (attempt, bool) {
	f := stateRE.FindStringSubmatch(s)
	if len(s) > maxStateLen || f == nil || f[1] != "_" && !slices.Contains(m.refs, f[1]) {
		return attempt{}, false
	}
	p, err := base64.RawURLEncoding.Strict().DecodeString(f[4])
	if err != nil {
		return attempt{}, false
	}
	return attempt{target: f[1], a: f[2], retry: f[3] == "1", ret: returnPath(string(p))}, true
}

func (m *flowModel) login(w http.ResponseWriter, r *http.Request, ref string) {
	if shown := loginCookies(r); len(shown) >= maxLoginCookies {
		for _, n := range shown {
			m.clear(w, n)
		}
	}
	ret := returnPath(r.URL.Query().Get("return"))
	a, rnd := randB64(8), randB64(32)
	n := "0"
	if r.URL.Query().Get("retry") == "1" {
		n = "1"
	}
	m.setCookie(w, loginPrefix+a, rnd, 600)
	state := strings.Join([]string{"v1", ref, a, n, base64.RawURLEncoding.EncodeToString([]byte(ret))}, ".")
	q := url.Values{"response_type": {"id_token"}, "response_mode": {"form_post"}, "client_id": {flowClientID},
		"redirect_uri": {"https://" + m.signIn + "/-/auth/callback"}, "scope": {"openid"},
		"nonce": {nonceOf(rnd)}, "state": {state}}
	http.Redirect(w, r, "https://"+m.issuer+"/authorize?"+q.Encode(), http.StatusFound)
}

// twoFields reads id_token and state, each exactly once, from a body of at
// most 16 KiB of application/x-www-form-urlencoded, and nothing from the
// address; ok is false otherwise. hasError reports the field error.
func twoFields(w http.ResponseWriter, r *http.Request) (tok, state string, hasError, ok bool) {
	const limit = 16 << 10
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" || r.ContentLength > limit {
		return "", "", false, false
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return "", "", false, false
	}
	f, err := url.ParseQuery(string(b))
	if err != nil {
		return "", "", false, false
	}
	_, hasError = f["error"]
	if len(f["id_token"]) != 1 || len(f["state"]) != 1 {
		return "", "", false, false
	}
	return f["id_token"][0], f["state"][0], hasError, true
}

// callback reads and sets no cookie: it relays the token and the state to the
// state's target, at its session endpoint with the relay's clock.
func (m *flowModel) callback(w http.ResponseWriter, r *http.Request) {
	tok, state, hasError, ok := twoFields(w, r)
	at, valid := m.parseState(state)
	if !ok || hasError || !valid || len(tok) > 8<<10 || !flowTokenRE.MatchString(tok) {
		m.text(w, http.StatusBadRequest, textDidNotComplete)
		return
	}
	w.Header().Set("Content-Security-Policy", pagesPolicy(hashOf(relayScript), m.origin(at.target)))
	m.page(w, http.StatusOK, "form", map[string]any{"Title": "signing in", "Script": template.JS(relayScript),
		"Action": template.URL(fmt.Sprintf("%s/-/auth/session?at=%d", m.origin(at.target), m.clock())),
		"Fields": map[string]string{"id_token": tok, "state": state}})
}

// session checks, in order: the state's form and target; the attempt's
// cookie, exactly once (with none the token is not verified); the token,
// its nonce last. The model's token is "idt." and the nonce; any other form
// stands for a token that fails before its nonce.
func (m *flowModel) session(w http.ResponseWriter, r *http.Request, ref string) {
	tok, state, _, ok := twoFields(w, r)
	at, valid := m.parseState(state)
	if !ok || !valid || at.target != ref {
		m.text(w, http.StatusBadRequest, textDidNotComplete)
		return
	}
	name := loginPrefix + at.a
	held := cookieValues(r, name)
	if len(held) > 0 {
		m.clear(w, name) // read, so cleared on every answer
	}
	again := "/-/auth/login?return=" + url.QueryEscape(at.ret)
	if len(held) == 1 && secretRE.MatchString(held[0]) {
		nonce, isToken := strings.CutPrefix(tok, "idt.")
		if !isToken {
			m.text(w, http.StatusUnauthorized, textFailed, again)
			return
		}
		if nonce == nonceOf(held[0]) {
			if m.dropSessions.Add(-1) < 0 {
				m.dropSessions.Store(0)
				m.setCookie(w, sessionCookie, "s."+ref, flowSessionSecs)
			}
			m.next(w, "signed in", at.ret)
			return
		}
	}
	switch {
	case !at.retry:
		m.next(w, "signing in", again+"&retry=1")
	case len(loginCookies(r)) == 0:
		m.text(w, http.StatusUnauthorized, textNoCookie, again)
	default:
		m.text(w, http.StatusUnauthorized, textFailed, again)
	}
}

// logout: with t, the model's ticket "<iat>.<more>.<refs still to visit>"
// (one query parameter, on a project host only, expiring 60 s after iat,
// refused at exactly 60 s; more 0 or 1), this host must be its first ref and
// the next hop's ticket keeps iat and more; without, a session of this host
// builds the chain over at most 16 other refs, more set when there were
// further ones, and no session goes to the signed-out page with ended=0. The
// last hop adds more=1 when more is set. Every answer clears the login
// cookies it was shown; a query that does not parse is refused.
func (m *flowModel) logout(w http.ResponseWriter, r *http.Request, ref string) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	t, hop := q["t"]
	if err != nil || hop && (len(t) != 1 || ref == "_") {
		m.text(w, http.StatusBadRequest, textBadTicket)
		return
	}
	signedOut := "https://" + m.signIn + "/-/auth/signed-out"
	var next []string
	more, iat := false, m.clock()
	switch {
	case hop:
		f := strings.SplitN(t[0], ".", 3)
		if len(f) != 3 {
			m.text(w, http.StatusBadRequest, textBadTicket)
			return
		}
		hops := strings.Split(f[2], ",")
		n, err := strconv.ParseInt(f[0], 10, 64)
		if !secondsRE.MatchString(f[0]) || err != nil || n > iat || iat-n >= ticketSecs || f[1] != "0" && f[1] != "1" ||
			hops[0] != ref || len(hops) > maxTicketRefs ||
			slices.ContainsFunc(hops, func(x string) bool { return !slices.Contains(m.refs, x) }) {
			m.text(w, http.StatusBadRequest, textBadTicket)
			return
		}
		next, iat, more = hops[1:], n, f[1] == "1"
		m.clear(w, sessionCookie)
	case m.hasSession(r, ref):
		m.clear(w, sessionCookie)
		for _, x := range m.refs {
			if x != ref {
				next = append(next, x)
			}
		}
		if len(next) > maxTicketRefs {
			next, more = next[:maxTicketRefs], true
		}
	default:
		if len(cookieValues(r, sessionCookie)) > 0 {
			m.clear(w, sessionCookie) // shown, so cleared
		}
		m.clearShownLogins(w, r)
		http.Redirect(w, r, signedOut+"?ended=0", http.StatusFound)
		return
	}
	m.clearShownLogins(w, r)
	if len(next) == 0 {
		if more {
			signedOut += "?more=1"
		}
		http.Redirect(w, r, signedOut, http.StatusFound)
		return
	}
	mark := "0"
	if more {
		mark = "1"
	}
	tk := fmt.Sprintf("%d.%s.%s", iat, mark, strings.Join(next, ","))
	http.Redirect(w, r, m.origin(next[0])+"/-/auth/logout?t="+url.QueryEscape(tk), http.StatusFound)
}

// signedOut is the sign-in host's last page: it clears that host's session
// cookie and the login cookies shown, whatever the query. more=1 and ended=0,
// each written exactly so and once, select a fixed sentence; nothing of the
// query is rendered.
func (m *flowModel) signedOut(w http.ResponseWriter, r *http.Request) {
	m.clear(w, sessionCookie)
	m.clearShownLogins(w, r)
	count, written := map[string]int{}, map[string]bool{}
	for _, kv := range strings.Split(r.URL.RawQuery, "&") {
		k, _, _ := strings.Cut(kv, "=")
		count[k]++
		written[kv] = true
	}
	m.page(w, http.StatusOK, "signedout", map[string]bool{
		"Ended": count["ended"] == 1 && written["ended=0"], "More": count["more"] == 1 && written["more=1"]})
}

func (m *flowModel) serveIssuer(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch r.URL.Path {
	case "/authorize":
		m.issuerN.Add(1)
		if q.Get("redirect_uri") != "https://"+m.signIn+"/-/auth/callback" || q.Get("response_mode") != "form_post" ||
			q.Get("response_type") != "id_token" || q.Get("client_id") != flowClientID || q.Get("nonce") == "" {
			http.Error(w, "bad_request", http.StatusBadRequest)
			return
		}
		m.page(w, http.StatusOK, "form", map[string]any{"Title": "issuer", "Script": template.JS(issuerScript),
			"Action": template.URL(q.Get("redirect_uri")),
			"Fields": map[string]string{"id_token": "idt." + q.Get("nonce"), "state": q.Get("state")}})
	case "/link":
		u, err := url.Parse(q.Get("to"))
		if err != nil || u.Scheme != "https" || u.Host != m.studio && !strings.HasSuffix(u.Host, "."+m.studio) {
			http.Error(w, "bad_request", http.StatusBadRequest)
			return
		}
		m.page(w, http.StatusOK, "link", template.URL(u.String()))
	case "/-/count":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"dashboard":%d,"issuer":%d}`, m.dashN.Swap(0), m.issuerN.Swap(0))
	case "/-/drop-session":
		var n int64
		if _, err := fmt.Sscan(q.Get("n"), &n); err != nil || n < 0 {
			http.Error(w, "bad_request", http.StatusBadRequest)
			return
		}
		m.dropSessions.Store(n)
		fmt.Fprintln(w, n)
	case "/-/clock":
		var n int64
		if _, err := fmt.Sscan(q.Get("add"), &n); err != nil || n < 0 {
			http.Error(w, "bad_request", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, m.ahead.Add(n))
	default:
		http.Error(w, "not_found", http.StatusNotFound)
	}
}
