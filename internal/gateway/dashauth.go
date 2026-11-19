package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/jwtx"
)

// Dashboard sign-in: an OpenID Connect ID token posted by the issuer to the
// sign-in host, relayed once to the host that began the attempt, verified
// there and exchanged for a session cookie of that host alone. The gateway
// keeps no state: an attempt lives in its login cookie and its state, a
// session in its cookie.
//
// An attempt has an id a (8 random bytes, 11 characters), a secret R (32
// random bytes, 43 characters) held only in the cookie __Host-sp-login-<a>,
// and a state v1.<target>.<a>.<n>.<p>: the ref of the host that began it
// ("_" for the sign-in host), 1 for n when it is the one retry, and the
// return path. The nonce sent to the issuer is the SHA-256 of R's 43
// characters. The state is neither signed nor secret; everything it names is
// validated where it is used.

func init() { dashAuth = serveSignIn }

const (
	loginPrefix     = "__Host-sp-login-"
	loginSeconds    = 600  // an attempt's cookie lives ten minutes
	maxLoginCookies = 16   // a login that is shown this many clears them first
	maxState        = 1404 // characters
	maxReturn       = 1024 // bytes of a return path
	maxIDToken      = 8 << 10
)

var (
	loginNameRE = regexp.MustCompile(`^__Host-sp-login-[A-Za-z0-9_-]{11}$`)
	secretRE    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	stateRE     = regexp.MustCompile(`^v1\.(_|[a-z0-9]{20})\.([A-Za-z0-9_-]{11})\.([01])\.([A-Za-z0-9_-]+)$`)
	idTokenRE   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// signIn is one request to the sign-in handler.
type signIn struct {
	w   http.ResponseWriter
	r   *http.Request
	d   *Dashboard
	dt  *dashTable
	is  *dashfile.Issuer
	ref string // the host's ref; "_" on the sign-in host
	now time.Time
}

// serveSignIn answers every request of the sign-in host, /-/auth/ on a
// dashboard host, and a dashboard navigation whose session cookie did not
// come back. It holds no slot and reaches no upstream.
func serveSignIn(w http.ResponseWriter, r *http.Request, dr *dashRequest) {
	// The table as it is now, with its index: one reading for the whole
	// request. It may be newer than the one the request was classified
	// against; the two cases that matters for are answered as the class
	// switch answers them.
	s := &signIn{w: w, r: r, d: dr.Dash, dt: dr.Dash.table.cur.Load(), ref: dr.Ref, now: time.Now()}
	switch {
	case s.dt == nil || s.dt.file.Issuer == nil: // no table; no issuer set yet
		s.refuse(http.StatusServiceUnavailable, "unavailable")
		return
	case !s.hosted(s.ref):
		s.refuse(http.StatusNotFound, "not_found")
		return
	}
	s.is = s.dt.file.Issuer
	if dr.Unpresented {
		s.unpresented()
		return
	}
	path, query, _ := strings.Cut(r.RequestURI, "?")
	// The two posts: the issuer's to the sign-in host and the relay's to the
	// attempt's host. Any other method there is refused without a redirect,
	// which would carry a token in a fragment along; and they alone are
	// exempt from the same-origin rule, being cross-site by design.
	posts := path == "/-/auth/session" || path == "/-/auth/callback" && s.ref == "_"
	switch {
	case posts && r.Method != http.MethodPost:
		s.refusal(http.StatusMethodNotAllowed, textMethod, "")
		return
	case !posts && crossOrigin(r, dr.Lower):
		s.refuse(http.StatusForbidden, "cross_origin")
		return
	}
	get := r.Method == http.MethodGet
	switch {
	case posts && path == "/-/auth/callback":
		s.callback()
	case posts:
		s.session()
	case get && path == "/-/auth/login":
		s.login(query)
	case get && path == "/-/auth/logout":
		s.logout(query)
	case get && path == "/-/auth/signed-out" && s.ref == "_":
		s.signedOut(query)
	case get && path == "/" && s.ref == "_":
		s.picker()
	default:
		s.refuse(http.StatusNotFound, "not_found")
	}
}

// hosted reports whether ref is the sign-in host's or a ref of the table.
func (s *signIn) hosted(ref string) bool {
	_, ok := s.dt.file.Projects[ref]
	return ok || ref == "_"
}

// origin is the origin of a ref's host; the sign-in host's for "_". ref is
// "_" or a ref of the table, so nothing of a request names a host.
func (s *signIn) origin(ref string) string {
	if ref == "_" {
		ref = dashcfg.SignInLabel
	}
	return "https://" + ref + "." + s.d.domain
}

// crossOrigin is the dashboard's same-origin rule: a Sec-Fetch-Site that is
// present and neither same-origin nor none, unless the request is a
// top-level navigation by GET to something that is not an API path.
func crossOrigin(r *http.Request, lower []string) bool {
	for _, v := range r.Header.Values("Sec-Fetch-Site") {
		if v != "same-origin" && v != "none" && !(r.Method == http.MethodGet && !apiPath(lower) &&
			r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document") {
			return true
		}
	}
	return false
}

// navigation reports whether a GET is a navigation, as the session rule
// reads one.
func navigation(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Mode") == "navigate" || strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: sameSite})
}

// Clearing a cookie is its name and attributes with Max-Age=0.
func (s *signIn) clearLogin(name string) { setCookie(s.w, name, "", -1, http.SameSiteNoneMode) }
func (s *signIn) clearSession()          { setCookie(s.w, sessionCookie, "", -1, http.SameSiteStrictMode) }

// loginCookies are the names of the login cookies r carries, each once, in
// order. A login cookie is a cookie named __Host-sp-login- and exactly 11
// base64url characters; no other name is counted, cleared or read as one.
func loginCookies(r *http.Request) []string {
	var names []string
	seen := map[string]bool{}
	for _, c := range r.Cookies() {
		if loginNameRE.MatchString(c.Name) && !seen[c.Name] {
			seen[c.Name] = true
			names = append(names, c.Name)
		}
	}
	return names
}

func (s *signIn) clearShownLogins() {
	for _, n := range loginCookies(s.r) {
		s.clearLogin(n)
	}
}

// returnPath keeps a path of this origin a sign-in may end on and makes
// anything else "/". It begins with one "/"; holds no "//", no backslash and
// no byte 0x00 to 0x20 or 0x7f; is at most 1,024 bytes; its path — what
// precedes any "?" or "#" — passes the gateway's rule for a request path, so
// that a browser requests it as written; and the first segment of that,
// percent-decoded once and lower-cased, is neither "-" nor "api": never one
// of the gateway's own endpoints, never an API route. It is never a URL. The
// query and the fragment are kept.
func returnPath(p string) string {
	if len(p) > maxReturn || !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.Contains(p, `\`) {
		return "/"
	}
	for i := 0; i < len(p); i++ {
		if p[i] <= 0x20 || p[i] == 0x7f {
			return "/"
		}
	}
	path := p
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		path = p[:i]
	}
	segs, ok := readPath(path)
	if !ok {
		return "/"
	}
	if len(segs) > 0 {
		if first := strings.ToLower(segs[0]); first == "-" || first == "api" {
			return "/"
		}
	}
	return p
}

// nonceOf is the nonce of an attempt's secret: the unpadded base64url of the
// SHA-256 over its characters.
func nonceOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func random(n int) string {
	b := make([]byte, n)
	rand.Read(b) // never fails
	return base64.RawURLEncoding.EncodeToString(b)
}

// attempt is what a state names. ret is validated.
type attempt struct {
	target, a string
	retry     bool
	ret       string
}

// parseState reads v1.<target>.<a>.<n>.<p>. The target has the shape of a
// ref or is "_"; whether it is a host of the table is the caller's check.
func parseState(state string) (attempt, bool) {
	if len(state) > maxState {
		return attempt{}, false
	}
	m := stateRE.FindStringSubmatch(state)
	if m == nil {
		return attempt{}, false
	}
	p, err := base64.RawURLEncoding.Strict().DecodeString(m[4])
	if err != nil {
		return attempt{}, false
	}
	return attempt{target: m[1], a: m[2], retry: m[3] == "1", ret: returnPath(string(p))}, true
}

// login begins an attempt: GET /-/auth/login?return=<path>[&retry=1].
func (s *signIn) login(query string) {
	au, err := url.Parse(s.is.AuthorizeURL)
	if err != nil || au.Scheme != "https" || au.Host == "" || au.Fragment != "" {
		s.refuse(http.StatusServiceUnavailable, "unavailable") // no address to send a browser to
		return
	}
	// A parameter counts when the query parses and holds it exactly once.
	q, err := url.ParseQuery(query)
	if err != nil {
		q = nil
	}
	ret, n := "/", "0"
	if v := q["return"]; len(v) == 1 {
		ret = returnPath(v[0])
	}
	if v := q["retry"]; len(v) == 1 && v[0] == "1" {
		n = "1"
	}
	if shown := loginCookies(s.r); len(shown) >= maxLoginCookies {
		for _, name := range shown {
			s.clearLogin(name)
		}
	}
	a, secret := random(8), random(32)
	setCookie(s.w, loginPrefix+a, secret, loginSeconds, http.SameSiteNoneMode)
	v := au.Query()
	for k, val := range map[string]string{
		"response_type": "id_token", "response_mode": "form_post", "scope": "openid", "client_id": s.is.ClientID,
		"redirect_uri": s.origin("_") + "/-/auth/callback", "nonce": nonceOf(secret),
		"state": "v1." + s.ref + "." + a + "." + n + "." + base64.RawURLEncoding.EncodeToString([]byte(ret)),
	} {
		v.Set(k, val)
	}
	au.RawQuery = v.Encode()
	s.redirect(au.String())
}

// fields reads the form of a sign-in post: at most 16 KiB of
// application/x-www-form-urlencoded with id_token and state each exactly
// once. Every other field is ignored; hasError reports the field "error".
// Nothing is read from the query.
func (s *signIn) fields() (tok, state string, hasError, ok bool) {
	limit := int64(dashcfg.Limits.SignInBodyBytes)
	mt, _, err := mime.ParseMediaType(s.r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" || s.r.ContentLength > limit {
		return "", "", false, false
	}
	b, err := io.ReadAll(http.MaxBytesReader(s.w, s.r.Body, limit))
	if err != nil {
		return "", "", false, false
	}
	f, err := url.ParseQuery(string(b))
	if err != nil || len(f["id_token"]) != 1 || len(f["state"]) != 1 {
		return "", "", false, false
	}
	_, hasError = f["error"]
	return f["id_token"][0], f["state"][0], hasError, true
}

// callback is the issuer's post to the sign-in host, the one registered
// redirect address. It reads no cookie, sets none and verifies nothing: it
// answers the relay page, which posts the two fields unchanged to the session
// endpoint of the state's target with the gateway's clock.
func (s *signIn) callback() {
	tok, state, hasError, ok := s.fields()
	at, valid := parseState(state)
	if !ok || hasError || !valid || !s.hosted(at.target) || len(tok) > maxIDToken || !idTokenRE.MatchString(tok) {
		s.refusal(http.StatusBadRequest, textDidNotComplete, "")
		return
	}
	origin := s.origin(at.target)
	s.page(http.StatusOK, "relay", struct{ Action, Token, State string }{
		origin + "/-/auth/session?at=" + strconv.FormatInt(s.now.Unix(), 10), tok, state}, relayHash, origin)
}

// session is the relay's post to the host that began the attempt. In order:
// the state's form and its target, which must be this host; the attempt's
// cookie, present exactly once; the token, its nonce last. The cookie is
// cleared on every answer that read it.
func (s *signIn) session() {
	tok, state, _, ok := s.fields()
	at, valid := parseState(state)
	if !ok || !valid || at.target != s.ref {
		s.refusal(http.StatusBadRequest, textDidNotComplete, "")
		return
	}
	name := loginPrefix + at.a
	held := s.r.CookiesNamed(name)
	if len(held) > 0 {
		s.clearLogin(name)
	}
	again := "/-/auth/login?return=" + url.QueryEscape(at.ret)
	// Without the cookie exactly once, holding a secret, the binding has
	// failed and the token is not verified at all.
	if len(held) == 1 && secretRE.MatchString(held[0].Value) {
		c, err := jwtx.VerifyID(tok, s.dt.keys, jwtx.IDCheck{Issuer: s.is.Iss, ClientID: s.is.ClientID, Nonce: nonceOf(held[0].Value)}, s.now)
		switch {
		case err == nil:
			s.signedIn(c, at.ret)
			return
		case !errors.Is(err, jwtx.ErrNonce): // any failure before the nonce, whatever the nonce and whatever n
			s.refusal(http.StatusUnauthorized, textFailed, again)
			return
		}
	}
	switch {
	case !at.retry: // the one retry
		s.page(http.StatusOK, "next", again+"&retry=1", nextHash, "'none'")
	case len(loginCookies(s.r)) == 0:
		s.refusal(http.StatusUnauthorized, textNoCookie, again)
	default:
		s.refusal(http.StatusUnauthorized, textFailed, again)
	}
}

// signedIn sets this host's session cookie and answers the page that
// navigates to ret — a page, not a redirect, so that the request which
// follows is the host's own and carries the cookie.
func (s *signIn) signedIn(c jwtx.IDClaims, ret string) {
	now := s.now.Unix()
	tok, err := dashtok.SignSession(s.d.priv, dashtok.Session{Iss: s.is.Iss, Sub: c.Sub, Name: displayName(c.Name),
		Ref: s.ref, Iat: now, Exp: now + s.is.SessionSeconds})
	if err != nil {
		s.refuse(http.StatusServiceUnavailable, "unavailable")
		return
	}
	setCookie(s.w, sessionCookie, tok, int(s.is.SessionSeconds), http.SameSiteStrictMode)
	s.page(http.StatusOK, "next", ret, nextHash, "'none'")
}

// displayName makes the issuer's name a session's: no control character, no
// U+2028 or U+2029, at most 128 bytes, cut at a rune boundary.
func displayName(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, strings.ToValidUTF8(name, ""))
	if len(name) > 128 {
		i := 128
		for !utf8.RuneStart(name[i]) {
			i--
		}
		name = name[:i]
	}
	return name
}

// unpresented answers a navigation without a session that comes from this
// host's own session page: a session cookie was set and did not come back.
// The page's link carries the request's path and query as a return path.
func (s *signIn) unpresented() {
	s.refusal(http.StatusUnauthorized, textUnpresented, "/-/auth/login?return="+url.QueryEscape(returnPath(s.r.RequestURI)))
}

// projects are the refs of the projects p is a member of, but for except, in
// order.
func (s *signIn) projects(p principal, except string) []string {
	var refs []string
	for ref, members := range s.dt.roles {
		if _, ok := members[p]; ok && ref != except {
			refs = append(refs, ref)
		}
	}
	slices.Sort(refs)
	return refs
}

// picker is the sign-in host's page: the principal's projects, each a link
// to its origin. Without a session it answers as a dashboard host does.
func (s *signIn) picker() {
	sess, ok := s.d.session(s.r, s.dt, "_", s.now)
	switch {
	case ok:
	case !navigation(s.r):
		s.refuse(http.StatusUnauthorized, "login_required")
		return
	case s.d.unpresented(s.r, dashcfg.SignInLabel, s.now):
		s.unpresented()
		return
	default:
		s.redirect("/-/auth/login")
		return
	}
	type project struct{ URL, Name, Ref string }
	data := struct {
		Name     string
		Projects []project
	}{Name: sess.Name}
	for _, ref := range s.projects(principal{sess.Iss, sess.Sub}, "") {
		data.Projects = append(data.Projects, project{s.origin(ref) + "/", s.dt.file.Projects[ref].Name, ref})
	}
	s.page(http.StatusOK, "picker", data, "'none'", "'none'")
}
