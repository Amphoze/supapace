package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/jwtx"
)

// What the sign-in handler must still do when a request, or the moment it
// arrives in, is not the one a browser in a working sign-in makes.

// sessionSet reports whether an answer sets a session cookie.
func sessionSet(w *httptest.ResponseRecorder) bool {
	for _, c := range cookies(w) {
		if strings.HasPrefix(c, sessionCookie+"=v1.") {
			return true
		}
	}
	return false
}

// TestSession_APairPostedAgainSetsNoSession: the answer that read an
// attempt's cookie cleared it, so the token and state of a completed sign-in,
// posted a second time, arrive without it and set no session — with the
// retry still open and with it spent, and whatever else the browser holds.
func TestSession_APairPostedAgainSetsNoSession(t *testing.T) {
	e := newAuthEnv(t)
	for _, retry := range []string{"", "?retry=1"} {
		at := e.login(t, dhostA, retry)
		tok := goodToken(t, at)
		first := e.sessionPost(t, dhostA, tok, at.state, at.cookie)
		e.signedIn(t, "the first post"+retry, first, at, refA, subOwnerA)
		held := ""
		for _, c := range cookies(first) {
			if m := sessionLineRE.FindStringSubmatch(c); m != nil {
				held = sessionCookie + "=" + m[1]
			}
		}
		if held == "" {
			t.Fatal("the first post set no session")
		}
		for name, cookie := range map[string]string{"nothing held": "", "the session held": held} {
			w := e.sessionPost(t, dhostA, tok, at.state, cookie)
			if sessionSet(w) {
				t.Errorf("%s%s: the pair posted again set a session", name, retry)
			}
			if retry == "" {
				retried(t, name, w)
			} else {
				refusal(t, name+retry, w, 401, textNoCookie)
			}
		}
		// Another attempt's secret under this attempt's name is no binding.
		other := e.login(t, dhostA, "")
		if w := e.sessionPost(t, dhostA, tok, at.state, at.name+"="+other.r); sessionSet(w) {
			t.Errorf("another secret%s: a session was set", retry)
		}
	}
}

// TestSession_IssuerKeys_EitherOfTwoSignsIn_NoneAndADoubledIdSignNoOne: the
// table's keys are the only ones a token is checked against. While the issuer
// changes its key the table holds two and a token of either signs in; a key
// that left signs no one in; with no key, and with one key id given to two
// keys, no token signs anyone in.
func TestSession_IssuerKeys_EitherOfTwoSignsIn_NoneAndADoubledIdSignNoOne(t *testing.T) {
	e := newAuthEnv(t)
	second := newSigner()
	try := func(name string, s signer) *httptest.ResponseRecorder {
		t.Helper()
		at := e.login(t, dhostA, "")
		w := e.sessionPost(t, dhostA, idToken(t, s, idClaims(subOwnerA, at.nonce)), at.state, at.cookie)
		if w.Code == 200 && sessionSet(w) {
			e.signedIn(t, name, w, at, refA, subOwnerA)
		}
		return w
	}
	refused := func(name string, s signer) {
		t.Helper()
		w := try(name, s)
		if sessionSet(w) {
			t.Errorf("%s: a session was set", name)
		}
		refusal(t, name, w, 401, textFailed)
	}
	e.setTable(t, func(f *dashfile.File) { f.Issuer.Keys = append(f.Issuer.Keys, issuerKey(second)) })
	for name, s := range map[string]signer{"two keys, the first": issuerSigner, "two keys, the second": second} {
		if w := try(name, s); !sessionSet(w) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	e.setTable(t, func(f *dashfile.File) { f.Issuer.Keys = []dashfile.IssuerKey{issuerKey(second)} })
	if w := try("the new key alone", second); !sessionSet(w) {
		t.Errorf("the new key alone: %d %s", w.Code, w.Body)
	}
	refused("the key that left", issuerSigner)

	e.setTable(t, func(f *dashfile.File) { f.Issuer.Keys = nil })
	refused("no key, the old signer", issuerSigner)
	refused("no key, the new signer", second)

	// One key id for two keys: which of them a token means cannot be told.
	doubled := issuerKey(second)
	doubled.Kid = issuerSigner.kid
	f := dfile(1000)
	f.Issuer.Keys = append(f.Issuer.Keys, doubled)
	writeDashFile(t, e.path(), f)
	if err := e.d.table.Reload(); err != nil {
		return // a table that refuses such a file never serves it
	}
	refused("a doubled key id, the first key", issuerSigner)
	refused("a doubled key id, the second key", signer{second.priv, issuerSigner.kid})
}

// TestSession_TheNewAudienceForm: an audience written as an array of the one
// client id signs in without an authorised party; an array of two needs it,
// and it must be this client.
func TestSession_TheNewAudienceForm(t *testing.T) {
	e := newAuthEnv(t)
	for name, c := range map[string]struct {
		mod     func(map[string]any)
		signsIn bool
	}{
		"an array of the client alone": {func(c map[string]any) { c["aud"] = []string{clientID} }, true},
		"two, this client authorised":  {func(c map[string]any) { c["aud"] = []string{"other", clientID}; c["azp"] = clientID }, true},
		"two, no authorised party":     {func(c map[string]any) { c["aud"] = []string{clientID, "other"} }, false},
		"two, another authorised":      {func(c map[string]any) { c["aud"] = []string{clientID, "other"}; c["azp"] = "other" }, false},
		"one, another authorised":      {func(c map[string]any) { c["aud"] = []string{clientID}; c["azp"] = "other" }, false},
		"an array of another client":   {func(c map[string]any) { c["aud"] = []string{"other"} }, false},
		"an empty array":               {func(c map[string]any) { c["aud"] = []string{} }, false},
	} {
		at := e.login(t, dhostA, "")
		claims := idClaims(subOwnerA, at.nonce)
		c.mod(claims)
		w := e.sessionPost(t, dhostA, idToken(t, issuerSigner, claims), at.state, at.cookie)
		if c.signsIn {
			e.signedIn(t, name, w, at, refA, subOwnerA)
			continue
		}
		if sessionSet(w) {
			t.Errorf("%s: a session was set", name)
		}
		refusal(t, name, w, 401, textFailed)
	}
}

// TestAuthAnswers_HeadersHoldNothingARequestChose: whatever a request writes
// into a return path, a parameter, a field, a ticket or a cookie, no header
// of the answer holds a line end, every redirect goes to the issuer's
// configured address, to a host of the table or to the sign-in host, and
// the only cookies named are the session's and login cookies of the exact
// form.
func TestAuthAnswers_HeadersHoldNothingARequestChose(t *testing.T) {
	e := newAuthEnv(t)
	const inject = "%0d%0aSet-Cookie:%20evil=1%0d%0aLocation:%20https://evil.test/"
	at := e.login(t, dhostA, "")
	tok := goodToken(t, at)
	hostileState := withPath(at.state, "/x\r\nSet-Cookie: evil=1")
	reqs := map[string]*http.Request{
		"login, a return path with line ends":         get(dhostA, "/-/auth/login?return=/x"+inject),
		"login, a return path that is a line end":     get(dhostA, "/-/auth/login?return="+inject),
		"login, line ends encoded twice":              get(dhostA, "/-/auth/login?return=/x%250d%250aSet-Cookie:evil"),
		"login, retry with line ends":                 get(dhostA, "/-/auth/login?retry=1"+inject),
		"login, another address as the return path":   get(signInH, "/-/auth/login?return=https://evil.test/"),
		"login, a parameter named by line ends":       get(dhostA, "/-/auth/login?"+inject+"=1"),
		"login, cookies of other names":               get(dhostA, "/-/auth/login", "Cookie", "__Host-sp-login-evil=1; __Host-sp-login-AAAAAAAAAAAA=1; evil=1"),
		"callback, a state with line ends":            post(signInH, "/-/auth/callback", form(tok, at.state+"\r\nSet-Cookie: evil=1")),
		"callback, a token with line ends":            post(signInH, "/-/auth/callback", form(tok+"\r\nLocation: https://evil.test/", at.state)),
		"session, a state whose path has line ends":   post(dhostA, "/-/auth/session?at=1"+inject, form(tok, hostileState), "Cookie", at.cookie),
		"session, the retry of such a state":          post(dhostA, "/-/auth/session?at=1", form("x", hostileState)),
		"session, a cookie value with markup":         post(dhostA, "/-/auth/session", form(tok, at.state), "Cookie", at.name+"=<evil>"),
		"logout, a ticket with line ends":             get(dhostA, "/-/auth/logout?t="+inject),
		"logout, a parameter with line ends":          get(dhostA, "/-/auth/logout?x="+inject, "Cookie", "__Host-sp-login-AAAAAAAAAAA=1; evil=1"),
		"logout on the sign-in host, with line ends":  get(signInH, "/-/auth/logout?x="+inject),
		"signed-out, parameters with line ends":       get(signInH, "/-/auth/signed-out?more=1"+inject+"&ended=0"+inject),
		"the picker, a query with line ends":          get(signInH, "/?x="+inject, navTo("none")...),
		"a session not presented, such a query":       get(dhostA, "/project/x?y="+inject, append(navTo("same-origin"), "Referer", "https://"+dhostA+"/-/auth/session?at="+strconv.FormatInt(time.Now().Unix()-1, 10))...),
		"a path that is not one, on the sign-in host": get(signInH, "/x?"+inject),
	}
	hosts := map[string]bool{"issuer.test": true, signInH: true, dhostA: true, dhostB: true}
	for name, r := range reqs {
		w := e.do(r)
		for k, vs := range w.Header() {
			for _, v := range vs {
				if strings.ContainsAny(k+v, "\r\n\x00") {
					t.Errorf("%s: header %s holds a line end: %q", name, k, v)
				}
				if strings.Contains(strings.ToLower(v), "evil") && k != "Location" {
					t.Errorf("%s: header %s holds what the request chose: %q", name, k, v)
				}
			}
		}
		if loc := w.Header().Get("Location"); loc != "" && loc != "/-/auth/login" {
			u, err := url.Parse(loc)
			if err != nil || u.Scheme != "https" || !hosts[u.Host] || u.User != nil || u.Fragment != "" {
				t.Errorf("%s: redirect to %q", name, loc)
				continue
			}
			// Only the issuer's address carries anything of the request,
			// and only inside the state, as a return path that was kept.
			if u.Host != "issuer.test" && strings.Contains(strings.ToLower(loc), "evil") {
				t.Errorf("%s: redirect %q holds what the request chose", name, loc)
			}
			if st := u.Query().Get("state"); u.Host == "issuer.test" {
				if p := statePath(t, st); p != "/" {
					t.Errorf("%s: the state carries the return path %q", name, p)
				}
				if strings.Contains(strings.ToLower(strings.Replace(loc, url.QueryEscape(st), "", 1)), "evil") {
					t.Errorf("%s: redirect %q holds what the request chose", name, loc)
				}
			}
		}
		for _, c := range cookies(w) {
			n, _, _ := strings.Cut(c, "=")
			if n != sessionCookie && !loginNameRE.MatchString(n) {
				t.Errorf("%s: Set-Cookie names %q", name, n)
			}
		}
		if ct := w.Header().Get("Content-Type"); w.Body.Len() > 0 && ct != "text/html; charset=utf-8" && ct != "application/json" {
			t.Errorf("%s: Content-Type %q", name, ct)
		}
		if strings.Contains(w.Body.String(), "evil=1\r") || strings.Contains(w.Body.String(), "<evil>") {
			t.Errorf("%s: the body holds the request's bytes: %s", name, w.Body)
		}
	}
}

// TestLogout_OnlyANavigationOrThisOriginEndsASession: a request of another
// origin that is not a top-level navigation — an image, a fetch, a frame —
// reaches the log-out endpoints with the session a same-site origin's request
// carries and ends nothing: 403, no cookie cleared, no chain begun. Neither
// does another method. The origin's own navigation does.
func TestLogout_OnlyANavigationOrThisOriginEndsASession(t *testing.T) {
	e := newAuthEnv(t)
	onA := e.sessionOf(t, refA, subOwnerA) + "; " + shownLogin + "=x"
	onSignIn := e.sessionOf(t, "_", subOwnerA) + "; " + shownLogin + "=x"
	notNavigations := map[string][]string{
		"an image of a sibling origin": {"Sec-Fetch-Site", "same-site", "Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Dest", "image"},
		"a fetch of a sibling origin":  {"Sec-Fetch-Site", "same-site", "Sec-Fetch-Mode", "cors", "Sec-Fetch-Dest", "empty"},
		"a frame of a sibling origin":  {"Sec-Fetch-Site", "same-site", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "iframe"},
		"a script of another site":     {"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "no-cors", "Sec-Fetch-Dest", "script"},
		"a prefetch of another site":   {"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "empty"},
	}
	targets := []struct{ host, target, cookie string }{
		{dhostA, "/-/auth/logout", onA},
		{signInH, "/-/auth/logout", onSignIn},
		{signInH, "/-/auth/signed-out", onSignIn},
		{signInH, "/-/auth/signed-out?ended=0", onSignIn},
	}
	for name, pairs := range notNavigations {
		for _, c := range targets {
			w := e.ask(t, get(c.host, c.target, append([]string{"Cookie", c.cookie}, pairs...)...))
			if w.Code != 403 || code(w) != "cross_origin" || len(cookies(w)) != 0 || w.Header().Get("Location") != "" {
				t.Errorf("%s, %s%s: %d %s, Set-Cookie %q, Location %q", name, c.host, c.target, w.Code, w.Body, cookies(w), w.Header().Get("Location"))
			}
		}
	}
	for _, m := range []string{"POST", "HEAD", "PUT", "DELETE", "OPTIONS"} {
		for _, c := range targets {
			w := e.ask(t, hdr(rawReq(m, c.host, c.target), "Cookie", c.cookie, "Sec-Fetch-Site", "same-origin"))
			if w.Code != 404 || len(cookies(w)) != 0 || w.Header().Get("Location") != "" {
				t.Errorf("%s %s%s: %d, Set-Cookie %q, Location %q", m, c.host, c.target, w.Code, cookies(w), w.Header().Get("Location"))
			}
		}
	}
	// Control: the origin's own navigation ends the session it shows.
	w := e.ask(t, get(dhostA, "/-/auth/logout", append(navTo("same-origin"), "Cookie", onA)...))
	if sc := cookies(w); w.Code != 302 || len(sc) != 2 || sc[0] != clearSessionLine || sc[1] != clearLoginLine(shownLogin) {
		t.Errorf("control: %d, Set-Cookie %q", w.Code, sc)
	}
}

// TestSignIn_ATableChangedAfterTheLogin: an attempt is judged by the table
// as it is when each request arrives. An issuer whose client id or identifier
// changed after the login signs no one in with the token of the old one, and
// a project that left the table is no relay target.
func TestSignIn_ATableChangedAfterTheLogin(t *testing.T) {
	e := newAuthEnv(t)
	for name, mod := range map[string]func(*dashfile.File){
		"another client id":     func(f *dashfile.File) { f.Issuer.ClientID = "another" },
		"another issuer":        func(f *dashfile.File) { f.Issuer.Iss = issuer + "/v2" },
		"a shorter session":     nil, // control: a change that refuses nothing
		"the member left since": func(f *dashfile.File) { p := f.Projects[refA]; p.Members = nil; f.Projects[refA] = p },
	} {
		at := e.login(t, dhostA, "")
		tok := goodToken(t, at)
		e.setTable(t, mod)
		w := e.sessionPost(t, dhostA, tok, at.state, at.cookie)
		switch name {
		case "a shorter session", "the member left since": // a session says who, not what they may do
			e.signedIn(t, name, w, at, refA, subOwnerA)
		default:
			if sessionSet(w) {
				t.Errorf("%s: a session was set", name)
			}
			refusal(t, name, w, 401, textFailed)
		}
		e.setTable(t, nil)
	}
	// The project leaves between the login and the issuer's post.
	at := e.login(t, dhostB, "")
	tok := idToken(t, issuerSigner, idClaims(subOwnerB, at.nonce))
	e.setTable(t, func(f *dashfile.File) { delete(f.Projects, refB) })
	if link := refusal(t, "a target that left", e.ask(t, post(signInH, "/-/auth/callback", form(tok, at.state))), 400, textDidNotComplete); link != "" {
		t.Errorf("a target that left: link %q", link)
	}
	if w := e.do(post(dhostB, "/-/auth/session?at=1", form(tok, at.state), "Cookie", at.cookie)); w.Code != 404 || sessionSet(w) {
		t.Errorf("the session endpoint of a host that left: %d, Set-Cookie %q", w.Code, cookies(w))
	}
}

// TestSession_TheAddressIsNotRead: the session endpoint takes its two fields
// from the body. A query that does not parse refuses nothing, and a field
// written into the address neither counts nor doubles one of the body.
func TestSession_TheAddressIsNotRead(t *testing.T) {
	e := newAuthEnv(t)
	for name, query := range map[string]string{
		"a broken escape":             "?at=%zz",
		"semicolons":                  "?at=1;x=2",
		"no query":                    "",
		"the fields again":            "?id_token=x&state=y&at=1",
		"an error parameter":          "?error=access_denied",
		"at twice and not a number":   "?at=x&at=y",
		"a state of another host too": "?state=v1." + refB + ".AAAAAAAAAAA.0.Lw",
	} {
		at := e.login(t, dhostA, "")
		r := post(dhostA, "/-/auth/session"+query, form(goodToken(t, at), at.state), "Cookie", at.cookie, "Origin", "null")
		e.signedIn(t, name, e.ask(t, r), at, refA, subOwnerA)
	}
	at := e.login(t, dhostA, "")
	r := post(dhostA, "/-/auth/session?"+form(goodToken(t, at), at.state), "", "Cookie", at.cookie)
	w := e.ask(t, r)
	if link := refusal(t, "fields in the address alone", w, 400, textDidNotComplete); link != "" || len(cookies(w)) != 0 {
		t.Errorf("fields in the address alone: link %q, Set-Cookie %q", link, cookies(w))
	}
}

// TestAuthAnswers_NothingAWorkerOrAnotherOriginCouldUse: no answer of the
// sign-in handler is a script a browser would install as a worker, and none
// opens itself to another origin's reader — also when the request asks for
// either.
func TestAuthAnswers_NothingAWorkerOrAnotherOriginCouldUse(t *testing.T) {
	e := newAuthEnv(t)
	session := e.sessionOf(t, refA, subOwnerA)
	ask := []string{"Service-Worker", "script", "Origin", "https://evil.test", "Access-Control-Request-Method", "POST",
		"Access-Control-Request-Headers", "content-type", "Sec-Fetch-Site", "same-origin"}
	for _, c := range []struct{ method, host, target string }{
		{"GET", dhostA, "/-/auth/login"}, {"GET", dhostA, "/-/auth/logout"}, {"GET", dhostA, "/-/auth/session"},
		{"GET", dhostA, "/-/auth/sw.js"}, {"GET", dhostA, "/-/auth/"}, {"OPTIONS", dhostA, "/-/auth/session"},
		{"OPTIONS", signInH, "/-/auth/callback"}, {"OPTIONS", dhostA, "/-/auth/login"}, {"POST", dhostA, "/-/auth/session"},
		{"POST", signInH, "/-/auth/callback"}, {"GET", signInH, "/"}, {"GET", signInH, "/sw.js"}, {"GET", signInH, "/-/auth/signed-out"},
	} {
		r := hdr(rawReq(c.method, c.host, c.target), append(ask, "Cookie", session)...)
		w := e.do(r)
		h := w.Header()
		if ct := h.Get("Content-Type"); ct != "" && ct != "text/html; charset=utf-8" && ct != "application/json" || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s%s: Content-Type %q, X-Content-Type-Options %q", c.method, c.host, c.target, ct, h.Get("X-Content-Type-Options"))
		}
		for k := range h {
			if strings.HasPrefix(k, "Access-Control-") || k == "Service-Worker-Allowed" || k == "Allow" {
				t.Errorf("%s %s%s: header %s", c.method, c.host, c.target, k)
			}
		}
		if h.Get("Cross-Origin-Resource-Policy") != "same-origin" {
			t.Errorf("%s %s%s: Cross-Origin-Resource-Policy %q", c.method, c.host, c.target, h.Get("Cross-Origin-Resource-Policy"))
		}
	}
}

// TestSignIn_ServedWhileTheTableIsReplaced: sign-ins, the picker and log-outs
// answered while the table is replaced under them each see one table, and
// none fails for it. Run under the race detector.
func TestSignIn_ServedWhileTheTableIsReplaced(t *testing.T) {
	e := newAuthEnv(t)
	stop := make(chan struct{})
	var reloads sync.WaitGroup
	reloads.Add(1)
	go func() {
		defer reloads.Done()
		for gen := int64(100); ; gen++ {
			select {
			case <-stop:
				return
			default:
			}
			f := dfile(gen)
			if gen%2 == 0 {
				member(&f, subOwnerA, refC)
			}
			b, err := f.Marshal()
			if err != nil {
				t.Error(err)
				return
			}
			writeRaw(t, e.path(), b)
			if err := e.d.table.Reload(); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 40 {
				w := e.do(get(dhostA, "/-/auth/login"))
				sc := cookies(w)
				if w.Code != 302 || len(sc) != 1 {
					t.Errorf("login: %d %q", w.Code, sc)
					return
				}
				m := loginLineRE.FindStringSubmatch(sc[0])
				loc, err := url.Parse(w.Header().Get("Location"))
				if m == nil || err != nil {
					t.Errorf("login: %q %q", sc, w.Header().Get("Location"))
					return
				}
				tok, err := jwtx.Sign(issuerSigner.priv, issuerSigner.kid, idClaims(subOwnerA, loc.Query().Get("nonce")))
				if err != nil {
					t.Error(err)
					return
				}
				w = e.do(post(dhostA, "/-/auth/session?at=1", form(tok, loc.Query().Get("state")), "Cookie", m[1]+"="+m[3]))
				held := ""
				for _, c := range cookies(w) {
					if sm := sessionLineRE.FindStringSubmatch(c); sm != nil {
						held = sessionCookie + "=" + sm[1]
					}
				}
				if w.Code != 200 || held == "" {
					t.Errorf("session: %d %s", w.Code, w.Body)
					return
				}
				if w := e.do(get(dhostA, "/-/auth/logout", "Cookie", held)); w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "https://") {
					t.Errorf("logout: %d %q", w.Code, w.Header().Get("Location"))
					return
				}
				if w := e.do(get(signInH, "/", navTo("none")...)); w.Code != 302 {
					t.Errorf("picker: %d", w.Code)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	reloads.Wait()
}
