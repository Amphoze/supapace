package gateway

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/dashtok"
)

const (
	signedOutURL = signInO + "/-/auth/signed-out"
	shownLogin   = "__Host-sp-login-AAAAAAAAAAA"
	subMany      = "user-many" // a principal the tests give many projects
)

func hostOf(ref string) string { return ref + "." + studioDom }

// hop is one answer of a log-out chain.
type hop struct {
	host   string
	set    []string        // its Set-Cookie lines
	ticket *dashtok.Ticket // the ticket its redirect carries; nil without one
	loc    string
}

// chain starts a log-out at host with the cookie header given and follows
// its redirects as a browser does, across origins: the hops are sent no
// session cookie, only one login cookie. It returns every answer that
// redirected and the page the chain ended on.
func (e *authEnv) chain(t *testing.T, host, cookie string) (hops []hop, end *httptest.ResponseRecorder) {
	t.Helper()
	u := "https://" + host + "/-/auth/logout"
	pairs := append(navTo("same-origin"), "Cookie", cookie)
	if cookie == "" {
		pairs = navTo("same-origin")
	}
	for range 40 {
		pu, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		w := e.ask(t, get(pu.Host, pu.RequestURI(), pairs...))
		if w.Code != 302 {
			return hops, w
		}
		h := hop{host: pu.Host, set: cookies(w), loc: w.Header().Get("Location")}
		lu, err := url.Parse(h.loc)
		if err != nil || lu.Scheme != "https" {
			t.Fatalf("%s redirects to %q", u, h.loc)
		}
		if q := lu.Query(); lu.Path == "/-/auth/logout" {
			if len(q) != 1 || len(q["t"]) != 1 {
				t.Fatalf("%s redirects to %q", u, h.loc)
			}
			tk, err := dashtok.VerifyTicket(e.d.pub, q.Get("t"), time.Now())
			if err != nil {
				t.Fatalf("%s: the redirect's ticket does not verify: %v", u, err)
			}
			if lu.Host != hostOf(tk.Refs[0]) {
				t.Fatalf("%s redirects to %s with a ticket for %v", u, lu.Host, tk.Refs)
			}
			h.ticket = &tk
		}
		hops = append(hops, h)
		u = h.loc
		pairs = append(navTo("cross-site"), "Cookie", shownLogin+"=x")
	}
	t.Fatal("the log-out chain does not end")
	return nil, nil
}

func hosts(hops []hop) []string {
	out := make([]string, len(hops))
	for i, h := range hops {
		out[i] = h.host
	}
	return out
}

func (e *authEnv) sessionOf(t *testing.T, ref, sub string) string {
	t.Helper()
	return sessionCookie + "=" + e.session(t, ref, issuer, sub, time.Now().Unix()-10, 3600)
}

// signedOutPage checks the signed-out page and says which of its sentences
// it shows.
func signedOutPage(t *testing.T, name string, w *httptest.ResponseRecorder) (plain, ended, more bool) {
	t.Helper()
	body := w.Body.String()
	if w.Code != 200 || !isPage(w) || w.Header().Get("Location") != "" || strings.Contains(body, "<script") || strings.Contains(body, "http-equiv") {
		t.Fatalf("%s: not the signed-out page: %d %s", name, w.Code, body)
	}
	has := func(s string) bool { return strings.Contains(body, "<p>"+html.EscapeString(s)+"</p>") }
	return has(textSignedOut), has(textEnded), has(textMore)
}

// manyProjects gives subMany n projects of its own beside the fixture's.
func (e *authEnv) manyProjects(t *testing.T, n int) []string {
	t.Helper()
	refs := refsN(n)
	e.setTable(t, func(f *dashfile.File) { member(f, subMany, refs...) })
	return refs
}

func TestLogout_ChainFromAProjectOrigin(t *testing.T) {
	e := newAuthEnv(t)
	e.setTable(t, func(f *dashfile.File) {
		member(f, subOwnerA, refC, refB) // now a member of A, B and C
		member(f, subOwnerB, refD)       // another principal's project
	})
	for _, c := range []struct {
		start string
		want  []string // the hosts that redirect, in order
		refs  []string // the first ticket
	}{
		{refB, []string{hostOf(refB), dhostA, hostOf(refC)}, []string{refA, refC}},
		{refA, []string{dhostA, dhostB, hostOf(refC)}, []string{refB, refC}},
		{refC, []string{hostOf(refC), dhostA, dhostB}, []string{refA, refB}},
	} {
		hops, end := e.chain(t, hostOf(c.start), e.sessionOf(t, c.start, subOwnerA)+"; "+shownLogin+"=x")
		if !slices.Equal(hosts(hops), c.want) {
			t.Fatalf("from %s: hops %v, want %v", c.start, hosts(hops), c.want)
		}
		first := hops[0].ticket
		if first == nil || !slices.Equal(first.Refs, c.refs) || first.More || first.Iss != issuer || first.Sub != subOwnerA ||
			first.Exp-first.Iat != 60 || first.Iat > time.Now().Unix() || first.Iat < time.Now().Unix()-30 {
			t.Errorf("from %s: first ticket %+v", c.start, first)
		}
		for i, h := range hops {
			if !slices.Equal(h.set, []string{clearSessionLine, clearLoginLine(shownLogin)}) {
				t.Errorf("from %s: %s sets %q", c.start, h.host, h.set)
			}
			if last := i == len(hops)-1; last != (h.loc == signedOutURL) {
				t.Errorf("from %s: %s redirects to %q", c.start, h.host, h.loc)
			}
		}
		if plain, ended, more := signedOutPage(t, "from "+c.start, end); !plain || ended || more {
			t.Errorf("from %s: the page's sentences: %v %v %v", c.start, plain, ended, more)
		}
		if !slices.Equal(cookies(end), []string{clearSessionLine, clearLoginLine(shownLogin)}) {
			t.Errorf("from %s: the signed-out page sets %q", c.start, cookies(end))
		}
	}
	// A session of the host logs out whether or not its principal is still
	// a member there: the chain is the principal's other projects.
	hops, _ := e.chain(t, dhostB, e.sessionOf(t, refB, subROA))
	if !slices.Equal(hosts(hops), []string{dhostB, dhostA}) || !slices.Equal(hops[0].ticket.Refs, []string{refA}) {
		t.Errorf("a session of a principal who is no member of the host's project: %+v", hops)
	}
	// A principal of one project: no hop, straight to the page.
	hops, end := e.chain(t, dhostA, e.sessionOf(t, refA, subROA))
	if len(hops) != 1 || hops[0].ticket != nil || hops[0].loc != signedOutURL || !slices.Equal(hops[0].set, []string{clearSessionLine}) {
		t.Errorf("a principal of one project: %+v", hops)
	}
	if plain, ended, more := signedOutPage(t, "one project", end); !plain || ended || more {
		t.Errorf("one project: the page's sentences: %v %v %v", plain, ended, more)
	}
}

func TestLogout_ChainFromTheSignInHost(t *testing.T) {
	e := newAuthEnv(t)
	e.setTable(t, func(f *dashfile.File) { member(f, subOwnerA, refC, refB) })
	hops, end := e.chain(t, signInH, e.sessionOf(t, "_", subOwnerA)+"; "+shownLogin+"=x")
	if want := []string{signInH, dhostA, dhostB, hostOf(refC)}; !slices.Equal(hosts(hops), want) {
		t.Fatalf("hops %v, want %v", hosts(hops), want)
	}
	if first := hops[0].ticket; first == nil || !slices.Equal(first.Refs, []string{refA, refB, refC}) || first.More {
		t.Errorf("first ticket %+v", first)
	}
	for _, h := range hops {
		if !slices.Equal(h.set, []string{clearSessionLine, clearLoginLine(shownLogin)}) {
			t.Errorf("%s sets %q", h.host, h.set)
		}
	}
	if hops[3].loc != signedOutURL {
		t.Errorf("the last hop redirects to %q", hops[3].loc)
	}
	if plain, ended, more := signedOutPage(t, "picker", end); !plain || ended || more {
		t.Errorf("the page's sentences: %v %v %v", plain, ended, more)
	}
	// The sign-in host is never a hop: no ticket names it and none is taken there.
	for _, h := range hops {
		if h.ticket != nil && slices.Contains(h.ticket.Refs, "_") {
			t.Errorf("a ticket names the sign-in host: %+v", h.ticket)
		}
	}
	// A principal of no project: straight to the page.
	hops, _ = e.chain(t, signInH, e.sessionOf(t, "_", "nobody"))
	if len(hops) != 1 || hops[0].ticket != nil || hops[0].loc != signedOutURL || !slices.Equal(hops[0].set, []string{clearSessionLine}) {
		t.Errorf("a principal of no project: %+v", hops)
	}
}

// ticket signs a ticket with the gateway's key.
func (e *authEnv) ticket(t *testing.T, tk dashtok.Ticket) string {
	t.Helper()
	tok, err := dashtok.SignTicket(e.priv, tk)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestLogout_HopsNeedNoCookie(t *testing.T) {
	e := newAuthEnv(t)
	now := time.Now().Unix()
	tok := e.ticket(t, dashtok.Ticket{Iss: issuer, Sub: subOwnerA, Refs: []string{refA, refB}, Iat: now, Exp: now + 60})
	for name, pairs := range map[string][]string{
		"no cookie, from another site":  navTo("cross-site"),
		"no cookie, no fetch metadata":  nil,
		"another principal's session":   {"Cookie", e.sessionOf(t, refA, subDevA)},
		"a session that does not count": {"Cookie", sessionCookie + "=x"},
	} {
		w := e.ask(t, get(dhostA, "/-/auth/logout?t="+tok, pairs...))
		if w.Code != 302 || !slices.Equal(cookies(w), []string{clearSessionLine}) {
			t.Errorf("%s: %d, Set-Cookie %q", name, w.Code, cookies(w))
		}
		lu, _ := url.Parse(w.Header().Get("Location"))
		next, err := dashtok.VerifyTicket(e.d.pub, lu.Query().Get("t"), time.Now())
		if err != nil || lu.Host != dhostB || lu.Path != "/-/auth/logout" || !slices.Equal(next.Refs, []string{refB}) {
			t.Errorf("%s: redirects to %q (%v)", name, w.Header().Get("Location"), err)
		}
	}
	// The ticket is not single use: the same answer a second time.
	if w := e.ask(t, get(dhostA, "/-/auth/logout?t="+tok)); w.Code != 302 {
		t.Errorf("second use: %d", w.Code)
	}
}

func TestLogout_AtMostSixteenOrigins(t *testing.T) {
	e := newAuthEnv(t)
	refs := e.manyProjects(t, 17)
	// From a project origin with sixteen others: every one is visited.
	hops, end := e.chain(t, hostOf(refs[0]), e.sessionOf(t, refs[0], subMany))
	if len(hops) != 17 || !slices.Equal(hops[0].ticket.Refs, refs[1:]) || hops[0].ticket.More {
		t.Fatalf("seventeen projects: %d redirects, first ticket %+v", len(hops), hops[0].ticket)
	}
	for i, h := range hops[1:] {
		if h.host != hostOf(refs[i+1]) || !slices.Equal(h.set, []string{clearSessionLine, clearLoginLine(shownLogin)}) {
			t.Errorf("hop %d: %s sets %q", i+1, h.host, h.set)
		}
	}
	if hops[16].loc != signedOutURL {
		t.Errorf("the last hop redirects to %q", hops[16].loc)
	}
	if plain, ended, more := signedOutPage(t, "seventeen", end); !plain || ended || more {
		t.Errorf("the page's sentences: %v %v %v", plain, ended, more)
	}
	// From the picker with sixteen: the same, one redirect of its own first.
	refs = e.manyProjects(t, 16)
	hops, _ = e.chain(t, signInH, e.sessionOf(t, "_", subMany))
	if len(hops) != 17 || !slices.Equal(hops[0].ticket.Refs, refs) || hops[0].ticket.More || hops[16].loc != signedOutURL {
		t.Fatalf("sixteen projects from the picker: %d redirects, first ticket %+v", len(hops), hops[0].ticket)
	}
	// No ticket ever lists more than sixteen.
	e.manyProjects(t, 40)
	hops, _ = e.chain(t, signInH, e.sessionOf(t, "_", subMany))
	for _, h := range hops {
		if h.ticket != nil && len(h.ticket.Refs) > 16 {
			t.Errorf("a ticket of %d refs", len(h.ticket.Refs))
		}
	}
	if len(hops) != 17 {
		t.Errorf("forty projects: %d redirects", len(hops))
	}
}

func TestLogout_TicketsKeepTheFirstTimes(t *testing.T) {
	e := newAuthEnv(t)
	refs := e.manyProjects(t, 5)
	now := time.Now().Unix()
	for _, more := range []bool{false, true} {
		first := dashtok.Ticket{Iss: issuer, Sub: subMany, Refs: refs, More: more, Iat: now - 30, Exp: now + 30}
		u := "/-/auth/logout?t=" + e.ticket(t, first)
		for i, ref := range refs {
			w := e.ask(t, get(hostOf(ref), u, navTo("cross-site")...))
			if w.Code != 302 {
				t.Fatalf("more %v, hop %d: %d %s", more, i, w.Code, w.Body)
			}
			lu, _ := url.Parse(w.Header().Get("Location"))
			if i == len(refs)-1 {
				want := signedOutURL
				if more {
					want += "?more=1"
				}
				if lu.String() != want {
					t.Errorf("more %v: the last hop redirects to %q, want %q", more, lu, want)
				}
				break
			}
			tk, err := dashtok.VerifyTicket(e.d.pub, lu.Query().Get("t"), time.Now())
			if err != nil {
				t.Fatalf("more %v, hop %d: %v", more, i, err)
			}
			if tk.Iat != first.Iat || tk.Exp != first.Exp || tk.More != more || tk.Iss != first.Iss || tk.Sub != first.Sub || !slices.Equal(tk.Refs, refs[i+1:]) {
				t.Errorf("more %v, hop %d: ticket %+v, want the first one's times and more with refs %v", more, i, tk, refs[i+1:])
			}
			u = lu.RequestURI()
		}
	}
	// A chain does not outlive its first ticket's minute: one issued 59 s
	// ago still redirects, with a ticket that ends in a second.
	old := dashtok.Ticket{Iss: issuer, Sub: subMany, Refs: refs[:2], Iat: now - 58, Exp: now + 2}
	w := e.ask(t, get(hostOf(refs[0]), "/-/auth/logout?t="+e.ticket(t, old)))
	lu, _ := url.Parse(w.Header().Get("Location"))
	if tk, err := dashtok.VerifyTicket(e.d.pub, lu.Query().Get("t"), time.Unix(now, 0)); err != nil || tk.Exp != old.Exp {
		t.Errorf("a ticket near its end: %d, next %+v, %v", w.Code, tk, err)
	}
}

func TestLogout_MoreThanSixteen(t *testing.T) {
	e := newAuthEnv(t)
	refs := e.manyProjects(t, 18)
	// From a project origin: seventeen others, the first sixteen visited.
	hops, end := e.chain(t, hostOf(refs[0]), e.sessionOf(t, refs[0], subMany))
	if len(hops) != 17 || !slices.Equal(hops[0].ticket.Refs, refs[1:17]) || !hops[0].ticket.More {
		t.Fatalf("from a project origin: %d redirects, first ticket %+v", len(hops), hops[0].ticket)
	}
	for i, h := range hops[:16] {
		if !h.ticket.More {
			t.Errorf("hop %d: the ticket lost its more", i)
		}
	}
	if hops[16].loc != signedOutURL+"?more=1" {
		t.Errorf("the last hop redirects to %q", hops[16].loc)
	}
	if plain, ended, more := signedOutPage(t, "eighteen", end); !plain || ended || !more {
		t.Errorf("the page's sentences: %v %v %v", plain, ended, more)
	}
	// The seventeenth origin was never visited: its session still verifies.
	if slices.Contains(hosts(hops), hostOf(refs[17])) {
		t.Error("the seventeenth origin was visited")
	}
	e.passes(t, "the seventeenth origin's session", get(hostOf(refs[17]), "/p", "Cookie", e.sessionOf(t, refs[17], subMany)))

	// From the picker: eighteen, the first sixteen.
	hops, end = e.chain(t, signInH, e.sessionOf(t, "_", subMany))
	if len(hops) != 17 || !slices.Equal(hops[0].ticket.Refs, refs[:16]) || !hops[0].ticket.More || hops[16].loc != signedOutURL+"?more=1" {
		t.Fatalf("from the picker: %d redirects, first ticket %+v, last %q", len(hops), hops[0].ticket, hops[len(hops)-1].loc)
	}
	if _, _, more := signedOutPage(t, "eighteen, picker", end); !more {
		t.Error("from the picker: the page does not say that more remain")
	}

	// With sixteen or fewer besides the start, more is false on every hop
	// and the last redirect has no parameter.
	for _, n := range []int{17, 2} {
		refs := e.manyProjects(t, n)
		hops, end := e.chain(t, hostOf(refs[0]), e.sessionOf(t, refs[0], subMany))
		for i, h := range hops[:len(hops)-1] {
			if h.ticket.More {
				t.Errorf("%d projects, hop %d: more", n, i)
			}
		}
		if len(hops) != n || hops[n-1].loc != signedOutURL {
			t.Errorf("%d projects: %d redirects, the last to %q", n, len(hops), hops[len(hops)-1].loc)
		}
		if _, _, more := signedOutPage(t, "no more", end); more {
			t.Errorf("%d projects: the page says that more remain", n)
		}
	}
}

func TestLogout_WithoutASession_NeverAnError(t *testing.T) {
	e := newAuthEnv(t)
	now := time.Now().Unix()
	e.setTable(t, func(f *dashfile.File) {
		f.Revoked = []dashfile.Revocation{{Iss: issuer, Sub: subDevA, NotBefore: now - 100}}
	})
	other, _ := dashtok.SignSession(otherKey(t), dashtok.Session{Iss: issuer, Sub: subOwnerA, Ref: refA, Iat: now - 10, Exp: now + 100})
	good := e.session(t, refA, issuer, subOwnerA, now-10, 3600)
	for name, session := range map[string]string{
		"no cookie":          "",
		"expired":            e.session(t, refA, issuer, subOwnerA, now-7200, 3600),
		"revoked":            e.session(t, refA, issuer, subDevA, now-101, 3600),
		"another project's":  e.session(t, refB, issuer, subOwnerA, now-10, 3600),
		"the sign-in host's": e.session(t, "_", issuer, subOwnerA, now-10, 3600),
		"another issuer's":   e.session(t, refA, "https://other.test", subOwnerA, now-10, 3600),
		"another key's":      other,
		"garbage":            "x",
		"twice":              good + "; " + sessionCookie + "=" + good,
	} {
		for _, logins := range [][]string{nil, {shownLogin, "__Host-sp-login-BBBBBBBBBBB"}} {
			var pairs, want []string
			if session != "" {
				pairs = append(pairs, sessionCookie+"="+session)
				want = append(want, clearSessionLine)
			}
			for _, l := range logins {
				pairs = append(pairs, l+"=x")
				want = append(want, clearLoginLine(l))
			}
			pairs = append(pairs, "other=1", "__Host-sp-login-AAAAAAAAAAAA=x", "__Host-sp-sessions=x")
			for _, site := range []string{"none", "cross-site", "same-origin"} {
				w := e.ask(t, get(dhostA, "/-/auth/logout", append(navTo(site), "Cookie", strings.Join(pairs, "; "))...))
				if w.Code != 302 || w.Header().Get("Location") != signedOutURL+"?ended=0" || w.Body.Len() != 0 {
					t.Errorf("%s (%s): %d %q %s", name, site, w.Code, w.Header().Get("Location"), w.Body)
				}
				// The cookies it was shown are cleared, none other.
				if !slices.Equal(cookies(w), want) {
					t.Errorf("%s (%s): Set-Cookie %q, want %q", name, site, cookies(w), want)
				}
			}
		}
	}
	// With no cookie at all nothing is set.
	if w := e.ask(t, get(dhostA, "/-/auth/logout")); w.Code != 302 || len(cookies(w)) != 0 || w.Header().Get("Location") != signedOutURL+"?ended=0" {
		t.Errorf("no cookie header: %d %q %q", w.Code, w.Header().Get("Location"), cookies(w))
	}
	// On the sign-in host the same.
	for name, cookie := range map[string]string{"no cookie": "", "a project's session": sessionCookie + "=" + good,
		"expired": sessionCookie + "=" + e.session(t, "_", issuer, subOwnerA, now-7200, 3600)} {
		r := get(signInH, "/-/auth/logout", navTo("none")...)
		var want []string
		if cookie != "" {
			r.Header.Set("Cookie", cookie)
			want = []string{clearSessionLine}
		}
		if w := e.ask(t, r); w.Code != 302 || w.Header().Get("Location") != signedOutURL+"?ended=0" || !slices.Equal(cookies(w), want) {
			t.Errorf("sign-in host, %s: %d %q %q", name, w.Code, w.Header().Get("Location"), cookies(w))
		}
	}
	// Control: the session builds the chain.
	if w := e.ask(t, get(dhostA, "/-/auth/logout", "Cookie", sessionCookie+"="+good)); w.Header().Get("Location") != signedOutURL {
		t.Errorf("control: %q", w.Header().Get("Location"))
	}
	// Only GET.
	for _, m := range []string{"POST", "HEAD", "DELETE"} {
		w := e.ask(t, hdr(rawReq(m, dhostA, "/-/auth/logout"), "Cookie", sessionCookie+"="+good))
		if w.Code != 404 || len(cookies(w)) != 0 {
			t.Errorf("%s logout: %d %q", m, w.Code, cookies(w))
		}
	}
}

func TestLogout_EveryHopClearsTheLoginCookiesItIsShown(t *testing.T) {
	e := newAuthEnv(t)
	tb := loadSignIn(t)
	var pairs, want []string
	for _, c := range tb.CookieNames {
		pairs = append(pairs, c.Name+"=v")
		if c.Login {
			want = append(want, clearLoginLine(c.Name))
		}
	}
	pairs = append(pairs, pairs[0]) // a name sent twice is cleared once
	if len(want) < 2 || len(want) == len(tb.CookieNames) {
		t.Fatalf("the table's cookie names: %d of %d are login cookies", len(want), len(tb.CookieNames))
	}
	shown := strings.Join(pairs, "; ")
	now := time.Now().Unix()
	tok := e.ticket(t, dashtok.Ticket{Iss: issuer, Sub: subOwnerA, Refs: []string{refA, refB}, Iat: now, Exp: now + 60})
	last := e.ticket(t, dashtok.Ticket{Iss: issuer, Sub: subOwnerA, Refs: []string{refA}, Iat: now, Exp: now + 60})
	for name, c := range map[string]struct {
		r       *http.Request
		session bool // the answer clears the session cookie too
	}{
		"the start":                  {get(dhostA, "/-/auth/logout", "Cookie", e.sessionOf(t, refA, subOwnerA)+"; "+shown), true},
		"the start, sign-in host":    {get(signInH, "/-/auth/logout", "Cookie", e.sessionOf(t, "_", subOwnerA)+"; "+shown), true},
		"a hop":                      {get(dhostA, "/-/auth/logout?t="+tok, "Cookie", shown), true},
		"the last hop":               {get(dhostA, "/-/auth/logout?t="+last, "Cookie", shown), true},
		"without a session":          {get(dhostA, "/-/auth/logout", "Cookie", shown), false},
		"without one, sign-in host":  {get(signInH, "/-/auth/logout", "Cookie", shown), false},
		"the signed-out page":        {get(signInH, "/-/auth/signed-out", "Cookie", shown), true},
		"the signed-out page, more ": {get(signInH, "/-/auth/signed-out?more=1&ended=0", "Cookie", shown), true},
	} {
		w := e.ask(t, c.r)
		exp := want
		if c.session {
			exp = append([]string{clearSessionLine}, want...)
		}
		if w.Code != 302 && w.Code != 200 || !slices.Equal(cookies(w), exp) {
			t.Errorf("%s: %d, Set-Cookie %q, want %q", name, w.Code, cookies(w), exp)
		}
	}
}

func TestLogout_TicketRefusals(t *testing.T) {
	e := newAuthEnv(t)
	now := time.Now().Unix()
	base := dashtok.Ticket{Iss: issuer, Sub: subOwnerA, Refs: []string{refA, refB}, Iat: now, Exp: now + 60}
	with := func(mod func(*dashtok.Ticket)) string {
		tk := base
		mod(&tk)
		return e.ticket(t, tk)
	}
	good := e.ticket(t, base)
	foreign, _ := dashtok.SignTicket(otherKey(t), base)
	assertion, _ := dashtok.SignAssertion(e.priv, dashtok.Assertion{Node: "local", Iss: issuer, Sub: subOwnerA, Ref: refA, Role: "owner", Iat: now, Exp: now + 30})
	payload := strings.Split(good, ".")[1]
	altered := "v1." + payload[:10] + flipSig("." + payload[10:11])[1:] + payload[11:] + "." + strings.Split(good, ".")[2]
	session := e.sessionOf(t, refA, subOwnerA)
	cases := map[string]string{
		"expired":                       "t=" + with(func(tk *dashtok.Ticket) { tk.Iat, tk.Exp = now-60, now }),
		"long expired":                  "t=" + with(func(tk *dashtok.Ticket) { tk.Iat, tk.Exp = now-3600, now-3540 }),
		"a lifetime of 61 s":            "t=" + with(func(tk *dashtok.Ticket) { tk.Exp = now + 61 }),
		"issued in the future":          "t=" + with(func(tk *dashtok.Ticket) { tk.Iat, tk.Exp = now+60, now+120 }),
		"an altered signature":          "t=" + flipSig(good),
		"an altered payload":            "t=" + altered,
		"another key":                   "t=" + foreign,
		"a later ref outside the table": "t=" + with(func(tk *dashtok.Ticket) { tk.Refs = []string{refA, refD} }),
		"not the next ref":              "t=" + with(func(tk *dashtok.Ticket) { tk.Refs = []string{refB, refA} }),
		"another host's alone":          "t=" + with(func(tk *dashtok.Ticket) { tk.Refs = []string{refB} }),

		"a session token":                "t=" + e.session(t, refA, issuer, subOwnerA, now-10, 60),
		"an assertion":                   "t=" + assertion,
		"twice":                          "t=" + good + "&t=" + good,
		"twice, the first empty":         "t=&t=" + good,
		"empty":                          "t=",
		"no value":                       "t",
		"garbage":                        "t=x",
		"a padded ticket":                "t=" + good + "%3D",
		"beside a query that is not one": "t=" + good + "&x=%zz",
		"a query that is not one":        "x=%zz",
		"semicolons":                     "t=" + good + ";x=1",
	}
	for name, q := range cases {
		// With the session too: a ticket that is refused ends nothing.
		for _, cookie := range []string{"", session + "; " + shownLogin + "=x"} {
			r := get(dhostA, "/-/auth/logout?"+q, navTo("cross-site")...)
			if cookie != "" {
				r.Header.Set("Cookie", cookie)
			}
			w := e.ask(t, r)
			if link := refusal(t, name, w, 400, textBadTicket); link != "" || len(cookies(w)) != 0 {
				t.Errorf("%s: link %q, Set-Cookie %q", name, link, cookies(w))
			}
		}
	}
	// A ticket on the sign-in host, which is never a hop — whatever it lists.
	for name, tok := range map[string]string{"a good ticket": good, "garbage": "x"} {
		w := e.ask(t, get(signInH, "/-/auth/logout?t="+tok, "Cookie", e.sessionOf(t, "_", subOwnerA)))
		if link := refusal(t, "sign-in host, "+name, w, 400, textBadTicket); link != "" || len(cookies(w)) != 0 {
			t.Errorf("sign-in host, %s: link %q, Set-Cookie %q", name, link, cookies(w))
		}
	}
	// A ref that left the table since the chain began ends it here.
	e.setTable(t, func(f *dashfile.File) { delete(f.Projects, refB) })
	if w := e.ask(t, get(dhostA, "/-/auth/logout?t="+good)); w.Code != 400 {
		t.Errorf("a ref that left the table: %d", w.Code)
	}
	e.setTable(t, nil)
	// Controls: the ticket itself, one second before its end, and with a
	// further parameter.
	for name, q := range map[string]string{"control": "t=" + good, "a further parameter": "x=1&t=" + good,
		"59 s old": "t=" + with(func(tk *dashtok.Ticket) { tk.Iat, tk.Exp = now-55, now+5 })} {
		if w := e.ask(t, get(dhostA, "/-/auth/logout?"+q, navTo("cross-site")...)); w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "https://"+dhostB+"/-/auth/logout?t=") {
			t.Errorf("%s: %d %q", name, w.Code, w.Header().Get("Location"))
		}
	}
}

func TestSignedOut_OnlyOnTheSignInHost_ClearsItsCookie(t *testing.T) {
	e := newAuthEnv(t)
	good := e.sessionOf(t, "_", subOwnerA)
	// Whoever asks, with or without the cookie: it is cleared.
	for name, pairs := range map[string][]string{
		"with the session":       append(navTo("none"), "Cookie", good),
		"no cookie, cross-site":  navTo("cross-site"),
		"no fetch metadata":      nil,
		"a session not its own ": {"Cookie", e.sessionOf(t, refA, subOwnerA)},
	} {
		w := e.ask(t, get(signInH, "/-/auth/signed-out", pairs...))
		if plain, ended, more := signedOutPage(t, name, w); !plain || ended || more {
			t.Errorf("%s: the page's sentences: %v %v %v", name, plain, ended, more)
		}
		if !slices.Equal(cookies(w), []string{clearSessionLine}) {
			t.Errorf("%s: Set-Cookie %q", name, cookies(w))
		}
		if link := linkOf(t, w); link != "" {
			t.Errorf("%s: link %q without an end-session address", name, link)
		}
	}
	// On a dashboard host there is no such page, and nothing is cleared.
	for _, target := range []string{"/-/auth/signed-out", "/-/auth/signed-out?ended=0"} {
		w := e.ask(t, get(dhostA, target, "Cookie", e.sessionOf(t, refA, subOwnerA)+"; "+shownLogin+"=x"))
		if w.Code != 404 || code(w) != "not_found" || len(cookies(w)) != 0 {
			t.Errorf("%s on a dashboard host: %d %s %q", target, w.Code, w.Body, cookies(w))
		}
	}
	// Only GET.
	for _, m := range []string{"POST", "HEAD", "DELETE"} {
		if w := e.ask(t, hdr(rawReq(m, signInH, "/-/auth/signed-out"), "Cookie", good)); w.Code != 404 || len(cookies(w)) != 0 {
			t.Errorf("%s signed-out: %d %q", m, w.Code, cookies(w))
		}
	}
	// The issuer's end-session address is linked when one is set, as an
	// HTTPS address; anything else is not rendered.
	const end = "https://issuer.test/logout?client=1&x=<y>"
	e.setTable(t, func(f *dashfile.File) { f.Issuer.EndSessionURL = end })
	w := e.ask(t, get(signInH, "/-/auth/signed-out?ended=0&more=1"))
	if u, err := url.Parse(linkOf(t, w)); err != nil || u.Host != "issuer.test" || u.Path != "/logout" || u.Query().Get("x") != "<y>" {
		t.Errorf("end-session link %q", linkOf(t, w))
	}
	for _, bad := range []string{"http://issuer.test/logout", "javascript:alert(1)", "//issuer.test/logout", "/logout", "data:text/html,x"} {
		e.setTable(t, func(f *dashfile.File) { f.Issuer.EndSessionURL = bad })
		w := e.ask(t, get(signInH, "/-/auth/signed-out"))
		if link := linkOf(t, w); link != "" || strings.Contains(w.Body.String(), "alert") {
			t.Errorf("end_session_url %q is rendered: %q", bad, link)
		}
	}
}

func TestSignedOut_WordingFollowsTheChain(t *testing.T) {
	e := newAuthEnv(t)
	refs := e.manyProjects(t, 18)

	// After a log-out that visited every origin: the plain page.
	_, end := e.chain(t, dhostA, e.sessionOf(t, refA, subOwnerA))
	plainBody := end.Body.String()
	if plain, ended, more := signedOutPage(t, "every origin", end); !plain || ended || more {
		t.Errorf("every origin: %v %v %v", plain, ended, more)
	}
	// After /-/auth/logout without a session: the sentence of ended=0, and
	// not the claim that a dashboard's session ended.
	hops, end := e.chain(t, dhostA, "")
	if plain, ended, more := signedOutPage(t, "no session", end); plain || !ended || more || len(hops) != 1 {
		t.Errorf("no session: %v %v %v after %d redirects", plain, ended, more, len(hops))
	}
	// After a chain whose ticket had more: the sentence of more=1.
	_, end = e.chain(t, hostOf(refs[0]), e.sessionOf(t, refs[0], subMany))
	if plain, ended, more := signedOutPage(t, "more", end); !plain || ended || !more {
		t.Errorf("more: %v %v %v", plain, ended, more)
	}

	// The plain page says what Log out from a dashboard ends. It never says
	// that this browser holds no session, which it cannot know.
	low := strings.ToLower(plainBody)
	if !strings.Contains(low, "log out") || !strings.Contains(low, "dashboard") {
		t.Errorf("the plain page does not say what Log out ends: %s", plainBody)
	}
	for _, claim := range []string{"no session", "not signed in", "you are signed out", "you have been signed out", "all sessions", "every session"} {
		if strings.Contains(low, claim) {
			t.Errorf("the plain page claims %q: %s", claim, plainBody)
		}
	}
	// The three sentences are three.
	if textSignedOut == textEnded || textSignedOut == textMore || textEnded == textMore || textSignedOut == "" || textEnded == "" || textMore == "" {
		t.Error("the page's three sentences are not three")
	}
	if !strings.Contains(textEnded, "not ended") && !strings.Contains(textEnded, "none was ended") {
		t.Errorf("the sentence of ended=0 does not say that none was ended: %q", textEnded)
	}
	if !strings.Contains(textMore, "expire") || !strings.Contains(textMore, "revoked") {
		t.Errorf("the sentence of more=1: %q", textMore)
	}
}

func TestSignedOut_ParametersOnlyWords(t *testing.T) {
	e := newAuthEnv(t)
	shown := e.sessionOf(t, "_", subOwnerA) + "; " + shownLogin + "=x"
	page := func(query string) *httptest.ResponseRecorder {
		target := "/-/auth/signed-out"
		if query != "" {
			target += "?" + query
		}
		return e.ask(t, get(signInH, target, append(navTo("cross-site"), "Cookie", shown)...))
	}
	type words struct{ plain, ended, more bool }
	fixed := map[words]string{}
	for q, want := range map[string]words{"": {true, false, false}, "ended=0": {false, true, false},
		"more=1": {true, false, true}, "more=1&ended=0": {false, true, true}} {
		w := page(q)
		p, en, m := signedOutPage(t, q, w)
		if got := (words{p, en, m}); got != want {
			t.Fatalf("?%s: sentences %+v, want %+v", q, got, want)
		}
		fixed[want] = w.Body.String()
	}
	for q, want := range map[string]words{
		"ended=1":                 {true, false, false},
		"more=0":                  {true, false, false},
		"more=true":               {true, false, false},
		"more=1&more=1":           {true, false, false},
		"more=1&more=0":           {true, false, false},
		"more=0&more=1":           {true, false, false},
		"ended=0&ended=0":         {true, false, false},
		"ended=%3Cscript%3E":      {true, false, false},
		"ended=<script>alert(1)":  {true, false, false},
		"x=1":                     {true, false, false},
		"evil=<b>x</b>&y=//z":     {true, false, false},
		"MORE=1":                  {true, false, false},
		"more=1;ended=0":          {true, false, false},
		"more%3D1":                {true, false, false},
		"mor%65=1":                {true, false, false},
		"more=%31":                {true, false, false},
		"more=1%20":               {true, false, false},
		"more=01":                 {true, false, false},
		"more":                    {true, false, false},
		"more=":                   {true, false, false},
		"ended":                   {true, false, false},
		"&":                       {true, false, false},
		"ended=0&more=1":          {false, true, true},
		"more=1&ended=0&x=1":      {false, true, true},
		"x=1&more=1":              {true, false, true},
		"&more=1&":                {true, false, true},
		"ended=0&x=<script>":      {false, true, false},
		"ended=0&more=2":          {false, true, false},
		"ended=0&more=1&more=1":   {false, true, false},
		"more=1&ended=1":          {true, false, true},
		"more=1&ended=0&ended=00": {true, false, true},
	} {
		w := page(q)
		// The body is one of the fixed pages, so no byte of the request is in it.
		if w.Body.String() != fixed[want] {
			t.Errorf("?%s: the body is not the fixed page of %+v: %s", q, want, w.Body)
		}
		// What the page clears does not depend on the query.
		if !slices.Equal(cookies(w), []string{clearSessionLine, clearLoginLine(shownLogin)}) {
			t.Errorf("?%s: Set-Cookie %q", q, cookies(w))
		}
	}
	if len(fixed) != 4 || fixed[words{true, false, false}] == fixed[words{true, false, true}] {
		t.Fatal("the four fixed pages are not four")
	}
}
