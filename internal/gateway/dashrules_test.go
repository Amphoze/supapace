package gateway

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/dashtok"
)

var allMethods = []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}

func TestDashPath_RuleZero(t *testing.T) {
	e := newDashEnv(t, active(), true)
	for _, raw := range []string{
		"", "a/b", "*", "/a//b", "//", "/a/", "/a/./b", "/a/../b", "/.", "/..", "/a/%2e%2e/b", "/a/.%2E/b", "/a/%2E/b",
		`/a\b`, "/a%5cb", "/a%5Cb", "/a\x01b", "/a%01b", "/a%1Fb", "/a\x7fb", "/a%7fb", "/a%zz", "/a%", "/a%4", "/a%2fb", "/a%2Fb",
		"/a\xe2\x84\xaab", "/api-%E2%84%AAeys", "/a/%C0%AE/b", "/a/%80",
		// a fragment: a URL parser drops it and all after it
		"/x#y", "/a/b#", "/api/mcp#x", "/api/ai#/x", "/api/platform/pg-meta/" + refB + "#y", "/x#/../api/mcp", "/#",
		// ... and in the query: a URL parser ends the query there too
		"/x?a#b", "/x?reveal=true#", "/x?#",
	} {
		e.dexpect(t, "dashboard "+raw, e.as(t, rawReq("GET", dhostA, raw), refA, subOwnerA), 400, "bad_request")
		e.dexpect(t, "sign-in host "+raw, rawReq("GET", signInH, raw), 400, "bad_request")
		// Rule 0 does not judge the studio domain: anything but "/" is 404.
		e.dexpect(t, "studio domain "+raw, rawReq("GET", studioDom, raw), 404, "not_found")
	}
	for _, raw := range []string{"/", "/a/b", "/a/b?q=%E2%84%AA", "/a?q=\xe2\x84\xaa", "/a%20b", "/a~b", "/a%25b", "/x%23y", "/x?a=%23"} {
		e.passes(t, "dashboard "+raw, e.as(t, rawReq("GET", dhostA, raw), refA, subOwnerA))
		e.resetSeams()
		if w := e.do(rawReq("GET", signInH, raw)); w.Code != 200 {
			t.Errorf("sign-in host %q: %d", raw, w.Code)
		}
	}
	dr := e.passes(t, "segments", e.as(t, rawReq("GET", dhostA, "/Project/%61b%20C?x=1"), refA, subOwnerA))
	if !slices.Equal(dr.Path, []string{"Project", "ab C"}) || !slices.Equal(dr.Lower, []string{"project", "ab c"}) || dr.Ref != refA {
		t.Errorf("Path %q Lower %q Ref %q", dr.Path, dr.Lower, dr.Ref)
	}
	dr = e.passes(t, "root", e.as(t, rawReq("GET", dhostA, "/"), refA, subOwnerA))
	if len(dr.Path) != 0 || len(dr.Lower) != 0 {
		t.Errorf("root: Path %q Lower %q", dr.Path, dr.Lower)
	}
	e.resetSeams()
	e.do(rawReq("GET", signInH, "/x"))
	if len(e.auth) != 1 || e.auth[0].Ref != "_" {
		t.Fatalf("sign-in host: %d requests at the seam", len(e.auth))
	}
}

func TestDashRefRule_BothReadings(t *testing.T) {
	e := newDashEnv(t, active(), true)
	owner := func(target string) *http.Request { return e.as(t, rawReq("GET", dhostA, target), refA, subOwnerA) }
	enc := "%62" + refB[1:]
	for _, p := range []string{
		"/x/" + refB, "/x/" + enc, "/x/" + strings.ToUpper(refB), "/x/%42" + strings.ToUpper(refB[1:]),
		"/project/" + refB + "/editor", "/_next/static/" + refB + "/x.js", "/" + refB,
	} {
		e.dexpect(t, p, owner(p), 404, "not_found")
	}
	for _, p := range []string{"/x/../api/" + refB, "/x/%2e%2e/api/" + refB + "/q", "/x/..%2f" + refB} {
		e.dexpect(t, p, owner(p), 400, "bad_request")
	}
	// A doubly encoded ref is decoded once, as the server's router does.
	dr := e.passes(t, "double encoding", owner("/x/%25"+enc[1:]))
	if dr.Path[1] != "%"+enc[1:] {
		t.Errorf("decoded twice: %q", dr.Path)
	}
	e.passes(t, "own ref", owner("/project/"+refA+"/editor"))
	e.passes(t, "own ref, capitals", owner("/project/"+strings.ToUpper(refA)))
	e.passes(t, "not ref-shaped", owner("/x/"+refB+"0"))
}

func TestDashOptIn_Refused(t *testing.T) {
	e := newDashEnv(t, active(), true)
	for _, m := range allMethods {
		r := func(target string) *http.Request { return e.as(t, rawReq(m, dhostA, target), refA, subOwnerA) }
		for _, p := range []string{"/api/ai/chat", "/api/ai/x/y", "/api/mcp", "/api/mcp/x", "/api/%61i/chat", "/api/%6dcp",
			"/API/AI/chat", "/Api/Mcp", "/api/AI/sql", "/api/ai", "/api/AI", "/API/MCP"} {
			e.dexpect(t, m+" "+p, r(p), 404, "not_found")
		}
		for _, p := range []string{"/api/v1/%2e%2e/ai/chat", "/x/../api/ai/chat", "/api/mcp/", "/api/ai/"} {
			e.dexpect(t, m+" "+p, r(p), 400, "bad_request")
		}
		e.passes(t, m+" /api/mcpx", r("/api/mcpx"))
		e.passes(t, m+" /api/aix/y", r("/api/aix/y"))
	}
}

func TestDashServiceWorker_Refused(t *testing.T) {
	e := newDashEnv(t, active(), true)
	for _, v := range []string{"script", "Script", " script"} {
		r := e.as(t, rawReq("GET", dhostA, "/sw.js"), refA, subOwnerA)
		r.Header.Set("Service-Worker", v)
		e.dexpect(t, "Service-Worker "+v, r, 404, "not_found")
	}
	e.passes(t, "control", e.as(t, rawReq("GET", dhostA, "/sw.js"), refA, subOwnerA))
}

func TestDashSession_Refusals(t *testing.T) {
	e := newDashEnv(t, active(), false)
	f := dfile(1)
	f.Issuer.SessionSeconds = 3600
	now := time.Now().Unix()
	f.Revoked = []dashfile.Revocation{{Iss: issuer, Sub: subDevA, NotBefore: now - 100}}
	writeDashFile(t, e.path(), f)
	if err := e.d.table.Reload(); err != nil {
		t.Fatal(err)
	}
	cookie := func(r *http.Request, v string) *http.Request {
		r.AddCookie(&http.Cookie{Name: "__Host-sp-session", Value: v})
		return r
	}
	api := func(tok string) *http.Request { return cookie(rawReq("GET", dhostA, "/api/x"), tok) }
	good := e.session(t, refA, issuer, subOwnerA, now-10, 3600)

	// No session: a navigation is redirected with its return path.
	nav := rawReq("GET", dhostA, "/project/"+refA+"/sql?tab=1&x=a%20b")
	nav.Header.Set("Sec-Fetch-Mode", "navigate")
	w := e.dexpect(t, "navigation", nav, 302, "")
	if loc := w.Header().Get("Location"); loc != "/-/auth/login?return=%2Fproject%2F"+refA+"%2Fsql%3Ftab%3D1%26x%3Da%2520b" {
		t.Errorf("Location %q", loc)
	}
	html := rawReq("GET", dhostA, "/x")
	html.Header.Set("Accept", "text/html,application/xhtml+xml")
	e.dexpect(t, "GET accepting html", html, 302, "")
	post := rawReq("POST", dhostA, "/x")
	post.Header.Set("Accept", "text/html")
	e.dexpect(t, "POST accepting html", post, 401, "login_required")
	e.dexpect(t, "no cookie", rawReq("GET", dhostA, "/api/x"), 401, "login_required")

	two := api(good)
	two.AddCookie(&http.Cookie{Name: "__Host-sp-session", Value: good})
	e.dexpect(t, "two cookies", two, 401, "login_required")
	e.dexpect(t, "other ref", api(e.session(t, refB, issuer, subOwnerA, now-10, 3600)), 401, "login_required")
	e.dexpect(t, "session of the sign-in host", api(e.session(t, "_", issuer, subOwnerA, now-10, 3600)), 401, "login_required")
	e.dexpect(t, "other issuer", api(e.session(t, refA, "https://other.test", subOwnerA, now-10, 3600)), 401, "login_required")
	e.dexpect(t, "expired", api(e.session(t, refA, issuer, subOwnerA, now-3600, 3600)), 401, "login_required")
	e.dexpect(t, "longer than the table allows", api(e.session(t, refA, issuer, subOwnerA, now-10, 3601)), 401, "login_required")
	e.passes(t, "as long as the table allows", api(e.session(t, refA, issuer, subOwnerA, now-10, 3600)))
	e.dexpect(t, "garbage", api("v1.x.y"), 401, "login_required")

	forged, _ := dashtok.SignSession(otherKey(t), dashtok.Session{Iss: issuer, Sub: subOwnerA, Ref: refA, Iat: now - 10, Exp: now + 100})
	e.dexpect(t, "another key", api(forged), 401, "login_required")
	as, _ := dashtok.SignAssertion(e.priv, dashtok.Assertion{Node: "local", Iss: issuer, Sub: subOwnerA, Ref: refA,
		Role: "owner", Iat: now - 1, Exp: now + 29})
	e.dexpect(t, "an assertion as a session", api(as), 401, "login_required")
	tk, _ := dashtok.SignTicket(e.priv, dashtok.Ticket{Iss: issuer, Sub: subOwnerA, Refs: []string{refA}, Iat: now - 1, Exp: now + 59})
	e.dexpect(t, "a ticket as a session", api(tk), 401, "login_required")

	// not_before: a session one second earlier is refused, one at it accepted.
	e.dexpect(t, "iat below not_before", api(e.session(t, refA, issuer, subDevA, now-101, 3600)), 401, "login_required")
	e.passes(t, "iat equal to not_before", api(e.session(t, refA, issuer, subDevA, now-100, 3600)))

	// No issuer: no session verifies.
	f.Issuer = nil
	f.Generation = 2
	writeDashFile(t, e.path(), f)
	if err := e.d.table.Reload(); err != nil {
		t.Fatal(err)
	}
	e.dexpect(t, "no issuer", api(good), 401, "login_required")
}

func otherKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	p, _, err := dashtok.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := dashtok.ParsePrivate(p)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestDashMembership_ReadOnEveryRequest(t *testing.T) {
	e := newDashEnv(t, active(), true)
	now := time.Now().Unix()
	devTok := e.session(t, refA, issuer, subDevA, now-10, 3600)
	ownTok := e.session(t, refA, issuer, subOwnerA, now-10, 3600)
	r := func(method, target, tok string) *http.Request {
		q := rawReq(method, dhostA, target)
		q.AddCookie(&http.Cookie{Name: "__Host-sp-session", Value: tok})
		return q
	}
	reveal := "/api/v1/projects/" + refA + "/api-keys?reveal=true"
	if dr := e.passes(t, "developer", r("POST", "/x", devTok)); dr.Role != "developer" {
		t.Errorf("role %q", dr.Role)
	}
	if dr := e.passes(t, "owner reveal", r("GET", reveal, ownTok)); dr.Role != "owner" || dr.Purpose != "reveal" {
		t.Errorf("role %q purpose %q", dr.Role, dr.Purpose)
	}
	e.dexpect(t, "member of B on A", r("GET", "/x", e.session(t, refA, issuer, subOwnerB, now-10, 3600)), 403, "not_a_member")

	f := dfile(2)
	p := f.Projects[refA]
	p.Members = []dashfile.Member{{Iss: issuer, Sub: subOwnerA, Role: "read_only"}, {Iss: issuer, Sub: subROA, Role: "read_only"}}
	f.Projects[refA] = p
	writeDashFile(t, e.path(), f)
	if err := e.d.table.Reload(); err != nil {
		t.Fatal(err)
	}
	e.dexpect(t, "removed", r("GET", "/x", devTok), 403, "not_a_member")
	e.dexpect(t, "demoted, write", r("POST", "/x", ownTok), 403, "read_only")
	if dr := e.passes(t, "demoted, reveal", r("GET", reveal, ownTok)); dr.Role != "read_only" || dr.Purpose != "" {
		t.Errorf("role %q purpose %q", dr.Role, dr.Purpose)
	}
}

func TestDashSameOrigin(t *testing.T) {
	e := newDashEnv(t, active(), true)
	r := func(method, target string, h ...string) *http.Request {
		q := e.as(t, rawReq(method, dhostA, target), refA, subOwnerA)
		for i := 0; i < len(h); i += 2 {
			q.Header.Add(h[i], h[i+1])
		}
		return q
	}
	for _, site := range []string{"same-site", "cross-site", "Same-Origin", ""} {
		for _, m := range []string{"GET", "POST"} {
			for _, p := range []string{"/api/x", "/project/" + refA} {
				e.dexpect(t, site+" "+m+" "+p, r(m, p, "Sec-Fetch-Site", site), 403, "cross_origin")
			}
		}
	}
	nav := []string{"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "document"}
	e.passes(t, "cross-site navigation to a page", r("GET", "/project/"+refA, nav...))
	e.passes(t, "cross-site navigation to a page that begins api", r("GET", "/apix", nav...))
	e.dexpect(t, "cross-site navigation to an API path", r("GET", "/api/x", nav...), 403, "cross_origin")
	for _, p := range []string{"/api", "/API", "/Api"} {
		e.dexpect(t, "cross-site navigation to "+p, r("GET", p, nav...), 403, "cross_origin")
	}
	e.dexpect(t, "cross-site navigation to /api/", r("GET", "/api/", nav...), 400, "bad_request")
	e.dexpect(t, "cross-site navigation to /API/", r("GET", "/API/x", nav...), 403, "cross_origin")
	e.dexpect(t, "cross-site navigation by POST", r("POST", "/project/"+refA, nav...), 403, "cross_origin")
	e.dexpect(t, "cross-site navigation into a frame", r("GET", "/project/"+refA,
		"Sec-Fetch-Site", "cross-site", "Sec-Fetch-Mode", "navigate", "Sec-Fetch-Dest", "iframe"), 403, "cross_origin")
	e.dexpect(t, "two values, one cross", r("GET", "/x", "Sec-Fetch-Site", "same-origin", "Sec-Fetch-Site", "cross-site"), 403, "cross_origin")
	for _, site := range []string{"same-origin", "none"} {
		e.passes(t, site, r("POST", "/api/x", "Sec-Fetch-Site", site))
	}
	e.passes(t, "no header", r("POST", "/api/x"))
}

func TestDashReadOnly(t *testing.T) {
	e := newDashEnv(t, active(), true)
	ro := func(m, target string) *http.Request { return e.as(t, rawReq(m, dhostA, target), refA, subROA) }
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "TRACE", "PROPFIND"} {
		e.dexpect(t, m, ro(m, "/api/v1/projects/"+refA), 403, "read_only")
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		e.passes(t, m, ro(m, "/api/x"))
	}
	e.passes(t, "query", ro("POST", "/api/platform/pg-meta/"+refA+"/query"))
	e.passes(t, "parse-query", ro("POST", "/api/parse-query"))
	e.dexpect(t, "query of another ref", ro("POST", "/api/platform/pg-meta/"+refB+"/query"), 404, "not_found")
	for _, p := range []string{
		"/api/platform/pg-meta/%61" + refA[1:] + "/query", "/api/platform/pg-meta/" + refA + "/%71uery",
		"/API/platform/pg-meta/" + refA + "/query", "/api/platform/pg-meta/" + strings.ToUpper(refA) + "/query",
		"/api/parse-Query", "/api/%70arse-query", "/api/platform/pg-meta/" + refA + "/query/x",
	} {
		e.dexpect(t, "spelling "+p, ro("POST", p), 403, "read_only")
	}
	e.dexpect(t, "PUT on the exception path", ro("PUT", "/api/parse-query"), 403, "read_only")
	e.passes(t, "developer writes", e.as(t, rawReq("DELETE", dhostA, "/api/x"), refA, subDevA))
}

func TestDashPurpose_OnlyTheTwoRequests(t *testing.T) {
	e := newDashEnv(t, active(), true)
	keysPath := "/api/v1/projects/" + refA + "/api-keys"
	purpose := func(name, method, target, sub string) string {
		t.Helper()
		return e.passes(t, name, e.as(t, rawReq(method, dhostA, target), refA, sub)).Purpose
	}
	for _, target := range []string{keysPath + "?reveal=true", keysPath + "/abc?reveal=true"} {
		if p := purpose(target, "GET", target, subOwnerA); p != "reveal" {
			t.Errorf("%s: purpose %q", target, p)
		}
	}
	for name, target := range map[string]string{
		"second parameter": keysPath + "?reveal=true&x=1", "parameter first": keysPath + "?x=1&reveal=true",
		"value case": keysPath + "?reveal=TRUE", "name case": keysPath + "?Reveal=true", "no query": keysPath,
		"empty pair": keysPath + "?reveal=true&", "path case": "/API/v1/projects/" + refA + "/api-keys?reveal=true",
		"segment case": "/api/v1/projects/" + refA + "/API-keys?reveal=true", "deeper": keysPath + "/a/b?reveal=true",
		"encoded": "/api/v1/projects/" + refA + "/api%2Dkeys?reveal=true", "encoded query": keysPath + "?reveal=%74rue",
		"other path": "/api/v1/projects/" + refA + "/api-keysx?reveal=true",
	} {
		if p := purpose(name, "GET", target, subOwnerA); p != "" {
			t.Errorf("%s: purpose %q", name, p)
		}
	}
	if p := purpose("developer", "GET", keysPath+"?reveal=true", subDevA); p != "" {
		t.Errorf("developer: purpose %q", p)
	}
	if p := purpose("POST", "POST", keysPath+"?reveal=true", subOwnerA); p != "" {
		t.Errorf("POST: purpose %q", p)
	}
	if p := purpose("HEAD", "HEAD", keysPath+"?reveal=true", subOwnerA); p != "" {
		t.Errorf("HEAD: purpose %q", p)
	}
}

func TestDashLimits(t *testing.T) {
	e := newDashEnv(t, active(), true)
	owner := func(m, target string, body string, length int64) *http.Request {
		r := e.as(t, rawReq(m, dhostA, target), refA, subOwnerA)
		r.Body = http.NoBody
		if body != "" {
			r.Body = nopCloser{strings.NewReader(body)}
		}
		r.ContentLength = length
		return r
	}
	const mib, kib = 1 << 20, 1 << 10
	big, parse := strings.Repeat("x", 2*mib), strings.Repeat("x", 256*kib)

	e.dexpect(t, "declared above the cap", owner("POST", "/api/x", big+"x", 2*mib+1), 413, "body_too_large")
	e.dexpect(t, "parse-query declared above its cap", owner("POST", "/api/parse-query", parse+"x", 256*kib+1), 413, "body_too_large")
	e.dexpect(t, "parse-query in capitals", owner("POST", "/API/Parse-Query", parse+"x", 256*kib+1), 413, "body_too_large")
	e.readBody = true
	for _, c := range []struct {
		name, target, body string
		length             int64
		tooLarge           bool
	}{
		{"at the cap", "/api/x", big, 2 * mib, false},
		{"undeclared at the cap", "/api/x", big, -1, false},
		{"undeclared above the cap", "/api/x", big + "x", -1, true},
		{"parse-query at its cap", "/api/parse-query", parse, 256 * kib, false},
		{"parse-query undeclared above its cap", "/api/parse-query", parse + "x", -1, true},
		{"other path above the parse cap", "/api/parse-queryx", parse + "x", -1, false},
		{"parse-query not under /api", "/x/parse-query", parse + "x", -1, false},
		{"parse-query not under /api, declared", "/x/parse-query", parse + "x", 256*kib + 1, false},
	} {
		e.passes(t, c.name, owner("POST", c.target, c.body, c.length))
		var tooLarge *http.MaxBytesError
		if got := errors.As(e.bodyErr, &tooLarge); got != c.tooLarge {
			t.Errorf("%s: body error %v", c.name, e.bodyErr)
		}
	}
	e.readBody = false

	for _, v := range []string{"websocket", "h2c"} {
		r := owner("GET", "/x", "", 0)
		r.Header.Set("Upgrade", v)
		e.dexpect(t, "upgrade "+v, r, 400, "upgrade_not_supported")
	}

	// 32 requests of project A in flight: the 33rd is 429, B is served.
	e.hold, e.entered = make(chan struct{}), make(chan struct{}, 64)
	done := make(chan int, 64)
	for i := 0; i < 32; i++ {
		go func() { done <- e.do(owner("GET", "/x", "", 0)).Code }()
		select {
		case <-e.entered:
		case c := <-done:
			close(e.hold)
			t.Fatalf("request %d of project A not forwarded: %d (slots leaked?)", i+1, c)
		}
	}
	if n := len(e.gw.inflight); n != 32 {
		t.Errorf("gateway-wide slots held: %d, want 32", n)
	}
	e.mu.Lock()
	e.fwd = nil
	e.mu.Unlock()
	// The 33rd runs on its own goroutine: if it were forwarded it would wait
	// on hold, and the test must fail, not hang.
	third, held := make(chan *httptest.ResponseRecorder, 1), 33
	go func() { third <- e.do(owner("GET", "/x", "", 0)) }()
	select {
	case w := <-third:
		if w.Code != 429 || dashHeadersWrong(w.Header()) != "" {
			t.Errorf("33rd request: %d %v", w.Code, w.Header())
		}
	case <-e.entered:
		t.Error("33rd request of a project forwarded")
		go func() { done <- (<-third).Code }()
		held++
	}
	go func() { done <- e.do(e.as(t, rawReq("GET", dhostB, "/x"), refB, subOwnerB)).Code }()
	<-e.entered
	close(e.hold)
	for i := 0; i < held; i++ {
		if c := <-done; c != 200 {
			t.Errorf("held request: %d", c)
		}
	}
	e.hold, e.entered = nil, nil
	if len(e.gw.inflight) != 0 || len(e.d.slots) != 0 || len(e.d.byRef) != 0 {
		t.Errorf("slots not returned: gateway %d dashboard %d projects %v", len(e.gw.inflight), len(e.d.slots), e.d.byRef)
	}

	// The node's dashboard cap, then the gateway-wide cap.
	for i := 0; i < cap(e.d.slots); i++ {
		e.d.slots <- struct{}{}
	}
	if cap(e.d.slots) != 256 {
		t.Errorf("dashboard cap %d", cap(e.d.slots))
	}
	e.dexpect(t, "dashboard cap", owner("GET", "/x", "", 0), 503, "unavailable")
	for len(e.d.slots) > 0 {
		<-e.d.slots
	}
	for i := 0; i < cap(e.gw.inflight); i++ {
		e.gw.inflight <- struct{}{}
	}
	e.dexpect(t, "gateway cap", owner("GET", "/x", "", 0), 503, "unavailable")
	for len(e.gw.inflight) > 0 {
		<-e.gw.inflight
	}
	if len(e.d.byRef) != 0 {
		t.Errorf("project slots leaked by refusals: %v", e.d.byRef)
	}
	e.passes(t, "after the caps", owner("GET", "/x", "", 0))
}

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }

func TestDashRules_FirstFailingRuleAnswers(t *testing.T) {
	e := newDashEnv(t, active(), true)
	ro := func(m, target string) *http.Request { return e.as(t, rawReq(m, dhostA, target), refA, subROA) }
	counts := func() [5]int64 {
		e.d.mu.Lock()
		defer e.d.mu.Unlock()
		if c := e.d.refused[refA]; c != nil {
			return *c
		}
		return [5]int64{}
	}
	e.dexpect(t, "rule 0 before rule 2", rawReq("GET", dhostA, "/x//"+refB), 400, "bad_request")
	e.dexpect(t, "rule 0 before rule 1", rawReq("GET", dhostA, "/-/auth//login"), 400, "bad_request")
	before := counts()
	e.dexpect(t, "rule 2 before rule 3", rawReq("GET", dhostA, "/api/ai/"+refB), 404, "not_found")
	if c := counts(); c[2] != before[2]+1 || c[3] != before[3] {
		t.Errorf("counted %v, then %v", before, c)
	}
	before = counts()
	sw := rawReq("POST", dhostA, "/api/mcp")
	sw.Header.Set("Service-Worker", "script")
	e.dexpect(t, "rule 3 before rule 4 and 5", sw, 404, "not_found")
	if c := counts(); c[3] != before[3]+1 || c[4] != before[4] {
		t.Errorf("counted %v, then %v", before, c)
	}
	sw = rawReq("GET", dhostA, "/sw.js")
	sw.Header.Set("Service-Worker", "script")
	e.dexpect(t, "rule 4 before rule 5", sw, 404, "not_found")
	cross := rawReq("DELETE", dhostA, "/x")
	cross.Header.Set("Sec-Fetch-Site", "cross-site")
	e.dexpect(t, "rule 5 before 7 and 8", cross, 401, "login_required")
	nm := e.as(t, rawReq("DELETE", dhostA, "/x"), refA, subOwnerB)
	nm.Header.Set("Sec-Fetch-Site", "cross-site")
	e.dexpect(t, "rule 6 before 7", nm, 403, "not_a_member")
	c := ro("DELETE", "/x")
	c.Header.Set("Sec-Fetch-Site", "cross-site")
	e.dexpect(t, "rule 7 before 8", c, 403, "cross_origin")
	u := ro("POST", "/x")
	u.Header.Set("Upgrade", "websocket")
	u.ContentLength = 3 << 20
	e.dexpect(t, "rule 8 before 10", u, 403, "read_only")
	u = e.as(t, rawReq("POST", dhostA, "/x"), refA, subOwnerA)
	u.Header.Set("Upgrade", "websocket")
	u.ContentLength = 3 << 20
	e.dexpect(t, "upgrade before body", u, 400, "upgrade_not_supported")
	// Rule 1 comes before the ref rule and the session: the sign-in paths are
	// the gateway's own.
	e.resetSeams()
	if w := e.do(rawReq("GET", dhostA, "/-/auth/login/"+refB)); w.Code != 200 || len(e.auth) != 1 {
		t.Errorf("rule 1: %d, auth %d", w.Code, len(e.auth))
	}
	e.passes(t, "an encoded auth path is not rule 1", e.as(t, rawReq("GET", dhostA, "/-/%61uth/login"), refA, subOwnerA))
	e.passes(t, "/-/auth alone is not rule 1", e.as(t, rawReq("GET", dhostA, "/-/auth"), refA, subOwnerA))
}

// TestDashSession_NotPresented_RefererOfTheSessionPage: a navigation without
// a session whose Referer is this host's own session address, at most 60 s
// old by the gateway's clock, goes to the sign-in seam marked Unpresented;
// every other Referer is redirected to sign-in as before.
func TestDashSession_NotPresented_RefererOfTheSessionPage(t *testing.T) {
	e := newDashEnv(t, active(), true)
	now := time.Now().Unix()
	at := func(n int64) string { return strconv.FormatInt(n, 10) }
	session := func(host, n string) string { return "https://" + host + "/-/auth/session?at=" + n }
	const target = "/project/" + refA + "/sql?x=1"
	nav := func(m, referer string) *http.Request {
		r := rawReq(m, dhostA, target)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		return r
	}
	html := func(referer string) *http.Request {
		r := rawReq("GET", dhostA, target)
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Referer", referer)
		return r
	}
	unpresented := func(name string, r *http.Request) {
		t.Helper()
		e.resetSeams()
		w := e.do(r)
		f, a := e.seams()
		if w.Code != 200 || f != 0 || a != 1 || w.Header().Get("Location") != "" {
			t.Errorf("%s: %d, forward %d, auth %d, Location %q", name, w.Code, f, a, w.Header().Get("Location"))
			return
		}
		e.mu.Lock()
		dr, held := e.auth[0], e.authHeld
		e.mu.Unlock()
		if !dr.Unpresented || dr.Ref != refA || dr.Session != (dashtok.Session{}) || held != 0 {
			t.Errorf("%s: unpresented %v, ref %q, session %+v, slots held %d", name, dr.Unpresented, dr.Ref, dr.Session, held)
		}
	}
	redirected := func(name string, r *http.Request) {
		t.Helper()
		w := e.dexpect(t, name, r, 302, "")
		if loc := w.Header().Get("Location"); loc != "/-/auth/login?return="+url.QueryEscape(target) {
			t.Errorf("%s: Location %q", name, loc)
		}
	}

	unpresented("10 s old", nav("GET", session(dhostA, at(now-10))))
	unpresented("now", nav("GET", session(dhostA, at(now))))
	unpresented("50 s old", nav("GET", session(dhostA, at(now-50))))
	unpresented("GET accepting html", html(session(dhostA, at(now-10))))
	unpresented("a navigation by POST", nav("POST", session(dhostA, at(now-10))))

	for name, ref := range map[string]string{
		"61 s old":               session(dhostA, at(now-61)),
		"an hour old":            session(dhostA, at(now-3600)),
		"in the future":          session(dhostA, at(now+3600)),
		"missing":                "https://" + dhostA + "/-/auth/session",
		"no parameter":           "https://" + dhostA + "/-/auth/session?",
		"empty":                  session(dhostA, ""),
		"exponent":               session(dhostA, "1e3"),
		"negative":               session(dhostA, "-"+at(now-10)),
		"plus sign":              session(dhostA, "+"+at(now-10)),
		"space":                  session(dhostA, " "+at(now-10)),
		"fraction":               session(dhostA, at(now-10)+".0"),
		"hexadecimal":            session(dhostA, "0x"+strconv.FormatInt(now-10, 16)),
		"overflow":               session(dhostA, "99999999999999999999999"),
		"second parameter":       session(dhostA, at(now-10)) + "&x=1",
		"parameter first":        "https://" + dhostA + "/-/auth/session?x=1&at=" + at(now-10),
		"twice":                  session(dhostA, at(now-10)) + "&at=" + at(now-10),
		"name case":              "https://" + dhostA + "/-/auth/session?AT=" + at(now-10),
		"fragment":               session(dhostA, at(now-10)) + "#",
		"another dashboard":      session(dhostB, at(now-10)),
		"the sign-in host":       session(signInH, at(now-10)),
		"the studio domain":      session(studioDom, at(now-10)),
		"another scheme":         "http://" + dhostA + "/-/auth/session?at=" + at(now-10),
		"a port":                 "https://" + dhostA + ":443/-/auth/session?at=" + at(now-10),
		"host in capitals":       session(strings.ToUpper(dhostA), at(now-10)),
		"a segment longer":       "https://" + dhostA + "/-/auth/session/x?at=" + at(now-10),
		"a segment shorter":      "https://" + dhostA + "/-/auth?at=" + at(now-10),
		"another path":           "https://" + dhostA + "/-/auth/login?at=" + at(now-10),
		"path case":              "https://" + dhostA + "/-/auth/Session?at=" + at(now-10),
		"encoded path":           "https://" + dhostA + "/-/auth/%73ession?at=" + at(now-10),
		"userinfo":               "https://x@" + dhostA + "/-/auth/session?at=" + at(now-10),
		"suffix of another host": "https://x" + dhostA + "/-/auth/session?at=" + at(now-10),
		"relative":               "/-/auth/session?at=" + at(now-10),
		"no Referer":             "",
	} {
		redirected(name, nav("GET", ref))
	}
	two := nav("GET", session(dhostA, at(now-10)))
	two.Header.Add("Referer", session(dhostA, at(now-10)))
	redirected("two Referer headers", two)

	// Not a navigation: 401 as before.
	api := rawReq("GET", dhostA, "/api/x")
	api.Header.Set("Referer", session(dhostA, at(now-10)))
	e.dexpect(t, "not a navigation", api, 401, "login_required")

	// With a valid session the request is forwarded whatever its Referer.
	for _, ref := range []string{session(dhostA, at(now-10)), "https://evil.example/", ""} {
		r := e.as(t, nav("GET", ref), refA, subOwnerA)
		if dr := e.passes(t, "session, Referer "+ref, r); dr.Unpresented {
			t.Errorf("session, Referer %q: marked unpresented", ref)
		}
	}

	// A session that is present but invalid is no session: the exception holds.
	bad := nav("GET", session(dhostA, at(now-10)))
	bad.AddCookie(&http.Cookie{Name: "__Host-sp-session", Value: e.session(t, refB, issuer, subOwnerA, now-10, 3600)})
	unpresented("session of another ref", bad)

	// Rules 2 to 4 come first.
	e.dexpect(t, "rule 2 first", func() *http.Request {
		r := rawReq("GET", dhostA, "/x/"+refB)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Referer", session(dhostA, at(now-10)))
		return r
	}(), 404, "not_found")

	// Without the sign-in seam the exception is answered 503, never a redirect.
	dashAuth = nil
	e.dexpect(t, "no sign-in seam", nav("GET", session(dhostA, at(now-10))), 503, "unavailable")
}
