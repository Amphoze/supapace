package gateway

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/routes"
)

func stoppedA() *routes.File { f := file(1, "stopped"); return &f }

func TestStopped_AnswersProjectStoppedBeforeTheKeyCheck(t *testing.T) {
	a, _, stranger := keys()
	e := newEnv(t, stoppedA())
	for name, key := range map[string]string{"no key": "", "foreign key": stranger.token(t, "anon"),
		"malformed key": "x", "valid key": a.anon.token(t, "anon")} {
		r := req("GET", hostA, "/rest/v1/", nil)
		if key != "" {
			withKey(r, key)
		}
		e.reset()
		w := e.do(r)
		if w.Code != 503 || strings.TrimSpace(w.Body.String()) != `{"code":"project_stopped","message":"the project is stopped"}` {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		if len(e.dialed) != 0 {
			t.Errorf("%s: stopped project dialled", name)
		}
	}
	// Controls: the same requests to an active entry meet the key check, and
	// a valid one is served.
	e = newEnv(t, active())
	e.expect(t, "active, no key", req("GET", hostA, "/rest/v1/", nil), 401, "no_apikey")
	e.expect(t, "active, valid key", withKey(req("GET", hostA, "/rest/v1/", nil), a.anon.token(t, "anon")), 200, "")
}

func TestStopped_CarriesNoRetryAfter(t *testing.T) {
	a, _, _ := keys()
	anon := a.anon.token(t, "anon")
	w := newEnv(t, stoppedA()).do(withKey(req("GET", hostA, "/rest/v1/", nil), anon))
	if w.Code != 503 || w.Header().Values("Retry-After") != nil {
		t.Errorf("stopped: %d, Retry-After %q", w.Code, w.Header().Values("Retry-After"))
	}
	if h := w.Header(); h.Get("Content-Security-Policy") != "sandbox" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("stopped: no sandbox headers: %v", h)
	}
	f := file(1, "draining")
	w = newEnv(t, &f).do(withKey(req("GET", hostA, "/rest/v1/", nil), anon))
	if w.Code != 503 || w.Header().Get("Retry-After") != "5" || !strings.Contains(w.Body.String(), "project_restarting") {
		t.Errorf("draining: %d, Retry-After %q, %s", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
}

func withRate(r *routes.Rate, refs ...string) *routes.File {
	f := file(1, "active")
	for _, ref := range refs {
		p := f.Projects[ref]
		p.Rate = r
		f.Projects[ref] = p
	}
	return &f
}

// frozen gives ref a bucket holding tokens whose time lies an hour ahead: a
// clock behind the bucket's time refills nothing, so the test does not depend
// on how fast the requests run.
func frozen(e *env, ref string, tokens float64, rps, burst int) {
	e.gw.rates.mu.Lock()
	defer e.gw.rates.mu.Unlock()
	if e.gw.rates.m == nil {
		e.gw.rates.m = map[string]*bucket{}
	}
	e.gw.rates.m[ref] = &bucket{tokens: tokens, at: time.Now().Add(time.Hour), rps: rps, burst: burst}
}

func TestRate_ThrottlesOneProjectOnly(t *testing.T) {
	a, b, _ := keys()
	e := newEnv(t, withRate(&routes.Rate{RPS: 1, Burst: 3}, refA, refB))
	frozen(e, refA, 3, 1, 3)
	frozen(e, refB, 3, 1, 3)
	keyA, keyB := a.anon.token(t, "anon"), b.anon.token(t, "anon")
	for i := range 3 { // below the rate: the burst is served
		e.expect(t, "A within its burst "+strconv.Itoa(i), withKey(req("GET", hostA, "/rest/v1/", nil), keyA), 200, "")
	}
	e.expect(t, "A over its burst", withKey(req("GET", hostA, "/rest/v1/", nil), keyA), 429, "too_many_requests")
	w := e.do(withKey(req("GET", hostA, "/rest/v1/", nil), keyA))
	if w.Header().Get("Retry-After") != "1" {
		t.Errorf("429 without Retry-After: %v", w.Header())
	}
	for i := range 3 {
		e.expect(t, "B with the same rate "+strconv.Itoa(i), withKey(req("GET", hostB, "/rest/v1/", nil), keyB), 200, "")
	}
	e.expect(t, "B over its burst", withKey(req("GET", hostB, "/rest/v1/", nil), keyB), 429, "too_many_requests")
}

func TestRate_RefusedKeyTakesNoToken(t *testing.T) {
	a, _, stranger := keys()
	e := newEnv(t, withRate(&routes.Rate{RPS: 1, Burst: 1}, refA))
	frozen(e, refA, 1, 1, 1)
	anon := a.anon.token(t, "anon")
	for i := range 20 {
		e.expect(t, "no key", req("GET", hostA, "/rest/v1/", nil), 401, "no_apikey")
		e.expect(t, "foreign key", withKey(req("GET", hostA, "/rest/v1/", nil), stranger.token(t, "anon")), 401, "invalid_apikey")
		r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
		r.Header.Set("Authorization", "Bearer x"+strconv.Itoa(i))
		e.expect(t, "bad bearer", r, 401, "invalid_token")
		r = withKey(req("GET", hostA, "/rest/v1/", nil), anon)
		r.Header.Set("Upgrade", "websocket")
		e.expect(t, "upgrade", r, 400, "upgrade_not_supported")
	}
	e.expect(t, "first valid", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 200, "")
	// Control: the bucket holds one token, and the valid request took it.
	e.expect(t, "second valid", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 429, "too_many_requests")
}

// TestRate_Bucket drives the bucket with explicit times: refill at the rate,
// never above the burst, a changed rate applies at once, and entries that
// are full again are dropped so the map holds only recently busy projects.
func TestRate_Bucket(t *testing.T) {
	var l rates
	t0 := time.Unix(1000, 0)
	r := &routes.Rate{RPS: 10, Burst: 20}
	if !l.allow("x", nil, t0) || len(l.m) != 0 {
		t.Fatal("no rate: refused or recorded")
	}
	n := 0
	for l.allow("x", r, t0) {
		n++
	}
	if n != 20 {
		t.Fatalf("burst served %d, want 20", n)
	}
	if l.allow("x", r, t0.Add(99*time.Millisecond)) || !l.allow("x", r, t0.Add(100*time.Millisecond)) {
		t.Fatal("refill is not one token per 1/RPS")
	}
	// A long pause refills to the burst and no further.
	n = 0
	for l.allow("x", r, t0.Add(time.Hour)) {
		n++
	}
	if n != 20 {
		t.Fatalf("after a pause served %d, want 20", n)
	}
	// A smaller burst caps what is held at once.
	n = 0
	for l.allow("x", &routes.Rate{RPS: 10, Burst: 10}, t0.Add(2*time.Hour)) {
		n++
	}
	if n != 10 {
		t.Fatalf("lowered burst served %d, want 10", n)
	}
	// A clock that steps back refills nothing.
	if l.allow("x", r, t0) {
		t.Fatal("a step back refilled the bucket")
	}
	// Nor does it move the bucket's time back: the hour before is not counted again.
	if l.allow("x", r, t0.Add(2*time.Hour)) {
		t.Fatal("time counted twice after a step back")
	}
	// Sweep: y is still empty, x is full by the time z arrives; z's arrival
	// drops x, keeps y.
	l.allow("y", &routes.Rate{RPS: 1, Burst: 1}, t0.Add(3*time.Hour))
	l.allow("z", r, t0.Add(3*time.Hour))
	if _, ok := l.m["x"]; ok || l.m["y"] == nil || l.m["z"] == nil || len(l.m) != 2 {
		t.Fatalf("sweep left %v", l.m)
	}
}

// TestNoSettings_AnswersUnchanged: entries without the new members get the
// gateway's answers as recorded before the members existed, every byte of
// status, Retry-After and body; and no rate applies.
func TestNoSettings_AnswersUnchanged(t *testing.T) {
	a, b, _ := keys()
	anon, user := a.anon.token(t, "anon"), a.iss.token(t, "authenticated")
	bearer := func(r *http.Request, tok string) *http.Request {
		r.Header.Set("Authorization", "Bearer "+tok)
		return r
	}
	draining := file(1, "draining")
	for _, c := range []struct {
		name       string
		f          *routes.File
		r          *http.Request
		status     int
		retryAfter string
		body       string
	}{
		{"served", active(), withKey(req("GET", hostA, "/rest/v1/t", nil), anon), 200, "", `{"ok":true}`},
		{"issuer bearer", active(), bearer(withKey(req("GET", hostA, "/rest/v1/t", nil), anon), user), 200, "", `{"ok":true}`},
		{"no apikey", active(), req("GET", hostA, "/rest/v1/t", nil), 401, "", `{"code":"no_apikey"}`},
		{"other project's key", active(), withKey(req("GET", hostA, "/rest/v1/t", nil), b.anon.token(t, "anon")), 401, "",
			`{"code":"invalid_apikey","message":"token kid is not a key of this project"}`},
		{"bad bearer", active(), bearer(withKey(req("GET", hostA, "/rest/v1/t", nil), anon), "x.y"), 401, "",
			`{"code":"invalid_token","message":"token is malformed"}`},
		{"unknown path", active(), withKey(req("GET", hostA, "/nope", nil), anon), 404, "", `{"code":"not_found"}`},
		{"unknown host", active(), req("GET", "cccccccccccccccccccc.sp.test", "/rest/v1/", nil), 404, "", `{"code":"not_found"}`},
		{"upgrade", active(), func() *http.Request {
			r := req("GET", hostA, "/rest/v1/", nil)
			r.Header.Set("Upgrade", "h2c")
			return r
		}(), 400, "", `{"code":"upgrade_not_supported"}`},
		{"draining", &draining, req("GET", hostA, "/rest/v1/", nil), 503, "5", `{"code":"project_restarting"}`},
	} {
		w := newEnv(t, c.f).do(c.r)
		if w.Code != c.status || w.Header().Get("Retry-After") != c.retryAfter || strings.TrimSpace(w.Body.String()) != c.body {
			t.Errorf("%s: %d %q %s, want %d %q %s", c.name, w.Code, w.Header().Get("Retry-After"), w.Body, c.status, c.retryAfter, c.body)
		}
	}
	// No rate member: many requests at once are all served.
	e := newEnv(t, active())
	for i := range 200 {
		if w := e.do(withKey(req("GET", hostA, "/rest/v1/", nil), anon)); w.Code != 200 {
			t.Fatalf("request %d: %d %s", i, w.Code, w.Body)
		}
	}
}

func TestUpstream_IdleConnectionsCloseAfterTheTimeout(t *testing.T) {
	if tr := New(NewTable("")).transport; tr.IdleConnTimeout != upstreamIdle || upstreamIdle != 60*time.Second {
		t.Fatalf("New's transport idle timeout %v, constant %v", tr.IdleConnTimeout, upstreamIdle)
	}
	const conns = 4
	open := func(idle time.Duration) (*atomic.Int32, *http.Transport, string) {
		var n atomic.Int32
		var arrived sync.WaitGroup
		arrived.Add(conns)
		up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			arrived.Done()
			arrived.Wait() // every request holds its own connection
		}))
		up.Config.ConnState = func(_ net.Conn, s http.ConnState) {
			switch s {
			case http.StateNew:
				n.Add(1)
			case http.StateClosed, http.StateHijacked:
				n.Add(-1)
			}
		}
		up.Start()
		t.Cleanup(up.Close)
		tr := newTransport(idle)
		t.Cleanup(tr.CloseIdleConnections)
		var done sync.WaitGroup
		for range conns {
			done.Add(1)
			go func() {
				defer done.Done()
				resp, err := (&http.Client{Transport: tr}).Get(up.URL)
				if err != nil {
					t.Error(err)
					return
				}
				resp.Body.Close()
			}()
		}
		done.Wait()
		if got := n.Load(); got != conns {
			t.Fatalf("upstream sees %d connections, want %d", got, conns)
		}
		return &n, tr, up.URL
	}
	n, _, _ := open(200 * time.Millisecond)
	start := time.Now()
	for n.Load() != 0 {
		if time.Since(start) > 10*time.Second {
			t.Fatalf("%d idle connections still open after 10 s", n.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	closed := time.Since(start)
	// Control: without a timeout they stay open well past the time the
	// timeout took.
	n0, tr0, _ := open(0)
	time.Sleep(max(2*closed, time.Second))
	if got := n0.Load(); got != conns {
		t.Fatalf("without a timeout %d of %d connections stayed open", got, conns)
	}
	tr0.CloseIdleConnections()
}

// gatewayAdditions are the files added to the package for rate limits,
// audiences and wakes. None may hand the upstream transport a hook (a trace,
// a body whose Read it calls) or write to a response from a goroutine of its
// own: such code runs beside the server's writer (see forward).
var gatewayAdditions = []string{"rate.go", "aud.go", "wake.go"}

func TestGatewayAdditions_UseNoTransportHook(t *testing.T) {
	for _, f := range gatewayAdditions {
		if v := transportHooks(t, f); len(v) != 0 {
			t.Errorf("%s: %s", f, strings.Join(v, "; "))
		}
	}
	// Control: the proxy's own file has a trace hook and a body's Read.
	if v := transportHooks(t, "proxy.go"); len(v) < 2 {
		t.Errorf("proxy.go: the check found only %v", v)
	}
}

func transportHooks(t *testing.T, name string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var v []string
	for _, im := range f.Imports {
		if p, _ := strconv.Unquote(im.Path.Value); p == "net/http/httptrace" {
			v = append(v, "imports "+p)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.GoStmt:
			v = append(v, "starts a goroutine")
		case *ast.FuncDecl:
			if n.Name.Name == "Read" {
				v = append(v, "declares a Read method")
			}
		case *ast.SelectorExpr:
			if n.Sel.Name == "Body" || n.Sel.Name == "ClientTrace" || n.Sel.Name == "WithClientTrace" || n.Sel.Name == "AfterFunc" {
				v = append(v, "uses "+n.Sel.Name)
			}
		}
		return true
	})
	return v
}
