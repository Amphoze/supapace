package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/routes"
	"github.com/Amphoze/supapace/internal/wakesock"
)

const refE = "eeeeeeeeeeeeeeeeeee5" // refC and refD are the dashboard tests'

func apiHost(ref string) string { return ref + ".sp.test" }

// standIn is the daemon's half behind wakesock.Serve: it records each call
// and answers with wake, nil by default.
type standIn struct {
	mu    sync.Mutex
	wakes []string
	idles [][]string
	wake  func(ctx context.Context, ref string) error
}

func (s *standIn) Wake(ctx context.Context, ref string) error {
	s.mu.Lock()
	s.wakes = append(s.wakes, ref)
	f := s.wake
	s.mu.Unlock()
	if f == nil {
		return nil
	}
	return f(ctx, ref)
}

func (s *standIn) Idle(_ context.Context, refs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idles = append(s.idles, refs)
}

func (s *standIn) count(ref string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.wakes {
		if r == ref || ref == "" {
			n++
		}
	}
	return n
}

// waitWakes waits, bounded, until the stand-in has seen n wakes of ref.
func (s *standIn) waitWakes(t *testing.T, ref string, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for s.count(ref) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d wakes of %s, want %d", s.count(ref), ref, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// sleepy is a route file whose given refs are asleep, all with A's keys.
func sleepy(gen int64, idle int, asleep []string, active ...string) routes.File {
	a, _, _ := keys()
	f := routes.File{Generation: gen, Domain: "sp.test", IdleStopS: idle, Projects: map[string]routes.Project{}}
	for i, ref := range asleep {
		f.Projects[ref] = routeOf(a, fmt.Sprintf("http://10.212.0.%d:3000", 16+i), "asleep")
	}
	for i, ref := range active {
		f.Projects[ref] = routeOf(a, fmt.Sprintf("http://10.212.%d.%d:3000", 1+i/200, 16+i%200), "active")
	}
	return f
}

// wakeEnv is a gateway on f with a stand-in on a temporary wake socket.
func wakeEnv(t *testing.T, f routes.File, s *standIn) *env {
	t.Helper()
	e := newEnv(t, &f)
	dir, err := os.MkdirTemp("", "wk")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, wakesock.SocketName)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- wakesock.Serve(ctx, path, os.Getuid(), s) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("Serve did not return")
		}
		os.RemoveAll(dir)
	})
	// The file exists from the bind on, before Serve listens; the mode it
	// sets after listening is the sign that it does.
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm() == 0o660 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not within 30 s: a wake socket of mode 0660")
		}
	}
	e.gw.SetWake(wakesock.NewClient(path))
	e.gw.wake.bound = time.Minute // tests of the bound set their own
	return e
}

// clock is a settable time for the back-off and the per-source window.
type clock struct{ ns atomic.Int64 }

func newClock(e *env) *clock {
	c := &clock{}
	c.ns.Store(time.Now().UnixNano())
	e.gw.wake.now = func() time.Time { return time.Unix(0, c.ns.Load()) }
	return c
}

func (c *clock) add(d time.Duration) { c.ns.Add(int64(d)) }

func anonReq(t *testing.T, ref, src string) *http.Request {
	a, _, _ := keys()
	r := withKey(req("GET", apiHost(ref), "/rest/v1/", nil), a.anon.token(t, "anon"))
	if src != "" {
		r.RemoteAddr = src
	}
	return r
}

// flip makes refs active in a new generation and waits until the table has it.
func flip(t *testing.T, e *env, f routes.File, refs ...string) routes.File {
	t.Helper()
	f.Generation++
	for _, ref := range refs {
		p := f.Projects[ref]
		p.State = "active"
		f.Projects[ref] = p
	}
	writeFile(t, e.path, f)
	if err := e.gw.table.Reload(); err != nil {
		t.Fatal(err)
	}
	return f
}

type answer struct {
	w  *httptest.ResponseRecorder
	at time.Duration
}

// async serves r in a goroutine and returns the channel of its answer.
func async(e *env, r *http.Request) <-chan answer {
	c := make(chan answer, 1)
	start := time.Now()
	go func() { w := e.do(r); c <- answer{w, time.Since(start)} }()
	return c
}

func answeredIn(t *testing.T, c <-chan answer, d time.Duration) answer {
	t.Helper()
	select {
	case a := <-c:
		return a
	case <-time.After(d):
		t.Fatalf("no answer within %v", d)
	}
	return answer{}
}

// restarting checks w is the gateway's 503 project_restarting, byte for byte
// the answer of a draining project.
func restarting(t *testing.T, name string, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != 503 || w.Body.String() != `{"code":"project_restarting"}` || w.Header().Get("Retry-After") != "5" ||
		w.Header().Get("Content-Security-Policy") != "sandbox" {
		t.Errorf("%s: %d %s %v, want 503 project_restarting", name, w.Code, w.Body, w.Header())
	}
}

func TestWake_KeylessRequestSendsNothing(t *testing.T) {
	s := &standIn{wake: func(context.Context, string) error { return wakesock.ErrBusy }}
	e := wakeEnv(t, sleepy(1, 0, []string{refA}), s)
	e.expect(t, "no apikey", req("GET", hostA, "/rest/v1/", nil), 401, "no_apikey")
	_, _, stranger := keys()
	e.expect(t, "a stranger's key", withKey(req("GET", hostA, "/rest/v1/", nil), stranger.token(t, "anon")), 401, "invalid_apikey")
	if n := s.count(""); n != 0 {
		t.Fatalf("keyless requests sent %d wakes", n)
	}
	// Control: the same request with the project's key asks for one.
	restarting(t, "with a key", e.do(anonReq(t, refA, "")))
	if n := s.count(refA); n != 1 {
		t.Fatalf("a keyed request sent %d wakes, want 1", n)
	}
}

// The wake comes after the key check, the bucket, the route check and the
// declared body length: each refusal on the way wakes nothing; the same
// request without its defect does.
func TestWake_RefusalsBeforeTheWakeSendNothing(t *testing.T) {
	s := &standIn{wake: func(context.Context, string) error { return wakesock.ErrBusy }}
	f := sleepy(1, 0, []string{refA})
	p := f.Projects[refA]
	p.Rate = &routes.Rate{RPS: 1, Burst: 1}
	f.Projects[refA] = p
	e := wakeEnv(t, f, s)
	a, _, _ := keys()
	anon := a.anon.token(t, "anon")
	cases := []struct {
		name, target string
		size         int64
		code         string
		status       int
	}{
		{"unknown path", "/nope", 0, "not_found", 404},
		{"declared body too large", "/rest/v1/t", maxBody + 1, "body_too_large", 413},
	}
	for i, c := range cases {
		frozen(e, refA, 1, 1, 1)
		r := withKey(req("POST", hostA, c.target, nil), anon)
		r.ContentLength = c.size
		e.expect(t, c.name, r, c.status, c.code)
		if n := s.count(refA); n != i {
			t.Fatalf("%s: %d wakes, want %d", c.name, n, i)
		}
		frozen(e, refA, 1, 1, 1)
		ok := withKey(req("POST", hostA, "/rest/v1/t", nil), anon) // control
		restarting(t, c.name+" control", e.do(ok))
		if n := s.count(refA); n != i+1 {
			t.Fatalf("%s control: %d wakes, want %d", c.name, n, i+1)
		}
	}
	// The bucket: the control takes the one token, the next is 429 and wakes nothing.
	frozen(e, refA, 1, 1, 1)
	restarting(t, "within the bucket", e.do(anonReq(t, refA, "")))
	e.expect(t, "over the bucket", anonReq(t, refA, ""), 429, "too_many_requests")
	if n := s.count(refA); n != 3 {
		t.Fatalf("after the bucket: %d wakes, want 3", n)
	}
}

func TestWake_ConcurrentRequestsOneCall(t *testing.T) {
	release := make(chan struct{})
	var e *env
	var f routes.File
	s := &standIn{}
	s.wake = func(ctx context.Context, ref string) error {
		select {
		case <-release:
		case <-ctx.Done():
			return wakesock.ErrFailed
		}
		f = flip(t, e, f, ref)
		return nil
	}
	f = sleepy(1, 0, []string{refA})
	e = wakeEnv(t, f, s)
	e.gw.projectCap = 512 // 200 held on one wake: above the default cap of 128
	const n = 200
	answers := make([]<-chan answer, n)
	for i := range n {
		answers[i] = async(e, anonReq(t, refA, "")) // one source: joiners spend none of its wakes
	}
	s.waitWakes(t, refA, 1)
	for deadline := time.Now().Add(30 * time.Second); e.gw.wake.joined(refA) < n-1; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d requests joined the wake, want %d", e.gw.wake.joined(refA), n-1)
		}
	}
	close(release)
	for i, c := range answers {
		if a := answeredIn(t, c, 30*time.Second); a.w.Code != 200 {
			t.Fatalf("request %d: %d %s", i, a.w.Code, a.w.Body)
		}
	}
	if w, u := s.count(refA), len(e.requests()); w != 1 || u != n {
		t.Fatalf("%d wakes for %d requests, upstream saw %d", w, n, u)
	}
}

func TestWake_NodeWideCapOfFour(t *testing.T) {
	release := make(chan struct{})
	s := &standIn{wake: func(ctx context.Context, ref string) error {
		if ref == refE {
			return wakesock.ErrBusy
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return wakesock.ErrBusy
	}}
	e := wakeEnv(t, sleepy(1, 0, []string{refA, refB, refC, refD, refE}), s)
	var held []<-chan answer
	for _, ref := range []string{refA, refB, refC, refD} {
		held = append(held, async(e, anonReq(t, ref, "")))
		s.waitWakes(t, ref, 1)
	}
	start := time.Now()
	restarting(t, "a fifth", e.do(anonReq(t, refE, "")))
	if el := time.Since(start); el > 5*time.Second || s.count(refE) != 0 {
		t.Fatalf("a fifth over the cap: answered after %v, %d wakes", el, s.count(refE))
	}
	close(release)
	for _, c := range held {
		restarting(t, "held", answeredIn(t, c, 30*time.Second).w)
	}
	// Control: with the places free the same request is sent.
	restarting(t, "a fifth, places free", e.do(anonReq(t, refE, "")))
	if n := s.count(refE); n != 1 {
		t.Fatalf("a fifth with free places: %d wakes", n)
	}
}

func TestWake_PerSourceRate(t *testing.T) {
	s := &standIn{wake: func(context.Context, string) error { return wakesock.ErrBusy }}
	e := wakeEnv(t, sleepy(1, 0, []string{refA}), s)
	c := newClock(e)
	src1, src1b, src2 := "[2001:db8:1::1]:4321", "[2001:db8:1::2]:4321", "[2001:db8:2::1]:4321"
	for i := range 6 {
		restarting(t, "within the rate", e.do(anonReq(t, refA, src1)))
		if n := s.count(refA); n != i+1 {
			t.Fatalf("request %d: %d wakes", i+1, n)
		}
	}
	start := time.Now()
	restarting(t, "the seventh", e.do(anonReq(t, refA, src1b))) // the same /64
	if el := time.Since(start); el > 5*time.Second || s.count(refA) != 6 {
		t.Fatalf("the seventh in a minute: answered after %v, %d wakes", el, s.count(refA))
	}
	restarting(t, "another source", e.do(anonReq(t, refA, src2)))
	if n := s.count(refA); n != 7 {
		t.Fatalf("another source: %d wakes, want 7", n)
	}
	c.add(time.Minute + time.Second)
	restarting(t, "a minute later", e.do(anonReq(t, refA, src1)))
	if n := s.count(refA); n != 8 {
		t.Fatalf("a minute later: %d wakes, want 8", n)
	}
}

func TestWake_HoldExpiresWithProjectRestarting(t *testing.T) {
	s := &standIn{wake: func(ctx context.Context, _ string) error { <-ctx.Done(); return nil }}
	e := wakeEnv(t, sleepy(1, 0, []string{refA}), s)
	e.gw.wake.bound = time.Second
	g0, f0 := runtime.NumGoroutine(), openFDs(t)
	a := answeredIn(t, async(e, anonReq(t, refA, "")), 30*time.Second)
	restarting(t, "held", a.w)
	// Ceiling: five holds, below the daemon's bound that an unbounded call would wait for.
	if a.at < 900*time.Millisecond || a.at > 5*time.Second {
		t.Errorf("answered after %v, want the hold of 1s", a.at)
	}
	if len(e.requests()) != 0 {
		t.Error("a held request reached the upstream")
	}
	// The wake call ends with the hold, not at the daemon's bound: its place is free.
	for deadline := time.Now().Add(5 * time.Second); e.gw.wake.inFlight() != 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the wake call outlived the hold")
		}
	}
	settle(t, g0, f0) // before the second gateway below adds its own
	// The answer is the draining project's, byte for byte.
	d := newEnv(t, &routes.File{Generation: 1, Domain: "sp.test", Projects: map[string]routes.Project{
		refA: sleepy(1, 0, []string{refA}).Projects[refA]}})
	p := d.gw.table.cur.Load().projects[refA]
	p.asleep, p.draining = false, true
	w := d.do(anonReq(t, refA, ""))
	if w.Body.String() != a.w.Body.String() || fmt.Sprint(w.Header()) != fmt.Sprint(a.w.Header()) {
		t.Errorf("held: %v %s, draining: %v %s", a.w.Header(), a.w.Body, w.Header(), w.Body)
	}
}

func TestWake_ForwardsOnlyAfterTheTableIsActive(t *testing.T) {
	var e *env
	f := sleepy(1, 0, []string{refA})
	flipIt := atomic.Bool{}
	s := &standIn{}
	s.wake = func(context.Context, string) error {
		if flipIt.Load() {
			f = flip(t, e, f, refA)
		}
		return nil // the route is said active, the table may not show it
	}
	e = wakeEnv(t, f, s)
	e.gw.wake.bound = time.Second
	restarting(t, "woken, the table still asleep", answeredIn(t, async(e, anonReq(t, refA, "")), 30*time.Second).w)
	if len(e.requests()) != 0 {
		t.Fatal("forwarded before the table showed the project active")
	}
	flipIt.Store(true) // control
	if a := answeredIn(t, async(e, anonReq(t, refA, "")), 30*time.Second); a.w.Code != 200 || len(e.requests()) != 1 {
		t.Fatalf("woken and active: %d %s, upstream %d", a.w.Code, a.w.Body, len(e.requests()))
	}
	if d := e.last(t); d.Path != "/" {
		t.Errorf("forwarded %q", d.Path)
	}
}

// A wake that returns while the table shows the project draining or stopped
// forwards nothing: the poll waits for active alone.
func TestWake_ForwardsNothingToADrainingOrStoppedEntry(t *testing.T) {
	for _, st := range []string{"draining", "stopped"} {
		var e *env
		f := sleepy(1, 0, []string{refA})
		s := &standIn{}
		s.wake = func(context.Context, string) error {
			f.Generation++
			p := f.Projects[refA]
			p.State = st
			f.Projects[refA] = p
			writeFile(t, e.path, f)
			if err := e.gw.table.Reload(); err != nil {
				t.Error(err)
			}
			return nil
		}
		e = wakeEnv(t, f, s)
		e.gw.wake.bound = time.Second
		w := answeredIn(t, async(e, anonReq(t, refA, "")), 30*time.Second).w
		restarting(t, st, w)
		if s.count(refA) != 1 || len(e.requests()) != 0 {
			t.Fatalf("%s: %d wakes, upstream saw %d", st, s.count(refA), len(e.requests()))
		}
	}
}

func TestWake_FailedWakeBacksOffTheProject(t *testing.T) {
	s := &standIn{wake: func(_ context.Context, ref string) error {
		if ref == refA {
			return wakesock.ErrFailed
		}
		return wakesock.ErrBusy
	}}
	e := wakeEnv(t, sleepy(1, 0, []string{refA, refB}), s)
	c := newClock(e)
	restarting(t, "the failed wake", e.do(anonReq(t, refA, "[2001:db8:1::1]:1")))
	for i := range 3 {
		start := time.Now()
		restarting(t, "backed off", e.do(anonReq(t, refA, fmt.Sprintf("[2001:db8:%x::1]:1", 10+i))))
		if el := time.Since(start); el > 5*time.Second {
			t.Errorf("a backed-off request answered after %v", el)
		}
		c.add(wakesock.Backoff / 4)
	}
	if n := s.count(refA); n != 1 {
		t.Fatalf("%d wakes of a backed-off project", n)
	}
	restarting(t, "another project", e.do(anonReq(t, refB, "")))
	if n := s.count(refB); n != 1 {
		t.Fatalf("another project meanwhile: %d wakes", n)
	}
	c.add(wakesock.Backoff/4 + time.Second)
	restarting(t, "after the back-off", e.do(anonReq(t, refA, "[2001:db8:20::1]:1")))
	if n := s.count(refA); n != 2 {
		t.Fatalf("after the back-off: %d wakes, want 2", n)
	}
}

// Four projects whose wakes never return hold the four places for one bound,
// then back off: a fifth is woken soon after, and the four are not asked again.
func TestWake_FourStallingProjectsDoNotStarveAFifth(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s := &standIn{wake: func(ctx context.Context, ref string) error {
		if ref == refE {
			return nil
		}
		<-release // never returns while the test looks
		return nil
	}}
	e := wakeEnv(t, sleepy(1, 0, []string{refA, refB, refC, refD, refE}), s)
	e.gw.wake.bound = wakesock.WakeBound
	start := time.Now()
	var held []<-chan answer
	for _, ref := range []string{refA, refB, refC, refD} {
		held = append(held, async(e, anonReq(t, ref, "")))
		s.waitWakes(t, ref, 1)
	}
	restarting(t, "a fifth at once", e.do(anonReq(t, refE, "")))
	if s.count(refE) != 0 {
		t.Fatal("a fifth sent over the cap")
	}
	for _, c := range held {
		restarting(t, "stalled", answeredIn(t, c, wakesock.WakeBound+30*time.Second).w)
	}
	e.gw.wake.bound = time.Second // the fifth's table stays asleep
	restarting(t, "a fifth", answeredIn(t, async(e, anonReq(t, refE, "")), 30*time.Second).w)
	if el := time.Since(start); s.count(refE) != 1 || el > wakesock.WakeBound+5*time.Second {
		t.Fatalf("a fifth: %d wakes, %v after the four stalled", s.count(refE), el)
	}
	for _, ref := range []string{refA, refB, refC, refD} {
		restarting(t, "stalled, again", e.do(anonReq(t, ref, "")))
	}
	if n := s.count(""); n != 5 {
		t.Fatalf("%d wakes: the stalled projects were asked again", n)
	}
}

func TestWake_BusyStartsNoBackoff(t *testing.T) {
	s := &standIn{wake: func(context.Context, string) error { return wakesock.ErrBusy }}
	e := wakeEnv(t, sleepy(1, 0, []string{refA}), s)
	restarting(t, "busy", e.do(anonReq(t, refA, "")))
	restarting(t, "busy again", e.do(anonReq(t, refA, "")))
	if n := s.count(refA); n != 2 {
		t.Fatalf("after a busy answer: %d wakes, want 2", n)
	}
}

// A wake that runs out of the hold is a failure: it backs off too.
func TestWake_UnansweredWakeBacksOff(t *testing.T) {
	s := &standIn{wake: func(ctx context.Context, _ string) error { <-ctx.Done(); return nil }}
	e := wakeEnv(t, sleepy(1, 0, []string{refA}), s)
	e.gw.wake.bound = 500 * time.Millisecond
	restarting(t, "unanswered", answeredIn(t, async(e, anonReq(t, refA, "")), 30*time.Second).w)
	restarting(t, "after", e.do(anonReq(t, refA, "")))
	if n := s.count(refA); n != 1 {
		t.Fatalf("%d wakes after an unanswered one", n)
	}
}

func TestIdle_ReportsOnlyQuietActiveProjects(t *testing.T) {
	s := &standIn{}
	// A quiet and active; B active with a request just now; C asleep; D active
	// with a request in flight; E draining.
	f := sleepy(1, 60, []string{refC}, refA, refB, refD, refE)
	p := f.Projects[refE]
	p.State = "draining"
	f.Projects[refE] = p
	e := wakeEnv(t, f, s)
	c := newClock(e)
	e.gw.reportIdle(context.Background()) // the first report: every active project is quiet from now
	c.add(61 * time.Second)
	if w := e.do(anonReq(t, refB, "")); w.Code != 200 {
		t.Fatalf("B: %d", w.Code)
	}
	if !e.gw.acquireProject(refD) {
		t.Fatal("D's slot")
	}
	e.gw.reportIdle(context.Background())
	s.mu.Lock()
	got := fmt.Sprint(s.idles)
	s.mu.Unlock()
	if got != "[["+refA+"]]" {
		t.Fatalf("reported %s, want only A", got)
	}
	// Control: once D's request ends and B is quiet too, both are reported.
	e.gw.releaseProject(refD)
	c.add(61 * time.Second)
	e.gw.reportIdle(context.Background())
	s.mu.Lock()
	got = fmt.Sprint(s.idles[1:])
	s.mu.Unlock()
	if got != "[["+strings.Join([]string{refA, refB, refD}, " ")+"]]" {
		t.Fatalf("reported %s, want A, B and D", got)
	}
	// With idle_stop_s 0 nothing is reported.
	f.IdleStopS = 0
	flip(t, e, f)
	e.gw.reportIdle(context.Background())
	if s.mu.Lock(); len(s.idles) != 2 {
		t.Errorf("idle_stop_s 0 reported %v", s.idles[2:])
	}
	s.mu.Unlock()
}

func (c *clock) now() time.Time { return time.Unix(0, c.ns.Load()) }

func TestIdle_StopPeriodBounded(t *testing.T) {
	f := sleepy(1, 86400, nil, refA)
	if _, err := f.Marshal(); err != nil {
		t.Errorf("86400: %v", err)
	}
	f.IdleStopS = 86401
	if _, err := f.Marshal(); err == nil {
		t.Error("86401 accepted")
	}
}

func TestNoSocket_AsleepAnswersProjectRestarting(t *testing.T) {
	e := newEnv(t, func() *routes.File { f := sleepy(1, 60, []string{refA}, refB); return &f }())
	path := filepath.Join(t.TempDir(), wakesock.SocketName)
	e.gw.SetWake(wakesock.NewClient(path))
	g0, f0 := runtime.NumGoroutine(), openFDs(t)
	start := time.Now()
	restarting(t, "no socket", e.do(anonReq(t, refA, "")))
	if el := time.Since(start); el > 5*time.Second || len(e.dialed) != 0 {
		t.Errorf("no socket: answered after %v, dialled %v", el, e.dialed)
	}
	e.gw.reportIdle(context.Background())
	if _, err := os.Lstat(path); err == nil {
		t.Error("something was created at the socket path")
	}
	settle(t, g0, f0)
	// A gateway without a client answers the same; an active project is served.
	n := newEnv(t, func() *routes.File { f := sleepy(1, 60, []string{refA}, refB); return &f }())
	restarting(t, "no client", n.do(anonReq(t, refA, "")))
	n.expect(t, "active", anonReq(t, refB, ""), 200, "")
}

func settle(t *testing.T, g0, f0 int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		g, f := runtime.NumGoroutine(), openFDs(t)
		if g <= g0 && f <= f0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines %d (was %d), descriptors %d (was %d)", g, g0, f, f0)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func openFDs(t *testing.T) int {
	t.Helper()
	d, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	return len(d)
}

// joined is how many requests wait on ref's wake besides the one that asked.
func (k *waker) joined(ref string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	if f := k.flights[ref]; f != nil {
		return f.joined
	}
	return 0
}

func (k *waker) inFlight() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.flights)
}

// A page's burst after a sleep: 30 keyed requests at once from one address,
// with the gateway's own figures, share one wake and are all served.
func TestWake_BurstFromOneAddressSharesOneWake(t *testing.T) {
	release := make(chan struct{})
	var e *env
	f := sleepy(1, 0, []string{refA})
	s := &standIn{}
	s.wake = func(ctx context.Context, ref string) error {
		select {
		case <-release:
		case <-ctx.Done():
			return wakesock.ErrFailed
		}
		f = flip(t, e, f, ref)
		return nil
	}
	e = wakeEnv(t, f, s)
	e.gw.wake.bound = 0 // the default hold
	const n = 30
	var answers []<-chan answer
	for range n {
		answers = append(answers, async(e, anonReq(t, refA, "")))
	}
	s.waitWakes(t, refA, 1)
	for deadline := time.Now().Add(9 * time.Second); e.gw.wake.joined(refA) < n-1; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d requests joined, want %d", e.gw.wake.joined(refA), n-1)
		}
	}
	close(release)
	codes := map[int]int{}
	for _, c := range answers {
		codes[answeredIn(t, c, 30*time.Second).w.Code]++
	}
	if codes[200] != n || s.count(refA) != 1 {
		t.Fatalf("answers %v, %d wakes; want %d × 200 and one wake", codes, s.count(refA), n)
	}
}

// Requests refused for the node cap ask for no wake and spend none of their
// source's six.
func TestWake_RefusedRequestsSpendNoneOfTheSourcesWakes(t *testing.T) {
	release := make(chan struct{})
	s := &standIn{wake: func(ctx context.Context, ref string) error {
		if ref == refE {
			return wakesock.ErrBusy
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return wakesock.ErrBusy
	}}
	e := wakeEnv(t, sleepy(1, 0, []string{refA, refB, refC, refD, refE}), s)
	var held []<-chan answer
	for _, ref := range []string{refA, refB, refC, refD} {
		held = append(held, async(e, anonReq(t, ref, "")))
		s.waitWakes(t, ref, 1)
	}
	const src = "[2001:db8:7::1]:1"
	for range 10 {
		restarting(t, "over the node cap", e.do(anonReq(t, refE, src)))
	}
	close(release)
	for _, c := range held {
		answeredIn(t, c, 30*time.Second)
	}
	for i := range 6 {
		restarting(t, "a wake asked", e.do(anonReq(t, refE, src)))
		if n := s.count(refE); n != i+1 {
			t.Fatalf("wake %d of the source: %d sent", i+1, n)
		}
	}
	restarting(t, "the seventh asked", e.do(anonReq(t, refE, src)))
	if n := s.count(refE); n != 6 {
		t.Fatalf("the seventh wake of a source in a minute was sent (%d)", n)
	}
}

// The requests held on one wake are at most the project's in-flight cap, so
// the held handlers are at most 4 × 128 on the gateway: four wakes, each
// with 129 requests from one address, hold 512 and refuse 4 at once.
func TestWake_HeldRequestsAtMostTheProjectCapEach(t *testing.T) {
	release := make(chan struct{})
	refs := []string{refA, refB, refC, refD}
	f := sleepy(1, 0, refs)
	var e *env
	var fmu sync.Mutex
	s := &standIn{}
	s.wake = func(ctx context.Context, ref string) error {
		select {
		case <-release:
		case <-ctx.Done():
			return wakesock.ErrFailed
		}
		fmu.Lock()
		f = flip(t, e, f, ref)
		fmu.Unlock()
		return nil
	}
	e = wakeEnv(t, f, s)
	if e.gw.projectCap != maxProjectInFlight || maxProjectInFlight != 128 || maxWakes != 4 {
		t.Fatalf("figures %d %d %d", e.gw.projectCap, maxProjectInFlight, maxWakes)
	}
	const per = maxProjectInFlight + 1
	var answers []<-chan answer
	for _, ref := range refs {
		for range per {
			answers = append(answers, async(e, anonReq(t, ref, "")))
		}
	}
	refused := 0
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		held := 0
		for _, ref := range refs {
			held += e.gw.wake.joined(ref) + 1
		}
		if held == maxWakes*maxProjectInFlight {
			break
		}
		if held > maxWakes*maxProjectInFlight || time.Now().After(deadline) {
			t.Fatalf("%d requests held, want %d", held, maxWakes*maxProjectInFlight)
		}
	}
	// The four over the cap are answered before the wakes end: only then are
	// the places freed, which would let a late one in.
	got := make([]*answer, len(answers))
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		n := 0
		for i, c := range answers {
			if got[i] == nil {
				select {
				case a := <-c:
					got[i] = &a
				default:
				}
			}
			if got[i] != nil {
				n++
			}
		}
		if n == len(refs) {
			break
		}
		if n > len(refs) || time.Now().After(deadline) {
			t.Fatalf("%d answered while the wakes were held, want %d", n, len(refs))
		}
	}
	close(release)
	for i, c := range answers {
		if got[i] == nil {
			a := answeredIn(t, c, 60*time.Second)
			got[i] = &a
		}
		switch w := got[i].w; w.Code {
		case 200:
		case 503:
			restarting(t, "over the project cap", w)
			refused++
		default:
			t.Fatalf("answer %d %s", w.Code, w.Body)
		}
	}
	if refused != len(refs) || s.count("") != len(refs) {
		t.Fatalf("%d refused, %d wakes; want %d each", refused, s.count(""), len(refs))
	}
}

// The idle report is sent in pieces the listener accepts: 1,025 quiet
// projects arrive whole, as 1,024 and 1.
func TestIdle_ReportInPiecesTheListenerAccepts(t *testing.T) {
	s := &standIn{}
	var refs []string
	for i := range wakesock.MaxIdleRefs + 1 {
		refs = append(refs, fmt.Sprintf("%020d", i))
	}
	e := wakeEnv(t, sleepy(1, 60, nil, refs...), s)
	c := newClock(e)
	e.gw.reportIdle(context.Background())
	c.add(61 * time.Second)
	e.gw.reportIdle(context.Background())
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.idles) != 2 || len(s.idles[0]) != wakesock.MaxIdleRefs || len(s.idles[1]) != 1 {
		t.Fatalf("%d reports received", len(s.idles))
	}
}
