package gateway

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/wakesock"
)

// Every refusal before the wake, whatever its cause, wakes nothing: a key of
// another project, an expired key, a key of the wrong class, a bearer without
// a listed audience, an upgrade, a preflight without a key, HTTP/1.0.
func TestWake_EveryEarlierRefusalSendsNothing(t *testing.T) {
	s := &standIn{wake: func(context.Context, string) error { return wakesock.ErrBusy }}
	f := sleepy(1, 0, []string{refA})
	p := f.Projects[refA]
	p.Aud = []string{"app"}
	f.Projects[refA] = p
	e := wakeEnv(t, f, s)
	a, b, _ := keys()
	expired, err := jwtx.Sign(a.anon.priv, a.anon.kid, map[string]any{"role": "anon", "exp": time.Now().Unix() - 3600})
	if err != nil {
		t.Fatal(err)
	}
	anon := a.anon.token(t, "anon")
	upgrade := anonReq(t, refA, "")
	upgrade.Header.Set("Connection", "Upgrade")
	upgrade.Header.Set("Upgrade", "websocket")
	wrongAud := anonReq(t, refA, "")
	wrongAud.Header.Set("Authorization", "Bearer "+audToken(t, a.iss, "other"))
	old := anonReq(t, refA, "")
	old.ProtoMajor, old.ProtoMinor = 1, 0
	for _, c := range []struct {
		name   string
		r      func() *http.Request
		status int
		code   string
	}{
		{"another project's key", func() *http.Request { return withKey(req("GET", hostA, "/rest/v1/", nil), b.anon.token(t, "anon")) }, 401, "invalid_apikey"},
		{"an expired key", func() *http.Request { return withKey(req("GET", hostA, "/rest/v1/", nil), expired) }, 401, "invalid_apikey"},
		{"an issuer key as apikey", func() *http.Request { return withKey(req("GET", hostA, "/rest/v1/", nil), a.iss.token(t, "anon")) }, 401, "invalid_apikey"},
		{"a bearer without a listed audience", func() *http.Request { return wrongAud }, 401, "invalid_token"},
		{"an upgrade with a key", func() *http.Request { return upgrade }, 400, "upgrade_not_supported"},
		{"a preflight without a key", func() *http.Request { return req("OPTIONS", hostA, "/rest/v1/t", nil) }, 401, "no_apikey"},
		{"HTTP/1.0 with a key", func() *http.Request { return old }, 505, "http_version_not_supported"},
	} {
		e.expect(t, c.name, c.r(), c.status, c.code)
	}
	if n := s.count(""); n != 0 {
		t.Fatalf("refused requests sent %d wakes", n)
	}
	// Control: the project's key and a listed audience ask for one.
	ok := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	ok.Header.Set("Authorization", "Bearer "+audToken(t, a.iss, "app"))
	restarting(t, "control", e.do(ok))
	if n := s.count(refA); n != 1 {
		t.Fatalf("control: %d wakes, want 1", n)
	}
}

// A project that turns active without a request through this gateway (an
// operator's start, a new project, a wake by another path) is not idle at
// once: its quiet period starts when the gateway first sees it active.
// Red until reportIdle stops dating unseen refs from the gateway's start.
func TestIdle_NewlyActiveProjectIsNotIdleAtOnce(t *testing.T) {
	s := &standIn{}
	f := sleepy(1, 60, []string{refA})
	e := wakeEnv(t, f, s)
	c := newClock(e)
	c.add(time.Hour) // the gateway has run an hour
	e.gw.reportIdle(context.Background())
	f = flip(t, e, f, refA) // A is active again, no request has come
	f.Generation++
	f.Projects[refB] = sleepy(1, 60, nil, refB).Projects[refB] // a new project
	writeFile(t, e.path, f)
	if err := e.gw.table.Reload(); err != nil {
		t.Fatal(err)
	}
	e.gw.reportIdle(context.Background())
	s.mu.Lock()
	got := len(s.idles)
	s.mu.Unlock()
	if got != 0 {
		t.Fatalf("reported %v at the moment the projects turned active", s.idles)
	}
	// Control: quiet for the period, both are reported.
	c.add(61 * time.Second)
	e.gw.reportIdle(context.Background())
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.idles) != 1 || len(s.idles[0]) != 2 {
		t.Fatalf("after the period: %v, want A and B", s.idles)
	}
}

// The wake does not end with the request that asked for it: a client that
// asks and goes away at once cannot fail the wake for those who joined it.
func TestWake_AskerGoneDoesNotEndTheWake(t *testing.T) {
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
	ctx, cancel := context.WithCancel(context.Background())
	asker := async(e, anonReq(t, refA, "[2001:db8:1::1]:1").WithContext(ctx))
	s.waitWakes(t, refA, 1)
	joiner := async(e, anonReq(t, refA, "[2001:db8:2::1]:1"))
	for deadline := time.Now().Add(30 * time.Second); e.gw.wake.joined(refA) < 1; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the second request never joined")
		}
	}
	cancel() // the asker is gone
	time.Sleep(100 * time.Millisecond)
	close(release)
	if a := answeredIn(t, joiner, 30*time.Second); a.w.Code != 200 {
		t.Fatalf("the joiner after the asker left: %d %s", a.w.Code, a.w.Body)
	}
	answeredIn(t, asker, 30*time.Second)
	if n := s.count(refA); n != 1 {
		t.Fatalf("%d wakes", n)
	}
}

// The per-source record is pruned: sources quiet for the window are dropped
// as new ones arrive (here once the map has doubled), so it follows the recent ones.
func TestWake_PerSourceRecordIsPruned(t *testing.T) {
	s := &standIn{wake: func(context.Context, string) error { return wakesock.ErrBusy }}
	e := wakeEnv(t, sleepy(1, 0, []string{refA}), s)
	c := newClock(e)
	for i := range 300 {
		e.do(anonReq(t, refA, fmt.Sprintf("[2001:db8:%x::1]:1", i)))
	}
	c.add(2 * time.Minute)
	for i := range 300 {
		e.do(anonReq(t, refA, fmt.Sprintf("[2001:db9:%x::1]:1", i)))
	}
	e.gw.wake.mu.Lock()
	n := len(e.gw.wake.asks)
	e.gw.wake.mu.Unlock()
	if n > 450 {
		t.Fatalf("%d sources recorded, want the old 300 dropped", n)
	}
	if n < 300 { // control: the recent ones are kept
		t.Fatalf("%d sources recorded, the recent 300 lost", n)
	}
}
