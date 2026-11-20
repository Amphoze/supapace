package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashtok"
)

// newFwdEnv is newDashEnv with the real forwarder in the forward seam.
func newFwdEnv(t *testing.T) *dashEnv {
	t.Helper()
	e := newDashEnv(t, active(), true)
	dashForward = forwardDash
	return e
}

// setLimits changes the bounds table until the test ends; call it before the
// transport is made (studioAt) when it changes the transport's members.
func setLimits(t *testing.T, f func(*dashcfg.LimitSet)) {
	t.Helper()
	old := dashcfg.Limits
	t.Cleanup(func() { stopServers(t); dashcfg.Limits = old })
	f(&dashcfg.Limits)
}

// studioAt gives the forwarder a fresh transport whose every dial lands on
// addr, until the test ends.
func studioAt(t *testing.T, addr string) *http.Transport {
	t.Helper()
	old := dashTransport
	tr := newDashTransport()
	tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	dashTransport = tr
	t.Cleanup(func() { stopServers(t); tr.CloseIdleConnections(); dashTransport = old })
	return tr
}

type studioReq struct {
	Method, URI, Host string
	Header            http.Header
	Body              []byte
}

// recStudio is a stand-in Studio that records every request it receives in
// full, then runs answer (or answers 200 "studio").
type recStudio struct {
	mu  sync.Mutex
	got []studioReq
}

func recordStudio(t *testing.T, answer http.HandlerFunc) *recStudio {
	t.Helper()
	s := &recStudio{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.got = append(s.got, studioReq{r.Method, r.RequestURI, r.Host, r.Header.Clone(), b})
		s.mu.Unlock()
		if answer != nil {
			answer(w, r)
			return
		}
		io.WriteString(w, "studio")
	}))
	t.Cleanup(srv.Close)
	studioAt(t, srv.Listener.Addr().String())
	return s
}

func (s *recStudio) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

func (s *recStudio) last(t *testing.T) studioReq {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.got) == 0 {
		t.Fatal("Studio saw nothing")
	}
	return s.got[len(s.got)-1]
}

// rawStudio answers every request on a loopback listener with f once the
// request (and its body) is read; it returns the count of connections.
func rawStudio(t *testing.T, f func(net.Conn, *http.Request)) *atomic.Int32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	n := new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					r, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					io.Copy(io.Discard, r.Body)
					f(c, r)
				}
			}()
		}
	}()
	studioAt(t, ln.Addr().String())
	return n
}

func (e *dashEnv) owner(t *testing.T, method, target string) *http.Request {
	return e.as(t, rawReq(method, dhostA, target), refA, subOwnerA)
}

func (e *dashEnv) cookie(t *testing.T, sub string) string {
	return "__Host-sp-session=" + e.session(t, refA, issuer, sub, time.Now().Unix()-10, 3600)
}

// serveDashTLS serves e's gateway over TLS with the real server
// configuration and both certificates.
func serveDashTLS(t *testing.T, e *dashEnv) string {
	t.Helper()
	dir := t.TempDir()
	pairPEM(t, dir, "*.sp.test")
	first, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(e.gw)
	srv.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLSConfig.Certificates = []tls.Certificate{first}
	srv.TLSConfig.GetCertificate = e.gw.Certificate
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	goServe(t, srv, ln, true)
	return ln.Addr().String()
}

// dashClient is an HTTPS client to addr for project A's dashboard host.
func dashClient(t *testing.T, addr string, h2 bool) *http.Client {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: dhostA}, ForceAttemptHTTP2: h2,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

func (e *dashEnv) wireReq(t *testing.T, ctx context.Context, method, target string, body io.Reader) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(ctx, method, "https://"+dhostA+target, body)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Cookie", e.cookie(t, subOwnerA))
	return r
}

// h2dash opens a raw HTTP/2 connection to addr with the TLS server name of
// project A's dashboard host (as h2open does for the project API).
func h2dash(t *testing.T, addr string) *h2raw {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: dhostA, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	h := &h2raw{c: c, frames: make(chan h2f, 1024)}
	io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	h.frame(4, 0, 0, nil)
	br := bufio.NewReader(c)
	read := func() (h2f, error) {
		hd := make([]byte, 9)
		if _, err := io.ReadFull(br, hd); err != nil {
			return h2f{}, err
		}
		p := make([]byte, int(hd[0])<<16|int(hd[1])<<8|int(hd[2]))
		if _, err := io.ReadFull(br, p); err != nil {
			return h2f{}, err
		}
		return h2f{hd[3], hd[4], binary.BigEndian.Uint32(hd[5:]) & 0x7fffffff, p}, nil
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	f, err := read()
	if err != nil || f.typ != 4 || f.flags&1 != 0 {
		t.Fatalf("server preface: type %d flags %d: %v", f.typ, f.flags, err)
	}
	c.SetReadDeadline(time.Time{})
	h.frame(4, 1, 0, nil)
	h.frames <- f
	go func() {
		defer close(h.frames)
		for {
			f, err := read()
			if err != nil {
				return
			}
			h.frames <- f
		}
	}()
	return h
}

func (e *dashEnv) h2Fields(t *testing.T, path string, extra ...[2]string) [][2]string {
	return append([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", dhostA}, {":path", path},
		{"cookie", e.cookie(t, subOwnerA)}}, extra...)
}

func dashIdle(e *dashEnv) bool {
	e.d.mu.Lock()
	defer e.d.mu.Unlock()
	return len(e.gw.inflight) == 0 && len(e.d.slots) == 0 && len(e.d.byRef) == 0
}

// TestDashProxy_DeadlinesPastTheServersTimeouts_H1AndH2: with the gateway's
// real server configuration (60 s read and write timeouts), a Studio that
// answers its header after 65 s and then trickles its body for 25 s reaches
// the client whole, over HTTP/1.1 and HTTP/2: the forwarder moves its
// response's write deadline and its request's read deadline past the
// server's. Control: the same server and Studio behind a handler that moves
// no deadline cut the response at the server's 60 s on both protocols: HTTP/2
// resets the stream at 60 s; HTTP/1.1 fails the first write after 60 s,
// when the header arrives (the read timeout no longer runs once the request
// is read, so it does not end the wait). And a request body that takes 65 s
// to arrive reaches Studio whole: the read deadline is moved at entry.
// Only test of the package, with TestProjectAPI_TimeoutsUnchanged, to run in
// parallel: no other may change the forwarder's globals.
func TestDashProxy_DeadlinesPastTheServersTimeouts_H1AndH2(t *testing.T) {
	t.Parallel()
	const headerAfter, chunks = 65 * time.Second, 26 // one chunk a second: 25 s of body
	var want strings.Builder
	for i := range chunks {
		fmt.Fprintf(&want, "%02d\n", i)
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/body" {
			if b, err := io.ReadAll(r.Body); err == nil {
				fmt.Fprintf(w, "%d", len(b))
			}
			return
		}
		select {
		case <-time.After(headerAfter):
		case <-r.Context().Done():
			return
		}
		rc := http.NewResponseController(w)
		w.WriteHeader(200)
		rc.Flush()
		for i := range chunks {
			if i > 0 {
				select {
				case <-time.After(time.Second):
				case <-r.Context().Done():
					return
				}
			}
			fmt.Fprintf(w, "%02d\n", i)
			rc.Flush()
		}
	}))
	t.Cleanup(up.Close)
	e := newFwdEnv(t)
	studioAt(t, up.Listener.Addr().String())
	gw := serveDashTLS(t, e)

	// The control: the server as configured, a proxy that sets no deadline.
	ctl := NewServer(&httputil.ReverseProxy{Transport: &http.Transport{}, Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(&url.URL{Scheme: "http", Host: up.Listener.Addr().String()})
	}})
	ctl.ErrorLog = log.New(io.Discard, "", 0)
	ctl.TLSConfig.Certificates = []tls.Certificate{testCert(t)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go ctl.ServeTLS(ln, "", "")
	t.Cleanup(func() { ctl.Close() })

	type result struct {
		body    string
		err     error
		elapsed time.Duration
	}
	get := func(c *http.Client, r *http.Request) result {
		start := time.Now()
		res, err := c.Do(r)
		var b []byte
		if err == nil {
			b, err = io.ReadAll(res.Body)
			res.Body.Close()
			if err == nil && res.StatusCode != 200 {
				err = fmt.Errorf("status %d", res.StatusCode)
			}
		}
		return result{string(b), err, time.Since(start)}
	}
	results := make(map[string]result)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h2 := range []bool{false, true} {
		wg.Add(3)
		go func() { // a body that takes 65 s to arrive
			defer wg.Done()
			pr, pw := io.Pipe()
			go func() {
				for range 66 { // the last byte at 65 s
					if _, err := io.WriteString(pw, "b"); err != nil {
						return
					}
					time.Sleep(time.Second)
				}
				pw.Close()
			}()
			r := get(dashClient(t, gw, h2), e.wireReq(t, context.Background(), "POST", "/body", pr))
			pr.Close()
			mu.Lock()
			results["body h2="+strconv.FormatBool(h2)] = r
			mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			r := get(dashClient(t, gw, h2), e.wireReq(t, context.Background(), "GET", "/slow", nil))
			mu.Lock()
			results["gateway h2="+strconv.FormatBool(h2)] = r
			mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			rq, _ := http.NewRequest("GET", "https://"+hostA+"/slow", nil)
			r := get(clientFor(t, ln.Addr().String(), h2), rq)
			mu.Lock()
			results["control h2="+strconv.FormatBool(h2)] = r
			mu.Unlock()
		}()
	}
	wg.Wait()
	for name, r := range results {
		t.Logf("%s: %v after %v, %d bytes", name, r.err, r.elapsed.Round(time.Second), len(r.body))
		if strings.HasPrefix(name, "gateway") && (r.err != nil || r.body != want.String()) {
			t.Errorf("%s: not whole: %v, %q", name, r.err, r.body)
		}
		if strings.HasPrefix(name, "body") && (r.err != nil || r.body != "66") {
			t.Errorf("%s: a slow body: %v, %q", name, r.err, r.body)
		}
		if strings.HasPrefix(name, "control") && (r.err == nil || r.elapsed < 59*time.Second) {
			t.Errorf("control %s: not cut at 60 s: %v after %v", name, r.err, r.elapsed)
		}
	}
}

// TestDashProxy_HeaderWait_504: Studio that sends no header within row 2 is
// 504 upstream_timeout, with the dashboard's headers; one that answers in
// time is forwarded.
func TestDashProxy_HeaderWait_504(t *testing.T) {
	e := newFwdEnv(t)
	setLimits(t, func(l *dashcfg.LimitSet) { l.StudioHeaderMS = 300 })
	gone := make(chan struct{})
	t.Cleanup(func() { close(gone) })
	recordStudio(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			select {
			case <-gone:
			case <-r.Context().Done():
			}
		}
	})
	start := time.Now()
	e.dexpect(t, "no header", e.owner(t, "GET", "/slow"), 504, "upstream_timeout")
	if d := time.Since(start); d < 300*time.Millisecond || d > 20*time.Second {
		t.Errorf("504 after %v, want the header wait of 300 ms", d)
	}
	if w := e.do(e.owner(t, "GET", "/fast")); w.Code != 200 {
		t.Errorf("an answer in time: %d", w.Code)
	}
	eventually(t, func() bool { return dashIdle(e) }, "slots not returned")
}

// TestDashProxy_TransferCutAfterRow1: once Studio's header has arrived the
// body must be handed over within row 1: past it the connection is closed
// (HTTP/1.1) or the stream reset (HTTP/2). Control: with the default row 1
// the same body arrives whole.
func TestDashProxy_TransferCutAfterRow1(t *testing.T) {
	e := newFwdEnv(t)
	recordStudio(t, func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		w.WriteHeader(200)
		rc.Flush()
		for i := range 20 {
			select {
			case <-time.After(100 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			fmt.Fprintf(w, "%02d", i)
			rc.Flush()
		}
	})
	addr := serveDashTLS(t, e)
	setLimits(t, func(*dashcfg.LimitSet) {}) // restored at the end
	get := func(h2 bool) (string, time.Duration, error) {
		start := time.Now()
		res, err := dashClient(t, addr, h2).Do(e.wireReq(t, context.Background(), "GET", "/x", nil))
		if err != nil {
			return "", time.Since(start), err
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		return string(b), time.Since(start), err
	}
	for _, h2 := range []bool{false, true} {
		dashcfg.Limits.TransferMS = 500
		b, d, err := get(h2)
		dashcfg.Limits.TransferMS = 30000
		t.Logf("h2=%v: row 1 of 500 ms: %d bytes, %v after %v", h2, len(b), err, d)
		// HTTP/1.1: the connection is cut, over TLS mid-record (a broken record
		// or an early end); HTTP/2: the stream is reset, the connection lives.
		cut := err != nil && h2 == strings.Contains(err.Error(), "stream error")
		if !cut || len(b) >= 40 || d > 1900*time.Millisecond {
			t.Errorf("h2=%v: not cut at row 1: %d bytes, %v after %v", h2, len(b), err, d)
		}
		if b, _, err := get(h2); err != nil || len(b) != 40 {
			t.Errorf("h2=%v control: %d bytes, %v", h2, len(b), err)
		}
	}
	eventually(t, func() bool { return dashIdle(e) }, "slots not returned")
}

// TestDashProxy_RemovesAndSets: what Studio receives. Removed in any letter
// case: the platform's cookies, credentials, forwarding headers and the
// headers by which a request restates its method or path; set: the
// forwarding headers and the assertion, each once; the rest unchanged.
func TestDashProxy_RemovesAndSets(t *testing.T) {
	e := newFwdEnv(t)
	rec := recordStudio(t, nil)
	r := e.owner(t, "POST", "/x/y?q=1")
	r.Body, r.ContentLength = io.NopCloser(strings.NewReader("hello")), 5
	r.Header["Cookie"][0] += "; a=1; __Host-sp-login-AAECAwQFBgc=r; __HOST-SP-x=1;__host-sp-y=2"
	r.Header.Add("Cookie", "b=2; __Host-sp-login-x=1")
	removed := map[string]string{
		"Authorization": "Bearer x", "apikey": "k", "X-Connection-Encrypted": "1", "Forwarded": "for=198.51.100.1",
		"X-Forwarded-For": "198.51.100.1", "x-forwarded-host": "other.test", "X-Forwarded-Proto": "http",
		"X-Forwarded-Port": "80", "X-Forwarded-Prefix": "/p", "X-Real-IP": "198.51.100.1",
		"x-supapace-assertion": "v1.forged", "X-HTTP-Method-Override": "DELETE", "x-http-method": "PUT",
		"X-METHOD-OVERRIDE": "PATCH", "x-original-url": "/api/ai", "X-Rewrite-Url": "/api/mcp",
	}
	for k, v := range removed {
		r.Header[k] = []string{v} // as sent: not canonicalised
	}
	passing := map[string]string{"Origin": "https://" + dhostA, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
		"Sec-Fetch-Dest": "empty", "Content-Type": "application/json", "X-Custom": "kept", "Accept-Encoding": "gzip"}
	for k, v := range passing {
		r.Header.Set(k, v)
	}
	if w := e.do(r); w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	got := rec.last(t)
	for k := range removed {
		for gk, gv := range got.Header {
			if strings.EqualFold(gk, k) && !strings.EqualFold(k, "X-Forwarded-For") && !strings.EqualFold(k, "X-Forwarded-Host") &&
				!strings.EqualFold(k, "X-Forwarded-Proto") && !strings.EqualFold(k, "X-Supapace-Assertion") {
				t.Errorf("%s reached Studio: %q", gk, gv)
			}
		}
	}
	for k, want := range map[string]string{"X-Forwarded-For": peerIP, "X-Forwarded-Host": dhostA, "X-Forwarded-Proto": "https",
		"Cookie": "a=1; b=2"} {
		if v := got.Header.Values(k); len(v) != 1 || v[0] != want {
			t.Errorf("%s: %q, want %q", k, v, want)
		}
	}
	if v := got.Header.Values("X-Supapace-Assertion"); len(v) != 1 || v[0] == "v1.forged" {
		t.Errorf("assertion: %q", v)
	}
	for k, v := range passing {
		if got.Header.Get(k) != v {
			t.Errorf("%s: %q, want %q", k, got.Header.Get(k), v)
		}
	}
	if got.Host != dhostA || got.Method != "POST" || got.URI != "/x/y?q=1" || string(got.Body) != "hello" {
		t.Errorf("Studio saw %s %s host %s body %q", got.Method, got.URI, got.Host, got.Body)
	}
	// Control: without any cookie of the platform's names the Cookie field is
	// the client's.
	if s := stripCookiesOf("a=1; b=2"); s != "a=1; b=2" {
		t.Errorf("plain cookies: %q", s)
	}
	if s := stripCookiesOf("__Host-sp-session=x"); s != "<none>" {
		t.Errorf("only the session: %q", s)
	}
}

func stripCookiesOf(v string) string {
	h := http.Header{"Cookie": {v}}
	stripPlatformCookies(h)
	if len(h["Cookie"]) == 0 {
		return "<none>"
	}
	return strings.Join(h["Cookie"], "|")
}

// TestDashProxy_AssertionVerifiesAndCarriesThePurpose: the assertion verifies
// under the gateway's key for this node and carries the principal, the
// project, the role and the purpose, for 30 s.
func TestDashProxy_AssertionVerifiesAndCarriesThePurpose(t *testing.T) {
	e := newFwdEnv(t)
	rec := recordStudio(t, nil)
	pub := e.priv.Public().(ed25519.PublicKey)
	keys := "/api/v1/projects/" + refA + "/api-keys"
	for _, c := range []struct {
		sub, target, role, purpose string
	}{
		{subOwnerA, keys + "?reveal=true", "owner", "reveal"},
		{subOwnerA, keys + "/k?reveal=true", "owner", "reveal"},
		{subOwnerA, keys, "owner", ""},
		{subOwnerA, "/x", "owner", ""},
		{subDevA, keys + "?reveal=true", "developer", ""},
		{subROA, "/x", "read_only", ""},
	} {
		w := e.do(e.as(t, rawReq("GET", dhostA, c.target), refA, c.sub))
		if w.Code != 200 {
			t.Fatalf("%s %s: %d", c.sub, c.target, w.Code)
		}
		tok := rec.last(t).Header.Get("X-Supapace-Assertion")
		now := time.Now()
		a, err := dashtok.VerifyAssertion(pub, tok, "local", now)
		if err != nil {
			t.Fatalf("%s %s: %v", c.sub, c.target, err)
		}
		want := dashtok.Assertion{Node: "local", Iss: issuer, Sub: c.sub, Name: "N", Ref: refA, Role: c.role, Purpose: c.purpose,
			Iat: a.Iat, Exp: a.Iat + 30}
		if a != want || a.Iat > now.Unix() || a.Iat < now.Unix()-5 {
			t.Errorf("%s %s: %+v, want %+v", c.sub, c.target, a, want)
		}
		if _, err := dashtok.VerifyAssertion(pub, tok, "other", now); !errors.Is(err, dashtok.ErrNode) {
			t.Errorf("another node accepted the assertion: %v", err)
		}
	}
}

// TestDashProxy_CompressesNothing: on an API path, in any spelling,
// Accept-Encoding is removed; on a public file it passes; the transport adds
// none of its own and an encoded answer reaches the client as Studio sent it.
func TestDashProxy_CompressesNothing(t *testing.T) {
	e := newFwdEnv(t)
	gz := []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xffencoded")
	rec := recordStudio(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gz)
	})
	for _, c := range []struct {
		target, sent, want string
	}{
		{"/api/x", "gzip, br", ""}, {"/API/x", "gzip", ""}, {"/Api", "gzip", ""}, {"/api", "gzip", ""},
		{"/x.js", "gzip, br", "gzip, br"}, {"/apix", "gzip", "gzip"}, {"/x.js", "", ""},
	} {
		r := e.owner(t, "GET", c.target)
		if c.sent != "" {
			r.Header.Set("Accept-Encoding", c.sent)
		}
		w := e.do(r)
		got := rec.last(t).Header.Values("Accept-Encoding")
		if strings.Join(got, ",") != c.want || len(got) > 1 {
			t.Errorf("%s with %q: Studio got %q, want %q", c.target, c.sent, got, c.want)
		}
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), gz) || w.Header().Get("Content-Encoding") != "gzip" {
			t.Errorf("%s: %d %q %v: the encoded answer changed", c.target, w.Code, w.Body, w.Header())
		}
	}
}

// TestDashProxy_ResponseHeaderBound_502: a response header above 32 KiB is
// 502 upstream_unavailable with the dashboard's headers; one of 16 KiB passes.
func TestDashProxy_ResponseHeaderBound_502(t *testing.T) {
	e := newFwdEnv(t)
	conns := rawStudio(t, func(c net.Conn, r *http.Request) {
		n := 16 << 10
		if r.URL.Path == "/big" {
			n = 40 << 10
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nX-Pad: "+strings.Repeat("p", n)+"\r\nContent-Length: 2\r\n\r\nok")
	})
	e.dexpect(t, "40 KiB header", e.owner(t, "GET", "/big"), 502, "upstream_unavailable")
	before := conns.Load()
	if w := e.do(e.owner(t, "GET", "/ok")); w.Code != 200 || len(w.Header().Get("X-Pad")) != 16<<10 {
		t.Errorf("16 KiB header: %d", w.Code)
	}
	if conns.Load() != before+1 {
		t.Errorf("the connection of the refused answer was reused")
	}
}

// TestDashProxy_OwnTransport: the dashboard's transport is its own, with the
// members of the bounds table; with the project API's transport unable to
// dial, a dashboard request still reaches Studio, and the reverse.
func TestDashProxy_OwnTransport(t *testing.T) {
	tr := newDashTransport()
	l := dashcfg.Limits
	if tr.ResponseHeaderTimeout != 70*time.Second || time.Duration(l.StudioHeaderMS)*time.Millisecond != tr.ResponseHeaderTimeout ||
		tr.MaxConnsPerHost != 256 || tr.MaxIdleConnsPerHost != 32 || tr.MaxResponseHeaderBytes != 32<<10 ||
		!tr.DisableCompression || tr.Proxy != nil || tr.ForceAttemptHTTP2 || dialer.Timeout != 5*time.Second {
		t.Errorf("transport: %+v", tr)
	}
	e := newFwdEnv(t)
	if dashTransport == e.gw.transport {
		t.Fatal("one transport for both")
	}
	rec := recordStudio(t, nil)
	e.gw.transport.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no project") }
	a, _, _ := keys()
	if w := e.do(e.owner(t, "GET", "/x")); w.Code != 200 || rec.n() != 1 {
		t.Errorf("dashboard: %d, Studio saw %d", w.Code, rec.n())
	}
	if w := e.do(withKey(req("GET", hostA, "/rest/v1/t", nil), a.anon.token(t, "anon"))); w.Code != 502 {
		t.Errorf("project API without its transport: %d", w.Code)
	}
	dashTransport.CloseIdleConnections()
	dashTransport.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no studio") }
	e.gw.transport.DialContext = nil
	upstreamFunc(t, e.env, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "project") })
	if w := e.do(withKey(req("GET", hostA, "/rest/v1/t", nil), a.anon.token(t, "anon"))); w.Code != 200 {
		t.Errorf("project API: %d", w.Code)
	}
	e.dexpect(t, "dashboard without its transport", e.owner(t, "GET", "/x"), 502, "upstream_unavailable")
}

// TestDashProxy_MethodList_405: a method outside the list is 405
// method_not_allowed and reaches nothing; each listed method is forwarded.
func TestDashProxy_MethodList_405(t *testing.T) {
	e := newFwdEnv(t)
	rec := recordStudio(t, nil)
	for _, m := range []string{"TRACE", "connect", "CONNECTX", "PROPFIND", "get", "TRACK"} {
		e.dexpect(t, m, e.owner(t, m, "/x"), 405, "method_not_allowed")
	}
	if rec.n() != 0 {
		t.Fatalf("Studio saw %d requests of refused methods", rec.n())
	}
	for i, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		if w := e.do(e.owner(t, m, "/x")); w.Code != 200 || rec.n() != i+1 || rec.last(t).Method != m {
			t.Errorf("%s: %d, Studio saw %d", m, w.Code, rec.n())
		}
	}
}

// TestDashProxy_TargetForwardedAsSent: the request target reaches Studio
// byte for byte — escapes, bytes the transport would otherwise escape, the
// query as sent — and on HTTP/2 a client's own host field is not forwarded:
// Host is the public host.
func TestDashProxy_TargetForwardedAsSent(t *testing.T) {
	e := newFwdEnv(t)
	rec := recordStudio(t, nil)
	targets := []string{"/x/a%41b", "/x/a{b}|c^d`e", "/x/%7e%7E%3b", "/x/a'b(c)*!$&+,;=:@",
		"/x?z=%zz&a=1;b&c=%41&d", "/x?", "/x/%20a?%20=%2F"}
	for i, target := range targets {
		r := e.owner(t, "GET", target)
		if i%2 == 1 {
			r.Host = dhostA + ":443" // classified without its port; Host is the name
		}
		if w := e.do(r); w.Code != 200 {
			t.Fatalf("%s: %d", target, w.Code)
		}
		if got := rec.last(t); got.URI != target || got.Host != dhostA || got.Header.Get("X-Forwarded-Host") != dhostA {
			t.Errorf("sent %q, Studio saw %q, host %q", target, got.URI, got.Host)
		}
	}
	addr := serveDashTLS(t, e)
	h := h2dash(t, addr)
	for i, target := range targets {
		sid := uint32(2*i + 1)
		h.headers(sid, e.h2Fields(t, target, [2]string{"host", "other.test"}), true, 16<<10)
		if out := h.wait(t, sid, 10*time.Second); out != "data:studio" {
			t.Fatalf("h2 %s: %s", target, out)
		}
		got := rec.last(t)
		if got.URI != target || got.Host != dhostA || len(got.Header.Values("Host")) != 0 {
			t.Errorf("h2: sent %q, Studio saw %q, host %q, host fields %q", target, got.URI, got.Host, got.Header.Values("Host"))
		}
	}
}

// TestDashProxy_Informational_HTTP1Only_Counted: Studio's 1xx responses are
// relayed over HTTP/1.1, filtered as the final header is; none to a client
// that sent Expect (it gets the server's own 100 Continue) and none over
// HTTP/2. Every one counts: the ninth is 502 on both protocols and the
// connection to Studio is not reused. Under the race detector, clients that
// reset their stream or close their connection while 1xx arrive.
func TestDashProxy_Informational_HTTP1Only_Counted(t *testing.T) {
	e := newFwdEnv(t)
	var hints atomic.Int32
	hint := "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\nServer: up/1\r\nAccess-Control-Allow-Origin: *\r\n" +
		"Set-Cookie: __Host-sp-session=x; Path=/\r\nSet-Cookie: y=2; Path=/\r\nX-Content-Type-Options: other\r\n\r\n"
	conns := rawStudio(t, func(c net.Conn, _ *http.Request) {
		io.WriteString(c, strings.Repeat(hint, int(hints.Load()))+"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := serveDashTLS(t, e)
	get := func(c *http.Client) (int, []http.Header, error) {
		var got []http.Header
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			Got1xxResponse: func(_ int, h textproto.MIMEHeader) error {
				got = append(got, http.Header(h).Clone())
				return nil
			}})
		res, err := c.Do(e.wireReq(t, ctx, "GET", "/x", nil))
		if err != nil {
			return 0, got, err
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode, got, nil
	}
	for _, h2 := range []bool{false, true} {
		relayed := func(n int) int {
			if h2 {
				return 0
			}
			return n
		}
		c := dashClient(t, addr, h2)
		hints.Store(1)
		code, got, err := get(c)
		if err != nil || code != 200 || len(got) != relayed(1) {
			t.Fatalf("h2=%v: %d %v, %d 1xx", h2, code, err, len(got))
		}
		if !h2 {
			h := got[0]
			if s := setHeadersWrong(h); s != "" || h.Get("Server") != "" || h.Get("Access-Control-Allow-Origin") != "" ||
				strings.Join(h.Values("Set-Cookie"), "|") != "y=2; Path=/" || h.Get("Link") != "</a>" {
				t.Errorf("103 relayed as %v (%s)", h, s)
			}
		}
		hints.Store(maxInformational)
		if code, got, err := get(c); err != nil || code != 200 || len(got) != relayed(maxInformational) {
			t.Errorf("h2=%v, %d 1xx: %d %v, %d relayed", h2, maxInformational, code, err, len(got))
		}
		hints.Store(maxInformational + 1)
		dashTransport.CloseIdleConnections()
		before := conns.Load()
		for range 2 {
			if code, _, err := get(c); err != nil || code != 502 {
				t.Errorf("h2=%v, %d 1xx: %d %v", h2, maxInformational+1, code, err)
			}
		}
		if n := conns.Load() - before; n != 2 {
			t.Errorf("h2=%v: %d connections to Studio for two requests ended by 1xx, want 2", h2, n)
		}
	}
	eventually(t, func() bool { return dashIdle(e) }, "slots not returned")

	t.Run("expect", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		const hint = "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { // 1xx as soon as the request header is in, then the body
					defer c.Close()
					br := bufio.NewReader(c)
					for {
						l, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if l == "\r\n" {
							break
						}
					}
					io.WriteString(c, strings.Repeat(hint, 3))
					if _, err := io.ReadFull(br, make([]byte, 5)); err != nil {
						return
					}
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
				}()
			}
		}()
		studioAt(t, ln.Addr().String())
		for _, cs := range []struct{ expect, informational string }{
			{"Expect: 100-continue\r\n", "HTTP/1.1 100 Continue\r\n\r\n"},
			{"", "HTTP/1.1 103 Early Hints\r\n"},
		} {
			for i := range 50 {
				c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: dhostA, NextProtos: []string{"http/1.1"}})
				if err != nil {
					t.Fatal(err)
				}
				io.WriteString(c, "POST /x HTTP/1.1\r\nHost: "+dhostA+"\r\nCookie: "+e.cookie(t, subOwnerA)+"\r\n"+cs.expect+
					"Content-Length: 5\r\nConnection: close\r\n\r\n")
				c.SetReadDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(c)
				first, _ := br.ReadString('\n') // the client waits for a 1xx before its body
				io.WriteString(c, "hello")
				rest, _ := io.ReadAll(br)
				c.Close()
				got := first + string(rest)
				if !strings.HasPrefix(got, cs.informational) || !strings.HasSuffix(got, "\r\n\r\nok") ||
					cs.expect != "" && strings.Contains(got, " 103 ") {
					t.Fatalf("%q request %d: %q", cs.expect, i, got)
				}
			}
		}
	})

	t.Run("reset and close while 1xx arrive", func(t *testing.T) {
		rawStudio(t, func(c net.Conn, _ *http.Request) {
			io.WriteString(c, strings.Repeat("HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n", maxInformational)+
				"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		})
		awaitHeaders := func(h *h2raw, sid uint32) {
			timeout := time.After(30 * time.Second)
			for {
				select {
				case f, ok := <-h.frames:
					if !ok {
						t.Fatal("connection closed")
					}
					if f.typ == 1 && (sid == 0 || f.sid == sid) {
						return
					}
				case <-timeout:
					t.Fatal("no answer")
				}
			}
		}
		h := h2dash(t, addr)
		for sid := uint32(1); sid < 200; sid += 2 {
			h.headers(sid, e.h2Fields(t, "/x"), true, 16<<10)
			awaitHeaders(h, sid)
			h.frame(3, 0, sid, []byte{0, 0, 0, 8}) // RST_STREAM CANCEL
		}
		for i := range 100 {
			h := h2dash(t, addr)
			for sid := uint32(1); sid < 2*maxH2Streams; sid += 2 {
				h.headers(sid, e.h2Fields(t, "/x"), true, 16<<10)
			}
			awaitHeaders(h, 0)
			if i%2 == 0 {
				h.c.NetConn().Close()
			} else {
				h.c.Close()
			}
		}
		eventually(t, func() bool { return dashIdle(e) }, "slots not returned")
	})
}

// TestDashProxy_BodyCapReachedWhileForwarding: a streamed body that passes
// the cap while Studio is reading it is 413 body_too_large, whole, with the
// dashboard's headers, to a client still sending; the connection is closed
// after it. The body is read on the upstream connection's writing goroutine:
// under the race detector a cap that touched the response from there fails
// the second part, where Studio answers at about the moment the cap is hit.
func TestDashProxy_BodyCapReachedWhileForwarding(t *testing.T) {
	e := newFwdEnv(t)
	rec := recordStudio(t, nil)
	addr := serveDashTLS(t, e)
	capBytes := dashcfg.Limits.BodyBytes
	chunk := "10000\r\n" + strings.Repeat("x", 64<<10) + "\r\n"
	dial := func() net.Conn {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: dhostA, NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	head := "POST /x HTTP/1.1\r\nHost: " + dhostA + "\r\nCookie: " + e.cookie(t, subOwnerA) + "\r\nTransfer-Encoding: chunked\r\n\r\n"
	for i := range 10 {
		c := dial()
		go func() { // the connection's only writer
			io.WriteString(c, head)
			for range 4 * capBytes / (64 << 10) {
				if _, err := io.WriteString(c, chunk); err != nil {
					return
				}
			}
		}()
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		b, err := io.ReadAll(c)
		c.Close()
		s := string(b)
		if err != nil || !strings.HasPrefix(s, "HTTP/1.1 413 ") || !strings.HasSuffix(s, `{"code":"body_too_large"}`) ||
			!strings.Contains(s, "\r\nStrict-Transport-Security: max-age=31536000\r\n") || !strings.Contains(s, "\r\nCache-Control: no-store\r\n") {
			t.Errorf("request %d: %v %q", i, err, s)
		}
	}
	rec.mu.Lock()
	for _, r := range rec.got {
		if len(r.Body) > capBytes {
			t.Errorf("Studio received %d bytes of a body capped at %d", len(r.Body), capBytes)
		}
	}
	rec.mu.Unlock()
	eventually(t, func() bool { return dashIdle(e) }, "slots not returned")

	// Studio answers once it has received all but early bytes of the cap.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	early := make(chan int, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(want int) {
				defer c.Close()
				buf := make([]byte, 64<<10)
				for n := 0; n < want; {
					m, err := c.Read(buf)
					if err != nil {
						return
					}
					n += m
				}
				for range maxInformational - 2 {
					io.WriteString(c, "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n")
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				io.Copy(io.Discard, c)
			}(capBytes - <-early)
		}
	}()
	studioAt(t, ln.Addr().String())
	for i := range 12 {
		early <- i * (16 << 10)
		c := dial()
		io.WriteString(c, head)
		for range capBytes/(64<<10) + 1 {
			if _, err := io.WriteString(c, chunk); err != nil {
				break
			}
		}
		io.WriteString(c, "0\r\n\r\n")
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		b, _ := io.ReadAll(c)
		c.Close()
		if s := string(b); !strings.Contains(s, "HTTP/1.1 200 ") && !strings.Contains(s, "HTTP/1.1 413 ") {
			t.Errorf("Studio answering %d bytes early: %.80q", i*(16<<10), s)
		}
	}
	eventually(t, func() bool { return dashIdle(e) }, "slots not returned")
}

// accessLines captures the gateway's log until the test ends.
func accessLines(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(io.Discard) })
	return &buf
}

var accessRE = regexp.MustCompile(`^\{"t":"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z","ref":"[^"]*","iss":"[^"]*","sub":"[^"]*",` +
	`"role":"[^"]*","method":"[^"]*","path":"[^"]*","status":\d+,"ms":\d+\}$`)

// lines returns the access lines in buf (the logger's prefix removed) and
// clears it.
func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		i := strings.IndexByte(l, '{')
		if i < 0 || !accessRE.MatchString(l[i:]) {
			t.Errorf("not an access line: %q", l)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l[i:]), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	buf.Reset()
	return out
}

// TestDashAccessLine_NoQueryNoSecret: a forwarded request is one line of the
// fixed form; it holds the path without its query, cut to 256 bytes, and no
// cookie, token, query or body.
func TestDashAccessLine_NoQueryNoSecret(t *testing.T) {
	e := newFwdEnv(t)
	recordStudio(t, nil)
	buf := accessLines(t)
	r := e.owner(t, "POST", "/x/y?token=QUERYSECRET")
	cookie := r.Header.Get("Cookie")
	r.Header.Set("Authorization", "Bearer HEADERSECRET")
	r.Body, r.ContentLength = io.NopCloser(strings.NewReader("BODYSECRET")), 10
	e.do(r)
	all := buf.String()
	ls := lines(t, buf)
	if len(ls) != 1 {
		t.Fatalf("%d lines: %q", len(ls), all)
	}
	want := map[string]any{"ref": refA, "iss": issuer, "sub": subOwnerA, "role": "owner", "method": "POST", "path": "/x/y", "status": 200.0}
	for k, v := range want {
		if ls[0][k] != v {
			t.Errorf("%s: %v, want %v", k, ls[0][k], v)
		}
	}
	_, tok, _ := strings.Cut(cookie, "=")
	for _, s := range []string{"SECRET", tok, "token", "?"} {
		if strings.Contains(all, s) {
			t.Errorf("the line holds %q: %q", s, all)
		}
	}
	long := "/" + strings.Repeat("a", 299)
	e.do(e.owner(t, "GET", long+"?q=1"))
	if ls := lines(t, buf); len(ls) != 1 || ls[0]["path"] != long[:256] {
		t.Errorf("long path: %v", ls)
	}
	if got := logField("/a\x00b\x1fc\x7fd\te", 256); got != "/abcde" {
		t.Errorf("control characters: %q", got)
	}
	if got := logField(strings.Repeat("M", 40), maxLogMethod); got != strings.Repeat("M", 16) {
		t.Errorf("method: %q", got)
	}
}

// TestDashAccessLine_RefusalsOfRulesFiveToTen: each refusal of rules 5 to 10
// and each slot refusal is one line with its status; a refusal of rules 0 to
// 4 and an answer of the sign-in seam are none.
func TestDashAccessLine_RefusalsOfRulesFiveToTen(t *testing.T) {
	e := newDashEnv(t, active(), true) // the recording seams
	buf := accessLines(t)
	nav := rawReq("GET", dhostA, "/x?q=1")
	nav.Header.Set("Sec-Fetch-Mode", "navigate")
	cross := e.owner(t, "POST", "/api/x")
	cross.Header.Set("Sec-Fetch-Site", "cross-site")
	up := e.owner(t, "GET", "/x")
	up.Header.Set("Upgrade", "websocket")
	big := e.owner(t, "POST", "/x")
	big.ContentLength = 3 << 20
	for _, c := range []struct {
		name   string
		r      *http.Request
		status int
		sub    string
	}{
		{"302", nav, 302, ""},
		{"401", rawReq("GET", dhostA, "/api/x"), 401, ""},
		{"403 not a member", e.as(t, rawReq("GET", dhostA, "/x"), refA, subOwnerB), 403, subOwnerB},
		{"403 cross origin", cross, 403, subOwnerA},
		{"403 read only", e.as(t, rawReq("POST", dhostA, "/x"), refA, subROA), 403, subROA},
		{"400 upgrade", up, 400, subOwnerA},
		{"413", big, 413, subOwnerA},
	} {
		path, _, _ := strings.Cut(c.r.RequestURI, "?")
		if w := e.do(c.r); w.Code != c.status {
			t.Fatalf("%s: %d", c.name, w.Code)
		}
		ls := lines(t, buf)
		if len(ls) != 1 || ls[0]["status"] != float64(c.status) || ls[0]["ref"] != refA || ls[0]["sub"] != c.sub || ls[0]["path"] != path {
			t.Errorf("%s: %v", c.name, ls)
		}
	}
	// The slots: the project's, the dashboard's, the gateway's.
	e.d.mu.Lock()
	e.d.byRef[refA] = e.d.projects
	e.d.mu.Unlock()
	slot := func(name string, status int) {
		if w := e.do(e.owner(t, "GET", "/x")); w.Code != status {
			t.Fatalf("%s: %d", name, w.Code)
		}
		if ls := lines(t, buf); len(ls) != 1 || ls[0]["status"] != float64(status) || ls[0]["role"] != "owner" {
			t.Errorf("%s: %v", name, ls)
		}
	}
	slot("429", 429)
	e.d.mu.Lock()
	delete(e.d.byRef, refA)
	e.d.mu.Unlock()
	for range cap(e.d.slots) {
		e.d.slots <- struct{}{}
	}
	slot("503 dashboard", 503)
	for len(e.d.slots) > 0 {
		<-e.d.slots
	}
	for range cap(e.gw.inflight) {
		e.gw.inflight <- struct{}{}
	}
	slot("503 gateway", 503)
	for len(e.gw.inflight) > 0 {
		<-e.gw.inflight
	}

	// None: rules 0 to 4, the sign-in seam, rule 5's exception.
	sw := e.owner(t, "GET", "/sw.js")
	sw.Header.Set("Service-Worker", "script")
	back := rawReq("GET", dhostA, "/x")
	back.Header.Set("Sec-Fetch-Mode", "navigate")
	back.Header.Set("Referer", "https://"+dhostA+"/-/auth/session?at="+strconv.FormatInt(time.Now().Unix(), 10))
	for _, r := range []*http.Request{e.owner(t, "GET", "/a//b"), e.owner(t, "GET", "/x/"+refB), e.owner(t, "GET", "/api/mcp"), sw,
		rawReq("GET", dhostA, "/-/auth/login"), rawReq("GET", signInH, "/"), back} {
		e.do(r)
	}
	if _, a := e.seams(); a != 3 {
		t.Errorf("the sign-in seam was reached %d times, want 3", a)
	}
	if buf.Len() != 0 {
		t.Errorf("logged: %q", buf.String())
	}
	// Control: forwarded, one line.
	e.do(e.owner(t, "GET", "/x"))
	if f, _ := e.seams(); f != 1 {
		t.Errorf("not forwarded")
	}
}

// TestProjectAPI_TimeoutsUnchanged: the server's timeouts and the project
// API's transport are as built, and a project response is still cut at the
// 60 s write timeout on both protocols: the dashboard's deadlines are its
// handler's own.
func TestProjectAPI_TimeoutsUnchanged(t *testing.T) {
	t.Parallel()
	s := NewServer(nil)
	if s.ReadHeaderTimeout != 10*time.Second || s.ReadTimeout != 60*time.Second || s.WriteTimeout != 60*time.Second ||
		s.IdleTimeout != 120*time.Second {
		t.Errorf("server timeouts: %v %v %v %v", s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout)
	}
	e := newEnv(t, active())
	if e.gw.transport.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("project header wait: %v", e.gw.transport.ResponseHeaderTimeout)
	}
	upstreamFunc(t, e, func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		w.WriteHeader(200)
		rc.Flush()
		for range 75 {
			select {
			case <-time.After(time.Second):
			case <-r.Context().Done():
				return
			}
			io.WriteString(w, ".")
			rc.Flush()
		}
	})
	a, _, _ := keys()
	addr := e.serve(t, true, nil)
	var wg sync.WaitGroup
	for _, h2 := range []bool{false, true} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := http.NewRequest("GET", "https://"+hostA+"/rest/v1/t", nil)
			r.Header.Set("apikey", a.anon.token(t, "anon"))
			start := time.Now()
			res, err := clientFor(t, addr, h2).Do(r)
			if err == nil {
				_, err = io.ReadAll(res.Body)
				res.Body.Close()
			}
			if d := time.Since(start); err == nil || d < 59*time.Second {
				t.Errorf("h2=%v: project response not cut at 60 s: %v after %v", h2, err, d)
			}
		}()
	}
	wg.Wait()
}

// TestDashProxy_ReadDeadlineMovesWithTheHeader: on HTTP/1.1 a request without
// a body is already watched by the server's background read when the
// forwarder sets the read deadline at entry, and that deadline, once it
// passes, ends the request. A slow dial to Studio, a header within row 2
// and a transfer within row 1 together outlast the entry deadline (row 2 +
// row 1): the response still arrives whole, because the read deadline moves
// to row 1 from the header with the write deadline.
func TestDashProxy_ReadDeadlineMovesWithTheHeader(t *testing.T) {
	e := newFwdEnv(t)
	setLimits(t, func(l *dashcfg.LimitSet) { l.StudioHeaderMS, l.TransferMS = 1000, 4000 }) // entry: 5 s
	recordStudio(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		rc := http.NewResponseController(w)
		w.WriteHeader(200)
		rc.Flush()
		for i := range 10 { // 3 s of body, inside row 1
			select {
			case <-time.After(300 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			fmt.Fprintf(w, "%d", i)
			rc.Flush()
		}
	})
	dial := dashTransport.DialContext
	dashTransport.DialContext = func(ctx context.Context, n, a string) (net.Conn, error) {
		time.Sleep(3 * time.Second) // the header arrives at about 3.5 s, the body ends at about 6.5 s
		return dial(ctx, n, a)
	}
	addr := serveDashTLS(t, e)
	start := time.Now()
	res, err := dashClient(t, addr, false).Do(e.wireReq(t, context.Background(), "GET", "/x", nil))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(res.Body)
	res.Body.Close()
	if d := time.Since(start); err != nil || string(b) != "0123456789" || d < 5500*time.Millisecond {
		t.Errorf("%v after %v: %q", err, d, b)
	}
}
