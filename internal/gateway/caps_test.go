package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// holdUpstream routes every upstream dial of e to a server that blocks
// requests for /hold until release is closed or the request ends, and counts
// the requests blocked at once.
func holdUpstream(t *testing.T, e *env, refuseB bool) (held *atomic.Int32, release chan struct{}) {
	t.Helper()
	held, release = new(atomic.Int32), make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hold":
			held.Add(1)
			defer held.Add(-1)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		case "/abort":
			w.Header().Set("Content-Length", "1000")
			w.WriteHeader(200)
			io.WriteString(w, "partial")
			w.(http.Flusher).Flush()
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		default:
			io.Copy(io.Discard, r.Body)
		}
	}))
	t.Cleanup(up.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	e.gw.transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		if refuseB && addr == "10.212.0.17:3000" {
			return nil, &net.OpError{Op: "dial", Err: io.ErrUnexpectedEOF}
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	return held, release
}

func idle(e *env) bool {
	e.gw.mu.Lock()
	defer e.gw.mu.Unlock()
	return len(e.gw.inflight) == 0 && len(e.gw.byProject) == 0
}

// TestServer_ProjectCapIsolatesProjects: with the real cap, all 128 requests
// of one project reach the upstream at once (none waits inside the gateway
// for a connection); the 129th gets 429 while another project is still served.
func TestServer_ProjectCapIsolatesProjects(t *testing.T) {
	a, b, _ := keys()
	e := newEnv(t, active())
	held, release := holdUpstream(t, e, false)
	anonA := a.anon.token(t, "anon")
	var wg sync.WaitGroup
	for range maxProjectInFlight {
		wg.Add(1)
		go func() { defer wg.Done(); e.do(withKey(req("GET", hostA, "/rest/v1/hold", nil), anonA)) }()
	}
	eventually(t, func() bool {
		e.gw.mu.Lock()
		defer e.gw.mu.Unlock()
		return e.gw.byProject[refA] == maxProjectInFlight && held.Load() == maxProjectInFlight
	}, "A's requests not all at the upstream")
	if w := within(t, e, withKey(req("GET", hostA, "/rest/v1/x", nil), anonA)); w.Code != 429 {
		t.Errorf("A over its cap: %d, want 429", w.Code)
	}
	if w := within(t, e, withKey(req("GET", hostB, "/rest/v1/x", nil), b.anon.token(t, "anon"))); w.Code != 200 {
		t.Errorf("B while A is at its cap: %d, want 200", w.Code)
	}
	close(release)
	wg.Wait()
	eventually(t, func() bool { return idle(e) }, "slots not returned")
}

// TestHTTP2_StreamsOverLimitRefused: on one connection the server runs at
// most maxH2Streams requests at once; further streams are reset, not queued.
func TestHTTP2_StreamsOverLimitRefused(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	held, release := holdUpstream(t, e, false)
	addr := e.serve(t, true, nil)
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: hostA, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	h2frame(c, 4, 0, 0, nil)
	resets := make(chan uint32, 64)
	go func() {
		for {
			h := make([]byte, 9)
			if _, err := io.ReadFull(c, h); err != nil {
				close(resets)
				return
			}
			p := make([]byte, int(h[0])<<16|int(h[1])<<8|int(h[2]))
			io.ReadFull(c, p)
			switch h[3] {
			case 4:
				if h[4]&1 == 0 {
					h2frame(c, 4, 1, 0, nil)
				}
			case 3:
				resets <- binary.BigEndian.Uint32(h[5:]) & 0x7fffffff
			}
		}
	}()
	time.Sleep(100 * time.Millisecond) // the server's SETTINGS are acknowledged
	tok := a.anon.token(t, "anon")
	const n = 24
	for i := range n {
		var hb bytes.Buffer
		for _, f := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", hostA},
			{":path", "/rest/v1/hold"}, {"apikey", tok}} {
			hb.WriteByte(0)
			hpackStr(&hb, f[0])
			hpackStr(&hb, f[1])
		}
		h2frame(c, 1, 5, uint32(2*i+1), hb.Bytes())
	}
	eventually(t, func() bool { return held.Load() == maxH2Streams }, "streams up to the limit not running")
	got := 0
	for deadline := time.After(2 * time.Second); got < n-maxH2Streams; {
		select {
		case _, ok := <-resets:
			if !ok {
				t.Fatal("connection closed")
			}
			got++
		case <-deadline:
			t.Fatalf("%d of %d streams over the limit reset", got, n-maxH2Streams)
		}
	}
	if h := held.Load(); h != maxH2Streams {
		t.Errorf("%d requests in flight on one connection, want %d", h, maxH2Streams)
	}
	close(release)
	eventually(t, func() bool { return idle(e) }, "slots not returned")
}

// TestServer_SlotsReturnToZero: under mixed load over HTTP/1.1 and HTTP/2 —
// success, upstream refused, upstream cut mid-response, client gone, body
// over the cap, no key — every in-flight slot is given back exactly once.
func TestServer_SlotsReturnToZero(t *testing.T) {
	a, b, _ := keys()
	e := newEnv(t, active())
	_, _ = holdUpstream(t, e, true)
	addr := e.serve(t, true, nil)
	clients := map[bool]*http.Client{}
	for _, h2 := range []bool{false, true} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: h2, MaxConnsPerHost: 8}
		if !h2 {
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}
		t.Cleanup(tr.CloseIdleConnections)
		clients[h2] = &http.Client{Transport: tr}
	}
	anonA, anonB := a.anon.token(t, "anon"), b.anon.token(t, "anon")
	big := bytes.Repeat([]byte("x"), maxBody+1)
	var tally sync.Map
	var wg sync.WaitGroup
	sem := make(chan struct{}, 48)
	for i := range 1200 {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			c := clients[i%2 == 0]
			host, key, path := hostA, anonA, "/rest/v1/ok"
			var body io.Reader
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			switch i % 6 {
			case 1:
				host, key = hostB, anonB // upstream refuses
			case 2:
				path = "/rest/v1/abort"
			case 3:
				path = "/rest/v1/hold"
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			case 4:
				body = io.MultiReader(bytes.NewReader(big)) // no length: cut by the body cap
			case 5:
				key = "x"
			}
			r, _ := http.NewRequestWithContext(ctx, "POST", "https://"+host+path, body)
			r.Host = host
			r.Header.Set("apikey", key)
			res, err := c.Do(r)
			k := [2]int{i % 6, 0}
			if err == nil {
				k[1] = res.StatusCode
			}
			n, _ := tally.LoadOrStore(k, new(atomic.Int32))
			n.(*atomic.Int32).Add(1)
			if err == nil {
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
		}()
	}
	wg.Wait()
	tally.Range(func(k, v any) bool { t.Logf("case %v: %d", k, v.(*atomic.Int32).Load()); return true })
	eventually(t, func() bool { return idle(e) }, "in-flight slots leaked")
	if w := within(t, e, withKey(req("GET", hostA, "/rest/v1/ok", nil), anonA)); w.Code != 200 {
		t.Errorf("after the load: %d", w.Code)
	}
}

// fakeListener hands out the connections sent on its channel.
type fakeListener chan net.Conn

func (l fakeListener) Accept() (net.Conn, error) { return <-l, nil }
func (fakeListener) Close() error                { return nil }
func (fakeListener) Addr() net.Addr              { return &net.TCPAddr{} }

type fakeConn struct {
	net.Conn
	remote net.Addr
	closed atomic.Bool
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeConn) Close() error         { c.closed.Store(true); return nil }

// TestLimitListener_SourceKeys: an IPv4 source is its address, also when it
// arrives IPv4-mapped; an IPv6 source is its /64.
func TestLimitListener_SourceKeys(t *testing.T) {
	l := make(fakeListener, 2*MaxConnsPerSource+4)
	lim := NewLimiter(1000, MaxConnsPerSource)
	ln := lim.Listen(l)
	from := func(a netip.Addr) *fakeConn {
		c := &fakeConn{remote: net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, 4321))}
		l <- c
		return c
	}
	var open []net.Conn
	accepted := func(want *fakeConn) bool {
		c, err := ln.Accept()
		if err != nil {
			return false
		}
		open = append(open, c)
		return c.(*limitConn).Conn == want
	}
	// Documentation prefix, built from bytes: subnet n, interface ID i.
	v6 := func(n, i byte) netip.Addr {
		return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, n, i, 0, 0, 0, 0, 0, 0, i})
	}
	for i := range byte(MaxConnsPerSource) {
		if !accepted(from(v6(1, i))) {
			t.Fatalf("connection %d of one /64 refused", i+1)
		}
	}
	over, other := from(v6(1, MaxConnsPerSource)), from(v6(2, 0))
	if !accepted(other) || !over.closed.Load() {
		t.Fatalf("connection %d of one /64: closed %v; next /64 not accepted", MaxConnsPerSource+1, over.closed.Load())
	}

	v4 := netip.MustParseAddr("192.0.2.10")
	mapped := netip.AddrFrom16(v4.As16())
	// A net.TCPAddr prints a mapped address in IPv4 form, so check the key itself too.
	if source(mapped) != source(v4) {
		t.Errorf("IPv4-mapped source %v, IPv4 source %v", source(mapped), source(v4))
	}
	for i := range MaxConnsPerSource {
		a := v4
		if i%2 == 1 {
			a = mapped
		}
		if !accepted(from(a)) {
			t.Fatalf("connection %d of one IPv4 source refused", i+1)
		}
	}
	over, other = from(mapped), from(netip.MustParseAddr("192.0.2.11"))
	if !accepted(other) || !over.closed.Load() {
		t.Errorf("IPv4-mapped connection over the cap: closed %v; other IPv4 source not accepted", over.closed.Load())
	}
	// Every count goes away when its connections are closed.
	for _, c := range open {
		c.Close()
	}
	lim.mu.Lock()
	defer lim.mu.Unlock()
	if lim.n != 0 || len(lim.bySrc) != 0 {
		t.Errorf("after closing all: %d connections, sources %v", lim.n, lim.bySrc)
	}
}

// TestHTTP2_ReceiveWindows: the server advertises a 128 KiB window per stream
// and opens the connection window to no more than 128 KiB, so a connection
// buffers at most that much request body before the handler reads it.
func TestHTTP2_ReceiveWindows(t *testing.T) {
	e := newEnv(t, active())
	addr := e.serve(t, true, nil)
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: hostA, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	h2frame(c, 4, 0, 0, nil)
	h2frame(c, 6, 0, 0, make([]byte, 8)) // PING: its ACK comes after the server's opening frames
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	stream, conn := uint32(65535), int64(65535) // RFC 9113 initial values
	for {
		h := make([]byte, 9)
		if _, err := io.ReadFull(c, h); err != nil {
			t.Fatal(err)
		}
		p := make([]byte, int(h[0])<<16|int(h[1])<<8|int(h[2]))
		if _, err := io.ReadFull(c, p); err != nil {
			t.Fatal(err)
		}
		typ, ack, id := h[3], h[4]&1 == 1, binary.BigEndian.Uint32(h[5:])&0x7fffffff
		if typ == 4 && !ack {
			for i := 0; i+6 <= len(p); i += 6 {
				if binary.BigEndian.Uint16(p[i:]) == 4 {
					stream = binary.BigEndian.Uint32(p[i+2:])
				}
			}
		}
		if typ == 8 && id == 0 {
			conn += int64(binary.BigEndian.Uint32(p) & 0x7fffffff)
		}
		if typ == 6 && ack {
			break
		}
	}
	if stream != 128<<10 {
		t.Errorf("initial stream window %d, want %d", stream, 128<<10)
	}
	if conn > 128<<10 {
		t.Errorf("connection window %d, want at most %d", conn, 128<<10)
	}
}

// TestHTTP2_LargeUploadFlows: with the small windows an 8 MiB body still
// reaches the upstream whole; flow control does not stall.
func TestHTTP2_LargeUploadFlows(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	addr := e.serve(t, true, nil)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: hostA}, ForceAttemptHTTP2: true}
	t.Cleanup(tr.CloseIdleConnections)
	body := make([]byte, maxBody)
	for i := range body {
		body[i] = byte(i*7 + i>>13)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, "POST", "https://"+addr+"/rest/v1/t", bytes.NewReader(body))
	r.Host = hostA
	r.Header.Set("apikey", a.anon.token(t, "anon"))
	res, err := (&http.Client{Transport: tr}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || res.ProtoMajor != 2 {
		t.Fatalf("upload: %d over %s", res.StatusCode, res.Proto)
	}
	if got := e.requests(); len(got) != 1 || !bytes.Equal(got[0].Body, body) {
		t.Errorf("upstream did not get the body byte-exact")
	}
}

// TestServer_ReleasesRequestHeaders: once the gateway has answered, the
// request no longer references its header values. HTTP/2 keeps the request
// of a stream until the response is on the wire, which a client that does
// not read can delay indefinitely.
func TestServer_ReleasesRequestHeaders(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	for _, r := range []*http.Request{
		req("GET", hostA, "/rest/v1/t", nil), // refused: no key
		withKey(req("GET", hostA, "/rest/v1/t", nil), a.anon.token(t, "anon")),
	} {
		r.Header.Set("X-Pad", strings.Repeat("p", 1000))
		w := e.do(r)
		if r.Header != nil {
			t.Errorf("status %d: request still holds %d header fields", w.Code, len(r.Header))
		}
	}
}

// upstreamFunc points every upstream dial of e at a server running h.
func upstreamFunc(t *testing.T, e *env, h http.HandlerFunc) {
	t.Helper()
	up := httptest.NewServer(h)
	t.Cleanup(up.Close)
	e.gw.transport.CloseIdleConnections()
	e.gw.transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
}

// TestForward_DropsDomainCookies: a cookie the upstream scopes with a Domain
// attribute would reach every other project's host, so it is dropped; host-
// only cookies and other headers pass unchanged.
func TestForward_DropsDomainCookies(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	upstreamFunc(t, e, func(w http.ResponseWriter, r *http.Request) {
		for _, c := range []string{
			"a=1; Domain=example.test",
			"b=2; Path=/; domain = .example.test",
			"c=3; Path=/; Secure; HttpOnly;DOMAIN=sub.example.test",
			"domain=example.test; Path=/",
			"d=mydomain; Path=/; HttpOnly",
		} {
			w.Header().Add("Set-Cookie", c)
		}
		w.Header().Set("X-Other", "domain=example.test")
	})
	w := e.do(withKey(req("GET", hostA, "/rest/v1/t", nil), a.anon.token(t, "anon")))
	got := strings.Join(w.Header().Values("Set-Cookie"), " | ")
	if want := "domain=example.test; Path=/ | d=mydomain; Path=/; HttpOnly"; w.Code != 200 || got != want {
		t.Errorf("%d: Set-Cookie %q, want %q", w.Code, got, want)
	}
	if w.Header().Get("X-Other") != "domain=example.test" {
		t.Errorf("other header changed: %q", w.Header().Get("X-Other"))
	}
	// When every cookie is dropped, no empty Set-Cookie is left behind.
	upstreamFunc(t, e, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "a=1; Domain=example.test")
	})
	w = e.do(withKey(req("GET", hostA, "/rest/v1/t", nil), a.anon.token(t, "anon")))
	if _, ok := w.Header()["Set-Cookie"]; ok {
		t.Errorf("Set-Cookie left: %q", w.Header()["Set-Cookie"])
	}
}

// TestForward_UpstreamHeaderLimit: an upstream response header over the
// limit is an upstream failure, answered 502 with nothing of the response;
// a large but allowed header passes.
func TestForward_UpstreamHeaderLimit(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	upstreamFunc(t, e, func(w http.ResponseWriter, r *http.Request) {
		n := 16 << 10
		if r.URL.Path == "/big" {
			n = 40 << 10
		}
		w.Header().Set("X-Pad", strings.Repeat("p", n))
		io.WriteString(w, "upstream body")
	})
	anon := a.anon.token(t, "anon")
	w := e.do(withKey(req("GET", hostA, "/rest/v1/big", nil), anon))
	if w.Code != 502 || strings.TrimSpace(w.Body.String()) != `{"code":"upstream_unavailable"}` || w.Header().Get("X-Pad") != "" {
		t.Errorf("40 KiB of upstream headers: %d %q, X-Pad %d bytes", w.Code, w.Body, len(w.Header().Get("X-Pad")))
	}
	w = e.do(withKey(req("GET", hostA, "/rest/v1/ok", nil), anon))
	if w.Code != 200 || len(w.Header().Get("X-Pad")) != 16<<10 || w.Body.String() != "upstream body" {
		t.Errorf("16 KiB of upstream headers: %d, X-Pad %d bytes", w.Code, len(w.Header().Get("X-Pad")))
	}
}

// clientFor returns an HTTPS client to addr speaking HTTP/2 or HTTP/1.1.
func clientFor(t *testing.T, addr string, h2 bool) *http.Client {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: hostA}, ForceAttemptHTTP2: h2,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

// TestForward_InformationalFilteredAndBounded: over HTTP/1.1 and HTTP/2 a 1xx
// response reaches the client without Server, Set-Cookie2 or Domain cookies,
// and with its other headers; past maxInformational of them the request ends
// in the gateway's 502 and the upstream connection is not reused.
func TestForward_InformationalFilteredAndBounded(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	var hints atomic.Int32
	hints.Store(1)
	conns := rawUpstream(t, e, func(c net.Conn) {
		var b strings.Builder
		for range hints.Load() {
			b.WriteString("HTTP/1.1 103 Early Hints\r\nLink: </app.js>; rel=preload\r\nServer: up/1\r\n" +
				"Set-Cookie: x=1; Domain=sp.test\r\nSet-Cookie: y=2; Path=/\r\nSet-Cookie2: z=3\r\n\r\n")
		}
		b.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		io.WriteString(c, b.String())
	})
	addr, tok := e.serve(t, true, nil), a.anon.token(t, "anon")
	get := func(c *http.Client) (int, []http.Header, error) {
		var got []http.Header
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
				got = append(got, http.Header(h).Clone())
				return nil
			}})
		r, _ := http.NewRequestWithContext(ctx, "GET", "https://"+hostA+"/rest/v1/t", nil)
		r.Header.Set("apikey", tok)
		res, err := c.Do(r)
		if err != nil {
			return 0, got, err
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode, got, nil
	}
	for _, h2 := range []bool{false, true} {
		c := clientFor(t, addr, h2)
		hints.Store(1)
		code, got, err := get(c)
		if err != nil || code != 200 || len(got) != 1 {
			t.Fatalf("h2=%v: %d %v, %d informational responses", h2, code, err, len(got))
		}
		if h := got[0]; h.Get("Server") != "" || h.Get("Set-Cookie2") != "" ||
			strings.Join(h.Values("Set-Cookie"), "|") != "y=2; Path=/" || h.Get("Link") != "</app.js>; rel=preload" {
			t.Errorf("h2=%v: 103 header %v", h2, h)
		}
		hints.Store(maxInformational)
		if code, got, err := get(c); err != nil || code != 200 || len(got) != maxInformational {
			t.Errorf("h2=%v: %d informational responses: %d %v, %d relayed", h2, maxInformational, code, err, len(got))
		}
		hints.Store(maxInformational + 1)
		before := conns.Load()
		if code, got, err := get(c); err != nil || code != 502 || len(got) != maxInformational {
			t.Errorf("h2=%v: %d informational responses: %d %v, %d relayed", h2, maxInformational+1, code, err, len(got))
		}
		hints.Store(1)
		if code, _, err := get(c); err != nil || code != 200 {
			t.Errorf("h2=%v: after the 502: %d %v", h2, code, err)
		}
		if conns.Load() == before {
			t.Errorf("h2=%v: upstream connection reused after too many informational responses", h2)
		}
	}
	eventually(t, func() bool { return idle(e) }, "slots not returned")
}

// TestForward_TrailersFiltered: response trailers get the same filter as the
// header, over HTTP/1.1 and HTTP/2.
func TestForward_TrailersFiltered(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	rawUpstream(t, e, func(c net.Conn) {
		io.WriteString(c, "HTTP/1.1 200 OK\r\nTrailer: Set-Cookie, Server, X-T\r\nTransfer-Encoding: chunked\r\n\r\n"+
			"2\r\nok\r\n0\r\nSet-Cookie: t=1; Domain=sp.test\r\nSet-Cookie: u=2; Path=/\r\nServer: up/1\r\n"+
			"Set-Cookie2: v=3\r\nX-T: 1\r\n\r\n")
	})
	addr := e.serve(t, true, nil)
	for _, h2 := range []bool{false, true} {
		r, _ := http.NewRequest("GET", "https://"+hostA+"/rest/v1/t", nil)
		r.Header.Set("apikey", a.anon.token(t, "anon"))
		res, err := clientFor(t, addr, h2).Do(r)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		tr := res.Trailer
		if string(b) != "ok" || tr.Get("Server") != "" || tr.Get("Set-Cookie2") != "" || tr.Get("X-T") != "1" ||
			strings.Join(tr.Values("Set-Cookie"), "|") != "u=2; Path=/" {
			t.Errorf("h2=%v: body %q, trailers %v", h2, b, tr)
		}
	}
}

// TestForward_SiblingSafeHeaders: projects share a parent domain, so no
// response may act on sibling hosts: Clear-Site-Data is dropped from the
// header, 1xx responses and trailers, and every final response, the
// gateway's own refusals included, is sandboxed and not sniffed. The
// upstream's Content-Type is kept.
func TestForward_SiblingSafeHeaders(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	rawUpstream(t, e, func(c net.Conn) {
		io.WriteString(c, "HTTP/1.1 103 Early Hints\r\nClear-Site-Data: \"cookies\"\r\nLink: </a.js>; rel=preload\r\n\r\n"+
			"HTTP/1.1 200 OK\r\nClear-Site-Data: \"cookies\"\r\nContent-Security-Policy: default-src *\r\n"+
			"Content-Security-Policy: script-src *\r\nX-Content-Type-Options: none\r\nContent-Type: text/html\r\n"+
			"Trailer: Clear-Site-Data\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nClear-Site-Data: \"*\"\r\n\r\n")
	})
	addr, tok := e.serve(t, true, nil), a.anon.token(t, "anon")
	for _, h2 := range []bool{false, true} {
		var hints []http.Header
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			Got1xxResponse: func(_ int, h textproto.MIMEHeader) error { hints = append(hints, http.Header(h).Clone()); return nil }})
		r, _ := http.NewRequestWithContext(ctx, "GET", "https://"+hostA+"/rest/v1/t", nil)
		r.Header.Set("apikey", tok)
		res, err := clientFor(t, addr, h2).Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		h := res.Header
		if h.Get("Clear-Site-Data") != "" || res.Trailer.Get("Clear-Site-Data") != "" ||
			strings.Join(h.Values("Content-Security-Policy"), "|") != "sandbox" ||
			strings.Join(h.Values("X-Content-Type-Options"), "|") != "nosniff" || h.Get("Content-Type") != "text/html" {
			t.Errorf("h2=%v: header %v trailer %v", h2, h, res.Trailer)
		}
		if len(hints) != 1 || hints[0].Get("Clear-Site-Data") != "" || hints[0].Get("Link") == "" {
			t.Errorf("h2=%v: 1xx %v", h2, hints)
		}
	}
	w := e.do(req("GET", hostA, "/rest/v1/t", nil))
	if w.Code != 401 || w.Header().Get("Content-Security-Policy") != "sandbox" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("gateway's own 401: %d %v", w.Code, w.Header())
	}
}
