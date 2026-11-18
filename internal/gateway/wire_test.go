package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type h2f struct {
	typ, flags byte
	sid        uint32
	p          []byte
}

// h2raw is a client HTTP/2 connection driven frame by frame. Only the test
// writes to it: a frame written from another goroutine could land between a
// HEADERS frame and its CONTINUATION, which the server must treat as a
// connection error (PROTOCOL_ERROR).
type h2raw struct {
	c      *tls.Conn
	frames chan h2f
	mu     sync.Mutex
}

func h2open(t *testing.T, addr string) *h2raw {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: hostA, NextProtos: []string{"h2"}})
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
	// The server's SETTINGS come first and only once; acknowledge them here,
	// before the test writes anything else.
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

func (h *h2raw) frame(typ, flags byte, sid uint32, p []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	hd := []byte{byte(len(p) >> 16), byte(len(p) >> 8), byte(len(p)), typ, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(hd[5:], sid)
	_, err := h.c.Write(append(hd, p...))
	return err
}

func hpackBlock(fields [][2]string) []byte {
	var b bytes.Buffer
	for _, f := range fields {
		b.WriteByte(0)
		hpackStr(&b, f[0])
		hpackStr(&b, f[1])
	}
	return b.Bytes()
}

// headers sends fields as HEADERS plus CONTINUATION frames of at most max bytes.
func (h *h2raw) headers(sid uint32, fields [][2]string, endStream bool, max int) {
	blk := hpackBlock(fields)
	typ, flags := byte(1), byte(0)
	if endStream {
		flags = 1
	}
	for {
		n := min(len(blk), max)
		f := flags
		if n == len(blk) {
			f |= 4
		}
		h.frame(typ, f, sid, blk[:n])
		blk = blk[n:]
		typ, flags = 9, 0
		if len(blk) == 0 {
			return
		}
	}
}

// wait returns the outcome of stream sid: "data:<body>", "reset:<code>",
// "goaway:<code>" or "eof".
func (h *h2raw) wait(t *testing.T, sid uint32, d time.Duration) string {
	t.Helper()
	var data []byte
	timeout := time.After(d)
	for {
		select {
		case f, ok := <-h.frames:
			if !ok {
				return "eof"
			}
			switch {
			case f.typ == 7:
				return fmt.Sprintf("goaway:%d", binary.BigEndian.Uint32(f.p[4:]))
			case f.sid != sid:
			case f.typ == 3:
				return fmt.Sprintf("reset:%d", binary.BigEndian.Uint32(f.p))
			case f.typ == 0:
				data = append(data, f.p...)
				if f.flags&1 != 0 {
					return "data:" + string(data)
				}
			case f.typ == 1 && f.flags&1 != 0:
				return "data:" + string(data)
			}
		case <-timeout:
			return "timeout"
		}
	}
}

func getFields(tok string, extra ...[2]string) [][2]string {
	return append([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", hostA},
		{":path", "/rest/v1/t"}, {"apikey", tok}}, extra...)
}

// TestHTTP2_SettingsOnWire: the server's SETTINGS carry the stream, frame and
// window limits and a header list limit near the request header limit.
func TestHTTP2_SettingsOnWire(t *testing.T) {
	e := newEnv(t, active())
	h := h2open(t, e.serve(t, true, nil))
	f := <-h.frames
	if f.typ != 4 {
		t.Fatalf("first frame type %d", f.typ)
	}
	got := map[uint16]uint32{}
	for i := 0; i+6 <= len(f.p); i += 6 {
		got[binary.BigEndian.Uint16(f.p[i:])] = binary.BigEndian.Uint32(f.p[i+2:])
	}
	t.Logf("server SETTINGS %v", got)
	if got[3] != maxH2Streams || got[4] != maxH2StreamWindow || got[5] != maxH2Frame {
		t.Errorf("SETTINGS %v", got)
	}
	if l := got[6]; l < 32<<10 || l > 48<<10 {
		t.Errorf("header list limit %d", l)
	}
}

// TestHTTP2_FrameOverMaxIsConnectionError: a frame of exactly the maximum is
// served; one byte more ends the connection with FRAME_SIZE_ERROR and the
// server keeps serving others.
func TestHTTP2_FrameOverMaxIsConnectionError(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	addr := e.serve(t, true, nil)
	tok := a.anon.token(t, "anon")
	for _, size := range []int{maxH2Frame, maxH2Frame + 1} {
		fields := getFields(tok, [2]string{"x-pad", ""})
		base := len(hpackBlock(fields))
		pad := size - base
		for len(hpackBlock(getFields(tok, [2]string{"x-pad", strings.Repeat("p", pad)}))) > size {
			pad--
		}
		fields = getFields(tok, [2]string{"x-pad", strings.Repeat("p", pad)})
		if n := len(hpackBlock(fields)); n != size {
			t.Fatalf("block %d, want %d", n, size)
		}
		h := h2open(t, addr)
		h.headers(1, fields, true, size)
		got := h.wait(t, 1, 3*time.Second)
		want := `data:{"ok":true}`
		if size > maxH2Frame {
			want = "goaway:6"
		}
		if got != want {
			t.Errorf("HEADERS of %d bytes: %s, want %s", size, got, want)
		}
	}
	if got := h2do(t, addr, hostA, getFields(tok)); got != `{"ok":true}` {
		t.Errorf("after the connection error: %q", got)
	}
}

// TestHTTP2_HeaderBlockAcrossContinuation: a header block near the request
// header limit split over CONTINUATION frames is served; one over it is
// answered 431 and the connection stays usable; an endless CONTINUATION
// sequence ends the connection after a bounded amount.
func TestHTTP2_HeaderBlockAcrossContinuation(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	addr := e.serve(t, true, nil)
	tok := a.anon.token(t, "anon")
	h := h2open(t, addr)
	h.headers(1, getFields(tok, [2]string{"x-pad", strings.Repeat("p", 30<<10)}), true, maxH2Frame)
	if got := h.wait(t, 1, 3*time.Second); got != `data:{"ok":true}` {
		t.Errorf("30 KiB header block: %s", got)
	} else if g := e.requests(); len(g) != 1 || len(g[0].Header.Get("X-Pad")) != 30<<10 {
		t.Errorf("upstream did not get the 30 KiB header")
	}
	// Over the limit: 431 when the excess is in the last frame, otherwise a
	// connection error (PROTOCOL_ERROR once the limit is spent, COMPRESSION_ERROR
	// for one field longer than the limit). Either way nothing reaches the
	// upstream and other connections are served.
	var many [][2]string
	for i := range 40 {
		many = append(many, [2]string{fmt.Sprintf("x-pad-%d", i), strings.Repeat("p", 1<<10)})
	}
	for name, fields := range map[string][][2]string{
		"40 KiB in 1 KiB fields": getFields(tok, many...),
		"one 40 KiB field":       getFields(tok, [2]string{"x-pad", strings.Repeat("p", 40<<10)}),
	} {
		e.reset()
		h := h2open(t, addr)
		h.headers(1, fields, true, maxH2Frame)
		got := h.wait(t, 1, 3*time.Second)
		t.Logf("%s: %s", name, got)
		if !strings.Contains(got, "431") && got != "goaway:1" && got != "goaway:9" {
			t.Errorf("%s: %s", name, got)
		}
		if len(e.requests()) != 0 {
			t.Errorf("%s: reached the upstream", name)
		}
	}
	if got := h2do(t, addr, hostA, getFields(tok)); got != `{"ok":true}` {
		t.Errorf("after the refusals: %q", got)
	}

	f := h2open(t, addr)
	f.frame(1, 1, 1, hpackBlock(getFields(tok)[:2]))
	var sent atomic.Int64
	go func() {
		chunk := hpackBlock([][2]string{{"x-flood", strings.Repeat("f", maxH2Frame-20)}})
		for sent.Load() < 64<<20 {
			f.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := f.frame(9, 0, 1, chunk); err != nil {
				return
			}
			sent.Add(int64(len(chunk) + 9))
		}
	}()
	got := f.wait(t, 1, 10*time.Second)
	t.Logf("CONTINUATION flood: %s after %d bytes written", got, sent.Load())
	if !strings.HasPrefix(got, "goaway:") && got != "eof" {
		t.Errorf("CONTINUATION flood: %s", got)
	}
	if sent.Load() >= 64<<20 {
		t.Errorf("server read %d bytes of one header block", sent.Load())
	}
}

// TestHTTP2_ReadTimeoutPerStream: over HTTP/2 the read timeout runs per
// stream: a stream whose body never comes is cut, other streams on the same
// connection are served.
func TestHTTP2_ReadTimeoutPerStream(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	addr := e.serve(t, true, func(s *http.Server) { s.ReadTimeout = 300 * time.Millisecond })
	tok := a.anon.token(t, "anon")
	h := h2open(t, addr)
	h.headers(1, [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", hostA},
		{":path", "/rest/v1/t"}, {"apikey", tok}, {"content-length", "10"}}, false, maxH2Frame)
	got := h.wait(t, 1, 5*time.Second)
	t.Logf("stream without its body: %s", got)
	if !strings.Contains(got, "bad_request") && !strings.HasPrefix(got, "reset:") {
		t.Errorf("stream without its body: %s", got)
	}
	h.headers(3, getFields(tok), true, maxH2Frame)
	if got := h.wait(t, 3, 3*time.Second); got != `data:{"ok":true}` {
		t.Errorf("next stream on the connection: %s", got)
	}
	if len(e.requests()) != 1 {
		t.Errorf("upstream saw %d requests, want 1", len(e.requests()))
	}
	eventually(t, func() bool { return idle(e) }, "slots not returned")
}

// TestHasDomain covers the Set-Cookie attribute syntax browsers accept.
func TestHasDomain(t *testing.T) {
	for v, want := range map[string]bool{
		"a=1; Domain=sp.test":                true,
		"a=1;Domain=sp.test":                 true,
		"a=1; domain=sp.test":                true,
		"a=1; DoMaIn = sp.test":              true,
		"a=1; Path=/;\tDomain=sp.test":       true,
		"a=1; Domain=":                       true, // browsers ignore it; dropping is safe
		"a=1; Domain":                        true,
		"a=1; Secure; Domain=.sp.test; Path": true,
		"a=\"x;y\"; Domain=sp.test":          true,
		"a=1, b=2; Domain=sp.test":           true,
		"noequals; Domain=sp.test":           true,
		"a=1; Path=/; ;; Domain=sp.test":     true,
		"a=1":                                false,
		"domain=sp.test":                     false,
		"a=domain; Path=/domain":             false,
		"a=1; Path=/; X-Domain=sp.test":      false,
		"a=1; Domains=sp.test":               false,
		"a=1; Path=/; Secure; HttpOnly":      false,
		"a=1; SameSite=Lax; Max-Age=60":      false,
		"":                                   false,
	} {
		if hasDomain(v) != want {
			t.Errorf("hasDomain(%q) = %v, want %v", v, !want, want)
		}
	}
}

// TestForward_CookieHeaderCasing: the upstream's header name casing does not
// matter, and the filter holds over HTTP/2 to the client.
func TestForward_CookieHeaderCasing(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	rawUpstream(t, e, func(c net.Conn) {
		io.WriteString(c, "HTTP/1.1 200 OK\r\nset-cookie: a=1; Domain=sp.test\r\nSET-COOKIE: b=2; domain=sp.test\r\n"+
			"Set-Cookie: c=3; Path=/\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := e.serve(t, true, nil)
	for _, h2 := range []bool{false, true} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: hostA}, ForceAttemptHTTP2: h2}
		if !h2 {
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		r, _ := http.NewRequest("GET", "https://"+addr+"/rest/v1/t", nil)
		r.Host = hostA
		r.Header.Set("apikey", a.anon.token(t, "anon"))
		res, err := (&http.Client{Transport: tr}).Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		tr.CloseIdleConnections()
		if got := res.Header.Values("Set-Cookie"); res.StatusCode != 200 || len(got) != 1 || got[0] != "c=3; Path=/" {
			t.Errorf("%s: %d Set-Cookie %q", res.Proto, res.StatusCode, got)
		}
	}
}

// rawUpstream points every upstream dial of e at a listener whose
// connections are answered by f after the request header is read; it
// returns the count of accepted connections.
func rawUpstream(t *testing.T, e *env, f func(net.Conn)) *atomic.Int32 {
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
					f(c)
				}
			}()
		}
	}()
	e.gw.transport.CloseIdleConnections()
	e.gw.transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}
	return n
}

// TestForward_InformationalHeadersFiltered: a 1xx response the upstream
// sends before its final one carries no Domain cookie and no Server header
// to the client either. The proxy relays 1xx headers without ModifyResponse.
func TestForward_InformationalHeadersFiltered(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	rawUpstream(t, e, func(c net.Conn) {
		io.WriteString(c, "HTTP/1.1 103 Early Hints\r\nSet-Cookie: x=1; Domain=sp.test\r\nServer: up/1\r\n\r\n"+
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := e.serve(t, false, nil)
	out := raw(t, addr, "GET /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+a.anon.token(t, "anon")+"\r\nConnection: close\r\n\r\n")
	t.Logf("client got:\n%s", out)
	if strings.Contains(strings.ToLower(out), "domain=") || strings.Contains(out, "up/1") {
		t.Errorf("1xx headers reached the client unfiltered")
	}
}

// TestForward_UpstreamHeaderLimitShapes: many small header fields and one
// large one both hit the limit; the 502 is the gateway's own, the slots come
// back and the upstream connection is not reused; 1xx responses do not add
// up against the final response's limit.
func TestForward_UpstreamHeaderLimitShapes(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	var mode atomic.Value
	mode.Store("")
	conns := rawUpstream(t, e, func(c net.Conn) {
		var b strings.Builder
		switch mode.Load().(string) {
		case "many":
			b.WriteString("HTTP/1.1 200 OK\r\n")
			for i := range 4000 {
				fmt.Fprintf(&b, "X-H%d: v\r\n", i)
			}
		case "one":
			b.WriteString("HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("b", 33<<10) + "\r\n")
		case "1xx":
			for range 3 {
				b.WriteString("HTTP/1.1 103 Early Hints\r\nLink: " + strings.Repeat("l", 20<<10) + "\r\n\r\n")
			}
			b.WriteString("HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("b", 20<<10) + "\r\n")
		case "1xx-big":
			b.WriteString("HTTP/1.1 103 Early Hints\r\nLink: " + strings.Repeat("l", 40<<10) + "\r\n\r\n")
			b.WriteString("HTTP/1.1 200 OK\r\n")
		default:
			b.WriteString("HTTP/1.1 200 OK\r\n")
		}
		b.WriteString("Content-Length: 2\r\n\r\nok")
		io.WriteString(c, b.String())
	})
	tok := a.anon.token(t, "anon")
	get := func() *httptest.ResponseRecorder {
		return e.do(withKey(req("GET", hostA, "/rest/v1/t", nil), tok))
	}
	if w := get(); w.Code != 200 {
		t.Fatalf("control: %d", w.Code)
	}
	before := conns.Load()
	for _, m := range []string{"many", "one", "1xx-big"} {
		mode.Store(m)
		w := get()
		if w.Code != 502 || strings.TrimSpace(w.Body.String()) != `{"code":"upstream_unavailable"}` || len(w.Header()) > 3 {
			t.Errorf("%s: %d %.80q, %d header fields", m, w.Code, w.Body, len(w.Header()))
		}
		if !idle(e) {
			t.Errorf("%s: slot held after the 502", m)
		}
	}
	mode.Store("")
	if w := get(); w.Code != 200 {
		t.Errorf("after the 502s: %d", w.Code)
	}
	// The first over-limit response arrives on the control request's idle
	// connection; every request after an over-limit response dials anew.
	if n := conns.Load() - before; n != 3 {
		t.Errorf("%d new upstream connections, want 3: a connection was reused after an over-limit header", n)
	}
	mode.Store("1xx")
	out := raw(t, e.serve(t, false, nil), "GET /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+tok+"\r\nConnection: close\r\n\r\n")
	if strings.Count(out, " 103 ") != 3 || !strings.Contains(out, "HTTP/1.1 200 OK") || !strings.Contains(out, strings.Repeat("b", 20<<10)) {
		t.Errorf("1xx then a final response, each under the limit: %.200q", out)
	}
}

// TestServer_ConcurrentMixedTraffic drives keep-alive HTTP/1.1, multiplexed
// HTTP/2, aborted uploads, refused requests, upstream failures, 100-continue
// and upgrade attempts at once; run under -race it shows nothing reads the
// request header after the handler has returned.
func TestServer_ConcurrentMixedTraffic(t *testing.T) {
	a, b, _ := keys()
	e := newEnv(t, active())
	e.gw.projectCap = 6 // some requests are refused 429
	_, release := holdUpstream(t, e, true)
	close(release)
	addr := e.serve(t, true, nil)
	clients := map[bool]*http.Client{}
	for _, h2 := range []bool{false, true} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: h2, MaxConnsPerHost: 4, ExpectContinueTimeout: time.Second}
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
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i := range 800 {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			host, key, path, method := hostA, anonA, "/rest/v1/ok", "GET"
			var body io.Reader
			hdr := http.Header{}
			switch i % 8 {
			case 1:
				host, key = hostB, anonB // upstream refuses
			case 2: // client aborts mid-body
				pr, pw := io.Pipe()
				method, body = "POST", pr
				go func() {
					pw.Write(make([]byte, 64<<10))
					cancel()
					pw.CloseWithError(io.ErrUnexpectedEOF)
				}()
			case 3:
				method, body = "POST", bytes.NewReader(make([]byte, 4<<10))
				hdr.Set("Expect", "100-continue")
			case 4:
				hdr.Set("Upgrade", "websocket")
				hdr.Set("Connection", "Upgrade")
			case 5:
				key = "x"
			case 6:
				method, body = "POST", bytes.NewReader(make([]byte, maxBody+1))
			case 7:
				path = "/rest/v1/abort"
			}
			r, _ := http.NewRequestWithContext(ctx, method, "https://"+host+path, body)
			r.Host = host
			for k, v := range hdr {
				r.Header[k] = v
			}
			r.Header.Set("apikey", key)
			r.Header.Set("X-Pad", strings.Repeat("p", 512))
			if res, err := clients[i%3 != 0].Do(r); err == nil {
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
		}()
	}
	wg.Wait()
	eventually(t, func() bool { return idle(e) }, "in-flight slots leaked")
}
