package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestForward_UnrequestedSwitchRefused: a 101 the client did not ask for is
// answered with the gateway's 502, over HTTP/1.1 and HTTP/2; nothing is
// tunnelled.
func TestForward_UnrequestedSwitchRefused(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	for _, up := range []string{"", "Upgrade: websocket\r\nConnection: Upgrade\r\n", "Connection: Upgrade\r\n"} {
		rawUpstream(t, e, func(c net.Conn) {
			io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n"+up+"Set-Cookie: s=1; Domain=sp.test\r\n\r\nTUNNEL")
		})
		addr := e.serve(t, true, nil)
		for _, h2 := range []bool{false, true} {
			r, _ := http.NewRequest("GET", "https://"+hostA+"/rest/v1/t", nil)
			r.Header.Set("apikey", a.anon.token(t, "anon"))
			res, err := clientFor(t, addr, h2).Do(r)
			if err != nil {
				t.Fatalf("%q h2=%v: %v", up, h2, err)
			}
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != 502 || strings.TrimSpace(string(b)) != `{"code":"upstream_unavailable"}` || res.Header.Get("Set-Cookie") != "" {
				t.Errorf("%q h2=%v: %d %q %v", up, h2, res.StatusCode, b, res.Header)
			}
		}
	}
	eventually(t, func() bool { return idle(e) }, "slots not returned")
}

// TestForward_FilterOnHeadAnd304AndUndeclaredTrailers: the filter also holds
// for a HEAD response, a 304 and trailers the upstream did not announce.
func TestForward_FilterOnHeadAnd304AndUndeclaredTrailers(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	addr := e.serve(t, true, nil)
	for _, cs := range []struct{ method, resp string }{
		{"HEAD", "HTTP/1.1 200 OK\r\nSet-Cookie: h=1; Domain=sp.test\r\nServer: up/1\r\nContent-Length: 5\r\n\r\n"},
		{"GET", "HTTP/1.1 304 Not Modified\r\nSet-Cookie: n=1; Domain=sp.test\r\nServer: up/1\r\n\r\n"},
		{"GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nSet-Cookie: u=1; Domain=sp.test\r\nServer: up/1\r\nX-U: 1\r\n\r\n"},
	} {
		rawUpstream(t, e, func(c net.Conn) { io.WriteString(c, cs.resp) })
		for _, h2 := range []bool{false, true} {
			r, _ := http.NewRequest(cs.method, "https://"+hostA+"/rest/v1/t", nil)
			r.Header.Set("apikey", a.anon.token(t, "anon"))
			res, err := clientFor(t, addr, h2).Do(r)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			all := fmt.Sprint(res.Header, res.Trailer)
			if strings.Contains(all, "Domain") || strings.Contains(all, "up/1") {
				t.Errorf("%s %.20q h2=%v: %d %s", cs.method, cs.resp[9:], h2, res.StatusCode, all)
			}
		}
	}
}

// TestForward_InformationalBurstsUnderLoad: concurrent requests whose
// upstream sends 0 to 12 1xx responses each, over both protocols, with some
// clients giving up early; slots and goroutines come back.
func TestForward_InformationalBurstsUnderLoad(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	rawUpstream(t, e, func(c net.Conn) {
		var b strings.Builder
		for range rand.IntN(13) {
			b.WriteString("HTTP/1.1 103 Early Hints\r\nLink: </a>\r\nSet-Cookie: x=1; Domain=sp.test\r\nServer: up\r\n\r\n")
		}
		b.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nSet-Cookie: t=1; Domain=sp.test\r\n\r\n")
		io.WriteString(c, b.String())
	})
	addr := e.serve(t, true, nil)
	tok := a.anon.token(t, "anon")
	clients := []*http.Client{clientFor(t, addr, false), clientFor(t, addr, true)}
	base := runtime.NumGoroutine()
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := range 600 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if i%10 == 0 {
				ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
			}
			defer cancel()
			r, _ := http.NewRequestWithContext(ctx, "GET", "https://"+hostA+"/rest/v1/t", nil)
			r.Header.Set("apikey", tok)
			res, err := clients[i%2].Do(r)
			code := 0
			if err == nil {
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				code = res.StatusCode
				if strings.Contains(fmt.Sprint(res.Header, res.Trailer), "Domain") {
					t.Errorf("Domain cookie reached the client")
				}
			}
			mu.Lock()
			codes[code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	t.Logf("codes %v", codes)
	eventually(t, func() bool { return idle(e) }, "slots not returned")
	// A transport finishes a dial whose request has gone and then keeps the
	// connection idle: such a connection can enter a pool after any one
	// close, so the pools are closed until the count settles.
	deadline := time.Now().Add(15 * time.Second)
	for {
		for _, c := range clients {
			c.Transport.(*http.Transport).CloseIdleConnections()
		}
		e.gw.transport.CloseIdleConnections()
		if runtime.NumGoroutine() <= base+10 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base+10 {
		t.Errorf("%d goroutines, %d before the load", n, base)
	}
}

// TestForward_InformationalThenClientReset: HTTP/2 clients reset their stream
// as soon as the first response header arrives (a relayed 1xx, were the
// gateway to relay one over HTTP/2 again), while the server may still be
// encoding the next one from the response's header map; the handler learns of
// the reset before that encoding ends. Under the race detector a proxy that
// changes the map afterwards fails this test (a race in most runs of 200
// streams; the detector reports a given pair of stacks once per process).
func TestForward_InformationalThenClientReset(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	rawUpstream(t, e, func(c net.Conn) {
		io.WriteString(c, strings.Repeat("HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n", maxInformational)+"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	h := h2open(t, e.serve(t, true, nil))
	tok := a.anon.token(t, "anon")
	timeout := time.After(30 * time.Second)
	for sid := uint32(1); sid < 400; sid += 2 {
		h.headers(sid, getFields(tok), true, 16<<10)
	wait:
		for {
			select {
			case f, ok := <-h.frames:
				if !ok {
					t.Fatal("connection closed")
				}
				if f.sid == sid && f.typ == 1 {
					break wait
				}
			case <-timeout:
				t.Fatal("no 1xx")
			}
		}
		h.frame(3, 0, sid, []byte{0, 0, 0, 8}) // RST_STREAM CANCEL
	}
	eventually(t, func() bool { return idle(e) }, "slots not returned")
}

// TestForward_InformationalThenClientCloses: HTTP/2 clients close their whole
// connection as soon as the first response header arrives (a relayed 1xx,
// were the gateway to relay one over HTTP/2 again). The server then stops waiting
// for the 1xx frame it is writing and only afterwards cancels the requests,
// so for a moment a handler cannot tell that the frame may still be read from
// the response's header map. Under the race detector a proxy that changes the
// map in that moment fails this test.
func TestForward_InformationalThenClientCloses(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	rawUpstream(t, e, func(c net.Conn) {
		io.WriteString(c, strings.Repeat("HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n", maxInformational)+"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := e.serve(t, true, nil)
	tok := a.anon.token(t, "anon")
	timeout := time.After(60 * time.Second)
	for i := range 500 {
		h := h2open(t, addr)
		for sid := uint32(1); sid < 2*maxH2Streams; sid += 2 {
			h.headers(sid, getFields(tok), true, 16<<10)
		}
	wait:
		for {
			select {
			case f, ok := <-h.frames:
				if !ok {
					t.Fatal("connection closed")
				}
				if f.typ == 1 {
					break wait
				}
			case <-timeout:
				t.Fatal("no 1xx")
			}
		}
		if i%2 == 0 {
			h.c.NetConn().Close() // no TLS close first
		} else {
			h.c.Close()
		}
	}
	eventually(t, func() bool { return idle(e) }, "slots not returned")
}

// TestForward_BodyLimitWhileRelaying: an HTTP/1.1 client streams a chunked
// body past the limit while the upstream sends 1xx responses and its final
// one at about the moment the limit is reached. The body is read on the
// upstream connection's writing goroutine, responses are relayed from its
// reading goroutine and from the handler's: under the race detector a
// gateway whose body reader touches the response from the first of them
// fails this test.
func TestForward_BodyLimitWhileRelaying(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	// The upstream answers once it has received all but early bytes of the
	// limit: the gateway is that far ahead of what the upstream has seen.
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
					time.Sleep(20 * time.Microsecond)
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				io.Copy(io.Discard, c)
			}(maxBody - <-early)
		}
	}()
	e.gw.transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}
	addr := e.serve(t, false, nil)
	tok := a.anon.token(t, "anon")
	chunk := "10000\r\n" + strings.Repeat("x", 64<<10) + "\r\n"
	for i := range 18 {
		early <- i * (32 << 10)
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, "POST /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+tok+"\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n")
		for range maxBody/(64<<10) + 1 {
			if _, err := io.WriteString(c, chunk); err != nil {
				break
			}
		}
		io.WriteString(c, "0\r\n\r\n")
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		b, _ := io.ReadAll(c)
		c.Close()
		// The upstream's 200 or the gateway's 413, whichever came first.
		if s := string(b); !strings.Contains(s, "HTTP/1.1 200 ") && !strings.Contains(s, "HTTP/1.1 413 ") {
			t.Errorf("upstream answering %d bytes early: %.80q", i*(32<<10), s)
		}
	}
	eventually(t, func() bool { return idle(e) }, "slots not returned")
}

// TestServer_BodyLimitStillSending: an HTTP/1.1 client that keeps streaming a
// chunked body past the limit while it waits receives the complete 413: the
// server is told of the limit and closes the connection only after the
// answer, giving the client time to read it.
func TestServer_BodyLimitStillSending(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	addr := e.serve(t, false, nil)
	tok := a.anon.token(t, "anon")
	chunk := "10000\r\n" + strings.Repeat("x", 64<<10) + "\r\n"
	for i := range 20 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		go func() { // the connection's only writer
			io.WriteString(c, "POST /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+tok+"\r\nTransfer-Encoding: chunked\r\n\r\n")
			for range 2 * maxBody / (64 << 10) {
				if _, err := io.WriteString(c, chunk); err != nil {
					return
				}
			}
		}()
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		b, err := io.ReadAll(c)
		c.Close()
		// The answer ends in the server's own close of its sending side: a
		// reset here means it closed without waiting for the client to read.
		if s := string(b); err != nil || !strings.HasPrefix(s, "HTTP/1.1 413 ") || !strings.HasSuffix(s, `{"code":"body_too_large"}`) {
			t.Errorf("request %d: %v %q", i, err, s)
		}
	}
	eventually(t, func() bool { return idle(e) }, "slots not returned")
}

// TestForward_InformationalWhileExpectContinue: an HTTP/1.1 client that sent
// Expect: 100-continue gets the server's own 100 Continue, which the server
// writes from the goroutine that first reads the body, and no upstream 1xx:
// one relayed at that moment from the upstream connection's reading goroutine
// would use the connection's write buffer at the same time (a garbled or lost
// answer; a race under the detector). Without Expect the 1xx are relayed.
func TestForward_InformationalWhileExpectContinue(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
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
	e.gw.transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}
	addr := e.serve(t, false, nil)
	tok := a.anon.token(t, "anon")
	for _, cs := range []struct{ expect, informational string }{
		{"Expect: 100-continue\r\n", "HTTP/1.1 100 Continue\r\n\r\n"},
		{"", strings.Repeat(hint, 3)},
	} {
		for i := range 200 {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			io.WriteString(c, "POST /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+tok+"\r\n"+cs.expect+
				"Content-Length: 5\r\nConnection: close\r\n\r\n")
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			br := bufio.NewReader(c)
			first, _ := br.ReadString('\n') // the client waits for a 1xx before its body
			io.WriteString(c, "hello")
			rest, _ := io.ReadAll(br)
			c.Close()
			got := first + string(rest)
			if !strings.HasPrefix(got, cs.informational+"HTTP/1.1 200 OK\r\n") || !strings.HasSuffix(got, "\r\n\r\nok") {
				t.Fatalf("%q request %d: %q", cs.expect, i, got)
			}
		}
	}
	eventually(t, func() bool { return idle(e) }, "slots not returned")
}
