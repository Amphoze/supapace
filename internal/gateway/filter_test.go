package gateway

import (
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
	for _, c := range clients {
		c.Transport.(*http.Transport).CloseIdleConnections()
	}
	e.gw.transport.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > base+10 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base+10 {
		t.Errorf("%d goroutines, %d before the load", n, base)
	}
}
