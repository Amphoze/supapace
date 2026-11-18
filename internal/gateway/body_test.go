package gateway

import (
	"bufio"
	"context"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestServer_UpstreamRefusedExpectContinue: when the upstream refuses the
// connection, a client that asked before sending its body gets the 502 at
// once and no 100 Continue, so it never uploads a body nobody will read.
func TestServer_UpstreamRefusedExpectContinue(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, active())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	down := ln.Addr().String()
	ln.Close()
	e.gw.transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", down)
	}
	addr := e.serve(t, false, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "POST /rest/v1/t HTTP/1.1\r\nHost: "+hostA+"\r\napikey: "+a.anon.token(t, "anon")+
		"\r\nExpect: 100-continue\r\nContent-Length: 1048576\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.HasPrefix(line, "HTTP/1.1 502 ") {
		t.Errorf("upstream down, Expect: 100-continue: first line %q, want the 502", strings.TrimSpace(line))
	}
}

// TestServer_AbortLeavesNoGoroutines: the stalled-body cases, aborted on
// both protocols, leave no goroutine behind once their servers are closed.
func TestServer_AbortLeavesNoGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	TestServer_StalledBodyNotBlamedOnUpstream(t)
	n := 0
	for range 200 {
		if n = runtime.NumGoroutine(); n <= before+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	buf := make([]byte, 1<<20)
	t.Errorf("goroutines: %d before, %d after\n%s", before, n, buf[:runtime.Stack(buf, true)])
}
