package wakesock

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// statusLine sends raw on a fresh connection and returns the answer's status
// line ("" when the connection is closed unanswered).
func statusLine(t *testing.T, path, raw string) string {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line)
}

// Only the exact path with a ref of the fixed form reaches the handler:
// other spellings of the target and bodies hidden behind framing do not.
func TestServe_OnlyTheExactTargetReachesTheHandler(t *testing.T) {
	h := &handler{}
	path := serve(t, os.Getuid(), h)
	hdr := "Host: wake\r\nContent-Length: 0\r\n\r\n"
	for name, raw := range map[string]string{
		"a query":           "POST /v1/wake/" + ref1 + "?x=1 HTTP/1.1\r\n" + hdr,
		"absolute form":     "POST http://wake/v1/wake/" + ref1 + " HTTP/1.1\r\n" + hdr,
		"an escaped ref":    "POST /v1/wake/%61aaaaaaaaaaaaaaaaaa1 HTTP/1.1\r\n" + hdr,
		"a doubled slash":   "POST //v1/wake/" + ref1 + " HTTP/1.1\r\n" + hdr,
		"a trailing slash":  "POST /v1/wake/" + ref1 + "/ HTTP/1.1\r\n" + hdr,
		"an upper-case ref": "POST /v1/wake/" + strings.ToUpper(ref1) + " HTTP/1.1\r\n" + hdr,
		"a chunked body":    "POST /v1/wake/" + ref1 + " HTTP/1.1\r\nHost: wake\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"length and chunked": "POST /v1/wake/" + ref1 + " HTTP/1.1\r\nHost: wake\r\nContent-Length: 0\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"idle query": "POST /v1/idle?x HTTP/1.1\r\nHost: wake\r\nContent-Length: 11\r\n\r\n{\"refs\":[]}",
	} {
		line := statusLine(t, path, raw)
		if strings.HasPrefix(line, "HTTP/1.1 204") {
			t.Errorf("%s: answered %q", name, line)
		}
	}
	if n, idles := h.calls(); n != 0 || len(idles) != 0 {
		t.Fatalf("refused shapes reached the handler: %d wakes, %v", n, idles)
	}
	// Control: the exact target.
	line := statusLine(t, path, "POST /v1/wake/"+ref1+" HTTP/1.1\r\n"+hdr)
	if n, _ := h.calls(); !strings.HasPrefix(line, "HTTP/1.1 204") || n != 1 {
		t.Fatalf("control: %q, %d wakes", line, n)
	}
}

// At most 16 connections are open: a seventeenth waits until one of them is
// cut (a silent peer, at the header bound), then is answered.
func TestServe_SixteenConnectionsAtMost(t *testing.T) {
	path := serve(t, os.Getuid(), &handler{})
	for range maxConns {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	start := time.Now()
	if err := NewClient(path).Wake(context.Background(), ref1); err != nil {
		t.Fatalf("the seventeenth: %v", err)
	}
	// Positive wait: the silent sixteen hold the places until the header bound.
	if el := time.Since(start); el < peerWindow-200*time.Millisecond {
		t.Errorf("the seventeenth was answered after %v, before a place was free", el)
	}
}

// A body that stops arriving is cut by the body bound; the handler is not called.
func TestServe_SlowBodyCut(t *testing.T) {
	h := &handler{}
	path := serve(t, os.Getuid(), h)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	io.WriteString(c, "POST /v1/idle HTTP/1.1\r\nHost: wake\r\nContent-Length: 100\r\n\r\n{")
	start := time.Now()
	io.Copy(io.Discard, c) // until the listener closes or answers and closes
	if el := time.Since(start); el > 20*time.Second {
		t.Errorf("a slow body held the connection %v", el)
	}
	if _, idles := h.calls(); len(idles) != 0 {
		t.Errorf("a partial body reached the handler: %v", idles)
	}
}

// An Idle handler that does not return is answered at WakeBound too.
func TestServe_BoundsTheIdleHandler(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	path := serve(t, os.Getuid(), idleStall{release})
	start := time.Now()
	c := rawClient(path)
	c.Timeout = WakeBound + 20*time.Second
	code := 0
	if resp, err := c.Post("http://wake/v1/idle", "", strings.NewReader(`{"refs":["`+ref1+`"]}`)); err == nil {
		code = resp.StatusCode
		resp.Body.Close()
	}
	if el := time.Since(start); code != 504 || el < WakeBound-100*time.Millisecond || el > WakeBound+20*time.Second {
		t.Errorf("a stalled Idle: %d after %v, want 504 at %v", code, el, WakeBound)
	}
}

type idleStall struct{ release chan struct{} }

func (idleStall) Wake(context.Context, string) error { return nil }
func (s idleStall) Idle(context.Context, []string)   { <-s.release }

// Anything at the path that is not a socket is left alone and refused.
func TestServe_LeavesAFileThatIsNotASocket(t *testing.T) {
	path := sockPath(t)
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Serve(ctx, path, os.Getuid(), &handler{}); err == nil {
		t.Fatal("Serve over a plain file: no error")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "keep" {
		t.Errorf("the file was touched: %q %v", b, err)
	}
}
