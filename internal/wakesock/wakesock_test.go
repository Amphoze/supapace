package wakesock

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const ref1 = "aaaaaaaaaaaaaaaaaaa1"

// handler is a stand-in for the daemon's half.
type handler struct {
	mu    sync.Mutex
	wakes []string
	idles [][]string
	wake  func(ctx context.Context, ref string) error
}

func (h *handler) Wake(ctx context.Context, ref string) error {
	h.mu.Lock()
	h.wakes = append(h.wakes, ref)
	f := h.wake
	h.mu.Unlock()
	if f == nil {
		return nil
	}
	return f(ctx, ref)
}

func (h *handler) Idle(ctx context.Context, refs []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.idles = append(h.idles, refs)
}

func (h *handler) calls() (wakes int, idles [][]string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.wakes), append([][]string(nil), h.idles...)
}

// sockPath is a fresh socket path short enough for a Unix socket address.
func sockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "wk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, SocketName)
}

// serve runs Serve on a fresh socket until the test ends and returns its path
// once the socket is in its final state: Serve listens first and then sets the
// mode, so the file exists, with the mode of the umask, before it is 0660.
func serve(t *testing.T, uid int, h Handler) string {
	t.Helper()
	path := sockPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, path, uid, h) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Error("Serve did not return after its context ended")
		}
	})
	last := "no socket"
	for deadline := time.Now().Add(30 * time.Second); ; {
		if fi, err := os.Stat(path); err == nil {
			if fi.Mode().Perm() == 0o660 {
				return path
			}
			last = "socket mode " + fi.Mode().Perm().String()
		}
		select {
		case err := <-done:
			t.Fatalf("Serve returned before listening: %v", err)
		case <-time.After(5 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("not within 30 s: a socket of mode 0660 (%s)", last)
		}
	}
}

// rawClient speaks HTTP over the socket without any bound of its own.
func rawClient(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}}}
}

func post(t *testing.T, c *http.Client, target, body string) (int, string) {
	t.Helper()
	resp, err := c.Post("http://wake"+target, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestServe_BoundsTheHandler(t *testing.T) {
	ended := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h := &handler{wake: func(ctx context.Context, _ string) error {
		<-ctx.Done()
		close(ended)
		<-release // never returns while the test looks
		return nil
	}}
	path := serve(t, os.Getuid(), h)
	start := time.Now()
	type res struct {
		code int
		err  error
	}
	got := make(chan res, 1)
	go func() {
		resp, err := rawClient(path).Post("http://wake/v1/wake/"+ref1, "", nil)
		if err != nil {
			got <- res{0, err}
			return
		}
		resp.Body.Close()
		got <- res{resp.StatusCode, nil}
	}()
	select {
	case r := <-got:
		if r.err != nil || r.code != http.StatusGatewayTimeout {
			t.Fatalf("answer %d %v, want 504", r.code, r.err)
		}
	case <-time.After(WakeBound + 30*time.Second):
		t.Fatal("a handler that never returns was never answered")
	}
	if el := time.Since(start); el < WakeBound-100*time.Millisecond {
		t.Errorf("answered after %v, before the bound %v", el, WakeBound)
	}
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Error("the handler's context was not ended")
	}
}

// Control: a handler that returns in time is answered by its result.
func TestServe_AnswersByTheHandlersResult(t *testing.T) {
	for _, c := range []struct {
		err  error
		code int
	}{{nil, 204}, {ErrBusy, 409}, {ErrFailed, 504}, {errors.New("other"), 504}} {
		h := &handler{wake: func(context.Context, string) error { return c.err }}
		path := serve(t, os.Getuid(), h)
		if code, _ := post(t, rawClient(path), "/v1/wake/"+ref1, ""); code != c.code {
			t.Errorf("handler %v: %d, want %d", c.err, code, c.code)
		}
	}
}

func TestServe_PeerOfAnotherUidClosedUnanswered(t *testing.T) {
	for _, own := range []bool{false, true} {
		uid := os.Getuid()
		if !own {
			uid++
		}
		h := &handler{}
		path := serve(t, uid, h)
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(20 * time.Second))
		fmt.Fprintf(c, "POST /v1/wake/%s HTTP/1.1\r\nHost: wake\r\nContent-Length: 0\r\n\r\n", ref1)
		line, err := bufio.NewReader(c).ReadString('\n')
		c.Close()
		n, _ := h.calls()
		if own {
			if !strings.HasPrefix(line, "HTTP/1.1 204") || n != 1 { // control
				t.Errorf("own uid: %q %v, %d wakes", line, err, n)
			}
			continue
		}
		if line != "" || !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !isReset(err) || n != 0 {
			t.Errorf("another uid: answered %q (%v), %d wakes", line, err, n)
		}
	}
}

func isReset(err error) bool { return err != nil && strings.Contains(err.Error(), "connection reset") }

func TestServe_StrictBodies(t *testing.T) {
	h := &handler{}
	path := serve(t, os.Getuid(), h)
	c := rawClient(path)
	many := make([]string, MaxIdleRefs+1)
	for i := range many {
		many[i] = fmt.Sprintf("%q", fmt.Sprintf("%020d", i))
	}
	for _, x := range []struct {
		name, target, body string
		code               int
	}{
		{"unknown member", "/v1/idle", `{"refs":[],"x":1}`, 400},
		{"trailing data", "/v1/idle", `{"refs":[]}{}`, 400},
		{"not an object", "/v1/idle", `[]`, 400},
		{"bad ref", "/v1/idle", `{"refs":["AAAAAAAAAAAAAAAAAAAA"]}`, 400},
		{"over 1024 refs", "/v1/idle", `{"refs":[` + strings.Join(many, ",") + `]}`, 400},
		{"over 64 KiB", "/v1/idle", `{"refs":[]` + strings.Repeat(" ", maxBody) + `}`, 400},
		{"wake with a body", "/v1/wake/" + ref1, `{}`, 400},
		{"wake of a bad ref", "/v1/wake/" + ref1 + "x", ``, 404},
		{"wake of a dotted path", "/v1/wake/../idle", ``, 404},
		{"unknown path", "/v1/sleep", ``, 404},
	} {
		if code, _ := post(t, c, x.target, x.body); code != x.code {
			t.Errorf("%s: %d, want %d", x.name, code, x.code)
		}
	}
	resp, err := c.Get("http://wake/v1/wake/" + ref1)
	if err != nil || resp.StatusCode != 405 {
		t.Errorf("GET: %v %v", resp, err)
	}
	if n, idles := h.calls(); n != 0 || len(idles) != 0 {
		t.Fatalf("refused requests reached the handler: %d wakes, %v", n, idles)
	}
	// Control: the same paths with valid bodies.
	full := make([]string, MaxIdleRefs)
	copy(full, many)
	if code, _ := post(t, c, "/v1/idle", `{"refs":[`+strings.Join(full, ",")+`]}`); code != 204 {
		t.Errorf("1024 refs: %d", code)
	}
	if code, _ := post(t, c, "/v1/idle", `{"refs":["`+ref1+`"]}`); code != 204 {
		t.Errorf("one ref: %d", code)
	}
	if code, _ := post(t, c, "/v1/wake/"+ref1, ""); code != 204 {
		t.Errorf("wake: %d", code)
	}
	if n, idles := h.calls(); n != 1 || len(idles) != 2 || len(idles[0]) != MaxIdleRefs || idles[1][0] != ref1 {
		t.Errorf("valid requests: %d wakes, %d idles", n, len(idles))
	}
}

// A peer that sends nothing, or a header without end, is cut by the
// server's own bounds.
func TestServe_BoundsAPeer(t *testing.T) {
	path := serve(t, os.Getuid(), &handler{})
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	start := time.Now()
	n, err := c.Read(make([]byte, 1))
	if n != 0 || err == nil || isTimeout(err) {
		t.Fatalf("a silent peer: read %d %v", n, err)
	}
	if el := time.Since(start); el > 20*time.Second {
		t.Errorf("a silent peer was held %v", el)
	}
	resp, err := rawClient(path).Do(func() *http.Request {
		r, _ := http.NewRequest("POST", "http://wake/v1/idle", nil)
		r.Header.Set("X-Big", strings.Repeat("a", 9<<10))
		return r
	}())
	if err != nil || resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("a 9 KiB header: %v %v", resp, err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func TestClient_MapsAnswers(t *testing.T) {
	for _, c := range []struct {
		err, want error
	}{{nil, nil}, {ErrBusy, ErrBusy}, {ErrFailed, ErrFailed}} {
		path := serve(t, os.Getuid(), &handler{wake: func(context.Context, string) error { return c.err }})
		if err := NewClient(path).Wake(context.Background(), ref1); !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
			t.Errorf("handler %v: Wake %v", c.err, err)
		}
	}
	h := &handler{}
	path := serve(t, os.Getuid(), h)
	cl := NewClient(path)
	if err := cl.Idle(context.Background(), []string{ref1}); err != nil {
		t.Errorf("Idle: %v", err)
	}
	if err := cl.Wake(context.Background(), "../idle"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("a bad ref: %v", err)
	}
	if err := cl.Idle(context.Background(), make([]string, MaxIdleRefs+1)); err == nil || errors.Is(err, ErrUnavailable) {
		t.Errorf("more than 1,024 refs sent: %v", err)
	}
	if n, idles := h.calls(); n != 0 || len(idles) != 1 {
		t.Errorf("handler saw %d wakes, %v", n, idles)
	}
}

func TestClient_NoSocketSendsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), SocketName)
	cl := NewClient(path)
	if err := cl.Wake(context.Background(), ref1); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Wake: %v", err)
	}
	if err := cl.Idle(context.Background(), []string{ref1}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Idle: %v", err)
	}
	// A file that is not a socket is no socket either.
	os.WriteFile(path, nil, 0o600)
	if err := cl.Wake(context.Background(), ref1); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Wake on a plain file: %v", err)
	}
}

// A listener that never answers, or answers without end, holds the client
// no longer than WakeBound, and leaves no goroutine or descriptor behind.
func TestClient_BoundedAgainstAHostileListener(t *testing.T) {
	path := sockPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	stall := true
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			s := stall
			mu.Unlock()
			if s { // never answers; closes when the client does
				go func() { io.Copy(io.Discard, c); c.Close() }()
			} else { // a header without end
				go func() {
					defer c.Close()
					io.WriteString(c, "HTTP/1.1 204 No Content\r\n")
					for {
						if _, err := io.WriteString(c, "X-A: "+strings.Repeat("a", 1000)+"\r\n"); err != nil {
							return
						}
					}
				}()
			}
		}
	}()
	t.Cleanup(func() { ln.Close() })
	g0, f0 := runtime.NumGoroutine(), fds(t)
	cl := NewClient(path)
	start := time.Now()
	if err := cl.Wake(context.Background(), ref1); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a silent listener: %v", err)
	}
	if el := time.Since(start); el < WakeBound-100*time.Millisecond || el > WakeBound+20*time.Second {
		t.Errorf("a silent listener held the client %v", el)
	}
	mu.Lock()
	stall = false
	mu.Unlock()
	start = time.Now()
	if err := cl.Wake(context.Background(), ref1); !errors.Is(err, ErrUnavailable) {
		t.Errorf("an endless header: %v", err)
	}
	if el := time.Since(start); el > WakeBound/2 {
		t.Errorf("an endless header held the client %v", el)
	}
	settle(t, g0, f0)
}

// settle waits, bounded, for the goroutine and descriptor counts to return
// to their baselines.
func settle(t *testing.T, g0, f0 int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		g, f := runtime.NumGoroutine(), fds(t)
		if g <= g0 && f <= f0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutines %d (was %d), descriptors %d (was %d)", g, g0, f, f0)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func fds(t *testing.T) int {
	t.Helper()
	e, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	return len(e)
}

// The protocol is HTTP/1.1: an HTTP/1.0 request is refused before the handler.
func TestServe_RefusesHTTP10(t *testing.T) {
	h := &handler{}
	path := serve(t, os.Getuid(), h)
	for _, proto := range []string{"HTTP/1.0", "HTTP/1.1"} {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(20 * time.Second))
		fmt.Fprintf(c, "POST /v1/wake/%s %s\r\nHost: wake\r\nContent-Length: 0\r\n\r\n", ref1, proto)
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		want := "505"
		if proto == "HTTP/1.1" { // control
			want = "204"
		}
		if !strings.HasPrefix(line, "HTTP/1.") || !strings.Contains(line, " "+want+" ") {
			t.Errorf("%s: %q, want %s", proto, line, want)
		}
	}
	if n, _ := h.calls(); n != 1 {
		t.Errorf("%d wakes, want the HTTP/1.1 one", n)
	}
}
