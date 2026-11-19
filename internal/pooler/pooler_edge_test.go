package pooler

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// counted wraps a pipe end and counts its closes.
type counted struct {
	net.Conn
	mu     sync.Mutex
	closes int
}

func (c *counted) Close() error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()
	return c.Conn.Close()
}

// stalled serves a pipe with script(s) and reports when the client closed.
func stalled(script func(s net.Conn), closed chan<- struct{}) func(context.Context) (net.Conn, error) {
	return func(context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			script(s)
			io.Copy(io.Discard, s) // until the client closes
			close(closed)
		}()
		return c, nil
	}
}

func readReq(s net.Conn) { http.ReadRequest(bufio.NewReader(s)) }

func TestClient_StallOnEveryPathEndsWithTheContext(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script func(s net.Conn)
		keep   bool // the ban list read (its body is kept)
		want   error
	}{
		// The server reads nothing: the request's write blocks.
		{"write", func(net.Conn) {}, false, ErrUnavailable},
		// The request is read, half a status line is sent.
		{"status", func(s net.Conn) { readReq(s); io.WriteString(s, "HTTP/1.1 2") }, false, ErrUnavailable},
		// Headers are never ended.
		{"headers", func(s net.Conn) { readReq(s); io.WriteString(s, "HTTP/1.1 200 OK\r\nX-A: b\r\n") }, false, ErrUnavailable},
		// A success whose body never comes: the status is the answer.
		{"body", func(s net.Conn) {
			readReq(s)
			io.WriteString(s, "HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n")
		}, false, nil},
		// The ban list's body never comes: no list, no DELETE.
		{"list", func(s net.Conn) { readReq(s); io.WriteString(s, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n{") }, true, ErrUnavailable},
	} {
		closed := make(chan struct{})
		dials := 0
		d := stalled(tc.script, closed)
		c := New(func(ctx context.Context) (net.Conn, error) { dials++; return d(ctx) }, []byte(testSecret))
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		start := time.Now()
		var err error
		if tc.keep {
			err = c.ClearBans(ctx, testRef, nil)
		} else {
			err = c.Terminate(ctx, testRef)
		}
		cancel()
		if took := time.Since(start); took > 3*time.Second {
			t.Fatalf("%s: the call took %v", tc.name, took)
		}
		if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Fatalf("%s: %v, want %v", tc.name, err, tc.want)
		}
		if dials != 1 {
			t.Fatalf("%s: %d dials", tc.name, dials)
		}
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: the connection was not closed", tc.name)
		}
	}
}

func TestClient_RequestCarriesTheSecretNowhereButTheSignature(t *testing.T) {
	var raw []string
	var mu sync.Mutex
	dial := func(context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			br := bufio.NewReader(s)
			r, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			b, _ := io.ReadAll(r.Body)
			var sb strings.Builder
			r.Header.Write(&sb)
			mu.Lock()
			raw = append(raw, r.Method+" "+r.RequestURI+" "+r.Host+"\n"+sb.String()+string(b))
			mu.Unlock()
			io.WriteString(s, answer(200, `{"banned_ipv4_addresses":[{"banned_address":"192.0.2.9"}]}`))
		}()
		return c, nil
	}
	c := New(dial, []byte(testSecret))
	ctx := context.Background()
	for _, err := range []error{c.Health(ctx), c.PutTenant(ctx, testRef, tenant()), c.Delete(ctx, testRef),
		c.ClearBans(ctx, testRef, nil)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	auth := regexp.MustCompile(`(?m)^Authorization: Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}\r$`)
	for _, r := range raw {
		if strings.Contains(r, testSecret) {
			t.Fatal("the API secret is in a request")
		}
		if len(auth.FindAllString(r, -1)) != 1 || strings.Count(r, "Bearer") != 1 {
			t.Fatal("the request does not carry exactly one bearer token of the constant form")
		}
		if first := strings.SplitN(r, "\n", 2)[0]; strings.ContainsAny(first, "?#%") || !strings.HasSuffix(first, " 127.0.0.1") {
			t.Fatalf("request line %q", first)
		}
	}
	if len(raw) != 6 {
		t.Fatalf("%d requests, want 6", len(raw))
	}
}

func TestClient_OneConnectionPerCallClosed(t *testing.T) {
	var conns []*counted
	f := &fake{t: t, answer: func(r seen) string {
		if r.method == http.MethodGet && strings.HasSuffix(r.path, "/network_bans") {
			return answer(200, `{"banned_ipv4_addresses":[{"banned_address":"192.0.2.9"}]}`)
		}
		return answer(200, "")
	}}
	c := New(func(ctx context.Context) (net.Conn, error) {
		n, err := f.dial(ctx)
		cc := &counted{Conn: n}
		conns = append(conns, cc)
		return cc, err
	}, []byte(testSecret))
	ctx := context.Background()
	if err := c.Delete(ctx, testRef); err != nil {
		t.Fatal(err)
	}
	if err := c.ClearBans(ctx, testRef, nil); err != nil {
		t.Fatal(err)
	}
	if len(conns) != 4 {
		t.Fatalf("%d connections for four requests", len(conns))
	}
	for i, cc := range conns {
		if cc.closes == 0 {
			t.Fatalf("connection %d not closed", i)
		}
	}
	// A failed write closes it too.
	cc := &counted{}
	c = New(func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		b.Close()
		cc.Conn = a
		return cc, nil
	}, []byte(testSecret))
	if err := c.Health(ctx); !errors.Is(err, ErrUnavailable) || cc.closes == 0 {
		t.Fatalf("broken pipe: %v, closes %d", err, cc.closes)
	}
}

func TestClient_AnswerShapes(t *testing.T) {
	list := `{"banned_ipv4_addresses":[{"banned_address":"192.0.2.9"}]}`
	for _, tc := range []struct {
		name, raw string
		want      error
		deletes   int
	}{
		// A chunked list is read whole.
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + hexLen(list) + "\r\n" + list + "\r\n0\r\n\r\n", nil, 1},
		// A broken chunk is no list.
		{"bad chunk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n" + list, ErrUnavailable, 0},
		// Bytes after the declared length are not read as the list.
		{"longer", "HTTP/1.1 200 OK\r\nContent-Length: " + itoa(len(list)) + "\r\n\r\n" + list + `garbage`, nil, 1},
		// A second answer behind the first is not read.
		{"second", answer(200, list) + answer(500, ""), nil, 1},
		// An interim answer is not a success.
		{"interim", "HTTP/1.1 100 Continue\r\n\r\n" + answer(200, list), ErrUnavailable, 0},
		// A redirect is not followed.
		{"redirect", "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://192.0.2.1/\r\nContent-Length: 0\r\n\r\n", ErrUnavailable, 0},
		// A status out of range.
		{"999", "HTTP/1.1 999 X\r\nContent-Length: 0\r\n\r\n", ErrUnavailable, 0},
	} {
		f, c := newFake(t, func(r seen) string {
			if r.method == http.MethodGet {
				return tc.raw
			}
			return answer(200, "")
		})
		err := c.ClearBans(context.Background(), testRef, nil)
		if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Fatalf("%s: %v, want %v", tc.name, err, tc.want)
		}
		del := 0
		for _, r := range f.requests() {
			if r.method == http.MethodDelete {
				del++
				if string(r.body) != `{"ipv4_addresses":["192.0.2.9"]}` {
					t.Fatalf("%s: body %s", tc.name, r.body)
				}
			}
		}
		if del != tc.deletes {
			t.Fatalf("%s: %d DELETEs", tc.name, del)
		}
	}
}

func hexLen(s string) string {
	const h = "0123456789abcdef"
	n := len(s)
	out := ""
	for n > 0 {
		out = string(h[n%16]) + out
		n /= 16
	}
	return out
}

func TestRef_NoPathOrQueryShapes(t *testing.T) {
	dialled := false
	c := New(func(context.Context) (net.Conn, error) { dialled = true; return nil, errors.New("no") }, []byte(testSecret))
	ctx := context.Background()
	for _, ref := range []string{"abcdefghij012345678?", "abcdefghij01234567%2", "abcdefghij012345678#",
		"abcdefghij012345678 ", "abcdefghij0123456789\n", "abcdefghij012345678.", "abcdefghij01234567-x"} {
		for _, err := range []error{c.PutTenant(ctx, ref, tenant()), c.Terminate(ctx, ref), c.Delete(ctx, ref),
			c.ClearBans(ctx, ref, nil)} {
			if err == nil || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRefused) {
				t.Fatalf("ref %q: %v", ref, err)
			}
		}
	}
	if dialled {
		t.Fatal("a refused ref dialled")
	}
}

func TestClearBans_AbsentTenantIsRefused(t *testing.T) {
	// Unlike terminate and delete, a clear of a tenant the pooler does not
	// know is not nil: the caller learns that nothing was cleared.
	_, c := newFake(t, func(seen) string { return answer(404, `{"error":"not found"}`) })
	for _, addrs := range [][]netip.Addr{nil, {netip.MustParseAddr("192.0.2.9")}} {
		if err := c.ClearBans(context.Background(), testRef, addrs); !errors.Is(err, ErrRefused) {
			t.Fatalf("addresses %v: %v", addrs, err)
		}
	}
}
