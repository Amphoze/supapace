package pooler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/poolcfg"
)

const (
	testRef    = "abcdefghij0123456789"
	testSecret = "an-api-secret-of-the-test-0123456789"
	marker     = "MARKER-manager-password-7f3c9"
)

// seen is one request the fake received.
type seen struct {
	method, path, proto, auth, ctype string
	body                             []byte
	closeConn                        bool
}

// fake serves each dialled connection on a pipe: it reads one request,
// records it, then writes answer(request) and closes.
type fake struct {
	t      *testing.T
	answer func(seen) string
	mu     sync.Mutex
	reqs   []seen
}

func (f *fake) dial(context.Context) (net.Conn, error) {
	c, s := net.Pipe()
	go func() {
		defer s.Close()
		r, err := http.ReadRequest(bufio.NewReader(s))
		if err != nil {
			return
		}
		b, _ := io.ReadAll(r.Body)
		q := seen{r.Method, r.URL.Path, r.Proto, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), b, r.Close}
		f.mu.Lock()
		f.reqs = append(f.reqs, q)
		f.mu.Unlock()
		io.WriteString(s, f.answer(q))
	}()
	return c, nil
}

func (f *fake) requests() []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seen(nil), f.reqs...)
}

func answer(status int, body string) string {
	return "HTTP/1.1 " + itoa(status) + " " + http.StatusText(status) + "\r\nContent-Length: " + itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func newFake(t *testing.T, fn func(seen) string) (*fake, *Client) {
	f := &fake{t: t, answer: fn}
	return f, New(f.dial, []byte(testSecret))
}

func tenant() poolcfg.Tenant {
	return poolcfg.Tenant{DBHost: netip.MustParseAddr("10.212.0.9"), DBPort: poolcfg.PoolPort(3),
		PoolSize: 5, MaxClients: 100, AllowList: poolcfg.OpenAllowList(), ManagerPassword: marker}
}

// verifyToken checks an HS256 token over testSecret and returns its claims.
func verifyToken(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	m := hmac.New(sha256.New, []byte(testSecret))
	m.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, m.Sum(nil)) {
		t.Fatalf("signature does not verify over the API secret")
	}
	var h map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if err := json.Unmarshal(hb, &h); err != nil || h["alg"] != "HS256" || h["typ"] != "JWT" || len(h) != 2 {
		t.Fatalf("header %s", hb)
	}
	var c map[string]any
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(cb, &c); err != nil {
		t.Fatalf("claims %s: %v", cb, err)
	}
	return c
}

func TestToken_HasExpiryAndVerifies(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tok := token([]byte(testSecret), now)
	c := verifyToken(t, tok)
	if exp, ok := c["exp"].(float64); !ok || int64(exp) != now.Unix()+60 || len(c) != 1 {
		t.Fatalf("claims %v, want exactly exp = now + 60", c)
	}
	// Control: another secret does not verify.
	other := token([]byte("another secret"), now)
	if other == tok || strings.Split(other, ".")[2] == strings.Split(tok, ".")[2] {
		t.Fatal("the signature does not depend on the secret")
	}
	// Each call is signed with the clock of the call.
	f, c2 := newFake(t, func(seen) string { return answer(204, "") })
	before := time.Now().Unix()
	if err := c2.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := f.requests()[0]
	cl := verifyToken(t, strings.TrimPrefix(r.auth, "Bearer "))
	if !strings.HasPrefix(r.auth, "Bearer ") || int64(cl["exp"].(float64)) < before+60 || int64(cl["exp"].(float64)) > time.Now().Unix()+60 {
		t.Fatalf("authorization not a bearer token of the call, claims %v", cl)
	}
}

func TestPutTenant_SendsExactBody(t *testing.T) {
	f, c := newFake(t, func(seen) string { return answer(201, `{"data":{}}`) })
	if err := c.PutTenant(context.Background(), testRef, tenant()); err != nil {
		t.Fatal(err)
	}
	want, err := tenant().Body()
	if err != nil {
		t.Fatal(err)
	}
	rs := f.requests()
	if len(rs) != 1 {
		t.Fatalf("%d requests", len(rs))
	}
	r := rs[0]
	if r.method != http.MethodPut || r.path != "/api/tenants/"+testRef || r.proto != "HTTP/1.1" ||
		r.ctype != "application/json" || !r.closeConn || !bytes.Equal(r.body, want) {
		t.Fatalf("request %s %s %s type %q close %v body %q", r.method, r.path, r.proto, r.ctype, r.closeConn, r.body)
	}
	verifyToken(t, strings.TrimPrefix(r.auth, "Bearer "))

	// An update is the same call: 200 is success too.
	f2, c2 := newFake(t, func(seen) string { return answer(200, "") })
	if err := c2.PutTenant(context.Background(), testRef, tenant()); err != nil || len(f2.requests()) != 1 {
		t.Fatalf("update: %v", err)
	}

	// Refusals before anything is dialled: a ref of another shape, a tenant
	// Body refuses (and its error does not carry the password).
	dialled := false
	c3 := New(func(context.Context) (net.Conn, error) { dialled = true; return nil, errors.New("no") }, []byte(testSecret))
	for _, ref := range []string{"", "ABCDEFGHIJ0123456789", testRef + "x", "abcdefghij012345678/", "../tenants/x0123456"} {
		if err := c3.PutTenant(context.Background(), ref, tenant()); err == nil {
			t.Fatalf("ref %q accepted", ref)
		}
	}
	bad := tenant()
	bad.AllowList = nil
	if err := c3.PutTenant(context.Background(), testRef, bad); err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("an incomplete tenant: %v", err)
	}
	if err := New(c3.dial, nil).PutTenant(context.Background(), testRef, tenant()); err == nil {
		t.Fatal("an empty API secret accepted")
	}
	if dialled {
		t.Fatal("a refused call dialled")
	}
}

func TestClient_ReadsStatusOnlyAndDiscardsTheBody(t *testing.T) {
	var logs bytes.Buffer
	prevLog, prevSlog := log.Writer(), slog.Default()
	log.SetOutput(&logs)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { log.SetOutput(prevLog); slog.SetDefault(prevSlog) })

	body := `{"error":"` + marker + `","data":{"users":[{"db_password":"` + marker + `"}]}}`
	for _, tc := range []struct {
		status int
		want   error
	}{{200, nil}, {201, nil}, {204, nil}, {400, ErrRefused}, {403, ErrRefused}, {422, ErrRefused},
		{500, ErrUnavailable}, {503, ErrUnavailable}, {302, ErrUnavailable}} {
		_, c := newFake(t, func(seen) string { return answer(tc.status, body) })
		err := c.PutTenant(context.Background(), testRef, tenant())
		if !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Fatalf("status %d: %v, want %v", tc.status, err, tc.want)
		}
		if err != nil {
			if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), testSecret) {
				t.Fatalf("status %d: the error carries the answer or the secret: %v", tc.status, err)
			}
			if !strings.Contains(err.Error(), itoa(tc.status)) {
				t.Fatalf("status %d: the error does not name the status: %v", tc.status, err)
			}
		}
	}
	// A refusal's message is the status alone.
	_, c := newFake(t, func(seen) string { return answer(403, body) })
	if err := c.Terminate(context.Background(), testRef); err == nil || err.Error() != "pooler: the call was refused: status 403" {
		t.Fatalf("refusal: %v", err)
	}
	// A malformed answer that quotes the marker in its status line.
	_, c = newFake(t, func(seen) string { return "HTTP/1.1 2" + marker + " OK\r\n\r\n" })
	if err := c.Health(context.Background()); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), marker) {
		t.Fatalf("malformed: %v", err)
	}
	if strings.Contains(logs.String(), marker) || strings.Contains(logs.String(), testSecret) {
		t.Fatalf("logged: %s", logs.String())
	}
}

func TestDelete_NeverDeletesAfterAFailedTerminate(t *testing.T) {
	for _, tc := range []struct {
		term int
		want error
	}{{500, ErrUnavailable}, {403, ErrRefused}} {
		f, c := newFake(t, func(r seen) string {
			if r.method == http.MethodGet {
				return answer(tc.term, "")
			}
			return answer(204, "")
		})
		if err := c.Delete(context.Background(), testRef); !errors.Is(err, tc.want) {
			t.Fatalf("terminate %d: %v", tc.term, err)
		}
		for _, r := range f.requests() {
			if r.method == http.MethodDelete {
				t.Fatalf("terminate %d: a DELETE was sent", tc.term)
			}
		}
	}
	// A terminate that cannot be dialled: no DELETE either.
	n := 0
	c := New(func(context.Context) (net.Conn, error) { n++; return nil, errors.New("down") }, []byte(testSecret))
	if err := c.Delete(context.Background(), testRef); !errors.Is(err, ErrUnavailable) || n != 1 {
		t.Fatalf("dial failure: %v after %d dials", err, n)
	}
	// Control: a terminate that succeeds is followed by the DELETE.
	f, c := newFake(t, func(r seen) string {
		if r.method == http.MethodGet {
			return answer(200, `{"result":"ok"}`)
		}
		return answer(204, "")
	})
	if err := c.Delete(context.Background(), testRef); err != nil {
		t.Fatal(err)
	}
	rs := f.requests()
	if len(rs) != 2 || rs[0].method != http.MethodGet || rs[0].path != "/api/tenants/"+testRef+"/terminate" ||
		rs[1].method != http.MethodDelete || rs[1].path != "/api/tenants/"+testRef || len(rs[1].body) != 0 {
		t.Fatalf("requests %+v", rs)
	}
}

func TestTerminateAndDelete_AbsentTenantIsNil(t *testing.T) {
	// The pin's terminate answers 200 for any ref; a 404 is absence too.
	for _, term := range []int{200, 404} {
		f, c := newFake(t, func(r seen) string {
			if r.method == http.MethodGet {
				return answer(term, `{"error":"not found"}`)
			}
			return answer(404, `{"error":"not found"}`)
		})
		if err := c.Terminate(context.Background(), testRef); err != nil {
			t.Fatalf("terminate %d: %v", term, err)
		}
		if err := c.Delete(context.Background(), testRef); err != nil {
			t.Fatalf("delete after terminate %d: %v", term, err)
		}
		if n := len(f.requests()); n != 3 {
			t.Fatalf("terminate %d: %d requests", term, n)
		}
	}
	// Control on the same path: another refusal is not absence.
	_, c := newFake(t, func(r seen) string {
		if r.method == http.MethodGet {
			return answer(200, "")
		}
		return answer(403, "")
	})
	if err := c.Delete(context.Background(), testRef); !errors.Is(err, ErrRefused) {
		t.Fatalf("DELETE 403: %v", err)
	}
	_, c = newFake(t, func(seen) string { return answer(401, "") })
	if err := c.Terminate(context.Background(), testRef); !errors.Is(err, ErrRefused) {
		t.Fatalf("terminate 401: %v", err)
	}
}

func TestClearBans_RequestShape(t *testing.T) {
	path := "/api/tenants/" + testRef + "/network_bans"
	// Named addresses: one DELETE with exactly those.
	f, c := newFake(t, func(seen) string { return answer(200, `{"banned_ipv4_addresses":[]}`) })
	addrs := []netip.Addr{netip.MustParseAddr("192.0.2.41"), netip.MustParseAddr("10.212.8.1")}
	if err := c.ClearBans(context.Background(), testRef, addrs); err != nil {
		t.Fatal(err)
	}
	rs := f.requests()
	if len(rs) != 1 || rs[0].method != http.MethodDelete || rs[0].path != path || rs[0].ctype != "application/json" ||
		string(rs[0].body) != `{"ipv4_addresses":["192.0.2.41","10.212.8.1"]}` {
		t.Fatalf("requests %+v", rs)
	}

	// No address: the tenant's bans are listed, and every listed IPv4
	// address is cleared; entries that are not one are left out.
	list := `{"banned_ipv4_addresses":[{"banned_until":1,"banned_address":"192.0.2.41"},` +
		`{"banned_address":"undefined"},{"banned_address":"192.0.2.010"},{"banned_address":"::1"},` +
		`{"banned_address":"::ffff:192.0.2.7"},{"banned_address":7},{"banned_address":"198.51.100.3"}]}`
	f, c = newFake(t, func(r seen) string {
		if r.method == http.MethodGet {
			return answer(200, list)
		}
		return answer(200, `{"banned_ipv4_addresses":[]}`)
	})
	if err := c.ClearBans(context.Background(), testRef, nil); err != nil {
		t.Fatal(err)
	}
	rs = f.requests()
	if len(rs) != 2 || rs[0].method != http.MethodGet || rs[0].path != path || len(rs[0].body) != 0 ||
		rs[1].method != http.MethodDelete || rs[1].path != path ||
		string(rs[1].body) != `{"ipv4_addresses":["192.0.2.41","198.51.100.3"]}` {
		t.Fatalf("requests %+v", rs)
	}

	// Nothing banned: no DELETE.
	f, c = newFake(t, func(seen) string { return answer(200, `{"banned_ipv4_addresses":[]}`) })
	if err := c.ClearBans(context.Background(), testRef, []netip.Addr{}); err != nil || len(f.requests()) != 1 {
		t.Fatalf("empty list: %v, %d requests", err, len(f.requests()))
	}

	// A list that is not the document: an error, no DELETE.
	for _, l := range []string{`{}`, `{"banned_ipv4_addresses":null}`, `[`, `{"banned_ipv4_addresses":{}}`, marker} {
		f, c = newFake(t, func(seen) string { return answer(200, l) })
		err := c.ClearBans(context.Background(), testRef, nil)
		if err == nil || strings.Contains(err.Error(), marker) || len(f.requests()) != 1 {
			t.Fatalf("list %q: %v, %d requests", l, err, len(f.requests()))
		}
	}
	// A list the answer does not deliver whole (its length says more): an
	// error, no DELETE.
	f, c = newFake(t, func(seen) string {
		return "HTTP/1.1 200 OK\r\nContent-Length: 999\r\nConnection: close\r\n\r\n{\"banned_ipv4_addresses\":[]}"
	})
	if err := c.ClearBans(context.Background(), testRef, nil); !errors.Is(err, ErrUnavailable) || len(f.requests()) != 1 {
		t.Fatalf("short list: %v, %d requests", err, len(f.requests()))
	}
	// A refused list: the status, no DELETE.
	f, c = newFake(t, func(seen) string { return answer(404, `{"error":"not found"}`) })
	if err := c.ClearBans(context.Background(), testRef, nil); !errors.Is(err, ErrRefused) || len(f.requests()) != 1 {
		t.Fatalf("404 list: %v", err)
	}

	// An address that is not IPv4 is refused before anything is dialled.
	f, c = newFake(t, func(seen) string { return answer(200, "") })
	for _, a := range []netip.Addr{{}, netip.MustParseAddr("::1"), netip.MustParseAddr("::ffff:192.0.2.1")} {
		if err := c.ClearBans(context.Background(), testRef, []netip.Addr{netip.MustParseAddr("192.0.2.1"), a}); err == nil {
			t.Fatalf("address %v accepted", a)
		}
	}
	if err := c.ClearBans(context.Background(), "x", addrs); err == nil {
		t.Fatal("a bad ref accepted")
	}
	if len(f.requests()) != 0 {
		t.Fatal("a refused call dialled")
	}
}

// endless writes head, then fill until the pipe breaks; it reports the
// bytes the client consumed.
func endless(head string, fill byte, done chan<- int) func(context.Context) (net.Conn, error) {
	return func(context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			if _, err := http.ReadRequest(bufio.NewReader(s)); err != nil {
				done <- -1
				return
			}
			total := 0
			n, err := io.WriteString(s, head)
			total += n
			chunk := bytes.Repeat([]byte{fill}, 1024)
			for err == nil && total < 64<<20 {
				n, err = s.Write(chunk)
				total += n
			}
			done <- total
		}()
		return c, nil
	}
}

func TestClient_OversizedAnswerCut(t *testing.T) {
	// A body that never ends: the status is used, at most 64 KiB is read.
	done := make(chan int, 1)
	c := New(endless("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", 'x', done), []byte(testSecret))
	if err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := <-done; n > maxAnswer || n < maxAnswer-4096 {
		t.Fatalf("read %d bytes of the answer, bound %d", n, maxAnswer)
	}
	// A header that never ends: an error, the same bound.
	c = New(endless("HTTP/1.1 200 OK\r\nX-Long: ", 'a', done), []byte(testSecret))
	if err := c.Health(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("endless header: %v", err)
	}
	if n := <-done; n > maxAnswer {
		t.Fatalf("read %d bytes of the answer, bound %d", n, maxAnswer)
	}
	// A ban list longer than the bound, with its length or delimited by the
	// close: ErrTooLarge, which is neither an outage nor a refusal; no DELETE.
	big := `{"banned_ipv4_addresses":[` + strings.Repeat(`{"banned_address":"192.0.2.1"},`, 3000) + `{"banned_address":"192.0.2.2"}]}`
	head := "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
	for _, a := range []string{answer(200, big), head + big} {
		f, c := newFake(t, func(seen) string { return a })
		err := c.ClearBans(context.Background(), testRef, nil)
		if !errors.Is(err, ErrTooLarge) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRefused) || len(f.requests()) != 1 {
			t.Fatalf("oversized list: %v, %d requests", err, len(f.requests()))
		}
	}
	// Control: a close-delimited list that fills the bound exactly is read whole.
	exact := `{"banned_ipv4_addresses":[{"banned_address":"192.0.2.2"}]}`
	exact = head + exact + strings.Repeat(" ", maxAnswer-len(head)-len(exact))
	f, c := newFake(t, func(seen) string { return exact })
	if err := c.ClearBans(context.Background(), testRef, nil); err != nil || len(f.requests()) != 2 {
		t.Fatalf("list of exactly the bound: %v, %d requests", err, len(f.requests()))
	}
	// Control: just under the bound it is read whole.
	fits := `{"banned_ipv4_addresses":[` + strings.Repeat(`{"banned_address":"192.0.2.1"},`, 2000) + `{"banned_address":"192.0.2.2"}]}`
	f, c = newFake(t, func(r seen) string { return answer(200, fits) })
	if err := c.ClearBans(context.Background(), testRef, nil); err != nil || len(f.requests()) != 2 {
		t.Fatalf("list under the bound: %v, %d requests", err, len(f.requests()))
	}
}

func TestClient_Bounds(t *testing.T) {
	// Each call's whole exchange, dial included, runs under its bound.
	for _, tc := range []struct {
		name  string
		bound time.Duration
		call  func(*Client) error
	}{
		{"health", 5 * time.Second, func(c *Client) error { return c.Health(context.Background()) }},
		{"put", 30 * time.Second, func(c *Client) error { return c.PutTenant(context.Background(), testRef, tenant()) }},
		{"terminate", 75 * time.Second, func(c *Client) error { return c.Terminate(context.Background(), testRef) }},
		{"delete", 75 * time.Second, func(c *Client) error { return c.Delete(context.Background(), testRef) }},
		{"bans", 30 * time.Second, func(c *Client) error {
			return c.ClearBans(context.Background(), testRef, []netip.Addr{netip.MustParseAddr("192.0.2.1")})
		}},
	} {
		f := &fake{t: t, answer: func(seen) string { return answer(204, "") }}
		var deadlines []time.Time
		c := New(func(ctx context.Context) (net.Conn, error) {
			d, ok := ctx.Deadline()
			if !ok {
				t.Errorf("%s: the dial has no deadline", tc.name)
			}
			deadlines = append(deadlines, d)
			return f.dial(ctx)
		}, []byte(testSecret))
		start := time.Now()
		if err := tc.call(c); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		end := time.Now()
		for _, d := range deadlines {
			if d.Before(start.Add(tc.bound)) || d.After(end.Add(tc.bound)) {
				t.Fatalf("%s: deadline %v after the start, want %v", tc.name, d.Sub(start), tc.bound)
			}
		}
	}

	// A server that never answers: the call ends with the deadline, and the
	// connection is closed.
	silent := func(closed chan<- struct{}) func(context.Context) (net.Conn, error) {
		return func(context.Context) (net.Conn, error) {
			c, s := net.Pipe()
			go func() {
				http.ReadRequest(bufio.NewReader(s))
				io.Copy(io.Discard, s) // until the client closes
				close(closed)
			}()
			return c, nil
		}
	}
	closed := make(chan struct{})
	c := New(silent(closed), []byte(testSecret))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := c.Terminate(ctx, testRef); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("silent server: %v", err)
	}
	<-closed
	// The same with a cancellation that carries no deadline.
	closed = make(chan struct{})
	c = New(silent(closed), []byte(testSecret))
	ctx, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel2)
	if err := c.Health(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("silent server, cancelled: %v", err)
	}
	<-closed
	// A dial that never connects: the dial's error, under ErrUnavailable.
	c = New(func(ctx context.Context) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }, []byte(testSecret))
	ctx, cancel3 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel3()
	if err := c.Health(ctx); !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial: %v", err)
	}
}
