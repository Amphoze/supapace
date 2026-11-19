package gateway

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// TestDashProxy_RawSpaceInTargetNeverForwarded: an HTTP/2 :path may hold a
// raw space, which no HTTP/1.1 request line can carry: written to Studio it
// splits the request line, and the parts after it are read as the version.
// Rule 0 refuses it, in the path and in the query. An encoded space passes.
func TestDashProxy_RawSpaceInTargetNeverForwarded(t *testing.T) {
	e := newFwdEnv(t)
	rec := recordStudio(t, nil)
	addr := serveDashTLS(t, e)
	h := h2dash(t, addr)
	for i, p := range []string{"/a b", "/x?a b", "/x?a b HTTP/1.1", "/x? "} {
		sid := uint32(2*i + 1)
		h.headers(sid, e.h2Fields(t, p), true, 16<<10)
		if out := h.wait(t, sid, 10*time.Second); out != `data:{"code":"bad_request"}` {
			t.Errorf("%q: %s", p, out)
		}
	}
	if n := rec.n(); n != 0 {
		t.Errorf("Studio saw %d requests", n)
	}
	h.headers(99, e.h2Fields(t, "/a%20b?x=%20"), true, 16<<10)
	if out := h.wait(t, 99, 10*time.Second); out != "data:studio" || rec.last(t).URI != "/a%20b?x=%20" {
		t.Errorf("encoded space: %s", out)
	}
}

// TestDashProxy_UnsolicitedSwitchingProtocols_502: no Upgrade reaches Studio
// (rule 10), so a 101 from it is a fault: 502, never a tunnel to the client.
func TestDashProxy_UnsolicitedSwitchingProtocols_502(t *testing.T) {
	e := newFwdEnv(t)
	rawStudio(t, func(c net.Conn, _ *http.Request) {
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nRAW")
	})
	addr := serveDashTLS(t, e)
	for _, h2 := range []bool{false, true} {
		res, err := dashClient(t, addr, h2).Do(e.wireReq(t, t.Context(), "GET", "/x", nil))
		if err != nil {
			t.Fatalf("h2 %v: %v", h2, err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 502 || string(b) != `{"code":"upstream_unavailable"}` {
			t.Errorf("h2 %v: %d %q", h2, res.StatusCode, b)
		}
	}
}

type tricklingBody struct{ n int }

func (s *tricklingBody) Read(p []byte) (int, error) {
	if s.n == 0 {
		return 0, io.EOF
	}
	time.Sleep(time.Second)
	s.n--
	p[0] = 'x'
	return 1, nil
}

// TestDashProxy_SlowUploadPastTheReadTimeout_H1AndH2: an upload that lasts
// longer than the server's read timeout reaches Studio whole on both
// protocols. HTTP/2 closes a stream's body at the read timeout unless the
// handler moved the read deadline at entry. The server's timeout is lowered
// so that the test takes seconds.
func TestDashProxy_SlowUploadPastTheReadTimeout_H1AndH2(t *testing.T) {
	e := newFwdEnv(t)
	rec := recordStudio(t, nil)
	dir := t.TempDir()
	pairPEM(t, dir, "*.sp.test")
	first, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(e.gw)
	srv.ReadTimeout = 2 * time.Second
	srv.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLSConfig.Certificates = []tls.Certificate{first}
	srv.TLSConfig.GetCertificate = e.gw.Certificate
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	for _, h2 := range []bool{false, true} {
		req := e.wireReq(t, t.Context(), "POST", "/x", &tricklingBody{5})
		req.ContentLength = -1
		res, err := dashClient(t, ln.Addr().String(), h2).Do(req)
		if err != nil {
			t.Errorf("h2 %v: %v", h2, err)
			continue
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || string(rec.last(t).Body) != "xxxxx" {
			t.Errorf("h2 %v: %d, Studio read %q", h2, res.StatusCode, rec.last(t).Body)
		}
	}
}

// TestDashTransport_IdleShorterThanStudiosKeepAlive: a kept connection is
// closed by the gateway before Studio's server (keep-alive 5 s) closes it,
// so a request that is not retried is never written to a connection the
// other side is closing.
func TestDashTransport_IdleShorterThanStudiosKeepAlive(t *testing.T) {
	if d := newDashTransport().IdleConnTimeout; d <= 0 || d >= 5*time.Second {
		t.Errorf("IdleConnTimeout %v, want above 0 and below 5 s", d)
	}
}

// TestDashAccessLine_MillisecondsOfTheForward: a forwarded request's line
// carries the time spent forwarding.
func TestDashAccessLine_MillisecondsOfTheForward(t *testing.T) {
	e := newFwdEnv(t)
	recordStudio(t, func(w http.ResponseWriter, _ *http.Request) { time.Sleep(300 * time.Millisecond) })
	buf := accessLines(t)
	if w := e.do(e.owner(t, "GET", "/x")); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	ls := lines(t, buf)
	if len(ls) != 1 || ls[0]["ms"].(float64) < 300 {
		t.Errorf("lines %v", ls)
	}
}
