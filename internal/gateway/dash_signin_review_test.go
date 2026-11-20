package gateway

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestDashSession_NotPresented_WindowEdgeAndPlainDecimal: the session page's
// mark holds at exactly the window's age and not one second later; "plain
// decimal" has no leading zero, as the sign-in flow's model reads it.
func TestDashSession_NotPresented_WindowEdgeAndPlainDecimal(t *testing.T) {
	e := newDashEnv(t, active(), true)
	now := time.Now()
	mark := func(n string) *http.Request {
		r := rawReq("GET", dhostA, "/x")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Referer", "https://"+dhostA+"/-/auth/session?at="+n)
		return r
	}
	at := func(age int64) string { return strconv.FormatInt(now.Unix()-age, 10) }
	if !e.d.unpresented(mark(at(sessionPageWindow)), refA, now) {
		t.Error("a mark exactly the window old was refused")
	}
	if e.d.unpresented(mark(at(sessionPageWindow+1)), refA, now) {
		t.Error("a mark one second past the window was accepted")
	}
	// The address is the configured one, whatever port the Host names.
	withPort := mark(at(10))
	withPort.Host = dhostA + ":443"
	if !e.d.unpresented(withPort, refA, now) {
		t.Error("a mark refused because the Host carried a port")
	}
	for _, n := range []string{"0" + at(10), "00" + at(10)} {
		if e.d.unpresented(mark(n), refA, now) {
			t.Errorf("at=%s (a leading zero) was accepted", n)
		}
	}
}

// TestDashSession_NotPresented_OnTheWire: over a real connection, a folded or
// repeated Referer is no mark; the plain mark is.
func TestDashSession_NotPresented_OnTheWire(t *testing.T) {
	e := newDashEnv(t, active(), true)
	dir := t.TempDir()
	pairPEM(t, dir, "*.sp.test")
	first, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(e.gw)
	srv.TLSConfig.Certificates = []tls.Certificate{first}
	srv.TLSConfig.GetCertificate = e.gw.Certificate
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	goServe(t, srv, ln, true)
	mark := "https://" + dhostA + "/-/auth/session?at=" + strconv.FormatInt(time.Now().Unix()-5, 10)
	send := func(referer string) (int, int) {
		e.resetSeams()
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: dhostA,
			NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(c, "GET /x HTTP/1.1\r\nHost: "+dhostA+"\r\nSec-Fetch-Mode: navigate\r\n"+referer+"\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return 0, 0
		}
		resp.Body.Close()
		_, a := e.seams()
		return resp.StatusCode, a
	}
	if st, a := send("Referer: " + mark + "\r\n"); st != 200 || a != 1 {
		t.Errorf("plain mark: %d, auth %d", st, a)
	}
	for name, h := range map[string]string{
		"repeated": "Referer: " + mark + "\r\nReferer: " + mark + "\r\n",
		"folded":   "Referer: " + mark[:20] + "\r\n " + mark[20:] + "\r\n",
		"trailing": "Referer: " + mark + "0\r\n",
	} {
		if _, a := send(h); a != 0 {
			t.Errorf("%s Referer reached the sign-in seam", name)
		}
	}
}
