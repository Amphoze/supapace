package gateway

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDashPath_FragmentRefused: a "#" in the request target is not part of
// the path for a URL parser, which drops it and everything after it; the
// gateway would judge a segment the server never sees. Rule 0 refuses it.
func TestDashPath_FragmentRefused(t *testing.T) {
	e := newDashEnv(t, active(), true)
	for _, raw := range []string{"/api/mcp#x", "/api/ai#/x", "/api/platform/pg-meta/" + refB + "#", "/x#y"} {
		e.dexpect(t, raw, e.as(t, rawReq("GET", dhostA, raw), refA, subOwnerA), 400, "bad_request")
		e.dexpect(t, raw+" on the apex", rawReq("GET", studioDom, raw), 400, "bad_request")
	}
	// An encoded "#" is a character of its segment for both readers.
	e.passes(t, "encoded", e.as(t, rawReq("GET", dhostA, "/x%23y"), refA, subOwnerA))
}

// TestDashHostClasses_PerRequestOnOneConnection: the class and the server
// name check are decided for every request, on a kept-alive HTTP/1.1
// connection and on an HTTP/2 connection a client reuses for another host.
func TestDashHostClasses_PerRequestOnOneConnection(t *testing.T) {
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
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	cookie := "__Host-sp-session=" + e.session(t, refA, issuer, subOwnerA, time.Now().Unix()-10, 3600)

	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: dhostA,
		NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	for _, x := range []struct {
		host string
		want int
	}{{dhostA, 200}, {dhostB, 421}, {studioDom, 421}, {hostA, 421}, {dhostA, 200}} {
		io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+x.host+"\r\nCookie: "+cookie+"\r\n\r\n")
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != x.want {
			t.Errorf("HTTP/1.1, server name %s, host %s: %d, want %d", dhostA, x.host, resp.StatusCode, x.want)
		}
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: dhostA}, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	for _, x := range []struct {
		host string
		want int
	}{{dhostA, 200}, {dhostB, 421}, {studioDom, 421}, {strings.ToUpper(dhostA), 404}} {
		r, _ := http.NewRequest("GET", "https://"+ln.Addr().String()+"/", nil)
		r.Host = x.host
		r.Header.Set("Cookie", cookie)
		resp, err := tr.RoundTrip(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 || resp.StatusCode != x.want {
			t.Errorf("HTTP/2, authority %s: %s %d, want %d", x.host, resp.Proto, resp.StatusCode, x.want)
		}
	}
}

// TestDashHostClasses_PortAndRuleOneSpelling: a host whose port is not a
// number is no studio host; rule 1 is the prefix as sent, in lower case.
func TestDashHostClasses_PortAndRuleOneSpelling(t *testing.T) {
	e := newDashEnv(t, active(), true)
	for _, h := range []string{dhostA + ":x", dhostA + ":", studioDom + ":443x"} {
		e.resetSeams()
		w := e.do(e.as(t, rawReq("GET", h, "/"), refA, subOwnerA))
		if f, a := e.seams(); w.Code != 404 || f+a != 0 {
			t.Errorf("host %q: %d, forward %d, auth %d", h, w.Code, f, a)
		}
	}
	e.dexpect(t, "rule 1 in capitals is not rule 1", rawReq("GET", dhostA, "/-/AUTH/login"), 401, "login_required")
}
