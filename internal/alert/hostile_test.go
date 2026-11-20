package alert

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/store"
)

// streamSink answers every connection by calling answer with it once the
// request's header has been read; answer may write for as long as it likes.
func streamSink(t *testing.T, answer func(c net.Conn, done <-chan struct{})) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" {
						break
					}
				}
				answer(c, done)
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

// endless writes chunk until the connection or the test ends.
func endless(c net.Conn, done <-chan struct{}, head, chunk string) {
	io.WriteString(c, head)
	b := []byte(chunk)
	for {
		select {
		case <-done:
			return
		default:
		}
		if _, err := c.Write(b); err != nil {
			return
		}
	}
}

// fixed is every text an error of Send may end with.
var fixed = []string{"the destination's answer is not HTTP/1.1, the only version this client speaks", "the connection was refused", "the destination is unreachable",
	"the host name does not resolve", "the destination's certificate is not trusted", "the destination does not speak TLS",
	"the request was cancelled"}

// sendTimed sends one document to d and returns the error, the time it took
// and the bytes allocated meanwhile.
func sendTimed(t *testing.T, snd *Sender, d Declaration) (error, time.Duration, uint64) {
	t.Helper()
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	start := time.Now()
	err := snd.Send(context.Background(), d, testDoc())
	el := time.Since(start)
	runtime.ReadMemStats(&m1)
	return err, el, m1.TotalAlloc - m0.TotalAlloc
}

func TestReview_HostileAnswersAreBoundedAndNeverQuoted(t *testing.T) {
	old := deliveryTimeout
	deliveryTimeout = 2 * time.Second
	t.Cleanup(func() { deliveryTimeout = old })
	snd := NewSender(nil, "node-a", nil)
	tok, marker := token(), token()
	caught := newSink(t, false)
	under := strings.Repeat("a", maxRespHeader-1024)
	over := strings.Repeat("a", maxRespHeader+1024)
	for _, c := range []struct {
		name   string
		answer func(net.Conn, <-chan struct{})
		want   string // "" = delivered
		slow   bool   // ends by the deadline, not before
	}{
		{"redirect to loopback", func(c net.Conn, _ <-chan struct{}) {
			io.WriteString(c, "HTTP/1.1 307 "+marker+"\r\nLocation: "+caught.URL+"/"+marker+"\r\nContent-Length: 0\r\n\r\n")
		}, "the destination answered HTTP 307", false},
		{"redirect to link-local", func(c net.Conn, _ <-chan struct{}) {
			io.WriteString(c, "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/"+marker+"\r\nContent-Length: 0\r\n\r\n")
		}, "the destination answered HTTP 302", false},
		{"redirect to another scheme", func(c net.Conn, _ <-chan struct{}) {
			io.WriteString(c, "HTTP/1.1 301 Moved\r\nLocation: file:///etc/"+marker+"\r\nContent-Length: 0\r\n\r\n")
		}, "the destination answered HTTP 301", false},
		{"endless header", func(c net.Conn, d <-chan struct{}) { endless(c, d, "HTTP/1.1 200 OK\r\nX: ", marker) },
			"the destination's answer is not HTTP/1.1, the only version this client speaks", false},
		{"header just under the bound", func(c net.Conn, _ <-chan struct{}) {
			io.WriteString(c, "HTTP/1.1 204 No Content\r\nX: "+under+"\r\n\r\n")
		}, "", false},
		{"header just over the bound", func(c net.Conn, _ <-chan struct{}) {
			io.WriteString(c, "HTTP/1.1 204 No Content\r\nX: "+over+"\r\n\r\n")
		}, "the destination's answer is not HTTP/1.1, the only version this client speaks", false},
		{"endless 1xx", func(c net.Conn, d <-chan struct{}) {
			endless(c, d, "", "HTTP/1.1 103 Early Hints\r\nLink: <"+marker+">\r\n\r\n")
		}, "the destination's answer is not HTTP/1.1, the only version this client speaks", false},
		{"body that never ends", func(c net.Conn, d <-chan struct{}) {
			endless(c, d, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "10\r\n"+marker[:16]+"\r\n")
		}, "", false},
		{"slow header inside the bound", func(c net.Conn, d <-chan struct{}) {
			for _, b := range []byte("HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", 4096)) {
				select {
				case <-d:
					return
				case <-time.After(20 * time.Millisecond):
				}
				if _, err := c.Write([]byte{b}); err != nil {
					return
				}
			}
		}, "no answer within 2s", true},
		{"reason phrase of controls", func(c net.Conn, _ <-chan struct{}) {
			io.WriteString(c, "HTTP/1.1 418 "+marker+"\x1b]0;"+marker+"\x07\x1b[2J\x00\r\nContent-Length: 0\r\n\r\n")
		}, "the destination answered HTTP 418", false},
		{"switching protocols", func(c net.Conn, _ <-chan struct{}) {
			io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: x\r\n\r\n")
		}, "the destination answered HTTP 101", false},
		{"status out of range", func(c net.Conn, _ <-chan struct{}) { io.WriteString(c, "HTTP/1.1 2000 OK\r\n\r\n") },
			"the destination's answer is not HTTP/1.1, the only version this client speaks", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := streamSink(t, c.answer)
			d := Declaration{URL: base + "/hook/" + tok + "?k=" + tok, dev: true}
			err, el, alloc := sendTimed(t, snd, d)
			t.Logf("%v after %v, %d KiB allocated", err, el.Round(time.Millisecond), alloc>>10)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("not delivered: %v", err)
			case c.want != "" && (err == nil || err.Error() != "alert: "+base+": "+c.want):
				t.Fatalf("error %v, want %q", err, c.want)
			}
			if err != nil && (strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), marker)) {
				t.Fatalf("quoted: %v", err)
			}
			// No request waits for the deadline unless the answer is still
			// arriving; none takes much longer than the deadline.
			if (!c.slow && el > deliveryTimeout/2) || el > 5*deliveryTimeout {
				t.Fatalf("took %v", el)
			}
			if alloc > 8<<20 {
				t.Fatalf("%d bytes allocated", alloc)
			}
		})
	}
	if len(caught.got()) != 0 {
		t.Fatal("a redirect was followed")
	}
}

// certs is a CA and three server certificates under it for 127.0.0.1: one
// valid, one expired, one for another name.
func certs(t *testing.T) (caPEM string, valid, expired, wrongName tls.Certificate) {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	caKey := key()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	leaf := func(n int64, ip net.IP, dns string, notAfter time.Time) tls.Certificate {
		k := key()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(n), NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		}
		if dns != "" {
			tmpl.DNSNames = []string{dns}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	}
	lo := net.IPv4(127, 0, 0, 1)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		leaf(2, lo, "", time.Now().Add(time.Hour)), leaf(3, lo, "", time.Now().Add(-time.Hour)),
		leaf(4, nil, "other.example.test", time.Now().Add(time.Hour))
}

func TestReview_TLSFailuresNamedByAFixedText(t *testing.T) {
	caPEM, valid, expired, wrong := certs(t)
	snd := NewSender(nil, "node-a", nil)
	tok := token()
	start := func(c tls.Certificate, h2only bool) string {
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		s.TLS = &tls.Config{Certificates: []tls.Certificate{c}}
		if h2only {
			s.EnableHTTP2 = true
			s.Config.Protocols = new(http.Protocols)
			s.Config.Protocols.SetHTTP2(true)
		}
		s.StartTLS()
		t.Cleanup(s.Close)
		return s.URL
	}
	for _, c := range []struct {
		name, base, want string
	}{
		{"valid (control)", start(valid, false), ""},
		{"expired", start(expired, false), "the destination's certificate is not trusted"},
		{"another name", start(wrong, false), "the destination's certificate is not trusted"},
		{"HTTP/2 only", start(valid, true), "the destination's answer is not HTTP/1.1, the only version this client speaks"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := Declaration{URL: c.base + "/hook/" + tok, CAPEM: caPEM}
			err, el, _ := sendTimed(t, snd, d)
			t.Logf("%v after %v", err, el.Round(time.Millisecond))
			if c.want == "?" { // recorded, not asserted: what an HTTP/2-only destination gets
				return
			}
			if (c.want == "" && err != nil) || (c.want != "" && (err == nil || err.Error() != "alert: "+c.base+": "+c.want)) {
				t.Fatalf("error %v, want %q", err, c.want)
			}
		})
	}
}

// memStore is a Store of fixed rows that records the marks.
type memStore struct {
	rows   []store.Alert
	marked []store.Alert
}

func (m *memStore) PendingAlerts(context.Context, time.Duration, int) ([]store.Alert, error) {
	var out []store.Alert
	for _, r := range m.rows {
		sent := false
		for _, x := range m.marked {
			sent = sent || (x.Subject == r.Subject && x.Code == r.Code)
		}
		if !sent {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *memStore) MarkAlertSent(_ context.Context, a store.Alert) error {
	m.marked = append(m.marked, a)
	return nil
}

func TestReview_TheDaemonsLogQuotesNoAnswerAndNoAddress(t *testing.T) {
	n := newTestNode(t, true)
	tok, marker := token(), token()
	base := streamSink(t, func(c net.Conn, _ <-chan struct{}) {
		io.WriteString(c, "HTTP/1.1 500 "+marker+"\x1b[2J\r\nContent-Length: 0\r\n\r\n")
	})
	if err := Save(n.p, n.k, Declaration{URL: base + "/hook/" + tok + "?k=" + tok}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	st := &memStore{rows: []store.Alert{
		{Subject: "cp", Code: "zz-unlisted\x1b[2J", Severity: "page", Count: 1, FirstAt: now, LastAt: now},
		{Subject: "node", Code: "disk-half", Severity: "warn", Count: 1, FirstAt: now, LastAt: now},
	}}
	var logs bytes.Buffer
	snd := NewSender(st, "node-a", n.load)
	snd.log = slog.New(slog.NewTextHandler(&logs, nil))
	snd.round(context.Background())
	snd.round(context.Background())
	if strings.Contains(logs.String(), tok) || strings.Contains(logs.String(), marker) || strings.ContainsRune(logs.String(), 0x1b) {
		t.Fatalf("logged %q", logs.String())
	}
	if !strings.Contains(logs.String(), "sent as unlisted-code") || !strings.Contains(logs.String(), "delivery failed") {
		t.Fatalf("logged %q", logs.String())
	}
	t.Logf("log:\n%s", logs.String())
}

func TestReview_SmallGaps(t *testing.T) {
	n := newTestNode(t, false)
	tok := token()
	// The dead-man template is held to the destination's rules.
	for _, dm := range []string{"http://h.example.test/{stanza}", "https://u:" + tok + "@h.example.test/{stanza}",
		"https://h.example.test/{stanza}#" + tok} {
		if err := Save(n.p, n.k, Declaration{URL: "https://h.example.test/x", DeadmanURL: dm}); err == nil ||
			strings.Contains(err.Error(), tok) {
			t.Errorf("dead-man %q: %v", dm, err)
		}
	}
	s := newSink(t, true)
	snd := NewSender(nil, "node-a", nil)
	d := s.decl(tok)
	// Undeclared is ErrUndeclared; a cancelled request says so.
	if err := snd.Send(context.Background(), Declaration{}, testDoc()); !errors.Is(err, ErrUndeclared) {
		t.Errorf("undeclared: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := snd.Send(ctx, d, testDoc()); err == nil || !strings.HasSuffix(err.Error(), "the request was cancelled") {
		t.Errorf("cancelled: %v", err)
	}
	// A short subject is not a ref.
	doc := testDoc()
	doc.Subject = "abc"
	if err := snd.Send(context.Background(), d, doc); err == nil {
		t.Error("subject abc sent")
	}
	// No figures go out as an empty object.
	if err := snd.Send(context.Background(), d, testDoc()); err != nil {
		t.Fatal(err)
	}
	if r := s.got(); len(r) != 1 || !bytes.Contains(r[0].Body, []byte(`"figures":{}`)) {
		t.Errorf("requests %+v", r)
	}
	// Every verb prints the declaration redacted.
	out := fmt.Sprintf("%x %X %d %10.3s %v", d, d, d, d, []Declaration{d})
	if strings.Contains(out, tok) || strings.Contains(out, hex.EncodeToString([]byte(tok))) || strings.Contains(out, "/hook") {
		t.Errorf("printed %s", out)
	}
}

func TestReview_MarkTestedAndTheMarker(t *testing.T) {
	n := newTestNode(t, false)
	d1 := Declaration{URL: "https://a.example.test/x", DeadmanURL: "https://a.example.test/{stanza}"}
	d2 := Declaration{URL: "https://b.example.test/x", DeadmanURL: "https://a.example.test/{stanza}"}
	if err := Save(n.p, n.k, d1); err != nil {
		t.Fatal(err)
	}
	if err := Save(n.p, n.k, d2); err != nil {
		t.Fatal(err)
	}
	// A test of the declaration that was replaced meanwhile is not recorded.
	if err := MarkTested(n.p, n.k, d1); err == nil {
		t.Fatal("recorded a test of a replaced declaration")
	}
	if d, _, err := n.load(); err != nil || d.NotReady() == "" {
		t.Fatalf("%v %q", err, d.NotReady())
	}
	// The development marker is a regular file, not a link to one.
	m := filepath.Join(t.TempDir(), "m")
	if err := os.WriteFile(m, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(m, filepath.Join(filepath.Dir(n.p.NodeJSON()), "dev-mode")); err != nil {
		t.Fatal(err)
	}
	if err := Save(n.p, n.k, Declaration{URL: "http://127.0.0.1:8080/h"}); err == nil {
		t.Fatal("a linked marker made a development node")
	}
}
