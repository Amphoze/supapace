package alert

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
)

var _ Store = (*store.Store)(nil)

// token is a value that stands for a secret in a declared address.
func token() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "tok" + hex.EncodeToString(b)
}

// testNode is a node root with its configuration directory and a key.
type testNode struct {
	p nodecfg.Paths
	k secrets.KEK
}

func newTestNode(t *testing.T, dev bool) testNode {
	t.Helper()
	n := testNode{p: nodecfg.Paths{Root: t.TempDir()}}
	rand.Read(n.k[:])
	if err := os.MkdirAll(filepath.Dir(n.p.AlertSealed()), 0o700); err != nil {
		t.Fatal(err)
	}
	if dev {
		if err := os.WriteFile(filepath.Join(filepath.Dir(n.p.NodeJSON()), "dev-mode"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return n
}

func (n testNode) load() (Declaration, bool, error) { return Load(n.p, n.k) }

// sink is a destination that records what reaches it and answers status.
type sink struct {
	*httptest.Server
	mu     sync.Mutex
	reqs   []sinkReq
	status int
}

type sinkReq struct {
	Method, URI, Type string
	Body              []byte
}

func newSink(t *testing.T, tlsOn bool) *sink {
	s := &sink{status: http.StatusNoContent}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, sinkReq{r.Method, r.RequestURI, r.Header.Get("Content-Type"), b})
		st := s.status
		s.mu.Unlock()
		w.WriteHeader(st)
	})
	if tlsOn {
		s.Server = httptest.NewTLSServer(h)
	} else {
		s.Server = httptest.NewServer(h)
	}
	t.Cleanup(s.Close)
	return s
}

func (s *sink) setStatus(c int) { s.mu.Lock(); s.status = c; s.mu.Unlock() }

func (s *sink) got() []sinkReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sinkReq(nil), s.reqs...)
}

func (s *sink) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
}

// decl declares s with a token in the path and the query of both addresses.
func (s *sink) decl(tok string) Declaration {
	d := Declaration{URL: s.URL + "/hook/" + tok + "?key=" + tok, DeadmanURL: s.URL + "/ping/" + tok + "/{stanza}?k=" + tok}
	if s.TLS != nil {
		d.CAPEM = s.caPEM()
	}
	return d
}

func testDoc() Document {
	now := time.Now().UTC().Truncate(time.Second)
	return Document{Node: "node-a", Subject: "node", Code: "test", Severity: "warn", Count: 1, FirstAt: now, LastAt: now}
}

func TestDocument_HasNoTextMember(t *testing.T) {
	allowed := map[string]bool{"Node": true, "Subject": true, "Code": true, "Severity": true, "Figures": true}
	var holdsString func(reflect.Type) bool
	holdsString = func(t reflect.Type) bool {
		switch t.Kind() {
		case reflect.String:
			return true
		case reflect.Map:
			return holdsString(t.Key()) || holdsString(t.Elem())
		case reflect.Slice, reflect.Array, reflect.Pointer:
			return holdsString(t.Elem())
		case reflect.Struct:
			if t == reflect.TypeOf(time.Time{}) {
				return false
			}
			for i := range t.NumField() {
				if holdsString(t.Field(i).Type) {
					return true
				}
			}
		case reflect.Interface:
			return true
		}
		return false
	}
	ty := reflect.TypeOf(Document{})
	seen := 0
	for i := range ty.NumField() {
		f := ty.Field(i)
		if !holdsString(f.Type) {
			continue
		}
		seen++
		if !allowed[f.Name] {
			t.Errorf("member %s (%v) can hold text", f.Name, f.Type)
		}
	}
	if fig, _ := ty.FieldByName("Figures"); fig.Type != reflect.TypeOf(map[string]int64{}) {
		t.Errorf("Figures is %v", fig.Type)
	}
	if seen != len(allowed) {
		t.Errorf("%d members hold strings, want the %d named", seen, len(allowed))
	}
}

func TestCodes_SeverityTable(t *testing.T) {
	page := "schedule-failed fleet-pusher-lag repository-damaged spool-dropped full-failing clock-jump " +
		"offsite-marker-unexpected offsite-purge-refused rekey-pending pooler-memory pooler-ended orphan-tenant " +
		"tenant-row-drift allow-list-node-address"
	warn := "test schedule-stale-list schedule-set-mismatch disk-half disk-soft pusher-lag replication-lag " +
		"expire-held canary-failed offsite-expire-undeclared offsite-expire-failed offsite-unrecorded " +
		"offsite-retention-exceeded offsite-purge-pending orphan-container orphan-network orphan-directory " +
		"orphan-route orphan-slice rendered-file-drift proxy-table-drift route-drift host-check-failed " +
		// the backup notices, passed through by code
		"unlisted-entry history-rewritten offsite-differs walk-truncated unreadable-entry segment-without-history " +
		"budget-exceeded record-not-in-store restore-shortfall timeline-mismatch quarantine backup-failed " +
		"offsite-undeclared cp-quota-half repo-space-low repo-quota-full fetch-too-large"
	page += " unlisted-code"
	want := map[string]string{}
	for sev, list := range map[string]string{"page": page, "warn": warn} {
		for _, c := range strings.Fields(list) {
			if _, dup := want[c]; dup {
				t.Fatalf("%s listed twice", c)
			}
			want[c] = sev
		}
	}
	for c, sev := range want {
		if got, known := Severity(c); !known || got != sev {
			t.Errorf("Severity(%q) = %q, %t; want %q", c, got, known, sev)
		}
	}
	if len(severities) != len(want) {
		t.Errorf("the table has %d codes, the list %d", len(severities), len(want))
	}
	for _, c := range []string{"", "Test", "test ", "disk-half\n", "other"} {
		if _, known := Severity(c); known {
			t.Errorf("%q is known", c)
		}
	}
}

func TestDeclaration_SealedAndRedactedInShow(t *testing.T) {
	n := newTestNode(t, false)
	if d, ok, err := n.load(); err != nil || ok || d != (Declaration{}) {
		t.Fatalf("undeclared: %v %t %v", d, ok, err)
	}
	tok := token()
	d := Declaration{URL: "https://hooks.example.test:8443/h/" + tok + "?k=" + tok, DeadmanURL: "https://dm.example.test/p/" + tok + "/{stanza}"}
	if err := Save(n.p, n.k, d); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(n.p.AlertSealed())
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(n.p.AlertSealed())
	if fi.Mode().Perm() != 0o600 || bytes.Contains(raw, []byte(tok)) || bytes.Contains(raw, []byte("example")) {
		t.Fatalf("file mode %v, or the address is readable in it", fi.Mode())
	}
	// Bound to its name: the same bytes do not open as another sealed file.
	if _, err := secrets.OpenNode(n.k, "offsite", raw); err == nil {
		t.Fatal("opened under another name")
	}
	got, ok, err := n.load()
	if err != nil || !ok || got.URL != d.URL || got.DeadmanURL != d.DeadmanURL || got.CAPEM != "" {
		t.Fatalf("loaded %v %t %v", got, ok, err)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%v %+v %#v %s %q|", got, got, got, got, got)
	slog.New(slog.NewTextHandler(&b, nil)).Info("x", "d", got)
	slog.New(slog.NewJSONHandler(&b, nil)).Info("x", "d", got)
	js, _ := json.Marshal(got)
	b.Write(js)
	if strings.Contains(b.String(), tok) || strings.Contains(b.String(), "/h/") || !strings.Contains(b.String(), "https://hooks.example.test:8443") {
		t.Fatalf("printed %s", b.String())
	}
	// A link or an oversized file in its place is not read.
	link := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(link, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, put := range []func() error{
		func() error { os.Remove(n.p.AlertSealed()); return os.Symlink(link, n.p.AlertSealed()) },
		func() error {
			os.Remove(n.p.AlertSealed())
			return os.WriteFile(n.p.AlertSealed(), append(raw, make([]byte, maxSealed)...), 0o600)
		},
	} {
		if err := put(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := n.load(); err == nil {
			t.Fatal("loaded through a link or past the bound")
		}
	}
	os.Remove(n.p.AlertSealed())
	if err := os.WriteFile(n.p.AlertSealed(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Another key does not open it.
	var other secrets.KEK
	rand.Read(other[:])
	if _, _, err := Load(n.p, other); err == nil {
		t.Fatal("opened under another key")
	}
	// A CA bundle is at most 512 KiB of certificates.
	ca := newSink(t, true).caPEM()
	if err := Save(n.p, n.k, Declaration{URL: d.URL, CAPEM: strings.Repeat(ca, maxCA/len(ca)+1)}); err == nil {
		t.Fatal("an oversized CA bundle saved")
	}
	if err := Save(n.p, n.k, Declaration{URL: d.URL, CAPEM: strings.Repeat(ca, maxCA/len(ca))}); err != nil {
		t.Fatalf("control: %v", err)
	}
	// Refusals never quote the address.
	for _, bad := range []Declaration{
		{URL: "ftp://x.example.test/" + tok},
		{URL: "https://user:" + tok + "@x.example.test/"},
		{URL: "https://x.example.test/" + tok + "#frag"},
		{URL: "https://x.example.test/" + tok + " y"},
		{URL: "https://x.example.test/" + tok + strings.Repeat("a", maxURL)},
		{URL: "https://x.example.test:0/" + tok},
		{URL: "https:///" + tok},
		{URL: "https://x.example.test/" + tok, DeadmanURL: "https://x.example.test/" + tok},
		{URL: "https://x.example.test/" + tok, CAPEM: "not a certificate " + tok},
		{URL: ""},
	} {
		err := Save(n.p, n.k, bad)
		if err == nil || strings.Contains(err.Error(), tok) {
			t.Errorf("%v: %v", bad, err)
		}
	}
}

func TestSender_PlainHTTPOnlyOnADevelopmentNode(t *testing.T) {
	s := newSink(t, false)
	tok := token()
	prod, dev := newTestNode(t, false), newTestNode(t, true)
	if err := Save(prod.p, prod.k, s.decl(tok)); err == nil || !strings.Contains(err.Error(), "development node") {
		t.Fatalf("saved on a node without the marker: %v", err)
	}
	if err := Save(prod.p, prod.k, Declaration{URL: s.URL + "/hook"}); err == nil {
		t.Fatal("an http destination saved on a node without the marker")
	}
	snd := NewSender(nil, "node-a", prod.load)
	// A declaration not loaded from a development node: refused before any request.
	if err := snd.Send(context.Background(), s.decl(tok), testDoc()); err == nil {
		t.Fatal("sent over http from a literal declaration")
	}
	// A file holding http, read on a node that lost its marker, does not load.
	if err := Save(dev.p, dev.k, s.decl(tok)); err != nil {
		t.Fatal(err)
	}
	cp, err := os.ReadFile(dev.p.AlertSealed())
	if err != nil {
		t.Fatal(err)
	}
	prod.k = dev.k
	if err := os.WriteFile(prod.p.AlertSealed(), cp, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prod.load(); err == nil {
		t.Fatal("an http destination loaded without the marker")
	}
	// Plain http elsewhere than 127.0.0.1:port is refused even on a development node.
	for _, u := range []string{"http://localhost:8080/h", "http://127.0.0.2:8080/h", "http://127.0.0.1/h", "http://[::1]:8080/h"} {
		if err := Save(dev.p, dev.k, Declaration{URL: u}); err == nil {
			t.Errorf("%s saved", u)
		}
	}
	if len(s.got()) != 0 {
		t.Fatal("a refused declaration reached the sink")
	}
	// Control: on the development node, loaded from its file, it is delivered.
	if err := Save(dev.p, dev.k, s.decl(tok)); err != nil {
		t.Fatal(err)
	}
	d, _, err := dev.load()
	if err != nil {
		t.Fatal(err)
	}
	if err := NewSender(nil, "node-a", dev.load).Send(context.Background(), d, testDoc()); err != nil {
		t.Fatal(err)
	}
	if r := s.got(); len(r) != 1 || r[0].Method != "POST" || r[0].Type != "application/json" || r[0].URI != "/hook/"+tok+"?key="+tok {
		t.Fatalf("requests %+v", r)
	}
}

func TestSender_NoRedirectFollowed(t *testing.T) {
	target := newSink(t, true)
	for _, code := range []int{301, 302, 303, 307, 308} {
		from := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/caught", code)
		}))
		d := Declaration{URL: from.URL + "/hook", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: from.Certificate().Raw}))}
		err := NewSender(nil, "node-a", nil).Send(context.Background(), d, testDoc())
		from.Close()
		if err == nil || !strings.HasSuffix(err.Error(), fmt.Sprintf("answered HTTP %d", code)) {
			t.Errorf("%d: %v", code, err)
		}
	}
	if len(target.got()) != 0 {
		t.Fatal("a redirect was followed")
	}
	// Control: the target itself is reachable with the same rules.
	d := Declaration{URL: target.URL + "/hook", CAPEM: target.caPEM()}
	if err := NewSender(nil, "node-a", nil).Send(context.Background(), d, testDoc()); err != nil || len(target.got()) != 1 {
		t.Fatalf("control: %v", err)
	}
}

func TestPing_TemplateSubstitutesTheStanza(t *testing.T) {
	s := newSink(t, true)
	n := newTestNode(t, false)
	tok := token()
	if err := Save(n.p, n.k, s.decl(tok)); err != nil {
		t.Fatal(err)
	}
	snd := NewSender(nil, "node-a", n.load)
	if err := snd.Ping(context.Background(), "abcdefghij0123456789-1"); err != nil {
		t.Fatal(err)
	}
	r := s.got()
	if len(r) != 1 || r[0].Method != "GET" || r[0].URI != "/ping/"+tok+"/abcdefghij0123456789-1?k="+tok || len(r[0].Body) != 0 {
		t.Fatalf("requests %+v", r)
	}
	// A stanza that is not one is refused before any request.
	for _, bad := range []string{"", "../x", "a/b", "a?b", "A", "a b", "x%2f", strings.Repeat("a", 64)} {
		if err := snd.Ping(context.Background(), bad); err == nil {
			t.Errorf("%q pinged", bad)
		}
	}
	if len(s.got()) != 1 {
		t.Fatal("a refused stanza reached the sink")
	}
	// A failed ping is returned and leaves the alert status alone.
	s.setStatus(http.StatusServiceUnavailable)
	if err := snd.Ping(context.Background(), "cp-7"); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("failing ping: %v", err)
	}
	if ok, fail := snd.Status(); !ok.IsZero() || !fail.IsZero() {
		t.Fatal("a ping changed the delivery status")
	}
	// No dead-man address: ErrNoDeadman, nothing requested.
	d := s.decl(tok)
	d.DeadmanURL = ""
	if err := Save(n.p, n.k, d); err != nil {
		t.Fatal(err)
	}
	if err := snd.Ping(context.Background(), "cp-7"); !errors.Is(err, ErrNoDeadman) || len(s.got()) != 2 {
		t.Fatalf("no dead-man: %v, %d requests", err, len(s.got()))
	}
}

// rawSink answers every connection with the bytes of answer and records
// whether anything arrived; hang keeps the connection open without a word.
func rawSink(t *testing.T, answer string, hang bool) string { return rawSinkAt(t, answer, hang, false) }

// rawSinkAt with now answers on accept, before reading anything.
func rawSinkAt(t *testing.T, answer string, hang, now bool) string {
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
				for !now { // the request's header
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" {
						break
					}
				}
				if hang {
					<-done
					return
				}
				io.WriteString(c, answer)
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

func TestSend_AnswerAndAddressNeverInTheError(t *testing.T) {
	n := newTestNode(t, true)
	snd := NewSender(nil, "node-a", n.load)
	tok, marker := token(), token()
	old := deliveryTimeout
	deliveryTimeout = 300 * time.Millisecond
	t.Cleanup(func() { deliveryTimeout = old })
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedURL := "http://" + closed.Addr().String()
	closed.Close()
	for _, c := range []struct {
		name, base, want string
	}{
		{"nonsense", rawSink(t, marker+" \x1b[31m\r\n\r\n", false), "the destination's answer is not HTTP/1.1, the only version this client speaks"},
		{"reason phrase", rawSink(t, "HTTP/1.1 500 "+marker+"\x1b[2J\r\nContent-Length: 3\r\n\r\n"+marker, false), "the destination answered HTTP 500"},
		{"huge header", rawSink(t, "HTTP/1.1 200 OK\r\nX: "+strings.Repeat(marker, 2000)+"\r\n\r\n", false), "the destination's answer is not HTTP/1.1, the only version this client speaks"},
		{"silent", rawSink(t, "", true), "no answer within 300ms"},
		{"refused", closedURL, "the connection was refused"},
	} {
		d := Declaration{URL: c.base + "/hook/" + tok + "?k=" + tok, dev: true}
		err := snd.Send(context.Background(), d, testDoc())
		if err == nil || !strings.HasSuffix(err.Error(), c.want) || strings.Contains(err.Error(), tok) ||
			strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), c.base) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A handshake needs no short deadline, and a loaded machine can take
	// longer than the one above for it.
	deliveryTimeout = old
	// TLS failures are named by a fixed text too: a certificate the node
	// does not trust, and a destination that is not TLS.
	s := newSink(t, true)
	for want, base := range map[string]string{
		"the destination's certificate is not trusted":                                  s.URL,
		"the destination does not speak TLS":                                            rawSinkAt(t, "\x16\x03\x09garbage "+marker, false, true),
		"the destination's answer is not HTTP/1.1, the only version this client speaks": rawSinkAt(t, "HTTP/1.1 200 OK\r\n\r\n", false, true),
	} {
		d := Declaration{URL: strings.Replace(base, "http:", "https:", 1) + "/" + tok}
		err := snd.Send(context.Background(), d, testDoc())
		if err == nil || strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), marker) || !strings.HasSuffix(err.Error(), want) {
			t.Errorf("want %q: %v", want, err)
		}
	}
	if ok, fail := snd.Status(); !ok.IsZero() || fail.IsZero() {
		t.Fatal("the status does not show the failures")
	}
}

func TestSend_RefusesADocumentOutsideItsForm(t *testing.T) {
	s := newSink(t, true)
	tok := token()
	snd := NewSender(nil, "node-a", nil)
	d := s.decl(tok)
	for name, f := range map[string]func(*Document){
		"code off the list": func(x *Document) { x.Code = "disk-half\n{\"code\":\"test\"}" },
		"subject":           func(x *Document) { x.Subject = "node\r\nX-Injected: 1" },
		"severity":          func(x *Document) { x.Severity = "critical" },
		"figure name":       func(x *Document) { x.Figures = map[string]int64{"see https://x.example.test": 1} },
		"too many figures": func(x *Document) {
			x.Figures = map[string]int64{}
			for i := range 17 {
				x.Figures[fmt.Sprintf("f%d", i)] = 1
			}
		},
		"node id control":   func(x *Document) { x.Node = "a\nb" },
		"node id separator": func(x *Document) { x.Node = "a b" },
		"node id empty":     func(x *Document) { x.Node = "" },
	} {
		doc := testDoc()
		f(&doc)
		if err := snd.Send(context.Background(), d, doc); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	if len(s.got()) != 0 {
		t.Fatal("a refused document reached the sink")
	}
	// Control, and the wire form: exactly the members of the type.
	doc := testDoc()
	doc.Figures = map[string]int64{"used_pct": 51}
	if err := snd.Send(context.Background(), d, doc); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(s.got()[0].Body, &m); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	if len(m) != 8 || m["node"] != "node-a" || m["code"] != "test" || m["subject"] != "node" || m["severity"] != "warn" ||
		m["count"] != float64(1) || m["figures"].(map[string]any)["used_pct"] != float64(51) {
		t.Fatalf("document %v (%v)", m, keys)
	}
}

func TestLoad_RefusesAWideModeOrAnotherOwner(t *testing.T) {
	n := newTestNode(t, false)
	if err := Save(n.p, n.k, Declaration{URL: "https://h.example.test/x"}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []os.FileMode{0o640, 0o604, 0o644, 0o700} {
		if err := os.Chmod(n.p.AlertSealed(), m); err != nil {
			t.Fatal(err)
		}
		if _, _, err := n.load(); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("mode %#o;", m)) {
			t.Errorf("mode %v: %v", m, err)
		}
	}
	if err := os.Chmod(n.p.AlertSealed(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := n.load(); err != nil || !ok {
		t.Fatalf("control: %v", err)
	}
	old := fileOwner
	fileOwner = func() int { return os.Geteuid() + 1 }
	t.Cleanup(func() { fileOwner = old })
	if _, _, err := n.load(); err == nil || !strings.Contains(err.Error(), "owned") {
		t.Fatalf("another owner: %v", err)
	}
}
