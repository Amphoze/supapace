package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/Amphoze/supapace/internal/alert"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/secrets"
)

// alertNode is a node with node.json, a key read through loadKEK, and a TLS
// sink whose CA bundle is in a file.
type alertNode struct {
	*node
	k      secrets.KEK
	caFile string
	tok    string

	srv    *httptest.Server
	mu     sync.Mutex
	docs   []alert.Document
	status int
}

func newAlertNode(t *testing.T) *alertNode {
	t.Helper()
	n := &alertNode{node: newNode(t), status: http.StatusNoContent, tok: randText()}
	if err := os.MkdirAll(filepath.Dir(n.p.AlertSealed()), 0o700); err != nil {
		t.Fatal(err)
	}
	c := nodecfg.Default("sp.test")
	c.NodeID = "node-a"
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(n.p.NodeJSON(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	rand.Read(n.k[:])
	old := loadKEK
	loadKEK = func(string) (secrets.KEK, error) { return n.k, nil }
	t.Cleanup(func() { loadKEK = old })
	n.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var d alert.Document
		json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&d)
		n.mu.Lock()
		n.docs = append(n.docs, d)
		st := n.status
		n.mu.Unlock()
		w.WriteHeader(st)
	}))
	t.Cleanup(n.srv.Close)
	n.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(n.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: n.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return n
}

func (n *alertNode) got() []alert.Document {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]alert.Document(nil), n.docs...)
}

func (n *alertNode) setStatus(c int) { n.mu.Lock(); n.status = c; n.mu.Unlock() }

// set declares base (the sink when ""), a token in path and query.
func (n *alertNode) set(base string, deadman bool) {
	n.t.Helper()
	if base == "" {
		base = n.srv.URL
	}
	args := []string{"alert", "set", "--url-file", n.file(base + "/hook/" + n.tok + "?k=" + n.tok + "\n"), "--ca-file", n.caFile}
	if deadman {
		args = append(args, "--deadman-url-file", n.file(n.srv.URL+"/ping/"+n.tok+"/{stanza}"))
	}
	if code, _, errs := n.run("", args...); code != 0 {
		n.t.Fatalf("alert set: %d %s", code, errs)
	}
}

// runClean runs a command and fails when its output holds the token.
func (n *alertNode) runClean(args ...string) (int, string, string) {
	n.t.Helper()
	code, out, errs := n.run("", args...)
	if strings.Contains(out+errs, n.tok) {
		n.t.Fatalf("%v printed the token: %s %s", args, out, errs)
	}
	return code, out, errs
}

func (n *alertNode) ready() string {
	n.t.Helper()
	d, _, err := alert.Load(n.p, n.k)
	if err != nil {
		n.t.Fatal(err)
	}
	return d.NotReady()
}

func TestAlertSend_WorksWithoutDaemonOrDatabase(t *testing.T) {
	n := newAlertNode(t)
	n.set("", false)
	code, out, errs := n.runClean("alert", "send", "--code", "schedule-failed")
	if code != 0 || out != "supapaced alert send: schedule-failed delivered to "+n.srv.URL+"\n" {
		t.Fatalf("exit %d, %q %q", code, out, errs)
	}
	d := n.got()
	if len(d) != 1 || d[0].Node != "node-a" || d[0].Subject != "node" || d[0].Code != "schedule-failed" ||
		d[0].Severity != "page" || d[0].Count != 1 {
		t.Fatalf("documents %+v", d)
	}
	for _, p := range []string{n.p.AdminSock(), n.p.CPDir()} {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("%s exists: the test would not show the command needs no daemon or database", p)
		}
	}
	// Sending is not a test: the readiness reason stays.
	if r := n.ready(); r == "" {
		t.Fatal("a sent alert counted as the test")
	}
}

func TestAlertSend_RefusesACodeOutsideTheList(t *testing.T) {
	n := newAlertNode(t)
	n.set("", false)
	for _, c := range []string{"other", "schedule-failed\nX-Injected: 1", "Test", "see https://x.example.test", "\x1b[2J"} {
		code, _, errs := n.runClean("alert", "send", "--code", c)
		if code != 2 || !strings.Contains(errs, "is not an alert code") || strings.Contains(errs, "\x1b") || strings.Count(errs, "\n") != 1 {
			t.Errorf("%q: exit %d, %q", c, code, errs)
		}
	}
	if len(n.got()) != 0 {
		t.Fatal("a refused code reached the sink")
	}
	if code, _, _ := n.runClean("alert", "send", "--code", "disk-half"); code != 0 || len(n.got()) != 1 {
		t.Fatal("control: a listed code was not sent")
	}
}

// rawAnswer listens on 127.0.0.1 and answers every request with answer, or
// never when answer is "".
func rawAnswer(t *testing.T, answer string) string {
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
				if answer == "" {
					<-done
					return
				}
				io.WriteString(c, answer)
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

func TestAlertTest_MessagesAndExitCodes(t *testing.T) {
	n := newAlertNode(t)
	marker := randText()
	if code, _, errs := n.runClean("alert", "test"); code != 1 ||
		errs != "supapaced alert test: no alert destination declared; run supapaced alert set --url-file F first\n" {
		t.Fatalf("undeclared: %d %q", code, errs)
	}
	n.set("", true)
	n.setStatus(http.StatusForbidden)
	if code, _, errs := n.runClean("alert", "test"); code != 1 ||
		errs != "supapaced alert test: not delivered: "+n.srv.URL+": the destination answered HTTP 403\n" {
		t.Fatalf("refused: %d %q", code, errs)
	}
	// Nonsense and silence, from a loopback sink on a development node.
	n.write("etc/supapace/dev-mode", "", 0o600)
	for _, c := range []struct{ answer, want string }{
		{marker + "\x1b[31m\r\n\r\n", "the destination's answer is not HTTP/1.1, the only version this client speaks"},
		{"HTTP/1.1 502 " + marker + "\r\n\r\n", "the destination answered HTTP 502"},
		{"", "no answer within 10s"},
	} {
		base := rawAnswer(t, c.answer)
		n.set(base, true)
		code, out, errs := n.runClean("alert", "test")
		if code != 1 || out != "" || errs != "supapaced alert test: not delivered: "+base+": "+c.want+"\n" {
			t.Errorf("exit %d, %q %q", code, out, errs)
		}
	}
	n.set("", true)
	n.setStatus(http.StatusOK)
	if code, out, _ := n.runClean("alert", "test"); code != 0 || out != "supapaced alert test: test delivered to "+n.srv.URL+"\n" {
		t.Fatalf("delivered: %d %q", code, out)
	}
	if d := n.got(); len(d) != 2 || d[1].Code != "test" || d[1].Severity != "warn" {
		t.Fatalf("documents %+v", d)
	}
}

func TestAlertTest_ReadinessReasonGoesOnlyAfterADeliveredTest(t *testing.T) {
	n := newAlertNode(t)
	if r := (alert.Declaration{}).NotReady(); r != "alert destination not declared" {
		t.Fatalf("undeclared: %q", r)
	}
	n.set("", false)
	n.runClean("alert", "test")
	if r := n.ready(); r != "dead-man address not declared" {
		t.Fatalf("without a dead-man address, tested: %q", r)
	}
	n.set("", true)
	if r := n.ready(); r != "no test alert delivered to the declared destination" {
		t.Fatalf("declared: %q", r)
	}
	n.setStatus(http.StatusServiceUnavailable)
	if code, _, _ := n.runClean("alert", "test"); code != 1 || n.ready() == "" {
		t.Fatal("a failed test cleared the reason")
	}
	n.setStatus(http.StatusOK)
	if code, _, _ := n.runClean("alert", "test"); code != 0 || n.ready() != "" {
		t.Fatalf("a delivered test left %q", n.ready())
	}
	_, out, _ := n.runClean("alert", "show")
	if !strings.HasSuffix(out, "alert gate for real data: met\n") {
		t.Fatalf("show: %q", out)
	}
	// A new declaration has had no test.
	n.set("", true)
	if r := n.ready(); r != "no test alert delivered to the declared destination" {
		t.Fatalf("set again: %q", r)
	}
}

func TestAlertShow_NoPathOrQuery(t *testing.T) {
	n := newAlertNode(t)
	if code, out, _ := n.runClean("alert", "show"); code != 0 ||
		out != "destination: not declared\nalert gate for real data: not met: alert destination not declared\n" {
		t.Fatalf("undeclared: %d %q", code, out)
	}
	n.set("", true)
	code, out, _ := n.runClean("alert", "show")
	want := "destination: " + n.srv.URL + " (path and query not shown)\nCA: the declared bundle\n" +
		"dead-man: " + n.srv.URL + " (path and query not shown)\n" +
		"alert gate for real data: not met: no test alert delivered to the declared destination\n"
	if code != 0 || out != want || strings.Contains(out, "/hook") {
		t.Fatalf("show: %d %q", code, out)
	}
}

func TestAlertSet_RefusesWithoutQuotingTheAddress(t *testing.T) {
	n := newAlertNode(t)
	for _, u := range []string{"http://hooks.example.test/" + n.tok, "https://u:" + n.tok + "@hooks.example.test/", "https://hooks.example.test/" + n.tok + "#f"} {
		if code, _, errs := n.runClean("alert", "set", "--url-file", n.file(u)); code != 1 || !strings.Contains(errs, "destination") {
			t.Errorf("exit %d %q", code, errs)
		}
	}
	if code, _, _ := n.runClean("alert", "set", "--url-file", n.file("https://h.example.test/x"), "--deadman-url-file", n.file("https://h.example.test/"+n.tok)); code != 1 {
		t.Error("a template without {stanza} saved")
	}
	if _, err := os.Lstat(n.p.AlertSealed()); err == nil {
		t.Fatal("a refused declaration was written")
	}
}

func TestAlert_RefusesWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as an unprivileged user")
	}
	n := newAlertNode(t)
	rootOnly = true
	for _, args := range [][]string{{"alert", "set", "--url-file", n.file("https://h.example.test/")}, {"alert", "show"}, {"alert", "test"},
		{"alert", "send", "--code", "test"}} {
		if code, _, errs := n.run("", args...); code != 1 || !strings.Contains(errs, "root") {
			t.Errorf("%v: exit %d, %q", args, code, errs)
		}
	}
}

// file writes s to a new file of the test's and returns its path.
func (n *alertNode) file(s string) string {
	n.t.Helper()
	f, err := os.CreateTemp(n.t.TempDir(), "addr")
	if err != nil {
		n.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		n.t.Fatal(err)
	}
	return f.Name()
}

func TestAlertSet_ReadsTheAddressesFromFilesAndPrintsThemRedacted(t *testing.T) {
	n := newAlertNode(t)
	u, dm := n.srv.URL+"/hook/"+n.tok+"?k="+n.tok, n.srv.URL+"/ping/"+n.tok+"/{stanza}?k="+n.tok
	code, out, errs := n.runClean("alert", "set", "--url-file", n.file(u+"\n"), "--deadman-url-file", n.file(dm), "--ca-file", n.caFile)
	want := "supapaced alert set: wrote " + n.p.AlertSealed() + "; destination " + n.srv.URL + ", dead-man " + n.srv.URL +
		" (paths and queries not shown); run supapaced alert test to deliver a first document\n"
	if code != 0 || out != want {
		t.Fatalf("exit %d, %q %q", code, out, errs)
	}
	d, _, err := alert.Load(n.p, n.k)
	if err != nil || d.URL != u || d.DeadmanURL != dm {
		t.Fatalf("saved %v %v", d, err)
	}
	// Without a dead-man address the line says so.
	code, out, _ = n.runClean("alert", "set", "--url-file", n.file(u))
	if code != 0 || !strings.Contains(out, "; destination "+n.srv.URL+", dead-man not declared (paths and queries not shown);") {
		t.Fatalf("exit %d, %q", code, out)
	}
}

func TestAlertSet_RefusesTheAddressOnTheCommandLine(t *testing.T) {
	n := newAlertNode(t)
	for flag, want := range map[string]string{"--url": "--url-file", "--deadman-url": "--deadman-url-file"} {
		args := []string{"alert", "set", "--url-file", n.file("https://h.example.test/x"), flag, "https://h.example.test/" + n.tok}
		code, _, errs := n.runClean(args...)
		if code != 2 || !strings.Contains(errs, flag+" is not accepted: the address may hold a token; give it in a file with "+want) {
			t.Errorf("%s: exit %d, %q", flag, code, errs)
		}
	}
	if _, err := os.Lstat(n.p.AlertSealed()); err == nil {
		t.Fatal("written")
	}
}

func TestAlertSet_AddressFileRules(t *testing.T) {
	n := newAlertNode(t)
	good := n.file("https://h.example.test/" + n.tok + "\n")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"link":        link,
		"fifo":        fifo,
		"directory":   t.TempDir(),
		"missing":     filepath.Join(t.TempDir(), "none"),
		"two lines":   n.file("https://h.example.test/" + n.tok + "\nhttps://other.example.test/\n"),
		"empty":       n.file(""),
		"blank line":  n.file("\n"),
		"oversized":   n.file("https://h.example.test/" + n.tok + strings.Repeat("a", 4096)),
		"inner space": n.file("https://h.example.test/" + n.tok + " x\n"),
	} {
		for _, flag := range []string{"--url-file", "--deadman-url-file"} {
			args := []string{"alert", "set", "--url-file", good, flag, p}
			if flag == "--url-file" {
				args = args[:4]
				args[3] = p
			}
			if code, _, errs := n.runClean(args...); code != 1 || !strings.Contains(errs, flag) || strings.Count(errs, p) != 1 ||
				name == "link" && !strings.Contains(errs, "is a link") {
				t.Errorf("%s %s: exit %d, %q", flag, name, code, errs)
			}
		}
	}
	if _, err := os.Lstat(n.p.AlertSealed()); err == nil {
		t.Fatal("a refused file was saved")
	}
	// Control: the file itself, with its final newline.
	if code, _, errs := n.runClean("alert", "set", "--url-file", good); code != 0 {
		t.Fatalf("control: %d %q", code, errs)
	}
}

func TestAlertCommands_MessagesCarryNoDoubledPrefix(t *testing.T) {
	n := newAlertNode(t)
	code, _, errs := n.runClean("alert", "set", "--url-file", n.file("ftp://h.example.test/x"))
	if code != 1 || errs != "supapaced alert set: the destination is not https\n" {
		t.Fatalf("exit %d, %q", code, errs)
	}
	code, _, errs = n.runClean("alert", "set", "--url-file", n.file("a b"))
	if code != 1 || strings.Contains(errs, "alert: ") {
		t.Fatalf("exit %d, %q", code, errs)
	}
	n.set("", true)
	if err := os.Chmod(n.p.AlertSealed(), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"show", "test"} {
		code, _, errs = n.runClean("alert", cmd)
		if code != 1 || strings.Contains(errs, "alert: ") || !strings.Contains(errs, "0600") {
			t.Errorf("%s: exit %d, %q", cmd, code, errs)
		}
	}
}
