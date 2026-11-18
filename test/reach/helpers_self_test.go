//go:build !reach

package reach

// Self-tests of the suite's own guards. They need no daemon, CLI or gateway:
// the plain ones run in any go test; the ones that need root, nft or a network
// namespace skip elsewhere and run as root in a bare node:
//
//	CGO_ENABLED=0 go test -c -o bin/reach-self.test ./test/reach
//	docker exec <node> /opt/supapace/bin/reach-self.test -test.v

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// fails reports whether f ends by failing the testing.TB it is given.
func fails(f func(testing.TB)) bool {
	m := &mainT{}
	ok := m.run(f)
	m.cleanup()
	return !ok
}

func TestHelpers_ProbeVerdictMustAgree(t *testing.T) {
	for _, c := range []struct {
		name, script string
		want         int // -1: the helper must fail the test
	}{
		{"connected_0", `echo connected; exit 0`, 0},
		{"refused_1", `echo refused ECONNREFUSED; exit 1`, 1},
		{"negative_1", `echo negative NXDOMAIN; exit 1`, 1},
		{"timeout_2", `echo timeout; exit 2`, 2},
		{"verdict_and_status_differ", `echo connected; exit 1`, -1},
		{"refused_but_status_0", `echo refused ECONNREFUSED; exit 0`, -1},
		{"error_verdict", `echo error socket: EPERM; exit 3`, -1},
		{"bad_namespace_no_verdict", `echo "nsenter: cannot open" >&2; exit 1`, -1},
		{"missing_binary", `exit 127`, -1},
		{"two_lines", `echo connected; echo connected; exit 0`, -1},
		{"no_newline", `printf connected; exit 0`, -1},
		{"unknown_word", `echo connectedx; exit 0`, -1},
		{"runtime_crash", `echo "fatal error" >&2; exit 2`, -1},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := -1
			failed := fails(func(tb testing.TB) { got = probeArgv(tb, "", []string{"sh", "-c", c.script}) })
			if c.want < 0 {
				if !failed {
					t.Fatalf("probe returned %d instead of failing", got)
				}
				return
			}
			if failed || got != c.want {
				t.Fatalf("probe: failed %v, returned %d, want %d", failed, got, c.want)
			}
		})
	}
}

func TestHelpers_RunKillsProcessGroupOnDeadline(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	start := time.Now()
	_, err := run(time.Second, nil, "sh", "-c", "sleep 60 & echo $! > "+pidFile+"; wait")
	if err == nil || !strings.Contains(err.Error(), "no exit within") {
		t.Fatalf("run past its deadline: err %v, want a deadline error", err)
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("run returned after %v", d)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if syscall.Kill(pid, 0) != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d outlived the deadline kill", pid)
		}
	}
	r, err := run(time.Minute, []string{"REACH_SELF=1"}, "sh", "-c", `echo "$REACH_SELF"; exit 7`)
	if err != nil || r.code != 7 || strings.TrimSpace(r.stdout) != "1" {
		t.Fatalf("run: %+v %v, want exit 7 and the added environment", r, err)
	}
	if _, err := run(time.Minute, nil, "/nonexistent/reach-self"); err == nil {
		t.Fatal("a missing binary is not an error")
	}
}

func TestHelpers_ParseListener(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:22":         "0.0.0.0:22",
		"127.0.0.53%lo:53":   "127.0.0.53:53",
		"[::]:443":           "[::]:443",
		"[fe80::1%eth0]:546": "[fe80::1%eth0]:546",
		"*:5353":             "0.0.0.0:5353 [::]:5353",
		// the form ss prints for a zoned socket (a DHCPv6 client's, a bridge canary's)
		"[fe80::1]%spp3:7001": "[fe80::1%spp3]:7001",
	} {
		aps, err := parseListener(in)
		var got []string
		for _, ap := range aps {
			got = append(got, ap.String())
		}
		if err != nil || strings.Join(got, " ") != want {
			t.Errorf("parseListener(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "nocolon", "192.0.2.1:x", "host:80", "192.0.2.1:70000", "[fe80::1:22"} {
		if _, err := parseListener(bad); err == nil {
			t.Errorf("parseListener(%q) accepted", bad)
		}
	}
}

func needRoot(t *testing.T, tools ...string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (run in a bare node)")
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not on PATH")
		}
	}
}

func netnsInode(t testing.TB) string {
	l, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// A socket opened by inNetns lives in the target namespace; afterwards no
// goroutine of this process runs in it.
func TestHelpers_InNetnsDialsFromTarget(t *testing.T) {
	needRoot(t, "unshare", "ip")
	own := netnsInode(t)
	cmd := exec.Command("unshare", "--net", "sh", "-c", "ip link set lo up && echo ready && exec sleep 120")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	if _, err := fmt.Fscanln(out, new(string)); err != nil {
		t.Fatalf("namespace holder: %v", err)
	}
	var l net.Listener
	var lerr error
	if err := inNetns(cmd.Process.Pid, func() { l, lerr = net.Listen("tcp", "127.0.0.1:0") }); err != nil || lerr != nil {
		t.Fatalf("listen in the target: %v %v", err, lerr)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	addr := l.Addr().String()
	if c, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		c.Close()
		t.Fatalf("%s reached from the node's own namespace: the listener is not in the target", addr)
	}
	var derr error
	if err := inNetns(cmd.Process.Pid, func() {
		var c net.Conn
		if c, derr = net.DialTimeout("tcp", addr, 2*time.Second); derr == nil {
			c.Close()
		}
	}); err != nil || derr != nil {
		t.Fatalf("dial from the target: %v %v", err, derr)
	}
	if err := inNetns(1<<22+1, func() { t.Error("fn ran without a namespace") }); err == nil {
		t.Error("inNetns into a missing pid succeeded")
	}
	// fn blocks and parks; a thread switched without being locked would be
	// left in the target namespace for other goroutines.
	for range 20 {
		if err := inNetns(cmd.Process.Pid, func() { time.Sleep(2 * time.Millisecond) }); err != nil {
			t.Fatal(err)
		}
		tasks, _ := filepath.Glob("/proc/self/task/*/ns/net")
		for _, task := range tasks {
			if ns, err := os.Readlink(task); err == nil && ns != own {
				t.Fatalf("thread %s is in %s after inNetns returned, want %s", task, ns, own)
			}
		}
	}
}

// withRuleDeleted and withRuleInserted: the rule found by comment is gone (or
// present) inside fn, the tables are reloaded when fn returns and when it
// fails, and the drift hold lives exactly as long as the change.
func TestHelpers_RuleChangesAreRestored(t *testing.T) {
	needRoot(t, "nft")
	dir := t.TempDir()
	const table = "inet reachself"
	ruleset := filepath.Join(dir, "rules.nft")
	if err := os.WriteFile(ruleset, []byte(`table inet reachself {}
delete table inet reachself
table inet reachself {
	chain c {
		tcp dport 9 drop comment "R1"
		tcp dport 10 drop comment "R2"
		tcp dport 11 drop comment "dup"
		tcp dport 12 drop comment "dup"
	}
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(dir, "supapaced")
	if err := os.WriteFile(stub, []byte(`#!/bin/sh
set -e
case "$1 $2" in
"nft load") nft -f `+ruleset+`; nft -s list table inet reachself > `+dir+`/sum ;;
"nft check") nft -s list table inet reachself | cmp -s - `+dir+`/sum ;;
*) exit 2 ;;
esac
`), 0o700); err != nil {
		t.Fatal(err)
	}
	oldBin, oldPaths := daemonBin, paths
	daemonBin, paths = stub, nodecfg.Paths{Root: dir}
	t.Cleanup(func() {
		daemonBin, paths = oldBin, oldPaths
		exec.Command("nft", "delete", "table", "inet", "reachself").Run()
	})
	if err := os.MkdirAll(filepath.Dir(paths.DriftHold()), 0o700); err != nil {
		t.Fatal(err)
	}
	must(t, cmdTimeout, stub, "nft", "load")
	listing := func() string { return must(t, cmdTimeout, "nft", "list", "chain", "inet", "reachself", "c") }
	held := func() bool { _, err := os.Stat(paths.DriftHold()); return err == nil }
	intact := func(what string) {
		t.Helper()
		if l := listing(); !strings.Contains(l, `"R1"`) || strings.Contains(l, "dport 99") {
			t.Fatalf("%s: tables not restored:\n%s", what, l)
		}
		if held() {
			t.Fatalf("%s: drift hold left behind", what)
		}
	}

	if fails(func(tb testing.TB) {
		withRuleDeleted(tb, table, "c", "R1", func() {
			if strings.Contains(listing(), `"R1"`) || !strings.Contains(listing(), `"R2"`) || !held() {
				tb.Errorf("inside fn: R1 still present, R2 gone, or no drift hold")
			}
		})
		if !strings.Contains(listing(), `"R1"`) {
			tb.Errorf("R1 not restored as soon as fn returned")
		}
	}) {
		t.Fatal("withRuleDeleted failed on a clean run")
	}
	intact("after a clean run")

	if !fails(func(tb testing.TB) { withRuleDeleted(tb, table, "c", "R1", func() { tb.Fatal("stop inside fn") }) }) {
		t.Fatal("Fatal inside fn did not fail")
	}
	intact("after Fatal inside fn")

	ran := false
	if !fails(func(tb testing.TB) { withRuleDeleted(tb, table, "c", "dup", func() { ran = true }) }) || ran {
		t.Fatal("a comment carried by two rules was not refused before fn")
	}
	intact("after a duplicate comment")

	if !fails(func(tb testing.TB) { withRuleDeleted(tb, table, "c", "absent", func() { ran = true }) }) || ran {
		t.Fatal("an absent comment was not refused before fn")
	}
	intact("after an absent comment")

	if fails(func(tb testing.TB) {
		withRuleInserted(tb, table, "c", "tcp dport 99 accept", func() {
			if !strings.Contains(listing(), "dport 99") {
				tb.Errorf("inside fn: inserted rule absent")
			}
		})
	}) {
		t.Fatal("withRuleInserted failed on a clean run")
	}
	intact("after an inserted rule")
}

// ───────── gateway helpers against a stand-in TLS server ─────────

const selfRef = "abcdefghij0123456789"

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "self-test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

// standInGateway serves h over TLS on loopback with a certificate for
// <selfRef>.sp.test issued by ca, points gatewayAt at it with roots as the
// trusted pool, and returns the SNI names it saw.
func standInGateway(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, roots *x509.CertPool, h http.Handler) func() []string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{selfRef + ".sp.test"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var sni []string
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			sni = append(sni, hello.ServerName)
			mu.Unlock()
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := netip.MustParseAddrPort(srv.Listener.Addr().String())
	old := gatewayAt
	gatewayAt = func(testing.TB) gatewayEndpoint { return gatewayEndpoint{addr, "sp.test", roots} }
	t.Cleanup(func() { gatewayAt = old })
	return func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(sni) }
}

// TLS verification is on (a certificate from another CA fails) and the SNI is
// the project's host.
func TestHelpers_GatewayTLSVerifiedWithProjectSNI(t *testing.T) {
	ca, caKey, pool := newCA(t)
	_, _, otherPool := newCA(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(r.Host)) })
	p := Project{Ref: selfRef}

	seen := standInGateway(t, ca, caKey, pool, ok)
	resp := gatewayDo(t, p, "GET", "/rest/v1/", nil, nil)
	if resp.StatusCode != 200 || string(bodyOf(resp)) != selfRef+".sp.test" {
		t.Fatalf("trusted stand-in: %s, Host %q", describe(resp), bodyOf(resp))
	}
	if s := seen(); len(s) != 1 || s[0] != selfRef+".sp.test" {
		t.Fatalf("SNI sent %q, want %q", s, selfRef+".sp.test")
	}
	c := gatewayConn(t, p, netip.Addr{})
	if sn := c.ConnectionState().ServerName; sn != selfRef+".sp.test" {
		t.Fatalf("gatewayConn SNI %q", sn)
	}

	standInGateway(t, ca, caKey, otherPool, ok)
	if !fails(func(tb testing.TB) { gatewayDo(tb, p, "GET", "/rest/v1/", nil, nil) }) {
		t.Fatal("gatewayDo accepted a certificate from an untrusted CA")
	}
	if !fails(func(tb testing.TB) { gatewayConn(tb, p, netip.Addr{}) }) {
		t.Fatal("gatewayConn accepted a certificate from an untrusted CA")
	}
}

// A refusal counts only when the gateway itself answers with its code: a
// gateway that forwards a bad token to a PostgREST answering 401 PGRST301 must
// fail wantGatewayRefusal.
func TestHelpers_RefusalMustComeFromGateway(t *testing.T) {
	ca, caKey, pool := newCA(t)
	postgrest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		w.Write([]byte(`{"code":"PGRST301","message":"JWSError JWSInvalidSignature"}`))
	}))
	t.Cleanup(postgrest.Close)
	up, _ := url.Parse(postgrest.URL)
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequest(r.Method, up.String()+r.URL.Path, nil)
		req.Header.Set("Authorization", r.Header.Get("Authorization"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		buffer(resp)
		w.Write(bodyOf(resp))
	})
	// The gateway's credential refusals carry a message beside the code;
	// only the code is matched.
	refusing := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"code":"invalid_token","message":"token signature is invalid"}`))
	})
	p := Project{Ref: selfRef}
	check := func(tb testing.TB) {
		wantGatewayRefusal(tb, "bad bearer", gatewayDo(tb, p, "GET", "/rest/v1/rpc/whoami", nil, nil), 401, "invalid_token")
	}

	standInGateway(t, ca, caKey, pool, proxy)
	var out bytes.Buffer
	m := &mainT{out: &out}
	if m.run(check) {
		t.Fatal("a 401 from PostgREST passed as the gateway's refusal")
	}
	if !strings.Contains(out.String(), "refused by PostgREST (PGRST301), not by the gateway") {
		t.Fatalf("failure text: %q", out.String())
	}

	standInGateway(t, ca, caKey, pool, refusing)
	if fails(check) {
		t.Fatal("the gateway's own refusal did not pass")
	}
	if !fails(func(tb testing.TB) {
		wantGatewayRefusal(tb, "bad apikey", gatewayDo(tb, p, "GET", "/rest/v1/rpc/whoami", nil, nil), 401, "invalid_apikey")
	}) {
		t.Fatal("a refusal with another gateway code passed")
	}
}

// A failed request never prints a query, a header value or a token.
func TestHelpers_FailureTextRedacted(t *testing.T) {
	const marker = "reachsecretmarker"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := netip.MustParseAddrPort(l.Addr().String())
	l.Close()
	old := gatewayAt
	gatewayAt = func(testing.TB) gatewayEndpoint { return gatewayEndpoint{closed, "sp.test", x509.NewCertPool()} }
	t.Cleanup(func() { gatewayAt = old })

	var out bytes.Buffer
	m := &mainT{out: &out}
	h := http.Header{"Apikey": {marker + "1"}, "Authorization": {"Bearer " + marker + "2"}}
	if m.run(func(tb testing.TB) {
		gatewayDo(tb, Project{Ref: selfRef}, "GET", "/rest/v1/rpc/whoami?apikey="+marker+"3", h, nil)
	}) {
		t.Fatal("a request to a closed port did not fail")
	}
	text := out.String()
	if strings.Contains(text, marker) || !strings.Contains(text, "/rest/v1/rpc/whoami") || !strings.Contains(text, "refused") {
		t.Fatalf("failure text %q: want the path and the cause, without the marker", text)
	}

	for _, in := range []string{
		`Get "https://192.0.2.1/x?hint=` + marker + `": EOF`,
		`{\"apikey\":\"` + marker + `\"}`,
		`password: "` + marker + `"`,
		`token %22eyJhbGciOiJSUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.` + marker + `%22`,
		`authorization: Bearer ` + marker,
		`{"apikey": "` + marker + `"}`,
		`password=` + marker,
		`token eyJhbGciOiJSUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.` + marker,
	} {
		if got := redact(in); strings.Contains(got, marker) {
			t.Errorf("redact(%q) = %q", in, got)
		}
	}
	for _, in := range []string{"password authentication failed for user \"postgres\"", "apikey missing", "what? nothing"} {
		if got := redact(in); got != in {
			t.Errorf("redact(%q) = %q, want it unchanged", in, got)
		}
	}
	ue := &url.Error{Op: "Get", URL: "https://192.0.2.1/x?apikey=" + marker, Err: fmt.Errorf("connection reset")}
	if got := outcome(nil, ue); strings.Contains(got, marker) || got != "connection reset" {
		t.Errorf("outcome of a url.Error = %q", got)
	}
	echo := &http.Response{StatusCode: 401, Body: http.NoBody}
	echo.Body = io.NopCloser(strings.NewReader(`{"message":"bad header authorization: Bearer ` + marker + `"}`))
	if got := describe(echo); strings.Contains(got, marker) {
		t.Errorf("describe kept a bearer value: %q", got)
	}
	if got := errText(fmt.Errorf("upstream said: authorization Bearer %s", marker)); strings.Contains(got, marker) {
		t.Errorf("errText kept a bearer value: %q", got)
	}
}

// Each bearer case TestReach02_KeyRole sends: the twin verifies and passes
// CheckRole; the bad token fails with exactly the error naming its defect; and
// repairing only that defect makes it verify, so no second defect hides behind
// the first.
func TestHelpers_GatewayOnlyBearers(t *testing.T) {
	priv, kid, err := jwtx.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := []jwtx.Key{{KID: kid, Class: "issuer", Pub: &priv.PublicKey}}
	roles := []string{"authenticated"}
	check := func(tok string) error {
		k, c, err := jwtx.Verify(tok, keys, time.Now())
		if err != nil {
			return err
		}
		return jwtx.CheckRole(k, c, roles)
	}
	twin, cases := gatewayOnlyBearers(kid, newUUID(), time.Now().Unix()+300)
	if err := check(twin.sign(t, priv)); err != nil {
		t.Fatalf("twin: %v", err)
	}
	_, again := gatewayOnlyBearers(kid, "same", 1)
	_, again2 := gatewayOnlyBearers(kid, "same", 1)
	if again[0].bad.sign(t, priv) != again2[0].bad.sign(t, priv) {
		t.Error("the same arguments gave different bytes")
	}
	if len(cases) != 6 {
		t.Fatalf("%d cases, want 6", len(cases))
	}
	for _, c := range cases {
		if err := check(c.bad.sign(t, priv)); err != c.want {
			t.Errorf("%s: bad token fails with %v, want %v", c.name, err, c.want)
		}
		if err := check(c.repair(c.bad).sign(t, priv)); err != nil {
			t.Errorf("%s: repaired token still fails: %v", c.name, err)
		}
	}
	if _, _, err := jwtx.Verify(hs256Token(`{"alg":"HS256","kid":"`+kid+`"}`, `{"role":"authenticated"}`, []byte("secret")), keys, time.Now()); err != jwtx.ErrAlg {
		t.Errorf("hs256: %v, want ErrAlg", err)
	}
}

// Command output is kept up to 1 MiB and a cut is marked.
func TestHelpers_OutputCapped(t *testing.T) {
	r, err := run(time.Minute, nil, "sh", "-c", "yes x | head -c 3000000")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(r.stdout, "[output truncated at 1 MiB]") || len(r.stdout) > maxOutput+64 {
		t.Fatalf("stdout of 3 MB kept as %d bytes, marker present %v", len(r.stdout), strings.HasSuffix(r.stdout, "[output truncated at 1 MiB]"))
	}
	if r, _ := run(time.Minute, nil, "sh", "-c", "echo short"); r.stdout != "short\n" {
		t.Fatalf("short output altered: %q", r.stdout)
	}
}

// removeProject's deadline holds while it waits for an operation that never
// ends.
func TestHelpers_RemoveProjectDeadline(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "supapace")
	if err := os.WriteFile(stub, []byte(`#!/bin/sh
case "$1 $2" in
"project show") echo '{"ref":"`+selfRef+`","state":"restarting"}' ;;
"op list") echo '{"operations":[{"id":7,"ref":"`+selfRef+`","state":"running"}]}' ;;
"op show") sleep 60; echo '{"id":7,"ref":"`+selfRef+`","state":"running"}' ;;
*) exit 2 ;;
esac
`), 0o755); err != nil {
		t.Fatal(err)
	}
	oldBin, oldDeadline := cliBin, removeDeadline
	cliBin, removeDeadline = stub, 2*time.Second
	t.Cleanup(func() { cliBin, removeDeadline = oldBin, oldDeadline })
	start := time.Now()
	done := make(chan bool, 1)
	go func() {
		var ok bool
		(&mainT{out: io.Discard}).run(func(tb testing.TB) { ok = removeProject(tb, selfRef) })
		done <- ok
	}()
	select {
	case ok := <-done:
		if d := time.Since(start); ok || d > 6*time.Second {
			t.Fatalf("removeProject returned %v after %v, want false within the 2 s deadline", ok, d.Round(time.Millisecond))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("removeProject still waiting 10 s into a 2 s deadline")
	}
}

// nodeListeners and nsListeners read the same ss output: a zoned link-local
// listener among others is a listener, not a failure.
func TestHelpers_ParseSSWithZonedListener(t *testing.T) {
	out := "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n" +
		"udp UNCONN 0 0 [fe80::f54b:1]%eth0:546 [::]:*\n" +
		"tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"
	l, err := parseSS(out)
	want := []Listener{
		{"udp", netip.MustParseAddrPort("127.0.0.53:53")},
		{"udp", netip.MustParseAddrPort("[fe80::f54b:1%eth0]:546")},
		{"tcp", netip.MustParseAddrPort("0.0.0.0:22")},
	}
	if err != nil || !slices.Equal(l, want) {
		t.Fatalf("parseSS = %v, %v; want %v", l, err, want)
	}
	if _, err := parseSS("raw UNCONN 0 0 0.0.0.0:1 0.0.0.0:*\n"); err == nil {
		t.Error("an unexpected protocol was accepted")
	}
}

// args renders every field it reads back, and nothing for the zero value: a
// field it dropped would make a "same flags" control differ for the wrong
// reason. An empty User renders no --user: the image's own user applies, which
// is root only when the image says so.
func TestHelpers_RunFlagsArgs(t *testing.T) {
	if a := (runFlags{}).args(); len(a) != 0 {
		t.Fatalf("zero flags render %q", a)
	}
	f := runFlags{User: "700000:700000", CapDrop: []string{"ALL"}, CapAdd: []string{"CHOWN"}, NoNewPrivs: true,
		OtherSecurity: []string{"apparmor=x"}, Seccomp: "/p.json", ReadOnly: true,
		Tmpfs: map[string]string{"/tmp": "size=64m", "/run": ""}, Memory: 512 << 20, Swap: 512 << 20,
		NanoCPUs: 1_500_000_000, PidsLimit: 256, ShmSize: 64 << 20, Ulimits: []string{"nofile=65536:65536"},
		IpcMode: "private", Sysctls: map[string]string{"b": "2", "a": "1 0"}, NoHealthcheck: true, Binds: []string{"/s:/d:ro"}}
	want := []string{"--user", "700000:700000", "--cap-drop", "ALL", "--cap-add", "CHOWN",
		"--security-opt", "no-new-privileges", "--security-opt", "apparmor=x", "--security-opt", "seccomp=/p.json",
		"--read-only", "--tmpfs", "/run", "--tmpfs", "/tmp:size=64m", "--memory", "536870912", "--memory-swap", "536870912",
		"--cpus", "1.5", "--pids-limit", "256", "--shm-size", "67108864", "--ulimit", "nofile=65536:65536",
		"--ipc", "private", "--sysctl", "a=1 0", "--sysctl", "b=2", "--no-healthcheck", "-v", "/s:/d:ro"}
	if got := f.args(); !slices.Equal(got, want) {
		t.Fatalf("args:\n got %q\nwant %q", got, want)
	}
}

// parseSys accepts the probe's whole frozen output contract, including a call
// killed by a seccomp kill action and an errno the probe cannot classify.
func TestHelpers_ParseSysContractLines(t *testing.T) {
	var b strings.Builder
	b.WriteString("seccomp 2\nnonewprivs 1\ncapeff 0000000000000000\ncapbnd 0000000000000000\n")
	for _, c := range sysCalls {
		switch c {
		case "getpid":
			b.WriteString("sys getpid ok\n")
		case "bpf":
			b.WriteString("sys bpf signal 31 SIGSYS\n")
		case "keyctl":
			b.WriteString("sys keyctl unknown errno 22 EINVAL\n")
		default:
			b.WriteString("sys " + c + " errno 1 EPERM\n")
		}
	}
	rep, err := parseSys(b.String())
	if err != nil || rep.Calls["bpf"] != "signal 31 SIGSYS" || rep.Calls["keyctl"] != "unknown errno 22 EINVAL" {
		t.Fatalf("contract lines: %v %+v", err, rep.Calls)
	}
	for _, bad := range []string{"sys bpf signal 9 SIGKILL\n", "sys bpf unknown\n"} {
		if _, err := parseSys(strings.Replace(b.String(), "sys bpf signal 31 SIGSYS\n", bad, 1)); err == nil {
			t.Errorf("%q accepted", strings.TrimSpace(bad))
		}
	}
}

// scratchContainer's cleanup removes the anonymous volume the control-plane
// image declares; one is leaked per call otherwise.
func TestHelpers_ScratchContainerLeavesNoVolume(t *testing.T) {
	needRoot(t, "docker")
	if _, err := nodecfg.LockedImages(); err != nil {
		t.Skip(err)
	}
	vols := func() []string {
		return strings.Fields(must(t, cmdTimeout, "docker", "volume", "ls", "-q", "--filter", "dangling=true"))
	}
	before := vols()
	var mounted string
	if fails(func(tb testing.TB) {
		name := scratchContainer(tb, "sp-test-selfvol", "--network", "none")
		mounted = strings.TrimSpace(docker(tb, "inspect", "-f", `{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{end}}{{end}}`, name))
	}) {
		t.Fatal("scratchContainer failed")
	}
	if mounted == "" {
		t.Fatal("control: the scratch container mounted no anonymous volume; the image no longer declares one")
	}
	if after := vols(); slices.Contains(after, mounted) || len(after) > len(before) {
		t.Fatalf("volume %s left behind (dangling before %d, after %d)", mounted, len(before), len(after))
	}
}
