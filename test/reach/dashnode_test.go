//go:build reach && dash

package reach

// The dashboard's helpers that need a node, and the suite hook that prepares
// it. dash.test is the suite built with the tags reach and dash: make
// reach-dash runs it on a node started with make node-up DASH=1. After the
// fixtures A and B are built, dashSetup registers the test issuer — the
// stand-in sp-dashstub issuer on the node's loopback, as issuer.<base domain>
// with a certificate of the node's development CA — and adds the fixture
// members.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashtok"
)

func init() { suiteHooks = append(suiteHooks, dashSetup) }

// The fixture members, subjects of the test issuer: on A an owner, a
// developer and a read_only member; on B an owner.
const (
	dashOwnerA, dashDeveloperA, dashReadOnlyA, dashOwnerB = "a-owner", "a-developer", "a-read-only", "b-owner"
	dashBrowsersImage                                     = "supapace-browsers:local"
)

var dashstubBin = binDir + "/sp-dashstub"

// dashIssuer is the test issuer: its iss, its stand-in's authorisation
// endpoint and address, and its signing key.
type dashIssuer struct {
	Iss, Host, AuthorizeURL string
	Addr                    netip.AddrPort
	Priv                    *rsa.PrivateKey
	KID                     string
	subjectFile             string
}

var dashIss *dashIssuer

// SetSubject makes the stand-in's next ID tokens ones for sub.
func (i *dashIssuer) SetSubject(t testing.TB, sub string) {
	t.Helper()
	if err := os.WriteFile(i.subjectFile, []byte(sub), 0o600); err != nil {
		t.Fatal(err)
	}
}

// needDash returns the node's studio domain; a node without one fails the
// test, never skips it.
func needDash(t testing.TB) string {
	t.Helper()
	s := nodeConf(t).StudioDomain
	if s == "" {
		t.Fatal("this node has no studio domain: the dashboard's tests run on a node started with make node-up DASH=1")
	}
	return s
}

// issuer is the test issuer dashSetup registered.
func issuer(t testing.TB) *dashIssuer {
	t.Helper()
	needDash(t)
	if dashIss == nil {
		t.Fatal("the test issuer is not set up: dashSetup did not run")
	}
	return dashIss
}

func dashSetup(t testing.TB) {
	t.Helper()
	needDash(t)
	A, B := fixtureAB(t)
	dir := filepath.Join(suiteDir, "dash")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	priv, kid, set, err := dashNewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	host := "issuer." + nodeConf(t).Domain
	i := &dashIssuer{Iss: "https://" + host, Host: host, Priv: priv, KID: kid, subjectFile: filepath.Join(dir, "subject")}
	for name, b := range map[string][]byte{"issuer.der": der, "jwks.json": set, "subject": []byte(dashOwnerA)} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cert, key := dashLeaf(t, dir, host)
	addr, err := netip.ParseAddrPort(dashStub(t, "issuer", "--listen", "127.0.0.1:0", "--cert", cert, "--key", key,
		"--signing-key", filepath.Join(dir, "issuer.der"), "--issuer", i.Iss, "--client-id", dashClientID, "--subject-file", i.subjectFile))
	if err != nil {
		t.Fatal(err)
	}
	i.Addr, i.AuthorizeURL = addr, fmt.Sprintf("https://%s:%d/authorize", host, addr.Port())
	if out, code := cli(t, "dashboard", "issuer", "set", "--issuer", i.Iss, "--client-id", dashClientID,
		"--authorize-url", i.AuthorizeURL, "--jwks", filepath.Join(dir, "jwks.json")); code != 0 {
		t.Fatalf("dashboard issuer set: exit %d: %s", code, brief(out))
	}
	dashIss = i
	for _, m := range []struct{ ref, sub, role string }{
		{A.Ref, dashOwnerA, dashcfg.RoleOwner}, {A.Ref, dashDeveloperA, dashcfg.RoleDeveloper},
		{A.Ref, dashReadOnlyA, dashcfg.RoleReadOnly}, {B.Ref, dashOwnerB, dashcfg.RoleOwner},
	} {
		// A and B are kept between runs, and their members with them.
		switch role := dashRole(t, m.ref, i.Iss, m.sub); role {
		case m.role:
		case "":
			addMember(t, m.ref, m.sub, m.role)
		default:
			t.Fatalf("%s of %s is %s, want %s: an earlier run left it changed", m.sub, m.ref, role, m.role)
		}
	}
}

// dashRole is the role of (iss, sub) on ref, "" when none.
func dashRole(t testing.TB, ref, iss, sub string) string {
	t.Helper()
	out, code := cli(t, "member", "list", ref)
	if code != 0 {
		t.Fatalf("member list %s: exit %d: %s", ref, code, brief(out))
	}
	var l struct {
		Members []struct{ Issuer, Subject, Role string }
	}
	decode(t, "member list", out, &l)
	for _, m := range l.Members {
		if m.Issuer == iss && m.Subject == sub {
			return m.Role
		}
	}
	return ""
}

// addMember adds sub of the test issuer to ref with role.
func addMember(t testing.TB, ref, sub, role string) {
	t.Helper()
	if out, code := cli(t, "member", "add", ref, "--subject", sub, "--role", role); code != 0 {
		t.Fatalf("member add %s %s %s: exit %d: %s", ref, sub, role, code, brief(out))
	}
}

// dashStub starts sp-dashstub with args on the node, stopped in cleanup, and
// returns the address it printed it listens on.
func dashStub(t testing.TB, args ...string) string {
	t.Helper()
	cmd := exec.Command(dashstubBin, args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line := make(chan string, 1)
	go func() { l, _ := bufio.NewReader(out).ReadString('\n'); line <- l }()
	select {
	case l := <-line:
		if addr, ok := strings.CutPrefix(strings.TrimSpace(l), "listening "); ok {
			return addr
		}
		t.Fatalf("sp-dashstub %s did not start: %q", args[0], l)
	case <-time.After(20 * time.Second):
		t.Fatalf("sp-dashstub %s: not listening within 20 s", args[0])
	}
	return ""
}

// dashLeaf issues a server certificate for host from the node's development
// CA (whose names are the base and the studio domain) into dir.
func dashLeaf(t testing.TB, dir, host string) (certFile, keyFile string) {
	t.Helper()
	ca, err := tls.LoadX509KeyPair(filepath.Join(paths.CADir(), "ca.pem"), filepath.Join(paths.CADir(), "ca.key"))
	if err != nil {
		t.Fatalf("node CA: %v", err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: serial, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		ca.Leaf, &k.PublicKey, ca.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(k)
	certFile, keyFile = filepath.Join(dir, host+".pem"), filepath.Join(dir, host+".key")
	for f, b := range map[string]*pem.Block{certFile: {Type: "CERTIFICATE", Bytes: der}, keyFile: {Type: "PRIVATE KEY", Bytes: kb}} {
		if err := os.WriteFile(f, pem.EncodeToMemory(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile
}

// dashClient is a client of one dashboard origin through the gateway.
type dashClient struct {
	Origin string         // https://<ref>.<studio domain>, or the sign-in host's for "_"
	Addr   netip.AddrPort // where its connections go: the gateway, or a relay of withRTT
	H1, H2 *http.Client   // HTTP/1.1 and HTTP/2; neither follows a redirect
}

// dash is a client of ref's origin ("_": the sign-in host) that sends what a
// browser sends (dashFetch) and the cookies given.
func dash(t testing.TB, ref string, cookies ...*http.Cookie) *dashClient {
	t.Helper()
	host := ref + "." + needDash(t)
	if ref == "_" {
		host = dashcfg.SignInLabel + "." + needDash(t)
	}
	e := gatewayAt(t)
	c := &dashClient{Origin: "https://" + host, Addr: e.addr}
	client := func(h2 bool) *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: h2,
			TLSHandshakeTimeout: 10 * time.Second,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer(netip.Addr{}).DialContext(ctx, network, c.Addr.String())
			}}
		if !h2 {
			tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		return &http.Client{Timeout: httpTimeout, Transport: dashFetch{tr, c.Origin, cookies},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	c.H1, c.H2 = client(false), client(true)
	return c
}

// dashDo sends one request with header pairs h; the body is read into memory.
func dashDo(t testing.TB, c *http.Client, method, u, form string, h ...string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, u, strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	if form != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(h); i += 2 {
		req.Header.Set(h[i], h[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %s", method, pathOnly(u), errText(err))
	}
	if err := buffer(resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// signIn signs subject in on ref's origin ("_": the sign-in host) through the
// gateway's own endpoints — the login, the callback on the sign-in host, the
// session post the relay page makes — with an ID token the test signed for
// the attempt's nonce, and returns the session cookie.
func signIn(t testing.TB, ref, subject string) *http.Cookie {
	t.Helper()
	i := issuer(t)
	c := dash(t, ref)
	r := dashDo(t, c.H1, "GET", c.Origin+"/-/auth/login?return=%2F", "", "Accept", "text/html")
	loc, err := r.Location()
	if r.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), i.AuthorizeURL+"?") {
		t.Fatalf("login on %s: %s, want 302 to %s", ref, describe(r), i.AuthorizeURL)
	}
	var login *http.Cookie
	for _, k := range r.Cookies() {
		if strings.HasPrefix(k.Name, "__Host-sp-login-") {
			login = k
		}
	}
	if login == nil {
		t.Fatalf("login on %s set no login cookie", ref)
	}
	tok, err := dashIDToken(i.Priv, i.KID, i.Iss, subject, loc.Query().Get("nonce"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"id_token": {tok}, "state": {loc.Query().Get("state")}}.Encode()
	signInHost := dash(t, "_")
	if r := dashDo(t, signInHost.H1, "POST", signInHost.Origin+"/-/auth/callback", form, "Sec-Fetch-Site", "cross-site", "Origin", "null"); r.StatusCode != http.StatusOK {
		t.Fatalf("callback: %s", describe(r))
	}
	at := strconv.FormatInt(time.Now().Unix(), 10)
	r = dashDo(t, dash(t, ref, login).H1, "POST", c.Origin+"/-/auth/session?at="+at, form, "Sec-Fetch-Site", "cross-site", "Origin", "null")
	for _, k := range r.Cookies() {
		if k.Name == "__Host-sp-session" && k.Value != "" {
			return k
		}
	}
	t.Fatalf("session post on %s for %s: %s, no session cookie", ref, subject, describe(r))
	return nil
}

// dashNodeKey is the node's own assertion key.
func dashNodeKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dashcfg.PathsFor(paths).KeyDir(), "assert.key"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := dashtok.ParsePrivate(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// bypassGateway is a client whose every connection goes to Studio from inside
// the gateway container's network namespace, whatever the URL's host, so that
// Studio sees the gateway's address; the test sets the assertion header
// itself (dashAssert, with dashNodeKey or any other key).
func bypassGateway(t testing.TB) *http.Client {
	t.Helper()
	a, err := dashcfg.For(nodeConf(t))
	if err != nil {
		t.Fatal(err)
	}
	to := netip.AddrPortFrom(a.Studio, dashcfg.StudioPort).String()
	pid, _ := containerPid(t, gatewayName)
	return &http.Client{Timeout: httpTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (c net.Conn, err error) {
			if nerr := inNetns(pid, func() { c, err = dialer(netip.Addr{}).DialContext(ctx, network, to) }); nerr != nil {
				return nil, nerr
			}
			return c, err
		}}}
}

// socket is a client of the dashboard socket (URL host ignored) whose
// connections are made as uid, with uid as its group too and no supplementary
// group: the socket's peer check reads them.
func socket(t testing.TB, uid int) *http.Client {
	t.Helper()
	path := filepath.Join(dashcfg.PathsFor(paths).SocketDir(), "dash.sock")
	return &http.Client{Timeout: httpTimeout, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		type dialed struct {
			c   net.Conn
			err error
		}
		ch := make(chan dialed, 1)
		go func() {
			// Credentials are per thread: this one is never unlocked, so it
			// ends with the goroutine and no other goroutine runs as uid.
			runtime.LockOSThread()
			const keep = ^uintptr(0)
			if _, _, e := syscall.RawSyscall(syscall.SYS_SETGROUPS, 0, 0, 0); e != 0 {
				ch <- dialed{nil, fmt.Errorf("setgroups: %w", e)}
				return
			}
			if _, _, e := syscall.RawSyscall(syscall.SYS_SETRESGID, keep, uintptr(uid), keep); e != 0 {
				ch <- dialed{nil, fmt.Errorf("setresgid %d: %w", uid, e)}
				return
			}
			if _, _, e := syscall.RawSyscall(syscall.SYS_SETRESUID, keep, uintptr(uid), keep); e != 0 {
				ch <- dialed{nil, fmt.Errorf("setresuid %d: %w", uid, e)}
				return
			}
			c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
			ch <- dialed{c, err}
		}()
		d := <-ch
		return d.c, d.err
	}}}
}

// withRTT starts the delay relay towards the gateway with round trip d and
// returns its address: set a dashClient's Addr to it.
func withRTT(t testing.TB, d time.Duration) netip.AddrPort {
	t.Helper()
	a, err := netip.ParseAddrPort(dashStub(t, "delay", "--listen", "127.0.0.1:0", "--to", gatewayAt(t).addr.String(), "--rtt", d.String()))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// dashMemory is a container's memory cgroup: current use and peak, in bytes.
type dashMemory struct{ Current, Peak int64 }

func studioMem(t testing.TB) dashMemory { return containerMem(t, dashcfg.StudioName) }
func proxyMem(t testing.TB) dashMemory  { return containerMem(t, dashcfg.PgcapName) }
func pgmetaMem(t testing.TB, i int) dashMemory {
	return containerMem(t, map[int]string{0: dashcfg.PgMeta0Name, 1: dashcfg.PgMeta1Name}[i])
}

func containerMem(t testing.TB, name string) dashMemory {
	t.Helper()
	pid, _ := containerPid(t, name)
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		t.Fatal(err)
	}
	var rel string
	for _, l := range strings.Split(string(b), "\n") {
		if r, ok := strings.CutPrefix(l, "0::"); ok {
			rel = r
		}
	}
	read := func(file string) int64 {
		v, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", rel, file))
		n, perr := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
		if rel == "" || err != nil || perr != nil {
			t.Fatalf("%s: %s of cgroup %q: %v %v", name, file, rel, err, perr)
		}
		return n
	}
	return dashMemory{read("memory.current"), read("memory.peak")}
}

// browsers runs sc in a fresh container of the browser harness on the node
// (its network namespace, every capability dropped, names only from the host
// map) trusting the node's development CA, and returns the harness's result.
func browsers(t testing.TB, sc dashScenario) map[string]any {
	t.Helper()
	dir, err := os.MkdirTemp("", "reach-browsers-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Chmod(dir, 0o755)
	resolv := filepath.Join(dir, "resolv.conf")
	// A resolver nothing answers on: only the mapped names resolve.
	if err := os.WriteFile(resolv, []byte("nameserver 127.0.0.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sc.CA = "/ca/ca.pem"
	if sc.Timeout == 0 {
		sc.Timeout = 45000
	}
	name := fmt.Sprintf("sp-test-browser-%s-%d", sc.Engine, time.Now().UnixNano())
	args := []string{"run", "--rm", "-i", "--name", name, "--label", testLabel, "--network", "host", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/tmp:size=512m", "--memory", "2g",
		"-v", resolv + ":/etc/resolv.conf:ro", "-v", filepath.Join(paths.CADir(), "ca.pem") + ":" + sc.CA + ":ro"}
	for h, a := range sc.Hosts {
		args = append(args, "--add-host", h+":"+a)
	}
	in, _ := json.Marshal(sc)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append(args, dashBrowsersImage)...)
	cmd.Stdin = strings.NewReader(string(in))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		exec.Command("docker", "rm", "-f", name).Run()
	}
	var r map[string]any
	if jerr := json.Unmarshal(out, &r); jerr != nil {
		t.Fatalf("browsers (%s): %v: %v; %s", sc.Engine, err, jerr, brief(stderr.String()))
	}
	return r
}
