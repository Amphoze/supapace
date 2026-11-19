// Package reach is the end-to-end reach suite. It runs on a node as root and
// proves from the outside what a tenant can and cannot reach. The tests and
// TestMain carry the build tag "reach"; this file has none, so its helpers are
// vetted everywhere and TestHelpers_DecodeGoldenShapes runs in a plain go test.
//
// Helpers take testing.TB and touch the node only through the supapace CLI, the
// docker CLI, nsenter, nft, ss, ip, files under /run/supapace and /etc/supapace,
// and the control-plane store (platformSecret). Every external command has a
// deadline; every object a helper creates is labelled supapace.test=1 and removed
// in an idempotent cleanup. No token, key or password is written to a test log:
// every failure message that carries request data goes through redact.
//
// The suite runs serially: scratchRef, holds and the fixtures are package
// state, and no test calls t.Parallel.
package reach

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
)

const (
	binDir      = "/opt/supapace/bin"
	testLabel   = "supapace.test=1"
	secondSrc   = "198.51.100.7" // the second source address of test 17
	gatewayName = "sp-gateway"
	scratchName = "reach-scratch"
	// suiteDir keeps the suite's own state across runs on a node: the test
	// issuer key of each fixture project (root 0600). Nothing else is kept.
	suiteDir = "/var/lib/supapace-reach"

	cmdTimeout   = 2 * time.Minute  // docker, nft, ip, ss, supapaced nft
	cliTimeout   = 10 * time.Minute // supapace: a waited create runs the whole saga
	probeTimeout = time.Minute      // one sp-probe run, its own --timeout included
	httpTimeout  = 90 * time.Second // one request through the gateway
	maxOutput    = 1 << 20          // bytes of a command's stdout or stderr kept
)

var (
	paths     nodecfg.Paths // production locations
	daemonBin = binDir + "/supapaced"
	cliBin    = binDir + "/supapace"
	probeBin  = binDir + "/sp-probe"

	fixA, fixB *Project // built once by TestMain
	scratchRef string   // the live scratch project, "" when none

	holdMu sync.Mutex
	holds  int // drift-hold users; the file exists while > 0
)

// ───────── decode structs: the JSON shapes of the admin API, verbatim ─────────

// Op is an operation object (GET /v1/operations/{id}).
type Op struct {
	ID         int64  `json:"id"`
	Ref        string `json:"ref"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
	Step       string `json:"step"`
	Attempts   int    `json:"attempts"`
	Generation int64  `json:"generation"`
	LastError  string `json:"last_error"`
}

// mutationJSON is the immediate response of every mutation (--no-wait).
type mutationJSON struct {
	Ref         string `json:"ref"`
	OperationID int64  `json:"operation_id"`
}

type projectJSON struct {
	Ref         string `json:"ref"`
	State       string `json:"state"`
	UID         int    `json:"uid"`
	SubnetIndex int    `json:"subnet_index"`
	Generation  int64  `json:"generation"`
	AppliedGen  int64  `json:"applied_gen"`
}

// listedProject is an element of {"projects":[…]} (GET /v1/projects).
type listedProject struct {
	projectJSON
	Name string `json:"name"`
}

// projectsJSON and opsJSON are the list wrappers.
type projectsJSON struct {
	Projects []listedProject `json:"projects"`
}

type opsJSON struct {
	Operations []Op `json:"operations"`
}

type keysJSON struct {
	Ref              string `json:"ref"`
	AnonKey          string `json:"anon_key"`
	ServiceRoleKey   string `json:"service_role_key"`
	PostgresPassword string `json:"postgres_password"`
}

// Project is a project as the suite uses it: its credentials, placement and the
// test issuer it was created with.
type Project struct {
	Ref, AnonKey, ServiceKey, PostgresPassword string
	UID, SubnetIndex                           int
	Issuer                                     *rsa.PrivateKey
	IssuerKID                                  string
}

// UserToken is a token of p's test issuer: role, a random UUID sub, iat, and exp
// five minutes ahead; extra adds or replaces claims.
func (p Project) UserToken(role string, extra map[string]any) string {
	now := time.Now().Unix()
	c := map[string]any{"role": role, "sub": newUUID(), "iat": now, "exp": now + 300}
	maps.Copy(c, extra)
	tok, err := jwtx.Sign(p.Issuer, p.IssuerKID, c)
	if err != nil {
		panic("reach: signing a user token: " + err.Error())
	}
	return tok
}

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ───────── commands ─────────

type result struct {
	stdout, stderr string
	code           int
}

// capped keeps the first maxOutput bytes written to it and marks a cut.
type capped struct {
	b   bytes.Buffer
	cut bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := maxOutput - c.b.Len(); len(p) > room {
		c.b.Write(p[:max(room, 0)])
		c.cut = true
	} else {
		c.b.Write(p)
	}
	return len(p), nil
}

func (c *capped) String() string {
	if c.cut {
		return c.b.String() + "\n[output truncated at 1 MiB]"
	}
	return c.b.String()
}

// run executes argv with a deadline; on expiry the whole process group is
// killed. A failure to start, a signal or the deadline is an error; a non-zero
// exit status is not. env entries are added to the environment.
func run(timeout time.Duration, env []string, argv ...string) (result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), env...)
	var out, errb capped
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	r := result{out.String(), errb.String(), 0}
	var ee *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return r, fmt.Errorf("%s: no exit within %v", argv[0], timeout)
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		r.code = ee.ExitCode()
		return r, nil
	case errors.Is(err, fs.ErrNotExist):
		return r, fmt.Errorf("%s not found", argv[0])
	case err != nil:
		return r, fmt.Errorf("%s: %v", argv[0], err)
	}
	return r, nil
}

func brief(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 2048 {
		s = s[:2048] + "…"
	}
	return s
}

var (
	tokenRE  = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*(\.[A-Za-z0-9_-]*){0,2}`)
	queryRE  = regexp.MustCompile(`\?[^\s"'<>]+`)
	secretRE = regexp.MustCompile(`(?i)(bearer\s+|(?:apikey|password)(?:(?:\\?["'])?\s*[=:]\s*(?:\\?["'])?|\s+\\?["']))[^\s"'&,\\]+`)
)

// redact removes from s what a failure message must never show: URL queries
// (an apikey may ride there), JWT-shaped tokens anywhere (the token alphabet
// survives JSON escaping and percent-encoding unchanged), the value after
// "bearer", and the value after "apikey" or "password" when one follows "=",
// ":" or a quote ("password authentication failed" stays readable).
func redact(s string) string {
	s = queryRE.ReplaceAllString(s, "?<redacted>")
	s = tokenRE.ReplaceAllString(s, "<token>")
	return secretRE.ReplaceAllString(s, "${1}<redacted>")
}

// pathOnly is a request path without its query.
func pathOnly(path string) string {
	p, _, _ := strings.Cut(path, "?")
	return p
}

// errText is err for a failure message: a url.Error repeats the whole URL, so
// only its cause is kept, and the text is redacted.
func errText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return redact(err.Error())
}

// must runs argv and fails the test unless it exits 0; it returns stdout.
func must(t testing.TB, timeout time.Duration, argv ...string) string {
	t.Helper()
	r, err := run(timeout, nil, argv...)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if r.code != 0 {
		t.Fatalf("%s %s: exit %d: %s", argv[0], argOne(argv), r.code, brief(r.stderr))
	}
	return r.stdout
}

func argOne(argv []string) string {
	if len(argv) > 1 {
		return argv[1]
	}
	return ""
}

func docker(t testing.TB, args ...string) string {
	t.Helper()
	return must(t, cmdTimeout, append([]string{"docker"}, args...)...)
}

// cli runs the supapace CLI and returns its stdout (one JSON document) and exit
// status (0 success, 1 API error or failed operation, 2 usage). stdout is never
// logged: `project keys` prints credentials.
func cli(t testing.TB, args ...string) (stdout string, code int) {
	t.Helper()
	return cliWithin(t, cliTimeout, args...)
}

// cliWithin is cli with its own deadline.
func cliWithin(t testing.TB, timeout time.Duration, args ...string) (stdout string, code int) {
	t.Helper()
	if timeout <= 0 {
		t.Fatalf("supapace %s: no time left", strings.Join(args[:min(2, len(args))], " "))
	}
	r, err := run(timeout, nil, append([]string{cliBin}, args...)...)
	if err != nil {
		t.Fatalf("supapace %s: %v", strings.Join(args[:min(2, len(args))], " "), err)
	}
	if r.code > 2 {
		t.Fatalf("supapace %s: exit %d: %s", strings.Join(args[:min(2, len(args))], " "), r.code, brief(r.stderr))
	}
	if r.code != 0 {
		t.Logf("supapace %s: exit %d: %s", strings.Join(args[:min(2, len(args))], " "), r.code, brief(r.stderr))
	}
	return r.stdout, r.code
}

// decode parses one CLI document; the document itself is never printed.
func decode(t testing.TB, what, doc string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(doc), v); err != nil {
		t.Fatalf("%s: undecodable output: %v", what, err)
	}
}

// waitOp polls `supapace op show ID` every 500 ms until the operation is done,
// failed or aborted.
func waitOp(t testing.TB, id int64) Op {
	t.Helper()
	op, ok := pollOp(t, id, time.Now().Add(cliTimeout))
	if !ok {
		t.Fatalf("operation %d still %s at step %q after %v (last error %q)", id, op.State, op.Step, cliTimeout, op.LastError)
	}
	return op
}

// pollOp polls the operation until it is done, failed or aborted, or until
// deadline (ok false); no call it makes outlives the deadline.
func pollOp(t testing.TB, id int64, deadline time.Time) (op Op, ok bool) {
	t.Helper()
	for {
		if time.Until(deadline) <= 0 {
			return op, false
		}
		out, _ := cliWithin(t, time.Until(deadline), "op", "show", strconv.FormatInt(id, 10))
		op = Op{}
		decode(t, "op show", out, &op)
		if op.ID != id {
			t.Fatalf("op show %d returned operation %d", id, op.ID)
		}
		switch op.State {
		case "done", "failed", "aborted":
			return op, true
		}
		if time.Until(deadline) < 500*time.Millisecond {
			return op, false
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// ───────── projects ─────────

// newIssuer returns a test issuer key, its kid and a JWKS file holding its
// public half; the file is removed in cleanup.
func newIssuer(t testing.TB) (*rsa.PrivateKey, string, string) {
	t.Helper()
	priv, kid, err := jwtx.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := jwtx.MarshalJWKS([]jwtx.Key{{KID: kid, Class: "issuer", Pub: &priv.PublicKey}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp("", "reach-jwks-*.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return priv, kid, f.Name()
}

// loadProject reads a project's placement and credentials through the CLI.
func loadProject(t testing.TB, ref string, issuer *rsa.PrivateKey, kid string) Project {
	t.Helper()
	out, code := cli(t, "project", "show", ref)
	if code != 0 {
		t.Fatalf("project show %s: exit %d", ref, code)
	}
	var pj projectJSON
	decode(t, "project show", out, &pj)
	out, code = cli(t, "project", "keys", ref)
	if code != 0 {
		t.Fatalf("project keys %s: exit %d", ref, code)
	}
	var kj keysJSON
	decode(t, "project keys", out, &kj)
	if pj.Ref != ref || kj.Ref != ref || kj.AnonKey == "" || kj.ServiceRoleKey == "" || kj.PostgresPassword == "" {
		t.Fatalf("project %s: show or keys lacks a field", ref)
	}
	return Project{Ref: ref, AnonKey: kj.AnonKey, ServiceKey: kj.ServiceRoleKey, PostgresPassword: kj.PostgresPassword,
		UID: pj.UID, SubnetIndex: pj.SubnetIndex, Issuer: issuer, IssuerKID: kid}
}

// fixtureAB returns the two projects TestMain created.
func fixtureAB(t testing.TB) (A, B Project) {
	t.Helper()
	if fixA == nil || fixB == nil {
		t.Fatal("fixture projects A and B were not built (TestMain)")
	}
	return *fixA, *fixB
}

// fixtureScratch creates the one scratch project (args are extra `project
// create` arguments). The create is always sent with --no-wait so the cleanup
// is registered as soon as the ref is known; unless the caller passed --no-wait
// itself, the create must then end done and the full Project is returned, else
// only Ref and the issuer are set. Cleanup takes the project to a terminal
// state (removeProject).
func fixtureScratch(t testing.TB, args ...string) Project {
	t.Helper()
	if scratchRef != "" {
		t.Fatalf("scratch project %s still exists; only one at a time", scratchRef)
	}
	wait := !slices.Contains(args, "--no-wait")
	if wait {
		args = append(slices.Clone(args), "--no-wait")
	}
	priv, kid, jwks := newIssuer(t)
	out, code := cli(t, append([]string{"project", "create", "--name", scratchName, "--issuer-jwks", jwks}, args...)...)
	var m mutationJSON
	if json.Unmarshal([]byte(out), &m) != nil || m.Ref == "" {
		t.Fatalf("scratch project create (exit %d) printed no ref", code)
	}
	scratchRef = m.Ref
	t.Cleanup(func() {
		if removeProject(t, m.Ref) {
			scratchRef = ""
		}
	})
	if code != 0 {
		t.Fatalf("scratch project create --no-wait: exit %d", code)
	}
	if !wait {
		return Project{Ref: m.Ref, Issuer: priv, IssuerKID: kid}
	}
	if op := waitOp(t, m.OperationID); op.State != "done" {
		t.Fatalf("scratch project create: operation %s at step %q: %s", op.State, op.Step, op.LastError)
	}
	return loadProject(t, m.Ref, priv, kid)
}

// removeDeadline bounds removeProject as a whole: every CLI call and wait in
// it gets only the time that is left. A variable for the helpers' self-tests.
var removeDeadline = 15 * time.Minute

// removeProject takes a project to a terminal state and reports success:
// provisioning → abort; active → delete, then purge; deleted → purge;
// restarting or deleting → wait for the project's open operation, or retry a
// failed one once, and look again. Each CLI verb waits for its own operation.
func removeProject(t testing.TB, ref string) bool {
	t.Helper()
	deadline := time.Now().Add(removeDeadline)
	verb := func(args ...string) bool {
		if _, code := cliWithin(t, time.Until(deadline), args...); code != 0 {
			t.Errorf("removing project %s: %s: exit %d", ref, strings.Join(args, " "), code)
			return false
		}
		return true
	}
	retried := map[int64]bool{}
	for time.Now().Before(deadline) {
		out, code := cliWithin(t, time.Until(deadline), "project", "show", ref)
		if code != 0 {
			t.Errorf("removing project %s: show: exit %d", ref, code)
			return false
		}
		var pj projectJSON
		decode(t, "project show", out, &pj)
		ok := true
		switch pj.State {
		case "aborted", "purged":
			return true
		case "provisioning":
			ok = verb("project", "abort", ref)
		case "active":
			ok = verb("project", "delete", ref)
		case "deleted":
			ok = verb("project", "purge", ref)
		case "restarting", "deleting":
			out, code := cliWithin(t, time.Until(deadline), "op", "list", ref)
			var ops opsJSON
			if code != 0 || json.Unmarshal([]byte(out), &ops) != nil || len(ops.Operations) == 0 {
				t.Errorf("removing project %s (%s): no operation listed", ref, pj.State)
				return false
			}
			op := ops.Operations[0] // newest first
			switch op.State {
			case "pending", "running", "aborting":
				if _, ok = pollOp(t, op.ID, deadline); !ok {
					t.Errorf("removing project %s: operation %d still %s at the deadline", ref, op.ID, op.State)
				}
			case "failed":
				if retried[op.ID] {
					t.Errorf("removing project %s: operation %d failed again after a retry: %s", ref, op.ID, op.LastError)
					return false
				}
				retried[op.ID] = true
				// --no-wait: a retried restart that rolls back ends aborted
				// (exit 1) with the project active, which the loop removes.
				if ok = verb("op", "retry", strconv.FormatInt(op.ID, 10), "--no-wait"); ok {
					if _, ok = pollOp(t, op.ID, deadline); !ok {
						t.Errorf("removing project %s: retried operation %d not finished at the deadline", ref, op.ID)
					}
				}
			default:
				t.Errorf("removing project %s: %s with its newest operation %s", ref, pj.State, op.State)
				return false
			}
		default:
			t.Errorf("removing project %s: unknown state %q", ref, pj.State)
			return false
		}
		if !ok {
			return false
		}
	}
	t.Errorf("removing project %s: not terminal after %v", ref, removeDeadline)
	return false
}

// platformSecret reads one of p's platform secrets the way the daemon does:
// control-plane store over its socket (peer auth as root), KEK, data key.
func platformSecret(t testing.TB, p Project, name string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(paths.CPDir(), "sock"))
	if err != nil {
		t.Fatalf("platform secret: %v", err)
	}
	defer st.Close()
	kek, err := secrets.LoadKEK(paths.KEK())
	if err != nil {
		t.Fatalf("platform secret: %v", err)
	}
	defer clear(kek[:])
	nonce, wrapped, err := st.GetDEK(ctx, p.Ref)
	if err != nil {
		t.Fatalf("platform secret: data key of %s: %v", p.Ref, err)
	}
	dek, err := secrets.UnwrapDEK(kek, p.Ref, nonce, wrapped)
	if err != nil {
		t.Fatalf("platform secret: data key of %s: %v", p.Ref, err)
	}
	defer clear(dek)
	nonce, ct, err := st.GetSecret(ctx, p.Ref, name)
	if err != nil {
		t.Fatalf("platform secret %s of %s: %v", name, p.Ref, err)
	}
	plain, err := secrets.Open(dek, p.Ref, name, nonce, ct)
	if err != nil {
		t.Fatalf("platform secret %s of %s: %v", name, p.Ref, err)
	}
	if len(plain) == 0 {
		t.Fatalf("platform secret %s of %s is empty", name, p.Ref)
	}
	return plain
}

// platformKey is a platform private key of p (name "jwt.anon.private" or
// "jwt.service_role.private", PKCS#8 DER) and its kid.
func platformKey(t testing.TB, p Project, name string) (*rsa.PrivateKey, string) {
	t.Helper()
	der := platformSecret(t, p, name)
	k, err := x509.ParsePKCS8PrivateKey(der)
	clear(der)
	priv, ok := k.(*rsa.PrivateKey)
	if err != nil || !ok {
		t.Fatalf("platform key %s of %s: not an RSA PKCS#8 key", name, p.Ref)
	}
	return priv, jwtx.KID(&priv.PublicKey)
}

// sqlAs runs sql in p's cluster as role (docker exec … psql -h psqlHost(role))
// and returns the unaligned, tuples-only output. postgres uses p's password,
// supabase_admin and authenticator their platform secrets, any other role
// none. The password reaches psql through the environment, never argv. The
// error carries psql's message.
func sqlAs(t testing.TB, p Project, role, sql string) (string, error) {
	t.Helper()
	var pw string
	switch role {
	case "postgres":
		pw = p.PostgresPassword
	case "supabase_admin", "authenticator":
		pw = string(platformSecret(t, p, "pg."+role+".password"))
	}
	r, err := run(cmdTimeout, []string{"PGPASSWORD=" + pw}, psqlArgv(p.Ref, role, sql)...)
	if err != nil {
		t.Fatalf("sql as %s in %s: %v", role, p.Ref, err)
	}
	if r.code != 0 {
		return "", fmt.Errorf("psql exit %d: %s", r.code, redact(brief(r.stderr)))
	}
	return strings.TrimSpace(r.stdout), nil
}

// psqlHost is where psql inside the cluster container reaches the server as
// role: the platform's administrative role is admitted over the socket only
// (its loopback line rejects), every other role over loopback.
func psqlHost(role string) string {
	if role == "supabase_admin" {
		return "/var/run/postgresql"
	}
	return "127.0.0.1"
}

// ───────── node ─────────

func nodeConf(t testing.TB) nodecfg.Config {
	t.Helper()
	c, err := nodecfg.Load(paths.NodeJSON())
	if err != nil {
		t.Fatalf("node config: %v", err)
	}
	return c
}

func uplink(t testing.TB) string {
	t.Helper()
	c := nodeConf(t)
	if len(c.Uplinks) == 0 {
		t.Fatal("node config lists no uplink")
	}
	return c.Uplinks[0]
}

// nodeAddr is the node's primary address: the first IPv4 address of its first
// uplink.
func nodeAddr(t testing.TB) netip.Addr {
	t.Helper()
	dev := uplink(t)
	var ifs []struct {
		AddrInfo []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(must(t, cmdTimeout, "ip", "-j", "-4", "addr", "show", "dev", dev)), &ifs); err != nil {
		t.Fatalf("ip addr show %s: %v", dev, err)
	}
	for _, i := range ifs {
		for _, a := range i.AddrInfo {
			if ip, err := netip.ParseAddr(a.Local); err == nil {
				return ip
			}
		}
	}
	t.Fatalf("uplink %s has no IPv4 address", dev)
	return netip.Addr{}
}

// Listener is a listening socket of the node: protocol "tcp" or "udp" and its
// local address.
type Listener struct {
	Proto string
	Addr  netip.AddrPort
}

// nodeListeners lists every TCP and UDP listening address of the node's own
// namespace (ss -Htlnu), sorted. A dual-stack wildcard ("*") is reported as both
// 0.0.0.0 and [::]; an IPv6 zone is kept, an IPv4 interface suffix dropped.
func nodeListeners(t testing.TB) []Listener {
	t.Helper()
	l, err := parseSS(must(t, cmdTimeout, "ss", "-Htlnu"))
	if err != nil {
		t.Fatalf("ss: %v", err)
	}
	slices.SortFunc(l, func(a, b Listener) int {
		if c := strings.Compare(a.Proto, b.Proto); c != 0 {
			return c
		}
		return a.Addr.Compare(b.Addr)
	})
	return slices.Compact(l)
}

// parseSS parses `ss -Htlnu` output.
func parseSS(out string) ([]Listener, error) {
	var l []Listener
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		if f[0] != "tcp" && f[0] != "udp" {
			return nil, fmt.Errorf("unexpected protocol %q", f[0])
		}
		aps, err := parseListener(f[4])
		if err != nil {
			return nil, err
		}
		for _, a := range aps {
			l = append(l, Listener{f[0], a})
		}
	}
	return l, nil
}

// parseListener parses a local address as ss prints it: "0.0.0.0:22",
// "127.0.0.53%lo:53" (interface dropped), "[::]:443", "[fe80::1]%eth0:546" and
// "[fe80::1%eth0]:546" (zone kept), "*:5353" (both families).
func parseListener(s string) ([]netip.AddrPort, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return nil, fmt.Errorf("bad local address %q", s)
	}
	port, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad local address %q", s)
	}
	host, zone := s[:i], ""
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return nil, fmt.Errorf("bad local address %q", s)
		}
		host, zone = host[1:end], strings.TrimPrefix(host[end+1:], "%")
	} else if j := strings.IndexByte(host, '%'); j >= 0 {
		host = host[:j]
	}
	if host == "*" {
		return []netip.AddrPort{netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(port)),
			netip.AddrPortFrom(netip.IPv6Unspecified(), uint16(port))}, nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("bad local address %q", s)
	}
	if zone != "" && ip.Is6() {
		ip = ip.WithZone(zone)
	}
	return []netip.AddrPort{netip.AddrPortFrom(ip, uint16(port))}, nil
}

// addSourceAddr adds the second source address of test 17 to the first uplink
// for the test's duration.
func addSourceAddr(t testing.TB) netip.Addr {
	t.Helper()
	dev := uplink(t)
	t.Cleanup(func() {
		if err := delSourceAddr(); err != nil {
			t.Errorf("removing %s: %v", secondSrc, err)
		}
	})
	must(t, cmdTimeout, "ip", "addr", "add", secondSrc+"/32", "dev", dev)
	return netip.MustParseAddr(secondSrc)
}

// delSourceAddr removes the second source address from whichever device holds it.
func delSourceAddr() error {
	r, err := run(cmdTimeout, nil, "ip", "-o", "addr", "show", "to", secondSrc+"/32")
	if err != nil || r.code != 0 {
		return fmt.Errorf("ip addr show: %v %s", err, brief(r.stderr))
	}
	for line := range strings.Lines(r.stdout) {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if r, err := run(cmdTimeout, nil, "ip", "addr", "del", secondSrc+"/32", "dev", f[1]); err != nil || r.code != 0 {
			return fmt.Errorf("ip addr del: %v %s", err, brief(r.stderr))
		}
	}
	return nil
}

// ───────── drift hold and rule changes ─────────

// driftHold creates /run/supapace/drift-hold (refreshing its age) and removes
// it in cleanup once its last user is done.
func driftHold(t testing.TB) {
	t.Helper()
	holdMu.Lock()
	defer holdMu.Unlock()
	f := paths.DriftHold()
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatalf("drift hold: %v", err)
	}
	now := time.Now()
	os.Chtimes(f, now, now)
	holds++
	var once sync.Once
	t.Cleanup(func() {
		once.Do(func() {
			holdMu.Lock()
			defer holdMu.Unlock()
			if holds--; holds == 0 {
				if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("releasing the drift hold: %v", err)
				}
			}
		})
	})
}

// restoreRules returns an idempotent function that reloads our tables and
// requires `supapaced nft check` to pass afterwards.
func restoreRules(t testing.TB) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			if r, err := run(cmdTimeout, nil, daemonBin, "nft", "load"); err != nil || r.code != 0 {
				t.Errorf("restoring the tables: supapaced nft load: %v exit %d %s", err, r.code, brief(r.stderr))
			}
			if r, err := run(cmdTimeout, nil, daemonBin, "nft", "check"); err != nil || r.code != 0 {
				t.Errorf("supapaced nft check fails after the reload: %v exit %d %s", err, r.code, brief(r.stderr))
			}
		})
	}
}

// splitTable splits "inet supapace" into family and name.
func splitTable(t testing.TB, table string) (string, string) {
	t.Helper()
	f := strings.Fields(table)
	if len(f) != 2 {
		t.Fatalf("table %q: want \"<family> <name>\"", table)
	}
	return f[0], f[1]
}

// ruleHandle finds the one rule of a chain whose comment is comment.
func ruleHandle(t testing.TB, family, table, chain, comment string) string {
	t.Helper()
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Handle  int    `json:"handle"`
				Comment string `json:"comment"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	out := must(t, cmdTimeout, "nft", "-j", "-a", "list", "chain", family, table, chain)
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("nft list chain %s %s %s: %v", family, table, chain, err)
	}
	var hs []int
	for _, o := range doc.Nftables {
		if o.Rule != nil && o.Rule.Comment == comment {
			hs = append(hs, o.Rule.Handle)
		}
	}
	if len(hs) != 1 {
		t.Fatalf("chain %s %s %s: %d rules with comment %q, want 1", family, table, chain, len(hs), comment)
	}
	return strconv.Itoa(hs[0])
}

// withRuleDeleted takes the drift hold, deletes the one rule of table ("inet
// supapace") and chain carrying comment, by handle, and runs fn. The tables are
// reloaded as soon as fn returns (and in cleanup if anything stopped earlier);
// `supapaced nft check` must then pass. The hold is released in cleanup.
func withRuleDeleted(t testing.TB, table, chain, comment string, fn func()) {
	t.Helper()
	driftHold(t)
	restore := restoreRules(t)
	t.Cleanup(restore)
	defer restore()
	family, name := splitTable(t, table)
	must(t, cmdTimeout, "nft", "delete", "rule", family, name, chain, "handle", ruleHandle(t, family, name, chain, comment))
	fn()
}

// withRuleInserted is withRuleDeleted for one rule inserted at the top of chain.
func withRuleInserted(t testing.TB, table, chain, rule string, fn func()) {
	t.Helper()
	driftHold(t)
	restore := restoreRules(t)
	t.Cleanup(restore)
	defer restore()
	family, name := splitTable(t, table)
	must(t, cmdTimeout, "nft", "insert", "rule", family, name, chain, rule)
	fn()
}

// ───────── scratch objects ─────────

// rmIgnoringAbsent runs a docker removal and reports any failure other than
// the object being gone already.
func rmIgnoringAbsent(t testing.TB, args ...string) {
	r, err := run(cmdTimeout, nil, append([]string{"docker"}, args...)...)
	if err != nil {
		t.Errorf("docker %s: %v", args[0], err)
	} else if r.code != 0 && !strings.Contains(r.stderr, "No such") && !strings.Contains(r.stderr, "not found") {
		t.Errorf("docker %s %s: exit %d: %s", strings.Join(args[:len(args)-1], " "), args[len(args)-1], r.code, brief(r.stderr))
	}
}

// scratchNet creates a docker network labelled supapace.test=1 (opts are
// `docker network create` options) and removes it in cleanup.
func scratchNet(t testing.TB, name string, opts ...string) string {
	t.Helper()
	t.Cleanup(func() { rmIgnoringAbsent(t, "network", "rm", name) })
	docker(t, slices.Concat([]string{"network", "create", "--label", testLabel}, opts, []string{name})...)
	return name
}

// scratchContainer runs a container of the control-plane image with sleep as
// its entrypoint, labelled supapace.test=1 (args are `docker run` options, e.g.
// --network, --ip, --user uid:gid), and removes it with its anonymous volumes
// in cleanup (the image declares one for its data directory).
func scratchContainer(t testing.TB, name string, args ...string) string {
	t.Helper()
	img, err := nodecfg.LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rmIgnoringAbsent(t, "rm", "-f", "-v", name) })
	docker(t, slices.Concat([]string{"run", "-d", "--label", testLabel, "--name", name}, args,
		[]string{"--entrypoint", "sleep", img.ControlPlane, "infinity"})...)
	return name
}

// ───────── probes ─────────

// containerPid is a running container's pid and its configured user.
func containerPid(t testing.TB, name string) (int, string) {
	t.Helper()
	out := strings.Fields(docker(t, "inspect", "-f", "{{.State.Pid}} {{.State.Running}} {{json .Config.User}}", name))
	pid := 0
	if len(out) == 3 {
		pid, _ = strconv.Atoi(out[0])
	}
	if len(out) != 3 || out[1] != "true" || pid <= 0 {
		t.Fatalf("container %s is not running", name)
	}
	var user string
	json.Unmarshal([]byte(out[2]), &user)
	return pid, user
}

// containerIdentity is a running container's pid and the uid:gid it runs as
// (an empty user is root).
func containerIdentity(t testing.TB, name string) (pid, uid, gid int) {
	t.Helper()
	pid, user := containerPid(t, name)
	if user == "" {
		return pid, 0, 0
	}
	u, g, ok := strings.Cut(user, ":")
	var e1, e2 error
	uid, e1 = strconv.Atoi(u)
	gid, e2 = strconv.Atoi(g)
	if !ok || e1 != nil || e2 != nil {
		t.Fatalf("container %s: user %q is not numeric uid:gid", name, user)
	}
	return pid, uid, gid
}

// inContainer is the argv prefix that runs a program in container's network
// namespace at its uid and gid; "" is the node's own namespace, as root.
func inContainer(t testing.TB, container string) []string {
	t.Helper()
	if container == "" {
		return nil
	}
	pid, uid, gid := containerIdentity(t, container)
	return nsenterArgv(fmt.Sprintf("/proc/%d/ns/net", pid), uid, gid)
}

func nsenterArgv(netns string, uid, gid int) []string {
	return []string{"nsenter", "--net=" + netns, "--setuid", strconv.Itoa(uid), "--setgid", strconv.Itoa(gid), "--"}
}

// verdicts maps sp-probe's verdict words to their exit status.
var verdicts = map[string]int{"connected": 0, "answered": 0, "refused": 1, "unreachable": 1, "negative": 1,
	"timeout": 2, "error": 3}

// probe runs `sp-probe ARGS` in container's network namespace at the
// container's uid ("" = the node's namespace, as root) and returns 0 reached,
// 1 refused or negative, 2 timeout. It fails the test unless the output is one
// verdict line whose status equals the exit status — a bad namespace path
// (exit 1, no verdict) and a missing binary (127) are never results — and on
// an "error" verdict.
func probe(t testing.TB, container string, args ...string) int {
	t.Helper()
	return probeArgv(t, container, slices.Concat(inContainer(t, container), []string{probeBin}, args))
}

func probeArgv(t testing.TB, from string, argv []string) int {
	t.Helper()
	r, err := run(probeTimeout, nil, argv...)
	if err != nil {
		t.Fatalf("probe from %q: %v", from, err)
	}
	line, rest, _ := strings.Cut(r.stdout, "\n")
	want, ok := verdicts[strings.SplitN(line, " ", 2)[0]]
	if !ok || rest != "" || !strings.HasSuffix(r.stdout, "\n") || want != r.code {
		t.Fatalf("probe from %q %q: exit %d with output %q (stderr %q): not a probe verdict", from, argv, r.code, brief(r.stdout), brief(r.stderr))
	}
	if want == 3 {
		t.Fatalf("probe from %q: %s", from, line)
	}
	return want
}

// listen starts `sp-probe listen PROTO ADDR [extra]` in container's namespace
// ("" = the node's), waits for it to be bound and returns the bound address.
// The listener is killed in cleanup.
func listen(t testing.TB, container, proto, addr string, extra ...string) string {
	t.Helper()
	argv := slices.Concat(inContainer(t, container), []string{probeBin, "listen", proto, addr}, extra)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	var errb bytes.Buffer
	cmd.Stderr = &errb
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("listener: %v", err)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			cmd.Wait()
		})
	}
	t.Cleanup(stop)
	got := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(out).ReadString('\n')
		got <- line
	}()
	select {
	case line := <-got:
		bound, ok := strings.CutPrefix(strings.TrimSpace(line), "listening ")
		if !ok {
			stop()
			t.Fatalf("listener %s %s in %q did not start: %q %s", proto, addr, container, line, brief(errb.String()))
		}
		return bound
	case <-time.After(10 * time.Second):
		stop()
		t.Fatalf("listener %s %s in %q: not bound within 10 s", proto, addr, container)
	}
	return ""
}

// ───────── gateway ─────────

// gatewayEndpoint is where the gateway is reached and how it is verified.
type gatewayEndpoint struct {
	addr   netip.AddrPort
	domain string
	roots  *x509.CertPool
}

// gatewayAt locates the gateway: the node's primary address on the published
// port, the node's domain and its CA. A variable, so the helpers' self-tests
// can point it at a stand-in.
var gatewayAt = func(t testing.TB) gatewayEndpoint {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(paths.CADir(), "ca.pem"))
	if err != nil {
		t.Fatalf("node CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("node CA: no certificate")
	}
	return gatewayEndpoint{netip.AddrPortFrom(nodeAddr(t), 443), nodeConf(t).Domain, pool}
}

// gatewayTLS is the client TLS configuration for p's host (SNI <ref>.<domain>,
// verified against the node's CA) and the gateway's address.
func gatewayTLS(t testing.TB, p Project) (*tls.Config, netip.AddrPort) {
	t.Helper()
	e := gatewayAt(t)
	return &tls.Config{ServerName: p.Ref + "." + e.domain, RootCAs: e.roots, MinVersion: tls.VersionTLS12}, e.addr
}

func dialer(local netip.Addr) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if local.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: local.AsSlice()}
	}
	return d
}

// dialGateway opens a TLS connection (HTTP/1.1, no ALPN) to the gateway for p
// from local (the zero Addr lets the kernel choose).
func dialGateway(t testing.TB, p Project, local netip.Addr) (*tls.Conn, error) {
	t.Helper()
	conf, dst := gatewayTLS(t, p)
	c, err := dialer(local).Dial("tcp", dst.String())
	if err != nil {
		return nil, err
	}
	tc := tls.Client(c, conf)
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		c.Close()
		return nil, err
	}
	tc.SetDeadline(time.Time{})
	return tc, nil
}

// gatewayConn is a raw TLS connection to the gateway for p from local, closed
// in cleanup.
func gatewayConn(t testing.TB, p Project, local netip.Addr) *tls.Conn {
	t.Helper()
	c, err := dialGateway(t, p, local)
	if err != nil {
		t.Fatalf("gateway connection from %v: %s", local, errText(err))
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func newRequest(t testing.TB, host, method, path string, h http.Header, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "https://"+host+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request %s %s: %s", method, pathOnly(path), errText(err))
	}
	if h != nil {
		req.Header = h.Clone()
	}
	req.Host = host
	return req
}

// connDo sends one HTTP/1.1 request over c and reads the whole response; the
// connection stays open for the next one.
func connDo(t testing.TB, c *tls.Conn, method, path string, h http.Header, body []byte) (*http.Response, error) {
	t.Helper()
	req := newRequest(t, c.ConnectionState().ServerName, method, path, h, body)
	c.SetDeadline(time.Now().Add(httpTimeout))
	defer c.SetDeadline(time.Time{})
	if err := req.Write(c); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return nil, err
	}
	return resp, buffer(resp)
}

// buffer replaces resp's body with an in-memory copy (at most 16 MiB).
func buffer(resp *http.Response) error {
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return err
}

// gatewayRoundTrip sends one request to p's host through the gateway on a new
// connection from local; the response body is read into memory.
func gatewayRoundTrip(t testing.TB, p Project, method, path string, h http.Header, body []byte, local netip.Addr) (*http.Response, error) {
	t.Helper()
	conf, dst := gatewayTLS(t, p)
	tr := &http.Transport{TLSClientConfig: conf, DisableKeepAlives: true, DialContext: dialer(local).DialContext,
		TLSHandshakeTimeout: 10 * time.Second, ExpectContinueTimeout: 10 * time.Second}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: httpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req := newRequest(t, conf.ServerName, method, path, h, body)
	req.URL.Host = dst.String()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, buffer(resp)
}

// gatewayDo is gatewayRoundTrip from the default source; any transport error
// fails the test.
func gatewayDo(t testing.TB, p Project, method, path string, h http.Header, body []byte) *http.Response {
	t.Helper()
	resp, err := gatewayRoundTrip(t, p, method, path, h, body, netip.Addr{})
	if err != nil {
		t.Fatalf("%s %s on %s: %s", method, pathOnly(path), p.Ref, errText(err))
	}
	return resp
}

// bodyOf returns a buffered response body and leaves it readable again.
func bodyOf(resp *http.Response) []byte {
	b, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return b
}

// describe is a response for a failure message; a 200 body is withheld, since
// headers() echoes the bearer token.
func describe(resp *http.Response) string {
	if resp.StatusCode == 200 {
		return "status 200"
	}
	b := bodyOf(resp)
	if len(b) > 512 {
		b = b[:512]
	}
	return redact(fmt.Sprintf("status %d: %s", resp.StatusCode, b))
}

func outcome(resp *http.Response, err error) string {
	if err != nil {
		return errText(err)
	}
	return describe(resp)
}

// wantGatewayRefusal requires the gateway's own refusal: status and the
// gateway's error code in the body. PostgREST refuses many of the same tokens
// by itself, so a status alone cannot tell the gateway's check from a missing
// one; a PGRST… code means the request reached PostgREST and fails the test.
func wantGatewayRefusal(t testing.TB, what string, resp *http.Response, status int, code string) {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	json.Unmarshal(bodyOf(resp), &body)
	if strings.HasPrefix(body.Code, "PGRST") {
		t.Fatalf("%s: refused by PostgREST (%s), not by the gateway: %s", what, body.Code, describe(resp))
	}
	if resp.StatusCode != status || body.Code != code {
		t.Fatalf("%s: want the gateway's %d %q, got %s", what, status, code, describe(resp))
	}
}

// rawToken signs header and payload exactly as given (no JSON encoder in
// between, so duplicate members survive) with RS256.
func rawToken(t testing.TB, priv *rsa.PrivateKey, header, payload string) string {
	t.Helper()
	b64 := base64.RawURLEncoding
	in := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload))
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64.EncodeToString(sig)
}

// hs256Token is an HS256 token over header and payload with secret as the key.
func hs256Token(header, payload string, secret []byte) string {
	b64 := base64.RawURLEncoding
	in := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload))
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(in))
	return in + "." + b64.EncodeToString(m.Sum(nil))
}

// tokenSpec is a token as ordered lists of literal header and payload members
// ("\"name\":value"), so a duplicate member survives to the wire.
type tokenSpec struct{ header, claims []string }

func (s tokenSpec) sign(t testing.TB, priv *rsa.PrivateKey) string {
	t.Helper()
	return rawToken(t, priv, "{"+strings.Join(s.header, ",")+"}", "{"+strings.Join(s.claims, ",")+"}")
}

// with returns list plus member; without drops every member named name;
// withoutLast drops the last one.
func with(list []string, member string) []string { return append(slices.Clone(list), member) }

func without(list []string, name string) []string {
	return slices.DeleteFunc(slices.Clone(list), func(m string) bool { return strings.HasPrefix(m, `"`+name+`":`) })
}

func withoutLast(list []string, name string) []string {
	l := slices.Clone(list)
	for i := len(l) - 1; i >= 0; i-- {
		if strings.HasPrefix(l[i], `"`+name+`":`) {
			return slices.Delete(l, i, i+1)
		}
	}
	return l
}

// bearerCase is a bearer PostgREST alone would serve and the gateway must
// refuse. bad carries exactly one defect, named by want (a jwtx error of Verify,
// or of CheckRole for a role the issuer may not carry); repair undoes exactly
// that defect, after which the token verifies.
type bearerCase struct {
	name   string
	bad    tokenSpec
	repair func(tokenSpec) tokenSpec
	want   error
}

// gatewayOnlyBearers returns the defect-free twin and the bearer cases for an
// issuer key, a subject and an expiry. The same arguments give the same bytes.
func gatewayOnlyBearers(kid, sub string, exp int64) (twin tokenSpec, cases []bearerCase) {
	kidM, role, expM := fmt.Sprintf(`"kid":%q`, kid), `"role":"authenticated"`, fmt.Sprintf(`"exp":%d`, exp)
	twin = tokenSpec{[]string{`"alg":"RS256"`, `"typ":"JWT"`, kidM}, []string{fmt.Sprintf(`"sub":%q`, sub), role, expM}}
	h, c := twin.header, twin.claims
	return twin, []bearerCase{
		{"no_exp", tokenSpec{h, without(c, "exp")},
			func(s tokenSpec) tokenSpec { return tokenSpec{s.header, with(s.claims, expM)} }, jwtx.ErrExpired},
		{"no_role", tokenSpec{h, without(c, "role")},
			func(s tokenSpec) tokenSpec { return tokenSpec{s.header, with(s.claims, role)} }, jwtx.ErrNoRole},
		{"unknown_crit", tokenSpec{with(with(h, `"crit":["x-reach"]`), `"x-reach":1`), c},
			func(s tokenSpec) tokenSpec { return tokenSpec{without(without(s.header, "crit"), "x-reach"), s.claims} }, jwtx.ErrMalformed},
		// The two orders of a duplicated role: one with the permitted role first,
		// one with it last, so a decoder that kept either member would serve one.
		{"duplicate_role", tokenSpec{h, with(c, `"role":"service_role"`)},
			func(s tokenSpec) tokenSpec { return tokenSpec{s.header, withoutLast(s.claims, "role")} }, jwtx.ErrDuplicateMember},
		{"duplicate_role_permitted_last", tokenSpec{h, with(with(without(c, "role"), `"role":"service_role"`), role)},
			func(s tokenSpec) tokenSpec { return tokenSpec{s.header, with(without(s.claims, "role"), role)} }, jwtx.ErrDuplicateMember},
		{"no_kid", tokenSpec{without(h, "kid"), c},
			func(s tokenSpec) tokenSpec { return tokenSpec{with(s.header, kidM), s.claims} }, jwtx.ErrNoKID},
		{"role_authenticator", tokenSpec{h, with(without(c, "role"), `"role":"authenticator"`)},
			func(s tokenSpec) tokenSpec { return tokenSpec{s.header, with(without(s.claims, "role"), role)} }, jwtx.ErrRole},
	}
}

// renderedJWKS is p's public key set exactly as the platform renders it for
// PostgREST (<render dir>/postgrest/jwks.json); its absence fails the test.
func renderedJWKS(t testing.TB, p Project) []byte {
	t.Helper()
	f := filepath.Join(paths.RenderDir(p.Ref), "postgrest", "jwks.json")
	b, err := os.ReadFile(f)
	if err != nil || len(bytes.TrimSpace(b)) == 0 {
		t.Fatalf("rendered key set of %s: %v (empty or absent)", p.Ref, err)
	}
	return b
}

// postgrestDirect sends GET /rpc/whoami with the bearer token straight to p's
// PostgREST at its platform address, from the gateway's network namespace (the
// host has no path to the platform bridge). reached is false when no HTTP
// response came back over the network; "not reached" is evidence of nothing
// unless a control that does reach stands next to it. A bad address or a local
// failure fails the test.
func postgrestDirect(t testing.TB, p Project, token string) (reached bool, status int) {
	t.Helper()
	pid, _ := containerPid(t, gatewayName)
	ip := nodeConf(t).PlatformAddr(p.SubnetIndex)
	if !ip.IsValid() {
		t.Fatalf("project %s: subnet index %d has no platform address", p.Ref, p.SubnetIndex)
	}
	addr := netip.AddrPortFrom(ip, 3000).String()
	var c net.Conn
	var dialErr error
	if err := inNetns(pid, func() { c, dialErr = net.DialTimeout("tcp", addr, 5*time.Second) }); err != nil {
		t.Fatalf("entering the gateway's network namespace: %v", err)
	}
	if dialErr != nil {
		return false, 0
	}
	defer c.Close()
	req, err := http.NewRequest("GET", "http://"+addr+"/rpc/whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if req.Write(c) != nil {
		return false, 0
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return false, 0
	}
	resp.Body.Close()
	return true, resp.StatusCode
}

// inNetns runs fn on an OS thread switched into pid's network namespace; a
// socket fn opens stays in that namespace. If the thread cannot be switched
// back it is left locked and dies with its goroutine.
func inNetns(pid int, fn func()) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		self, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			errc <- err
			return
		}
		defer self.Close()
		target, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer target.Close()
		if err := setns(target.Fd()); err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("setns: %w", err)
			return
		}
		fn()
		if setns(self.Fd()) == nil {
			runtime.UnlockOSThread()
		}
		errc <- nil
	}()
	return <-errc
}

// sysSetns is setns(2)'s number; package syscall does not define it.
var sysSetns = map[string]uintptr{"amd64": 308, "arm64": 268}[runtime.GOARCH]

func setns(fd uintptr) error {
	if sysSetns == 0 {
		return errors.New("setns: unsupported architecture " + runtime.GOARCH)
	}
	if _, _, e := syscall.RawSyscall(sysSetns, fd, syscall.CLONE_NEWNET, 0); e != 0 {
		return e
	}
	return nil
}

// ───────── outside a test ─────────

// mainT is the testing.TB handed to helpers outside a test (TestMain). It
// implements the methods helpers call; Fatal ends the goroutine run started,
// as in a test.
type mainT struct {
	testing.TB
	failed   bool
	cleanups []func()
	out      io.Writer // nil: stderr
}

func (m *mainT) w() io.Writer {
	if m.out != nil {
		return m.out
	}
	return os.Stderr
}

func (m *mainT) Helper()                   {}
func (m *mainT) Name() string              { return "TestMain" }
func (m *mainT) Failed() bool              { return m.failed }
func (m *mainT) Log(a ...any)              { fmt.Fprintln(m.w(), append([]any{"reach:"}, a...)...) }
func (m *mainT) Logf(f string, a ...any)   { fmt.Fprintf(m.w(), "reach: "+f+"\n", a...) }
func (m *mainT) Error(a ...any)            { m.Log(a...); m.failed = true }
func (m *mainT) Errorf(f string, a ...any) { m.Logf(f, a...); m.failed = true }
func (m *mainT) Fatal(a ...any)            { m.Error(a...); runtime.Goexit() }
func (m *mainT) Fatalf(f string, a ...any) { m.Errorf(f, a...); runtime.Goexit() }
func (m *mainT) Cleanup(f func())          { m.cleanups = append(m.cleanups, f) }

// run calls f in its own goroutine, so Fatal can end it, and reports whether
// nothing has failed.
func (m *mainT) run(f func(testing.TB)) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f(m)
	}()
	<-done
	return !m.failed
}

// cleanup runs the registered cleanups, last first.
func (m *mainT) cleanup() {
	for len(m.cleanups) > 0 {
		f := m.cleanups[len(m.cleanups)-1]
		m.cleanups = m.cleanups[:len(m.cleanups)-1]
		m.run(func(testing.TB) { f() })
	}
}

// ───────── the frozen JSON shapes ─────────

// TestHelpers_DecodeGoldenShapes decodes the admin API's documented examples
// into the suite's decode structs: every tagged field must name a member of the
// example and carry its value, so a misspelt tag cannot decode to empty.
func TestHelpers_DecodeGoldenShapes(t *testing.T) {
	for _, c := range []struct {
		name, doc string
		v         any
	}{
		{"mutation", `{ "ref": "abcdefghij0123456789", "operation_id": 12 }`, &mutationJSON{}},
		{"operation", `{ "id": 12, "ref": "abcdefghij0123456789", "kind": "create", "state": "done", "step": "12", "attempts": 1,
  "epoch": 1, "generation": 1, "last_error": "", "created_at": "2026-11-17T10:00:00Z", "updated_at": "2026-11-17T10:00:41Z" }`, &Op{}},
		{"project", `{ "ref": "abcdefghij0123456789", "name": "demo", "state": "active", "generation": 1, "applied_gen": 1,
  "uid": 700000, "subnet_index": 0, "config": { "disk_quota_mb": 8192, "mem_mb": 512, "guc": {} },
  "user_roles": ["authenticated"], "created_at": "…", "deleted_at": null, "purge_after": null }`, &projectJSON{}},
		{"keys", `{ "ref": "abcdefghij0123456789", "anon_key": "<jwt>", "service_role_key": "<jwt>", "postgres_password": "<string>" }`, &keysJSON{}},
		{"project list element", `{ "ref": "abcdefghij0123456789", "name": "demo", "state": "active", "generation": 1, "applied_gen": 1,
  "uid": 700000, "subnet_index": 0, "config": { "disk_quota_mb": 8192, "mem_mb": 512, "guc": {} },
  "user_roles": ["authenticated"], "created_at": "…", "deleted_at": null, "purge_after": null }`, &listedProject{}},
	} {
		if err := json.Unmarshal([]byte(c.doc), c.v); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var src, got map[string]any
		json.Unmarshal([]byte(c.doc), &src)
		b, _ := json.Marshal(c.v)
		json.Unmarshal(b, &got)
		if n := jsonFields(reflect.TypeOf(c.v).Elem()); len(got) != n {
			t.Fatalf("%s: %d of %d fields encode under their own name", c.name, len(got), n)
		}
		for k, v := range got {
			sv, ok := src[k]
			if !ok {
				t.Errorf("%s: field tag %q names no member of the documented shape", c.name, k)
			} else if !reflect.DeepEqual(sv, v) {
				t.Errorf("%s: member %q decodes to %v, documented %v", c.name, k, v, sv)
			}
			if s, ok := sv.(string); ok && s == "" && k != "last_error" {
				t.Errorf("%s: member %q is empty", c.name, k)
			}
		}
	}
	// The list wrappers around the same elements.
	const op = `{ "id": 12, "ref": "abcdefghij0123456789", "kind": "create", "state": "done", "step": "12", "attempts": 1,
  "epoch": 1, "generation": 1, "last_error": "", "created_at": "2026-11-17T10:00:00Z", "updated_at": "2026-11-17T10:00:41Z" }`
	const pr = `{ "ref": "abcdefghij0123456789", "name": "demo", "state": "active", "generation": 1, "applied_gen": 1,
  "uid": 700000, "subnet_index": 0, "config": {}, "user_roles": ["authenticated"] }`
	var ops opsJSON
	var prs projectsJSON
	if err := json.Unmarshal([]byte(`{"operations":[`+op+`]}`), &ops); err != nil || len(ops.Operations) != 1 ||
		ops.Operations[0].ID != 12 || ops.Operations[0].Ref != "abcdefghij0123456789" {
		t.Errorf("operation list: %v %+v", err, ops)
	}
	if err := json.Unmarshal([]byte(`{"projects":[`+pr+`]}`), &prs); err != nil || len(prs.Projects) != 1 ||
		prs.Projects[0].Name != "demo" || prs.Projects[0].Ref != "abcdefghij0123456789" || prs.Projects[0].UID != 700000 {
		t.Errorf("project list: %v %+v", err, prs)
	}
}

// jsonFields counts the JSON members a struct type encodes, through embedded
// structs.
func jsonFields(t reflect.Type) int {
	n := 0
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			n += jsonFields(f.Type)
		} else {
			n++
		}
	}
	return n
}
