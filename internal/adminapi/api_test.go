package adminapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
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

// The tests that need the control-plane database run against a throw-away
// postgres container (the control-plane image, pinned by digest) with no
// network, reached through a unix-socket directory, as internal/store's own
// tests do. They are skipped when Docker is unavailable.
var (
	dbName   string
	sockDir  string
	noDocker string
)

func TestMain(m *testing.M) {
	code := func() int {
		name, dir, err := startDB()
		if name != "" {
			defer exec.Command("docker", "rm", "-f", "-v", name).Run()
		}
		if dir != "" {
			defer os.RemoveAll(dir)
		}
		if err != nil {
			noDocker = err.Error()
		}
		dbName, sockDir = name, dir
		return m.Run()
	}()
	os.Exit(code)
}

func startDB() (name, dir string, err error) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		return "", "", fmt.Errorf("docker unavailable: %v", err)
	}
	im, err := nodecfg.LockedImages()
	if err != nil {
		return "", "", err
	}
	dir, err = os.MkdirTemp("", "sp-adminapi-")
	if err != nil {
		return "", "", err
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		return "", dir, err
	}
	b := make([]byte, 6)
	rand.Read(b)
	name = "sp-test-adminapi-" + hex.EncodeToString(b)
	// A watchdog in its own session removes the container and the socket
	// directory once this process is gone, even if TestMain's cleanup is
	// skipped (panic, timeout, kill).
	w := exec.Command("sh", "-c", `while kill -0 "$1" 2>/dev/null; do sleep 1; done
		docker rm -f -v "$2" >/dev/null 2>&1; sleep 5; docker rm -f -v "$2" >/dev/null 2>&1; rm -rf "$3"`,
		"sh", strconv.Itoa(os.Getpid()), name, dir)
	w.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := w.Start(); err != nil {
		return "", dir, err
	}
	w.Process.Release()
	pw := make([]byte, 16)
	rand.Read(pw)
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "--label", "supapace.test=1",
		"--network", "none", "--user", "70:70", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--read-only",
		"--tmpfs", "/tmp", "--tmpfs", "/var/lib/postgresql/data:uid=70,gid=70,mode=0700",
		"-v", dir+":/var/run/postgresql",
		"-e", "POSTGRES_USER=supapaced", "-e", "POSTGRES_DB=supapaced",
		"-e", "POSTGRES_PASSWORD="+hex.EncodeToString(pw),
		"--entrypoint", "timeout", im.ControlPlane, "-s", "INT", "1800",
		"docker-entrypoint.sh", "postgres", "-c", "listen_addresses=", "-c", "fsync=off").CombinedOutput()
	if err != nil {
		return name, dir, fmt.Errorf("docker run: %v: %s", err, bytes.TrimSpace(out))
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if bytes.Contains(logs, []byte("PostgreSQL init process complete")) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s, err := store.Open(ctx, dir)
			cancel()
			if err == nil {
				s.Close()
				return name, dir, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return name, dir, fmt.Errorf("control-plane test database not ready")
}

// ───────── fixtures ─────────

// fakeOps stands in for the daemon's Ops. Submit and Abort go to the store
// (as the saga runner does) unless an error is injected.
type fakeOps struct {
	st *store.Store

	mu           sync.Mutex
	calls        []string // "submit <kind> <ref>", "abort <ref>", "verify <ref>", "nodecheck"
	params       json.RawMessage
	submitErr    error
	beforeSubmit func() // runs at the start of Submit
	code, msg    string
	drift        []nodecfg.CheckResult
	checks       []nodecfg.CheckResult
	failed       bool // containment failed
}

func (f *fakeOps) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeOps) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeOps) Submit(ctx context.Context, kind, ref string, params json.RawMessage) (int64, error) {
	f.record("submit " + kind + " " + ref)
	f.mu.Lock()
	f.params = params
	err, before := f.submitErr, f.beforeSubmit
	f.mu.Unlock()
	if before != nil {
		before()
	}
	if err != nil {
		return 0, err
	}
	// The store refuses a restart whose merge base is no longer the
	// project's generation; a delete is based on the current one.
	var rp restartShape
	if kind == "restart" {
		dec := json.NewDecoder(bytes.NewReader(params))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rp); err != nil {
			return 0, err
		}
	} else {
		p, err := f.st.GetProject(ctx, ref)
		if err != nil {
			return 0, err
		}
		rp.BaseGeneration = p.Generation
	}
	return f.st.SubmitOperation(ctx, ref, kind, params, rp.BaseGeneration, time.Now())
}

func (f *fakeOps) Abort(ctx context.Context, ref string) (int64, error) {
	f.record("abort " + ref)
	return f.st.RequestAbort(ctx, ref)
}

func (f *fakeOps) VerifyProject(_ context.Context, ref string) (string, string, []nodecfg.CheckResult) {
	f.record("verify " + ref)
	return f.code, f.msg, f.drift
}

func (f *fakeOps) NodeCheck(context.Context) []nodecfg.CheckResult {
	f.record("nodecheck")
	return f.checks
}

func (f *fakeOps) ContainmentOK() bool { return !f.failed }

type env struct {
	st  *store.Store
	ops *fakeOps
	kek secrets.KEK
	h   http.Handler
	p   nodecfg.Paths // the node CA and the gateway certificate
}

// newEnv returns an API on an empty, migrated database with one node row.
func newEnv(t *testing.T) *env {
	t.Helper()
	if noDocker != "" {
		t.Skip(noDocker)
	}
	out, err := exec.Command("docker", "exec", dbName, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "supapaced",
		"-d", "supapaced", "-c", "drop schema public cascade; create schema public").CombinedOutput()
	if err != nil {
		t.Fatalf("reset database: %v: %s", err, out)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, sockDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	c := nodecfg.Default("sp.test")
	c.MemAllocMB, c.PidsAlloc, c.Uplinks = 1<<20, 1<<20, nil
	if err := st.EnsureNode(ctx, c); err != nil {
		t.Fatal(err)
	}
	var kek secrets.KEK
	rand.Read(kek[:])
	ops := &fakeOps{st: st}
	p := nodecfg.Paths{Root: t.TempDir()}
	return &env{st: st, ops: ops, kek: kek, h: New(st, kek, ops, "sp.test", p), p: p}
}

func (e *env) do(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("%s %s: Content-Type %q", method, path, ct)
	}
	b := w.Body.Bytes()
	if !json.Valid(b) {
		t.Fatalf("%s %s: body is not one JSON document: %q", method, path, b)
	}
	return w.Code, b
}

// wantCode asserts an error response: HTTP status and code.
func (e *env) wantCode(t *testing.T, method, path, body string, status int, code string) errBody {
	t.Helper()
	got, b := e.do(t, method, path, body)
	var eb errBody
	strict(t, b, &eb)
	if got != status || eb.Code != code {
		t.Fatalf("%s %s: %d %s (%q), want %d %s", method, path, got, eb.Code, eb.Message, status, code)
	}
	if eb.Message == "" {
		t.Errorf("%s %s: empty message", method, path)
	}
	return eb
}

func (e *env) wantOK(t *testing.T, method, path, body string, status int) []byte {
	t.Helper()
	got, b := e.do(t, method, path, body)
	if got != status {
		t.Fatalf("%s %s: %d %s, want %d", method, path, got, b, status)
	}
	return b
}

// strict decodes one JSON document into v, refusing unknown members and
// trailing data.
func strict(t *testing.T, b []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("decode %T: %v: %s", v, err, b)
	}
	if dec.More() {
		t.Fatalf("decode %T: trailing data: %s", v, b)
	}
}

const demoRef = "abcdefghij0123456789"

var (
	keyOnce sync.Once
	testKey jwtx.Key
)

// issuerKey is one generated RSA-2048 public key.
func issuerKey(t *testing.T) jwtx.Key {
	t.Helper()
	keyOnce.Do(func() {
		priv, kid, err := jwtx.GenerateKey()
		if err != nil {
			panic(err)
		}
		testKey = jwtx.Key{KID: kid, Class: "issuer", Pub: &priv.PublicKey}
	})
	return testKey
}

// jwks returns a key set of n entries, all carrying the same public key under
// distinct kids.
func jwks(t *testing.T, n int) string {
	t.Helper()
	k := issuerKey(t)
	var ks []jwtx.Key
	for i := range n {
		ks = append(ks, jwtx.Key{KID: fmt.Sprintf("k%02d", i), Class: "issuer", Pub: k.Pub})
	}
	b, err := jwtx.MarshalJWKS(ks)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func createBody(t *testing.T, ref string) string {
	t.Helper()
	b := `{"name":"demo","issuer_jwks":` + jwks(t, 1)
	if ref != "" {
		b += `,"ref":"` + ref + `"`
	}
	return b + "}"
}

// restartShape is what a restart hands to Ops.Submit.
type restartShape struct {
	BaseGeneration int64               `json:"base_generation"`
	Config         store.ProjectConfig `json:"config"`
}

type mutation struct {
	Ref         string `json:"ref"`
	OperationID int64  `json:"operation_id"`
}

type errBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// create creates a project through the API and returns its create operation.
func (e *env) create(t *testing.T, ref string) mutation {
	t.Helper()
	var m mutation
	strict(t, e.wantOK(t, "POST", "/v1/projects", createBody(t, ref), http.StatusAccepted), &m)
	if ref != "" && m.Ref != ref || m.OperationID <= 0 {
		t.Fatalf("create %q: %+v", ref, m)
	}
	return m
}

// activate places the project, finishes its create (step 12, done) and makes
// it active at generation 1.
func (e *env) activate(t *testing.T, ref string, op int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := e.st.Place(ctx, ref); err != nil {
		t.Fatal(err)
	}
	must(t, e.st.StartOperation(ctx, op))
	must(t, e.st.AdvanceStep(ctx, op, "12"))
	must(t, e.st.FinishOperation(ctx, op, "done", ""))
	must(t, e.st.SetProjectState(ctx, ref, "active"))
	must(t, e.st.SetApplied(ctx, ref, 1))
}

func (e *env) active(t *testing.T, ref string) {
	t.Helper()
	e.activate(t, ref, e.create(t, ref).OperationID)
}

// deleted takes an active project through delete to the deleted state and
// returns its purge operation.
func (e *env) deleted(t *testing.T, ref string) int64 {
	t.Helper()
	ctx := context.Background()
	must(t, e.st.SetProjectState(ctx, ref, "deleting"))
	id, err := e.st.MarkDeleted(ctx, ref, time.Hour)
	must(t, err)
	return id
}

// failed makes the operation fail (it must be pending or running).
func (e *env) failed(t *testing.T, op int64, lastError string) {
	t.Helper()
	ctx := context.Background()
	must(t, e.st.StartOperation(ctx, op))
	must(t, e.st.FinishOperation(ctx, op, "failed", lastError))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) op(t *testing.T, id int64) store.Operation {
	t.Helper()
	o, err := e.st.GetOperation(context.Background(), id)
	must(t, err)
	return o
}

func (e *env) project(t *testing.T, ref string) store.Project {
	t.Helper()
	p, err := e.st.GetProject(context.Background(), ref)
	must(t, err)
	return p
}

// seedKeys stores a DEK and the three credentials keys returns.
func (e *env) seedKeys(t *testing.T, ref string) {
	t.Helper()
	ctx := context.Background()
	dek := make([]byte, 32)
	rand.Read(dek)
	nonce, wrapped, err := secrets.WrapDEK(e.kek, ref, dek)
	must(t, err)
	must(t, e.st.PutDEK(ctx, ref, "kek", nonce, wrapped))
	for name, v := range map[string]string{"token.anon": "anon-token", "token.service_role": "service-token",
		"pg.postgres.password": "pg-password"} {
		n, ct, err := secrets.Seal(dek, ref, name, []byte(v))
		must(t, err)
		must(t, e.st.PutSecret(ctx, ref, name, n, ct))
	}
}

// ───────── create ─────────

func TestAPI_CreateValidates(t *testing.T) {
	e := newEnv(t)
	one := jwks(t, 1)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	must(t, err)
	weak := `{"keys":[{"kty":"RSA","kid":"w","n":"` + base64.RawURLEncoding.EncodeToString(small.N.Bytes()) + `","e":"AQAB"}]}`
	padded := strings.Replace(one, `"n":"`, `"n":"AAAA`, 1) // leading zero bytes: not minimal
	private := strings.Replace(one, `"kty":"RSA"`, `"kty":"RSA","d":"AQAB"`, 1)
	symmetric := `{"keys":[{"kty":"oct","kid":"s","k":"c2VjcmV0"}]}`
	noUsable := `{"keys":[{"kty":"EC","kid":"e","crv":"P-256","x":"AA","y":"AA"}]}`
	for _, c := range []struct{ name, body string }{
		{"no name", `{"issuer_jwks":` + one + `}`},
		{"empty name", `{"name":"","issuer_jwks":` + one + `}`},
		{"name with control character", `{"name":"de\u001bmo","issuer_jwks":` + one + `}`},
		{"name too long", `{"name":"` + strings.Repeat("a", 65) + `","issuer_jwks":` + one + `}`},
		{"name not a string", `{"name":7,"issuer_jwks":` + one + `}`},
		{"no issuer key set", `{"name":"demo"}`},
		{"null issuer key set", `{"name":"demo","issuer_jwks":null}`},
		{"issuer key set not an object", `{"name":"demo","issuer_jwks":"x"}`},
		{"empty issuer key set", `{"name":"demo","issuer_jwks":{"keys":[]}}`},
		{"1024-bit key", `{"name":"demo","issuer_jwks":` + weak + `}`},
		{"key not minimal", `{"name":"demo","issuer_jwks":` + padded + `}`},
		{"private member", `{"name":"demo","issuer_jwks":` + private + `}`},
		{"symmetric key", `{"name":"demo","issuer_jwks":` + symmetric + `}`},
		{"no usable key", `{"name":"demo","issuer_jwks":` + noUsable + `}`},
		{"seventeen keys", `{"name":"demo","issuer_jwks":` + jwks(t, 17) + `}`},
		{"forbidden role anon", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":["anon"]}`},
		{"forbidden role service_role", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":["service_role"]}`},
		{"forbidden role authenticator", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":["authenticator"]}`},
		{"forbidden role postgres", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":["authenticated","postgres"]}`},
		{"forbidden prefix pg_", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":["pg_monitor"]}`},
		{"forbidden prefix supabase_", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":["supabase_x"]}`},
		{"forbidden prefix supapace_", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":["supapace_x"]}`},
		{"role not an identifier", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":["Bad-Role"]}`},
		{"role empty", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":[""]}`},
		{"role too long", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":["` + strings.Repeat("r", 64) + `"]}`},
		{"duplicate role", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":["editor","editor"]}`},
		{"too many roles", `{"name":"demo","issuer_jwks":` + one + `,"user_roles":["r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","r13","r14","r15","r16","r17"]}`},
		{"disk quota below the floor", `{"name":"demo","issuer_jwks":` + one + `,"disk_quota_mb":1023}`},
		{"disk quota zero", `{"name":"demo","issuer_jwks":` + one + `,"disk_quota_mb":0}`},
		{"disk quota negative", `{"name":"demo","issuer_jwks":` + one + `,"disk_quota_mb":-1}`},
		{"disk quota too large", `{"name":"demo","issuer_jwks":` + one + `,"disk_quota_mb":16777217}`},
		{"disk quota fraction", `{"name":"demo","issuer_jwks":` + one + `,"disk_quota_mb":1.5}`},
		{"unknown field", `{"name":"demo","issuer_jwks":` + one + `,"mem_mb":1024}`},
		{"trailing data", `{"name":"demo","issuer_jwks":` + one + `} {}`},
		{"empty body", ``},
	} {
		t.Run(c.name, func(t *testing.T) {
			e.wantCode(t, "POST", "/v1/projects", c.body, http.StatusBadRequest, "bad_request")
		})
	}
	if ps, _ := e.st.ListProjects(context.Background()); len(ps) != 0 {
		t.Fatalf("refused creates left %d projects", len(ps))
	}

	// The accepted forms.
	var m mutation
	strict(t, e.wantOK(t, "POST", "/v1/projects", `{"name":"demo two","issuer_jwks":`+jwks(t, 16)+
		`,"user_roles":["authenticated","editor"],"disk_quota_mb":16384}`, http.StatusAccepted), &m)
	p := e.project(t, m.Ref)
	want := store.ProjectConfig{DiskQuotaMB: 16384, MemMB: 512, GUC: map[string]string{}}
	if p.Name != "demo two" || p.State != "provisioning" || !reflect.DeepEqual(p.Config, want) ||
		!reflect.DeepEqual(p.UserRoles, []string{"authenticated", "editor"}) {
		t.Fatalf("stored project %+v", p)
	}
	// The create operation carries the validated key set for the worker.
	op := e.op(t, m.OperationID)
	var params struct {
		IssuerJWKS json.RawMessage `json:"issuer_jwks"`
	}
	strict(t, op.Params, &params)
	keys, err := jwtx.ParseJWKS(params.IssuerJWKS, "issuer")
	if err != nil || len(keys) != 16 {
		t.Fatalf("operation params: %d keys, %v", len(keys), err)
	}
	strict(t, e.wantOK(t, "POST", "/v1/projects", `{"name":"d","issuer_jwks":`+one+`}`, http.StatusAccepted), &m)
	p = e.project(t, m.Ref)
	if p.Config.DiskQuotaMB != 8192 || !reflect.DeepEqual(p.UserRoles, []string{"authenticated"}) {
		t.Fatalf("defaults: %+v", p)
	}
}

func TestAPI_CreateBodyBound(t *testing.T) {
	e := newEnv(t)
	pad := strings.Repeat(" ", maxBody)
	e.wantCode(t, "POST", "/v1/projects", createBody(t, "")+pad, http.StatusRequestEntityTooLarge, "bad_request")
	// Just inside the bound is decoded.
	b := createBody(t, "")
	e.wantOK(t, "POST", "/v1/projects", b+strings.Repeat(" ", maxBody-len(b)), http.StatusAccepted)
}

func TestAPI_CreateWithRef(t *testing.T) {
	e := newEnv(t)
	for _, r := range []string{"short", "ABCDEFGHIJ0123456789", "abcdefghij012345678_", "abcdefghij01234567890",
		"abcdefghij012345678", "abcdefghij 123456789", "abcdefghij012345678é"} {
		e.wantCode(t, "POST", "/v1/projects", createBody(t, r), http.StatusBadRequest, "bad_ref")
	}
	live, del, purged := "live0000000000000000", "dele0000000000000000", "purg0000000000000000"
	e.active(t, live)
	e.active(t, del)
	e.deleted(t, del)
	e.active(t, purged)
	e.deleted(t, purged)
	must(t, e.st.MarkPurged(context.Background(), purged))
	prov := "prov0000000000000000"
	e.create(t, prov)
	for _, r := range []string{live, del, purged, prov} {
		e.wantCode(t, "POST", "/v1/projects", createBody(t, r), http.StatusConflict, "ref_exists")
	}
	if got := len(e.ops.Calls()); got != 0 {
		t.Fatalf("create called Ops: %v", e.ops.Calls())
	}
}

func TestAPI_CreateGeneratesRef(t *testing.T) {
	e := newEnv(t)
	m := e.create(t, "")
	if !regexp.MustCompile(`^[a-z0-9]{20}$`).MatchString(m.Ref) {
		t.Fatalf("generated ref %q", m.Ref)
	}
	p := e.project(t, m.Ref)
	op := e.op(t, m.OperationID)
	if p.State != "provisioning" || op.Ref != m.Ref || op.Kind != "create" || op.State != "pending" || op.Step != "1" {
		t.Fatalf("project %+v, operation %+v", p, op)
	}
	if calls := e.ops.Calls(); len(calls) != 0 {
		t.Fatalf("Ops called: %v", calls)
	}
}

func TestNewRef_AlphabetAndLength(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9]{20}$`)
	seen := map[string]bool{}
	counts := map[rune]int{}
	for range 10000 {
		r, err := NewRef()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(r) {
			t.Fatalf("ref %q", r)
		}
		if seen[r] {
			t.Fatalf("duplicate ref %q", r)
		}
		seen[r] = true
		for _, c := range r {
			counts[c]++
		}
	}
	// 200,000 draws over 36 symbols: each about 5,556. A modulo bias over
	// bytes would put the first four symbols near 6,250.
	if len(counts) != 36 {
		t.Fatalf("%d distinct symbols", len(counts))
	}
	for c, n := range counts {
		if n < 5100 || n > 6000 {
			t.Errorf("symbol %q drawn %d times", c, n)
		}
	}
}

// ───────── the output contract ─────────

// sameShape compares a response with its golden file member by member:
// the same members at every level, the same values, except timestamps, which
// must both be RFC 3339 UTC strings (or both null).
func sameShape(t *testing.T, name string, got []byte) {
	t.Helper()
	golden, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	must(t, json.Unmarshal(got, &g))
	must(t, json.Unmarshal(golden, &w))
	compare(t, name, "", g, w)
}

var stamps = map[string]bool{"created_at": true, "updated_at": true, "deleted_at": true, "purge_after": true}

func compare(t *testing.T, file, path string, got, want any) {
	t.Helper()
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			t.Errorf("%s: %s is %T, want an object", file, path, got)
			return
		}
		for k := range g {
			if _, ok := w[k]; !ok {
				t.Errorf("%s: %s.%s emitted, not in the golden file", file, path, k)
			}
		}
		for k, wv := range w {
			gv, ok := g[k]
			if !ok {
				t.Errorf("%s: %s.%s missing", file, path, k)
				continue
			}
			if stamps[k] {
				if (wv == nil) != (gv == nil) {
					t.Errorf("%s: %s.%s = %v, golden %v", file, path, k, gv, wv)
				}
				for _, v := range []any{gv, wv} {
					if s, ok := v.(string); ok {
						if ts, err := time.Parse(time.RFC3339, s); err != nil || !strings.HasSuffix(s, "Z") || ts.Nanosecond() != 0 {
							t.Errorf("%s: %s.%s = %q is not RFC 3339 UTC", file, path, k, s)
						}
					} else if v != nil {
						t.Errorf("%s: %s.%s = %v is not a string", file, path, k, v)
					}
				}
				continue
			}
			compare(t, file, path+"."+k, gv, wv)
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			t.Errorf("%s: %s = %v, golden %v", file, path, got, want)
			return
		}
		for i := range w {
			compare(t, file, fmt.Sprintf("%s[%d]", path, i), g[i], w[i])
		}
	default:
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %s = %#v, golden %#v", file, path, got, want)
		}
	}
}

// The frozen shapes, as a reader that knows only the contract decodes them.
type (
	configShape struct {
		DiskQuotaMB int               `json:"disk_quota_mb"`
		MemMB       int               `json:"mem_mb"`
		GUC         map[string]string `json:"guc"`
	}
	projectShape struct {
		Ref         string      `json:"ref"`
		Name        string      `json:"name"`
		State       string      `json:"state"`
		Generation  int64       `json:"generation"`
		AppliedGen  int64       `json:"applied_gen"`
		UID         *int        `json:"uid"`
		SubnetIndex *int        `json:"subnet_index"`
		Config      configShape `json:"config"`
		UserRoles   []string    `json:"user_roles"`
		CreatedAt   string      `json:"created_at"`
		DeletedAt   *string     `json:"deleted_at"`
		PurgeAfter  *string     `json:"purge_after"`
		URL         string      `json:"url"`
		CACert      *string     `json:"ca_cert"`
	}
	opShape struct {
		ID         int64  `json:"id"`
		Ref        string `json:"ref"`
		Kind       string `json:"kind"`
		State      string `json:"state"`
		Step       string `json:"step"`
		Attempts   int    `json:"attempts"`
		Epoch      int64  `json:"epoch"`
		Generation int64  `json:"generation"`
		LastError  string `json:"last_error"`
		CreatedAt  string `json:"created_at"`
		UpdatedAt  string `json:"updated_at"`
	}
	keysShape struct {
		Ref              string  `json:"ref"`
		AnonKey          string  `json:"anon_key"`
		ServiceRoleKey   string  `json:"service_role_key"`
		PostgresPassword string  `json:"postgres_password"`
		URL              string  `json:"url"`
		CACert           *string `json:"ca_cert"`
	}
	checkShape struct {
		OK      bool   `json:"ok"`
		Code    string `json:"code"`
		Message string `json:"message"`
		Drift   []struct {
			Name   string `json:"name"`
			Detail string `json:"detail"`
		} `json:"drift"`
	}
	nodeCheckShape struct {
		OK                bool `json:"ok"`
		ContainmentFailed bool `json:"containment_failed"`
		Checks            []struct {
			Name   string `json:"name"`
			OK     bool   `json:"ok"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
)

func TestAPI_JSONShapes(t *testing.T) {
	e := newEnv(t)
	check := func(name string, b []byte, v any) {
		t.Helper()
		strict(t, b, v)
		golden, err := os.ReadFile(filepath.Join("testdata", name+".json"))
		must(t, err)
		strict(t, golden, reflect.New(reflect.TypeOf(v).Elem()).Interface())
		sameShape(t, name, b)
	}

	b := e.wantOK(t, "POST", "/v1/projects", createBody(t, demoRef), http.StatusAccepted)
	check("mutation", b, &mutation{})
	var m mutation
	strict(t, b, &m)
	e.activate(t, demoRef, m.OperationID)
	e.seedKeys(t, demoRef)

	check("operation", e.wantOK(t, "GET", "/v1/operations/"+strconv.FormatInt(m.OperationID, 10), "", 200), &opShape{})
	check("operations", e.wantOK(t, "GET", "/v1/operations?ref="+demoRef, "", 200), &struct {
		Operations []opShape `json:"operations"`
	}{})
	check("operations", e.wantOK(t, "GET", "/v1/operations", "", 200), &struct {
		Operations []opShape `json:"operations"`
	}{})
	check("project", e.wantOK(t, "GET", "/v1/projects/"+demoRef, "", 200), &projectShape{})
	check("projects", e.wantOK(t, "GET", "/v1/projects", "", 200), &struct {
		Projects []projectShape `json:"projects"`
	}{})
	check("keys", e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/keys", "", 200), &keysShape{})
	check("check_ok", e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/check", "", 200), &checkShape{})
	e.ops.code, e.ops.msg = "peer", "peer check failed"
	e.ops.drift = []nodecfg.CheckResult{{Name: "event-triggers", Detail: "an event trigger exists"}}
	check("check_failed", e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/check", "", 200), &checkShape{})
	e.ops.checks = []nodecfg.CheckResult{{Name: "nft", OK: true}}
	check("node_check", e.wantOK(t, "GET", "/v1/node/check", "", 200), &nodeCheckShape{})
	got, b := e.do(t, "POST", "/v1/projects", createBody(t, demoRef))
	if got != http.StatusConflict {
		t.Fatalf("second create: %d", got)
	}
	check("error", b, &errBody{})

	// A deleted project carries its timestamps; a fresh one has nulls.
	e.deleted(t, demoRef)
	var p projectShape
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef, "", 200), &p)
	if p.DeletedAt == nil || p.PurgeAfter == nil || p.State != "deleted" {
		t.Fatalf("deleted project: %+v", p)
	}
	m = e.create(t, "")
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+m.Ref, "", 200), &p)
	if p.UID != nil || p.SubnetIndex != nil || p.DeletedAt != nil {
		t.Fatalf("unplaced project: %+v", p)
	}
	// Empty lists are arrays, never null.
	e2 := newEnv(t)
	if b := e2.wantOK(t, "GET", "/v1/projects", "", 200); string(bytes.TrimSpace(b)) != `{"projects":[]}` {
		t.Fatalf("empty project list: %s", b)
	}
	if b := e2.wantOK(t, "GET", "/v1/operations", "", 200); string(bytes.TrimSpace(b)) != `{"operations":[]}` {
		t.Fatalf("empty operation list: %s", b)
	}
	e2.ops.checks = nil
	var nc nodeCheckShape
	strict(t, e2.wantOK(t, "GET", "/v1/node/check", "", 200), &nc)
	if nc.Checks == nil || nc.OK {
		t.Fatalf("node check without rows: %+v", nc)
	}
}

// ───────── operations ─────────

func TestAPI_SubmitOnlyRestartAndDelete(t *testing.T) {
	e := newEnv(t)
	a, d, p, r, x := "aaaa0000000000000000", "dddd0000000000000000", "pppp0000000000000000", "rrrr0000000000000000", "xxxx0000000000000000"
	e.active(t, a)
	e.active(t, d)
	e.active(t, p)
	purge := e.deleted(t, p)
	rop := e.create(t, r).OperationID
	e.failed(t, rop, "internal: x")
	e.create(t, x)
	ctx := context.Background()
	beforePurge := e.op(t, purge).NotBefore

	var m mutation
	strict(t, e.wantOK(t, "POST", "/v1/projects/"+a+"/restart", `{}`, 202), &m)
	if o := e.op(t, m.OperationID); m.Ref != a || o.Kind != "restart" || o.Generation != 2 {
		t.Fatalf("restart: %+v %+v", m, o)
	}
	strict(t, e.wantOK(t, "DELETE", "/v1/projects/"+d, "", 202), &m)
	if o := e.op(t, m.OperationID); m.Ref != d || o.Kind != "delete" {
		t.Fatalf("delete: %+v %+v", m, o)
	}
	want := []string{"submit restart " + a, "submit delete " + d}
	if got := e.ops.Calls(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}

	strict(t, e.wantOK(t, "POST", "/v1/projects/"+p+"/purge", "", 202), &m)
	o := e.op(t, purge)
	if m.Ref != p || m.OperationID != purge || !o.NotBefore.Before(beforePurge) || o.NotBefore.After(time.Now().Add(time.Minute)) {
		t.Fatalf("purge: %+v, not_before %v (was %v)", m, o.NotBefore, beforePurge)
	}
	strict(t, e.wantOK(t, "POST", "/v1/operations/"+strconv.FormatInt(rop, 10)+"/retry", "", 202), &m)
	if o := e.op(t, rop); m.Ref != r || m.OperationID != rop || o.State != "pending" || o.Attempts != 0 {
		t.Fatalf("retry: %+v %+v", m, o)
	}
	if got := e.ops.Calls(); !slices.Equal(got, want) {
		t.Fatalf("purge or retry called Ops: %v", got)
	}

	strict(t, e.wantOK(t, "POST", "/v1/projects/"+x+"/abort", "", 202), &m)
	ops, err := e.st.ListOperations(ctx, x)
	must(t, err)
	if m.Ref != x || m.OperationID != ops[0].ID || ops[0].State != "aborting" {
		t.Fatalf("abort: %+v %+v", m, ops)
	}
	if got := e.ops.Calls(); !slices.Equal(got, append(want, "abort "+x)) {
		t.Fatalf("calls %v", got)
	}
}

func TestAPI_ErrorCodes(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	e.wantCode(t, "GET", "/v1/projects/NOT-A-REF", "", 400, "bad_ref")
	e.wantCode(t, "POST", "/v1/projects", createBody(t, demoRef), 409, "ref_exists")
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/restart", `{"set":{"fsync":"off"}}`, 400, "bad_request")
	e.wantCode(t, "GET", "/v1/projects/zzzz0000000000000000", "", 404, "not_found")
	e.wantCode(t, "GET", "/v1/operations/999", "", 404, "not_found")
	e.wantCode(t, "GET", "/v1/nothing", "", 404, "not_found")
	e.wantCode(t, "PUT", "/v1/projects/"+demoRef, "", 404, "not_found")
	e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/abort", "", 409, "conflict")
	e.ops.failed = true
	e.wantCode(t, "DELETE", "/v1/projects/"+demoRef, "", 503, "containment_failed")
}

func TestAPI_StrictRequests(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	pr := "/v1/projects/" + demoRef
	for _, c := range []struct{ method, path, body string }{
		{"POST", pr + "/restart", `{"set":{},"extra":1}`},
		{"POST", pr + "/restart", `{"set":{}}{}`},
		{"POST", pr + "/restart", `{"set":{}} x`},
		{"POST", pr + "/restart", `[]`},
		{"POST", pr + "/restart", ``},
		{"POST", pr + "/restart", `{"set":{"max_connections":200}}`},
		{"POST", pr + "/restart", `{"set":{}}` + strings.Repeat(" ", maxBody)},
		{"DELETE", pr, `{}`},
		{"POST", pr + "/purge", `{}`},
		{"POST", pr + "/abort", `x`},
		{"POST", pr + "/check", `{}`},
		{"POST", "/v1/operations/1/retry", `{}`},
		{"GET", "/v1/operations?ref=" + demoRef + "&ref=" + demoRef, ``},
		{"GET", "/v1/operations?kind=create", ``},
		{"GET", "/v1/operations?ref=%zz", ``},
		{"GET", "/v1/operations/0", ``},
		{"GET", "/v1/operations/-1", ``},
		{"GET", "/v1/operations/+1", ``},
		{"GET", "/v1/operations/01", ``},
		{"GET", "/v1/operations/x", ``},
		{"GET", "/v1/operations/99999999999999999999", ``},
	} {
		got, b := e.do(t, c.method, c.path, c.body)
		var eb errBody
		strict(t, b, &eb)
		if got/100 != 4 || eb.Code != "bad_request" {
			t.Errorf("%s %s %.40q: %d %s", c.method, c.path, c.body, got, b)
		}
	}
	e.wantCode(t, "GET", "/v1/operations?ref=BAD", "", 400, "bad_ref")
	if calls := e.ops.Calls(); len(calls) != 0 {
		t.Fatalf("refused requests reached Ops: %v", calls)
	}
}

func TestAPI_RestartSet(t *testing.T) {
	pr := "/v1/projects/" + demoRef + "/restart"
	for _, c := range []struct {
		body string
		ok   bool
		want store.ProjectConfig
	}{
		{`{"set":{"max_connections":"200"}}`, true, store.ProjectConfig{DiskQuotaMB: 8192, MemMB: 512, GUC: map[string]string{"max_connections": "200"}}},
		{`{"disk_quota_mb":16384}`, true, store.ProjectConfig{DiskQuotaMB: 16384, MemMB: 512, GUC: map[string]string{}}},
		{`{"set":{"work_mem":"8MB","cron.max_running_jobs":"4"},"disk_quota_mb":4096}`, true,
			store.ProjectConfig{DiskQuotaMB: 4096, MemMB: 512, GUC: map[string]string{"work_mem": "8MB", "cron.max_running_jobs": "4"}}},
		{`{}`, true, store.ProjectConfig{DiskQuotaMB: 8192, MemMB: 512, GUC: map[string]string{}}},
		{`{"set":{"fsync":"off"}}`, false, store.ProjectConfig{}},
		{`{"set":{"disk_quota_mb":"4096"}}`, false, store.ProjectConfig{}},
		{`{"set":{"Max_Connections":"200"}}`, false, store.ProjectConfig{}},
		{`{"set":{"max_connections":"5"}}`, false, store.ProjectConfig{}},
		{`{"set":{"max_connections":"0200"}}`, false, store.ProjectConfig{}},
		{`{"set":{"max_connections":"200; x"}}`, false, store.ProjectConfig{}},
		// 40 % of the cluster's 512 MB, not of the 768 MB admission figure.
		{`{"set":{"shared_buffers":"256MB"}}`, false, store.ProjectConfig{}},
		{`{"set":{"effective_cache_size":"600MB"}}`, false, store.ProjectConfig{}},
		{`{"disk_quota_mb":1023}`, false, store.ProjectConfig{}},
		{`{"disk_quota_mb":0}`, false, store.ProjectConfig{}},
		{`null`, false, store.ProjectConfig{}},
		{`"x"`, false, store.ProjectConfig{}},
		{`{"disk_quota_mb":16777217}`, false, store.ProjectConfig{}},
	} {
		e2 := newEnv(t)
		e2.active(t, demoRef)
		if !c.ok {
			e2.wantCode(t, "POST", pr, c.body, 400, "bad_request")
			if calls := e2.ops.Calls(); len(calls) != 0 {
				t.Errorf("%s: refused restart reached Ops: %v", c.body, calls)
			}
			continue
		}
		e2.wantOK(t, "POST", pr, c.body, 202)
		var got restartShape
		strict(t, e2.ops.params, &got)
		if !reflect.DeepEqual(got, restartShape{1, c.want}) {
			t.Errorf("%s: params %+v, want %+v", c.body, got, c.want)
		}
	}
	// Settings merge over the stored configuration.
	e3 := newEnv(t)
	e3.active(t, demoRef)
	ctx := context.Background()
	must(t, e3.st.BumpGeneration(ctx, demoRef, 2, store.ProjectConfig{DiskQuotaMB: 8192, MemMB: 512,
		GUC: map[string]string{"work_mem": "8MB"}}))
	e3.wantOK(t, "POST", pr, `{"set":{"max_connections":"200"}}`, 202)
	var got restartShape
	strict(t, e3.ops.params, &got)
	if want := map[string]string{"work_mem": "8MB", "max_connections": "200"}; !reflect.DeepEqual(got.Config.GUC, want) {
		t.Fatalf("merged %v, want %v", got.Config.GUC, want)
	}
	// The base generation is the generation the merge read.
	if got.BaseGeneration != 2 {
		t.Fatalf("base_generation %d, want 2", got.BaseGeneration)
	}
	if p := e3.project(t, demoRef); !reflect.DeepEqual(p.Config.GUC, map[string]string{"work_mem": "8MB"}) {
		t.Fatalf("the API changed the stored configuration: %v", p.Config.GUC)
	}
	e3.wantCode(t, "POST", "/v1/projects/zzzz0000000000000000/restart", `{}`, 404, "not_found")
	// A configuration change between the read and the admission is refused.
	e4 := newEnv(t)
	e4.active(t, demoRef)
	e4.ops.beforeSubmit = func() {
		must(t, e4.st.BumpGeneration(ctx, demoRef, 2, store.ProjectConfig{DiskQuotaMB: 8192, MemMB: 512}))
	}
	e4.wantCode(t, "POST", pr, `{"set":{"max_connections":"200"}}`, 409, "conflict")
}

func TestAPI_StateRules(t *testing.T) {
	e := newEnv(t)
	prov, act := "prov0000000000000000", "acti0000000000000000"
	e.create(t, prov)
	e.active(t, act)
	e.wantCode(t, "DELETE", "/v1/projects/"+prov, "", 409, "conflict")
	e.wantCode(t, "POST", "/v1/projects/"+prov+"/restart", `{}`, 409, "conflict")
	e.wantCode(t, "POST", "/v1/projects/"+act+"/abort", "", 409, "conflict")
	e.wantCode(t, "POST", "/v1/projects/"+act+"/purge", "", 409, "conflict")
	// A second restart or delete on a busy ref.
	e.wantOK(t, "POST", "/v1/projects/"+act+"/restart", `{}`, 202)
	e.wantCode(t, "POST", "/v1/projects/"+act+"/restart", `{}`, 409, "conflict")
	e.wantCode(t, "DELETE", "/v1/projects/"+act, "", 409, "conflict")
	e.wantCode(t, "DELETE", "/v1/projects/zzzz0000000000000000", "", 404, "not_found")
	e.wantCode(t, "POST", "/v1/projects/zzzz0000000000000000/abort", "", 404, "not_found")
	e.wantCode(t, "POST", "/v1/projects/zzzz0000000000000000/purge", "", 404, "not_found")
}

func TestAPI_RestartOnRestartingIsConflict(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	must(t, e.st.SetProjectState(context.Background(), demoRef, "restarting"))
	eb := e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/restart", `{}`, 409, "conflict")
	if !strings.Contains(eb.Message, "restarting") {
		t.Fatalf("message %q", eb.Message)
	}
}

func TestAPI_SubmitConflictCarriesMessage(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	e.ops.submitErr = fmt.Errorf("%w: not yet adopted", store.ErrConflict)
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/v1/projects/" + demoRef + "/restart", `{}`},
		{"DELETE", "/v1/projects/" + demoRef, ""},
	} {
		eb := e.wantCode(t, c.method, c.path, c.body, 409, "conflict")
		if !strings.Contains(eb.Message, "not yet adopted") {
			t.Fatalf("message %q", eb.Message)
		}
	}
	for _, m := range []string{"conflict: not yet adopted", "conflict:"} {
		if eb := e.wantCode(t, "DELETE", "/v1/projects/"+demoRef, "", 409, "conflict"); eb.Message == m {
			t.Fatalf("message repeats the code: %q", eb.Message)
		}
	}
}

// logs captures the default logger for the test.
func logs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&b, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &b
}

func TestAPI_InternalErrorIsFixedAndLogged(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	b := logs(t)
	e.ops.submitErr = errors.New("boom\x1b[31m at /some/socket/path " + strings.Repeat("z", 3000))
	eb := e.wantCode(t, "DELETE", "/v1/projects/"+demoRef, "", 500, "internal")
	if eb.Message != "internal error" {
		t.Fatalf("message %q", eb.Message)
	}
	out := b.String()
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "boom[31m at /some/socket/path") ||
		strings.ContainsRune(out, 0x1b) || strings.Contains(out, strings.Repeat("z", 1100)) {
		t.Fatalf("log %q", out)
	}
	// Errors that are not internal are not logged.
	b.Reset()
	e.wantCode(t, "GET", "/v1/projects/zzzz0000000000000000", "", 404, "not_found")
	if b.Len() != 0 {
		t.Fatalf("log %q", b.String())
	}
}

func TestAPI_ErrorMessages(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	purged := "purg0000000000000000"
	e.active(t, purged)
	e.seedKeys(t, purged)
	must(t, e.st.DestroyKeys(context.Background(), purged))
	for _, c := range []struct {
		method, path, body string
		status             int
		code, message      string
	}{
		{"GET", "/v1/projects/BAD", "", 400, "bad_ref", "a ref is 20 characters of a-z and 0-9"},
		{"POST", "/v1/projects", createBody(t, demoRef), 409, "ref_exists",
			"ref " + demoRef + " exists or existed; refs are never reused"},
		{"GET", "/v1/projects/zzzz0000000000000000", "", 404, "not_found", "no such project"},
		{"GET", "/v1/operations/999", "", 404, "not_found", "no such operation"},
		{"POST", "/v1/operations/999/retry", "", 404, "not_found", "no such operation"},
		{"GET", "/v1/projects/" + purged + "/keys", "", 404, "not_found",
			"the project's keys were destroyed when it was purged or aborted"},
		{"POST", "/v1/projects/" + demoRef + "/abort", "", 409, "conflict",
			"project is active; abort applies only to a create in progress; an active project is removed with delete"},
		{"GET", "/v1/nothing", "", 404, "not_found", "no such route"},
		{"POST", "/v1/projects", `{"name":"demo","issuer_jwks":{"keys":[]}}`, 400, "bad_request",
			"issuer_jwks: unacceptable key; it must be a JSON Web Key Set of 1 to 16 RSA signing keys " +
				"(RS256, 2048 to 4096 bits, exponent 65537), each with a kid and without private members"},
		{"POST", "/v1/projects", `{"name":"demo"}`, 400, "bad_request",
			"issuer_jwks: malformed; it must be a JSON Web Key Set of 1 to 16 RSA signing keys " +
				"(RS256, 2048 to 4096 bits, exponent 65537), each with a kid and without private members"},
		{"POST", "/v1/projects", `null`, 400, "bad_request", "request body must be a JSON object"},
	} {
		eb := e.wantCode(t, c.method, c.path, c.body, c.status, c.code)
		if eb.Message != c.message {
			t.Errorf("%s %s: message %q, want %q", c.method, c.path, eb.Message, c.message)
		}
	}
	e.ops.failed = true
	eb := e.wantCode(t, "DELETE", "/v1/projects/"+demoRef, "", 503, "containment_failed")
	if !strings.Contains(eb.Message, "supapace node check") {
		t.Fatalf("message %q", eb.Message)
	}
}

func TestAPI_BodyMustBeObject(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	for _, b := range []string{`null`, ` null `, `"x"`, `1`, `[]`, `true`} {
		e.wantCode(t, "POST", "/v1/projects", b, 400, "bad_request")
		e.wantCode(t, "POST", "/v1/projects/"+demoRef+"/restart", b, 400, "bad_request")
	}
	e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/restart", " \n{}\n", 202)
	if calls := e.ops.Calls(); len(calls) != 1 {
		t.Fatalf("calls %v", calls)
	}
}

func TestAPI_CheckOnlyRunningStates(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	prov, act, rst, dlg, del, prg, abt := "prov0000000000000000", "acti0000000000000000", "rest0000000000000000",
		"dlng0000000000000000", "dele0000000000000000", "purg0000000000000000", "abor0000000000000000"
	e.create(t, prov)
	e.active(t, act)
	e.active(t, rst)
	must(t, e.st.SetProjectState(ctx, rst, "restarting"))
	e.active(t, dlg)
	must(t, e.st.SetProjectState(ctx, dlg, "deleting"))
	e.active(t, del)
	e.deleted(t, del)
	e.active(t, prg)
	e.deleted(t, prg)
	must(t, e.st.MarkPurged(ctx, prg))
	e.create(t, abt)
	_, err := e.st.RequestAbort(ctx, abt)
	must(t, err)
	must(t, e.st.MarkAborted(ctx, abt))
	for ref, state := range map[string]string{prov: "provisioning", dlg: "deleting", del: "deleted", prg: "purged", abt: "aborted"} {
		eb := e.wantCode(t, "POST", "/v1/projects/"+ref+"/check", "", 409, "conflict")
		if !strings.Contains(eb.Message, state) {
			t.Errorf("%s: message %q", state, eb.Message)
		}
	}
	if calls := e.ops.Calls(); len(calls) != 0 {
		t.Fatalf("refused checks reached Ops: %v", calls)
	}
	e.ops.failed = true // still a read
	for _, ref := range []string{act, rst} {
		e.wantOK(t, "POST", "/v1/projects/"+ref+"/check", "", 200)
	}
}

func TestAPI_KeysShape(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	e.wantCode(t, "GET", "/v1/projects/"+demoRef+"/keys", "", 404, "not_found") // no DEK yet
	e.seedKeys(t, demoRef)
	var k keysShape
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef+"/keys", "", 200), &k)
	if k != (keysShape{demoRef, "anon-token", "service-token", "pg-password", "https://" + demoRef + ".sp.test", nil}) {
		t.Fatalf("keys %+v", k)
	}
	must(t, e.st.DestroyKeys(context.Background(), demoRef))
	e.wantCode(t, "GET", "/v1/projects/"+demoRef+"/keys", "", 404, "not_found")
	e.wantCode(t, "GET", "/v1/projects/zzzz0000000000000000/keys", "", 404, "not_found")

	// A DEK but a credential not yet minted.
	other := "othe0000000000000000"
	e.active(t, other)
	dek := make([]byte, 32)
	nonce, wrapped, err := secrets.WrapDEK(e.kek, other, dek)
	must(t, err)
	must(t, e.st.PutDEK(context.Background(), other, "kek", nonce, wrapped))
	e.wantCode(t, "GET", "/v1/projects/"+other+"/keys", "", 404, "not_found")
	// A DEK the node's KEK cannot open is an internal error.
	third := "thir0000000000000000"
	e.active(t, third)
	e.seedKeys(t, third)
	var wrong secrets.KEK
	e.h = New(e.st, wrong, e.ops, "sp.test", e.p)
	e.wantCode(t, "GET", "/v1/projects/"+third+"/keys", "", 500, "internal")
}

func TestAPI_CheckCallsVerify(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	path := "/v1/projects/" + demoRef + "/check"
	b := e.wantOK(t, "POST", path, "", 200)
	if string(bytes.TrimSpace(b)) != `{"ok":true,"drift":[]}` {
		t.Fatalf("ok check: %s", b)
	}
	e.ops.code, e.ops.msg = "peer", "socket peer is not the cluster"
	var c checkShape
	c = checkShape{}
	strict(t, e.wantOK(t, "POST", path, "", 200), &c)
	if c.OK || c.Code != "peer" || c.Message != "socket peer is not the cluster" || c.Drift == nil {
		t.Fatalf("peer check: %+v", c)
	}
	for _, code := range []string{"timeout", "internal"} {
		e.ops.code = code
		c = checkShape{}
		strict(t, e.wantOK(t, "POST", path, "", 200), &c)
		if c.OK || c.Code != code {
			t.Fatalf("%s check: %+v", code, c)
		}
	}
	// Only the three operational codes leave the API.
	for _, code := range []string{"assertion", "peer\n", "x"} {
		e.ops.code = code
		c = checkShape{}
		strict(t, e.wantOK(t, "POST", path, "", 200), &c)
		if c.OK || c.Code != "internal" {
			t.Fatalf("code %q: %+v", code, c)
		}
	}
	e.ops.code, e.ops.msg = "peer", ""
	c = checkShape{}
	strict(t, e.wantOK(t, "POST", path, "", 200), &c)
	if c.Message == "" {
		t.Fatalf("empty message: %+v", c)
	}
	// Drift: findings only, sanitised and capped; ok follows the code alone.
	e.ops.code, e.ops.msg = "", "ignored"
	long := strings.Repeat("d", 300)
	e.ops.drift = []nodecfg.CheckResult{
		{Name: "superuser", Detail: "role \x1b]0;x\x07evil‮ is superuser"},
		{Name: "presence", OK: true, Detail: "fine"},
		{Name: "source-file", Detail: long},
	}
	c = checkShape{}
	strict(t, e.wantOK(t, "POST", path, "", 200), &c)
	if !c.OK || c.Code != "" || c.Message != "" || len(c.Drift) != 2 {
		t.Fatalf("drift check: %+v", c)
	}
	if c.Drift[0].Name != "superuser" || c.Drift[0].Detail != "role ]0;xevil is superuser" {
		t.Fatalf("drift not sanitised: %q", c.Drift[0].Detail)
	}
	if c.Drift[1].Name != "source-file" || len(c.Drift[1].Detail) != 256 {
		t.Fatalf("drift detail not capped: %d", len(c.Drift[1].Detail))
	}
	// Many findings are capped.
	e.ops.drift = nil
	for i := range 200 {
		e.ops.drift = append(e.ops.drift, nodecfg.CheckResult{Name: "configuration", Detail: strconv.Itoa(i)})
	}
	c = checkShape{}
	strict(t, e.wantOK(t, "POST", path, "", 200), &c)
	if len(c.Drift) != maxDrift {
		t.Fatalf("%d drift rows", len(c.Drift))
	}
	// The message is sanitised and capped at 1 KiB.
	e.ops.drift = nil
	e.ops.code, e.ops.msg = "peer", "bad\x00\x1b[2Jpeer"+strings.Repeat("m", 2000)
	c = checkShape{}
	strict(t, e.wantOK(t, "POST", path, "", 200), &c)
	if !strings.HasPrefix(c.Message, "bad[2Jpeer") || len(c.Message) != 1024 {
		t.Fatalf("message %.40q (%d bytes)", c.Message, len(c.Message))
	}
	before := len(e.ops.Calls())
	e.wantCode(t, "POST", "/v1/projects/zzzz0000000000000000/check", "", 404, "not_found")
	if len(e.ops.Calls()) != before {
		t.Fatalf("unknown project reached VerifyProject")
	}
}

func TestAPI_NodeCheck(t *testing.T) {
	e := newEnv(t)
	var nc nodeCheckShape
	e.ops.checks = []nodecfg.CheckResult{{Name: "nft", OK: true}, {Name: "bridge-nf", OK: true, Detail: "off"}}
	strict(t, e.wantOK(t, "GET", "/v1/node/check", "", 200), &nc)
	if !nc.OK || nc.ContainmentFailed || len(nc.Checks) != 2 {
		t.Fatalf("%+v", nc)
	}
	e.ops.checks = []nodecfg.CheckResult{{Name: "nft", OK: true}, {Name: "docker\x1b", OK: false, Detail: "x\x07" + strings.Repeat("y", 300)}}
	strict(t, e.wantOK(t, "GET", "/v1/node/check", "", 200), &nc)
	if nc.OK || nc.Checks[1].Name != "docker" || len(nc.Checks[1].Detail) != 256 || strings.ContainsRune(nc.Checks[1].Detail, 7) {
		t.Fatalf("%+v", nc)
	}
	e.ops.checks = []nodecfg.CheckResult{{Name: "nft", OK: true}}
	e.ops.failed = true
	strict(t, e.wantOK(t, "GET", "/v1/node/check", "", 200), &nc)
	if nc.OK || !nc.ContainmentFailed {
		t.Fatalf("%+v", nc)
	}
}

func TestAPI_OpRetry(t *testing.T) {
	e := newEnv(t)
	m := e.create(t, demoRef)
	path := "/v1/operations/" + strconv.FormatInt(m.OperationID, 10) + "/retry"
	e.wantCode(t, "POST", path, "", 409, "conflict") // pending
	e.failed(t, m.OperationID, "timeout: step 4")
	var got mutation
	strict(t, e.wantOK(t, "POST", path, "", 202), &got)
	if o := e.op(t, m.OperationID); got != m || o.State != "pending" || o.Attempts != 0 {
		t.Fatalf("retry: %+v %+v", got, o)
	}
	e.wantCode(t, "POST", path, "", 409, "conflict")
	e.wantCode(t, "POST", "/v1/operations/999/retry", "", 404, "not_found")
	e.wantCode(t, "POST", "/v1/operations/x/retry", "", 400, "bad_request")
}

func TestAPI_OperationSanitisesLastError(t *testing.T) {
	e := newEnv(t)
	m := e.create(t, demoRef)
	e.failed(t, m.OperationID, "internal: \x1b[31mred\x1b[0m "+strings.Repeat("e", 2000))
	var o opShape
	strict(t, e.wantOK(t, "GET", "/v1/operations/"+strconv.FormatInt(m.OperationID, 10), "", 200), &o)
	if !strings.HasPrefix(o.LastError, "internal: [31mred[0m") || len(o.LastError) != 1024 {
		t.Fatalf("last_error %.40q (%d bytes)", o.LastError, len(o.LastError))
	}
}

func TestAPI_RefusesMutationsWhenContainmentFailed(t *testing.T) {
	e := newEnv(t)
	act, del, prov, fail := "acti0000000000000000", "dele0000000000000000", "prov0000000000000000", "fail0000000000000000"
	e.active(t, act)
	e.seedKeys(t, act)
	e.active(t, del)
	e.deleted(t, del)
	e.create(t, prov)
	fop := e.create(t, fail).OperationID
	e.failed(t, fop, "internal: x")
	e.ops.failed = true
	before, _ := e.st.ListOperations(context.Background(), "")
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/v1/projects", createBody(t, "")},
		{"POST", "/v1/projects/" + act + "/restart", `{}`},
		{"DELETE", "/v1/projects/" + act, ""},
		{"POST", "/v1/projects/" + del + "/purge", ""},
		{"POST", "/v1/projects/" + prov + "/abort", ""},
		{"POST", "/v1/operations/" + strconv.FormatInt(fop, 10) + "/retry", ""},
	} {
		e.wantCode(t, c.method, c.path, c.body, 503, "containment_failed")
	}
	after, _ := e.st.ListOperations(context.Background(), "")
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("refused mutations changed operations")
	}
	if calls := e.ops.Calls(); len(calls) != 0 {
		t.Fatalf("refused mutations reached Ops: %v", calls)
	}
	e.ops.checks = []nodecfg.CheckResult{{Name: "nft", OK: true}}
	for _, p := range []string{"/v1/projects", "/v1/projects/" + act, "/v1/projects/" + act + "/keys", "/v1/operations",
		"/v1/operations?ref=" + act, "/v1/operations/" + strconv.FormatInt(fop, 10), "/v1/node/check"} {
		e.wantOK(t, "GET", p, "", 200)
	}
	e.wantOK(t, "POST", "/v1/projects/"+act+"/check", "", 200)
}

func TestAPI_CreateRetriesGeneratedRefCollision(t *testing.T) {
	e := newEnv(t)
	e.create(t, demoRef)
	fresh := "fres0000000000000000"
	draws := []string{demoRef, demoRef, fresh}
	newRef = func() (string, error) {
		r := draws[0]
		draws = draws[1:]
		return r, nil
	}
	t.Cleanup(func() { newRef = NewRef })
	if m := e.create(t, ""); m.Ref != fresh || len(draws) != 0 {
		t.Fatalf("created %q, %d draws left", m.Ref, len(draws))
	}
	// A ref that keeps colliding ends in an error, not a loop.
	newRef = func() (string, error) { return demoRef, nil }
	e.wantCode(t, "POST", "/v1/projects", createBody(t, ""), 500, "internal")
}

func TestAPI_DiskQuotaFloor(t *testing.T) {
	e := newEnv(t)
	var m mutation
	strict(t, e.wantOK(t, "POST", "/v1/projects", `{"name":"demo","issuer_jwks":`+jwks(t, 1)+`,"disk_quota_mb":1024}`, 202), &m)
	if p := e.project(t, m.Ref); p.Config.DiskQuotaMB != 1024 {
		t.Fatalf("quota %d", p.Config.DiskQuotaMB)
	}
	e.active(t, demoRef)
	e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/restart", `{"disk_quota_mb":1024}`, 202)
}

// A restart that was rolled back is shown aborted with code rolled_back; its
// retry is refused, and the project takes the next restart and a delete.
func TestAPI_RolledBackRestart(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.active(t, demoRef)
	rop, err := e.st.SubmitOperation(ctx, demoRef, "restart", nil, 1, time.Now())
	must(t, err)
	must(t, e.st.StartOperation(ctx, rop))
	must(t, e.st.FinishOperation(ctx, rop, "aborted", "rolled_back: the project runs its previous configuration at generation 3"))
	var o struct {
		State     string `json:"state"`
		LastError string `json:"last_error"`
	}
	json.Unmarshal(e.wantOK(t, "GET", "/v1/operations/"+strconv.FormatInt(rop, 10), "", 200), &o)
	if o.State != "aborted" || !strings.HasPrefix(o.LastError, "rolled_back: ") {
		t.Fatalf("operation %+v", o)
	}
	eb := e.wantCode(t, "POST", "/v1/operations/"+strconv.FormatInt(rop, 10)+"/retry", "", 409, "conflict")
	if !strings.Contains(eb.Message, "only a failed operation can be retried") {
		t.Fatalf("retry refusal %+v", eb)
	}
	e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/restart", `{}`, 202)
	other := "rolledback0000000002"
	e.active(t, other)
	rop, err = e.st.SubmitOperation(ctx, other, "restart", nil, 1, time.Now())
	must(t, err)
	must(t, e.st.StartOperation(ctx, rop))
	must(t, e.st.FinishOperation(ctx, rop, "aborted", "rolled_back: x"))
	e.wantOK(t, "DELETE", "/v1/projects/"+other, "", 202)
}

// ───────── where to connect, admission, messages, list filter ─────────

// writeCert issues a certificate for name signed by parent (self-signed when
// parent is nil) and writes it as PEM to path.
func writeCert(t *testing.T, path, name string, ca bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true}
	if ca {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	must(t, err)
	must(t, os.MkdirAll(filepath.Dir(path), 0o700))
	must(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	c, err := x509.ParseCertificate(der)
	must(t, err)
	return c, key
}

// TestAPI_ProjectEndpoint: show, list and keys carry the project's URL and,
// only when the node's CA signed the gateway's certificate, that CA's path.
func TestAPI_ProjectEndpoint(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	e.seedKeys(t, demoRef)
	caPath := filepath.Join(e.p.CADir(), "ca.pem")
	certPath := filepath.Join(e.p.TLSDir(), "cert.pem")
	t.Cleanup(func() { os.RemoveAll(e.p.CADir()); os.RemoveAll(e.p.TLSDir()) })
	type ep struct {
		URL    string  `json:"url"`
		CACert *string `json:"ca_cert"`
	}
	want := func(what string, ca *string) {
		t.Helper()
		var list struct{ Projects []ep }
		must(t, json.Unmarshal(e.wantOK(t, "GET", "/v1/projects", "", 200), &list))
		for _, p := range []string{"/v1/projects/" + demoRef, "/v1/projects/" + demoRef + "/keys", ""} {
			var got ep
			if p == "" {
				got = list.Projects[0]
			} else {
				must(t, json.Unmarshal(e.wantOK(t, "GET", p, "", 200), &got))
			}
			if got.URL != "https://"+demoRef+".sp.test" || (got.CACert == nil) != (ca == nil) || ca != nil && *got.CACert != *ca {
				t.Errorf("%s: %s: %+v, want CA %v", what, p, got, ca)
			}
		}
	}
	want("no certificate", nil)
	ca, caKey := writeCert(t, caPath, "test CA", true, nil, nil)
	writeCert(t, certPath, "*.sp.test", false, ca, caKey)
	want("signed by the node's CA", &caPath)
	writeCert(t, certPath, "*.sp.test", false, nil, nil) // the operator's own
	want("another issuer", nil)
}

// setCeiling sets the node's memory admission ceiling.
func (e *env) setCeiling(t *testing.T, memMB int) {
	t.Helper()
	c := nodecfg.Default("sp.test")
	c.MemAllocMB, c.PidsAlloc, c.Uplinks = memMB, 1<<20, nil
	must(t, e.st.EnsureNode(context.Background(), c))
}

// TestAPI_CreateRefusedWhenNodeFull: a create the placement would refuse is
// refused at once with node_full and the figures, and writes nothing.
func TestAPI_CreateRefusedWhenNodeFull(t *testing.T) {
	e := newEnv(t)
	e.setCeiling(t, 2*768)
	e.active(t, demoRef)
	e.create(t, "") // pending, not placed yet: it counts
	eb := e.wantCode(t, "POST", "/v1/projects", createBody(t, "full0000000000000000"), 409, "node_full")
	if want := "admission ceiling reached: 2 projects hold 1536 of the node's 1536 MiB; a project needs 768 MiB"; eb.Message != want {
		t.Fatalf("message %q, want %q", eb.Message, want)
	}
	if _, err := e.st.GetProject(context.Background(), "full0000000000000000"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refused create left a row: %v", err)
	}
	ops, err := e.st.ListOperations(context.Background(), "")
	must(t, err)
	if len(ops) != 2 {
		t.Fatalf("%d operations after the refusal, want 2", len(ops))
	}
}

// TestAPI_ConcurrentCreatesAdmitOne: a second create arriving while the
// first one, already admitted, has not inserted its row yet, is refused with
// node_full and burns no ref.
func TestAPI_ConcurrentCreatesAdmitOne(t *testing.T) {
	e := newEnv(t)
	e.setCeiling(t, 768)
	post := func() int {
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/projects", strings.NewReader(createBody(t, ""))))
		return w.Code
	}
	second := make(chan int, 1)
	var once sync.Once
	afterAdmission = func() {
		once.Do(func() {
			go func() { second <- post() }()
			// The second create must wait for the first; give it time to
			// get past the admission check if it does not.
			select {
			case <-second:
				t.Error("the second create finished while the first held its admission")
			case <-time.After(500 * time.Millisecond):
			}
		})
	}
	t.Cleanup(func() { afterAdmission = func() {} })
	if got := post(); got != http.StatusAccepted {
		t.Fatalf("first create: %d", got)
	}
	if got := <-second; got != http.StatusConflict {
		t.Fatalf("second create: %d, want 409", got)
	}
	ps, err := e.st.ListProjects(context.Background())
	must(t, err)
	if len(ps) != 1 {
		t.Fatalf("%d projects, want 1", len(ps))
	}
}

func TestAPI_MessagesAreClean(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	pr := "/v1/projects/" + demoRef + "/restart"
	for body, want := range map[string]string{
		`{"set":{"max_connections":"0100"}}`: `max_connections = "0100": a value is 1 to 64 letters, digits or '.', and does not start with 0`,
		`{"set":{"max_connections":"-1"}}`:   `max_connections = "-1": a value is 1 to 64 letters, digits or '.'`,
		`{"set":{"max_connections":"5"}}`:    `max_connections = "5": want an integer 16–400`,
		`{"set":{"fsync":"off"}}`:            `setting "fsync" cannot be set; see 'supapace project restart --help'`,
	} {
		eb := e.wantCode(t, "POST", pr, body, 400, "bad_request")
		if !strings.HasPrefix(eb.Message, want) || strings.Contains(eb.Message, "pgconf") {
			t.Errorf("%s: message %q, want it to start with %q", body, eb.Message, want)
		}
	}
	// Text from elsewhere loses package prefixes and repeated parts.
	e.ops.code, e.ops.msg = "internal", "pgsock: connect: connect: connection refused"
	var c checkShape
	strict(t, e.wantOK(t, "POST", "/v1/projects/"+demoRef+"/check", "", 200), &c)
	if c.Message != "connect: connection refused" {
		t.Errorf("check message %q", c.Message)
	}
	m := e.create(t, "")
	e.failed(t, m.OperationID, "internal: agent: pgsock: socket peer is not the recorded cluster process")
	var o opShape
	strict(t, e.wantOK(t, "GET", "/v1/operations/"+strconv.FormatInt(m.OperationID, 10), "", 200), &o)
	if o.LastError != "internal: socket peer is not the recorded cluster process" {
		t.Errorf("last_error %q", o.LastError)
	}
	// A busy project names the operation that holds it.
	m = mutation{}
	strict(t, e.wantOK(t, "POST", pr, `{}`, 202), &m)
	eb := e.wantCode(t, "DELETE", "/v1/projects/"+demoRef, "", 409, "conflict")
	if want := fmt.Sprintf("operation %d (restart) of the project is pending", m.OperationID); !strings.Contains(eb.Message, want) {
		t.Errorf("message %q lacks %q", eb.Message, want)
	}
	// A reserved role says why.
	eb = e.wantCode(t, "POST", "/v1/projects", `{"name":"demo","issuer_jwks":`+jwks(t, 1)+`,"user_roles":["postgres"]}`, 400, "bad_request")
	if !strings.Contains(eb.Message, "no user token may claim") {
		t.Errorf("message %q", eb.Message)
	}
}

func TestAPI_ListStateFilter(t *testing.T) {
	e := newEnv(t)
	act, prov, abt := "acti0000000000000000", "prov0000000000000000", "abor0000000000000000"
	e.active(t, act)
	e.create(t, prov)
	e.create(t, abt)
	must(t, e.st.MarkAborted(context.Background(), abt))
	refs := func(q string) []string {
		var l struct{ Projects []projectShape }
		must(t, json.Unmarshal(e.wantOK(t, "GET", "/v1/projects"+q, "", 200), &l))
		var out []string
		for _, p := range l.Projects {
			out = append(out, p.Ref)
		}
		return out
	}
	for q, want := range map[string][]string{
		"":                                 {abt, act, prov},
		"?state=active":                    {act},
		"?state=active&state=provisioning": {act, prov},
		"?state=deleted":                   nil,
	} {
		if got := refs(q); !slices.Equal(got, want) {
			t.Errorf("%q: %v, want %v", q, got, want)
		}
	}
	e.wantCode(t, "GET", "/v1/projects?state=gone", "", 400, "bad_request")
	e.wantCode(t, "GET", "/v1/projects?ref=x", "", 400, "bad_request")
	// A parameter other than state is refused even when its value is a state.
	if eb := e.wantCode(t, "GET", "/v1/projects?ref=active", "", 400, "bad_request"); eb.Message != "the only query parameter is state" {
		t.Errorf("message %q", eb.Message)
	}
}

// TestTidy_DropsOnlyAndKeepsTheCode: tidy only removes whole parts, never
// the leading code of a last_error, never a part that precedes a hostile
// repeat, and leaves text without package names or repeats unchanged.
func TestTidy_DropsOnlyAndKeepsTheCode(t *testing.T) {
	codes := []string{"node_full", "containment_failed", "stale_generation", "epoch_divergence", "assertion", "peer",
		"timeout", "internal"}
	hostile := []string{"", "store", "store: store", "x: x: x", "server error XX000: store: agent: y",
		"internal: internal", "a:b: c ", ": : ", "jwtx:jwtx: z"}
	for _, c := range codes {
		if slices.Contains(internalPrefixes, c) {
			t.Fatalf("code %q is also a package name: tidy would drop it", c)
		}
		for _, h := range hostile {
			in := c + ": pgsock: server error XX000: " + h
			got := tidy(in)
			if !strings.HasPrefix(got, c+": server error XX000") {
				t.Errorf("tidy(%q) = %q: the code or the platform's part moved", in, got)
			}
			// Drop-only: every part of the result is a part of the input, in order.
			rest := strings.Split(in, ": ")
			for _, p := range strings.Split(got, ": ") {
				i := slices.Index(rest, p)
				if i < 0 {
					t.Fatalf("tidy(%q) = %q: part %q is not from the input in order", in, got, p)
				}
				rest = rest[i+1:]
			}
		}
	}
	for _, s := range []string{"conflict without parts", "operation 7 (restart) of the project is running; wait for it to end",
		`user role "store" is reserved`} {
		if got := tidy(s); got != s {
			t.Errorf("tidy(%q) = %q, want it unchanged", s, got)
		}
	}
}

// TestAPI_EndpointFromConstruction: the URL is built from the domain the API
// was given; no node.json is read, so an unreadable one changes nothing.
func TestAPI_EndpointFromConstruction(t *testing.T) {
	e := newEnv(t)
	e.active(t, demoRef)
	must(t, os.MkdirAll(filepath.Dir(e.p.NodeJSON()), 0o700))
	must(t, os.WriteFile(e.p.NodeJSON(), []byte("not json"), 0o000))
	e.h = New(e.st, e.kek, e.ops, "example.test", e.p)
	var p projectShape
	strict(t, e.wantOK(t, "GET", "/v1/projects/"+demoRef, "", 200), &p)
	if p.URL != "https://"+demoRef+".example.test" {
		t.Fatalf("url %q", p.URL)
	}
}

// TestAPI_CreateWaitHonoursContext: a create waiting for another create's
// admission gives up when its request ends.
func TestAPI_CreateWaitHonoursContext(t *testing.T) {
	e := newEnv(t)
	release, inside := make(chan struct{}), make(chan struct{})
	var once sync.Once
	afterAdmission = func() { once.Do(func() { close(inside); <-release }) }
	t.Cleanup(func() { afterAdmission = func() {} })
	first := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/projects", strings.NewReader(createBody(t, ""))))
		first <- w.Code
	}()
	<-inside
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	second := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/projects", strings.NewReader(createBody(t, ""))).WithContext(ctx))
		second <- w.Code
	}()
	select {
	case code := <-second:
		if code == http.StatusAccepted {
			t.Errorf("second create accepted while the first held the admission")
		}
	case <-time.After(5 * time.Second):
		t.Error("the second create did not give up when its request ended")
	}
	close(release)
	if code := <-first; code != http.StatusAccepted {
		t.Fatalf("first create: %d", code)
	}
}

// TestAPI_CreateExistingRefOnFullNode: a taken ref is ref_exists even when
// the node is full.
func TestAPI_CreateExistingRefOnFullNode(t *testing.T) {
	e := newEnv(t)
	e.setCeiling(t, 768)
	e.active(t, demoRef)
	e.wantCode(t, "POST", "/v1/projects", createBody(t, demoRef), 409, "ref_exists")
	e.wantCode(t, "POST", "/v1/projects", createBody(t, "UPPER0000000000000000"[:20]), 400, "bad_ref")
	e.wantCode(t, "POST", "/v1/projects", createBody(t, "free0000000000000000"), 409, "node_full")
}

// TestAPI_AbortMessageFitsTheState: the pointer to delete is for an active
// project only.
func TestAPI_AbortMessageFitsTheState(t *testing.T) {
	e := newEnv(t)
	act, del := "acti0000000000000000", "dele0000000000000000"
	e.active(t, act)
	e.active(t, del)
	e.deleted(t, del)
	if eb := e.wantCode(t, "POST", "/v1/projects/"+act+"/abort", "", 409, "conflict"); !strings.Contains(eb.Message, "removed with delete") {
		t.Errorf("active: %q", eb.Message)
	}
	eb := e.wantCode(t, "POST", "/v1/projects/"+del+"/abort", "", 409, "conflict")
	if strings.Contains(eb.Message, "with delete") || !strings.Contains(eb.Message, "purge") {
		t.Errorf("deleted: %q", eb.Message)
	}
	must(t, e.st.MarkPurged(context.Background(), del))
	eb = e.wantCode(t, "POST", "/v1/projects/"+del+"/abort", "", 409, "conflict")
	if eb.Message != "project is purged; abort applies only to a create in progress" {
		t.Errorf("purged: %q", eb.Message)
	}
}
