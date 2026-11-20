package repl

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/s3x"
)

// provider is a bucket with the settings a probe reads, and what each
// credential may do.
type provider struct {
	b                                        *fake
	versioning, lockMode                     string
	lockDays                                 int
	deleteAllowed, regionChecked, sumChecked bool
	abortAllowed, readCanWrite, otherOpen    bool
	broken                                   bool // every request of the write credential is refused
	partFails                                int  // the n-th part upload is refused (0: none)
	parts                                    int
	put400                                   bool // every raw PUT is answered 400
	lifecycle                                string
	deletes                                  []string
}

func goodProvider() *provider {
	return &provider{b: newFake(), versioning: "Enabled", lockMode: "COMPLIANCE", lockDays: 14, regionChecked: true, sumChecked: true,
		abortAllowed: true, lifecycle: `<LifecycleConfiguration><Rule><ID>a</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter>` +
			`<NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration>` +
			`<AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>`}
}

// role is one credential on one bucket of the provider.
type role struct {
	p    *provider
	name string // write, read, other
}

func (r role) denied(write bool) error {
	if r.p.broken || r.name == "other" && !r.p.otherOpen || r.name == "read" && write && !r.p.readCanWrite {
		return fmt.Errorf("%w (fake)", s3x.ErrDenied)
	}
	return nil
}

func (r role) Prefix() string { return r.p.b.prefix }
func (r role) Put(ctx context.Context, k string, b []byte, m map[string]string, ia bool) (string, error) {
	if err := r.denied(true); err != nil {
		return "", err
	}
	return r.p.b.Put(ctx, k, b, m, ia)
}
func (r role) Head(ctx context.Context, k, v string) (s3x.Object, error) {
	if err := r.denied(false); err != nil {
		return s3x.Object{}, err
	}
	return r.p.b.Head(ctx, k, v)
}
func (r role) CreateMultipart(ctx context.Context, k string, m map[string]string) (string, error) {
	if err := r.denied(true); err != nil {
		return "", err
	}
	return r.p.b.CreateMultipart(ctx, k, m)
}
func (r role) UploadPart(ctx context.Context, k, id string, n int, b []byte) (string, error) {
	if r.p.parts++; r.p.parts == r.p.partFails {
		return "", errors.New("connection reset")
	}
	if err := r.denied(true); err != nil {
		return "", err
	}
	return r.p.b.UploadPart(ctx, k, id, n, b)
}
func (r role) CompleteMultipart(ctx context.Context, k, id string, e []string, ia bool) (string, error) {
	if err := r.denied(true); err != nil {
		return "", err
	}
	return r.p.b.CompleteMultipart(ctx, k, id, e, ia)
}
func (r role) AbortMultipart(ctx context.Context, k, id string) error {
	panic("the probe aborts with its own signed request")
}
func (r role) ListVersions(ctx context.Context, p, km, vm string) ([]s3x.Object, string, string, error) {
	if err := r.denied(false); err != nil {
		return nil, "", "", err
	}
	return r.p.b.ListVersions(ctx, p, km, vm)
}

func (p *provider) Delete(ctx context.Context, key, vid string) error {
	p.deletes = append(p.deletes, key)
	if !strings.HasPrefix(key, ProbeBase(p.b.prefix)+"/") {
		panic("delete outside the probe's prefix: " + key)
	}
	if p.broken || !p.deleteAllowed {
		return fmt.Errorf("%w (fake)", s3x.ErrDenied)
	}
	vs := p.b.objs[key]
	if vid == "" {
		p.b.objs[key] = append(vs, fakeObj{vid: "marker", marker: true})
		return nil
	}
	p.b.objs[key] = slices.DeleteFunc(vs, func(o fakeObj) bool { return o.vid == vid })
	return nil
}

func (p *provider) Send(ctx context.Context, r RawRequest) (int, string, http.Header, []byte, error) {
	st, code, doc, err := p.send(r)
	h := http.Header{}
	if st == 200 && r.Method == http.MethodHead && p.lockDays > 0 {
		h.Set("X-Amz-Object-Lock-Mode", p.lockMode)
		h.Set("X-Amz-Object-Lock-Retain-Until-Date", time.Now().Add(time.Duration(p.lockDays)*24*time.Hour).UTC().Format(time.RFC3339))
	}
	return st, code, h, doc, err
}

func (p *provider) send(r RawRequest) (int, string, []byte, error) {
	if r.Method == http.MethodDelete && !strings.HasPrefix(r.Key, ProbeBase(p.b.prefix)+"/") {
		panic("raw delete outside the probe's prefix: " + r.Key)
	}
	if p.broken {
		return 403, "AccessDenied", nil, nil
	}
	if p.put400 && r.Method == http.MethodPut {
		return 400, "InvalidRequest", nil, nil
	}
	if p.regionChecked && r.Region != "" {
		return 400, "AuthorizationHeaderMalformed", nil, nil
	}
	switch {
	case r.Method == http.MethodGet && r.Query.Has("versioning"):
		return 200, "", []byte("<VersioningConfiguration><Status>" + p.versioning + "</Status></VersioningConfiguration>"), nil
	case r.Method == http.MethodGet && r.Query.Has("object-lock"):
		return 200, "", []byte(fmt.Sprintf("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention>"+
			"<Mode>%s</Mode><Days>%d</Days></DefaultRetention></Rule></ObjectLockConfiguration>", p.lockMode, p.lockDays)), nil
	case r.Method == http.MethodGet && r.Query.Has("lifecycle"):
		if p.lifecycle == "" {
			return 404, "NoSuchLifecycleConfiguration", nil, nil
		}
		return 200, "", []byte(p.lifecycle), nil
	case r.Method == http.MethodDelete && r.Query.Has("uploadId"):
		if !p.abortAllowed {
			return 403, "AccessDenied", nil, nil
		}
		delete(p.b.uploads, r.Query.Get("uploadId"))
		return 204, "", nil, nil
	case r.Method == http.MethodHead:
		if _, ok := p.b.current(r.Key); !ok {
			return 404, "", nil, nil
		}
		return 200, "", nil, nil
	case r.Method == http.MethodPut:
		m := md5.Sum(r.Body)
		if p.sumChecked && (r.MD5 != "" && r.MD5 != base64.StdEncoding.EncodeToString(m[:])) {
			return 400, "BadDigest", nil, nil
		}
		if p.sumChecked && r.SHA256 != "" && r.SHA256 != hexSum(r.Body) {
			return 400, "XAmzContentSHA256Mismatch", nil, nil
		}
		p.b.store(r.Key, r.Body, nil, false)
		return 200, "", nil, nil
	}
	return 400, "Unexpected", nil, nil
}

func probe(t *testing.T, p *provider, cp bool) map[string]jobio.ProbeRow {
	t.Helper()
	in := jobio.Input{Job: 3, Kind: "probe", Subject: "probe-projects", Repl: &jobio.ReplInput{Mode: "probe"}}
	if cp {
		in.Subject = "cp"
	}
	tg := ProbeTargets{Write: role{p, "write"}, Read: role{p, "read"}, Other: role{p, "other"}, Raw: p}
	r, err := Probe(context.Background(), in, tg, p)
	if err != nil {
		t.Fatal(err)
	}
	line, err := jobio.MarshalResult(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := jobio.ParseResult("probe", line); err != nil {
		t.Fatalf("%v: %s", err, line)
	}
	rows := map[string]jobio.ProbeRow{}
	for _, x := range r.ProbeRows {
		rows[x.Name] = x
	}
	return rows
}

var probeNames = []string{"versioning", "default-lock-compliance", "write-cannot-delete", "write-can-abort-multipart", "read-only-cannot-write",
	"projects-credential-cannot-reach-control-plane-bucket", "conditional-create", "conditional-create-multipart", "checksum-enforced",
	"region-checked", "lifecycle-noncurrent-rule-present", "lifecycle-abort-incomplete-rule-present"}

func TestProbe_Rows(t *testing.T) {
	rows := probe(t, goodProvider(), false)
	if len(rows) != len(probeNames) {
		t.Errorf("%d rows", len(rows))
	}
	for _, n := range probeNames {
		if r, ok := rows[n]; !ok || !r.OK {
			t.Errorf("good provider: %s = %+v", n, r)
		}
	}
	if d := rows["lifecycle-noncurrent-rule-present"].Detail; !strings.Contains(d, "30 days") {
		t.Errorf("the noncurrent row's detail lacks the delay: %q", d)
	}
	if d := rows["default-lock-compliance"].Detail; !strings.Contains(d, "COMPLIANCE") || !strings.Contains(d, "retained until") {
		t.Errorf("lock detail %q", d)
	}
	if _, ok := probe(t, goodProvider(), true)["control-plane-credential-cannot-reach-projects-bucket"]; !ok {
		t.Error("the control plane's probe names its cross-bucket row for the other bucket")
	}
	// Each row fails on the provider that lacks its property.
	for name, spoil := range map[string]func(*provider){
		"versioning":                func(p *provider) { p.versioning = "Suspended" },
		"default-lock-compliance":   func(p *provider) { p.lockMode = "GOVERNANCE" },
		"write-cannot-delete":       func(p *provider) { p.deleteAllowed = true },
		"write-can-abort-multipart": func(p *provider) { p.abortAllowed = false },
		"read-only-cannot-write":    func(p *provider) { p.readCanWrite = true },
		"projects-credential-cannot-reach-control-plane-bucket": func(p *provider) { p.otherOpen = true },
		"checksum-enforced": func(p *provider) { p.sumChecked = false },
		"region-checked":    func(p *provider) { p.regionChecked = false },
		"lifecycle-noncurrent-rule-present": func(p *provider) {
			p.lifecycle = strings.Replace(goodProvider().lifecycle, "NoncurrentDays>30", "NoncurrentDays>0", 1)
		},
		"lifecycle-abort-incomplete-rule-present": func(p *provider) {
			p.lifecycle = strings.Replace(goodProvider().lifecycle, "<Status>Enabled", "<Status>Disabled", 1)
		},
	} {
		p := goodProvider()
		spoil(p)
		rows := probe(t, p, false)
		if rows[name].OK {
			t.Errorf("%s reads ok on a provider without it: %+v", name, rows[name])
		}
	}
	// One bucket for both uses: the cross-bucket row is not checked, so not ok.
	p := goodProvider()
	in := jobio.Input{Job: 3, Kind: "probe", Repl: &jobio.ReplInput{Mode: "probe"}}
	r, _ := Probe(context.Background(), in, ProbeTargets{Write: role{p, "write"}, Read: role{p, "read"}, Raw: p}, p)
	for _, x := range r.ProbeRows {
		if strings.Contains(x.Name, "cannot-reach") && x.OK {
			t.Errorf("%+v", x)
		}
	}
}

// A credential that is refused everything — a wrong key, a skewed clock —
// passes no row: every denial row's control fails first.
func TestProbe_EveryDenialRowHasAPositiveControlWithTheSameCredential(t *testing.T) {
	// A store that answers every raw write 400 has no checksum to enforce: the control fails first.
	q := goodProvider()
	q.put400 = true
	if r := probe(t, q, false)["checksum-enforced"]; r.OK {
		t.Errorf("checksum-enforced ok on a store that refuses every write: %+v", r)
	}
	p := goodProvider()
	p.broken = true
	for name, r := range probe(t, p, false) {
		if r.OK {
			t.Errorf("%s reads ok with a credential refused everything: %+v", name, r)
		}
	}
}

func TestProbe_DeletesOnlyKeysUnderItsProbePrefix(t *testing.T) {
	p := goodProvider()
	p.deleteAllowed = true // as on the stand-in: the probe's own objects are removed again
	probe(t, p, false)
	if len(p.deletes) == 0 {
		t.Fatal("no delete was tried")
	}
	for _, k := range p.deletes {
		if !strings.HasPrefix(k, "pre/fix/.probe/3-") {
			t.Errorf("delete of %s", k)
		}
	}
	for k := range p.b.objs {
		if !strings.HasPrefix(k, "pre/fix/.probe/") {
			t.Errorf("the probe wrote %s", k)
		}
	}
	// The signer refuses a delete of any other key before a request is made.
	s := NewSigner(&http.Client{Transport: refuseRT{t}}, "s3.example.test:9443", "sp-projects", "r", true, Keys{"a", "b"}, "pre/fix")
	for _, k := range []string{"pre/fix/" + ref + "/" + seg(1, 1), "pre/fix/.probe", "pre/fix/.probex/a", "pre/fix/.probe/../" + ref + "/x", "other/.probe/a"} {
		if err := s.Delete(context.Background(), k, "v1"); err == nil {
			t.Errorf("deleted %s", k)
		}
		if _, _, _, _, err := s.Send(context.Background(), RawRequest{Method: http.MethodDelete, Key: k, Query: url.Values{"uploadId": {"u"}}}); err == nil {
			t.Errorf("raw delete of %s", k)
		}
	}
}

type refuseRT struct{ t *testing.T }

func (r refuseRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r.t.Errorf("a request was sent: %s %s", req.Method, req.URL)
	return nil, fmt.Errorf("refused")
}

// deleteFiles are the files of the package allowed to build a request with
// the DELETE method: the probe's, under its own prefix. AbortMultipart is
// called from the copy alone; Copy, Rebuild and Fetch take no Deleter.
var deleteFiles = []string{"probe.go"}

func TestRepl_ObjectDeletesOnlyInTheAllowedFiles(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	fs := token.NewFileSet()
	var sawDelete, sawAbort bool
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fs, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if x.Sel.Name == "MethodDelete" {
					sawDelete = true
					if !slices.Contains(deleteFiles, name) {
						t.Errorf("%s: a DELETE request at %v", name, fs.Position(x.Pos()))
					}
				}
				if x.Sel.Name == "AbortMultipart" {
					if _, isCall := parentCall(f, x); isCall {
						sawAbort = true
						if name != "copy.go" {
							t.Errorf("%s: AbortMultipart called at %v", name, fs.Position(x.Pos()))
						}
					}
				}
			case *ast.BasicLit:
				if s, _ := strconv.Unquote(x.Value); strings.EqualFold(s, "DELETE") && !slices.Contains(deleteFiles, name) {
					t.Errorf("%s: the literal %s at %v", name, x.Value, fs.Position(x.Pos()))
				}
			case *ast.FuncDecl:
				if x.Recv == nil && slices.Contains([]string{"Copy", "Rebuild", "Fetch"}, x.Name.Name) {
					for _, p := range x.Type.Params.List {
						if typ := fmt.Sprint(p.Type); strings.Contains(typ, "Deleter") || strings.Contains(typ, "Signer") || strings.Contains(typ, "Raw") ||
							strings.Contains(typ, "ProbeTargets") {
							t.Errorf("%s takes %s", x.Name.Name, typ)
						}
					}
				}
			}
			return true
		})
	}
	if !sawDelete || !sawAbort {
		t.Errorf("the scan saw no DELETE (%v) or no abort (%v): it scans nothing", sawDelete, sawAbort)
	}
}

// parentCall tells whether sel is the function of a call expression in f.
func parentCall(f *ast.File, sel *ast.SelectorExpr) (*ast.CallExpr, bool) {
	var call *ast.CallExpr
	ast.Inspect(f, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && c.Fun == sel {
			call = c
		}
		return call == nil
	})
	return call, call != nil
}

func (r role) Get(ctx context.Context, k, v string, w io.Writer, max int64) (s3x.Object, error) {
	if err := r.denied(false); err != nil {
		return s3x.Object{}, err
	}
	return r.p.b.Get(ctx, k, v, w, max)
}
