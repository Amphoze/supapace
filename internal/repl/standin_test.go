package repl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/s3x"
)

// The pinned object-store stand-in, started by digest with a certificate made
// here; its tests run only with SUPAPACE_STANDIN_TEST=1.
const (
	standinImage = "chrislusf/seaweedfs@sha256:4b42c212543a0acd4c0e675215ecdcaf62a186ef98def76c7e12701871222d15"
	standinName  = "s3.sp.test"
)

type standinT struct {
	name, ca string
	addr     netip.AddrPort
	keys     map[string]Keys // admin, write, read, cp-write
	err      error
}

var standin *standinT

func TestMain(m *testing.M) {
	if os.Getenv("SUPAPACE_STANDIN_TEST") != "1" {
		os.Exit(m.Run())
	}
	standin = startStandin()
	code := m.Run()
	if standin.name != "" {
		dockerx.Run(context.Background(), "rm", "-f", "-v", standin.name)
	}
	os.Exit(code)
}

func needStandin(t *testing.T) *standinT {
	t.Helper()
	if standin == nil {
		t.Skip("stand-in tests run only with SUPAPACE_STANDIN_TEST=1")
	}
	if standin.err != nil {
		t.Fatalf("stand-in: %v", standin.err)
	}
	return standin
}

func rnd(n int) string { b := make([]byte, n); rand.Read(b); return hex.EncodeToString(b) }

func startStandin() *standinT {
	s := &standinT{keys: map[string]Keys{}}
	fail := func(err error) *standinT { s.err = err; return s }
	dir, err := os.MkdirTemp("", "sp-test-repl-")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(dir)
	if s.ca, err = writeTLS(dir); err != nil {
		return fail(err)
	}
	actions := map[string]string{"admin": `"Admin","Read","List","Tagging","Write"`, "write": `"Read:sp-projects","List:sp-projects","Write:sp-projects"`,
		"read": `"Read:sp-projects","List:sp-projects"`, "cp-write": `"Read:sp-cp","List:sp-cp","Write:sp-cp"`}
	var ids []string
	for _, r := range []string{"admin", "write", "read", "cp-write"} {
		s.keys[r] = Keys{rnd(10), rnd(20)}
		ids = append(ids, fmt.Sprintf(`{"name":%q,"credentials":[{"accessKey":%q,"secretKey":%q}],"actions":[%s]}`, r, s.keys[r].Access, s.keys[r].Secret, actions[r]))
	}
	if err := os.WriteFile(filepath.Join(dir, "s3.json"), []byte(`{"identities":[`+strings.Join(ids, ",")+`]}`), 0o644); err != nil {
		return fail(err)
	}
	ctx := context.Background()
	name := "sp-test-repl-standin-" + rnd(4)
	// A detached watchdog removes the container once this process is gone, however it ends.
	w := exec.Command("sh", "-c", `while kill -0 "$1" 2>/dev/null; do sleep 1; done
		docker unpause "$2" >/dev/null 2>&1; docker rm -f -v "$2" >/dev/null 2>&1; sleep 5; docker rm -f -v "$2" >/dev/null 2>&1`,
		"sh", strconv.Itoa(os.Getpid()), name)
	w.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := w.Start(); err != nil {
		return fail(err)
	}
	w.Process.Release()
	if _, err := dockerx.Run(ctx, "create", "--label", "supapace.test=1", "--name", name, "-p", "127.0.0.1:0:9443", "--memory", "1g",
		"--tmpfs", "/data:size=512m", "--entrypoint", "weed", standinImage, "mini", "-dir=/data", "-ip=127.0.0.1",
		"-ip.bind=0.0.0.0", "-s3.port.https=9443", "-s3.cert.file=/tls/cert.pem", "-s3.key.file=/tls/key.pem",
		"-s3.config=/tls/s3.json"); err != nil {
		return fail(err)
	}
	s.name = name
	if _, err := dockerx.Run(ctx, "cp", dir+"/.", name+":/tls"); err != nil {
		return fail(err)
	}
	if _, err := dockerx.Run(ctx, "start", name); err != nil {
		return fail(err)
	}
	out, err := dockerx.Run(ctx, "port", name, "9443/tcp")
	if err != nil {
		return fail(err)
	}
	if s.addr, err = netip.ParseAddrPort(strings.TrimSpace(strings.Split(out, "\n")[0])); err != nil {
		return fail(fmt.Errorf("docker port: %q", out))
	}
	deadline := time.Now().Add(120 * time.Second)
	for {
		if code, _, err := s.admin("GET", "", "", nil, nil); err == nil && code == 200 {
			break
		}
		if time.Now().After(deadline) {
			logs, _, _ := dockerx.RunOutput(ctx, "logs", "--tail", "20", name)
			return fail(fmt.Errorf("not ready in 120 s: %s", logs))
		}
		time.Sleep(500 * time.Millisecond)
	}
	// The buckets as the harness makes them: the lock header, versioning, a
	// compliance lock of a day, the lifecycle rule.
	for _, b := range []string{"sp-projects", "sp-cp"} {
		for _, st := range []struct {
			q, body string
			hdr     map[string]string
		}{
			{"", "", map[string]string{"X-Amz-Bucket-Object-Lock-Enabled": "true"}},
			{"versioning=", "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>", nil},
			{"object-lock=", "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>", nil},
			{"lifecycle=", "<LifecycleConfiguration><Rule><ID>sp</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>" +
				"<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration>" +
				"<AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>", nil},
		} {
			if code, doc, err := s.admin("PUT", "/"+b, st.q, []byte(st.body), st.hdr); err != nil || code != 200 {
				return fail(fmt.Errorf("bucket %s ?%s: %d %s %v", b, st.q, code, doc, err))
			}
		}
	}
	return s
}

func (s *standinT) hc() *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(s.ca))
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", s.addr.String())
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
}

func (s *standinT) admin(method, path, query string, body []byte, hdr map[string]string) (int, string, error) {
	r, err := http.NewRequest(method, "https://"+standinName+":9443"+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	r.URL.RawQuery, r.ContentLength = query, int64(len(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	if len(body) > 0 {
		m := md5.Sum(body)
		r.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(m[:]))
	}
	s3x.Sign(r, hexSum(body), s.keys["admin"].Access, s.keys["admin"].Secret, "us-east-1", time.Now())
	resp, err := s.hc().Do(r)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	doc, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(doc), nil
}

// env is the job's environment for the projects bucket, as the launcher
// writes it; addrs before the stand-in's own address are tried first.
func (s *standinT) env(prefix string, addrs ...netip.AddrPort) Env {
	return Env{Endpoint: "https://" + standinName + ":9443", Region: "us-east-1", Bucket: "sp-projects", Prefix: prefix, OtherBucket: "sp-cp",
		PathStyle: true, Addrs: append(addrs, s.addr)}
}

func (s *standinT) bucket(t *testing.T, e Env, bucket, role string, timeout time.Duration) Bucket {
	t.Helper()
	c := e.Config(bucket, s.keys[role], s.ca)
	if timeout > 0 {
		c.Timeout = timeout
	}
	cl, err := s3x.New(c)
	if err != nil {
		t.Fatal(err)
	}
	return NewBucket(cl, e.Prefix)
}

func writeTLS(dir string) (string, error) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "throw-away test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return "", err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: standinName}, DNSNames: []string{standinName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	for n, b := range map[string][]byte{"cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"key.pem": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})} {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
			return "", err
		}
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), nil
}

// record is what the daemon keeps after a copy: the index rows and the last
// info hashes.
type record struct {
	rows []jobio.IndexRow
	info map[string]string
}

func (r *record) add(res jobio.ReplResult) {
	if r.info == nil {
		r.info = map[string]string{}
	}
	for _, row := range append(slices.Clone(res.Uploaded), res.Adopted...) {
		r.rows = slices.DeleteFunc(r.rows, func(x jobio.IndexRow) bool { return x.Key == row.Key })
		r.rows = append(r.rows, jobio.IndexRow{Key: row.Key, Size: row.Size, Ino: row.Ino, CtimeNS: row.CtimeNS, SHA256: row.SHA256})
	}
	for _, i := range res.Info {
		r.info[i.Name] = i.SHA256
	}
}

func (r *record) copy(t *testing.T, ctx context.Context, root string, st Store, mut ...func(*jobio.ReplInput)) jobio.ReplResult {
	t.Helper()
	in := input(append([]func(*jobio.ReplInput){func(x *jobio.ReplInput) { x.InfoSHA256 = r.info }}, mut...)...)
	res, err := Copy(ctx, in, root, indexOf(t, r.rows...), st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobio.MarshalResult(res); err != nil {
		t.Fatal(err)
	}
	r.add(res)
	return res
}

// versions lists every version under the subject's prefix.
func versionsOf(t *testing.T, b Bucket) []s3x.Object {
	t.Helper()
	var all []s3x.Object
	km, vm := "", ""
	for i := 0; i < 100; i++ {
		page, nk, nv, err := b.ListVersions(context.Background(), base(b.Prefix(), ref)+"/", km, vm)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, page...)
		if nk == "" {
			return all
		}
		km, vm = nk, nv
	}
	t.Fatal("listing never ends")
	return nil
}

// A first replication copies everything, multipart included; an unchanged
// second one copies nothing; a changed info file is one new version; a
// rewritten data file is noticed and never overwritten; a file removed
// locally stays off-site. The first of two handed addresses is unreachable.
func TestStandin_CopyThenNothingThenChanges(t *testing.T) {
	s := needStandin(t)
	unreachable := netip.MustParseAddrPort("127.0.0.1:1")
	e := s.env("repl/"+rnd(4), unreachable)
	b := s.bucket(t, e, "sp-projects", "write", 0)
	root := fixture(t)
	big := bytes.Repeat([]byte("supapace"), (32<<20)/8+1024)
	mk(t, root, pSetFile, string(big))
	var rec record
	r1 := rec.copy(t, context.Background(), root, b)
	if !r1.Complete || len(r1.Uploaded) != 8 || len(r1.Info) != 4 || !slices.Equal(r1.SetsComplete, []string{label}) {
		t.Fatalf("first: complete %v uploaded %q info %d sets %q notices %+v", r1.Complete, keys(r1.Uploaded), len(r1.Info), r1.SetsComplete, r1.Notices)
	}
	o, err := b.Head(context.Background(), base(e.Prefix, ref)+"/"+pSetFile, "")
	if err != nil || o.Size != int64(len(big)) || o.Meta["sha256"] != sum(big) {
		t.Fatalf("the multipart object: %+v %v", o, err)
	}
	before := len(versionsOf(t, b))
	r2 := rec.copy(t, context.Background(), root, b)
	if len(r2.Uploaded)+len(r2.Adopted)+len(r2.Info) != 0 || r2.Objects != 0 || !r2.Complete || len(versionsOf(t, b)) != before {
		t.Fatalf("second: %+v", r2)
	}
	// Changed: a new backup.info, a rewritten segment, a removed segment.
	mk(t, root, pBackInfo, "a new set listed")
	mk(t, root, seg(1, 1), "rewritten")
	os.Remove(filepath.Join(root, seg(1, 2)))
	r3 := rec.copy(t, context.Background(), root, b)
	if len(r3.Uploaded) != 0 || len(r3.Info) != 1 || r3.Info[0].Name != "backup.info" || noticeOf(r3, "history-rewritten") == nil {
		t.Fatalf("third: %+v", r3)
	}
	after := versionsOf(t, b)
	if len(after) != before+1 {
		t.Errorf("versions %d → %d, want one more (backup.info)", before, len(after))
	}
	for _, rel := range []string{seg(1, 1), seg(1, 2)} {
		o, err := b.Head(context.Background(), base(e.Prefix, ref)+"/"+rel, "")
		if err != nil || o.DeleteMarker {
			t.Errorf("%s off-site: %+v %v", rel, o, err)
		}
	}
	got, _ := s3get(b, base(e.Prefix, ref)+"/"+seg(1, 1))
	if got != "segment 1/1" {
		t.Errorf("the rewritten segment was overwritten off-site: %q", got)
	}
}

func s3get(b Bucket, key string) (string, error) {
	var w bytes.Buffer
	_, err := b.Get(context.Background(), key, "", &w, 1<<20)
	return w.String(), err
}

// A copy interrupted after some uploads — its result lost, so the index
// does not hold them — is resumed by the next: what went up is adopted, the
// rest uploaded, no key gains a second version. A multipart upload cut
// between its parts is aborted.
func TestStandin_InterruptedCopyResumed(t *testing.T) {
	s := needStandin(t)
	e := s.env("repl/" + rnd(4))
	b := s.bucket(t, e, "sp-projects", "write", 0)
	root := fixture(t)
	mk(t, root, strings.Replace(pSetFile, "1259", "9999", 1), strings.Repeat("m", 33<<20))
	ctx, cancel := context.WithCancel(context.Background())
	cut := &cutStore{Bucket: b, after: func(op string) {
		if op == "part" {
			cancel()
		}
	}}
	var lost record
	r1 := lost.copy(t, ctx, root, cut)
	if r1.Stopped != "upload-failed" || r1.Complete {
		t.Fatalf("first: stopped %q", r1.Stopped)
	}
	var rec record // the daemon never recorded the first job
	r2 := rec.copy(t, context.Background(), root, b)
	if !r2.Complete || len(r2.Adopted) == 0 || len(r2.Adopted)+len(r2.Uploaded) != 9 {
		t.Fatalf("resumed: complete %v adopted %q uploaded %q notices %+v", r2.Complete, keys(r2.Adopted), keys(r2.Uploaded), r2.Notices)
	}
	counts := map[string]int{}
	for _, v := range versionsOf(t, b) {
		counts[v.Key]++
	}
	for k, c := range counts {
		if c != 1 {
			t.Errorf("%s has %d versions", k, c)
		}
	}
	if code, doc, _ := s.admin("GET", "/sp-projects", "uploads=&prefix="+base(e.Prefix, ref), nil, nil); code != 200 || strings.Contains(doc, "<Upload>") {
		t.Errorf("open uploads left: %d %s", code, doc)
	}
}

// cutStore calls after once an upload or a part was sent.
type cutStore struct {
	Bucket
	after func(op string)
}

func (c *cutStore) Put(ctx context.Context, k string, b []byte, m map[string]string, ia bool) (string, error) {
	v, err := c.Bucket.Put(ctx, k, b, m, ia)
	c.after("put")
	return v, err
}

func (c *cutStore) UploadPart(ctx context.Context, k, id string, n int, b []byte) (string, error) {
	e, err := c.Bucket.UploadPart(ctx, k, id, n, b)
	c.after("part")
	return e, err
}

// A stand-in that stops answering in the middle of a rebuild's listing ends
// the job with an error and no page; the next job, from the same markers,
// lists the whole page once the store answers again.
func TestStandin_FailsMidListing(t *testing.T) {
	s := needStandin(t)
	e := s.env("repl/" + rnd(4))
	w := s.bucket(t, e, "sp-projects", "write", 0)
	for n := 1; n <= 1100; n++ {
		if _, err := w.Put(context.Background(), base(e.Prefix, ref)+"/"+seg(1, n), []byte("s"), nil, true); err != nil {
			t.Fatal(err)
		}
	}
	b := s.bucket(t, e, "sp-projects", "write", 5*time.Second)
	paused := false
	defer func() {
		if paused {
			dockerx.Run(context.Background(), "unpause", s.name)
		}
	}()
	lst := &listStore{Bucket: b, after: func(call int) {
		if call == 1 {
			if _, err := dockerx.Run(context.Background(), "pause", s.name); err != nil {
				t.Fatal(err)
			}
			paused = true
		}
	}}
	if r, err := Rebuild(context.Background(), rebuildInput("", "", 4000), lst); err == nil {
		t.Fatalf("a listing cut after its first page gave a result: %d rows", len(r.Rows))
	}
	dockerx.Run(context.Background(), "unpause", s.name)
	paused = false
	var r jobio.ReplResult
	var err error
	for i := 0; i < 20; i++ { // the store needs a moment after it is resumed
		if r, err = Rebuild(context.Background(), rebuildInput("", "", 4000), b); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil || !r.Last || len(r.Rows) != 1100 {
		t.Fatalf("after the store answers again: %d rows, last %v, %v", len(r.Rows), r.Last, err)
	}
	if _, err := jobio.MarshalResult(r); err != nil {
		t.Fatal(err)
	}
}

type listStore struct {
	Bucket
	calls int
	after func(call int)
}

func (l *listStore) ListVersions(ctx context.Context, p, km, vm string) ([]s3x.Object, string, string, error) {
	page, nk, nv, err := l.Bucket.ListVersions(ctx, p, km, vm)
	l.calls++
	l.after(l.calls)
	return page, nk, nv, err
}

// The probe's rows against the stand-in, with the real signer: what the
// stand-in has and what it lacks (its write right includes delete; it
// accepts any region).
func TestStandin_ProbeRows(t *testing.T) {
	s := needStandin(t)
	e := s.env("repl/" + rnd(4))
	write := s.bucket(t, e, "sp-projects", "write", 0)
	tg := ProbeTargets{Write: write, Read: s.bucket(t, e, "sp-projects", "read", 0), Other: s.bucket(t, e, "sp-cp", "write", 0)}
	sg := NewSigner(write.HTTPClient(), standinName+":9443", "sp-projects", "us-east-1", true, s.keys["write"], e.Prefix)
	tg.Raw = sg
	r, err := Probe(context.Background(), jobio.Input{Job: 9, Kind: "probe", Repl: &jobio.ReplInput{Mode: "probe"}}, tg, sg)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"versioning": true, "default-lock-compliance": true, "write-cannot-delete": false, "write-can-abort-multipart": true,
		"read-only-cannot-write": true, "projects-credential-cannot-reach-control-plane-bucket": true, "conditional-create": true,
		"conditional-create-multipart": true, "checksum-enforced": true, "region-checked": false, "lifecycle-noncurrent-rule-present": true,
		"lifecycle-abort-incomplete-rule-present": true}
	for _, row := range r.ProbeRows {
		t.Logf("%-55s %-5v %s", row.Name, row.OK, row.Detail)
		if w, ok := want[row.Name]; !ok || w != row.OK {
			t.Errorf("%s: ok %v, want %v (%s)", row.Name, row.OK, w, row.Detail)
		}
	}
	if len(r.ProbeRows) != len(want) {
		t.Errorf("%d rows", len(r.ProbeRows))
	}
	// Nothing outside the probe's prefix was written.
	page, _, _, err := write.ListVersions(context.Background(), e.Prefix+"/", "", "")
	for _, o := range page {
		if !strings.HasPrefix(o.Key, ProbeBase(e.Prefix)+"/") {
			t.Errorf("the probe wrote %s", o.Key)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}
