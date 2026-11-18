package s3x

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
)

// The stand-in object store, started by digest with a certificate made here.
// Its tests run only when SUPAPACE_STANDIN_TEST=1.
const standinImage = "chrislusf/seaweedfs@sha256:4b42c212543a0acd4c0e675215ecdcaf62a186ef98def76c7e12701871222d15"

type standinT struct {
	cfg  Config
	hc   *http.Client
	name string
	err  error
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

func startStandin() *standinT {
	s := &standinT{}
	fail := func(err error) *standinT { s.err = err; return s }
	dir, err := os.MkdirTemp("", "sp-test-s3x-")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(dir)
	ca, err := writeTLS(dir, testName)
	if err != nil {
		return fail(err)
	}
	s.cfg = Config{Endpoint: "https://" + testName + ":9443", Region: "us-east-1", Bucket: "sp-standin", PathStyle: true,
		AccessKey: hex.EncodeToString(randBytes(8)), SecretKey: hex.EncodeToString(randBytes(18)), CAPEM: ca, Timeout: 30 * time.Second}
	conf := fmt.Sprintf(`{"identities":[{"name":"admin","credentials":[{"accessKey":%q,"secretKey":%q}],"actions":["Admin","Read","List","Tagging","Write"]}]}`,
		s.cfg.AccessKey, s.cfg.SecretKey)
	if err := os.WriteFile(filepath.Join(dir, "s3.json"), []byte(conf), 0o644); err != nil {
		return fail(err)
	}
	ctx := context.Background()
	name := "sp-test-s3x-standin-" + hex.EncodeToString(randBytes(4))
	// A detached watchdog removes the container once this process is gone, whatever
	// ends it (a panic, the test timeout, a kill); the second removal covers a
	// create still in flight at that moment.
	w := exec.Command("sh", "-c", `while kill -0 "$1" 2>/dev/null; do sleep 1; done
		docker rm -f -v "$2" >/dev/null 2>&1; sleep 5; docker rm -f -v "$2" >/dev/null 2>&1`,
		"sh", strconv.Itoa(os.Getpid()), name)
	w.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := w.Start(); err != nil {
		return fail(err)
	}
	w.Process.Release()
	// The container is created from a copy of the TLS directory (docker cp), so nothing depends on the host path.
	if _, err := dockerx.Run(ctx, "create", "--label", "supapace.test=1", "--name", name, "-p", "127.0.0.1:0:9443",
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
	ap, err := netip.ParseAddrPort(strings.TrimSpace(strings.Split(out, "\n")[0]))
	if err != nil {
		return fail(fmt.Errorf("docker port: %q", out))
	}
	s.cfg.Addrs = []netip.AddrPort{ap}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(ca))
	s.hc = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", ap.String())
		},
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	// Ready when the store answers a signed request; then the bucket as the harness makes it:
	// created, versioning enabled, then the compliance lock.
	deadline := time.Now().Add(120 * time.Second)
	for {
		if code, _, err := s.raw("GET", "/", "", nil, nil); err == nil && code == 200 {
			break
		}
		if time.Now().After(deadline) {
			logs, _, _ := dockerx.RunOutput(ctx, "logs", "--tail", "20", name)
			return fail(fmt.Errorf("not ready in 120 s: %s", logs))
		}
		time.Sleep(500 * time.Millisecond)
	}
	steps := []struct {
		method, query, body string
		hdr                 map[string]string
	}{
		{"PUT", "", "", map[string]string{"X-Amz-Bucket-Object-Lock-Enabled": "true"}},
		{"PUT", "versioning", "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>", nil},
		{"PUT", "object-lock", "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>", nil},
	}
	for _, st := range steps {
		code, doc, err := s.raw(st.method, "/"+s.cfg.Bucket, st.query, []byte(st.body), st.hdr)
		if err != nil || code != 200 {
			return fail(fmt.Errorf("bucket set-up %s ?%s: %d %s %v", st.method, st.query, code, doc, err))
		}
	}
	return s
}

// raw sends one signed request and returns the status and at most 1 MiB of the body.
func (s *standinT) raw(method, path, query string, body []byte, hdr map[string]string) (int, string, error) {
	r, err := http.NewRequest(method, "https://"+testName+":9443"+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	r.URL.RawQuery = query
	r.ContentLength = int64(len(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	sum := sha256.Sum256(body)
	Sign(r, hex.EncodeToString(sum[:]), s.cfg.AccessKey, s.cfg.SecretKey, s.cfg.Region, time.Now())
	resp, err := s.hc.Do(r)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	doc, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(doc), nil
}

func (s *standinT) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func writeTLS(dir, name string) (string, error) {
	ca, err := makeCA([]string{name}, nil)
	if err != nil {
		return "", err
	}
	leaf := ca.cert
	var certPEM []byte
	for _, der := range leaf.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o644); err != nil {
		return "", err
	}
	return ca.pem, nil
}

func versionsOf(t *testing.T, c *Client, prefix string) []Object {
	t.Helper()
	var all []Object
	km, vm := "", ""
	for i := 0; i < 100; i++ {
		page, nk, nv, err := c.ListVersions(bg, prefix, km, vm)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, page...)
		if nk == "" {
			return all
		}
		km, vm = nk, nv
	}
	t.Fatal("version listing did not end")
	return nil
}

func TestStandin_RoundTrip(t *testing.T) {
	s := needStandin(t)
	c := s.client(t)
	p := "rt-" + hex.EncodeToString(randBytes(4)) + "/"
	body := randBytes(1000)
	v, err := c.Put(bg, p+"one", body, map[string]string{"sha256": "abc"}, true)
	if err != nil || v == "" {
		t.Fatalf("put: %q %v", v, err)
	}
	if _, err := c.Put(bg, p+"one", randBytes(1000), nil, true); !errors.Is(err, ErrExists) {
		t.Errorf("second conditional put: %v", err)
	}
	o, err := c.Head(bg, p+"one", "")
	if err != nil || o.VersionID != v || o.Size != 1000 || o.Meta["sha256"] != "abc" {
		t.Errorf("head: %+v %v", o, err)
	}
	var buf bytes.Buffer
	if o, err := c.Get(bg, p+"one", v, &buf, 1000); err != nil || !bytes.Equal(buf.Bytes(), body) || o.VersionID != v {
		t.Errorf("get: %+v %v", o, err)
	}
	if _, err := c.Get(bg, p+"one", v, &buf, 999); err == nil {
		t.Error("get over max accepted")
	}
	if _, err := c.Head(bg, p+"none", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("head absent: %v", err)
	}
	// Multipart, conditional at completion.
	id, err := c.CreateMultipart(bg, p+"big", map[string]string{"sha256": "whole"})
	if err != nil {
		t.Fatal(err)
	}
	p1, p2 := randBytes(5<<20), randBytes(1<<20)
	e1, err := c.UploadPart(bg, p+"big", id, 1, p1)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := c.UploadPart(bg, p+"big", id, 2, p2)
	if err != nil {
		t.Fatal(err)
	}
	mv, err := c.CompleteMultipart(bg, p+"big", id, []string{e1, e2}, true)
	if err != nil || mv == "" {
		t.Fatalf("complete: %q %v", mv, err)
	}
	buf.Reset()
	if _, err := c.Get(bg, p+"big", mv, &buf, 6<<20); err != nil || !bytes.Equal(buf.Bytes(), append(p1, p2...)) {
		t.Errorf("multipart read back: %d bytes %v", buf.Len(), err)
	}
	page, next, err := c.List(bg, p, "")
	if err != nil || next != "" || len(page) != 2 || page[0].Key != p+"big" || page[1].Key != p+"one" {
		t.Errorf("list: %+v %q %v", page, next, err)
	}
	// A wrong secret is refused.
	cfg := s.cfg
	cfg.SecretKey += "x"
	bad, _ := New(cfg)
	if _, err := bad.Put(bg, p+"denied", []byte("x"), nil, false); !errors.Is(err, ErrDenied) {
		t.Errorf("wrong secret: %v", err)
	}
}

func TestStandin_VersionsAfterTwoPuts(t *testing.T) {
	s := needStandin(t)
	c := s.client(t)
	p := "vv-" + hex.EncodeToString(randBytes(4)) + "/"
	b1, b2 := []byte("first"), []byte("second")
	v1, err := c.Put(bg, p+"k", b1, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := c.Put(bg, p+"k", b2, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	vs := versionsOf(t, c, p)
	if len(vs) != 2 || vs[0].VersionID != v2 || !vs[0].Latest || vs[1].VersionID != v1 || vs[1].Latest || vs[0].DeleteMarker || vs[1].DeleteMarker {
		t.Fatalf("versions: %+v (want %s then %s)", vs, v2, v1)
	}
	for v, want := range map[string][]byte{v1: b1, v2: b2} {
		var buf bytes.Buffer
		if _, err := c.Get(bg, p+"k", v, &buf, 100); err != nil || !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("version %s: %q %v", v, buf.String(), err)
		}
	}
	// Paging by markers, one entry per page, visits the same list.
	q := fmt.Sprintf("versions=&prefix=%s&max-keys=1", p)
	code, doc, err := s.raw("GET", "/"+s.cfg.Bucket, q, nil, nil)
	if err != nil || code != 200 || !strings.Contains(doc, "<IsTruncated>true</IsTruncated>") {
		t.Errorf("one-entry page: %d %v %s", code, err, doc)
	}
}

func TestStandin_RefusedCompletionThenAbort(t *testing.T) {
	s := needStandin(t)
	c := s.client(t)
	p := "ab-" + hex.EncodeToString(randBytes(4)) + "/"
	if _, err := c.Put(bg, p+"m", []byte("exists"), nil, true); err != nil {
		t.Fatal(err)
	}
	id, err := c.CreateMultipart(bg, p+"m", nil)
	if err != nil {
		t.Fatal(err)
	}
	e, err := c.UploadPart(bg, p+"m", id, 1, randBytes(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CompleteMultipart(bg, p+"m", id, []string{e}, true); !errors.Is(err, ErrExists) {
		t.Fatalf("completion on an existing key: %v", err)
	}
	uploads := func() int {
		code, doc, err := s.raw("GET", "/"+s.cfg.Bucket, "prefix="+p+"&uploads=", nil, nil)
		if err != nil || code != 200 {
			t.Fatalf("list uploads: %d %v %s", code, err, doc)
		}
		return strings.Count(doc, "<UploadId>"+id+"</UploadId>")
	}
	if n := uploads(); n != 1 {
		t.Fatalf("refused upload listed %d times, want 1 (still open)", n)
	}
	if err := c.AbortMultipart(bg, p+"m", id); err != nil {
		t.Fatal(err)
	}
	if n := uploads(); n != 0 {
		t.Errorf("upload listed %d times after the abort", n)
	}
	if vs := versionsOf(t, c, p); len(vs) != 1 || vs[0].DeleteMarker {
		t.Errorf("versions after the abort: %+v", vs)
	}
}
