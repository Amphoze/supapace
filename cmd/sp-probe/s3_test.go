package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/s3x"
)

type s3Req struct {
	method, path, query string
	header              http.Header
	body                []byte
}

// s3Fake answers with answer(r) after checking the signature, the payload
// hash and Content-MD5 the way a server does.
type s3Fake struct {
	mu     sync.Mutex
	reqs   []s3Req
	answer func(w http.ResponseWriter, r s3Req)
	srv    *httptest.Server
	args   []string // the common flags for this fake
}

func newS3Fake(t *testing.T) *s3Fake {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"s3.sp.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &s3Fake{}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf}, PrivateKey: key}}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	dir := t.TempDir()
	caFile, keys := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "k.keys")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600)
	os.WriteFile(keys, []byte("ak\nsk\n"), 0o600)
	f.args = []string{"--endpoint", "https://s3.sp.test:9443", "--ca", caFile, "--keys", keys, "--bucket", "sp-b",
		"--addr", f.srv.Listener.Addr().String(), "--timeout", "5s"}
	return f
}

func (f *s3Fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	rq := s3Req{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Clone(), body}
	f.mu.Lock()
	f.reqs = append(f.reqs, rq)
	answer := f.answer
	f.mu.Unlock()
	auth := r.Header.Get("Authorization")
	_, signed, _ := strings.Cut(auth, "SignedHeaders=")
	signed, _, _ = strings.Cut(signed, ",")
	when, _ := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	again, _ := http.NewRequest(r.Method, "https://"+r.Host+r.RequestURI, nil)
	for _, n := range strings.Split(signed, ";") {
		if n != "host" {
			again.Header[http.CanonicalHeaderKey(n)] = r.Header.Values(n)
		}
	}
	s3x.Sign(again, r.Header.Get("X-Amz-Content-Sha256"), "ak", "sk", "us-east-1", when)
	sum, m := sha256.Sum256(body), md5.Sum(body)
	switch {
	case auth == "" || again.Header.Get("Authorization") != auth:
		w.WriteHeader(403)
		io.WriteString(w, "<Error><Code>SignatureDoesNotMatch</Code></Error>")
	case r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]):
		w.WriteHeader(400)
	case len(body) > 0 && r.Header.Get("Content-MD5") != base64.StdEncoding.EncodeToString(m[:]):
		w.WriteHeader(400)
		io.WriteString(w, "<Error><Code>BadDigest</Code></Error>")
	case answer != nil:
		answer(w, rq)
	}
}

func (f *s3Fake) requests() []s3Req {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]s3Req(nil), f.reqs...)
}

func (f *s3Fake) run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	return probe(t, append(append([]string{"s3"}, args...), f.args...)...)
}

func TestS3_Usage(t *testing.T) {
	f := newS3Fake(t)
	for _, args := range [][]string{
		{"s3"}, {"s3", "head"}, {"s3", "head", "--endpoint", "https://s3.sp.test", "--keys", "/nonexistent", "--bucket", "sp-b"},
		append([]string{"s3", "frobnicate"}, f.args...), append([]string{"s3", "versioning", "on"}, f.args...),
		append([]string{"s3", "lock", "0"}, f.args...), append([]string{"s3", "lifecycle", "1"}, f.args...),
		append([]string{"s3", "put"}, f.args...), append([]string{"s3", "head", "--addr", "x"}, f.args...),
		append([]string{"s3", "put", "k", "--meta", "novalue"}, f.args...),
		append([]string{"s3", "head", "--endpoint", "http://s3.sp.test"}, f.args[2:]...),
	} {
		code, out := probe(t, args...)
		if code != exitError || !strings.HasPrefix(out, "error ") || strings.Count(out, "\n") != 1 {
			t.Errorf("%q: exit %d %q", args, code, out)
		}
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("usage errors sent %d requests", n)
	}
}

func TestS3_BucketSetUp(t *testing.T) {
	f := newS3Fake(t)
	f.answer = func(w http.ResponseWriter, r s3Req) {
		switch {
		case r.method == "GET" && r.query == "versioning=":
			io.WriteString(w, "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
		case r.method == "GET" && r.query == "object-lock=":
			io.WriteString(w, "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>")
		case r.method == "GET" && r.query == "lifecycle=":
			w.WriteHeader(404)
			io.WriteString(w, "<Error><Code>NoSuchLifecycleConfiguration</Code></Error>")
		}
	}
	for _, c := range []struct {
		args []string
		out  string
		reqs []string // method path?query
	}{
		{[]string{"mkbucket"}, "created\n", []string{"PUT /sp-b?"}},
		{[]string{"head"}, "bucket ok\n", []string{"HEAD /sp-b?"}},
		{[]string{"versioning", "enable"}, "versioning Enabled\n", []string{"PUT /sp-b?versioning=", "GET /sp-b?versioning="}},
		{[]string{"lock", "1"}, "lock COMPLIANCE 1\n", []string{"PUT /sp-b?object-lock=", "GET /sp-b?object-lock="}},
		{[]string{"lifecycle"}, "lifecycle none\n", []string{"GET /sp-b?lifecycle="}},
	} {
		n := len(f.requests())
		code, out := f.run(t, c.args...)
		if code != 0 || out != c.out {
			t.Errorf("%v: exit %d %q", c.args, code, out)
		}
		var got []string
		for _, r := range f.requests()[n:] {
			got = append(got, r.method+" "+r.path+"?"+r.query)
		}
		if strings.Join(got, ",") != strings.Join(c.reqs, ",") {
			t.Errorf("%v: requests %v, want %v", c.args, got, c.reqs)
		}
	}
	reqs := f.requests()
	if reqs[0].header.Get("X-Amz-Bucket-Object-Lock-Enabled") != "true" {
		t.Errorf("mkbucket headers %v", reqs[0].header)
	}
	for _, i := range []int{2, 4} {
		if reqs[i].header.Get("Content-MD5") == "" || len(reqs[i].body) == 0 {
			t.Errorf("request %d sent without a body digest", i)
		}
	}
	if !strings.Contains(string(reqs[2].body), "<Status>Enabled</Status>") ||
		!strings.Contains(string(reqs[4].body), "<Mode>COMPLIANCE</Mode><Days>1</Days>") {
		t.Errorf("bodies %q %q", reqs[2].body, reqs[4].body)
	}
	// lifecycle set: one rule with both actions.
	f.answer = func(w http.ResponseWriter, r s3Req) {
		if r.method == "GET" {
			io.WriteString(w, "<LifecycleConfiguration><Rule><ID>sp</ID><NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration><AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>")
		}
	}
	if code, out := f.run(t, "lifecycle", "1", "30"); code != 0 || out != "lifecycle sp 1 30\n" {
		t.Errorf("lifecycle set: %d %q", code, out)
	}
	put := f.requests()[len(f.requests())-2]
	if put.method != "PUT" || !strings.Contains(string(put.body), "<DaysAfterInitiation>1</DaysAfterInitiation>") ||
		!strings.Contains(string(put.body), "<NoncurrentDays>30</NoncurrentDays>") {
		t.Errorf("lifecycle body %s %q", put.method, put.body)
	}
	// A missing bucket is not "no configuration".
	f.answer = func(w http.ResponseWriter, r s3Req) {
		w.WriteHeader(404)
		io.WriteString(w, "<Error><Code>NoSuchBucket</Code></Error>")
	}
	if code, out := f.run(t, "lock"); code != exitRefused || out != "not-found\n" {
		t.Errorf("lock on a missing bucket: %d %q", code, out)
	}
}

func TestS3_PutGetAndRefusals(t *testing.T) {
	f := newS3Fake(t)
	status := 200
	f.answer = func(w http.ResponseWriter, r s3Req) {
		w.Header().Set("X-Amz-Version-Id", "v1\xc3\xa9")
		w.WriteHeader(status)
		if r.method == "GET" {
			io.WriteString(w, "hello")
		}
	}
	stdin = strings.NewReader("payload")
	t.Cleanup(func() { stdin = os.Stdin })
	if code, out := f.run(t, "put", "a/k", "--if-absent", "--meta", "sha256=abc"); code != 0 || out != "version v1?\n" {
		t.Errorf("put: %d %q", code, out)
	}
	r := f.requests()[0]
	if r.method != "PUT" || r.path != "/sp-b/a/k" || string(r.body) != "payload" || r.header.Get("If-None-Match") != "*" ||
		r.header.Get("X-Amz-Meta-Sha256") != "abc" {
		t.Errorf("put request %s %s %q %v", r.method, r.path, r.body, r.header)
	}
	sum := sha256.Sum256([]byte("hello"))
	out := filepath.Join(t.TempDir(), "o")
	if code, got := f.run(t, "get", "a/k", "--version", "v0", "--out", out); code != 0 || got != fmt.Sprintf("object 5 %x v1?\n", sum) {
		t.Errorf("get: %d %q", code, got)
	}
	if b, _ := os.ReadFile(out); string(b) != "hello" {
		t.Errorf("get --out wrote %q", b)
	}
	if r := f.requests()[1]; r.query != "versionId=v0" {
		t.Errorf("get query %q", r.query)
	}
	if code, got := f.run(t, "get", "a/k", "--max", "4"); code != exitError || !strings.HasPrefix(got, "error ") {
		t.Errorf("get over max: %d %q", code, got)
	}
	for st, want := range map[int]string{412: "exists", 403: "denied", 404: "not-found"} {
		status = st
		stdin = strings.NewReader("x")
		if code, got := f.run(t, "put", "a/k"); code != exitRefused || got != want+"\n" {
			t.Errorf("put answered %d: exit %d %q", st, code, got)
		}
	}
	n := len(f.requests())
	stdin = strings.NewReader(strings.Repeat("x", s3MaxBody+1))
	if code, got := f.run(t, "put", "a/k"); code != exitError || len(f.requests()) != n {
		t.Errorf("stdin over the bound: exit %d %q, %d requests", code, got, len(f.requests())-n)
	}
	status = 500
	stdin = strings.NewReader("x")
	if code, got := f.run(t, "put", "a/k"); code != exitError || !strings.HasPrefix(got, "error ") {
		t.Errorf("put answered 500: exit %d %q", code, got)
	}
}

func TestS3_RmBuildsASignedDelete(t *testing.T) {
	f := newS3Fake(t)
	f.answer = func(w http.ResponseWriter, r s3Req) {
		w.Header().Set("X-Amz-Version-Id", "m1")
		w.Header().Set("X-Amz-Delete-Marker", "true")
		w.WriteHeader(204)
	}
	if code, out := f.run(t, "rm", "a/k", "--version", "v 1"); code != 0 || out != "removed m1 marker=true\n" {
		t.Errorf("rm: %d %q", code, out)
	}
	r := f.requests()[0]
	if r.method != "DELETE" || r.path != "/sp-b/a/k" || r.query != "versionId=v%201" {
		t.Errorf("rm request %s %s %q", r.method, r.path, r.query)
	}
	f.answer = func(w http.ResponseWriter, r s3Req) { w.WriteHeader(403) }
	if code, out := f.run(t, "rm", "a/k"); code != exitRefused || out != "denied\n" {
		t.Errorf("rm refused: %d %q", code, out)
	}
	if r := f.requests()[1]; r.query != "" {
		t.Errorf("rm without a version sent %q", r.query)
	}
	// The fake checks the signature: a wrong secret is refused.
	os.WriteFile(f.args[5], []byte("ak\nwrong\n"), 0o600)
	f.answer = func(w http.ResponseWriter, r s3Req) { w.WriteHeader(204) }
	if code, out := f.run(t, "rm", "a/k"); code != exitRefused || out != "denied\n" {
		t.Errorf("wrong secret: %d %q", code, out)
	}
}

func TestS3_VersionsAllPagesInStoreOrder(t *testing.T) {
	f := newS3Fake(t)
	f.answer = func(w http.ResponseWriter, r s3Req) {
		if !strings.Contains(r.query, "key-marker") {
			io.WriteString(w, "<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>p/a</NextKeyMarker><NextVersionIdMarker>2</NextVersionIdMarker>"+
				"<DeleteMarker><Key>p/a</Key><VersionId>1</VersionId><IsLatest>true</IsLatest><LastModified>2026-01-01T00:00:00Z</LastModified></DeleteMarker>"+
				"<Version><Key>p/a</Key><VersionId>2</VersionId><IsLatest>false</IsLatest><LastModified>2026-01-02T00:00:00Z</LastModified></Version></ListVersionsResult>")
			return
		}
		io.WriteString(w, "<ListVersionsResult><Version><Key>p/b</Key><VersionId>3</VersionId><IsLatest>true</IsLatest><LastModified>2025-01-01T00:00:00Z</LastModified></Version></ListVersionsResult>")
	}
	want := "marker \"p/a\" 1 latest\nversion \"p/a\" 2 noncurrent\nversion \"p/b\" 3 latest\n"
	if code, out := f.run(t, "versions", "p/"); code != 0 || out != want {
		t.Errorf("versions: %d %q", code, out)
	}
	if r := f.requests()[1]; !strings.Contains(r.query, "key-marker=p%2Fa") || !strings.Contains(r.query, "version-id-marker=2") {
		t.Errorf("second page query %q", r.query)
	}
}

func TestS3_AddrsInOrderAndTimeout(t *testing.T) {
	f := newS3Fake(t)
	f.answer = func(w http.ResponseWriter, r s3Req) {}
	dead := closedPort(t, "tcp")
	args := append([]string{"s3", "head", "--addr", dead}, f.args...) // the dead address first, then the fake's
	if code, out := probe(t, args...); code != 0 || out != "bucket ok\n" {
		t.Errorf("dead address first: %d %q", code, out)
	}
	f.answer = func(w http.ResponseWriter, r s3Req) { time.Sleep(2 * time.Second) }
	args = append([]string{"s3", "head"}, f.args...)
	args[len(args)-1] = "200ms"
	if code, out := probe(t, args...); code != exitTimeout || out != "timeout\n" {
		t.Errorf("stalled: %d %q", code, out)
	}
}

func TestS3_OptionNotTakenIsUsage(t *testing.T) {
	f := newS3Fake(t)
	f.answer = func(w http.ResponseWriter, r s3Req) {}
	stdin = strings.NewReader("x")
	t.Cleanup(func() { stdin = os.Stdin })
	for _, args := range [][]string{
		{"get", "k", "--if-absent"}, {"put", "k", "--version", "v"}, {"versioning", "--max", "3"},
		{"head", "--version", "v"}, {"rm", "k", "--meta", "a=b"}, {"versions", "--out", "/dev/null"}, {"mkbucket", "--if-absent"},
	} {
		if code, out := f.run(t, args...); code != exitError || !strings.Contains(out, "does not take") {
			t.Errorf("%v: exit %d %q", args, code, out)
		}
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d requests sent", n)
	}
	// Controls: the same options where they apply.
	for _, args := range [][]string{{"head", "k", "--version", "v"}, {"rm", "k", "--version", "v"}, {"put", "k", "--if-absent", "--meta", "a=b"}} {
		if code, out := f.run(t, args...); code == exitError && strings.Contains(out, "usage") {
			t.Errorf("control %v: %q", args, out)
		}
	}
}

func TestS3_MkbucketAgainIsOwned(t *testing.T) {
	f := newS3Fake(t)
	code := "BucketAlreadyOwnedByYou"
	f.answer = func(w http.ResponseWriter, r s3Req) {
		w.WriteHeader(409)
		io.WriteString(w, "<Error><Code>"+code+"</Code></Error>")
	}
	if c, out := f.run(t, "mkbucket"); c != 0 || out != "owned\n" {
		t.Errorf("own bucket again: %d %q", c, out)
	}
	code = "BucketAlreadyExists" // someone else's
	if c, out := f.run(t, "mkbucket"); c != exitError || !strings.HasPrefix(out, "error ") {
		t.Errorf("foreign bucket: %d %q", c, out)
	}
}

func TestS3_FieldsAreSingleTokens(t *testing.T) {
	f := newS3Fake(t)
	f.answer = func(w http.ResponseWriter, r s3Req) {
		io.WriteString(w, "<ListVersionsResult><Version><Key>p/a b\tc\"d</Key><VersionId>v 1</VersionId><IsLatest>true</IsLatest>"+
			"<LastModified>2026-01-01T00:00:00Z</LastModified></Version><Version><Key>p/e</Key><VersionId></VersionId>"+
			"<IsLatest>false</IsLatest><LastModified>2026-01-01T00:00:00Z</LastModified></Version></ListVersionsResult>")
	}
	want := "version \"p/a b\\tc\\\"d\" v?1 latest\nversion \"p/e\" - noncurrent\n"
	if code, out := f.run(t, "versions", "p/"); code != 0 || out != want {
		t.Errorf("versions: %d %q, want %q", code, out, want)
	}
}

func TestS3_RawAnswersMapped(t *testing.T) {
	f := newS3Fake(t)
	code := ""
	f.answer = func(w http.ResponseWriter, r s3Req) {
		w.WriteHeader(400)
		io.WriteString(w, "<Error><Code>"+code+"</Code></Error>")
	}
	for c, want := range map[string]string{"BadDigest": "bad-digest\n", "XAmzContentSHA256Mismatch": "bad-digest\n"} {
		code = c
		if ec, out := f.run(t, "versioning", "enable"); ec != exitRefused || out != want {
			t.Errorf("%s: %d %q", c, ec, out)
		}
	}
	code = strings.Repeat("C", 1000)
	if ec, out := f.run(t, "versioning"); ec != exitError || len(out) > 200 {
		t.Errorf("long code: %d, %d bytes", ec, len(out))
	}
}
