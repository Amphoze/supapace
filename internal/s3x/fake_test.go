package s3x

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAK     = "testaccess"
	testSK     = "testsecret"
	testRegion = "test-region"
	testBucket = "sp-bk"
	testName   = "s3.sp.test"
)

// testCA is a throw-away CA and a server certificate issued by it.
type testCA struct {
	pem  string // the CA certificate
	cert tls.Certificate
}

func newCA(t *testing.T, dns []string, ips []net.IP) testCA {
	t.Helper()
	ca, err := makeCA(dns, ips)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func makeCA(dns []string, ips []net.IP) (testCA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return testCA{}, err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "throw-away test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return testCA{}, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "server"}, DNSNames: dns, IPAddresses: ips,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		return testCA{}, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	if err != nil {
		return testCA{}, err
	}
	return testCA{pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), cert: cert}, nil
}

type fakeVersion struct {
	key, id, etag string
	body          []byte
	meta          map[string]string
	mod           time.Time
	marker        bool
}

type fakeUpload struct {
	key   string
	meta  map[string]string
	parts map[int][]byte
}

type recorded struct {
	method, path string
	query        url.Values
	header       http.Header
	body         []byte
}

// fake is an in-process object store: path style, one bucket, signatures,
// payload hashes and Content-MD5 checked as a server does.
type fake struct {
	t        *testing.T
	srv      *httptest.Server
	ca       testCA
	mu       sync.Mutex
	seq      int
	versions []fakeVersion // every version, newest first per key after sort
	uploads  map[string]*fakeUpload
	pageSize int
	reqs     []recorded
	// hook, when set, answers a request instead of the store.
	hook func(w http.ResponseWriter, r *http.Request)
}

func newFake(t *testing.T) *fake {
	t.Helper()
	return newFakeWith(t, newCA(t, []string{testName}, []net.IP{net.IPv4(127, 0, 0, 1)}), 0)
}

// newFakeWith serves with ca's certificate, at most TLS version max (0: the default).
func newFakeWith(t *testing.T, ca testCA, max uint16) *fake {
	t.Helper()
	f := &fake{t: t, uploads: map[string]*fakeUpload{}, pageSize: 2, ca: ca}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{f.ca.cert}, MinVersion: tls.VersionTLS10, MaxVersion: max}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) addr() netip.AddrPort { return netip.MustParseAddrPort(f.srv.Listener.Addr().String()) }

// config dials the fake by address under the test name.
func (f *fake) config() Config {
	return Config{Endpoint: "https://" + testName + ":9443", Region: testRegion, Bucket: testBucket, PathStyle: true,
		AccessKey: testAK, SecretKey: testSK, CAPEM: f.ca.pem, Addrs: []netip.AddrPort{f.addr()}, Timeout: 10 * time.Second}
}

func (f *fake) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(f.config())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fake) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

func s3err(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code></Error>", code)
}

// verify checks the request the way a server does; it returns the failure code.
func verify(r *http.Request, body []byte) (int, string) {
	auth := r.Header.Get("Authorization")
	rest, ok := strings.CutPrefix(auth, "AWS4-HMAC-SHA256 ")
	if !ok {
		return 403, "AccessDenied"
	}
	var cred, signed string
	for _, p := range strings.Split(rest, ",") {
		k, v, _ := strings.Cut(p, "=")
		switch k {
		case "Credential":
			cred = v
		case "SignedHeaders":
			signed = v
		}
	}
	if !strings.HasPrefix(cred, testAK+"/") || !strings.HasSuffix(cred, "/"+testRegion+"/s3/aws4_request") {
		return 403, "InvalidAccessKeyId"
	}
	names := strings.Split(signed, ";")
	for _, must := range []string{"host", "x-amz-date", "x-amz-content-sha256"} {
		if !contains(names, must) {
			return 403, "SignatureDoesNotMatch"
		}
	}
	if r.Header.Get("Content-MD5") != "" && !contains(names, "content-md5") {
		return 403, "SignatureDoesNotMatch"
	}
	when, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return 403, "AccessDenied"
	}
	again, _ := http.NewRequest(r.Method, "https://"+r.Host+r.RequestURI, nil)
	again.Host = r.Host
	for _, n := range names {
		if n != "host" {
			again.Header[http.CanonicalHeaderKey(n)] = r.Header.Values(n)
		}
	}
	Sign(again, r.Header.Get("X-Amz-Content-Sha256"), testAK, testSK, testRegion, when)
	if again.Header.Get("Authorization") != auth {
		return 403, "SignatureDoesNotMatch"
	}
	sum := sha256.Sum256(body)
	if r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) {
		return 400, "XAmzContentSHA256Mismatch"
	}
	if m := r.Header.Get("Content-MD5"); m != "" {
		ms := md5.Sum(body)
		if m != base64.StdEncoding.EncodeToString(ms[:]) {
			return 400, "BadDigest"
		}
	}
	return 0, ""
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func metaOf(h http.Header) map[string]string {
	m := map[string]string{}
	for k, v := range h {
		if n, ok := strings.CutPrefix(strings.ToLower(k), "x-amz-meta-"); ok {
			m[n] = v[0]
		}
	}
	return m
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	r.Body = io.NopCloser(bytes.NewReader(body))
	f.mu.Lock()
	f.reqs = append(f.reqs, recorded{r.Method, r.URL.Path, r.URL.Query(), r.Header.Clone(), body})
	hook := f.hook
	f.mu.Unlock()
	if hook != nil {
		hook(w, r)
		return
	}
	if code, name := verify(r, body); code != 0 {
		s3err(w, code, name)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key, ok := strings.CutPrefix(r.URL.Path, "/"+testBucket)
	if !ok {
		s3err(w, 404, "NoSuchBucket")
		return
	}
	key = strings.TrimPrefix(key, "/")
	q := r.URL.Query()
	switch {
	case r.Method == "GET" && key == "" && q.Has("versions"):
		f.listVersions(w, q)
	case r.Method == "GET" && key == "" && q.Get("list-type") == "2":
		f.list(w, q)
	case r.Method == "POST" && q.Has("uploads"):
		f.seq++
		id := fmt.Sprintf("up%d", f.seq)
		f.uploads[id] = &fakeUpload{key: key, meta: metaOf(r.Header), parts: map[int][]byte{}}
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><UploadId>%s</UploadId></InitiateMultipartUploadResult>", testBucket, key, id)
	case r.Method == "PUT" && q.Has("uploadId"):
		u := f.uploads[q.Get("uploadId")]
		n, _ := strconv.Atoi(q.Get("partNumber"))
		if u == nil || u.key != key {
			s3err(w, 404, "NoSuchUpload")
			return
		}
		u.parts[n] = body
		w.Header().Set("ETag", etagOf(body))
	case r.Method == "POST" && q.Has("uploadId"):
		u := f.uploads[q.Get("uploadId")]
		if u == nil || u.key != key {
			s3err(w, 404, "NoSuchUpload")
			return
		}
		var c struct {
			Parts []struct {
				PartNumber int
				ETag       string
			} `xml:"Part"`
		}
		if xml.Unmarshal(body, &c) != nil || len(c.Parts) == 0 {
			s3err(w, 400, "MalformedXML")
			return
		}
		var all []byte
		for _, p := range c.Parts {
			b, ok := u.parts[p.PartNumber]
			if !ok || etagOf(b) != p.ETag {
				s3err(w, 400, "InvalidPart")
				return
			}
			all = append(all, b...)
		}
		if r.Header.Get("If-None-Match") == "*" && f.current(key) != nil {
			s3err(w, 412, "PreconditionFailed")
			return
		}
		v := f.add(key, all, u.meta)
		w.Header().Set("X-Amz-Version-Id", v.id)
		fmt.Fprintf(w, "<CompleteMultipartUploadResult><Key>%s</Key><ETag>%s</ETag></CompleteMultipartUploadResult>", key, v.etag)
	case r.Method == "DELETE" && q.Has("uploadId"):
		if _, ok := f.uploads[q.Get("uploadId")]; !ok {
			s3err(w, 404, "NoSuchUpload")
			return
		}
		delete(f.uploads, q.Get("uploadId"))
		w.WriteHeader(204)
	case r.Method == "PUT" && key != "":
		if r.Header.Get("If-None-Match") == "*" && f.current(key) != nil {
			s3err(w, 412, "PreconditionFailed")
			return
		}
		v := f.add(key, body, metaOf(r.Header))
		w.Header().Set("X-Amz-Version-Id", v.id)
		w.Header().Set("ETag", v.etag)
	case (r.Method == "GET" || r.Method == "HEAD") && key != "":
		v := f.find(key, q.Get("versionId"))
		if v == nil {
			if r.Method == "HEAD" {
				w.WriteHeader(404)
				return
			}
			s3err(w, 404, "NoSuchKey")
			return
		}
		w.Header().Set("X-Amz-Version-Id", v.id)
		w.Header().Set("ETag", v.etag)
		w.Header().Set("Last-Modified", v.mod.UTC().Format(http.TimeFormat))
		for k, m := range v.meta {
			w.Header().Set("X-Amz-Meta-"+k, m)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(v.body)))
		if r.Method == "GET" {
			w.Write(v.body)
		}
	default:
		s3err(w, 400, "NotImplemented")
	}
}

func etagOf(b []byte) string {
	s := md5.Sum(b)
	return `"` + hex.EncodeToString(s[:]) + `"`
}

// add stores a new version. Version ids sort ascending newest first, and each
// newer version gets an EARLIER modification time, so that any ordering by time
// would reverse the store's order.
func (f *fake) add(key string, body []byte, meta map[string]string) fakeVersion {
	f.seq++
	v := fakeVersion{key: key, id: fmt.Sprintf("v%08d", 99999999-f.seq), etag: etagOf(body), body: body, meta: meta,
		mod: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(-time.Duration(f.seq) * time.Second)}
	f.versions = append(f.versions, v)
	sort.SliceStable(f.versions, func(i, j int) bool {
		a, b := f.versions[i], f.versions[j]
		return a.key < b.key || a.key == b.key && a.id < b.id
	})
	return v
}

func (f *fake) current(key string) *fakeVersion {
	for i := range f.versions {
		if f.versions[i].key == key {
			if f.versions[i].marker {
				return nil
			}
			return &f.versions[i]
		}
	}
	return nil
}

func (f *fake) find(key, id string) *fakeVersion {
	if id == "" {
		return f.current(key)
	}
	for i := range f.versions {
		if f.versions[i].key == key && f.versions[i].id == id && !f.versions[i].marker {
			return &f.versions[i]
		}
	}
	return nil
}

func (f *fake) list(w http.ResponseWriter, q map[string][]string) {
	prefix, token := first(q["prefix"]), first(q["continuation-token"])
	var keys []string
	for _, v := range f.versions {
		if strings.HasPrefix(v.key, prefix) && v.key > token && f.current(v.key) != nil && (len(keys) == 0 || keys[len(keys)-1] != v.key) {
			keys = append(keys, v.key)
		}
	}
	var b strings.Builder
	b.WriteString("<ListBucketResult>")
	trunc := len(keys) > f.pageSize
	if trunc {
		keys = keys[:f.pageSize]
		fmt.Fprintf(&b, "<IsTruncated>true</IsTruncated><NextContinuationToken>%s</NextContinuationToken>", keys[len(keys)-1])
	}
	for _, k := range keys {
		v := f.current(k)
		fmt.Fprintf(&b, "<Contents><Key>%s</Key><LastModified>%s</LastModified><ETag>%s</ETag><Size>%d</Size></Contents>",
			k, v.mod.Format(time.RFC3339), v.etag, len(v.body))
	}
	b.WriteString("</ListBucketResult>")
	io.WriteString(w, b.String())
}

func (f *fake) listVersions(w http.ResponseWriter, q map[string][]string) {
	prefix, km, vm := first(q["prefix"]), first(q["key-marker"]), first(q["version-id-marker"])
	var sel []fakeVersion
	for _, v := range f.versions {
		if !strings.HasPrefix(v.key, prefix) {
			continue
		}
		if km != "" && (v.key < km || v.key == km && (vm == "" || v.id <= vm)) {
			continue
		}
		sel = append(sel, v)
	}
	var b strings.Builder
	b.WriteString("<ListVersionsResult><Name>" + testBucket + "</Name>")
	if len(sel) > f.pageSize {
		sel = sel[:f.pageSize]
		last := sel[len(sel)-1]
		fmt.Fprintf(&b, "<IsTruncated>true</IsTruncated><NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>%s</NextVersionIdMarker>", last.key, last.id)
	}
	for _, v := range sel {
		latest := f.versions[indexOfKey(f.versions, v.key)].id == v.id
		el := "Version"
		if v.marker {
			el = "DeleteMarker"
		}
		fmt.Fprintf(&b, "<%s><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%t</IsLatest><LastModified>%s</LastModified>", el, v.key, v.id, latest, v.mod.Format(time.RFC3339))
		if !v.marker {
			fmt.Fprintf(&b, "<ETag>%s</ETag><Size>%d</Size>", v.etag, len(v.body))
		}
		fmt.Fprintf(&b, "</%s>", el)
	}
	b.WriteString("</ListVersionsResult>")
	io.WriteString(w, b.String())
}

func indexOfKey(vs []fakeVersion, key string) int {
	for i, v := range vs {
		if v.key == key {
			return i
		}
	}
	return -1
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// addMarker places a delete marker as the newest version of key.
func (f *fake) addMarker(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.add(key, nil, nil)
	for i := range f.versions {
		if f.versions[i].key == key {
			f.versions[i].marker = true
			break
		}
	}
}

func bodyOf(n int, seed byte) []byte { return bytes.Repeat([]byte{seed}, n) }
