package s3x

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A proxy named by the environment is never used: with addresses given the
// request still reaches the store, and without them the proxy sees nothing.
// The proxy environment is read once per process, so the check runs in a child
// that sets it before any request.
func TestProxyEnvironmentIgnored(t *testing.T) {
	if os.Getenv("S3X_PROXY_CHILD") == "1" {
		proxyChild(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestProxyEnvironmentIgnored$", "-test.count=1")
	cmd.Env = append(os.Environ(), "S3X_PROXY_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func proxyChild(t *testing.T) {
	pl, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pl.Close()
	var hits atomic.Int32
	go func() {
		for {
			conn, err := pl.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			conn.Close()
		}
	}()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		os.Setenv(k, "http://"+pl.Addr().String())
	}
	os.Setenv("NO_PROXY", "")
	os.Setenv("no_proxy", "")
	f := newFake(t)
	cfg := f.config()
	cfg.Timeout = 3 * time.Second
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Head(bg, "k", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("with addresses and a proxy in the environment: %v", err)
	}
	cfg.Addrs = nil // the name resolves nowhere: the call fails, and must not reach the proxy
	c, _ = New(cfg)
	c.Head(bg, "k", "")
	if n := hits.Load(); n != 0 {
		t.Errorf("the proxy was contacted %d times", n)
	}
}

// With addresses given no name is ever looked up: the default resolver is
// replaced by one that counts every query.
func TestDial_NoLookupWithAddrs(t *testing.T) {
	var queries atomic.Int32
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		queries.Add(1)
		return nil, errors.New("no resolver in this test")
	}}
	defer func() { net.DefaultResolver = old }()
	f := newFake(t)
	c := f.client(t)
	if _, err := c.Head(bg, "k", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("by address: %v", err)
	}
	if n := queries.Load(); n != 0 {
		t.Errorf("%d lookups with addresses given", n)
	}
	cfg := f.config()
	cfg.Addrs = nil
	c, _ = New(cfg)
	if _, err := c.Head(bg, "k", ""); err == nil || queries.Load() == 0 {
		t.Errorf("control without addresses: %v, %d lookups", err, queries.Load())
	}
}

// An outcome the store did not state is never a sentinel: the caller can tell
// "refused, nothing created" (the four sentinels) from "unknown".
func TestAmbiguousOutcomesAreNotSentinels(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	sentinel := func(err error) bool {
		return errors.Is(err, ErrExists) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrDenied) || errors.Is(err, ErrChecksum)
	}
	for name, hook := range map[string]func(w http.ResponseWriter, r *http.Request){
		"5xx after the body": func(w http.ResponseWriter, r *http.Request) { io.ReadAll(r.Body); s3err(w, 500, "InternalError") },
		"reset after the body": func(w http.ResponseWriter, r *http.Request) {
			io.ReadAll(r.Body)
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.(interface{ CloseWrite() error }).CloseWrite()
			conn.Close()
		},
		"completion cut mid-document": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "200")
			io.WriteString(w, "<CompleteMultipartUploadResult><Key>m</Key>")
			w.(http.Flusher).Flush()
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
		},
	} {
		f.hook = hook
		if _, err := c.Put(bg, "k", []byte("x"), nil, true); name != "completion cut mid-document" && (err == nil || sentinel(err)) {
			t.Errorf("put, %s: %v", name, err)
		}
		if _, err := c.CompleteMultipart(bg, "m", "u", []string{`"e"`}, true); err == nil || sentinel(err) {
			t.Errorf("complete, %s: %v", name, err)
		}
	}
}

// Documents the store controls never expand entities, and nesting is bounded.
func TestList_HostileDocuments(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	docs := map[string]string{
		"external entity": `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` +
			`<ListVersionsResult><Version><Key>p/&e;</Key><VersionId>v</VersionId><LastModified>2026-01-01T00:00:00Z</LastModified></Version></ListVersionsResult>`,
		"internal entity": `<!DOCTYPE x [<!ENTITY a "aaaaaaaaaa">]><ListVersionsResult><Version><Key>p/&a;</Key><VersionId>v</VersionId>` +
			`<LastModified>2026-01-01T00:00:00Z</LastModified></Version></ListVersionsResult>`,
		"deep nesting":           `<ListVersionsResult><Version>` + strings.Repeat("<a>", 200000) + strings.Repeat("</a>", 200000) + `</Version></ListVersionsResult>`,
		"key outside the prefix": `<ListVersionsResult><Version><Key>q/x</Key><VersionId>v</VersionId><LastModified>2026-01-01T00:00:00Z</LastModified></Version></ListVersionsResult>`,
	}
	for name, doc := range docs {
		f.hook = func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, doc) }
		start := time.Now()
		if p, _, _, err := c.ListVersions(bg, "p/", "", ""); err == nil {
			t.Errorf("%s: accepted %+v", name, p)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
}

// An object is the bytes as stored: a response the store chose to compress is
// not decoded by the client (the fetch compares the stored hash).
func TestGet_ContentEncodingNotDecoded(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(bytes.Repeat([]byte("a"), 1000))
	zw.Close()
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gz.Bytes())
	}
	var buf bytes.Buffer
	_, err := c.Get(bg, "k", "", &buf, 1<<20)
	if err != nil || !bytes.Equal(buf.Bytes(), gz.Bytes()) {
		t.Errorf("got %d bytes (stored %d), %v", buf.Len(), gz.Len(), err)
	}
}

// A store that answers a write without a version id has versioning off (or
// suspended): the record would hold no handle, so the write is an error.
func TestPut_NoVersionIDRefused(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	for _, v := range []string{"", "null"} {
		f.hook = func(w http.ResponseWriter, r *http.Request) {
			io.ReadAll(r.Body)
			if v != "" {
				w.Header().Set("X-Amz-Version-Id", v)
			}
		}
		if got, err := c.Put(bg, "k", []byte("x"), nil, true); err == nil {
			t.Errorf("put answered with version %q: accepted as %q", v, got)
		}
		f.hook = func(w http.ResponseWriter, r *http.Request) {
			io.ReadAll(r.Body)
			if v != "" {
				w.Header().Set("X-Amz-Version-Id", v)
			}
			io.WriteString(w, "<CompleteMultipartUploadResult><Key>m</Key></CompleteMultipartUploadResult>")
		}
		if got, err := c.CompleteMultipart(bg, "m", "u", []string{`"e"`}, true); err == nil {
			t.Errorf("completion answered with version %q: accepted as %q", v, got)
		}
	}
}

// Nothing of the credentials or of a signature reaches an error text.
func TestErrors_CarryNoSecret(t *testing.T) {
	f := newFake(t)
	closed := func() netip.AddrPort {
		l, _ := net.Listen("tcp4", "127.0.0.1:0")
		a := netip.MustParseAddrPort(l.Addr().String())
		l.Close()
		return a
	}()
	for name, mod := range map[string]func(*Config){
		"wrong secret":       func(c *Config) { c.SecretKey = "wrongsecret" },
		"newline in the key": func(c *Config) { c.AccessKey = "testaccess\nX-Evil: 1" },
		"unknown CA":         func(c *Config) { c.CAPEM = "" },
		"closed port":        func(c *Config) { c.Addrs = []netip.AddrPort{closed} },
		"timeout":            func(c *Config) { c.Timeout = time.Nanosecond },
	} {
		cfg := f.config()
		mod(&cfg)
		c, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Put(bg, "k", []byte("x"), nil, false)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		for _, s := range []string{testAK, testSK, cfg.SecretKey, "Signature=", "Credential=", "AWS4-HMAC"} {
			if strings.Contains(err.Error(), s) {
				t.Errorf("%s: %q in %q", name, s, err)
			}
		}
	}
}

// badDigest re-signs each request after spoiling its Content-MD5 or its
// payload hash, as a probe of the store's checks does.
type badDigest struct {
	rt      http.RoundTripper
	payload bool
}

func (b badDigest) RoundTrip(r *http.Request) (*http.Response, error) {
	pay := r.Header.Get("X-Amz-Content-Sha256")
	if b.payload {
		s := sha256.Sum256([]byte("other"))
		pay = hex.EncodeToString(s[:])
	} else {
		m := md5.Sum([]byte("other"))
		r.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(m[:]))
	}
	Sign(r, pay, standin.cfg.AccessKey, standin.cfg.SecretKey, standin.cfg.Region, time.Now())
	return b.rt.RoundTrip(r)
}

// The stand-in's answers to a wrong digest and to a wrong payload hash, as the
// client maps them; nothing is stored in either case.
func TestStandin_WrongDigestsRefused(t *testing.T) {
	s := needStandin(t)
	p := "dg-" + hex.EncodeToString(randBytes(4)) + "/"
	for _, payload := range []bool{false, true} {
		c := s.client(t)
		c.hc.Transport = badDigest{c.hc.Transport, payload}
		_, err := c.Put(bg, p+"k", []byte("body"), nil, true)
		if !errors.Is(err, ErrChecksum) {
			t.Errorf("payload hash %v: %v, want ErrChecksum", payload, err)
		}
	}
	if vs := versionsOf(t, s.client(t), p); len(vs) != 0 {
		t.Errorf("versions after refused writes: %+v", vs)
	}
}

// An abort with an id that names no upload touches no object or version.
func TestStandin_AbortWithForeignIDTouchesNothing(t *testing.T) {
	s := needStandin(t)
	c := s.client(t)
	p := "af-" + hex.EncodeToString(randBytes(4)) + "/"
	if _, err := c.Put(bg, p+"k", []byte("kept"), nil, true); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"bogus", " ", "null", "../k", "*"} {
		if err := c.AbortMultipart(bg, p+"k", id); err == nil {
			t.Logf("abort %q answered success", id)
		}
	}
	vs := versionsOf(t, c, p)
	if len(vs) != 1 || vs[0].DeleteMarker {
		t.Errorf("versions after foreign aborts: %+v", vs)
	}
	var buf bytes.Buffer
	if _, err := c.Get(bg, p+"k", "", &buf, 10); err != nil || buf.String() != "kept" {
		t.Errorf("object after foreign aborts: %q %v", buf.String(), err)
	}
}

// Names a store rewrites (or refuses, depending on the store) are refused
// before any request; every other troublesome character round-trips.
var rewrittenKeys = []string{"a//b", "a/./b", "a/../b", "/lead", "trail/", "..", "."}

func TestKey_RewrittenNamesRefused(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	for _, n := range rewrittenKeys {
		k := "p/" + n
		if n[0] == '/' {
			k = n
		}
		if _, err := c.Put(bg, k, []byte("x"), nil, true); err == nil {
			t.Errorf("put %q accepted", k)
		}
		if _, err := c.CreateMultipart(bg, k, nil); err == nil {
			t.Errorf("create %q accepted", k)
		}
		if _, err := c.Head(bg, k, ""); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("head %q sent: %v", k, err)
		}
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d requests sent for refused names", n)
	}
	if _, _, err := c.List(bg, "p//", ""); err == nil {
		t.Error("prefix with an empty segment accepted")
	}
	if _, _, err := c.List(bg, "p/", ""); err != nil {
		t.Errorf("control prefix: %v", err)
	}
}

// On the stand-in: the troublesome characters round-trip through put, head,
// get, both listings and multipart (what is signed is what the store verifies
// and stores); the rewritten names are refused and nothing is stored for them.
func TestStandin_TroublesomeKeys(t *testing.T) {
	s := needStandin(t)
	c := s.client(t)
	p := "tk-" + hex.EncodeToString(randBytes(4)) + "/"
	names := []string{"a b", "a+b", "a%2Fb", "a%b", "~x", "a*b", "it's", "(p)", "a=b&c=d", "q?x", "h#x", "é漢",
		"a,b;c:d@e$f!", "tab\tx", strings.Repeat("l", 200)}
	for _, n := range names {
		k := p + n
		v, err := c.Put(bg, k, []byte(n), map[string]string{"sha256": "x"}, true)
		if err != nil {
			t.Errorf("put %q: %v", n, err)
			continue
		}
		if o, err := c.Head(bg, k, v); err != nil || o.VersionID != v {
			t.Errorf("head %q: %+v %v", n, o, err)
		}
		var buf bytes.Buffer
		if _, err := c.Get(bg, k, v, &buf, 1<<10); err != nil || buf.String() != n {
			t.Errorf("get %q: %q %v", n, buf.String(), err)
		}
		id, err := c.CreateMultipart(bg, k+".m", nil)
		if err != nil {
			t.Errorf("create %q: %v", n, err)
			continue
		}
		e, err := c.UploadPart(bg, k+".m", id, 1, []byte(n))
		if err != nil {
			t.Errorf("part %q: %v", n, err)
		} else if _, err := c.CompleteMultipart(bg, k+".m", id, []string{e}, true); err != nil {
			t.Errorf("complete %q: %v", n, err)
		}
	}
	for _, n := range rewrittenKeys {
		if _, err := c.Put(bg, p+n, []byte(n), nil, true); err == nil {
			t.Errorf("rewritten name %q accepted", n)
		}
	}
	listed := map[string]bool{}
	all := versionsOf(t, c, p)
	for _, o := range all {
		listed[o.Key] = true
	}
	var tok string
	cur := map[string]bool{}
	for i := 0; i < 100; i++ {
		page, next, err := c.List(bg, p, tok)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range page {
			cur[o.Key] = true
		}
		if next == "" {
			break
		}
		tok = next
	}
	for _, n := range names {
		if !listed[p+n] || !cur[p+n] || !listed[p+n+".m"] {
			t.Errorf("%q: in versions %v, in list %v, multipart in versions %v", n, listed[p+n], cur[p+n], listed[p+n+".m"])
		}
	}
	if len(all) != 2*len(names) {
		t.Errorf("%d versions listed, want %d (nothing for refused names)", len(all), 2*len(names))
	}
}
