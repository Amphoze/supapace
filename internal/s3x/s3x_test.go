package s3x

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var bg = context.Background()

func TestSign_KnownVector(t *testing.T) {
	// The worked examples of the S3 signature version 4 documentation.
	const ak, sk = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	const empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	when := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	cred := "AWS4-HMAC-SHA256 Credential=" + ak + "/20130524/us-east-1/s3/aws4_request,"
	cases := []struct {
		name, method, url, payload, signed, sig, wirePath string
		hdr                                               map[string]string
	}{
		{"get-object", "GET", "https://examplebucket.s3.amazonaws.com/test.txt", empty,
			"host;range;x-amz-content-sha256;x-amz-date", "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
			"/test.txt", map[string]string{"Range": "bytes=0-9"}},
		{"put-object", "PUT", "https://examplebucket.s3.amazonaws.com/test$file.text",
			"44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			"date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class", "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
			"/test%24file.text", map[string]string{"Date": "Fri, 24 May 2013 00:00:00 GMT", "X-Amz-Storage-Class": "REDUCED_REDUNDANCY"}},
		{"list-objects", "GET", "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", empty,
			"host;x-amz-content-sha256;x-amz-date", "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
			"/", nil},
		{"get-lifecycle", "GET", "https://examplebucket.s3.amazonaws.com/?lifecycle", empty,
			"host;x-amz-content-sha256;x-amz-date", "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
			"/", nil},
	}
	for _, c := range cases {
		r, err := http.NewRequest(c.method, c.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range c.hdr {
			r.Header.Set(k, v)
		}
		Sign(r, c.payload, ak, sk, "us-east-1", when)
		want := cred + "SignedHeaders=" + c.signed + ",Signature=" + c.sig
		if got := r.Header.Get("Authorization"); got != want {
			t.Errorf("%s: Authorization\n got %s\nwant %s", c.name, got, want)
		}
		if r.Header.Get("X-Amz-Date") != "20130524T000000Z" || r.Header.Get("X-Amz-Content-Sha256") != c.payload {
			t.Errorf("%s: date/payload headers %q %q", c.name, r.Header.Get("X-Amz-Date"), r.Header.Get("X-Amz-Content-Sha256"))
		}
		// What goes on the wire is what was signed.
		if p := r.URL.EscapedPath(); p != c.wirePath {
			t.Errorf("%s: wire path %q, want %q", c.name, p, c.wirePath)
		}
	}
	// Signing again replaces, never accumulates.
	r, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	r.Header.Set("Range", "bytes=0-9")
	Sign(r, empty, ak, sk, "us-east-1", when.Add(time.Hour))
	Sign(r, empty, ak, sk, "us-east-1", when)
	if !strings.HasSuffix(r.Header.Get("Authorization"), "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41") {
		t.Errorf("re-signed: %s", r.Header.Get("Authorization"))
	}
}

func signedHeaders(h http.Header) []string {
	_, s, _ := strings.Cut(h.Get("Authorization"), "SignedHeaders=")
	s, _, _ = strings.Cut(s, ",")
	return strings.Split(s, ";")
}

// checkBodyHeaders asserts Content-MD5 and the signed payload hash of a recorded body.
func checkBodyHeaders(t *testing.T, what string, r recorded) {
	t.Helper()
	m := md5.Sum(r.body)
	s := sha256.Sum256(r.body)
	if r.header.Get("Content-MD5") != base64.StdEncoding.EncodeToString(m[:]) {
		t.Errorf("%s: Content-MD5 %q", what, r.header.Get("Content-MD5"))
	}
	if r.header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(s[:]) {
		t.Errorf("%s: payload hash %q", what, r.header.Get("X-Amz-Content-Sha256"))
	}
	sh := signedHeaders(r.header)
	if !contains(sh, "content-md5") || !contains(sh, "x-amz-content-sha256") {
		t.Errorf("%s: signed headers %v", what, sh)
	}
}

func TestPut_SendsMD5AndPayloadHash(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	for i, body := range [][]byte{bodyOf(1000, 'a'), {}} {
		key := fmt.Sprintf("p/obj%d", i)
		v, err := c.Put(bg, key, body, map[string]string{"sha256": "abc"}, false)
		if err != nil || v == "" {
			t.Fatalf("put %d: %q %v", i, v, err)
		}
		reqs := f.requests()
		r := reqs[len(reqs)-1]
		if r.method != "PUT" || r.path != "/"+testBucket+"/"+key || !bytes.Equal(r.body, body) {
			t.Fatalf("request %s %s %d bytes", r.method, r.path, len(r.body))
		}
		checkBodyHeaders(t, key, r)
		if r.header.Get("X-Amz-Meta-Sha256") != "abc" {
			t.Errorf("meta header %v", r.header)
		}
	}
	// The fake refuses a body whose digest does not match: the headers are checked, not just present.
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(make([]byte, 16)))
		body, _ := io.ReadAll(r.Body)
		if code, name := verify(r, body); code != 0 {
			s3err(w, code, name)
		}
	}
	if _, err := c.Put(bg, "p/x", []byte("data"), nil, false); err == nil {
		t.Error("altered digest accepted by the fake")
	}
}

func TestPut_IfAbsentHeader(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	if _, err := c.Put(bg, "k1", []byte("a"), nil, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(bg, "k2", []byte("a"), nil, false); err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	if got := reqs[0].header.Values("If-None-Match"); len(got) != 1 || got[0] != "*" {
		t.Errorf("ifAbsent: If-None-Match %v", got)
	}
	if !contains(signedHeaders(reqs[0].header), "if-none-match") {
		t.Errorf("If-None-Match not signed: %v", signedHeaders(reqs[0].header))
	}
	if got := reqs[1].header.Values("If-None-Match"); len(got) != 0 {
		t.Errorf("no ifAbsent: If-None-Match %v", got)
	}
}

func TestPut_412IsErrExists(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	v1, err := c.Put(bg, "k", []byte("one"), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Put(bg, "k", []byte("two"), nil, true)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("second conditional put: %v, want ErrExists", err)
	}
	var buf bytes.Buffer
	if o, err := c.Get(bg, "k", "", &buf, 100); err != nil || o.VersionID != v1 || buf.String() != "one" {
		t.Errorf("after refusal: %+v %q %v", o, buf.String(), err)
	}
	// Control: the same put without the condition adds a version.
	if v2, err := c.Put(bg, "k", []byte("two"), nil, false); err != nil || v2 == v1 {
		t.Errorf("unconditional put: %q %v", v2, err)
	}
}

func TestGet_VersionAndMax(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	v1, err := c.Put(bg, "k", bodyOf(10, '1'), map[string]string{"sha256": "h1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := c.Put(bg, "k", bodyOf(20, '2'), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	o, err := c.Get(bg, "k", v1, &buf, 100)
	if err != nil || o.VersionID != v1 || o.Size != 10 || !bytes.Equal(buf.Bytes(), bodyOf(10, '1')) || o.Meta["sha256"] != "h1" || o.Key != "k" {
		t.Fatalf("get v1: %+v %q %v", o, buf.String(), err)
	}
	if got := f.requests()[2].query["versionId"]; len(got) != 1 || got[0] != v1 {
		t.Errorf("versionId sent %v", got)
	}
	buf.Reset()
	if o, err := c.Get(bg, "k", "", &buf, 20); err != nil || o.VersionID != v2 || buf.Len() != 20 {
		t.Errorf("get current at exactly max: %+v %d %v", o, buf.Len(), err)
	}
	buf.Reset()
	if _, err := c.Get(bg, "k", v2, &buf, 19); err == nil || buf.Len() != 0 {
		t.Errorf("over max with a known length: %d bytes written, err %v", buf.Len(), err)
	}
	// A body over max without a length is cut at max, and is an error.
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Version-Id", "vx")
		w.(http.Flusher).Flush()
		w.Write(bodyOf(50, 'z'))
	}
	buf.Reset()
	if _, err := c.Get(bg, "k", "", &buf, 30); err == nil || buf.Len() > 30 {
		t.Errorf("chunked over max: %d bytes, err %v", buf.Len(), err)
	}
	if _, err := c.Get(bg, "k", "", &buf, -1); err == nil {
		t.Error("negative max accepted")
	}
	f.hook = nil
	if _, err := c.Get(bg, "absent", "", &buf, 10); !errors.Is(err, ErrNotFound) {
		t.Errorf("absent: %v", err)
	}
}

func TestHead_ObjectAndNotFound(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	v, err := c.Put(bg, "d/k", bodyOf(7, 'x'), map[string]string{"sha256": "hh"}, false)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.Head(bg, "d/k", v)
	if err != nil || o.Key != "d/k" || o.VersionID != v || o.Size != 7 || o.Meta["sha256"] != "hh" || o.ETag != etagOf(bodyOf(7, 'x')) || o.Modified.IsZero() {
		t.Errorf("head: %+v %v", o, err)
	}
	if _, err := c.Head(bg, "d/none", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("head absent: %v", err)
	}
	if _, err := c.Head(bg, "", ""); err == nil {
		t.Error("empty key accepted")
	}
}

func TestList_Paging(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	want := []string{"p/a", "p/b", "p/c", "p/d", "p/e"}
	for _, k := range append([]string{"q/x"}, want...) {
		if _, err := c.Put(bg, k, []byte(k), nil, false); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	token, pages := "", 0
	for {
		page, next, err := c.List(bg, "p/", token)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, o := range page {
			got = append(got, o.Key)
			if o.Size != 3 || o.ETag == "" || !o.Latest {
				t.Errorf("entry %+v", o)
			}
		}
		if next == "" {
			break
		}
		token = next
	}
	if strings.Join(got, " ") != strings.Join(want, " ") || pages != 3 {
		t.Errorf("listed %v in %d pages", got, pages)
	}
	for _, r := range f.requests()[6:] {
		if r.query["list-type"][0] != "2" || r.query["prefix"][0] != "p/" {
			t.Errorf("list query %v", r.query)
		}
	}
	if r := f.requests()[7]; first(r.query["continuation-token"]) != "p/b" {
		t.Errorf("second page token %v", r.query)
	}
	// A truncated page without a token, or with the token it was asked with, is refused (it would never end).
	for _, body := range []string{
		"<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>p/a</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified></Contents></ListBucketResult>",
		"<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>T</NextContinuationToken></ListBucketResult>",
	} {
		f.hook = func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }
		if _, _, err := c.List(bg, "p/", "T"); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
	// An entry outside the prefix asked for is refused.
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<ListBucketResult><Contents><Key>z/a</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified></Contents></ListBucketResult>")
	}
	if _, _, err := c.List(bg, "p/", ""); err == nil {
		t.Error("key outside the prefix accepted")
	}
}

func TestListVersions_OrderAndMarkers(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	for _, k := range []string{"l/a", "l/b", "l/a", "m/z", "l/a", "l/c", "l/b"} {
		if _, err := c.Put(bg, k, []byte(k), nil, false); err != nil {
			t.Fatal(err)
		}
	}
	f.addMarker("l/c")
	var want []fakeVersion
	for _, v := range f.versions {
		if strings.HasPrefix(v.key, "l/") {
			want = append(want, v)
		}
	}
	var got []Object
	km, vm := "", ""
	for i := 0; ; i++ {
		page, nk, nv, err := c.ListVersions(bg, "l/", km, vm)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, page...)
		r := f.requests()[len(f.requests())-1]
		if !r.query.Has("versions") || first(r.query["key-marker"]) != km || first(r.query["version-id-marker"]) != vm {
			t.Errorf("page %d query %v", i, r.query)
		}
		if nk == "" {
			break
		}
		km, vm = nk, nv
	}
	if len(got) != len(want) {
		t.Fatalf("listed %d versions, want %d", len(got), len(want))
	}
	for i := range want {
		w, g := want[i], got[i]
		latest := f.versions[indexOfKey(f.versions, w.key)].id == w.id
		if g.Key != w.key || g.VersionID != w.id || g.DeleteMarker != w.marker || g.Latest != latest || !g.Modified.Equal(w.mod) {
			t.Errorf("entry %d: %+v, want %s %s marker=%t latest=%t", i, g, w.key, w.id, w.marker, latest)
		}
	}
	// The fake gives newer versions earlier times: the store's order is kept, not the times'.
	if !got[0].Modified.Before(got[1].Modified) {
		t.Fatalf("fixture: times do not contradict the order")
	}
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<ListVersionsResult><IsTruncated>true</IsTruncated></ListVersionsResult>")
	}
	if _, _, _, err := c.ListVersions(bg, "l/", "", ""); err == nil {
		t.Error("truncated page without markers accepted")
	}
}

func TestMultipart_ThreeCalls(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	id, err := c.CreateMultipart(bg, "big", map[string]string{"sha256": "whole"})
	if err != nil || id == "" {
		t.Fatalf("create: %q %v", id, err)
	}
	p1, p2 := bodyOf(5<<20, 'a'), bodyOf(1<<20, 'b')
	e1, err := c.UploadPart(bg, "big", id, 1, p1)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := c.UploadPart(bg, "big", id, 2, p2)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.CompleteMultipart(bg, "big", id, []string{e1, e2}, false)
	if err != nil || v == "" {
		t.Fatalf("complete: %q %v", v, err)
	}
	reqs := f.requests()
	if len(reqs) != 4 {
		t.Fatalf("%d requests", len(reqs))
	}
	if r := reqs[0]; r.method != "POST" || !r.query.Has("uploads") || r.header.Get("X-Amz-Meta-Sha256") != "whole" || r.header.Get("If-None-Match") != "" {
		t.Errorf("create request %s %v %v", r.method, r.query, r.header)
	}
	for i, r := range reqs[1:3] {
		if r.method != "PUT" || first(r.query["partNumber"]) != fmt.Sprint(i+1) || first(r.query["uploadId"]) != id {
			t.Errorf("part request %s %v", r.method, r.query)
		}
		checkBodyHeaders(t, "part", r)
	}
	if r := reqs[3]; r.method != "POST" || first(r.query["uploadId"]) != id || !bytes.Contains(r.body, []byte("<PartNumber>2</PartNumber>")) {
		t.Errorf("complete request %s %v %s", r.method, r.query, r.body)
	}
	checkBodyHeaders(t, "complete", reqs[3])
	var buf bytes.Buffer
	if o, err := c.Get(bg, "big", v, &buf, 6<<20); err != nil || !bytes.Equal(buf.Bytes(), append(p1, p2...)) || o.Meta["sha256"] != "whole" {
		t.Errorf("read back: %d bytes %v", buf.Len(), err)
	}
	// Refusals made before any request.
	n := len(f.requests())
	for _, err := range []error{
		func() error { _, err := c.UploadPart(bg, "big", id, 0, p2); return err }(),
		func() error { _, err := c.UploadPart(bg, "big", id, 10001, p2); return err }(),
		func() error { _, err := c.UploadPart(bg, "big", "", 1, p2); return err }(),
		func() error { _, err := c.CompleteMultipart(bg, "big", id, nil, false); return err }(),
		func() error { _, err := c.CompleteMultipart(bg, "big", "", []string{e1}, false); return err }(),
		func() error { _, err := c.CompleteMultipart(bg, "big", id, []string{e1, ""}, false); return err }(),
	} {
		if err == nil {
			t.Error("bad argument accepted")
		}
	}
	if len(f.requests()) != n {
		t.Error("a refused call sent a request")
	}
}

func TestComplete_IfAbsent(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	open := func() (string, string) {
		id, err := c.CreateMultipart(bg, "m", nil)
		if err != nil {
			t.Fatal(err)
		}
		e, err := c.UploadPart(bg, "m", id, 1, []byte("part"))
		if err != nil {
			t.Fatal(err)
		}
		return id, e
	}
	id1, e1 := open()
	id2, e2 := open()
	v1, err := c.CompleteMultipart(bg, "m", id1, []string{e1}, true)
	if err != nil {
		t.Fatal(err)
	}
	if r := f.requests()[len(f.requests())-1]; r.header.Get("If-None-Match") != "*" {
		t.Errorf("completion header %v", r.header)
	}
	if _, err := c.CompleteMultipart(bg, "m", id2, []string{e2}, true); !errors.Is(err, ErrExists) {
		t.Fatalf("second completion: %v, want ErrExists", err)
	}
	if o, err := c.Head(bg, "m", ""); err != nil || o.VersionID != v1 {
		t.Errorf("after refusal: %+v %v", o, err)
	}
	// Control: without the condition the completion adds a version.
	id3, e3 := open()
	if v, err := c.CompleteMultipart(bg, "m", id3, []string{e3}, false); err != nil || v == v1 {
		t.Errorf("unconditional completion: %q %v", v, err)
	}
	if r := f.requests()[len(f.requests())-1]; r.header.Get("If-None-Match") != "" {
		t.Errorf("unconditional completion header %v", r.header)
	}
}

func TestComplete_ErrorIn200Refused(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Version-Id", "v")
		io.WriteString(w, "<Error><Code>PreconditionFailed</Code></Error>")
	}
	if _, err := c.CompleteMultipart(bg, "m", "u", []string{`"e"`}, true); !errors.Is(err, ErrExists) {
		t.Errorf("error document in a 200: %v", err)
	}
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amz-Version-Id", "v")
		io.WriteString(w, "<Error><Code>InternalError</Code></Error>")
	}
	if _, err := c.CompleteMultipart(bg, "m", "u", []string{`"e"`}, true); err == nil {
		t.Error("error document in a 200 accepted")
	}
	f.hook = func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "<Other><Key>m</Key></Other>") }
	if _, err := c.CompleteMultipart(bg, "m", "u", []string{`"e"`}, true); err == nil {
		t.Error("a completion answered with another document accepted")
	}
}

func TestAbortMultipart_NeedsAnUploadID(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	id, err := c.CreateMultipart(bg, "m", nil)
	if err != nil {
		t.Fatal(err)
	}
	n := len(f.requests())
	if err := c.AbortMultipart(bg, "m", ""); err == nil {
		t.Fatal("empty upload id accepted")
	}
	if len(f.requests()) != n {
		t.Fatal("a request was sent without an upload id")
	}
	if err := c.AbortMultipart(bg, "m", id); err != nil {
		t.Fatal(err)
	}
	r := f.requests()[n]
	if r.method != "DELETE" || first(r.query["uploadId"]) != id || r.path != "/"+testBucket+"/m" {
		t.Errorf("abort request %s %s %v", r.method, r.path, r.query)
	}
	if len(f.uploads) != 0 {
		t.Errorf("upload still open")
	}
}

func TestErrors_Mapped(t *testing.T) {
	f := newFake(t)
	cfg := f.config()
	cfg.SecretKey = "wrong"
	bad, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Put(bg, "k", []byte("x"), nil, false); !errors.Is(err, ErrDenied) {
		t.Errorf("wrong secret: %v", err)
	}
	c := f.client(t)
	for _, tc := range []struct {
		status int
		code   string
		want   error
	}{{403, "AccessDenied", ErrDenied}, {404, "NoSuchKey", ErrNotFound}, {412, "PreconditionFailed", ErrExists},
		{400, "BadDigest", ErrChecksum}, {400, "XAmzContentSHA256Mismatch", ErrChecksum}, {500, "InternalError", nil}, {409, "x", nil}} {
		f.hook = func(w http.ResponseWriter, r *http.Request) { s3err(w, tc.status, tc.code) }
		_, err := c.Put(bg, "k", []byte("x"), nil, false)
		if err == nil {
			t.Errorf("%d %s: no error", tc.status, tc.code)
			continue
		}
		for _, s := range []error{ErrDenied, ErrNotFound, ErrExists, ErrChecksum} {
			if errors.Is(err, s) != (s == tc.want) {
				t.Errorf("%d %s: %v", tc.status, tc.code, err)
			}
		}
	}
	// A server-chosen error code reaches the message only as plain characters.
	f.hook = func(w http.ResponseWriter, r *http.Request) { s3err(w, 500, "Bad\x1b[31mCode") }
	if _, err := c.Put(bg, "k", []byte("x"), nil, false); err == nil || strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("escape in error: %q", err)
	}
}

func TestNew_RefusesBadConfig(t *testing.T) {
	f := newFake(t)
	for name, mod := range map[string]func(*Config){
		"plain http":     func(c *Config) { c.Endpoint = "http://" + testName },
		"path":           func(c *Config) { c.Endpoint = "https://" + testName + "/x" },
		"query":          func(c *Config) { c.Endpoint = "https://" + testName + "?a=b" },
		"user":           func(c *Config) { c.Endpoint = "https://u:p@" + testName },
		"no host":        func(c *Config) { c.Endpoint = "https://" },
		"bucket":         func(c *Config) { c.Bucket = "" },
		"bucket slash":   func(c *Config) { c.Bucket = "a/b" },
		"region":         func(c *Config) { c.Region = "" },
		"access":         func(c *Config) { c.AccessKey = "" },
		"secret":         func(c *Config) { c.SecretKey = "" },
		"timeout":        func(c *Config) { c.Timeout = 0 },
		"ca":             func(c *Config) { c.CAPEM = "not a certificate" },
		"addr port zero": func(c *Config) { c.Addrs = []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")} },
		"addr invalid":   func(c *Config) { c.Addrs = []netip.AddrPort{{}} },
	} {
		cfg := f.config()
		mod(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(f.config()); err != nil {
		t.Errorf("control: %v", err)
	}
}

func TestPathStyleOff_UsesBucketHost(t *testing.T) {
	f := newFakeWith(t, newCA(t, []string{testBucket + "." + testName}, nil), 0)
	var host, path string
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		host, path = r.Host, r.URL.Path
		if code, name := verify(r, nil); code != 0 {
			s3err(w, code, name)
			return
		}
		w.Header().Set("Content-Length", "0")
	}
	cfg := f.config()
	cfg.PathStyle = false
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Head(bg, "a/b", ""); err != nil {
		t.Fatal(err)
	}
	if host != testBucket+"."+testName+":9443" || path != "/a/b" {
		t.Errorf("host %q path %q", host, path)
	}
}

// ---- hostile server ----

func TestResponse_HugeHeaderRefused(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	size := 0
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Big", strings.Repeat("a", size))
		w.Header().Set("Content-Length", "0")
	}
	size = 1 << 10 // control
	if _, err := c.Head(bg, "k", ""); err != nil {
		t.Fatalf("control: %v", err)
	}
	size = 100 << 10
	if _, err := c.Head(bg, "k", ""); err == nil {
		t.Error("100 KiB of headers accepted")
	}
}

// endless writes until the client goes away (at most 1 GiB).
func endless(w http.ResponseWriter) {
	chunk := bodyOf(64<<10, '<')
	for i := 0; i < 1<<14; i++ {
		if _, err := w.Write(chunk); err != nil {
			return
		}
	}
}

func TestResponse_EndlessBodyBounded(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	var buf bytes.Buffer
	f.hook = func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Amz-Version-Id", "v1"); endless(w) }
	if _, err := c.Get(bg, "k", "", &buf, 1<<20); err == nil || buf.Len() > 1<<20 {
		t.Errorf("get: %d bytes, %v", buf.Len(), err)
	}
	// A success response body nobody needs is not read to its end.
	if _, err := c.Put(bg, "k", []byte("x"), nil, false); err != nil {
		t.Errorf("put with an endless success body: %v", err)
	}
	f.hook = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500); endless(w) }
	if _, err := c.Put(bg, "k", []byte("x"), nil, false); err == nil {
		t.Error("put: endless error body gave no error")
	}
	f.hook = func(w http.ResponseWriter, r *http.Request) { endless(w) }
	if _, err := c.CreateMultipart(bg, "k", nil); err == nil {
		t.Error("create: endless document accepted")
	}
	if _, err := c.CompleteMultipart(bg, "k", "u", []string{`"e"`}, false); err == nil {
		t.Error("complete: endless document accepted")
	}
}

func TestResponse_StalledServerTimesOut(t *testing.T) {
	// A TCP server that accepts and never answers, a TLS server that never answers a
	// request, and one that sends the headers and then stalls in the body.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	f := newFake(t)
	f.hook = func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	g := newFakeWith(t, f.ca, 0)
	g.hook = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.Write([]byte("abc"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}
	for name, addr := range map[string]netip.AddrPort{"accepts only": netip.MustParseAddrPort(l.Addr().String()), "no answer": f.addr(),
		"body stalls": g.addr()} {
		cfg := f.config()
		cfg.Addrs = []netip.AddrPort{addr}
		cfg.Timeout = 300 * time.Millisecond
		c, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, err = c.Get(bg, "k", "", io.Discard, 100)
		var ne net.Error
		if err == nil || !(errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded)) {
			t.Errorf("%s: %v, want a timeout", name, err)
		}
		if d := time.Since(start); d > 30*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
}

func TestResponse_RedirectNotFollowed(t *testing.T) {
	a := newFake(t)
	b := newFakeWith(t, a.ca, 0)
	cfg := a.config()
	cfg.Addrs = nil
	cfg.Endpoint = "https://" + a.addr().String()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.hook = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+b.addr().String()+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}
	var buf bytes.Buffer
	if _, err := c.Get(bg, "k", "", &buf, 10); err == nil {
		t.Error("redirect gave no error")
	}
	if len(b.requests()) != 0 {
		t.Errorf("redirect followed: %d requests at the target", len(b.requests()))
	}
	// Control: the target is reachable by the same client configuration.
	cfg.Endpoint = "https://" + b.addr().String()
	cb, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cb.Head(bg, "k", ""); !errors.Is(err, ErrNotFound) || len(b.requests()) != 1 {
		t.Errorf("control: %v, %d requests", err, len(b.requests()))
	}
}

func bigList(root, entry string, n int) string {
	return "<" + root + ">" + strings.Repeat(entry, n) + "</" + root + ">"
}

func TestList_OversizedPageRefused(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	const obj = "<Contents><Key>p/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>1</Size></Contents>"
	const ver = "<Version><Key>p/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</Key><VersionId>v</VersionId><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>1</Size></Version>"
	under, over := (4<<20)/len(ver)-1, (4<<20)/len(obj)+1
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("versions") {
			io.WriteString(w, bigList("ListVersionsResult", ver, over))
		} else {
			io.WriteString(w, bigList("ListBucketResult", obj, over))
		}
	}
	if _, _, err := c.List(bg, "p/", ""); err == nil {
		t.Error("list: page over 4 MiB accepted")
	}
	if _, _, _, err := c.ListVersions(bg, "p/", "", ""); err == nil {
		t.Error("versions: page over 4 MiB accepted")
	}
	// A small page followed by more than the bound of padding is refused too.
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<ListBucketResult></ListBucketResult>"+strings.Repeat(" ", 5<<20))
	}
	if _, _, err := c.List(bg, "p/", ""); err == nil {
		t.Error("list: padded page over 4 MiB accepted")
	}
	// Control: the same pages just under the bound.
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("versions") {
			io.WriteString(w, bigList("ListVersionsResult", ver, under))
		} else {
			io.WriteString(w, bigList("ListBucketResult", obj, (4<<20)/len(obj)-1))
		}
	}
	if p, _, err := c.List(bg, "p/", ""); err != nil || len(p) != (4<<20)/len(obj)-1 {
		t.Errorf("list control: %d %v", len(p), err)
	}
	if p, _, _, err := c.ListVersions(bg, "p/", "", ""); err != nil || len(p) != under {
		t.Errorf("versions control: %d %v", len(p), err)
	}
}

func TestTLS_WrongNameRefused(t *testing.T) {
	f := newFakeWith(t, newCA(t, []string{"other.sp.test"}, nil), 0)
	if _, err := f.client(t).Head(bg, "k", ""); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("wrong name: %v", err)
	}
	cfg := f.config()
	cfg.Endpoint = "https://other.sp.test:9443"
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Head(bg, "k", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("control (right name): %v", err)
	}
	cfg.CAPEM = "" // the system's roots do not know the test CA
	c, _ = New(cfg)
	if _, err := c.Head(bg, "k", ""); err == nil {
		t.Error("unknown CA accepted")
	}
}

// decoy accepts and closes connections, counting them.
func decoy(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var n atomic.Int32
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			conn.Close()
		}
	}()
	return l.Addr().String(), &n
}

func TestDial_OnlyGivenAddrs(t *testing.T) {
	f := newFakeWith(t, newCA(t, []string{"localhost"}, nil), 0)
	addr, hits := decoy(t)
	_, port, _ := net.SplitHostPort(addr)
	cfg := f.config()
	cfg.Endpoint = "https://localhost:" + port // resolves to the decoy
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Head(bg, "k", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("by address: %v", err)
	}
	if hits.Load() != 0 || len(f.requests()) != 1 {
		t.Errorf("decoy hits %d, fake requests %d", hits.Load(), len(f.requests()))
	}
	// Control: without Addrs the name is resolved, and the decoy is reached.
	cfg.Addrs = nil
	c, _ = New(cfg)
	if _, err := c.Head(bg, "k", ""); err == nil || hits.Load() == 0 {
		t.Errorf("control: %v, decoy hits %d", err, hits.Load())
	}
}

func TestDial_TriesEveryAddrBeforeFailing(t *testing.T) {
	f := newFake(t)
	closed := func() netip.AddrPort {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		a := netip.MustParseAddrPort(l.Addr().String())
		l.Close()
		return a
	}
	d1, d2 := closed(), closed()
	cfg := f.config()
	cfg.Addrs = []netip.AddrPort{d1, d2, f.addr()}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Head(bg, "k", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("third address: %v", err)
	}
	cfg.Addrs = []netip.AddrPort{d1, d2}
	c, _ = New(cfg)
	_, err = c.Head(bg, "k", "")
	if err == nil || !strings.Contains(err.Error(), d1.String()) || !strings.Contains(err.Error(), d2.String()) {
		t.Errorf("all closed: %v", err)
	}
}

func TestNoObjectDeleteInPackage(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	var found []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fn, _ := d.(*ast.FuncDecl)
			where := "package level"
			if fn != nil {
				where = fn.Name.Name
			}
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					if x.Kind == token.STRING && strings.EqualFold(strings.Trim(x.Value, "`\""), "DELETE") {
						found = append(found, where+": "+x.Value)
					}
				case *ast.SelectorExpr:
					if x.Sel.Name == "MethodDelete" {
						found = append(found, where+": http.MethodDelete")
					}
				}
				return true
			})
		}
	}
	if len(found) != 1 || !strings.HasPrefix(found[0], "AbortMultipart: ") {
		t.Errorf("delete-method references: %v; want exactly one, in AbortMultipart", found)
	}
}

func TestTLS_OldVersionRefused(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	if _, err := c.Head(bg, "k", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("control (TLS 1.3): %v", err)
	}
	old := newFakeWith(t, f.ca, tls.VersionTLS11)
	if _, err := old.client(t).Head(bg, "k", ""); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("TLS 1.1 server accepted: %v", err)
	}
}

// ---- HTTPClient: a caller's own signed request under the client's rules ----

func signedHead(t *testing.T, url string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	Sign(r, emptySHA, testAK, testSK, testRegion, time.Now())
	return r
}

func TestHTTPClient_NoLookupWithAddrs(t *testing.T) {
	var queries atomic.Int32
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		queries.Add(1)
		return nil, errors.New("no resolver in this test")
	}}
	defer func() { net.DefaultResolver = old }()
	f := newFake(t)
	resp, err := f.client(t).HTTPClient().Do(signedHead(t, "https://"+testName+":9443/"+testBucket+"/k"))
	if err != nil || resp.StatusCode != 404 {
		t.Fatalf("by address: %v %v", resp, err)
	}
	resp.Body.Close()
	if n := queries.Load(); n != 0 {
		t.Errorf("%d lookups with addresses given", n)
	}
	cfg := f.config()
	cfg.Addrs = nil
	c, _ := New(cfg)
	if _, err := c.HTTPClient().Do(signedHead(t, "https://"+testName+":9443/"+testBucket+"/k")); err == nil || queries.Load() == 0 {
		t.Errorf("control without addresses: %v, %d lookups", err, queries.Load())
	}
}

func TestHTTPClient_RedirectNotFollowed(t *testing.T) {
	a := newFake(t)
	b := newFakeWith(t, a.ca, 0)
	cfg := a.config()
	cfg.Addrs = nil
	cfg.Endpoint = "https://" + a.addr().String()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.hook = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+b.addr().String()+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}
	resp, err := c.HTTPClient().Do(signedHead(t, "https://"+a.addr().String()+"/"+testBucket+"/k"))
	if err != nil || resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect answer: %v %v", resp, err)
	}
	resp.Body.Close()
	if n := len(b.requests()); n != 0 {
		t.Errorf("redirect followed: %d requests at the target", n)
	}
}

// The proxy environment is read once per process: the check runs in a child.
func TestHTTPClient_ProxyEnvironmentIgnored(t *testing.T) {
	if os.Getenv("S3X_HTTPCLIENT_PROXY_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHTTPClient_ProxyEnvironmentIgnored$", "-test.count=1")
		cmd.Env = append(os.Environ(), "S3X_HTTPCLIENT_PROXY_CHILD=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		return
	}
	addr, hits := decoy(t)
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		os.Setenv(k, "http://"+addr)
	}
	os.Setenv("NO_PROXY", "")
	os.Setenv("no_proxy", "")
	f := newFake(t)
	cfg := f.config()
	cfg.Addrs = nil
	cfg.Endpoint = "https://" + f.addr().String()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.HTTPClient().Do(signedHead(t, "https://"+f.addr().String()+"/"+testBucket+"/k"))
	if err != nil {
		t.Fatalf("direct request with a proxy in the environment: %v", err)
	}
	resp.Body.Close()
	if n := hits.Load(); n != 0 {
		t.Errorf("the proxy was contacted %d times", n)
	}
}

// ---- answers the store must not be able to pass off ----

func TestListVersions_SameMarkersRefused(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	f.hook = func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>p/a</NextKeyMarker>"+
			"<NextVersionIdMarker>v1</NextVersionIdMarker></ListVersionsResult>")
	}
	if _, _, _, err := c.ListVersions(bg, "p/", "p/a", "v1"); err == nil {
		t.Error("the markers asked with, handed back, accepted")
	}
	if _, nk, nv, err := c.ListVersions(bg, "p/", "p/a", "v2"); err != nil || nk != "p/a" || nv != "v1" {
		t.Errorf("control (new markers): %q %q %v", nk, nv, err)
	}
}

func TestUploadPart_NoETagRefused(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	f.hook = func(w http.ResponseWriter, r *http.Request) {}
	if e, err := c.UploadPart(bg, "m", "u", 1, []byte("x")); err == nil {
		t.Errorf("part answered without an ETag: accepted as %q", e)
	}
	f.hook = func(w http.ResponseWriter, r *http.Request) { w.Header().Set("ETag", `"e"`) }
	if e, err := c.UploadPart(bg, "m", "u", 1, []byte("x")); err != nil || e != `"e"` {
		t.Errorf("control: %q %v", e, err)
	}
}

func TestResponse_RedirectIsNoSuccess(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	for _, st := range []int{301, 302, 304, 307} {
		f.hook = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Amz-Version-Id", "v1")
			w.Header().Set("ETag", `"e"`)
			w.WriteHeader(st)
		}
		if _, err := c.Put(bg, "k", []byte("x"), nil, false); err == nil {
			t.Errorf("put answered %d: success", st)
		}
		if _, err := c.Head(bg, "k", ""); err == nil {
			t.Errorf("head answered %d: success", st)
		}
		if err := c.AbortMultipart(bg, "k", "u"); err == nil {
			t.Errorf("abort answered %d: success", st)
		}
	}
}

// A document over the bound is refused as soon as the bound is read: the
// client does not wait for the rest (the server here never ends it).
func TestResponse_DocumentReadStopsAtBound(t *testing.T) {
	f := newFake(t)
	cfg := f.config()
	cfg.Timeout = 20 * time.Second
	c, _ := New(cfg)
	for name, hook := range map[string]func(w http.ResponseWriter, r *http.Request){
		"document": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<ListBucketResult>"+strings.Repeat(" ", maxXML+64<<10))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		},
		"error document": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			io.WriteString(w, "<Error><Code>X</Code></Error>"+strings.Repeat(" ", maxErrDoc+64<<10))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		},
	} {
		f.hook = hook
		start := time.Now()
		_, _, err := c.List(bg, "p/", "")
		var ne net.Error
		if err == nil || errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: %v, want a refusal before the timeout", name, err)
		}
		if d := time.Since(start); d > 15*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
}

func TestNew_CopiesAddrs(t *testing.T) {
	f := newFake(t)
	cfg := f.config()
	addrs := []netip.AddrPort{f.addr()}
	cfg.Addrs = addrs
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	addrs[0] = netip.MustParseAddrPort("127.0.0.1:1") // the caller's slice changes afterwards
	if _, err := c.Head(bg, "k", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("after the caller changed its slice: %v", err)
	}
}

func TestSign_CanonicalEncodingByHand(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://"+testName+"/", nil)
	r.URL.Path = "/b/a+b c$~é/x"
	r.URL.RawQuery = "z=1&a=x+y&prefix=p%2Fq"
	Sign(r, emptySHA, testAK, testSK, testRegion, time.Now())
	if got, want := r.URL.EscapedPath(), "/b/a%2Bb%20c%24~%C3%A9/x"; got != want {
		t.Errorf("path %q, want %q", got, want)
	}
	if got, want := r.URL.RawQuery, "a=x%20y&prefix=p%2Fq&z=1"; got != want {
		t.Errorf("query %q, want %q", got, want)
	}
}

func TestKey_LengthBound(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	if _, err := c.Put(bg, "p/"+strings.Repeat("k", 1022), []byte("x"), nil, false); err != nil {
		t.Errorf("1024-byte key: %v", err)
	}
	n := len(f.requests())
	if _, err := c.Put(bg, "p/"+strings.Repeat("k", 1023), []byte("x"), nil, false); err == nil || len(f.requests()) != n {
		t.Errorf("1025-byte key: %v, %d requests", err, len(f.requests())-n)
	}
	if _, _, err := c.List(bg, strings.Repeat("p", 1025), ""); err == nil {
		t.Error("1025-byte prefix accepted")
	}
	for _, p := range []string{"", "p/", "p", "p/q/", "p/q"} {
		if _, _, err := c.List(bg, p, ""); err != nil {
			t.Errorf("prefix %q: %v", p, err)
		}
	}
	for _, p := range []string{"/", "/p", "p//", "./", "p/../"} {
		if _, _, err := c.List(bg, p, ""); err == nil {
			t.Errorf("prefix %q accepted", p)
		}
	}
}
