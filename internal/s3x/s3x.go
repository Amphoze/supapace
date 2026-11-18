// Package s3x is a minimal client of an S3-compatible object store: signature
// version 4, one bucket per client, and only the calls the off-site copy needs.
//
// No call deletes an object or a version. The one request with the DELETE
// method is AbortMultipart's, which needs the id of an upload: it discards the
// parts of an upload that was never completed and can touch nothing that ever
// was a version.
//
// The store is not trusted to behave: TLS 1.2 or later only, no proxy, no
// redirect followed, response headers at most 64 KiB, an XML document at most
// 4 MiB, an object body at most what the caller allows, and every call ends
// within Config.Timeout. With Config.Addrs set the endpoint's name is never
// resolved: each connection is tried to those addresses, in order, and the name
// serves only as the TLS server name and the Host header. Every request body is
// sent with Content-MD5 and its signed SHA-256 (a server refuses a wrong digest
// but need not require one, so the rule is the client's).
package s3x

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Config names one bucket of one endpoint and how to reach it.
type Config struct {
	Endpoint, Region, Bucket    string // Endpoint: https://name[:port], nothing more
	PathStyle                   bool   // /bucket/key on the endpoint; else bucket.name/key
	AccessKey, SecretKey, CAPEM string // CAPEM empty: the system's roots
	Addrs                       []netip.AddrPort
	Timeout                     time.Duration // the bound of each call, from dial to the last byte read
}

// Object is one object or version, as a response describes it. Modified has
// whole seconds on some stores and is never an order: a listing's order is.
type Object struct {
	Key, VersionID, ETag string
	Size                 int64
	Modified             time.Time
	Meta                 map[string]string // x-amz-meta-*, names lower case without the prefix
	DeleteMarker, Latest bool
}

// Client is safe for concurrent use.
type Client struct {
	c    Config
	host string // the endpoint's host[:port] as given
	hc   *http.Client
}

var (
	ErrExists   = errors.New("s3x: precondition failed: the key exists") // 412
	ErrNotFound = errors.New("s3x: not found")                           // 404
	ErrDenied   = errors.New("s3x: access denied")                       // 403
	ErrChecksum = errors.New("s3x: body digest refused")                 // 400 BadDigest or XAmzContentSHA256Mismatch
)

const (
	maxHeader = 64 << 10
	maxXML    = 4 << 20
	maxErrDoc = 64 << 10
	emptySHA  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// New checks c and builds a client. Nothing is sent.
func New(c Config) (*Client, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, fmt.Errorf("s3x: endpoint must be https://name[:port]")
	}
	if !validBucket(c.Bucket) {
		return nil, fmt.Errorf("s3x: invalid bucket name %q", c.Bucket)
	}
	if c.Region == "" || c.AccessKey == "" || c.SecretKey == "" {
		return nil, errors.New("s3x: region, access key and secret key are required")
	}
	if c.Timeout <= 0 {
		return nil, errors.New("s3x: timeout must be positive")
	}
	for _, a := range c.Addrs {
		if !a.IsValid() || a.Port() == 0 {
			return nil, fmt.Errorf("s3x: invalid address %v", a)
		}
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAPEM != "" {
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return nil, errors.New("s3x: no certificate in the CA bundle")
		}
	}
	d := &net.Dialer{Timeout: c.Timeout}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		TLSClientConfig:        tc,
		TLSHandshakeTimeout:    c.Timeout,
		ResponseHeaderTimeout:  c.Timeout,
		MaxResponseHeaderBytes: maxHeader,
		DisableCompression:     true, // the bytes returned are the bytes stored
	}
	if addrs := append([]netip.AddrPort(nil), c.Addrs...); len(addrs) > 0 {
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var errs []error
			for _, a := range addrs {
				conn, err := d.DialContext(ctx, "tcp", a.String())
				if err == nil {
					return conn, nil
				}
				errs = append(errs, err)
			}
			return nil, errors.Join(errs...)
		}
	}
	hc := &http.Client{Transport: tr, Timeout: c.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{c: c, host: u.Host, hc: hc}, nil
}

func validBucket(b string) bool {
	if len(b) < 3 || len(b) > 63 {
		return false
	}
	for _, r := range b {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// do sends one signed request; a response that is not 2xx is closed and
// returned as an error. The caller closes a returned response's body.
func (c *Client) do(ctx context.Context, method, key string, q url.Values, hdr map[string]string, body []byte) (*http.Response, error) {
	if key != "" || method != http.MethodGet {
		if err := checkName(key, false); err != nil {
			return nil, err
		}
	}
	host, path := c.host, "/"+c.c.Bucket+"/"+key
	if !c.c.PathStyle {
		host, path = c.c.Bucket+"."+c.host, "/"+key
	}
	if key == "" && c.c.PathStyle {
		path = "/" + c.c.Bucket
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r, err := http.NewRequestWithContext(ctx, method, "https://"+host+"/", rd)
	if err != nil {
		return nil, err
	}
	r.URL.Path, r.URL.RawQuery = path, q.Encode()
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	payload := emptySHA
	if body != nil {
		r.ContentLength = int64(len(body))
		m := md5.Sum(body)
		s := sha256.Sum256(body)
		r.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(m[:]))
		payload = hex.EncodeToString(s[:])
	}
	Sign(r, payload, c.c.AccessKey, c.c.SecretKey, c.c.Region, time.Now())
	resp, err := c.hc.Do(r)
	if err != nil {
		return nil, fmt.Errorf("s3x: %s %q: %w", method, key, err)
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		doc, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrDoc))
		return nil, statusErr(method, key, resp.StatusCode, errorCode(doc))
	}
	return resp, nil
}

func errorCode(doc []byte) string {
	var e struct {
		XMLName xml.Name
		Code    string
	}
	if xml.Unmarshal(doc, &e) != nil || elem(e.XMLName) != "Error" {
		return ""
	}
	return e.Code
}

// statusErr maps a refusal to its sentinel; the server's code is kept only
// as letters and digits.
func statusErr(method, key string, status int, code string) error {
	code = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' {
			return r
		}
		return -1
	}, code)
	if len(code) > 64 {
		code = code[:64]
	}
	var base error
	switch {
	case status == http.StatusPreconditionFailed:
		base = ErrExists
	case status == http.StatusNotFound:
		base = ErrNotFound
	case status == http.StatusForbidden:
		base = ErrDenied
	case status == http.StatusBadRequest && (code == "BadDigest" || code == "XAmzContentSHA256Mismatch"):
		base = ErrChecksum
	default:
		return fmt.Errorf("s3x: %s %q: HTTP %d %s", method, key, status, code)
	}
	return fmt.Errorf("%w (%s %q: HTTP %d %s)", base, method, key, status, code)
}

// readXML decodes a document of at most maxXML bytes; an Error document is
// a refusal even under a 2xx status (a completion may answer so).
func readXML(resp *http.Response, method, key string, v any) error {
	defer resp.Body.Close()
	doc, err := io.ReadAll(io.LimitReader(resp.Body, maxXML+1))
	if err != nil {
		return fmt.Errorf("s3x: %s %q: %w", method, key, err)
	}
	if len(doc) > maxXML {
		return fmt.Errorf("s3x: %s %q: document over %d bytes", method, key, maxXML)
	}
	if code := errorCode(doc); code != "" {
		status := resp.StatusCode
		if code == "PreconditionFailed" {
			status = http.StatusPreconditionFailed
		}
		return statusErr(method, key, status, code)
	}
	if err := xml.Unmarshal(doc, v); err != nil {
		return fmt.Errorf("s3x: %s %q: %w", method, key, err)
	}
	return nil
}

func metaHeaders(meta map[string]string, ifAbsent bool) map[string]string {
	h := map[string]string{}
	for k, v := range meta {
		h["X-Amz-Meta-"+k] = v
	}
	if ifAbsent {
		h["If-None-Match"] = "*"
	}
	return h
}

func objectOf(key string, resp *http.Response) Object {
	h := resp.Header
	o := Object{Key: key, VersionID: h.Get("X-Amz-Version-Id"), ETag: h.Get("ETag"), Size: resp.ContentLength,
		DeleteMarker: h.Get("X-Amz-Delete-Marker") == "true", Meta: map[string]string{}}
	o.Modified, _ = http.ParseTime(h.Get("Last-Modified"))
	for k, v := range h {
		if n, ok := strings.CutPrefix(strings.ToLower(k), "x-amz-meta-"); ok && len(v) > 0 {
			o.Meta[n] = v[0]
		}
	}
	return o
}

func versionQuery(versionID string) url.Values {
	q := url.Values{}
	if versionID != "" {
		q.Set("versionId", versionID)
	}
	return q
}

// Put stores body under key in one request; ifAbsent makes it a conditional
// create (If-None-Match: *), refused with ErrExists when the key exists.
func (c *Client) Put(ctx context.Context, key string, body []byte, meta map[string]string, ifAbsent bool) (versionID string, err error) {
	if body == nil {
		body = []byte{}
	}
	resp, err := c.do(ctx, http.MethodPut, key, nil, metaHeaders(meta, ifAbsent), body)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	return versionOf(resp, key)
}

// Head describes key, or one version of it.
func (c *Client) Head(ctx context.Context, key, versionID string) (Object, error) {
	if key == "" {
		return Object{}, errors.New("s3x: empty key")
	}
	resp, err := c.do(ctx, http.MethodHead, key, versionQuery(versionID), nil, nil)
	if err != nil {
		return Object{}, err
	}
	resp.Body.Close()
	return objectOf(key, resp), nil
}

// Get writes key, or one version of it, to w. A body over max bytes is cut at
// max and is an error.
func (c *Client) Get(ctx context.Context, key, versionID string, w io.Writer, max int64) (Object, error) {
	if key == "" || max < 0 {
		return Object{}, errors.New("s3x: empty key or negative bound")
	}
	resp, err := c.do(ctx, http.MethodGet, key, versionQuery(versionID), nil, nil)
	if err != nil {
		return Object{}, err
	}
	defer resp.Body.Close()
	o := objectOf(key, resp)
	if resp.ContentLength > max {
		return o, fmt.Errorf("s3x: GET %q: %d bytes, over %d", key, resp.ContentLength, max)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, max))
	if err != nil {
		return o, fmt.Errorf("s3x: GET %q: %w", key, err)
	}
	if k, _ := io.ReadFull(resp.Body, make([]byte, 1)); k > 0 {
		return o, fmt.Errorf("s3x: GET %q: body over %d bytes", key, max)
	}
	o.Size = n
	return o, nil
}

type xmlEntry struct {
	XMLName      xml.Name
	Key          string
	VersionId    string
	IsLatest     bool
	LastModified string
	ETag         string
	Size         int64
}

func (e xmlEntry) object(prefix string) (Object, error) {
	if e.Key == "" || !strings.HasPrefix(e.Key, prefix) {
		return Object{}, fmt.Errorf("s3x: listed key %q outside prefix %q", e.Key, prefix)
	}
	t, err := time.Parse(time.RFC3339, e.LastModified)
	if err != nil {
		return Object{}, fmt.Errorf("s3x: listed key %q: %w", e.Key, err)
	}
	return Object{Key: e.Key, VersionID: e.VersionId, ETag: e.ETag, Size: e.Size, Modified: t, Latest: e.IsLatest,
		DeleteMarker: elem(e.XMLName) == "DeleteMarker"}, nil
}

// List gives one page of the current objects under prefix (ListObjectsV2),
// from the continuation token; next is empty on the last page.
func (c *Client) List(ctx context.Context, prefix, token string) (page []Object, next string, err error) {
	if err := checkName(prefix, true); err != nil {
		return nil, "", err
	}
	q := url.Values{"list-type": {"2"}, "prefix": {prefix}}
	if token != "" {
		q.Set("continuation-token", token)
	}
	resp, err := c.do(ctx, http.MethodGet, "", q, nil, nil)
	if err != nil {
		return nil, "", err
	}
	var v struct {
		IsTruncated           bool
		NextContinuationToken string
		Contents              []xmlEntry
	}
	if err := readXML(resp, "GET", prefix, &v); err != nil {
		return nil, "", err
	}
	for _, e := range v.Contents {
		e.IsLatest = true
		o, err := e.object(prefix)
		if err != nil {
			return nil, "", err
		}
		page = append(page, o)
	}
	if v.IsTruncated && (v.NextContinuationToken == "" || v.NextContinuationToken == token) {
		return nil, "", errors.New("s3x: truncated listing without a new continuation token")
	}
	if !v.IsTruncated {
		return page, "", nil
	}
	return page, v.NextContinuationToken, nil
}

// ListVersions gives one page of the versions and delete markers under
// prefix, in the store's order (by key; a key's versions newest first), from
// the markers; nextKey is empty on the last page.
func (c *Client) ListVersions(ctx context.Context, prefix, keyMarker, versionMarker string) (page []Object, nextKey, nextVersion string, err error) {
	if err := checkName(prefix, true); err != nil {
		return nil, "", "", err
	}
	q := url.Values{"versions": {""}, "prefix": {prefix}}
	if keyMarker != "" {
		q.Set("key-marker", keyMarker)
	}
	if versionMarker != "" {
		q.Set("version-id-marker", versionMarker)
	}
	resp, err := c.do(ctx, http.MethodGet, "", q, nil, nil)
	if err != nil {
		return nil, "", "", err
	}
	var v struct {
		IsTruncated         bool
		NextKeyMarker       string
		NextVersionIdMarker string
		Entries             []xmlEntry `xml:",any"` // Version and DeleteMarker, interleaved: the order is the point
	}
	if err := readXML(resp, "GET", prefix, &v); err != nil {
		return nil, "", "", err
	}
	for _, e := range v.Entries {
		if elem(e.XMLName) != "Version" && elem(e.XMLName) != "DeleteMarker" {
			continue
		}
		o, err := e.object(prefix)
		if err != nil {
			return nil, "", "", err
		}
		page = append(page, o)
	}
	if !v.IsTruncated {
		return page, "", "", nil
	}
	if v.NextKeyMarker == "" || v.NextKeyMarker == keyMarker && v.NextVersionIdMarker == versionMarker {
		return nil, "", "", errors.New("s3x: truncated version listing without new markers")
	}
	return page, v.NextKeyMarker, v.NextVersionIdMarker, nil
}

// CreateMultipart opens an upload of key. The write-once condition belongs on
// CompleteMultipart: a store does not evaluate it here.
func (c *Client) CreateMultipart(ctx context.Context, key string, meta map[string]string) (uploadID string, err error) {
	resp, err := c.do(ctx, http.MethodPost, key, url.Values{"uploads": {""}}, metaHeaders(meta, false), nil)
	if err != nil {
		return "", err
	}
	var v struct{ UploadId string }
	if err := readXML(resp, "POST", key, &v); err != nil {
		return "", err
	}
	if v.UploadId == "" {
		return "", fmt.Errorf("s3x: POST %q: no upload id", key)
	}
	return v.UploadId, nil
}

// UploadPart sends part n (1 to 10,000) of an upload and returns its ETag.
func (c *Client) UploadPart(ctx context.Context, key, uploadID string, n int, body []byte) (etag string, err error) {
	if uploadID == "" || n < 1 || n > 10000 {
		return "", errors.New("s3x: upload part needs an upload id and a part number from 1 to 10000")
	}
	if body == nil {
		body = []byte{}
	}
	resp, err := c.do(ctx, http.MethodPut, key, url.Values{"partNumber": {strconv.Itoa(n)}, "uploadId": {uploadID}}, nil, body)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if etag = resp.Header.Get("ETag"); etag == "" {
		return "", fmt.Errorf("s3x: PUT %q part %d: no ETag", key, n)
	}
	return etag, nil
}

// CompleteMultipart joins the parts, etags[i] being part i+1's; ifAbsent
// makes it a conditional create, refused with ErrExists when the key exists.
// A refused or failed completion leaves the upload open: abort it.
func (c *Client) CompleteMultipart(ctx context.Context, key, uploadID string, etags []string, ifAbsent bool) (versionID string, err error) {
	if uploadID == "" || len(etags) == 0 || len(etags) > 10000 {
		return "", errors.New("s3x: completion needs an upload id and 1 to 10000 parts")
	}
	type part struct {
		PartNumber int
		ETag       string
	}
	doc := struct {
		XMLName xml.Name `xml:"CompleteMultipartUpload"`
		Parts   []part   `xml:"Part"`
	}{}
	for i, e := range etags {
		if e == "" {
			return "", fmt.Errorf("s3x: completion: part %d has no ETag", i+1)
		}
		doc.Parts = append(doc.Parts, part{i + 1, e})
	}
	body, err := xml.Marshal(doc)
	if err != nil {
		return "", err
	}
	resp, err := c.do(ctx, http.MethodPost, key, url.Values{"uploadId": {uploadID}}, metaHeaders(nil, ifAbsent), body)
	if err != nil {
		return "", err
	}
	var v struct{ XMLName xml.Name }
	if err := readXML(resp, "POST", key, &v); err != nil {
		return "", err
	}
	if elem(v.XMLName) != "CompleteMultipartUploadResult" {
		return "", fmt.Errorf("s3x: POST %q: unexpected completion document %q", key, elem(v.XMLName))
	}
	return versionOf(resp, key)
}

// AbortMultipart discards an upload this client opened, and its parts. It
// refuses an empty uploadID: without one the request would address the object.
func (c *Client) AbortMultipart(ctx context.Context, key, uploadID string) error {
	if uploadID == "" {
		return errors.New("s3x: abort needs an upload id")
	}
	resp, err := c.do(ctx, http.MethodDelete, key, url.Values{"uploadId": {uploadID}}, nil, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Sign adds signature version 4 headers (x-amz-date, x-amz-content-sha256,
// Authorization) for service s3 to r, signing the host and every header r
// carries. It also sets r's escaped path and query to their canonical forms,
// so that what is sent is what was signed.
func Sign(r *http.Request, payloadSHA256, accessKey, secretKey, region string, now time.Time) {
	amz := now.UTC().Format("20060102T150405Z")
	day := amz[:8]
	r.Header.Del("Authorization")
	r.Header.Set("X-Amz-Date", amz)
	r.Header.Set("X-Amz-Content-Sha256", payloadSHA256)

	path := uriEncode(r.URL.Path, false)
	if path == "" {
		path = "/"
	}
	r.URL.RawPath = path
	q := r.URL.Query()
	var qs []string
	for k, vs := range q {
		for _, v := range vs {
			qs = append(qs, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	sort.Strings(qs)
	r.URL.RawQuery = strings.Join(qs, "&")

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	hs := map[string]string{"host": host}
	for k, vs := range r.Header {
		var vals []string
		for _, v := range vs {
			vals = append(vals, strings.Join(strings.Fields(v), " "))
		}
		hs[strings.ToLower(k)] = strings.Join(vals, ",")
	}
	names := make([]string, 0, len(hs))
	for k := range hs {
		names = append(names, k)
	}
	sort.Strings(names)
	var canon strings.Builder
	for _, k := range names {
		canon.WriteString(k + ":" + hs[k] + "\n")
	}
	signed := strings.Join(names, ";")
	creq := r.Method + "\n" + path + "\n" + r.URL.RawQuery + "\n" + canon.String() + "\n" + signed + "\n" + payloadSHA256
	scope := day + "/" + region + "/s3/aws4_request"
	h := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + amz + "\n" + scope + "\n" + hex.EncodeToString(h[:])
	key := mac(mac(mac(mac([]byte("AWS4"+secretKey), day), region), "s3"), "aws4_request")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/"+scope+",SignedHeaders="+signed+
		",Signature="+hex.EncodeToString(mac(key, sts)))
}

func mac(k []byte, s string) []byte {
	h := hmac.New(sha256.New, k)
	h.Write([]byte(s))
	return h.Sum(nil)
}

// uriEncode is the signature's encoding: unreserved characters stay, '/'
// stays in a path, every other byte is %XX.
func uriEncode(s string, query bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~',
			c == '/' && !query:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func elem(n xml.Name) string { return n.Local }

// checkName refuses a key (or, with prefix, a listing prefix) that a store
// may store under another name: more than 1,024 bytes, a leading or trailing
// "/", or an empty, "." or ".." segment. A prefix may be empty or end in "/".
func checkName(s string, prefix bool) error {
	n := s
	if prefix {
		if s == "" {
			return nil
		}
		n = strings.TrimSuffix(s, "/")
	}
	bad := len(s) > 1024 || n == ""
	for _, seg := range strings.Split(n, "/") {
		bad = bad || seg == "" || seg == "." || seg == ".."
	}
	if bad {
		return fmt.Errorf("s3x: refused name %q: empty, over 1024 bytes, or with an empty, \".\" or \"..\" segment", s)
	}
	return nil
}

// versionOf is a write's version id. A write answered without one (versioning
// off or suspended) is an error: a record without a version means the oldest.
func versionOf(resp *http.Response, key string) (string, error) {
	v := resp.Header.Get("X-Amz-Version-Id")
	if v == "" || v == "null" {
		return "", fmt.Errorf("s3x: write of %q answered without a version id", key)
	}
	return v, nil
}

// HTTPClient is the client's own transport under its connection rules (only
// the given addresses, TLS 1.2 or later, the CA, no proxy, no redirect
// followed, the header bound and the timeout), for a request this package
// does not offer: the caller builds it and signs it with Sign. The value is
// a copy: changing it does not change this client.
func (c *Client) HTTPClient() *http.Client { h := *c.hc; return &h }
