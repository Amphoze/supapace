package main

// sp-probe s3 drives an S3-compatible store for the harness: the bucket set-up
// and what the tests read back. Object calls go through internal/s3x; the
// bucket calls and rm build their own requests, signed with s3x.Sign and sent
// with the s3x client's own transport (s3x.Client.HTTPClient).
//
// Grammar (options may stand before, between or after the arguments; "--"
// ends the options, for a KEY that starts with "-"):
//
//	sp-probe s3 SUBCOMMAND [ARG]… CONNECTION [OPTION]…
//
//	CONNECTION  --endpoint https://NAME[:PORT]   required
//	            --keys FILE                      required; line 1 the access key, line 2 the secret key
//	            --bucket B                       required
//	            --ca FILE                        PEM roots; default: the system's
//	            --addr IP:PORT                   repeatable; dial only these, in order, never resolve NAME
//	            --region R                       default us-east-1
//	            --timeout D                      default 30s; bounds each request, dial to last byte
//
// Requests are path style. An option a subcommand does not take is a usage
// error. On success: exactly one line, except versions (one line per entry,
// possibly none) and lifecycle (one line per rule):
//
//	SUBCOMMAND                                   SUCCESS LINE
//	mkbucket                                     created | owned
//	    PUT the bucket with object lock enabled. "owned" is the answer
//	    409 BucketAlreadyOwnedByYou (a set-up run again); any other 409 is an error.
//	versioning [enable]                          versioning Enabled|Suspended|off
//	    with "enable": PUT Status=Enabled first; then GET and print.
//	lock [DAYS]                                  lock MODE DAYS | lock none
//	    with DAYS (a positive integer): PUT a COMPLIANCE default retention of
//	    DAYS days first; then GET and print ("none": no default retention;
//	    DAYS is 0 when the retention is not stated in days).
//	lifecycle [ABORT NONCURRENT]                 lifecycle ID ABORT NONCURRENT (one line per rule) | lifecycle none
//	    with both (positive integers): PUT one rule "sp" — abort incomplete
//	    uploads after ABORT days, expire noncurrent versions after NONCURRENT
//	    days — first; then GET and print (0: the rule has no such action).
//	put KEY [--if-absent] [--meta K=V]…          version ID
//	    the body is stdin, at most 64 MiB; --if-absent: conditional create.
//	get KEY [--version V] [--max N] [--out FILE] object SIZE SHA256HEX ID
//	    --max default 64 MiB; a larger object is an error; --out writes the body.
//	head                                         bucket ok
//	head KEY [--version V]                       object SIZE ID ETAG
//	rm KEY [--version V]                         removed ID marker=true|false
//	    without --version the store places a delete marker (ID is the marker's).
//	    KEY is sent as given: the name rule of internal/s3x is not applied.
//	versions [PREFIX]                            version|marker "KEY" ID latest|noncurrent
//	    every page, in the store's order; KEY is a Go double-quoted ASCII string
//	    (strconv.QuoteToASCII).
//	    KEY may hold spaces inside its quotes; ID and the state are always
//	    the last two fields.
//
// ID, ETAG, MODE and the lifecycle ID are single fields: every rune outside
// printable ASCII, and the space, is printed as "?"; an empty value as "-".
//
// Failure: one line, the last on stdout. Only versions may print entry lines
// before it (those of the pages already read); every other subcommand prints
// nothing else:
//
//	denied       exit 1   403 (any code)
//	not-found    exit 1   404 (for lock and lifecycle only NoSuchBucket; another 404 code is "none")
//	exists       exit 1   412
//	bad-digest   exit 1   400 BadDigest or XAmzContentSHA256Mismatch
//	timeout      exit 2   no answer within --timeout
//	error TEXT   exit 3   usage, a file, TLS, a refused name, any other answer;
//	                      TEXT is printable ASCII ("?" for anything else)
//
// Success exits 0.

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/s3x"
)

// stdin is put's body; a variable for the tests.
var stdin io.Reader = os.Stdin

const s3MaxBody = 64 << 20

type s3Cmd struct {
	cfg  s3x.Config
	cl   *s3x.Client
	hc   *http.Client
	host string
	out  io.Writer
}

func s3Command(args []string, stdout io.Writer) verdict {
	fs := flag.NewFlagSet("sp-probe s3", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	endpoint := fs.String("endpoint", "", "")
	keys := fs.String("keys", "", "")
	caFile := fs.String("ca", "", "")
	bucket := fs.String("bucket", "", "")
	region := fs.String("region", "us-east-1", "")
	timeout := fs.Duration("timeout", 30*time.Second, "")
	ifAbsent := fs.Bool("if-absent", false, "")
	version := fs.String("version", "", "")
	maxBytes := fs.Int64("max", s3MaxBody, "")
	outFile := fs.String("out", "", "")
	var addrs []netip.AddrPort
	meta := map[string]string{}
	fs.Func("addr", "", func(s string) error {
		a, err := netip.ParseAddrPort(s)
		addrs = append(addrs, a)
		return err
	})
	fs.Func("meta", "", func(s string) error {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			return errors.New("--meta takes K=V")
		}
		meta[strings.ToLower(k)] = v
		return nil
	})
	pos, err := parse(fs, args)
	if err != nil {
		return errorVerdict("usage: %v", err)
	}
	if len(pos) == 0 || *endpoint == "" || *keys == "" || *bucket == "" {
		return errorVerdict("usage: s3 SUB --endpoint URL --keys FILE --bucket B")
	}
	kb, err := os.ReadFile(*keys)
	if err != nil {
		return errorVerdict("%v", err)
	}
	lines := strings.Split(string(kb), "\n")
	if len(lines) < 2 {
		return errorVerdict("usage: --keys FILE holds the access key and the secret key on two lines")
	}
	cfg := s3x.Config{Endpoint: *endpoint, Region: *region, Bucket: *bucket, PathStyle: true,
		AccessKey: strings.TrimSpace(lines[0]), SecretKey: strings.TrimSpace(lines[1]), Addrs: addrs, Timeout: *timeout}
	if *caFile != "" {
		b, err := os.ReadFile(*caFile)
		if err != nil {
			return errorVerdict("%v", err)
		}
		cfg.CAPEM = string(b)
	}
	cl, err := s3x.New(cfg)
	if err != nil {
		return errorVerdict("usage: %v", err)
	}
	u, _ := url.Parse(cfg.Endpoint)
	c := &s3Cmd{cfg: cfg, cl: cl, hc: cl.HTTPClient(), host: u.Host, out: stdout}
	ctx := context.Background()
	sub, rest := pos[0], pos[1:]
	if err := optionsApply(fs, sub, len(rest)); err != nil {
		return errorVerdict("usage: %v", err)
	}
	one := func(n int) bool { return len(rest) == n }
	switch {
	case sub == "mkbucket" && one(0):
		return c.result(c.mkbucket(ctx))
	case sub == "versioning" && (one(0) || one(1) && rest[0] == "enable"):
		return c.result(c.versioning(ctx, one(1)))
	case sub == "lock" && (one(0) || one(1)):
		return c.result(c.lock(ctx, rest))
	case sub == "lifecycle" && (one(0) || one(2)):
		return c.result(c.lifecycle(ctx, rest))
	case sub == "put" && one(1):
		return c.result(c.put(ctx, rest[0], meta, *ifAbsent))
	case sub == "get" && one(1) && *maxBytes >= 0:
		return c.result(c.get(ctx, rest[0], *version, *maxBytes, *outFile))
	case sub == "head" && one(0):
		return c.result(c.bucketHead(ctx))
	case sub == "head" && one(1):
		o, err := cl.Head(ctx, rest[0], *version)
		if err == nil {
			fmt.Fprintf(stdout, "object %d %s %s\n", o.Size, token(o.VersionID), token(o.ETag))
		}
		return c.result(err)
	case sub == "rm" && one(1):
		return c.result(c.rm(ctx, rest[0], *version))
	case sub == "versions" && len(rest) <= 1:
		return c.result(c.versions(ctx, strings.Join(rest, "")))
	}
	return errorVerdict("usage: s3: bad arguments %q", args)
}

// subOptions are the options each subcommand takes beyond the connection
// options; head takes --version only with a KEY.
var subOptions = map[string]string{"put": "if-absent meta", "get": "version max out", "head": "version", "rm": "version"}

var connOptions = "endpoint keys ca bucket region timeout addr"

// optionsApply refuses an option the subcommand does not take.
func optionsApply(fs *flag.FlagSet, sub string, nargs int) error {
	allowed := strings.Fields(connOptions + " " + subOptions[sub])
	if sub == "head" && nargs == 0 {
		allowed = strings.Fields(connOptions)
	}
	var bad []string
	fs.Visit(func(f *flag.Flag) {
		if !slices.Contains(allowed, f.Name) {
			bad = append(bad, "--"+f.Name)
		}
	})
	if len(bad) > 0 {
		return fmt.Errorf("%s does not take %s", sub, strings.Join(bad, " "))
	}
	return nil
}

// result turns a call's error into the verdict line; success printed its own lines.
func (c *s3Cmd) result(err error) verdict {
	var ne net.Error
	switch {
	case err == nil:
		return verdict{code: exitOK}
	case errors.Is(err, s3x.ErrDenied):
		return verdict{exitRefused, "denied"}
	case errors.Is(err, s3x.ErrNotFound):
		return verdict{exitRefused, "not-found"}
	case errors.Is(err, s3x.ErrExists):
		return verdict{exitRefused, "exists"}
	case errors.Is(err, s3x.ErrChecksum):
		return verdict{exitRefused, "bad-digest"}
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout():
		return verdict{exitTimeout, "timeout"}
	}
	return errorVerdict("%s", plain(err.Error()))
}

// token is one field of a verdict line: every rune outside printable ASCII,
// and the space, becomes "?"; an empty value is "-".
func token(s string) string {
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(plain(s), " ", "?")
}

// plain replaces every byte outside printable ASCII with "?".
func plain(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

// raw sends one signed request on the bucket (key empty) or an object, and
// returns the response headers and at most 1 MiB of its body. A status other
// than 2xx is an error mapped as s3x maps it.
func (c *s3Cmd) raw(ctx context.Context, method, key, query string, body []byte, hdr map[string]string) (http.Header, []byte, error) {
	path := "/" + c.cfg.Bucket
	if key != "" {
		path += "/" + key
	}
	r, err := http.NewRequestWithContext(ctx, method, "https://"+c.host+"/", strings.NewReader(string(body)))
	if err != nil {
		return nil, nil, err
	}
	r.URL.Path, r.URL.RawQuery = path, query
	r.ContentLength = int64(len(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	sum := sha256.Sum256(body)
	if len(body) > 0 {
		r.Header.Set("Content-MD5", md5b64(body))
	}
	s3x.Sign(r, hex.EncodeToString(sum[:]), c.cfg.AccessKey, c.cfg.SecretKey, c.cfg.Region, time.Now())
	resp, err := c.hc.Do(r)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	doc, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode/100 != 2 {
		var e struct{ Code string }
		xml.Unmarshal(doc, &e)
		if len(e.Code) > 64 {
			e.Code = e.Code[:64]
		}
		return nil, nil, rawErr(resp.StatusCode, e.Code)
	}
	return resp.Header, doc, nil
}

type statusError struct {
	status int
	code   string
}

func (e *statusError) Error() string { return fmt.Sprintf("HTTP %d %s", e.status, e.code) }

func md5b64(b []byte) string {
	m := md5.Sum(b)
	return base64.StdEncoding.EncodeToString(m[:])
}

func rawErr(status int, code string) error {
	var base error
	switch {
	case status == 403:
		base = s3x.ErrDenied
	case status == 404:
		base = s3x.ErrNotFound
	case status == 412:
		base = s3x.ErrExists
	case status == 400 && (code == "BadDigest" || code == "XAmzContentSHA256Mismatch"):
		base = s3x.ErrChecksum
	}
	se := &statusError{status, code}
	if base == nil {
		return se
	}
	return fmt.Errorf("%w: %w", base, se)
}

// notConfigured is the 404 a bucket gives for a configuration it does not have.
func notConfigured(err error) bool {
	var se *statusError
	return errors.As(err, &se) && se.status == 404 && se.code != "NoSuchBucket"
}

func (c *s3Cmd) mkbucket(ctx context.Context) error {
	_, _, err := c.raw(ctx, "PUT", "", "", nil, map[string]string{"X-Amz-Bucket-Object-Lock-Enabled": "true"})
	var se *statusError
	switch {
	case err == nil:
		fmt.Fprintln(c.out, "created")
	case errors.As(err, &se) && se.status == 409 && se.code == "BucketAlreadyOwnedByYou":
		fmt.Fprintln(c.out, "owned")
		return nil
	}
	return err
}

func (c *s3Cmd) bucketHead(ctx context.Context) error {
	_, _, err := c.raw(ctx, "HEAD", "", "", nil, nil)
	if err == nil {
		fmt.Fprintln(c.out, "bucket ok")
	}
	return err
}

func (c *s3Cmd) versioning(ctx context.Context, enable bool) error {
	if enable {
		body := "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"
		if _, _, err := c.raw(ctx, "PUT", "", "versioning=", []byte(body), nil); err != nil {
			return err
		}
	}
	_, doc, err := c.raw(ctx, "GET", "", "versioning=", nil, nil)
	if err != nil {
		return err
	}
	var v struct{ Status string }
	if err := xml.Unmarshal(doc, &v); err != nil {
		return err
	}
	if v.Status == "" {
		v.Status = "off"
	}
	fmt.Fprintln(c.out, "versioning", token(v.Status))
	return nil
}

func (c *s3Cmd) lock(ctx context.Context, days []string) error {
	if len(days) == 1 {
		n, err := strconv.Atoi(days[0])
		if err != nil || n < 1 {
			return errors.New("usage: lock DAYS takes a positive number")
		}
		body := fmt.Sprintf("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention>"+
			"<Mode>COMPLIANCE</Mode><Days>%d</Days></DefaultRetention></Rule></ObjectLockConfiguration>", n)
		if _, _, err := c.raw(ctx, "PUT", "", "object-lock=", []byte(body), nil); err != nil {
			return err
		}
	}
	_, doc, err := c.raw(ctx, "GET", "", "object-lock=", nil, nil)
	if notConfigured(err) {
		fmt.Fprintln(c.out, "lock none")
		return nil
	}
	if err != nil {
		return err
	}
	var v struct {
		Mode string `xml:"Rule>DefaultRetention>Mode"`
		Days int    `xml:"Rule>DefaultRetention>Days"`
	}
	if err := xml.Unmarshal(doc, &v); err != nil {
		return err
	}
	if v.Mode == "" {
		fmt.Fprintln(c.out, "lock none")
		return nil
	}
	fmt.Fprintf(c.out, "lock %s %d\n", token(v.Mode), v.Days)
	return nil
}

func (c *s3Cmd) lifecycle(ctx context.Context, days []string) error {
	if len(days) == 2 {
		a, err1 := strconv.Atoi(days[0])
		n, err2 := strconv.Atoi(days[1])
		if err1 != nil || err2 != nil || a < 1 || n < 1 {
			return errors.New("usage: lifecycle ABORT NONCURRENT take positive numbers")
		}
		body := fmt.Sprintf("<LifecycleConfiguration><Rule><ID>sp</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>"+
			"<NoncurrentVersionExpiration><NoncurrentDays>%d</NoncurrentDays></NoncurrentVersionExpiration>"+
			"<AbortIncompleteMultipartUpload><DaysAfterInitiation>%d</DaysAfterInitiation></AbortIncompleteMultipartUpload>"+
			"</Rule></LifecycleConfiguration>", n, a)
		if _, _, err := c.raw(ctx, "PUT", "", "lifecycle=", []byte(body), nil); err != nil {
			return err
		}
	}
	_, doc, err := c.raw(ctx, "GET", "", "lifecycle=", nil, nil)
	if notConfigured(err) {
		fmt.Fprintln(c.out, "lifecycle none")
		return nil
	}
	if err != nil {
		return err
	}
	var v struct {
		Rules []struct {
			ID         string
			Abort      int `xml:"AbortIncompleteMultipartUpload>DaysAfterInitiation"`
			Noncurrent int `xml:"NoncurrentVersionExpiration>NoncurrentDays"`
		} `xml:"Rule"`
	}
	if err := xml.Unmarshal(doc, &v); err != nil {
		return err
	}
	if len(v.Rules) == 0 {
		fmt.Fprintln(c.out, "lifecycle none")
	}
	for _, r := range v.Rules {
		fmt.Fprintf(c.out, "lifecycle %s %d %d\n", token(r.ID), r.Abort, r.Noncurrent)
	}
	return nil
}

func (c *s3Cmd) put(ctx context.Context, key string, meta map[string]string, ifAbsent bool) error {
	body, err := io.ReadAll(io.LimitReader(stdin, s3MaxBody+1))
	if err != nil {
		return err
	}
	if len(body) > s3MaxBody {
		return fmt.Errorf("usage: put: stdin over %d bytes", s3MaxBody)
	}
	v, err := c.cl.Put(ctx, key, body, meta, ifAbsent)
	if err == nil {
		fmt.Fprintln(c.out, "version", token(v))
	}
	return err
}

func (c *s3Cmd) get(ctx context.Context, key, version string, max int64, out string) error {
	h := sha256.New()
	var w io.Writer = h
	if out != "" {
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = io.MultiWriter(h, f)
	}
	o, err := c.cl.Get(ctx, key, version, w, max)
	if err == nil {
		fmt.Fprintf(c.out, "object %d %x %s\n", o.Size, h.Sum(nil), token(o.VersionID))
	}
	return err
}

func (c *s3Cmd) rm(ctx context.Context, key, version string) error {
	q := ""
	if version != "" {
		q = "versionId=" + url.QueryEscape(version)
	}
	h, _, err := c.raw(ctx, "DELETE", key, q, nil, nil)
	if err == nil {
		fmt.Fprintf(c.out, "removed %s marker=%t\n", token(h.Get("X-Amz-Version-Id")), h.Get("X-Amz-Delete-Marker") == "true")
	}
	return err
}

func (c *s3Cmd) versions(ctx context.Context, prefix string) error {
	km, vm := "", ""
	for range 10000 {
		page, nk, nv, err := c.cl.ListVersions(ctx, prefix, km, vm)
		if err != nil {
			return err
		}
		for _, o := range page {
			kind, state := "version", "noncurrent"
			if o.DeleteMarker {
				kind = "marker"
			}
			if o.Latest {
				state = "latest"
			}
			fmt.Fprintf(c.out, "%s %s %s %s\n", kind, strconv.QuoteToASCII(o.Key), token(o.VersionID), state)
		}
		if nk == "" {
			return nil
		}
		km, vm = nk, nv
	}
	return errors.New("versions: more than 10000 pages")
}
