package repl

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/s3x"
)

// Deleter deletes one object or version the probe wrote itself. It is built
// only in this file and handed only to Probe.
type Deleter interface {
	Delete(ctx context.Context, key, versionID string) error
}

// Raw sends one signed request the object-store client does not offer: a
// bucket setting read back, a body sent with a wrong digest, a request signed
// for another region. It returns the status and the error code of the answer.
type Raw interface {
	Send(ctx context.Context, r RawRequest) (status int, code string, hdr http.Header, doc []byte, err error)
}

// RawRequest: Key "" addresses the bucket. MD5 and SHA256 override the
// body's own digests (a wrong one on purpose); Region overrides the signing
// region.
type RawRequest struct {
	Method, Key         string
	Query               url.Values
	Body                []byte
	MD5, SHA256, Region string
}

// ProbeTargets are the bucket under its write credential, the same bucket
// under its read-only credential, the other bucket under the write
// credential (nil when one bucket serves both), and the signed requests.
type ProbeTargets struct {
	Write, Read, Other Store
	Raw                Raw
}

// probeDir is where the probe writes, below the declared prefix and outside
// every subject's prefix: no listing, plan or walk ever sees it.
const probeDir = ".probe"

// ProbeBase is "<prefix>/.probe", the one place the probe writes or deletes.
func ProbeBase(prefix string) string {
	if prefix == "" {
		return probeDir
	}
	return prefix + "/" + probeDir
}

// Probe checks one bucket for what the copy relies on and returns one row
// each. Every row that expects a refusal has a positive control with the same
// credential first: a 403 is also a wrong signature or a skewed clock.
func Probe(ctx context.Context, in jobio.Input, t ProbeTargets, del Deleter) (jobio.ReplResult, error) {
	if in.Repl == nil || in.Repl.Mode != "probe" || t.Write == nil || t.Read == nil || t.Raw == nil || del == nil {
		return jobio.ReplResult{}, fmt.Errorf("%w: not a probe input", ErrInput)
	}
	if !validPrefix(t.Write.Prefix()) {
		return jobio.ReplResult{}, fmt.Errorf("%w: the prefix breaks the key rule", ErrInput)
	}
	run := make([]byte, 8)
	rand.Read(run)
	p := &prober{ctx: ctx, t: t, del: del, open: map[string]string{}, base: fmt.Sprintf("%s/%d-%s", ProbeBase(t.Write.Prefix()), in.Job, hex.EncodeToString(run))}
	p.versioning()
	p.lock()
	p.readOnly()
	p.writeCannotDelete()
	p.abortMultipart()
	p.otherBucket(in.Subject == "cp")
	p.conditional()
	p.conditionalMultipart()
	p.checksum()
	p.region()
	p.lifecycle()
	// Best effort, bounded: the uploads it left open are aborted; its objects
	// deleted where the lock does not refuse it.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupMax)
	defer cancel()
	for id, k := range p.open {
		t.Raw.Send(cctx, RawRequest{Method: http.MethodDelete, Key: k, Query: url.Values{"uploadId": {id}}})
	}
	for _, w := range p.written {
		del.Delete(cctx, w[0], w[1])
	}
	return jobio.ReplResult{OK: true, Mode: "probe", ProbeRows: p.rows}, nil
}

type prober struct {
	ctx     context.Context
	t       ProbeTargets
	del     Deleter
	base    string
	rows    []jobio.ProbeRow
	written [][2]string       // key, version id
	open    map[string]string // upload id → key: uploads opened and neither completed nor aborted
	control bool              // the write credential's own put succeeded
}

func (p *prober) row(name string, ok bool, detail string) {
	p.rows = append(p.rows, jobio.ProbeRow{Name: name, OK: ok, Detail: clean(detail)})
}

func (p *prober) key(n string) string { return p.base + "/" + n }

func (p *prober) put(st Store, n string, ifAbsent bool) (string, error) {
	vid, err := st.Put(p.ctx, p.key(n), []byte("probe "+n), nil, ifAbsent)
	if err == nil {
		p.written = append(p.written, [2]string{p.key(n), vid})
	}
	return vid, err
}

func unknown(err error) string { return "unknown: " + err.Error() }

func (p *prober) versioning() {
	var v struct{ Status string }
	if err := p.getXML("versioning", &v); err != nil {
		p.row("versioning", false, unknown(err))
		return
	}
	p.row("versioning", v.Status == "Enabled", "status "+v.Status)
}

// lock writes the probe's object with the write credential (the control of
// every later row) and reads its lock back: the bucket's default retention
// in compliance mode must reach the replicator's own writes.
func (p *prober) lock() {
	const name = "default-lock-compliance"
	if _, err := p.put(p.t.Write, "obj", true); err != nil {
		p.row(name, false, "control: the write credential cannot write: "+err.Error())
		return
	}
	p.control = true
	st, code, hdr, _, err := p.t.Raw.Send(p.ctx, RawRequest{Method: http.MethodHead, Key: p.key("obj")})
	if err != nil || st != 200 {
		p.row(name, false, fmt.Sprintf("unknown: HEAD answered %d %s %v", st, code, err))
		return
	}
	mode, until := hdr.Get("X-Amz-Object-Lock-Mode"), hdr.Get("X-Amz-Object-Lock-Retain-Until-Date")
	t, terr := time.Parse(time.RFC3339, until)
	p.row(name, mode == "COMPLIANCE" && terr == nil && t.After(time.Now()), fmt.Sprintf("a new object's lock: mode %q, retained until %q", mode, until))
}

// writeCannotDelete: the write credential, which can write (the control),
// can delete neither a version nor, without one, place a delete marker.
func (p *prober) writeCannotDelete() {
	const name = "write-cannot-delete"
	vid, err := p.put(p.t.Write, "del", true)
	if err != nil {
		p.row(name, false, "control: the write credential cannot write: "+err.Error())
		return
	}
	e1 := p.del.Delete(p.ctx, p.key("del"), vid)
	e2 := p.del.Delete(p.ctx, p.key("del"), "")
	page, _, _, err := p.t.Write.ListVersions(p.ctx, p.key("del"), "", "")
	marker := false
	for _, o := range page {
		marker = marker || o.DeleteMarker
	}
	switch {
	case err != nil:
		p.row(name, false, unknown(err))
	case !errors.Is(e1, s3x.ErrDenied) || !errors.Is(e2, s3x.ErrDenied) || marker:
		p.row(name, false, fmt.Sprintf("a delete was not refused (version delete accepted: %v; marker delete accepted: %v; marker listed: %v)", e1 == nil, e2 == nil, marker))
	default:
		p.row(name, true, "a version delete and a delete marker both refused")
	}
}

// create opens an upload and keeps it until it is completed or aborted.
func (p *prober) create(k string) (string, error) {
	id, err := p.t.Write.CreateMultipart(p.ctx, k, nil)
	if err == nil {
		p.open[id] = k
	}
	return id, err
}

func (p *prober) abortMultipart() {
	const name = "write-can-abort-multipart"
	id, err := p.create(p.key("mp"))
	if err == nil {
		_, err = p.t.Write.UploadPart(p.ctx, p.key("mp"), id, 1, []byte("part"))
	}
	if err != nil {
		p.row(name, false, unknown(err))
		return
	}
	status, code, _, _, err := p.t.Raw.Send(p.ctx, RawRequest{Method: http.MethodDelete, Key: p.key("mp"), Query: url.Values{"uploadId": {id}}})
	switch {
	case err != nil:
		p.row(name, false, unknown(err))
	case status/100 != 2:
		p.row(name, false, fmt.Sprintf("abort answered %d %s: the abort-incomplete rule must clear refused uploads", status, code))
	default:
		delete(p.open, id)
		p.row(name, true, "an upload the probe opened was aborted")
	}
}

// readOnly: the read-only credential reads what the write one wrote (the
// control) and cannot write.
func (p *prober) readOnly() {
	const name = "read-only-cannot-write"
	if !p.control {
		p.row(name, false, "no object to read: the write credential's control failed")
		return
	}
	if _, err := p.t.Read.Head(p.ctx, p.key("obj"), ""); err != nil {
		p.row(name, false, "control: the read-only credential cannot read: "+err.Error())
		return
	}
	_, err := p.put(p.t.Read, "ro", false)
	switch {
	case errors.Is(err, s3x.ErrDenied):
		p.row(name, true, "a write was refused")
	case err == nil:
		p.row(name, false, "the read-only credential wrote an object")
	default:
		p.row(name, false, unknown(err))
	}
}

// otherBucket: the write credential, which reaches its own bucket (the
// control), can neither list nor write the other one.
func (p *prober) otherBucket(cp bool) {
	name := "projects-credential-cannot-reach-control-plane-bucket"
	if cp {
		name = "control-plane-credential-cannot-reach-projects-bucket"
	}
	if p.t.Other == nil {
		p.row(name, false, "one bucket serves both: not checked")
		return
	}
	if _, _, _, err := p.t.Write.ListVersions(p.ctx, p.base+"/", "", ""); err != nil || !p.control {
		p.row(name, false, fmt.Sprintf("control: the credential's own bucket (listed: %v, written: %v)", err == nil, p.control))
		return
	}
	_, _, _, e1 := p.t.Other.ListVersions(p.ctx, p.base+"/", "", "")
	_, e2 := p.put(p.t.Other, "cross", true)
	if errors.Is(e1, s3x.ErrDenied) && errors.Is(e2, s3x.ErrDenied) {
		p.row(name, true, "a listing and a write of the other bucket were refused")
		return
	}
	p.row(name, false, fmt.Sprintf("the other bucket: listed %v, written %v", e1 == nil, e2 == nil))
}

func (p *prober) conditional() {
	const name = "conditional-create"
	if _, err := p.put(p.t.Write, "cc", true); err != nil {
		p.row(name, false, "control: "+err.Error())
		return
	}
	_, err := p.put(p.t.Write, "cc", true)
	p.verdict(name, err, "a second create of one key was refused")
}

func (p *prober) verdict(name string, err error, okDetail string) {
	switch {
	case errors.Is(err, s3x.ErrExists):
		p.row(name, true, okDetail)
	case err == nil:
		p.row(name, false, "a create of an existing key was accepted")
	default:
		p.row(name, false, unknown(err))
	}
}

func (p *prober) conditionalMultipart() {
	const name = "conditional-create-multipart"
	k := p.key("mp2")
	u1, err := p.create(k)
	var u2 string
	if err == nil {
		u2, err = p.create(k)
	}
	var e1, e2 string
	if err == nil {
		e1, err = p.t.Write.UploadPart(p.ctx, k, u1, 1, []byte("one"))
	}
	if err == nil {
		e2, err = p.t.Write.UploadPart(p.ctx, k, u2, 1, []byte("two"))
	}
	if err != nil {
		p.row(name, false, unknown(err))
		return
	}
	vid, err := p.t.Write.CompleteMultipart(p.ctx, k, u1, []string{e1}, true)
	if err != nil {
		p.row(name, false, "control: "+err.Error())
		return
	}
	delete(p.open, u1)
	p.written = append(p.written, [2]string{k, vid})
	_, err = p.t.Write.CompleteMultipart(p.ctx, k, u2, []string{e2}, true) // refused: aborted at the end
	p.verdict(name, err, "the second completion of one key was refused")
}

// checksum: a body with its right digests is stored (the control); one with a
// wrong Content-MD5 and one with a wrong signed SHA-256 are each refused.
func (p *prober) checksum() {
	const name = "checksum-enforced"
	body := []byte("probe checksum")
	wrong := []byte("probe checksumX")
	st, code, _, _, err := p.t.Raw.Send(p.ctx, RawRequest{Method: http.MethodPut, Key: p.key("sum-ok"), Body: body})
	if err != nil || st/100 != 2 {
		p.row(name, false, fmt.Sprintf("control: %d %s %v", st, code, err))
		return
	}
	m := md5.Sum(wrong)
	s1, c1, _, _, err1 := p.t.Raw.Send(p.ctx, RawRequest{Method: http.MethodPut, Key: p.key("sum-md5"), Body: body,
		MD5: base64.StdEncoding.EncodeToString(m[:])})
	s2, c2, _, _, err2 := p.t.Raw.Send(p.ctx, RawRequest{Method: http.MethodPut, Key: p.key("sum-sha"), Body: body, SHA256: hexSum(wrong)})
	if err1 != nil || err2 != nil {
		p.row(name, false, unknown(errors.Join(err1, err2)))
		return
	}
	p.row(name, s1 == 400 && s2 == 400, fmt.Sprintf("wrong Content-MD5: %d %s; wrong payload SHA-256: %d %s", s1, c1, s2, c2))
}

// region: the same request signed for the declared region is stored (the
// control), signed for another region it is refused.
func (p *prober) region() {
	body := []byte("probe region")
	if st, code, _, _, err := p.t.Raw.Send(p.ctx, RawRequest{Method: http.MethodPut, Key: p.key("region-ok"), Body: body}); err != nil || st/100 != 2 {
		p.row("region-checked", false, fmt.Sprintf("control: %d %s %v", st, code, err))
		return
	}
	st, code, _, _, err := p.t.Raw.Send(p.ctx, RawRequest{Method: http.MethodPut, Key: p.key("region"), Body: body,
		Region: "probe-wrong-region-1"})
	switch {
	case err != nil:
		p.row("region-checked", false, unknown(err))
	case st/100 == 2:
		p.row("region-checked", false, "a request signed for another region was accepted")
	default:
		p.row("region-checked", true, fmt.Sprintf("refused with %d %s", st, code))
	}
}

// lifecycle reads the bucket's rules: every enabled rule that expires
// noncurrent versions, with its delay and filter, and the one that aborts
// incomplete uploads.
func (p *prober) lifecycle() {
	type sizes struct {
		Tag                                       []struct{ Key, Value string }
		ObjectSizeGreaterThan, ObjectSizeLessThan *int64
	}
	var v struct {
		Rule []struct {
			ID, Status, Prefix string
			Filter             struct {
				Prefix string
				sizes
				And *struct {
					Prefix string
					sizes
				}
			}
			Noncurrent struct{ NoncurrentDays int }      `xml:"NoncurrentVersionExpiration"`
			Abort      struct{ DaysAfterInitiation int } `xml:"AbortIncompleteMultipartUpload"`
		}
	}
	const ncName, abName = "lifecycle-noncurrent-rule-present", "lifecycle-abort-incomplete-rule-present"
	st, code, _, doc, err := p.t.Raw.Send(p.ctx, RawRequest{Method: http.MethodGet, Query: url.Values{"lifecycle": {""}}})
	if err == nil && st == 404 && code == "NoSuchLifecycleConfiguration" {
		p.row(ncName, false, "no lifecycle configuration")
		p.row(abName, false, "no lifecycle configuration")
		return
	}
	if err == nil && st != 200 {
		err = fmt.Errorf("?lifecycle answered %d %s", st, code)
	}
	if err == nil {
		err = xml.Unmarshal(doc, &v)
	}
	if err != nil {
		p.row(ncName, false, unknown(err))
		p.row(abName, false, unknown(err))
		return
	}
	// A rule counts when it covers every key the replicator writes: no tag
	// or size filter, and a prefix that every key under the declared prefix
	// begins with.
	scope := ""
	if pre := p.t.Write.Prefix(); pre != "" {
		scope = pre + "/"
	}
	var nc, ab, not []string
	for _, r := range v.Rule {
		if r.Status != "Enabled" {
			continue
		}
		f := r.Filter
		prefixes, filtered := []string{r.Prefix, f.Prefix}, len(f.Tag) > 0 || f.ObjectSizeGreaterThan != nil || f.ObjectSizeLessThan != nil
		if f.And != nil {
			prefixes = append(prefixes, f.And.Prefix)
			filtered = filtered || len(f.And.Tag) > 0 || f.And.ObjectSizeGreaterThan != nil || f.And.ObjectSizeLessThan != nil
		}
		prefix, n := "", 0
		for _, x := range prefixes {
			if x != "" {
				prefix, n = x, n+1
			}
		}
		desc := fmt.Sprintf("rule %q, prefix %q", r.ID, prefix)
		if filtered || n > 1 || !strings.HasPrefix(scope, prefix) {
			if r.Noncurrent.NoncurrentDays > 0 || r.Abort.DaysAfterInitiation > 0 {
				not = append(not, desc)
			}
			continue
		}
		if r.Noncurrent.NoncurrentDays > 0 {
			nc = append(nc, fmt.Sprintf("%d days (%s)", r.Noncurrent.NoncurrentDays, desc))
		}
		if r.Abort.DaysAfterInitiation > 0 {
			ab = append(ab, fmt.Sprintf("%d days (%s)", r.Abort.DaysAfterInitiation, desc))
		}
	}
	tail := ""
	if len(not) > 0 {
		tail = "; not counted, filtered by tag, size or another prefix: " + strings.Join(not, ", ")
	}
	p.row(ncName, len(nc) > 0, "noncurrent versions expire after: "+strings.Join(nc, "; ")+tail)
	p.row(abName, len(ab) > 0, "incomplete uploads aborted after: "+strings.Join(ab, "; ")+tail)
}

func (p *prober) getXML(setting string, v any) error {
	st, code, _, doc, err := p.t.Raw.Send(p.ctx, RawRequest{Method: http.MethodGet, Query: url.Values{setting: {""}}})
	if err != nil {
		return err
	}
	if st != 200 {
		return fmt.Errorf("?%s answered %d %s", setting, st, code)
	}
	return xml.Unmarshal(doc, v)
}

// Signer sends the probe's own signed requests through the object-store
// client's transport. It deletes, and sends a DELETE of any kind, only below
// its base, "<prefix>/.probe/".
type Signer struct {
	hc                           *http.Client
	host, bucket, region, access string
	secret                       string
	pathStyle                    bool
	base                         string
}

// NewSigner builds the probe's signer for one bucket; hc is that bucket's
// client's transport (s3x.Client.HTTPClient), host the endpoint's host[:port].
func NewSigner(hc *http.Client, host, bucket, region string, pathStyle bool, k Keys, prefix string) *Signer {
	return &Signer{hc: hc, host: host, bucket: bucket, region: region, access: k.Access, secret: k.Secret,
		pathStyle: pathStyle, base: ProbeBase(prefix) + "/"}
}

// Delete deletes key, or one version of it, when key is below the probe's base.
func (s *Signer) Delete(ctx context.Context, key, versionID string) error {
	q := url.Values{}
	if versionID != "" {
		q.Set("versionId", versionID)
	}
	st, code, _, _, err := s.Send(ctx, RawRequest{Method: http.MethodDelete, Key: key, Query: q})
	switch {
	case err != nil:
		return err
	case st == http.StatusForbidden:
		return fmt.Errorf("%w (DELETE %d %s)", s3x.ErrDenied, st, code)
	case st/100 != 2:
		return fmt.Errorf("repl: DELETE answered %d %s", st, code)
	}
	return nil
}

// Send signs and sends r; the answer's document is read up to 64 KiB.
func (s *Signer) Send(ctx context.Context, r RawRequest) (int, string, http.Header, []byte, error) {
	if r.Query.Has("delete") {
		return 0, "", nil, nil, errors.New("repl: the probe sends no multi-object delete")
	}
	if r.Method == http.MethodDelete && (!strings.HasPrefix(r.Key, s.base) || strings.Contains(r.Key[len(s.base):], "..")) {
		return 0, "", nil, nil, errors.New("repl: the probe deletes only below its own prefix")
	}
	host, p := s.host, "/"+s.bucket
	if !s.pathStyle {
		host, p = s.bucket+"."+s.host, ""
	}
	if r.Key != "" {
		p += "/" + r.Key
	}
	if p == "" {
		p = "/"
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, "https://"+host+"/", bytes.NewReader(r.Body))
	if err != nil {
		return 0, "", nil, nil, err
	}
	req.URL.Path, req.URL.RawQuery = p, r.Query.Encode()
	req.ContentLength = int64(len(r.Body))
	sum, m := hexSum(r.Body), md5.Sum(r.Body)
	if r.SHA256 != "" {
		sum = r.SHA256
	}
	md := base64.StdEncoding.EncodeToString(m[:])
	if r.MD5 != "" {
		md = r.MD5
	}
	if len(r.Body) > 0 {
		req.Header.Set("Content-MD5", md)
	}
	region := s.region
	if r.Region != "" {
		region = r.Region
	}
	s3x.Sign(req, sum, s.access, s.secret, region, time.Now())
	resp, err := s.hc.Do(req)
	if err != nil {
		return 0, "", nil, nil, fmt.Errorf("repl: %s request: %w", r.Method, err)
	}
	defer resp.Body.Close()
	doc, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var e struct{ Code string }
	if resp.StatusCode/100 != 2 {
		xml.Unmarshal(doc, &e)
	}
	return resp.StatusCode, clean(e.Code), resp.Header, doc, nil
}
