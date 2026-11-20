package repl

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/s3x"
)

// strayStore lists, beside the fake's own versions, a key outside the
// listing prefix (a store's answer the client would refuse; the seam does not).
type strayStore struct{ *fake }

func (s strayStore) ListVersions(ctx context.Context, p, km, vm string) ([]s3x.Object, string, string, error) {
	page, nk, nv, err := s.fake.ListVersions(ctx, p, km, vm)
	if km == "" {
		page = append([]s3x.Object{{Key: "elsewhere/" + seg(1, 9), VersionID: "v1", Size: 1, Modified: time.Unix(1e9, 0)}}, page...)
	}
	return page, nk, nv, err
}

// A rebuild page carries no notice but unlisted-entry, whatever the listing
// holds: keys outside the layout, a folder object, delete markers, a key
// without the listing prefix, a version id out of shape.
func TestRebuild_APageCarriesNoNoticeButUnlistedEntry(t *testing.T) {
	f := versioned(t, map[string]int{seg(1, 1): 2, pHist2: 1})
	for _, k := range []string{"hx/planted", "archive/" + stanza + "/17-1/x", "backup/other-1/backup.info"} {
		f.store(f.putKey(k), []byte("x"), nil, false)
	}
	f.objs[f.putKey(seg(1, 2))] = []fakeObj{{vid: strings.Repeat("v", versionMax+1), body: []byte("x")}}
	for _, st := range []Store{f, strayStore{f}} {
		for _, rows := range []int{1, 3, 4000} {
			km, vm := "", ""
			for i := 0; i < 50; i++ {
				r, err := Rebuild(context.Background(), rebuildInput(km, vm, rows), st)
				if err != nil {
					t.Fatal(err)
				}
				for _, n := range r.Notices {
					if n.Code != "unlisted-entry" {
						t.Errorf("a rebuild page carries notice %q", n.Code)
					}
				}
				for _, row := range r.Rows {
					if row.Key == "elsewhere/"+seg(1, 9) || strings.HasPrefix(row.Key, "pre/") {
						t.Errorf("row %q", row.Key)
					}
				}
				if r.Last {
					break
				}
				km, vm = r.NextKeyMarker, r.NextVersionMarker
			}
		}
	}
	r, _ := Rebuild(context.Background(), rebuildInput("", "", 4000), strayStore{f})
	if n := noticeOf(r, "unlisted-entry"); n == nil || n.Count != 5 {
		t.Errorf("unlisted %+v, want 5 (three keys, the version id, the stray key)", n)
	}
}

// The program's bounds stay below its job's deadline, with room for the
// cleanup after a cut; one call never takes a whole bound.
func TestBound_BelowTheRunnersDeadline(t *testing.T) {
	for mode, kind := range map[string]string{"copy": "replicate", "rebuild": "replicate", "probe": "probe"} {
		d, err := bklimit.Deadline(kind, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if b := Bound(mode); b+cleanupMax+10*time.Second > d || CallTimeout >= b {
			t.Errorf("%s: bound %v, cleanup %v, call %v against the %s deadline %v", mode, b, cleanupMax, CallTimeout, kind, d)
		}
	}
}

// cancelStore ends its context after n uploads, as the program's bound does.
type cancelStore struct {
	*fake
	n      int
	cancel func()
}

func (c *cancelStore) Put(ctx context.Context, k string, b []byte, m map[string]string, ia bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	v, err := c.fake.Put(ctx, k, b, m, ia)
	if c.n--; c.n == 0 {
		c.cancel()
	}
	return v, err
}

// tripCtx ends with err when tripped: as the program's deadline
// (DeadlineExceeded) or its stop signal (Canceled) ends its context.
type tripCtx struct {
	context.Context
	done chan struct{}
	err  error
}

func newTrip() *tripCtx { return &tripCtx{Context: context.Background(), done: make(chan struct{})} }

func (c *tripCtx) Done() <-chan struct{} { return c.done }
func (c *tripCtx) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}
func (c *tripCtx) trip(err error) { c.err = err; close(c.done) }

// A copy that reaches its bound stops with a result that records what went
// up: not complete, no info file. Its own time bound (the deadline) is
// reason caps — progress, the rest is the next job's; a stop signal (a
// cancel) stays upload-failed.
func TestCopy_StopsAtItsOwnBoundWithWhatWentUp(t *testing.T) {
	for err, want := range map[error]string{context.DeadlineExceeded: "caps", context.Canceled: "upload-failed"} {
		root := fixture(t)
		ctx := newTrip()
		st := &cancelStore{fake: newFake(), n: 2, cancel: func() { ctx.trip(err) }}
		r, cerr := Copy(ctx, input(), root, nilIndex(), st)
		if cerr != nil {
			t.Fatal(cerr)
		}
		if r.Stopped != want || r.Complete || len(r.Uploaded) != 2 || len(r.Info) != 0 || len(st.callsWith("PUT ")) != 2 {
			t.Errorf("%v: stopped %q complete %v uploaded %q info %d puts %d", err, r.Stopped, r.Complete, keys(r.Uploaded), len(r.Info), len(st.callsWith("PUT ")))
		}
		if _, err := jobio.MarshalResult(r); err != nil {
			t.Fatal(err)
		}
	}
}

// A directory that fails to read part-way is unreadable, never a short
// listing: the job is not complete and no info file goes up.
func TestWalk_ADirectoryReadErrorIsNeverAShortListing(t *testing.T) {
	root := fixture(t)
	for n := 3; n <= 1500; n++ { // more than one batch of names, fewer than the file cap
		mk(t, root, seg(1, n), "s")
	}
	// A directory whose first batch of names is full fails its second read with no names.
	old := readdir
	full := map[*os.File]bool{}
	readdir = func(f *os.File, n int) ([]string, error) {
		if full[f] {
			return nil, errors.New("input/output error")
		}
		names, err := old(f, n)
		full[f] = len(names) == n
		return names, err
	}
	defer func() { readdir = old }()
	f := newFake()
	r := run(t, root, input(), nil, f)
	if r.Complete || len(r.Info) != 0 || noticeOf(r, "unreadable-entry") == nil {
		t.Errorf("complete %v info %d notices %+v", r.Complete, len(r.Info), r.Notices)
	}
	for _, u := range r.Uploaded {
		if strings.HasPrefix(u.Key, segDir(1)+"/") {
			t.Errorf("uploaded %s from a directory that did not read", u.Key)
			break
		}
	}
	// Control: the same tree read whole.
	readdir = old
	if r := run(t, root, input(), nil, newFake()); !r.Complete || len(r.Info) != 4 {
		t.Errorf("control: complete %v info %d", r.Complete, len(r.Info))
	}
}

// The lifecycle rows count only an enabled rule that covers every key the
// replicator writes; no configuration is a definite absence.
func TestProbe_LifecycleRulesMustCoverTheReplicatorsKeys(t *testing.T) {
	rule := func(filter string) string {
		return `<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status>` + filter +
			`<NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration>` +
			`<AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>`
	}
	for filter, want := range map[string]bool{
		``:                                       true,
		`<Filter></Filter>`:                      true,
		`<Filter><Prefix>pre/</Prefix></Filter>`: true, // the declared prefix is pre/fix
		`<Filter><Prefix>pre/fix/</Prefix></Filter>`:                                                  true,
		`<Prefix>pre</Prefix>`:                                                                        true,
		`<Filter><Prefix>other/</Prefix></Filter>`:                                                    false,
		`<Filter><Prefix>pre/fix/abc</Prefix></Filter>`:                                               false,
		`<Prefix>pre/</Prefix><Filter><Prefix>pre/</Prefix></Filter>`:                                 false, // two prefix sources in one rule
		`<Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter>`:                                    false,
		`<Filter><ObjectSizeGreaterThan>1</ObjectSizeGreaterThan></Filter>`:                           false,
		`<Filter><And><Prefix>pre/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And></Filter>`:    false,
		`<Filter><And><Prefix>pre/</Prefix><ObjectSizeLessThan>9</ObjectSizeLessThan></And></Filter>`: false,
	} {
		p := goodProvider()
		p.lifecycle = rule(filter)
		rows := probe(t, p, false)
		for _, n := range []string{"lifecycle-noncurrent-rule-present", "lifecycle-abort-incomplete-rule-present"} {
			if rows[n].OK != want {
				t.Errorf("%s with %q: ok %v, want %v (%s)", n, filter, rows[n].OK, want, rows[n].Detail)
			}
		}
	}
	p := goodProvider()
	p.lifecycle = ""
	if r := probe(t, p, false)["lifecycle-noncurrent-rule-present"]; r.OK || r.Detail != "no lifecycle configuration" {
		t.Errorf("no configuration: %+v", r)
	}
}

// The probe leaves no upload of its own open, whatever step fails.
func TestProbe_AbortsItsOwnUploadsOnEveryEarlyExit(t *testing.T) {
	for _, fail := range []int{1, 2, 3} {
		p := goodProvider()
		p.partFails = fail
		probe(t, p, false)
		if len(p.b.uploads) != 0 {
			t.Errorf("part %d refused: %d uploads left open", fail, len(p.b.uploads))
		}
	}
	p := goodProvider()
	probe(t, p, false)
	if len(p.b.uploads) != 0 {
		t.Errorf("control: %d uploads left open", len(p.b.uploads))
	}
}

func TestSigner_RefusesAMultiObjectDelete(t *testing.T) {
	s := NewSigner(&http.Client{Transport: refuseRT{t}}, "s3.example.test:9443", "sp-projects", "r", true, Keys{"a", "b"}, "pre/fix")
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodGet} {
		for _, k := range []string{"", "pre/fix/.probe/x"} {
			if _, _, _, _, err := s.Send(context.Background(), RawRequest{Method: m, Key: k, Query: url.Values{"delete": {""}}}); err == nil {
				t.Errorf("%s %q ?delete was sent", m, k)
			}
		}
	}
}

func TestCodes_TheOneListPerKind(t *testing.T) {
	if got := Codes("replicate"); !slices.Equal(got, []string{"input", "credential", "index", "repository", "store", "result"}) {
		t.Errorf("replicate: %q", got)
	}
	if got := Codes("probe"); !slices.Equal(got, []string{"input", "credential", "store", "result"}) {
		t.Errorf("probe: %q", got)
	}
	if Codes("push") != nil {
		t.Error("a kind of another program")
	}
}

// boundStore ends the program's time bound at its call-th listing, which
// then fails with the context's error.
type boundStore struct {
	*fake
	ctx  *tripCtx
	call int
	n    int
}

func (b *boundStore) ListVersions(ctx context.Context, p, km, vm string) ([]s3x.Object, string, string, error) {
	if b.n++; b.n == b.call {
		b.ctx.trip(context.DeadlineExceeded)
		return nil, "", "", ctx.Err()
	}
	return b.fake.ListVersions(ctx, p, km, vm)
}

// A rebuild cut by its bound returns the page so far — not the last, stop
// reason rebuild, the markers after the last complete listing page, so the
// next page starts exactly there; cut before anything was listed it fails.
func TestRebuild_CutByItsBoundReturnsThePageSoFar(t *testing.T) {
	n := map[string]int{}
	for i := 1; i <= 10; i++ {
		n[seg(1, i)] = 1
	}
	f := versioned(t, n)
	f.page = 3
	_, nk, nv, _ := f.ListVersions(context.Background(), f.prefix+"/"+ref+"/", "", "")
	ctx := newTrip()
	r, err := Rebuild(ctx, rebuildInput("", "", 4000), &boundStore{fake: f, ctx: ctx, call: 2})
	if err != nil {
		t.Fatal(err)
	}
	if r.Last || r.Complete || r.Stopped != "rebuild" || r.NextKeyMarker != nk || r.NextVersionMarker != nv || len(r.Rows) != 3 {
		t.Errorf("last %v stopped %q markers %q %q (want %q %q) rows %d", r.Last, r.Stopped, r.NextKeyMarker, r.NextVersionMarker, nk, nv, len(r.Rows))
	}
	ctx = newTrip()
	if _, err := Rebuild(ctx, rebuildInput("", "", 4000), &boundStore{fake: f, ctx: ctx, call: 1}); err == nil {
		t.Error("a rebuild cut before its first page gave a page")
	}
}
