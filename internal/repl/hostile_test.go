package repl

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/s3x"
)

// A data file swapped for a link between the walk and its open is never
// read: the open by path refuses the link, the file is counted, the job is
// not complete.
func TestCopy_FileSwappedForALinkAfterTheWalkNotRead(t *testing.T) {
	root := fixture(t)
	outside := filepath.Join(t.TempDir(), "secret")
	mk(t, filepath.Dir(outside), "secret", "secret outside")
	target := filepath.Join(root, seg(1, 2))
	old := openForRead
	openForRead = func(dirfd int, name string) (int, error) {
		if name == filepath.Base(seg(1, 2)) {
			os.Remove(target)
			os.Symlink(outside, target)
		}
		return old(dirfd, name)
	}
	t.Cleanup(func() { openForRead = old })
	f := newFake()
	r := run(t, root, input(), nil, f)
	for k, v := range f.objs {
		for _, o := range v {
			if strings.Contains(string(o.body), "secret") {
				t.Errorf("uploaded %s from outside the tree", k)
			}
		}
	}
	if r.Complete || slices.Contains(keys(r.Uploaded), seg(1, 2)) || noticeOf(r, "unreadable-entry") == nil {
		t.Errorf("complete %v uploaded %q notices %+v", r.Complete, keys(r.Uploaded), r.Notices)
	}
	if len(r.Info) != 0 {
		t.Errorf("info uploaded by a job that skipped a file: %+v", r.Info)
	}
	if !slices.Contains(keys(r.Uploaded), seg(1, 1)) {
		t.Errorf("control: %q", keys(r.Uploaded))
	}
}

// partFails is the fake with a part that fails, or a hook run at a part.
type partFails struct {
	*fake
	at   func(n int) error
	seen int
}

func (p *partFails) UploadPart(ctx context.Context, key, id string, n int, body []byte) (string, error) {
	p.seen++
	if err := p.at(n); err != nil {
		return "", err
	}
	return p.fake.UploadPart(ctx, key, id, n, body)
}

// Every way a multipart upload can end without its completion aborts it:
// a part refused, the file rewritten in place while its parts are sent, the
// job's context cancelled. No upload is left open and nothing is written.
func TestCopy_EveryUnfinishedMultipartIsAborted(t *testing.T) {
	big := strings.Repeat("x", bklimit.PartSize+1)
	for name, tc := range map[string]struct {
		at      func(root string, cancel func()) func(int) error
		stopped string
	}{
		"part refused": {func(string, func()) func(int) error {
			return func(n int) error {
				if n == 2 {
					return errors.New("connection reset")
				}
				return nil
			}
		}, "upload-failed"},
		"rewritten in place": {func(root string, _ func()) func(int) error {
			return func(n int) error {
				if n == 1 {
					f, err := os.OpenFile(filepath.Join(root, pSetFile), os.O_WRONLY, 0)
					if err != nil {
						return err
					}
					f.WriteAt([]byte("y"), 0) // same size, new content
					f.Close()
				}
				return nil
			}
		}, ""},
		"cancelled": {func(_ string, cancel func()) func(int) error {
			return func(n int) error {
				if n == 1 {
					cancel()
					return context.Canceled
				}
				return nil
			}
		}, "upload-failed"},
	} {
		t.Run(name, func(t *testing.T) {
			root := fixture(t)
			mk(t, root, pSetFile, big)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &partFails{fake: newFake()}
			p.at = tc.at(root, cancel)
			r, err := Copy(ctx, input(), root, nilIndex(), p)
			if err != nil {
				t.Fatal(err)
			}
			if a := p.callsWith("ABORT "); len(a) != 1 || len(p.uploads) != 0 {
				t.Errorf("aborts %q, open uploads %d", a, len(p.uploads))
			}
			if _, ok := p.objs[p.putKey(pSetFile)]; ok || slices.Contains(keys(r.Uploaded), pSetFile) {
				t.Error("the set file was written")
			}
			if r.Stopped != tc.stopped || r.Complete || len(r.Info) != 0 {
				t.Errorf("stopped %q complete %v info %d, want %q false 0", r.Stopped, r.Complete, len(r.Info), tc.stopped)
			}
		})
	}
}

// The signer sends no delete of the bucket itself, of a key outside its base
// or through an encoded or dot segment.
func TestSigner_RefusesEveryDeleteOutsideItsBase(t *testing.T) {
	s := NewSigner(&http.Client{Transport: refuseRT{t}}, "s3.example.test:9443", "sp-projects", "r", true, Keys{"a", "b"}, "pre/fix")
	for _, k := range []string{"", "pre", "pre/fix", "pre/fix/", "pre/fix/.probe", "pre/fix/.probe/..", "pre/fix/.probe/x/../../" + ref,
		"pre/fix/.probe/.." + "/x", "pre/fix/" + ref + "/.probe/x", "Pre/fix/.probe/x"} {
		if _, _, _, _, err := s.Send(context.Background(), RawRequest{Method: http.MethodDelete, Key: k}); err == nil {
			t.Errorf("a DELETE of %q was sent", k)
		}
	}
	// An encoded dot segment is a literal name below the base: the request
	// path keeps the percent sign escaped, so no store reads it as "..".
	var got string
	s2 := NewSigner(&http.Client{Transport: recordRT{&got}}, "s3.example.test:9443", "b", "r", true, Keys{"a", "b"}, "pre/fix")
	s2.Send(context.Background(), RawRequest{Method: http.MethodDelete, Key: "pre/fix/.probe/%2e%2e/x", Query: url.Values{}})
	if !strings.Contains(got, "/.probe/%252e%252e/x") {
		t.Errorf("request path %q", got)
	}
}

type recordRT struct{ path *string }

func (r recordRT) RoundTrip(req *http.Request) (*http.Response, error) {
	*r.path = req.URL.EscapedPath()
	return nil, errors.New("not sent")
}

// Info files never go up from a job that held segments back or whose walk
// was cut: they would name sets or segments that are not off-site.
func TestCopy_NoInfoFromAHeldOrTruncatedJob(t *testing.T) {
	changed := func(r *jobio.ReplInput) { r.InfoSHA256 = map[string]string{"archive.info": "0"} }
	// Held: timeline 2's history is not in the index and fails to go up.
	root := fixture(t)
	f := newFake()
	f.failPut = func(k string) error {
		if strings.HasSuffix(k, pHist2) {
			return errors.New("connection reset")
		}
		return nil
	}
	if r := run(t, root, input(changed), nil, f); len(r.Info) != 0 {
		t.Errorf("held: info %+v", r.Info)
	}
	root = fixture(t)
	os.Remove(filepath.Join(root, pHist2)) // no history: its segment is held, nothing fails
	if r := run(t, root, input(changed), nil, newFake()); r.Held == 0 || len(r.Info) != 0 || r.Stopped != "held" {
		t.Errorf("held: held %d info %+v stopped %q", r.Held, r.Info, r.Stopped)
	}
	// Truncated walk.
	root = fixture(t)
	if r := run(t, root, input(changed, func(r *jobio.ReplInput) { r.MaxEntries = 5 }), nil, newFake()); !r.Truncated || len(r.Info) != 0 {
		t.Errorf("truncated: %v info %+v", r.Truncated, r.Info)
	}
	// Control: the same tree whole uploads the changed info file.
	if r := run(t, fixture(t), input(changed), nil, newFake()); len(r.Info) == 0 {
		t.Error("control: no info uploaded")
	}
}

// noVersionHead answers HEAD without a version id.
type noVersionHead struct{ *fake }

func (n noVersionHead) Head(ctx context.Context, key, versionID string) (s3x.Object, error) {
	o, err := n.fake.Head(ctx, key, versionID)
	o.VersionID = ""
	return o, err
}

// An existing equal object whose HEAD names no version is not adopted: a
// row without a version id would make the record point at nothing.
func TestCopy_AdoptionNeedsAVersionID(t *testing.T) {
	root := fixture(t)
	f := newFake()
	b, _ := os.ReadFile(filepath.Join(root, seg(1, 1)))
	f.store(f.putKey(seg(1, 1)), b, map[string]string{"sha256": sum(b)}, false)
	r := run(t, root, input(), nil, noVersionHead{f})
	for _, a := range r.Adopted {
		if a.VersionID == "" {
			t.Errorf("adopted %s without a version id", a.Key)
		}
	}
	if noticeOf(r, "offsite-differs") == nil {
		t.Errorf("notices %+v", r.Notices)
	}
	// Control: with the version id the object is adopted.
	r = run(t, root, input(), nil, f)
	if !slices.Contains(keys(r.Adopted), seg(1, 1)) {
		t.Errorf("control: adopted %q", keys(r.Adopted))
	}
}

// emptyPages answers an empty page that says it is not the last.
type emptyPages struct{ *fake }

func (e emptyPages) ListVersions(context.Context, string, string, string) ([]s3x.Object, string, string, error) {
	return nil, "k", "v", nil
}

func TestRebuild_EmptyPageNotTheLastAndAnOverLargePageSize(t *testing.T) {
	if _, err := Rebuild(context.Background(), rebuildInput("", "", 4000), emptyPages{newFake()}); err == nil {
		t.Error("an empty page that is not the last gave a result")
	}
	// page_rows above the bound is cut to it.
	n := map[string]int{}
	for i := 1; i <= bklimit.RebuildPageRows+100; i++ {
		n[seg(1, i)] = 1
	}
	r, err := Rebuild(context.Background(), rebuildInput("", "", 1_000_000), versioned(t, n))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rows) > bklimit.RebuildPageRows || r.Last {
		t.Errorf("%d rows, last %v", len(r.Rows), r.Last)
	}
}

// An info file of another owner is never uploaded (root-only: files of
// another uid).
func TestCopy_ForeignInfoFileNotUploaded(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to own files as another uid")
	}
	root := fixture(t)
	filepath.Walk(root, func(p string, _ os.FileInfo, _ error) error { return os.Lchown(p, 4242, 4242) })
	os.Lchown(filepath.Join(root, pBackInfo), 0, 0)
	in := input(func(r *jobio.ReplInput) { r.InfoSHA256 = map[string]string{} })
	in.UID = 4242
	r := run(t, root, in, nil, newFake())
	names := map[string]bool{}
	for _, i := range r.Info {
		names[i.Name] = true
	}
	if names["backup.info"] || !names["archive.info"] {
		t.Errorf("info uploaded %+v", r.Info)
	}
}
