package repl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jobio"
)

func walkOf(t *testing.T, root string, max int, timelines []uint32) *walk {
	t.Helper()
	fd, err := syscall.Open(root, dirFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	w := &walk{root: fd, uid: os.Getuid(), stanza: stanza, timelines: timelines, max: max}
	w.run()
	return w
}

func rels(w *walk) []string {
	var out []string
	for _, f := range w.files {
		out = append(out, f.rel)
	}
	slices.Sort(out)
	return out
}

func TestWalk_RegularOwnedListedOnly(t *testing.T) {
	root := fixture(t)
	mk(t, root, "hx/junk", "x")
	mk(t, root, "archive/"+stanza+"/17-1/notasegment", "x")
	w := walkOf(t, root, 1000, []uint32{1, 2})
	want := []string{seg(1, 1), seg(1, 2), pHist2, seg(2, 3), pManifest, pManCopy, pSetFile, pHistMan}
	slices.Sort(want)
	if got := rels(w); !slices.Equal(got, want) {
		t.Errorf("files:\n%q\nwant\n%q", got, want)
	}
	if w.unlisted != 2 || w.unreadable != 0 || w.truncated {
		t.Errorf("unlisted %d unreadable %d truncated %v, want 2 0 false", w.unlisted, w.unreadable, w.truncated)
	}
	// Files of another uid are foreign: with the walk at uid+1, nothing is listed.
	fd, _ := syscall.Open(root, dirFlags, 0)
	defer syscall.Close(fd)
	other := &walk{root: fd, uid: os.Getuid() + 1, stanza: stanza, timelines: []uint32{1, 2}, max: 1000}
	other.run()
	if len(other.files) != 0 || other.unlisted != 14 {
		t.Errorf("another uid: %d files, %d unlisted, want 0 and 14", len(other.files), other.unlisted)
	}
	// The info files are read by name before the walk, never listed by it.
	for _, f := range w.files {
		if strings.HasSuffix(f.rel, ".info") || strings.HasSuffix(f.rel, ".info.copy") {
			t.Errorf("walk listed info file %s", f.rel)
		}
	}
}

func TestWalk_LinkFileDirRoot(t *testing.T) {
	root := fixture(t)
	outside := t.TempDir()
	mk(t, outside, "secret", "secret")
	mk(t, outside, "d/"+filepath.Base(seg(1, 9)), "secret")
	// A link with a segment name to a file, a link with a directory's name to a directory.
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, seg(1, 7)))
	os.Rename(filepath.Join(root, segDir(1)), filepath.Join(root, segDir(1)+".real"))
	os.Symlink(filepath.Join(outside, "d"), filepath.Join(root, segDir(1)))
	w := walkOf(t, root, 1000, []uint32{1, 2})
	for _, r := range rels(w) {
		if strings.Contains(r, "/0000000100000000/") {
			t.Errorf("walk followed the link: %s", r)
		}
	}
	// The directory link, and the real directory under its other name: its two
	// files and the file link are at paths the layout does not admit.
	if w.unlisted != 4 {
		t.Errorf("unlisted %d, want 4", w.unlisted)
	}
	// The root itself a link: nothing is walked.
	link := filepath.Join(t.TempDir(), "repo")
	os.Symlink(root, link)
	f := newFake()
	if _, err := Copy(context.Background(), input(), link, nilIndex(), f); err == nil {
		t.Fatal("a root that is a link was walked")
	}
	if len(f.calls) != 0 {
		t.Errorf("calls %v", f.calls)
	}
	// Control: the same root by its own path.
	if _, err := Copy(context.Background(), input(), root, nilIndex(), f); err != nil {
		t.Fatal(err)
	}
}

func nilIndex() *strings.Reader { return strings.NewReader("") }

// Links named like segments to the job's own files — its environment, its
// credential, its input — are refused by type: nothing of them is opened or
// uploaded.
func TestWalk_LinkToTheJobsOwnFilesNeverRead(t *testing.T) {
	root := fixture(t)
	job := t.TempDir()
	mk(t, job, "cred", "test-access\nsecret-key-value")
	mk(t, job, "input.json", `{"job":1}`)
	targets := []string{"/proc/self/environ", filepath.Join(job, "cred"), filepath.Join(job, "input.json")}
	var names []string
	for i, tg := range targets {
		rel := seg(1, 20+i)
		os.Symlink(tg, filepath.Join(root, rel))
		names = append(names, filepath.Base(rel))
	}
	os.Symlink("/proc/self/environ", filepath.Join(root, "backup/"+stanza+"/backup.info.x"))
	var opened []string
	hookOpen(t, func(n string) { opened = append(opened, n) })
	f := newFake()
	r := run(t, root, input(), nil, f)
	for _, n := range names {
		if slices.Contains(opened, n) {
			t.Errorf("opened %s", n)
		}
	}
	if n := noticeOf(r, "unlisted-entry"); n == nil || n.Count != 4 {
		t.Errorf("unlisted-entry %+v, want 4", n)
	}
	for k, v := range f.objs {
		for _, o := range v {
			if strings.Contains(string(o.body), "secret") || strings.Contains(string(o.body), "job") || strings.Contains(string(o.body), "PATH=") {
				t.Errorf("uploaded %s with %q", k, o.body)
			}
		}
	}
	// Control: the files the links name are readable to this process.
	if b, err := os.ReadFile(filepath.Join(root, seg(1, 21))); err != nil || !strings.Contains(string(b), "secret") {
		t.Fatalf("control: %q %v", b, err)
	}
}

// A directory swapped for a link after the listing is never entered: the
// open by path refuses the link at that level.
func TestWalk_SwappedAfterListing(t *testing.T) {
	root := fixture(t)
	outside := t.TempDir()
	mk(t, outside, filepath.Base(seg(2, 3)), "outside")
	swapped := false
	hookOpen(t, func(n string) {
		if !swapped && n == filepath.Base(seg(1, 1)) { // the first data file, before timeline 2's
			swapped = true
			d := filepath.Join(root, segDir(2))
			os.Rename(d, d+".x")
			os.Symlink(outside, d)
		}
	})
	// Nothing is opened in a directory outside the root.
	old := openForRead
	openForRead = func(dirfd int, name string) (int, error) {
		if d, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", dirfd)); strings.HasPrefix(d, outside) {
			t.Errorf("opened %s in %s", name, d)
		}
		return old(dirfd, name)
	}
	f := newFake()
	r := run(t, root, input(), nil, f)
	if !swapped {
		t.Fatal("hook never ran")
	}
	if _, ok := f.objs[f.putKey(seg(2, 3))]; ok {
		t.Error("uploaded through the swapped link")
	}
	if r.Complete || slices.Contains(keys(r.Uploaded), seg(2, 3)) {
		t.Errorf("complete %v, uploaded %q", r.Complete, keys(r.Uploaded))
	}
	if !slices.Contains(keys(r.Uploaded), seg(1, 1)) {
		t.Errorf("control: %q", keys(r.Uploaded))
	}
}

func TestWalk_SparseHugeNotRead(t *testing.T) {
	root := fixture(t)
	for _, rel := range []string{seg(1, 30), "hx/sparse"} {
		mk(t, root, rel, "")
		if err := os.Truncate(filepath.Join(root, rel), 100<<30); err != nil {
			t.Fatal(err)
		}
	}
	var opened []string
	hookOpen(t, func(n string) { opened = append(opened, n) })
	start := time.Now()
	f := newFake()
	r := run(t, root, input(), nil, f)
	if slices.Contains(opened, filepath.Base(seg(1, 30))) || slices.Contains(opened, "sparse") {
		t.Errorf("opened %q", opened)
	}
	if n := noticeOf(r, "unreadable-entry"); n == nil || n.Count != 1 {
		t.Errorf("unreadable-entry %+v, want 1 (the listed one over its bound)", n)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("took %v", d)
	}
	if !slices.Contains(opened, filepath.Base(seg(1, 1))) {
		t.Errorf("control: %q", opened)
	}
}

func TestWalk_FifoDoesNotBlock(t *testing.T) {
	root := fixture(t)
	for _, rel := range []string{seg(1, 40), pBackInfo + ".fifo"} {
		if err := syscall.Mkfifo(filepath.Join(root, rel), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	// The info file itself a FIFO: read by name before the walk, without blocking.
	os.Remove(filepath.Join(root, pArchCopy))
	syscall.Mkfifo(filepath.Join(root, pArchCopy), 0o640)
	done := make(chan struct{})
	var r jobio.ReplResult
	go func() { r = run(t, root, input(), nil, newFake()); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the walk blocked on a FIFO")
	}
	if n := noticeOf(r, "unlisted-entry"); n == nil || n.Count != 3 {
		t.Errorf("unlisted-entry %+v, want 3", n)
	}
}

func TestWalk_DepthBound(t *testing.T) {
	root := fixture(t)
	deep := "hx"
	for i := 0; i < 14; i++ {
		deep += "/d"
	}
	mk(t, root, deep+"/f", "x")
	for i := 0; i < 50; i++ {
		mk(t, root, deep+fmt.Sprintf("/g%d", i), "x")
	}
	mk(t, root, pSetFile[:strings.LastIndex(pSetFile, "/")]+"/a/b/c/d/e/f", "within bound")
	w := walkOf(t, root, 1000, []uint32{1, 2})
	if w.unlisted != 1 {
		t.Errorf("unlisted %d, want 1: the directory at the 13th level", w.unlisted)
	}
	if w.walked > 70 { // 45 with the bound, 98 without
		t.Errorf("walked %d entries: the walk went below the 12th level", w.walked)
	}
	if !slices.Contains(rels(w), pSetFile[:strings.LastIndex(pSetFile, "/")]+"/a/b/c/d/e/f") {
		t.Error("control: a set file nine levels down was not listed")
	}
}

func TestWalk_EntryBound_Truncated_NewestFirst(t *testing.T) {
	root := t.TempDir()
	for n := 1; n <= 10; n++ {
		mk(t, root, seg(1, n), "s")
	}
	// archive, the stanza, 17-1, the segment directory: four entries, then the segments newest first.
	w := walkOf(t, root, 7, []uint32{1})
	want := []string{seg(1, 8), seg(1, 9), seg(1, 10)}
	if got := rels(w); !w.truncated || !slices.Equal(got, want) || w.walked != 7 {
		t.Errorf("truncated %v walked %d files %q, want true 7 %q", w.truncated, w.walked, got, want)
	}
	r := run(t, root, input(func(r *jobio.ReplInput) { r.MaxEntries = 7 }), nil, newFake())
	if !r.Truncated || r.Complete || noticeOf(r, "walk-truncated") == nil {
		t.Errorf("result %+v", r)
	}
	// Control: with room, nothing is cut.
	if w := walkOf(t, root, 14, []uint32{1}); w.truncated || len(w.files) != 10 {
		t.Errorf("control: truncated %v, %d files", w.truncated, len(w.files))
	}
}

func TestWalk_SkipsSetWithoutManifest(t *testing.T) {
	root := fixture(t)
	other := "20261119-010101F"
	mk(t, root, "backup/"+stanza+"/"+other+"/backup.manifest.copy", "in progress")
	mk(t, root, "backup/"+stanza+"/"+other+"/pg_data/base/1/1", "partial")
	w := walkOf(t, root, 1000, []uint32{1, 2})
	for _, r := range rels(w) {
		if strings.Contains(r, other) {
			t.Errorf("listed %s", r)
		}
	}
	if w.unlisted != 0 {
		t.Errorf("unlisted %d", w.unlisted)
	}
	if !slices.Contains(rels(w), pManCopy) {
		t.Error("control: the complete set's manifest copy is listed")
	}
}

func TestWalk_SkipsTmp(t *testing.T) {
	root := fixture(t)
	mk(t, root, seg(1, 3)+".pgbackrest.tmp", "temporary")
	mk(t, root, pManifest+".pgbackrest.tmp", "temporary")
	w := walkOf(t, root, 1000, []uint32{1, 2})
	if w.unlisted != 0 || slices.ContainsFunc(rels(w), func(s string) bool { return strings.HasSuffix(s, ".tmp") }) {
		t.Errorf("unlisted %d files %q", w.unlisted, rels(w))
	}
}

func TestWalk_LatestLinkNotCounted(t *testing.T) {
	root := fixture(t)
	w := walkOf(t, root, 1000, []uint32{1, 2})
	if w.unlisted != 0 {
		t.Errorf("unlisted %d, want 0", w.unlisted)
	}
	// Control: a link of that name elsewhere is counted.
	os.Symlink(label, filepath.Join(root, "archive/"+stanza+"/latest"))
	if w := walkOf(t, root, 1000, []uint32{1, 2}); w.unlisted != 1 {
		t.Errorf("control: unlisted %d, want 1", w.unlisted)
	}
}

func TestWalk_UnadmittedTimelineIsUnlisted(t *testing.T) {
	root := fixture(t)
	w := walkOf(t, root, 1000, []uint32{1})
	if slices.Contains(rels(w), seg(2, 3)) || slices.Contains(rels(w), pHist2) || w.unlisted != 2 {
		t.Errorf("unlisted %d files %q", w.unlisted, rels(w))
	}
	if w := walkOf(t, root, 1000, []uint32{}); len(w.files) != 4 { // an empty list admits none: the set kinds only
		t.Errorf("empty list: %q", rels(w))
	}
}

func TestWalk_ForeignOwnerCounted(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to own files as another uid")
	}
	root := fixture(t)
	if err := os.Chown(filepath.Join(root, seg(1, 2)), 0, 0); err != nil {
		t.Fatal(err)
	}
	fd, _ := syscall.Open(root, dirFlags, 0)
	defer syscall.Close(fd)
	w := &walk{root: fd, uid: 4242, stanza: stanza, timelines: []uint32{1, 2}, max: 1000}
	// Give every other file to 4242: only the root-owned one is foreign.
	filepath.Walk(root, func(p string, _ os.FileInfo, _ error) error {
		if p != filepath.Join(root, seg(1, 2)) {
			os.Lchown(p, 4242, 4242)
		}
		return nil
	})
	w.run()
	if w.unlisted != 1 || slices.Contains(rels(w), seg(1, 2)) {
		t.Errorf("unlisted %d files %q", w.unlisted, rels(w))
	}
}
