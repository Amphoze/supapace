package repl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/s3x"
)

func puts(f *fake) []string {
	var out []string
	for _, c := range f.callsWith("PUT ") {
		k := strings.Fields(c)[1]
		out = append(out, strings.TrimPrefix(k, f.prefix+"/"+ref+"/"))
	}
	return out
}

func TestCopy_InfoReadFirstUploadedLast(t *testing.T) {
	root := fixture(t)
	var order []string
	// Once the first data file is opened, the info files change on disk: what
	// goes up is what was read before the walk.
	hookOpen(t, func(n string) {
		order = append(order, n)
		if n == filepath.Base(seg(1, 1)) {
			mk(t, root, pBackInfo, "rewritten after the snapshot")
		}
	})
	f := newFake()
	r := run(t, root, input(), nil, f)
	if len(order) < 5 || !slices.Equal(order[:4], infoNames) {
		t.Errorf("opened %q, want the four info files first", order)
	}
	p := puts(f)
	if len(p) != 12 || !slices.Equal(p[8:], []string{pArchInfo, pArchCopy, pBackInfo, pBackCopy}) {
		t.Errorf("puts %q, want the info files last", p)
	}
	if b := f.objs[f.putKey(pBackInfo)][0].body; string(b) != "info "+pBackInfo {
		t.Errorf("backup.info went up as %q", b)
	}
	if len(r.Info) != 4 || r.Info[2].Name != "backup.info" || r.Info[2].SHA256 != sum([]byte("info "+pBackInfo)) || r.Info[2].VersionID == "" {
		t.Errorf("info %+v", r.Info)
	}
	if !r.Complete || r.Stopped != "" {
		t.Errorf("complete %v stopped %q", r.Complete, r.Stopped)
	}
}

func TestCopy_AscendingOrder_HistoryBeforeItsSegments(t *testing.T) {
	root := fixture(t)
	f := newFake()
	run(t, root, input(), nil, f)
	p := puts(f)[:8]
	if !slices.IsSorted(p) {
		t.Errorf("puts not ascending: %q", p)
	}
	if slices.Index(p, pHist2) > slices.Index(p, seg(2, 3)) || slices.Index(p, pHist2) < 0 {
		t.Errorf("history after its segment: %q", p)
	}
}

func TestCopy_StopsAtFirstFailedUpload(t *testing.T) {
	root := fixture(t)
	f := newFake()
	f.failPut = func(k string) error {
		if strings.HasSuffix(k, seg(1, 2)) {
			return errors.New("HTTP 500")
		}
		return nil
	}
	r := run(t, root, input(), nil, f)
	if r.Stopped != "upload-failed" || r.Complete {
		t.Errorf("stopped %q complete %v", r.Stopped, r.Complete)
	}
	p := puts(f)
	if !slices.Equal(p, []string{seg(1, 1), seg(1, 2)}) || !slices.Equal(keys(r.Uploaded), []string{seg(1, 1)}) || len(r.Info) != 0 {
		t.Errorf("puts %q uploaded %q info %d", p, keys(r.Uploaded), len(r.Info))
	}
}

func TestCopy_ChangedDuringReadSkipped(t *testing.T) {
	root := fixture(t)
	hookOpen(t, func(n string) {
		if n == filepath.Base(seg(1, 2)) {
			fh, _ := os.OpenFile(filepath.Join(root, seg(1, 2)), os.O_APPEND|os.O_WRONLY, 0)
			fh.WriteString("more")
			fh.Close()
		}
	})
	f := newFake()
	r := run(t, root, input(), nil, f)
	if slices.Contains(keys(r.Uploaded), seg(1, 2)) || r.Complete || len(r.Info) != 0 {
		t.Errorf("uploaded %q complete %v info %d", keys(r.Uploaded), r.Complete, len(r.Info))
	}
	if !slices.Contains(keys(r.Uploaded), seg(1, 1)) || !slices.Contains(keys(r.Uploaded), seg(2, 3)) {
		t.Errorf("control: uploaded %q", keys(r.Uploaded))
	}
}

func TestCopy_SegmentWithoutItsHistoryHeld(t *testing.T) {
	t.Run("history changed during its read", func(t *testing.T) {
		root := fixture(t)
		mk(t, root, labelOf(2, 3), "label")
		hookOpen(t, func(n string) {
			if n == "00000002.history" {
				mk(t, root, pHist2, "history 2, rewritten")
			}
		})
		f := newFake()
		r := run(t, root, input(), nil, f)
		for _, k := range puts(f) {
			if strings.Contains(k, "/00000002") {
				t.Errorf("uploaded %s of timeline 2", k)
			}
		}
		if r.Held != 2 || r.Stopped != "held" || r.Complete || noticeOf(r, "segment-without-history") == nil {
			t.Errorf("held %d stopped %q complete %v notices %+v", r.Held, r.Stopped, r.Complete, r.Notices)
		}
	})
	t.Run("walk cut inside the segment directory", func(t *testing.T) {
		root := t.TempDir()
		mk(t, root, pHist2, "history 2")
		for n := 1; n <= 3; n++ {
			mk(t, root, seg(2, n), "s")
		}
		// archive, stanza, 17-1, the segment directory, two segments: the history is never reached.
		f := newFake()
		r := run(t, root, input(func(r *jobio.ReplInput) { r.MaxEntries = 6 }), nil, f)
		if len(f.calls) != 0 || r.Held != 2 || r.Stopped != "held" || r.Complete {
			t.Errorf("calls %q held %d stopped %q", f.calls, r.Held, r.Stopped)
		}
		// Control: with the whole walk, the history and then its segments go up.
		f = newFake()
		r = run(t, root, input(), nil, f)
		if r.Held != 0 || len(r.Uploaded) != 4 || r.Uploaded[0].Key != pHist2 {
			t.Errorf("control: held %d uploaded %q", r.Held, keys(r.Uploaded))
		}
	})
}

func TestCopy_HistoryInIndexAdmitsItsSegments(t *testing.T) {
	root := fixture(t)
	hookOpen(t, func(n string) {
		if n == "00000002.history" {
			mk(t, root, pHist2, "history 2, rewritten")
		}
	})
	ix := indexOf(t, jobio.IndexRow{Key: pHist2, Size: 9, Ino: 1, CtimeNS: 1, SHA256: sum([]byte("history 2"))})
	r := run(t, root, input(), ix, newFake())
	if r.Held != 0 || !slices.Contains(keys(r.Uploaded), seg(2, 3)) {
		t.Errorf("held %d uploaded %q", r.Held, keys(r.Uploaded))
	}
	if noticeOf(r, "history-rewritten") == nil {
		t.Error("the recorded history differs from the file: notice expected")
	}
}

func TestCopy_HistoryUploadedEarlierInTheJobAdmitsItsSegments(t *testing.T) {
	root := fixture(t)
	mk(t, root, labelOf(2, 3), "label")
	f := newFake()
	r := run(t, root, input(), nil, f)
	if r.Held != 0 || !slices.Contains(keys(r.Uploaded), seg(2, 3)) || !slices.Contains(keys(r.Uploaded), labelOf(2, 3)) {
		t.Errorf("held %d uploaded %q", r.Held, keys(r.Uploaded))
	}
	// The same history adopted (it exists off-site, equal) admits them too.
	f = newFake()
	f.store(f.putKey(pHist2), []byte("history 2"), map[string]string{"sha256": sum([]byte("history 2"))}, false)
	r = run(t, root, input(), nil, f)
	if r.Held != 0 || !slices.Contains(keys(r.Adopted), pHist2) || !slices.Contains(keys(r.Uploaded), seg(2, 3)) {
		t.Errorf("adopted: held %d adopted %q uploaded %q", r.Held, keys(r.Adopted), keys(r.Uploaded))
	}
}

func TestCopy_Multipart32MiB(t *testing.T) {
	root := fixture(t)
	big := bytes.Repeat([]byte("0123456789abcdef"), (bklimit.PartSize+16)/16)[:bklimit.PartSize+1]
	exact := big[:bklimit.PartSize]
	mk(t, root, pSetFile, string(big))
	other := strings.Replace(pSetFile, "1259", "1260", 1)
	mk(t, root, other, string(exact))
	f := newFake()
	r := run(t, root, input(), nil, f)
	if got := f.callsWith("PART "); len(got) != 2 || !strings.HasSuffix(got[0], fmt.Sprintf(" 1 %d", bklimit.PartSize)) || !strings.HasSuffix(got[1], " 2 1") {
		t.Errorf("parts %q", got)
	}
	o := f.objs[f.putKey(pSetFile)]
	if len(o) != 1 || !bytes.Equal(o[0].body, big) || o[0].meta["sha256"] != sum(big) {
		t.Errorf("the multipart object differs")
	}
	if c := f.callsWith("COMPLETE "); len(c) != 1 || !strings.HasSuffix(c[0], " true") {
		t.Errorf("completion %q, want one with the condition", c)
	}
	// Exactly the part size goes up in one conditional PUT.
	if o := f.objs[f.putKey(other)]; len(o) != 1 || !bytes.Equal(o[0].body, exact) || !slices.Contains(f.calls, "PUT "+f.putKey(other)+" true") {
		t.Errorf("the 32 MiB file was not one conditional PUT")
	}
	if !r.Complete || r.Bytes < int64(2*bklimit.PartSize) {
		t.Errorf("complete %v bytes %d", r.Complete, r.Bytes)
	}
}

func TestCopy_WriteOnceAtTheStore(t *testing.T) {
	root := fixture(t)
	f := newFake()
	run(t, root, input(), nil, f)
	for _, c := range f.callsWith("PUT ") {
		info := strings.Contains(c, ".info ") || strings.Contains(c, ".info.copy ")
		if info != strings.HasSuffix(c, " false") {
			t.Errorf("%s: data files are conditional creates, info files the one overwrite", c)
		}
	}
	// A second run over a changed info file and an unchanged tree adds one info version and nothing else.
	n := len(f.objs)
	mk(t, root, pBackInfo, "new set listed")
	ix := indexOfStore(t, root, f)
	r := run(t, root, input(func(r *jobio.ReplInput) { r.InfoSHA256 = infoSums(root, "backup.info") }), ix, f)
	if len(f.objs) != n || len(f.objs[f.putKey(pBackInfo)]) != 2 || len(r.Uploaded) != 0 || len(r.Info) != 1 {
		t.Errorf("objects %d→%d, backup.info versions %d, uploaded %d, info %d", n, len(f.objs), len(f.objs[f.putKey(pBackInfo)]), len(r.Uploaded), len(r.Info))
	}
}

// indexOfStore is the index the daemon would write after the fake's uploads:
// every data object, with the local file's inode and ctime.
func indexOfStore(t *testing.T, root string, f *fake) *bytes.Reader {
	t.Helper()
	var rows []jobio.IndexRow
	for k := range f.objs {
		rel := strings.TrimPrefix(k, f.prefix+"/"+ref+"/")
		if strings.HasSuffix(rel, ".info") || strings.HasSuffix(rel, ".info.copy") {
			continue
		}
		rows = append(rows, indexed(t, root, rel, true))
	}
	return indexOf(t, rows...)
}

// infoSums are the hashes of the info files on disk, but for the names given.
func infoSums(root string, except ...string) map[string]string {
	m := map[string]string{}
	for _, p := range []string{pArchInfo, pArchCopy, pBackInfo, pBackCopy} {
		if !slices.Contains(except, filepath.Base(p)) {
			b, _ := os.ReadFile(filepath.Join(root, p))
			m[filepath.Base(p)] = sum(b)
		}
	}
	return m
}

func TestCopy_RefusedOrFailedCompletionAbortsItsUpload(t *testing.T) {
	big := strings.Repeat("x", bklimit.PartSize+1)
	t.Run("refused", func(t *testing.T) {
		root := fixture(t)
		mk(t, root, pSetFile, big)
		f := newFake()
		f.failComplete = func(k string) error {
			if strings.HasSuffix(k, pSetFile) {
				f.store(k, []byte("planted"), nil, false) // another writer won the race
				return fmt.Errorf("%w (POST)", s3x.ErrExists)
			}
			return nil
		}
		r := run(t, root, input(), nil, f)
		if a := f.callsWith("ABORT "); len(a) != 1 || !strings.Contains(a[0], pSetFile) || len(f.uploads) != 0 {
			t.Errorf("aborts %q, open uploads %d", a, len(f.uploads))
		}
		if noticeOf(r, "offsite-differs") == nil || slices.Contains(keys(r.Uploaded), pSetFile) {
			t.Errorf("notices %+v uploaded %q", r.Notices, keys(r.Uploaded))
		}
	})
	t.Run("failed", func(t *testing.T) {
		root := fixture(t)
		mk(t, root, pSetFile, big)
		f := newFake()
		f.failComplete = func(string) error { return errors.New("connection reset") }
		r := run(t, root, input(), nil, f)
		if a := f.callsWith("ABORT "); len(a) != 1 || len(f.uploads) != 0 || r.Stopped != "upload-failed" {
			t.Errorf("aborts %q open %d stopped %q", a, len(f.uploads), r.Stopped)
		}
	})
	t.Run("control", func(t *testing.T) {
		root := fixture(t)
		mk(t, root, pSetFile, big)
		f := newFake()
		run(t, root, input(), nil, f)
		if a := f.callsWith("ABORT "); len(a) != 0 {
			t.Errorf("aborted a completed upload: %q", a)
		}
	})
}

func TestCopy_RecordedRowWithoutAHashIsComparedByHeadBeforeItIsSkipped(t *testing.T) {
	root := fixture(t)
	body := []byte("segment 1/1")
	t.Run("equal", func(t *testing.T) {
		f := newFake()
		vid, _ := f.store(f.putKey(seg(1, 1)), body, map[string]string{"sha256": sum(body)}, false)
		ix := indexOf(t, jobio.IndexRow{Key: seg(1, 1), Size: int64(len(body)), Ino: 0, CtimeNS: 0})
		r := run(t, root, input(), ix, f)
		want := indexed(t, root, seg(1, 1), true)
		if len(r.Adopted) != 1 || r.Adopted[0].Key != seg(1, 1) || r.Adopted[0].SHA256 != want.SHA256 || r.Adopted[0].Ino != want.Ino ||
			r.Adopted[0].CtimeNS != want.CtimeNS || r.Adopted[0].VersionID != vid {
			t.Errorf("adopted %+v", r.Adopted)
		}
		if slices.Contains(puts(f), seg(1, 1)) {
			t.Error("uploaded over it")
		}
	})
	t.Run("different", func(t *testing.T) {
		f := newFake()
		f.store(f.putKey(seg(1, 1)), []byte("planted"), map[string]string{"sha256": sum([]byte("planted"))}, false)
		ix := indexOf(t, jobio.IndexRow{Key: seg(1, 1), Size: 7, Ino: 1, CtimeNS: 1})
		r := run(t, root, input(), ix, f)
		if len(r.Adopted) != 0 || slices.Contains(puts(f), seg(1, 1)) || noticeOf(r, "offsite-differs") == nil || len(f.objs[f.putKey(seg(1, 1))]) != 1 {
			t.Errorf("adopted %+v puts %q notices %+v", r.Adopted, puts(f), r.Notices)
		}
	})
	t.Run("a row with a hash and the same file: no request", func(t *testing.T) {
		f := newFake()
		ix := indexOf(t, indexed(t, root, seg(1, 1), true))
		run(t, root, input(), ix, f)
		for _, c := range f.calls {
			if strings.Contains(c, seg(1, 1)) {
				t.Errorf("request %s", c)
			}
		}
	})
}

func TestCopy_AdoptionsCountAgainstTheFileCap(t *testing.T) {
	root := t.TempDir()
	f := newFake()
	for n := 1; n <= 4; n++ {
		b := fmt.Sprintf("s%d", n)
		mk(t, root, seg(1, n), b)
		f.store(f.putKey(seg(1, n)), []byte(b), map[string]string{"sha256": sum([]byte(b))}, false)
	}
	mk(t, root, seg(1, 5), "new")
	r := run(t, root, input(func(r *jobio.ReplInput) { r.MaxFiles = 3 }), nil, f)
	if len(r.Uploaded)+len(r.Adopted) != 3 || r.Stopped != "caps" || r.Complete {
		t.Errorf("uploaded %d adopted %d stopped %q", len(r.Uploaded), len(r.Adopted), r.Stopped)
	}
}

func TestCopy_ExistingEqualAdopted(t *testing.T) {
	root := fixture(t)
	f := newFake()
	b := []byte("segment 1/2")
	vid, _ := f.store(f.putKey(seg(1, 2)), b, map[string]string{"sha256": sum(b)}, false)
	r := run(t, root, input(), nil, f)
	if len(r.Adopted) != 1 || r.Adopted[0].VersionID != vid || r.Adopted[0].SHA256 != sum(b) || len(f.objs[f.putKey(seg(1, 2))]) != 1 {
		t.Errorf("adopted %+v", r.Adopted)
	}
	if !r.Complete {
		t.Error("not complete")
	}
}

func TestCopy_ExistingDifferentNoticed(t *testing.T) {
	root := fixture(t)
	f := newFake()
	f.store(f.putKey(seg(1, 2)), []byte("segment 1/2"), map[string]string{"sha256": sum([]byte("other"))}, false)
	f.store(f.putKey(seg(1, 1)), []byte("other bytes"), nil, false)
	r := run(t, root, input(), nil, f)
	n := noticeOf(r, "offsite-differs")
	if n == nil || n.Count != 2 || len(r.Adopted) != 0 || len(f.objs[f.putKey(seg(1, 2))]) != 1 || len(f.objs[f.putKey(seg(1, 1))]) != 1 {
		t.Errorf("notice %+v adopted %+v", n, r.Adopted)
	}
}

func TestCopy_IndexedFileRewrittenNoticed(t *testing.T) {
	root := fixture(t)
	row := indexed(t, root, seg(1, 1), true)
	row.Ino++
	f := newFake()
	r := run(t, root, input(), indexOf(t, row), f)
	if n := noticeOf(r, "history-rewritten"); n == nil || n.Detail != seg(1, 1) || slices.Contains(puts(f), seg(1, 1)) {
		t.Errorf("notice %+v puts %q", n, puts(f))
	}
}

func TestCopy_InfoOnlyWhenChanged(t *testing.T) {
	root := fixture(t)
	f := newFake()
	r := run(t, root, input(func(r *jobio.ReplInput) { r.InfoSHA256 = infoSums(root, "archive.info", "backup.info.copy") }), nil, f)
	var names []string
	for _, i := range r.Info {
		names = append(names, i.Name)
	}
	if !slices.Equal(names, []string{"archive.info", "backup.info.copy"}) {
		t.Errorf("info %q", names)
	}
}

func TestCopy_Caps_StoppedCaps(t *testing.T) {
	root := fixture(t)
	for _, c := range []func(*jobio.ReplInput){
		func(r *jobio.ReplInput) { r.MaxFiles = 2 },
		func(r *jobio.ReplInput) { r.MaxBytes = 25 },
	} {
		f := newFake()
		r := run(t, root, input(c), nil, f)
		if r.Stopped != "caps" || r.Complete || len(r.Info) != 0 || len(r.Uploaded) > 2 {
			t.Errorf("stopped %q uploaded %q", r.Stopped, keys(r.Uploaded))
		}
	}
}

func TestCopy_BudgetLeft_StoppedBudget(t *testing.T) {
	root := fixture(t)
	for _, c := range []func(*jobio.ReplInput){
		func(r *jobio.ReplInput) { r.BudgetBytes = 0 },
		func(r *jobio.ReplInput) { r.BudgetBytes = 30 },
		func(r *jobio.ReplInput) { r.BudgetObjects = 0 },
		func(r *jobio.ReplInput) { r.BudgetObjects = 3 },
	} {
		f := newFake()
		r := run(t, root, input(c), nil, f)
		if r.Stopped != "budget" || r.Complete || len(r.Uploaded) > 3 {
			t.Errorf("stopped %q uploaded %q", r.Stopped, keys(r.Uploaded))
		}
	}
	// -1: no budget.
	if r := run(t, root, input(), nil, newFake()); r.Stopped != "" {
		t.Errorf("control: stopped %q", r.Stopped)
	}
}

func TestCopy_SizeBoundsPerKind(t *testing.T) {
	root := fixture(t)
	sparse := func(rel string, size int64) {
		mk(t, root, rel, "")
		if err := os.Truncate(filepath.Join(root, rel), size); err != nil {
			t.Fatal(err)
		}
	}
	sparse(seg(1, 5), bklimit.SegmentMax+1)
	sparse(seg(1, 6), bklimit.SegmentMax)
	sparse("archive/"+stanza+"/17-1/00000003.history", bklimit.SmallMax+1)
	sparse(labelOf(1, 6), bklimit.SmallMax+1)
	sparse(strings.Replace(pSetFile, "1259", "2000", 1), bklimit.SegmentMax+1)
	in := input(func(r *jobio.ReplInput) { r.MaxBytes = 1 << 30 })
	in.Timelines = []uint32{1, 2, 3}
	r := run(t, root, in, nil, newFake())
	u := keys(r.Uploaded)
	if slices.Contains(u, seg(1, 5)) || slices.Contains(u, labelOf(1, 6)) || !slices.Contains(u, seg(1, 6)) ||
		!slices.Contains(u, strings.Replace(pSetFile, "1259", "2000", 1)) {
		t.Errorf("uploaded %q", u)
	}
	if n := noticeOf(r, "unreadable-entry"); n == nil || n.Count != 3 {
		t.Errorf("unreadable %+v, want 3 (segment, history, label over their bounds)", n)
	}
}

func TestCopy_SetsComplete(t *testing.T) {
	root := fixture(t)
	second := "20261119-010101F"
	m2 := "backup/" + stanza + "/" + second + "/backup.manifest"
	f2 := "backup/" + stanza + "/" + second + "/pg_data/base/1/1"
	mk(t, root, m2, "m2")
	mk(t, root, f2, "f2")
	hookOpen(t, func(n string) {
		if n == "1" { // f2 changes while read: its set is not complete this cycle
			mk(t, root, f2, "f2 longer")
		}
	})
	r := run(t, root, input(), nil, newFake())
	if !slices.Equal(r.SetsComplete, []string{label}) {
		t.Errorf("sets complete %q", r.SetsComplete)
	}
	// Recorded in the index, the first set is complete without an upload.
	root2 := fixture(t)
	ix := indexOf(t, indexed(t, root2, pManifest, true), indexed(t, root2, pManCopy, true), indexed(t, root2, pSetFile, true))
	r = run(t, root2, input(), ix, newFake())
	if !slices.Equal(r.SetsComplete, []string{label}) || slices.Contains(keys(r.Uploaded), pManifest) {
		t.Errorf("indexed: sets %q uploaded %q", r.SetsComplete, keys(r.Uploaded))
	}
}

func TestCopy_ManyValidNames_BoundedByCaps(t *testing.T) {
	root := t.TempDir()
	for n := 1; n <= 3000; n++ {
		mk(t, root, seg(1, n), "")
	}
	f := newFake()
	r := run(t, root, input(), nil, f)
	if len(r.Uploaded) != bklimit.ReplMaxFiles || r.Stopped != "caps" || len(f.callsWith("PUT ")) != bklimit.ReplMaxFiles {
		t.Errorf("uploaded %d stopped %q puts %d", len(r.Uploaded), r.Stopped, len(f.callsWith("PUT ")))
	}
	// A file cap above the constant is the constant.
	r = run(t, root, input(func(r *jobio.ReplInput) { r.MaxFiles = 1 << 20 }), nil, newFake())
	if len(r.Uploaded) != bklimit.ReplMaxFiles {
		t.Errorf("uploaded %d", len(r.Uploaded))
	}
}

func TestCopy_ResultUnderOneMiBAtTheFileCap(t *testing.T) {
	root := fixture(t)
	dir := "backup/" + stanza + "/" + label + "/pg_data/" + strings.Repeat("d", 200) + "/" + strings.Repeat("e", 200) + "/"
	for n := 0; n < 2100; n++ {
		mk(t, root, dir+fmt.Sprintf("%s%05d", strings.Repeat("f", 100), n), "")
	}
	f := newFake()
	r := run(t, root, input(), nil, f)
	line, err := jobio.MarshalResult(r)
	if err != nil || len(line) > bklimit.ResultMax {
		t.Fatalf("%d bytes, %v", len(line), err)
	}
	if r.Stopped != "caps" || len(r.Uploaded) < 1000 {
		t.Errorf("stopped %q uploaded %d", r.Stopped, len(r.Uploaded))
	}
	if _, _, err := jobio.ParseResult("replicate", line); err != nil {
		t.Errorf("the line does not parse: %v", err)
	}
}

func TestCopy_RefusesAnInputOfAnotherShape(t *testing.T) {
	root := fixture(t)
	for _, in := range []jobio.Input{
		func() jobio.Input { i := input(); i.Repl.Mode = "rebuild"; return i }(),
		func() jobio.Input { i := input(); i.Stanza = "zzzzzzzzzz0123456789-1"; return i }(),
		func() jobio.Input { i := input(); i.Repl = nil; return i }(),
	} {
		if _, err := Copy(context.Background(), in, root, nilIndex(), newFake()); err == nil {
			t.Errorf("accepted %+v", in)
		}
	}
	f := newFake()
	f.prefix = "/bad"
	if _, err := Copy(context.Background(), input(), root, nilIndex(), f); err == nil {
		t.Error("accepted a bad prefix")
	}
}

// A file rewritten in place after the listing, to the same length, is not
// the listed file: its times differ, and it is skipped for the cycle.
func TestCopy_RewrittenInPlaceSameSizeSkipped(t *testing.T) {
	root := fixture(t)
	hookOpen(t, func(n string) {
		if n == filepath.Base(seg(1, 2)) {
			fh, _ := os.OpenFile(filepath.Join(root, seg(1, 2)), os.O_WRONLY, 0)
			fh.WriteString("SEGMENT 1/2")
			fh.Close()
		}
	})
	r := run(t, root, input(), nil, newFake())
	if slices.Contains(keys(r.Uploaded), seg(1, 2)) || r.Complete {
		t.Errorf("uploaded %q complete %v", keys(r.Uploaded), r.Complete)
	}
}
