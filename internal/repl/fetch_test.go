package repl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/s3x"
)

// fetchIn is a project's fetch input by plan.
func fetchIn(mut ...func(*jobio.Input)) jobio.Input {
	in := jobio.Input{Job: 9, Kind: "fetch", Subject: ref, Stanza: stanza, UID: os.Getuid(), Timelines: []uint32{1, 2}, MaxBytes: 1 << 30}
	for _, m := range mut {
		m(&in)
	}
	return in
}

// cpIn is the control plane's fetch input for stanza.
func cpIn(st string, mut ...func(*jobio.Input)) jobio.Input {
	in := jobio.Input{Job: 9, Kind: "fetch", Subject: "cp", Stanza: st, UID: 70, MaxBytes: 1 << 30, ListCurrent: true}
	for _, m := range mut {
		m(&in)
	}
	return in
}

func planOf(t testing.TB, rows ...jobio.PlanRow) io.Reader {
	t.Helper()
	var b bytes.Buffer
	if err := jobio.WritePlan(&b, rows); err != nil {
		t.Fatal(err)
	}
	return &b
}

// put stores body as a new version of key in f and returns its version id.
func put(f *fake, key, body string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	vid, err := f.store(key, []byte(body), map[string]string{"sha256": sum([]byte(body))}, false)
	if err != nil {
		panic(err)
	}
	return vid
}

// marker puts a delete marker on top of key.
func marker(f *fake, key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	f.objs[key] = append(f.objs[key], fakeObj{vid: fmt.Sprintf("m%06d", f.n), marker: true})
}

// row is the plan row of rel as the record holds it after a copy.
func row(f *fake, rel, body string) jobio.PlanRow {
	vs := f.objs[f.putKey(rel)]
	return jobio.PlanRow{Key: rel, VersionID: vs[0].vid, SHA256: sum([]byte(body)), Size: int64(len(body))}
}

// gets records the version id of every GET.
type gets struct {
	*fake
	vids []string
}

func (g *gets) Get(ctx context.Context, key, vid string, w io.Writer, max int64) (s3x.Object, error) {
	g.mu.Lock()
	g.vids = append(g.vids, key+"@"+vid)
	g.mu.Unlock()
	return g.fake.Get(ctx, key, vid, w, max)
}

func fetch(t *testing.T, in jobio.Input, plan io.Reader, st Store) (string, jobio.FetchResult, error) {
	t.Helper()
	dest := t.TempDir()
	r, err := Fetch(context.Background(), in, plan, dest, st)
	if err == nil {
		line, merr := jobio.MarshalResult(r)
		if merr != nil {
			t.Fatal(merr)
		}
		if _, _, perr := jobio.ParseResult("fetch", line); perr != nil {
			t.Fatalf("the result does not read back: %v", perr)
		}
	}
	return dest, r, err
}

// tree is every regular file under dest, by relative path, with its body.
func tree(t *testing.T, dest string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dest, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if d.Type().IsRegular() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(dest, p)
			out[rel] = string(b)
		}
		return nil
	})
	return out
}

func TestFetch_ByVersionID_VerifiesHash(t *testing.T) {
	f := newFake()
	put(f, f.putKey(pHist2), "history 2")
	put(f, f.putKey(pHist2), "a newer version") // never the recorded one
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	g := &gets{fake: f}
	dest, r, err := fetch(t, fetchIn(), planOf(t, row(f, pHist2, "history 2"), row(f, seg(1, 1), "segment 1/1")), g)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{pHist2: "history 2", seg(1, 1): "segment 1/1"}
	if got := tree(t, dest); fmt.Sprint(got) != fmt.Sprint(want) || r.Files != 2 || r.Bytes != int64(len("history 2segment 1/1")) {
		t.Errorf("fetched %q, result %+v", got, r)
	}
	if r.NewestSegment != "" || r.NewestSet != "" {
		t.Errorf("a fetch by plan reports %+v", r)
	}
	for _, v := range g.vids {
		if strings.HasSuffix(v, "@") || strings.HasSuffix(v, "@v000002") {
			t.Errorf("GET %s: not the recorded version", v)
		}
	}
}

func TestFetch_OldestWhenNoVersion(t *testing.T) {
	f := newFake()
	put(f, f.putKey(pHist2), "history 2")
	put(f, f.putKey(pHist2), "forged") // a newer version, written with the write credential
	marker(f, f.putKey(pHist2))        // and a delete marker on top
	put(f, f.putKey(pHist2)+"x", "a key with the planned one as its prefix")
	f.page = 1 // a key's versions across pages
	g := &gets{fake: f}
	rebuilt := jobio.PlanRow{Key: pHist2, Size: int64(len("history 2"))} // a rebuilt row: no version, no hash
	dest, _, err := fetch(t, fetchIn(), planOf(t, rebuilt), g)
	if err != nil {
		t.Fatal(err)
	}
	if got := tree(t, dest)[pHist2]; got != "history 2" {
		t.Errorf("fetched %q, want the oldest version", got)
	}
	if !slices.Equal(g.vids, []string{f.putKey(pHist2) + "@v000001"}) {
		t.Errorf("GETs %q", g.vids)
	}
	// A delete marker below the oldest object is never the version taken.
	marker(f, f.putKey(pHist2)+".x")
	under := f.putKey(seg(1, 1))
	marker(f, under)
	put(f, under, "segment 1/1")
	dest, _, err = fetch(t, fetchIn(), planOf(t, jobio.PlanRow{Key: seg(1, 1), Size: 11}), f)
	if err != nil || tree(t, dest)[seg(1, 1)] != "segment 1/1" {
		t.Errorf("a marker below: %v %q", err, tree(t, dest))
	}
	// Control: with a hash, a row without a version id is verified too.
	f2 := newFake()
	put(f2, f2.putKey(pHist2), "history 2")
	rebuilt.SHA256 = sum([]byte("history 2"))
	if _, _, err := fetch(t, fetchIn(), planOf(t, rebuilt), f2); err != nil {
		t.Errorf("control: %v", err)
	}
}

func TestFetch_HashMismatchFails(t *testing.T) {
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	r := row(f, seg(1, 1), "segment 1/1")
	r.SHA256 = sum([]byte("segment 1/X"))
	dest, _, err := fetch(t, fetchIn(), planOf(t, r), f)
	if !errors.Is(err, ErrMismatch) || len(tree(t, dest)) != 0 {
		t.Errorf("hash: %v, left %q", err, tree(t, dest))
	}
	// A row without a hash is checked by its size; so is a row with one.
	for _, size := range []int64{10, 12} {
		r := jobio.PlanRow{Key: seg(1, 1), VersionID: "v000001", Size: size}
		if _, _, err := fetch(t, fetchIn(), planOf(t, r), clientGet{f}); !errors.Is(err, ErrMismatch) {
			t.Errorf("size %d: %v", size, err)
		}
	}
	// The store answers another version than asked for.
	other := &otherVersion{f}
	if _, _, err := fetch(t, fetchIn(), planOf(t, row(f, seg(1, 1), "segment 1/1")), other); !errors.Is(err, ErrMismatch) {
		t.Errorf("another version: %v", err)
	}
	// Control: the right hash and size.
	if _, _, err := fetch(t, fetchIn(), planOf(t, row(f, seg(1, 1), "segment 1/1")), f); err != nil {
		t.Errorf("control: %v", err)
	}
}

type otherVersion struct{ *fake }

func (o *otherVersion) Get(ctx context.Context, key, vid string, w io.Writer, max int64) (s3x.Object, error) {
	ob, err := o.fake.Get(ctx, key, vid, w, max)
	ob.VersionID += "x"
	return ob, err
}

func TestFetch_MissingFails(t *testing.T) {
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	put(f, f.putKey(seg(1, 2)), "segment 1/2")
	marker(f, f.putKey(seg(1, 2)))
	marker(f, f.putKey(seg(1, 3))) // markers only
	for name, r := range map[string]jobio.PlanRow{
		"unknown version":   {Key: seg(1, 1), VersionID: "v999999", Size: 11},
		"absent key":        {Key: seg(1, 4), Size: 11},
		"markers only":      {Key: seg(1, 3), Size: 11},
		"version of a gone": {Key: seg(2, 3), VersionID: "v000001", Size: 11},
	} {
		dest, _, err := fetch(t, fetchIn(), planOf(t, r), f)
		if !errors.Is(err, ErrMissing) || len(tree(t, dest)) != 0 {
			t.Errorf("%s: %v %q", name, err, tree(t, dest))
		}
	}
	// Control: a deleted key is fetched by its recorded version.
	if _, _, err := fetch(t, fetchIn(), planOf(t, row(f, seg(1, 2), "segment 1/2")), f); err != nil {
		t.Errorf("control: %v", err)
	}
}

func TestFetch_PathRevalidated(t *testing.T) {
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	good := row(f, seg(1, 1), "segment 1/1")
	for name, rel := range map[string]string{
		"dot-dot":               "archive/" + stanza + "/17-1/../../../../etc/passwd",
		"unlisted":              "archive/" + stanza + "/notes.txt",
		"another stanza":        strings.Replace(seg(1, 1), stanza, ref+"-2", 1),
		"another subject":       strings.Replace(seg(1, 1), stanza, "zyxwvutsrq9876543210-1", 1),
		"timeline not admitted": seg(3, 1),
		"the latest link":       pLatest,
		"absolute":              "/" + seg(1, 1),
	} {
		f.calls = nil
		dest, _, err := fetch(t, fetchIn(), planOf(t, good, jobio.PlanRow{Key: rel, Size: 1}), f)
		if !errors.Is(err, ErrPath) || len(f.calls) != 0 || len(tree(t, dest)) != 0 {
			t.Errorf("%s: %v, calls %q", name, err, f.calls)
		}
	}
	for name, plan := range map[string][]jobio.PlanRow{
		"twice":           {good, good},
		"above its bound": {good, {Key: pHist2, Size: bklimit.SmallMax + 1}},
		"bad version id":  {good, {Key: pHist2, VersionID: strings.Repeat("v", versionMax+1), Size: 1}},
	} {
		f.calls = nil
		if _, _, err := fetch(t, fetchIn(), planOf(t, plan...), f); !errors.Is(err, ErrPath) || len(f.calls) != 0 {
			t.Errorf("%s: %v, calls %q", name, err, f.calls)
		}
	}
	// A plan that does not read is an input error, before any request.
	f.calls = nil
	if _, err := Fetch(context.Background(), fetchIn(), strings.NewReader("no tabs\n"), t.TempDir(), f); !errors.Is(err, ErrInput) || len(f.calls) != 0 {
		t.Errorf("malformed: %v %q", err, f.calls)
	}
	// Control: the good row alone is fetched.
	f.calls = nil
	if _, _, err := fetch(t, fetchIn(), planOf(t, good), f); err != nil || len(f.calls) == 0 {
		t.Errorf("control: %v %q", err, f.calls)
	}
}

func TestFetch_ExclusiveCreate_LinkAtTargetFails(t *testing.T) {
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	plan := func() io.Reader { return planOf(t, row(f, seg(1, 1), "segment 1/1")) }
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("kept"), 0o644)
	for name, prep := range map[string]func(dest string){
		"a link at the file": func(dest string) {
			os.MkdirAll(filepath.Join(dest, filepath.Dir(seg(1, 1))), 0o755)
			os.Symlink(outside, filepath.Join(dest, seg(1, 1)))
		},
		"a dangling link at the file": func(dest string) {
			os.MkdirAll(filepath.Join(dest, filepath.Dir(seg(1, 1))), 0o755)
			os.Symlink(outside+".new", filepath.Join(dest, seg(1, 1)))
		},
		"a link at a directory": func(dest string) {
			os.Symlink(filepath.Dir(outside), filepath.Join(dest, "archive"))
		},
		"a file there": func(dest string) {
			mk(t, dest, seg(1, 1), "stale")
		},
	} {
		dest := t.TempDir()
		prep(dest)
		if _, err := Fetch(context.Background(), fetchIn(), plan(), dest, f); !errors.Is(err, ErrPath) {
			t.Errorf("%s: %v", name, err)
		}
		if b, _ := os.ReadFile(outside); string(b) != "kept" {
			t.Errorf("%s: the file outside is %q", name, b)
		}
		if ents, _ := os.ReadDir(filepath.Dir(outside)); len(ents) != 1 {
			t.Errorf("%s: written outside: %v", name, ents)
		}
	}
	// The destination itself is a link.
	link := filepath.Join(t.TempDir(), "fetch")
	os.Symlink(filepath.Dir(outside), link)
	if _, err := Fetch(context.Background(), fetchIn(), plan(), link, f); !errors.Is(err, ErrPath) {
		t.Errorf("a linked destination: %v", err)
	}
	// Control: an empty destination.
	if _, _, err := fetch(t, fetchIn(), plan(), f); err != nil {
		t.Errorf("control: %v", err)
	}
}

func TestFetch_Modes0640_2750(t *testing.T) {
	old := syscall.Umask(0o077) // the modes are set, not left to the mask
	defer syscall.Umask(old)
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	put(f, f.putKey(pManifest), "manifest")
	dest, _, err := fetch(t, fetchIn(), planOf(t, row(f, seg(1, 1), "segment 1/1"), row(f, pManifest, "manifest")), f)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	filepath.WalkDir(dest, func(p string, d fs.DirEntry, err error) error {
		if p == dest {
			return nil
		}
		fi, _ := os.Lstat(p)
		want := fs.FileMode(0o640)
		if d.IsDir() {
			want = fs.ModeDir | fs.ModeSetgid | 0o750
		}
		if fi.Mode() != want {
			t.Errorf("%s: %v, want %v", p, fi.Mode(), want)
		}
		n++
		return nil
	})
	if n != 9 { // archive, stanza, 17-1, the segment directory, the segment; backup, stanza, the set, its manifest
		t.Errorf("%d entries", n)
	}
}

func TestFetch_QuotaErrorCode(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EDQUOT, syscall.ENOSPC} {
		old := fileWrite
		fileWrite = func(f *os.File, b []byte) (int, error) { return 0, errno }
		f := newFake()
		put(f, f.putKey(seg(1, 1)), "segment 1/1")
		dest, _, err := fetch(t, fetchIn(), planOf(t, row(f, seg(1, 1), "segment 1/1")), f)
		fileWrite = old
		if !errors.Is(err, ErrQuota) || len(tree(t, dest)) != 0 {
			t.Errorf("%v: %v %q", errno, err, tree(t, dest))
		}
	}
	// Another write error is not the quota.
	old := fileWrite
	fileWrite = func(f *os.File, b []byte) (int, error) { return 0, syscall.EIO }
	defer func() { fileWrite = old }()
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	if _, _, err := fetch(t, fetchIn(), planOf(t, row(f, seg(1, 1), "segment 1/1")), f); !errors.Is(err, ErrPath) {
		t.Errorf("EIO: %v, want the destination's code", err)
	}
}

func TestFetch_StopsAtMaxBytes(t *testing.T) {
	f := newFake()
	bodies := []string{"segment 1/1", "segment 1/2", "segment 1/3"}
	var plan []jobio.PlanRow
	for i, b := range bodies {
		put(f, f.putKey(seg(1, i+1)), b)
		plan = append(plan, row(f, seg(1, i+1), b))
	}
	limit := int64(len(bodies[0])+len(bodies[1])) + 5
	dest, _, err := fetch(t, fetchIn(func(in *jobio.Input) { in.MaxBytes = limit }), planOf(t, plan...), f)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v", err)
	}
	var n int64
	for _, b := range tree(t, dest) {
		n += int64(len(b))
	}
	if n > limit || len(tree(t, dest)) != 2 {
		t.Errorf("%d bytes written of a limit of %d: %q", n, limit, tree(t, dest))
	}
	// Exactly the sum fits.
	if _, r, err := fetch(t, fetchIn(func(in *jobio.Input) { in.MaxBytes = int64(len(strings.Join(bodies, ""))) }), planOf(t, plan...), f); err != nil || r.Files != 3 {
		t.Errorf("at the limit: %v %+v", err, r)
	}
}

// An info file's plan row carries its kind's bound, not its size.
func TestFetch_InfoRowSizeIsABound(t *testing.T) {
	f := newFake()
	put(f, f.putKey(pBackInfo), "backup info")
	r := row(f, pBackInfo, "backup info")
	r.Size = bklimit.SmallMax
	dest, res, err := fetch(t, fetchIn(), planOf(t, r), f)
	if err != nil || tree(t, dest)[pBackInfo] != "backup info" || res.Bytes != int64(len("backup info")) {
		t.Errorf("%v %+v", err, res)
	}
	// A data file's size is its size.
	put(f, f.putKey(pManifest), "manifest")
	r = row(f, pManifest, "manifest")
	r.Size = bklimit.SmallMax
	if _, _, err := fetch(t, fetchIn(), planOf(t, r), f); !errors.Is(err, ErrMismatch) {
		t.Errorf("a data file under a bound: %v", err)
	}
	// An info body above its bound.
	put(f, f.putKey(pArchInfo), strings.Repeat("i", 100))
	r = row(f, pArchInfo, strings.Repeat("i", 100))
	r.Size = 99
	if _, _, err := fetch(t, fetchIn(), planOf(t, r), f); err == nil {
		t.Error("an info body above its row's bound was taken")
	}
}

func TestFetch_InputRefused(t *testing.T) {
	f := newFake()
	plan := func() io.Reader { return strings.NewReader("") }
	for name, in := range map[string]jobio.Input{
		"another kind":      fetchIn(func(in *jobio.Input) { in.Kind = "seed" }),
		"no byte limit":     fetchIn(func(in *jobio.Input) { in.MaxBytes = 0 }),
		"a negative limit":  fetchIn(func(in *jobio.Input) { in.MaxBytes = -1 }),
		"another's stanza":  fetchIn(func(in *jobio.Input) { in.Stanza = "zyxwvutsrq9876543210-1" }),
		"a replication job": fetchIn(func(in *jobio.Input) { in.Repl = &jobio.ReplInput{Mode: "copy"} }),
	} {
		if _, err := Fetch(context.Background(), in, plan(), t.TempDir(), f); !errors.Is(err, ErrInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Fetch(context.Background(), fetchIn(), nil, t.TempDir(), f); !errors.Is(err, ErrInput) {
		t.Errorf("no plan: %v", err)
	}
	if _, err := Fetch(context.Background(), cpIn("cp-1"), plan(), t.TempDir(), f); !errors.Is(err, ErrInput) {
		t.Errorf("a plan with list_current: %v", err)
	}
	f.prefix = "a//b"
	if _, err := Fetch(context.Background(), fetchIn(), plan(), t.TempDir(), f); !errors.Is(err, ErrInput) {
		t.Errorf("a bad prefix: %v", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("calls %q", f.calls)
	}
}

func TestFetchBound_BelowTheDeadline(t *testing.T) {
	for _, mb := range []int{1, 8192, 1 << 20} {
		d, err := bklimit.Deadline("fetch", 0, mb)
		if err != nil {
			t.Fatal(err)
		}
		if b := FetchBound(int64(mb) << 20); b+cleanupMax+10*time.Second > d || b <= CallTimeout {
			t.Errorf("%d MiB: bound %v against the deadline %v", mb, b, d)
		}
	}
	if b := FetchBound(1<<62 + 5); b <= 0 {
		t.Errorf("a huge limit: %v", b)
	}
}

func TestCodes_Fetch(t *testing.T) {
	want := []string{"input", "credential", "path", "missing", "mismatch", "quota", "too_large", "store", "result"}
	if got := Codes("fetch"); !slices.Equal(got, want) {
		t.Errorf("fetch: %q", got)
	}
}

// The control plane's fixture: its keys under "<prefix>/cp/".
func cpKey(f *fake, rel string) string { return f.prefix + "/cp/" + rel }

func cpRel(st, rel string) string { return strings.Replace(rel, stanza, st, 1) }

func TestFetch_ListCurrent_ControlPlaneOnly(t *testing.T) {
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	for _, in := range []jobio.Input{
		fetchIn(func(in *jobio.Input) { in.ListCurrent = true }),
		cpIn(ref+"-1", func(in *jobio.Input) { in.Subject = ref }),
	} {
		if _, err := Fetch(context.Background(), in, nil, t.TempDir(), f); !errors.Is(err, ErrPath) || len(f.calls) != 0 {
			t.Errorf("a project's list_current: %v %q", err, f.calls)
		}
	}
	// For cp: the oldest version of a write-once key, the newest of an info
	// file, an unlisted key refused, the newest set with a manifest.
	const st = "cp-1"
	put(f, cpKey(f, cpRel(st, seg(1, 1))), "segment 1/1")
	put(f, cpKey(f, cpRel(st, seg(1, 1))), "forged")
	put(f, cpKey(f, cpRel(st, pBackInfo)), "old info")
	put(f, cpKey(f, cpRel(st, pBackInfo)), "current info")
	unlisted := cpKey(f, "backup/"+st+"/folder.txt")
	put(f, unlisted, "a stray key")
	older, newer, newest := "20261101-000000F", "20261102-000000F", "20261103-000000F"
	for _, l := range []string{older, newer} {
		put(f, cpKey(f, "backup/"+st+"/"+l+"/backup.manifest"), "manifest "+l)
	}
	put(f, cpKey(f, "backup/"+st+"/"+newest+"/pg_data/PG_VERSION"), "a set without its manifest")
	g := &gets{fake: f}
	dest, r, err := fetch(t, cpIn(st), nil, g)
	if err != nil {
		t.Fatal(err)
	}
	got := tree(t, dest)
	if got[cpRel(st, seg(1, 1))] != "segment 1/1" || got[cpRel(st, pBackInfo)] != "current info" || r.NewestSet != newer || r.Files != 5 {
		t.Errorf("fetched %q, result %+v", got, r)
	}
	for _, v := range g.vids {
		if strings.HasPrefix(v, unlisted+"@") {
			t.Errorf("the unlisted key was requested")
		}
	}
	// The byte limit is kept.
	if _, _, err := fetch(t, cpIn(st, func(in *jobio.Input) { in.MaxBytes = 20 }), nil, f); !errors.Is(err, ErrTooLarge) {
		t.Errorf("byte limit: %v", err)
	}
}

func TestFetch_ListCurrent_NoSetIsMissing(t *testing.T) {
	f := newFake()
	const st = "cp-1"
	put(f, cpKey(f, cpRel(st, seg(1, 1))), "segment 1/1")
	put(f, cpKey(f, cpRel(st, pBackInfo)), "info")
	put(f, cpKey(f, "backup/"+st+"/"+label+"/backup.manifest.copy"), "only the copy")
	if _, _, err := fetch(t, cpIn(st), nil, f); !errors.Is(err, ErrMissing) {
		t.Errorf("%v", err)
	}
	// Control: with the manifest.
	put(f, cpKey(f, cpRel(st, pManifest)), "manifest")
	if _, r, err := fetch(t, cpIn(st), nil, f); err != nil || r.NewestSet != label {
		t.Errorf("control: %v %+v", err, r)
	}
}

func TestFetch_ListCurrent_OnlyTheNamedStanzasTwoTrees(t *testing.T) {
	f := newFake()
	const st = "cp-7"
	mine := []string{cpRel(st, seg(1, 1)), cpRel(st, pManifest)}
	for _, rel := range mine {
		put(f, cpKey(f, rel), rel)
	}
	foreign := []string{
		cpKey(f, cpRel("cp-74", seg(1, 2))), cpKey(f, cpRel("cp-74", pManifest)), // a stanza with st as its prefix
		cpKey(f, cpRel("cp-2", seg(1, 3))),
		cpKey(f, "other/"+st+"/x"), cpKey(f, "archive.info"), f.prefix + "/" + ref + "/" + seg(1, 4),
	}
	for _, k := range foreign {
		put(f, k, "foreign")
	}
	g := &gets{fake: f}
	dest, r, err := fetch(t, cpIn(st), nil, g)
	if err != nil || len(tree(t, dest)) != 2 || r.Files != 2 {
		t.Fatalf("%v %q %+v", err, tree(t, dest), r)
	}
	for _, c := range f.callsWith("LIST ") {
		if c != "LIST "+cpKey(f, "archive/"+st+"/") && c != "LIST "+cpKey(f, "backup/"+st+"/") {
			t.Errorf("listed %s", c)
		}
	}
	for _, v := range g.vids {
		for _, k := range foreign {
			if strings.HasPrefix(v, k+"@") {
				t.Errorf("requested %s", k)
			}
		}
	}
}

func TestFetch_ListCurrent_WriteOnceKeysAtTheirOldestVersion(t *testing.T) {
	f := newFake()
	const st = "cp-1"
	hist := cpRel(st, pHist2)
	for _, rel := range []string{cpRel(st, seg(1, 1)), hist, cpRel(st, pSetFile), cpRel(st, pManifest)} {
		put(f, cpKey(f, rel), "first "+rel)
		put(f, cpKey(f, rel), "newer")
	}
	f.page = 1
	dest, _, err := fetch(t, cpIn(st), nil, f)
	if err != nil {
		t.Fatal(err)
	}
	got := tree(t, dest)
	for _, rel := range []string{cpRel(st, seg(1, 1)), hist, cpRel(st, pSetFile), cpRel(st, pManifest)} {
		if got[rel] != "first "+rel {
			t.Errorf("%s: %q", rel, got[rel])
		}
	}
}

func TestFetch_ListCurrent_InfoFilesAtTheirCurrentVersion(t *testing.T) {
	f := newFake()
	const st = "cp-1"
	infos := []string{cpRel(st, pArchInfo), cpRel(st, pArchCopy), cpRel(st, pBackInfo), cpRel(st, pBackCopy)}
	for _, rel := range infos {
		put(f, cpKey(f, rel), "old")
		put(f, cpKey(f, rel), "current "+rel)
	}
	put(f, cpKey(f, cpRel(st, pManifest)), "manifest")
	dest, _, err := fetch(t, cpIn(st), nil, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range infos {
		if got := tree(t, dest)[rel]; got != "current "+rel {
			t.Errorf("%s: %q", rel, got)
		}
	}
}

func TestFetch_ListCurrent_ADeleteMarkerIsNeverAVersion(t *testing.T) {
	f := newFake()
	const st = "cp-1"
	once, info, gone := cpRel(st, seg(1, 1)), cpRel(st, pBackInfo), cpRel(st, seg(1, 2))
	marker(f, cpKey(f, once)) // a marker below the oldest object
	put(f, cpKey(f, once), "oldest object")
	put(f, cpKey(f, once), "newer")
	put(f, cpKey(f, info), "older info")
	put(f, cpKey(f, info), "newest object")
	marker(f, cpKey(f, info)) // the current version is a marker
	marker(f, cpKey(f, gone))
	marker(f, cpKey(f, gone))
	put(f, cpKey(f, cpRel(st, pManifest)), "manifest")
	g := &gets{fake: f}
	dest, _, err := fetch(t, cpIn(st), nil, g)
	if err != nil {
		t.Fatal(err)
	}
	got := tree(t, dest)
	if got[once] != "oldest object" || got[info] != "newest object" {
		t.Errorf("%q", got)
	}
	if _, ok := got[gone]; ok {
		t.Error("a key of markers only was fetched")
	}
	for _, v := range g.vids {
		if strings.HasPrefix(v, cpKey(f, gone)) || strings.Contains(v, "@m") {
			t.Errorf("GET %s", v)
		}
	}
}

func TestFetch_ListCurrent_ReportsNewestSegment(t *testing.T) {
	f := newFake()
	const st = "cp-1"
	segOf := func(tli, n int) string { return cpRel(st, seg(tli, n)) }
	for _, rel := range []string{segOf(1, 1), segOf(1, 6), segOf(2, 5), cpRel(st, pHist2), cpRel(st, pManifest),
		cpRel(st, strings.Replace(pHist2, "00000002", "00000003", 1)), cpRel(st, labelOf(2, 9))} {
		put(f, cpKey(f, rel), rel)
	}
	_, r, err := fetch(t, cpIn(st), nil, f)
	if want := fmt.Sprintf("%08X%08X%08X", 1, 0, 6); err != nil || r.NewestSegment != want {
		t.Errorf("%v: newest %q, want %q (the highest number, whatever its timeline; a label is no segment)", err, r.NewestSegment, want)
	}
}

// pagesForEver never ends its pages: each holds one fresh version.
type pagesForEver struct {
	*fake
	n int
}

func (p *pagesForEver) ListVersions(ctx context.Context, prefix, km, vm string) ([]s3x.Object, string, string, error) {
	p.n++
	k := fmt.Sprintf("%sarchive.info", prefix)
	v := fmt.Sprintf("v%d", p.n)
	return []s3x.Object{{Key: k, VersionID: v, DeleteMarker: true}}, k, v, nil
}

func TestFetch_ListCurrent_PagingCapped(t *testing.T) {
	p := &pagesForEver{fake: newFake()}
	_, err := Fetch(context.Background(), cpIn("cp-1", func(in *jobio.Input) { in.MaxBytes = 1 }), nil, t.TempDir(), p)
	if err == nil || !strings.Contains(err.Error(), "listing above 2048 pages") || errors.Is(err, ErrTooLarge) || errors.Is(err, ErrMissing) {
		t.Errorf("%v", err)
	}
	if p.n != ListCurrentMaxPages || ListCurrentMaxPages != 2048 {
		t.Errorf("%d pages listed", p.n)
	}
	// A fetch by plan of a row without a version is capped the same.
	p.n = 0
	_, err = Fetch(context.Background(), fetchIn(), planOf(t, jobio.PlanRow{Key: pHist2, Size: 1}), t.TempDir(), p)
	if err == nil || !strings.Contains(err.Error(), "listing above 2048 pages") || p.n != ListCurrentMaxPages {
		t.Errorf("by plan: %v after %d pages", err, p.n)
	}
}

// The program's bound cuts a fetch with an error, never a result.
func TestFetch_CutByItsContextFails(t *testing.T) {
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Fetch(ctx, fetchIn(), planOf(t, row(f, seg(1, 1), "segment 1/1")), t.TempDir(), ctxStore{f}); err == nil {
		t.Error("a cancelled fetch succeeded")
	}
}

type ctxStore struct{ *fake }

func (c ctxStore) Get(ctx context.Context, key, vid string, w io.Writer, max int64) (s3x.Object, error) {
	if err := ctx.Err(); err != nil {
		return s3x.Object{}, err
	}
	return c.fake.Get(ctx, key, vid, w, max)
}

// A repository copied with the write credential is fetched back with the
// read-only credential, byte for byte: by a plan built from the copy's rows,
// and, for the control plane, by listing its two trees.
func TestStandin_FetchReadOnlyCredentialSuffices(t *testing.T) {
	s := needStandin(t)
	ctx := context.Background()
	e := s.env("repl/" + rnd(4))
	write, read := s.bucket(t, e, "sp-projects", "write", 0), s.bucket(t, e, "sp-projects", "read", 0)
	root := fixture(t)
	mk(t, root, pSetFile, strings.Repeat("supapace", (33<<20)/8)) // a multipart object
	var rec record
	res := rec.copy(t, ctx, root, write)
	if !res.Complete {
		t.Fatalf("copy: %+v", res.Notices)
	}
	var plan []jobio.PlanRow
	for _, r := range res.Uploaded {
		plan = append(plan, jobio.PlanRow{Key: r.Key, VersionID: r.VersionID, SHA256: r.SHA256, Size: r.Size})
	}
	for _, i := range res.Info {
		tr := "archive"
		if strings.HasPrefix(i.Name, "backup") {
			tr = "backup"
		}
		plan = append(plan, jobio.PlanRow{Key: tr + "/" + stanza + "/" + i.Name, VersionID: i.VersionID, SHA256: i.SHA256, Size: bklimit.SmallMax})
	}
	dest := t.TempDir()
	if _, err := Fetch(ctx, fetchIn(), planOf(t, plan...), dest, read); err != nil {
		t.Fatal(err)
	}
	if got, want := tree(t, dest), tree(t, root); fmt.Sprint(got) != fmt.Sprint(want) || len(got) != 12 {
		t.Errorf("fetched %d files, the repository holds %d; equal: %v", len(got), len(want), fmt.Sprint(got) == fmt.Sprint(want))
	}
	// Control: the read-only credential cannot write.
	if _, err := read.Put(ctx, base(e.Prefix, ref)+"/"+seg(1, 9), []byte("x"), nil, true); !errors.Is(err, s3x.ErrDenied) {
		t.Errorf("a write with the read-only credential: %v", err)
	}

	// The control plane: copied under subject cp, listed back.
	cpRoot := t.TempDir()
	for rel, body := range tree(t, fixture(t)) {
		mk(t, cpRoot, cpRel("cp-1", rel), body)
	}
	in := input(func(x *jobio.ReplInput) { x.InfoSHA256 = map[string]string{} })
	in.Subject, in.Stanza, in.Timelines = "cp", "cp-1", nil
	if r, err := Copy(ctx, in, cpRoot, bytes.NewReader(nil), write); err != nil || !r.Complete {
		t.Fatalf("cp copy: %v %+v", err, r.Notices)
	}
	dest = t.TempDir()
	r, err := Fetch(ctx, cpIn("cp-1"), nil, dest, read)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := tree(t, dest), tree(t, cpRoot); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("list_current fetched %d files of %d", len(got), len(want))
	}
	if r.NewestSet != label || r.NewestSegment != fmt.Sprintf("%08X%08X%08X", 2, 0, 3) {
		t.Errorf("%+v", r)
	}
}

// clientGet answers a body above max as the client does: an error, with the
// object's announced size.
type clientGet struct{ *fake }

func (c clientGet) Get(ctx context.Context, key, vid string, w io.Writer, max int64) (s3x.Object, error) {
	var b bytes.Buffer
	o, err := c.fake.Get(ctx, key, vid, &b, 1<<40)
	if err == nil && int64(b.Len()) > max {
		return o, fmt.Errorf("s3x: GET %q: %d bytes, over %d", key, b.Len(), max)
	}
	w.Write(b.Bytes())
	return o, err
}

// shaped rewrites the listing: a version id or a size out of shape, or keys
// outside the listed prefix.
type shaped struct {
	*fake
	edit func(*s3x.Object)
	add  []s3x.Object
}

func (s *shaped) ListVersions(ctx context.Context, prefix, km, vm string) ([]s3x.Object, string, string, error) {
	page, nk, nv, err := s.fake.ListVersions(ctx, prefix, km, vm)
	for i := range page {
		s.edit(&page[i])
	}
	return append(page, s.add...), nk, nv, err
}

func TestFetch_AListedVersionOutOfShapeIsRefused(t *testing.T) {
	f := newFake()
	put(f, f.putKey(pHist2), "history 2")
	long := func(o *s3x.Object) { o.VersionID = strings.Repeat("v", versionMax+1) }
	if _, _, err := fetch(t, fetchIn(), planOf(t, jobio.PlanRow{Key: pHist2, Size: 9}), &shaped{fake: f, edit: long}); !errors.Is(err, ErrMismatch) {
		t.Errorf("by plan: %v", err)
	}
	const st = "cp-1"
	put(f, cpKey(f, cpRel(st, pManifest)), "manifest")
	put(f, cpKey(f, cpRel(st, seg(1, 1))), "segment 1/1")
	for name, edit := range map[string]func(*s3x.Object){
		"version id":      long,
		"above its bound": func(o *s3x.Object) { o.Size = bklimit.SegmentMax + 1 },
		"negative size":   func(o *s3x.Object) { o.Size = -1 },
	} {
		f.calls = nil
		if _, _, err := fetch(t, cpIn(st), nil, &shaped{fake: f, edit: edit}); !errors.Is(err, ErrMismatch) || len(f.callsWith("GET ")) != 0 {
			t.Errorf("%s: %v, GETs %q (refused before any request)", name, err, f.callsWith("GET "))
		}
	}
	// Control: the listing as the store gives it.
	if _, _, err := fetch(t, cpIn(st), nil, &shaped{fake: f, edit: func(*s3x.Object) {}}); err != nil {
		t.Errorf("control: %v", err)
	}
}

// A listing that names a key outside its prefix — here a key that is the
// relative path itself, under an empty declared prefix — is never fetched.
func TestFetch_ListCurrent_AKeyOutsideTheListingIsRefused(t *testing.T) {
	f := newFake()
	f.prefix = ""
	const st = "cp-1"
	put(f, "cp/"+cpRel(st, pManifest), "manifest")
	stray := s3x.Object{Key: cpRel(st, seg(1, 1)), VersionID: "v1", Size: 5}
	f.objs[stray.Key] = []fakeObj{{vid: "v1", body: []byte("stray")}}
	dest, r, err := fetch(t, cpIn(st), nil, &shaped{fake: f, edit: func(*s3x.Object) {}, add: []s3x.Object{stray}})
	if err != nil || r.Files != 1 || len(tree(t, dest)) != 1 {
		t.Errorf("%v %+v %q", err, r, tree(t, dest))
	}
}

// The plan is held whole before any request, at most fetchMaxRows rows.
func TestFetch_PlanRowCap(t *testing.T) {
	var b bytes.Buffer
	for n := 1; n <= fetchMaxRows+1; n++ {
		fmt.Fprintf(&b, "%s\t-\t-\t1\n", seg(1, n))
	}
	f := newFake()
	if _, err := Fetch(context.Background(), fetchIn(), &b, t.TempDir(), f); !errors.Is(err, ErrTooLarge) || len(f.calls) != 0 {
		t.Errorf("%v, calls %d", err, len(f.calls))
	}
}
