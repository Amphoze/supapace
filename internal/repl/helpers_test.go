package repl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/s3x"
)

const (
	ref    = "abcdefghij0123456789"
	stanza = ref + "-1"
	hex40  = "0123456789abcdef0123456789abcdef01234567"
)

// Repository paths of the fixture, by name.
var (
	pArchInfo = "archive/" + stanza + "/archive.info"
	pArchCopy = "archive/" + stanza + "/archive.info.copy"
	pBackInfo = "backup/" + stanza + "/backup.info"
	pBackCopy = "backup/" + stanza + "/backup.info.copy"
	pHist2    = "archive/" + stanza + "/17-1/00000002.history"
	label     = "20261118-134740F"
	pManifest = "backup/" + stanza + "/" + label + "/backup.manifest"
	pManCopy  = "backup/" + stanza + "/" + label + "/backup.manifest.copy"
	pSetFile  = "backup/" + stanza + "/" + label + "/pg_data/base/1/1259"
	pHistMan  = "backup/" + stanza + "/backup.history/2026/" + label + ".manifest.gz"
	pLatest   = "backup/" + stanza + "/latest"
)

// seg is the repository path of segment n of timeline tli.
func seg(tli, n int) string {
	name := fmt.Sprintf("%08X%08X%08X", tli, 0, n)
	return fmt.Sprintf("archive/%s/17-1/%s/%s-%s.zst", stanza, name[:16], name, hex40)
}

// labelOf is the repository path of the backup label of segment n of timeline tli.
func labelOf(tli, n int) string {
	name := fmt.Sprintf("%08X%08X%08X", tli, 0, n)
	return fmt.Sprintf("archive/%s/17-1/%s/%s.00000028.backup", stanza, name[:16], name)
}

func segDir(tli int) string { return fmt.Sprintf("archive/%s/17-1/%08X%08X", stanza, tli, 0) }

// mk writes rel under root with body, creating its directories.
func mk(t testing.TB, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

// fixture is a repository with info files, timeline 1 and 2 segments, a
// history, a complete set and its history manifest.
func fixture(t testing.TB) string {
	root := t.TempDir()
	for _, p := range []string{pArchInfo, pArchCopy, pBackInfo, pBackCopy} {
		mk(t, root, p, "info "+p)
	}
	mk(t, root, seg(1, 1), "segment 1/1")
	mk(t, root, seg(1, 2), "segment 1/2")
	mk(t, root, pHist2, "history 2")
	mk(t, root, seg(2, 3), "segment 2/3")
	mk(t, root, pManifest, "manifest")
	mk(t, root, pManCopy, "manifest copy")
	mk(t, root, pSetFile, "set file")
	mk(t, root, pHistMan, "history manifest")
	if err := os.Symlink(label, filepath.Join(root, pLatest)); err != nil {
		t.Fatal(err)
	}
	return root
}

func input(mut ...func(*jobio.ReplInput)) jobio.Input {
	r := &jobio.ReplInput{Mode: "copy", MaxFiles: 2048, MaxEntries: 250000, MaxBytes: 1280 << 20, BudgetBytes: -1, BudgetObjects: -1,
		InfoSHA256: map[string]string{}}
	for _, m := range mut {
		m(r)
	}
	return jobio.Input{Job: 7, Kind: "replicate", Subject: ref, Stanza: stanza, UID: os.Getuid(), Timelines: []uint32{1, 2}, Repl: r}
}

// indexOf is an index file holding rows.
func indexOf(t testing.TB, rows ...jobio.IndexRow) *bytes.Reader {
	t.Helper()
	var b []byte
	for _, r := range rows {
		var err error
		if b, err = jobio.AppendIndexRow(b, r); err != nil {
			t.Fatal(err)
		}
	}
	return bytes.NewReader(b)
}

// indexed is the index row of rel as it is on disk now, with its hash.
func indexed(t testing.TB, root, rel string, withHash bool) jobio.IndexRow {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(filepath.Join(root, rel), &st); err != nil {
		t.Fatal(err)
	}
	r := jobio.IndexRow{Key: rel, Size: st.Size, Ino: int64(st.Ino), CtimeNS: st.Ctim.Nano()}
	if withHash {
		b, _ := os.ReadFile(filepath.Join(root, rel))
		r.SHA256 = sum(b)
	}
	return r
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func run(t testing.TB, root string, in jobio.Input, ix *bytes.Reader, st Store) jobio.ReplResult {
	t.Helper()
	if ix == nil {
		ix = bytes.NewReader(nil)
	}
	r, err := Copy(context.Background(), in, root, ix, st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobio.MarshalResult(r); err != nil {
		t.Fatalf("result does not marshal: %v", err)
	}
	return r
}

// hookOpen calls fn with the name of every file the program opens for reading.
func hookOpen(t testing.TB, fn func(name string)) {
	t.Helper()
	old := openForRead
	openForRead = func(dirfd int, name string) (int, error) {
		fn(name)
		return old(dirfd, name)
	}
	t.Cleanup(func() { openForRead = old })
}

func keys(rows []jobio.Row) []string {
	var k []string
	for _, r := range rows {
		k = append(k, r.Key)
	}
	return k
}

func noticeOf(r jobio.ReplResult, code string) *jobio.Notice {
	for i := range r.Notices {
		if r.Notices[i].Code == code {
			return &r.Notices[i]
		}
	}
	return nil
}

// fake is a versioned bucket in memory with the write-once condition, and a
// log of every call.
type fake struct {
	mu      sync.Mutex
	prefix  string
	objs    map[string][]fakeObj // oldest first
	uploads map[string]*fakeUpload
	n       int
	calls   []string
	page    int // versions a listing page holds; 0: 1000

	failPut      func(key string) error
	failComplete func(key string) error
	failList     func(call int) error
	lists        int
}

type fakeObj struct {
	vid    string
	body   []byte
	meta   map[string]string
	marker bool
	at     time.Time
}

type fakeUpload struct {
	key   string
	meta  map[string]string
	parts map[int][]byte
}

func newFake() *fake {
	return &fake{prefix: "pre/fix", objs: map[string][]fakeObj{}, uploads: map[string]*fakeUpload{}}
}

func (f *fake) Prefix() string { return f.prefix }

func (f *fake) log(s string) { f.calls = append(f.calls, s) }

func (f *fake) current(key string) (fakeObj, bool) {
	v := f.objs[key]
	if len(v) == 0 || v[len(v)-1].marker {
		return fakeObj{}, false
	}
	return v[len(v)-1], true
}

func (f *fake) store(key string, body []byte, meta map[string]string, ifAbsent bool) (string, error) {
	if _, ok := f.current(key); ok && ifAbsent {
		return "", fmt.Errorf("%w (PUT %q)", s3x.ErrExists, key)
	}
	f.n++
	vid := fmt.Sprintf("v%06d", f.n)
	f.objs[key] = append(f.objs[key], fakeObj{vid: vid, body: slices.Clone(body), meta: meta, at: time.Unix(int64(1e9+f.n), 0)})
	return vid, nil
}

func (f *fake) Put(ctx context.Context, key string, body []byte, meta map[string]string, ifAbsent bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log(fmt.Sprintf("PUT %s %v", key, ifAbsent))
	if err := checkKey(key); err != nil {
		return "", err
	}
	if f.failPut != nil {
		if err := f.failPut(key); err != nil {
			return "", err
		}
	}
	return f.store(key, body, meta, ifAbsent)
}

func checkKey(key string) error {
	if key == "" || len(key) > 1024 || strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") || strings.Contains(key, "//") {
		return errors.New("fake: bad key " + key)
	}
	return nil
}

func (f *fake) Head(ctx context.Context, key, versionID string) (s3x.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log("HEAD " + key)
	o, ok := f.current(key)
	if !ok {
		return s3x.Object{}, s3x.ErrNotFound
	}
	return s3x.Object{Key: key, VersionID: o.vid, Size: int64(len(o.body)), Meta: o.meta}, nil
}

func (f *fake) CreateMultipart(ctx context.Context, key string, meta map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log("CREATE " + key)
	f.n++
	id := fmt.Sprintf("u%d", f.n)
	f.uploads[id] = &fakeUpload{key: key, meta: meta, parts: map[int][]byte{}}
	return id, nil
}

func (f *fake) UploadPart(ctx context.Context, key, id string, n int, body []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log(fmt.Sprintf("PART %s %d %d", key, n, len(body)))
	u := f.uploads[id]
	if u == nil || u.key != key {
		return "", errors.New("fake: no such upload")
	}
	u.parts[n] = slices.Clone(body)
	return fmt.Sprintf("e%d", n), nil
}

func (f *fake) CompleteMultipart(ctx context.Context, key, id string, etags []string, ifAbsent bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log(fmt.Sprintf("COMPLETE %s %v", key, ifAbsent))
	if f.failComplete != nil {
		if err := f.failComplete(key); err != nil {
			return "", err
		}
	}
	u := f.uploads[id]
	if u == nil {
		return "", errors.New("fake: no such upload")
	}
	var body []byte
	for i := range etags {
		body = append(body, u.parts[i+1]...)
	}
	vid, err := f.store(key, body, u.meta, ifAbsent)
	if err == nil {
		delete(f.uploads, id)
	}
	return vid, err
}

func (f *fake) AbortMultipart(ctx context.Context, key, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log("ABORT " + key + " " + id)
	delete(f.uploads, id)
	return nil
}

// ListVersions lists in the store's order: keys ascending, a key's versions
// newest first, from the markers (exclusive).
func (f *fake) ListVersions(ctx context.Context, prefix, km, vm string) ([]s3x.Object, string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists++
	f.log("LIST " + prefix)
	if f.failList != nil {
		if err := f.failList(f.lists); err != nil {
			return nil, "", "", err
		}
	}
	var all []s3x.Object
	for k, vs := range f.objs {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		for i := len(vs) - 1; i >= 0; i-- {
			all = append(all, s3x.Object{Key: k, VersionID: vs[i].vid, Size: int64(len(vs[i].body)), DeleteMarker: vs[i].marker,
				Latest: i == len(vs)-1, Modified: vs[i].at})
		}
	}
	slices.SortStableFunc(all, func(a, b s3x.Object) int { return strings.Compare(a.Key, b.Key) })
	start := 0
	if km != "" {
		start = len(all)
		for i, o := range all {
			if vm != "" && o.Key == km && o.VersionID == vm {
				start = i + 1
				break
			}
			if vm == "" && o.Key > km {
				start = i
				break
			}
		}
	}
	page := f.page
	if page == 0 {
		page = 1000
	}
	end := min(start+page, len(all))
	out := all[start:end]
	if end == len(all) {
		return out, "", "", nil
	}
	return out, out[len(out)-1].Key, out[len(out)-1].VersionID, nil
}

// putKey is the store key of rel.
func (f *fake) putKey(rel string) string { return f.prefix + "/" + ref + "/" + rel }

func (f *fake) callsWith(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

func (f *fake) Get(ctx context.Context, key, versionID string, w io.Writer, max int64) (s3x.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log("GET " + key)
	vs := f.objs[key]
	for i := len(vs) - 1; i >= 0; i-- { // newest first: "" is the current version
		o := vs[i]
		if o.vid == versionID || versionID == "" && i == len(vs)-1 && !o.marker {
			if int64(len(o.body)) > max {
				return s3x.Object{}, errors.New("fake: over max")
			}
			w.Write(o.body)
			return s3x.Object{Key: key, VersionID: o.vid, Size: int64(len(o.body)), Meta: o.meta}, nil
		}
	}
	return s3x.Object{}, s3x.ErrNotFound
}
