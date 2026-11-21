package bkjob

import (
	"context"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// tree writes files (path → content; a path ending in "/" is a directory).
func tree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for _, p := range slices.Sorted(maps.Keys(files)) {
		full := filepath.Join(root, p)
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o750); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(files[p]), 0o640); err != nil {
			t.Fatal(err)
		}
	}
}

// walkTree is root's files (path → content) and directories (path + "/"), with modes.
func walkTree(t *testing.T, root string) (map[string]string, map[string]fs.FileMode) {
	t.Helper()
	files, modes := map[string]string{}, map[string]fs.FileMode{}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		fi, _ := d.Info()
		if d.IsDir() {
			files[rel+"/"] = ""
			modes[rel+"/"] = fi.Mode()
			return nil
		}
		b, _ := os.ReadFile(p)
		files[rel] = string(b)
		modes[rel] = fi.Mode()
		return nil
	})
	return files, modes
}

var fetched = map[string]string{
	"archive/ref-1/archive.info": "info",
	"archive/ref-1/17-1/0000000100000000/000000010000000000000003-" + strings.Repeat("a", 40) + ".zst": "seg",
	"archive/ref-1/17-1/00000002.history":                  "hist",
	"backup/ref-1/backup.info":                             "binfo",
	"backup/ref-1/" + testSet + "/backup.manifest":         "manifest",
	"backup/ref-1/" + testSet + "/pg_data/base/1/1259.zst": "page",
	"backup/ref-1/backup.history/2026/":                    "",
}

// The seed empties repo/ — whatever its tree — and copies fetch/ into it.
func TestSeed_EmptiesThenCopies(t *testing.T) {
	d := t.TempDir()
	repo, fetch := filepath.Join(d, "repo"), filepath.Join(d, "fetch")
	tree(t, fetch, fetched)
	tree(t, repo, map[string]string{"archive/ref-1/archive.info": "old", "backup/ref-1/old-set/x": "old", "stray": "s", "deep/a/b/c/d/e/f/g/h/": ""})
	outside := filepath.Join(d, "outside")
	os.WriteFile(outside, []byte("keep"), 0o600)
	os.Symlink(outside, filepath.Join(repo, "link"))
	os.Symlink(d, filepath.Join(repo, "backup", "dirlink"))
	os.Chmod(filepath.Join(repo, "deep", "a"), 0) // rmtree regains access
	r, err := Seed(context.Background(), repo, fetch)
	if err != nil {
		t.Fatal(err)
	}
	got, modes := walkTree(t, repo)
	if !maps.Equal(got, fetched2(fetched)) {
		t.Errorf("repo/ holds %q, want %q", slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(fetched2(fetched))))
	}
	for p, m := range modes {
		want := fs.FileMode(0o640)
		if strings.HasSuffix(p, "/") {
			want = fs.ModeDir | 0o750
		}
		if m != want {
			t.Errorf("%s: mode %v, want %v", p, m, want)
		}
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Error("a link's target was changed")
	}
	if r.Files != 6 || r.Bytes != int64(len("info"+"seg"+"hist"+"binfo"+"manifest"+"page")) || !r.OK {
		t.Errorf("result %+v", r)
	}
}

// fetched2 is fetched with every parent directory listed.
func fetched2(m map[string]string) map[string]string {
	out := map[string]string{}
	for p, v := range m {
		out[p] = v
		for dir := filepath.Dir(strings.TrimSuffix(p, "/")); dir != "."; dir = filepath.Dir(dir) {
			out[dir+"/"] = ""
		}
	}
	return out
}

// Anything in fetch/ that is not a directory or a regular file — a link to a
// file or a directory, a FIFO — or a name outside the repository's characters
// fails the job before repo/ is touched.
func TestSeed_LinkInFetchRefused(t *testing.T) {
	cases := map[string]func(fetch, outside string){
		"file link": func(f, o string) { os.Symlink(filepath.Join(o, "secret"), filepath.Join(f, "archive/ref-1/x")) },
		"dir link":  func(f, o string) { os.Symlink(o, filepath.Join(f, "backup/ref-1/l")) },
		"fifo":      func(f, o string) { syscall.Mkfifo(filepath.Join(f, "backup/ref-1/p"), 0o600) },
		"name":      func(f, o string) { os.WriteFile(filepath.Join(f, "backup/ref-1/a b"), nil, 0o640) },
		"too deep":  func(f, o string) { os.MkdirAll(filepath.Join(f, strings.Repeat("d/", seedDepthMax+1)), 0o750) },
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			d := t.TempDir()
			repo, fetch, outside := filepath.Join(d, "repo"), filepath.Join(d, "fetch"), filepath.Join(d, "outside")
			tree(t, fetch, fetched)
			tree(t, repo, map[string]string{"archive/ref-1/archive.info": "old"})
			tree(t, outside, map[string]string{"secret": "s"})
			plant(fetch, outside)
			_, err := Seed(context.Background(), repo, fetch)
			if failCode(err) != seedFailed {
				t.Fatalf("Seed = %v, want %s", err, seedFailed)
			}
			if got, _ := walkTree(t, repo); !maps.Equal(got, map[string]string{"archive/": "", "archive/ref-1/": "", "archive/ref-1/archive.info": "old"}) {
				t.Errorf("repo/ was changed: %q", slices.Sorted(maps.Keys(got)))
			}
		})
	}
	// Control: at the depth bound it copies.
	d := t.TempDir()
	repo, fetch := filepath.Join(d, "repo"), filepath.Join(d, "fetch")
	os.MkdirAll(repo, 0o750)
	tree(t, fetch, map[string]string{strings.Repeat("d/", seedDepthMax) + "f": "x"})
	if _, err := Seed(context.Background(), repo, fetch); err != nil {
		t.Errorf("at the bound: %v", err)
	}
	// fetch/ itself a link: refused.
	d2 := t.TempDir()
	os.MkdirAll(filepath.Join(d2, "repo"), 0o750)
	os.MkdirAll(filepath.Join(d2, "real"), 0o750)
	os.Symlink(filepath.Join(d2, "real"), filepath.Join(d2, "fetch"))
	if _, err := Seed(context.Background(), filepath.Join(d2, "repo"), filepath.Join(d2, "fetch")); failCode(err) != seedFailed {
		t.Errorf("fetch/ a link: %v", err)
	}
}

func TestSeed_PreservesRelativePaths(t *testing.T) {
	d := t.TempDir()
	repo, fetch := filepath.Join(d, "repo"), filepath.Join(d, "fetch")
	os.MkdirAll(repo, 0o750)
	files := map[string]string{"a": "1", "b/c": "2", "b/d/e": "3", "b/d/f/": "", "x+y.z_-": "4"}
	tree(t, fetch, files)
	if _, err := Seed(context.Background(), repo, fetch); err != nil {
		t.Fatal(err)
	}
	got, _ := walkTree(t, repo)
	want, _ := walkTree(t, fetch)
	if !maps.Equal(got, want) {
		t.Errorf("repo/ %q, fetch/ %q", got, want)
	}
}

// The repository's modes whatever the job's umask.
func TestSeed_ModesUnderAStrictUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	d := t.TempDir()
	repo, fetch := filepath.Join(d, "repo"), filepath.Join(d, "fetch")
	os.MkdirAll(repo, 0o750)
	tree(t, fetch, map[string]string{"a/b": "1"})
	if _, err := Seed(context.Background(), repo, fetch); err != nil {
		t.Fatal(err)
	}
	_, modes := walkTree(t, repo)
	if modes["a/"] != fs.ModeDir|0o750 || modes["a/b"] != 0o640 {
		t.Errorf("modes %v", modes)
	}
}

// A seed that fails part-way through its copy leaves repo/ partly written; the
// next seed job over the same fetch/ makes repo/ equal to it, with nothing of
// the first run left behind.
func TestSeed_RerunAfterAFailedCopyIsComplete(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("an unreadable file is readable to root")
	}
	d := t.TempDir()
	repo, fetch := filepath.Join(d, "repo"), filepath.Join(d, "fetch")
	tree(t, fetch, fetched)
	tree(t, repo, map[string]string{"stray": "s"})
	locked := filepath.Join(fetch, "backup/ref-1/"+testSet+"/pg_data/base/1/1259.zst")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Seed(context.Background(), repo, fetch); failCode(err) != seedFailed {
		t.Fatalf("first run: %v, want %s", err, seedFailed)
	}
	os.Chmod(locked, 0o640)
	r, err := Seed(context.Background(), repo, fetch)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got, _ := walkTree(t, repo); !maps.Equal(got, fetched2(fetched)) {
		t.Errorf("repo/ holds %q", slices.Sorted(maps.Keys(got)))
	}
	if r.Files != 6 {
		t.Errorf("result %+v", r)
	}
}

// Each copied file is synced before it is closed, each directory after its
// walk, and the repository last: a seed recorded done survives a crash.
func TestSeed_SyncsFilesThenDirectoriesThenTheRepository(t *testing.T) {
	var calls []string
	old := seedSync
	seedSync = func(fd int, name string) error {
		var st syscall.Stat_t
		syscall.Fstat(fd, &st)
		kind := "file"
		if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			kind = "dir"
		}
		calls = append(calls, kind+" "+name)
		return old(fd, name)
	}
	t.Cleanup(func() { seedSync = old })
	d := t.TempDir()
	repo, fetch := filepath.Join(d, "repo"), filepath.Join(d, "fetch")
	os.MkdirAll(repo, 0o750)
	tree(t, fetch, map[string]string{"a/b/c": "1"})
	if _, err := Seed(context.Background(), repo, fetch); err != nil {
		t.Fatal(err)
	}
	if want := []string{"file c", "dir a/b", "dir a", "dir ."}; !slices.Equal(calls, want) {
		t.Errorf("syncs %q, want %q", calls, want)
	}
	// A failed sync fails the seed.
	seedSync = func(int, string) error { return syscall.EIO }
	os.RemoveAll(repo)
	os.MkdirAll(repo, 0o750)
	if _, err := Seed(context.Background(), repo, fetch); failCode(err) != seedFailed {
		t.Errorf("a failed sync: %v", err)
	}
}
