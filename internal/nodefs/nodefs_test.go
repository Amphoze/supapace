package nodefs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

const testRef = "abcdefghij0123456789"

// TestMain doubles as the entry point of the helper process that acts as a
// tenant: the test binary re-executes itself at a project uid.
func TestMain(m *testing.M) {
	if os.Getenv("NODEFS_TENANT_HELPER") == "1" {
		os.Exit(tenantMain(os.Args[1:]))
	}
	code := m.Run()
	if helperBin != "" {
		os.RemoveAll(filepath.Dir(helperBin))
	}
	os.Exit(code)
}

// ───────── WriteFile ─────────

func me() (int, int) { return os.Geteuid(), os.Getegid() }

func mkRenderDir(t *testing.T, p nodecfg.Paths) string {
	t.Helper()
	dir := p.RenderDir(testRef)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestWriteFile_RefusesSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	p := nodecfg.Paths{Root: root}
	dir := mkRenderDir(t, p)
	canary := filepath.Join(root, "canary")
	if err := os.WriteFile(canary, []byte("canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, filepath.Join(dir, "pg_hba.conf")); err != nil {
		t.Fatal(err)
	}
	uid, gid := me()
	if err := WriteFile(p, dir, "pg_hba.conf", []byte("evil"), 0o444, uid, gid); err == nil {
		t.Fatal("WriteFile over a symbolic link succeeded")
	}
	if b, _ := os.ReadFile(canary); string(b) != "canary" {
		t.Fatalf("link target changed: %q", b)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "pg_hba.conf")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link replaced: %v %v", fi, err)
	}
	assertNoTemp(t, dir)
}

func TestWriteFile_FIFOAtNameRefused(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	dir := mkRenderDir(t, p)
	if err := syscall.Mkfifo(filepath.Join(dir, "state.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	uid, gid := me()
	done := make(chan error, 1)
	go func() { done <- WriteFile(p, dir, "state.json", []byte("{}"), 0o600, uid, gid) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("WriteFile over a FIFO succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WriteFile blocked on a FIFO")
	}
}

func TestWriteFile_HardLinkAtNameLeavesOtherLinkIntact(t *testing.T) {
	root := t.TempDir()
	p := nodecfg.Paths{Root: root}
	dir := mkRenderDir(t, p)
	other := filepath.Join(root, "other")
	if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(other, filepath.Join(dir, "group")); err != nil {
		t.Fatal(err)
	}
	uid, gid := me()
	if err := WriteFile(p, dir, "group", []byte("new"), 0o444, uid, gid); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(other); string(b) != "other" {
		t.Fatalf("the other link changed: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "group")); string(b) != "new" {
		t.Fatalf("got %q", b)
	}
}

func TestWriteFile_Atomic(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	dir := mkRenderDir(t, p)
	a := bytes.Repeat([]byte("a"), 1<<20)
	b := bytes.Repeat([]byte("b"), 1<<20)
	uid, gid := me()
	if err := WriteFile(p, dir, "f", a, 0o444, uid, gid); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var reads int
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		for !stop.Load() {
			got, err := os.ReadFile(filepath.Join(dir, "f"))
			if err != nil {
				errc <- err
				return
			}
			if !bytes.Equal(got, a) && !bytes.Equal(got, b) {
				errc <- fmt.Errorf("partial read: %d bytes", len(got))
				return
			}
			reads++
		}
	}()
	for i := 0; i < 100; i++ {
		data := a
		if i%2 == 0 {
			data = b
		}
		if err := WriteFile(p, dir, "f", data, 0o444, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if reads == 0 {
		t.Fatal("reader never ran")
	}
	assertNoTemp(t, dir)
}

func TestWriteFile_OutsideRenderRootRefused(t *testing.T) {
	root := t.TempDir()
	p := nodecfg.Paths{Root: root}
	proj := p.ProjectDir(testRef)
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	mkRenderDir(t, p)
	uid, gid := me()
	for _, dir := range []string{
		proj,
		p.ProjectsDir(),
		filepath.Join(p.PlatformDir(), "..", "projects", testRef),
		filepath.Dir(p.PlatformDir()),
		root,
		"var/lib/supapace/platform",
		p.PlatformDir() + "x",
	} {
		err := WriteFile(p, dir, "f", []byte("x"), 0o444, uid, gid)
		if !errors.Is(err, ErrOutsideRenderRoot) {
			t.Errorf("%s: got %v, want ErrOutsideRenderRoot", dir, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(proj, "f")); !os.IsNotExist(err) {
		t.Fatalf("a file was written under ProjectsDir: %v", err)
	}
}

func TestWriteFile_UnderTempRoot(t *testing.T) {
	root := t.TempDir()
	p := nodecfg.Paths{Root: root}
	uid, gid := me()
	for _, dir := range []string{p.PlatformDir(), p.GatewayDir(), p.RenderDir(testRef),
		filepath.Join(p.RenderDir(testRef), "conf.d"), filepath.Dir(p.NodeJSON()), p.TLSDir()} {
		if !strings.HasPrefix(dir, root+"/") {
			t.Fatalf("%s is not under the temp root", dir)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(p, dir, "x.conf", []byte("hello"), 0o440, uid, gid); err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		fi, err := os.Lstat(filepath.Join(dir, "x.conf"))
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o440 || int(st.Uid) != uid || int(st.Gid) != gid {
			t.Fatalf("%s: mode %v owner %d:%d", dir, fi.Mode(), st.Uid, st.Gid)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "x.conf")); string(b) != "hello" {
			t.Fatalf("%s: got %q", dir, b)
		}
	}
}

func TestWriteFile_RefusesWeakDirAndBadName(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	dir := mkRenderDir(t, p)
	uid, gid := me()
	for _, name := range []string{"", ".", "..", "a/b", "/abs"} {
		if err := WriteFile(p, dir, name, []byte("x"), 0o444, uid, gid); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	// A group- or world-writable directory on the way is refused.
	if err := os.Chmod(filepath.Dir(dir), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, dir, "f", []byte("x"), 0o444, uid, gid); err == nil {
		t.Fatal("write below a world-writable directory succeeded")
	}
	if err := os.Chmod(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	// A symbolic link as a directory component is refused.
	alt := filepath.Join(p.PlatformDir(), "alt")
	if err := os.Symlink(dir, alt); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, alt, "f", []byte("x"), 0o444, uid, gid); err == nil {
		t.Fatal("write through a linked directory succeeded")
	}
}

func TestWriteFile_RefusesBadIDs(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	dir := mkRenderDir(t, p)
	uid, gid := me()
	for _, c := range [][2]int{{-1, gid}, {uid, -1}, {-2, -2}, {1<<32 - 1, gid}, {uid, 1<<32 - 1}, {1 << 32, gid}} {
		if err := WriteFile(p, dir, "f", []byte("x"), 0o444, c[0], c[1]); err == nil {
			t.Errorf("owner %d:%d accepted", c[0], c[1])
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "f")); !os.IsNotExist(err) {
		t.Fatalf("file created: %v", err)
	}
	assertNoTemp(t, dir)
}

// The temporary name adds a fixed suffix, so the longest name is 255 minus it.
func TestWriteFile_NameLengthLimit(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	dir := mkRenderDir(t, p)
	uid, gid := me()
	longest := strings.Repeat("n", 255-len(".")-len(".tmp-")-16)
	if err := WriteFile(p, dir, longest, []byte("x"), 0o444, uid, gid); err != nil {
		t.Fatalf("%d-byte name: %v", len(longest), err)
	}
	if err := WriteFile(p, dir, longest+"n", []byte("x"), 0o444, uid, gid); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("%d-byte name: got %v, want a too-long error", len(longest)+1, err)
	}
	// The limit counts bytes: a two-byte character counts twice.
	two := strings.Repeat("\u00e9", len(longest)/2)
	if err := WriteFile(p, dir, two+"n", []byte("x"), 0o444, uid, gid); err != nil {
		t.Fatalf("%d-byte name of %d characters: %v", len(two)+1, len(two)/2+1, err)
	}
	if err := WriteFile(p, dir, two+"\u00e9", []byte("x"), 0o444, uid, gid); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("%d-byte name of %d characters: got %v, want a too-long error", len(two)+2, len(two)/2+1, err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Fatalf("entries: %v", ents)
	}
}

func assertNoTemp(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

// ───────── CheckRange ─────────

func TestCheckRange_Overlap(t *testing.T) {
	const base, count = 700000, 65536
	passwdOK := "root:x:0:0:root:/root:/bin/sh\n# comment\n\nsvc:x:999:999:g:/:/sbin/nologin\nhi:x:765536:100:g:/:/bin/sh\n"
	groupOK := "root:x:0:\nwheel:x:10:root\n"
	subOK := "builder:100000:65536\nother:765536:1000\n"
	cases := []struct {
		name                          string
		passwd, group, subuid, subgid string
		ok                            bool
	}{
		{"clean", passwdOK, groupOK, subOK, subOK, true},
		{"passwd uid at base", passwdOK + "a:x:700000:1:g:/:/bin/sh\n", groupOK, subOK, subOK, false},
		{"passwd uid at end", passwdOK + "a:x:765535:1:g:/:/bin/sh\n", groupOK, subOK, subOK, false},
		{"passwd gid inside", passwdOK + "a:x:5:700100:g:/:/bin/sh\n", groupOK, subOK, subOK, false},
		{"group gid inside", passwdOK, groupOK + "g:x:712345:\n", subOK, subOK, false},
		{"subuid straddles base", passwdOK, groupOK, subOK + "u:699999:2\n", subOK, false},
		{"subuid covers range", passwdOK, groupOK, "u:100000:1000000\n", subOK, false},
		{"subgid inside", passwdOK, groupOK, subOK, subOK + "u:720000:10\n", false},
		{"subuid ends at base", passwdOK, groupOK, "u:600000:100000\n", subOK, true},
		{"malformed passwd", "x:x:notanumber:0:g:/:/bin/sh\n", groupOK, subOK, subOK, false},
		{"malformed subuid", passwdOK, groupOK, "u:1\n", subOK, false},
	}
	for _, c := range cases {
		err := CheckRange(base, count, strings.NewReader(c.passwd), strings.NewReader(c.group),
			strings.NewReader(c.subuid), strings.NewReader(c.subgid))
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
	// Absent subordinate-id files are nil readers.
	if err := CheckRange(base, count, strings.NewReader(passwdOK), strings.NewReader(groupOK), nil, nil); err != nil {
		t.Errorf("nil readers: %v", err)
	}
	if err := CheckRange(base, 0, strings.NewReader(""), strings.NewReader(""), nil, nil); err == nil {
		t.Error("empty range accepted")
	}
	if err := CheckRange(base, count, nil, strings.NewReader(groupOK), nil, nil); err == nil {
		t.Error("nil passwd accepted")
	}
	if err := CheckRange(base, count, strings.NewReader(passwdOK), nil, nil, nil); err == nil {
		t.Error("nil group accepted")
	}
	// The range must lie within [65536, 2^31-1]: system accounts, the usual
	// nobody/nonroot ids and the overflow id are below it.
	for _, r := range [][2]int{{0, 10}, {65000, 1000}, {65535, 10}, {1<<31 - 100, 101}, {1 << 31, 1}} {
		if err := CheckRange(r[0], r[1], strings.NewReader(""), strings.NewReader(""), nil, nil); err == nil {
			t.Errorf("range %v accepted", r)
		}
	}
	for _, r := range [][2]int{{65536, 1}, {1<<31 - 100, 100}} {
		if err := CheckRange(r[0], r[1], strings.NewReader(""), strings.NewReader(""), nil, nil); err != nil {
			t.Errorf("range %v: %v", r, err)
		}
	}
	if err := CheckRange(-1, 10, strings.NewReader(""), strings.NewReader(""), nil, nil); err == nil {
		t.Error("negative base accepted")
	}
}

// ───────── RemoveEmptyProjectDir (any user) ─────────

func TestRemoveEmptyProjectDir_AbsentEmptyAndLink(t *testing.T) {
	root := t.TempDir()
	p := nodecfg.Paths{Root: root}
	if err := os.MkdirAll(p.ProjectsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEmptyProjectDir(p, testRef); err != nil {
		t.Fatalf("absent: %v", err)
	}
	if err := os.Mkdir(p.ProjectDir(testRef), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEmptyProjectDir(p, testRef); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if _, err := os.Lstat(p.ProjectDir(testRef)); !os.IsNotExist(err) {
		t.Fatalf("still present: %v", err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p.ProjectDir(testRef)); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEmptyProjectDir(p, testRef); err == nil {
		t.Fatal("a link at the ref was removed as a directory")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("link target gone: %v", err)
	}
	if err := RemoveEmptyProjectDir(p, "../x"); err == nil {
		t.Fatal("bad ref accepted")
	}
}

// ───────── root and XFS ─────────

// xfsPaths returns Paths under a fresh temporary root whose ProjectsDir is a
// bind mount of a new directory on the node's XFS quota mount, so quota
// commands work against it and nothing of a real project is touched. It
// requires root.
func xfsPaths(t *testing.T) nodecfg.Paths {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	mount := nodecfg.Paths{}.ProjectsDir()
	var sfs syscall.Statfs_t
	if err := syscall.Statfs(mount, &sfs); err != nil || sfs.Type != xfsSuperMagic {
		t.Skipf("needs an XFS quota mount at %s", mount)
	}
	root, err := os.MkdirTemp("", "nodefs-")
	if err != nil {
		t.Fatal(err)
	}
	p := nodecfg.Paths{Root: root}
	// Every directory down to ProjectsDir stays traversable, so a helper
	// process at the project uid can reach its own tree.
	if err := os.MkdirAll(p.ProjectsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	for d := p.ProjectsDir(); d != filepath.Dir(root); d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sub, err := os.MkdirTemp(mount, ".nodefs-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(sub, p.ProjectsDir(), "", syscall.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(p.ProjectsDir(), syscall.MNT_DETACH); err != nil {
			t.Errorf("unmount: %v", err)
		}
		os.RemoveAll(sub)
		os.RemoveAll(root)
	})
	return p
}

var uidSeq atomic.Int32

// testIDs returns a fresh uid/gid pair outside the node's reserved range and
// clears its quota limits when the test ends.
func testIDs(t *testing.T, p nodecfg.Paths) (int, int) {
	id := 800000 + (os.Getpid()%1000)*100 + int(uidSeq.Add(1))
	t.Cleanup(func() {
		if err := SetQuota(p, id, 0); err != nil {
			t.Errorf("clear quota: %v", err)
		}
	})
	return id, id
}

func owner(t *testing.T, path string) (uint32, uint32, os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid, fi.Mode()
}

func projid(t *testing.T, path string) fsxattr {
	t.Helper()
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	var x fsxattr
	if err := ioctlFsxattr(fd, fsIocFsGetXattr, &x); err != nil {
		t.Fatal(err)
	}
	return x
}

func setFailpoint(t *testing.T, f func() error) {
	afterInnerChown = f
	t.Cleanup(func() { afterInnerChown = nil })
}

func TestCreateProjectDir_OwnerAndModes(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	dir := p.ProjectDir(testRef)
	hit := false
	setFailpoint(t, func() error {
		hit = true
		for _, sub := range []string{"data", "sock"} {
			u, g, m := owner(t, filepath.Join(dir, sub))
			if int(u) != uid || int(g) != gid || m != os.ModeDir|0o700 {
				t.Errorf("at failpoint %s: %d:%d %v", sub, u, g, m)
			}
		}
		if u, g, _ := owner(t, dir); u != 0 || g != 0 {
			t.Errorf("outer chowned before the inner ones: %d:%d", u, g)
		}
		return nil
	})
	if err := CreateProjectDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	if !hit {
		t.Fatal("failpoint not reached")
	}
	for _, d := range []string{dir, filepath.Join(dir, "data"), filepath.Join(dir, "sock")} {
		u, g, m := owner(t, d)
		if int(u) != uid || int(g) != gid || m != os.ModeDir|0o700 {
			t.Errorf("%s: %d:%d %v", d, u, g, m)
		}
		x := projid(t, d)
		if int(x.Projid) != uid || x.Xflags&fsXflagProjInherit == 0 {
			t.Errorf("%s: project id %d flags %#x", d, x.Projid, x.Xflags)
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2 {
		t.Errorf("entries: %v", ents)
	}
}

func TestCreateProjectDir_IdempotentOnOwner(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	if err := CreateProjectDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(p.ProjectDir(testRef), "data")
	// Stand-in for tenant activity: a changed mode below the outer directory.
	if err := os.Chmod(data, 0o750); err != nil {
		t.Fatal(err)
	}
	setFailpoint(t, func() error { t.Error("steps repeated on a completed directory"); return nil })
	if err := CreateProjectDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	if _, _, m := owner(t, data); m.Perm() != 0o750 {
		t.Fatalf("data touched: %v", m)
	}
}

func TestCreateProjectDir_ResumeAfterPartial(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	dir := p.ProjectDir(testRef)
	interrupted := errors.New("interrupted")
	setFailpoint(t, func() error { return interrupted })
	if err := CreateProjectDir(p, testRef, uid, gid, 16); !errors.Is(err, interrupted) {
		t.Fatalf("got %v", err)
	}
	if u, _, _ := owner(t, dir); u != 0 {
		t.Fatalf("outer owner %d after interruption", u)
	}
	afterInnerChown = nil
	if err := CreateProjectDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	if u, g, m := owner(t, dir); int(u) != uid || int(g) != gid || m.Perm() != 0o700 {
		t.Fatalf("after resume: %d:%d %v", u, g, m)
	}

	// Interrupted right after the first mkdir: a bare root-owned directory.
	ref2 := "zzzzzzzzzz0123456789"
	if err := os.Mkdir(p.ProjectDir(ref2), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CreateProjectDir(p, ref2, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"", "data", "sock"} {
		if u, _, m := owner(t, filepath.Join(p.ProjectDir(ref2), d)); int(u) != uid || m.Perm() != 0o700 {
			t.Fatalf("%q after resume: %d %v", d, u, m)
		}
	}
}

// A root-owned outer directory with any mode but 0700 was not left by an
// interrupted call and is refused untouched.
func TestCreateProjectDir_ResumeRefusesOuterMode(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	dir := p.ProjectDir(testRef)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, m := range []os.FileMode{0o755, 0o750, 0o770, 0o777, 0o500, 0o700 | os.ModeSticky} {
		if err := os.Chmod(dir, m); err != nil {
			t.Fatal(err)
		}
		if err := CreateProjectDir(p, testRef, uid, gid, 16); err == nil {
			t.Errorf("mode %v: resume accepted it", m)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Fatalf("mode %v: created %v", m, ents)
		}
		if u, _, _ := owner(t, dir); u != 0 {
			t.Fatalf("mode %v: chowned", m)
		}
	}
}

func TestCreateProjectDir_ForeignOwner(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	dir := p.ProjectDir(testRef)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, uid+1, gid+1); err != nil {
		t.Fatal(err)
	}
	if err := CreateProjectDir(p, testRef, uid, gid, 16); !errors.Is(err, ErrExistsForeign) {
		t.Fatalf("got %v, want ErrExistsForeign", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("created inside a foreign directory: %v", ents)
	}
	// The right uid with another gid is foreign too.
	if err := os.Chown(dir, uid, gid+1); err != nil {
		t.Fatal(err)
	}
	if err := CreateProjectDir(p, testRef, uid, gid, 16); !errors.Is(err, ErrExistsForeign) {
		t.Fatalf("uid match, gid mismatch: got %v", err)
	}
	// A root-owned outer directory holding a foreign-owned data directory.
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(dir, "data"), uid+2, gid+2); err != nil {
		t.Fatal(err)
	}
	if err := CreateProjectDir(p, testRef, uid, gid, 16); !errors.Is(err, ErrExistsForeign) {
		t.Fatalf("foreign data: got %v", err)
	}
	if u, _, _ := owner(t, filepath.Join(dir, "data")); int(u) != uid+2 {
		t.Fatalf("foreign data chowned: %d", u)
	}
	// Neither a link nor a file at the ref is accepted.
	ref2 := "linklinklink01234567"
	if err := os.Symlink(t.TempDir(), p.ProjectDir(ref2)); err != nil {
		t.Fatal(err)
	}
	if err := CreateProjectDir(p, ref2, uid, gid, 16); err == nil {
		t.Fatal("a link at the ref was accepted")
	}
}

// TestProjectTree_RootTouchesNothingAfterCreation acts as the tenant: it
// replaces data with a link to a canary outside the tree (once, then in a loop
// racing the calls, then with a FIFO in place of sock) and checks that no call
// root makes afterwards changes the canary.
func TestProjectTree_RootTouchesNothingAfterCreation(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	dir := p.ProjectDir(testRef)
	if err := CreateProjectDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	canary, err := os.MkdirTemp("", "nodefs-canary-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(canary) })
	if err := os.Chmod(canary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(canary, "f"), []byte("canary"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := func() string {
		u, g, m := owner(t, canary)
		var b strings.Builder
		fmt.Fprintf(&b, "%d:%d %v %v;", u, g, m, projid(t, canary))
		ents, _ := os.ReadDir(canary)
		for _, e := range ents {
			c, _ := os.ReadFile(filepath.Join(canary, e.Name()))
			fu, fg, fm := owner(t, filepath.Join(canary, e.Name()))
			fmt.Fprintf(&b, "%s %d:%d %v %q;", e.Name(), fu, fg, fm, c)
		}
		return b.String()
	}
	before := snap()
	calls := func() {
		if err := CreateProjectDir(p, testRef, uid, gid, 16); err != nil {
			t.Errorf("CreateProjectDir: %v", err)
		}
		if err := SetQuota(p, uid, 32); err != nil {
			t.Errorf("SetQuota: %v", err)
		}
		if err := RemoveEmptyProjectDir(p, testRef); err == nil {
			t.Error("RemoveEmptyProjectDir removed a non-empty project directory")
		}
	}

	asTenant(t, uid, gid, "symlink", dir, canary)
	calls()
	if fi, err := os.Lstat(filepath.Join(dir, "data")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("root repaired the tenant's link: %v %v", fi, err)
	}
	if got := snap(); got != before {
		t.Fatalf("canary changed:\n%s\n%s", before, got)
	}

	// The tenant swaps children while root calls in.
	var wg sync.WaitGroup
	wg.Add(1)
	var raceOut string
	var raceCode int
	go func() { defer wg.Done(); raceOut, raceCode = runTenant(t, uid, gid, "race", dir, canary, "1500") }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		calls()
	}
	wg.Wait()
	if raceCode != 0 {
		t.Fatalf("race helper: exit %d: %s", raceCode, raceOut)
	}
	if got := snap(); got != before {
		t.Fatalf("canary changed under the race:\n%s\n%s", before, got)
	}

	// A FIFO where root might open a directory.
	asTenant(t, uid, gid, "fifo", dir)
	done := make(chan struct{})
	go func() { calls(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a call blocked on the tenant's FIFO")
	}
	if got := snap(); got != before {
		t.Fatalf("canary changed:\n%s\n%s", before, got)
	}
}

// ───────── validation at the boundary (any user) ─────────

func TestProjectDir_RefusesBadRefsAndIDs(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(p.ProjectsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"", ".", "..", "../" + testRef[3:], "abc/efghij0123456789", "ABCDEFGHIJ0123456789",
		testRef + "\x00", testRef[:19], testRef + "a", strings.Repeat("a", 300)} {
		if err := CreateProjectDir(p, ref, 900001, 900001, 16); err == nil {
			t.Errorf("CreateProjectDir accepted ref %q", ref)
		}
		if err := RemoveEmptyProjectDir(p, ref); err == nil {
			t.Errorf("RemoveEmptyProjectDir accepted ref %q", ref)
		}
	}
	for _, c := range []struct{ uid, gid, mb int }{
		{0, 900001, 16}, {900001, 0, 16}, {-1, 900001, 16}, {900001, -1, 16},
		{1<<32 - 1, 900001, 16}, {900001, 1<<32 - 1, 16}, {1 << 40, 900001, 16},
		{900001, 900001, 0}, {900001, 900001, -1},
	} {
		if err := CreateProjectDir(p, testRef, c.uid, c.gid, c.mb); err == nil {
			t.Errorf("CreateProjectDir accepted %d:%d %d MiB", c.uid, c.gid, c.mb)
		}
	}
	// Project ids lie within [65536, 2^31-1], like the range CheckRange admits.
	for _, id := range []int{1, 70, 65532, 65534, 65535, 1 << 31} {
		if err := CreateProjectDir(p, testRef, id, 900001, 16); err == nil {
			t.Errorf("CreateProjectDir accepted uid %d", id)
		}
		if err := CreateProjectDir(p, testRef, 900001, id, 16); err == nil {
			t.Errorf("CreateProjectDir accepted gid %d", id)
		}
		if err := SetQuota(p, id, 16); err == nil {
			t.Errorf("SetQuota accepted uid %d", id)
		}
	}
	for _, c := range []struct{ uid, mb int }{{0, 16}, {-1, 16}, {1<<32 - 1, 16}, {900001, -1}, {900001, 1<<30 + 1}} {
		if err := SetQuota(p, c.uid, c.mb); err == nil {
			t.Errorf("SetQuota accepted uid %d %d MiB", c.uid, c.mb)
		}
	}
	if ents, _ := os.ReadDir(p.ProjectsDir()); len(ents) != 0 {
		t.Fatalf("entries created: %v", ents)
	}
}

func TestProjectDir_ProjectsDirLinkOrWeakRefused(t *testing.T) {
	root := t.TempDir()
	p := nodecfg.Paths{Root: root}
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p.ProjectsDir()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, p.ProjectsDir()); err != nil {
		t.Fatal(err)
	}
	if err := CreateProjectDir(p, testRef, 900001, 900001, 16); err == nil {
		t.Error("CreateProjectDir through a linked ProjectsDir succeeded")
	}
	if err := RemoveEmptyProjectDir(p, testRef); err == nil {
		t.Error("RemoveEmptyProjectDir through a linked ProjectsDir succeeded")
	}
	if ents, _ := os.ReadDir(real); len(ents) != 0 {
		t.Fatalf("created through the link: %v", ents)
	}
	os.Remove(p.ProjectsDir())
	if err := os.Mkdir(p.ProjectsDir(), 0o777); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p.ProjectsDir(), 0o777)
	if err := os.Mkdir(p.ProjectDir(testRef), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEmptyProjectDir(p, testRef); err == nil {
		t.Error("RemoveEmptyProjectDir below a world-writable ProjectsDir succeeded")
	}
	if err := CreateProjectDir(p, "bbbbbbbbbb0123456789", 900001, 900001, 16); err == nil {
		t.Error("CreateProjectDir below a world-writable ProjectsDir succeeded")
	}
}

// ───────── WriteFile (any user) ─────────

func TestWriteFile_ExactModeUnderUmask(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	dir := mkRenderDir(t, p)
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	uid, gid := me()
	for _, m := range []os.FileMode{0o644, 0o400, 0o4755 | os.ModeSetuid} {
		if err := WriteFile(p, dir, "f", []byte("x"), m, uid, gid); err != nil {
			t.Fatal(err)
		}
		_, _, got := owner(t, filepath.Join(dir, "f"))
		if got != m.Perm() {
			t.Errorf("mode %v: got %v, want %v", m, got, m.Perm())
		}
	}
}

func TestWriteFile_DirectoryAtNameAndPathForms(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	dir := mkRenderDir(t, p)
	uid, gid := me()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, dir, "d", []byte("x"), 0o444, uid, gid); err == nil {
		t.Error("WriteFile over a directory succeeded")
	}
	if fi, err := os.Lstat(filepath.Join(dir, "d")); err != nil || !fi.IsDir() {
		t.Errorf("directory replaced: %v", err)
	}
	// A trailing slash and a redundant dot are the same directory.
	for _, d := range []string{dir + "/", dir + "/./"} {
		if err := WriteFile(p, d, "ok", []byte("x"), 0o444, uid, gid); err != nil {
			t.Errorf("%s: %v", d, err)
		}
	}
	// .. that leaves the render roots is refused before anything is opened.
	for _, d := range []string{
		p.GatewayDir() + "/../../projects",
		filepath.Dir(p.NodeJSON()) + "-evil",
		filepath.Dir(p.NodeJSON()) + "/../..",
	} {
		if err := WriteFile(p, d, "f", []byte("x"), 0o444, uid, gid); !errors.Is(err, ErrOutsideRenderRoot) {
			t.Errorf("%s: got %v", d, err)
		}
	}
	if err := WriteFile(p, dir, "a\x00b", []byte("x"), 0o444, uid, gid); err == nil {
		t.Error("NUL in name accepted")
	}
	assertNoTemp(t, dir)
}

// An error after the temporary file exists removes it and does not leak the
// content into the error.
func TestWriteFile_ErrorRemovesTemp(t *testing.T) {
	if os.Geteuid() == 0 {
		// Root's chown never fails: run this test again as nobody.
		out, code := runAs(t, 65534, 65534, nil, "-test.run=^TestWriteFile_ErrorRemovesTemp$", "-test.v")
		if code != 0 || !strings.Contains(out, "--- PASS: TestWriteFile_ErrorRemovesTemp") {
			t.Fatalf("unprivileged run: exit %d: %s", code, out)
		}
		return
	}
	p := nodecfg.Paths{Root: t.TempDir()}
	dir := mkRenderDir(t, p)
	err := WriteFile(p, dir, "f", []byte("s3cr3t-content"), 0o400, 0, 0)
	if err == nil {
		t.Fatal("chown to root as a user succeeded")
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("content in error: %v", err)
	}
	assertNoTemp(t, dir)
	if _, err := os.Lstat(filepath.Join(dir, "f")); !os.IsNotExist(err) {
		t.Errorf("target created: %v", err)
	}
}

// ───────── CheckRange edges ─────────

func TestCheckRange_Edges(t *testing.T) {
	const base, count = 700000, 65536
	ok := func(s string) bool {
		return CheckRange(base, count, strings.NewReader(s), strings.NewReader(""), nil, nil) == nil
	}
	sub := func(s string) bool {
		return CheckRange(base, count, strings.NewReader(""), strings.NewReader(""), strings.NewReader(s), nil) == nil
	}
	grp := func(s string) bool {
		return CheckRange(base, count, strings.NewReader(""), strings.NewReader(s), nil, nil) == nil
	}
	for _, c := range []struct {
		name string
		got  bool
		want bool
	}{
		{"uid just below", ok("a:x:699999:1:g:/:/bin/sh\n"), true},
		{"uid just above", ok("a:x:765536:1:g:/:/bin/sh\n"), true},
		{"CRLF inside", ok("a:x:700001:1:g:/:/bin/sh\r\n"), false},
		{"CRLF outside", ok("a:x:1:1:g:/:/bin/sh\r\n"), true},
		{"uid above 32 bits", ok("a:x:4294967296:1:g:/:/bin/sh\n"), false},
		{"negative uid", ok("a:x:-1:1:g:/:/bin/sh\n"), false},
		{"too few fields", ok("a:x:1:1\n"), false},
		{"very long line", ok("a:x:1:1:" + strings.Repeat("g", 1<<17) + ":/:/bin/sh\n"), false},
		{"gid only, group file", grp("g:x:765535:\n"), false},
		{"subuid adjacent after", sub("u:765536:10\n"), true},
		{"subuid zero count inside", sub("u:700001:0\n"), true},
		{"subuid huge count", sub("u:1:4294967295\n"), false},
		{"subuid malformed count", sub("u:1:x\n"), false},
	} {
		if c.got != c.want {
			t.Errorf("%s: ok=%v, want %v", c.name, c.got, c.want)
		}
	}
	for _, r := range [][2]int{{1<<32 - 10, 11}, {0, 0}, {5, -1}} {
		if err := CheckRange(r[0], r[1], strings.NewReader(""), strings.NewReader(""), nil, nil); err == nil {
			t.Errorf("range %v accepted", r)
		}
	}
}

// ───────── root and XFS ─────────

// TestCreateProjectDir_ResumeRefusesPlantedChildren: with the outer directory
// still root-owned, a data or sock entry that is not a directory owned by root
// or by the pair is refused, nothing is chowned, and nothing outside changes.
func TestCreateProjectDir_ResumeRefusesPlantedChildren(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	canary := t.TempDir()
	os.Chmod(canary, 0o755)
	cu, cg, cm := owner(t, canary)
	cx := projid(t, canary)
	plants := map[string]func(dir string) error{
		"data link": func(d string) error { return os.Symlink(canary, filepath.Join(d, "data")) },
		"sock link": func(d string) error { return os.Symlink(canary, filepath.Join(d, "sock")) },
		"data file": func(d string) error { return os.WriteFile(filepath.Join(d, "data"), nil, 0o600) },
		"data fifo": func(d string) error { return syscall.Mkfifo(filepath.Join(d, "data"), 0o600) },
		"sock fifo": func(d string) error { return syscall.Mkfifo(filepath.Join(d, "sock"), 0o600) },
		"data foreign": func(d string) error {
			if err := os.Mkdir(filepath.Join(d, "data"), 0o700); err != nil {
				return err
			}
			return os.Chown(filepath.Join(d, "data"), uid+7, gid+7)
		},
		"data foreign gid": func(d string) error {
			if err := os.Mkdir(filepath.Join(d, "data"), 0o700); err != nil {
				return err
			}
			return os.Chown(filepath.Join(d, "data"), uid, gid+7)
		},
	}
	i := 0
	for name, plant := range plants {
		i++
		ref := strings.Repeat(string(rune('k'+i)), 10) + "0123456789"
		dir := p.ProjectDir(ref)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := plant(dir); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- CreateProjectDir(p, ref, uid, gid, 16) }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: resume accepted it", name)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: CreateProjectDir blocked", name)
		}
		if u, _, _ := owner(t, dir); u != 0 {
			t.Errorf("%s: outer chowned to %d", name, u)
		}
	}
	if u, g, m := owner(t, canary); u != cu || g != cg || m != cm || projid(t, canary) != cx {
		t.Fatalf("canary changed: %d:%d %v %v", u, g, m, projid(t, canary))
	}
	if ents, _ := os.ReadDir(canary); len(ents) != 0 {
		t.Fatalf("created in the canary: %v", ents)
	}
}

// TestProjectTree_TenantSocketAndFIFO: a tenant socket in place of sock and a
// FIFO in place of data neither block nor redirect any later call.
func TestProjectTree_TenantSocketAndFIFO(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	dir := p.ProjectDir(testRef)
	if err := CreateProjectDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	asTenant(t, uid, gid, "socket", dir)
	if err := os.Remove(filepath.Join(dir, "data")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "data"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Lchown(filepath.Join(dir, "data"), uid, gid)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := CreateProjectDir(p, testRef, uid, gid, 16); err != nil {
			t.Errorf("CreateProjectDir: %v", err)
		}
		if err := SetQuota(p, uid, 32); err != nil {
			t.Errorf("SetQuota: %v", err)
		}
		if err := RemoveEmptyProjectDir(p, testRef); err == nil {
			t.Error("removed a non-empty project directory")
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a call blocked")
	}
	if fi, err := os.Lstat(filepath.Join(dir, "sock")); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket touched: %v %v", fi, err)
	}
}

func TestWriteFile_NonRootOwnedDirRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	p := nodecfg.Paths{Root: t.TempDir()}
	dir := mkRenderDir(t, p)
	for _, d := range []string{dir, filepath.Dir(dir), p.PlatformDir()} {
		if err := os.Chown(d, 4242, 0); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(p, dir, "f", []byte("x"), 0o444, 0, 0); err == nil {
			t.Errorf("write with %s owned by 4242 succeeded", d)
		}
		os.Chown(d, 0, 0)
	}
	if err := WriteFile(p, dir, "f", []byte("x"), 0o400, 4242, 4343); err != nil {
		t.Fatal(err)
	}
	if u, g, m := owner(t, filepath.Join(dir, "f")); u != 4242 || g != 4343 || m != 0o400 {
		t.Fatalf("got %d:%d %v", u, g, m)
	}
}

// TestSetQuota_DistrustsXfsQuota replaces xfs_quota with scripts that exit 0
// while failing: one reports on standard error, one prints nothing, one reads
// back another limit.
func TestSetQuota_DistrustsXfsQuota(t *testing.T) {
	p := xfsPaths(t)
	bin := t.TempDir()
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	const state = `*state*) printf 'User quota state on /m (/dev/x)\n  Accounting: ON\n  Enforcement: ON\n';;`
	const good = `'/dev/x 0 0 16384 00 [--------] 3 0 65536 00 [--------] /m'`
	for name, script := range map[string]string{
		"stderr":                "echo 'xfs_quota: cannot set limits' >&2",
		"silent":                `case "$*" in ` + state + ` esac`,
		"wrong block limit":     `case "$*" in ` + state + ` *quota*) echo '/dev/x 0 0 1024 00 [--------] 3 0 65536 00 [--------] /m';; esac`,
		"wrong inode limit":     `case "$*" in ` + state + ` *quota*) echo '/dev/x 0 0 16384 00 [--------] 3 0 0 00 [--------] /m';; esac`,
		"two records":           `case "$*" in ` + state + ` *quota*) echo ` + good + `; echo ` + good + `;; esac`,
		"stderr, good readback": `echo 'xfs_quota: warning' >&2; case "$*" in ` + state + ` *quota*) echo ` + good + `;; esac`,
		"enforcement off":       `case "$*" in *state*) printf '  Accounting: ON\n  Enforcement: OFF\n';; *quota*) echo ` + good + `;; esac`,
		"no state":              `case "$*" in *quota*) echo ` + good + `;; esac`,
	} {
		if err := os.WriteFile(filepath.Join(bin, "xfs_quota"), []byte("#!/bin/sh\n"+script+"\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := SetQuota(p, 900042, 16); err == nil {
			t.Errorf("%s: SetQuota trusted a failing xfs_quota", name)
		}
	}
}

// A root-owned data directory left with another mode by an interrupted call
// ends 0700.
func TestCreateProjectDir_ResumeFixesInnerMode(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	dir := p.ProjectDir(testRef)
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o700)
	os.Chmod(filepath.Join(dir, "data"), 0o755)
	if err := CreateProjectDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	if u, _, m := owner(t, filepath.Join(dir, "data")); int(u) != uid || m.Perm() != 0o700 {
		t.Fatalf("data: %d %v", u, m)
	}
}

// SetQuota refuses ids outside the project range on a real quota mount, and
// records no limit for them.
func TestSetQuota_RefusesOutOfRangeIDs(t *testing.T) {
	p := xfsPaths(t)
	for _, id := range []int{1, 65535, 1 << 31} {
		t.Cleanup(func() {
			exec.Command("xfs_quota", "-x", "-c", fmt.Sprintf("limit -u bhard=0 ihard=0 %d", id), p.ProjectsDir()).Run()
		})
		if err := SetQuota(p, id, 16); err == nil {
			t.Errorf("SetQuota accepted uid %d", id)
		}
		recs, err := readLimits(p.ProjectsDir(), id)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if r != [2]int{0, 0} {
				t.Errorf("uid %d: limit recorded: %d KiB / %d inodes", id, r[0], r[1])
			}
		}
	}
}

// Limits on id 0 are XFS's default limits for every id: SetQuota must never
// set them.
func TestSetQuota_RefusesRootID(t *testing.T) {
	p := xfsPaths(t)
	t.Cleanup(func() {
		if out, err := exec.Command("xfs_quota", "-x", "-c", "limit -u bhard=0 ihard=0 0", p.ProjectsDir()).CombinedOutput(); err != nil || len(out) > 0 {
			t.Errorf("clear id 0: %v %s", err, out)
		}
	})
	if err := SetQuota(p, 0, 16); err == nil {
		t.Error("SetQuota accepted uid 0")
	}
	recs, err := readLimits(p.ProjectsDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r != [2]int{0, 0} {
			t.Fatalf("default user limits set: %d KiB / %d inodes", r[0], r[1])
		}
	}
}

// ───────── tenant helper ─────────

var (
	helperOnce sync.Once
	helperBin  string
	helperErr  error
)

// asTenant runs the test binary again at uid:gid with a tenant command and
// returns its output; a non-zero exit fails the test.
func asTenant(t *testing.T, uid, gid int, args ...string) string {
	t.Helper()
	out, code := runTenant(t, uid, gid, args...)
	if code != 0 {
		t.Fatalf("tenant %v: exit %d: %s", args, code, out)
	}
	return out
}

func runTenant(t *testing.T, uid, gid int, args ...string) (string, int) {
	t.Helper()
	return runAs(t, uid, gid, []string{"NODEFS_TENANT_HELPER=1"}, args...)
}

func copyHelper(t *testing.T) {
	t.Helper()
	helperOnce.Do(func() {
		// The binary may sit in a directory the project uid cannot read
		// (/root); a world-readable copy is executed instead.
		self, err := os.Executable()
		if err != nil {
			helperErr = err
			return
		}
		d, err := os.MkdirTemp("", "nodefs-helper-")
		if err != nil {
			helperErr = err
			return
		}
		os.Chmod(d, 0o755)
		helperBin = filepath.Join(d, "tenant")
		src, err := os.Open(self)
		if err != nil {
			helperErr = err
			return
		}
		defer src.Close()
		dst, err := os.OpenFile(helperBin, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
		if err != nil {
			helperErr = err
			return
		}
		_, helperErr = io.Copy(dst, src)
		if cerr := dst.Close(); helperErr == nil {
			helperErr = cerr
		}
	})
	if helperErr != nil {
		t.Fatal(helperErr)
	}
}

// runAs runs a world-readable copy of the test binary at uid:gid.
func runAs(t *testing.T, uid, gid int, env []string, args ...string) (string, int) {
	t.Helper()
	copyHelper(t)
	cmd := exec.Command(helperBin, args...)
	cmd.Dir = "/"
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	default:
		return err.Error(), -1
	}
}

// tenantMain is the tenant side. Exit 0 = done, 2 = a quota error was hit,
// 1 = anything else.
func tenantMain(args []string) int {
	fail := func(err error) int { fmt.Println(err); return 1 }
	switch args[0] {
	case "symlink": // <projectdir> <target>: replace data with a link
		data := filepath.Join(args[1], "data")
		if err := os.Remove(data); err != nil {
			return fail(err)
		}
		if err := os.Symlink(args[2], data); err != nil {
			return fail(err)
		}
	case "race": // <projectdir> <target> <ms>: swap children in a loop
		ms, _ := strconv.Atoi(args[3])
		data := filepath.Join(args[1], "data")
		alt := filepath.Join(args[1], "alt")
		for end := time.Now().Add(time.Duration(ms) * time.Millisecond); time.Now().Before(end); {
			os.Rename(data, alt)
			os.Symlink(args[2], data)
			os.Rename(data, filepath.Join(args[1], "sock2"))
			os.Rename(alt, data)
			os.Remove(filepath.Join(args[1], "sock2"))
		}
	case "touch": // <dir> <n>: make dir and n empty files in it; prints the count made
		n, _ := strconv.Atoi(args[2])
		if err := os.Mkdir(args[1], 0o700); err != nil {
			return fail(err)
		}
		made := 0
		for ; made < n; made++ {
			f, err := os.OpenFile(filepath.Join(args[1], strconv.Itoa(made)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				fmt.Println(made)
				return quotaExit(err)
			}
			f.Close()
		}
		fmt.Println(made)
	case "fifo": // <projectdir>: replace sock with a FIFO
		sock := filepath.Join(args[1], "sock")
		if err := os.Remove(sock); err != nil {
			return fail(err)
		}
		if err := syscall.Mkfifo(sock, 0o600); err != nil {
			return fail(err)
		}
	case "socket": // <projectdir>: replace sock with a unix socket node
		sock := filepath.Join(args[1], "sock")
		if err := os.Remove(sock); err != nil {
			return fail(err)
		}
		fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			return fail(err)
		}
		defer syscall.Close(fd)
		if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: sock}); err != nil {
			return fail(err)
		}
	case "fill": // <file> <MiB> [plain|escape|<projid>]: write; "escape" first moves the file to project id 0, a number to that project id
		mib, _ := strconv.Atoi(args[2])
		f, err := os.OpenFile(args[1], os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		if len(args) > 3 && args[3] != "plain" {
			var x fsxattr
			if err := ioctlFsxattr(int(f.Fd()), fsIocFsGetXattr, &x); err != nil {
				return fail(err)
			}
			x.Projid = 0
			if args[3] != "escape" {
				id, _ := strconv.Atoi(args[3])
				x.Projid = uint32(id)
			}
			if err := ioctlFsxattr(int(f.Fd()), fsIocFsSetXattr, &x); err != nil {
				return fail(fmt.Errorf("escape: %w", err))
			}
		}
		buf := bytes.Repeat([]byte{0x5a}, 1<<20)
		for i := 0; i < mib; i++ {
			if _, err := f.Write(buf); err != nil {
				return quotaExit(err)
			}
		}
		if err := f.Sync(); err != nil {
			return quotaExit(err)
		}
	default:
		return fail(fmt.Errorf("unknown tenant command %q", args[0]))
	}
	return 0
}

func quotaExit(err error) int {
	fmt.Println(err)
	if errors.Is(err, syscall.EDQUOT) || errors.Is(err, syscall.ENOSPC) {
		return 2
	}
	return 1
}

// TestSetQuota_ReadsWrappedDeviceName: xfs_quota puts a long device name
// (a device-mapper volume) on a line of its own; the limits are still read.
func TestSetQuota_ReadsWrappedDeviceName(t *testing.T) {
	p := xfsPaths(t)
	bin := t.TempDir()
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	t.Setenv("LANG", "de_DE.UTF-8")
	script := "#!/bin/sh\n[ \"$LC_ALL\" = C ] || { echo \"locale $LC_ALL\" >&2; exit 1; }\n" +
		"for a in \"$@\"; do case \"$a\" in \"quota -v\"*)\n" +
		"printf '/dev/mapper/vg0-projects\\n                             0          0      16384   00 [--------]           3          0      65536   00 [--------] /m\\n';;\n" +
		"\"state -u\") printf 'User quota state on /m (/dev/mapper/vg0-projects)\\n  Accounting: ON\\n  Enforcement: ON\\n';; esac; done\n"
	if err := os.WriteFile(filepath.Join(bin, "xfs_quota"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SetQuota(p, 900042, 16); err != nil {
		t.Fatal(err)
	}
}
