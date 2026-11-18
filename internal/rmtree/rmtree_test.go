//go:build linux

package rmtree

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// write creates the file rel below dir, with its parent directories.
func write(t *testing.T, dir, rel string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustRemove(t *testing.T, root string) {
	t.Helper()
	if err := Remove(root); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root still there after Remove: %v", err)
	}
}

// bothForms runs f for Remove (keep false) and for Empty (keep true).
func bothForms(t *testing.T, f func(t *testing.T, keep bool)) {
	t.Run("Remove", func(t *testing.T) { f(t, false) })
	t.Run("Empty", func(t *testing.T) { f(t, true) })
}

// mustClear runs Remove, or Empty when keep is set, on root and checks the
// result: no root, or an empty root its owner can use.
func mustClear(t *testing.T, root string, keep bool) {
	t.Helper()
	if !keep {
		mustRemove(t, root)
		return
	}
	if err := Empty(root); err != nil {
		t.Fatalf("Empty: %v", err)
	}
	fi, err := os.Lstat(root)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o700 != 0o700 {
		t.Fatalf("root after Empty: %v %v", fi, err)
	}
	if es, err := os.ReadDir(root); err != nil || len(es) != 0 {
		t.Fatalf("root not empty after Empty (%v): %d entries left, first %v", err, len(es), es[:min(1, len(es))])
	}
}

func mustExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); err != nil {
		t.Fatalf("%s should be untouched: %v", p, err)
	}
}

// withHook installs f as the after-read hook for the rest of the test.
func withHook(t *testing.T, f func()) {
	t.Helper()
	afterRead = f
	t.Cleanup(func() { afterRead = nil })
}

func TestRemove_OrdinaryTree(t *testing.T) { bothForms(t, testOrdinaryTree) }

func testOrdinaryTree(t *testing.T, keep bool) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	for _, rel := range []string{"a/b/c/f1", "a/f2", "d/e/f3", "f4"} {
		write(t, root, rel, 0o644)
	}
	if err := os.Mkdir(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	sibling := write(t, base, "sibling", 0o644)
	mustClear(t, root, keep)
	mustExist(t, sibling)
}

func TestRemove_AbsentRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	for range 2 {
		if err := Remove(root); err != nil {
			t.Fatalf("absent root: %v", err)
		}
	}
}

func TestRemove_RootNotADirectory(t *testing.T) {
	base := t.TempDir()
	file := write(t, base, "file", 0o644)
	for _, f := range []func(string) error{Remove, Empty} {
		if err := f(file); err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("file root: %v", err)
		}
	}
	if fi, err := os.Lstat(file); err != nil || fi.Mode() != 0o644 {
		t.Fatalf("refused file root changed: %v %v", fi, err)
	}

	target := filepath.Join(base, "target")
	inside := write(t, target, "inside", 0o644)
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Remove(link); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("symlink root: %v", err)
	}
	mustExist(t, link)
	mustExist(t, inside)
}

func TestRemove_RefusesBadRoots(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	keep := write(t, dir, "rel/keep", 0o644)
	for _, root := range []string{"", "rel", "./rel", "rel/", dir + "/../" + filepath.Base(dir) + "/rel",
		dir + "/rel/", dir + "//rel", dir + "/./rel", "/"} {
		if err := Remove(root); err == nil || !strings.Contains(err.Error(), "absolute, clean") {
			t.Errorf("Remove(%q) = %v; want a refusal", root, err)
		}
	}
	mustExist(t, keep)
}

func TestRemove_RefusesUID0(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	keep := write(t, root, "keep", 0o644)
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = os.Geteuid })
	if err := Remove(root); err == nil || !strings.Contains(err.Error(), "uid 0") {
		t.Fatalf("as uid 0: %v", err)
	}
	mustExist(t, keep)
}

// treeFds counts this process's open descriptors on dir or below it. A link
// too long to read fails the test: the walk must stay where a path can name
// it. The listing's own descriptor is closed by the time it is read back.
func treeFds(t *testing.T, dir string) int {
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range es {
		l, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("descriptor %s: %v", e.Name(), err)
		}
		if strings.HasPrefix(l, dir) {
			n++
		}
	}
	return n
}

// TestRemove_Deep removes a chain of 5,000 directories, far deeper than any
// path can name, with mode-000 directories and files along it, while the
// number of open descriptors stays constant.
func TestRemove_Deep(t *testing.T) { bothForms(t, testDeep) }

func testDeep(t *testing.T, keep bool) {
	const depth = 5000
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	zeroDir := map[int]bool{1: true, 2: true, 2500: true, depth - 1: true}
	var parents []int // descriptors of the directories holding a mode-000 one
	for i := 1; i <= depth; i++ {
		if i%1000 == 1 || i == depth {
			f, err := syscall.Openat(fd, "f", syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			syscall.Close(f)
		}
		if err := syscall.Mkdirat(fd, "d", 0o700); err != nil {
			t.Fatalf("mkdir level %d: %v", i, err)
		}
		next, err := syscall.Openat(fd, "d", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if zeroDir[i] {
			parents = append(parents, fd)
		} else {
			syscall.Close(fd)
		}
		fd = next
	}
	syscall.Close(fd)
	for i := len(parents) - 1; i >= 0; i-- { // deepest first: each needs its parent searchable
		p := parents[i]
		if err := syscall.Fchmodat(p, "d", 0, 0); err != nil {
			t.Fatal(err)
		}
		syscall.Close(p)
	}
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}

	peak, calls := 0, 0
	withHook(t, func() {
		calls++
		peak = max(peak, treeFds(t, filepath.Dir(root)))
	})
	mustClear(t, root, keep)
	if calls < depth {
		t.Fatalf("hook ran %d times; the walk did not visit every level", calls)
	}
	if peak != hoistDepth+2 { // the root's parent and a full stack
		t.Fatalf("%d descriptors open in the tree during removal; want %d", peak, hoistDepth+2)
	}
}

// TestRemove_WideDirectory removes 200,000 entries of one directory while the
// live heap stays bounded: entries are read and handled one batch at a time.
func TestRemove_WideDirectory(t *testing.T) {
	const n = 200_000
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := syscall.Mknodat(fd, fmt.Sprintf("entry-%018d", i), syscall.S_IFREG|0o600, 0); err != nil {
			t.Fatal(err)
		}
	}
	syscall.Close(fd)

	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	base, peak, calls := ms.HeapAlloc, uint64(0), 0
	withHook(t, func() {
		calls++
		runtime.GC()
		runtime.ReadMemStats(&ms)
		peak = max(peak, ms.HeapAlloc)
	})
	mustRemove(t, root)
	if calls < 10 {
		t.Fatalf("hook ran %d times; entries were not read in batches", calls)
	}
	if grew := int64(peak) - int64(base); grew > 2<<20 {
		t.Fatalf("live heap grew by %d bytes during removal; want under 2 MiB", grew)
	}
}

func TestRemove_ModeZeroEntries(t *testing.T) { bothForms(t, testModeZeroEntries) }

func testModeZeroEntries(t *testing.T, keep bool) {
	root := filepath.Join(t.TempDir(), "root")
	write(t, root, "a/b/c/f", 0)
	write(t, root, "a/f", 0)
	write(t, root, "w/f", 0o644)
	write(t, root, "x/f", 0o644)
	for _, c := range []struct {
		rel  string
		mode os.FileMode
	}{
		{"a/b/c", 0}, {"a/b", 0}, {"a", 0}, // no access at all, at several depths, deepest first
		{"w", 0o500}, // readable, not writable
		{"x", 0o300}, // writable, not readable
	} {
		if err := os.Chmod(filepath.Join(root, c.rel), c.mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
	mustClear(t, root, keep)
}

func TestRemove_SymlinksNotFollowed(t *testing.T) {
	base := t.TempDir()
	outDir := filepath.Join(base, "outside")
	outInDir := write(t, outDir, "keep", 0o644)
	outFile := write(t, base, "outside-file", 0o644)
	root := filepath.Join(base, "root")
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"to-dir": outDir, "to-file": outFile, "to-parent": "..", "to-base": "../..",
		"dangling": "/nonexistent", "to-self": "to-self",
	} {
		if err := os.Symlink(target, filepath.Join(sub, name)); err != nil {
			t.Fatal(err)
		}
	}
	mustRemove(t, root)
	mustExist(t, outInDir)
	mustExist(t, outFile)
}

func TestRemove_FifoAndSocket(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	if err := os.MkdirAll(filepath.Join(root, "s"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "s", "fifo0"), 0); err != nil {
		t.Fatal(err)
	}
	s, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(s, &syscall.SockaddrUnix{Name: filepath.Join(root, "s", "sock")}); err != nil {
		t.Fatal(err)
	}
	syscall.Close(s)

	done := make(chan error, 1)
	go func() { done <- Remove(root) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Remove blocked on a FIFO or socket")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root still there: %v", err)
	}
}

func TestRemove_HardLinkAndSparseFile(t *testing.T) {
	base := t.TempDir()
	outFile := write(t, base, "outside", 0o644)
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(filepath.Join(root, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outFile, filepath.Join(root, "d", "link")); err != nil {
		t.Fatal(err)
	}
	sparse := write(t, root, "sparse", 0o644)
	if err := os.Truncate(sparse, 1<<40); err != nil {
		t.Fatal(err)
	}
	mustRemove(t, root)
	var st syscall.Stat_t
	if err := syscall.Stat(outFile, &st); err != nil {
		t.Fatal(err)
	}
	if st.Nlink != 1 {
		t.Fatalf("outside file has %d links; want 1", st.Nlink)
	}
	if b, _ := os.ReadFile(outFile); string(b) != "x" {
		t.Fatalf("outside file changed: %q", b)
	}
}

// hostileNames are entry names an owner can create: line breaks, control and
// escape bytes, invalid UTF-8, the longest name the kernel allows.
var hostileNames = []string{"line\nbreak", "\x01\x1b[2J\x7f", "\xff\xfe\xc0", strings.Repeat("n", 255), " ", "-rf"}

func TestRemove_HostileNames(t *testing.T) { bothForms(t, testHostileNames) }

func testHostileNames(t *testing.T, keep bool) {
	root := filepath.Join(t.TempDir(), "root")
	for _, name := range hostileNames {
		dir := filepath.Join(root, name)
		write(t, dir, name, 0o644)
		write(t, root, "files/"+name, 0o644)
		if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mustClear(t, root, keep)
}

// TestRemove_DirectoryMovedOutDuringTheWalk moves a directory on the current
// path out of the tree while the walk is below it: next to the root, into the
// root's parent, or into another directory there. Whatever the walk does with
// the directories it already holds, nothing that was outside the tree is
// touched.
func TestRemove_DirectoryMovedOutDuringTheWalk(t *testing.T) {
	for _, tc := range []struct {
		name, move, to string // to is relative to the root's parent
	}{
		{"depth 1 into a stranger", "a", "outside/a"},
		{"depth 2 into the root's parent", "a/b", "b"},
		{"depth 2 into a stranger", "a/b", "outside/b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "root")
			if err := os.MkdirAll(filepath.Join(root, "a/b/c"), 0o755); err != nil {
				t.Fatal(err)
			}
			keep := write(t, base, "keep", 0o644)
			keepOut := write(t, base, "outside/keep", 0o644)
			keepIn := write(t, base, "outside/sub/keep", 0o644)
			calls := 0
			withHook(t, func() {
				// Reads: root, a, b, c (end of c). Then the walk leaves c.
				if calls++; calls == 4 {
					if err := os.Rename(filepath.Join(root, tc.move), filepath.Join(base, tc.to)); err != nil {
						t.Error(err)
					}
				}
			})
			t.Log(Remove(root)) // success or not, only the outside matters
			mustExist(t, keep)
			mustExist(t, keepOut)
			mustExist(t, keepIn)
		})
	}
}

func TestQuote(t *testing.T) {
	for _, name := range append(hostileNames, strings.Repeat("\x1b", 300), "caf\u00e9", "\u202e", strings.Repeat("\u00e9", 100)) {
		q := quote(name)
		if len(q) > 4*maxQuoted+8 {
			t.Errorf("quote of %d bytes is %d bytes long", len(name), len(q))
		}
		for _, c := range []byte(q) {
			if c < 0x20 || c >= 0x7f {
				t.Errorf("quote(%q) carries byte %#x", name, c)
			}
		}
	}
}

// TestRemove_MountPointInTree mounts a file system inside the tree (in a user
// and mount namespace of a child process) and checks that removal stops at
// the mount point and leaves the mounted file system's contents alone.
func TestRemove_MountPointInTree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	mnt := filepath.Join(root, "a", hostileNames[1])
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(filepath.Dir(root), "mounted"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMountHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "RMTREE_MOUNT_HELPER="+root)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "SKIP-NO-MOUNT") || (err != nil && len(out) == 0) {
		t.Skipf("cannot mount in a user namespace here: %v %s", err, out)
	}
	if err != nil || !strings.Contains(string(out), "HELPER-OK") {
		t.Fatalf("helper: %v\n%s", err, out)
	}
}

// TestMountHelper runs only as the child of TestRemove_MountPointInTree, as
// root of its own user namespace.
func TestMountHelper(t *testing.T) {
	root := os.Getenv("RMTREE_MOUNT_HELPER")
	if root == "" {
		t.Skip("helper of TestRemove_MountPointInTree")
	}
	mnt := filepath.Join(root, "a", hostileNames[1])
	if err := syscall.Mount("t", mnt, "tmpfs", 0, ""); err != nil {
		fmt.Println("SKIP-NO-MOUNT", err)
		return
	}
	keep := write(t, mnt, "keep", 0o644)
	// Root of the namespace is uid 0 here; the refusal is tested elsewhere.
	geteuid = func() int { return 1 }
	err := Remove(root)
	if err == nil || !strings.Contains(err.Error(), "another file system") {
		t.Fatalf("Remove = %v; want a mount point error", err)
	}
	for _, c := range []byte(err.Error()) {
		if c < 0x20 || c >= 0x7f {
			t.Fatalf("error text carries byte %#x: %q", c, err)
		}
	}
	mustExist(t, keep)

	// A root that is itself a mount point is refused, in both forms.
	mounted := filepath.Join(filepath.Dir(root), "mounted")
	if err := syscall.Mount("t", mounted, "tmpfs", 0, ""); err != nil {
		t.Fatal(err)
	}
	keep = write(t, mounted, "keep", 0o644)
	for _, f := range []func(string) error{Remove, Empty} {
		if err := f(mounted); err == nil || !strings.Contains(err.Error(), "another file system") {
			t.Fatalf("mounted root: %v; want a mount point error", err)
		}
	}
	mustExist(t, keep)
	fmt.Println("HELPER-OK", err)
}

// TestRemove_MovesDeepDirectoriesUp checks the moves that keep the walk within
// hoistDepth levels of the root: directories without access at the levels
// where they are moved, and names in the root that the moves must not reuse.
func TestRemove_MovesDeepDirectoriesUp(t *testing.T) { bothForms(t, testMovesDeepDirectoriesUp) }

func testMovesDeepDirectoriesUp(t *testing.T, keep bool) {
	root := filepath.Join(t.TempDir(), "root")
	chain := strings.Repeat("d/", 3*hoistDepth)
	write(t, root, chain+"f", 0o644)
	for _, level := range []int{2 * hoistDepth, hoistDepth, hoistDepth - 1} { // the levels moved up, and one above
		if err := os.Chmod(filepath.Join(root, strings.Repeat("d/", level+1)), 0); err != nil {
			t.Fatal(err)
		}
	}
	// Once the root is listed, the first names a move would take appear in it;
	// a move onto either fails (not a directory; not empty).
	calls := 0
	withHook(t, func() {
		if calls++; calls == 1 {
			write(t, root, ".rmtree-0", 0o644)
			write(t, root, ".rmtree-1/f", 0o644)
		}
	})
	mustClear(t, root, keep)
}

func TestEmpty_KeepsTheRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	write(t, root, "a/f", 0o644)
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	var before, after syscall.Stat_t
	if err := syscall.Lstat(root, &before); err != nil {
		t.Fatal(err)
	}
	mustClear(t, root, true)
	if err := syscall.Lstat(root, &after); err != nil {
		t.Fatal(err)
	}
	if after.Ino != before.Ino || after.Mode != before.Mode || after.Uid != before.Uid || after.Gid != before.Gid {
		t.Fatalf("root changed: inode %d→%d, mode %o→%o", before.Ino, after.Ino, before.Mode, after.Mode)
	}

	// A root its owner could not use is left at 0700.
	write(t, root, "f", 0o644)
	if err := os.Chmod(root, 0); err != nil {
		t.Fatal(err)
	}
	mustClear(t, root, true)
	if fi, _ := os.Lstat(root); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode-000 root left at %o; want 0700", fi.Mode().Perm())
	}

	if err := Empty(filepath.Join(base, "absent")); err == nil {
		t.Error("Empty of an absent root succeeded")
	}
	file := write(t, base, "file", 0o644)
	link := filepath.Join(base, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{file, link, "rel", base + "/root/"} {
		if err := Empty(p); err == nil {
			t.Errorf("Empty(%q) succeeded", p)
		}
	}
	mustExist(t, file)
	mustExist(t, link)
}

// TestRemove_PlantedTemporaryNames plants entries named like the walk's moved
// directories before it starts: they are removed like any other entry, and
// what a symbolic link among them points to is left alone.
func TestRemove_PlantedTemporaryNames(t *testing.T) { bothForms(t, testPlantedTemporaryNames) }

func testPlantedTemporaryNames(t *testing.T, keep bool) {
	base := t.TempDir()
	outside := write(t, base, "outside/keep", 0o644)
	root := filepath.Join(base, "root")
	write(t, root, strings.Repeat("d/", 3*hoistDepth)+"f", 0o644)
	write(t, root, ".rmtree-0/"+strings.Repeat("d/", 2*hoistDepth)+"f", 0o644)
	write(t, root, ".rmtree-1", 0o644)
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, ".rmtree-2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".rmtree-3"), 0); err != nil {
		t.Fatal(err)
	}
	mustClear(t, root, keep)
	mustExist(t, outside)
}

// TestRemove_EntrySwappedBeforeOpen replaces a directory, after it was found
// to be one and before it is opened, by a FIFO or by a symbolic link to a
// directory outside the tree. The removal must neither block nor descend.
func TestRemove_EntrySwappedBeforeOpen(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			outside := write(t, base, "outside/keep", 0o644)
			root := filepath.Join(base, "root")
			write(t, root, "a/f", 0o644)
			a := filepath.Join(root, "a")
			calls := 0
			beforeOpen = func() {
				if calls++; calls != 2 { // the first open is the root's
					return
				}
				if err := os.Rename(a, filepath.Join(base, "moved")); err != nil {
					t.Error(err)
				}
				var err error
				switch kind {
				case "fifo":
					err = syscall.Mkfifo(a, 0o600)
				case "symlink":
					err = os.Symlink(filepath.Dir(outside), a)
				default: // another directory under the same name
					if err = os.Mkdir(a, 0o755); err == nil {
						err = os.WriteFile(filepath.Join(a, "keep"), nil, 0o644)
					}
				}
				if err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(func() { beforeOpen = nil })
			done := make(chan error, 1)
			go func() { done <- Remove(root) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("Remove succeeded through a swapped entry")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Remove blocked on a swapped entry")
			}
			if calls < 2 {
				t.Fatal("the swap did not happen")
			}
			mustExist(t, outside)
			if kind == "directory" {
				mustExist(t, filepath.Join(a, "keep"))
			}
		})
	}
}

// TestRemove_PathBelowRootStaysShort removes a chain of 255-byte names three
// times deeper than the walk enters and checks, after every directory read,
// that no descriptor it holds is more than hoistDepth names below the root.
func TestRemove_PathBelowRootStaysShort(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("n", 255)
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 * hoistDepth {
		if err := syscall.Mkdirat(fd, long, 0o700); err != nil {
			t.Fatal(err)
		}
		next, err := syscall.Openat(fd, long, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		syscall.Close(fd)
		fd = next
	}
	syscall.Close(fd)

	longest := 0
	withHook(t, func() {
		es, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			l, err := os.Readlink("/proc/self/fd/" + e.Name())
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("descriptor %s: %v", e.Name(), err) // too long for a path
				continue
			}
			if strings.HasPrefix(l, root) {
				longest = max(longest, len(l)-len(root))
			}
		}
	})
	mustRemove(t, root)
	if longest > hoistDepth*(255+1) {
		t.Fatalf("a descriptor was %d bytes below the root; want at most %d", longest, hoistDepth*(255+1))
	}
}

// TestRemove_SwappedBeforeChmod replaces a directory without access, after it
// was found to be one, by a symbolic link to a directory outside the tree:
// regaining access must not change the link's target.
func TestRemove_SwappedBeforeChmod(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	write(t, outside, "keep", 0o644)
	if err := os.Chmod(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "root")
	a := filepath.Join(root, "a")
	write(t, root, "f", 0o644)
	if err := os.Mkdir(a, 0); err != nil {
		t.Fatal(err)
	}
	calls := 0
	beforeOpen = func() {
		if calls++; calls == 2 { // the first is the root's
			if err := syscall.Rmdir(a); err != nil {
				t.Error(err)
			}
			if err := os.Symlink(outside, a); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() { beforeOpen = nil })
	if err := Remove(root); err == nil {
		t.Fatal("Remove succeeded through a swapped entry")
	}
	if fi, err := os.Stat(outside); err != nil || fi.Mode().Perm() != 0o750 {
		t.Fatalf("outside directory changed: %v %v", fi.Mode(), err)
	}
	mustExist(t, filepath.Join(outside, "keep"))
}

// TestEmpty_EntryAddedAfterTheListing adds an entry to the root once its
// listing has ended: Empty reads the root again and returns only when a whole
// read finds it empty.
func TestEmpty_EntryAddedAfterTheListing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	write(t, root, "f", 0o644)
	calls := 0
	withHook(t, func() {
		if calls++; calls == 2 { // the root's first read listed f; this one is its end
			write(t, root, "late", 0o644)
		}
	})
	mustClear(t, root, true)
}
