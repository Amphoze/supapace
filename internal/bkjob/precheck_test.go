package bkjob

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// dataTree is a small data directory: a few files and directories of the
// shapes a cluster has.
func dataTree(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "data")
	for _, p := range []string{"base/5", "global", "pg_wal/archive_status", "pg_tblspc"} {
		if err := os.MkdirAll(filepath.Join(d, p), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"PG_VERSION", "base/5/1259", "global/pg_control", "pg_wal/000000010000000000000001"} {
		if err := os.WriteFile(filepath.Join(d, p), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func precheckCode(t *testing.T, root string) string {
	t.Helper()
	err := precheck(root)
	if err == nil {
		return ""
	}
	return failCode(err)
}

// Any link in the data directory refuses the job before the tool runs: to a
// file, to a directory, dangling, and deep in the tree.
func TestPrecheck_SymlinkAnywhereRefused(t *testing.T) {
	if got := precheckCode(t, dataTree(t)); got != "" {
		t.Fatalf("control: a tree without links: %s", got)
	}
	deep := "base/a/b/c/d/e"
	for name, link := range map[string][2]string{
		"file":      {"base/5/16384", "/etc/passwd"},
		"directory": {"global/sub", "/repo"},
		"dangling":  {"pg_wal/x", "/nowhere/at/all"},
		"depth 6":   {deep + "/f", "/proc/self/environ"},
	} {
		t.Run(name, func(t *testing.T) {
			d := dataTree(t)
			if err := os.MkdirAll(filepath.Join(d, deep), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(link[1], filepath.Join(d, link[0])); err != nil {
				t.Fatal(err)
			}
			err := precheck(d)
			if failCode(err) != CodeSymlink || !strings.Contains(err.Error(), link[0]) {
				t.Fatalf("precheck = %v, want code %s naming %s", err, CodeSymlink, link[0])
			}
		})
	}
	// The data directory itself a link: refused, not followed.
	d := dataTree(t)
	l := filepath.Join(t.TempDir(), "data")
	os.Symlink(d, l)
	if got := precheckCode(t, l); got != CodeSymlink {
		t.Fatalf("the data directory a link: %q", got)
	}
}

// Any entry in pg_tblspc — a link, a directory, a file — is a tablespace.
func TestPrecheck_AnyTablespaceEntryRefused(t *testing.T) {
	for name, mk := range map[string]func(p string) error{
		"link":      func(p string) error { return os.Symlink("/var/run/postgresql/ts", p) },
		"directory": func(p string) error { return os.Mkdir(p, 0o700) },
		"file":      func(p string) error { return os.WriteFile(p, nil, 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			d := dataTree(t)
			if err := mk(filepath.Join(d, "pg_tblspc", "16667")); err != nil {
				t.Fatal(err)
			}
			if got := precheckCode(t, d); got != CodeTablespace {
				t.Fatalf("code %q, want %s", got, CodeTablespace)
			}
		})
	}
	// pg_tblspc itself a link: refused too.
	d := dataTree(t)
	os.Remove(filepath.Join(d, "pg_tblspc"))
	os.Symlink(t.TempDir(), filepath.Join(d, "pg_tblspc"))
	if got := precheckCode(t, d); got != CodeSymlink {
		t.Fatalf("pg_tblspc a link: %q", got)
	}
}

// The walk opens no entry but directories, each without following a link: a
// FIFO (whose open would block) and a socket are passed over, and a directory
// replaced by a link between the listing and its open is refused — nothing
// is read through it.
func TestPrecheck_WalksWithoutFollowing(t *testing.T) {
	d := dataTree(t)
	if err := syscall.Mkfifo(filepath.Join(d, "base/5/fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(d, "global", "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("no unix socket here: %v", err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() { done <- precheck(d) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a FIFO and a socket: %v", err)
		}
	case <-time.After(60 * time.Second): // an open of the FIFO never returns
		t.Fatal("the walk opened the FIFO")
	}

	// A directory swapped for a link to a tree holding a link: the walk must
	// refuse at the swap, not report the link behind it.
	outside := t.TempDir()
	os.Symlink("/etc/passwd", filepath.Join(outside, "behind-the-swap"))
	old := beforeOpen
	t.Cleanup(func() { beforeOpen = old })
	beforeOpen = func(rel string) {
		if rel == "base" {
			os.Rename(filepath.Join(d, "base"), filepath.Join(d, "base.old"))
			os.Symlink(outside, filepath.Join(d, "base"))
		}
	}
	err = precheck(d)
	if failCode(err) != CodeSymlink || strings.Contains(err.Error(), "behind-the-swap") || !strings.Contains(err.Error(), "base") {
		t.Fatalf("a directory swapped for a link: %v", err)
	}

	// An entry gone between the listing and its open is no failure.
	d = dataTree(t)
	beforeOpen = func(rel string) {
		if rel == "base" {
			os.RemoveAll(filepath.Join(d, "base"))
		}
	}
	if err := precheck(d); err != nil {
		t.Fatalf("a directory gone under the walk: %v", err)
	}
}

// The walk is bounded in depth and in entries; past a bound the tree is not
// proven free of links and the job is refused.
func TestPrecheck_Bounds(t *testing.T) {
	oldD, oldN := walkDepthMax, walkEntriesMax
	t.Cleanup(func() { walkDepthMax, walkEntriesMax = oldD, oldN })
	walkDepthMax, walkEntriesMax = 4, 100

	d := dataTree(t)
	if err := precheck(d); err != nil {
		t.Fatalf("control: within the bounds: %v", err)
	}
	os.MkdirAll(filepath.Join(d, "base/a/b/c/d"), 0o700)
	if err := precheck(d); failCode(err) != CodeSymlink || !strings.Contains(err.Error(), "deeper") {
		t.Fatalf("past the depth: %v", err)
	}
	d = dataTree(t)
	for i := range 100 {
		os.WriteFile(filepath.Join(d, "base/5", fmt.Sprint("f", i)), nil, 0o600)
	}
	if err := precheck(d); failCode(err) != CodeSymlink || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("past the entry count: %v", err)
	}
}

// A refusal names the entry in bounded, cleaned text: no control byte of a
// tenant-chosen name reaches the message, which stays within 256 bytes.
func TestPrecheck_MessageIsCleanedAndBounded(t *testing.T) {
	d := dataTree(t)
	name := "a\x1b[31m\nb‮" + strings.Repeat("n", 240)
	if err := os.Symlink("/x", filepath.Join(d, "base", name)); err != nil {
		t.Fatal(err)
	}
	err := precheck(d)
	var e *Error
	if failCode(err) != CodeSymlink || !errors.As(err, &e) {
		t.Fatalf("precheck = %v", err)
	}
	if len(e.Message) > 256 || strings.ContainsAny(e.Message, "\x1b\n‮") || !strings.Contains(e.Message, "base/a") {
		t.Fatalf("message %q", e.Message)
	}
}

// A filesystem that gives an entry no type in its listing: the entry is never
// looked up by a path; the tree is refused as not walked whole.
func TestPrecheck_UnknownEntryTypeRefused(t *testing.T) {
	d := dataTree(t)
	if err := precheck(d); err != nil {
		t.Fatalf("control: %v", err)
	}
	old := direntType
	t.Cleanup(func() { direntType = old })
	direntType = func(uint8) uint8 { return syscall.DT_UNKNOWN }
	if err := precheck(d); failCode(err) != CodeSymlink || !strings.Contains(err.Error(), "not walked whole") {
		t.Fatalf("an entry of unknown type: %v", err)
	}
}
