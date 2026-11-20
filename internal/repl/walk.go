package repl

import (
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/walname"
)

// maxDepth bounds the directory levels below the repository root.
const maxDepth = 12

// oPath is O_PATH (the same value on amd64 and arm64), which the syscall
// package does not export: a descriptor to examine an entry, never to read it.
const oPath = 0x200000

const (
	dirFlags  = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	pathFlags = oPath | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	readFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
)

// openForRead opens a file for reading: never through a link, never
// blocking on a FIFO. A seam: tests record what is opened.
var openForRead = func(dirfd int, name string) (int, error) {
	return syscall.Openat(dirfd, name, readFlags, 0)
}

// file is one walked file that may be copied: regular, owned by the
// project's uid, its path admitted for the stanza and its timeline.
type file struct {
	rel     string
	kind    walname.Kind
	tli     uint32
	label   string
	ino     uint64
	size    int64
	ctimeNS int64
	mtimeNS int64
}

type walk struct {
	root      int
	uid       int
	stanza    string
	timelines []uint32
	max       int

	files      []file
	walked     int
	truncated  bool
	unlisted   int64
	unreadable int64
	firstBad   string
}

// run walks the tree below the root descriptor: one openat per level without
// following, newest name first, at most w.max entries and maxDepth levels.
// Nothing is read: an entry is examined with fstat on an O_PATH descriptor.
func (w *walk) run() {
	w.dir(w.root, "", 0)
}

func (w *walk) dir(fd int, rel string, depth int) {
	names, ok := w.names(fd)
	if !ok {
		w.unreadable++
		return
	}
	// A set directory goes up only once its manifest exists.
	if k, _, _, isSet := walname.RepoPath(w.stanza, join(rel, "backup.manifest")); isSet && k == walname.SetManifest &&
		!slices.Contains(names, "backup.manifest") {
		return
	}
	for _, n := range names {
		if w.walked >= w.max {
			w.truncated = true
			return
		}
		w.walked++
		w.entry(fd, n, join(rel, n), depth)
	}
}

// readdir reads names of a directory: a seam, tests fail it mid-way.
var readdir = func(f *os.File, n int) ([]string, error) { return f.Readdirnames(n) }

// names lists a directory, newest (highest) name first, keeping at most what
// the entry cap leaves: a directory of millions of names costs time, not memory.
func (w *walk) names(fd int) ([]string, bool) {
	dup, err := syscall.Dup(fd)
	if err != nil {
		return nil, false
	}
	f := os.NewFile(uintptr(dup), "dir")
	defer f.Close()
	keep := w.max - w.walked
	var names []string
	for {
		batch, err := readdir(f, 1024)
		if err != nil && !errors.Is(err, io.EOF) { // a read error is never a short listing
			return nil, false
		}
		names = append(names, batch...)
		if len(names) > 2*keep+1024 {
			names = w.top(names, keep)
		}
		if err != nil || len(batch) == 0 {
			break
		}
	}
	return w.top(names, keep), true
}

func (w *walk) top(names []string, keep int) []string {
	slices.Sort(names)
	slices.Reverse(names)
	if len(names) > keep {
		w.truncated = true
		names = names[:keep]
	}
	return slices.Clip(names)
}

func (w *walk) entry(dirfd int, name, rel string, depth int) {
	// The temporaries pgBackRest renames into place, and the link to the
	// newest set it keeps, are its own: neither counted nor copied.
	if strings.HasSuffix(name, ".pgbackrest.tmp") {
		return
	}
	pfd, err := syscall.Openat(dirfd, name, pathFlags, 0)
	if err != nil {
		if err != syscall.ENOENT { // gone since the listing: nothing to copy
			w.bad(rel, &w.unreadable)
		}
		return
	}
	var st syscall.Stat_t
	err = syscall.Fstat(pfd, &st)
	syscall.Close(pfd)
	if err != nil {
		w.bad(rel, &w.unreadable)
		return
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFDIR:
		if depth+1 > maxDepth {
			w.bad(rel, &w.unlisted)
			return
		}
		fd, err := syscall.Openat(dirfd, name, dirFlags, 0)
		if err != nil { // swapped for a link or removed since: never entered
			w.bad(rel, &w.unreadable)
			return
		}
		w.dir(fd, rel, depth+1)
		syscall.Close(fd)
		return
	case syscall.S_IFREG:
	case syscall.S_IFLNK:
		if rel == "backup/"+w.stanza+"/latest" {
			return
		}
		w.bad(rel, &w.unlisted)
		return
	default:
		w.bad(rel, &w.unlisted)
		return
	}
	k, tli, label, ok := walname.RepoPath(w.stanza, rel)
	if !ok || int(st.Uid) != w.uid || (tli != 0 && !walname.Admitted(tli, w.timelines)) {
		w.bad(rel, &w.unlisted)
		return
	}
	if k == walname.Info { // read before the walk, by name
		return
	}
	w.files = append(w.files, file{rel: rel, kind: k, tli: tli, label: label, ino: st.Ino, size: st.Size,
		ctimeNS: st.Ctim.Nano(), mtimeNS: st.Mtim.Nano()})
}

func (w *walk) bad(rel string, n *int64) {
	*n++
	if w.firstBad == "" {
		w.firstBad = rel
	}
}

func join(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// sizeMax is the bound of a kind's object: nothing larger is read.
func sizeMax(k walname.Kind) int64 {
	switch k {
	case walname.Segment:
		return bklimit.SegmentMax
	case walname.Info, walname.History, walname.Label:
		return bklimit.SmallMax
	}
	return bklimit.SetFileMax
}

// openRel opens rel below root for reading, one directory level at a time,
// never following a link and never blocking.
func openRel(root int, rel string) (int, error) {
	parts := strings.Split(rel, "/")
	fd := root
	for i, p := range parts {
		var next int
		var err error
		if i == len(parts)-1 {
			next, err = openForRead(fd, p)
		} else {
			next, err = syscall.Openat(fd, p, dirFlags, 0)
		}
		if fd != root {
			syscall.Close(fd)
		}
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}
