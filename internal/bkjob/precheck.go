package bkjob

import (
	"bytes"
	"syscall"
	"unsafe"
)

// The walk's bounds. A cluster's data directory is a few levels deep; its
// entries are bounded by the inode quota, but a hard link is an entry
// without an inode, so the count has a bound of its own.
var (
	walkDepthMax   = 64
	walkEntriesMax = 1 << 24
)

// beforeOpen, when set, runs before a directory of the walk is opened. Tests only.
var beforeOpen func(rel string)

// precheck walks the data directory at root — the project's to write — and
// refuses any symbolic link in it (code symlink) and any entry of pg_tblspc
// (code tablespace), before the tool reads anything: the tool follows links
// and would store what they name. Only directories are opened, each from its
// parent's descriptor with O_NOFOLLOW, so no link is followed and no FIFO or
// device is opened; other entries (files, FIFOs, sockets, devices, entries
// of another owner) are passed over. An entry gone under the walk is skipped;
// a directory replaced by a link before its open is a link. A tree the walk
// cannot complete — past its bounds, unreadable, or on a filesystem that gives an entry no type — is not proven free of
// links and is refused with code symlink too. What the tree holds after the
// walk is the residual a job without a network keeps.
func precheck(root string) error {
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return refuse(CodeSymlink, "the data directory could not be opened without following a link: %v", err)
	}
	w := walker{}
	return w.dir(fd, "", 0)
}

type walker struct{ entries int }

// direntType is the type the listing gives an entry (d_type). Tests
// substitute it to stand for a filesystem that gives none.
var direntType = func(t uint8) uint8 { return t }

// dir walks the open directory fd (rel to the data directory) and closes it.
// The entries are read with getdents and their types taken from it: an entry
// whose type the filesystem does not give is never looked up by a path.
func (w *walker) dir(fd int, rel string, depth int) error {
	defer syscall.Close(fd)
	buf := make([]byte, 8192)
	nameOff := int(unsafe.Offsetof(syscall.Dirent{}.Name))
	for {
		n, err := syscall.ReadDirent(fd, buf)
		if err != nil {
			return refuse(CodeSymlink, "%s could not be listed: %v: not walked whole", rel, err)
		}
		if n <= 0 {
			return nil
		}
		for off := 0; off < n; {
			de := (*syscall.Dirent)(unsafe.Pointer(&buf[off]))
			end := off + int(de.Reclen)
			if de.Reclen == 0 || end > n {
				return refuse(CodeSymlink, "%s: a listing record out of shape: not walked whole", rel)
			}
			name := buf[off+nameOff : end]
			if i := bytes.IndexByte(name, 0); i >= 0 {
				name = name[:i]
			}
			typ := direntType(de.Type)
			off = end
			if s := string(name); s == "." || s == ".." {
				continue
			}
			if err := w.entry(fd, rel, string(name), typ, depth); err != nil {
				return err
			}
		}
	}
}

// entry decides one entry of the directory fd.
func (w *walker) entry(fd int, rel, name string, typ uint8, depth int) error {
	p := name
	if rel != "" {
		p = rel + "/" + name
	}
	if w.entries++; w.entries > walkEntriesMax {
		return refuse(CodeSymlink, "the data directory holds more than %d entries: not walked whole", walkEntriesMax)
	}
	if rel == "pg_tblspc" {
		return refuse(CodeTablespace, "the data directory holds a tablespace: pg_tblspc/%s", name)
	}
	switch typ { // the entry's own type: never a link's target
	case syscall.DT_UNKNOWN:
		return refuse(CodeSymlink, "the filesystem gives no type for %s: not walked whole", p)
	case syscall.DT_LNK:
		return refuse(CodeSymlink, "the data directory holds a link: %s", p)
	case syscall.DT_DIR:
		if depth+1 > walkDepthMax {
			return refuse(CodeSymlink, "the data directory is deeper than %d levels at %s: not walked whole", walkDepthMax, p)
		}
		if beforeOpen != nil {
			beforeOpen(p)
		}
		cfd, err := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		switch {
		case err == syscall.ENOENT: // gone
			return nil
		case err == syscall.ELOOP, err == syscall.ENOTDIR: // replaced since the listing: by a link, or so it is taken
			return refuse(CodeSymlink, "the data directory holds a link: %s (it changed under the walk)", p)
		case err != nil:
			return refuse(CodeSymlink, "%s could not be opened: %v: not walked whole", p, err)
		}
		return w.dir(cfd, p, depth+1)
	}
	return nil
}
