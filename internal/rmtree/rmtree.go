//go:build linux

// Package rmtree removes, or empties, a directory tree whose owner may have
// shaped it to make removal fail or misbehave: nested deeper than any path can
// name, entries with mode 000, millions of entries in one directory, symbolic
// links pointing anywhere, FIFOs, sockets, device nodes, hard links to files
// elsewhere, names with any bytes.
//
// Below the root's parent it makes only descriptor-relative calls and never
// builds a path of more than one name. It never follows a symbolic link and
// never descends onto another file system.
//
// A confining security module can refuse an operation whose full path is too
// long even when it is made relative to a descriptor (Docker's default
// AppArmor profile does at about 8 KiB), and an owner can still build a tree
// deeper than that by renaming directories with short paths. So the walk
// never goes more than hoistDepth levels below the root: a directory found
// there is first moved up into the root under a fresh name and removed from
// there later. With depth bounded, the walk keeps a stack of the directories
// it is in: their descriptors, names and read positions. It never opens "..",
// so it acts only in directories it opened from the root downwards, whatever
// else happens to the tree meanwhile.
//
// Resources, whatever the tree's shape: at most hoistDepth+2 descriptors (the
// root's parent and the stack) plus one held briefly to regain access to a
// directory, and (hoistDepth+1) × batchSize bytes of directory buffers.
//
// Known limits: each move into the root needs a new entry there, which may
// need a free block. With the owner's block quota or the file system full, a
// tree deeper than hoistDepth may then fail to be removed on every attempt;
// callers lift the owner's quota limits first. Moves need a file system with
// RENAME_NOREPLACE. Regaining access to a directory uses /proc/self/fd.
// Entries the caller does not own make the removal fail.
package rmtree

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	// atRemoveDir is AT_REMOVEDIR from include/uapi/linux/fcntl.h.
	atRemoveDir = 0x200
	// atFdcwd is AT_FDCWD from include/uapi/linux/fcntl.h.
	atFdcwd = -100
	// atSymlinkNofollow is AT_SYMLINK_NOFOLLOW from include/uapi/linux/fcntl.h.
	atSymlinkNofollow = 0x100
	// oPath is O_PATH from include/uapi/asm-generic/fcntl.h (amd64, arm64).
	oPath = 0x200000
	// batchSize is the buffer of one directory read at one level: some 28 to
	// 250 entries depending on name length.
	batchSize = 8 << 10
	// maxQuoted caps how much of a name an error carries.
	maxQuoted = 64
	// hoistDepth is the deepest level the walk enters. Each level adds at most
	// a 255-byte name and a slash, and the walk acts by name on the entries of
	// the deepest level, so no path below the root it uses is longer than
	// hoistDepth×256 + 255 = 2303 bytes. Docker's default AppArmor profile
	// refuses full paths over 8 KiB, and the root's own path is below 4 KiB.
	hoistDepth = 2048 / (255 + 1)
	// renameNoReplace is RENAME_NOREPLACE from include/uapi/linux/fs.h.
	renameNoReplace = 1
	dirFlags        = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
)

// geteuid is the effective uid lookup; tests replace it.
var geteuid = os.Geteuid

// afterRead, when set, runs after every getdents call; only tests set it.
var afterRead func()

// beforeOpen, when set, runs after an entry was found to be a directory and
// before access to it is regained and it is opened; only tests set it.
var beforeOpen func()

type ident struct{ dev, ino uint64 }

func identOf(st *syscall.Stat_t) ident { return ident{uint64(st.Dev), st.Ino} }

// level is one directory on the walk's stack: its descriptor, its name in the
// directory below it on the stack, and its unread entries buf[off:n].
type level struct {
	fd, off, n int
	name       string
	buf        []byte
}

// Remove removes the directory root and everything below it. root must be an
// absolute, clean path; a root that does not exist is nil; a root that is not
// a directory (a symbolic link to one included) or is a mount point is
// refused. It refuses to run as uid 0. Errors name the operation, a quoted and
// shortened entry name and the errno.
func Remove(root string) error { return walk(root, false) }

// Empty removes everything below the directory root and keeps root itself,
// with its owner, attributes and mode; a mode that denied its owner access is
// left at 0700. A root that does not exist is an error. Otherwise it follows
// the rules of Remove.
func Empty(root string) error { return walk(root, true) }

// walk empties root and, unless keep, removes it.
func walk(root string, keep bool) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return fmt.Errorf("rmtree: root %s is not an absolute, clean path below /", quote(root))
	}
	if geteuid() == 0 {
		return errors.New("rmtree: refusing to run as uid 0")
	}
	name := filepath.Base(root)
	pfd, err := openDir(atFdcwd, filepath.Dir(root))
	if err != nil {
		return fail("open the parent of", root, 0, err)
	}
	defer syscall.Close(pfd)
	var st, pst syscall.Stat_t
	if err := retry(func() error { return syscall.Fstat(pfd, &pst) }); err != nil {
		return fail("stat the parent of", root, 0, err)
	}
	if err := lstatAt(pfd, name, &st); errors.Is(err, syscall.ENOENT) && !keep {
		return nil
	} else if err != nil {
		return fail("stat", root, 0, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("rmtree: root %s is not a directory", quote(root))
	}
	if st.Dev != pst.Dev {
		return fmt.Errorf("rmtree: root %s is on another file system than its parent", quote(root))
	}
	dev := uint64(st.Dev)
	rfd, err := enter(pfd, name, &st)
	if err != nil {
		return fail("open", root, 0, err)
	}

	bufs := make([]byte, (hoistDepth+1)*batchSize)
	stack := make([]level, 1, hoistDepth+1)
	stack[0] = level{fd: rfd, name: name, buf: bufs[:batchSize]}
	defer func() {
		for _, l := range stack {
			syscall.Close(l.fd)
		}
	}()
	moved := 0        // the next .rmtree-N to try
	rootSeen := false // the root's current pass listed an entry
	var names []string
	for {
		top := &stack[len(stack)-1]
		depth := len(stack) - 1
		if top.off >= top.n {
			var n int
			err := retry(func() (e error) { n, e = syscall.Getdents(top.fd, top.buf); return })
			if afterRead != nil {
				afterRead()
			}
			if err != nil {
				return fail("read directory", top.name, depth, err)
			}
			top.off, top.n = 0, n
			if n > 0 {
				continue
			}
			if depth == 0 {
				// Moves add entries to the root while it is being read, and
				// a read may or may not return them: read it again from the
				// start until a whole pass lists nothing.
				if !rootSeen {
					break
				}
				if _, err := syscall.Seek(top.fd, 0, 0); err != nil {
					return fail("rewind", root, 0, err)
				}
				rootSeen = false
				continue
			}
			// The directory is empty: leave it and remove it.
			syscall.Close(top.fd)
			gone := top.name
			stack = stack[:depth]
			if err := unlinkAt(stack[depth-1].fd, gone, atRemoveDir); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fail("remove directory", gone, depth-1, err)
			}
			continue
		}
		c, _, parsed := syscall.ParseDirent(top.buf[top.off:top.n], 1, names[:0])
		top.off += c
		if names = parsed; len(names) == 0 {
			continue // ".", "..", or a deleted slot
		}
		nm := names[0]
		if depth == 0 {
			rootSeen = true
		}
		err := lstatAt(top.fd, nm, &st)
		if errors.Is(err, syscall.ENOENT) {
			continue
		}
		if err != nil {
			return fail("stat", nm, depth, err)
		}
		if uint64(st.Dev) != dev {
			return fmt.Errorf("rmtree: entry %s at depth %d is on another file system", quote(nm), depth)
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			if err := unlinkAt(top.fd, nm, 0); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fail("unlink", nm, depth, err)
			}
			continue
		}
		if depth == hoistDepth {
			if err := hoist(top.fd, nm, rfd, &st, &moved); err != nil {
				return fail("move up", nm, depth, err)
			}
			continue
		}
		child, err := enter(top.fd, nm, &st)
		if err != nil {
			return fail("open", nm, depth, err)
		}
		stack = append(stack, level{fd: child, name: nm, buf: bufs[(depth+1)*batchSize : (depth+2)*batchSize]})
	}
	if keep {
		return nil
	}
	syscall.Close(rfd)
	stack = stack[:0]
	if err := unlinkAt(pfd, name, atRemoveDir); err != nil {
		return fail("remove directory", root, 0, err)
	}
	return nil
}

// hoist moves the directory name of dirfd, whose lstat is st, into the root
// rootfd as .rmtree-N, the first such name not taken from *n on. The move
// never replaces an entry (RENAME_NOREPLACE); an entry of that name, planted
// or left by an earlier move, is skipped here and removed like any other.
func hoist(dirfd int, name string, rootfd int, st *syscall.Stat_t, n *int) error {
	if st.Mode&0o700 != 0o700 { // moving a directory rewrites its ".." entry
		if err := chmodDir(dirfd, name, st); err != nil {
			return err
		}
	}
	for ; ; *n++ {
		err := renameAt2(dirfd, name, rootfd, ".rmtree-"+strconv.Itoa(*n), renameNoReplace)
		switch {
		case err == nil:
			*n++
			return nil
		case errors.Is(err, syscall.EINVAL):
			return fmt.Errorf("the file system does not support RENAME_NOREPLACE: %w", err)
		case !errors.Is(err, syscall.EEXIST):
			return err
		}
	}
}

// chmodDir gives the directory name of dirfd, whose lstat is st, mode 0700
// without following a link: it opens name with O_PATH|O_NOFOLLOW, checks that
// it is the same directory, and changes the mode of exactly that inode
// through its /proc/self/fd entry.
func chmodDir(dirfd int, name string, st *syscall.Stat_t) error {
	var fd int
	err := retry(func() (e error) {
		fd, e = syscall.Openat(dirfd, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		return
	})
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var got syscall.Stat_t
	if err := retry(func() error { return syscall.Fstat(fd, &got) }); err != nil {
		return err
	}
	if got.Mode&syscall.S_IFMT != syscall.S_IFDIR || identOf(&got) != identOf(st) {
		return errors.New("replaced while being removed")
	}
	return retry(func() error { return syscall.Chmod("/proc/self/fd/"+strconv.Itoa(fd), 0o700) })
}

// enter opens the directory name of dirfd, whose lstat is st, first giving
// its owner the access removal needs, and checks that it opened that inode.
func enter(dirfd int, name string, st *syscall.Stat_t) (int, error) {
	if beforeOpen != nil {
		beforeOpen()
	}
	if st.Mode&0o500 != 0o500 {
		if err := chmodDir(dirfd, name, st); err != nil {
			return -1, err
		}
	}
	fd, err := openDir(dirfd, name)
	if err != nil {
		return -1, err
	}
	var got syscall.Stat_t
	err = retry(func() error { return syscall.Fstat(fd, &got) })
	if err == nil && identOf(&got) != identOf(st) {
		err = errors.New("replaced while being removed")
	}
	if err == nil && got.Mode&0o700 != 0o700 {
		err = retry(func() error { return syscall.Fchmod(fd, 0o700) })
	}
	if err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openDir(dirfd int, name string) (fd int, err error) {
	err = retry(func() (e error) { fd, e = syscall.Openat(dirfd, name, dirFlags, 0); return })
	return fd, err
}

// lstatAt is fstatat(dirfd, name, st, AT_SYMLINK_NOFOLLOW).
func lstatAt(dirfd int, name string, st *syscall.Stat_t) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	return retry(func() error {
		_, _, e := syscall.Syscall6(sysFstatat, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(st)), atSymlinkNofollow, 0, 0)
		return errnoErr(e)
	})
}

// renameAt2 is renameat2(2), which the syscall package does not export.
func renameAt2(olddirfd int, oldname string, newdirfd int, newname string, flags int) error {
	old, err := syscall.BytePtrFromString(oldname)
	if err != nil {
		return err
	}
	nw, err := syscall.BytePtrFromString(newname)
	if err != nil {
		return err
	}
	return retry(func() error {
		_, _, e := syscall.Syscall6(sysRenameat2, uintptr(olddirfd), uintptr(unsafe.Pointer(old)), uintptr(newdirfd), uintptr(unsafe.Pointer(nw)), uintptr(flags), 0)
		return errnoErr(e)
	})
}

// unlinkAt is unlinkat(2); the syscall package has no flags argument.
func unlinkAt(dirfd int, name string, flags int) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	return retry(func() error {
		_, _, e := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(flags))
		return errnoErr(e)
	})
}

func errnoErr(e syscall.Errno) error {
	if e == 0 {
		return nil
	}
	return e
}

func retry(f func() error) error {
	for {
		if err := f(); err != syscall.EINTR {
			return err
		}
	}
}

func fail(op, name string, depth int, err error) error {
	if name == "" {
		return fmt.Errorf("rmtree: %s at depth %d: %w", op, depth, err)
	}
	return fmt.Errorf("rmtree: %s %s at depth %d: %w", op, quote(name), depth, err)
}

// quote renders a hostile name for a log: at most maxQuoted bytes of it,
// Go-quoted with every byte outside printable ASCII escaped.
func quote(name string) string {
	if len(name) > maxQuoted {
		return strconv.QuoteToASCII(name[:maxQuoted]) + "..."
	}
	return strconv.QuoteToASCII(name)
}
