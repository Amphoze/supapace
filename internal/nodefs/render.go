// Package nodefs owns what root does on a node's filesystems: the per-project
// directory on the quota mount, its quota limits, the check that the reserved
// uid/gid range is free on the host, and the rendering of root-owned
// platform files.
//
// Every operation is descriptor-based. A directory is opened with
// O_DIRECTORY|O_NOFOLLOW from a parent descriptor, checked with fstat, and
// acted on through the descriptor (fchown, fchmod, ioctl, mkdirat, unlinkat,
// renameat). Below a project directory root acts only while creating it,
// before any tenant process exists; afterwards it opens nothing there.
package nodefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// tmpSuffix is ".tmp-" and 16 hex digits; with the leading dot the temporary
// name must still fit the 255-byte file-name limit.
const (
	tmpSuffixLen = len(".tmp-") + 16
	maxNameLen   = 255 - 1 - tmpSuffixLen
)

var ErrOutsideRenderRoot = errors.New("nodefs: directory outside the render roots")

// renderRoots are the trees root renders platform files into: the platform
// tree (which holds the gateway directory) and the node configuration
// directory. None of them is ever writable by a tenant.
func renderRoots(p nodecfg.Paths) []string {
	return []string{p.PlatformDir(), filepath.Dir(p.NodeJSON())}
}

// WriteFile atomically replaces dir/name with data, owned by uid:gid with the
// permission bits of mode. dir must lie under a render root, and every
// directory from that root down to dir must be a real directory owned by
// the caller and writable by no one else. The file is created under a
// temporary name with O_CREAT|O_EXCL|O_NOFOLLOW, written, chmodded, chowned
// and synced through its descriptor, then renamed over name. An existing
// entry at name that is not a regular file (a link, a FIFO, a directory) is
// an error and is left alone.
//
// WriteFile creates no directories: dir must exist. It always replaces the
// file at name, so a file that must never be overwritten is the caller's to
// check first. A crash can leave a ".<name>.tmp-*" file behind in dir.
func WriteFile(p nodecfg.Paths, dir, name string, data []byte, mode os.FileMode, uid, gid int) error {
	root, rel, ok := underRenderRoot(p, dir)
	if !ok {
		return fmt.Errorf("%w: %s", ErrOutsideRenderRoot, dir)
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("nodefs: invalid file name %q", name)
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("nodefs: file name is longer than %d bytes", maxNameLen)
	}
	if uid < 0 || gid < 0 || uint64(uid) >= 1<<32-1 || uint64(gid) >= 1<<32-1 {
		return fmt.Errorf("nodefs: invalid owner %d:%d", uid, gid)
	}
	dfd, err := openTrustedDir(root, rel)
	if err != nil {
		return err
	}
	defer syscall.Close(dfd)

	if err := refuseNonRegular(dfd, name); err != nil {
		return fmt.Errorf("nodefs: %s/%s: %w", dir, name, err)
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := "." + name + ".tmp-" + hex.EncodeToString(suffix[:])
	fd, err := syscall.Openat(dfd, tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("nodefs: create %s/%s: %w", dir, tmp, err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	renamed := false
	defer func() {
		if !renamed {
			syscall.Unlinkat(dfd, tmp)
		}
	}()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode.Perm())
	}
	if err == nil {
		err = f.Chown(uid, gid)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("nodefs: write %s/%s: %w", dir, name, err)
	}
	if err := syscall.Renameat(dfd, tmp, dfd, name); err != nil {
		return fmt.Errorf("nodefs: rename into %s/%s: %w", dir, name, err)
	}
	renamed = true
	if err := syscall.Fsync(dfd); err != nil {
		return fmt.Errorf("nodefs: sync %s: %w", dir, err)
	}
	return nil
}

// underRenderRoot splits an absolute dir into the render root holding it and
// the path below that root.
func underRenderRoot(p nodecfg.Paths, dir string) (root, rel string, ok bool) {
	if !filepath.IsAbs(dir) {
		return "", "", false
	}
	c := filepath.Clean(dir)
	for _, r := range renderRoots(p) {
		if c == r {
			return r, "", true
		}
		if strings.HasPrefix(c, r+"/") {
			return r, c[len(r)+1:], true
		}
	}
	return "", "", false
}

// openTrustedDir opens root, then each component of rel from the previous
// descriptor, refusing links and any directory not owned by the caller's
// effective uid or writable by its group or others.
func openTrustedDir(root, rel string) (int, error) {
	fd, err := openDirAt(atFdcwd, root)
	if err != nil {
		return -1, fmt.Errorf("nodefs: open %s: %w", root, err)
	}
	path := root
	for {
		if err := checkTrusted(fd, path); err != nil {
			syscall.Close(fd)
			return -1, err
		}
		if rel == "" {
			return fd, nil
		}
		comp, rest, _ := strings.Cut(rel, "/")
		rel = rest
		path += "/" + comp
		next, err := openDirAt(fd, comp)
		syscall.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("nodefs: open %s: %w", path, err)
		}
		fd = next
	}
}

func checkTrusted(fd int, path string) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("nodefs: stat %s: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || int(st.Uid) != os.Geteuid() || st.Mode&0o022 != 0 {
		return fmt.Errorf("nodefs: %s is not a directory owned by uid %d and writable only by it", path, os.Geteuid())
	}
	return nil
}

// openDirAt opens name relative to dirfd as a directory, never following a
// link in its last component. O_DIRECTORY makes a FIFO or device node fail
// with ENOTDIR before it is opened.
func openDirAt(dirfd int, name string) (int, error) {
	return syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
}

// refuseNonRegular returns an error when dirfd/name exists and is not a
// regular file. O_PATH|O_NOFOLLOW opens the entry itself (a link stays a
// link) without opening what it names, so a FIFO cannot block.
func refuseNonRegular(dirfd int, name string) error {
	fd, err := syscall.Openat(dirfd, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return errors.New("existing entry is not a regular file")
	}
	return nil
}
