package nodefs

import (
	"errors"
	"fmt"
	"regexp"
	"syscall"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

var ErrExistsForeign = errors.New("nodefs: project directory exists with a foreign owner")

var refRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

// afterInnerChown, when set, runs after data/ and sock/ are chowned and before
// the outer directory is; a non-nil error stops CreateProjectDir there. Only
// this package's tests set it.
var afterInnerChown func() error

// CreateProjectDir creates <projects>/<ref> (0700) with data/ and sock/ (0700),
// sets the project id uid with inheritance on all three, sets the user and
// project block limits to quotaMB, and chowns data/, sock/ and then the outer
// directory to uid:gid — the outer one last.
//
// The outer directory's owner is the idempotency test. Owned by uid:gid: the
// directory is complete and nothing below it is touched (a tenant may have
// changed anything there). Owned by root: an earlier call was interrupted
// before the outer chown, so before any tenant process could exist, and the
// steps run again. Any other owner is ErrExistsForeign.
func CreateProjectDir(p nodecfg.Paths, ref string, uid, gid, quotaMB int) error {
	if !refRE.MatchString(ref) {
		return fmt.Errorf("nodefs: invalid ref %q", ref)
	}
	if !projectID(uid) || !projectID(gid) {
		return fmt.Errorf("nodefs: invalid project uid/gid %d:%d", uid, gid)
	}
	if quotaMB <= 0 {
		return fmt.Errorf("nodefs: invalid disk quota %d MiB", quotaMB)
	}
	pfd, err := openTrustedDir(p.ProjectsDir(), "")
	if err != nil {
		return err
	}
	defer syscall.Close(pfd)

	err = syscall.Mkdirat(pfd, ref, 0o700)
	existed := errors.Is(err, syscall.EEXIST)
	if err != nil && !existed {
		return fmt.Errorf("nodefs: mkdir %s: %w", ref, err)
	}
	rfd, err := openDirAt(pfd, ref)
	if err != nil {
		return fmt.Errorf("nodefs: open %s: %w", ref, err)
	}
	defer syscall.Close(rfd)
	var st syscall.Stat_t
	if err := syscall.Fstat(rfd, &st); err != nil {
		return err
	}
	switch {
	case int(st.Uid) == uid && int(st.Gid) == gid:
		return nil
	case st.Uid != 0:
		return fmt.Errorf("%w: %s owned by %d:%d", ErrExistsForeign, ref, st.Uid, st.Gid)
	}
	// An interrupted call leaves the outer directory exactly as mkdirat made
	// it; any other mode means someone else set it.
	if existed && st.Mode&0o7777 != 0o700 {
		return fmt.Errorf("nodefs: root-owned %s has mode %#o, not 0700", ref, st.Mode&0o7777)
	}

	// Root-owned: no tenant process has existed, so the children are ours
	// (or a pair-owned leftover of the interrupted call).
	var inner []int
	defer func() {
		for _, fd := range inner {
			syscall.Close(fd)
		}
	}()
	for _, name := range []string{"data", "sock"} {
		if err := syscall.Mkdirat(rfd, name, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("nodefs: mkdir %s/%s: %w", ref, name, err)
		}
		fd, err := openDirAt(rfd, name)
		if err != nil {
			return fmt.Errorf("nodefs: open %s/%s: %w", ref, name, err)
		}
		inner = append(inner, fd)
		if err := syscall.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Uid != 0 && (int(st.Uid) != uid || int(st.Gid) != gid) {
			return fmt.Errorf("%w: %s/%s owned by %d:%d", ErrExistsForeign, ref, name, st.Uid, st.Gid)
		}
	}
	// data/ and sock/ exist before the outer directory carries the project
	// id, so each is given it directly; entries created later inherit it.
	for _, fd := range append([]int{rfd}, inner...) {
		if err := setProjectID(fd, uint32(uid)); err != nil {
			return fmt.Errorf("nodefs: project id on %s: %w", ref, err)
		}
	}
	if err := SetQuota(p, uid, quotaMB); err != nil {
		return err
	}
	for _, fd := range inner {
		if err := syscall.Fchmod(fd, 0o700); err != nil {
			return err
		}
		if err := syscall.Fchown(fd, uid, gid); err != nil {
			return err
		}
	}
	if afterInnerChown != nil {
		if err := afterInnerChown(); err != nil {
			return err
		}
	}
	if err := syscall.Fchmod(rfd, 0o700); err != nil {
		return err
	}
	if err := syscall.Fchown(rfd, uid, gid); err != nil {
		return err
	}
	return nil
}

// setProjectID sets the XFS project id and the inherit flag on fd.
func setProjectID(fd int, id uint32) error {
	var x fsxattr
	if err := ioctlFsxattr(fd, fsIocFsGetXattr, &x); err != nil {
		return err
	}
	x.Projid = id
	x.Xflags |= fsXflagProjInherit
	return ioctlFsxattr(fd, fsIocFsSetXattr, &x)
}

// RemoveEmptyProjectDir removes <projects>/<ref> with a single
// unlinkat(projectsFd, ref, AT_REMOVEDIR): non-recursive, never following a
// link, failing on a non-empty directory. An absent ref is nil.
func RemoveEmptyProjectDir(p nodecfg.Paths, ref string) error {
	if !refRE.MatchString(ref) {
		return fmt.Errorf("nodefs: invalid ref %q", ref)
	}
	pfd, err := openTrustedDir(p.ProjectsDir(), "")
	if err != nil {
		return err
	}
	defer syscall.Close(pfd)
	if err := unlinkatDir(pfd, ref); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("nodefs: remove %s: %w", ref, err)
	}
	return nil
}
