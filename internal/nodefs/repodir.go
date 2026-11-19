package nodefs

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// The repository filesystem (RepoRoot) holds one directory per backup
// subject — a project ref or the control plane — owned by root 0755, with
// repo/ (the subject's repository, uid:gid 0750) and, only during a restore,
// fetch/ (uid:gid 2750, written by the replicator). Root reaches them only by
// descriptor from a trusted RepoRoot, never follows a link and never opens
// anything inside repo/ or fetch/.

var errNoSubject = errors.New("no such backup subject directory")

func validSubject(s string) bool { return s == nodecfg.ControlPlaneSubject || refRE.MatchString(s) }

// openSubject opens RepoRoot (trusted) and, below it, the subject directory,
// which must be a directory owned by root and writable by no one else.
// create makes it 0755 when absent; otherwise an absent one is
// errNoSubject.
func openSubject(p nodecfg.Paths, subject string, create bool) (rootFd, subjFd int, err error) {
	if !validSubject(subject) {
		return -1, -1, fmt.Errorf("nodefs: invalid backup subject %q", subject)
	}
	rfd, err := openTrustedDir(p.RepoRoot(), "")
	if err != nil {
		return -1, -1, err
	}
	if create {
		if err := syscall.Mkdirat(rfd, subject, 0o755); err != nil && !errors.Is(err, syscall.EEXIST) {
			syscall.Close(rfd)
			return -1, -1, fmt.Errorf("nodefs: mkdir %s/%s: %w", p.RepoRoot(), subject, err)
		}
	}
	sfd, err := openDirAt(rfd, subject)
	if err == nil {
		if err = checkTrusted(sfd, p.RepoDir(subject)); err != nil {
			syscall.Close(sfd)
		}
	} else {
		if errors.Is(err, syscall.ENOENT) {
			err = errNoSubject
		}
		err = fmt.Errorf("nodefs: open %s: %w", p.RepoDir(subject), err)
	}
	if err != nil {
		syscall.Close(rfd)
		return -1, -1, err
	}
	return rfd, sfd, nil
}

// ensureOwnedDir makes dirfd/name a directory of uid:gid with mode. It
// returns done when the directory is already uid:gid (then it is not touched:
// its owner may have changed anything in it), ErrExistsForeign for any owner
// but root or uid:gid, and otherwise the open root-owned directory, which
// only root can have made (its parent is root's and writable by no one else).
func ensureOwnedDir(dirfd int, name string, uid, gid int) (fd int, done bool, err error) {
	if err := syscall.Mkdirat(dirfd, name, 0o700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return -1, false, fmt.Errorf("nodefs: mkdir %s: %w", name, err)
	}
	fd, err = openDirAt(dirfd, name)
	if err != nil {
		return -1, false, fmt.Errorf("nodefs: open %s: %w", name, err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return -1, false, err
	}
	switch {
	case int(st.Uid) == uid && int(st.Gid) == gid:
		syscall.Close(fd)
		return -1, true, nil
	case st.Uid != 0:
		syscall.Close(fd)
		return -1, false, fmt.Errorf("%w: %s owned by %d:%d", ErrExistsForeign, name, st.Uid, st.Gid)
	}
	return fd, false, nil
}

// EnsureRepoDir makes RepoDir(subject) (root 0755) and its repo/ (uid:gid
// 0750), and sets the user quota of uid on the repository filesystem to
// quotaMB on every call. A repo/ owned by uid:gid is complete and not
// touched; a root-owned one (an interrupted call) is completed — its quota
// set before it is handed over; any other owner is ErrExistsForeign. uid and
// gid are each a project id or exactly the control plane's or the
// replicator's id.
func EnsureRepoDir(p nodecfg.Paths, subject string, uid, gid, quotaMB int) error {
	if !validSubject(subject) {
		return fmt.Errorf("nodefs: invalid backup subject %q", subject)
	}
	if !quotaID(uid) || !quotaID(gid) {
		return fmt.Errorf("nodefs: invalid repository owner %d:%d", uid, gid)
	}
	if quotaMB <= 0 || quotaMB > 1<<30 {
		return fmt.Errorf("nodefs: invalid repository quota %d MiB", quotaMB)
	}
	rfd, sfd, err := openSubject(p, subject, true)
	if err != nil {
		return err
	}
	defer syscall.Close(rfd)
	defer syscall.Close(sfd)
	if err := syscall.Fchmod(sfd, 0o755); err != nil {
		return err
	}
	fd, done, err := ensureOwnedDir(sfd, "repo", uid, gid)
	if err != nil {
		return fmt.Errorf("nodefs: %s: %w", p.RepoDir(subject), err)
	}
	if !done {
		defer syscall.Close(fd)
	}
	if err := setQuotaAt(p.RepoRoot(), uid, quotaMB); err != nil {
		return err
	}
	if done {
		return nil
	}
	if err := syscall.Fchmod(fd, 0o750); err != nil {
		return err
	}
	return syscall.Fchown(fd, uid, gid)
}

// EnsureFetchDir makes fetch/ in RepoDir(subject), uid:gid 2750, so that
// what uid writes there belongs to group gid. It refuses when RepoDir(subject)
// is absent and never creates it. The ownership rules are EnsureRepoDir's;
// the ids are the caller's choice among those EnsureRepoDir accepts.
func EnsureFetchDir(p nodecfg.Paths, subject string, uid, gid int) error {
	if !validSubject(subject) {
		return fmt.Errorf("nodefs: invalid backup subject %q", subject)
	}
	if !quotaID(uid) || !quotaID(gid) {
		return fmt.Errorf("nodefs: invalid fetch directory owner %d:%d", uid, gid)
	}
	rfd, sfd, err := openSubject(p, subject, false)
	if err != nil {
		return err
	}
	defer syscall.Close(rfd)
	defer syscall.Close(sfd)
	fd, done, err := ensureOwnedDir(sfd, "fetch", uid, gid)
	if err != nil || done {
		if err != nil {
			err = fmt.Errorf("nodefs: %s: %w", p.RepoDir(subject), err)
		}
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Fchmod(fd, 0o2750); err != nil {
		return err
	}
	return syscall.Fchown(fd, uid, gid)
}

// RemoveEmptyRepoDirs removes repo/, fetch/ and then RepoDir(subject), each
// with one non-recursive unlinkat from a descriptor, never following a link:
// a non-empty directory, or anything but a directory, fails and is left.
// Every absent directory is done.
func RemoveEmptyRepoDirs(p nodecfg.Paths, subject string) error {
	rfd, sfd, err := openSubject(p, subject, false)
	if errors.Is(err, errNoSubject) {
		return nil
	}
	if err != nil {
		return err
	}
	defer syscall.Close(rfd)
	defer syscall.Close(sfd)
	for _, name := range []string{"repo", "fetch"} {
		if err := unlinkatDir(sfd, name); err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("nodefs: remove %s/%s: %w", p.RepoDir(subject), name, err)
		}
	}
	if err := unlinkatDir(rfd, subject); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("nodefs: remove %s: %w", p.RepoDir(subject), err)
	}
	return nil
}

// RemoveEmptyFetchDir removes only fetch/ of RepoDir(subject), with one
// non-recursive unlinkat from the subject's descriptor that follows no link:
// a non-empty fetch/, or anything but a directory there, fails and is left.
// An absent fetch/ or subject is done; repo/ and the subject directory are
// never touched.
func RemoveEmptyFetchDir(p nodecfg.Paths, subject string) error {
	rfd, sfd, err := openSubject(p, subject, false)
	if errors.Is(err, errNoSubject) {
		return nil
	}
	if err != nil {
		return err
	}
	defer syscall.Close(rfd)
	defer syscall.Close(sfd)
	if err := unlinkatDir(sfd, "fetch"); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("nodefs: remove %s/fetch: %w", p.RepoDir(subject), err)
	}
	return nil
}
