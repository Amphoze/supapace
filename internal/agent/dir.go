package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/Amphoze/supapace/internal/nodefs"
)

// Seams of the repository filesystem and the quota reports (tests replace
// them).
var (
	createProjectDirL2 = nodefs.CreateProjectDirL2
	ensureRepoDir      = nodefs.EnsureRepoDir
	repoSetQuota       = nodefs.SetQuotaAt
	quotaUsage         = nodefs.QuotaUsage
	repoStatfs         = syscall.Statfs
)

// quotaBlockKB is one filesystem block: a quota whose usage is within it of
// its hard limit is full.
const quotaBlockKB = 4

// EnsureDir creates the project's directory on the quota mount (nodefs: the
// tree is owned by the project's ids, root touches nothing below it once
// it is complete). Layout 2 creates the spool directories with it; a
// completed directory is left as it is (EnsureSpoolDirs completes it).
func (a *Agent) EnsureDir(ctx context.Context, s Spec) error {
	if err := checkRef(s.Ref); err != nil {
		return err
	}
	if s.Layout == 2 {
		return createProjectDirL2(a.p, s.Ref, s.UID, s.GID, s.DiskQuotaMB)
	}
	return createProjectDir(a.p, s.Ref, s.UID, s.GID, s.DiskQuotaMB)
}

// SetQuota sets the project uid's disk quota (by id; opens nothing below the
// project directory) and, at layout 2, its repository quota on the
// repository filesystem. A layout-2 spec without a repository quota is
// refused before anything is set: 0 would clear it.
func (a *Agent) SetQuota(ctx context.Context, s Spec) error {
	if err := checkRef(s.Ref); err != nil {
		return err
	}
	if s.Layout == 2 && s.RepoQuotaMB <= 0 {
		return fmt.Errorf("agent: %s: no repository quota in the spec", s.Ref)
	}
	if err := setQuota(a.p, s.UID, s.DiskQuotaMB); err != nil {
		return err
	}
	if s.Layout == 2 {
		return repoSetQuota(a.p.RepoRoot(), s.UID, s.RepoQuotaMB)
	}
	return nil
}

// DiskUsage returns the bytes the project uid's user quota charges: a
// host-side fact, never a figure the cluster reports. At layout 2 it is the
// larger of the uid's use of the projects filesystem and of the repository
// filesystem: the repository quota follows the disk quota, so a disk quota
// below either is too small.
func (a *Agent) DiskUsage(ctx context.Context, s Spec) (int64, error) {
	if err := checkRef(s.Ref); err != nil {
		return 0, err
	}
	if s.Layout == 2 {
		u, err := a.QuotaUse(ctx, s.UID)
		return max(u.DiskUsedKB, u.RepoUsedKB) << 10, err
	}
	return diskUsage(ctx, a.p, s.UID)
}

// QuotaUse reads uid's quota report on the projects filesystem and on the
// repository filesystem. ctx bounds each quota tool: it is killed when ctx
// ends, and the error then matches ctx's.
func (a *Agent) QuotaUse(ctx context.Context, uid int) (QuotaUse, error) {
	var u QuotaUse
	var err error
	if u.DiskUsedKB, u.DiskHardKB, err = quotaUsage(ctx, a.p.ProjectsDir(), uid); err != nil {
		return QuotaUse{}, err
	}
	if u.RepoUsedKB, u.RepoHardKB, err = quotaUsage(ctx, a.p.RepoRoot(), uid); err != nil {
		return QuotaUse{}, err
	}
	return u, nil
}

// RepoSpace returns the size and the space available to users of the
// repository filesystem, in MiB.
func (a *Agent) RepoSpace(ctx context.Context) (sizeMB, freeMB int64, err error) {
	var st syscall.Statfs_t
	if err := repoStatfs(a.p.RepoRoot(), &st); err != nil {
		return 0, 0, fmt.Errorf("agent: repository filesystem: %w", err)
	}
	bs := st.Frsize
	return int64(st.Blocks) * bs >> 20, int64(st.Bavail) * bs >> 20, nil
}

// EnsureRepoDir creates the project's repository directory with its quota
// (nodefs: <repo>/<ref> root 0755, repo/ owned by the project's ids).
func (a *Agent) EnsureRepoDir(ctx context.Context, s Spec) error {
	if err := checkRef(s.Ref); err != nil {
		return err
	}
	return ensureRepoDir(a.p, s.Ref, s.UID, s.GID, s.RepoQuotaMB)
}

// HostState reads what the node holds of the project, without entering its
// tree: its directory (a real directory, never a link), its state file, a
// running cluster container, and whether its disk quota is full — usage
// within one block of the hard limit, from the quota report, whatever the
// container does.
func (a *Agent) HostState(ctx context.Context, s Spec) (HostState, error) {
	if err := checkRef(s.Ref); err != nil {
		return HostState{}, err
	}
	var h HostState
	fi, err := os.Lstat(a.p.ProjectDir(s.Ref))
	switch {
	case err == nil:
		h.ProjectDir = fi.IsDir()
	case !errors.Is(err, fs.ErrNotExist):
		return HostState{}, err
	}
	if _, h.StateFile, err = a.readState(s.Ref); err != nil {
		return HostState{}, err
	}
	c, err := dockerInspectContainer(ctx, clusterName(s.Ref))
	if err != nil {
		return HostState{}, err
	}
	h.ClusterRunning = c != nil && c.Running
	u, err := a.QuotaUse(ctx, s.UID)
	if err != nil {
		return HostState{}, err
	}
	h.QuotaFull = u.DiskHardKB > 0 && u.DiskUsedKB+quotaBlockKB >= u.DiskHardKB
	return h, nil
}

// RemoveRender removes the project's root-owned render directory; nil when
// absent. Nothing a tenant can write lies below it, and links are removed,
// never followed.
func (a *Agent) RemoveRender(ctx context.Context, ref string) error {
	if err := checkRef(ref); err != nil {
		return err
	}
	return os.RemoveAll(a.p.RenderDir(ref))
}

// ensureDir makes path a directory (never a link) with exactly mode, owned
// by uid:gid when uid >= 0 (else by its creator, the daemon). The daemon runs
// with umask 0077, so the mode is always set explicitly.
func ensureDir(path string, mode os.FileMode, uid, gid int) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("agent: %s is not a directory", path)
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if uid >= 0 {
		return chown(path, uid, gid)
	}
	return nil
}
