package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// EnsureDir creates the project's directory on the quota mount (nodefs: the
// tree is owned by the project's ids, root touches nothing below it once
// it is complete).
func (a *Agent) EnsureDir(ctx context.Context, s Spec) error {
	if err := checkRef(s.Ref); err != nil {
		return err
	}
	return createProjectDir(a.p, s.Ref, s.UID, s.GID, s.DiskQuotaMB)
}

// SetQuota sets the project uid's disk quota (by id; opens nothing below the
// project directory).
func (a *Agent) SetQuota(ctx context.Context, s Spec) error {
	if err := checkRef(s.Ref); err != nil {
		return err
	}
	return setQuota(a.p, s.UID, s.DiskQuotaMB)
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
