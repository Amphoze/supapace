package nodefs

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// A repository root that is not the XFS filesystem (it is not mounted, say)
// gets nothing created in it: the subject directory would be hidden by the
// later mount.
func TestEnsureRepoDir_NotXFSCreatesNothing(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(p.RepoRoot(), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{p.RepoRoot(), p.RepoRoot() + "/..", p.RepoRoot() + "/../.."} {
		os.Chmod(d, 0o755)
	}
	err := EnsureRepoDir(p, nodecfg.ControlPlaneSubject, nodecfg.ControlPlaneUID, nodecfg.ControlPlaneUID, 16)
	if err == nil || !strings.Contains(err.Error(), "not XFS") {
		t.Fatalf("got %v, want the filesystem refusal", err)
	}
	if _, err := os.Lstat(p.RepoDir(nodecfg.ControlPlaneSubject)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("subject directory made on the wrong filesystem: %v", err)
	}
}
