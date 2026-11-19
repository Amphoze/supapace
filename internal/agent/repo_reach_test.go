//go:build reach

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
)

// repoXFS returns Paths under a fresh root whose directories down to
// RepoRoot are root 0755, with a scratch XFS (user quotas enforced,
// nosuid,nodev,noexec, as the repository filesystem is mounted) at RepoRoot.
// It needs root: nodefs refuses a repository root that root does not own.
func repoXFS(t *testing.T) nodecfg.Paths {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	root, err := os.MkdirTemp("", "agent-repo-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	p := nodecfg.Paths{Root: root}
	if err := os.MkdirAll(p.RepoRoot(), 0o755); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(t.TempDir(), "xfs.img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 320<<20); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("mkfs.xfs", "-q", img).CombinedOutput(); err != nil {
		t.Fatalf("mkfs.xfs: %v: %s", err, out)
	}
	dev := attachLoopDev(t, img)
	t.Cleanup(func() {
		if out, err := exec.Command("losetup", "-d", dev).CombinedOutput(); err != nil {
			t.Errorf("losetup -d %s: %v: %s", dev, err, out)
		}
	})
	if out, err := exec.Command("mount", "-o", "usrquota,nosuid,nodev,noexec", dev, p.RepoRoot()).CombinedOutput(); err != nil {
		t.Fatalf("mount: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(p.RepoRoot(), 0); err != nil {
			syscall.Unmount(p.RepoRoot(), syscall.MNT_DETACH)
		}
	})
	for d := p.RepoRoot(); d != filepath.Dir(root); d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// attachLoopDev attaches img to a free loop device, first creating the node
// of every loop device the kernel has (a container's /dev is a snapshot),
// with three tries.
func attachLoopDev(t *testing.T, img string) string {
	t.Helper()
	var last string
	for try := 0; try < 3; try++ {
		devs, _ := filepath.Glob("/sys/block/loop*/dev")
		exec.Command("losetup", "-f").Run()
		more, _ := filepath.Glob("/sys/block/loop*/dev")
		for _, d := range append(devs, more...) {
			b, err := os.ReadFile(d)
			var maj, mnr int
			if err != nil {
				continue
			}
			if _, err := fmt.Sscanf(string(b), "%d:%d", &maj, &mnr); err != nil {
				continue
			}
			n := "/dev/" + filepath.Base(filepath.Dir(d))
			if _, err := os.Lstat(n); err != nil {
				syscall.Mknod(n, syscall.S_IFBLK|0o660, mnr&0xff|maj<<8|(mnr&^0xff)<<12)
			}
		}
		out, err := exec.Command("losetup", "--find", "--show", img).CombinedOutput()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
		last = fmt.Sprintf("%v: %s", err, out)
		time.Sleep(time.Second)
	}
	t.Fatalf("losetup: %s", last)
	return ""
}

// TestRemoveFetch_LeavesRepoAndTheSubject: on a real repository filesystem,
// RemoveFetch removes the emptied fetch/ and leaves repo/ — non-empty, and
// empty (a project before its first backup) — and the subject directory, so
// a push's source check of repo/ still passes. Control: the removal of all
// three directories, on the same empty repo/, removes repo/ and the subject.
func TestRemoveFetch_LeavesRepoAndTheSubject(t *testing.T) {
	const uid, gid = 900301, 900301
	for _, withFile := range []bool{true, false} {
		t.Run(fmt.Sprintf("repo-not-empty-%v", withFile), func(t *testing.T) {
			p := repoXFS(t)
			t.Cleanup(func() { nodefs.SetQuotaAt(p.RepoRoot(), uid, 0) })
			f := fakeDocker(t)
			clFakePG(t, f) // the purge task's container: polled, exits 0
			a := New(nodecfg.Default("sp.test"), p)
			s := Spec{Ref: testRef, Epoch: 1, Generation: 1, UID: uid, GID: gid, Layout: 2, RepoQuotaMB: 16}
			if err := a.EnsureRepoDir(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			if err := nodefs.EnsureFetchDir(p, s.Ref, nodecfg.ReplicatorUID, gid); err != nil {
				t.Fatal(err)
			}
			repo := filepath.Join(p.RepoDir(s.Ref), "repo")
			if withFile {
				// What a push leaves: a file of the project in repo/.
				if err := os.WriteFile(filepath.Join(repo, "archive.info"), []byte("x"), 0o640); err != nil {
					t.Fatal(err)
				}
				os.Chown(filepath.Join(repo, "archive.info"), uid, gid)
			}
			if err := a.RemoveFetch(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(p.RepoDir(s.Ref), "fetch")); !os.IsNotExist(err) {
				t.Fatalf("fetch/ still there: %v", err)
			}
			if fi, err := os.Lstat(p.RepoDir(s.Ref)); err != nil || !fi.IsDir() {
				t.Fatalf("subject directory: %v", err)
			}
			pushSourceCheck(t, repo, uid, gid)
			if withFile {
				if _, err := os.Lstat(filepath.Join(repo, "archive.info")); err != nil {
					t.Fatalf("repo/ content: %v", err)
				}
				return
			}
			// Control, on this same empty repo/: the purge's removal takes
			// repo/ and the subject with it.
			if err := nodefs.RemoveEmptyRepoDirs(p, s.Ref); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(p.RepoDir(s.Ref)); !os.IsNotExist(err) {
				t.Fatalf("control: the subject directory survived the full removal: %v", err)
			}
		})
	}
}

// pushSourceCheck is the check a push makes of its repo/ source before it is
// launched: it exists, is a directory and no link, and is owned by the
// project's ids.
func pushSourceCheck(t *testing.T, path string, uid, gid int) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		t.Fatalf("push source %s: %v", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || int(st.Uid) != uid || int(st.Gid) != gid {
		t.Fatalf("push source %s: mode %o owner %d:%d", path, st.Mode, st.Uid, st.Gid)
	}
}
