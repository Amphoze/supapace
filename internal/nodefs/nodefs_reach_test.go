//go:build reach

package nodefs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// TestQuota_UserLimitEnforces writes at the project uid past the limit, after
// first moving its file out of the project id (which the owner may do): the
// user quota still stops it.
func TestQuota_UserLimitEnforces(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	if err := CreateProjectDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(p.ProjectDir(testRef), "data", "fill")
	if out, code := runTenant(t, uid, gid, "fill", f, "8"); code != 0 {
		t.Fatalf("a write under the limit failed: exit %d: %s", code, out)
	}
	for _, mode := range []string{"plain", "escape"} {
		if out, code := runTenant(t, uid, gid, "fill", f, "32", mode); code != 2 {
			t.Fatalf("%s: a 32 MiB write under a 16 MiB limit: exit %d (want a quota error): %s", mode, code, out)
		}
	}
}

func TestQuota_SetQuotaRaises(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	if err := CreateProjectDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(p.ProjectDir(testRef), "data", "fill")
	if out, code := runTenant(t, uid, gid, "fill", f, "24"); code != 2 {
		t.Fatalf("24 MiB under 16 MiB: exit %d: %s", code, out)
	}
	if err := SetQuota(p, uid, 32); err != nil {
		t.Fatal(err)
	}
	if out, code := runTenant(t, uid, gid, "fill", f, "24"); code != 0 {
		t.Fatalf("24 MiB under 32 MiB: exit %d: %s", code, out)
	}
	if err := SetQuota(p, uid, 0); err != nil {
		t.Fatal(err)
	}
	if out, code := runTenant(t, uid, gid, "fill", f, "48"); code != 0 {
		t.Fatalf("48 MiB with the limit cleared: exit %d: %s", code, out)
	}
}

// TestQuota_ProjectLimitNotBorrowable: a tenant may set any project id on its
// own files, so a project limit would let it exhaust another project's limit.
// The project quota must stay accounting only.
func TestQuota_ProjectLimitNotBorrowable(t *testing.T) {
	p := xfsPaths(t)
	a, _ := testIDs(t, p)
	b, _ := testIDs(t, p)
	refB := "bbbbbbbbbb0123456789"
	if err := CreateProjectDir(p, testRef, a, a, 16); err != nil {
		t.Fatal(err)
	}
	if err := CreateProjectDir(p, refB, b, b, 16); err != nil {
		t.Fatal(err)
	}
	fa := filepath.Join(p.ProjectDir(testRef), "data", "fill")
	if out, code := runTenant(t, a, a, "fill", fa, "15", strconv.Itoa(b)); code != 0 {
		t.Fatalf("tenant a, 15 MiB under its own limit: exit %d: %s", code, out)
	}
	fb := filepath.Join(p.ProjectDir(refB), "data", "fill")
	if out, code := runTenant(t, b, b, "fill", fb, "8"); code != 0 {
		t.Fatalf("tenant b, 8 MiB of 16 MiB, after tenant a moved files into its project id: exit %d: %s", code, out)
	}
}

// TestQuota_InodeLimitEnforces creates empty files at the project uid until
// the inode limit stops it with EDQUOT; raising the block quota raises the
// inode limit with it.
func TestQuota_InodeLimitEnforces(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	if err := CreateProjectDir(p, testRef, uid, gid, 64); err != nil {
		t.Fatal(err)
	}
	if b, i := limitsOf(t, p, uid); b != 64*1024 || i != minInodes {
		t.Fatalf("limits %d KiB / %d inodes, want %d / %d", b, i, 64*1024, minInodes)
	}
	data := filepath.Join(p.ProjectDir(testRef), "data")
	out, code := runTenant(t, uid, gid, "touch", filepath.Join(data, "a"), strconv.Itoa(minInodes+10))
	if code != 2 {
		t.Fatalf("%d empty files under a %d inode limit: exit %d: %s", minInodes+10, minInodes, code, out)
	}
	n, _ := strconv.Atoi(strings.Fields(out)[0])
	if n < minInodes-10 || n >= minInodes {
		t.Fatalf("stopped after %d files, want just under %d: %s", n, minInodes, out)
	}
	if err := SetQuota(p, uid, 512); err != nil {
		t.Fatal(err)
	}
	if b, i := limitsOf(t, p, uid); b != 512*1024 || i != 512*inodesPerMB {
		t.Fatalf("limits %d KiB / %d inodes after raising", b, i)
	}
	if out, code := runTenant(t, uid, gid, "touch", filepath.Join(data, "b"), "1000"); code != 0 {
		t.Fatalf("1000 more files after raising: exit %d: %s", code, out)
	}
}

func limitsOf(t *testing.T, p nodecfg.Paths, uid int) (blocksKiB, inodes int) {
	t.Helper()
	recs, err := readLimits(p.ProjectsDir(), uid)
	if err != nil || len(recs) != 1 {
		t.Fatalf("read limits: %v %v", recs, err)
	}
	return recs[0][0], recs[0][1]
}

// scratchXFS mounts a fresh small XFS image with the given options as the
// ProjectsDir of a temporary root.
func scratchXFS(t *testing.T, opts string) nodecfg.Paths {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	p, _, err := attachXFS(t, opts)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// attachXFS mounts a scratch XFS (mountScratchXFS) at the ProjectsDir of a
// fresh temporary root, returning the device ("" when none was attached).
func attachXFS(t *testing.T, opts string) (p nodecfg.Paths, dev string, err error) {
	t.Helper()
	p = nodecfg.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(p.ProjectsDir(), 0o755); err != nil {
		return p, "", err
	}
	dev, err = mountScratchXFS(t, p.ProjectsDir(), opts)
	return p, dev, err
}

// TestScratchXFS_DetachesLoop: the loop device is gone after the test that
// used it, also when the mount failed. Devices are told apart by their
// backing file: another run may reuse a number at once.
func TestScratchXFS_DetachesLoop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	var backs []string
	for _, opts := range []string{"usrquota", "no-such-option"} {
		t.Run(opts, func(t *testing.T) {
			_, dev, err := attachXFS(t, opts)
			if dev == "" {
				t.Fatalf("attach %s: no loop device: %v", opts, err)
			}
			b, berr := exec.Command("losetup", "-n", "-O", "BACK-FILE", dev).Output()
			if berr != nil || strings.TrimSpace(string(b)) == "" {
				t.Fatalf("backing file of %s: %v %q", dev, berr, b)
			}
			backs = append(backs, strings.TrimSpace(string(b)))
			if (err == nil) != (opts == "usrquota") {
				t.Fatalf("attach %s: %v", opts, err)
			}
		})
	}
	if len(backs) != 2 {
		t.Fatalf("backing files: %v", backs)
	}
	out, err := exec.Command("losetup", "-l", "-n", "-O", "BACK-FILE").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range backs {
		for _, l := range strings.Split(string(out), "\n") {
			if strings.TrimSpace(l) == b {
				t.Errorf("loop device of %s left attached", b)
			}
		}
	}
}

// TestSetQuota_RefusesUnenforcedQuota: a limit on a mount whose user quota is
// accounted but not enforced would be recorded and ignored.
func TestSetQuota_RefusesUnenforcedQuota(t *testing.T) {
	const uid = 900100
	p := scratchXFS(t, "usrquota")
	if err := SetQuota(p, uid, 16); err != nil {
		t.Fatalf("enforced mount: %v", err)
	}
	xq := func(c string) {
		if out, err := exec.Command("xfs_quota", "-x", "-c", c, p.ProjectsDir()).CombinedOutput(); err != nil || len(out) > 0 {
			t.Fatalf("%s: %v %s", c, err, out)
		}
	}
	xq("disable -u")
	if err := SetQuota(p, uid, 32); !errors.Is(err, errQuotaNotEnforced) {
		t.Fatalf("after disable -u: got %v", err)
	}
	if err := SetQuota(p, uid, 0); err != nil {
		t.Fatalf("clearing on an unenforced mount: %v", err)
	}
	xq("enable -u")
	if err := SetQuota(p, uid, 32); err != nil {
		t.Fatalf("after enable -u: %v", err)
	}
	for _, opts := range []string{"uqnoenforce", "prjquota", "noquota"} {
		q := scratchXFS(t, opts)
		if err := SetQuota(q, uid, 16); err == nil {
			t.Errorf("%s: limit set on an unenforced mount", opts)
		}
	}
}

// TestRepoQuota_Enforced: the project's writes into its repo/ stop at the
// repository quota EnsureRepoDir sets.
func TestRepoQuota_Enforced(t *testing.T) {
	p := repoPaths(t)
	const uid, gid = 900201, 900201
	t.Cleanup(func() { SetQuotaAt(p.RepoRoot(), uid, 0) })
	if err := EnsureRepoDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(p.RepoDir(testRef), "repo", "fill")
	if out, code := runTenant(t, uid, gid, "fill", f, "8"); code != 0 {
		t.Fatalf("a write under the limit failed: exit %d: %s", code, out)
	}
	if out, code := runTenant(t, uid, gid, "fill", f, "32"); code != 2 {
		t.Fatalf("a 32 MiB write under a 16 MiB repository quota: exit %d (want a quota error): %s", code, out)
	}
}

// TestRepoQuota_IndependentOfProjectsQuota: the disk quota on the projects
// filesystem and the repository quota on the repository filesystem are
// separate limits on the same uid: either one full leaves the other usable
// up to its own limit, and each mount reports its own usage. A create at a
// full disk quota fails at its open, with the quota error.
func TestRepoQuota_IndependentOfProjectsQuota(t *testing.T) {
	p := xfsPaths(t)
	withRepoXFS(t, p)
	uid, gid := testIDs(t, p)
	t.Cleanup(func() { SetQuotaAt(p.RepoRoot(), uid, 0) })
	if err := CreateProjectDirL2(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	if err := EnsureRepoDir(p, testRef, uid, gid, 48); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(p.ProjectDir(testRef), "spool", "fill")
	repo := filepath.Join(p.RepoDir(testRef), "repo", "fill")
	if out, code := runTenant(t, uid, gid, "fill", data, "24"); code != 2 {
		t.Fatalf("24 MiB under a 16 MiB disk quota: exit %d: %s", code, out)
	}
	if out, code := runTenant(t, uid, gid, "fill", repo, "32"); code != 0 {
		t.Fatalf("32 MiB into the repository with the disk quota full: exit %d: %s", code, out)
	}
	if out, code := runTenant(t, uid, gid, "fill", repo, "64"); code != 2 {
		t.Fatalf("64 MiB under a 48 MiB repository quota: exit %d: %s", code, out)
	}
	if out, code := runTenant(t, uid, gid, "fill", data+"2", "1"); code == 0 || !strings.Contains(out, "quota") {
		t.Fatalf("the disk quota freed by the repository: exit %d: %s", code, out)
	}
	// Each filesystem charges its own writes.
	dUsed, dHard, err := QuotaUsage(context.Background(), p.ProjectsDir(), uid)
	if err != nil || dHard != 16<<10 || dUsed < 15<<10 || dUsed > 17<<10 {
		t.Errorf("projects: used %d KiB, hard %d KiB, %v", dUsed, dHard, err)
	}
	rUsed, rHard, err := QuotaUsage(context.Background(), p.RepoRoot(), uid)
	if err != nil || rHard != 48<<10 || rUsed < 47<<10 || rUsed > 49<<10 {
		t.Errorf("repository: used %d KiB, hard %d KiB, %v", rUsed, rHard, err)
	}
	// Control: freeing the repository frees nothing on the projects filesystem.
	if err := os.Remove(repo); err != nil {
		t.Fatal(err)
	}
	if out, code := runTenant(t, uid, gid, "fill", data+"3", "1"); code == 0 || !strings.Contains(out, "quota") {
		t.Fatalf("the disk quota freed by emptying the repository: exit %d: %s", code, out)
	}
	if out, code := runTenant(t, uid, gid, "fill", repo, "32"); code != 0 {
		t.Fatalf("the emptied repository: exit %d: %s", code, out)
	}
}

// TestRepoQuota_PlatformIDsEnforced: the control plane's uid in its repo/ and
// the replicator's uid in a fetch/ stop at the limits set for them.
func TestRepoQuota_PlatformIDsEnforced(t *testing.T) {
	p := repoPaths(t)
	cp, r := nodecfg.ControlPlaneUID, nodecfg.ReplicatorUID
	t.Cleanup(func() {
		SetQuotaAt(p.RepoRoot(), cp, 0)
		SetQuotaAt(p.RepoRoot(), r, 0)
	})
	if err := EnsureRepoDir(p, nodecfg.ControlPlaneSubject, cp, cp, 16); err != nil {
		t.Fatal(err)
	}
	if err := SetQuotaAt(p.RepoRoot(), r, 16); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFetchDir(p, nodecfg.ControlPlaneSubject, r, cp); err != nil {
		t.Fatal(err)
	}
	for _, w := range []struct {
		id  int
		dir string
	}{{cp, "repo"}, {r, "fetch"}} {
		f := filepath.Join(p.RepoDir(nodecfg.ControlPlaneSubject), w.dir, "fill")
		if out, code := runTenant(t, w.id, w.id, "fill", f, "8"); code != 0 {
			t.Fatalf("uid %d, 8 MiB under 16 MiB: exit %d: %s", w.id, code, out)
		}
		if out, code := runTenant(t, w.id, w.id, "fill", f, "32"); code != 2 {
			t.Fatalf("uid %d, 32 MiB under 16 MiB: exit %d (want a quota error): %s", w.id, code, out)
		}
	}
}

// TestFetchDir_SetgidInherits: what the replicator writes into fetch/ — files
// and directories at any depth — belongs to the subject's group, so the
// subject's own jobs can read it; a directory without the setgid bit (the
// control) gives the writer's own group.
func TestFetchDir_SetgidInherits(t *testing.T) {
	p := repoPaths(t)
	const uid, gid = 900211, 900212
	r := nodecfg.ReplicatorUID
	t.Cleanup(func() { SetQuotaAt(p.RepoRoot(), uid, 0) })
	if err := EnsureRepoDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFetchDir(p, testRef, r, gid); err != nil {
		t.Fatal(err)
	}
	fetch := filepath.Join(p.RepoDir(testRef), "fetch")
	asTenant(t, r, r, "fill", filepath.Join(fetch, "f"), "1")
	asTenant(t, r, r, "touch", filepath.Join(fetch, "d"), "1")
	asTenant(t, r, r, "touch", filepath.Join(fetch, "d", "e"), "1")
	for _, n := range []string{"f", "d", "d/0", "d/e", "d/e/0"} {
		u, g, m := owner(t, filepath.Join(fetch, n))
		if int(u) != r || int(g) != gid {
			t.Errorf("%s: %d:%d, want %d:%d", n, u, g, r, gid)
		}
		if m.IsDir() && m&os.ModeSetgid == 0 {
			t.Errorf("%s: directory without the setgid bit: %v", n, m)
		}
	}
	// Control: in a directory of the replicator without the setgid bit.
	plain := filepath.Join(fetch, "plain")
	if err := os.Mkdir(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(plain, r, r); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	asTenant(t, r, r, "fill", filepath.Join(plain, "f"), "1")
	if _, g, _ := owner(t, filepath.Join(plain, "f")); int(g) != r {
		t.Errorf("control: file in a plain directory has group %d, want %d", g, r)
	}
}
