//go:build reach

package nodefs

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// attachXFS attaches a fresh image to a loop device and mounts it, returning
// the device ("" when none was attached). Cleanups registered as soon as each
// piece exists unmount (lazily if busy) and detach the device, whatever fails
// later.
func attachXFS(t *testing.T, opts string) (p nodecfg.Paths, dev string, err error) {
	t.Helper()
	root := t.TempDir()
	p = nodecfg.Paths{Root: root}
	if err := os.MkdirAll(p.ProjectsDir(), 0o755); err != nil {
		return p, "", err
	}
	img := filepath.Join(root, "xfs.img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		return p, dev, err
	}
	if err := os.Truncate(img, 320<<20); err != nil {
		return p, dev, err
	}
	if out, err := exec.Command("mkfs.xfs", "-q", img).CombinedOutput(); err != nil {
		return p, dev, fmt.Errorf("mkfs.xfs: %v: %s", err, out)
	}
	out, err := exec.Command("losetup", "--find", "--show", img).CombinedOutput()
	if err != nil {
		return p, dev, fmt.Errorf("losetup: %v: %s", err, out)
	}
	dev = strings.TrimSpace(string(out))
	t.Cleanup(func() {
		if out, err := exec.Command("losetup", "-d", dev).CombinedOutput(); err != nil {
			t.Errorf("losetup -d %s: %v: %s", dev, err, out)
		}
	})
	if out, err := exec.Command("mount", "-o", opts, dev, p.ProjectsDir()).CombinedOutput(); err != nil {
		return p, dev, fmt.Errorf("mount: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(p.ProjectsDir(), 0); err != nil {
			if err := syscall.Unmount(p.ProjectsDir(), syscall.MNT_DETACH); err != nil {
				t.Errorf("unmount: %v", err)
			}
		}
	})
	return p, dev, nil
}

// TestScratchXFS_DetachesLoop: the loop device is gone after the test that
// used it, also when the mount failed.
func TestScratchXFS_DetachesLoop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	var devs []string
	for _, opts := range []string{"usrquota", "no-such-option"} {
		t.Run(opts, func(t *testing.T) {
			_, dev, err := attachXFS(t, opts)
			if dev == "" {
				t.Fatalf("attach %s: no loop device: %v", opts, err)
			}
			devs = append(devs, dev)
			if (err == nil) != (opts == "usrquota") {
				t.Fatalf("attach %s: %v", opts, err)
			}
		})
	}
	out, err := exec.Command("losetup", "-l", "-n", "-O", "NAME").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, dev := range devs {
		for _, l := range strings.Fields(string(out)) {
			if l == dev {
				t.Errorf("loop device %s left attached", dev)
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
