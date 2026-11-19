package nodefs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

// mountScratchXFS makes a fresh 320 MiB XFS image in its own temporary
// directory, attaches it to a loop device and mounts it at dir with opts. It
// returns the device ("" when none was attached). Cleanups registered as soon
// as each piece exists unmount (lazily if busy) and detach the device,
// whatever fails later.
func mountScratchXFS(t *testing.T, dir, opts string) (dev string, err error) {
	t.Helper()
	img := filepath.Join(t.TempDir(), "xfs.img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		return "", err
	}
	if err := os.Truncate(img, 320<<20); err != nil {
		return "", err
	}
	if out, err := exec.Command("mkfs.xfs", "-q", img).CombinedOutput(); err != nil {
		return "", fmt.Errorf("mkfs.xfs: %v: %s", err, out)
	}
	dev, err = attachLoop(img)
	if err != nil {
		return "", err
	}
	t.Cleanup(func() {
		if out, err := exec.Command("losetup", "-d", dev).CombinedOutput(); err != nil {
			t.Errorf("losetup -d %s: %v: %s", dev, err, out)
		}
	})
	if out, err := exec.Command("mount", "-o", opts, dev, dir).CombinedOutput(); err != nil {
		return dev, fmt.Errorf("mount: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(dir, 0); err != nil {
			if err := syscall.Unmount(dir, syscall.MNT_DETACH); err != nil {
				t.Errorf("unmount %s: %v", dir, err)
			}
		}
	})
	return dev, nil
}

// attachLoop attaches img to a free loop device and returns its name. A
// container's /dev is a snapshot of the host's loop devices, which other
// users add to: as the node's init does, the node of every loop device the
// kernel has, and of the next free one, is created first, and the attach is
// tried three times. Whatever a failed attempt left attached to img is
// detached.
func attachLoop(img string) (string, error) {
	var err error
	for try := 0; try < 3; try++ {
		mknodLoops()
		exec.Command("losetup", "-f").Run()
		mknodLoops()
		var out []byte
		out, err = exec.Command("losetup", "--find", "--show", img).CombinedOutput()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
		err = fmt.Errorf("losetup: %v: %s", err, out)
		mknodLoops()
		left, _ := exec.Command("losetup", "-n", "-O", "NAME", "-j", img).Output()
		for _, d := range strings.Fields(string(left)) {
			exec.Command("losetup", "-d", d).Run()
		}
		time.Sleep(time.Second)
	}
	return "", err
}

// mknodLoops creates /dev/loopN for every loop device in /sys/block that has
// no node.
func mknodLoops() {
	devs, _ := filepath.Glob("/sys/block/loop*/dev")
	for _, d := range devs {
		b, err := os.ReadFile(d)
		if err != nil {
			continue
		}
		var maj, mnr int
		if _, err := fmt.Sscanf(string(b), "%d:%d", &maj, &mnr); err != nil {
			continue
		}
		n := "/dev/" + filepath.Base(filepath.Dir(d))
		if _, err := os.Lstat(n); err == nil {
			continue
		}
		// The kernel's encoding of a device number (new_encode_dev).
		syscall.Mknod(n, syscall.S_IFBLK|0o660, mnr&0xff|maj<<8|(mnr&^0xff)<<12)
	}
}

// traversablePaths returns Paths under a fresh temporary root whose
// directories down to RepoRoot are root 0755, so a helper process at any uid
// can reach what lies below.
func traversablePaths(t *testing.T) nodecfg.Paths {
	t.Helper()
	root, err := os.MkdirTemp("", "nodefs-repo-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	p := nodecfg.Paths{Root: root}
	if err := os.MkdirAll(p.RepoRoot(), 0o755); err != nil {
		t.Fatal(err)
	}
	for d := p.RepoRoot(); d != filepath.Dir(root); d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// withRepoXFS mounts a scratch XFS with user-quota enforcement, as the
// repository filesystem is mounted, at p.RepoRoot(). It requires root.
func withRepoXFS(t *testing.T, p nodecfg.Paths) {
	t.Helper()
	needRoot(t)
	if err := os.MkdirAll(p.RepoRoot(), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := mountScratchXFS(t, p.RepoRoot(), "usrquota,nosuid,nodev,noexec"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.RepoRoot(), 0o755); err != nil {
		t.Fatal(err)
	}
}

// repoPaths returns traversable Paths whose RepoRoot is a scratch quota XFS.
func repoPaths(t *testing.T) nodecfg.Paths {
	t.Helper()
	needRoot(t)
	p := traversablePaths(t)
	withRepoXFS(t, p)
	return p
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func limitsAt(t *testing.T, mount string, id int) [][2]int {
	t.Helper()
	recs, err := readLimits(mount, id)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// noLimit fails when id carries a limit on mount.
func noLimit(t *testing.T, mount string, id int) {
	t.Helper()
	for _, r := range limitsAt(t, mount, id) {
		if r != [2]int{0, 0} {
			t.Errorf("id %d: limit recorded on %s: %d KiB / %d inodes", id, mount, r[0], r[1])
		}
	}
}

// ───────── CreateProjectDirL2 ─────────

// TestCreateProjectDirL2_Resumes: interrupted before the outer chown, the
// next call completes every directory; once the outer directory is the
// project's, nothing below it is touched again — neither a changed spool
// directory nor a layout-1 directory, which gets no spool directories.
func TestCreateProjectDirL2_Resumes(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	dir := p.ProjectDir(testRef)
	all := []string{"", "data", "sock", "spool", "rspool", "rspool/req", "rspool/out"}
	interrupted := errors.New("interrupted")
	setFailpoint(t, func() error {
		for _, d := range all[1:] {
			if u, g, m := owner(t, filepath.Join(dir, d)); int(u) != uid || int(g) != gid || m != os.ModeDir|0o700 {
				t.Errorf("at failpoint %s: %d:%d %v", d, u, g, m)
			}
		}
		if u, _, _ := owner(t, dir); u != 0 {
			t.Errorf("outer chowned before the inner ones: %d", u)
		}
		return interrupted
	})
	if err := CreateProjectDirL2(p, testRef, uid, gid, 16); !errors.Is(err, interrupted) {
		t.Fatalf("got %v", err)
	}
	if u, _, _ := owner(t, dir); u != 0 {
		t.Fatalf("outer owner %d after interruption", u)
	}
	afterInnerChown = nil
	if err := CreateProjectDirL2(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	for _, d := range all {
		path := filepath.Join(dir, d)
		if u, g, m := owner(t, path); int(u) != uid || int(g) != gid || m != os.ModeDir|0o700 {
			t.Errorf("%q: %d:%d %v", d, u, g, m)
		}
		if x := projid(t, path); int(x.Projid) != uid || x.Xflags&fsXflagProjInherit == 0 {
			t.Errorf("%q: project id %d flags %#x", d, x.Projid, x.Xflags)
		}
	}
	if got := strings.Join(entries(t, dir), " "); got != "data rspool sock spool" {
		t.Errorf("outer entries: %s", got)
	}
	if got := strings.Join(entries(t, filepath.Join(dir, "rspool")), " "); got != "out req" {
		t.Errorf("rspool entries: %s", got)
	}

	// Complete: stand-ins for tenant activity are left as they are.
	if err := os.Chmod(filepath.Join(dir, "spool"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "rspool", "out")); err != nil {
		t.Fatal(err)
	}
	setFailpoint(t, func() error { t.Error("steps repeated on a completed directory"); return nil })
	if err := CreateProjectDirL2(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	if _, _, m := owner(t, filepath.Join(dir, "spool")); m.Perm() != 0o750 {
		t.Errorf("spool touched: %v", m)
	}
	if _, err := os.Lstat(filepath.Join(dir, "rspool", "out")); !os.IsNotExist(err) {
		t.Errorf("rspool/out created again: %v", err)
	}

	// A completed layout-1 directory is complete for this call too.
	ref1 := "llllllllll0123456789"
	afterInnerChown = nil
	if err := CreateProjectDir(p, ref1, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	setFailpoint(t, func() error { t.Error("steps repeated on a completed layout-1 directory"); return nil })
	if err := CreateProjectDirL2(p, ref1, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(entries(t, p.ProjectDir(ref1)), " "); got != "data sock" {
		t.Errorf("layout-1 directory changed: %s", got)
	}
}

// TestCreateProjectDirL2_ResumeRefusesPlantedChildren: with the outer
// directory root-owned, a spool or nested restore-spool entry that is a link,
// a FIFO or a foreign directory is refused without blocking, nothing is
// chowned and the canary the links name is unchanged.
func TestCreateProjectDirL2_ResumeRefusesPlantedChildren(t *testing.T) {
	p := xfsPaths(t)
	uid, gid := testIDs(t, p)
	canary := t.TempDir()
	os.Chmod(canary, 0o755)
	cu, cg, cm := owner(t, canary)
	cx := projid(t, canary)
	rspool := func(d string) string {
		if err := os.Mkdir(filepath.Join(d, "rspool"), 0o700); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(d, "rspool")
	}
	plants := map[string]func(dir string) error{
		"spool link":  func(d string) error { return os.Symlink(canary, filepath.Join(d, "spool")) },
		"rspool link": func(d string) error { return os.Symlink(canary, filepath.Join(d, "rspool")) },
		"req link":    func(d string) error { return os.Symlink(canary, filepath.Join(rspool(d), "req")) },
		"out fifo":    func(d string) error { return syscall.Mkfifo(filepath.Join(rspool(d), "out"), 0o600) },
		"spool fifo":  func(d string) error { return syscall.Mkfifo(filepath.Join(d, "spool"), 0o600) },
		"rspool file": func(d string) error { return os.WriteFile(filepath.Join(d, "rspool"), nil, 0o600) },
		"req foreign": func(d string) error {
			r := rspool(d)
			os.Mkdir(r+"/req", 0o700)
			return os.Chown(r+"/req", uid+7, gid+7)
		},
		"spool foreign": func(d string) error {
			os.Mkdir(filepath.Join(d, "spool"), 0o700)
			return os.Chown(filepath.Join(d, "spool"), uid, gid+7)
		},
	}
	i := 0
	for name, plant := range plants {
		i++
		ref := strings.Repeat(string(rune('k'+i)), 10) + "0123456789"
		dir := p.ProjectDir(ref)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := plant(dir); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- CreateProjectDirL2(p, ref, uid, gid, 16) }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: resume accepted it", name)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("%s: CreateProjectDirL2 blocked", name)
		}
		if u, _, _ := owner(t, dir); u != 0 {
			t.Errorf("%s: outer chowned to %d", name, u)
		}
	}
	if u, g, m := owner(t, canary); u != cu || g != cg || m != cm || projid(t, canary) != cx {
		t.Fatalf("canary changed: %d:%d %v %v", u, g, m, projid(t, canary))
	}
	if ents := entries(t, canary); len(ents) != 0 {
		t.Fatalf("created in the canary: %v", ents)
	}
	// Control: the same planted-free path completes.
	ref := "cccccccccc0123456789"
	if err := os.Mkdir(p.ProjectDir(ref), 0o700); err != nil {
		t.Fatal(err)
	}
	rspool(p.ProjectDir(ref))
	if err := CreateProjectDirL2(p, ref, uid, gid, 16); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// ───────── EnsureRepoDir ─────────

// TestEnsureRepoDir_Modes: <subject>/ root 0755, repo/ uid:gid 0750 and the
// user quota of uid on the repository filesystem. A second call leaves a
// complete repo/ as the project left it and sets the quota it is given.
func TestEnsureRepoDir_Modes(t *testing.T) {
	p := repoPaths(t)
	const uid, gid = 900101, 900102
	t.Cleanup(func() { SetQuotaAt(p.RepoRoot(), uid, 0) })
	if err := EnsureRepoDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	if u, g, m := owner(t, p.RepoDir(testRef)); u != 0 || g != 0 || m != os.ModeDir|0o755 {
		t.Errorf("subject: %d:%d %v", u, g, m)
	}
	repo := filepath.Join(p.RepoDir(testRef), "repo")
	if u, g, m := owner(t, repo); u != uid || g != gid || m != os.ModeDir|0o750 {
		t.Errorf("repo: %d:%d %v", u, g, m)
	}
	if got := entries(t, p.RepoDir(testRef)); len(got) != 1 {
		t.Errorf("subject entries: %v", got)
	}
	if r := limitsAt(t, p.RepoRoot(), uid); len(r) != 1 || r[0] != [2]int{16 << 10, minInodes} {
		t.Errorf("limits: %v", r)
	}
	if u, h, err := QuotaUsage(context.Background(), p.RepoRoot(), uid); err != nil || h != 16<<10 || u != 0 {
		t.Errorf("usage: %d %d %v", u, h, err)
	}
	// The project's own changes inside its repo/ stay.
	if err := os.Chmod(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureRepoDir(p, testRef, uid, gid, 32); err != nil {
		t.Fatal(err)
	}
	if _, _, m := owner(t, repo); m.Perm() != 0o700 {
		t.Errorf("a complete repo/ touched: %v", m)
	}
	if u, _, _ := owner(t, filepath.Join(repo, "f")); u != 0 {
		t.Errorf("a file in repo/ chowned to %d", u)
	}
	if r := limitsAt(t, p.RepoRoot(), uid); len(r) != 1 || r[0] != [2]int{32 << 10, max(minInodes, 32*inodesPerMB)} {
		t.Errorf("limits after the second call: %v", r)
	}
	// Interrupted before the chown: a root-owned repo/ is completed.
	ref2 := "dddddddddd0123456789"
	if err := os.MkdirAll(filepath.Join(p.RepoDir(ref2), "repo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := EnsureRepoDir(p, ref2, uid, gid, 32); err != nil {
		t.Fatal(err)
	}
	if u, g, m := owner(t, filepath.Join(p.RepoDir(ref2), "repo")); u != uid || g != gid || m != os.ModeDir|0o750 {
		t.Errorf("resumed repo: %d:%d %v", u, g, m)
	}
	if _, _, m := owner(t, p.RepoDir(ref2)); m != os.ModeDir|0o755 {
		t.Errorf("resumed subject: %v", m)
	}
}

// TestEnsureRepoDir_ControlPlaneIDs: the control plane's subject at 70:70 is
// accepted and its quota is set; ids next to it are refused with nothing
// created and no limit recorded.
func TestEnsureRepoDir_ControlPlaneIDs(t *testing.T) {
	p := repoPaths(t)
	cp, id := nodecfg.ControlPlaneSubject, nodecfg.ControlPlaneUID
	for _, bad := range [][2]int{{0, 0}, {69, 69}, {71, 71}, {id, 0}, {0, id}, {id, 71}} {
		if err := EnsureRepoDir(p, cp, bad[0], bad[1], 16); err == nil {
			t.Errorf("ids %d:%d accepted", bad[0], bad[1])
		}
		noLimit(t, p.RepoRoot(), bad[0])
	}
	if got := entries(t, p.RepoRoot()); len(got) != 0 {
		t.Fatalf("created for refused ids: %v", got)
	}
	t.Cleanup(func() { SetQuotaAt(p.RepoRoot(), id, 0) })
	if err := EnsureRepoDir(p, cp, id, id, 16); err != nil {
		t.Fatal(err)
	}
	if u, g, m := owner(t, filepath.Join(p.RepoDir(cp), "repo")); u != 70 || g != 70 || m != os.ModeDir|0o750 {
		t.Errorf("cp repo: %d:%d %v", u, g, m)
	}
	if r := limitsAt(t, p.RepoRoot(), id); len(r) != 1 || r[0] != [2]int{16 << 10, minInodes} {
		t.Errorf("cp limits: %v", r)
	}
}

// TestEnsureRepoDir_RefusesBadInput: an invalid subject, id or quota is
// refused before anything is created (no root needed).
func TestEnsureRepoDir_RefusesBadInput(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(p.RepoRoot(), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"", ".", "..", "cp/..", "../" + testRef[3:], "CP", "abc/efghij0123456789", testRef + "\x00", testRef[:19]} {
		if err := EnsureRepoDir(p, s, 900001, 900001, 16); err == nil {
			t.Errorf("subject %q accepted", s)
		}
		if err := EnsureFetchDir(p, s, nodecfg.ReplicatorUID, 900001); err == nil {
			t.Errorf("fetch: subject %q accepted", s)
		}
		if err := RemoveEmptyRepoDirs(p, s); err == nil {
			t.Errorf("remove: subject %q accepted", s)
		}
	}
	for _, c := range [][3]int{{0, 900001, 16}, {900001, 1, 16}, {65535, 900001, 16}, {900001, 900001, 0}, {900001, 900001, -1}, {900001, 900001, 1<<30 + 1}} {
		if err := EnsureRepoDir(p, testRef, c[0], c[1], c[2]); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
	if got := entries(t, p.RepoRoot()); len(got) != 0 {
		t.Fatalf("created: %v", got)
	}
	// fetch/ ids are refused with the subject directory present.
	if err := os.Mkdir(p.RepoDir(testRef), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]int{{0, 900001}, {nodecfg.ReplicatorUID, 0}, {65531, 900001}, {nodecfg.ReplicatorUID, 69}} {
		if err := EnsureFetchDir(p, testRef, c[0], c[1]); err == nil {
			t.Errorf("fetch: %v accepted", c)
		}
	}
	if got := entries(t, p.RepoDir(testRef)); len(got) != 0 {
		t.Fatalf("fetch: created %v", got)
	}
}

// TestEnsureRepoDir_RefusesForeignOwnedRepo: a repo/ owned by another uid or
// gid, a subject directory that is not root's or that others can write, and a
// repository root that is not root's are refused untouched, with no limit set.
func TestEnsureRepoDir_RefusesForeignOwnedRepo(t *testing.T) {
	p := repoPaths(t)
	const uid, gid = 900111, 900112
	t.Cleanup(func() { SetQuotaAt(p.RepoRoot(), uid, 0) })
	subj, repo := p.RepoDir(testRef), filepath.Join(p.RepoDir(testRef), "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, o := range [][2]int{{uid + 1, gid}, {uid, gid + 1}, {uid + 1, gid + 1}} {
		if err := os.Chown(repo, o[0], o[1]); err != nil {
			t.Fatal(err)
		}
		if err := EnsureRepoDir(p, testRef, uid, gid, 16); !errors.Is(err, ErrExistsForeign) {
			t.Errorf("repo/ %d:%d: got %v", o[0], o[1], err)
		}
		if u, g, m := owner(t, repo); int(u) != o[0] || int(g) != o[1] || m.Perm() != 0o700 {
			t.Errorf("repo/ %d:%d changed: %d:%d %v", o[0], o[1], u, g, m)
		}
		noLimit(t, p.RepoRoot(), uid)
	}
	os.Chown(repo, 0, 0)
	for name, f := range map[string]func() error{
		"subject owned by the project":  func() error { return os.Chown(subj, uid, gid) },
		"subject writable by its group": func() error { return os.Chmod(subj, 0o775) },
		"subject writable by others":    func() error { return os.Chmod(subj, 0o757) },
		"root owned by the project":     func() error { return os.Chown(p.RepoRoot(), uid, gid) },
	} {
		if err := f(); err != nil {
			t.Fatal(err)
		}
		if err := EnsureRepoDir(p, testRef, uid, gid, 16); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if u, _, _ := owner(t, repo); u != 0 {
			t.Errorf("%s: repo/ chowned to %d", name, u)
		}
		noLimit(t, p.RepoRoot(), uid)
		os.Chown(subj, 0, 0)
		os.Chmod(subj, 0o755)
		os.Chown(p.RepoRoot(), 0, 0)
	}
	// Control: the same tree, rightly owned, is accepted.
	if err := EnsureRepoDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatalf("control: %v", err)
	}
	if u, g, _ := owner(t, repo); u != uid || g != gid {
		t.Errorf("control: repo/ %d:%d", u, g)
	}
}

// TestEnsureRepoDir_LinkAtRepoRefused: a link, a FIFO or a file at repo/ or
// at the subject is refused without blocking and without acting on what a
// link names.
func TestEnsureRepoDir_LinkAtRepoRefused(t *testing.T) {
	p := repoPaths(t)
	const uid, gid = 900121, 900122
	t.Cleanup(func() { SetQuotaAt(p.RepoRoot(), uid, 0) })
	canary := t.TempDir()
	os.Chmod(canary, 0o755)
	cu, cg, cm := owner(t, canary)
	subj, repo := p.RepoDir(testRef), filepath.Join(p.RepoDir(testRef), "repo")
	reset := func() {
		os.Remove(repo)
		os.Remove(subj)
	}
	for name, plant := range map[string]func() error{
		"link at repo": func() error { os.Mkdir(subj, 0o755); return os.Symlink(canary, repo) },
		"fifo at repo": func() error { os.Mkdir(subj, 0o755); return syscall.Mkfifo(repo, 0o600) },
		"file at repo": func() error { os.Mkdir(subj, 0o755); return os.WriteFile(repo, nil, 0o600) },
		"link at subject": func() error {
			return os.Symlink(canary, subj)
		},
		"fifo at subject": func() error { return syscall.Mkfifo(subj, 0o600) },
	} {
		reset()
		if err := plant(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- EnsureRepoDir(p, testRef, uid, gid, 16) }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("%s: EnsureRepoDir blocked", name)
		}
		noLimit(t, p.RepoRoot(), uid)
	}
	if u, g, m := owner(t, canary); u != cu || g != cg || m != cm {
		t.Fatalf("canary changed: %d:%d %v", u, g, m)
	}
	if ents := entries(t, canary); len(ents) != 0 {
		t.Fatalf("created in the canary: %v", ents)
	}
	// Control: the link gone, the same call succeeds.
	reset()
	if err := EnsureRepoDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// ───────── EnsureFetchDir ─────────

// TestEnsureFetchDir_RefusesAMissingRepoDir_CreatesNothing: without
// RepoDir(subject) nothing is created; with it fetch/ is the given ids'
// 2750, and a complete fetch/ is left alone.
func TestEnsureFetchDir_RefusesAMissingRepoDir_CreatesNothing(t *testing.T) {
	needRoot(t)
	p := traversablePaths(t)
	r, gid := nodecfg.ReplicatorUID, 900131
	if err := EnsureFetchDir(p, testRef, r, gid); err == nil {
		t.Fatal("accepted without the subject directory")
	}
	if got := entries(t, p.RepoRoot()); len(got) != 0 {
		t.Fatalf("created: %v", got)
	}
	// Control: with the subject directory the same call creates fetch/.
	if err := os.Mkdir(p.RepoDir(testRef), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFetchDir(p, testRef, r, gid); err != nil {
		t.Fatal(err)
	}
	fetch := filepath.Join(p.RepoDir(testRef), "fetch")
	if u, g, m := owner(t, fetch); int(u) != r || int(g) != gid || m != os.ModeDir|os.ModeSetgid|0o750 {
		t.Fatalf("fetch: %d:%d %v", u, g, m)
	}
	if err := os.Chmod(fetch, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFetchDir(p, testRef, r, gid); err != nil {
		t.Fatal(err)
	}
	if _, _, m := owner(t, fetch); m != os.ModeDir|0o700 {
		t.Errorf("a complete fetch/ touched: %v", m)
	}
	// A foreign fetch/, a link at it and a root-owned one left by an
	// interrupted call.
	if err := os.Chown(fetch, r, gid+1); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFetchDir(p, testRef, r, gid); !errors.Is(err, ErrExistsForeign) {
		t.Errorf("foreign fetch/: got %v", err)
	}
	os.Remove(fetch)
	canary := t.TempDir()
	os.Symlink(canary, fetch)
	if err := EnsureFetchDir(p, testRef, r, gid); err == nil {
		t.Error("link at fetch/ accepted")
	}
	if u, _, m := owner(t, canary); u != 0 || m&os.ModeSetgid != 0 {
		t.Errorf("canary changed: %d %v", u, m)
	}
	os.Remove(fetch)
	os.Mkdir(fetch, 0o700)
	if err := EnsureFetchDir(p, testRef, r, gid); err != nil {
		t.Fatal(err)
	}
	if u, g, m := owner(t, fetch); int(u) != r || int(g) != gid || m != os.ModeDir|os.ModeSetgid|0o750 {
		t.Fatalf("resumed fetch: %d:%d %v", u, g, m)
	}
}

// ───────── RemoveEmptyRepoDirs ─────────

// TestRemoveEmptyRepoDirs_NonEmptyFails: a non-empty repo/ or fetch/, or a
// link in place of one, fails and is left; emptied, the same call removes
// all three directories.
func TestRemoveEmptyRepoDirs_NonEmptyFails(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	subj := p.RepoDir(testRef)
	repo, fetch := filepath.Join(subj, "repo"), filepath.Join(subj, "fetch")
	for _, d := range []string{repo, fetch} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{subj, p.RepoRoot()} {
		os.Chmod(d, 0o755)
	}
	for _, f := range []string{filepath.Join(repo, "f"), filepath.Join(fetch, "f")} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := RemoveEmptyRepoDirs(p, testRef); err == nil {
			t.Errorf("%s: removed a non-empty tree", f)
		}
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		os.Remove(f)
	}
	canary := t.TempDir()
	os.Remove(fetch)
	os.Symlink(canary, fetch)
	if err := RemoveEmptyRepoDirs(p, testRef); err == nil {
		t.Error("a link at fetch/ was accepted")
	}
	if fi, err := os.Lstat(fetch); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("link at fetch/ removed: %v", err)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Errorf("canary: %v", err)
	}
	os.Remove(fetch)
	// A link at the subject is not followed (repo/ went with the call above:
	// each directory is removed on its own).
	os.Mkdir(repo, 0o755)
	os.Rename(subj, subj+".real")
	os.Symlink(subj+".real", subj)
	if err := RemoveEmptyRepoDirs(p, testRef); err == nil {
		t.Error("a link at the subject was accepted")
	}
	if _, err := os.Stat(filepath.Join(subj+".real", "repo")); err != nil {
		t.Errorf("repo/ behind the link removed: %v", err)
	}
	os.Remove(subj)
	os.Rename(subj+".real", subj)
	// Control: empty, the same call removes the tree.
	if err := RemoveEmptyRepoDirs(p, testRef); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(subj); !os.IsNotExist(err) {
		t.Errorf("subject left: %v", err)
	}
}

// TestRemoveEmptyRepoDirs_AbsentIsDone: each absent directory is done.
func TestRemoveEmptyRepoDirs_AbsentIsDone(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(p.RepoRoot(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEmptyRepoDirs(p, testRef); err != nil {
		t.Fatalf("nothing there: %v", err)
	}
	for _, sub := range []string{"", "repo", "fetch"} {
		if err := os.MkdirAll(filepath.Join(p.RepoDir(nodecfg.ControlPlaneSubject), sub), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := RemoveEmptyRepoDirs(p, nodecfg.ControlPlaneSubject); err != nil {
			t.Fatalf("%q only: %v", sub, err)
		}
		if got := entries(t, p.RepoRoot()); len(got) != 0 {
			t.Fatalf("%q only: left %v", sub, got)
		}
	}
	// The repository root itself must be trusted, absent or not.
	if err := os.Chmod(p.RepoRoot(), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEmptyRepoDirs(p, testRef); err == nil {
		t.Error("a repository root others can write was accepted")
	}
}

// ───────── quotas ─────────

// TestQuotaUsage_Parses: used blocks and the block hard limit of the id's
// one record, in KiB, read with the C locale for the id and the mount given;
// no record is 0, 0; anything else, and any id SetQuotaAt refuses, is an
// error.
func TestQuotaUsage_Parses(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	const rec = `/dev/x 2411724 0 1048576 00 [--------] 1220 0 262144 00 [--------] /m`
	for name, tc := range map[string]struct {
		out        string
		used, hard int64
		ok         bool
	}{
		"one record":  {rec, 2411724, 1048576, true},
		"no limit":    {"/dev/x 12 0 0 00 [--------] 3 0 0 00 [--------] /m", 12, 0, true},
		"wrapped":     {"/dev/mapper/vg0-repo\\n  2411724 0 1048576 00 [--------] 1220 0 262144 00 [--------] /m", 2411724, 1048576, true},
		"no record":   {"", 0, 0, true},
		"two records": {rec + `\n` + rec, 0, 0, false},
		"garbage":     {"/dev/x 1 0 lots 00 [--------] 1220 0 262144 00 [--------] /m", 0, 0, false},
		"short":       {"/dev/x 1 0 1048576 00 [--------] /m", 0, 0, false},
		"negative":    {"/dev/x -1 0 1048576 00 [--------] 1220 0 262144 00 [--------] /m", 0, 0, false},
	} {
		for _, id := range []int{nodecfg.ControlPlaneUID, nodecfg.ReplicatorUID, 900042} {
			script := fmt.Sprintf("#!/bin/sh\n[ \"$LC_ALL\" = C ] || exit 1\n"+
				"[ \"$1 $2 $3 $4\" = \"-x -c quota -v -N -b -i -u %d /srv/repo\" ] || { echo bad \"$*\" >&2; exit 0; }\nprintf '%s\\n'\n", id, tc.out)
			if err := os.WriteFile(filepath.Join(bin, "xfs_quota"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			u, h, err := QuotaUsage(context.Background(), "/srv/repo", id)
			if tc.ok && (err != nil || u != tc.used || h != tc.hard) || !tc.ok && err == nil {
				t.Errorf("%s, id %d: %d %d %v", name, id, u, h, err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "xfs_quota"), []byte("#!/bin/sh\necho 'xfs_quota: no such mount' >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := QuotaUsage(context.Background(), "/srv/repo", 900042); err == nil {
		t.Error("error output trusted")
	}
	called := filepath.Join(t.TempDir(), "called")
	if err := os.WriteFile(filepath.Join(bin, "xfs_quota"), []byte("#!/bin/sh\ntouch "+called+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int{0, 1, 69, 71, 65529, 65531, 65535, 1 << 31} {
		if _, _, err := QuotaUsage(context.Background(), "/srv/repo", id); err == nil {
			t.Errorf("id %d accepted", id)
		}
	}
	if _, _, err := QuotaUsage(context.Background(), "srv/repo", 900042); err == nil {
		t.Error("a relative mount accepted")
	}
	if _, err := os.Stat(called); err == nil {
		t.Error("xfs_quota ran for a refused call")
	}
}

// TestSetQuotaAt_PlatformIDs: 70 and 65530 and a project id are accepted on
// a quota mount and read back; 0 and the ids next to the platform ids are
// refused before anything runs and record no limit. SetQuota still refuses
// the platform ids.
func TestSetQuotaAt_PlatformIDs(t *testing.T) {
	refused := []int{0, 1, 69, 71, 65529, 65531, 65535}
	bin := t.TempDir()
	called := filepath.Join(t.TempDir(), "called")
	if err := os.WriteFile(filepath.Join(bin, "xfs_quota"), []byte("#!/bin/sh\ntouch "+called+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	func() {
		old := os.Getenv("PATH")
		os.Setenv("PATH", bin+":"+old)
		defer os.Setenv("PATH", old)
		for _, id := range refused {
			if err := SetQuotaAt(t.TempDir(), id, 16); err == nil {
				t.Errorf("id %d accepted", id)
			}
		}
		if _, err := os.Stat(called); err == nil {
			t.Error("xfs_quota ran for a refused id")
		}
	}()

	p := repoPaths(t)
	mount := p.RepoRoot()
	accepted := []int{nodecfg.ControlPlaneUID, nodecfg.ReplicatorUID, 900141}
	for _, id := range append(accepted, refused...) {
		t.Cleanup(func() {
			exec.Command("xfs_quota", "-x", "-c", fmt.Sprintf("limit -u bhard=0 ihard=0 %d", id), mount).Run()
		})
	}
	for _, id := range accepted {
		if err := SetQuotaAt(mount, id, 16); err != nil {
			t.Errorf("id %d: %v", id, err)
		}
		if r := limitsAt(t, mount, id); len(r) != 1 || r[0] != [2]int{16 << 10, minInodes} {
			t.Errorf("id %d: limits %v", id, r)
		}
		if _, h, err := QuotaUsage(context.Background(), mount, id); err != nil || h != 16<<10 {
			t.Errorf("id %d: usage reads %d %v", id, h, err)
		}
	}
	for _, id := range refused {
		if err := SetQuotaAt(mount, id, 16); err == nil {
			t.Errorf("id %d accepted on a quota mount", id)
		}
		noLimit(t, mount, id)
	}
	// SetQuota is unchanged: on a quota mount as its projects filesystem it
	// refuses the platform ids and takes a project id.
	if err := os.MkdirAll(p.ProjectsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := mountScratchXFS(t, p.ProjectsDir(), "usrquota"); err != nil {
		t.Fatal(err)
	}
	for _, id := range accepted[:2] {
		if err := SetQuota(p, id, 16); err == nil {
			t.Errorf("SetQuota accepted id %d", id)
		}
		noLimit(t, p.ProjectsDir(), id)
	}
	if err := SetQuota(p, accepted[2], 16); err != nil {
		t.Errorf("SetQuota, project id: %v", err)
	}
}

// TestQuotaUsage_HungToolEndsWithContext: a quota tool that never returns (a
// stalled filesystem) is killed with what it started when the caller's
// context ends; QuotaUsage returns promptly with the context's error.
func TestQuotaUsage_HungToolEndsWithContext(t *testing.T) {
	bin, pids := t.TempDir(), filepath.Join(t.TempDir(), "pids")
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	script := "#!/bin/sh\nsleep 600 &\necho $$ $! > " + pids + "\nwait\n"
	if err := os.WriteFile(filepath.Join(bin, "xfs_quota"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if _, _, err := QuotaUsage(ctx, "/srv/repo", nodecfg.ReplicatorUID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want the context's error", err)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("QuotaUsage returned after %v", d)
	}
	b, err := os.ReadFile(pids)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range strings.Fields(string(b)) {
		pid, err := strconv.Atoi(f)
		if err != nil {
			t.Fatal(err)
		}
		// The orphaned child is reaped by init shortly after its kill.
		deadline := time.Now().Add(5 * time.Second)
		for syscall.Kill(pid, 0) == nil {
			if time.Now().After(deadline) {
				syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("process %d left running", pid)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Control: the same stand-in answering at once gives a usage.
	if err := os.WriteFile(filepath.Join(bin, "xfs_quota"), []byte("#!/bin/sh\necho '/dev/x 8 0 16 00 [--------] 1 0 9 00 [--------] /m'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if u, h, err := QuotaUsage(context.Background(), "/srv/repo", nodecfg.ReplicatorUID); err != nil || u != 8 || h != 16 {
		t.Fatalf("control: %d %d %v", u, h, err)
	}
}

// TestRemoveEmptyFetchDir_LeavesRepo: an empty fetch/ is removed while repo/
// and the subject directory stay; a non-empty one, or anything but a
// directory at fetch, fails with everything left as it was and nothing
// followed; an absent fetch/ or subject is done, an absent repository root is
// an error.
func TestRemoveEmptyFetchDir_LeavesRepo(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	subj := p.RepoDir(testRef)
	repo, fetch := filepath.Join(subj, "repo"), filepath.Join(subj, "fetch")
	if err := RemoveEmptyFetchDir(p, testRef); err == nil {
		t.Error("an absent repository root was accepted")
	}
	if err := os.MkdirAll(p.RepoRoot(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEmptyFetchDir(p, testRef); err != nil {
		t.Fatalf("absent subject: %v", err)
	}
	for _, d := range []string{repo, fetch} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.Chmod(subj, 0o755)
	if err := os.WriteFile(filepath.Join(fetch, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEmptyFetchDir(p, testRef); err == nil {
		t.Error("a non-empty fetch/ was removed")
	}
	if _, err := os.Stat(filepath.Join(fetch, "f")); err != nil {
		t.Errorf("fetch/f: %v", err)
	}
	os.Remove(filepath.Join(fetch, "f"))
	if err := RemoveEmptyFetchDir(p, testRef); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(fetch); !os.IsNotExist(err) {
		t.Errorf("fetch/ left: %v", err)
	}
	if got := strings.Join(entries(t, subj), " "); got != "repo" {
		t.Errorf("subject entries: %q", got)
	}
	if err := RemoveEmptyFetchDir(p, testRef); err != nil {
		t.Fatalf("absent fetch/: %v", err)
	}
	canary := t.TempDir()
	for name, plant := range map[string]func() error{
		"link": func() error { return os.Symlink(canary, fetch) },
		"fifo": func() error { return syscall.Mkfifo(fetch, 0o600) },
		"file": func() error { return os.WriteFile(fetch, nil, 0o600) },
	} {
		if err := plant(); err != nil {
			t.Fatal(err)
		}
		if err := RemoveEmptyFetchDir(p, testRef); err == nil {
			t.Errorf("%s at fetch: accepted", name)
		}
		if _, err := os.Lstat(fetch); err != nil {
			t.Errorf("%s at fetch removed: %v", name, err)
		}
		os.Remove(fetch)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Errorf("canary: %v", err)
	}
	if got := strings.Join(entries(t, subj), " "); got != "repo" {
		t.Errorf("subject entries at the end: %q", got)
	}
	// A subject holding only fetch/ keeps its directory.
	if err := os.Remove(repo); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fetch, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEmptyFetchDir(p, testRef); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(subj); err != nil || !fi.IsDir() {
		t.Errorf("subject directory removed: %v", err)
	}
}
