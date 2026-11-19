package nodefs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// TestEnsureRepoDir_QuotaFailureHandsNothingOver: when the repository quota
// cannot be set, repo/ stays root's: the project is never given a directory
// it could write without a limit. With enforcement back, the same call
// completes it.
func TestEnsureRepoDir_QuotaFailureHandsNothingOver(t *testing.T) {
	p := repoPaths(t)
	const uid, gid = 900301, 900302
	t.Cleanup(func() { SetQuotaAt(p.RepoRoot(), uid, 0) })
	xq := func(c string) {
		if out, err := exec.Command("xfs_quota", "-x", "-c", c, p.RepoRoot()).CombinedOutput(); err != nil || len(out) > 0 {
			t.Fatalf("%s: %v %s", c, err, out)
		}
	}
	xq("disable -u")
	if err := EnsureRepoDir(p, testRef, uid, gid, 16); !errors.Is(err, errQuotaNotEnforced) {
		t.Fatalf("unenforced quota: got %v", err)
	}
	repo := filepath.Join(p.RepoDir(testRef), "repo")
	if u, g, _ := owner(t, repo); u != 0 || g != 0 {
		t.Fatalf("repo/ handed over without its quota: %d:%d", u, g)
	}
	xq("enable -u")
	if err := EnsureRepoDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	if u, g, m := owner(t, repo); u != uid || g != gid || m != os.ModeDir|0o750 {
		t.Errorf("resumed repo/: %d:%d %v", u, g, m)
	}
}

// TestEnsureRepoDir_TenantCannotPlantInSubject: the premise of leaving a
// complete repo/ as it is — the project uid can create, replace or rename
// nothing in its subject directory, only inside repo/.
func TestEnsureRepoDir_TenantCannotPlantInSubject(t *testing.T) {
	p := repoPaths(t)
	const uid, gid = 900311, 900312
	t.Cleanup(func() { SetQuotaAt(p.RepoRoot(), uid, 0) })
	if err := EnsureRepoDir(p, testRef, uid, gid, 16); err != nil {
		t.Fatal(err)
	}
	subj := p.RepoDir(testRef)
	for _, d := range []string{"fetch", "repo/../x"} {
		if out, code := runTenant(t, uid, gid, "touch", filepath.Join(subj, d), "0"); code == 0 {
			t.Errorf("tenant created %s in the subject directory: %s", d, out)
		}
	}
	if out, code := runTenant(t, uid, gid, "touch", filepath.Join(subj, "repo", "d"), "1"); code != 0 {
		t.Fatalf("control: tenant cannot write its repo/: exit %d: %s", code, out)
	}
	if got := entries(t, subj); len(got) != 1 || got[0] != "repo" {
		t.Errorf("subject entries: %v", got)
	}
}

// TestRemoveEmptyRepoDirs_StrayEntryFails: a subject directory that still
// holds anything besides repo/ and fetch/ is not removed and the call fails:
// only an absent directory is done.
func TestRemoveEmptyRepoDirs_StrayEntryFails(t *testing.T) {
	p := nodecfg.Paths{Root: t.TempDir()}
	subj := p.RepoDir(testRef)
	if err := os.MkdirAll(filepath.Join(subj, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{subj, p.RepoRoot()} {
		os.Chmod(d, 0o755)
	}
	if err := os.WriteFile(filepath.Join(subj, "stray"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveEmptyRepoDirs(p, testRef); err == nil {
		t.Error("a subject directory with a stray entry reported removed")
	}
	if _, err := os.Stat(filepath.Join(subj, "stray")); err != nil {
		t.Errorf("stray entry: %v", err)
	}
}

// TestQuotaUsage_EndedContextStartsNothing: with the caller's context
// already ended, the quota tool is not started and the error is the
// context's.
func TestQuotaUsage_EndedContextStartsNothing(t *testing.T) {
	bin, called := t.TempDir(), filepath.Join(t.TempDir(), "called")
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	if err := os.WriteFile(filepath.Join(bin, "xfs_quota"), []byte("#!/bin/sh\ntouch "+called+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := QuotaUsage(ctx, "/srv/repo", nodecfg.ReplicatorUID); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want the context's error", err)
	}
	if _, err := os.Stat(called); err == nil {
		t.Error("the quota tool ran with an ended context")
	}
}

// TestRemoveEmptyFetchDir_MountPointLeft: a fetch/ that is a mount point is
// refused and stays mounted.
func TestRemoveEmptyFetchDir_MountPointLeft(t *testing.T) {
	needRoot(t)
	p := nodecfg.Paths{Root: t.TempDir()}
	fetch := filepath.Join(p.RepoDir(testRef), "fetch")
	if err := os.MkdirAll(fetch, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{p.RepoDir(testRef), p.RepoRoot()} {
		os.Chmod(d, 0o755)
	}
	if err := syscall.Mount("tmpfs", fetch, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Unmount(fetch, syscall.MNT_DETACH) })
	if err := RemoveEmptyFetchDir(p, testRef); err == nil {
		t.Error("a mount point at fetch/ was removed")
	}
	var a, b syscall.Stat_t
	if err := syscall.Stat(fetch, &a); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat(p.RepoDir(testRef), &b); err != nil {
		t.Fatal(err)
	}
	if a.Dev == b.Dev {
		t.Error("fetch/ no longer a mount point")
	}
}
