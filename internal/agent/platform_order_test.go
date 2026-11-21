package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// The old tree renamed and the copy not yet switched in, with a container
// of the database's name present: it is stopped and removed before the copy
// becomes the data directory.
func TestEnsureCP_Move_FinishRemovesAContainerFirst(t *testing.T) {
	a, f, _ := cpSetup(t)
	mkdirs(t, a.p.CPDir(), a.p.CPProjectDir())
	os.Chmod(a.p.CPDir(), 0o700)
	os.Chmod(a.p.CPProjectDir(), 0o700)
	part, data := filepath.Join(a.p.CPProjectDir(), "data.part"), filepath.Join(a.p.CPProjectDir(), "data")
	cpTree(t, filepath.Join(a.p.CPDir(), "data.moved"))
	want := cpTree(t, part)
	f.ctr(fakeCtr{Name: cpName, Running: true, Restart: "unless-stopped", Labels: map[string]string{labelRole: "cp-db"}})
	f.resetLog()
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := f.calls()
	stop := slices.Index(calls, "docker stop -t 30 -- sp-cp-db")
	rm := slices.Index(calls, "docker rm -- sp-cp-db")
	rename := slices.Index(calls, "rename "+part+" "+data)
	if stop < 0 || rm < stop || rename < rm {
		t.Fatalf("stop %d, rm %d, rename %d in %q", stop, rm, rename, calls)
	}
	if got := tree(t, data); len(got) != len(want) {
		t.Fatalf("data directory after the switch: %v", got)
	}
}

// On a node where the database was never started by this build (a restore
// on a new node): the recovery start writes the archive binary its commands
// run, replaces an earlier recovery start, and carries its own role label.
func TestEnsureCPRecovery_ReplacesAnEarlierStartAndWritesTheArchiveBinary(t *testing.T) {
	a, f, _ := cpSetup(t)
	ctx := context.Background()
	if err := a.PrepareControlPlaneRestore(ctx); err != nil {
		t.Fatal(err)
	}
	tools := filepath.Join(a.p.ToolsDir(), archBinary)
	if _, err := os.Lstat(tools); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixture: the archive binary is there before the recovery start: %v", err)
	}
	f.ctr(fakeCtr{Name: cpRecoveryName, Running: true, Labels: map[string]string{labelRole: "cp-recovery"}})
	f.resetLog()
	if err := a.EnsureControlPlaneRecovery(ctx, cpTarget); err != nil {
		t.Fatal(err)
	}
	m := f.mutations()
	if len(m) != 3 || m[0] != "docker stop -t 30 -- sp-cp-recovery" || m[1] != "docker rm -- sp-cp-recovery" || !strings.HasPrefix(m[2], "docker run ") {
		t.Fatalf("mutations %q", m)
	}
	if fi, err := os.Lstat(tools); err != nil || fi.Mode().Perm() != 0o555 {
		t.Fatalf("archive binary after the recovery start: %v %v", fi, err)
	}
	if labels := flagValues(cpRun(t, f, cpRecoveryName), "--label"); !slices.Contains(labels, labelRole+"=cp-recovery") {
		t.Fatalf("labels %q", labels)
	}
}

// The marker is written before any tree is touched: a preparation that
// fails later leaves a marked node, never an unmarked one with trees that
// may already be emptied.
func TestPrepareControlPlaneRestore_MarkerBeforeTheTrees(t *testing.T) {
	a, _, _ := cpSetup(t)
	boom := errors.New("not enforced")
	defer swap(&ensureRepoDir, func(nodecfg.Paths, string, int, int, int) error { return boom })()
	if err := a.PrepareControlPlaneRestore(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Lstat(a.p.CPRestoring()); err != nil {
		t.Fatalf("no marker after a failed preparation: %v", err)
	}
}

// The marker goes last: while fetch/ cannot be removed the node stays marked.
func TestFinishControlPlaneRestore_MarkerStaysUntilFetchIsGone(t *testing.T) {
	a, _, _ := cpSetup(t)
	cpMark(t, a)
	fetch := filepath.Join(a.p.RepoDir("cp"), "fetch")
	mkdirs(t, fetch)
	boom := errors.New("busy")
	defer swap(&removeEmptyFetchDir, func(nodecfg.Paths, string) error { return boom })()
	if err := a.FinishControlPlaneRestore(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Lstat(a.p.CPRestoring()); err != nil {
		t.Fatalf("marker removed although fetch/ is still there: %v", err)
	}
}

// A first preparation (no marker yet) finds a repository on the node: that
// may be the only copy of the newest archive, so it is refused and nothing
// is emptied — as for a database at the data path. Only a re-run, with the
// marker already there, starts from emptied trees.
func TestPrepareControlPlaneRestore_FirstRunRefusesAPopulatedRepository(t *testing.T) {
	a, _, _ := cpSetup(t)
	repo := filepath.Join(a.p.RepoDir("cp"), "repo")
	mkdirs(t, filepath.Join(repo, "archive", "cp-1"))
	os.WriteFile(filepath.Join(repo, "archive", "cp-1", "archive.info"), []byte("the node's own repository"), 0o640)
	before := tree(t, repo)
	if err := a.PrepareControlPlaneRestore(context.Background()); err == nil {
		t.Error("prepared over a repository without the marker")
	}
	if after := tree(t, repo); len(after) != len(before) {
		t.Errorf("the repository was emptied on a first run: %v", after)
	}
	if _, err := os.Lstat(a.p.CPRestoring()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("marker after the refusal: %v", err)
	}
}

// A database still at the older data path and no marker: a restore prepared
// beside it would leave two data directories, which the next ensure refuses
// for good. Refused here, nothing written.
func TestPrepareControlPlaneRestore_RefusesADatabaseAtTheOlderPath(t *testing.T) {
	a, _, _ := cpSetup(t)
	ctx := context.Background()
	mkdirs(t, a.p.CPDir())
	os.Chmod(a.p.CPDir(), 0o700)
	cpTree(t, filepath.Join(a.p.CPDir(), "data"))
	err := a.PrepareControlPlaneRestore(ctx)
	if err == nil {
		t.Error("prepared beside a database at the older path")
		// What follows today: the restore finishes, and the database can
		// never be started.
		if err := a.FinishControlPlaneRestore(ctx); err != nil {
			t.Fatal(err)
		}
		if err := a.EnsureControlPlaneDB(ctx); err == nil {
			t.Fatal("control: the ensure after such a restore was expected to refuse")
		} else {
			t.Logf("the ensure after the restore: %v", err)
		}
		return
	}
	if _, err := os.Lstat(a.p.CPRestoring()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("marker after the refusal: %v", err)
	}
}
