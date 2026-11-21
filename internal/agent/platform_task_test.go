package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A removal task that fails is an error of the preparation: a re-run never
// goes on to a restore over a repository that still holds the first run's
// files.
func TestPrepareControlPlaneRestore_FailedRemovalTaskIsAnError(t *testing.T) {
	a, f, _ := cpSetup(t)
	cpMark(t, a)
	repo := filepath.Join(a.p.RepoDir("cp"), "repo")
	mkdirs(t, filepath.Join(repo, "archive", "cp-1"))
	os.WriteFile(filepath.Join(repo, "archive", "cp-1", "archive.info"), []byte("first run"), 0o640)
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if !strings.HasPrefix(clLast(args), "task-cp-purge-") {
			return "", nil, false
		}
		switch args[0] {
		case "inspect":
			return "exited 3\n", nil, true
		case "logs":
			return "", nil, true
		}
		return "", nil, false
	}
	err := a.PrepareControlPlaneRestore(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exit 3") {
		t.Fatalf("got %v, want the task's failure", err)
	}
	if _, err := os.Lstat(a.p.CPRestoring()); err != nil {
		t.Fatalf("marker after the failure: %v", err)
	}
}
