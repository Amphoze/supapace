package dashpush

import (
	"os"
	"path/filepath"
	"testing"
)

// Only the writer's own temporary names go: another writer's temporary file in
// the same directory, and the file's own name without the suffix, stay.
func TestPush_LeftoverRemovalKeepsOtherNames(t *testing.T) {
	p, path := pushEnv(t, &fakeSource{tbl: pushTable()})
	dir := filepath.Dir(path)
	keep := []string{".routes.json.tmp-0123", ".dashboard.json", "dashboard.json-1"}
	for _, n := range keep {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("kept"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pushOK(t, p)
	for _, n := range keep {
		if _, err := os.Lstat(filepath.Join(dir, n)); err != nil {
			t.Fatalf("%s was removed: %v", n, err)
		}
	}
}

// A directory of the writer's temporary form that cannot be removed does not
// stop the push, and what it holds is not removed.
func TestPush_LeftoverDirectoryDoesNotBlock(t *testing.T) {
	p, path := pushEnv(t, &fakeSource{tbl: pushTable()})
	d := filepath.Join(filepath.Dir(path), tempPrefix+"dir")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "x"), []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	pushOK(t, p)
	if _, err := os.Stat(filepath.Join(d, "x")); err != nil {
		t.Fatalf("the directory's content was removed: %v", err)
	}
	pushRead(t, path)
}
