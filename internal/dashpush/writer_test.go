package dashpush

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A link at the path is neither read through nor written through: the push
// replaces the link itself and leaves its target as it was.
func TestPush_LinkAtThePathIsReplaced(t *testing.T) {
	p, path := pushEnv(t, &fakeSource{tbl: pushTable()})
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, in, err := p.InForce(context.Background()); in || err != nil {
		t.Fatalf("a link is in force: %v %v", in, err)
	}
	pushOK(t, p)
	if b, _ := os.ReadFile(target); string(b) != "untouched" {
		t.Fatalf("the link's target was written: %q", b)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the path is not a regular file after the push: %v %v", fi, err)
	}
	pushRead(t, path)
}

// Two pushes at once from one pusher: each returns a generation that is on
// disk or was replaced by a later one, and the file ends as the last snapshot.
func TestPush_ConcurrentPushesEndOnTheLastSnapshot(t *testing.T) {
	src := &fakeSource{tbl: pushTable()}
	p, path := pushEnv(t, src)
	done := make(chan int64, 8)
	for range 8 {
		go func() { g, _ := p.Push(context.Background()); done <- g }()
	}
	var top int64
	for range 8 {
		top = max(top, <-done)
	}
	tbl := pushTable()
	tbl.Projects = tbl.Projects[:1]
	src.set(tbl)
	g := pushOK(t, p)
	if g <= top {
		t.Fatalf("generation %d after %d", g, top)
	}
	if f := pushRead(t, path); len(f.Projects) != 1 || f.Generation != g {
		t.Fatalf("file %d projects, generation %d", len(f.Projects), f.Generation)
	}
}

// A FIFO at the path with no writer: a blocking open would wait for one.
func TestPush_FIFOWithoutWriterDoesNotHold(t *testing.T) {
	p, path := pushEnv(t, &fakeSource{tbl: pushTable()})
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := p.Push(context.Background()); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Minute):
		// Unblock the open so the goroutine ends, then fail.
		if w, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		t.Fatal("a FIFO without a writer held the push")
	}
	pushRead(t, path)
}

// A push that cannot put its file in place leaves no temporary file behind.
func TestPush_FailedRenameLeavesNoTemporaryFile(t *testing.T) {
	p, path := pushEnv(t, &fakeSource{tbl: pushTable()})
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Push(context.Background()); err == nil {
		t.Fatal("a push over a directory succeeded")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Fatalf("left behind: %s", e.Name())
		}
	}
}

// Temporary files a stopped push left in the directory are removed by the
// next push: only names of the writer's own form, and a link of that form is
// removed itself, its target left alone.
func TestPush_RemovesLeftoverTemporaryFiles(t *testing.T) {
	p, path := pushEnv(t, &fakeSource{tbl: pushTable()})
	dir := filepath.Dir(path)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{tempPrefix + "123", tempPrefix + "456"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("partial"), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(target, filepath.Join(dir, tempPrefix+"link")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.json")
	if err := os.WriteFile(other, []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	pushOK(t, p)
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 2 || names[0] != filepath.Base(path) || names[1] != "other.json" {
		t.Fatalf("directory holds %v", names)
	}
	if b, _ := os.ReadFile(target); string(b) != "untouched" {
		t.Fatalf("a link's target was touched: %q", b)
	}
}
