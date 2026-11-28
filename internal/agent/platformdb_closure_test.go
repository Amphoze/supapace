package agent

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/poolcfg"
)

// The short bound is the time waited, not only the text of the error: a
// container found running that never answers returns the caller long before
// the long bound.
func TestPlatformDB_ShortBoundIsTheTimeWaited(t *testing.T) {
	a, _, pf, _ := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(swap(&pdbShortWait, 30*time.Millisecond))
	t.Cleanup(swap(&pdbAnswerWait, 30*time.Second))
	pf.err = func(int) error { return errPDBNotUp }
	start := time.Now()
	err := a.EnsurePlatformDB(ctx)
	if el := time.Since(start); err == nil || el > 10*time.Second {
		t.Fatalf("found running, never answers: %v after %v, want an error within the short bound", err, el)
	}
}

// A container this call made again (another configuration) may still be
// starting: it gets the long bound, as one made for the first time.
func TestPlatformDB_AContainerMadeAgainGetsTheLongBound(t *testing.T) {
	a, f, pf, _ := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(swap(&pdbShortWait, 30*time.Millisecond))
	t.Cleanup(swap(&pdbAnswerWait, 300*time.Millisecond))
	pf.err = func(int) error { return errPDBNotUp }
	f.ctrs[poolcfg.PlatformDBName].Labels[labelConfig] = "other"
	if err := a.EnsurePlatformDB(ctx); err == nil || !strings.Contains(err.Error(), "did not answer within 300ms") {
		t.Fatalf("made again: %v, want the long bound", err)
	}
}

// A stamp that cannot be removed stops the repair before anything is
// touched: with it left in place an interrupted initialisation would read as
// a database again.
func TestPlatformDB_StampThatCannotBeRemovedStopsTheRepair(t *testing.T) {
	a, f, _, _ := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	pd := pdbDirOf(a)
	stamp, version := filepath.Join(pd, "initialised"), filepath.Join(pd, "data", "PG_VERSION")
	if err := os.Remove(stamp); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(stamp, "kept"), 0o700); err != nil { // Remove fails on it
		t.Fatal(err)
	}
	keep := filepath.Join(pd, "data", "kept")
	os.Remove(version)
	os.WriteFile(keep, nil, 0o600)
	f.resetLog()
	if err := a.EnsurePlatformDB(ctx); err == nil {
		t.Fatal("the repair went on although the stamp could not be removed")
	}
	if m := f.mutations(); len(m) != 0 {
		t.Errorf("docker changes: %q", m)
	}
	if _, err := os.Lstat(keep); err != nil {
		t.Errorf("the data directory was emptied: %v", err)
	}
}

// At the moment the secret is given its name it is whole, root 0600 and lies
// in the secrets directory itself; a second call makes nothing; and when
// another maker's file already has the name — even one that is not a secret —
// it is refused as found, never replaced, and nothing is left beside it.
func TestPlatformDB_SecretIsWholeWhenPlaced(t *testing.T) {
	a, _, _, _ := pdbNode(t)
	dir, p := a.p.PoolerSecrets(), metaPasswordPath(a)
	links := 0
	restore := swap(&linkSecret, func(from, to string) error {
		links++
		fi, err := os.Lstat(from)
		b, rerr := os.ReadFile(from)
		if err != nil || rerr != nil || filepath.Dir(from) != dir || to != p || fi.Mode() != 0o600 || !metaPasswordRE.Match(b) {
			t.Errorf("placed from %s to %s: mode %v, %d bytes (%v, %v); want a whole 0600 file in %s", from, to, fi.Mode(), len(b), err, rerr, dir)
		}
		if _, err := os.Lstat(to); err == nil {
			t.Errorf("the name held a file before it was placed")
		}
		return os.Link(from, to)
	})
	pw, err := a.metaPassword()
	if err != nil || links != 1 {
		t.Fatalf("first call: %v, %d placings", err, links)
	}
	if again, err := a.metaPassword(); err != nil || again != pw || links != 1 {
		t.Fatalf("second call: %v, same value %v, %d placings", err, again == pw, links)
	}
	restore()

	// Another maker won with a file that is no secret.
	os.Remove(p)
	t.Cleanup(swap(&linkSecret, func(string, string) error {
		if err := os.WriteFile(p, []byte("short"), 0o600); err != nil {
			t.Error(err)
		}
		return fs.ErrExist
	}))
	got, err := a.metaPassword()
	if err == nil || got != "" || !strings.Contains(err.Error(), "not 64 hexadecimal characters") {
		t.Fatalf("another maker's short file: %q %v, want it refused", got, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "short" {
		t.Errorf("the other maker's file was replaced: %q", b)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("left in the directory: %v", ents)
	}
}
