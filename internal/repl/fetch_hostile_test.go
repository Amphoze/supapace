package repl

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/s3x"
)

// Every directory of a target is opened from its parent's descriptor, never
// through a link: a link at any level, or a file where a directory belongs,
// stops the fetch, and nothing is written outside the destination.
func TestFetch_ALinkAtAnyDirectoryLevelIsNeverFollowed(t *testing.T) {
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	plan := func() io.Reader { return planOf(t, row(f, seg(1, 1), "segment 1/1")) }
	parts := strings.Split(seg(1, 1), "/")
	for level := 1; level < len(parts); level++ {
		for _, kind := range []string{"link", "file"} {
			dest, outside := t.TempDir(), t.TempDir()
			at := filepath.Join(dest, filepath.Join(parts[:level]...))
			os.MkdirAll(filepath.Dir(at), 0o755)
			if kind == "link" {
				os.Symlink(outside, at)
			} else {
				os.WriteFile(at, []byte("x"), 0o644)
			}
			if _, err := Fetch(context.Background(), fetchIn(), plan(), dest, f); !errors.Is(err, ErrPath) {
				t.Errorf("a %s at %s: %v", kind, strings.Join(parts[:level], "/"), err)
			}
			if ents, _ := os.ReadDir(outside); len(ents) != 0 {
				t.Errorf("a %s at level %d: written outside", kind, level)
			}
		}
	}
}

// A directory swapped for a link while a file of it is written: that file
// goes on through its open directory (still inside the destination), and the
// next file of the directory is refused at the link.
func TestFetch_ADirectorySwappedForALinkMidFetchIsNeverEntered(t *testing.T) {
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	put(f, f.putKey(seg(1, 2)), "segment 1/2")
	dest, outside := t.TempDir(), t.TempDir()
	old := fileWrite
	swapped := false
	fileWrite = func(file *os.File, b []byte) (int, error) {
		if !swapped {
			swapped = true
			d := filepath.Join(dest, filepath.Dir(seg(1, 1)))
			os.Rename(d, d+".moved")
			os.Symlink(outside, d)
		}
		return old(file, b)
	}
	defer func() { fileWrite = old }()
	_, err := Fetch(context.Background(), fetchIn(), planOf(t, row(f, seg(1, 1), "segment 1/1"), row(f, seg(1, 2), "segment 1/2")), dest, f)
	if !swapped || !errors.Is(err, ErrPath) {
		t.Fatalf("swapped %v: %v", swapped, err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("written outside: %v", ents)
	}
}

// A by-plan row without a version id takes the oldest version of exactly its
// key: a longer key that begins with it lists under the same prefix.
func TestFetch_OldestIsOfTheExactKeyNeverOfALongerOne(t *testing.T) {
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	put(f, f.putKey(seg(1, 1)), "a newer version")
	put(f, f.putKey(seg(1, 1))+"x", "a longer key's version")
	r := jobio.PlanRow{Key: seg(1, 1), Size: int64(len("segment 1/1"))}
	dest, _, err := fetch(t, fetchIn(), planOf(t, r), f)
	if err != nil {
		t.Fatal(err)
	}
	if got := tree(t, dest)[seg(1, 1)]; got != "segment 1/1" {
		t.Errorf("fetched %q", got)
	}
}

// overLong is a store that does not keep to the bound it is given.
type overLong struct{ *fake }

func (o overLong) Get(ctx context.Context, key, vid string, w io.Writer, max int64) (s3x.Object, error) {
	ob, err := o.fake.Get(ctx, key, vid, w, 1<<40)
	return ob, err
}

// A body longer than its row — an exact size, or an info file's bound — is
// refused and its file removed, whatever the store does with the bound.
// (Red until fetch.go checks s.n > p.size for a bound row too.)
func TestFetch_ABodyPastItsRowIsRefusedWhateverTheStore(t *testing.T) {
	f := newFake()
	big := strings.Repeat("i", bklimit.SmallMax+1)
	put(f, f.putKey(pArchInfo), big)
	info := jobio.PlanRow{Key: pArchInfo, VersionID: f.objs[f.putKey(pArchInfo)][0].vid, SHA256: sum([]byte(big)), Size: bklimit.SmallMax}
	dest, _, err := fetch(t, fetchIn(), planOf(t, info), overLong{f})
	if !errors.Is(err, ErrMismatch) || len(tree(t, dest)) != 0 {
		t.Errorf("an info body above its bound: %v, files %d", err, len(tree(t, dest)))
	}
}

// deadlines records the deadline of every call's context.
type deadlines struct {
	*fake
	list, get []time.Duration
}

func (d *deadlines) left(ctx context.Context) time.Duration {
	t, ok := ctx.Deadline()
	if !ok {
		return 1 << 62
	}
	return time.Until(t)
}

func (d *deadlines) ListVersions(ctx context.Context, prefix, km, vm string) ([]s3x.Object, string, string, error) {
	d.list = append(d.list, d.left(ctx))
	return d.fake.ListVersions(ctx, prefix, km, vm)
}

func (d *deadlines) Get(ctx context.Context, key, vid string, w io.Writer, max int64) (s3x.Object, error) {
	d.get = append(d.get, d.left(ctx))
	return d.fake.Get(ctx, key, vid, w, max)
}

// The program's client is given the whole fetch's bound as its call timeout
// (one GET may move a set file): each call is then bounded by its own
// context — a listing page by CallTimeout, a GET by CallTimeout plus its
// object's bound at the assumed rate — never by the whole fetch's.
func TestFetch_EveryCallHasItsOwnBound(t *testing.T) {
	f := newFake()
	put(f, f.putKey(seg(1, 1)), "segment 1/1")
	d := &deadlines{fake: f}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	r := jobio.PlanRow{Key: seg(1, 1), Size: int64(len("segment 1/1"))} // no version: one listing
	if _, err := Fetch(ctx, fetchIn(), planOf(t, r), t.TempDir(), d); err != nil {
		t.Fatal(err)
	}
	if len(d.list) != 1 || d.list[0] > CallTimeout || len(d.get) != 1 || d.get[0] > CallTimeout+2*time.Second {
		t.Errorf("listing bounds %v, GET bounds %v", d.list, d.get)
	}
}
