package repl

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIndex_ParseStrict(t *testing.T) {
	h := strings.Repeat("a", 64)
	good := "k1\t1\t2\t3\t" + h + "\nk2\t4\t5\t6\t-\n"
	ix, err := loadIndex(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	if x, ok, _ := ix.lookup("k1"); !ok || x != (hit{1, 2, 3, true}) {
		t.Errorf("k1: %+v %v", x, ok)
	}
	if x, ok, _ := ix.lookup("k2"); !ok || x != (hit{4, 5, 6, false}) {
		t.Errorf("k2: %+v %v", x, ok)
	}
	if _, ok, _ := ix.lookup("k"); ok {
		t.Error("a prefix of a key hit")
	}
	for _, bad := range []string{
		"k1\t1\t2\t3\t" + h,                          // unterminated
		"k1\t1\t2\t3\n",                              // four fields
		"k1\t1\t2\t3\t" + h + "\textra\n",            // six
		"k1\t-1\t2\t3\t-\n",                          // negative
		"k1\t1\t2\t3\t" + strings.ToUpper(h) + "\n",  // upper-case hash
		"k\x01\t1\t2\t3\t-\n",                        // control byte
		"\t1\t2\t3\t-\n",                             // empty key
		strings.Repeat("k", 1025) + "\t1\t2\t3\t-\n", // key over 1,024 bytes
		strings.Repeat("k", 5000) + "\n",             // line over the buffer
		"k1\t1\t2\t3\t-\r\n",
	} {
		if _, err := loadIndex(strings.NewReader(good + bad)); err == nil {
			t.Errorf("accepted %.40q", bad)
		}
	}
	if _, err := loadIndex(strings.NewReader(good + "x\n")); !errors.Is(err, ErrIndex) {
		t.Errorf("a malformed line: %v, want ErrIndex", err)
	}
	if _, err := loadIndex(bufio.NewReader(strings.NewReader(good))); err == nil {
		t.Error("accepted an index that cannot be read at an offset")
	}
}

// 3 M rows are held in under 160 MiB: 40 bytes a row, no copy of the array.
func TestIndex_FortyBytesARow(t *testing.T) {
	if testing.Short() {
		t.Skip("writes and loads 3 M rows")
	}
	const rows = 3_000_000
	p := filepath.Join(t.TempDir(), "idx")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	for i := 0; i < rows; i++ {
		fmt.Fprintf(w, "k%d\t%d\t%d\t%d\t-\n", i, i, i, i)
	}
	w.Flush()
	f.Seek(0, 0)
	defer f.Close()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	ix, err := loadIndex(f)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if used := int64(after.HeapAlloc) - int64(before.HeapAlloc); used > 160<<20 {
		t.Errorf("%d rows hold %d MiB", rows, used>>20)
	} else {
		t.Logf("%d rows hold %d MiB (%d bytes a row)", rows, used>>20, used/rows)
	}
	if x, ok, err := ix.lookup("k2999999"); !ok || err != nil || x.size != 2999999 {
		t.Errorf("lookup: %+v %v %v", x, ok, err)
	}
	runtime.KeepAlive(ix)
}

func TestIndex_HashHitConfirmedByTheKeyAtItsOffset(t *testing.T) {
	old := keyHash
	keyHash = func(string) uint64 { return 7 }
	defer func() { keyHash = old }()
	ix, err := loadIndex(strings.NewReader("alpha\t1\t1\t1\t-\nbeta\t2\t2\t2\t-\nalphabet\t3\t3\t3\t-\n"))
	if err != nil {
		t.Fatal(err)
	}
	for k, size := range map[string]int64{"alpha": 1, "beta": 2, "alphabet": 3} {
		if x, ok, _ := ix.lookup(k); !ok || x.size != size {
			t.Errorf("%s: %+v %v", k, x, ok)
		}
	}
	for _, k := range []string{"gamma", "alph", "bet"} {
		if x, ok, _ := ix.lookup(k); ok {
			t.Errorf("%s: a false hit %+v", k, x)
		}
	}
}
