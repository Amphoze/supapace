package repl

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/Amphoze/supapace/internal/jobio"
)

func rebuildInput(km, vm string, rows int) jobio.Input {
	in := input()
	in.Repl = &jobio.ReplInput{Mode: "rebuild", KeyMarker: km, VersionMarker: vm, PageRows: rows}
	return in
}

// versioned is a fake holding, for each rel, n versions (oldest first), and
// a delete marker on the last one.
func versioned(t *testing.T, n map[string]int) *fake {
	f := newFake()
	for rel, k := range n {
		for i := 0; i < k; i++ {
			f.store(f.putKey(rel), []byte{byte(i)}, nil, false)
		}
	}
	f.objs[f.putKey(pHist2)] = append(f.objs[f.putKey(pHist2)], fakeObj{vid: "v999998", marker: true})
	return f
}

func pages(t *testing.T, f *fake, rows int) (all [][]jobio.Row, last []jobio.ReplResult) {
	km, vm := "", ""
	for i := 0; i < 100; i++ {
		r, err := Rebuild(context.Background(), rebuildInput(km, vm, rows), f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jobio.MarshalResult(r); err != nil {
			t.Fatal(err)
		}
		all, last = append(all, r.Rows), append(last, r)
		if r.Last {
			return all, last
		}
		km, vm = r.NextKeyMarker, r.NextVersionMarker
	}
	t.Fatal("no last page")
	return nil, nil
}

func TestRebuild_OnePageFromMarkers_OldestVersionIsTheLastListed_LastFlag(t *testing.T) {
	f := versioned(t, map[string]int{seg(1, 1): 3, seg(1, 2): 1, pHist2: 2, pArchInfo: 4})
	f.store("pre/fix/"+ref+"/hx/planted", []byte("x"), nil, false)
	all, rs := pages(t, f, 3)
	// The oldest version of each key is the last one merged, across pages.
	oldest := map[string]string{}
	for _, p := range all {
		if len(p) > 3 {
			t.Errorf("page of %d rows", len(p))
		}
		for _, r := range p {
			oldest[r.Key] = r.VersionID
		}
	}
	for rel, want := range map[string]string{seg(1, 1): f.objs[f.putKey(seg(1, 1))][0].vid, seg(1, 2): f.objs[f.putKey(seg(1, 2))][0].vid,
		pHist2: f.objs[f.putKey(pHist2)][0].vid, pArchInfo: f.objs[f.putKey(pArchInfo)][0].vid} {
		if oldest[rel] != want {
			t.Errorf("%s: %s, want the oldest %s", rel, oldest[rel], want)
		}
	}
	if len(oldest) != 4 {
		t.Errorf("keys %v (the planted key is not a row)", oldest)
	}
	for i, r := range rs {
		final := i == len(rs)-1
		if r.Last != final || r.Complete != final || (r.Stopped == "") != final || (final && (r.NextKeyMarker != "" || r.NextVersionMarker != "")) {
			t.Errorf("page %d: last %v complete %v stopped %q markers %q %q", i, r.Last, r.Complete, r.Stopped, r.NextKeyMarker, r.NextVersionMarker)
		}
	}
	// One page, rows within the page: the last listed of a key is its oldest there.
	r, _ := Rebuild(context.Background(), rebuildInput("", "", 4000), f)
	if !r.Last || len(r.Rows) != 4 || r.Rows[slices.IndexFunc(r.Rows, func(x jobio.Row) bool { return x.Key == seg(1, 1) })].VersionID != oldest[seg(1, 1)] {
		t.Errorf("one page: %+v", r.Rows)
	}
	if n := noticeOf(r, "unlisted-entry"); n == nil || n.Count != 1 {
		t.Errorf("unlisted %+v", n)
	}
}

func TestRebuild_PageNeverAbovePageRows(t *testing.T) {
	n := map[string]int{}
	for i := 1; i <= 50; i++ {
		n[seg(1, i)] = 2
	}
	for _, server := range []int{3, 7, 1000} {
		f := versioned(t, n)
		f.page = server
		all, _ := pages(t, f, 5)
		seen := map[string]int{}
		for _, p := range all {
			if len(p) > 5 {
				t.Errorf("server page %d: a page of %d rows", server, len(p))
			}
			for _, r := range p {
				seen[r.Key]++
			}
		}
		if len(seen) != 50 {
			t.Errorf("server page %d: %d keys, want 50", server, len(seen))
		}
	}
	// A store that answers an empty page that is not the last stops the job.
	f := versioned(t, n)
	f.failList = func(call int) error {
		if call == 2 {
			return errors.New("connection reset")
		}
		return nil
	}
	f.page = 2
	if _, err := Rebuild(context.Background(), rebuildInput("", "", 4000), f); err == nil {
		t.Error("a listing that failed on its second page gave a result")
	}
}
