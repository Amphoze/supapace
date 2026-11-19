package gateway

import (
	"math/bits"
	"strconv"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/routes"
)

// TestRate_SweepsLogarithmically: N new buckets, all busy, run O(log N)
// sweeps, not N. A sweep is seen by a full bucket planted before each new
// one: a sweep drops it. Then, with every earlier bucket full, the map never
// grows past twice its size at the last sweep, and within that many new
// buckets the stale ones are gone.
func TestRate_SweepsLogarithmically(t *testing.T) {
	for _, n := range []int{1024, 10000} {
		var l rates
		t0 := time.Unix(1000, 0)
		busy := &routes.Rate{RPS: 1, Burst: 2} // one token taken: busy at t0
		sweeps := 0
		for i := range n {
			l.mu.Lock()
			if l.m == nil {
				l.m = map[string]*bucket{}
			}
			if _, ok := l.m["sentinel"]; !ok {
				l.m["sentinel"] = &bucket{tokens: 1, at: t0, rps: 1, burst: 1}
			}
			l.mu.Unlock()
			l.allow("old"+strconv.Itoa(i), busy, t0)
			if _, ok := l.m["sentinel"]; !ok {
				sweeps++
			}
		}
		if limit := 2*bits.Len(uint(n)) + 4; sweeps < 1 || sweeps > limit {
			t.Errorf("%d new buckets: %d sweeps, want 1 to %d", n, sweeps, limit)
		}
		delete(l.m, "sentinel")
		// An hour later every bucket is full again.
		later := t0.Add(time.Hour)
		bound := 2*len(l.m) + 1
		for i := range len(l.m) + 2 {
			l.allow("new"+strconv.Itoa(i), busy, later)
			if len(l.m) > bound {
				t.Fatalf("%d: map of %d past the bound %d", n, len(l.m), bound)
			}
		}
		for k := range l.m {
			if k[:3] == "old" {
				t.Fatalf("%d: stale bucket %s kept after the map doubled", n, k)
			}
		}
	}
}

// BenchmarkRate_NewBucketAmongBusy: a new bucket each request (a project
// whose bucket was full and dropped comes back as new) while n buckets stay
// busy. With the doubling threshold the cost per request does not grow
// with n.
func BenchmarkRate_NewBucketAmongBusy(b *testing.B) {
	for _, n := range []int{1024, 10000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			var l rates
			t0 := time.Unix(1000, 0)
			l.m = map[string]*bucket{}
			for i := range n { // time far ahead: these never refill
				l.m["busy"+strconv.Itoa(i)] = &bucket{at: t0.Add(1e9 * time.Second), rps: 1, burst: 10}
			}
			hot := &routes.Rate{RPS: 1, Burst: 1}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				l.allow("hot"+strconv.Itoa(i), hot, t0.Add(time.Duration(i)*time.Second))
			}
		})
	}
}
