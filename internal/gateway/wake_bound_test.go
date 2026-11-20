package gateway

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// A wake that answers nil before the table shows the project active (the
// table's reload lag) does not let more than the project's cap be held: the
// requests that wait for the table still count until they leave.
func TestWake_HeldAfterTheWakeStillCounted(t *testing.T) {
	s := &standIn{wake: func(context.Context, string) error { return nil }} // the table stays asleep
	e := wakeEnv(t, sleepy(1, 0, []string{refA}), s)
	e.gw.wake.bound = 2 * time.Second
	var wg sync.WaitGroup
	var mu sync.Mutex
	type span struct{ from, to time.Time }
	var spans []span
	for w := range 4 {
		for i := range 200 {
			wg.Add(1)
			r := anonReq(t, refA, fmt.Sprintf("[2001:db8:%x:%x::1]:1", w, i))
			go func() {
				defer wg.Done()
				t0 := time.Now()
				restarting(t, "held or refused", e.do(r))
				if t1 := time.Now(); t1.Sub(t0) > time.Second { // held: answered at the hold, not at once
					mu.Lock()
					spans = append(spans, span{t0, t1})
					mu.Unlock()
				}
			}()
		}
		time.Sleep(100 * time.Millisecond) // all within one hold
	}
	wg.Wait()
	held := 0 // the most held spans that overlap one instant: some span's start
	for _, a := range spans {
		n := 0
		for _, b := range spans {
			if !b.from.After(a.from) && b.to.After(a.from) {
				n++
			}
		}
		held = max(held, n)
	}
	// The spans are timed outside the handler: a few overlap at their edges.
	if held > e.gw.projectCap+32 {
		t.Fatalf("%d requests of one project held at once, want at most %d", held, e.gw.projectCap)
	}
	if held == 0 { // control: the wake holds requests at all
		t.Fatal("nothing was held")
	}
}
