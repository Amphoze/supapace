package pgcap

import (
	"sync/atomic"
	"time"
)

// StreamSlots counts a slice's connections of one class in the stream state.
// Its owner keeps one per slice and class and gives it to every connection of
// that slice and class; the zero value is ready.
type StreamSlots struct{ n atomic.Int64 }

func (s *StreamSlots) acquire(max int) bool {
	if s.n.Add(1) > int64(max) {
		s.n.Add(-1)
		return false
	}
	return true
}

func (s *StreamSlots) release() { s.n.Add(-1) }

// allowance returns, in the stream state, how many bytes may be read from the
// server now or, with none, how long to wait for the next interval. A new
// interval starts the count caps again.
func (s *state) allowance(now time.Time) (int64, time.Duration) {
	iv := time.Duration(s.c.Stream.IntervalMS) * time.Millisecond
	if s.ivStart.IsZero() || now.Sub(s.ivStart) >= iv {
		// Only an overdraft carries over: the bytes already read when the state
		// began; an idle interval leaves no credit.
		s.ivStart, s.ivUsed = now, max(0, s.ivUsed-s.c.Stream.BytesPerInterval)
		s.resetCounts()
	}
	if left := s.c.Stream.BytesPerInterval - s.ivUsed; left > 0 {
		return left, 0
	}
	return 0, iv - now.Sub(s.ivStart)
}

func (s *state) took(n int) { s.ivUsed += int64(n) }
