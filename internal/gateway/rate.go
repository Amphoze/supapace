package gateway

import (
	"sync"
	"time"

	"github.com/Amphoze/supapace/internal/routes"
)

// rates holds a token bucket per project ref that has a rate member. The zero
// value is ready. Buckets are keyed by ref and live outside the route table,
// so a reload neither refills nor resets them; the figures are the entry's
// of the moment. A bucket that has refilled to its burst equals a new one and
// may be dropped. Dropping is a sweep of the whole map, run by a new bucket
// once the map has doubled since the last sweep: amortised constant work per
// new bucket, and one walk per doubling, so alternating busy projects cannot
// make every request walk the map. Memory: after a sweep the map holds only
// refs busy in the last Burst/RPS seconds (at most 10 s), each of which was
// in the route table; until the next sweep it grows to at most twice that,
// plus one.
type rates struct {
	mu    sync.Mutex
	m     map[string]*bucket
	sweep int // the map's size at which a new bucket sweeps it next
}

type bucket struct {
	tokens     float64
	at         time.Time
	rps, burst int // the figures of the last request, for the sweep
}

// allow takes one token of ref's bucket for a request that passed the key
// check; without a rate member every request passes and nothing is kept.
func (l *rates) allow(ref string, r *routes.Rate, now time.Time) bool {
	if r == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[ref]
	if b == nil {
		if l.m == nil {
			l.m = map[string]*bucket{}
		}
		if len(l.m) >= l.sweep {
			for k, o := range l.m {
				if o.refill(now) >= float64(o.burst) {
					delete(l.m, k)
				}
			}
			l.sweep = 2 * len(l.m)
		}
		b = &bucket{tokens: float64(r.Burst), at: now}
		l.m[ref] = b
	}
	b.rps, b.burst = r.RPS, r.Burst
	b.tokens = min(b.refill(now), float64(r.Burst))
	if now.After(b.at) {
		b.at = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// refill is what b holds at now; a clock that stepped back adds nothing.
func (b *bucket) refill(now time.Time) float64 {
	if d := now.Sub(b.at); d > 0 {
		return b.tokens + d.Seconds()*float64(b.rps)
	}
	return b.tokens
}
