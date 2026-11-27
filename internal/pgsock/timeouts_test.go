package pgsock

import (
	"testing"
	"time"
)

// TestConfig_TimeoutsInMillisecondsRoundedUp: the two timeouts of a target
// are sent in milliseconds, a fraction rounded up (0 would mean none); unset,
// the list's 0 stands.
func TestConfig_TimeoutsInMillisecondsRoundedUp(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{{0, "0"}, {time.Microsecond, "1ms"}, {999 * time.Microsecond, "1ms"}, {time.Millisecond, "1ms"},
		{1500 * time.Microsecond, "2ms"}, {2 * time.Second, "2000ms"}} {
		cfg, err := config(Target{LockTimeout: c.d, StatementTimeout: c.d}, DefaultBudget)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.RuntimeParams["lock_timeout"]; got != c.want || cfg.RuntimeParams["statement_timeout"] != c.want {
			t.Errorf("%v: lock_timeout %q, statement_timeout %q, want %q", c.d, got, cfg.RuntimeParams["statement_timeout"], c.want)
		}
	}
}
