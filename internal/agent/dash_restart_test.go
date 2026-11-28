package agent

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/dashcfg"
)

// TestCheckDashboard_RestartCountAfterAStartByHand: the runtime counts a
// container's restarts from nought again once it is started by hand, or by
// an ensure that found it stopped. A count below the one the last check saw
// is therefore the same container counted anew: its restarts since are
// reported, not taken for fewer than before.
func TestCheckDashboard_RestartCountAfterAStartByHand(t *testing.T) {
	x := newDashFix(t, "studio.test")
	ctx := context.Background()
	if err := x.a.EnsureDashboard(ctx); err != nil {
		t.Fatal(err)
	}
	failing := func() (bad []string, detail string) {
		for _, r := range x.a.CheckDashboard(ctx) {
			if !r.OK {
				bad = append(bad, r.Name)
				detail += r.Detail
			}
		}
		return
	}
	set := func(n int) {
		x.mu.Lock()
		x.restarts[dashcfg.StudioName] = n
		x.logs[dashcfg.StudioName] = "the server's last line\n"
		x.mu.Unlock()
	}
	set(6)
	if bad, d := failing(); len(bad) != 0 {
		t.Fatalf("the first check: failing %q: %s", bad, d)
	}
	// Stopped and started again, the same container: the runtime's count was
	// nought at that start and is two now.
	set(2)
	if bad, d := failing(); !slices.Equal(bad, []string{dashcfg.StudioName}) || !strings.Contains(d, "restarted 2 times since the last check") {
		t.Errorf("restarted twice after a start by hand: failing %q: %s", bad, d)
	}
	if bad, d := failing(); len(bad) != 0 {
		t.Errorf("no restart since: failing %q: %s", bad, d)
	}
}
