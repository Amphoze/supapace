package agent

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/Amphoze/supapace/internal/dashcfg"
)

// TestProxy_StateNotReadAsRestarting_NeverStopped: the proxy is stopped for a
// failing network call only when the runtime says, readably, that it holds
// the proxy between two restarts. A state that cannot be read, or reads as
// anything else, stops nothing: a proxy that serves is not cut on a guess.
func TestProxy_StateNotReadAsRestarting_NeverStopped(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	ctx := context.Background()
	live := x.projects(3)
	x.ensure(t, live...)
	// The fixture refuses the call as the runtime does while it holds the
	// proxy, and its own answer would be "restarting": only what is read
	// below keeps the proxy from being stopped.
	x.mu.Lock()
	x.restarting[dashcfg.PgcapName] = true
	x.mu.Unlock()
	onRun := x.f.onRun
	t.Cleanup(func() { x.f.onRun = onRun })
	for _, c := range []struct {
		name, out string
		err       error
	}{
		{"the state cannot be read", "", errors.New("docker: no answer")},
		{"the state reads empty", "\n", nil},
		{"the state reads short", "0123456789ab true\n", nil},
		{"the state reads long", "0123456789ab true 3 2026-01-01T00:00:00Z more\n", nil},
		{"not restarting", "0123456789ab false 3 2026-01-01T00:00:00Z\n", nil},
	} {
		x.f.onRun = func(args []string, stdin []byte) (string, error, bool) {
			if len(args) > 3 && args[0] == "container" && args[1] == "inspect" && args[3] == restartFormat {
				return c.out, c.err, true
			}
			return onRun(args, stdin)
		}
		x.f.resetLog()
		if err := x.a.DetachProxy(ctx, live[0].Ref); err == nil {
			t.Errorf("%s: the refused call was not reported", c.name)
		}
		ev := x.events()
		if slices.Contains(ev, "stop") || slices.Contains(ev, "start") || !slices.Contains(ev, "disconnect proj-"+live[0].Ref) {
			t.Errorf("%s: %q, want the one failing call and the proxy left as it runs", c.name, ev)
		}
		if !x.ctr().Running {
			t.Errorf("%s: the proxy was stopped", c.name)
		}
	}
}
