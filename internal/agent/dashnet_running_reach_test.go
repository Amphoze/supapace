//go:build reach

package agent

import (
	"context"
	"testing"

	"github.com/Amphoze/supapace/internal/dashcfg"
)

// TestNode_ProxyThatRunsIsNotStoppedOverAFailingCall: on the node's runtime,
// an attach that the runtime refuses for a reason of its own — a stranger
// holds host 4 of the project's network — fails and leaves the running proxy
// exactly as it was: the same process, started when it was, serving the
// slice it served. Only a proxy held between two restarts is ever stopped.
func TestNode_ProxyThatRunsIsNotStoppedOverAFailingCall(t *testing.T) {
	n := pxSetup(t, 31, 32)
	a, ctx := n.a, context.Background()
	if err := a.AttachProxy(ctx, n.s[0]); err != nil {
		t.Fatal(err)
	}
	state := func() string {
		return nodeDocker(t, "inspect", "-f", "{{.Id}} {{.State.Running}} {{.State.Pid}} {{.State.StartedAt}} {{.RestartCount}}", dashcfg.PgcapName)
	}
	before := state()
	pxMember(t, "sp-test-proxy-squat", networkName(n.s[1].Ref), dashcfg.ProxyAddr(a.cfg, 32).String())
	err := a.AttachProxy(ctx, n.s[1])
	if err == nil {
		t.Fatal("control: the attach to a network whose host 4 is taken passed")
	}
	t.Logf("the refused attach: %v", err)
	if got := state(); got != before {
		t.Errorf("the proxy changed over a failing call:\n before %s\n after  %s", before, got)
	}
	if tb, _, err := a.readProxyTable(); err != nil || len(tb.Slices) != 1 {
		t.Errorf("the table holds %v (%v), want the first slice alone", tb.Slices, err)
	}
}
