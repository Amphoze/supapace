//go:build reach

package agent

import (
	"context"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
)

// TestNode_ProxyInARestartLoopDoesNotHoldAProjectNetwork: the proxy is a
// service whose outage stops no tenant. While the runtime holds it between
// two restarts — where a container in a crash loop spends nearly all its
// time — a project's network is still removed: the delete of a project, and
// the abort of a create, do not wait for the proxy to be well again.
func TestNode_ProxyInARestartLoopDoesNotHoldAProjectNetwork(t *testing.T) {
	n := pxSetup(t, 26, 27)
	a, ctx := n.a, context.Background()
	for _, s := range n.s {
		if err := a.AttachProxy(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	// The proxy's process cannot read its table at a start, and is killed:
	// from here on the runtime restarts it and it exits at once.
	if err := os.Chmod(dashcfg.PathsFor(a.p).ProxyConf(), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dashcfg.PathsFor(a.p).ProxyConf(), 0o755) })
	if err := syscall.Kill(pxPid(t, dashcfg.PgcapName), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	state := func() string {
		return nodeDocker(t, "inspect", "-f", "{{.State.Restarting}} {{.RestartCount}}", dashcfg.PgcapName)
	}
	// Far enough into the back-off that the next start is seconds away.
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(200 * time.Millisecond) {
		f := strings.Fields(state())
		if len(f) == 2 && f[0] == "true" {
			if k, err := strconv.Atoi(f[1]); err == nil && k >= 7 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy is not in a restart loop: %s", state())
		}
	}
	t.Logf("the proxy (restarting, restart count): %s", state())
	if err := a.RemoveNetwork(ctx, n.s[0].Ref); err != nil {
		t.Errorf("removing a project's network while the proxy is between two restarts (%s): %v", state(), err)
	}
	if out := nodeDocker(t, "network", "ls", "-q", "--filter", "name=^"+networkName(n.s[0].Ref)+"$"); out != "" {
		t.Errorf("the project's network is still there")
	}
	if tb, _, err := a.readProxyTable(); err != nil || len(tb.Slices) != 1 {
		t.Errorf("the table holds %v (%v), want the other slice alone", tb.Slices, err)
	}
	// A create's step in the same state. The agent's write of the table put
	// the directory's mode back and it started the proxy, which runs again:
	// the loop is made once more.
	if err := a.EnsureNetwork(ctx, n.s[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dashcfg.PathsFor(a.p).ProxyConf(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pxPid(t, dashcfg.PgcapName), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(200 * time.Millisecond) {
		f := strings.Fields(state())
		if len(f) == 2 && f[0] == "true" {
			if k, err := strconv.Atoi(f[1]); err == nil && k >= 7 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy is not in a restart loop again: %s", state())
		}
	}
	held := state()
	if err := a.AttachProxy(ctx, n.s[0]); err != nil {
		t.Errorf("attaching while the proxy is between two restarts (%s): %v", held, err)
	}
	if got := pxNetworks(t); !strings.Contains(got, networkName(n.s[0].Ref)) {
		t.Errorf("after the attach the proxy is on %q", got)
	}
	if tb, _, err := a.readProxyTable(); err != nil || len(tb.Slices) != 2 {
		t.Errorf("the table holds %v (%v), want both slices", tb.Slices, err)
	}
}
