//go:build reach

package agent

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/dashcfg"
)

// TestNode_EnsureProxyOnTheRuntime: the whole ensure against the node's own
// runtime — from nothing, again, with a project gone from the list, with an
// attachment nobody accounts for, with the proxy stopped, removed by hand,
// and of another shape. After each: the networks the runtime reports, the
// table on disk, and whether the container is the one of before.
func TestNode_EnsureProxyOnTheRuntime(t *testing.T) {
	n := pxSetup(t, 28, 29)
	a, ctx, cfg := n.a, context.Background(), n.a.cfg
	s1, s2 := n.s[0], n.s[1]
	both := []Spec{s1, s2}
	at := func(s Spec) string {
		return fmt.Sprintf("%s=%s", networkName(s.Ref), dashcfg.ProxyAddr(cfg, s.SubnetIndex))
	}
	platform := "platform=" + n.ad.Pgcap.String()
	id := func() string { return nodeDocker(t, "inspect", "-f", "{{.Id}}", dashcfg.PgcapName) }
	state := func(what string, live []Spec, wantNets ...string) {
		t.Helper()
		if err := a.EnsureProxy(ctx, listed(live)); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if got := strings.Fields(pxNetworks(t)); !slices.Equal(got, wantNets) {
			t.Errorf("%s: the proxy is on %q, want %q", what, got, wantNets)
		}
		tb, have, err := a.readProxyTable()
		if err != nil || !have {
			t.Fatalf("%s: the table: %v (there %v)", what, err, have)
		}
		var want []string
		for _, s := range live {
			want = append(want, strconv.Itoa(s.SubnetIndex))
		}
		if got := slices.Sorted(maps.Keys(tb.Slices)); !slices.Equal(got, want) {
			t.Errorf("%s: the table holds the slices %q, want %q", what, got, want)
		}
		if got := nodeDocker(t, "inspect", "-f", "{{.State.Running}}", dashcfg.PgcapName); got != "true" {
			t.Errorf("%s: the proxy runs: %s", what, got)
		}
	}
	meta := pxMember(t, "sp-test-proxy-meta", platformNet, n.ad.PgMeta0.String())
	open := func(what string) {
		t.Helper()
		pxWait(t, what+": both slices' ports open to postgres-meta's address", func() bool {
			for _, s := range both {
				if pxTCP(t, meta, n.ad.Pgcap.String()+":"+strconv.Itoa(dashcfg.MetaPort(s.SubnetIndex))) != "connected" {
					return false
				}
			}
			return pxRows(a, n.ad) == nil
		})
	}

	state("from nothing", both, platform, at(s1), at(s2))
	open("from nothing")
	first, inode := id(), pxInode(t, a.proxyTablePath())
	state("again", both, platform, at(s1), at(s2))
	if id() != first || pxInode(t, a.proxyTablePath()) != inode {
		t.Error("a second ensure made the container or the file again")
	}

	state("a project gone from the list", []Spec{s1}, platform, at(s1))
	state("the project back", both, platform, at(s1), at(s2))
	if id() != first {
		t.Error("a changed list made the container again")
	}

	// An attachment nobody accounts for: a scratch network, joined by hand.
	const odd = "sp-test-proxy-odd"
	t.Cleanup(func() { nodeDockerQuiet("network", "rm", odd) })
	nodeDocker(t, "network", "create", "--label", pxLabel, "--internal", odd)
	nodeDocker(t, "network", "connect", odd, dashcfg.PgcapName)
	if _, nets := a.checkProxy(ctx, n.ad); nets == nil || !strings.Contains(nets.Error(), odd) {
		t.Errorf("control: the blocking row with the proxy on %s: %v", odd, nets)
	}
	state("with an attachment nobody accounts for", both, platform, at(s1), at(s2))
	if id() != first {
		t.Error("an attachment to drop made the container again")
	}

	nodeDocker(t, "stop", "-t", "1", dashcfg.PgcapName)
	state("stopped by hand", both, platform, at(s1), at(s2))
	if id() != first {
		t.Error("a stopped proxy was made again, not started")
	}
	open("started again")

	nodeDocker(t, "rm", "-f", dashcfg.PgcapName)
	state("removed by hand", both, platform, at(s1), at(s2))
	second := id()
	if second == first {
		t.Fatal("control: the container was not removed")
	}
	open("made again")

	// Another shape: the container is made again and every slice attached again.
	saved := dashcfg.Limits
	t.Cleanup(func() { dashcfg.Limits = saved })
	dashcfg.Limits.Proxy.MaxConns++
	state("of another shape", both, platform, at(s1), at(s2))
	if id() == second {
		t.Error("a changed shape left the container")
	}
	open("of another shape")
	if tb, _, _ := a.readProxyTable(); tb.MaxConns != dashcfg.Limits.Proxy.MaxConns {
		t.Errorf("the table's ceiling is %d, want %d", tb.MaxConns, dashcfg.Limits.Proxy.MaxConns)
	}
}
