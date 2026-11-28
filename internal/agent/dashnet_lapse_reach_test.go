//go:build reach

package agent

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// pxRPDrops is how many packets the reverse-path filter has dropped in pid's
// network namespace (the kernel's own counter).
func pxRPDrops(t *testing.T, pid int) int {
	t.Helper()
	var names []string
	for _, l := range strings.Split(pxMust(t, pid, "cat", "/proc/net/netstat"), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || f[0] != "TcpExt:" {
			continue
		}
		if names == nil {
			names = f
			continue
		}
		for i, name := range names {
			if name == "IPReversePathFilter" && i < len(f) {
				n, err := strconv.Atoi(f[i])
				if err != nil {
					t.Fatal(err)
				}
				return n
			}
		}
	}
	t.Fatal("the kernel reports no reverse-path filter counter")
	return 0
}

// pxLogged counts the proxy's log lines that hold sub.
func pxLogged(t *testing.T, sub string) int {
	t.Helper()
	out, err := exec.Command("docker", "logs", dashcfg.PgcapName).CombinedOutput()
	if err != nil {
		t.Fatalf("the proxy's log: %v", err)
	}
	return strings.Count(string(out), sub)
}

// TestNode_ProxyBehindALapsedBridgePolicy: what is left when the bridge
// policy of a project's bridge does not hold — an accept inserted for it. A
// cluster, as root in its namespace and routing through the proxy's address
// on its bridge: (a) finds nothing listening at that address; (b) completes a
// handshake with the proxy's platform address, which the proxy closes as no
// peer of the class, so the other slice's cluster hears nothing; (c) under a
// peer's address as its source gets no answer, the packets counted by the
// reverse-path filter of the proxy's namespace — the six settings' doing.
func TestNode_ProxyBehindALapsedBridgePolicy(t *testing.T) {
	n := pxSetup(t, 21, 22)
	a, ctx, cfg := n.a, context.Background(), n.a.cfg
	net1, net2 := networkName(n.s[0].Ref), networkName(n.s[1].Ref)
	cluster1, cluster2 := cfg.ClusterAddr(21).String(), cfg.ClusterAddr(22).String()
	proxy1 := dashcfg.ProxyAddr(cfg, 21).String()
	pg1 := pxMember(t, "sp-test-proxy-pg1", net1, cluster1)
	pg2 := pxMember(t, "sp-test-proxy-pg2", net2, cluster2)
	meta := pxMember(t, "sp-test-proxy-meta", platformNet, n.ad.PgMeta0.String())
	pxListen(t, pg2, cluster2+":5432")
	for _, s := range n.s {
		if err := a.AttachProxy(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	px := pxPid(t, dashcfg.PgcapName)
	port2 := strconv.Itoa(dashcfg.MetaPort(22))
	other := n.ad.Pgcap.String() + ":" + port2 // the port that leads to the second slice's cluster
	pxWait(t, "the second slice's port open to postgres-meta's address", func() bool { return pxTCP(t, meta, other) == "connected" })

	pxMust(t, pg1, "ip", "route", "add", cfg.PlatformSubnet, "via", proxy1)
	if v := pxTCP(t, pg1, other); v == "connected" {
		t.Fatalf("control: under the bridge policy the cluster reached %s", other)
	}
	// The lapse: everything the first slice's bridge carries is accepted.
	if out, err := exec.Command("nft", "insert", "rule", "bridge", "supapace", "forward", "meta", "ibrname", nodecfg.BridgeName(21), "ether", "type", "ip", "accept").CombinedOutput(); err != nil {
		t.Fatalf("nft insert: %v: %s", err, out)
	}

	// (a) nothing listens at the proxy's address on the cluster's bridge.
	if v := pxTCP(t, pg1, proxy1+":"+port2); v != "refused" {
		t.Errorf("(a) %s:%s from the cluster with the bridge open: %s, want refused (the control of the lapse: no longer a timeout)", proxy1, port2, v)
	}
	// (b) the platform address answers through host 4, and the proxy closes
	// the connection before it reads a byte: it comes from no peer.
	const noPeer = `"index":22,"reason":"not a peer of the class"`
	before := pxLogged(t, noPeer)
	v := pxTCP(t, pg1, other)
	t.Logf("(b) %s from the cluster with the bridge open: %s", other, v)
	if v == "connected" {
		pxWait(t, "the proxy logging the cluster's connection as no peer", func() bool { return pxLogged(t, noPeer) > before })
	}
	// (c) the same under a peer's address: no answer comes back, and the
	// proxy's reverse-path filter counted the packets.
	drops := pxRPDrops(t, px)
	before = pxLogged(t, noPeer)
	pxMust(t, pg1, "ip", "addr", "add", n.ad.PgMeta0.String()+"/32", "dev", "lo")
	pxMust(t, pg1, "ip", "route", "replace", cfg.PlatformSubnet, "via", proxy1, "src", n.ad.PgMeta0.String())
	if v := pxTCP(t, pg1, other); v != "timeout" {
		t.Errorf("(c) %s from the cluster under a peer's address: %s, want timeout", other, v)
	}
	if got := pxRPDrops(t, px); got <= drops {
		t.Errorf("(c) the proxy's reverse-path filter counted %d packets, %d before: the silence is not its doing", got, drops)
	} else {
		t.Logf("(c) under a peer's address: timeout; the proxy's reverse-path filter dropped %d packets", got-drops)
	}
	if pxLogged(t, noPeer) != before {
		t.Error("(c) the proxy accepted a connection under the peer's address")
	}
	// The other cluster's listener is still there, and reachable only as before.
	if v := pxTCP(t, pg1, cluster2+":5432"); v == "connected" {
		t.Error("the second slice's cluster was reached from the first")
	}
}
