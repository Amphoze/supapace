package poolcfg

import (
	"net/netip"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// FuzzStatic: on any node configuration Static does not panic, names no
// port past 65535 and no inverted range, and names no address For refuses
// (it zeroes those); when For accepts, Static is For's answer, and on a
// configuration nodecfg accepts the three addresses lie in their subnets
// and are none of the gateway's two, the dashboard's four or the fixed
// PostgREST addresses, nor in the range Docker allocates from.
func FuzzStatic(f *testing.F) {
	d := defaultCfg()
	f.Add(d.ProjectBlock, d.SlicePrefix, d.PlatformSubnet, d.PlatformIPRange, d.GatewayIP, d.IngressSubnet, d.GatewayIngressIP, d.UIDBase, d.UIDCount)
	f.Add("0.0.0.0/0", 32, "255.255.255.248/29", "255.255.255.252/30", "255.255.255.254", "255.255.255.254/31", "255.255.255.255", 1, 1<<31-1)
	f.Add("10.213.0.0/16", 26, "2001:db8::/64", "::ffff:10.212.0.0/120", "10.212.0.8", "10.212.8.0/31", "10.212.8.1", 65000, 600)
	f.Add("10.213.0.0/16", 26, "10.212.0.5/21", "10.212.0.4/31", "10.212.0.7", "10.212.8.9/24", "10.212.8.3", 0, 0)
	f.Fuzz(func(t *testing.T, block string, slicePrefix int, subnet, rng, gw, ingress, gwi string, uidBase, uidCount int) {
		c := defaultCfg()
		c.ProjectBlock, c.SlicePrefix, c.PlatformSubnet, c.PlatformIPRange, c.GatewayIP = block, slicePrefix, subnet, rng, gw
		c.IngressSubnet, c.GatewayIngressIP, c.UIDBase, c.UIDCount = ingress, gwi, uidBase, uidCount
		s := Static(c)
		if s.PoolPortHi > 65535 || s.PoolPortLo > s.PoolPortHi || (s.PoolPortLo == 0) != (s.PoolPortHi == 0) {
			t.Fatalf("ports %d-%d", s.PoolPortLo, s.PoolPortHi)
		}
		// No member Static names is one For refuses: each lies in its subnet,
		// is neither gateway address, and no platform member is in the range
		// Docker allocates from.
		gwA, _ := netip.ParseAddr(gw)
		gwiA, _ := netip.ParseAddr(gwi)
		rngP, rerr := netip.ParsePrefix(rng)
		for _, m := range []struct {
			addr     netip.Addr
			subnet   string
			platform bool
		}{{s.PlatformDB, subnet, true}, {s.Pooler, subnet, true}, {s.PoolerIngress, ingress, false}} {
			if !m.addr.IsValid() {
				continue
			}
			n, err := netip.ParsePrefix(m.subnet)
			if err != nil || !n.Masked().Contains(m.addr) || m.addr == gwA || m.addr == gwiA || m.platform && rerr == nil && rngP.Contains(m.addr) {
				t.Fatalf("Static names %s, which For refuses, on %+v", m.addr, c)
			}
		}
		a, err := For(c)
		if err != nil {
			if a != (Addrs{}) {
				t.Fatalf("For refused but returned %+v", a)
			}
			return
		}
		if a != s {
			t.Fatalf("For %+v, Static %+v", a, s)
		}
		v := c
		v.MemAllocMB, v.PidsAlloc, v.Retention = 1, 1, "1h"
		v.Images, _ = nodecfg.LockedImages()
		if v.Validate() != nil {
			return
		}
		p, i, r := netip.MustParsePrefix(subnet), netip.MustParsePrefix(ingress), netip.MustParsePrefix(rng)
		fixed := map[netip.Addr]bool{netip.MustParseAddr(gw): true, netip.MustParseAddr(gwi): true}
		for off := 3; off <= 6; off++ {
			fixed[addOffset(p.Addr(), uint32(off))] = true
		}
		lo, hi := c.PlatformAddr(0), c.PlatformAddr(c.Slices()-1)
		for _, m := range []netip.Addr{a.PlatformDB, a.Pooler, a.PoolerIngress} {
			if fixed[m] || r.Contains(m) || (!m.Less(lo) && !hi.Less(m)) {
				t.Fatalf("%s collides on %+v", m, c)
			}
		}
		if !p.Contains(a.PlatformDB) || !p.Contains(a.Pooler) || !i.Contains(a.PoolerIngress) {
			t.Fatalf("outside the subnets: %+v on %+v", a, c)
		}
	})
}

// Static masks a network written with host bits, as For does.
func TestStatic_MasksTheSubnets(t *testing.T) {
	c := defaultCfg()
	c.PlatformSubnet, c.IngressSubnet = "10.212.0.5/21", "10.212.8.9/24"
	s := Static(c)
	if s.PlatformDB != ip("10.212.0.7") || s.Pooler != ip("10.212.0.8") || s.PoolerIngress != ip("10.212.8.3") {
		t.Errorf("Static = %+v", s)
	}
}

// The default pool fits the default tier: both platform roles in both modes
// take 26 of the default allowance.
func TestDefaults_FitTheDefaultTier(t *testing.T) {
	if err := Fits(defaultMaxConnections, DefaultPoolSize); err != nil {
		t.Error(err)
	}
	if need := 2 * ((2 + DefaultPoolSize) + (1 + DefaultPoolSize)); need != 26 || MinMaxConnections(DefaultPoolSize) != TierReserved+need {
		t.Errorf("the platform roles' pools take %d", need)
	}
	if RestrictionsOffered {
		t.Error("network restrictions are offered before the address-preserving path is proven")
	}
}
