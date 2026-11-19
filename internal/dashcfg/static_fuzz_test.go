package dashcfg

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// validLike: c with the members Static does not read filled as nodecfg.Validate wants.
func validLike(c nodecfg.Config) bool {
	c.MemAllocMB, c.PidsAlloc, c.Retention = 1, 1, "1h"
	c.Images, _ = nodecfg.LockedImages()
	return c.Validate() == nil
}

// FuzzStatic: on any node configuration Static does not panic, names no port
// past 65535 and no inverted range, and zeroes exactly the members For's rules
// refuse; when For accepts, Static is For's answer.
func FuzzStatic(f *testing.F) {
	d := defaultCfg()
	f.Add(d.ProjectBlock, d.SlicePrefix, d.PlatformSubnet, d.PlatformIPRange, d.GatewayIP, d.UIDBase, d.UIDCount)
	w := wideCfg()
	f.Add(w.ProjectBlock, w.SlicePrefix, w.PlatformSubnet, w.PlatformIPRange, w.GatewayIP, w.UIDBase, w.UIDCount)
	f.Add("0.0.0.0/0", 32, "255.255.255.248/29", "255.255.255.252/30", "255.255.255.254", 1, 1<<31-1)
	f.Add("10.213.0.0/16", 26, "2001:db8::/64", "::ffff:10.212.0.0/120", "10.212.0.6", 65000, 600)
	f.Add("10.213.0.0/16", 26, "10.212.0.5/21", "10.212.0.4/31", "10.212.0.3", 0, 0)
	f.Fuzz(func(t *testing.T, block string, slicePrefix int, subnet, rng, gw string, uidBase, uidCount int) {
		c := defaultCfg()
		c.ProjectBlock, c.SlicePrefix, c.PlatformSubnet, c.PlatformIPRange, c.GatewayIP = block, slicePrefix, subnet, rng, gw
		c.UIDBase, c.UIDCount = uidBase, uidCount
		s := Static(c)
		if s.MetaPortHi > 65535 || s.MetaPortLo > s.MetaPortHi || (s.MetaPortLo == 0) != (s.MetaPortHi == 0) {
			t.Fatalf("ports %d-%d", s.MetaPortLo, s.MetaPortHi)
		}
		p, perr := netip.ParsePrefix(subnet)
		r, rerr := netip.ParsePrefix(rng)
		g, _ := netip.ParseAddr(gw)
		for i, m := range []netip.Addr{s.Studio, s.PgMeta0, s.PgMeta1, s.Pgcap} {
			if !m.IsValid() {
				continue
			}
			if perr != nil || !p.Contains(m) || m == g || rerr != nil || r.Contains(m) ||
				m != addOffset(p.Masked().Addr(), uint32(3+i)) {
				t.Fatalf("member %d = %v on %+v", i, m, c)
			}
		}
		a, err := For(c)
		if err == nil {
			if a != s || !a.Studio.IsValid() || !a.PgMeta0.IsValid() || !a.PgMeta1.IsValid() || !a.Pgcap.IsValid() ||
				a.MetaPortLo != MetaPortBase || !a.RestLo.IsValid() || !a.RestHi.IsValid() {
				t.Fatalf("For accepted %+v, Static %+v", a, s)
			}
			return
		}
		if a != (Addrs{}) {
			t.Fatalf("For refused but returned %+v", a)
		}
		// For refuses: a member is zero, or a rule that concerns no member fired.
		zero := !s.Studio.IsValid() || !s.PgMeta0.IsValid() || !s.PgMeta1.IsValid() || !s.Pgcap.IsValid() ||
			s.MetaPortHi == 0 || !s.RestLo.IsValid() || !s.RestHi.IsValid()
		if !zero && !strings.Contains(err.Error(), "uid") && !strings.Contains(err.Error(), "the dashboard file carries") {
			t.Fatalf("For refused %+v with every member set: %v", c, err)
		}
		// On a configuration Validate accepts, a dashboard address is zero only when
		// it is the gateway's or in the allocation range, the port range only past
		// 65535, and the PostgREST range is always set.
		if !validLike(c) {
			return
		}
		if !s.RestLo.IsValid() || !s.RestHi.IsValid() || s.MetaPortHi == 0 && MetaPortBase+c.Slices()-1 <= 65535 {
			t.Fatalf("valid %+v: %+v", c, s)
		}
		for i, m := range []netip.Addr{s.Studio, s.PgMeta0, s.PgMeta1, s.Pgcap} {
			if e := addOffset(p.Masked().Addr(), uint32(3+i)); !m.IsValid() && e != g && !r.Contains(e) {
				t.Fatalf("valid %+v: member %d zero for another reason", c, i)
			}
		}
	})
}
