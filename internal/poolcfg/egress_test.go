package poolcfg

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

func TestValidAllowList_RefusesTheEgressSubnet(t *testing.T) {
	for name, c := range map[string]nodecfg.Config{
		"the default subnet": defaultCfg(),
		"one set in the node file": func() nodecfg.Config {
			c := defaultCfg()
			c.EgressSubnet = "10.212.12.0/24"
			return c
		}(),
	} {
		egress := netip.MustParsePrefix(c.Egress())
		for _, p := range []netip.Prefix{egress, netip.PrefixFrom(egress.Addr().Next(), 32), netip.PrefixFrom(egress.Addr(), 25)} {
			if got, err := ValidAllowList(c, []string{p.String()}); err == nil || !strings.Contains(err.Error(), egress.String()) {
				t.Errorf("%s: %s: %v, %v; want the egress subnet refused", name, p, got, err)
			}
		}
		// Control on the same path: the address block beside it is accepted.
		beside := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 212, 13, 0}), 24)
		if _, err := ValidAllowList(c, []string{beside.String()}); err != nil {
			t.Errorf("%s: control %s: %v", name, beside, err)
		}
	}
}

// A node file whose platform subnet is damaged: every list is an error naming
// it, where the merged function skipped the subnet and let a list inside it
// pass.
func TestValidAllowList_ANodeSubnetThatDoesNotParseIsAnError(t *testing.T) {
	inside := []string{"10.212.1.0/24"} // inside the platform subnet
	outside := []string{"192.0.2.0/24"}
	if _, err := ValidAllowList(defaultCfg(), inside); err == nil || !strings.Contains(err.Error(), "overlaps 10.212.0.0/21") {
		t.Fatalf("control: the intact subnet: %v, want the overlap refused", err)
	}
	for _, field := range []func(*nodecfg.Config, string){
		func(c *nodecfg.Config, s string) { c.PlatformSubnet = s },
		func(c *nodecfg.Config, s string) { c.ProjectBlock = s },
		func(c *nodecfg.Config, s string) { c.IngressSubnet = s },
		func(c *nodecfg.Config, s string) { c.DockerPool = s },
		func(c *nodecfg.Config, s string) { c.BackupSubnet = s },
		func(c *nodecfg.Config, s string) { c.EgressSubnet = s },
	} {
		for _, damaged := range []string{"10.212.0.0/21x", "spl0", "10.212.0.0"} {
			c := defaultCfg()
			field(&c, damaged)
			for _, list := range [][]string{inside, outside} {
				if got, err := ValidAllowList(c, list); err == nil || !strings.Contains(err.Error(), damaged) {
					t.Errorf("subnet %q, list %v: %v, %v; want an error naming the subnet", damaged, list, got, err)
				}
			}
		}
	}
	// An empty egress subnet is the default, not damage.
	if _, err := ValidAllowList(defaultCfg(), outside); err != nil {
		t.Errorf("control: %v", err)
	}
}
