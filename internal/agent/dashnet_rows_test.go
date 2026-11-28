package agent

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// TestNodeCheck_ProxyNetworks_ANameThatIsNoProjects: a network with a slice's
// exact shape whose name only starts like a project's is no project network:
// the proxy on it fails the blocking row.
func TestNodeCheck_ProxyNetworks_ANameThatIsNoProjects(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	x.ensure(t, x.projects(3)...)
	if err := x.networks(); err != nil {
		t.Fatalf("control: as made: %v", err)
	}
	for _, name := range []string{"proj-short", "proj-" + strings.Repeat("A", 20), "proj-" + strings.Repeat("a", 21)} {
		x.f.net(fakeNet{Network: dockerx.Network{Name: name, Internal: true, Subnet: x.a.cfg.Slice(9).String(), BridgeName: nodecfg.BridgeName(9),
			Options: map[string]string{optBridgeName: nodecfg.BridgeName(9), optGatewayMode: "isolated"}}})
		x.f.mu.Lock()
		x.f.ctrs[dashcfg.PgcapName].Nets[name] = x.addr(9)
		x.f.mu.Unlock()
		if err := x.networks(); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("the proxy on %s: %v, want a failure naming it", name, err)
		}
		x.f.mu.Lock()
		delete(x.f.ctrs[dashcfg.PgcapName].Nets, name)
		delete(x.f.nets, name)
		x.f.mu.Unlock()
	}
	if err := x.networks(); err != nil {
		t.Errorf("control: back as made: %v", err)
	}
}

// TestNodeCheck_Proxy_UnopenedPortReasonIsCut: the row quotes the proxy's own
// words for a port it could not open, at most 256 bytes of them and never
// half a character.
func TestNodeCheck_Proxy_UnopenedPortReasonIsCut(t *testing.T) {
	x := newProxyFix(t, "studio.test")
	x.ensure(t, x.projects(3)...)
	reason := "listen: x" + strings.Repeat("é", 400) // two bytes each: the cut falls inside one
	x.pmu.Lock()
	x.log = []string{fmt.Sprintf(`%s {"class":"meta","index":3,"reason":%q}`, stamp(time.Second), reason)}
	x.pmu.Unlock()
	err := x.check()
	if err == nil || !strings.Contains(err.Error(), "slice 3") {
		t.Fatalf("a port not opened: %v", err)
	}
	if n := len(err.Error()); n > 256+200 || !utf8.ValidString(err.Error()) {
		t.Errorf("the row is %d bytes (valid text %v), want the reason cut at 256", n, utf8.ValidString(err.Error()))
	}
}
