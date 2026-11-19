//go:build reach

package nft

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// The platform bridge's closed list, in a bare node: scratch members at the
// default node's fixed addresses, a listener on every listed port and on ports
// beside them. Each listed flow connects; every other pair and port among the
// members times out, and each of those connects once B8 is deleted — the
// ruleset closes the path, not Docker.
func TestClosedList_Flows(t *testing.T) {
	p := node(t)
	isolatedPlatform(t)
	type m struct{ name, ip string }
	ms := []m{
		{"gw", gatewayIP}, {"rest-lo", restIP}, {"rest-hi", "10.212.4.15"}, {"studio", "10.212.0.3"},
		{"pgmeta-0", "10.212.0.4"}, {"pgmeta-1", "10.212.0.5"}, {"pgcap", "10.212.0.6"},
	}
	pid := map[string]int{}
	for _, x := range ms {
		pid[x.name] = member(t, "spnft-cl-"+x.name, "spnft-plat", x.ip)
	}
	ip := func(name string) string {
		for _, x := range ms {
			if x.name == name {
				return x.ip
			}
		}
		t.Fatalf("no member %s", name)
		return ""
	}
	type target struct{ owner, addr string }
	var targets []target
	for _, x := range []struct {
		owner string
		ports []int
	}{
		{"gw", []int{8443}},
		{"rest-lo", []int{3000, 3001}}, {"rest-hi", []int{3000}},
		{"studio", []int{3000, 3001, 8080}},
		{"pgmeta-0", []int{8080, 8081, 3000}}, {"pgmeta-1", []int{8080}},
		{"pgcap", []int{20000, 21023, 19999, 21024, 3000}},
	} {
		for _, port := range x.ports {
			a := fmt.Sprintf("%s:%d", ip(x.owner), port)
			listen(t, pid[x.owner], a)
			targets = append(targets, target{x.owner, a})
		}
	}
	// The four flows of the list, by the rule that accepts each.
	flows := map[string]string{}
	for _, f := range []struct{ rule, from, to string }{
		{"B11", "gw", "rest-lo:3000"}, {"B11", "gw", "rest-hi:3000"},
		{"B12", "gw", "studio:3000"},
		{"B13", "studio", "pgmeta-0:8080"}, {"B13", "studio", "pgmeta-1:8080"},
		{"B14", "pgmeta-0", "pgcap:20000"}, {"B14", "pgmeta-0", "pgcap:21023"},
		{"B14", "pgmeta-1", "pgcap:20000"}, {"B14", "pgmeta-1", "pgcap:21023"},
	} {
		owner, port, _ := strings.Cut(f.to, ":")
		flows[f.from+">"+ip(owner)+":"+port] = f.rule
	}
	sweep := func(when string, want func(rule string) string) {
		for _, from := range ms {
			for _, to := range targets {
				if to.owner == from.name {
					continue
				}
				expect(t, fmt.Sprintf("%s -> %s %s", from.name, to.addr, when), pid[from.name], to.addr, want(flows[from.name+">"+to.addr]))
			}
		}
	}
	sweep("(loaded)", func(rule string) string {
		if rule != "" {
			return "connected"
		}
		return "timeout"
	})
	withDeleted(t, p, []ruleRef{B8}, func() {
		sweep("with B8 deleted", func(string) string { return "connected" })
	})
	for _, del := range []string{"B11", "B12", "B13", "B14"} {
		withDeleted(t, p, ruleRefs(del), func() {
			for k, rule := range flows {
				from, to, _ := strings.Cut(k, ">")
				want := "connected"
				if rule == del {
					want = "timeout"
				}
				expect(t, fmt.Sprintf("%s -> %s with %s deleted", from, to, del), pid[from], to, want)
			}
		})
	}
}

// Every rendering with a zero dashboard input loads as one transaction and
// checks clean, with exactly the rules it renders installed.
func TestClosedList_ZeroInputLoads(t *testing.T) {
	p := node(t)
	defer load(t, p)
	for _, zc := range zeroCases {
		b := zeroRender(t, zc)
		if err := os.WriteFile(p.NftFile(), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := Load(t.Context(), p); err != nil {
			t.Errorf("%s: Load: %v", zc.name, err)
			continue
		}
		if err := Check(t.Context(), p); err != nil {
			t.Errorf("%s: Check: %v", zc.name, err)
		}
		hs := labels(t, "bridge", "forward")
		for _, l := range []string{"B11", "B12", "B13", "B14"} {
			gone := slices.Contains(zc.gone, l)
			if (len(hs[l]) == 0) != gone {
				t.Errorf("%s: %s installed %d times, left out %v", zc.name, l, len(hs[l]), gone)
			}
		}
	}
	b, err := Render(nodecfg.Default("sp.test"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.NftFile(), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// What the list does not name: a stranger from Docker's allocation range opens
// none of the listed flows, nobody reaches it, no listed pair passes UDP, and a
// stranger borrowing Studio's address (IP_FREEBIND, no capability) opens
// nothing. Each negative beside the control that deletes B8.
func TestClosedList_StrangersAndOtherProtocols(t *testing.T) {
	p := node(t)
	isolatedPlatform(t)
	const studio, pgmeta, pgcap, stranger = "10.212.0.3", "10.212.0.4", "10.212.0.6", secondIP
	gw := member(t, "spnft-cl-gw", "spnft-plat", gatewayIP)
	rest := member(t, "spnft-cl-rest", "spnft-plat", restIP)
	st := member(t, "spnft-cl-studio", "spnft-plat", studio)
	pm := member(t, "spnft-cl-pgmeta", "spnft-plat", pgmeta)
	pc := member(t, "spnft-cl-pgcap", "spnft-plat", pgcap)
	sx := member(t, "spnft-cl-stranger", "spnft-plat", stranger)
	listen(t, rest, restIP+":3000")
	listen(t, st, studio+":3000")
	listen(t, pm, pgmeta+":8080")
	listen(t, pc, pgcap+":20000")
	listen(t, sx, stranger+":3000")
	listen(t, sx, stranger+":20000")
	listen(t, sx, stranger+":8080")
	listen(t, pc, pgcap+":8080")
	got := receiver(t, rest, restIP+":3000")

	expect(t, "gateway -> PostgREST :3000 (listed)", gw, restIP+":3000", "connected")
	for _, a := range []string{restIP + ":3000", studio + ":3000", pgmeta + ":8080", pgcap + ":20000"} {
		expect(t, "stranger -> "+a, sx, a, "timeout")
	}
	expect(t, "gateway -> stranger :3000 (outside the PostgREST range)", gw, stranger+":3000", "timeout")
	expect(t, "postgres-meta -> stranger on a meta port (not the proxy)", pm, stranger+":20000", "timeout")
	expect(t, "Studio -> stranger :8080 (not postgres-meta)", st, stranger+":8080", "timeout")
	expect(t, "Studio -> proxy :8080 (not postgres-meta)", st, pgcap+":8080", "timeout")
	expect(t, "gateway -> Studio :3000 (listed)", gw, studio+":3000", "connected")
	expect(t, "Studio -> postgres-meta :8080 (listed)", st, pgmeta+":8080", "connected")
	expect(t, "postgres-meta -> proxy :20000 (listed)", pm, pgcap+":20000", "connected")
	tsend(t, gw, restIP+":3000", "-", 5)
	if got(2 * time.Second) {
		t.Error("gateway -> PostgREST :3000 over UDP: delivered")
	}
	o, _, code, err := exe(nil, append([]string{"env", helperEnv + "=1"}, asTenant(sx, self(t), "spoof", "tcp", pgmeta+":8080", studio)...)...)
	if err != nil || code == 0 || strings.HasPrefix(o, "connected") {
		t.Errorf("stranger with Studio's source address -> postgres-meta: %q exit %d %v", o, code, err)
	}
	withDeleted(t, p, []ruleRef{B8}, func() {
		for _, a := range []string{restIP + ":3000", studio + ":3000", pgmeta + ":8080", pgcap + ":20000"} {
			expect(t, "control: stranger -> "+a+" with B8 deleted", sx, a, "connected")
		}
		expect(t, "control: gateway -> stranger :3000 with B8 deleted", gw, stranger+":3000", "connected")
		expect(t, "control: postgres-meta -> stranger :20000 with B8 deleted", pm, stranger+":20000", "connected")
		expect(t, "control: Studio -> stranger :8080 with B8 deleted", st, stranger+":8080", "connected")
		expect(t, "control: Studio -> proxy :8080 with B8 deleted", st, pgcap+":8080", "connected")
		tsend(t, gw, restIP+":3000", "-", 5)
		if !got(2 * time.Second) {
			t.Error("control: gateway -> PostgREST :3000 over UDP with B8 deleted: nothing arrived")
		}
	})
}
