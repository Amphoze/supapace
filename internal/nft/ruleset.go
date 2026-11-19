// Package nft renders, loads and checks the node's nftables tables — the network
// boundary between tenants, the host and the platform bridge — keeps the
// bridge-netfilter switches off, and carries the systemd units that load the
// tables before Docker starts.
//
// The ruleset is two tables, "inet supapace" and "bridge supapace", rendered
// from the node configuration and the off-site endpoint's addresses. Every rule
// carries a comment with its label (I1–I2, F1–F7, B1–B4, B6, B8–B14), unique
// within its chain, so a rule can be found by comment.
//
// The bridge chain drops every frame no rule accepts, on every bridge in the
// network namespace: also on bridges this ruleset does not name, such as other
// software's bridges or Docker's default bridge. Members of such bridges cannot
// reach each other while these tables are loaded.
package nft

import (
	"bytes"
	_ "embed"
	"fmt"
	"net/netip"
	"text/template"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

//go:embed ruleset.tmpl
var rulesetText string

var rulesetTmpl = template.Must(template.New("ruleset").Option("missingkey=error").Parse(rulesetText))

// Render returns the ruleset file for c with an empty off-site set.
func Render(c nodecfg.Config) ([]byte, error) { return RenderWith(c, nil) }

// RenderWith returns the ruleset file for c whose set offsite4 holds the given
// IPv4 address and port pairs, sorted and without duplicates, so the same set
// always renders the same bytes. Its inputs are the gateway's fixed platform
// address, the node's static platform addresses of dashcfg.Static and the
// operator's endpoint; it names no project index and no address that depends
// on a project.
func RenderWith(c nodecfg.Config, offsite []netip.AddrPort) ([]byte, error) {
	gw, err := netip.ParseAddr(c.GatewayIP)
	if err != nil || !gw.Is4() {
		return nil, fmt.Errorf("nft: gateway_ip %q is not an IPv4 address", c.GatewayIP)
	}
	return renderAddrs(gw, dashcfg.Static(c), offsite)
}

// renderAddrs renders the ruleset with the platform bridge's closed list from a.
// A zero member of a is rendered nowhere: its define and every rule naming it
// are left out, and a set keeps only its valid members.
func renderAddrs(gw netip.Addr, a dashcfg.Addrs, offsite []netip.AddrPort) ([]byte, error) {
	set, err := normalize(offsite)
	if err != nil {
		return nil, err
	}
	var pgmeta []netip.Addr
	for _, m := range []netip.Addr{a.PgMeta0, a.PgMeta1} {
		if m.Is4() {
			pgmeta = append(pgmeta, m)
		}
	}
	var metaPorts string
	switch {
	case a.MetaPortLo == 0:
	case a.MetaPortLo == a.MetaPortHi: // nft refuses a range of one
		metaPorts = fmt.Sprint(a.MetaPortLo)
	default:
		metaPorts = fmt.Sprintf("%d-%d", a.MetaPortLo, a.MetaPortHi)
	}
	var rest string
	switch {
	case !a.RestLo.Is4() || !a.RestHi.Is4():
	case a.RestLo == a.RestHi:
		rest = a.RestLo.String()
	default:
		rest = a.RestLo.String() + "-" + a.RestHi.String()
	}
	var b bytes.Buffer
	if err := rulesetTmpl.Execute(&b, struct {
		GatewayIP, RestAddrs, StudioIP, PgcapIP, MetaPorts string
		PgMetaIPs                                          []netip.Addr
		Offsite                                            []netip.AddrPort
	}{gw.String(), rest, addr4(a.Studio), addr4(a.Pgcap), metaPorts, pgmeta, set}); err != nil {
		return nil, fmt.Errorf("nft: render: %w", err)
	}
	return b.Bytes(), nil
}

// addr4 is a's text when it is an IPv4 address, empty otherwise.
func addr4(a netip.Addr) string {
	if !a.Is4() {
		return ""
	}
	return a.String()
}
