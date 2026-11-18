// Package nft renders, loads and checks the node's nftables tables — the network
// boundary between tenants, the host and the platform bridge — keeps the
// bridge-netfilter switches off, and carries the systemd units that load the
// tables before Docker starts.
//
// The ruleset is two tables, "inet supapace" and "bridge supapace", rendered once
// from the node configuration. Every rule carries a comment with its label
// (I1–I2, F1–F4, B1–B4, B6, B8, B9), unique within its chain, so a rule can be
// found by comment.
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

	"github.com/Amphoze/supapace/internal/nodecfg"
)

//go:embed ruleset.tmpl
var rulesetText string

var rulesetTmpl = template.Must(template.New("ruleset").Option("missingkey=error").Parse(rulesetText))

// Render returns the ruleset file for c. Its only input is the gateway's fixed
// platform address; it names no project index and no other address.
func Render(c nodecfg.Config) ([]byte, error) {
	gw, err := netip.ParseAddr(c.GatewayIP)
	if err != nil || !gw.Is4() {
		return nil, fmt.Errorf("nft: gateway_ip %q is not an IPv4 address", c.GatewayIP)
	}
	var b bytes.Buffer
	if err := rulesetTmpl.Execute(&b, struct{ GatewayIP string }{gw.String()}); err != nil {
		return nil, fmt.Errorf("nft: render: %w", err)
	}
	return b.Bytes(), nil
}
