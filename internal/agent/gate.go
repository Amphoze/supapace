package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// refuse is the gate's error: ErrContainment, the reason, and the cause when
// there is one (so a caller can still tell a deadline from a violation).
func refuse(cause error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if cause != nil {
		return fmt.Errorf("%w: %s: %w", ErrContainment, msg, cause)
	}
	return fmt.Errorf("%w: %s", ErrContainment, msg)
}

// CheckContainment is the start gate, called immediately before every run or
// start of a tenant container. It refuses with ErrContainment unless all of
// these hold:
//
//  1. the bridge-nf switches are off and nft.Check verifies our tables;
//  2. proj-<ref> is ours: internal, IPv6 off, bridge spp<i>, the slice as
//     subnet, isolated gateway mode, and the bridge interface is a bridge
//     holding no address but an IPv6 link-local one;
//  3. platform is ours (internal, IPv6 off, bridge spl0, isolated, its
//     interface as in 2) and no container but postgrest-<ref> holds
//     PlatformAddr(i) on it; postgrest-<ref>, when attached, holds exactly
//     that address;
//  4. neither pg-<ref> nor postgrest-<ref>, where it exists, has a restart
//     policy or shares the host's or another container's network namespace;
//  5. the node is not containment_failed;
//  6. no member of proj-<ref>, platform or ingress, nor pg-<ref> or
//     postgrest-<ref>, nor any container sharing the network namespace of
//     one of them or of the host, is privileged, runs without --cap-drop
//     ALL, or adds any capability.
//
// It takes the spec, not a container name: conditions 3, 4 and 6 cover both
// tenant containers whenever each exists. Everything is read from Docker's
// record of container configuration and from the host; nothing from a
// tenant process. Any error on the way is a refusal.
func (a *Agent) CheckContainment(ctx context.Context, s Spec) error {
	if err := s.valid(a.cfg); err != nil {
		return err
	}
	if a.ContainmentFailed() {
		return refuse(nil, "node is containment_failed")
	}
	if err := ensureBridgeNF(); err != nil {
		return refuse(err, "bridge-nf switches")
	}
	if err := nftCheck(ctx, a.p); err != nil {
		return refuse(err, "nftables")
	}
	return a.checkProject(ctx, s)
}

// CheckAdopted evaluates conditions 2 to 6 for a running tenant being
// adopted; condition 1 is the caller's, established for the whole node.
func (a *Agent) CheckAdopted(ctx context.Context, s Spec) error {
	if err := s.valid(a.cfg); err != nil {
		return err
	}
	if a.ContainmentFailed() {
		return refuse(nil, "node is containment_failed")
	}
	return a.checkProject(ctx, s)
}

// checkProject is conditions 2, 3, 4 and 6.
func (a *Agent) checkProject(ctx context.Context, s Spec) error {
	i := s.SubnetIndex
	// 2: the project network, from Docker and from the interface itself.
	pn, err := dockerInspectNetwork(ctx, networkName(s.Ref))
	if err != nil {
		return refuse(err, "inspect %s", networkName(s.Ref))
	}
	if pn == nil {
		return refuse(nil, "%s absent", networkName(s.Ref))
	}
	if why := a.projectNetMismatch(pn, i); why != "" {
		return refuse(nil, "%s: %s", networkName(s.Ref), why)
	}
	if err := refuseIPv6(ctx, networkName(s.Ref)); err != nil {
		return err
	}
	if err := a.checkBridgeIface(ctx, nodecfg.BridgeName(i)); err != nil {
		return err
	}
	// 3: the platform network.
	plat, err := dockerInspectNetwork(ctx, platformNet)
	if err != nil {
		return refuse(err, "inspect %s", platformNet)
	}
	if plat == nil {
		return refuse(nil, "%s absent", platformNet)
	}
	if why := platformNetMismatch(plat); why != "" {
		return refuse(nil, "%s: %s", platformNet, why)
	}
	if err := refuseIPv6(ctx, platformNet); err != nil {
		return err
	}
	if err := a.checkBridgeIface(ctx, nodecfg.PlatformBridge); err != nil {
		return err
	}
	ing, err := dockerInspectNetwork(ctx, ingressNet)
	if err != nil {
		return refuse(err, "inspect %s", ingressNet)
	}
	// The tenant containers, running or not, and every member, all read by
	// id: Docker resolves a full id before a name, so a member named like
	// another container's id would otherwise be judged by that container.
	nets := []string{networkName(s.Ref), platformNet}
	if ing != nil {
		nets = append(nets, ingressNet)
	}
	var ids []string
	for _, n := range nets {
		m, err := memberIDs(ctx, n)
		if err != nil {
			return refuse(err, "members of %s", n)
		}
		ids = append(ids, m...)
	}
	tenantNames := []string{clusterName(s.Ref), postgrestName(s.Ref)}
	for _, n := range tenantNames {
		c, err := dockerInspectContainer(ctx, n)
		if err != nil {
			return refuse(err, "inspect %s", n)
		}
		if c != nil {
			ids = append(ids, c.ID)
		}
	}
	slices.Sort(ids)
	confs, err := inspectConfigs(ctx, slices.Compact(ids))
	if err != nil {
		return refuse(err, "read container configuration")
	}
	addr := a.cfg.PlatformAddr(i).String()
	for _, c := range confs {
		// 6
		if why := c.capViolation(); why != "" {
			return refuse(nil, "%s: %s", c.name(), why)
		}
		// 4
		if slices.Contains(tenantNames, c.name()) {
			if c.Restart != "" && c.Restart != "no" {
				return refuse(nil, "%s has restart policy %q", c.name(), c.Restart)
			}
			if c.NetMode == "host" || strings.HasPrefix(c.NetMode, "container:") {
				return refuse(nil, "%s has network mode %q", c.name(), c.NetMode)
			}
		}
		// 3
		held, attached := c.addr(platformNet)
		switch {
		case c.name() == postgrestName(s.Ref):
			if attached && held != addr {
				return refuse(nil, "%s holds %s on %s, want %s", c.name(), held, platformNet, addr)
			}
		case attached && held == addr:
			return refuse(nil, "%s holds %s on %s", c.name(), addr, platformNet)
		}
	}
	// 6 for the containers that are on no member list: those sharing the
	// network namespace of a container judged above, or the host's.
	sharers, err := namespaceSharers(ctx, confs)
	if err != nil {
		return refuse(err, "list containers sharing a network namespace")
	}
	more, err := inspectConfigs(ctx, sharers)
	if err != nil {
		return refuse(err, "read container configuration")
	}
	for _, c := range more {
		if why := c.capViolation(); why != "" {
			return refuse(nil, "%s (network mode %q): %s", c.name(), c.NetMode, why)
		}
	}
	return nil
}

// refuseIPv6 refuses the network name when Docker records IPv6 as enabled
// on it (or the flag cannot be read).
func refuseIPv6(ctx context.Context, name string) error {
	out, err := dockerRun(ctx, "network", "inspect", "--format", "{{json .EnableIPv6}}", "--", name)
	if err != nil {
		return refuse(err, "inspect %s", name)
	}
	var on bool
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &on); err != nil {
		return refuse(err, "%s: IPv6 flag unreadable", name)
	}
	if on {
		return refuse(nil, "%s has IPv6 enabled", name)
	}
	return nil
}

// modeFormat reads a container's id, name and network mode (the name only
// keeps each record self-describing; sharers are matched by id).
const modeFormat = `{{json .Id}} {{json .Name}} {{json .HostConfig.NetworkMode}}`

type netMode struct{ id, mode string }

// namespaceSharers returns the ids of every container whose network mode is
// "host" or "container:<id>" of one of members or, in turn, of such a
// container (Docker records the full id, also when given a name). All containers are listed once; when that read fails (one
// may go between the listing and the read) they are listed once more.
func namespaceSharers(ctx context.Context, members []ctrConf) ([]string, error) {
	modes, err := networkModes(ctx)
	if err != nil {
		if modes, err = networkModes(ctx); err != nil {
			return nil, err
		}
	}
	joined := map[string]bool{}
	for _, c := range members {
		joined[c.ID] = true
	}
	var out []string
	for grew := true; grew; {
		grew = false
		for _, m := range modes {
			target, shares := strings.CutPrefix(m.mode, "container:")
			if !joined[m.id] && (m.mode == "host" || shares && joined[target]) {
				joined[m.id] = true
				out = append(out, m.id)
				grew = true
			}
		}
	}
	return out, nil
}

// memberIDs returns the ids of the containers attached to network name, as
// Docker's own endpoint keys (a full id each; anything else is an error).
func memberIDs(ctx context.Context, name string) ([]string, error) {
	out, err := dockerRun(ctx, "network", "inspect", "--format", "{{json .Containers}}", "--", name)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(out))
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("docker network inspect: parse: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("docker network inspect: trailing data")
	}
	ids := make([]string, 0, len(m))
	for id := range m {
		if !fullID.MatchString(id) {
			return nil, fmt.Errorf("docker network inspect: member key %q is not a container id", id)
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

var fullID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// networkModes lists every container (running or not) with its network mode.
func networkModes(ctx context.Context) ([]netMode, error) {
	out, err := dockerRun(ctx, "ps", "-a", "-q", "--no-trunc")
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(out)
	if len(ids) == 0 {
		return nil, nil
	}
	out, err = dockerRun(ctx, append([]string{"container", "inspect", "--format", modeFormat, "--"}, ids...)...)
	if err != nil {
		return nil, err
	}
	var modes []netMode
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var m netMode
		var name string // read so that every record has exactly its three values
		dec := json.NewDecoder(strings.NewReader(line))
		for _, v := range []*string{&m.id, &name, &m.mode} {
			if err := dec.Decode(v); err != nil {
				return nil, fmt.Errorf("docker container inspect: parse: %w", err)
			}
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, fmt.Errorf("docker container inspect: trailing data in %q", line)
		}
		modes = append(modes, m)
	}
	if len(modes) != len(ids) {
		return nil, fmt.Errorf("docker container inspect: %d records for %d containers", len(modes), len(ids))
	}
	return modes, nil
}

// projectNetMismatch says why n is not the project network of slice i, or "".
func (a *Agent) projectNetMismatch(n *dockerx.Network, i int) string {
	switch {
	case !n.Internal:
		return "not internal"
	case n.BridgeName != nodecfg.BridgeName(i):
		return fmt.Sprintf("bridge %q, want %q", n.BridgeName, nodecfg.BridgeName(i))
	case !samePrefix(n.Subnet, a.cfg.Slice(i)):
		return fmt.Sprintf("subnet %q, want %s", n.Subnet, a.cfg.Slice(i))
	case n.Options[optGatewayMode] != "isolated":
		return "gateway mode not isolated"
	}
	return ""
}

func platformNetMismatch(n *dockerx.Network) string {
	switch {
	case !n.Internal:
		return "not internal"
	case n.BridgeName != nodecfg.PlatformBridge:
		return fmt.Sprintf("bridge %q, want %q", n.BridgeName, nodecfg.PlatformBridge)
	case n.Options[optGatewayMode] != "isolated":
		return "gateway mode not isolated"
	}
	return ""
}

// netPrefix parses a configured prefix; the zero Prefix (which matches
// nothing) when it does not parse.
func netPrefix(s string) netip.Prefix {
	p, _ := netip.ParsePrefix(s)
	return p
}

func samePrefix(s string, want netip.Prefix) bool {
	p, err := netip.ParsePrefix(s)
	return err == nil && want.IsValid() && p == want
}

// checkBridgeIface confirms on the interface itself (`ip -j -d addr show
// dev NAME`) that it is a bridge holding no address but IPv6 link-local
// ones. `ip link` would show no addresses at all, so it would prove nothing.
func (a *Agent) checkBridgeIface(ctx context.Context, name string) error {
	out, err := runIP(ctx, "-j", "-d", "addr", "show", "dev", name)
	if err != nil {
		return refuse(err, "interface %s", name)
	}
	var ifs []struct {
		IfName   string `json:"ifname"`
		LinkInfo struct {
			InfoKind string `json:"info_kind"`
		} `json:"linkinfo"`
		AddrInfo []struct {
			Family string `json:"family"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(out, &ifs); err != nil {
		return refuse(err, "interface %s: unreadable", name)
	}
	if len(ifs) != 1 || ifs[0].IfName != name {
		return refuse(nil, "interface %s: not found", name)
	}
	if ifs[0].LinkInfo.InfoKind != "bridge" {
		return refuse(nil, "interface %s is of kind %q, not a bridge", name, ifs[0].LinkInfo.InfoKind)
	}
	for _, ai := range ifs[0].AddrInfo {
		if ai.Family != "inet6" || ai.Scope != "link" {
			return refuse(nil, "interface %s holds a %s address of scope %q", name, ai.Family, ai.Scope)
		}
	}
	return nil
}

// ctrConf is a container's configuration as Docker recorded it at create
// time (plus its running state and actual addresses).
type ctrConf struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Running    bool              `json:"running"`
	Privileged bool              `json:"privileged"`
	CapAdd     []string          `json:"cap_add"`
	CapDrop    []string          `json:"cap_drop"`
	Restart    string            `json:"restart"`
	NetMode    string            `json:"netmode"`
	Labels     map[string]string `json:"labels"`
	Networks   map[string]struct {
		IPAMConfig *struct {
			IPv4Address string
		}
		IPAddress string
	} `json:"networks"`
}

const confFormat = `{"id":{{json .Id}},"name":{{json .Name}},"running":{{json .State.Running}},` +
	`"privileged":{{json .HostConfig.Privileged}},"cap_add":{{json .HostConfig.CapAdd}},"cap_drop":{{json .HostConfig.CapDrop}},` +
	`"restart":{{json .HostConfig.RestartPolicy.Name}},"netmode":{{json .HostConfig.NetworkMode}},"labels":{{json .Config.Labels}},"networks":{{json .NetworkSettings.Networks}}}`

func (c ctrConf) name() string { return strings.TrimPrefix(c.Name, "/") }

// addr is the container's address on network n: the configured one when set
// (a created, not yet started container has no other), else the actual one.
func (c ctrConf) addr(n string) (string, bool) {
	e, ok := c.Networks[n]
	if !ok {
		return "", false
	}
	if e.IPAMConfig != nil && e.IPAMConfig.IPv4Address != "" {
		return e.IPAMConfig.IPv4Address, true
	}
	return e.IPAddress, true
}

// capViolation says why the container could hold a capability, or "": the
// platform drops all of them and adds none, anywhere.
func (c ctrConf) capViolation() string {
	switch {
	case c.Privileged:
		return "privileged"
	case !slices.ContainsFunc(c.CapDrop, func(s string) bool { return strings.TrimPrefix(strings.ToUpper(s), "CAP_") == "ALL" }):
		return "capabilities not dropped"
	case len(c.CapAdd) > 0:
		return "adds capabilities " + strings.Join(c.CapAdd, ",")
	}
	return ""
}

// inspectConfigs reads the configuration of each named container in one
// call. When that fails, a container that has gone since it was listed is
// dropped and the rest read once more; a missing container is never a
// failure.
func inspectConfigs(ctx context.Context, names []string) ([]ctrConf, error) {
	confs, err := readConfs(ctx, names)
	if err == nil {
		return confs, nil
	}
	var keep []string
	for _, n := range names {
		c, ierr := dockerInspectContainer(ctx, n)
		if ierr != nil {
			return nil, ierr
		}
		if c != nil {
			keep = append(keep, n)
		}
	}
	if len(keep) == len(names) {
		return nil, err
	}
	return readConfs(ctx, keep)
}

func readConfs(ctx context.Context, names []string) ([]ctrConf, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out, err := dockerRun(ctx, append([]string{"container", "inspect", "--format", confFormat, "--"}, names...)...)
	if err != nil {
		return nil, err
	}
	var confs []ctrConf
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var c ctrConf
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			return nil, fmt.Errorf("docker container inspect: parse: %w", err)
		}
		confs = append(confs, c)
	}
	if len(confs) != len(names) {
		return nil, fmt.Errorf("docker container inspect: %d records for %d containers", len(confs), len(names))
	}
	return confs, nil
}
