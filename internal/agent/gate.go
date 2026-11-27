package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
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
//     ALL, or adds any capability;
//  7. proj-<ref> holds at most pg-<ref>, postgrest-<ref> and, on a node
//     whose dashboard is configured, sp-pgcap, each at its address there,
//     and nothing else, whatever its capabilities (memberViolation); and
//     each of the dashboard's addresses on platform is held by its own
//     container or by none.
//
// It takes the spec, not a container name: conditions 3, 4, 6 and 7 cover
// both tenant containers whenever each exists. Everything is read from Docker's
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
// adopted; condition 1 is the caller's, established for the whole node. A
// fact that could not be read gives a refusal that also matches
// ErrCheckIncomplete; any other refusal is a completed check's finding.
func (a *Agent) CheckAdopted(ctx context.Context, s Spec) error {
	if err := s.valid(a.cfg); err != nil {
		return err
	}
	if a.ContainmentFailed() {
		return refuse(nil, "node is containment_failed")
	}
	return a.checkProject(ctx, s)
}

// checkProject is conditions 2, 3, 4, 6 and 7.
func (a *Agent) checkProject(ctx context.Context, s Spec) error {
	i := s.SubnetIndex
	// 2: the project network, from Docker and from the interface itself.
	pn, err := dockerInspectNetwork(ctx, networkName(s.Ref))
	if err != nil {
		return refuse(incomplete{err}, "inspect %s", networkName(s.Ref))
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
		return refuse(incomplete{err}, "inspect %s", platformNet)
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
		return refuse(incomplete{err}, "inspect %s", ingressNet)
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
			return refuse(incomplete{err}, "inspect %s", n)
		}
		if c != nil {
			ids = append(ids, c.ID)
		}
	}
	slices.Sort(ids)
	confs, err := inspectConfigs(ctx, slices.Compact(ids))
	if err != nil {
		return refuse(incomplete{err}, "read container configuration")
	}
	addr := a.cfg.PlatformAddr(i).String()
	fixed := dashMembers(dashcfg.Static(a.cfg))
	for _, c := range confs {
		// 6
		if why := c.capViolation(); why != "" {
			return refuse(nil, "%s: %s", c.name(), why)
		}
		// 7
		if why := a.memberViolation(c, s.Ref, i); why != "" {
			return refuse(nil, "%s", why)
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
		for _, m := range fixed { // 7
			if attached && held == m.addr && c.name() != m.name {
				return refuse(nil, "%s holds %s on %s, the address of %s", c.name(), held, platformNet, m.name)
			}
		}
	}
	// 6 for the containers that are on no member list: those sharing the
	// network namespace of a container judged above, or the host's.
	sharers, err := namespaceSharers(ctx, confs)
	if err != nil {
		return refuse(incomplete{err}, "list containers sharing a network namespace")
	}
	more, err := inspectConfigs(ctx, sharers)
	if err != nil {
		return refuse(incomplete{err}, "read container configuration")
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
		return refuse(incomplete{err}, "inspect %s", name)
	}
	var on bool
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &on); err != nil {
		return refuse(incomplete{err}, "%s: IPv6 flag unreadable", name)
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
// Docker's own endpoint keys. While a container's endpoint is not joined to
// it (as it starts, or is connected while running), Docker lists the
// endpoint under "ep-<endpoint id>" for a moment. The listing is then read
// again, at most memberRereads times memberReread apart, until every such
// key of the first read is gone, and the ids of all reads are returned (one
// that left meanwhile is skipped where its configuration is read). The
// decision rests on Docker's keys alone: an endpoint key still listed after
// the last read is an unidentified member and refused, any other key that is
// not a full id at once. A failed read, or a context that ends while
// waiting, is ErrCheckIncomplete.
func memberIDs(ctx context.Context, name string) ([]string, error) {
	ids, eps, err := readMembers(ctx, name)
	for try := 0; err == nil && len(eps) > 0; try++ {
		if try == memberRereads {
			k := slices.Sorted(maps.Keys(eps))[0]
			return nil, fmt.Errorf("docker network inspect %s: member key %q (endpoint name %q) is an endpoint without a container, still listed after %d re-reads %v apart: unidentified member",
				name, k, eps[k], memberRereads, memberReread)
		}
		select {
		case <-ctx.Done():
			return nil, incomplete{fmt.Errorf("docker network inspect: re-reading endpoint keys: %w", ctx.Err())}
		case <-time.After(memberReread):
		}
		var more []string
		var again map[string]string
		more, again, err = readMembers(ctx, name)
		ids = append(ids, more...)
		for k := range eps {
			if _, still := again[k]; !still {
				delete(eps, k)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// readMembers reads network name's member keys once: the full ids, and the
// endpoint keys with the endpoint name Docker lists for each.
func readMembers(ctx context.Context, name string) (ids []string, eps map[string]string, err error) {
	out, err := dockerRun(ctx, "network", "inspect", "--format", "{{json .Containers}}", "--", name)
	if err != nil {
		return nil, nil, incomplete{err}
	}
	var m map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(out))
	if err := dec.Decode(&m); err != nil {
		return nil, nil, incomplete{fmt.Errorf("docker network inspect: parse: %w", err)}
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, incomplete{fmt.Errorf("docker network inspect: trailing data")}
	}
	eps = map[string]string{}
	for k, v := range m {
		switch {
		case fullID.MatchString(k):
			ids = append(ids, k)
		case endpointKey.MatchString(k):
			var e struct{ Name string }
			if err := json.Unmarshal(v, &e); err != nil {
				return nil, nil, incomplete{fmt.Errorf("docker network inspect: parse %q: %w", k, err)}
			}
			eps[k] = e.Name
		default:
			return nil, nil, fmt.Errorf("docker network inspect: member key %q is not a container id", k)
		}
	}
	return ids, eps, nil
}

var (
	fullID      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	endpointKey = regexp.MustCompile(`^ep-[0-9a-f]{64}$`) // Docker's key for an endpoint not joined to a container
)

// The re-reads of a member listing that holds endpoint keys. Measured on
// Docker 29: such a key lasts under 0.4 s per container while up to 64
// containers start at once, and under 0.9 s with every core busy; one to
// three of the 5 re-reads 200 ms apart were needed. A slow daemon stretches
// the window with it, since the bound counts re-reads.
const memberRereads = 5

var memberReread = 200 * time.Millisecond

// ErrCheckIncomplete marks a containment check that could not be completed:
// a fact it needed could not be read (Docker did not answer, an answer did
// not parse, the context ended). It is not a finding. A gate refusal
// carrying it still matches ErrContainment: nothing is started on it.
var ErrCheckIncomplete = errors.New("agent: containment check incomplete")

// incomplete marks err as a fact that could not be read (ErrCheckIncomplete);
// its text is err's.
type incomplete struct{ error }

func (e incomplete) Unwrap() error      { return e.error }
func (incomplete) Is(target error) bool { return target == ErrCheckIncomplete }

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
	if err != nil { // the interface could not be read: not a finding about it
		return refuse(incomplete{err}, "interface %s", name)
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
	Sysctls    map[string]string `json:"sysctls"`
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
	`"restart":{{json .HostConfig.RestartPolicy.Name}},"netmode":{{json .HostConfig.NetworkMode}},"labels":{{json .Config.Labels}},"networks":{{json .NetworkSettings.Networks}},` +
	// Docker leaves Sysctls out of a container that has none: index, not a
	// field, which would fail the whole read.
	`"sysctls":{{json (index .HostConfig "Sysctls")}}}`

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

// memberViolation says why container c may not be on the project network of
// ref (slice i) as Docker records it, or "": that network holds pg-<ref> at
// the cluster's address, postgrest-<ref> at the REST address and, on a node
// whose dashboard is configured, sp-pgcap at the proxy's address — at most
// those, each there, and nothing else. A member's capabilities do not enter
// into it. The text names the member, its address on this network and what
// the network may hold, nothing of another network.
func (a *Agent) memberViolation(c ctrConf, ref string, i int) string {
	net := networkName(ref)
	held, on := c.addr(net)
	if !on {
		return ""
	}
	type slot struct {
		name string
		addr netip.Addr
	}
	may := []slot{{clusterName(ref), a.cfg.ClusterAddr(i)}, {postgrestName(ref), a.cfg.PostgRESTAddr(i)}}
	if _, dash, _ := a.dashAddrs(); dash {
		may = append(may, slot{dashcfg.PgcapName, dashcfg.ProxyAddr(a.cfg, i)})
	}
	var list []string
	for _, m := range may {
		if c.name() == m.name && held == m.addr.String() {
			return ""
		}
		list = append(list, m.name+" at "+m.addr.String())
	}
	return fmt.Sprintf("%s: member rule: %s is on it at %q; it may hold only %s", net, c.name(), held, strings.Join(list, ", "))
}

// dashMember is one of the dashboard's containers on platform: its role
// label and the address that it alone may hold there.
type dashMember struct{ name, role, addr string }

// dashMembers lists the dashboard's containers at the addresses of ad. An
// address the configuration cannot state (zero in dashcfg.Static) reads
// "invalid IP" here, which no container holds.
func dashMembers(ad dashcfg.Addrs) []dashMember {
	return []dashMember{{dashcfg.StudioName, "studio", ad.Studio.String()}, {dashcfg.PgMeta0Name, "pgmeta", ad.PgMeta0.String()},
		{dashcfg.PgMeta1Name, "pgmeta", ad.PgMeta1.String()}, {dashcfg.PgcapName, "pgcap", ad.Pgcap.String()}}
}
