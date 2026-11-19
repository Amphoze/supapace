// Package poolcfg holds the connection pooler's node constants, its platform
// addresses and port range, the connection arithmetic every other package
// takes its figures from, and the document that registers a project with the
// pooler. It computes; it reads no clock, socket or file.
package poolcfg

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// The table of figures. A figure that moves is changed here, and
// the tests recompute every derived one from its rule.
const (
	PoolerUID, PlatformDBUID           = 65526, 65525 // each also its gid; below the dashboard's 65527–65529
	PoolerName, PlatformDBName         = "sp-pooler", "sp-platform-db"
	SessionPort, TxnPort, AdminPort    = 5432, 6543, 4000  // Supavisor's own
	PoolPortBase                       = 24096             // the proxy's class "pooler": PoolPortBase + subnet index
	ManagerRole                        = "supapace_pooler" // also the name of the helper's schema
	AuthQuery                          = "SELECT * FROM supapace_pooler.get_auth($1)"
	RegistryDB, RegistryRole           = "supavisor", "supavisor_meta"
	SecretManagerPassword              = "pg.supapace_pooler.password"
	DefaultPoolSize, DefaultMaxClients = 5, 100
	// TierReserved is every consumer of a cluster's connections but the
	// pooler, at the default tier: Realtime 14, Storage 10, PostgREST 11,
	// postgres-meta 5, scheduled jobs 0 (they hold background workers), the
	// backup worker 2, the agent 3, reserved 3, and 2.
	TierReserved      = 50
	CancelsPerProject = 2
	// ProxyFixedConns: class "meta" 32 and its cancels 16, and the two pools
	// of refusals in flight, 16 and 48.
	ProxyFixedConns              = 112
	DefaultProxyMaxConns         = 2128 // 28 × ProjectConns(Allowance(120)) + ProxyFixedConns
	ScramIterMax                 = 32768
	SourceConnMax                = 64   // concurrent connections from one source address to the pooler's two ports
	EgressFlowMax                = 4096 // tracked flows of one cluster with outbound network; a default until measured
	PoolerMemMB, PlatformDBMemMB = 1024, 256
	SliceHold                    = 25 * time.Hour // the pooler's 24 h caches and an hour
)

// RestrictionsOffered says whether network restrictions are offered to
// projects. It stays false until the address-preserving path is proven.
var RestrictionsOffered = false

// ClassValues is the proxy's class "pooler" as plain numbers.
type ClassValues struct {
	CancelsPerProject, CancelMS, ConnsPerSecond, ConnsBurst, RefusalsMax, CopyBufBytes, SockBufBytes,
	DialMS, AuthMS, ScramIterMax, ParamStatusMax, RowFieldsMax, NoticesMax int
}

var PoolClass = ClassValues{2, 5000, 7, 70, 48, 16384, 16384, 3000, 10000, 32768, 64, 1664, 64}

// Addrs are the pooler's and the platform database's addresses and the
// pooler class's port range on a node.
type Addrs struct {
	PlatformDB, Pooler, PoolerIngress netip.Addr
	PoolPortLo, PoolPortHi            int
}

// pooledUIDs are the two uids no project uid range may contain.
var pooledUIDs = []int{PlatformDBUID, PoolerUID}

// For returns the node's pooler addresses and port range, or the joined
// refusals of a configuration that cannot host the pooler: a network that is
// not IPv4, an address outside its subnet, a gateway address that is one of
// the three, an allocation range containing a platform address, a port range
// past 65535, or a project uid range containing one of the two uids. It
// assumes nodecfg's validation passed.
func For(c nodecfg.Config) (Addrs, error) {
	a, errs := compute(c)
	if c.UIDCount > 0 {
		lo, hi := int64(c.UIDBase), int64(c.UIDBase)+int64(c.UIDCount)-1
		for _, u := range pooledUIDs {
			if lo <= int64(u) && int64(u) <= hi {
				errs = append(errs, fmt.Errorf("uid_base/uid_count: the project uid range %d-%d contains the pooler uid %d", lo, hi, u))
			}
		}
	}
	if len(errs) > 0 {
		return Addrs{}, errors.Join(errs...)
	}
	return a, nil
}

// Static never fails or panics: it returns For's addresses and port range
// with the zero value for every member For refuses (ports 0-0), so a renderer
// that must not fail (the ruleset) omits what it cannot state and never names
// an address that belongs to something else. Where For accepts, it equals For.
// A server is given For's value.
func Static(c nodecfg.Config) Addrs {
	a, _ := compute(c)
	return a
}

// compute is the members — the platform subnet's base plus 7 and plus 8, the
// ingress subnet's base plus 3, the port range — each zero when refused, and
// the refusals that concern them.
func compute(c nodecfg.Config) (Addrs, []error) {
	var a Addrs
	var errs []error
	plat, perr := v4(c.PlatformSubnet)
	ingress, ierr := v4(c.IngressSubnet)
	if perr != nil {
		errs = append(errs, fmt.Errorf("platform_subnet: %q is not an IPv4 network", c.PlatformSubnet))
	}
	if ierr != nil {
		errs = append(errs, fmt.Errorf("ingress_subnet: %q is not an IPv4 network", c.IngressSubnet))
	}
	gw, _ := netip.ParseAddr(c.GatewayIP)
	gwi, _ := netip.ParseAddr(c.GatewayIngressIP)
	rng, rerr := netip.ParsePrefix(c.PlatformIPRange)
	for _, m := range []struct {
		dst    *netip.Addr
		ok     bool
		within netip.Prefix
		off    uint32
		field  string
	}{{&a.PlatformDB, perr == nil, plat, 7, "platform_subnet"}, {&a.Pooler, perr == nil, plat, 8, "platform_subnet"},
		{&a.PoolerIngress, ierr == nil, ingress, 3, "ingress_subnet"}} {
		if !m.ok {
			continue // the network itself is refused above
		}
		addr, refused := addOffset(m.within.Addr(), m.off), false
		refuse := func(err error) { errs, refused = append(errs, err), true }
		if !m.within.Contains(addr) {
			refuse(fmt.Errorf("%s: %s cannot hold the pooler address %s", m.field, m.within, addr))
		}
		if addr == gw {
			refuse(fmt.Errorf("gateway_ip: %s is a pooler address", gw))
		}
		if addr == gwi {
			refuse(fmt.Errorf("gateway_ingress_ip: %s is a pooler address", gwi))
		}
		if m.field == "platform_subnet" && rerr == nil && rng.Contains(addr) {
			refuse(fmt.Errorf("platform_ip_range: %s contains the pooler address %s", rng, addr))
		}
		if !refused {
			*m.dst = addr
		}
	}
	var err error
	if a.PoolPortLo, a.PoolPortHi, err = portRange(c.Slices()); err != nil {
		errs = append(errs, err)
	}
	return a, errs
}

// portRange is the pool ports of n slices, or 0-0 and an error when there is
// no slice or n slices would pass 65535.
func portRange(n int) (lo, hi int, err error) {
	if n < 1 {
		return 0, 0, fmt.Errorf("project_block/slice_prefix: no project slice")
	}
	if n > 65535-PoolPortBase+1 {
		return 0, 0, fmt.Errorf("project_block/slice_prefix: %d slices take the pool ports %d+ past 65535", n, PoolPortBase)
	}
	return PoolPortBase, PoolPortBase + n - 1, nil
}

// v4 is s as a masked IPv4 network.
func v4(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, errors.New("not IPv4")
	}
	return p.Masked(), nil
}

// addOffset adds off to a, wrapping within IPv4.
func addOffset(a netip.Addr, off uint32) netip.Addr {
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) + off
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// PoolPort is the proxy's pooler-class port of project slice subnetIndex.
func PoolPort(subnetIndex int) int { return PoolPortBase + subnetIndex }

var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// refRE is a project ref's shape, which a label must not have.
var refRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

// ValidLabel accepts the pooler zone's label: one DNS label of [a-z0-9-],
// 1 to 63 characters, no dash at either end, and not shaped like a ref.
func ValidLabel(label string) error {
	if !labelRE.MatchString(label) {
		return fmt.Errorf("poolcfg: pooler label %q is not a DNS label of [a-z0-9-]", label)
	}
	if refRE.MatchString(label) {
		return fmt.Errorf("poolcfg: pooler label %q has the shape of a project ref", label)
	}
	return nil
}

// Zone is the pooler's zone, "<label>.<domain>".
func Zone(domain, label string) string { return label + "." + domain }

// Host is a project's pooler name, "<ref>.<label>.<domain>".
func Host(domain, label, ref string) string { return ref + "." + Zone(domain, label) }

// ConnString is a project's pooled connection string for login. It never
// carries a password.
func ConnString(domain, label, ref, login string, port int) string {
	return "postgresql://" + login + "." + ref + "@" + Host(domain, label, ref) + ":" + strconv.Itoa(port) +
		"/postgres?sslmode=verify-full"
}

// ProxyWanted says whether a node runs the wire proxy: it has a studio domain
// or a pooler label.
func ProxyWanted(studioDomain, poolerLabel string) bool {
	return studioDomain != "" || poolerLabel != ""
}

// ErrBudget: a pool size does not fit a cluster's max_connections.
var ErrBudget = errors.New("poolcfg: connection budget")

// Allowance is the pooler's share of a cluster's max_connections.
func Allowance(maxConnections int) int { return maxConnections - TierReserved }

// MaxPoolSize is the largest pool size P with 2 × (2P + 3) ≤ allowance: two
// modes, each P server connections, its own reserve and three of Supavisor's.
// Below 1 it is 0.
func MaxPoolSize(allowance int) int {
	if allowance < 10 {
		return 0
	}
	return (allowance - 6) / 4
}

// MinMaxConnections is the least max_connections that fits poolSize:
// TierReserved + 2 × (2P + 3), saturating at either end rather than
// overflowing.
func MinMaxConnections(poolSize int) int {
	if poolSize < math.MinInt/4+15 {
		return math.MinInt
	}
	if poolSize > (math.MaxInt-TierReserved-6)/4 {
		return math.MaxInt
	}
	return TierReserved + 2*(2*poolSize+3)
}

// Fits is nil when poolSize (at least 1) fits maxConnections, else ErrBudget
// naming both figures, the largest pool size that fits and the
// max_connections poolSize needs.
func Fits(maxConnections, poolSize int) error {
	largest := 0
	if maxConnections >= TierReserved {
		largest = MaxPoolSize(Allowance(maxConnections))
	}
	if poolSize >= 1 && poolSize <= largest {
		return nil
	}
	return fmt.Errorf("%w: max_connections %d, pool size %d: the largest pool size that fits is %d; pool size %d needs max_connections %d",
		ErrBudget, maxConnections, poolSize, largest, poolSize, MinMaxConnections(poolSize))
}

// ProjectConns is a project's share of the proxy's ceiling: its allowance
// and its cancels.
func ProjectConns(allowance int) int { return allowance + CancelsPerProject }
