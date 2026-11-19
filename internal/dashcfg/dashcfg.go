// Package dashcfg holds the dashboard's node constants: uids, container names,
// ports, the platform addresses derived from a node's configuration, the
// connection strings Studio is given, the on-disk paths and the bounds table.
// It computes; it reads no clock, socket or file.
package dashcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

const (
	StudioUID, PgMetaUID, PgcapUID                  = 65527, 65528, 65529 // each also its gid
	StudioName, PgMeta0Name, PgMeta1Name, PgcapName = "sp-studio", "sp-pgmeta-0", "sp-pgmeta-1", "sp-pgcap"
	StudioImage, PgcapImage                         = "supapace-studio:local", "supapace-pgcap:local"
	StudioPort, PgMetaPort                          = 3000, 8080
	MetaPortBase                                    = 20000      // pgcap, class "meta": port MetaPortBase + subnet index
	ClusterHost, RestHost, ProxyHost, ReservedHost  = 2, 3, 4, 5 // host addresses on a project bridge
	RoleOwner, RoleDeveloper, RoleReadOnly          = "owner", "developer", "read_only"
	LoginRW, LoginRO                                = "postgres", "supabase_read_only_user"
	SecretROPassword                                = "pg.supabase_read_only_user.password"
	SignInLabel                                     = "sign-in" // the sign-in host's label under the studio domain; no ref can be it
)

// maxSlices is the dashboard file's cap on projects (dashfile.MaxProjects; a
// test of that package holds the two equal).
const maxSlices = 4096

// platformUIDs are the ids of the platform's own containers and processes: the
// control plane, Studio, postgres-meta, pgcap, the replicator, the gateway and
// PostgREST. No project uid may be one of them.
var platformUIDs = []int{70, 65527, 65528, 65529, 65530, 65531, 65532}

// Addrs are the dashboard's platform addresses, its meta port range and the
// fixed PostgREST range of a node.
type Addrs struct {
	Studio, PgMeta0, PgMeta1, Pgcap netip.Addr
	MetaPortLo, MetaPortHi          int
	RestLo, RestHi                  netip.Addr
}

// For returns the node's addresses, or an error when the configuration cannot
// host a dashboard: a dashboard address that is the gateway's or lies in the
// Docker allocation range (or outside the platform subnet), a meta port range
// that passes 65535, more slices than the dashboard file carries, or a project
// uid range containing a platform uid.
func For(c nodecfg.Config) (Addrs, error) {
	a, errs := compute(c)
	if n := c.Slices(); n > maxSlices {
		errs = append(errs, fmt.Errorf("project_block/slice_prefix: %d slices, more than the %d the dashboard file carries", n, maxSlices))
	}
	if c.UIDCount > 0 {
		lo, hi := int64(c.UIDBase), int64(c.UIDBase)+int64(c.UIDCount)-1
		for _, u := range platformUIDs {
			if lo <= int64(u) && int64(u) <= hi {
				errs = append(errs, fmt.Errorf("uid_base/uid_count: the project uid range %d-%d contains the platform uid %d", lo, hi, u))
			}
		}
	}
	if len(errs) > 0 {
		return Addrs{}, errors.Join(errs...)
	}
	return a, nil
}

// Static never fails: it returns For's addresses with the zero value for every
// member For's rules refuse, so a renderer that must not fail (the ruleset) can
// omit what it cannot state.
func Static(c nodecfg.Config) Addrs {
	a, _ := compute(c)
	return a
}

// compute is the members and the refusals that concern them.
func compute(c nodecfg.Config) (Addrs, []error) {
	var a Addrs
	var errs []error
	p, perr := netip.ParsePrefix(c.PlatformSubnet)
	rng, rerr := netip.ParsePrefix(c.PlatformIPRange)
	gw, _ := netip.ParseAddr(c.GatewayIP)
	for i, m := range []*netip.Addr{&a.Studio, &a.PgMeta0, &a.PgMeta1, &a.Pgcap} {
		if perr != nil || !p.Addr().Is4() {
			errs = append(errs, fmt.Errorf("platform_subnet: %q is not an IPv4 network", c.PlatformSubnet))
			break
		}
		addr := addOffset(p.Masked().Addr(), uint32(3+i))
		switch {
		case !p.Contains(addr):
			errs = append(errs, fmt.Errorf("platform_subnet: %s cannot hold the dashboard address %s", p, addr))
		case addr == gw:
			errs = append(errs, fmt.Errorf("gateway_ip: %s is a dashboard address", gw))
		case rerr != nil:
			errs = append(errs, fmt.Errorf("platform_ip_range: %q is not a network", c.PlatformIPRange))
		case rng.Contains(addr):
			errs = append(errs, fmt.Errorf("platform_ip_range: %s contains the dashboard address %s", rng, addr))
		default:
			*m = addr
		}
	}
	n := c.Slices()
	if n < 1 || MetaPortBase+n-1 > 65535 {
		errs = append(errs, fmt.Errorf("project_block/slice_prefix: %d slices take the meta ports %d+ past 65535", n, MetaPortBase))
	} else {
		a.MetaPortLo, a.MetaPortHi = MetaPortBase, MetaPortBase+n-1
	}
	a.RestLo, a.RestHi = c.PlatformAddr(0), c.PlatformAddr(n-1)
	if !a.RestLo.IsValid() || !a.RestHi.IsValid() {
		errs = append(errs, fmt.Errorf("platform_subnet: no fixed PostgREST range"))
	}
	return a, errs
}

func PgMetaIndex(subnetIndex int) int { return subnetIndex % 2 }
func MetaPort(subnetIndex int) int    { return MetaPortBase + subnetIndex }

// ProxyAddr is pgcap's address on project network i; zero when i is out of range.
func ProxyAddr(c nodecfg.Config, subnetIndex int) netip.Addr {
	s := c.Slice(subnetIndex)
	if !s.IsValid() {
		return netip.Addr{}
	}
	return addOffset(s.Addr(), ProxyHost)
}

func addOffset(a netip.Addr, off uint32) netip.Addr {
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) + off
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// maxDSN bounds what ParseDSN reads: generated passwords are far shorter.
const maxDSN = 512

const dsnScheme, dsnTail = "postgresql://", "/postgres?sslmode=disable"

// DSN is the one connection string form Studio is given for a project.
func DSN(a Addrs, login, password string, subnetIndex int) string {
	return dsnScheme + login + ":" + encodePassword(password) + "@" + a.Pgcap.String() + ":" +
		strconv.Itoa(MetaPort(subnetIndex)) + dsnTail
}

// ParseDSN accepts exactly the form DSN writes — one of the two logins, a
// non-empty printable-ASCII password in DSN's encoding, the proxy's address,
// a port of the meta range, database postgres and the one parameter — and
// nothing else; Addrs without the proxy's address or a port range accept nothing.
func ParseDSN(a Addrs, dsn string) (login string, subnetIndex int, err error) {
	refuse := func(why string) (string, int, error) { return "", 0, errors.New("dsn: " + why) }
	if len(dsn) > maxDSN {
		return refuse("too long")
	}
	if !a.Pgcap.IsValid() || a.MetaPortLo < 1 || a.MetaPortHi < a.MetaPortLo { // a zero address prints "invalid IP"
		return refuse("no proxy address")
	}
	rest, ok := strings.CutPrefix(dsn, dsnScheme)
	if !ok {
		return refuse("not " + dsnScheme)
	}
	rest, ok = strings.CutSuffix(rest, dsnTail)
	if !ok {
		return refuse("not database postgres with sslmode=disable alone")
	}
	user, hostport, ok := strings.Cut(rest, "@")
	if !ok {
		return refuse("no login")
	}
	login, pw, ok := strings.Cut(user, ":")
	if !ok || (login != LoginRW && login != LoginRO) {
		return refuse("not one of the two logins")
	}
	if dec, ok := decodePassword(pw); !ok || dec == "" || !printable(dec) || encodePassword(dec) != pw {
		return refuse("password not in the canonical encoding")
	}
	host, port, ok := strings.Cut(hostport, ":")
	if !ok || host != a.Pgcap.String() {
		return refuse("not the proxy's address")
	}
	n, err := strconv.Atoi(port)
	if err != nil || strconv.Itoa(n) != port || n < a.MetaPortLo || n > a.MetaPortHi {
		return refuse("port outside the meta range")
	}
	return login, n - MetaPortBase, nil
}

// printable: bytes 0x20 to 0x7e only, as the generated passwords are.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func unreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

// encodePassword percent-encodes every byte but the unreserved ones, upper-case hex.
func encodePassword(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; unreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

func decodePassword(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' { // a byte DSN would have escaped fails the canonical comparison
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", false
		}
		b.WriteByte(byte(v))
		i += 2
	}
	return b.String(), true
}
