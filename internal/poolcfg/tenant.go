package poolcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// maxAllowList bounds a project's network restrictions.
const maxAllowList = 32

// Tenant is what registers a project with the pooler.
type Tenant struct {
	DBHost                       netip.Addr
	DBPort, PoolSize, MaxClients int
	AllowList                    []netip.Prefix
	ManagerPassword              string `json:"-"`
}

// String, GoString and Format keep the manager password out of every fmt
// verb and log line; JSON leaves it out. A Tenant held in an unexported field
// of a printed struct is printed by reflection, raw: never print such a struct.
func (t Tenant) String() string {
	return fmt.Sprintf("poolcfg.Tenant{DBHost:%s DBPort:%d PoolSize:%d MaxClients:%d AllowList:%v}",
		t.DBHost, t.DBPort, t.PoolSize, t.MaxClients, t.AllowList)
}

func (t Tenant) GoString() string { return t.String() }

func (t Tenant) Format(f fmt.State, _ rune) { io.WriteString(f, t.String()) }

type tenantDoc struct {
	Tenant tenantBody `json:"tenant"`
}

type tenantBody struct {
	DBHost            string       `json:"db_host"`
	DBPort            int          `json:"db_port"`
	DBDatabase        string       `json:"db_database"`
	IPVersion         string       `json:"ip_version"`
	RequireUser       bool         `json:"require_user"`
	EnforceSSL        bool         `json:"enforce_ssl"`
	AuthQuery         string       `json:"auth_query"`
	DefaultPoolSize   int          `json:"default_pool_size"`
	DefaultMaxClients int          `json:"default_max_clients"`
	AllowList         []string     `json:"allow_list"`
	FeatureFlags      featureFlags `json:"feature_flags"`
	Users             []tenantUser `json:"users"`
}

type featureFlags struct {
	NamedPreparedStatements bool `json:"named_prepared_statements"`
}

type tenantUser struct {
	DBUser     string `json:"db_user"`
	DBPassword string `json:"db_password"`
	PoolSize   int    `json:"pool_size"`
	ModeType   string `json:"mode_type"`
	IsManager  bool   `json:"is_manager"`
}

// Body is the registration document: one user, the manager, and no
// sni_hostname. It refuses a tenant that is not complete: an IPv4 unicast
// host, a port, a pool size and a client count of at least 1, 1 to 32 canonical IPv4
// prefixes, and a manager password. No error carries the password.
func (t Tenant) Body() ([]byte, error) {
	switch {
	case !t.DBHost.Is4() || !t.DBHost.IsGlobalUnicast(): // not unspecified, broadcast, multicast, loopback or link-local
		return nil, errors.New("poolcfg: tenant: the database host is not an IPv4 unicast address")
	case t.DBPort < 1 || t.DBPort > 65535:
		return nil, fmt.Errorf("poolcfg: tenant: port %d", t.DBPort)
	case t.PoolSize < 1 || t.MaxClients < 1:
		return nil, fmt.Errorf("poolcfg: tenant: pool size %d, clients %d", t.PoolSize, t.MaxClients)
	case len(t.AllowList) < 1 || len(t.AllowList) > maxAllowList:
		return nil, fmt.Errorf("poolcfg: tenant: %d allow-list entries, want 1 to %d", len(t.AllowList), maxAllowList)
	case t.ManagerPassword == "":
		return nil, errors.New("poolcfg: tenant: no manager password")
	}
	list := make([]string, len(t.AllowList))
	for i, p := range t.AllowList {
		if !p.Addr().Is4() || p != p.Masked() {
			return nil, fmt.Errorf("poolcfg: tenant: allow-list entry %s is not a canonical IPv4 prefix", p)
		}
		list[i] = p.String()
	}
	return json.Marshal(tenantDoc{tenantBody{
		DBHost: t.DBHost.String(), DBPort: t.DBPort, DBDatabase: "postgres", IPVersion: "v4",
		RequireUser: false, EnforceSSL: true, AuthQuery: AuthQuery,
		DefaultPoolSize: t.PoolSize, DefaultMaxClients: t.MaxClients, AllowList: list,
		FeatureFlags: featureFlags{NamedPreparedStatements: true},
		Users: []tenantUser{{DBUser: ManagerRole, DBPassword: t.ManagerPassword, PoolSize: t.PoolSize,
			ModeType: "transaction", IsManager: true}},
	}})
}

// Address blocks no allow-list entry may touch, besides the node's own networks.
var notInAllowList = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local
	netip.MustParsePrefix("0.0.0.0/8"),      // this network, the unspecified address
	netip.MustParsePrefix("224.0.0.0/4"),    // multicast
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved, the broadcast address
}

// ValidAllowList parses 1 to 32 IPv4 prefixes in canonical form and refuses
// one that overlaps a network of the node (project block, platform, ingress,
// Docker pool, backup), this network, loopback, link-local, multicast or the
// reserved block: no node-internal address is ever written into a list.
func ValidAllowList(c nodecfg.Config, list []string) ([]netip.Prefix, error) {
	if len(list) < 1 || len(list) > maxAllowList {
		return nil, fmt.Errorf("poolcfg: %d allow-list entries, want 1 to %d", len(list), maxAllowList)
	}
	deny := append([]netip.Prefix(nil), notInAllowList...)
	for _, s := range []string{c.ProjectBlock, c.PlatformSubnet, c.IngressSubnet, c.DockerPool, c.BackupSubnet} {
		if p, err := netip.ParsePrefix(s); err == nil {
			deny = append(deny, p.Masked())
		}
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() || p != p.Masked() || p.String() != s {
			return nil, fmt.Errorf("poolcfg: allow-list entry %q is not a canonical IPv4 prefix", s)
		}
		for _, d := range deny {
			if p.Overlaps(d) {
				return nil, fmt.Errorf("poolcfg: allow-list entry %s overlaps %s", p, d)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// OpenAllowList is the list of a project without restrictions.
func OpenAllowList() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} }
