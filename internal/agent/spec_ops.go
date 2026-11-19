package agent

import "net/netip"

// The operability fields of a specification. This file declares every type
// it names and imports the standard library only, so that the packages that
// fill and read the fields compile against it in any order. A zero OpsSpec
// renders every container exactly as before; nothing here is a secret, so
// Spec.String is unchanged.

// IOLimits has the same four members as the store's; the saga converts.
type IOLimits struct{ ReadBPS, WriteBPS, ReadIOPS, WriteIOPS int64 }

type APISpec struct {
	Schemas, ExtraSearchPath []string
	MaxRows                  int
}

// Rate has the same two members as the route file's; RouteFor converts.
type Rate struct{ RPS, Burst int }

type OpsSpec struct {
	Outbound     bool
	Image        string   // empty: the node's locked Postgres image
	ImageVersion string   // the version the image was admitted with; empty: the locked one
	IO           IOLimits // zero: no limit is written
	// Zero pool size or clients: poolcfg's defaults.
	PoolSize, MaxClients, PoolerAllowance int
	AllowList                             []netip.Prefix // empty: open
	Stopped                               bool
	API                                   APISpec
	Aud                                   []string
	Rate                                  *Rate
}
