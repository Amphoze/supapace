// Package dashsock is the dashboard socket: what Studio asks the control plane
// for a project, over HTTP/1.1 on a Unix socket. This file is what both sides
// share: the answers' shapes and the header that carries the assertion.
package dashsock

import "github.com/Amphoze/supapace/internal/dashcfg"

// HeaderAssertion carries the gateway's signed assertion on every request.
const HeaderAssertion = "X-Supapace-Assertion"

// ResolveAnswer is the answer to POST /v1/resolve. DSNRW is set for owner and
// developer only; DSNRO when the project has its read-only login. Empty means
// absent on the wire, never an empty string.
type ResolveAnswer struct {
	Ref        string  `json:"ref"`
	Name       string  `json:"name"`
	State      string  `json:"state"`
	DBVersion  string  `json:"db_version"`
	PgMeta     int     `json:"pg_meta"`
	DSNRW      string  `json:"dsn_rw,omitempty"`
	DSNRO      string  `json:"dsn_ro,omitempty"`
	APIURL     string  `json:"api_url"`
	DataAPI    DataAPI `json:"data_api"`
	Generation int64   `json:"generation"`
	At         string  `json:"at"` // RFC 3339, UTC
}

// DataAPI is what the project's PostgREST is configured with; MaxRows is null
// while it sets none.
type DataAPI struct {
	Schemas         []string `json:"schemas"`
	ExtraSearchPath []string `json:"extra_search_path"`
	MaxRows         *int     `json:"max_rows"`
}

// KeysAnswer is the answer to POST /v1/keys. ServiceRoleKey is set only for an
// owner under an assertion whose purpose is reveal; otherwise it is absent.
type KeysAnswer struct {
	AnonKey        string       `json:"anon_key"`
	SigningKeys    []SigningKey `json:"signing_keys"`
	ServiceRoleKey string       `json:"service_role_key,omitempty"`
}

// SigningKey is one public key of the project's key set (alg RS256, kty RSA).
type SigningKey struct {
	Kid   string `json:"kid"`
	Class string `json:"class"`
	Alg   string `json:"alg"`
	Kty   string `json:"kty"`
	N     string `json:"n"`
	E     string `json:"e"`
}

// RoleClass is "rw" for owner and developer, "ro" for read_only, and "" for
// anything else.
func RoleClass(role string) string {
	switch role {
	case dashcfg.RoleOwner, dashcfg.RoleDeveloper:
		return "rw"
	case dashcfg.RoleReadOnly:
		return "ro"
	}
	return ""
}
