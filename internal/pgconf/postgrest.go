package pgconf

import (
	"fmt"
	"net/netip"
	"strings"
)

// PostgRESTConfig is what postgrest.conf varies on.
type PostgRESTConfig struct {
	ClusterAddr           netip.Addr
	AuthenticatorPassword string
}

const maxPasswordLen = 256

// PostgREST renders postgrest.conf. The password appears only here, inside
// db-uri, with every byte outside [A-Za-z0-9._~-] percent-encoded (PostgREST's
// configuration syntax gives '$' a meaning of its own). ClusterAddr must be
// IPv4; a password with a NUL or longer than 256 bytes is refused.
// db-config = false makes PostgREST ignore pgrst.* settings stored in the
// database; there is no admin port. PostgREST may re-read this file at any
// moment, so it must be complete when it is renamed into place.
func PostgREST(c PostgRESTConfig) ([]byte, error) {
	if !c.ClusterAddr.Is4() || c.ClusterAddr.IsUnspecified() {
		return nil, fmt.Errorf("pgconf: cluster address %s is not IPv4", c.ClusterAddr)
	}
	pw := c.AuthenticatorPassword
	if len(pw) > maxPasswordLen || strings.IndexByte(pw, 0) >= 0 {
		return nil, fmt.Errorf("pgconf: authenticator password longer than %d bytes or holding a NUL", maxPasswordLen)
	}
	var enc strings.Builder
	for _, b := range []byte(pw) {
		if b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || strings.IndexByte("._~-", b) >= 0 {
			enc.WriteByte(b)
		} else {
			fmt.Fprintf(&enc, "%%%02X", b)
		}
	}
	return fmt.Appendf(nil, `db-uri = "postgres://authenticator:%s@%s:5432/postgres?require_auth=scram-sha-256"
db-schemas = "public, graphql_public"
db-anon-role = "anon"
db-pool = 10
db-extra-search-path = "public, extensions"
jwt-secret = "@/etc/postgrest/jwks.json"
db-config = false
server-host = "*4"
server-port = 3000
`, enc.String(), c.ClusterAddr), nil
}
