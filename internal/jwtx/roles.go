package jwtx

import (
	"slices"
	"strings"
)

// forbidden is every role of the image baseline except authenticated, plus the
// roles this platform adds.
var forbidden = map[string]bool{
	"anon": true, "service_role": true, "authenticator": true, "dashboard_user": true,
	"pgbouncer": true, "postgres": true,
	"supabase_admin": true, "supabase_auth_admin": true, "supabase_etl_admin": true,
	"supabase_privileged_role": true, "supabase_read_only_user": true,
	"supabase_replication_admin": true, "supabase_storage_admin": true,
	"supabase_realtime_admin": true, "supapace_backup": true,
}

// ForbiddenUserRole reports whether role may never be carried by an
// issuer-class token nor listed as a project's user role.
func ForbiddenUserRole(role string) bool {
	return forbidden[role] ||
		strings.HasPrefix(role, "pg_") ||
		strings.HasPrefix(role, "supabase_") ||
		strings.HasPrefix(role, "supapace_")
}

// CheckRole binds the claimed role to the class of the key that signed it: an
// anon key carries only "anon", a service_role key only "service_role", an
// issuer key only a role in userRoles that is not forbidden.
func CheckRole(k Key, c Claims, userRoles []string) error {
	if c.Role == "" {
		return ErrNoRole
	}
	switch k.Class {
	case "anon", "service_role":
		if c.Role == string(k.Class) {
			return nil
		}
	case "issuer":
		if slices.Contains(userRoles, c.Role) && !ForbiddenUserRole(c.Role) {
			return nil
		}
	}
	return ErrRole
}
