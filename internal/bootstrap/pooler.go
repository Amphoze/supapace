package bootstrap

import (
	"context"
	"errors"
	"fmt"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

// poolerVerifier computes the verifier of the pooler manager's password: no
// entry when s.PoolerPassword is empty. The password must differ from the
// three platform passwords.
func poolerVerifier(s Secrets) ([]roleVerifier, error) {
	if s.PoolerPassword == "" {
		return nil, nil
	}
	for _, p := range []string{s.SupabaseAdminPassword, s.PostgresPassword, s.AuthenticatorPassword} {
		if p == s.PoolerPassword {
			return nil, errors.New("bootstrap: supapace_pooler has the password of another role")
		}
	}
	v, err := pgsock.ScramVerifier(s.PoolerPassword, s.ScramSalts["supapace_pooler"])
	if err != nil {
		return nil, fmt.Errorf("bootstrap: verifier for supapace_pooler: %w", err)
	}
	return []roleVerifier{{"supapace_pooler", sqlPasswordPooler, v, true}}, nil
}

// EnsurePoolerLogin makes the pooler's manager role supapace_pooler with the
// verifier of s.PoolerPassword and every attribute as defined, and its lookup
// helper supapace_pooler.get_auth(text), owned by supabase_admin and
// executable by the manager alone (a session as supabase_admin). It sends, in
// this order: the role's creation (an existing role is success); its password
// statement; the helper's schema and grants; the helper and its grants; then
// reads both back: any difference is an error, among them a membership that
// names the manager and an access entry of the helper's schema other than the
// two it grants, neither of which it takes back. Idempotent: the attributes,
// owners, body and grants it sets are set back. The read-back is the cluster's
// word: it shows an honest cluster's drift and proves nothing about one that
// answers otherwise than it holds.
func EnsurePoolerLogin(ctx context.Context, c *pgx.Conn, s Secrets) error {
	pv, err := poolerVerifier(s)
	if err != nil {
		return err
	}
	if len(pv) == 0 {
		return errors.New("bootstrap: no password for supapace_pooler")
	}
	return ensurePoolerLogin(ctx, c, pv[0])
}

func ensurePoolerLogin(ctx context.Context, c *pgx.Conn, v roleVerifier) error {
	err := execSQL(ctx, c, sqlCreatePooler)
	if se := (*pgsock.ServerError)(nil); errors.As(err, &se) && se.Code == "42710" {
		err = nil // the role exists; its attributes are set next
	}
	if err == nil {
		err = setVerifier(ctx, c, v.prefix, v.verifier)
	}
	// Each statement is passed as its constant, one call each.
	if err == nil {
		err = execSQL(ctx, c, sqlPoolerSchema)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlPoolerSchemaOwner)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlPoolerSchemaRevoke)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlPoolerSchemaGrant)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlCreatePoolerHelper)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlPoolerHelperOwner)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlPoolerHelperRevoke)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlPoolerHelperGrant)
	}
	if err != nil {
		return fmt.Errorf("bootstrap: role supapace_pooler: %w", err)
	}
	d, err := poolerDiff(ctx, c)
	if err != nil {
		return fmt.Errorf("bootstrap: role supapace_pooler: %w", err)
	}
	if len(d) > 0 {
		return fmt.Errorf("bootstrap: role supapace_pooler: %s", d[0])
	}
	return nil
}

// poolerDiff reads the manager role and its helper and returns one line per
// difference from what EnsurePoolerLogin defines.
func poolerDiff(ctx context.Context, c *pgx.Conn) ([]string, error) {
	var d []string
	n := 0
	err := querySQL(ctx, c, sqlPoolerRole, nil, func(rows pgx.Rows) error {
		n++
		var g [7]bool
		var unclaimed *bool
		var acl *string
		if err := rows.Scan(&g[0], &g[1], &g[2], &g[3], &g[4], &g[5], &g[6], &unclaimed, &acl); err != nil {
			return err
		}
		if !deref(unclaimed) {
			d = append(d, "role supapace_pooler has a membership")
		}
		if deref(acl) != poolerSchemaACL {
			d = append(d, "schema supapace_pooler has the access list "+q(deref(acl)))
		}
		if g != [7]bool{false, false, false, false, false, true, true} {
			d = append(d, fmt.Sprintf("role supapace_pooler: super=%t createrole=%t createdb=%t replication=%t "+
				"bypassrls=%t login=%t unlimited=%t, expected login and unlimited alone", g[0], g[1], g[2], g[3], g[4], g[5], g[6]))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if n != 1 {
		d = append(d, "role supapace_pooler is absent")
	}
	n = 0
	err = querySQL(ctx, c, sqlPoolerHelper, []any{bodyPoolerHelper, poolerHelperConfig}, func(rows pgx.Rows) error {
		n++
		var owner, grantees *string
		var body, secdef, config *bool
		if err := rows.Scan(&owner, &body, &secdef, &config, &grantees); err != nil {
			return err
		}
		if deref(owner) != "supabase_admin" {
			d = append(d, "helper supapace_pooler.get_auth is owned by "+q(deref(owner)))
		}
		if !deref(body) {
			d = append(d, "helper supapace_pooler.get_auth has another body")
		}
		if !deref(secdef) {
			d = append(d, "helper supapace_pooler.get_auth is not security definer")
		}
		if !deref(config) {
			d = append(d, "helper supapace_pooler.get_auth has another SET clause")
		}
		if deref(grantees) != poolerHelperGrantees {
			d = append(d, "helper supapace_pooler.get_auth may be executed by "+q(deref(grantees)))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if n != 1 {
		d = append(d, "helper supapace_pooler.get_auth is absent")
	}
	return d, nil
}

// AssertServices reports, under the check service-logins, where the pooler's
// manager role or its helper differ from what EnsurePoolerLogin defines. With
// pooler false it reads nothing and returns nothing. As every check, what it
// reports is drift for that project, never a guarantee.
func AssertServices(ctx context.Context, c *pgx.Conn, pooler bool) ([]nodecfg.CheckResult, error) {
	if !pooler {
		return nil, nil
	}
	d, err := poolerDiff(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: assert %s: %w", checkServiceLogins, err)
	}
	r := &report{n: map[string]int{}}
	for _, l := range d {
		r.add(checkServiceLogins, "%s", l)
	}
	return r.out, nil
}
