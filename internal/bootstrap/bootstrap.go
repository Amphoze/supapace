// Package bootstrap prepares a project's cluster once, at its first boot, and
// later compares a running cluster with what the platform expects.
//
// Run sets the platform's passwords (as SCRAM verifiers computed here, so no
// password reaches the server), creates the platform's two roles and defines
// the auth helper functions. It runs only in the first-boot phase, before any
// project credential exists.
//
// Assert and AssertHBA read the catalog with plain SQL and return one finding
// per difference. The database server is untrusted: what they report is drift
// for that project, never a guarantee about it, and every value read from the
// server is bounded and sanitized before it reaches a finding.
//
// Every statement runs under a pgsock.Stmt context on a connection from
// pgsock.Dial; every error from a statement, a rows iteration or a scan is
// passed through pgsock.Clean.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

// Secrets are a project's database secrets. ScramSalts maps each of
// supabase_admin, postgres and authenticator to its salt (pgsock.ScramSalt).
type Secrets struct {
	SupabaseAdminPassword, PostgresPassword, AuthenticatorPassword string
	PgsodiumRootKey                                                string
	ScramSalts                                                     map[string][]byte
}

// ErrAssertion is what a caller returns when a blocking assertion has
// findings.
var ErrAssertion = errors.New("bootstrap: cluster differs from what the platform expects")

var verifierRE = regexp.MustCompile(`^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$`)

// verifierStatement returns prefix completed with v, after checking that
// prefix is one of the three sqlPassword… constants and v is a SCRAM-SHA-256
// verifier with 4096 iterations and nothing else.
func verifierStatement(prefix, v string) (string, error) {
	switch prefix {
	case sqlPasswordSupabaseAdmin, sqlPasswordPostgres, sqlPasswordAuthenticator:
	default:
		return "", errors.New("bootstrap: not a password statement")
	}
	if !verifierRE.MatchString(v) {
		return "", errors.New("bootstrap: malformed verifier")
	}
	return prefix + v + "'", nil
}

// Run bootstraps a freshly initialised cluster over c (a session as
// supabase_admin in the first-boot phase). Every step is idempotent.
func Run(ctx context.Context, c *pgx.Conn, s Secrets) error {
	pw := []struct{ role, password, prefix string }{
		{"supabase_admin", s.SupabaseAdminPassword, sqlPasswordSupabaseAdmin},
		{"postgres", s.PostgresPassword, sqlPasswordPostgres},
		{"authenticator", s.AuthenticatorPassword, sqlPasswordAuthenticator},
	}
	verifiers := make([]string, len(pw))
	for i, p := range pw {
		for _, q := range pw[:i] {
			if p.password == q.password {
				return fmt.Errorf("bootstrap: %s and %s have the same password", q.role, p.role)
			}
		}
		v, err := pgsock.ScramVerifier(p.password, s.ScramSalts[p.role])
		if err != nil {
			return fmt.Errorf("bootstrap: verifier for %s: %w", p.role, err)
		}
		verifiers[i] = v
	}
	for i, p := range pw {
		if err := setVerifier(ctx, c, p.prefix, verifiers[i]); err != nil {
			return fmt.Errorf("bootstrap: password of %s: %w", p.role, err)
		}
	}
	exists, err := roleExists(ctx, c, "supabase_realtime_admin")
	if err == nil && !exists {
		err = execSQL(ctx, c, sqlCreateRealtimeAdmin)
	}
	if err != nil {
		return fmt.Errorf("bootstrap: role supabase_realtime_admin: %w", err)
	}
	exists, err = roleExists(ctx, c, "supapace_backup")
	if err == nil && !exists {
		err = execSQL(ctx, c, sqlCreateBackup)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlGrantBackupSettings)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlGrantBackupFuncs)
	}
	if err != nil {
		return fmt.Errorf("bootstrap: role supapace_backup: %w", err)
	}
	// The functions are created as their owner, supabase_auth_admin.
	err = execSQL(ctx, c, sqlSetRoleAuthAdmin)
	if err == nil {
		err = execSQL(ctx, c, sqlCreateUID)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlCreateRole)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlCreateEmail)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlCreateJWT)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlResetRole)
	} else {
		_ = execSQL(ctx, c, sqlResetRole) // best effort: leave the session in its own role; the first error is returned
	}
	if err != nil {
		return fmt.Errorf("bootstrap: auth functions: %w", err)
	}
	return nil
}

// roleExists reports whether the role name exists.
func roleExists(ctx context.Context, c *pgx.Conn, name string) (bool, error) {
	var exists bool
	err := querySQL(ctx, c, sqlRoleExists, []any{name}, func(rows pgx.Rows) error { return rows.Scan(&exists) })
	return exists, err
}

// setVerifier sets a role's password to the verifier v.
func setVerifier(ctx context.Context, c *pgx.Conn, prefix, v string) error {
	stmt, err := verifierStatement(prefix, v)
	if err != nil {
		return err
	}
	return execSQL(ctx, c, stmt)
}

// execSQL runs one statement under its own statement budget.
func execSQL(ctx context.Context, c *pgx.Conn, sql string, args ...any) error {
	sctx, cancel := pgsock.Stmt(ctx, pgsock.DefaultBudget)
	defer cancel()
	_, err := c.Exec(sctx, sql, args...)
	return pgsock.Clean(err)
}

// querySQL runs one query under its own statement budget and calls scan for
// each row.
func querySQL(ctx context.Context, c *pgx.Conn, sql string, args []any, scan func(pgx.Rows) error) error {
	sctx, cancel := pgsock.Stmt(ctx, pgsock.DefaultBudget)
	defer cancel()
	rows, err := c.Query(sctx, sql, args...)
	if err != nil {
		return pgsock.Clean(err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return pgsock.Clean(err)
		}
	}
	return pgsock.Clean(rows.Err())
}
