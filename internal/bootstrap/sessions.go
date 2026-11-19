package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

// EnsureCanary makes the schema supapace and its table _backup_canary when
// absent and sets both owners back to supabase_admin (a schema of that name a
// project role made first is taken over). A table of that name another role
// owns is dropped with everything on it and made again; a relation of another
// kind in its place is refused. A session as supabase_admin.
func EnsureCanary(ctx context.Context, c *pgx.Conn) error {
	err := execSQL(ctx, c, sqlCanarySchema)
	if err == nil {
		err = execSQL(ctx, c, sqlCanarySchemaOwner)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlCanarySchemaRevoke)
	}
	kind, admins := "", false
	var acl *string
	if err == nil {
		err = querySQL(ctx, c, sqlCanaryRelation, nil, func(rows pgx.Rows) error { return rows.Scan(&kind, &admins, &acl) })
	}
	if err == nil && deref(acl) != canarySchemaACL {
		return fmt.Errorf("bootstrap: canary table: schema supapace has the access list %s", q(deref(acl)))
	}
	if err == nil && kind != "" && (kind != "r" || !admins) {
		if kind != "r" && kind != "p" {
			return fmt.Errorf("bootstrap: canary table: a relation of kind %s holds its name", q(kind))
		}
		err = execSQL(ctx, c, sqlCanaryDrop)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlCanaryTable)
	}
	if err == nil {
		err = execSQL(ctx, c, sqlCanaryTableOwner)
	}
	if err != nil {
		return fmt.Errorf("bootstrap: canary table: %w", err)
	}
	return nil
}

// WriteCanary makes the canary table as EnsureCanary does, then writes its one
// row with the server's current time. The row is the cluster's evidence for
// that project only.
func WriteCanary(ctx context.Context, c *pgx.Conn) error {
	if err := EnsureCanary(ctx, c); err != nil {
		return err
	}
	if err := execSQL(ctx, c, sqlCanaryWrite); err != nil {
		return fmt.Errorf("bootstrap: canary write: %w", err)
	}
	return nil
}

// RekeyResult is what RekeyLogin did after the new verifier was set: the
// sessions it ended, the read-only role's large objects it removed, whether
// some may remain, and the cause when their removal failed (empty when it did
// not; sanitised and at most 256 bytes, never a statement or a secret). The
// counts and the cause are the server's answers.
type RekeyResult struct {
	Terminated, LargeObjects int
	LargeObjectsLeft         bool
	LargeObjectsError        string
}

// loBatch is the LIMIT of sqlUnlinkReadOnlyLargeObjects; loRounds bounds its
// repetitions.
const (
	loBatch  = 10000
	loRounds = 10
)

// RekeyLogin sets the password of role (postgres or supabase_read_only_user)
// to the SCRAM verifier v as the session's first statement of the call, then
// ends every other session of that role. For supabase_read_only_user it then
// removes the large objects that role owns, at most loRounds batches; a
// failure there is reported as LargeObjectsLeft and LargeObjectsError and
// does not undo the re-key: the call still succeeds.
// A session as supabase_admin into the project's own database. Nothing is
// sent for another role or a malformed verifier.
func RekeyLogin(ctx context.Context, c *pgx.Conn, role, v string) (RekeyResult, error) {
	var res RekeyResult
	prefix := map[string]string{"postgres": sqlPasswordPostgres, "supabase_read_only_user": sqlPasswordReadOnly}[role]
	if prefix == "" {
		return res, errors.New("bootstrap: re-key of a login other than postgres or supabase_read_only_user")
	}
	if err := setVerifier(ctx, c, prefix, v); err != nil {
		return res, fmt.Errorf("bootstrap: password of %s: %w", role, err)
	}
	err := querySQL(ctx, c, sqlTerminateRole, []any{role}, func(rows pgx.Rows) error {
		var ok *bool
		if err := rows.Scan(&ok); err != nil {
			return err
		}
		if deref(ok) {
			res.Terminated++
		}
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("bootstrap: sessions of %s: %w", role, err)
	}
	if role != "supabase_read_only_user" {
		return res, nil
	}
	for range loRounds {
		n := 0
		err := querySQL(ctx, c, sqlUnlinkReadOnlyLargeObjects, nil, func(pgx.Rows) error {
			n++
			return nil
		})
		if err == nil && n > loBatch {
			err = fmt.Errorf("more than %d rows", loBatch)
		}
		if err != nil {
			res.LargeObjectsLeft = true
			res.LargeObjectsError = pgsock.Sanitize("bootstrap: large objects of "+role+": "+err.Error(), maxDetail)
			return res, nil
		}
		res.LargeObjects += n
		if res.LargeObjectsLeft = n == loBatch; !res.LargeObjectsLeft {
			break
		}
	}
	return res, nil
}

// SetReadOnlySignal sets (on) or removes the database setting
// default_transaction_read_only of the database postgres. It reaches new
// sessions only.
func SetReadOnlySignal(ctx context.Context, c *pgx.Conn, on bool) error {
	var err error
	if on {
		err = execSQL(ctx, c, sqlReadOnlySignalOn)
	} else {
		err = execSQL(ctx, c, sqlReadOnlySignalOff)
	}
	if err != nil {
		return fmt.Errorf("bootstrap: read-only signal: %w", err)
	}
	return nil
}

var lsnRE = regexp.MustCompile(`^[0-9A-F]{1,8}/[0-9A-F]{1,8}$`)

// CreateRestorePoint creates the named restore point and returns its WAL
// location as the server reports it: exactly one row in the form X/X, else an
// error. The caller reads the timeline with ReadTimeline in the same session.
func CreateRestorePoint(ctx context.Context, c *pgx.Conn, name string) (lsn string, err error) {
	var s *string
	n := 0
	err = querySQL(ctx, c, sqlRestorePoint, []any{name}, func(rows pgx.Rows) error {
		n++
		return rows.Scan(&s)
	})
	if err == nil && (n != 1 || s == nil || !lsnRE.MatchString(*s)) {
		err = errors.New("not a WAL location")
	}
	if err != nil {
		return "", fmt.Errorf("bootstrap: restore point: %w", err)
	}
	return *s, nil
}
