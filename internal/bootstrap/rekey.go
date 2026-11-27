package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

// Rekey sets the passwords of supabase_admin, postgres and authenticator to
// the verifiers of s on a cluster started from a restored data directory
// (one session as supabase_admin). It computes the verifiers before sending
// anything, then sends exactly: the three password statements, in that order
// and before any other statement; when s.ReadOnlyPassword is set, the
// read-only login's, then, when s.PoolerPassword is set, the pooler
// manager's password statement, each skipped when its role does not exist
// (the re-key creates no role); the backup role's existence read and its
// creation when absent; its two grants. Each statement also restores the
// role's login right, connection limit and expiry. Rekey is idempotent.
//
// A later identity is re-keyed by appending its password statement to the
// list verifiers returns, or, when its role may be absent, to the list after
// them, where SQLSTATE 42704 (no such role) is a skip; the session keeps this
// shape.
func Rekey(ctx context.Context, c *pgx.Conn, s Secrets) error {
	vs, err := verifiers(s)
	if err != nil {
		return err
	}
	pv, err := poolerVerifier(s)
	if err != nil {
		return err
	}
	for _, v := range slices.Concat(vs, pv) {
		err := setVerifier(ctx, c, v.prefix, v.verifier)
		if se := (*pgsock.ServerError)(nil); v.optional && errors.As(err, &se) && se.Code == "42704" {
			err = nil // the role does not exist: nothing to re-key
		}
		if err != nil {
			return fmt.Errorf("bootstrap: password of %s: %w", v.role, err)
		}
	}
	return ensureBackupRole(ctx, c)
}

// GrantBackup grants pg_read_all_settings to supapace_backup with the inherit
// option, so the role reads the settings it needs without a SET ROLE.
func GrantBackup(ctx context.Context, c *pgx.Conn) error {
	if err := execSQL(ctx, c, sqlGrantBackupSettings); err != nil {
		return fmt.Errorf("bootstrap: grant to supapace_backup: %w", err)
	}
	return nil
}

// InRecovery reports whether the server is still in recovery. The answer is
// the cluster's, as every read is.
func InRecovery(ctx context.Context, c *pgx.Conn) (bool, error) {
	var in bool
	n := 0
	err := querySQL(ctx, c, sqlInRecovery, nil, func(rows pgx.Rows) error {
		n++
		return rows.Scan(&in)
	})
	if err == nil && n != 1 {
		err = errors.New("no single row")
	}
	if err != nil {
		return false, fmt.Errorf("bootstrap: recovery state: %w", err)
	}
	return in, nil
}

var timelineRE = regexp.MustCompile(`^[0-9A-F]{8}$`)

// ReadTimeline returns the server's current timeline: the first eight hex
// digits of the name of the current WAL file. A value that is not eight upper
// hex digits, or zero, is an error.
func ReadTimeline(ctx context.Context, c *pgx.Conn) (int, error) {
	var s *string
	n := 0
	err := querySQL(ctx, c, sqlTimeline, nil, func(rows pgx.Rows) error {
		n++
		return rows.Scan(&s)
	})
	if err == nil && (n != 1 || s == nil || !timelineRE.MatchString(*s)) {
		err = errors.New("not a timeline")
	}
	var tl uint64
	if err == nil {
		if tl, err = strconv.ParseUint(*s, 16, 32); err == nil && tl == 0 {
			err = errors.New("timeline 0")
		}
	}
	if err != nil {
		return 0, fmt.Errorf("bootstrap: timeline: %w", err)
	}
	return int(tl), nil
}

// ResetStatementStats clears the statement statistics of the platform's login
// role only (supabase_admin), at the schema the image installs the extension
// in; the statistics of every other role are left alone. When the function or
// its schema is not there it returns reset=false and no error. The function is
// the cluster's: callers send nothing after it and treat any error as best
// effort.
func ResetStatementStats(ctx context.Context, c *pgx.Conn) (reset bool, err error) {
	err = execSQL(ctx, c, sqlResetStatementStats)
	var se *pgsock.ServerError
	if errors.As(err, &se) && (se.Code == "42883" || se.Code == "3F000") {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("bootstrap: statement statistics: %w", err)
	}
	return true, nil
}
