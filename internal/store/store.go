// Package store holds the control-plane database: schema, migrations, locks,
// placement and queries. Every exported method is one transaction; none is
// exposed for composition, so a caller can never leave an invariant half-written.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNodeFull  = errors.New("node full")
	ErrRefExists = errors.New("ref exists")
	ErrBadRef    = errors.New("bad ref")
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("conflict")
	ErrDestroyed = errors.New("key destroyed")
)

// Advisory lock classes: per ref (session-level, held for an operation) and per
// node (transaction-level, inside placement only).
const (
	lockClassMigrate = 7300
	lockClassRef     = 7301
	lockClassNode    = 7302
)

// maxConns bounds the pool. Every held or waiting LockRef pins one connection:
// the adoption round holds up to four, the worker one, an index-file stream
// one, and the rest is shared by everything else.
const maxConns = 16

type Store struct{ pool *pgxpool.Pool }

type ProjectConfig struct {
	DiskQuotaMB         int               `json:"disk_quota_mb"`
	MemMB               int               `json:"mem_mb"`
	GUC                 map[string]string `json:"guc"`
	Layout              int               `json:"layout,omitempty"`                 // 0 or 1: as built; 2: with backups
	UploadMBPerDay      int               `json:"upload_mb_per_day,omitempty"`      // 0: 2 × disk_quota_mb
	UploadObjectsPerDay int               `json:"upload_objects_per_day,omitempty"` // 0: the default budget
	Outbound            bool              `json:"outbound,omitempty"`
	Image               string            `json:"image,omitempty"`         // name@sha256:<64 hex>; empty: the node's
	ImageVersion        string            `json:"image_version,omitempty"` // the version the image was admitted with
	IO                  *IOLimits         `json:"io,omitempty"`            // nil: DefaultIO
}

// IOLimits are a cluster's device limits: bytes and operations a second.
type IOLimits struct {
	ReadBPS   int64 `json:"read_bps"`
	WriteBPS  int64 `json:"write_bps"`
	ReadIOPS  int64 `json:"read_iops"`
	WriteIOPS int64 `json:"write_iops"`
}

var DefaultIO = IOLimits{128 << 20, 64 << 20, 2000, 1000}

type Project struct {
	Ref, Name, NodeID, State      string
	Epoch, Generation, AppliedGen int64
	UID, SubnetIndex              *int
	MemMB, Pids                   int
	Config                        ProjectConfig
	UserRoles                     []string
	CreatedAt                     time.Time
	DeletedAt, PurgeAfter         *time.Time
}

type NewProject struct {
	Ref, Name string
	Config    ProjectConfig
	UserRoles []string
	Params    json.RawMessage
}

type Operation struct {
	ID                     int64
	Ref, Kind, State, Step string
	Attempts               int
	Params                 json.RawMessage
	Epoch, Generation      int64
	NotBefore              time.Time
	LastError              string
	CreatedAt, UpdatedAt   time.Time
	Result                 json.RawMessage // null until a step records one
}

type Placement struct{ UID, GID, SubnetIndex int }

type KeyRow struct {
	Ref, KID, Class string
	JWK             json.RawMessage
}

// Open connects to the control-plane database "supapaced" through the socket
// in socketDir, as role supapaced (peer authentication, no password).
func Open(ctx context.Context, socketDir string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	cc := cfg.ConnConfig
	cc.Host, cc.Port, cc.Database, cc.User, cc.Password = socketDir, 5432, "supapaced", "supapaced", ""
	cc.TLSConfig, cc.Fallbacks = nil, nil
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Epoch(ctx context.Context) (int64, error) {
	var e int64
	err := s.pool.QueryRow(ctx, "select epoch from cp_meta").Scan(&e)
	return e, wrap(err)
}

// LockRef takes the ref's session-level advisory lock on a connection reserved
// for the caller, and returns the function that releases both. Unlock is
// idempotent; if the unlock statement fails the connection is closed, which
// releases the lock with it.
//
// Each held or waiting lock pins one pool connection (the pool has maxConns).
// If that connection dies the server releases the lock without notice to the
// holder. An unlock that is never called keeps its connection out of the pool,
// and Close then blocks.
func (s *Store) LockRef(ctx context.Context, ref string) (unlock func(), err error) {
	unlock, _, err = s.LockRefChecked(ctx, ref)
	return unlock, err
}

// LockRefChecked is LockRef that also returns held, which reports whether the
// lock is still held: one round trip on the connection that holds it, an
// error once that connection is gone (the server then released the lock).
// held must not be called beside unlock or after it.
func (s *Store) LockRefChecked(ctx context.Context, ref string) (unlock func(), held func(context.Context) error, err error) {
	c, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, nil, wrap(err)
	}
	if _, err := c.Exec(ctx, "select pg_advisory_lock($1, hashtext($2))", lockClassRef, ref); err != nil {
		// A wait cut short by ctx may still have been granted on the server: drop
		// the connection so the lock cannot outlive this call.
		c.Conn().Close(context.Background())
		c.Release()
		return nil, nil, wrap(err)
	}
	return unlocker(c, ref), heldOn(c), nil
}

// heldOn reports whether the lock held on c is still held.
func heldOn(c *pgxpool.Conn) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := c.Exec(ctx, "select 1")
		return err
	}
}

// unlocker releases the ref lock held on c, then c. It is idempotent; if the
// unlock statement fails the connection is closed, which releases the lock.
func unlocker(c *pgxpool.Conn, ref string) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var ok bool
			if err := c.QueryRow(ctx, "select pg_advisory_unlock($1, hashtext($2))", lockClassRef, ref).Scan(&ok); err != nil || !ok {
				c.Conn().Close(ctx)
			}
			c.Release()
		})
	}
}

// TryLockRef is LockRef without waiting: ok is false, and no connection is
// kept, when another session holds the lock.
func (s *Store) TryLockRef(ctx context.Context, ref string) (unlock func(), ok bool, err error) {
	unlock, _, ok, err = s.TryLockRefChecked(ctx, ref)
	return unlock, ok, err
}

// TryLockRefChecked is TryLockRef that also returns held, as LockRefChecked
// does: one round trip on the lock's connection, an error once it is gone.
func (s *Store) TryLockRefChecked(ctx context.Context, ref string) (unlock func(), held func(context.Context) error, ok bool, err error) {
	c, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, nil, false, wrap(err)
	}
	if err := c.QueryRow(ctx, "select pg_try_advisory_lock($1, hashtext($2))", lockClassRef, ref).Scan(&ok); err != nil || !ok {
		if err != nil {
			// The answer may have been lost after the server granted it.
			c.Conn().Close(context.Background())
		}
		c.Release()
		return nil, nil, false, wrap(err)
	}
	return unlocker(c, ref), heldOn(c), true, nil
}

func (s *Store) tx(ctx context.Context, f func(pgx.Tx) error) error {
	return wrap(pgx.BeginFunc(ctx, s.pool, f))
}

// wrap maps "no row" and a missing referenced project to ErrNotFound.
func wrap(err error) error {
	var pe *pgconn.PgError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case errors.As(err, &pe) && pe.Code == "23503": // foreign_key_violation
		return ErrNotFound
	}
	return err
}

// WALPosition is the database's current WAL insert position.
func (s *Store) WALPosition(ctx context.Context) (lsn string, err error) {
	err = s.pool.QueryRow(ctx, "select pg_current_wal_insert_lsn()::text").Scan(&lsn)
	return lsn, wrap(err)
}

// SwitchWAL names the WAL segment that holds lsn, then switches to a new
// segment so that one is complete and can be archived.
func (s *Store) SwitchWAL(ctx context.Context, lsn string) (segment string, err error) {
	if err := s.pool.QueryRow(ctx, "select pg_walfile_name($1::pg_lsn)", lsn).Scan(&segment); err != nil {
		return "", wrap(err)
	}
	if _, err := s.pool.Exec(ctx, "select pg_switch_wal()"); err != nil {
		return "", wrap(err)
	}
	return segment, nil
}
