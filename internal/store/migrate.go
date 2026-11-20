package store

import (
	"context"
	"embed"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

//go:embed schema.sql
var schemaSQL string

//go:embed migration_*.sql
var migrationFiles embed.FS

// migrations names the numbered migrations: element i takes the schema from
// version i+1 to i+2. A new version is a new file and one more element.
var migrations = [...]string{"migration_2.sql", "migration_3.sql", "migration_4.sql"}

// schemaVersion is the version this build migrates to.
const schemaVersion = 1 + len(migrations)

// Migrate creates the schema once, with cp_meta at epoch 1, and then applies
// every migration above the stored version, all in one transaction under one
// lock; on a database already at schemaVersion it does nothing. A stored
// version above schemaVersion is refused.
func (s *Store) Migrate(ctx context.Context) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		// Serialise concurrent first runs; the check below then sees the winner's schema.
		if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock($1, 0)", lockClassMigrate); err != nil {
			return err
		}
		var present bool
		if err := tx.QueryRow(ctx, "select to_regclass('cp_meta') is not null").Scan(&present); err != nil {
			return err
		}
		v := 1
		if present {
			if err := tx.QueryRow(ctx, "select schema_ver from cp_meta").Scan(&v); err != nil {
				return err
			}
			if v > schemaVersion || v < 1 {
				return fmt.Errorf("store: schema version %d, this build knows %d", v, schemaVersion)
			}
		} else {
			if _, err := tx.Exec(ctx, schemaSQL); err != nil {
				return fmt.Errorf("store: schema: %w", err)
			}
			if _, err := tx.Exec(ctx, "insert into cp_meta (epoch, schema_ver) values (1, 1)"); err != nil {
				return err
			}
		}
		for ; v < schemaVersion; v++ {
			name := migrations[v-1]
			sql, err := migrationFiles.ReadFile(name)
			if err != nil {
				return fmt.Errorf("store: %s: %w", name, err)
			}
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("store: %s: %w", name, err)
			}
			if _, err := tx.Exec(ctx, "update cp_meta set schema_ver = $1", v+1); err != nil {
				return err
			}
		}
		return nil
	})
}

// EnsureNode inserts the node row from c when absent (next_uid = uid_base). On
// an existing row the ranges must equal c's, and the admission ceilings are
// updated to c's.
func (s *Store) EnsureNode(ctx context.Context, c nodecfg.Config) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("store: node config: %w", err)
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `insert into node (id, project_block, slice_prefix, uid_base, uid_count, next_uid, mem_alloc_mb, pids_alloc)
			values ($1, $2::cidr, $3, $4, $5, $4, $6, $7) on conflict (id) do nothing`,
			c.NodeID, c.ProjectBlock, c.SlicePrefix, c.UIDBase, c.UIDCount, c.MemAllocMB, c.PidsAlloc); err != nil {
			return err
		}
		var block string
		var prefix, base, count int
		if err := tx.QueryRow(ctx, "select project_block::text, slice_prefix, uid_base, uid_count from node where id = $1", c.NodeID).
			Scan(&block, &prefix, &base, &count); err != nil {
			return err
		}
		stored, err := netip.ParsePrefix(block)
		want, _ := netip.ParsePrefix(c.ProjectBlock) // validated above
		if err != nil || stored != want || prefix != c.SlicePrefix || base != c.UIDBase || count != c.UIDCount {
			return fmt.Errorf("store: node %q is stored with project_block %s/%d, uids %d+%d; node.json has %s/%d, uids %d+%d",
				c.NodeID, block, prefix, base, count, c.ProjectBlock, c.SlicePrefix, c.UIDBase, c.UIDCount)
		}
		_, err = tx.Exec(ctx, "update node set mem_alloc_mb = $2, pids_alloc = $3 where id = $1", c.NodeID, c.MemAllocMB, c.PidsAlloc)
		return err
	})
}
