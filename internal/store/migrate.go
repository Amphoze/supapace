package store

import (
	"context"
	_ "embed"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

//go:embed schema.sql
var schemaSQL string

const schemaVersion = 1

// Migrate creates the schema once, with cp_meta at epoch 1; on a database that
// already carries this schema version it does nothing.
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
		if present {
			var v int
			if err := tx.QueryRow(ctx, "select schema_ver from cp_meta").Scan(&v); err != nil {
				return err
			}
			if v != schemaVersion {
				return fmt.Errorf("store: schema version %d, this build knows %d", v, schemaVersion)
			}
			return nil
		}
		if _, err := tx.Exec(ctx, schemaSQL); err != nil {
			return fmt.Errorf("store: schema: %w", err)
		}
		_, err := tx.Exec(ctx, "insert into cp_meta (epoch, schema_ver) values (1, $1)", schemaVersion)
		return err
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
