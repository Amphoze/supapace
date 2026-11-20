package store

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/poolcfg"
)

// abortHold is how long a slice freed by an aborted create stays unassigned
// (nanoseconds); zero holds nothing.
var abortHold atomic.Int64

// SetAbortSliceHold sets how long a slice freed by an aborted create stays
// unassigned: a pooler that served the create may still name its port. Zero,
// the default, holds nothing. Like SetSliceHold it is the process's; set it
// once, before the first operation.
func (s *Store) SetAbortSliceHold(d time.Duration) { abortHold.Store(int64(d)) }

// descPerMiB: one file descriptor is counted for every 230 bytes of a
// project's memory admission (mem_mb × 2^20 ÷ 230).
const descPerMiB = 230

// ProjectShare is a project's share of the proxy's connections for its
// configuration: its pooler allowance and its cancels, at max_connections
// 120 when the configuration sets none.
func ProjectShare(c ProjectConfig) (int, error) {
	mc := 120
	if v, ok := c.GUC["max_connections"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > math.MaxInt32/2 {
			return 0, fmt.Errorf("%w: max_connections %.16q is not a connection count", ErrConflict, v)
		}
		mc = n
	}
	return poolcfg.ProjectConns(max(poolcfg.Allowance(mc), 0)), nil
}

// atV4 reports whether the schema has the admission columns. A database is
// at the build's version once Migrate has run; older versions are only met
// while a migration test builds one.
func atV4(ctx context.Context, q pgx.Tx) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, "select schema_ver >= 4 from cp_meta").Scan(&ok)
	return ok, err
}

// connTerm refuses with ErrNodeFull when the projects admit counts (the same
// predicate), with conns more for this one and the proxy's fixed terms,
// exceed the node's connection ceiling; and when their memory admission,
// with mem MiB more, exceeds its descriptor ceiling.
func connTerm(ctx context.Context, tx pgx.Tx, node, ref string, unplaced bool, conns, mem int64) error {
	var n, usedConns, usedMem, connAlloc, descAlloc int64
	if err := tx.QueryRow(ctx, `select count(p.ref), coalesce(sum(p.conns), 0), coalesce(sum(p.mem_mb), 0), n.conn_alloc, n.desc_alloc
		from node n left join project p on p.node_id = n.id and p.ref <> $2 and (p.uid is not null or $3)
			and p.state in ('provisioning', 'active', 'restarting', 'restoring', 'deleting')
		where n.id = $1 group by n.conn_alloc, n.desc_alloc`, node, ref, unplaced).
		Scan(&n, &usedConns, &usedMem, &connAlloc, &descAlloc); err != nil {
		return err
	}
	// Memory beyond this would overflow the shift; it is over any ceiling.
	const memMax = math.MaxInt64 >> 21
	desc := func(m int64) int64 { return min(m, memMax) << 20 / descPerMiB }
	switch {
	case usedConns+conns+poolcfg.ProxyFixedConns > connAlloc:
		return fmt.Errorf("%w: admission ceiling reached: %d projects hold %d of the node's %d connections through the proxy; a project needs %d",
			ErrNodeFull, n, usedConns, connAlloc, conns)
	case usedMem+mem > memMax || desc(usedMem+mem) > descAlloc:
		return fmt.Errorf("%w: admission ceiling reached: %d projects hold %d of the node's %d descriptors; a project needs %d",
			ErrNodeFull, n, desc(usedMem), descAlloc, desc(mem))
	}
	return nil
}

func validShare(conns int) error {
	if conns < 0 || conns > math.MaxInt32 {
		return fmt.Errorf("%w: a share of %d connections", ErrConflict, conns)
	}
	return nil
}

// CheckConns answers whether the project's share of the proxy's connections
// may become conns: the shares of the other placed projects admission counts,
// with conns and the proxy's fixed terms, within the node's ceiling.
// ErrNodeFull carries the figures.
func (s *Store) CheckConns(ctx context.Context, ref string, conns int) error {
	if err := validShare(conns); err != nil {
		return err
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		var node string
		if err := tx.QueryRow(ctx, "select node_id from project where ref = $1", ref).Scan(&node); err != nil {
			return err
		}
		return connTerm(ctx, tx, node, ref, false, int64(conns), 0)
	})
}

// SetConns records the project's share of the proxy's connections.
func (s *Store) SetConns(ctx context.Context, ref string, conns int) error {
	if err := validShare(conns); err != nil {
		return err
	}
	return s.update(ctx, "update project set conns = $2 where ref = $1", ref, conns)
}

// SetNodeAllocs records the node's connection and descriptor ceilings.
func (s *Store) SetNodeAllocs(ctx context.Context, connAlloc int, descAlloc int64) error {
	if connAlloc <= 0 || connAlloc > math.MaxInt32 || descAlloc <= 0 {
		return fmt.Errorf("%w: ceilings of %d connections and %d descriptors", ErrConflict, connAlloc, descAlloc)
	}
	return s.update(ctx, "update node set conn_alloc = $1, desc_alloc = $2", connAlloc, descAlloc)
}
