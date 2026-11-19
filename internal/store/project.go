package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

var refRE = regexp.MustCompile(`^[a-z0-9]{20}$`)

// Admission inputs of a project: its cluster plus PostgREST.
const (
	postgrestMemMB = 256
	projectPids    = 512 + 64
)

const projectCols = `ref, name, node_id, state, epoch, generation, applied_gen, uid, subnet_index,
	mem_mb, pids, config, user_roles, created_at, deleted_at, purge_after`

func scanProject(row pgx.Row) (Project, error) {
	var p Project
	err := row.Scan(&p.Ref, &p.Name, &p.NodeID, &p.State, &p.Epoch, &p.Generation, &p.AppliedGen, &p.UID,
		&p.SubnetIndex, &p.MemMB, &p.Pids, &p.Config, &p.UserRoles, &p.CreatedAt, &p.DeletedAt, &p.PurgeAfter)
	return p, err
}

func normConfig(c ProjectConfig) ProjectConfig {
	if c.GUC == nil {
		c.GUC = map[string]string{}
	}
	return c
}

// CreateProject inserts the project (provisioning, generation 1, on the node)
// and its create operation, whose step 1 is this insert.
func (s *Store) CreateProject(ctx context.Context, np NewProject) (opID int64, err error) {
	if !refRE.MatchString(np.Ref) {
		return 0, ErrBadRef
	}
	roles := np.UserRoles
	if len(roles) == 0 {
		roles = nil // the column default
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		var epoch int64
		if err := tx.QueryRow(ctx, "select epoch from cp_meta").Scan(&epoch); err != nil {
			return err
		}
		// One node until multi-node placement exists.
		var node string
		var nodes int
		if err := tx.QueryRow(ctx, "select min(id), count(*) from node").Scan(&node, &nodes); err != nil || nodes != 1 {
			return fmt.Errorf("store: want exactly one node row, have %d (%v)", nodes, err)
		}
		tag, err := tx.Exec(ctx, `insert into project (ref, name, node_id, state, epoch, mem_mb, pids, config, user_roles)
			values ($1, $2, $3, 'provisioning', $4, $5, $6, $7, coalesce($8::text[], '{authenticated}'))
			on conflict (ref) do nothing`,
			np.Ref, np.Name, node, epoch, np.Config.MemMB+postgrestMemMB, projectPids, normConfig(np.Config), roles)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrRefExists
		}
		return tx.QueryRow(ctx, `insert into operation (ref, kind, state, step, params, epoch, generation)
			values ($1, 'create', 'pending', '1', $2, $3, 1) returning id`, np.Ref, orEmpty(np.Params), epoch).Scan(&opID)
	})
	return opID, err
}

func (s *Store) GetProject(ctx context.Context, ref string) (Project, error) {
	p, err := scanProject(s.pool.QueryRow(ctx, "select "+projectCols+" from project where ref = $1", ref))
	return p, wrap(err)
}

// ListProjects returns every project, tombstones included, in ref order.
func (s *Store) ListProjects(ctx context.Context) ([]Project, error) {
	rows, err := s.pool.Query(ctx, "select "+projectCols+" from project order by ref")
	if err != nil {
		return nil, err
	}
	ps, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Project, error) { return scanProject(r) })
	return ps, wrap(err)
}

// update runs a one-row update; no row is ErrNotFound.
func (s *Store) update(ctx context.Context, q string, args ...any) error {
	tag, err := s.pool.Exec(ctx, q, args...)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return wrap(err)
}

func (s *Store) SetProjectState(ctx context.Context, ref, state string) error {
	return s.update(ctx, "update project set state = $2 where ref = $1", ref, state)
}

func (s *Store) SetApplied(ctx context.Context, ref string, gen int64) error {
	return s.update(ctx, "update project set applied_gen = $2 where ref = $1", ref, gen)
}

// BumpGeneration sets the desired generation and configuration when gen is
// newer than the stored generation; otherwise it changes nothing.
func (s *Store) BumpGeneration(ctx context.Context, ref string, gen int64, cfg ProjectConfig) error {
	return s.update(ctx, `update project set generation = greatest(generation, $2),
		config = case when generation < $2 then $3 else config end where ref = $1`, ref, gen, normConfig(cfg))
}

// lockProject reads a project's state under a row lock.
func lockProject(ctx context.Context, tx pgx.Tx, ref string) (state string, err error) {
	err = tx.QueryRow(ctx, "select state from project where ref = $1 for update", ref).Scan(&state)
	return state, err
}

// MarkDeleted moves a deleting project to deleted and queues its purge at
// now + retention. On a project already deleted it returns that purge.
func (s *Store) MarkDeleted(ctx context.Context, ref string, retention time.Duration) (purgeOpID int64, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		state, err := lockProject(ctx, tx, ref)
		if err != nil {
			return err
		}
		switch state {
		case "deleted":
			return tx.QueryRow(ctx, "select id from operation where ref = $1 and kind = 'purge' order by id desc limit 1", ref).Scan(&purgeOpID)
		case "deleting":
		default:
			return fmt.Errorf("%w: project is %s", ErrConflict, state)
		}
		return tx.QueryRow(ctx, `with p as (
				update project set state = 'deleted', deleted_at = now(),
					purge_after = now() + $2 * interval '1 microsecond'
				where ref = $1 returning ref, generation, purge_after)
			insert into operation (ref, kind, state, epoch, generation, not_before)
			select ref, 'purge', 'pending', (select epoch from cp_meta), generation, purge_after from p
			returning id`, ref, retention.Microseconds()).Scan(&purgeOpID)
	})
	return purgeOpID, err
}

// release frees a project's slice and moves it to a terminal state; the uid
// stays on the row, retired. allowed decides, under the row locks, whether the
// current state admits it. Repeating it is a no-op.
func (s *Store) release(ctx context.Context, ref, to string, allowed func(tx pgx.Tx, state string) (bool, error)) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		state, err := lockProject(ctx, tx, ref)
		if err != nil || state == to {
			return err
		}
		ok, err := allowed(tx, state)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: project is %s", ErrConflict, state)
		}
		// A slice freed by a purge is held: something may still name it. One freed
		// by an abort was never named.
		if hold := time.Duration(sliceHold.Load()); to == "purged" && hold > 0 {
			if _, err := tx.Exec(ctx, `insert into slice_hold (node_id, subnet_index, free_after)
					select node_id, subnet_index, now() + $2 * interval '1 microsecond' from project where ref = $1 and subnet_index is not null
				on conflict (node_id, subnet_index) do update set free_after = greatest(slice_hold.free_after, excluded.free_after)`,
				ref, hold.Microseconds()); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, "update project set state = $2, subnet_index = null where ref = $1", ref, to)
		return err
	})
}

// MarkPurged: deleted → purged; frees the slice, keeps the uid.
func (s *Store) MarkPurged(ctx context.Context, ref string) error {
	return s.release(ctx, ref, "purged", func(_ pgx.Tx, state string) (bool, error) { return state == "deleted", nil })
}

// MarkAborted: provisioning → aborted (an active project never has an
// aborting create: step 12 and RequestAbort exclude each other). Frees the
// slice, keeps the uid.
func (s *Store) MarkAborted(ctx context.Context, ref string) error {
	return s.release(ctx, ref, "aborted", func(_ pgx.Tx, state string) (bool, error) {
		return state == "provisioning", nil
	})
}

// Place gives a provisioning project its uid (= gid) from the node's monotonic
// counter and the lowest free slice, after admission, under the node lock. A
// project already placed gets its stored placement back. ErrNodeFull leaves
// the project unplaced and the counter unchanged.
func (s *Store) Place(ctx context.Context, ref string) (Placement, error) {
	var pl Placement
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var node, state string
		var uid, slice *int
		var mem, pids int64
		if err := tx.QueryRow(ctx, "select node_id, state, uid, subnet_index, mem_mb, pids from project where ref = $1 for update", ref).
			Scan(&node, &state, &uid, &slice, &mem, &pids); err != nil {
			return err
		}
		if uid != nil {
			if slice == nil {
				return fmt.Errorf("%w: project is %s and no longer holds a slice", ErrConflict, state)
			}
			pl = Placement{UID: *uid, GID: *uid, SubnetIndex: *slice}
			return nil
		}
		if state != "provisioning" {
			return fmt.Errorf("%w: project is %s", ErrConflict, state)
		}
		if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock($1, hashtext($2))", lockClassNode, node); err != nil {
			return err
		}
		// Statements after the lock see every placement committed before it.
		var base, count, next, slices int
		var memAlloc, pidsAlloc int64
		if err := tx.QueryRow(ctx, `select uid_base, uid_count, next_uid, mem_alloc_mb, pids_alloc,
				1 << (slice_prefix - masklen(project_block)) from node where id = $1 for update`, node).
			Scan(&base, &count, &next, &memAlloc, &pidsAlloc, &slices); err != nil {
			return err
		}
		if err := admit(ctx, tx, node, ref, false, mem, pids, memAlloc, pidsAlloc); err != nil {
			return err
		}
		if next >= base+count {
			return fmt.Errorf("%w: uid range exhausted", ErrNodeFull)
		}
		// With a hold set, an index held until later than now is not free, and a
		// hold that has passed is dropped. With none set the allocator is the
		// as-built one and reads no hold.
		holding := sliceHold.Load() > 0
		q := `select min(i) from generate_series(0, $2 - 1) i
			where not exists (select 1 from project where node_id = $1 and subnet_index = i)`
		if holding {
			if _, err := tx.Exec(ctx, "delete from slice_hold where node_id = $1 and free_after <= now()", node); err != nil {
				return err
			}
			q += ` and not exists (select 1 from slice_hold where node_id = $1 and subnet_index = i)`
		}
		var free *int
		if err := tx.QueryRow(ctx, q, node, slices).Scan(&free); err != nil {
			return err
		}
		if free == nil && holding {
			var held int
			var until *time.Time
			if err := tx.QueryRow(ctx, "select count(*), min(free_after) from slice_hold where node_id = $1", node).Scan(&held, &until); err != nil {
				return err
			}
			if held > 0 {
				return fmt.Errorf("%w: no free slice; %d held until %s", ErrNodeFull, held, until.UTC().Format(time.RFC3339))
			}
		}
		if free == nil {
			return fmt.Errorf("%w: no free slice", ErrNodeFull)
		}
		if _, err := tx.Exec(ctx, "update project set uid = $2, subnet_index = $3 where ref = $1", ref, next, *free); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "update node set next_uid = next_uid + 1 where id = $1", node); err != nil {
			return err
		}
		pl = Placement{UID: next, GID: next, SubnetIndex: *free}
		return nil
	})
	return pl, err
}

// admit is the admission rule: a project needing mem MiB and pids fits when
// the projects counted against the node's ceilings leave room for it. Counted
// are the projects other than ref in provisioning, active, restarting,
// restoring (it holds its cluster's memory) or
// deleting — placed ones only, or with unplaced also those not placed yet.
// ErrNodeFull carries the figures.
func admit(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, node, ref string, unplaced bool, mem, pids, memAlloc, pidsAlloc int64) error {
	var n, usedMem, usedPids int64
	if err := q.QueryRow(ctx, `select count(*), coalesce(sum(mem_mb), 0), coalesce(sum(pids), 0) from project
			where node_id = $1 and ref <> $2 and (uid is not null or $3) and state in ('provisioning', 'active', 'restarting', 'restoring', 'deleting')`,
		node, ref, unplaced).Scan(&n, &usedMem, &usedPids); err != nil {
		return err
	}
	switch {
	case usedMem+mem > memAlloc:
		return fmt.Errorf("%w: admission ceiling reached: %d projects hold %d of the node's %d MiB; a project needs %d MiB",
			ErrNodeFull, n, usedMem, memAlloc, mem)
	case usedPids+pids > pidsAlloc:
		return fmt.Errorf("%w: admission ceiling reached: %d projects hold %d of the node's %d processes; a project needs %d",
			ErrNodeFull, n, usedPids, pidsAlloc, pids)
	}
	return nil
}

// QuotaHeadroomMB is the room a new disk quota must leave above the project's
// current usage: what a clean cluster start needs. A start creates files
// before it serves (the postmaster's lock file first: at a quota below the
// usage the start fails there) and keeps up to min_wal_size (80 MB) of WAL
// segments of 16 MiB each; 256 MiB covers that with room for the writes of a
// cluster that runs on until its restart stops it. It is a floor, not a
// guarantee for a cluster that stopped at its quota: crash recovery replays
// up to max_wal_size (1 GiB) of WAL before its first checkpoint and can
// re-create relation data freed since the last one, so such a cluster needs
// about its usage plus 1280 MiB.
const QuotaHeadroomMB = 256

// ErrQuotaBelowUsage: a disk quota that would leave a project less than
// QuotaHeadroomMB above its usage.
var ErrQuotaBelowUsage = errors.New("disk quota below usage")

// CheckQuota refuses a disk quota of quotaMB MiB for a project whose user
// quota charges usedBytes (a host-side figure: the filesystem's accounting,
// never the cluster's) unless it is at least the usage, rounded up to MiB,
// plus QuotaHeadroomMB. The error names both figures and the smallest
// accepted value.
func CheckQuota(quotaMB int, usedBytes int64) error {
	usedMB := (usedBytes + 1<<20 - 1) >> 20
	least := usedMB + QuotaHeadroomMB
	if int64(quotaMB) >= least {
		return nil
	}
	return fmt.Errorf("%w: disk_quota_mb %d is below the project's usage of %d MiB plus the %d MiB a clean cluster start needs; "+
		"the smallest accepted value is %d", ErrQuotaBelowUsage, quotaMB, usedMB, QuotaHeadroomMB, least)
}

// CheckAdmission answers whether a new project whose cluster has clusterMemMB
// would be admitted now, by the rule Place applies, also counting projects not
// placed yet. It is advisory: Place remains the authority.
func (s *Store) CheckAdmission(ctx context.Context, clusterMemMB int) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var node string
		var memAlloc, pidsAlloc int64
		if err := tx.QueryRow(ctx, "select id, mem_alloc_mb, pids_alloc from node order by id limit 1").
			Scan(&node, &memAlloc, &pidsAlloc); errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: the node is not initialised (no node row); start the daemon, which records it", ErrConflict)
		} else if err != nil {
			return err
		}
		return admit(ctx, tx, node, "", true, int64(clusterMemMB+postgrestMemMB), projectPids, memAlloc, pidsAlloc)
	})
}

// BeginRestart sets the desired generation and configuration of an active or
// restarting project and marks it restarting, in one statement, when target
// is newer than the stored generation. Repeating it once done is a no-op —
// the same target generation and configuration; another configuration at
// that generation is another restart's bump. Anything else is ErrConflict.
func (s *Store) BeginRestart(ctx context.Context, ref string, target int64, cfg ProjectConfig) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `update project set generation = $2, config = $3, state = 'restarting'
			where ref = $1 and generation < $2 and state in ('active', 'restarting')`, ref, target, normConfig(cfg))
		if err != nil || tag.RowsAffected() > 0 {
			return err
		}
		var state string
		var gen int64
		var same bool
		if err := tx.QueryRow(ctx, "select state, generation, config = $2 from project where ref = $1", ref, normConfig(cfg)).
			Scan(&state, &gen, &same); err != nil {
			return err
		}
		if gen == target && state == "restarting" && same {
			return nil
		}
		return fmt.Errorf("%w: project is %s at generation %d", ErrConflict, state, gen)
	})
}

// SetSlot gives the project's backup slot to operation opID: free → opID;
// held by opID already → no change; held by another → ErrConflict.
func (s *Store) SetSlot(ctx context.Context, ref string, opID int64) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var slot *int64
		if err := tx.QueryRow(ctx, "select slot_op from project where ref = $1 for update", ref).Scan(&slot); err != nil {
			return err
		}
		switch {
		case slot == nil:
			_, err := tx.Exec(ctx, "update project set slot_op = $2 where ref = $1", ref, opID)
			return err
		case *slot != opID:
			return fmt.Errorf("%w: operation %d holds the project's backup slot", ErrConflict, *slot)
		}
		return nil
	})
}

// ClearSlot frees the project's backup slot if opID holds it.
func (s *Store) ClearSlot(ctx context.Context, ref string, opID int64) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := lockProject(ctx, tx, ref); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "update project set slot_op = null where ref = $1 and slot_op = $2", ref, opID)
		return err
	})
}

// recoveredError is the last_error of an operation the new epoch ended.
const recoveredError = "recovered: the node was recovered while this operation was open"

// EnterNewEpoch is the first write to a recovered control-plane database, in
// one transaction: the epoch + 1; the uid counter raised above every recorded
// uid and to at least uidFloor, never lowered; every queued or running job
// failed (code recovered); every open operation but a purge failed — the
// create of a provisioning project aborted — with recoveredError; a running
// purge back to pending, every other purge as it is (destroying a deleted
// project's keys stays an obligation); every provisioning project aborted
// with its slice released and its off-site prefix marked for purging; every
// slot freed. It returns the new epoch.
func (s *Store) EnterNewEpoch(ctx context.Context, uidFloor int) (epoch int64, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "update cp_meta set epoch = epoch + 1 returning epoch").Scan(&epoch); err != nil {
			return err
		}
		for _, st := range []struct {
			q    string
			args []any
		}{
			{"update node set next_uid = greatest(next_uid, (select max(uid) + 1 from project), $1)", []any{uidFloor}},
			{"update backup_job set state = 'failed', code = 'recovered', finished_at = now() where state in ('queued', 'running')", nil},
			{`update operation o set last_error = $1, updated_at = now(), state = case when o.kind = 'create' and
				exists (select 1 from project p where p.ref = o.ref and p.state = 'provisioning') then 'aborted' else 'failed' end
			where o.kind <> 'purge' and o.state in ` + openStates, []any{recoveredError}},
			{"update operation set state = 'pending', updated_at = now() where kind = 'purge' and state = 'running'", nil},
			{"update backup_state set offsite_purge = true where subject in (select ref from project where state = 'provisioning')", nil},
			{"update project set state = 'aborted', subnet_index = null where state = 'provisioning'", nil},
			{"update project set slot_op = null where slot_op is not null", nil}, // kept last
		} {
			if _, err := tx.Exec(ctx, st.q, st.args...); err != nil {
				return err
			}
		}
		return nil
	})
	return epoch, err
}

// SetSliceHold sets how long a slice freed by a purge stays unassigned, so
// that nothing still naming it reaches the next project placed on it. Zero,
// the default, reuses a freed slice at once. The setting is the process's,
// not this Store value's: set it once, before the saga runner, the clean-up
// converger and the admin API start.
func (s *Store) SetSliceHold(d time.Duration) { sliceHold.Store(int64(d)) }
