package store

import (
	"context"
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
		_, err = tx.Exec(ctx, "update project set state = $2, subnet_index = null where ref = $1", ref, to)
		return err
	})
}

// MarkPurged: deleted → purged; frees the slice, keeps the uid.
func (s *Store) MarkPurged(ctx context.Context, ref string) error {
	return s.release(ctx, ref, "purged", func(_ pgx.Tx, state string) (bool, error) { return state == "deleted", nil })
}

// MarkAborted: provisioning → aborted, or active → aborted when the abort of
// the create was accepted just before the project became active (the create
// operation is aborting). Frees the slice, keeps the uid.
func (s *Store) MarkAborted(ctx context.Context, ref string) error {
	return s.release(ctx, ref, "aborted", func(tx pgx.Tx, state string) (bool, error) {
		switch state {
		case "provisioning":
			return true, nil
		case "active":
			var aborting bool
			err := tx.QueryRow(ctx, `select coalesce((select state = 'aborting' from operation
				where ref = $1 and kind = 'create' order by id desc limit 1 for update), false)`, ref).Scan(&aborting)
			return aborting, err
		}
		return false, nil
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
		var usedMem, usedPids int64
		if err := tx.QueryRow(ctx, `select coalesce(sum(mem_mb), 0), coalesce(sum(pids), 0) from project
				where node_id = $1 and ref <> $2 and uid is not null and state in ('provisioning', 'active', 'restarting', 'deleting')`,
			node, ref).Scan(&usedMem, &usedPids); err != nil {
			return err
		}
		if usedMem+mem > memAlloc || usedPids+pids > pidsAlloc {
			return fmt.Errorf("%w: admission ceiling reached", ErrNodeFull)
		}
		if next >= base+count {
			return fmt.Errorf("%w: uid range exhausted", ErrNodeFull)
		}
		var free *int
		if err := tx.QueryRow(ctx, `select min(i) from generate_series(0, $2 - 1) i
				where not exists (select 1 from project where node_id = $1 and subnet_index = i)`, node, slices).Scan(&free); err != nil {
			return err
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
