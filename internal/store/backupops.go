package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/walname"
)

var (
	ErrNotRebuilt = errors.New("store: the off-site record is not rebuilt")
	ErrClock      = errors.New("store: a job of the subject carries a time later than now")
	ErrNoLaunch   = errors.New("store: a record row needs the launch number of the job that recorded it")
)

// maxRunKeys bounds the keys one off-site expire run reports as marked or as
// listed and not recorded.
const maxRunKeys = 2000

// SubjectSchedule is what the schedule pass reads of one subject.
type SubjectSchedule struct {
	Subject, ProjectState                 string // ProjectState "" for cp
	Sets, SetsNotExpiredLocal, FullsToday int    // FullsToday: backup jobs of the subject created this UTC day
	NewestSetFinished                     *time.Time
	NewestSetReplicated                   bool
	FullDue, OffsitePurge                 bool
	OffsitePurgeSeenAt                    *time.Time
	LastPushOK, LastPushLaunched, LastReplOK, LastCheckOK, LastVerifyAt, LastExpireAt, LastOffsiteExpireAt,
	SpoolDroppedAt, CanaryAt, DeadmanAt *time.Time
	LastPushFailed                     bool // the newest finished push job ended failed; false when there is none
	SpoolBytes, DiskUsedKB, DiskHardKB int64
	VerifyOK                           *bool
}

// Schedule returns one row per backup_state subject, in subject order. The
// newest set is the one whose backup job was launched last.
func (s *Store) Schedule(ctx context.Context) ([]SubjectSchedule, error) {
	rows, err := s.pool.Query(ctx, `select b.subject, coalesce(p.state, ''),
			(select count(*) from backup_set x where x.subject = b.subject),
			(select count(*) from backup_set x where x.subject = b.subject and x.expired_local_at is null),
			(select count(*) from backup_job j where j.subject = b.subject and j.kind = 'backup' and j.created_at >= date_trunc('day', now(), 'UTC')),
			ns.finished_at, coalesce(ns.replicated, false), b.full_due, b.offsite_purge, b.offsite_purge_seen_at,
			b.last_push_ok, (select max(j.started_at) from backup_job j where j.subject = b.subject and j.kind = 'push'),
			b.last_repl_ok, b.last_check_ok, b.last_verify_at, b.last_expire_at, b.last_offsite_expire_at,
			b.spool_dropped_at, b.canary_at, b.deadman_at,
			coalesce((select j.state = 'failed' from backup_job j where j.subject = b.subject and j.kind = 'push'
				and j.state in ('done', 'failed') order by j.finished_at desc nulls last, j.id desc limit 1), false),
			coalesce(b.spool_bytes, 0), coalesce(b.disk_used_kb, 0), coalesce(b.disk_hard_kb, 0), b.verify_ok
		from backup_state b left join project p on p.ref = b.subject
		left join lateral (select j.finished_at, x.replicated from backup_set x join backup_job j on j.id = x.job_id
			where x.subject = b.subject order by j.launch desc nulls last, j.id desc limit 1) ns on true
		order by b.subject`)
	if err != nil {
		return nil, wrap(err)
	}
	l, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (SubjectSchedule, error) {
		var x SubjectSchedule
		err := r.Scan(&x.Subject, &x.ProjectState, &x.Sets, &x.SetsNotExpiredLocal, &x.FullsToday, &x.NewestSetFinished,
			&x.NewestSetReplicated, &x.FullDue, &x.OffsitePurge, &x.OffsitePurgeSeenAt, &x.LastPushOK, &x.LastPushLaunched,
			&x.LastReplOK, &x.LastCheckOK, &x.LastVerifyAt, &x.LastExpireAt, &x.LastOffsiteExpireAt, &x.SpoolDroppedAt,
			&x.CanaryAt, &x.DeadmanAt, &x.LastPushFailed, &x.SpoolBytes, &x.DiskUsedKB, &x.DiskHardKB, &x.VerifyOK)
		return x, err
	})
	return l, wrap(err)
}

// markStatements: what MarkSchedule records, by name; ok is read for check
// (only a check that ended done is recorded) and verify.
var markStatements = map[string]string{
	"check":          "update backup_state set last_check_ok = case when $3 then $2 else last_check_ok end where subject = $1",
	"verify":         "update backup_state set last_verify_at = $2, verify_ok = $3 where subject = $1",
	"expire":         "update backup_state set last_expire_at = $2 where subject = $1",
	"offsite-expire": "update backup_state set last_offsite_expire_at = $2 where subject = $1",
	"spool-drop":     "update backup_state set spool_dropped_at = $2 where subject = $1",
	"canary":         "update backup_state set canary_at = $2 where subject = $1",
	"deadman":        "update backup_state set deadman_at = $2 where subject = $1",
}

// MarkSchedule records the time of what: check, verify, expire,
// offsite-expire, spool-drop, canary or deadman.
func (s *Store) MarkSchedule(ctx context.Context, subject, what string, at time.Time, ok bool) error {
	q, known := markStatements[what]
	if !known {
		return fmt.Errorf("%w: %.32q is not a scheduled kind", ErrConflict, what)
	}
	args := []any{subject, at}
	if what == "check" || what == "verify" {
		args = append(args, ok)
	}
	return s.updateOne(ctx, q, args...)
}

func (s *Store) SetFullDue(ctx context.Context, subject string, due bool) error {
	return s.updateOne(ctx, "update backup_state set full_due = $2 where subject = $1", subject, due)
}

// ExpireAllowed: the subject's record is rebuilt in this epoch, and a done
// replicate job of mode copy whose result says complete was launched after
// every job of the subject that writes the repository and has left the queue
// — jobID, the expire being launched, left out. No number orders below every
// number; with no such copy the answer is false.
func (s *Store) ExpireAllowed(ctx context.Context, subject string, jobID int64) (bool, error) {
	var rebuilt bool
	var copied, written *int64
	err := s.pool.QueryRow(ctx, `select b.rebuild_epoch = (select epoch from cp_meta),
			(select max(launch) from backup_job where subject = $1 and kind = 'replicate' and state = 'done'
				and result->>'mode' = 'copy' and result->'complete' = 'true'::jsonb),
			(select max(coalesce(launch, 0)) from backup_job where subject = $1 and id <> $2 and state <> 'queued'
				and kind in ('push', 'backup', 'check', 'stanza-create', 'seed', 'expire'))
		from backup_state b where b.subject = $1`, subject, jobID).Scan(&rebuilt, &copied, &written)
	if err != nil {
		return false, wrap(err)
	}
	return rebuilt && copied != nil && (written == nil || *copied > *written), nil
}

// MarkExpiredLocal records at as the time the same location expired each set
// of the subject that remaining does not list and that has none yet.
func (s *Store) MarkExpiredLocal(ctx context.Context, subject string, remaining []string, at time.Time) error {
	if len(remaining) > bklimit.ReplMaxFiles {
		return fmt.Errorf("%w: %d remaining sets", ErrConflict, len(remaining))
	}
	for _, l := range remaining {
		if !setLabelRE.MatchString(l) {
			return fmt.Errorf("%w: set label %.64q refused", ErrConflict, l)
		}
	}
	_, err := s.pool.Exec(ctx, `update backup_set set expired_local_at = $3
		where subject = $1 and expired_local_at is null and not (label = any($2))`, subject, remaining, at)
	return wrap(err)
}

// ExpirePlan is one off-site expire run's plan. Anchor "": none, and no key.
// HeldByLocal counts the sets older than the anchor that stay only because
// the same location still holds them, for longer than the limit given.
type ExpirePlan struct {
	Keys        []string
	More        bool
	Anchor      string
	KeepLaunch  int64
	HeldByLocal int
}

// The plan's statements. They read the launch numbers, the jobs' states,
// replicated, expired_local_at, the restores' timelines and the record's keys;
// one job time each for the clock's rule and for the anchor; never a set's
// reported positions or times, and never an upload time.
const (
	planClockQ = `select b.incarnation, b.rebuild_epoch >= (select epoch from cp_meta),
			exists (select 1 from backup_job j where j.subject = b.subject and greatest(j.created_at, j.started_at, j.finished_at) > $2)
		from backup_state b where b.subject = $1`
	planSetsQ = `select x.label, j.launch, j.state = 'done', j.finished_at, x.replicated, x.expired_local_at is null
		from backup_set x join backup_job j on j.id = x.job_id where x.subject = $1 order by j.launch nulls first, j.id`
	planRestoresQ = `select o.params->>'set' from operation o join backup_timeline t on t.subject = o.ref and t.op_id = o.id
		where o.ref = $1 and o.kind = 'restore' and t.state = 'recorded' and t.launch > $2`
	planKeysQ = `select key from offsite_object where subject = $1 and launch < $2 order by launch, key collate "C"`
)

var planStatements = []string{planClockQ, planSetsQ, planRestoresQ, planKeysQ}

type planSet struct {
	label       string
	launch      *int64
	done        bool
	finished    *time.Time
	repl, local bool
}

// after: launch a is later than b; no number orders below every number.
func after(a, b *int64) bool { return a != nil && (b == nil || *a > *b) }

var plannedKinds = map[walname.Kind]bool{walname.Segment: true, walname.SetFile: true, walname.SetManifest: true,
	walname.SetManifestCopy: true, walname.HistoryManifest: true}

// OffsiteExpirePlan decides which recorded keys of subject an off-site expire
// may mark, in one read-only transaction. The anchor is the newest replicated
// set whose job is done, finished at least window before now, with at least
// minNewer replicated sets launched after it. A set stays when it is the
// anchor, was launched after it, is still at the same location, or is the
// base of a restore whose timeline was recorded with a number above the
// anchor's job's. Planned are the record's keys below the lowest launch
// number of the staying sets' jobs, lowest first, at most max, of a segment
// or a set's files and under no staying set's directory. Nothing is planned
// without an anchor or while a staying set's job has no number. A record not
// rebuilt in this epoch is ErrNotRebuilt; a job of the subject dated after now
// is ErrClock.
func (s *Store) OffsiteExpirePlan(ctx context.Context, subject, stanza string, window, held time.Duration,
	now time.Time, minNewer, max int) (ExpirePlan, error) {
	if window < 0 || held < 0 || minNewer < 0 || max < 1 {
		return ExpirePlan{}, fmt.Errorf("%w: window %v, held %v, %d newer, %d keys", ErrConflict, window, held, minNewer, max)
	}
	var plan ExpirePlan
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var inc string
		var rebuilt, ahead bool
		if err := tx.QueryRow(ctx, planClockQ, subject, now).Scan(&inc, &rebuilt, &ahead); err != nil {
			return err
		}
		switch {
		case stanza != subject+"-"+inc:
			return fmt.Errorf("%w: stanza %.64q is not the subject's", ErrConflict, stanza)
		case !rebuilt:
			return ErrNotRebuilt
		case ahead:
			return ErrClock
		}
		rows, _ := tx.Query(ctx, planSetsQ, subject)
		sets, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (planSet, error) {
			var x planSet
			return x, r.Scan(&x.label, &x.launch, &x.done, &x.finished, &x.repl, &x.local)
		})
		if err != nil {
			return err
		}
		anchor := -1
		for i := len(sets) - 1; i >= 0 && anchor < 0; i-- {
			a := sets[i]
			if !a.repl || !a.done || a.finished == nil || a.finished.After(now.Add(-window)) {
				continue
			}
			newer := 0
			for _, o := range sets[i+1:] {
				if o.repl && after(o.launch, a.launch) {
					newer++
				}
			}
			if newer >= minNewer {
				anchor = i
			}
		}
		if anchor < 0 {
			return nil
		}
		a := sets[anchor]
		plan.Anchor = a.label
		var floor int64
		if a.launch != nil {
			floor = *a.launch
		}
		rows, _ = tx.Query(ctx, planRestoresQ, subject, floor)
		bases, err := pgx.CollectRows(rows, pgx.RowTo[*string])
		if err != nil {
			return err
		}
		isBase := map[string]bool{}
		for _, b := range bases {
			if b != nil {
				isBase[*b] = true
			}
		}
		staying := map[string]bool{}
		var keep *int64
		for i, x := range sets {
			older := i != anchor && !after(x.launch, a.launch)
			if older && !x.local && !isBase[x.label] {
				continue
			}
			if older && !isBase[x.label] && x.finished != nil && !x.finished.After(now.Add(-window-held)) {
				plan.HeldByLocal++
			}
			staying[x.label] = true
			if x.launch == nil {
				return nil // launched before the numbers existed: nothing is planned
			}
			if keep == nil || *x.launch < *keep {
				keep = x.launch
			}
		}
		plan.KeepLaunch = *keep
		rows, err = tx.Query(ctx, planKeysQ, subject, *keep)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				return err
			}
			kind, _, label, ok := walname.RepoPath(stanza, key)
			if !ok || !plannedKinds[kind] || label != "" && staying[label] {
				continue
			}
			if len(plan.Keys) == max {
				plan.More = true
				break
			}
			plan.Keys = append(plan.Keys, key)
		}
		return rows.Err()
	})
	if err != nil {
		return ExpirePlan{}, wrap(err)
	}
	return plan, nil
}

// RecordPass records a schedule pass at now. A pass more than late after the
// previous one, or earlier than it, is a jump: it sets the clock hold until
// now + hold. A node's first pass sets the hold and is no jump. holdUntil is
// the hold this pass set, nil when it set none.
func (s *Store) RecordPass(ctx context.Context, now time.Time, late, hold time.Duration) (jumped bool, holdUntil *time.Time, err error) {
	if late <= 0 || hold <= 0 {
		return false, nil, fmt.Errorf("%w: late %v, hold %v", ErrConflict, late, hold)
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		var prev *time.Time
		if err := tx.QueryRow(ctx, "select pass_at from node order by id limit 1 for update").Scan(&prev); err != nil {
			return err
		}
		jumped = prev != nil && (now.After(prev.Add(late)) || now.Before(*prev))
		if prev == nil || jumped {
			until := now.Add(hold)
			holdUntil = &until
		}
		_, err := tx.Exec(ctx, "update node set pass_at = $1, clock_hold_until = coalesce($2, clock_hold_until)", now, holdUntil)
		return err
	})
	if err != nil {
		return false, nil, err
	}
	return jumped, holdUntil, nil
}

// ClockHold reports whether the clock hold stands at now.
func (s *Store) ClockHold(ctx context.Context, now time.Time) (bool, error) {
	var held bool
	err := s.pool.QueryRow(ctx, "select coalesce(bool_or(clock_hold_until > $1), false) from node", now).Scan(&held)
	return held, wrap(err)
}

// UnrecordedRow is a listed current key the record did not hold, with its
// oldest version as listed.
type UnrecordedRow struct {
	Key, VersionID string
	At             time.Time
	Size           int64
}

// MergeUnrecorded records rows as a rebuild page records them — no hash —
// under the launch number of job jobID, a job of subject. A job without a
// number is ErrNoLaunch; a row without its version id is refused. Both before
// any row is written. A key already recorded keeps its row.
func (s *Store) MergeUnrecorded(ctx context.Context, subject string, rows []UnrecordedRow, jobID int64) error {
	if len(rows) > maxRunKeys {
		return fmt.Errorf("%w: %d rows, at most %d", ErrConflict, len(rows), maxRunKeys)
	}
	keys, sizes, versions, ats := make([]string, len(rows)), make([]int64, len(rows)), make([]string, len(rows)), make([]time.Time, len(rows))
	for i, r := range rows {
		if r.Key == "" || !fits(r.Key) || r.VersionID == "" || !fits(r.VersionID) || r.Size < 0 || r.Size > bklimit.SetFileMax {
			return fmt.Errorf("%w: unrecorded row %.64q refused", ErrConflict, r.Key)
		}
		keys[i], sizes[i], versions[i], ats[i] = r.Key, r.Size, r.VersionID, r.At
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := stateOf(ctx, tx, subject); err != nil {
			return err
		}
		var launch *int64
		if err := tx.QueryRow(ctx, "select launch from backup_job where id = $1 and subject = $2", jobID, subject).Scan(&launch); errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: job %d is no job of %s", ErrConflict, jobID, subject)
		} else if err != nil {
			return err
		}
		if launch == nil || *launch <= 0 {
			return ErrNoLaunch
		}
		_, err := tx.Exec(ctx, `insert into offsite_object (subject, key, size, version_id, uploaded_at, launch)
			select $1, key, size, version_id, uploaded_at, $6
			from unnest($2::text[], $3::bigint[], $4::text[], $5::timestamptz[]) as t(key, size, version_id, uploaded_at)
			on conflict (subject, key) do nothing`, subject, keys, sizes, versions, ats, *launch)
		return err
	})
}

// MarkPurgeSeen records the pass that first saw the subject's purge flag.
func (s *Store) MarkPurgeSeen(ctx context.Context, subject string, at time.Time) error {
	_, err := s.pool.Exec(ctx, "update backup_state set offsite_purge_seen_at = $2 where subject = $1 and offsite_purge_seen_at is null", subject, at)
	return wrap(err)
}

// PurgeAllowed decides an off-site purge at launch: reason "state" unless the
// flag is set and the project is purged (any epoch) or aborted in this epoch;
// "wait" until window after the pass first saw the flag, or the wait was
// waived. ErrNotRebuilt and ErrClock as for a plan. It writes nothing.
func (s *Store) PurgeAllowed(ctx context.Context, subject string, window time.Duration, now time.Time) (ok bool, reason string, err error) {
	var rebuilt, flag, stateOK, ahead bool
	var seen *time.Time
	err = s.pool.QueryRow(ctx, `select b.rebuild_epoch >= (select epoch from cp_meta), b.offsite_purge, b.offsite_purge_seen_at,
			coalesce(p.state = 'purged' or p.state = 'aborted' and p.epoch = (select epoch from cp_meta), false),
			exists (select 1 from backup_job j where j.subject = b.subject and greatest(j.created_at, j.started_at, j.finished_at) > $2)
		from backup_state b left join project p on p.ref = b.subject where b.subject = $1`, subject, now).
		Scan(&rebuilt, &flag, &seen, &stateOK, &ahead)
	switch {
	case err != nil:
		return false, "", wrap(err)
	case !rebuilt:
		return false, "", ErrNotRebuilt
	case ahead:
		return false, "", ErrClock
	case !flag || !stateOK:
		return false, "state", nil
	case seen == nil || seen.Add(window).After(now):
		return false, "wait", nil
	}
	return true, "", nil
}

// SetPurgeWait applies the operator's choice for a subject's purge: keep
// clears the obligation, now waives the wait — only while the purge flag is
// set; without it ErrConflict. Exactly one is true.
func (s *Store) SetPurgeWait(ctx context.Context, subject string, keep, now bool) error {
	switch {
	case keep == now:
		return fmt.Errorf("%w: keep or now, one of them", ErrConflict)
	case keep:
		return s.ClearOffsitePurge(ctx, subject)
	}
	// Only while the flag is set: a waiver given earlier would waive the wait
	// of a purge flagged later.
	tag, err := s.pool.Exec(ctx, "update backup_state set offsite_purge_seen_at = timestamptz 'epoch' where subject = $1 and offsite_purge", subject)
	if err != nil || tag.RowsAffected() == 1 {
		return wrap(err)
	}
	var one int
	if err := s.pool.QueryRow(ctx, "select 1 from backup_state where subject = $1", subject).Scan(&one); err != nil {
		return wrap(err)
	}
	return fmt.Errorf("%w: %s has no off-site purge to waive the wait of", ErrConflict, subject)
}

// ClearOffsitePurge clears the subject's purge flag and its first sighting.
func (s *Store) ClearOffsitePurge(ctx context.Context, subject string) error {
	return s.updateOne(ctx, "update backup_state set offsite_purge = false, offsite_purge_seen_at = null where subject = $1", subject)
}

// PruneObjects removes the rows of keys, which an off-site expire marked; a
// set one of whose files is among them gets offsite_removed_at = at when it
// has none.
func (s *Store) PruneObjects(ctx context.Context, subject string, keys []string, at time.Time) error {
	if len(keys) > maxRunKeys {
		return fmt.Errorf("%w: %d keys, at most %d", ErrConflict, len(keys), maxRunKeys)
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		stanza, err := stateOf(ctx, tx, subject)
		if err != nil {
			return err
		}
		var labels []string
		for _, k := range keys {
			if _, _, label, ok := walname.RepoPath(stanza, k); ok && label != "" {
				labels = append(labels, label)
			}
		}
		if _, err := tx.Exec(ctx, "delete from offsite_object where subject = $1 and key = any($2)", subject, keys); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `update backup_set set offsite_removed_at = $3
			where subject = $1 and label = any($2) and offsite_removed_at is null`, subject, labels, at)
		return err
	})
}

type infoQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func collectInfo(rows pgx.Rows, err error) ([]InfoVersion, error) {
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[InfoVersion])
}

func infoAsOf(ctx context.Context, q infoQuerier, subject string, asOf time.Time) ([]InfoVersion, error) {
	return collectInfo(q.Query(ctx, `select distinct on (name) name, version_id, sha256, uploaded_at from offsite_info_version
		where subject = $1 and uploaded_at <= $2 order by name, uploaded_at desc, version_id desc`, subject, asOf))
}

// infoFor is InfoVersionsFor on q.
func infoFor(ctx context.Context, q infoQuerier, subject, label string) (asListed, whileLocal []InfoVersion, err error) {
	var listed, local *time.Time
	if err := q.QueryRow(ctx, "select listed_at, expired_local_at from backup_set where subject = $1 and label = $2", subject, label).
		Scan(&listed, &local); err != nil {
		return nil, nil, err
	}
	if listed == nil {
		return nil, nil, nil
	}
	if asListed, err = infoAsOf(ctx, q, subject, *listed); err != nil {
		return nil, nil, err
	}
	whileLocal, err = collectInfo(q.Query(ctx, `select distinct on (name) name, version_id, sha256, uploaded_at from offsite_info_version
		where subject = $1 and uploaded_at > $2 and ($3::timestamptz is null or uploaded_at < $3)
		order by name, uploaded_at, version_id`, subject, *listed, local))
	return asListed, whileLocal, err
}

// PruneInfoVersions removes the info version rows uploaded before before,
// keeping each name's newest and both candidates InfoVersionsFor returns for
// every set that is replicated and not removed off-site.
func (s *Store) PruneInfoVersions(ctx context.Context, subject string, before time.Time) (int, error) {
	var n int
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := stateOf(ctx, tx, subject); err != nil {
			return err
		}
		keep, err := collectInfo(tx.Query(ctx, `select distinct on (name) name, version_id, sha256, uploaded_at from offsite_info_version
			where subject = $1 order by name, uploaded_at desc, version_id desc`, subject))
		if err != nil {
			return err
		}
		rows, _ := tx.Query(ctx, "select label from backup_set where subject = $1 and replicated and offsite_removed_at is null", subject)
		labels, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, l := range labels {
			a, w, err := infoFor(ctx, tx, subject, l)
			if err != nil {
				return err
			}
			keep = append(append(keep, a...), w...)
		}
		ids := make([]string, len(keep))
		for i, v := range keep {
			ids[i] = v.Name + "/" + v.VersionID
		}
		tag, err := tx.Exec(ctx, `delete from offsite_info_version where subject = $1 and uploaded_at < $2
			and not (name || '/' || version_id = any($3))`, subject, before, ids)
		n = int(tag.RowsAffected())
		return err
	})
	return n, err
}

// DropsSince counts the spool drops submitted on the node since since.
func (s *Store) DropsSince(ctx context.Context, since time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, "select count(*) from backup_job where kind = 'drop-spool' and created_at >= $1", since).Scan(&n)
	return n, wrap(err)
}

// InfoVersionsAsOf returns, per name, the newest info version uploaded at or
// before asOf.
func (s *Store) InfoVersionsAsOf(ctx context.Context, subject string, asOf time.Time) ([]InfoVersion, error) {
	l, err := infoAsOf(ctx, s.pool, subject, asOf)
	return l, wrap(err)
}

// InfoVersionsFor returns a set's two candidates for a fetch: the info
// versions as of its listing, and per name the oldest later version uploaded
// while the set was still at the same location. A set never listed has none.
func (s *Store) InfoVersionsFor(ctx context.Context, subject, label string) (asListed, whileLocal []InfoVersion, err error) {
	asListed, whileLocal, err = infoFor(ctx, s.pool, subject, label)
	return asListed, whileLocal, wrap(err)
}

// SetsListedBy returns the labels of the subject's replicated sets listed at
// or before asOf and not removed off-site.
func (s *Store) SetsListedBy(ctx context.Context, subject string, asOf time.Time) ([]string, error) {
	rows, _ := s.pool.Query(ctx, `select label from backup_set where subject = $1 and replicated and listed_at <= $2
		and offsite_removed_at is null order by label`, subject, asOf)
	l, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return l, wrap(err)
}
