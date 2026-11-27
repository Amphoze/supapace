package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/walname"
)

type BackupState struct {
	Subject                                                    string
	Incarnation                                                string
	StanzaCreated                                              bool
	LastPushOK, LastReplOK, SpoolOldest, ReplPausedUntil       *time.Time
	SeededAt, QuotaAt                                          *time.Time
	SpoolEntries                                               *int
	SpoolBytes, DiskUsedKB, DiskHardKB, RepoUsedKB, RepoHardKB *int64
	NewestSegment                                              string
	ForcedFullDay, BudgetDay                                   *time.Time
	BytesToday                                                 int64
	ObjectsToday                                               int
	RebuildEpoch                                               int64
	RebuildKeyMarker, RebuildVersionMarker                     string
	RebuildPages                                               int
	OffsitePurge                                               bool
}

type BackupSet struct {
	Subject, Label                               string
	TLI                                          int
	StartSegment, StopSegment, StartLSN, StopLSN string
	StartAt, StopAt                              time.Time
	JobID                                        int64
	Replicated                                   bool
	ListedAt                                     *time.Time
}

type Timeline struct {
	TLI   int
	State string
	OpID  int64
}

type ObjectRow struct {
	Key          string
	Size         int64
	SHA256       []byte
	Ino, CtimeNS int64
	VersionID    string
	UploadedAt   time.Time
}

type InfoVersion struct {
	Name, VersionID string
	SHA256          []byte
	UploadedAt      time.Time
}

// QuotaUse is the host-side quota report of one uid on both filesystems. The
// agent declares the same shape; the runner converts.
type QuotaUse struct{ DiskUsedKB, DiskHardKB, RepoUsedKB, RepoHardKB int64 }

type PushRecord struct {
	Complete      bool
	Pushed        int
	NewestSegment string
	SpoolEntries  int
	SpoolBytes    int64
	SpoolOldest   *time.Time
	Gaps          []Gap
	Quota         *QuotaUse
	At            time.Time
}

type Gap struct{ Cause, First, Last, Detail string }

type Notice struct {
	Code            string
	Count           int64
	FirstAt, LastAt time.Time
	Detail          string
}

type Uploads struct {
	Rows          []ObjectRow
	Info          []InfoVersion
	SetsComplete  []string
	Complete      bool
	BudgetBytes   int64
	BudgetObjects int
	At            time.Time
	Launch        int64 // the launch number of the job whose result this is (Job.Launch)
}

type ListingPage struct {
	Rows                             []ObjectRow
	NextKeyMarker, NextVersionMarker string
	Last                             bool
	Launch                           int64 // the launch number of the job whose result this is (Job.Launch)
}

var ErrTimelineConflict = errors.New("store: timeline is off-site but not in the repository")

// maxText bounds every text a job or a listing hands in that the store keeps
// as a detail.
const maxText = 256

var (
	segmentRE  = regexp.MustCompile(`^[0-9A-F]{24}$`)
	setLabelRE = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}F$`)
)

// detail caps a text for a detail column: no control or invalid byte, at most
// maxText bytes, never a split character.
func detail(s string) string { return pgsock.Sanitize(s, maxText) }

// fits: at most 1,024 bytes without a control byte — a key, a version id, a
// marker. The database refuses invalid UTF-8 itself.
func fits(s string) bool {
	return len(s) <= 1024 && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// stateOf locks the subject's row and returns its stanza.
func stateOf(ctx context.Context, tx pgx.Tx, subject string) (stanza string, err error) {
	var inc string
	if err := tx.QueryRow(ctx, "select incarnation from backup_state where subject = $1 for update", subject).Scan(&inc); err != nil {
		return "", err
	}
	return subject + "-" + inc, nil
}

func notice(ctx context.Context, tx pgx.Tx, subject, code, text string) error {
	_, err := tx.Exec(ctx, `insert into backup_notice (subject, code, detail) values ($1, $2, $3)
		on conflict (subject, code) do update set count = backup_notice.count + 1, last_at = now(), detail = excluded.detail`,
		subject, code, detail(text))
	return err
}

// updateOne runs q, which must change the subject's row; none is ErrNotFound.
func (s *Store) updateOne(ctx context.Context, q string, args ...any) error {
	tag, err := s.pool.Exec(ctx, q, args...)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return wrap(err)
}

// EnsureBackupState inserts the subject's row once. A project's incarnation is
// "1"; the control plane's is its own database system identifier as an
// unsigned decimal, read when the row is inserted and never changed.
func (s *Store) EnsureBackupState(ctx context.Context, subject string) error {
	inc := "1"
	if subject == "cp" {
		var id int64
		if err := s.pool.QueryRow(ctx, "select system_identifier from pg_control_system()").Scan(&id); err != nil {
			return wrap(err)
		}
		inc = strconv.FormatUint(uint64(id), 10)
	}
	_, err := s.pool.Exec(ctx, "insert into backup_state (subject, incarnation) values ($1, $2) on conflict (subject) do nothing", subject, inc)
	return wrap(err)
}

const stateCols = `subject, incarnation, stanza_created, last_push_ok, last_repl_ok, spool_oldest, repl_paused_until, seeded_at, quota_at,
	spool_entries, spool_bytes, disk_used_kb, disk_hard_kb, repo_used_kb, repo_hard_kb, coalesce(newest_segment, ''),
	forced_full_day, budget_day, bytes_today, objects_today, rebuild_epoch, rebuild_key_marker, rebuild_version_marker,
	rebuild_pages, offsite_purge`

func (s *Store) GetBackupState(ctx context.Context, subject string) (BackupState, error) {
	var b BackupState
	err := s.pool.QueryRow(ctx, "select "+stateCols+" from backup_state where subject = $1", subject).Scan(
		&b.Subject, &b.Incarnation, &b.StanzaCreated, &b.LastPushOK, &b.LastReplOK, &b.SpoolOldest, &b.ReplPausedUntil, &b.SeededAt,
		&b.QuotaAt, &b.SpoolEntries, &b.SpoolBytes, &b.DiskUsedKB, &b.DiskHardKB, &b.RepoUsedKB, &b.RepoHardKB, &b.NewestSegment,
		&b.ForcedFullDay, &b.BudgetDay, &b.BytesToday, &b.ObjectsToday, &b.RebuildEpoch, &b.RebuildKeyMarker,
		&b.RebuildVersionMarker, &b.RebuildPages, &b.OffsitePurge)
	return b, wrap(err)
}

// MarkStanza records that the stanza exists and, for a project, timeline 1.
func (s *Store) MarkStanza(ctx context.Context, subject string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "update backup_state set stanza_created = true where subject = $1", subject)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if subject == "cp" {
			return nil
		}
		_, err = tx.Exec(ctx, `insert into backup_timeline (subject, tli, state, launch) values ($1, 1, 'recorded', 0)
			on conflict (subject, tli) do nothing`, subject)
		return err
	})
}

// RecordPush records what a push job reported: the push time only when the
// job was complete, the spool figures, the newest segment when one was
// reported, the quota report when there is one, and each gap with its notice.
func (s *Store) RecordPush(ctx context.Context, subject string, r PushRecord) error {
	for _, g := range r.Gaps {
		if g.Cause != "quarantine" {
			return fmt.Errorf("store: gap cause %q refused", g.Cause)
		}
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `update backup_state set
				last_push_ok = case when $2 then $3 else last_push_ok end,
				spool_entries = $4, spool_bytes = $5, spool_oldest = $6,
				newest_segment = coalesce(nullif($7, ''), newest_segment)
			where subject = $1`, subject, r.Complete, r.At, r.SpoolEntries, r.SpoolBytes, r.SpoolOldest, r.NewestSegment)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if q := r.Quota; q != nil {
			if _, err := tx.Exec(ctx, `update backup_state set disk_used_kb = $2, disk_hard_kb = $3, repo_used_kb = $4, repo_hard_kb = $5,
				quota_at = $6 where subject = $1`, subject, q.DiskUsedKB, q.DiskHardKB, q.RepoUsedKB, q.RepoHardKB, r.At); err != nil {
				return err
			}
		}
		for _, g := range r.Gaps {
			if _, err := tx.Exec(ctx, `insert into backup_gap (subject, cause, first_segment, last_segment, detail, at)
				values ($1, $2, $3, $4, $5, $6)`, subject, g.Cause, detail(g.First), detail(g.Last), detail(g.Detail), r.At); err != nil {
				return err
			}
			if err := notice(ctx, tx, subject, g.Cause, g.Detail); err != nil {
				return err
			}
		}
		return nil
	})
}

// RecordSet records a full backup set. A label already recorded for the
// subject keeps its first record.
func (s *Store) RecordSet(ctx context.Context, b BackupSet) error {
	if !setLabelRE.MatchString(b.Label) || !segmentRE.MatchString(b.StartSegment) || !segmentRE.MatchString(b.StopSegment) {
		return fmt.Errorf("store: backup set %.64q refused", b.Label)
	}
	_, err := s.pool.Exec(ctx, `insert into backup_set (subject, label, tli, start_segment, stop_segment, start_lsn, stop_lsn,
			start_at, stop_at, job_id) values ($1, $2, $3, $4, $5, $6::pg_lsn, $7::pg_lsn, $8, $9, $10)
		on conflict (subject, label) do nothing`,
		b.Subject, b.Label, b.TLI, b.StartSegment, b.StopSegment, b.StartLSN, b.StopLSN, b.StartAt, b.StopAt, b.JobID)
	return wrap(err)
}

// ListSets returns the subject's sets, oldest first.
func (s *Store) ListSets(ctx context.Context, subject string) ([]BackupSet, error) {
	rows, _ := s.pool.Query(ctx, `select subject, label, tli, start_segment, stop_segment, start_lsn::text, stop_lsn::text,
		start_at, stop_at, job_id, replicated, listed_at from backup_set where subject = $1 order by stop_at, label`, subject)
	sets, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (BackupSet, error) {
		var b BackupSet
		err := r.Scan(&b.Subject, &b.Label, &b.TLI, &b.StartSegment, &b.StopSegment, &b.StartLSN, &b.StopLSN,
			&b.StartAt, &b.StopAt, &b.JobID, &b.Replicated, &b.ListedAt)
		return b, err
	})
	return sets, wrap(err)
}

// MarkForcedFull takes the subject's one forced full backup of day (UTC):
// false when it was already taken that day.
func (s *Store) MarkForcedFull(ctx context.Context, subject string, day time.Time) (bool, error) {
	d := day.UTC()
	tag, err := s.pool.Exec(ctx, `update backup_state set forced_full_day = $2::date
		where subject = $1 and (forced_full_day is null or forced_full_day < $2::date)`, subject, d.Format(time.DateOnly))
	return err == nil && tag.RowsAffected() == 1, wrap(err)
}

// RecordUploads records what a copy job uploaded or adopted, in one
// transaction. A new key is inserted. A key already recorded is never
// changed when its row has a hash; a row without one (rebuilt from a listing)
// takes the new hash, inode and ctime only under the same version id (a
// missing one never matches),
// and otherwise stays as it is and raises notice offsite-differs.
// A new row takes u.Launch, the copy job's launch number; one that is not
// above zero is ErrNoLaunch, and nothing is written.
func (s *Store) RecordUploads(ctx context.Context, subject string, u Uploads) (overBudget bool, err error) {
	if u.Launch <= 0 {
		return false, ErrNoLaunch
	}
	if len(u.Rows) > bklimit.ReplMaxFiles || len(u.Info) > 4 || len(u.SetsComplete) > bklimit.ReplMaxFiles {
		return false, fmt.Errorf("store: %d rows, %d info versions, %d sets: above the job's caps", len(u.Rows), len(u.Info), len(u.SetsComplete))
	}
	n := len(u.Rows)
	keys, sizes, hashes, inos, ctimes, versions, ats := make([]string, 0, n), make([]int64, 0, n), make([][]byte, 0, n),
		make([]int64, 0, n), make([]int64, 0, n), make([]string, 0, n), make([]time.Time, 0, n)
	seen := make(map[string]bool, n)
	var bytes int64
	for _, r := range u.Rows {
		if r.Key == "" || !fits(r.Key) || !fits(r.VersionID) || r.Size < 0 || r.Size > bklimit.SetFileMax || len(r.SHA256) != 32 || r.Ino < 0 || r.CtimeNS < 0 {
			return false, fmt.Errorf("store: object row %.64q refused", r.Key)
		}
		bytes += r.Size
		if seen[r.Key] { // the first of a repeated key is the one recorded
			continue
		}
		seen[r.Key] = true
		keys, sizes, hashes, inos, ctimes = append(keys, r.Key), append(sizes, r.Size), append(hashes, r.SHA256), append(inos, r.Ino), append(ctimes, r.CtimeNS)
		versions, ats = append(versions, r.VersionID), append(ats, r.UploadedAt)
	}
	for _, v := range u.Info {
		if v.VersionID == "" || !fits(v.VersionID) || len(v.SHA256) != 32 {
			return false, fmt.Errorf("store: info version of %.32q refused", v.Name)
		}
	}
	for _, l := range u.SetsComplete {
		if !setLabelRE.MatchString(l) {
			return false, fmt.Errorf("store: set label %.64q refused", l)
		}
	}
	day := u.At.UTC().Format(time.DateOnly)
	err = s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := stateOf(ctx, tx, subject); err != nil {
			return err
		}
		// The select reads the rows as they were before the insert: a key whose
		// row had no hash and was not adopted by the insert differs.
		differs, _ := tx.Query(ctx, `with i as (select * from unnest($2::text[], $3::bigint[], $4::bytea[], $5::bigint[], $6::bigint[],
				$7::text[], $8::timestamptz[]) as t(key, size, sha256, ino, ctime_ns, version_id, uploaded_at)),
			w as (insert into offsite_object (subject, key, size, sha256, ino, ctime_ns, version_id, uploaded_at, launch)
				select $1, key, size, sha256, ino, ctime_ns, nullif(version_id, ''), uploaded_at, $9 from i
				on conflict (subject, key) do update set sha256 = excluded.sha256, ino = excluded.ino, ctime_ns = excluded.ctime_ns
				where offsite_object.sha256 is null and offsite_object.version_id = excluded.version_id
				returning key)
			select o.key from offsite_object o join i on o.key = i.key
			where o.subject = $1 and o.sha256 is null and o.key not in (select key from w)`,
			subject, keys, sizes, hashes, inos, ctimes, versions, ats, u.Launch)
		dk, err := pgx.CollectRows(differs, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, k := range dk {
			if err := notice(ctx, tx, subject, "offsite-differs", k); err != nil {
				return err
			}
		}
		for _, v := range u.Info {
			if _, err := tx.Exec(ctx, `insert into offsite_info_version (subject, name, version_id, sha256, uploaded_at)
				values ($1, $2, $3, $4, $5) on conflict do nothing`, subject, v.Name, v.VersionID, v.SHA256, v.UploadedAt); err != nil {
				return err
			}
		}
		if len(u.SetsComplete) > 0 {
			if _, err := tx.Exec(ctx, `update backup_set b set replicated = true,
					listed_at = case when b.listed_at is null and ($3 or exists (select 1 from offsite_info_version v
						where v.subject = b.subject and v.name in ('backup.info', 'backup.info.copy') and v.uploaded_at >= b.stop_at)) then $4 else b.listed_at end
				where b.subject = $1 and b.label = any($2)`, subject, u.SetsComplete, len(u.Info) > 0, u.At); err != nil {
				return err
			}
		}
		return tx.QueryRow(ctx, `update backup_state set
				budget_day = greatest(budget_day, $2::date),
				bytes_today = case when budget_day is null or budget_day < $2::date then 0 else bytes_today end + $3,
				objects_today = case when budget_day is null or budget_day < $2::date then 0 else objects_today end + $4,
				last_repl_ok = case when $5 then $6 else last_repl_ok end
			where subject = $1
			returning ($7::bigint > 0 and bytes_today > $7::bigint) or ($8::bigint > 0 and objects_today > $8::bigint)`,
			subject, day, bytes, len(u.Rows), u.Complete, u.At, u.BudgetBytes, u.BudgetObjects).Scan(&overBudget)
	})
	return overBudget, err
}

// ObjectRows streams the subject's record in byte order of the key.
func (s *Store) ObjectRows(ctx context.Context, subject string, fn func(ObjectRow) error) error {
	rows, err := s.pool.Query(ctx, `select key, size, sha256, coalesce(ino, 0), coalesce(ctime_ns, 0), coalesce(version_id, ''), uploaded_at
		from offsite_object where subject = $1 order by key collate "C"`, subject)
	if err != nil {
		return wrap(err)
	}
	defer rows.Close()
	var r ObjectRow
	for rows.Next() {
		if err := rows.Scan(&r.Key, &r.Size, &r.SHA256, &r.Ino, &r.CtimeNS, &r.VersionID, &r.UploadedAt); err != nil {
			return wrap(err)
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return wrap(rows.Err())
}

func (s *Store) ObjectCount(ctx context.Context, subject string) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, "select count(*) from offsite_object where subject = $1", subject).Scan(&n)
	return n, wrap(err)
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// archiveRows calls fn for every recorded key under archive/<stanza>/ whose
// last component is like base (a LIKE pattern), with its upload time, until
// fn returns false. The candidates are in descending order of their last
// component; fn checks each with walname.RepoPath.
func archiveRows(ctx context.Context, q querier, subject, stanza, base string, fn func(key string, at time.Time) bool) error {
	rows, err := q.Query(ctx, `select key, uploaded_at from offsite_object
		where subject = $1 and starts_with(key, $2) and key like '%/' || $3
		order by reverse(split_part(reverse(key), '/', 1)) collate "C" desc`, subject, "archive/"+stanza+"/", base)
	if err != nil {
		return err
	}
	defer rows.Close()
	var key string
	var at time.Time
	for rows.Next() {
		if err := rows.Scan(&key, &at); err != nil {
			return err
		}
		if !fn(key, at) {
			break
		}
	}
	return rows.Err()
}

// hasArchive reports whether the record holds name — a segment (any hash
// suffix), a history file or a backup label — under any archive id.
func hasArchive(ctx context.Context, q querier, subject, stanza, name string) (bool, error) {
	k, tli, ok := walname.Spool(name)
	if !ok {
		return false, fmt.Errorf("store: archive name %.64q refused", name)
	}
	pattern, match := name, func(b string) bool { return b == name }
	if k == walname.Segment {
		pattern, match = name+"-%", func(b string) bool { return strings.HasPrefix(b, name+"-") }
	}
	found := false
	err := archiveRows(ctx, q, subject, stanza, pattern, func(key string, _ time.Time) bool {
		kk, t, _, ok := walname.RepoPath(stanza, key)
		found = ok && kk == k && t == tli && match(path.Base(key))
		return !found
	})
	return found, err
}

// HasArchiveObject reports whether the record holds name under any archive id
// of stanza.
func (s *Store) HasArchiveObject(ctx context.Context, subject, stanza, name string) (bool, error) {
	ok, err := hasArchive(ctx, s.pool, subject, stanza, name)
	return ok, wrap(err)
}

// SegmentReplicated: the record holds that segment (its timeline, any archive
// id and hash suffix) and a complete replication ended at or after its upload.
func (s *Store) SegmentReplicated(ctx context.Context, subject, segment string) (bool, error) {
	if !segmentRE.MatchString(segment) {
		return false, fmt.Errorf("store: segment %.64q refused", segment)
	}
	var inc string
	var replOK *time.Time
	if err := s.pool.QueryRow(ctx, "select incarnation, last_repl_ok from backup_state where subject = $1", subject).Scan(&inc, &replOK); err != nil {
		return false, wrap(err)
	}
	stanza := subject + "-" + inc
	tli, _ := strconv.ParseUint(segment[:8], 16, 32)
	found := false
	err := archiveRows(ctx, s.pool, subject, stanza, segment+"-%", func(key string, at time.Time) bool {
		k, t, _, ok := walname.RepoPath(stanza, key)
		found = ok && k == walname.Segment && uint64(t) == tli && strings.HasPrefix(path.Base(key), segment+"-") &&
			replOK != nil && !replOK.Before(at)
		return !found
	})
	return found, wrap(err)
}

// NewestRecordedSegment is the highest segment of timeline tli in the record,
// "" when none.
func (s *Store) NewestRecordedSegment(ctx context.Context, subject string, tli int) (segment string, err error) {
	if tli < 1 || tli > math.MaxUint32 {
		return "", fmt.Errorf("store: timeline %d refused", tli)
	}
	var inc string
	if err := s.pool.QueryRow(ctx, "select incarnation from backup_state where subject = $1", subject).Scan(&inc); err != nil {
		return "", wrap(err)
	}
	stanza := subject + "-" + inc
	hex := fmt.Sprintf("%08X", tli)
	err = archiveRows(ctx, s.pool, subject, stanza, hex+"%.zst", func(key string, _ time.Time) bool {
		if k, t, _, ok := walname.RepoPath(stanza, key); ok && k == walname.Segment && int(t) == tli {
			segment = path.Base(key)[:24]
			return false
		}
		return true
	})
	return segment, wrap(err)
}

// MergeListing merges one page of a rebuild listing, in one transaction. A
// new row takes page.Launch, the rebuild job's launch number; one that is
// not above zero is ErrNoLaunch, and nothing is written.
func (s *Store) MergeListing(ctx context.Context, subject string, page ListingPage, epoch int64) error {
	if page.Launch <= 0 {
		return ErrNoLaunch
	}
	if len(page.Rows) > bklimit.RebuildPageRows {
		return fmt.Errorf("store: %d listed rows, at most %d", len(page.Rows), bklimit.RebuildPageRows)
	}
	if !fits(page.NextKeyMarker) || !fits(page.NextVersionMarker) {
		return fmt.Errorf("store: listing markers refused")
	}
	// A key listed twice in one page (two versions) is merged once: the last
	// listed is its oldest version.
	idx := make(map[string]int, len(page.Rows))
	var rows []ObjectRow
	for _, r := range page.Rows {
		if r.Key == "" || !fits(r.Key) || !fits(r.VersionID) || r.Size < 0 {
			return fmt.Errorf("store: object row %.64q refused", r.Key)
		}
		if i, ok := idx[r.Key]; ok {
			rows[i] = r
			continue
		}
		idx[r.Key] = len(rows)
		rows = append(rows, r)
	}
	keys, sizes, versions, ats := make([]string, len(rows)), make([]int64, len(rows)), make([]string, len(rows)), make([]time.Time, len(rows))
	for i, r := range rows {
		keys[i], sizes[i], versions[i], ats[i] = r.Key, r.Size, r.VersionID, r.UploadedAt
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		stanza, err := stateOf(ctx, tx, subject)
		if err != nil {
			return err
		}
		var done int64
		if err := tx.QueryRow(ctx, "select rebuild_epoch from backup_state where subject = $1", subject).Scan(&done); err != nil {
			return err
		}
		if done >= epoch {
			return fmt.Errorf("%w: the record of %s is already rebuilt for epoch %d", ErrConflict, subject, done)
		}
		// A row that has a hash keeps everything but seen_epoch; a row rebuilt
		// from a listing takes what this listing says.
		if _, err := tx.Exec(ctx, `insert into offsite_object (subject, key, size, version_id, uploaded_at, seen_epoch, launch)
				select $1, key, size, nullif(version_id, ''), uploaded_at, $6, $7
				from unnest($2::text[], $3::bigint[], $4::text[], $5::timestamptz[]) as t(key, size, version_id, uploaded_at)
			on conflict (subject, key) do update set seen_epoch = excluded.seen_epoch,
				size = case when offsite_object.sha256 is null then excluded.size else offsite_object.size end,
				version_id = case when offsite_object.sha256 is null then excluded.version_id else offsite_object.version_id end,
				uploaded_at = case when offsite_object.sha256 is null then excluded.uploaded_at else offsite_object.uploaded_at end`,
			subject, keys, sizes, versions, ats, epoch, page.Launch); err != nil {
			return err
		}
		if subject != "cp" {
			var tlis []int32
			for _, k := range keys {
				if kind, t, _, ok := walname.RepoPath(stanza, k); ok && kind == walname.History && t >= 1 && t <= math.MaxInt32 {
					tlis = append(tlis, int32(t))
				}
			}
			if len(tlis) > 0 {
				if _, err := tx.Exec(ctx, `insert into backup_timeline (subject, tli, state, launch)
					select $1, tli, 'abandoned', 0 from unnest($2::integer[]) as t(tli) on conflict (subject, tli) do nothing`, subject, tlis); err != nil {
					return err
				}
			}
		}
		if !page.Last {
			_, err := tx.Exec(ctx, `update backup_state set rebuild_key_marker = $2, rebuild_version_marker = $3,
				rebuild_pages = rebuild_pages + 1 where subject = $1`, subject, page.NextKeyMarker, page.NextVersionMarker)
			return err
		}
		var missing int64
		if err := tx.QueryRow(ctx, "select count(*) from offsite_object where subject = $1 and seen_epoch < $2", subject, epoch).Scan(&missing); err != nil {
			return err
		}
		if missing > 0 {
			if err := notice(ctx, tx, subject, "record-not-in-store", strconv.FormatInt(missing, 10)+" recorded objects not listed"); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `update backup_state set rebuild_key_marker = '', rebuild_version_marker = '', rebuild_pages = 0,
			rebuild_epoch = $2 where subject = $1`, subject, epoch)
		return err
	})
}

func (s *Store) PauseReplication(ctx context.Context, subject string, until time.Time) error {
	return s.updateOne(ctx, "update backup_state set repl_paused_until = $2 where subject = $1", subject, until)
}

// Notice raises notice code for the subject: the first raise inserts it, each
// later one adds one to its count and replaces its time and detail.
func (s *Store) Notice(ctx context.Context, subject, code, text string) error {
	return s.tx(ctx, func(tx pgx.Tx) error { return notice(ctx, tx, subject, code, text) })
}

// ListNotices returns the subject's notices, the most recent first.
func (s *Store) ListNotices(ctx context.Context, subject string) ([]Notice, error) {
	rows, _ := s.pool.Query(ctx, `select code, count, first_at, last_at, detail from backup_notice where subject = $1
		order by last_at desc, code`, subject)
	ns, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Notice, error) {
		var n Notice
		return n, r.Scan(&n.Code, &n.Count, &n.FirstAt, &n.LastAt, &n.Detail)
	})
	return ns, wrap(err)
}

// ListGaps returns the subject's newest 64 gaps, newest first, with the time
// of each.
func (s *Store) ListGaps(ctx context.Context, subject string) ([]Gap, []time.Time, error) {
	rows, err := s.pool.Query(ctx, `select cause, first_segment, last_segment, detail, at from backup_gap where subject = $1
		order by id desc limit 64`, subject)
	if err != nil {
		return nil, nil, wrap(err)
	}
	defer rows.Close()
	gaps, ats := []Gap{}, []time.Time{}
	for rows.Next() {
		var g Gap
		var at time.Time
		if err := rows.Scan(&g.Cause, &g.First, &g.Last, &g.Detail, &at); err != nil {
			return nil, nil, wrap(err)
		}
		gaps, ats = append(gaps, g), append(ats, at)
	}
	return gaps, ats, wrap(rows.Err())
}

// ListInfoVersions returns the subject's newest limit info versions, newest first.
func (s *Store) ListInfoVersions(ctx context.Context, subject string, limit int) ([]InfoVersion, error) {
	rows, _ := s.pool.Query(ctx, `select name, version_id, sha256, uploaded_at from offsite_info_version where subject = $1
		order by uploaded_at desc, name, version_id limit $2`, subject, limit)
	vs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (InfoVersion, error) {
		var v InfoVersion
		return v, r.Scan(&v.Name, &v.VersionID, &v.SHA256, &v.UploadedAt)
	})
	return vs, wrap(err)
}

// Timelines returns the subject's admitted set: every timeline row, whatever
// its state, in timeline order. It is never nil (a nil list would admit
// every timeline, walname.Admitted).
func (s *Store) Timelines(ctx context.Context, subject string) ([]Timeline, error) {
	return timelines(ctx, s.pool, subject)
}

func timelines(ctx context.Context, q querier, subject string) ([]Timeline, error) {
	rows, err := q.Query(ctx, "select tli, state, coalesce(op_id, 0) from backup_timeline where subject = $1 order by tli", subject)
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()
	ts := []Timeline{}
	for rows.Next() {
		var t Timeline
		if err := rows.Scan(&t.TLI, &t.State, &t.OpID); err != nil {
			return nil, wrap(err)
		}
		ts = append(ts, t)
	}
	return ts, wrap(rows.Err())
}

// BeginRecoveryAttempt chooses, before a restore's recovery starts, the
// timeline that recovery will create, in one transaction. held lists the
// timelines above 1 whose history the repository holds. The steps:
//  1. a pending timeline whose history is held becomes abandoned (an earlier
//     attempt promoted it);
//  2. N = 1 + the highest admitted timeline whose history is held (timeline 1
//     counts as held);
//  3. without a row for N, N is inserted pending for opID;
//  4. a row for N whose history is neither held nor in the record becomes
//     opID's pending timeline (a reused number or a re-take);
//  5. a row for N whose history is in the record but not held:
//     ErrTimelineConflict, and nothing is written.
func (s *Store) BeginRecoveryAttempt(ctx context.Context, ref, stanza string, opID int64, held []int) (pending int, err error) {
	if ref == "cp" {
		return 0, fmt.Errorf("store: the control plane has no timelines")
	}
	isHeld := map[int]bool{1: true}
	for _, t := range held {
		isHeld[t] = true
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := stateOf(ctx, tx, ref); err != nil {
			return err
		}
		ts, err := timelines(ctx, tx, ref)
		if err != nil {
			return err
		}
		n, row := 2, map[int]string{}
		for _, t := range ts {
			if isHeld[t.TLI] {
				if t.State == "pending" {
					if _, err := tx.Exec(ctx, "update backup_timeline set state = 'abandoned' where subject = $1 and tli = $2", ref, t.TLI); err != nil {
						return err
					}
					t.State = "abandoned"
				}
				n = max(n, t.TLI+1)
			}
			row[t.TLI] = t.State
		}
		pending = n
		if _, ok := row[n]; !ok {
			_, err := tx.Exec(ctx, `insert into backup_timeline (subject, tli, state, op_id, launch) values ($1, $2, 'pending', $3, 0)`, ref, n, opID)
			return err
		}
		off, err := hasArchive(ctx, tx, ref, stanza, fmt.Sprintf("%08X.history", n))
		if err != nil {
			return err
		}
		if off {
			return ErrTimelineConflict
		}
		_, err = tx.Exec(ctx, "update backup_timeline set state = 'pending', op_id = $3 where subject = $1 and tli = $2", ref, n, opID)
		return err
	})
	return pending, err
}

// ConfirmTimeline makes opID's pending timeline tli recorded and sets the
// operation's t8_done, in one transaction; anything else is ErrConflict.
// The recorded timeline draws a launch number: what a restore made is
// ordered among the jobs.
func (s *Store) ConfirmTimeline(ctx context.Context, ref string, opID int64, tli int) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `update backup_timeline set state = 'recorded', launch = nextval('backup_job_launch')
			where subject = $1 and tli = $2 and state = 'pending' and op_id = $3`, ref, tli, opID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: timeline %d of %s is not the pending timeline of operation %d", ErrConflict, tli, ref, opID)
		}
		tag, err = tx.Exec(ctx, `update operation set params = jsonb_set(params, '{t8_done}', 'true'), updated_at = now()
			where id = $1 and ref = $2`, opID, ref)
		if err == nil && tag.RowsAffected() != 1 {
			err = fmt.Errorf("%w: operation %d of %s not found", ErrConflict, opID, ref)
		}
		return err
	})
}

func (s *Store) SetSeeded(ctx context.Context, subject string, at time.Time) error {
	return s.updateOne(ctx, "update backup_state set seeded_at = $2 where subject = $1", subject, at)
}

func (s *Store) SetOffsitePurge(ctx context.Context, subject string) error {
	return s.updateOne(ctx, "update backup_state set offsite_purge = true where subject = $1", subject)
}

// LagCounts counts the subjects whose last complete push, and last complete
// replication, is older than push and repl. A subject is counted while its
// backups are expected to run — the control plane, and every project that is
// active or restarting — and only once it has such a time.
func (s *Store) LagCounts(ctx context.Context, push, repl time.Duration) (overPush, overRepl int, err error) {
	err = s.pool.QueryRow(ctx, `select count(*) filter (where b.last_push_ok < now() - make_interval(secs => $1)),
			count(*) filter (where b.last_repl_ok < now() - make_interval(secs => $2))
		from backup_state b left join project p on p.ref = b.subject
		where b.subject = 'cp' or p.state in ('active', 'restarting')`, push.Seconds(), repl.Seconds()).Scan(&overPush, &overRepl)
	return overPush, overRepl, wrap(err)
}

// RepoQuotaTotals sums, and takes the largest of, the repository quotas (the
// disk quota) of the projects that are neither purged nor aborted.
func (s *Store) RepoQuotaTotals(ctx context.Context) (sumMB int64, maxMB int, err error) {
	err = s.pool.QueryRow(ctx, `select coalesce(sum((config->>'disk_quota_mb')::bigint), 0), coalesce(max((config->>'disk_quota_mb')::integer), 0)
		from project where state not in ('purged', 'aborted')`).Scan(&sumMB, &maxMB)
	return sumMB, maxMB, wrap(err)
}

// ContinueRebuild lets a record's rebuild that stopped at its page cap go on
// for another maxPages pages: one statement sets the subject's page count to
// 0 where its record is not rebuilt for the current epoch and the count is at
// least maxPages, and returns the count it replaced. The markers and every
// other column stay, so the rebuild continues where it stopped. No such row
// is ErrConflict (the subject is not at the cap, or its record is rebuilt),
// an unknown subject ErrNotFound.
func (s *Store) ContinueRebuild(ctx context.Context, subject string, maxPages int) (pages int, err error) {
	if maxPages < 1 {
		return 0, fmt.Errorf("%w: a page cap of %d", ErrConflict, maxPages)
	}
	var known bool
	// The old count is read by the same statement that replaces it.
	err = s.pool.QueryRow(ctx, `with old as (select subject, rebuild_pages from backup_state where subject = $1 for update),
		reset as (update backup_state b set rebuild_pages = 0 from old where b.subject = old.subject
			and b.rebuild_epoch < (select epoch from cp_meta) and old.rebuild_pages >= $2 returning old.rebuild_pages)
		select exists (select 1 from old), coalesce((select rebuild_pages from reset), -1)`, subject, maxPages).Scan(&known, &pages)
	switch {
	case err != nil:
		return 0, wrap(err)
	case !known:
		return 0, ErrNotFound
	case pages < 0:
		return 0, fmt.Errorf("%w: the rebuild of %s is not stopped at its page cap", ErrConflict, subject)
	}
	return pages, nil
}

// SchemaVersion is the schema version this build migrates a database to.
func SchemaVersion() int { return schemaVersion }
