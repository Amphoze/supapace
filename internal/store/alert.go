package store

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

// Alert is a row of the alert table, or a backup notice read as one
// (FromNotice: severity warn, no figures; its detail is never read).
type Alert struct {
	Subject, Code, Severity string
	Count                   int64
	FirstAt, LastAt         time.Time
	Figures                 map[string]int64
	FromNotice              bool
}

// Bounds of what a raise may write: the codes and figures are the daemon's,
// and a subject holds a bounded number of rows.
const (
	maxAlertsPerSubject = 64
	maxFigures          = 16
	lockClassAlert      = 7303 // per subject, transaction-level, inside RaiseAlert only
)

var (
	alertSubjectRE = regexp.MustCompile(`^([a-z0-9]{20}|cp|node)$`)
	alertCodeRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	figureNameRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// RaiseAlert opens or raises (subject, code): count + 1, last_at now, the
// figures replaced. A new or re-opened row takes severity, and is pending;
// an open row keeps the higher of the two, and a raise that lifts it from
// warn to page makes it pending at once.
func (s *Store) RaiseAlert(ctx context.Context, subject, code, severity string, figures map[string]int64) error {
	if !alertSubjectRE.MatchString(subject) || !alertCodeRE.MatchString(code) || (severity != "warn" && severity != "page") ||
		len(figures) > maxFigures {
		return fmt.Errorf("%w: alert %.64q of %.64q, severity %.16q, %d figures refused", ErrConflict, code, subject, severity, len(figures))
	}
	for k := range figures {
		if !figureNameRE.MatchString(k) {
			return fmt.Errorf("%w: figure %.64q refused", ErrConflict, k)
		}
	}
	if figures == nil {
		figures = map[string]int64{}
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		// Serialise the raises of one subject, so that its bound holds.
		if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock($1, hashtext($2))", lockClassAlert, subject); err != nil {
			return err
		}
		var rows int
		var exists bool
		if err := tx.QueryRow(ctx, "select count(*), bool_or(code = $2) is true from alert where subject = $1", subject, code).
			Scan(&rows, &exists); err != nil {
			return err
		}
		if !exists && rows >= maxAlertsPerSubject {
			return fmt.Errorf("%w: %s holds %d alerts", ErrConflict, subject, rows)
		}
		_, err := tx.Exec(ctx, `insert into alert as a (subject, code, severity, figures) values ($1, $2, $3, $4)
			on conflict (subject, code) do update set count = a.count + 1, last_at = now(), figures = excluded.figures, open = true,
				severity = case when a.open and a.severity = 'page' then 'page' else excluded.severity end,
				sent_at = case when not a.open or (a.severity = 'warn' and excluded.severity = 'page') then null else a.sent_at end`,
			subject, code, severity, figures)
		return err
	})
}

// ClearAlert closes (subject, code); a later raise opens it again.
func (s *Store) ClearAlert(ctx context.Context, subject, code string) error {
	_, err := s.pool.Exec(ctx, "update alert set open = false where subject = $1 and code = $2", subject, code)
	return wrap(err)
}

// pendingQ: the alert rows — a cleared one too: what was raised is
// delivered — and the backup notices whose count moved since their last
// delivery and whose last delivery is older than $1 microseconds, the
// earliest raised first.
const pendingQ = `select subject, code, severity, count, first_at, last_at, figures, false from alert
		where count > sent_count and (sent_at is null or sent_at <= now() - $1 * interval '1 microsecond')
	union all
	select subject, code, 'warn', count, first_at, last_at, '{}'::jsonb, true from backup_notice
		where count > sent_count and (sent_at is null or sent_at <= now() - $1 * interval '1 microsecond')
	order by 6, 1, 2 limit $2`

func collectAlerts(rows pgx.Rows, err error) ([]Alert, error) {
	if err != nil {
		return nil, wrap(err)
	}
	l, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Alert, error) {
		var a Alert
		err := r.Scan(&a.Subject, &a.Code, &a.Severity, &a.Count, &a.FirstAt, &a.LastAt, &a.Figures, &a.FromNotice)
		return a, err
	})
	return l, wrap(err)
}

// PendingAlerts returns at most limit rows a sender owes a delivery:
// alerts and backup notices whose count is above the count last sent, last
// sent longer than repeat ago or never.
func (s *Store) PendingAlerts(ctx context.Context, repeat time.Duration, limit int) ([]Alert, error) {
	return collectAlerts(s.pool.Query(ctx, pendingQ, repeat.Microseconds(), limit))
}

// MarkAlertSent records that a, as read, was delivered.
func (s *Store) MarkAlertSent(ctx context.Context, a Alert) error {
	q := "update alert set sent_count = greatest(sent_count, $3), sent_at = now() where subject = $1 and code = $2"
	if a.FromNotice {
		q = "update backup_notice set sent_count = greatest(sent_count, $3), sent_at = now() where subject = $1 and code = $2"
	}
	_, err := s.pool.Exec(ctx, q, a.Subject, a.Code, a.Count)
	return wrap(err)
}

// OpenAlerts returns the open alert rows of subject ("" every subject).
func (s *Store) OpenAlerts(ctx context.Context, subject string) ([]Alert, error) {
	return collectAlerts(s.pool.Query(ctx, `select subject, code, severity, count, first_at, last_at, figures, false from alert
		where open and ($1 = '' or subject = $1) order by subject, code`, subject))
}
