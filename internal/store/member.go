package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/dashfile"
	"github.com/Amphoze/supapace/internal/jwtx"
)

// The dashboard's authorization table: members of projects, the sign-in
// issuer and the revocations of principals. Every row the store accepts fits
// the dashboard file: a value or a count the file refuses is refused here
// with ErrConflict, so a row can never make the file fail to render.

type Member struct {
	Ref, Issuer, Subject, Role string
	AddedAt                    time.Time
}

type DashboardIssuer struct {
	Issuer, ClientID, AuthorizeURL, EndSessionURL string
	SessionSeconds                                int
	JWKS                                          json.RawMessage
	UpdatedAt                                     time.Time
}

// DashboardTable is one snapshot of everything the dashboard file carries.
type DashboardTable struct {
	Issuer   *DashboardIssuer // nil while unset
	Revoked  []Revocation
	Projects []TableProject
}

type Revocation struct {
	Issuer, Subject string
	NotBefore       time.Time
}

type TableProject struct {
	Ref, Name string
	Members   []Member
}

// ReadOnlyCleanup is the record of a clean-up owed after a read_only
// membership ended: its last run must start at or after Due.
type ReadOnlyCleanup struct {
	Ref      string
	Due      time.Time
	DueFixed bool
	NextTry  time.Time
	Failures int
}

// MaxSessionSeconds is the longest a dashboard session can live: the upper
// bound of an issuer's session_seconds, here and in the dashboard file.
const MaxSessionSeconds = 28800

const minSessionSeconds = 300

// liveStates are the project states the dashboard file carries.
const liveStates = `('active', 'restarting', 'restoring')`

// The clean-up delay and the slice hold are set once at the daemon's start,
// before the first request. They are the process's settings, not one Store
// value's: the daemon opens one store, and the clean-up record is written
// from inside a transaction that has no Store.
var cleanupDelay, sliceHold atomic.Int64 // nanoseconds

// SetCleanupDelay sets how long after a membership change the last clean-up
// run of a read_only membership is owed; zero until set. The setting is the
// process's, not this Store value's: set it once, before the saga runner, the
// clean-up converger and the admin API start.
func (s *Store) SetCleanupDelay(d time.Duration) { cleanupDelay.Store(int64(d)) }

func conflictf(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrConflict}, a...)...)
}

// principalOK: 1 to 255 bytes of printable ASCII, as the dashboard file holds
// an issuer and a subject.
func principalOK(s string) bool {
	if len(s) < 1 || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func checkPrincipal(issuer, subject string) error {
	if !principalOK(issuer) || !principalOK(subject) {
		return conflictf("an issuer and a subject are 1 to 255 bytes of printable ASCII")
	}
	return nil
}

func roleOK(r string) bool { return r == "owner" || r == "developer" || r == "read_only" }

// AddMember adds a member to a project in state active, restarting or
// restoring. An existing member, a project at dashfile.MaxMembers members and
// a node at dashfile.MaxMemberRows member rows are ErrConflict.
func (s *Store) AddMember(ctx context.Context, m Member) error {
	if err := checkPrincipal(m.Issuer, m.Subject); err != nil {
		return err
	}
	if !roleOK(m.Role) {
		return conflictf("role %q is not owner, developer or read_only", m.Role)
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		var node, state string
		if err := tx.QueryRow(ctx, "select node_id, state from project where ref = $1 for update", m.Ref).Scan(&node, &state); err != nil {
			return err
		}
		if state != "active" && state != "restarting" && state != "restoring" {
			return conflictf("project is %s", state)
		}
		var n int
		var exists bool
		if err := tx.QueryRow(ctx, "select count(*), count(*) filter (where issuer = $2 and subject = $3) > 0 from member where ref = $1",
			m.Ref, m.Issuer, m.Subject).Scan(&n, &exists); err != nil {
			return err
		}
		switch {
		case exists:
			return conflictf("the principal is already a member")
		case n >= dashfile.MaxMembers:
			return conflictf("the project has the most members a dashboard file carries (%d)", dashfile.MaxMembers)
		}
		// The node's count, under the lock placement takes: adds to two projects
		// cannot both pass. Rows of a project that has left for good are not
		// counted; every other project may be in the file again.
		if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock($1, hashtext($2))", lockClassNode, node); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `select count(*) from member m join project p using (ref)
				where p.node_id = $1 and p.state not in ('deleted', 'purged', 'aborted')`, node).Scan(&n); err != nil {
			return err
		}
		if n >= dashfile.MaxMemberRows {
			return conflictf("the node has the most members a dashboard file carries (%d)", dashfile.MaxMemberRows)
		}
		_, err := tx.Exec(ctx, "insert into member (ref, issuer, subject, role) values ($1, $2, $3, $4)", m.Ref, m.Issuer, m.Subject, m.Role)
		return err
	})
}

// ChangeMember sets a member's role; an empty toRole removes the member. No
// member is ErrNotFound; a stored role other than fromRole is ErrConflict.
func (s *Store) ChangeMember(ctx context.Context, ref, issuer, subject, fromRole, toRole string) error {
	return s.tx(ctx, func(tx pgx.Tx) error { return changeMemberTx(ctx, tx, ref, issuer, subject, fromRole, toRole) })
}

// changeMemberTx is ChangeMember inside tx. A change that ends a read_only
// membership owes the read-only role's clean-up in the same transaction.
func changeMemberTx(ctx context.Context, tx pgx.Tx, ref, issuer, subject, fromRole, toRole string) error {
	if toRole != "" && !roleOK(toRole) {
		return conflictf("role %q is not owner, developer or read_only", toRole)
	}
	var role string
	if err := tx.QueryRow(ctx, "select role from member where ref = $1 and issuer = $2 and subject = $3 for update",
		ref, issuer, subject).Scan(&role); err != nil {
		return wrap(err)
	}
	if role != fromRole {
		return conflictf("the member's role is %s, not %s", role, fromRole)
	}
	var err error
	if toRole == "" {
		_, err = tx.Exec(ctx, "delete from member where ref = $1 and issuer = $2 and subject = $3", ref, issuer, subject)
	} else {
		_, err = tx.Exec(ctx, "update member set role = $4 where ref = $1 and issuer = $2 and subject = $3", ref, issuer, subject, toRole)
	}
	if err != nil || fromRole != "read_only" || toRole == "read_only" {
		return err
	}
	return oweReadOnlyCleanupTx(ctx, tx, ref)
}

// oweReadOnlyCleanupTx records, inside tx, that the project's read-only role
// is owed a clean-up whose last run starts at or after now + the delay: the
// later due is kept, and the rest starts over — not fixed, no failures, the
// next attempt now. It is the only statement that writes a record or moves
// its due.
func oweReadOnlyCleanupTx(ctx context.Context, tx pgx.Tx, ref string) error {
	_, err := tx.Exec(ctx, `insert into readonly_cleanup (ref, due) values ($1, now() + $2 * interval '1 microsecond')
		on conflict (ref) do update set due = greatest(readonly_cleanup.due, excluded.due),
			due_fixed = false, failures = 0, next_try = now()`, ref, time.Duration(cleanupDelay.Load()).Microseconds())
	return err
}

// ListMembers returns a project's members by issuer and subject; no project
// is ErrNotFound.
func (s *Store) ListMembers(ctx context.Context, ref string) ([]Member, error) {
	var ms []Member
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var one int
		if err := tx.QueryRow(ctx, "select 1 from project where ref = $1", ref).Scan(&one); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "select ref, issuer, subject, role, added_at from member where ref = $1 order by issuer, subject", ref)
		if err != nil {
			return err
		}
		ms, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Member])
		return err
	})
	return ms, err
}

// MemberRole is the principal's role in the project, whatever the project's
// state; ErrNotFound without a row.
func (s *Store) MemberRole(ctx context.Context, ref, issuer, subject string) (role string, err error) {
	err = s.pool.QueryRow(ctx, "select role from member where ref = $1 and issuer = $2 and subject = $3", ref, issuer, subject).Scan(&role)
	return role, wrap(err)
}

// Revoke refuses the principal's sessions issued before notBefore (stored to
// the microsecond, the later of two kept). Revocations older than the longest
// session are deleted first; a principal without one when dashfile's cap of
// live revocations is reached is ErrConflict.
func (s *Store) Revoke(ctx context.Context, issuer, subject string, notBefore time.Time) error {
	if err := checkPrincipal(issuer, subject); err != nil {
		return err
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		// One revoker at a time, so two cannot both take the last place.
		if _, err := tx.Exec(ctx, "lock table principal_revocation in exclusive mode"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "delete from principal_revocation where not_before <= now() - $1 * interval '1 second'", MaxSessionSeconds); err != nil {
			return err
		}
		var n int
		var has bool
		if err := tx.QueryRow(ctx, "select count(*), count(*) filter (where issuer = $1 and subject = $2) > 0 from principal_revocation",
			issuer, subject).Scan(&n, &has); err != nil {
			return err
		}
		if !has && n >= dashfile.MaxRevocations {
			return conflictf("the node has the most live revocations a dashboard file carries (%d)", dashfile.MaxRevocations)
		}
		_, err := tx.Exec(ctx, `insert into principal_revocation (issuer, subject, not_before) values ($1, $2, $3)
			on conflict (issuer, subject) do update set not_before = greatest(principal_revocation.not_before, excluded.not_before)`,
			issuer, subject, notBefore)
		return err
	})
}

// issuerKeys reads a key set's keys as the dashboard file carries them.
func issuerKeys(jwks json.RawMessage) ([]dashfile.IssuerKey, error) {
	var set struct {
		Keys []dashfile.IssuerKey `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		return nil, err
	}
	return set.Keys, nil
}

// SetDashboardIssuer stores the sign-in issuer, replacing any. A string
// longer than the dashboard file's cap for it, a session outside 300 to
// MaxSessionSeconds, more than dashfile.MaxKeys keys, or a key that is not an
// RSA key the gateway would load is ErrConflict.
func (s *Store) SetDashboardIssuer(ctx context.Context, d DashboardIssuer) error {
	var errs []error
	if !principalOK(d.Issuer) {
		errs = append(errs, errors.New("the issuer is 1 to 255 bytes of printable ASCII"))
	}
	for _, f := range []struct {
		name, v  string
		required bool
		max      int
	}{
		{"client_id", d.ClientID, true, dashfile.MaxClientIDBytes},
		{"authorize_url", d.AuthorizeURL, true, dashfile.MaxURLBytes},
		{"end_session_url", d.EndSessionURL, false, dashfile.MaxURLBytes},
	} {
		if len(f.v) > f.max || f.required && f.v == "" {
			errs = append(errs, fmt.Errorf("%s is empty or longer than %d bytes", f.name, f.max))
		}
	}
	if d.SessionSeconds < minSessionSeconds || d.SessionSeconds > MaxSessionSeconds {
		errs = append(errs, fmt.Errorf("session_seconds %d is outside %d to %d", d.SessionSeconds, minSessionSeconds, MaxSessionSeconds))
	}
	keys, err := issuerKeys(d.JWKS)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("jwks: %v", err))
	case len(keys) > dashfile.MaxKeys:
		errs = append(errs, fmt.Errorf("%d keys, more than %d", len(keys), dashfile.MaxKeys))
	}
	for _, k := range keys {
		if k.Kid == "" || len(k.Kid) > dashfile.MaxKidBytes || k.Kty != "RSA" || len(k.N) > dashfile.MaxNBytes || len(k.E) > dashfile.MaxEBytes {
			errs = append(errs, fmt.Errorf("key %.64q: an RSA key with kid, n and e within %d, %d and %d bytes is required",
				k.Kid, dashfile.MaxKidBytes, dashfile.MaxNBytes, dashfile.MaxEBytes))
		} else if _, err := jwtx.DashboardKeyFromJWK(k.Kid, k.N, k.E); err != nil {
			errs = append(errs, fmt.Errorf("key %.64q: %v", k.Kid, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: dashboard issuer: %w", ErrConflict, errors.Join(errs...))
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `insert into dashboard_issuer (issuer, client_id, authorize_url, end_session_url, session_seconds, jwks)
			values ($1, $2, $3, $4, $5, $6)
			on conflict (singleton) do update set issuer = excluded.issuer, client_id = excluded.client_id,
				authorize_url = excluded.authorize_url, end_session_url = excluded.end_session_url,
				session_seconds = excluded.session_seconds, jwks = excluded.jwks, updated_at = now()`,
			d.Issuer, d.ClientID, d.AuthorizeURL, d.EndSessionURL, d.SessionSeconds, string(d.JWKS)); err != nil {
			return err
		}
		// The database keeps one member of each name and re-orders them: the set
		// that is rendered is the stored one, so it must read as the checked one.
		var stored []byte
		if err := tx.QueryRow(ctx, "select jwks from dashboard_issuer").Scan(&stored); err != nil {
			return err
		}
		if again, err := issuerKeys(stored); err != nil || !slices.Equal(again, keys) {
			return conflictf("dashboard issuer: the key set reads differently once stored; send each member once, in one spelling")
		}
		return nil
	})
}

const issuerCols = "issuer, client_id, authorize_url, end_session_url, session_seconds, jwks, updated_at"

func scanIssuer(row pgx.Row) (d DashboardIssuer, err error) {
	var jwks []byte
	err = row.Scan(&d.Issuer, &d.ClientID, &d.AuthorizeURL, &d.EndSessionURL, &d.SessionSeconds, &jwks, &d.UpdatedAt)
	d.JWKS = jwks
	return d, err
}

// GetDashboardIssuer is the stored issuer; ErrNotFound while unset.
func (s *Store) GetDashboardIssuer(ctx context.Context) (DashboardIssuer, error) {
	d, err := scanIssuer(s.pool.QueryRow(ctx, "select "+issuerCols+" from dashboard_issuer"))
	return d, wrap(err)
}

// DashboardTable reads, in one repeatable-read snapshot, the issuer, the
// revocations younger than MaxSessionSeconds by the database's clock, and
// every project in state active, restarting or restoring with its members,
// in ref order.
func (s *Store) DashboardTable(ctx context.Context) (DashboardTable, error) {
	var t DashboardTable
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		d, err := scanIssuer(tx.QueryRow(ctx, "select "+issuerCols+" from dashboard_issuer"))
		switch {
		case err == nil:
			t.Issuer = &d
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		rows, err := tx.Query(ctx, `select issuer, subject, not_before from principal_revocation
			where not_before > now() - $1 * interval '1 second' order by issuer, subject`, MaxSessionSeconds)
		if err != nil {
			return err
		}
		if t.Revoked, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Revocation]); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `select p.ref, p.name, m.issuer, m.subject, m.role, m.added_at
			from project p left join member m using (ref) where p.state in `+liveStates+`
			order by p.ref, m.issuer, m.subject`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ref, name string
			var iss, sub, role *string
			var added *time.Time
			if err := rows.Scan(&ref, &name, &iss, &sub, &role, &added); err != nil {
				return err
			}
			if n := len(t.Projects); n == 0 || t.Projects[n-1].Ref != ref {
				t.Projects = append(t.Projects, TableProject{Ref: ref, Name: name})
			}
			if iss != nil {
				p := &t.Projects[len(t.Projects)-1]
				p.Members = append(p.Members, Member{Ref: ref, Issuer: *iss, Subject: *sub, Role: *role, AddedAt: *added})
			}
		}
		return rows.Err()
	})
	return t, wrap(err)
}

// ReadOnlyCleanups returns the records of projects in state active whose next
// attempt is due, earliest first, at most limit, and the database's now().
func (s *Store) ReadOnlyCleanups(ctx context.Context, limit int) (rows []ReadOnlyCleanup, now time.Time, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "select now()").Scan(&now); err != nil {
			return err
		}
		r, err := tx.Query(ctx, `select c.ref, c.due, c.due_fixed, c.next_try, c.failures from readonly_cleanup c
			join project p using (ref) where p.state = 'active' and c.next_try <= now() order by c.next_try, c.ref limit $1`, limit)
		if err != nil {
			return err
		}
		rows, err = pgx.CollectRows(r, pgx.RowToStructByPos[ReadOnlyCleanup])
		return err
	})
	return rows, now, err
}

// FixReadOnlyCleanupDue fixes a record's due, once: the later of due and
// generation (milliseconds since the epoch) plus the delay. seenDue is the due
// the caller read with the record: a record a later change has moved since is
// not the one the generation carried, and is left for the next round. A fixed
// record, or none, is left as it is.
func (s *Store) FixReadOnlyCleanupDue(ctx context.Context, ref string, generation int64, seenDue time.Time) error {
	_, err := s.pool.Exec(ctx, `update readonly_cleanup set due_fixed = true,
			due = greatest(due, timestamptz 'epoch' + $2 * interval '1 millisecond' + $3 * interval '1 microsecond')
		where ref = $1 and not due_fixed and due = $4`, ref, generation, time.Duration(cleanupDelay.Load()).Microseconds(), seenDue)
	return wrap(err)
}

// FailReadOnlyCleanup counts a failed run and sets the next attempt to now +
// retry, doubled once per earlier failure, at most an hour.
func (s *Store) FailReadOnlyCleanup(ctx context.Context, ref string, retry time.Duration) error {
	_, err := s.pool.Exec(ctx, `update readonly_cleanup set failures = failures + 1,
			next_try = now() + least(interval '1 hour', $2 * interval '1 microsecond' * power(2, least(failures, 32)))
		where ref = $1`, ref, retry.Microseconds())
	return wrap(err)
}

// DoneReadOnlyCleanup records a successful run that started at startedAt: it
// deletes a fixed record whose due is not later than startedAt; a fixed
// record due later is kept with no failures and its next attempt at its due.
// A record a later change has unfixed keeps the next attempt that change
// wrote: its first run is owed at once.
func (s *Store) DoneReadOnlyCleanup(ctx context.Context, ref string, startedAt time.Time) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "delete from readonly_cleanup where ref = $1 and due_fixed and due <= $2", ref, startedAt)
		if err != nil || tag.RowsAffected() > 0 {
			return err
		}
		_, err = tx.Exec(ctx, `update readonly_cleanup set failures = 0, next_try = case when due_fixed then due else next_try end where ref = $1`, ref)
		return err
	})
}
