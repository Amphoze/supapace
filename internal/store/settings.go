package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/poolcfg"
)

// ProjectSettings is a project's document of settings that touch no cluster
// (project.settings). It has no generation: the operation settings replaces
// it whole, merged onto the document it was read as.
type ProjectSettings struct {
	API     *APISettings    `json:"api,omitempty"`
	Pooler  *PoolerSettings `json:"pooler,omitempty"`
	Rate    *RateSettings   `json:"rate,omitempty"`
	Aud     []string        `json:"aud,omitempty"`
	Stopped bool            `json:"stopped,omitempty"`
}

// APISettings: nil or zero members leave the REST service as built.
type APISettings struct {
	Schemas         []string `json:"schemas,omitempty"`
	ExtraSearchPath []string `json:"extra_search_path,omitempty"`
	MaxRows         int      `json:"max_rows,omitempty"`
}

// PoolerSettings: zero is the pooler's default; an empty list is open.
type PoolerSettings struct {
	PoolSize   int      `json:"pool_size,omitempty"`
	MaxClients int      `json:"max_clients,omitempty"`
	AllowList  []string `json:"allow_list,omitempty"`
}

type RateSettings struct {
	RPS   int `json:"rps"`
	Burst int `json:"burst"`
}

type PendingRekey struct {
	Ref, Login string
	Since      time.Time
}

type RestorePoint struct {
	Ref, Name, LSN string
	TLI            int
	CreatedAt      time.Time
}

var (
	schemaNameRE  = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	loginRE       = schemaNameRE
	pointNameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	lsnRE         = regexp.MustCompile(`^[0-9A-F]{1,8}/[0-9A-F]{1,8}$`)
	reservedNames = map[string]bool{"information_schema": true, "supapace": true, poolcfg.ManagerRole: true}
)

// Bounds of the settings; the route's members are the gateway's.
const (
	maxSchemas      = 16
	maxRows         = 1_000_000
	maxClients      = 1000
	maxRPS          = 100_000
	maxAud          = 8
	maxAudLen       = 255
	maxPendingLogin = 16 // logins queued for a re-key, a project
	maxTextLen      = 255
	readOnlyLogin   = "supabase_read_only_user"
)

func schemaList(what string, l []string) error {
	if len(l) == 0 {
		return nil
	}
	if len(l) > maxSchemas {
		return fmt.Errorf("%w: %d %s, at most %d", ErrConflict, len(l), what, maxSchemas)
	}
	for _, n := range l {
		if !schemaNameRE.MatchString(n) || strings.HasPrefix(n, "pg_") || reservedNames[n] {
			return fmt.Errorf("%w: %s %.64q is not an allowed schema name", ErrConflict, what, n)
		}
	}
	return nil
}

// Validate holds the document to its bounds, given the node file, the node's
// addresses and the project's max_connections. While restrictions are not
// offered an allow list is refused before the addresses are looked at; a
// document without a list never looks at them.
func (p ProjectSettings) Validate(c nodecfg.Config, own []netip.Addr, maxConnections int) error {
	if a := p.API; a != nil {
		if err := schemaList("schemas", a.Schemas); err != nil {
			return err
		}
		if err := schemaList("extra search path", a.ExtraSearchPath); err != nil {
			return err
		}
		if a.MaxRows < 0 || a.MaxRows > maxRows {
			return fmt.Errorf("%w: max_rows %d, want 1 to %d", ErrConflict, a.MaxRows, maxRows)
		}
	}
	if q := p.Pooler; q != nil {
		// The effective size: zero runs at the default, which must fit too.
		size := q.PoolSize
		if size == 0 {
			size = poolcfg.DefaultPoolSize
		}
		if err := poolcfg.Fits(maxConnections, size); err != nil {
			return fmt.Errorf("%w: %v", ErrConflict, err)
		}
		if q.MaxClients < 0 || q.MaxClients > maxClients {
			return fmt.Errorf("%w: max_clients %d, want 1 to %d", ErrConflict, q.MaxClients, maxClients)
		}
		if len(q.AllowList) > 0 {
			if !poolcfg.RestrictionsOffered {
				return fmt.Errorf("%w: network restrictions are not offered", ErrConflict)
			}
			if _, err := poolcfg.ValidAllowListOn(c, own, q.AllowList); err != nil {
				return fmt.Errorf("%w: %v", ErrConflict, err)
			}
		}
	}
	if r := p.Rate; r != nil && (r.RPS < 1 || r.RPS > maxRPS || r.Burst < r.RPS || r.Burst > 10*r.RPS) {
		return fmt.Errorf("%w: rate %d a second with a burst of %d; want 1 to %d, and a burst of the rate to ten times it",
			ErrConflict, r.RPS, r.Burst, maxRPS)
	}
	if len(p.Aud) > maxAud {
		return fmt.Errorf("%w: %d audiences, at most %d", ErrConflict, len(p.Aud), maxAud)
	}
	for _, a := range p.Aud {
		if !printable(a, maxAudLen) {
			return fmt.Errorf("%w: an audience must be 1 to %d printable bytes", ErrConflict, maxAudLen)
		}
	}
	return nil
}

// printable: 1 to n bytes of printable ASCII.
func printable(s string, n int) bool {
	return len(s) >= 1 && len(s) <= n && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r > 0x7e })
}

func (s *Store) GetSettings(ctx context.Context, ref string) (ProjectSettings, error) {
	var p ProjectSettings
	err := s.pool.QueryRow(ctx, "select settings from project where ref = $1", ref).Scan(&p)
	return p, wrap(err)
}

// SubmitSettings queues the operation settings for an active project with no
// open operation whose stored document equals base; target is the whole new
// document. The caller has validated target.
func (s *Store) SubmitSettings(ctx context.Context, ref string, base, target ProjectSettings) (opID int64, err error) {
	params, err := json.Marshal(struct {
		Base   ProjectSettings `json:"base"`
		Target ProjectSettings `json:"target"`
	}{base, target})
	if err != nil {
		return 0, err
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		var state string
		var same bool
		var gen int64
		if err := tx.QueryRow(ctx, "select state, generation, settings = $2::jsonb from project where ref = $1 for update", ref, base).
			Scan(&state, &gen, &same); err != nil {
			return err
		}
		if err := openOperation(ctx, tx, ref, 0); err != nil {
			return err
		}
		if state != "active" {
			return fmt.Errorf("%w: settings need an active project; it is %s", ErrConflict, state)
		}
		if !same {
			return fmt.Errorf("%w: settings changed meanwhile; read them again", ErrConflict)
		}
		return tx.QueryRow(ctx, `insert into operation (ref, kind, state, params, epoch, generation)
			values ($1, 'settings', 'pending', $2, (select epoch from cp_meta), $3) returning id`, ref, params, gen).Scan(&opID)
	})
	return opID, err
}

// StoreSettings writes target as the project's document, for the open
// settings operation opID.
func (s *Store) StoreSettings(ctx context.Context, opID int64, target ProjectSettings) error {
	tag, err := s.pool.Exec(ctx, `update project set settings = $2 where ref = (select ref from operation
		where id = $1 and kind = 'settings' and state in `+openStates+`)`, opID, target)
	if err == nil && tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: operation %d is no open settings operation", ErrConflict, opID)
	}
	return wrap(err)
}

// SubmitRekey queues the operation rekey-login for login when the project is
// active with no open operation; otherwise it records the login as pending,
// once, and returns queued. Both under the project's row lock.
func (s *Store) SubmitRekey(ctx context.Context, ref, login string) (opID int64, queued bool, err error) {
	if !loginRE.MatchString(login) {
		return 0, false, fmt.Errorf("%w: login %.64q", ErrConflict, login)
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		var state string
		var gen int64
		var pending int
		var has bool
		if err := tx.QueryRow(ctx, `select state, generation, jsonb_array_length(rekey_pending),
				exists (select 1 from jsonb_array_elements(rekey_pending) e where e->>'login' = $2)
			from project where ref = $1 for update`, ref, login).Scan(&state, &gen, &pending, &has); err != nil {
			return err
		}
		open := openOperation(ctx, tx, ref, 0)
		if open != nil && !errors.Is(open, ErrConflict) {
			return open
		}
		if state == "active" && open == nil {
			return tx.QueryRow(ctx, `insert into operation (ref, kind, state, params, epoch, generation)
				values ($1, 'rekey-login', 'pending', jsonb_build_object('login', $2::text), (select epoch from cp_meta), $3)
				returning id`, ref, login, gen).Scan(&opID)
		}
		queued = true
		if has {
			return nil
		}
		if pending >= maxPendingLogin {
			return fmt.Errorf("%w: %d logins already wait for a re-key", ErrConflict, pending)
		}
		_, err := tx.Exec(ctx, `update project set rekey_pending = rekey_pending || jsonb_build_array(jsonb_build_object('login', $2::text, 'since', now()))
			where ref = $1`, ref, login)
		return err
	})
	return opID, queued, err
}

func collectRekeys(rows pgx.Rows, err error) ([]PendingRekey, error) {
	if err != nil {
		return nil, wrap(err)
	}
	l, err := pgx.CollectRows(rows, pgx.RowToStructByPos[PendingRekey])
	return l, wrap(err)
}

// PendingRekeys lists every login waiting for a re-key, by project and time.
func (s *Store) PendingRekeys(ctx context.Context) ([]PendingRekey, error) {
	return collectRekeys(s.pool.Query(ctx, `select p.ref, e->>'login', (e->>'since')::timestamptz
		from project p, jsonb_array_elements(p.rekey_pending) with ordinality as x(e, n) order by p.ref, x.n`))
}

// FailedRekeys lists each project and login whose newest rekey-login
// operation ended failed, with the time it failed.
func (s *Store) FailedRekeys(ctx context.Context) ([]PendingRekey, error) {
	return collectRekeys(s.pool.Query(ctx, `select ref, login, updated_at from (
			select distinct on (ref, params->>'login') ref, params->>'login' as login, state, updated_at
			from operation where kind = 'rekey-login' order by ref, params->>'login', id desc) n
		where state = 'failed' order by ref, login`))
}

// PromoteNextSecret replaces the secret name with name + ".next", removes the
// latter and takes login out of the pending re-keys, in one transaction; for
// the read-only login the same transaction owes its clean-up again. Without a
// ".next" it writes nothing.
func (s *Store) PromoteNextSecret(ctx context.Context, ref, name, login string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := lockProject(ctx, tx, ref); err != nil {
			return err
		}
		var nonce, ct []byte
		err := tx.QueryRow(ctx, "delete from secret where ref = $1 and name = $2 returning nonce, ciphertext", ref, name+".next").Scan(&nonce, &ct)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `insert into secret (ref, name, nonce, ciphertext) values ($1, $2, $3, $4)
			on conflict (ref, name) do update set nonce = excluded.nonce, ciphertext = excluded.ciphertext, created_at = now()`,
			ref, name, nonce, ct); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `update project set rekey_pending = coalesce((select jsonb_agg(e order by n)
			from jsonb_array_elements(rekey_pending) with ordinality as x(e, n) where e->>'login' <> $2), '[]') where ref = $1`, ref, login); err != nil {
			return err
		}
		if login == readOnlyLogin {
			return oweReadOnlyCleanupTx(ctx, tx, ref)
		}
		return nil
	})
}

// SetReadOnlySince records when the quota signal set the project read-only;
// nil clears it.
func (s *Store) SetReadOnlySince(ctx context.Context, ref string, at *time.Time) error {
	return s.update(ctx, "update project set read_only_since = $2 where ref = $1", ref, at)
}

// RecordIssuance records that askedBy was given login's password.
func (s *Store) RecordIssuance(ctx context.Context, ref, login, role, askedBy string) error {
	if !printable(login, maxTextLen) || !printable(role, maxTextLen) || !printable(askedBy, maxTextLen) {
		return fmt.Errorf("%w: an issuance names 1 to %d printable bytes each", ErrConflict, maxTextLen)
	}
	_, err := s.pool.Exec(ctx, "insert into issuance (ref, login, role, asked_by) values ($1, $2, $3, $4)", ref, login, role, askedBy)
	return wrap(err)
}

// AddRestorePoint records a restore point at lsn on timeline tli, which must
// be the project's newest recorded timeline. An existing name is ErrConflict.
func (s *Store) AddRestorePoint(ctx context.Context, ref, name, lsn string, tli int) error {
	if !pointNameRE.MatchString(name) || !lsnRE.MatchString(lsn) {
		return fmt.Errorf("%w: restore point %.64q at %.32q refused", ErrConflict, name, lsn)
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := stateOf(ctx, tx, ref); err != nil {
			return err
		}
		var newest *int
		if err := tx.QueryRow(ctx, "select max(tli) from backup_timeline where subject = $1 and state = 'recorded'", ref).Scan(&newest); err != nil {
			return err
		}
		if newest == nil || *newest != tli {
			return fmt.Errorf("%w: timeline %d is not the project's newest recorded timeline", ErrConflict, tli)
		}
		tag, err := tx.Exec(ctx, `insert into restore_point (ref, name, lsn, tli) values ($1, $2, $3::pg_lsn, $4)
			on conflict (ref, name) do nothing`, ref, name, lsn, tli)
		if err == nil && tag.RowsAffected() == 0 {
			err = fmt.Errorf("%w: restore point %s exists", ErrConflict, name)
		}
		return err
	})
}

const pointCols = "ref, name, lsn::text, tli, created_at"

func (s *Store) GetRestorePoint(ctx context.Context, ref, name string) (RestorePoint, error) {
	rows, _ := s.pool.Query(ctx, "select "+pointCols+" from restore_point where ref = $1 and name = $2", ref, name)
	p, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[RestorePoint])
	return p, wrap(err)
}

// ListRestorePoints returns the project's newest 64 restore points, newest first.
func (s *Store) ListRestorePoints(ctx context.Context, ref string) ([]RestorePoint, error) {
	rows, _ := s.pool.Query(ctx, "select "+pointCols+" from restore_point where ref = $1 order by created_at desc, name desc limit 64", ref)
	l, err := pgx.CollectRows(rows, pgx.RowToStructByPos[RestorePoint])
	return l, wrap(err)
}
