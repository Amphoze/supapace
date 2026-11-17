package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// PutDEK stores the project's wrapped DEK; a row already present (live or
// destroyed) is kept.
func (s *Store) PutDEK(ctx context.Context, ref, kekID string, nonce, wrapped []byte) error {
	_, err := s.pool.Exec(ctx, `insert into project_dek (ref, kek_id, nonce, wrapped) values ($1, $2, $3, $4)
		on conflict (ref) do nothing`, ref, kekID, nonce, wrapped)
	return wrap(err)
}

func (s *Store) GetDEK(ctx context.Context, ref string) (nonce, wrapped []byte, err error) {
	var destroyed bool
	err = s.pool.QueryRow(ctx, "select nonce, wrapped, destroyed_at is not null from project_dek where ref = $1", ref).
		Scan(&nonce, &wrapped, &destroyed)
	if err == nil && destroyed {
		return nil, nil, ErrDestroyed
	}
	return nonce, wrapped, wrap(err)
}

// DestroyKeys nulls the DEK and deletes the project's secrets and keys, in one
// transaction. Repeating it changes nothing.
func (s *Store) DestroyKeys(ctx context.Context, ref string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		for _, q := range []string{
			"update project_dek set wrapped = null, nonce = null, destroyed_at = now() where ref = $1 and wrapped is not null",
			"delete from secret where ref = $1",
			"delete from project_key where ref = $1",
		} {
			if _, err := tx.Exec(ctx, q, ref); err != nil {
				return err
			}
		}
		return nil
	})
}

// PutSecret stores a sealed secret once; an existing (ref, name) is kept.
func (s *Store) PutSecret(ctx context.Context, ref, name string, nonce, ct []byte) error {
	_, err := s.pool.Exec(ctx, `insert into secret (ref, name, nonce, ciphertext) values ($1, $2, $3, $4)
		on conflict (ref, name) do nothing`, ref, name, nonce, ct)
	return wrap(err)
}

func (s *Store) GetSecret(ctx context.Context, ref, name string) (nonce, ct []byte, err error) {
	err = s.pool.QueryRow(ctx, "select nonce, ciphertext from secret where ref = $1 and name = $2", ref, name).Scan(&nonce, &ct)
	return nonce, ct, wrap(err)
}

// PutKey stores a public key of a project; storing the same row again is a
// no-op, a different class or JWK under the same (ref, kid) is ErrConflict.
func (s *Store) PutKey(ctx context.Context, k KeyRow) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `insert into project_key (ref, kid, class, jwk) values ($1, $2, $3, $4)
			on conflict (ref, kid) do nothing`, k.Ref, k.KID, k.Class, k.JWK)
		if err != nil || tag.RowsAffected() > 0 {
			return err
		}
		var same bool
		if err := tx.QueryRow(ctx, "select class = $3 and jwk = $4::jsonb from project_key where ref = $1 and kid = $2",
			k.Ref, k.KID, k.Class, string(k.JWK)).Scan(&same); err != nil {
			return err
		}
		if !same {
			return fmt.Errorf("%w: kid %q is stored with another key", ErrConflict, k.KID)
		}
		return nil
	})
}

func (s *Store) ListKeys(ctx context.Context, ref string) ([]KeyRow, error) {
	rows, err := s.pool.Query(ctx, "select ref, kid, class, jwk from project_key where ref = $1 order by created_at, kid", ref)
	if err != nil {
		return nil, err
	}
	ks, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (KeyRow, error) {
		var k KeyRow
		var jwk []byte
		err := r.Scan(&k.Ref, &k.KID, &k.Class, &jwk)
		k.JWK = jwk
		return k, err
	})
	return ks, wrap(err)
}
