package secrets

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"coffer/internal/crypto"
)

// SecretRow is one row of an environment listing. It never carries a value.
type SecretRow struct {
	ID        string
	Key       string
	Version   int64
	UpdatedAt time.Time
	UpdatedBy string
}

// VersionRow is one entry of a key's history.
type VersionRow struct {
	Version   int64
	Deleted   bool
	CreatedAt time.Time
	CreatedBy string
}

// Value is a decrypted secret value together with its version.
type Value struct {
	Key     string
	Version int64
	Value   []byte
}

// List returns the environment's live secrets with metadata only: one query, no per-row
// decryption and no N+1.
//
// The join on current_version means the version reported is exactly the version a get would
// return, and a key whose current version is a tombstone is excluded, because for a reader such a
// key does not exist.
func (s *Store) List(ctx context.Context, sc Scope) ([]SecretRow, error) {
	const q = `
SELECT s.id, s.key, s.current_version, s.updated_at, COALESCE(s.updated_by, '')
  FROM secrets s
  JOIN secret_versions sv
    ON sv.secret_id = s.id AND sv.version = s.current_version AND sv.deleted = false
 WHERE s.env_id = $1
 ORDER BY s.key`
	rows, err := s.Pool().Query(ctx, q, sc.EnvID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]SecretRow, 0, 64)
	for rows.Next() {
		var r SecretRow
		if err := rows.Scan(&r.ID, &r.Key, &r.Version, &r.UpdatedAt, &r.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// CurrentVersion returns the allocator value for a key, its secret id, and whether it exists.
//
// This is what a proposal records as base_version: the version the proposer saw.
func (s *Store) CurrentVersion(ctx context.Context, sc Scope, key string) (version int64, secretID string, found bool, err error) {
	const q = `SELECT id, current_version FROM secrets WHERE env_id = $1 AND key = $2`
	err = s.Pool().QueryRow(ctx, q, sc.EnvID, key).Scan(&secretID, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, err
	}
	return version, secretID, true, nil
}

// Value returns the current value of a key.
//
// A tombstoned current version and a missing key are both ErrNotFound: a caller must not be able
// to tell a deleted key from one that never existed.
func (s *Store) Value(ctx context.Context, sc Scope, key string) (Value, error) {
	const q = `
SELECT s.current_version, sv.nonce, sv.ciphertext
  FROM secrets s
  JOIN secret_versions sv
    ON sv.secret_id = s.id AND sv.version = s.current_version AND sv.deleted = false
 WHERE s.env_id = $1 AND s.key = $2`
	return s.decryptRow(ctx, s.Pool(), q, key, sc, sc.EnvID, key)
}

// ValueAt returns a historical value. A tombstone version has no value and is ErrNotFound.
func (s *Store) ValueAt(ctx context.Context, sc Scope, key string, version int64) (Value, error) {
	const q = `
SELECT sv.version, sv.nonce, sv.ciphertext
  FROM secrets s
  JOIN secret_versions sv ON sv.secret_id = s.id
 WHERE s.env_id = $1 AND s.key = $2 AND sv.version = $3 AND sv.deleted = false`
	return s.decryptRow(ctx, s.Pool(), q, key, sc, sc.EnvID, key, version)
}

// querier is the read surface shared by the pool and a transaction.
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// decryptRow runs a value query and decrypts the row under the value's own associated data.
//
// The AAD is rebuilt from the scope and the row's stored version, never from anything the caller
// supplied. A ciphertext moved into another row therefore fails the GCM tag check here and returns
// an error with no plaintext, never a value.
func (s *Store) decryptRow(ctx context.Context, q querier, sql, key string, sc Scope, args ...any) (Value, error) {
	var version int64
	var nonce, ciphertext []byte
	err := q.QueryRow(ctx, sql, args...).Scan(&version, &nonce, &ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return Value{}, ErrNotFound
	}
	if err != nil {
		return Value{}, err
	}

	dk, err := s.sealer.Load(ctx, s.Pool(), sc.OrgID, sc.ProjectID)
	if err != nil {
		return Value{}, err
	}
	plaintext, err := dk.Open(sc.OrgID, sc.ProjectID, sc.EnvID, key, version, nonce, ciphertext)
	if err != nil {
		return Value{}, err
	}
	return Value{Key: key, Version: version, Value: plaintext}, nil
}

// History returns every version of a key, oldest first, including tombstones.
func (s *Store) History(ctx context.Context, sc Scope, key string) ([]VersionRow, error) {
	const q = `
SELECT sv.version, sv.deleted, sv.created_at, COALESCE(sv.created_by, '')
  FROM secrets s
  JOIN secret_versions sv ON sv.secret_id = s.id
 WHERE s.env_id = $1 AND s.key = $2
 ORDER BY sv.version`
	rows, err := s.Pool().Query(ctx, q, sc.EnvID, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]VersionRow, 0, 8)
	for rows.Next() {
		var r VersionRow
		if err := rows.Scan(&r.Version, &r.Deleted, &r.CreatedAt, &r.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// ExportValues returns every live value in the environment, sorted by key, decrypted.
//
// It is one query for the ciphertexts plus one data-key load, so exporting 1,000 secrets does not
// become 1,000 queries.
func (s *Store) ExportValues(ctx context.Context, sc Scope) ([]Value, error) {
	const q = `
SELECT s.key, s.current_version, sv.nonce, sv.ciphertext
  FROM secrets s
  JOIN secret_versions sv
    ON sv.secret_id = s.id AND sv.version = s.current_version AND sv.deleted = false
 WHERE s.env_id = $1
 ORDER BY s.key`
	rows, err := s.Pool().Query(ctx, q, sc.EnvID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type cipherRow struct {
		key       string
		version   int64
		nonce     []byte
		ciphertxt []byte
	}
	var raw []cipherRow
	for rows.Next() {
		var r cipherRow
		if err := rows.Scan(&r.key, &r.version, &r.nonce, &r.ciphertxt); err != nil {
			return nil, err
		}
		raw = append(raw, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}

	dk, err := s.sealer.Load(ctx, s.Pool(), sc.OrgID, sc.ProjectID)
	if err != nil {
		return nil, err
	}
	out := make([]Value, 0, len(raw))
	for _, r := range raw {
		plaintext, err := dk.Open(sc.OrgID, sc.ProjectID, sc.EnvID, r.key, r.version, r.nonce, r.ciphertxt)
		if err != nil {
			// One corrupt row fails the whole export. A partial export would silently drop a
			// variable and the caller could not tell the difference.
			return nil, err
		}
		out = append(out, Value{Key: r.key, Version: r.version, Value: plaintext})
	}
	return out, nil
}

// DecryptChangeValue opens a pending change's payload under the change bound associated data.
func (s *Store) DecryptChangeValue(ctx context.Context, q querier, ch Change) ([]byte, error) {
	dk, err := s.sealer.Load(ctx, q, ch.OrgID, ch.ProjectID)
	if err != nil {
		return nil, err
	}
	return dk.OpenChange(ch.OrgID, ch.ProjectID, ch.EnvID, ch.Key, ch.ID, ch.PayloadNonce, ch.PayloadCT)
}

// EncryptChangeValue seals a proposed value for a pending change.
//
// It provisions the project data key when the project has none yet, exactly as a direct write does:
// the first write to a protected environment is a proposal, so without this the very first change
// could never be created.
func (s *Store) EncryptChangeValue(ctx context.Context, q querier, orgID, projectID, envID, key, changeID string, value []byte) (nonce, ct []byte, err error) {
	dk, err := s.sealer.Load(ctx, q, orgID, projectID)
	if errors.Is(err, crypto.ErrDataKeyMissing) {
		dk, err = s.sealer.Ensure(ctx, q, orgID, projectID)
	}
	if err != nil {
		return nil, nil, err
	}
	return dk.SealChange(orgID, projectID, envID, key, changeID, value)
}
