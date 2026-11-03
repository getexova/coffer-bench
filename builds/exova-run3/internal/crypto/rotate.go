package crypto

// Project data key rotation.
//
// The master key wraps every project's data key. Rotating it means re-wrapping each of those data
// keys under the new master key; the data keys themselves do not change, so no secret value is
// re-encrypted and nothing is rewritten except the wrapping.
//
// This lives in its own file because it is the one operation in this package that touches the
// database, and because it must run to completion before the server reports ready: once it returns
// nil, the old master key is no longer needed and can be removed from the environment.

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RotateIfNeeded re-wraps every project data key from oldKey to newKey in a single transaction.
//
// It is a no-op when oldKey is unset, which is the normal case: COFFER_MASTER_KEY_PREVIOUS is only
// set for the boot that performs the rotation. server.go calls it before reporting ready, so once
// it returns nil the old key is no longer needed and can be removed from the environment.
//
// Every data key is unwrapped and re-wrapped inside one transaction, so a failure part way through
// leaves every key wrapped under the old key: the rotation either completes or does not happen.
// The associated data is unchanged, because it binds the data key to its project and key version,
// not to the master key that wraps it.
func RotateIfNeeded(ctx context.Context, pool *pgxpool.Pool, oldKey, newKey Key) error {
	_, err := RotateIfNeededCount(ctx, pool, oldKey, newKey)
	return err
}

// RotateIfNeededCount is RotateIfNeeded, reporting how many data keys were re-wrapped so the boot
// log can state it.
func RotateIfNeededCount(ctx context.Context, pool *pgxpool.Pool, oldKey, newKey Key) (int, error) {
	// Checked first: with no previous key there is no rotation in progress, and the caller should
	// not need a usable pool to be told so.
	if oldKey.IsZero() {
		return 0, nil // no rotation in progress
	}
	if pool == nil {
		return 0, errors.New("crypto: rotation needs a database pool")
	}
	if newKey.IsZero() {
		return 0, ErrKeySize
	}
	if oldKey == newKey {
		return 0, nil
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Read every row before issuing updates: a pgx transaction is one connection, so it cannot
	// stream a result set while writing on the same connection.
	const sel = `
SELECT p.org_id, k.project_id, k.wrapped_key, k.nonce, k.key_version
  FROM project_data_keys k
  JOIN projects p ON p.id = k.project_id
 ORDER BY k.project_id`
	rows, err := tx.Query(ctx, sel)
	if err != nil {
		return 0, err
	}
	type row struct {
		orgID, projectID string
		wrapped, nonce   []byte
		keyVersion       int
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.orgID, &r.projectID, &r.wrapped, &r.nonce, &r.keyVersion); err != nil {
			rows.Close()
			return 0, err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	const upd = `UPDATE project_data_keys SET wrapped_key = $2, nonce = $3 WHERE project_id = $1`
	rotated := 0
	for _, r := range all {
		aad := DataKeyAAD(r.orgID, r.projectID, r.keyVersion)
		dek, err := UnwrapDataKey(oldKey, r.nonce, r.wrapped, aad)
		if err != nil {
			// The row is wrapped under neither the old nor the new key. Aborting is the only
			// safe answer: skipping it would leave a key nobody can unwrap once the old key is
			// retired, and pretending it succeeded would hide a corrupt row.
			return 0, ErrDecrypt
		}
		nonce, wrapped, err := WrapDataKey(newKey, dek, aad)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, upd, r.projectID, wrapped, nonce); err != nil {
			return 0, err
		}
		rotated++
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return rotated, nil
}
