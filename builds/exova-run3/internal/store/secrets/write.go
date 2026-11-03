package secrets

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"coffer/internal/crypto"
	"coffer/internal/idgen"
)

// Op is a secret mutation. The values match change_requests.op.
type Op string

const (
	// OpSet writes a new value.
	OpSet Op = "set"
	// OpDelete writes a tombstone version.
	OpDelete Op = "delete"
	// OpRollback copies an earlier version's value into a new version.
	OpRollback Op = "rollback"
)

// WriteRequest is one mutation, applied through the allocator.
type WriteRequest struct {
	Scope Scope
	Key   string
	Op    Op

	// Value is the new value for OpSet. It may be empty, and its bytes are stored exactly.
	Value []byte
	// TargetVersion is the source version for OpRollback.
	TargetVersion int64
	// ExpectedVersion, when set, makes the write conditional: a mismatch allocates nothing and
	// returns ErrConflict.
	ExpectedVersion *int64

	Actor ActorRef
}

// Applied is the result of a mutation.
type Applied struct {
	Version  int64
	SecretID string
}

// Apply runs one mutation in its own transaction. Callers that also write an audit event use
// ApplyTx so the two commit together.
func (s *Store) Apply(ctx context.Context, w WriteRequest) (Applied, error) {
	var out Applied
	err := s.InTx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.ApplyTx(ctx, tx, w)
		return err
	})
	if err != nil {
		return Applied{}, err
	}
	return out, nil
}

// ApplyTx runs one mutation inside the caller's transaction.
//
// # The version allocator
//
// There is no MAX(version)+1 anywhere in this package, and there must never be one. The allocator
// is secrets.current_version:
//
//	UPDATE secrets SET current_version = current_version + 1, updated_at = now(), updated_by = $u
//	 WHERE env_id = $e AND key = $k [AND current_version = $expected]
//	 RETURNING id, current_version
//
// That UPDATE is both the allocator and the lock. Two concurrent unconditional writers to the same
// key are serialised by the row lock: the second blocks until the first commits, then re-reads the
// committed row and increments from it, so it sees the first writer's number. Writer A gets n+1,
// writer B gets n+2. There is no window in which two writers read the same value and both write it,
// which is exactly how MAX+1 loses an update. No number is skipped either, because the only way to
// obtain one is to increment the single committed counter, and a transaction that fails after
// incrementing rolls the increment back with it. Postgres takes the lock before the update and
// holds it to commit, so the read-modify-write of the counter is atomic even at READ COMMITTED.
//
// A conditional write adds AND current_version = $expected to the same statement, so the compare
// and the increment are one atomic operation rather than a read followed by a write that another
// transaction could interleave with. Zero rows affected with an expected version is ErrConflict and
// allocates nothing: no version number is consumed and no row is written.
//
// The secret_versions row is inserted with that number in the same transaction, and the primary key
// (secret_id, version) makes a duplicate impossible even if the allocator were ever wrong: the
// insert would fail and the whole transaction would roll back rather than fork a version number.
func (s *Store) ApplyTx(ctx context.Context, tx pgx.Tx, w WriteRequest) (Applied, error) {
	if !ValidKey(w.Key) {
		return Applied{}, ErrInvalidKey
	}
	if w.Op == OpSet {
		if err := ValidateValue(w.Value); err != nil {
			return Applied{}, err
		}
	}
	if w.Op != OpSet && w.Op != OpDelete && w.Op != OpRollback {
		return Applied{}, ErrInvalidKey
	}

	// Only a set may create the key. Creating the row for a delete or a rollback would turn a
	// write against a key that does not exist into a tombstone (or a rollback of nothing), so
	// those operations must find the row to succeed.
	//
	// ON CONFLICT DO NOTHING means two concurrent first-writes agree on one row, and it
	// deliberately does not touch current_version, so creating the row consumes no version
	// number.
	if w.Op == OpSet {
		const create = `
INSERT INTO secrets (id, env_id, key)
VALUES ($1, $2, $3)
ON CONFLICT (env_id, key) DO NOTHING`
		if _, err := tx.Exec(ctx, create, idgen.New("sec"), w.Scope.EnvID, w.Key); err != nil {
			return Applied{}, err
		}
	}

	version, secretID, err := s.allocate(ctx, tx, w)
	if err != nil {
		return Applied{}, err
	}

	var (
		nonce      []byte
		ciphertext []byte
		deleted    bool
	)
	switch w.Op {
	case OpSet:
		nonce, ciphertext, err = s.sealForWrite(ctx, tx, w.Scope, w.Key, version, w.Value)
	case OpDelete:
		// A tombstone carries no ciphertext: there is nothing to decrypt and a get returns 404.
		deleted = true
	case OpRollback:
		nonce, ciphertext, err = s.rollbackCiphertext(ctx, tx, w.Scope, w.Key, version, w.TargetVersion)
	}
	if err != nil {
		return Applied{}, err
	}

	const insert = `
INSERT INTO secret_versions (secret_id, version, ciphertext, nonce, deleted, created_by)
VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := tx.Exec(ctx, insert, secretID, version, ciphertext, nonce, deleted, w.Actor.ID); err != nil {
		return Applied{}, err
	}
	return Applied{Version: version, SecretID: secretID}, nil
}

// allocate is the version allocator described on ApplyTx. It is the only place a secret version
// number is produced.
func (s *Store) allocate(ctx context.Context, tx pgx.Tx, w WriteRequest) (version int64, secretID string, err error) {
	const unconditional = `
UPDATE secrets
   SET current_version = current_version + 1, updated_at = now(), updated_by = $2
 WHERE env_id = $1 AND key = $3
 RETURNING id, current_version`
	const conditional = `
UPDATE secrets
   SET current_version = current_version + 1, updated_at = now(), updated_by = $2
 WHERE env_id = $1 AND key = $3 AND current_version = $4
 RETURNING id, current_version`

	if w.ExpectedVersion != nil {
		err = tx.QueryRow(ctx, conditional, w.Scope.EnvID, w.Actor.ID, w.Key, *w.ExpectedVersion).
			Scan(&secretID, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, "", ErrConflict
		}
		return version, secretID, err
	}
	err = tx.QueryRow(ctx, unconditional, w.Scope.EnvID, w.Actor.ID, w.Key).Scan(&secretID, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		// A set created the row immediately above in this transaction, so it cannot be absent.
		// A delete or a rollback against a key that does not exist lands here, and the caller
		// must see the same 404 a get would give.
		return 0, "", ErrNotFound
	}
	return version, secretID, err
}

// sealForWrite encrypts a value for its version under the project's data key, provisioning the data
// key on the write path so a project whose key was never created still works.
func (s *Store) sealForWrite(ctx context.Context, tx pgx.Tx, sc Scope, key string, version int64, value []byte) (nonce, ciphertext []byte, err error) {
	dk, err := s.sealer.Load(ctx, tx, sc.OrgID, sc.ProjectID)
	if errors.Is(err, crypto.ErrDataKeyMissing) {
		dk, err = s.sealer.Ensure(ctx, tx, sc.OrgID, sc.ProjectID)
	}
	if err != nil {
		return nil, nil, err
	}
	return dk.Seal(sc.OrgID, sc.ProjectID, sc.EnvID, key, version, value)
}

// rollbackCiphertext reads version k and re-encrypts its value at the new version.
//
// The read is authenticated with version k's associated data and the write is sealed with the new
// version's, so a rollback is a genuine re-encryption rather than a copied ciphertext: copying the
// bytes would produce a value that cannot be decrypted at the new version. The new version holds
// the value, so deleting the source version later cannot change history.
func (s *Store) rollbackCiphertext(ctx context.Context, tx pgx.Tx, sc Scope, key string, newVersion, target int64) (nonce, ciphertext []byte, err error) {
	if target <= 0 {
		return nil, nil, ErrConflict
	}
	const sel = `
SELECT sv.nonce, sv.ciphertext
  FROM secrets s
  JOIN secret_versions sv ON sv.secret_id = s.id
 WHERE s.env_id = $1 AND s.key = $2 AND sv.version = $3 AND sv.deleted = false`
	var srcNonce, srcCiphertext []byte
	err = tx.QueryRow(ctx, sel, sc.EnvID, key, target).Scan(&srcNonce, &srcCiphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either the version does not exist or it is a tombstone. Neither has a value to roll
		// back to, and the caller must not learn which.
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}

	dk, err := s.sealer.Load(ctx, tx, sc.OrgID, sc.ProjectID)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := dk.Open(sc.OrgID, sc.ProjectID, sc.EnvID, key, target, srcNonce, srcCiphertext)
	if err != nil {
		return nil, nil, err
	}
	return dk.Seal(sc.OrgID, sc.ProjectID, sc.EnvID, key, newVersion, plaintext)
}
