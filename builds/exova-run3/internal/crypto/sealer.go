package crypto

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrDataKeyMissing is returned when a project has no data key row. The sealer provisions one on
// the write path with Ensure, so this only surfaces on a read of ciphertext whose key is gone.
var ErrDataKeyMissing = errors.New("crypto: project data key is not provisioned")

// CurrentKeyVersion is the data-key version stamped on a newly created project data key.
const CurrentKeyVersion = 1

// DataKey is a project's data key, bound to the project it belongs to.
//
// The coordinates are part of the value so that a caller cannot accidentally open another
// project's ciphertext: Open refuses when the coordinates it is given differ from its own, and the
// associated data differs anyway.
type DataKey struct {
	orgID     string
	projectID string
	key       Key
}

// OrgID returns the organization the data key belongs to.
func (d *DataKey) OrgID() string { return d.orgID }

// ProjectID returns the project the data key belongs to.
func (d *DataKey) ProjectID() string { return d.projectID }

// Open decrypts a secret value under this project's data key, with the value's own associated
// data rebuilt from its coordinates and stored version.
//
// This is the only way a secret value leaves ciphertext inside the process, and it returns
// ErrDecrypt with no plaintext when the associated data does not match — which is what makes a
// ciphertext copied into another row fail rather than return a value.
func (d *DataKey) Open(orgID, projectID, envID, name string, version int64, nonce, ciphertext []byte) ([]byte, error) {
	if d == nil || d.key.IsZero() {
		return nil, ErrDecrypt
	}
	if orgID != d.orgID || projectID != d.projectID {
		return nil, ErrDecrypt
	}
	return Open(d.key, nonce, ciphertext, SecretAAD(orgID, projectID, envID, name, version))
}

// Seal encrypts a secret value under this project's data key with the value's own associated data.
func (d *DataKey) Seal(orgID, projectID, envID, name string, version int64, plaintext []byte) (nonce, ciphertext []byte, err error) {
	if d == nil || d.key.IsZero() {
		return nil, nil, ErrDecrypt
	}
	if orgID != d.orgID || projectID != d.projectID {
		return nil, nil, ErrDecrypt
	}
	return Seal(d.key, plaintext, SecretAAD(orgID, projectID, envID, name, version))
}

// OpenChange decrypts a pending change's proposed value. The associated data is bound to the change
// id, so a payload cannot be redirected to another key, environment or request.
func (d *DataKey) OpenChange(orgID, projectID, envID, name, changeID string, nonce, ciphertext []byte) ([]byte, error) {
	if d == nil || d.key.IsZero() {
		return nil, ErrDecrypt
	}
	if orgID != d.orgID || projectID != d.projectID {
		return nil, ErrDecrypt
	}
	return Open(d.key, nonce, ciphertext, ChangeAAD(orgID, projectID, envID, name, changeID))
}

// SealChange encrypts a pending change's proposed value under the change bound associated data.
func (d *DataKey) SealChange(orgID, projectID, envID, name, changeID string, plaintext []byte) (nonce, ciphertext []byte, err error) {
	if d == nil || d.key.IsZero() {
		return nil, nil, ErrDecrypt
	}
	if orgID != d.orgID || projectID != d.projectID {
		return nil, nil, ErrDecrypt
	}
	return Seal(d.key, plaintext, ChangeAAD(orgID, projectID, envID, name, changeID))
}

// Sealer wraps and unwraps project data keys with the master key. It holds no cache: a data key is
// read from the database on each use, so a rotation takes effect for the next request rather than
// for the next process.
type Sealer struct {
	master Key
}

// NewSealer builds a sealer from an already validated master key.
func NewSealer(master Key) *Sealer { return &Sealer{master: master} }

// NewSealerFromBytes validates and builds a sealer from raw master-key bytes, which is the shape
// config.Config carries them in.
func NewSealerFromBytes(master []byte) (*Sealer, error) {
	if len(master) != KeySize {
		return nil, ErrKeySize
	}
	var k Key
	copy(k[:], master)
	return &Sealer{master: k}, nil
}

// Master returns the master key. Callers that need to hand it to RotateIfNeeded use this.
func (s *Sealer) Master() Key {
	if s == nil {
		return Key{}
	}
	return s.master
}

// rowQuerier is the surface shared by *pgxpool.Pool and pgx.Tx.
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Load reads and unwraps a project's data key.
//
// It never provisions: a read must not create a key, because a project with no data key has no
// ciphertext to read, and minting one there would mask a provisioning bug.
func (s *Sealer) Load(ctx context.Context, q rowQuerier, orgID, projectID string) (*DataKey, error) {
	if s == nil || s.master.IsZero() {
		return nil, ErrKeyMissing
	}
	const query = `SELECT wrapped_key, nonce, key_version FROM project_data_keys WHERE project_id = $1`
	var wrapped, nonce []byte
	var keyVersion int
	err := q.QueryRow(ctx, query, projectID).Scan(&wrapped, &nonce, &keyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDataKeyMissing
	}
	if err != nil {
		return nil, err
	}
	dek, err := UnwrapDataKey(s.master, nonce, wrapped, DataKeyAAD(orgID, projectID, keyVersion))
	if err != nil {
		return nil, err
	}
	return &DataKey{orgID: orgID, projectID: projectID, key: dek}, nil
}

// Ensure returns the project's data key, creating it if it does not exist yet.
//
// It is a single statement, which makes it race-safe without an advisory lock: the insert conflicts
// on the primary key, and DO UPDATE makes the statement return the winning row while taking its
// row lock. Two concurrent first-writes therefore agree on one data key instead of each creating a
// key that cannot decrypt the other's ciphertext.
//
// It is idempotent and safe to call at project creation as well as on the write path.
func (s *Sealer) Ensure(ctx context.Context, q rowQuerier, orgID, projectID string) (*DataKey, error) {
	if s == nil || s.master.IsZero() {
		return nil, ErrKeyMissing
	}
	// Fast path: the key almost always exists, and this takes no write lock.
	if dk, err := s.Load(ctx, q, orgID, projectID); err == nil {
		return dk, nil
	} else if !errors.Is(err, ErrDataKeyMissing) {
		return nil, err
	}

	fresh, err := NewKey()
	if err != nil {
		return nil, err
	}
	aad := DataKeyAAD(orgID, projectID, CurrentKeyVersion)
	nonce, wrapped, err := WrapDataKey(s.master, fresh, aad)
	if err != nil {
		return nil, err
	}

	const upsert = `
INSERT INTO project_data_keys (project_id, wrapped_key, nonce, key_version)
VALUES ($1, $2, $3, $4)
ON CONFLICT (project_id) DO UPDATE SET project_id = EXCLUDED.project_id
RETURNING wrapped_key, nonce, key_version`
	var gotWrapped, gotNonce []byte
	var gotVersion int
	if err := q.QueryRow(ctx, upsert, projectID, wrapped, nonce, CurrentKeyVersion).
		Scan(&gotWrapped, &gotNonce, &gotVersion); err != nil {
		return nil, err
	}
	dek, err := UnwrapDataKey(s.master, gotNonce, gotWrapped, DataKeyAAD(orgID, projectID, gotVersion))
	if err != nil {
		return nil, err
	}
	return &DataKey{orgID: orgID, projectID: projectID, key: dek}, nil
}
