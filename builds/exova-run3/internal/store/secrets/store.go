// Package secrets is the store layer for secrets, versions, project data keys and
// change requests.
//
// It owns the two pieces of logic in this product that cannot be recovered from by the compiler:
// the version allocator (write.go) and the change-approval transaction (changes.go). Both are
// documented at their implementation.
//
// Rules that hold for every query in this package:
//   - Version allocation uses the allocator column, never MAX()+1
//     (docs/CONTRACTS.md §9): UPDATE secrets SET current_version = current_version + 1
//     [AND current_version = $expected] RETURNING current_version. The row update is
//     the lock.
//   - Ciphertext and nonce are stored as bytea and never converted to text, so a
//     value cannot reach a log through a driver's string rendering.
//   - A plaintext value never leaves this package's callers except through the three
//     audited exits: single-key get, export and run.
//   - No error returned from here carries a secret value, a ciphertext or key material.
package secrets

import (
	"context"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5"

	"coffer/internal/crypto"
	"coffer/internal/store"
)

// MaxValueBytes is the inclusive upper bound on a secret value (SPEC §3).
const MaxValueBytes = 65536

// Errors. Each maps to exactly one HTTP status in internal/api/secretsapi; nothing here knows
// about HTTP.
var (
	// ErrNotFound is a missing row, a key in another organization, or a tombstoned key.
	ErrNotFound = errors.New("secrets: not found")
	// ErrConflict is an expected-version mismatch or a write against a version with no value.
	ErrConflict = errors.New("secrets: version conflict")
	// ErrAlreadyResolved is a change request that is no longer pending.
	ErrAlreadyResolved = errors.New("secrets: change already resolved")
	// ErrStale is a change whose base version is no longer current. The request is marked stale.
	ErrStale = errors.New("secrets: change is stale")
	// ErrSelfApproval is an attempt to approve a request the caller proposed.
	ErrSelfApproval = errors.New("secrets: proposer cannot approve")
	// ErrNotApprover is an approver who is neither an owner nor an admin.
	ErrNotApprover = errors.New("secrets: approver must be an owner or admin")
	// ErrInvalidKey is a key that does not match the frozen format, or an unknown operation.
	ErrInvalidKey = errors.New("secrets: invalid key")
	// ErrValueTooLarge is a value above MaxValueBytes.
	ErrValueTooLarge = errors.New("secrets: value too large")
	// ErrProposerUnavailable is a proposal whose would-be proposer cannot be resolved: a service
	// token whose issuing user has been removed or no longer exists. It maps to 403, never 500.
	ErrProposerUnavailable = errors.New("secrets: proposer is unavailable")
	// ErrInvalidUTF8 is a value whose bytes are not valid UTF-8. It is refused because a value is
	// returned as a JSON string, and a non-UTF-8 sequence would not round-trip byte-exactly.
	ErrInvalidUTF8 = errors.New("secrets: value is not valid UTF-8")
)

// keyPattern is the frozen key format from SPEC §3.
var keyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// ValidKey reports whether key matches ^[A-Z_][A-Z0-9_]{0,127}$.
func ValidKey(key string) bool { return keyPattern.MatchString(key) }

// ValidateValue enforces the byte-length bound. Any UTF-8 sequence of length 0..65536 is accepted:
// the column holds bytes, and an empty value is valid and must round-trip exactly.
func ValidateValue(v []byte) error {
	if len(v) > MaxValueBytes {
		return ErrValueTooLarge
	}
	return nil
}

// ActorRef identifies who performed a write. Kind is "user" or "service"; ID is the user id or the
// service token id, matching the audit actor.
type ActorRef struct {
	ID   string
	Kind string
}

// Scope is a resolved (project, environment) pair. Grant is the caller's project grant level, or
// "" when there is none; it is resolved in the same query as the scope so a request never costs an
// extra round trip to authorize itself.
type Scope struct {
	OrgID     string
	ProjectID string
	EnvID     string
	EnvSlug   string
	Protected bool
	Grant     string
}

// Store is the secrets storage layer.
type Store struct {
	store.Base
	sealer *crypto.Sealer
}

// New builds a Store over the given base and sealer.
func New(base store.Base, sealer *crypto.Sealer) *Store {
	return &Store{Base: base, sealer: sealer}
}

// Sealer exposes the envelope sealer, which the API layer needs for change payloads.
func (s *Store) Sealer() *crypto.Sealer { return s.sealer }

// ResolveScope resolves a project and environment by slug inside one organization.
//
// org_id is in the SQL predicate, so a project in another organization, a project the caller has no
// grant for, and a project that does not exist are the same result: ErrNotFound. That is what makes
// "invisible means 404" (SPEC §2.1) a property of the query rather than of the handler.
func (s *Store) ResolveScope(ctx context.Context, orgID, projectSlug, envSlug, userID string) (Scope, error) {
	const q = `
SELECT p.id, e.id, e.slug, e.protected,
       COALESCE((SELECT g.level FROM project_grants g
                  WHERE g.project_id = p.id AND g.user_id = $4), '') AS grant_level
  FROM projects p
  JOIN environments e ON e.project_id = p.id
 WHERE p.org_id = $1 AND p.slug = $2 AND e.slug = $3`
	var sc Scope
	sc.OrgID = orgID
	err := s.Pool().QueryRow(ctx, q, orgID, projectSlug, envSlug, userID).
		Scan(&sc.ProjectID, &sc.EnvID, &sc.EnvSlug, &sc.Protected, &sc.Grant)
	if errors.Is(err, pgx.ErrNoRows) {
		return Scope{}, ErrNotFound
	}
	if err != nil {
		return Scope{}, err
	}
	return sc, nil
}

// ProjectExists reports whether a project id belongs to the organization. It is used by the change
// list, which is not scoped to a single project.
func (s *Store) ProjectExists(ctx context.Context, orgID, projectID string) (bool, error) {
	const q = `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND org_id = $2)`
	var ok bool
	if err := s.Pool().QueryRow(ctx, q, projectID, orgID).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

// ServiceTokenCreator returns the user id that created a service token. A change request needs a
// human proposer (change_requests.proposer_id references users), so a proposal made by a service
// token is attributed to the user who issued the token. That user then cannot approve it, which is
// the two-person rule working as intended for machine credentials.
// It returns ErrProposerUnavailable when the token no longer exists or the user who issued it has
// been removed. A removed user cannot be the proposer of a change request: they cannot be held to
// it, and they must not be able to approve it either. The caller turns that into a 403 — never a
// 500, and the user is never resurrected.
func (s *Store) ServiceTokenCreator(ctx context.Context, tokenID string) (string, error) {
	const q = `
SELECT t.created_by
  FROM service_tokens t
  JOIN users u ON u.id = t.created_by
 WHERE t.id = $1 AND u.removed_at IS NULL`
	var createdBy string
	err := s.Pool().QueryRow(ctx, q, tokenID).Scan(&createdBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrProposerUnavailable
	}
	if err != nil {
		return "", err
	}
	return createdBy, nil
}
