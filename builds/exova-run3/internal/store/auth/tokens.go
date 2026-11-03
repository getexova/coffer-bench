package authstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Token kinds returned by ResolveToken.
const (
	KindUser    = "user"
	KindService = "service"
)

// HashToken returns the lowercase hex SHA-256 of a credential. Only this value is
// ever stored: the plaintext token exists in the response that minted it and
// nowhere else (SPEC §4).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Resolved is the outcome of the single token-resolution query: the principal, its
// organization and, for a service token, its scope.
type Resolved struct {
	Kind               string
	TokenID            string
	UserID             string
	Email              string
	OrgID              string
	Role               string
	MustChangePassword bool
	ProjectID          string
	EnvID              string
	Access             string
}

// ResolveTokenSQL is the one statement every authenticated request runs.
//
// It is deliberately a single round trip over the two unique token_hash indexes,
// and it has no cache in front of it anywhere in the process, so a revoked or
// expired token, a removed user, a lowered grant or a disabled organization is
// visible on the very next request (SPEC §2.11).
//
// Every rejection is a predicate in SQL rather than a check in Go:
//
//	personal_access_tokens.revoked_at IS NOT NULL   -> rejected
//	service_tokens.revoked_at IS NOT NULL           -> rejected
//	service_tokens.expires_at <= now()              -> rejected, using the
//	                                                   DATABASE clock so that a
//	                                                   skewed application server
//	                                                   cannot extend a token
//	users.removed_at IS NOT NULL                    -> rejected
//	organizations.disabled_at IS NOT NULL           -> rejected
//
// The platform admin is the one user with a NULL org_id, so the organization join
// is a LEFT JOIN and the disabled check only applies when an organization exists.
const ResolveTokenSQL = `
SELECT kind, token_id, user_id, email, org_id, role, must_change_password,
       project_id, env_id, access
  FROM (
        SELECT 'user'::text                     AS kind,
               t.id                             AS token_id,
               u.id                             AS user_id,
               u.email                          AS email,
               COALESCE(u.org_id, '')           AS org_id,
               u.role                           AS role,
               u.must_change_password           AS must_change_password,
               ''::text                         AS project_id,
               ''::text                         AS env_id,
               ''::text                         AS access
          FROM personal_access_tokens t
          JOIN users u ON u.id = t.user_id
          LEFT JOIN organizations o ON o.id = u.org_id
         WHERE t.token_hash = $1
           AND t.revoked_at IS NULL
           AND u.removed_at IS NULL
           AND (u.org_id IS NULL OR o.disabled_at IS NULL)
        UNION ALL
        SELECT 'service'::text                  AS kind,
               st.id                            AS token_id,
               ''::text                         AS user_id,
               ''::text                         AS email,
               st.org_id                        AS org_id,
               ''::text                         AS role,
               false                            AS must_change_password,
               st.project_id                    AS project_id,
               st.env_id                        AS env_id,
               st.access                        AS access
          FROM service_tokens st
          JOIN organizations o ON o.id = st.org_id
         WHERE st.token_hash = $1
           AND st.revoked_at IS NULL
           AND st.expires_at > now()
           AND o.disabled_at IS NULL
       ) AS resolved
 LIMIT 1`

// ResolveToken runs ResolveTokenSQL. A credential that does not resolve is
// ErrNotFound, which the caller turns into a 401 without distinguishing unknown,
// expired and revoked.
func ResolveToken(ctx context.Context, q Querier, tokenHash string) (Resolved, error) {
	var r Resolved
	err := q.QueryRow(ctx, ResolveTokenSQL, tokenHash).Scan(
		&r.Kind, &r.TokenID, &r.UserID, &r.Email, &r.OrgID, &r.Role,
		&r.MustChangePassword, &r.ProjectID, &r.EnvID, &r.Access)
	return r, mapErr(err)
}

// CreatePAT stores a personal access token hash for one user.
func CreatePAT(ctx context.Context, q Querier, id, userID, tokenHash string) error {
	_, err := q.Exec(ctx,
		`INSERT INTO personal_access_tokens (id, user_id, token_hash) VALUES ($1, $2, $3)`,
		id, userID, tokenHash)
	return mapErr(err)
}

// RevokePAT revokes one token by id. It reports whether this call performed the
// transition, so logout is idempotent and cannot emit a second audit event.
func RevokePAT(ctx context.Context, q Querier, tokenID string) (bool, error) {
	tag, err := q.Exec(ctx,
		`UPDATE personal_access_tokens SET revoked_at = now()
		  WHERE id = $1 AND revoked_at IS NULL`, tokenID)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() > 0, nil
}

// ServiceToken is a machine credential scoped to exactly one project and one
// environment. It always has an expiry.
type ServiceToken struct {
	ID          string
	OrgID       string
	ProjectID   string
	ProjectSlug string
	EnvID       string
	EnvSlug     string
	Access      string
	Name        string
	CreatedBy   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}

const serviceTokenCols = `st.id, st.org_id, st.project_id, p.slug, st.env_id, e.slug,
	st.access, COALESCE(st.name, ''), st.created_by, st.created_at, st.expires_at, st.revoked_at`

func scanServiceToken(row pgxRow) (ServiceToken, error) {
	var t ServiceToken
	err := row.Scan(&t.ID, &t.OrgID, &t.ProjectID, &t.ProjectSlug, &t.EnvID, &t.EnvSlug,
		&t.Access, &t.Name, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.RevokedAt)
	return t, mapErr(err)
}

// CreateServiceToken stores a service token hash. expires_at is computed with
// now() + ttl in SQL so that issue time and expiry share the database clock that
// ResolveTokenSQL later compares against.
func CreateServiceToken(ctx context.Context, q Querier, t ServiceToken, ttlSeconds int, tokenHash string) (ServiceToken, error) {
	return scanServiceToken(q.QueryRow(ctx,
		`WITH inserted AS (
		   INSERT INTO service_tokens
		         (id, org_id, project_id, env_id, access, name, token_hash, created_by, expires_at)
		   VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, $8,
		           now() + make_interval(secs => $9::double precision))
		   RETURNING *
		 )
		 SELECT `+serviceTokenCols+`
		   FROM inserted st
		   JOIN projects p ON p.id = st.project_id
		   JOIN environments e ON e.id = st.env_id`,
		t.ID, t.OrgID, t.ProjectID, t.EnvID, t.Access, t.Name, tokenHash, t.CreatedBy, ttlSeconds))
}

// ListServiceTokens lists the service tokens of one organization. Personal access
// tokens are session credentials and are never listed here.
func ListServiceTokens(ctx context.Context, q Querier, orgID string) ([]ServiceToken, error) {
	rows, err := q.Query(ctx,
		`SELECT `+serviceTokenCols+`
		   FROM service_tokens st
		   JOIN projects p ON p.id = st.project_id
		   JOIN environments e ON e.id = st.env_id
		  WHERE st.org_id = $1
		  ORDER BY st.created_at DESC, st.id`, orgID)
	if err != nil {
		return nil, mapErr(err)
	}
	return collect(rows, func(r pgxRows) (ServiceToken, error) { return scanServiceToken(r) })
}

// RevokeServiceToken revokes one service token of one organization. The org id is
// part of the predicate, so another organization's token id is the same zero-row
// result as an unknown id. It reports whether the revocation happened now and
// whether the row exists at all, so the caller can be idempotent on an
// already-revoked token while still returning 404 for an id it cannot see.
func RevokeServiceToken(ctx context.Context, q Querier, orgID, id string) (revoked, found bool, err error) {
	tag, err := q.Exec(ctx,
		`UPDATE service_tokens SET revoked_at = now()
		  WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`, id, orgID)
	if err != nil {
		return false, false, mapErr(err)
	}
	if tag.RowsAffected() > 0 {
		return true, true, nil
	}
	var exists bool
	if err := q.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM service_tokens WHERE id = $1 AND org_id = $2)`,
		id, orgID).Scan(&exists); err != nil {
		return false, false, mapErr(err)
	}
	return false, exists, nil
}

// ServiceTokenByID reads one service token by id inside its organization, with its
// project and environment slugs resolved. GET /me uses it to answer a service token
// with its scope only.
func ServiceTokenByID(ctx context.Context, q Querier, orgID, id string) (ServiceToken, error) {
	return scanServiceToken(q.QueryRow(ctx,
		`SELECT `+serviceTokenCols+`
		   FROM service_tokens st
		   JOIN projects p ON p.id = st.project_id
		   JOIN environments e ON e.id = st.env_id
		  WHERE st.org_id = $1 AND st.id = $2`, orgID, id))
}
