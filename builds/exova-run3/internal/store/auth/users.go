package authstore

import (
	"context"
	"time"
)

// User is one account. OrgID is empty for the platform admin only, which is the
// single row in the schema whose org_id is NULL.
type User struct {
	ID                 string
	OrgID              string
	Email              string
	PasswordHash       string
	Role               string
	MustChangePassword bool
	CreatedAt          time.Time
	// OrgDisabled is derived, not stored: it is true when this user's
	// organization has disabled_at set. Login needs it to answer 401 without a
	// second round trip.
	OrgDisabled bool
}

// userCols assumes the users table is aliased `u` and organizations `o`.
const userCols = `u.id, COALESCE(u.org_id, ''), u.email, u.password_hash, u.role,
	u.must_change_password, u.created_at, (o.disabled_at IS NOT NULL)`

func scanUser(row pgxRow) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.Role,
		&u.MustChangePassword, &u.CreatedAt, &u.OrgDisabled)
	return u, mapErr(err)
}

// CreateUser inserts one account and returns the row as stored, so the caller can
// report the database's own created_at rather than an approximation. An empty OrgID
// stores NULL, which is how the platform admin is represented. A duplicate email is
// ErrConflict; the caller must answer with a generic 409 that names no organization.
func CreateUser(ctx context.Context, q Querier, u User) (User, error) {
	var out User
	err := q.QueryRow(ctx,
		`INSERT INTO users (id, org_id, email, password_hash, role, must_change_password)
		 VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6)
		 RETURNING id, COALESCE(org_id, ''), email, password_hash, role,
		           must_change_password, created_at`,
		u.ID, u.OrgID, NormalizeEmail(u.Email), u.PasswordHash, u.Role, u.MustChangePassword).
		Scan(&out.ID, &out.OrgID, &out.Email, &out.PasswordHash, &out.Role,
			&out.MustChangePassword, &out.CreatedAt)
	return out, mapErr(err)
}

// UserByEmail is the login lookup. Removed users are filtered out here so that a
// removed account and an unknown address take exactly the same code path: the
// caller then performs the dummy argon2id verification for both.
func UserByEmail(ctx context.Context, q Querier, email string) (User, error) {
	return scanUser(q.QueryRow(ctx,
		`SELECT `+userCols+`
		   FROM users u
		   LEFT JOIN organizations o ON o.id = u.org_id
		  WHERE u.email = $1 AND u.removed_at IS NULL`,
		NormalizeEmail(email)))
}

// UserByIDInOrg reads one live member of one organization. The org id is part of
// the predicate, so another organization's user is indistinguishable from a
// missing one.
func UserByIDInOrg(ctx context.Context, q Querier, orgID, userID string) (User, error) {
	return scanUser(q.QueryRow(ctx,
		`SELECT `+userCols+`
		   FROM users u
		   LEFT JOIN organizations o ON o.id = u.org_id
		  WHERE u.id = $1 AND u.org_id = $2 AND u.removed_at IS NULL`,
		userID, orgID))
}

// UserByID reads one live user by id, without an organization predicate. It is
// used only for the caller's own account, where the id came from a credential that
// already resolved, so there is no organization to scope by.
func UserByID(ctx context.Context, q Querier, userID string) (User, error) {
	return scanUser(q.QueryRow(ctx,
		`SELECT `+userCols+`
		   FROM users u
		   LEFT JOIN organizations o ON o.id = u.org_id
		  WHERE u.id = $1 AND u.removed_at IS NULL`, userID))
}

// ListMembers returns the live members of one organization, ordered by email.
func ListMembers(ctx context.Context, q Querier, orgID string) ([]User, error) {
	rows, err := q.Query(ctx,
		`SELECT `+userCols+`
		   FROM users u
		   JOIN organizations o ON o.id = u.org_id
		  WHERE u.org_id = $1 AND u.removed_at IS NULL
		  ORDER BY u.email`, orgID)
	if err != nil {
		return nil, mapErr(err)
	}
	return collect(rows, func(r pgxRows) (User, error) { return scanUser(r) })
}

// UpdateUserRole changes one live member's role inside one organization.
func UpdateUserRole(ctx context.Context, q Querier, orgID, userID, role string) (bool, error) {
	tag, err := q.Exec(ctx,
		`UPDATE users SET role = $3
		  WHERE id = $1 AND org_id = $2 AND removed_at IS NULL`, userID, orgID, role)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() > 0, nil
}

// RemoveUser soft-deletes one live member. Their tokens stop resolving on the
// next request because ResolveTokenSQL filters on users.removed_at.
func RemoveUser(ctx context.Context, q Querier, orgID, userID string) (bool, error) {
	tag, err := q.Exec(ctx,
		`UPDATE users SET removed_at = now()
		  WHERE id = $1 AND org_id = $2 AND removed_at IS NULL`, userID, orgID)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() > 0, nil
}

// CountOwners counts the live owners of one organization. It is read inside the
// same transaction as any role change or removal, so the last-owner rule cannot
// race with a concurrent demotion.
func CountOwners(ctx context.Context, q Querier, orgID string) (int64, error) {
	var n int64
	err := q.QueryRow(ctx,
		`SELECT count(*) FROM users
		  WHERE org_id = $1 AND role = 'owner' AND removed_at IS NULL`, orgID).Scan(&n)
	return n, mapErr(err)
}

// LockOwners locks and returns the ids of the live owners of one organization.
//
// It exists because the last-owner rule needs a count that two concurrent
// transactions cannot both read as two. The row locks are taken before the count is
// observed by the caller, so a demotion and a removal of the last two owners
// serialise instead of both succeeding and leaving the organization ownerless.
func LockOwners(ctx context.Context, q Querier, orgID string) ([]string, error) {
	rows, err := q.Query(ctx,
		`SELECT id FROM users
		  WHERE org_id = $1 AND role = 'owner' AND removed_at IS NULL
		  ORDER BY id
		    FOR UPDATE`, orgID)
	if err != nil {
		return nil, mapErr(err)
	}
	return collect(rows, func(r pgxRows) (string, error) {
		var id string
		err := r.Scan(&id)
		return id, mapErr(err)
	})
}

// CountUsers is the first-boot gate: the platform admin is created only when no
// user exists at all.
func CountUsers(ctx context.Context, q Querier) (int64, error) {
	var n int64
	err := q.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, mapErr(err)
}

// SetPassword replaces a password hash and the must-change flag together, so the
// two can never disagree.
func SetPassword(ctx context.Context, q Querier, userID, passwordHash string, mustChange bool) error {
	_, err := q.Exec(ctx,
		`UPDATE users SET password_hash = $2, must_change_password = $3 WHERE id = $1`,
		userID, passwordHash, mustChange)
	return mapErr(err)
}

// RevokeOtherPATs revokes every live PAT of one user except keepTokenID, the one
// that performed the password change. An empty keepTokenID revokes them all.
// This is P1(b): a password change kills sessions opened with the old password.
func RevokeOtherPATs(ctx context.Context, q Querier, userID, keepTokenID string) (int64, error) {
	tag, err := q.Exec(ctx,
		`UPDATE personal_access_tokens SET revoked_at = now()
		  WHERE user_id = $1 AND revoked_at IS NULL AND ($2 = '' OR id <> $2)`,
		userID, keepTokenID)
	if err != nil {
		return 0, mapErr(err)
	}
	return tag.RowsAffected(), nil
}
