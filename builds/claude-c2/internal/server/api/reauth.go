package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// Org row lock modes for lockActor.
//
// The org row is the per-org authorization mutex. Every transaction that
// changes who may do what (role changes, removals, member additions, grant
// changes) takes it FOR NO KEY UPDATE; every other mutating org-scoped
// transaction (approve/reject, token issue/revoke, project/env creation,
// secret writes and proposals) takes it FOR SHARE. Org disable takes it FOR
// UPDATE. So a mutation that is serialised after a committed demotion,
// removal, grant change or disable re-reads the caller's state after that
// commit and is judged against it (SPEC §2.2, §2.3, §2.11), while ordinary
// mutations do not block each other.
//
// Lock order, always: org row, then the caller's token row, then the change
// row / target user / grant rows, then secret head rows, then the audit chain
// head (appended last).
const (
	orgShare      = "FOR SHARE"
	orgMembership = "FOR NO KEY UPDATE"
)

// lockActor takes the org row lock in mode and re-validates p inside tx: the
// org is still enabled, and the caller's token is still unrevoked and
// unexpired (and, for a PAT, its user is still in the org). It returns a copy
// of p carrying the role and access as of now, or nil if the caller is no
// longer authenticated. Every permission decision after this call must use
// the returned principal.
func lockActor(ctx context.Context, tx pgx.Tx, p *Principal, mode string) (*Principal, error) {
	if p == nil || (p.Kind != KindUser && p.Kind != KindService) || p.OrgID == "" {
		return nil, nil
	}
	if mode != orgShare && mode != orgMembership {
		return nil, errors.New("lockActor: invalid lock mode")
	}
	var disabled bool
	err := tx.QueryRow(ctx, `SELECT disabled FROM orgs WHERE id=$1 `+mode, p.OrgID).Scan(&disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if disabled {
		return nil, nil
	}
	q := *p
	switch p.Kind {
	case KindUser:
		// The token row is locked FOR SHARE so an in-flight logout or
		// password change (which revokes it) serialises with this request.
		// The user row needs no lock: every change to role or membership
		// holds the org row FOR NO KEY UPDATE, which we now hold against.
		err = tx.QueryRow(ctx, `SELECT u.role, u.email FROM tokens t JOIN users u ON u.id = t.user_id
			WHERE t.id=$1 AND t.kind='pat' AND t.org_id=$3 AND t.revoked_at IS NULL AND t.expires_at > now()
			  AND u.id=$2 AND u.org_id=$3
			FOR SHARE OF t`, p.TokenID, p.UserID, p.OrgID).Scan(&q.Role, &q.Email)
	case KindService:
		err = tx.QueryRow(ctx, `SELECT access, project_id, env_id FROM tokens
			WHERE id=$1 AND kind='service' AND org_id=$2 AND revoked_at IS NULL AND expires_at > now()
			FOR SHARE`, p.TokenID, p.OrgID).Scan(&q.Access, &q.ProjectID, &q.EnvID)
		if err == nil && (q.ProjectID != p.ProjectID || q.EnvID != p.EnvID) {
			return nil, nil
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if q.Kind == KindUser && q.Role != "owner" && q.Role != "admin" && q.Role != "member" {
		return nil, nil
	}
	return &q, nil
}

// relockOA is lockActor for owner/admin-only mutations. On failure it rolls
// tx back, writes the response (401 if the caller is gone, audited 403 if it
// is no longer an owner or admin) and returns nil.
func (s *Server) relockOA(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, r *http.Request, p *Principal, mode string) *Principal {
	q, err := lockActor(ctx, tx, p, mode)
	if err != nil {
		s.internalError(w, r, err)
		return nil
	}
	if q == nil {
		tx.Rollback(ctx)
		writeError(w, errUnauth)
		return nil
	}
	if !q.isOA() {
		tx.Rollback(ctx)
		s.deny(w, r, q, errForbidden)
		return nil
	}
	return q
}

// stillCanWrite re-checks, inside tx and after lockActor, that q may write in
// sc. It returns the denial to answer with, or nil.
func stillCanWrite(ctx context.Context, tx pgx.Tx, q *Principal, sc *scope) (*apiError, error) {
	switch {
	case q.Kind == KindService:
		if q.ProjectID != sc.projectID || q.EnvID != sc.envID {
			return errNotFound, nil
		}
		if q.Access != "read-write" {
			return errForbidden, nil
		}
		return nil, nil
	case q.isOA():
		return nil, nil
	case q.Kind == KindUser && q.Role == "member":
		var level string
		err := tx.QueryRow(ctx, `SELECT level FROM grants WHERE user_id=$1 AND project_id=$2`, q.UserID, sc.projectID).Scan(&level)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound, nil // the project is no longer visible
		}
		if err != nil {
			return nil, err
		}
		if levelRank(level) < 3 {
			return errForbidden, nil
		}
		return nil, nil
	}
	return errNotFound, nil
}

// relockWrite is lockActor + stillCanWrite for secret writes. A non-nil
// writeResult is the response to give (the caller returns it as is).
func relockWrite(ctx context.Context, tx pgx.Tx, p *Principal, sc *scope) (*Principal, *writeResult, error) {
	q, err := lockActor(ctx, tx, p, orgShare)
	if err != nil {
		return nil, nil, err
	}
	if q == nil {
		return nil, &writeResult{err: errUnauth}, nil
	}
	e, err := stillCanWrite(ctx, tx, q, sc)
	if err != nil {
		return nil, nil, err
	}
	if e != nil {
		return nil, &writeResult{err: e, deny: true}, nil
	}
	return q, nil, nil
}

func derefResult(r *writeResult) writeResult {
	if r == nil {
		return writeResult{}
	}
	return *r
}
