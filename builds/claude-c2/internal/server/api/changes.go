package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/coffer-dev/coffer/internal/server/audit"
	"github.com/coffer-dev/coffer/internal/server/crypto"
)

type changeJSON struct {
	ID             string  `json:"id"`
	Project        string  `json:"project"`
	Env            string  `json:"env"`
	Key            string  `json:"key"`
	Op             string  `json:"op"`
	Status         string  `json:"status"`
	ProposedBy     string  `json:"proposed_by"`
	CreatedAt      string  `json:"created_at"`
	DecidedBy      *string `json:"decided_by"`
	DecidedAt      *string `json:"decided_at"`
	BaseVersion    int     `json:"base_version"`
	RollbackTo     *int    `json:"rollback_to"`
	AppliedVersion *int    `json:"applied_version"`
}

var changeStatuses = map[string]bool{"pending": true, "approved": true, "rejected": true, "stale": true}

// orgUserOnly enforces "OA only" style routes: PA → 404, ST/member → 403.
// It returns false after writing the denial.
func (s *Server) orgAdminOnly(w http.ResponseWriter, r *http.Request, p *Principal) bool {
	if p.Kind == KindPlatform {
		s.deny(w, r, p, errNotFound)
		return false
	}
	if !p.isOA() {
		s.deny(w, r, p, errForbidden)
		return false
	}
	return true
}

func (s *Server) handleListChanges(w http.ResponseWriter, r *http.Request, p *Principal) {
	if p.Kind == KindPlatform {
		s.deny(w, r, p, errNotFound)
		return
	}
	if p.Kind != KindUser {
		s.deny(w, r, p, errForbidden)
		return
	}
	status := ""
	if q := r.URL.Query(); q.Has("status") {
		status = q.Get("status")
		if !changeStatuses[status] {
			writeError(w, badRequest("status must be one of pending, approved, rejected, stale"))
			return
		}
	}
	sql := `SELECT c.id, p.slug, e.slug, c.key, c.op, c.status, c.proposed_by, c.created_at, c.decided_by, c.decided_at,
		c.base_version, c.rollback_to, c.applied_version
		FROM change_requests c JOIN projects p ON p.id=c.project_id JOIN environments e ON e.id=c.env_id
		WHERE c.org_id=$1 AND ($2='' OR c.status=$2)`
	args := []any{p.OrgID, status}
	if !p.isOA() {
		// Members see only their own proposals, and only while they can still
		// see the project.
		sql += ` AND c.proposed_by_user=$3 AND EXISTS (SELECT 1 FROM grants g WHERE g.user_id=$3 AND g.project_id=c.project_id)`
		args = append(args, p.UserID)
	}
	sql += ` ORDER BY c.created_at DESC, c.id DESC LIMIT 1000`
	rows, err := s.pool.Query(r.Context(), sql, args...)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer rows.Close()
	out := []changeJSON{}
	for rows.Next() {
		var c changeJSON
		var created time.Time
		var decided *time.Time
		if err := rows.Scan(&c.ID, &c.Project, &c.Env, &c.Key, &c.Op, &c.Status, &c.ProposedBy, &created, &c.DecidedBy, &decided,
			&c.BaseVersion, &c.RollbackTo, &c.AppliedVersion); err != nil {
			s.internalError(w, r, err)
			return
		}
		c.CreatedAt = ts(created)
		c.DecidedAt = tsPtr(decided)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type lockedChange struct {
	sc             scope
	key, op        string
	ct             []byte
	rollbackTo     *int
	baseVersion    int
	status         string
	proposedBy     string
	proposedByUser *string
}

func lockChange(ctx context.Context, tx pgx.Tx, orgID, id string) (*lockedChange, error) {
	if !validID(id) {
		return nil, nil
	}
	c := &lockedChange{}
	err := tx.QueryRow(ctx, `SELECT c.project_id, p.slug, p.wrapped_dek, c.env_id, e.slug, e.protected, c.key, c.op, c.ciphertext,
		c.rollback_to, c.base_version, c.status, c.proposed_by, c.proposed_by_user
		FROM change_requests c JOIN projects p ON p.id=c.project_id JOIN environments e ON e.id=c.env_id
		WHERE c.id=$1 AND c.org_id=$2 FOR UPDATE OF c`, id, orgID).Scan(
		&c.sc.projectID, &c.sc.projectSlug, &c.sc.wrappedDEK, &c.sc.envID, &c.sc.envSlug, &c.sc.protected, &c.key, &c.op, &c.ct,
		&c.rollbackTo, &c.baseVersion, &c.status, &c.proposedBy, &c.proposedByUser)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.sc.orgID = orgID
	return c, nil
}

// errProposerUnauthorized answers an approval whose proposer lost write
// access after proposing; the change is now stale.
var errProposerUnauthorized = conflict("the proposer can no longer write this secret; the change is now stale")

// proposerCanWrite re-resolves the change's proposer inside the approval
// transaction. A user must still exist in the change's org and be an owner or
// admin, or a member holding a writer grant on the project. A service token
// must be unrevoked, unexpired, read-write and scoped to the change's
// project and environment.
//
// The caller holds the org row FOR SHARE (lockActor), so every role, removal
// and grant change has either committed (and each statement below sees it)
// or waits for this transaction. Role and grant are still read in separate
// statements and the rows locked FOR SHARE, so correctness does not depend on
// a joined row being re-fetched after a lock wait (under READ COMMITTED only
// the locked row is).
func proposerCanWrite(ctx context.Context, tx pgx.Tx, c *lockedChange) (bool, error) {
	if c.proposedByUser == nil || c.proposedBy != *c.proposedByUser {
		var ok bool
		err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM tokens t
			WHERE t.id=$1 AND t.kind='service' AND t.org_id=$2 AND t.project_id=$3 AND t.env_id=$4
			  AND t.access='read-write' AND t.revoked_at IS NULL AND t.expires_at > now()
			FOR SHARE OF t)`, c.proposedBy, c.sc.orgID, c.sc.projectID, c.sc.envID).Scan(&ok)
		return ok, err
	}
	var role string
	err := tx.QueryRow(ctx, `SELECT role FROM users WHERE id=$1 AND org_id=$2 FOR SHARE`, c.proposedBy, c.sc.orgID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch role {
	case "owner", "admin":
		return true, nil
	case "member":
	default:
		return false, nil
	}
	// A separate statement: it gets a fresh snapshot after any lock wait above.
	var level string
	err = tx.QueryRow(ctx, `SELECT level FROM grants WHERE user_id=$1 AND project_id=$2 FOR SHARE`, c.proposedBy, c.sc.projectID).Scan(&level)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return level == "writer", nil
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	// Re-judge the approver after the org lock: an approver demoted or
	// removed before this point cannot decide (SPEC §2.3, §2.9, §2.11).
	if p = s.relockOA(ctx, tx, w, r, p, orgShare); p == nil {
		return
	}
	c, err := lockChange(ctx, tx, p.OrgID, id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if c == nil {
		tx.Rollback(ctx)
		s.deny(w, r, p, errNotFound)
		return
	}
	// Two-person rule: the human behind the proposal (including the creator
	// of a service token that proposed it) cannot approve it.
	if c.proposedByUser != nil && *c.proposedByUser == p.UserID || c.proposedBy == p.UserID {
		tx.Rollback(ctx)
		s.deny(w, r, p, errForbidden)
		return
	}
	if c.status != "pending" {
		writeError(w, conflict("change is not pending"))
		return
	}
	target := secretTarget(&c.sc, c.key)
	// Revocation is immediate (SPEC §2.11): a change is only applied on
	// behalf of a proposer who could still make that write now.
	stillAllowed, err := proposerCanWrite(ctx, tx, c)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !stillAllowed {
		if _, err := tx.Exec(ctx, `UPDATE change_requests SET status='stale', decided_by=$2, decided_at=now(), ciphertext=NULL WHERE id=$1`, id, p.UserID); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := audit.AppendTx(ctx, tx, s.event(r, p, "change.stale", target, audit.Failed,
			map[string]any{"change_id": id, "base_version": c.baseVersion, "reason": "proposer_unauthorized"})); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			s.internalError(w, r, err)
			return
		}
		writeError(w, errProposerUnauthorized)
		return
	}
	dek, err := s.dek(&c.sc)
	if err != nil {
		s.internalError(w, r, errors.New("data key unwrap failed"))
		return
	}
	req := writeReq{kind: writeKind(c.op), key: c.key}
	var plaintext []byte
	switch req.kind {
	case wSet:
		plaintext, err = crypto.Open(dek, c.ct, crypto.ChangeAAD(c.sc.orgID, c.sc.projectID, c.sc.envID, c.key, id))
		if err != nil {
			tx.Rollback(ctx)
			s.integrityFailure(w, r, p, "change.approve", &integrityError{target: target, version: c.baseVersion},
				map[string]any{"change_id": id})
			return
		}
		if plaintext == nil {
			plaintext = []byte{}
		}
	case wRollback:
		if c.rollbackTo == nil {
			s.internalError(w, r, errors.New("rollback change without target"))
			return
		}
		req.to = *c.rollbackTo
	case wDelete:
	default:
		s.internalError(w, r, errors.New("unknown change op"))
		return
	}
	author := c.proposedBy
	res, version, err := s.applyLocked(ctx, tx, &c.sc, dek, req, author, plaintext, &c.baseVersion)
	if err != nil {
		var ie *integrityError
		if errors.As(err, &ie) {
			tx.Rollback(ctx)
			s.integrityFailure(w, r, p, "change.approve", ie, map[string]any{"change_id": id, "to": req.to})
			return
		}
		s.internalError(w, r, err)
		return
	}
	if res.err == errTooManyKeys {
		// Not stale: the change stays pending and can be approved once
		// keys are freed.
		tx.Rollback(ctx)
		writeError(w, res.err)
		return
	}
	if res.err != nil {
		// Stale (or the target vanished): mark stale, commit, 409.
		if _, err := tx.Exec(ctx, `UPDATE change_requests SET status='stale', decided_by=$2, decided_at=now(), ciphertext=NULL WHERE id=$1`, id, p.UserID); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := audit.AppendTx(ctx, tx, s.event(r, p, "change.stale", target, audit.Failed, map[string]any{"change_id": id, "base_version": c.baseVersion})); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := tx.Commit(ctx); err != nil {
			s.internalError(w, r, err)
			return
		}
		writeError(w, errStale)
		return
	}
	if _, err := tx.Exec(ctx, `UPDATE change_requests SET status='approved', decided_by=$2, decided_at=now(), applied_version=$3, ciphertext=NULL WHERE id=$1`,
		id, p.UserID, version); err != nil {
		s.internalError(w, r, err)
		return
	}
	d := map[string]any{"change_id": id, "version": version}
	if req.kind == wRollback {
		d["to"] = req.to
	}
	if err := audit.AppendTx(ctx, tx,
		s.event(r, p, "change.approve", target, audit.Success, map[string]any{"change_id": id, "version": version}),
		s.event(r, p, writeAction[req.kind], target, audit.Success, d)); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "approved", "version": version})
}

func (s *Server) handleReject(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	// Re-judge the approver after the org lock: an approver demoted or
	// removed before this point cannot decide (SPEC §2.3, §2.9, §2.11).
	if p = s.relockOA(ctx, tx, w, r, p, orgShare); p == nil {
		return
	}
	c, err := lockChange(ctx, tx, p.OrgID, id)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if c == nil {
		tx.Rollback(ctx)
		s.deny(w, r, p, errNotFound)
		return
	}
	if c.status != "pending" {
		writeError(w, conflict("change is not pending"))
		return
	}
	if _, err := tx.Exec(ctx, `UPDATE change_requests SET status='rejected', decided_by=$2, decided_at=now(), ciphertext=NULL WHERE id=$1`, id, p.UserID); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "change.reject", secretTarget(&c.sc, c.key), audit.Success, map[string]any{"change_id": id})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "rejected"})
}
