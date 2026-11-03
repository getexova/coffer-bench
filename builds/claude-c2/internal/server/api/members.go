package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/coffer-dev/coffer/internal/server/audit"
	"github.com/coffer-dev/coffer/internal/server/config"
	"github.com/coffer-dev/coffer/internal/server/crypto"
)

type grantJSON struct {
	Project string `json:"project"`
	Level   string `json:"level"`
}

type memberJSON struct {
	ID        string      `json:"id"`
	Email     string      `json:"email"`
	Role      string      `json:"role"`
	CreatedAt string      `json:"created_at"`
	Grants    []grantJSON `json:"grants,omitempty"`
}

var orgRoles = map[string]bool{"member": true, "admin": true, "owner": true}
var grantLevels = map[string]bool{"viewer": true, "reader": true, "writer": true}

func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	ctx := r.Context()
	rows, err := s.pool.Query(ctx, `SELECT u.id, u.email, u.role, u.created_at, p.slug, g.level
		FROM users u LEFT JOIN grants g ON g.user_id=u.id LEFT JOIN projects p ON p.id=g.project_id AND p.org_id=u.org_id
		WHERE u.org_id=$1 ORDER BY u.email_norm, u.id, p.slug COLLATE "C"`, p.OrgID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer rows.Close()
	type full struct {
		memberJSON
		Grants []grantJSON `json:"grants"`
	}
	out := []*full{}
	idx := map[string]*full{}
	for rows.Next() {
		var id, email, role string
		var created time.Time
		var proj, level *string
		if err := rows.Scan(&id, &email, &role, &created, &proj, &level); err != nil {
			s.internalError(w, r, err)
			return
		}
		m := idx[id]
		if m == nil {
			m = &full{memberJSON: memberJSON{ID: id, Email: email, Role: role, CreatedAt: ts(created)}, Grants: []grantJSON{}}
			idx[id] = m
			out = append(out, m)
		}
		if proj != nil && level != nil {
			m.Grants = append(m.Grants, grantJSON{Project: *proj, Level: *level})
		}
	}
	if err := rows.Err(); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type addMemberReq struct {
	Email    *string `json:"email"`
	Role     *string `json:"role"`
	Password *string `json:"password"`
}

func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	var req addMemberReq
	if e := decodeBody(r, &req); e != nil {
		writeError(w, e)
		return
	}
	if req.Email == nil || req.Role == nil || req.Password == nil {
		writeError(w, badRequest("email, role and password are required"))
		return
	}
	if !orgRoles[*req.Role] {
		writeError(w, badRequest("role must be member, admin or owner"))
		return
	}
	if *req.Role == "owner" && p.Role != "owner" {
		s.deny(w, r, p, errForbidden)
		return
	}
	norm, ok := config.NormalizeEmail(*req.Email)
	if !ok {
		writeError(w, badRequest("invalid email address"))
		return
	}
	if err := config.CheckPassword(*req.Password); err != nil {
		writeError(w, badRequest(err.Error()))
		return
	}
	ctx := r.Context()
	var taken bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE email_norm=$1)`, norm).Scan(&taken); err != nil {
		s.internalError(w, r, err)
		return
	}
	if taken {
		writeError(w, conflict("email already in use"))
		return
	}
	hash, err := s.hasher.Hash(ctx, *req.Password)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	id := crypto.NewID("usr")
	email := trimEmail(*req.Email)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	// Re-judge the caller under the org's membership lock: a demotion that
	// committed while we hashed must apply (SPEC §2.2, §2.11).
	if p = s.relockOA(ctx, tx, w, r, p, orgMembership); p == nil {
		return
	}
	if *req.Role == "owner" && p.Role != "owner" {
		tx.Rollback(ctx)
		s.deny(w, r, p, errForbidden)
		return
	}
	var created time.Time
	err = tx.QueryRow(ctx, `INSERT INTO users (id, org_id, email, email_norm, password_hash, role, must_change_password)
		VALUES ($1,$2,$3,$4,$5,$6,true) RETURNING created_at`, id, p.OrgID, email, norm, hash, *req.Role).Scan(&created)
	if isUniqueViolation(err) {
		writeError(w, conflict("email already in use"))
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "member.add", id, audit.Success, map[string]any{"role": *req.Role})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, memberJSON{ID: id, Email: email, Role: *req.Role, CreatedAt: ts(created)})
}

// trimEmail stores the address as given (trimmed); matching uses email_norm.
func trimEmail(e string) string { return strings.TrimSpace(e) }

type target struct {
	id, email, role string
	created         time.Time
}

// lockTarget locks and loads the target user if it is in the org. The caller
// already holds the org row (lockActor with orgMembership).
func lockTarget(ctx context.Context, tx pgx.Tx, orgID, userID string) (*target, error) {
	if !validID(userID) {
		return nil, nil
	}
	t := &target{}
	err := tx.QueryRow(ctx, `SELECT id, email, role, created_at FROM users WHERE id=$1 AND org_id=$2 FOR UPDATE`, userID, orgID).
		Scan(&t.id, &t.email, &t.role, &t.created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// lockMembership serialises a membership change per org (the org row is the
// mutex), re-validates the caller under that lock and loads the target user.
// It returns the re-validated caller; on failure it has written the response
// and returns ok=false.
func (s *Server) lockMembership(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, r *http.Request, p *Principal) (*Principal, *target, bool) {
	q := s.relockOA(ctx, tx, w, r, p, orgMembership)
	if q == nil {
		return nil, nil, false
	}
	t, err := lockTarget(ctx, tx, q.OrgID, r.PathValue("user_id"))
	if err != nil {
		s.internalError(w, r, err)
		return nil, nil, false
	}
	if t == nil {
		tx.Rollback(ctx)
		s.deny(w, r, q, errNotFound)
		return nil, nil, false
	}
	return q, t, true
}

func countOtherOwners(ctx context.Context, tx pgx.Tx, orgID, exceptID string) (int, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM users WHERE org_id=$1 AND role='owner' AND id<>$2 FOR UPDATE`, orgID, exceptID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	return n, rows.Err()
}

type roleReq struct {
	Role *string `json:"role"`
}

func (s *Server) handlePatchMember(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	var req roleReq
	if e := decodeBody(r, &req); e != nil {
		writeError(w, e)
		return
	}
	if req.Role == nil || !orgRoles[*req.Role] {
		writeError(w, badRequest("role must be member, admin or owner"))
		return
	}
	newRole := *req.Role
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	p, t, ok := s.lockMembership(ctx, tx, w, r, p)
	if !ok {
		return
	}
	if (t.role == "owner" || newRole == "owner") && p.Role != "owner" {
		tx.Rollback(ctx)
		s.deny(w, r, p, errForbidden)
		return
	}
	if t.id == p.UserID {
		if t.role == "owner" && newRole != "owner" {
			n, err := countOtherOwners(ctx, tx, p.OrgID, t.id)
			if err != nil {
				s.internalError(w, r, err)
				return
			}
			if n == 0 {
				writeError(w, conflict("cannot demote the last owner"))
				return
			}
		}
		tx.Rollback(ctx)
		s.deny(w, r, p, errForbidden)
		return
	}
	if t.role == "owner" && newRole != "owner" {
		n, err := countOtherOwners(ctx, tx, p.OrgID, t.id)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if n == 0 {
			writeError(w, conflict("cannot demote the last owner"))
			return
		}
	}
	if t.role == newRole {
		writeJSON(w, http.StatusOK, memberJSON{ID: t.id, Email: t.email, Role: t.role, CreatedAt: ts(t.created)})
		return
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET role=$1 WHERE id=$2`, newRole, t.id); err != nil {
		s.internalError(w, r, err)
		return
	}
	if newRole != "member" {
		// Grants only apply to members; drop them so a later demotion does not
		// silently resurrect old access.
		if _, err := tx.Exec(ctx, `DELETE FROM grants WHERE user_id=$1`, t.id); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "member.role_change", t.id, audit.Success, map[string]any{"from": t.role, "to": newRole})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, memberJSON{ID: t.id, Email: t.email, Role: newRole, CreatedAt: ts(t.created)})
}

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	p, t, ok := s.lockMembership(ctx, tx, w, r, p)
	if !ok {
		return
	}
	if t.role == "owner" && p.Role != "owner" {
		tx.Rollback(ctx)
		s.deny(w, r, p, errForbidden)
		return
	}
	if t.role == "owner" {
		n, err := countOtherOwners(ctx, tx, p.OrgID, t.id)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if n == 0 {
			writeError(w, conflict("cannot remove the last owner"))
			return
		}
	}
	if t.id == p.UserID {
		tx.Rollback(ctx)
		s.deny(w, r, p, errForbidden)
		return
	}
	// PATs and grants cascade; service tokens they created are org assets
	// and keep working.
	if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id=$1`, t.id); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "member.remove", t.id, audit.Success, map[string]any{"role": t.role})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

type levelReq struct {
	Level *string `json:"level"`
}

// grantTarget resolves the target user and project for grant routes. It
// writes the denial and returns ok=false on failure.
func (s *Server) grantTarget(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, r *http.Request, p *Principal) (*Principal, *target, string, bool) {
	p, t, ok := s.lockMembership(ctx, tx, w, r, p)
	if !ok {
		return nil, nil, "", false
	}
	var projectID string
	err := pgx.ErrNoRows
	if ValidSlug(r.PathValue("project")) {
		err = tx.QueryRow(ctx, `SELECT id FROM projects WHERE org_id=$1 AND slug=$2`, p.OrgID, r.PathValue("project")).Scan(&projectID)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		tx.Rollback(ctx)
		s.deny(w, r, p, errNotFound)
		return nil, nil, "", false
	}
	if err != nil {
		s.internalError(w, r, err)
		return nil, nil, "", false
	}
	if t.id == p.UserID {
		tx.Rollback(ctx)
		s.deny(w, r, p, errForbidden)
		return nil, nil, "", false
	}
	return p, t, projectID, true
}

func (s *Server) handleSetGrant(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	var req levelReq
	if e := decodeBody(r, &req); e != nil {
		writeError(w, e)
		return
	}
	if req.Level == nil || !grantLevels[*req.Level] {
		writeError(w, badRequest("level must be viewer, reader or writer"))
		return
	}
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	p, t, projectID, ok := s.grantTarget(ctx, tx, w, r, p)
	if !ok {
		return
	}
	if t.role != "member" {
		writeError(w, badRequest("grants apply only to members; owners and admins have access to every project"))
		return
	}
	var previous *string
	err = tx.QueryRow(ctx, `SELECT level FROM grants WHERE user_id=$1 AND project_id=$2 FOR UPDATE`, t.id, projectID).Scan(&previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.internalError(w, r, err)
		return
	}
	if _, err := tx.Exec(ctx, `INSERT INTO grants (user_id, project_id, level) VALUES ($1,$2,$3)
		ON CONFLICT (user_id, project_id) DO UPDATE SET level=EXCLUDED.level`, t.id, projectID, *req.Level); err != nil {
		s.internalError(w, r, err)
		return
	}
	prev := ""
	if previous != nil {
		prev = *previous
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "grant.set", t.id+" "+r.PathValue("project"), audit.Success,
		map[string]any{"level": *req.Level, "previous": prev})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"user_id": t.id, "project": r.PathValue("project"), "level": *req.Level})
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	p, t, projectID, ok := s.grantTarget(ctx, tx, w, r, p)
	if !ok {
		return
	}
	var level string
	err = tx.QueryRow(ctx, `DELETE FROM grants WHERE user_id=$1 AND project_id=$2 RETURNING level`, t.id, projectID).Scan(&level)
	if errors.Is(err, pgx.ErrNoRows) {
		tx.Rollback(ctx)
		s.deny(w, r, p, errNotFound)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "grant.revoke", t.id+" "+r.PathValue("project"), audit.Success,
		map[string]any{"previous": level})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
