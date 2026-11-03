package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/coffer-dev/coffer/internal/server/audit"
	"github.com/coffer-dev/coffer/internal/server/crypto"
)

type tokenJSON struct {
	ID         string  `json:"id"`
	Name       *string `json:"name"`
	Project    string  `json:"project"`
	Env        string  `json:"env"`
	Access     string  `json:"access"`
	CreatedAt  string  `json:"created_at"`
	ExpiresAt  string  `json:"expires_at"`
	RevokedAt  *string `json:"revoked_at"`
	CreatedBy  *string `json:"created_by"`
	LastUsedAt *string `json:"last_used_at"`
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT t.id, t.name, p.slug, e.slug, t.access, t.created_at, t.expires_at, t.revoked_at, t.created_by, t.last_used_at
		FROM tokens t JOIN projects p ON p.id=t.project_id JOIN environments e ON e.id=t.env_id
		WHERE t.org_id=$1 AND t.kind='service' ORDER BY t.created_at DESC, t.id`, p.OrgID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer rows.Close()
	out := []tokenJSON{}
	for rows.Next() {
		var t tokenJSON
		var created, expires time.Time
		var revoked, last *time.Time
		if err := rows.Scan(&t.ID, &t.Name, &t.Project, &t.Env, &t.Access, &created, &expires, &revoked, &t.CreatedBy, &last); err != nil {
			s.internalError(w, r, err)
			return
		}
		t.CreatedAt, t.ExpiresAt, t.RevokedAt, t.LastUsedAt = ts(created), ts(expires), tsPtr(revoked), tsPtr(last)
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type createTokenReq struct {
	Project    *string          `json:"project"`
	Env        *string          `json:"env"`
	Access     *string          `json:"access"`
	TTLSeconds *json.RawMessage `json:"ttl_seconds"`
	Name       *string          `json:"name"`
}

const (
	minTTL = 60
	maxTTL = 90 * 24 * 3600
)

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	var req createTokenReq
	if e := decodeBody(r, &req); e != nil {
		writeError(w, e)
		return
	}
	if req.Project == nil || req.Env == nil {
		writeError(w, badRequest("project and env are required"))
		return
	}
	if req.Access == nil || (*req.Access != "read" && *req.Access != "read-write") {
		writeError(w, badRequest("access must be read or read-write"))
		return
	}
	if req.TTLSeconds == nil {
		writeError(w, badRequest("ttl_seconds is required"))
		return
	}
	ttl, ok := parseJSONInt(*req.TTLSeconds)
	if !ok || ttl < minTTL || ttl > maxTTL {
		writeError(w, badRequest("ttl_seconds must be an integer between 60 and 7776000"))
		return
	}
	var name *string
	if req.Name != nil && *req.Name != "" {
		if utf8.RuneCountInString(*req.Name) > 100 || !utf8.ValidString(*req.Name) {
			writeError(w, badRequest("name must be at most 100 characters"))
			return
		}
		for _, c := range *req.Name {
			if c < 0x20 || c == 0x7f {
				writeError(w, badRequest("name must not contain control characters"))
				return
			}
		}
		name = req.Name
	}
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if p = s.relockOA(ctx, tx, w, r, p, orgShare); p == nil {
		return
	}
	var projectID, envID string
	err = pgx.ErrNoRows
	if ValidSlug(*req.Project) && ValidSlug(*req.Env) {
		err = tx.QueryRow(ctx, `SELECT p.id, e.id FROM projects p JOIN environments e ON e.project_id=p.id
		WHERE p.org_id=$1 AND p.slug=$2 AND e.slug=$3`, p.OrgID, *req.Project, *req.Env).Scan(&projectID, &envID)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		tx.Rollback(ctx)
		s.deny(w, r, p, errNotFound)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	tok := crypto.NewToken(crypto.ServicePrefix)
	id := crypto.NewID("tok")
	var expires time.Time
	if err := tx.QueryRow(ctx, `INSERT INTO tokens (id, kind, token_hash, org_id, user_id, created_by, project_id, env_id, access, name, expires_at)
		VALUES ($1,'service',$2,$3,NULL,$4,$5,$6,$7,$8, now() + make_interval(secs => $9)) RETURNING expires_at`,
		id, crypto.TokenHash(tok), p.OrgID, p.UserID, projectID, envID, *req.Access, name, float64(ttl)).Scan(&expires); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "token.issue", id, audit.Success, map[string]any{
		"project": *req.Project, "env": *req.Env, "access": *req.Access, "ttl_seconds": ttl})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "token": tok, "name": name, "project": *req.Project, "env": *req.Env, "access": *req.Access,
		"expires_at": ts(expires),
	})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	id := r.PathValue("id")
	if !validID(id) {
		s.deny(w, r, p, errNotFound)
		return
	}
	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if p = s.relockOA(ctx, tx, w, r, p, orgShare); p == nil {
		return
	}
	var already bool
	err = tx.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM tokens WHERE id=$1 AND org_id=$2 AND kind='service' FOR UPDATE`, id, p.OrgID).Scan(&already)
	if errors.Is(err, pgx.ErrNoRows) {
		tx.Rollback(ctx)
		s.deny(w, r, p, errNotFound)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !already {
		if _, err := tx.Exec(ctx, `UPDATE tokens SET revoked_at=now() WHERE id=$1`, id); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "token.revoke", id, audit.Success, map[string]any{"already_revoked": already})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
