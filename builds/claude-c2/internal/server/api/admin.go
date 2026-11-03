package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/coffer-dev/coffer/internal/server/audit"
	"github.com/coffer-dev/coffer/internal/server/config"
	"github.com/coffer-dev/coffer/internal/server/crypto"
)

type orgJSON struct {
	ID        string          `json:"id"`
	Slug      string          `json:"slug"`
	Disabled  bool            `json:"disabled"`
	CreatedAt string          `json:"created_at"`
	Owner     *memberJSONLite `json:"owner,omitempty"`
}

type memberJSONLite struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// platformOnly: everyone but the platform admin gets 404 (audited).
func (s *Server) platformOnly(w http.ResponseWriter, r *http.Request, p *Principal) bool {
	if p.Kind != KindPlatform {
		s.deny(w, r, p, errNotFound)
		return false
	}
	return true
}

func (s *Server) handleAdminListOrgs(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.platformOnly(w, r, p) {
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT id, slug, disabled, created_at FROM orgs ORDER BY slug COLLATE "C"`)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer rows.Close()
	out := []orgJSON{}
	for rows.Next() {
		var o orgJSON
		var created time.Time
		if err := rows.Scan(&o.ID, &o.Slug, &o.Disabled, &created); err != nil {
			s.internalError(w, r, err)
			return
		}
		o.CreatedAt = ts(created)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type createOrgReq struct {
	Slug          *string `json:"slug"`
	OwnerEmail    *string `json:"owner_email"`
	OwnerPassword *string `json:"owner_password"`
}

func (s *Server) handleAdminCreateOrg(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.platformOnly(w, r, p) {
		return
	}
	var req createOrgReq
	if e := decodeBody(r, &req); e != nil {
		writeError(w, e)
		return
	}
	if req.Slug == nil || req.OwnerEmail == nil || req.OwnerPassword == nil {
		writeError(w, badRequest("slug, owner_email and owner_password are required"))
		return
	}
	if !ValidSlug(*req.Slug) {
		writeError(w, badRequest("slug must match ^[a-z0-9][a-z0-9-]{0,62}$"))
		return
	}
	norm, ok := config.NormalizeEmail(*req.OwnerEmail)
	if !ok {
		writeError(w, badRequest("invalid owner_email"))
		return
	}
	if err := config.CheckPassword(*req.OwnerPassword); err != nil {
		writeError(w, badRequest(err.Error()))
		return
	}
	ctx := r.Context()
	var slugTaken, emailTaken bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM orgs WHERE slug=$1), EXISTS (SELECT 1 FROM users WHERE email_norm=$2)`,
		*req.Slug, norm).Scan(&slugTaken, &emailTaken); err != nil {
		s.internalError(w, r, err)
		return
	}
	if slugTaken {
		writeError(w, conflict("an organization with this slug already exists"))
		return
	}
	if emailTaken {
		writeError(w, conflict("email already in use"))
		return
	}
	hash, err := s.hasher.Hash(ctx, *req.OwnerPassword)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	orgID := crypto.NewID("org")
	ownerID := crypto.NewID("usr")
	email := trimEmail(*req.OwnerEmail)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var created time.Time
	err = tx.QueryRow(ctx, `INSERT INTO orgs (id, slug) VALUES ($1,$2) RETURNING created_at`, orgID, *req.Slug).Scan(&created)
	if isUniqueViolation(err) {
		writeError(w, conflict("an organization with this slug already exists"))
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	_, err = tx.Exec(ctx, `INSERT INTO users (id, org_id, email, email_norm, password_hash, role, must_change_password)
		VALUES ($1,$2,$3,$4,$5,'owner',true)`, ownerID, orgID, email, norm, hash)
	if isUniqueViolation(err) {
		writeError(w, conflict("email already in use"))
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	details := map[string]any{"org_id": orgID, "slug": *req.Slug, "owner_id": ownerID}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "org.create", orgID, audit.Success, details)); err != nil {
		s.internalError(w, r, err)
		return
	}
	genesis := s.event(r, p, "org.create", orgID, audit.Success, details)
	genesis.Chain, genesis.OrgID = orgID, orgID
	if err := audit.AppendTx(ctx, tx, genesis); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, orgJSON{ID: orgID, Slug: *req.Slug, Disabled: false, CreatedAt: ts(created),
		Owner: &memberJSONLite{ID: ownerID, Email: email, Role: "owner"}})
}

func (s *Server) handleAdminDisableOrg(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.platformOnly(w, r, p) {
		return
	}
	if !ValidSlug(r.PathValue("org")) {
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
	var o orgJSON
	var created time.Time
	var wasDisabled bool
	err = tx.QueryRow(ctx, `SELECT id, slug, disabled, created_at FROM orgs WHERE slug=$1 FOR UPDATE`, r.PathValue("org")).
		Scan(&o.ID, &o.Slug, &wasDisabled, &created)
	if errors.Is(err, pgx.ErrNoRows) {
		tx.Rollback(ctx)
		s.deny(w, r, p, errNotFound)
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !wasDisabled {
		if _, err := tx.Exec(ctx, `UPDATE orgs SET disabled=true, disabled_at=now() WHERE id=$1`, o.ID); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "org.disable", o.ID, audit.Success,
		map[string]any{"slug": o.Slug, "already_disabled": wasDisabled})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	o.Disabled, o.CreatedAt = true, ts(created)
	writeJSON(w, http.StatusOK, o)
}

// ---------------------------------------------------------------- audit

type auditJSON struct {
	Seq      int64          `json:"seq"`
	TS       string         `json:"ts"`
	Actor    auditActor     `json:"actor"`
	Action   string         `json:"action"`
	Target   string         `json:"target"`
	SourceIP string         `json:"source_ip"`
	Result   string         `json:"result"`
	Details  map[string]any `json:"details"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

type auditActor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func parseLimit(r *http.Request) (int, *apiError) {
	q := r.URL.Query()
	if !q.Has("limit") {
		return 100, nil
	}
	n, err := strconv.Atoi(q.Get("limit"))
	if err != nil || n < 1 || n > 1000 {
		return 0, badRequest("limit must be an integer between 1 and 1000")
	}
	return n, nil
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request, chain string, f audit.ListFilter) {
	events, err := audit.List(r.Context(), s.pool, chain, f)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	out := make([]auditJSON, 0, len(events))
	for _, e := range events {
		out = append(out, auditJSON{Seq: e.Seq, TS: ts(e.TS), Actor: auditActor{Type: e.ActorType, ID: e.ActorID},
			Action: e.Action, Target: e.Target, SourceIP: e.SourceIP, Result: e.Result, Details: e.Details,
			PrevHash: e.PrevHash, Hash: e.Hash})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request, chain string) {
	res, err := audit.Verify(r.Context(), func(ctx context.Context) (pgx.Tx, error) {
		return s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	}, chain)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.platformOnly(w, r, p) {
		return
	}
	limit, e := parseLimit(r)
	if e != nil {
		writeError(w, e)
		return
	}
	s.listAudit(w, r, audit.PlatformChain, audit.ListFilter{Limit: limit})
}

func (s *Server) handleAdminAuditVerify(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.platformOnly(w, r, p) {
		return
	}
	s.verifyAudit(w, r, audit.PlatformChain)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	limit, e := parseLimit(r)
	if e != nil {
		writeError(w, e)
		return
	}
	q := r.URL.Query()
	f := audit.ListFilter{Actor: audit.Sanitize(q.Get("actor")), Action: audit.Sanitize(q.Get("action")), Limit: limit}
	if q.Has("since") {
		t, err := time.Parse(time.RFC3339Nano, q.Get("since"))
		if err != nil {
			writeError(w, badRequest("since must be an RFC 3339 timestamp"))
			return
		}
		f.Since = &t
	}
	s.listAudit(w, r, p.OrgID, f)
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.orgAdminOnly(w, r, p) {
		return
	}
	s.verifyAudit(w, r, p.OrgID)
}
