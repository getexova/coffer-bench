package authapi

import (
	"errors"

	"net/http"

	"coffer/internal/audit"
	"coffer/internal/httpx"
	"coffer/internal/idgen"
	authstore "coffer/internal/store/auth"
)

type serviceTokenView struct {
	ID          string  `json:"id"`
	Project     string  `json:"project"`
	Env         string  `json:"env"`
	Access      string  `json:"access"`
	Name        string  `json:"name,omitempty"`
	CreatedAt   string  `json:"created_at"`
	ExpiresAt   string  `json:"expires_at"`
	RevokedAt   *string `json:"revoked_at"`
	ProjectID   string  `json:"project_id"`
	Environment string  `json:"environment_id"`
}

// timeString renders a timestamp in the canonical audit form, which is also the
// form the CLI parses. UTC, microseconds, always present.

// handleListTokens implements GET /api/v1/tokens.
//
// Only service tokens are listed. A personal access token is a session credential:
// listing them would turn this route into a way to enumerate a colleague's sessions,
// and the CLI never needs it.
func (a *api) handleListTokens(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "tokens")
	if !ok {
		return
	}
	if !a.requireManager(w, r, actor, "tokens") {
		return
	}
	if !a.gate(w, r) {
		return
	}
	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	tokens, err := authstore.ListServiceTokens(r.Context(), conn, actor.OrgID)
	if err != nil {
		a.logger().Error("tokens: list", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	out := make([]map[string]any, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, map[string]any{
			"id":             t.ID,
			"project":        t.ProjectSlug,
			"env":            t.EnvSlug,
			"project_id":     t.ProjectID,
			"environment_id": t.EnvID,
			"access":         t.Access,
			"name":           t.Name,
			"created_at":     timeString(t.CreatedAt),
			"expires_at":     timeString(t.ExpiresAt),
			"revoked_at":     timeStringPtr(t.RevokedAt),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

// handleCreateToken implements POST /api/v1/tokens {project, env, access, ttl_seconds, name?}.
//
// The issued credential is a cof_st_ service token scoped to exactly one project and
// one environment, with an access level and an expiry that is always present and
// bounded to 1 minute..90 days. The plaintext is returned once and only its SHA-256
// hex is stored.

// handleCreateToken implements POST /api/v1/tokens {project, env, access, ttl_seconds, name?}.
//
// The issued credential is a cof_st_ service token scoped to exactly one project and
// one environment, with an access level and an expiry that is always present and
// bounded to 1 minute..90 days. The plaintext is returned once and only its SHA-256
// hex is stored.
func (a *api) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "tokens")
	if !ok {
		return
	}
	if !a.requireManager(w, r, actor, "tokens") {
		return
	}
	if !a.gate(w, r) {
		return
	}
	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	var req struct {
		Project    string `json:"project"`
		Env        string `json:"env"`
		Access     string `json:"access"`
		TTLSeconds int    `json:"ttl_seconds"`
		Name       string `json:"name"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	// Visibility before validation: an admin issuing a token for a project that is
	// not in their organization must get 404, not a 400 about the payload.
	project, err := authstore.ProjectBySlug(r.Context(), conn, actor.OrgID, req.Project)
	if err != nil {
		if errors.Is(err, authstore.ErrNotFound) {
			a.hide(w, r, "tokens")
			return
		}
		a.logger().Error("tokens: load project", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	env, err := authstore.EnvBySlug(r.Context(), conn, project.ID, req.Env)
	if err != nil {
		if errors.Is(err, authstore.ErrNotFound) {
			a.hide(w, r, "tokens")
			return
		}
		a.logger().Error("tokens: load environment", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	if err := validateAccess(req.Access); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}
	if err := validateTTL(req.TTLSeconds); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}
	if err := validateTokenName(req.Name); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}

	token := idgen.Secret(idgen.PrefixService)
	record := authstore.ServiceToken{
		ID:        idgen.New("tok_"),
		OrgID:     actor.OrgID,
		ProjectID: project.ID,
		EnvID:     env.ID,
		Access:    req.Access,
		Name:      req.Name,
		CreatedBy: actor.UserID,
	}

	tx, err := conn.Begin(r.Context())
	if err != nil {
		a.logger().Error("tokens: begin transaction", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	stored, err := authstore.CreateServiceToken(r.Context(), tx, record, req.TTLSeconds, authstore.HashToken(token))
	if err != nil {
		a.logger().Error("tokens: create", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	ev := a.auditEvent(r.Context(), actor, audit.ActionTokenIssued,
		"token/"+stored.ID+"/project/"+stored.ProjectSlug+"/env/"+stored.EnvSlug, audit.ResultSuccess)
	if err := a.appendAuditTx(r.Context(), tx, ev); err != nil {
		a.logger().Error("tokens: audit token.issued", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		a.logger().Error("tokens: commit", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// The frozen body for this route: the id and the plaintext token, once.
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id":         stored.ID,
		"token":      token,
		"project":    stored.ProjectSlug,
		"env":        stored.EnvSlug,
		"access":     stored.Access,
		"name":       stored.Name,
		"expires_at": timeString(stored.ExpiresAt),
	})
}

// handleRevokeToken implements DELETE /api/v1/tokens/{id}.
//
// Revocation is immediate: the next request made with the token fails, because
// resolution rejects revoked tokens in SQL. Revoking an already-revoked token is
// idempotent — 200 with revoked=false and no second audit event — while an id that
// is not in this organization is the same 404 an unknown id gets.

// handleRevokeToken implements DELETE /api/v1/tokens/{id}.
//
// Revocation is immediate: the next request made with the token fails, because
// resolution rejects revoked tokens in SQL. Revoking an already-revoked token is
// idempotent — 200 with revoked=false and no second audit event — while an id that
// is not in this organization is the same 404 an unknown id gets.
func (a *api) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "tokens")
	if !ok {
		return
	}
	if !a.requireManager(w, r, actor, "tokens") {
		return
	}
	if !a.gate(w, r) {
		return
	}
	conn := a.conn()
	if conn == nil {
		httpx.WriteError(w, r, httpx.Internal(errors.New("no database configured")))
		return
	}

	tx, err := conn.Begin(r.Context())
	if err != nil {
		a.logger().Error("tokens: begin transaction", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	revoked, found, err := authstore.RevokeServiceToken(r.Context(), tx, actor.OrgID, r.PathValue("id"))
	if err != nil {
		a.logger().Error("tokens: revoke", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if !found {
		a.hide(w, r, "tokens")
		return
	}
	if revoked {
		ev := a.auditEvent(r.Context(), actor, audit.ActionTokenRevoked,
			"token/"+r.PathValue("id"), audit.ResultSuccess)
		if err := a.appendAuditTx(r.Context(), tx, ev); err != nil {
			a.logger().Error("tokens: audit token.revoked", "error", err)
			httpx.WriteError(w, r, httpx.Internal(err))
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		a.logger().Error("tokens: commit", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"revoked": revoked})
}
