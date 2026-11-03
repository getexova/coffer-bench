package authapi

import (
	"errors"

	"net/http"

	"coffer/internal/audit"
	"coffer/internal/httpx"
	"coffer/internal/idgen"
	"coffer/internal/reqctx"
	authstore "coffer/internal/store/auth"
)

// requirePlatform guards every /admin route. The platform admin manages
// organizations and reads the platform audit log, and nothing else; every other
// principal is refused with 403, because /admin is not an organization-scoped
// route and so has nothing to hide behind a 404.
func (a *api) requirePlatform(w http.ResponseWriter, r *http.Request) (reqctx.Actor, bool) {
	actor, ok := a.requireActor(w, r)
	if !ok {
		return actor, false
	}
	if !actor.IsPlatform() {
		a.deny(w, r, "admin")
		return actor, false
	}
	return actor, true
}

// handleAdminListOrgs implements GET /api/v1/admin/orgs.

// handleAdminListOrgs implements GET /api/v1/admin/orgs.
func (a *api) handleAdminListOrgs(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requirePlatform(w, r); !ok {
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

	orgs, err := authstore.ListOrgs(r.Context(), conn)
	if err != nil {
		a.logger().Error("admin: list organizations", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	out := make([]map[string]any, 0, len(orgs))
	for _, org := range orgs {
		out = append(out, map[string]any{
			"id":          org.ID,
			"slug":        org.Slug,
			"created_at":  timeString(org.CreatedAt),
			"disabled_at": timeStringPtr(org.DisabledAt),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"organizations": out})
}

// handleAdminCreateOrg implements POST /api/v1/admin/orgs.
//
// The organization and its first owner are created in one transaction: an
// organization with no owner would be unreachable, because only an owner can create
// one. The owner's password was chosen by the platform admin, not by the owner, so
// the account starts with must_change_password set — the rule is "gated whenever a
// principal other than the account holder supplies the initial password", applied
// to every call site rather than to a list.

// handleAdminCreateOrg implements POST /api/v1/admin/orgs.
//
// The organization and its first owner are created in one transaction: an
// organization with no owner would be unreachable, because only an owner can create
// one. The owner's password was chosen by the platform admin, not by the owner, so
// the account starts with must_change_password set — the rule is "gated whenever a
// principal other than the account holder supplies the initial password", applied
// to every call site rather than to a list.
func (a *api) handleAdminCreateOrg(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.requirePlatform(w, r)
	if !ok {
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
		Slug          string `json:"slug"`
		OwnerEmail    string `json:"owner_email"`
		OwnerPassword string `json:"owner_password"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	// Authorization is settled (platform admin), so field validation may speak.
	if err := validateSlug("organization", req.Slug); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}
	email := authstore.NormalizeEmail(req.OwnerEmail)
	if err := validateEmail(email); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}
	if err := validatePassword(req.OwnerPassword); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}

	hash, err := HashPassword(req.OwnerPassword)
	if err != nil {
		a.logger().Error("admin: hash owner password", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	tx, err := conn.Begin(r.Context())
	if err != nil {
		a.logger().Error("admin: begin transaction", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	org, err := authstore.CreateOrg(r.Context(), tx, idgen.New("org_"), req.Slug)
	if err != nil {
		if errors.Is(err, authstore.ErrConflict) {
			// Generic: the slug is taken. Nothing about who holds it.
			httpx.WriteError(w, r, httpx.Conflict("that organization slug is already in use"))
			return
		}
		a.logger().Error("admin: create organization", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	owner := authstore.User{
		ID:                 idgen.New("usr_"),
		OrgID:              org.ID,
		Email:              email,
		PasswordHash:       hash,
		Role:               reqctx.RoleOwner,
		MustChangePassword: true,
	}
	createdOwner, err := authstore.CreateUser(r.Context(), tx, owner)
	if err != nil {
		if errors.Is(err, authstore.ErrConflict) {
			// Generic: no organization name, no "already in org X". The
			// transaction rolls back, so no empty organization is left behind.
			httpx.WriteError(w, r, httpx.Conflict("a user with that email already exists"))
			return
		}
		a.logger().Error("admin: create owner", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// The platform admin's own action goes to the platform chain; the creation of
	// the first owner is an organization event and goes to the new organization's
	// chain.
	created := audit.Event{
		Scope:     audit.PlatformScope,
		Timestamp: nowUTC(),
		ActorID:   actorID(actor),
		ActorKind: actorKind(actor),
		Action:    audit.ActionOrganizationCreated,
		Target:    "organization/" + org.Slug,
		SourceIP:  a.sourceIP(r),
		Result:    audit.ResultSuccess,
	}
	if err := a.appendAuditTx(r.Context(), tx, created); err != nil {
		a.logger().Error("admin: audit organization.created", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	added := audit.Event{
		Scope:     org.ID,
		Timestamp: nowUTC(),
		ActorID:   actorID(actor),
		ActorKind: actorKind(actor),
		OrgID:     org.ID,
		Action:    audit.ActionMemberAdded,
		Target:    "user/" + createdOwner.ID,
		SourceIP:  a.sourceIP(r),
		Result:    audit.ResultSuccess,
	}
	if err := a.appendAuditTx(r.Context(), tx, added); err != nil {
		a.logger().Error("admin: audit member.added", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		a.logger().Error("admin: commit", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// The organization is reported both nested (the shape this route documents) and
	// with a top-level id, because internal/testutil's CreateOrg reads the top-level
	// id to identify the organization it just made. Both name the same row.
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id":   org.ID,
		"slug": org.Slug,
		"organization": map[string]any{
			"id":          org.ID,
			"slug":        org.Slug,
			"created_at":  timeString(org.CreatedAt),
			"disabled_at": nil,
		},
		"owner": map[string]any{
			"id":                   createdOwner.ID,
			"email":                createdOwner.Email,
			"role":                 createdOwner.Role,
			"must_change_password": true,
		},
	})
}

// handleAdminDisableOrg implements POST /api/v1/admin/orgs/{org}/disable.
//
// Disabling is a single UPDATE, and it takes effect on the next request because
// token resolution rejects a disabled organization in SQL. A second disable is a
// no-op that still answers 200, so the route is idempotent and cannot be used to
// write duplicate audit rows.

// handleAdminDisableOrg implements POST /api/v1/admin/orgs/{org}/disable.
//
// Disabling is a single UPDATE, and it takes effect on the next request because
// token resolution rejects a disabled organization in SQL. A second disable is a
// no-op that still answers 200, so the route is idempotent and cannot be used to
// write duplicate audit rows.
func (a *api) handleAdminDisableOrg(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.requirePlatform(w, r)
	if !ok {
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

	slug := r.PathValue("org")
	org, err := authstore.OrgBySlug(r.Context(), conn, slug)
	if err != nil {
		if errors.Is(err, authstore.ErrNotFound) {
			httpx.WriteError(w, r, httpx.NotFound("organization not found"))
			return
		}
		a.logger().Error("admin: load organization", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	changed, err := authstore.DisableOrg(r.Context(), conn, org.ID)
	if err != nil {
		a.logger().Error("admin: disable organization", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if changed {
		ev := audit.Event{
			Scope:     audit.PlatformScope,
			Timestamp: nowUTC(),
			ActorID:   actorID(actor),
			ActorKind: actorKind(actor),
			Action:    audit.ActionOrganizationDisabled,
			Target:    "organization/" + org.Slug,
			SourceIP:  a.sourceIP(r),
			Result:    audit.ResultSuccess,
		}
		a.appendAudit(r.Context(), ev)
	}

	// Re-read so the response reports the state the database now holds, including
	// the timestamp set by now().
	if fresh, err := authstore.OrgByID(r.Context(), conn, org.ID); err == nil {
		org = fresh
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"organization": map[string]any{
			"id":          org.ID,
			"slug":        org.Slug,
			"created_at":  timeString(org.CreatedAt),
			"disabled_at": timeStringPtr(org.DisabledAt),
		},
	})
}
