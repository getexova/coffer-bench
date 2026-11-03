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

// handleListProjects implements GET /api/v1/projects.
//
// An owner or admin sees every project in the organization. A member sees only the
// projects they hold a grant on, and a member with no grant gets an empty list
// rather than an error: the response must not reveal that other projects exist
// (SPEC §2.5).
func (a *api) handleListProjects(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "projects")
	if !ok {
		return
	}
	if actor.IsService() {
		// A service token's world is one project and one environment; it may not
		// enumerate the organization's projects (SPEC §2.7).
		a.deny(w, r, "projects")
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

	var (
		projects []authstore.Project
		err      error
	)
	switch actor.Role {
	case reqctx.RoleOwner, reqctx.RoleAdmin:
		projects, err = authstore.ListProjects(r.Context(), conn, actor.OrgID)
	default:
		projects, err = authstore.ListProjectsForMember(r.Context(), conn, actor.OrgID, actor.UserID)
	}
	if err != nil {
		a.logger().Error("projects: list", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	out := make([]map[string]any, 0, len(projects))
	for _, p := range projects {
		out = append(out, map[string]any{
			"id":         p.ID,
			"slug":       p.Slug,
			"created_at": timeString(p.CreatedAt),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"projects": out})
}

// handleCreateProject implements POST /api/v1/projects {slug}.
//
// Admins manage projects (SPEC §2.3), so owners and admins may create one and a
// member may not. A duplicate slug is a 409 for THIS organization only: slugs are
// unique per organization, and a global check would let one tenant learn another
// tenant's project names.

// handleCreateProject implements POST /api/v1/projects {slug}.
//
// Admins manage projects (SPEC §2.3), so owners and admins may create one and a
// member may not. A duplicate slug is a 409 for THIS organization only: slugs are
// unique per organization, and a global check would let one tenant learn another
// tenant's project names.
func (a *api) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "projects")
	if !ok {
		return
	}
	if !a.requireManager(w, r, actor, "projects") {
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
		Slug string `json:"slug"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if err := validateSlug("project", req.Slug); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}

	tx, err := conn.Begin(r.Context())
	if err != nil {
		a.logger().Error("projects: begin transaction", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	project, err := authstore.CreateProject(r.Context(), tx, idgen.New("prj_"), actor.OrgID, req.Slug)
	if err != nil {
		if errors.Is(err, authstore.ErrConflict) {
			httpx.WriteError(w, r, httpx.Conflict("that project slug is already in use in this organization"))
			return
		}
		a.logger().Error("projects: create", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	ev := a.auditEvent(r.Context(), actor, audit.ActionProjectCreated, "project/"+project.Slug, audit.ResultSuccess)
	if err := a.appendAuditTx(r.Context(), tx, ev); err != nil {
		a.logger().Error("projects: audit project.created", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		a.logger().Error("projects: commit", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// Shape: {"project":{id,slug,created_at}}. internal/testutil's NewProject decodes
	// the nested form, and it is the shape this route has answered with since it
	// landed; changing it breaks every peer test that uses the shared harness.
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"project": map[string]any{
			"id":         project.ID,
			"slug":       project.Slug,
			"created_at": timeString(project.CreatedAt),
		},
	})
}

// projectForActor resolves {p} for a caller and answers the invisible-resource 404
// when it is out of reach.
//
// The predicate is "the project is in the caller's organization AND (the caller is
// an owner or admin, OR holds a grant on it)". For a service token it is "the
// project is the one the token is scoped to". All of those are resolved with the
// organization in SQL, so a project in another organization produces exactly the
// same zero rows as a project that does not exist.

// projectForActor resolves {p} for a caller and answers the invisible-resource 404
// when it is out of reach.
//
// The predicate is "the project is in the caller's organization AND (the caller is
// an owner or admin, OR holds a grant on it)". For a service token it is "the
// project is the one the token is scoped to". All of those are resolved with the
// organization in SQL, so a project in another organization produces exactly the
// same zero rows as a project that does not exist.
func (a *api) projectForActor(w http.ResponseWriter, r *http.Request, q authstore.Querier, actor reqctx.Actor, target string) (authstore.Project, bool) {
	slug := r.PathValue("p")

	if actor.IsService() {
		project, err := authstore.ProjectByID(r.Context(), q, actor.OrgID, actor.ProjectID)
		if err != nil {
			if errors.Is(err, authstore.ErrNotFound) {
				a.hide(w, r, target)
				return authstore.Project{}, false
			}
			a.logger().Error("project: load scoped project", "error", err)
			httpx.WriteError(w, r, httpx.Internal(err))
			return authstore.Project{}, false
		}
		if project.Slug != slug {
			// Outside the token's scope: indistinguishable from missing (SPEC §2.1).
			a.hide(w, r, target)
			return authstore.Project{}, false
		}
		return project, true
	}

	switch actor.Role {
	case reqctx.RoleOwner, reqctx.RoleAdmin:
		project, err := authstore.ProjectBySlug(r.Context(), q, actor.OrgID, slug)
		if err != nil {
			if errors.Is(err, authstore.ErrNotFound) {
				a.hide(w, r, target)
				return authstore.Project{}, false
			}
			a.logger().Error("project: load", "error", err)
			httpx.WriteError(w, r, httpx.Internal(err))
			return authstore.Project{}, false
		}
		return project, true
	default:
		// A member needs a grant; the join makes "no grant" and "no project" the
		// same zero-row result.
		project, _, err := authstore.GrantOnSlug(r.Context(), q, actor.OrgID, actor.UserID, slug)
		if err != nil {
			if errors.Is(err, authstore.ErrNotFound) {
				a.hide(w, r, target)
				return authstore.Project{}, false
			}
			a.logger().Error("project: load grant", "error", err)
			httpx.WriteError(w, r, httpx.Internal(err))
			return authstore.Project{}, false
		}
		return project, true
	}
}

// handleListEnvs implements GET /api/v1/projects/{p}/envs.

// handleListEnvs implements GET /api/v1/projects/{p}/envs.
func (a *api) handleListEnvs(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "environments")
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

	project, ok := a.projectForActor(w, r, conn, actor, "environments")
	if !ok {
		return
	}
	if actor.IsService() {
		// Visible inside the scope, but enumerating environments is not a secret
		// operation, so this is a 403 and not a 404.
		a.deny(w, r, "environments")
		return
	}

	envs, err := authstore.ListEnvs(r.Context(), conn, project.ID)
	if err != nil {
		a.logger().Error("envs: list", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	out := make([]map[string]any, 0, len(envs))
	for _, e := range envs {
		out = append(out, map[string]any{
			"id":         e.ID,
			"slug":       e.Slug,
			"protected":  e.Protected,
			"created_at": timeString(e.CreatedAt),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"environments": out})
}

// handleCreateEnv implements POST /api/v1/projects/{p}/envs {slug, protected}.
//
// Visibility is settled first, so a member with a grant on the project gets 403 for
// a route they may not use, while a member with no grant gets the same 404 as a
// missing project.

// handleCreateEnv implements POST /api/v1/projects/{p}/envs {slug, protected}.
//
// Visibility is settled first, so a member with a grant on the project gets 403 for
// a route they may not use, while a member with no grant gets the same 404 as a
// missing project.
func (a *api) handleCreateEnv(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.orgScope(w, r, "environments")
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
		Slug      string `json:"slug"`
		Protected bool   `json:"protected"`
	}

	// Visibility and permission are settled before the body is read, so a plain
	// member gets 404 for a project they cannot see and 403 for one they can, never
	// a 400 that would describe the payload they are not allowed to send.
	project, ok := a.projectForActor(w, r, conn, actor, "environments")
	if !ok {
		return
	}
	if actor.IsService() || (actor.Role != reqctx.RoleOwner && actor.Role != reqctx.RoleAdmin) {
		a.deny(w, r, "environments")
		return
	}

	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if err := validateSlug("environment", req.Slug); err != nil {
		httpx.WriteError(w, r, httpx.Validation(err.Error()))
		return
	}

	tx, err := conn.Begin(r.Context())
	if err != nil {
		a.logger().Error("envs: begin transaction", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	env, err := authstore.CreateEnv(r.Context(), tx, idgen.New("env_"), project.ID, req.Slug, req.Protected)
	if err != nil {
		if errors.Is(err, authstore.ErrConflict) {
			httpx.WriteError(w, r, httpx.Conflict("that environment slug is already in use in this project"))
			return
		}
		a.logger().Error("envs: create", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	ev := a.auditEvent(r.Context(), actor, audit.ActionEnvironmentCreated,
		"project/"+project.Slug+"/env/"+env.Slug, audit.ResultSuccess)
	if err := a.appendAuditTx(r.Context(), tx, ev); err != nil {
		a.logger().Error("envs: audit environment.created", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		a.logger().Error("envs: commit", "error", err)
		httpx.WriteError(w, r, httpx.Internal(err))
		return
	}

	// Shape: flat {"id",slug,protected,created_at}. internal/testutil's NewEnv decodes
	// the top-level form.
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id":         env.ID,
		"slug":       env.Slug,
		"protected":  env.Protected,
		"created_at": timeString(env.CreatedAt),
	})
}

// handleListTokens implements GET /api/v1/tokens.
//
// Only service tokens are listed. A personal access token is a session credential:
// listing them would turn this route into a way to enumerate a colleague's sessions,
// and the CLI never needs it.
