package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/coffer-dev/coffer/internal/server/audit"
	"github.com/coffer-dev/coffer/internal/server/crypto"
	"github.com/coffer-dev/coffer/internal/server/db"
)

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ri := info(r)
		ri.handled, ri.route = true, "GET /healthz"
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ri := info(r)
		ri.handled, ri.route = true, "GET /readyz"
		if !s.Ready(r.Context()) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	pub := routeOpts{public: true}
	pw := routeOpts{allowPwRequired: true}
	std := routeOpts{}

	s.handle("POST /auth/token", pub, s.handleLogin)
	s.handle("POST /auth/logout", pw, s.handleLogout)
	s.handle("POST /auth/password", pw, s.handlePassword)
	s.handle("GET /me", pw, s.handleMe)

	s.handle("GET /admin/orgs", std, s.handleAdminListOrgs)
	s.handle("POST /admin/orgs", std, s.handleAdminCreateOrg)
	s.handle("POST /admin/orgs/{org}/disable", std, s.handleAdminDisableOrg)
	s.handle("GET /admin/audit", std, s.handleAdminAudit)
	s.handle("GET /admin/audit/verify", std, s.handleAdminAuditVerify)

	s.handle("GET /members", std, s.handleListMembers)
	s.handle("POST /members", std, s.handleAddMember)
	s.handle("PATCH /members/{user_id}", std, s.handlePatchMember)
	s.handle("DELETE /members/{user_id}", std, s.handleRemoveMember)
	s.handle("PUT /members/{user_id}/grants/{project}", std, s.handleSetGrant)
	s.handle("DELETE /members/{user_id}/grants/{project}", std, s.handleRevokeGrant)

	s.handle("GET /projects", std, s.handleListProjects)
	s.handle("POST /projects", std, s.handleCreateProject)
	s.handle("GET /projects/{p}/envs", std, s.handleListEnvs)
	s.handle("POST /projects/{p}/envs", std, s.handleCreateEnv)

	s.handle("GET /projects/{p}/envs/{e}/secrets", std, s.handleListSecrets)
	s.handle("GET /projects/{p}/envs/{e}/secrets/{key}", std, s.handleGetSecret)
	s.handle("PUT /projects/{p}/envs/{e}/secrets/{key}", std, s.handlePutSecret)
	s.handle("DELETE /projects/{p}/envs/{e}/secrets/{key}", std, s.handleDeleteSecret)
	s.handle("GET /projects/{p}/envs/{e}/secrets/{key}/versions", std, s.handleListVersions)
	s.handle("GET /projects/{p}/envs/{e}/secrets/{key}/versions/{n}", std, s.handleGetVersion)
	s.handle("POST /projects/{p}/envs/{e}/secrets/{key}/rollback", std, s.handleRollback)
	s.handle("GET /projects/{p}/envs/{e}/export", std, s.handleExport)

	s.handle("GET /changes", std, s.handleListChanges)
	s.handle("POST /changes/{id}/approve", std, s.handleApprove)
	s.handle("POST /changes/{id}/reject", std, s.handleReject)

	s.handle("GET /tokens", std, s.handleListTokens)
	s.handle("POST /tokens", std, s.handleCreateToken)
	s.handle("DELETE /tokens/{id}", std, s.handleRevokeToken)

	s.handle("GET /audit", std, s.handleAudit)
	s.handle("GET /audit/verify", std, s.handleAuditVerify)
}

// Ready reports readiness: boot finished, the pool answers within 2 s and
// every embedded migration is recorded in schema_migrations of the database
// currently behind the pool (a database replaced underneath a running server
// is not ready). A positive migration check is cached for one second.
func (s *Server) Ready(ctx context.Context) bool {
	if !s.ready.Load() {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if t, ok := s.migOK.Load().(time.Time); ok && time.Since(t) < time.Second {
		var one int
		return s.pool.QueryRow(ctx, `SELECT 1`).Scan(&one) == nil && one == 1
	}
	ok, err := db.MigrationsApplied(ctx, s.pool)
	if err != nil || !ok {
		return false
	}
	s.migOK.Store(time.Now())
	return true
}

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// ---------------------------------------------------------------- scope

// scope is a resolved project (and optionally environment) the caller can see.
type scope struct {
	orgID       string
	projectID   string
	projectSlug string
	wrappedDEK  []byte
	level       string // member grant level; "" for OA / ST
	envID       string
	envSlug     string
	protected   bool
}

// Operations for permission checks.
type op int

const (
	opMeta  op = iota // list, history
	opRead            // get value, versions/{n}, export
	opWrite           // set, delete, rollback
)

func levelRank(l string) int {
	switch l {
	case "viewer":
		return 1
	case "reader":
		return 2
	case "writer":
		return 3
	}
	return 0
}

// resolveScope implements the mandatory resolution order (CONTRACT §5.3,
// Secrets steps 2–5). envSlug == "" resolves the project only. On failure it
// has already written (and audited) the 404 and returns nil.
func (s *Server) resolveScope(w http.ResponseWriter, r *http.Request, p *Principal, projectSlug, envSlug string) *scope {
	if p.Kind == KindPlatform {
		s.deny(w, r, p, errNotFound)
		return nil
	}
	if !ValidSlug(projectSlug) || (envSlug != "" && !ValidSlug(envSlug)) {
		// Can never exist; also keeps NUL/invalid UTF-8 out of SQL.
		s.deny(w, r, p, errNotFound)
		return nil
	}
	sc := &scope{orgID: p.OrgID}
	var level, envID, envSlugDB *string
	var protected *bool
	err := s.pool.QueryRow(r.Context(), `
		SELECT p.id, p.slug, p.wrapped_dek, g.level, e.id, e.slug, e.protected
		FROM projects p
		LEFT JOIN grants g ON g.project_id = p.id AND g.user_id = $3
		LEFT JOIN environments e ON e.project_id = p.id AND e.slug = $4
		WHERE p.org_id = $1 AND p.slug = $2`,
		p.OrgID, projectSlug, p.UserID, envSlug).Scan(&sc.projectID, &sc.projectSlug, &sc.wrappedDEK, &level, &envID, &envSlugDB, &protected)
	if errors.Is(err, pgx.ErrNoRows) {
		s.deny(w, r, p, errNotFound)
		return nil
	}
	if err != nil {
		s.internalError(w, r, err)
		return nil
	}
	switch {
	case p.Kind == KindService:
		if sc.projectID != p.ProjectID {
			s.deny(w, r, p, errNotFound)
			return nil
		}
	case p.isOA():
	case p.Kind == KindUser && p.Role == "member":
		if level == nil {
			s.deny(w, r, p, errNotFound)
			return nil
		}
		sc.level = *level
	default:
		s.deny(w, r, p, errNotFound)
		return nil
	}
	if envSlug == "" {
		return sc
	}
	if envID == nil {
		s.deny(w, r, p, errNotFound)
		return nil
	}
	if p.Kind == KindService && *envID != p.EnvID {
		s.deny(w, r, p, errNotFound)
		return nil
	}
	sc.envID, sc.envSlug, sc.protected = *envID, *envSlugDB, protected != nil && *protected
	return sc
}

// allowed reports whether p may perform o within sc (step 6).
func allowed(p *Principal, sc *scope, o op) bool {
	switch p.Kind {
	case KindService:
		return o != opWrite || p.Access == "read-write"
	case KindUser:
		if p.isOA() {
			return true
		}
		switch o {
		case opMeta:
			return levelRank(sc.level) >= 1
		case opRead:
			return levelRank(sc.level) >= 2
		case opWrite:
			return levelRank(sc.level) >= 3
		}
	}
	return false
}

// resolveSecretScope runs steps 2–7 for a secret route. key == "" skips key
// validation (collection routes).
func (s *Server) resolveSecretScope(w http.ResponseWriter, r *http.Request, p *Principal, o op, withKey bool) *scope {
	sc := s.resolveScope(w, r, p, r.PathValue("p"), r.PathValue("e"))
	if sc == nil {
		return nil
	}
	if !allowed(p, sc, o) {
		s.deny(w, r, p, errForbidden)
		return nil
	}
	if withKey && !ValidKey(r.PathValue("key")) {
		writeError(w, badRequest("invalid key: must match ^[A-Z_][A-Z0-9_]{0,127}$"))
		return nil
	}
	return sc
}

// dek unwraps the project data key.
func (s *Server) dek(sc *scope) ([]byte, error) {
	return crypto.Open(s.cfg.MasterKey, sc.wrappedDEK, crypto.DEKAAD(sc.orgID, sc.projectID))
}

// ---------------------------------------------------------------- projects

type projectJSON struct {
	ID        string  `json:"id"`
	Slug      string  `json:"slug"`
	CreatedAt string  `json:"created_at"`
	Level     *string `json:"level,omitempty"`
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request, p *Principal) {
	if p.Kind == KindPlatform {
		s.deny(w, r, p, errNotFound)
		return
	}
	if p.Kind != KindUser {
		s.deny(w, r, p, errForbidden)
		return
	}
	var rows pgx.Rows
	var err error
	if p.isOA() {
		rows, err = s.pool.Query(r.Context(), `SELECT id, slug, created_at, NULL::text FROM projects WHERE org_id=$1 ORDER BY slug COLLATE "C"`, p.OrgID)
	} else {
		rows, err = s.pool.Query(r.Context(), `SELECT p.id, p.slug, p.created_at, g.level FROM projects p
			JOIN grants g ON g.project_id=p.id AND g.user_id=$2 WHERE p.org_id=$1 ORDER BY p.slug COLLATE "C"`, p.OrgID, p.UserID)
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer rows.Close()
	out := []projectJSON{}
	for rows.Next() {
		var pj projectJSON
		var created time.Time
		if err := rows.Scan(&pj.ID, &pj.Slug, &created, &pj.Level); err != nil {
			s.internalError(w, r, err)
			return
		}
		pj.CreatedAt = ts(created)
		out = append(out, pj)
	}
	if err := rows.Err(); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type slugReq struct {
	Slug *string `json:"slug"`
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request, p *Principal) {
	if p.Kind == KindPlatform {
		s.deny(w, r, p, errNotFound)
		return
	}
	if !p.isOA() {
		s.deny(w, r, p, errForbidden)
		return
	}
	var req slugReq
	if e := decodeBody(r, &req); e != nil {
		writeError(w, e)
		return
	}
	if req.Slug == nil || !ValidSlug(*req.Slug) {
		writeError(w, badRequest("slug must match ^[a-z0-9][a-z0-9-]{0,62}$"))
		return
	}
	id := crypto.NewID("prj")
	dek := crypto.RandomBytes(32)
	wrapped, err := crypto.Seal(s.cfg.MasterKey, dek, crypto.DEKAAD(p.OrgID, id))
	if err != nil {
		s.internalError(w, r, err)
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
	var created time.Time
	err = tx.QueryRow(ctx, `INSERT INTO projects (id, org_id, slug, wrapped_dek, created_by) VALUES ($1,$2,$3,$4,$5) RETURNING created_at`,
		id, p.OrgID, *req.Slug, wrapped, p.UserID).Scan(&created)
	if isUniqueViolation(err) {
		writeError(w, conflict("a project with this slug already exists"))
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "project.create", *req.Slug, audit.Success, map[string]any{"project_id": id})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, projectJSON{ID: id, Slug: *req.Slug, CreatedAt: ts(created)})
}

type envJSON struct {
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	Protected bool   `json:"protected"`
	CreatedAt string `json:"created_at"`
}

// resolveProjectForEnvRoutes resolves {p} for /projects/{p}/envs. A service
// token gets 403 for its own project and 404 for any other.
func (s *Server) resolveProjectForEnvRoutes(w http.ResponseWriter, r *http.Request, p *Principal) *scope {
	sc := s.resolveScope(w, r, p, r.PathValue("p"), "")
	if sc == nil {
		return nil
	}
	if p.Kind == KindService {
		s.deny(w, r, p, errForbidden)
		return nil
	}
	return sc
}

func (s *Server) handleListEnvs(w http.ResponseWriter, r *http.Request, p *Principal) {
	sc := s.resolveProjectForEnvRoutes(w, r, p)
	if sc == nil {
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT id, slug, protected, created_at FROM environments WHERE project_id=$1 ORDER BY slug COLLATE "C"`, sc.projectID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer rows.Close()
	out := []envJSON{}
	for rows.Next() {
		var e envJSON
		var created time.Time
		if err := rows.Scan(&e.ID, &e.Slug, &e.Protected, &created); err != nil {
			s.internalError(w, r, err)
			return
		}
		e.CreatedAt = ts(created)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type envReq struct {
	Slug      *string `json:"slug"`
	Protected *bool   `json:"protected"`
}

func (s *Server) handleCreateEnv(w http.ResponseWriter, r *http.Request, p *Principal) {
	sc := s.resolveProjectForEnvRoutes(w, r, p)
	if sc == nil {
		return
	}
	if !p.isOA() {
		s.deny(w, r, p, errForbidden)
		return
	}
	var req envReq
	if e := decodeBody(r, &req); e != nil {
		writeError(w, e)
		return
	}
	if req.Slug == nil || !ValidSlug(*req.Slug) {
		writeError(w, badRequest("slug must match ^[a-z0-9][a-z0-9-]{0,62}$"))
		return
	}
	protected := req.Protected != nil && *req.Protected
	id := crypto.NewID("env")
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
	var created time.Time
	err = tx.QueryRow(ctx, `INSERT INTO environments (id, project_id, slug, protected, created_by) VALUES ($1,$2,$3,$4,$5) RETURNING created_at`,
		id, sc.projectID, *req.Slug, protected, p.UserID).Scan(&created)
	if isUniqueViolation(err) {
		writeError(w, conflict("an environment with this slug already exists"))
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := audit.AppendTx(ctx, tx, s.event(r, p, "env.create", sc.projectSlug+"/"+*req.Slug, audit.Success,
		map[string]any{"env_id": id, "protected": protected})); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, envJSON{ID: id, Slug: *req.Slug, Protected: protected, CreatedAt: ts(created)})
}
