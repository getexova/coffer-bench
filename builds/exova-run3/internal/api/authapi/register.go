package authapi

import (
	"net/http"
)

// routeSpec is one route this slice owns. The table exists so the route set has a
// single declaration: Register binds it, and the tests enumerate it to prove that a
// rule holds for every route rather than for the ones someone remembered to list.
type routeSpec struct {
	Method  string
	Pattern string // relative to apiPrefix, e.g. "/members/{user_id}"
	Handler func(*api) http.HandlerFunc
}

// routes is the complete set of routes this slice binds. It is the only place a
// route is declared, so a route cannot exist without appearing here.

// routes is the complete set of routes this slice binds. It is the only place a
// route is declared, so a route cannot exist without appearing here.
func (a *api) routes() []routeSpec {
	return []routeSpec{
		// Authentication and self-service.
		{http.MethodPost, "/auth/token", func(a *api) http.HandlerFunc { return a.handleLogin }},
		{http.MethodPost, "/auth/logout", func(a *api) http.HandlerFunc { return a.handleLogout }},
		{http.MethodPost, "/auth/password", func(a *api) http.HandlerFunc { return a.handlePasswordChange }},
		{http.MethodGet, "/me", func(a *api) http.HandlerFunc { return a.handleMe }},

		// Platform admin: organizations only.
		{http.MethodGet, "/admin/orgs", func(a *api) http.HandlerFunc { return a.handleAdminListOrgs }},
		{http.MethodPost, "/admin/orgs", func(a *api) http.HandlerFunc { return a.handleAdminCreateOrg }},
		{http.MethodPost, "/admin/orgs/{org}/disable", func(a *api) http.HandlerFunc { return a.handleAdminDisableOrg }},

		// Members and grants.
		{http.MethodGet, "/members", func(a *api) http.HandlerFunc { return a.handleListMembers }},
		{http.MethodPost, "/members", func(a *api) http.HandlerFunc { return a.handleCreateMember }},
		{http.MethodPatch, "/members/{user_id}", func(a *api) http.HandlerFunc { return a.handleUpdateMember }},
		{http.MethodDelete, "/members/{user_id}", func(a *api) http.HandlerFunc { return a.handleRemoveMember }},
		{http.MethodPut, "/members/{user_id}/grants/{project}", func(a *api) http.HandlerFunc { return a.handleSetGrant }},
		{http.MethodDelete, "/members/{user_id}/grants/{project}", func(a *api) http.HandlerFunc { return a.handleRevokeGrant }},

		// Projects and environments.
		{http.MethodGet, "/projects", func(a *api) http.HandlerFunc { return a.handleListProjects }},
		{http.MethodPost, "/projects", func(a *api) http.HandlerFunc { return a.handleCreateProject }},
		{http.MethodGet, "/projects/{p}/envs", func(a *api) http.HandlerFunc { return a.handleListEnvs }},
		{http.MethodPost, "/projects/{p}/envs", func(a *api) http.HandlerFunc { return a.handleCreateEnv }},

		// Service tokens.
		{http.MethodGet, "/tokens", func(a *api) http.HandlerFunc { return a.handleListTokens }},
		{http.MethodPost, "/tokens", func(a *api) http.HandlerFunc { return a.handleCreateToken }},
		{http.MethodDelete, "/tokens/{id}", func(a *api) http.HandlerFunc { return a.handleRevokeToken }},
	}
}

// RoutePatterns returns every full route pattern this slice registers, in
// "METHOD /api/v1/..." form. Tests use it to assert a rule across the whole surface.

// RoutePatterns returns every full route pattern this slice registers, in
// "METHOD /api/v1/..." form. Tests use it to assert a rule across the whole surface.
func RoutePatterns() []string {
	a := &api{}
	specs := a.routes()
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		out = append(out, s.Method+" "+apiPrefix+s.Pattern)
	}
	return out
}

// Register binds every route this slice owns onto mux.
//
// Authentication is not done here: reqctx.Authenticator (NewAuthenticator) resolves
// the bearer token once, in middleware, and handlers read reqctx.From. Handlers
// still fail closed — an anonymous actor is a 401 — so a missing middleware is a
// refusal, never an open door.

// Register binds every route this slice owns onto mux.
//
// Authentication is not done here: reqctx.Authenticator (NewAuthenticator) resolves
// the bearer token once, in middleware, and handlers read reqctx.From. Handlers
// still fail closed — an anonymous actor is a 401 — so a missing middleware is a
// refusal, never an open door.
func Register(mux *http.ServeMux, deps Deps) {
	a := &api{Deps: deps, limits: newLimiter()}
	for _, spec := range a.routes() {
		mux.HandleFunc(spec.Method+" "+apiPrefix+spec.Pattern, spec.Handler(a))
	}
}

// RegisterRoutes is an alias kept for a composition root that names the seam
// differently. It binds exactly the same routes.

// RegisterRoutes is an alias kept for a composition root that names the seam
// differently. It binds exactly the same routes.
func RegisterRoutes(mux *http.ServeMux, deps Deps) { Register(mux, deps) }
