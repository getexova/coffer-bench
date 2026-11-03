package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// frozenRoutes is every route in docs/CONTRACTS.md §4, in "METHOD /path" form.
//
// It is written out by hand rather than derived from the slice packages, so the test
// fails if a slice stops registering a route the contract requires. Deriving it from
// the slices would make the test agree with whatever the slices happen to do, which is
// the failure mode it exists to catch.
var frozenRoutes = []string{
	// authapi
	"POST /api/v1/auth/token",
	"POST /api/v1/auth/logout",
	"POST /api/v1/auth/password",
	"GET /api/v1/me",
	"GET /api/v1/admin/orgs",
	"POST /api/v1/admin/orgs",
	"POST /api/v1/admin/orgs/{org}/disable",
	"GET /api/v1/members",
	"POST /api/v1/members",
	"PATCH /api/v1/members/{user_id}",
	"DELETE /api/v1/members/{user_id}",
	"PUT /api/v1/members/{user_id}/grants/{project}",
	"DELETE /api/v1/members/{user_id}/grants/{project}",
	"GET /api/v1/projects",
	"POST /api/v1/projects",
	"GET /api/v1/projects/{p}/envs",
	"POST /api/v1/projects/{p}/envs",
	"GET /api/v1/tokens",
	"POST /api/v1/tokens",
	"DELETE /api/v1/tokens/{id}",

	// secretsapi
	"GET /api/v1/projects/{p}/envs/{e}/secrets",
	"GET /api/v1/projects/{p}/envs/{e}/secrets/{key}",
	"PUT /api/v1/projects/{p}/envs/{e}/secrets/{key}",
	"DELETE /api/v1/projects/{p}/envs/{e}/secrets/{key}",
	"GET /api/v1/projects/{p}/envs/{e}/secrets/{key}/versions",
	"GET /api/v1/projects/{p}/envs/{e}/secrets/{key}/versions/{n}",
	"POST /api/v1/projects/{p}/envs/{e}/secrets/{key}/rollback",
	"GET /api/v1/projects/{p}/envs/{e}/export",
	"GET /api/v1/changes",
	"POST /api/v1/changes/{id}/approve",
	"POST /api/v1/changes/{id}/reject",

	// auditapi
	"GET /api/v1/audit",
	"GET /api/v1/audit/verify",
	"GET /api/v1/admin/audit",
	"GET /api/v1/admin/audit/verify",

	// probes, outside /api/v1
	"GET /healthz",
	"GET /readyz",
}

// concretePath substitutes a placeholder value for every {param} in a pattern.
func concretePath(pattern string) string {
	var out strings.Builder
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '{' {
			end := strings.IndexByte(pattern[i:], '}')
			if end < 0 {
				out.WriteByte(pattern[i])
				continue
			}
			out.WriteString("x1")
			i += end
			continue
		}
		out.WriteByte(pattern[i])
	}
	return out.String()
}

// TestEveryFrozenRouteIsBound pins that no route from docs/CONTRACTS.md §4 is left
// unregistered. router.go is frozen, so a route that no slice registers is a missing
// feature that would otherwise only surface in the acceptance suite.
//
// A route counts as bound when the mux resolves it to a pattern that is not the
// catch-all. The handler is allowed to answer 404 because it is unimplemented; what
// this test rejects is the catch-all answering, which means nothing is registered.
func TestEveryFrozenRouteIsBound(t *testing.T) {
	deps := testDeps(t)
	apiMux := registerSlices(deps)
	rootMux := newRootMux(deps, apiMux)

	for _, route := range frozenRoutes {
		method, pattern, ok := strings.Cut(route, " ")
		if !ok {
			t.Fatalf("malformed route %q", route)
		}

		path := concretePath(pattern)
		req := httptest.NewRequest(method, path, nil)

		// A probe is registered on the root mux; every API route on the API mux.
		// Resolve each where it actually lives, so this test never passes because a
		// catch-all answered.
		mux := apiMux
		if !strings.HasPrefix(path, "/api/v1/") {
			mux = rootMux
		}
		matched, gotPattern := mux.Handler(req)

		if gotPattern == "" || gotPattern == "/" {
			t.Errorf("%s is not bound: the mux resolved it to the catch-all (%q)", route, gotPattern)
			continue
		}
		// The pattern must carry the method too, so a route cannot be bound to every
		// method by accident.
		if !strings.HasPrefix(gotPattern, method+" ") {
			t.Errorf("%s resolved to %q, which is not method-scoped", route, gotPattern)
		}
		_ = matched
	}
}
