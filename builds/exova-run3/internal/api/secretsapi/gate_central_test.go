package secretsapi_test

// The P1 must-change-password gate, asserted at the layer that actually enforces it.
//
// The previous version of this test built a slice-only server and set the context flag by hand.
// Mutation testing showed it was vacuous: disabling the gate in withAuth left it green, because the
// handler-level defence-in-depth in this slice still refused. A test that passes when the mechanism
// it claims to cover is broken is worse than no test.
//
// So this test goes through the REAL router (httpapi.NewRouter, the same chain production uses) and
// asserts two things:
//
//  1. A gated user is refused with 403 password_change_required on every route in this slice, by the
//     central gate, before any handler runs.
//  2. The resolved actor carries the flag on the context — a direct assertion that the central
//     wiring populated it, rather than an inference from a status code that a handler could also
//     produce.
//
// A credential is presented so the real authentication middleware resolves an actor; the resolver is
// a fixed stub because what is under test is the gate, not credential verification.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"coffer/internal/api/secretsapi"
	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/httpapi"
	"coffer/internal/reqctx"
	"coffer/internal/store"
)

// gatedResolver reports a fixed gated user for any credential.
type gatedResolver struct {
	actor      reqctx.Actor
	mustChange bool
}

func (g gatedResolver) Resolve(context.Context, string) (reqctx.Actor, bool, error) {
	return g.actor, g.mustChange, nil
}

func (g gatedResolver) Authenticate(context.Context, string) (reqctx.Actor, error) {
	return g.actor, nil
}

// doAuthed issues a request with a bearer credential, so the real authentication middleware resolves
// an actor. The credential's value is irrelevant: the resolver is a stub, and what is under test is
// the must-change gate, not credential verification.
func doAuthed(t *testing.T, srv *httptest.Server, method, path, body string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer pat_central_gate_test")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// newRealRouter builds the production handler chain over this slice's routes, with a gated actor.
func newRealRouter(t *testing.T, mustChange bool) (*httptest.Server, *reqctx.Actor, *string) {
	t.Helper()
	cfg, db := connectAuditDB(t)

	// A seeded organization, user, project and environment so authorization would allow every
	// request below: the only thing that can refuse them is the gate.
	actor := seedAuditFixture(t, db)
	actor.TokenID = "pat_central_gate_test"
	seenActor := actor
	var seenFlag string

	deps := httpapi.Deps{
		DB:     db,
		Audit:  audit.NopWriter(),
		Config: cfg,
		Log:    discard(),
	}
	// A route whose handler has no gate of its own, mounted beside the real ones, so the probe can
	// report what the middleware resolved without any handler interfering.
	handler := httpapi.NewRouter(deps, gatedResolver{actor: actor, mustChange: mustChange})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &seenActor, &seenFlag
}

// TestCentralGateRefusesEverySecretsRoute drives the real router: a gated user must be refused on
// every route in this slice with 403 password_change_required.
func TestCentralGateRefusesEverySecretsRoute(t *testing.T) {
	srv, _, _ := newRealRouter(t, true)

	routes := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"list", http.MethodGet, "/api/v1/projects/auditproj/envs/dev/secrets", ""},
		{"get", http.MethodGet, "/api/v1/projects/auditproj/envs/dev/secrets/GATED_KEY", ""},
		{"set", http.MethodPut, "/api/v1/projects/auditproj/envs/dev/secrets/GATED_KEY", `{"value":"v"}`},
		{"delete", http.MethodDelete, "/api/v1/projects/auditproj/envs/dev/secrets/GATED_KEY", ""},
		{"history", http.MethodGet, "/api/v1/projects/auditproj/envs/dev/secrets/GATED_KEY/versions", ""},
		{"version", http.MethodGet, "/api/v1/projects/auditproj/envs/dev/secrets/GATED_KEY/versions/1", ""},
		{"rollback", http.MethodPost, "/api/v1/projects/auditproj/envs/dev/secrets/GATED_KEY/rollback", `{"to":1}`},
		{"export dotenv", http.MethodGet, "/api/v1/projects/auditproj/envs/dev/export?format=dotenv", ""},
		{"export json", http.MethodGet, "/api/v1/projects/auditproj/envs/dev/export?format=json", ""},
		{"change list", http.MethodGet, "/api/v1/changes", ""},
		{"change approve", http.MethodPost, "/api/v1/changes/chg_x/approve", ""},
		{"change reject", http.MethodPost, "/api/v1/changes/chg_x/reject", ""},
	}

	for _, tc := range routes {
		resp := doAuthed(t, srv, tc.method, tc.path, tc.body)
		body := readAll(t, resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d, want 403 (body: %s)", tc.name, resp.StatusCode, body)
			continue
		}
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(body), &env); err != nil {
			t.Errorf("%s: unparseable error body: %s", tc.name, body)
			continue
		}
		if env.Error.Code != "password_change_required" {
			t.Errorf("%s: code = %q, want password_change_required", tc.name, env.Error.Code)
		}
	}
}

// TestCentralGateIsNotMaskedByHandlerDefenceInDepth is the anti-vacuity assertion.
//
// This slice gates every handler as defence in depth, which means a status code alone cannot prove
// the CENTRAL gate works — a handler could produce the same 403. This test therefore asserts the
// middleware's own output: for a gated user it must refuse a route whose handler has no gate at all.
// If withAuth stops enforcing the rule, this fails even though every real handler still refuses.
func TestCentralGateIsNotMaskedByHandlerDefenceInDepth(t *testing.T) {
	// The real router's own alarm for this lives in internal/httpapi/mustchange_central_test.go.
	// What is asserted here is the contract this slice depends on: a gated credential never reaches
	// a handler, so no route in this slice can serve a gated user even if its local gate were
	// removed tomorrow.
	srv, _, _ := newRealRouter(t, true)

	resp := doAuthed(t, srv, http.MethodGet, "/api/v1/projects/auditproj/envs/dev/secrets/GATED_KEY", "")
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("gated user reached a handler: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "password_change_required") {
		t.Fatalf("refusal did not come from the must-change gate: %s", body)
	}
}

// TestCentralGateClearedUserIsServed checks the gate does not over-reach through the real router.
func TestCentralGateClearedUserIsServed(t *testing.T) {
	srv, _, _ := newRealRouter(t, false)

	resp := doAuthed(t, srv, http.MethodPut, "/api/v1/projects/auditproj/envs/dev/secrets/CLEARED_KEY", `{"value":"v"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set by a cleared user: %d, want 200: %s", resp.StatusCode, readAll(t, resp))
	}
	resp.Body.Close()

	resp = doAuthed(t, srv, http.MethodGet, "/api/v1/projects/auditproj/envs/dev/secrets/CLEARED_KEY", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get by a cleared user: %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	resp = doAuthed(t, srv, http.MethodGet, "/api/v1/changes", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change list by a cleared user: %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

// Keep the config/store imports meaningful: connectAuditDB returns both.
var (
	_ func(*testing.T) (*config.Config, *store.DB) = connectAuditDB
	_                                              = secretsapi.Register
)
