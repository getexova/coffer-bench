package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"coffer/internal/audit"
	"coffer/internal/reqctx"
)

// fixedResolver is a reqctx.ActorResolver returning a fixed gated actor, standing in
// for the real authenticator's answer for a user who has not changed their password.
type fixedResolver struct {
	actor      reqctx.Actor
	mustChange bool
}

func (f fixedResolver) Resolve(context.Context, string) (reqctx.Actor, bool, error) {
	return f.actor, f.mustChange, nil
}

func (f fixedResolver) Authenticate(context.Context, string) (reqctx.Actor, error) {
	return f.actor, nil
}

// ungatedProbe is a route whose handler has NO must-change gate of its own. It exists
// so this test can prove the rule is enforced by the middleware alone.
//
// Every real slice handler calls its own gate first (auditapi's a.gate, secretsapi's
// gateMustChangePassword, authapi's requireActor), which means the central gate is
// currently masked: removing it from withAuth would not fail any test that goes
// through a real handler. That is exactly the single-point-of-failure the CTO asked
// for an alarm on, so this test drives a handler with no local gate.
func ungatedProbe() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/ungated-probe", func(w http.ResponseWriter, r *http.Request) {
		// Reached only if the middleware let the request through.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"reached":true}`))
	})
	return mux
}

// TestCentralGateIsEnforcedWithoutHandlerCooperation is the alarm the CTO asked for:
// it fails if withAuth stops setting the flag, because the handler behind it does not
// defend itself.
func TestCentralGateIsEnforcedWithoutHandlerCooperation(t *testing.T) {
	gated := fixedResolver{
		actor:      reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_gated", TokenID: "pat_1", OrgID: "org_1", Role: reqctx.RoleOwner},
		mustChange: true,
	}

	// Build the middleware chain the router installs, around a handler with no gate.
	probe := ungatedProbe()
	handler := chain(probe,
		withRoutePattern(probe),
		withRequestLog(testLogger()),
		withRecover(testLogger()),
		withSourceIP(false),
		withAuth(gated, nil),
		withDenialFlush(audit.NopWriter(), testLogger()),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ungated-probe", nil)
	req.Header.Set("Authorization", "Bearer cof_pat_whatever")
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("the ungated handler was reached by a gated user; withAuth is not enforcing the rule: %s", rec.Body)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	var env errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("body is not the envelope: %v", err)
	}
	if env.Error.Code != CodePasswordChangeRequired {
		t.Errorf("code = %q, want %q", env.Error.Code, CodePasswordChangeRequired)
	}
}

// TestCentralGateLetsAClearedUserThrough pins the other direction, so the test above
// cannot pass by refusing everyone.
func TestCentralGateLetsAClearedUserThrough(t *testing.T) {
	cleared := fixedResolver{
		actor:      reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_ok", TokenID: "pat_2", OrgID: "org_1", Role: reqctx.RoleOwner},
		mustChange: false,
	}

	probe := ungatedProbe()
	handler := chain(probe,
		withRoutePattern(probe),
		withRequestLog(testLogger()),
		withRecover(testLogger()),
		withSourceIP(false),
		withAuth(cleared, nil),
		withDenialFlush(audit.NopWriter(), testLogger()),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ungated-probe", nil)
	req.Header.Set("Authorization", "Bearer cof_pat_whatever")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a user who changed their password was refused: %d %s", rec.Code, rec.Body)
	}
}

// TestCentralGateExemptsPasswordChangeAndLogout pins that a gated user can still reach
// the two routes that let them out of the gate, without any handler cooperation.
func TestCentralGateExemptsPasswordChangeAndLogout(t *testing.T) {
	gated := fixedResolver{
		actor:      reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_gated", TokenID: "pat_1", OrgID: "org_1", Role: reqctx.RoleOwner},
		mustChange: true,
	}

	for _, path := range []string{"/api/v1/auth/password", "/api/v1/auth/logout"} {
		mux := http.NewServeMux()
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		handler := chain(mux,
			withRoutePattern(mux),
			withRequestLog(testLogger()),
			withRecover(testLogger()),
			withSourceIP(false),
			withAuth(gated, nil),
			withDenialFlush(audit.NopWriter(), testLogger()),
		)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer cof_pat_whatever")
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200 (a gated user must be able to escape the gate): %s", path, rec.Code, rec.Body)
		}
	}
}

// TestCentralGatePopulatesTheContextFlag pins the OTHER half of the fix, the one the
// slices actually consume.
//
// The refusal above is enforced by withAuth's own local variable, so it would keep
// working even if the context were never populated. What auditapi and secretsapi read
// is reqctx.MustChangePasswordFrom, so if withAuth stops setting it, their gates
// silently pass every request. This test reaches a handler that records what the
// context said, which is the only way to catch that regression.
func TestCentralGatePopulatesTheContextFlag(t *testing.T) {
	gated := fixedResolver{
		actor:      reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_gated", TokenID: "pat_1", OrgID: "org_1", Role: reqctx.RoleOwner},
		mustChange: true,
	}

	// The probe sits on an exempt route so the gate lets it through and the handler
	// runs; that is what makes the context observable.
	var sawFlag bool
	var sawActor reqctx.Actor
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/password", func(w http.ResponseWriter, r *http.Request) {
		sawFlag = reqctx.MustChangePasswordFrom(r.Context())
		sawActor = reqctx.From(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := chain(mux,
		withRoutePattern(mux),
		withRequestLog(testLogger()),
		withRecover(testLogger()),
		withSourceIP(false),
		withAuth(gated, nil),
		withDenialFlush(audit.NopWriter(), testLogger()),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password", nil)
	req.Header.Set("Authorization", "Bearer cof_pat_whatever")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("the exempt route was refused: %d %s", rec.Code, rec.Body)
	}
	if !sawFlag {
		t.Fatal("reqctx.MustChangePasswordFrom was false inside the handler for a gated user; withAuth did not populate the context and every slice gate will pass")
	}
	if sawActor.UserID != "usr_gated" {
		t.Fatalf("the actor did not reach the handler: %+v", sawActor)
	}
}

// TestCentralGateClearsTheContextFlagForAClearedUser pins that the context says false
// for a user who has already changed their password, so a slice gate does not refuse
// everyone.
func TestCentralGateClearsTheContextFlagForAClearedUser(t *testing.T) {
	cleared := fixedResolver{
		actor:      reqctx.Actor{Kind: reqctx.KindUser, UserID: "usr_ok", TokenID: "pat_2", OrgID: "org_1", Role: reqctx.RoleOwner},
		mustChange: false,
	}

	var sawFlag = true
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/password", func(w http.ResponseWriter, r *http.Request) {
		sawFlag = reqctx.MustChangePasswordFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := chain(mux,
		withRoutePattern(mux),
		withRequestLog(testLogger()),
		withRecover(testLogger()),
		withSourceIP(false),
		withAuth(cleared, nil),
		withDenialFlush(audit.NopWriter(), testLogger()),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password", nil)
	req.Header.Set("Authorization", "Bearer cof_pat_whatever")
	handler.ServeHTTP(rec, req)

	if sawFlag {
		t.Fatal("the context flag was set for a user who had already changed their password")
	}
}
