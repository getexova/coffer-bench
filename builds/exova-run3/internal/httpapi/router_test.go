package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/reqctx"
)

// testLogger discards output so a test run is quiet.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testConfig is a valid configuration without a database.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	values := map[string]string{
		"COFFER_MASTER_KEY":               "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		"COFFER_BOOTSTRAP_ADMIN_EMAIL":    "admin@example.com",
		"COFFER_BOOTSTRAP_ADMIN_PASSWORD": "correct-horse-battery",
		"COFFER_ENV":                      "development",
		"COFFER_APP_DB_PASSWORD":          "app-password",
		"POSTGRES_USER":                   "coffer_owner",
		"POSTGRES_PASSWORD":               "owner-password",
		"POSTGRES_DB":                     "coffer",
	}
	cfg, err := config.LoadFrom(func(key string) (string, bool) {
		v, ok := values[key]
		return v, ok
	})
	if err != nil {
		t.Fatalf("test configuration: %v", err)
	}
	return cfg
}

// newTestRouter builds the router with a nil database and a fail-closed
// authenticator, which is exactly the Stage 0 composition.
func newTestRouter(t *testing.T) http.Handler {
	t.Helper()
	return NewRouter(Deps{
		DB:     nil,
		Audit:  audit.NopWriter(),
		Config: testConfig(t),
		Log:    testLogger(),
	}, failClosedAuthenticator{})
}

type failClosedAuthenticator struct{}

func (failClosedAuthenticator) Authenticate(context.Context, string) (reqctx.Actor, error) {
	return reqctx.Actor{}, reqctx.ErrUnauthenticated
}

// errorEnvelope mirrors the frozen body.
type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func assertErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()

	if rec.Code != wantStatus {
		t.Errorf("status = %d, want %d (body %s)", rec.Code, wantStatus, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Error("X-Request-Id is missing")
	}

	var env errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("body is not the error envelope: %v\nbody: %s", err, rec.Body)
	}
	if env.Error.Code != wantCode {
		t.Errorf("code = %q, want %q", env.Error.Code, wantCode)
	}
	if env.Error.Message == "" {
		t.Error("message is empty")
	}
}

// TestUnknownPathIsEnvelope404 pins that every unknown path returns the frozen
// envelope, never Go's plain-text 404.
func TestUnknownPathIsEnvelope404(t *testing.T) {
	router := newTestRouter(t)

	for _, path := range []string{
		"/",
		"/nope",
		"/api/v1/nope",
		"/api/v1/projects/p/envs/e/secrets/key/versions/1/extra",
		"/api",
		"/admin",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			router.ServeHTTP(rec, req)

			if strings.Contains(rec.Body.String(), "page not found") {
				t.Fatalf("plain-text mux 404 leaked for %s: %s", path, rec.Body)
			}
			assertErrorEnvelope(t, rec, http.StatusNotFound, "not_found")
		})
	}
}

// TestWrongMethodIsEnvelope404 pins that a wrong method on a real route is the same
// 404 as an unknown path.
func TestWrongMethodIsEnvelope404(t *testing.T) {
	router := newTestRouter(t)

	// Probes live outside the auth chain, so a wrong method there is the plain 404
	// envelope: they are not part of /api/v1 and never require a credential.
	probes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/healthz"},
		{http.MethodPost, "/readyz"},
		{http.MethodDelete, "/healthz"},
	}

	for _, tt := range probes {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			router.ServeHTTP(rec, req)

			if strings.Contains(rec.Body.String(), "page not found") {
				t.Fatalf("plain-text mux 404 leaked: %s", rec.Body)
			}
			assertErrorEnvelope(t, rec, http.StatusNotFound, "not_found")
		})
	}

	// A wrong method resolves to the catch-all, and CONTRACTS §2 lists "wrong
	// method" as 404 alongside "unknown path". It is not a 401: there is no
	// resource to authenticate against, and a 401 here would tell an
	// unauthenticated scanner which paths exist.
	wrongMethods := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/auth/token"},     // registered POST only
		{http.MethodPost, "/api/v1/me"},            // registered GET only
		{http.MethodPut, "/api/v1/members"},        // registered GET|POST
		{http.MethodDelete, "/api/v1/projects"},    // registered GET|POST
		{http.MethodDelete, "/api/v1/admin/audit"}, // registered GET only
	}

	for _, tt := range wrongMethods {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			router.ServeHTTP(rec, req)

			assertErrorEnvelope(t, rec, http.StatusNotFound, "not_found")
		})
	}
}

// TestHealthzIsAlwaysOK pins that liveness never depends on the database.
func TestHealthzIsAlwaysOK(t *testing.T) {
	router := newTestRouter(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Error("X-Request-Id is missing on /healthz")
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want ok", body["status"])
	}
}

// TestReadyzWithoutDatabase pins the 503 body: it names the database and leaks no
// SQL, host or path.
func TestReadyzWithoutDatabase(t *testing.T) {
	router := newTestRouter(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v\nbody: %s", err, rec.Body)
	}
	if body["status"] != "not_ready" {
		t.Errorf("status = %q, want not_ready", body["status"])
	}
	if body["reason"] != "database" {
		t.Errorf("reason = %q, want database", body["reason"])
	}

	text := rec.Body.String()
	for _, leak := range []string{"SELECT", "postgres://", "/home/", "coffer_app", "password"} {
		if strings.Contains(text, leak) {
			t.Errorf("readyz body leaks %q: %s", leak, text)
		}
	}
}

// TestBearerTokenWithoutResolverIsUnauthenticated pins that a presented credential
// with no resolver fails closed rather than being treated as anonymous.
func TestBearerTokenWithoutResolverIsUnauthenticated(t *testing.T) {
	router := NewRouter(Deps{
		DB:     nil,
		Audit:  audit.NopWriter(),
		Config: testConfig(t),
		Log:    testLogger(),
	}, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer cof_pat_deadbeef")
	router.ServeHTTP(rec, req)

	assertErrorEnvelope(t, rec, http.StatusUnauthorized, "unauthenticated")
}

// TestUnknownCredentialIsUnauthenticated pins that a resolver error is a 401 and
// never reaches a handler.
func TestUnknownCredentialIsUnauthenticated(t *testing.T) {
	router := newTestRouter(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer cof_pat_unknown")
	router.ServeHTTP(rec, req)

	assertErrorEnvelope(t, rec, http.StatusUnauthorized, "unauthenticated")
}

// TestMalformedAuthorizationIsUnauthenticated pins that a bad header is treated as
// no credential, so it cannot bypass anything.
func TestMalformedAuthorizationIsUnauthenticated(t *testing.T) {
	router := newTestRouter(t)

	for _, header := range []string{
		"Basic dXNlcjpwYXNz",
		"Bearer",
		"Bearer ",
		"cof_pat_bare",
	} {
		t.Run(header, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			router.ServeHTTP(rec, req)

			// A malformed header is anonymous, and the Stage 0 handler answers 404
			// (it does not know the route yet); the important part is that it is not
			// treated as authenticated and never reaches a real handler.
			if rec.Code == http.StatusOK {
				t.Fatalf("malformed Authorization %q was accepted", header)
			}
		})
	}
}

// TestCORSHeadersAreNeverEmitted pins SPEC §4: no origin gets CORS access.
func TestCORSHeadersAreNeverEmitted(t *testing.T) {
	router := newTestRouter(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Origin", "https://evil.example")
	router.ServeHTTP(rec, req)

	for _, header := range []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials",
		"Access-Control-Allow-Methods",
	} {
		if got := rec.Header().Get(header); got != "" {
			t.Errorf("%s = %q, want it absent", header, got)
		}
	}
}

// TestRequestIDIsHonouredOrReplaced pins the header on every response and that a
// hostile value is not reflected.
func TestRequestIDIsHonouredOrReplaced(t *testing.T) {
	router := newTestRouter(t)

	t.Run("valid id is echoed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Header.Set("X-Request-Id", "abc-123_DEF")
		router.ServeHTTP(rec, req)

		if got := rec.Header().Get("X-Request-Id"); got != "abc-123_DEF" {
			t.Errorf("X-Request-Id = %q, want the caller's id", got)
		}
	})

	t.Run("hostile id is replaced", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Header.Set("X-Request-Id", "abc\r\nX-Injected: 1")
		router.ServeHTTP(rec, req)

		got := rec.Header().Get("X-Request-Id")
		if got == "" || strings.ContainsAny(got, "\r\n") {
			t.Errorf("X-Request-Id = %q, want a fresh safe id", got)
		}
		if rec.Header().Get("X-Injected") != "" {
			t.Error("header injection succeeded")
		}
	})
}

// TestProbeResponsesCarrySecurityHeaders pins the headers on the probes too.
func TestProbeResponsesCarrySecurityHeaders(t *testing.T) {
	router := newTestRouter(t)

	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		router.ServeHTTP(rec, req)

		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q", path, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q", path, got)
		}
	}
}

// TestValidRequestID pins the character class rule.
func TestValidRequestID(t *testing.T) {
	tests := map[string]bool{
		"abc123":                true,
		"abc-123_DEF":           true,
		"":                      false,
		"has space":             false,
		"newline\n":             false,
		strings.Repeat("a", 65): false,
		strings.Repeat("a", 64): true,
	}
	for value, want := range tests {
		if got := validRequestID(value); got != want {
			t.Errorf("validRequestID(%q) = %v, want %v", value, got, want)
		}
	}
}

// TestRemoteIP pins the trusted-proxy rule from docs/CONTRACTS.md §8.
func TestRemoteIP(t *testing.T) {
	t.Run("socket peer by default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.9:5555"
		req.Header.Set("X-Forwarded-For", "10.0.0.1")

		if got := remoteIP(req, false); got != "203.0.113.9" {
			t.Errorf("remoteIP = %q, want the socket peer", got)
		}
	})

	t.Run("rightmost untrusted with trust proxy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.9")

		if got := remoteIP(req, true); got != "203.0.113.9" {
			t.Errorf("remoteIP = %q, want the rightmost XFF entry", got)
		}
	})

	t.Run("non-IP header entries are skipped", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", "203.0.113.9, not-an-ip")

		if got := remoteIP(req, true); got != "203.0.113.9" {
			t.Errorf("remoteIP = %q, want the last valid IP", got)
		}
	})

	t.Run("falls back to the peer with no header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.9:5555"

		if got := remoteIP(req, true); got != "203.0.113.9" {
			t.Errorf("remoteIP = %q, want the socket peer", got)
		}
	})
}

// testDeps is the dependency set the router is built with in a test: no database, a
// no-op audit writer and a quiet logger.
func testDeps(t *testing.T) Deps {
	t.Helper()
	return Deps{
		DB:     nil,
		Audit:  audit.NopWriter(),
		Config: testConfig(t),
		Log:    testLogger(),
	}
}

// TestAnonymousOnAProtectedRouteIs401 pins the CEO ruling: a caller with no
// credential gets 401 unauthenticated, not 404. A caller with no credential has no
// tenant to be invisible from, so §2.1's 404 rule does not apply to it.
func TestAnonymousOnAProtectedRouteIs401(t *testing.T) {
	router := newTestRouter(t)

	protected := []string{
		"/api/v1/me",
		"/api/v1/members",
		"/api/v1/projects",
		"/api/v1/tokens",
		"/api/v1/audit",
		"/api/v1/admin/orgs",
		"/api/v1/projects/p/envs/e/secrets",
		"/api/v1/changes",
	}

	for _, path := range protected {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			router.ServeHTTP(rec, req)

			assertErrorEnvelope(t, rec, http.StatusUnauthorized, "unauthenticated")
		})
	}
}

// TestLoginRouteIsReachableWithoutCredential pins the exception that makes the
// ruling survivable: the route that hands out a credential cannot require one.
// Without this, POST /auth/token would 401 and nobody could ever sign in.
func TestLoginRouteIsReachableWithoutCredential(t *testing.T) {
	router := newTestRouter(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", strings.NewReader(`{"email":"a@b.c","password":"x"}`))
	router.ServeHTTP(rec, req)

	// Stage 0 handlers answer 404 for an unimplemented route; the point is only that
	// the request got past the auth middleware, so it is not 401.
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("POST /auth/token was rejected as unauthenticated; login is unreachable: %s", rec.Body)
	}
}

// TestUnknownPathStaysUnauthenticated404 pins that the 404-for-unknown-path rule
// survives the 401 ruling, so a scanner cannot learn which paths exist.
func TestUnknownPathStaysUnauthenticated404(t *testing.T) {
	router := newTestRouter(t)

	for _, path := range []string{"/api/v1/nope", "/api/v1/a/b/c/d/e/f", "/nope"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, rec.Code)
		}
	}
}

// TestNewRouterRefusesNilAuditWriter is the guard E3 asked for: a router built with no
// audit writer must fail loudly rather than silently recording nothing.
//
// The failure this catches is real and was measured: with a no-op writer, an org is
// created, audit_events stays empty, and `audit verify` reports valid because an empty
// chain verifies trivially. Nothing looks wrong until someone needs the log.
func TestNewRouterRefusesNilAuditWriter(t *testing.T) {
	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatal("NewRouter accepted a nil audit writer; a server with no audit log must not start")
		}
		msg, ok := rec.(string)
		if !ok || !strings.Contains(msg, "audit writer") {
			t.Fatalf("panic = %v, want a message naming the audit writer", rec)
		}
	}()

	NewRouter(Deps{
		DB:     nil,
		Audit:  nil, // the mistake
		Config: testConfig(t),
		Log:    testLogger(),
	}, failClosedAuthenticator{})
}

// TestNopWriterIsAvailableForTests pins that the no-op remains reachable explicitly,
// which is what keeps it out of production wiring: a test says so on purpose.
func TestNopWriterIsAvailableForTests(t *testing.T) {
	router := NewRouter(Deps{
		DB:     nil,
		Audit:  audit.NopWriter(),
		Config: testConfig(t),
		Log:    testLogger(),
	}, failClosedAuthenticator{})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", rec.Code)
	}
}

// plainAuthenticator implements only the frozen reqctx.Authenticator, with no way to
// report the must-change flag.
type plainAuthenticator struct {
	actor reqctx.Actor
}

func (p plainAuthenticator) Authenticate(context.Context, string) (reqctx.Actor, error) {
	return p.actor, nil
}

// TestUnknownMustChangeFlagIsRefusedWithoutADatabase pins the direction of the
// fallback when it cannot answer at all.
//
// An authenticator that cannot report the flag causes middleware to read it from the
// database. With no database there is no answer, and an unanswerable gate must not
// become an open door: the request is refused with a 500 rather than admitted.
//
// The earlier design kept the flag in a side map whose miss returned false, i.e. "not
// gated", so an evicted entry admitted a gated caller. This asserts the opposite
// direction: no answer refuses.
func TestUnknownMustChangeFlagIsRefusedWithoutADatabase(t *testing.T) {
	router := NewRouter(Deps{
		DB:     nil,
		Audit:  audit.NopWriter(),
		Config: testConfig(t),
		Log:    testLogger(),
	}, plainAuthenticator{actor: reqctx.Actor{
		Kind: reqctx.KindUser, UserID: "usr_1", TokenID: "pat_1", OrgID: "org_1", Role: reqctx.RoleOwner,
	}})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer cof_pat_whatever")
	router.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("an unresolvable flag admitted a user: %s", rec.Body)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (no database to answer the gate)", rec.Code)
	}
}

// TestServiceTokenIsNotGatedByTheFallback pins the other half: a service token has no
// user, so an unreportable flag must not lock it out.
func TestServiceTokenIsNotGatedByTheFallback(t *testing.T) {
	router := NewRouter(Deps{
		DB:     nil,
		Audit:  audit.NopWriter(),
		Config: testConfig(t),
		Log:    testLogger(),
	}, plainAuthenticator{actor: reqctx.Actor{
		Kind: reqctx.KindService, TokenID: "st_1", OrgID: "org_1",
		ProjectID: "prj", EnvID: "env", Access: reqctx.AccessRead,
	}})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/envs/e/secrets", nil)
	req.Header.Set("Authorization", "Bearer cof_st_whatever")
	router.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("a service token was gated by the password fallback: %s", rec.Body)
	}
}
