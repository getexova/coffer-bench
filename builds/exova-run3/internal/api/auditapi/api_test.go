package auditapi_test

// Tests for the four audit routes: the authorization matrix, the frozen response
// shapes, and the tamper probe through the HTTP surface.
//
// The router is built here rather than through internal/testutil's full harness,
// because that harness composes every slice's routes and this slice's contract is
// only about its own four. The middleware that matters to these handlers — the
// resolved actor, the source IP and the denial recorder — is installed directly, so a
// test proves the handler's own decision rather than a peer's middleware.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"coffer/internal/api/auditapi"
	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/httpx"
	"coffer/internal/reqctx"
	"coffer/internal/store"
)

const testDSNEnv = "COFFER_TEST_DATABASE_URL"

// harness is a real database, a real Appender and a mux carrying only this slice's
// routes.
type harness struct {
	db       *store.DB
	appender *audit.Appender
	server   *httptest.Server
	owner    *pgx.Conn
	orgID    string
	scope    string
	logs     *syncBuffer
}

// syncBuffer collects the server log so a test can assert that a finding's detail
// goes to the log rather than to the response body.
type syncBuffer struct {
	buf strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) { return s.buf.Write(p) }
func (s *syncBuffer) String() string              { return s.buf.String() }

func newHarness(t *testing.T) *harness {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv(testDSNEnv))
	if dsn == "" {
		t.Skipf("%s is not set; skipping the audit API test (set it to a postgres URL to run)", testDSNEnv)
	}

	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	values := map[string]string{
		"COFFER_MASTER_KEY":               "0J4n1s0XQ2m8bV3kR7pY6tL9wZ2cF5hD8gK1nM4qS0U=",
		"COFFER_BOOTSTRAP_ADMIN_EMAIL":    "platform-admin@auditapi-test.invalid",
		"COFFER_BOOTSTRAP_ADMIN_PASSWORD": "auditapi-test-bootstrap-password",
		"COFFER_ENV":                      config.EnvDevelopment,
		"COFFER_MIGRATION_DATABASE_URL":   dsn,
		"DATABASE_URL":                    dsn,
		"COFFER_ALLOW_DEGRADED_DB_ROLE":   "1",
	}
	cfg, err := config.LoadFrom(func(key string) (string, bool) { v, ok := values[key]; return v, ok })
	if err != nil {
		t.Fatalf("test configuration is invalid: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	db, err := store.Boot(ctx, cfg, log)
	if err != nil {
		t.Fatalf("could not boot the test database: %v", err)
	}
	t.Cleanup(db.Close)

	appender, err := audit.NewAppender(db)
	if err != nil {
		t.Fatalf("could not build the appender: %v", err)
	}

	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("could not open the owner connection: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = owner.Close(closeCtx)
	})

	// A unique organization per harness: the handler reads the caller's OrgID as the
	// chain scope, so a fixed id would let tests that share a database see each other's
	// events and make a count assertion depend on test order.
	orgID := fmt.Sprintf("org_api_%d_%d", os.Getpid(), time.Now().UnixNano())

	mux := http.NewServeMux()
	auditapi.Register(mux, auditapi.Deps{DB: db, Audit: appender, Config: cfg, Log: log})

	// The composition root installs a JSON 404 catch-all for unknown paths inside
	// /api/v1 (internal/httpapi/router.go). Reproduce it here so a test that compares
	// the platform admin's 404 against an unknown path's 404 compares like with like.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteError(w, r, httpx.NotFound("not found"))
	})

	// The middleware the handlers rely on, installed directly: the actor, the source
	// IP, and the denial recorder that the central flush would otherwise consume.
	withActor := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actor := actorFromHeader(r, orgID)
			ctx := reqctx.WithActor(r.Context(), actor)
			// Mirror httpapi.withAuth: the flag is resolved once with the credential
			// and put on the request context, which is the only place this slice's
			// gate reads it from. The central gate itself is proven separately by
			// internal/httpapi/mustchange_central_test.go, against a handler with no
			// local gate; this harness stands in for the middleware, not for the rule.
			// X-Test-MustChange lets a test model the state after POST /auth/password,
			// where the same user now resolves with must_change_password = false.
			actorName := r.Header.Get("X-Test-Actor")
			mustChange := strings.HasSuffix(actorName, "-gated") ||
				strings.Contains(actorName, "-gated-") ||
				actorName == "owner-gated-ctx"
			if v := r.Header.Get("X-Test-MustChange"); v != "" {
				mustChange = v == "true"
			}
			ctx = reqctx.WithMustChangePassword(ctx, mustChange)
			ctx = reqctx.WithSourceIP(ctx, "203.0.113.7")
			ctx = reqctx.WithRecorder(ctx, &reqctx.Recorder{})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	h := &harness{
		db:       db,
		appender: appender,
		server:   httptest.NewServer(withActor(mux)),
		owner:    owner,
		orgID:    orgID,
		scope:    orgID,
		logs:     logs,
	}
	t.Cleanup(h.server.Close)
	return h
}

// actorFromHeader maps the X-Test-Actor header onto a reqctx.Actor. It is the stand-in
// for the auth middleware, which resolves a bearer token; using a header keeps the
// test focused on this slice's authorization decision.
func actorFromHeader(r *http.Request, orgID string) reqctx.Actor {
	switch r.Header.Get("X-Test-Actor") {
	case "owner":
		return reqctx.Actor{Kind: reqctx.KindUser, UserID: "user_owner", OrgID: orgID, Role: reqctx.RoleOwner}
	case "admin":
		return reqctx.Actor{Kind: reqctx.KindUser, UserID: "user_admin", OrgID: orgID, Role: reqctx.RoleAdmin}
	case "member":
		return reqctx.Actor{Kind: reqctx.KindUser, UserID: "user_member", OrgID: orgID, Role: reqctx.RoleMember}
	case "service":
		return reqctx.Actor{Kind: reqctx.KindService, TokenID: "st_1", OrgID: orgID,
			ProjectID: "p1", EnvID: "e1", Access: reqctx.AccessRead}
	case "platform":
		return reqctx.Actor{Kind: reqctx.KindPlatform, UserID: "user_platform", Role: reqctx.RolePlatformAdmin}
	case "owner-gated":
		// A user whose initial password was never changed. The "-gated" suffix makes
		// the middleware stand-in set reqctx.MustChangePassword, which is what
		// httpapi.withAuth does for such a user.
		return reqctx.Actor{Kind: reqctx.KindUser, UserID: "user_gated", OrgID: orgID,
			Role: reqctx.RoleOwner, TokenID: "pat_gated_owner"}
	case "owner-ungated":
		return reqctx.Actor{Kind: reqctx.KindUser, UserID: "user_ungated", OrgID: orgID,
			Role: reqctx.RoleOwner, TokenID: "pat_ungated_owner"}
	case "owner-gated-member":
		return reqctx.Actor{Kind: reqctx.KindUser, UserID: "user_gated_member", OrgID: orgID,
			Role: reqctx.RoleMember, TokenID: "pat_gated_member"}
	case "owner-gated-ctx":
		// The flag is on the context, as authapi.Middleware sets it. No database row
		// exists, so this proves the context path alone refuses.
		return reqctx.Actor{Kind: reqctx.KindUser, UserID: "user_ctx", OrgID: orgID,
			Role: reqctx.RoleOwner, TokenID: "pat_ctx"}
	default:
		return reqctx.Actor{Kind: reqctx.KindAnonymous}
	}
}

// seedUser inserts a real user and personal access token so the must-change gate's
// database fallback has a row to read. The gate queries
// personal_access_tokens JOIN users, so a fake token id would prove nothing.
func (h *harness) seedUser(t *testing.T, userID, tokenID, role string, mustChange bool) {
	t.Helper()
	ctx := context.Background()

	if _, err := h.owner.Exec(ctx,
		`INSERT INTO organizations (id, slug) VALUES ($1, $2)
		 ON CONFLICT (id) DO NOTHING`, h.orgID, "auditapi-"+h.orgID,
	); err != nil {
		t.Fatalf("could not seed the organization: %v", err)
	}
	if _, err := h.owner.Exec(ctx,
		`INSERT INTO users (id, org_id, email, password_hash, role, must_change_password)
		 VALUES ($1, $2, $3, 'x', $4, $5)
		 ON CONFLICT (id) DO UPDATE SET must_change_password = EXCLUDED.must_change_password`,
		userID, h.orgID, userID+"@auditapi.invalid", role, mustChange,
	); err != nil {
		t.Fatalf("could not seed the user: %v", err)
	}
	if _, err := h.owner.Exec(ctx,
		`INSERT INTO personal_access_tokens (id, user_id, token_hash)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (id) DO NOTHING`,
		tokenID, userID, "hash-"+tokenID,
	); err != nil {
		t.Fatalf("could not seed the personal access token: %v", err)
	}
}

// setMustChange flips the flag, which is what POST /auth/password does on success.
func (h *harness) setMustChange(t *testing.T, userID string, must bool) {
	t.Helper()
	if _, err := h.owner.Exec(context.Background(),
		`UPDATE users SET must_change_password = $2 WHERE id = $1`, userID, must,
	); err != nil {
		t.Fatalf("could not update must_change_password: %v", err)
	}
}

// get issues a request as the named actor and returns the response.
func (h *harness) get(t *testing.T, path, asActor string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.server.URL+path, nil)
	if err != nil {
		t.Fatalf("could not build the request: %v", err)
	}
	req.Header.Set("X-Test-Actor", asActor)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (h *harness) getBody(t *testing.T, path, asActor string) (int, []byte) {
	t.Helper()
	return h.getBodyAs(t, path, asActor, nil)
}

// getBodyAs is getBody with extra request headers, used to model the flag's value
// explicitly (e.g. cleared after a password change).
func (h *harness) getBodyAs(t *testing.T, path, asActor string, headers map[string]string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.server.URL+path, nil)
	if err != nil {
		t.Fatalf("could not build the request: %v", err)
	}
	req.Header.Set("X-Test-Actor", asActor)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		t.Fatalf("could not read the response body: %v", err)
	}
	return resp.StatusCode, body
}

// appendEvent writes one event to the harness's scope.
func (h *harness) appendEvent(t *testing.T, target string) audit.Event {
	t.Helper()
	ev, err := h.appender.Append(context.Background(), audit.Event{
		Scope:     h.scope,
		Timestamp: time.Now().UTC(),
		ActorID:   "user_owner",
		ActorKind: audit.ActorUser,
		OrgID:     h.scope,
		Action:    audit.ActionSecretRead,
		Target:    target,
		SourceIP:  "203.0.113.7",
		Result:    audit.ResultSuccess,
	})
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	return ev
}

// TestAuthorizationMatrix pins every caller's status on all four routes. This is the
// table from SPEC §2 rules 6, 7 and 10, and it is the one thing a reviewer checks
// first.
func TestAuthorizationMatrix(t *testing.T) {
	h := newHarness(t)

	h.appendEvent(t, "project/p/env/e/key/SEED")

	cases := []struct {
		path  string
		actor string
		want  int
		why   string
	}{
		// Organization routes.
		{"/api/v1/audit", "anonymous", http.StatusUnauthorized, "no actor to attribute a denial to"},
		{"/api/v1/audit", "owner", http.StatusOK, "owners read the org log"},
		{"/api/v1/audit", "admin", http.StatusOK, "admins read the org log"},
		{"/api/v1/audit", "member", http.StatusForbidden, "a member can see the org but not the log"},
		{"/api/v1/audit", "service", http.StatusForbidden, "a service token can never read the log"},
		{"/api/v1/audit", "platform", http.StatusNotFound, "every org route is invisible to the platform admin"},

		{"/api/v1/audit/verify", "anonymous", http.StatusUnauthorized, "unauthenticated"},
		{"/api/v1/audit/verify", "owner", http.StatusOK, "owners verify the org chain"},
		{"/api/v1/audit/verify", "admin", http.StatusOK, "admins verify the org chain"},
		{"/api/v1/audit/verify", "member", http.StatusForbidden, "a member may not read the log"},
		{"/api/v1/audit/verify", "service", http.StatusForbidden, "a service token may not read the log"},
		{"/api/v1/audit/verify", "platform", http.StatusNotFound, "org routes are invisible to the platform admin"},

		// Platform routes.
		{"/api/v1/admin/audit", "anonymous", http.StatusUnauthorized, "unauthenticated"},
		{"/api/v1/admin/audit", "platform", http.StatusOK, "the platform admin reads the platform log"},
		{"/api/v1/admin/audit", "owner", http.StatusForbidden, "an owner is not the platform admin"},
		{"/api/v1/admin/audit", "admin", http.StatusForbidden, "an admin is not the platform admin"},
		{"/api/v1/admin/audit", "member", http.StatusForbidden, "a member is not the platform admin"},
		{"/api/v1/admin/audit", "service", http.StatusForbidden, "a service token is not the platform admin"},

		{"/api/v1/admin/audit/verify", "anonymous", http.StatusUnauthorized, "unauthenticated"},
		{"/api/v1/admin/audit/verify", "platform", http.StatusOK, "the platform admin verifies the platform chain"},
		{"/api/v1/admin/audit/verify", "owner", http.StatusForbidden, "an owner is not the platform admin"},
		{"/api/v1/admin/audit/verify", "member", http.StatusForbidden, "a member is not the platform admin"},
		{"/api/v1/admin/audit/verify", "service", http.StatusForbidden, "a service token is not the platform admin"},
	}

	for _, tc := range cases {
		t.Run(tc.path+"/"+tc.actor, func(t *testing.T) {
			status, body := h.getBody(t, tc.path, tc.actor)
			if status != tc.want {
				t.Fatalf("GET %s as %s: got %d, want %d (%s); body: %s", tc.path, tc.actor, status, tc.want, tc.why, body)
			}
			// Every response carries the security headers (docs/CONTRACTS.md §2).
			resp := h.get(t, tc.path, tc.actor)
			if got := resp.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type is %q, want application/json", got)
			}
			if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("X-Content-Type-Options is %q, want nosniff", got)
			}
			if got := resp.Header.Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control is %q, want no-store", got)
			}
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
				t.Fatalf("a CORS header was emitted: %q", got)
			}
		})
	}
}

// TestPlatformAdminGetsIdenticalNotFoundBody: the 404 for the platform admin must be
// the same body an unknown path produces, or it reveals that the organization's log
// exists.
func TestPlatformAdminGetsIdenticalNotFoundBody(t *testing.T) {
	h := newHarness(t)

	_, realBody := h.getBody(t, "/api/v1/audit", "platform")
	_, unknownBody := h.getBody(t, "/api/v1/this/route/does/not/exist", "platform")

	if string(realBody) != string(unknownBody) {
		t.Fatalf("the platform admin's 404 differs from an unknown path's 404\n audit: %s\nunknown: %s", realBody, unknownBody)
	}
}

// TestVerifyResponseShapeIsFrozen: the body is exactly the two fields §7.2 fixes, with
// first_invalid_seq null on a valid chain.
func TestVerifyResponseShapeIsFrozen(t *testing.T) {
	h := newHarness(t)
	h.appendEvent(t, "project/p/env/e/key/ONE")

	status, body := h.getBody(t, "/api/v1/audit/verify", "owner")
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", status, body)
	}

	// Decode into a map so an extra field fails the test rather than being ignored.
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the verify body is not JSON: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("the verify body has %d fields, expected exactly 2: %s", len(decoded), body)
	}
	if _, ok := decoded["valid"]; !ok {
		t.Fatalf("the verify body has no valid field: %s", body)
	}
	rawInvalid, ok := decoded["first_invalid_seq"]
	if !ok {
		t.Fatalf("the verify body has no first_invalid_seq field: %s", body)
	}
	if string(rawInvalid) != "null" {
		t.Fatalf("first_invalid_seq is %s on a valid chain, expected null", rawInvalid)
	}
	if want := `{"valid":true,"first_invalid_seq":null}`; string(body) != want {
		t.Fatalf("the verify body is not the frozen shape\n got: %s\nwant: %s", body, want)
	}
}

// TestTamperIsReportedThroughTheAPI is the end-to-end probe the CTO will run: a
// superuser edits one row's target, and GET /audit/verify returns valid:false with
// first_invalid_seq:2.
func TestTamperIsReportedThroughTheAPI(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		h.appendEvent(t, fmt.Sprintf("project/p/env/e/key/K%d", i))
	}

	// Clean first.
	status, body := h.getBody(t, "/api/v1/audit/verify", "owner")
	if status != http.StatusOK {
		t.Fatalf("expected 200 before tampering, got %d: %s", status, body)
	}
	if want := `{"valid":true,"first_invalid_seq":null}`; string(body) != want {
		t.Fatalf("a clean chain did not verify\n got: %s\nwant: %s", body, want)
	}
	if logged := h.logs.String(); !strings.Contains(logged, "event=audit_chain_valid") {
		t.Fatalf("a valid verification did not log the valid marker; log was:\n%s", logged)
	}

	// The tamper, over the owner connection: the runtime role cannot do this.
	if _, err := h.owner.Exec(ctx,
		`UPDATE audit_events SET target = 'x' WHERE scope = $1 AND seq = 2`, h.scope,
	); err != nil {
		t.Fatalf("the superuser tamper did not apply: %v", err)
	}

	status, body = h.getBody(t, "/api/v1/audit/verify", "owner")
	if status != http.StatusOK {
		t.Fatalf("a broken chain must still answer 200, got %d: %s", status, body)
	}
	if want := `{"valid":false,"first_invalid_seq":2}`; string(body) != want {
		t.Fatalf("the tamper was not reported correctly\n got: %s\nwant: %s", body, want)
	}

	// The distinct reason must be in the server log, and NOT in the response body.
	// The log line must be alertable: a stable event marker, the machine-readable
	// finding kind and the numeric sequence, so a rule can match without parsing prose.
	logged := h.logs.String()
	for _, want := range []string{
		"event=audit_chain_invalid",
		"finding=hash_mismatch",
		"first_invalid_seq=2",
		"level=ERROR",
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("the server log is missing %q; log was:\n%s", want, logged)
		}
	}
	if strings.Contains(string(body), "hash_mismatch") || strings.Contains(string(body), "tamper") {
		t.Fatalf("the response body leaks the finding kind: %s", body)
	}
}

// TestVerifyDoesNotWriteThroughTheAPI: verifying must not add an event, which would
// both modify the chain and grow the log on every check.
func TestVerifyDoesNotWriteThroughTheAPI(t *testing.T) {
	h := newHarness(t)
	h.appendEvent(t, "project/p/env/e/key/ONE")

	before := h.countEvents(t)

	for i := 0; i < 3; i++ {
		if status, body := h.getBody(t, "/api/v1/audit/verify", "owner"); status != http.StatusOK {
			t.Fatalf("verify returned %d: %s", status, body)
		}
	}

	if after := h.countEvents(t); after != before {
		t.Fatalf("verification wrote %d events", after-before)
	}
}

func (h *harness) countEvents(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := h.db.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE scope = $1`, h.scope).Scan(&n); err != nil {
		t.Fatalf("could not count events: %v", err)
	}
	return n
}

// TestListReturnsFrozenFieldSet: the response is the wrapped shape the CLI decodes,
// with exactly the frozen fields and no secret value.
func TestListReturnsFrozenFieldSet(t *testing.T) {
	h := newHarness(t)
	h.appendEvent(t, "project/p/env/e/key/API_KEY")

	status, body := h.getBody(t, "/api/v1/audit", "owner")
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", status, body)
	}

	var decoded struct {
		Events []map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the list body is not the wrapped shape: %v\nbody: %s", err, body)
	}
	if len(decoded.Events) == 0 {
		t.Fatalf("the list body holds no events: %s", body)
	}

	want := []string{"seq", "timestamp", "actor", "action", "target", "source_ip", "result", "prev_hash", "hash"}
	got := decoded.Events[0]
	if len(got) != len(want) {
		t.Fatalf("an event has %d fields, expected %d: %s", len(got), len(want), body)
	}
	for _, field := range want {
		if _, ok := got[field]; !ok {
			t.Fatalf("an event is missing the field %q: %s", field, body)
		}
	}

	// The timestamp must be the canonical microsecond form.
	var ts string
	if err := json.Unmarshal(got["timestamp"], &ts); err != nil {
		t.Fatalf("timestamp is not a string: %v", err)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000000Z", ts); err != nil {
		t.Fatalf("timestamp %q is not the canonical layout: %v", ts, err)
	}
}

// TestListQueryParameters: limit, since and the filters behave, and a malformed value
// is a 400 rather than a silently ignored filter.
func TestListQueryParameters(t *testing.T) {
	h := newHarness(t)
	for i := 1; i <= 5; i++ {
		h.appendEvent(t, fmt.Sprintf("project/p/env/e/key/K%d", i))
	}

	count := func(t *testing.T, query string) int {
		t.Helper()
		status, body := h.getBody(t, "/api/v1/audit"+query, "owner")
		if status != http.StatusOK {
			t.Fatalf("GET %s returned %d: %s", query, status, body)
		}
		var decoded struct {
			Events []json.RawMessage `json:"events"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("body is not the wrapped shape: %v", err)
		}
		return len(decoded.Events)
	}

	if got := count(t, ""); got != 5 {
		t.Fatalf("an unfiltered read returned %d events, expected 5", got)
	}
	if got := count(t, "?limit=2"); got != 2 {
		t.Fatalf("limit=2 returned %d events", got)
	}
	if got := count(t, "?limit=100000"); got != 5 {
		t.Fatalf("a limit above the cap returned %d events", got)
	}
	if got := count(t, "?actor=user_owner"); got != 5 {
		t.Fatalf("an actor filter returned %d events, expected 5", got)
	}
	if got := count(t, "?actor=nobody"); got != 0 {
		t.Fatalf("an unmatched actor returned %d events", got)
	}
	if got := count(t, "?action=secret.read"); got != 5 {
		t.Fatalf("an action filter returned %d events, expected 5", got)
	}
	if got := count(t, "?action=not.an.action"); got != 0 {
		t.Fatalf("an unknown action matched %d events", got)
	}
	if got := count(t, "?since="+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); got != 0 {
		t.Fatalf("a future since returned %d events", got)
	}

	// Malformed values are 400s, not silently ignored.
	for _, query := range []string{"?since=yesterday", "?limit=abc", "?limit=-1"} {
		status, body := h.getBody(t, "/api/v1/audit"+query, "owner")
		if status != http.StatusBadRequest {
			t.Fatalf("GET %s returned %d, expected 400: %s", query, status, body)
		}
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatalf("the error body is not the frozen envelope: %v", err)
		}
		if envelope.Error.Code != "validation_error" {
			t.Fatalf("GET %s returned error code %q, expected validation_error", query, envelope.Error.Code)
		}
	}
}

// TestOrgReadDoesNotCrossScopes: the organization route reads the caller's own chain,
// whatever it is asked for. There is no query parameter that names a scope.
func TestOrgReadDoesNotCrossScopes(t *testing.T) {
	h := newHarness(t)

	// An event on a scope the caller does not belong to.
	otherScope := "org_someone_else"
	if _, err := h.appender.Append(context.Background(), audit.Event{
		Scope:     otherScope,
		Timestamp: time.Now().UTC(),
		ActorID:   "user_other",
		ActorKind: audit.ActorUser,
		OrgID:     otherScope,
		Action:    audit.ActionSecretRead,
		Target:    "project/p/env/e/key/SECRET_OF_ANOTHER_TENANT",
		SourceIP:  "198.51.100.1",
		Result:    audit.ResultSuccess,
	}); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// The caller's own chain is empty: nothing was appended to it.
	// Every attempt to name the other scope must be ignored, and must not return its
	// events.
	for _, query := range []string{"", "?scope=" + otherScope, "?org=" + otherScope, "?actor=user_other"} {
		status, body := h.getBody(t, "/api/v1/audit"+query, "owner")
		if status != http.StatusOK {
			t.Fatalf("GET /api/v1/audit%s returned %d: %s", query, status, body)
		}
		if strings.Contains(string(body), "SECRET_OF_ANOTHER_TENANT") || strings.Contains(string(body), "user_other") {
			t.Fatalf("GET /api/v1/audit%s leaked another scope's events: %s", query, body)
		}
	}
}

// TestPlatformChainIsSeparate: the platform route reads the platform chain, not an
// organization's.
func TestPlatformChainIsSeparate(t *testing.T) {
	h := newHarness(t)

	// The route reads the literal platform chain, so the assertion is that the
	// organization's own events never appear in it.
	h.scope = "org_test"
	h.appendEvent(t, "project/p/env/e/key/ORG_ONLY_EVENT")

	status, body := h.getBody(t, "/api/v1/admin/audit?limit=1000", "platform")
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", status, body)
	}
	if strings.Contains(string(body), "ORG_ONLY_EVENT") {
		t.Fatalf("the platform log contains an organization event: %s", body)
	}
}

// TestMustChangePasswordGateRefusesAllFourRoutes is the P1(a) gate (SPEC §4).
//
// A user created with an initial password must change it before doing anything else.
// The audit log is the most sensitive surface to leak through that window: it names
// every actor, action and target in the organization, so an account that has not yet
// proven it is the person the administrator intended must not read it.
//
// The flag arrives on the request context, exactly as httpapi.withAuth now provides it:
// the middleware stand-in resolves it with the credential and calls
// reqctx.WithMustChangePassword. This slice's gate reads only that value — it has no
// database fallback — so this test proves the handler refuses when the central gate
// passes the flag through, and that the refusal is the frozen 403 with the right code.
//
// The central gate's own enforcement is proven separately, and independently of this
// slice, by internal/httpapi/mustchange_central_test.go: an ungated probe handler is
// never reached by a gated user, so a regression in withAuth fails there loudly rather
// than being masked by a handler-local check.
func TestMustChangePasswordGateRefusesAllFourRoutes(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "user_gated", "pat_gated_owner", reqctx.RoleOwner, true)
	h.seedUser(t, "user_ungated", "pat_ungated_owner", reqctx.RoleOwner, false)

	// The organization has a chain to read, so a 200 is a real read and not an empty one.
	h.appendEvent(t, "project/p/env/e/key/GATED")

	paths := []string{
		"/api/v1/audit",
		"/api/v1/audit/verify",
		"/api/v1/admin/audit",
		"/api/v1/admin/audit/verify",
	}

	for _, path := range paths {
		t.Run("gated"+path, func(t *testing.T) {
			status, body := h.getBody(t, path, "owner-gated")
			if status != http.StatusForbidden {
				t.Fatalf("GET %s as a must-change user: got %d, want 403; body: %s", path, status, body)
			}
			var envelope struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatalf("the refusal body is not the frozen envelope: %v", err)
			}
			if envelope.Error.Code != "password_change_required" {
				t.Fatalf("GET %s returned code %q, want password_change_required; body: %s", path, envelope.Error.Code, body)
			}
			// The refusal must not leak a single event.
			if strings.Contains(string(body), "GATED") {
				t.Fatalf("the refusal body leaked an audit event: %s", body)
			}
		})
	}

	// Clearing the flag — what POST /auth/password does on success, so the next
	// credential resolution reports must_change_password = false — restores access.
	h.setMustChange(t, "user_gated", false)
	cleared := map[string]string{"X-Test-MustChange": "false"}

	for _, path := range paths {
		t.Run("after_passwd"+path, func(t *testing.T) {
			status, body := h.getBodyAs(t, path, "owner-gated", cleared)
			// The platform routes refuse an owner with 403 for a different reason (not
			// the platform admin); the organization routes must now be 200.
			want := http.StatusForbidden
			if strings.HasPrefix(path, "/api/v1/audit") {
				want = http.StatusOK
			}
			if status != want {
				t.Fatalf("GET %s after the password change: got %d, want %d; body: %s", path, status, want, body)
			}
			if want == http.StatusOK && strings.Contains(string(body), "password_change_required") {
				t.Fatalf("GET %s still reports password_change_required after the change: %s", path, body)
			}
		})
	}
}

// TestMustChangePasswordGateLeavesNormalUsersAlone: a user who never had the flag is
// unaffected, so the gate cannot become a blanket refusal.
func TestMustChangePasswordGateLeavesNormalUsersAlone(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "user_ungated", "pat_ungated_owner", reqctx.RoleOwner, false)
	h.appendEvent(t, "project/p/env/e/key/NORMAL")

	status, body := h.getBody(t, "/api/v1/audit", "owner-ungated")
	if status != http.StatusOK {
		t.Fatalf("a normal owner got %d on /audit, want 200; body: %s", status, body)
	}
	if !strings.Contains(string(body), "NORMAL") {
		t.Fatalf("a normal owner's read returned no events: %s", body)
	}

	status, body = h.getBody(t, "/api/v1/audit/verify", "owner-ungated")
	if status != http.StatusOK {
		t.Fatalf("a normal owner got %d on /audit/verify, want 200; body: %s", status, body)
	}
	if want := `{"valid":true,"first_invalid_seq":null}`; string(body) != want {
		t.Fatalf("a normal owner's verify body is %s, want %s", body, want)
	}
}

// TestMustChangeGatePrecedesAuthorization pins the ordering: a must-change MEMBER gets
// password_change_required, not the plain 403 a member would otherwise get. The two are
// different answers and the order decides which one is returned.
func TestMustChangeGatePrecedesAuthorization(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "user_gated_member", "pat_gated_member", reqctx.RoleMember, true)

	// Reuse the gated owner's actor shape but with the member role.
	if _, err := h.owner.Exec(context.Background(),
		`UPDATE users SET role = 'member' WHERE id = 'user_gated_member'`); err != nil {
		t.Fatalf("could not set the role: %v", err)
	}

	status, body := h.getBody(t, "/api/v1/audit", "owner-gated-member")
	if status != http.StatusForbidden {
		t.Fatalf("got %d, want 403; body: %s", status, body)
	}
	if !strings.Contains(string(body), "password_change_required") {
		t.Fatalf("a must-change member got the plain forbidden answer instead of password_change_required: %s", body)
	}
}

// TestMustChangeGateContextFlagIsHonoured: when the middleware did set the flag (the
// authapi.Middleware path), the gate refuses without touching the database.
func TestMustChangeGateContextFlagIsHonoured(t *testing.T) {
	h := newHarness(t)
	// No users or tokens seeded at all: if the gate consulted the database it would
	// find nothing and allow the request. The context flag alone must refuse it.
	h.appendEvent(t, "project/p/env/e/key/CTXFLAG")

	status, body := h.getBody(t, "/api/v1/audit", "owner-gated-ctx")
	if status != http.StatusForbidden {
		t.Fatalf("the context flag did not refuse the request: got %d; body: %s", status, body)
	}
	if !strings.Contains(string(body), "password_change_required") {
		t.Fatalf("the refusal body is %s", body)
	}
}
