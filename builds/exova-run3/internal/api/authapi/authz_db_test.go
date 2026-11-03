package authapi_test

// Authorization tests for SPEC §2, written from the wrong side: every case here is a
// caller trying something they must not be allowed to do, and the assertion is the
// exact status and body the API must answer.
//
// The suite needs a PostgreSQL database with the schema from
// docs/CONTRACTS.md §6 already applied. It is configured with
// COFFER_TEST_DATABASE_URL and it SKIPS LOUDLY when that is unset — a skipped run is
// not a passing run, and the skip message says so.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"coffer/internal/api/authapi"
	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/idgen"
	"coffer/internal/reqctx"
	"coffer/internal/store"
	authstore "coffer/internal/store/auth"
)

// captureWriter records audit events in memory so the tests can assert on them
// without depending on the audit slice's writer.
type captureWriter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (w *captureWriter) Append(_ context.Context, e audit.Event) (audit.Event, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, e)
	return e, nil
}

func (w *captureWriter) AppendTx(ctx context.Context, _ pgx.Tx, e audit.Event) (audit.Event, error) {
	return w.Append(ctx, e)
}

func (w *captureWriter) actions() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.events))
	for _, e := range w.events {
		out = append(out, e.Action+"/"+string(e.Result))
	}
	return out
}

func (w *captureWriter) count(action string, result audit.Result) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, e := range w.events {
		if e.Action == action && e.Result == result {
			n++
		}
	}
	return n
}

// harness is one API instance over one test database.
type harness struct {
	t      *testing.T
	db     *store.DB
	pool   *pgxpool.Pool
	srv    *httptest.Server
	audit  *captureWriter
	suffix string
}

// testConfig builds a real config.Config whose runtime URL is the test database.
// It goes through config.LoadFrom with a map-backed lookup so it never mutates the
// process environment.
//
// Precedence rule this relies on (internal/config/config.go, loadDatabase): an
// explicit COFFER_MIGRATION_DATABASE_URL skips the POSTGRES_USER/PASSWORD/POSTGRES_DB
// derivation entirely ("if raw := ...; raw != "" { ... } else { db.OwnerUser, err =
// required(lookup, "POSTGRES_USER") }"), and an explicit DATABASE_URL short-circuits
// the runtime URL ("if raw := ...; raw != "" { ... return fillDatabaseName(...) }").
// So with both URLs set, no POSTGRES_* variable is read at all. That is what makes
// this harness work when the only thing the environment provides is
// COFFER_TEST_DATABASE_URL, which is the contract scripts/test.sh implements.
//
// The gated degraded-role mode is used because a test database is reached as its
// owner role; config refuses that in COFFER_ENV=production, so the harness runs as
// development.
func testConfig(t *testing.T, databaseURL string) *config.Config {
	t.Helper()

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, config.MasterKeyLen))
	vars := map[string]string{
		"COFFER_MASTER_KEY":               key,
		"COFFER_BOOTSTRAP_ADMIN_EMAIL":    "bootstrap@example.com",
		"COFFER_BOOTSTRAP_ADMIN_PASSWORD": "a-long-enough-bootstrap-password",
		"COFFER_ENV":                      config.EnvDevelopment,
		"COFFER_ALLOW_DEGRADED_DB_ROLE":   "1",
		// Both URLs, so neither the POSTGRES_* derivation nor the runtime
		// derivation from the migration URL is reached.
		"COFFER_MIGRATION_DATABASE_URL": databaseURL,
		"DATABASE_URL":                  databaseURL,
	}
	cfg, err := config.LoadFrom(func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	})
	if err != nil {
		t.Fatalf("build the test config: %v", err)
	}
	if cfg.RuntimeURL() != databaseURL {
		t.Fatalf("the test config's runtime URL is not the test database URL")
	}
	return cfg
}

// newHarness connects to the test database, wires the slice the way router.go does,
// and returns a harness whose orgs and emails are unique per call.
func newHarness(t *testing.T) *harness {
	t.Helper()

	url := strings.TrimSpace(os.Getenv("COFFER_TEST_DATABASE_URL"))
	if url == "" {
		t.Skip("SKIPPED, NOT PASSED: COFFER_TEST_DATABASE_URL is unset, so the authorization suite did not run. " +
			"Point it at a PostgreSQL database with the docs/CONTRACTS.md §6 schema applied to actually exercise SPEC §2.")
	}

	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := testConfig(t, url)

	// Apply the frozen schema before connecting. scripts/test.sh starts a throwaway
	// postgres:16 with an empty database, so the suite must migrate it itself rather
	// than assume someone else did. Migrate is idempotent, so this is also correct
	// against a database that already has the schema.
	if err := store.Migrate(ctx, cfg, log); err != nil {
		t.Fatalf("apply migrations to the test database: %v", err)
	}

	db, err := store.Connect(ctx, cfg, log)
	if err != nil {
		t.Fatalf("connect to the test database: %v", err)
	}
	t.Cleanup(db.Close)

	pool := db.Pool()
	if pool == nil {
		t.Fatal("store.Connect returned a DB with no pool")
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping the test database: %v", err)
	}

	capture := &captureWriter{}
	mux := http.NewServeMux()
	deps := authapi.Deps{
		DB:    db,
		Audit: capture,
		Log:   log,
	}
	authapi.Register(mux, deps)
	srv := httptest.NewServer(deps.Middleware(mux))
	t.Cleanup(srv.Close)

	return &harness{
		t:      t,
		db:     db,
		pool:   pool,
		srv:    srv,
		audit:  capture,
		suffix: fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid()),
	}
}

// unique returns a value unique to this harness, for slugs and emails.
func (h *harness) unique(prefix string) string {
	return prefix + "-" + strings.ToLower(h.suffix)
}

// do performs a request and returns the status and the exact body bytes.
func (h *harness) do(method, path, token string, body any) (int, []byte) {
	h.t.Helper()

	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, reader)
	if err != nil {
		h.t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, raw
}

// errorCode extracts error.code from an error body, or "" when the body is not an
// error envelope.
func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}
	return parsed.Error.Code
}

// seedOrg inserts an organization.
func (h *harness) seedOrg(slug string) string {
	h.t.Helper()
	id := idgen.New("org_")
	_, err := h.pool.Exec(context.Background(),
		`INSERT INTO organizations (id, slug) VALUES ($1, $2)`, id, slug)
	if err != nil {
		h.t.Fatalf("seed organization: %v", err)
	}
	return id
}

// seedUser inserts a user and a live PAT, and returns the user id and the plaintext
// token. The password is fixed per call so a test can log in with it.
func (h *harness) seedUser(orgID, email, role, password string, mustChange bool) (string, string) {
	h.t.Helper()

	hash, err := authapi.HashPassword(password)
	if err != nil {
		h.t.Fatalf("hash password: %v", err)
	}
	userID := idgen.New("usr_")
	_, err = h.pool.Exec(context.Background(),
		`INSERT INTO users (id, org_id, email, password_hash, role, must_change_password)
		 VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6)`,
		userID, orgID, strings.ToLower(email), hash, role, mustChange)
	if err != nil {
		h.t.Fatalf("seed user: %v", err)
	}

	pat := idgen.Secret(idgen.PrefixPAT)
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO personal_access_tokens (id, user_id, token_hash) VALUES ($1, $2, $3)`,
		idgen.New("pat_"), userID, authstore.HashToken(pat)); err != nil {
		h.t.Fatalf("seed personal access token: %v", err)
	}
	return userID, pat
}

// seedProject inserts a project.
func (h *harness) seedProject(orgID, slug string) string {
	h.t.Helper()
	id := idgen.New("prj_")
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO projects (id, org_id, slug) VALUES ($1, $2, $3)`, id, orgID, slug); err != nil {
		h.t.Fatalf("seed project: %v", err)
	}
	return id
}

// seedEnv inserts an environment.
func (h *harness) seedEnv(projectID, slug string, protected bool) string {
	h.t.Helper()
	id := idgen.New("env_")
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO environments (id, project_id, slug, protected) VALUES ($1, $2, $3, $4)`,
		id, projectID, slug, protected); err != nil {
		h.t.Fatalf("seed environment: %v", err)
	}
	return id
}

// seedGrant gives a user a grant on a project.
func (h *harness) seedGrant(projectID, userID, level string) {
	h.t.Helper()
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO project_grants (project_id, user_id, level) VALUES ($1, $2, $3)
		 ON CONFLICT (project_id, user_id) DO UPDATE SET level = EXCLUDED.level`,
		projectID, userID, level); err != nil {
		h.t.Fatalf("seed grant: %v", err)
	}
}

// seedServiceToken inserts a live service token and returns its id and plaintext.
// The TTL is passed in seconds so the expiry is computed by the database clock,
// exactly as the production insert does.
func (h *harness) seedServiceToken(orgID, projectID, envID, createdBy, access string, ttlSeconds int) (string, string) {
	h.t.Helper()
	id := idgen.New("tok_")
	token := idgen.Secret(idgen.PrefixService)
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO service_tokens (id, org_id, project_id, env_id, access, token_hash, created_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))`,
		id, orgID, projectID, envID, access, authstore.HashToken(token), createdBy, ttlSeconds); err != nil {
		h.t.Fatalf("seed service token: %v", err)
	}
	return id, token
}

const testPassword = "a-long-enough-test-password"

// TestInvisibleIs404 (SPEC §2.1) proves that a resource in another organization and
// a resource that does not exist produce byte-identical 404s, and that a member
// without a grant cannot see a project.
func TestInvisibleIs404(t *testing.T) {
	h := newHarness(t)

	orgA := h.seedOrg(h.unique("org-a"))
	orgB := h.seedOrg(h.unique("org-b"))
	projectInA := h.seedProject(orgA, "shared-name")
	h.seedEnv(projectInA, "prod", false)

	// A member of B holding a grant on a project of B.
	memberB, tokenB := h.seedUser(orgB, h.unique("member")+"@example.com", reqctx.RoleMember, testPassword, false)
	projectInB := h.seedProject(orgB, "own-project")
	h.seedGrant(projectInB, memberB, "reader")

	// Another organization's project: the slug is the SAME as one that exists in A.
	statusOther, bodyOther := h.do(http.MethodGet, "/api/v1/projects/shared-name/envs", tokenB, nil)
	// A project that exists nowhere.
	statusMissing, bodyMissing := h.do(http.MethodGet, "/api/v1/projects/does-not-exist-anywhere/envs", tokenB, nil)

	if statusOther != http.StatusNotFound {
		t.Fatalf("another organization's project returned %d, want 404", statusOther)
	}
	if statusMissing != http.StatusNotFound {
		t.Fatalf("a missing project returned %d, want 404", statusMissing)
	}
	if !bytes.Equal(bodyOther, bodyMissing) {
		t.Fatalf("the two 404 bodies differ, so existence is observable:\n other:   %s\n missing: %s", bodyOther, bodyMissing)
	}
	if code := errorCode(t, bodyOther); code != "not_found" {
		t.Fatalf("the 404 code is %q, want not_found", code)
	}

	// A member with no grant cannot see a project in their OWN organization either.
	memberNoGrant, tokenNoGrant := h.seedUser(orgB, h.unique("nogrant")+"@example.com", reqctx.RoleMember, testPassword, false)
	_ = memberNoGrant
	statusNoGrant, bodyNoGrant := h.do(http.MethodGet, "/api/v1/projects/own-project/envs", tokenNoGrant, nil)
	if statusNoGrant != http.StatusNotFound {
		t.Fatalf("a member with no grant got %d, want 404", statusNoGrant)
	}
	if !bytes.Equal(bodyNoGrant, bodyMissing) {
		t.Fatalf("the no-grant 404 differs from the missing-project 404:\n%s\n%s", bodyNoGrant, bodyMissing)
	}

	// And the project list is empty rather than an error, so it reveals nothing.
	statusList, bodyList := h.do(http.MethodGet, "/api/v1/projects", tokenNoGrant, nil)
	if statusList != http.StatusOK {
		t.Fatalf("the project list returned %d, want 200", statusList)
	}
	if !strings.Contains(string(bodyList), `"projects":[]`) {
		t.Fatalf("a member with no grant should see an empty list, got %s", bodyList)
	}
}

// TestLastOwnerRules (SPEC §2.2) proves the last owner cannot be demoted or removed
// (409), and that only an owner may create, promote, demote or remove an owner.
func TestLastOwnerRules(t *testing.T) {
	h := newHarness(t)

	org := h.seedOrg(h.unique("org"))
	owner1, tokenOwner1 := h.seedUser(org, h.unique("owner1")+"@example.com", reqctx.RoleOwner, testPassword, false)
	owner2, _ := h.seedUser(org, h.unique("owner2")+"@example.com", reqctx.RoleOwner, testPassword, false)
	admin, tokenAdmin := h.seedUser(org, h.unique("admin")+"@example.com", reqctx.RoleAdmin, testPassword, false)
	_ = admin

	// An admin may not touch an owner at all: 403, while TWO owners exist.
	status, body := h.do(http.MethodPatch, "/api/v1/members/"+owner2, tokenAdmin, map[string]string{"role": "member"})
	if status != http.StatusForbidden {
		t.Fatalf("an admin demoting a non-last owner got %d, want 403 (%s)", status, body)
	}

	// An admin may not promote anyone else to owner: 403. The target must be a
	// DIFFERENT user, because changing your own role is a 400 that takes precedence.
	promoteTarget, _ := h.seedUser(org, h.unique("promotee")+"@example.com", reqctx.RoleMember, testPassword, false)
	status, body = h.do(http.MethodPatch, "/api/v1/members/"+promoteTarget, tokenAdmin, map[string]string{"role": "owner"})
	if status != http.StatusForbidden {
		t.Fatalf("an admin promoting another member to owner got %d, want 403 (%s)", status, body)
	}

	// An owner may demote the second owner, leaving one.
	status, body = h.do(http.MethodPatch, "/api/v1/members/"+owner2, tokenOwner1, map[string]string{"role": "admin"})
	if status != http.StatusOK {
		t.Fatalf("an owner demoting another owner got %d, want 200 (%s)", status, body)
	}

	// Now owner1 is the last owner. Demoting themselves is a 409 (the last-owner rule
	// is checked before the self-change rule), and so is removing themselves.
	status, body = h.do(http.MethodPatch, "/api/v1/members/"+owner1, tokenOwner1, map[string]string{"role": "admin"})
	if status != http.StatusConflict {
		t.Fatalf("the last owner demoting themselves got %d, want 409 (%s)", status, body)
	}
	status, body = h.do(http.MethodDelete, "/api/v1/members/"+owner1, tokenOwner1, nil)
	if status != http.StatusConflict {
		t.Fatalf("the last owner removing themselves got %d, want 409 (%s)", status, body)
	}

	// An admin demoting an owner gets 403 whether or not that owner is the last one.
	// Authorization is checked before the last-owner rule, so the status cannot vary
	// with the number of owners — otherwise an admin could infer, from a 409, that
	// they are looking at the sole owner.
	status, body = h.do(http.MethodPatch, "/api/v1/members/"+owner1, tokenAdmin, map[string]string{"role": "member"})
	if status != http.StatusForbidden {
		t.Fatalf("an admin demoting the last owner got %d, want 403 (%s)", status, body)
	}

	// And the last owner is still an owner: nothing was applied.
	var finalRole string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT role FROM users WHERE id = $1`, owner1).Scan(&finalRole); err != nil {
		t.Fatalf("read the last owner's role: %v", err)
	}
	if finalRole != reqctx.RoleOwner {
		t.Fatalf("the last owner's role was changed to %q", finalRole)
	}

	// The three branches the CTO's ruling pins, stated together so a future
	// reordering of the gates fails here rather than in production:
	//
	//   admin  -> sole owner      = 403   (authorization precedes last-owner)
	//   admin  -> non-last owner  = 403   (asserted above, with two owners)
	//   owner  -> last owner      = 409   (asserted above, self-demote and DELETE)
	//
	// The invariant is that an admin's status never depends on how many owners
	// exist. Both admin calls above must agree, which is what makes the 409 above
	// safe for an owner and unreachable for an admin.
}

// TestNoSelfEscalation (SPEC §2.12) proves no request changes the caller's own role,
// grants or organization, and that the answer is 400, never 200.
func TestNoSelfEscalation(t *testing.T) {
	h := newHarness(t)

	org := h.seedOrg(h.unique("org"))
	admin, tokenAdmin := h.seedUser(org, h.unique("admin")+"@example.com", reqctx.RoleAdmin, testPassword, false)
	other, _ := h.seedUser(org, h.unique("other")+"@example.com", reqctx.RoleMember, testPassword, false)
	// The grant routes take a project SLUG (SPEC §7.2: {project}), not its id.
	h.seedProject(org, "proj")

	// An admin promoting themselves to owner. Both rules are violated at once — it
	// is a self-change AND it is an admin creating an owner — and after the CTO's
	// "authorization first" ruling the owner-permission gate wins, so the answer is
	// 403. What must never happen is a 200: the role below is checked in SQL.
	status, body := h.do(http.MethodPatch, "/api/v1/members/"+admin, tokenAdmin, map[string]string{"role": "owner"})
	if status == http.StatusOK {
		t.Fatalf("an admin promoted themselves to owner: %s", body)
	}
	if status != http.StatusForbidden {
		t.Fatalf("an admin promoting themselves got %d, want 403 (%s)", status, body)
	}
	var role string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT role FROM users WHERE id = $1`, admin).Scan(&role); err != nil {
		t.Fatalf("read the caller's role: %v", err)
	}
	if role != reqctx.RoleAdmin {
		t.Fatalf("the self-promotion was applied: role is now %q", role)
	}

	// The pure self-change rule is still 400, and it is reachable: a member
	// promoting themselves to admin violates no owner rule, so the self-change gate
	// is the one that answers. Never applied, never a 200.
	memberSelf, tokenMemberSelf := h.seedUser(org, h.unique("selfmember")+"@example.com", reqctx.RoleMember, testPassword, false)
	_ = tokenMemberSelf
	// A member cannot manage members at all, so use an admin changing their own role
	// to a non-owner role: self-change, no owner involved, no last-owner question.
	status, body = h.do(http.MethodPatch, "/api/v1/members/"+admin, tokenAdmin, map[string]string{"role": "member"})
	if status != http.StatusBadRequest {
		t.Fatalf("an admin demoting themselves got %d, want 400 (%s)", status, body)
	}
	if err := h.pool.QueryRow(context.Background(),
		`SELECT role FROM users WHERE id = $1`, admin).Scan(&role); err != nil {
		t.Fatalf("read the caller's role: %v", err)
	}
	if role != reqctx.RoleAdmin {
		t.Fatalf("the self-demotion was applied: role is now %q", role)
	}
	_ = memberSelf

	// A caller granting themselves a writer level: 400, and no grant row appears.
	status, body = h.do(http.MethodPut, "/api/v1/members/"+admin+"/grants/proj", tokenAdmin, map[string]string{"level": "writer"})
	if status != http.StatusBadRequest {
		t.Fatalf("a caller granting themselves got %d, want 400 (%s)", status, body)
	}
	var grants int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM project_grants WHERE user_id = $1`, admin).Scan(&grants); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if grants != 0 {
		t.Fatalf("the self-grant was applied: %d grant rows", grants)
	}

	// A field the caller may not set is a 400, not a silent no-op.
	status, body = h.do(http.MethodPost, "/api/v1/members", tokenAdmin, map[string]any{
		"email": h.unique("new") + "@example.com", "role": "member",
		"password": testPassword, "org_id": "some-other-org",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("a request carrying an unknown field got %d, want 400 (%s)", status, body)
	}

	// Granting to somebody else still works, so the rule is not a blanket refusal.
	status, body = h.do(http.MethodPut, "/api/v1/members/"+other+"/grants/proj", tokenAdmin, map[string]string{"level": "writer"})
	if status != http.StatusOK {
		t.Fatalf("granting to another member got %d, want 200 (%s)", status, body)
	}
}

// TestMemberAndServiceTokenCannotManage (SPEC §2.3, §2.6, §2.7) proves the 403s for
// callers that can see the resource but may not act on it, and that a member gets
// 403 rather than a 400 for a malformed body on a route they may not use.
func TestMemberAndServiceTokenCannotManage(t *testing.T) {
	h := newHarness(t)

	org := h.seedOrg(h.unique("org"))
	owner, _ := h.seedUser(org, h.unique("owner")+"@example.com", reqctx.RoleOwner, testPassword, false)
	member, tokenMember := h.seedUser(org, h.unique("member")+"@example.com", reqctx.RoleMember, testPassword, false)
	project := h.seedProject(org, "proj")
	env := h.seedEnv(project, "dev", false)
	h.seedGrant(project, member, "writer")

	_, tokenService := h.seedServiceToken(org, project, env, owner, "read-write", 3600)

	memberRoutes := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/members", nil},
		{http.MethodPost, "/api/v1/members", map[string]string{"email": "x@example.com", "role": "member", "password": testPassword}},
		{http.MethodPatch, "/api/v1/members/" + owner, map[string]string{"role": "member"}},
		{http.MethodDelete, "/api/v1/members/" + owner, nil},
		{http.MethodPut, "/api/v1/members/" + member + "/grants/proj", map[string]string{"level": "writer"}},
		{http.MethodDelete, "/api/v1/members/" + member + "/grants/proj", nil},
		{http.MethodGet, "/api/v1/tokens", nil},
		{http.MethodPost, "/api/v1/tokens", map[string]any{"project": "proj", "env": "dev", "access": "read", "ttl_seconds": 3600}},
		{http.MethodPost, "/api/v1/projects", map[string]string{"slug": "nope"}},
		{http.MethodPost, "/api/v1/projects/proj/envs", map[string]any{"slug": "nope"}},
	}
	for _, route := range memberRoutes {
		status, body := h.do(route.method, route.path, tokenMember, route.body)
		if status != http.StatusForbidden {
			t.Errorf("member %s %s got %d, want 403 (%s)", route.method, route.path, status, body)
		}
		if code := errorCode(t, body); code != "forbidden" {
			t.Errorf("member %s %s code = %q, want forbidden", route.method, route.path, code)
		}
	}

	// Authorization runs before field validation: a member sending a body that is
	// ALSO invalid still gets 403, never a 400 that describes the payload.
	status, body := h.do(http.MethodPost, "/api/v1/members", tokenMember, map[string]string{"role": "not-a-role"})
	if status != http.StatusForbidden {
		t.Errorf("a member sending an invalid body got %d, want 403 (%s)", status, body)
	}

	// A service token may not manage members, grants, tokens or projects, and may not
	// enumerate environments. It can see the project it is scoped to, so these are
	// 403s and not 404s.
	serviceRoutes := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/members", nil},
		{http.MethodPost, "/api/v1/members", map[string]string{"email": "y@example.com", "role": "member", "password": testPassword}},
		{http.MethodPut, "/api/v1/members/" + member + "/grants/proj", map[string]string{"level": "viewer"}},
		{http.MethodGet, "/api/v1/tokens", nil},
		{http.MethodPost, "/api/v1/tokens", map[string]any{"project": "proj", "env": "dev", "access": "read", "ttl_seconds": 3600}},
		{http.MethodGet, "/api/v1/projects", nil},
		{http.MethodPost, "/api/v1/projects", map[string]string{"slug": "nope"}},
		{http.MethodGet, "/api/v1/projects/proj/envs", nil},
		{http.MethodPost, "/api/v1/projects/proj/envs", map[string]any{"slug": "nope"}},
		{http.MethodPost, "/api/v1/auth/logout", nil},
	}
	for _, route := range serviceRoutes {
		status, body := h.do(route.method, route.path, tokenService, route.body)
		if status != http.StatusForbidden {
			t.Errorf("service token %s %s got %d, want 403 (%s)", route.method, route.path, status, body)
		}
	}

	// A service token outside its project gets the invisible 404, not a 403.
	otherProject := h.seedProject(org, "other-proj")
	_ = otherProject
	status, body = h.do(http.MethodGet, "/api/v1/projects/other-proj/envs", tokenService, nil)
	if status != http.StatusNotFound {
		t.Errorf("a service token outside its scope got %d, want 404 (%s)", status, body)
	}
}

// TestPlatformAdminSeesNothing (SPEC §2.10) proves the platform admin gets 404 on
// every organization-scoped route, and that a non-platform-admin gets 403 on /admin.
func TestPlatformAdminSeesNothing(t *testing.T) {
	h := newHarness(t)

	org := h.seedOrg(h.unique("org"))
	owner, _ := h.seedUser(org, h.unique("owner")+"@example.com", reqctx.RoleOwner, testPassword, false)
	project := h.seedProject(org, "proj")
	h.seedEnv(project, "dev", false)

	// The platform admin: no organization, role platform_admin.
	_, tokenPlatform := h.seedUser("", h.unique("platform")+"@example.com", reqctx.RolePlatformAdmin, testPassword, false)

	// A missing-project 404 to compare against.
	_, tokenOwner := h.seedUser(org, h.unique("owner2")+"@example.com", reqctx.RoleOwner, testPassword, false)
	_, bodyMissing := h.do(http.MethodGet, "/api/v1/projects/never-existed/envs", tokenOwner, nil)

	orgRoutes := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/members", nil},
		{http.MethodPost, "/api/v1/members", map[string]string{"email": "z@example.com", "role": "member", "password": testPassword}},
		{http.MethodGet, "/api/v1/projects", nil},
		{http.MethodPost, "/api/v1/projects", map[string]string{"slug": "nope"}},
		{http.MethodGet, "/api/v1/projects/proj/envs", nil},
		{http.MethodPost, "/api/v1/projects/proj/envs", map[string]any{"slug": "nope"}},
		{http.MethodGet, "/api/v1/tokens", nil},
		{http.MethodPost, "/api/v1/tokens", map[string]any{"project": "proj", "env": "dev", "access": "read", "ttl_seconds": 3600}},
		{http.MethodDelete, "/api/v1/tokens/tok_x", nil},
	}
	for _, route := range orgRoutes {
		status, body := h.do(route.method, route.path, tokenPlatform, route.body)
		if status != http.StatusNotFound {
			t.Errorf("platform admin %s %s got %d, want 404 (%s)", route.method, route.path, status, body)
			continue
		}
		if !bytes.Equal(body, bodyMissing) {
			t.Errorf("platform admin %s %s 404 body differs from a missing resource: %s vs %s",
				route.method, route.path, body, bodyMissing)
		}
	}

	// /me reports the platform admin with no organization.
	status, body := h.do(http.MethodGet, "/api/v1/me", tokenPlatform, nil)
	if status != http.StatusOK {
		t.Fatalf("platform admin GET /me got %d, want 200 (%s)", status, body)
	}
	var me struct {
		Role         string  `json:"role"`
		Organization *string `json:"organization"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatalf("decode /me: %v", err)
	}
	if me.Role != reqctx.RolePlatformAdmin {
		t.Errorf("/me role = %q, want platform_admin", me.Role)
	}
	if me.Organization != nil {
		t.Errorf("/me organization = %v, want null", me.Organization)
	}

	// /admin is the platform admin's own surface and works.
	status, body = h.do(http.MethodGet, "/api/v1/admin/orgs", tokenPlatform, nil)
	if status != http.StatusOK {
		t.Fatalf("platform admin GET /admin/orgs got %d, want 200 (%s)", status, body)
	}

	// An owner calling /admin gets 403, not 404: /admin is not organization-scoped,
	// so there is nothing to hide.
	status, body = h.do(http.MethodGet, "/api/v1/admin/orgs", tokenOwner, nil)
	if status != http.StatusForbidden {
		t.Fatalf("an owner calling /admin/orgs got %d, want 403 (%s)", status, body)
	}

	// The platform admin cannot create an owner in an organization through /members.
	_ = owner
}

// TestRevocationIsImmediate (SPEC §2.11) proves each revocation event is visible on
// the very next request, with no cache in the way.
func TestRevocationIsImmediate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A revoked PAT stops working on the next request.
	org := h.seedOrg(h.unique("org-revoke"))
	_, token := h.seedUser(org, h.unique("revoked")+"@example.com", reqctx.RoleOwner, testPassword, false)
	if status, _ := h.do(http.MethodGet, "/api/v1/me", token, nil); status != http.StatusOK {
		t.Fatalf("the live token did not work: %d", status)
	}
	if _, err := h.pool.Exec(ctx,
		`UPDATE personal_access_tokens SET revoked_at = now() WHERE token_hash = $1`,
		authstore.HashToken(token)); err != nil {
		t.Fatalf("revoke the token: %v", err)
	}
	if status, body := h.do(http.MethodGet, "/api/v1/me", token, nil); status != http.StatusUnauthorized {
		t.Fatalf("a revoked token got %d, want 401 (%s)", status, body)
	}

	// An expired service token stops working, and expiry is judged by the DATABASE
	// clock: the test moves the row's expires_at into the past rather than waiting.
	org2 := h.seedOrg(h.unique("org-expire"))
	owner2, _ := h.seedUser(org2, h.unique("owner")+"@example.com", reqctx.RoleOwner, testPassword, false)
	project2 := h.seedProject(org2, "proj")
	env2 := h.seedEnv(project2, "dev", false)
	stID, serviceToken := h.seedServiceToken(org2, project2, env2, owner2, "read", 3600)
	// A live service token authenticates, but /me is not a secret operation inside
	// its scope, so it gets 403 (SPEC §2.7, CEO ruling): the token is visible to us
	// and forbidden, which is why this is not a 404.
	if status, body := h.do(http.MethodGet, "/api/v1/me", serviceToken, nil); status != http.StatusForbidden {
		t.Fatalf("a live service token on /me got %d, want 403 (%s)", status, body)
	}
	// Proof the token itself is still live: an expired one must be 401, not 403.
	// A 403 here would mean the credential never resolved.
	if _, err := h.pool.Exec(ctx,
		`UPDATE service_tokens SET expires_at = now() - interval '1 second' WHERE id = $1`, stID); err != nil {
		t.Fatalf("expire the service token: %v", err)
	}
	if status, body := h.do(http.MethodGet, "/api/v1/me", serviceToken, nil); status != http.StatusUnauthorized {
		t.Fatalf("an expired service token got %d, want 401 (%s)", status, body)
	}

	// A removed user's token stops working.
	org3 := h.seedOrg(h.unique("org-remove"))
	_, token3 := h.seedUser(org3, h.unique("removed")+"@example.com", reqctx.RoleMember, testPassword, false)
	if _, err := h.pool.Exec(ctx,
		`UPDATE users SET removed_at = now() WHERE email = $1`,
		h.unique("removed")+"@example.com"); err != nil {
		t.Fatalf("remove the user: %v", err)
	}
	if status, body := h.do(http.MethodGet, "/api/v1/me", token3, nil); status != http.StatusUnauthorized {
		t.Fatalf("a removed user's token got %d, want 401 (%s)", status, body)
	}

	// A disabled organization stops working for everyone in it.
	org4 := h.seedOrg(h.unique("org-disable"))
	_, token4 := h.seedUser(org4, h.unique("disabled")+"@example.com", reqctx.RoleOwner, testPassword, false)
	if _, err := h.pool.Exec(ctx,
		`UPDATE organizations SET disabled_at = now() WHERE id = $1`, org4); err != nil {
		t.Fatalf("disable the organization: %v", err)
	}
	if status, body := h.do(http.MethodGet, "/api/v1/me", token4, nil); status != http.StatusUnauthorized {
		t.Fatalf("a disabled organization's token got %d, want 401 (%s)", status, body)
	}

	// A revoked grant removes the project from the member's view immediately.
	org5 := h.seedOrg(h.unique("org-grant"))
	member5, token5 := h.seedUser(org5, h.unique("granted")+"@example.com", reqctx.RoleMember, testPassword, false)
	project5 := h.seedProject(org5, "granted-proj")
	h.seedGrant(project5, member5, "reader")
	if status, _ := h.do(http.MethodGet, "/api/v1/projects/granted-proj/envs", token5, nil); status != http.StatusOK {
		t.Fatalf("the granted project was not visible: %d", status)
	}
	if _, err := h.pool.Exec(ctx,
		`DELETE FROM project_grants WHERE project_id = $1 AND user_id = $2`, project5, member5); err != nil {
		t.Fatalf("revoke the grant: %v", err)
	}
	if status, body := h.do(http.MethodGet, "/api/v1/projects/granted-proj/envs", token5, nil); status != http.StatusNotFound {
		t.Fatalf("after revoking the grant the project got %d, want 404 (%s)", status, body)
	}
}

// TestLoginIndistinguishableAndLockout covers SPEC §4: an unknown email and a wrong
// password are the same response, and five failures lock the account even for the
// correct password while other accounts stay usable.
func TestLoginIndistinguishableAndLockout(t *testing.T) {
	h := newHarness(t)

	org := h.seedOrg(h.unique("org-login"))
	email := h.unique("user") + "@example.com"
	h.seedUser(org, email, reqctx.RoleOwner, testPassword, false)

	// Unknown email versus wrong password: same status, same body.
	statusUnknown, bodyUnknown := h.do(http.MethodPost, "/api/v1/auth/token",
		"", map[string]string{"email": h.unique("ghost") + "@example.com", "password": testPassword})
	statusWrong, bodyWrong := h.do(http.MethodPost, "/api/v1/auth/token",
		"", map[string]string{"email": email, "password": "definitely-the-wrong-password"})

	if statusUnknown != http.StatusUnauthorized || statusWrong != http.StatusUnauthorized {
		t.Fatalf("unknown=%d wrong=%d, both must be 401", statusUnknown, statusWrong)
	}
	if !bytes.Equal(bodyUnknown, bodyWrong) {
		t.Fatalf("the two login failures differ, so the response reveals whether the account exists:\n unknown: %s\n wrong:   %s",
			bodyUnknown, bodyWrong)
	}

	// A correct login works and mints a usable PAT.
	status, body := h.do(http.MethodPost, "/api/v1/auth/token", "",
		map[string]string{"email": email, "password": testPassword})
	if status != http.StatusOK {
		t.Fatalf("a correct login got %d, want 200 (%s)", status, body)
	}
	var login struct {
		Token string `json:"token"`
		User  struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if !strings.HasPrefix(login.Token, idgen.PrefixPAT) {
		t.Fatalf("the issued token is %q, want a cof_pat_ prefix", login.Token)
	}
	if login.User.Email != email {
		t.Fatalf("login returned email %q, want %q", login.User.Email, email)
	}
	if status, _ := h.do(http.MethodGet, "/api/v1/me", login.Token, nil); status != http.StatusOK {
		t.Fatalf("the token minted at login did not work: %d", status)
	}

	// Only the hash is stored: the plaintext must not be in the database.
	var stored string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT token_hash FROM personal_access_tokens WHERE token_hash = $1`,
		authstore.HashToken(login.Token)).Scan(&stored); err != nil {
		t.Fatalf("the token hash was not stored: %v", err)
	}
	if stored == login.Token {
		t.Fatal("the plaintext token was stored instead of its hash")
	}

	// Lockout: five failures, then the correct password is refused with 429.
	lockEmail := h.unique("lockme") + "@example.com"
	h.seedUser(org, lockEmail, reqctx.RoleMember, testPassword, false)
	for i := 0; i < lockoutThresholdForTest; i++ {
		status, _ := h.do(http.MethodPost, "/api/v1/auth/token", "",
			map[string]string{"email": lockEmail, "password": "wrong-password-here"})
		if status != http.StatusUnauthorized {
			t.Fatalf("failure %d returned %d, want 401", i+1, status)
		}
	}
	status, body = h.do(http.MethodPost, "/api/v1/auth/token", "",
		map[string]string{"email": lockEmail, "password": testPassword})
	if status != http.StatusTooManyRequests {
		t.Fatalf("a correct password during the lockout got %d, want 429 (%s)", status, body)
	}

	// Another account is unaffected by that lockout.
	status, body = h.do(http.MethodPost, "/api/v1/auth/token", "",
		map[string]string{"email": email, "password": testPassword})
	if status != http.StatusOK {
		t.Fatalf("an unrelated account was affected by the lockout: %d (%s)", status, body)
	}
}

// lockoutThresholdForTest mirrors the policy in the package under test. It is a
// literal because the constant is unexported; if the policy changes, this test fails
// loudly rather than silently testing the wrong number.
const lockoutThresholdForTest = 5

// TestMustChangePasswordGate (SPEC §4 P1(a)) proves a user created with an initial
// password can do nothing except change it, and that the gate covers every route.
func TestMustChangePasswordGate(t *testing.T) {
	h := newHarness(t)

	org := h.seedOrg(h.unique("org-p1"))
	_, tokenOwner := h.seedUser(org, h.unique("owner")+"@example.com", reqctx.RoleOwner, testPassword, false)

	// Created through the API, so the flag is set by the code under test rather than
	// by the test's own INSERT.
	newEmail := h.unique("newbie") + "@example.com"
	status, body := h.do(http.MethodPost, "/api/v1/members", tokenOwner, map[string]string{
		"email": newEmail, "role": "member", "password": testPassword,
	})
	if status != http.StatusCreated {
		t.Fatalf("creating a member got %d, want 201 (%s)", status, body)
	}

	// Log in as the new user; the login itself must succeed.
	status, body = h.do(http.MethodPost, "/api/v1/auth/token", "",
		map[string]string{"email": newEmail, "password": testPassword})
	if status != http.StatusOK {
		t.Fatalf("the new user could not log in: %d (%s)", status, body)
	}
	var login struct {
		Token string `json:"token"`
		User  struct {
			MustChangePassword bool `json:"must_change_password"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if !login.User.MustChangePassword {
		t.Fatal("a member created by an admin did not get must_change_password")
	}

	// Every route except the two exempt ones refuses with the machine-readable code.
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/me"},
		{http.MethodGet, "/api/v1/members"},
		{http.MethodGet, "/api/v1/projects"},
		{http.MethodGet, "/api/v1/tokens"},
		{http.MethodGet, "/api/v1/admin/orgs"},
	}
	for _, route := range routes {
		status, body := h.do(route.method, route.path, login.Token, nil)
		if status != http.StatusForbidden {
			t.Errorf("%s %s with must_change_password got %d, want 403 (%s)", route.method, route.path, status, body)
			continue
		}
		if code := errorCode(t, body); code != authapi.CodePasswordChangeRequired {
			t.Errorf("%s %s code = %q, want %q", route.method, route.path, code, authapi.CodePasswordChangeRequired)
		}
	}

	// The exempt route works and clears the flag.
	status, body = h.do(http.MethodPost, "/api/v1/auth/password", login.Token, map[string]string{
		"current_password": testPassword,
		"new_password":     "a-brand-new-long-password",
	})
	if status != http.StatusOK {
		t.Fatalf("the password change got %d, want 200 (%s)", status, body)
	}
	status, body = h.do(http.MethodGet, "/api/v1/me", login.Token, nil)
	if status != http.StatusOK {
		t.Fatalf("after changing the password /me got %d, want 200 (%s)", status, body)
	}

	// The old password no longer works and the new one does.
	status, _ = h.do(http.MethodPost, "/api/v1/auth/token", "",
		map[string]string{"email": newEmail, "password": testPassword})
	if status != http.StatusUnauthorized {
		t.Fatalf("the old password still works: %d", status)
	}
	status, body = h.do(http.MethodPost, "/api/v1/auth/token", "",
		map[string]string{"email": newEmail, "password": "a-brand-new-long-password"})
	if status != http.StatusOK {
		t.Fatalf("the new password does not work: %d (%s)", status, body)
	}
}

// TestPasswordChangeRevokesOtherPATs (SPEC §4 P1(b)) proves a password change kills
// the other sessions and keeps the one that made the change.
func TestPasswordChangeRevokesOtherPATs(t *testing.T) {
	h := newHarness(t)

	org := h.seedOrg(h.unique("org-p1b"))
	email := h.unique("person") + "@example.com"
	h.seedUser(org, email, reqctx.RoleMember, testPassword, false)

	// Two sessions, as two logins would produce.
	_, body1 := h.do(http.MethodPost, "/api/v1/auth/token", "", map[string]string{"email": email, "password": testPassword})
	_, body2 := h.do(http.MethodPost, "/api/v1/auth/token", "", map[string]string{"email": email, "password": testPassword})

	tokenA := loginToken(t, body1)
	tokenB := loginToken(t, body2)

	status, body := h.do(http.MethodPost, "/api/v1/auth/password", tokenA, map[string]string{
		"current_password": testPassword,
		"new_password":     "another-long-password-1",
	})
	if status != http.StatusOK {
		t.Fatalf("the password change got %d, want 200 (%s)", status, body)
	}

	// The token used for the change keeps working.
	if status, body := h.do(http.MethodGet, "/api/v1/me", tokenA, nil); status != http.StatusOK {
		t.Fatalf("the token used for the change was revoked: %d (%s)", status, body)
	}
	// The other one is dead on the next request.
	if status, body := h.do(http.MethodGet, "/api/v1/me", tokenB, nil); status != http.StatusUnauthorized {
		t.Fatalf("the other session survived the password change: %d (%s)", status, body)
	}
}

func loginToken(t *testing.T, body []byte) string {
	t.Helper()
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if login.Token == "" {
		t.Fatal("the login response carried no token")
	}
	return login.Token
}

// TestDuplicateEmailIsGenericConflict proves a duplicate email is a 409 that names
// no organization and no "already in org X".
func TestDuplicateEmailIsGenericConflict(t *testing.T) {
	h := newHarness(t)

	orgA := h.seedOrg(h.unique("org-dup-a"))
	orgB := h.seedOrg(h.unique("org-dup-b"))
	_, tokenA := h.seedUser(orgA, h.unique("owner-a")+"@example.com", reqctx.RoleOwner, testPassword, false)
	_, tokenB := h.seedUser(orgB, h.unique("owner-b")+"@example.com", reqctx.RoleOwner, testPassword, false)

	shared := h.unique("shared") + "@example.com"
	status, body := h.do(http.MethodPost, "/api/v1/members", tokenA, map[string]string{
		"email": shared, "role": "member", "password": testPassword,
	})
	if status != http.StatusCreated {
		t.Fatalf("creating the first member got %d, want 201 (%s)", status, body)
	}

	// The same email from another organization: 409, and nothing about which
	// organization holds it.
	status, body = h.do(http.MethodPost, "/api/v1/members", tokenB, map[string]string{
		"email": shared, "role": "member", "password": testPassword,
	})
	if status != http.StatusConflict {
		t.Fatalf("a duplicate email got %d, want 409 (%s)", status, body)
	}
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "org-dup-a") || strings.Contains(lower, "already in") {
		t.Fatalf("the conflict body leaks the holding organization: %s", body)
	}

	// Project slugs are unique per organization only, so the same slug in two
	// organizations must both succeed.
	for i, token := range []string{tokenA, tokenB} {
		status, body := h.do(http.MethodPost, "/api/v1/projects", token, map[string]string{"slug": "shared-project"})
		if status != http.StatusCreated {
			t.Fatalf("organization %d could not create the same project slug: %d (%s)", i+1, status, body)
		}
	}
}

// TestDenialAuditEvents proves an authorization 403 or 404 writes exactly one
// `denied` event, and that a bare 401 writes none.
func TestDenialAuditEvents(t *testing.T) {
	h := newHarness(t)

	org := h.seedOrg(h.unique("org-deny"))
	_, tokenMember := h.seedUser(org, h.unique("member")+"@example.com", reqctx.RoleMember, testPassword, false)

	before := h.audit.count(audit.ActionDenied, audit.ResultDenied)

	// A 403 by authorization.
	if status, _ := h.do(http.MethodGet, "/api/v1/members", tokenMember, nil); status != http.StatusForbidden {
		t.Fatalf("the member route did not return 403")
	}
	afterForbidden := h.audit.count(audit.ActionDenied, audit.ResultDenied)
	if afterForbidden != before+1 {
		t.Fatalf("a 403 wrote %d denied events, want exactly 1", afterForbidden-before)
	}

	// A 404 by invisibility.
	if status, _ := h.do(http.MethodGet, "/api/v1/projects/no-such-project/envs", tokenMember, nil); status != http.StatusNotFound {
		t.Fatalf("the invisible project did not return 404")
	}
	afterNotFound := h.audit.count(audit.ActionDenied, audit.ResultDenied)
	if afterNotFound != afterForbidden+1 {
		t.Fatalf("a 404 wrote %d denied events, want exactly 1", afterNotFound-afterForbidden)
	}

	// A bare 401 writes nothing: there is no actor to attribute, and an anonymous
	// caller must not be able to write audit rows freely.
	if status, _ := h.do(http.MethodGet, "/api/v1/me", "cof_pat_"+strings.Repeat("0", 64), nil); status != http.StatusUnauthorized {
		t.Fatalf("an unknown token did not return 401")
	}
	afterUnauthenticated := h.audit.count(audit.ActionDenied, audit.ResultDenied)
	if afterUnauthenticated != afterNotFound {
		t.Fatalf("a 401 wrote %d denied events, want 0", afterUnauthenticated-afterNotFound)
	}

	// The denial for an invisible resource carries the actor's own organization, and
	// the target it asked for, so a denial on another tenant's resource cannot reveal
	// whether that resource exists.
	h.audit.mu.Lock()
	defer h.audit.mu.Unlock()
	var found bool
	for _, e := range h.audit.events {
		if e.Action == audit.ActionDenied && e.Scope == org {
			found = true
			if e.ActorKind != audit.ActorUser {
				t.Errorf("denial actor kind = %q, want user", e.ActorKind)
			}
			if e.SourceIP == "" {
				t.Errorf("denial event has no source_ip")
			}
		}
	}
	if !found {
		t.Fatal("no denial event was written to the actor's organization chain")
	}
}
