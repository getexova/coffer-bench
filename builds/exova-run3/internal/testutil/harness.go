// Package testutil is the shared test harness: a migrated test database, a real
// router behind an httptest.Server, and tokens minted through the real login route.
//
// There is no test-only auth seam and no backdoor. Every token a test uses is a real
// personal access token or service token created through POST /api/v1/auth/token or
// the token route, so a test that passes proves the real authentication path works.
// A bypass would let the suite pass while the product rejected every real caller.
//
// The harness skips cleanly when COFFER_TEST_DATABASE_URL is unset, so `go test ./...`
// is green on a machine with no database.
package testutil

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"coffer/internal/api/authapi"
	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/httpapi"
	"coffer/internal/store"
)

// TestDatabaseEnv is the only environment variable the harness requires: a postgres
// URL for a role that may create the schema and roles.
const TestDatabaseEnv = "COFFER_TEST_DATABASE_URL"

// TestAppDatabaseEnv is optional. When set, the runtime pool runs as coffer_app
// against this URL instead of as the owner, which exercises the real privilege split.
const TestAppDatabaseEnv = "COFFER_TEST_APP_DATABASE_URL"

// defaultBootstrapEmail and defaultBootstrapPassword are the platform admin the
// harness boots with. They are test values, generated per process where it matters.
const defaultBootstrapEmail = "platform-admin@testutil.invalid"

// Harness is one isolated test installation.
type Harness struct {
	t      *testing.T
	db     *store.DB
	server *httptest.Server
	cfg    *config.Config

	bootstrapEmail    string
	bootstrapPassword string
}

// Require returns a harness for the calling test, skipping when no test database is
// configured. It runs migrations and starts the real router.
func Require(t *testing.T) *Harness {
	t.Helper()
	return New(t)
}

// New builds a harness: config from the environment, migrations, the real router, and
// an httptest.Server in front of it.
func New(t *testing.T) *Harness {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv(TestDatabaseEnv))
	if dsn == "" {
		t.Skipf("%s is not set; skipping the integration test (set it to a postgres URL to run)", TestDatabaseEnv)
	}

	cfg := testConfig(t, dsn)
	h := &Harness{
		t:                 t,
		cfg:               cfg,
		bootstrapEmail:    cfg.BootstrapAdminEmail,
		bootstrapPassword: cfg.BootstrapAdminPassword,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	db, err := store.Boot(ctx, cfg, log)
	if err != nil {
		t.Fatalf("testutil: could not boot the test database: %v", err)
	}
	h.db = db

	deps := httpapi.Deps{DB: db, Audit: audit.NopWriter(), Config: cfg, Log: log}

	// Create the platform admin the same way the server does on first boot. Without
	// this the bootstrap account does not exist, every PlatformAdminToken() login
	// returns 401, and every test that needs an organization fails for a reason that
	// has nothing to do with the code under test. Bootstrap is idempotent and only
	// acts when no users exist, so running it per harness is safe.
	authDeps := authapi.Deps{DB: db, Audit: deps.Audit, Config: cfg, Log: log}
	bootstrapCtx, bootstrapCancel := context.WithTimeout(ctx, 30*time.Second)
	bootstrapErr := authapi.Bootstrap(bootstrapCtx, authDeps)
	bootstrapCancel()
	if bootstrapErr != nil {
		t.Fatalf("testutil: could not bootstrap the platform admin: %v", bootstrapErr)
	}

	handler := httpapi.NewRouter(deps, authapi.NewAuthenticator(authapi.Deps{
		DB:     db,
		Audit:  deps.Audit,
		Config: cfg,
		Log:    log,
	}))

	h.server = httptest.NewServer(handler)
	t.Cleanup(h.Close)
	return h
}

// stableSecret derives a deterministic value from the test database URL and a label.
//
// `go test ./...` runs every package as a separate process, and they all share one test
// database. If each process generated a random master key and bootstrap password, the
// first package would create the platform admin and every later package would fail to log
// in as it (401) or to decrypt data written by it. Deriving both from the DSN makes the
// whole run coherent: same database, same key, same admin password.
//
// This is a test-only value for a throwaway database; it is never used outside a test run.
func stableSecret(dsn, label string, n int) []byte {
	sum := sha256.Sum256([]byte(label + "\x00" + dsn))
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = sum[i%len(sum)]
	}
	// One round is enough to spread the first sum's bytes; the input is not a secret.
	if n > len(sum) {
		more := sha256.Sum256(sum[:])
		copy(out[len(sum):], more[:])
	}
	return out
}

// testConfig builds the config the server boots with. The master key, the bootstrap
// admin password and the database URLs come from the environment when the operator
// set them, and are derived from the test database URL otherwise, so a test run needs
// exactly one variable and stays consistent across packages.
func testConfig(t *testing.T, dsn string) *config.Config {
	t.Helper()

	masterKey := strings.TrimSpace(os.Getenv("COFFER_MASTER_KEY"))
	if masterKey == "" {
		masterKey = base64.StdEncoding.EncodeToString(stableSecret(dsn, "master-key", 32))
	}

	bootstrapPassword := strings.TrimSpace(os.Getenv("COFFER_BOOTSTRAP_ADMIN_PASSWORD"))
	if bootstrapPassword == "" {
		bootstrapPassword = "test-" + hex.EncodeToString(stableSecret(dsn, "bootstrap-password", 12)) + "-password"
	}

	bootstrapEmail := strings.TrimSpace(os.Getenv("COFFER_BOOTSTRAP_ADMIN_EMAIL"))
	if bootstrapEmail == "" {
		bootstrapEmail = defaultBootstrapEmail
	}

	values := map[string]string{
		"COFFER_MASTER_KEY":               masterKey,
		"COFFER_BOOTSTRAP_ADMIN_EMAIL":    bootstrapEmail,
		"COFFER_BOOTSTRAP_ADMIN_PASSWORD": bootstrapPassword,
		"COFFER_ENV":                      config.EnvDevelopment,
		"COFFER_MIGRATION_DATABASE_URL":   dsn,
		"COFFER_ALLOW_DEGRADED_DB_ROLE":   "1",
		"COFFER_DB_HOST":                  config.DefaultDBHost,
		"COFFER_DB_PORT":                  "5432",
		"COFFER_DB_SSLMODE":               config.DefaultDBSSLMode,
		"COFFER_TRUST_PROXY":              "0",
	}

	if appDSN := strings.TrimSpace(os.Getenv(TestAppDatabaseEnv)); appDSN != "" {
		values["DATABASE_URL"] = appDSN
		values["COFFER_APP_DB_PASSWORD"] = strings.TrimSpace(os.Getenv("COFFER_APP_DB_PASSWORD"))
		if values["COFFER_APP_DB_PASSWORD"] == "" {
			delete(values, "DATABASE_URL")
		}
	} else {
		values["DATABASE_URL"] = dsn
	}

	cfg, err := config.LoadFrom(func(key string) (string, bool) {
		v, ok := values[key]
		return v, ok
	})
	if err != nil {
		t.Fatalf("testutil: test configuration is invalid: %v", err)
	}
	return cfg
}

// Close stops the server and releases the pool. It is registered with t.Cleanup, so
// calling it directly is optional and idempotent.
func (h *Harness) Close() {
	if h == nil {
		return
	}
	if h.server != nil {
		h.server.Close()
		h.server = nil
	}
	if h.db != nil {
		h.db.Close()
		h.db = nil
	}
}

// DB returns the runtime store, for a test that needs to assert on rows directly.
func (h *Harness) DB() *store.DB { return h.db }

// Config returns the configuration the server booted with.
func (h *Harness) Config() *config.Config { return h.cfg }

// Server returns the httptest.Server.
func (h *Harness) Server() *httptest.Server { return h.server }

// URL returns the base URL, without a trailing slash.
func (h *Harness) URL() string {
	if h == nil || h.server == nil {
		return ""
	}
	return h.server.URL
}

// Response is one HTTP response, fully read.
type Response struct {
	Status int
	Body   []byte
	Header http.Header
}

// Decode unmarshals the body into dst, failing the test when it is not valid JSON.
func (r *Response) Decode(t *testing.T, dst any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, dst); err != nil {
		t.Fatalf("response body is not JSON (status %d): %v\nbody: %s", r.Status, err, r.Body)
	}
}

// String returns the body as a string, for a failure message.
func (r *Response) String() string { return string(r.Body) }

// Do sends a request with an optional JSON body and optional bearer token. A nil body
// sends no body. The path may be relative to /api/v1 or absolute from the root.
func (h *Harness) Do(method, path string, body any, token string) *Response {
	h.t.Helper()

	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("testutil: could not encode the request body: %v", err)
		}
		reader = bytes.NewReader(buf)
	}

	url := h.resolve(path)
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		h.t.Fatalf("testutil: could not build a request for %s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatalf("testutil: %s %s failed: %v", method, path, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		h.t.Fatalf("testutil: could not read the response body for %s %s: %v", method, path, err)
	}
	return &Response{Status: resp.StatusCode, Body: payload, Header: resp.Header}
}

// MustDo is Do with a status assertion: it fails the test unless the status is want,
// and returns the response.
func (h *Harness) MustDo(t *testing.T, method, path string, body any, token string) *Response {
	t.Helper()
	resp := h.Do(method, path, body, token)
	if resp.Status != http.StatusOK && resp.Status != http.StatusCreated {
		t.Fatalf("%s %s: expected 200 or 201, got %d: %s", method, path, resp.Status, resp.Body)
	}
	return resp
}

// resolve turns a test path into a URL. A path starting with "/api/" or "/health" or
// "/ready" is used as-is; anything else is treated as an API path.
func (h *Harness) resolve(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	base := h.URL()
	switch {
	case strings.HasPrefix(path, "/api/"), path == "/healthz", path == "/readyz":
		return base + path
	case strings.HasPrefix(path, "/"):
		return base + "/api/v1" + path
	default:
		return base + "/api/v1/" + path
	}
}

// TokenResponse is the body of POST /api/v1/auth/token.
type TokenResponse struct {
	Token string `json:"token"`
	User  struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		OrgID string `json:"org_id"`
		Role  string `json:"role"`
	} `json:"user"`
}

// MintPAT signs in through the real login route and returns the personal access
// token. It is the only way a test obtains a credential for a person.
func (h *Harness) MintPAT(email, password string) (string, error) {
	body := map[string]string{"email": email, "password": password}
	buf, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(h.URL()+"/api/v1/auth/token", "application/json", bytes.NewReader(buf))
	if err != nil {
		return "", fmt.Errorf("testutil: login request failed: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("testutil: could not read the login response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("testutil: login for %s returned %d: %s", email, resp.StatusCode, payload)
	}

	var out TokenResponse
	if err := json.Unmarshal(payload, &out); err != nil {
		return "", fmt.Errorf("testutil: login response is not JSON: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("testutil: login for %s returned no token", email)
	}
	return out.Token, nil
}

// MustMintPAT is MintPAT, failing the test on error.
func (h *Harness) MustMintPAT(t *testing.T, email, password string) string {
	t.Helper()
	token, err := h.MintPAT(email, password)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// PlatformAdminToken signs in as the bootstrap platform admin.
func (h *Harness) PlatformAdminToken(t *testing.T) string {
	t.Helper()
	return h.MustMintPAT(t, h.bootstrapEmail, h.bootstrapPassword)
}

// BootstrapCredentials returns the platform admin credentials, for a test that wants
// to assert on the login route directly.
func (h *Harness) BootstrapCredentials() (email, password string) {
	return h.bootstrapEmail, h.bootstrapPassword
}

// Org is one organization with its users, all created through the real routes.
type Org struct {
	ID            string
	Slug          string
	OwnerEmail    string
	OwnerPassword string
	OwnerToken    string

	h *Harness
}

var orgCounter atomic.Int64

// ChangePassword clears the must-change-password gate for a freshly created account.
//
// Accounts whose password was chosen by a different principal — an organization owner
// created by the platform admin, a member added by an admin — are created with
// must_change_password set (SPEC §4 P1), and every route except this one answers 403
// password_change_required until it is cleared. The harness therefore signs in and calls
// the real POST /api/v1/auth/password, exactly as `coffer passwd` does. Nothing is
// bypassed: a test that gets past this point has proved the real password-change path
// works.
//
// The route revokes every other PAT of the user on success, so the returned token is a
// fresh one and the caller must use it.
func (h *Harness) ChangePassword(t *testing.T, email, currentPassword, newPassword string) string {
	t.Helper()

	token := h.MustMintPAT(t, email, currentPassword)
	resp := h.Do(http.MethodPost, "/api/v1/auth/password", map[string]string{
		"current_password": currentPassword,
		"new_password":     newPassword,
	}, token)
	if resp.Status != http.StatusOK && resp.Status != http.StatusNoContent {
		t.Fatalf("testutil: could not clear the password-change gate for %s: %d: %s",
			email, resp.Status, resp.Body)
	}
	// The old token is revoked by the change; sign in again with the new password.
	return h.MustMintPAT(t, email, newPassword)
}

// NewOrg creates an organization with an owner through the real platform-admin route,
// then signs the owner in. The slug is made unique per process and per call so two
// tests never collide on the global unique constraint.
func (h *Harness) NewOrg(t *testing.T, slug string) *Org {
	t.Helper()

	if slug == "" {
		slug = "org"
	}
	unique := fmt.Sprintf("%s-%d-%s", slug, os.Getpid(), randomHex(4))
	if len(unique) > 63 {
		unique = unique[:63]
	}

	ownerEmail := unique + "@testutil.invalid"
	ownerPassword := "owner-" + randomHex(12) + "-password"

	adminToken := h.PlatformAdminToken(t)
	resp := h.Do(http.MethodPost, "/api/v1/admin/orgs", map[string]string{
		"slug":           unique,
		"owner_email":    ownerEmail,
		"owner_password": ownerPassword,
	}, adminToken)
	if resp.Status != http.StatusOK && resp.Status != http.StatusCreated {
		t.Fatalf("testutil: could not create organization %q: %d: %s", unique, resp.Status, resp.Body)
	}

	org := &Org{
		Slug:          unique,
		OwnerEmail:    ownerEmail,
		OwnerPassword: ownerPassword,
		h:             h,
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp.Body, &created); err == nil {
		org.ID = created.ID
	}

	// The owner's password was chosen by the platform admin, so the account is created
	// with must_change_password set; clear it through the real route before using it.
	org.OwnerPassword = "owner-changed-" + randomHex(12) + "-password"
	org.OwnerToken = h.ChangePassword(t, ownerEmail, ownerPassword, org.OwnerPassword)
	return org
}

// NewProject creates a project through the real route and returns its id.
//
// The id is what store-level helpers need (a data key is keyed by project id, and AAD
// binds it). HTTP paths resolve a project by SLUG, so NewEnv and the secret helpers
// accept either and translate. Returning the id here keeps `project := org.NewProject(...)`
// usable both as a store key and, through that translation, in a URL.
func (o *Org) NewProject(t *testing.T, slug string) string {
	t.Helper()
	resp := o.h.Do(http.MethodPost, "/api/v1/projects", map[string]string{"slug": slug}, o.OwnerToken)
	if resp.Status != http.StatusOK && resp.Status != http.StatusCreated {
		t.Fatalf("testutil: could not create project %q: %d: %s", slug, resp.Status, resp.Body)
	}
	// The route answers {"project":{id,slug,created_at}}.
	var created struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
	}
	resp.Decode(t, &created)
	if created.Project.ID == "" {
		t.Fatalf("testutil: the project route returned no id for %q: %s", slug, resp.Body)
	}
	return created.Project.ID
}

// ProjectSlug resolves a project identifier to the slug the HTTP routes expect.
//
// It accepts a slug as-is and looks up an id through the real list route, so a caller can
// pass whatever NewProject returned without knowing which the routes want.
func (o *Org) ProjectSlug(t *testing.T, project string) string {
	t.Helper()
	if project == "" {
		t.Fatal("testutil: empty project identifier")
	}

	resp := o.h.Do(http.MethodGet, "/api/v1/projects", nil, o.OwnerToken)
	if resp.Status != http.StatusOK {
		t.Fatalf("testutil: could not list projects: %d: %s", resp.Status, resp.Body)
	}
	var listed struct {
		Projects []struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"projects"`
	}
	resp.Decode(t, &listed)

	for _, p := range listed.Projects {
		if p.ID == project || p.Slug == project {
			return p.Slug
		}
	}
	t.Fatalf("testutil: project %q is not visible to %s", project, o.OwnerEmail)
	return ""
}

// NewEnv creates an environment through the real route and returns its id. The project
// may be given as a slug or as the id NewProject returned.
func (o *Org) NewEnv(t *testing.T, project, slug string, protected bool) string {
	t.Helper()
	projectSlug := o.ProjectSlug(t, project)
	resp := o.h.Do(http.MethodPost, "/api/v1/projects/"+projectSlug+"/envs", map[string]any{
		"slug":      slug,
		"protected": protected,
	}, o.OwnerToken)
	if resp.Status != http.StatusOK && resp.Status != http.StatusCreated {
		t.Fatalf("testutil: could not create environment %q: %d: %s", slug, resp.Status, resp.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	resp.Decode(t, &created)
	return created.ID
}

// AddMember creates a member with the given role through the real route and returns
// its email, password and a PAT.
func (o *Org) AddMember(t *testing.T, role string) (email, password, token string) {
	t.Helper()

	email = fmt.Sprintf("%s-%s@testutil.invalid", role, randomHex(6))
	password = role + "-" + randomHex(12) + "-password"

	resp := o.h.Do(http.MethodPost, "/api/v1/members", map[string]string{
		"email":    email,
		"role":     role,
		"password": password,
	}, o.OwnerToken)
	if resp.Status != http.StatusOK && resp.Status != http.StatusCreated {
		t.Fatalf("testutil: could not add a %s member: %d: %s", role, resp.Status, resp.Body)
	}

	// A member's initial password is chosen by an admin, so the account is gated too.
	newPassword := role + "-changed-" + randomHex(12) + "-password"
	token = o.h.ChangePassword(t, email, password, newPassword)
	return email, newPassword, token
}

// AdminToken creates an admin member and returns its PAT.
func (o *Org) AdminToken(t *testing.T) string {
	t.Helper()
	_, _, token := o.AddMember(t, "admin")
	return token
}

// MemberToken creates a member with no grant and returns its PAT.
func (o *Org) MemberToken(t *testing.T) string {
	t.Helper()
	_, _, token := o.AddMember(t, "member")
	return token
}

// MemberWithGrant creates a member, grants it a level on a project and returns its PAT.
func (o *Org) MemberWithGrant(t *testing.T, project, level string) string {
	t.Helper()
	email, _, token := o.AddMember(t, "member")

	resp := o.h.Do(http.MethodPut, "/api/v1/members/"+email+"/grants/"+o.ProjectSlug(t, project),
		map[string]string{"level": level}, o.OwnerToken)
	if resp.Status != http.StatusOK && resp.Status != http.StatusCreated {
		t.Fatalf("testutil: could not grant %s on %s: %d: %s", level, project, resp.Status, resp.Body)
	}
	return token
}

// ServiceToken issues a service token through the real route and returns it once.
func (o *Org) ServiceToken(t *testing.T, project, env, access string) string {
	t.Helper()
	resp := o.h.Do(http.MethodPost, "/api/v1/tokens", map[string]any{
		"project":     project,
		"env":         env,
		"access":      access,
		"ttl_seconds": 3600,
		"name":        "testutil",
	}, o.OwnerToken)
	if resp.Status != http.StatusOK && resp.Status != http.StatusCreated {
		t.Fatalf("testutil: could not issue a service token: %d: %s", resp.Status, resp.Body)
	}
	var created struct {
		Token string `json:"token"`
	}
	resp.Decode(t, &created)
	if created.Token == "" {
		t.Fatal("testutil: the token route returned no token")
	}
	return created.Token
}

// DeleteOrg disables an organization through the real route, for a test that asserts
// immediate revocation.
func (h *Harness) DisableOrg(t *testing.T, slug string) {
	t.Helper()
	adminToken := h.PlatformAdminToken(t)
	resp := h.Do(http.MethodPost, "/api/v1/admin/orgs/"+slug+"/disable", nil, adminToken)
	if resp.Status != http.StatusOK {
		t.Fatalf("testutil: could not disable organization %q: %d: %s", slug, resp.Status, resp.Body)
	}
}
