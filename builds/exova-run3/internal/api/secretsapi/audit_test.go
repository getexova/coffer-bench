package secretsapi_test

// This file tests the audit behaviour of the handlers with a recording audit.Writer.
//
// It cannot go through the shared harness: testutil builds its router with audit.NopWriter(), so no
// event is ever stored and a test that counted rows in audit_events could never pass for any slice.
// Registering this slice's routes on a fresh mux with a recording writer exercises the real
// handlers, the real store and the real per-key audit calls, and nothing else.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"coffer/internal/api/secretsapi"
	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/reqctx"
	"coffer/internal/store"
)

// recordingWriter captures audit events instead of storing them.
type recordingWriter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (w *recordingWriter) Append(_ context.Context, e audit.Event) (audit.Event, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, e)
	return e, nil
}

func (w *recordingWriter) AppendTx(_ context.Context, _ pgx.Tx, e audit.Event) (audit.Event, error) {
	return w.Append(context.Background(), e)
}

func (w *recordingWriter) actions() map[string]int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]int, len(w.events))
	for _, e := range w.events {
		out[e.Action]++
	}
	return out
}

func (w *recordingWriter) count(action string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, e := range w.events {
		if e.Action == action {
			n++
		}
	}
	return n
}

func (w *recordingWriter) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = nil
}

// auditedServer builds a server over this slice's routes only, with a recording audit writer and a
// fixed actor injected by a wrapper. Authentication itself is not under test here.
func auditedServer(t *testing.T) (*httptest.Server, *recordingWriter, reqctx.Actor) {
	t.Helper()
	cfg, db := connectAuditDB(t)

	// Seed an organization, owner, project and environment directly, for the same isolation reason
	// as the HTTP tests: this file is about audit events, not about another slice's routes.
	actor := seedAuditFixture(t, db)

	rec := &recordingWriter{}
	mux := http.NewServeMux()
	secretsapi.Register(mux, secretsapi.Deps{
		DB:     db,
		Audit:  rec,
		Config: cfg,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	withActor := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := reqctx.WithActor(r.Context(), actor)
		ctx = reqctx.WithSourceIP(ctx, "203.0.113.7")
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(withActor)
	t.Cleanup(srv.Close)
	return srv, rec, actor
}

// seedAuditFixture creates the rows the routes need and returns the actor they act as.
func seedAuditFixture(t *testing.T, db *store.DB) reqctx.Actor {
	t.Helper()
	ctx := context.Background()
	pool := db.Pool()

	orgID, userID, projectID, envID := "org_audit", "usr_audit", "prj_audit", "env_audit"
	statements := []string{
		`DELETE FROM change_requests WHERE org_id = '` + orgID + `'`,
		`DELETE FROM secret_versions WHERE secret_id IN (SELECT s.id FROM secrets s JOIN environments e ON e.id = s.env_id WHERE e.project_id = '` + projectID + `')`,
		`DELETE FROM secrets WHERE env_id IN (SELECT id FROM environments WHERE project_id = '` + projectID + `')`,
		`DELETE FROM project_data_keys WHERE project_id = '` + projectID + `'`,
		`DELETE FROM environments WHERE project_id = '` + projectID + `'`,
		`DELETE FROM projects WHERE id = '` + projectID + `'`,
		`DELETE FROM audit_events WHERE scope = '` + orgID + `'`,
		`DELETE FROM audit_heads WHERE scope = '` + orgID + `'`,
		`DELETE FROM users WHERE id = '` + userID + `'`,
		`DELETE FROM organizations WHERE id = '` + orgID + `'`,
		`INSERT INTO organizations (id, slug) VALUES ('` + orgID + `', 'audit-org')`,
		`INSERT INTO users (id, org_id, email, password_hash, role) VALUES ('` + userID + `', '` + orgID + `', 'audit@seeded.invalid', 'x', 'owner')`,
		`INSERT INTO projects (id, org_id, slug) VALUES ('` + projectID + `', '` + orgID + `', 'auditproj')`,
		`INSERT INTO environments (id, project_id, slug, protected) VALUES ('` + envID + `', '` + projectID + `', 'dev', false)`,
	}
	for _, sql := range statements {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatalf("seed: %v\nstatement: %s", err, sql)
		}
	}

	return reqctx.Actor{
		Kind:   reqctx.KindUser,
		UserID: userID,
		OrgID:  orgID,
		Role:   "owner",
	}
}

// do issues a request against the slice-only server.
func do(t *testing.T, srv *httptest.Server, method, path, body string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = stringReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

type sr struct {
	s string
	i int
}

func stringReader(s string) io.Reader { return &sr{s: s} }

func (r *sr) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

// TestExportWritesOneReadPerKey is the §3 requirement: one secret.read per key exported.
func TestExportWritesOneReadPerKey(t *testing.T) {
	srv, rec, _ := auditedServer(t)

	for _, k := range []string{"AUDIT_A", "AUDIT_B", "AUDIT_C"} {
		resp := do(t, srv, http.MethodPut, "/api/v1/projects/auditproj/envs/dev/secrets/"+k,
			`{"value":"v"}`)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("set %s: %d", k, resp.StatusCode)
		}
	}

	rec.reset()
	resp := do(t, srv, http.MethodGet, "/api/v1/projects/auditproj/envs/dev/export?format=json", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export: %d", resp.StatusCode)
	}
	if got := rec.count(audit.ActionSecretRead); got != 3 {
		t.Fatalf("%d secret.read events for a three-key export, want 3 (actions: %v)", got, rec.actions())
	}
	// One event per key, so the targets are distinct and name the key.
	seen := map[string]bool{}
	rec.mu.Lock()
	for _, e := range rec.events {
		if e.Action == audit.ActionSecretRead {
			if seen[e.Target] {
				t.Fatalf("duplicate target %q", e.Target)
			}
			seen[e.Target] = true
		}
	}
	rec.mu.Unlock()
	if len(seen) != 3 {
		t.Fatalf("%d distinct targets, want 3", len(seen))
	}
}

// TestGetWritesOneRead covers the single-key get exit.
func TestGetWritesOneRead(t *testing.T) {
	srv, rec, _ := auditedServer(t)

	resp := do(t, srv, http.MethodPut, "/api/v1/projects/auditproj/envs/dev/secrets/GET_KEY", `{"value":"v"}`)
	resp.Body.Close()

	rec.reset()
	resp = do(t, srv, http.MethodGet, "/api/v1/projects/auditproj/envs/dev/secrets/GET_KEY", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get: %d", resp.StatusCode)
	}
	if got := rec.count(audit.ActionSecretRead); got != 1 {
		t.Fatalf("%d secret.read events, want 1", got)
	}

	// A historical read is a value exit too.
	resp = do(t, srv, http.MethodGet, "/api/v1/projects/auditproj/envs/dev/secrets/GET_KEY/versions/1", "")
	resp.Body.Close()
	if got := rec.count(audit.ActionSecretRead); got != 2 {
		t.Fatalf("%d secret.read events after a version read, want 2", got)
	}
}

// TestWriteDeleteRollbackActions covers the three mutation action names.
func TestWriteDeleteRollbackActions(t *testing.T) {
	srv, rec, _ := auditedServer(t)

	resp := do(t, srv, http.MethodPut, "/api/v1/projects/auditproj/envs/dev/secrets/WDR_KEY", `{"value":"one"}`)
	resp.Body.Close()
	resp = do(t, srv, http.MethodPut, "/api/v1/projects/auditproj/envs/dev/secrets/WDR_KEY", `{"value":"two"}`)
	resp.Body.Close()
	resp = do(t, srv, http.MethodPost, "/api/v1/projects/auditproj/envs/dev/secrets/WDR_KEY/rollback", `{"to":1}`)
	resp.Body.Close()
	resp = do(t, srv, http.MethodDelete, "/api/v1/projects/auditproj/envs/dev/secrets/WDR_KEY", "")
	resp.Body.Close()

	actions := rec.actions()
	if actions[audit.ActionSecretWrite] != 2 {
		t.Errorf("secret.write count = %d, want 2 (all: %v)", actions[audit.ActionSecretWrite], actions)
	}
	if actions[audit.ActionSecretRollback] != 1 {
		t.Errorf("secret.rollback count = %d, want 1 (all: %v)", actions[audit.ActionSecretRollback], actions)
	}
	if actions[audit.ActionSecretDelete] != 1 {
		t.Errorf("secret.delete count = %d, want 1 (all: %v)", actions[audit.ActionSecretDelete], actions)
	}
}

// TestNoAuditEventCarriesAValue is the "never logged" rule: no event's target or any field contains
// the plaintext, for any operation.
func TestNoAuditEventCarriesAValue(t *testing.T) {
	srv, rec, _ := auditedServer(t)
	const secretValue = "super-secret-plaintext-12345"

	resp := do(t, srv, http.MethodPut, "/api/v1/projects/auditproj/envs/dev/secrets/LEAK_KEY",
		`{"value":"`+secretValue+`"}`)
	resp.Body.Close()
	resp = do(t, srv, http.MethodGet, "/api/v1/projects/auditproj/envs/dev/secrets/LEAK_KEY", "")
	resp.Body.Close()
	resp = do(t, srv, http.MethodGet, "/api/v1/projects/auditproj/envs/dev/export?format=dotenv", "")
	resp.Body.Close()

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.events) == 0 {
		t.Fatal("no audit events were recorded")
	}
	for _, e := range rec.events {
		for _, field := range []string{e.Target, e.ActorID, e.Action, e.OrgID, e.SourceIP, e.Scope} {
			if field == secretValue {
				t.Fatalf("an audit field equals the secret value")
			}
			if len(field) >= len(secretValue) && contains(field, secretValue) {
				t.Fatalf("an audit field %q contains the secret value", field)
			}
		}
	}
}

// readAll drains and closes a response body.
func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// shortSuffix returns a short random suffix for a unique test slug.
func shortSuffix() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000"
	}
	return hex.EncodeToString(b[:])
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestProtectedProposalAuditsChangeCreated covers change.created and that the proposal stores no
// plaintext in the audit event.
func TestProtectedProposalAuditsChangeCreated(t *testing.T) {
	srv, rec, actor := auditedServer(t)
	pool := seedPool(t)
	_ = actor

	// A protected environment has to exist for this fixture.
	// (The fixture creates "dev" unprotected; "prod" is created here.)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO environments (id, project_id, slug, protected)
		 VALUES ('env_audit_prod', 'prj_audit', 'prod', true)
		 ON CONFLICT (project_id, slug) DO UPDATE SET protected = true`); err != nil {
		t.Fatalf("seed protected env: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM change_requests WHERE org_id = 'org_audit'`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM environments WHERE project_id = 'prj_audit'`)
	})

	resp := do(t, srv, http.MethodPut, "/api/v1/projects/auditproj/envs/prod/secrets/CHANGE_KEY",
		`{"value":"proposed-value"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("proposal: %d, want 202", resp.StatusCode)
	}
	if got := rec.count(audit.ActionChangeCreated); got != 1 {
		t.Fatalf("%d change.created events, want 1 (all: %v)", got, rec.actions())
	}
	// Nothing was written to the secret itself.
	if got := rec.count(audit.ActionSecretWrite); got != 0 {
		t.Fatalf("a proposal wrote a secret: %v", rec.actions())
	}
}

// connectAuditDB builds a store.DB over the test database without importing internal/testutil.
//
// It cannot use the shared harness: harness.go imports internal/httpapi, which imports this package
// to register its routes, so importing testutil from a test in this package is an import cycle. The
// configuration mirrors what the harness uses, in the gated degraded single-role mode.
func connectAuditDB(t *testing.T) (*config.Config, *store.DB) {
	t.Helper()
	return connectAuditDBAt(t, strings.TrimSpace(os.Getenv("COFFER_TEST_DATABASE_URL")))
}

// auditDatabase returns a connection string for a database private to the audit tests, creating it
// on first use.
//
// These fixtures insert users directly, and authapi.Bootstrap creates the platform admin only when
// no users exist. Sharing the harness database would let a fixture that runs first suppress the
// bootstrap and break every login-based test in the same run.
func auditDatabase(t *testing.T) string {
	t.Helper()
	base := strings.TrimSpace(os.Getenv("COFFER_TEST_DATABASE_URL"))
	if base == "" {
		t.Skip("COFFER_TEST_DATABASE_URL is not set; skipping the integration test")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	const name = "coffer_audit_test"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to create the audit test database: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("create audit test database: %v", err)
		}
	}
	u.Path = "/" + name
	return u.String()
}

// connectAuditDBAt connects to a specific database and applies the migrations.
func connectAuditDBAt(t *testing.T, dsn string) (*config.Config, *store.DB) {
	t.Helper()
	if dsn == "" {
		t.Skip("COFFER_TEST_DATABASE_URL is not set; skipping the integration test")
	}
	cfg, err := config.LoadFrom(func(key string) (string, bool) {
		switch key {
		case "COFFER_MASTER_KEY":
			return base64.StdEncoding.EncodeToString(stableBytes(dsn, "master-key", 32)), true
		case "COFFER_BOOTSTRAP_ADMIN_EMAIL":
			return "audit-bootstrap@seeded.invalid", true
		case "COFFER_BOOTSTRAP_ADMIN_PASSWORD":
			return "audit-bootstrap-password", true
		case "COFFER_ENV":
			return "development", true
		case "COFFER_ALLOW_DEGRADED_DB_ROLE":
			return "1", true
		case "COFFER_MIGRATION_DATABASE_URL":
			return dsn, true
		case "DATABASE_URL":
			return dsn, true
		case "POSTGRES_DB":
			return "coffer_test", true
		default:
			return "", false
		}
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx := context.Background()
	migrateSerialized(t, dsn, cfg, discard())
	db, err := store.Connect(ctx, cfg, discard())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return cfg, db
}

// seedPool returns the pool of a fresh connection, for the tests that need one directly.
func seedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	_, db := connectAuditDB(t)
	return db.Pool()
}

// stableBytes derives a deterministic key from the DSN, so every test process that shares the test
// database derives the same master key. It is a test-only value for a throwaway database.
func stableBytes(dsn, label string, n int) []byte {
	sum := sha256.Sum256([]byte(label + "\x00" + dsn))
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = sum[i%len(sum)]
	}
	return out
}

// discard keeps migration output out of the test log.
func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// migrateSerialized applies the migrations while holding a cluster-wide advisory lock.
//
// PostgreSQL roles are cluster-wide, not per-database, so the CREATE ROLE coffer_app block in
// 0001_init.sql collides when two packages migrate different databases in the same cluster at the
// same time ("duplicate key value violates unique constraint pg_authid_rolname_index"). `go test`
// runs packages in parallel and each of this slice's test files migrates its own private database,
// so the migrations are serialised here on the shared database, which every test process can reach.
//
// The lock key is an arbitrary constant; it only has to be the same in every process that migrates
// this cluster.
func migrateSerialized(t *testing.T, targetDSN string, cfg *config.Config, log *slog.Logger) {
	t.Helper()
	base := strings.TrimSpace(os.Getenv("COFFER_TEST_DATABASE_URL"))
	if base == "" {
		t.Fatalf("COFFER_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to take the migration lock: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	const lockKey = int64(0x636f6666657231) // "coffe r1"
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		t.Fatalf("take the migration lock: %v", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockKey)
	}()

	if err := store.Migrate(ctx, cfg, log); err != nil {
		t.Fatalf("migrate %s: %v", targetDSN, err)
	}
}

// gatedServer builds a slice-only server whose actor can be marked must-change-password, which is
// what the authentication middleware does for a user whose administrator-set password is unchanged.
func gatedServer(t *testing.T, gated bool) *httptest.Server {
	t.Helper()
	cfg, db := connectAuditDB(t)
	actor := seedAuditFixture(t, db)

	mux := http.NewServeMux()
	secretsapi.Register(mux, secretsapi.Deps{
		DB:     db,
		Audit:  audit.NopWriter(),
		Config: cfg,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	withActor := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := reqctx.WithActor(r.Context(), actor)
		ctx = reqctx.WithSourceIP(ctx, "198.51.100.10")
		ctx = reqctx.WithMustChangePassword(ctx, gated)
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(withActor)
	t.Cleanup(srv.Close)
	return srv
}

// TestMustChangeGateLetsNormalUsersThrough checks the gate does not over-reach: with the flag clear,
// the same actor's requests behave normally.
func TestMustChangeGateLetsNormalUsersThrough(t *testing.T) {
	srv := gatedServer(t, false)

	resp := do(t, srv, http.MethodPut, "/api/v1/projects/auditproj/envs/dev/secrets/OK_KEY", `{"value":"v"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set with the flag clear: %d, want 200: %s", resp.StatusCode, readAll(t, resp))
	}
	resp.Body.Close()

	resp = do(t, srv, http.MethodGet, "/api/v1/projects/auditproj/envs/dev/secrets/OK_KEY", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get with the flag clear: %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, srv, http.MethodGet, "/api/v1/changes", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change list with the flag clear: %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}
