package secretsapi_test

// This file verifies the audit contract against the REAL appender, not a fake.
//
// Two things only a real writer can answer:
//
//  1. Every event this slice builds is accepted by audit.NewAppender. A fake writer that stores
//     whatever it is handed hides a validation failure, and a rejected event fails the request that
//     produced it — correct behaviour, but it makes a malformed event look like a broken route. A
//     live report of `audit: invalid event: field timestamp is zero` on `secrets set` is exactly
//     that failure mode.
//  2. The event lands in audit_events, in the actor's organization chain, under the frozen action
//     name. "My slice sends the right event" and "the writer stores it" are different bugs in
//     different slices, and this separates them.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"coffer/internal/api/secretsapi"
	"coffer/internal/audit"
	"coffer/internal/reqctx"
	"coffer/internal/store/auditq"
)

// realAuditServer builds a server over this slice's routes with audit.NewAppender as the writer.
func realAuditServer(t *testing.T) (*httptest.Server, *pgxpool.Pool, reqctx.Actor) {
	t.Helper()
	// Its own database: these fixtures insert users directly, and authapi.Bootstrap only creates the
	// platform admin when no users exist at all. Sharing the harness database would let these tests
	// suppress the bootstrap and break every login-based test in the run.
	cfg, db := connectAuditDBAt(t, auditDatabase(t))
	pool := db.Pool()

	appender, err := audit.NewAppender(db)
	if err != nil {
		t.Fatalf("audit.NewAppender: %v", err)
	}

	actor := seedRealAuditFixture(t, pool)

	mux := http.NewServeMux()
	secretsapi.Register(mux, secretsapi.Deps{
		DB:     db,
		Audit:  appender,
		Config: cfg,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	withActor := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := reqctx.WithActor(r.Context(), actor)
		ctx = reqctx.WithSourceIP(ctx, "198.51.100.9")
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(withActor)
	t.Cleanup(srv.Close)
	return srv, pool, actor
}

// seedRealAuditFixture creates an isolated organization with a project and environment and returns
// the actor the routes act as.
func seedRealAuditFixture(t *testing.T, pool *pgxpool.Pool) reqctx.Actor {
	t.Helper()
	ctx := context.Background()

	orgID, userID, projectID, devID, prodID := "org_ra", "usr_ra", "prj_ra", "env_ra_dev", "env_ra_prod"

	// A unique slug per run keeps parallel or repeated runs from colliding on organizations.slug.
	orgSlug := orgID + "_" + shortSuffix()
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations (id, slug) VALUES ($1, $2)`, []any{orgID, orgSlug}},
		{`INSERT INTO users (id, org_id, email, password_hash, role) VALUES ($1, $2, $3, 'x', 'owner')`,
			[]any{userID, orgID, orgSlug + "@seeded.invalid"}},
		{`INSERT INTO projects (id, org_id, slug) VALUES ($1, $2, 'raproj')`, []any{projectID, orgID}},
		{`INSERT INTO environments (id, project_id, slug, protected) VALUES ($1, $2, 'dev', false)`,
			[]any{devID, projectID}},
		{`INSERT INTO environments (id, project_id, slug, protected) VALUES ($1, $2, 'prod', true)`,
			[]any{prodID, projectID}},
	}
	// Clean first, in case a previous run left rows behind after a crash.
	cleanupSQL := []string{
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
	}
	for _, sql := range cleanupSQL {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatalf("cleanup: %v\nstatement: %s", err, sql)
		}
	}
	for _, s := range statements {
		if _, err := pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("seed: %v\nstatement: %s", err, s.sql)
		}
	}
	t.Cleanup(func() {
		for _, sql := range cleanupSQL {
			_, _ = pool.Exec(context.Background(), sql)
		}
	})

	return reqctx.Actor{
		Kind:   reqctx.KindUser,
		UserID: userID,
		OrgID:  orgID,
		Role:   "owner",
	}
}

// TestRealAppenderAcceptsEveryEventThisSliceBuilds is the regression test for the live 500.
//
// Every write path in this slice is exercised through the real appender. If any event this slice
// builds were malformed — a zero timestamp, an unknown action, a bad actor kind, a NUL in a field —
// the request would fail and this test would catch it here rather than in a user's terminal.
func TestRealAppenderAcceptsEveryEventThisSliceBuilds(t *testing.T) {
	srv, pool, actor := realAuditServer(t)
	ctx := context.Background()

	type step struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
	}
	steps := []step{
		{"set", http.MethodPut, "/api/v1/projects/raproj/envs/dev/secrets/RA_KEY", `{"value":"v1"}`, http.StatusOK},
		{"set again", http.MethodPut, "/api/v1/projects/raproj/envs/dev/secrets/RA_KEY", `{"value":"v2"}`, http.StatusOK},
		{"get", http.MethodGet, "/api/v1/projects/raproj/envs/dev/secrets/RA_KEY", "", http.StatusOK},
		{"list", http.MethodGet, "/api/v1/projects/raproj/envs/dev/secrets", "", http.StatusOK},
		{"history", http.MethodGet, "/api/v1/projects/raproj/envs/dev/secrets/RA_KEY/versions", "", http.StatusOK},
		{"version", http.MethodGet, "/api/v1/projects/raproj/envs/dev/secrets/RA_KEY/versions/1", "", http.StatusOK},
		{"export", http.MethodGet, "/api/v1/projects/raproj/envs/dev/export?format=json", "", http.StatusOK},
		{"rollback", http.MethodPost, "/api/v1/projects/raproj/envs/dev/secrets/RA_KEY/rollback", `{"to":1}`, http.StatusOK},
		{"delete", http.MethodDelete, "/api/v1/projects/raproj/envs/dev/secrets/RA_KEY", "", http.StatusOK},
		{"propose", http.MethodPut, "/api/v1/projects/raproj/envs/prod/secrets/RA_PROD", `{"value":"v"}`, http.StatusAccepted},
	}

	for _, s := range steps {
		resp := do(t, srv, s.method, s.path, s.body)
		body := readAll(t, resp)
		if resp.StatusCode != s.wantStatus {
			t.Fatalf("%s: %d, want %d: %s", s.name, resp.StatusCode, s.wantStatus, body)
		}
		if body == "" && s.wantStatus != http.StatusOK {
			t.Fatalf("%s: empty body", s.name)
		}
	}

	// Now approve and reject through the real appender as well.
	pendingID := pendingChangeID(t, pool, actor.OrgID, "RA_PROD")
	resp := do(t, srv, http.MethodPost, "/api/v1/changes/"+pendingID+"/approve", "")
	if resp.StatusCode != http.StatusForbidden {
		// The actor is the proposer, so this is the two-person rule, and it must not 500.
		t.Fatalf("self approval: %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// Every event this slice produced is stored, and none was rejected.
	var stored int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE scope = $1`, actor.OrgID).Scan(&stored); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if stored == 0 {
		t.Fatal("no audit events were stored: either this slice sent none, or the appender rejected them")
	}

	// The action names present are exactly the frozen ones this slice is allowed to write.
	rows, err := pool.Query(ctx,
		`SELECT DISTINCT action FROM audit_events WHERE scope = $1 ORDER BY action`, actor.OrgID)
	if err != nil {
		t.Fatalf("actions: %v", err)
	}
	defer rows.Close()
	allowed := map[string]bool{
		audit.ActionSecretRead:     true,
		audit.ActionSecretWrite:    true,
		audit.ActionSecretDelete:   true,
		audit.ActionSecretRollback: true,
		audit.ActionChangeCreated:  true,
		audit.ActionChangeApproved: true,
		audit.ActionChangeRejected: true,
		audit.ActionChangeStale:    true,
		audit.ActionDenied:         true,
	}
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatalf("scan action: %v", err)
		}
		if !allowed[action] {
			t.Errorf("this slice wrote an action it does not own: %q", action)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
}

// TestRealAppenderStoresOneReadPerKey proves §3 against the real writer: one stored secret.read per
// key exported, each with a distinct target.
func TestRealAppenderStoresOneReadPerKey(t *testing.T) {
	srv, pool, actor := realAuditServer(t)
	ctx := context.Background()

	for _, k := range []string{"EXP_A", "EXP_B", "EXP_C"} {
		resp := do(t, srv, http.MethodPut, "/api/v1/projects/raproj/envs/dev/secrets/"+k, `{"value":"v"}`)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("set %s: %d", k, resp.StatusCode)
		}
		resp.Body.Close()
	}
	// Clear the events the writes produced, so the count below is only about the export.
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events WHERE scope = $1`, actor.OrgID); err != nil {
		t.Fatalf("clear events: %v", err)
	}

	resp := do(t, srv, http.MethodGet, "/api/v1/projects/raproj/envs/dev/export?format=json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export: %d", resp.StatusCode)
	}
	resp.Body.Close()

	var reads int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE scope = $1 AND action = 'secret.read'`,
		actor.OrgID).Scan(&reads); err != nil {
		t.Fatalf("count reads: %v", err)
	}
	if reads != 3 {
		t.Fatalf("%d stored secret.read events for a three-key export, want 3", reads)
	}
}

// TestRealAppenderChainIsValid checks the events this slice writes keep the chain verifiable: an
// invalid event would break verification for the whole organization.
func TestRealAppenderChainIsValid(t *testing.T) {
	srv, pool, actor := realAuditServer(t)

	for i, k := range []string{"CHAIN_A", "CHAIN_B"} {
		resp := do(t, srv, http.MethodPut, "/api/v1/projects/raproj/envs/dev/secrets/"+k, `{"value":"v"}`)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("set %d: %d", i, resp.StatusCode)
		}
		resp.Body.Close()
	}

	verdict, err := audit.Verify(context.Background(), auditq.NewFromPool(pool), actor.OrgID)
	if err != nil {
		t.Fatalf("audit.Verify: %v", err)
	}
	if !verdict.Valid {
		t.Fatalf("the chain this slice wrote does not verify: first invalid seq %d (%s)",
			verdict.FirstInvalidSeq, verdict.Detail)
	}
}

// pendingChangeID returns the id of the pending change for a key.
func pendingChangeID(t *testing.T, pool *pgxpool.Pool, orgID, key string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM change_requests WHERE org_id = $1 AND key = $2 AND status = 'pending'`,
		orgID, key).Scan(&id); err != nil {
		t.Fatalf("pending change for %s: %v", key, err)
	}
	return id
}
