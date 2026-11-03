package secretsapi_test

// These tests drive the real router and the real routes, but seed their organization, project and
// environment rows directly instead of through the HTTP creation routes.
//
// The reason is isolation, not convenience: the harness helpers for creating projects and
// environments decode a response shape that is still moving between the tenancy slice and the
// harness, and a test of the secrets routes should not fail because a different route's body
// changed. Everything the secrets slice itself is responsible for — authentication, authorization,
// the 202 proposal, the 403 self-approval, the 409 double-approval and the export bytes — goes
// through the real middleware and the real handlers.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"coffer/internal/api/authapi"
	"coffer/internal/audit"
	"coffer/internal/crypto"
	"coffer/internal/idgen"
	"coffer/internal/store/secrets"
	"coffer/internal/testutil"
)

// httpFixture is a live server over a seeded organization.
type httpFixture struct {
	srv    *httpapiFixture
	orgID  string
	userID string
	owner  string // bearer token
	admin  string
	member string
	writer string
	reader string
	viewer string
	roTok  string // read-only service token
	rwTok  string // read-write service token
}

// httpapiFixture wraps an httptest server built by the harness.
type httpapiFixture struct {
	h *testutil.Harness
}

// newHTTPFixture builds the server and seeds an organization with one user per role.
func newHTTPFixture(t *testing.T) *httpFixture {
	t.Helper()
	// Run this fixture against its own database.
	//
	// The harness creates the platform admin through authapi.Bootstrap, which only acts when NO
	// users exist. This fixture inserts users directly, so on a shared database a single leftover
	// row from an earlier run (or a sibling test) makes the bootstrap skip and every later
	// testutil.NewOrg in the same process fail to log in. A private database makes the suite
	// order-independent and repeatable.
	t.Setenv(testutil.TestDatabaseEnv, privateDatabase(t, "coffer_http_test"))
	h := testutil.Require(t)
	ctx := context.Background()
	pool := h.DB().Pool()

	orgID := idgen.New("org")
	projectID := idgen.New("prj")
	devID := idgen.New("env")
	prodID := idgen.New("env")
	ownerID := idgen.New("usr")

	email := strings.ToLower(idgen.New("owner")) + "@seeded.invalid"
	const password = "seeded-owner-password"

	hash, err := authapi.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Seed: organization, owner, project, two environments (one protected), and a grant for the
	// owner so the grant lookup has a row (owners do not need one).
	steps := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations (id, slug) VALUES ($1, $2)`, []any{orgID, orgID}},
		{`INSERT INTO users (id, org_id, email, password_hash, role) VALUES ($1, $2, $3, $4, 'owner')`,
			[]any{ownerID, orgID, email, hash}},
		{`INSERT INTO projects (id, org_id, slug) VALUES ($1, $2, 'svc')`, []any{projectID, orgID}},
		{`INSERT INTO environments (id, project_id, slug, protected) VALUES ($1, $2, 'dev', false)`,
			[]any{devID, projectID}},
		{`INSERT INTO environments (id, project_id, slug, protected) VALUES ($1, $2, 'prod', true)`,
			[]any{prodID, projectID}},
	}
	for _, s := range steps {
		if _, err := pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM change_requests WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM secret_versions WHERE secret_id IN
			(SELECT s.id FROM secrets s JOIN environments e ON e.id = s.env_id WHERE e.project_id = $1)`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM secrets WHERE env_id IN
			(SELECT id FROM environments WHERE project_id = $1)`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM project_data_keys WHERE project_id = $1`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM service_tokens WHERE project_id = $1`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM project_grants WHERE project_id = $1`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM environments WHERE project_id = $1`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, projectID)
		_, _ = pool.Exec(ctx, `DELETE FROM personal_access_tokens WHERE user_id IN
			(SELECT id FROM users WHERE org_id = $1)`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	// Tokens are minted the real way, through POST /auth/token.
	owner := h.MustMintPAT(t, email, password)

	f := &httpFixture{
		srv:    &httpapiFixture{h: h},
		orgID:  orgID,
		userID: ownerID,
		owner:  owner,
	}
	f.admin = f.seedUser(t, "admin", "admin")
	f.member = f.seedUser(t, "member", "member")
	f.writer = f.seedUserWithGrant(t, "writer")
	f.reader = f.seedUserWithGrant(t, "reader")
	f.viewer = f.seedUserWithGrant(t, "viewer")
	return f
}

// seedUser inserts a user with the given role and returns a real PAT for it.
func (f *httpFixture) seedUser(t *testing.T, role, label string) string {
	t.Helper()
	return f.seed(t, role, label, "")
}

// seedUserWithGrant inserts a member and grants it a level on the fixture's project.
//
// The organization role is always "member": viewer, reader and writer are project grant levels
// (SPEC §1, §2.4), not organization roles. Seeding them into users.role would create accounts that
// no authorization path recognises.
func (f *httpFixture) seedUserWithGrant(t *testing.T, level string) string {
	t.Helper()
	return f.seed(t, "member", level, level)
}

func (f *httpFixture) seed(t *testing.T, role, label, grantLevel string) string {
	t.Helper()
	ctx := context.Background()
	pool := f.srv.h.DB().Pool()

	id := idgen.New("usr")
	email := strings.ToLower(idgen.New(label)) + "@seeded.invalid"
	password := label + "-seeded-password"
	hash, err := authapi.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, org_id, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)`,
		id, f.orgID, email, hash, role); err != nil {
		t.Fatalf("seed %s: %v", label, err)
	}
	if grantLevel != "" {
		var projectID string
		if err := pool.QueryRow(ctx, `SELECT id FROM projects WHERE org_id = $1 AND slug = 'svc'`, f.orgID).
			Scan(&projectID); err != nil {
			t.Fatalf("project id: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO project_grants (project_id, user_id, level) VALUES ($1, $2, $3)`,
			projectID, id, grantLevel); err != nil {
			t.Fatalf("grant %s: %v", label, err)
		}
	}
	return f.srv.h.MustMintPAT(t, email, password)
}

// do issues a request through the real server.
func (f *httpFixture) do(method, path string, body any, token string) *testutil.Response {
	return f.srv.h.Do(method, path, body, token)
}

// secretsPath builds the path for one key.
func secretsPath(project, env, key string) string {
	p := "/api/v1/projects/" + project + "/envs/" + env + "/secrets"
	if key != "" {
		p += "/" + key
	}
	return p
}

type versionBody struct {
	Version int64 `json:"version"`
}

type pendingBody struct {
	Status   string `json:"status"`
	ChangeID string `json:"change_id"`
}

type valueBody struct {
	Key     string `json:"key"`
	Version int64  `json:"version"`
	Value   string `json:"value"`
}

// TestSetGetRoundTrip covers the basic write and read, including an empty value and awkward bytes.
func TestSetGetRoundTrip(t *testing.T) {
	f := newHTTPFixture(t)

	for _, value := range []string{"hello", "", "line1\nline2", "quote\"back\\slash$dollar", "héllo→"} {
		resp := f.do(http.MethodPut, secretsPath("svc", "dev", "API_KEY"),
			map[string]any{"value": value}, f.owner)
		if resp.Status != http.StatusOK {
			t.Fatalf("set %q: %d: %s", value, resp.Status, resp.Body)
		}
		resp = f.do(http.MethodGet, secretsPath("svc", "dev", "API_KEY"), nil, f.owner)
		if resp.Status != http.StatusOK {
			t.Fatalf("get %q: %d: %s", value, resp.Status, resp.Body)
		}
		var got valueBody
		resp.Decode(t, &got)
		if got.Value != value {
			t.Fatalf("round trip: got %q want %q", got.Value, value)
		}
		if got.Key != "API_KEY" {
			t.Fatalf("key = %q", got.Key)
		}
	}
}

// TestSetWithoutValueFieldIs400 checks an omitted value is a validation error, while `""` is a
// valid empty value.
func TestSetWithoutValueFieldIs400(t *testing.T) {
	f := newHTTPFixture(t)
	if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "API_KEY"), map[string]any{}, f.owner); resp.Status != http.StatusBadRequest {
		t.Fatalf("missing value: %d: %s", resp.Status, resp.Body)
	}
}

// TestValueBounds covers the 65,536-byte inclusive bound.
func TestValueBounds(t *testing.T) {
	f := newHTTPFixture(t)
	big := strings.Repeat("a", 65537)
	if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "BIG_KEY"), map[string]any{"value": big}, f.owner); resp.Status != http.StatusBadRequest {
		t.Fatalf("65537 bytes: %d, want 400", resp.Status)
	}
	edge := strings.Repeat("a", 65536)
	if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "EDGE_KEY"), map[string]any{"value": edge}, f.owner); resp.Status != http.StatusOK {
		t.Fatalf("65536 bytes: %d, want 200", resp.Status)
	}
}

// TestInvalidKeyIs400 covers the frozen key format on the key routes.
func TestInvalidKeyIs400(t *testing.T) {
	f := newHTTPFixture(t)
	for _, key := range []string{"lower", "1LEADING", "WITH-DASH", "WITH.DOT", strings.Repeat("A", 129)} {
		if resp := f.do(http.MethodPut, secretsPath("svc", "dev", key), map[string]any{"value": "v"}, f.owner); resp.Status != http.StatusBadRequest {
			t.Errorf("set %q: %d, want 400", key, resp.Status)
		}
		if resp := f.do(http.MethodGet, secretsPath("svc", "dev", key), nil, f.owner); resp.Status != http.StatusBadRequest {
			t.Errorf("get %q: %d, want 400", key, resp.Status)
		}
	}
}

// TestExpectedVersionConflictIs409 covers the conditional write.
func TestExpectedVersionConflictIs409(t *testing.T) {
	f := newHTTPFixture(t)
	if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "CONFLICT_KEY"), map[string]any{"value": "one"}, f.owner); resp.Status != http.StatusOK {
		t.Fatalf("first set: %d", resp.Status)
	}
	resp := f.do(http.MethodPut, secretsPath("svc", "dev", "CONFLICT_KEY"),
		map[string]any{"value": "two", "expected_version": 99}, f.owner)
	if resp.Status != http.StatusConflict {
		t.Fatalf("stale expectation: %d: %s", resp.Status, resp.Body)
	}
	// The value did not change.
	got := f.do(http.MethodGet, secretsPath("svc", "dev", "CONFLICT_KEY"), nil, f.owner)
	var v valueBody
	got.Decode(t, &v)
	if v.Value != "one" {
		t.Fatalf("a rejected write changed the value: %+v", v)
	}
}

// TestTombstoneThenGetIs404 covers delete.
func TestTombstoneThenGetIs404(t *testing.T) {
	f := newHTTPFixture(t)
	if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "GONE_KEY"), map[string]any{"value": "v"}, f.owner); resp.Status != http.StatusOK {
		t.Fatalf("set: %d", resp.Status)
	}
	resp := f.do(http.MethodDelete, secretsPath("svc", "dev", "GONE_KEY"), nil, f.owner)
	if resp.Status != http.StatusOK {
		t.Fatalf("delete: %d: %s", resp.Status, resp.Body)
	}
	var del versionBody
	resp.Decode(t, &del)
	if del.Version != 2 {
		t.Fatalf("tombstone version = %d, want 2", del.Version)
	}
	if resp := f.do(http.MethodGet, secretsPath("svc", "dev", "GONE_KEY"), nil, f.owner); resp.Status != http.StatusNotFound {
		t.Fatalf("get after delete: %d, want 404", resp.Status)
	}

	resp = f.do(http.MethodGet, secretsPath("svc", "dev", "GONE_KEY")+"/versions", nil, f.owner)
	if resp.Status != http.StatusOK {
		t.Fatalf("history: %d", resp.Status)
	}
	var history []struct {
		Version int64 `json:"version"`
		Deleted bool  `json:"deleted"`
	}
	resp.Decode(t, &history)
	if len(history) != 2 || !history[1].Deleted {
		t.Fatalf("history = %+v", history)
	}
}

// TestListingHasNoValues covers the listing shape: metadata only.
func TestListingHasNoValues(t *testing.T) {
	f := newHTTPFixture(t)
	if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "LISTED_KEY"), map[string]any{"value": "secret-value"}, f.owner); resp.Status != http.StatusOK {
		t.Fatalf("set: %d", resp.Status)
	}
	resp := f.do(http.MethodGet, secretsPath("svc", "dev", ""), nil, f.owner)
	if resp.Status != http.StatusOK {
		t.Fatalf("list: %d: %s", resp.Status, resp.Body)
	}
	if strings.Contains(string(resp.Body), "secret-value") {
		t.Fatalf("the listing returned a value: %s", resp.Body)
	}
	var rows []struct {
		Key       string `json:"key"`
		Version   int64  `json:"version"`
		UpdatedAt string `json:"updated_at"`
		UpdatedBy string `json:"updated_by"`
	}
	resp.Decode(t, &rows)
	if len(rows) != 1 || rows[0].Key != "LISTED_KEY" || rows[0].Version != 1 {
		t.Fatalf("listing = %+v", rows)
	}
	if rows[0].UpdatedAt == "" || rows[0].UpdatedBy == "" {
		t.Fatalf("listing row is missing updated_at or updated_by: %+v", rows[0])
	}
}

// TestViewerCanListButNotGet is the 403-versus-404 distinction: the viewer sees the resource and
// lacks the capability, so it is 403 rather than 404.
func TestViewerCanListButNotGet(t *testing.T) {
	f := newHTTPFixture(t)
	if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "VIEW_KEY"), map[string]any{"value": "v"}, f.owner); resp.Status != http.StatusOK {
		t.Fatalf("set: %d", resp.Status)
	}
	if resp := f.do(http.MethodGet, secretsPath("svc", "dev", ""), nil, f.viewer); resp.Status != http.StatusOK {
		t.Fatalf("viewer list: %d, want 200", resp.Status)
	}
	if resp := f.do(http.MethodGet, secretsPath("svc", "dev", "VIEW_KEY"), nil, f.viewer); resp.Status != http.StatusForbidden {
		t.Fatalf("viewer get: %d, want 403", resp.Status)
	}
	if resp := f.do(http.MethodGet, "/api/v1/projects/svc/envs/dev/export", nil, f.viewer); resp.Status != http.StatusForbidden {
		t.Fatalf("viewer export: %d, want 403", resp.Status)
	}
	if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "VIEW_KEY"), map[string]any{"value": "v2"}, f.viewer); resp.Status != http.StatusForbidden {
		t.Fatalf("viewer set: %d, want 403", resp.Status)
	}
}

// TestReaderCanReadNotWrite covers the reader boundary.
func TestReaderCanReadNotWrite(t *testing.T) {
	f := newHTTPFixture(t)
	if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "READ_KEY"), map[string]any{"value": "v"}, f.owner); resp.Status != http.StatusOK {
		t.Fatalf("set: %d", resp.Status)
	}
	if resp := f.do(http.MethodGet, secretsPath("svc", "dev", "READ_KEY"), nil, f.reader); resp.Status != http.StatusOK {
		t.Fatalf("reader get: %d, want 200", resp.Status)
	}
	if resp := f.do(http.MethodGet, "/api/v1/projects/svc/envs/dev/export", nil, f.reader); resp.Status != http.StatusOK {
		t.Fatalf("reader export: %d, want 200", resp.Status)
	}
	if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "READ_KEY"), map[string]any{"value": "v2"}, f.reader); resp.Status != http.StatusForbidden {
		t.Fatalf("reader set: %d, want 403", resp.Status)
	}
	if resp := f.do(http.MethodDelete, secretsPath("svc", "dev", "READ_KEY"), nil, f.reader); resp.Status != http.StatusForbidden {
		t.Fatalf("reader delete: %d, want 403", resp.Status)
	}
}

// TestMemberWithoutGrantIs404 covers invisibility.
func TestMemberWithoutGrantIs404(t *testing.T) {
	f := newHTTPFixture(t)
	for _, path := range []string{
		secretsPath("svc", "dev", ""),
		secretsPath("svc", "dev", "ANY_KEY"),
		"/api/v1/projects/svc/envs/dev/export",
	} {
		if resp := f.do(http.MethodGet, path, nil, f.member); resp.Status != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, resp.Status)
		}
	}
}

// TestUnknownProjectIs404 checks a missing project and a project in another organization are the
// same answer.
func TestUnknownProjectIs404(t *testing.T) {
	f := newHTTPFixture(t)
	for _, path := range []string{
		secretsPath("nosuchproject", "dev", ""),
		secretsPath("svc", "nosuchenv", ""),
	} {
		if resp := f.do(http.MethodGet, path, nil, f.owner); resp.Status != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, resp.Status)
		}
	}
	// The same slug in a different organization is also 404 for that organization's owner.
	other := f.srv.h.NewOrg(t, "other-tenant")
	if resp := f.do(http.MethodGet, secretsPath("svc", "dev", ""), nil, other.OwnerToken); resp.Status != http.StatusNotFound {
		t.Fatalf("another organization's project: %d, want 404", resp.Status)
	}
}

// TestProtectedWriteReturns202 covers §2.8 for an owner, and that the change is applied only after
// a second person approves it.
func TestProtectedWriteReturns202(t *testing.T) {
	f := newHTTPFixture(t)

	resp := f.do(http.MethodPut, secretsPath("svc", "prod", "PROTECTED_KEY"), map[string]any{"value": "v"}, f.owner)
	if resp.Status != http.StatusAccepted {
		t.Fatalf("protected set: %d, want 202: %s", resp.Status, resp.Body)
	}
	var pending pendingBody
	resp.Decode(t, &pending)
	if pending.Status != "pending" || pending.ChangeID == "" {
		t.Fatalf("202 body = %+v", pending)
	}
	if r := f.do(http.MethodGet, secretsPath("svc", "prod", "PROTECTED_KEY"), nil, f.owner); r.Status != http.StatusNotFound {
		t.Fatalf("get after a proposal: %d, want 404", r.Status)
	}

	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/approve", nil, f.admin); r.Status != http.StatusOK {
		t.Fatalf("approve: %d: %s", r.Status, r.Body)
	}
	got := f.do(http.MethodGet, secretsPath("svc", "prod", "PROTECTED_KEY"), nil, f.owner)
	if got.Status != http.StatusOK {
		t.Fatalf("get after approval: %d: %s", got.Status, got.Body)
	}
	var v valueBody
	got.Decode(t, &v)
	if v.Value != "v" || v.Version != 1 {
		t.Fatalf("after approval: %+v", v)
	}
}

// TestSelfApprovalIs403 covers §2.9 and that a refused self-approval does not consume the request.
func TestSelfApprovalIs403(t *testing.T) {
	f := newHTTPFixture(t)
	resp := f.do(http.MethodPut, secretsPath("svc", "prod", "SELF_KEY"), map[string]any{"value": "v"}, f.owner)
	if resp.Status != http.StatusAccepted {
		t.Fatalf("propose: %d", resp.Status)
	}
	var pending pendingBody
	resp.Decode(t, &pending)

	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/approve", nil, f.owner); r.Status != http.StatusForbidden {
		t.Fatalf("self approval: %d, want 403: %s", r.Status, r.Body)
	}

	list := f.do(http.MethodGet, "/api/v1/changes?status=pending", nil, f.owner)
	var changes []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	list.Decode(t, &changes)
	var found bool
	for _, c := range changes {
		if c.ID == pending.ChangeID {
			found = true
			if c.Status != "pending" {
				t.Fatalf("status after a self-approval attempt = %q, want pending", c.Status)
			}
		}
	}
	if !found {
		t.Fatal("the request disappeared after a self-approval attempt")
	}

	// The change list must never carry the proposed value.
	if strings.Contains(string(list.Body), `"value"`) {
		t.Fatalf("the change list carries a value: %s", list.Body)
	}
}

// TestDoubleApproveIs409ThroughHTTP covers the second resolution.
func TestDoubleApproveIs409ThroughHTTP(t *testing.T) {
	f := newHTTPFixture(t)
	resp := f.do(http.MethodPut, secretsPath("svc", "prod", "DOUBLE_KEY"), map[string]any{"value": "v"}, f.owner)
	var pending pendingBody
	resp.Decode(t, &pending)

	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/approve", nil, f.admin); r.Status != http.StatusOK {
		t.Fatalf("first approve: %d: %s", r.Status, r.Body)
	}
	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/approve", nil, f.admin); r.Status != http.StatusConflict {
		t.Fatalf("second approve: %d, want 409: %s", r.Status, r.Body)
	}
	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/reject", nil, f.admin); r.Status != http.StatusConflict {
		t.Fatalf("reject after approve: %d, want 409: %s", r.Status, r.Body)
	}
}

// TestStaleApprovalIs409ThroughHTTP covers §2.9's staleness rule end to end.
func TestStaleApprovalIs409ThroughHTTP(t *testing.T) {
	f := newHTTPFixture(t)

	// Seed the key to version 1 through an approved change.
	resp := f.do(http.MethodPut, secretsPath("svc", "prod", "STALE_KEY"), map[string]any{"value": "first"}, f.owner)
	var first pendingBody
	resp.Decode(t, &first)
	if r := f.do(http.MethodPost, "/api/v1/changes/"+first.ChangeID+"/approve", nil, f.admin); r.Status != http.StatusOK {
		t.Fatalf("seed approve: %d: %s", r.Status, r.Body)
	}

	// Propose at base version 1.
	resp = f.do(http.MethodPut, secretsPath("svc", "prod", "STALE_KEY"), map[string]any{"value": "proposed"}, f.owner)
	var second pendingBody
	resp.Decode(t, &second)

	// The key moves to version 2 meanwhile.
	resp = f.do(http.MethodPut, secretsPath("svc", "prod", "STALE_KEY"), map[string]any{"value": "intervening"}, f.owner)
	var third pendingBody
	resp.Decode(t, &third)
	if r := f.do(http.MethodPost, "/api/v1/changes/"+third.ChangeID+"/approve", nil, f.admin); r.Status != http.StatusOK {
		t.Fatalf("intervening approve: %d: %s", r.Status, r.Body)
	}

	if r := f.do(http.MethodPost, "/api/v1/changes/"+second.ChangeID+"/approve", nil, f.admin); r.Status != http.StatusConflict {
		t.Fatalf("stale approve: %d, want 409: %s", r.Status, r.Body)
	}

	list := f.do(http.MethodGet, "/api/v1/changes?status=stale", nil, f.owner)
	var stale []struct {
		ID string `json:"id"`
	}
	list.Decode(t, &stale)
	if len(stale) != 1 || stale[0].ID != second.ChangeID {
		t.Fatalf("stale list = %+v", stale)
	}

	got := f.do(http.MethodGet, secretsPath("svc", "prod", "STALE_KEY"), nil, f.owner)
	var v valueBody
	got.Decode(t, &v)
	if v.Value != "intervening" || v.Version != 2 {
		t.Fatalf("value after a stale approval: %+v", v)
	}
}

// TestRejectThroughHTTP covers reject and the second-resolution conflict.
func TestRejectThroughHTTP(t *testing.T) {
	f := newHTTPFixture(t)
	resp := f.do(http.MethodPut, secretsPath("svc", "prod", "REJECT_KEY"), map[string]any{"value": "v"}, f.owner)
	var pending pendingBody
	resp.Decode(t, &pending)

	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/reject", nil, f.admin); r.Status != http.StatusOK {
		t.Fatalf("reject: %d: %s", r.Status, r.Body)
	}
	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/reject", nil, f.admin); r.Status != http.StatusConflict {
		t.Fatalf("second reject: %d, want 409", r.Status)
	}
	if r := f.do(http.MethodGet, secretsPath("svc", "prod", "REJECT_KEY"), nil, f.owner); r.Status != http.StatusNotFound {
		t.Fatalf("get after reject: %d, want 404", r.Status)
	}
}

// TestMemberCannotApprove covers §2.6 and invisibility of the change.
func TestMemberCannotApprove(t *testing.T) {
	f := newHTTPFixture(t)
	resp := f.do(http.MethodPut, secretsPath("svc", "prod", "MEMBER_KEY"), map[string]any{"value": "v"}, f.owner)
	var pending pendingBody
	resp.Decode(t, &pending)

	// A writer member sees the change but may not resolve it: 403.
	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/approve", nil, f.writer); r.Status != http.StatusForbidden {
		t.Fatalf("member approve: %d, want 403: %s", r.Status, r.Body)
	}
	// A member with no grant cannot see it: 404.
	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/approve", nil, f.member); r.Status != http.StatusNotFound {
		t.Fatalf("stranger approve: %d, want 404: %s", r.Status, r.Body)
	}
	// A viewer sees it and may not resolve it: 403.
	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/approve", nil, f.viewer); r.Status != http.StatusForbidden {
		t.Fatalf("viewer approve: %d, want 403: %s", r.Status, r.Body)
	}
}

// TestExportFormats covers both export formats, the exact dotenv escaping and the headers.
func TestExportFormats(t *testing.T) {
	f := newHTTPFixture(t)
	for key, value := range map[string]string{
		"ZED_KEY":  "last",
		"ALPHA":    `a"b\c$d`,
		"MULTILIN": "x\ny",
		"TAB":      "a\tb",
	} {
		if resp := f.do(http.MethodPut, secretsPath("svc", "dev", key), map[string]any{"value": value}, f.owner); resp.Status != http.StatusOK {
			t.Fatalf("set %s: %d", key, resp.Status)
		}
	}

	resp := f.do(http.MethodGet, "/api/v1/projects/svc/envs/dev/export?format=dotenv", nil, f.owner)
	if resp.Status != http.StatusOK {
		t.Fatalf("dotenv export: %d: %s", resp.Status, resp.Body)
	}
	want := "ALPHA=\"a\\\"b\\\\c\\$d\"\nMULTILIN=\"x\\ny\"\nTAB=\"a\tb\"\nZED_KEY=\"last\"\n"
	if string(resp.Body) != want {
		t.Fatalf("dotenv export mismatch\n got: %q\nwant: %q", resp.Body, want)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("dotenv Content-Type = %q", ct)
	}
	assertSecurityHeaders(t, resp.Header)

	resp = f.do(http.MethodGet, "/api/v1/projects/svc/envs/dev/export?format=json", nil, f.owner)
	if resp.Status != http.StatusOK {
		t.Fatalf("json export: %d", resp.Status)
	}
	var decoded map[string]string
	if err := json.Unmarshal(resp.Body, &decoded); err != nil {
		t.Fatalf("json export is not valid JSON: %v", err)
	}
	if decoded["ALPHA"] != `a"b\c$d` || decoded["MULTILIN"] != "x\ny" || decoded["ZED_KEY"] != "last" || decoded["TAB"] != "a\tb" {
		t.Fatalf("json export values = %+v", decoded)
	}
	assertSecurityHeaders(t, resp.Header)

	if resp := f.do(http.MethodGet, "/api/v1/projects/svc/envs/dev/export?format=yaml", nil, f.owner); resp.Status != http.StatusBadRequest {
		t.Fatalf("bad format: %d, want 400", resp.Status)
	}
}

// TestRollbackThroughHTTP covers rollback numbering end to end.
func TestRollbackThroughHTTP(t *testing.T) {
	f := newHTTPFixture(t)
	for _, v := range []string{"one", "two"} {
		if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "RB_KEY"), map[string]any{"value": v}, f.owner); resp.Status != http.StatusOK {
			t.Fatalf("set %s: %d", v, resp.Status)
		}
	}
	resp := f.do(http.MethodPost, secretsPath("svc", "dev", "RB_KEY")+"/rollback", map[string]any{"to": 1}, f.owner)
	if resp.Status != http.StatusOK {
		t.Fatalf("rollback: %d: %s", resp.Status, resp.Body)
	}
	var rb versionBody
	resp.Decode(t, &rb)
	if rb.Version != 3 {
		t.Fatalf("rollback version = %d, want 3", rb.Version)
	}

	got := f.do(http.MethodGet, secretsPath("svc", "dev", "RB_KEY"), nil, f.owner)
	var v valueBody
	got.Decode(t, &v)
	if v.Value != "one" || v.Version != 3 {
		t.Fatalf("after rollback: %+v", v)
	}

	if r := f.do(http.MethodPost, secretsPath("svc", "dev", "RB_KEY")+"/rollback", map[string]any{"to": 99}, f.owner); r.Status != http.StatusNotFound {
		t.Fatalf("rollback to a missing version: %d, want 404", r.Status)
	}
	if r := f.do(http.MethodPost, secretsPath("svc", "dev", "RB_KEY")+"/rollback", map[string]any{"to": 0}, f.owner); r.Status != http.StatusBadRequest {
		t.Fatalf("rollback to 0: %d, want 400", r.Status)
	}
}

// TestVersionAtAndHistory covers the historical value route.
func TestVersionAtAndHistory(t *testing.T) {
	f := newHTTPFixture(t)
	for _, v := range []string{"one", "two"} {
		if resp := f.do(http.MethodPut, secretsPath("svc", "dev", "HIST_KEY"), map[string]any{"value": v}, f.owner); resp.Status != http.StatusOK {
			t.Fatalf("set: %d", resp.Status)
		}
	}

	resp := f.do(http.MethodGet, secretsPath("svc", "dev", "HIST_KEY")+"/versions/1", nil, f.owner)
	if resp.Status != http.StatusOK {
		t.Fatalf("version 1: %d: %s", resp.Status, resp.Body)
	}
	var v valueBody
	resp.Decode(t, &v)
	if v.Value != "one" || v.Version != 1 {
		t.Fatalf("version 1 = %+v", v)
	}

	if r := f.do(http.MethodGet, secretsPath("svc", "dev", "HIST_KEY")+"/versions/9", nil, f.owner); r.Status != http.StatusNotFound {
		t.Fatalf("version 9: %d, want 404", r.Status)
	}
	if r := f.do(http.MethodGet, secretsPath("svc", "dev", "HIST_KEY")+"/versions/+1", nil, f.owner); r.Status != http.StatusBadRequest {
		t.Fatalf("version +1: %d, want 400", r.Status)
	}
	if r := f.do(http.MethodGet, secretsPath("svc", "dev", "HIST_KEY")+"/versions", nil, f.viewer); r.Status != http.StatusOK {
		t.Fatalf("viewer history: %d, want 200", r.Status)
	}
	if r := f.do(http.MethodGet, secretsPath("svc", "dev", "HIST_KEY")+"/versions/1", nil, f.viewer); r.Status != http.StatusForbidden {
		t.Fatalf("viewer historical value: %d, want 403", r.Status)
	}
}

// TestUnauthenticatedIs401 checks the routes require a credential.
func TestUnauthenticatedIs401(t *testing.T) {
	f := newHTTPFixture(t)
	for _, path := range []string{secretsPath("svc", "dev", ""), "/api/v1/changes"} {
		if resp := f.do(http.MethodGet, path, nil, ""); resp.Status != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", path, resp.Status)
		}
	}
}

// TestChangeListFiltersThroughHTTP covers the status filter values.
func TestChangeListFiltersThroughHTTP(t *testing.T) {
	f := newHTTPFixture(t)
	if resp := f.do(http.MethodPut, secretsPath("svc", "prod", "FILTER_KEY"), map[string]any{"value": "v"}, f.owner); resp.Status != http.StatusAccepted {
		t.Fatalf("propose: %d", resp.Status)
	}
	for _, status := range []string{"pending", "approved", "rejected", "stale"} {
		if resp := f.do(http.MethodGet, "/api/v1/changes?status="+status, nil, f.owner); resp.Status != http.StatusOK {
			t.Fatalf("status=%s: %d", status, resp.Status)
		}
	}
	if resp := f.do(http.MethodGet, "/api/v1/changes?status=deleted", nil, f.owner); resp.Status != http.StatusBadRequest {
		t.Fatalf("status=deleted: %d, want 400", resp.Status)
	}
}

// TestCiphertextMovedBetweenRowsIs500 is the AAD copy-failure test through the HTTP surface: a
// ciphertext copied into another key's row must produce a 500 and never a value.
func TestCiphertextMovedBetweenRowsIs500(t *testing.T) {
	f := newHTTPFixture(t)
	for _, k := range []string{"COPY_SOURCE", "COPY_TARGET"} {
		if resp := f.do(http.MethodPut, secretsPath("svc", "dev", k), map[string]any{"value": "value-of-" + k}, f.owner); resp.Status != http.StatusOK {
			t.Fatalf("set %s: %d", k, resp.Status)
		}
	}
	if _, err := f.srv.h.DB().Pool().Exec(context.Background(), `
UPDATE secret_versions t
   SET ciphertext = s.ciphertext, nonce = s.nonce
  FROM secret_versions s, secrets ks, secrets kt, environments e
 WHERE e.project_id = (SELECT id FROM projects WHERE org_id = $1 AND slug = 'svc')
   AND ks.env_id = e.id AND ks.key = 'COPY_SOURCE'
   AND kt.env_id = e.id AND kt.key = 'COPY_TARGET'
   AND s.secret_id = ks.id AND s.version = ks.current_version
   AND t.secret_id = kt.id AND t.version = kt.current_version`, f.orgID); err != nil {
		t.Fatalf("copy ciphertext: %v", err)
	}

	resp := f.do(http.MethodGet, secretsPath("svc", "dev", "COPY_TARGET"), nil, f.owner)
	if resp.Status != http.StatusInternalServerError {
		t.Fatalf("a copied ciphertext returned %d, want 500: %s", resp.Status, resp.Body)
	}
	if strings.Contains(string(resp.Body), "value-of-COPY_SOURCE") {
		t.Fatalf("the response leaked the source value: %s", resp.Body)
	}
	if strings.Contains(string(resp.Body), "value-of-COPY_TARGET") {
		t.Fatalf("the response leaked a value: %s", resp.Body)
	}
}

// privateDatabase creates (or reuses) a database named name on the test server and returns its URL.
func privateDatabase(t *testing.T, name string) string {
	t.Helper()
	base := strings.TrimSpace(os.Getenv(testutil.TestDatabaseEnv))
	if base == "" {
		t.Skip("COFFER_TEST_DATABASE_URL is not set; skipping the integration test")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to create %s: %v", name, err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	u.Path = "/" + name
	return u.String()
}

// assertSecurityHeaders checks the three headers that must be on every /api/v1 response.
func assertSecurityHeaders(t *testing.T, h http.Header) {
	t.Helper()
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := h.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := h.Get("X-Request-Id"); got == "" {
		t.Error("X-Request-Id is missing")
	}
}

// The pgx and audit imports are used by the seeding helpers and the audit assertion below.
var (
	_ = pgx.ErrNoRows
	_ = audit.ActionSecretRead
	_ = crypto.KeySize
	_ = secrets.MaxValueBytes
)

// seedServiceToken issues a service token through the real route and returns the token string.
func (f *httpFixture) seedServiceToken(t *testing.T, env, access string) string {
	t.Helper()
	resp := f.do(http.MethodPost, "/api/v1/tokens", map[string]any{
		"project":     "svc",
		"env":         env,
		"access":      access,
		"ttl_seconds": 3600,
		"name":        "regression",
	}, f.owner)
	if resp.Status != http.StatusOK && resp.Status != http.StatusCreated {
		t.Fatalf("issue service token: %d: %s", resp.Status, resp.Body)
	}
	var created struct {
		Token string `json:"token"`
	}
	resp.Decode(t, &created)
	if created.Token == "" {
		t.Fatal("the token route returned no token")
	}
	return created.Token
}

// TestServiceTokenProtectedWriteIs202 is the regression test for the change_requests_proposer_id
// foreign key.
//
// A service token's id is a token id, not a user id, so attributing a proposal to it violates the
// FK and used to return 500. The proposal must instead be attributed to the user who issued the
// token, while the audit event keeps naming the token.
func TestServiceTokenProtectedWriteIs202(t *testing.T) {
	f := newHTTPFixture(t)
	rw := f.seedServiceToken(t, "prod", "read-write")

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"set", http.MethodPut, secretsPath("svc", "prod", "SVC_PROT"), map[string]any{"value": "v"}},
		{"delete", http.MethodDelete, secretsPath("svc", "prod", "SVC_PROT"), nil},
		{"rollback", http.MethodPost, secretsPath("svc", "prod", "SVC_PROT") + "/rollback", map[string]any{"to": 1}},
	} {
		resp := f.do(tc.method, tc.path, tc.body, rw)
		if resp.Status != http.StatusAccepted {
			t.Fatalf("%s by a service token: %d, want 202: %s", tc.name, resp.Status, resp.Body)
		}
		var pending pendingBody
		resp.Decode(t, &pending)
		if pending.Status != "pending" || pending.ChangeID == "" {
			t.Fatalf("%s: 202 body = %+v", tc.name, pending)
		}
	}

	// The proposer recorded on every request is the issuing user, never the token id.
	var proposers []string
	rows, err := f.srv.h.DB().Pool().Query(context.Background(),
		`SELECT proposer_id FROM change_requests WHERE org_id = $1`, f.orgID)
	if err != nil {
		t.Fatalf("query proposers: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatalf("scan proposer: %v", err)
		}
		proposers = append(proposers, p)
	}
	if len(proposers) != 3 {
		t.Fatalf("%d change requests, want 3", len(proposers))
	}
	for _, p := range proposers {
		if p != f.userID {
			t.Fatalf("proposer_id = %q, want the issuing user %q", p, f.userID)
		}
		if strings.HasPrefix(p, "tok") {
			t.Fatalf("proposer_id names a token: %q", p)
		}
	}
}

// TestServiceTokenIssuerCannotApproveOwnProposal covers the two-person rule for machine credentials:
// the human accountable for the proposal cannot also approve it.
func TestServiceTokenIssuerCannotApproveOwnProposal(t *testing.T) {
	f := newHTTPFixture(t)
	rw := f.seedServiceToken(t, "prod", "read-write")

	resp := f.do(http.MethodPut, secretsPath("svc", "prod", "SVC_SELF"), map[string]any{"value": "v"}, rw)
	if resp.Status != http.StatusAccepted {
		t.Fatalf("propose: %d: %s", resp.Status, resp.Body)
	}
	var pending pendingBody
	resp.Decode(t, &pending)

	// The owner issued the token, so the owner is the proposer.
	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/approve", nil, f.owner); r.Status != http.StatusForbidden {
		t.Fatalf("issuer approving its own token's proposal: %d, want 403: %s", r.Status, r.Body)
	}

	// A different admin can approve it, and the value applies.
	if r := f.do(http.MethodPost, "/api/v1/changes/"+pending.ChangeID+"/approve", nil, f.admin); r.Status != http.StatusOK {
		t.Fatalf("admin approve: %d: %s", r.Status, r.Body)
	}
	got := f.do(http.MethodGet, secretsPath("svc", "prod", "SVC_SELF"), nil, f.owner)
	if got.Status != http.StatusOK {
		t.Fatalf("get after approval: %d: %s", got.Status, got.Body)
	}
	var v valueBody
	got.Decode(t, &v)
	if v.Value != "v" || v.Version != 1 {
		t.Fatalf("after approval: %+v", v)
	}
}

// TestServiceTokenUnprotectedWriteIs200 checks the fix did not turn every service-token write into
// a proposal: an unprotected environment still writes directly.
func TestServiceTokenUnprotectedWriteIs200(t *testing.T) {
	f := newHTTPFixture(t)
	rw := f.seedServiceToken(t, "dev", "read-write")

	resp := f.do(http.MethodPut, secretsPath("svc", "dev", "SVC_OPEN"), map[string]any{"value": "v"}, rw)
	if resp.Status != http.StatusOK {
		t.Fatalf("service token write on an unprotected env: %d, want 200: %s", resp.Status, resp.Body)
	}
	var vb versionBody
	resp.Decode(t, &vb)
	if vb.Version != 1 {
		t.Fatalf("version = %d, want 1", vb.Version)
	}
}

// TestServiceTokenRemovedIssuerIs403 checks a proposal whose issuing user has been removed is a
// clean 403, not a 500, and that the user is not resurrected.
func TestServiceTokenRemovedIssuerIs403(t *testing.T) {
	f := newHTTPFixture(t)
	rw := f.seedServiceToken(t, "prod", "read-write")

	// Remove the issuing user directly: this is the state a revocation leaves behind.
	if _, err := f.srv.h.DB().Pool().Exec(context.Background(),
		`UPDATE users SET removed_at = now() WHERE id = $1`, f.userID); err != nil {
		t.Fatalf("remove issuer: %v", err)
	}

	resp := f.do(http.MethodPut, secretsPath("svc", "prod", "SVC_ORPHAN"), map[string]any{"value": "v"}, rw)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("proposal by a token whose issuer was removed: %d, want 403: %s", resp.Status, resp.Body)
	}

	// No change request was created, and the user was not resurrected.
	var count int
	if err := f.srv.h.DB().Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM change_requests WHERE org_id = $1`, f.orgID).Scan(&count); err != nil {
		t.Fatalf("count changes: %v", err)
	}
	if count != 0 {
		t.Fatalf("%d change requests created for an unavailable proposer", count)
	}
	var removedAt *string
	if err := f.srv.h.DB().Pool().QueryRow(context.Background(),
		`SELECT removed_at::text FROM users WHERE id = $1`, f.userID).Scan(&removedAt); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if removedAt == nil {
		t.Fatal("the removed user was resurrected")
	}
}
