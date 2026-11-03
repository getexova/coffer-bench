package auditq_test

// Tests for the read layer, against a real database.
//
// The API tests cover these queries through HTTP; these cover the parts the API does
// not expose — limit clamping, the empty-scope semantics of Head, and the guarantee
// that a scan never crosses scopes — so a regression in the query layer fails here
// rather than as a confusing HTTP status.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"coffer/internal/audit"
	"coffer/internal/config"
	"coffer/internal/store"
	"coffer/internal/store/auditq"
)

const testDSNEnv = "COFFER_TEST_DATABASE_URL"

type harness struct {
	db       *store.DB
	appender *audit.Appender
	reader   *auditq.Store
	scope    string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv(testDSNEnv))
	if dsn == "" {
		t.Skipf("%s is not set; skipping the auditq test (set it to a postgres URL to run)", testDSNEnv)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	values := map[string]string{
		"COFFER_MASTER_KEY":               "0J4n1s0XQ2m8bV3kR7pY6tL9wZ2cF5hD8gK1nM4qS0U=",
		"COFFER_BOOTSTRAP_ADMIN_EMAIL":    "platform-admin@auditq-test.invalid",
		"COFFER_BOOTSTRAP_ADMIN_PASSWORD": "auditq-test-bootstrap-password",
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

	return &harness{
		db:       db,
		appender: appender,
		reader:   auditq.New(db),
		scope:    fmt.Sprintf("org_q_%d_%d", os.Getpid(), time.Now().UnixNano()),
	}
}

func (h *harness) seed(t *testing.T, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if _, err := h.appender.Append(context.Background(), audit.Event{
			Scope:     h.scope,
			Timestamp: time.Now().UTC(),
			ActorID:   "user_q",
			ActorKind: audit.ActorUser,
			OrgID:     h.scope,
			Action:    audit.ActionSecretRead,
			Target:    fmt.Sprintf("project/p/env/e/key/K%d", i),
			SourceIP:  "203.0.113.7",
			Result:    audit.ResultSuccess,
		}); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}
}

// TestListLimitClamping pins the default and the cap at the query layer, where they
// are defined, rather than relying on the HTTP tests to notice a change.
func TestListLimitClamping(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.seed(t, 5)

	cases := []struct {
		name  string
		limit int
		want  int
	}{
		{"zero_is_default", 0, 5},
		{"negative_is_default", -1, 5},
		{"explicit", 2, 2},
		{"above_cap_is_clamped", auditq.MaxLimit + 5000, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := h.reader.List(ctx, auditq.Filter{Scope: h.scope, Limit: tc.limit})
			if err != nil {
				t.Fatalf("List failed: %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("limit %d returned %d events, expected %d", tc.limit, len(got), tc.want)
			}
		})
	}

	if auditq.DefaultLimit != 100 || auditq.MaxLimit != 1000 {
		t.Fatalf("the frozen limits changed: default %d, cap %d", auditq.DefaultLimit, auditq.MaxLimit)
	}
}

// TestListIsNewestFirst: `limit` must take the most recent events, not the oldest.
func TestListIsNewestFirst(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.seed(t, 4)

	got, err := h.reader.List(ctx, auditq.Filter{Scope: h.scope, Limit: 2})
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(got) != 2 || got[0].Seq != 4 || got[1].Seq != 3 {
		t.Fatalf("expected the two newest events (seq 4, 3), got %d events starting at seq %d", len(got), got[0].Seq)
	}
}

// TestHeadOnEmptyScope: a scope that has never had an event reports Present false and
// no error. That is the state every organization starts in, and the verifier depends
// on being able to tell it from a deleted head.
func TestHeadOnEmptyScope(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	head, err := h.reader.Head(ctx, h.scope+"_never_used")
	if err != nil {
		t.Fatalf("Head returned an error for an unused scope: %v", err)
	}
	if head.Present {
		t.Fatalf("an unused scope reported a present head: %+v", head)
	}
}

// TestHeadAfterAppend: after one append the head is present and describes the row.
func TestHeadAfterAppend(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.seed(t, 1)

	head, err := h.reader.Head(ctx, h.scope)
	if err != nil {
		t.Fatalf("Head failed: %v", err)
	}
	if !head.Present || head.Seq != 1 || len(head.Hash) != 64 {
		t.Fatalf("unexpected head after one append: %+v", head)
	}
}

// TestScanScopeNeverCrossesScopes: a scan of one scope must not return another's rows,
// even when both hold events. This is the query-level tenant boundary.
func TestScanScopeNeverCrossesScopes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.seed(t, 3)

	otherScope := h.scope + "_other"
	if _, err := h.appender.Append(ctx, audit.Event{
		Scope:     otherScope,
		Timestamp: time.Now().UTC(),
		ActorID:   "user_other",
		ActorKind: audit.ActorUser,
		OrgID:     otherScope,
		Action:    audit.ActionSecretWrite,
		Target:    "project/p/env/e/key/OTHER_TENANT",
		SourceIP:  "198.51.100.1",
		Result:    audit.ResultSuccess,
	}); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	rows, err := h.reader.ScanScope(ctx, h.scope, 0, 1000)
	if err != nil {
		t.Fatalf("ScanScope failed: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("the scan returned %d rows, expected 3", len(rows))
	}
	for _, row := range rows {
		if row.Scope != h.scope {
			t.Fatalf("the scan returned a row from scope %q", row.Scope)
		}
		if strings.Contains(row.Target, "OTHER_TENANT") {
			t.Fatal("the scan returned another scope's row")
		}
	}
}

// TestScanScopeIsAscending: the verifier's gap detection depends on strictly ascending
// sequence order, so the query must guarantee it.
func TestScanScopeIsAscending(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.seed(t, 6)

	rows, err := h.reader.ScanScope(ctx, h.scope, 0, 1000)
	if err != nil {
		t.Fatalf("ScanScope failed: %v", err)
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].Seq <= rows[i-1].Seq {
			t.Fatalf("rows are not strictly ascending: seq %d followed by %d", rows[i-1].Seq, rows[i].Seq)
		}
	}

	// afterSeq is exclusive.
	rows, err = h.reader.ScanScope(ctx, h.scope, 3, 1000)
	if err != nil {
		t.Fatalf("ScanScope failed: %v", err)
	}
	if len(rows) != 3 || rows[0].Seq != 4 {
		t.Fatalf("afterSeq 3 returned %d rows starting at seq %d, expected 3 starting at 4", len(rows), rows[0].Seq)
	}
}

// TestScanScopeRebuildsCanonicalBytes: the row the query returns must be enough to
// recompute its own hash. A column the query forgets — scope was the real bug here —
// makes every row hash differently and reports a false tamper.
func TestScanScopeRebuildsCanonicalBytes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.seed(t, 2)

	rows, err := h.reader.ScanScope(ctx, h.scope, 0, 1000)
	if err != nil {
		t.Fatalf("ScanScope failed: %v", err)
	}
	for _, row := range rows {
		if row.Scope == "" {
			t.Fatal("the scan returned a row with an empty scope; the canonical bytes would not match")
		}
		if row.OrgID == "" {
			t.Fatal("the scan returned a row with an empty org_id")
		}
		if row.ActorKind == "" || row.Result == "" {
			t.Fatal("the scan returned a row with an empty actor_kind or result")
		}
		if got := row.ComputeHash(); got != row.Hash {
			t.Fatalf("seq %d: the hash rebuilt from the scanned row is not the stored hash\n rebuilt: %s\n  stored: %s", row.Seq, got, row.Hash)
		}
	}
}

// TestCountAndScopes: the operator helpers see what is there.
func TestCountAndScopes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.seed(t, 4)

	n, err := h.reader.Count(ctx, h.scope)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if n != 4 {
		t.Fatalf("Count returned %d, expected 4", n)
	}

	scopes, err := h.reader.Scopes(ctx)
	if err != nil {
		t.Fatalf("Scopes failed: %v", err)
	}
	found := false
	for _, s := range scopes {
		if s == h.scope {
			found = true
		}
	}
	if !found {
		t.Fatalf("Scopes did not list %q", h.scope)
	}
}

// TestNilPoolIsAnError: a store with no database returns an error rather than an empty
// result, so a misconfigured server does not look like an empty audit log.
func TestNilPoolIsAnError(t *testing.T) {
	empty := auditq.New(nil)
	if _, err := empty.List(context.Background(), auditq.Filter{Scope: "x"}); err == nil {
		t.Fatal("List on a store with no pool returned no error")
	}
	if _, err := empty.Head(context.Background(), "x"); err == nil {
		t.Fatal("Head on a store with no pool returned no error")
	}
	if _, err := empty.ScanScope(context.Background(), "x", 0, 10); err == nil {
		t.Fatal("ScanScope on a store with no pool returned no error")
	}
}
