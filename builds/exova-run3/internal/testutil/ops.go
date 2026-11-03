package testutil

// Ops extension to the shared harness (E5). Nothing here duplicates harness.go: the
// additions are the handles the operations slice needs to test what it ships — the raw
// test database URL, a schema reset that reproduces what scripts/restore.sh does, a
// /readyz poller, and a check for a built CLI binary.
//
// Same rule as the rest of this package: no backdoors and no test-only seams. A helper
// that needs a credential gets it from the environment or through a real route.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestDatabaseURL returns the test database URL, skipping the test when it is unset.
//
// Require() gives a fully booted harness; this is for a test that needs the raw
// connection string instead — a backup/restore round trip, or an assertion on rows that
// the HTTP surface does not expose. The URL must belong to a role that can create the
// schema and roles, because a reset drops the schema and a boot recreates it.
func TestDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(TestDatabaseEnv))
	if dsn == "" {
		t.Skipf("%s is not set; skipping (set it to a postgres URL to run)", TestDatabaseEnv)
	}
	return dsn
}

// ResetSchema reproduces the state scripts/restore.sh leaves behind: the public schema is
// dropped and recreated empty, with no tables, no grants and no schema_migrations rows.
//
// It exists so a restore path can be tested end to end: reset the schema, load a dump,
// boot the server, and assert that the boot re-applies the role grants and that the audit
// chain still verifies. It is destructive and only ever touches the test database.
func ResetSchema(t *testing.T, dsn string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("testutil: could not connect to the test database to reset it: %v", err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		_ = conn.Close(closeCtx)
	}()

	// Two statements, one per call: DROP SCHEMA ... CASCADE cannot share a simple query
	// with CREATE SCHEMA on every PostgreSQL build, and ON_ERROR_STOP semantics matter
	// more here than saving a round trip.
	if _, err := conn.Exec(ctx, `DROP SCHEMA IF EXISTS public CASCADE`); err != nil {
		t.Fatalf("testutil: could not drop the public schema: %v", err)
	}
	if _, err := conn.Exec(ctx, `CREATE SCHEMA public`); err != nil {
		t.Fatalf("testutil: could not recreate the public schema: %v", err)
	}
}

// ReadyResult is one /readyz observation.
type ReadyResult struct {
	Status int
	Body   string
}

// Ready is true when the server reported itself ready.
func (r ReadyResult) Ready() bool { return r.Status == http.StatusOK }

// ProbeReady calls GET /readyz once. It never fails the test: a 503 before the database is
// reachable is an expected observation, not an error.
func ProbeReady(t *testing.T, baseURL string) ReadyResult {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(strings.TrimRight(baseURL, "/") + "/readyz")
	if err != nil {
		t.Fatalf("testutil: GET /readyz failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		t.Fatalf("testutil: could not read the /readyz body: %v", err)
	}
	return ReadyResult{Status: resp.StatusCode, Body: string(body)}
}

// WaitReady polls /readyz until it answers 200, and returns the last observation. It fails
// the test after the timeout, reporting the last status and body so the failure names the
// dependency that was not ready instead of only saying "timed out".
func WaitReady(t *testing.T, baseURL string, timeout time.Duration) ReadyResult {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last ReadyResult
	for {
		last = ProbeReady(t, baseURL)
		if last.Ready() {
			return last
		}
		if time.Now().After(deadline) {
			t.Fatalf("testutil: /readyz was not ready within %s; last status %d, body %q",
				timeout, last.Status, last.Body)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ServerBinary returns the path to a built ./bin/coffer, skipping the test when it has not
// been built. End-to-end tests that drive the real CLI or the real server process call
// this so a machine that only ran `go test` skips instead of failing on a missing binary.
//
// Build it with ./scripts/build.sh.
func ServerBinary(t *testing.T) string {
	t.Helper()

	path := strings.TrimSpace(os.Getenv("COFFER_BIN"))
	if path == "" {
		path = "../../bin/coffer"
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		t.Skipf("no coffer binary at %s; run ./scripts/build.sh to enable this test", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Skipf("%s is not executable; run ./scripts/build.sh", path)
	}
	return path
}

// DescribeReady formats a ReadyResult for a failure message.
func DescribeReady(r ReadyResult) string {
	return fmt.Sprintf("status %d, body %q", r.Status, r.Body)
}
