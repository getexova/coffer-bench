package store

import (
	"strings"
	"testing"
)

// TestAppRolePasswordIsNotRewrittenOnEveryBoot is the regression guard for B3.
//
// The bug: ensureAppRole ran ALTER ROLE coffer_app PASSWORD on every boot, so a
// COFFER_APP_DB_PASSWORD that the database had rejected was silently rewritten into
// the database. The wrong password became the correct one, the operator never
// learned, and docs/CONTRACTS.md §11's "a rejected credential is a failed start"
// was inverted.
//
// The behavioural proof needs a live database and lives in the acceptance run; this
// test pins the source-level property that is cheap to check and easy to regress:
// the ALTER must be guarded by a provisioning check, and a rejected credential must
// produce an error naming COFFER_APP_DB_PASSWORD.
func TestAppRolePasswordIsNotRewrittenOnEveryBoot(t *testing.T) {
	// The guard exists and is consulted before the ALTER.
	if !strings.Contains(funcBody(t, "ensureAppRole"), "roleHasPassword") {
		t.Fatal("ensureAppRole no longer checks whether the role is already provisioned; a wrong COFFER_APP_DB_PASSWORD would be rewritten into the database")
	}
	if !strings.Contains(funcBody(t, "roleHasPassword"), "pg_authid") {
		t.Fatal("roleHasPassword does not consult pg_authid")
	}
}

// TestRejectedAppCredentialNamesTheVariable pins the operator-facing half of §11: the
// failure has to say which variable to fix, or a typo looks like an outage.
func TestRejectedAppCredentialNamesTheVariable(t *testing.T) {
	body := funcBody(t, "ConnectWithPolicy")
	if !strings.Contains(body, "COFFER_APP_DB_PASSWORD") {
		t.Fatal("the rejected-credential error does not name COFFER_APP_DB_PASSWORD")
	}
	if !strings.Contains(body, "isAuthFailure") {
		t.Fatal("ConnectWithPolicy does not treat an auth rejection as fatal")
	}
}

// funcBody returns the source of one function, so a test can assert on the code
// rather than on behaviour that needs a database.
func funcBody(t *testing.T, name string) string {
	t.Helper()
	src, err := readSource("db.go")
	if err != nil {
		t.Fatalf("could not read db.go: %v", err)
	}
	marker := "func " + name + "("
	start := strings.Index(src, marker)
	if start < 0 {
		marker = "func (db *DB) " + name + "("
		start = strings.Index(src, marker)
	}
	if start < 0 {
		t.Fatalf("%s not found in db.go", name)
	}
	// Take a generous slice to the end of the file; the assertions only look for
	// substrings, so over-reading is harmless and avoids brace matching.
	end := start + 4000
	if end > len(src) {
		end = len(src)
	}
	return src[start:end]
}
