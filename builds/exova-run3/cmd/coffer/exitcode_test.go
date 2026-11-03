package main

import (
	"net/http"
	"testing"
)

// TestExitCodeForEveryStatus pins the SPEC §7.1 exit-code table: every HTTP
// status the API can return maps onto exactly one exit code.
func TestExitCodeForEveryStatus(t *testing.T) {
	cases := []struct {
		status int
		want   int
	}{
		{http.StatusOK, exitOK},
		{http.StatusCreated, exitOK},
		{http.StatusNoContent, exitOK},
		{http.StatusAccepted, exitPending},
		{http.StatusBadRequest, exitValidation},
		{http.StatusUnauthorized, exitUnauthenticated},
		{http.StatusForbidden, exitForbidden},
		{http.StatusNotFound, exitNotFound},
		{http.StatusConflict, exitConflict},
		{http.StatusRequestEntityTooLarge, exitValidation},
		{http.StatusUnprocessableEntity, exitValidation},
		{http.StatusTooManyRequests, exitRateLimited},
		{http.StatusInternalServerError, exitOther},
		{http.StatusBadGateway, exitOther},
		{http.StatusTeapot, exitOther},
	}
	for _, tc := range cases {
		if got := statusExit(tc.status); got != tc.want {
			t.Errorf("statusExit(%d) = %d, want %d", tc.status, got, tc.want)
		}
	}
}

// TestEveryStatusThroughACommand proves the mapping holds end to end: a command
// that hits each status exits with the documented code, and every error goes to
// stderr rather than stdout.
func TestEveryStatusThroughACommand(t *testing.T) {
	cases := []struct {
		status int
		want   int
		code   string
	}{
		{http.StatusBadRequest, exitValidation, "validation_error"},
		{http.StatusUnauthorized, exitUnauthenticated, "unauthenticated"},
		{http.StatusForbidden, exitForbidden, "forbidden"},
		{http.StatusNotFound, exitNotFound, "not_found"},
		{http.StatusConflict, exitConflict, "conflict"},
		{http.StatusRequestEntityTooLarge, exitValidation, "body_too_large"},
		{http.StatusUnprocessableEntity, exitValidation, "validation_error"},
		{http.StatusTooManyRequests, exitRateLimited, "rate_limited"},
		{http.StatusInternalServerError, exitOther, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			h := newHarness(t).login("cof_pat_test")
			h.server.reply(tc.status, `{"error":{"code":"`+tc.code+`","message":"`+tc.code+`"}}`)
			h.run("", "project", "list")
			h.wantCode(tc.want)
			if h.stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty: errors go to stderr", h.stdout.String())
			}
			h.wantStderrContains(tc.code)
		})
	}
}

// TestPendingWriteExitsSeven covers the protected-environment path: a 202 is not
// an error, so the change ID is printed and the exit code is 7.
func TestPendingWriteExitsSeven(t *testing.T) {
	t.Run("human output prints the change id", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusAccepted, `{"status":"pending","change_id":"chg_123"}`)
		h.run("", "secrets", "set", "DB_URL", "postgres://x", "-p", "app", "-e", "prod")
		h.wantCode(exitPending)
		h.wantStdout("chg_123\n")
		if h.stderr.Len() != 0 {
			t.Errorf("stderr = %q, want empty: a pending write is not an error", h.stderr.String())
		}
	})

	t.Run("json output is one pending document", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusAccepted, `{"status":"pending","change_id":"chg_123"}`)
		h.run("", "secrets", "set", "DB_URL", "x", "-p", "app", "-e", "prod", "--json")
		h.wantCode(exitPending)
		doc := h.oneJSONDocument()
		if doc["status"] != "pending" {
			t.Errorf(`status = %v, want "pending"`, doc["status"])
		}
		if doc["change_id"] != "chg_123" {
			t.Errorf("change_id = %v, want chg_123", doc["change_id"])
		}
	})

	t.Run("delete and rollback are pending too", func(t *testing.T) {
		for _, args := range [][]string{
			{"secrets", "delete", "DB_URL", "-p", "app", "-e", "prod"},
			{"secrets", "rollback", "DB_URL", "--to", "2", "-p", "app", "-e", "prod"},
		} {
			h := newHarness(t).login("cof_pat_test")
			h.server.reply(http.StatusAccepted, `{"status":"pending","change_id":"chg_9"}`)
			h.run("", args...)
			h.wantCode(exitPending)
			h.wantStdout("chg_9\n")
		}
	})
}

// TestUsageErrorsExitTwoLocally proves a usage error is decided without a
// network call: the fake server must see no request at all.
func TestUsageErrorsExitTwoLocally(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown command", []string{"frobnicate"}},
		{"unknown subcommand", []string{"project", "frobnicate"}},
		{"unknown secrets subcommand", []string{"secrets", "frobnicate"}},
		{"missing secrets subcommand", []string{"secrets"}},
		{"missing command", nil},
		{"missing required flag -p", []string{"secrets", "list", "-e", "dev"}},
		{"missing required flag -e", []string{"secrets", "list", "-p", "app"}},
		{"missing --email", []string{"login"}},
		{"missing --owner-email", []string{"admin", "org", "create", "acme"}},
		{"missing --role", []string{"member", "add", "a@b.c"}},
		{"missing --level", []string{"grant", "set", "a@b.c", "-p", "app"}},
		{"missing --format", []string{"secrets", "export", "-p", "app", "-e", "dev"}},
		{"missing --access", []string{"token", "create", "-p", "app", "-e", "dev", "--ttl", "7d"}},
		{"missing --ttl", []string{"token", "create", "-p", "app", "-e", "dev", "--access", "read"}},
		{"missing --to", []string{"secrets", "rollback", "KEY", "-p", "app", "-e", "dev"}},
		{"missing run command", []string{"run", "-p", "app", "-e", "dev"}},
		{"bad slug", []string{"project", "create", "Not_A_Slug"}},
		{"bad project slug", []string{"secrets", "list", "-p", "Bad_Slug", "-e", "dev"}},
		{"bad env slug", []string{"secrets", "list", "-p", "app", "-e", "Bad_Slug"}},
		{"bad secret key", []string{"secrets", "get", "lower_case", "-p", "app", "-e", "dev"}},
		{"bad role", []string{"member", "add", "a@b.c", "--role", "superuser"}},
		{"bad level", []string{"grant", "set", "a@b.c", "-p", "app", "--level", "owner"}},
		{"bad access", []string{"token", "create", "-p", "app", "-e", "dev", "--access", "write", "--ttl", "7d"}},
		{"bad format", []string{"secrets", "export", "-p", "app", "-e", "dev", "--format", "yaml"}},
		{"bad change status", []string{"change", "list", "--status", "open"}},
		{"bad ttl unit", []string{"token", "create", "-p", "app", "-e", "dev", "--access", "read", "--ttl", "7w"}},
		{"ttl too long", []string{"token", "create", "-p", "app", "-e", "dev", "--access", "read", "--ttl", "91d"}},
		{"ttl too short", []string{"token", "create", "-p", "app", "-e", "dev", "--access", "read", "--ttl", "30s"}},
		{"bad since", []string{"audit", "list", "--since", "yesterday"}},
		{"unknown flag", []string{"project", "list", "--nope"}},
		{"password in argv is refused", []string{"login", "--email", "a@b.c", "--password", "secret"}},
		{"extra argument", []string{"project", "list", "extra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t).login("cof_pat_test")
			h.run("", tc.args...)
			h.wantCode(exitUsage)
			if n := h.server.requestCount(); n != 0 {
				t.Fatalf("the fake server saw %d requests, want 0: usage errors are decided locally", n)
			}
			if h.stderr.Len() == 0 {
				t.Error("stderr is empty, want a usage message")
			}
		})
	}
}

// TestNotLoggedInExitsThree covers the local authentication failure: with no
// token and no COFFER_TOKEN, a command that needs auth exits 3 without a
// request and points at `coffer login`.
func TestNotLoggedInExitsThree(t *testing.T) {
	h := newHarness(t)
	h.run("", "project", "list")
	h.wantCode(exitUnauthenticated)
	h.wantStderrContains("coffer login")
	if n := h.server.requestCount(); n != 0 {
		t.Fatalf("the fake server saw %d requests, want 0", n)
	}
}

// TestUnauthorizedKeepsConfig proves a 401 does not delete the stored token: the
// token may be a transient failure, so the CLI keeps it.
func TestUnauthorizedKeepsConfig(t *testing.T) {
	h := newHarness(t).login("cof_pat_keepme")
	h.server.reply(http.StatusUnauthorized, `{"error":{"code":"unauthenticated","message":"unauthenticated"}}`)
	h.run("", "whoami")
	h.wantCode(exitUnauthenticated)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Token != "cof_pat_keepme" {
		t.Fatalf("token = %q, want it preserved after a 401", cfg.Token)
	}
}

// TestForbiddenExitsFour proves a 403 is distinct from a 404.
func TestForbiddenExitsFour(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusForbidden, `{"error":{"code":"forbidden","message":"forbidden"}}`)
	h.run("", "audit", "list")
	h.wantCode(exitForbidden)
}

// TestAuditVerifyInvalidExitsNine proves an invalid chain is a successful HTTP
// call reporting valid:false, so it exits 9 rather than an HTTP error code.
func TestAuditVerifyInvalidExitsNine(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"valid":false,"first_invalid_seq":42}`)
		h.run("", "audit", "verify")
		h.wantCode(exitAuditInvalid)
		h.wantStdout("Audit chain INVALID at sequence 42\n")
	})

	t.Run("valid", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"valid":true,"first_invalid_seq":0}`)
		h.run("", "audit", "verify")
		h.wantCode(exitOK)
		h.wantStdout("Audit chain valid.\n")
	})

	t.Run("invalid under json is one document", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"valid":false,"first_invalid_seq":7}`)
		h.run("", "audit", "verify", "--json")
		h.wantCode(exitAuditInvalid)
		doc := h.oneJSONDocument()
		if doc["valid"] != false {
			t.Errorf("valid = %v, want false", doc["valid"])
		}
	})

	t.Run("admin verify uses the platform route", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"valid":false,"first_invalid_seq":3}`)
		h.run("", "admin", "audit", "verify")
		h.wantCode(exitAuditInvalid)
		if got := h.server.lastRequest().Path; got != "/api/v1/admin/audit/verify" {
			t.Errorf("path = %q, want /api/v1/admin/audit/verify", got)
		}
	})
}
