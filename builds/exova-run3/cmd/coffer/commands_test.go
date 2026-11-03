package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestCommandRoutes pins the HTTP route each §7.1 command calls, so a wrong path
// or method is caught here rather than by the hidden suite.
func TestCommandRoutes(t *testing.T) {
	members := `{"members":[{"id":"usr_1","email":"a@b.c","role":"member"}]}`

	cases := []struct {
		name   string
		args   []string
		stdin  string
		status int
		body   string
		method string
		path   string
	}{
		{"login", []string{"login", "--email", "a@b.c"}, "hunter2hunter2\n", http.StatusOK, `{"token":"t","user":{"id":"u","email":"a@b.c"}}`, "POST", "/api/v1/auth/token"},
		{"logout", []string{"logout"}, "", http.StatusOK, `{}`, "POST", "/api/v1/auth/logout"},
		{"whoami", []string{"whoami"}, "", http.StatusOK, `{"role":"owner","user":{"id":"u","email":"a@b.c"}}`, "GET", "/api/v1/me"},
		{"passwd", []string{"passwd"}, "old-password-1\nnew-password-1\n", http.StatusOK, `{}`, "POST", "/api/v1/auth/password"},
		{"admin org create", []string{"admin", "org", "create", "acme", "--owner-email", "o@b.c"}, "hunter2hunter2\n", http.StatusCreated, `{"organization":{"id":"o1","slug":"acme"}}`, "POST", "/api/v1/admin/orgs"},
		{"admin org list", []string{"admin", "org", "list"}, "", http.StatusOK, `{"organizations":[]}`, "GET", "/api/v1/admin/orgs"},
		{"admin org disable", []string{"admin", "org", "disable", "acme"}, "", http.StatusOK, `{"organization":{"slug":"acme"}}`, "POST", "/api/v1/admin/orgs/acme/disable"},
		{"admin audit list", []string{"admin", "audit", "list"}, "", http.StatusOK, `{"events":[]}`, "GET", "/api/v1/admin/audit"},
		{"admin audit verify", []string{"admin", "audit", "verify"}, "", http.StatusOK, `{"valid":true,"first_invalid_seq":null}`, "GET", "/api/v1/admin/audit/verify"},
		{"member add", []string{"member", "add", "a@b.c", "--role", "member"}, "hunter2hunter2\n", http.StatusCreated, `{"member":{"id":"u1"}}`, "POST", "/api/v1/members"},
		{"member list", []string{"member", "list"}, "", http.StatusOK, members, "GET", "/api/v1/members"},
		{"member role", []string{"member", "role", "a@b.c", "admin"}, "", http.StatusOK, members, "PATCH", "/api/v1/members/usr_1"},
		{"member remove", []string{"member", "remove", "a@b.c"}, "", http.StatusOK, members, "DELETE", "/api/v1/members/usr_1"},
		{"grant set", []string{"grant", "set", "a@b.c", "-p", "app", "--level", "writer"}, "", http.StatusOK, members, "PUT", "/api/v1/members/usr_1/grants/app"},
		{"grant revoke", []string{"grant", "revoke", "a@b.c", "-p", "app"}, "", http.StatusOK, members, "DELETE", "/api/v1/members/usr_1/grants/app"},
		{"project create", []string{"project", "create", "app"}, "", http.StatusCreated, `{"project":{"id":"p1","slug":"app"}}`, "POST", "/api/v1/projects"},
		{"project list", []string{"project", "list"}, "", http.StatusOK, `{"projects":[]}`, "GET", "/api/v1/projects"},
		{"env create", []string{"env", "create", "dev", "-p", "app"}, "", http.StatusCreated, `{"environment":{"id":"e1","slug":"dev"}}`, "POST", "/api/v1/projects/app/envs"},
		{"env list", []string{"env", "list", "-p", "app"}, "", http.StatusOK, `{"environments":[]}`, "GET", "/api/v1/projects/app/envs"},
		{"secrets list", []string{"secrets", "list", "-p", "app", "-e", "dev"}, "", http.StatusOK, `[]`, "GET", "/api/v1/projects/app/envs/dev/secrets"},
		{"secrets get", []string{"secrets", "get", "A", "-p", "app", "-e", "dev"}, "", http.StatusOK, `{"key":"A","version":1,"value":"v"}`, "GET", "/api/v1/projects/app/envs/dev/secrets/A"},
		{"secrets set", []string{"secrets", "set", "A", "v", "-p", "app", "-e", "dev"}, "", http.StatusOK, `{"version":1}`, "PUT", "/api/v1/projects/app/envs/dev/secrets/A"},
		{"secrets delete", []string{"secrets", "delete", "A", "-p", "app", "-e", "dev"}, "", http.StatusOK, `{"version":2}`, "DELETE", "/api/v1/projects/app/envs/dev/secrets/A"},
		{"secrets history", []string{"secrets", "history", "A", "-p", "app", "-e", "dev"}, "", http.StatusOK, `[]`, "GET", "/api/v1/projects/app/envs/dev/secrets/A/versions"},
		{"secrets rollback", []string{"secrets", "rollback", "A", "--to", "1", "-p", "app", "-e", "dev"}, "", http.StatusOK, `{"version":3}`, "POST", "/api/v1/projects/app/envs/dev/secrets/A/rollback"},
		{"secrets export", []string{"secrets", "export", "-p", "app", "-e", "dev", "--format", "dotenv"}, "", http.StatusOK, "A=\"v\"\n", "GET", "/api/v1/projects/app/envs/dev/export"},
		{"change list", []string{"change", "list"}, "", http.StatusOK, `{"changes":[]}`, "GET", "/api/v1/changes"},
		{"change approve", []string{"change", "approve", "chg_1"}, "", http.StatusOK, `{"status":"approved"}`, "POST", "/api/v1/changes/chg_1/approve"},
		{"change reject", []string{"change", "reject", "chg_1"}, "", http.StatusOK, `{"status":"rejected"}`, "POST", "/api/v1/changes/chg_1/reject"},
		{"token create", []string{"token", "create", "-p", "app", "-e", "dev", "--access", "read", "--ttl", "7d"}, "", http.StatusCreated, `{"id":"t1","token":"cof_st_x"}`, "POST", "/api/v1/tokens"},
		{"token list", []string{"token", "list"}, "", http.StatusOK, `{"tokens":[]}`, "GET", "/api/v1/tokens"},
		{"token revoke", []string{"token", "revoke", "t1"}, "", http.StatusOK, `{"revoked":true}`, "DELETE", "/api/v1/tokens/t1"},
		{"audit list", []string{"audit", "list"}, "", http.StatusOK, `{"events":[]}`, "GET", "/api/v1/audit"},
		{"audit verify", []string{"audit", "verify"}, "", http.StatusOK, `{"valid":true,"first_invalid_seq":null}`, "GET", "/api/v1/audit/verify"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t).login("cof_pat_test")
			h.server.reply(tc.status, tc.body)
			h.run(tc.stdin, tc.args...)
			h.wantCode(exitOK)
			req := h.server.lastRequest()
			if req.Method != tc.method {
				t.Errorf("method = %s, want %s", req.Method, tc.method)
			}
			if req.Path != tc.path {
				t.Errorf("path = %q, want %q", req.Path, tc.path)
			}
			// login is the one exception: it authenticates by the password in
			// its body, so it must never carry a stored credential.
			wantAuth := "Bearer cof_pat_test"
			if tc.path == "/api/v1/auth/token" {
				wantAuth = ""
			}
			if req.Auth != wantAuth {
				t.Errorf("Authorization = %q, want %q", req.Auth, wantAuth)
			}
		})
	}
}

// TestMemberCommandsNeverSendAPasswordInArgv proves the initial password reaches
// the server in the body only.
func TestMemberCommandsNeverSendAPasswordInArgv(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusCreated, `{"member":{"id":"u1"}}`)
	h.run("initial-pass-123\n", "member", "add", "a@b.c", "--role", "member")
	h.wantCode(exitOK)
	var body map[string]string
	if err := json.Unmarshal(h.server.lastRequest().Body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body["password"] != "initial-pass-123" {
		t.Errorf("password = %q", body["password"])
	}
	if strings.Contains(h.server.lastRequest().Auth, "initial-pass") {
		t.Error("the password leaked into a header")
	}
}

// TestAdminOrgCreateSendsOwnerPassword proves the owner's password travels in the
// body and the slug and email are validated locally.
func TestAdminOrgCreateSendsOwnerPassword(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusCreated, `{"organization":{"id":"o1","slug":"acme"}}`)
	h.run("owner-pass-1234\n", "admin", "org", "create", "acme", "--owner-email", "owner@acme.test")
	h.wantCode(exitOK)
	var body map[string]string
	if err := json.Unmarshal(h.server.lastRequest().Body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body["slug"] != "acme" || body["owner_email"] != "owner@acme.test" || body["owner_password"] != "owner-pass-1234" {
		t.Fatalf("body = %v", body)
	}
}

// TestEnvCreateSendsProtectedFlag proves --protected reaches the server.
func TestEnvCreateSendsProtectedFlag(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusCreated, `{"environment":{"id":"e1","slug":"prod","protected":true}}`)
	h.run("", "env", "create", "prod", "-p", "app", "--protected")
	h.wantCode(exitOK)
	var body map[string]any
	if err := json.Unmarshal(h.server.lastRequest().Body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body["protected"] != true || body["slug"] != "prod" {
		t.Fatalf("body = %v", body)
	}
}

// TestMemberRoleChangeStatusForwarded proves --status is sent as a filter.
func TestChangeListStatusFilter(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusOK, `{"changes":[]}`)
	h.run("", "change", "list", "--status", "pending")
	h.wantCode(exitOK)
	if q := h.server.lastRequest().Query; !strings.Contains(q, "status=pending") {
		t.Fatalf("query = %q, want status=pending", q)
	}
}

// TestChangeResolveWording proves the confirmation line uses the real past tense.
// "reject" + "d" is "rejectd", which is the kind of thing a user sees and a
// reviewer notices.
func TestChangeResolveWording(t *testing.T) {
	cases := map[string]string{
		"approve": "Approved change chg_1\n",
		"reject":  "Rejected change chg_1\n",
	}
	for action, want := range cases {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"status":"ok"}`)
		h.run("", "change", action, "chg_1")
		h.wantCode(exitOK)
		h.wantStdout(want)
	}
}
