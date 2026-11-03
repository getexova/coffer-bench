package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestJSONPrintsExactlyOneDocument walks the commands that take --json and proves
// each prints exactly one JSON document on stdout (SPEC §7.1).
func TestJSONPrintsExactlyOneDocument(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		status int
		body   string
	}{
		{
			name:   "whoami",
			args:   []string{"whoami", "--json"},
			status: http.StatusOK,
			body:   `{"role":"owner","organization":{"id":"o1","slug":"acme"},"user":{"id":"u1","email":"a@b.c"}}`,
		},
		{
			name:   "project list",
			args:   []string{"project", "list", "--json"},
			status: http.StatusOK,
			body:   `{"projects":[{"id":"p1","slug":"app","created_at":"2026-01-01T00:00:00Z"}]}`,
		},
		{
			name:   "project create",
			args:   []string{"project", "create", "app", "--json"},
			status: http.StatusCreated,
			body:   `{"project":{"id":"p1","slug":"app"}}`,
		},
		{
			name:   "env list",
			args:   []string{"env", "list", "-p", "app", "--json"},
			status: http.StatusOK,
			body:   `{"environments":[{"id":"e1","slug":"dev","protected":false}]}`,
		},
		{
			name:   "env create",
			args:   []string{"env", "create", "dev", "-p", "app", "--json"},
			status: http.StatusCreated,
			body:   `{"environment":{"id":"e1","slug":"dev","protected":false}}`,
		},
		{
			name:   "secrets list",
			args:   []string{"secrets", "list", "-p", "app", "-e", "dev", "--json"},
			status: http.StatusOK,
			body:   `[{"key":"A","version":1}]`,
		},
		{
			name:   "secrets get",
			args:   []string{"secrets", "get", "A", "-p", "app", "-e", "dev", "--json"},
			status: http.StatusOK,
			body:   `{"key":"A","version":1,"value":"v"}`,
		},
		{
			name:   "secrets set",
			args:   []string{"secrets", "set", "A", "v", "-p", "app", "-e", "dev", "--json"},
			status: http.StatusOK,
			body:   `{"version":2}`,
		},
		{
			name:   "secrets history",
			args:   []string{"secrets", "history", "A", "-p", "app", "-e", "dev", "--json"},
			status: http.StatusOK,
			body:   `[{"version":1,"deleted":false}]`,
		},
		{
			name:   "member list",
			args:   []string{"member", "list", "--json"},
			status: http.StatusOK,
			body:   `{"members":[{"id":"u1","email":"a@b.c","role":"member"}]}`,
		},
		{
			name:   "admin org list",
			args:   []string{"admin", "org", "list", "--json"},
			status: http.StatusOK,
			body:   `{"organizations":[{"id":"o1","slug":"acme"}]}`,
		},
		{
			name:   "change list",
			args:   []string{"change", "list", "--json"},
			status: http.StatusOK,
			body:   `{"changes":[{"id":"c1","status":"pending"}]}`,
		},
		{
			name:   "token list",
			args:   []string{"token", "list", "--json"},
			status: http.StatusOK,
			body:   `{"tokens":[{"id":"t1","access":"read"}]}`,
		},
		{
			name:   "audit list",
			args:   []string{"audit", "list", "--json"},
			status: http.StatusOK,
			body:   `{"events":[{"seq":1,"action":"login.success"}]}`,
		},
		{
			name:   "audit verify",
			args:   []string{"audit", "verify", "--json"},
			status: http.StatusOK,
			body:   `{"valid":true,"first_invalid_seq":0}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t).login("cof_pat_test")
			h.server.reply(tc.status, tc.body)
			h.run("", tc.args...)
			h.wantCode(exitOK)
			// oneJSONValue fails if there is more than one document.
			h.oneJSONValue()
			if strings.Contains(h.stderr.String(), "coffer:") {
				t.Errorf("stderr = %q, want no error on a success path", h.stderr.String())
			}
		})
	}
}

// TestJSONFlagPositionIsFlexible proves --json works before the command, after
// it, and on a subcommand.
func TestJSONFlagPositionIsFlexible(t *testing.T) {
	placements := [][]string{
		{"--json", "project", "list"},
		{"project", "list", "--json"},
		{"project", "--json", "list"},
	}
	for _, args := range placements {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"projects":[]}`)
		h.run("", args...)
		h.wantCode(exitOK)
		h.oneJSONDocument()
	}
}

// TestJSONIsValidForEmptyLists proves an empty listing is still one document.
func TestJSONIsValidForEmptyLists(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusOK, `{"projects":[]}`)
	h.run("", "project", "list", "--json")
	h.wantCode(exitOK)
	doc := h.oneJSONDocument()
	if _, ok := doc["projects"]; !ok {
		t.Fatalf("document = %v, want a projects field", doc)
	}
}

// TestHumanTablesRender proves the non-json output of a listing is a readable
// table with a header, not a raw JSON dump.
func TestHumanTablesRender(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusOK, `{"projects":[{"id":"p1","slug":"app","created_at":"2026-01-01T00:00:00Z"}]}`)
	h.run("", "project", "list")
	h.wantCode(exitOK)
	out := h.stdout.String()
	if !strings.Contains(out, "SLUG") || !strings.Contains(out, "app") {
		t.Fatalf("stdout = %q, want a table with a SLUG header and the row", out)
	}
	if strings.Contains(out, "{") {
		t.Fatalf("stdout = %q, want a table, not JSON", out)
	}
}

// TestTokenCreatePrintsTokenOnce proves the token goes to stdout alone, so
// `TOKEN=$(coffer token create ...)` works.
func TestTokenCreatePrintsTokenOnce(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusCreated, `{"id":"tok_1","token":"cof_st_abc123"}`)
	h.run("", "token", "create", "-p", "app", "-e", "dev", "--access", "read", "--ttl", "7d")
	h.wantCode(exitOK)
	h.wantStdout("cof_st_abc123\n")
	if !strings.Contains(h.stderr.String(), "shown once") {
		t.Errorf("stderr = %q, want a warning that the token is shown once", h.stderr.String())
	}
	var body map[string]any
	if err := json.Unmarshal(h.server.lastRequest().Body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body["ttl_seconds"] != float64(604800) {
		t.Errorf("ttl_seconds = %v, want 604800 for 7d", body["ttl_seconds"])
	}
	if body["access"] != "read" || body["project"] != "app" || body["env"] != "dev" {
		t.Errorf("body = %v", body)
	}
}
