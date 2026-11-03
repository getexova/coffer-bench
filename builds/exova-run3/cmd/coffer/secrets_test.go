package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestSecretsGetWritesExactBytes proves the value leaves the CLI byte for byte
// when stdout is not a TTY, and gains exactly one newline when it is.
func TestSecretsGetWritesExactBytes(t *testing.T) {
	value := "line one\nline two\ttabbed  spaces \x00 end"

	t.Run("pipe gets no added newline", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, jsonBody(map[string]any{
			"key": "MULTI", "version": 3, "value": value,
		}))
		h.run("", "secrets", "get", "MULTI", "-p", "app", "-e", "dev")
		h.wantCode(exitOK)
		h.wantStdout(value)
	})

	t.Run("tty appends one newline", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, jsonBody(map[string]any{
			"key": "MULTI", "version": 3, "value": value,
		}))
		h.runTTY("", "secrets", "get", "MULTI", "-p", "app", "-e", "dev")
		h.wantCode(exitOK)
		h.wantStdout(value + "\n")
	})

	t.Run("empty value through a pipe is zero bytes", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"key":"EMPTY","version":1,"value":""}`)
		h.run("", "secrets", "get", "EMPTY", "-p", "app", "-e", "dev")
		h.wantCode(exitOK)
		h.wantStdout("")
	})

	t.Run("a version read goes to the version route", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"key":"DB_URL","version":2,"value":"old"}`)
		h.run("", "secrets", "get", "DB_URL", "-p", "app", "-e", "dev", "--version", "2")
		h.wantCode(exitOK)
		h.wantStdout("old")
		if got := h.server.lastRequest().Path; got != "/api/v1/projects/app/envs/dev/secrets/DB_URL/versions/2" {
			t.Errorf("path = %q", got)
		}
	})
}

// TestSecretsSetReadsStdinExactly proves a piped file round-trips byte for byte:
// no trimming, no newline stripping, no re-encoding.
func TestSecretsSetReadsStdinExactly(t *testing.T) {
	cases := []struct {
		name  string
		stdin string
	}{
		{"trailing newline is kept", "value\n"},
		{"no trailing newline", "value"},
		{"multiple lines", "first\nsecond\nthird\n"},
		{"crlf is kept", "line\r\n"},
		{"leading and trailing spaces are kept", "  padded  "},
		{"empty stdin is an empty value", ""},
		{"nul and control bytes", "a\x00b\x1bc"},
		{"utf8", "héllo wörld ✓"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t).login("cof_pat_test")
			h.server.reply(http.StatusOK, `{"key":"CONFIG","version":4}`)
			h.run(tc.stdin, "secrets", "set", "CONFIG", "-p", "app", "-e", "dev")
			h.wantCode(exitOK)
			req := h.server.lastRequest()
			if req.Method != http.MethodPut {
				t.Errorf("method = %s, want PUT", req.Method)
			}
			var body struct {
				Value string `json:"value"`
			}
			if err := json.Unmarshal(req.Body, &body); err != nil {
				t.Fatalf("request body is not JSON: %v (%q)", err, req.Body)
			}
			if body.Value != tc.stdin {
				t.Fatalf("value sent = %q, want %q", body.Value, tc.stdin)
			}
		})
	}
}

// TestSecretsSetFromArgv covers the positional VALUE form, which must be sent
// exactly as given too.
func TestSecretsSetFromArgv(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusOK, `{"key":"GREETING","version":1}`)
	h.run("ignored stdin", "secrets", "set", "GREETING", "hello world", "-p", "app", "-e", "dev")
	h.wantCode(exitOK)
	var body struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(h.server.lastRequest().Body, &body); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if body.Value != "hello world" {
		t.Fatalf("value = %q, want %q", body.Value, "hello world")
	}
	h.wantStdout("Set GREETING (version 1)\n")
}

// TestSecretsSetExpectVersion proves --expect-version reaches the server, which
// owns the 409 decision.
func TestSecretsSetExpectVersion(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusConflict, `{"error":{"code":"conflict","message":"version mismatch"}}`)
	h.run("", "secrets", "set", "KEY", "v", "-p", "app", "-e", "dev", "--expect-version", "3")
	h.wantCode(exitConflict)
	var body map[string]any
	if err := json.Unmarshal(h.server.lastRequest().Body, &body); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if got, ok := body["expected_version"]; !ok || got != float64(3) {
		t.Fatalf("expected_version = %v, want 3", got)
	}
}

// TestSecretsListNeverPrintsValues proves the listing renders metadata only.
func TestSecretsListNeverPrintsValues(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusOK, `[{"key":"DB_URL","version":3,"updated_at":"2026-01-02T03:04:05Z","updated_by":"usr_1"}]`)
	h.run("", "secrets", "list", "-p", "app", "-e", "dev")
	h.wantCode(exitOK)
	out := h.stdout.String()
	for _, want := range []string{"DB_URL", "3", "usr_1"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want it to contain %q", out, want)
		}
	}
}

// TestSecretsHistoryAndDelete cover the remaining secret subcommands' routes.
func TestSecretsHistoryAndDelete(t *testing.T) {
	t.Run("history", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `[{"version":1,"deleted":false,"created_at":"2026-01-01T00:00:00Z","created_by":"usr_1"},{"version":2,"deleted":true,"created_at":"2026-01-02T00:00:00Z","created_by":"usr_2"}]`)
		h.run("", "secrets", "history", "DB_URL", "-p", "app", "-e", "dev")
		h.wantCode(exitOK)
		if got := h.server.lastRequest().Path; got != "/api/v1/projects/app/envs/dev/secrets/DB_URL/versions" {
			t.Errorf("path = %q", got)
		}
		out := h.stdout.String()
		if !strings.Contains(out, "VERSION") || !strings.Contains(out, "yes") {
			t.Errorf("stdout = %q, want a history table marking the tombstone", out)
		}
	})

	t.Run("delete", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"version":4}`)
		h.run("", "secrets", "delete", "DB_URL", "-p", "app", "-e", "dev")
		h.wantCode(exitOK)
		req := h.server.lastRequest()
		if req.Method != http.MethodDelete || req.Path != "/api/v1/projects/app/envs/dev/secrets/DB_URL" {
			t.Errorf("request = %s %s", req.Method, req.Path)
		}
		h.wantStdout("Deleted DB_URL (version 4)\n")
	})

	t.Run("rollback", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"version":5}`)
		h.run("", "secrets", "rollback", "DB_URL", "--to", "2", "-p", "app", "-e", "dev")
		h.wantCode(exitOK)
		req := h.server.lastRequest()
		if req.Path != "/api/v1/projects/app/envs/dev/secrets/DB_URL/rollback" {
			t.Errorf("path = %q", req.Path)
		}
		if !strings.Contains(string(req.Body), `"to":2`) {
			t.Errorf("body = %q, want to:2", req.Body)
		}
	})
}

// TestSecretsExportPassesServerBytesThrough proves the export is not re-escaped:
// whatever the server sent is what reaches stdout.
func TestSecretsExportPassesServerBytesThrough(t *testing.T) {
	serverDotenv := "ALPHA=\"one\"\nBETA=\"two\\nlines\"\n"

	t.Run("dotenv", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.on(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(serverDotenv))
		})
		h.run("", "secrets", "export", "-p", "app", "-e", "dev", "--format", "dotenv")
		h.wantCode(exitOK)
		h.wantStdout(serverDotenv)
		if got := h.server.lastRequest().Query; !strings.Contains(got, "format=dotenv") {
			t.Errorf("query = %q, want format=dotenv", got)
		}
	})

	t.Run("json", func(t *testing.T) {
		serverJSON := `{"ALPHA":"one","BETA":"two"}`
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, serverJSON)
		h.run("", "secrets", "export", "-p", "app", "-e", "dev", "--format", "json", "--json")
		h.wantCode(exitOK)
		doc := h.oneJSONDocument()
		if doc["ALPHA"] != "one" {
			t.Errorf("ALPHA = %v, want one", doc["ALPHA"])
		}
	})
}
