package main

import (
	"net/http"
	"strings"
	"testing"
)

// TestAuditListDecodesE3Shape pins the shape E3 emits: a wrapped
// {"events":[...]} object, newest first, with the field set
// seq, timestamp, actor, action, target, source_ip, result, prev_hash, hash.
func TestAuditListDecodesE3Shape(t *testing.T) {
	body := `{"events":[
		{"seq":2,"timestamp":"2026-01-16T09:41:07.123456Z","actor":"usr_1","action":"secret.read","target":"app/dev/DB_URL","source_ip":"127.0.0.1","result":"success","prev_hash":"ab","hash":"cd"},
		{"seq":1,"timestamp":"2026-01-16T09:41:06.000001Z","actor":"usr_2","action":"login.success","target":"","source_ip":"10.0.0.1","result":"success","prev_hash":"00","hash":"ab"}
	]}`

	t.Run("human table shows timestamp, actor, action, result", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, body)
		h.run("", "audit", "list")
		h.wantCode(exitOK)
		out := h.stdout.String()
		for _, want := range []string{"SEQ", "TIME", "ACTOR", "ACTION", "RESULT", "secret.read", "usr_1", "2026-01-16T09:41:07Z", "success"} {
			if !strings.Contains(out, want) {
				t.Errorf("stdout missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("json passes the server body through as one document", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, body)
		h.run("", "audit", "list", "--json")
		h.wantCode(exitOK)
		doc := h.oneJSONDocument()
		events, ok := doc["events"].([]any)
		if !ok || len(events) != 2 {
			t.Fatalf("events = %v, want 2 entries", doc["events"])
		}
	})

	t.Run("filters are forwarded as query params", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"events":[]}`)
		h.run("", "audit", "list", "--actor", "usr_1", "--action", "secret.read", "--since", "2026-01-01T00:00:00Z", "--limit", "5")
		h.wantCode(exitOK)
		q := h.server.lastRequest().Query
		for _, want := range []string{"actor=usr_1", "action=secret.read", "limit=5", "since=2026-01-01T00%3A00%3A00Z"} {
			if !strings.Contains(q, want) {
				t.Errorf("query %q missing %q", q, want)
			}
		}
	})

	t.Run("admin audit uses the platform route", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"events":[]}`)
		h.run("", "admin", "audit", "list", "--limit", "10")
		h.wantCode(exitOK)
		if got := h.server.lastRequest().Path; got != "/api/v1/admin/audit" {
			t.Errorf("path = %q, want /api/v1/admin/audit", got)
		}
	})
}

// TestAuditVerifyNullFirstInvalidSeq proves a null first_invalid_seq is not read
// as sequence 0: null means the chain is intact.
func TestAuditVerifyNullFirstInvalidSeq(t *testing.T) {
	t.Run("valid with null", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"valid":true,"first_invalid_seq":null}`)
		h.run("", "audit", "verify")
		h.wantCode(exitOK)
		h.wantStdout("Audit chain valid.\n")
	})

	t.Run("invalid with a number", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"valid":false,"first_invalid_seq":2}`)
		h.run("", "audit", "verify")
		h.wantCode(exitAuditInvalid)
		h.wantStdout("Audit chain INVALID at sequence 2\n")
	})

	t.Run("invalid with null still exits 9 without claiming sequence 0", func(t *testing.T) {
		h := newHarness(t).login("cof_pat_test")
		h.server.reply(http.StatusOK, `{"valid":false,"first_invalid_seq":null}`)
		h.run("", "audit", "verify")
		h.wantCode(exitAuditInvalid)
		if strings.Contains(h.stdout.String(), "sequence 0") {
			t.Fatalf("stdout = %q, want it not to report sequence 0 for a null", h.stdout.String())
		}
	})
}

// TestAuditListAcceptsBareArray proves the fallback decoder also works, so a
// shape change on the server cannot break the CLI.
func TestAuditListAcceptsBareArray(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.server.reply(http.StatusOK, `[{"seq":1,"timestamp":"2026-01-16T09:41:06.000001Z","action":"login.success","result":"success"}]`)
	h.run("", "audit", "list")
	h.wantCode(exitOK)
	if !strings.Contains(h.stdout.String(), "login.success") {
		t.Fatalf("stdout = %q", h.stdout.String())
	}
}
