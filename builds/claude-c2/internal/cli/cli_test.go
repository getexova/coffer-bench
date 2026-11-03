package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- argument parsing ----

func TestParseFlagForms(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 200, []map[string]any{})
	})
	cases := [][]string{
		{"secrets", "list", "-p", "app", "-e", "prod"},
		{"secrets", "list", "--project", "app", "--env", "prod"},
		{"secrets", "list", "--project=app", "--env=prod"},
		{"secrets", "list", "-p=app", "-e=prod"},
		{"--json", "secrets", "list", "-e", "prod", "-p", "app"},
		{"secrets", "--json", "list", "-p", "app", "-e", "prod"},
		{"secrets", "list", "-p", "app", "--json", "-e", "prod", "--url", f.srv.URL},
		{"--url", f.srv.URL, "secrets", "list", "-p", "app", "-e", "prod"},
		{"--url=" + f.srv.URL, "secrets", "list", "-p", "app", "-e", "prod"},
	}
	for _, args := range cases {
		h := newHarness(t, "http://127.0.0.1:1") // wrong URL unless --url wins
		if !strings.Contains(strings.Join(args, " "), "--url") {
			h.env["COFFER_URL"] = f.srv.URL
		}
		code, _, stderr := h.run(args...)
		mustExit(t, 0, code, stderr)
		r := f.last()
		if r.Method != "GET" || r.Path != "/api/v1/projects/app/envs/prod/secrets" {
			t.Fatalf("%v: got %s %s", args, r.Method, r.Path)
		}
		if r.Auth != "Bearer "+testToken {
			t.Fatalf("%v: auth header %q", args, r.Auth)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		t.Errorf("no request expected, got %s %s", r.Method, r.URL.Path)
	})
	cases := [][]string{
		{},
		{"bogus"},
		{"secrets"},
		{"secrets", "frobnicate"},
		{"secrets", "list", "-p", "a"}, // missing -e
		{"secrets", "list", "-p", "a", "-e", "b", "--bogus"},       // unknown flag
		{"secrets", "list", "-p", "a", "-e", "b", "extra"},         // extra arg
		{"secrets", "get", "-p", "a", "-e", "b"},                   // missing KEY
		{"secrets", "get", "K", "-p", "a", "-e", "b", "--to", "1"}, // flag not allowed here
		{"secrets", "list", "-p", "a", "-e"},                       // missing value
		{"secrets", "set", "K", "V", "X", "-p", "a", "-e", "b"},    // too many args
		{"login"}, // missing --email
		{"login", "--email", "a@b.c", "--password", "x"}, // passwords never in argv
		{"member", "role", "a@b.c"},
		{"run", "-p", "a", "-e", "b"},                            // missing command
		{"token", "create", "-p", "a", "-e", "b", "--ttl", "1h"}, // missing --access
		{"env", "create", "dev", "-p", "a", "--protected=maybe"},
		{"--url", "ftp://x", "whoami"},
		{"--url", "http://user:pw@x", "whoami"},
	}
	for _, args := range cases {
		h := newHarness(t, f.srv.URL)
		code, stdout, stderr := h.run(args...)
		if code != ExitUsage {
			t.Errorf("%v: exit %d, want 2 (stderr %q)", args, code, stderr)
		}
		if stdout != "" {
			t.Errorf("%v: stdout must be empty on error, got %q", args, stdout)
		}
		if !strings.HasPrefix(stderr, "error: ") {
			t.Errorf("%v: stderr %q", args, stderr)
		}
	}
}

func TestHelpExitsZero(t *testing.T) {
	h := newHarness(t, "http://127.0.0.1:1")
	for _, args := range [][]string{{"help"}, {"--help"}, {"secrets", "get", "--help"}, {"help", "secrets", "get"}} {
		code, out, stderr := h.run(args...)
		mustExit(t, 0, code, stderr)
		if !strings.Contains(out, "usage") {
			t.Errorf("%v: %q", args, out)
		}
	}
}

func TestJSONUsageErrorOnStderr(t *testing.T) {
	h := newHarness(t, "http://127.0.0.1:1")
	code, out, stderr := h.run("--json", "secrets", "list")
	mustExit(t, 2, code, stderr)
	if out != "" {
		t.Fatalf("stdout %q", out)
	}
	i := strings.Index(stderr, "{")
	var doc map[string]map[string]string
	if i < 0 || json.Unmarshal([]byte(stderr[i:]), &doc) != nil || doc["error"]["code"] != "usage" {
		t.Fatalf("stderr %q", stderr)
	}
}

// ---- exit code mapping ----

func TestExitCodeMapping(t *testing.T) {
	cases := []struct {
		status int
		want   int
	}{
		{401, 3}, {403, 4}, {404, 5}, {400, 6}, {413, 6}, {422, 6}, {409, 8}, {429, 10},
		{500, 1}, {503, 1}, {405, 1}, {418, 1}, {302, 1},
	}
	for _, tc := range cases {
		f := newFake(t, errReply(tc.status, "some_code", "some message"))
		h := newHarness(t, f.srv.URL)
		code, out, stderr := h.run("secrets", "get", "K", "-p", "a", "-e", "b")
		if code != tc.want {
			t.Errorf("status %d: exit %d, want %d", tc.status, code, tc.want)
		}
		if out != "" {
			t.Errorf("status %d: stdout %q", tc.status, out)
		}
		if tc.status != 302 && stderr != "error: some message (some_code)\n" {
			t.Errorf("status %d: stderr %q", tc.status, stderr)
		}
		if strings.Contains(stderr, testToken) {
			t.Errorf("token leaked to stderr")
		}
	}
}

func TestNonJSONErrorBody(t *testing.T) {
	f := newFake(t, rawReply(502, "text/html", "<html>bad gateway</html>"))
	h := newHarness(t, f.srv.URL)
	code, _, stderr := h.run("whoami")
	mustExit(t, 1, code, stderr)
	if stderr != "error: HTTP 502\n" {
		t.Fatalf("stderr %q", stderr)
	}
}

func TestConnectionFailureExit1(t *testing.T) {
	h := newHarness(t, "http://127.0.0.1:1")
	code, _, stderr := h.run("whoami")
	mustExit(t, 1, code, stderr)
	if strings.Contains(stderr, testToken) {
		t.Fatal("token leaked")
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var hits int
	target := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		hits++
		jsonReply(w, 200, map[string]any{"type": "user"})
	})
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		http.Redirect(w, r, target.srv.URL+"/api/v1/me", http.StatusFound)
	})
	h := newHarness(t, f.srv.URL)
	code, _, stderr := h.run("whoami")
	mustExit(t, 1, code, stderr)
	if hits != 0 {
		t.Fatal("redirect was followed with the bearer token")
	}
}

// ---- secrets get ----

func TestSecretsGetByteExact(t *testing.T) {
	value := "line1\nline2\r\n  trailing space \x01 ünïcode \"q\" $HOME\n"
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 200, map[string]any{"key": "DB_URL", "version": 3, "value": value})
	})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("secrets", "get", "DB_URL", "-p", "app", "-e", "prod")
	mustExit(t, 0, code, stderr)
	if out != value {
		t.Fatalf("non-TTY output not byte-exact: %q", out)
	}
	if got := f.last().Path; got != "/api/v1/projects/app/envs/prod/secrets/DB_URL" {
		t.Fatalf("path %q", got)
	}

	h.ttyOut = true
	_, out, _ = h.run("secrets", "get", "DB_URL", "-p", "app", "-e", "prod")
	if out != value+"\n" {
		t.Fatalf("TTY output %q", out)
	}
}

func TestSecretsGetEmptyValueNoNewline(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 200, map[string]any{"key": "E", "version": 1, "value": ""})
	})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("secrets", "get", "E", "-p", "a", "-e", "b")
	mustExit(t, 0, code, stderr)
	if out != "" {
		t.Fatalf("%q", out)
	}
}

func TestSecretsGetVersion(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 200, map[string]any{"key": "K", "version": 2, "value": "old"})
	})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("secrets", "get", "K", "--version", "2", "-p", "a", "-e", "b")
	mustExit(t, 0, code, stderr)
	if out != "old" || f.last().Path != "/api/v1/projects/a/envs/b/secrets/K/versions/2" {
		t.Fatalf("out %q path %q", out, f.last().Path)
	}
	code, _, _ = h.run("secrets", "get", "K", "--version=abc", "-p", "a", "-e", "b")
	mustExit(t, 6, code, "")
	if len(f.reqs()) != 1 {
		t.Fatal("request sent for malformed --version")
	}
}

func TestSecretsGetJSON(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 200, map[string]any{"key": "K", "version": 4, "value": "v<&>"})
	})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("secrets", "get", "K", "-p", "a", "-e", "b", "--json")
	mustExit(t, 0, code, stderr)
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(out))
	if err := dec.Decode(&m); err != nil || dec.More() {
		t.Fatalf("not exactly one JSON doc: %q", out)
	}
	if m["key"] != "K" || m["value"] != "v<&>" || m["version"].(float64) != 4 {
		t.Fatalf("%v", m)
	}
}

func TestPathSegmentsEscaped(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 404, map[string]any{"error": map[string]string{"code": "not_found", "message": "not found"}})
	})
	h := newHarness(t, f.srv.URL)
	code, _, _ := h.run("secrets", "get", "A/B?x=1#f", "-p", "my proj", "-e", "pr%od")
	mustExit(t, 5, code, "")
	r := f.last()
	if r.RequestURI != "/api/v1/projects/my%20proj/envs/pr%25od/secrets/A%2FB%3Fx=1%23f" {
		t.Fatalf("request URI %q", r.RequestURI)
	}
	if r.Query != "" {
		t.Fatalf("query leaked: %q", r.Query)
	}
	// dot segments are rejected locally
	for _, k := range []string{".", ".."} {
		n := len(f.reqs())
		code, _, _ = h.run("secrets", "get", k, "-p", "a", "-e", "b")
		mustExit(t, 6, code, "")
		if len(f.reqs()) != n {
			t.Fatal("request sent for dot segment")
		}
	}
}

// ---- secrets set ----

func TestSecretsSetFromStdinByteExact(t *testing.T) {
	values := []string{"", "x", "trailing newline\n", "crlf\r\n", "  spaces  ", "multi\nline\nvalue\n\n", "\t-starts-with-dash", strings.Repeat("é", 1000)}
	for _, v := range values {
		var got map[string]any
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
			if err := json.Unmarshal(body, &got); err != nil {
				t.Errorf("body not JSON: %q", body)
			}
			jsonReply(w, 200, map[string]any{"version": 1})
		})
		h := newHarness(t, f.srv.URL)
		h.stdin = strings.NewReader(v)
		code, out, stderr := h.run("secrets", "set", "K", "-p", "a", "-e", "b")
		mustExit(t, 0, code, stderr)
		if got["value"] != v {
			t.Fatalf("value %q sent as %q", v, got["value"])
		}
		if _, ok := got["expected_version"]; ok {
			t.Fatal("expected_version sent without flag")
		}
		r := f.last()
		if r.Method != "PUT" || r.Path != "/api/v1/projects/a/envs/b/secrets/K" || r.Query != "" {
			t.Fatalf("%s %s ?%s", r.Method, r.Path, r.Query)
		}
		if v != "" && strings.Contains(r.RequestURI, v) {
			t.Fatal("value in URL")
		}
		if out != "set K (version 1)\n" {
			t.Fatalf("out %q", out)
		}
	}
}

func TestSecretsSetArgvAndExpectVersion(t *testing.T) {
	var got map[string]any
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		got = nil
		_ = json.Unmarshal(body, &got)
		jsonReply(w, 200, map[string]any{"version": 7})
	})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("secrets", "set", "K", "-p", "a", "-e", "b", "--expect-version", "6", "--", "--looks-like-flag")
	mustExit(t, 0, code, stderr)
	if got["value"] != "--looks-like-flag" || got["expected_version"].(float64) != 6 {
		t.Fatalf("%v", got)
	}
	code, out, _ = h.run("--json", "secrets", "set", "K", "plain", "-p", "a", "-e", "b", "--expect-version=0")
	mustExit(t, 0, code, "")
	if got["value"] != "plain" || got["expected_version"].(float64) != 0 {
		t.Fatalf("%v", got)
	}
	var m map[string]any
	if json.Unmarshal([]byte(out), &m) != nil || m["version"].(float64) != 7 {
		t.Fatalf("json out %q", out)
	}
}

func TestSecretsSetInvalidUTF8NoRequest(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		t.Errorf("request sent")
	})
	h := newHarness(t, f.srv.URL)
	h.stdin = strings.NewReader("ok\xff\xfe")
	code, _, stderr := h.run("secrets", "set", "K", "-p", "a", "-e", "b")
	mustExit(t, 6, code, stderr)

	h.stdin = strings.NewReader(strings.Repeat("a", maxValueBytes+1))
	code, _, stderr = h.run("secrets", "set", "K", "-p", "a", "-e", "b")
	mustExit(t, 6, code, stderr)

	h.stdin = strings.NewReader("")
	code, _, stderr = h.run("secrets", "set", "K", "x\xff", "-p", "a", "-e", "b")
	mustExit(t, 6, code, stderr)
}

func TestSecretsSetMaxSizeAccepted(t *testing.T) {
	var n int
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		var m map[string]string
		_ = json.Unmarshal(body, &m)
		n = len(m["value"])
		jsonReply(w, 200, map[string]any{"version": 1})
	})
	h := newHarness(t, f.srv.URL)
	h.stdin = strings.NewReader(strings.Repeat("a", maxValueBytes))
	code, _, stderr := h.run("secrets", "set", "K", "-p", "a", "-e", "b")
	mustExit(t, 0, code, stderr)
	if n != maxValueBytes {
		t.Fatalf("sent %d bytes", n)
	}
}

// ---- 202 pending ----

func TestProtectedWritePending(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 202, map[string]any{"status": "pending", "change_id": "chg_abc"})
	})
	h := newHarness(t, f.srv.URL)
	for _, args := range [][]string{
		{"secrets", "set", "K", "v", "-p", "a", "-e", "prod"},
		{"secrets", "delete", "K", "-p", "a", "-e", "prod"},
		{"secrets", "rollback", "K", "--to", "1", "-p", "a", "-e", "prod"},
	} {
		code, out, stderr := h.run(args...)
		mustExit(t, 7, code, stderr)
		if out != "pending approval: change chg_abc\n" {
			t.Fatalf("%v: out %q", args, out)
		}
		code, out, stderr = h.run(append(args, "--json")...)
		mustExit(t, 7, code, stderr)
		var m map[string]string
		if err := json.Unmarshal([]byte(out), &m); err != nil || len(m) != 2 || m["status"] != "pending" || m["change_id"] != "chg_abc" {
			t.Fatalf("%v: json out %q", args, out)
		}
		if stderr != "" {
			t.Fatalf("stderr %q", stderr)
		}
	}
	// check methods/paths
	rs := f.reqs()
	if rs[2].Method != "DELETE" || rs[2].Path != "/api/v1/projects/a/envs/prod/secrets/K" {
		t.Fatalf("delete: %+v", rs[2])
	}
	if rs[4].Method != "POST" || rs[4].Path != "/api/v1/projects/a/envs/prod/secrets/K/rollback" || string(rs[4].Body) != "{\"to\":1}\n" {
		t.Fatalf("rollback: %+v %q", rs[4], rs[4].Body)
	}
}

// ---- export ----

func TestExportPassthrough(t *testing.T) {
	dotenv := "A=\"x\\\"y\"\nB=\"line\\nnext \\$HOME\"\n"
	jsonBody := `{"A":"x\"y","B":"line\nnext $HOME"}`
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.URL.Query().Get("format") == "dotenv" {
			rawReply(200, "text/plain; charset=utf-8", dotenv)(w, r, nil)
			return
		}
		rawReply(200, "application/json", jsonBody)(w, r, nil)
	})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("secrets", "export", "-p", "a", "-e", "b", "--format", "dotenv")
	mustExit(t, 0, code, stderr)
	if out != dotenv {
		t.Fatalf("dotenv %q", out)
	}
	if r := f.last(); r.Path != "/api/v1/projects/a/envs/b/export" || r.Query != "format=dotenv" {
		t.Fatalf("%+v", r)
	}
	code, out, stderr = h.run("secrets", "export", "-p", "a", "-e", "b", "--format=json")
	mustExit(t, 0, code, stderr)
	if out != jsonBody+"\n" {
		t.Fatalf("json %q", out)
	}
	code, out, _ = h.run("secrets", "export", "-p", "a", "-e", "b", "--json")
	mustExit(t, 0, code, "")
	if out != jsonBody+"\n" || f.last().Query != "format=json" {
		t.Fatalf("json default %q", out)
	}
}

func TestExportEmptyDotenv(t *testing.T) {
	f := newFake(t, rawReply(200, "text/plain; charset=utf-8", ""))
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("secrets", "export", "-p", "a", "-e", "b", "--format", "dotenv")
	mustExit(t, 0, code, stderr)
	if out != "" {
		t.Fatalf("%q", out)
	}
}

// ---- config & tokens ----

func TestLoginWritesConfigWithModes(t *testing.T) {
	var body map[string]string
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, b []byte) {
		_ = json.Unmarshal(b, &body)
		jsonReply(w, 201, map[string]any{"token": "cof_pat_NEWTOKEN", "user": map[string]any{"id": "usr_1", "email": "a@x.io"}, "expires_at": "2026-11-30T00:00:00Z"})
	})
	h := newHarness(t, "")
	delete(h.env, "COFFER_TOKEN")
	delete(h.env, "COFFER_URL")
	h.stdin = strings.NewReader("correct horse battery\r\nIGNORED\n")
	code, out, stderr := h.run("login", "--email", "a@x.io", "--url", f.srv.URL)
	mustExit(t, 0, code, stderr)
	if out != "logged in as a@x.io\n" {
		t.Fatalf("out %q", out)
	}
	if body["password"] != "correct horse battery" || body["email"] != "a@x.io" {
		t.Fatalf("body %v", body)
	}
	if r := f.last(); r.Path != "/api/v1/auth/token" || r.Auth != "" || strings.Contains(r.RequestURI, "horse") {
		t.Fatalf("%+v", r)
	}
	if m := fileMode(t, h.cfgDir); m != 0o700 {
		t.Fatalf("dir mode %o", m)
	}
	p := filepath.Join(h.cfgDir, "config.json")
	if m := fileMode(t, p); m != 0o600 {
		t.Fatalf("file mode %o", m)
	}
	data, _ := os.ReadFile(p)
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil || cfg.Token != "cof_pat_NEWTOKEN" || cfg.URL != f.srv.URL {
		t.Fatalf("config %s", data)
	}
	if strings.Contains(string(data), "horse") {
		t.Fatal("password in config")
	}
	entries, _ := os.ReadDir(h.cfgDir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}

	// The stored token and URL are used by later commands.
	code, _, stderr = h.run("whoami")
	mustExit(t, 0, code, stderr)
	if f.last().Auth != "Bearer cof_pat_NEWTOKEN" || f.last().Path != "/api/v1/me" {
		t.Fatalf("%+v", f.last())
	}

	// --json login output never contains the token.
	h.stdin = strings.NewReader("correct horse battery\n")
	code, out, _ = h.run("login", "--email", "a@x.io", "--json")
	mustExit(t, 0, code, "")
	if strings.Contains(out, "cof_pat_") || !json.Valid([]byte(out)) {
		t.Fatalf("json login out %q", out)
	}
}

func TestLoginTightensExistingModes(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, b []byte) {
		jsonReply(w, 201, map[string]any{"token": "cof_pat_T", "user": map[string]any{"email": "a@x.io"}})
	})
	h := newHarness(t, f.srv.URL)
	delete(h.env, "COFFER_TOKEN")
	if err := os.MkdirAll(h.cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(h.cfgDir, 0o755)
	p := filepath.Join(h.cfgDir, "config.json")
	os.WriteFile(p, []byte(`{"url":"`+f.srv.URL+`"}`), 0o644)
	h.stdin = strings.NewReader("pw-pw-pw-pw-pw\n")
	code, _, stderr := h.run("login", "--email", "a@x.io")
	mustExit(t, 0, code, stderr)
	if fileMode(t, h.cfgDir) != 0o700 || fileMode(t, p) != 0o600 {
		t.Fatalf("modes %o %o", fileMode(t, h.cfgDir), fileMode(t, p))
	}
}

func TestLoginEmptyPasswordNoRequest(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) { t.Errorf("request sent") })
	h := newHarness(t, f.srv.URL)
	delete(h.env, "COFFER_TOKEN")
	h.stdin = strings.NewReader("")
	code, _, _ := h.run("login", "--email", "a@x.io")
	mustExit(t, 2, code, "")
}

func TestLoginFailureCodes(t *testing.T) {
	for status, want := range map[int]int{401: 3, 429: 10} {
		f := newFake(t, errReply(status, "x", "y"))
		h := newHarness(t, f.srv.URL)
		delete(h.env, "COFFER_TOKEN")
		h.stdin = strings.NewReader("password-password\n")
		code, _, _ := h.run("login", "--email", "a@x.io")
		mustExit(t, want, code, "")
		if _, err := os.Stat(filepath.Join(h.cfgDir, "config.json")); err == nil {
			t.Fatal("config written on failed login")
		}
	}
}

func TestCofferTokenNoConfigFile(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 200, map[string]any{"type": "service_token", "id": "tok_1"})
	})
	h := newHarness(t, f.srv.URL)
	// A config file with a different token and an unreachable URL, unreadable.
	os.MkdirAll(h.cfgDir, 0o700)
	p := filepath.Join(h.cfgDir, "config.json")
	os.WriteFile(p, []byte(`{"url":"http://127.0.0.1:1","token":"cof_pat_FROMFILE"}`), 0o600)
	delete(h.env, "COFFER_URL")
	h.env["COFFER_URL"] = f.srv.URL
	os.Chmod(p, 0o000)
	defer os.Chmod(p, 0o600)
	code, _, stderr := h.run("whoami")
	mustExit(t, 0, code, stderr)
	if f.last().Auth != "Bearer "+testToken {
		t.Fatalf("auth %q", f.last().Auth)
	}

	// No file is ever created when COFFER_TOKEN is set.
	h2 := newHarness(t, f.srv.URL)
	for _, args := range [][]string{{"whoami"}, {"logout"}, {"secrets", "list", "-p", "a", "-e", "b"}} {
		h2.run(args...)
	}
	if _, err := os.Stat(h2.cfgDir); !os.IsNotExist(err) {
		t.Fatalf("config dir created with COFFER_TOKEN set")
	}
	// login refuses (exit 2) and writes nothing.
	h2.stdin = strings.NewReader("pw\n")
	code, _, _ = h2.run("login", "--email", "a@x.io")
	mustExit(t, 2, code, "")
	if _, err := os.Stat(h2.cfgDir); !os.IsNotExist(err) {
		t.Fatal("config dir created by login with COFFER_TOKEN")
	}
}

func TestCofferTokenUsesDefaultURLNotConfig(t *testing.T) {
	h := newHarness(t, "")
	delete(h.env, "COFFER_URL")
	os.MkdirAll(h.cfgDir, 0o700)
	os.WriteFile(filepath.Join(h.cfgDir, "config.json"), []byte(`{"url":"http://config.invalid"}`), 0o600)
	a := &App{LookupEnv: func(k string) (string, bool) { v, ok := h.env[k]; return v, ok }}
	a.defaults()
	c := &ctx{app: a, f: map[string]string{}}
	cl, err := c.newClient(true)
	if err != nil {
		t.Fatal(err)
	}
	if cl.base != defaultURL {
		t.Fatalf("base %q", cl.base)
	}
}

func TestNotLoggedIn(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) { t.Errorf("request sent") })
	h := newHarness(t, f.srv.URL)
	delete(h.env, "COFFER_TOKEN")
	code, _, _ := h.run("whoami")
	mustExit(t, 3, code, "")
	h.env["COFFER_TOKEN"] = ""
	code, _, _ = h.run("whoami")
	mustExit(t, 3, code, "")
}

func TestLogoutRemovesToken(t *testing.T) {
	for _, tc := range []struct {
		status    int
		wantCode  int
		wantToken bool
	}{{200, 0, false}, {401, 0, false}, {500, 1, true}} {
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
			if tc.status == 200 {
				jsonReply(w, 200, map[string]string{"status": "logged_out"})
				return
			}
			errReply(tc.status, "x", "y")(w, r, nil)
		})
		h := newHarness(t, f.srv.URL)
		delete(h.env, "COFFER_TOKEN")
		os.MkdirAll(h.cfgDir, 0o700)
		p := filepath.Join(h.cfgDir, "config.json")
		os.WriteFile(p, []byte(`{"url":"`+f.srv.URL+`","token":"cof_pat_OLD"}`), 0o600)
		code, _, stderr := h.run("logout")
		mustExit(t, tc.wantCode, code, stderr)
		if r := f.last(); r.Method != "POST" || r.Path != "/api/v1/auth/logout" || r.Auth != "Bearer cof_pat_OLD" {
			t.Fatalf("%+v", r)
		}
		data, _ := os.ReadFile(p)
		if strings.Contains(string(data), "cof_pat_OLD") != tc.wantToken {
			t.Fatalf("status %d: config %s", tc.status, data)
		}
		if fileMode(t, p) != 0o600 {
			t.Fatal("mode")
		}
	}
}

func TestPasswdTwoLines(t *testing.T) {
	var body map[string]string
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, b []byte) {
		_ = json.Unmarshal(b, &body)
		jsonReply(w, 200, map[string]string{"status": "ok"})
	})
	h := newHarness(t, f.srv.URL)
	h.stdin = strings.NewReader("old password 1\nnew password 22\n")
	code, _, stderr := h.run("passwd")
	mustExit(t, 0, code, stderr)
	if body["current_password"] != "old password 1" || body["new_password"] != "new password 22" || f.last().Path != "/api/v1/auth/password" {
		t.Fatalf("%v %s", body, f.last().Path)
	}
	h.stdin = strings.NewReader("only one line\n")
	code, _, _ = h.run("passwd")
	mustExit(t, 2, code, "")
}

// ---- tokens ----

func TestParseTTL(t *testing.T) {
	good := map[string]int64{"1m": 60, "60s": 60, "30m": 1800, "12h": 43200, "7d": 604800, "90d": 7776000, "2160h": 7776000}
	for s, want := range good {
		got, err := parseTTL(s)
		if err != nil || got != want {
			t.Errorf("%s: %d %v", s, got, err)
		}
	}
	for _, s := range []string{"", "59s", "0m", "91d", "7776001s", "1w", "1.5h", "-1h", "h", "10", " 1h", "1H", "99999999999d"} {
		if _, err := parseTTL(s); err == nil {
			t.Errorf("%q accepted", s)
		} else if err.(*cliError).code != ExitValidation {
			t.Errorf("%q: code %d", s, err.(*cliError).code)
		}
	}
}

func TestTokenCreate(t *testing.T) {
	var body map[string]any
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, b []byte) {
		body = nil
		_ = json.Unmarshal(b, &body)
		jsonReply(w, 201, map[string]any{"id": "tok_9", "token": "cof_st_SECRET", "access": "read", "expires_at": "x"})
	})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("token", "create", "-p", "app", "-e", "prod", "--access", "read", "--ttl", "7d", "--name", "ci")
	mustExit(t, 0, code, stderr)
	if out != "cof_st_SECRET\n" || !strings.Contains(stderr, "id: tok_9") || strings.Contains(stderr, "cof_st_") {
		t.Fatalf("out %q stderr %q", out, stderr)
	}
	if body["project"] != "app" || body["env"] != "prod" || body["access"] != "read" || body["ttl_seconds"].(float64) != 604800 || body["name"] != "ci" {
		t.Fatalf("%v", body)
	}
	code, out, _ = h.run("token", "create", "-p", "app", "-e", "prod", "--access", "read", "--ttl", "30m", "--json")
	mustExit(t, 0, code, "")
	var m map[string]any
	if json.Unmarshal([]byte(out), &m) != nil || m["token"] != "cof_st_SECRET" || m["id"] != "tok_9" {
		t.Fatalf("%q", out)
	}
	if _, ok := body["name"]; ok {
		t.Fatal("name sent without flag")
	}
	n := len(f.reqs())
	code, _, _ = h.run("token", "create", "-p", "app", "-e", "prod", "--access", "read", "--ttl", "100d")
	mustExit(t, 6, code, "")
	if len(f.reqs()) != n {
		t.Fatal("request sent for bad ttl")
	}
}

func TestTokenRevokeAndList(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.Method == "GET" {
			jsonReply(w, 200, []map[string]any{{"id": "tok_1", "name": "ci", "project": "p", "env": "e", "access": "read"}})
			return
		}
		jsonReply(w, 200, map[string]string{"status": "revoked"})
	})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("token", "list")
	mustExit(t, 0, code, stderr)
	if !strings.HasPrefix(out, "ID\tNAME\tPROJECT") || !strings.Contains(out, "tok_1\tci\tp\te\tread") {
		t.Fatalf("%q", out)
	}
	code, _, stderr = h.run("token", "revoke", "tok_1")
	mustExit(t, 0, code, stderr)
	if r := f.last(); r.Method != "DELETE" || r.Path != "/api/v1/tokens/tok_1" {
		t.Fatalf("%+v", r)
	}
}

// ---- members ----

func TestMemberEmailLookup(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.Method == "GET" && r.URL.Path == "/api/v1/members" {
			jsonReply(w, 200, []map[string]any{{"id": "usr_a", "email": "alice@x.io", "role": "member"}, {"id": "usr_b", "email": "Bob@X.io", "role": "admin"}})
			return
		}
		jsonReply(w, 200, map[string]any{"ok": true})
	})
	h := newHarness(t, f.srv.URL)
	code, _, stderr := h.run("member", "role", "bob@x.io", "owner")
	mustExit(t, 0, code, stderr)
	if r := f.last(); r.Method != "PATCH" || r.Path != "/api/v1/members/usr_b" || string(r.Body) != "{\"role\":\"owner\"}\n" {
		t.Fatalf("%+v %s", r, r.Body)
	}
	code, _, _ = h.run("member", "remove", "alice@x.io")
	mustExit(t, 0, code, "")
	if r := f.last(); r.Method != "DELETE" || r.Path != "/api/v1/members/usr_a" {
		t.Fatalf("%+v", r)
	}
	code, _, _ = h.run("grant", "set", "alice@x.io", "-p", "app", "--level", "reader")
	mustExit(t, 0, code, "")
	if r := f.last(); r.Method != "PUT" || r.Path != "/api/v1/members/usr_a/grants/app" || string(r.Body) != "{\"level\":\"reader\"}\n" {
		t.Fatalf("%+v", r)
	}
	code, _, _ = h.run("grant", "revoke", "alice@x.io", "--project=app")
	mustExit(t, 0, code, "")
	if r := f.last(); r.Method != "DELETE" || r.Path != "/api/v1/members/usr_a/grants/app" {
		t.Fatalf("%+v", r)
	}
	n := len(f.reqs())
	code, _, _ = h.run("member", "remove", "nobody@x.io")
	mustExit(t, 5, code, "")
	if len(f.reqs()) != n+1 {
		t.Fatal("expected only the lookup request")
	}
}

func TestMemberAddPasswordFromStdin(t *testing.T) {
	var body map[string]string
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, b []byte) {
		_ = json.Unmarshal(b, &body)
		jsonReply(w, 201, map[string]any{"id": "usr_n", "email": "n@x.io", "role": "member"})
	})
	h := newHarness(t, f.srv.URL)
	h.stdin = strings.NewReader("initial-password-1\n")
	code, _, stderr := h.run("member", "add", "n@x.io", "--role", "member")
	mustExit(t, 0, code, stderr)
	if body["email"] != "n@x.io" || body["role"] != "member" || body["password"] != "initial-password-1" {
		t.Fatalf("%v", body)
	}
}

func TestAdminOrgCreate(t *testing.T) {
	var body map[string]string
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, b []byte) {
		_ = json.Unmarshal(b, &body)
		jsonReply(w, 201, map[string]any{"id": "org_1", "slug": "acme", "owner": map[string]any{"email": "o@acme.io"}})
	})
	h := newHarness(t, f.srv.URL)
	h.stdin = strings.NewReader("owner-password-1\n")
	code, _, stderr := h.run("admin", "org", "create", "acme", "--owner-email", "o@acme.io")
	mustExit(t, 0, code, stderr)
	if body["slug"] != "acme" || body["owner_email"] != "o@acme.io" || body["owner_password"] != "owner-password-1" || f.last().Path != "/api/v1/admin/orgs" {
		t.Fatalf("%v", body)
	}
	code, _, _ = h.run("admin", "org", "disable", "acme")
	mustExit(t, 0, code, "")
	if r := f.last(); r.Method != "POST" || r.Path != "/api/v1/admin/orgs/acme/disable" {
		t.Fatalf("%+v", r)
	}
}

// ---- audit ----

func TestAuditVerify(t *testing.T) {
	valid := true
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if valid {
			jsonReply(w, 200, map[string]any{"valid": true, "first_invalid_seq": nil})
		} else {
			jsonReply(w, 200, map[string]any{"valid": false, "first_invalid_seq": 17})
		}
	})
	h := newHarness(t, f.srv.URL)
	for _, args := range [][]string{{"audit", "verify"}, {"admin", "audit", "verify"}} {
		valid = true
		code, out, _ := h.run(args...)
		mustExit(t, 0, code, "")
		if out != "chain valid\n" {
			t.Fatalf("%q", out)
		}
		valid = false
		code, out, _ = h.run(args...)
		mustExit(t, 9, code, "")
		if out != "chain invalid at seq 17\n" {
			t.Fatalf("%q", out)
		}
		code, out, _ = h.run(append(args, "--json")...)
		mustExit(t, 9, code, "")
		var m map[string]any
		if json.Unmarshal([]byte(out), &m) != nil || m["valid"] != false || m["first_invalid_seq"].(float64) != 17 {
			t.Fatalf("%q", out)
		}
	}
	if f.reqs()[0].Path != "/api/v1/audit/verify" || f.last().Path != "/api/v1/admin/audit/verify" {
		t.Fatal("paths")
	}
}

func TestAuditListQueryAndSanitize(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 200, []map[string]any{{"seq": 1, "ts": "t", "actor": map[string]any{"type": "user", "id": "usr_1"}, "action": "authz.denied", "target": "GET /x p=\x1b[31mevil\tcol\n", "result": "denied", "source_ip": "127.0.0.1"}})
	})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("audit", "list", "--actor", "usr_1", "--action=secret.read", "--since", "2026-01-01T00:00:00Z", "--limit", "5")
	mustExit(t, 0, code, stderr)
	q := f.last().Query
	for _, want := range []string{"actor=usr_1", "action=secret.read", "since=2026-01-01T00%3A00%3A00Z", "limit=5"} {
		if !strings.Contains(q, want) {
			t.Fatalf("query %q missing %q", q, want)
		}
	}
	if strings.ContainsAny(out[strings.Index(out, "\n")+1:len(out)-1], "\x1b\n") || strings.Count(out, "\t") != 12 {
		t.Fatalf("unsanitized table: %q", out)
	}
	if !strings.Contains(out, `\x1b[31mevil\tcol\n`) {
		t.Fatalf("%q", out)
	}
	code, out, _ = h.run("audit", "list", "--json")
	mustExit(t, 0, code, "")
	var arr []any
	if json.Unmarshal([]byte(out), &arr) != nil || len(arr) != 1 {
		t.Fatalf("%q", out)
	}
}

// ---- changes ----

func TestChangeCommands(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		switch {
		case r.Method == "GET":
			jsonReply(w, 200, []map[string]any{{"id": "chg_1", "status": "pending"}})
		case strings.HasSuffix(r.URL.Path, "/approve"):
			errReply(409, "conflict", "stale")(w, r, nil)
		default:
			jsonReply(w, 200, map[string]any{"id": "chg_1", "status": "rejected"})
		}
	})
	h := newHarness(t, f.srv.URL)
	code, _, _ := h.run("change", "list", "--status", "pending")
	mustExit(t, 0, code, "")
	if f.last().Query != "status=pending" {
		t.Fatal(f.last().Query)
	}
	code, _, _ = h.run("change", "approve", "chg_1")
	mustExit(t, 8, code, "")
	if r := f.last(); r.Method != "POST" || r.Path != "/api/v1/changes/chg_1/approve" || len(r.Body) != 0 {
		t.Fatalf("%+v", r)
	}
	code, out, _ := h.run("change", "reject", "chg_1")
	mustExit(t, 0, code, "")
	if out != "rejected change chg_1\n" {
		t.Fatalf("%q", out)
	}
}

// ---- projects & envs ----

func TestProjectEnvCommands(t *testing.T) {
	var body map[string]any
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, b []byte) {
		body = nil
		_ = json.Unmarshal(b, &body)
		if r.Method == "GET" {
			jsonReply(w, 200, []map[string]any{{"id": "env_1", "slug": "prod", "protected": true}})
			return
		}
		jsonReply(w, 201, map[string]any{"id": "x"})
	})
	h := newHarness(t, f.srv.URL)
	code, _, _ := h.run("project", "create", "app")
	mustExit(t, 0, code, "")
	if f.last().Path != "/api/v1/projects" || body["slug"] != "app" {
		t.Fatal(body)
	}
	code, _, _ = h.run("env", "create", "prod", "-p", "app", "--protected")
	mustExit(t, 0, code, "")
	if f.last().Path != "/api/v1/projects/app/envs" || body["slug"] != "prod" || body["protected"] != true {
		t.Fatal(body)
	}
	code, _, _ = h.run("env", "create", "dev", "-p", "app")
	mustExit(t, 0, code, "")
	if body["protected"] != false {
		t.Fatal(body)
	}
	code, out, _ := h.run("env", "list", "-p", "app")
	mustExit(t, 0, code, "")
	if out != "ID\tSLUG\tPROTECTED\tCREATED_AT\nenv_1\tprod\ttrue\t-\n" {
		t.Fatalf("%q", out)
	}
}

func TestJSONOutputSingleDocument(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 200, []map[string]any{{"key": "A", "version": 1}})
	})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("secrets", "list", "-p", "a", "-e", "b", "--json")
	mustExit(t, 0, code, stderr)
	dec := json.NewDecoder(strings.NewReader(out))
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		t.Fatalf("%q", out)
	}
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"plain":        "plain",
		"a\tb":         `a\tb`,
		"\x1b[2J":      `\x1b[2J`,
		"ok\u202eevil": `ok\u202eevil`,
		"bad\xffbyte":  `bad\xffbyte`,
		"ünïcødé 日本":   "ünïcødé 日本",
		"del\x7f":      `del\x7f`,
		"c1\u009b31m":  `c1\x9b31m`,
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

// --json must print exactly one JSON document even for a dotenv export; the
// dotenv text is wrapped byte-exact in {"format":"dotenv","content":...}.
func TestExportDotenvWithJSONIsWrapped(t *testing.T) {
	dotenv := "A=\"x\\\"y <&>   é\"\nB=\"line\\nnext \\$HOME\\r\"\n"
	f := newFake(t, rawReply(200, "text/plain; charset=utf-8", dotenv))
	h := newHarness(t, f.srv.URL)
	for _, args := range [][]string{
		{"--json", "secrets", "export", "-p", "a", "-e", "b", "--format", "dotenv"},
		{"secrets", "export", "-p", "a", "-e", "b", "--format=dotenv", "--json"},
	} {
		code, out, stderr := h.run(args...)
		mustExit(t, 0, code, stderr)
		dec := json.NewDecoder(strings.NewReader(out))
		var doc map[string]string
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("%v: not JSON: %v %q", args, err, out)
		}
		if dec.More() {
			t.Fatalf("%v: more than one JSON document: %q", args, out)
		}
		if len(doc) != 2 || doc["format"] != "dotenv" || doc["content"] != dotenv {
			t.Fatalf("%v: %#v", args, doc)
		}
		if f.last().Query != "format=dotenv" {
			t.Fatalf("query %q", f.last().Query)
		}
	}
	// empty environment: content is the empty string
	f2 := newFake(t, rawReply(200, "text/plain; charset=utf-8", ""))
	h2 := newHarness(t, f2.srv.URL)
	code, out, stderr := h2.run("--json", "secrets", "export", "-p", "a", "-e", "b", "--format", "dotenv")
	mustExit(t, 0, code, stderr)
	var doc map[string]string
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc["content"] != "" || doc["format"] != "dotenv" {
		t.Fatalf("%q %v", out, err)
	}
	// non-UTF-8 body cannot be represented exactly: error, stdout empty
	f3 := newFake(t, rawReply(200, "text/plain; charset=utf-8", "A=\"\xff\"\n"))
	h3 := newHarness(t, f3.srv.URL)
	code, out, _ = h3.run("--json", "secrets", "export", "-p", "a", "-e", "b", "--format", "dotenv")
	if code != 1 || out != "" {
		t.Fatalf("code %d out %q", code, out)
	}
}

// The --json error document carries the server's message and code verbatim;
// the human "error:" line keeps the "(code)" suffix.
func TestJSONErrorUsesRawServerMessage(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 404, map[string]any{"error": map[string]string{"code": "not_found", "message": "secret not found"}})
	})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("--json", "secrets", "get", "NOPE", "-p", "app", "-e", "dev")
	mustExit(t, 5, code, stderr)
	if out != "" {
		t.Fatalf("stdout %q", out)
	}
	if !strings.Contains(stderr, "error: secret not found (not_found)\n") {
		t.Fatalf("human line missing: %q", stderr)
	}
	i := strings.Index(stderr, "{")
	var doc map[string]map[string]string
	if i < 0 || json.Unmarshal([]byte(stderr[i:]), &doc) != nil {
		t.Fatalf("no JSON doc: %q", stderr)
	}
	if doc["error"]["code"] != "not_found" || doc["error"]["message"] != "secret not found" {
		t.Fatalf("%v", doc)
	}
	// server error without a code: message verbatim, code falls back to http_<status>
	f2 := newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		jsonReply(w, 403, map[string]any{"error": map[string]string{"message": "nope"}})
	})
	h2 := newHarness(t, f2.srv.URL)
	code, _, stderr = h2.run("--json", "secrets", "get", "K", "-p", "app", "-e", "dev")
	mustExit(t, 4, code, stderr)
	if !strings.Contains(stderr, "error: nope\n") {
		t.Fatalf("human line: %q", stderr)
	}
	i = strings.Index(stderr, "{")
	doc = nil
	if i < 0 || json.Unmarshal([]byte(stderr[i:]), &doc) != nil || doc["error"]["code"] != "http_403" || doc["error"]["message"] != "nope" {
		t.Fatalf("%q", stderr)
	}
}
