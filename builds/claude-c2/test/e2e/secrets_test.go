//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// TestSecretsVersioning covers SPEC §3 versions, tombstones, rollback and
// expected-version concurrency.
func TestSecretsVersioning(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "ver")
	o.project(t, "app", map[string]bool{"dev": false})
	tok := o.Owner.Token
	p := secPath("app", "dev", "API_KEY")

	if v := setSecret(t, tok, "app", "dev", "API_KEY", "one"); v != 1 {
		t.Fatalf("first set version %d, want 1", v)
	}
	if v := setSecret(t, tok, "app", "dev", "API_KEY", "two"); v != 2 {
		t.Fatalf("second set version %d, want 2", v)
	}
	r := must(t, 200, api(t, "DELETE", p, tok, nil), "delete")
	if num(r.obj(t), "version") != 3 {
		t.Errorf("delete should create tombstone version 3: %s", r)
	}
	must(t, 404, api(t, "GET", p, tok, nil), "get after delete")
	if r := api(t, "GET", p, tok, nil); string(r.Body) != notFoundBody {
		t.Errorf("tombstone 404 body differs: %s", r.Body)
	}
	must(t, 404, api(t, "DELETE", p, tok, nil), "delete twice")
	// The list excludes deleted heads.
	for _, x := range must(t, 200, api(t, "GET", secPath("app", "dev", ""), tok, nil), "list").arr(t) {
		if x["key"] == "API_KEY" {
			t.Errorf("deleted key listed: %v", x)
		}
	}
	h := must(t, 200, api(t, "GET", p+"/versions", tok, nil), "history").arr(t)
	if len(h) != 3 || h[2]["deleted"] != true || h[0]["deleted"] != false || num(h[0], "version") != 1 {
		t.Fatalf("history should keep the tombstone: %v", h)
	}
	for _, x := range h {
		if _, ok := x["value"]; ok {
			t.Errorf("history leaks value: %v", x)
		}
		if str(x, "created_by") == "" || str(x, "created_at") == "" {
			t.Errorf("history missing created_by/at: %v", x)
		}
	}
	must(t, 404, api(t, "GET", p+"/versions/3", tok, nil), "get tombstone version")
	must(t, 400, api(t, "GET", p+"/versions/abc", tok, nil), "non-integer version")
	if g := must(t, 200, api(t, "GET", p+"/versions/1", tok, nil), "v1").obj(t); str(g, "value") != "one" || num(g, "version") != 1 {
		t.Errorf("version 1: %v", g)
	}
	// Later set continues numbering.
	if v := setSecret(t, tok, "app", "dev", "API_KEY", "four"); v != 4 {
		t.Errorf("set after delete: version %d, want 4", v)
	}
	// Rollback to k creates a new version with k's value.
	r = must(t, 200, api(t, "POST", p+"/rollback", tok, map[string]int{"to": 1}), "rollback")
	if num(r.obj(t), "version") != 5 {
		t.Errorf("rollback version: %s", r)
	}
	if g := must(t, 200, api(t, "GET", p, tok, nil), "get").obj(t); str(g, "value") != "one" || num(g, "version") != 5 {
		t.Errorf("after rollback: %v", g)
	}
	must(t, 404, api(t, "POST", p+"/rollback", tok, map[string]int{"to": 3}), "rollback to tombstone")
	must(t, 404, api(t, "POST", p+"/rollback", tok, map[string]int{"to": 99}), "rollback to missing")
	must(t, 400, api(t, "POST", p+"/rollback", tok, map[string]string{"to": "1"}), "rollback non-int")

	// expected_version.
	must(t, 409, api(t, "PUT", p, tok, map[string]any{"value": "x", "expected_version": 4}), "stale expected_version")
	must(t, 200, api(t, "PUT", p, tok, map[string]any{"value": "six", "expected_version": 5}), "matching expected_version")
	must(t, 409, api(t, "PUT", secPath("app", "dev", "FRESH"), tok, map[string]any{"value": "x", "expected_version": 1}), "expected on absent key")
	must(t, 200, api(t, "PUT", secPath("app", "dev", "FRESH"), tok, map[string]any{"value": "x", "expected_version": 0}), "expected 0 on absent key")
	must(t, 409, api(t, "PUT", secPath("app", "dev", "FRESH"), tok, map[string]any{"value": "x", "expected_version": 0}), "expected 0 on existing key")
	must(t, 400, api(t, "PUT", p, tok, map[string]any{"value": "x", "expected_version": -1}), "negative expected_version")

	// CLI: --expect-version mismatch exits 8; rollback via CLI.
	c := newCLIEnv(t)
	c.Token = tok
	c.want(t, 8, nil, "secrets", "set", "API_KEY", "nope", "-p", "app", "-e", "dev", "--expect-version", "1")
	c.want(t, 0, nil, "secrets", "set", "API_KEY", "seven", "-p", "app", "-e", "dev", "--expect-version=6")
	c.want(t, 0, nil, "secrets", "rollback", "API_KEY", "--to", "2", "-p", "app", "-e", "dev")
	if r := c.want(t, 0, nil, "secrets", "get", "API_KEY", "-p", "app", "-e", "dev"); string(r.Stdout) != "two" {
		t.Errorf("after CLI rollback: %s", r)
	}
	if r := c.want(t, 0, nil, "secrets", "get", "API_KEY", "-p", "app", "-e", "dev", "--version", "4"); string(r.Stdout) != "four" {
		t.Errorf("get --version 4: %s", r)
	}
	r2 := c.want(t, 0, nil, "secrets", "history", "API_KEY", "-p", "app", "-e", "dev", "--json")
	var hist []map[string]any
	if err := json.Unmarshal(r2.Stdout, &hist); err != nil || len(hist) != 8 {
		t.Errorf("history --json: %v %s", err, r2)
	}
	c.want(t, 0, nil, "secrets", "delete", "API_KEY", "-p", "app", "-e", "dev")
	c.want(t, 5, nil, "secrets", "get", "API_KEY", "-p", "app", "-e", "dev")
	c.want(t, 5, nil, "secrets", "get", "NOPE", "-p", "app", "-e", "dev")
	c.want(t, 6, nil, "secrets", "set", "bad-key", "v", "-p", "app", "-e", "dev")
}

// TestSecretsConcurrentWrites: distinct versions, no gaps, no lost updates (SPEC §3).
func TestSecretsConcurrentWrites(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "conc")
	o.project(t, "app", map[string]bool{"dev": false})
	const n = 25
	var wg sync.WaitGroup
	versions := make([]int, n)
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := api(t, "PUT", secPath("app", "dev", "COUNTER"), o.Owner.Token, map[string]string{"value": fmt.Sprint(i)})
			statuses[i] = r.Status
			var m map[string]any
			_ = json.Unmarshal(r.Body, &m)
			versions[i] = num(m, "version")
		}(i)
	}
	wg.Wait()
	for i, s := range statuses {
		if s != 200 {
			t.Fatalf("concurrent write %d: status %d", i, s)
		}
	}
	sort.Ints(versions)
	for i, v := range versions {
		if v != i+1 {
			t.Fatalf("versions not distinct/gap-free: %v", versions)
		}
	}
	h := must(t, 200, api(t, "GET", secPath("app", "dev", "COUNTER")+"/versions", o.Owner.Token, nil), "history").arr(t)
	if len(h) != n {
		t.Fatalf("history has %d versions, want %d", len(h), n)
	}
	// Every write's value is preserved in its own version (no lost updates).
	seen := map[string]bool{}
	for v := 1; v <= n; v++ {
		g := must(t, 200, api(t, "GET", fmt.Sprintf("%s/versions/%d", secPath("app", "dev", "COUNTER"), v), o.Owner.Token, nil), "get version").obj(t)
		seen[str(g, "value")] = true
	}
	if len(seen) != n {
		t.Errorf("lost updates: only %d distinct values over %d versions", len(seen), n)
	}
}

// TestSecretsValidation covers SPEC §3 format rules.
func TestSecretsValidation(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "val")
	o.project(t, "app", map[string]bool{"dev": false})
	tok := o.Owner.Token
	put := func(key string, body any) resp { return api(t, "PUT", secPath("app", "dev", key), tok, body) }

	long := "K" + strings.Repeat("A", 127)
	must(t, 200, put(long, map[string]string{"value": "x"}), "128-char key")
	must(t, 400, put(long+"A", map[string]string{"value": "x"}), "129-char key")
	must(t, 200, put("_LEADING", map[string]string{"value": "x"}), "underscore key")
	for _, k := range []string{"lower", "1START", "HAS-DASH", "HAS.DOT", "SP%20ACE", "%C3%84"} {
		if r := put(k, map[string]string{"value": "x"}); r.Status != 400 {
			t.Errorf("key %q: want 400, got %s", k, r)
		}
	}
	must(t, 200, put("EMPTY", map[string]string{"value": ""}), "empty value")
	if g := must(t, 200, api(t, "GET", secPath("app", "dev", "EMPTY"), tok, nil), "get empty").obj(t); g["value"] != "" {
		t.Errorf("empty value round-trip: %v", g)
	}
	max := strings.Repeat("é", 32768) // 65,536 bytes
	must(t, 200, put("MAXVAL", map[string]string{"value": max}), "65536-byte value")
	if g := must(t, 200, api(t, "GET", secPath("app", "dev", "MAXVAL"), tok, nil), "get max").obj(t); str(g, "value") != max {
		t.Errorf("max value not returned exactly")
	}
	must(t, 400, put("TOOBIG", map[string]string{"value": max + "x"}), "65537-byte value")
	must(t, 400, put("NUMVAL", `{"value":12}`), "non-string value")
	must(t, 400, put("NOVAL", `{}`), "missing value")
	must(t, 400, put("BADJSON", `{"value":`), "malformed JSON")
	must(t, 400, put("ARR", `["x"]`), "non-object JSON")
	must(t, 400, put("BADUTF", []byte("{\"value\":\"\xff\xfe\"}")), "invalid UTF-8")
	must(t, 400, put("NOBODY", nil), "empty body")
	must(t, 400, put("EXTRA", `{"value":"x","version":99}`), "unknown field")

	// CLI rejects invalid UTF-8 locally with exit 6.
	c := newCLIEnv(t)
	c.Token = tok
	c.want(t, 6, []byte{0xff, 0xfe, 'a'}, "secrets", "set", "BADUTF", "-p", "app", "-e", "dev")
	must(t, 404, api(t, "GET", secPath("app", "dev", "BADUTF"), tok, nil), "invalid UTF-8 must not be stored")
}

// TestByteExactCLI: stdin to EOF in, exact bytes out through a pipe (SPEC §3, §7.1).
func TestByteExactCLI(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "bytes")
	o.project(t, "app", map[string]bool{"dev": false})
	c := newCLIEnv(t)
	c.Token = o.Owner.Token
	values := map[string]string{
		"TRAILING_NL":  "value\n",
		"CRLF":         "a\r\nb\r\n",
		"MULTI":        "line1\nline2\n\n",
		"SPACES":       "  padded  ",
		"UNICODE":      "pässwörd ✓ 日本 🚀",
		"SHELL":        `$HOME "quoted" 'single' \back\slash $(id) ` + "`x`",
		"NUL":          "a\x00b",
		"TABS":         "\t\t",
		"DASH":         "-starts-with-dash",
		"EMPTY_STDIN":  "",
		"PEM":          "-----BEGIN KEY-----\nMIIB\n-----END KEY-----\n",
		"JSON_LOOKING": `{"value":"inner"}`,
	}
	for k, v := range values {
		c.want(t, 0, []byte(v), "secrets", "set", k, "-p", "app", "-e", "dev")
		r := c.want(t, 0, nil, "secrets", "get", k, "-p", "app", "-e", "dev")
		if !bytes.Equal(r.Stdout, []byte(v)) {
			t.Errorf("%s: stdin->get not byte-exact: got %q want %q", k, r.Stdout, v)
		}
		// HTTP view matches too.
		g := must(t, 200, api(t, "GET", secPath("app", "dev", k), o.Owner.Token, nil), "get").obj(t)
		if str(g, "value") != v {
			t.Errorf("%s: server stored %q, want %q", k, g["value"], v)
		}
	}
	// VALUE in argv is used as-is; `--` allows a leading dash.
	c.want(t, 0, nil, "secrets", "set", "ARGV", "-p", "app", "-e", "dev", "--", "-x y\n")
	if r := c.want(t, 0, nil, "secrets", "get", "ARGV", "-p", "app", "-e", "dev"); string(r.Stdout) != "-x y\n" {
		t.Errorf("argv value after --: %q", r.Stdout)
	}
	// --json get.
	r := c.want(t, 0, nil, "secrets", "get", "MULTI", "-p", "app", "-e", "dev", "--json")
	var g map[string]any
	if err := json.Unmarshal(r.Stdout, &g); err != nil || g["value"] != values["MULTI"] || g["key"] != "MULTI" {
		t.Errorf("get --json: %v %s", err, r)
	}
}

// TestExportFormats checks dotenv escaping, sorting, and JSON shape (SPEC §7.1).
func TestExportFormats(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "export")
	o.project(t, "app", map[string]bool{"dev": false, "empty": false})
	tok := o.Owner.Token
	vals := map[string]string{
		"ZED":      "last",
		"ALPHA":    `back\slash "quote" $VAR`,
		"MIDDLE":   "line1\nline2\r\nend",
		"B_PLAIN":  "it's `fine` & <ok> # ; \t tab",
		"EMPTYVAL": "",
		"UNI":      "日本",
	}
	for k, v := range vals {
		setSecret(t, tok, "app", "dev", k, v)
	}
	setSecret(t, tok, "app", "dev", "GONE", "x")
	must(t, 200, api(t, "DELETE", secPath("app", "dev", "GONE"), tok, nil), "delete")

	want := "ALPHA=\"back\\\\slash \\\"quote\\\" \\$VAR\"\n" +
		"B_PLAIN=\"it's `fine` & <ok> # ; \t tab\"\n" +
		"EMPTYVAL=\"\"\n" +
		"MIDDLE=\"line1\\nline2\\r\\nend\"\n" +
		"UNI=\"日本\"\n" +
		"ZED=\"last\"\n"

	r := must(t, 200, api(t, "GET", "/projects/app/envs/dev/export?format=dotenv", tok, nil), "export dotenv")
	if string(r.Body) != want {
		t.Errorf("dotenv export:\n got %q\nwant %q", r.Body, want)
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") && !strings.HasPrefix(ct, "application/json") {
		t.Errorf("dotenv content type %q", ct)
	}
	c := newCLIEnv(t)
	c.Token = tok
	cr := c.want(t, 0, nil, "secrets", "export", "-p", "app", "-e", "dev", "--format", "dotenv")
	if string(cr.Stdout) != want {
		t.Errorf("CLI dotenv export:\n got %q\nwant %q", cr.Stdout, want)
	}

	r = must(t, 200, api(t, "GET", "/projects/app/envs/dev/export?format=json", tok, nil), "export json")
	var m map[string]string
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("json export not an object of strings: %v %s", err, r.Body)
	}
	if len(m) != len(vals) {
		t.Errorf("json export has %d keys, want %d (deleted keys excluded): %v", len(m), len(vals), m)
	}
	for k, v := range vals {
		if m[k] != v {
			t.Errorf("json export %s=%q want %q", k, m[k], v)
		}
	}
	assertSortedKeys(t, r.Body)
	cr = c.want(t, 0, nil, "secrets", "export", "-p", "app", "-e", "dev", "--format", "json")
	var cm map[string]string
	if err := json.Unmarshal(cr.Stdout, &cm); err != nil || len(cm) != len(vals) {
		t.Errorf("CLI json export: %v %s", err, cr)
	}
	assertSortedKeys(t, cr.Stdout)

	must(t, 400, api(t, "GET", "/projects/app/envs/dev/export?format=yaml", tok, nil), "bad format")
	if r := must(t, 200, api(t, "GET", "/projects/app/envs/empty/export?format=dotenv", tok, nil), "empty dotenv"); len(r.Body) != 0 {
		t.Errorf("empty env dotenv export should be empty: %q", r.Body)
	}
	if r := must(t, 200, api(t, "GET", "/projects/app/envs/empty/export?format=json", tok, nil), "empty json"); strings.TrimSpace(string(r.Body)) != "{}" {
		t.Errorf("empty env json export: %q", r.Body)
	}
}

func assertSortedKeys(t *testing.T, b []byte) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	if _, err := dec.Token(); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatalf("decode key: %v", err)
		}
		keys = append(keys, k.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatalf("decode value: %v", err)
		}
	}
	if !sort.StringsAreSorted(keys) {
		t.Errorf("JSON keys not sorted: %v", keys)
	}
}

// TestRun covers `coffer run` env injection and exit codes (SPEC §7.1 run).
func TestRun(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "run")
	o.project(t, "app", map[string]bool{"dev": false})
	o.project(t, "hidden", map[string]bool{"dev": false})
	tok := o.Owner.Token
	setSecret(t, tok, "app", "dev", "DB_URL", "postgres://u:p@h/db")
	setSecret(t, tok, "app", "dev", "MULTI", "a\nb $X \"q\"")
	setSecret(t, tok, "app", "dev", "E2E_CONFLICT", "from-secret")
	st := o.serviceToken(t, "app", "dev", "read", 600)
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}

	c := newCLIEnv(t)
	c.Token = st.Token
	c.Extra = []string{"E2E_CONFLICT=from-parent", "E2E_PARENT_ONLY=kept"}
	r := c.want(t, 0, nil, "run", "-p", "app", "-e", "dev", "--", "sh", "-c",
		`printf '%s|%s|%s|%s' "$DB_URL" "$E2E_CONFLICT" "$E2E_PARENT_ONLY" "$MULTI"`)
	if want := "postgres://u:p@h/db|from-secret|kept|a\nb $X \"q\""; string(r.Stdout) != want {
		t.Errorf("run env: got %q want %q", r.Stdout, want)
	}
	c.want(t, 0, nil, "run", "-p", "app", "-e", "dev", "--", "true")
	c.want(t, 3, nil, "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "exit 3")
	c.want(t, 42, nil, "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "exit 42")
	c.want(t, 143, nil, "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "kill -TERM $$")
	c.want(t, 137, nil, "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "kill -KILL $$")
	// stdin inherited.
	if r := c.want(t, 0, []byte("piped-in"), "run", "-p", "app", "-e", "dev", "--", "cat"); string(r.Stdout) != "piped-in" {
		t.Errorf("run stdin not inherited: %s", r)
	}
	// stderr inherited.
	if r := c.want(t, 0, nil, "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "echo oops >&2"); !strings.Contains(string(r.Stderr), "oops") {
		t.Errorf("run stderr not inherited: %s", r)
	}
	// Fetch failure: mapped exit code and the child must not run.
	marker := filepath.Join(t.TempDir(), "ran")
	c.want(t, 5, nil, "run", "-p", "hidden", "-e", "dev", "--", "sh", "-c", "touch "+marker)
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("child ran although the fetch failed")
	}
	bad := newCLIEnv(t)
	bad.Token = "cof_st_" + rnd(32)
	bad.want(t, 3, nil, "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "touch "+marker)
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("child ran although authentication failed")
	}
	// Nothing written to disk: the config dir stays empty and cwd is untouched.
	entries, _ := os.ReadDir(c.CfgHome)
	for _, e := range entries {
		t.Errorf("run wrote %s to disk", e.Name())
	}
	// A viewer cannot use run (reader+ required, SPEC §2.4).
	v := o.addUser(t, "viewer", "member")
	o.grant(t, v, "app", "viewer")
	vc := newCLIEnv(t)
	vc.Token = v.Token
	vc.want(t, 4, nil, "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "touch "+marker)
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("child ran although the viewer lacks read permission")
	}
}
