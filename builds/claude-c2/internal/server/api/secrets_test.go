package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/coffer-dev/coffer/internal/server/api"
	"github.com/coffer-dev/coffer/internal/server/testutil"
)

// simple builds one org with an owner, project "app" and env "dev".
func simple(t *testing.T) (*testutil.Server, *testutil.Client) {
	t.Helper()
	s := testutil.New(t)
	pa := s.Client(s.Login(t, testutil.AdminEmail, testutil.AdminPassword))
	create(t, pa, "/admin/orgs", map[string]string{"slug": "org", "owner_email": "o@org.test", "owner_password": pw})
	o := s.Client(s.Login(t, "o@org.test", pw))
	create(t, o, "/projects", map[string]string{"slug": "app"})
	create(t, o, "/projects/app/envs", map[string]any{"slug": "dev"})
	return s, o
}

const sp = "/projects/app/envs/dev/secrets/"

func TestSecretValuesExactRoundTrip(t *testing.T) {
	_, o := simple(t)
	values := map[string]string{
		"EMPTY":     "",
		"NEWLINES":  "line1\nline2\r\nline3\n",
		"QUOTES":    `he said "hi" and 'bye' \ backslash`,
		"DOLLAR":    "$HOME ${PATH} $$",
		"EMOJI":     "🔐 café ñ 中文   ",
		"NUL":       "a\x00b\x00",
		"HTMLISH":   "<script>&amp;</script>",
		"SPACES":    "  leading and trailing  ",
		"MAX":       strings.Repeat("x", api.MaxValue),
		"MAX_MULTI": strings.Repeat("é", api.MaxValue/2),
	}
	for k, v := range values {
		o.Must(t, 200, "PUT", sp+k, map[string]string{"value": v})
		got := o.Must(t, 200, "GET", sp+k, nil).Map(t)
		if got["value"] != v || got["key"] != k || got["version"].(float64) != 1 {
			t.Errorf("%s: round trip mismatch (len %d vs %d)", k, len(got["value"].(string)), len(v))
		}
	}
	// 65,537 bytes rejected; multi-byte over the limit too.
	o.Must(t, 400, "PUT", sp+"TOO_BIG", map[string]string{"value": strings.Repeat("x", api.MaxValue+1)})
	o.Must(t, 400, "PUT", sp+"TOO_BIG", map[string]string{"value": strings.Repeat("é", api.MaxValue/2) + "x"})
	o.Must(t, 404, "GET", sp+"TOO_BIG", nil)
	// Non-string / missing / null values rejected.
	for _, body := range []string{`{"value": 5}`, `{"value": null}`, `{}`, `{"value": ["a"]}`, `{"value": {"a":1}}`, `{"value": true}`, `"str"`, `[]`, ``, `{"value":"a"} {"value":"b"}`, `{"value":"a",}`} {
		if r := o.Do(t, "PUT", sp+"BAD", body); r.Status != 400 {
			t.Errorf("body %q: %d %s", body, r.Status, r.Body)
		}
	}
	// Lone surrogates rejected; valid pairs accepted.
	if r := o.Do(t, "PUT", sp+"SURR", `{"value":"\ud800"}`); r.Status != 400 {
		t.Errorf("lone high surrogate: %d", r.Status)
	}
	if r := o.Do(t, "PUT", sp+"SURR", `{"value":"\udc00x"}`); r.Status != 400 {
		t.Errorf("lone low surrogate: %d", r.Status)
	}
	o.Must(t, 200, "PUT", sp+"SURR", `{"value":"😀 \\ud800"}`)
	if got := o.Must(t, 200, "GET", sp+"SURR", nil).Map(t)["value"]; got != `😀 \ud800` {
		t.Errorf("surrogate pair: %q", got)
	}
	// Invalid UTF-8 in the raw body.
	if r := o.Do(t, "PUT", sp+"BADUTF", []byte("{\"value\":\"\xff\xfe\"}")); r.Status != 400 {
		t.Errorf("invalid utf8: %d", r.Status)
	}
	// Invalid keys.
	for _, k := range []string{"lower", "1START", "HAS-DASH", strings.Repeat("A", 129), "A%20B", "%C3%A9"} {
		if r := o.Do(t, "PUT", sp+k, map[string]string{"value": "v"}); r.Status != 400 {
			t.Errorf("key %q: %d", k, r.Status)
		}
	}
	o.Must(t, 200, "PUT", sp+strings.Repeat("A", 128), map[string]string{"value": "v"})
	o.Must(t, 200, "PUT", sp+"_UNDERSCORE_1", map[string]string{"value": "v"})

	// Export: dotenv escaping exactly per spec, sorted keys.
	r := o.Must(t, 200, "GET", "/projects/app/envs/dev/export?format=dotenv", nil)
	if ct := r.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("dotenv content type %q", ct)
	}
	body := string(r.Body)
	for _, want := range []string{
		"EMPTY=\"\"\n",
		`NEWLINES="line1\nline2\r\nline3\n"` + "\n",
		`QUOTES="he said \"hi\" and 'bye' \\ backslash"` + "\n",
		`DOLLAR="\$HOME \${PATH} \$\$"` + "\n",
		"EMOJI=\"🔐 café ñ 中文   \"\n",
		"NUL=\"a\x00b\x00\"\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dotenv missing %q", want)
		}
	}
	if !strings.HasSuffix(body, "\n") || strings.Contains(body, "\r\n\"") {
		t.Error("dotenv line endings")
	}
	var keys []string
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		keys = append(keys, strings.SplitN(line, "=", 2)[0])
	}
	if !sort.StringsAreSorted(keys) || len(keys) != len(values)+3 {
		t.Errorf("dotenv keys: %v", keys)
	}
	// JSON export: exact values, keys sorted.
	r = o.Must(t, 200, "GET", "/projects/app/envs/dev/export?format=json", nil)
	var m map[string]string
	r.JSON(t, &m)
	for k, v := range values {
		if m[k] != v {
			t.Errorf("json export %s mismatch", k)
		}
	}
	dec := json.NewDecoder(strings.NewReader(string(r.Body)))
	dec.Token()
	var order []string
	for dec.More() {
		tok, _ := dec.Token()
		order = append(order, tok.(string))
		var v any
		dec.Decode(&v)
	}
	if !sort.StringsAreSorted(order) {
		t.Errorf("json export not sorted: %v", order)
	}
	o.Must(t, 200, "GET", "/projects/app/envs/dev/export", nil) // default json
	o.Must(t, 400, "GET", "/projects/app/envs/dev/export?format=yaml", nil)
}

func TestDotenvEscape(t *testing.T) {
	cases := map[string]string{
		``:         ``,
		`a\b`:      `a\\b`,
		`"`:        `\"`,
		"\n":       `\n`,
		"\r":       `\r`,
		`$X`:       `\$X`,
		"\t'`!#=":  "\t'`!#=",
		"é😀\x00":   "é😀\x00",
		"\\n":      `\\n`,
		"a\"b$c\n": `a\"b\$c\n`,
	}
	for in, want := range cases {
		if got := api.DotenvEscape(in); got != want {
			t.Errorf("DotenvEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExportEmptyEnv(t *testing.T) {
	_, o := simple(t)
	r := o.Must(t, 200, "GET", "/projects/app/envs/dev/export?format=dotenv", nil)
	if len(r.Body) != 0 {
		t.Errorf("empty dotenv: %q", r.Body)
	}
	r = o.Must(t, 200, "GET", "/projects/app/envs/dev/export?format=json", nil)
	if strings.TrimSpace(string(r.Body)) != "{}" {
		t.Errorf("empty json: %q", r.Body)
	}
}

func TestSecretVersioning(t *testing.T) {
	_, o := simple(t)
	ver := func(r *testutil.Resp) int { return int(r.Map(t)["version"].(float64)) }
	if v := ver(o.Must(t, 200, "PUT", sp+"K", map[string]string{"value": "one"})); v != 1 {
		t.Fatalf("v1 = %d", v)
	}
	if v := ver(o.Must(t, 200, "PUT", sp+"K", map[string]string{"value": "two"})); v != 2 {
		t.Fatalf("v2 = %d", v)
	}
	// Delete: tombstone v3, get 404, history keeps it.
	if v := ver(o.Must(t, 200, "DELETE", sp+"K", nil)); v != 3 {
		t.Fatalf("delete version = %d", v)
	}
	o.Must(t, 404, "GET", sp+"K", nil)
	o.Must(t, 404, "DELETE", sp+"K", nil)
	o.Must(t, 404, "GET", sp+"K/versions/3", nil)
	if got := o.Must(t, 200, "GET", sp+"K/versions/1", nil).Map(t)["value"]; got != "one" {
		t.Fatalf("v1 value %v", got)
	}
	var hist []map[string]any
	o.Must(t, 200, "GET", sp+"K/versions", nil).JSON(t, &hist)
	if len(hist) != 3 || hist[2]["deleted"] != true || hist[0]["deleted"] != false {
		t.Fatalf("history %v", hist)
	}
	// Listing excludes the deleted head.
	var list []map[string]any
	o.Must(t, 200, "GET", "/projects/app/envs/dev/secrets", nil).JSON(t, &list)
	if len(list) != 0 {
		t.Fatalf("list after delete %v", list)
	}
	// Rollback works on a deleted head and creates v4 = v1's value.
	if v := ver(o.Must(t, 200, "POST", sp+"K/rollback", map[string]int{"to": 1})); v != 4 {
		t.Fatalf("rollback version %d", v)
	}
	if got := o.Must(t, 200, "GET", sp+"K", nil).Map(t); got["value"] != "one" || got["version"].(float64) != 4 {
		t.Fatalf("after rollback %v", got)
	}
	o.Must(t, 404, "POST", sp+"K/rollback", map[string]int{"to": 3}) // tombstone
	o.Must(t, 404, "POST", sp+"K/rollback", map[string]int{"to": 99})
	o.Must(t, 404, "POST", sp+"K/rollback", map[string]int{"to": 0})
	o.Must(t, 404, "POST", sp+"NEVER/rollback", map[string]int{"to": 1})
	o.Must(t, 400, "POST", sp+"K/rollback", map[string]any{"to": "1"})
	o.Must(t, 400, "POST", sp+"K/rollback", map[string]any{"to": 1.5})
	o.Must(t, 400, "POST", sp+"K/rollback", map[string]any{})
	// Set after delete continues numbering.
	o.Must(t, 200, "DELETE", sp+"K", nil) // v5
	if v := ver(o.Must(t, 200, "PUT", sp+"K", map[string]string{"value": "six"})); v != 6 {
		t.Fatalf("set after delete %d", v)
	}
	// Version parsing.
	o.Must(t, 400, "GET", sp+"K/versions/abc", nil)
	o.Must(t, 400, "GET", sp+"K/versions/-1", nil)
	o.Must(t, 400, "GET", sp+"K/versions/1.0", nil)
	o.Must(t, 404, "GET", sp+"K/versions/0", nil)
	o.Must(t, 404, "GET", sp+"K/versions/99999999999999999999", nil)
	o.Must(t, 404, "GET", sp+"NEVER/versions", nil)

	// expected_version semantics.
	o.Must(t, 409, "PUT", sp+"K", map[string]any{"value": "x", "expected_version": 5})
	o.Must(t, 200, "PUT", sp+"K", map[string]any{"value": "x", "expected_version": 6})
	o.Must(t, 409, "PUT", sp+"NEW", map[string]any{"value": "x", "expected_version": 1})
	o.Must(t, 404, "GET", sp+"NEW", nil) // the failed conditional write left nothing behind
	o.Must(t, 404, "GET", sp+"NEW/versions", nil)
	o.Must(t, 200, "PUT", sp+"NEW", map[string]any{"value": "x", "expected_version": 0})
	o.Must(t, 409, "PUT", sp+"NEW", map[string]any{"value": "x", "expected_version": 0})
	o.Must(t, 400, "PUT", sp+"NEW", map[string]any{"value": "x", "expected_version": -1})
	o.Must(t, 400, "PUT", sp+"NEW", map[string]any{"value": "x", "expected_version": "1"})
	o.Must(t, 400, "PUT", sp+"NEW", map[string]any{"value": "x", "expected_version": 1.5})
	o.Must(t, 409, "DELETE", sp+"NEW?expected_version=7", nil)
	o.Must(t, 400, "DELETE", sp+"NEW?expected_version=x", nil)
	o.Must(t, 200, "DELETE", sp+"NEW?expected_version=1", nil)
	o.Must(t, 409, "POST", sp+"K/rollback", map[string]any{"to": 1, "expected_version": 1})
	o.Must(t, 200, "POST", sp+"K/rollback", map[string]any{"to": 1, "expected_version": 7})

	// Listing fields.
	o.Must(t, 200, "GET", "/projects/app/envs/dev/secrets", nil).JSON(t, &list)
	if len(list) != 1 || list[0]["key"] != "K" || list[0]["version"].(float64) != 8 || list[0]["updated_by"] == "" || list[0]["updated_at"] == "" {
		t.Fatalf("list %v", list)
	}
	if _, ok := list[0]["value"]; ok {
		t.Fatal("list includes value")
	}
}

func TestConcurrentWritesGetDistinctVersions(t *testing.T) {
	_, o := simple(t)
	const n = 50
	var wg sync.WaitGroup
	versions := make(chan int, n)
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := o.Do(t, "PUT", sp+"RACE", map[string]string{"value": fmt.Sprintf("v%d", i)})
			if r.Status != 200 {
				errs <- fmt.Sprintf("%d %s", r.Status, r.Body)
				return
			}
			var out struct{ Version int }
			json.Unmarshal(r.Body, &out)
			versions <- out.Version
		}(i)
	}
	wg.Wait()
	close(versions)
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	seen := map[int]bool{}
	for v := range versions {
		if seen[v] {
			t.Errorf("duplicate version %d", v)
		}
		seen[v] = true
	}
	for v := 1; v <= n; v++ {
		if !seen[v] {
			t.Errorf("missing version %d", v)
		}
	}
	var hist []map[string]any
	o.Must(t, 200, "GET", sp+"RACE/versions", nil).JSON(t, &hist)
	if len(hist) != n {
		t.Errorf("history has %d versions", len(hist))
	}
	// The head's value is the value of the last version.
	head := o.Must(t, 200, "GET", sp+"RACE", nil).Map(t)
	last := o.Must(t, 200, "GET", fmt.Sprintf("%sRACE/versions/%d", sp, n), nil).Map(t)
	if head["version"].(float64) != n || head["value"] != last["value"] {
		t.Errorf("head %v last %v", head, last)
	}
	// Concurrent conditional writes: exactly one wins.
	var wins, conflicts int
	var mu sync.Mutex
	var wg2 sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			r := o.Do(t, "PUT", sp+"RACE", map[string]any{"value": "cond", "expected_version": n})
			mu.Lock()
			defer mu.Unlock()
			switch r.Status {
			case 200:
				wins++
			case 409:
				conflicts++
			}
		}()
	}
	wg2.Wait()
	if wins != 1 || conflicts != 19 {
		t.Errorf("conditional writes: %d wins, %d conflicts", wins, conflicts)
	}
}

// A ciphertext copied into another row must never decrypt.
func TestCiphertextBoundToRow(t *testing.T) {
	s, o := simple(t)
	create(t, o, "/projects/app/envs", map[string]any{"slug": "prd"})
	create(t, o, "/projects", map[string]string{"slug": "other"})
	create(t, o, "/projects/other/envs", map[string]any{"slug": "dev"})
	o.Must(t, 200, "PUT", sp+"SRC", map[string]string{"value": "top-secret-source"})
	o.Must(t, 200, "PUT", sp+"SRC", map[string]string{"value": "second"})
	o.Must(t, 200, "PUT", sp+"DST", map[string]string{"value": "dest"})
	o.Must(t, 200, "PUT", "/projects/app/envs/prd/secrets/SRC", map[string]string{"value": "prod"})
	o.Must(t, 200, "PUT", "/projects/other/envs/dev/secrets/SRC", map[string]string{"value": "other"})
	ctx := t.Context()
	db := s.DB.Owner
	copyCT := func(sql string) {
		t.Helper()
		if _, err := db.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	src := `(SELECT v.ciphertext FROM secret_versions v JOIN environments e ON e.id=v.env_id JOIN projects p ON p.id=e.project_id
		WHERE p.slug='app' AND e.slug='dev' AND v.key='SRC' AND v.version=1)`
	// 1. Another key, same env.
	copyCT(`UPDATE secret_versions SET ciphertext=` + src + ` WHERE key='DST'`)
	// 2. Same key, other version.
	copyCT(`UPDATE secret_versions v SET ciphertext=` + src + ` FROM environments e JOIN projects p ON p.id=e.project_id
		WHERE e.id=v.env_id AND p.slug='app' AND e.slug='dev' AND v.key='SRC' AND v.version=2`)
	// 3. Same key, other env; 4. same key, other project.
	copyCT(`UPDATE secret_versions v SET ciphertext=` + src + ` FROM environments e JOIN projects p ON p.id=e.project_id
		WHERE e.id=v.env_id AND ((p.slug='app' AND e.slug='prd') OR p.slug='other') AND v.key='SRC'`)

	for _, path := range []string{sp + "DST", sp + "SRC", sp + "SRC/versions/2", "/projects/app/envs/prd/secrets/SRC", "/projects/other/envs/dev/secrets/SRC"} {
		r := o.Do(t, "GET", path, nil)
		if r.Status != 500 || string(r.Body) != `{"error":{"code":"internal","message":"internal error"}}` {
			t.Errorf("%s: %d %s", path, r.Status, r.Body)
		}
		if strings.Contains(string(r.Body), "top-secret") {
			t.Errorf("%s leaked value", path)
		}
	}
	for _, path := range []string{"/projects/app/envs/dev/export", "/projects/app/envs/prd/export?format=dotenv"} {
		if r := o.Do(t, "GET", path, nil); r.Status != 500 || strings.Contains(string(r.Body), "top-secret") {
			t.Errorf("%s: %d %s", path, r.Status, r.Body)
		}
	}
	// Rollback to a tampered version fails closed too.
	if r := o.Do(t, "POST", sp+"SRC/rollback", map[string]int{"to": 2}); r.Status != 500 {
		t.Errorf("rollback to tampered version: %d", r.Status)
	}
	// The untampered original still decrypts.
	if got := o.Must(t, 200, "GET", sp+"SRC/versions/1", nil).Map(t)["value"]; got != "top-secret-source" {
		t.Errorf("original: %v", got)
	}
	// Swapping project DEKs breaks decryption as well.
	copyCT(`UPDATE projects SET wrapped_dek=(SELECT wrapped_dek FROM projects WHERE slug='other') WHERE slug='app'`)
	if r := o.Do(t, "GET", sp+"SRC/versions/1", nil); r.Status != 500 {
		t.Errorf("swapped DEK: %d", r.Status)
	}
	if strings.Contains(s.LogText(), "top-secret") {
		t.Error("value in logs")
	}
}

func TestNoPlaintextInDatabase(t *testing.T) {
	s, o := simple(t)
	const marker = "PLAINTEXT-MARKER-6f1d2c"
	o.Must(t, 200, "PUT", sp+"K", map[string]string{"value": marker})
	create(t, o, "/projects/app/envs", map[string]any{"slug": "prot", "protected": true})
	o.Must(t, 202, "PUT", "/projects/app/envs/prot/secrets/K", map[string]string{"value": marker})
	o.Must(t, 200, "GET", sp+"K", nil)
	tok := create(t, o, "/tokens", map[string]any{"project": "app", "env": "dev", "access": "read", "ttl_seconds": 600})["token"].(string)
	pat := s.Login(t, "o@org.test", pw)
	// Dump every text-ish column of every table and search for secrets.
	rows, err := s.DB.Owner.Query(t.Context(), `SELECT table_name FROM information_schema.tables WHERE table_schema='public'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	for _, tbl := range tables {
		var dump string
		if err := s.DB.Owner.QueryRow(t.Context(), `SELECT coalesce(string_agg(t::text, E'\n'), '') FROM `+tbl+` t`).Scan(&dump); err != nil {
			t.Fatal(err)
		}
		for _, needle := range []string{marker, tok, pat, pw, testutil.AdminPassword, strings.TrimPrefix(tok, "cof_st_"), strings.TrimPrefix(pat, "cof_pat_")} {
			if strings.Contains(dump, needle) {
				t.Errorf("table %s contains plaintext %q", tbl, needle[:8])
			}
		}
	}
	logs := s.LogText()
	for _, needle := range []string{marker, tok, pat, pw, testutil.AdminPassword} {
		if strings.Contains(logs, needle) {
			t.Errorf("logs contain plaintext %q", needle[:8])
		}
	}
}

func TestReadsAudited(t *testing.T) {
	_, o := simple(t)
	for _, k := range []string{"A", "B", "C"} {
		o.Must(t, 200, "PUT", sp+k, map[string]string{"value": "v"})
	}
	o.Must(t, 200, "GET", sp+"A", nil)
	o.Must(t, 200, "GET", sp+"A/versions/1", nil)
	o.Must(t, 200, "GET", "/projects/app/envs/dev/export?format=dotenv", nil)
	o.Must(t, 200, "GET", "/projects/app/envs/dev/export?format=json", nil)
	var evs []map[string]any
	o.Must(t, 200, "GET", "/audit?action=secret.read", nil).JSON(t, &evs)
	if len(evs) != 2+3+3 {
		t.Fatalf("secret.read events: %d", len(evs))
	}
	exports := 0
	for _, e := range evs {
		d := e["details"].(map[string]any)
		if d["via"] == "export" {
			exports++
		}
		if !strings.HasPrefix(e["target"].(string), "app/dev/") {
			t.Errorf("target %v", e["target"])
		}
		if strings.Contains(fmt.Sprint(e), `"v"`) {
			t.Errorf("value in audit: %v", e)
		}
	}
	if exports != 6 {
		t.Errorf("export reads %d", exports)
	}
	o.Must(t, 200, "GET", "/audit?action=secret.write", nil).JSON(t, &evs)
	if len(evs) != 3 {
		t.Errorf("writes %d", len(evs))
	}
	// Filters.
	me := o.Must(t, 200, "GET", "/me", nil).Map(t)["id"].(string)
	o.Must(t, 200, "GET", "/audit?actor="+me+"&limit=2", nil).JSON(t, &evs)
	if len(evs) != 2 || evs[0]["seq"].(float64) <= evs[1]["seq"].(float64) {
		t.Errorf("actor filter/newest first: %v", evs)
	}
	o.Must(t, 200, "GET", "/audit?since=2000-01-01T00:00:00Z", nil)
	o.Must(t, 400, "GET", "/audit?since=yesterday", nil)
	for _, l := range []string{"0", "1001", "x", "-1"} {
		o.Must(t, 400, "GET", "/audit?limit="+l, nil)
	}
	o.Must(t, 200, "GET", "/audit?limit=1000", nil)
}

func TestHeadersAndRouting(t *testing.T) {
	s, o := simple(t)
	anon := s.Client("")
	check := func(r *testutil.Resp, what string) {
		t.Helper()
		h := r.Header
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" || len(h.Get("X-Request-Id")) != 32 {
			t.Errorf("%s: missing headers %v", what, h)
		}
		for k := range h {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("%s: CORS header %s", what, k)
			}
		}
		if !strings.HasPrefix(h.Get("Content-Type"), "application/json") && !strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
			t.Errorf("%s: content type %q", what, h.Get("Content-Type"))
		}
	}
	check(anon.Raw(t, "GET", "/healthz", nil, nil), "healthz")
	check(anon.Raw(t, "GET", "/readyz", nil, nil), "readyz")
	for _, p := range []string{"/", "/api", "/api/v1", "/api/v1/", "/api/v2/me", "/metrics", "/debug/pprof/", "/api/v1/projects/", "/api/v1//projects", "/api/v1/../healthz", "/healthz/"} {
		r := anon.Raw(t, "GET", p, nil, nil)
		if r.Status != 404 || string(r.Body) != notFoundBody {
			t.Errorf("%s: %d %s", p, r.Status, r.Body)
		}
		check(r, p)
	}
	r := o.Raw(t, "DELETE", "/api/v1/projects", nil, nil)
	if r.Status != 405 || !strings.Contains(string(r.Body), "method_not_allowed") || r.Header.Get("Allow") == "" {
		t.Errorf("405: %d %s %v", r.Status, r.Body, r.Header)
	}
	r = o.Raw(t, "OPTIONS", "/api/v1/projects", nil, map[string]string{"Origin": "https://evil.test", "Access-Control-Request-Method": "GET"})
	if r.Status != 405 {
		t.Errorf("OPTIONS: %d", r.Status)
	}
	check(r, "options")
	r = o.Raw(t, "GET", "/api/v1/projects", nil, map[string]string{"Origin": "https://evil.test"})
	check(r, "cors get")
	// Unauthenticated.
	for _, hdr := range []string{"", "Bearer", "Bearer ", "Basic abc", "Bearer cof_pat_short", "Bearer cof_pat_" + strings.Repeat("A", 43), "bearer cof_st_" + strings.Repeat("B", 43)} {
		h := map[string]string{}
		if hdr != "" {
			h["Authorization"] = hdr
		}
		r := anon.Raw(t, "GET", "/api/v1/projects", nil, h)
		if r.Status != 401 || !strings.Contains(string(r.Body), `"unauthenticated"`) {
			t.Errorf("auth %q: %d %s", hdr, r.Status, r.Body)
		}
		check(r, "401")
	}
	// Body limit: 1 MiB + 1 is 413 on any route, even ones ignoring bodies.
	big := strings.Repeat("a", api.MaxBody+1)
	for _, route := range []struct{ m, p string }{{"PUT", "/api/v1" + sp + "BIG"}, {"POST", "/api/v1/auth/token"}, {"GET", "/api/v1/me"}, {"POST", "/nope"}} {
		r := o.Raw(t, route.m, route.p, big, nil)
		if r.Status != 413 || !strings.Contains(string(r.Body), "payload_too_large") {
			t.Errorf("%s %s big body: %d %s", route.m, route.p, r.Status, r.Body)
		}
	}
	// Chunked (no Content-Length) oversize body too.
	req, _ := http.NewRequest("PUT", s.URL+"/api/v1"+sp+"BIG", &slowReader{n: api.MaxBody + 10})
	req.Header.Set("Authorization", "Bearer "+o.Token)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		if resp.StatusCode != 413 {
			t.Errorf("chunked big body: %d", resp.StatusCode)
		}
		resp.Body.Close()
	}
	// Exactly 1 MiB is accepted by the limiter (then fails validation).
	r = o.Raw(t, "PUT", "/api/v1"+sp+"BIG", `{"value":"`+strings.Repeat("a", api.MaxBody-12)+`"}`, nil)
	if r.Status != 400 {
		t.Errorf("1MiB body: %d", r.Status)
	}
	// Request log lines are JSON with route patterns, no query strings.
	o.Must(t, 200, "GET", "/projects/app/envs/dev/export?format=json&secret=SHOULD_NOT_APPEAR", nil)
	logs := s.LogText()
	if strings.Contains(logs, "SHOULD_NOT_APPEAR") || strings.Contains(logs, o.Token) || strings.Contains(logs, "Bearer") {
		t.Error("log leaked query/token")
	}
	found := false
	for _, line := range strings.Split(logs, "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil || m["msg"] != "request" {
			continue
		}
		if m["route"] == "GET /api/v1/projects/{p}/envs/{e}/export" {
			found = true
			for _, k := range []string{"method", "status", "duration_ms", "request_id"} {
				if _, ok := m[k]; !ok {
					t.Errorf("log missing %s: %v", k, m)
				}
			}
		}
	}
	if !found {
		t.Error("no request log line for export")
	}
}

type slowReader struct{ n int }

func (s *slowReader) Read(p []byte) (int, error) {
	if s.n <= 0 {
		return 0, io.EOF
	}
	k := len(p)
	if k > s.n {
		k = s.n
	}
	for i := 0; i < k; i++ {
		p[i] = 'a'
	}
	s.n -= k
	return k, nil
}

// Hostile path/query bytes never cause a 500 (NUL and invalid UTF-8 can't
// reach Postgres text columns).
func TestHostileIdentifiers(t *testing.T) {
	s, o := simple(t)
	pa := s.Client(s.Login(t, testutil.AdminEmail, testutil.AdminPassword))
	for _, bad := range []string{"%00", "a%00b", "%ff", "%c3%28", strings.Repeat("a", 5000), "x'%20OR%201=1--"} {
		for _, c := range []struct {
			cl     *testutil.Client
			method string
			path   string
			body   any
		}{
			{o, "GET", "/projects/" + bad + "/envs", nil},
			{o, "GET", "/projects/app/envs/" + bad + "/secrets", nil},
			{o, "GET", "/projects/" + bad + "/envs/dev/secrets/K", nil},
			{o, "PUT", "/projects/app/envs/dev/secrets/" + bad, map[string]string{"value": "v"}},
			{o, "GET", "/projects/app/envs/dev/secrets/K/versions/" + bad, nil},
			{o, "PATCH", "/members/" + bad, map[string]string{"role": "member"}},
			{o, "DELETE", "/members/" + bad, nil},
			{o, "PUT", "/members/" + bad + "/grants/app", map[string]string{"level": "reader"}},
			{o, "DELETE", "/tokens/" + bad, nil},
			{o, "POST", "/changes/" + bad + "/approve", nil},
			{o, "POST", "/changes/" + bad + "/reject", nil},
			{o, "GET", "/audit?actor=" + bad + "&action=" + bad, nil},
			{pa, "POST", "/admin/orgs/" + bad + "/disable", nil},
		} {
			r := c.cl.Do(t, c.method, c.path, c.body)
			if r.Status >= 500 {
				t.Errorf("%s %s: %d %s", c.method, c.path, r.Status, r.Body)
			}
		}
	}
	for _, email := range []string{"a\u0000@b.c", "\u0000", strings.Repeat("e", 2000) + "@x.y"} {
		r := s.Client("").Do(t, "POST", "/auth/token", map[string]string{"email": email, "password": "whatever-password"})
		if r.Status != 401 {
			t.Errorf("login %q: %d %s", email[:1], r.Status, r.Body)
		}
	}
	for _, body := range []map[string]any{
		{"project": "a\u0000", "env": "dev", "access": "read", "ttl_seconds": 600},
		{"project": "app", "env": "dev", "access": "read", "ttl_seconds": 600, "name": "n\u0000"},
	} {
		if r := o.Do(t, "POST", "/tokens", body); r.Status >= 500 {
			t.Errorf("token %v: %d", body, r.Status)
		}
	}
	if r := o.Do(t, "POST", "/members", map[string]string{"email": "x\u0000@y.z", "role": "member", "password": pw}); r.Status != 400 {
		t.Errorf("member NUL email: %d", r.Status)
	}
	// Audit chain still verifies (denial targets were sanitized consistently).
	if o.Must(t, 200, "GET", "/audit/verify", nil).Map(t)["valid"] != true {
		t.Error("org chain invalid")
	}
	if pa.Must(t, 200, "GET", "/admin/audit/verify", nil).Map(t)["valid"] != true {
		t.Error("platform chain invalid")
	}
}
