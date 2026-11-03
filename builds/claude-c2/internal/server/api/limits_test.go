package api_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// R2-S5: live keys per environment are capped (409 beyond the cap); updates,
// deletes and creation after a delete keep working.
func TestLiveKeyCap(t *testing.T) {
	s, o := simple(t)
	ctx := t.Context()
	o.Must(t, 200, "PUT", sp+"SEED", map[string]string{"value": "x"})
	// Fill the environment up to the cap directly (metadata only: these
	// rows are never read back).
	if _, err := s.DB.Owner.Exec(ctx, `INSERT INTO secrets (env_id, key, current_version, deleted, updated_at, updated_by)
		SELECT env_id, 'K' || g, 1, false, now(), 'test' FROM secrets, generate_series(2, 10000) g WHERE key='SEED'`); err != nil {
		t.Fatal(err)
	}
	o.Must(t, 409, "PUT", sp+"ONE_TOO_MANY", map[string]string{"value": "x"})
	o.Must(t, 200, "PUT", sp+"SEED", map[string]string{"value": "updated"})
	// Proposals that would create a key are refused too.
	o.Must(t, 201, "POST", "/projects/app/envs", map[string]any{"slug": "prd", "protected": true})
	if _, err := s.DB.Owner.Exec(ctx, `INSERT INTO secrets (env_id, key, current_version, deleted, updated_at, updated_by)
		SELECT e.id, 'K' || g, 1, false, now(), 'test' FROM environments e, generate_series(1, 10000) g WHERE e.slug='prd'`); err != nil {
		t.Fatal(err)
	}
	o.Must(t, 409, "PUT", "/projects/app/envs/prd/secrets/NEW", map[string]string{"value": "x"})
	// Freeing a slot allows a new key again.
	o.Must(t, 200, "DELETE", sp+"SEED", nil)
	o.Must(t, 200, "PUT", sp+"ONE_TOO_MANY", map[string]string{"value": "x"})
	o.Must(t, 409, "PUT", sp+"SEED", map[string]string{"value": "again"})
}

// R2-S5: export streams in batches; the result is identical to an in-memory
// build (sorted, exact bytes) and every key is audited once.
func TestExportBatches(t *testing.T) {
	s, o := simple(t)
	want := map[string]string{}
	for i := 0; i < 600; i++ {
		k := fmt.Sprintf("K%04d", i)
		v := fmt.Sprintf("v%d \"q\" $x\n\\ <&>", i)
		want[k] = v
		o.Must(t, 200, "PUT", sp+k, map[string]string{"value": v})
	}
	r := o.Must(t, 200, "GET", "/projects/app/envs/dev/export?format=json", nil)
	var got map[string]string
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d keys", len(got))
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s = %q, want %q", k, got[k], v)
		}
	}
	if !strings.HasPrefix(string(r.Body), `{"K0000":`) || !strings.HasSuffix(string(r.Body), "}\n") {
		t.Errorf("json framing: %.40q ... %q", r.Body, r.Body[len(r.Body)-20:])
	}
	r = o.Must(t, 200, "GET", "/projects/app/envs/dev/export?format=dotenv", nil)
	lines := strings.Split(strings.TrimSuffix(string(r.Body), "\n"), "\n")
	if len(lines) != 600 || !strings.HasPrefix(lines[0], `K0000="v0 \"q\" \$x\n\\ <&>"`) || !strings.HasPrefix(lines[599], "K0599=") {
		t.Errorf("dotenv: %d lines, first %q", len(lines), lines[0])
	}
	var n int
	if err := s.DB.Owner.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='secret.read' AND details->>'via'='export'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1200 {
		t.Errorf("export read events = %d, want 1200", n)
	}
	// Empty environment.
	o.Must(t, 201, "POST", "/projects/app/envs", map[string]any{"slug": "empty"})
	if r := o.Must(t, 200, "GET", "/projects/app/envs/empty/export?format=json", nil); string(r.Body) != "{}\n" {
		t.Errorf("empty json export %q", r.Body)
	}
	if r := o.Must(t, 200, "GET", "/projects/app/envs/empty/export?format=dotenv", nil); len(r.Body) != 0 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("empty dotenv export %q %s", r.Body, r.Header.Get("Content-Type"))
	}
	// Versions listing streams too.
	var vs []map[string]any
	o.Must(t, 200, "GET", sp+"K0001/versions", nil).JSON(t, &vs)
	if len(vs) != 1 || vs[0]["version"] != float64(1) {
		t.Errorf("versions %v", vs)
	}
	o.Must(t, 404, "GET", sp+"NOPE/versions", nil)
}
