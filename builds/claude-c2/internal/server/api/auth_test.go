package api_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coffer-dev/coffer/internal/server/testutil"
)

func TestLoginResponsesIdentical(t *testing.T) {
	s, _ := simple(t)
	anon := s.Client("")
	wrong := anon.Do(t, "POST", "/auth/token", map[string]string{"email": "o@org.test", "password": "wrong-password-1"})
	unknown := anon.Do(t, "POST", "/auth/token", map[string]string{"email": "nobody@org.test", "password": "wrong-password-1"})
	malformed := anon.Do(t, "POST", "/auth/token", map[string]string{"email": "not-an-email", "password": "x"})
	for name, r := range map[string]*testutil.Resp{"wrong": wrong, "unknown": unknown, "malformed": malformed} {
		if r.Status != 401 || string(r.Body) != `{"error":{"code":"unauthenticated","message":"invalid credentials"}}` {
			t.Errorf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	// Timing is similar (both run one argon2id verification).
	measure := func(email string) time.Duration {
		start := time.Now()
		for i := 0; i < 3; i++ {
			anon.Do(t, "POST", "/auth/token", map[string]string{"email": email, "password": "wrong-password-2"})
		}
		return time.Since(start) / 3
	}
	known, unk := measure("o@org.test"), measure("ghost@org.test")
	ratio := float64(known) / float64(unk)
	if ratio < 0.33 || ratio > 3 {
		t.Errorf("login timing differs: known %v unknown %v", known, unk)
	}
	// Email is case/space-insensitive.
	s.Login(t, "  O@ORG.test ", pw)
	// Disabled org: same 401 body.
	pa := s.Client(s.Login(t, testutil.AdminEmail, testutil.AdminPassword))
	pa.Must(t, 200, "POST", "/admin/orgs/org/disable", nil)
	r := anon.Do(t, "POST", "/auth/token", map[string]string{"email": "o@org.test", "password": pw})
	if r.Status != 401 || string(r.Body) != string(unknown.Body) {
		t.Errorf("disabled org login: %d %s", r.Status, r.Body)
	}
	// Login with a garbage or PAT Authorization header is a normal login.
	r = s.Client("cof_pat_garbage").Do(t, "POST", "/auth/token", map[string]string{"email": testutil.AdminEmail, "password": testutil.AdminPassword})
	if r.Status != 201 {
		t.Errorf("login with garbage bearer: %d", r.Status)
	}
	anon.Must(t, 400, "POST", "/auth/token", map[string]string{"email": "x@y.z"})
	anon.Must(t, 400, "POST", "/auth/token", nil)
}

func TestLoginLockout(t *testing.T) {
	s, _ := simple(t)
	anon := s.Client("")
	o := s.Client("")
	login := func(email, password string) int {
		return anon.Do(t, "POST", "/auth/token", map[string]string{"email": email, "password": password}).Status
	}
	// Second account in the same org to check isolation.
	owner := s.Client(s.Login(t, "o@org.test", pw))
	create(t, owner, "/members", map[string]string{"email": "other@org.test", "role": "member", "password": pw})
	_ = o
	for i := 0; i < 5; i++ {
		if st := login("o@org.test", "wrong-password-x"); st != 401 {
			t.Fatalf("attempt %d: %d", i+1, st)
		}
	}
	r := anon.Do(t, "POST", "/auth/token", map[string]string{"email": "o@org.test", "password": pw})
	if r.Status != 429 || !strings.Contains(string(r.Body), `"rate_limited"`) {
		t.Fatalf("locked correct password: %d %s", r.Status, r.Body)
	}
	if st := login("O@ORG.TEST", pw); st != 429 {
		t.Fatalf("locked (case variant): %d", st)
	}
	if st := login("other@org.test", pw); st != 201 {
		t.Fatalf("other account affected: %d", st)
	}
	// Existing sessions are not affected by lockout.
	owner.Must(t, 200, "GET", "/me", nil)
	// Unknown emails lock too (no account enumeration via lockout).
	for i := 0; i < 5; i++ {
		login("ghost@org.test", "wrong-password-x")
	}
	if st := login("ghost@org.test", "wrong-password-x"); st != 429 {
		t.Fatalf("unknown email lockout: %d", st)
	}
	// Window passes.
	if _, err := s.DB.Owner.Exec(t.Context(), `UPDATE login_failures SET failed_at = failed_at - interval '16 minutes'`); err != nil {
		t.Fatal(err)
	}
	if st := login("o@org.test", pw); st != 201 {
		t.Fatalf("after window: %d", st)
	}
	// Success clears the failures.
	var n int
	s.DB.Owner.QueryRow(t.Context(), `SELECT count(*) FROM login_failures WHERE email_norm='o@org.test'`).Scan(&n)
	if n != 0 {
		t.Errorf("failures not cleared: %d", n)
	}
	// Locked attempts are audited as denied with reason locked.
	var evs []map[string]any
	owner.Must(t, 200, "GET", "/audit?action=auth.login&limit=1000", nil).JSON(t, &evs)
	var failed, denied, ok int
	for _, e := range evs {
		switch e["result"] {
		case "failed":
			failed++
		case "denied":
			denied++
			if e["details"].(map[string]any)["reason"] != "locked" {
				t.Errorf("locked details %v", e["details"])
			}
		case "success":
			ok++
		}
	}
	if failed != 5 || denied != 2 || ok < 3 {
		t.Errorf("login audit: failed=%d denied=%d success=%d", failed, denied, ok)
	}
	// Unknown-email failures went to the platform chain (known-email
	// failures too, under the same email:<hash> target form).
	pa := s.Client(s.Login(t, testutil.AdminEmail, testutil.AdminPassword))
	pa.Must(t, 200, "GET", "/admin/audit?limit=1000", nil).JSON(t, &evs)
	ghost := 0
	for _, e := range evs {
		if e["action"] == "auth.login" && e["target"] == emailTargetOf("ghost@org.test") {
			ghost++
			if strings.Contains(e["target"].(string), "ghost") {
				t.Error("email in clear in audit target")
			}
		}
	}
	if ghost != 6 {
		t.Errorf("platform ghost login events: %d", ghost)
	}
}

func TestLoginLockoutConcurrent(t *testing.T) {
	s, _ := simple(t)
	anon := s.Client("")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			anon.Do(t, "POST", "/auth/token", map[string]string{"email": "o@org.test", "password": "wrong-password-x"})
		}()
	}
	wg.Wait()
	var n int
	s.DB.Owner.QueryRow(t.Context(), `SELECT count(*) FROM login_failures WHERE email_norm='o@org.test'`).Scan(&n)
	if n != 5 {
		t.Errorf("concurrent failures recorded: %d (want exactly 5 checked attempts)", n)
	}
	anon.Must(t, 429, "POST", "/auth/token", map[string]string{"email": "o@org.test", "password": pw})
}

func TestPasswordChangeAndMe(t *testing.T) {
	s, o := simple(t)
	me := o.Must(t, 200, "GET", "/me", nil).Map(t)
	if me["type"] != "user" || me["role"] != "owner" || me["email"] != "o@org.test" || me["org_slug"] != "org" {
		t.Errorf("me %v", me)
	}
	other := s.Client(s.Login(t, "o@org.test", pw))
	o.Must(t, 403, "POST", "/auth/password", map[string]string{"current_password": "wrong-password-z", "new_password": "new-password-123"})
	o.Must(t, 400, "POST", "/auth/password", map[string]string{"current_password": pw, "new_password": "short"})
	o.Must(t, 400, "POST", "/auth/password", map[string]string{"current_password": pw, "new_password": pw})
	o.Must(t, 400, "POST", "/auth/password", map[string]string{"current_password": pw})
	o.Must(t, 200, "POST", "/auth/password", map[string]string{"current_password": pw, "new_password": "new-password-123"})
	o.Must(t, 200, "GET", "/me", nil)
	other.Must(t, 401, "GET", "/me", nil) // other PATs revoked
	s.Client("").Must(t, 401, "POST", "/auth/token", map[string]string{"email": "o@org.test", "password": pw})
	s.Login(t, "o@org.test", "new-password-123")

	// Service token /me.
	create(t, o, "/projects/app/envs", map[string]any{"slug": "ci"})
	st := create(t, o, "/tokens", map[string]any{"project": "app", "env": "ci", "access": "read", "ttl_seconds": 120, "name": "ci bot"})
	if !strings.HasPrefix(st["token"].(string), "cof_st_") || st["name"] != "ci bot" {
		t.Errorf("token create %v", st)
	}
	stMe := s.Client(st["token"].(string)).Must(t, 200, "GET", "/me", nil).Map(t)
	if stMe["type"] != "service_token" || stMe["project"] != "app" || stMe["env"] != "ci" || stMe["access"] != "read" || stMe["expires_at"] == nil {
		t.Errorf("st me %v", stMe)
	}
	// Token validation.
	for _, body := range []map[string]any{
		{"project": "app", "env": "ci", "access": "admin", "ttl_seconds": 120},
		{"project": "app", "env": "ci", "access": "read", "ttl_seconds": 59},
		{"project": "app", "env": "ci", "access": "read", "ttl_seconds": 7776001},
		{"project": "app", "env": "ci", "access": "read", "ttl_seconds": 120.5},
		{"project": "app", "env": "ci", "access": "read"},
		{"project": "app", "env": "ci", "access": "read", "ttl_seconds": 120, "name": strings.Repeat("n", 101)},
	} {
		o.Must(t, 400, "POST", "/tokens", body)
	}
	o.Must(t, 201, "POST", "/tokens", map[string]any{"project": "app", "env": "ci", "access": "read-write", "ttl_seconds": 7776000})
	o.Must(t, 404, "POST", "/tokens", map[string]any{"project": "app", "env": "nope", "access": "read", "ttl_seconds": 120})
	var toks []map[string]any
	o.Must(t, 200, "GET", "/tokens", nil).JSON(t, &toks)
	if len(toks) != 2 {
		t.Errorf("tokens %v", toks)
	}
	for _, tk := range toks {
		if _, ok := tk["token"]; ok {
			t.Error("token list includes token")
		}
		if _, ok := tk["token_hash"]; ok {
			t.Error("token list includes hash")
		}
	}
	// PATs can't be revoked via /tokens.
	o.Must(t, 404, "DELETE", "/tokens/"+me["id"].(string), nil)
}

func TestMustChangePassword(t *testing.T) {
	d := testutil.NewDB(t)
	cfg := d.Config(testutil.RandomKeyBytes())
	cfg.RequirePasswordChange = true
	s := testutil.Boot(t, d, cfg)
	pa := s.Client(s.Login(t, testutil.AdminEmail, testutil.AdminPassword))
	pa.Must(t, 200, "GET", "/admin/orgs", nil) // bootstrap admin is not forced
	create(t, pa, "/admin/orgs", map[string]string{"slug": "org", "owner_email": "o@org.test", "owner_password": pw})
	o := s.Client(s.Login(t, "o@org.test", pw))
	if o.Must(t, 200, "GET", "/me", nil).Map(t)["must_change_password"] != true {
		t.Error("must_change_password not reported")
	}
	r := o.Do(t, "GET", "/projects", nil)
	if r.Status != 403 || !strings.Contains(string(r.Body), "password_change_required") {
		t.Fatalf("forced change: %d %s", r.Status, r.Body)
	}
	o.Must(t, 200, "POST", "/auth/password", map[string]string{"current_password": pw, "new_password": "brand-new-password"})
	o.Must(t, 200, "GET", "/projects", nil)
	if o.Must(t, 200, "GET", "/me", nil).Map(t)["must_change_password"] != false {
		t.Error("flag not cleared")
	}
}
