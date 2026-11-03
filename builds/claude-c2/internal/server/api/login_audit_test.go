package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/coffer-dev/coffer/internal/server/config"
	"github.com/coffer-dev/coffer/internal/server/testutil"
)

type auditEvent struct {
	Seq     int64          `json:"seq"`
	Action  string         `json:"action"`
	Target  string         `json:"target"`
	Result  string         `json:"result"`
	ActorID string         `json:"actor_id"`
	Details map[string]any `json:"details"`
}

func loginEvents(t *testing.T, c *testutil.Client, path, result string) []auditEvent {
	t.Helper()
	var evs []auditEvent
	c.Must(t, 200, "GET", path, nil).JSON(t, &evs)
	var out []auditEvent
	for _, e := range evs {
		if e.Action == "auth.login" && e.Result == result {
			out = append(out, e)
		}
	}
	return out
}

// SPEC §4 "Where events go": failed/locked logins are by unauthenticated
// callers and land in the platform log, also for known org users' emails
// (with a copy in the org chain). Successful logins stay in the org chain.
// SPEC §1: the platform copy must not reveal whether the email is an org
// member, so known and unknown emails produce the same shape there.
func TestFailedLoginAuditedToPlatform(t *testing.T) {
	s, o := simple(t)
	anon := s.Client("")
	pa := s.Client(s.Login(t, testutil.AdminEmail, testutil.AdminPassword))
	var me map[string]any
	o.Must(t, 200, "GET", "/me", nil).JSON(t, &me)
	uid := me["id"].(string)

	anon.Must(t, 401, "POST", "/auth/token", map[string]string{"email": "o@org.test", "password": "wrong-password-1"})
	anon.Must(t, 401, "POST", "/auth/token", map[string]string{"email": "ghost@org.test", "password": "wrong-password-1"})

	plat := loginEvents(t, pa, "/admin/audit?limit=200", "failed")
	org := loginEvents(t, o, "/audit?action=auth.login&limit=200", "failed")
	hasTarget := func(evs []auditEvent, target string) bool {
		for _, e := range evs {
			if e.Target == target {
				return true
			}
		}
		return false
	}
	if !hasTarget(plat, emailTargetOf("o@org.test")) {
		t.Errorf("known-user failed login missing from platform log: %+v", plat)
	}
	if !hasTarget(plat, emailTargetOf("ghost@org.test")) {
		t.Errorf("unknown-email failed login missing from platform log: %+v", plat)
	}
	if !hasTarget(org, uid) {
		t.Errorf("known-user failed login missing from org log: %+v", org)
	}
	if len(plat) != 2 {
		t.Errorf("platform failed logins = %d, want 2 (%+v)", len(plat), plat)
	}
	if len(org) != 1 {
		t.Errorf("org failed logins = %d, want 1 (%+v)", len(org), org)
	}
	// The two platform events are indistinguishable apart from the hash.
	var raw []map[string]any
	pa.Must(t, 200, "GET", "/admin/audit?limit=200", nil).JSON(t, &raw)
	shapes := map[string]string{}
	for _, e := range raw {
		if e["action"] != "auth.login" || e["result"] != "failed" {
			continue
		}
		if e["target"] == uid || strings.Contains(fmt.Sprint(e), uid) {
			t.Errorf("platform log reveals org user id: %v", e)
		}
		var b strings.Builder
		for _, k := range sortedKeys(e) {
			switch k {
			case "seq", "ts", "hash", "prev_hash", "target":
				continue
			}
			fmt.Fprintf(&b, "%s=%v;", k, e[k])
		}
		shapes[fmt.Sprint(e["target"])] = b.String()
	}
	if a, b := shapes[emailTargetOf("o@org.test")], shapes[emailTargetOf("ghost@org.test")]; a == "" || a != b {
		t.Errorf("known vs unknown email platform events differ:\n known:   %s\n unknown: %s", a, b)
	}
	// Successful org-user logins are not copied to the platform log.
	for _, e := range loginEvents(t, pa, "/admin/audit?limit=200", "success") {
		if e.Target == uid {
			t.Errorf("org user's successful login in platform log: %+v", e)
		}
	}

	// Locked attempts (429) also reach the platform log.
	for i := 0; i < 5; i++ {
		anon.Do(t, "POST", "/auth/token", map[string]string{"email": "o@org.test", "password": "wrong-password-2"})
	}
	anon.Must(t, 429, "POST", "/auth/token", map[string]string{"email": "o@org.test", "password": pw})
	if d := loginEvents(t, pa, "/admin/audit?limit=200", "denied"); !hasTarget(d, emailTargetOf("o@org.test")) || hasTarget(d, uid) {
		t.Errorf("locked login missing from platform log or names the user: %+v", d)
	}
	if d := loginEvents(t, o, "/audit?action=auth.login&limit=200", "denied"); !hasTarget(d, uid) {
		t.Errorf("locked login missing from org log: %+v", d)
	}
	for _, c := range []struct {
		cl   *testutil.Client
		path string
	}{{pa, "/admin/audit/verify"}, {o, "/audit/verify"}} {
		if v := c.cl.Must(t, 200, "GET", c.path, nil).Map(t)["valid"]; v != true {
			t.Errorf("%s invalid", c.path)
		}
	}
}

// emailTargetOf mirrors the server's audit target for a login email.
func emailTargetOf(email string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return "email:" + hex.EncodeToString(h[:])[:16]
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SPEC §4 Lockout/Audit: a client that disconnects while its password is
// being verified still has the attempt counted and audited.
func TestLoginAbortStillCounted(t *testing.T) {
	s, _ := simple(t)
	u, _ := url.Parse(s.URL)
	body := `{"email":"o@org.test","password":"wrong-password-abort"}`
	req := fmt.Sprintf("POST /api/v1/auth/token HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", u.Host)
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte(req))
		time.Sleep(5 * time.Millisecond)
		c.Close()
	}
	norm, _ := config.NormalizeEmail("o@org.test")
	deadline := time.Now().Add(10 * time.Second)
	var n int
	for time.Now().Before(deadline) {
		s.DB.Owner.QueryRow(t.Context(), `SELECT count(*) FROM login_failures WHERE email_norm=$1`, norm).Scan(&n)
		if n == 3 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if n != 3 {
		t.Fatalf("login_failures = %d after 3 aborted attempts, want 3", n)
	}
	var audited int
	s.DB.Owner.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE chain='platform' AND action='auth.login' AND result='failed'`).Scan(&audited)
	if audited != 3 {
		t.Fatalf("platform failed-login events = %d, want 3", audited)
	}
	if strings.Contains(s.LogText(), "context canceled") {
		t.Errorf("login work was cancelled:\n%s", s.LogText())
	}
}

// Hardening of SPEC §4 Lockout: expired login_failures rows are pruned.
func TestLoginFailuresPruned(t *testing.T) {
	d := testutil.NewDB(t)
	s := testutil.Boot(t, d, nil)
	ctx := t.Context()
	// Old rows for an unrelated (spam) email and enough old rows for the
	// admin to have been locked out if they still counted.
	adminNorm, _ := config.NormalizeEmail(testutil.AdminEmail)
	for _, e := range []string{"spam1@x.test", "spam2@x.test", adminNorm, adminNorm, adminNorm, adminNorm, adminNorm} {
		if _, err := d.Owner.Exec(ctx, `INSERT INTO login_failures (email_norm, failed_at) VALUES ($1, now() - interval '16 minutes')`, e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Owner.Exec(ctx, `INSERT INTO login_failures (email_norm, failed_at) VALUES ('fresh@x.test', now())`); err != nil {
		t.Fatal(err)
	}
	s.Client("").Must(t, 401, "POST", "/auth/token", map[string]string{"email": testutil.AdminEmail, "password": "wrong-password-x"})
	deadline := time.Now().Add(10 * time.Second)
	var old, fresh int
	for time.Now().Before(deadline) {
		d.Owner.QueryRow(ctx, `SELECT count(*) FILTER (WHERE failed_at < now() - interval '15 minutes'), count(*) FILTER (WHERE email_norm='fresh@x.test') FROM login_failures`).Scan(&old, &fresh)
		if old == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if old != 0 || fresh != 1 {
		t.Fatalf("after prune: %d expired rows (want 0), %d fresh (want 1)", old, fresh)
	}
	s.Login(t, testutil.AdminEmail, testutil.AdminPassword)
}

// SPEC §4 timing equality after an Argon2 parameter change: a successful
// login re-hashes with the configured parameters.
func TestLoginRehashesOnParamChange(t *testing.T) {
	d := testutil.NewDB(t)
	k := testutil.RandomKeyBytes()
	cfg := d.Config(k)
	cfg.Argon2MemoryKiB = config.MinArgon2MemoryKiB * 2
	s1 := testutil.Boot(t, d, cfg)
	s1.Login(t, testutil.AdminEmail, testutil.AdminPassword)
	s1.HTTP.Close()
	s1.App.Close()

	hash := func() string {
		var h string
		d.Owner.QueryRow(t.Context(), `SELECT password_hash FROM users WHERE role='platform_admin'`).Scan(&h)
		return h
	}
	want := fmt.Sprintf("$m=%d,", cfg.Argon2MemoryKiB)
	if !strings.Contains(hash(), want) {
		t.Fatalf("initial hash params: %s", hash())
	}
	s2 := testutil.Boot(t, d, d.Config(k)) // MinArgon2MemoryKiB
	s2.Client("").Must(t, 401, "POST", "/auth/token", map[string]string{"email": testutil.AdminEmail, "password": "wrong-password-x"})
	if !strings.Contains(hash(), want) {
		t.Fatal("failed login must not rehash")
	}
	s2.Login(t, testutil.AdminEmail, testutil.AdminPassword)
	if h := hash(); !strings.Contains(h, fmt.Sprintf("$m=%d,", config.MinArgon2MemoryKiB)) {
		t.Fatalf("hash not upgraded: %s", h)
	}
	s2.Login(t, testutil.AdminEmail, testutil.AdminPassword)
}
