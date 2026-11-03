//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestAuditTrail covers SPEC §4 Audit: events, routing, fields, chain, verify.
func TestAuditTrail(t *testing.T) {
	t.Parallel()
	a := newOrg(t, "audit-a")
	b := newOrg(t, "audit-b")
	a.project(t, "app", map[string]bool{"dev": false, "prod": true})
	tok := a.Owner.Token
	secretVals := []string{"s3cr3t-alpha-" + rnd(4), "s3cr3t-beta-" + rnd(4), "s3cr3t-gamma-" + rnd(4)}
	setSecret(t, tok, "app", "dev", "A1", secretVals[0])
	setSecret(t, tok, "app", "dev", "A2", secretVals[1])
	setSecret(t, tok, "app", "dev", "A3", secretVals[2])
	since := time.Now().UTC().Add(-2 * time.Second).Format(time.RFC3339)

	must(t, 200, api(t, "GET", secPath("app", "dev", "A1"), tok, nil), "get")
	must(t, 200, api(t, "GET", secPath("app", "dev", "A1")+"/versions/1", tok, nil), "get version")
	must(t, 200, api(t, "GET", "/projects/app/envs/dev/export?format=json", tok, nil), "export")
	must(t, 200, api(t, "DELETE", secPath("app", "dev", "A3"), tok, nil), "delete")
	must(t, 200, api(t, "POST", secPath("app", "dev", "A3")+"/rollback", tok, map[string]int{"to": 1}), "rollback")
	m := a.addUser(t, "m", "member")
	adm := a.addUser(t, "adm", "admin")
	a.grant(t, m, "app", "writer")
	must(t, 200, api(t, "PATCH", "/members/"+adm.ID, tok, map[string]string{"role": "member"}), "demote admin")
	must(t, 200, api(t, "PATCH", "/members/"+adm.ID, tok, map[string]string{"role": "admin"}), "promote back")
	must(t, 403, api(t, "GET", "/audit", m.Token, nil), "member denied")
	must(t, 404, api(t, "GET", secPath("nope", "dev", "X"), m.Token, nil), "member 404")
	ch := str(must(t, 202, api(t, "PUT", secPath("app", "prod", "P"), m.Token, map[string]string{"value": "pv-" + rnd(4)}), "change").obj(t), "change_id")
	must(t, 200, api(t, "POST", "/changes/"+ch+"/approve", adm.Token, nil), "approve")
	ch2 := str(must(t, 202, api(t, "PUT", secPath("app", "prod", "P"), m.Token, map[string]string{"value": "pv2"}), "change2").obj(t), "change_id")
	ch3 := str(must(t, 202, api(t, "PUT", secPath("app", "prod", "P"), m.Token, map[string]string{"value": "pv3"}), "change3").obj(t), "change_id")
	must(t, 200, api(t, "POST", "/changes/"+ch2+"/reject", adm.Token, nil), "reject")
	ch4 := str(must(t, 202, api(t, "PUT", secPath("app", "prod", "P"), m.Token, map[string]string{"value": "pv4"}), "change4").obj(t), "change_id")
	must(t, 200, api(t, "POST", "/changes/"+ch4+"/approve", adm.Token, nil), "approve 4")
	must(t, 409, api(t, "POST", "/changes/"+ch3+"/approve", adm.Token, nil), "stale")
	st := a.serviceToken(t, "app", "dev", "read", 600)
	must(t, 200, api(t, "GET", secPath("app", "dev", "A2"), st.Token, nil), "ST read")
	must(t, 200, api(t, "DELETE", "/tokens/"+st.ID, tok, nil), "revoke")
	must(t, 200, api(t, "DELETE", "/members/"+m.ID+"/grants/app", tok, nil), "grant revoke")
	// Failed login for an org user; logout.
	api(t, "POST", "/auth/token", "", map[string]string{"email": adm.Email, "password": "wrong-password-xyz"})
	extra := login(t, adm.Email, testPassword)
	must(t, 200, api(t, "POST", "/auth/logout", extra, nil), "logout")
	// Cross-org denial: org B's owner probes org A's project → goes to B's log.
	must(t, 404, api(t, "GET", secPath("app", "dev", "A1"), b.Owner.Token, nil), "cross-org")
	// Platform admin probes an org route → platform log.
	must(t, 404, api(t, "GET", "/projects", adminToken(t), nil), "PA org route")

	evs := auditEvents(t, tok, "limit=1000")
	actions := map[string]int{}
	for _, e := range evs {
		actions[str(e, "action")]++
	}
	// SPEC §4 events recorded.
	for _, want := range []string{
		"auth.login", "auth.logout", "secret.read", "secret.write", "secret.delete", "secret.rollback",
		"change.create", "change.approve", "change.reject", "change.stale",
		"member.add", "member.role_change", "grant.set", "grant.revoke",
		"token.issue", "token.revoke", "project.create", "env.create", "org.create", "authz.denied",
	} {
		if actions[want] == 0 {
			t.Errorf("org audit log has no %q event (have %v)", want, actions)
		}
	}
	// One read event per key read: get(1) + version get(1) + export(3) + ST get(1) = 6.
	if actions["secret.read"] != 6 {
		t.Errorf("secret.read events = %d, want 6 (one per key read)", actions["secret.read"])
	}
	// Required fields and results.
	results := map[string]bool{}
	for _, e := range evs {
		for _, f := range []string{"seq", "ts", "actor", "action", "target", "source_ip", "result", "prev_hash", "hash"} {
			if _, ok := e[f]; !ok {
				t.Errorf("event missing field %s: %v", f, e)
				break
			}
		}
		results[str(e, "result")] = true
		if r := str(e, "result"); r != "success" && r != "denied" && r != "failed" {
			t.Errorf("bad result %q", r)
		}
	}
	for _, r := range []string{"success", "denied", "failed"} {
		if !results[r] {
			t.Errorf("no event with result %q", r)
		}
	}
	// Never logged: values, passwords, tokens.
	raw, _ := json.Marshal(evs)
	for _, s := range append(secretVals, testPassword, "wrong-password-xyz", tok, st.Token, extra, "cof_pat_", "cof_st_", "pv4") {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("audit log contains sensitive string %q", s)
		}
	}
	// The cross-org probe is in B's log, not A's.
	bEvs := auditEvents(t, b.Owner.Token, "action=authz.denied")
	if len(bEvs) == 0 {
		t.Errorf("org B's denied cross-org attempt is not in B's audit log")
	}
	for _, e := range evs {
		if str(e, "action") == "org.create" {
			continue // genesis event (CONTRACT §5.3: written to both chains)
		}
		if actor, _ := e["actor"].(map[string]any); str(actor, "id") == b.Owner.ID || str(actor, "id") == str(adminMe(t), "id") {
			t.Errorf("org A log contains an event by an outsider: %v", e)
		}
	}
	// Denied events in B do not reveal that A's resource exists: same shape as a
	// probe of a nonexistent project.
	must(t, 404, api(t, "GET", secPath("e2e-absent", "dev", "A1"), b.Owner.Token, nil), "absent")
	bEvs = auditEvents(t, b.Owner.Token, "action=authz.denied&limit=2")
	if len(bEvs) == 2 {
		k1, k2 := keysOf(bEvs[0]), keysOf(bEvs[1])
		if k1 != k2 || str(bEvs[0], "result") != str(bEvs[1], "result") ||
			fmt.Sprint(bEvs[0]["details"]) != fmt.Sprint(bEvs[1]["details"]) {
			t.Errorf("denial events differ for existing vs absent target: %v vs %v", bEvs[0], bEvs[1])
		}
	}

	// Hash chain: contiguous seqs from 1, prev_hash links, recomputed hash.
	sort.Slice(evs, func(i, j int) bool { return num(evs[i], "seq") < num(evs[j], "seq") })
	prev := strings.Repeat("0", 64)
	for i, e := range evs {
		if num(e, "seq") != i+1 {
			t.Fatalf("seq gap at index %d: %v", i, e["seq"])
		}
		if str(e, "prev_hash") != prev {
			t.Fatalf("seq %d prev_hash %s != previous hash %s", i+1, e["prev_hash"], prev)
		}
		if h := recomputeHash(e, a.ID); h != str(e, "hash") {
			t.Errorf("seq %d: recomputed hash %s != stored %s (canonical JSON per CONTRACT §5.4)", i+1, h, e["hash"])
		}
		prev = str(e, "hash")
	}
	v := must(t, 200, api(t, "GET", "/audit/verify", tok, nil), "verify").obj(t)
	if v["valid"] != true || v["first_invalid_seq"] != nil {
		t.Errorf("verify: %v", v)
	}

	// Filters.
	for _, e := range auditEvents(t, tok, "action=secret.read") {
		if str(e, "action") != "secret.read" {
			t.Errorf("action filter returned %v", e["action"])
		}
	}
	for _, e := range auditEvents(t, tok, "actor="+url.QueryEscape(st.ID)) {
		if actor, _ := e["actor"].(map[string]any); str(actor, "id") != st.ID {
			t.Errorf("actor filter returned %v", e["actor"])
		}
	}
	if n := len(auditEvents(t, tok, "actor="+url.QueryEscape(st.ID)+"&action=secret.read")); n != 1 {
		t.Errorf("ST read events = %d, want 1", n)
	}
	if n := len(auditEvents(t, tok, "limit=3")); n != 3 {
		t.Errorf("limit=3 returned %d", n)
	}
	mid := evs[len(evs)/2]
	sinceEvs := auditEvents(t, tok, "since="+url.QueryEscape(str(mid, "ts"))+"&limit=1000")
	if len(sinceEvs) == 0 || len(sinceEvs) >= len(evs) {
		t.Errorf("since=%s returned %d of %d", str(mid, "ts"), len(sinceEvs), len(evs))
	}
	for _, e := range sinceEvs {
		if str(e, "ts") < str(mid, "ts") {
			t.Errorf("since filter returned older event %v", e["ts"])
		}
	}
	_ = since
	if n := len(auditEvents(t, tok, "since="+url.QueryEscape(time.Now().UTC().Add(time.Hour).Format(time.RFC3339)))); n != 0 {
		t.Errorf("since=future returned %d", n)
	}
	for _, q := range []string{"since=yesterday", "limit=0", "limit=1001", "limit=abc"} {
		if r := api(t, "GET", "/audit?"+q, tok, nil); r.Status != 400 {
			t.Errorf("audit ?%s: want 400, got %s", q, r)
		}
	}
	ord := auditEvents(t, tok, "limit=5")
	for i := 1; i < len(ord); i++ {
		if num(ord[i-1], "seq") < num(ord[i], "seq") {
			t.Errorf("audit list not newest first")
		}
	}

	// CLI audit commands.
	c := newCLIEnv(t)
	c.Token = tok
	if r := c.want(t, 0, nil, "audit", "verify"); !strings.Contains(string(r.Stdout), "valid") {
		t.Errorf("audit verify output: %s", r)
	}
	jr := c.want(t, 0, nil, "audit", "list", "--limit", "2", "--action", "secret.read", "--json")
	var cl []map[string]any
	if err := json.Unmarshal(jr.Stdout, &cl); err != nil || len(cl) != 2 {
		t.Errorf("audit list --json: %v %s", err, jr)
	}
	mc := newCLIEnv(t)
	mc.Token = adm.Token
	mc.want(t, 0, nil, "audit", "verify", "--json")

	// Platform log: PA's actions and PA's denied org-route probe; org events absent.
	pa := newCLIEnv(t)
	pa.Token = adminToken(t)
	pa.want(t, 0, nil, "admin", "audit", "verify")
	pr := pa.want(t, 0, nil, "admin", "audit", "list", "--limit", "1000", "--json")
	var pev []map[string]any
	if err := json.Unmarshal(pr.Stdout, &pev); err != nil {
		t.Fatalf("admin audit list --json: %v", err)
	}
	var sawCreate, sawDenied bool
	for _, e := range pev {
		if str(e, "action") == "org.create" && strings.Contains(str(e, "target"), a.Slug) || strings.Contains(str(e, "target"), a.ID) && str(e, "action") == "org.create" {
			sawCreate = true
		}
		if str(e, "action") == "authz.denied" {
			sawDenied = true
		}
		if strings.HasPrefix(str(e, "action"), "secret.") {
			t.Errorf("platform log contains a secret event: %v", e)
		}
	}
	if !sawCreate || !sawDenied {
		t.Errorf("platform log missing org.create(%v) or PA denial(%v)", sawCreate, sawDenied)
	}
	pv := must(t, 200, api(t, "GET", "/admin/audit/verify", adminToken(t), nil), "platform verify").obj(t)
	if pv["valid"] != true {
		t.Errorf("platform chain invalid: %v", pv)
	}
	must(t, 400, api(t, "GET", "/admin/audit?limit=0", adminToken(t), nil), "admin audit limit=0")
}

func adminMe(t testing.TB) map[string]any {
	return must(t, 200, api(t, "GET", "/me", adminToken(t), nil), "admin me").obj(t)
}

func keysOf(m map[string]any) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

// recomputeHash rebuilds the canonical event JSON documented in CONTRACT §5.4.
func recomputeHash(e map[string]any, orgID string) string {
	actor, _ := e["actor"].(map[string]any)
	details, _ := e["details"].(map[string]any)
	if details == nil {
		details = map[string]any{}
	}
	ev := map[string]any{
		"action": e["action"], "actor_id": actor["id"], "actor_type": actor["type"],
		"chain": orgID, "details": details, "org_id": orgID, "prev_hash": e["prev_hash"],
		"result": e["result"], "seq": json.Number(fmt.Sprint(num(e, "seq"))), "source_ip": e["source_ip"],
		"target": e["target"], "ts": e["ts"],
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(ev)
	sum := sha256.Sum256(append([]byte(str(e, "prev_hash")), bytes.TrimRight(buf.Bytes(), "\n")...))
	return hex.EncodeToString(sum[:])
}

// TestLoginAndLockout covers SPEC §4 Authentication.
func TestLoginAndLockout(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "lock")
	victim := o.addUser(t, "victim", "member")
	bystander := o.addUser(t, "bystander", "member")

	wrong := api(t, "POST", "/auth/token", "", map[string]string{"email": bystander.Email, "password": "definitely-wrong-pw"})
	unknown := api(t, "POST", "/auth/token", "", map[string]string{"email": "e2e-nobody-" + rnd(4) + "@nowhere.test", "password": "definitely-wrong-pw"})
	if wrong.Status != 401 || unknown.Status != 401 || !bytes.Equal(wrong.Body, unknown.Body) {
		t.Errorf("unknown email vs wrong password differ:\n%s\n%s", wrong, unknown)
	}
	// Similar timing: median of 3 each, generous bound.
	timeIt := func(email string) time.Duration {
		var ds []time.Duration
		for i := 0; i < 3; i++ {
			start := time.Now()
			api(t, "POST", "/auth/token", "", map[string]string{"email": email, "password": "timing-wrong-pw-" + rnd(2)})
			ds = append(ds, time.Since(start))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[1]
	}
	timer := o.addUser(t, "timer", "member")
	known := timeIt(timer.Email)
	unk := timeIt("e2e-ghost-" + rnd(4) + "@nowhere.test")
	if known > 4*unk+50*time.Millisecond || unk > 4*known+50*time.Millisecond {
		t.Errorf("login timing differs: known-email wrong password %v vs unknown email %v", known, unk)
	}
	for _, bad := range []any{`{"email":"x"}`, `{}`, `not json`, map[string]any{"email": 1, "password": 2}} {
		if r := api(t, "POST", "/auth/token", "", bad); r.Status != 400 && r.Status != 401 {
			t.Errorf("malformed login %v: %s", bad, r)
		}
	}

	for i := 0; i < 5; i++ {
		r := api(t, "POST", "/auth/token", "", map[string]string{"email": victim.Email, "password": "wrong-password-" + fmt.Sprint(i)})
		if r.Status != 401 {
			t.Fatalf("failed attempt %d: want 401, got %s", i+1, r)
		}
	}
	r := api(t, "POST", "/auth/token", "", map[string]string{"email": victim.Email, "password": testPassword})
	if r.Status != 429 {
		t.Fatalf("6th login with correct password: want 429, got %s", r)
	}
	if r.errCode() != "rate_limited" {
		t.Errorf("429 body: %s", r.Body)
	}
	// Case/whitespace variants of the email are the same account.
	if r := api(t, "POST", "/auth/token", "", map[string]string{"email": strings.ToUpper(victim.Email), "password": testPassword}); r.Status != 429 {
		t.Errorf("upper-cased email bypasses lockout: %s", r)
	}
	c := newCLIEnv(t)
	c.want(t, 10, []byte(testPassword+"\n"), "login", "--email", victim.Email)
	// Other accounts are unaffected.
	login(t, bystander.Email, testPassword)
	// The existing session of the locked user keeps working (lockout is about logins).
	must(t, 200, api(t, "GET", "/me", victim.Token, nil), "victim existing PAT")
	// The CLI maps a wrong password to exit 3.
	c.want(t, 3, []byte("wrong-password-zz\n"), "login", "--email", bystander.Email)
}

// TestHTTPSurface covers SPEC §4 HTTP.
func TestHTTPSurface(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "http")
	o.project(t, "app", map[string]bool{"dev": false})
	tok := o.Owner.Token
	setSecret(t, tok, "app", "dev", "K", "v")

	for _, p := range []string{"/", "/api", "/api/v1", "/api/v2/projects", "/metrics", "/debug/pprof/", "/.env",
		"/api/v1/nope", "/healthz/x", "/static/index.html", "/api/v1/../../etc/passwd"} {
		r := rawDo(t, "GET", p, tok, nil, nil)
		if r.Status != 404 {
			t.Errorf("GET %s: want 404, got %d", p, r.Status)
		}
	}
	for _, p := range []string{"/healthz", "/readyz"} {
		r := rawDo(t, "GET", p, "", nil, nil)
		if r.Status != 200 || r.Header.Get("X-Request-Id") == "" {
			t.Errorf("%s: %s (X-Request-Id %q)", p, r, r.Header.Get("X-Request-Id"))
		}
	}

	big := bytes.Repeat([]byte("a"), 1<<20+1)
	bigBody := append(append([]byte(`{"value":"`), big...), '"', '}')
	checks := map[string]resp{
		"success":    api(t, "GET", secPath("app", "dev", "K"), tok, nil),
		"list":       api(t, "GET", "/projects", tok, nil),
		"401":        api(t, "GET", "/projects", "", nil),
		"401 bad":    api(t, "GET", "/projects", "cof_pat_"+rnd(32), nil),
		"404":        api(t, "GET", "/projects/nope/envs", tok, nil),
		"400":        api(t, "PUT", secPath("app", "dev", "K"), tok, `{"value":`),
		"413":        api(t, "PUT", secPath("app", "dev", "K"), tok, bigBody),
		"413 unauth": api(t, "POST", "/auth/token", "", bigBody),
		"413 chunked": rawDo(t, "PUT", "/api/v1"+secPath("app", "dev", "K"), tok,
			struct{ *bytes.Reader }{bytes.NewReader(bigBody)}, map[string]string{"Content-Type": "application/json"}),
		"dotenv": api(t, "GET", "/projects/app/envs/dev/export?format=dotenv", tok, nil),
		"verify": api(t, "GET", "/audit/verify", tok, nil),
	}
	for name, r := range checks {
		switch {
		case strings.HasPrefix(name, "413") && r.Status != 413:
			t.Errorf("%s: want 413, got %d %.200s", name, r.Status, r.Body)
		case strings.HasPrefix(name, "401") && r.Status != 401:
			t.Errorf("%s: want 401, got %s", name, r)
		}
		ct := r.Header.Get("Content-Type")
		if name == "dotenv" {
			if !strings.HasPrefix(ct, "text/plain") && !strings.HasPrefix(ct, "application/json") {
				t.Errorf("%s: Content-Type %q", name, ct)
			}
		} else if !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s: Content-Type %q", name, ct)
		}
		if r.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options %q", name, r.Header.Get("X-Content-Type-Options"))
		}
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", name, r.Header.Get("Cache-Control"))
		}
		if r.Header.Get("X-Request-Id") == "" {
			t.Errorf("%s: no X-Request-Id", name)
		}
		if r.Status >= 400 {
			var e struct {
				Error struct{ Code, Message string } `json:"error"`
			}
			if err := json.Unmarshal(r.Body, &e); err != nil || e.Error.Code == "" || e.Error.Message == "" {
				t.Errorf("%s: error body not {\"error\":{code,message}}: %.200s", name, r.Body)
			}
		}
	}
	// The 413'd value was not stored.
	if g := must(t, 200, api(t, "GET", secPath("app", "dev", "K"), tok, nil), "get").obj(t); str(g, "value") != "v" {
		t.Errorf("oversized write changed the value")
	}
	// Exactly 1 MiB is not 413 (it is a too-long value: 400).
	exact := append(append([]byte(`{"value":"`), bytes.Repeat([]byte("a"), 1<<20-12)...), '"', '}')
	if r := api(t, "PUT", secPath("app", "dev", "K"), tok, exact); r.Status != 400 {
		t.Errorf("1 MiB body: want 400 (value too long), got %d", r.Status)
	}
	// An unmatched path still returns the JSON error.
	if r := rawDo(t, "GET", "/nothing-here", "", nil, nil); r.errCode() != "not_found" {
		t.Errorf("unmatched path body: %s", r.Body)
	}

	// CORS: no origin gets access, even on preflight.
	for _, m := range []string{"GET", "OPTIONS"} {
		r := rawDo(t, m, "/api/v1"+secPath("app", "dev", "K"), tok, nil, map[string]string{
			"Origin": "https://evil.example", "Access-Control-Request-Method": "GET",
			"Access-Control-Request-Headers": "authorization",
		})
		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("%s with Origin: CORS header %s: %s", m, k, r.Header.Get(k))
			}
		}
	}
	// Incoming X-Request-Id is not reflected.
	if r := rawDo(t, "GET", "/healthz", "", nil, map[string]string{"X-Request-Id": "injected-by-client"}); strings.Contains(r.Header.Get("X-Request-Id"), "injected") {
		t.Errorf("client X-Request-Id echoed")
	}
	// Malformed Authorization headers are 401, not 500.
	for _, h := range []string{"Basic Zm9vOmJhcg==", "Bearer", "Bearer ", "bearer " + tok + "x", "Bearer " + strings.Repeat("x", 4000)} {
		r := rawDo(t, "GET", "/api/v1/me", "", nil, map[string]string{"Authorization": h})
		if r.Status != 401 {
			t.Errorf("Authorization %.20q: want 401, got %s", h, r)
		}
	}
	// No stack traces, SQL or paths on weird input.
	weird := []resp{
		api(t, "PUT", secPath("app", "dev", "K"), tok, `{"value":"x","expected_version":1e400}`),
		api(t, "PUT", secPath("app", "dev", "K"), tok, `{"value":"x","expected_version":99999999999999999999}`),
		api(t, "PUT", secPath("app", "dev", "K"), tok, strings.Repeat("[", 10000)),
		api(t, "PUT", secPath("app", "dev", "K"), tok, `{"value":"\ud800"}`),
		api(t, "GET", secPath("app", "dev", "K")+"/versions/99999999999999999999", tok, nil),
		api(t, "GET", secPath("app", "dev", "K")+"/versions/-1", tok, nil),
		api(t, "GET", "/projects/"+strings.Repeat("a", 300)+"/envs", tok, nil),
		api(t, "GET", "/projects/'%3B%20select%201--/envs", tok, nil),
		api(t, "POST", "/tokens", tok, `{"project":"app","env":"dev","access":"read","ttl_seconds":1.5}`),
		api(t, "GET", "/audit?limit=99999999999999999999", tok, nil),
	}
	for i, r := range weird {
		if r.Status >= 500 {
			t.Errorf("weird input %d: server error %s", i, r)
		}
		lb := strings.ToLower(string(r.Body))
		for _, bad := range []string{"goroutine", ".go:", "panic", "select ", "insert ", "pgx", "sqlstate", "/home/", "/app/", "/usr/"} {
			if strings.Contains(lb, bad) {
				t.Errorf("weird input %d: body leaks %q: %s", i, bad, r.Body)
			}
		}
	}
	// Request JSON fields not in the API are rejected or ignored, never applied.
	if r := api(t, "POST", "/projects", tok, map[string]any{"slug": "p-" + rnd(3), "org_id": "org_other"}); r.Status != 400 && r.Status != 201 {
		t.Errorf("project with org_id: %s", r)
	}
	// Slug validation.
	for _, s := range []string{"UPPER", "-lead", "has_underscore", strings.Repeat("a", 64), "", "a b"} {
		if r := api(t, "POST", "/projects", tok, map[string]string{"slug": s}); r.Status != 400 {
			t.Errorf("project slug %q: want 400, got %s", s, r)
		}
	}
	must(t, 201, api(t, "POST", "/projects", tok, map[string]string{"slug": strings.Repeat("a", 63)}), "63-char slug")
	must(t, 409, api(t, "POST", "/projects", tok, map[string]string{"slug": "app"}), "duplicate project")
	must(t, 409, api(t, "POST", "/projects/app/envs", tok, map[string]any{"slug": "dev"}), "duplicate env")
	must(t, 400, api(t, "POST", "/projects/app/envs", tok, map[string]any{"slug": "Bad"}), "bad env slug")
	must(t, 409, api(t, "POST", "/admin/orgs", adminToken(t), map[string]string{"slug": o.Slug, "owner_email": "e2e-dup-" + rnd(3) + "@x.test", "owner_password": testPassword}), "duplicate org")
	must(t, 400, api(t, "POST", "/admin/orgs", adminToken(t), map[string]string{"slug": "Bad_Slug", "owner_email": "e2e-bad-" + rnd(3) + "@x.test", "owner_password": testPassword}), "bad org slug")
	must(t, 400, api(t, "POST", "/admin/orgs", adminToken(t), map[string]string{"slug": "e2e-short-" + rnd(3), "owner_email": "e2e-s-" + rnd(3) + "@x.test", "owner_password": "short"}), "short owner password")
}
