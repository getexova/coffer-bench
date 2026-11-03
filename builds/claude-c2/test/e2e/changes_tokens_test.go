//go:build e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestProtectedEnvChanges covers SPEC §2.8 and §2.9 and the CLI exit code 7.
func TestProtectedEnvChanges(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "chg")
	o.project(t, "app", map[string]bool{"prod": true})
	adm := o.addUser(t, "adm", "admin")
	wr := o.addUser(t, "writer", "member")
	o.grant(t, wr, "app", "writer")
	key := secPath("app", "prod", "DB_PASS")

	// Writes to a protected env return 202 and do not change the value.
	r := must(t, 202, api(t, "PUT", key, wr.Token, map[string]string{"value": "v1"}), "protected set")
	m := r.obj(t)
	c1 := str(m, "change_id")
	if c1 == "" || str(m, "status") != "pending" {
		t.Fatalf("202 body: %s", r)
	}
	must(t, 404, api(t, "GET", key, o.Owner.Token, nil), "value must not exist before approval")
	// Even an owner's write is a change request.
	r = must(t, 202, api(t, "PUT", secPath("app", "prod", "OWNER_KEY"), o.Owner.Token, map[string]string{"value": "o"}), "owner protected set")
	cOwner := str(r.obj(t), "change_id")

	// Pending change values are not in the list response.
	if b := string(must(t, 200, api(t, "GET", "/changes?status=pending", adm.Token, nil), "list").Body); strings.Contains(b, `"v1"`) {
		t.Errorf("change list leaks values: %s", b)
	}
	// A member sees only their own changes.
	for _, x := range must(t, 200, api(t, "GET", "/changes", wr.Token, nil), "member list").arr(t) {
		if x["id"] == cOwner {
			t.Errorf("member sees another user's change")
		}
	}

	// Two-person rule.
	must(t, 403, api(t, "POST", "/changes/"+c1+"/approve", wr.Token, nil), "member approves")
	must(t, 403, api(t, "POST", "/changes/"+cOwner+"/approve", o.Owner.Token, nil), "self-approval")
	r = must(t, 200, api(t, "POST", "/changes/"+c1+"/approve", adm.Token, nil), "admin approves")
	if g := r.obj(t); str(g, "status") != "approved" || num(g, "version") != 1 {
		t.Errorf("approve response: %s", r)
	}
	if g := must(t, 200, api(t, "GET", key, o.Owner.Token, nil), "get after approval").obj(t); str(g, "value") != "v1" || num(g, "version") != 1 {
		t.Errorf("approved value: %v", g)
	}
	must(t, 409, api(t, "POST", "/changes/"+c1+"/approve", o.Owner.Token, nil), "approve twice")
	must(t, 409, api(t, "POST", "/changes/"+c1+"/reject", o.Owner.Token, nil), "reject approved")
	must(t, 200, api(t, "POST", "/changes/"+cOwner+"/approve", adm.Token, nil), "admin approves owner change")

	// Stale: two pending changes against the same base; approving one makes the other stale.
	ca := str(must(t, 202, api(t, "PUT", key, wr.Token, map[string]string{"value": "v2a"}), "set a").obj(t), "change_id")
	cb := str(must(t, 202, api(t, "PUT", key, wr.Token, map[string]string{"value": "v2b"}), "set b").obj(t), "change_id")
	must(t, 200, api(t, "POST", "/changes/"+ca+"/approve", adm.Token, nil), "approve a")
	must(t, 409, api(t, "POST", "/changes/"+cb+"/approve", adm.Token, nil), "approve stale b")
	found := false
	for _, x := range must(t, 200, api(t, "GET", "/changes?status=stale", adm.Token, nil), "stale list").arr(t) {
		if x["id"] == cb {
			found = true
		}
	}
	if !found {
		t.Errorf("change %s should be stale", cb)
	}
	if g := must(t, 200, api(t, "GET", key, o.Owner.Token, nil), "get").obj(t); str(g, "value") != "v2a" {
		t.Errorf("stale change applied: %v", g)
	}

	// expected_version mismatch at creation: 409.
	must(t, 409, api(t, "PUT", key, wr.Token, map[string]any{"value": "x", "expected_version": 1}), "protected expected mismatch")
	// Delete and rollback also go through change requests.
	cd := str(must(t, 202, api(t, "DELETE", key, wr.Token, nil), "protected delete").obj(t), "change_id")
	must(t, 200, api(t, "GET", key, o.Owner.Token, nil), "delete not applied before approval")
	must(t, 200, api(t, "POST", "/changes/"+cd+"/reject", adm.Token, nil), "reject delete")
	must(t, 200, api(t, "GET", key, o.Owner.Token, nil), "rejected delete not applied")
	cr := str(must(t, 202, api(t, "POST", key+"/rollback", wr.Token, map[string]int{"to": 1}), "protected rollback").obj(t), "change_id")
	must(t, 200, api(t, "POST", "/changes/"+cr+"/approve", o.Owner.Token, nil), "approve rollback")
	if g := must(t, 200, api(t, "GET", key, o.Owner.Token, nil), "get").obj(t); str(g, "value") != "v1" || num(g, "version") != 3 {
		t.Errorf("after approved rollback: %v", g)
	}
	rejected := false
	for _, x := range must(t, 200, api(t, "GET", "/changes?status=rejected", adm.Token, nil), "rejected list").arr(t) {
		if x["id"] == cd {
			rejected = true
		}
	}
	if !rejected {
		t.Errorf("change %s should be listed as rejected", cd)
	}

	// Service-token proposals: the token's creator (owner) can't approve them.
	st := o.serviceToken(t, "app", "prod", "read-write", 600)
	cs := str(must(t, 202, api(t, "PUT", key, st.Token, map[string]string{"value": "from-ci"}), "ST protected write").obj(t), "change_id")
	must(t, 403, api(t, "POST", "/changes/"+cs+"/approve", st.Token, nil), "ST approves")
	must(t, 403, api(t, "POST", "/changes/"+cs+"/approve", o.Owner.Token, nil), "token creator approves ST change")
	must(t, 200, api(t, "POST", "/changes/"+cs+"/approve", adm.Token, nil), "admin approves ST change")

	// CLI: protected write exits 7; --json prints {"status":"pending","change_id":...}.
	c := newCLIEnv(t)
	c.Token = wr.Token
	hr := c.want(t, 7, nil, "secrets", "set", "CLI_KEY", "v", "-p", "app", "-e", "prod")
	if !strings.Contains(string(hr.Stdout), "chg_") && !strings.Contains(string(hr.Stdout), "change") {
		t.Errorf("protected write should print the change id: %s", hr)
	}
	jr := c.want(t, 7, nil, "secrets", "set", "CLI_KEY", "v", "-p", "app", "-e", "prod", "--json")
	var pj map[string]any
	if err := json.Unmarshal(jr.Stdout, &pj); err != nil || pj["status"] != "pending" || str(pj, "change_id") == "" {
		t.Errorf("protected write --json: %v %s", err, jr)
	}
	ac := newCLIEnv(t)
	ac.Token = adm.Token
	ac.want(t, 0, nil, "change", "approve", str(pj, "change_id"))
	ac.want(t, 8, nil, "change", "approve", str(pj, "change_id"))
	lr := ac.want(t, 0, nil, "change", "list", "--status", "pending", "--json")
	var pend []map[string]any
	if err := json.Unmarshal(lr.Stdout, &pend); err != nil {
		t.Errorf("change list --json: %v %s", err, lr)
	}
	c.want(t, 4, nil, "change", "approve", str(pj, "change_id"))
	ac.want(t, 5, nil, "change", "approve", "chg_doesnotexist")
}

// TestServiceTokens covers SPEC §1 service token, §2.7 and §4 token format.
func TestServiceTokens(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "st")
	o.project(t, "app", map[string]bool{"dev": false, "stage": false})
	tok := o.Owner.Token
	setSecret(t, tok, "app", "dev", "K", "v")

	st := o.serviceToken(t, "app", "dev", "read", 600)
	if !strings.HasPrefix(st.Token, "cof_st_") || len(st.Token) < len("cof_st_")+22 {
		t.Errorf("service token format: %q", st.Token)
	}
	// TTL bounds (1m..90d) and access values.
	for _, bad := range []map[string]any{
		{"project": "app", "env": "dev", "access": "read", "ttl_seconds": 59},
		{"project": "app", "env": "dev", "access": "read", "ttl_seconds": 7776001},
		{"project": "app", "env": "dev", "access": "read", "ttl_seconds": 0},
		{"project": "app", "env": "dev", "access": "read"},
		{"project": "app", "env": "dev", "access": "admin", "ttl_seconds": 600},
		{"project": "app", "env": "dev", "access": "write", "ttl_seconds": 600},
		{"project": "app", "env": "dev", "access": "read", "ttl_seconds": 600, "name": strings.Repeat("n", 101)},
	} {
		if r := api(t, "POST", "/tokens", tok, bad); r.Status != 400 {
			t.Errorf("token %v: want 400, got %s", bad, r)
		}
	}
	must(t, 201, api(t, "POST", "/tokens", tok, map[string]any{"project": "app", "env": "dev", "access": "read", "ttl_seconds": 60}), "ttl 60")
	must(t, 201, api(t, "POST", "/tokens", tok, map[string]any{"project": "app", "env": "dev", "access": "read", "ttl_seconds": 7776000}), "ttl 90d")
	must(t, 404, api(t, "POST", "/tokens", tok, map[string]any{"project": "app", "env": "nope", "access": "read", "ttl_seconds": 600}), "missing env")
	must(t, 404, api(t, "POST", "/tokens", tok, map[string]any{"project": "nope", "env": "dev", "access": "read", "ttl_seconds": 600}), "missing project")

	// The token value is shown once: never in the list.
	lb := must(t, 200, api(t, "GET", "/tokens", tok, nil), "list tokens")
	if strings.Contains(string(lb.Body), st.Token) || strings.Contains(string(lb.Body), "cof_st_") {
		t.Errorf("token list leaks token values: %s", lb.Body)
	}
	foundExp := false
	for _, x := range lb.arr(t) {
		if x["id"] == st.ID && str(x, "expires_at") != "" {
			foundExp = true
		}
	}
	if !foundExp {
		t.Errorf("token %s missing from list or lacks expires_at", st.ID)
	}

	// A read token can read but not write; scope is exactly one env.
	must(t, 200, api(t, "GET", secPath("app", "dev", "K"), st.Token, nil), "ST read")
	must(t, 403, api(t, "PUT", secPath("app", "dev", "K"), st.Token, map[string]string{"value": "x"}), "ST read write")
	must(t, 403, api(t, "DELETE", secPath("app", "dev", "K"), st.Token, nil), "ST read delete")
	must(t, 404, api(t, "GET", secPath("app", "stage", ""), st.Token, nil), "ST other env")
	rw := o.serviceToken(t, "app", "dev", "read-write", 600)
	must(t, 200, api(t, "PUT", secPath("app", "dev", "K2"), rw.Token, map[string]string{"value": "x"}), "RW write")
	must(t, 200, api(t, "POST", secPath("app", "dev", "K2")+"/rollback", rw.Token, map[string]int{"to": 1}), "RW rollback")
	must(t, 200, api(t, "DELETE", secPath("app", "dev", "K2"), rw.Token, nil), "RW delete")
	// STs can't create PATs, issue tokens, manage members, read the audit log.
	must(t, 403, api(t, "POST", "/auth/token", rw.Token, map[string]string{"email": o.Owner.Email, "password": testPassword}), "ST creates PAT")
	must(t, 403, api(t, "POST", "/tokens", rw.Token, map[string]any{"project": "app", "env": "dev", "access": "read", "ttl_seconds": 600}), "ST issues token")
	must(t, 403, api(t, "GET", "/audit", rw.Token, nil), "ST reads audit")
	must(t, 403, api(t, "POST", "/members", rw.Token, map[string]string{"email": "e2e-z-" + rnd(3) + "@x.test", "role": "member", "password": testPassword}), "ST adds member")

	// CLI: token create prints the token alone on stdout; bad TTL exits 6.
	c := newCLIEnv(t)
	c.Token = tok
	r := c.want(t, 0, nil, "token", "create", "-p", "app", "-e", "dev", "--access", "read", "--ttl", "30m", "--name", "ci")
	out := strings.TrimSpace(string(r.Stdout))
	if !strings.HasPrefix(out, "cof_st_") || strings.Contains(out, "\n") {
		t.Errorf("token create stdout should be the token alone: %s", r)
	}
	sc := newCLIEnv(t)
	sc.Token = out
	if g := sc.want(t, 0, nil, "secrets", "get", "K", "-p", "app", "-e", "dev"); string(g.Stdout) != "v" {
		t.Errorf("CLI-created token read: %s", g)
	}
	sc.want(t, 4, nil, "token", "list")
	sc.want(t, 4, nil, "audit", "list")
	for _, ttl := range []string{"59s", "91d", "0m", "1y", "abc", "-5m"} {
		if r := c.run(t, nil, "token", "create", "-p", "app", "-e", "dev", "--access", "read", "--ttl", ttl); r.Code != 6 && r.Code != 2 {
			t.Errorf("--ttl %s: want exit 6, got %s", ttl, r)
		}
	}
	c.want(t, 0, nil, "token", "create", "-p", "app", "-e", "dev", "--access", "read", "--ttl", "90d")
	c.want(t, 0, nil, "token", "create", "-p", "app", "-e", "dev", "--access", "read-write", "--ttl", "1m")
}

// TestRevocationImmediate covers SPEC §2.11.
func TestRevocationImmediate(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "revoke")
	o.project(t, "app", map[string]bool{"dev": false})
	tok := o.Owner.Token
	setSecret(t, tok, "app", "dev", "K", "v")
	get := secPath("app", "dev", "K")

	t.Run("token_revoke", func(t *testing.T) {
		st := o.serviceToken(t, "app", "dev", "read", 600)
		must(t, 200, api(t, "GET", get, st.Token, nil), "before revoke")
		must(t, 200, api(t, "DELETE", "/tokens/"+st.ID, tok, nil), "revoke")
		must(t, 401, api(t, "GET", get, st.Token, nil), "after revoke")
		must(t, 200, api(t, "DELETE", "/tokens/"+st.ID, tok, nil), "revoke idempotent")
		c := newCLIEnv(t)
		c.Token = st.Token
		c.want(t, 3, nil, "secrets", "get", "K", "-p", "app", "-e", "dev")
	})
	t.Run("token_revoke_cli", func(t *testing.T) {
		st := o.serviceToken(t, "app", "dev", "read", 600)
		c := newCLIEnv(t)
		c.Token = tok
		c.want(t, 0, nil, "token", "revoke", st.ID)
		must(t, 401, api(t, "GET", get, st.Token, nil), "after CLI revoke")
	})
	t.Run("member_removed", func(t *testing.T) {
		u := o.addUser(t, "gone", "member")
		o.grant(t, u, "app", "reader")
		must(t, 200, api(t, "GET", get, u.Token, nil), "before remove")
		must(t, 200, api(t, "DELETE", "/members/"+u.ID, tok, nil), "remove")
		must(t, 401, api(t, "GET", get, u.Token, nil), "after remove")
		must(t, 401, api(t, "GET", "/me", u.Token, nil), "me after remove")
		r := api(t, "POST", "/auth/token", "", map[string]string{"email": u.Email, "password": testPassword})
		if r.Status != 401 {
			t.Errorf("removed user can log in: %s", r)
		}
	})
	t.Run("member_removed_cli", func(t *testing.T) {
		u := o.addUser(t, "gonecli", "member")
		c := newCLIEnv(t)
		c.Token = tok
		c.want(t, 0, nil, "member", "remove", u.Email)
		must(t, 401, api(t, "GET", "/me", u.Token, nil), "after CLI remove")
		c.want(t, 5, nil, "member", "remove", u.Email)
	})
	t.Run("grant_lowered_and_revoked", func(t *testing.T) {
		u := o.addUser(t, "lower", "member")
		o.grant(t, u, "app", "writer")
		must(t, 200, api(t, "PUT", secPath("app", "dev", "W"), u.Token, map[string]string{"value": "1"}), "writer write")
		o.grant(t, u, "app", "reader")
		must(t, 403, api(t, "PUT", secPath("app", "dev", "W"), u.Token, map[string]string{"value": "2"}), "write after lower to reader")
		must(t, 200, api(t, "GET", get, u.Token, nil), "reader read")
		o.grant(t, u, "app", "viewer")
		must(t, 403, api(t, "GET", get, u.Token, nil), "read after lower to viewer")
		must(t, 200, api(t, "GET", secPath("app", "dev", ""), u.Token, nil), "viewer list")
		must(t, 200, api(t, "DELETE", "/members/"+u.ID+"/grants/app", tok, nil), "revoke grant")
		if r := api(t, "GET", secPath("app", "dev", ""), u.Token, nil); r.Status != 404 || string(r.Body) != notFoundBody {
			t.Errorf("after grant revoke: want identical 404, got %s", r)
		}
		must(t, 404, api(t, "DELETE", "/members/"+u.ID+"/grants/app", tok, nil), "revoke missing grant")
	})
	t.Run("role_demoted", func(t *testing.T) {
		u := o.addUser(t, "demote", "admin")
		must(t, 200, api(t, "GET", "/members", u.Token, nil), "admin lists members")
		must(t, 200, api(t, "PATCH", "/members/"+u.ID, tok, map[string]string{"role": "member"}), "demote")
		must(t, 403, api(t, "GET", "/members", u.Token, nil), "demoted lists members")
		must(t, 404, api(t, "GET", get, u.Token, nil), "demoted member without grant")
	})
	t.Run("logout", func(t *testing.T) {
		u := o.addUser(t, "logout", "member")
		must(t, 200, api(t, "POST", "/auth/logout", u.Token, nil), "logout")
		must(t, 401, api(t, "GET", "/me", u.Token, nil), "after logout")
	})
	t.Run("org_disabled", func(t *testing.T) {
		d := newOrg(t, "disable")
		d.project(t, "app", map[string]bool{"dev": false})
		setSecret(t, d.Owner.Token, "app", "dev", "K", "v")
		st := d.serviceToken(t, "app", "dev", "read", 600)
		m := d.addUser(t, "m", "member")
		must(t, 200, api(t, "POST", "/admin/orgs/"+d.Slug+"/disable", adminToken(t), nil), "disable")
		must(t, 401, api(t, "GET", secPath("app", "dev", "K"), d.Owner.Token, nil), "owner after disable")
		must(t, 401, api(t, "GET", secPath("app", "dev", "K"), st.Token, nil), "ST after disable")
		must(t, 401, api(t, "GET", "/me", m.Token, nil), "member after disable")
		if r := api(t, "POST", "/auth/token", "", map[string]string{"email": d.Owner.Email, "password": testPassword}); r.Status != 401 {
			t.Errorf("login into disabled org: %s", r)
		}
		must(t, 200, api(t, "POST", "/admin/orgs/"+d.Slug+"/disable", adminToken(t), nil), "disable idempotent")
		must(t, 404, api(t, "POST", "/admin/orgs/e2e-nope-"+rnd(4)+"/disable", adminToken(t), nil), "disable missing org")
		// Other orgs are unaffected.
		must(t, 200, api(t, "GET", get, tok, nil), "other org unaffected")
		var disabled bool
		for _, x := range must(t, 200, api(t, "GET", "/admin/orgs", adminToken(t), nil), "orgs").arr(t) {
			if x["slug"] == d.Slug {
				disabled, _ = x["disabled"].(bool)
			}
		}
		if !disabled {
			t.Errorf("org %s not reported as disabled", d.Slug)
		}
	})
}
