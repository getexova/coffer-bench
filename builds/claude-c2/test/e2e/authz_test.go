//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
)

// world is a two-organization fixture used by the authorization table.
type world struct {
	A, B                                   *org
	admin, viewer, reader, writer, nogrant user
	stRead, stRW, stProd                   svcToken
	bMember                                user
	changeID                               string // pending change in A (proposed by writer)
	pa                                     string
}

func buildWorld(t *testing.T) *world {
	t.Helper()
	w := &world{pa: adminToken(t)}
	w.A = newOrg(t, "authz-a")
	w.B = newOrg(t, "authz-b")
	w.A.project(t, "web", map[string]bool{"dev": false, "prod": true})
	w.A.project(t, "other", map[string]bool{"dev": false})
	w.B.project(t, "web", map[string]bool{"dev": false})

	w.admin = w.A.addUser(t, "admin", "admin")
	w.viewer = w.A.addUser(t, "viewer", "member")
	w.reader = w.A.addUser(t, "reader", "member")
	w.writer = w.A.addUser(t, "writer", "member")
	w.nogrant = w.A.addUser(t, "nogrant", "member")
	w.bMember = w.B.addUser(t, "bmember", "member")
	w.A.grant(t, w.viewer, "web", "viewer")
	w.A.grant(t, w.reader, "web", "reader")
	w.A.grant(t, w.writer, "web", "writer")

	setSecret(t, w.A.Owner.Token, "web", "dev", "KEY1", "a-value")
	setSecret(t, w.A.Owner.Token, "other", "dev", "OKEY", "other-value")
	setSecret(t, w.B.Owner.Token, "web", "dev", "KEY1", "b-value")

	w.stRead = w.A.serviceToken(t, "web", "dev", "read", 3600)
	w.stRW = w.A.serviceToken(t, "web", "dev", "read-write", 3600)
	w.stProd = w.A.serviceToken(t, "web", "prod", "read", 3600)

	r := must(t, 202, api(t, "PUT", secPath("web", "prod", "PKEY"), w.writer.Token, map[string]string{"value": "p"}), "protected write")
	w.changeID = str(r.obj(t), "change_id")
	if w.changeID == "" {
		t.Fatalf("202 without change_id: %s", r)
	}
	return w
}

type authzCase struct {
	caller string
	method string
	path   string
	body   any
	want   int
}

// TestAuthorizationMatrix tries every SPEC §2 rule from the wrong side and
// checks that every 404 is byte-identical to a genuine not-found (§2.1).
func TestAuthorizationMatrix(t *testing.T) {
	t.Parallel()
	w := buildWorld(t)
	tok := map[string]string{
		"owner": w.A.Owner.Token, "admin": w.admin.Token, "viewer": w.viewer.Token,
		"reader": w.reader.Token, "writer": w.writer.Token, "nogrant": w.nogrant.Token,
		"stRead": w.stRead.Token, "stRW": w.stRW.Token, "stProd": w.stProd.Token,
		"ownerB": w.B.Owner.Token, "pa": w.pa,
	}
	sec := secPath("web", "dev", "KEY1")
	ver := sec + "/versions"
	exp := "/projects/web/envs/dev/export?format=json"
	ownerID, viewerID := w.A.Owner.ID, w.viewer.ID

	var cases []authzCase
	add := func(method, path string, body any, want map[string]int) {
		for c, s := range want {
			cases = append(cases, authzCase{c, method, path, body, s})
		}
	}
	// --- secrets (rules 1, 4, 5, 7, 10)
	add("GET", secPath("web", "dev", ""), nil, map[string]int{
		"owner": 200, "admin": 200, "viewer": 200, "reader": 200, "writer": 200, "nogrant": 404,
		"stRead": 200, "stRW": 200, "stProd": 404, "pa": 404})
	add("GET", sec, nil, map[string]int{
		"owner": 200, "admin": 200, "viewer": 403, "reader": 200, "writer": 200, "nogrant": 404,
		"stRead": 200, "stRW": 200, "stProd": 404, "pa": 404})
	add("GET", secPath("other", "dev", "OKEY"), nil, map[string]int{
		"owner": 200, "admin": 200, "viewer": 404, "reader": 404, "writer": 404, "nogrant": 404,
		"stRead": 404, "stRW": 404, "pa": 404})
	add("GET", secPath("web", "prod", ""), nil, map[string]int{
		"owner": 200, "stRead": 404, "stRW": 404, "stProd": 200})
	add("GET", ver, nil, map[string]int{
		"owner": 200, "viewer": 200, "reader": 200, "nogrant": 404, "stRead": 200, "stProd": 404, "pa": 404})
	add("GET", ver+"/1", nil, map[string]int{
		"owner": 200, "viewer": 403, "reader": 200, "nogrant": 404, "stRead": 200, "stProd": 404, "pa": 404})
	add("PUT", sec, map[string]string{"value": "a-value"}, map[string]int{
		"owner": 200, "admin": 200, "viewer": 403, "reader": 403, "writer": 200, "nogrant": 404,
		"stRead": 403, "stRW": 200, "stProd": 404, "pa": 404})
	add("DELETE", secPath("web", "dev", "NO_SUCH_KEY"), nil, map[string]int{
		"viewer": 403, "reader": 403, "writer": 404, "nogrant": 404, "stRead": 403, "stRW": 404, "stProd": 404, "pa": 404})
	add("POST", sec+"/rollback", map[string]int{"to": 9999}, map[string]int{
		"viewer": 403, "reader": 403, "writer": 404, "nogrant": 404, "stRead": 403, "stRW": 404, "stProd": 404, "pa": 404})
	add("GET", exp, nil, map[string]int{
		"owner": 200, "admin": 200, "viewer": 403, "reader": 200, "writer": 200, "nogrant": 404,
		"stRead": 200, "stRW": 200, "stProd": 404, "pa": 404})
	// Key validation happens after authz: invalid key never reveals existence (§2.1).
	add("GET", secPath("web", "dev", "bad-key"), nil, map[string]int{
		"nogrant": 404, "stProd": 404, "pa": 404, "viewer": 403, "reader": 400})
	add("PUT", secPath("web", "dev", "bad-key"), map[string]string{"value": "x"}, map[string]int{
		"nogrant": 404, "viewer": 403, "writer": 400, "stRead": 403})
	// Genuinely missing things for a fully-authorized caller.
	add("GET", secPath("web", "dev", "NO_SUCH_KEY"), nil, map[string]int{"owner": 404, "stRead": 404})
	add("GET", secPath("web", "nope", "KEY1"), nil, map[string]int{"owner": 404, "stRead": 404, "nogrant": 404})
	add("GET", secPath("nope", "dev", "KEY1"), nil, map[string]int{"owner": 404, "viewer": 404, "stRead": 404})
	add("GET", ver+"/77", nil, map[string]int{"owner": 404})

	// --- projects / envs (rule 3, 6, 7)
	add("GET", "/projects", nil, map[string]int{
		"owner": 200, "admin": 200, "viewer": 200, "nogrant": 200, "stRead": 403, "pa": 404})
	add("POST", "/projects", map[string]string{"slug": "x-" + rnd(3)}, map[string]int{
		"viewer": 403, "writer": 403, "nogrant": 403, "stRW": 403, "pa": 404})
	add("GET", "/projects/web/envs", nil, map[string]int{
		"owner": 200, "viewer": 200, "nogrant": 404, "stRead": 403, "stProd": 403, "pa": 404})
	add("GET", "/projects/other/envs", nil, map[string]int{"viewer": 404, "stRead": 404, "owner": 200})
	add("POST", "/projects/web/envs", map[string]any{"slug": "zz"}, map[string]int{
		"viewer": 403, "reader": 403, "writer": 403, "nogrant": 404, "stRW": 403, "pa": 404})

	// --- members and grants (rules 2, 3, 6, 7, 10)
	add("GET", "/members", nil, map[string]int{
		"owner": 200, "admin": 200, "viewer": 403, "writer": 403, "stRead": 403, "stRW": 403, "pa": 404})
	add("POST", "/members", map[string]string{"email": "e2e-x-" + rnd(3) + "@x.test", "role": "member", "password": testPassword}, map[string]int{
		"viewer": 403, "writer": 403, "stRW": 403, "pa": 404})
	add("POST", "/members", map[string]string{"email": "e2e-y-" + rnd(3) + "@x.test", "role": "owner", "password": testPassword}, map[string]int{
		"admin": 403})
	add("PATCH", "/members/"+viewerID, map[string]string{"role": "member"}, map[string]int{
		"admin": 200, "viewer": 403, "writer": 403, "stRW": 403, "ownerB": 404, "pa": 404})
	add("PATCH", "/members/"+ownerID, map[string]string{"role": "member"}, map[string]int{
		"admin": 403, "writer": 403, "ownerB": 404, "pa": 404})
	add("PATCH", "/members/"+viewerID, map[string]string{"role": "owner"}, map[string]int{"admin": 403})
	add("DELETE", "/members/"+ownerID, nil, map[string]int{
		"admin": 403, "writer": 403, "stRW": 403, "ownerB": 404, "pa": 404})
	add("DELETE", "/members/"+viewerID, nil, map[string]int{"writer": 403, "stRW": 403, "ownerB": 404, "pa": 404})
	add("PATCH", "/members/usr_doesnotexist", map[string]string{"role": "member"}, map[string]int{"owner": 404})
	add("PUT", "/members/"+viewerID+"/grants/web", map[string]string{"level": "viewer"}, map[string]int{
		"admin": 200, "reader": 403, "writer": 403, "stRW": 403, "ownerB": 404, "pa": 404})
	add("PUT", "/members/"+w.writer.ID+"/grants/web", map[string]string{"level": "writer"}, map[string]int{"writer": 403})
	add("PUT", "/members/"+viewerID+"/grants/nope", map[string]string{"level": "viewer"}, map[string]int{"owner": 404})
	add("PUT", "/members/"+w.bMember.ID+"/grants/web", map[string]string{"level": "writer"}, map[string]int{"owner": 404})
	add("DELETE", "/members/"+viewerID+"/grants/web", nil, map[string]int{
		"reader": 403, "stRW": 403, "ownerB": 404, "pa": 404})
	add("DELETE", "/members/"+viewerID+"/grants/other", nil, map[string]int{"owner": 404})

	// --- service tokens (rules 3, 6, 7)
	add("GET", "/tokens", nil, map[string]int{
		"owner": 200, "admin": 200, "writer": 403, "stRW": 403, "pa": 404})
	add("POST", "/tokens", map[string]any{"project": "web", "env": "dev", "access": "read", "ttl_seconds": 600}, map[string]int{
		"writer": 403, "reader": 403, "stRW": 403, "stRead": 403, "pa": 404})
	add("POST", "/tokens", map[string]any{"project": "other", "env": "dev", "access": "read", "ttl_seconds": 600}, map[string]int{
		"ownerB": 404})
	add("DELETE", "/tokens/"+w.stRead.ID, nil, map[string]int{
		"writer": 403, "stRW": 403, "stRead": 403, "ownerB": 404, "pa": 404})
	add("DELETE", "/tokens/tok_doesnotexist", nil, map[string]int{"owner": 404})

	// --- change requests (rules 6, 7, 9)
	add("GET", "/changes", nil, map[string]int{"owner": 200, "admin": 200, "writer": 200, "stRW": 403, "pa": 404})
	add("GET", "/changes?status=bogus", nil, map[string]int{"owner": 400})
	for _, act := range []string{"approve", "reject"} {
		add("POST", "/changes/"+w.changeID+"/"+act, nil, map[string]int{
			"viewer": 403, "reader": 403, "writer": 403, "nogrant": 403, "stRW": 403, "stProd": 403,
			"ownerB": 404, "pa": 404})
		add("POST", "/changes/chg_doesnotexist/"+act, nil, map[string]int{"owner": 404})
	}

	// --- audit (rules 3, 6, 7, 10)
	for _, p := range []string{"/audit", "/audit/verify"} {
		add("GET", p, nil, map[string]int{
			"owner": 200, "admin": 200, "viewer": 403, "writer": 403, "stRead": 403, "stRW": 403, "pa": 404})
	}

	// --- platform routes: everyone but the platform admin gets 404 (rule 10)
	for _, p := range []string{"/admin/orgs", "/admin/audit", "/admin/audit/verify"} {
		add("GET", p, nil, map[string]int{"pa": 200, "owner": 404, "admin": 404, "writer": 404, "stRead": 404})
	}
	add("POST", "/admin/orgs", map[string]string{"slug": "e2e-nope-" + rnd(3), "owner_email": "e2e-n-" + rnd(3) + "@x.test", "owner_password": testPassword}, map[string]int{
		"owner": 404, "stRW": 404})
	add("POST", "/admin/orgs/"+w.A.Slug+"/disable", nil, map[string]int{"owner": 404, "admin": 404, "stRW": 404, "ownerB": 404})

	// --- auth (rule 7: STs can't create PATs or log out)
	add("POST", "/auth/token", map[string]string{"email": w.A.Owner.Email, "password": testPassword}, map[string]int{"stRead": 403})
	add("POST", "/auth/logout", nil, map[string]int{"stRead": 403})
	add("GET", "/me", nil, map[string]int{"owner": 200, "viewer": 200, "stRead": 200, "pa": 200})

	for _, c := range cases {
		name := fmt.Sprintf("%s_%s_%s", c.caller, c.method, c.path)
		t.Run(name, func(t *testing.T) {
			r := api(t, c.method, c.path, tok[c.caller], c.body)
			if r.Status != c.want {
				t.Fatalf("%s %s as %s: want %d, got %s", c.method, c.path, c.caller, c.want, r)
			}
			switch r.Status {
			case 404:
				if string(r.Body) != notFoundBody {
					t.Errorf("404 body not identical to not-found: %q", r.Body)
				}
			case 403:
				if r.errCode() != "forbidden" {
					t.Errorf("403 body: %s", r.Body)
				}
			}
		})
	}

	// Slugs are per-org: B's "web/dev/KEY1" is its own secret, A's stays A's.
	t.Run("tenant_isolation_same_slug", func(t *testing.T) {
		b := must(t, 200, api(t, "GET", sec, w.B.Owner.Token, nil), "B get").obj(t)
		a := must(t, 200, api(t, "GET", sec, w.A.Owner.Token, nil), "A get").obj(t)
		if str(b, "value") != "b-value" || str(a, "value") != "a-value" {
			t.Fatalf("cross-tenant leak: A=%v B=%v", a, b)
		}
		pl := must(t, 200, api(t, "GET", "/projects", w.viewer.Token, nil), "viewer projects").arr(t)
		if len(pl) != 1 || pl[0]["slug"] != "web" {
			t.Errorf("member must see only granted projects: %v", pl)
		}
		ng := must(t, 200, api(t, "GET", "/projects", w.nogrant.Token, nil), "nogrant projects").arr(t)
		if len(ng) != 0 {
			t.Errorf("member without grant sees projects: %v", ng)
		}
		ml := must(t, 200, api(t, "GET", "/members", w.B.Owner.Token, nil), "B members").arr(t)
		for _, m := range ml {
			if strings.HasSuffix(str(m, "email"), "@"+w.A.Slug+".test") {
				t.Errorf("org B member list contains org A user %v", m)
			}
		}
		tl := must(t, 200, api(t, "GET", "/tokens", w.B.Owner.Token, nil), "B tokens").arr(t)
		for _, x := range tl {
			if x["id"] == w.stRead.ID {
				t.Errorf("org B sees org A token")
			}
		}
		cl := must(t, 200, api(t, "GET", "/changes", w.B.Owner.Token, nil), "B changes").arr(t)
		for _, x := range cl {
			if x["id"] == w.changeID {
				t.Errorf("org B sees org A change")
			}
		}
		// Viewer list returns metadata only.
		vl := must(t, 200, api(t, "GET", secPath("web", "dev", ""), w.viewer.Token, nil), "viewer list").arr(t)
		for _, x := range vl {
			if _, ok := x["value"]; ok {
				t.Errorf("list leaks value: %v", x)
			}
			for _, k := range []string{"key", "version", "updated_at", "updated_by"} {
				if _, ok := x[k]; !ok {
					t.Errorf("list item missing %s: %v", k, x)
				}
			}
		}
		// The platform admin's org listing must not leak secrets/members.
		if strings.Contains(string(api(t, "GET", "/admin/orgs", w.pa, nil).Body), "a-value") {
			t.Errorf("admin org list leaks values")
		}
	})

	// ST /me reports its scope.
	t.Run("st_me", func(t *testing.T) {
		m := must(t, 200, api(t, "GET", "/me", w.stRead.Token, nil), "st me").obj(t)
		if str(m, "type") != "service_token" || str(m, "access") != "read" {
			t.Errorf("ST /me: %v", m)
		}
	})
}

// TestNoSelfEscalation covers SPEC §2.2 and §2.12.
func TestNoSelfEscalation(t *testing.T) {
	t.Parallel()
	o := newOrg(t, "esc")
	o.project(t, "web", map[string]bool{"dev": false})
	adm := o.addUser(t, "adm", "admin")
	mem := o.addUser(t, "mem", "member")
	o.grant(t, mem, "web", "viewer")

	check := func(name string, r resp, want ...int) {
		t.Helper()
		for _, w := range want {
			if r.Status == w {
				return
			}
		}
		t.Errorf("%s: want %v, got %s", name, want, r)
	}
	// Own role changes.
	check("admin self->owner", api(t, "PATCH", "/members/"+adm.ID, adm.Token, map[string]string{"role": "owner"}), 403)
	check("admin self->member", api(t, "PATCH", "/members/"+adm.ID, adm.Token, map[string]string{"role": "member"}), 403)
	check("member self->admin", api(t, "PATCH", "/members/"+mem.ID, mem.Token, map[string]string{"role": "admin"}), 403)
	check("member self grant writer", api(t, "PUT", "/members/"+mem.ID+"/grants/web", mem.Token, map[string]string{"level": "writer"}), 403)
	check("admin self grant", api(t, "PUT", "/members/"+adm.ID+"/grants/web", adm.Token, map[string]string{"level": "writer"}), 400, 403)
	// Fields a caller may not set: rejected (400) or ignored, never applied.
	check("patch with org_id", api(t, "PATCH", "/members/"+mem.ID, o.Owner.Token, map[string]any{"role": "member", "org_id": "org_x"}), 400, 200)
	check("patch platform_admin", api(t, "PATCH", "/members/"+mem.ID, o.Owner.Token, map[string]string{"role": "platform_admin"}), 400)
	check("add platform_admin", api(t, "POST", "/members", o.Owner.Token, map[string]string{"email": "e2e-pa-" + rnd(3) + "@x.test", "role": "platform_admin", "password": testPassword}), 400)
	check("add bogus role", api(t, "POST", "/members", o.Owner.Token, map[string]string{"email": "e2e-pb-" + rnd(3) + "@x.test", "role": "root", "password": testPassword}), 400)
	check("grant to admin", api(t, "PUT", "/members/"+adm.ID+"/grants/web", o.Owner.Token, map[string]string{"level": "reader"}), 400)
	check("bad grant level", api(t, "PUT", "/members/"+mem.ID+"/grants/web", o.Owner.Token, map[string]string{"level": "owner"}), 400)
	check("short password", api(t, "POST", "/members", o.Owner.Token, map[string]string{"email": "e2e-pc-" + rnd(3) + "@x.test", "role": "member", "password": "short"}), 400)
	check("eleven-char password", api(t, "POST", "/members", o.Owner.Token, map[string]string{"email": "e2e-pd-" + rnd(3) + "@x.test", "role": "member", "password": "elevenchars"}), 400)
	check("duplicate email", api(t, "POST", "/members", o.Owner.Token, map[string]string{"email": mem.Email, "role": "member", "password": testPassword}), 409)

	me := must(t, 200, api(t, "GET", "/me", mem.Token, nil), "me").obj(t)
	if str(me, "role") != "member" || str(me, "org_id") != str(must(t, 200, api(t, "GET", "/me", o.Owner.Token, nil), "me").obj(t), "org_id") {
		t.Fatalf("member role/org changed: %v", me)
	}
	if r := api(t, "GET", "/members", mem.Token, nil); r.Status != 403 {
		t.Errorf("member gained member management: %s", r)
	}
	if r := api(t, "GET", secPath("web", "dev", ""), mem.Token, nil); r.Status != 200 {
		t.Errorf("viewer grant changed: %s", r)
	}
	if r := api(t, "PUT", secPath("web", "dev", "X"), mem.Token, map[string]string{"value": "x"}); r.Status != 403 {
		t.Errorf("viewer could write after self-grant attempt: %s", r)
	}

	// Last-owner protection (SPEC §2.2 → 409).
	check("last owner self-demote", api(t, "PATCH", "/members/"+o.Owner.ID, o.Owner.Token, map[string]string{"role": "admin"}), 409)
	check("last owner self-remove", api(t, "DELETE", "/members/"+o.Owner.ID, o.Owner.Token, nil), 409)
	// Only an owner can create/promote owners.
	check("admin promote member to owner", api(t, "PATCH", "/members/"+mem.ID, adm.Token, map[string]string{"role": "owner"}), 403)
	o2 := o.addUser(t, "owner2", "owner")
	check("admin demote owner2", api(t, "PATCH", "/members/"+o2.ID, adm.Token, map[string]string{"role": "admin"}), 403)
	check("admin remove owner2", api(t, "DELETE", "/members/"+o2.ID, adm.Token, nil), 403)
	check("owner demotes owner2", api(t, "PATCH", "/members/"+o2.ID, o.Owner.Token, map[string]string{"role": "admin"}), 200)
	check("owner promotes owner2 back", api(t, "PATCH", "/members/"+o2.ID, o.Owner.Token, map[string]string{"role": "owner"}), 200)
	check("owner2 removes original owner", api(t, "DELETE", "/members/"+o.Owner.ID, o2.Token, nil), 200)
	must(t, 401, api(t, "GET", "/me", o.Owner.Token, nil), "removed owner PAT")
	check("owner2 now last: self-demote", api(t, "PATCH", "/members/"+o2.ID, o2.Token, map[string]string{"role": "member"}), 409)
	check("admin promotes self via add owner", api(t, "POST", "/members", adm.Token, map[string]string{"email": "e2e-pe-" + rnd(3) + "@x.test", "role": "owner", "password": testPassword}), 403)
	check("admin adds admin", api(t, "POST", "/members", adm.Token, map[string]string{"email": "e2e-pf-" + rnd(3) + "@x.test", "role": "admin", "password": testPassword}), 201)
	check("admin manages member", api(t, "PATCH", "/members/"+mem.ID, adm.Token, map[string]string{"role": "admin"}), 200)
	check("admin removes admin(mem)", api(t, "DELETE", "/members/"+mem.ID, adm.Token, nil), 200)
}
