package api_test

import (
	"sort"
	"strings"
	"testing"
)

func keysOf(m map[string]any) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

// Response shapes the CLI depends on (CONTRACT §5.3).
func TestResponseShapes(t *testing.T) {
	w := newWorld(t)
	o := w.c(w.OwnerA)
	expect := func(what string, m map[string]any, want string) {
		t.Helper()
		if got := keysOf(m); got != want {
			t.Errorf("%s keys = %s, want %s", what, got, want)
		}
	}
	var members []map[string]any
	o.Must(t, 200, "GET", "/members", nil).JSON(t, &members)
	for _, m := range members {
		expect("member", m, "created_at,email,grants,id,role")
		if m["email"] == "viewer@acme.test" {
			g := m["grants"].([]any)
			if len(g) != 1 || g[0].(map[string]any)["project"] != "web" || g[0].(map[string]any)["level"] != "viewer" {
				t.Errorf("viewer grants %v", g)
			}
		}
	}
	var projects []map[string]any
	o.Must(t, 200, "GET", "/projects", nil).JSON(t, &projects)
	expect("project", projects[0], "created_at,id,slug")
	var envs []map[string]any
	o.Must(t, 200, "GET", "/projects/web/envs", nil).JSON(t, &envs)
	expect("env", envs[0], "created_at,id,protected,slug")
	var secrets []map[string]any
	o.Must(t, 200, "GET", "/projects/web/envs/dev/secrets", nil).JSON(t, &secrets)
	expect("secret", secrets[0], "key,updated_at,updated_by,version")
	expect("value", o.Must(t, 200, "GET", "/projects/web/envs/dev/secrets/DB_URL", nil).Map(t), "key,value,version")
	var versions []map[string]any
	o.Must(t, 200, "GET", "/projects/web/envs/dev/secrets/DB_URL/versions", nil).JSON(t, &versions)
	expect("version", versions[0], "created_at,created_by,deleted,version")
	var changes []map[string]any
	o.Must(t, 200, "GET", "/changes", nil).JSON(t, &changes)
	expect("change", changes[0], "applied_version,base_version,created_at,decided_at,decided_by,env,id,key,op,project,proposed_by,rollback_to,status")
	var tokens []map[string]any
	o.Must(t, 200, "GET", "/tokens", nil).JSON(t, &tokens)
	expect("token", tokens[0], "access,created_at,created_by,env,expires_at,id,last_used_at,name,project,revoked_at")
	expect("token create", create(t, o, "/tokens", map[string]any{"project": "web", "env": "dev", "access": "read", "ttl_seconds": 60}),
		"access,env,expires_at,id,name,project,token")
	var events []map[string]any
	o.Must(t, 200, "GET", "/audit?limit=1", nil).JSON(t, &events)
	expect("audit", events[0], "action,actor,details,hash,prev_hash,result,seq,source_ip,target,ts")
	expect("verify", o.Must(t, 200, "GET", "/audit/verify", nil).Map(t), "first_invalid_seq,valid")
	expect("me", o.Must(t, 200, "GET", "/me", nil).Map(t), "email,id,must_change_password,org_id,org_slug,role,type")
	expect("st me", w.c(w.STReadA).Must(t, 200, "GET", "/me", nil).Map(t), "access,env,expires_at,id,org_id,org_slug,project,type")
	login := w.S.Client("").Must(t, 201, "POST", "/auth/token", map[string]string{"email": "reader@acme.test", "password": pw}).Map(t)
	expect("login", login, "expires_at,token,user")
	expect("login user", login["user"].(map[string]any), "email,id,must_change_password,org_id,org_slug,role")
	var orgs []map[string]any
	w.c(w.PA).Must(t, 200, "GET", "/admin/orgs", nil).JSON(t, &orgs)
	expect("org", orgs[0], "created_at,disabled,id,slug")
	expect("org create", create(t, w.c(w.PA), "/admin/orgs", map[string]string{"slug": "new-org", "owner_email": "n@new.test", "owner_password": pw}),
		"created_at,disabled,id,owner,slug")
	w.c(w.PA).Must(t, 409, "POST", "/admin/orgs", map[string]string{"slug": "new-org", "owner_email": "n2@new.test", "owner_password": pw})
	w.c(w.PA).Must(t, 409, "POST", "/admin/orgs", map[string]string{"slug": "new-org2", "owner_email": "N@new.test", "owner_password": pw})
	w.c(w.PA).Must(t, 400, "POST", "/admin/orgs", map[string]string{"slug": "Bad_Slug", "owner_email": "b@new.test", "owner_password": pw})
	w.c(w.PA).Must(t, 400, "POST", "/admin/orgs", map[string]string{"slug": "short-pw", "owner_email": "b@new.test", "owner_password": "short"})
	o.Must(t, 409, "POST", "/projects", map[string]string{"slug": "web"})
	w.c(w.OwnerB).Must(t, 409, "POST", "/projects", map[string]string{"slug": "web"})
	w.c(w.OwnerB).Must(t, 201, "POST", "/projects", map[string]string{"slug": "api"}) // slugs are per-org
	o.Must(t, 409, "POST", "/projects/web/envs", map[string]any{"slug": "dev"})
	o.Must(t, 409, "POST", "/members", map[string]string{"email": "owner@globex.test", "role": "member", "password": pw})
	o.Must(t, 400, "POST", "/members", map[string]string{"email": "m@acme.test", "role": "superuser", "password": pw})
	o.Must(t, 400, "POST", "/members", map[string]string{"email": "m@acme.test", "role": "member", "password": "short"})
}
