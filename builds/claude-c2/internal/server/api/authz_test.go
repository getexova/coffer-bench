package api_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/coffer-dev/coffer/internal/server/testutil"
)

// secretPaths returns every secret-route request under project p / env e.
type req struct {
	method, path string
	body         any
}

func secretPaths(p, e string) []req {
	base := fmt.Sprintf("/projects/%s/envs/%s", p, e)
	return []req{
		{"GET", base + "/secrets", nil},
		{"GET", base + "/secrets/DB_URL", nil},
		{"PUT", base + "/secrets/DB_URL", map[string]string{"value": "x"}},
		{"DELETE", base + "/secrets/DB_URL", nil},
		{"GET", base + "/secrets/DB_URL/versions", nil},
		{"GET", base + "/secrets/DB_URL/versions/1", nil},
		{"POST", base + "/secrets/DB_URL/rollback", map[string]int{"to": 1}},
		{"GET", base + "/export?format=json", nil},
		{"GET", base + "/export?format=dotenv", nil},
	}
}

// expectAll asserts every request in reqs returns want, and for 404/403 that
// the body is the canonical one.
func expectAll(t *testing.T, w *world, who, tok string, reqs []req, want int) {
	t.Helper()
	for _, q := range reqs {
		r := w.c(tok).Do(t, q.method, q.path, q.body)
		if r.Status != want {
			t.Errorf("%s: %s %s => %d, want %d (%s)", who, q.method, q.path, r.Status, want, r.Body)
			continue
		}
		if want == 404 && string(r.Body) != notFoundBody {
			t.Errorf("%s: %s %s 404 body %q", who, q.method, q.path, r.Body)
		}
		if want == 403 && string(r.Body) != forbiddenBody {
			t.Errorf("%s: %s %s 403 body %q", who, q.method, q.path, r.Body)
		}
	}
}

// TestAuthzReadOnly covers rules that don't mutate shared state (or only
// mutate keys nobody else reads).
func TestAuthzReadOnly(t *testing.T) {
	w := newWorld(t)

	t.Run("rule1_invisible_is_404_and_identical", func(t *testing.T) {
		// Something that really does not exist, asked by an owner who can see
		// everything in their org.
		missing := w.c(w.OwnerA).Do(t, "GET", "/projects/does-not-exist/envs/dev/secrets/DB_URL", nil)
		if missing.Status != 404 || string(missing.Body) != notFoundBody {
			t.Fatalf("baseline missing: %d %s", missing.Status, missing.Body)
		}
		// Another org's project, secret and env: identical 404.
		cases := []struct{ who, tok, path string }{
			{"acme owner -> globex project", w.OwnerA, "/projects/globex-only/envs/dev/secrets/SECRET"},
			{"acme owner -> globex project envs", w.OwnerA, "/projects/globex-only/envs"},
			{"acme admin -> globex project", w.AdminA, "/projects/globex-only/envs/dev/secrets"},
			{"globex owner -> acme project", w.OwnerB, "/projects/api/envs/dev/secrets/API_KEY"},
			{"globex owner -> acme project envs", w.OwnerB, "/projects/api/envs"},
			{"acme member no grant", w.NoGrantA, "/projects/web/envs/dev/secrets/DB_URL"},
			{"acme member no grant envs", w.NoGrantA, "/projects/web/envs"},
			{"acme viewer -> ungranted project", w.ViewerA, "/projects/api/envs/dev/secrets"},
			{"acme ST -> other env", w.STReadA, "/projects/web/envs/prod/secrets/DB_URL"},
			{"acme ST -> other project", w.STReadA, "/projects/api/envs/dev/secrets/API_KEY"},
			{"acme ST -> other project envs", w.STReadA, "/projects/api/envs"},
			{"globex ST -> globex other project", w.STReadB, "/projects/globex-only/envs/dev/secrets/SECRET"},
			{"globex ST -> acme project", w.STReadB, "/projects/api/envs/dev/secrets/API_KEY"},
			{"platform admin -> acme secret", w.PA, "/projects/web/envs/dev/secrets/DB_URL"},
			{"owner -> missing env", w.OwnerA, "/projects/web/envs/nope/secrets/DB_URL"},
			{"owner -> missing key", w.OwnerA, "/projects/web/envs/dev/secrets/NOPE"},
			{"owner -> missing version", w.OwnerA, "/projects/web/envs/dev/secrets/DB_URL/versions/99"},
			{"owner -> missing key versions", w.OwnerA, "/projects/web/envs/dev/secrets/NOPE/versions"},
		}
		for _, c := range cases {
			r := w.c(c.tok).Do(t, "GET", c.path, nil)
			if r.Status != 404 || string(r.Body) != string(missing.Body) {
				t.Errorf("%s: %d %s", c.who, r.Status, r.Body)
			}
			if ct := r.Header.Get("Content-Type"); ct != missing.Header.Get("Content-Type") {
				t.Errorf("%s: content-type %q", c.who, ct)
			}
		}
		// Every secret operation, not only GET.
		expectAll(t, w, "nogrant", w.NoGrantA, secretPaths("web", "dev"), 404)
		expectAll(t, w, "acme owner -> globex", w.OwnerA, secretPaths("globex-only", "dev"), 404)
		expectAll(t, w, "ST other env", w.STRWA, secretPaths("web", "prod"), 404)
		expectAll(t, w, "ST other project", w.STRWA, secretPaths("api", "dev"), 404)
		expectAll(t, w, "PA", w.PA, secretPaths("web", "dev"), 404)
		// Validation never reveals existence: an invalid key under an
		// invisible project is 404, not 400.
		r := w.c(w.NoGrantA).Do(t, "GET", "/projects/web/envs/dev/secrets/bad-key", nil)
		if r.Status != 404 {
			t.Errorf("invalid key under invisible project: %d", r.Status)
		}
		r = w.c(w.OwnerB).Do(t, "PUT", "/projects/api/envs/dev/secrets/API_KEY", `{"value": 5}`)
		if r.Status != 404 {
			t.Errorf("bad body under invisible project: %d", r.Status)
		}
		// Approve/reject a change in another org.
		r = w.c(w.OwnerA).Must(t, 202, "PUT", "/projects/web/envs/prod/secrets/OTHER_ORG_PROBE", map[string]string{"value": "v"})
		id := r.Map(t)["change_id"].(string)
		for _, tok := range []string{w.OwnerB} {
			for _, act := range []string{"approve", "reject"} {
				r := w.c(tok).Do(t, "POST", "/changes/"+id+"/"+act, nil)
				if r.Status != 404 || string(r.Body) != notFoundBody {
					t.Errorf("cross-org %s: %d %s", act, r.Status, r.Body)
				}
			}
		}
		r = w.c(w.OwnerA).Do(t, "POST", "/changes/chg_doesnotexist/approve", nil)
		if r.Status != 404 {
			t.Errorf("missing change approve: %d", r.Status)
		}
		// Members/tokens of another org.
		runChecks(t, w, []check{
			{"patch other-org member", w.OwnerA, "PATCH", "/members/" + w.OwnerBID, map[string]string{"role": "member"}, 404},
			{"delete other-org member", w.OwnerA, "DELETE", "/members/" + w.OwnerBID, nil, 404},
			{"grant other-org member", w.OwnerA, "PUT", "/members/" + w.OwnerBID + "/grants/web", map[string]string{"level": "reader"}, 404},
			{"grant other-org project", w.OwnerA, "PUT", "/members/" + w.ViewerAID + "/grants/globex-only", map[string]string{"level": "reader"}, 404},
			{"revoke other-org token", w.OwnerB, "DELETE", "/tokens/" + w.STReadAID, nil, 404},
			{"token for other-org project", w.OwnerA, "POST", "/tokens", map[string]any{"project": "globex-only", "env": "dev", "access": "read", "ttl_seconds": 600}, 404},
			{"env create other-org project", w.OwnerA, "POST", "/projects/globex-only/envs", map[string]any{"slug": "x"}, 404},
			{"platform admin user via members", w.OwnerA, "DELETE", "/members/nonexistent", nil, 404},
		})
	})

	t.Run("rule2_3_owner_admin_capabilities", func(t *testing.T) {
		for _, who := range []struct{ name, tok string }{{"owner", w.OwnerA}, {"admin", w.AdminA}} {
			runChecks(t, w, []check{
				{who.name + " list members", who.tok, "GET", "/members", nil, 200},
				{who.name + " list projects", who.tok, "GET", "/projects", nil, 200},
				{who.name + " list envs", who.tok, "GET", "/projects/web/envs", nil, 200},
				{who.name + " list secrets", who.tok, "GET", "/projects/web/envs/dev/secrets", nil, 200},
				{who.name + " get secret", who.tok, "GET", "/projects/api/envs/dev/secrets/API_KEY", nil, 200},
				{who.name + " export", who.tok, "GET", "/projects/web/envs/dev/export", nil, 200},
				{who.name + " changes", who.tok, "GET", "/changes", nil, 200},
				{who.name + " tokens", who.tok, "GET", "/tokens", nil, 200},
				{who.name + " audit", who.tok, "GET", "/audit", nil, 200},
				{who.name + " audit verify", who.tok, "GET", "/audit/verify", nil, 200},
			})
		}
		// Admins never manage owners.
		runChecks(t, w, []check{
			{"admin creates owner", w.AdminA, "POST", "/members", map[string]string{"email": "o3@acme.test", "role": "owner", "password": pw}, 403},
			{"admin promotes to owner", w.AdminA, "PATCH", "/members/" + w.ViewerAID, map[string]string{"role": "owner"}, 403},
			{"admin demotes owner", w.AdminA, "PATCH", "/members/" + w.Owner2AID, map[string]string{"role": "member"}, 403},
			{"admin changes owner to admin", w.AdminA, "PATCH", "/members/" + w.OwnerAID, map[string]string{"role": "admin"}, 403},
			{"admin removes owner", w.AdminA, "DELETE", "/members/" + w.Owner2AID, nil, 403},
			{"admin no-op owner", w.AdminA, "PATCH", "/members/" + w.OwnerAID, map[string]string{"role": "owner"}, 403},
		})
		// Nothing changed.
		var members []struct{ ID, Role string }
		w.c(w.OwnerA).Must(t, 200, "GET", "/members", nil).JSON(t, &members)
		for _, m := range members {
			if (m.ID == w.OwnerAID || m.ID == w.Owner2AID) && m.Role != "owner" {
				t.Errorf("owner %s role became %s", m.ID, m.Role)
			}
			if m.ID == w.ViewerAID && m.Role != "member" {
				t.Errorf("viewer role became %s", m.Role)
			}
		}
	})

	t.Run("rule4_member_grant_levels", func(t *testing.T) {
		base := "/projects/web/envs/dev"
		read := []check{
			{"list", "", "GET", base + "/secrets", nil, 0},
			{"versions", "", "GET", base + "/secrets/DB_URL/versions", nil, 0},
			{"get", "", "GET", base + "/secrets/DB_URL", nil, 0},
			{"get version", "", "GET", base + "/secrets/DB_URL/versions/1", nil, 0},
			{"export json", "", "GET", base + "/export?format=json", nil, 0},
			{"export dotenv", "", "GET", base + "/export?format=dotenv", nil, 0},
			{"list envs", "", "GET", "/projects/web/envs", nil, 0},
		}
		write := []check{
			{"set", "", "PUT", base + "/secrets/LEVEL_PROBE", map[string]string{"value": "x"}, 0},
			{"rollback", "", "POST", base + "/secrets/LEVEL_PROBE/rollback", map[string]int{"to": 1}, 0},
			{"delete", "", "DELETE", base + "/secrets/LEVEL_PROBE", nil, 0},
		}
		expect := map[string][]int{
			// list versions get getv json dotenv envs | set rollback delete
			"viewer": {200, 200, 403, 403, 403, 403, 200, 403, 403, 403},
			"reader": {200, 200, 200, 200, 200, 200, 200, 403, 403, 403},
			"writer": {200, 200, 200, 200, 200, 200, 200, 200, 200, 200},
		}
		toks := map[string]string{"viewer": w.ViewerA, "reader": w.ReaderA, "writer": w.WriterA}
		for _, who := range []string{"viewer", "reader", "writer"} {
			all := append(append([]check{}, read...), write...)
			for i := range all {
				all[i].name = who + " " + all[i].name
				all[i].tok = toks[who]
				all[i].want = expect[who][i]
			}
			runChecks(t, w, all)
		}
		// Viewer sees names/metadata but never values.
		r := w.c(w.ViewerA).Must(t, 200, "GET", base+"/secrets", nil)
		if strings.Contains(string(r.Body), "acme-dev") || !strings.Contains(string(r.Body), "DB_URL") {
			t.Errorf("viewer list: %s", r.Body)
		}
		// Members see only granted projects in /projects.
		var projects []struct{ Slug, Level string }
		w.c(w.ViewerA).Must(t, 200, "GET", "/projects", nil).JSON(t, &projects)
		if len(projects) != 1 || projects[0].Slug != "web" || projects[0].Level != "viewer" {
			t.Errorf("viewer projects: %+v", projects)
		}
		w.c(w.NoGrantA).Must(t, 200, "GET", "/projects", nil).JSON(t, &projects)
		if len(projects) != 0 {
			t.Errorf("no-grant projects: %+v", projects)
		}
	})

	t.Run("rule6_members_cannot_manage", func(t *testing.T) {
		for _, who := range []struct{ name, tok string }{{"viewer", w.ViewerA}, {"writer", w.WriterA}, {"nogrant", w.NoGrantA}} {
			runChecks(t, w, []check{
				{who.name + " list members", who.tok, "GET", "/members", nil, 403},
				{who.name + " add member", who.tok, "POST", "/members", map[string]string{"email": "x@acme.test", "role": "member", "password": pw}, 403},
				{who.name + " patch member", who.tok, "PATCH", "/members/" + w.ReaderAID, map[string]string{"role": "admin"}, 403},
				{who.name + " patch self", who.tok, "PATCH", "/members/" + w.ViewerAID, map[string]string{"role": "owner"}, 403},
				{who.name + " remove member", who.tok, "DELETE", "/members/" + w.ReaderAID, nil, 403},
				{who.name + " patch unknown member", who.tok, "PATCH", "/members/usr_nope", map[string]string{"role": "admin"}, 403},
				{who.name + " set grant", who.tok, "PUT", "/members/" + w.NoGrAID + "/grants/web", map[string]string{"level": "writer"}, 403},
				{who.name + " self grant", who.tok, "PUT", "/members/" + w.ViewerAID + "/grants/web", map[string]string{"level": "writer"}, 403},
				{who.name + " revoke grant", who.tok, "DELETE", "/members/" + w.ReaderAID + "/grants/web", nil, 403},
				{who.name + " list tokens", who.tok, "GET", "/tokens", nil, 403},
				{who.name + " create token", who.tok, "POST", "/tokens", map[string]any{"project": "web", "env": "dev", "access": "read", "ttl_seconds": 600}, 403},
				{who.name + " revoke token", who.tok, "DELETE", "/tokens/" + w.STReadAID, nil, 403},
				{who.name + " approve", who.tok, "POST", "/changes/chg_x/approve", nil, 403},
				{who.name + " reject", who.tok, "POST", "/changes/chg_x/reject", nil, 403},
				{who.name + " audit", who.tok, "GET", "/audit", nil, 403},
				{who.name + " audit verify", who.tok, "GET", "/audit/verify", nil, 403},
				{who.name + " create project", who.tok, "POST", "/projects", map[string]string{"slug": "mine"}, 403},
				{who.name + " list changes", who.tok, "GET", "/changes", nil, 200},
			})
		}
		// Grants unchanged.
		var projects []struct{ Slug, Level string }
		w.c(w.ViewerA).Must(t, 200, "GET", "/projects", nil).JSON(t, &projects)
		if len(projects) != 1 || projects[0].Level != "viewer" {
			t.Errorf("viewer escalated: %+v", projects)
		}
		// Viewer on a visible project gets 403 (not 404) for env create.
		runChecks(t, w, []check{{"viewer env create", w.ViewerA, "POST", "/projects/web/envs", map[string]any{"slug": "x"}, 403}})
	})

	t.Run("rule7_service_tokens", func(t *testing.T) {
		base := "/projects/web/envs/dev"
		runChecks(t, w, []check{
			{"ST read list", w.STReadA, "GET", base + "/secrets", nil, 200},
			{"ST read get", w.STReadA, "GET", base + "/secrets/DB_URL", nil, 200},
			{"ST read history", w.STReadA, "GET", base + "/secrets/DB_URL/versions", nil, 200},
			{"ST read version", w.STReadA, "GET", base + "/secrets/DB_URL/versions/1", nil, 200},
			{"ST read export", w.STReadA, "GET", base + "/export?format=dotenv", nil, 200},
			{"ST read set", w.STReadA, "PUT", base + "/secrets/ST_PROBE", map[string]string{"value": "x"}, 403},
			{"ST read delete", w.STReadA, "DELETE", base + "/secrets/DB_URL", nil, 403},
			{"ST read rollback", w.STReadA, "POST", base + "/secrets/DB_URL/rollback", map[string]int{"to": 1}, 403},
			{"ST rw set", w.STRWA, "PUT", base + "/secrets/ST_PROBE", map[string]string{"value": "x"}, 200},
			{"ST rw set 2", w.STRWA, "PUT", base + "/secrets/ST_PROBE", map[string]string{"value": "y"}, 200},
			{"ST rw rollback", w.STRWA, "POST", base + "/secrets/ST_PROBE/rollback", map[string]int{"to": 1}, 200},
			{"ST rw delete", w.STRWA, "DELETE", base + "/secrets/ST_PROBE", nil, 200},
		})
		for _, who := range []struct{ name, tok string }{{"ST read", w.STReadA}, {"ST rw", w.STRWA}} {
			runChecks(t, w, []check{
				{who.name + " members", who.tok, "GET", "/members", nil, 403},
				{who.name + " add member", who.tok, "POST", "/members", map[string]string{"email": "st@acme.test", "role": "owner", "password": pw}, 403},
				{who.name + " patch member", who.tok, "PATCH", "/members/" + w.ViewerAID, map[string]string{"role": "admin"}, 403},
				{who.name + " remove member", who.tok, "DELETE", "/members/" + w.ViewerAID, nil, 403},
				{who.name + " grant", who.tok, "PUT", "/members/" + w.ViewerAID + "/grants/web", map[string]string{"level": "writer"}, 403},
				{who.name + " tokens", who.tok, "GET", "/tokens", nil, 403},
				{who.name + " issue token", who.tok, "POST", "/tokens", map[string]any{"project": "web", "env": "dev", "access": "read-write", "ttl_seconds": 600}, 403},
				{who.name + " revoke token", who.tok, "DELETE", "/tokens/" + w.STReadAID, nil, 403},
				{who.name + " audit", who.tok, "GET", "/audit", nil, 403},
				{who.name + " audit verify", who.tok, "GET", "/audit/verify", nil, 403},
				{who.name + " changes", who.tok, "GET", "/changes", nil, 403},
				{who.name + " approve", who.tok, "POST", "/changes/chg_x/approve", nil, 403},
				{who.name + " reject", who.tok, "POST", "/changes/chg_x/reject", nil, 403},
				{who.name + " create PAT", who.tok, "POST", "/auth/token", map[string]string{"email": "owner@acme.test", "password": pw}, 403},
				{who.name + " logout", who.tok, "POST", "/auth/logout", nil, 403},
				{who.name + " password", who.tok, "POST", "/auth/password", map[string]string{"current_password": pw, "new_password": pw + "x"}, 403},
				{who.name + " projects", who.tok, "GET", "/projects", nil, 403},
				{who.name + " create project", who.tok, "POST", "/projects", map[string]string{"slug": "st"}, 403},
				{who.name + " own project envs", who.tok, "GET", "/projects/web/envs", nil, 403},
				{who.name + " own project env create", who.tok, "POST", "/projects/web/envs", map[string]any{"slug": "x"}, 403},
				{who.name + " other project envs", who.tok, "GET", "/projects/api/envs", nil, 404},
				{who.name + " me", who.tok, "GET", "/me", nil, 200},
			})
		}
		// The PAT-creation attempt by an ST was rejected even though the
		// credentials were right; the owner's own PAT still works.
		w.c(w.OwnerA).Must(t, 200, "GET", "/me", nil)
	})

	t.Run("rule10_platform_admin", func(t *testing.T) {
		orgScoped := []check{
			{"members", w.PA, "GET", "/members", nil, 404},
			{"add member", w.PA, "POST", "/members", map[string]string{"email": "pa@x.test", "role": "owner", "password": pw}, 404},
			{"patch member", w.PA, "PATCH", "/members/" + w.OwnerAID, map[string]string{"role": "member"}, 404},
			{"remove member", w.PA, "DELETE", "/members/" + w.OwnerAID, nil, 404},
			{"grant", w.PA, "PUT", "/members/" + w.ViewerAID + "/grants/web", map[string]string{"level": "writer"}, 404},
			{"revoke grant", w.PA, "DELETE", "/members/" + w.ViewerAID + "/grants/web", nil, 404},
			{"projects", w.PA, "GET", "/projects", nil, 404},
			{"create project", w.PA, "POST", "/projects", map[string]string{"slug": "pa"}, 404},
			{"envs", w.PA, "GET", "/projects/web/envs", nil, 404},
			{"create env", w.PA, "POST", "/projects/web/envs", map[string]any{"slug": "pa"}, 404},
			{"changes", w.PA, "GET", "/changes", nil, 404},
			{"approve", w.PA, "POST", "/changes/chg_x/approve", nil, 404},
			{"reject", w.PA, "POST", "/changes/chg_x/reject", nil, 404},
			{"tokens", w.PA, "GET", "/tokens", nil, 404},
			{"create token", w.PA, "POST", "/tokens", map[string]any{"project": "web", "env": "dev", "access": "read", "ttl_seconds": 600}, 404},
			{"revoke token", w.PA, "DELETE", "/tokens/" + w.STReadAID, nil, 404},
			{"audit", w.PA, "GET", "/audit", nil, 404},
			{"audit verify", w.PA, "GET", "/audit/verify", nil, 404},
		}
		runChecks(t, w, orgScoped)
		for _, c := range orgScoped {
			r := w.c(c.tok).Do(t, c.method, c.path, c.body)
			if string(r.Body) != notFoundBody {
				t.Errorf("PA %s body %s", c.name, r.Body)
			}
		}
		expectAll(t, w, "PA secrets", w.PA, secretPaths("web", "dev"), 404)
		runChecks(t, w, []check{
			{"PA list orgs", w.PA, "GET", "/admin/orgs", nil, 200},
			{"PA platform audit", w.PA, "GET", "/admin/audit", nil, 200},
			{"PA platform verify", w.PA, "GET", "/admin/audit/verify", nil, 200},
			{"PA me", w.PA, "GET", "/me", nil, 200},
		})
		// Nobody else can reach /admin (404, not 403).
		for _, who := range []struct{ name, tok string }{{"owner", w.OwnerA}, {"admin", w.AdminA}, {"member", w.ReaderA}, {"ST", w.STRWA}} {
			runChecks(t, w, []check{
				{who.name + " admin orgs", who.tok, "GET", "/admin/orgs", nil, 404},
				{who.name + " admin create org", who.tok, "POST", "/admin/orgs", map[string]string{"slug": "evil", "owner_email": "e@e.test", "owner_password": pw}, 404},
				{who.name + " admin disable", who.tok, "POST", "/admin/orgs/globex/disable", nil, 404},
				{who.name + " admin audit", who.tok, "GET", "/admin/audit", nil, 404},
				{who.name + " admin verify", who.tok, "GET", "/admin/audit/verify", nil, 404},
			})
		}
		// The PA's denials went to the platform chain, which no org can read;
		// org A's chain does not contain PA events.
		var events []map[string]any
		w.c(w.PA).Must(t, 200, "GET", "/admin/audit?limit=1000", nil).JSON(t, &events)
		found := false
		for _, e := range events {
			if e["action"] == "authz.denied" {
				found = true
			}
		}
		if !found {
			t.Error("PA denial not in platform chain")
		}
		w.c(w.OwnerA).Must(t, 200, "GET", "/audit?limit=1000", nil).JSON(t, &events)
		paID := w.mustPAID(t)
		for _, e := range events {
			// The org's genesis org.create event is written by the PA by design.
			if actor, _ := e["actor"].(map[string]any); actor["id"] == paID && e["action"] != "org.create" {
				t.Errorf("platform admin event leaked into org chain: %v", e)
			}
		}
	})

	t.Run("denials_audited_to_actor_chain_without_existence", func(t *testing.T) {
		// Org B owner probes org A's real project and a nonexistent one.
		w.c(w.OwnerB).Do(t, "GET", "/projects/api/envs/dev/secrets/API_KEY", nil)
		w.c(w.OwnerB).Do(t, "GET", "/projects/zzz-nonexistent/envs/dev/secrets/API_KEY", nil)
		var bEvents []map[string]any
		w.c(w.OwnerB).Must(t, 200, "GET", "/audit?action=authz.denied&limit=1000", nil).JSON(t, &bEvents)
		var real, fake map[string]any
		for _, e := range bEvents {
			switch e["target"] {
			case "GET /projects/{p}/envs/{e}/secrets/{key} p=api e=dev key=API_KEY":
				real = e
			case "GET /projects/{p}/envs/{e}/secrets/{key} p=zzz-nonexistent e=dev key=API_KEY":
				fake = e
			}
		}
		if real == nil || fake == nil {
			t.Fatalf("denials missing from actor chain: %v", bEvents)
		}
		if fmt.Sprint(real["details"]) != fmt.Sprint(fake["details"]) || real["result"] != "denied" || fake["result"] != "denied" {
			t.Errorf("denials distinguishable: %v vs %v", real, fake)
		}
		// Org A's chain has no trace of org B's probe.
		var aEvents []map[string]any
		w.c(w.OwnerA).Must(t, 200, "GET", "/audit?limit=1000", nil).JSON(t, &aEvents)
		for _, e := range aEvents {
			if e["actor"].(map[string]any)["id"] == w.OwnerBID {
				t.Errorf("org B event in org A chain: %v", e)
			}
		}
		// Both chains verify.
		for _, tok := range []string{w.OwnerA, w.OwnerB} {
			v := w.c(tok).Must(t, 200, "GET", "/audit/verify", nil).Map(t)
			if v["valid"] != true {
				t.Errorf("chain invalid: %v", v)
			}
		}
	})
}

func (w *world) mustPAID(t *testing.T) string {
	t.Helper()
	return w.c(w.PA).Must(t, 200, "GET", "/me", nil).Map(t)["id"].(string)
}

func TestAuthzProtectedAndTwoPerson(t *testing.T) {
	w := newWorld(t)
	prod := "/projects/web/envs/prod/secrets/DB_URL"
	getProd := func() string {
		return w.c(w.OwnerA).Must(t, 200, "GET", prod, nil).Map(t)["value"].(string)
	}

	// Rule 8: every write path by everyone allowed to write returns 202 and
	// changes nothing.
	ids := map[string]string{}
	for _, who := range []struct{ name, tok string }{{"owner", w.OwnerA}, {"admin", w.AdminA}, {"writer", w.WriterA}, {"st", w.STProdRWA}} {
		r := w.c(who.tok).Must(t, 202, "PUT", prod, map[string]string{"value": "proposed-by-" + who.name})
		m := r.Map(t)
		if m["status"] != "pending" || m["change_id"] == "" {
			t.Fatalf("%s: %v", who.name, m)
		}
		ids[who.name] = m["change_id"].(string)
		w.c(who.tok).Must(t, 202, "DELETE", prod, nil)
		w.c(who.tok).Must(t, 202, "POST", prod+"/rollback", map[string]int{"to": 1})
	}
	if v := getProd(); v != "postgres://acme-prod" {
		t.Fatalf("protected value changed: %q", v)
	}
	// Readers still can't propose.
	w.c(w.ReaderA).Must(t, 403, "PUT", prod, map[string]string{"value": "x"})

	// Rule 9: proposer can't approve.
	w.c(w.AdminA).Must(t, 403, "POST", "/changes/"+ids["admin"]+"/approve", nil)
	w.c(w.OwnerA).Must(t, 403, "POST", "/changes/"+ids["owner"]+"/approve", nil)
	// Via a service token the approver created (STProdRWA was created by admin).
	w.c(w.AdminA).Must(t, 403, "POST", "/changes/"+ids["st"]+"/approve", nil)
	// Members can't approve at all, even others' changes.
	w.c(w.WriterA).Must(t, 403, "POST", "/changes/"+ids["owner"]+"/approve", nil)
	// Writer's change listing shows only their own.
	var mine []map[string]any
	w.c(w.WriterA).Must(t, 200, "GET", "/changes", nil).JSON(t, &mine)
	if len(mine) != 3 {
		t.Errorf("writer sees %d changes, want 3", len(mine))
	}
	for _, c := range mine {
		if c["proposed_by"] != w.WriterAID {
			t.Errorf("writer sees foreign change %v", c)
		}
		if _, ok := c["value"]; ok {
			t.Error("change list includes a value")
		}
	}

	// A different OA approves: applies atomically.
	r := w.c(w.OwnerA).Must(t, 200, "POST", "/changes/"+ids["admin"]+"/approve", nil).Map(t)
	if r["status"] != "approved" || r["version"].(float64) != 2 {
		t.Fatalf("approve: %v", r)
	}
	if v := getProd(); v != "proposed-by-admin" {
		t.Fatalf("after approve: %q", v)
	}
	// Approving again: 409 (not pending).
	w.c(w.OwnerA).Must(t, 409, "POST", "/changes/"+ids["admin"]+"/approve", nil)
	// Others are now stale: 409 and status stale.
	w.c(w.AdminA).Must(t, 409, "POST", "/changes/"+ids["owner"]+"/approve", nil)
	var stale []map[string]any
	w.c(w.OwnerA).Must(t, 200, "GET", "/changes?status=stale", nil).JSON(t, &stale)
	if len(stale) != 1 || stale[0]["id"] != ids["owner"] {
		t.Fatalf("stale list: %v", stale)
	}
	if v := getProd(); v != "proposed-by-admin" {
		t.Fatalf("stale approval changed value: %q", v)
	}
	// Owner (not the ST's creator) can decide the ST's change (stale now).
	w.c(w.OwnerA).Must(t, 409, "POST", "/changes/"+ids["st"]+"/approve", nil)
	// Reject: OA only, proposer allowed, 409 if not pending.
	w.c(w.WriterA).Must(t, 403, "POST", "/changes/"+ids["writer"]+"/reject", nil)
	w.c(w.OwnerA).Must(t, 200, "POST", "/changes/"+ids["writer"]+"/reject", nil)
	w.c(w.OwnerA).Must(t, 409, "POST", "/changes/"+ids["writer"]+"/reject", nil)
	w.c(w.OwnerA).Must(t, 400, "GET", "/changes?status=bogus", nil)

	// Expected-version mismatch on a protected write is 409 immediately.
	w.c(w.OwnerA).Must(t, 409, "PUT", prod, map[string]any{"value": "x", "expected_version": 1})
	r2 := w.c(w.OwnerA).Must(t, 202, "PUT", prod, map[string]any{"value": "x", "expected_version": 2}).Map(t)
	// Delete and rollback through approval.
	w.c(w.AdminA).Must(t, 200, "POST", "/changes/"+r2["change_id"].(string)+"/approve", nil)
	del := w.c(w.WriterA).Must(t, 202, "DELETE", prod, nil).Map(t)
	w.c(w.AdminA).Must(t, 200, "POST", "/changes/"+del["change_id"].(string)+"/approve", nil)
	w.c(w.OwnerA).Must(t, 404, "GET", prod, nil)
	rb := w.c(w.WriterA).Must(t, 202, "POST", prod+"/rollback", map[string]int{"to": 1}).Map(t)
	res := w.c(w.AdminA).Must(t, 200, "POST", "/changes/"+rb["change_id"].(string)+"/approve", nil).Map(t)
	if res["version"].(float64) != 5 {
		t.Errorf("rollback version: %v", res)
	}
	if v := getProd(); v != "postgres://acme-prod" {
		t.Fatalf("after rollback: %q", v)
	}
	// History: version authors are the proposers.
	var hist []map[string]any
	w.c(w.OwnerA).Must(t, 200, "GET", prod+"/versions", nil).JSON(t, &hist)
	if len(hist) != 5 || hist[3]["deleted"] != true || hist[4]["created_by"] != w.WriterAID {
		t.Errorf("history: %v", hist)
	}

	// New key via approval (base_version 0) and stale when the key appears first.
	n1 := w.c(w.WriterA).Must(t, 202, "PUT", "/projects/web/envs/prod/secrets/NEW_KEY", map[string]string{"value": "one"}).Map(t)
	n2 := w.c(w.WriterA).Must(t, 202, "PUT", "/projects/web/envs/prod/secrets/NEW_KEY", map[string]string{"value": "two"}).Map(t)
	w.c(w.AdminA).Must(t, 200, "POST", "/changes/"+n2["change_id"].(string)+"/approve", nil)
	w.c(w.AdminA).Must(t, 409, "POST", "/changes/"+n1["change_id"].(string)+"/approve", nil)
	v := w.c(w.ReaderA).Must(t, 200, "GET", "/projects/web/envs/prod/secrets/NEW_KEY", nil).Map(t)
	if v["value"] != "two" {
		t.Errorf("NEW_KEY = %v", v)
	}
	// Audit chain still verifies after all of that.
	if w.c(w.OwnerA).Must(t, 200, "GET", "/audit/verify", nil).Map(t)["valid"] != true {
		t.Error("audit chain invalid")
	}
	var evs []map[string]any
	w.c(w.OwnerA).Must(t, 200, "GET", "/audit?action=change.stale", nil).JSON(t, &evs)
	if len(evs) < 2 {
		t.Errorf("change.stale events: %d", len(evs))
	}
}

func TestAuthzRevocationIsImmediate(t *testing.T) {
	w := newWorld(t)
	get := "/projects/web/envs/dev/secrets/DB_URL"

	// Token revoked.
	w.c(w.STReadA).Must(t, 200, "GET", get, nil)
	w.c(w.OwnerA).Must(t, 200, "DELETE", "/tokens/"+w.STReadAID, nil)
	w.c(w.STReadA).Must(t, 401, "GET", get, nil)
	w.c(w.OwnerA).Must(t, 200, "DELETE", "/tokens/"+w.STReadAID, nil) // idempotent

	// Grant lowered then revoked.
	w.c(w.ReaderA).Must(t, 200, "GET", get, nil)
	w.c(w.OwnerA).Must(t, 200, "PUT", "/members/"+w.ReaderAID+"/grants/web", map[string]string{"level": "viewer"})
	w.c(w.ReaderA).Must(t, 403, "GET", get, nil)
	w.c(w.ReaderA).Must(t, 200, "GET", "/projects/web/envs/dev/secrets", nil)
	w.c(w.OwnerA).Must(t, 200, "DELETE", "/members/"+w.ReaderAID+"/grants/web", nil)
	w.c(w.ReaderA).Must(t, 404, "GET", "/projects/web/envs/dev/secrets", nil)
	w.c(w.OwnerA).Must(t, 404, "DELETE", "/members/"+w.ReaderAID+"/grants/web", nil)

	// User removed: PAT dead, but service tokens they created keep working.
	stByAdmin := w.STProdRWA
	w.c(w.AdminA).Must(t, 200, "GET", "/me", nil)
	w.c(w.OwnerA).Must(t, 200, "DELETE", "/members/"+w.AdminAID, nil)
	w.c(w.AdminA).Must(t, 401, "GET", "/me", nil)
	w.c(stByAdmin).Must(t, 200, "GET", "/projects/web/envs/prod/secrets/DB_URL", nil)
	w.S.Client("").Must(t, 401, "POST", "/auth/token", map[string]string{"email": "admin@acme.test", "password": pw})

	// Logout revokes the PAT server-side.
	tok := w.S.Login(t, "writer@acme.test", pw)
	w.c(tok).Must(t, 200, "POST", "/auth/logout", nil)
	w.c(tok).Must(t, 401, "GET", "/me", nil)
	w.c(w.WriterA).Must(t, 200, "GET", "/me", nil) // other PATs unaffected

	// Org disabled: every user and token of the org gets 401, other orgs fine.
	w.c(w.PA).Must(t, 200, "POST", "/admin/orgs/acme/disable", nil)
	for _, tok := range []string{w.OwnerA, w.WriterA, w.STRWA, stByAdmin} {
		w.c(tok).Must(t, 401, "GET", "/me", nil)
	}
	w.S.Client("").Must(t, 401, "POST", "/auth/token", map[string]string{"email": "owner@acme.test", "password": pw})
	w.c(w.OwnerB).Must(t, 200, "GET", "/projects", nil)
	w.c(w.STReadB).Must(t, 200, "GET", "/projects/web/envs/dev/secrets/DB_URL", nil)
	w.c(w.PA).Must(t, 200, "POST", "/admin/orgs/acme/disable", nil) // idempotent
	w.c(w.PA).Must(t, 404, "POST", "/admin/orgs/nope/disable", nil)
}

func TestAuthzExpiredToken(t *testing.T) {
	w := newWorld(t)
	// Force-expire the token in the DB (TTL minimum is 60 s).
	if _, err := w.S.DB.Owner.Exec(t.Context(), `UPDATE tokens SET expires_at=now() - interval '1 second' WHERE id=$1`, w.STReadAID); err != nil {
		t.Fatal(err)
	}
	w.c(w.STReadA).Must(t, 401, "GET", "/projects/web/envs/dev/secrets", nil)
}

func TestAuthzNoSelfEscalation(t *testing.T) {
	w := newWorld(t)
	runChecks(t, w, []check{
		{"admin self promote", w.AdminA, "PATCH", "/members/" + w.AdminAID, map[string]string{"role": "owner"}, 403},
		{"admin self demote", w.AdminA, "PATCH", "/members/" + w.AdminAID, map[string]string{"role": "member"}, 403},
		{"admin self no-op", w.AdminA, "PATCH", "/members/" + w.AdminAID, map[string]string{"role": "admin"}, 403},
		{"owner self demote (other owner exists)", w.OwnerA, "PATCH", "/members/" + w.OwnerAID, map[string]string{"role": "admin"}, 403},
		{"owner self remove (other owner exists)", w.OwnerA, "DELETE", "/members/" + w.OwnerAID, nil, 403},
		{"admin self remove", w.AdminA, "DELETE", "/members/" + w.AdminAID, nil, 403},
		{"smuggled org_id", w.OwnerA, "PATCH", "/members/" + w.ViewerAID, map[string]string{"role": "admin", "org_id": w.OrgB}, 400},
		{"smuggled platform role", w.OwnerA, "PATCH", "/members/" + w.ViewerAID, map[string]string{"role": "platform_admin"}, 400},
		{"smuggled fields on create", w.OwnerA, "POST", "/members", map[string]string{"email": "s@acme.test", "role": "member", "password": pw, "org_id": w.OrgB}, 400},
		{"smuggled level on grant", w.OwnerA, "PUT", "/members/" + w.ViewerAID + "/grants/web", map[string]string{"level": "writer", "user_id": w.AdminAID}, 400},
		{"admin role on grant", w.OwnerA, "PUT", "/members/" + w.ViewerAID + "/grants/web", map[string]string{"level": "admin"}, 400},
		{"self grant (admin)", w.AdminA, "PUT", "/members/" + w.AdminAID + "/grants/web", map[string]string{"level": "writer"}, 403},
		{"grant to admin", w.OwnerA, "PUT", "/members/" + w.AdminAID + "/grants/web", map[string]string{"level": "writer"}, 400},
		{"grant unknown user", w.OwnerA, "PUT", "/members/usr_nope/grants/web", map[string]string{"level": "writer"}, 404},
		{"grant unknown project", w.OwnerA, "PUT", "/members/" + w.ViewerAID + "/grants/nope", map[string]string{"level": "writer"}, 404},
		{"PA user not an org member", w.OwnerA, "PATCH", "/members/" + w.mustPAID(t), map[string]string{"role": "member"}, 404},
		{"smuggled field on project", w.OwnerA, "POST", "/projects", map[string]any{"slug": "x1", "org_id": w.OrgB}, 400},
		{"smuggled field on token", w.OwnerA, "POST", "/tokens", map[string]any{"project": "web", "env": "dev", "access": "read", "ttl_seconds": 600, "org_id": w.OrgB}, 400},
		{"smuggled field on secret", w.WriterA, "PUT", "/projects/web/envs/dev/secrets/X", map[string]any{"value": "v", "version": 99}, 400},
		{"smuggled field on login", "", "POST", "/auth/token", map[string]any{"email": "viewer@acme.test", "password": pw, "role": "owner"}, 400},
	})
	// Me still reports the original roles.
	for tok, role := range map[string]string{w.AdminA: "admin", w.ViewerA: "member", w.OwnerA: "owner"} {
		if got := w.c(tok).Must(t, 200, "GET", "/me", nil).Map(t)["role"]; got != role {
			t.Errorf("role changed to %v, want %s", got, role)
		}
	}

	// Owner management by an owner works.
	w.c(w.OwnerA).Must(t, 200, "PATCH", "/members/"+w.ViewerAID, map[string]string{"role": "owner"})
	w.c(w.OwnerA).Must(t, 200, "PATCH", "/members/"+w.ViewerAID, map[string]string{"role": "member"})
	// Promotion to admin dropped the viewer's grant; demotion doesn't resurrect it.
	var projects []map[string]any
	w.c(w.ViewerA).Must(t, 200, "GET", "/projects", nil).JSON(t, &projects)
	if len(projects) != 0 {
		t.Errorf("grant resurrected: %v", projects)
	}
	create(t, w.c(w.OwnerA), "/members", map[string]string{"email": "o3@acme.test", "role": "owner", "password": pw})
}

func TestAuthzLastOwner(t *testing.T) {
	s := testutil.New(t)
	pa := s.Client(s.Login(t, testutil.AdminEmail, testutil.AdminPassword))
	o := create(t, pa, "/admin/orgs", map[string]string{"slug": "solo", "owner_email": "solo@x.test", "owner_password": pw})
	ownerID := o["owner"].(map[string]any)["id"].(string)
	owner := s.Client(s.Login(t, "solo@x.test", pw))

	owner.Must(t, 409, "PATCH", "/members/"+ownerID, map[string]string{"role": "admin"})
	owner.Must(t, 409, "PATCH", "/members/"+ownerID, map[string]string{"role": "member"})
	owner.Must(t, 409, "DELETE", "/members/"+ownerID, nil)
	owner.Must(t, 403, "PATCH", "/members/"+ownerID, map[string]string{"role": "owner"}) // no-op self change is still a self change

	// Add a second owner; now owner1 may demote owner2, but then owner1 is
	// last again.
	o2 := create(t, owner, "/members", map[string]string{"email": "solo2@x.test", "role": "owner", "password": pw})
	o2ID := o2["id"].(string)
	owner2 := s.Client(s.Login(t, "solo2@x.test", pw))
	owner.Must(t, 200, "PATCH", "/members/"+o2ID, map[string]string{"role": "admin"})
	owner.Must(t, 409, "DELETE", "/members/"+ownerID, nil)
	// The (now admin) owner2 can't touch the owner.
	owner2.Must(t, 403, "PATCH", "/members/"+ownerID, map[string]string{"role": "member"})
	owner2.Must(t, 403, "DELETE", "/members/"+ownerID, nil)
	// Promote back, then owner2 removes owner1 (allowed, one remains).
	owner.Must(t, 200, "PATCH", "/members/"+o2ID, map[string]string{"role": "owner"})
	owner2.Must(t, 200, "DELETE", "/members/"+ownerID, nil)
	owner.Must(t, 401, "GET", "/me", nil)
	owner2.Must(t, 409, "DELETE", "/members/"+o2ID, nil)
}

// Concurrent demotions of two owners must never leave zero owners.
func TestAuthzLastOwnerConcurrent(t *testing.T) {
	s := testutil.New(t)
	pa := s.Client(s.Login(t, testutil.AdminEmail, testutil.AdminPassword))
	o := create(t, pa, "/admin/orgs", map[string]string{"slug": "duo", "owner_email": "a@duo.test", "owner_password": pw})
	aID := o["owner"].(map[string]any)["id"].(string)
	a := s.Client(s.Login(t, "a@duo.test", pw))
	bID := create(t, a, "/members", map[string]string{"email": "b@duo.test", "role": "owner", "password": pw})["id"].(string)
	b := s.Client(s.Login(t, "b@duo.test", pw))
	done := make(chan int, 2)
	go func() { done <- a.Do(t, "PATCH", "/members/"+bID, map[string]string{"role": "admin"}).Status }()
	go func() { done <- b.Do(t, "PATCH", "/members/"+aID, map[string]string{"role": "admin"}).Status }()
	s1, s2 := <-done, <-done
	var owners int
	if err := s.DB.Owner.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE role='owner'`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners < 1 {
		t.Fatalf("no owners left (statuses %d %d)", s1, s2)
	}
}
