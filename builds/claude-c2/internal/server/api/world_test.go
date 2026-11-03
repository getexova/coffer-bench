package api_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/coffer-dev/coffer/internal/server/testutil"
)

const pw = "correct-horse-battery"

// world is a two-org fixture covering every principal kind in SPEC §2.
type world struct {
	S *testutil.Server

	PA string // platform admin PAT

	// Org A ("acme").
	OrgA, OrgB                               string // org ids
	OwnerA, Owner2A, AdminA                  string // PATs
	ViewerA, ReaderA, WriterA, NoGrantA      string // member PATs
	OwnerAID, Owner2AID, AdminAID            string // user ids
	ViewerAID, ReaderAID, WriterAID, NoGrAID string
	STReadA, STRWA, STProdRWA                string // service tokens (web/dev, web/dev, web/prod)
	STReadAID, STProdRWAID                   string
	// Org B ("globex").
	OwnerB, OwnerBID, STReadB string
}

func (w *world) c(tok string) *testutil.Client { return w.S.Client(tok) }

func create(t *testing.T, c *testutil.Client, path string, body any) map[string]any {
	t.Helper()
	return c.Must(t, http.StatusCreated, "POST", path, body).Map(t)
}

func (w *world) addMember(t *testing.T, owner, email, role string) (string, string) {
	t.Helper()
	m := create(t, w.c(owner), "/members", map[string]string{"email": email, "role": role, "password": pw})
	return m["id"].(string), w.S.Login(t, email, pw)
}

func (w *world) token(t *testing.T, owner, project, env, access string) (string, string) {
	t.Helper()
	m := create(t, w.c(owner), "/tokens", map[string]any{"project": project, "env": env, "access": access, "ttl_seconds": 3600})
	return m["token"].(string), m["id"].(string)
}

func setSecret(t *testing.T, c *testutil.Client, p, e, key, value string) {
	t.Helper()
	c.Must(t, 200, "PUT", fmt.Sprintf("/projects/%s/envs/%s/secrets/%s", p, e, key), map[string]string{"value": value})
}

// newWorld builds:
//
//	org acme: owner, owner2, admin, viewer/reader/writer members on "web",
//	          a member with no grant; projects web (dev, prod[protected]) and
//	          api (dev); secrets web/dev/DB_URL, web/prod/DB_URL, api/dev/API_KEY;
//	          service tokens web/dev read, web/dev read-write, web/prod read-write.
//	org globex: owner, project web (dev) with secret DB_URL, project
//	            globex-only (dev) with secret SECRET, a web/dev read token.
func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{S: testutil.New(t)}
	w.PA = w.S.Login(t, testutil.AdminEmail, testutil.AdminPassword)
	pa := w.c(w.PA)

	a := create(t, pa, "/admin/orgs", map[string]string{"slug": "acme", "owner_email": "owner@acme.test", "owner_password": pw})
	w.OrgA = a["id"].(string)
	w.OwnerAID = a["owner"].(map[string]any)["id"].(string)
	b := create(t, pa, "/admin/orgs", map[string]string{"slug": "globex", "owner_email": "owner@globex.test", "owner_password": pw})
	w.OrgB = b["id"].(string)
	w.OwnerBID = b["owner"].(map[string]any)["id"].(string)

	w.OwnerA = w.S.Login(t, "owner@acme.test", pw)
	w.OwnerB = w.S.Login(t, "owner@globex.test", pw)

	w.Owner2AID, w.Owner2A = w.addMember(t, w.OwnerA, "owner2@acme.test", "owner")
	w.AdminAID, w.AdminA = w.addMember(t, w.OwnerA, "admin@acme.test", "admin")
	w.ViewerAID, w.ViewerA = w.addMember(t, w.OwnerA, "viewer@acme.test", "member")
	w.ReaderAID, w.ReaderA = w.addMember(t, w.OwnerA, "reader@acme.test", "member")
	w.WriterAID, w.WriterA = w.addMember(t, w.OwnerA, "writer@acme.test", "member")
	w.NoGrAID, w.NoGrantA = w.addMember(t, w.OwnerA, "nogrant@acme.test", "member")

	oa := w.c(w.OwnerA)
	create(t, oa, "/projects", map[string]string{"slug": "web"})
	create(t, oa, "/projects", map[string]string{"slug": "api"})
	create(t, oa, "/projects/web/envs", map[string]any{"slug": "dev"})
	create(t, oa, "/projects/web/envs", map[string]any{"slug": "prod", "protected": true})
	create(t, oa, "/projects/api/envs", map[string]any{"slug": "dev"})
	for id, lvl := range map[string]string{w.ViewerAID: "viewer", w.ReaderAID: "reader", w.WriterAID: "writer"} {
		oa.Must(t, 200, "PUT", "/members/"+id+"/grants/web", map[string]string{"level": lvl})
	}
	setSecret(t, oa, "web", "dev", "DB_URL", "postgres://acme-dev")
	setSecret(t, oa, "api", "dev", "API_KEY", "acme-api-key")
	// Seed prod directly: protected, so go through a change request.
	r := oa.Must(t, 202, "PUT", "/projects/web/envs/prod/secrets/DB_URL", map[string]string{"value": "postgres://acme-prod"})
	chg := r.Map(t)["change_id"].(string)
	w.c(w.AdminA).Must(t, 200, "POST", "/changes/"+chg+"/approve", nil)

	w.STReadA, w.STReadAID = w.token(t, w.OwnerA, "web", "dev", "read")
	w.STRWA, _ = w.token(t, w.OwnerA, "web", "dev", "read-write")
	w.STProdRWA, w.STProdRWAID = w.token(t, w.AdminA, "web", "prod", "read-write")

	ob := w.c(w.OwnerB)
	create(t, ob, "/projects", map[string]string{"slug": "web"})
	create(t, ob, "/projects/web/envs", map[string]any{"slug": "dev"})
	setSecret(t, ob, "web", "dev", "DB_URL", "postgres://globex-dev")
	create(t, ob, "/projects", map[string]string{"slug": "globex-only"})
	create(t, ob, "/projects/globex-only/envs", map[string]any{"slug": "dev"})
	setSecret(t, ob, "globex-only", "dev", "SECRET", "globex-secret")
	w.STReadB, _ = w.token(t, w.OwnerB, "web", "dev", "read")
	return w
}

// check asserts the status of one request.
type check struct {
	name   string
	tok    string
	method string
	path   string
	body   any
	want   int
}

func runChecks(t *testing.T, w *world, checks []check) {
	t.Helper()
	for _, c := range checks {
		r := w.c(c.tok).Do(t, c.method, c.path, c.body)
		if r.Status != c.want {
			t.Errorf("%s: %s %s => %d, want %d (%s)", c.name, c.method, c.path, r.Status, c.want, r.Body)
		}
	}
}

const notFoundBody = `{"error":{"code":"not_found","message":"not found"}}`
const forbiddenBody = `{"error":{"code":"forbidden","message":"forbidden"}}`
