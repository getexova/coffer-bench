package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/coffer-dev/coffer/internal/server/testutil"
)

// asyncResp is the outcome of a request sent from a goroutine.
type asyncResp struct {
	status int
	body   string
	err    error
}

func sendAsync(base, tok, method, path string, body any) <-chan asyncResp {
	ch := make(chan asyncResp, 1)
	go func() {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, base+"/api/v1"+path, rd)
		if err != nil {
			ch <- asyncResp{err: err}
			return
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			ch <- asyncResp{err: err}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		ch <- asyncResp{status: resp.StatusCode, body: string(b)}
	}()
	return ch
}

func await(t *testing.T, name string, ch <-chan asyncResp) asyncResp {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("%s: %v", name, r.err)
		}
		return r
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: timed out", name)
	}
	return asyncResp{}
}

// orgHold holds an org row lock from outside the server, so requests that
// need it queue up behind it in a known order.
type orgHold struct {
	t   *testing.T
	db  *testutil.DB
	tx  pgx.Tx
	pid int
}

func holdOrg(t *testing.T, db *testutil.DB, orgID string) *orgHold {
	t.Helper()
	ctx := context.Background()
	tx, err := db.Owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := &orgHold{t: t, db: db, tx: tx}
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&h.pid); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM orgs WHERE id=$1 FOR UPDATE`, orgID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return h
}

// waitBlocked waits until n other backends of this database wait on a lock.
func (h *orgHold) waitBlocked(n int) {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var got int
		if err := h.db.Owner.QueryRow(context.Background(), `SELECT count(DISTINCT pid) FROM pg_stat_activity
			WHERE datname=current_database() AND pid<>$1 AND wait_event_type='Lock'`, h.pid).Scan(&got); err != nil {
			h.t.Fatal(err)
		}
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("only %d of %d requests blocked on the org lock", got, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (h *orgHold) release() {
	h.t.Helper()
	if err := h.tx.Commit(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

func roleOf(t *testing.T, c *testutil.Client, id string) string {
	t.Helper()
	var ms []map[string]any
	c.Must(t, 200, "GET", "/members", nil).JSON(t, &ms)
	for _, m := range ms {
		if m["id"] == id {
			return m["role"].(string)
		}
	}
	return ""
}

// SPEC §2.2 + §2.11: an owner's demotion that is serialised before the
// owner's own promotion request wins; the demoted user cannot create an
// owner with a PAT authenticated before the demotion.
func TestDemotedOwnerCannotPromoteAfterDemotion(t *testing.T) {
	w := newWorld(t)
	h := holdOrg(t, w.S.DB, w.OrgA)
	demote := sendAsync(w.S.URL, w.OwnerA, "PATCH", "/members/"+w.Owner2AID, map[string]string{"role": "member"})
	h.waitBlocked(1)
	promote := sendAsync(w.S.URL, w.Owner2A, "PATCH", "/members/"+w.NoGrAID, map[string]string{"role": "owner"})
	addOwner := sendAsync(w.S.URL, w.Owner2A, "POST", "/members", map[string]string{"email": "late-owner@acme.test", "role": "owner", "password": pw})
	h.waitBlocked(3)
	h.release()
	if r := await(t, "demote", demote); r.status != 200 {
		t.Fatalf("demote: %d %s", r.status, r.body)
	}
	if r := await(t, "promote", promote); r.status != 403 {
		t.Errorf("promote after demotion: %d %s, want 403", r.status, r.body)
	}
	if r := await(t, "add owner", addOwner); r.status != 403 {
		t.Errorf("add owner after demotion: %d %s, want 403", r.status, r.body)
	}
	oa := w.c(w.OwnerA)
	if got := roleOf(t, oa, w.NoGrAID); got != "member" {
		t.Errorf("target role = %q, want member", got)
	}
	var ms []map[string]any
	oa.Must(t, 200, "GET", "/members", nil).JSON(t, &ms)
	for _, m := range ms {
		if m["email"] == "late-owner@acme.test" {
			t.Errorf("owner created by a demoted user: %v", m)
		}
	}
}

// SPEC §2.11: a removal serialised before the removed admin's request makes
// that request unauthenticated.
func TestRemovedAdminRequestAfterRemoval(t *testing.T) {
	w := newWorld(t)
	h := holdOrg(t, w.S.DB, w.OrgA)
	remove := sendAsync(w.S.URL, w.OwnerA, "DELETE", "/members/"+w.AdminAID, nil)
	h.waitBlocked(1)
	grant := sendAsync(w.S.URL, w.AdminA, "PUT", "/members/"+w.NoGrAID+"/grants/web", map[string]string{"level": "writer"})
	tok := sendAsync(w.S.URL, w.AdminA, "POST", "/tokens", map[string]any{"project": "web", "env": "dev", "access": "read", "ttl_seconds": 3600})
	h.waitBlocked(3)
	h.release()
	if r := await(t, "remove", remove); r.status != 200 {
		t.Fatalf("remove: %d %s", r.status, r.body)
	}
	if r := await(t, "grant", grant); r.status != 401 {
		t.Errorf("grant by removed admin: %d %s, want 401", r.status, r.body)
	}
	if r := await(t, "token", tok); r.status != 401 {
		t.Errorf("token issued by removed admin: %d %s, want 401", r.status, r.body)
	}
	if r := w.c(w.NoGrantA).Do(t, "GET", "/projects/web/envs", nil); r.Status != 404 {
		t.Errorf("grant applied: %d %s", r.Status, r.Body)
	}
}

// SPEC §2.3/§2.9/§2.11: an approver demoted to member before the approval is
// serialised cannot approve; the change stays pending.
func TestDemotedApproverCannotApprove(t *testing.T) {
	w := newWorld(t)
	oa := w.c(w.OwnerA)
	r := w.c(w.WriterA).Must(t, 202, "PUT", "/projects/web/envs/prod/secrets/DB_URL", map[string]string{"value": "evil"})
	chg := r.Map(t)["change_id"].(string)

	h := holdOrg(t, w.S.DB, w.OrgA)
	demote := sendAsync(w.S.URL, w.OwnerA, "PATCH", "/members/"+w.AdminAID, map[string]string{"role": "member"})
	h.waitBlocked(1)
	approve := sendAsync(w.S.URL, w.AdminA, "POST", "/changes/"+chg+"/approve", nil)
	h.waitBlocked(2)
	h.release()
	if r := await(t, "demote", demote); r.status != 200 {
		t.Fatalf("demote: %d %s", r.status, r.body)
	}
	if r := await(t, "approve", approve); r.status != 403 {
		t.Errorf("approve by demoted admin: %d %s, want 403", r.status, r.body)
	}
	if v := oa.Must(t, 200, "GET", "/projects/web/envs/prod/secrets/DB_URL", nil).Map(t)["value"]; v != "postgres://acme-prod" {
		t.Errorf("protected value = %v", v)
	}
	var pending []map[string]any
	oa.Must(t, 200, "GET", "/changes?status=pending", nil).JSON(t, &pending)
	found := false
	for _, c := range pending {
		found = found || c["id"] == chg
	}
	if !found {
		t.Error("change no longer pending")
	}
}

// SPEC §2.11 (R2-S3): a grant revoke or lowering serialised before the
// approval makes the proposer's change stale, even though the approval's
// proposer check runs while the revoke is in flight.
func TestApproveAfterConcurrentGrantChange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		body   any
	}{
		{"revoke", "DELETE", nil},
		{"lower", "PUT", map[string]string{"level": "viewer"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			oa := w.c(w.OwnerA)
			r := w.c(w.WriterA).Must(t, 202, "PUT", "/projects/web/envs/prod/secrets/DB_URL", map[string]string{"value": "evil"})
			chg := r.Map(t)["change_id"].(string)

			h := holdOrg(t, w.S.DB, w.OrgA)
			change := sendAsync(w.S.URL, w.OwnerA, tc.method, "/members/"+w.WriterAID+"/grants/web", tc.body)
			h.waitBlocked(1)
			approve := sendAsync(w.S.URL, w.AdminA, "POST", "/changes/"+chg+"/approve", nil)
			h.waitBlocked(2)
			h.release()
			if r := await(t, "grant change", change); r.status != 200 {
				t.Fatalf("grant change: %d %s", r.status, r.body)
			}
			if r := await(t, "approve", approve); r.status != 409 {
				t.Errorf("approve after grant change: %d %s, want 409", r.status, r.body)
			}
			if v := oa.Must(t, 200, "GET", "/projects/web/envs/prod/secrets/DB_URL", nil).Map(t)["value"]; v != "postgres://acme-prod" {
				t.Errorf("protected value = %v", v)
			}
		})
	}
}

// SPEC §2.11: a secret write serialised after a grant revoke is judged
// against the revoked grant.
func TestWriteAfterConcurrentGrantRevoke(t *testing.T) {
	w := newWorld(t)
	h := holdOrg(t, w.S.DB, w.OrgA)
	revoke := sendAsync(w.S.URL, w.OwnerA, "DELETE", "/members/"+w.WriterAID+"/grants/web", nil)
	h.waitBlocked(1)
	write := sendAsync(w.S.URL, w.WriterA, "PUT", "/projects/web/envs/dev/secrets/DB_URL", map[string]string{"value": "evil"})
	propose := sendAsync(w.S.URL, w.WriterA, "PUT", "/projects/web/envs/prod/secrets/DB_URL", map[string]string{"value": "evil"})
	h.waitBlocked(3)
	h.release()
	if r := await(t, "revoke", revoke); r.status != 200 {
		t.Fatalf("revoke: %d %s", r.status, r.body)
	}
	if r := await(t, "write", write); r.status != 404 {
		t.Errorf("write after revoke: %d %s, want 404", r.status, r.body)
	}
	if r := await(t, "propose", propose); r.status != 404 {
		t.Errorf("proposal after revoke: %d %s, want 404", r.status, r.body)
	}
	if v := w.c(w.OwnerA).Must(t, 200, "GET", "/projects/web/envs/dev/secrets/DB_URL", nil).Map(t)["value"]; v != "postgres://acme-dev" {
		t.Errorf("value = %v", v)
	}
}

// SPEC §2.11: an org disabled while a write waits for it is honoured.
func TestWriteAfterConcurrentOrgDisable(t *testing.T) {
	w := newWorld(t)
	h := holdOrg(t, w.S.DB, w.OrgA)
	disable := sendAsync(w.S.URL, w.PA, "POST", "/admin/orgs/acme/disable", nil)
	h.waitBlocked(1)
	write := sendAsync(w.S.URL, w.STRWA, "PUT", "/projects/web/envs/dev/secrets/DB_URL", map[string]string{"value": "evil"})
	h.waitBlocked(2)
	h.release()
	if r := await(t, "disable", disable); r.status != 200 {
		t.Fatalf("disable: %d %s", r.status, r.body)
	}
	if r := await(t, "write", write); r.status != 401 {
		t.Errorf("write after disable: %d %s, want 401", r.status, r.body)
	}
	var v int
	if err := w.S.DB.Owner.QueryRow(context.Background(), `SELECT max(version) FROM secret_versions v JOIN environments e ON e.id=v.env_id
		JOIN projects p ON p.id=e.project_id WHERE p.org_id=$1 AND v.key='DB_URL' AND e.slug='dev' AND p.slug='web'`, w.OrgA).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Errorf("DB_URL version = %d, want 1", v)
	}
}
