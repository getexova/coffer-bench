package api_test

import (
	"testing"
)

// SPEC §2.11 + §2.4/§2.7: a pending change is never applied on behalf of a
// proposer who lost write access in the meantime; approval marks it stale
// (409) and audits change.stale with reason proposer_unauthorized.
func TestApproveRechecksProposer(t *testing.T) {
	w := newWorld(t)
	oa := w.c(w.OwnerA)
	admin := w.c(w.AdminA)
	const prod = "/projects/web/envs/prod/secrets/"

	propose := func(tok, key string) string {
		t.Helper()
		r := w.c(tok).Must(t, 202, "PUT", prod+key, map[string]string{"value": "x-" + key})
		return r.Map(t)["change_id"].(string)
	}
	expectStale := func(name, chg, key string) {
		t.Helper()
		r := admin.Do(t, "POST", "/changes/"+chg+"/approve", nil)
		if r.Status != 409 {
			t.Fatalf("%s: approve => %d %s, want 409", name, r.Status, r.Body)
		}
		var list []map[string]any
		admin.Must(t, 200, "GET", "/changes?status=stale", nil).JSON(t, &list)
		found := false
		for _, c := range list {
			if c["id"] == chg {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: change %s not stale", name, chg)
		}
		if r := oa.Do(t, "GET", prod+key, nil); r.Status != 404 {
			t.Errorf("%s: value applied: %d %s", name, r.Status, r.Body)
		}
		// Retrying is a plain conflict (no longer pending).
		admin.Must(t, 409, "POST", "/changes/"+chg+"/approve", nil)
	}

	// Writer lowered to viewer.
	c1 := propose(w.WriterA, "LOWERED")
	oa.Must(t, 200, "PUT", "/members/"+w.WriterAID+"/grants/web", map[string]string{"level": "viewer"})
	expectStale("grant lowered", c1, "LOWERED")

	// Writer grant revoked.
	oa.Must(t, 200, "PUT", "/members/"+w.WriterAID+"/grants/web", map[string]string{"level": "writer"})
	c2 := propose(w.WriterA, "REVOKED")
	oa.Must(t, 200, "DELETE", "/members/"+w.WriterAID+"/grants/web", nil)
	expectStale("grant revoked", c2, "REVOKED")

	// Member removed.
	oa.Must(t, 200, "PUT", "/members/"+w.WriterAID+"/grants/web", map[string]string{"level": "writer"})
	c3 := propose(w.WriterA, "REMOVED")
	oa.Must(t, 200, "DELETE", "/members/"+w.WriterAID, nil)
	expectStale("member removed", c3, "REMOVED")

	// Read-write service token revoked.
	st, stID := w.token(t, w.OwnerA, "web", "prod", "read-write")
	c4 := propose(st, "TOKREVOKED")
	oa.Must(t, 200, "DELETE", "/tokens/"+stID, nil)
	expectStale("token revoked", c4, "TOKREVOKED")

	// Admin demoted to member without a grant.
	c5 := propose(w.Owner2A, "DEMOTED")
	oa.Must(t, 200, "PATCH", "/members/"+w.Owner2AID, map[string]string{"role": "member"})
	expectStale("owner demoted", c5, "DEMOTED")

	// Control: a proposer who keeps access still gets applied.
	c6 := propose(w.OwnerA, "STILLOK")
	admin.Must(t, 200, "POST", "/changes/"+c6+"/approve", nil)
	if got := oa.Must(t, 200, "GET", prod+"STILLOK", nil).Map(t)["value"]; got != "x-STILLOK" {
		t.Fatalf("control value %v", got)
	}

	var events []map[string]any
	oa.Must(t, 200, "GET", "/audit?action=change.stale&limit=100", nil).JSON(t, &events)
	n := 0
	for _, e := range events {
		if d, _ := e["details"].(map[string]any); d != nil && d["reason"] == "proposer_unauthorized" {
			n++
		}
	}
	if n != 5 {
		t.Errorf("change.stale proposer_unauthorized events: %d, want 5 (%v)", n, events)
	}
	if v := oa.Must(t, 200, "GET", "/audit/verify", nil).Map(t)["valid"]; v != true {
		t.Fatal("chain invalid")
	}
}
