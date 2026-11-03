package api_test

import (
	"testing"
)

// SPEC §3 Value exits are audited, §4 result "failed": a ciphertext copied
// into another row fails to decrypt, returns no value, and is audited as a
// failed event on every exit path.
func TestDecryptionFailureAudited(t *testing.T) {
	s, o := simple(t)
	ctx := t.Context()
	setSecretTo := func(key, v string) { o.Must(t, 200, "PUT", sp+key, map[string]string{"value": v}) }
	setSecretTo("MARK_A", "a1")
	setSecretTo("MARK_A", "a2")
	setSecretTo("MARK_B", "b1")
	if _, err := s.DB.Owner.Exec(ctx, `UPDATE secret_versions SET ciphertext=(SELECT ciphertext FROM secret_versions WHERE key='MARK_B' AND version=1)
		WHERE key='MARK_A' AND version=2`); err != nil {
		t.Fatal(err)
	}
	failedCount := func(action string) int {
		var n int
		s.DB.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action=$1 AND result='failed' AND details->>'reason'='integrity'`, action).Scan(&n)
		return n
	}
	for _, c := range []struct{ method, path string }{
		{"GET", sp + "MARK_A"},
		{"GET", sp + "MARK_A/versions/2"},
		{"GET", "/projects/app/envs/dev/export?format=json"},
	} {
		r := o.Do(t, c.method, c.path, nil)
		if r.Status != 500 || len(r.Body) > 200 {
			t.Errorf("%s %s: %d %s", c.method, c.path, r.Status, r.Body)
		}
	}
	if n := failedCount("secret.read"); n != 3 {
		t.Errorf("failed secret.read events = %d, want 3", n)
	}
	// Rollback to the tampered version.
	setSecretTo("MARK_A", "a3")
	if r := o.Do(t, "POST", sp+"MARK_A/rollback", map[string]int{"to": 2}); r.Status != 500 {
		t.Errorf("rollback: %d %s", r.Status, r.Body)
	}
	if n := failedCount("secret.rollback"); n != 1 {
		t.Errorf("failed secret.rollback events = %d, want 1", n)
	}
	// Approve of a change whose ciphertext was swapped.
	o.Must(t, 201, "POST", "/projects/app/envs", map[string]any{"slug": "prod", "protected": true})
	pp := "/projects/app/envs/prod/secrets/"
	c1 := o.Must(t, 202, "PUT", pp+"P1", map[string]string{"value": "p1"}).Map(t)["change_id"].(string)
	c2 := o.Must(t, 202, "PUT", pp+"P2", map[string]string{"value": "p2"}).Map(t)["change_id"].(string)
	if _, err := s.DB.Owner.Exec(ctx, `UPDATE change_requests SET ciphertext=(SELECT ciphertext FROM change_requests WHERE id=$2) WHERE id=$1`, c1, c2); err != nil {
		t.Fatal(err)
	}
	create(t, o, "/members", map[string]string{"email": "adm@org.test", "role": "admin", "password": pw})
	adm := s.Client(s.Login(t, "adm@org.test", pw))
	if r := adm.Do(t, "POST", "/changes/"+c1+"/approve", nil); r.Status != 500 {
		t.Errorf("approve tampered: %d %s", r.Status, r.Body)
	}
	if n := failedCount("change.approve"); n != 1 {
		t.Errorf("failed change.approve events = %d, want 1", n)
	}
	adm.Must(t, 200, "POST", "/changes/"+c2+"/approve", nil)
	if v := o.Must(t, 200, "GET", "/audit/verify", nil).Map(t)["valid"]; v != true {
		t.Fatal("chain invalid")
	}
}
