package api_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The re-validation locks (org row, token rows, grants) must not introduce
// deadlocks: a mixed concurrent workload of membership changes, grant
// changes, approvals, writes, proposals and token issue/revoke never
// answers 500.
func TestStalePrincipalLocksNoDeadlock(t *testing.T) {
	w := newWorld(t)
	type op struct {
		tok, method, path string
		body              any
	}
	var props []string
	for i := 0; i < 20; i++ {
		tok := w.WriterA
		if i%2 == 0 {
			tok = w.Owner2A
		}
		r := w.c(tok).Must(t, 202, "PUT", fmt.Sprintf("/projects/web/envs/prod/secrets/P%d", i), map[string]string{"value": "v"})
		props = append(props, r.Map(t)["change_id"].(string))
	}
	ops := []op{}
	for i := 0; i < 20; i++ {
		ops = append(ops,
			op{w.OwnerA, "PATCH", "/members/" + w.Owner2AID, map[string]string{"role": []string{"admin", "owner", "member"}[i%3]}},
			op{w.OwnerA, "PATCH", "/members/" + w.AdminAID, map[string]string{"role": []string{"member", "admin"}[i%2]}},
			op{w.Owner2A, "PATCH", "/members/" + w.NoGrAID, map[string]string{"role": []string{"admin", "member"}[i%2]}},
			op{w.AdminA, "PUT", "/members/" + w.WriterAID + "/grants/web", map[string]string{"level": []string{"viewer", "writer"}[i%2]}},
			op{w.Owner2A, "DELETE", "/members/" + w.WriterAID + "/grants/web", nil},
			op{w.OwnerA, "POST", "/changes/" + props[i] + "/approve", nil},
			op{w.AdminA, "POST", "/changes/" + props[(i+7)%20] + "/approve", nil},
			op{w.WriterA, "PUT", "/projects/web/envs/dev/secrets/W", map[string]string{"value": fmt.Sprint(i)}},
			op{w.WriterA, "PUT", "/projects/web/envs/prod/secrets/W", map[string]string{"value": fmt.Sprint(i)}},
			op{w.STRWA, "PUT", "/projects/web/envs/dev/secrets/S", map[string]string{"value": fmt.Sprint(i)}},
			op{w.AdminA, "POST", "/tokens", map[string]any{"project": "web", "env": "dev", "access": "read", "ttl_seconds": 600}},
			op{w.Owner2A, "POST", "/projects/web/envs", map[string]any{"slug": fmt.Sprintf("e%d", i)}},
		)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var bad []string
	sem := make(chan struct{}, 24)
	for _, o := range ops {
		wg.Add(1)
		sem <- struct{}{}
		go func(o op) {
			defer wg.Done()
			defer func() { <-sem }()
			r := <-sendAsync(w.S.URL, o.tok, o.method, o.path, o.body)
			if r.err != nil || r.status >= 500 {
				mu.Lock()
				bad = append(bad, fmt.Sprintf("%s %s: %d %v %s", o.method, o.path, r.status, r.err, r.body))
				mu.Unlock()
			}
		}(o)
	}
	wg.Wait()
	if len(bad) > 0 {
		t.Errorf("%d server errors:\n%s", len(bad), strings.Join(bad, "\n"))
	}
	if strings.Contains(w.S.LogText(), "deadlock") {
		t.Error("deadlock in server log")
	}
	if v := w.c(w.OwnerA).Must(t, 200, "GET", "/audit/verify", nil).Map(t)["valid"]; v != true {
		t.Fatal("chain invalid")
	}
}
