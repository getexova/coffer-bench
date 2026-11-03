//go:build e2e

package e2e

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"
)

func p95(ds []time.Duration) time.Duration {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[(len(ds)*95+99)/100-1]
}

// TestPerformance is a smoke check of SPEC §5 Performance on the running stack:
// listing 1,000 secrets p95 < 300 ms; 50 concurrent value reads p95 < 200 ms.
func TestPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	o := newOrg(t, "perf")
	o.project(t, "app", map[string]bool{"big": false})
	tok := o.Owner.Token
	keys := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range keys {
				r := api(t, "PUT", secPath("app", "big", fmt.Sprintf("KEY_%04d", i)), tok, map[string]string{"value": "v"})
				if r.Status != 200 {
					t.Errorf("seed %d: %s", i, r)
				}
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		keys <- i
	}
	close(keys)
	wg.Wait()

	var list []time.Duration
	for i := 0; i < 20; i++ {
		start := time.Now()
		r := must(t, 200, api(t, "GET", secPath("app", "big", ""), tok, nil), "list")
		list = append(list, time.Since(start))
		if i == 0 && len(r.arr(t)) != 1000 {
			t.Fatalf("list returned %d secrets, want 1000", len(r.arr(t)))
		}
	}
	if p := p95(list); p > 300*time.Millisecond {
		t.Errorf("listing 1,000 secrets p95 = %v, want < 300ms", p)
	}

	reads := make([]time.Duration, 50)
	var rw sync.WaitGroup
	for i := 0; i < 50; i++ {
		rw.Add(1)
		go func(i int) {
			defer rw.Done()
			start := time.Now()
			r := api(t, "GET", secPath("app", "big", fmt.Sprintf("KEY_%04d", i)), tok, nil)
			reads[i] = time.Since(start)
			if r.Status != 200 {
				t.Errorf("read %d: %s", i, r)
			}
		}(i)
	}
	rw.Wait()
	if p := p95(reads); p > 200*time.Millisecond {
		t.Errorf("50 concurrent reads p95 = %v, want < 200ms", p)
	}
	t.Logf("list p95=%v, concurrent read p95=%v", p95(list), p95(reads))
}
