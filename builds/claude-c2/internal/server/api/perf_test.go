package api_test

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/coffer-dev/coffer/internal/server/testutil"
)

func p95(ds []time.Duration) time.Duration {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[(len(ds)*95+99)/100-1]
}

// SPEC §5: list of 1,000 secrets p95 < 300 ms; 50 concurrent value reads
// p95 < 200 ms. Timing assertions are skipped under -race and -short.
func TestPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	_, o := simple(t)
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			o.Must(t, 200, "PUT", fmt.Sprintf("%sKEY_%04d", sp, i), map[string]string{"value": fmt.Sprintf("value-%d-%0100d", i, i)})
		}(i)
	}
	wg.Wait()

	var list []time.Duration
	for i := 0; i < 40; i++ {
		start := time.Now()
		r := o.Must(t, 200, "GET", "/projects/app/envs/dev/secrets", nil)
		list = append(list, time.Since(start))
		if i == 0 {
			var items []map[string]any
			r.JSON(t, &items)
			if len(items) != 1000 {
				t.Fatalf("list has %d items", len(items))
			}
		}
	}
	listP95 := p95(list)

	var mu sync.Mutex
	var reads []time.Duration
	for round := 0; round < 4; round++ {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				t0 := time.Now()
				o.Must(t, 200, "GET", fmt.Sprintf("%sKEY_%04d", sp, (i*37+round)%1000), nil)
				d := time.Since(t0)
				mu.Lock()
				reads = append(reads, d)
				mu.Unlock()
			}(i)
		}
		close(start)
		wg.Wait()
	}
	readP95 := p95(reads)
	t.Logf("list(1000) p95=%v, 50 concurrent reads p95=%v (race=%v)", listP95, readP95, testutil.Race)
	if testutil.Race {
		return
	}
	if listP95 > 300*time.Millisecond {
		t.Errorf("list p95 %v >= 300ms", listP95)
	}
	if readP95 > 200*time.Millisecond {
		t.Errorf("concurrent read p95 %v >= 200ms", readP95)
	}
}
