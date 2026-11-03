// Command perftest measures the two SPEC §5 performance targets against a live
// Coffer server, using only the public /api/v1 surface so it measures what a
// client actually sees.
//
//	go run ./tools/perftest
//
// Environment:
//
//	COFFER_URL       server base URL, e.g. http://127.0.0.1:8420
//	COFFER_EMAIL     an owner of the target organization
//	COFFER_PASSWORD  that user's password
//	COFFER_PROJECT   project slug to use (default "perf")
//	COFFER_ENV_NAME  environment slug to use (default "dev")
//
// Target 1: listing an environment holding 1,000 secrets, p95 under 300 ms.
// Target 2: 50 concurrent value reads, p95 under 200 ms.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

var (
	base  = os.Getenv("COFFER_URL")
	token string
	httpc = &http.Client{Timeout: 60 * time.Second}
)

func call(method, path string, body any) (int, []byte) {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		panic(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpc.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func must(want, got int, what string, body []byte) {
	if got != want {
		fmt.Fprintf(os.Stderr, "FAIL %s: status %d want %d: %s\n", what, got, want, body)
		os.Exit(1)
	}
}

// quantile returns the p-quantile of d, with d sorted in place.
func quantile(d []time.Duration, p float64) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	idx := int(float64(len(d))*p+0.5) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(d) {
		idx = len(d) - 1
	}
	return d[idx]
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if base == "" {
		fmt.Fprintln(os.Stderr, "COFFER_URL is required")
		os.Exit(1)
	}
	project := envOr("COFFER_PROJECT", "perf")
	envName := envOr("COFFER_ENV_NAME", "dev")

	st, body := call("POST", "/api/v1/auth/token", map[string]string{
		"email": os.Getenv("COFFER_EMAIL"), "password": os.Getenv("COFFER_PASSWORD"),
	})
	must(200, st, "login", body)
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		panic(err)
	}
	token = login.Token

	call("POST", "/api/v1/projects", map[string]any{"slug": project})
	st, body = call("POST", "/api/v1/projects/"+project+"/envs",
		map[string]any{"slug": envName, "protected": false})
	if st != 200 && st != 201 && st != 409 {
		fmt.Fprintf(os.Stderr, "create env: %d %s\n", st, body)
		os.Exit(1)
	}

	const n = 1000
	secretPath := "/api/v1/projects/" + project + "/envs/" + envName + "/secrets/"
	fmt.Printf("seeding %d secrets into %s/%s\n", n, project, envName)
	seedStart := time.Now()
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("KEY_%04d", i)
		st, body := call("PUT", secretPath+key, map[string]any{
			"value": fmt.Sprintf("value-%04d-payload", i),
		})
		if st != 200 {
			fmt.Fprintf(os.Stderr, "seed %s: %d %s\n", key, st, body)
			os.Exit(1)
		}
	}
	fmt.Printf("seeded in %s\n", time.Since(seedStart).Round(time.Millisecond))

	const listRuns = 40
	listDur := make([]time.Duration, 0, listRuns)
	var count int
	for i := 0; i < listRuns; i++ {
		t0 := time.Now()
		st, body := call("GET", "/api/v1/projects/"+project+"/envs/"+envName+"/secrets", nil)
		d := time.Since(t0)
		must(200, st, "list", body)
		listDur = append(listDur, d)
		if i == 0 {
			var rows []struct {
				Key string `json:"key"`
			}
			_ = json.Unmarshal(body, &rows)
			count = len(rows)
		}
	}
	fmt.Printf("TARGET1 list_1000_secrets: runs=%d keys_returned=%d p50=%s p95=%s max=%s\n",
		listRuns, count,
		quantile(listDur, 0.50).Round(time.Millisecond),
		quantile(listDur, 0.95).Round(time.Millisecond),
		listDur[len(listDur)-1].Round(time.Millisecond))

	const readers = 50
	readDur := make([]time.Duration, readers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan string, readers)
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("KEY_%04d", (i*17)%n)
			<-start
			t0 := time.Now()
			st, body := call("GET", secretPath+key, nil)
			readDur[i] = time.Since(t0)
			if st != 200 {
				errs <- fmt.Sprintf("%s: %d %s", key, st, body)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		fmt.Fprintf(os.Stderr, "concurrent read failed: %s\n", e)
		os.Exit(1)
	}
	fmt.Printf("TARGET2 concurrent_value_reads: n=%d p50=%s p95=%s max=%s\n",
		readers,
		quantile(readDur, 0.50).Round(time.Millisecond),
		quantile(readDur, 0.95).Round(time.Millisecond),
		readDur[len(readDur)-1].Round(time.Millisecond))
}
