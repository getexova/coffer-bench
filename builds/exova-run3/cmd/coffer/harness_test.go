package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// testServer is a fake Coffer API. No database is required: every route the CLI
// touches is answered from a handler the test supplies.
type testServer struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	handler func(w http.ResponseWriter, r *http.Request)
	// requests records what the CLI sent, so a test can assert on the path,
	// the query and the body without the server having to guess.
	requests []recordedRequest
}

type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Auth   string
	Body   []byte
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	ts := &testServer{t: t}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts.mu.Lock()
		ts.requests = append(ts.requests, recordedRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.RawQuery,
			Auth:   r.Header.Get("Authorization"),
			Body:   body,
		})
		handler := ts.handler
		ts.mu.Unlock()
		if handler == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"not found"}}`))
			return
		}
		handler(w, r)
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

// on installs the handler for subsequent requests.
func (ts *testServer) on(handler func(w http.ResponseWriter, r *http.Request)) {
	ts.mu.Lock()
	ts.handler = handler
	ts.mu.Unlock()
}

// reply is a convenience handler that answers every request the same way.
func (ts *testServer) reply(status int, body string) {
	ts.on(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	})
}

func (ts *testServer) lastRequest() recordedRequest {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.requests) == 0 {
		return recordedRequest{}
	}
	return ts.requests[len(ts.requests)-1]
}

func (ts *testServer) requestCount() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return len(ts.requests)
}

// harness is one CLI invocation against a fake server and a temporary HOME, so
// the config directory is isolated and no test touches the developer's config.
type harness struct {
	t      *testing.T
	server *testServer
	home   string
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	code   int
}

// newHarness prepares an isolated environment. COFFER_TOKEN is unset by default;
// a test that wants stateless mode sets it with withEnv.
func newHarness(t *testing.T) *harness {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("COFFER_URL", "")
	t.Setenv("COFFER_TOKEN", "")
	h := &harness{t: t, server: newTestServer(t), home: home}
	// Point the CLI at the fake server through the documented override, so the
	// URL-precedence tests (--url > COFFER_URL > stored > default) are real.
	t.Setenv("COFFER_URL", h.server.srv.URL)
	return h
}

// withEnv sets an environment variable for this invocation.
func (h *harness) withEnv(key, value string) *harness {
	h.t.Setenv(key, value)
	return h
}

// login seeds the config file with a token, as a successful login would.
func (h *harness) login(token string) *harness {
	h.t.Helper()
	cfg := &cliConfig{URL: h.server.srv.URL, Token: token}
	if err := cfg.save(); err != nil {
		h.t.Fatalf("seeding the config file: %v", err)
	}
	return h
}

// run executes the CLI with args and records stdout, stderr and the exit code.
func (h *harness) run(stdin string, args ...string) *harness {
	h.t.Helper()
	h.stdout = &bytes.Buffer{}
	h.stderr = &bytes.Buffer{}
	c := newCLI(strings.NewReader(stdin), h.stdout, h.stderr)
	// httptest servers are not terminals, but assert it so the "no added
	// newline" behaviour is what the tests actually exercise.
	c.stdoutTTY = func() bool { return false }
	h.code = c.run(args)
	return h
}

// runTTY is run with stdout pretending to be a terminal.
func (h *harness) runTTY(stdin string, args ...string) *harness {
	h.t.Helper()
	h.stdout = &bytes.Buffer{}
	h.stderr = &bytes.Buffer{}
	c := newCLI(strings.NewReader(stdin), h.stdout, h.stderr)
	c.stdoutTTY = func() bool { return true }
	h.code = c.run(args)
	return h
}

// url points the invocation at the fake server.
func (h *harness) url() string { return h.server.srv.URL }

func (h *harness) wantCode(want int) *harness {
	h.t.Helper()
	if h.code != want {
		h.t.Fatalf("exit code = %d, want %d\nstdout: %q\nstderr: %q", h.code, want, h.stdout.String(), h.stderr.String())
	}
	return h
}

func (h *harness) wantStdout(want string) *harness {
	h.t.Helper()
	if got := h.stdout.String(); got != want {
		h.t.Fatalf("stdout = %q, want %q", got, want)
	}
	return h
}

func (h *harness) wantStderrContains(fragment string) *harness {
	h.t.Helper()
	if !strings.Contains(h.stderr.String(), fragment) {
		h.t.Fatalf("stderr = %q, want it to contain %q", h.stderr.String(), fragment)
	}
	return h
}

// jsonDocuments splits stdout into top-level JSON documents and fails if there is
// not exactly one, which is the --json contract of SPEC §7.1.
func (h *harness) oneJSONDocument() map[string]any {
	h.t.Helper()
	h.oneJSONValue()
	var doc map[string]any
	if err := json.Unmarshal([]byte(h.stdout.String()), &doc); err != nil {
		h.t.Fatalf("stdout is a JSON value but not an object: %v\nstdout: %q", err, h.stdout.String())
	}
	return doc
}

// oneJSONValue asserts stdout holds exactly one JSON document of any shape, which
// is the actual --json contract: a top-level array is one document too.
func (h *harness) oneJSONValue() any {
	h.t.Helper()
	dec := json.NewDecoder(strings.NewReader(h.stdout.String()))
	var docs []any
	for {
		var doc any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			h.t.Fatalf("stdout is not valid JSON: %v\nstdout: %q", err, h.stdout.String())
		}
		docs = append(docs, doc)
	}
	if len(docs) != 1 {
		h.t.Fatalf("stdout has %d JSON documents, want exactly 1\nstdout: %q", len(docs), h.stdout.String())
	}
	return docs[0]
}

// configDirPath is the directory the CLI must create with mode 0700.
func configDirPath(t *testing.T, home string) string {
	t.Helper()
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	return filepath.Join(xdg, "coffer")
}

// modeOf returns the permission bits of a path.
func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

// jsonBody is a small helper for handlers that need to echo a value.
func jsonBody(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
