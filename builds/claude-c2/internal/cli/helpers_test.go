package cli

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

const testToken = "cof_pat_TESTTOKENtesttokenTESTTOKENtesttoken0"

type recorded struct {
	Method     string
	Path       string // decoded path
	RequestURI string // raw request URI as sent
	Query      string
	Auth       string
	CType      string
	Body       []byte
}

type fakeServer struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex
	got []recorded
	h   func(w http.ResponseWriter, r *http.Request, body []byte)
}

func newFake(t *testing.T, h func(w http.ResponseWriter, r *http.Request, body []byte)) *fakeServer {
	t.Helper()
	f := &fakeServer{t: t, h: h}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.got = append(f.got, recorded{
			Method: r.Method, Path: r.URL.Path, RequestURI: r.RequestURI, Query: r.URL.RawQuery,
			Auth: r.Header.Get("Authorization"), CType: r.Header.Get("Content-Type"), Body: body,
		})
		f.mu.Unlock()
		f.h(w, r, body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) reqs() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.got...)
}

func (f *fakeServer) last() recorded {
	r := f.reqs()
	if len(r) == 0 {
		f.t.Fatalf("no request received")
	}
	return r[len(r)-1]
}

func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func rawReply(status int, ctype, body string) func(http.ResponseWriter, *http.Request, []byte) {
	return func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func errReply(status int, code, msg string) func(http.ResponseWriter, *http.Request, []byte) {
	return func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		jsonReply(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
	}
}

// harness runs the CLI in-process.
type harness struct {
	env      map[string]string
	stdin    io.Reader
	ttyOut   bool
	ttyIn    bool
	environ  []string
	stdout   io.Writer // optional override
	cfgDir   string
	fakeBase string
}

func newHarness(t *testing.T, base string) *harness {
	t.Helper()
	x := t.TempDir()
	return &harness{
		env: map[string]string{
			"COFFER_URL":      base,
			"COFFER_TOKEN":    testToken,
			"XDG_CONFIG_HOME": x,
			"HOME":            t.TempDir(),
		},
		cfgDir:   filepath.Join(x, "coffer"),
		fakeBase: base,
	}
}

func (h *harness) run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	a := &App{
		Stdin:       h.stdin,
		Stdout:      &out,
		Stderr:      &errb,
		LookupEnv:   func(k string) (string, bool) { v, ok := h.env[k]; return v, ok },
		Environ:     func() []string { return h.environ },
		StdoutIsTTY: func() bool { return h.ttyOut },
		StdinIsTTY:  func() bool { return h.ttyIn },
	}
	if h.stdout != nil {
		a.Stdout = h.stdout
	}
	if a.Stdin == nil {
		a.Stdin = strings.NewReader("")
	}
	code := a.Run(args)
	return code, out.String(), errb.String()
}

func mustExit(t *testing.T, want, got int, stderr string) {
	t.Helper()
	if want != got {
		t.Fatalf("exit code = %d, want %d (stderr: %q)", got, want, stderr)
	}
}

func fileMode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return fi.Mode().Perm()
}
