package cli

import (
	"bytes"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func exportServer(t *testing.T, secrets map[string]string) *fakeServer {
	return newFake(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.URL.Path != "/api/v1/projects/app/envs/dev/export" || r.URL.Query().Get("format") != "json" {
			t.Errorf("unexpected request %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		jsonReply(w, 200, secrets)
	})
}

func TestRunEnvInjectionSecretsWin(t *testing.T) {
	f := exportServer(t, map[string]string{"DB_URL": "postgres://s3cr3t", "SHARED": "from-secret", "MULTI": "a\nb"})
	h := newHarness(t, f.srv.URL)
	h.environ = []string{"PATH=" + os.Getenv("PATH"), "SHARED=from-env", "KEEP=kept"}
	code, out, stderr := h.run("run", "-p", "app", "-e", "dev", "--", "/bin/sh", "-c", `printf '%s|%s|%s|%s' "$DB_URL" "$SHARED" "$KEEP" "$MULTI"`)
	mustExit(t, 0, code, stderr)
	if out != "postgres://s3cr3t|from-secret|kept|a\nb" {
		t.Fatalf("child output %q", out)
	}
	// SHARED must appear exactly once in the child's environment.
	code, out, _ = h.run("run", "-p", "app", "-e", "dev", "--", "/bin/sh", "-c", "env | grep -c '^SHARED='")
	mustExit(t, 0, code, "")
	if strings.TrimSpace(out) != "1" {
		t.Fatalf("SHARED count %q", out)
	}
}

func TestRunWithoutDoubleDash(t *testing.T) {
	f := exportServer(t, map[string]string{"X": "1"})
	h := newHarness(t, f.srv.URL)
	code, out, stderr := h.run("run", "-p", "app", "-e", "dev", "/bin/sh", "-c", `printf %s "$X"`, "-p", "ignored")
	mustExit(t, 0, code, stderr)
	if out != "1" {
		t.Fatalf("%q", out)
	}
}

func TestRunExitCodes(t *testing.T) {
	f := exportServer(t, map[string]string{})
	h := newHarness(t, f.srv.URL)
	cases := []struct {
		script string
		want   int
	}{
		{"exit 0", 0},
		{"exit 3", 3},
		{"exit 42", 42},
		{"kill -TERM $$", 128 + 15},
		{"kill -KILL $$", 128 + 9},
		{"kill -INT $$", 128 + 2},
	}
	for _, tc := range cases {
		code, _, stderr := h.run("run", "-p", "app", "-e", "dev", "--", "/bin/sh", "-c", tc.script)
		if code != tc.want {
			t.Errorf("%q: exit %d, want %d (stderr %q)", tc.script, code, tc.want, stderr)
		}
	}
	code, _, stderr := h.run("run", "-p", "app", "-e", "dev", "--", "definitely-not-a-command-xyz")
	mustExit(t, 127, code, stderr)
}

func TestRunStdinInherited(t *testing.T) {
	f := exportServer(t, map[string]string{})
	h := newHarness(t, f.srv.URL)
	h.stdin = strings.NewReader("piped input")
	code, out, stderr := h.run("run", "-p", "app", "-e", "dev", "--", "/bin/cat")
	mustExit(t, 0, code, stderr)
	if out != "piped input" {
		t.Fatalf("%q", out)
	}
}

func TestRunFetchFailureDoesNotRunChild(t *testing.T) {
	f := newFake(t, errReply(403, "forbidden", "forbidden"))
	h := newHarness(t, f.srv.URL)
	marker := t.TempDir() + "/ran"
	code, _, _ := h.run("run", "-p", "app", "-e", "dev", "--", "/bin/sh", "-c", "touch "+marker)
	mustExit(t, 4, code, "")
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("child ran despite fetch failure")
	}
}

// lockedBuffer signals once the child has written something (it is ready).
type lockedBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.buf.Write(p)
	if strings.Contains(b.buf.String(), "ready") {
		b.once.Do(func() { close(b.ready) })
	}
	return n, err
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRunForwardsSignals(t *testing.T) {
	f := exportServer(t, map[string]string{})
	cases := []struct {
		name   string
		sig    syscall.Signal
		script string
		want   int
		output string
	}{
		// Child traps the signal and exits 42: proves the signal was forwarded.
		{"trapped TERM", syscall.SIGTERM, `trap 'echo got-term; exit 42' TERM; echo ready; while :; do sleep 0.05; done`, 42, "got-term"},
		{"trapped INT", syscall.SIGINT, `trap 'echo got-int; exit 43' INT; echo ready; while :; do sleep 0.05; done`, 43, "got-int"},
		// Child does not trap: dies from the forwarded signal -> 128+N.
		{"untrapped TERM", syscall.SIGTERM, `echo ready; exec sleep 30`, 128 + 15, ""},
		{"untrapped HUP", syscall.SIGHUP, `echo ready; exec sleep 30`, 128 + 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, f.srv.URL)
			out := &lockedBuffer{ready: make(chan struct{})}
			h.stdout = out
			done := make(chan int, 1)
			go func() {
				code, _, _ := h.run("run", "-p", "app", "-e", "dev", "--", "/bin/sh", "-c", tc.script)
				done <- code
			}()
			select {
			case <-out.ready:
			case <-time.After(10 * time.Second):
				t.Fatal("child never became ready")
			}
			if err := syscall.Kill(os.Getpid(), tc.sig); err != nil {
				t.Fatal(err)
			}
			select {
			case code := <-done:
				if code != tc.want {
					t.Fatalf("exit %d, want %d (out %q)", code, tc.want, out.String())
				}
				if !strings.Contains(out.String(), tc.output) {
					t.Fatalf("output %q", out.String())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("child did not exit after signal")
			}
		})
	}
}

func TestMergeEnv(t *testing.T) {
	got := mergeEnv([]string{"A=1", "B=2", "B=dup", "=weird", "NOEQ"}, map[string]string{"B": "s", "C": "c"})
	want := []string{"A=1", "=weird", "NOEQ", "B=s", "C=c"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%v", got)
	}
}

func TestRunRejectsNUL(t *testing.T) {
	f := exportServer(t, map[string]string{"BAD": "a\x00b"})
	h := newHarness(t, f.srv.URL)
	code, _, _ := h.run("run", "-p", "app", "-e", "dev", "--", "/bin/true")
	mustExit(t, 1, code, "")
}
