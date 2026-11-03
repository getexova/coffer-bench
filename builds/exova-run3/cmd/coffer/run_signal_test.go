package main

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRunForwardsSignalsToTheChild is the only test that needs the real binary:
// signal forwarding cannot be exercised in-process without signalling the test
// binary itself. It builds ./cmd/coffer, runs it against a fake API, and sends
// SIGTERM to the CLI process, which must relay it to the child.
func TestRunForwardsSignalsToTheChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix signals only")
	}
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := buildBinary(t)

	// The child traps SIGTERM and exits 42, proving it received the signal.
	ts := newTestServer(t)
	ts.reply(http.StatusOK, `{"SECRET_A":"alpha"}`)

	cmd := exec.Command(bin, "run", "-p", "app", "-e", "dev", "--",
		"sh", "-c", `trap 'exit 42' TERM; echo started; while :; do sleep 0.05; done`)
	cmd.Env = append(os.Environ(),
		"COFFER_URL="+ts.srv.URL,
		"COFFER_TOKEN=cof_pat_test",
	)
	stdout := &strings.Builder{}
	cmd.Stdout = stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Wait for the child to be running before signalling.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(stdout.String(), "started") {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("child never started; stdout=%q", stdout.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if err == nil {
			t.Fatal("the CLI exited 0, want the child's trapped exit code 42")
		}
		if !asExitError(err, &exitErr) {
			t.Fatalf("wait: %v", err)
		}
		if got := exitErr.ExitCode(); got != 42 {
			t.Fatalf("exit code = %d, want 42: the child did not receive the forwarded SIGTERM", got)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the CLI did not exit after SIGTERM: the signal was not forwarded")
	}
}

// buildBinary compiles the CLI once for the tests that need a subprocess.
func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "coffer")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func asExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}
