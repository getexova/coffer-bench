package main

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// runHarness answers the export read that `coffer run` performs.
func (h *harness) serveExport(pairs map[string]string) *harness {
	h.server.on(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/export") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"not found"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonBody(pairs)))
	})
	return h
}

// TestRunExitCodeIsTheChilds proves the CLI returns the child's exit code.
func TestRunExitCodeIsTheChilds(t *testing.T) {
	for _, want := range []int{0, 3, 42} {
		h := newHarness(t).login("cof_pat_test").serveExport(nil)
		h.run("", "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "exit "+itoa(int64(want)))
		h.wantCode(want)
	}
}

// TestRunKilledBySignalIs128PlusN proves a child killed by signal N exits 128+N
// (SPEC §7.1).
func TestRunKilledBySignalIs128PlusN(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals are not meaningful on windows")
	}
	cases := []struct {
		signal int
		want   int
	}{
		{15, 143}, // SIGTERM
		{9, 137},  // SIGKILL
		{2, 130},  // SIGINT
		{1, 129},  // SIGHUP
	}
	for _, tc := range cases {
		h := newHarness(t).login("cof_pat_test").serveExport(nil)
		h.run("", "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "kill -"+itoa(int64(tc.signal))+" $$")
		h.wantCode(tc.want)
	}
}

// TestRunSecretsWinOnConflict proves secrets override the inherited environment
// and that the parent's other variables survive.
func TestRunSecretsWinOnConflict(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh is not available on windows")
	}
	h := newHarness(t).login("cof_pat_test")
	h.withEnv("CONFLICT", "from-parent")
	h.withEnv("PARENT_ONLY", "kept")
	h.serveExport(map[string]string{
		"CONFLICT": "from-secret",
		"SECRET_A": "alpha",
	})
	h.run("", "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "printf '%s|%s|%s' \"$CONFLICT\" \"$PARENT_ONLY\" \"$SECRET_A\"")
	h.wantCode(exitOK)
	h.wantStdout("from-secret|kept|alpha")
}

// TestRunForwardsStdinAndStdout proves the child's streams are inherited.
func TestRunForwardsStdinAndStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh is not available on windows")
	}
	h := newHarness(t).login("cof_pat_test").serveExport(nil)
	h.run("piped input\n", "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "cat")
	h.wantCode(exitOK)
	h.wantStdout("piped input\n")
}

// TestRunWritesNothingToDisk proves no temp file is created: the secrets exist
// only in the child's environment.
func TestRunWritesNothingToDisk(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh is not available on windows")
	}
	h := newHarness(t).login("cof_pat_test").serveExport(map[string]string{"SECRET_A": "value"})
	// Run the child with a private TMPDIR and an empty cwd listing afterwards.
	tmp := t.TempDir()
	h.withEnv("TMPDIR", tmp)
	before := listDir(t, tmp)
	h.run("", "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "true")
	h.wantCode(exitOK)
	after := listDir(t, tmp)
	if strings.Join(before, ",") != strings.Join(after, ",") {
		t.Fatalf("temp dir changed: before %v, after %v", before, after)
	}
}

// TestRunMissingCommandIsUsage proves `coffer run` without `--` and a command
// exits 2 before a request.
func TestRunMissingCommandIsUsage(t *testing.T) {
	h := newHarness(t).login("cof_pat_test")
	h.run("", "run", "-p", "app", "-e", "dev")
	h.wantCode(exitUsage)
	if n := h.server.requestCount(); n != 0 {
		t.Fatalf("server saw %d requests, want 0", n)
	}
}

// TestRunUnknownBinaryExits127 proves a missing executable is reported as 127,
// the shell convention.
func TestRunUnknownBinaryExits127(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh is not available on windows")
	}
	h := newHarness(t).login("cof_pat_test").serveExport(nil)
	h.run("", "run", "-p", "app", "-e", "dev", "--", "coffer-definitely-not-a-binary")
	h.wantCode(127)
}

// TestRunChildArgsAreNotParsedAsCLIFlags proves the child's own flags pass
// through untouched: everything after `--` belongs to the child.
func TestRunChildArgsAreNotParsedAsCLIFlags(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh is not available on windows")
	}
	h := newHarness(t).login("cof_pat_test").serveExport(nil)
	h.run("", "run", "-p", "app", "-e", "dev", "--", "sh", "-c", "printf '%s' \"$*\"", "sh", "--json", "-p", "x", "--version", "5")
	h.wantCode(exitOK)
	h.wantStdout("--json -p x --version 5")
}

// TestRunChildIsNotInterpretedByAShell proves there is no shell interpolation:
// a metacharacter in an argument reaches the child literally.
func TestRunChildIsNotInterpretedByAShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh is not available on windows")
	}
	h := newHarness(t).login("cof_pat_test").serveExport(nil)
	h.run("", "run", "-p", "app", "-e", "dev", "--", "printf", "%s", "$(echo injected)")
	h.wantCode(exitOK)
	h.wantStdout("$(echo injected)")
}

// TestMergeEnv covers the merge rules directly.
func TestMergeEnv(t *testing.T) {
	parent := []string{"A=parent", "B=parent", "PATH=/bin"}
	secrets := map[string]string{"B": "secret", "C": "secret"}
	got := mergeEnv(parent, secrets)

	env := map[string]string{}
	order := make([]string, 0, len(got))
	for _, entry := range got {
		name, value, _ := strings.Cut(entry, "=")
		if _, dup := env[name]; dup {
			t.Fatalf("duplicate variable %q in %v", name, got)
		}
		env[name] = value
		order = append(order, name)
	}
	if env["A"] != "parent" || env["PATH"] != "/bin" {
		t.Errorf("parent variables lost: %v", env)
	}
	if env["B"] != "secret" {
		t.Errorf("B = %q, want the secret to win", env["B"])
	}
	if env["C"] != "secret" {
		t.Errorf("C = %q, want it added", env["C"])
	}
	// Deterministic means two calls with the same input agree, not that the
	// result is sorted: parent order is preserved, secrets are appended sorted.
	if again := mergeEnv(parent, secrets); strings.Join(again, "\x00") != strings.Join(got, "\x00") {
		t.Errorf("mergeEnv is not deterministic:\n first = %v\n second = %v", got, again)
	}
	parentOrder := []string{"A", "PATH"}
	if strings.Join(order[:2], ",") != strings.Join(parentOrder, ",") {
		t.Errorf("parent order not preserved: %v", order)
	}
}

// TestMergeEnvEmptySecretValue proves an empty secret still overrides the parent,
// which is what "secrets win" means.
func TestMergeEnvEmptySecretValue(t *testing.T) {
	got := mergeEnv([]string{"A=parent"}, map[string]string{"A": ""})
	if len(got) != 1 || got[0] != "A=" {
		t.Fatalf("mergeEnv = %v, want [A=]", got)
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, filepath.Join(dir, e.Name()))
	}
	sort.Strings(names)
	return names
}
