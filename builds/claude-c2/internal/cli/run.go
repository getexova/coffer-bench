package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
)

// forwardedSignals are relayed from the CLI to the child.
var forwardedSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

func cmdRun(c *ctx) error {
	base, err := secretBase(c)
	if err != nil {
		return err
	}
	cl, err := c.newClient(true)
	if err != nil {
		return err
	}
	resp, err := cl.do("GET", base+"/export", map[string][]string{"format": {"json"}}, nil)
	if err != nil {
		return err
	}
	secrets := map[string]string{}
	dec := json.NewDecoder(bytes.NewReader(resp.body))
	if err := dec.Decode(&secrets); err != nil {
		return genericErr("unexpected response from server")
	}
	for k, v := range secrets {
		if k == "" || strings.ContainsAny(k, "=\x00") {
			return genericErr("secret name %q cannot be used as an environment variable", sanitize(k))
		}
		if strings.IndexByte(v, 0) >= 0 {
			return genericErr("secret %s contains a NUL byte and cannot be passed in the environment", sanitize(k))
		}
	}
	env := mergeEnv(c.app.Environ(), secrets)
	code, err := c.app.runChild(c.args, env)
	if err != nil {
		return err
	}
	return exitSilently(code)
}

// mergeEnv returns base plus secrets; secrets replace same-named variables.
func mergeEnv(base []string, secrets map[string]string) []string {
	out := make([]string, 0, len(base)+len(secrets))
	for _, kv := range base {
		name := kv
		if i := strings.IndexByte(kv, '='); i > 0 {
			name = kv[:i]
		}
		if _, override := secrets[name]; override {
			continue
		}
		out = append(out, kv)
	}
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, k+"="+secrets[k])
	}
	return out
}

// runChild starts argv with env and inherited stdio, forwards signals, and
// returns the child's exit code (128+N if killed by signal N). Nothing is
// written to disk.
func (a *App) runChild(argv []string, env []string) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin = a.Stdin
	cmd.Stdout = a.Stdout
	cmd.Stderr = a.Stderr

	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, forwardedSignals...)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		return startErrorCode(a, argv[0], err)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				_ = cmd.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	waitErr := cmd.Wait()
	close(done)
	return exitCodeOf(cmd.ProcessState, waitErr), nil
}

func startErrorCode(a *App, name string, err error) (int, error) {
	switch {
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, exec.ErrDot), errors.Is(err, fs.ErrNotExist):
		fmt.Fprintf(a.Stderr, "error: command not found: %s\n", sanitize(name))
		return 127, nil
	case errors.Is(err, fs.ErrPermission):
		fmt.Fprintf(a.Stderr, "error: permission denied: %s\n", sanitize(name))
		return 126, nil
	}
	fmt.Fprintf(a.Stderr, "error: cannot run %s: %s\n", sanitize(name), sanitize(pathErrReason(err)))
	return 126, nil
}

func exitCodeOf(ps *os.ProcessState, waitErr error) int {
	if ps == nil {
		if waitErr != nil {
			return ExitError
		}
		return ExitOK
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok {
		if ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		if ws.Exited() {
			return ws.ExitStatus()
		}
	}
	if c := ps.ExitCode(); c >= 0 {
		return c
	}
	return ExitError
}
