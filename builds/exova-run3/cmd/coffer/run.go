package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
)

// cmdRun implements `coffer run -p P -e E -- COMMAND [ARGS...]` (SPEC §7.1).
//
// The child gets the current environment plus every secret in the environment,
// with secrets winning on a name conflict. stdin, stdout and stderr are
// inherited, SIGINT and SIGTERM are forwarded, the exit code is the child's (or
// 128+N when it was killed by signal N), and nothing is written to disk: no temp
// file, no shell interpolation.
func (c *cli) cmdRun(args []string) error {
	const synopsis = "run -p P -e E -- COMMAND [ARGS...]"

	// The command is everything after a bare `--`. Splitting it off first keeps
	// a child's own flags (`--version`, `-p`) out of the CLI's parser.
	cmdArgs, rest := splitAfterDashDash(args)
	if len(cmdArgs) == 0 {
		return usagef("missing command: expected `coffer %s`", synopsis)
	}

	fs := newFlagSet("run")
	var scope secretScope
	scope.register(fs)
	if err := parseFlags(fs, rest, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, synopsis); err != nil {
		return err
	}
	project, env, err := scope.require(synopsis)
	if err != nil {
		return err
	}

	cl, err := c.authClient()
	if err != nil {
		return err
	}
	secrets, err := c.fetchRunSecrets(cl, project, env)
	if err != nil {
		return err
	}

	return c.execChild(cmdArgs, secrets)
}

// splitAfterDashDash splits args at the first bare `--`.
func splitAfterDashDash(args []string) (after []string, before []string) {
	for i, a := range args {
		if a == "--" {
			return args[i+1:], args[:i]
		}
	}
	return nil, args
}

// fetchRunSecrets reads every value in the environment through the export route,
// which is the one bulk read the API offers and is audited per key by the server.
func (c *cli) fetchRunSecrets(cl *client, project, env string) (map[string]string, error) {
	q := values("format", "json")
	resp, err := cl.raw(http.MethodGet, envPath(project, env)+"/export", q, nil)
	if err != nil {
		return nil, err
	}
	return parseExportJSON(resp.body)
}

// parseExportJSON accepts either a bare object of key to value or the
// {"secrets":{...}} wrapper, so the CLI is robust to either shape.
func parseExportJSON(body []byte) (map[string]string, error) {
	var flat map[string]string
	if err := json.Unmarshal(body, &flat); err == nil {
		return flat, nil
	}
	var wrapped struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal(body, &wrapped); err == nil && wrapped.Secrets != nil {
		return wrapped.Secrets, nil
	}
	return nil, errors.New("the server returned an unreadable export")
}

// execChild runs the command with the merged environment and translates its exit
// status. A child killed by signal N exits 128+N.
func (c *cli) execChild(argv []string, secrets map[string]string) error {
	child := exec.Command(argv[0], argv[1:]...)
	child.Env = mergeEnv(os.Environ(), secrets)
	child.Stdin = c.stdin
	child.Stdout = c.stdout
	child.Stderr = c.stderr

	if err := child.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return &exitError{code: 127, msg: fmt.Sprintf("cannot run %q: no such command", argv[0])}
		}
		return &exitError{code: 126, msg: fmt.Sprintf("cannot run %q: %v", argv[0], err)}
	}

	// Forward SIGINT and SIGTERM to the child. signal.Notify takes delivery away
	// from the default handler, so the CLI itself keeps running until the child
	// is gone; SIGTERM is also relayed so a container stop reaches the child.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for sig := range sigs {
			if err := child.Process.Signal(sig); err != nil {
				// The child is already gone; nothing left to forward.
				return
			}
		}
	}()

	waitErr := child.Wait()
	signal.Stop(sigs)
	close(sigs)
	<-done

	return childExitError(waitErr)
}

// childExitError maps the child's wait result onto an error that carries its
// exit code.
func childExitError(waitErr error) error {
	if waitErr == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		return fmt.Errorf("the command failed: %w", waitErr)
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		// 128+N, the shell convention (SPEC §7.1).
		return &silentError{code: 128 + int(status.Signal())}
	}
	code := exitErr.ExitCode()
	if code < 0 {
		return &exitError{code: exitOther, msg: "the command was terminated"}
	}
	if code == 0 {
		return nil
	}
	return &silentError{code: code}
}

// mergeEnv returns the parent environment plus the secrets, with secrets winning
// on a name conflict. The result is deterministic (parent order, then secrets
// sorted by name) so a child that dumps its environment sees a stable order.
func mergeEnv(parent []string, secrets map[string]string) []string {
	merged := make([]string, 0, len(parent)+len(secrets))
	index := make(map[string]int, len(parent)+len(secrets))
	for _, entry := range parent {
		name, _, _ := strings.Cut(entry, "=")
		if _, dup := secrets[name]; dup {
			// A secret overrides the inherited variable; the secret is added
			// below so exactly one definition reaches the child.
			continue
		}
		if _, seen := index[name]; seen {
			// Keep the last definition, which is what execve would use.
			merged[index[name]] = entry
			continue
		}
		index[name] = len(merged)
		merged = append(merged, entry)
	}
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := name + "=" + secrets[name]
		if i, ok := index[name]; ok {
			merged[i] = entry
			continue
		}
		index[name] = len(merged)
		merged = append(merged, entry)
	}
	return merged
}
