// Package cli implements the coffer command-line client.
//
// It uses only the Go standard library. All behaviour follows SPEC.md §7.1 and
// docs/CONTRACT.md §6–§7.
package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Version is the CLI version reported in the User-Agent header.
var Version = "0.1.0"

// Exit codes (SPEC §7.1).
const (
	ExitOK           = 0
	ExitError        = 1
	ExitUsage        = 2
	ExitUnauth       = 3
	ExitForbidden    = 4
	ExitNotFound     = 5
	ExitValidation   = 6
	ExitPending      = 7
	ExitConflict     = 8
	ExitChainInvalid = 9
	ExitRateLimited  = 10
)

// App is one CLI invocation's environment. Everything the CLI touches
// (stdio, environment, TTY detection, HTTP transport) is injectable for tests.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// LookupEnv looks up an environment variable (default os.LookupEnv).
	LookupEnv func(string) (string, bool)
	// Environ returns the environment passed to `run` children (default os.Environ).
	Environ func() []string
	// StdoutIsTTY / StdinIsTTY report whether the streams are terminals.
	StdoutIsTTY func() bool
	StdinIsTTY  func() bool

	// Transport overrides the HTTP transport (nil = http.DefaultTransport clone).
	Transport http.RoundTripper
	// Timeout for HTTP requests (default 30s).
	Timeout time.Duration

	stdinBuf *bufio.Reader
	jsonOut  bool
}

// New returns an App wired to the real process environment.
func New() *App {
	return &App{
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		LookupEnv:   os.LookupEnv,
		Environ:     os.Environ,
		StdoutIsTTY: func() bool { return isTerminal(os.Stdout) },
		StdinIsTTY:  func() bool { return isTerminal(os.Stdin) },
		Timeout:     30 * time.Second,
	}
}

func (a *App) defaults() {
	if a.Stdin == nil {
		a.Stdin = strings.NewReader("")
	}
	if a.Stdout == nil {
		a.Stdout = io.Discard
	}
	if a.Stderr == nil {
		a.Stderr = io.Discard
	}
	if a.LookupEnv == nil {
		a.LookupEnv = os.LookupEnv
	}
	if a.Environ == nil {
		a.Environ = os.Environ
	}
	if a.StdoutIsTTY == nil {
		a.StdoutIsTTY = func() bool { return false }
	}
	if a.StdinIsTTY == nil {
		a.StdinIsTTY = func() bool { return false }
	}
	if a.Timeout == 0 {
		a.Timeout = 30 * time.Second
	}
}

// env returns a non-empty environment variable value.
func (a *App) env(name string) (string, bool) {
	v, ok := a.LookupEnv(name)
	return v, ok
}

// cliError carries an exit code and a user-facing message.
type cliError struct {
	code    int    // process exit code
	errCode string // machine code for --json error documents
	msg     string // human message (already includes server code suffix if any)
	rawMsg  string // server's error.message, used verbatim in --json error documents
	usage   string // optional usage text appended on stderr
	silent  bool   // print nothing (e.g. `run` propagating the child's exit code)
}

func (e *cliError) Error() string { return e.msg }

func usageErr(usage, format string, args ...any) *cliError {
	return &cliError{code: ExitUsage, errCode: "usage", msg: fmt.Sprintf(format, args...), usage: usage}
}

func validationErr(format string, args ...any) *cliError {
	return &cliError{code: ExitValidation, errCode: "validation", msg: fmt.Sprintf(format, args...)}
}

func genericErr(format string, args ...any) *cliError {
	return &cliError{code: ExitError, errCode: "error", msg: fmt.Sprintf(format, args...)}
}

func exitSilently(code int) *cliError { return &cliError{code: code, silent: true} }

// Run executes the CLI with args (without the program name) and returns the
// process exit code.
func (a *App) Run(args []string) int {
	a.defaults()
	a.stdinBuf = nil
	a.jsonOut = prescanJSON(args)
	err := a.run(args)
	if err == nil {
		return ExitOK
	}
	return a.report(err)
}

// prescanJSON looks for --json before flag parsing so early usage errors can
// honour it. It stops at the "--" terminator.
func prescanJSON(args []string) bool {
	for _, s := range args {
		if s == "--" {
			return false
		}
		if s == "--json" || s == "--json=true" || s == "--json=1" {
			return true
		}
	}
	return false
}

func (a *App) report(err error) int {
	var ce *cliError
	if !errors.As(err, &ce) {
		ce = genericErr("%s", err.Error())
	}
	if ce.silent {
		return ce.code
	}
	fmt.Fprintf(a.Stderr, "error: %s\n", sanitize(ce.msg))
	if ce.usage != "" {
		fmt.Fprintf(a.Stderr, "usage: %s\n", ce.usage)
	}
	if a.jsonOut {
		code := ce.errCode
		if code == "" {
			code = "error"
		}
		msg := ce.msg
		if ce.rawMsg != "" {
			msg = ce.rawMsg
		}
		doc := map[string]any{"error": map[string]any{"code": code, "message": msg}}
		_ = writeJSON(a.Stderr, doc)
	}
	return ce.code
}

// writeJSON encodes v as indented JSON without HTML escaping.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
