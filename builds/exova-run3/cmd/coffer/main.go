// Command coffer is the Coffer command-line client specified in SPEC §7.1.
//
// The same binary also runs the server: `coffer serve` boots internal/httpapi,
// which is how bin/coffer backs the compose stack (`coffer server` is accepted as
// an alias so the container image and the CLI cannot drift apart on the
// spelling). The two live side by side in one package so that
// scripts/build.sh produces a single artifact and every §7.1 command sits beside
// the server entrypoint.
package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// version is overridable at link time: -X main.version=<git describe>.
var version = "dev"

// Exit codes, fixed by SPEC §7.1.
const (
	exitOK              = 0
	exitOther           = 1
	exitUsage           = 2
	exitUnauthenticated = 3
	exitForbidden       = 4
	exitNotFound        = 5
	exitValidation      = 6
	exitPending         = 7
	exitConflict        = 8
	exitAuditInvalid    = 9
	exitRateLimited     = 10
)

// cli is one invocation: the streams, the global flags, and the configuration
// and HTTP client loaded on first use.
type cli struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	in *inputReader

	// stdoutTTY reports whether stdout is a terminal. `secrets get` appends a
	// newline only when it is, so a pipe receives the exact value bytes.
	stdoutTTY func() bool

	json bool   // --json
	url  string // --url

	cfg    *cliConfig
	client *client
}

// errNotLoggedIn is a local authentication failure: exit 3 without a request.
var errNotLoggedIn = &exitError{
	code: exitUnauthenticated,
	msg:  "not logged in: run `coffer login --email EMAIL`, or set COFFER_TOKEN",
}

func main() {
	os.Exit(newCLI(os.Stdin, os.Stdout, os.Stderr).run(os.Args[1:]))
}

// newCLI builds one invocation. It is separated from main so a test can drive it
// without ending the test binary.
func newCLI(stdin io.Reader, stdout, stderr io.Writer) *cli {
	return &cli{
		stdin:     stdin,
		stdout:    stdout,
		stderr:    stderr,
		in:        newInputReader(stdin),
		stdoutTTY: func() bool { return isTerminalFile(stdout) },
	}
}

// run executes one command line and returns the process exit code.
func (c *cli) run(args []string) int {
	err := c.dispatch(args)
	if err == nil || errors.Is(err, errHelp) {
		return exitOK
	}
	var silent *silentError
	if errors.As(err, &silent) {
		// The command already reported its outcome on stdout.
		return silent.code
	}
	c.printError(err)
	return exitCodeFor(err)
}

// dispatch strips the global flags, then routes to a subcommand tree.
func (c *cli) dispatch(args []string) error {
	rest, err := c.stripGlobals(args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		c.printUsage(c.stderr)
		return usagef("missing command")
	}
	command, rest := rest[0], rest[1:]
	switch command {
	case "help", "-h", "-help", "--help":
		c.printUsage(c.stdout)
		return nil
	case "version", "--version":
		fmt.Fprintf(c.stdout, "coffer %s\n", version)
		return nil
	case "login":
		return c.cmdLogin(rest)
	case "logout":
		return c.cmdLogout(rest)
	case "whoami":
		return c.cmdWhoami(rest)
	case "passwd":
		return c.cmdPasswd(rest)
	case "admin":
		return c.cmdAdmin(rest)
	case "member", "members":
		return c.cmdMember(rest)
	case "grant", "grants":
		return c.cmdGrant(rest)
	case "project", "projects":
		return c.cmdProject(rest)
	case "env", "envs", "environment", "environments":
		return c.cmdEnv(rest)
	case "secrets", "secret":
		return c.cmdSecrets(rest)
	case "run":
		return c.cmdRun(rest)
	case "change", "changes":
		return c.cmdChange(rest)
	case "token", "tokens":
		return c.cmdToken(rest)
	case "audit":
		return c.cmdAudit(rest)
	case "serve", "server":
		return c.cmdServe(rest)
	default:
		return usagef("unknown command %q: run `coffer help`", command)
	}
}

// stripGlobals removes --json and --url/--url=VALUE from anywhere on the command
// line, so `coffer --json project list` and `coffer project list --json` behave
// identically. Everything from a bare `--` onward is left untouched: it belongs
// to `coffer run`.
func (c *cli) stripGlobals(args []string) ([]string, error) {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			out = append(out, args[i:]...)
			return out, nil
		case a == "--json" || a == "-json":
			c.json = true
		case a == "--url" || a == "-url":
			if i+1 >= len(args) {
				return nil, usagef("--url requires a value")
			}
			i++
			c.url = args[i]
		case strings.HasPrefix(a, "--url=") || strings.HasPrefix(a, "-url="):
			c.url = a[strings.IndexByte(a, '=')+1:]
		default:
			out = append(out, a)
		}
	}
	return out, nil
}

// exitCodeFor maps a Go error onto the fixed exit codes of SPEC §7.1.
func exitCodeFor(err error) int {
	var usage *usageError
	if errors.As(err, &usage) {
		return exitUsage
	}
	var api *apiError
	if errors.As(err, &api) {
		return statusExit(api.Status)
	}
	var coded *exitError
	if errors.As(err, &coded) {
		return coded.code
	}
	return exitOther
}

// printError writes the failure to stderr. Server messages are stable, generic
// strings from docs/CONTRACTS.md §2 and never contain a value or a token.
func (c *cli) printError(err error) {
	var api *apiError
	if errors.As(err, &api) {
		msg := api.Message
		if msg == "" {
			msg = api.Code
		}
		if msg == "" {
			msg = http.StatusText(api.Status)
		}
		fmt.Fprintf(c.stderr, "coffer: %s\n", msg)
		if api.Hint != "" {
			fmt.Fprintf(c.stderr, "coffer: hint: %s\n", api.Hint)
			return
		}
		switch api.Status {
		case http.StatusUnauthorized:
			fmt.Fprintln(c.stderr, "coffer: hint: run `coffer login --email EMAIL` to obtain a token, or check COFFER_TOKEN")
		case http.StatusForbidden:
			fmt.Fprintln(c.stderr, "coffer: hint: you may lack permission, or a password set by an administrator must be changed first with `coffer passwd`")
		case http.StatusTooManyRequests:
			fmt.Fprintln(c.stderr, "coffer: hint: too many attempts; wait for the window to pass and retry")
		}
		return
	}
	fmt.Fprintf(c.stderr, "coffer: %v\n", err)
}

// config loads the CLI configuration once per invocation.
func (c *cli) config() (*cliConfig, error) {
	if c.cfg == nil {
		cfg, err := loadConfig()
		if err != nil {
			return nil, err
		}
		c.cfg = cfg
	}
	return c.cfg, nil
}

// api returns a client without requiring a credential. Only `login` uses it: the
// server, not the CLI, decides that a password is wrong.
func (c *cli) api() (*client, error) {
	if c.client != nil {
		return c.client, nil
	}
	cfg, err := c.config()
	if err != nil {
		return nil, err
	}
	base := cfg.baseURL(c.url)
	if err := validateBaseURL(base); err != nil {
		return nil, err
	}
	c.client = newClient(base, cfg.credential())
	return c.client, nil
}

// anonymousClient builds a client with no credential at all.
//
// `login` must use this. The token endpoint is the one route that authenticates a
// caller by the password in its body, and the server's middleware rejects an
// unknown, revoked or expired bearer before the handler runs. Sending the stored
// PAT would therefore make a correct password fail with 401, and a stale config
// would lock the user out of logging in again until they deleted it by hand.
func (c *cli) anonymousClient() (*client, error) {
	cfg, err := c.config()
	if err != nil {
		return nil, err
	}
	base := cfg.baseURL(c.url)
	if err := validateBaseURL(base); err != nil {
		return nil, err
	}
	return newClient(base, ""), nil
}

// authClient is api() for commands that need a credential.
func (c *cli) authClient() (*client, error) {
	cl, err := c.api()
	if err != nil {
		return nil, err
	}
	if cl.token == "" {
		return nil, errNotLoggedIn
	}
	return cl, nil
}

const usageText = `coffer — Coffer secrets CLI

Usage:
  coffer <command> [flags]

Authentication:
  coffer login --email EMAIL [--url URL]                  password on stdin
  coffer logout
  coffer whoami
  coffer passwd                                           stdin: current, then new

Platform admin:
  coffer admin org create SLUG --owner-email EMAIL        owner password on stdin
  coffer admin org list
  coffer admin org disable SLUG
  coffer admin audit list [--limit N]
  coffer admin audit verify

Organization:
  coffer member add EMAIL --role member|admin|owner       initial password on stdin
  coffer member list
  coffer member role EMAIL member|admin|owner
  coffer member remove EMAIL
  coffer grant set EMAIL -p PROJECT --level viewer|reader|writer
  coffer grant revoke EMAIL -p PROJECT

Projects and environments:
  coffer project create SLUG
  coffer project list
  coffer env create SLUG -p PROJECT [--protected]
  coffer env list -p PROJECT

Secrets:
  coffer secrets list -p P -e E
  coffer secrets get KEY -p P -e E [--version N]
  coffer secrets set KEY [VALUE] -p P -e E [--expect-version N]
  coffer secrets delete KEY -p P -e E
  coffer secrets history KEY -p P -e E
  coffer secrets rollback KEY --to N -p P -e E
  coffer secrets export -p P -e E --format dotenv|json
  coffer run -p P -e E -- COMMAND [ARGS...]

Change requests:
  coffer change list [--status pending|approved|rejected|stale]
  coffer change approve ID
  coffer change reject ID

Service tokens:
  coffer token create -p P -e E --access read|read-write --ttl DURATION [--name NAME]
  coffer token list
  coffer token revoke ID

Audit:
  coffer audit list [--actor ID] [--action NAME] [--since RFC3339] [--limit N]
  coffer audit verify

Server:
  coffer serve                                            run the HTTP API server
                                                          (configuration is environment-only)

Global flags:
  --url URL    server base URL (default $COFFER_URL, then the stored URL,
               then http://127.0.0.1:8420)
  --json       print exactly one JSON document to stdout

Environment:
  COFFER_URL    server base URL
  COFFER_TOKEN  personal access token or service token; when set, no config file
                is read or written

Exit codes:
  0 success      1 other error   2 usage        3 unauthenticated
  4 forbidden    5 not found     6 validation   7 pending approval
  8 conflict     9 audit chain invalid          10 rate limited
`

func (c *cli) printUsage(w io.Writer) {
	fmt.Fprint(w, usageText)
}
