# The Coffer CLI (`cmd/coffer`)

Owner: E4. This is the implementation of SPEC §7.1, plus the server entrypoint that
`bin/coffer` uses to back the compose stack.

Build it with `./scripts/build.sh`, which runs:

```
CGO_ENABLED=0 go build -o bin/coffer ./cmd/coffer
```

One `package main`, one binary, no runtime dependency.

## Two entrypoints, one binary

| Invocation | What runs |
|---|---|
| `coffer serve` (alias `coffer server`) | `cmdServe` → `internal/httpapi.ServeWithOptions` — the HTTP server |
| every other §7.1 word | the CLI command trees below |

`serve` takes **no flags**: SPEC §5 makes server configuration environment-only, so an
operator changes the port with `COFFER_PORT`, never `--port`. The alias exists because the
container image runs `coffer server`; keeping both spellings means the image and the CLI
cannot drift apart.

## File map

| File | Contents |
|---|---|
| `main.go` | `cli` struct, `newCLI`, `run` → `dispatch`, global-flag stripping, exit-code mapping, `printError`, usage text |
| `errors.go` | `usageError`, `apiError`, `exitError`, `silentError`, and `statusExit` (HTTP status → exit code) |
| `validate.go` | slug `^[a-z0-9][a-z0-9-]{0,62}$`, key `^[A-Z_][A-Z0-9_]{0,127}$`, TTL `1m..90d`, base-URL checks |
| `flags.go` | stdlib `flag` wrapper, `reorderFlags`, `secretScope` (`-p`/`-e`), `requireProject` |
| `config.go` | config directory and file, modes, atomic write, `baseURL` precedence |
| `client.go` | HTTP client, JSON encode/decode, status→`apiError`, path builders |
| `input.go` | `inputReader`: one-line password reads vs read-to-EOF |
| `output.go` | `printJSON`, dotenv escaping, sorted JSON export, tables, `writeValue` |
| `types.go` | response types with tolerant decoding (`flexTime`, `flexInt64`, `decodeList`, `decodeObject`) |
| `tty.go` | `isTerminalFile` (character-device check) |
| `serve.go` | the server entrypoint and its wiring |
| `auth.go` | `login`, `logout`, `whoami`, `passwd` |
| `admin.go` | `admin org create|list|disable`, `admin audit list|verify` |
| `members.go` | `member add|list|role|remove`, `grant set|revoke` |
| `projects.go` | `project create|list`, `env create|list` |
| `secrets.go` | `secrets list|get|set|delete|history|rollback|export` |
| `run.go` | `run`, environment merge, signal forwarding, child exit status |
| `changes.go` | `change list|approve|reject` |
| `tokens.go` | `token create|list|revoke` |
| `audit.go` | `audit list|verify`, shared with `admin audit` |

## Exit codes

| Code | Meaning | Decided by |
|---|---|---|
| 0 | success | — |
| 1 | other error, including a 5xx or an unreachable server | client |
| 2 | usage error | **locally, before any network call** |
| 3 | unauthenticated (401), or no token configured at all | client |
| 4 | forbidden (403) | client |
| 5 | not found (404) | client |
| 6 | validation (400 / 413 / 422) | client |
| 7 | pending approval (202) | client |
| 8 | conflict (409) | client |
| 9 | audit chain invalid — a **successful** HTTP call reporting `valid:false` | command |
| 10 | rate limited (429) | client |

Exit 2 covers an unknown command or subcommand, a missing required flag, a bad flag value,
an invalid slug or key, an out-of-range TTL, a malformed `--since`, an unknown flag, and any
attempt to pass a password in argv. All of these are checked before a request is built, and
the tests assert the fake server receives zero requests on those paths.

Exit 9 is deliberately not an HTTP error: the request succeeded and the server reported a
broken chain. A 401 does **not** delete the stored token, because the failure may be
transient; a 403 never does.

## Output contracts

- `--json` prints **exactly one JSON document** to stdout and nothing else. Errors always go
  to stderr. Where the server already returned a document, it is passed through byte for byte
  so the CLI cannot alter it.
- `secrets get` writes the **exact value bytes** when stdout is not a TTY, with **no added
  newline**; on a TTY it appends one so the shell prompt does not run into the value. The
  check is `isTerminalFile` (`tty.go`): an `*os.File` whose mode has `os.ModeCharDevice`.
- `secrets set KEY` with no `VALUE` reads stdin **to EOF** and sends the bytes exactly. There
  is no trimming, so `cat file | coffer secrets set KEY ...` round-trips byte for byte,
  including a trailing newline, CRLF and NUL bytes. `input.go` refuses to both read a
  password line and then read a value from the same stdin rather than silently truncating.
- Passwords come from **stdin only**, never argv: `login` and `member add` and
  `admin org create` read one line; `passwd` reads two lines (current, then new). No command
  registers a password flag, so `--password` is an unknown-flag usage error (exit 2).
- A write to a protected environment prints the change ID and exits 7. Under `--json` it
  prints `{"status":"pending","change_id":"..."}`.
- `token create` prints only the token on stdout, so `TOKEN=$(coffer token create ...)`
  works; the warning that it is shown once goes to stderr.

## Configuration and overrides

Config directory: `${XDG_CONFIG_HOME:-$HOME/.config}/coffer/`, created with mode **0700**;
`config.json` inside is written with mode **0600** via a temp file and a rename, so a reader
never sees a half-written credential. An existing file with looser permissions is tightened
on read.

Server URL precedence: `--url` > `COFFER_URL` > the URL stored at login >
`http://127.0.0.1:8420`.

`COFFER_TOKEN` supplies a PAT or a service token. **When it is set, no config file is read or
written at all**, which is what makes the CLI usable in CI and immune to a stale local token.

`login` deliberately uses a **token-less client** (`anonymousClient`). The token endpoint
authenticates the caller by the password in its body, and the server's middleware rejects an
unknown or revoked bearer before the handler runs — so sending a stored PAT would make a
correct password fail with 401, and a stale config would lock the user out of logging in
again. `logout` is the opposite case and does send the token it is revoking.

## `run`

`coffer run -p P -e E -- COMMAND [ARGS...]`:

- The child environment is the current environment plus every secret in the environment;
  **secrets win** on a name conflict. The merge is deterministic: parent order is preserved
  and secrets are appended sorted by name.
- stdin, stdout and stderr are inherited.
- The exit code is the child's, or **128+N** when the child was killed by signal N.
- **SIGINT and SIGTERM are forwarded** to the child.
- Nothing is written to disk: no temp file, no shell, no interpolation. Everything after a
  bare `--` belongs to the child, so the child's own `--json` or `-p` flags are never parsed
  as the CLI's.

## Export formats

`dotenv`: one `KEY="VALUE"` line per secret, sorted by key, LF endings, final newline. Inside
the quotes **only** `\`→`\\`, `"`→`\"`, newline→`\n`, CR→`\r`, `$`→`\$`. Nothing else is
escaped, so a tab, a single quote or a backtick pass through unchanged.
`json`: a single object mapping key to value, keys sorted.

**Decision: the CLI passes the server's export bytes through unchanged for both formats**
rather than re-escaping. The server owns the escaping; a re-render could only introduce a
difference, and pass-through is what makes

```
coffer secrets export -p P -e E --format dotenv > .env
```

byte-identical to the API response. The one exception is that a json export gets exactly one
trailing newline if the server omitted it, because json is a document rather than a file of
exact bytes and without it the shell prompt runs into the closing brace. The dotenv escaper
in `output.go` is still exercised directly by the tests, which pin the escaping table
character by character.

## Server wiring (`serve.go`)

`httpapi` boots the database internally, so the caller never holds the `*store.DB`. The
`Bootstrap` hook is the one point that sees the wired `Deps` — including `deps.DB` — before
the router is built, so `serve.go` builds both dependencies there and installs them through
small indirections that resolve at first use:

- `authapi.NewAuthenticator` — resolves bearer tokens. Without it `httpapi` rejects every
  credential, so a correct PAT would still get 401.
- `audit.NewAppender` — the real audit writer. Without it `httpapi` installs
  `audit.NopWriter()`, which accepts every event and discards it: the slices believe they
  recorded the action, `audit_events` stays empty, and `audit verify` reports "valid"
  because an empty chain verifies trivially. A failure to build the appender **fails the
  boot** rather than degrading silently, because a server that cannot record what happened
  must not serve traffic.

This was not theoretical: before the appender was wired, a live stack recorded zero audit
events for a full session of org, member, grant, project, environment and secret activity.

## Testing

```
go test ./cmd/coffer/ -count=1
```

No database is required. `harness_test.go` runs the CLI in-process against an `httptest`
server, with `HOME` and `XDG_CONFIG_HOME` pointed at a temp directory, and records every
request so a test can assert the method, path, query and body.

| File | Covers |
|---|---|
| `exitcode_test.go` | every HTTP status → exit code; pending writes → 7; 31 usage errors → 2 with zero requests; not-logged-in → 3; 401 keeps the config; 403 → 4; audit verify → 9 |
| `secrets_test.go` | `get` exact bytes vs TTY newline; `set` byte-exact from stdin (8 cases incl. CRLF, NUL, UTF-8); `--expect-version`; export pass-through; history/delete/rollback |
| `format_test.go` | dotenv escaping character by character; sorted output; round-trip; TTL window; slug and key patterns |
| `json_test.go` | `--json` = one document for 15 commands; flag position; empty lists; human tables; token printed once |
| `run_test.go` | child exit code; 128+N for four signals; secrets win; stdin/stdout inherited; nothing written to disk; no shell interpolation; env merge |
| `run_signal_test.go` | builds the real binary and proves SIGTERM is forwarded to the child |
| `config_test.go` | dir 0700 / file 0600; login stores URL and token; password from stdin; login failures; `passwd` two lines; `COFFER_TOKEN` statelessness; URL precedence; logout clears; login never sends a stored token |
| `commands_test.go` | the exact route, method and credential for every §7.1 command |
| `audit_test.go` | the audit response shape, `first_invalid_seq: null`, filters, bare-array fallback |
