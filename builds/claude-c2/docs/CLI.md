# Coffer CLI reference

`coffer` is a single static Linux x86_64 binary (`./bin/coffer`) with no runtime
dependencies. It talks to the server's HTTP API. `./scripts/up.sh` builds it
automatically; you can also run `./scripts/build.sh` yourself (or
`CGO_ENABLED=0 go build -o bin/coffer ./cmd/coffer`).

## Configuration

| Setting | Source (first wins) |
|---|---|
| Server URL | `--url URL`, then `COFFER_URL` (if not empty), then `url` in the config file, then `http://127.0.0.1:8420` |
| Token | `COFFER_TOKEN` (a PAT or service token), otherwise `token` in the config file |

- The config file is `${XDG_CONFIG_HOME:-$HOME/.config}/coffer/config.json`
  (`{"url":"...","token":"..."}`). Its directory has mode 0700 and the file mode 0600.
  Every write re-applies those modes. Only `login` and `logout` write it, atomically
  (temp file plus rename). If the file's mode is looser, a warning is printed.
- When `COFFER_TOKEN` is set, the config file is never read or written, and that
  includes its `url`. This holds even if the variable is empty, in which case commands
  exit 3. `coffer login` exits 2 while `COFFER_TOKEN` is set. Whitespace around the
  token is trimmed. A token with spaces or control characters exits 3 without sending
  a request.
- A URL must be `http://` or `https://` with a host. Credentials, a query or a
  fragment make it a usage error (exit 2).
- **Passwords** are read from stdin only, never from argv:
  - On a terminal, the CLI prompts on stderr with echo turned off. Ctrl-C restores
    echo and exits 130.
  - Otherwise it reads the first line of stdin and strips the trailing `\n` or `\r\n`.
  - An empty line exits 2 with no request, so it never counts toward the login lockout.
  - A password over 1024 bytes, or not valid UTF-8, exits 6.

## Global conventions

- `--url URL`, `--json` and `--help`/`-h` can go anywhere on the command line, even
  before the command words. Secret commands take `-p/--project` and `-e/--env`.
- Flags work as `--flag value` or `--flag=value` (`-p=x` works too). `--` ends flag
  parsing. A flag the command doesn't accept, a missing argument or an extra argument
  is a usage error (exit 2).
- `--json` prints exactly one JSON document to stdout. Usually that is the server's
  response, re-indented with its key order kept. The exceptions are documented per
  command below.
- **Errors** go to stderr as `error: <message> (<code>)`, and stdout stays empty
  when a command fails. With `--json`, stderr also gets the document
  `{"error":{"code":"...","message":"..."}}`. It carries the server's `code` and
  `message` unchanged (the message has no `(<code>)` suffix). Errors the CLI detects
  itself use the codes `usage`, `validation`, `connection`, `unauthenticated`,
  `not_found` and `error`. A server error without a code gets `http_<status>`.
- **Human output:** tables are tab-separated with a header line. Control characters,
  bidi overrides and invalid UTF-8 in text from the server are shown escaped (for
  example `\x1b`). Secret values from `secrets get` and `secrets export` are never
  altered.
- **HTTP:** requests time out after 30 s. Redirects are never followed (a 3xx exits 1),
  and response bodies are capped at 64 MiB. `login` warns on stderr when it sends
  credentials over plain `http://` to a host that isn't loopback.
- **Local validation:** some mistakes are caught before any request is sent:
  - a non-integer `--version`, `--expect-version` or `--to`: exit 6;
  - an invalid `--ttl`: exit 6;
  - a key, slug or id that is empty, `.` or `..`: exit 6.

  `--limit`, `--since`, `--status` and `--format` values go to the server unchecked,
  and its 400 becomes exit 6.

## Commands

```
coffer login --email EMAIL [--url URL]            # password on stdin
coffer logout                                      # revokes the PAT server-side, then removes it locally
coffer whoami
coffer passwd                                      # stdin: current password line, then new password line

coffer admin org create SLUG --owner-email EMAIL   # platform admin only; owner password on stdin
coffer admin org list
coffer admin org disable SLUG
coffer admin audit list [--limit N]                # platform log
coffer admin audit verify

coffer member add EMAIL --role member|admin|owner  # initial password on stdin
coffer member list
coffer member role EMAIL member|admin|owner
coffer member remove EMAIL
coffer grant set EMAIL -p PROJECT --level viewer|reader|writer
coffer grant revoke EMAIL -p PROJECT

coffer project create SLUG
coffer project list
coffer env create SLUG -p PROJECT [--protected]
coffer env list -p PROJECT

coffer secrets list -p P -e E
coffer secrets get KEY -p P -e E [--version N]
coffer secrets set KEY [VALUE] -p P -e E [--expect-version N]   # no VALUE: read stdin to EOF, bytes exact
coffer secrets delete KEY -p P -e E [--expect-version N]
coffer secrets history KEY -p P -e E
coffer secrets rollback KEY --to N -p P -e E [--expect-version N]
coffer secrets export -p P -e E [--format dotenv|json]           # default json
coffer run -p P -e E -- COMMAND [ARGS...]

coffer change list [--status pending|approved|rejected|stale]
coffer change approve ID
coffer change reject ID

coffer token create -p P -e E --access read|read-write --ttl DURATION [--name NAME]
coffer token list
coffer token revoke ID

coffer audit list [--actor ID] [--action NAME] [--since RFC3339] [--limit N]
coffer audit verify

coffer help [COMMAND...]
coffer version
```

`coffer --help`, `coffer -h`, `coffer help` and `coffer COMMAND --help` print help and
exit 0. `coffer` with no arguments exits 2.

### Authentication

- **`login`** POSTs the email and the password from stdin to `/auth/token`. It stores
  `{url, token}` in the config file and prints `logged in as EMAIL`. With `--json` it
  prints the server response without the token. A returned token that doesn't start
  with `cof_pat_` exits 1. Logging in again replaces the stored session.
- **`logout`** revokes the PAT on the server, then removes it locally:
  - A 401 (token already invalid) still removes the local token and exits 0.
  - A network error or 5xx keeps the token (it may still be valid) and exits with the
    mapped code.
  - With no stored token it prints `not logged in` and exits 0.
  - With `COFFER_TOKEN` set it only calls the server.
  - `--json` prints `{"status":"logged_out"}` or `{"status":"not_logged_in"}`.
- **`whoami`** shows `GET /me`: the type, id, email, role and org for a user, or the
  project, env, access and expiry for a service token.
- **`passwd`** (P1) reads the current password line, then the new password line. A
  wrong current password exits 4 and counts toward the login lockout. A new password
  that breaks the policy (at least 12 characters), or equals the current one, exits 6.
  On success the user's other PATs are revoked.

### Administration

- **`admin org create SLUG --owner-email EMAIL`** (platform admin only) reads the owner's
  initial password from stdin. A duplicate slug or an email already in use exits 8.
  Every `admin ...` command run by anyone other than the platform admin exits 5.
- **`admin org disable SLUG`** is idempotent. The org's users and tokens get 401
  (exit 3) on their next request.
- **`member role|remove EMAIL`** and **`grant set|revoke EMAIL`** look up the email
  (case-insensitive) with `GET /members`, then call the route that takes the user id.
  If no member has that email, the command exits 5. `member add` reads the initial
  password from stdin.
- **Rules enforced by the server** (exit codes in parentheses):
  - Only owners manage owners (4).
  - Nobody can change their own role, remove themself, or grant to themself (4).
  - The last owner can't be demoted or removed (8).
  - Grants apply only to members (6).
  - Promoting a member to admin or owner drops their grants.

### Secrets

- **`secrets list`** prints KEY, VERSION, UPDATED_AT and UPDATED_BY, never values.
  Deleted keys are not listed.
- **`secrets get`:** when stdout is not a terminal, it writes the exact value bytes with
  no newline, so `$(coffer secrets get ...)` and `> file` are byte-exact. On a terminal
  it adds one newline. `--json` prints `{"key","version","value"}`. `--version N`
  reads version N through `/versions/N`. A deleted key, or a tombstone version, exits 5.
- **`secrets set KEY [VALUE]`:** with no VALUE, it reads stdin to EOF, byte-exact, with
  no trimming; on a terminal it prints a Ctrl-D hint on stderr. A value that isn't valid
  UTF-8, or is larger than 65,536 bytes, exits 6 before any request is sent. Use `--`
  for a value that starts with `-`. The value always travels in the JSON request body,
  never in the URL. A mismatched `--expect-version N` exits 8 (`0` means "the key must
  never have existed").
- **`secrets delete`** writes a tombstone version. A key that is absent or already
  deleted exits 5. Version numbering continues after a delete.
- **`secrets history`** lists every version, including tombstones (VERSION, DELETED,
  CREATED_AT, CREATED_BY).
- **`secrets rollback KEY --to N`** creates a new version holding version N's value. A
  deleted key can be rolled back too. N must exist and must not be a tombstone
  (otherwise exit 5).
- **Write output:** `set KEY (version N)`, `deleted KEY (version N)` or
  `rolled back KEY (version N)`. With `--json`, the server body `{"version":N}` is
  printed.
- **Protected environments:** any write (set, delete, rollback) prints
  `pending approval: change <id>` and exits 7. With `--json` it prints
  `{"status":"pending","change_id":"<id>"}`.

### Export

`secrets export -p P -e E --format dotenv|json` writes every current secret, sorted by
key. `--format` defaults to `json`.

- `--format json`: one object mapping key to value, printed as the server sent it,
  with a trailing newline.
- `--format dotenv`: one `KEY="VALUE"` line per secret, LF endings, and a final newline.
  Inside the quotes, `\` → `\\`, `"` → `\"`, newline → `\n`, CR → `\r` and `$` → `\$`.
  Nothing else is escaped. The output is byte-exact.
- **`--json` with `--format dotenv`:** because `--json` promises exactly one JSON
  document, the dotenv text is wrapped:

  ```json
  {
    "content": "API_KEY=\"abc\"\nDB_URL=\"postgres://u:p@db/app\"\n",
    "format": "dotenv"
  }
  ```

  `content` holds the dotenv body byte for byte, as a JSON string. If the server body is
  not valid UTF-8 (which can't happen for SPEC-conformant values), the command exits 1
  and prints nothing on stdout. `--json` with `--format json` prints the json export
  unchanged.

### `run`

`coffer run -p P -e E -- COMMAND [ARGS...]` fetches `export?format=json` and starts
COMMAND:

- The child's environment is the current environment plus every secret in the env.
  Secrets win on a name conflict.
- COMMAND is looked up with the CLI's own `PATH`, not a `PATH` secret.
- stdin, stdout and stderr are inherited. `--json` has no effect, because the child
  owns stdout.
- SIGINT, SIGTERM, SIGHUP and SIGQUIT are forwarded to the child. On a terminal,
  Ctrl-C reaches the child both directly and through forwarding.
- **Exit code:** the child's own, or 128+N if signal N killed it. 127 if COMMAND
  can't be found, 126 if it can't be executed.
- If the fetch fails, the child is not started and the CLI exits with the mapped code
  (for example 5 or 4).
- **NUL values:** if any secret value contains a NUL byte (U+0000), or a key can't be an
  environment variable name, `run` exits 1 without starting COMMAND. The error names
  the key, never the value. POSIX environment strings can't carry NUL, so the value
  would otherwise be cut short silently. The server still stores, returns and exports
  such values exactly: use `secrets get` or `secrets export --format json` for them
  (DECISIONS 62).
- Nothing is written to disk. `--` is optional: flag parsing stops at the first
  positional argument, so flags after COMMAND go to the child.

### Change requests

- **`change list [--status S]`** prints ID, PROJECT, ENV, KEY, OP, STATUS, PROPOSED_BY,
  CREATED_AT, DECIDED_BY and APPLIED_VERSION, newest first. Owners and admins see every
  change. Members see only their own proposals in projects they still have access to.
  Service tokens get exit 4.
- **`change approve ID`** (owner or admin, and not the proposer: otherwise exit 4)
  applies the change and prints `approved change <id> (version N)`. It exits 8 if the
  change isn't pending, if the key changed since the proposal, or if the proposer can no
  longer write that secret. In the last two cases the change becomes `stale`.
- **`change reject ID`** (owner or admin; the proposer may reject their own change)
  prints `rejected change <id>`. It exits 8 if the change isn't pending.

### Service tokens

- **`token create`** (owner or admin) prints the token alone on stdout. This is the
  only time it is shown. `id:` and `expires_at:` go to stderr, so
  `TOKEN=$(coffer token create ...)` captures exactly the token. `--ttl` is
  `<int><s|m|h|d>`, between 1m and 90d; any other value exits 6 locally. `--name` is
  optional (at most 100 characters). With `--json` it prints the server body,
  `{id, token, name, project, env, access, expires_at}`.
- **`token list`** shows service tokens only (never their hashes), newest first.
- **`token revoke ID`** takes effect on the token's next request and is idempotent. An
  unknown id, or a PAT's id, exits 5.

### Audit

- **`audit list`** (owner or admin) and **`admin audit list`** (platform admin) print
  SEQ, TS, ACTOR (`type:id`), ACTION, TARGET, RESULT and SOURCE_IP, newest first.
  `--limit` defaults to 100 (maximum 1000). `--actor` and `--action` are exact matches,
  and `--since` is an RFC 3339 timestamp.
- **`audit verify`** and **`admin audit verify`** recompute the hash chain. They print
  `chain valid`, or `chain invalid at seq N` and exit 9. `--json` prints
  `{"valid":...,"first_invalid_seq":...}` (exit 9 when invalid).

## Examples

```sh
printf '%s\n' "$PASSWORD" | coffer login --email alice@acme.example --url http://127.0.0.1:8420
coffer project create web
coffer env create dev -p web
coffer env create prod -p web --protected
printf 'postgres://u:p@db/app' | coffer secrets set DATABASE_URL -p web -e dev
coffer secrets get DATABASE_URL -p web -e dev > db_url.txt
coffer secrets export -p web -e dev --format dotenv > .env.dev
coffer --json secrets export -p web -e dev --format dotenv | jq -r .content
coffer run -p web -e dev -- ./server --port 8080
TOKEN=$(coffer token create -p web -e dev --access read --ttl 7d --name ci)
COFFER_TOKEN=$TOKEN coffer secrets list -p web -e dev --json
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | other error (connection failure, timeout, redirect, 5xx, unexpected response, `run` refused a NUL value) |
| 2 | usage error (unknown flag, missing or extra argument, bad URL, empty password line, `login` while `COFFER_TOKEN` is set) |
| 3 | unauthenticated (401, no token, or an invalid `COFFER_TOKEN`) |
| 4 | forbidden (403) |
| 5 | not found (404, or no member with that email) |
| 6 | validation (400 / 413 / 422, or invalid input detected locally) |
| 7 | pending approval (202) |
| 8 | conflict (409) |
| 9 | audit chain invalid |
| 10 | rate limited (429, login lockout) |

`run` exits with the child's code instead, or 128+N if signal N killed the child, 127 if
the command can't be found, and 126 if it can't be executed.
