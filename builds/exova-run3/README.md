# Coffer

Coffer is a self-hosted secrets and configuration service for an engineering organization:
one server with an HTTP API, one CLI, no web interface. Teams store API keys, database
passwords and config values per project and environment; people and CI read them with least
privilege, and every access is written to an append-only, hash-chained audit log.

Secrets are encrypted at rest with envelope encryption (a per-project data key, wrapped by
`COFFER_MASTER_KEY`, encrypting values with AES-256-GCM). The database holds only ciphertext.

- [Prerequisites](#prerequisites)
- [Quickstart](#quickstart)
- [What the platform admin does](#what-the-platform-admin-does)
- [Everyday use](#everyday-use)
- [Operations](#operations)
- [Backup and restore](#backup-and-restore)
- [Configuration](#configuration)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

## Prerequisites

| Requirement | Why | Notes |
|---|---|---|
| A container runtime | runs the server and PostgreSQL | Docker or Podman. Rootless Podman is fine and is what this repo is tested on. |
| A compose implementation | starts the stack | `docker compose`, `podman compose` or `podman-compose` (1.6.0 or newer). On hosts where `docker` is a shim for Podman, `docker compose` runs podman-compose. |
| `openssl` | `./scripts/init-env.sh` generates the master key and passwords | Any recent version; `openssl rand -base64 32` must produce 44 characters. |
| `curl` or `wget` | `./scripts/up.sh` polls `/readyz` | One of the two; `curl` is preferred because it reports the HTTP status. |
| `gzip` | `./scripts/backup.sh` and `./scripts/restore.sh` | Ships with any normal system. |
| Go 1.27+ (**optional**) | building the CLI on the host | **Optional.** If `go` is not installed, `./scripts/build.sh` falls back to the pinned `golang:1.27.3-bookworm` container and produces the same `./bin/coffer`. No other toolchain (Node, Python, JVM) is needed at any point. |

Ports: the server is published on `127.0.0.1:${COFFER_PORT:-8420}` only, where
`COFFER_PORT` comes from `.env` (`./scripts/init-env.sh` sets `8420`). The CLI defaults to
`http://127.0.0.1:8420`; if you change `COFFER_PORT`, pass `--url http://127.0.0.1:$COFFER_PORT`
to the CLI or export `COFFER_URL`. PostgreSQL is **not** published to the host. Nothing is
reachable from outside the machine.

## Quickstart

From a clean clone to a working `coffer secrets get`, in ten commands. They work verbatim in
one shell session, in this order; no step needs interactive input.

```sh
1  ./scripts/init-env.sh
2  ./scripts/up.sh
3  ./scripts/build.sh
4  sed -n 's/^COFFER_BOOTSTRAP_ADMIN_PASSWORD=//p' .env | ./bin/coffer login --email admin@coffer.local
5  printf 'owner-password-123456\n' | ./bin/coffer admin org create acme --owner-email owner@acme.test
6  printf 'owner-password-123456\n' | ./bin/coffer login --email owner@acme.test
7  printf 'owner-password-123456\nnew-owner-password-123456\n' | ./bin/coffer passwd
8  ./bin/coffer project create demo && ./bin/coffer env create dev -p demo
9  printf 'hello-from-coffer' | ./bin/coffer secrets set GREETING -p demo -e dev
10 ./bin/coffer secrets get GREETING -p demo -e dev
```

Step 10 prints `hello-from-coffer` and nothing else: when stdout is not a TTY, `secrets get`
writes the exact value bytes with no added newline, so `| od -c` shows the seventeen
characters of the value and no `\n`.

What each one does, and the two behaviours that are easy to trip over:

1. **`./scripts/init-env.sh`** writes `.env` (mode 0600) from `.env.example` with a freshly
   generated master key, a fresh platform-admin password and fresh database passwords, then
   prints the admin password **once**. It refuses to overwrite an existing `.env` — replacing
   the master key would make every stored secret undecryptable.
2. **`./scripts/up.sh`** builds the images, starts `db` and `server`, and polls
   `http://127.0.0.1:${COFFER_PORT:-8420}/readyz` once a second for up to 180 seconds. It
   returns as soon as `/readyz` answers 200. If it cannot, it names the failing dependency and
   prints the last `/readyz` status and body plus the logs of both services.
3. **`./scripts/build.sh`** produces `./bin/coffer` (Linux x86_64, statically linked) and
   prints which path it took: the host Go toolchain, or the pinned container image.
4. **`coffer login`** reads the password from **stdin**, never from an argument, and stores a
   personal access token in `${XDG_CONFIG_HOME:-$HOME/.config}/coffer/` (directory 0700, file
   0600). Here the password comes straight out of `.env` so the step is scriptable. This
   signs in as the **platform admin**, which can create organizations and nothing inside them.
5. **`admin org create acme --owner-email owner@acme.test`** creates an organization and its
   first owner. The platform admin is the only account that can do this, and the owner's
   initial password is read from stdin. The password literal is repeated in steps 5–7 on
   purpose: it keeps the block copy-pasteable with no shell variables. It must be at least 12
   characters.
6. **`coffer login --email owner@acme.test`** switches to the new owner. It prints
   `Your password must be changed before you can use the service: run 'coffer passwd'`.
   **This is not a warning you can skip:** an account whose initial password was chosen by
   someone else must change it before any other route works, so step 7 is required.
7. **`coffer passwd`** reads two lines from stdin — the current password, then the new one —
   and clears the gate. Skipping it makes step 8 fail with exit code 4.
8. **`project create demo` then `env create dev -p demo`** — a project, and an environment
   inside it. Projects and environments are organization-scoped, which is why the platform
   admin from step 4 cannot create them (every organization-scoped route answers 404 to the
   platform admin) and step 6 has to happen first.
9. **`secrets set GREETING`** with no value argument reads the value from stdin to EOF,
   byte-exact, so `printf` (not `echo`) is used to avoid a trailing newline.
10. **`secrets get GREETING`** prints the exact value bytes.

`/healthz` returns 200 whenever the process is up; `/readyz` returns 200 only when the
database is reachable and migrations are applied, and 503 otherwise (it recovers by itself).

## What the platform admin does

The platform admin account is created on first boot from `COFFER_BOOTSTRAP_ADMIN_EMAIL` and
`COFFER_BOOTSTRAP_ADMIN_PASSWORD`, and only when no users exist yet.

**The platform admin creates organizations, and creates each organization's first owner.**
It cannot read any organization's secrets, members, tokens or audit log — every
organization-scoped route answers 404 to it. Its own audit log (the platform log) is the one
it can read.

So the first organization is created by the platform admin, with its owner's password on
stdin:

```sh
printf '%s' 'a-first-owner-password' | ./bin/coffer admin org create acme --owner-email owner@acme.test
```

The owner of that organization can then add members, create projects and grant access. A user
belongs to exactly one organization.

## Everyday use

```sh
./bin/coffer whoami
./bin/coffer project list
./bin/coffer env list -p demo
./bin/coffer secrets list -p demo -e dev
./bin/coffer secrets get GREETING -p demo -e dev --version 1
./bin/coffer secrets history GREETING -p demo -e dev
./bin/coffer secrets export -p demo -e dev --format dotenv
./bin/coffer run -p demo -e dev -- ./my-service --flag
```

`coffer run` puts every secret in the environment into the child's environment (secrets win
on a name conflict), inherits stdin/stdout/stderr, forwards SIGINT and SIGTERM, and writes
nothing to disk.

Machine credentials for CI are service tokens, scoped to exactly one project and environment,
with an expiry:

```sh
./bin/coffer token create -p demo -e dev --access read --ttl 30d --name ci
```

The token is printed once. In CI, set `COFFER_TOKEN` (and `COFFER_URL` if the server is not on
`http://127.0.0.1:8420`); when `COFFER_TOKEN` is set, no CLI config file is read or written.

Writes to a **protected** environment do not take effect immediately: they create a change
request (HTTP 202, CLI exit code 7) that a second owner or admin must approve.

Add `--json` to any command for exactly one JSON document on stdout. Errors go to stderr.
Exit codes: 0 success, 1 other error, 2 usage, 3 unauthenticated, 4 forbidden, 5 not found,
6 validation, 7 pending approval, 8 conflict, 9 audit chain invalid, 10 rate limited.

## Operations

| Script | What it does |
|---|---|
| `./scripts/init-env.sh` | Creates `.env` with fresh secrets; prints the admin password once; never overwrites. |
| `./scripts/up.sh` | Starts the stack, waits for `/readyz` 200 (180 s), and names the failing dependency if it never arrives. |
| `./scripts/down.sh` | Stops the stack and **keeps the data**. |
| `./scripts/build.sh` | Produces `./bin/coffer`. |
| `./scripts/test.sh` | Runs the test suite. Exit 0 means pass. |
| `./scripts/backup.sh FILE` | Dumps the database to FILE (gzip). |
| `./scripts/restore.sh FILE` | Restores the database from FILE. |

`./scripts/down.sh` never passes `-v`, so the `db_data` volume survives: every secret version
and every audit event is still there when `./scripts/up.sh` brings the stack back.

The stack is a two-service `compose.yaml`: `db` (`postgres:16`, named volume, healthcheck via
`pg_isready`, never published to the host) and `server` (built from `./Dockerfile`, runs as
UID 10001, published on `127.0.0.1:8420`). Healthchecks live in the compose file rather than
the Dockerfile because podman's default OCI image format silently drops a `HEALTHCHECK`
instruction. The server also retries its database connection at boot, so the stack comes up
even on a runtime that ignores `depends_on`.

Server logs are JSON lines on stdout: one per request, with method, route, status,
`duration_ms` and `request_id`. Every response carries `X-Request-Id`. No value, password,
token, cookie or `Authorization` header is ever logged.

## Backup and restore

Back up:

```sh
./scripts/backup.sh backup.sql.gz
```

The dump is produced by the **container's** `pg_dump` (16.15), not the host's — a newer
client's dump can carry settings the 16 server rejects. The file contains only ciphertext, so
it is useless without the same `COFFER_MASTER_KEY`. Keep the master key separate from the
backups.

Restore into an empty stack **with the same master key**:

```sh
./scripts/restore.sh backup.sql.gz
```

`restore.sh` stops the server, drops and recreates the `public` schema, loads the dump
verbatim with `ON_ERROR_STOP=1`, and starts the stack again. It deliberately does **not**
validate the audit hash chain: a restore has to be able to reproduce a tampered dump so that
verification can report the tampering, so it cannot be the step that declares a restore good.

**The restore is not complete until `./bin/coffer audit verify` reports the chain valid.**
`restore.sh` prints that command on success; run it. If it reports an invalid chain, the dump
was altered — restore a known-good backup instead of trusting the data.

## Configuration

All configuration comes from environment variables, documented one line each in
`.env.example`. The compose stack reads `.env`; a process started on the host reads the same
variables from its environment.

| Variable | Required | Purpose |
|---|---|---|
| `COFFER_MASTER_KEY` | yes | base64 of exactly 32 bytes; wraps every project's data key. The server refuses to start while it holds the `.env.example` placeholder. |
| `COFFER_MASTER_KEY_PREVIOUS` | no | set only during key rotation |
| `COFFER_BOOTSTRAP_ADMIN_EMAIL` | yes | platform admin, created only when no users exist |
| `COFFER_BOOTSTRAP_ADMIN_PASSWORD` | yes | at least 12 characters |
| `COFFER_PORT` | no | **host** port the API is published on, default 8420; the process inside the container always listens on 8420 and compose maps `127.0.0.1:${COFFER_PORT}->8420`. It does not change the port the CLI dials — pass `--url` or set `COFFER_URL` if you change it |
| `COFFER_BIND_ADDR` | no | default `127.0.0.1`; compose sets `0.0.0.0` inside the container |
| `COFFER_TRUST_PROXY` | no | `1` enables rightmost-untrusted `X-Forwarded-For` |
| `COFFER_ENV` | no | `production` (default) or `development` |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | yes | owner role and database name |
| `COFFER_APP_DB_PASSWORD` | no | password for the `coffer_app` runtime role, which cannot `UPDATE` or `DELETE` audit rows |
| `COFFER_MIGRATION_DATABASE_URL` | no | overrides the derived owner URL |
| `DATABASE_URL` | no | overrides the derived runtime URL |
| `COFFER_DB_HOST` / `COFFER_DB_PORT` / `COFFER_DB_SSLMODE` | no | defaults `127.0.0.1` / `5432` / `disable` |
| `COFFER_ALLOW_DEGRADED_DB_ROLE` | no | `1` opts into single-role boot; refused when `COFFER_ENV=production` |

`.env` is gitignored and must stay that way: it holds the master key and the database
passwords. `.env.example` is committed and holds key names with placeholders only.

To rotate the master key: set `COFFER_MASTER_KEY_PREVIOUS` to the old value and
`COFFER_MASTER_KEY` to the new one, restart, and wait for `/readyz` — every data key is
re-wrapped under the new key before the server reports ready. Then remove
`COFFER_MASTER_KEY_PREVIOUS`.

## Development

```sh
./scripts/test.sh
```

Runs `go test ./...` against a real PostgreSQL 16. With `COFFER_TEST_DATABASE_URL` set it uses
that database and starts nothing; otherwise it starts a throwaway `postgres:16` container on a
random loopback port and removes it afterwards. The compose `db` service is not published to
the host, so it cannot be reused without opening a port. If no host Go toolchain is installed,
the suite runs inside the pinned `golang:1.27.3-bookworm` container.

CI (`.github/workflows/ci.yml`) runs `gofmt -l` (failing on any output), `go vet ./...`, the
tests against a `postgres:16` service container, `go build ./...`, `./scripts/build.sh`, and
`govulncheck`.

Layout: `cmd/coffer` is the CLI, `internal/httpapi` the composition root and HTTP server,
`internal/api/*` the route slices, `internal/store/*` the database layer, `internal/crypto`
envelope encryption, `internal/audit` the hash chain, `internal/config` environment parsing.

## Troubleshooting

- **`./scripts/up.sh` fails and names `db`** — the database never became healthy. Run
  `docker compose logs db` (or `podman compose logs db`). A `db_data` volume created by an
  older PostgreSQL major version cannot be opened by `postgres:16`; `./scripts/down.sh` keeps
  it on purpose, so remove the volume by hand only if you accept losing the data.
- **`/readyz` returns 503 with `"reason":"database"`** — the server is up and cannot reach
  PostgreSQL. Check `docker compose exec -T db pg_isready`.
- **`/readyz` returns 503 with `"reason":"migrations"`** — migrations have not finished or
  failed; the server logs name the migration.
- **`permission denied` running `./scripts/*.sh`** — the executable bit was lost in the
  checkout: `chmod +x scripts/*.sh`.
- **`coffer: command not found`** — the CLI is `./bin/coffer`; run `./scripts/build.sh` first.
- **`the server refuses to start naming COFFER_MASTER_KEY`** — `.env` still holds the
  placeholder. Run `./scripts/init-env.sh` on a fresh tree, or put a real
  `openssl rand -base64 32` value in it.
- **A login returns 429** — five failed logins within 15 minutes lock that account for the
  rest of the window, even with the correct password. Other accounts are unaffected.
