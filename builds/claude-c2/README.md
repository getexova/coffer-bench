# Coffer

Coffer is a self-hosted secrets and configuration service for an engineering
organization: a Go HTTP API server backed by PostgreSQL, plus a CLI (`coffer`).
Teams store API keys, database passwords and config values per **project** and
**environment**; people and CI read them with least privilege, and every access is
recorded in a tamper-evident, hash-chained audit log. There is no web interface.

- Multi-tenant: organizations are hard tenant boundaries; anything outside yours is a 404.
- Roles `owner` / `admin` / `member`, per-project grants `viewer` / `reader` / `writer`.
- Versioned secrets with tombstones, rollback and optimistic concurrency.
- Envelope encryption (AES-256-GCM): a master key wraps a data key per project; each
  ciphertext is bound to its org, project, environment, key and version.
- Scoped, expiring service tokens for CI; protected environments with two-person approval.
- Per-organization SHA-256 audit hash chains with verification.

## Prerequisites

| Need | Version | Used by |
|---|---|---|
| A container runtime **with compose**: either **podman** >= 4 with **podman-compose** >= 1.0 (so `podman compose` works), or **Docker** with the **compose v2** plugin (`docker compose`). `docker-compose` / `podman-compose` also work. | | `up.sh`, `down.sh`, `backup.sh`, `restore.sh`, `test.sh` (throwaway test DB) |
| **bash** >= 4, coreutils (`head`, `tail`, `cut`, `tr`, `base64`, `mktemp`, `wc`, `seq`, ...), `grep`, `sed`, `awk` | | all scripts |
| **curl** | any | `up.sh`, `restore.sh` (polling `/readyz`) |
| **tar** | any | `build.sh` (when it builds in a container, the binary is streamed out with tar) |
| **Go** >= 1.26 **or** the container runtime above | | `build.sh` and `test.sh`. Without a local Go >= 1.26 they run inside the pinned `docker.io/library/golang:1.26.10-alpine3.24@sha256:a201…` image. |
| findutils (`xargs`) | any | `test.sh` with a local Go (gofmt check), `check-env-docs.sh` |
| **git** | any | cloning |
| openssl | optional | `init-env.sh` and key rotation (falls back to `/dev/urandom` + `base64`) |
| python3 | optional | only `scripts/ops-smoke.sh` |

The CLI is a single static Linux x86_64 binary with no runtime dependencies. These
images are pulled automatically on first run:
- `docker.io/library/postgres:16` (db, and the throwaway test database)
- `docker.io/library/golang:1.26.10-alpine3.24` (server build stage, and `build.sh`/`test.sh` without a local Go)
- `gcr.io/distroless/static-debian12:nonroot` (server runtime)

The Go and distroless images are pinned by digest in the `Dockerfile` and scripts. The
first `up.sh` needs network access to pull them and the Go modules. Port
`127.0.0.1:8420` must be free; otherwise set `COFFER_PORT` in `.env`, and set
`COFFER_URL=http://127.0.0.1:<port>` (or pass `--url`) for the CLI.

## Quickstart

Ten commands take a clean clone to a working `coffer secrets get`. Copy and paste each
line as is, one command per line. `<REPO_URL>` is wherever you got this repository
from; there is no public canonical URL.

```bash
git clone <REPO_URL> coffer
cd coffer
./scripts/up.sh
grep '^COFFER_BOOTSTRAP_ADMIN_PASSWORD=' .env | cut -d= -f2- | ./bin/coffer login --email admin@example.com
echo 'correct-horse-battery-staple' | ./bin/coffer admin org create acme --owner-email owner@acme.example
echo 'correct-horse-battery-staple' | ./bin/coffer login --email owner@acme.example
./bin/coffer project create web
./bin/coffer env create dev -p web
./bin/coffer secrets set DATABASE_URL 'postgres://app:pw@db/app' -p web -e dev
./bin/coffer secrets get DATABASE_URL -p web -e dev
```

What each step does:

1. Clone the repository.
2. Enter it. Every script also works when called from any other directory.
3. Start everything. Because there is no `.env` yet, `up.sh` first runs
   `./scripts/init-env.sh`. That creates `.env` (mode 0600) from `.env.example` with a
   fresh random master key, bootstrap admin password and Postgres password, and prints
   the admin password once. The admin email is `admin@example.com`. `up.sh` then builds
   the server image, starts `server` and `db`, and waits until
   `http://127.0.0.1:8420/readyz` returns 200 (it fails after 180 s and prints the server
   logs). Finally it builds the CLI as `./bin/coffer` with `./scripts/build.sh`.
   You can also run `./scripts/init-env.sh` and `./scripts/build.sh` on their own.
4. Log in as the platform admin. The password is read from stdin, never from argv. The
   CLI stores its token in `${XDG_CONFIG_HOME:-~/.config}/coffer/config.json` (mode 0600).
5. As platform admin, create organization `acme` and its first owner. The platform
   admin can manage organizations but can never see any organization's data.
6. Log in as that owner. This replaces the admin session in the CLI config.
7. Create project `web`.
8. Create environment `dev` in it.
9. Store a secret. This creates version 1.
10. Read it back. When stdout is not a terminal, the exact value bytes are written with
    no trailing newline, so `$(./bin/coffer secrets get ...)` is safe.

Stop with `./scripts/down.sh`. The data is kept in the `pgdata` volume, and
`./scripts/up.sh` brings it back.

## CLI overview

Full reference: [docs/CLI.md](docs/CLI.md). The global flags `--url URL` and `--json`
work anywhere, and secret commands take `-p/--project` and `-e/--env`. `COFFER_URL`
sets the server. `COFFER_TOKEN` supplies a PAT or service token; while it is set, the
config file is neither read nor written. `--json` always prints exactly one JSON
document. For `secrets export --format dotenv` that document is
`{"content":"<dotenv text>","format":"dotenv"}`.

```bash
coffer whoami
coffer member add dev@acme.example --role member < initial-password.txt
coffer grant set dev@acme.example -p web --level reader
coffer secrets list -p web -e dev
coffer secrets set API_KEY -p web -e dev < api-key.txt        # value from stdin, bytes exact
coffer secrets history API_KEY -p web -e dev
coffer secrets rollback API_KEY --to 1 -p web -e dev
coffer secrets export -p web -e dev --format dotenv
coffer run -p web -e dev -- ./my-app                            # secrets injected as env vars (refuses NUL values)
coffer audit list --limit 20
coffer audit verify
```

Exit codes: 0 ok, 1 other error, 2 usage, 3 unauthenticated, 4 forbidden, 5 not found,
6 validation, 7 pending approval, 8 conflict, 9 audit chain invalid, 10 rate limited.

## Service tokens and CI

A service token is scoped to exactly one project and environment, has `read` or
`read-write` access, and always expires (1 minute to 90 days). Owners and admins issue them:

```bash
coffer token create -p web -e prod --access read --ttl 7d --name github-deploy
# prints the token once (cof_st_...) on stdout; its id and expiry go to stderr
coffer token list
coffer token revoke tok_...
```

In CI, store the token as a CI secret and use it via the environment:

```bash
export COFFER_URL=https://coffer.internal.example   # behind your TLS reverse proxy
export COFFER_TOKEN="$COFFER_SERVICE_TOKEN"
coffer run -p web -e prod -- ./deploy.sh
DB_URL="$(coffer secrets get DATABASE_URL -p web -e prod)"
```

Service tokens can only perform secret operations inside their scope. They can never
manage members, issue tokens, approve changes, read the audit log or create PATs.
Revocation and expiry take effect on the very next request.

## Protected environments and approvals

```bash
coffer env create prod -p web --protected
coffer secrets set DATABASE_URL 'postgres://...' -p web -e prod   # prints "pending approval: change chg_...", exit 7
coffer change list --status pending
coffer change approve chg_...    # a different owner/admin than the proposer
coffer change reject chg_...
```

Every write (set, delete, rollback) to a protected environment becomes a change request.
Only an owner or admin who is **not** the proposer can approve it (the two-person rule;
it also covers changes proposed with a service token the approver created). Approval
fails with 409 and the request becomes `stale` in two cases:
- the key changed after the request was created;
- the proposer can no longer write that secret (removed, demoted, grant lowered, or
  token revoked or expired).

Members can list their own proposals.

## Backup and restore

```bash
./scripts/backup.sh /secure/place/coffer-2026-10-30.dump   # pg_dump -Fc, mode 0600, stack may be running
./scripts/restore.sh /secure/place/coffer-2026-10-30.dump  # replaces the database (only after the file restored cleanly)
```

- The dump contains only ciphertext, password hashes and token hashes. **The master key
  is not in the backup.** Store `COFFER_MASTER_KEY` separately, for example in a
  password manager or a vault. A backup without its master key can't be decrypted.
- `backup.sh` starts `db` if needed and writes the dump through a 0600 temp file.
- `restore.sh`:
  1. Checks that the file is a `pg_dump` custom-format dump.
  2. Starts `db` and stops `server`.
  3. Drops and recreates the database.
  4. Runs `pg_restore --single-transaction`.
  5. Recreates `server` from the current `.env` and waits for `/readyz`.
- **Same machine:** run `./scripts/restore.sh FILE`. The `.env` must still hold the
  master key the backup was made with. If you have rotated since, restore with the old
  key, then rotate again.
- **New machine, or a fresh volume:**
  1. Clone the repository.
  2. Run `./scripts/init-env.sh`.
  3. Replace `COFFER_MASTER_KEY` in `.env` with the original stack's key.
  4. Run `./scripts/restore.sh FILE`.
  5. Run `./scripts/build.sh` for the CLI.

  You may copy the whole original `.env` instead, but only while no `pgdata` volume
  exists yet for this checkout. An existing volume keeps the Postgres password it was
  created with, and it won't accept a different `POSTGRES_PASSWORD`. In that case,
  copy only `COFFER_MASTER_KEY`.
- If the master key doesn't match, the server refuses to start and logs
  `master key does not match database`. `restore.sh` then fails after the readiness
  timeout and prints the server logs.
- After a restore, all secrets, versions, users, tokens and audit events are back, and
  `coffer audit verify` still reports `chain valid`. Users log in with the passwords
  they had in the backup. The bootstrap admin variables in `.env` are not applied,
  because users already exist.

## Master key rotation

1. Generate a new key: `openssl rand -base64 32` (or
   `head -c 32 /dev/urandom | base64`).
2. In `.env`, set `COFFER_MASTER_KEY_PREVIOUS=<current key>` and
   `COFFER_MASTER_KEY=<new key>`.
3. Run `./scripts/up.sh`. It always recreates the server container, so the new `.env`
   takes effect. Before `/readyz` turns 200, the server re-wraps every project data key
   under the new key in one transaction and logs `master key rotated`
   (`podman logs` / `docker logs` of the server container). Secret values themselves
   are not re-encrypted, because they are encrypted under the data keys, which don't
   change.
4. Remove the `COFFER_MASTER_KEY_PREVIOUS` line and run `./scripts/up.sh` again.
5. Take a fresh backup. Old backups still need the old key.

Rotation is idempotent: restarting with both keys still set is harmless. Existing
tokens and CLI sessions keep working. `./scripts/ops-smoke.sh` runs this whole flow
against a private, throwaway stack.

## Configuration

All configuration comes from environment variables (`.env`, read by compose).
[.env.example](.env.example) documents every variable, and
`./scripts/check-env-docs.sh` checks that.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `COFFER_MASTER_KEY` | yes | — | base64 of exactly 32 bytes. The placeholder from `.env.example` is rejected. |
| `COFFER_MASTER_KEY_PREVIOUS` | no | — | old master key, only during rotation |
| `COFFER_BOOTSTRAP_ADMIN_EMAIL` | yes | — | platform admin email (used only on first boot, when no users exist) |
| `COFFER_BOOTSTRAP_ADMIN_PASSWORD` | yes | — | platform admin password (>= 12 characters; checked on every boot) |
| `COFFER_PORT` | yes in `.env` | `8420` | host port, published on `127.0.0.1` only (compose setting; the server doesn't read it) |
| `COFFER_LISTEN_ADDR` | no | `:8420` | bind address inside the container (compose sets `:8420`; leave it) |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | yes | — | database owner credentials (also used by the `db` service) |
| `POSTGRES_HOST` / `POSTGRES_PORT` | no | `db` / `5432` | database address (compose sets them) |
| `POSTGRES_SSLMODE` | no | `disable` | libpq `sslmode` for the server's DB connection; ignored when `COFFER_DATABASE_URL` is set |
| `COFFER_DATABASE_URL` | no | — | full URL; overrides `POSTGRES_*` (used by tests) |
| `COFFER_TRUST_PROXY` | no | `false` | record the first `X-Forwarded-For` entry as the source IP (only behind a proxy that overwrites it) |
| `COFFER_PAT_TTL` | no | `720h` | lifetime of login tokens (Go duration, 1m..8760h) |
| `COFFER_ARGON2_MEMORY_KIB` | no | `65536` | argon2id memory (19456..4194304) |
| `COFFER_REQUIRE_PASSWORD_CHANGE` | no | `false` | force users created with an initial password to run `coffer passwd` first |

If a required variable is missing, the server exits 1 with
`config error: missing required environment variable NAME`. Changes to `.env` take
effect on the next `./scripts/up.sh`, which always recreates the server container.

**Script-only variables.** Set these in your shell, not in `.env`; the server never
reads them.

| Variable | Default | Effect |
|---|---|---|
| `COFFER_COMPOSE` | auto-detected | compose command, e.g. `podman-compose` or `docker compose` |
| `COFFER_CONTAINER_RUNTIME` | `podman` if installed, else `docker` | runtime for one-off containers in `build.sh`/`test.sh` |
| `COFFER_READY_TIMEOUT` | `180` | seconds `up.sh`/`restore.sh` wait for `/readyz` |
| `COFFER_SKIP_CLI_BUILD` | `0` | `1` = `up.sh` doesn't run `build.sh` |
| `COFFER_BUILD_IN_CONTAINER` | `0` | `1` = `build.sh` always builds in the pinned Go image |
| `COFFER_TEST_IN_CONTAINER` | `0` | `1` = `test.sh` always runs in the pinned Go image |
| `COFFER_TEST_DATABASE_URL` | unset | superuser DSN for the tests (otherwise a throwaway `postgres:16` is started) |
| `COFFER_E2E` | `0` | `1` = `test.sh` also builds the CLI and runs the e2e suite against the running stack |
| `COFFER_SMOKE_PORT` | a free port | host port for `ops-smoke.sh`'s private stack |

## Running tests

```bash
./scripts/test.sh                # gofmt check, go vet, go test -race ./... (incl. authorization tests)
COFFER_E2E=1 ./scripts/test.sh   # also the black-box e2e suite (needs ./scripts/up.sh first)
./scripts/check-env-docs.sh      # every variable read by the server/scripts is in .env.example
./scripts/ops-smoke.sh           # private stack: env propagation, rotation, down/up, backup/restore
```

If `COFFER_TEST_DATABASE_URL` is not set, `test.sh` starts a throwaway `postgres:16`
container on a free loopback port and always removes it on exit. Without a local Go
1.26 toolchain, the tests run inside the pinned `golang:1.26.10-alpine3.24` image,
which installs a C compiler on the fly for `-race`. The e2e suite talks to
`COFFER_E2E_URL` (default `http://127.0.0.1:8420`), drives `COFFER_E2E_CLI` (default
`./bin/coffer`) and logs in as `COFFER_E2E_ADMIN_EMAIL` / `COFFER_E2E_ADMIN_PASSWORD`
(default: `admin@example.com` and the password from `.env`). CI (`.github/workflows/ci.yml`) has these jobs:
- lint: gofmt, vet, `go mod verify`, golangci-lint, govulncheck, shellcheck and
  `check-env-docs.sh`;
- tests;
- build;
- quickstart/e2e plus `ops-smoke.sh`.

## Repository layout

```
cmd/coffer-server/     server entrypoint (also `coffer-server healthcheck`)
cmd/coffer/            CLI entrypoint
internal/server/       app (boot/run), config, crypto, db (+ embedded migrations), audit,
                       api (HTTP), testutil
internal/cli/          CLI implementation (standard library only)
test/e2e/              black-box end-to-end tests (build tag e2e)
scripts/               init-env, up, down, build, test, backup, restore (+ lib.sh,
                       check-env-docs, ops-smoke)
docs/                  CONTRACT (detailed design), ARCHITECTURE, SECURITY, DECISIONS, CLI
Dockerfile             multi-stage build -> distroless, non-root image
compose.yaml           server + db (postgres:16)
.github/workflows/     CI: lint, test, build, e2e
.env.example           every configuration variable, documented
```

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and known limitations.
Coffer does not terminate TLS: expose it only through a TLS reverse proxy.
