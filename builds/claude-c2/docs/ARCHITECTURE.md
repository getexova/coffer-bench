# Coffer architecture

This document is an overview. [CONTRACT.md](CONTRACT.md) has the detailed design:
schema, crypto formats, HTTP and CLI semantics. [../SPEC.md](../SPEC.md) has the product
requirements, [DECISIONS.md](DECISIONS.md) the rationale, and [SECURITY.md](SECURITY.md)
the threat model.

## Components

```
            operator / CI                          host (127.0.0.1 only)
  +-------------------------+        HTTP        +------------------------------------+
  | coffer CLI (bin/coffer) | -----------------> | TLS reverse proxy (operator-owned) |
  |  ${XDG_CONFIG_HOME}/    |   Bearer token     +------------------------------------+
  |  coffer/config.json     |                                   |
  |  (0600, dir 0700)       |                                   v  127.0.0.1:${COFFER_PORT:-8420}
  +-------------------------+          +------------------------------------------------+
                                       | server container (distroless static, uid 65532,|
                                       |   read-only rootfs, cap_drop ALL, no-new-privs)|
                                       |  /coffer-server  (listens on :8420)            |
                                       |   api.ServeHTTP: request id, headers, body     |
                                       |     limit, panic recovery, JSON 404/405, log   |
                                       |   api.handle: ready gate -> authenticate       |
                                       |     -> handler (authz -> pgx tx -> audit)      |
                                       |   crypto (master key, DEKs, argon2id, tokens)  |
                                       |   audit (hash chains, group-commit appender)   |
                                       +------------------------------------------------+
                                                         |  compose network only
                                                         |  request pool: role coffer_app
                                                         v
                                       +------------------------------------------------+
                                       | db container: postgres:16, volume pgdata,      |
                                       |   no published port, only POSTGRES_* env       |
                                       +------------------------------------------------+
```

### Packages

| Path | Role |
|---|---|
| `cmd/coffer-server` | Server entrypoint. Loads config (exits 1 on error), handles SIGTERM/SIGINT, runs `app.Run`. The `coffer-server healthcheck` subcommand GETs `127.0.0.1:<port>/readyz` and is the container healthcheck (the image has no shell or curl). |
| `internal/server/app` | Boot sequence, HTTP server with timeouts, graceful shutdown, JSON logger. |
| `internal/server/config` | Reads and validates environment variables, parses the master key, password policy, email normalisation. |
| `internal/server/crypto` | AES-256-GCM seal/open, AAD builders, random IDs and tokens, token hashing, the argon2id hasher (4-slot semaphore, dummy hash, rehash check). |
| `internal/server/db` | Connecting with retry, embedded migrations (`db/migrations/0001_init.sql`), master-key canary check and rotation, the restricted `coffer_app` role, bootstrap of the platform admin. |
| `internal/server/audit` | Canonical JSON, hash computation, `AppendTx` (in the caller's transaction), the per-chain group-commit `Appender`, `List`, `Verify`. |
| `internal/server/api` | Middleware, router, authentication, authorization, and every handler: `http.go`, `auth.go`, `projects.go` (routes, readiness, scope resolution), `secrets.go`, `changes.go`, `members.go`, `tokens.go`, `admin.go` (orgs and audit). |
| `internal/server/testutil` | Test-only: a fresh, randomly named database and app role per test, an httptest server, log capture. |
| `cmd/coffer`, `internal/cli` | The CLI. Standard library only, static binary. Command table and flag parsing, config file, HTTP client, output and sanitising, `run`, TTY handling. |
| `test/e2e` | Black-box end-to-end suite (build tag `e2e`). It drives `./bin/coffer` and raw HTTP against a running stack, with two orgs. |
| `scripts/` | `init-env`, `up`, `down`, `build`, `test`, `backup`, `restore` (SPEC §5), plus `lib.sh`, `check-env-docs.sh`, `ops-smoke.sh`. |

Dependencies: `github.com/jackc/pgx/v5` and `golang.org/x/crypto` (argon2). Nothing else
outside the standard library. Routing uses `net/http.ServeMux` with Go 1.22 method and
wildcard patterns.

## Request flow

1. **`api.ServeHTTP` (outermost):**
   - Generates `X-Request-Id`. Any incoming value is ignored.
   - Sets `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`,
     `Content-Type: application/json`, `Referrer-Policy`, `X-Frame-Options` and CSP.
     No CORS headers are ever set.
   - Enforces the 1 MiB body limit: 413 on `Content-Length`, or while buffering the
     whole body before routing.
   - Recovers panics as a generic 500.
   - Writes one JSON log line per request on stdout: method, route pattern, status,
     `duration_ms`, `request_id`, `actor`. Never the URL, query, headers or body.
2. **Routing:** only `/healthz`, `/readyz` and `/api/v1/...` exist. Anything else,
   including `OPTIONS *` and ServeMux redirects, becomes a JSON 404. A known route with
   an unknown method returns 405 with `Allow`.
3. **Ready gate:** API routes return 503 until boot has finished.
4. **Authentication:** `Authorization: Bearer cof_pat_...|cof_st_...`. A token that
   isn't well formed is 401 with no DB access. Otherwise the server SHA-256-hashes the
   token and looks it up together with its user, org, project and env rows in **one
   query per request**. There is no cache, so revocation, expiry, user removal and org
   disable take effect on the next request. `last_used_at` is updated in the
   background, at most once a minute.
5. **Resolution and authorization** follow the fixed order in CONTRACT §5.3:
   1. Platform admin on an org route: 404.
   2. Slug syntax: 404.
   3. Project in the caller's org: 404.
   4. Project access (role, grant or token scope): 404.
   5. Env: 404.
   6. Operation permission: 403.
   7. Key syntax: 400.
   8. Secret or version: 404.

   Every 403 and 404 from authorization is audited as `authz.denied` in the caller's
   own chain. The bodies are byte-identical, whether the resource is missing or just
   not visible.
6. **Handler:** writes run in a transaction that locks the secret's head row and
   appends the audit event in the same transaction. Value reads (get, get version,
   export) wait until their audit events are committed, through the group-commit
   appender, before the value is sent. If the append fails, the response is 500.
7. **Errors** are always `{"error":{"code","message"}}`. Internal errors are logged
   with the request id, and the client sees only `internal error`.

## Data model

All tables are in `internal/server/db/migrations/0001_init.sql`. CONTRACT §3 has the
full column list.

```
orgs(id, slug unique, disabled)
  1--* users(id, org_id NULL only for platform_admin, email_norm unique globally,
             password_hash argon2id PHC, role, must_change_password)
  1--* projects(id, org_id, slug unique per org, wrapped_dek)
          1--* environments(id, project_id, slug unique per project, protected)
                  1--* secrets   (head row per key: current_version, deleted, updated_*)
                          1--* secret_versions(version, deleted, ciphertext NULL iff deleted)
users *--* projects via grants(user_id, project_id, level viewer|reader|writer)
tokens(id, kind pat|service, token_hash sha256 unique, org_id, user_id [PAT],
       created_by/project_id/env_id/access [service], expires_at, revoked_at, last_used_at)
change_requests(id, org/project/env, key, op set|delete|rollback, ciphertext [set, pending only],
                rollback_to, expected_version, base_version, status pending|approved|rejected|stale,
                proposed_by (actor id), proposed_by_user (human), decided_by/at, applied_version)
audit_chains(chain = org id | 'platform', last_seq, last_hash)  -- chain head, lock point
audit_events(chain, seq, ts, org_id, actor_type, actor_id, action, target, source_ip,
             result, details jsonb, prev_hash, hash)            -- PK (chain, seq)
login_failures(email_norm, failed_at)                           -- lockout window
master_key_check(id = 1, wrapped)                               -- canary under the master key
schema_migrations(version, applied_at)
```

The schema enforces some invariants with CHECKs: platform admin if and only if no org;
the column shapes of PATs and service tokens; a version is deleted if and only if its
ciphertext is NULL. Removing a user cascades to their PATs and grants. Service tokens
keep working.

**Versioning:**
- A write runs `INSERT head ON CONFLICT DO NOTHING; SELECT head FOR UPDATE;
  version = current+1`, then inserts the version row and updates the head in one
  transaction. Concurrent writers each get a distinct version, with no gaps.
- A delete writes a tombstone version. A rollback writes a new version holding an
  older value.
- `expected_version` is compared with the locked head (409 on mismatch).
- Listing reads only the head table (`COLLATE "C"` order, no values).

**Protected environments:** a write becomes a `change_requests` row (202). Approval
locks the change row, applies the two-person rule, re-checks that the proposer can
still write, locks the head, compares it with `base_version` (stale means 409), then
applies the write and audits it, all in one transaction.

## Crypto envelope

```
COFFER_MASTER_KEY (32 B, environment only, never stored)
   | AES-256-GCM, AAD "coffer/dek/v1|<org_id>|<project_id>"
   v
project DEK (32 B random, generated at project creation, stored wrapped in projects.wrapped_dek)
   | AES-256-GCM, AAD "coffer/secret/v1|<org_id>|<project_id>|<env_id>|<key>|<version>"
   v
secret_versions.ciphertext = 0x01 || nonce(12, random) || ciphertext || tag(16)

pending change value: AAD "coffer/change/v1|<org>|<project>|<env>|<key>|<change_id>"
                      (re-encrypted under the secret AAD on approval, then set to NULL)
canary:               32 random bytes, AAD "coffer/canary/v1", in master_key_check
```

- The AAD binds each ciphertext to its exact place. A ciphertext copied to another
  row, env, project, org or version fails authentication. The result is a 500 and an
  audited `failed` event with reason `integrity`, never a value.
- **Passwords:** argon2id (t=2, m=64 MiB by default, p=2, 16-byte salt, 32-byte key)
  as PHC strings, with at most 4 hashes at a time. Unknown and malformed emails verify
  against a dummy hash with the same parameters. Outdated hashes are upgraded on the
  next successful login.
- **Tokens:** 32 random bytes in base64url (256 bits) after `cof_pat_` or `cof_st_`.
  Only the SHA-256 is stored.
- **Rotation:** the canary shows whether the database is wrapped under
  `COFFER_MASTER_KEY`. If it isn't, and `COFFER_MASTER_KEY_PREVIOUS` opens it, every
  DEK is re-wrapped in one transaction before ready (values are not re-encrypted).
  Rows already under the new key are skipped, so a restart is harmless.

## Audit chain

- One chain per organization (chain id = org id), plus `platform`. The platform chain
  holds the platform admin's events, the system's (bootstrap), unauthenticated callers'
  events (failed and locked logins), and `org.create`/`org.disable`.
- `hash = hex(sha256(prev_hash_hex || canonical_json(event without hash)))`. The
  genesis `prev_hash` is 64 zeros and `seq` starts at 1. Canonical JSON has a fixed key
  set, sorted keys, no whitespace, no HTML escaping, and microsecond UTC timestamps.
  String fields are sanitised before hashing.
- **Appends** lock the chain head (`audit_chains ... FOR UPDATE`). Writes append in
  their own transaction. Standalone events (reads, denials) are batched per chain by
  the group-commit appender, and each request still waits for its own commit.
- **Verification** walks the chain in a read-only repeatable-read transaction. It
  checks seq continuity, `prev_hash` links and recomputed hashes, then compares the
  chain head with the last row (which catches a truncated tail). It returns the first
  invalid `seq`.
- **Protection (P1):** the request pool runs as `coffer_app`, which has no UPDATE,
  DELETE or TRUNCATE on `audit_events`. Triggers block UPDATE, DELETE and TRUNCATE for
  every role, as defense in depth.

## Boot sequence

1. Load and validate configuration. A missing variable exits 1 and names it. An
   invalid value, or a placeholder or wrong-length master key, also exits 1.
2. Start the HTTP listener. `/healthz` returns 200. `/readyz` and the API return 503.
3. Connect to Postgres as the owner (`POSTGRES_USER`), retrying until it is reachable.
4. Run migrations: embedded SQL, advisory lock, one transaction per file, idempotent.
5. Check or rotate the master key via the canary. On a mismatch the server exits 1
   with `master key does not match database`, before it has changed anything.
6. Set up the restricted `coffer_app` role. Its password is derived from the canary,
   so it is the same on every boot. Open the 25-connection request pool as that role.
   If this fails, the server falls back to the owner pool with a warning.
7. Bootstrap the platform admin if `users` is empty, then close the owner pool.
8. Ready. `/readyz` returns 200 while all of these hold: a `SELECT 1` answers within
   2 s, and every embedded migration is recorded (this check is cached for 1 s). It is
   checked on every call, so it recovers by itself after a DB outage.

**Shutdown:** on SIGTERM or SIGINT, the server stops accepting connections, drains
in-flight requests (`http.Server.Shutdown`, 8 s), waits for background audit flushes,
closes the pool, and exits 0. Compose allows 10 s before SIGKILL. A signal during boot
cancels the boot cleanly.

## Deployment

- **`compose.yaml` `server`:**
  - Built from the `Dockerfile`: a multi-stage build from
    `golang:1.26.10-alpine3.24@sha256:…` to
    `gcr.io/distroless/static-debian12:nonroot@sha256:…`, both pinned by digest.
  - Runs as UID/GID 65532 with a read-only root filesystem, a 16 MB `/tmp` tmpfs,
    `cap_drop: ALL` and `no-new-privileges`.
  - Published only on `127.0.0.1:${COFFER_PORT:-8420}`. It gets `.env` through
    `env_file`.
  - Healthcheck: `/coffer-server healthcheck`. Restart policy `unless-stopped`.
- **`compose.yaml` `db`:** `docker.io/library/postgres:16` with the named volume
  `pgdata`, no published port, only the `POSTGRES_*` variables, `no-new-privileges`, and
  a `pg_isready` healthcheck.
- **`up.sh`:**
  1. Creates `.env` with `init-env.sh` if it is missing.
  2. Starts `db` and waits for `pg_isready`.
  3. Runs `compose up -d --build --force-recreate --no-deps server`, so every `.env`
     change is applied.
  4. Polls `/readyz` for up to 180 s.
  5. Builds `./bin/coffer` with `build.sh`.
- Works with `docker compose` and `podman compose` (and `docker-compose` or
  `podman-compose`). The scripts detect which one is installed, and `COFFER_COMPOSE`
  overrides the choice.
- TLS is terminated by a reverse proxy the operator provides (out of scope).
- **Backups:** `pg_dump -Fc` from inside the db container, containing only ciphertext
  and hashes. The master key is backed up separately. `restore.sh` recreates the
  database, runs `pg_restore`, and recreates the server. The server re-applies the app
  role's privileges at boot.
