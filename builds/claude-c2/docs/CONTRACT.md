# Coffer implementation contract

This is the detailed design that all of Coffer's components follow, kept in line with
the code. SPEC.md is the product spec and wins over this document. Where SPEC is
silent, this document decides. The rationale for every such choice is in
`docs/DECISIONS.md` (cited here as "DECISIONS N"). The CLI's user reference is
`docs/CLI.md`.

Language: Go (module `github.com/coffer-dev/coffer`, go 1.26). Dependencies allowed:
`github.com/jackc/pgx/v5` (server only), `golang.org/x/crypto` (argon2), and the Go
standard library. The CLI uses the standard library only. No web framework: routing
uses `net/http.ServeMux` (Go 1.22+ patterns), wrapped so that every response under
`/api/v1` is JSON.

## 1. Repository layout

```
cmd/coffer-server/main.go     server entrypoint (also: `coffer-server healthcheck`)
cmd/coffer/main.go            CLI entrypoint
internal/server/...           all server packages (app, config, crypto, db, audit, api, testutil)
internal/cli/...              CLI packages
internal/server/db/migrations/*.sql   embedded SQL migrations (go:embed)
scripts/*.sh                  ops scripts from SPEC §5
Dockerfile, compose.yaml, .env.example, .github/workflows/ci.yml
docs/{SECURITY,ARCHITECTURE,DECISIONS,CONTRACT,CLI}.md
test/e2e/                     black-box end-to-end test (Go test, build tag `e2e`, drives ./bin/coffer + HTTP)
```

## 2. Configuration (environment variables)

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `COFFER_MASTER_KEY` | yes | — | base64 (std, padded; also accept raw/url variants) of exactly 32 bytes |
| `COFFER_MASTER_KEY_PREVIOUS` | no | — | old master key during rotation |
| `COFFER_BOOTSTRAP_ADMIN_EMAIL` | yes | — | platform admin email (used only when no users exist) |
| `COFFER_BOOTSTRAP_ADMIN_PASSWORD` | yes | — | platform admin password (≥12 chars) |
| `COFFER_PORT` | yes in `.env` | 8420 | host port (compose maps `127.0.0.1:${COFFER_PORT}` → container 8420); not read by the server |
| `COFFER_LISTEN_ADDR` | no | `:8420` | server bind address inside the container |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | yes | — | DB owner credentials (also used by the `db` service) |
| `POSTGRES_HOST` | no | `db` | DB host |
| `POSTGRES_PORT` | no | `5432` | DB port |
| `POSTGRES_SSLMODE` | no | `disable` | libpq `sslmode` added to the built DSN; ignored when `COFFER_DATABASE_URL` is set |
| `COFFER_DATABASE_URL` | no | — | if set, overrides the POSTGRES_* variables (used by tests) |
| `COFFER_TRUST_PROXY` | no | `false` | if `true`, source IP is taken from the first `X-Forwarded-For` entry |
| `COFFER_PAT_TTL` | no | `720h` | lifetime of PATs issued at login (Go duration, 1m..8760h) |
| `COFFER_ARGON2_MEMORY_KIB` | no | `65536` | argon2id memory (tests may lower it; 19456..4194304) |
| `COFFER_REQUIRE_PASSWORD_CHANGE` | no | `false` | P1: if `true`, users created with an initial password must change it first |

The required variables are `COFFER_MASTER_KEY`, `COFFER_BOOTSTRAP_ADMIN_EMAIL`,
`COFFER_BOOTSTRAP_ADMIN_PASSWORD`, plus `POSTGRES_USER`/`POSTGRES_PASSWORD`/`POSTGRES_DB`
unless `COFFER_DATABASE_URL` is set (`COFFER_PORT` is a compose setting only). The server
checks them first, in that order. If one is missing or empty, it exits 1 and prints
`config error: missing required environment variable NAME` to stderr. Next comes the
master key. It may be in standard or URL base64, padded or not, and must decode to
exactly 32 bytes. It must also not be the `.env.example` placeholder,
`REPLACE_ME_with_output_of_init_env_sh_0000000000=`, which is rejected by exact string
comparison (it is not 32 bytes either). If `COFFER_MASTER_KEY_PREVIOUS` is set, it gets
the same checks. The bootstrap email must look like an email address. The bootstrap
password must meet the password policy (§4). Boolean variables accept
`true/false/1/0/yes/no`. Any invalid value exits 1 with
`config error: invalid environment variable NAME: reason`.

## 3. Database schema (Postgres 16)

Migrations are embedded SQL files, numbered `0001_init.sql` and up. They are applied at
boot inside a transaction, under `pg_advisory_lock(7420001)`, and recorded in
`schema_migrations(version int primary key, applied_at timestamptz)`. They are idempotent.

IDs are text: a type prefix plus 20 random bytes in base32 (lowercase, no padding), e.g.
`usr_...`, `org_...`, `prj_...`, `env_...`, `tok_...`, `chg_...`.

```sql
orgs(id text pk, slug text unique not null, disabled bool not null default false,
     created_at timestamptz not null default now(), disabled_at timestamptz)

users(id text pk, org_id text null references orgs(id),   -- null org_id only for platform admin
      email text not null, email_norm text unique not null,   -- lower(trim(email))
      password_hash text not null,                          -- argon2id PHC string
      role text not null check (role in ('platform_admin','owner','admin','member')),
      must_change_password bool not null default false,
      created_at timestamptz not null default now(), password_changed_at timestamptz,
      check ((role = 'platform_admin') = (org_id is null)))            -- index users(org_id)

login_failures(email_norm text not null, failed_at timestamptz not null)   -- index (email_norm, failed_at)

tokens(id text pk, kind text check (kind in ('pat','service')),
       token_hash bytea unique not null,           -- SHA-256 of the full token string
       org_id text null references orgs(id),       -- null for the platform admin's PATs
       user_id text null references users(id) on delete cascade,   -- PAT owner only (null for service tokens)
       created_by text null,                       -- service-token creator user id (no FK: survives user removal)
       project_id text null references projects(id), env_id text null references environments(id),  -- service tokens only
       access text null check (access in ('read','read-write')),
       name text, created_at timestamptz not null default now(),
       expires_at timestamptz not null, revoked_at timestamptz, last_used_at timestamptz,
       check (kind='pat' and user_id is not null and project_id/env_id/access are null
           or kind='service' and user_id is null and org_id/project_id/env_id/access are not null))
       -- indexes tokens(org_id, kind), tokens(user_id)

projects(id text pk, org_id text not null references orgs(id), slug text not null,
         wrapped_dek bytea not null,          -- AES-256-GCM(master, dek, aad="coffer/dek/v1|"+org_id+"|"+project_id), nonce-prefixed
         created_at timestamptz not null default now(), created_by text not null,
         unique(org_id, slug))

environments(id text pk, project_id text not null references projects(id), slug text not null,
             protected bool not null default false, created_at timestamptz not null default now(),
             created_by text not null, unique(project_id, slug))

grants(user_id text references users(id) on delete cascade, project_id text references projects(id),
       level text check (level in ('viewer','reader','writer')),
       created_at timestamptz default now(), primary key(user_id, project_id))

secrets(env_id text references environments(id), key text,
        current_version int not null, deleted bool not null,
        updated_at timestamptz not null, updated_by text not null,
        primary key(env_id, key))                                -- the "head" row, used for listing and row locks

secret_versions(env_id text, key text, version int, deleted bool not null,
                ciphertext bytea null,                           -- null when deleted
                created_at timestamptz not null, created_by text not null,
                primary key(env_id, key, version),
                foreign key(env_id, key) references secrets(env_id, key),
                check (deleted = (ciphertext is null)))

change_requests(id text pk, org_id text references orgs, project_id text references projects,
                env_id text references environments, key text,     -- all not null
                op text check (op in ('set','delete','rollback')),
                ciphertext bytea null,          -- for set: value encrypted with AAD scoped to the change id
                rollback_to int null, expected_version int null,
                base_version int not null,      -- head version (0 = absent) when the request was created
                status text check (status in ('pending','approved','rejected','stale')),
                proposed_by text not null,      -- actor id (user id or token id)
                proposed_by_user text null,     -- the human behind it (user id, or a service token's creator)
                decided_by text null, decided_at timestamptz null, applied_version int null,
                created_at timestamptz not null default now())   -- index (org_id, created_at desc)
                -- ciphertext is set to NULL once the change is approved, rejected or stale

audit_chains(chain text pk, last_seq bigint not null, last_hash text not null)   -- chain = org id or 'platform'

audit_events(chain text, seq bigint, ts timestamptz not null, org_id text null,
             actor_type text, actor_id text, action text, target text, source_ip text,
             result text check (result in ('success','denied','failed')),
             details jsonb not null default '{}', prev_hash text not null, hash text not null,
             primary key(chain, seq))

master_key_check(id int pk check (id=1), wrapped bytea not null)   -- canary wrapped under the current master key
```

**App role (P1).** At every boot, once the master-key check has passed, the owner
connection (POSTGRES_USER) does the following under the migration advisory lock:
- Create role `coffer_app` (LOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION,
  NOBYPASSRLS) if it is missing, otherwise `ALTER` it.
- Set its password to `hex(HMAC-SHA256(canary, "coffer/app-role-password/v1|" + dbname + "|" + role))`.
  The canary is the plaintext of `master_key_check`: random per database and stable across
  rotation, backup and restore. So every boot sets the *same* password, and a second or
  refused boot never breaks a running server's connections. The password is sent as a
  SCRAM-SHA-256 verifier computed by the client, so the plaintext never reaches Postgres.
- Grant CONNECT on the database and USAGE (not CREATE) on schema `public`.
- Revoke everything, then grant SELECT/INSERT/UPDATE/DELETE on all tables, then revoke
  UPDATE/DELETE/TRUNCATE on `audit_events` and INSERT/UPDATE/DELETE/TRUNCATE on
  `schema_migrations` and `master_key_check`. Privileges are re-applied on every boot,
  because restored dumps are made with `--no-privileges`.

The request pool (25 connections) is then opened as `coffer_app`, and the owner pool is
closed before ready. If any of this fails, the server logs a warning and serves from the
owner connection. Two triggers on `audit_events` raise an exception as defense in depth:
row-level `BEFORE UPDATE OR DELETE`, and statement-level `BEFORE TRUNCATE`. The DB owner
can still drop them to simulate tampering in tests.

## 4. Cryptography

- **Master key wrap:** AES-256-GCM. Format: `version byte 0x01 || 12-byte random nonce || ciphertext||tag`.
  - DEK AAD = `"coffer/dek/v1|" + org_id + "|" + project_id`.
  - Canary AAD = `"coffer/canary/v1"`. The canary plaintext is 32 random bytes and is not secret.
- **DEK:** 32 random bytes per project, generated when the project is created.
- **Secret value:** AES-256-GCM under the project DEK, in the same format. AAD =
  `"coffer/secret/v1|" + org_id + "|" + project_id + "|" + env_id + "|" + key + "|" + decimal(version)`.
  A decrypt failure is an internal error (500, code `internal`). It never returns a value.
- **Pending change value:** AAD = `"coffer/change/v1|" + org_id + "|" + project_id + "|" + env_id + "|" + key + "|" + change_id`.
  On approval the value is decrypted and re-encrypted under the secret AAD for the new version.
- **Boot sequence:**
  1. Validate config (exit 1 on any error, naming the variable).
  2. Start the HTTP listener. `/healthz` returns 200 immediately. `/readyz` and every API route return 503 until step 8.
  3. Connect to the DB as the owner, retrying until it succeeds (backoff up to 2 s, logged now and then).
  4. Run migrations (advisory lock 7420001; up to 5 tries).
  5. Check the master key (in one transaction under advisory lock 7420002):
     - If `master_key_check` is empty, every existing `projects.wrapped_dek` must unwrap with the current key (otherwise mismatch). Then wrap a new random canary under the current key.
     - If the canary unwraps under the current key, there is nothing to do. If `PREVIOUS` is also set, any DEKs still under the previous key are re-wrapped, which finishes a partial rotation.
     - If it doesn't, and `COFFER_MASTER_KEY_PREVIOUS` is set and unwraps it: lock every `projects` row (`SELECT ... FOR UPDATE`), unwrap each DEK with the previous key, and re-wrap it with the current key. Rows that already unwrap with the current key are skipped. Then re-wrap the same canary and log `master key rotated`.
     - Otherwise log `master key does not match database` and exit 1. Nothing has been changed at this point.
  6. Set up the app role (see §3) and open the request pool.
  7. Bootstrap the platform admin if `users` is empty (advisory lock 7420003; audited as `platform.bootstrap`). Then close the owner pool.
  8. Mark ready.
- **Passwords:** argon2id. t=2, m=COFFER_ARGON2_MEMORY_KIB (default 64 MiB), p=2, 16-byte salt, 32-byte key, PHC string format. A semaphore limits concurrent hashes to 4. The minimum length is 12 characters (runes), the maximum is 1024 bytes, and the password must be valid UTF-8 with no NUL. Hashing waits for a semaphore slot on the request context. After a successful login, a stored hash with different parameters is rehashed in the same transaction.
- **Tokens:** `cof_pat_` or `cof_st_` followed by 32 random bytes in base64url without padding, giving 256 bits. The DB stores `sha256(token)`. Lookup is by hash, with a constant-time compare.
- **Constant-time login:** if the email is unknown or malformed, run argon2 verify against a dummy hash made with the live parameters, so the timing is similar.

## 5. HTTP behaviour (server)

### 5.1 Global

- Only `/healthz`, `/readyz` and `/api/v1/...` exist. Everything else returns 404 with the JSON error body.
- Every response the server writes, including 404s outside `/api/v1`, carries these headers:
  - `X-Request-Id` (random 16 bytes in hex; an incoming `X-Request-Id` is ignored)
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: no-store`
  - `Content-Type: application/json` (dotenv export uses `text/plain; charset=utf-8`)
  - `Referrer-Policy: no-referrer`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
- No `Access-Control-*` headers are ever sent. `OPTIONS` falls through to normal routing: 404 if no route matches, 405 if the route exists. `OPTIONS *` and any other request target that doesn't start with `/` get the JSON 404 (`DisableGeneralOptionsHandler`). A non-canonical path that ServeMux would redirect also gets a JSON 404.
- Responses that Go's `net/http` writes before our handler runs are an exception. These are 400 for a malformed request line or `%`-escape, 431 for headers over 64 KiB, and 400 for a bad `Content-Length`. They are `text/plain`, with no JSON body, no `X-Request-Id` and no log line (see SECURITY.md known limitations).
- Unknown method on a known route: 405 `{"error":{"code":"method_not_allowed",...}}` with an `Allow` header.
- **Body limit:** if `Content-Length` > 1 MiB (1,048,576), the server answers 413 immediately. Otherwise the body is wrapped in `http.MaxBytesReader(1 MiB)` and read fully in middleware before routing; overflow returns 413 `payload_too_large`. This applies to every route, including ones that ignore the body.
- **JSON input:** request bodies must be a JSON object. The decoder runs with `DisallowUnknownFields` (an unknown field is 400 `validation`). Trailing data is 400. Invalid UTF-8 in the raw body is 400. Escaped lone surrogates (`\ud800`) inside values are rejected with 400. A missing or empty body on a route that expects a body is 400. Routes that take no body (`POST /auth/logout`, `/changes/{id}/approve`, `/changes/{id}/reject`, `/admin/orgs/{org}/disable`) accept an empty body without a Content-Type. Duplicate keys are not rejected (the last one wins).
- **Errors:** `{"error":{"code":"<code>","message":"<human text>"}}`. Codes: `validation` 400, `unauthenticated` 401, `forbidden` 403, `not_found` 404, `method_not_allowed` 405, `conflict` 409, `payload_too_large` 413, `rate_limited` 429, `internal` 500, `unavailable` 503. The 404 body for "doesn't exist" and "not visible" is byte-for-byte identical: `{"error":{"code":"not_found","message":"not found"}}`. A 403 body is always `{"error":{"code":"forbidden","message":"forbidden"}}`. Internal errors are logged server-side with the request id, and the client sees only `{"error":{"code":"internal","message":"internal error"}}`. Panics are recovered the same way.
- **Request log:** one JSON line per request on stdout: `{"ts","level":"info","msg":"request","method","route","status","duration_ms","request_id","actor"?}`. `actor` is the authenticated user or token id. `method` is `OTHER` when it isn't plain upper-case letters. `route` is the matched pattern, e.g. `GET /api/v1/projects/{p}/envs/{e}/secrets/{key}`, never the raw URL. Use `"unmatched"` when no route matched. Query strings, headers and bodies are never logged.
- **Source IP:** the host of `r.RemoteAddr`. If `COFFER_TRUST_PROXY=true` and the first `X-Forwarded-For` entry parses as an IP, use that entry instead.
- **Timestamps:** RFC 3339 with microseconds, UTC (e.g. `2026-10-30T10:00:00.123456Z`).
- `/healthz` returns `{"status":"ok"}`. `/readyz` returns 200 `{"status":"ready"}` or 503 `{"status":"not_ready"}`. Readiness requires three things: the boot sequence is done; every embedded migration is recorded in `schema_migrations` of the database behind the pool; and the query succeeds within 2 s. A passing migration check is cached for 1 s, and in between a plain `SELECT 1` is used. It is checked on every call, so readiness recovers by itself. An API route called before boot finishes returns 503 `unavailable`.
- **Shutdown:** on SIGTERM/SIGINT, call `http.Server.Shutdown` with an 8 s timeout, close the pool, exit 0.
- Server timeouts: ReadHeaderTimeout 10 s, ReadTimeout 30 s, WriteTimeout 60 s, IdleTimeout 120 s. MaxHeaderBytes 64 KiB.

### 5.2 Authentication

- `Authorization: Bearer <token>`. If the header is missing or malformed, or the token is unknown, revoked or expired, or its user was removed, or the org is disabled, the response is 401 `unauthenticated`. Every request re-checks the token row, the user row and the org row in one DB query. Nothing is cached, which gives immediate revocation.
- **Principal kinds:**
  - **platform admin:** a PAT whose user has role `platform_admin`.
  - **org user:** a PAT whose user has role owner, admin or member.
  - **service token:** has `org_id`, `project_id`, `env_id` and `access`. It does not depend on its creator still existing.
- `last_used_at` updates are best-effort and happen at most once per minute per token.
- **P1 must-change-password:** only when `COFFER_REQUIRE_PASSWORD_CHANGE=true`. If the user has `must_change_password` (set for every user created with an initial password, never for the bootstrap admin), every route except `POST /auth/password`, `POST /auth/logout` and `GET /me` returns 403 with code `password_change_required`, audited as `authz.denied` with reason `password_change_required`. When the flag is off, `must_change_password` is reported as `false`.
- A bearer token that isn't well formed (wrong prefix or characters) is rejected as 401 before any DB lookup.

### 5.3 Routes and semantics

Every route below is under `/api/v1`. "OA" means owner or admin. "ST" means service token.
"PA" means platform admin. Any org-scoped route called by a PA returns 404, and that denial is
audited to the platform chain.

**Auth**
- `POST /auth/token {email, password}`
  - Success: 201 `{token, expires_at, user:{id,email,role,org_id|null,org_slug|null,must_change_password}}`. The PAT is named `login` and lives for `COFFER_PAT_TTL`.
  - Bad credentials (unknown email, or wrong password, or user in a disabled org): 401 `{"error":{"code":"unauthenticated","message":"invalid credentials"}}`. The body is identical in every case.
  - Order: wait for a hashing slot on the request context. All later DB work runs on a context the client can't cancel (10 s), inside one transaction under `pg_advisory_xact_lock(hash(email_norm))`.
  - Lockout: the check is keyed by normalized email, so it covers unknown emails too. A malformed email uses the bucket `invalid:email:<hash>` and is never looked up. First, that email's `login_failures` rows older than 15 minutes are deleted (and, at most once a minute, everyone's, in the background). If 5 or more failures remain in the last 15 minutes, the response is 429 `rate_limited` before the password is checked, and nothing is recorded as a new failure. A failed attempt (unknown or malformed email, wrong password, disabled org) inserts a row into `login_failures`. A successful login deletes that email's rows, and rehashes the password if its argon2 parameters are outdated.
  - Audit `auth.login`:
    - **Success:** result `success`, actor = the user, target = user id, details `{token_id}`. It goes only to the user's own chain (the org's, or platform for the platform admin).
    - **Failed:** result `failed`, actor type `anonymous`. **Locked:** result `denied`, details `{"reason":"locked"}`.
    - Failed and locked events always go to the `platform` chain with actor `anonymous`, no org id, and target `email:<first 16 hex chars of sha256(email_norm)>`, whether or not the email exists. If the email belongs to an org user, a copy also goes to that org's chain, with target = user id. The platform chain is always appended first, so the lock order is fixed.
  - When the bearer is a service token, the response is 403 (an ST cannot create PATs). Any other request carrying an Authorization header is treated as a normal login.
- `POST /auth/logout`: revokes the calling PAT, also when the client hangs up, and returns 200 `{"status":"logged_out"}`. With an ST: 403. Audit `auth.logout` (target = token id).
- `POST /auth/password {current_password,new_password}` (P1): PAT only (ST 403). Checks run in this order:
  1. A new password that breaks the policy, or equals the current one: 400.
  2. Same email lock and lockout window as login. If locked: 429, audited as `denied` / `locked`.
  3. Wrong current password: 403 `forbidden`. It counts as a login failure and is audited as `failed`.
  4. Success: 200 `{"status":"password_changed"}`. Clears `must_change_password`, revokes the user's other PATs, and clears the failure rows.

  Audit `auth.password_change` (details `{revoked_tokens}`).
- `GET /me`:
  - User: `{type:"user", id, email, role, org_id, org_slug, must_change_password}`.
  - ST: `{type:"service_token", id, org_id, org_slug, project, env, access, expires_at}`.
  - Platform admin: the user shape, with `org_id` and `org_slug` set to null.

**Platform admin**
Only the platform admin can use these routes. Anyone else gets 404, and the denial is audited.
- `GET /admin/orgs` → `[{id,slug,disabled,created_at}]`, sorted by slug.
- `POST /admin/orgs {slug, owner_email, owner_password}` → 201 `{id,slug,disabled:false,created_at,owner:{id,email,role:"owner"}}`.
  - Slug regex `^[a-z0-9][a-z0-9-]{0,62}$`. A duplicate slug returns 409.
  - An owner email already in use (any org) returns 409 (emails are globally unique, see DECISIONS).
  - The owner password must meet the policy (400). The owner is created with `must_change_password=true` (enforced only when the P1 flag is on).
  - Audit `org.create` (details `{org_id, slug, owner_id}`) to the platform chain, and also to the new org's chain as its genesis event.
- `POST /admin/orgs/{org}/disable`: `{org}` is the slug. Returns 200 with the org object. Users and tokens of a disabled org get 401 on the next request. Disabling an already-disabled org returns 200 and is idempotent. A malformed or unknown slug returns 404. Audit `org.disable` (platform chain only), with details `{slug, already_disabled}`.
- `GET /admin/audit?limit=` (default 100, 1..1000, otherwise 400): platform chain, newest first.
- `GET /admin/audit/verify` → `{valid, first_invalid_seq: null|int}`

**Members**
OA only. A member gets 403. An ST gets 403.
- `GET /members` → `[{id,email,role,created_at,grants:[{project,level}]}]`, sorted by email. `project` is the slug, and `grants` is always present (possibly `[]`). The org is the caller's own.
- `POST /members {email, role, password}` → 201 `{id,email,role,created_at}`.
  - `role` ∈ {member,admin,owner}, otherwise 400. Only an owner may create an owner; an admin trying gets 403.
  - Invalid email or password policy violation: 400. Email already in use anywhere: 409.
  - Sets `must_change_password=true`.
  - Audit `member.add`.
- `PATCH /members/{user_id} {role}`: checks run in this order:
  1. A member or ST caller gets 403 (a PA gets 404).
  2. Body validation: `role` must be `member`, `admin` or `owner` (400). Any other field gets 400.
  3. The target must be in the caller's org (404; a malformed id is also 404).
  4. If the target is an owner or the new role is owner, the caller must be an owner, otherwise 403.
  5. If the target is the caller (self-change): if the caller is the last owner and is demoting themself, 409. Otherwise 403 (a caller can never change their own role).
  6. If the request demotes an owner and no other owner remains, 409. The org row is locked (`FOR NO KEY UPDATE`) and owners are counted with `SELECT ... FOR UPDATE` inside the transaction.
  7. A no-op change returns 200 and is not audited.

  Returns 200 with the member object. Audit `member.role_change` with details `{from,to}`.
  A change to `admin` or `owner` deletes all of the target's grants in the same transaction, so a later demotion to `member` starts with no grants (DECISIONS 61).
- `DELETE /members/{user_id}`: the same rules apply. An admin cannot remove an owner (403). Removing the last owner returns 409. Removing yourself returns 403, or 409 if you are the last owner. Deleting a user deletes that user's PATs and grants (FK cascade). Their pending change requests can no longer be approved (the approval re-check marks them `stale`). Their service tokens keep working until they expire or are revoked, because service tokens are org assets. Returns 200 `{"status":"removed"}`. Audit `member.remove`.
- `PUT /members/{user_id}/grants/{project} {level}`:
  - OA only. Checks run in this order:
    1. The body is validated: `level` ∈ {viewer, reader, writer}, otherwise 400.
    2. The target user must be in the org (404). The project must be in the org (404).
    3. A caller can't grant to themself (403).
    4. The target must have role `member`, otherwise 400, since owners and admins have implicit access.
  - Upsert. Returns 200 `{user_id, project, level}`.
  - Audit `grant.set` with details `{level, previous}`.
- `DELETE /members/{user_id}/grants/{project}`: OA only. The same target, project and self checks apply. Returns 200 `{"status":"revoked"}`, or 404 if there is no grant. Audit `grant.revoke` with details `{previous}`. Lowering or revoking a grant takes effect on the next request. Pending changes the member proposed in that project can then no longer be approved.
- Grant targets are audited as `<user_id> <project slug>`.

**Projects and environments**
- `GET /projects`:
  - OA: all projects in the org.
  - Member: only projects the member has a grant for.
  - ST: 403.
  - Response: `[{id,slug,created_at}]`, sorted by slug. Members also get `level`.
- `POST /projects {slug}`: OA only (member 403, ST 403). Returns 201 `{id,slug,created_at}`. A duplicate in the org returns 409. Generates and wraps the DEK. Audit `project.create` (target = slug, details `{project_id}`).
- `GET /projects/{p}/envs`: the project must be visible, otherwise 404 (a member with no grant gets 404). An ST gets 403 if `{p}` is its own project, and 404 otherwise. Response: `[{id,slug,protected,created_at}]`, sorted by slug.
- `POST /projects/{p}/envs {slug, protected?:bool}`: the project must be visible (404), then the caller must be OA (403). Returns 201. A duplicate returns 409. An ST gets 403 for its own project, 404 otherwise. Audit `env.create` (target `<project>/<env>`, details `{env_id, protected}`).

**Secrets**
Base path `/projects/{p}/envs/{e}/secrets`.

Resolution order (this order is mandatory):
1. Authenticate (401).
2. Platform admin → 404.
3. Resolve the project by slug in the caller's org (404). A slug that doesn't match the slug pattern is also 404, before any SQL runs.
4. Access to the project: OA → full. Member → their grant, or 404 if they have none. ST → its project must equal this project, otherwise 404.
5. Resolve the env (404). For an ST, the env must equal its env, otherwise 404.
6. Permission for the operation, otherwise 403:
   - list and history (metadata): viewer+, any ST.
   - get value, get version, export, `run`: reader+, any ST.
   - set, delete, rollback: writer+, or an ST with read-write.
7. Validate the key against `^[A-Z_][A-Z0-9_]{0,127}$`. An invalid key returns 400 (after the authz checks, so a validation error never reveals existence).
8. Resolve the secret or version (404).

Endpoints:
- `GET .../secrets` → `[{key, version, updated_at, updated_by}]` sorted by key, excluding deleted heads. `updated_by` is the actor id. No values. One SQL query using the head table.
- `GET .../secrets/{key}` → `{key, version, value}`. Returns 404 if the key is absent or its head is deleted. Audit `secret.read` with target `<project>/<env>/<key>` and details `{version}`. The audit insert must commit before the response is sent; if it fails, the response is 500 and no value is returned.
- `GET .../secrets/{key}/versions` → `[{version, deleted, created_at, created_by}]` ascending. Returns 404 if the key never existed. Requires viewer+.
- `GET .../secrets/{key}/versions/{n}` → `{key, version, value}`. A tombstone version, a version that doesn't exist, `0`, or a number larger than int32 returns 404. A `n` that isn't all digits returns 400. Audit `secret.read`.
- `PUT .../secrets/{key} {value: string, expected_version?: int}`:
  - The value must be ≤ 65,536 bytes of valid UTF-8, otherwise 400. A non-string or null value returns 400.
  - `expected_version` means the current head version, counting tombstones. `0` means "the key has never existed". It must be a plain JSON integer ≥ 0 (no quotes, fraction or exponent), otherwise 400. `null` means it is absent.
  - Mismatch: 409 `conflict`.
  - Unprotected env: in one tx, `INSERT ... ON CONFLICT DO NOTHING` the head, `SELECT ... FOR UPDATE` the head, then version = current+1, insert the version row, update the head. Returns 200 `{version}`. Audit `secret.write`.
  - Protected env: check `expected_version` against the current head now (409 if it mismatches). Then create the change request (`base_version` = current head version, 0 if absent) and return 202 `{status:"pending", change_id}`. Audit `change.create` (details `{change_id, op, base_version, to?}`).
- `DELETE .../secrets/{key}` (query `expected_version` optional): 404 if the key is absent or already deleted. Otherwise create a tombstone version: 200 `{version}`, or 202 on a protected env. On a protected env, existence and `expected_version` are checked when the request is created as well. Audit `secret.delete`.
- `POST .../secrets/{key}/rollback {to: int, expected_version?}`: `to` must be an existing, non-tombstone version, otherwise 404. A rollback is allowed even if the head is deleted. It creates a new version holding the value of version `to`. A non-integer `to` returns 400. `to < 1` or larger than int32 returns 404. Returns 200 `{version}`, or 202 on a protected env. Audit `secret.rollback` (details `{version, to}`).
- `GET /projects/{p}/envs/{e}/export?format=dotenv|json` (default `json`; any other value returns 400):
  - Permission: reader+ or any ST.
  - `json`: `application/json`, an object of key → value with keys sorted.
  - `dotenv`: `text/plain; charset=utf-8`, lines `KEY="VALUE"\n` sorted by key. Escape `\`→`\\`, `"`→`\"`, LF→`\n`, CR→`\r`, `$`→`\$`. An empty env gives an empty body.
  - Writes one `secret.read` audit event per key, all committed together before the response. Details `{version, via:"export"}`. An empty env writes no events.
- **Decryption failure** (tampered or swapped ciphertext): 500 `internal`. A `failed` event with reason `integrity` is appended on a context the client can't cancel: `secret.read` for get, version and export, `secret.rollback` for rollback, `change.approve` for approval. Any open transaction is rolled back first.
- Secret write events (`secret.write`, `secret.delete`, `secret.rollback`) have target `<project>/<env>/<key>` and details `{version}` (plus `to` for rollback). They are appended in the write's own transaction.
  - The CLI's `run` uses `format=json`.

**Change requests**
- `GET /changes?status=`: OA sees every change in the org. A member sees only changes they proposed, in projects where they still hold a grant. An ST gets 403. At most 1000 entries. A `status` value other than pending, approved, rejected or stale returns 400. Response: `[{id, project, env, key, op, status, proposed_by, created_at, decided_by, decided_at, base_version, rollback_to, applied_version}]`, newest first. Values are never included.
- `POST /changes/{id}/approve`:
  - A change in another org, or one that doesn't exist, returns 404.
  - A member gets 403. An ST gets 403.
  - In one tx, the change row is locked (`FOR UPDATE`), then:
    1. Two-person rule: if the caller's user id equals `proposed_by_user` or `proposed_by`, 403. This covers changes proposed through a service token the approver created. The check comes before the status check.
    2. A change that is not pending returns 409.
    3. Proposer re-check (rows locked `FOR SHARE`). A user proposer must still be in the org and be owner/admin, or a member with a `writer` grant on the project. A service-token proposer must be unrevoked, unexpired, `read-write` and scoped to the change's project and env. Otherwise: status `stale`, `decided_by`/`decided_at` set, ciphertext set to NULL, audit `change.stale` / `failed` with details `{change_id, base_version, reason:"proposer_unauthorized"}`, commit, 409.
    4. Lock the head row. If its current version differs from `base_version`, or the target vanished, the change becomes `stale` the same way (no `reason`) and returns 409.
    5. Otherwise apply the operation (the version author is the proposer), set the status to `approved` with `decided_by`/`decided_at`/`applied_version`, and set the ciphertext to NULL. Audit `change.approve` (details `{change_id, version}`) plus the underlying `secret.write`/`secret.delete`/`secret.rollback` (actor = approver, details `{change_id, version, to?}`).
  - Returns 200 `{id, status:"approved", version}`.
- `POST /changes/{id}/reject`: OA only, and the two-person rule does not apply. Returns 200 `{id,status:"rejected"}` and sets the ciphertext to NULL, or 409 if the change is not pending. Audit `change.reject`.
- Change targets are audited as `<project>/<env>/<key>`. A malformed change id returns 404.

**Service tokens**
- `GET /tokens`: OA only. Response: `[{id, name, project, env, access, created_at, expires_at, revoked_at, created_by, last_used_at}]`, newest first (service tokens only, never hashes).
- `POST /tokens {project, env, access, ttl_seconds, name?}`:
  - OA only. A member gets 403 and an ST gets 403.
  - The body is validated first (400). `project` and `env` are required. `access` ∈ {read, read-write}. `ttl_seconds` is a plain JSON integer in [60, 7776000] (1 minute to 90 days). A name, if given, is at most 100 characters with no control characters.
  - The project and env are then resolved within the org, otherwise 404.
  - Returns 201 `{id, token, name, project, env, access, expires_at}`.
  - Audit `token.issue` (target = token id, details `{project, env, access, ttl_seconds}`; never the token). `created_by` is the issuing user.
- `DELETE /tokens/{id}`: OA only. Returns 404 if the token is not a service token of this org. Returns 200 `{"status":"revoked"}`. Idempotent: an already-revoked token returns 200. PATs are 404 here. Audit `token.revoke` (details `{already_revoked}`).

**Audit**
- `GET /audit?actor=&action=&since=&limit=`:
  - OA only (a member gets 403, an ST gets 403).
  - Filters: `actor` is an exact actor id. `action` is an exact action name. `since` is RFC 3339 (fractional seconds allowed; invalid returns 400) and matches `ts >= since`. `actor` and `action` are sanitised like stored audit strings. `limit` defaults to 100, max 1000; a value that is not an integer between 1 and 1000 returns 400.
  - Returns events newest first: `[{seq, ts, actor:{type,id}, action, target, source_ip, result, details, prev_hash, hash}]`.
- `GET /audit/verify` → `{valid: bool, first_invalid_seq: int|null}` for the caller's org chain. OA only.

### 5.4 Audit chain

- Chains: one per org (chain = org id) plus `platform`.
- **Routing:**
  - Org user or ST actor → their org chain.
  - Platform admin, system (`platform.bootstrap`) or unauthenticated actor → `platform`.
  - Failed and locked logins → always `platform`, with target `email:<sha256 prefix>` for known and unknown emails alike. When the email belongs to an org user, a copy also goes to that org's chain, with target = the user id. Successful logins go only to the user's own chain (§5.3 Auth).
  - `org.create` → `platform` plus the new org's chain (genesis event). `org.disable` → `platform` only.
- **Denials:** every 403 or 404 produced by authorization (the not-visible resolution steps above, role checks, ST scope checks) is audited with action `authz.denied`. The target is the requested method and route pattern plus the identifiers exactly as given in the request (for example `GET /projects/{p}/envs/{e}/secrets/{key} p=acme e=prod key=DB_URL`). Values are never included, and the target never says whether the resource exists. Result is `denied`. Details are `{status: 403|404}`. A 404 from a genuinely missing resource under an authorized caller is also audited as `authz.denied` with status 404, so the two cases are indistinguishable in the log as well. Unmatched-route 404s and 401s are not audited, except for login. 400s are not audited. If appending a denial event fails, the 403/404 is still returned and the failure is logged.
- **Event JSON used for hashing:** a canonical JSON object with exactly these keys, sorted lexicographically:
  `action, actor_id, actor_type, chain, details, org_id, prev_hash, result, seq, source_ip, target, ts`.
  - `ts` is RFC 3339 UTC with microseconds (`2006-01-02T15:04:05.000000Z`).
  - `seq` is a JSON integer. `org_id` is a string or null.
  - `details` is an object whose keys are also sorted recursively. Its values are strings, integers or bools only.
  - No insignificant whitespace. Go `encoding/json` with HTML escaping disabled.
- `hash = hex(sha256( prev_hash_hex_ascii || canonical_json ))`. The genesis `prev_hash` is 64 `"0"` characters. `seq` starts at 1 for each chain.
- **Append:** in a tx:
  1. `SELECT last_seq,last_hash FROM audit_chains WHERE chain=$1 FOR UPDATE`. If there is no row, insert `(chain, 0, genesis)` with `ON CONFLICT DO NOTHING` and select again.
  2. Take `ts` now, after the lock, so timestamps are monotonic per chain.
  3. Sanitise the string fields: invalid UTF-8 is replaced, NUL removed, and each field capped at 2048 bytes.
  4. Compute the events and insert them.
  5. Update the chain head.

  `ts` is truncated to microseconds *before* hashing and stored as-is. A write's audit append happens in the same tx as the write. Standalone events (reads, denials, integrity failures) go through a per-chain group-commit appender: one tx per batch of at most 1000 events, and each request waits for its own commit before responding.
- **Verify:** walk the chain in seq order. For each row, check that seq = previous seq + 1 (starting at 1), that `prev_hash` equals the previous row's hash, and that the recomputed hash equals the stored hash. Also check that the chain head matches the last row; if it doesn't, the first invalid seq is last+1. Return the first invalid seq.
- Never stored in the audit log: secret values, passwords, tokens, token hashes.

## 6. CLI behaviour

- The binary is `./bin/coffer`, built from `cmd/coffer`, statically linked (`CGO_ENABLED=0`). The full user-facing reference is [CLI.md](CLI.md); DECISIONS 85–100 record the CLI choices SPEC leaves open.
- **Config:** `${XDG_CONFIG_HOME:-$HOME/.config}/coffer/config.json` = `{"url": "...", "token": "..."}`. The directory is 0700 and the file 0600, created with those modes and re-chmodded on every write. The file is written atomically (temp file plus rename in the same directory).
- **URL resolution:** `--url` flag, then `COFFER_URL`, then the config `url`, then `http://127.0.0.1:8420`.
- **Token resolution:** if `COFFER_TOKEN` is set (even to an empty string), use it, trimmed, and never read or write the config file. In that case the config `url` isn't used either. Otherwise use the config `token`. No token, an empty token, or one with spaces or control characters exits 3 without a request. `login` with `COFFER_TOKEN` set prints an error and exits 2. An empty `COFFER_URL` is ignored. An invalid URL (not http(s), no host, or with credentials, query or fragment) exits 2.
- **Flags:** global flags `--url`, `--json` and `--help`/`-h` may appear anywhere, also before the command words. `-p/--project`, `-e/--env`, `--version`, `--expect-version`, `--to`, `--format`, `--access`, `--ttl`, `--name`, `--status`, `--limit`, `--actor`, `--action`, `--since`, `--role`, `--level`, `--owner-email`, `--email` and `--protected` are accepted in both `--flag value` and `--flag=value` forms, in any position, as long as the command accepts them. `--` ends flag parsing. `run` also stops at the first positional argument, so `--` is optional there. For `secrets set`, `--` allows a value starting with `-`. An unknown flag, a missing argument, or an extra argument is a usage error: exit 2 with a usage message on stderr.
- **Passwords:** read from stdin, as the first line with the trailing `\n` or `\r\n` stripped. They are never accepted in argv. `passwd` reads two lines: the current password, then the new one. An empty line or no input exits 2. More than 1024 bytes, or invalid UTF-8, exits 6.
- **Output:** human-readable text by default. With `--json`, stdout carries exactly one JSON document on success: usually the server response, re-indented with its key order kept. The exceptions are login (token removed), 202 writes, logout and version, and `secrets export --format dotenv`, which is wrapped as `{"content":"<dotenv>","format":"dotenv"}`. Errors always go to stderr as `error: <message> (<code>)`, and stdout stays empty. With `--json`, a JSON error document `{"error":{"code","message"}}` is also written to stderr, using the server's code and message unchanged.
- **`secrets get`:** if stdout is not a TTY, write the exact value bytes with no newline. If it is a TTY, add a trailing newline. With `--json`, print `{"key","version","value"}`.
- **`secrets set KEY [VALUE]`:** without VALUE, read stdin to EOF, bytes exact, no trimming. Invalid UTF-8 or more than 65,536 bytes exits 6 before any request is sent. A value given in argv is used as-is (same checks).
- **`secrets delete` / `secrets rollback`** accept `--expect-version N` (query parameter for delete, body for rollback). `secrets export` defaults to `--format json`.
- Integer flags (`--version`, `--expect-version`, `--to`) that aren't integers exit 6 locally. An empty, `.` or `..` path segment (key, slug, id) exits 6 locally. Every other segment is escaped with `url.PathEscape`.
- **Protected writes (202):** print the change id. Human output is `pending approval: change <id>` on stdout; `--json` prints `{"status":"pending","change_id":"..."}`. Exit 7.
- **Exit codes:**
  - From HTTP status: 401→3, 403→4, 404→5, 400/413/422→6, 409→8, 429→10, other non-2xx→1. 202 on a write→7.
  - Connection failure, redirect (3xx, never followed) or unexpected response → 1. Usage → 2. No token → 3.
  - `audit verify` and `admin audit verify` exit 9 when `valid` is false. They print `chain valid` / `chain invalid at seq N` (or the JSON with `--json`).
- **Email lookup:** `member role|remove EMAIL` and `grant set|revoke EMAIL` call `GET /members`, find the user by email (case-insensitive), and call the id-based route. An unknown email exits 5.
- **`admin org create SLUG --owner-email E`:** owner password on stdin. `admin org disable SLUG`.
- **`token create`:** TTL syntax is `<int><unit>` where unit ∈ s, m, h, d; it must fall between 1m and 90d, otherwise exit 6 locally. Human output prints the token alone on stdout (one line), plus `id: ...` and `expires_at: ...` on stderr. `--json` prints `{id, token, ...}`. A returned token without the `cof_st_` prefix exits 1.
- **`run -p P -e E -- CMD ARGS...`:**
  - Fetch `export?format=json` and build the environment from os.Environ() plus the secrets (secrets win).
  - If any value contains a NUL byte, or a key cannot be an environment variable name, exit 1 with an error naming the key (never the value) and do not start the child. POSIX environment strings cannot carry NUL (DECISIONS 62).
  - Use `exec.Command` with stdin, stdout and stderr inherited.
  - Forward SIGINT, SIGTERM, SIGHUP and SIGQUIT to the child.
  - Exit with the child's exit code, or 128+signal if the child died from a signal.
  - Nothing is written to disk. `--json` has no effect (the child owns stdout).
  - CMD is looked up with the CLI's own `PATH`. If CMD is not found, exit 127; if it can't be executed, exit 126. If the fetch fails, use the mapped exit code and do not run the child.
- **`login --email E [--url U]`:**
  - Read the password from stdin and POST `/auth/token`.
  - Save `{url, token}` to the config. Print `logged in as E` (`--json`: the response without the token). A returned token without the `cof_pat_` prefix exits 1.
  - If stdin is a TTY, prompt on stderr and turn off echo with a TCGETS/TCSETS ioctl (best effort; Ctrl-C restores echo and exits 130). A non-TTY stdin is fine.
  - Warn on stderr when the URL is plain `http://` to a host that isn't loopback.
- **`logout`:** POST `/auth/logout`, then remove the token from the config file, also when the server answered 401. On a network error or 5xx the token is kept and the mapped code is returned. With no stored token, print `not logged in` and exit 0. With `COFFER_TOKEN` set, only the server call is made.
- **`whoami`:** GET `/me`.
- **Human output of tables:** tab-separated columns with a header line.
- **HTTP client:** 30 s timeout. User-Agent `coffer-cli/<version>`. Redirects are never followed. Response bodies are capped at 64 MiB. The token never appears in error messages. Control characters, bidi overrides and invalid UTF-8 in server text are escaped in human output (never in secret values).
- Reading a config file with a mode looser than 0600 prints a warning. Every write re-applies 0700/0600.

## 7. Error messages shown by the CLI

For a non-2xx response, the CLI prints `error: <server message> (<code>)` to stderr. If the
body has no `code`, it prints `error: <message>` and the JSON error code is `http_<status>`.
If the body is not a JSON error, it prints `error: HTTP <status>`. Errors the CLI detects
itself use the JSON codes `usage`, `validation`, `connection`, `unauthenticated`, `not_found`
and `error`.
