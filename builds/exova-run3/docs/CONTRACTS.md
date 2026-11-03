# Frozen contracts (v1)

Everything in this file is frozen. Foundation implements it; no slice invents a route, a table,
an error code or an audit action name. Changing anything here requires an entry in
`docs/DECISIONS.md`.

## 1. Package boundaries

Go compiles whole packages, so each slice must be a separate package. A slice that imports a
peer's package cannot build until that peer is finished.

```
internal/config            env parsing, master-key gate                     foundation
internal/httpx             envelope, codes, headers, body limit             foundation
internal/reqctx            Actor, Denial, Recorder                          foundation
internal/authz             pure visibility predicates                       foundation
internal/idgen             opaque ids and credential secrets                foundation
internal/crypto            envelope encryption, AAD, rotation               E2
internal/audit             event model, chain append, verify                 E3 (event.go: foundation)
internal/store             db.go, store.go, migrations                      foundation
internal/store/auth        orgs, users, members, grants, tokens, projects    E1
internal/store/secrets     secrets, versions, change requests               E2
internal/store/auditq      audit reads and filters                          E3
internal/api/authapi       auth, members, grants, projects, envs, tokens    E1
internal/api/secretsapi    secrets, versions, export, changes               E2
internal/api/auditapi      audit routes                                     E3
internal/httpapi           router.go (composition root), server.go          foundation
internal/testutil          test DB + PAT minting                            foundation, extended by E5
cmd/coffer                 CLI                                              E4
```

`router.go` is the composition root. It calls one `Register(mux, deps)` per slice package and
**never changes after Stage 0**. Slices cross-talk only through `audit.Writer`, `reqctx`,
`authz`, `httpx` and the `store` base — never through a peer's internals.

Scoped check per engineer: `go build ./internal/<own pkgs>/... && go vet ./internal/<own pkgs>/...`
plus `go test ./internal/<own pkgs>/...`.

Each slice is its own package for exactly this reason: a slice that imported a peer's package could
not build until that peer finished, so the scoped check would be meaningless and four engineers
would serialise behind each other. Cross-slice needs go through the frozen interfaces only —
`audit.Writer`, `reqctx`, `authz`, `httpx`, and the `store` base — never a peer's internals.

`router.go` is frozen at the end of Stage 0. It calls `authapi.Register`, `secretsapi.Register` and
`auditapi.Register`; it never learns a route afterwards.

`internal/testutil` ships in Stage 0, not with ops: connecting to the test database, running
migrations, and minting a real PAT over `POST /auth/token`. Every slice's acceptance depends on it,
so it cannot belong to one slice's peer. E5 extends it; nobody forks it.

## 2. Error codes and status mapping

Body on every error: `{"error":{"code":"...","message":"..."}}`. Never a stack trace, SQL text or
internal path. Message text is stable and generic.

| Status | Code | When |
|---|---|---|
| 400 | `validation_error` | malformed body, bad slug, bad key format, field the caller may not set, self role change |
| 401 | `unauthenticated` | missing, malformed, unknown, expired or revoked credential; disabled organization |
| 403 | `forbidden` | resource is visible but the caller lacks the permission |
| 403 | `password_change_required` | the caller must change an initial password first; exactly two routes are exempt (`POST /auth/password`, `POST /auth/logout`). See `docs/DECISIONS.md` |
| 404 | `not_found` | missing, other organization, no grant, outside service-token scope, platform admin on any org route, unknown path, wrong method |
| 409 | `conflict` | expected-version mismatch, stale change, last owner, duplicate email, duplicate slug, already-resolved change |
| 413 | `body_too_large` | request body over 1 MiB |
| 429 | `rate_limited` | login lockout, per-IP bucket, global denial cap |
| 500 | `internal_error` | anything unexpected; message is the literal string `internal error` |
| 202 | — | pending approval; body is `{"status":"pending","change_id":"..."}`, not an error |

Headers on every `/api/v1` response: `Content-Type: application/json`,
`X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `X-Request-Id`.
A dotenv export may be `text/plain` instead of `application/json`; the other three still apply.
No CORS headers are ever emitted.

## 3. Audit action names

```
login.success   login.failure   logout
secret.read     secret.write    secret.delete    secret.rollback
change.created  change.approved change.rejected  change.stale
member.added    member.removed  member.role_changed
grant.set       grant.revoked
token.issued    token.revoked
project.created environment.created
organization.created  organization.disabled
denied
masterkey.rotated
```

Results: `success`, `denied`, `failed`.

Chain scopes: an organization ID, or the literal `platform` for the platform admin, for
unauthenticated callers, and for anonymous denials. `seq` starts at 1 per scope.

## 4. Route table (§7.2, all under `/api/v1`)

`authapi`: `POST /auth/token`, `POST /auth/logout`, `POST /auth/password`, `GET /me`,
`GET|POST /admin/orgs`, `POST /admin/orgs/{org}/disable`, `GET|POST /members`,
`PATCH|DELETE /members/{user_id}`, `PUT|DELETE /members/{user_id}/grants/{project}`,
`GET|POST /projects`, `GET|POST /projects/{p}/envs`, `GET|POST /tokens`,
`DELETE /tokens/{id}`.

`secretsapi`: `GET /projects/{p}/envs/{e}/secrets`,
`GET|PUT|DELETE /projects/{p}/envs/{e}/secrets/{key}`,
`GET /projects/{p}/envs/{e}/secrets/{key}/versions`,
`GET /projects/{p}/envs/{e}/secrets/{key}/versions/{n}`,
`POST /projects/{p}/envs/{e}/secrets/{key}/rollback`,
`GET /projects/{p}/envs/{e}/export`, `GET /changes`,
`POST /changes/{id}/approve`, `POST /changes/{id}/reject`.

`auditapi`: `GET /audit`, `GET /audit/verify`, `GET /admin/audit`, `GET /admin/audit/verify`.

Outside `/api/v1`: `GET /healthz`, `GET /readyz`. Every other path returns 404.

## 5. AAD byte layout

`aad(parts ...string) []byte` is `uvarint(len(p)) || p` for each part in order. Length prefixes
make adjacent fields unambiguous, so no value can be shifted across a field boundary to forge a
valid tag.

| Purpose | Parts |
|---|---|
| secret value | `coffer:v1`, org id, project id, env id, key, version (decimal) |
| project data key wrap | `coffer:dek:v1`, org id, project id, key version (decimal) |
| change request payload | `coffer:change:v1`, org id, project id, env id, key, change id |

A ciphertext moved to another row fails the tag check and returns an error. It never returns a
value. Rollback decrypts at version k with k's AAD and re-encrypts under n+1 with n+1's AAD.

## 6. Schema

`0001_init.sql` runs as the owner inside one transaction under the advisory lock, together with
the grant/revoke block. A failure leaves no partial schema.

```sql
CREATE TABLE organizations (
  id           text PRIMARY KEY,
  slug         text NOT NULL UNIQUE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  disabled_at  timestamptz
);

CREATE TABLE users (
  id                   text PRIMARY KEY,
  org_id               text REFERENCES organizations(id),   -- NULL only for the platform admin
  email                text NOT NULL UNIQUE,                -- lowercased
  password_hash        text NOT NULL,
  role                 text NOT NULL,                       -- owner|admin|member|platform_admin
  must_change_password boolean NOT NULL DEFAULT false,
  removed_at           timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE personal_access_tokens (
  id         text PRIMARY KEY,
  user_id    text NOT NULL REFERENCES users(id),
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE INDEX ON personal_access_tokens (user_id);

CREATE TABLE projects (
  id         text PRIMARY KEY,
  org_id     text NOT NULL REFERENCES organizations(id),
  slug       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, slug)                                     -- per-org only; global would leak
);

CREATE TABLE environments (
  id         text PRIMARY KEY,
  project_id text NOT NULL REFERENCES projects(id),
  slug       text NOT NULL,
  protected  boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, slug)
);

CREATE TABLE project_grants (
  project_id text NOT NULL REFERENCES projects(id),
  user_id    text NOT NULL REFERENCES users(id),
  level      text NOT NULL,                                 -- viewer|reader|writer
  PRIMARY KEY (project_id, user_id)
);

CREATE TABLE service_tokens (
  id         text PRIMARY KEY,
  org_id     text NOT NULL REFERENCES organizations(id),
  project_id text NOT NULL REFERENCES projects(id),
  env_id     text NOT NULL REFERENCES environments(id),
  access     text NOT NULL,                                 -- read|read-write
  name       text,
  token_hash text NOT NULL UNIQUE,
  created_by text NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX ON service_tokens (project_id, env_id);

CREATE TABLE project_data_keys (
  project_id  text PRIMARY KEY REFERENCES projects(id),
  wrapped_key bytea NOT NULL,
  nonce       bytea NOT NULL,
  key_version integer NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE secrets (
  id              text PRIMARY KEY,
  env_id          text NOT NULL REFERENCES environments(id),
  key             text NOT NULL,
  current_version bigint NOT NULL DEFAULT 0,                -- the allocator; never MAX()+1
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  updated_by      text,
  UNIQUE (env_id, key)
);

CREATE TABLE secret_versions (
  secret_id  text NOT NULL REFERENCES secrets(id),
  version    bigint NOT NULL,
  ciphertext bytea,                                         -- NULL on a tombstone
  nonce      bytea,
  deleted    boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text,
  PRIMARY KEY (secret_id, version)
);

CREATE TABLE change_requests (
  id             text PRIMARY KEY,
  org_id         text NOT NULL REFERENCES organizations(id),
  project_id     text NOT NULL REFERENCES projects(id),
  env_id         text NOT NULL REFERENCES environments(id),
  secret_id      text REFERENCES secrets(id),               -- NULL for a create-by-set
  key            text NOT NULL,
  op             text NOT NULL,                             -- set|delete|rollback
  payload_ct     bytea,                                     -- AAD-bound to id
  payload_nonce  bytea,
  base_version   bigint NOT NULL,                           -- version seen at proposal time
  target_version bigint,                                    -- rollback source, else NULL
  status         text NOT NULL DEFAULT 'pending',           -- pending|approved|rejected|stale
  proposer_id    text NOT NULL REFERENCES users(id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  resolved_at    timestamptz,
  resolver_id    text REFERENCES users(id)
);
CREATE INDEX ON change_requests (org_id, status);

CREATE TABLE audit_events (
  scope      text NOT NULL,
  seq        bigint NOT NULL,
  ts         timestamptz NOT NULL,
  actor_id   text NOT NULL,
  actor_kind text NOT NULL,
  org_id     text NOT NULL DEFAULT '',
  action     text NOT NULL,
  target     text NOT NULL DEFAULT '',
  source_ip  text NOT NULL DEFAULT '',
  result     text NOT NULL,
  prev_hash  text NOT NULL,
  hash       text NOT NULL,
  PRIMARY KEY (scope, seq)
);

CREATE TABLE audit_heads (
  scope text PRIMARY KEY,
  seq   bigint NOT NULL,
  hash  text NOT NULL
);

CREATE TABLE schema_migrations (
  version    bigint PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now(),
  checksum   text NOT NULL
);
```

### Roles and grants, inside the same transaction

```sql
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coffer_app') THEN
    CREATE ROLE coffer_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;

REVOKE ALL ON audit_events FROM PUBLIC;
GRANT SELECT, INSERT ON audit_events TO coffer_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  organizations, users, personal_access_tokens, projects, environments,
  project_grants, service_tokens, project_data_keys, secrets, secret_versions,
  change_requests TO coffer_app;
GRANT SELECT, INSERT, UPDATE ON audit_heads TO coffer_app;   -- append advances the head
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO coffer_app;
GRANT USAGE ON SCHEMA public TO coffer_app;                  -- no CREATE

ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO coffer_app;
ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO coffer_app;
```

`coffer_app` owns nothing, is not a member of the owner role, and has no `CREATE` on the schema,
so it cannot `ALTER TABLE … DROP TRIGGER` or re-grant itself. The whole block is re-applied after
every migration.

```sql
CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    RETURN COALESCE(NEW, OLD);   -- superuser tamper succeeds so verify can report it
  END IF;
  RAISE EXCEPTION 'audit_events is append-only';
END $$;

CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();
```

`COPY` does not fire row triggers, so backup and restore are unaffected.
`session_replication_role = replica` bypasses both controls and requires superuser; documented.

## 7. Canonical audit encoding (frozen at v1)

Field order is fixed by the struct; HTML escaping is off; timestamps are
`2006-01-02T15:04:05.000000Z` (UTC, microsecond, matching `timestamptz`).

```
hash = lowercase hex of SHA-256( prev_hash_bytes || canonicalJSON )
canonicalJSON = {"scope","seq","ts","actor","actor_kind","org","action","target","source_ip","result","prev_hash"}
```

Verify walks `audit_events` from `seq` 1 per scope, rebuilds the canonical bytes from the row's own
columns, and never trusts `audit_heads`. A head/events disagreement is reported as its own finding.
Adding a field to the canonical form needs a `canon_version` marker and a migration.

## 8. Authentication and revocation

One indexed query per request, no cache anywhere:

```
token → (user | service_token) → org → grant
reject when revoked_at IS NOT NULL, expires_at <= now(), users.removed_at IS NOT NULL,
        organizations.disabled_at IS NOT NULL
```

Expiry is compared with the database clock in SQL. Tokens are 256-bit, prefixed `cof_pat_` or
`cof_st_`, stored only as SHA-256 hex, and shown once at creation.

`source_ip` is the socket peer unless `COFFER_TRUST_PROXY=1`, which takes the rightmost
`X-Forwarded-For` entry that is not in the trusted-proxy set. The same resolver feeds the per-IP
login throttle, so a rotated header cannot buy extra attempts.

## 9. Concurrency invariants

- Secret version allocation: `UPDATE secrets SET current_version = current_version + 1
  WHERE id = $1 [AND current_version = $expected] RETURNING current_version`. Zero rows with an
  expected version is a 409. The row update is the lock.
- Change approval: `UPDATE change_requests SET status='approved' WHERE id=$1 AND status='pending'
  RETURNING …`; zero rows is a 409. Then `SELECT … FROM secrets FOR UPDATE` and compare
  `base_version` to `current_version`; a mismatch marks the request `stale`, audits
  `change.stale`, returns 409. Proposer equals approver is a 403 before any state change.
- Audit append: `SELECT … FROM audit_heads WHERE scope=$1 FOR UPDATE`, then insert, then update
  the head, all in the caller's transaction.

## 10. Environment variables

| Variable | Required | Notes |
|---|---|---|
| `COFFER_MASTER_KEY` | yes | base64, exactly 32 bytes; placeholder from `.env.example` is refused |
| `COFFER_MASTER_KEY_PREVIOUS` | no | set only during rotation |
| `COFFER_BOOTSTRAP_ADMIN_EMAIL` | yes | used only when no users exist |
| `COFFER_BOOTSTRAP_ADMIN_PASSWORD` | yes | at least 12 characters |
| `COFFER_PORT` | no | default 8420 |
| `COFFER_BIND_ADDR` | no | default `127.0.0.1`; compose sets `0.0.0.0` |
| `COFFER_TRUST_PROXY` | no | `1` enables rightmost-untrusted XFF |
| `COFFER_ENV` | no | `production` (default) or `development` |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | yes | owner role, superuser in compose |
| `COFFER_APP_DB_PASSWORD` | no | runtime role `coffer_app`; absence is the gated degraded mode |
| `COFFER_MIGRATION_DATABASE_URL` | no | overrides the derived owner URL |
| `DATABASE_URL` | no | overrides the derived runtime URL |
| `COFFER_DB_HOST` / `COFFER_DB_PORT` / `COFFER_DB_SSLMODE` | no | defaults `127.0.0.1` / `5432` / `disable` |
| `COFFER_DB_MAX_CONNS` | no | runtime pool ceiling, default `32`, max `500`; bounded so a spike cannot exhaust a shared database |
| `COFFER_DB_MIN_CONNS` | no | runtime pool warm floor, default `4` |
| `COFFER_ALLOW_DEGRADED_DB_ROLE` | no | `1` opts into single-role boot; refused when `COFFER_ENV=production` |

## 11. Degraded database role, gated

Running the server as the owner role gives up the isolation `coffer_app` exists to provide, so it
is never silent:

- `COFFER_APP_DB_PASSWORD` absent **and** `COFFER_ALLOW_DEGRADED_DB_ROLE=1` and
  `COFFER_ENV != production` → boot proceeds as the owner role, logging a WARN that names the lost
  isolation in the message.
- `COFFER_ENV=production` with the degraded flag set → refuse to start, naming both variables.
- `COFFER_APP_DB_PASSWORD` present but rejected by the server → **failed start**, never a fallback.
  A rejected credential is a misconfiguration, and silently escalating to the owner role would
  turn a typo into a privilege change.
- Neither variable set in a non-production environment → refuse to start, naming
  `COFFER_APP_DB_PASSWORD` and `COFFER_ALLOW_DEGRADED_DB_ROLE`.

## 12. Migration atomicity

Each migration file runs inside a single transaction, under the advisory lock, and the
grant/revoke/`ALTER DEFAULT PRIVILEGES` block runs inside that same transaction. A failure part way
through `0001_init.sql` therefore rolls back to no schema at all rather than leaving a half-created
one, and the roles and grants can never be applied against tables that do not exist.

## 13. Restore hands off to verify

`restore.sh` restores the dump verbatim and does not validate the audit chain, because a restore
must be able to reproduce a tampered dump so that verification can report it. It therefore cannot
be the thing that declares a restore good. On success it prints the exact command

```
./bin/coffer audit verify
```

and states that the restore is not complete until that command reports the chain valid. The same
sentence appears in the README restore section.
