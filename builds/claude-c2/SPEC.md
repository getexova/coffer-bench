# Coffer: build specification

Coffer is a self-hosted secrets and configuration service for an engineering organization. It is a server with an HTTP API and a CLI. There is no web interface. Teams store API keys, database passwords and config values per project and environment. People and CI read them with least privilege, and every access is audited.

Build it to the standard you would hand to a security reviewer before production. Language, framework and libraries are your choice. The interfaces in §7 are fixed. A hidden black-box acceptance suite will run against a clean clone of your repository, using only those interfaces and the scripts in §5. Anything it cannot reach through them does not count. Nothing will be fixed for you: if the README quickstart does not work verbatim on a clean clone, every runtime check scores zero.

You will not receive further input. Where this spec is silent, decide, and record the decision in `docs/DECISIONS.md`.

**Priorities.** Items marked **(P1)** are stretch goals and are worth less. Everything else is required. A working, secure core beats a broken extra.

**Done means** you ran it the way the suite will: a clean clone, the README followed verbatim, two organizations, and every rule in §2 tried from the wrong side.

---

## 1. Domain

- **Platform admin.** Created on first boot from `COFFER_BOOTSTRAP_ADMIN_EMAIL` and `COFFER_BOOTSTRAP_ADMIN_PASSWORD`, but only if no users exist yet. The platform admin creates and disables organizations and creates each organization's first owner. The platform admin can never read an organization's secrets, members, tokens or audit log.
- **Organization.** A hard tenant boundary. Every user belongs to exactly one organization.
- **Org roles.** `owner`, `admin`, `member`.
- **Project.** Belongs to one organization and has environments. Slugs are unique within an organization, not globally.
- **Environment.** For example `dev`, `staging` or `prod`. An environment may be **protected**.
- **Secret.** A key and value inside an environment. Secrets are versioned.
- **Project grant.** Gives a `member` access to one project at level `viewer`, `reader` or `writer`. Owners and admins can access every project in their organization without a grant.
- **Personal access token (PAT).** Issued at login and used by the CLI.
- **Service token.** A machine credential scoped to exactly one project and one environment. Its access is `read` or `read-write`, and it always has an expiry.
- **Change request.** A pending write to a protected environment.
- **Audit event.** An append-only record of something that happened.

## 2. Authorization rules

1. **Invisible means 404.** A request returns **404** when it targets something outside the caller's organization, a project the caller has no access to, or anything outside a service token's project and environment. That response is identical to the one for a resource that does not exist. Return **403** only when the caller can see the resource but lacks the permission.
2. **Owners** can do everything inside their organization. Only an owner can create an owner, promote someone to owner, demote an owner or remove an owner. The last owner cannot be demoted or removed (**409**).
3. **Admins** manage members and grants (but never owners), projects, environments and service tokens. They approve and reject changes and read the audit log.
4. **Members with a grant:**
   - `viewer` sees secret names and metadata only.
   - `reader` can also read values, export, and use `run`.
   - `writer` can also set, delete and roll back.
5. **Members without a grant** cannot see the project (404).
6. **Members** cannot manage members, grants or tokens, cannot approve changes, and cannot read the audit log (403).
7. **Service tokens** can only perform secret operations inside their scope.
   - `read` allows list, get, export and `run`.
   - `read-write` also allows set, delete and rollback.
   - Service tokens can never approve changes, manage members, issue tokens, read the audit log or create PATs (403).
8. **Protected environments.** Any write (set, delete or rollback) by anyone allowed to write creates a change request (**202**) instead of changing the value.
9. **Two-person rule.** A change request can be approved only by an owner or admin who is not its proposer. Approving your own request returns 403. Approval applies the change atomically. If the key has changed since the request was created, approval fails with **409** and the request becomes `stale`.
10. **Platform admin.** Can manage organizations and read the platform audit log only. Every organization-scoped route returns 404 for the platform admin.
11. **Revocation is immediate.** The next request after any of these events must reflect it, within 1 second: a token revoked or expired, a user removed, a grant revoked or lowered, an organization disabled.
12. **No self-escalation.** No request lets a caller change their own role, grants, organization or platform-admin status. Fields a caller may not set are rejected with 400 or ignored. They are never applied.

## 3. Secrets

- **Format.** Keys match `^[A-Z_][A-Z0-9_]{0,127}$`. A value is any UTF-8 string from 0 to 65,536 bytes inclusive, and its bytes are stored and returned exactly.
- **Versions.** Each set creates version n+1, starting at 1.
  - **Delete** creates a tombstone version. A get then returns 404, but history keeps the tombstone, and a later set continues the numbering.
  - **Rollback** to version k creates a new version holding k's value.
- **Concurrency.** A write may carry an expected version, and a mismatch returns **409**. Concurrent unconditional writes to the same key must each get a distinct version, with no gaps and no lost updates.
- **Listing** returns key, current version, `updated_at` and `updated_by`, and never values.
- **Value exits.** Values leave the server only through a single-key get (current or past version), export and `run`. All three are audited, with one event per key read.

## 4. Security requirements

### Encryption at rest
- **Envelope encryption.** `COFFER_MASTER_KEY` (base64, 32 bytes) wraps a data key per project. Data keys encrypt values with an AEAD cipher (AES-256-GCM or XChaCha20-Poly1305).
- **Bound ciphertext.** Associated data binds each ciphertext to its organization, project, environment, key and version. A ciphertext copied into another row must fail to decrypt. It must never return a value.
- **No plaintext anywhere.** No plaintext secret value, token or password may appear in the database, logs, backups or CLI config. The one exception is the CLI's own token in its own config file.
- **Startup check.** The server refuses to start if the master key is missing, is not 32 bytes, or equals the placeholder in `.env.example`.
- **Rotation.** Starting with `COFFER_MASTER_KEY_PREVIOUS=<old>` and `COFFER_MASTER_KEY=<new>` re-wraps every data key under the new key before the server reports ready. After that, the old key is no longer needed.

### Authentication
- **Passwords** are hashed with argon2id, bcrypt (cost ≥ 12) or scrypt, and must be at least 12 characters.
- **Login responses** for an unknown email and for a wrong password are identical in status and body and take similar time.
- **Lockout.** After 5 failed logins for an account within 15 minutes, further logins for that account return **429** until the window passes, even with the correct password. Other accounts are unaffected.
- **Tokens:**
  - at least 128 bits of randomness
  - prefixed `cof_pat_` or `cof_st_`
  - stored only as a hash and shown once, at creation
  - logout revokes the PAT on the server
- **CLI passwords** are accepted on stdin only, never in argv.
- **(P1)** Users created with an initial password must change it before doing anything else.
- **(P1)** A password change revokes the user's other PATs.

### HTTP
- **Surface.** The server serves only the API under `/api/v1`, plus `/healthz` and `/readyz`. Every other path returns 404.
- **Headers on every `/api/v1` response:** `Content-Type: application/json` (a dotenv export may be `text/plain`), `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`.
- **CORS.** No origin gets CORS access.
- **No values in URLs.** Secret values never appear in a URL.
- **Body limit.** A request body larger than 1 MiB returns **413**.
- **Errors** use the JSON body `{"error":{"code":"...","message":"..."}}`. No response contains a stack trace, SQL text or an internal path.

### Audit
- **Events recorded.**
  - Logins: success and failure. Logout.
  - Secrets: each read (one event per key), each write, delete and rollback.
  - Change requests: created, approved, rejected, stale.
  - Organization changes: member, role and grant changes; token issued and revoked; project and environment created; organization created and disabled.
  - Denials: every request denied by authorization (403 or 404).
- **Where events go.** Each event goes to the actor's organization log, including a denied attempt on another organization's resource, which must not reveal whether that resource exists. Events by the platform admin and by unauthenticated callers go to a platform log, which only the platform admin can read.
- **Fields.** Sequence number, timestamp, actor (user or token ID), action, target, source IP, result (`success`, `denied` or `failed`), `prev_hash` and `hash`.
- **Hash chain.** Each organization has its own chain, and so does the platform log: `hash = SHA-256(prev_hash || canonical JSON of the event without hash)`.
- **Never logged.** Secret values, passwords and tokens never appear in the audit log.
- **Verification** recomputes the chain and reports the first invalid sequence number.
- **(P1)** The database role the server uses cannot `UPDATE` or `DELETE` audit rows.

## 5. Operations

- **Compose file.** `compose.yaml` sits at the repository root, with services named `server` and `db`. `db` uses the image `postgres:16`. The stack must work with both `docker compose` and `podman compose`.
- **Scripts** (all at repository root):

  | Script | Behaviour |
  |---|---|
  | `./scripts/init-env.sh` | Creates `.env` from `.env.example` with a freshly generated master key and bootstrap admin password, and prints the password once. |
  | `./scripts/up.sh` | Starts the stack. Returns 0 once `/readyz` is 200, or fails after 180 s. |
  | `./scripts/down.sh` | Stops the stack and keeps the data. |
  | `./scripts/build.sh` | Produces `./bin/coffer`. |
  | `./scripts/test.sh` | Runs your test suite. Exit 0 means pass. |
  | `./scripts/backup.sh FILE` / `./scripts/restore.sh FILE` | Back up the database to FILE and restore it from FILE. |

- **Port.** The server listens on host `127.0.0.1:${COFFER_PORT:-8420}`.
- **Health.** `GET /healthz` returns 200 while the process is up. `GET /readyz` returns 200 only when the database is reachable and migrations are applied, and 503 otherwise. It recovers by itself when the database comes back.
- **Migrations** run automatically and idempotently at boot. Data survives `down.sh` followed by `up.sh`.
- **Containers.** The server container runs as non-root. Base images are pinned to a version, never `latest`.
- **Shutdown.** On SIGTERM the server stops accepting connections, finishes in-flight requests and exits within 10 s.
- **Logging.** The server writes JSON lines to stdout, one per request: method, route, status, `duration_ms`, `request_id`. Every response carries `X-Request-Id`. Logs never contain values, passwords, tokens, cookies or `Authorization` headers.
- **Backup and restore.** The backup file contains only ciphertext. Restoring into an empty stack with the same master key reproduces every secret, version and audit event, and the audit chain still verifies.
- **Configuration** comes from environment variables only, all documented in `.env.example`.
  - `.env` defines at least `COFFER_MASTER_KEY`, `COFFER_BOOTSTRAP_ADMIN_EMAIL`, `COFFER_BOOTSTRAP_ADMIN_PASSWORD`, `COFFER_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB`.
  - If a required variable is missing, the server exits non-zero with a message that names it.
- **Performance** on a laptop: listing an environment holding 1,000 secrets has p95 under 300 ms, and 50 concurrent value reads have p95 under 200 ms.

## 6. Engineering

- **README.md** has a quickstart that takes a clean clone to a working `coffer secrets get` in 10 commands or fewer, and lists every prerequisite (container runtime, compose, and any toolchain `build.sh` needs).
- **Tests.** Automated tests run through `./scripts/test.sh` and include authorization tests covering the rules in §2.
- **CI.** A GitHub Actions workflow runs lint, tests and build.
- **Dependencies.** Lockfiles are committed. No dependency may have a known High or Critical advisory at build time.
- **No real secrets** appear anywhere in git history.
- **Docs:**
  - `docs/SECURITY.md`: a threat model covering assets, actors, trust boundaries, master-key handling, what is out of scope, and known limitations.
  - `docs/ARCHITECTURE.md`
  - `docs/DECISIONS.md`
- **Commits.** Commit as you go. What gets graded is the final commit on the default branch.

## 7. Fixed interfaces

### 7.1 CLI

`./scripts/build.sh` produces `./bin/coffer` for Linux x86_64. If it needs a runtime (Node, Python, JVM), the README must list it.

- **Config directory.** `${XDG_CONFIG_HOME:-$HOME/.config}/coffer/`, with directory mode 0700 and file mode 0600.
- **Environment overrides.** `COFFER_URL` sets the server. `COFFER_TOKEN` supplies a PAT or a service token; when it is set, no config file is read or written.
- **Global flags.** `--url URL` and `--json`. Secret commands also take `-p/--project` and `-e/--env`.
- **Output.**
  - `--json` prints exactly one JSON document to stdout.
  - Errors go to stderr.
  - When stdout is not a TTY, `secrets get` writes the exact value bytes with no added newline.

```
coffer login --email EMAIL [--url URL]            # password on stdin
coffer logout
coffer whoami
coffer passwd                                      # (P1) stdin: current password line, then new password line

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
coffer secrets set KEY [VALUE] -p P -e E [--expect-version N]  # no VALUE: read stdin to EOF, bytes exact
coffer secrets delete KEY -p P -e E
coffer secrets history KEY -p P -e E
coffer secrets rollback KEY --to N -p P -e E
coffer secrets export -p P -e E --format dotenv|json
coffer run -p P -e E -- COMMAND [ARGS...]

coffer change list [--status pending|approved|rejected|stale]
coffer change approve ID
coffer change reject ID

coffer token create -p P -e E --access read|read-write --ttl DURATION [--name NAME]  # 1m..90d, e.g. 30m, 12h, 7d; prints the token once
coffer token list
coffer token revoke ID

coffer audit list [--actor ID] [--action NAME] [--since RFC3339] [--limit N]
coffer audit verify
```

- **Slugs** match `^[a-z0-9][a-z0-9-]{0,62}$`.
- **Protected writes.** A write to a protected environment prints the change ID and exits 7. With `--json` it prints `{"status":"pending","change_id":"..."}`.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | other error |
| 2 | usage error |
| 3 | unauthenticated (401) |
| 4 | forbidden (403) |
| 5 | not found (404) |
| 6 | validation (400 / 413 / 422) |
| 7 | pending approval (202) |
| 8 | conflict (409) |
| 9 | audit chain invalid |
| 10 | rate limited (429) |

**Export formats**
- `dotenv`: one `KEY="VALUE"` line per secret, sorted by key, LF line endings, with a final newline. Inside the quotes, escape `\` as `\\`, `"` as `\"`, newline as `\n`, carriage return as `\r`, and `$` as `\$`. Nothing else is escaped.
- `json`: a single object mapping key to value, with keys sorted.

**`run`**
- The child gets the current environment plus every secret in the environment. Secrets win on a name conflict.
- stdin, stdout and stderr are inherited.
- The exit code is the child's, or 128+N if the child was killed by signal N.
- SIGINT and SIGTERM are forwarded to the child.
- Nothing is written to disk.

### 7.2 HTTP API

The API is JSON under `/api/v1`. Requests authenticate with `Authorization: Bearer <PAT or service token>`. IDs are opaque strings. Organization-scoped routes resolve against the caller's own organization.

```
POST       /auth/token                    {email, password} -> {token, user}
POST       /auth/logout
POST       /auth/password                 {current_password, new_password}            (P1)
GET        /me

GET|POST   /admin/orgs                    POST {slug, owner_email, owner_password}
POST       /admin/orgs/{org}/disable
GET        /admin/audit?limit=            GET /admin/audit/verify     (platform log)

GET|POST   /members                       POST {email, role, password}
PATCH      /members/{user_id}             {role}
DELETE     /members/{user_id}
PUT|DELETE /members/{user_id}/grants/{project}     PUT {level}

GET|POST   /projects                      POST {slug}
GET|POST   /projects/{p}/envs             POST {slug, protected}

GET        /projects/{p}/envs/{e}/secrets                       -> [{key, version, updated_at, updated_by}]
GET        /projects/{p}/envs/{e}/secrets/{key}                 -> {key, version, value}
PUT        /projects/{p}/envs/{e}/secrets/{key}                 {value, expected_version?} -> 200 {version} | 202 {change_id}
DELETE     /projects/{p}/envs/{e}/secrets/{key}                 -> 200 {version} | 202 {change_id}
GET        /projects/{p}/envs/{e}/secrets/{key}/versions        -> [{version, deleted, created_at, created_by}]
GET        /projects/{p}/envs/{e}/secrets/{key}/versions/{n}    -> {key, version, value}
POST       /projects/{p}/envs/{e}/secrets/{key}/rollback        {to} -> 200 {version} | 202 {change_id}
GET        /projects/{p}/envs/{e}/export?format=dotenv|json

GET        /changes?status=
POST       /changes/{id}/approve
POST       /changes/{id}/reject

GET|POST   /tokens                        POST {project, env, access, ttl_seconds, name?} -> {id, token}
DELETE     /tokens/{id}

GET        /audit?actor=&action=&since=&limit=
GET        /audit/verify                  -> {valid, first_invalid_seq}

GET /healthz   GET /readyz                (outside /api/v1)
```

**Status codes**

| Code | Meaning |
|---|---|
| 200 / 201 | success |
| 202 | pending approval |
| 400 | validation |
| 401 | unauthenticated |
| 403 | forbidden |
| 404 | not found or not visible |
| 409 | conflict |
| 413 | body too large |
| 429 | rate limited |

## 8. Out of scope

Any web console or browser UI; SSO, OIDC and SAML; MFA; email delivery; TLS termination (assume a reverse proxy in front); multi-node or high availability; Kubernetes manifests; dynamic or leased secrets; users in more than one organization; billing.
