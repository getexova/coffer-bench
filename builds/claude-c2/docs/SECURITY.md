# Coffer security model

Scope: a single-node, self-hosted Coffer stack (server and PostgreSQL), run with the
provided `compose.yaml`, reached through a TLS reverse proxy the operator provides.
[CONTRACT.md](CONTRACT.md) has the design details referred to here, and
[DECISIONS.md](DECISIONS.md) the rationale.

## 1. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Secret values (current and older versions, pending changes) | `secret_versions.ciphertext`, `change_requests.ciphertext` (AES-256-GCM; pending ciphertext set to NULL once decided) | What Coffer exists to protect |
| Master key `COFFER_MASTER_KEY` | `.env` on the host, then the server container's environment and process memory | Unwraps every project DEK |
| Project data keys (DEKs) | `projects.wrapped_dek`, wrapped by the master key; plaintext only in server memory while in use | Decrypt one project's values |
| Credentials: passwords, PATs, service tokens | The DB stores argon2id hashes and SHA-256 hashes only. The CLI config holds the CLI's own PAT. CI holds service tokens. | Impersonation |
| Bootstrap admin password, Postgres owner password | `.env` (mode 0600) | Platform admin access, full DB access |
| Restricted DB role password | Not stored. Derived from the DB canary at boot. Postgres holds only a SCRAM verifier. | Request-pool DB access |
| Authorization state: roles, grants, token scopes, org disabled flag | DB | Privilege escalation |
| Audit log | `audit_events` and `audit_chains` (hash chain per org, plus platform) | Accountability, detection |
| Availability | server and DB | Deployments depend on it |

## 2. Actors

| Actor | Capabilities assumed | Goal |
|---|---|---|
| Unauthenticated network client (behind the proxy) | Can send any HTTP request to the API | Guess credentials, enumerate orgs and users, exploit parsing, exhaust resources |
| Malicious org member | Valid PAT in org A, perhaps a `viewer`/`reader`/`writer` grant | Read or write beyond the grant, escalate role, reach org B, approve their own change |
| Malicious org admin | Valid admin PAT | Become owner, remove owners, get around the two-person rule, keep access after demotion |
| Compromised service token | Token for one project and env | Act outside its scope, mint PATs or tokens, read the audit log, approve changes |
| Platform admin (curious or compromised) | Platform admin PAT | Read any org's secrets, members, tokens or audit log |
| Removed, demoted or disabled user | Old PAT, cached CLI config, pending change requests | Keep using access they have lost |
| DB or backup thief | A copy of the database or a `backup.sh` dump, without the master key | Recover secrets or credentials |
| Log reader | Server stdout, CI logs, terminal scrollback | Collect values, passwords, tokens |
| Network attacker between client and proxy | Can watch or change traffic if TLS is missing | Steal tokens in transit |
| Host root or container-runtime admin | Full control of the host | Out of scope: can read the master key |

## 3. Trust boundaries

1. **Client → reverse proxy → server.** Everything in a request is untrusted. TLS
   ends at the proxy. The server is published on `127.0.0.1` only.
2. **Organization ↔ organization.** This is the hard tenant boundary. Every
   org-scoped query is keyed by the caller's org id, which comes from the token, never
   from the request.
3. **Platform admin ↔ organizations.** The platform admin sits *outside* every org,
   and every org-scoped route returns 404 for it.
4. **Server ↔ database.** The DB holds only ciphertext and hashes, and the server
   holds the master key. Requests use the restricted `coffer_app` role, which can't
   modify or truncate audit rows or touch `master_key_check`/`schema_migrations`. The
   owner role is used only during boot.
5. **Host ↔ containers.** Containers run unprivileged. The host, and anyone who can
   read `.env` or inspect the server container, is trusted.
6. **CLI workstation.** The config file holds one PAT. The CLI treats all text from
   the server as untrusted when printing it.

## 4. Master key handling

- **Generation:** `./scripts/init-env.sh` (also run by `up.sh` when `.env` is missing)
  takes 32 bytes from `openssl rand`, or from `/dev/urandom` if openssl is missing. It
  writes them base64-encoded into `.env` only, through a 0600 temp file and a rename.
  It never overwrites an existing `.env` without `--force`.
- **Storage:** the key exists only in `.env`, which is git-ignored, excluded from the
  Docker build context, and mode 0600. It reaches only the `server` container
  (`env_file`); the `db` container gets only the `POSTGRES_*` variables. It is never
  logged, never stored in the DB, and never included in backups.
- **Validation at startup:** the server refuses to start in any of these cases:
  - the key is missing or doesn't decode to exactly 32 bytes;
  - the key equals the `.env.example` placeholder;
  - the key doesn't open the DB canary (`master key does not match database`).

  A wrong key therefore never creates a second keyspace silently. The check runs before
  the boot changes anything (role password, grants), so a refused boot can't disturb a
  server that is already running.
- **Rotation:**
  1. Set `COFFER_MASTER_KEY_PREVIOUS=<old>` and `COFFER_MASTER_KEY=<new>`.
  2. Run `./scripts/up.sh`, which always recreates the server container so the new
     `.env` is applied.
  3. Before ready, every DEK is re-wrapped in one transaction and the canary is
     re-sealed.
  4. Remove `PREVIOUS` and run `up.sh` again.

  Rotation is idempotent. It re-wraps only DEKs; values are not re-encrypted. That is
  enough after a suspected master-key exposure *only if* the attacker did not also get
  the DB contents. With both, they can unwrap the DEKs, so rotate the secrets
  themselves. Backups taken before rotation still need the old key.
- **Loss:** without the master key, no DEK can be unwrapped, and every secret value,
  in the live DB and in every backup, is lost for good. There is no recovery path or
  escrow. Back the key up separately from database dumps (a password manager or a
  vault). Users, tokens, grants and the audit log stay readable, but values do not.

## 5. Threats and controls

| Threat | Control |
|---|---|
| Cross-tenant access (an org A user reads org B) | Every lookup is scoped by the caller's org id. Invisible resources get a **404** byte-for-byte identical to "does not exist". The denial is audited in the caller's own chain without revealing whether the resource exists. Malformed slugs and ids are 404 before any SQL runs. |
| Member exceeds their grant | Fixed resolution order: visibility (404), then permission (403), then validation (400). Viewer/reader/writer checks per operation; no grant is 404. Grants are re-read on every request. |
| Role escalation or owner takeover by an admin | Only owners create, promote, demote or remove owners. Nobody changes their own role or grants. The last owner can't be demoted or removed (409, counted under row locks). Unknown JSON fields are rejected (400). Promotion drops grants, so a demotion can't bring back old access. |
| Approving your own change; approval after losing access | Two-person rule on `proposed_by` and `proposed_by_user` (this includes the person behind a service token). Approval re-checks, under locks, that the proposer can still write; otherwise the change goes `stale` with a 409. A changed head also makes it stale. |
| Compromised service token | Scoped to one project and env, `read` or `read-write`, always expires (90 d at most). 403 on every route that isn't a secret operation (PAT creation, logout, members, tokens, audit, approvals). Revocable at once. |
| Platform admin reading tenant data | Every org-scoped route returns 404 for the platform admin, which has no org id and no grants. |
| Stale access after revocation | Token, user, org, project and env are re-checked in one query on every request, with no cache. Disabled orgs get 401. |
| Credential stuffing, brute force | argon2id (64 MiB). Lockout after 5 failures in 15 minutes per normalized email: 429, even with the correct password, serialised per email. Unknown and wrong-password responses are identical, with similar timing (dummy hash, rehash on parameter change). Failed attempts are counted and audited even if the client disconnects. |
| Account enumeration | Identical 401 for unknown email, wrong password and disabled org. Unknown emails appear in the audit log only as `email:<sha256 prefix>`. |
| Token theft from DB or backup | Tokens are stored as SHA-256 of 256-bit random values and shown once. |
| DB or backup theft | Values are AES-256-GCM encrypted under per-project DEKs wrapped by the master key. Passwords are argon2id. Backups contain only ciphertext and hashes. |
| Ciphertext swapped inside the DB | The AAD binds org, project, env, key and version (pending values: the change id). A swapped ciphertext fails to decrypt and gives a 500 with an audited `failed`/`integrity` event, never a value. |
| Audit tampering | Per-chain SHA-256 hash chain with `audit verify` (a truncated tail is caught via the chain head). The app DB role has no UPDATE, DELETE or TRUNCATE on `audit_events`. Triggers block UPDATE, DELETE and TRUNCATE. |
| Value exit without an audit record | Get, version get and export commit their `secret.read` events before responding. If the audit insert fails, the response is 500 and contains no value. |
| Secrets in logs | The request log has only the route pattern, status, timing and ids (no query strings, headers or bodies). The audit log never stores values, passwords or tokens. DB error text never reaches clients. |
| Secrets in URLs or browser caches | Values travel only in JSON bodies. `Cache-Control: no-store`, no CORS headers, CSP `default-src 'none'`, `nosniff`. |
| Resource exhaustion | 1 MiB body limit (413). Header, read, write and idle timeouts. 64 KiB header limit. Argon2 concurrency semaphore (4). Bounded list sizes (1000). `login_failures` pruning. |
| Leaks through error messages | Generic JSON errors. Internal details only in server logs, keyed by request id. Panics recovered. |
| Log or terminal injection | `X-Request-Id` is generated by the server. Audit strings are sanitised (NUL and invalid UTF-8). The CLI escapes control and bidi characters in server text. |
| Container breakout impact | Distroless static image, non-root UID 65532, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`. The DB isn't published to the host and never sees the master key. |
| CLI token theft on a workstation | Config dir 0700 and file 0600, written atomically, with a warning if the modes are looser. Passwords come only from stdin, with echo off on a TTY. In `COFFER_TOKEN` mode the CLI never touches disk. `run` writes nothing to disk. Redirects are never followed. The CLI warns about plain HTTP to hosts that aren't loopback. |
| Supply chain | Base images pinned by digest. `go.sum` committed, `go mod verify`. `govulncheck`, golangci-lint (gosec) and shellcheck in CI. Minimal dependencies (pgx, x/crypto). |

## 6. Out of scope (SPEC §8)

These are out of scope:
- a web console or browser UI;
- SSO, OIDC and SAML;
- MFA;
- email delivery;
- **TLS termination** (a reverse proxy is required);
- multi-node setups and high availability;
- Kubernetes manifests;
- dynamic or leased secrets;
- users in more than one organization;
- billing.

Also out of scope: an attacker with root on the host or control of the container
runtime (they can read the master key from the environment), and a malicious database
superuser who also holds the master key.

## 7. Known limitations

- **No TLS.** The server speaks plain HTTP on loopback. Without a TLS reverse proxy,
  tokens and values cross the network in clear text.
- **The master key is an environment variable.** Host root, and anyone who can run
  `podman inspect` or `docker inspect` on the server container or read `.env`, can
  read it. There is no KMS or HSM integration.
- **Global email uniqueness.** Emails are unique across all organizations. Adding a
  member, or creating an org owner, with an email already used elsewhere returns 409.
  This tells an org admin that the email exists in *some* organization (not which).
- **The audit chain detects tampering by a DB superuser; it doesn't prevent it.**
  Someone with owner or superuser DB access can drop the triggers and rewrite rows. They
  can even recompute a consistent chain, because it isn't anchored outside the
  database. The `coffer_app` role can UPDATE the `audit_chains` head row. That lets it
  make `verify` fail (detectable tampering), but it can't rewrite events. For stronger
  guarantees, export `audit list` output and chain heads to an external system
  regularly.
- **Lockout as denial of service.** Anyone who knows an email can lock that account
  out for 15 minutes with 5 failed logins. The lockout is per account by design, not
  per source IP.
- **Login failures are serialised on the platform chain.** Every failed login appends
  to the platform audit chain, so a login flood across all orgs is serialised there.
  The 4-slot hashing limit bounds this.
- **Timing after an argon2 parameter change.** After `COFFER_ARGON2_MEMORY_KIB` changes,
  each account still verifies at the old cost until its next successful login. Until
  then, its timing differs from that of unknown emails.
- **PAT lifetime** defaults to 30 days (`COFFER_PAT_TTL=720h`). A stolen CLI config
  works until logout, revocation, expiry or a password change. Lower the TTL for
  stricter environments.
- **Rotation re-wraps DEKs but doesn't re-encrypt values** (see §4).
- **Initial passwords** set by the platform admin or by org admins are known to them.
  The forced password change is off by default (`COFFER_REQUIRE_PASSWORD_CHANGE=false`).
- **Pending changes aren't cancelled when the proposer loses access.** They stay
  `pending` until someone decides them, and approving one then fails with 409 (it
  becomes `stale`).
- **Audit failure on denials.** If the audit append for a 403/404 fails, for example
  because the DB is down or the client has disconnected, the denial is still returned
  and only logged, so that event is missing from the chain. Value reads fail closed
  instead.
- **Responses produced by Go's HTTP library.** `net/http` itself answers a malformed
  request line or bad `%`-escape (400), headers over 64 KiB (431) and a malformed
  `Content-Length` (400) before Coffer's handler runs. These responses are
  `text/plain`, with no JSON body, no `X-Request-Id` and no log line. The reverse proxy
  should normalise or reject such requests.
- **Source IPs in the audit log** are the address of the TCP peer the server sees.
  Anything that rewrites the source address hides the real client: a reverse proxy,
  any NAT, and in particular rootless podman port publishing (the default with `podman
  compose` as a normal user). There, every request appears to come from the container
  network gateway (for example `10.89.0.x`), even a local `curl`. Behind a reverse
  proxy, set `COFFER_TRUST_PROXY=true` so the first `X-Forwarded-For` entry is
  recorded, but only when that proxy overwrites `X-Forwarded-For` (rather than
  appending to it) and is the only path to the server. Otherwise clients can forge
  their audit IP. Without a proxy, or with rootless publishing, treat `source_ip` as
  informational.
- **Plaintext in memory.** DEKs and values sit in server memory while in use, and Go
  doesn't guarantee zeroing. `coffer run` passes values to the child through its
  environment, where other processes of the same user may be able to read them (for
  example `/proc/<pid>/environ`).
- **`coffer run` can't pass values that contain NUL.** It refuses to start the child
  (DECISIONS 62).
- **Single node.** There is no HA: the DB and its volume are a single point of
  failure. Backups are run by the operator (`backup.sh`).
- **Service tokens outlive their creator** by design (they belong to the org) until
  they expire or are revoked.
- **The fallback to the owner role.** If the restricted role can't be set up, the
  server logs a warning and serves requests as the DB owner. The audit-row protection
  then rests only on the triggers.
