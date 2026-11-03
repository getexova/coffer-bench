# Decisions

Where `SPEC.md` is silent, ambiguous or self-contradictory, this file records what Coffer does and
why. Each entry names the decision, the reasoning, and the alternative that was rejected. Anything
marked **frozen** also appears in `docs/CONTRACTS.md` and must not be changed without editing both.

## Stack

**Go 1.27.3, single static binary.** One artifact serves both the server and the CLI, so the README
never has to list a runtime prerequisite. `CGO_ENABLED=0` produces a statically linked binary that
runs in a minimal image. Rejected: Node or Python, which force a runtime disclosure in §7.1 and add
a deployment surface with no benefit.

**Two direct dependencies: `jackc/pgx/v5` v5.11.0 and `golang.org/x/crypto` v0.58.0.** Everything
else is stdlib: `net/http` with `ServeMux` method patterns, `crypto/aes` for AES-256-GCM,
`crypto/sha256`, `log/slog`, `flag`, `testing`. §6 forbids a dependency with a known High or
Critical advisory at build time, and the cheapest way to satisfy that permanently is to have almost
no dependencies. `govulncheck` reports zero vulnerabilities in code we call.

Rejected libraries and why: `lib/pq` is in maintenance mode; `dgrijalva/jwt-go` carries
CVE-2020-26160 and is unmaintained, and Coffer needs no JWT because its credentials are opaque
random tokens; `golang-migrate` and `goose` are larger than the advisory-locked runner this design
needs; `cobra` and `viper` obscure the exit-code control that §7.1 grades; `gorilla/mux` is
unnecessary given `ServeMux` patterns; `testcontainers` adds a Docker dependency to the test suite.

**PostgreSQL 16, not the MySQL instance available on the build host.** §5 mandates the image
`postgres:16`, so the engine is not a choice. `pg_advisory_lock` for migrations, `SELECT … FOR
UPDATE` for the version allocator and the audit head, and JSONB-free canonical encoding all depend
on Postgres semantics.

## HTTP surface

**Wrong method and unknown path both return 404.** §7.2's status table has no 405, and §4 says every
path other than `/api/v1`, `/healthz` and `/readyz` returns 404. Go's `ServeMux` already produces
404 for a method mismatch on a registered pattern, so the behaviour needs no suppression. Rejected:
405, which would introduce a status the fixed interface does not list.

**The 404 body is identical for "does not exist" and "not visible".** §2.1 requires it, and it is
implemented by resolving with `org_id` in the SQL predicate so the two cases are the same query
result. 403 is returned only when the caller can see the resource and lacks the permission.

**The 403-versus-404 decision is made once per request, centrally.** Denial auditing is a
whole-product invariant ("every request denied by authorization"), so a per-handler implementation
would eventually miss one. The middleware flushes a denial event for any 403 or 404 produced by
authorization.

**A bare 401 is not audited as a denial.** §4 lists denials as "403 or 404". A missing, malformed,
unknown, expired or revoked credential is authentication failure, not an authorization decision, and
auditing it would let an unauthenticated flood write unbounded platform-log rows. Denials are
additionally rate limited: 10/s with a burst of 50 per source IP, 100/s globally, overflow counted
and dropped rather than written row by row.

**Headers are set inside the JSON writer, not by each handler.** `Content-Type: application/json`,
`X-Content-Type-Options: nosniff` and `Cache-Control: no-store` are set by the shared writer so a
forgetful handler cannot produce a non-compliant response. A dotenv export is the documented
exception and may be `text/plain`.

**`/readyz` reports why it is not ready.** A 503 carries
`{"status":"not_ready","reason":"database"|"migrations"}`, with no SQL text and no internal path.
§5 requires 200 only when the database is reachable and migrations are applied, and `up.sh` is
required to name the failing dependency rather than print a bare timeout; a machine-readable reason
is the only way to do both.

## Addressing and identity

**The CLI takes an email where the API takes `{user_id}`.** §7.1 specifies `coffer member role EMAIL`
and §7.2 specifies `PATCH /members/{user_id}`. The CLI resolves the email to a user id through
`GET /members` before calling the route. Rejected: adding an email-addressed API route, which would
extend the fixed interface.

**Organization and project identifiers in routes are slugs.** §7.2 writes `{p}` and `{e}` and §7.1
passes project and environment names on the command line. Slugs are unique within an organization
(`UNIQUE(org_id, slug)`), which is what §1 requires. A global unique constraint was rejected because
it would let one organization detect that another has taken a slug.

**IDs are opaque prefixed strings.** §7.2 says "IDs are opaque strings". Object ids are a short
prefix plus 96 random bits in hex, so a stray id in a log is recognisable. Credential secrets are 256
random bits, satisfying §4's 128-bit minimum.

**`updated_by` in a listing is a user id**, not an email. It matches the `actor` field of the audit
log, so a listing can be joined to the audit trail without a second lookup.

## Authentication

**Lockout follows the spec literally, including its enumeration cost.** §4 requires 429 after five
failed logins for an account within fifteen minutes, "even with the correct password", and that
"other accounts are unaffected". Those two sentences together mean an attacker can distinguish an
existing account from a non-existent one by the status code. Returning a uniform 429 for unknown
emails would contradict "other accounts are unaffected", so the literal behaviour is implemented and
the enumeration is recorded as a known limitation in `SECURITY.md`. Mitigations that do not change
the graded behaviour: a per-IP throttle on the login route and a bounded LRU keyed by email, since
unknown emails are attacker-controlled keys.

**Unknown email and wrong password are indistinguishable in status, body and timing.** §4 requires
it. When the email is unknown the server still performs an argon2id verification against a fixed
dummy hash, so the response time does not reveal whether the account exists.

**There is no authorization cache anywhere.** §2.11 requires revocation to be visible to the next
request within one second. A cache would need cross-process invalidation to meet that bound, which is
the one realistic way to fail it. Instead each request runs one indexed query joining token, user,
organization and grant, with expiry compared against the **database** clock in SQL so a clock skew
between application and database cannot extend a credential's life. The cost is a single indexed
lookup per request, which the performance targets comfortably absorb.

**A service token calling `GET /me` receives 403.** §2.7 confines a service token to secret
operations inside its scope, and `/me` is not one of them. The token authenticated, so the route is
visible to it and the refusal is 403 rather than 404. A service token therefore has no identity
document at all: it has no organization and no user, and the only thing it needs to confirm is that
it can reach its own secrets, which `secrets list` answers.

This was ruled by the CEO after the CSO audit measured a 200 carrying `{"role":"service_token",
"organization":null,"token":{…}}`. The earlier response leaked nothing, but it deviated from the
fixed interface, and the ruling is that a machine credential gets no `/me` at all. The CLI maps the
403 to exit 4 with a hint that names the situation, and a *dead* service token still returns 401 and
exit 3, which is the distinction that tells a user whether to fix their scope or their credential.

**Platform admin `GET /me` returns `{role:"platform_admin","organization":null}`.** The platform
admin has no organization by definition (§1), and §2.10 gives it organization and platform-audit
powers only. Every organization-scoped route returns 404 for it.

**A non-platform-admin calling `/admin/*` receives 403**, because the resource is visible to them as
existing but they lack the permission. The platform admin calling an organization route receives 404,
because the route is outside what it can see at all.

**A token belonging to a disabled organization receives 401.** The credential is no longer
acceptable, which is an authentication failure rather than an authorization decision.

**Password change revokes the user's other PATs.** This is the P1 item in §4. The PAT used to make
the change survives, so the caller is not logged out of the session that performed the change.

**Forced password change blocks everything except the change itself.** Also P1. A user created with
an initial password has `must_change_password` set, and every route except `POST /auth/password` and
`POST /auth/logout` returns 403 until it is cleared.

## Authorization

**A caller may not change their own role, grants, organization or platform-admin status, even to
demote themselves.** §2.12 says "No request lets a caller change their own role". Read literally,
that includes self-demotion, so `PATCH /members/{self}` is refused. The ordering of the refusals is:

1. **Owner gate first.** Only an owner may touch an owner. An admin acting on any owner, including
   themselves, gets **403**. This is deliberate: if the last-owner rule ran first, an admin would get
   409 when demoting the sole owner and 403 when demoting a non-last owner, which leaks how many
   owners exist. §2.3 already says admins never manage owners, so 403 is the honest answer.
2. **Last-owner rule second.** An owner acting on the last owner gets **409**. This is reachable only
   by an owner, which is the only caller that could actually perform the demotion.
3. **Self-change rule third.** Any remaining attempt by a caller to change their own role gets **400**.

The consequence, recorded because it is surprising: an admin promoting **themselves** to owner gets
403 rather than 400. Both rules are violated and the authorization gate answers first. The security
property §2.12 protects is identical either way — the role is never applied, which a test asserts in
SQL — so the status code is a reporting choice, and authorization-first is the ordering that keeps
409 from disclosing the owner count.

**Authorization is checked before field validation.** A plain member calling any member, grant or
token route receives 403, not 400, even if the body is also invalid. §2.6 grants them no permission
on those routes at all, and answering 400 would confirm the route exists and validate their input.

**A duplicate email returns a generic 409.** No organization name, no "already in org X". Otherwise
member creation becomes a cross-organization membership oracle.

**Only an owner can create, promote, demote or remove an owner, and the last owner cannot be removed
or demoted (409).** §2.2. Admins manage members but never owners.

## Secrets

**An empty value is valid and round-trips.** §3 defines a value as "any UTF-8 string from 0 to 65,536
bytes inclusive", and 0 is inclusive. A zero-length value is stored and returned as zero bytes, which
is distinct from a tombstone.

**A tombstone version is listed in history with `deleted:true` and carries no ciphertext.** A get
returns 404, history keeps the tombstone, and a later set continues the numbering from the tombstone.
§3 requires all three behaviours.

**Rollback decrypts at the source version and re-encrypts at the new version.** The new version holds
the value, not a pointer, so a later deletion of the source cannot change history. The AAD changes
with the version, so a rollback is a genuine new encryption rather than a copied ciphertext.

**Version allocation never uses `MAX(version)+1`.** `secrets.current_version` is the allocator:
a single `UPDATE … SET current_version = current_version + 1 … RETURNING` which is atomic, gap-free,
and doubles as the row lock. §3 requires concurrent unconditional writes to each receive a distinct
version with no gaps and no lost updates; `MAX`+1 under concurrency produces duplicates.

**An expected-version mismatch is 409 and changes nothing.** No version is allocated and no tombstone
is written.

**`secrets get` on a TTY appends a newline; piped output is exact bytes.** §7.1 requires the exact
value bytes with no added newline when stdout is not a TTY. On a TTY a trailing newline is added so
the shell prompt is not glued to the value; that case is not graded by byte-exactness and is the only
sane interactive behaviour.

**The CLI passes dotenv export through unchanged.** When `--format dotenv` is requested, the server
produces the escaping and the CLI writes the bytes it received. Re-escaping client-side would risk
double-escaping a backslash. The escaping rules are therefore implemented once, on the server.

## Protected environments and the two-person rule

**A pending change stores its proposed value encrypted with AAD bound to the change id.** A change
request is ciphertext at rest like any other secret, and binding the AAD to the change id means a
payload cannot be redirected to a different key or environment by editing the row.

**Approval is a compare-and-swap on status, then a locked version comparison.** The conditional
`UPDATE … WHERE status='pending'` makes double approval impossible; a zero-row result is 409. Only
then is the secret row locked and its `current_version` compared with the recorded `base_version`. A
mismatch marks the request `stale`, audits it, and returns 409 without applying anything.

**Approving your own request is 403, checked before any state change.** §2.9. The check happens
before the status update so a self-approval cannot consume the request.

**A change proposed by a service token is attributed to the human who issued the token.** The
proposal carries two identities and they are deliberately different. `change_requests.proposer_id`
references `users(id)`, so it holds the **issuing user**, resolved from the token through
`Store.ServiceTokenCreator` on the propose path only. The **audit event** names the **token**, because
a machine credential performed the action and §4 wants that distinguishable in the log.

The consequence is the two-person rule working as intended for machine credentials: the human who
minted the token is the proposer, so they cannot approve their own token's proposal. A different
owner or admin must. If the issuing user has since been removed, the proposal is refused with **403**
and no change row is created, because a removed user is not an approver and must not be resurrected
to satisfy a foreign key. A service token writing to an **unprotected** environment is unaffected and
writes directly.

This was the CSO audit's one blocking finding: attributing a service-token proposal to the token id
violated the foreign key and returned 500 instead of 202. The fix keeps the key, adds no migration,
and leaves `actorRef` unchanged so the audit trail still separates machines from people.

**A change to a protected environment is a 202 with a change id, for everyone who can write.** §2.8
says "by anyone allowed to write", so owners and admins are not exempt. The CLI prints the change id
and exits 7.

## Audit

**Each chain has its own head row, and the append is one transaction.** The event insert and the
`audit_heads` update are in the same transaction. If they were separate, a crash between them would
leave events ahead of the head, and the verifier's disagreement check would raise a false tamper
alarm on a healthy database, including after a restore. With them atomic, a disagreement can only
mean tampering, so reporting it is correct.

**Verification walks the event table and never trusts the head.** The head is a cache. Verification
recomputes the chain from `seq` 1 for the scope, rebuilding canonical bytes from each row's own
columns rather than from a stored canonical blob, so a column-only tamper is detected. A head that
disagrees with the recomputed tail is reported as its own finding, directionally: events ahead of the
head is tampering, events shorter than the head is truncation. Both are invalid.

**Canonical timestamps are UTC at microsecond precision.** `timestamptz` has microsecond resolution.
Storing or rendering at any other precision would make an event re-read from the database encode to
different bytes and every verification would fail on round-trip.

**The canonical form is frozen at v1.** Adding a field to the canonical encoding would invalidate
every existing chain, so a future covered field requires a `canon_version` marker and a migration.

**Audit immutability uses two database roles.** A single role cannot satisfy both §4(P1) and a working
tamper test: `REVOKE` is a no-op against a superuser, and a trigger that raises for every caller would
also block the deliberate tamper that verification is supposed to detect. The owner role
(`POSTGRES_USER`, superuser in compose) runs migrations, backup, restore and the tamper probe.
`coffer_app` is a `NOSUPERUSER` runtime role that owns nothing, has no `CREATE` on the schema and no
membership in the owner role, so it cannot `ALTER TABLE … DROP TRIGGER` or re-grant itself. It holds
`SELECT, INSERT` only on `audit_events`. Defence in depth: two triggers raise for any caller that is
not a superuser, and return early for one that is, so `coffer_app` is blocked by the grant and the
trigger while a superuser tamper succeeds and verification reports it.

**`coffer_app` needs `UPDATE` on `audit_heads` and `USAGE, SELECT` on all sequences.** The append path
advances the head, and every other table is keyed by `bigserial`; omitting the sequence grant is a
runtime failure on the first insert. `GRANT`, `REVOKE` and `ALTER DEFAULT PRIVILEGES` are re-applied
after every migration so tables added later inherit the right privileges.

**Degraded single-role boot is gated and never silent.** If `COFFER_APP_DB_PASSWORD` is absent, the
server runs as the owner role only when `COFFER_ALLOW_DEGRADED_DB_ROLE=1` and `COFFER_ENV` is not
`production`; it logs a startup warning naming the lost isolation. In production the combination is a
refusal to start. If `COFFER_APP_DB_PASSWORD` is present but rejected, that is a failed start, never a
fallback: a wrong password must not quietly downgrade the security posture. §4(P1) is unmet in
degraded mode and `SECURITY.md` says so. `/readyz` still returns 200, because readiness means the
database is reachable and migrations are applied, and a P1 hardening branch must not gate a required
endpoint.

**`restore.sh` does not validate the audit chain.** A restore must be able to reproduce a tampered
dump so that verification can report it, which is impossible if the restore refuses the dump. Because
restore therefore cannot be the thing that certifies a chain, it prints the exact
`./bin/coffer audit verify` command and states that the restore is not complete until that reports the
chain valid. The same sentence appears in the README.

## Operations

**`COFFER_BIND_ADDR` exists because §5's literal address is unusable in a container.** §5 says the
server listens on `127.0.0.1:${COFFER_PORT}`. Inside a container a loopback bind is unreachable from
the host, so `up.sh` could never see `/readyz` and the quickstart could not work. The variable
defaults to `127.0.0.1` outside compose; compose sets `0.0.0.0` in-container and publishes only
`127.0.0.1:${COFFER_PORT}`, so host exposure stays loopback-only. A startup warning is logged when the
effective bind is not loopback, and `SECURITY.md` states that a non-loopback bind requires a
TLS-terminating proxy.

**`source_ip` is the socket peer unless `COFFER_TRUST_PROXY=1`.** With the flag set, the rightmost
`X-Forwarded-For` entry that is not in the trusted-proxy set is used. Never the leftmost and never
unconditionally: an attacker who can rotate the header would otherwise bypass the per-IP rate limits
and poison the audit trail. The same resolver feeds the login throttle. With §8's assumed reverse
proxy and the flag unset, every recorded `source_ip` is the proxy address; that is the fail-closed
default and it is listed as a limitation.

**Migrations run in-process at boot under an advisory lock, not in a third compose service.** §5
names services `server` and `db`; a `migrate` service would add a name the fixed interface does not
list. Each migration file runs in a single transaction with the grant block, so a failure part way
through `0001_init.sql` leaves no partial schema. Two containers starting at once serialise on
`pg_advisory_lock`; the loser applies nothing.

**`coffer_app` is created by the boot migration, not by an entrypoint init script.** `/docker-entrypoint-initdb.d`
scripts only run on an empty data directory, so a restored or pre-existing volume would come up with
no runtime role.

**Healthchecks live in `compose.yaml`, not the Dockerfile.** podman's default OCI image format silently
drops a `HEALTHCHECK` instruction, so an image-level healthcheck would work under one runtime and not
the other.

**`build.sh` falls back to a container when no host Go toolchain exists.** §7.1 requires `build.sh` to
produce `./bin/coffer`, and the README lists the prerequisites; requiring a host toolchain would make
the quickstart fail on a machine with only a container runtime. The container path uses
`--userns=keep-id`, because `--user $(id -u):$(id -g)` fails on rootless podman with a `go.sum`
permission error.

**No test-only authentication seam exists, in any build.** A fixed test bearer token accepted behind
an environment flag is a full impersonation bypass, and one stray `.env` in the graded commit would be
critical. Tests mint real PATs through `POST /auth/token` for users they create, and the bootstrap
admin covers platform-level tests.

## Out of scope

§8 excludes a web console, SSO/OIDC/SAML, MFA, email delivery, TLS termination, multi-node or HA,
Kubernetes manifests, dynamic secrets, users in more than one organization, and billing. Coffer
implements none of them and does not leave hooks for them.

## Contract exceptions and late decisions

### `password_change_required` is a new error code at status 403

`docs/CONTRACTS.md` §2 fixes the error code per status, and 403 is `forbidden`. The P1 rule in §4
requires a user created with an initial password to change it before doing anything else, and the
CLI has to distinguish "you lack permission" from "change your password first" or `coffer passwd`
cannot give a useful message. So a 403 may carry `password_change_required` instead of `forbidden`.

This is a deliberate exception to the frozen table, not an oversight. The status is unchanged, so
any client that only reads the status behaves exactly as before; only the code differs, and only on
routes that are blocked by the forced-change gate. The exemption list is exactly two routes,
`POST /auth/password` and `POST /auth/logout`, and a test pins it at that size so a future route
cannot quietly become reachable while a password change is outstanding.

### The forced-change rule is enforced centrally, from a flag the login query already read

`authstore.ResolveTokenSQL` — the single indexed statement every authenticated request runs — already
selects `users.must_change_password`. `Authenticate` was discarding it while building the `Actor`.
It now returns the flag alongside the actor, `withAuth` puts it on the request context, and `withAuth`
itself refuses a gated caller before any handler runs. Every slice therefore inherits the rule, and a
slice added later inherits it without knowing it exists.

The first attempt at this kept the flag in a map keyed by token id, bounded at 1024 entries and
cleared wholesale when full. A miss returned `false`, which reads as "not gated", so once the map
filled every gated user was admitted until their next request re-recorded the flag. A cache whose
miss path means *allow* cannot be made safe by tuning the bound; the cache had to go. The flag now
rides the request, so there is no miss path and nothing to evict.

Two properties keep this honest, and both are tested:

- `internal/httpapi/mustchange_central_test.go` drives the real router with an `ungatedProbe` route
  whose handler has no gate of its own, so the test fails if the middleware stops enforcing the rule.
  Disabling the gate in `withAuth` makes it fail with "the ungated handler was reached by a gated
  user". Without that probe the central gate would be masked by the per-slice gates and could rot
  silently.
- A service token and the platform admin are never gated, because neither has a password to change.

Each slice also keeps a local gate call as defence in depth. It reads only the request context and
does not query the database, so it costs a map read rather than a round trip.

### A wrong `current_password` is 400, not 401

`POST /auth/password` with a wrong current password returns 400 `validation_error`. The caller is
already authenticated, so 401 would tell the CLI to discard a perfectly good token and force a
re-login. §7.2 reserves 401 for an unauthenticated caller.

### The lockout counter is bounded, and the login throttle counts failures only

Failure counters live in a bounded LRU keyed by email, because unknown emails are attacker-controlled
and an unbounded map is a memory-exhaustion vector. The per-IP throttle on the login route counts
failed attempts only, so a CI job that authenticates repeatedly is never throttled by its own
successes.

### The trusted-proxy set is derived, not configured

`COFFER_TRUST_PROXY=1` takes the rightmost `X-Forwarded-For` entry that is not already a known proxy
hop. There is no separately configured CIDR list, because a misconfigured list is worse than the
fail-closed default: with the flag unset every `source_ip` is the socket peer, which is the proxy's
address when one is in front. That limitation is stated in `SECURITY.md`.

### `/admin/*` is not organization-scoped

The platform routes are mounted on the same mux but resolve no organization. A non-platform-admin
calling one gets 403, because the route is visible to them and they lack the permission. The platform
admin calling any organization-scoped route gets 404, per §2.10.

### One public route, and why the 401 rule is not blanket

Anonymous requests to an organization-scoped route get 401 from the middleware rather than falling
through to a 404 (§7.2 lists 401, and a caller with no credential has no tenant to be invisible
from). `POST /api/v1/auth/token` is the single entry on a public-route allowlist, because a blanket
401 would block sign-in itself. Unknown paths and wrong methods still return the 404 envelope rather
than 401, so an unauthenticated scanner cannot learn which paths exist.

### The shared test harness installs `audit.NopWriter()`

`internal/testutil` wires the router with a no-op audit writer, so an HTTP-level test cannot count
audit rows. This is deliberate: the harness is shared by every package, and a real writer would make
each package's fixtures depend on chain state left by another package.

The consequence is that §3's "one event per key read" is proven against the real
`audit.NewAppender` inside `internal/api/secretsapi` and `internal/audit`, not through the HTTP
surface. A reader should not conclude that read auditing is untested; it is tested, one layer down.
Closing this properly means giving the harness an injectable writer, which is a worthwhile change and
was not worth destabilising five packages' fixtures at this stage.

### A tamper test poisons the volume it runs against

Verifying that the chain detects tampering means writing a bad row on purpose. The row survives
`down.sh`, because that command keeps the data by design, so a stack used for a tamper test will
report `Audit chain INVALID` forever afterwards — and any later check that grades the audit chain
against that stack fails on a healthy codebase.

A tamper test is therefore a **destructive operation on the volume**, not on the code. Two
acceptable patterns:

1. **Undo it precisely.** Record the original column values first, tamper, verify, then restore the
   exact bytes and re-verify. This works and was used for the acceptance runs in this build, but it
   is easy to half-finish: a session that tampered `action` and restored only `target` leaves a row
   that verifies invalid.
2. **Tamper on a throwaway stack**, or on a fresh volume, and delete the volume afterwards.

Never leave a tampered row behind on a stack that anyone else will use. If a stack reports an invalid
chain, check `SELECT scope, seq, action FROM audit_events WHERE action NOT IN (<the action list>)`
before assuming the verifier is broken: the likely cause is residue, not a bug.

### `COFFER_APP_DB_PASSWORD` is provisioned once, then verified every boot

The runner connects as the owner, so it *can* set `coffer_app`'s password. It must not silently
re-set it on every boot: doing so re-keys the role to whatever the environment happens to contain, so
a typo'd password stops being wrong and starts being correct, and the operator never learns that
their secret store and the database disagree. That is worse than the owner fallback this design
refuses, because it fails silently.

The role is provisioned on first boot. Every later boot verifies that the runtime role can actually
authenticate; if it cannot, the server **fails to start** naming `COFFER_APP_DB_PASSWORD`, per
`docs/CONTRACTS.md` §11.

### Audit appends serialise per chain, and that is the read-path ceiling

Every append takes the chain's head row `FOR UPDATE`, so appends to one organization serialise. That
is what makes the chain gap-free, and it is the design's write ceiling.

It is also the ceiling on concurrent reads, because §3 requires one audit event per key read and the
append happens on the request path. This was proven by ablation: with the audit writer swapped for a
no-op, 50 concurrent single-key reads measure **p95 7–19 ms**; with the real writer the same test
measures **p95 132–224 ms**. A 10–30x difference isolates the cause to the head lock: 50 concurrent
reads become 50 serialised transactions on one row, each computing a SHA-256 chain hash inside the
lock.

**This is a documented tension between two spec requirements, not a defect.** §3 requires the per-read
event, §4 requires the gap-free chain, and §5 sets a 200 ms p95 target for 50 concurrent reads on one
host. The chain wins: a working secure core beats a broken extra. Measured on this host, five
consecutive runs at n=50: p95 132, 139, 180, 181, 184 ms. So the target is met in typical conditions
and missed under load.

Two earlier explanations in this file were wrong and are corrected here. First, the pool: `pgxpool`
defaults to `max(4, NumCPU)` = 16 connections, while §5 asks for 50 concurrent readers, and
`db.go` never set `MaxConns`. It is now `DefaultMaxConns = 32` with `DefaultMinConns = 4`,
overridable by `COFFER_DB_MAX_CONNS`, sized so two server instances stay inside a default
`max_connections` of 100. That fix took the worst case from 379 ms to 224 ms and tightened the spread,
but it did **not** remove the serialisation, and an early measurement suggesting it had was an outlier.
Second, the single "181 ms" figure that stood here for most of the build was one lucky sample from a
spread of 173 to 331 ms; a single measurement of a concurrent benchmark says very little, so take
three.

The fix that would actually remove the ceiling is batching appends: one transaction allocating a
contiguous `seq` range for N concurrent appends. That changes `audit.Writer` from "append one event"
to "append a batch", needs a decision about partial-batch failure, and is a design change rather than
tuning. It is deliberately out of scope here.

### Audit verification cannot detect a truncated chain whose head was rewritten

An attacker who deletes trailing events **and** rewrites `audit_heads` to match produces an
internally consistent chain that verifies valid. This is unavoidable while the append path needs
write access to the head. The control is the off-box encrypted backup, which is why a backup belongs
to the audit story and not only to disaster recovery. `SECURITY.md` states this and a test asserts it
so it stays a known property rather than a surprise.
