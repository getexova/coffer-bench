# Security

Coffer stores secrets for an engineering organization and records who touched them. This document
states what it protects, from whom, where the trust boundaries are, and what it does not protect
against.

## Assets

1. **Secret values.** The data the system exists to protect. Stored encrypted, returned only through
   three audited exits.
2. **Credentials.** User passwords (argon2id hashes), personal access tokens and service tokens
   (SHA-256 hashes). A stolen live credential is as good as the access it grants.
3. **The master key.** `COFFER_MASTER_KEY`. Its compromise defeats encryption at rest for every
   project.
4. **The audit log.** The record of who did what. Its value depends on being complete and unmodified.
5. **Organizational metadata.** Which organizations, projects, environments and members exist, and
   the shape of the grants. Less sensitive than values, still not public.

## Actors

| Actor | Trust | Capability |
|---|---|---|
| Platform admin | Trusted for platform operations, **not** for organization data | Creates and disables organizations, creates first owners, reads the platform audit log. Cannot read any organization's secrets, members, tokens or audit log. |
| Organization owner | Trusted inside one organization | Everything inside that organization, including owner management. |
| Organization admin | Trusted inside one organization, below owners | Members, grants, projects, environments, service tokens, change approval, audit log. Never owners. |
| Organization member | Least trusted authenticated user | Only what a project grant allows: viewer sees names, reader reads values, writer writes. |
| Service token | Machine credential, least privilege | Secret operations inside one project and one environment, `read` or `read-write`, always expiring. |
| Unauthenticated caller | Untrusted | Login only. |
| Host operator | Trusted, out of scope | Has the master key and database superuser. Can read everything by design; not defended against. |

## Trust boundaries

1. **The HTTP boundary.** Everything from the network is untrusted. Authentication resolves a bearer
   credential to an actor before any business logic runs.
2. **The organization boundary.** A hard tenant separation enforced in SQL, not in application
   filters: every resolution carries `org_id` in the predicate, so another organization's resource and
   a non-existent resource are the same query result.
3. **The service-token boundary.** Confined to one project and one environment, enforced in the same
   resolution as the organization boundary.
4. **The process boundary.** The server holds the master key and all decrypted values in memory.
   Anything that can read the process memory has the secrets.
5. **The database boundary.** The runtime role cannot modify audit rows. The owner role can, and is
   used for migrations, backup, restore and the tamper probe.
6. **The container boundary.** The server runs as a non-root user in a pinned image.

## Master key handling

The master key is supplied as `COFFER_MASTER_KEY`, base64 of exactly 32 bytes, and the server refuses
to start if it is missing, is the wrong length, or still holds the placeholder from `.env.example`.

It never appears in the database, in a log, in an audit event, or in a backup. It wraps one data key
per project; data keys encrypt values. Compromising the database alone yields ciphertext and wrapped
data keys, which is why the key is held outside the database and the backup.

Rotation uses `COFFER_MASTER_KEY_PREVIOUS`: every data key is unwrapped with the old key and re-wrapped
under the new one before the server reports ready, after which the old key is not needed. Rotation
does not re-encrypt values, so it is fast and bounded.

The key is held in the process environment, which is readable by the host operator and by anything
that can inspect the process. A production deployment should supply it from a secret manager or a
file with restricted permissions rather than a checked-in file.

## Authentication

Passwords are argon2id. Login responses for an unknown email and a wrong password are identical in
status, body and timing, with a dummy hash verification on the unknown-email path so the response time
does not leak account existence.

Tokens carry 256 bits of randomness, are prefixed `cof_pat_` or `cof_st_`, are stored only as
SHA-256 hex, and are shown once at creation.

Revocation is checked on every request with no cache, so it is visible to the next request well inside
the one-second requirement. Expiry is compared against the database clock, not the application clock.

The CLI accepts passwords on stdin only, never in argv, so they do not appear in process listings or
shell history.

## Authorization

The rules of §2 are implemented in one pure package and applied through one resolution path. Three
properties matter most:

**Invisibility is a 404.** A caller who cannot see a resource receives the same response as for a
resource that does not exist. This is enforced by resolving with `org_id` in the SQL predicate rather
than by filtering after the fact.

**Denials are audited.** Every 403 or 404 produced by authorization writes one audit event with result
`denied`, in the actor's organization chain, or the platform chain for callers with no organization.
The write happens after the response is decided and without resolving whether the target exists.

**There is no self-escalation.** No request changes the caller's own role, grants, organization or
platform-admin status. A sole owner attempting it receives 409 (last owner); any other self-change
receives 400.

## Audit integrity

Each organization has a hash chain, and so does the platform log. Each event's hash covers the previous
hash and a canonical encoding of the event, so modifying, reordering, inserting or deleting an event
breaks the chain from that point. Verification reports the first invalid sequence number.

The runtime database role holds `SELECT, INSERT` only on `audit_events` and cannot own, alter or
re-grant the table, so it cannot remove the append-only triggers. Two triggers additionally raise for
any non-superuser caller. `COPY` does not fire row triggers, which is why backup and restore still work.

**Residual risk, stated plainly.** The append path needs `UPDATE` on `audit_heads`, so a compromised
runtime role can rewrite the head to agree with a truncated event table, and verification would then
agree with itself. Preventing that requires the head to be unwritable, which the append design does not
allow. The real control against an attacker at that level is the off-box copy of the chain: the
encrypted backup, taken regularly and stored where the attacker cannot reach it. Treat a backup as part
of the audit story, not only a disaster-recovery measure.

A superuser can also bypass both controls with `session_replication_role = replica`. This is a
deliberate escape hatch used by the tamper probe; it means superuser access defeats immutability
entirely, and that is out of scope to prevent.

## What is not protected

**Host and database operator.** Anyone with the master key and database superuser reads every secret.
Coffer does not defend against its own operator, and does not claim to.

**A compromised running process.** An attacker who can read the server's memory or execute code in it
has the master key and the decrypted values.

**TLS.** §8 puts TLS termination outside the service, assuming a reverse proxy. **Bearer tokens and
secret values cross the wire in clear if no proxy terminates TLS.** This is why a non-loopback bind
logs a startup warning: binding beyond loopback without TLS in front exposes every credential on the
network.

**Denial of service.** The per-IP login throttle and the denial-audit rate caps bound the cheapest
abuse, but there is no global request limit and no protection against a flood that consumes
connections.

**Traffic analysis and metadata.** Request sizes and timings are observable to anyone on the network
path.

**Backups.** A backup contains ciphertext and wrapped data keys. It is only as safe as the master key,
and the master key must not be stored beside it.

## Known limitations

**Account enumeration through lockout.** §4 requires 429 after five failed logins for an account
within fifteen minutes, even with the correct password, while other accounts are unaffected. Those two
requirements together let an attacker distinguish an existing account from a non-existent one by the
status code. The literal behaviour is implemented because changing it would contradict the spec's own
"other accounts are unaffected". Mitigations: a per-IP throttle on the login route and a bounded LRU
keyed by email so the failure counters cannot be used to exhaust memory.

**Degraded single-role mode weakens audit immutability.** If `COFFER_APP_DB_PASSWORD` is absent and
`COFFER_ALLOW_DEGRADED_DB_ROLE=1` is set in a non-production environment, the server runs as the owner
role. The audit-immutability requirement is then unmet, because the owner is a superuser and both the
grant and the triggers permit it. A startup warning states this. Production refuses the combination,
and a rejected app password is a failed start rather than a fallback.

**Audit `source_ip` is the proxy address unless `COFFER_TRUST_PROXY=1`.** With §8's assumed reverse
proxy and the flag unset, every event records the proxy, not the client. This is the fail-closed
default: trusting `X-Forwarded-For` unconditionally would let a caller rotate the header to evade the
per-IP limits and poison the audit trail. With the flag set, the rightmost untrusted hop is used, which
is only correct if the trusted-proxy list is accurate.

**A non-loopback bind needs TLS in front of it.** The server serves plain HTTP. Binding to `0.0.0.0`
without a TLS-terminating proxy exposes bearer tokens and secret values. The startup warning exists to
make this hard to miss.

**Change requests are visible to the whole organization.** Anyone with admin or owner rights can see a
pending change, including its target key, but the proposed value is encrypted and only decrypted when
applied. A pending change does not expire; it stays pending until resolved or superseded by a stale
mark.

**The audit log grows without bound.** There is no retention policy and no rotation. A long-lived
installation will need one, and deleting audit rows is exactly what the immutability controls prevent,
so any retention scheme is a deliberate, documented operation by the owner role.

**Timing side channels beyond login are not analysed.** Authorization decisions differ in work
performed, and the 404-for-invisible rule equalises the response but not necessarily the timing. No
attempt is made to make every path constant-time.

**No rate limit on authenticated requests.** A valid credential can read as fast as the server serves.
The performance targets assume that is acceptable inside an organization.

**Concurrent reads are serialised per organization by the audit chain.** Every secret read appends an
audit event, and every append takes the organization's chain head row `FOR UPDATE` so the chain stays
gap-free. Reads of different secrets in the same organization therefore queue behind each other. This
is a deliberate consequence of requiring one audited event per read, and it is why 50 concurrent reads
measure p95 132–224 ms with the chain versus 7–19 ms with auditing disabled. The same mechanism means
an organization's write throughput is bounded by its chain, not by the database.

It is not a defence against a denial of service by an authenticated insider: one organization's
traffic cannot slow another's, but it can slow itself, and a burst of reads delays every other read in
that organization. Documented in `docs/DECISIONS.md` with the measurements.

## Out of scope

A web console, SSO, OIDC, SAML, MFA, email delivery, TLS termination, multi-node or high availability,
Kubernetes manifests, dynamic or leased secrets, users in more than one organization, and billing. §8
excludes all of these and Coffer implements none of them.

## Reporting

This is a build exercise, not a deployed service. In a real deployment, a security issue should go to
whoever operates the installation, with the master key rotated and the audit chain verified as the
first two steps of any incident response.
