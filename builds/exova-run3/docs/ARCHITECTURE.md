# Architecture

Coffer is a Go HTTP service with a command-line client. One binary serves both roles: `bin/coffer
serve` runs the server, every other invocation is the CLI. The server stores encrypted secret values
in PostgreSQL and records every access in a per-organization hash chain.

## Process shape

```
cmd/coffer ──┬── serve ──► internal/httpapi (router, server, middleware)
             └── CLI ────► internal/httpapi over HTTPS/HTTP
```

The CLI speaks to the server only through `/api/v1`, with one exception: nothing. There is no
in-process shortcut, so a CLI test against an `httptest` server exercises the same code a remote
client does.

`internal/httpapi/router.go` is the composition root. It builds a `http.ServeMux`, installs
middleware, and calls one `Register` function per slice package. It contains no business route of
its own and does not change once the foundation is frozen.

## Packages

| Package | Responsibility |
|---|---|
| `internal/config` | Reads the environment, validates the master key, gates degraded mode. Fails with a message naming the offending variable. |
| `internal/httpx` | The single error envelope, the status and code mapping, the required response headers, the 1 MiB body limit. |
| `internal/reqctx` | `Actor` (user, PAT, service token, platform admin, anonymous), the per-request denial `Recorder`. |
| `internal/authz` | Pure predicates deciding visibility and permission. No I/O, so every rule in §2 is directly unit-testable. |
| `internal/idgen` | Opaque object ids and 256-bit credential secrets. |
| `internal/crypto` | Envelope encryption, AAD construction, master-key rotation. |
| `internal/audit` | The event model, the chained writer, the verifier. |
| `internal/store` | Connection management, the migration runner, the embedded schema. |
| `internal/store/{auth,secrets,auditq}` | SQL for each slice, split so each slice is a separate Go package. |
| `internal/api/{authapi,secretsapi,auditapi}` | HTTP handlers for each slice, same reason. |
| `internal/testutil` | Test harness: test database, migrations, a real PAT minted over `POST /auth/token`. |

The split into per-slice packages is deliberate. Go compiles whole packages, so a slice importing a
peer's package could not build until that peer finished, and the per-engineer scoped check would be
meaningless. Slices share only frozen interfaces: `audit.Writer`, `reqctx`, `authz`, `httpx` and the
store base.

## Request lifecycle

1. **Request id.** Generated if absent, echoed in `X-Request-Id`, placed in the context.
2. **Logging.** A JSON line to stdout with method, route, status, `duration_ms` and `request_id`.
   Bodies, headers, cookies and `Authorization` are never logged.
3. **Panic recovery.** Any panic becomes a 500 with the literal message `internal error`.
4. **Authentication.** One indexed query resolves the bearer credential to an `Actor`: the token row,
   its user, the organization, and the caller's grant for the target project. Revocation, expiry and
   removal are checked here, with expiry compared against the database clock in SQL. There is no
   cache, which is what makes revocation visible within one second.
5. **Authorization.** The handler asks `authz` whether the actor can see and do the thing. An
   invisible resource and a missing resource produce the same query result, hence the same 404.
6. **Business transaction.** Reads and writes, with audit events appended through `AppendTx` so the
   audit row commits with the change.
7. **Denial flush.** If the response was a 403 or 404 produced by authorization, one audit event is
   written with result `denied`. This happens centrally, so no handler can forget it.

## Data model

```
organizations ─┬─ users ──────────────┬─ personal_access_tokens
               │                      └─ project_grants ──┐
               ├─ projects ──┬─ environments ── secrets ── secret_versions
               │             │        │
               │             └─ project_data_keys
               ├─ service_tokens ─────┘
               ├─ change_requests
               └─ audit_events, audit_heads
```

`secrets` carries `current_version`, which is the version allocator. `secret_versions` holds one row
per version, keyed `(secret_id, version)`, with a NULL ciphertext for a tombstone. `audit_events` is
keyed `(scope, seq)` where scope is an organization id or the literal `platform`; `audit_heads` holds
the tail of each chain.

## Encryption

A master key (`COFFER_MASTER_KEY`, base64, exactly 32 bytes) wraps one data key per project. Data
keys encrypt secret values with AES-256-GCM.

Associated data binds a ciphertext to its position:

```
aad(parts...) = for each part: uvarint(len(part)) || part
secret value : "coffer:v1", org, project, environment, key, version
data key wrap: "coffer:dek:v1", org, project, key_version
change payload: "coffer:change:v1", org, project, environment, key, change_id
```

The length prefixes make adjacent fields unambiguous, so a value cannot be shifted across a field
boundary to forge a tag. A ciphertext copied into another row fails the tag check and returns an
error, never a value.

Rotation reads `COFFER_MASTER_KEY_PREVIOUS`, unwraps every data key with the old key, re-wraps under
the new one, and completes before the server reports ready.

## The version allocator

Concurrent writes to one key must each receive a distinct version with no gaps and no lost updates.
The allocator is a single statement:

```sql
UPDATE secrets SET current_version = current_version + 1, updated_at = now(), updated_by = $2
 WHERE id = $1 [AND current_version = $3]
 RETURNING current_version
```

The row update is the lock. The `secret_versions` insert happens in the same transaction, and its
primary key makes a duplicate version impossible even under a bug. An expected-version mismatch
affects zero rows and returns 409 without allocating anything.

## Change requests

A write to a protected environment stores the proposed value encrypted with AAD bound to the change
id and returns 202. Approval is:

1. Proposer equals approver → 403, before any state change.
2. `UPDATE change_requests SET status='approved' WHERE id=$1 AND status='pending' RETURNING …`
   Zero rows → 409. This is the compare-and-swap that makes double approval impossible.
3. `SELECT … FROM secrets WHERE id=$1 FOR UPDATE`, compare `base_version` with `current_version`.
4. Mismatch → mark `stale`, audit, 409. Match → apply through the same allocator, in the same
   transaction.

## Audit chain

Each organization has a chain, and so does the platform log. An append, in one transaction:

1. `SELECT seq, hash FROM audit_heads WHERE scope=$1 FOR UPDATE`
2. `seq := head.seq + 1`
3. `hash := SHA-256(prev_hash || canonicalJSON(event without hash))`
4. insert the event at `(scope, seq)`
5. update the head

Canonical JSON has a fixed field order, HTML escaping disabled, and UTC timestamps at microsecond
precision to match `timestamptz`. The form is frozen at v1.

Verification walks `audit_events` from `seq` 1, rebuilds canonical bytes from each row's own columns,
and recomputes the chain. It never trusts `audit_heads`; a disagreement between the head and the
recomputed tail is reported directionally, because events ahead of the head is tampering and events
shorter than the head is truncation.

Immutability uses two roles. The owner role runs migrations and may tamper, which is what makes the
tamper test meaningful. `coffer_app` is the runtime role: no superuser, owns nothing, no `CREATE` on
the schema, no membership in the owner role, and `SELECT, INSERT` only on `audit_events`. Two triggers
raise for a non-superuser and return early for a superuser, so the runtime role is blocked by both the
grant and the trigger while a deliberate superuser tamper still succeeds and is detected.

## Migrations

SQL files are embedded with `//go:embed`, ordered by numeric prefix, and applied under
`pg_advisory_lock`. Each file runs in one transaction together with the grant block, so a failure
leaves no partial schema. Applied versions and their checksums are recorded in `schema_migrations`;
a checksum mismatch on an already-applied version is a hard failure. Two containers starting together
serialise on the lock and the loser applies nothing.

The server opens the owner connection for migrations, closes it, then opens the runtime pool as
`coffer_app`. `/readyz` cannot report ready before that handover completes.

## Failure behaviour

- Database unreachable at boot: retry with backoff, `/healthz` 200, `/readyz` 503 `reason: database`.
- Migrations incomplete: `/readyz` 503 `reason: migrations`.
- Database returns later: `/readyz` recovers on its own, no restart needed.
- SIGTERM: stop accepting, finish in-flight requests, exit within 10 seconds.
- A ciphertext that fails its tag check: 500 with no value, never a partial read.

## Performance

Two targets from §5, both measured rather than assumed: listing an environment with 1,000 secrets has
p95 under 300 ms (one query, no per-row decryption), and 50 concurrent value reads have p95 under
200 ms. The audit append serialises per chain on the head row, which is the design's write ceiling;
if it binds, denial rows are batched, never the chain weakened.
