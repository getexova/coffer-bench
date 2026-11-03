# Slice: secrets, encryption and change requests

Owner: E2. Packages: `internal/crypto`, `internal/store/secrets`, `internal/api/secretsapi`.
Routes: `docs/CONTRACTS.md` §4, `secretsapi` block. AAD and schema are frozen by §5 and §6.

This document explains the parts a reviewer should check by hand, because the compiler cannot:
the version allocator, the two-person approval transaction, and the associated-data binding.

## 1. Envelope encryption

`COFFER_MASTER_KEY` is base64 of exactly 32 bytes and is validated once in `internal/config`
(missing, not base64, wrong length, or the shipped placeholder all refuse to start). It never
encrypts a secret directly.

```
master key  --wraps-->  project data key (one row per project in project_data_keys)
project data key --AES-256-GCM--> secret value
```

`project_data_keys` stores `wrapped_key`, `nonce` and `key_version`. The data key is created on the
write path by `crypto.Sealer.Ensure`, which is a single `INSERT … ON CONFLICT (project_id) DO UPDATE`
statement: two concurrent first-writes agree on one data key instead of each creating one that cannot
decrypt the other's ciphertext. It is never created on a read path, because a project with no data key
has no ciphertext to read and minting one there would hide a provisioning bug.

A `crypto.Key` is an array, so it is copied by value, and it implements `String`/`GoString` so that
`%v`, `%s`, `%+v` and `%#v` of a key or of a struct containing one print `crypto.Key(redacted)`.

## 2. Associated data (the frozen layout)

`aad(parts...)` is, for each part in order, `uvarint(len(part)) || part`. The length prefixes are the
security property: without them `("ab","c")` and `("a","bc")` would encode identically and a value
could be shifted across a field boundary to forge a tag that verifies. `internal/crypto/aad.go`
implements it, and `crypto_test.go` asserts the byte layout, that every field participates, and that
every split of one string encodes differently.

| Purpose | Parts |
|---|---|
| secret value | `coffer:v1`, org id, project id, env id, key, version (decimal) |
| project data key wrap | `coffer:dek:v1`, org id, project id, key version (decimal) |
| change request payload | `coffer:change:v1`, org id, project id, env id, key, change id |

A ciphertext moved to another row therefore fails the GCM tag check and `Open` returns
`ErrDecrypt` with no plaintext at all — never a partial or empty value. This is tested three ways:
in isolation (`TestCopiedCiphertextNeverReturnsAValue`), through the real schema
(`TestRawCopiedCiphertextFails`), and through the HTTP surface where it must be a 500
(`TestCiphertextMovedBetweenRowsIs500`). The 500 is expected behaviour and is what the error log line
in the suite is: it is produced by that test on purpose.

The AAD is always rebuilt from the row's own coordinates and its stored version, never from anything
the caller supplied, so a copy cannot be made to verify by relabelling it in the request.

## 3. The version allocator

There is no `MAX(version)+1` anywhere in this slice, and there must never be one.
`secrets.current_version` is the allocator, in `internal/store/secrets/write.go`:

```sql
UPDATE secrets
   SET current_version = current_version + 1, updated_at = now(), updated_by = $2
 WHERE env_id = $1 AND key = $3 [AND current_version = $expected]
 RETURNING id, current_version
```

That statement is both the allocator and the lock.

**Why two concurrent unconditional writers cannot duplicate or lose a version.** Postgres takes a row
lock before applying the update and holds it until the transaction commits. Writer A and writer B
therefore serialise: B blocks until A commits, then re-evaluates the row it read and increments from
A's committed value. A gets n+1 and B gets n+2. There is no window in which both read n and both write
n+1, which is exactly how `MAX+1` loses an update.

**Why there can be no gap.** The only way to obtain a number is to increment the single committed
counter, and a transaction that increments and then fails rolls the increment back with everything
else. A rejected conditional write (`ErrConflict`) never reaches the increment, so it consumes
nothing.

**Why a duplicate is impossible even if the allocator were wrong.** The `secret_versions` row is
inserted with that number in the same transaction, and the primary key `(secret_id, version)` would
reject a second row with the same number, rolling the whole transaction back rather than forking a
version.

**Expected version.** A conditional write puts `AND current_version = $expected` on the same
statement, so the compare and the increment are one atomic operation rather than a read followed by a
write that another transaction could interleave with. Zero rows affected is `ErrConflict` (409) and
allocates nothing.

The secret row is created first for a `set` only (`INSERT … ON CONFLICT (env_id, key) DO NOTHING`,
which does not touch `current_version` and so consumes no number). A `delete` or a `rollback` against
a key that does not exist is `ErrNotFound` (404) rather than a phantom tombstone.

## 4. Tombstones, history and rollback

A delete writes a new version with `deleted = true` and a NULL ciphertext. A get then returns 404 —
identical to a key that never existed — while history keeps the tombstone with `deleted: true`, and a
later set continues the numbering from it. An empty value is a *live* value of zero bytes, distinct
from a tombstone, and it round-trips exactly.

Rollback to version k decrypts at k with k's associated data and re-encrypts at n+1 with n+1's. It is
a genuine re-encryption, not a copied ciphertext: copying the bytes would produce a value that cannot
be decrypted at the new version. The new version holds the value, so deleting the source later cannot
change history.

## 5. Listing and export

Listing is one query that joins `secret_versions` on `current_version` and returns key, version,
`updated_at` and `updated_by` only. It decrypts nothing, so it has no per-row cost and no N+1; a
tombstoned key is excluded because for a reader it does not exist.

Export decrypts every live value with one ciphertext query plus one data-key load. `dotenv` escapes
exactly five characters and nothing else — `\`→`\\`, `"`→`\"`, newline→`\n`, CR→`\r`, `$`→`\$` — and
emits `KEY="VALUE"` lines sorted by key, LF endings, with a final newline. `json` is one object
marshalled by hand with sorted keys and HTML escaping off, so `<`, `>` and `&` come back unchanged.
Each key in an export writes its own `secret.read` event before the body is written, so a failed audit
fails the request rather than returning values that were never recorded.

## 6. Protected environments and the two-person rule

A write to a protected environment by anyone allowed to write — owners and admins included — creates
a change request and returns `202 {"status":"pending","change_id":"…"}`. The proposed value is sealed
with associated data bound to the **change id**, so a pending change is ciphertext at rest and cannot
be redirected to another key, environment or request by editing the row. `base_version` records the
version the proposer saw.

Approval is one transaction, in this order (`Store.ApproveTx`):

1. Proposer == approver → `ErrSelfApproval` (403), before any state change, so a self-approval cannot
   consume the request.
2. The approver must be an owner or an admin → otherwise `ErrNotApprover` (403).
3. `UPDATE change_requests SET status='approved' … WHERE id=$1 AND status='pending' RETURNING …`.
   Zero rows is `ErrAlreadyResolved` (409). Everything the apply needs is taken from the `RETURNING`
   row, so nothing outside the row can influence what is applied.
4. For a `set`, `INSERT … ON CONFLICT (env_id, key) DO NOTHING` **before** the lock, so the row to
   lock always exists; then `SELECT … FOR UPDATE` and compare `base_version` with the live
   `current_version`.
5. Mismatch → mark the request `stale`, audit `change.stale`, return `ErrStale` (409). Nothing is
   applied and no version is allocated.
6. Match → apply through the same allocator path as a direct write, in this transaction, then audit
   `change.approved` and the secret action.

**Why approval cannot be applied twice.** Step 3 is a compare-and-swap. Postgres serialises two
concurrent approvers on the change row; the first commits, and the second re-evaluates its `WHERE`
against the committed row, finds `status` no longer `'pending'`, and affects zero rows. There is no
read-then-write window to lose, so the second approver cannot apply the value a second time and cannot
overwrite the first resolver's decision. `TestConcurrentApprovalAppliesOnce` (and the raw variant with
16 approvers) asserts exactly one success, N-1 conflicts, and `current_version = 1` afterwards.

**Why a key created concurrently is detected.** `SELECT … FOR UPDATE` on a row that does not exist
takes no lock, so a writer could create the key between the version check and the apply. Step 4
therefore creates the row first: the insert blocks a concurrent creator, and after that transaction
commits the live `current_version` is no longer the recorded `base_version`, so the change is stale.

Reject sets `rejected` through the same conditional update; a second resolution of any kind is 409.
`GET /changes?status=` accepts `pending|approved|rejected|stale` and anything else is 400.

## 7. Authorization

Project and environment are resolved in one query with `org_id` in the predicate, so another
organization's project, a project with no grant, and a missing project are the same 404.

The status depends on which question fails:

- `authz.CanView` is "can the caller see this at all", and it decides **404**. A member with no grant,
  the platform admin, and a service token pointed at another project or environment are all invisible
  here.
- The specific capability decides **403**. A viewer reading a value or exporting, and a read-only
  service token attempting a write, can see the resource and lack the permission.

Service tokens map `read`→reader and `read-write`→writer through `authz.Effective`, and can never
approve or reject a change (403 on both routes, and `/changes` itself).

## 8. Rotation

`crypto.RotateIfNeeded(ctx, pool, oldKey, newKey) error` re-wraps every project data key from the old
master key to the new one in a single transaction, and is called during boot before the server reports
ready. It is a no-op when no previous key is set. If any row cannot be unwrapped with the old key the
whole rotation aborts rather than skipping it, because skipping would leave a data key nobody can
unwrap once the old key is retired. The associated data is unchanged, because it binds the data key to
its project and key version, not to the master key that wraps it.

## 9. Test coverage and known gaps

Always runs (no database needed): `internal/crypto` — AAD layout, field shifting, wrap/unwrap, copy
failure, malformed input, key redaction, rotation no-op; and the pure functions in `secretsapi` —
dotenv escaping and document shape, JSON export, value bounds, key format, version parsing.

Needs `COFFER_TEST_DATABASE_URL` and skips without it: the allocator concurrency test, expected-version
409, tombstones, rollback numbering, empty-value round trip, the copy-failure test through SQL, the
approval tests (self, non-manager, double, concurrent, stale, reject, payload-at-rest), rotation, and
the HTTP authorization/export/audit tests. `./scripts/test.sh` provisions its own throwaway
`postgres:16`, so these run in the normal path.

Two test files use their own database (`coffer_raw_test`, `coffer_audit_test`, `coffer_http_test`)
rather than the shared one. `authapi.Bootstrap` creates the platform admin only when no users exist,
and those fixtures insert users directly; sharing one database would let a fixture that runs first
suppress the bootstrap and break every login-based test in the run.

Not covered by an automated test in this slice: the p95 performance targets (measured by ops, not
here), and the degraded single-role database mode (a foundation concern).
