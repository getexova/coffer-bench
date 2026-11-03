# Slice: AUTH and TENANCY (E1)

`internal/api/authapi` and `internal/store/auth`: authentication, the actor resolver,
authorization for the tenancy routes, and the denial audit flush. 20 routes, no stubs.

## Verified

Run against a throwaway `postgres:16` (`podman run … postgres:16`), schema applied by
`store.Migrate`:

```
$ go build ./internal/store/auth/... ./internal/api/authapi/...   → exit 0
$ go vet   ./internal/store/auth/... ./internal/api/authapi/...   → exit 0
$ gofmt -l internal/store/auth internal/api/authapi                → (empty)
$ COFFER_TEST_DATABASE_URL=… go test ./internal/store/auth/... ./internal/api/authapi/... -v
  → 30 tests, 30 PASS, ok coffer/internal/api/authapi 3.996s
$ ./scripts/test.sh            → ok coffer/internal/api/authapi 4.628s
$ go test ./internal/api/authapi/   (no COFFER_TEST_DATABASE_URL)
  → ok; the 11 database-backed tests SKIP with an explicit "SKIPPED, NOT PASSED" message
```

## Authentication

- argon2id (`x/crypto/argon2`), m=64 MiB, t=3, p=2, 16-byte salt per hash, PHC string
  with its own parameters so raising the cost later does not invalidate old hashes.
- Concurrent hashing is bounded by a slot semaphore (`runtime.NumCPU()`, floor 2),
  because each hash holds 64 MiB and an unbounded burst would be a memory-exhaustion
  vector on the login path.
- **Unknown email vs wrong password**: same 401, same body, and the unknown-email path
  runs a full verification against `dummyHash`, a real argon2id hash built once at
  startup. Building it lazily would make the first unknown-email request measurably
  slower, which is the exact signal this removes.
- **Lockout**: 5 failures in 15 minutes locks the account until the oldest of those
  ages out, checked *before* verification, so a correct password is refused with 429.
  Bounded LRU (4096 entries) keyed by lowercased email, plus a per-IP failed-attempt
  bucket (burst 100, 10/s). Accepted consequence: an unknown email that has been
  failed 5 times is locked like a real one, so 429 is evidence the account exists.
  Returning a uniform 429 for unknown emails would claim a lockout that is not there.
- Tokens: `idgen.Secret(idgen.PrefixPAT)` / `PrefixService` (32 random bytes, hex).
  Only the SHA-256 hex is stored. Plaintext is returned once.

## Token resolution — one query, no cache

`authstore.ResolveTokenSQL` is a single statement over a `UNION ALL` of the two
`token_hash` unique indexes. Every rejection is a SQL predicate: `revoked_at IS NOT
NULL`, `expires_at > now()` (the **database** clock), `users.removed_at IS NOT NULL`,
`organizations.disabled_at IS NOT NULL`. Nothing is cached in the process, which is
what makes revocation visible on the next request.

## Authorization

Order in `handleUpdateMember` (`internal/api/authapi/members.go`), after the CTO's
"authorization first" ruling:

| # | Check | Status |
|---|---|---|
| 1 | target is a live member of this org (`UserByIDInOrg`) | 404 |
| 2 | non-owner touching or creating an owner | 403 |
| 3 | last owner cannot be demoted (owner callers only) | 409 |
| 4 | caller changing their own role | 400 |
| 5 | unknown role | 400 |

**Authorization precedes the last-owner rule**, and the reason is a visibility leak: with
the old order an admin demoting the sole owner got 409 while an admin demoting a
non-last owner got 403, so the status told an admin how many owners existed. An admin is
never permitted to touch an owner, so an admin now gets **403 in both cases**; 409 is
reserved for an **owner** acting on the last owner, the only caller who could actually
perform the demotion. `TestLastOwnerRules` pins all three branches:
admin→sole owner 403, admin→non-last owner 403, owner→last owner 409.

Consequence worth knowing: an admin promoting *themselves* to owner now gets **403**
(the owner gate answers first) rather than 400. Both rules are violated and the gate
wins; the role is still never applied, which the test asserts in SQL.

`requireActor` applies the must-change gate, so the gate runs before any role or
visibility check on every route. `orgScope` answers the platform admin with 404 on
every organization-scoped route. `requireManager` refuses members and service tokens
with 403 **before** any field is validated, so a member posting an invalid body to
`/members` gets 403, never a 400 describing the payload.

Invisibility is a 404 with a byte-identical body, because every organization-scoped
lookup carries the caller's `org_id` in the SQL predicate.

### A service token on `GET /me` gets 403

A service token may only perform secret operations inside its scope (SPEC §2.7), and
`/me` is not one, so a service-token actor gets **403** — not a 200 reduced to its
scope. It is not a 404 because the credential authenticated and the route is visible to
it. Users and the platform admin keep their 200 responses.


## P1

- **P1(a)** `must_change_password` is set by `POST /members` **and** `POST /admin/orgs`:
  the rule is "gated whenever a principal other than the account holder supplies the
  initial password", applied to the call site rather than to a list. The bootstrap
  platform admin is the one exception (`false`) — the operator supplies their own
  password, and gating it would deadlock every automated flow including bootstrap
  itself.
  The gate is deny-by-default with a two-entry allowlist (`POST /auth/password`,
  `POST /auth/logout`) enforced in the middleware *and* in `requireActor`.
  **`GET /me` is gated** — the brief's allowlist is exactly those two routes.
- **P1(b)** `POST /auth/password` sets the new hash, clears the flag and revokes every
  other PAT in **one transaction**, keeping the token that made the change.

## `source_ip`

`authapi.SourceIP(r, trustProxy)` — socket peer by default; only when
`COFFER_TRUST_PROXY=1`, the **rightmost** `X-Forwarded-For` entry that is not a trusted
proxy. Never the leftmost (that is attacker-supplied). The trusted set is derived —
loopback, private, link-local — because the frozen env list has no variable for it;
adding one would be a contract change.

## Denial flush

One `denied`/`denied` event per 403 or 404 **by authorization**, written after the
status is known, never resolving whether the target exists. Never for a bare 401.
Budget 10/s burst 50 per IP, 100/s global, overflow counted and logged in aggregate
(`denialReportEvery`), never one row per drop.

## Response shapes (what the CLI and testutil compile against)

SPEC §7.2 pins bodies for `/auth/token` (`{token,user}`) and `/tokens` (`{id,token}`)
and says nothing about the rest, so these are the shapes this slice answers with and
they are now settled with E2 and E0:

| Route | Body |
|---|---|
| `POST /projects` | `{"project":{id,slug,created_at}}` — **nested**; `testutil.NewProject` decodes this |
| `POST /projects/{p}/envs` | flat `{"id",slug,protected,created_at}` — `testutil.NewEnv` decodes this |
| `POST /admin/orgs` | org id **both** nested (`{"organization":{…}}`) and top-level (`{"id","slug"}`), because `testutil.CreateOrg` reads a top-level `id` |
| `POST /members`, `PATCH /members/{id}` | `{"member":{…}}` |
| `GET` list routes | `{"projects":[…]}`, `{"environments":[…]}`, `{"members":[…]}`, `{"tokens":[…]}`, `{"organizations":[…]}`; always `[]`, never `null` |
| `POST /tokens` | flat `{"id","token","project","env","access","name","expires_at"}` |

The project/env asymmetry is ugly and is kept deliberately: both forms are already
consumed by the shared harness, and changing either one breaks peer tests that do not
belong to this slice.

## Decisions

These are recorded here in full because `docs/DECISIONS.md` is outside this slice's
paths. They are ready to move there verbatim. Decision 1 is the only one that touches
a frozen contract, and `docs/CONTRACTS.md` §2 explicitly requires an entry in
`docs/DECISIONS.md` for that — so it needs to land before this counts as complete.

### 1. `password_change_required` — a new error code at status 403 (contract exception)

SPEC §4 (P1) requires a user created with an initial password to change it before
doing anything else, but fixes neither the status nor the code. `docs/CONTRACTS.md` §2
is a frozen table mapping 403 to `forbidden`, and forbids slices inventing codes.

**Decision.** Return a distinct code `password_change_required` with status **403** when
an authenticated caller still has `users.must_change_password = true` and calls any
route other than `POST /api/v1/auth/password` and `POST /api/v1/auth/logout`.

**Alternative rejected.** Reusing `forbidden`. It would make "you lack permission" and
"you must change your password first" indistinguishable to a machine, and both
`coffer passwd` (SPEC §7.1) and the black-box acceptance script must tell them apart to
give a usable next step. Message prose is not a contract; a code is.

**Consequence.** The HTTP status is unchanged at 403, so a client that only knows the
frozen table still sees a forbidden status and does not break. The message text is
stable — `password change required: call POST /api/v1/auth/password (coffer passwd)
first` — because the CLI keys off the code and prints the message as the hint. The
allowlist is exactly two routes and the gate is deny-by-default, enforced in the auth
middleware and again per request, so a route added later is gated without anyone
remembering to add it.

### 2. A wrong `current_password` is 400, not 401

`POST /auth/password` with a wrong `current_password` returns **400
`validation_error`**. The personal access token resolved fine; the fault is in the
payload. A 401 would tell the CLI to discard a working token, and exit 3 ("get a new
token") instead of exit 6 ("your input is wrong"). Only a genuinely dead credential
returns 401 from that route.

### 3. The lockout is bounded

Five failures in fifteen minutes locks the account; the failure history lives in an LRU
of 4096 accounts and the per-IP bucket in an LRU of 8192 addresses. Both keys are
attacker-controlled — an unknown email is whatever the attacker types — so an unbounded
map would be a memory-exhaustion vector rather than a cache. Consequence: an account
whose history is evicted can be attempted again, which requires 4096 distinct accounts
under attack first.

### 4. The trusted-proxy set is derived, not configured

`source_ip` honours `X-Forwarded-For` only when `COFFER_TRUST_PROXY=1`, and then takes
the rightmost entry that is not a trusted proxy. The trusted set is loopback, private
and link-local addresses, derived rather than configured, because the frozen
environment list in `docs/CONTRACTS.md` §10 has no variable for it and adding one is a
larger contract change than deriving it. Consequence: with the flag on, a client that
reaches the proxy from a private address is indistinguishable from a proxy hop, so its
request is attributed to the nearest non-private hop, or to the proxy when there is
none. That over-attributes to the proxy and never under-attributes to an attacker.

### 5. `/admin/*` is not organization-scoped

A non-platform caller gets **403** on `/admin/*`, while the platform admin gets **404**
on every organization-scoped route. `/admin` is not an organization resource, so there
is nothing to hide behind a 404; organization-scoped routes are outside the platform
admin's reach entirely (SPEC §2.10), so they are invisible to it.

### 6. The login throttle counts failed attempts only

A successful login does not consume the per-IP bucket, so a test harness or a CI job
logging in repeatedly from one address is never throttled, while an online guessing
attack from one address is. The per-account lockout is the primary control; this is the
anti-spraying control beside it.

### 7. Bootstrap is gated, and the platform admin is the one exception

`must_change_password` is set by `POST /members` **and** `POST /admin/orgs`, because the
rule is "gated whenever a principal other than the account holder supplies the initial
password", applied at the call site rather than to a list of routes. The bootstrap
platform admin is the one `false`: the operator supplies that password from their own
environment, nobody else chose it, and gating it would deadlock the first boot of every
automated flow including bootstrap itself.

## Known gaps in my slice

- The authorization suite needs `COFFER_TEST_DATABASE_URL`; without it 11 tests skip.
  A skipped run is not a passing run.
- Values never leave through my routes, so §2.4 (`viewer` sees names not values) and
  §2.9 (self-approval 403) are E2's `secretsapi`, not mine. My side of them is the
  grant level and the role, both covered.
- No slice's HTTP-level tests can count audit rows, because `internal/testutil` hard-codes
  `audit.NopWriter()`. That is a shared-harness gap, not a slice defect; the denial
  events my slice writes are asserted against an in-test writer instead.
- The denial budget is per-process. Two replicas would each get the full budget; that
  is fine for the single-process deployment the spec assumes.
