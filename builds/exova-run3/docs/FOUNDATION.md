# Foundation (Stage 0)

The packages every slice compiles against. They implement the frozen contracts in
[`CONTRACTS.md`](CONTRACTS.md) and contain no business routes of their own.

Read this before touching a slice package. Nothing here may be changed casually:
`router.go` is frozen, `audit/event.go` is a contract four packages compile against,
and `0001_init.sql` carries a checksum that the runner enforces.

| Package | Contract | Owner |
|---|---|---|
| `internal/config` | §10, §11 | foundation |
| `internal/httpx` | §2 | foundation |
| `internal/reqctx` | §8 | foundation |
| `internal/authz` | SPEC §2 | foundation |
| `internal/idgen` | §8 | foundation |
| `internal/audit/event.go` | §3, §7 | foundation (append/verify: E3) |
| `internal/store` | §6, §9, §12 | foundation |
| `internal/httpapi` | §4 | foundation |
| `internal/testutil` | none | foundation, extended by E5 |

---

## `internal/config`. Environment, and only environment

`config.Load()` reads `os.LookupEnv`. `config.LoadFrom(lookup)` takes a lookup
function so tests never mutate the process environment. The binary never reads a
dotenv file: `.env` / `.env.production` are materialised into the process environment
by the container runtime, so a value that exists only in an interactive shell is not
configuration.

**Required:** `COFFER_MASTER_KEY` (base64, exactly 32 bytes, refused if it is the
`.env.example` placeholder or contains a placeholder marker), `COFFER_BOOTSTRAP_ADMIN_EMAIL`,
`COFFER_BOOTSTRAP_ADMIN_PASSWORD` (≥ 12 characters), and. When the connection URLs are
not given explicitly. `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`.

**Optional:** `COFFER_PORT` (8420), `COFFER_BIND_ADDR` (127.0.0.1), `COFFER_ENV`
(`production`), `COFFER_TRUST_PROXY`, `COFFER_DB_HOST` (127.0.0.1), `COFFER_DB_PORT`
(5432), `COFFER_DB_SSLMODE` (disable), `DATABASE_URL`, `COFFER_MIGRATION_DATABASE_URL`,
`COFFER_APP_DB_PASSWORD`, `COFFER_ALLOW_DEGRADED_DB_ROLE`, `COFFER_MASTER_KEY_PREVIOUS`.

A missing required variable returns `*config.MissingEnvError` whose message names the
variable. **No value is ever echoed**. A master key, a password and a connection URL
all stay out of error strings and logs. Passwords are escaped into the derived URL with
`url.UserPassword`, so `@`, `/`, `:` and `?` cannot corrupt it.

**An empty string is unset.** `compose` passes every key in `.env` into the container,
so optional variables arrive present-but-empty rather than absent; treating `""` as a
value would make the stack refuse to boot.

### Degraded database role (§11), as implemented

| `COFFER_APP_DB_PASSWORD` | `COFFER_ALLOW_DEGRADED_DB_ROLE` | `COFFER_ENV` | Result |
|---|---|---|---|
| set | any | any | run as `coffer_app` (`RoleApp`); a set flag adds a warning |
| unset | `1` | `production` | **refuse to start**, naming both variables |
| unset | `1` | not production | run as the owner (`RoleOwnerDegraded`) with a WARN naming the lost isolation |
| unset | unset | any | **refuse to start**, naming both variables |

A password that is present but **rejected by the server is a failed start**, never a
fallback (`internal/store` detects SQLSTATE 28P01/28000/42501 and stops). A typo must
not silently become a privilege change.

`Config` also exposes `Addr()`, `IsLoopback()` (drives the non-loopback WARN),
`IsProduction()`, `Degraded()`, `RuntimeURL()`, `MigrationURL()` and `Warnings`.

---

## `internal/httpx`. The only wire behaviour

One error body, ever:

```json
{"error":{"code":"..","message":".."}}
```

Codes and statuses (§2): `validation_error` 400, `unauthenticated` 401, `forbidden`
403, `not_found` 404, `conflict` 409, `body_too_large` 413, `rate_limited` 429,
`internal_error` 500. `StatusFor` maps them; an **unknown code maps to 500**, so a
slice that invents a code cannot leak a success status.

| Helper | Use |
|---|---|
| `WriteJSON(w, status, v)` | any JSON body |
| `WriteText(w, status, contentType, body)` | dotenv export: `text/plain`, other three headers kept |
| `WriteError(w, r, err)` | any error; `*httpx.Error` keeps its code, anything else is 500 |
| `WriteErrorCode(w, status, code, msg)` | rare, when only a code is known |
| `DecodeJSON(w, r, &dst) bool` | `false` means it already wrote 413 or 400 |
| `DecodeJSONOptional(w, r, &dst) bool` | a body that may be absent |

The three security headers. `Content-Type`, `X-Content-Type-Options: nosniff`,
`Cache-Control: no-store`. Are set by these helpers, not by handlers, so a handler
cannot forget them. `X-Request-Id` is set by middleware for every response including
errors and panics. No CORS header is ever emitted.

`DecodeJSON` wraps the body in `http.MaxBytesReader` at `MaxBodyBytes` (1 MiB), returns
**413 `body_too_large`** on `*http.MaxBytesError` and **400 `validation_error`** on
malformed JSON, a trailing second document, or an unknown field (`DisallowUnknownFields`,
so a field the caller may not set is a 400 rather than a silent no-op).

An unknown error becomes 500 with the **literal** message `internal error`; the cause is
logged server-side and never sent.

---

## `internal/reqctx`. The actor and the denial record

```go
type Actor struct {
  Kind   Kind  // anonymous | user | service | platform
  UserID  string
  TokenID  string
  Email   string
  OrgID   string
  Role   string // owner | admin | member | platform_admin
  ProjectID string // service tokens only
  EnvID   string // service tokens only
  Access  Access // read | read-write
}
```

`From(ctx)` returns an **anonymous** actor when nothing was set, so a handler that
forgot to resolve authentication fails closed rather than running privileged. `SetActor`
attaches in place for middleware.

`Authenticator` is the frozen seam E1 implements; middleware owns the call and a handler
never parses `Authorization`. Return an error wrapping `ErrUnauthenticated` for a bad
credential. Middleware turns that into 401, and anything else into 500, so a database
outage never looks like a wrong password.

`Deny(ctx, scope, action, target)` records a denial on the per-request `Recorder`,
keeping only the **first**. The recorder is installed by middleware; `Deny` is a no-op
without one, so a handler never panics.

Two values ride the context rather than the `Actor`, which stays at the frozen §8 shape:
`SourceIPFrom(ctx)` (resolved once by middleware: socket peer, or rightmost untrusted
`X-Forwarded-For` when `COFFER_TRUST_PROXY=1`) and `MustChangePasswordFrom(ctx)`.

---

## `internal/authz`. Pure predicates

No database, no network, no clock. A handler resolves the grant and asks this package
what it means, so every rule in SPEC §2 is readable in one file and table-testable
without a server.

```go
Effective(actor, projectID, envID, grant) string // "" | viewer | reader | writer
CanView / CanRead / CanWrite(actor, projectID, envID, grant) bool
IsOwner / IsAdmin / IsOrgManager / IsMember / IsPlatformAdmin
CanManageMembers / CanManageTokens / CanReadAudit / CanApprove / CanManageOwnership
```

Rules: **platform and anonymous get nothing** (the platform admin is invisible inside an
org, 404, not 403); a **service token is confined to its own project and environment**
and maps `read`→reader, `read-write`→writer, and can never manage anything; **owner and
admin reach every project in their org**; a **member reaches only a granted project**.
`grant` is `""` when the caller has none. Which answers "no access", never "full".
An empty project id is never writable, so a handler that fails to resolve a project
cannot accidentally grant access.

---

## `internal/idgen`

`New(prefix)` = 12 random bytes as hex (96 bits). `Secret(prefix)` = 32 random bytes as
hex (256 bits), used for `cof_pat_` and `cof_st_` (`PrefixPAT`, `PrefixService`). Both
read `crypto/rand` and panic on failure: a predictable id or a weak token would be far
worse than stopping.

---

## `internal/audit/event.go`. The chain contract

`Event{Scope, Seq, Timestamp, ActorID, ActorKind, OrgID, Action, Target, SourceIP,
Result, PrevHash}`. `Scope` is explicit. An organization ID or `PlatformScope`. And is never
inferred from `OrgID`, so an org event cannot silently land on the platform chain.

`Writer` is the only cross-slice audit dependency:

```go
Append(ctx, e Event) (Event, error)
AppendTx(ctx, tx pgx.Tx, e Event) (Event, error)
```

Both return the stored event with `Seq` and the chain hash filled in. `AppendTx` joins
the caller's transaction, so a secret write and its audit event commit or roll back
together. `NopWriter()` is the nil-safe default the server starts with before E3 lands.

Every action name from §3 is a constant (`ActionLoginSuccess`, `ActionSecretRead`, …),
`ActionNames` lists them, and `IsKnownAction` rejects an invented one. Results:
`ResultSuccess`, `ResultDenied`, `ResultFailed`. `PlatformScope` is `"platform"`;
`GenesisHash` is 32 zero bytes as hex.

Canonical encoding (§7) is fixed and must not change without a `canon_version` marker and
a migration:

- `FormatTimestamp` → `2006-01-02T15:04:05.000000Z`, **UTC, microseconds**. Microseconds,
 not nanoseconds, because `timestamptz` stores microseconds. Hashing nanoseconds at
 write time would make verify recompute a different hash from the stored row.
- `Canonical(e, prevHash) []byte`. Field order `scope, seq, ts, actor, actor_kind, org,
 action, target, source_ip, result, prev_hash`, with `SetEscapeHTML(false)` so a target
 containing `<`, `>` or `&` hashes to the bytes actually stored.
- `Hash(e, prevHash) string`. Lowercase hex of `SHA-256(prev_hash_bytes || canonicalJSON)`.
 The previous hash contributes its ASCII hex bytes.
- `Event.Hash()` is a **method**, not a field, so the hash can never disagree with the
 event it describes.

Append and verify are E3's (`append.go`, `chain.go`, `verify.go`).

---

## `internal/store`. Pools, migrations, base

Two connections by design: migrations run as the **owner** (the only role that can create
schema, roles and grants), serving runs as **`coffer_app`** (owns nothing, no `CREATE`,
cannot rewrite the audit log). `Migrate` opens the owner connection, uses it and closes
it before the runtime pool exists, so the privileged credential is not held for the life
of the process.

`Boot(ctx, cfg, log)` = `Migrate` then `Connect`. `Connect` retries with exponential
backoff and jitter (default 120 s budget) so the server survives a database that is not up
yet; an **auth rejection fails immediately** rather than retrying into a fallback.

`Base` / `NewBase(db)` / `NewBaseFromPool(pool)` give a slice store `Pool()`, `InTx(ctx,
fn func(pgx.Tx) error) error` (rolls back on error or panic, with a fresh context so a
cancelled request cannot leak a connection), `Ping`, `MigrationsApplied`.

`Querier` is the single narrow interface satisfied by both `*pgxpool.Pool` and `pgx.Tx`,
with compile-time assertions. Do not declare a second general-purpose one.

### Migration runner

`//go:embed migrations/*.sql`, sorted by **numeric** prefix. `pg_advisory_lock` on
`0x636f66666572` is taken before anything else, so two containers starting together
serialise and the loser applies nothing. Each file runs in **one transaction** together
with its grant block and its `schema_migrations` row (§12), so a failure part way through
leaves no partial schema.

`schema_migrations(version, applied_at, checksum)` is owned by the **runner**, not by
`0001_init.sql`. The runner must record the row for the very migration that would
otherwise create the table, and creating it in both places made every boot fail with
`42P07` and roll back. A **checksum mismatch on an already-applied version fails the
start**: the file changed, so applying it again could corrupt live data.

The grant/revoke/`ALTER DEFAULT PRIVILEGES` block in `grants.sql` is re-applied on
**every boot**, pending migrations or not, because a `pg_dump --no-owner --no-privileges`
restore brings `schema_migrations` back populated with no `GRANT` statements in it. It
includes `GRANT SELECT ON schema_migrations TO coffer_app`, without which `/readyz` can
never succeed.

The `coffer_app` password is set from `COFFER_APP_DB_PASSWORD` on every boot via
`SELECT format('ALTER ROLE %I PASSWORD %L', $1, $2)` followed by the returned statement:
`ALTER ROLE` cannot take a bind parameter, so PostgreSQL builds the quoted literal and the
password never reaches a log, an error string or a query plan.

---

## `internal/httpapi`. Composition root and server

`NewRouter(deps, authenticator)` builds the API mux, calls `authapi.Register`,
`secretsapi.Register` and `auditapi.Register`, and installs the chain. **It contains no
business route and is frozen**. A slice adds a route by registering it, never by editing
this file. `registerSlices` and `newRootMux` exist so the route-coverage test can resolve
against the real tables.

Chain, outermost first:

1. **request id**. `X-Request-Id` on every response, validated for length and character
  class so a caller-supplied value cannot inject a header or a log line; in the context.
2. **route pattern**. The matched pattern, so logs name the route and not the raw path.
3. **request log**. One JSON line: `method`, `route`, `status`, `duration_ms`,
  `request_id`. Never a body, a header, a token or a value.
4. **panic recovery**. 500 envelope, stack trace logged server-side only.
5. **source IP**. The one resolver, so the login throttle and the audit event agree.
6. **auth**. No credential passes through as anonymous (login needs that); a presented
  credential that does not resolve is rejected here with 401.
7. **denial flush**. Writes one `denied` audit event for a **403 or 404 only, never
  401**: an unauthenticated request has no actor to attribute and letting anonymous
  callers write to the log is free write amplification.

The public surface is `/api/v1` plus `/healthz` and `/readyz`; everything else is the 404
envelope, including a wrong method (`GET /healthz`, `GET /readyz` are method-scoped, so a
`POST` falls to the catch-all). A plain-text 404/405 from the mux is rewritten into the
envelope.

`Serve(ctx, cfg, log)` / `ServeWithOptions(..)`: opens the listener first so a port
conflict fails fast, logs the **effective** bind address and **WARNs when it is not
loopback** (the API is plaintext and expects a TLS-terminating proxy), boots the store,
runs bootstrap, then serves. SIGTERM/SIGINT stop accepting, finish in-flight requests and
return within `ShutdownBudget` (10 s). It never calls `os.Exit`.

`/healthz` → 200 while the process is up; it never touches the database, so an outage does
not get the container restarted. `/readyz` → 200 only when the pool answers `SELECT 1`
**and** every embedded migration version is present, else 503 with
`{"status":"not_ready","reason":"database"}` or `{"status":"not_ready","reason":"migrations"}`. No SQL text, no host, no internal path. A schema problem reached through a working pool
is `migrations`; only a failed ping is `database`.

---

## `internal/testutil`. The harness

`testutil.Require(t)` / `New(t)` connect to `COFFER_TEST_DATABASE_URL`, run migrations,
start an `httptest.Server` around the **real** router, and **skip with `t.Skip` when the
variable is unset**, so `go test ./..` is green on a machine with no database.

There is **no test-only auth seam and no backdoor**. Every token is minted through the real
`POST /api/v1/auth/token`; `NewOrg` creates the org and its owner through the real
platform-admin routes. A test that passes therefore proves the real authentication path
works.

Helpers: `DB()`, `Server()`, `URL()`, `Do(method, path, body, token)`, `MustDo`,
`MintPAT(email, password)`, `PlatformAdminToken(t)`, `NewOrg(t, slug)` → `*Org` with
`AdminToken`, `MemberToken`, `MemberWithGrant`, `ServiceToken`, `NewProject`, `NewEnv`,
`AddMember`, and `DisableOrg`.

The master key and bootstrap password are derived deterministically from the test DSN, so
separate `go test` processes sharing one database agree on the key and the admin password.

---

## `Deps` each slice receives

`httpapi.Deps{DB *store.DB, Audit audit.Writer, Config *config.Config, Log *slog.Logger}`,
copied field-for-field into each slice's own `Deps`. A slice gets no peer's package; all
cross-slice needs go through `audit.Writer`, `reqctx`, `authz`, `httpx` and the `store`
base.

---

## Verification

Run on this host, `go1.27.3`:

```
$ go build ./.. && go vet ./..           # clean, exit 0
$ go test ./internal/httpx ./internal/authz ./internal/config
ok coffer/internal/httpx
ok coffer/internal/authz
ok coffer/internal/config
$ go test ./..                   # every package ok
$ go mod tidy                    # two direct requires: pgx/v5, x/crypto
$ ls -l go.sum                    # 2613 bytes
```

`TestEveryFrozenRouteIsBound` (`internal/httpapi/routes_test.go`) enumerates all **37**
routes from CONTRACTS §4, 20 authapi, 11 secretsapi, 4 auditapi, 2 probes. And resolves
each against the real routing table, asserting it is not the catch-all and is
method-scoped. The table is hand-written, not derived from the slices, so it fails if a
slice drops a route.

Boot verified against a real `postgres:16`: first boot applies `0001`, connects as
`coffer_app` (`rolsuper = f`), `/readyz` 200, `schema_migrations` has version 1; a second
boot applies nothing, preserves data, and leaves exactly one migration row.
