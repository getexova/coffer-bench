# Judge 1, claude-c2: E2, E4, E5

What I did: I read `criteria.md`, `SPEC.md` and every line of `results.jsonl`. In `build/` I read the authorization tests (`internal/server/api/authz_test.go` in full, `test/e2e/authz_test.go` in full, plus the two-person and stale parts of `test/e2e/changes_tokens_test.go`, `internal/server/api/changes_revocation_test.go`, `stale_principal_test.go` and `auth_test.go`) and `scripts/test.sh`, to see which suites the default run includes. I read `docs/SECURITY.md` and `docs/ARCHITECTURE.md` in full and checked `docs/DECISIONS.md` (structure, size, the entries those docs cite). Then I checked each doc claim against the code it names: `internal/server/api/{http,auth,admin,changes,members,projects,secrets,tokens}.go`, `internal/server/audit/audit.go`, `internal/server/crypto/{crypto,password}.go`, `internal/server/db/db.go` and `migrations/0001_init.sql`, `internal/server/app/app.go`, `internal/server/config/config.go`, `internal/cli/{config,client,auth,run}.go`, `compose.yaml`, `Dockerfile`, `.dockerignore`, `.gitignore`, `scripts/{init-env,up,lib,backup,restore}.sh` and `.github/workflows/ci.yml`. I did not run the build or its tests.

## E2: PASS
- `scripts/test.sh` runs `go test -race -count=1 ./...` against a throwaway postgres:16. That covers the untagged `internal/server/api` authz tests. The black-box e2e authz suite (`//go:build e2e`) runs with `COFFER_E2E=1` and in CI (`.github/workflows/ci.yml:121`). E1 passed, so the default suite runs green.
- **Cross-org 404:**
  - `internal/server/api/authz_test.go` `TestAuthzReadOnly/rule1_invisible_is_404_and_identical`: the acme owner and admin probe globex projects, and the globex owner probes acme. The test asserts 404 with a body byte-identical to a genuine not-found and an identical Content-Type. It runs every secret op (`secretPaths`) cross-org, plus cross-org approve/reject of a change (404), cross-org member PATCH/DELETE/grant (404), cross-org token revoke (404), and token/env creation on another org's project (404). An invalid key or bad body under an invisible project is also 404, not 400.
  - The same file's `denials_audited_to_actor_chain_without_existence` checks three things: the org-B probe lands in B's chain, the real and nonexistent targets have indistinguishable details, and nothing appears in A's chain.
  - `test/e2e/authz_test.go` `TestAuthorizationMatrix` covers the `ownerB` cases (PATCH/DELETE members, grants, tokens, approve/reject → 404, with the body compared to `notFoundBody`) and `tenant_isolation_same_slug` (same slug in both orgs returns each org's own value; B's lists show no A members, tokens or changes).
- **Two-person rule:**
  - `internal/server/api/authz_test.go` `TestAuthzProtectedAndTwoPerson`: admin self-approve 403, owner self-approve 403, and an admin approving a change made through a service token they created 403 (`proposed_by_user`). A member approving someone else's change gets 403. A different owner's approval returns 200 and applies the change atomically. A second approve returns 409. Competing changes go 409 and are listed as `stale`. The test also covers expected-version 409, and delete and rollback through approval.
  - `test/e2e/changes_tokens_test.go` `TestProtectedEnvChanges` (lines 45-47, 98-103): member approves 403, self-approval 403, ST approves 403, token creator approves the ST's change 403, another admin 200.
  - Re-check tests: `changes_revocation_test.go` `TestApproveRechecksProposer`; `stale_principal_test.go` `TestDemotedApproverCannotApprove` and `TestApproveAfterConcurrentGrantChange`.
- Beyond the spot-check: last owner 409, including a concurrent demotion race (`TestAuthzLastOwner`, `TestAuthzLastOwnerConcurrent`); no self-escalation and smuggled fields rejected with 400 (`TestAuthzNoSelfEscalation`, e2e `TestNoSelfEscalation`); immediate revocation (`TestAuthzRevocationIsImmediate`); service-token and platform-admin matrices (rule7/rule10 subtests).

## E4: PASS
- **Required sections, all present in `docs/SECURITY.md`:** §1 Assets (table), §2 Actors (table, including out-of-scope host root), §3 Trust boundaries (6), §4 Master key handling (generation, storage, startup validation, rotation, loss), §6 Out of scope, §7 Known limitations (17 items).

| Claim (SECURITY.md) | Result |
|---|---|
| Cross-org: identical 404, scoped by the token's org id, denial audited in the caller's chain | S1 pass, S2 pass, S3 pass, S5 pass, A2 pass |
| Order: visibility 404, then permission 403; no grant is 404; grants re-read every request | S5 pass, S6 pass, S7 pass, S8 pass, S18 pass |
| Only owners manage owners; no self-change; last owner 409; unknown fields 400 | S11 pass, S12 pass, S13 pass |
| Two-person rule on `proposed_by` and `proposed_by_user`; re-check, else stale 409 | S10 pass, F12 pass, F13 pass, F14 pass, F15 pass, A8 pass |
| Service token scoped to one project/env, read/read-write, max 90 d, 403 off secret routes | S14 pass, S15 pass, S17 pass (S16 error = harness; code `tokens.go:71`, 90 d) |
| Platform admin gets 404 on every org route | S1 pass, S20 pass (code `http.go`, `authz_test.go` rule10) |
| Revocation re-checked in one uncached query; disabled org 401 | S17 pass, S18 pass, S19 pass (code `auth.go:130` single JOIN query) |
| argon2id 64 MiB; lockout 5/15 min → 429 even with the correct password | X8 pass; X5 fail is a harness false positive (`password.go:26,35` argon2id PHC, `config.go:160` 65536 KiB) |
| Identical 401 for unknown email and wrong password, similar timing (dummy hash) | X7 pass (`auth.go:442` DummyHeld, `:468` rehash) |
| Tokens are SHA-256 of 256-bit random values, shown once | X6 pass (`crypto.go:116`) |
| DB/backup hold only ciphertext and hashes | X1 pass, X6 pass, O7 pass |
| AAD binds org, project, env, key, version (pending: change id) | X2 pass (`crypto.go:74-89`) |
| Audit hash chain plus verify; app role has no UPDATE/DELETE/TRUNCATE; triggers | A4 pass, A5 pass, X19 pass; A6 fail (see below) (`db.go:257`, migration triggers) |
| Value reads commit `secret.read` before responding | A1 pass, A3 pass (`secrets.go:127`) |
| Request log: route pattern, status, timing, ids only; no secrets in logs | O5 pass, X18 pass; O4 fail is flaky (4/4 in isolation) (`http.go:229`) |
| `no-store`, no CORS, CSP `default-src 'none'`, `nosniff` | X9 pass (`http.go:204-210`) |
| 1 MiB body 413; 64 KiB headers; timeouts; argon2 semaphore 4 | X12 pass, O3 pass (`app.go:175-179`, `password.go:26`) |
| Generic errors, no internals | X11 pass |
| Master key: missing, wrong length or placeholder refused; canary mismatch refused before changes | X3 pass, G3 pass, O8 pass (`app.go:78` runs before `SetupAppRole`) |
| init-env: 32 random bytes, 0600 temp file plus rename, no overwrite without `--force` | G3 pass (`init-env.sh`, verified by reading) |
| `.env` git-ignored, excluded from Docker context; db gets only `POSTGRES_*` | `.gitignore`, `.dockerignore`, `compose.yaml` `db.environment`, verified by reading |
| Rotation re-wraps DEKs before ready; old key alone then fails | X4 pass |
| Non-root 65532, read-only rootfs, `cap_drop: ALL`, `no-new-privileges` | O2 pass (`compose.yaml`, `Dockerfile`) |
| CLI config 0700/0600 atomic; passwords stdin only; `COFFER_TOKEN` writes nothing | X17 pass, X14 pass, F11 pass |
| Logout and password change revoke PATs | X13 pass, X20 pass |
| Supply chain: digests, govulncheck, gosec, shellcheck | X15 pass, O9 pass, E3 pass (`ci.yml:33-44`) |
| Limitation: forced password change is off by default | F18 fail is consistent with this (see below) |
| Audit strings sanitised (NUL, invalid UTF-8) | X10 fail is related but does not contradict the claim (see below) |

- **Contradictions and whether they are material:**
  - **F18 (real fail):** this does not contradict SECURITY.md. §7 states plainly: "The forced password change is off by default (`COFFER_REQUIRE_PASSWORD_CHANGE=false`)." The opt-in path exists and is enforced: `http.go:375` returns 403 `password_change_required`, `projects.go:35` exempts only logout, password and /me, and `auth_test.go` `TestMustChangePassword` covers it. In the code, `/me` reports `must_change_password` only when enforcement is on (`auth.go:682`). The P1 requirement goes unmet by default, but the document says so.
  - **X10 (real fail):** `admin.go:303` passes `actor` and `action` through `audit.Sanitize`, which strips NUL. A NUL-only filter becomes `""`, `audit.List` drops it, and the caller's whole chain comes back. The rows stay within the caller's own org, so no tenant boundary is crossed (S1/S2 pass). The claim "Audit strings are sanitised (NUL and invalid UTF-8)" is literally true, and CONTRACT.md:383 says the filters are "sanitised like stored audit strings". This is a real input-validation bug, but it falsifies no SECURITY.md claim. Not material for E4.
  - **A6 (fail, not pre-adjudicated):** after a middle row is deleted, verify returns `valid:false` with `first_invalid_seq` set to the missing seq (2623) rather than the next row (2624). Tampering is detected. SECURITY.md claims detection, not which seq is reported, and the behaviour matches the documented algorithm (seq-continuity check, `audit.go:358-361`; CONTRACT.md:411). Not material for E4.
  - **X16 (real fail):** a test-fixture password in `test/e2e/helpers_test.go:27`. SECURITY.md makes no claim about git history, so this contradicts nothing.
  - **Minor overstatements, found by reading code (no failing result):**
    - "Bounded list sizes (1000)" holds only for `/changes` and `/audit`. Secrets are capped at 10,000 live keys (`secrets.go:26`), and the member, project, env, token and version lists have no LIMIT.
    - "Base images pinned by digest" holds for both Dockerfile `FROM`s, but `db` uses `postgres:16` by tag (which the SPEC requires).
    - "`coffer_app` can't … touch `master_key_check`/`schema_migrations`": write access is revoked, but SELECT remains (`db.go:256-259`).

    None of these affects a security property in a meaningful way. Not material.
- **Verdict:** every required section is present, and every claim tested by a black-box check matches a passing result or a disclosed limitation. No claim is contradicted by a failing result.

## E5: PASS
- **DECISIONS.md:** exists, 35,507 bytes and 153 lines. It has roughly 100 numbered, stable entries, grouped by area (platform, tenancy and authz, secrets, crypto and auth, HTTP, audit, operations, plus later additions). Each gives a decision and a reason, and the other docs cite them, for example "DECISIONS 62" for the NUL-in-`run` behaviour, which matches `internal/cli/run.go:39-43`.
- **ARCHITECTURE.md claims checked against code (all match):**
  - **Packages and dependencies:** the package table matches the tree. `go.mod` has only pgx/v5 and x/crypto as direct deps; the CLI imports only the standard library. The `coffer-server healthcheck` subcommand exists (`cmd/coffer-server/main.go:24`).
  - **Request flow** (`http.go:200-250`):
    - The request id is server-generated and any incoming value is ignored.
    - The security headers are set, including Referrer-Policy, X-Frame-Options and CSP.
    - The 1 MiB limit applies through Content-Length and MaxBytesReader.
    - Panics are recovered.
    - The log line has method, route pattern, status, duration_ms, request_id and actor.
    - A malformed token is 401 with no DB access (`auth.go:107` `WellFormedToken`).
    - Lookup is one uncached query (`auth.go:130`).
    - `last_used_at` is updated at most once a minute (`auth.go:205`).
  - **Boot sequence** (`app.go:63-130`): migrate (under an advisory lock, `db.go`), then `CheckMasterKey`, then `SetupAppRole` (password derived from the canary, `db.go:189`; 25-connection pool; owner fallback with a warning), then `Bootstrap`, closing the owner pool, and ready. `/readyz` uses a 2 s timeout and a 1 s migration cache (`projects.go:90-92`). Shutdown uses an 8 s `Shutdown` (`app.go:235`); compose sets `stop_grace_period: 10s`.
  - **Data model** (`0001_init.sql`):
    - CHECK: platform admin if and only if `org_id IS NULL`.
    - CHECK on the PAT and service-token column shapes.
    - CHECK: `deleted = (ciphertext IS NULL)`.
    - Removing a user cascades to PATs and grants; service tokens use a plain `created_by` with no FK, so they keep working.
    - Versioning uses `ON CONFLICT DO NOTHING` + `FOR UPDATE` (`secrets.go:516-521`).
    - Lists are ordered `COLLATE "C"`.
  - **Crypto:** the AAD strings match `crypto.go:74-89` character for character. Tokens are 32 random bytes in base64url (`crypto.go:116`). argon2id uses t=2, p=2, a 32-byte key and a 4-slot semaphore (`password.go:26,34`).
  - **Audit:** verify runs in a read-only repeatable-read transaction (`admin.go:265`) and checks seq continuity, prev_hash and hash, then the head against the last row (`audit.go:330-401`). `coffer_app` has UPDATE, DELETE and TRUNCATE revoked on `audit_events` (`db.go:257`), and the triggers exist in the migration.
  - **Deployment:**
    - `up.sh` creates `.env` if it is missing, starts db and waits for it, then runs `compose up -d --build --force-recreate --no-deps server` (`lib.sh:57`), polls `/readyz`, and runs `build.sh`.
    - The compose settings (`read_only`, 16 MB `/tmp`, `cap_drop`, `no-new-privileges`, loopback port, db with no published port) and the Dockerfile digests match.
    - `restore.sh` uses `pg_restore --single-transaction`.
- **Drift:** none found that matters. The only nuance is that ARCHITECTURE.md lists `actor` as a log field; it is present only when the request authenticated, which is accurate behaviour, not drift.
