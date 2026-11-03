# Judge 2, claude-c2: E2, E4, E5

What I did: I read criteria.md, SPEC.md (the same as build/SPEC.md), results.jsonl, and the three docs in build/docs (SECURITY.md, ARCHITECTURE.md, DECISIONS.md), plus the parts of CONTRACT.md that the docs defer to. I read the authorization tests in full (`internal/server/api/authz_test.go`, `world_test.go`, `changes_revocation_test.go`) and spot-read the e2e suite (`test/e2e/authz_test.go`, `changes_tokens_test.go`) and `scripts/test.sh`. For every SECURITY.md and ARCHITECTURE.md claim I could check, I went to the named code: `internal/server/{api,audit,crypto,db,app,config}`, `internal/cli`, `migrations/0001_init.sql`, `compose.yaml`, `Dockerfile`, `.gitignore`/`.dockerignore`, `scripts/*.sh`, `.github/workflows/ci.yml`, `.golangci.yml` and `go.mod`. I then compared each claim with the black-box results, looking hardest at the real failures (X10, X16, F18) and at one failure the caller did not adjudicate (A6). I did not run the build or its tests, and I did not modify anything in build/.

## E2: PASS
- **The tests run by default.** `scripts/test.sh` always exports `COFFER_TEST_DATABASE_URL`: it starts a throwaway postgres:16 when the variable is unset, then runs `go test -race ./...`. The `internal/server/api` tests have no build tag. They boot the real server behind httptest on a fresh, randomly named database (`internal/server/testutil`) and skip only when no database URL is set, which test.sh prevents. E1 passed in 107 s, which is consistent with the integration tests actually running. The e2e suite (`//go:build e2e`) runs only with `COFFER_E2E=1`, so I counted it as supporting evidence only.
- **Cross-org 404.** `internal/server/api/authz_test.go` `TestAuthzReadOnly/rule1_invisible_is_404_and_identical`, on a two-org fixture (acme and globex, `world_test.go` `newWorld`):
  - The acme owner and admin request globex projects, envs and secrets, and the globex owner and token request acme's. Each response is compared byte for byte, and on Content-Type, with a genuine missing-resource 404 (`notFoundBody`).
  - `expectAll(... "acme owner -> globex", secretPaths("globex-only","dev"), 404)` covers all 9 secret operations, including PUT, DELETE, rollback and export.
  - Cross-org approve and reject of a change: 404 with the canonical body.
  - Cross-org member PATCH/DELETE, grant PUT, token revoke, token create and env create: all 404.
  - Validation never reveals existence: a bad key or bad body under an invisible project gives 404, not 400.
  - `denials_audited_to_actor_chain_without_existence` checks that org B's probes of a real and a fake acme project produce indistinguishable `authz.denied` events in org B's chain and nothing in org A's chain.
  - The e2e suite repeats this: `test/e2e/authz_test.go` `TestAuthorizationMatrix` (`ownerB` and `pa` columns, every 404 body checked as identical) and `tenant_isolation_same_slug`.
- **Two-person rule.** `authz_test.go` `TestAuthzProtectedAndTwoPerson`:
  - Self-approval returns 403 for both the admin and the owner.
  - An admin cannot approve a change proposed by a service token that admin created, which exercises the `proposed_by_user` check in `changes.go`.
  - A member cannot approve at all.
  - A different owner or admin can approve, and the change applies atomically. Approving again returns 409. A competing change becomes `stale` (409) and shows up under `?status=stale` with an audited `change.stale`.
  - `TestApproveRechecksProposer` (`changes_revocation_test.go`) and `stale_principal_test.go` `TestDemotedApproverCannotApprove` cover approval after the proposer or the approver has lost access.
  - The e2e `changes_tokens_test.go` `TestProtectedEnvChanges` repeats these: "self-approval", "token creator approves ST change" and "ST approves" all return 403.
- **Other §2 rules.** There are also tests for owners and admins (rules 2 and 3), grant levels (4), members (6), service tokens (7), the platform admin (10), revocation (11), self-escalation (12) and the last owner, including a concurrent-demotion race. The black-box S10, S1, S2, S3 and S5 results all pass, which agrees with these tests.

## E4: PASS
- **Required sections present.** SECURITY.md has §1 Assets (9 rows), §2 Actors (10 rows), §3 Trust boundaries (6), §4 Master key handling (generation, storage, startup validation, rotation, loss), §6 Out of scope and §7 Known limitations (16 items). §5 Threats and controls is a bonus.

| Claim (SECURITY.md) | Code check | Result |
|---|---|---|
| Cross-tenant 404 is byte-identical, and the denial is audited in the caller's chain | `api/http.go` deny, authz tests | S1, S2, S3, S5, A2 pass |
| Fixed visibility (404) → permission (403) → validation (400) order; grants re-read on every request | `projects.go` resolution | S5, S6, S7, S8, S18 pass |
| Only owners manage owners; no self-changes; last owner 409 under locks; unknown JSON fields → 400 | `members.go`, `DisallowUnknownFields` | S11, S12, S13 pass |
| Two-person rule on `proposed_by` and `proposed_by_user`; proposer re-checked; head changed → stale | `changes.go:215-245` | S10, F12, F14, A8 pass |
| Service tokens: one project and env, at most 90 d, 403 off secret routes | `tokens.go` (ttl 60..7776000) | S14, S15 pass; S16 error (harness control bug) |
| Platform admin gets 404 on org routes | tests rule10 | S1 pass |
| No auth cache, one query per request; disabled org → 401 | `auth.go:130-184` (single joined SELECT) | S17, S18, S19 pass |
| Lockout 5 per 15 min → 429 even with the right password; identical responses, dummy hash | `auth.go:293-294, 422, 442` | X8, X7 pass |
| Tokens are SHA-256 of 256-bit random values | `crypto.go:110-116` | X6 pass |
| AES-256-GCM, AAD binds org/project/env/key/version; a swapped ciphertext gives 500 and no value | `crypto.go:75-88` | X2 pass |
| Passwords stored as argon2id | `crypto/password.go` | X5 "fail" is a harness false positive: `password_changed_at` is a `timestamptz` column (`0001_init.sql:20`) |
| Hash chain plus verify; truncated tail caught via the chain head | `audit.go:330-401` | A4, A5 pass; A6 fail (see below) |
| App role has no UPDATE/DELETE/TRUNCATE on `audit_events`; triggers block them | `db.go:257`, `0001_init.sql:156-171` | X19 pass |
| Value reads commit `secret.read` before responding | appender | A1 pass |
| Request log has no query strings, headers or bodies; no values, passwords or tokens in audit | `http.go:225-233` | X18, O5, A3, X1 pass; O4 flaky (adjudicated) |
| `nosniff`, `no-store`, CSP `default-src 'none'`, no CORS | `http.go:204-209` | X9 pass |
| 1 MiB body limit (413); 64 KiB headers; timeouts; list bounds of 1000 | `http.go:30,244`, `app.go:175-179`, `admin.go:242` | X12, O10 pass |
| Generic JSON errors, no traces | `http.go:149` | X11 pass |
| Audit strings sanitised (NUL, invalid UTF-8); CLI escapes control and bidi characters | `audit.go:67-82` | X10 fail (see below) |
| Distroless, UID 65532, read-only, `cap_drop ALL`, `no-new-privileges`, DB not published | `compose.yaml`, `Dockerfile` | O2, O9 pass |
| CLI config 0700/0600 written atomically; stdin passwords; redirects not followed; plain-HTTP warning | `cli/config.go:92-135`, `client.go:75`, `auth.go:59-72` | X17, X14, F11 pass |
| Master key: openssl or urandom, 0600 temp file and rename, no overwrite without `--force`; refused if missing, wrong length or placeholder; canary mismatch refused before any change | `init-env.sh:23-83`, `config.go:182-199`, `app.go:74-85` | G3, X3, O8 pass |
| Rotation re-wraps DEKs before ready; idempotent | `db.go:303-372` | X4 pass |
| `.env` git-ignored and excluded from the build context; DB gets only `POSTGRES_*` | `.gitignore`, `.dockerignore`, `compose.yaml` | X1 pass; X16 fail (see below) |
| Supply chain: digest pins, `go mod verify`, govulncheck, golangci (gosec), shellcheck | `ci.yml:33-44`, `.golangci.yml` | X15, E3 pass |
| Limitation: forced password change off by default | `http.go:375`, `config.go:168` | F18 fail (see below) |
| Limitation: password change revokes other PATs | `auth.go:643` | X20 pass |
| Backups hold only ciphertext and hashes | `backup.sh` | O7, X1 pass |

**Contradictions and whether they matter:**
- **X10 (NUL in audit `actor`/`action` filters → 200 with the caller's own rows). Not contradicted.**
  - `handleAudit` runs both filters through `audit.Sanitize`, which strips NUL (`admin.go:303`). So `<own id>\x00` collapses to the caller's own id, and a bare NUL removes the filter.
  - SECURITY.md promises only that "audit strings are sanitised (NUL and invalid UTF-8)", and CONTRACT §(audit list) says outright "`actor` and `action` are sanitised like stored audit strings". The build does what it documents.
  - The nearby promise "malformed slugs and ids are 404 before any SQL runs" (DECISIONS 77) is scoped to path parameters, and audit filters are query filters inside the caller's own chain.
  - No document claims these filters are rejected or 4xx'd, and the result is only the caller's own org rows, so there is no tenant leak.
  - The behaviour is a weak validation choice, but no claim is false.
- **X16 (gitleaks hit on a test-fixture password constant in `test/e2e/helpers_test.go:27`). Not contradicted.** SECURITY.md never says the repository or its history is free of credential-shaped strings. It says `.env` is git-ignored and excluded from the Docker context, and both are true. Its supply-chain row lists govulncheck, gosec and shellcheck, not secret scanning. The constant is a fixture used only against throwaway e2e stacks. It is a real SPEC §6 finding, already scored in X16, and it does not make a SECURITY.md claim false.
- **F18 (must_change_password not enforced). Disclosed, so not contradicted.**
  - §7 "Initial passwords" says: "The forced password change is off by default (`COFFER_REQUIRE_PASSWORD_CHANGE=false`)." The code matches: enforcement is gated on `s.cfg.RequirePasswordChange` (`http.go:375`), the default is false (`config.go:168`, `.env.example:90`), and DECISIONS 35 and 107 record the trade-off.
  - `TestMustChangePassword` (`auth_test.go:217`) shows enforcement works when the flag is on.
  - No document claims enforcement by default. The SPEC P1 is unmet by default, but SECURITY.md is honest about it.
- **A6 (a deleted audit row at seq 2623 is reported as `first_invalid_seq=2623`; the harness wanted 2624). Not adjudicated by the caller; I judge it non-material for E4.**
  - Verification did detect the tampering: the API and CLI both return a non-null `first_invalid_seq`, so the chain is reported invalid.
  - `audit.Verify` reports the missing seq (`expect := prevSeq+1`, `audit.go:358-361`). That matches ARCHITECTURE.md ("checks seq continuity … returns the first invalid `seq`") and CONTRACT §411 ("check that seq = previous seq + 1").
  - SECURITY.md promises detection, not a particular numbering convention for gaps. The harness expected the first row whose `prev_hash` breaks, and both readings are defensible.
- **Wording nits, not material:**
  - §3.4 says `coffer_app` can't "touch" `master_key_check`/`schema_migrations`. The code revokes write access but leaves SELECT (`db.go:258-259`). Readiness needs that SELECT, and the canary is stored wrapped.
  - §7 says `coffer_app` "can UPDATE the `audit_chains` head row". It can also DELETE that row, which is still caught by verify (`audit.go:388-392`).

## E5: PASS
- **DECISIONS.md exists.** It is 35,507 bytes and 153 lines, with 107 numbered decisions in sections from "Platform and stack" to "Round-2 hardening". The decisions are specific and cross-referenced: 35 and 107 cover the forced password change, 76 and 77 sanitising, and 62 NUL in `run`.
- **ARCHITECTURE.md claims checked against the code:**
  - **Packages and dependencies.** The table matches the tree (`cmd/coffer-server`, `internal/server/{app,config,crypto,db,audit,api,testutil}`, `internal/cli`, `test/e2e`). The scripts list matches `scripts/` exactly. The `healthcheck` subcommand exists (`cmd/coffer-server/main.go:24`). The only direct dependencies are pgx/v5 and x/crypto (`go.mod`), and the CLI imports nothing outside the standard library.
  - **Middleware.** Matches `http.go:204-244`: server-generated `X-Request-Id`, nosniff/no-store/Referrer/X-Frame/CSP, no CORS, `MaxBody = 1<<20`, panic recovery, and a log line of method, route, status, duration_ms, request_id and actor.
  - **Ready gate, authentication, resolution.**
    - The ready gate runs before authentication (`http.go:355-370`).
    - Authentication is one joined query over tokens, users, orgs, projects and environments (`auth.go:130-140`), and `last_used_at` is updated at most once a minute (`auth.go:201-217`).
    - The two-person check, proposer re-check and stale-on-head-change happen under row locks (`changes.go:205-314`).
  - **Data model.** The schema matches `0001_init.sql`: CHECKs for platform admin ⇔ no org, token shape and deleted ⇔ NULL ciphertext; ON DELETE CASCADE for tokens and grants; and the change_requests columns. The triggers block UPDATE, DELETE and TRUNCATE (`0001_init.sql:156-171`).
  - **Crypto envelope.** Matches `crypto.go`: the `0x01 || nonce(12) || ct||tag` format and the dek, secret, change and canary AAD strings at lines 75-88. Argon2id uses t=2, p=2, a 32-byte key and a 4-slot semaphore (`password.go:26-41`). Tokens are 32 random bytes in base64url with the `cof_pat_`/`cof_st_` prefixes.
  - **Audit chain.** Matches `audit.go`: a genesis of 64 zeros, `SetEscapeHTML(false)`, microsecond UTC timestamps, the `audit_chains ... FOR UPDATE` lock, and the group-commit `Appender`. Verify runs in a RepeatableRead/ReadOnly transaction (`admin.go:265`) and compares the chain head with the last row (`audit.go:385-399`).
  - **Boot sequence.** Matches `app.go:63-130` in order: migrations under an advisory lock, then the canary check, then app-role setup (password derived from the canary by HMAC, `db.go:189`; 25-connection pool; owner fallback with a warning), then bootstrap and closing the owner pool.
    - `/readyz` uses a 2 s timeout, `SELECT 1` and a 1 s migration cache (`projects.go:83-96`).
    - Shutdown waits 8 s (`app.go:235`).
  - **Deployment.** Matches `compose.yaml` and `Dockerfile`: read-only rootfs, 16m `/tmp` tmpfs, `cap_drop ALL`, `no-new-privileges`, port 127.0.0.1 only, `unless-stopped`, `stop_grace_period 10s`, db `postgres:16` with no ports and only `POSTGRES_*`, golang alpine and distroless nonroot images pinned by digest, and UID 65532.
  - **up.sh.** The flow matches `up.sh` and `lib.sh`: init-env, then db, then `--force-recreate --no-deps server`, then 180 s of readyz polling, then build.sh.
- **Drift found (all minor):**
  1. The file list for `internal/server/api` omits `reauth.go`, which holds the org-row lock helpers and the lock-order comment.
  2. "All tables are in `0001_init.sql`" is not quite true: `schema_migrations` is created by `db.Migrate` (`db.go:109`).
  3. The users row in the schema sketch omits `created_at` and `password_changed_at`, but the sketch defers to CONTRACT §3 for the full column list.

  None of these misstates how a component behaves or how components connect, so none is material.
