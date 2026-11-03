# Coffer acceptance suite (HIDDEN — never shown to a builder)

Black-box only: a clean clone of the final commit, the README, `./bin/coffer`, the HTTP API in SPEC §7.2, `psql` / `pg_dump` against the `db` container, and container logs. Never read or edit the builder's source to make a check pass.

**Points.** P0 = 2, P1 = 1. **⛔ = ship-blocker**: one failure caps the verdict at NOT SHIPPABLE regardless of score.
Where SPEC rules overlap (e.g. a member asking for a token on a project they cannot see), accept 403 **or** 404. Any 500 anywhere is a fail for that check.

## Fixture (built through the CLI as part of F1)

- Platform admin `root@bench.test` (from `init-env.sh`).
- Orgs `acme` (owner `owner@acme.test`) and `globex` (owner `owner@globex.test`).
- acme users: `admin@`, `admin2@` (admin); `writer@`, `reader@`, `viewer@`, `nogrant@` (member).
- acme projects: `api` (envs `dev`, `prod --protected`), `web` (env `dev`). Grants on `api`: writer/reader/viewer at their levels; `nogrant` none.
- globex: project **`api`** with envs `dev`, `prod` — slugs deliberately collide with acme.
- Canaries: every secret value is a unique 40-char random string; record them all. Plant one per env plus `MULTI` (contains `"`, `\`, `$HOME`, `\n`, `\r\n`, emoji, a NUL-free 0x01 byte).
- Tokens in acme: `T_dev_r` (api/dev read), `T_dev_rw` (api/dev read-write), `T_prod_rw` (api/prod read-write), `T_exp` (api/dev, ttl 1m, wait it out), `T_rev` (api/dev, revoked).

## G — Gate (not scored; decides strict vs assisted)

- **G1** Fresh clone, a fresh OS user, README quickstart verbatim, no edits → `secrets get` works in ≤ 30 min of grader time. Strict pass or fail.
- **G2** `up.sh` returns 0 within 180 s and `/readyz` = 200.
- **G3** `init-env.sh` writes a real random master key; starting with the `.env.example` placeholder key → server refuses (⛔ if it boots).
- **Assisted lane.** If G1 fails, the grader may make ONE README-level fix (a missing prerequisite or a typo'd command, never source code), records it, and scores as *assisted*. If that is not enough, every runtime check scores 0.

## F — Functional (P0 unless marked)

- **F1** Fixture builds entirely via CLI; every command exits 0 (except protected writes = 7).
- **F2** set → get byte-exact for: empty string; 1 byte; exactly 65,536 bytes; `MULTI`; stdin input ending in `\n` (newline preserved).
- **F3** 65,537 bytes → exit 6, nothing stored. Bad keys (`lower`, `1ABC`, `A-B`, 129 chars) → exit 6.
- **F4** history shows v1..n; `get --version k` returns the old value; `rollback --to 1` creates v(n+1) = v1's value.
- **F5** delete → get exit 5; history shows a tombstone; set again → next version number, not 1.
- **F6** `--expect-version` stale → exit 8, value unchanged; correct → succeeds.
- **F7** 20 parallel unconditional sets on one key → exactly 20 new versions, contiguous, no duplicates; final value equals the highest version's value.
- **F8** `export --format dotenv` is byte-exact to the §7.1 escaping rule (compare against a reference encoder over `MULTI`); sorted; LF; trailing newline.
- **F9** `export --format json` round-trips through `jq` to the exact values.
- **F10** `run`: secrets visible in the child; a secret overrides an existing env var; child `exit 42` → 42; child killed by SIGTERM → 143; SIGTERM sent to `coffer run` reaches the child; stdin passes through.
- **F11** `COFFER_TOKEN=$T_dev_r coffer secrets get …` works with an empty `HOME` and creates no config file.
- **F12** Protected write by `writer` → exit 7 + change id; value unchanged; `admin` approves → value updated; the audit shows proposer and approver.
- **F13** reject → value unchanged, status `rejected`.
- **F14** Two pending CRs on one key; approve the first, then the second → 409 / exit 8, status `stale`, value = first.
- **F15** Protected delete and protected rollback both go through change requests.
- **F16** `--json` output parses for list, get, history, token create, change list, audit list.
- **F17** Data survives `down.sh` + `up.sh`.
- **F18 (P1)** Created user must change password before any other call; `passwd` works.

## S — Separation and authorization

**Cross-tenant ⛔** (the most important block in the suite)
- **S1** ⛔ `owner@globex` → acme's `web` project and every route under it → 404, body byte-identical to a nonexistent project's 404.
- **S2** ⛔ The colliding slug: globex `secrets get KEY -p api -e dev` returns only globex values; no acme canary in any globex response or export, ever.
- **S3** ⛔ IDOR with acme IDs, called by `owner@globex`: approve/reject an acme change id; `DELETE` an acme token id; `PATCH`/`DELETE` an acme user id; `PUT` a grant for an acme user → all 404, acme state unchanged (verify afterwards).
- **S4** ⛔ Platform admin → every org-scoped route (secrets, members, tokens, audit, changes) → 404. Only `/admin/*` works.

**Role matrix** — run the full actor × operation matrix (actors: owner, admin, writer, reader, viewer, nogrant, globex owner, platform admin, each fixture token, anonymous; ops: list, get, export, run, set, delete, rollback, approve, member/grant/token management, audit list). Expected cells come from SPEC §2.
- **S5** ⛔ nogrant → `api` → 404 everywhere.
- **S6** viewer: list 200, values 403, writes 403.
- **S7** reader: get/export/run work; writes 403.
- **S8** writer: dev writes 200; prod → 202.
- **S9** ⛔ Members: approve, member/grant/token management, audit list → 403.
- **S10** ⛔ Two-person rule: the proposer cannot approve their own CR (403) as writer, as admin, **and as owner**; `admin2` can.
- **S11** Owner-only powers: admin cannot create, promote, demote or remove an owner (403).
- **S12** Last owner cannot demote or remove themselves → 409.
- **S13** ⛔ Self-escalation: each member PATCHes their own role and grants, and POSTs to `/members` and `/tokens`, with extra fields (`role:"owner"`, `org_id`, `is_platform_admin`, `level:"writer"`) → rejected or ignored; re-read state to prove nothing changed.

**Token scope**
- **S14** ⛔ `T_dev_rw` → api/prod, the web project, any globex path → 404. `T_dev_r` → writes 403.
- **S15** `T_prod_rw` set → 202 (a token cannot skip approval).
- **S16** ⛔ Any service token → approve, members, `POST /tokens`, audit, `/auth/token` → 403 (or 401).

**Revocation**
- **S17** ⛔ Revoked and expired tokens → 401 on the next request (≤ 1 s).
- **S18** Removed user's PAT → 401; a lowered grant takes effect on the next request; a revoked grant → 404.
- **S19** Disabled org: all its PATs and tokens → 401/403; the other org is unaffected.
- **S20** No unauthenticated route besides `/healthz`, `/readyz` and `/auth/token`; any path outside `/api/v1` and the health routes → 404. Malformed, tampered or wrong-prefix bearers → 401, never 500.

## X — Security

- **X1** ⛔ **Canary sweep.** After the full suite, grep every canary, every token and every password across: `pg_dumpall` of `db`; all container logs; every `backup.sh` output; the CLI config dir (only its own token allowed). Any hit = fail.
- **X2** ⛔ **AAD binding.** In SQL, copy one secret's ciphertext row onto another key, another env, and an acme→globex row. Each read must error. Returning any value at all = fail.
- **X3** Placeholder, short, or missing master key → refuse to start (overlaps G3; scored here).
- **X4** Rotation: restart with `PREVIOUS=old MASTER=new` → everything readable; restart with `MASTER=new` alone → still readable; restart with `MASTER=old` alone → fails closed (refuses or errors), never garbage.
- **X5** Password hashes in the dump are `$argon2id$`, or `$2b$` with cost ≥ 12, or scrypt. An 11-char password is rejected.
- **X6** ⛔ Tokens are not in the dump in plaintext (covered by X1, scored separately because it is the common miss).
- **X7** Unknown email vs wrong password: same status, byte-identical body; median latency over 30 tries within 25%.
- **X8** 5 failures → 429 even with the correct password; another account is unaffected.
- **X9** Every `/api/v1` response, including 401/404/413 and malformed-JSON errors: `Content-Type: application/json` (dotenv export may be `text/plain`), `nosniff`, `Cache-Control: no-store`. CORS preflight from `https://evil.test` → no `Access-Control-Allow-Origin`, never reflected, never `*`.
- **X10** ⛔ Injection: `' OR 1=1--`, `"; DROP TABLE`, `../../etc/passwd`, `%00`, unicode homoglyphs in every path param, query param and JSON field → 4xx, no 500, no foreign data.
- **X11** Errors: 400/404/405/413/malformed JSON all use the `{"error":{code,message}}` shape. No response body contains `Traceback`, `at ` with a file path, `.ts:`/`.py:`/`.go:`, `SELECT`, or a stack.
- **X12** 2 MiB body → 413 in < 1 s.
- **X13** Logout revokes the PAT on the server (reuse → 401).
- **X14** Passwords never appear in argv: `ps` during `login`, `member add` and `admin org create`.
- **X15** `osv-scanner` over lockfiles: 0 High/Critical. Lockfiles exist.
- **X16** `gitleaks` across full history: no findings other than `.env.example` placeholders.
- **X17** CLI config: dir 0700, file 0600.
- **X18** No secret value or token in any URL: run the whole F block through `mitmdump` as a reverse proxy (`COFFER_URL` pointed at it) and grep every captured URL and query string, plus the server's request logs.
- **X19 (P1)** Audit rows: `UPDATE`/`DELETE` as the server's DB role → permission denied.
- **X20 (P1)** Password change revokes the user's other PATs.

## A — Audit

- **A1** ⛔ Every get (including `--version`), export and run, every set, delete, rollback, approve, reject, member/role/grant/token change and login (success and fail) emits an event with actor, target and result. Export of n keys → n read events.
- **A2** Denied requests (403/404) are logged as `denied` in the **actor's** org log; the cross-org attempt does not reveal the target in acme's log. Unauthenticated failed logins appear in `admin audit list`.
- **A3** ⛔ No canary, token or password in any audit row (subset of X1, scored separately).
- **A4** `audit verify` passes on the untouched log; `admin audit verify` passes on the platform log.
- **A5** ⛔ Tamper: `UPDATE` one mid-chain row's target via psql (as postgres superuser) → `verify` exits 9 with `first_invalid_seq` = that row.
- **A6** Delete one mid-chain row → `verify` exits 9 at the following sequence.
- **A7** Filters `--actor`, `--action`, `--since`, `--limit` return the correct subsets.
- **A8** Change-request lifecycle (created, approved, rejected, stale) is all audited.

## O — Operations

- **O1** `/healthz` 200; stop `db` → `/readyz` 503 within 10 s; start `db` → 200 without restarting `server`.
- **O2** `server` container user is not uid 0.
- **O3** SIGTERM during 20 in-flight requests → every request completes or gets a clean error; the process exits ≤ 10 s.
- **O4** Request logs are JSON lines with method, route, status, `duration_ms`, `request_id`; `X-Request-Id` matches.
- **O5** ⛔ No `Authorization`, cookie, token, password or value in the logs (subset of X1, scored separately).
- **O6** 3× `down`/`up` → migrations idempotent, no errors, data intact.
- **O7** ⛔ backup → wipe the volume → restore into a fresh stack with the same key → every secret, every version and the whole audit log intact; `audit verify` passes.
- **O8** Unset each required env var → non-zero exit, message names it.
- **O9** No `:latest` and no untagged image in compose or Dockerfiles (`postgres:16` is mandated by the spec and passes).
- **O10 (P1)** List over 1,000 secrets p95 < 300 ms; 50 concurrent gets p95 < 200 ms.

## E — Engineering

- **E1** `./scripts/test.sh` exits 0 on a clean clone.
- **E2** Its tests include authorization tests. Spot-check: they exercise cross-org 404 and the two-person rule.
- **E3** CI workflow runs lint, test and build.
- **E4** `docs/SECURITY.md` names assets, actors, trust boundaries, master-key handling and known limitations, and the claims are true of the build.
- **E5** `ARCHITECTURE.md` matches the code; `DECISIONS.md` exists.
- **E6 (P1)** More than 1 commit; the history is not a single dump.

## Ship-blockers (⛔)

G3, S1, S2, S3, S4, S5, S9, S10, S13, S14, S16, S17, X1, X2, X6, X10, A1, A3, A5, O5, O7.

## Verdict

- **SHIP**: G1 strict, 0 blockers, ≥ 90% of P0 points.
- **FIX-THEN-SHIP**: 0 blockers and ≥ 75% of P0 points (G1 may be assisted).
- **NOT SHIPPABLE**: anything else.

Report per arm: verdict; blockers failed (IDs); P0 % and total score; strict or assisted; the per-check table with one line of evidence for each fail. Then the unscored run metrics from PROTOCOL.md.

## Grader integrity

- Run the identical suite, commands and order on both arms.
- Grade **blinded**: the repos are renamed `build-1` / `build-2` by someone else (or by a coin flip recorded before grading).
- If a check fails on **both** arms, inspect whether the spec or the check is at fault **before** unblinding. Void it for both if so, and record why.
- Never fix builder code. The only intervention is the one assisted-lane README fix.
- Best: validate the suite's harness against a deliberately broken reference before trusting a pass, so a grader bug cannot pass both arms.
