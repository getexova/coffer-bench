# Coffer — Security review (reviewer report)

Reviewed against `SPEC.md`, `docs/CONTRACTS.md` (frozen contracts) and `docs/DECISIONS.md`.
All findings below come from commands I actually ran against a running stack, or from source
reads named in the finding. Nothing is inferred from tests passing.

**Verdict: NEEDS WORK** — two blocking defects (service-token proposals 500, ws-stack
platform chain carries prior-session tamper residue that down/up does not heal; plus a
contract deviation on the coffer_app password reset). Everything else I exercised passed.

---

## Core job (first, as ordered)

| # | Check | Status | Evidence |
|---|---|---|---|
| 1 | Fresh clone has `cmd/coffer` (`.gitignore` bug stays fixed) | **reached** | Cloned `/home/coffer/ws` → `/tmp/coffer-clone`; `cmd/coffer/` present with 20+ Go files incl. `main.go`, `admin.go`, `secrets.go`. Also re-cloned later to `/tmp/coffer-clone2` — same. |
| 2 | Ten README quickstart commands verbatim, one shell session | **reached** | All ten run in one session in `/tmp/coffer-clone`; every step exited 0. Step 10 piped to `od -c` showed exactly the 17 bytes `hello-from-coffer` and no `\n` (`wc -c` = 17). |
| 3 | Second organization isolation | **reached** | Created org `beta` via platform admin, set `BETAKEY` in `proj-beta/dev`. From the beta owner (after clearing the P1 password gate), 14 cross-org probes (list/get/versions/version-N/export/members on `demo`, PUT/DELETE/POST on GREETING) all returned **404** with `{"error":{"code":"not_found","message":"not found"}}`. That body is **byte-identical** (`cmp` clean, same md5) to the 404 for a nonexistent key in the beta owner's *own* org. Cross-org probes for another member (`member2`) on list/get also byte-identical to nonexistent. |

Notes: on the very first isolation pass the beta owner got 403 `password_change_required` on
`projects`, `members`, `audit` while `audit`/`audit/verify`/`changes` returned 200 — the P1
gate exempts exactly the routes the DECISIONS doc says it does (auth/password, logout) plus
apparently audit/verify/changes GETs. The gate is P1; the exemption list is documented there.

---

## Environment

- `go1.27.3`, `podman 5.8.9`, `podman-compose 1.6.0` (docker is the podman shim) — as briefed.
- Port 8420 was **free** when I started (other stacks run on other host ports); the
  "address already in use" remediation was not needed, but I confirmed the leftover-container
  inventory (`podman ps -a`) several times and never edited the repo for ports.
- Clone stack (`coffer-clone*`) used for most testing on a **clean clone**; the pre-existing
  `ws` stack was left running, untouched except a readyz/login probe, and restored to running.
- `./scripts/init-env.sh` → fresh key + admin password printed once; `./scripts/up.sh` →
  exit 0 in ~1 s; `./scripts/build.sh` → `./bin/coffer` (18,563,419 bytes, host toolchain path).
- At the end, clone2 stack brought down via `./scripts/down.sh` (volume kept, as designed).

### Two environmental events you should know about (not product bugs)
1. **The pre-existing `ws` stack's platform audit chain is INVALID at seq 2.** Row 2 has
   `action='x'`, which is not a frozen action name — residue of an earlier session's tamper
   test that was never undone (down/up keeps the volume). My own fresh-clone chain verified
   valid, and I ran the full tamper test myself in the clean stack and undid it exactly.
   **Someone must reset the ws stack's data volume (or repair seq 2) before anything grades
   against that stack.** See blocking finding B2.
2. **`/tmp/coffer-clone` was deleted externally mid-run** (the directory went empty at
   20:21 while containers kept running). I re-cloned to `/tmp/coffer-clone2` and continued;
   the rotation test lost its stack state the first time and was redone cleanly.

---

## Coverage — every area from the brief, with what I ran

### Authorization (§2) — verified from the wrong side, against the running stack
- Member, no grant: `GET/PUT/DELETE` on project/env/secret/export → **404**, byte-identical to
  nonexistent (`cmp` clean for both single-key GET and list). ✅
- Viewer (member + viewer grant): list 200 with `{key,version,updated_at,updated_by}` only
  (verified no `value` field in listing); get value **403**; export **403**; put **403**;
  versions-list 200 (metadata); `run` CLI exit **4** (forbidden). ✅
- Reader (member + reader grant): get value **200**; put **403**; delete **403**; rollback 403
  (on protected env); export 200; run OK. ✅
- Writer (member + writer grant): set/delete/rollback all 200. ✅
- Admin role: members/tokens/audit 200; can create member; **403 creating an owner**
  (`member add --role owner`); **403/409** touching owners (PATCH owner2 → 403-without-grant,
  DELETE owner2 → 403); approve/reject changes 200. ✅
- Member routes (members, grants, tokens, audit): plain member gets **403** on GET and POST,
  including `PATCH /members/{self}` (**403**, authz-before-validation per DECISIONS) and
  self-grant PUT (403). ✅
- Platform admin: `GET me` → 200 `role:platform_admin,organization:null`; every org-scoped
  route (`projects`, `members`, `audit`, `audit/verify`, `tokens`, `changes`) → **404**;
  `/admin/orgs`, `/admin/audit`, `/admin/audit/verify` → **200**. Non-admin on `/admin/*` →
  **403**. ✅
- Owner rules: owner creates owner 201; admin demoting an owner → 403/409; **sole owner
  self-demote → 409** (`the last owner cannot be demoted`); with a second owner present,
  self-demote → **400** (`you cannot change your own role`) — matches DECISIONS (409 checked
  first, then §2.12 400). Owner2 demoting owner1 → 200. Member remove by owner → 200; removed
  user's PAT → 401 on next request. ✅
- 404 "not visible" vs "does not exist": byte-identical bodies confirmed by `cmp` in three
  separate actor contexts (beta owner cross-org, member2 no-grant, list endpoints). ✅
- Service tokens: read token — get/export/run 200 in scope; put 403; other env → 404;
  other project → 404; nonexistent in scope → 404. read-write token — set/delete on
  **non-protected** env 200. Management routes (members, audit, tokens POST, changes) → 403.
  `GET /me` 200 with scope only (`organization:null, role:service_token`, no org/user).
  **Blocking exception on protected-env writes — see B1.** ⚠️

### Revocation within 1 second (§2.11)
- `grep -rn "cache\|Cache" internal/` → only comments and the `Cache-Control` header + the
  rate limiter's in-memory buckets; **no authorization cache**. The single `ResolveTokenSQL`
  query joins token→user→org and is the only credential path. ✅
- Expiry is `st.expires_at > now()` **in SQL** (`internal/store/auth/tokens.go:95`) — database
  clock, not Go. ✅
- Revoke: created token, `DELETE /tokens/{id}` → 200; the very next GET → **401**; measured
  delta ≈15 ms. Grant revoke → next request 404 within the same second. Member remove → 401.
  Org disable (beta) → 401. ✅

### Secrets (§3)
- Set → version 1; set again → 2; delete → version 3 tombstone; get → 404; history shows
  `deleted:true` with no value; next set → **4**; rollback to 1 → **5**; get past version
  works; get tombstone → 404. ✅
- `grep -rn "MAX(" internal/` → no `MAX(version)+1` anywhere; allocator is
  `UPDATE … SET current_version = current_version+1 … RETURNING` (CONTRACTS §9). ✅
- 30 parallel unconditional sets on one key: all 30 got **distinct, gapless** versions 1–30
  (`vs == range(min,max+1)` verified in Python); history holds 30 rows. ✅
- Empty value: CLI set of 0 bytes → version 1, get → 0 bytes (`wc -c` = 0). ✅
- 65,537 bytes → CLI exit **6** (`invalid value`); via API 400. 65,536 bytes → 200, round-trips
  exactly. ✅
- Expected-version mismatch → 409 (API `{"error":{"code":"conflict",…}}`, CLI exit 8). ✅
- Listing format verified: exactly `{key, version, updated_at, updated_by}`, never values. ✅

### Two-person rule (§2.9)
- Write to protected env → **202** `{"status":"pending","change_id":…}`; CLI prints the change
  id and exits **7**; `--json` prints exactly `{"change_id":…,"status":"pending"}`. ✅
- Self-approval → **403** (checked before state change — request still pending afterwards). ✅
- Second owner approves → 200, value applied atomically, get returns the approved value.
  Admin approves → 200 (allowed per §2.3). Member proposer approval attempt → 403. Service
  token approve → 403. Double-approve → **409** `change already resolved`. ✅
- Stale: propose, approve a second change on the same key, then approve the first → **409**
  `change is stale`, and the change list shows `status:"stale"` with `resolved_at`/`resolver_id`
  set. Delete-op staleness (propose delete, apply a set, approve delete) → 409 stale. ✅
- Reject flow: rejected change leaves the value unchanged. ✅
- **Blocking exception for service-token proposers — see B1.**

### Encryption (§4)
- `cipher.NewGCM` over AES (`internal/crypto/aead.go:18`) → **AES-256-GCM**. ✅
- Per-project data keys in `project_data_keys` (`wrapped_key`, `nonce`, `key_version`), wrapped
  by the master key via `DataKeyAAD`. ✅
- AAD: `internal/crypto/aad.go` — `uvarint(len(part)) || part` per CONTRACTS §5, with
  `SecretAAD(org,project,env,key,version)`, `DataKeyAAD(org,project,key_version)`,
  `ChangeAAD(org,project,env,key,change_id)`. All nonce lengths in the DB are 12 bytes (48/48
  rows sampled). ✅
- **Decisive cross-row test (executed via psql, superuser, my own test data):** copied the
  prod-env ciphertext of `TPKEY` into the dev-env `READERWRITE` latest version → GET returned
  **500 `internal_error` and never a value**; export of that env also 500; list still 200.
  Same-env/different-key swap and cross-env swap → also error, never a value. I then repaired
  the rows by writing fresh versions through the API (no test data left tampered). ✅
- No plaintext at rest: `convert_from(ciphertext,…)` searches for my known values return 0 rows;
  `change_requests.payload_ct` also ciphertext; backup file has zero occurrences of any value.
  ✅
- Master-key gate (ran `coffer server` in the container with overridden env): missing →
  `missing required environment variable COFFER_MASTER_KEY`; 3-byte key → `must decode to
  exactly 32 bytes, got 3`; `.env.example` placeholder → refused. Server booted normally
  afterwards (readyz 200). ✅
- Rotation: on a fresh clone I set `COFFER_MASTER_KEY` to a new key with
  `COFFER_MASTER_KEY_PREVIOUS=<old>` and restarted. Boot logged
  `master key rotated, data_keys_rewrapped:1`, `key_version` stayed 1 (re-wrap, not re-encrypt),
  secrets still decrypted, chain verified; after removing `PREVIOUS` and restarting, values
  still decrypted (old key no longer needed). ✅
  ⚠️ Caveat: my first rotation attempt on the *original* clone appeared to not rotate; the
  clean retest proves the path works. One cause was my own env-editing mistake, and part of
  the anomaly remains unexplained because `/tmp/coffer-clone` was wiped mid-test. I am not
  counting that first attempt as a finding, but flagging it for honesty: the clean run is the
  evidence.

### Audit (§4)
- Every frozen action observed live in `audit_events` for my test orgs: `login.success`,
  `login.failure`, `logout`, `secret.read/write/delete/rollback`, `change.created/approved/
  rejected/stale`, `member.added/removed/role_changed`, `grant.set/revoked`, `token.issued/
  revoked`, `project.created`, `environment.created`, `denied`, and (platform)
  `organization.created/disabled`. `masterkey.rotated` was **not** audited (see Minor M3). ⚠️
- One event per key read: 3 single gets → 3 new `secret.read` rows; export of 7 keys →
  **+7** `secret.read` rows (delta == key count). ✅
- Denials: 403/404 denials are audited (`denied` rows, and per-action `denied` results);
  a bare 401 with a garbage token added **zero** new denial rows (before=33, after=33). ✅
- Chain: `hash = SHA-256(prev_hash_bytes || canonical JSON)` — I recomputed seq 1 and 2 of a
  live scope **independently in Python** using the event.go canonical encoding
  (`{"scope","seq","ts","actor","actor_kind","org","action","target","source_ip","result",
  "prev_hash"}`, `SetEscapeHTML(false)`, timestamps `%06d` microseconds) and got **exact
  matches** for both stored hashes. ✅
- `GET /api/v1/audit/verify` body is exactly `{"valid":bool,"first_invalid_seq":number|null}`
  (verified raw and via key listing). ✅
- **Tamper test executed:** `podman exec … psql -U coffer` `UPDATE audit_events SET
  target='tampered' WHERE seq=1` → verify returned `{"valid":false,"first_invalid_seq":1}` and
  the CLI printed `Audit chain INVALID at sequence 1` with exit **9**. I then restored seq 1's
  original target exactly (verified `valid:true`) — chain left intact. ✅
  ⚠️ Note: `coffer_app` cannot `UPDATE` audit rows (verified: `permission denied`; grants are
  `SELECT,INSERT` only), so the tamper required the superuser as the brief specified.
- No values in audit: grep of `audit_events` for every value I set → 0 rows. ✅
- Anonymous denials (e.g. `GET /` unauthenticated) land in the **platform** log
  (`denied` row with empty actor); platform-admin denials on org routes land there too.
  ✅

### HTTP (§4)
- On 200/403/404/401/404-unknown responses: `Content-Type: application/json`,
  `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, unique `X-Request-Id` per
  response. dotenv export is `text/plain; charset=utf-8` with the other three headers present
  (documented exception). ✅
- No CORS headers on any response (`grep -ic access-control` = 0). ✅
- Body > 1 MiB → **413** `body_too_large` (1,100,000-byte JSON body; smaller valid bodies
  pass). ✅
- Unknown path, wrong method (PATCH /me, POST /healthz, GET /auth/token, DELETE /members,
  PUT on a collection, trailing slash) → **404** with the JSON envelope. ✅
- Error bodies: only `{"error":{"code","message"}}` with generic messages; the 500 body is the
  literal `internal error`; no stack trace, SQL, or internal path in any body I sampled
  (including the AAD-tamper 500s). ✅
- `/healthz` 200 while process up (including while the DB was down); `/readyz` **503**
  `{"reason":"database","status":"not_ready"}` with the db container stopped, and **self-recovered
  to 200** after the db came back. Both live outside `/api/v1`. ✅
- Server request logs are JSON lines with method, route (path values redacted to `{p}` etc.),
  status, `duration_ms`, `request_id`; log scan found no values, tokens, passwords, or
  `Authorization` headers. ✅

### CLI (§7.1)
- `./bin/coffer --help` lists every §7.1 command (login/logout/whoami/passwd, admin org ×5,
  member ×4, grant ×2, project ×2, env ×2, secrets ×8, change ×3, token ×3, audit ×2) plus
  `serve`. ✅
- Exit codes observed: 3 (401), 4 (403), 5 (404), 6 (400 validation incl. oversize value),
  7 (202 pending), 8 (409 conflict), 9 (invalid chain), 10 (429 lockout), 2 (usage,
  bad key format, missing arg), 1 (connection error), 0 success, 127 (`run` with a missing
  binary). ✅
- Piped `secrets get` = exact bytes (17-byte check, 65,536-byte check); on a real PTY (python
  `pty.fork`) output was `value\r\n` — newline appended on TTY only. ✅
- No `--password` flag (`flag provided but not defined: -password`); no positional password;
  no password reaches argv (the login process's `/proc/<pid>/cmdline` shows only `--email`).
  Passwords come from stdin everywhere (login, passwd 2-line, org create, member add). ✅
- Config dir/file modes: `0700` dir, `0600` config.json (checked for both the default HOME and
  an `XDG_CONFIG_HOME` override). `COFFER_TOKEN` set → corrupt config file is neither read nor
  rewritten (verified with a deliberately corrupt config). ✅
- `run`: child inherits stdio; secrets injected (child saw the value; existing parent env
  var overridden by the secret — "secrets win"); child exit code propagates (42), signalled
  child → 128+N (SIGTERM→143 verified; SIGINT→130 verified with a Python child that traps the
  signal and reports receiving SIGINT). Earlier "not forwarded" observations were an artifact
  of my shell harness inheriting `SIG_IGN` for SIGINT, not a product defect. Nothing written
  to disk (no temp files observed). ✅
- `--json` prints exactly one JSON document for whoami/list/export (sorted keys in json
  export); errors to stderr. ✅
- Export escaping verified byte-for-byte: input `a\b"c\nd\re$f` → `ESC2="a\\b\"c\nd\re\$f"`
  — exactly `\`, `"`, newline, CR, `$` escaped, nothing else; keys sorted; LF only; final
  newline. ✅

### Ops (§5)
- `compose.yaml` at repo root with `server` and `db`; `db` is `postgres:16`; works under
  `docker compose` shim (podman-compose 1.6.0) — used throughout. ✅
- `backup.sh FILE` → gzip dump, ciphertext only (plaintext grep = 0); `restore.sh FILE` →
  drops/reloads schema, starts stack; every secret and audit event reproduced; chain verified
  valid after restore; restore prints the exact `./bin/coffer audit verify` line (CONTRACTS
  §13). ✅
- Data survives `down.sh` → `up.sh` (verified twice: GREETING still exact after down/up, and
  after the db-container restart). ✅
- `up.sh` returns 0 only on `/readyz` 200: with the server's host port held by another
  process, up.sh **exited 1 after ~6 s** and printed `--- docker compose logs --tail 40 server`
  (naming the failing dependency with its logs). ✅ (I could not produce a db-failure variant
  of this test without disturbing the shared host; the server-failure path is the one graded
  here.)
- Server container runs as `uid=10001(coffer)` non-root (both clone and ws stacks). ✅
- Base images pinned: `golang:1.27.3-bookworm`, `alpine:3.22@sha256:dc92f0…`, `postgres:16`
  (major-version pin; the two alpine/golang pins are digest-pinned). No `latest`. ✅
- `db` not published to the host (`podman port ws_db_1`/`coffer-clone2_db_1` empty). ✅
- SIGTERM: `podman stop coffer-clone_server_1` → container exited 0 in **1 s** (budget 10 s,
  graceful `shutting down` log line). ✅
- Server connects as `coffer_app`, `degraded:false` (log line). ✅
- Performance: 1,000 secrets listed in ~5–6 ms (p95 of 5 runs); 50 concurrent value reads
  p95 ≈ 160 ms on the quiet host (spec allows 200 ms; one run on a loaded host hit 270 ms —
  borderline, worth a note, not a violation on the quiet numbers). ✅
- Migrations: single row in `schema_migrations`, applied once; re-up idempotent. ✅

### Degraded DB role (CONTRACTS §11)
- `COFFER_ENV=production` + `COFFER_ALLOW_DEGRADED_DB_ROLE=1` + no app password → **refused**,
  naming both variables. ✅
- Neither app password nor flag in non-production → **refused**, naming
  `COFFER_APP_DB_PASSWORD` and the flag. ✅
- Degraded boot in development → boots with a WARN naming the lost isolation. ✅
- **App password "present but rejected" → NOT a failed start. See B3.** ⚠️

### Code & docs
- `docs/SECURITY.md` has sections: Assets, Actors, Trust boundaries, Master key handling,
  Authentication, Authorization, Audit integrity, What is not protected, Known limitations,
  Out of scope, Reporting — covers the required content, and the account-enumeration tradeoff
  is honestly recorded as a known limitation. ✅
- `docs/DECISIONS.md` records the ambiguous calls (404 vs 403 centrally, bare-401 not audited,
  lockout enumeration, no authz cache, self-role-change 400 vs 409 ordering, service-token
  `/me`, restore-does-not-verify, bind-addr rationale, `proposer` attribution for machine
  credentials — note this last one is contradicted by behavior, see B1). ✅
- Smell hunt: no TODO/FIXME/fmt.Print in non-test code; no ignored errors on security paths
  (`_ =` uses are listener.Close and rollback defers); no password/token in any URL; error
  bodies cannot carry internal text (`httpx.Internal` → literal `internal error`); token
  verification is a single indexed query on a unique hash column (no timing-side-channel
  comparator needed since the lookup is the comparison). ✅
- One dead-code trap: `internal/store/secrets/store.go:147` `ServiceTokenCreator` exists
  precisely to attribute machine proposals to the token creator, and is **never called** —
  the live path uses `actorRef()` (token id) instead, which is B1.
- Tests: `./scripts/test.sh` exit 0, full suite runs against a real throwaway postgres:16
  (integration tests are DB-gated by env var but test.sh always provides one — zero silent
  skips in the run I watched; `t.Skip` sites are all guarded with explicit reasons and the
  DB-dependent ones are *not* skipped under test.sh). `go build ./...`, `go vet ./...`,
  `gofmt -l` all clean. CI workflow present (lint+vet+tests+build+govulncheck, pinned action
  versions). Lockfiles committed. No real secret in git history (searched all 13 commits for
  the live master key: 0 hits; `.env` gitignored). ✅

---

## Findings

### Blocking
- **B1 — Service-token write/delete to a protected environment returns 500 instead of 202.**
  File: `internal/api/secretsapi/secrets.go:174-207` (and `common.go:41-48`) —
  `write()`/`remove()` pass `Proposer: actorRef(res.actor)`; for a service token `actorRef`
  yields the **token id** (`tok_…`, `ActorRef.Kind=service`), which violates the
  `change_requests_proposer_id → users(id)` FK. Observed (clone1 and clone2):
  `PUT /projects/demo/envs/prod/secrets/…` with a read-write service token →
  **500 `{"error":{"code":"internal_error","message":"internal error"}}`**, server log:
  `ERROR: insert or update on table "change_requests" violates foreign key constraint
  "change_requests_proposer_id_fkey" (SQLSTATE 23503)`. Same for DELETE on a protected env.
  SPEC §2.8 requires **202** for any write by anyone allowed to write (a read-write service
  token in scope *is* allowed to write), and §2.9's two-person rule is specified for it via
  DECISIONS ("attributed to the user who issued the token. That user then cannot approve
  it, which is the two-person rule working as intended"). `ServiceTokenCreator`
  (`internal/store/secrets/store.go:147`) was written for exactly this and is dead code on
  the live path. Also: because the request 500s before any insert, the denial is *not*
  audited as a `change.created`, and the response leaks nothing (good) but the operation is
  broken, not merely degraded.

- **B2 — The pre-existing ws stack's platform audit chain is invalid and self-heals into
  "invalid" on every boot.** `podman exec ws_db_1 psql -U coffer` shows platform seq 2 with
  `action='x'` (not a frozen action) and `login.success` correctly at seq 4; `admin audit
  verify` → `Audit chain INVALID at sequence 2`, exit 9. This is residue from an earlier
  session's tamper test that was never undone; `down.sh`/`up.sh` preserve it by design. The
  chain code itself is sound (fresh stacks verify valid; my tamper test in a clean stack
  detected and localized the damage exactly). **Action needed:** reset that stack's volume or
  repair the row; any grading run against the standing stack will score audit/verify as
  broken through no fault of the current code. (Reported here because it is environment
  state that gates acceptance, not a code defect.)

- **B3 — A "present but rejected" `COFFER_APP_DB_PASSWORD` does not fail the start; the boot
  silently re-provisions the role password to whatever the env says.** `ensureAppRole`
  (`internal/store/db.go:479-500`) runs `ALTER ROLE coffer_app PASSWORD <env value>` on every
  owner-connection migration pass, before the runtime pool connects. Observed: booting a
  server with `COFFER_APP_DB_PASSWORD=definitely-wrong-password` connected successfully as
  `coffer_app degraded:false`; afterwards `psql` as `coffer_app` with that "wrong" password
  **succeeded** — the role's password had been overwritten to the typo. CONTRACTS §11 says:
  "`COFFER_APP_DB_PASSWORD` present but rejected by the server → **failed start**, never a
  fallback. A rejected credential is a misconfiguration, and silently escalating to the owner
  role would turn a typo into a privilege change." The rejection path exists
  (`internal/store/db.go:196-198`, `isAuthFailure`) but is unreachable in practice because
  the same boot repairs the credential first. The observable contract behavior — a
  misconfigured password must fail loudly — is not met; instead every boot rewrites the
  role password to the env value, which also means any actor with owner-connection
  privileges re-keys the runtime role without any signal. (I restored the role password to
  the stack's real value after the test.)

### Minor
- **M1 — `secret.read` audit targets are inconsistent between endpoints.** Single-key get and
  versions/get record the target as `project/<pslug>/env/<eslug>/key/<key>` (human-readable),
  while some events record `prj_<id>/env_<id>/key/<key>` (opaque ids) — both forms appear in
  the same org log (seq 213 vs 218 of the same scope). Harmless but makes filters/joins
  awkward; pick one form.
- **M2 — The P1 password-change gate exempts `GET /audit`, `GET /audit/verify` and
  `GET /changes`.** Observed on the gated beta owner: `me/projects/members/tokens` → 403
  `password_change_required`, but `audit`, `audit/verify`, `changes` → 200. DECISIONS says
  "every route except `POST /auth/password` and `POST /auth/logout` returns 403 until it is
  cleared." Read-only audit/changes reads are not privilege escalation, but the documented
  rule and the behavior differ; align one with the other.
- **M3 — `masterkey.rotated` is a frozen action (CONTRACTS §3) but no such event is written.**
  After a real rotation (log line `master key rotated, data_keys_rewrapped:1`), the audit
  tables contain no `masterkey%` row. The spec's audit-event list doesn't name it, but the
  frozen contract does; either emit it or drop it from the contract.
- **M4 — Performance under load is borderline.** On the quiet host: list p95 ~5 ms, 50
  concurrent reads p95 ~160 ms (spec: 200 ms). One sample set during host load measured 270
  ms p95. No violation on the clean numbers, but the margin is thin if the grading host is
  busy.
- **M5 — A JSON value containing a lone surrogate escape (`"\ud800"`) is accepted and stored
  as U+FFFD.** The spec says values are UTF-8 strings; the raw body is valid UTF-8, and Go's
  JSON decoder replaces the escape with the replacement character, so the stored bytes differ
  from what a strict reader might expect. Defensible reading of the spec; worth a line in
  DECISIONS.
- **M6 — `admin orgs` listing exposes `disabled_at` rather than a friendly status in JSON**
  (CLI renders active/disabled correctly). Cosmetic only.

### What I could NOT verify (stated plainly)
- **`docker compose` (real Docker) compatibility** — only the podman shim was available on
  this host, as briefed.
- **`up.sh` failure path with a *db* failure** (e.g. corrupt volume): I exercised the
  server-port-collision failure (exit 1, names the dependency) but not a db-side failure,
  because producing one safely on a shared host would have meant damaging other agents'
  stacks. The db-recovery path (readyz 503 → self-heal) *was* verified.
- **govulncheck** — not installed on this host; the CI workflow runs it, but I could not run
  it here. Dependency set is two pinned modules per DECISIONS, which I did not independently
  advisory-check.
- **The first rotation attempt on the original clone** — inconclusive (see Encryption caveats
  above); the clean retest passes, but I cannot fully explain the first anomaly because the
  tree was deleted mid-test.

### One-stack hygiene
Per the brief I kept only one stack up at a time (brought the clone down before working on
ws and vice versa; clone2 down at the end). The ws stack was already running when I started
and is left running, untouched.

---

## Verdict

**NEEDS WORK.** The core job is fully met (clean clone quickstart verbatim, byte-exact value
out, two-org isolation with byte-identical 404s), the authorization matrix, revocation,
versioning, two-person rule, crypto binding, tamper detection, HTTP surface, CLI and ops
behaviors I exercised all pass with real evidence — but B1 (service-token protected writes
500) is a spec-visible break on a §2.8/§2.9 path, B2 must be cleaned up before anything
grades against the standing stack, and B3 means a misconfigured database credential is
silently self-healed instead of failing the start as the frozen contract requires.

---

## Re-verification round 2 (after fixes)

### B1 — CLOSED (re-verified at `9203db3`, fresh clone + fresh stack, no cached layers)
RW service token → protected env: PUT **202** with change id (was 500); DELETE **202**;
`change_requests.proposer_id` in the DB is the issuing **user id**, never a `tok_…`;
the issuer approving its own token's proposal → **403**; a different owner approves → 200,
value applies atomically; audit `change.created` still names the **token** as actor;
unprotected write by token → direct 200. `./scripts/test.sh` exit 0 with **zero skips**,
including `TestServiceTokenProtectedWriteIs202` (set/delete/rollback + proposer attribution)
and `TestServiceTokenIssuerCannotApproveOwnProposal`. Regression tests read and match the
live behavior.

### B3 — PASS (re-verified at `fc1e820`, fresh clone `coffer-rev3`)
Boot with `COFFER_APP_DB_PASSWORD=definitely-wrong-password` → server **fails to start**:
`store: the database rejected the coffer_app credentials from COFFER_APP_DB_PASSWORD; fix the
password (the role's password is never rewritten automatically) … SQLSTATE 28P01`.
`pg_authid.rolpassword` for `coffer_app` **byte-identical before and after** the failed boot.
Per E0's method correction I verified the credential from a **non-trust client** (separate
container on the compose network, scram path): wrong password → `FATAL: password
authentication failed`; correct password → connects. The trust-path pitfall in
`postgres:16`'s default `pg_hba.conf` (127.0.0.1/32 trust) did not apply to either probe.

### B2 — CLOSED (ws stack volume reset by the CTO, confirmed by me)
`./bin/coffer admin audit verify` on the standing ws stack → **`Audit chain valid.`**, exit 0;
`/admin/audit/verify` → `{"valid":true,"first_invalid_seq":null}`. The hazard is recorded in
`docs/DECISIONS.md` (`e8d1fad`).

### P1-gate leak — PASS (re-verified at `fc1e820`, which includes the central-gate commits
`3e16222` + `28f0e25`)
Fresh gated member (must_change_password=true), probed during the gated window:
`/audit`, `/audit/verify`, `/changes`, `/projects`, `/members`, `/tokens`, `/me`,
secrets list/get/PUT (existing *and* nonexistent keys) → **all 403
`password_change_required`** — the gate wins over visibility, so the leak is closed in both
directions (a gated user can no longer read audit/changes, and the gate does not depend on
resource state). Exemptions verified exactly two: `POST /auth/token` (re-login) **200**,
`POST /auth/logout` **200**, `POST /auth/password` **200** (clears the gate). After
clearing, member-level reality returns (`changes` 200, `audit` 403 member-denied, nonexistent
secret 404). Platform admin `/me` shows no gate flag and platform routes work; a service
token reads secrets 200 (never gated). **Quickstart does not dead-end:** I re-ran the exact
README steps 4–10 verbatim at this HEAD (clean XDG config home) — every step exit 0, step 10
exactly 17 bytes. A gated user can log in, run `passwd`, and proceed.

### Lone-surrogate (Important) — PASS
`{"value":"a\ud800b"}` → **400** `request body contains an unpaired UTF-16 surrogate escape`;
the fix lives in `httpx.DecodeJSON` so every route inherits it (verified on a member-create
body too). A legitimate multi-byte value (`héllo ☃`) still round-trips byte-exactly.

### ⚠️ New finding N1 — the graded commit `fc1e820` ("Checkpoint: CEO — run start") does not
compile. It committed `internal/httpapi/mustchange_central_test.go` as **broken test code**
(`ungatedProbe()` returns `http.Handler`; `withRoutePattern` requires `*http.ServeMux`):
`go vet`/`go test ./internal/httpapi` fail with a build error on a clean clone of HEAD.
`28f0e25` (the last real commit) builds, vets, and passes the full suite green with zero
skips — product code is identical between the two; only the WIP test file differs. The ws
working tree holds the fix uncommitted. **If the graded commit is the final commit on the
default branch, this must be committed and the suite re-run before grading** (SPEC §6:
"Automated tests run through ./scripts/test.sh"; CI runs vet). Everything I verified live
runs on the working-tree fix and is valid for the product code; this is a commit-hygiene
blocker, not a product defect.

### Re-verdict
**PASS on all four gates** (B1 closed, B3 probes green, B2 chain valid, P1-gate correct in
both directions with the exemption list exactly right), plus the surrogate fix verified —
conditioned on N1: the broken test file must be committed in fixed form and the suite re-run.

---

## Re-verification round 3 (final, closing verdict)

**Commit under review: `30ae8e2` (current default-branch HEAD).** Fresh clone, zero local
state.

- `go build ./...` exit 0; `go vet ./...` exit 0 (clean).
- `./scripts/test.sh` exit 0, "Tests passed.", **zero skips** (full DB-backed integration
  suite ran).
- Fresh-clone `git status` clean.
- Verbatim README quickstart steps 4–10 re-run at this SHA: every step exit 0, step 10 =
  exactly 17 bytes (`hello-from-coffer`, no newline).
- Gate matrix re-confirmed live at this SHA during the gated window: 403
  `password_change_required` on audit, audit/verify, changes, projects, members, tokens (and
  per the round-2 matrix, /me and secrets too); exemptions exactly `POST /auth/token`,
  `POST /auth/logout`, `POST /auth/password` (all 200; password clears the gate).

**N1 resolution — the diff is five files, not one, and the CTO accepted it after review.**
`fc1e820..30ae8e2` contains: the fixed `mustchange_central_test.go` (N1's fix), plus
BackendEngineer_3's deliberate removal of the now-redundant per-slice database gate lookups
in `auditapi/audit.go` and `secretsapi/common.go`, matching test updates, and a DECISIONS
entry. I verified this was deliberate, owned, documented work — not unexamined WIP: the
checkpoint's parent touched only the test file, so the three product files are new, coherent
cleanup on top.

**CTO condition 2, answered with source evidence:** the gate's enforcement point is still
the **central `withAuth`** (`internal/httpapi/router.go:425` — `mustChange &&
!mustChangeExempt(r)` → 403; exempt list at `router.go:508-518` is exactly `POST
/api/v1/auth/password` and `POST /api/v1/auth/logout`, POST-only). The per-handler call
sites are **still live as defence-in-depth** and are now **context-only reads with zero
database access** (`reqctx.MustChangePasswordFrom(ctx)` at `secretsapi/common.go:156` and
`auditapi/audit.go:73`; `grep pgx|QueryRow|db.` in both files returns **0 matches**). The
simplification removed redundant DB reads on the hot path; it did not remove a check. Had
the per-slice lookups been dropped without the central gate, my verdict would differ.

## Final verdict

**PASS at `30ae8e2`** — N1's fixed test file plus BackendEngineer_3's removal of the
redundant per-slice gate-lookup queries (auditapi, secretsapi) and its DECISIONS entry, all
re-verified at this SHA: build, vet, full suite green with zero skips, live gate matrix
identical in both directions, quickstart verbatim green. Standing verdict conditions: one
logical change per commit from here (the next mixed diff goes back on sight), and the two
environment notes recorded earlier — the ws volume-reset hazard is documented in DECISIONS
(`e8d1fad`), and my report's B1/B3 history stands as the record of what was fixed.
