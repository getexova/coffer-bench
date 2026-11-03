# adjudicate c2 — us-west-2 grading host (harness 9f2f03b9a573, provisional)

Build c2, bundle `~/build-c2.bundle`, graded commit **ba861e566a19771008a6cb077ba5615d36e607bb**.
Host: <grading-host> (us-west-2), grader2 (uid 1003), rootless podman 5.8.9, 16 vCPU, Fedora 44.
Harness: `~/harness-9f2f03b9a573` (85 rows, same hash as r4's scored harness).

What I read: `results.jsonl`, `summary.json`, `logs/*.log` (all 21 ship-blocker logs plus X5, X16, O4, F18, E6, A6, E1, O10, X7), `sweep/` counts from the logs, GRADER.md/SPEC.md, the r4 adjudication notes and voids.md, and the harness code paths for X5 (`_find_pw_hashes`), O4 (`o4`) and the S4/S16 controls. I read one line of build source — `test/e2e/helpers_test.go:27` — only to identify the gitleaks finding that X16 named; I did not read anything else to make a check pass. No secret values printed.

## Run facts

- Command (exactly the task's): `timeout 1800 python3 -I run.py --bundle ~/build-c2.bundle --work ~/work-c2 --out ~/out-c2`.
- Store cleaned per task, `podman pull docker.io/library/postgres:16` first (image 74d436cb49d3).
- **Exit code 0**, console log 0 bytes, `partial=false`.
- started 2026-10-30T15:23:42Z, finished 15:37:42Z (**14.0 min**).
- 85 rows: **73 pass, 6 fail (X16, F18, X5, X10, O4, A6), 2 error (S4, S16), 0 timeout, 4 na (G1, E2, E4, E5)**.
- `summary.json`: p0 134/148 = 90.5%, p1 4, total 138, `blockers_failed: [X10]`, `errors: [S4,S16]`, verdict NOT SHIPPABLE (provisional).
- Timing rows clean: O10 list p95 4 ms / 50-concurrent get p95 23 ms; X7 ratio 1.00; E1 rc=0. The O4 failure is the only timing/lifecycle-sensitive miss (see §A).

## A. Non-pass rows

| ID | Verdict | Basis |
|---|---|---|
| **X10** | **real-fail** (ship-blocker) | `ASSERT FAIL GET audit?actor=nul/raw: 200 with non-empty/unknown result (want 4xx or [])` and the same for `?action=nul/raw` (X10.log:1667,1720). A NUL in those two query filters is silently dropped: the request returns **200 with 43 KB of the caller's own audit rows** instead of 4xx or `[]`. Positive controls pass, the other ~3,200 payload lines pass, NUL in JSON fields is rejected (`name must not contain control characters`), and there are **0 responses with status 500** in the whole log. c1 answers the identical probes with 400, so the harness can tell them apart and this is a build difference, not a grader artifact. GRADER X10 requires 4xx for `%00` in every query param. No cross-tenant data leaks (the rows are the caller's own), but the criterion is not met. |
| **S4** | **harness-fault → unevaluated** (ship-blocker) | `HARNESS ERROR: control failed: root PUT grant (400)` (S4.log:219). The control PATCHed its scratch user to `admin` (`CONTROL ok: root PATCH /members/{id} (200)`) and then PUT a grant **on that admin**: the build answers `400 grants apply only to members; owners and admins have access to every project`. SPEC §1 defines a grant as something that "gives a member access"; owners/admins already have access, so rejecting it is SPEC-consistent, and the harness control demands a behaviour SPEC does not require. 30 graded asserts had already passed (root 404 on projects/members/routes); the run aborted before tokens/changes/audit/secret routes, so S4 is **not evaluated**, not failed. c1 accepts the same PUT (200), which is why the control passed there. |
| **S16** | **harness-fault → unevaluated** (ship-blocker) | Same control defect: `HARNESS ERROR: control failed: T_dev_r PUT grant (400)` (S16.log:88) and `T_prod_rw PUT grant (400)` (:367), after 40 graded asserts had passed. Because the check aborts at the first service token, the **T_dev_rw and T_prod_rw cells never ran**. Not evaluated, not failed. |
| **X5** | **harness-fault** (P0) | `ASSERT FAIL admin2@acme.test: public.users.password_changed_at = unrecognized (prefix '2026-10-30', len 32)` ×8. `password_changed_at` is an ISO-8601 timestamp; the harness's `_find_pw_hashes` collects **any string column whose name contains "pass"**, so it classifies the timestamp as a password hash. Every real hash column passed: `admin2@…: public.users.password_hash = argon2id` (8/8 users). The 11-char-rejection half of X5 passes. Not a build defect. |
| **X16** | **real-fail** (P0) | `1 gitleaks findings: generic-api-key test/e2e/helpers_test.go:27 commit 1fbcde8e`. The hit is the test constant `testPassword = "e2e-correct-horse-battery-staple"` — a fixture password, not a live credential. GRADER allows only `.env.example` placeholders, and r4 counted first-party `generic-api-key` hits in a test file (`crates/coffer-server/tests/auth_flow.rs`) as a real fail, so the same standard is applied here. Weakest of the fails; if the review wants X16 scoped to real secrets only, this would pass. Positive control (`gitleaks control detects planted token`) passed. |
| **O4** | **flaky** (P0) | In the scored run all four probes answered with an `X-Request-Id` but `0 log lines with request_id=…` for each; the server log shows an 9 s gap (15:29:20.3 → 15:29:29.4) covering the probe window, while the same server logs other requests normally. The probes came **8 s after O3's SIGTERM restart** (new container started 15:29:19.301), which points at a post-restart log-pipe/flush window. **Reproduction: an isolated `--only O4` re-run on the same bundle passed 4/4** (`4 JSON request lines with all 5 fields; X-Request-Id matched for 4 probes`, out-c2-o4, not scored). Single occurrence, not reproducible → flaky, but a repeat full run should settle whether the O3→O4 sequence matters. |
| **F18** | **real-fail** (P1) | `ASSERT FAIL before passwd: project list rc=0 (want refused)` and `before passwd: API GET /projects -> 200 (want refused)`. A user created with an initial password can use the API before `passwd`; `must_change_password` is surfaced in `/me` but not enforced. P1. |
| **A6** | **spec-or-grader-fault** (candidate void) | `DELETE seq 2623 (expect first_invalid_seq 2624): first_invalid_seq=2623`, same from the CLI. Detection works; the N-vs-N+1 split is identical to c1 and to r4's void. |
| **G1** | **unevaluated (harness/manual gap)** | `na  manual; recorded na`. No G1 lane run; strict/assisted and the SHIP gate undecided. |
| **E2, E4, E5** | **not judged (provisional, per task)** | `na  manual; recorded na`. |

## B. Ship-blocker passes (19 pass-confirmed; S4/S16 unevaluated)

- **G3** — distinct random 32-byte keys; placeholder → `refused: exit=1 restarts=4 log names key=True`; boots before and after.
- **S1** — 14 `404 identical to absent` probes + CLI get/list/export with acme controls; acme web state unchanged.
- **S2** — `no acme canary in any of 23 globex responses`; globex-only values on API/CLI/run/token/export; acme-only `MULTI` 404.
- **S3** — 9 IDOR probes 404 with controls; acme state re-read unchanged (tokens still work, writer still member, grant targets unchanged).
- **S5** — 21 controls; nogrant `404 identical to absent` everywhere, targets unchanged.
- **S9** — 43 controls; all member ops 403 (CLI rc 4), targets re-read.
- **S10** — self-approve 403 for writer/admin/owner (CLI rc 4), CR pending; `admin2` approves 200 and the change applies.
- **S13** — `state identical after 30 attempts (0 returned 2xx)`, 40-key snapshot, owner PATCH control 200.
- **S14** — T_dev_rw api/prod+web 404 identical to absent; T_dev_r 403 on PUT/rollback/DELETE and the key survives.
- **S17** — revoked/expired 401 on the next request, ttl=60 token 401 at expiry+1 s, works-before controls.
- **X1** — `scanned 119 files for 373 needles`, 0 hits, self-test, each home ≤1 own token.
- **X2** — tampered ciphertext reads give a generic value-free 500, source still reads, destination restored; passes under the r4 X2 interpretation fix (see §D).
- **X6** — `129 token needles scanned over 44 dumps`, 0 hits, self-test.
- **A1** — 55 asserts: every op has its own event with actor/target/result, per-key read events for export/run, failed login in the platform log.
- **A3** — 373 needles × 3 API audit pulls + **3,386 DB audit rows**, 0 hits, inline self-test.
- **A5** — target UPDATE at seq 2622 → rc 9 and `first_invalid_seq=2622`; valid before/after.
- **O5** — 42 log files, 373 needles, 0 hits, no token/header shapes, self-test control.
- **O7** — backup → wipe → restore; acme/globex/platform verify rc 0, post-restore write/read 200/200.
- **S4/S16** — see §A: **not evaluated** (control aborted the check). 30 and 40 asserts respectively had passed before the abort, all with controls.

## C. Score (provisional, from results.jsonl)

- P0: **134/148 = 90.5%** (E2/E4/E5 na excluded; X16, X5, X10, O4, A6 fails + S4, S16 errors counted as 0).
- P1: **4/5** (E6, X19, X20, O10 pass; F18 fails).
- **Total 138** (max 153).
- Blockers failed: **X10**. Blockers unevaluated: **S4, S16**. G1 unevaluated.
- Verdict as run: **NOT SHIPPABLE** on X10 alone, and S4/S16 are open coverage gaps.
- Adjudicated view (not applied to the score): if X5 is a harness false positive (+2) and A6 is voided (+2), P0 becomes 138/146 = 94.5%, total 142. **The verdict does not change**: X10 is still a failed blocker and S4/S16 are still unevaluated.

## D. Harness / spec questions

1. **S4/S16 control design (the main finding).** The control promotes a scratch user to admin and then PUTs a grant on that admin, then requires 2xx. SPEC never requires a grant on an admin to succeed; a build that rejects it (400 "grants apply only to members") loses coverage of two ship-blockers. Fix: run the grant control on a **member**, or accept 400 for an admin target and use a member for the positive control. Until then S4/S16 are unevaluable for any build that rejects admin grants.
2. **X5 column matching.** `_find_pw_hashes` treats any string column whose name contains `pass`/`pwd` as a password hash; `password_changed_at` (timestamp) fails it. Restrict to columns whose values look like hashes, or exclude `*_at`/timestamp columns.
3. **X2** — passes only under the r4 interpretation fix (generic value-free 5xx accepted on decrypt failure). Same as c1; flag for the void review, not a build-specific issue.
4. **A6** — N-vs-N+1, identical on both builds; candidate void as in r4.
5. **X16** — first-party gitleaks hit is a test constant. r4 precedent counts it; a narrower reading of "no real secrets" would not.
6. **O4** — single-occurrence post-restart log gap; passed on isolated re-run. Recommend one repeat full run before treating it as a build defect.
7. No void review was run for this round; E2/E4/E5 were not judged.
