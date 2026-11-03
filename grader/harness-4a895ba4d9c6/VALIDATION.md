# Harness null-reference validation (2026-10-26)

GRADER asks that the harness be validated against a deliberately broken reference before a pass is trusted. This file records that run. It was done on the laptop only: no build bundle was cloned or read, and nothing ran on gradevm.

## The null reference

- Bundle `/tmp/nullref/nullref.bundle` has 2 commits. It contains the SPEC-named scripts (`init-env.sh`, `up.sh`, `down.sh`, `build.sh`, `test.sh`, `backup.sh`, `restore.sh`), `bin/coffer`, `.env.example`, README and docs stubs. The build script is `/tmp/nullref-tools/mkbundle.sh`.
- `init-env.sh` writes a `.env` that points at `127.0.0.1:18420`. The other scripts exit 0. `up.sh` starts the stub server and `down.sh` stops it.
- `bin/coffer` prints `{}` and exits 0 for every call.
- The stub server is `/tmp/nullref/tools/stub_server.py`. It runs one of these variants:

| variant | behavior |
|---|---|
| A | 200 `{}` for everything |
| B | 404 `{"error":{"code":"not_found","message":"x"}}` for everything, except that GET /healthz and /readyz return 200 so setup gets past S4 |
| B0 | 404 for everything, including the health routes |
| C | A, plus every POST returns a fresh random `{id, token, user:{id}}`, so the fixture and scratch actors end up with credentials |
| D | B, plus POST /auth/token returns a token, so actors have PATs and every resource route returns 404. This is the strongest test of denial checks that lack a positive control. |
| E | (round 2) every POST returns 200 with fresh `{id, token, user:{id}}`, health routes return 200, and every other method and route returns 404. Scratch users, orgs and tokens get created, so denial rows go past scratch setup to their probe and control stage. |

- There is no compose file. Every `compose exec/ps/logs` call fails fast with rc != 0. Destructive rows therefore record `error: checkpoint failed`, and container rows record `error: no server container`. Both are graceful failures, so the compose helpers needed no change.
- How to run it: `/tmp/nullref-tools/runvar.sh <V>`, which uses the harness's full `run.py`.

## Final results (after the fixes)

| variant | pass | fail | error | na | verdict |
|---|---|---|---|---|---|
| A | 3 (G2, X16, E1) | 23 | 55 | 4 | NOT SHIPPABLE, P0 4/148 |
| B | 3 (G2, X16, E1) | 15 | 63 | 4 | NOT SHIPPABLE, P0 4/148 |
| B0 | 2 (X16, E1) | 3 | 76 | 4 | NOT SHIPPABLE, P0 4/148 |
| C | 3 (G2, X16, E1) | 34 | 44 | 4 | NOT SHIPPABLE, P0 4/148, blocker S2 failed |
| D | 3 (G2, X16, E1) | 15 | 63 | 4 | NOT SHIPPABLE, P0 4/148 |

In B and D, no denial row passed. Each one errored on its positive control (for example `control failed: viewer@acme get api/dev (404)` or `absent target not 404`) or on a precondition. Runner rule R4 (a pass with 0 controls becomes an error) was not needed, because the controls caught every case first.

## Passes that genuinely hold for the stub (accepted)

- **G2** (0 points, gate): `up.sh` exited 0 and `/readyz` returned 200 from the server that `up.sh` started. That is the literal criterion. B0 fails it, as it should. The pass is genuine only because of fix N1 below. Before N1, a server already listening before `up.sh` also passed.
- **X16** (2 points): gitleaks found nothing in the stub history, which is true. The check runs a positive control first: gitleaks must detect a `ghp_` token planted in a scratch repo.
- **E1** (2 points): GRADER's criterion is only that `./scripts/test.sh` exits 0 on a clean clone, and it does. Whether the tests are meaningful is E2, which is graded manually (na). **Graders: an E1 pass says nothing about test quality. Read it together with E2.**

## Vacuous passes found and fixed

- **N1 (fixture.py, setup S4): port-squatter pass.** On the first variant A run, G2 passed while the stub server was already running before `up.sh`. Setup never checked that the port was free, so a leftover server (from the other arm or a stray process) would answer `/readyz`. G2 and every runtime check would then grade the wrong server.
  - Fix: before `up.sh`, `GET /readyz` must fail at transport level. If it does not, setup fails at S4 with `port N already in use before up.sh`, and every stack check records `error: setup failed at S4`.
  - Verified with `--only G2,X16` and a pre-started stub: G2 is `error: setup failed at S4`.
- **N2 (checks_x_b.py, X14): control that a do-nothing CLI satisfies.** In variant C, X14 passed. Its only control was "the CLI process was seen in ps and exited 0", which is true of a CLI that never reads or sends the password, and in that case the password can never appear in argv.
  - Fix: a new helper, `_x14_effect`. Each run must now also show a server-side effect:
    - a raw `/auth/token` login with the password piped on stdin returns a token;
    - the same login with a wrong password is refused (400, 401 or 403);
    - for `login`, `coffer login` with a wrong password exits non-zero.
  - In variant C, X14 is now `error: control failed: login: raw login with a WRONG password -> 200`. On a real build each of these holds.

## Not covered by this validation (open)

- **Compose and database paths.** No container ran, so these rows were exercised only as far as their "no container / checkpoint failed" error paths:
  - destructive rows: S3, S9, S11, S13, S16, X10, X19, G3, X3, O8, O7, X4, X2, A5, A6;
  - container rows: O1, O2, O3, O4, O6;
  - sweep rows: X1, X6, A3, O5;
  - DB rows: X5, X19.
  
  For these rows, the absence of a vacuous pass is shown only on that path. The next step is a null build whose compose runs `postgres:16` plus a stub server container, run on gradevm with podman.
- The rows that error in A/C because of missing fixture fields (for example S1 and S5 preconditions) were not driven to their probe stage in A. D drove most of them to the control stage, and every one errored there.
- X15 failed on the stub correctly (no lockfiles, osv rc 128).
- O9 errored correctly (no image references).
- E6 failed correctly (one commit holds 98% of the lines).

## Files changed

- `harness/fixture.py`: port-free precheck before `up.sh` (N1). Writes `setup.json` `port_busy_before_up`.
- `harness/checks_x_b.py`: X14 effect controls (N2) and the new helper `_x14_effect`.
- Both files compile, and `run.py --list` still exits 0 with 85 rows.
- No other harness file was edited. The stub artifacts are under `/tmp/nullref*` (outside the grading tree).

## Round 2: re-validation after the 16:28-16:35 module edits

checks_s_b, checks_x_b (16:28), checks_x_a (16:33) and checks_a (16:34) changed after round 1, so round 1 no longer covered the current harness. I re-ran every variant with the same bundle and the same `runvar.sh`, one at a time on port 18420, after checking that the port was free. All 12 .py files compile. No harness file was edited in this round.

| variant | pass | fail | error | na |
|---|---|---|---|---|
| A | 3 (G2, X16, E1) | 23 | 55 | 4 |
| B | 3 (G2, X16, E1) | 15 | 63 | 4 |
| B0 | 2 (X16, E1) | 3 | 76 | 4 |
| C | 3 (G2, X16, E1) | 34 | 44 | 4 |
| D | 3 (G2, X16, E1) | 15 | 63 | 4 |
| E (new) | 3 (G2, X16, E1) | 19 | 59 | 4 |

- **A to D.** The (id, status) pairs match round 1 row for row (diffed against `/tmp/nullref/final<V>.txt`). The edits added no vacuous pass.
- **E.** I added E because in B and D many denial rows (S18, S19, X13, X14, X20, A1, A7, A8) stopped at `scratch_user POST /members -> 404` and never reached their denial probe.
  - Under E those rows reach the grant, control or probe step. Every one of them errored on a positive control or precondition, for example `control failed: fresh PAT GET /me (404)`, `control failed: read token works before revoke (404)` or `scratch_user grant ... -> 404`.
  - X14 hit the N2 control (`raw login with a WRONG password -> 200`).
  - X7 and X8 failed correctly: a wrong password returned 200.
  - No denial row passed.
- **Compose helpers.** There is no compose file and no container. `podman-compose` exits rc 255. Destructive rows record `error: checkpoint failed: pg_dumpall globals rc=255`, container rows record `no server container`, and sweep rows record `sweep source dumps is empty`. These are graceful failures, so no change was needed.
- **Literal variant B.** The task's variant B (404 for everything) is B0. Its setup stops at S4 because `/readyz` is 404, so only the static rows run. B (health 200) and E exist so that the runtime denial rows actually execute against 404s.
- **Accepted passes.** G2, X16 and E1 hold for the stub, for the reasons given above. They are worth 0, 2 and 2 points.
- **Still open.** The compose, DB and sweep rows are unchanged from round 1. They are covered only on their error paths and still need a podman null run on gradevm.
- **Artifacts.** `/tmp/nullref/r2_<V>.txt` and `/tmp/nullref/o<V>/`. Variant E was added to `/tmp/nullref/tools/stub_server.py`.

## Round 3: re-validation after the r2 reviewer-finding fixes

Round 3 was run after these harness edits: the ENV host prep, the S4b container discovery gate and the VOID verdict (fixture.py, run.py); engine-label container discovery and env_override recreate evidence (lib.py); runner rollback via `recreate_server` with diagnostics (run.py); the G3 refusal-evidence and recovery controls (checks_g_o.py); the S16 probe with the same body plus a bearer (checks_s_b.py); the X7/X8/X10 reorder and login gate (registry.py, checks_x_a.py); and the bytes decode in A2/A7 (checks_a.py).

Setup: the same bundle and `runvar.sh` as before, one variant at a time on port 18420, with the port verified free before each run. All 12 .py files compile. `run.py --list` prints 85 rows in the new order X8 501, X10 502, X7 558.

| variant | pass | fail | error | na | vs round 2 |
|---|---|---|---|---|---|
| A | 3 (G2, X16, E1) | 23 | 55 | 4 | every (id, status) identical |
| B | 3 (G2, X16, E1) | 15 | 63 | 4 | identical |
| B0 | 2 (X16, E1) | 3 | 76 | 4 | identical |
| C | 3 (G2, X16, E1) | 34 | 44 | 4 | identical |
| D | 3 (G2, X16, E1) | 15 | 63 | 4 | identical |
| E | 3 (G2, X16, E1) | 19 | 59 | 4 | identical |

- **No new pass.** The accepted passes (G2, X16, E1) are unchanged. Artifacts: `/tmp/nullref/r3_<V>.txt` and `/tmp/nullref/o<V>/`.
- **ENV step.** It ran in every variant. The pull exited 0 and the non-TTY control `podman create postgres:16` exited 0. `setup.json` records `env_prep` and `image_store` (the postgres images plus the total count). If the control fails, setup is `failed_at=ENV`, `void=true` and the summary verdict is null with "VOID/ENV". That path was not exercised, because the control passed.
- **S4b.** The null reference has no compose file. The S4b gate is skipped (`compose_file=false`) and the container rows error individually, as in rounds 1 and 2. When a compose file exists, S4b fails setup if `server` or `db` is not found.
- **Login gate (X7/X8/X10).** The gate fails fast on any non-429 answer. Under A, B and D that answer is 404 or a missing token, so X7 and X8 are `error: login gate ...` (round 2: also error). Under C and E the gate passes, and X7 and X8 still `fail` correctly (a wrong password gives 200).
- **Compose paths, tested on a scratch podman-compose 1.6.0 project.** This was not a null build. I used two fedora containers named `server` and `db` in /tmp, deleted afterwards.
  - Confirmed: `podman compose ps -q server` is rejected ("unrecognized arguments: server"), and so is `ps -a`. This was the root cause of the r1 "no container" results.
  - `lib.discover_containers` finds `repo_db_1` and `repo_server_1`.
  - `env_override` gives a new container id, with `recreated=True` and the new env in its log.
  - `Runner.recreate_server` gives a new server container carrying the restored env. On failure it writes "recovery diagnostics" with the project containers and the server log tail.
- **Still open.** No real `postgres:16` + server null build has run on gradevm, which was unreachable (ssh timeout x2) during this pass. The destructive, DB and sweep rows are still covered on the null reference only along their error paths. Their success paths were exercised only on the scratch project above.

## Round 4: re-validation after the r3 reviewer-finding fixes (2026-10-26)

The harness edits in this round (no build source was read; one fix applies identically to both builds):

- **S1, S2, S4 to S11, X5 (lib.py L16): saved CLI logins are URL-bound.** The fixture homes are logged in during proxied F1 (`:18420`), and most rows point the CLI at `base_url` (`:8420`). Each successful `coffer login` run through `c.cli` now records its `COFFER_URL` in `WORK/homebind/<hash>`, outside the home. When a check drives an actor's own home against a different URL, `c.cli` logs that actor in once to a sibling home `<home>~base` (or `~proxy`, or `~u<hash>`) and then reuses it. Fixture homes from before L16 that have no record are treated as proxy-bound. Runs with `COFFER_TOKEN`, runs with `home=` set to another directory, and `login` itself are never redirected. Offline test with a fake CLI that refuses a login saved for another URL: F1 home kept, `~base` created once and reused, proxied rows unchanged.
- **Inverted ASSERT wording (lib.py L19).** `expect(cond, msg, ok_msg=None)` now logs `ok_msg` on success, or `not(<msg>)` when none is given. This covers S2, G3, S3 and every other row. S2, S3, O6, O7 and X19 have explicit ok wording.
- **X19 (checks_x_b.py).** Only audit event tables are judged: tables with a prev-hash column and a hash column (the A5/A6 detector, now `lib.audit_event_tables`). Other audit-named tables, such as a chain-head pointer, are logged as info.
- **O6, O7 and the sweep audit pull (lib.py L18, checks_g_o.py).**
  - New `lib.audit_list`: it sends `limit=100000`, and on a 400 retries with 1000, then 500, then 100. It flags the list as possibly truncated when its length equals the limit or a round cap.
  - O6 counts audit events through SQL row counts of the event tables, and falls back to the API.
  - O7 compares every audit event row (`row_to_json` through psql) before backup and after restore. The post-restore rows are read before any post-restore secret read. The API audit lists are positive controls only.
  - The sweep's audit pull uses `audit_list`.
- **O8 (checks_g_o.py).** An unset `COFFER_PORT` that boots counts as na-by-design (SPEC §5 `${COFFER_PORT:-8420}`), never as a fail. The other six variables are unchanged.
- **X1 (checks_x_a.py).** The log positive control is now "at least one JSON log line with method, route, status and request_id (top level or one level nested)". It no longer looks for the literal `/api/v1`. Offline unit test: the detector counts 2 of 4 sample lines (2 expected).
- **X7 (checks_x_a.py, registry.py).**
  - X7 now runs last of all stack rows (order 985, after the sweeps), so its failed logins cannot trip a limiter for a later row.
  - Its timeout is 5400 s: up to 5 limiter windows of 15 min, plus margin.
  - Sampling stops 300 s before the timeout. Each clean pair is appended to `OUT/X7-pairs.jsonl` (status, ms and masked-body sha only).
  - Batches stay sized below the observed limiter threshold.
  - The gate's wait is capped by the remaining budget.
  - The verdict still needs 30 pairs (GRADER: "over 30 tries"). With fewer, X7 is an error, and the persisted pairs remain available.
- **A1, A2, A7, A8 (lib.py L17).**
  - `scratch_user` and `scratch_org` setup logins now back off on 429 (Retry-After, or exponential, up to 20 min in total).
  - The login gate passes `wait429=False`.
  - X8 and X10 keep their own gate.
- **S3 (checks_s_a.py).**
  - The PUT-grant and DELETE-grant targets are now logged-in scratch members.
  - Before the probes, these controls must hold: `u_grant` gets 404 on api/dev, and `u_grev` gets list 200 and value 403.
  - After the probes, the same reads must still give 404 and 200/403. A cross-org grant change that answered 404 but was still applied now fails.

**Checks.** All 12 .py files compile (`python3 -m py_compile`). `run.py --list` prints 85 rows, with X7 at 985.

**Null reference.** Same bundle and `runvar.sh` as before, one variant at a time on port 18420, with the port verified free first.

| variant | pass | fail | error | na | vs round 3 |
|---|---|---|---|---|---|
| A | 3 (G2, X16, E1) | 23 | 55 | 4 | every (id, status) identical |
| B | 3 (G2, X16, E1) | 15 | 63 | 4 | identical |
| B0 | 2 (X16, E1) | 3 | 76 | 4 | identical |
| C | 3 (G2, X16, E1) | 34 | 44 | 4 | identical |
| D | 3 (G2, X16, E1) | 15 | 63 | 4 | identical |
| E | 3 (G2, X16, E1) | 19 | 59 | 4 | identical |

- No new pass.
- The new home binding ran: in C, the S2, S5 and S6 logs show `homebind: <actor> home ... is bound to <proxy>; using <home>~base`.
- In C and E, X7 still fails correctly (a wrong password gives 200).
- Artifacts: `/tmp/nullref/r4_<V>.txt` and `/tmp/nullref/o<V>/`.

**Still open.**
- The new SQL audit paths (O6, O7, X19) and the 429 backoff are reached only on their error paths in the null reference: there is no compose, and the stub never answers 429.
- S1 to S11, X5, X19, O6, O7, O8, X1, X7, A1, A2, A7, A8 and S3 have not been re-run on gradevm in this pass. They need a re-run on both builds, in the same order, with the same harness.

## Round 5: S11 stale CLI home after a runner rollback (2026-10-26)

**Finding (S11, seen on both builds, harness fault).** S11's CLI leg ran as `admin@acme` in `admin@acme~base`. That home was logged in during S9. S9's rollback restored the DB and so deleted that PAT, but the `WORK/homebind` record and the `~base` home survived. `lib._home_for_url` then reused a dead token: rc 3. Every API leg of S11 passed with controls. One fix, applied identically to both builds. No build source was read.

**Harness edits.**
- **run.py: checkpoint and rollback.**
  - `checkpoint()` saves `ckpt/<name>/homebind.json`, a copy of every `WORK/homebind` record.
  - `rollback()` calls `_restore_homebind()` after the DB restore. It drops every record that is new or changed since the checkpoint. If the record names an alt home (`<home>~base|~proxy|~u<hash>` under `WORK/homes`), that home is deleted too. A primary fixture home keeps its files, and its record falls back to the pre-L16 default (proxy-bound).
  - A checkpoint without `homebind.json` treats every record as post-checkpoint.
  - The result is logged as `rollback <name> for <row>: homebind: dropped N record(s), M alt home(s)`. This covers both per-row rollbacks and the guard rollback to `base`.
- **lib.py: liveness check before reusing a bound alt home (L20).**
  - `_home_for_url` runs `coffer whoami` once per row in the alt home, through `_alt_alive` (actor=None, so the call is never redirected).
  - On rc 3, the actor logs in again into the same alt home.
  - A fresh login marks the home alive with no extra call. `whoami` is not an audited action in SPEC §Audit.
- **lib.py: actor-specific positive control in `denied()` and `same_404()` (L21).**
  - This applies when a CLI probe answers rc 3 and 401 is not an accepted denial. The harness re-runs `whoami` with the probe's own HOME, URL and env (CliResult now carries `home`, `url`, `env`).
  - If `whoami` is also rc 3, the row records `error: control failed: <what>: probe session unauthenticated`, not fail.
  - If `whoami` succeeds, the rc 3 is the build's real answer, and the row still fails.
  - Probes where 401 is allowed are unchanged.

**Offline test.** I used a fake CLI that binds a token to its URL, plus a token "DB" file that the test rolls back. Results:
- S9-style base login creates `~base`. Rollback drops 1 record and 1 alt home. An S11-style CLI probe then logs in fresh and gets rc 4 (want 4).
- With a stale `~base` and a surviving record (the old failure), the liveness check sees rc 3, logs in again, and the probe gets rc 4.
- `denied()` with a dead session records an error, with no failed expect.

**Checks.** All 12 .py files compile (`python3 -m py_compile`). `run.py --list` prints 85 rows.

**Null reference.** Same bundle and `runvar.sh` as before, one variant at a time on port 18420, with the port verified free first.

| variant | pass | fail | error | na | vs round 4 |
|---|---|---|---|---|---|
| A | 3 (G2, X16, E1) | 23 | 55 | 4 | every (id, status) identical |
| B | 3 (G2, X16, E1) | 15 | 63 | 4 | identical |
| B0 | 2 (X16, E1) | 3 | 76 | 4 | identical |
| C | 3 (G2, X16, E1) | 34 | 44 | 4 | identical |
| D | 3 (G2, X16, E1) | 15 | 63 | 4 | identical |
| E | 3 (G2, X16, E1) | 19 | 59 | 4 | identical |

- No new pass.
- Artifacts: `/tmp/nullref/r5_<V>.txt` and `/tmp/nullref/o<V>/`.

**Still open.**
- The null reference has no compose, so destructive rows stop at `checkpoint failed`. The new rollback homebind path ran only in the offline test above.
- The stub CLI never answers rc 3, so L20 and L21 are not triggered there.
- S11 (and, to be safe, every CLI row after S9 and S3) has not been re-run on gradevm in this pass. It needs a re-run on both builds, in the same order, with the same harness.

## Round r3-1: reviewer findings S9, A1, A2, E6 (2026-10-29)

Harness 00dcf74bd482 was snapshotted to `provenance/harness-00dcf74bd482/` before any edit. Each fix applies identically to both builds. No build source was read.

**Findings (all harness faults).**
- **S9 (seen on build-1).** nogrant approve/reject of a CR in api/prod got 404. nogrant cannot see `api`, so SPEC 2.1/2.5 (404) and 2.6 (403) both apply, and GRADER says to accept 403 or 404 where rules overlap. The matrix had strict 403 there, while the analogous grant and token cells were already `4or3`.
- **A1 (seen on build-1).** The events existed, but the matcher missed them:
  - the protected-set CR event names the change id, not the key;
  - the management events carry the owner's PAT id as actor (SPEC 4: "actor (user or token ID)"), but the matcher accepted only the user id or e-mail.
- **A2 (seen on build-1).** The unauthenticated failed login was logged (`login.failure`, result failed, target auth/token) without the attempted e-mail. Neither SPEC 4 nor GRADER requires the e-mail, so the `admin audit list` display check never ran.
- **E6 (seen on build-2).** Added-line shares counted vendored dependencies (vendor/), so the logged measurement was not first-party history.

**Edits.**
- **checks_s_a.py (S9).** ROLE_MATRIX nogrant `approve` and `reject` 403 -> `4or3`, as for g_set, g_rev, t_new and t_rev. The admin@acme positive control and the "target CR still pending" check are unchanged. The docstring was updated.
- **checks_a.py (A1).**
  - *Actor aliases.* Before the scored ops, owner and admin each add one calibration member through the same CLI path, using COFFER_TOKEN and their PAT. The event is matched on the new member's e-mail or id with result success, and never on the actor. Its actor values, minus any value both calibration events carry and minus other actors' known ids, become that actor's aliases. Each actor's own user id and e-mail still match. An alias is only ever observed on an event the actor caused, never guessed. A calibration that finds nothing only logs, so this adds no new requirement.
  - *Protected set.* The step matches the key name OR the `change_id` from the CLI's `--json` output (as A8 does), with actor = writer.
  - *Logging.* `_require` logs the full redacted new events (up to 20, 2000 chars each) when there is no match.
  - A `_member_id` helper was factored out.
- **checks_a.py (A2).**
  - The platform tracker is drained just before the single probe.
  - The match is on the e-mail first. Otherwise it is the ONE new platform event with result=failed and a login-like action or target (`login|log_in|auth|token|sign.?in|session`).
  - Two or more such events with none naming the e-mail is ambiguous: an expect fails, and the full events are logged.
  - The `coffer admin audit list` check then runs with that event's seq or hash.
- **checks_e.py (E6).**
  - Excluded from line counts:
    - any path with a directory component `vendor`, `node_modules`, `third_party`, `third-party`, `thirdparty` or `bower_components`, or under `.yarn/cache`;
    - generated or minified files (`*.pb.go`, `*_pb2.py`, `*_pb2_grpc.py`, `*.pb.gw.go`, `*_gen.go`, `*.gen.go`, `*.min.js`, `*.min.css`, `*.js.map`, `*.css.map`).
  - Lockfiles stay excluded.
  - numstat rename paths (`a/{b => c}/d`) are resolved to the new path.
  - The summary logs `added_lines_first_party`, `excluded_lines` by category, and per-commit `first_party_lines` plus `excluded`.
  - The 80% threshold is unchanged.

**Offline tests.**
- `_excluded`: `vendor/github.com/...` -> vendor, `cmd/vendor.go` -> kept, `src/{old => new}/vendor/x.go` -> vendor, `go.sum` -> lockfile, `api/x.pb.go` -> generated, `internal/server.go` -> kept.
- `_match` on a `login.failure`/`auth/token` event with an empty actor: 1 match under the A2 fallback.
- `_match` on `change.created` / target `chg...` / actor `pat_...`: matches the change id with the alias in actor_ids.

**Checks.** All 12 .py files compile (`python3 -m py_compile`). `run.py --list` exits 0 with 85 rows.

**Null reference.** The /tmp artifacts were gone, so they were rebuilt under `~/coffer-grade-r3/nullref-r1/`:
- `tools/mkbundle.sh`: 2-commit bundle with the SPEC scripts, `bin/coffer` printing `{}`, `.env` on 127.0.0.1:18420, README and docs stubs, no compose file.
- `tools/stub_server.py`: variants A, B, B0, C, D and E as tabled above.
- `tools/runvar.sh <V> <harness> <tag>`: refuses if 18420 or 28420 is busy, runs the full `run.py`, then stops the stub.

The runs were on the laptop, one variant at a time on port 18420, with the port checked free first. The baseline is the pre-fix snapshot.

| variant | baseline 00dcf74bd482 (pass/fail/error/na) | fixed (pass/fail/error/na) | (id, status) diff |
|---|---|---|---|
| A | 3 (G2, X16, E1) / 23 / 55 / 4 | 3 / 23 / 55 / 4 | identical |
| B | 3 (G2, X16, E1) / 15 / 63 / 4 | 3 / 15 / 63 / 4 | identical |
| B0 | 2 (X16, E1) / 3 / 76 / 4 | 2 / 3 / 76 / 4 | identical |
| C | 3 (G2, X16, E1) / 34 / 44 / 4 | 3 / 34 / 44 / 4 | identical |
| D | 3 (G2, X16, E1) / 15 / 63 / 4 | 3 / 15 / 63 / 4 | identical |
| E | 3 (G2, X16, E1) / 19 / 59 / 4 | 3 / 19 / 59 / 4 | identical |

- The rebuilt reference reproduces the round-5 table exactly (counts and pass ids), so no stub adjustment was needed.
- No new pass.
- E6 ran its new path: first-party 248 lines, nothing excluded, largest share 99.6% -> fail. The earlier 98% came from the old /tmp bundle.
- Artifacts: `nullref-r1/{base,fixed}-<V>.txt`, `nullref-r1/out/<tag>-<V>/`, `nullref-r1/logs/`.

**Still open.**
- A1 calibration and the A2 fallback are not reached on the null reference. The stub returns no event list (A, C) or 404 on scratch setup (B, D, E), as in earlier rounds, so only the offline matcher tests above cover them.
- S9 stops at `checkpoint failed` (no compose).
- S9, A1, A2 and E6 need a re-run on both builds, in the same order, with the same harness.
- E6 on build-2 may still fail on first-party history: the finding estimated about 95% in one commit. That is the build's result, not a harness question.
