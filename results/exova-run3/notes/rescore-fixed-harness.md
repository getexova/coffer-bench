# Round 3 re-score under the fixed harness (both builds)

Blinded. Builds are named only build-1 and build-2. Nothing ran on any VM, no build source was read, no secret is quoted, and nothing is committed. All work is in `~/coffer-grade-fix/`. `~/coffer-grade-r3/` is unchanged.

**Revision 2 (2026-10-29).** The harness is now **f69b191bb8f1**. Revision 1 was 84686bc05858, which a skeptic refused. Fix 2 is now a pure mismatch rule (`CHANGES.md`, "Revision 2"). The re-run of the driver and of `score.py` moved no check status and no total. Two labels changed. The "Fix 2 not applied" sensitivity row and the sentence about it are now ESTIMATED, because they rest on the 7 escaped raw-`;` probes. Their answers are replayed from the `q` twins, not observed.

## Result

| | build-1 as graded | build-1 re-scored | build-2 as graded | build-2 re-scored |
|---|---|---|---|---|
| P0 | 138 / 148 (93.2%) | **142 / 150 (94.7%)** | 144 / 148 (97.3%) | **146 / 150 (97.3%)** |
| P1 | 5 / 5 | 5 / 5 | 4 / 5 | 4 / 5 |
| Total | 143 | **147** | 148 | **150** |
| Blockers failed | X10 | **X10** | X10 | **X10** |
| G1 | assisted | assisted | assisted | assisted |
| Verdict | NOT SHIPPABLE | **NOT SHIPPABLE** | NOT SHIPPABLE | **NOT SHIPPABLE** |

Every status change behind these numbers is MEASURED: the recorded r2 response decides it. Only sub-asserts that cannot change a check status in this re-score are ESTIMATED (see the X10 table). The exception is the sensitivity row "Fix 2 not applied". Its build-2 verdict does rest on ESTIMATED probes (see "Blockers and verdict"). The scores equal the fairness audit's "A and B, round-trip enforced" row (147 v 150).

## How it was scored

- **Inputs.** `results/build-{1,2}/r2/results.jsonl`, harness 4a895ba4d9c6, plus the round-3 resolutions:
  - E2, E4 and E5 PASS for both builds (`notes/judge-build-*-{1,2}.md`, both judges agree).
  - G1 is an assisted pass for both (`notes/G1-build-*.md`), worth 0 points.
  - S16, X2 and A6 are void for both (`notes/voids.md`).
  - With these the as-graded figures come out at 143 and 148, the same as `notes/fairness-audit.md`.
- **Rules (GRADER.md).** P0 is worth 2 and P1 is worth 1. A void earns 0 and leaves the denominator. The P0 % is P0 points over non-void P0 points. SHIP needs G1 strict, 0 blockers and at least 90% P0. FIX-THEN-SHIP needs 0 blockers and at least 75% P0. Anything else is NOT SHIPPABLE.
- **Fix outcomes.** These come from the offline replay driver `/tmp/hfix/driver.py`, re-run on both trees (outputs in `rescore/`):
  - The old tree (4a895ba4d9c6) still reproduces every recorded r2 result for X2, X4 and X10 on both builds.
  - The new tree (f69b191bb8f1) gives output byte-identical to `/tmp/hfix/out-new.json`, which was regenerated from that tree.
  - Against revision 1 (84686bc05858), every probe status is the same. Only the build-2 `ci\u0000` fail message changed, and it now names its source: "name shown as 'ci?' in the 201 echo".
- **Edit scope.** The only file that differs is `checks_x_a.py`. Its hunks lie inside `x10`/`_X10`/`_raw_seg`, the new `_generic_5xx`, `x4` and `x2`, plus docstrings. No other check's code changed.
- **Script.** `rescore/score.py` does the arithmetic, and its output is in `rescore/score.out.json`.

## Scoring decisions

- **X2 is un-voided and scored.** The void (`notes/voids.md`, X2 row) rested on one point: the check demanded a 4xx that SPEC's status table cannot give for operator-corrupted ciphertext. The fix it named was "pass a clean 5xx with a generic error body and no value". Fix 1 is exactly that edit. With the fault removed, the GRADER integrity rule no longer supports a void, so X2 is scored as a ⛔ again. It passes on both builds.
  - If X2 were kept void instead: 145 v 148, with no verdict change.
- **A6 stays void.** None of the four fixes touches A6. Fix 4 applies A6's standard to X10, which is the opposite direction.
  - If A6 accepted {k, k+1}, which is not among the fixes: +2 P0 each, 149 v 152, with no verdict change.
- **S16 stays void.** Its decisive probe (service-token bearer alone) was never run, and no fix adds it.
- **X11 (build-1) stands.** The failure is `GET /projects/%00/envs -> 500`. No fix touches X11, and the audit's "drop the probe" option is not one of the four.

## Per-check before/after

"Basis" says whether the recorded response decides the new status (MEASURED) or a probe changed, so the new response has not been observed (ESTIMATED).

| Check | Pts | ⛔ | build-1 before | build-1 after | Basis | build-2 before | build-2 after | Basis |
|---|---|---|---|---|---|---|---|---|
| X4 | P0 | | fail | **pass** | MEASURED | pass | pass | MEASURED (unchanged) |
| X2 | P0 | ⛔ | void | **pass** | MEASURED | void | **pass** | MEASURED |
| X10 | P0 | ⛔ | fail (46 sub-fails) | fail (35) | MEASURED | fail (11) | fail (1) | MEASURED |
| X11 | P0 | | fail | fail | unchanged | pass | pass | unchanged |
| F3 | P0 | | fail | fail | unchanged | pass | pass | unchanged |
| O4 | P0 | | fail | fail | unchanged | pass | pass | unchanged |
| E1 | P0 | | pass | pass | unchanged | fail | fail | unchanged |
| E6 | P1 | | pass | pass | unchanged | fail | fail | unchanged |
| A6 | P0 | | void | void | unchanged | void | void | unchanged |
| S16 | P0 | ⛔ | void | void | unchanged | void | void | unchanged |
| E2, E4, E5 | P0 | | pass (judges) | pass | unchanged | pass (judges) | pass | unchanged |
| G1 | gate | | assisted | assisted | unchanged | assisted | assisted | unchanged |
| the other 71 checks | | | pass | pass | unchanged | pass | pass | unchanged |

### Why each changed status is MEASURED

- **X4, build-1.** The real `x4()` replays end to end and consumes every recorded request, with no unrecorded calls.
  - With `MASTER=old` alone, the 7 reads returned 500 `{"error":{"code":"internal_error","message":"internal error"}}`. Each body is logged in full, none truncated, and none holds a value or key material.
  - `_generic_5xx` accepts all 7. The other 5 asserts (rotation re-wrap 7/7 exact, new key alone 7/7, 0 reads succeeded) are unchanged.
- **X4, build-2.** It refused to become ready with `MASTER=old` and sent no reads, so fix 1 is not reached.
- **X2, both builds.** The SQL tamper and the reads are unchanged probes.
  - On each build, all 9 tampered reads (get, get v1 and export, for 3 transplants) returned the same generic 500 body, logged in full:
    - build-1: `internal_error`
    - build-2: `internal`
  - The 9 "want a 4xx" sub-asserts flip to ok.
  - The 6 "want an error" sub-asserts, the dst-before, src-after and restore controls, and the export no-leak asserts were ok before and stay ok. Nothing fails outside the replayed reads.
- **X10, build-1.** The 35 remaining fails are 500s on NUL input:
  - 28 raw path params
  - 2 query params: audit `actor`/`action` = NUL
  - 5 JSON fields = `\u0000`: `auth/token.email`, `admin/orgs.owner_email`, `members.email`, `tokens.project`, `tokens.env`

  The fixes change none of these probes or judgements (the `nul` payloads hold no `;`). Any one of them fails the check.
- **X10, build-2.** One fail remains: `POST /tokens` with name `"ci\u0000"` returned **201 and echoed `"name":"ci?"`**.
  - The `?` is a literal byte from the server. The harness log decodes with `errors="replace"` and would show U+FFFD, not `?`.
  - Fix 2 is a mismatch rule. Wherever the build shows the name (the 201 echo or the `GET /tokens` row for the id), it must equal the sent name. Here the build shows it in the echo and it differs, so the echo alone decides the fail. The unrecorded `GET /tokens` leg cannot rescue it.
  - r1 shows the same answer (`build-2/r1/logs/X10.log:3056`).

### X10 sub-asserts touched by the fixes

| Group | Probes per build | build-1 old → new | build-2 old → new | Basis |
|---|---|---|---|---|
| Raw `"; DROP TABLE` query params: changes?status, export?format, audit since/limit, admin/audit limit (fix 3) | 5 | FAIL → ok | FAIL → ok | ESTIMATED |
| Raw `"; DROP TABLE` query params: audit actor/action (fix 3) | 2 | FAIL → ok | FAIL → ok | ESTIMATED |
| Raw `"; DROP TABLE` path params (fix 3) | 35 | ok → ok | ok → ok | ESTIMATED |
| Homoglyph and fullwidth e-mails in admin/orgs.owner_email and members.email, 201 (fix 4) | 4 | FAIL → info | FAIL → info | MEASURED |
| Homoglyph and fullwidth e-mails in auth/token.email, 401 (fix 4) | 2 | ok → info/ok | ok → info/ok | MEASURED |
| Token name, accepted with the exact echo (fix 2) | 6 | ok → ok | ok → ok | echo MEASURED; list leg ESTIMATED (a list row can only add a mismatch fail) |
| Token name `ci\u0000` (fix 2) | 1 | ok (400) → ok | **ok (201) → FAIL** (echo `ci?`) | MEASURED |
| NUL-byte 500s (no fix) | | 35 FAIL → 35 FAIL | 0 | MEASURED |
| X10 fails in total | | 46 → 35 | 11 → 1 | |

Notes on the ESTIMATED groups:

- **Raw `"; DROP TABLE` query params, 5 probes.** The probe changed: `;` is now `%3B`, so the request is byte-identical to its `q` twin. The twin was sent just before it on the same state and got 400 on both builds. The most likely answer is that same 400, which is ok.
- **Raw `"; DROP TABLE` query params, audit actor/action.** Same reasoning. The `q` twin got 200 with `[]`, which mode "empty" accepts, so ok is the most likely answer.
- **Raw `"; DROP TABLE` path params, 35 probes.** The probe changed only by `;` → `%3B`. The `q` twin got the same 400 or 404 as the old raw probe, so ok is the most likely answer.
- **Token names accepted with the exact echo.** `GET /tokens` was not called in r2. The driver stubs it as status 0, so the verdict rests on the echo. Under the mismatch rule, a missing or unreadable list leaves the echo's ok standing. Only a list row whose name differs from the one sent could fail it. The most likely live result is that the list matches the echo, which is ok.

In this re-score, none of the ESTIMATED rows can change a check status. On build-1, X10 fails on the 35 NUL 500s whatever they return. On build-2, X10 fails on the measured `ci?` echo whatever they return. A surprise could only add fails to a check that already fails.

This does not hold for the "Fix 2 not applied" counterfactual. There, build-2's X10 passes only if every ESTIMATED raw-drop row answers ok. See below.

## Blockers and verdict

- **build-1.** X10 fails on 35 NUL-input 500s, which no fix touches. P0 is 94.7% and G1 is assisted, so the verdict is NOT SHIPPABLE. This is unchanged and MEASURED.
- **build-2.** X10 fails on one probe: a control-character token name accepted with 201 and echoed as `ci?`. The build shows the name and it differs from the one sent, so it fails under the mismatch rule. P0 is 97.3% and G1 is assisted, so the verdict is NOT SHIPPABLE. MEASURED: r2 and r1 both returned 201 with `ci?`.
  - **Without fix 2 (ESTIMATED).** build-2 would have 0 blockers: 148/150 P0 (98.7%), total 152, FIX-THEN-SHIP. It could not reach SHIP, because G1 is assisted.
    - This counterfactual is ESTIMATED, not measured. It needs X10 to pass for build-2 with fixes 1, 3 and 4.
    - That rests on two MEASURED groups. The 4 homoglyph/fullwidth e-mail 201s become informational under fix 4. The `ci?` 201 is X10's only other recorded fail.
    - It also rests on the 7 escaped raw-`;` query probes: changes?status, export?format, audit?since, audit?limit, admin/audit?limit, audit?actor and audit?action. The old raw-`;` requests all got 200 and failed. Fix 3 changed those requests, and the new ones were never sent. `out-new.json` reuses the answers of their byte-identical `q` twins: 400 for the five strict params, and 200 with `[]` for actor and action.
    - The 35 escaped raw-`;` path probes are ESTIMATED the same way.
  - **What a live run on f69b191bb8f1 must confirm** for that row to stand:
    - build-2 answers each of the 7 escaped raw-`;` query probes the way its `q` twin did: a 4xx for the five strict params, and a 4xx or 200 `[]` for actor and action.
    - It answers the 35 escaped path probes with a 4xx.
    - It returns nothing that X10's leak scan flags.
    - No other X10 assert fails.

    If any of these fails, build-2 fails X10 without fix 2 as well, and the row becomes NOT SHIPPABLE. The live run must also show that `ci\u0000` still gets 201 with a differing name, in the echo or in the `GET /tokens` row. Otherwise the main re-score's X10 fail for build-2 does not stand either.
  - So what is shown is narrower than "fix 2 alone decides this verdict". The fail fix 2 produces is MEASURED, and it is build-2's only remaining blocker in this re-score. That build-2 would be FIX-THEN-SHIP without it is ESTIMATED.
- **Order.** build-2 leads by 3 points (150 v 147), against 5 as graded. X4 closed 2 of the 5 points, and X2 adds 2 points to each build.

## Sensitivity (same evidence, other choices)

| Variant | build-1 | build-2 | Verdicts |
|---|---|---|---|
| Re-scored (this report) | 147, P0 94.7% | 150, P0 97.3% | NS / NS |
| X2 kept void | 145, P0 94.6% | 148, P0 97.3% | NS / NS |
| Fix 2 not applied (**ESTIMATED**: build-2 rests on the 7 escaped raw-`;` query probes, answers taken from their `q` twins) | 147 | 152, P0 98.7%, 0 blockers (ESTIMATED) | NS / **FIX-THEN-SHIP** (ESTIMATED) |
| A6 accepts {k, k+1} as well (not a fix in scope) | 149 | 152 | NS / NS |

## Still needed

- A live run of X2, X4 and X10 on both builds with f69b191bb8f1. It turns the ESTIMATED rows into observations: the 42 escaped raw-drop requests per build, and the `GET /tokens` list leg for the accepted names.
- No check status in the main re-score is expected to move, unless build-2's `ci\u0000` answer differs from r1 and r2.
- The "Fix 2 not applied" row stands only if build-2's 7 escaped raw-`;` query probes (and the 35 path probes) answer ok. The list under "Blockers and verdict" says exactly what to check.

## Files

- `~/coffer-grade-fix/r3-rescore.md`: this report
- `~/coffer-grade-fix/rescore/score.py` and `score.out.json`: the scoring arithmetic, all variants
- `~/coffer-grade-fix/rescore/out-old.json` and `out-new.json`: the driver re-run on 4a895ba4d9c6 and f69b191bb8f1. `out-new.json` is identical to `/tmp/hfix/out-new.json`. Revision 1's copies are kept in `/tmp/hfix/prev-84686bc05858/`.
- `~/coffer-grade-fix/rescore/report.txt`: the driver comparison report, redacted
- `~/coffer-grade-fix/CHANGES.md` and `~/coffer-grade-fix/harness/`: the fix step's edits, with revision 2 of fix 2
