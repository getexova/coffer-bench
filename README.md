# Coffer bench

Exova on an open-weights model scored 147. Claude Code on Opus 5.5 scored 146. Exova's run cost $13.76; Claude Code's cost $70.68.

Both were given the same spec for a production-grade secrets service: multi-tenant, envelope encryption, a two-person rule for protected environments, and a hash-chained audit log. Each built it alone, with no human help on the code. A suite of 85 black-box checks that neither builder saw then graded what each one shipped.

| | Exova | Claude Code |
|---|---|---|
| Model | DeepSeek V4.1 Flash, open weights | Claude Opus 5.5 |
| Score | 147 | 146 |
| Polish checks (P1) | 5 of 5 | 4 of 5 |
| Judged design checks (E2, E4, E5) | 3 of 3 | 3 of 3 |
| Total cost | $13.76 | $70.68 |

Both builds are scored on the same harness under the same rules. See [Results](#results).

Exova's cost comes from its gateway billing ledger. Claude Code ran through a proxy and has no bill of its own, so its cost is its logged token usage priced at Anthropic list rates: 1,074 calls and 111.8M tokens. That figure assumes every cache write was a 5-minute write. If they were all 1-hour writes, the total is $82.

Published 2026-10-30. Updated 2026-11-03.

This repository holds everything behind the result: both builds with their full git history, the spec, the grader, the harness code that ran it, and the raw grading output.

## Head to head

These four checks are where the builds differ.

Where Exova came out ahead:
- X16, clean git history. Exova's history holds no secrets. Claude Code's holds a test password in `test/e2e/helpers_test.go`.
- F18, forced password change. Exova makes a new user change their initial password before doing anything else. Claude Code reports the flag in `/me` but doesn't enforce it.

Where Claude Code came out ahead:
- F3, CLI exit codes. On a malformed key, Claude Code's CLI exits with 6, the code SPEC section 7 assigns. Exova's exits with 2.
- X11, error responses. Claude Code answers a NUL byte in a URL path with 404. Exova answers it with a generic 500.

Neither build cleared the ship bar. The bar is strict on purpose: one ship-blocker caps the verdict whatever the score. Both builds hit the same one, X10 (hostile input), on different inputs. Exova rejects NUL-byte input with a 500 in 35 places, so the request fails closed. Claude Code silently drops a NUL in two audit filters and answers 200 with the caller's own audit rows, where the grader wants a 4xx.

## The two runs

| | Exova (run 3) | Claude Code (c2) |
|---|---|---|
| Harness | Exova Team (desktop engine `fc90e43`) | Claude Code 2.1.310, `ultracode` workflow |
| Models | DeepSeek V4.1 Flash for every role except Reviewer (GLM-5.3-Flash). Cost-Saving preset, builders at `high` effort | Claude Opus 5.5 (`claude-opus-5-5`), effort `high`, through an Anthropic-compatible endpoint |
| Run id | `armB-20261028-154212` | c2, 2026-10-30 |
| Prompt | the protocol prompt | the same prompt with `ultracode ` prepended |
| Human input | 3: plan approval and two verbatim `Continue.` | none after the prompt |
| Cost | $13.76 (gateway ledger, 2,730 calls) | $70.68 at list price (1,074 calls: 106.4M cache reads, 3.8M cache writes, 1.5M output) |
| Language | Go | Go |
| Graded commit | `b5426446` (37 commits) | `ba861e56` (6 commits) |

Both builds started in an empty directory holding only `SPEC.md` (sha256 `66db7199…e463a9e`). Both ran as a separate OS user on a fresh VM that could not read the grader.

## Results

| | Exova run 3 | Claude Code c2 |
|---|---|---|
| Same harness and same rules | 147, P0 142/150 (94.7%), P1 5/5 | 146, P0 142/148 (95.9%), P1 4/5 |
| As graded | 143, P0 138/148 (93.2%), P1 5/5 | 138, P0 134/148 (90.5%), P1 4/5, harness total before its judged checks were scored |
| Ship-blockers hit | X10 | X10 |

The as-graded totals came from different harness versions, so they aren't directly comparable. The first row puts both builds on harness `9f2f03b9a573`'s rules with the same void set. On that row Exova scores higher, at about one fifth of the cost.

E2, E4 and E5 are worth 6 P0 points and cover authorization tests, a truthful `SECURITY.md`, and `ARCHITECTURE.md`/`DECISIONS.md`. Both builds passed all three, each judged by two independent judges.

The verdict is the same for both: not shippable, because both hit X10. Ship-blockers are scored separately from points, and one is enough to hold a build back.

### Check by check

Every check not listed passed on both builds.

| Check | What it tests | Exova run 3 | Claude Code c2 |
|---|---|---|---|
| X10 (ship-blocker) | hostile input (NUL bytes, injection strings) never yields a 5xx or a wrong answer | fail: 500 on 35 NUL-byte inputs | fail: 200 with the caller's own audit rows for `audit?actor=%00` and `?action=%00` |
| F3 | CLI exit codes match SPEC section 7 | fail: exits 2 on a malformed key; SPEC says 6 | pass |
| X11 | error responses keep the SPEC shape | fail: generic 500 for a NUL byte in the path (same root cause as X10) | pass |
| O4 | one structured log line per request | fail: logs `/api/v1` requests only, not `/healthz` and other root paths | fail: logged nothing during one window of the scored run; 4/4 when re-run alone |
| X16 | no secrets in git history | pass | fail: test-fixture password in `test/e2e/helpers_test.go` |
| F18 (P1) | forced password change on first login | pass | fail: flag reported in `/me`, not enforced |
| X5 | password hashes are argon2id/bcrypt | pass | pass on every hash column; the harness misread `password_changed_at` as a hash |
| S4, S16 (ship-blockers) | platform admin and service tokens can't reach tenant data | S4 pass, S16 void | not evaluated (grader control bug) |
| A6 | audit-chain deletion is reported at the right sequence number | void (both builds answer N, GRADER says N+1) | void (same) |

## How it was graded

- Blind. Each build was renamed `build-1` or `build-2` by a recorded coin flip before cloning. Graders saw only the bundle, `SPEC.md` and `GRADER.md`, and ran as separate OS users on a dedicated host.
- Black-box. The harness boots each build with its own `compose.yaml` and drives it through the HTTP API and the CLI. It never reads source, except where a check is explicitly about the repository (X15, X16, E1, E6).
- Scoring. P0 checks are worth 2 points and P1 checks 1. A void earns nothing and leaves the denominator. A ship-blocker failure caps the verdict at not shippable, whatever the score. SHIP needs zero ship-blocker failures, at least 90% of P0 points and a strict G1: a fresh clone and the README quickstart, followed exactly, reach a working `secrets get` within 30 minutes. G1 carries no points.
- G1. Exova run 3 got an assisted pass. Its `compose.yaml` uses the unqualified image `postgres:16`, which rootless podman with short-name enforcement won't pull without a TTY. One prerequisite pull fixed it. Claude Code c2 names `docker.io/library/postgres:16` in full. G1 was not run for c2; it carries no points, and c2's X10 ship-blocker already sets its verdict.
- Exova run 3 was graded on 2026-10-29 with harness `4a895ba4d9c6` and given a final score of 143. After a blinded fairness audit, four interpretation fixes were applied identically to both builds in that round (`grader/harness-f69b191bb8f1/INTERPRETATION-FIXES.md`). The re-score from the recorded responses is 147 (`results/exova-run3/notes/rescore-fixed-harness.md`).
- Claude Code c2 was graded on 2026-10-30 with harness `9f2f03b9a573`, which already contains those four fixes. Its adjudication notes are in `results/claude-c2/notes/`. E2, E4 and E5 were judged on 2026-11-03 by two independent judges who read the build's tests, docs and code; both passed all three (`judge-c2-1.md`, `judge-c2-2.md`). Unlike round 3, these judges were told the build's label.

### Grader issues and how each was handled

Four grader issues came up during grading. Each was settled under one rule for both builds, and the matched scores above already include it.

| Issue | How it was handled |
|---|---|
| X2, X4: a literal reading of "any 500 fails" also fails a generic, value-free 500 on tampered ciphertext. | Fixed in the harness (interpretation fix 1, in `harness-f69b191bb8f1` and `harness-9f2f03b9a573`). |
| A6: GRADER says "the following sequence", but SPEC only says "first invalid sequence number". Both builds answer N. | Voided for both builds. |
| X5: any column with "pass" in its name is read as a password hash, timestamps included. | Corrected in adjudication and scored on the real hash columns. |
| S4/S16 control: the positive control grants a project to a user it has just made admin. SPEC lets a build refuse that, and c2 does (400, "grants apply only to members"), so the check stops early. | S4 left out of c2's denominator; S16 void for both. |

X5 and S4 are corrected at scoring time. Their harness code is unchanged, so a re-run reproduces the raw result in `results/`.

## Layout

```
SPEC.md                         what the builders saw (same bytes as grader/SPEC.md)
grader/GRADER.md                the acceptance suite (hidden from builders)
grader/PROTOCOL.md              how runs and grading are conducted
grader/harness-4a895ba4d9c6/    harness that graded Exova run 3
grader/harness-f69b191bb8f1/    + interpretation fixes (used for the re-score)
grader/harness-9f2f03b9a573/    + fix round 1; graded Claude Code c2
builds/exova-run3/              source at the graded commit
builds/exova-run3.bundle        full git history (git clone builds/exova-run3.bundle)
builds/claude-c2/
builds/claude-c2.bundle
results/<build>/results.jsonl   one line per check: status, points, evidence
results/<build>/summary.json    harness totals, before adjudication
results/<build>/logs/           per-check logs
results/<build>/notes/          adjudication, judges, G1, voids, re-score
```

## Reproduce

You need Linux with rootless podman 5.x, podman-compose, Python 3.12 or later, gitleaks, osv-scanner and mitmproxy. The graders used Fedora 44, 16 vCPU and 64 GiB.

```sh
podman pull docker.io/library/postgres:16
python3 -I grader/harness-9f2f03b9a573/run.py \
  --bundle builds/claude-c2.bundle --work /tmp/work-c2 --out /tmp/out-c2
```

A full run takes 10 to 15 minutes per build. G1, E2, E4 and E5 are manual (`grader/GRADER.md`).

## Notes on the artifacts

- Exova run 3's commit messages were replaced with `commit N` when the history was rewritten for blinding. The builder's own final commit was `7fae8c87`.
- In the round-3 notes, `build-1` is Exova run 3. `build-2`, and the labels `c1` and `r4` in the c2 notes, refer to other runs that are not published in this repository.
- Throwaway credentials the grader generated on its disposable stacks have been replaced with `<redacted-…>` in `results/`. The remaining strings secret scanners flag are canary values and test fixtures, listed in `.gitleaksignore`.
