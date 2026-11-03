# Harness integration (2026-10-26)

Integrator pass over registry.py, lib.py, fixture.py, run.py and the eight checks_*.py modules against CONTRACT.md v1.
Laptop only: nothing has run on gradevm or against a real build yet.

## Result

- Every file passes `python3 -m py_compile`. pyflakes reports no undefined names.
- `python3 -I run.py --list` exits 0 and prints 85 rows. Each ID appears exactly once, and the set equals the IDs in GRADER.md (diffed). 81 are `impl` and 4 are `na` (G1, E2, E4, E5).
- **No source changes were needed.** I edited no harness file. Every check's logic is as its author wrote it.

## What was verified, and how

1. **Call signatures (AST).** Every `c.<method>(...)` call in checks_*.py and fixture.py was checked against `inspect.signature(lib.Context.<method>)` for whether the method exists, for unknown keyword arguments and for too many positional arguments. Every `from lib/registry import X` and `lib.X` was also checked. 0 mismatches.
2. **Record fields.** The attributes modules read on Resp, CliResult, Proc, Psql, Override, Actor and Hit match the lib dataclasses. `.returncode` and `.stdout` are only used on raw `subprocess` results (git, jq, podman top/kill).
3. **Contract rules (AST, transitive through module-local helpers):**
   - No `print`, `sys.exit`, `os._exit`, `signal.signal` or `os.chdir` inside a check.
   - `c.sweep()` is only called from X1, X6, A3 and O5.
   - `c.env_override`, `c.wipe_volumes` and `c.restore` are only called from destructive rows.
   - F17, O1, O3 and O6 stop or restart the stack (`down/up` or `compose stop db`). They are not destructive in registry.py, which is the authoritative source. The contract restricts only env_override to destructive rows. Each of them restarts the stack itself (O1 in `finally`), and the runner's guard runs afterwards.
4. **State handoff.**
   - fixture.json keys that modules read (users.*, tokens.*.{id,token,expires_at}, orgs.*.id, canaries, multi_core, projects) are the keys fixture.py writes.
   - setup.json keys that lib and run.py read (port, base_url, proxy_url, cli.{json_position,bin}, compose, commit, up_rc, up_ms, readyz_status) are the keys fixture.setup writes.
   - The only cross-check `c.put` is `F12.change_id`, which no other check reads. Nothing depends on the order in which `c.state` entries are written.
   - lib `put` saves immediately, and run.py `child_main` saves again after the check.
5. **Child smoke test.** I ran `run.py --_child ID` for each of the 80 non-na, non-F1 rows against a fake HTTP server (`/readyz` 200, everything else 404), a stub `bin/coffer` (exit 1), a fake compose (`false`) and a synthetic fixture.json.
   - All 80 returned a Result. None returned a harness exception (TypeError, AttributeError, KeyError, NameError).
   - Each one ended in `error` (control or precondition failed) or `fail` (CLI rc 1 against a live /readyz), which is the expected outcome.
   - Two errors came only from reusing `c.tmp` between my smoke runs (E1 and G3 clone into an existing dir). The runner's `fresh_tmp` removes that dir before every check, and the e2e run below confirms it.
6. **End-to-end runner.** I ran `run.py --bundle dummy --work W --out O` on a 1-commit dummy repo whose init-env.sh fails.
   - It exited 0. results.jsonl has 85 unique lines in run order.
   - Rows with stack=True came out as `error: setup failed at S2`. The static rows ran. Teardown ran, then E1 ran after it. The na rows were recorded with `points: null`.
   - summary.json was written with `verdict_note` PROVISIONAL.
   - In that run X15 controlled correctly: the django==1.11.0 control found High findings, then the dummy repo with no lockfile got `fail`.

## Behaviors to note (kept, not changed)

- **E1** clones `WORK/repo`, not the bundle file, then asserts HEAD == `setup.commit` and that the clone is clean. This is the same commit, so the result is the same. CONTRACT §9 says "clone of the bundle".
- **osv-scanner** rc 128 = "no packages found" → X15 `fail` (no lockfiles). This is a build verdict, not a harness error.
- **lib `_cli_prep`** sets `COFFER_TOKEN=<PAT>` for a user actor with no `home` (scratch users). The contract defines this only for token actors. It is the same for both builds.
- **F12** `c.put("change_id")` is unused downstream (harmless).

## Not yet verified (the first VM run should check these)

- Real compose, psql, pg_dump and rollback paths: rollback, base checkpoint, `server_db_role`, and sweep dumps against podman on gradevm.
- mitmdump presence on the VM, for S5/X18. Without it, X18 is `error: proxy not running`.
- gitleaks/osv-scanner on the VM PATH (`/usr/local/bin`, `~/.local/bin` searched). `tools/osv-scanner` must be installed there.
- Timing-sensitive rows: S17 (T_exp expiry wait), X7 (latency), O3 and O10.

---

# Re-integration pass 2 (2026-10-26, after the 16:28-16:35 module edits)

Done after INTEGRATION pass 1 (15:34). Since then, fixture.py (15:39), checks_s_b.py and checks_x_b.py (16:28), checks_x_a.py (16:33) and checks_a.py (16:34) had changed. I worked on the laptop only and read no build source.

## Result: step 1 passes. **No source changes were needed.**

- All 12 .py files pass `python3 -m py_compile`.
- pyflakes finds no undefined names and no other real errors. The only hits are unused imports and variables.
- `python3 -I run.py --list` and `python3 run.py --list` both exit 0 and print 85 rows: 81 `impl` and 4 `na` (G1 E2 E4 E5).
- Each ID appears exactly once. The ID set equals the GRADER.md bullet IDs, including the five `(P1)`-suffixed ones: E6 F18 O10 X19 X20 (diffed).
- I edited no harness file in this pass.

## Re-verified against the current files (scripts in /tmp/integ2/)

1. **Signatures (AST vs `inspect.signature(lib.Context.*)`).** 0 real mismatches.
   - The only hit was `c._env_file(path)` in X3/X4. It is a false positive: `_env_file` is a `@staticmethod`, so the call is correct.
   - Every `from lib/registry import X` and every `lib.X` resolves.
2. **`c.<attr>` reads.** All exist on Context. The exception is `c._x429` (checks_x_a's local 429 back-off budget), which is set via `getattr`/assignment on the plain Context instance. That is valid because Context has no `__slots__`.
3. **Record fields** (Resp, CliResult, Actor, Psql, Proc, Override, Hit). All flagged reads were variable reuse within one function, for example `r` rebound from `c.psql` to `c.api`. None is a real drift.
4. **Contract rules (transitive through module helpers).**
   - No `print`, `sys.exit`, `os._exit`, `signal.signal` or `chdir` in any check.
   - `c.sweep` is called only from X1, X6, A3 and O5.
   - `env_override`, `wipe_volumes` and `restore` are called only from D rows (G3 X3 O8 O7 X4).
5. **Order.** It matches CONTRACT §phases: F1 → static → F block (F17 last) → X18 → S → X → A → O → 800 env-override → 900 restore-class → 950 sweeps → teardown → E1 → na.
6. **State handoff.**
   - The only `c.put` is still `F12.change_id`, and nothing reads it.
   - The fixture keys that modules read (canaries, tokens, orgs, projects, multi_core, users) are all written by fixture.py.
   - The platform admin label is `"root"` (CONTRACT §2, fixture.py:628).
7. **Child smoke.** I ran 39 rows from the changed modules against a fake HTTP server (`/readyz` 200, all else 404), a stub CLI (exit 1) and a synthetic fixture: S13-S20, X1-X14, X17-X20, A1-A8, X2-X4 and X10.
   - Every row returned a Result with status `error` and a specific precondition or control message.
   - There was no harness exception (TypeError, AttributeError, NameError).
   - A `KeyError: unknown actor 'root'` came from my synthetic fixture mislabelling root. It disappeared once the fixture used `"root"`.

## Still open (unchanged from pass 1)

On gradevm, the first real run must check these: the compose/psql/rollback paths, mitmdump for X18, gitleaks/osv-scanner on PATH, and the timing rows (S17, X7, O3, O10).
