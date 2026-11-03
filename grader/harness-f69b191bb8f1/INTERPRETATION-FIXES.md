# Harness fixes after grading round 3 (r3-fix)

**What this is.** These are interpretation changes to the grading harness, made **after** a graded round. The founder asked for them on 2026-10-29. They come from the blinded fairness audit (`~/coffer-grade-r3/notes/fairness-audit.md`, "Harness fixes for the re-run" and section 3). They are not bug fixes discovered before scoring. Each change applies identically to both builds and is the smallest edit that implements its rule. The work was blinded: builds are named only build-1 and build-2, no build source was read, nothing ran on any VM, and no secret was printed. Nothing is committed.

- **Starting tree:** `~/coffer-grade-r3/harness`, copied without `__pycache__`. It hashes to **4a895ba4d9c6**, the tree both scored r2 runs used (`notes/run-build-1-r2.md:7-9`, `notes/run-build-2-r2.md:7-9`; `notes/fix-harness-r1.md` moved it from 00dcf74bd482).
- **New tree:** `~/coffer-grade-fix/harness`, hash **f69b191bb8f1**. Computed the same way as v2: `find . -type f -name '*.py' | sort | xargs sha256sum | sha256sum | cut -c1-12`, run in the tree with no `__pycache__`.
  - Revision 1 of this tree hashed **84686bc05858**. A skeptic refused it, and revision 2 changes only fix 2 (see "Revision 2" below). Score the live re-run with f69b191bb8f1, not 84686bc05858.
- **Files changed:** only `checks_x_a.py`. The other 11 .py files and all .md files are byte-identical to 4a895ba4d9c6.
- **Rule-free parts:** `registry.py` already has X2 and X4 as `allow_5xx`, so the runner's "5xx seen → fail" rule (run.py R4) never applied to them. The verdict comes only from the in-check assertions edited below. X10 is not `allow_5xx`, and none of the edits touch its 5xx handling.

## The four edits

Line numbers refer to the new `checks_x_a.py`.

### 1. Rule A: a generic SPEC-shaped 5xx on a server-side decrypt failure passes (X2, X4)

- **Rule.** A read that hits data the server cannot decrypt may answer with a 5xx, but only if all of these hold:
  - The body has the SPEC error shape `{"error":{"code","message"}}` with non-empty strings. This reuses X11's `_shape`.
  - It matches none of X11's stack, SQL or path patterns. This reuses X11's `_leaks`.
  - It contains no registered secret value (raw or JSON-escaped) and no key material. For a key, this covers the base64 string and the key bytes as hex, HEX and b64url.
- **What still fails:**
  - a 2xx
  - a transport error while the server is up
  - a 5xx that is not generic
  - every existing no-leak and control assertion: X2's export-contains-dst-key, export-contains-source-value, "dst readable before", "src readable after" and "dst reads back after restore"; X4's "any 2xx in step 3 fails" and every readability assertion in steps 1 and 2.
- **Edits:**
  - **`_generic_5xx(c, r)`, a new helper at 1271-1295.** It imports `_shape` and `_leaks` lazily from `checks_x_b`, so X11's definition is not duplicated.
  - **x4, MASTER=old step, 1351-1358.** A 5xx or status-0 read joins the failing list `five` only if `_generic_5xx` rejects it. The message now says "non-generic 5xx/transport" and gives the reason for each read.
  - **x2, tampered get and get v1, 1545-1549, and export, 1559-1562.** The condition was `status < 500 and (status != 0 or not up)`. It is now that condition `or g5`. Before, the expression was all of the check.
  - **Docstring, 33-34 (X2) and 46-47 (X4).**
- **What it rests on:**
  - GRADER.md:79 (X2): "Each read must error. Returning any value at all = fail."
  - GRADER.md:81 (X4): "fails closed (refuses or errors), never garbage."
  - SPEC.md:64: "A ciphertext copied into another row must fail to decrypt. It must never return a value."
  - SPEC.md:88: "Errors use the JSON body {"error":{"code":"...","message":"..."}}. No response contains a stack trace, SQL text or an internal path."
  - The SPEC status table (SPEC.md:276-287) has no 4xx for an authenticated, valid request that hits operator-corrupted data. Every 4xx there is a client fault.
  - This sets aside GRADER.md:6 ("Any 500 anywhere is a fail") **for these decrypt-failure reads only**, as the void review did for X2 (`notes/voids.md`, X2 row). Before, X4 still failed on that line. That inconsistency is what this edit resolves.

### 2. `v_ok` rejects a token name the build shows differently from the one sent (X10, token name)

- **Rule.** This is a mismatch rule, applied to a name accepted with a 2xx.
  - The name can be shown in two places: the 201 echo, and the `GET /tokens` row with the same `id`. Wherever the build shows it, it must equal the sent name byte for byte. If either one differs, the probe fails.
  - A name counts as shown when the field is present and not null. An empty string is shown, and it differs.
  - If the build shows the name in neither place, the read-back cannot be tested. That leg passes, and the harness records an `ASSERT ok` line that says "read-back not testable" and gives the `GET /tokens` status. These cases are not testable: no `name` in the 201, no row for the id, a row without `name`, `name: null`, no `id` in the 201, and a `GET /tokens` that is not 2xx or not JSON.
  - The token is still registered for the sweep, as before.
- **Edit.** `v_ok` at 1034-1058. It used to `return True, ""` unconditionally, at old lines 1025-1029.
- **What it rests on:**
  - The harness's own docstring, lines 77-81: "Free-text fields where SPEC allows any string (secret value, token name, …) may be 2xx only if the value round-trips." Lines 79-81 now say how that applies to a token name.
  - SPEC.md:267: `POST {project, env, access, ttl_seconds, name?} -> {id, token}`. The name is optional, the 201 shape has no name, and SPEC gives `GET /tokens` no response shape. So a build is not required to show the name anywhere, and a build that never shows it must not fail. Only a name the build does show can be checked.
  - SPEC.md:282: "400 | validation". Rejecting a name it will not store is always open to a build.
  - The audit's evidence: `ci\u0000` accepted with 201 and echoed as `ci?` (`results/build-2/r1/logs/X10.log:3056`, same at `r2/logs/X10.log:3056`). The build shows the name and it differs, so it fails under the mismatch rule as well.

### 3. Percent-escape `;` in `_raw_seg` (X10)

- **Rule.** The raw variant still leaves most characters unescaped. It now also escapes `;`, so a raw `;` cannot reach the HTTP framework's query-separator parsing. With `;` escaped, the `"; DROP TABLE` probes test the API's validation and no longer test how the framework splits `;`.
- **Edit.**
  - Line 769: `elif ch in '"#?':` becomes `elif ch in '"#?;':`.
  - Docstring line 76.
- **Effect on requests.** Only the `drop` payload contains `;`. Its raw variant is now byte-identical to its `q` variant (`%22%3B%20DROP%20TABLE`). The probe count is unchanged.
- **What it rests on:**
  - GRADER.md:87 (X10): the payload is `"; DROP TABLE` "in every … query param". The probe has to deliver that value to the API as a parameter value.
  - `notes/voids.md`, X10 row: "the raw unescaped `;` 'DROP' query variants make the server ignore the filter and return the caller's own data (7 asserts on each build) … Harness should still fix the raw `;` variants."
  - The audit's section 3, rule B: "strike the raw-`;` probes".

### 4. Homoglyph and fullwidth e-mails are informational (X10), the same standard as A6's k+1

- **Rule.**
  - **The probes affected.** The rule covers the `homoglyph` and `fullwidth` payloads in the three JSON e-mail fields X10 probes: `auth/token.email`, `admin/orgs.owner_email` and `members.email`. For these probes a 2xx/3xx is logged as `X10 INFO (not scored)` and is not an assertion.
  - **What still fails on them:** a 5xx, a transport error, and any foreign or unrequested data in the body. Those are GRADER rules this audit did not question.
  - **What is unchanged:** every other payload on these fields (`' OR 1=1--`, `"; DROP TABLE`, `../../etc/passwd`, `%00`, NUL) and every homoglyph probe on non-e-mail fields stay strict.
- **Edit.**
  - **judge,** 833-835: a new `mode == "info"` branch, reached only after the leak, transport and 5xx checks.
  - **JSON loop,** 1189-1190: the mode is set to `"info"` for `fld in ("email", "owner_email") and pl_name in ("homoglyph", "fullwidth")`.
  - **Docstring,** 82-84.
- **What it rests on:**
  - GRADER.md:87 asks for "unicode homoglyphs in every … JSON field → 4xx".
  - SPEC says nothing about e-mail format or charset. It only names the fields, at SPEC.md:237, :242 and :246.
  - The void review voided A6 because SPEC.md:101 ("reports the first invalid sequence number") does not imply GRADER.md:106's "at the following sequence". The fairness audit (section 1, "X10 void standard") asks that the same standard apply here.
  - The audit counted 4 probes (2 fields × 2 payloads, all 201 on both builds). `auth/token.email` is the third e-mail field and falls under the same rule. It returned 401 on both builds, so including it changes no outcome.

## Validation (offline; no VM)

- **Compile.** `python -m py_compile` ran after each edit, and again on all 12 .py files at the end. All OK.
- **Lists and imports.**
  - `python3 -I -B run.py --list` exits 0 with 85 rows, byte-identical to the 4a895ba4d9c6 listing.
  - `registry.load_all()` imports every module and reports no missing implementations.
  - The harness has no other unit or fixture test suite.
- **Replay driver, `/tmp/hfix/driver.py`.** It feeds the responses recorded in `results/build-{1,2}/r2/logs/{X2,X4,X10}.log` into the harness's own code, once with a copy of 4a895ba4d9c6 and once with the new tree:
  - **X4:** the real `x4(c)` runs end to end on a `lib.Context` subclass. Its `http`, `env_override` and `wait_ready` return the recorded results in order.
  - **X2:** the post-tamper read statements, AST-extracted from x2, run on the 9 recorded tampered reads.
  - **X10:** the real `_X10.judge`, `v_ok`, `_raw_seg` and e-mail mode statements run on every probe the edits can touch.
  - Redacted «labels» become deterministic fakes that are registered as the same secrets.
- **Fidelity.** On the old tree, the replay reproduces every recorded r2 result, for both builds:
  - X4: status and all assertion messages are identical, and every recorded request is consumed.
  - X2: the 15 replayed assertions are identical to the recorded ones.
  - X10: the touched probes reproduce exactly the 11 recorded fails on each build.
- **Old → new per sub-assert:**

| | build-1 | build-2 |
|---|---|---|
| X4 | fail → **pass** (7 × generic 500 `internal_error`, no value) | pass → pass (refused to become ready) |
| X2 | fail → **pass**: 9/9 "want 4xx" sub-asserts now ok (generic 500); the 6 "want an error" sub-asserts and all controls are unchanged and ok | fail → **pass**, same 9/9 |
| X10 raw `"; DROP TABLE` | 7 query fails → ok. The new request equals the `q` twin, whose recorded answer was 400, or 200 with `[]` for audit actor/action. The 35 path variants stay ok. | same 7 → ok |
| X10 homoglyph/fullwidth e-mail | 4 fails (201) → info; 2 × auth/token 401 stay ok | same 4 → info |
| X10 token name | 6 × 201 echo exact → ok; `ci\u0000` 400 → ok | 6 × 201 echo exact → ok; `ci\u0000` 201 echoed `ci?` → **FAIL** |
| X10 total | 46 → 35 fails, still fail (35 NUL-byte 500s, all unchanged) | 11 → 1 fail, still fail on a ⛔: the only remaining fail is the token-name round-trip. With fixes 3 and 4 but not fix 2 it would pass, but that is ESTIMATED: it needs the 7 escaped raw-`;` query probes to answer the way their `q` twins did |

These results match the audit's section 3 ("A and B, round-trip enforced"). X2 had been voided for both builds by `notes/voids.md`. Whether it is un-voided under the new harness is a scoring decision and is not taken here.

- **Synthetic cases, `/tmp/hfix/unit.py`.** 50 of 50 pass on f69b191bb8f1:
  - `_generic_5xx`: generic 500/503 pass. These fail: a 4xx, status 0, a non-JSON body, the wrong shape, an empty code, a Traceback, SQL text, the secret value, and the key as b64, hex, HEX or b64url.
  - `v_ok`, 18 cases, each run on both `GET /tokens` shapes seen in r2 (`{"tokens":[…]}` and a bare list):
    - Pass: echoed equal; listed equal; both equal; homoglyph stored exactly; another id's row with a different name is ignored.
    - Fail: echoed different (the build-2 r2 shape `ci?`); listed different with no echo; echo right but list wrong; echo wrong but list right; empty-string echo.
    - Pass, recorded as not testable: shown nowhere; a row for the id without `name`; `name: null` in both; only another id's row; `GET /tokens` 500; no `id` in the 201.
    - Each case also checks that every assert v_ok records is ok, and that it makes exactly the one `GET /tokens` call.
  - Run against revision 1 (84686bc05858), the same file gives 12 fails. They are the 6 not-testable cases on each shape, which revision 1 failed. The mismatch cases agree.

## Revision 2 (2026-10-29): fix 2 narrowed to a mismatch rule

- **Why.** A skeptic refused revision 1 (84686bc05858). Its fix 2 also failed a token name the build never showed: `if not got: return False, "name not read back ..."`. SPEC.md:267 gives `POST /tokens` no name in the 201 and gives `GET /tokens` no shape. A SPEC-compliant build that accepted the optional name and showed it nowhere would have failed X10, which is a ship-blocker. That went past the rule.
- **Change.**
  - `v_ok`, 1034-1058, as described under fix 2. A name shown nowhere now passes that leg, with an ok assert saying it was not testable.
  - A row without a `name` key now counts as not shown. Revision 1 compared that `None` with the sent name, so it failed too.
  - The fail message now names its source: `name shown as 'ci?' in the 201 echo, sent 'ci\x00'`.
  - Docstring lines 79-81.
  - No other line changed. Fixes 1, 3 and 4 are byte-identical to revision 1.
- **Checks.**
  - All 12 .py files compile.
  - `run.py --list` still gives the same 85 rows, byte-identical to 4a895ba4d9c6.
  - `registry.load_all()` reports no missing implementations.
  - `unit.py`: 50 of 50 pass.
  - The replay driver on 4a895ba4d9c6 still reproduces every recorded r2 result.
  - The replay driver on f69b191bb8f1 matches revision 1 for every probe status. The only output differences are the fail message above and the extracted `v_ok` source.
  - build-2's recorded `ci\u0000` → 201 `ci?` echo still fails X10. build-1 is unchanged: X4 pass, X2 pass, X10 fail on the same 35 NUL-byte 500s, and `ci\u0000` → 400 ok.
  - r2 never reached the shown-nowhere branch. Every accepted name was echoed: 6 on build-1 and 7 on build-2. So their results do not depend on the change.
- **Driver fix.** `judged()` in `/tmp/hfix/driver.py` reported the first new assert as FAIL whether or not it was ok. It now reports only a failed one. Revision 1's code never recorded an ok assert inside `judge`, so revision 1's outputs were not affected. The old-tree output is byte-identical after the fix.

## Open items

- r2 never called `GET /tokens` after an X10 token probe, so offline the driver stubs it as status 0. The token-name results above rest on the recorded 201 echo. The list leg is covered only by the synthetic cases until the live re-run.
- The new raw-drop results reuse the recorded answer of the byte-identical `q` request sent just before it. They were not observed directly.
- **Gaps not changed here, recorded for whoever re-scores:**
  - X4 does not scan a **4xx** body for values. Rule A is checked only on 5xx.
  - The non-homoglyph payloads on e-mail fields stay strict.
- Every effect above comes from an offline replay. The re-score needs a live run of X2, X4 and X10 on both builds with f69b191bb8f1.
