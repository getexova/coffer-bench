"""Coffer grading checks: F2-F18 (functional block, GRADER.md lines 28-44).

Black-box only: ./bin/coffer (SPEC 7.1), the HTTP API (SPEC 7.2) and the
SPEC 5 scripts. Never reads build source. Identical for both builds.

Readings (stricter on the build, identical for both builds):
R1  Keys written in acme/api/dev and acme/api/prod are prefixed "<ID>_" plus a
    random hex suffix, so re-runs never collide. Keys that must be INVALID
    (F3 bad keys) and the F8/F9 reference values go to a scratch project of
    owner@acme, never to the fixture envs.
R2  CLI is the system under test. Writes in acme/api/dev use writer@acme's
    fixture HOME (writer is allowed); protected-env proposals use writer@acme,
    approvals/rejections use admin@acme. Raw API reads are cross-checks.
R3  Values are fed through stdin (`secrets set KEY` without VALUE), except the
    F2 "empty string" case, which is tested both as positional "" and as empty
    stdin, and both must store the empty value.
R4  Version lists: CLI --json history may be a list or an object wrapping a
    list (items/versions/data/history). Only the version numbers and the
    deleted flag are read. The API /versions list is the cross-check.
R5  A change id is taken from the CLI stdout (exit 7). It must also appear in
    the API /changes?status=pending list as owner@acme; a printed id that is not
    in that list is a fail.
R6  "Audit shows proposer and approver" (F12): among acme audit events since the
    check started (GET /audit?since=, owner@acme), at least one event mentions
    the change id or key and carries writer's user id (or email), and at least
    one carries admin's user id (or email).
R7  F10 child commands are python3 -I (sys.executable, absolute path) and
    /bin/sh; nothing else is assumed on the VM. SIGTERM is sent to the coffer
    process only (os.kill(pid)), never to its group, and the child records the
    signal in a marker file under c.tmp.
R8  F11 "creates no config file": after the call, the empty HOME contains no
    regular file anywhere (empty dirs tolerated, logged).
R9  F16 token create: the printed token is registered as a secret before
    anything is logged (local quiet spawn), and the token is revoked after.
R10 F17: the stack must actually be down between down.sh and up.sh
    (/readyz not 200), otherwise the check errors (nothing was proven).
    After up.sh: every fixture canary readable by its org owner with the
    recorded value, the F17 marker key keeps value and both versions, and the
    fixture owner PAT still works (sessions are data too).
R11 F18 uses a fresh member created through `coffer member add` by owner@acme;
    "any other call" is probed as `project list` in the CLI and GET /projects on
    the raw API; both must be refused (any non-success) before `passwd`, and
    succeed after. The old password must stop working (401) after the change.
lib gaps implemented locally: _qcli (spawn that registers a printed token
before logging), _items (tolerant list extraction).
"""
from __future__ import annotations

import datetime
import json as _json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import lib
from registry import Result, check, not_implemented  # noqa: F401

P, DEV, PROD = "api", "dev", "prod"
W, ADM, OWN = "writer@acme", "admin@acme", "owner@acme"
T = 60.0  # per CLI call timeout (s)


# ---------------------------------------------------------------- helpers

def _key(c, tag: str = "") -> str:
    return f"{c.id}_{tag}{secrets.token_hex(4).upper()}" if tag else f"{c.id}_{secrets.token_hex(4).upper()}"


def _rand(n: int) -> str:
    al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(al) for _ in range(n))


def _canary(c, label: str, n: int = 40) -> str:
    return c.secret(f"canary:{c.id}:{label}", _rand(n), "canary")


def _set(c, key, value: bytes, *, actor=W, env=DEV, proj=P, extra=(), pos=False):
    if pos:
        return c.cli("secrets", "set", key, value.decode(), "-p", proj, "-e", env, *extra, actor=actor, timeout=T)
    return c.cli("secrets", "set", key, "-p", proj, "-e", env, *extra, actor=actor, stdin=value, timeout=T)


def _get(c, key, *, actor=W, env=DEV, proj=P, version=None):
    a = ("--version", str(version)) if version is not None else ()
    return c.cli("secrets", "get", key, "-p", proj, "-e", env, *a, actor=actor, timeout=T)


def _items(obj):
    """First list of dicts in a JSON doc (list itself, or a wrapper key)."""
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for k in ("items", "versions", "history", "data", "changes", "events", "secrets",
                  "results", "change_requests", "audit"):
            if isinstance(obj.get(k), list):
                return obj[k]
        for v in obj.values():
            if isinstance(v, list) and (not v or isinstance(v[0], dict)):
                return v
    return None


def _api_value(c, key, *, actor=OWN, env=DEV, proj=P):
    r = c.api("GET", f"/projects/{proj}/envs/{env}/secrets/{key}", actor=actor)
    v = None
    if r.status == 200:
        try:
            v = r.json().get("value")
        except (ValueError, AttributeError):
            v = None
    return r.status, v


def _api_versions(c, key, *, actor=OWN, env=DEV, proj=P):
    """[(version:int, deleted:bool)] from the API, or None."""
    r = c.api("GET", f"/projects/{proj}/envs/{env}/secrets/{key}/versions", actor=actor)
    if r.status != 200:
        return None
    try:
        it = _items(r.json())
    except ValueError:
        return None
    return _vers(it)


def _vers(it):
    if it is None:
        return None
    out = []
    for x in it:
        if not isinstance(x, dict):
            return None
        try:
            v = int(x.get("version"))
        except (TypeError, ValueError):
            return None
        d = x.get("deleted")
        if d is None:
            d = bool(x.get("tombstone")) or x.get("action") in ("delete", "deleted")
        out.append((v, bool(d)))
    return sorted(out)


def _cli_versions(c, key, *, actor=W, env=DEV, proj=P):
    r = c.cli("secrets", "history", key, "-p", proj, "-e", env, actor=actor, json=True, timeout=T)
    if r.rc != 0:
        return r, None
    try:
        return r, _vers(_items(r.json()))
    except ValueError:
        return r, None


def _pending_ids(c):
    r = c.api("GET", "/changes", actor=OWN, query={"status": "pending"})
    if r.status != 200:
        return None
    try:
        it = _items(r.json()) or []
    except ValueError:
        return None
    return {str(x.get("id") or x.get("change_id")) for x in it if isinstance(x, dict)}


def _change_status(c, cid):
    """Status of change cid from GET /changes (all statuses), or None."""
    for st in ("pending", "approved", "rejected", "stale"):
        r = c.api("GET", "/changes", actor=OWN, query={"status": st})
        if r.status != 200:
            continue
        try:
            it = _items(r.json()) or []
        except ValueError:
            continue
        for x in it:
            if isinstance(x, dict) and str(x.get("id") or x.get("change_id")) == cid:
                return str(x.get("status") or st)
    return None


_ID_RE = re.compile(r"[A-Za-z0-9_\-]{6,}")


def _propose(c, argv_tail, *, what, stdin=b""):
    """Run a protected write as writer. Returns change id (str) or None. Asserts exit 7."""
    before = _pending_ids(c)
    r = c.cli(*argv_tail, actor=W, stdin=stdin, timeout=T)
    if not c.expect(r.rc == 7, f"{what}: rc={r.rc} (want 7)"):
        return None
    after = _pending_ids(c)
    if before is None or after is None:
        c.error_once(f"{what}: GET /changes?status=pending as owner failed")
        return None
    new = sorted(after - before)
    out = r.out.decode("utf-8", "replace")
    printed = [n for n in new if n in out]
    if not c.expect(len(printed) == 1, f"{what}: change id not printed on stdout (new pending={len(new)}, "
                                       f"stdout={out.strip()[:80]!r})"):
        return None
    return printed[0]


def _qcli(c, *args, actor=None, home=None, json=False, timeout=T):
    """CLI call whose stdout may carry a fresh token: register it before logging."""
    p = c.cli_spawn(*args, actor=actor, home=home, stdin=subprocess.DEVNULL, json=json)
    t0 = time.monotonic()
    try:
        out, err = p.communicate(timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        out, err = p.communicate()
        rc = 124
    for m in re.findall(rb"cof_(?:st|pat)_[A-Za-z0-9_\-]+", out + err):
        c.secret(f"token:{c.id}:{secrets.token_hex(3)}", m.decode(), "token")
    res = lib.CliResult(rc, out, err, (time.monotonic() - t0) * 1000, list(p.args))
    c.log("QCLI %s -> rc=%s\n  out: %s\n  err: %s", " ".join(["coffer"] + [str(a) for a in args]), rc,
          c.redact(out.decode("utf-8", "replace"))[:2000], c.redact(err.decode("utf-8", "replace"))[:1000])
    return res


def _dotenv_line(k: str, v: str) -> bytes:
    e = (v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
         .replace("\r", "\\r").replace("$", "\\$"))
    return f'{k}="{e}"\n'.encode()


def _since(c) -> str:
    t = c.now().replace(microsecond=0) - datetime.timedelta(seconds=5)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- F2

@check("F2")
def f2(c) -> Result:
    """set -> get byte-exact: empty, 1 byte, 65,536 bytes, MULTI, stdin ending in \n"""
    multi = (c.fx.get("canaries") or {}).get("acme/api/dev/MULTI")
    if not multi:
        return c.error("fixture MULTI canary missing")
    big = _canary(c, "big", 65536)
    cases = [
        ("EMPTY_POS", b"", True),
        ("EMPTY_STDIN", b"", False),
        ("ONE", _rand(1).encode(), False),
        ("BIG", big.encode(), False),
        ("MULTI", multi.encode(), False),
        ("NL", (_canary(c, "nl") + "\n").encode(), False),
    ]
    for tag, val, pos in cases:
        k = _key(c, tag + "_")
        s = _set(c, k, val, pos=pos)
        if not c.expect(s.rc == 0, f"set {tag} ({len(val)}B{' positional' if pos else ' stdin'}) rc={s.rc}"):
            continue
        g = _get(c, k)
        c.expect(g.rc == 0 and g.out == val,
                 f"get {tag}: rc={g.rc} len={len(g.out)} want {len(val)}B exact"
                 + ("" if g.out == val else f" (first diff at {next((i for i, (a, b) in enumerate(zip(g.out, val)) if a != b), min(len(g.out), len(val)))})"))
        st, av = _api_value(c, k)
        c.log("API cross-check %s: status=%s exact=%s", tag, st, av == val.decode())
    # fixture MULTI itself, read back via CLI
    g = _get(c, "MULTI")
    c.expect(g.rc == 0 and g.out == multi.encode(), f"get fixture MULTI rc={g.rc} exact={g.out == multi.encode()}")
    return c.done("empty(pos+stdin), 1B, 65536B, MULTI, trailing-\\n all byte-exact via CLI")


# ---------------------------------------------------------------- F3

@check("F3")
def f3(c) -> Result:
    """65,537 bytes -> exit 6, nothing stored; bad keys -> exit 6"""
    # control: exactly 65,536 bytes is accepted
    k_ok = _key(c, "MAX_")
    s = _set(c, k_ok, _canary(c, "max", 65536).encode())
    c.expect(s.rc == 0, f"control: 65,536 B set rc={s.rc} (want 0)")
    k = _key(c, "OVER_")
    s = _set(c, k, _canary(c, "over", 65537).encode())
    c.expect(s.rc == 6, f"65,537 B set rc={s.rc} (want 6)")
    g = _get(c, k)
    c.expect(g.rc == 5, f"after 65,537 B: get rc={g.rc} (want 5, nothing stored)")
    st, _ = _api_value(c, k)
    c.expect(st == 404, f"after 65,537 B: API GET -> {st} (want 404)")
    vs = _api_versions(c, k)
    c.log("versions after oversize: %s", vs)
    # bad keys in a scratch project (owner@acme)
    try:
        sp = c.scratch_project(OWN, envs=(("dev", False),))
    except lib.HarnessError as e:
        return c.error(f"scratch project: {e}")
    good128 = "F3_" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") for _ in range(125))
    r = _set(c, good128, b"v", actor=OWN, proj=sp)
    c.expect(r.rc == 0, f"control: 128-char key set rc={r.rc} (want 0)")
    for bad in ("lower", "1ABC", "A-B", "A" * 129):
        r = _set(c, bad, b"v", actor=OWN, proj=sp)
        c.expect(r.rc == 6, f"bad key {bad[:12]}{'..' if len(bad) > 12 else ''}({len(bad)}): rc={r.rc} (want 6)")
    lr = c.api("GET", f"/projects/{sp}/envs/dev/secrets", actor=OWN)
    try:
        keys = {x.get("key") for x in (_items(lr.json()) or [])}
    except ValueError:
        keys = set()
    c.log("scratch keys after bad-key attempts: %s", sorted(k for k in keys if k)[:10])
    c.expect(not ({"lower", "1ABC", "A-B", "A" * 129} & keys), "a bad key was stored anyway")
    return c.done("65,537 B -> 6, not stored; lower/1ABC/A-B/129 chars -> 6; 65,536 B and 128-char key accepted")


# ---------------------------------------------------------------- F4

@check("F4")
def f4(c) -> Result:
    """history v1..n; get --version k; rollback --to 1 creates v(n+1) = v1"""
    k = _key(c, "HIST_")
    vals = [_canary(c, f"v{i}").encode() for i in (1, 2, 3)]
    for i, v in enumerate(vals, 1):
        if not c.expect(_set(c, k, v).rc == 0, f"set v{i} failed"):
            return c.done()
    r, vs = _cli_versions(c, k)
    c.expect(vs is not None and [v for v, _ in vs] == [1, 2, 3],
             f"CLI history versions={vs} rc={r.rc} (want [1,2,3])")
    c.expect(_api_versions(c, k) == [(1, False), (2, False), (3, False)],
             f"API versions={_api_versions(c, k)} (want 1..3)")
    for i in (1, 2):
        g = _get(c, k, version=i)
        c.expect(g.rc == 0 and g.out == vals[i - 1], f"get --version {i}: rc={g.rc} exact={g.out == vals[i - 1]}")
    rb = c.cli("secrets", "rollback", k, "--to", "1", "-p", P, "-e", DEV, actor=W, timeout=T)
    c.expect(rb.rc == 0, f"rollback --to 1 rc={rb.rc} (want 0)")
    g = _get(c, k)
    c.expect(g.rc == 0 and g.out == vals[0], f"after rollback: current exact v1={g.out == vals[0]} rc={g.rc}")
    av = _api_versions(c, k)
    c.expect(av is not None and [v for v, _ in av] == [1, 2, 3, 4], f"after rollback API versions={av} (want 1..4)")
    g4 = _get(c, k, version=4)
    c.expect(g4.rc == 0 and g4.out == vals[0], f"get --version 4 == v1: {g4.out == vals[0]} rc={g4.rc}")
    return c.done("history 1..3, get --version 1/2 exact, rollback --to 1 -> v4 == v1")


# ---------------------------------------------------------------- F5

@check("F5")
def f5(c) -> Result:
    """delete -> get exit 5; tombstone in history; set again continues numbering"""
    k = _key(c, "DEL_")
    if not c.expect(_set(c, k, _canary(c, "a").encode()).rc == 0, "initial set failed"):
        return c.done()
    d = c.cli("secrets", "delete", k, "-p", P, "-e", DEV, actor=W, timeout=T)
    c.expect(d.rc == 0, f"delete rc={d.rc} (want 0)")
    g = _get(c, k)
    c.expect(g.rc == 5, f"get after delete rc={g.rc} (want 5)")
    st, _ = _api_value(c, k)
    c.expect(st == 404, f"API GET after delete -> {st} (want 404)")
    av = _api_versions(c, k)
    c.expect(av == [(1, False), (2, True)], f"API versions after delete={av} (want [(1,live),(2,tombstone)])")
    r, cv = _cli_versions(c, k)
    c.expect(cv is not None and [v for v, _ in cv] == [1, 2], f"CLI history after delete={cv} rc={r.rc}")
    v3 = _canary(c, "b").encode()
    c.expect(_set(c, k, v3).rc == 0, "set after delete failed")
    av = _api_versions(c, k)
    c.expect(av is not None and [v for v, _ in av] == [1, 2, 3], f"versions after re-set={av} (want 1..3)")
    g = _get(c, k)
    c.expect(g.rc == 0 and g.out == v3, f"get after re-set rc={g.rc} exact={g.out == v3}")
    return c.done("delete -> get 5 / API 404; v2 tombstone; re-set -> v3")


# ---------------------------------------------------------------- F6

@check("F6")
def f6(c) -> Result:
    """--expect-version stale -> exit 8, unchanged; correct -> succeeds"""
    k = _key(c, "CAS_")
    v1, v2, vx, v3 = (_canary(c, n).encode() for n in ("1", "2", "x", "3"))
    for v in (v1, v2):
        if not c.expect(_set(c, k, v).rc == 0, "setup set failed"):
            return c.done()
    s = _set(c, k, vx, extra=("--expect-version", "1"))
    c.expect(s.rc == 8, f"--expect-version 1 (current 2) rc={s.rc} (want 8)")
    g = _get(c, k)
    c.expect(g.rc == 0 and g.out == v2, f"after stale write value unchanged={g.out == v2}")
    c.expect([v for v, _ in (_api_versions(c, k) or [])] == [1, 2], "stale write created a version")
    s = _set(c, k, v3, extra=("--expect-version", "2"))
    c.expect(s.rc == 0, f"--expect-version 2 (current 2) rc={s.rc} (want 0)")
    g = _get(c, k)
    c.expect(g.rc == 0 and g.out == v3, f"after correct CAS value == v3: {g.out == v3}")
    # raw API cross-check of the 409
    r = c.api("PUT", f"/projects/{P}/envs/{DEV}/secrets/{k}", actor=OWN,
              json={"value": _canary(c, "y"), "expected_version": 1})
    c.expect(r.status == 409, f"API PUT expected_version=1 (current 3) -> {r.status} (want 409)")
    return c.done("stale -> 8 unchanged; correct -> 0; API stale -> 409")


# ---------------------------------------------------------------- F7

@check("F7")
def f7(c) -> Result:
    """20 parallel unconditional sets -> 20 contiguous versions; final = highest"""
    k = _key(c, "PAR_")
    if not c.expect(_set(c, k, _canary(c, "base").encode()).rc == 0, "base set failed"):
        return c.done()
    vals = [_canary(c, f"p{i}").encode() for i in range(20)]
    res = c.parallel([lambda v=v: _set(c, k, v) for v in vals], workers=20)
    rcs = [r.rc if isinstance(r, lib.CliResult) else repr(r) for r in res]
    c.expect(all(x == 0 for x in rcs), f"parallel set rcs={rcs}")
    av = _api_versions(c, k)
    nums = [v for v, _ in (av or [])]
    c.expect(nums == list(range(1, 22)), f"versions={nums} (want 1..21 contiguous, no duplicates)")
    seen = {}
    for n in range(2, 22):
        r = c.api("GET", f"/projects/{P}/envs/{DEV}/secrets/{k}/versions/{n}", actor=OWN)
        try:
            seen[n] = r.json().get("value") if r.status == 200 else None
        except (ValueError, AttributeError):
            seen[n] = None
    want = {v.decode() for v in vals}
    got = [v for v in seen.values() if v is not None]
    c.expect(len(got) == 20 and set(got) == want,
             f"versions 2..21 hold {len(set(got) & want)}/20 distinct written values (no lost updates)")
    g = _get(c, k)
    c.expect(g.rc == 0 and seen.get(21) is not None and g.out == seen[21].encode(),
             f"current value equals v21 value: {seen.get(21) is not None and g.out == (seen.get(21) or '').encode()}")
    return c.done("20 parallel sets -> v2..v21 contiguous, all 20 values present, current == v21")


# ---------------------------------------------------------------- F8

def _ref_env(c):
    multi = (c.fx.get("canaries") or {}).get("acme/api/dev/MULTI")
    v = {
        "A_PLAIN": _canary(c, "plain"),
        "B_MULTI": multi,
        "C_ESC": _canary(c, "esc", 12) + '\\"$\n\r\t\'`' + "\U0001F600\x01" + "$HOME${X}",
        "D_EMPTY": "",
        "E_UNI": "h\u00e9llo w\u00f6rld \u2603 " + _canary(c, "uni", 12),
    }
    return v, multi


def _seed(c, sp, vals):
    for k, v in vals.items():
        r = c.api("PUT", f"/projects/{sp}/envs/dev/secrets/{k}", actor=OWN, json={"value": v})
        if r.status not in (200, 201):
            raise lib.HarnessError(f"seed {k} -> {r.status}")


@check("F8")
def f8(c) -> Result:
    """export dotenv byte-exact to the 7.1 escaping rule; sorted; LF; trailing newline"""
    vals, multi = _ref_env(c)
    if not multi:
        return c.error("fixture MULTI canary missing")
    try:
        sp = c.scratch_project(OWN, envs=(("dev", False),))
        _seed(c, sp, vals)
    except lib.HarnessError as e:
        return c.error(f"scratch setup: {e}")
    want = b"".join(_dotenv_line(k, vals[k]) for k in sorted(vals))
    r = c.cli("secrets", "export", "-p", sp, "-e", "dev", "--format", "dotenv", actor=OWN, timeout=T)
    c.expect(r.rc == 0, f"export dotenv rc={r.rc}")
    if r.out != want:
        lines_got, lines_want = r.out.split(b"\n"), want.split(b"\n")
        bad = next((i for i, (a, b) in enumerate(zip(lines_got, lines_want)) if a != b), None)
        c.log("dotenv mismatch at line %s\n got: %r\n want: %r", bad,
              lines_got[bad] if bad is not None else r.out[-80:], lines_want[bad] if bad is not None else want[-80:])
    c.expect(r.out == want, f"scratch dotenv byte-exact vs reference encoder: {r.out == want} "
                            f"(len {len(r.out)} want {len(want)})")
    c.expect(r.out.endswith(b"\n") and b"\r" not in r.out, "dotenv: final newline + LF only (no raw CR)")
    # fixture env acme/api/dev: MULTI line exact, keys sorted, LF, trailing newline
    r2 = c.cli("secrets", "export", "-p", P, "-e", DEV, "--format", "dotenv", actor="reader@acme", timeout=T)
    c.expect(r2.rc == 0, f"reader export acme/api/dev rc={r2.rc}")
    out = r2.out
    c.expect(out.endswith(b"\n") and b"\r" not in out, "acme/api/dev dotenv: LF only + trailing newline")
    lines = out[:-1].split(b"\n") if out.endswith(b"\n") else out.split(b"\n")
    keys = [ln.split(b"=", 1)[0].decode("utf-8", "replace") for ln in lines if ln]
    c.expect(keys == sorted(keys), f"acme/api/dev dotenv keys sorted: {keys == sorted(keys)} ({len(keys)} keys)")
    c.expect(_dotenv_line("MULTI", multi) in out, "acme/api/dev MULTI line not byte-exact to the 7.1 rule")
    return c.done("dotenv byte-exact (5 keys incl. MULTI, empty, \\t/'/` unescaped); sorted; LF; final newline")


# ---------------------------------------------------------------- F9

def _jq():
    for p in (shutil.which("jq", path="/usr/local/bin:/usr/bin:/bin"),):
        if p:
            return p
    return None


@check("F9")
def f9(c) -> Result:
    """export json round-trips through jq to exact values"""
    jq = _jq()
    if not jq:
        return c.error("jq not installed on the grading host")
    vals, multi = _ref_env(c)
    if not multi:
        return c.error("fixture MULTI canary missing")
    try:
        sp = c.scratch_project(OWN, envs=(("dev", False),))
        _seed(c, sp, vals)
    except lib.HarnessError as e:
        return c.error(f"scratch setup: {e}")
    r = c.cli("secrets", "export", "-p", sp, "-e", "dev", "--format", "json", actor=OWN, timeout=T)
    c.expect(r.rc == 0, f"export json rc={r.rc}")
    try:
        pairs = _json.loads(r.out, object_pairs_hook=list)
    except ValueError as e:
        return c.fail(f"export json does not parse: {e}")
    if not c.expect(isinstance(pairs, list) and all(isinstance(p, tuple) for p in pairs),
                    "export json is not a single object"):
        return c.done()
    ks = [k for k, _ in pairs]
    c.expect(ks == sorted(ks), f"json keys sorted: {ks}")
    c.expect(set(ks) == set(vals), f"json keys {ks} (want {sorted(vals)})")
    for k, v in vals.items():
        p = subprocess.run([jq, "-j", "--arg", "k", k, ".[$k]"], input=r.out, capture_output=True, timeout=30)
        c.expect(p.returncode == 0 and p.stdout == v.encode(),
                 f"jq .[{k}] rc={p.returncode} exact={p.stdout == v.encode()}")
    # fixture env: MULTI through jq
    r2 = c.cli("secrets", "export", "-p", P, "-e", DEV, "--format", "json", actor="reader@acme", timeout=T)
    p = subprocess.run([jq, "-j", ".MULTI"], input=r2.out, capture_output=True, timeout=30)
    c.expect(r2.rc == 0 and p.returncode == 0 and p.stdout == multi.encode(),
             f"acme/api/dev json .MULTI via jq exact={p.stdout == multi.encode()} rc={r2.rc}/{p.returncode}")
    return c.done("export json parses, keys sorted, every value exact through jq (incl. MULTI, empty)")


# ---------------------------------------------------------------- F10

_ENV_DUMP = ("import os,json,sys;print(json.dumps({k:os.environ.get(k,'').encode('utf-8','surrogateescape').hex()"
             " if k in os.environ else None for k in sys.argv[1:]}))")
_TERM_CHILD = ("import signal,sys,time,pathlib\n"
               "m=pathlib.Path(sys.argv[1])\n"
               "def h(s,f):\n m.write_text('TERM');sys.exit(0)\n"
               "signal.signal(signal.SIGTERM,h)\n"
               "print('ready',flush=True)\n"
               "time.sleep(30)\n"
               "m.write_text('TIMEOUT')\n")


@check("F10")
def f10(c) -> Result:
    """run: env injection, override, exit 42, 143, SIGTERM forwarding, stdin"""
    py = sys.executable
    try:
        sp = c.scratch_project(OWN, envs=(("dev", False),))
        vals = {"F10_A": _canary(c, "a"), "F10_MULTI": (c.fx.get("canaries") or {}).get("acme/api/dev/MULTI") or "",
                "HOME": _canary(c, "home")}
        _seed(c, sp, vals)
    except lib.HarnessError as e:
        return c.error(f"scratch setup: {e}")
    reader = c.scratch_user("acme", "member", grants={sp: "reader"})
    base = ("run", "-p", sp, "-e", "dev", "--")
    # 1+2: injection and override (HOME exists in the parent env, secret must win)
    r = c.cli(*base, py, "-I", "-c", _ENV_DUMP, "F10_A", "F10_MULTI", "HOME", "PATH",
              actor=reader, env={"F10_A": "parent-value"}, timeout=T)
    c.expect(r.rc == 0, f"run env dump rc={r.rc}")
    try:
        d = _json.loads(r.out.decode().strip().splitlines()[-1])
    except (ValueError, IndexError, UnicodeDecodeError):
        d = {}
    for k in ("F10_A", "F10_MULTI", "HOME"):
        got = bytes.fromhex(d[k]).decode("utf-8", "replace") if d.get(k) is not None else None
        c.expect(got == vals[k], f"child env {k}: {'missing' if got is None else 'exact' if got == vals[k] else 'wrong'}"
                                 f"{' (secret must override parent)' if k in ('F10_A', 'HOME') else ''}")
    c.expect(d.get("PATH") is not None, "child lost the parent env (PATH missing)")
    # 3: exit 42
    r = c.cli(*base, "/bin/sh", "-c", "exit 42", actor=reader, timeout=T)
    c.expect(r.rc == 42, f"child exit 42 -> rc={r.rc} (want 42)")
    # 4: child killed by SIGTERM -> 143
    r = c.cli(*base, "/bin/sh", "-c", "kill -TERM $$", actor=reader, timeout=T)
    c.expect(r.rc == 143, f"child killed by SIGTERM -> rc={r.rc} (want 143)")
    # 5: SIGTERM to `coffer run` reaches the child
    marker = c.tmp / "f10-term.marker"
    p = c.cli_spawn(*base, py, "-I", "-c", _TERM_CHILD, str(marker), actor=reader, stdin=subprocess.DEVNULL)
    got = []
    th = threading.Thread(target=lambda: got.append(p.stdout.readline()), daemon=True)
    th.start()
    th.join(30)
    if not got or b"ready" not in got[0]:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.wait(10)
        c.log("SIGTERM test: child never printed ready (first line %r)", got[:1])
        c.expect(False, "SIGTERM test: child under coffer run did not start within 30 s")
    else:
        os.kill(p.pid, signal.SIGTERM)
        delivered = c.wait_until(lambda: marker.exists(), 10.0)
        try:
            rc = p.wait(15)
        except subprocess.TimeoutExpired:
            rc = None
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        mtxt = marker.read_text() if marker.exists() else None
        c.log("SIGTERM to coffer pid %s: marker=%r coffer rc=%s", p.pid, mtxt, rc)
        c.expect(delivered and mtxt == "TERM", f"SIGTERM to coffer run did not reach the child (marker={mtxt!r})")
        c.expect(rc is not None, "coffer run still running 15 s after its child handled SIGTERM")
    # 6: stdin passes through
    payload = (_canary(c, "stdin") + "\nline2\n").encode()
    r = c.cli(*base, "/bin/cat", actor=reader, stdin=payload, timeout=T)
    c.expect(r.rc == 0 and r.out == payload, f"stdin passthrough rc={r.rc} exact={r.out == payload}")
    return c.done("env injected+override, exit 42, 143, SIGTERM forwarded, stdin passthrough")


# ---------------------------------------------------------------- F11

@check("F11")
def f11(c) -> Result:
    """COFFER_TOKEN with empty HOME works and creates no config file"""
    tok = c.actor("T_dev_r")
    want = (c.fx.get("canaries") or {}).get("acme/api/dev/CANARY")
    if not tok.secret or not want:
        return c.error("fixture T_dev_r or acme/api/dev canary missing")
    h = c.scratch_home()
    r = c.cli("secrets", "get", "CANARY", "-p", P, "-e", DEV, home=h, env={"COFFER_TOKEN": tok.secret}, timeout=T)
    c.expect(r.rc == 0 and r.out == want.encode(), f"COFFER_TOKEN get rc={r.rc} exact={r.out == want.encode()}")
    files = [str(p.relative_to(h)) for p in h.rglob("*") if p.is_file() or p.is_symlink()]
    dirs = [str(p.relative_to(h)) for p in h.rglob("*") if p.is_dir()]
    c.log("HOME after: files=%s dirs=%s", files, dirs)
    c.expect(not files, f"COFFER_TOKEN run created files in HOME: {files[:5]}")
    return c.done("token get exact with empty HOME; HOME still has no files")


# ---------------------------------------------------------------- F12

@check("F12")
def f12(c) -> Result:
    """Protected write by writer -> exit 7 + id; admin approves; audit shows both"""
    since = _since(c)
    k = _key(c, "PROT_")
    v = _canary(c, "prot")
    cid = _propose(c, ("secrets", "set", k, "-p", P, "-e", PROD), what="writer set prod", stdin=v.encode())
    if cid is None:
        return c.done()
    c.put("change_id", cid)
    st, _ = _api_value(c, k, env=PROD)
    c.expect(st == 404, f"before approval: GET prod {k} -> {st} (want 404, value unchanged)")
    a = c.cli("change", "approve", cid, actor=ADM, timeout=T)
    c.expect(a.rc == 0, f"admin approve rc={a.rc} (want 0)")
    st, av = _api_value(c, k, env=PROD)
    c.expect(st == 200 and av == v, f"after approval: GET prod -> {st} exact={av == v}")
    c.expect(_change_status(c, cid) == "approved", f"change status after approve={_change_status(c, cid)}")
    # --json shape for a protected write (SPEC 7.1)
    jr = c.cli("secrets", "set", _key(c, "PJ_"), "-p", P, "-e", PROD, actor=W, stdin=_canary(c, "pj").encode(),
               json=True, timeout=T)
    try:
        jd = jr.json()
    except ValueError:
        jd = None
    c.expect(jr.rc == 7 and isinstance(jd, dict) and jd.get("status") == "pending" and jd.get("change_id"),
             f"--json protected write rc={jr.rc} doc={str(jd)[:80]} (want {{status:pending,change_id}})")
    if isinstance(jd, dict) and jd.get("change_id"):
        c.cli("change", "reject", str(jd["change_id"]), actor=ADM, timeout=T)
    # audit: proposer and approver
    r = c.api("GET", "/audit", actor=OWN, query={"since": since, "limit": 1000})
    try:
        evs = _items(r.json()) or []
    except ValueError:
        evs = []
    rel = [e for e in evs if isinstance(e, dict) and (cid in _json.dumps(e) or k in _json.dumps(e))]
    wa, aa = c.actor(W), c.actor(ADM)

    def has(e, a):
        s = _json.dumps(e)
        return bool((a.user_id and a.user_id in s) or (a.email and a.email in s))
    c.log("audit since %s: %d events, %d mention change/key", since, len(evs), len(rel))
    c.expect(r.status == 200 and any(has(e, wa) for e in rel), "audit: no event for the change by the proposer (writer)")
    c.expect(r.status == 200 and any(has(e, aa) for e in rel), "audit: no event for the change by the approver (admin)")
    return c.done("writer prod set -> 7 + id; unchanged; admin approve -> value; audit has proposer + approver")


# ---------------------------------------------------------------- F13

def _prod_v1(c, k, v):
    """Create prod key k = v through an approved CR. Returns True on success."""
    cid = _propose(c, ("secrets", "set", k, "-p", P, "-e", PROD), what="setup set prod", stdin=v.encode())
    if cid is None:
        return False
    a = c.cli("change", "approve", cid, actor=ADM, timeout=T)
    st, av = _api_value(c, k, env=PROD)
    if a.rc != 0 or av != v:
        c.error_once(f"setup: approve of setup CR rc={a.rc}, value present={av == v}")
        return False
    return True


@check("F13")
def f13(c) -> Result:
    """reject -> value unchanged, status rejected"""
    k = _key(c, "REJ_")
    v1, v2 = _canary(c, "v1"), _canary(c, "v2")
    if not _prod_v1(c, k, v1):
        return c.done()
    cid = _propose(c, ("secrets", "set", k, "-p", P, "-e", PROD), what="writer set v2", stdin=v2.encode())
    if cid is None:
        return c.done()
    r = c.cli("change", "reject", cid, actor=ADM, timeout=T)
    c.expect(r.rc == 0, f"admin reject rc={r.rc}")
    st, av = _api_value(c, k, env=PROD)
    c.expect(st == 200 and av == v1, f"after reject value unchanged (v1)={av == v1} status={st}")
    s = _change_status(c, cid)
    c.expect(s == "rejected", f"API change status={s} (want rejected)")
    lr = c.cli("change", "list", "--status", "rejected", actor=ADM, json=True, timeout=T)
    c.expect(lr.rc == 0 and cid in lr.text(), f"CLI change list --status rejected contains id: {cid in lr.text()}")
    return c.done("reject -> value unchanged, status rejected (API + CLI)")


# ---------------------------------------------------------------- F14

@check("F14")
def f14(c) -> Result:
    """Two pending CRs on one key: approve first, second -> 409 / exit 8, stale"""
    k = _key(c, "STALE_")
    va, vb = _canary(c, "a"), _canary(c, "b")
    c1 = _propose(c, ("secrets", "set", k, "-p", P, "-e", PROD), what="CR1", stdin=va.encode())
    c2 = _propose(c, ("secrets", "set", k, "-p", P, "-e", PROD), what="CR2", stdin=vb.encode())
    if not c1 or not c2:
        return c.done()
    a1 = c.cli("change", "approve", c1, actor=ADM, timeout=T)
    c.expect(a1.rc == 0, f"approve first rc={a1.rc}")
    a2 = c.cli("change", "approve", c2, actor=ADM, timeout=T)
    c.expect(a2.rc == 8, f"approve second (stale) rc={a2.rc} (want 8)")
    st, av = _api_value(c, k, env=PROD)
    c.expect(av == va, f"value == first CR's: {av == va} (status {st})")
    s = _change_status(c, c2)
    c.expect(s == "stale", f"second CR status={s} (want stale)")
    # raw API: same flow must give HTTP 409
    k2 = _key(c, "STALEAPI_")
    ids = []
    for n in ("c", "d"):
        r = c.api("PUT", f"/projects/{P}/envs/{PROD}/secrets/{k2}", actor=W, json={"value": _canary(c, n)})
        try:
            ids.append(str(r.json().get("change_id")) if r.status == 202 else None)
        except (ValueError, AttributeError):
            ids.append(None)
    if c.expect(all(ids), f"API proposals -> change ids {ids}"):
        r1 = c.api("POST", f"/changes/{ids[0]}/approve", actor=ADM)
        c.expect(r1.status == 200, f"API approve first -> {r1.status}")
        r2 = c.api("POST", f"/changes/{ids[1]}/approve", actor=ADM)
        c.expect(r2.status == 409, f"API approve stale -> {r2.status} (want 409)")
    return c.done("second approval -> exit 8 / HTTP 409, status stale, value = first")


# ---------------------------------------------------------------- F15

@check("F15")
def f15(c) -> Result:
    """Protected delete and protected rollback both go through change requests"""
    k = _key(c, "PDR_")
    v1, v2 = _canary(c, "v1"), _canary(c, "v2")
    if not _prod_v1(c, k, v1) or not _prod_v1(c, k, v2):
        return c.done()
    # rollback --to 1
    cid = _propose(c, ("secrets", "rollback", k, "--to", "1", "-p", P, "-e", PROD), what="writer rollback prod")
    if cid:
        st, av = _api_value(c, k, env=PROD)
        c.expect(av == v2, f"rollback pending: value unchanged={av == v2}")
        c.expect([v for v, _ in (_api_versions(c, k, env=PROD) or [])] == [1, 2], "pending rollback created a version")
        a = c.cli("change", "approve", cid, actor=ADM, timeout=T)
        c.expect(a.rc == 0, f"approve rollback rc={a.rc}")
        st, av = _api_value(c, k, env=PROD)
        c.expect(av == v1, f"after approved rollback value == v1: {av == v1}")
        c.expect([v for v, _ in (_api_versions(c, k, env=PROD) or [])] == [1, 2, 3], "approved rollback is not v3")
    # delete
    cid = _propose(c, ("secrets", "delete", k, "-p", P, "-e", PROD), what="writer delete prod")
    if cid:
        st, av = _api_value(c, k, env=PROD)
        c.expect(st == 200 and av == v1, f"delete pending: value still present={st == 200 and av == v1}")
        a = c.cli("change", "approve", cid, actor=ADM, timeout=T)
        c.expect(a.rc == 0, f"approve delete rc={a.rc}")
        st, _ = _api_value(c, k, env=PROD)
        c.expect(st == 404, f"after approved delete GET -> {st} (want 404)")
    return c.done("protected rollback and delete -> exit 7 + CR; unchanged until approved; applied after")


# ---------------------------------------------------------------- F16

@check("F16")
def f16(c) -> Result:
    """--json parses for list, get, history, token create, change list, audit list"""
    canary = (c.fx.get("canaries") or {}).get("acme/api/dev/CANARY")

    def parse(r, what):
        try:
            d = r.json()
        except (ValueError, UnicodeDecodeError) as e:
            c.expect(False, f"{what} --json: rc={r.rc}, not one JSON doc ({e})")
            return None
        c.expect(r.rc == 0, f"{what} --json rc={r.rc}")
        return d

    d = parse(c.cli("secrets", "list", "-p", P, "-e", DEV, actor=ADM, json=True, timeout=T), "secrets list")
    if d is not None:
        c.expect("CANARY" in _json.dumps(d) and canary not in _json.dumps(d), "secrets list: CANARY key missing or value shown")
    d = parse(c.cli("secrets", "get", "CANARY", "-p", P, "-e", DEV, actor=ADM, json=True, timeout=T), "secrets get")
    if d is not None:
        c.expect(canary in _json.dumps(d, ensure_ascii=False), "secrets get --json: value missing")
    d = parse(c.cli("secrets", "history", "CANARY", "-p", P, "-e", DEV, actor=ADM, json=True, timeout=T), "history")
    if d is not None:
        c.expect(bool(_vers(_items(d))), f"history --json has no version list: {str(d)[:80]}")
    tr = _qcli(c, "token", "create", "-p", P, "-e", DEV, "--access", "read", "--ttl", "30m", "--name",
               f"f16-{secrets.token_hex(3)}", actor=ADM, json=True)
    d = parse(tr, "token create")
    if isinstance(d, dict):
        c.expect(str(d.get("token", "")).startswith("cof_st_"), "token create --json: no cof_st_ token field")
        tid = d.get("id") or d.get("token_id")
        if tid:
            c.cli("token", "revoke", str(tid), actor=ADM, timeout=T)
    elif d is not None:
        c.expect(False, "token create --json is not an object")
    d = parse(c.cli("change", "list", actor=ADM, json=True, timeout=T), "change list")
    if d is not None:
        c.expect(_items(d) is not None, "change list --json has no list")
    d = parse(c.cli("audit", "list", "--limit", "5", actor=ADM, json=True, timeout=T), "audit list")
    if d is not None:
        it = _items(d)
        c.expect(bool(it), "audit list --json has no events")
    return c.done("--json parses (one doc) for list, get, history, token create, change list, audit list")


# ---------------------------------------------------------------- F18

@check("F18")
def f18(c) -> Result:
    """Created user must change password before any other call; passwd works"""
    email = f"f18-{secrets.token_hex(4)}@acme.test"
    pw0 = c.secret(f"pw0:{email}", _rand(16), "password")
    pw1 = c.secret(f"pw1:{email}", _rand(16), "password")
    r = c.cli("member", "add", email, "--role", "member", actor=OWN, stdin=(pw0 + "\n").encode(), timeout=T)
    if not c.expect(r.rc == 0, f"member add rc={r.rc}"):
        return c.done()
    h = c.scratch_home()
    lg = c.cli("login", "--email", email, home=h, stdin=(pw0 + "\n").encode(), timeout=T)
    if not c.expect(lg.rc == 0, f"login with initial password rc={lg.rc} (passwd needs a session)"):
        return c.done()
    pl = c.cli("project", "list", home=h, timeout=T)
    c.expect(pl.rc != 0, f"before passwd: project list rc={pl.rc} (want refused)")
    ar = c.api("POST", "/auth/token", json={"email": email, "password": pw0})
    if ar.status in (200, 201):
        try:
            t0 = c.secret(f"pat0:{email}", ar.json()["token"], "token")
        except (ValueError, KeyError, TypeError):
            t0 = None
        if t0:
            gp = c.http("GET", "/api/v1/projects", headers={"Authorization": f"Bearer {t0}"})
            c.expect(400 <= gp.status < 500,
                     f"before passwd: API GET /projects -> {gp.status} (want refused)")
    else:
        c.log("raw login with initial password -> %s (refusal at login also blocks other calls)", ar.status)
        c.expect(ar.status < 500, f"raw login -> {ar.status}")
    pw = c.cli("passwd", home=h, stdin=f"{pw0}\n{pw1}\n".encode(), timeout=T)
    c.expect(pw.rc == 0, f"passwd rc={pw.rc} (want 0)")
    pl = c.cli("project", "list", home=h, timeout=T)
    if pl.rc != 0:   # the CLI may have dropped the session on password change: log in with the new password
        h2 = c.scratch_home()
        lg2 = c.cli("login", "--email", email, home=h2, stdin=(pw1 + "\n").encode(), timeout=T)
        c.expect(lg2.rc == 0, f"login with new password rc={lg2.rc}")
        pl = c.cli("project", "list", home=h2, timeout=T)
    c.expect(pl.rc == 0, f"after passwd: project list rc={pl.rc} (want 0)")
    n = c.api("POST", "/auth/token", json={"email": email, "password": pw1})
    c.expect(n.status in (200, 201), f"raw login new password -> {n.status}")
    if n.status in (200, 201):
        try:
            c.secret(f"pat1:{email}", n.json()["token"], "token")
        except (ValueError, KeyError, TypeError):
            pass
    o = c.api("POST", "/auth/token", json={"email": email, "password": pw0})
    c.expect(o.status == 401, f"raw login old password -> {o.status} (want 401)")
    return c.done("initial-password user refused until passwd; passwd 0; new password works, old 401")


# ---------------------------------------------------------------- F17

@check("F17")
def f17(c) -> Result:
    """Data survives down.sh + up.sh"""
    can = c.fx.get("canaries") or {}
    if not can:
        return c.error("fixture canaries missing")
    k = _key(c, "PERSIST_")
    v1, v2 = _canary(c, "v1").encode(), _canary(c, "v2").encode()
    for v in (v1, v2):
        if not c.expect(_set(c, k, v).rc == 0, "pre set failed"):
            return c.done()
    pre = {}
    for path, val in can.items():
        org, proj, env, key = path.split("/")
        st, av = _api_value(c, key, actor=f"owner@{org}", env=env, proj=proj)
        pre[path] = (st, av == val)
    if not all(s == 200 and ok for s, ok in pre.values()):
        return c.error(f"pre-down canary reads not all exact: {pre}")
    d = c.down()
    c.expect(d.rc == 0, f"down.sh rc={d.rc}")
    rz = c.http("GET", "/readyz", timeout=3.0, _quiet=True)
    c.log("readyz after down.sh -> %s %s", rz.status, rz.error)
    if rz.status == 200:
        c.error_once("stack still ready after down.sh (nothing proven)")
    u = c.up()
    c.expect(u.rc == 0, f"up.sh rc={u.rc}")
    if not c.wait_ready(60.0):
        return c.fail("not ready 60 s after up.sh")
    for path, val in can.items():
        org, proj, env, key = path.split("/")
        st, av = _api_value(c, key, actor=f"owner@{org}", env=env, proj=proj)
        c.expect(st == 200 and av == val, f"after down/up {path}: {st} exact={av == val}")
    g = _get(c, k)
    c.expect(g.rc == 0 and g.out == v2, f"marker current after restart exact={g.out == v2} rc={g.rc}")
    g1 = _get(c, k, version=1)
    c.expect(g1.rc == 0 and g1.out == v1, f"marker v1 after restart exact={g1.out == v1}")
    av = _api_versions(c, k)
    c.expect(av == [(1, False), (2, False)], f"marker versions after restart={av}")
    return c.done(f"down.sh+up.sh: {len(can)} canaries + 2-version marker intact, owner PATs still valid")
