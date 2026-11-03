"""Coffer grading checks: S1, S2, S3, S4, S5, S6, S7, S8, S9, S10, S11, S12.

Black-box only (CONTRACT.md): the SPEC 7.2 HTTP API and ./bin/coffer. No build source is read.
Every denial probe runs after a positive control: the same route and operation, done by an
actor SPEC section 2 allows, against an equivalent target (lib.denied / lib.control / _same404).

Readings chosen where GRADER/CONTRACT leave room (stricter on the build, identical for both):
- "404 identical to nonexistent" (S1, S5, S4 project routes) uses the local _same404, not
  lib.same_404. Both bodies get the same normalisation: the X-Request-Id value (and its
  16+ char runs), RFC3339 timestamps, and the identifiers *the caller itself put in the URL*
  (the probe's slug/id in the probe body, the absent slug/id in the absent body) become «X».
  UUIDs are NOT masked unless two calls on the same absent target differ (a per-request
  UUID). In that case UUIDs are masked on both sides and that is logged. content-type and
  the set of header names must also match. This is closer to GRADER's "byte-identical"
  wording than lib.same_404: a UUID that leaks a real resource id makes the check fail.
- Allowed alternatives are exact. S5/S1/S3/S4 accept only 404. S6/S7/S9/S11 accept only 403.
  S10 accepts only 403, S12 only 409. Exceptions: nogrant on project-scoped management ops
  (token create/revoke for api, grant set/revoke on api, and approve/reject of a change
  request on api/prod) may be 403 or 404, because SPEC 2.1/2.5 (invisible -> 404) and 2.6
  (members -> 403) both apply to that cell (GRADER: overlap -> accept 403 or 404). The
  admin@acme positive control and the "target CR still pending" check are unchanged (r3-1).
  The CLI forms use the SPEC 7.1 exit-code mapping.
- Viewer `history` (version metadata) is not scored: SPEC 2.4 says viewers see "names and
  metadata only", and GRADER S6 does not list it. Both 200 and 403 are logged as info.
- Member list / token list by plain members are not scored (SPEC 2.6 forbids *managing*).
- S8: a dev write must be exactly 200 (SPEC 7.2 "200 {version}"). A prod write must be
  exactly 202 with a change id, and the stored value must not change.
- S9 approve/reject controls use change requests proposed by owner@acme and approved/
  rejected by admin@acme, so the two-person rule is never what blocks the control.
- S12 uses a scratch org (CONTRACT 9). As a non-vacuity control, with two owners present,
  demoting the second owner must succeed (200). Then the remaining sole owner's self-demote
  and self-remove must each return exactly 409, and they must still be owner afterwards.
- Destructive rows (S3, S9, S11) may touch fixture state, and the runner rolls it back.
  Non-destructive rows use scratch users/tokens/projects and keys from c.junk_key() only.
  Leftover change requests are rejected by admin@acme at the end of every check.
- The role matrix (ROLE_MATRIX below) covers every actor x operation of GRADER's matrix.
  This module scores the cells tagged S5-S9. Cells tagged S2/S4/S14/S15/S16/S17/S20 are
  listed for completeness and are scored by those checks (S14-S20 live in checks_s_b.py).
"""
from __future__ import annotations

import json as _json
import re
import secrets as _secrets

import lib
from registry import Result, check, not_implemented  # noqa: F401

# ---------------------------------------------------------------------------
# ROLE MATRIX (SPEC section 2). One row per actor; one column per operation.
#   ok    2xx success (data ops: 200; checked for the right value where it returns one)
#   202   pending change request (protected env write, SPEC 2.8)
#   403   forbidden (SPEC 2.1: visible but not permitted)
#   404   invisible, and for project routes byte-identical to an absent project (SPEC 2.1)
#   4or3  403 or 404 accepted (both SPEC 2.1/2.5 and 2.6 apply)
#   401   unauthenticated
#   ~     not scored (logged only)
#   d/p   "dev-outcome/prod-outcome" for acme api dev (unprotected) / prod (protected)
# Ops: list get ver(sion n) hist(ory) export run set del(ete) rb(rollback) | approve reject
#      m_add m_role m_rm(member add/role/remove) g_set g_rev(grant set/revoke)
#      t_new t_rev(token create/revoke) audit(list)
# Targets: data ops on acme project `api` (env dev / prod); management ops in org acme.
# ---------------------------------------------------------------------------
OPS = ("list", "get", "ver", "hist", "export", "run", "set", "del", "rb",
       "approve", "reject", "m_add", "m_role", "m_rm", "g_set", "g_rev", "t_new", "t_rev", "audit")

ROLE_MATRIX_TEXT = """
actor         list    get     ver     hist    export  run     set     del     rb      approve reject  m_add   m_role  m_rm    g_set   g_rev   t_new   t_rev   audit   | SPEC        | scored by
owner@acme    ok      ok      ok      ok      ok      ok      ok/202  ok/202  ok/202  ok      ok      ok      ok      ok      ok      ok      ok      ok      ok      | 2.2 2.8     | (F block)
admin@acme    ok      ok      ok      ok      ok      ok      ok/202  ok/202  ok/202  ok      ok      ok      ok      ok      ok      ok      ok      ok      ok      | 2.3 2.8     | (F block, S11 for owners)
writer@acme   ok      ok      ok      ok      ok      ok      ok/202  ok/202  ok/202  403     403     403     403     403     403     403     403     403     403     | 2.4 2.6 2.8 | S8 S9
reader@acme   ok      ok      ok      ok      ok      ok      403     403     403     403     403     403     403     403     403     403     403     403     403     | 2.4 2.6     | S7 S9
viewer@acme   ok      403     403     ~       403     403     403     403     403     403     403     403     403     403     403     403     403     403     403     | 2.4 2.6     | S6 S9
nogrant@acme  404     404     404     404     404     404     404     404     404     4or3    4or3    403     403     403     4or3    4or3    4or3    4or3    403     | 2.1 2.5 2.6 | S5 S9
owner@globex  404     404     404     404     404     404     404     404     404     404     404     404     404     404     404     404     404     404     ok      | 2.1         | S1 S2 S3
root          404     404     404     404     404     404     404     404     404     404     404     404     404     404     404     404     404     404     404     | 2.10        | S4
T_dev_r       ok/404  ok/404  ok/404  ok/404  ok/404  ok/404  403/404 403/404 403/404 403     403     403     403     403     403     403     403     403     403     | 2.7         | S14 S16
T_dev_rw      ok/404  ok/404  ok/404  ok/404  ok/404  ok/404  ok/404  ok/404  ok/404  403     403     403     403     403     403     403     403     403     403     | 2.7         | S14 S16
T_prod_rw     404/ok  404/ok  404/ok  404/ok  404/ok  404/ok  404/202 404/202 404/202 403     403     403     403     403     403     403     403     403     403     | 2.7 2.8     | S15 S16
T_exp         401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     | 2.11        | S17
T_rev         401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     | 2.11        | S17
anon          401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     401     | 7.2         | S20
"""


def _parse_matrix(text: str) -> dict:
    rows = {}
    for line in text.strip().splitlines()[1:]:
        cells, ref, by = [p.strip() for p in line.split("|")]
        parts = cells.split()
        actor, vals = parts[0], parts[1:]
        assert len(vals) == len(OPS), (actor, len(vals))
        rows[actor] = {"cells": dict(zip(OPS, vals)), "spec": ref, "scored_by": by}
    return rows


ROLE_MATRIX = _parse_matrix(ROLE_MATRIX_TEXT)


def _cell(actor: str, op: str, env: str) -> str:
    v = ROLE_MATRIX[actor]["cells"][op]
    if "/" in v and op not in ("approve", "reject"):
        d, p = v.split("/")
        return d if env == "dev" else p
    return v


DATA_OPS = ("list", "get", "ver", "hist", "export", "run", "set", "del", "rb")
MGMT_OPS = ("approve", "reject", "m_add", "m_role", "m_rm", "g_set", "g_rev", "t_new", "t_rev", "audit")

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
_PENDING: list = []          # change ids this check created (each check is its own process)
_TS = re.compile(r"\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


class _Pre(Exception):
    """A precondition the harness needs failed: recorded as error, never as a pass."""


def _sp(p, e, key=None, tail=""):
    base = f"/projects/{p}/envs/{e}"
    if key is None:
        return base + "/secrets" + tail
    return f"{base}/secrets/{key}{tail}"


def _js(r):
    try:
        return r.json()
    except (ValueError, AttributeError):
        return None


def _rows(d):
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        for k in ("items", "data", "results", "members", "tokens", "changes", "projects",
                  "secrets", "envs", "environments", "events", "versions", "orgs"):
            if isinstance(d.get(k), list):
                return d[k]
    return []


def _find_id(d, *keys):
    if not isinstance(d, dict):
        return None
    for k in keys:
        if d.get(k) not in (None, ""):
            return str(d[k])
    for sub in ("user", "member", "token", "change", "data"):
        if isinstance(d.get(sub), dict):
            v = _find_id(d[sub], *keys)
            if v:
                return v
    return None


def _cid(r):
    return _find_id(_js(r), "change_id", "id")


def _canary(c, path):
    v = ((c.fx or {}).get("canaries") or {}).get(path)
    if not v:
        raise _Pre(f"fixture canary {path} missing")
    return v


def _need_actor(c, label):
    a = c.actor(label)
    if not a.secret:
        raise _Pre(f"fixture actor {label} has no credential")
    return a


def _val(c, r):
    d = _js(r)
    if isinstance(d, dict):
        if "value" in d:
            return d["value"]
        for sub in ("secret", "data"):
            if isinstance(d.get(sub), dict) and "value" in d[sub]:
                return d[sub]["value"]
    return None


def _ver(r):
    d = _js(r)
    if isinstance(d, dict):
        v = d.get("version")
        if v is None and isinstance(d.get("secret"), dict):
            v = d["secret"].get("version")
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
    return None


def _owner_get(c, p, e, key):
    return c.api("GET", _sp(p, e, key), actor="owner@acme")


def _put_ok(c, p, e, key, value, actor="owner@acme"):
    """Create or overwrite a junk key (as owner); on a protected env approve it as admin."""
    r = c.api("PUT", _sp(p, e, key), actor=actor, json={"value": value})
    if r.status in (200, 201):
        return
    if r.status == 202:
        cid = _cid(r)
        if not cid:
            raise _Pre(f"setup PUT {p}/{e}/{key} -> 202 without change id")
        ar = c.api("POST", f"/changes/{cid}/approve", actor="admin@acme", json={})
        if ar.status in (200, 201, 204):
            return
        raise _Pre(f"setup approve {cid} -> {ar.status}")
    raise _Pre(f"setup PUT {p}/{e}/{key} -> {r.status}")


def _fresh_key(c, p, e, versions=1):
    k = c.junk_key()
    for i in range(versions):
        _put_ok(c, p, e, k, f"{k}-v{i + 1}")
    return k


def _new_cr(c, actor="owner@acme", p="api", e="prod"):
    """A pending change request on a fresh junk key in a protected env."""
    k = c.junk_key()
    r = c.api("PUT", _sp(p, e, k), actor=actor, json={"value": f"{k}-cr"})
    if r.status != 202:
        raise _Pre(f"setup protected PUT by {getattr(actor, 'label', actor)} -> {r.status} (want 202)")
    cid = _cid(r)
    if not cid:
        raise _Pre("setup protected PUT -> 202 without change id")
    _PENDING.append(cid)
    return cid, k


def _track(r):
    if getattr(r, "status", None) == 202:
        cid = _cid(r)
        if cid:
            _PENDING.append(cid)


def _cleanup(c):
    for cid in list(dict.fromkeys(_PENDING)):
        try:
            c.api("POST", f"/changes/{cid}/reject", actor="admin@acme", json={})
        except Exception:  # noqa: BLE001
            pass
    _PENDING.clear()


def _change_status(c, cid):
    """Status of a change as owner@acme sees it: GET /changes, then each ?status= filter."""
    for st in (None, "pending", "approved", "rejected", "stale"):
        r = c.api("GET", "/changes", actor="owner@acme", query={"status": st} if st else None)
        for row in _rows(_js(r)):
            if isinstance(row, dict) and str(row.get("id") or row.get("change_id")) == str(cid):
                return row.get("status")
    return None


def _members(c, actor="owner@acme"):
    r = c.api("GET", "/members", actor=actor)
    if r.status != 200:
        raise _Pre(f"GET /members as {getattr(actor, 'label', actor)} -> {r.status}")
    return _rows(_js(r))


def _member(c, uid, actor="owner@acme"):
    for m in _members(c, actor):
        if str(m.get("id") or m.get("user_id")) == str(uid):
            return m
    return None


def _like_id(real) -> str:
    """An absent id with the same shape as a real one (so a 404 is not a 400 on format)."""
    s = str(real or "")
    if _UUID.fullmatch(s):
        h = _secrets.token_hex(16)
        return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"
    if s.isdigit():
        return str(10 ** max(len(s) + 2, 9) + _secrets.randbelow(10 ** 6))
    if s and re.fullmatch(r"[0-9a-f]+", s):
        return _secrets.token_hex(max(len(s) // 2, 8))[:len(s)]
    m = re.fullmatch(r"([A-Za-z]+[_-])([A-Za-z0-9]+)", s)
    if m:
        alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
        return m.group(1) + "".join(_secrets.choice(alpha) for _ in m.group(2))
    return _secrets.token_hex(16)


# ---------------------------------------------------------------------------
# strict "identical 404" comparison
# ---------------------------------------------------------------------------
def _norm(r, ids, mask_uuid):
    if isinstance(r, lib.CliResult):
        t = r.err.decode("utf-8", "replace") + "\x00" + r.out.decode("utf-8", "replace")
        hdr = None
    else:
        t = r.text()
        rid = r.headers.get("x-request-id")
        if rid:
            t = t.replace(rid, "«X»")
            for run in set(re.findall(r"[A-Za-z0-9_-]{16,}", rid)):
                t = t.replace(run, "«X»")
        hdr = (r.headers.get("content-type"), tuple(sorted(r.headers)))
    for i in sorted({str(x) for x in ids if x}, key=len, reverse=True):
        t = t.replace(i, "«ID»")
    t = _TS.sub("«T»", t)
    if mask_uuid:
        t = _UUID.sub("«U»", t)
    return t, hdr


def _is404(r):
    if isinstance(r, lib.CliResult):
        return r.rc == 5
    return isinstance(r, lib.Resp) and r.status == 404


def _desc(r):
    if r is None:
        return "no response"
    if isinstance(r, lib.CliResult):
        return f"rc={r.rc}"
    return str(r.status)


def _same404(c, probe, probe_ids, absent, absent_ids, control, what):
    """control must succeed; absent must 404 (twice, to detect volatile content);
    probe must 404 with a body equal to absent's after _norm."""
    if not c.control(control, what=f"control {what}"):
        return False
    a1, a2 = absent(), absent()
    if not (_is404(a1) and _is404(a2)):
        c.error_once(f"absent target not 404: {what} ({_desc(a1)}, {_desc(a2)})")
        return False
    mask = _norm(a1, absent_ids, False) != _norm(a2, absent_ids, False)
    if mask:
        c.log("note %s: absent 404 bodies differ between calls; masking UUIDs on both sides", what)
    pr = probe()
    if isinstance(pr, lib.Resp) and pr.status >= 500:
        c.expect(False, f"{what}: got {pr.status} (5xx in 404 probe)")
        return False
    if not _is404(pr):
        c.expect(False, f"{what}: got {_desc(pr)} (want 404 like absent)")
        return False
    pn, ph = _norm(pr, probe_ids, mask)
    an, ah = _norm(a1, absent_ids, mask)
    if pn != an or ph != ah:
        c.expect(False, f"{what}: 404 differs from absent: {pn[:90]!r} vs {an[:90]!r}"
                        + (f" headers {ph} vs {ah}" if ph != ah else ""))
        return False
    return c.expect(True, f"{what}: 404 identical to absent")


def _guard(fn):
    """Run a check body; precondition failures become `error`, cleanup always runs."""
    def wrapper(c) -> Result:
        try:
            res = fn(c)
        except _Pre as e:
            c.error_once(f"precondition: {e}")
            res = None
        except lib.HarnessError as e:
            c.error_once(f"harness: {e}")
            res = None
        finally:
            try:
                _cleanup(c)
            except Exception:  # noqa: BLE001
                pass
        return res if res is not None else c.done()
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


# ---------------------------------------------------------------------------
# data-op requests (HTTP + CLI `run`)
# ---------------------------------------------------------------------------
def _cli_actor_kw(c, actor):
    a = c.actor(actor)
    if a.kind == "user" and not a.home:
        # no CLI home (scratch or root): drive the CLI with the raw PAT via COFFER_TOKEN
        return {"actor": None, "env": {"COFFER_TOKEN": a.secret}} if a.secret else {"actor": None}
    return {"actor": a}


def _req(c, op, actor, p, e, key, *, value=None, to=1, expect_canary=None):
    """Zero-arg closure performing one data operation."""
    if op == "list":
        return lambda: c.api("GET", _sp(p, e), actor=actor)
    if op == "get":
        return lambda: c.api("GET", _sp(p, e, key), actor=actor)
    if op == "ver":
        return lambda: c.api("GET", _sp(p, e, key, "/versions/1"), actor=actor)
    if op == "hist":
        return lambda: c.api("GET", _sp(p, e, key, "/versions"), actor=actor)
    if op == "export":
        return lambda: c.api("GET", f"/projects/{p}/envs/{e}/export", actor=actor, query={"format": "json"})
    if op == "run":
        kw = _cli_actor_kw(c, actor)
        env = dict(kw.pop("env", {}) or {})
        env["S_EXPECT"] = expect_canary or "-"

        def run():
            return c.cli("run", "-p", p, "-e", e, "--", "/bin/sh", "-c",
                         f'[ "${{{key}}}" = "$S_EXPECT" ]', env=env, timeout=60, **kw)
        return run
    if op == "set":
        return lambda: c.api("PUT", _sp(p, e, key), actor=actor, json={"value": value or "x"})
    if op == "del":
        return lambda: c.api("DELETE", _sp(p, e, key), actor=actor)
    if op == "rb":
        return lambda: c.api("POST", _sp(p, e, key, "/rollback"), actor=actor, json={"to": to})
    raise ValueError(op)


def _data_cells(c, actor, envs=("dev", "prod")):
    """Score every data-op cell of ROLE_MATRIX for `actor` on acme api/<env>."""
    for e in envs:
        canary = _canary(c, f"acme/api/{e}/CANARY")
        for op in DATA_OPS:
            want = _cell(actor, op, e)
            what = f"{actor} {op} api/{e}"
            if want == "~":
                r = _req(c, op, actor, "api", e, "CANARY")()
                c.log("INFO (not scored) %s -> %s", what, _desc(r))
                continue
            if op in ("list", "get", "ver", "hist", "export", "run"):
                ctrl = _req(c, op, "reader@acme", "api", e, "CANARY", expect_canary=canary)
                if want == "ok":
                    r = _req(c, op, actor, "api", e, "CANARY", expect_canary=canary)()
                    _check_read_ok(c, op, r, canary, what)
                elif want == "404":
                    absent = c.absent_slug()
                    _same404(c, _req(c, op, actor, "api", e, "CANARY", expect_canary=canary), ["api"],
                             _req(c, op, actor, absent, e, "CANARY", expect_canary=canary), [absent],
                             ctrl, what)
                else:
                    if op == "list":
                        raise ValueError("list never denied with 403 in this matrix")
                    allow = (403, 404) if want == "4or3" else (int(want),)
                    pr = _req(c, op, actor, "api", e, "CANARY", expect_canary=canary)
                    c.denied(pr, ctrl, allow=allow, what=what)
                continue
            # writes
            if want == "ok" or want == "202":
                _write_ok(c, op, actor, e, int(200 if want == "ok" else 202), what)
                continue
            # denied write: control = writer on its own fresh key; probe key must stay as it was
            if op == "set":
                ck, pk = c.junk_key(), c.junk_key()
            else:
                ck = _fresh_key(c, "api", e, 2)
                pk = _fresh_key(c, "api", e, 2)
            ctrl_raw = _req(c, op, "writer@acme", "api", e, ck, value="ctl")

            def ctrl(ctrl_raw=ctrl_raw):
                r = ctrl_raw()
                _track(r)
                return r
            before = _owner_get(c, "api", e, pk)

            def probe(op=op, pk=pk):
                r = _req(c, op, actor, "api", e, pk, value="PROBE-must-not-land")()
                _track(r)
                return r
            if want == "404":
                absent = c.absent_slug()
                _same404(c, probe, ["api"], _req(c, op, actor, absent, e, pk, value="x"), [absent],
                         ctrl, what)
            else:
                allow = (403, 404) if want == "4or3" else (int(want),)
                c.denied(probe, ctrl, allow=allow, what=what)
            after = _owner_get(c, "api", e, pk)
            c.expect((before.status, _val(c, before), _ver(before)) == (after.status, _val(c, after), _ver(after)),
                     f"{what}: target {pk} changed after denied write "
                     f"({before.status}/v{_ver(before)} -> {after.status}/v{_ver(after)})")


def _check_read_ok(c, op, r, canary, what):
    if op == "run":
        c.expect(r.rc == 0, f"{what}: rc={r.rc} (want 0 and the canary in the child env)")
        return
    if not c.expect(r.status == 200, f"{what}: got {r.status} (want 200)"):
        return
    if op == "list":
        keys = {str(x.get("key")) for x in _rows(_js(r)) if isinstance(x, dict)}
        c.expect("CANARY" in keys, f"{what}: CANARY not in list")
        c.expect(canary not in r.text(), f"{what}: list body contains a secret value")
    elif op in ("get", "ver"):
        if op == "get":
            c.expect(_val(c, r) == canary, f"{what}: value is not the fixture canary")
        else:
            c.expect(_val(c, r) is not None, f"{what}: no value in version 1")
    elif op == "hist":
        c.expect(len(_rows(_js(r))) >= 1, f"{what}: empty history")
    elif op == "export":
        c.expect(canary in r.text(), f"{what}: export lacks the canary")


def _write_ok(c, op, actor, e, want, what):
    """Positive write cell: dev -> exactly 200 and applied; prod -> exactly 202, not applied."""
    if op == "set":
        k = c.junk_key()
        before = None
    else:
        k = _fresh_key(c, "api", e, 2)
        before = _owner_get(c, "api", e, k)
    r = _req(c, op, actor, "api", e, k, value=f"{k}-by-{actor}", to=1)()
    _track(r)
    if not c.expect(r.status == want, f"{what}: got {r.status} (want {want})"):
        return
    after = _owner_get(c, "api", e, k)
    if want == 202:
        c.expect(bool(_cid(r)), f"{what}: 202 without change_id")
        if op == "set":
            c.expect(after.status == 404, f"{what}: value applied before approval ({after.status})")
        else:
            c.expect((after.status, _val(c, after), _ver(after)) == (before.status, _val(c, before), _ver(before)),
                     f"{what}: value changed before approval")
        return
    if op == "set":
        c.expect(after.status == 200 and _val(c, after) == f"{k}-by-{actor}", f"{what}: value not stored")
    elif op == "del":
        c.expect(after.status == 404, f"{what}: key still readable after delete ({after.status})")
    else:
        c.expect(after.status == 200 and _val(c, after) == f"{k}-v1", f"{what}: rollback value is not v1")


# ---------------------------------------------------------------------------
# management-op cells (S9)
# ---------------------------------------------------------------------------
def _add_member(c, actor, role="member"):
    """POST /members, no login. Returns (status, uid, email)."""
    email = f"{c._uniq()}@acme.test"
    pw = c.secret(f"pw0:{email}", _secrets.token_urlsafe(12), "password")
    r = c.api("POST", "/members", actor=actor, json={"email": email, "role": role, "password": pw})
    return r, _find_id(_js(r), "id", "user_id"), email


_EMAILS: dict = {}


def _member_uid(c, role="member", grant_level=None):
    r, uid, email = _add_member(c, "owner@acme", role)
    if r.status not in (200, 201):
        raise _Pre(f"setup POST /members -> {r.status}")
    if not uid:
        for m in _members(c):
            if (m.get("email") or "").lower() == email:
                uid = str(m.get("id") or m.get("user_id"))
    if not uid:
        raise _Pre("setup member has no id")
    _EMAILS[str(uid)] = email
    if grant_level:
        g = c.api("PUT", f"/members/{uid}/grants/api", actor="owner@acme", json={"level": grant_level})
        if g.status not in (200, 201, 204):
            raise _Pre(f"setup grant -> {g.status}")
    return uid


def _new_token(c, actor="owner@acme"):
    r = c.api("POST", "/tokens", actor=actor, json={"project": "api", "env": "dev", "access": "read",
                                                    "ttl_seconds": 3600, "name": c._uniq()})
    d = _js(r)
    if isinstance(d, dict) and d.get("token"):
        c.secret(f"token:{c.id}-{c._next()}", str(d["token"]), "token")
    return r, _find_id(d, "id", "token_id"), (d or {}).get("token") if isinstance(d, dict) else None


def _mgmt_cells(c, actors):
    """Score every management cell for each actor. Controls are admin@acme on its own target."""
    adm = "admin@acme"
    target_cr, _ = _new_cr(c)
    tr, target_tok_id, target_tok = _new_token(c)
    if tr.status not in (200, 201) or not target_tok_id or not target_tok:
        raise _Pre(f"setup token create -> {tr.status}")
    role_target = _member_uid(c)
    for actor in actors:
        for op in MGMT_OPS:
            want = _cell(actor, op, "dev")
            allow = (403, 404) if want == "4or3" else (int(want),)
            what = f"{actor} {op}"
            if op in ("approve", "reject"):
                ccr, _ = _new_cr(c)
                c.denied(lambda op=op, actor=actor: c.api("POST", f"/changes/{target_cr}/{op}", actor=actor, json={}),
                         lambda op=op, ccr=ccr: c.api("POST", f"/changes/{ccr}/{op}", actor=adm, json={}),
                         allow=allow, what=what)
                st = _change_status(c, target_cr)
                c.expect(st == "pending", f"{what}: target change status {st!r} after probe (want pending)")
            elif op == "m_add":
                holder = {}

                def probe(actor=actor, holder=holder):
                    r, uid, email = _add_member(c, actor)
                    holder["email"] = email
                    return r
                c.denied(probe, lambda: _add_member(c, adm)[0], allow=allow, what=what)
                if holder.get("email"):
                    c.expect(all((m.get("email") or "").lower() != holder["email"] for m in _members(c)),
                             f"{what}: member {holder['email']} exists after denied add")
            elif op == "m_role":
                cu = _member_uid(c)
                c.denied(lambda actor=actor: c.api("PATCH", f"/members/{role_target}", actor=actor, json={"role": "admin"}),
                         lambda cu=cu: c.api("PATCH", f"/members/{cu}", actor=adm, json={"role": "admin"}),
                         allow=allow, what=what)
                m = _member(c, role_target)
                c.expect(m is not None and m.get("role") == "member",
                         f"{what}: target role is {None if m is None else m.get('role')!r} (want member)")
            elif op == "m_rm":
                cu, pu = _member_uid(c), _member_uid(c)
                c.denied(lambda actor=actor, pu=pu: c.api("DELETE", f"/members/{pu}", actor=actor),
                         lambda cu=cu: c.api("DELETE", f"/members/{cu}", actor=adm),
                         allow=allow, what=what)
                c.expect(_member(c, pu) is not None, f"{what}: target member gone after denied remove")
            elif op == "g_set":
                cu = _member_uid(c)
                c.denied(lambda actor=actor: c.api("PUT", f"/members/{role_target}/grants/api", actor=actor,
                                                   json={"level": "writer"}),
                         lambda cu=cu: c.api("PUT", f"/members/{cu}/grants/api", actor=adm, json={"level": "writer"}),
                         allow=allow, what=what)
            elif op == "g_rev":
                cu, pu = _member_uid(c, grant_level="viewer"), _member_uid(c, grant_level="viewer")
                c.denied(lambda actor=actor, pu=pu: c.api("DELETE", f"/members/{pu}/grants/api", actor=actor),
                         lambda cu=cu: c.api("DELETE", f"/members/{cu}/grants/api", actor=adm),
                         allow=allow, what=what)
            elif op == "t_new":
                def probe(actor=actor):
                    r, _, tok = _new_token(c, actor)
                    return r
                c.denied(probe, lambda: _new_token(c, adm)[0], allow=allow, what=what)
            elif op == "t_rev":
                cr_, ctid, _ = _new_token(c)
                if not ctid:
                    raise _Pre(f"setup control token -> {cr_.status}")
                c.denied(lambda actor=actor: c.api("DELETE", f"/tokens/{target_tok_id}", actor=actor),
                         lambda ctid=ctid: c.api("DELETE", f"/tokens/{ctid}", actor=adm),
                         allow=allow, what=what)
                still = c.api("GET", _sp("api", "dev"), headers={"Authorization": f"Bearer {target_tok}"})
                c.expect(still.status == 200, f"{what}: target token no longer works ({still.status})")
            elif op == "audit":
                c.denied(lambda actor=actor: c.api("GET", "/audit", actor=actor, query={"limit": 5}),
                         lambda: c.api("GET", "/audit", actor=adm, query={"limit": 5}),
                         allow=allow, what=what)
    # grant targets: role_target must have gained no grant (still invisible -> 404 for nobody's PAT to test);
    # verify through the members view when it exposes grants, else via the change it would make.
    m = _member(c, role_target)
    gr = (m or {}).get("grants")
    if isinstance(gr, (list, dict)) and gr:
        c.expect(False, f"g_set: target member has grants after denied grant set: {gr}")


# ---------------------------------------------------------------------------
# S1-S4 cross-tenant
# ---------------------------------------------------------------------------
@check("S1")
@_guard
def s1(c) -> Result:
    """globex owner -> acme web and every route under it -> 404 identical to nonexistent"""
    g = _need_actor(c, "owner@globex")
    _need_actor(c, "owner@acme")
    web_canary = _canary(c, "acme/web/dev/CANARY")
    # acme web/dev keys the probes aim at (never CANARY for writes)
    kdel, krb = _fresh_key(c, "web", "dev", 2), _fresh_key(c, "web", "dev", 2)
    kset = c.junk_key()
    snap_keys = ("CANARY", kdel, krb, kset)

    def snap():
        out = {}
        for k in snap_keys:
            r = _owner_get(c, "web", "dev", k)
            out[k] = (r.status, _val(c, r), _ver(r))
        envs = c.api("GET", "/projects/web/envs", actor="owner@acme")
        out["_envs"] = sorted(str(x.get("slug") or x.get("name")) for x in _rows(_js(envs)))
        lst = c.api("GET", _sp("web", "dev"), actor="owner@acme")
        out["_keys"] = sorted(str(x.get("key")) for x in _rows(_js(lst)) if not str(x.get("key")).startswith("JUNK_S1_"))
        return out
    before = snap()
    if before["CANARY"][1] != web_canary:
        raise _Pre("owner@acme cannot read acme/web/dev/CANARY")

    def pair(method, tail, body=None, query=None, ctl_tail=None, ctl_method=None, ctl_body=None, ctl_proj="web"):
        def mk(proj, actor, t=tail, m=method, b=body):
            kw = {"actor": actor}
            if b is not None:
                kw["json"] = b
            if query:
                kw["query"] = query
            return lambda: c.api(m, f"/projects/{proj}{t}", **kw)
        absent = c.absent_slug()
        ct = ctl_tail if ctl_tail is not None else tail
        cm = ctl_method or method
        cb = ctl_body if ctl_body is not None else body
        ckw = {"actor": "owner@acme"}
        if cb is not None:
            ckw["json"] = cb
        if query:
            ckw["query"] = query
        ctrl = lambda: c.api(cm, f"/projects/{ctl_proj}{ct}", **ckw)  # noqa: E731
        _same404(c, mk("web", g), ["web"], mk(absent, g), [absent], ctrl, f"globex {method} /projects/<acme web>{tail}")

    pair("GET", "/envs")
    pair("POST", "/envs", body={"slug": "s1x", "protected": False},
         ctl_proj=c.scratch_project("owner@acme", envs=()), ctl_tail="/envs")
    pair("GET", "/envs/dev/secrets")
    pair("GET", "/envs/dev/secrets/CANARY")
    pair("GET", "/envs/dev/secrets/CANARY/versions")
    pair("GET", "/envs/dev/secrets/CANARY/versions/1")
    pair("GET", "/envs/dev/export", query={"format": "json"})
    pair("GET", "/envs/dev/export", query={"format": "dotenv"})
    pair("PUT", f"/envs/dev/secrets/{kset}", body={"value": "S1-PROBE"},
         ctl_tail=f"/envs/dev/secrets/{c.junk_key()}", ctl_body={"value": "ctl"})
    pair("DELETE", f"/envs/dev/secrets/{kdel}", ctl_tail=f"/envs/dev/secrets/{_fresh_key(c, 'web', 'dev')}")
    pair("POST", f"/envs/dev/secrets/{krb}/rollback", body={"to": 1},
         ctl_tail=f"/envs/dev/secrets/{_fresh_key(c, 'web', 'dev', 2)}/rollback")
    # CLI forms (stderr compared the same way)
    for args in (("secrets", "get", "CANARY", "-e", "dev"), ("secrets", "list", "-e", "dev"),
                 ("secrets", "export", "-e", "dev", "--format", "dotenv")):
        absent = c.absent_slug()
        _same404(c, lambda a=args: c.cli(*a, "-p", "web", actor=g), ["web"],
                 lambda a=args, s=absent: c.cli(*a, "-p", s, actor=g), [absent],
                 lambda a=args: c.cli(*a, "-p", "web", actor="owner@acme"),
                 f"globex CLI {' '.join(args[:2])} -p <acme web>")
    # web never appears in globex project list as an acme project
    pl = c.api("GET", "/projects", actor=g)
    c.expect(pl.status == 200 and web_canary not in pl.text() and
             "web" not in [str(x.get("slug")) for x in _rows(_js(pl))],
             f"globex GET /projects -> {pl.status}, lists acme web")
    after = snap()
    c.expect(before == after, f"acme web/dev state changed: {before} -> {after}")
    return c.done(f"{c.controls} controls; every web route 404 identical to absent; acme web state unchanged")


@check("S2")
@_guard
def s2(c) -> Result:
    """Colliding slug: globex api/dev returns only globex values; no acme canary ever"""
    g = _need_actor(c, "owner@globex")
    gdev, gprod = _canary(c, "globex/api/dev/CANARY"), _canary(c, "globex/api/prod/CANARY")
    acme = {k: v for k, v in (c.fx.get("canaries") or {}).items() if k.startswith("acme/")}
    if c.fx.get("multi_core"):
        acme["acme/multi_core"] = c.fx["multi_core"]
    if len(acme) < 4:
        raise _Pre("acme canaries missing")
    # positive control: acme's api/dev really holds a different value at the same path
    ar = _owner_get(c, "api", "dev", "CANARY")
    c.control(lambda: ar, what="owner@acme GET api/dev/CANARY")
    c.expect(_val(c, ar) == acme["acme/api/dev/CANARY"] != gdev, "acme and globex api/dev canaries are not distinct")
    seen = []   # (what, bytes)

    def keep(what, r):
        seen.append((what, r.body if isinstance(r, lib.Resp) else r.out + r.err))
        return r
    r = keep("cli get dev", c.cli("secrets", "get", "CANARY", "-p", "api", "-e", "dev", actor=g))
    c.expect(r.rc == 0 and r.out == gdev.encode(), f"globex `secrets get CANARY -p api -e dev` rc={r.rc}, value not globex's",
             "globex `secrets get CANARY -p api -e dev` -> globex's value")
    r = keep("cli get prod", c.cli("secrets", "get", "CANARY", "-p", "api", "-e", "prod", actor=g))
    c.expect(r.rc == 0 and r.out == gprod.encode(), f"globex `secrets get CANARY -p api -e prod` rc={r.rc}, value not globex's",
             "globex `secrets get CANARY -p api -e prod` -> globex's value")
    for e, want in (("dev", gdev), ("prod", gprod)):
        r = keep(f"api get {e}", c.api("GET", _sp("api", e, "CANARY"), actor=g))
        c.expect(r.status == 200 and _val(c, r) == want, f"globex GET api/{e}/CANARY -> {r.status}, value not globex's",
                 f"globex GET api/{e}/CANARY -> 200, globex's value")
        r = keep(f"api v1 {e}", c.api("GET", _sp("api", e, "CANARY", "/versions/1"), actor=g))
        c.expect(r.status == 200 and _val(c, r) == want, f"globex GET api/{e}/CANARY/versions/1 -> {r.status}")
        keep(f"api hist {e}", c.api("GET", _sp("api", e, "CANARY", "/versions"), actor=g))
        r = keep(f"api list {e}", c.api("GET", _sp("api", e), actor=g))
        keys = sorted(str(x.get("key")) for x in _rows(_js(r)))
        c.expect(r.status == 200 and "MULTI" not in keys, f"globex list api/{e} -> {r.status} keys={keys}")
        r = keep(f"api export json {e}", c.api("GET", f"/projects/api/envs/{e}/export", actor=g, query={"format": "json"}))
        d = _js(r)
        c.expect(r.status == 200 and isinstance(d, dict) and d.get("CANARY") == want and "MULTI" not in d,
                 f"globex export json api/{e} -> {r.status}, not exactly globex values")
        keep(f"api export dotenv {e}", c.api("GET", f"/projects/api/envs/{e}/export", actor=g, query={"format": "dotenv"}))
        r = keep(f"cli export dotenv {e}", c.cli("secrets", "export", "-p", "api", "-e", e, "--format", "dotenv", actor=g))
        c.expect(r.rc == 0 and f'CANARY="{want}"'.encode() in r.out, f"globex CLI export api/{e} rc={r.rc}")
        r = keep(f"cli run {e}", c.cli("run", "-p", "api", "-e", e, "--", "/bin/sh", "-c", '[ "$CANARY" = "$S_EXPECT" ]',
                                       actor=g, env={"S_EXPECT": want}))
        c.expect(r.rc == 0, f"globex run api/{e}: CANARY in child is not globex's (rc={r.rc})")
    r = keep("api get MULTI", c.api("GET", _sp("api", "dev", "MULTI"), actor=g))
    c.expect(r.status == 404, f"globex GET api/dev/MULTI (acme-only key) -> {r.status} (want 404)")
    keep("changes", c.api("GET", "/changes", actor=g))
    keep("audit", c.api("GET", "/audit", actor=g, query={"limit": 200}))
    # a globex service token on the colliding path
    t = c.scratch_token("api", "dev", "read", actor=g, org="globex")
    r = keep("token get dev", c.api("GET", _sp("api", "dev", "CANARY"), actor=t))
    c.expect(r.status == 200 and _val(c, r) == gdev, f"globex token GET api/dev/CANARY -> {r.status}, value not globex's",
             "globex token GET api/dev/CANARY -> 200, globex's value")
    r = keep("token export", c.api("GET", "/projects/api/envs/dev/export", actor=t, query={"format": "dotenv"}))
    hits = [f"{w}:{lbl}" for w, b in seen for lbl, v in acme.items() if v.encode() in b]
    c.expect(not hits, f"acme canary in globex response: {hits[:5]}",
             f"no acme canary in any of {len(seen)} globex responses")
    return c.done(f"{len(seen)} globex responses, only globex values, no acme canary")


@check("S3")
@_guard
def s3(c) -> Result:
    """IDOR with acme IDs by globex owner -> 404; acme state unchanged"""
    g = _need_actor(c, "owner@globex")
    adm = "admin@acme"
    cr_target, _ = _new_cr(c)
    cr_target2, _ = _new_cr(c)
    tr, tok_target, tok_val = _new_token(c)
    if not tok_target or not tok_val:
        raise _Pre(f"setup token -> {tr.status}")
    u_patch, u_del = _member_uid(c), _member_uid(c)
    # r4 (S3 on build-2): the grant targets are logged-in scratch members, so the effect of
    # the PUT/DELETE grant probes can be read back by their own access (grants are not in
    # /members, /tokens or /changes).
    try:
        a_grant = c.scratch_user("acme", "member")
        a_grev = c.scratch_user("acme", "member", grants={"api": "viewer"})
    except lib.HarnessError as e:
        raise _Pre(f"grant-target scratch members: {e}")
    u_grant, u_grev = a_grant.user_id, a_grev.user_id
    gkey = "CANARY"
    writer = c.actor("writer@acme")
    fixture_tok = c.actor("T_dev_r")

    def norm_rows(rows):
        out = []
        for x in rows:
            if isinstance(x, dict):
                out.append({k: v for k, v in sorted(x.items()) if not k.startswith("last_") and k != "updated_at"})
        return sorted(out, key=lambda d: _json.dumps(d, sort_keys=True, default=str))

    def state():
        return {"members": norm_rows(_members(c)),
                "tokens": norm_rows(_rows(_js(c.api("GET", "/tokens", actor="owner@acme")))),
                "cr": (_change_status(c, cr_target), _change_status(c, cr_target2))}
    # positive controls first (acme admin on its own equivalent targets) so the snapshot excludes them
    ccr1, _ = _new_cr(c)
    ccr2, _ = _new_cr(c)
    c.control(lambda: c.api("POST", f"/changes/{ccr1}/approve", actor=adm, json={}), what="admin approve acme CR")
    c.control(lambda: c.api("POST", f"/changes/{ccr2}/reject", actor=adm, json={}), what="admin reject acme CR")
    _, ctok, _ = _new_token(c)
    c.control(lambda: c.api("DELETE", f"/tokens/{ctok}", actor=adm), what="admin DELETE acme token")
    cu1, cu2, cu3, cu4 = _member_uid(c), _member_uid(c), _member_uid(c), _member_uid(c, grant_level="viewer")
    c.control(lambda: c.api("PATCH", f"/members/{cu1}", actor="owner@acme", json={"role": "admin"}), what="owner PATCH acme member")
    c.control(lambda: c.api("DELETE", f"/members/{cu2}", actor="owner@acme"), what="owner DELETE acme member")
    c.control(lambda: c.api("PUT", f"/members/{cu3}/grants/api", actor="owner@acme", json={"level": "writer"}),
              what="owner PUT acme grant")
    c.control(lambda: c.api("DELETE", f"/members/{cu4}/grants/api", actor="owner@acme"), what="owner DELETE acme grant")
    # grant-target controls: u_grant has no api grant (404), u_grev is a viewer (list 200,
    # value 403); the same reads are repeated after the probes
    def grant_view():
        return (c.api("GET", _sp("api", "dev"), actor=a_grant).status,
                c.api("GET", _sp("api", "dev"), actor=a_grev).status,
                c.api("GET", _sp("api", "dev", gkey), actor=a_grev).status)
    gv0 = grant_view()
    c.log("S3 grant targets before probes: u_grant list=%s, u_grev list=%s value=%s", *gv0)
    if gv0[0] != 404:
        raise _Pre(f"ungranted u_grant GET api/dev -> {gv0[0]} (want 404)")
    c.control(lambda: c.api("GET", _sp("api", "dev"), actor=a_grev), what="viewer u_grev lists api/dev")
    if gv0[2] != 403:
        raise _Pre(f"viewer u_grev GET api/dev/{gkey} -> {gv0[2]} (want 403)")
    before = state()
    if before["cr"] != ("pending", "pending"):
        raise _Pre(f"target CRs not pending: {before['cr']}")
    probes = [
        ("POST", f"/changes/{cr_target}/approve", {}, cr_target),
        ("POST", f"/changes/{cr_target2}/reject", {}, cr_target2),
        ("DELETE", f"/tokens/{tok_target}", None, tok_target),
        ("DELETE", f"/tokens/{fixture_tok.token_id}", None, fixture_tok.token_id),
        ("PATCH", f"/members/{u_patch}", {"role": "owner"}, u_patch),
        ("PATCH", f"/members/{writer.user_id}", {"role": "owner"}, writer.user_id),
        ("DELETE", f"/members/{u_del}", None, u_del),
        ("PUT", f"/members/{u_grant}/grants/api", {"level": "writer"}, u_grant),
        ("DELETE", f"/members/{u_grev}/grants/api", None, u_grev),
    ]
    for m, path, body, rid in probes:
        if not rid:
            c.error_once(f"precondition: missing acme id for {m} {path}")
            continue
        kw = {"actor": g}
        if body is not None:
            kw["json"] = body
        r = c.api(m, path, **kw)
        absent_path = path.replace(str(rid), _like_id(rid))
        a = c.api(m, absent_path, **kw)
        if a.status != 404:
            c.log("note: absent-id twin %s %s -> %s", m, absent_path, a.status)
        ok = c.expect(r.status == 404, f"globex {m} {path.replace(str(rid), '<acme id>')} -> {r.status} (want 404)")
        if ok and a.status == 404:
            pn, ph = _norm(r, [rid], True)
            an, ah = _norm(a, [absent_path.split('/')[2]], True)
            c.expect(pn == an and ph[0] == ah[0], f"globex {m} acme id: 404 differs from absent id: {pn[:80]!r} vs {an[:80]!r}")
    after = state()
    for k in before:
        c.expect(before[k] == after[k], f"acme {k} changed after globex IDOR probes")
    still = c.api("GET", _sp("api", "dev"), headers={"Authorization": f"Bearer {tok_val}"})
    c.expect(still.status == 200, f"acme scratch token stopped working after globex DELETE ({still.status})")
    sw = c.api("GET", _sp("api", "dev"), actor=fixture_tok)
    c.expect(sw.status == 200, f"T_dev_r stopped working after globex DELETE ({sw.status})")
    w = _member(c, writer.user_id)
    c.expect(w is not None and w.get("role") == "member", f"writer@acme role now {None if w is None else w.get('role')!r}",
             "writer@acme is still a member")
    gv1 = grant_view()
    c.expect(gv1[0] == 404, f"u_grant GET api/dev -> {gv1[0]} after globex PUT grant (want 404: grant applied?)",
             "u_grant still has no api access after globex PUT grant (404)")
    c.expect(gv1[1] == 200 and gv1[2] == 403,
             f"u_grev list/value -> {gv1[1]}/{gv1[2]} after globex DELETE grant (want 200/403: grant removed?)",
             "u_grev still a viewer after globex DELETE grant (list 200, value 403)")
    pg = c.api("GET", _sp("api", "dev"), actor=c.scratch_user("acme"))  # sanity: fresh member w/o grant still 404
    c.expect(pg.status == 404, f"fresh ungranted acme member GET api -> {pg.status}")
    return c.done(f"{len(probes)} IDOR probes 404; acme members/tokens/changes and the 2 probed grants unchanged")


@check("S4")
@_guard
def s4(c) -> Result:
    """Platform admin -> every org-scoped route 404; only /admin/* works"""
    root = _need_actor(c, "root")
    own, adm = "owner@acme", "admin@acme"
    cr, _ = _new_cr(c)
    ccr, _ = _new_cr(c)
    ccr2, _ = _new_cr(c)
    tr, tid, _ = _new_token(c)
    _, ctid, _ = _new_token(c)
    uid, cuid = _member_uid(c), _member_uid(c)
    k = _fresh_key(c, "api", "dev", 2)
    ck = _fresh_key(c, "api", "dev", 2)
    rs = lambda m, p, **kw: (lambda: c.api(m, p, actor=root, **kw))  # noqa: E731
    os_ = lambda a, m, p, **kw: (lambda: c.api(m, p, actor=a, **kw))  # noqa: E731
    # project routes: identical to an absent project
    for m, tail, kw, ctail in [
        ("GET", "/envs", {}, "/envs"),
        ("GET", "/envs/dev/secrets", {}, "/envs/dev/secrets"),
        ("GET", "/envs/dev/secrets/CANARY", {}, "/envs/dev/secrets/CANARY"),
        ("GET", "/envs/dev/secrets/CANARY/versions", {}, "/envs/dev/secrets/CANARY/versions"),
        ("GET", "/envs/dev/export", {"query": {"format": "json"}}, "/envs/dev/export"),
        ("PUT", f"/envs/dev/secrets/{c.junk_key()}", {"json": {"value": "S4-PROBE"}}, f"/envs/dev/secrets/{c.junk_key()}"),
        ("DELETE", f"/envs/dev/secrets/{k}", {}, f"/envs/dev/secrets/{ck}"),
        ("POST", f"/envs/dev/secrets/{k}/rollback", {"json": {"to": 1}}, f"/envs/dev/secrets/{_fresh_key(c, 'api', 'dev', 2)}/rollback"),
    ]:
        ab = c.absent_slug()
        _same404(c, rs(m, f"/projects/api{tail}", **kw), ["api"], rs(m, f"/projects/{ab}{tail}", **kw), [ab],
                 os_(own, m, f"/projects/api{ctail}", **({"query": kw["query"]} if "query" in kw else
                                                         {"json": kw["json"]} if "json" in kw else {})),
                 f"root {m} /projects/api{tail}")
    # org-scoped collection and IDOR routes: exactly 404
    pslug = c._uniq()
    plan = [
        ("GET /projects", rs("GET", "/projects"), os_(own, "GET", "/projects")),
        ("POST /projects", rs("POST", "/projects", json={"slug": pslug}),
         os_(own, "POST", "/projects", json={"slug": c._uniq()})),
        ("GET /members", rs("GET", "/members"), os_(own, "GET", "/members")),
        ("POST /members", rs("POST", "/members", json={"email": f"{c._uniq()}@acme.test", "role": "member",
                                                      "password": c.secret("pw0:s4", _secrets.token_urlsafe(12))}),
         lambda: _add_member(c, own)[0]),
        ("PATCH /members/{id}", rs("PATCH", f"/members/{uid}", json={"role": "admin"}),
         os_(own, "PATCH", f"/members/{cuid}", json={"role": "admin"})),
        ("PUT grant", rs("PUT", f"/members/{uid}/grants/api", json={"level": "writer"}),
         os_(own, "PUT", f"/members/{cuid}/grants/api", json={"level": "writer"})),
        ("DELETE /members/{id}", rs("DELETE", f"/members/{uid}"), os_(own, "DELETE", f"/members/{cuid}")),
        ("GET /tokens", rs("GET", "/tokens"), os_(own, "GET", "/tokens")),
        ("POST /tokens", rs("POST", "/tokens", json={"project": "api", "env": "dev", "access": "read", "ttl_seconds": 600}),
         lambda: _new_token(c, own)[0]),
        ("DELETE /tokens/{id}", rs("DELETE", f"/tokens/{tid}"), os_(own, "DELETE", f"/tokens/{ctid}")),
        ("GET /changes", rs("GET", "/changes"), os_(own, "GET", "/changes")),
        ("approve", rs("POST", f"/changes/{cr}/approve", json={}), os_(adm, "POST", f"/changes/{ccr}/approve", json={})),
        ("reject", rs("POST", f"/changes/{cr}/reject", json={}), os_(adm, "POST", f"/changes/{ccr2}/reject", json={})),
        ("GET /audit", rs("GET", "/audit", query={"limit": 5}), os_(own, "GET", "/audit", query={"limit": 5})),
        ("GET /audit/verify", rs("GET", "/audit/verify"), os_(own, "GET", "/audit/verify")),
    ]
    for what, probe, ctrl in plan:
        c.denied(probe, ctrl, allow=(404,), what=f"root {what}")
    c.expect(_change_status(c, cr) == "pending", "acme CR not pending after root approve/reject")
    c.expect(_member(c, uid) is not None and _member(c, uid).get("role") == "member", "acme member changed by root")
    c.expect(pslug not in [str(x.get("slug")) for x in _rows(_js(c.api("GET", "/projects", actor=own)))],
             "root POST /projects created a project in acme")
    # CLI form
    c.denied(lambda: c.cli("secrets", "get", "CANARY", "-p", "api", "-e", "dev", **_cli_actor_kw(c, root)),
             lambda: c.cli("secrets", "get", "CANARY", "-p", "api", "-e", "dev", actor=own),
             allow=(404,), what="root CLI secrets get api/dev")
    # /admin/* works for root
    for p in ("/admin/orgs", "/admin/audit", "/admin/audit/verify"):
        r = c.api("GET", p, actor=root, query={"limit": 5} if p == "/admin/audit" else None)
        c.expect(r.status == 200, f"root GET {p} -> {r.status} (want 200)")
    r = c.api("GET", "/admin/orgs", actor=root)
    c.expect("acme" in r.text() and _canary(c, "acme/api/dev/CANARY") not in r.text(), "root /admin/orgs lacks acme or leaks a value")
    return c.done(f"{c.controls} controls; every org-scoped route 404 for root; /admin/* 200")


# ---------------------------------------------------------------------------
# S5-S9 role matrix
# ---------------------------------------------------------------------------
@check("S5")
@_guard
def s5(c) -> Result:
    """nogrant -> api -> 404 everywhere"""
    _need_actor(c, "nogrant@acme")
    _data_cells(c, "nogrant@acme")
    # project list must not show api; env list 404 like absent
    pl = c.api("GET", "/projects", actor="nogrant@acme")
    c.expect(pl.status == 200 and "api" not in [str(x.get("slug")) for x in _rows(_js(pl))],
             f"nogrant GET /projects -> {pl.status}, lists api")
    ab = c.absent_slug()
    _same404(c, lambda: c.api("GET", "/projects/api/envs", actor="nogrant@acme"), ["api"],
             lambda: c.api("GET", f"/projects/{ab}/envs", actor="nogrant@acme"), [ab],
             lambda: c.api("GET", "/projects/api/envs", actor="reader@acme"), "nogrant GET /projects/api/envs")
    for args in (("secrets", "get", "CANARY", "-e", "dev"), ("secrets", "list", "-e", "prod")):
        ab = c.absent_slug()
        _same404(c, lambda a=args: c.cli(*a, "-p", "api", actor="nogrant@acme"), ["api"],
                 lambda a=args, s=ab: c.cli(*a, "-p", s, actor="nogrant@acme"), [ab],
                 lambda a=args: c.cli(*a, "-p", "api", actor="reader@acme"), f"nogrant CLI {' '.join(args[:2])}")
    return c.done(f"{c.controls} controls; nogrant 404 identical to absent on every api route")


@check("S6")
@_guard
def s6(c) -> Result:
    """viewer: list 200, values 403, writes 403"""
    _need_actor(c, "viewer@acme")
    _data_cells(c, "viewer@acme")
    r = c.cli("secrets", "get", "CANARY", "-p", "api", "-e", "dev", actor="viewer@acme")
    c.expect(r.rc == 4 and _canary(c, "acme/api/dev/CANARY").encode() not in r.out + r.err,
             f"viewer CLI secrets get -> rc={r.rc} (want 4, no value)")
    return c.done(f"{c.controls} controls; viewer list 200, values 403, writes 403")


@check("S7")
@_guard
def s7(c) -> Result:
    """reader: get/export/run work; writes 403"""
    _need_actor(c, "reader@acme")
    _data_cells(c, "reader@acme")
    can = _canary(c, "acme/api/dev/CANARY")
    r = c.cli("secrets", "get", "CANARY", "-p", "api", "-e", "dev", actor="reader@acme")
    c.expect(r.rc == 0 and r.out == can.encode(), f"reader CLI secrets get rc={r.rc}, value not exact")
    r = c.cli("secrets", "export", "-p", "api", "-e", "dev", "--format", "dotenv", actor="reader@acme")
    c.expect(r.rc == 0 and f'CANARY="{can}"'.encode() in r.out, f"reader CLI export rc={r.rc}")
    return c.done(f"{c.controls} controls; reader reads ok on dev+prod, writes 403")


@check("S8")
@_guard
def s8(c) -> Result:
    """writer: dev writes 200; prod -> 202"""
    _need_actor(c, "writer@acme")
    _data_cells(c, "writer@acme")
    # CLI form: protected set exits 7 with a change id; dev set exits 0
    k = c.junk_key()
    r = c.cli("secrets", "set", k, "v", "-p", "api", "-e", "dev", actor="writer@acme")
    c.expect(r.rc == 0, f"writer CLI set dev rc={r.rc} (want 0)")
    r = c.cli("secrets", "set", c.junk_key(), "v", "-p", "api", "-e", "prod", actor="writer@acme", json=True)
    d = None
    try:
        d = r.json()
    except ValueError:
        pass
    if isinstance(d, dict) and d.get("change_id"):
        _PENDING.append(str(d["change_id"]))
    c.expect(r.rc == 7 and isinstance(d, dict) and d.get("status") == "pending" and bool(d.get("change_id")),
             f"writer CLI set prod --json rc={r.rc} out={r.text()[:80]!r} (want 7 + pending change_id)")
    return c.done("writer dev writes 200 + applied; prod writes 202 + not applied")


@check("S9")
@_guard
def s9(c) -> Result:
    """Members: approve, member/grant/token management, audit list -> 403"""
    actors = ("writer@acme", "reader@acme", "viewer@acme", "nogrant@acme")
    for a in actors:
        _need_actor(c, a)
    _mgmt_cells(c, actors)
    # CLI forms for one member
    cr, _ = _new_cr(c)
    ccr, _ = _new_cr(c)
    c.denied(lambda: c.cli("change", "approve", cr, actor="reader@acme"),
             lambda: c.cli("change", "approve", ccr, actor="admin@acme"), allow=(403,), what="reader CLI change approve")
    c.denied(lambda: c.cli("audit", "list", "--limit", "5", actor="writer@acme"),
             lambda: c.cli("audit", "list", "--limit", "5", actor="admin@acme"), allow=(403,), what="writer CLI audit list")
    c.denied(lambda: c.cli("token", "create", "-p", "api", "-e", "dev", "--access", "read", "--ttl", "1h", actor="writer@acme"),
             lambda: _new_token(c, "admin@acme")[0],
             allow=(403,), what="writer CLI token create")
    return c.done(f"{c.controls} controls; every member management cell 403")


# ---------------------------------------------------------------------------
# S10-S12
# ---------------------------------------------------------------------------
@check("S10")
@_guard
def s10(c) -> Result:
    """Two-person rule: proposer cannot approve own CR as writer, admin, owner; admin2 can"""
    for a in ("writer@acme", "admin@acme", "admin2@acme", "owner@acme"):
        _need_actor(c, a)
    for proposer in ("writer@acme", "admin@acme", "owner@acme"):
        cid, k = _new_cr(c, proposer)
        ccid, _ = _new_cr(c, proposer)
        c.denied(lambda cid=cid, p=proposer: c.api("POST", f"/changes/{cid}/approve", actor=p, json={}),
                 lambda ccid=ccid: c.api("POST", f"/changes/{ccid}/approve", actor="admin2@acme", json={}),
                 allow=(403,), what=f"{proposer} approves own CR")
        st = _change_status(c, cid)
        c.expect(st == "pending", f"{proposer} own CR status {st!r} after self-approve (want pending)")
        g = _owner_get(c, "api", "prod", k)
        c.expect(g.status == 404, f"{proposer} self-approve applied the value ({g.status})")
        r = c.api("POST", f"/changes/{cid}/approve", actor="admin2@acme", json={})
        c.expect(r.status == 200, f"admin2 approves {proposer}'s CR -> {r.status} (want 200)")
        g = _owner_get(c, "api", "prod", k)
        c.expect(g.status == 200 and _val(c, g) == f"{k}-cr", f"admin2 approval of {proposer}'s CR not applied ({g.status})")
        c.expect(_change_status(c, cid) == "approved", f"{proposer}'s CR status after admin2 approve != approved")
    # CLI form: owner self-approve -> exit 4
    cid, _ = _new_cr(c, "owner@acme")
    ccid, _ = _new_cr(c, "owner@acme")
    c.denied(lambda: c.cli("change", "approve", cid, actor="owner@acme"),
             lambda: c.cli("change", "approve", ccid, actor="admin2@acme"), allow=(403,), what="owner CLI approve own CR")
    return c.done("writer/admin/owner self-approve 403; admin2 approves 200 and applies")


@check("S11")
@_guard
def s11(c) -> Result:
    """Admin cannot create, promote, demote or remove an owner (403)"""
    adm, own = "admin@acme", "owner@acme"
    _need_actor(c, adm)
    o = _need_actor(c, own)
    # create an owner
    holder = {}

    def probe_create():
        r, uid, email = _add_member(c, adm, "owner")
        holder["email"] = email
        return r
    c.denied(probe_create, lambda: _add_member(c, own, "owner")[0], allow=(403,), what="admin POST /members role=owner")
    if holder.get("email"):
        c.expect(all((m.get("email") or "").lower() != holder["email"] for m in _members(c)),
                 "admin-created owner exists after 403")
    # promote a member to owner
    pu, cu = _member_uid(c), _member_uid(c)
    c.denied(lambda: c.api("PATCH", f"/members/{pu}", actor=adm, json={"role": "owner"}),
             lambda: c.api("PATCH", f"/members/{cu}", actor=own, json={"role": "owner"}), allow=(403,),
             what="admin promotes member to owner")
    m = _member(c, pu)
    c.expect(m is not None and m.get("role") == "member", f"promoted target role {None if m is None else m.get('role')!r}")
    # demote / remove an owner: targets are scratch owners created by owner@acme; controls by the owner
    t1, t2, ct1, ct2, ct3 = (_member_uid(c, "owner") for _ in range(5))
    c.denied(lambda: c.api("PATCH", f"/members/{t1}", actor=adm, json={"role": "member"}),
             lambda: c.api("PATCH", f"/members/{ct1}", actor=own, json={"role": "member"}), allow=(403,),
             what="admin demotes an owner")
    c.denied(lambda: c.api("DELETE", f"/members/{t2}", actor=adm),
             lambda: c.api("DELETE", f"/members/{ct2}", actor=own), allow=(403,), what="admin removes an owner")
    c.denied(lambda: c.api("PATCH", f"/members/{o.user_id}", actor=adm, json={"role": "admin"}),
             lambda: c.api("PATCH", f"/members/{ct3}", actor=own, json={"role": "admin"}), allow=(403,),
             what="admin demotes owner@acme")
    for t in (t1, t2, o.user_id):
        m = _member(c, t)
        c.expect(m is not None and m.get("role") == "owner", f"owner {t} is {None if m is None else m.get('role')!r} after admin probes")
    # CLI form
    pe, ce = _EMAILS.get(str(pu)), _EMAILS.get(str(_member_uid(c)))
    if pe and ce:
        c.denied(lambda: c.cli("member", "role", pe, "owner", actor=adm),
                 lambda: c.cli("member", "role", ce, "owner", actor=own), allow=(403,),
                 what="admin CLI member role <member> owner")
    m = _member(c, pu)
    c.expect(m is not None and m.get("role") == "member", f"CLI-promoted target role {None if m is None else m.get('role')!r}")
    return c.done("admin create/promote/demote/remove owner -> 403; owners unchanged")


@check("S12")
@_guard
def s12(c) -> Result:
    """Last owner cannot demote or remove themselves -> 409"""
    slug, o = c.scratch_org()
    me = c.api("GET", "/me", actor=o)
    uid = _find_id(_js(me), "id", "user_id")
    if not uid:
        for m in _members(c, o):
            if (m.get("email") or "").lower() == o.email.lower():
                uid = str(m.get("id") or m.get("user_id"))
    if not uid:
        raise _Pre("scratch org owner has no id")
    # non-vacuity: with two owners, demoting one works
    pw = c.secret(f"pw0:s12-{slug}", _secrets.token_urlsafe(12), "password")
    r = c.api("POST", "/members", actor=o, json={"email": f"o2-{slug}@{slug}.test", "role": "owner", "password": pw})
    o2 = _find_id(_js(r), "id", "user_id")
    if r.status not in (200, 201) or not o2:
        raise _Pre(f"second owner create -> {r.status}")
    c.control(lambda: c.api("PATCH", f"/members/{o2}", actor=o, json={"role": "admin"}),
              what="demote a non-last owner (two owners present)")
    roles = [m.get("role") for m in _members(c, o)]
    c.expect(roles.count("owner") == 1, f"scratch org owners after demote: {roles}")
    r = c.api("PATCH", f"/members/{uid}", actor=o, json={"role": "admin"})
    c.expect(r.status == 409, f"last owner PATCH self role=admin -> {r.status} (want 409)")
    r = c.api("PATCH", f"/members/{uid}", actor=o, json={"role": "member"})
    c.expect(r.status == 409, f"last owner PATCH self role=member -> {r.status} (want 409)")
    r = c.api("DELETE", f"/members/{uid}", actor=o)
    c.expect(r.status == 409, f"last owner DELETE self -> {r.status} (want 409)")
    h = c.scratch_home(o)
    r = c.cli("member", "role", o.email, "member", home=h)
    c.expect(r.rc == 8, f"last owner CLI member role self member rc={r.rc} (want 8)")
    r = c.cli("member", "remove", o.email, home=h)
    c.expect(r.rc == 8, f"last owner CLI member remove self rc={r.rc} (want 8)")
    m = _member(c, uid, o)
    c.expect(m is not None and m.get("role") == "owner", f"last owner is now {None if m is None else m.get('role')!r}")
    w = c.api("GET", "/projects", actor=o)
    c.expect(w.status == 200, f"last owner PAT after probes -> {w.status}")
    return c.done("last owner self-demote/remove 409 (API+CLI); non-last owner demote 200")
