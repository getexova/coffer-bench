"""Coffer grading checks: A1, A2, A4, A7, A8, A5, A6, A3 (GRADER.md "A — Audit").

Black-box only: ./bin/coffer (SPEC 7.1), the HTTP API (SPEC 7.2), psql as the
postgres superuser inside the db container (A5/A6 tamper, A3 row scan), and the
sweep cache (A3). Never reads build source. Identical for both builds.

Readings (stricter on the build, identical for both builds):
R1  Audit lists come from GET /audit (org owner/admin) and GET /admin/audit (root),
    limit=1000 (falls back to 500/200/100 if the server rejects 1000). Items are
    the JSON list itself or the first list under items/events/entries/audit/data/
    results/logs. An event is identified by (seq, hash) when present, else by its
    sorted JSON. "New events" for an operation = events not seen in the previous
    fetch of the same log. Each fetch is the union of a plain fetch and a
    since=<check start - 60s> fetch, so oldest-first or newest-first ordering
    both work on long logs.
R2  SPEC 4 field names are used: actor (any key containing "actor", nested dicts
    flattened), target (a key containing "target" must be non-empty), result
    (exactly one of success|denied|failed). A needle (key name, change id, user
    id, token id, email) may appear in any non-volatile field (everything except
    seq/hash/prev_hash/timestamps/ip), because SPEC does not say where details go.
    Actor match: an actor value equals the user/token id or e-mail, or (ids of
    >= 8 chars only) contains it. SPEC 4 allows "actor (user or token ID)", so in A1
    an actor's PAT id also counts. It is learned, never guessed: before the scored
    ops, owner and admin each add one calibration member through the same CLI path;
    the actor values on that member.add event (minus any value the other actor's
    calibration event also carries) are that actor's aliases (r3-1).
R3  A1 runs in a scratch org (small log, no fixture mutation). Ops run through the
    CLI with COFFER_TOKEN = the actor's PAT, except token issue (scratch_token,
    raw API, so the token is registered for redaction first). Export of n=3 live
    keys (dotenv and json each) and `run` need >= 1 distinct read event PER KEY
    whose text mentions that key and none of the other two keys. Login success
    and failure may land in the org log or the platform log (both are watched);
    the failure event must carry result=failed and the e-mail or user id.
    r4-1: SPEC 4 allows result denied|failed and does not say which a failed login
    uses, so a login failure matches result=failed, or result=denied on an event
    whose action/target is login-like (LOGIN_RE); the user id/e-mail is still needed.
    A protected write's CR event matches on the key name OR the change id that the
    CLI printed (--json change_id), as in A8 (r3-1). When a step finds no match, the
    full (redacted) new events are logged.
R4  A2: viewer (403) and nogrant (404) GET of acme/api/dev/CANARY, each after a
    reader control; a scratch-org owner GET of the same acme path (control:
    owner@acme). Pass needs a denied event with that actor in the actor's own
    org log, and no new acme event whose actor is the scratch owner. Unauth failed
    login with an unknown e-mail -> a failed event in /admin/audit. It matches
    on the e-mail; else (SPEC 4 does not require the e-mail) on the ONE new
    platform event in the window with result=failed and a login-like action or
    target (login|auth|token|sign); two or more such events without the e-mail are
    ambiguous and fail (r3-1). r4-1: "failed" there means result=failed, or
    result=denied on a login-like event (the fallback already requires login-like).
    Then `coffer admin audit list` (root) exits 0 and
    shows it (e-mail, or the event's seq/hash, in stdout).
R5  A4: `audit verify` (owner@acme, owner@globex) and `admin audit verify` (root)
    exit 0, and the API verify says valid=true, first_invalid_seq null; each log
    must be non-empty (no vacuous pass).
R6  A5/A6 (destructive slot; runner rolls back the DB too): audit table = base
    table with a hash and a prev_hash-like column. Row = a mid-chain acme event
    (middle of the API list, never the first or last), located by its hash (hex
    or base64 text, or bytea) or else by seq + an org column holding acme's id;
    must match exactly one row. Tamper/delete runs with
    session_replication_role=replica (superuser, bypasses triggers/rules), and
    the row is restored afterwards from its row_to_json copy. Pass needs: verify
    rc 0 before; rc 9 after with first_invalid_seq (API /audit/verify) == the
    tampered seq (A5) / the next seq in the list (A6); rc 0 again after restore
    (else error: the tamper was not the cause).
R7  A3: scans the sweep's pulled audit lists AND a superuser row dump of every
    audit-like table (row_to_json of every row) for every canary/token/password
    needle in raw/hex/HEX/b64. A scanner self-test must hit a planted needle.
"""
from __future__ import annotations

import datetime as _dt
import json as _json
import re
import secrets
import time

from lib import CliResult, HarnessError, Resp  # noqa: F401
from registry import Result, check, not_implemented  # noqa: F401

OWN = "owner@acme"
T = 60.0
VOLATILE = re.compile(r"^(seq|sequence|sequence_number|seq_no|id|event_id|hash|prev_hash|prevhash|ts|time|"
                      r"timestamp|created_at|occurred_at|at|ip|source_ip|ip_address|remote_addr)$", re.I)
RESULTS = ("success", "denied", "failed")
LOGIN_RE = r"login|log_in|auth|token|sign.?in|session"


# ----------------------------------------------------------------- parsing

def _items(obj):
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for k in ("items", "events", "entries", "audit", "data", "results", "logs"):
            if isinstance(obj.get(k), list):
                return obj[k]
        for v in obj.values():
            if isinstance(v, list) and (not v or isinstance(v[0], dict)):
                return v
    return None


def _flat(e: dict) -> dict:
    out = dict(e)
    for k in ("event", "payload"):
        if isinstance(e.get(k), dict):
            for kk, vv in e[k].items():
                out.setdefault(kk, vv)
    return out


def _pick(e: dict, *names):
    f = _flat(e)
    for n in names:
        if n in f and f[n] not in (None, ""):
            return f[n]
    return None


def _seq(e):
    v = _pick(e, "seq", "sequence", "sequence_number", "seq_no")
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _ts(e):
    """event timestamp (RFC3339) -> aware UTC datetime, or None."""
    v = _pick(e, "ts", "timestamp", "time", "at", "created_at", "occurred_at")
    if not isinstance(v, str):
        return None
    t = v.strip().replace("Z", "+00:00")
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)(\.\d+)?(.*)$", t)
    if m:
        t = m.group(1) + ((m.group(2) or "")[:7]) + m.group(3)
    try:
        d = _dt.datetime.fromisoformat(t)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.astimezone(_dt.timezone.utc)


def _result(e):
    v = _pick(e, "result", "outcome")
    return str(v).lower() if v is not None else None


def _action(e):
    v = _pick(e, "action", "event_type", "type")
    return str(v) if v is not None else ""


def _actor_vals(e) -> list:
    vals = []

    def walk(k, v):
        if isinstance(v, dict):
            for kk, vv in v.items():
                walk(k + "." + kk, vv)
        elif isinstance(v, (str, int)) and "actor" in k.lower():
            vals.append(str(v))
    for k, v in _flat(e).items():
        if "actor" in k.lower():
            walk(k, v)
    return vals


def _actor_is(e, ids) -> bool:
    ids = [str(i) for i in ids if i]
    for v in _actor_vals(e):
        for i in ids:
            if v == i or v.lower() == i.lower() or (len(i) >= 8 and i in v):
                return True
    return False


def _has_target(e) -> bool:
    for k, v in _flat(e).items():
        if "target" in k.lower() and v not in (None, "", {}, []):
            return True
    return False


def _text(e) -> str:
    """Non-volatile, non-actor content of the event, as text."""
    f = {k: v for k, v in _flat(e).items() if not VOLATILE.search(k) and "actor" not in k.lower()}
    return _json.dumps(f, ensure_ascii=False, sort_keys=True)


def _ekey(e) -> str:
    s, h = _seq(e), _pick(e, "hash")
    if s is not None or h:
        return f"{s}|{h}"
    return _json.dumps(e, sort_keys=True)


def _short(e) -> str:
    return (f"seq={_seq(e)} action={_action(e)} result={_result(e)} actor={_actor_vals(e)[:2]} "
            f"text={_text(e)[:160]}")


# ----------------------------------------------------------------- fetching

def _fetch(c, actor, path, query=None):
    """-> (status, list of dict events). Tries limit 1000, then smaller."""
    last = 0
    for lim in (1000, 500, 200, 100):
        q = dict(query or {})
        q.setdefault("limit", lim)
        r = c.api("GET", path, actor=actor, query=q, timeout=30)
        last = r.status
        if r.status == 400 and "limit" not in (query or {}):
            continue
        if r.status != 200:
            return r.status, None
        try:
            it = _items(r.json())
        except ValueError:
            return r.status, None
        if it is None:
            return r.status, None
        return 200, [e for e in it if isinstance(e, dict)]
    return last, None


class Tracker:
    def __init__(self, c, actor, path, name):
        self.c, self.actor, self.path, self.name = c, actor, path, name
        self.since = (c.now().replace(microsecond=0) - _dt.timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.seen: set = set()
        self.all: dict = {}
        st, ev = self.fetch()
        if ev is None:
            raise HarnessError(f"{name}: GET {path} -> {st} (no event list)")
        for e in ev:
            self.seen.add(_ekey(e))

    def fetch(self):
        st, ev = _fetch(self.c, self.actor, self.path)
        if ev is None:
            return st, None
        st2, ev2 = _fetch(self.c, self.actor, self.path, {"since": self.since, "limit": 1000})
        merged = {}
        for e in ev + (ev2 or []):
            merged[_ekey(e)] = e
        self.all.update(merged)
        return st, list(merged.values())

    def new(self) -> list:
        st, ev = self.fetch()
        if ev is None:
            self.c.log("%s: refetch -> %s", self.name, st)
            return []
        out = [e for e in ev if _ekey(e) not in self.seen]
        for e in out:
            self.seen.add(_ekey(e))
        return out


def _rc(r):
    if isinstance(r, CliResult):
        return r.rc
    if isinstance(r, Resp):
        return r.status
    return None


def _cli(c, *args, actor=None, home=None, env=None, **kw):
    """c.cli, but a FIXTURE user (saved login in its fixture HOME) runs with a fresh
    HOME and COFFER_TOKEN=<its PAT> (SPEC 7.1). The fixture homes were logged in
    through the F-block proxy URL, and a CLI may bind a saved login to its server
    URL; COFFER_TOKEN is the SPEC-mandated way to supply a PAT, so both builds get
    the same, URL-independent auth. Scratch/token actors are unchanged."""
    if home is None and actor is not None:
        a = c.actor(actor)
        if a.kind == "user" and a.home and a.secret and a.label not in getattr(c, "_actors", {}):
            home = c.tmp / f"home-pat-{secrets.token_hex(4)}"
            home.mkdir(parents=True, mode=0o700, exist_ok=True)
            env = dict(env or {})
            env.setdefault("COFFER_TOKEN", a.secret)
    return c.cli(*args, actor=actor, home=home, env=env, **kw)


def _s(b) -> str:
    """bytes|str|None -> str (r2 fix A2/A7: CliResult.err is bytes)."""
    if b is None:
        return ""
    return b.decode("utf-8", "replace") if isinstance(b, (bytes, bytearray)) else str(b)


def _cli_lim(c, *args, actor=None, lim=1000, **kw):
    """CLI list with --limit LIM; SPEC sets no max, so a usage error (rc 2) naming the
    limit retries with 500/200/100 (same ladder as the API fetch)."""
    r = None
    for n in (lim, 500, 200, 100):
        if n > lim:
            continue
        r = _cli(c, *args, "--limit", str(n), actor=actor, **kw)
        if not (r.rc == 2 and "limit" in _s(r.err).lower()):
            return r, n
        c.log("CLI rejected --limit %d (rc 2); retrying smaller", n)
    return r, n


def _login_failure(e) -> bool:
    """r4-1: a failed login is result=failed, or result=denied on a login-like event
    (SPEC 4 allows denied|failed and does not say which a failed login uses)."""
    r = _result(e)
    if r == "failed":
        return True
    return r == "denied" and re.search(LOGIN_RE, _action(e) + " " + _text(e), re.I) is not None


def _match(evs, *, actor_ids=None, result=None, needles=(), exclude=(), text_any=None, action_re=None,
           login_fail=False):
    """events satisfying all constraints."""
    out = []
    for e in evs:
        t = _text(e)
        whole = _json.dumps(e, ensure_ascii=False)
        if actor_ids is not None and not _actor_is(e, actor_ids):
            continue
        if result is not None and _result(e) not in ((result,) if isinstance(result, str) else result):
            continue
        if login_fail and not _login_failure(e):
            continue
        if any(n not in t for n in needles):
            continue
        if any(x in t for x in exclude):
            continue
        if text_any is not None and not any(n and n in whole for n in text_any):
            continue
        if action_re is not None and not re.search(action_re, _action(e) + " " + t, re.I):
            continue
        out.append(e)
    return out


def _wait_new(c, trackers, pred, tries=6):
    """Accumulate new events from all trackers until pred(events) is true."""
    got = []
    for i in range(tries):
        for t in trackers:
            got.extend(t.new())
        if pred(got):
            break
        time.sleep(0.5)
    return got


def _require(c, what, evs, want: int = 1, distinct_from=None, **kw):
    m = _match(evs, **kw)
    if distinct_from is not None:
        m = [e for e in m if _ekey(e) not in distinct_from]
    ok = len(m) >= want
    for e in m:
        if not _has_target(e):
            c.expect(False, f"{what}: event has no non-empty target field ({_short(e)})")
            return False
        if _result(e) not in RESULTS:
            c.expect(False, f"{what}: result {_result(e)!r} not in {RESULTS}")
            return False
    c.log("%s: %d matching of %d new; %s", what, len(m), len(evs), "; ".join(_short(e) for e in m[:3]))
    if not ok:
        c.log("%s: new events were: %s", what, " || ".join(_short(e) for e in evs[:12]))
        for e in evs[:20]:
            c.log("%s: full event: %s", what, _json.dumps(e, ensure_ascii=False, sort_keys=True,
                                                          default=str)[:2000])
    c.expect(ok, f"{what}: {len(m)} matching audit event(s) (want >= {want}) among {len(evs)} new")
    return m if ok else False


def _keys(c, n):
    return [f"{c.id}_{secrets.token_hex(5).upper()}" for _ in range(n)]


def _val(c, lab):
    return c.secret(f"canary:{c.id}:{lab}", "".join(secrets.choice(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for _ in range(40)), "canary")


def _cid_from(r: CliResult):
    try:
        d = r.json()
        if isinstance(d, dict) and d.get("change_id"):
            return str(d["change_id"])
    except ValueError:
        pass
    m = re.search(r"[A-Za-z0-9_-]{6,}", r.text())
    return m.group(0) if m else None


def _cid_json(r) -> str | None:
    """change_id from the CLI's --json output only (no free-text fallback)."""
    try:
        d = r.json()
        if isinstance(d, dict) and d.get("change_id"):
            return str(d["change_id"])
    except (ValueError, AttributeError):
        pass
    return None


def _member_id(c, actor, email):
    r = c.api("GET", "/members", actor=actor)
    try:
        for m in (_items(r.json()) or []):
            if (m.get("email") or (m.get("user") or {}).get("email") or "").lower() == email:
                return str(m.get("id") or m.get("user_id") or (m.get("user") or {}).get("id") or "") or None
    except (ValueError, AttributeError):
        pass
    return None


def _calib_actor(c, trk, actor, slug, tag, cli):
    """r3-1: one member add by `actor` through the scored CLI path. Returns
    (event-actor values on the matching member.add event, the event or None). The
    match is on the new member's e-mail or id, result=success; never on the actor."""
    email = f"{c.id.lower()}-cal{tag}{secrets.token_hex(3)}@{slug}.test"
    pw = c.secret(f"pw0:{email}", "Cc" + secrets.token_urlsafe(12), "password")
    r = cli("member", "add", email, "--role", "member", actor=actor, stdin=(pw + "\n").encode())()
    if _rc(r) != 0:
        c.log("calibration %s: member add rc=%s; no alias learned", tag, _rc(r))
        return set(), None
    mid = _member_id(c, actor, email)
    MT = tuple(x for x in (mid, email) if x)
    evs = _wait_new(c, trk, lambda ev: bool(_match(ev, result="success", text_any=MT)))
    m = _match(evs, result="success", text_any=MT)
    if len(m) != 1:
        c.log("calibration %s: %d matching member.add events of %d new; no alias learned", tag, len(m), len(evs))
        for e in evs[:10]:
            c.log("calibration %s: full event: %s", tag,
                  _json.dumps(e, ensure_ascii=False, sort_keys=True, default=str)[:2000])
        return set(), None
    vals = {v for v in _actor_vals(m[0]) if v and v not in MT and v.lower() != email}
    c.log("calibration %s: member.add event %s; actor values %s", tag, _short(m[0]), sorted(vals))
    return vals, m[0]


def _me(c, a):
    """Fill a.user_id from GET /me if the login response did not carry it."""
    if a.user_id:
        return
    r = c.api("GET", "/me", actor=a)
    try:
        d = r.json()
        u = d.get("user") if isinstance(d.get("user"), dict) else d
        a.user_id = str(u.get("id") or u.get("user_id") or "") or None
    except (ValueError, AttributeError):
        pass


# ----------------------------------------------------------------- A1

@check("A1")
def a1(c) -> Result:
    """Every value read, write, CR, member/grant/token change and login emits an event"""
    slug, own = c.scratch_org()
    p = c.scratch_project(own, envs=(("dev", False), ("prod", True)))
    adm = c.scratch_user(slug, "admin")
    wr = c.scratch_user(slug, "member", grants={p: "writer"})
    _me(c, own)
    org_t = Tracker(c, own, "/audit", f"audit:{slug}")
    plat_t = Tracker(c, "root", "/admin/audit", "audit:platform")
    c.control(lambda: c.api("GET", "/audit", actor=own, query={"limit": 5}), what="owner reads org audit")
    W = [wr.user_id, wr.email]
    A = [adm.user_id, adm.email]
    O = [own.user_id, own.email]
    K1, K2, K3, KP1, KP2 = _keys(c, 5)
    trk = [org_t]
    S = "success"

    # r3-1: learn each manager's token-id actor alias (SPEC 4 "actor (user or token ID)")
    def _cal_cli(*a, actor=None, **kw):
        return lambda: _cli(c, *a, actor=actor, timeout=T, **kw)
    o_vals, _ = _calib_actor(c, trk, own, slug, "o", _cal_cli)
    a_vals, _ = _calib_actor(c, trk, adm, slug, "a", _cal_cli)
    shared = o_vals & a_vals
    known = {str(x) for x in (wr.user_id, wr.email, adm.user_id, adm.email, own.user_id, own.email) if x}
    o_al = sorted(v for v in o_vals - shared if v not in known - {str(own.user_id), str(own.email)})
    a_al = sorted(v for v in a_vals - shared if v not in known - {str(adm.user_id), str(adm.email)})
    c.log("actor aliases: owner %s, admin %s (dropped as shared: %s)", o_al, a_al, sorted(shared))
    O = O + o_al
    A = A + a_al

    def step(what, fn, want_rc, checks):
        r = fn()
        rc = _rc(r)
        c.expect(rc == want_rc, f"{what}: rc={rc} (want {want_rc})")
        if callable(checks):
            checks = checks(r)

        def pred(evs):
            return all(len(_match(evs, **kw)) >= n for n, kw in checks)
        evs = _wait_new(c, trk, pred)
        for i, (n, kw) in enumerate(checks):
            _require(c, f"{what}[{i}]", evs, want=n, **kw)
        return r, evs

    def sec(*a, actor=wr, **kw):
        return lambda: _cli(c, *a, actor=actor, timeout=T, **kw)

    # writes
    step("set K1 v1", sec("secrets", "set", K1, "-p", p, "-e", "dev", stdin=_val(c, "k1v1").encode()), 0,
         [(1, dict(actor_ids=W, result=S, needles=(K1,)))])
    step("set K1 v2", sec("secrets", "set", K1, "-p", p, "-e", "dev", stdin=_val(c, "k1v2").encode()), 0,
         [(1, dict(actor_ids=W, result=S, needles=(K1,)))])
    step("set K2", sec("secrets", "set", K2, "-p", p, "-e", "dev", stdin=_val(c, "k2").encode()), 0,
         [(1, dict(actor_ids=W, result=S, needles=(K2,)))])
    step("set K3", sec("secrets", "set", K3, "-p", p, "-e", "dev", stdin=_val(c, "k3").encode()), 0,
         [(1, dict(actor_ids=W, result=S, needles=(K3,)))])
    # reads
    step("get K1", sec("secrets", "get", K1, "-p", p, "-e", "dev"), 0,
         [(1, dict(actor_ids=W, result=S, needles=(K1,)))])
    step("get K1 --version 1", sec("secrets", "get", K1, "-p", p, "-e", "dev", "--version", "1"), 0,
         [(1, dict(actor_ids=W, result=S, needles=(K1,)))])
    ks = (K1, K2, K3)
    for fmt in ("dotenv", "json"):
        step(f"export {fmt} (3 keys)", sec("secrets", "export", "-p", p, "-e", "dev", "--format", fmt), 0,
             [(1, dict(actor_ids=W, result=S, needles=(k,), exclude=tuple(x for x in ks if x != k)))
              for k in ks])
    step("run -- /bin/true (3 keys)", sec("run", "-p", p, "-e", "dev", "--", "/bin/true"), 0,
         [(1, dict(actor_ids=W, result=S, needles=(k,), exclude=tuple(x for x in ks if x != k))) for k in ks])
    step("rollback K1 --to 1", sec("secrets", "rollback", K1, "--to", "1", "-p", p, "-e", "dev"), 0,
         [(1, dict(actor_ids=W, result=S, needles=(K1,)))])
    step("delete K3", sec("secrets", "delete", K3, "-p", p, "-e", "dev"), 0,
         [(1, dict(actor_ids=W, result=S, needles=(K3,)))])
    # change requests
    def _cr_checks(k):
        # r3-1: the CR-created event may name the key or the change id the CLI printed (as A8)
        def mk(r):
            cid = _cid_json(r)
            c.log("protected set %s: CLI change_id %s", k, cid)
            return [(1, dict(actor_ids=W, text_any=tuple(x for x in (k, cid) if x)))]
        return mk
    r1, _ = step("protected set KP1 (CR created)",
                 sec("secrets", "set", KP1, "-p", p, "-e", "prod", stdin=_val(c, "kp1").encode(), json=True), 7,
                 _cr_checks(KP1))
    cr1 = _cid_from(r1)
    r2, _ = step("protected set KP2 (CR created)",
                 sec("secrets", "set", KP2, "-p", p, "-e", "prod", stdin=_val(c, "kp2").encode(), json=True), 7,
                 _cr_checks(KP2))
    cr2 = _cid_from(r2)
    if not cr1 or not cr2:
        c.error_once("no change id printed for a protected write")
    else:
        step("approve CR1", sec("change", "approve", cr1, actor=adm), 0,
             [(1, dict(actor_ids=A, result=S, text_any=(cr1, KP1), action_re="approv"))])
        step("reject CR2", sec("change", "reject", cr2, actor=adm), 0,
             [(1, dict(actor_ids=A, result=S, text_any=(cr2, KP2), action_re="reject"))])
    # members / roles / grants
    email = f"{c.id.lower()}-m{secrets.token_hex(3)}@{slug}.test"
    mpw = c.secret(f"pw0:{email}", "Mm" + secrets.token_urlsafe(12), "password")
    # member add: the event may name the new member by e-mail OR by user id, and the
    # id is only known after the add, so look it up before matching.
    r_add = sec("member", "add", email, "--role", "member", actor=own, stdin=(mpw + "\n").encode())()
    c.expect(_rc(r_add) == 0, f"member add: rc={_rc(r_add)} (want 0)")
    mid = _member_id(c, own, email)
    c.log("new member id: %s", mid)
    MT = tuple(x for x in (mid, email) if x)
    evs = _wait_new(c, trk, lambda ev: bool(_match(ev, actor_ids=O, result=S, text_any=MT)))
    _require(c, "member add[0]", evs, actor_ids=O, result=S, text_any=MT)
    step("grant set reader", sec("grant", "set", email, "-p", p, "--level", "reader", actor=own), 0,
         [(1, dict(actor_ids=O, result=S, text_any=MT))])
    step("grant revoke", sec("grant", "revoke", email, "-p", p, actor=own), 0,
         [(1, dict(actor_ids=O, result=S, text_any=MT))])
    step("member role admin", sec("member", "role", email, "admin", actor=own), 0,
         [(1, dict(actor_ids=O, result=S, text_any=MT))])
    step("member remove", sec("member", "remove", email, actor=own), 0,
         [(1, dict(actor_ids=O, result=S, text_any=MT))])
    # tokens
    before = len(org_t.seen)
    tok = c.scratch_token(p, "dev", "read", 3600, actor=own, org=slug)
    evs = _wait_new(c, trk, lambda ev: bool(_match(ev, actor_ids=O, result=S, text_any=(tok.token_id,))))
    c.log("token issue: seen %d -> %d", before, len(org_t.seen))
    if not tok.token_id:
        c.error_once("token create returned no id")
    else:
        _require(c, "token issued", evs, actor_ids=O, result=S, text_any=(tok.token_id,))
        step("token reads K1", lambda: _cli(c, "secrets", "get", K1, "-p", p, "-e", "dev", actor=tok, timeout=T), 0,
             [(1, dict(actor_ids=[tok.token_id], result=S, needles=(K1,)))])
        step("token revoke", sec("token", "revoke", tok.token_id, actor=own), 0,
             [(1, dict(actor_ids=O, result=S, text_any=(tok.token_id,)))])
    # logins (org or platform log)
    trk = [org_t, plat_t]
    WT = tuple(x for x in (wr.user_id, wr.email) if x)
    bad = c.secret(f"pw:wrong:{c.id}", "Wrong-" + secrets.token_urlsafe(12), "password")
    step("login fail (wrong password)",
         lambda: c.cli("login", "--email", wr.email, home=c.scratch_home(), stdin=(bad + "\n").encode(), timeout=T),
         3, [(1, dict(login_fail=True, text_any=WT))])
    step("login success", lambda: c.cli("login", "--email", wr.email, home=c.scratch_home(),
                                        stdin=(wr.password + "\n").encode(), timeout=T),
         0, [(1, dict(result=S, text_any=WT))])
    return c.done("every op (set/get/--version/export x2 per key/run per key/rollback/delete/CR "
                  "create+approve+reject/member+grant+role+remove/token issue+use+revoke/login ok+fail) audited")


# ----------------------------------------------------------------- A2

@check("A2")
def a2(c) -> Result:
    """Denials logged as denied in the actor's org log; no cross-org leak; platform log"""
    path = "/projects/api/envs/dev/secrets/CANARY"
    acme_t = Tracker(c, OWN, "/audit", "audit:acme")
    plat_t = Tracker(c, "root", "/admin/audit", "audit:platform")
    for lab, allow in (("viewer@acme", (403, 404)), ("nogrant@acme", (404, 403))):
        a = c.actor(lab)
        if not a.user_id:
            return c.error(f"fixture {lab} has no user_id")
        ok = c.denied(lambda a=a: c.api("GET", path, actor=a),
                      lambda: c.api("GET", path, actor="reader@acme"), allow=allow, what=f"{lab} GET CANARY")
        if not ok:
            continue
        evs = _wait_new(c, [acme_t], lambda ev, a=a: bool(_match(ev, actor_ids=[a.user_id, a.email],
                                                                 result="denied")))
        _require(c, f"{lab} denial in acme log", evs, actor_ids=[a.user_id, a.email], result="denied")
    # cross-org
    slug, xo = c.scratch_org()
    _me(c, xo)
    x_t = Tracker(c, xo, "/audit", f"audit:{slug}")
    if not xo.user_id:
        return c.error("scratch org owner has no user id (GET /me)")
    acme_t.new()
    ok = c.denied(lambda: c.api("GET", path, actor=xo), lambda: c.api("GET", path, actor=OWN),
                  allow=(403, 404), what="cross-org GET acme CANARY")
    if ok:
        XI = [xo.user_id, xo.email]
        evs = _wait_new(c, [x_t], lambda ev: bool(_match(ev, actor_ids=XI, result="denied")))
        _require(c, "cross-org denial in actor's (scratch) org log", evs, actor_ids=XI, result="denied")
        time.sleep(1.0)
        anew = acme_t.new()
        leak = [e for e in anew if _actor_is(e, XI) or (xo.email and xo.email in _json.dumps(e))]
        c.log("acme new events after cross-org probe: %d; by scratch owner: %d", len(anew), len(leak))
        c.expect(not leak, f"cross-org attempt visible in acme log: {_short(leak[0]) if leak else ''}")
        c.expect(len(anew) >= 1, "acme log recorded nothing (not even the owner control read): tracker blind")
    # unauthenticated failed login -> platform log
    em = f"a2-nobody-{secrets.token_hex(4)}@nowhere.test"
    pw = c.secret(f"pw:a2:{em}", "Nope-" + secrets.token_urlsafe(12), "password")
    plat_t.new()   # r3-1: narrow the window to the one probe below
    r = c.api("POST", "/auth/token", json={"email": em, "password": pw})
    c.expect(r.status in (400, 401), f"unknown-email login -> {r.status} (want 401)")
    evs = _wait_new(c, [plat_t], lambda ev: bool(_match(ev, login_fail=True, text_any=(em,)))
                    or bool(_match(ev, login_fail=True, action_re=LOGIN_RE)))
    if _match(evs, login_fail=True, text_any=(em,)):
        m = _require(c, "unauth failed login in platform log", evs, login_fail=True, text_any=(em,))
    else:
        cand = _match(evs, login_fail=True, action_re=LOGIN_RE)
        c.log("unauth failed login: no event names the e-mail; %d failed login-like event(s) in window: %s",
              len(cand), " || ".join(_short(e) for e in cand[:5]))
        if len(cand) > 1:
            for e in evs[:20]:
                c.log("A2 window full event: %s", _json.dumps(e, ensure_ascii=False, sort_keys=True,
                                                              default=str)[:2000])
            c.expect(False, f"unauth failed login: {len(cand)} failed login-like events in the probe window "
                            "and none names the e-mail (ambiguous)")
            m = False
        else:
            m = _require(c, "unauth failed login in platform log (one failed login-like event)", evs,
                         login_fail=True, action_re=LOGIN_RE)
    cl, cl_lim = _cli_lim(c, "admin", "audit", "list", actor="root", timeout=T)
    c.expect(cl.rc == 0, f"coffer admin audit list rc={cl.rc}")
    if m:
        e = m[0]
        marks = [em] + [str(x) for x in (_pick(e, "hash"),) if x]
        shown = any(x in cl.text() for x in marks)
        if not shown and _seq(e) is not None:
            # r4-1: the seq plus the event's own result word (failed|denied) or action
            low = cl.text().lower()
            shown = re.search(rf"(?<!\d){_seq(e)}(?!\d)", cl.text()) is not None and (
                (_result(e) or "fail") in low or bool(_action(e)) and _action(e).lower() in low)
        plat_n = len(plat_t.all)
        c.log("admin audit list: limit used %s, platform events known %d, shown=%s", cl_lim, plat_n, shown)
        if not shown and cl.rc == 0 and cl_lim < 1000 and plat_n >= cl_lim:
            return c.error(f"admin audit list capped at --limit {cl_lim} (CLI max) below the platform log "
                           f"size ({plat_n}); cannot tell an omission from truncation")
        c.expect(shown, "admin audit list does not show the failed unauth login")
    return c.done("viewer/nogrant denials + cross-org denial in actor's org log, nothing in acme; "
                  "unauth failed login in platform log + admin audit list")


# ----------------------------------------------------------------- A4

def _verify_api(c, actor, path):
    r = c.api("GET", path, actor=actor, timeout=60)
    try:
        d = r.json()
    except ValueError:
        d = None
    return r.status, d


@check("A4")
def a4(c) -> Result:
    """audit verify and admin audit verify pass on the untouched logs"""
    for lab, cmd, path, lpath in ((OWN, ("audit", "verify"), "/audit/verify", "/audit"),
                                  ("owner@globex", ("audit", "verify"), "/audit/verify", "/audit"),
                                  ("root", ("admin", "audit", "verify"), "/admin/audit/verify", "/admin/audit")):
        st, ev = _fetch(c, lab, lpath)
        if ev is None:
            return c.error(f"{lab}: GET {lpath} -> {st}")
        c.expect(len(ev) >= 1, f"{lab}: log non-empty ({len(ev)} events; an empty log would make verify vacuous)")
        r = _cli(c, *cmd, actor=lab, timeout=T)
        c.expect(r.rc == 0, f"{lab}: coffer {' '.join(cmd)} rc={r.rc} (want 0)")
        s, d = _verify_api(c, lab, path)
        c.expect(s == 200 and isinstance(d, dict) and d.get("valid") is True and d.get("first_invalid_seq") is None,
                 f"{lab}: GET {path} -> {s} {str(d)[:100]} (want valid:true, first_invalid_seq:null)")
    return c.done("audit verify (acme, globex) and admin audit verify: rc 0, valid:true")


# ----------------------------------------------------------------- A7

def _cli_events(c, actor, *args):
    args = list(args)
    if "--limit" in args:
        i = args.index("--limit")
        lim = int(args[i + 1])
        del args[i:i + 2]
        r, _n = _cli_lim(c, "audit", "list", *args, actor=actor, lim=lim, json=True, timeout=T)
    else:
        r = _cli(c, "audit", "list", *args, actor=actor, json=True, timeout=T)
    try:
        it = _items(r.json())
    except ValueError:
        it = None
    return r.rc, ([e for e in it if isinstance(e, dict)] if it is not None else None)


@check("A7")
def a7(c) -> Result:
    """Filters --actor, --action, --since, --limit return the correct subsets"""
    slug, own = c.scratch_org()
    p = c.scratch_project(own, envs=(("dev", False),))
    mem = c.scratch_user(slug, "member", grants={p: "writer"})
    if not mem.user_id:
        return c.error("scratch member has no user id")
    t = Tracker(c, own, "/audit", f"audit:{slug}")
    b1 = _keys(c, 2)
    for k in b1:
        _cli(c, "secrets", "set", k, "-p", p, "-e", "dev", actor=mem, stdin=_val(c, k).encode(), timeout=T)
        _cli(c, "secrets", "get", k, "-p", p, "-e", "dev", actor=mem, timeout=T)
    time.sleep(1.2)
    t.new()
    before = set(t.seen)
    # The mark comes from the SERVER's own timestamps (no harness/container clock
    # skew): the first whole second after the newest event seen so far. The
    # tracker's own audit.read events are in `before` and are older than the mark.
    bts = [x for x in (_ts(e) for e in t.all.values() if _ekey(e) in before) if x is not None]
    if not bts:
        return c.error("no parseable event timestamps; cannot place a --since mark")
    mark = max(bts).replace(microsecond=0) + _dt.timedelta(seconds=1)
    t_mid = mark.strftime("%Y-%m-%dT%H:%M:%SZ")
    c.log("since mark %s (newest pre-mark event ts %s)", t_mid, max(bts).isoformat())
    time.sleep(2.5)   # mark <= newest+1s; batch 2 is then later on the server clock (checked below)
    b2 = _keys(c, 2)
    for k in b2:
        _cli(c, "secrets", "set", k, "-p", p, "-e", "dev", actor=mem, stdin=_val(c, k).encode(), timeout=T)
        _cli(c, "secrets", "get", k, "-p", p, "-e", "dev", actor=mem, timeout=T)
    st, full = _fetch(c, own, "/audit")
    if full is None:
        return c.error(f"GET /audit -> {st}")
    fk = {_ekey(e): e for e in full}
    mine = [e for e in full if _actor_is(e, [mem.user_id])]
    b2ev = [e for e in full if any(k in _text(e) for k in b2) and _ekey(e) not in before]
    c.log("full=%d member-events=%d batch2-events=%d", len(full), len(mine), len(b2ev))
    b2_early = [e for e in b2ev if _ts(e) is not None and _ts(e) < mark]
    if b2_early:
        return c.error(f"batch-2 event stamped before the mark {t_mid}: {_short(b2_early[0])}")
    if len(full) < 5 or len(mine) < 4 or not b2ev:
        return c.error(f"not enough events to test filters (full={len(full)} member={len(mine)} b2={len(b2ev)})")
    c.control(lambda: c.api("GET", "/audit", actor=own, query={"limit": 1}), what="owner audit list")
    # --limit
    s, lim = _fetch(c, own, "/audit", {"limit": 3})
    c.expect(lim is not None and len(lim) == 3, f"API limit=3 -> {s} {len(lim) if lim is not None else None} events")
    rc, cl = _cli_events(c, own, "--limit", "3")
    c.expect(rc == 0 and cl is not None and len(cl) == 3,
             f"CLI audit list --limit 3 -> rc={rc} {len(cl) if cl is not None else 'no JSON list'} events")
    # --actor
    for how, res in (("API", _fetch(c, own, "/audit", {"actor": mem.user_id, "limit": 1000})),
                     ("CLI", _cli_events(c, own, "--actor", mem.user_id, "--limit", "1000"))):
        code, ev = res
        if ev is None:
            c.expect(False, f"{how} actor filter -> {code}, no list")
            continue
        wrong = [e for e in ev if not _actor_is(e, [mem.user_id])]
        rk = {_ekey(e) for e in ev}
        missing = [e for e in mine if _ekey(e) not in rk]
        c.expect(ev and not wrong, f"{how} --actor: {len(wrong)} of {len(ev)} not by actor"
                 + (f" e.g. {_short(wrong[0])}" if wrong else ""))
        c.expect(not missing, f"{how} --actor: {len(missing)} of the member's {len(mine)} events missing")
    # --action
    act = _action(mine[-1])
    want = [e for e in full if _action(e) == act]
    for how, res in (("API", _fetch(c, own, "/audit", {"action": act, "limit": 1000})),
                     ("CLI", _cli_events(c, own, "--action", act, "--limit", "1000"))):
        code, ev = res
        if ev is None:
            c.expect(False, f"{how} action filter -> {code}, no list")
            continue
        wrong = [e for e in ev if _action(e) != act]
        rk = {_ekey(e) for e in ev}
        missing = [e for e in want if _ekey(e) not in rk]
        c.expect(ev and not wrong, f"{how} --action {act}: {len(wrong)} of {len(ev)} other actions")
        c.expect(not missing, f"{how} --action {act}: {len(missing)} of {len(want)} expected events missing")
    # --since
    for how, res in (("API", _fetch(c, own, "/audit", {"since": t_mid, "limit": 1000})),
                     ("CLI", _cli_events(c, own, "--since", t_mid, "--limit", "1000"))):
        code, ev = res
        if ev is None:
            c.expect(False, f"{how} since filter -> {code}, no list")
            continue
        rk = {_ekey(e) for e in ev}
        early = [e for e in ev if _ekey(e) in before or (_ts(e) is not None and _ts(e) < mark)]
        missing = [e for e in b2ev if _ekey(e) not in rk]
        c.expect(not early, f"{how} --since {t_mid}: {len(early)} events from before the mark"
                 + (f" e.g. {_short(early[0])}" if early else ""))
        c.expect(not missing, f"{how} --since {t_mid}: {len(missing)} of {len(b2ev)} later events missing")
    c.log("full keys %d", len(fk))
    return c.done("--limit 3 exact; --actor/--action/--since exact subsets (API and CLI)")


# ----------------------------------------------------------------- A8

@check("A8")
def a8(c) -> Result:
    """Change-request lifecycle created/approved/rejected/stale all audited"""
    slug, own = c.scratch_org()
    p = c.scratch_project(own, envs=(("prod", True),))
    adm = c.scratch_user(slug, "admin")
    wr = c.scratch_user(slug, "member", grants={p: "writer"})
    t = Tracker(c, own, "/audit", f"audit:{slug}")
    KS, KR = _keys(c, 2)
    W, A = [wr.user_id, wr.email], [adm.user_id, adm.email]

    def propose(k, lab):
        r = _cli(c, "secrets", "set", k, "-p", p, "-e", "prod", actor=wr, stdin=_val(c, lab).encode(),
                  json=True, timeout=T)
        c.expect(r.rc == 7, f"protected set {lab} rc={r.rc} (want 7)")
        return _cid_from(r) if r.rc == 7 else None
    ca, cb, cr = propose(KS, "a"), propose(KS, "b"), propose(KR, "r")
    if not (ca and cb and cr):
        return c.error("protected write printed no change id")
    created = _wait_new(c, [t], lambda ev: len(_match(ev, actor_ids=W, needles=())) >= 3)
    seen = list(created)
    for cid, k in ((ca, KS), (cb, KS), (cr, KR)):
        m = _match(seen, actor_ids=W, text_any=(cid,))
        if not m:
            m = _match(seen, actor_ids=W, needles=(k,), action_re=r"chang|request|propos|pending|\bcr\b|creat")
        c.expect(bool(m), f"CR {cid} created: no event by proposer mentioning it")
    cnt_ks = len(_match(seen, actor_ids=W, needles=(KS,)))
    c.expect(cnt_ks >= 2 or (_match(seen, text_any=(ca,)) and _match(seen, text_any=(cb,))),
             f"two CRs on {KS}: only {cnt_ks} distinct created events")
    r = _cli(c, "change", "approve", cb, actor=adm, timeout=T)
    c.expect(r.rc == 0, f"approve CR b rc={r.rc}")
    ev = _wait_new(c, [t], lambda e: bool(_match(e, actor_ids=A, text_any=(cb, KS), action_re="approv")))
    _require(c, "approved", ev, actor_ids=A, text_any=(cb, KS), action_re="approv")
    r = _cli(c, "change", "approve", ca, actor=adm, timeout=T)
    c.expect(r.rc == 8, f"approve stale CR a rc={r.rc} (want 8 / 409)")
    ev = _wait_new(c, [t], lambda e: bool(_match(e, text_any=(ca, KS), action_re="stale")))
    _require(c, "stale", ev, text_any=(ca, KS), action_re="stale")
    r = _cli(c, "change", "reject", cr, actor=adm, timeout=T)
    c.expect(r.rc == 0, f"reject CR r rc={r.rc}")
    ev = _wait_new(c, [t], lambda e: bool(_match(e, actor_ids=A, text_any=(cr, KR), action_re="reject")))
    _require(c, "rejected", ev, actor_ids=A, text_any=(cr, KR), action_re="reject")
    return c.done("CR created x3, approved, stale (409), rejected: all audited")


# ----------------------------------------------------------------- A5 / A6

def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _audit_tables(c):
    r = c.psql("SELECT table_schema, table_name, string_agg(column_name || ':' || data_type, ',') "
               "FROM information_schema.columns WHERE table_schema NOT IN ('pg_catalog','information_schema') "
               "AND (table_schema, table_name) IN (SELECT table_schema, table_name FROM information_schema.tables "
               "WHERE table_type='BASE TABLE') GROUP BY 1,2;")
    if r.rc != 0:
        raise HarnessError("information_schema query failed")
    out = []
    for sch, tab, cols in r.rows:
        cd = dict(x.split(":", 1) for x in (cols or "").split(",") if ":" in x)
        names = {k.lower(): k for k in cd}
        prev = [k for k in cd if re.search(r"prev.*hash", k, re.I)]
        hsh = [k for k in cd if k.lower() == "hash"] or [k for k in cd if re.search(r"hash", k, re.I) and k not in prev]
        if prev and hsh:
            out.append({"schema": sch, "table": tab, "cols": cd, "prev": prev[0], "hash": hsh[0], "names": names})
    return out


def _find_row(c, ev, org_id):
    """-> (table dict, WHERE clause) matching exactly one row, or (None, why)."""
    tabs = _audit_tables(c)
    c.log("audit-like tables: %s", [(t["schema"], t["table"]) for t in tabs])
    if not tabs:
        return None, "no audit table (hash + prev_hash columns) found"
    h = str(_pick(ev, "hash") or "")
    seq = _seq(ev)
    for t in tabs:
        fq = f'"{t["schema"]}"."{t["table"]}"'
        hc = f'"{t["hash"]}"'
        conds = []
        if h:
            if t["cols"][t["hash"]] == "bytea":
                conds += [f"encode({hc},'hex') = lower({_q(h)})", f"encode({hc},'base64') = {_q(h)}"]
            else:
                conds += [f"{hc}::text = {_q(h)}", f"lower({hc}::text) = lower({_q(h)})"]
        sc = next((t["names"][n] for n in ("seq", "sequence", "sequence_number", "seq_no") if n in t["names"]), None)
        oc = next((t["names"][n] for n in ("org_id", "organization_id", "org", "tenant_id", "chain_id")
                   if n in t["names"]), None)
        if sc and oc and seq is not None and org_id:
            conds.append(f'"{sc}"::text = {_q(str(seq))} AND "{oc}"::text = {_q(org_id)}')
        for cond in conds:
            r = c.psql(f"SELECT count(*) FROM {fq} WHERE {cond};")
            if r.rc == 0 and r.rows and r.rows[0][0] == "1":
                return (t, cond), None
    return None, f"no audit row matches event seq={seq} hash={h[:16]}"


def _verify(c):
    r = _cli(c, "audit", "verify", actor=OWN, timeout=T)
    s, d = _verify_api(c, OWN, "/audit/verify")
    fis = d.get("first_invalid_seq") if isinstance(d, dict) else None
    c.log("verify: cli rc=%s api=%s %s", r.rc, s, str(d)[:200])
    return r.rc, s, d, fis


def _tamper(c, kind: str) -> Result:
    st, ev = _fetch(c, OWN, "/audit")
    if ev is None:
        return c.error(f"GET /audit -> {st}")
    ev = [e for e in ev if _seq(e) is not None]
    ev.sort(key=_seq)
    if len(ev) < 5:
        return c.error(f"acme log too short ({len(ev)})")
    i = len(ev) // 2
    target, nxt = ev[i], ev[i + 1]
    org_id = ((c.fx.get("orgs") or {}).get("acme") or {}).get("id")
    rc0, s0, d0, _ = _verify(c)
    if rc0 != 0 or not (isinstance(d0, dict) and d0.get("valid") is True):
        return c.error(f"precondition: verify on untouched log rc={rc0} api={str(d0)[:80]}")
    found, why = _find_row(c, target, org_id)
    if not found:
        return c.error(why)
    t, cond = found
    fq = f'"{t["schema"]}"."{t["table"]}"'
    snap = c.psql(f"SELECT row_to_json(x)::text FROM {fq} x WHERE {cond};")
    if snap.rc != 0 or len(snap.rows) != 1:
        return c.error("could not snapshot the target row")
    orig = snap.rows[0][0]
    tag = "q" + secrets.token_hex(6)
    pre = "BEGIN; SET LOCAL session_replication_role = replica; "
    tcol = None
    if kind == "update":
        tcol = next((t["names"][n] for n in ("target", "target_id", "resource") if n in t["names"]),
                    next((k for k in t["cols"] if "target" in k.lower()), None))
        if not tcol:
            return c.error(f"no target column in {t['table']}: {sorted(t['cols'])}")
        dt = t["cols"][tcol]
        if dt in ("jsonb", "json"):
            newv = f"to_jsonb(coalesce(\"{tcol}\"::text,'') || '~A5')::{dt}"
        elif dt in ("text", "character varying", "character"):
            newv = f"coalesce(\"{tcol}\",'') || '~A5'"
        else:
            return c.error(f"target column {tcol} has type {dt}; cannot tamper as text")
        sql = pre + f'UPDATE {fq} SET "{tcol}" = {newv} WHERE {cond}; COMMIT;'
        want = _seq(target)
        what = f"UPDATE {t['table']}.{tcol} at seq {want}"
    else:
        sql = pre + f"DELETE FROM {fq} WHERE {cond}; COMMIT;"
        want = _seq(nxt)
        what = f"DELETE seq {_seq(target)} (expect first_invalid_seq {want})"
    r = c.psql(sql)
    if r.rc != 0:
        return c.error(f"tamper failed: {r.err.strip()[:120]}")
    c.log("tampered: %s", what)
    rc1, s1, d1, fis = _verify(c)
    c.expect(rc1 == 9, f"{what}: coffer audit verify rc={rc1} (want 9)")
    c.expect(isinstance(d1, dict) and d1.get("valid") is False,
             f"{what}: GET /audit/verify -> {s1} {str(d1)[:80]} (want valid:false)")
    try:
        fis_i = int(fis)
    except (TypeError, ValueError):
        fis_i = None
    c.expect(fis_i == want, f"{what}: first_invalid_seq={fis} (want {want})")
    try:
        cj = _cli(c, "audit", "verify", actor=OWN, json=True, timeout=T).json()
        if isinstance(cj, dict) and "first_invalid_seq" in cj:
            c.expect(str(cj["first_invalid_seq"]) == str(want),
                     f"{what}: CLI --json first_invalid_seq={cj['first_invalid_seq']} (want {want})")
    except ValueError:
        c.log("CLI verify --json: not one JSON doc (not scored)")
    # restore
    dq = "$" + tag + "$"
    if kind == "update":
        rs = pre + (f'UPDATE {fq} SET "{tcol}" = (json_populate_record(NULL::{fq}, {dq}{orig}{dq}::json))."{tcol}" '
                    f"WHERE {cond}; COMMIT;")
    else:
        rs = pre + (f"INSERT INTO {fq} OVERRIDING SYSTEM VALUE SELECT * FROM "
                    f"json_populate_record(NULL::{fq}, {dq}{orig}{dq}::json); COMMIT;")
    rr = c.psql(rs)
    if rr.rc != 0:
        c.log("restore failed (runner rollback restores the DB): %s", rr.err.strip()[:200])
        return c.done(f"{what}: verify rc 9, first_invalid_seq {want}")
    rc2, s2, d2, _ = _verify(c)
    if rc2 != 0:
        c.error_once(f"verify still failing after restoring the row (rc={rc2}); cause of rc 9 unproven")
    return c.done(f"{what}: verify rc 9 + first_invalid_seq {want}; restored -> rc 0")


@check("A5")
def a5(c) -> Result:
    """Tamper a mid-chain row -> verify exits 9 with first_invalid_seq = that row"""
    return _tamper(c, "update")


@check("A6")
def a6(c) -> Result:
    """Delete a mid-chain row -> verify exits 9 at the following sequence"""
    return _tamper(c, "delete")


# ----------------------------------------------------------------- A3

@check("A3")
def a3(c) -> Result:
    """No canary, token or password in any audit row"""
    sw = c.sweep()
    needles = sw.needles(("canary", "token", "password"))
    kinds = {k for _, k, _ in needles}
    c.log("needles: %d kinds=%s", len(needles), sorted(kinds))
    if not {"canary", "password", "token"} <= kinds:
        return c.error(f"needle set incomplete: kinds={sorted(kinds)}")
    # self-test of the scanner
    lab, kind, val = next(n for n in needles if len(n[2].encode()) >= 12)
    probe: list = []
    sw._scan_bytes(b"xx" + val.encode() + b"yy", [(lab, kind, val)], "selftest", "selftest", probe, ("raw",))
    if not probe:
        return c.error("scanner self-test found no hit")
    files = sw.files("audit")
    nonempty = [f for f in files if f.stat().st_size > 2]
    c.log("pulled audit files: %s", [(f.name, f.stat().st_size) for f in files])
    if len(nonempty) < 2:
        return c.error(f"sweep pulled {len(nonempty)} non-empty audit lists (want acme/globex/platform)")
    hits = sw.scan(sources=("audit",))
    # direct DB rows
    tabs = _audit_tables(c)
    if not tabs:
        return c.error("no audit table (hash + prev_hash) in the DB")
    rows = 0
    for t in tabs:
        fq = f'"{t["schema"]}"."{t["table"]}"'
        r = c.psql(f"SELECT row_to_json(x)::text FROM {fq} x;", timeout=120)
        if r.rc != 0:
            return c.error(f"dump of {fq} failed")
        rows += len(r.rows)
        p = c.tmp / f"rows-{t['table']}.jsonl"
        p.write_text(r.out, encoding="utf-8")
        sw._scan_bytes(r.out.encode("utf-8"), needles, "db-audit", f"{t['schema']}.{t['table']}", hits,
                       ("raw", "hex", "HEX", "b64"))
    c.log("db audit rows scanned: %d", rows)
    if rows == 0:
        return c.error("audit tables are empty")
    for h in hits[:20]:
        c.log("HIT %s %s %s %s %s @%d", h.source, h.file, h.label, h.kind, h.encoding, h.offset)
    c.expect(not hits, (f"{len(hits)} needle hit(s) in audit: first {hits[0].kind} «{hits[0].label}» "
                        f"({hits[0].encoding}) in {hits[0].source}:{hits[0].file}") if hits else "")
    return c.done(f"0 hits: {len(needles)} needles x {len(nonempty)} API audit lists + {rows} DB audit rows")
