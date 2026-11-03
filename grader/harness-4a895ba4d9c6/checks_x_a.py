"""Coffer grading checks: X1-X10 (data protection, auth hardening, HTTP hygiene, injection).

Black-box only (CONTRACT.md): the SPEC 7.2 HTTP API, ./bin/coffer, psql / pg_dumpall in
the db container (superuser), container logs, compose, repo-level .env.example. No build
source is read. Schema facts (X2, X5) come from information_schema / row contents only.

Readings chosen where GRADER/CONTRACT leave room (stricter on the build, identical for
both builds):

- X1: c.sweep() (cache, CONTRACT 4) scanned over dumps, logs, backups and homes for every
  canary/token/password needle in raw/hex/HEX/b64. X1 first runs one backup.sh itself
  (read-only) so the backups source is never empty. Homes: the CLI's own PAT is the one
  allowed plaintext; a token needle is excused only if its label ends in ":cli" (the label
  X13 uses for the PAT it read from a CLI config) and ALL its hits lie under one single
  home's .config/coffer/. Extra regex pass: any cof_pat_/cof_st_ + >=16 token-shaped string
  in dumps/logs/backups (including decompressed backups) fails; in homes, at most ONE
  distinct token-shaped string per home, and only under .config/coffer/. Positive controls:
  the scanner finds a planted needle in raw/hex/b64; each source has >= 1 file; the dumps
  contain a fixture email and an org id (they hold real app data); logs mention /api/v1;
  at least one home holds a coffer config file with a token-shaped string.
- X6: the dump-only token subset of X1 (needles of kind token + token-shaped regex with
  >= 22 chars after the prefix, i.e. >= ~128 bits). Shorter prefix runs are logged only.
- X2: scratch project (dev, stg) in acme plus junk keys in acme/api/dev and globex/api/dev.
  Six writes, each wrapped in a whole-db row snapshot (md5 of row_to_json per ctid, all
  non-audit public tables) to attribute the new/changed rows to each write. A table counts
  as the ciphertext table if every write produced exactly one changed row in it and it has
  >= 1 "crypto column": bytea, or text/json whose value is base64/hex-like (>= 24 chars),
  distinct across all six writes, not an id/uuid/timestamp, not the key name/value.
  Tamper = UPDATE the dst row's crypto columns from the src row (src: K1->K2 same env,
  dev->stg same key, acme->globex same key). Originals are kept in a scratch schema
  (dropped afterwards; the runner's rollback restores the db anyway). The server is then
  restarted (kills any plaintext cache) and current + v1 get + json export are read as the
  owner. Any 2xx get = fail; any 5xx (or transport error while up) get/export = fail
  (GRADER "Any 500 anywhere is a fail"; registry allow_5xx only spares restart paths);
  an export containing the dst key = fail. A failure to start
  after tampering counts as fail-closed (pass for that read). Controls: every dst reads its
  own value before tampering; the src still reads after tampering; after restoring the
  original crypto columns the dst reads its own value again (proves the tamper was the
  cause). Restore not reading back is an error unless a real failure was already found.
- X3: env_override with the .env.example placeholder, a 16-byte base64 key, and the key
  unset. Each must not become ready. A control override with no change must become ready
  (proves the override/restart path works). If still running after the wait, /readyz is
  polled for 30 s more before deciding.
- X4: canaries + a fresh junk value read as owners; restart PREVIOUS=old MASTER=new ->
  ready + all readable; restart MASTER=new (PREVIOUS removed) -> ready + all readable;
  restart MASTER=old (PREVIOUS removed) -> not ready, or every read is a 4xx (5xx = fail). Any 2xx
  (even the right value) in step 3 fails: the old key must no longer open the data.
- X5: password hashes located by scanning tables that hold the fixture users' emails
  (row_to_json); a value under a key containing pass/pwd, or a $-prefixed hash string. Each
  fixture user must have one; accepted: $argon2id$, bcrypt $2a$/$2b$/$2y$ with cost >= 12
  (variant logged), scrypt ($scrypt$, $7$, scrypt:, scrypt$). Anything else fails. 11-char
  password rejected (400/422) on POST /members, POST /auth/password, POST /admin/orgs and
  `coffer member add` (exit 6); 12-char accepted on each (control); no account created by a
  rejected request (login -> not 2xx).
- X7: 8 scratch users, 30 interleaved pairs (unknown email, wrong password; <= 4 wrong per
  account). All 60 statuses equal (and 4xx); bodies byte-identical after masking only the
  response's own X-Request-Id value; medians max/min <= 1.25. A 429 in the sample = error
  (the measurement is not valid), with the fact recorded. Pairs are paced 0.25 s; a
  limiter 429 is backed off (Retry-After or 2..20 s, 150 s budget/check), logged, counted
  and the same attempt retried, so 429s are never sampled; error only if it persists.
- 429 resilience (X7, X8, X10): lib scratch_user/scratch_org raise on a 429 setup login;
  local _retry429/_login429 back off and retry setup and verification logins only.
  Verdict probes (X8 tries 1-7, X8 B-check, X10 auth probes) never back off.
- X8: scratch A and B. Controls (with backoff): both log in, right before A's failures.
  A: 5 wrong tries, none 429 (want 401); then the correct password -> exactly 429, and a
  7th wrong -> 429. B correct -> 200 immediately (no backoff: a 429 there = fail).
- X9: headers checked on every /api/v1 response this check elicits: 200 (several routes),
  201, 202, 400 (malformed JSON), 401 (anon, bad bearer, bad login), 403, 404, 409, 413
  (raw socket, 2 MiB), wrong method, OPTIONS preflight. Each: Content-Type
  application/json (dotenv export may be text/plain), nosniff, Cache-Control contains
  no-store. CORS: preflight + simple GET with Origin https://evil.test must have no
  Access-Control-Allow-Origin at all. Statuses 400/401/403/404/409/413 must each be seen.
- X10: payloads ' OR 1=1--, "; DROP TABLE, ../../etc/passwd, %00, a Cyrillic homoglyph and
  a fullwidth homoglyph of the slot's real value; path params also with a raw variant
  (only space/"/#/? escaped). Every path param and every typed query param / JSON field ->
  must be 4xx (no 2xx/3xx/5xx/transport error). Free-text fields where SPEC allows any
  string (secret value, token name, new passwords >= 12 chars) may be 2xx only if the value
  round-trips (value GET == sent; password logs in). Free filters (audit actor/action) may
  be 2xx only with an empty result list. Every body is scanned for foreign data: any
  fixture canary, or (for acme actors) the globex org id. A canary of another org is
  reported as "foreign data"; one of the actor's own org that the probe did not ask for
  as "unrequested own-tenant data" (both fail). Each route has a positive
  control (same route, valid value) run first. Afterwards: all fixture canaries still read,
  acme and globex still work, /readyz 200.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json as _json
import re
import secrets as _secrets
import socket
import statistics
import string
import time
import urllib.parse

import lib
from registry import Result, check, not_implemented  # noqa: F401

_ALNUM = string.ascii_letters + string.digits
TOKEN_RE = re.compile(rb"cof_(?:pat|st)_[A-Za-z0-9_\-]{16,}")
MIB = 1024 * 1024
EVIL = "https://evil.test"


def _rand(n: int = 40) -> str:
    return "".join(_secrets.choice(_ALNUM) for _ in range(n))


def _pw(n: int = 16) -> str:
    return "Pw" + _rand(n - 2)


def _items(v):
    if isinstance(v, dict):
        for k in ("items", "events", "entries", "audit", "data", "results", "changes",
                  "tokens", "members", "secrets", "versions", "orgs", "projects"):
            if isinstance(v.get(k), list):
                return v[k]
        return None
    return v if isinstance(v, list) else None


def _jget(r, key, default=None):
    try:
        d = r.json()
    except (ValueError, AttributeError):
        return default
    if isinstance(d, dict):
        return d.get(key, default)
    return default


def _canary_paths(c):
    """[(org, project, env, key, value)] for every fixture canary."""
    out = []
    for path, v in sorted(((c.fx or {}).get("canaries") or {}).items()):
        parts = path.split("/")
        if len(parts) == 4 and v:
            out.append((parts[0], parts[1], parts[2], parts[3], v))
    return out


def _secret_path(p, e, k):
    return f"/projects/{p}/envs/{e}/secrets/{k}"


def _read_value(c, actor, p, e, k):
    r = c.api("GET", _secret_path(p, e, k), actor=actor)
    return r, _jget(r, "value")


def _reg_token(c, r, tag):
    t = _jget(r, "token")
    if isinstance(t, str) and t:
        c.secret(f"token:{c.id}-{tag}-{c._next()}", t, "token")
    return r


def _bump_control(c, what):
    """A non-request positive control (scanner self-test etc.)."""
    with c._lock:
        c.controls += 1
    c.log("CONTROL ok: %s", what)


# --------------------------------------------------------------------------
# rate-limiter resilience (local; lib's scratch_user/_login_raw raise on a 429 login)
# A 429 on a harness-side setup login is not a verdict: back off (Retry-After if given,
# else 2,4,8..20 s) within a per-check budget, log every 429, then retry. Verdict probes
# (X8 tries, X8 B-check) never go through these helpers.
# --------------------------------------------------------------------------

def _budget(c):
    b = getattr(c, "_x429", None)
    if b is None:
        b = {"left": {"X8": 90.0}.get(getattr(c, "id", ""), 150.0), "n429": 0}
        c._x429 = b
    return b


def _backoff(c, what, delay, r=None):
    b = _budget(c)
    ra = None
    try:
        ra = float(((r.headers or {}).get("retry-after") or "").strip()) if r is not None else None
    except ValueError:
        ra = None
    d = min(max(delay, ra or 0.0), 30.0, b["left"])
    if d <= 0:
        return False
    b["n429"] += 1
    c.log("X429 %s -> 429; backoff %.1fs (budget left %.0fs, 429s so far %d)", what, d, b["left"], b["n429"])
    time.sleep(d)
    b["left"] -= d
    return True


def _retry429(c, fn, what):
    """Run a lib scratch helper; retry it after a backoff when its login got 429."""
    delay = 2.0
    while True:
        try:
            return fn()
        except lib.HarnessError as e:
            if "-> 429" not in str(e) or not _backoff(c, f"{what} ({e})", delay):
                raise
            delay = min(delay * 2, 20.0)


def _login429(c, email, pw, tag, what):
    """POST /auth/token, retrying after a backoff on 429. Returns the final Resp."""
    delay = 2.0
    while True:
        r = _reg_token(c, c.api("POST", "/auth/token", json={"email": email, "password": pw}), tag)
        if r.status != 429 or not _backoff(c, what, delay, r):
            return r
        delay = min(delay * 2, 20.0)


X7_STOP_S = 300.0   # stop sampling this long before the runner's X7 timeout


def _login_gate(c, what, max_wait=900.0):
    """r2 (X7/X8/X10 on build-2): wait until a BRAND-NEW scratch account's correct login
    returns 200, so a source limiter left by an earlier row cannot poison this row.
    Polls every 15 s up to max_wait (15 min). Returns True when clean. Logs every try."""
    t0 = time.monotonic()
    n = 0
    while True:
        n += 1
        try:
            u = c.scratch_user("acme", wait429=False)  # raises on a 429 setup login
            r = c.api("POST", "/auth/token", json={"email": u.email, "password": u.password})
            _reg_token(c, r, "gate")
            st = r.status
        except lib.HarnessError as e:
            st = f"setup: {e}"
        c.log("login gate %s try %d after %.0fs: fresh-account correct login -> %s",
              what, n, time.monotonic() - t0, st)
        if st in (200, 201):
            return True
        # only a limiter (429) is worth waiting out; any other answer will not clear
        if not (st == 429 or "-> 429" in str(st)):
            return False
        if time.monotonic() - t0 >= max_wait:
            return False
        time.sleep(15)


# --------------------------------------------------------------------------
# raw socket request (lib.http may lose a 413 sent before the body is read)
# --------------------------------------------------------------------------

def _raw(c, method, path, *, body=b"", headers=None, actor=None, timeout=15.0):
    u = urllib.parse.urlsplit(c.base_url)
    host, port = u.hostname or "127.0.0.1", u.port or 80
    hdrs = {"Host": f"{host}:{port}", "Connection": "close", "Content-Length": str(len(body))}
    if actor is not None:
        a = c.actor(actor)
        if a.secret:
            hdrs["Authorization"] = f"Bearer {a.secret}"
    hdrs.update(headers or {})
    head = (f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
            + "\r\n").encode()
    t0 = time.monotonic()
    status, rh, rb, err = 0, {}, b"", None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return lib.Resp(0, {}, b"", (time.monotonic() - t0) * 1000, path, f"connect: {e}")
    data = b""
    try:
        try:
            s.sendall(head)
            mv = memoryview(body)
            for i in range(0, len(body), 65536):
                s.sendall(mv[i:i + 65536])
        except OSError as e:
            err = f"send: {e}"
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        while True:
            try:
                chunk = s.recv(65536)
            except OSError as e:
                err = (err or "") + f" recv: {e}"
                break
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    ms = (time.monotonic() - t0) * 1000
    if b"\r\n\r\n" in data:
        h, rb = data.split(b"\r\n\r\n", 1)
        lines = h.decode("latin-1").split("\r\n")
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            status = 0
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                k = k.strip().lower()
                rh[k] = f"{rh[k]}, {v.strip()}" if k in rh else v.strip()
    resp = lib.Resp(status, rh, rb, ms, path, err if status == 0 else None)
    c.log("RAW %s %s -> %s %.0fms err=%s body=%s", method, path, status, ms, err, c._body_for_log(rb))
    if status >= 500:
        c.saw_5xx.append(f"{method} {path} -> {status}")
    return resp


# ==========================================================================
# X5: password hashing + 12-char minimum
# ==========================================================================

_HASH_OK = [
    ("argon2id", re.compile(r"^\$argon2id\$")),
    ("bcrypt", re.compile(r"^\$2[aby]\$(\d{2})\$")),
    ("scrypt", re.compile(r"^(\$scrypt\$|\$7\$|scrypt[:$])")),
]


def _classify_hash(h: str):
    for name, rx in _HASH_OK:
        m = rx.match(h)
        if m:
            if name == "bcrypt":
                cost = int(m.group(1))
                return (cost >= 12), f"bcrypt {h[:4]} cost={cost}"
            return True, name
    return False, f"unrecognized (prefix {h[:10]!r}, len {len(h)})"


def _find_pw_hashes(c, emails, uid2email=None):
    """{email: [(table, key, hash)]} by scanning every table holding the email or the user id."""
    uid2email = uid2email or {}
    found = {e: [] for e in emails}
    r = c.psql("SELECT DISTINCT table_schema, table_name FROM information_schema.columns "
               "WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1,2;")
    if r.rc != 0:
        return None
    lits = ",".join("'" + e.replace("'", "''").lower() + "'" for e in list(emails) + list(uid2email))
    for sch, tbl in [(row[0], row[1]) for row in r.rows if len(row) >= 2]:
        q = (f'SELECT row_to_json(t)::text FROM "{sch}"."{tbl}" t '
             f"WHERE EXISTS (SELECT 1 FROM json_each_text(row_to_json(t)) j WHERE lower(j.value) IN ({lits}));")
        rr = c.psql(q)
        if rr.rc != 0:
            continue
        for row in rr.rows:
            try:
                d = _json.loads(row[0])
            except (ValueError, TypeError, IndexError):
                continue
            em = next((str(v).lower() for v in d.values() if isinstance(v, str) and str(v).lower() in found), None)
            if not em:
                em = next((uid2email[str(v).lower()] for v in d.values()
                           if isinstance(v, (str, int)) and str(v).lower() in uid2email), None)
            if not em:
                continue
            for k, v in d.items():
                if not isinstance(v, str) or not v:
                    continue
                kl = k.lower()
                if ("pass" in kl or "pwd" in kl) or re.match(r"^(\$argon2|\$2[aby]\$|\$scrypt\$|\$7\$|scrypt[:$]|"
                                                            r"pbkdf2|\$pbkdf2|\$1\$|\$5\$|\$6\$|sha256\$|md5\$)", v):
                    if "token" in kl:
                        continue
                    if (f"{sch}.{tbl}", k, v) not in found[em]:
                        found[em].append((f"{sch}.{tbl}", k, v))
    return found


@check("X5")
def x5(c) -> Result:
    """Password hashes argon2id / bcrypt>=12 / scrypt; 11-char password rejected"""
    users = (c.fx or {}).get("users") or {}
    emails = sorted({(u or {}).get("email", "").lower() for u in users.values() if (u or {}).get("email")})
    if not emails:
        return c.error("fixture has no user emails")
    # register password hashes for redaction? they are not secrets; we only log prefixes.
    uid2email = {str(u["user_id"]).lower(): u["email"].lower() for u in users.values()
                 if (u or {}).get("user_id") and (u or {}).get("email")}
    found = _find_pw_hashes(c, emails, uid2email)
    if found is None:
        return c.error("psql schema listing failed")
    for em in emails:
        hs = found.get(em) or []
        if not hs:
            c.expect(False, f"no password hash found in the dump for {em}")
            continue
        for tbl, key, h in hs:
            okh, desc = _classify_hash(h)
            c.expect(okh, f"{em}: {tbl}.{key} = {desc}")
    # 11-char rejection, 12-char acceptance
    owner = "owner@acme"
    p11, p12 = _pw(11), _pw(12)
    c.secret(f"pw:x5-11-{c._next()}", p11, "password")
    c.secret(f"pw:x5-12-{c._next()}", p12, "password")
    assert len(p11) == 11 and len(p12) == 12
    # POST /members
    e11 = f"{c._uniq()}@acme.test"
    r = c.api("POST", "/members", actor=owner, json={"email": e11, "role": "member", "password": p11})
    c.expect(r.status in (400, 422), f"POST /members 11-char password -> {r.status} (want 400/422)")
    lr = _reg_token(c, c.api("POST", "/auth/token", json={"email": e11, "password": p11}), "x5")
    c.expect(not lr.ok(), f"login as rejected 11-char member -> {lr.status} (want not 2xx)")
    e12 = f"{c._uniq()}@acme.test"
    c.control(lambda: c.api("POST", "/members", actor=owner, json={"email": e12, "role": "member", "password": p12}),
              what="POST /members with 12-char password")
    # POST /auth/password on a scratch user
    try:
        su = c.scratch_user("acme")
    except lib.HarnessError as e:
        return c.error(f"scratch user: {e}")
    r = c.api("POST", "/auth/password", actor=su, json={"current_password": su.password, "new_password": p11})
    c.expect(r.status in (400, 422), f"POST /auth/password new 11-char -> {r.status} (want 400/422)")
    lr = c.api("POST", "/auth/token", json={"email": su.email, "password": su.password})
    c.expect(lr.ok(), f"old password still logs in after rejected change -> {lr.status}")
    if lr.ok():
        tok = _jget(lr, "token")
        if tok:
            su.secret = c.secret(f"pat:{su.label}:x5", tok, "token")
    newp = c.secret(f"pw:x5-chg-{c._next()}", _pw(12), "password")
    if c.control(lambda: c.api("POST", "/auth/password", actor=su,
                               json={"current_password": su.password, "new_password": newp}),
                 what="POST /auth/password with 12-char new password"):
        su.password = newp
    # POST /admin/orgs (root)
    s11 = c._uniq()
    r = c.api("POST", "/admin/orgs", actor="root",
              json={"slug": s11, "owner_email": f"owner@{s11}.test", "owner_password": p11})
    c.expect(r.status in (400, 422), f"POST /admin/orgs owner 11-char password -> {r.status} (want 400/422)")
    s12 = c._uniq()
    c.control(lambda: c.api("POST", "/admin/orgs", actor="root",
                            json={"slug": s12, "owner_email": f"owner@{s12}.test", "owner_password": p12}),
              what="POST /admin/orgs with 12-char owner password")
    # CLI member add
    e11c = f"{c._uniq()}@acme.test"
    cr = c.cli("member", "add", e11c, "--role", "member", actor=owner, stdin=(p11 + "\n").encode())
    c.expect(cr.rc == 6, f"coffer member add with 11-char password -> rc={cr.rc} (want 6)")
    e12c = f"{c._uniq()}@acme.test"
    c.control(lambda: c.cli("member", "add", e12c, "--role", "member", actor=owner, stdin=(p12 + "\n").encode()),
              what="coffer member add with 12-char password")
    return c.done("hashes ok for all fixture users; 11-char rejected on 4 paths, 12-char accepted")


# ==========================================================================
# X7: login response uniformity
# ==========================================================================

def _mask_rid(r) -> bytes:
    rid = (r.headers or {}).get("x-request-id")
    b = r.body or b""
    if rid:
        b = b.replace(rid.encode(), b"\xc2\xabRID\xc2\xbb")
    return b


@check("X7")
def x7(c) -> Result:
    """Unknown email vs wrong password: same status, same body, median latency within 25%"""
    if not _login_gate(c, "X7 start"):
        return c.error("login gate: a fresh account's correct login did not return 200 "
                       "(non-429 answer, or 429 for 15 min): measurement invalid")
    users = []
    try:
        for i in range(8):
            users.append(_retry429(c, lambda: c.scratch_user("acme"), f"X7 scratch user {i}"))
    except lib.HarnessError as e:
        return c.error(f"scratch users: {e}")
    # control: a correct login works (0 failures so far on this account)
    c.control(lambda: _login429(c, users[0].email, users[0].password, "x7", "X7 control login"),
              what="correct login for scratch user 0")
    # warm-up (unknown emails only; not recorded)
    for _ in range(3):
        _login429(c, f"warm-{_rand(10).lower()}@acme.test", _pw(16), "x7", "X7 warm-up")
    # Sample: 30 interleaved pairs, paced 0.25 s. A 429 is a rate limiter answering, not
    # a login response: the same attempt is retried after a backoff and the 429 is not
    # sampled (logged + counted). <= 4 wrong tries per account (8 accounts), so the SPEC
    # per-account lockout (5) is never reached by design.
    # r2 (X7 on build-2): the build may have a SOURCE limiter (SPEC does not forbid it).
    # Sample in batches; on a 429 the pair is dropped, the threshold (failed tries since
    # the last clean gate) is logged, the batch size shrinks below it, and the login gate
    # (fresh-account correct login 200, up to 15 min) runs before the next batch.
    # 429s are never sampled.
    # r4 (X7 on build-2): the run is time-budgeted (registry timeout = limiter windows x
    # 15 min + margin); sampling stops X7_STOP_S before the runner timeout, every clean pair
    # is appended to X7-pairs.jsonl as it is taken, and the verdict uses the pairs collected.
    # After the first 429 the batch is sized below the observed threshold, so most windows
    # cost one gate wait. X7 runs LAST (registry), so its failed logins poison no later row.
    t_start = time.monotonic()
    budget = float(getattr(getattr(c, "row", None), "timeout", 1500) or 1500) - X7_STOP_S
    pairs_f = c.out / "X7-pairs.jsonl"
    n429 = 0
    unk, wrong = [], []
    batch = 10
    since_gate = 0
    thresholds = []
    wrong_n = [0] * 8
    i = 0
    stopped = ""
    while len(unk) < 30:
        if i >= 240:
            stopped = "attempt cap"
            break
        if time.monotonic() - t_start > budget:
            stopped = f"time budget {budget:.0f}s"
            break
        ue = f"nouser-{_rand(12).lower()}@acme.test"
        ru = _reg_token(c, c.api("POST", "/auth/token", json={"email": ue, "password": _pw(16)}), "x7")
        k = i % 8
        if wrong_n[k] >= 4:  # keep every account below the SPEC per-account lockout (5)
            try:
                users[k] = _retry429(c, lambda: c.scratch_user("acme"), f"X7 replacement user {k}")
                wrong_n[k] = 0
            except lib.HarnessError as e:
                return c.error(f"scratch replacement user: {e}")
        u = users[k]
        rw = _reg_token(c, c.api("POST", "/auth/token", json={"email": u.email, "password": _pw(16)}), "x7")
        wrong_n[k] += 1
        i += 1
        if ru.status == 429 or rw.status == 429:
            n429 += 1
            thresholds.append(since_gate + (1 if ru.status == 429 else 2))
            c.log("X7 limiter 429 after %d failed tries since last gate (pair %d dropped)", thresholds[-1], i)
            batch = max(2, min(batch, (thresholds[-1] - 2) // 2))
            if not _login_gate(c, f"X7 after 429 #{n429}",
                               max_wait=max(0.0, min(1200.0, budget - (time.monotonic() - t_start)))):
                stopped = "login gate did not clear"
                break
            since_gate = 0
            continue
        unk.append(ru)
        wrong.append(rw)
        try:
            with open(pairs_f, "a", encoding="utf-8") as pf:
                pf.write(_json.dumps({"pair": len(unk), "batch_after_429": n429,
                                      "unknown": {"status": ru.status, "ms": round(ru.ms, 1),
                                                  "body_sha": hashlib.sha256(_mask_rid(ru)).hexdigest()[:16]},
                                      "wrong": {"status": rw.status, "ms": round(rw.ms, 1),
                                                "body_sha": hashlib.sha256(_mask_rid(rw)).hexdigest()[:16]}}) + "\n")
        except OSError as e:
            c.log("X7 persist pair failed: %s", e)
        since_gate += 2
        time.sleep(0.25)
        if since_gate >= 2 * batch and n429:
            if not _login_gate(c, "X7 between batches",
                               max_wait=max(0.0, min(1200.0, budget - (time.monotonic() - t_start)))):
                stopped = "login gate did not clear"
                break
            since_gate = 0
    c.log("X7 sample: %d pairs, %d limiter 429s (dropped), thresholds %s, batch %d, stopped=%s, %.0fs",
          len(unk), n429, thresholds, batch, stopped or "-", time.monotonic() - t_start)
    if len(unk) < 30:
        return c.error(f"only {len(unk)}/30 clean pairs ({stopped or 'stopped'}; limiter thresholds {thresholds}; "
                       f"pairs kept in X7-pairs.jsonl): measurement invalid")
    c.log("X7 sample: %d rate-limit 429s retried (not sampled)", n429)
    allr = unk + wrong
    statuses = sorted({r.status for r in allr})
    c.log("X7 statuses=%s", statuses)
    if 429 in statuses:
        return c.error(f"429 persisted after backoff during X7 sample (statuses {statuses}, "
                       f"{n429} 429s retried): measurement invalid")
    c.expect(len(statuses) == 1, f"login statuses differ: unknown={sorted({r.status for r in unk})} "
                                 f"wrong={sorted({r.status for r in wrong})}")
    c.expect(all(400 <= r.status < 500 for r in allr), f"failed-login statuses not all 4xx: {statuses}")
    bodies = {_mask_rid(r) for r in allr}
    if len(bodies) != 1:
        sample = sorted(bodies, key=len)[:2]
        c.expect(False, f"login bodies differ ({len(bodies)} distinct): {sample[0][:80]!r} vs {sample[-1][:80]!r}")
    else:
        c.expect(True, f"all 60 failed-login bodies identical ({len(next(iter(bodies)))} bytes)")
    mu = statistics.median(r.ms for r in unk)
    mw = statistics.median(r.ms for r in wrong)
    lo, hi = min(mu, mw), max(mu, mw)
    ratio = hi / lo if lo > 0 else float("inf")
    c.log("X7 median unknown=%.1fms wrong=%.1fms ratio=%.3f", mu, mw, ratio)
    c.expect(ratio <= 1.25, f"median latency unknown={mu:.1f}ms wrong={mw:.1f}ms ratio={ratio:.2f} (want <= 1.25)")
    return c.done(f"60 tries: status {statuses}, 1 body, medians {mu:.0f}/{mw:.0f} ms (ratio {ratio:.2f})"
                  f"{f'; {n429} rate-limit 429s retried, not sampled' if n429 else ''}",
                  data={"median_unknown_ms": round(mu, 1), "median_wrong_ms": round(mw, 1),
                        "ratio": round(ratio, 3), "statuses": statuses, "retried_429": n429})


# ==========================================================================
# X8: lockout
# ==========================================================================

@check("X8")
def x8(c) -> Result:
    """5 failures -> 429 even with correct password; another account unaffected"""
    if not _login_gate(c, "X8 start"):
        return c.error("login gate: a fresh account's correct login did not return 200 (non-429, or 429 for 15 min)")
    try:
        a = _retry429(c, lambda: c.scratch_user("acme"), "X8 scratch A")
        b = _retry429(c, lambda: c.scratch_user("acme"), "X8 scratch B")
    except lib.HarnessError as e:
        return c.error(f"scratch users: {e}")

    def login(u, pw):
        return lambda: _reg_token(c, c.api("POST", "/auth/token", json={"email": u.email, "password": pw}), "x8")

    # Controls (with backoff, so a limiter left over from an earlier check cannot poison
    # the test): both correct logins succeed right before A's failures. That proves the
    # verdict probes below start from a clean state. The verdict probes do NOT back off.
    if not c.control(lambda: _login429(c, a.email, a.password, "x8", "X8 A control"),
                     what="A correct login before failures"):
        return c.done()
    if not c.control(lambda: _login429(c, b.email, b.password, "x8", "X8 B control"),
                     what="B correct login before failures"):
        return c.done()
    sts = []
    for i in range(5):
        r = login(a, _pw(16))()
        sts.append(r.status)
    c.log("X8 A wrong statuses %s", sts)
    c.expect(429 not in sts, f"A wrong tries 1-5 -> {sts} (429 before 5 failures)")
    c.expect(all(s == 401 for s in sts), f"A wrong tries 1-5 -> {sts} (want 401)")
    r6 = login(a, a.password)()
    c.expect(r6.status == 429, f"A correct password after 5 failures -> {r6.status} (want 429)")
    r7 = login(a, _pw(16))()
    c.expect(r7.status == 429, f"A 7th (wrong) try -> {r7.status} (want 429)")
    rb = login(b, b.password)()
    c.log("X8 cross-account: 5 failures on A -> B correct login %s (%s)", rb.status,
          "B affected" if rb.status == 429 else "B unaffected")
    c.expect(rb.status in (200, 201), f"B correct login while A locked -> {rb.status} (want 200)")
    return c.done(f"A: {sts} then {r6.status}/{r7.status}; B {rb.status}")


# ==========================================================================
# X9: headers + CORS
# ==========================================================================

def _hdr_check(c, r, what, *, allow_text=False):
    h = r.headers or {}
    if r.status == 0:
        c.expect(False, f"{what}: transport error {r.error}")
        return
    ct = h.get("content-type", "").lower()
    ct_ok = ct.startswith("application/json") or (allow_text and ct.startswith("text/plain"))
    if r.status in (204, 304) and not r.body and not ct:
        ct_ok = True
    c.expect(ct_ok, f"{what} -> {r.status}: Content-Type {ct!r}")
    c.expect(h.get("x-content-type-options", "").strip().lower() == "nosniff",
             f"{what} -> {r.status}: X-Content-Type-Options {h.get('x-content-type-options')!r}")
    c.expect("no-store" in h.get("cache-control", "").lower(),
             f"{what} -> {r.status}: Cache-Control {h.get('cache-control')!r}")


def _no_cors(c, r, what):
    h = r.headers or {}
    acao = h.get("access-control-allow-origin")
    c.expect(acao is None, f"{what} -> {r.status}: Access-Control-Allow-Origin {acao!r}")
    acac = h.get("access-control-allow-credentials")
    c.expect(acac is None or acao is None, f"{what}: Access-Control-Allow-Credentials {acac!r}")


@check("X9")
def x9(c) -> Result:
    """JSON content type, nosniff, no-store on every /api/v1 response; no CORS"""
    own = "owner@acme"
    sp = _secret_path("api", "dev", "CANARY")
    seen = {}

    def run(what, r, allow_text=False):
        seen.setdefault(r.status, []).append(what)
        _hdr_check(c, r, what, allow_text=allow_text)
        return r

    c.control(lambda: run("GET /me owner", c.api("GET", "/me", actor=own)), what="GET /me owner")
    for path in ("/projects", "/projects/api/envs", "/projects/api/envs/dev/secrets", sp,
                 sp + "/versions", "/members", "/tokens", "/changes", "/audit", "/audit/verify"):
        run(f"GET {path} owner", c.api("GET", path, actor=own))
    run("export json", c.api("GET", "/projects/api/envs/dev/export", actor=own, query={"format": "json"}))
    run("export dotenv", c.api("GET", "/projects/api/envs/dev/export", actor=own, query={"format": "dotenv"}),
        allow_text=True)
    run("GET /admin/orgs root", c.api("GET", "/admin/orgs", actor="root"))
    run("GET /admin/audit root", c.api("GET", "/admin/audit", actor="root", query={"limit": 5}))
    jk = c.junk_key()
    run("PUT junk", c.api("PUT", _secret_path("api", "dev", jk), actor=own, json={"value": _rand(20)}))
    run("PUT junk stale expected_version", c.api("PUT", _secret_path("api", "dev", jk), actor=own,
                                                 json={"value": _rand(20), "expected_version": 99}))
    try:
        sproj = c.scratch_project(own, envs=(("prot", True),))
    except lib.HarnessError as e:
        return c.error(f"scratch project: {e}")
    run("PUT protected junk (202)", c.api("PUT", _secret_path(sproj, "prot", c.junk_key()), actor=own,
                                          json={"value": _rand(20)}))
    run("POST /projects (201)", c.api("POST", "/projects", actor=own, json={"slug": c._uniq()}))
    run("viewer GET value", c.api("GET", sp, actor="viewer@acme"))
    run("absent project", c.api("GET", f"/projects/{c.absent_slug()}/envs", actor=own))
    run("anon GET /projects", c.api("GET", "/projects"))
    run("bad bearer", c.api("GET", "/projects", headers={"Authorization": "Bearer cof_pat_" + "x" * 40}))
    run("bad login", c.api("POST", "/auth/token", json={"email": f"nouser-{_rand(8).lower()}@acme.test",
                                                       "password": _pw(16)}))
    run("malformed JSON", c.api("PUT", _secret_path("api", "dev", c.junk_key()), actor=own,
                                body=b'{"value": "x"', headers={"Content-Type": "application/json"}))
    run("malformed JSON login", c.api("POST", "/auth/token", body=b"{not json",
                                      headers={"Content-Type": "application/json"}))
    big = b'{"value":"' + b"A" * (2 * MIB) + b'"}'
    run("2 MiB PUT (413)", _raw(c, "PUT", "/api/v1" + _secret_path("api", "dev", c.junk_key()), body=big,
                                actor=own, headers={"Content-Type": "application/json"}))
    run("wrong method", c.api("PATCH", "/projects", actor=own, json={}))
    run("unknown /api/v1 route", c.api("GET", "/nope-" + _rand(6).lower(), actor=own))
    pf = c.api("OPTIONS", "/projects", headers={"Origin": EVIL, "Access-Control-Request-Method": "GET",
                                                "Access-Control-Request-Headers": "authorization"})
    run("OPTIONS preflight /projects", pf)
    _no_cors(c, pf, "preflight /projects")
    pf2 = c.api("OPTIONS", sp, headers={"Origin": EVIL, "Access-Control-Request-Method": "PUT",
                                        "Access-Control-Request-Headers": "authorization,content-type"})
    run("OPTIONS preflight secret", pf2)
    _no_cors(c, pf2, "preflight secret")
    sg = c.api("GET", sp, actor=own, headers={"Origin": EVIL})
    run("GET secret with Origin", sg)
    _no_cors(c, sg, "GET secret with Origin")
    sl = c.api("POST", "/auth/token", headers={"Origin": EVIL},
               json={"email": "nouser@acme.test", "password": _pw(16)})
    run("POST /auth/token with Origin", sl)
    _no_cors(c, sl, "POST /auth/token with Origin")
    for want in (202, 400, 401, 403, 404, 409, 413):
        c.expect(want in seen, f"status {want} never elicited (seen {sorted(seen)})")
    c.log("X9 statuses seen: %s", {k: len(v) for k, v in sorted(seen.items())})
    return c.done(f"{sum(len(v) for v in seen.values())} responses, statuses {sorted(seen)}: headers ok, no CORS")


# ==========================================================================
# X10: injection
# ==========================================================================

_CYR = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х",
        "y": "у", "i": "і", "A": "А", "E": "Е", "O": "О", "P": "Р",
        "C": "С", "T": "Т", "H": "Н", "K": "К", "M": "М", "B": "В",
        "X": "Х"}


def _homo(s: str) -> str:
    for i, ch in enumerate(s):
        if ch in _CYR:
            return s[:i] + _CYR[ch] + s[i + 1:]
    return s + "а"


def _fullw(s: str) -> str:
    for i, ch in enumerate(s):
        if "!" <= ch <= "~" and ch.isalnum():
            return s[:i] + chr(ord(ch) + 0xFEE0) + s[i + 1:]
    return s + "ａ"


def _payloads(base: str):
    return [("sqli", "' OR 1=1--"), ("drop", '"; DROP TABLE'), ("trav", "../../etc/passwd"),
            ("nul", "%00"), ("homoglyph", _homo(base)), ("fullwidth", _fullw(base))]


def _raw_seg(p: str) -> str:
    out = []
    for ch in p:
        if ch == " ":
            out.append("%20")
        elif ch in '"#?':
            out.append("%{:02X}".format(ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


def _q_seg(p: str) -> str:
    return urllib.parse.quote(p, safe="")


class _X10:
    def __init__(self, c):
        self.c = c
        self.n = 0
        self.markers = []

    def leak(self, r, actor_org):
        body = r.body or b""
        for lab, v in self.markers:
            if lab.startswith("org:") and (actor_org is None or lab == f"org:{actor_org}"):
                continue
            if v and v.encode() in body:
                if lab.startswith("canary:") and "/" in lab and actor_org is not None:
                    corg = lab[len("canary:"):].split("/", 1)[0]
                    if corg == actor_org:
                        return f"unrequested own-tenant data {lab}"
                return f"foreign data {lab}"
        return None

    def judge(self, r, what, *, mode="strict", verify=None, actor_org="acme"):
        c = self.c
        self.n += 1
        lk = self.leak(r, actor_org)
        if lk:
            c.expect(False, f"{what}: {r.status} and response contains {lk}")
            return
        if r.status == 0:
            c.expect(False, f"{what}: transport error {r.error}")
            return
        if r.status >= 500:
            c.expect(False, f"{what}: {r.status}")
            return
        if 400 <= r.status < 500:
            return
        if 200 <= r.status < 300 and mode == "empty":
            items = None
            try:
                items = _items(r.json())
            except ValueError:
                pass
            if items == []:
                return
            c.expect(False, f"{what}: {r.status} with non-empty/unknown result (want 4xx or [])")
            return
        if 200 <= r.status < 300 and mode == "free" and verify is not None:
            okv, why = verify(r)
            if okv:
                return
            c.expect(False, f"{what}: {r.status} accepted but {why}")
            return
        c.expect(False, f"{what}: {r.status} (want 4xx)")


@check("X10")
def x10(c) -> Result:
    """Injection payloads in every param and field -> 4xx, no 500, no foreign data"""
    X = _X10(c)
    for org, p, e, k, v in _canary_paths(c):
        X.markers.append((f"canary:{org}/{p}/{e}/{k}", v))
    if (c.fx or {}).get("multi_core"):
        X.markers.append(("canary:multi_core", c.fx["multi_core"]))
    for org, d in ((c.fx or {}).get("orgs") or {}).items():
        if (d or {}).get("id"):
            X.markers.append((f"org:{org}", str(d["id"])))
    if not any(lab.startswith("canary:") for lab, _ in X.markers):
        return c.error("fixture has no canaries")
    own, adm = "owner@acme", "admin@acme"
    if not _login_gate(c, "X10 start"):
        return c.error("login gate: a fresh account's correct login did not return 200 (non-429, or 429 for 15 min)")
    # ---- scratch setup ----
    try:
        proj = c.scratch_project(own, envs=(("dev", False), ("prot", True)))
        jkey = "X10_SEED"
        for _ in range(2):
            r = c.api("PUT", _secret_path(proj, "dev", jkey), actor=own, json={"value": _rand(24)})
            if not r.ok():
                return c.error(f"seed PUT -> {r.status}")
        oslug, oowner = _retry429(c, lambda: c.scratch_org(), "X10 scratch org")
    except lib.HarnessError as e:
        return c.error(f"scratch setup: {e}")

    def mk_member():
        return _retry429(c, lambda: c.scratch_user("acme"), "X10 scratch member")

    def org_disable_ctl():
        r = c.api("POST", f"/admin/orgs/{oslug}/disable", actor="root")
        if r.ok():
            return r
        lr = c.api("GET", "/admin/orgs", actor="root")
        try:
            for o in _items(lr.json()) or []:
                if isinstance(o, dict) and o.get("slug") == oslug and o.get("id"):
                    c.log("X10 org disable by slug -> %s; retrying by id", r.status)
                    return c.api("POST", f"/admin/orgs/{o['id']}/disable", actor="root")
        except ValueError:
            pass
        return r

    def change_id():
        r = c.api("PUT", _secret_path(proj, "prot", c.junk_key()), actor=own, json={"value": _rand(20)})
        return _jget(r, "change_id") or _jget(r, "id")

    # ---- 1. path params ----
    try:
        m_role = mk_member()
        m_del = mk_member()
        m_grant = mk_member()
    except lib.HarnessError as e:
        return c.error(f"scratch members: {e}")
    tok = c.scratch_token(proj, "dev", "read")
    cid_a, cid_r = change_id(), change_id()
    if not cid_a or not cid_r:
        return c.error("could not create pending change requests in scratch protected env")

    S = {"p": "api", "e": "dev", "k": "CANARY", "n": "1"}
    # (label, method, template, slots, actor, json body for probe, control closure)
    routes = [
        ("envs", "GET", "/projects/{p}/envs", ("p",), own, None, None),
        ("list", "GET", "/projects/{p}/envs/{e}/secrets", ("p", "e"), own, None, None),
        ("get", "GET", "/projects/{p}/envs/{e}/secrets/{k}", ("p", "e", "k"), own, None, None),
        ("versions", "GET", "/projects/{p}/envs/{e}/secrets/{k}/versions", ("p", "e", "k"), own, None, None),
        ("version", "GET", "/projects/{p}/envs/{e}/secrets/{k}/versions/{n}", ("p", "e", "k", "n"), own, None, None),
        ("export", "GET", "/projects/{p}/envs/{e}/export", ("p", "e"), own, None, None),
    ]
    W = {"p": proj, "e": "dev", "k": jkey, "n": "1"}
    wroutes = [
        ("put", "PUT", "/projects/{p}/envs/{e}/secrets/{k}", ("p", "e", "k"), own, {"value": "x10"}),
        ("delete", "DELETE", "/projects/{p}/envs/{e}/secrets/{k}", ("p", "e", "k"), own, None),
        ("rollback", "POST", "/projects/{p}/envs/{e}/secrets/{k}/rollback", ("p", "e", "k"), own, {"to": 1}),
        ("env-create", "POST", "/projects/{p}/envs", ("p",), own, None),
    ]
    # read routes: control = same route with valid slots (fixture api/dev, CANARY)
    for lab, meth, tpl, slots, actor, body, _ in routes:
        q = {"format": "json"} if lab == "export" else None
        if not c.control(lambda: c.api(meth, tpl.format(**S), actor=actor, query=q), what=f"X10 {lab} control"):
            continue
        for slot in slots:
            for pl_name, pl in _payloads(S[slot]):
                for enc, seg in (("q", _q_seg(pl)), ("raw", _raw_seg(pl))):
                    vals = dict(S)
                    vals[slot] = seg
                    path = "/api/v1" + tpl.format(**vals)
                    if q:
                        path += "?format=json"
                    r = c.http(meth, path, actor=actor, raw_path=True)
                    X.judge(r, f"{meth} {lab} {{{slot}}}={pl_name}/{enc}")
    # write routes on the scratch project
    for lab, meth, tpl, slots, actor, body in wroutes:
        def ctl(lab=lab, meth=meth, tpl=tpl, actor=actor, body=body):
            if lab == "delete":
                kk = c.junk_key()
                c.api("PUT", _secret_path(proj, "dev", kk), actor=own, json={"value": "d"})
                return c.api("DELETE", _secret_path(proj, "dev", kk), actor=actor)
            if lab == "env-create":
                return c.api("POST", f"/projects/{proj}/envs", actor=actor, json={"slug": c._uniq(), "protected": False})
            if lab == "put":
                return c.api("PUT", _secret_path(proj, "dev", c.junk_key()), actor=actor, json={"value": "x10"})
            return c.api(meth, tpl.format(**W), actor=actor, json=body)
        if not c.control(ctl, what=f"X10 {lab} control"):
            continue
        for slot in slots:
            for pl_name, pl in _payloads(W[slot]):
                for enc, seg in (("q", _q_seg(pl)), ("raw", _raw_seg(pl))):
                    vals = dict(W)
                    vals[slot] = seg
                    path = "/api/v1" + tpl.format(**vals)
                    b = body if lab != "env-create" else {"slug": c._uniq(), "protected": False}
                    r = c.http(meth, path, actor=actor, raw_path=True,
                               **({"json": b} if b is not None else {}))
                    X.judge(r, f"{meth} {lab} {{{slot}}}={pl_name}/{enc}")
    # id routes
    idroutes = [
        ("member-patch", "PATCH", "/members/{id}", own, {"role": "member"},
         lambda: c.api("PATCH", f"/members/{m_role.user_id}", actor=own, json={"role": "member"}), m_role.user_id),
        ("member-delete", "DELETE", "/members/{id}", own, None,
         lambda: c.api("DELETE", f"/members/{mk_member().user_id}", actor=own), m_del.user_id),
        ("grant-put", "PUT", "/members/{id}/grants/" + proj, own, {"level": "viewer"},
         lambda: c.api("PUT", f"/members/{m_grant.user_id}/grants/{proj}", actor=own, json={"level": "viewer"}),
         m_grant.user_id),
        ("grant-delete", "DELETE", "/members/{id}/grants/" + proj, own, None,
         lambda: (c.api("PUT", f"/members/{m_grant.user_id}/grants/{proj}", actor=own, json={"level": "viewer"}),
                  c.api("DELETE", f"/members/{m_grant.user_id}/grants/{proj}", actor=own))[1], m_grant.user_id),
        ("token-delete", "DELETE", "/tokens/{id}", own, None,
         lambda: c.api("DELETE", f"/tokens/{c.scratch_token(proj, 'dev', 'read').token_id}", actor=own),
         tok.token_id or "x"),
        ("change-approve", "POST", "/changes/{id}/approve", adm, None,
         lambda: c.api("POST", f"/changes/{cid_a}/approve", actor=adm), cid_a),
        ("change-reject", "POST", "/changes/{id}/reject", adm, None,
         lambda: c.api("POST", f"/changes/{cid_r}/reject", actor=adm), cid_r),
        ("org-disable", "POST", "/admin/orgs/{id}/disable", "root", None, org_disable_ctl, oslug),
    ]
    grant_tpl_slot = [("grant-put-project", "PUT", "/members/" + str(m_grant.user_id) + "/grants/{id}", own,
                       {"level": "viewer"}, None, proj),
                      ("grant-delete-project", "DELETE", "/members/" + str(m_grant.user_id) + "/grants/{id}", own,
                       None, None, proj)]
    for lab, meth, tpl, actor, body, ctl, base in idroutes + grant_tpl_slot:
        if ctl is not None and not c.control(ctl, what=f"X10 {lab} control"):
            continue
        aorg = None if actor == "root" else "acme"
        for pl_name, pl in _payloads(str(base)):
            for enc, seg in (("q", _q_seg(pl)), ("raw", _raw_seg(pl))):
                path = "/api/v1" + tpl.format(id=seg)
                r = c.http(meth, path, actor=actor, raw_path=True, **({"json": body} if body is not None else {}))
                X.judge(r, f"{meth} {lab} {{id}}={pl_name}/{enc}", actor_org=aorg)

    # ---- 2. query params ----
    own_a = c.actor(own)
    qspecs = [
        ("changes?status", "/changes", own, "status", "pending", "strict"),
        ("export?format", "/projects/api/envs/dev/export", own, "format", "json", "strict"),
        ("audit?since", "/audit", own, "since", "2020-01-01T00:00:00Z", "strict"),
        ("audit?limit", "/audit", own, "limit", "5", "strict"),
        ("audit?actor", "/audit", own, "actor", str(own_a.user_id or "x"), "empty"),
        ("audit?action", "/audit", own, "action", "login", "empty"),
        ("admin/audit?limit", "/admin/audit", "root", "limit", "5", "strict"),
    ]
    for lab, path, actor, name, good, mode in qspecs:
        if not c.control(lambda: c.api("GET", path, actor=actor, query={name: good}), what=f"X10 {lab} control"):
            continue
        aorg = None if actor == "root" else "acme"
        for pl_name, pl in _payloads(good):
            for enc, seg in (("q", _q_seg(pl)), ("raw", _raw_seg(pl).replace("&", "%26"))):
                r = c.http("GET", f"/api/v1{path}?{name}={seg}", actor=actor, raw_path=True)
                X.judge(r, f"GET {lab}={pl_name}/{enc}", mode=mode, actor_org=aorg)

    # ---- 3. JSON fields ----
    try:
        lu = mk_member()      # login probes (lockout-safe scratch account)
        pu = mk_member()      # password-change probes
    except lib.HarnessError as e:
        return c.error(f"scratch users (json): {e}")

    def login_ok(email, pw):
        # verification login (not a probe): back off on a limiter 429
        r = _login429(c, email, pw, "x10", "X10 verify login")
        return r.ok()

    def v_secret(key):
        def v(r, sent):
            g = c.api("GET", _secret_path(proj, "dev", key), actor=own)
            return (_jget(g, "value") == sent), f"read-back {g.status} differs from sent value"
        return v

    def v_pwlogin(email_of):
        def v(r, sent):
            return login_ok(email_of(), sent), "new password does not log in"
        return v

    def v_ok(r, sent):
        tokv = _jget(r, "token")
        if tokv:
            c.secret(f"token:x10-{c._next()}", str(tokv), "token")
        return True, ""

    # pu: new_password probes must keep a usable current password
    pstate = {"pw": pu.password}

    def pw_body(field, val):
        cur = pstate["pw"]
        return {"current_password": val if field == "current_password" else cur,
                "new_password": val if field == "new_password" else _pw(16)}

    def pw_send(body):
        r = c.api("POST", "/auth/password", actor=pu, json=body)
        if r.ok():
            pstate["pw"] = body["new_password"]
            lr = _login429(c, pu.email, pstate["pw"], "x10", "X10 pu re-login")
            t = _jget(lr, "token")
            if t:
                pu.secret = c.secret(f"pat:{pu.label}:x10-{c._next()}", t, "token")
        return r

    def free_pw(val):
        return "free" if len(val) >= 12 else "strict"

    vkey = "X10_VAL"
    jspecs = [
        # (label, field, base value, send(body)->Resp, body(field,val)->dict, mode(val), verify, actor_org)
        ("auth/token", "email", lu.email,
         lambda b: _reg_token(c, c.api("POST", "/auth/token", json=b), "x10"),
         lambda f, v: {"email": v if f == "email" else lu.email, "password": v if f == "password" else lu.password},
         lambda v: "strict", None, None),
        ("auth/token", "password", lu.password,
         lambda b: _reg_token(c, c.api("POST", "/auth/token", json=b), "x10"),
         lambda f, v: {"email": lu.email, "password": v},
         lambda v: "strict", None, None),
        ("auth/password", "new_password", pu.password, pw_send, pw_body, free_pw,
         v_pwlogin(lambda: pu.email), "acme"),
        ("auth/password", "current_password", pu.password, pw_send, pw_body, lambda v: "strict", None, "acme"),
        ("admin/orgs", "slug", "acme",
         lambda b: c.api("POST", "/admin/orgs", actor="root", json=b),
         lambda f, v: dict({"slug": c._uniq(), "owner_email": f"owner-{c._uniq()}@x10.test", "owner_password": _pw(16)},
                           **{f: v}),
         lambda v: "strict", None, None),
        ("admin/orgs", "owner_email", "owner@acme.test",
         lambda b: c.api("POST", "/admin/orgs", actor="root", json=b),
         lambda f, v: dict({"slug": c._uniq(), "owner_email": f"owner-{c._uniq()}@x10.test", "owner_password": _pw(16)},
                           **{f: v}),
         lambda v: "strict", None, None),
        ("admin/orgs", "owner_password", _pw(16),
         lambda b: c.api("POST", "/admin/orgs", actor="root", json=b),
         lambda f, v: dict({"slug": c._uniq(), "owner_email": f"owner-{c._uniq()}@x10.test", "owner_password": _pw(16)},
                           **{f: v}),
         free_pw, None, None),
        ("members", "email", "writer@acme.test",
         lambda b: c.api("POST", "/members", actor=own, json=b),
         lambda f, v: dict({"email": f"{c._uniq()}@acme.test", "role": "member", "password": _pw(16)}, **{f: v}),
         lambda v: "strict", None, "acme"),
        ("members", "role", "member",
         lambda b: c.api("POST", "/members", actor=own, json=b),
         lambda f, v: dict({"email": f"{c._uniq()}@acme.test", "role": "member", "password": _pw(16)}, **{f: v}),
         lambda v: "strict", None, "acme"),
        ("members", "password", _pw(16),
         lambda b: c.api("POST", "/members", actor=own, json=b),
         lambda f, v: dict({"email": f"{c._uniq()}@acme.test", "role": "member", "password": _pw(16)}, **{f: v}),
         free_pw, None, "acme"),
        ("members/{id} PATCH", "role", "member",
         lambda b: c.api("PATCH", f"/members/{m_role.user_id}", actor=own, json=b),
         lambda f, v: {"role": v}, lambda v: "strict", None, "acme"),
        ("grants PUT", "level", "viewer",
         lambda b: c.api("PUT", f"/members/{m_grant.user_id}/grants/{proj}", actor=own, json=b),
         lambda f, v: {"level": v}, lambda v: "strict", None, "acme"),
        ("projects", "slug", "api",
         lambda b: c.api("POST", "/projects", actor=own, json=b),
         lambda f, v: {"slug": v if f == "slug" else c._uniq()}, lambda v: "strict", None, "acme"),
        ("envs", "slug", "dev",
         lambda b: c.api("POST", f"/projects/{proj}/envs", actor=own, json=b),
         lambda f, v: dict({"slug": c._uniq(), "protected": False}, **{f: v}), lambda v: "strict", None, "acme"),
        ("envs", "protected", "true",
         lambda b: c.api("POST", f"/projects/{proj}/envs", actor=own, json=b),
         lambda f, v: dict({"slug": c._uniq(), "protected": False}, **{f: v}), lambda v: "strict", None, "acme"),
    ]
    tok_base = lambda f, v: dict({"project": proj, "env": "dev", "access": "read", "ttl_seconds": 3600,
                                  "name": c._uniq()}, **{f: v})
    post_tok = lambda b: _reg_token(c, c.api("POST", "/tokens", actor=own, json=b), "x10")
    for fld, base in (("project", proj), ("env", "dev"), ("access", "read"), ("ttl_seconds", "3600")):
        jspecs.append(("tokens", fld, base, post_tok, tok_base,
                       lambda v: "strict", None, "acme"))
    jspecs.append(("tokens", "name", "ci", post_tok, tok_base,
                   lambda v: "free", v_ok, "acme"))
    jspecs.append(("secrets PUT", "value", "v",
                   lambda b: c.api("PUT", _secret_path(proj, "dev", vkey), actor=own, json=b),
                   lambda f, v: {"value": v}, lambda v: "free", None, "acme"))
    jspecs.append(("secrets PUT", "expected_version", "1",
                   lambda b: c.api("PUT", _secret_path(proj, "dev", c.junk_key()), actor=own, json=b),
                   lambda f, v: {"value": "x", "expected_version": v}, lambda v: "strict", None, "acme"))
    jspecs.append(("rollback", "to", "1",
                   lambda b: c.api("POST", _secret_path(proj, "dev", jkey) + "/rollback", actor=own, json=b),
                   lambda f, v: {"to": v}, lambda v: "strict", None, "acme"))

    good_vals = {("auth/token", "email"): lu.email, ("auth/token", "password"): lu.password,
                 ("auth/password", "current_password"): None, ("auth/password", "new_password"): None,
                 ("members", "email"): None, ("admin/orgs", "slug"): None, ("projects", "slug"): None,
                 ("admin/orgs", "owner_email"): None,
                 ("envs", "slug"): None, ("envs", "protected"): False, ("tokens", "ttl_seconds"): 3600,
                 ("secrets PUT", "expected_version"): None, ("rollback", "to"): 1}
    for lab, fld, base, send, mkbody, modef, verify, aorg in jspecs:
        gv = good_vals.get((lab, fld), base)

        def ctl(send=send, mkbody=mkbody, fld=fld, gv=gv, lab=lab):
            b = mkbody(fld, gv)
            if gv is None:
                b = mkbody(fld, "__keep__")
                if fld == "current_password":
                    b["current_password"] = pstate["pw"]
                elif fld == "new_password":
                    b["new_password"] = _pw(16)
                elif fld == "email":
                    b["email"] = f"{c._uniq()}@acme.test"
                elif fld == "owner_email":
                    b["owner_email"] = f"owner-{c._uniq()}@x10.test"
                elif fld in ("slug",):
                    b["slug"] = c._uniq()
                elif fld == "expected_version":
                    b.pop("expected_version", None)
            return send(b)
        if not c.control(ctl, what=f"X10 json {lab}.{fld} control"):
            continue
        pls = _payloads(str(base)) + [("nul-char", str(base) + "\x00")]
        for pl_name, pl in pls:
            b = mkbody(fld, pl)
            r = send(b)
            mode = modef(pl)
            vf = None
            if mode == "free":
                if lab == "secrets PUT":
                    vf = (lambda r, pl=pl: v_secret(vkey)(r, pl))
                elif verify is not None:
                    vf = (lambda r, pl=pl, verify=verify: verify(r, pl))
                else:
                    vf = (lambda r: (True, ""))
            X.judge(r, f"{lab}.{fld}={pl_name}", mode=mode, verify=vf, actor_org=aorg)

    # ---- 4. integrity afterwards ----
    c.expect(c.wait_ready(30), "/readyz not 200 after injection probes")
    for org, p, e, k, v in _canary_paths(c):
        r, val = _read_value(c, f"owner@{org}", p, e, k)
        c.expect(val == v, f"after X10: {org}/{p}/{e}/{k} read by owner -> {r.status}, value "
                           f"{'matches' if val == v else 'differs'}")
    for lab in ("writer@acme", "reader@acme", "viewer@acme", "admin@acme"):
        u = c.actor(lab)
        r = c.api("GET", "/me", actor=u)
        c.expect(r.ok(), f"after X10: {lab} GET /me -> {r.status}")
    r = c.api("GET", "/projects", actor="owner@globex")
    c.expect(r.ok(), f"after X10: owner@globex GET /projects -> {r.status}")
    c.log("X10 probes judged: %d", X.n)
    return c.done(f"{X.n} injection probes -> 4xx/round-trip, no 5xx, no foreign data; fixture intact",
                  data={"probes": X.n})


# ==========================================================================
# X3: master key validation at startup
# ==========================================================================

def _placeholder(c):
    try:
        ex = c._env_file(c.repo / ".env.example")
    except Exception:  # noqa: BLE001
        ex = {}
    return ex.get("COFFER_MASTER_KEY")


def _override_refused(c, ov):
    if ov.ready:
        return False
    if ov.compose_rc == 0 and ov.running:
        # still running: give it 30 s more to be sure it never becomes ready
        if c.wait_ready(30):
            return False
    return True


@check("X3")
def x3(c) -> Result:
    """Placeholder, short or missing master key -> refuse to start"""
    ov0 = c.env_override(wait=90)
    if not ov0.ready:
        return c.error(f"control: unchanged .env did not become ready (compose_rc={ov0.compose_rc}, "
                       f"exit={ov0.exit_code})")
    _bump_control(c, "env_override with unchanged .env -> ready")
    ph = _placeholder(c)
    cases = []
    if ph is None:
        c.log("X3: .env.example has no COFFER_MASTER_KEY line")
        c.expect(False, ".env.example has no COFFER_MASTER_KEY placeholder")
    else:
        cases.append(("placeholder", {"set": {"COFFER_MASTER_KEY": ph}}))
    short = base64.b64encode(_secrets.token_bytes(16)).decode()
    cases.append(("16-byte key", {"set": {"COFFER_MASTER_KEY": short}}))
    cases.append(("unset", {"unset": ["COFFER_MASTER_KEY"]}))
    res = {}
    for name, kw in cases:
        ov = c.env_override(wait=75, **kw)
        refused = _override_refused(c, ov)
        res[name] = {"ready": ov.ready, "running": ov.running, "exit": ov.exit_code, "compose_rc": ov.compose_rc}
        c.expect(refused, f"master key {name}: server became ready (want refuse to start)")
    return c.done("placeholder, 16-byte and missing master key all refused", data=res)


# ==========================================================================
# X4: rotation
# ==========================================================================

def _read_all(c, items, what):
    bad = []
    for org, p, e, k, v in items:
        r, val = _read_value(c, f"owner@{org}", p, e, k)
        if val != v:
            bad.append(f"{org}/{p}/{e}/{k}->{r.status}")
    c.expect(not bad, f"{what}: {len(bad)}/{len(items)} unreadable or wrong: {', '.join(bad[:4])}")
    return not bad


@check("X4")
def x4(c) -> Result:
    """Key rotation PREVIOUS+MASTER, then MASTER=new, then MASTER=old fails closed"""
    items = _canary_paths(c)
    if not items:
        return c.error("fixture has no canaries")
    jk = c.junk_key()
    jv = c.secret(f"canary:x4-{jk}", _rand(40), "canary")
    r = c.api("PUT", _secret_path("api", "dev", jk), actor="owner@acme", json={"value": jv})
    if not r.ok():
        return c.error(f"junk PUT -> {r.status}")
    items = items + [("acme", "api", "dev", jk, jv)]
    if not c.control(lambda: c.api("GET", _secret_path("api", "dev", jk), actor="owner@acme"),
                     what="junk value readable before rotation"):
        return c.done()
    for org, p, e, k, v in items:
        rr, val = _read_value(c, f"owner@{org}", p, e, k)
        if val != v:
            return c.error(f"precondition: {org}/{p}/{e}/{k} not readable before rotation ({rr.status})")
    base = c._env_file(c.work / "ckpt" / c.id / "env") or c._env_file(c.work / "base.env")
    old = base.get("COFFER_MASTER_KEY")
    if not old:
        return c.error("no COFFER_MASTER_KEY in base .env")
    c.secret("key:x4-old", old, "key")
    new = c.secret("key:x4-new", base64.b64encode(_secrets.token_bytes(32)).decode(), "key")
    ov1 = c.env_override(set={"COFFER_MASTER_KEY_PREVIOUS": old, "COFFER_MASTER_KEY": new}, wait=180)
    c.expect(ov1.ready, f"PREVIOUS=old MASTER=new: not ready (exit={ov1.exit_code}, restarts={ov1.restarts})")
    if ov1.ready:
        _read_all(c, items, "after PREVIOUS=old MASTER=new")
    ov2 = c.env_override(set={"COFFER_MASTER_KEY": new}, unset=["COFFER_MASTER_KEY_PREVIOUS"], wait=180)
    c.expect(ov2.ready, f"MASTER=new alone: not ready (exit={ov2.exit_code}, restarts={ov2.restarts})")
    if ov2.ready:
        _read_all(c, items, "after MASTER=new alone")
    ov3 = c.env_override(set={"COFFER_MASTER_KEY": old}, unset=["COFFER_MASTER_KEY_PREVIOUS"], wait=90)
    refused = _override_refused(c, ov3)
    if refused:
        c.expect(True, f"MASTER=old alone: refused to start (exit={ov3.exit_code})")
    else:
        got, five = [], []
        for org, p, e, k, v in items:
            rr = c.api("GET", _secret_path(p, e, k), actor=f"owner@{org}")
            if rr.ok():
                got.append(f"{org}/{p}/{e}/{k}->{rr.status}{' (value!)' if _jget(rr, 'value') is not None else ''}")
            elif rr.status >= 500 or rr.status == 0:
                five.append(f"{org}/{p}/{e}/{k}->{rr.status}")
        c.expect(not got, f"MASTER=old alone: server ready and {len(got)} reads succeeded: {', '.join(got[:4])}")
        # GRADER "Any 500 anywhere is a fail": a ready server must answer with a 4xx, not 5xx
        c.expect(not five, f"MASTER=old alone: server ready and {len(five)} reads -> 5xx/transport: "
                           f"{', '.join(five[:4])}")
    return c.done("rotation re-wrapped; new key alone works; old key alone fails closed",
                  data={"ov1_ready": ov1.ready, "ov2_ready": ov2.ready, "ov3_ready": ov3.ready,
                        "ov3_exit": ov3.exit_code})


# ==========================================================================
# X2: AAD binding (SQL ciphertext transplant)
# ==========================================================================

_B64ISH = re.compile(r"^[A-Za-z0-9+/=_\-:.$]{24,}$")
_UUIDISH = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-")
_TSISH = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _app_tables(c):
    r = c.psql("SELECT c.table_schema, c.table_name, c.column_name, c.data_type FROM information_schema.columns c "
               "JOIN information_schema.tables t ON t.table_schema=c.table_schema AND t.table_name=c.table_name "
               "WHERE t.table_type='BASE TABLE' AND c.table_schema NOT IN ('pg_catalog','information_schema') "
               "AND c.table_schema NOT LIKE 'x2_%' ORDER BY 1,2,c.ordinal_position;")
    if r.rc != 0:
        return None
    tabs = {}
    for row in r.rows:
        if len(row) < 4:
            continue
        tabs.setdefault((row[0], row[1]), []).append((row[2], row[3]))
    out = {}
    for (s, t), cols in tabs.items():
        names = {n.lower() for n, _ in cols}
        if "audit" in t.lower() or "prev_hash" in names:
            continue
        out[(s, t)] = cols
    return out


def _snapshot(c, tabs):
    """{(schema,table): {ctid: md5}}"""
    parts = [f"SELECT '{s}.{t}', ctid::text, md5(row_to_json(x)::text) FROM \"{s}\".\"{t}\" x" for (s, t) in tabs]
    snap = {k: {} for k in tabs}
    for i in range(0, len(parts), 40):
        r = c.psql(" UNION ALL ".join(parts[i:i + 40]) + ";")
        if r.rc != 0:
            raise lib.HarnessError(f"snapshot failed: {r.err[:200]}")
        for row in r.rows:
            s, t = row[0].split(".", 1)
            snap[(s, t)][row[1]] = row[2]
    return snap


def _row_json(c, s, t, ctid):
    r = c.psql(f"SELECT row_to_json(x)::text FROM \"{s}\".\"{t}\" x WHERE ctid = '{ctid}'::tid;")
    if r.rc != 0 or not r.rows:
        return None
    try:
        return _json.loads(r.rows[0][0])
    except (ValueError, TypeError):
        return None


def _cryptoish(name, dtype, val, key, value):
    nl = name.lower()
    if nl == "id" or nl.endswith("_id") or nl.endswith("_at") or nl in ("key", "name", "slug", "version"):
        return False
    if val is None:
        return False
    if dtype == "bytea":
        return True
    if isinstance(val, (dict, list)):
        return True
    if not isinstance(val, str) or val in (key, value):
        return False
    if _UUIDISH.match(val) or _TSISH.match(val):
        return False
    if val.startswith("\\x") and len(val) >= 26:
        return True
    return bool(_B64ISH.match(val))


@check("X2")
def x2(c) -> Result:
    """AAD binding: copied ciphertext onto another key/env/org must fail to read"""
    own_a, own_g = "owner@acme", "owner@globex"
    try:
        proj = c.scratch_project(own_a, envs=(("dev", False), ("stg", False)))
    except lib.HarnessError as e:
        return c.error(f"scratch project: {e}")
    ok_ = c.api("GET", "/projects/api/envs/dev/secrets", actor=own_g)
    if not ok_.ok():
        return c.error(f"globex api/dev not listable by owner@globex ({ok_.status})")
    # warm-up writes so lazily created data keys do not show up as per-write rows
    for actor, p, e in ((own_a, proj, "dev"), (own_a, proj, "stg"), (own_a, "api", "dev"), (own_g, "api", "dev")):
        c.api("PUT", _secret_path(p, e, c.junk_key()), actor=actor, json={"value": "warm"})
    tabs = _app_tables(c)
    if not tabs:
        return c.error("no application tables found via information_schema")
    ko = f"X2_O_{_secrets.token_hex(3).upper()}"
    writes = [  # (name, actor, project, env, key)
        ("K1", own_a, proj, "dev", "X2_SRC"), ("K2", own_a, proj, "dev", "X2_DST"),
        ("Edev", own_a, proj, "dev", "X2_ENV"), ("Estg", own_a, proj, "stg", "X2_ENV"),
        ("Oacme", own_a, "api", "dev", ko), ("Oglobex", own_g, "api", "dev", ko),
    ]
    W = {}
    try:
        for name, actor, p, e, k in writes:
            v = c.secret(f"canary:x2-{name}", _rand(40), "canary")
            before = _snapshot(c, tabs)
            r = c.api("PUT", _secret_path(p, e, k), actor=actor, json={"value": v})
            if not r.ok():
                return c.error(f"write {name} {p}/{e}/{k} -> {r.status}")
            after = _snapshot(c, tabs)
            changed = {}
            for tk in tabs:
                cs = [ct for ct, h in after[tk].items() if before[tk].get(ct) != h]
                if cs:
                    changed[tk] = cs
            W[name] = {"actor": actor, "p": p, "e": e, "k": k, "v": v, "changed": changed}
            c.log("X2 write %s changed %s", name, {f"{s}.{t}": len(x) for (s, t), x in changed.items()})
    except lib.HarnessError as e:
        return c.error(str(e))
    # candidate tables: one changed row per write in each
    cand = [tk for tk in tabs if all(len(W[n]["changed"].get(tk, [])) == 1 for n in W)]
    chosen = []
    for tk in cand:
        rows = {n: _row_json(c, tk[0], tk[1], W[n]["changed"][tk][0]) for n in W}
        if any(v is None for v in rows.values()):
            continue
        dtypes = dict(tabs[tk])
        ccols = []
        for col, dt in tabs[tk]:
            vals = [rows[n].get(col) for n in W]
            if not all(_cryptoish(col, dt, rows[n].get(col), W[n]["k"], W[n]["v"]) for n in W):
                continue
            if len({_json.dumps(v, sort_keys=True) for v in vals}) != len(W):
                continue
            ccols.append(col)
        c.log("X2 candidate %s.%s crypto columns=%s", tk[0], tk[1], ccols)
        if ccols:
            chosen.append((tk, ccols, rows, dtypes))
    if not chosen:
        return c.error(f"could not locate ciphertext rows (candidates {[f'{s}.{t}' for s, t in cand]})")
    for tk, ccols, _, _ in chosen:
        c.expect(True, f"ciphertext table {tk[0]}.{tk[1]} columns {ccols}")
    # controls: each dst reads its own value before tampering
    pairs = [("same env, other key", "K1", "K2"), ("same key, other env", "Edev", "Estg"),
             ("acme -> globex", "Oacme", "Oglobex")]
    for label, s, d in pairs:
        wd = W[d]
        if not c.control(lambda wd=wd: c.api("GET", _secret_path(wd["p"], wd["e"], wd["k"]), actor=wd["actor"]),
                         what=f"{label}: dst readable before tamper"):
            return c.done()
    # tamper
    bs = f"x2_{_secrets.token_hex(4)}"
    if c.psql(f"CREATE SCHEMA {bs};").rc != 0:
        return c.error("cannot create backup schema")
    tampered = []
    for label, s, d in pairs:
        for i, (tk, ccols, rows, dtypes) in enumerate(chosen):
            sc, sd = W[s]["changed"][tk][0], W[d]["changed"][tk][0]
            bt = f"{bs}.b_{d.lower()}_{i}"
            setl = ", ".join(f'"{col}" = s."{col}"' for col in ccols)
            sql = (f'CREATE TABLE {bt} AS SELECT * FROM "{tk[0]}"."{tk[1]}" WHERE ctid = \'{sd}\'::tid;\n'
                   f'WITH s AS (SELECT * FROM "{tk[0]}"."{tk[1]}" WHERE ctid = \'{sc}\'::tid) '
                   f'UPDATE "{tk[0]}"."{tk[1]}" t SET {setl} FROM s WHERE t.ctid = \'{sd}\'::tid RETURNING t.ctid::text;')
            r = c.psql(sql)
            if r.rc != 0 or len(r.rows) != 1:
                return c.error(f"tamper {label} on {tk[1]} failed rc={r.rc} rows={len(r.rows)} {r.err[:150]}")
            newct = r.rows[0][0]
            eq = " AND ".join(f't."{col}" IS NOT DISTINCT FROM s."{col}"' for col in ccols)
            vr = c.psql(f'SELECT count(*) FROM "{tk[0]}"."{tk[1]}" t, "{tk[0]}"."{tk[1]}" s '
                        f"WHERE t.ctid = '{newct}'::tid AND s.ctid = '{sc}'::tid AND {eq};")
            c.expect(vr.rc == 0 and vr.rows and vr.rows[0][0] == "1",
                     f"{label}: dst crypto columns equal src after UPDATE on {tk[1]}")
            tampered.append((label, d, tk, ccols, bt, newct))
    # restart to clear any cache
    c.compose("restart", "server", timeout=180)
    up = c.wait_ready(120)
    c.log("X2 after tamper restart ready=%s", up)
    for label, s, d in pairs:
        wd, ws = W[d], W[s]
        r1 = c.api("GET", _secret_path(wd["p"], wd["e"], wd["k"]), actor=wd["actor"])
        r2 = c.api("GET", _secret_path(wd["p"], wd["e"], wd["k"]) + "/versions/1", actor=wd["actor"])
        r3 = c.api("GET", f"/projects/{wd['p']}/envs/{wd['e']}/export", actor=wd["actor"], query={"format": "json"})
        for what, rr in (("get", r1), ("get v1", r2)):
            leaked = ws["v"].encode() in (rr.body or b"")
            c.expect(not rr.ok(), f"{label}: tampered {what} -> {rr.status}"
                                  f"{' with SOURCE value' if leaked else ''} (want an error)")
            # GRADER: "Any 500 anywhere is a fail". X2 is allow_5xx in registry.py only so a
            # server that fails to restart is not auto-failed; an /api/v1 5xx is still a fail.
            c.expect(rr.status < 500 and (rr.status != 0 or not up),
                     f"{label}: tampered {what} -> {rr.status} (want a 4xx error, not 5xx/transport)")
        if r3.ok():
            try:
                ex = r3.json()
            except ValueError:
                ex = None
            has = isinstance(ex, dict) and wd["k"] in ex
            c.expect(not has, f"{label}: export after tamper -> {r3.status} includes {wd['k']}")
            c.expect(ws["v"].encode() not in r3.body or ws["p"] == wd["p"] and ws["e"] == wd["e"],
                     f"{label}: export of dst env contains the source value")
        else:
            c.expect(r3.status < 500 and (r3.status != 0 or not up),
                     f"{label}: export after tamper -> {r3.status} (want a 4xx error, not 5xx/transport)")
        if up:
            c.control(lambda ws=ws: c.api("GET", _secret_path(ws["p"], ws["e"], ws["k"]), actor=ws["actor"]),
                      what=f"{label}: src still readable after tamper")
    # restore originals and prove the dst reads its own value again
    failed_already = any(not ok for ok, _ in c._expects)
    for label, d, tk, ccols, bt, newct in tampered:
        setl = ", ".join(f'"{col}" = b."{col}"' for col in ccols)
        rr = c.psql(f'UPDATE "{tk[0]}"."{tk[1]}" t SET {setl} FROM {bt} b WHERE t.ctid = \'{newct}\'::tid;')
        if rr.rc != 0:
            c.log("X2 restore %s failed: %s", label, rr.err[:200])
    c.psql(f"DROP SCHEMA {bs} CASCADE;")
    c.compose("restart", "server", timeout=180)
    c.wait_ready(120)
    for label, s, d in pairs:
        wd = W[d]
        rr, val = _read_value(c, wd["actor"], wd["p"], wd["e"], wd["k"])
        if val == wd["v"]:
            _bump_control(c, f"{label}: dst reads its own value after restoring its ciphertext")
        elif not failed_already:
            c.error_once(f"control failed: {label}: dst not readable after restore ({rr.status})")
        else:
            c.log("X2 restore control %s failed (%s) after real failures; not overriding", label, rr.status)
    return c.done("3 transplants (key, env, org): every read errored; restore reads back")


# ==========================================================================
# X1 / X6: sweeps
# ==========================================================================

def _home_label(rel: str) -> str:
    parts = rel.split("/")
    return parts[1] if len(parts) > 1 else rel


def _decoded_layers(c, p):
    data = p.read_bytes()
    out = [("", data)]
    if data[:2] == b"\x1f\x8b":
        try:
            g = gzip.decompress(data)
            out.append(("!gunzip", g))
            data = g
        except Exception:  # noqa: BLE001
            pass
    if data[:5] == b"PGDMP":
        out.append(("!pg_restore", c._pg_restore_text(data)))
    return out


def _sweep_selftest(c, sw):
    needle = _rand(40)
    fake = b"x" + needle.encode().hex().encode() + b"y" + base64.b64encode(needle.encode()) + b"z" + needle.encode()
    hits = []
    sw._scan_bytes(fake, [("selftest", "canary", needle)], "selftest", "selftest", hits, ("raw", "hex", "b64"))
    encs = sorted({h.encoding for h in hits})
    if encs == ["b64", "hex", "raw"]:
        _bump_control(c, "sweep scanner finds a planted needle raw/hex/b64")
        return True
    c.error_once(f"control failed: sweep scanner self-test found {encs}")
    return False


_X1_REQ = ("method", "route", "status", "request_id")


def _x1_request_lines(data: bytes) -> int:
    n = 0
    for ln in data.splitlines():
        i = ln.find(b"{")
        if i < 0:
            continue
        try:
            o = _json.loads(ln[i:].decode("utf-8", "replace"))
        except ValueError:
            continue
        if not isinstance(o, dict):
            continue
        cands = [o] + [v for v in o.values() if isinstance(v, dict)]
        if any(all(k in d for k in _X1_REQ) for d in cands) or \
                all(any(k in d for d in cands) for k in _X1_REQ):
            n += 1
    return n


@check("X1")
def x1(c) -> Result:
    """Canary sweep: canaries/tokens/passwords absent from dumps, logs, backups, CLI config"""
    p, dest = c.backup("x1")
    c.log("X1 backup.sh rc=%s exists=%s", p.rc, dest.exists())
    sw = c.sweep()
    if not _sweep_selftest(c, sw):
        return c.done()
    nd = sw.needles()
    kinds = {k: sum(1 for _, kk, _ in nd if kk == k) for k in ("canary", "token", "password")}
    c.log("X1 needles %s", kinds)
    if kinds["canary"] < 6 or kinds["token"] < 1 or kinds["password"] < 1:
        return c.error(f"too few needles {kinds}")
    files = {s: sw.files(s) for s in ("dumps", "logs", "backups", "homes")}
    for s, fs in files.items():
        if not fs:
            return c.error(f"sweep source {s} is empty")
    if not any(f.stat().st_size > 0 for f in files["backups"]):
        return c.error("every backup file is empty")
    # dumps hold real app data: a fixture email and an org id
    emails = [u.get("email") for u in ((c.fx or {}).get("users") or {}).values() if (u or {}).get("email")]
    org_ids = [str(o.get("id")) for o in ((c.fx or {}).get("orgs") or {}).values() if (o or {}).get("id")]
    last = files["dumps"][-1].read_bytes()
    if not (any(e.encode() in last for e in emails) and any(o.encode() in last for o in org_ids)):
        return c.error("final dump has no fixture email / org id: not the app data")
    _bump_control(c, "final dump contains fixture emails and org ids")
    # r4 (X1 on build-2): the control is SPEC-5 request lines, i.e. JSON log lines carrying
    # method, route, status and request_id (top level or one level nested), not a literal
    # "/api/v1" (a build may log route templates without the prefix).
    nreq = sum(_x1_request_lines(f.read_bytes()) for f in files["logs"])
    c.log("X1 SPEC-5 request lines in swept logs: %d", nreq)
    if nreq == 0:
        return c.error("no swept log holds a JSON request line (method, route, status, request_id)")
    _bump_control(c, f"server logs contain {nreq} JSON request lines")
    hits = sw.scan()
    by_label = {}
    for h in hits:
        by_label.setdefault(h.label, []).append(h)
    for lab, hs in sorted(by_label.items()):
        homes = [h for h in hs if h.source == "homes"]
        other = [h for h in hs if h.source != "homes"]
        allowed = (not other and lab.endswith(":cli") and hs[0].kind == "token"
                   and len({_home_label(h.file) for h in homes}) == 1
                   and all("/.config/coffer/" in "/" + h.file for h in homes))
        if allowed:
            c.log("X1 allowed: %s only in its own CLI config %s", lab, homes[0].file)
            continue
        for h in hs[:3]:
            c.expect(False, f"{h.kind} {lab} found in {h.source}/{h.file} ({h.encoding} @ {h.offset})")
    # token-shaped regex
    for s in ("dumps", "logs", "backups"):
        for f in files[s]:
            layers = _decoded_layers(c, f) if s == "backups" else [("", f.read_bytes())]
            for suf, data in layers:
                m = TOKEN_RE.search(data)
                if m:
                    c.expect(False, f"token-shaped string in {s}/{f.name}{suf} @ {m.start()} "
                                    f"({m.group()[:10].decode()}…)")
    per_home = {}
    cfg_seen = False
    for f in files["homes"]:
        rel = str(f.relative_to(sw.root / "homes"))
        lab = rel.split("/")[0]
        data = f.read_bytes()
        toks = set(TOKEN_RE.findall(data))
        if "/.config/coffer/" in "/" + rel and toks:
            cfg_seen = True
        if toks and "/.config/coffer/" not in "/" + rel:
            c.expect(False, f"token-shaped string outside the CLI config dir: homes/{rel}")
        per_home.setdefault(lab, set()).update(toks)
    for lab, toks in sorted(per_home.items()):
        c.expect(len(toks) <= 1, f"home {lab} holds {len(toks)} distinct tokens (only its own allowed)")
    if not cfg_seen:
        return c.error("no CLI home holds a coffer config with a token: homes rule untestable")
    _bump_control(c, "a CLI config with its own token was found")
    c.expect(True, f"scanned {sum(len(v) for v in files.values())} files for {len(nd)} needles")
    return c.done(f"{len(nd)} needles ({kinds}) absent from {len(files['dumps'])} dumps, {len(files['logs'])} logs, "
                  f"{len(files['backups'])} backups, {len(files['homes'])} home files",
                  data={"needles": kinds, "files": {k: len(v) for k, v in files.items()}})


@check("X6")
def x6(c) -> Result:
    """Tokens not in the dump in plaintext"""
    sw = c.sweep()
    if not _sweep_selftest(c, sw):
        return c.done()
    dumps = sw.files("dumps")
    if not dumps:
        return c.error("no dumps in the sweep cache")
    toks = sw.needles(("token",))
    if len(toks) < 3:
        return c.error(f"only {len(toks)} token needles")
    hits = sw.scan(sources=("dumps",), kinds=("token",))
    for h in hits[:5]:
        c.expect(False, f"token {h.label} in dumps/{h.file} ({h.encoding} @ {h.offset})")
    full = re.compile(rb"cof_(?:pat|st)_[A-Za-z0-9_\-]{22,}")
    for f in dumps:
        data = f.read_bytes()
        m = full.search(data)
        if m:
            c.expect(False, f"token-shaped string in dumps/{f.name} @ {m.start()} ({m.group()[:10].decode()}…)")
        else:
            m2 = TOKEN_RE.search(data)
            if m2:
                c.log("X6 short token-prefix run in %s @ %d (len %d), not counted", f.name, m2.start(), len(m2.group()))
    c.expect(True, f"{len(toks)} token needles scanned over {len(dumps)} dumps")
    return c.done(f"{len(toks)} tokens absent (raw/hex/b64 + regex) from {len(dumps)} dumps")
