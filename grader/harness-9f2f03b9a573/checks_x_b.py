"""Coffer grading checks: X15, X16, X17, X18, X11, X12, X13, X14, X19, X20.

Black-box only (CONTRACT.md): README, ./bin/coffer, the SPEC 7.2 HTTP API, psql in the
db container, container logs, ps, repo-level files. No build source is read.

Readings chosen where GRADER/CONTRACT leave room (stricter on the build, identical for
both builds):
- X11: every probe that must fail has to return a 4xx (never 2xx/5xx/transport error)
  whose body is {"error":{"code":<non-empty str>,"message":<non-empty str>}}. Extra
  top-level keys are allowed. Coverage: across the probes, 400, 404 and 413 must each be
  observed. The wrong-method probes accept 405 or 404 (SPEC: unknown routes are 404).
  "Lenient" probes (bad query params, odd content type) may legitimately be 2xx; they are
  only scanned for leaks, and their shape is checked when they are 4xx. Every response
  body seen (including the positive control) is scanned for traces, file paths, SQL.
- X12: a 2 MiB JSON PUT to a secret (owner@acme, junk key) and a 2 MiB POST /auth/token,
  each sent over a raw socket with Content-Length, must return 413 within 1 s (wall time
  from connect to full response). The oversized key must not be stored afterwards (404).
  A chunked (no Content-Length) variant is logged for information only.
- X13: exactly 401 after logout (GRADER: "reuse -> 401"). Two paths, both must pass:
  (a) raw API login -> PAT works -> POST /auth/logout -> same PAT -> 401;
  (b) CLI: `coffer login` in a fresh HOME, the PAT is read from the CLI's own config
      file (the one place SPEC allows it in plaintext), works, `coffer logout`, -> 401.
      If no cof_pat_ token is found in the config file, (b) is a fail.
- X14: `ps -eo pid,user,args` is sampled repeatedly while each command waits on stdin and
  until it exits. Any ps line (any user) containing the password is a fail. Controls: our
  spawned pid must be seen in ps at least once, and each command must exit 0.
- X17: the fixture users' config dirs, plus one fresh `coffer login` run under umask 000
  (so a build that relies on the default umask is caught), must be dir 0700 and every
  file under it 0600; each dir must contain at least one file.
- X18: a representative F-style sequence (login, whoami, set via stdin and via argv, get,
  get --version, list, history, export dotenv/json, run, token create/list/revoke,
  COFFER_TOKEN get, delete, rollback, protected write + change list/reject, audit
  list/verify, member add, login as the new member, passwd, admin org create, logout) is
  run with COFFER_URL = the mitmdump reverse proxy started in setup (S5). Every captured
  URL in OUT/proxy_urls.jsonl (F block + this sequence) is checked raw, %-decoded and
  +-decoded against every registered secret (>= 12 chars) and against a token-shaped
  regex (cof_pat_/cof_st_ + 16 chars, which also catches the CLI's own PAT that the
  harness never sees). Server request logs (current container + every server log in the
  sweep cache) are checked the same way, whole line (strict: any secret/token anywhere in
  a request log line fails). Non-vacuity: the capture must contain this sequence's
  /secrets and /auth/token requests; the CLI must have returned the canary byte-exact.
  If the proxy is not running, the check is an error.
- X19: as server_db_role(), for every table whose name contains "audit" or that has a
  prev_hash column (pg_class, black-box schema discovery), with at least one row: an
  UPDATE (col = col) and a DELETE of one real row (by ctid, read as superuser), each in
  BEGIN ... ROLLBACK, must fail with "permission denied". A superuser server role fails.
  If 0 rows were affected without an error (e.g. RLS) it is still a fail per CONTRACT,
  with that fact in the evidence.
- X20: a scratch user logs in twice (PAT A, PAT B); both work (control); password change
  via POST /auth/password using PAT A; PAT B must then give exactly 401. The new password
  must log in (precondition, else fail with the status).
- X15: `osv-scanner scan source -r <clone> --format json`, retried once on a tool error.
  Lockfiles = files osv-scanner reports as "Scanned <file> file and found N packages";
  0 -> fail. High/Critical = a vuln group with max_severity >= 7.0 or a vuln whose
  database_specific.severity is HIGH/CRITICAL. Control: the same tool on a planted
  requirements.txt (django==1.11.0) must report >= 1 High/Critical.
  r4-1: every finding records its repo-relative lockfile path and the full list is
  logged untruncated. Only first-party lockfiles are judged: a lockfile under a
  vendored/third-party directory (any dir component vendor, node_modules,
  third_party, third-party, thirdparty, bower_components, or under .yarn/cache) is an
  upstream package's own lockfile that the build's resolver never reads (the build's
  resolved versions of those packages are in its root/workspace lockfile). Its hits
  are logged as info. 0 first-party lockfiles -> fail (as before).
- X16: `gitleaks git <clone> --report-format json`; findings whose file basename is
  .env.example are dropped; anything left fails. Control: a throwaway repo with a planted
  ghp_ token must yield a finding.
"""
from __future__ import annotations

import json as _json
import os
import re
import secrets as _secrets
import shutil
import socket
import stat
import string
import subprocess
import time
import urllib.parse
from pathlib import Path

import lib
from registry import Result, check, not_implemented  # noqa: F401

_ALNUM = string.ascii_letters + string.digits
TOKEN_RE = re.compile(r"cof_(?:pat|st)_[A-Za-z0-9_\-]{16,}")
MIB = 1024 * 1024


def _rand(n: int = 40) -> str:
    return "".join(_secrets.choice(_ALNUM) for _ in range(n))


def _owner(c) -> lib.Actor:
    return c.actor("owner@acme")


# --------------------------------------------------------------------------
# raw socket request (local helper: lib.http cannot time a 413 that is sent
# before the server reads the whole body without risking a send-side reset)
# --------------------------------------------------------------------------

def _raw(c, method: str, path: str, *, body: bytes = b"", headers: dict | None = None,
         actor=None, chunked: bool = False, timeout: float = 10.0) -> dict:
    u = urllib.parse.urlsplit(c.base_url)
    host, port = u.hostname or "127.0.0.1", u.port or 80
    hdrs = {"Host": f"{host}:{port}", "Connection": "close"}
    if actor is not None:
        a = c.actor(actor)
        if a.secret:
            hdrs["Authorization"] = f"Bearer {a.secret}"
    hdrs.update(headers or {})
    if chunked:
        hdrs["Transfer-Encoding"] = "chunked"
    else:
        hdrs["Content-Length"] = str(len(body))
    head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    res = {"status": 0, "headers": {}, "body": b"", "ms": 0.0, "err": None, "sent": 0}
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        res["err"] = f"connect: {e}"
        res["ms"] = (time.monotonic() - t0) * 1000
        return res
    try:
        s.settimeout(timeout)
        try:
            s.sendall(head.encode("latin-1"))
            step = 64 * 1024
            for i in range(0, len(body), step):
                part = body[i:i + step]
                if chunked:
                    s.sendall(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                else:
                    s.sendall(part)
                res["sent"] += len(part)
            if chunked:
                s.sendall(b"0\r\n\r\n")
        except OSError as e:  # server may answer and close before reading everything
            res["err"] = f"send stopped after {res['sent']}B: {e}"
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            except OSError as e:
                if not buf:
                    res["err"] = (res["err"] or "") + f" recv: {e}"
                break
            if not d:
                break
            buf += d
            if b"\r\n\r\n" in buf:
                hpart, _, rest = buf.partition(b"\r\n\r\n")
                m = re.search(rb"(?im)^content-length:\s*(\d+)", hpart)
                if m and len(rest) >= int(m.group(1)):
                    break
    finally:
        try:
            s.close()
        except OSError:
            pass
    res["ms"] = (time.monotonic() - t0) * 1000
    if buf:
        hpart, _, rest = buf.partition(b"\r\n\r\n")
        lines = hpart.decode("latin-1", "replace").split("\r\n")
        m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
        if m:
            res["status"] = int(m.group(1))
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                res["headers"][k.strip().lower()] = v.strip()
        if "chunked" in res["headers"].get("transfer-encoding", "").lower():
            out, r = b"", rest
            while r:
                sz, _, r = r.partition(b"\r\n")
                try:
                    n = int(sz.split(b";")[0], 16)
                except ValueError:
                    break
                if n == 0:
                    break
                out += r[:n]
                r = r[n + 2:]
            rest = out
        res["body"] = rest
    if res["status"] >= 500:
        c.saw_5xx.append(f"{method} {path} (raw) -> {res['status']}")
    c.log("RAW %s %s len=%d chunked=%s -> %s %.0fms sent=%d err=%s\n  resp: %s", method, path, len(body),
          chunked, res["status"], res["ms"], res["sent"], res["err"], c._body_for_log(res["body"]))
    return res


# --------------------------------------------------------------------------
# shared: error shape + leak scan
# --------------------------------------------------------------------------

LEAK_PATTERNS = [
    ("traceback", re.compile(r"Traceback")),
    ("at-path", re.compile(r"\bat\s+[^\n\"]*?(?:/|[A-Za-z]:\\)[\w.\-/\\<>]+(?::\d+)")),
    ("src-file", re.compile(r"\.(?:ts|py|go|js|mjs|cjs|tsx):\d*")),
    ("sql-select", re.compile(r"\bSELECT\b")),
    ("sql-insert", re.compile(r"\bINSERT INTO\b")),
    ("sql-error", re.compile(r"syntax error at or near|SQLSTATE|duplicate key value violates|\bpq: ")),
    ("stack-go", re.compile(r"goroutine \d+|\bpanic: ")),
    ("stack-py", re.compile(r"File \"[^\"]+\", line \d+")),
    ("stack-js", re.compile(r"\n\s+at \S|node_modules|Exception in thread")),
]


def _leaks(text: str) -> list:
    return [name for name, rx in LEAK_PATTERNS if rx.search(text)]


def _shape(body: bytes) -> tuple:
    try:
        d = _json.loads(body)
    except ValueError:
        return False, "body not JSON"
    if not isinstance(d, dict) or not isinstance(d.get("error"), dict):
        return False, "no error object"
    e = d["error"]
    for k in ("code", "message"):
        if not isinstance(e.get(k), str) or not e.get(k):
            return False, f"error.{k} missing/empty"
    return True, "ok"


# --------------------------------------------------------------------------
# X15 osv-scanner
# --------------------------------------------------------------------------

def _which(name: str) -> str | None:
    search = os.environ.get("PATH", "") + os.pathsep + "/usr/local/bin:/usr/bin" + os.pathsep + \
        str(Path.home() / ".local" / "bin")
    return shutil.which(name, path=search)


def _osv_run(c, exe: str, target: Path, timeout: float):
    p = lib._run([exe, "scan", "source", "-r", str(target), "--format", "json"], cwd=c.tmp,
                 env=dict(os.environ), timeout=timeout)
    c.log("osv-scanner %s -> rc=%s %.0fms\n  err: %s", target, p.rc, p.ms,
          p.err.decode("utf-8", "replace")[-3000:])
    return p


_OSV_VENDOR_DIRS = {"vendor", "node_modules", "third_party", "third-party", "thirdparty", "bower_components"}


def _osv_third_party(rel: str) -> bool:
    """r4-1: a repo-relative lockfile path inside a vendored / third-party tree."""
    parts = rel.replace("\\", "/").split("/")[:-1]
    if any(x in _OSV_VENDOR_DIRS for x in parts):
        return True
    return "/".join(parts).startswith(".yarn/cache") or "/.yarn/cache" in "/" + "/".join(parts)


def _osv_rel(src: str, repo_s: str) -> str:
    """repo-relative path of an osv-scanner source (tries the repo path and its realpath)."""
    for r in ((repo_s, os.path.realpath(repo_s)) if repo_s else ()):
        if src == r or src.startswith(r.rstrip("/") + "/"):
            return os.path.relpath(src, r)
    return src


def _osv_parse(p, repo_s: str = "") -> tuple:
    """returns (scanned_files, high_list, parse_ok); high items are dicts with a
    repo-relative 'file' (r4-1)."""
    txt = p.err.decode("utf-8", "replace") + "\n" + p.out.decode("utf-8", "replace")
    scanned = re.findall(r"Scanned (.+?) file and found (\d+) package", txt)
    high = []
    try:
        d = _json.loads(p.out) if p.out.strip() else {"results": []}
    except ValueError:
        return scanned, high, False
    for r in d.get("results") or []:
        src = (r.get("source") or {}).get("path", "?")
        rel = _osv_rel(src, repo_s)
        for pk in r.get("packages") or []:
            pkg = pk.get("package") or {}
            vsev = {}
            for v in pk.get("vulnerabilities") or []:
                s = str((v.get("database_specific") or {}).get("severity") or "").upper()
                vsev[v.get("id")] = s
            for g in pk.get("groups") or []:
                ids = g.get("ids") or []
                try:
                    ms = float(g.get("max_severity") or 0)
                except (TypeError, ValueError):
                    ms = 0.0
                db_hi = any(vsev.get(i) in ("HIGH", "CRITICAL") for i in ids)
                if ms >= 7.0 or db_hi:
                    high.append({"file": rel, "third_party": _osv_third_party(rel),
                                 "desc": f"{pkg.get('name')}@{pkg.get('version')} {','.join(ids)} "
                                         f"sev={g.get('max_severity')} in {rel}"})
    return scanned, high, True


@check("X15")
def x15(c) -> Result:
    """osv-scanner over lockfiles: 0 High/Critical; lockfiles exist"""
    exe = _which("osv-scanner")
    if not exe:
        return c.error("osv-scanner not found on PATH")
    # positive control: a known-vulnerable pin must produce >= 1 High/Critical
    ctl = c.tmp / "osv-control"
    ctl.mkdir(parents=True, exist_ok=True)
    (ctl / "requirements.txt").write_text("django==1.11.0\n")
    cp = _osv_run(c, exe, ctl, 180)
    if cp.rc not in (0, 1):
        cp = _osv_run(c, exe, ctl, 180)
    _cs, chigh, cok = _osv_parse(cp, str(ctl))
    if not (cok and chigh):
        return c.error(f"osv control (django==1.11.0) found no High/Critical (rc={cp.rc}); scanner/network broken")
    c.control(lambda: lib.CliResult(0, b"", b"", 0.0, []), what="osv control finds High/Critical")
    p = _osv_run(c, exe, c.repo, 300)
    if p.rc not in (0, 1, 128):
        c.log("osv-scanner rc=%s, retrying once", p.rc)
        p = _osv_run(c, exe, c.repo, 300)
    repo_s = str(c.repo)
    scanned, high, ok = _osv_parse(p, repo_s)
    rows = [(_osv_rel(f, repo_s), n) for f, n in scanned]
    first = [f"{f} ({n} pkgs)" for f, n in rows if not _osv_third_party(f)]
    third = [f"{f} ({n} pkgs)" for f, n in rows if _osv_third_party(f)]
    c.log("lockfiles scanned: %d first-party, %d vendored/third-party (info only)", len(first), len(third))
    c.log("first-party lockfiles: %s", first)
    c.log("vendored/third-party lockfiles (not judged): %d, e.g. %s", len(third), third[:10])
    hi_1 = [h["desc"] for h in high if not h["third_party"]]
    hi_3 = [h["desc"] for h in high if h["third_party"]]
    c.log("High/Critical in first-party lockfiles (%d):\n  %s", len(hi_1), "\n  ".join(hi_1) or "-")
    c.log("High/Critical in vendored/third-party lockfiles, info only (%d):\n  %s", len(hi_3),
          "\n  ".join(hi_3) or "-")
    if p.rc == 128 or not scanned:
        return c.fail(f"no lockfiles found by osv-scanner (rc={p.rc})", {"rc": p.rc})
    if p.rc not in (0, 1) or not ok:
        return c.error(f"osv-scanner rc={p.rc} or unparseable JSON (after retry)")
    data = {"lockfiles": first, "third_party_lockfiles": len(third), "high": hi_1,
            "high_third_party_info": hi_3}
    if not first:
        return c.fail(f"no first-party lockfiles (only {len(third)} vendored/third-party ones)", data)
    c.expect(not hi_1, f"{len(hi_1)} High/Critical in first-party lockfiles: " + "; ".join(hi_1),
             ok_msg="0 High/Critical in first-party lockfiles")
    return c.done(f"0 High/Critical across {len(first)} first-party lockfiles: " + ", ".join(first[:6])
                  + (f" ({len(hi_3)} hit(s) in {len(third)} vendored lockfiles, info)" if third else ""), data)


# --------------------------------------------------------------------------
# X16 gitleaks
# --------------------------------------------------------------------------

def _gitleaks(c, exe: str, repo: Path, report: Path):
    p = lib._run([exe, "git", str(repo), "--report-format", "json", "--report-path", str(report),
                  "--no-banner"], cwd=c.tmp, env=dict(os.environ), timeout=400)
    c.log("gitleaks %s -> rc=%s %.0fms\n  err: %s", repo, p.rc, p.ms, p.err.decode("utf-8", "replace")[-2000:])
    try:
        findings = _json.loads(report.read_text() or "[]")
    except (OSError, ValueError):
        findings = None
    return p, findings


@check("X16")
def x16(c) -> Result:
    """gitleaks across full history: no findings beyond .env.example placeholders"""
    exe = _which("gitleaks")
    if not exe:
        return c.error("gitleaks not found on PATH")
    git = _which("git") or "git"
    ctl = c.tmp / "gl-control"
    ctl.mkdir(parents=True, exist_ok=True)
    genv = dict(os.environ, GIT_CONFIG_NOSYSTEM="1")
    lib._run([git, "init", "-q", str(ctl)], env=genv, timeout=30)
    (ctl / "cfg.py").write_text(f'token = "ghp_{_rand(36)}"\n')
    lib._run([git, "-C", str(ctl), "add", "."], env=genv, timeout=30)
    lib._run([git, "-C", str(ctl), "-c", "user.name=g", "-c", "user.email=g@g.test", "commit", "-qm", "c"],
             env=genv, timeout=30)
    cp, cf = _gitleaks(c, exe, ctl, c.tmp / "gl-control.json")
    if cp.rc != 1 or not cf:
        return c.error(f"gitleaks control (planted ghp_ token) not detected (rc={cp.rc})")
    c.control(lambda: lib.CliResult(0, b"", b"", 0.0, []), what="gitleaks control detects planted token")
    p, f = _gitleaks(c, exe, c.repo, c.tmp / "gl.json")
    if p.rc not in (0, 1) or f is None:
        p, f = _gitleaks(c, exe, c.repo, c.tmp / "gl.json")
    if p.rc not in (0, 1) or f is None:
        return c.error(f"gitleaks rc={p.rc}, report unreadable")
    kept = [x for x in f if os.path.basename(str(x.get("File", ""))) != ".env.example"]
    dropped = len(f) - len(kept)
    summ = [f"{x.get('RuleID')} {x.get('File')}:{x.get('StartLine')} commit {str(x.get('Commit', ''))[:8]}"
            for x in kept]
    for s in summ:
        c.log("finding: %s", s)
    c.expect(not kept, f"{len(kept)} gitleaks findings: " + "; ".join(summ[:3]) if kept else "0 findings")
    return c.done(f"0 findings outside .env.example ({dropped} .env.example placeholder findings ignored)",
                  {"findings": summ[:50], "env_example_ignored": dropped})


# --------------------------------------------------------------------------
# X17 config modes
# --------------------------------------------------------------------------

def _mode_check(c, label: str, home: Path) -> int:
    d = home / ".config" / "coffer"
    if not d.is_dir():
        c.expect(False, f"{label}: no config dir at {d}")
        return 0
    m = stat.S_IMODE(d.stat().st_mode)
    c.expect(m == 0o700, f"{label}: dir {d.name} mode {m:04o} (want 0700)")
    n = 0
    for p in sorted(d.rglob("*")):
        pm = stat.S_IMODE(p.lstat().st_mode)
        if p.is_dir():
            c.expect(pm == 0o700, f"{label}: subdir {p.relative_to(d)} mode {pm:04o} (want 0700)")
        else:
            n += 1
            c.expect(pm == 0o600, f"{label}: file {p.relative_to(d)} mode {pm:04o} (want 0600)")
    c.expect(n > 0, f"{label}: config dir has {n} files (want >= 1)")
    return n


@check("X17")
def x17(c) -> Result:
    """CLI config: dir 0700, file 0600"""
    users = (c.fx or {}).get("users") or {}
    checked = 0
    for lab in sorted(users):
        h = (users[lab] or {}).get("home")
        if h:
            _mode_check(c, lab, Path(h))
            checked += 1
    if checked == 0:
        return c.error("fixture has no user homes")
    # fresh login under umask 000: modes must be set explicitly, not inherited
    a = c.scratch_user("acme", "member")
    h = c.scratch_home()
    old = os.umask(0)
    try:
        r = c.cli("login", "--email", a.email, home=h, stdin=(a.password + "\n").encode(), url=c.base_url)
    finally:
        os.umask(old)
    if r.rc != 0:
        return c.error(f"coffer login (umask 000) rc={r.rc}")
    c.control(lambda: r, what="login under umask 000")
    _mode_check(c, "fresh login umask000", h)
    return c.done(f"{checked} fixture homes + 1 umask-000 login: dir 0700, files 0600")


# --------------------------------------------------------------------------
# X18 no secrets/tokens in URLs
# --------------------------------------------------------------------------

def _url_hits(text: str, needles: list) -> list:
    forms = {text, urllib.parse.unquote(text), urllib.parse.unquote_plus(text)}
    hits = []
    for lab, v in needles:
        if any(v in f for f in forms):
            hits.append(lab)
    for f in forms:
        for m in TOKEN_RE.finditer(f):
            hits.append("token-shaped:" + m.group(0)[:12] + "…")
    return sorted(set(hits))


def _walk_strings(obj, key=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, str(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v, key)
    elif isinstance(obj, str):
        yield key, obj


@check("X18")
def x18(c) -> Result:
    """No secret value or token in any URL (mitmdump capture of F block + request logs)"""
    purl = c.proxy_url
    if not purl:
        return c.error(f"mitmdump proxy not running ({(c.setup or {}).get('proxy_error')})")
    cap = c.out / "proxy_urls.jsonl"

    def cap_lines():
        try:
            return cap.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
    start = len(cap_lines())
    own = _owner(c)
    P = ["-p", "api", "-e", "dev"]
    pfx = f"X18_{_secrets.token_hex(3).upper()}"
    v1 = c.secret(f"canary:{pfx}_V1", _rand(40), "canary")
    v2 = c.secret(f"canary:{pfx}_V2", _rand(40), "canary")
    v3 = c.secret(f"canary:{pfx}_ARGV", _rand(40), "canary")
    kv, ka = f"{pfx}_V", f"{pfx}_ARGV"

    def run(*args, **kw):
        kw.setdefault("url", purl)
        kw.setdefault("timeout", 30)
        return c.cli(*args, **kw)
    h = c.scratch_home()
    lr = run("login", "--email", own.email, home=h, stdin=(own.password + "\n").encode())
    if lr.rc != 0:
        return c.error(f"owner login via proxy rc={lr.rc}")
    run("whoami", home=h)
    run("secrets", "set", kv, *P, home=h, stdin=v1.encode())
    run("secrets", "set", kv, *P, home=h, stdin=v2.encode())
    run("secrets", "set", ka, v3, *P, home=h)
    g = run("secrets", "get", kv, *P, home=h)
    routed = g.rc == 0 and g.out == v2.encode()
    run("secrets", "get", kv, "--version", "1", *P, home=h)
    run("secrets", "list", *P, home=h)
    run("secrets", "history", kv, *P, home=h)
    run("secrets", "export", *P, "--format", "dotenv", home=h)
    run("secrets", "export", *P, "--format", "json", home=h)
    run("run", *P, "--", "/bin/true", home=h)
    tc = run("token", "create", *P, "--access", "read", "--ttl", "30m", "--name", pfx.lower(), home=h, json=True)
    tok = tid = None
    try:
        d = tc.json()
        tok, tid = d.get("token"), d.get("id")
    except (ValueError, AttributeError):
        m = TOKEN_RE.search(tc.text())
        tok = m.group(0) if m else None
    if tok:
        c.secret(f"token:{pfx}", tok, "token")
        run("secrets", "get", kv, *P, env={"COFFER_TOKEN": tok})
    run("token", "list", home=h)
    if tid:
        run("token", "revoke", str(tid), home=h)
    run("secrets", "delete", ka, *P, home=h)
    run("secrets", "rollback", kv, "--to", "1", *P, home=h)
    pw = run("secrets", "set", f"{pfx}_PROT", "-p", "api", "-e", "prod", home=h, stdin=_rand(40).encode(),
             json=True)
    cid = None
    try:
        cid = pw.json().get("change_id")
    except (ValueError, AttributeError):
        pass
    run("change", "list", "--status", "pending", home=h)
    if cid:
        run("change", "reject", str(cid), home=h)
    run("audit", "list", "--limit", "5", home=h)
    run("audit", "verify", home=h)
    memail = f"x18-{_secrets.token_hex(4)}@acme.test"
    mpw0 = c.secret(f"pw0:{memail}", _rand(16), "password")
    mpw1 = c.secret(f"pw:{memail}", _rand(16), "password")
    run("member", "add", memail, "--role", "member", home=h, stdin=(mpw0 + "\n").encode())
    mh = c.scratch_home()
    run("login", "--email", memail, home=mh, stdin=(mpw0 + "\n").encode())
    run("passwd", home=mh, stdin=(mpw0 + "\n" + mpw1 + "\n").encode())
    run("logout", home=mh)
    root = c.actor("root")
    if root.home:
        oslug = f"x18-{_secrets.token_hex(3)}"
        opw = c.secret(f"pw0:owner@{oslug}", _rand(16), "password")
        run("admin", "org", "create", oslug, "--owner-email", f"owner@{oslug}.test", home=root.home,
            stdin=(opw + "\n").encode())
    run("logout", home=h)
    time.sleep(1.0)
    lines = cap_lines()
    mine = lines[start:]
    c.log("proxy capture: %d lines total, %d from this sequence", len(lines), len(mine))
    if not routed:
        return c.error(f"CLI get via COFFER_URL=proxy did not return the canary (rc={g.rc}); cannot judge")
    if not any(pfx in ln and "/secrets" in ln for ln in mine) or not any("/auth/token" in ln for ln in mine):
        return c.error("proxy capture lacks this sequence's /secrets or /auth/token requests (CLI bypassed proxy?)")
    c.control(lambda: g, what="CLI traffic captured by proxy")
    needles = sorted({(lab, v) for lab, v, _k in c._all_secrets() if v and len(v) >= 12},
                     key=lambda x: x[0])
    c.log("needles: %d", len(needles))
    url_bad = []
    for ln in lines:
        try:
            u = _json.loads(ln).get("url") or ""
        except (ValueError, AttributeError):
            u = ln
        hits = _url_hits(u, needles)
        if hits:
            url_bad.append((u, hits))
    for u, hits in url_bad[:20]:
        c.log("URL LEAK %s -> %s", c.redact(u)[:300], hits)
    c.expect(not url_bad, f"{len(url_bad)} captured URLs contain a secret/token: "
             + "; ".join(f"{c.redact(u)[:80]} [{','.join(h[:2])}]" for u, h in url_bad[:2])
             if url_bad else f"{len(lines)} captured URLs clean")
    # server request logs: current container + sweep cache
    blobs = [("server(current)", c.logs("server"))]
    sd = c.out / "sweep" / "logs"
    if sd.is_dir():
        for f in sorted(sd.glob("*server*.log")):
            try:
                blobs.append((f.name, f.read_bytes()))
            except OSError:
                pass
    nlines, log_url_bad, log_other_bad, seen_mine = 0, [], [], False
    for name, b in blobs:
        for ln in b.decode("utf-8", "replace").splitlines():
            nlines += 1
            if pfx in ln:
                seen_mine = True
            try:
                obj = _json.loads(ln[ln.index("{"):]) if "{" in ln else None
            except ValueError:
                obj = None
            urlish = []
            if isinstance(obj, (dict, list)):
                urlish = [s for k, s in _walk_strings(obj)
                          if any(t in k.lower() for t in ("path", "url", "uri", "route", "query", "target"))]
            uh = sorted({h for s in urlish for h in _url_hits(s, needles)})
            if uh:
                log_url_bad.append((name, uh))
                continue
            wh = _url_hits(ln, needles)
            if wh:
                log_other_bad.append((name, wh))
    c.log("server log lines scanned: %d (this sequence seen: %s)", nlines, seen_mine)
    # GRADER X18 greps the captured URLs AND the server's request logs. With no log lines the
    # second half never ran, so a pass would be partly vacuous: error (r1 had 0 lines).
    if nlines == 0:
        return c.error(f"server request logs unavailable (0 lines from container + sweep cache); "
                       f"URL half: {len(url_bad)} of {len(lines)} captured URLs leak")
    c.expect(not log_url_bad, f"{len(log_url_bad)} server log URL fields contain a secret/token: "
             + "; ".join(f"{n} {h[:2]}" for n, h in log_url_bad[:2]) if log_url_bad else "log URLs clean")
    c.expect(not log_other_bad, f"{len(log_other_bad)} server request log lines contain a secret/token: "
             + "; ".join(f"{n} {h[:2]}" for n, h in log_other_bad[:2]) if log_other_bad else "log lines clean")
    return c.done(f"{len(lines)} proxied URLs ({len(mine)} from this sequence) and {nlines} server log lines: "
                  f"no secret or token; {len(needles)} needles + token regex"
                  + ("" if seen_mine else "; note: sequence keys not seen in server logs"),
                  {"captured": len(lines), "mine": len(mine), "log_lines": nlines, "needles": len(needles)})


# --------------------------------------------------------------------------
# X11 error shape
# --------------------------------------------------------------------------

@check("X11")
def x11(c) -> Result:
    """Error shape {error:{code,message}}; no traces, paths or SQL in bodies"""
    own = "owner@acme"
    sp = "/api/v1/projects/api/envs/dev/secrets"
    jk = c.junk_key()
    JH = {"Content-Type": "application/json"}
    bodies = []
    ctl = c.api("GET", "/projects", actor=own)
    bodies.append(("control GET /projects", ctl.body))
    if not c.control(lambda: ctl, what="owner GET /projects"):
        return c.done()
    # (label, fn, strict, allowed-status-set or None for any 4xx)
    probes = [
        ("malformed JSON /auth/token", lambda: c.http("POST", "/api/v1/auth/token", body=b'{"email": "a@b.test", "password": ',
                                                    headers=JH), True, None),
        ("malformed JSON PUT secret", lambda: c.http("PUT", f"{sp}/{jk}", actor=own, body=b'{"value": ', headers=JH),
         True, None),
        ("empty JSON body /auth/token", lambda: c.http("POST", "/api/v1/auth/token", body=b"", headers=JH), True, None),
        ("JSON array /auth/token", lambda: c.api("POST", "/auth/token", json=[1, 2]), True, None),
        ("bad key 1ABC", lambda: c.http("PUT", f"{sp}/1ABC", actor=own, json={"value": "x"}), True, None),
        ("bad member body", lambda: c.api("POST", "/members", actor=own,
                                          json={"email": "not-an-email", "role": "emperor", "password": "x"}),
         True, None),
        ("absent project", lambda: c.http("GET", f"/api/v1/projects/{c.absent_slug()}/envs/dev/secrets", actor=own),
         True, (403, 404)),
        ("absent secret", lambda: c.http("GET", f"{sp}/ZZ_ABSENT_X11", actor=own), True, (404,)),
        ("unknown api route", lambda: c.http("GET", "/api/v1/zz-no-such-route", actor=own), True, (404,)),
        ("unknown root path", lambda: c.http("GET", "/zz-no-such-path"), True, (404,)),
        ("wrong method DELETE /me", lambda: c.api("DELETE", "/me", actor=own), True, (404, 405)),
        ("wrong method PATCH /projects", lambda: c.api("PATCH", "/projects", actor=own, json={}), True, (404, 405)),
        ("wrong method DELETE /audit", lambda: c.api("DELETE", "/audit", actor=own), True, (404, 405)),
        ("anon GET /projects", lambda: c.api("GET", "/projects"), True, (401,)),
        ("garbage bearer", lambda: c.api("GET", "/projects", headers={"Authorization": "Bearer cof_pat_zzzz"}),
         True, (401,)),
        ("audit limit=abc", lambda: c.api("GET", "/audit", actor=own, query={"limit": "abc"}), False, None),
        ("audit since=bad", lambda: c.api("GET", "/audit", actor=own, query={"since": "not-a-date"}), False, None),
        ("export format=xml", lambda: c.http("GET", "/api/v1/projects/api/envs/dev/export", actor=own,
                                             query={"format": "xml"}), False, None),
        ("text/plain login", lambda: c.http("POST", "/api/v1/auth/token", body=b'{"email":"a@b.test","password":"x"}',
                                            headers={"Content-Type": "text/plain"}), False, None),
        ("NUL in path", lambda: c.http("GET", "/api/v1/projects/%00/envs", actor=own, raw_path=True), False, None),
        ("version=abc", lambda: c.http("GET", f"{sp}/ZZ_ABSENT_X11/versions/abc", actor=own), False, None),
    ]
    seen = set()
    for label, fn, strict, allowed in probes:
        r = fn()
        bodies.append((label, r.body))
        st = r.status
        if st >= 500 or st == 0:
            c.expect(False, f"{label}: got {st}{' ' + r.error if r.error else ''}")
            continue
        if strict:
            if allowed is not None:
                c.expect(st in allowed, f"{label}: got {st} (want {'/'.join(map(str, allowed))})")
            else:
                c.expect(400 <= st < 500, f"{label}: got {st} (want 4xx)")
        if 400 <= st < 500:
            seen.add(st)
            ok, why = _shape(r.body)
            c.expect(ok, f"{label}: {st} body not {{error:{{code,message}}}} ({why})")
    # 413 via raw socket
    big = b'{"value":"' + b"A" * (2 * MIB) + b'"}'
    rr = _raw(c, "PUT", f"{sp}/{jk}", body=big, headers=JH, actor=own)
    bodies.append(("2MiB PUT", rr["body"]))
    if rr["status"] == 413:
        seen.add(413)
    c.expect(rr["status"] == 413, f"2 MiB PUT secret: got {rr['status']} (want 413)")
    if 400 <= rr["status"] < 500:
        ok, why = _shape(rr["body"])
        c.expect(ok, f"2 MiB PUT: {rr['status']} body not {{error:{{code,message}}}} ({why})")
    for want in (400, 404, 413):
        c.expect(want in seen, f"status {want} never elicited (seen {sorted(seen)})")
    for label, b in bodies:
        lk = _leaks((b or b"").decode("utf-8", "replace"))
        c.expect(not lk, f"{label}: body leaks {lk}: {c.redact((b or b'')[:120].decode('utf-8', 'replace'))}")
    return c.done(f"{len(probes) + 1} error probes: shape ok, statuses seen {sorted(seen)}; "
                  f"{len(bodies)} bodies free of traces/paths/SQL")


# --------------------------------------------------------------------------
# X12 body limit
# --------------------------------------------------------------------------

@check("X12")
def x12(c) -> Result:
    """2 MiB body -> 413 in < 1 s"""
    own = "owner@acme"
    sp = "/api/v1/projects/api/envs/dev/secrets"
    JH = {"Content-Type": "application/json"}
    jk, bk = c.junk_key(), c.junk_key()
    small = _json.dumps({"value": "ok"}).encode()
    cr = _raw(c, "PUT", f"{sp}/{jk}", body=small, headers=JH, actor=own)
    if not (200 <= cr["status"] < 300):
        return c.error(f"control PUT small body via raw socket -> {cr['status']}")
    c.control(lambda: c.http("GET", f"{sp}/{jk}", actor=own), what="small PUT stored and readable")
    big = b'{"value":"' + b"A" * (2 * MIB) + b'"}'
    r1 = _raw(c, "PUT", f"{sp}/{bk}", body=big, headers=JH, actor=own)
    c.expect(r1["status"] == 413, f"2 MiB PUT secret -> {r1['status']} (want 413)")
    c.expect(r1["ms"] < 1000, f"2 MiB PUT secret took {r1['ms']:.0f} ms (want < 1000)")
    r2 = _raw(c, "POST", "/api/v1/auth/token", body=b'{"email":"a@b.test","password":"' + b"A" * (2 * MIB) + b'"}',
              headers=JH)
    c.expect(r2["status"] == 413, f"2 MiB POST /auth/token -> {r2['status']} (want 413)")
    c.expect(r2["ms"] < 1000, f"2 MiB POST /auth/token took {r2['ms']:.0f} ms (want < 1000)")
    g = c.http("GET", f"{sp}/{bk}", actor=own)
    c.expect(g.status == 404, f"oversized key after 413: GET -> {g.status} (want 404, not stored)")
    r3 = _raw(c, "PUT", f"{sp}/{c.junk_key()}", body=big, headers=JH, actor=own, chunked=True)
    c.log("INFO chunked 2 MiB PUT -> %s in %.0f ms (not scored)", r3["status"], r3["ms"])
    if r3["status"] >= 500:
        c.expect(False, f"chunked 2 MiB PUT -> {r3['status']}")
    return c.done(f"2 MiB PUT -> 413 in {r1['ms']:.0f} ms; 2 MiB login -> 413 in {r2['ms']:.0f} ms; not stored",
                  {"put_ms": round(r1["ms"]), "login_ms": round(r2["ms"]), "chunked_status": r3["status"]})


# --------------------------------------------------------------------------
# X13 logout revokes the PAT
# --------------------------------------------------------------------------

def _tok_actor(label: str, tok: str) -> lib.Actor:
    return lib.Actor(label, "user", None, None, None, "acme", None, tok, None, None)


def _raw_login(c, a: lib.Actor, label: str, password: str | None = None) -> str | None:
    r = c.api("POST", "/auth/token", json={"email": a.email, "password": password or a.password})
    if r.status not in (200, 201):
        return None
    try:
        tok = r.json()["token"]
    except (ValueError, KeyError, TypeError):
        return None
    return c.secret(label, tok, "token")


@check("X13")
def x13(c) -> Result:
    """Logout revokes the PAT server-side (reuse -> 401)"""
    a = c.scratch_user("acme", "member")
    # (a) raw API
    tok = _raw_login(c, a, f"pat:{a.label}:x13a")
    if not tok:
        return c.error("raw login for scratch user failed")
    ta = _tok_actor("x13a", tok)
    if c.control(lambda: c.api("GET", "/me", actor=ta), what="fresh PAT GET /me"):
        lo = c.api("POST", "/auth/logout", actor=ta)
        c.expect(200 <= lo.status < 300, f"POST /auth/logout -> {lo.status} (want 2xx)")
        r = c.api("GET", "/me", actor=ta)
        c.expect(r.status == 401, f"API: PAT after logout GET /me -> {r.status} (want 401)")
        r2 = c.api("GET", "/projects", actor=ta)
        c.expect(r2.status == 401, f"API: PAT after logout GET /projects -> {r2.status} (want 401)")
    # (b) CLI logout; PAT read from the CLI's own config file
    h = c.scratch_home(a)
    found = None
    cfg = h / ".config" / "coffer"
    if cfg.is_dir():
        for p in sorted(cfg.rglob("*")):
            if p.is_file():
                m = TOKEN_RE.search(p.read_text(encoding="utf-8", errors="replace"))
                if m and m.group(0).startswith("cof_pat_"):
                    found = m.group(0)
                    break
    if not found:
        c.expect(False, f"CLI: no cof_pat_ token found in {cfg} after login")
        return c.done()
    c.secret(f"pat:{a.label}:cli", found, "token")
    tb = _tok_actor("x13cli", found)
    if c.control(lambda: c.api("GET", "/me", actor=tb), what="CLI PAT GET /me"):
        lo = c.cli("logout", home=h)
        c.expect(lo.rc == 0, f"coffer logout rc={lo.rc} (want 0)")
        r = c.api("GET", "/me", actor=tb)
        c.expect(r.status == 401, f"CLI: PAT after `coffer logout` GET /me -> {r.status} (want 401)")
    return c.done("API logout and `coffer logout` both revoke the PAT (reuse -> 401)")


# --------------------------------------------------------------------------
# X14 passwords never in argv
# --------------------------------------------------------------------------

def _spawn_watch(c, label: str, args: tuple, home: Path, password: str) -> dict:
    p = c.cli_spawn(*args, home=home, url=c.base_url)
    samples, seen_pid, leaks = 0, False, []

    def sample():
        nonlocal samples, seen_pid
        samples += 1
        for row in c.ps():
            if row["pid"] == p.pid:
                seen_pid = True
            if password in row["args"]:
                leaks.append(f"pid {row['pid']} user {row['user']}")
    for _ in range(6):
        sample()
        time.sleep(0.1)
    try:
        p.stdin.write((password + "\n").encode())
        p.stdin.flush()
        p.stdin.close()
    except OSError as e:
        c.log("%s: stdin write failed: %s", label, e)
    end = time.monotonic() + 45
    while p.poll() is None and time.monotonic() < end:
        sample()
        time.sleep(0.05)
    sample()
    if p.poll() is None:
        lib._killpg(p)
    try:
        out, err = p.communicate(timeout=10)
    except Exception:  # noqa: BLE001
        out, err = b"", b""
    c.log("%s: rc=%s samples=%d pid_seen=%s leaks=%s\n  out: %s\n  err: %s", label, p.returncode, samples,
          seen_pid, leaks[:3], c._body_for_log(out), c._body_for_log(err))
    return {"rc": p.returncode, "samples": samples, "seen": seen_pid, "leaks": leaks}


@check("X14")
def x14(c) -> Result:
    """Passwords never in argv (ps during login, member add, admin org create)"""
    runs = []
    a = c.scratch_user("acme", "member")
    runs.append(("login", ("login", "--email", a.email), c.scratch_home(), a.password))
    # Fresh homes logged in directly against base_url (r1 fix): the shared fixture homes hold a
    # login saved against the S5 proxy URL, and a CLI that binds its saved login to a URL then
    # refuses with rc=3 here, which measures the harness, not the build. Same for both builds.
    own = _owner(c)
    try:
        oh = c.scratch_home(own.label)
        rh = c.scratch_home("root")
    except lib.HarnessError as e:
        return c.error(f"precondition: fresh CLI login for owner/root failed: {e}")
    mpw = c.secret("pw0:x14-member", _rand(16), "password")
    runs.append(("member add", ("member", "add", f"x14-{_secrets.token_hex(4)}@acme.test", "--role", "member"),
                 oh, mpw))
    slug = f"x14-{_secrets.token_hex(3)}"
    opw = c.secret(f"pw0:owner@{slug}", _rand(16), "password")
    runs.append(("admin org create", ("admin", "org", "create", slug, "--owner-email", f"owner@{slug}.test"),
                 rh, opw))
    summary = []
    # Null-reference fix (VALIDATION.md N2): "seen in ps and exited 0" is not a positive control;
    # a CLI that never reads or sends the password passes it. Each run must also show its server-side
    # effect: the password piped on stdin logs in over the raw API (and a wrong one does not), and
    # for `login` the CLI rejects a wrong password.
    emails = {"login": a.email, "member add": runs[1][1][2], "admin org create": f"owner@{slug}.test"}
    for label, args, home, pw in runs:
        r = _spawn_watch(c, label, args, home, pw)
        summary.append(f"{label}: {r['samples']} ps samples, rc={r['rc']}")
        if not r["seen"]:
            c.error_once(f"control failed: {label} process never seen in ps")
            continue
        if r["rc"] != 0:
            c.error_once(f"control failed: {label} rc={r['rc']} (cannot judge argv while it fails)")
            continue
        why = _x14_effect(c, label, emails[label], pw)
        if why:
            c.error_once(f"control failed: {label}: {why}")
            continue
        c.control(lambda: lib.CliResult(0, b"", b"", 0.0, []),
                  what=f"{label} seen in ps, exited 0, stdin password effective on the server")
        c.expect(not r["leaks"], f"{label}: password visible in ps argv ({r['leaks'][0] if r['leaks'] else ''})")
    return c.done("password absent from ps argv: " + "; ".join(summary))


def _x14_effect(c, label: str, email: str, pw: str) -> str | None:
    """None if the stdin password demonstrably reached the server, else why not."""
    ok = c.api("POST", "/auth/token", json={"email": email, "password": pw})
    tok = None
    try:
        d = ok.json()
        tok = d.get("token") if isinstance(d, dict) else None
    except ValueError:
        pass
    if ok.status not in (200, 201) or not isinstance(tok, str) or not tok:
        return f"raw login with the stdin password -> {ok.status} (no token)"
    c.secret(f"pat:x14-{label}", tok, "token")
    bad = c.api("POST", "/auth/token", json={"email": email, "password": pw + "-wrong"})
    if bad.status not in (400, 401, 403):
        return f"raw login with a WRONG password -> {bad.status} (want 401: server not checking passwords)"
    if label == "login":
        h = c.scratch_home()
        w = c.cli("login", "--email", email, home=h, stdin=(pw + "-wrong\n").encode())
        if w.rc == 0:
            return "coffer login with a WRONG password exited 0 (CLI not sending the password)"
    return None


# --------------------------------------------------------------------------
# X19 audit rows immutable for the server's DB role
# --------------------------------------------------------------------------

def _qi(s: str) -> str:
    return '"' + s.replace('"', '""') + '"'


@check("X19")
def x19(c) -> Result:
    """(P1) Audit rows: UPDATE/DELETE as the server's DB role -> permission denied"""
    role = c.server_db_role()
    if not role:
        return c.error("server DB role not found in pg_stat_activity")
    sup = c.psql(f"SELECT rolsuper FROM pg_roles WHERE rolname = '{role.replace(chr(39), chr(39) * 2)}';")
    is_super = bool(sup.rows) and sup.rows[0][0] in ("t", "true")
    c.log("server DB role: %s superuser=%s", role, is_super)
    who = c.psql("SELECT current_user;", user=role)
    if who.rc != 0:
        return c.error(f"cannot connect as server role {role}: {who.err.strip()[:150]}")
    # r4: only tables holding audit EVENT rows (prev-hash + hash columns, the A5/A6 detector).
    # Other audit-named tables (e.g. a chain-head pointer the server must update) are info.
    try:
        tables = c.audit_event_tables()
    except lib.HarnessError:
        return c.error("audit table discovery failed")
    t = c.psql("SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
               "WHERE c.relkind = 'r' AND n.nspname NOT IN ('pg_catalog','information_schema') "
               "AND n.nspname NOT LIKE 'pg_toast%' AND c.relname ILIKE '%audit%' ORDER BY 1, 2;")
    other = [(r[0], r[1]) for r in t.rows if len(r) >= 2 and (r[0], r[1]) not in tables] if t.rc == 0 else []
    c.log("audit event tables: %s; other audit-named tables (info, not judged): %s", tables, other)
    if not tables:
        return c.error("no audit event table found (prev-hash + hash columns)")
    tested = 0
    for sch, tbl in tables:
        q = f"{_qi(sch)}.{_qi(tbl)}"
        col = c.psql(f"SELECT attname FROM pg_attribute WHERE attrelid = '{q}'::regclass AND attnum > 0 "
                     "AND NOT attisdropped AND attgenerated = '' AND attidentity <> 'a' ORDER BY attnum LIMIT 1;")
        row = c.psql(f"SELECT ctid::text FROM {q} LIMIT 1;")
        if col.rc != 0 or row.rc != 0 or not col.rows or not row.rows:
            c.log("skip %s: no usable column or no rows", q)
            continue
        cn, ctid = _qi(col.rows[0][0]), row.rows[0][0]
        tested += 1
        c.control(lambda: lib.CliResult(0, b"", b"", 0.0, []), what=f"real row {ctid} exists in {q}")
        for verb, stmt in (("UPDATE", f"UPDATE {q} SET {cn} = {cn} WHERE ctid = '{ctid}'::tid RETURNING 1"),
                           ("DELETE", f"DELETE FROM {q} WHERE ctid = '{ctid}'::tid RETURNING 1")):
            r = c.psql(f"BEGIN;\nWITH x AS ({stmt}) SELECT count(*) FROM x;\nROLLBACK;\n", user=role)
            err = r.err.strip().splitlines()
            if r.rc != 0 and "permission denied" in r.err.lower():
                c.expect(True, f"{verb} {tbl} as {role}: not permission denied",
                         f"{verb} {tbl} as {role}: permission denied")
            elif r.rc != 0:
                c.expect(False, f"{verb} {tbl} as {role}: error but not permission denied: {err[0][:120] if err else ''}")
            else:
                n = r.rows[0][0] if r.rows else "?"
                c.expect(False, f"{verb} {tbl} as {role} succeeded ({n} rows; rolled back)"
                         + (" [role is superuser]" if is_super else ""))
    if tested == 0:
        return c.error("no audit table with rows to target")
    return c.done(f"UPDATE/DELETE on {tested} audit tables as {role}: permission denied")


# --------------------------------------------------------------------------
# X20 password change revokes other PATs
# --------------------------------------------------------------------------

@check("X20")
def x20(c) -> Result:
    """(P1) Password change revokes the user's other PATs"""
    a = c.scratch_user("acme", "member")
    ta_tok = _raw_login(c, a, f"pat:{a.label}:x20a")
    tb_tok = _raw_login(c, a, f"pat:{a.label}:x20b")
    if not ta_tok or not tb_tok:
        return c.error("scratch user raw logins failed")
    ta, tb = _tok_actor("x20a", ta_tok), _tok_actor("x20b", tb_tok)
    if not c.control(lambda: c.api("GET", "/me", actor=ta), what="PAT A GET /me"):
        return c.done()
    if not c.control(lambda: c.api("GET", "/me", actor=tb), what="PAT B GET /me (before change)"):
        return c.done()
    new = c.secret(f"pw:{a.label}:x20", _rand(16), "password")
    pr = c.api("POST", "/auth/password", actor=ta, json={"current_password": a.password, "new_password": new})
    if not (200 <= pr.status < 300):
        return c.fail(f"POST /auth/password -> {pr.status} (password change not possible)")
    old = a.password
    a.password = new
    nl = c.api("POST", "/auth/token", json={"email": a.email, "password": new})
    c.expect(nl.status in (200, 201), f"login with new password -> {nl.status} (want 200)")
    try:
        if nl.status in (200, 201):
            c.secret(f"pat:{a.label}:x20new", nl.json()["token"], "token")
    except (ValueError, KeyError, TypeError):
        pass
    ol = c.api("POST", "/auth/token", json={"email": a.email, "password": old})
    c.log("login with old password -> %s (info)", ol.status)
    r = c.api("GET", "/me", actor=tb)
    c.expect(r.status == 401, f"other PAT B after password change GET /me -> {r.status} (want 401)")
    r2 = c.api("GET", "/projects", actor=tb)
    c.expect(r2.status == 401, f"other PAT B after password change GET /projects -> {r2.status} (want 401)")
    return c.done("password change revoked the user's other PAT (-> 401); new password logs in")
