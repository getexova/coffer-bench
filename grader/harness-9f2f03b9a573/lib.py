"""Coffer grading harness: lib.py, the helper library and the check context `c`.

Implements CONTRACT.md v1 §2-§4 (Context, Resp, CliResult, Actor, Psql, Proc,
Override, Sweep, Hit, HarnessError). Python 3.14 standard library only.
Black-box: nothing here reads build source. Every behaviour is identical for
both builds; the only build-dependent input is setup.json["cli"]["json_position"].

Contract readings (where CONTRACT.md is ambiguous, simplest reading, same for both builds):
L1  HTTP: a subclass of http.client.HTTPConnection encodes the request line as UTF-8
    (homoglyph paths would otherwise raise UnicodeEncodeError) and skips path
    validation when raw_path=True. Non-raw paths are urllib.parse.quote'd with a wide
    safe set (existing %XX escapes, '/', '?', '=', '&' etc. are kept). A header whose
    value is None removes that header. POST/PUT/PATCH with no body send
    Content-Length: 0. Transport errors (and a client-side refusal to send an illegal
    header) return Resp(status=0, error=...). Header values that are not latin-1 are
    sent as UTF-8 bytes.
L2  Redaction: registered values are replaced longest-first; values shorter than 6
    chars are not redacted (they would shred the log). Each value is also redacted in
    its JSON-escaped form. Bodies are redacted first, then truncated (bodies > 2048
    bytes -> first 512 bytes + "…[sha256=<hex of ORIGINAL bytes> len=<n>]").
L3  psql uses -A -t -F '\\x1f' -R '\\x1e' -P null=<sentinel>, so NULL (-> None) and ''
    differ and multi-line fields survive. db_conn parses .env with simple KEY=VALUE
    (optional `export `, surrounding quotes stripped, # comments skipped).
L4  Secrets are persisted by appending to OUT/secrets.jsonl (0600) so they survive
    across check subprocesses; Context loads that file plus fixture.json values.
    kind is inferred from the label: contains "canary" -> canary; starts with "pw"
    or contains "pass" -> password; contains "key" (not "token") -> key; else token.
    `secret(label, value, kind=None)` accepts an explicit kind as an extension.
L5  Actors: a fixture user's bearer is fixture.json users[label].pat; label "root"
    is fixture.json users["root"] (fixture R2). A token label resolves from
    fixture.json tokens. Scratch actors are kept in memory (per check process) and
    their labels are "<id>-<n>@<org>" / "tok:<id>-<n>".
L6  c.cli: when the actor has no home (scratch user, token) COFFER_TOKEN is set to
    its secret and HOME is fresh; when it has a home (fixture user, or scratch actor
    after scratch_home(actor)) that home is used and COFFER_TOKEN is not set. The CLI
    output is not parsed for 5xx (CONTRACT §3.3 "does not try to parse that").
    A timeout kills the child's process group and returns rc 124.
L7  wait_ready() polling is not logged per request and its 503s do NOT go to
    c.saw_5xx (a starting server answering 503 on /readyz is not a build 5xx).
    Only the final outcome is logged.
L8  logs(service) uses the engine (`podman|docker logs`) on the current container id
    (stdout+stderr merged in order); `since` is a unix time passed as --since.
L9  server_db_role(): with several non-superuser client roles, the alphabetically
    first is returned and the rest are logged.
L10 env_override: the base .env is WORK/ckpt/<ID>/env when it exists, else
    WORK/base.env. If compose itself fails, no readiness wait is done (ready=False).
    Raises HarnessError when called from a non-destructive row.
L11 compose(): verbs down/up/rm/restart/stop/kill/create/start trigger an automatic
    sweep_snapshot first ("start" excluded: it cannot remove a container; "up"
    included because it may recreate).
L12 same_404 also accepts CliResult: absent must be rc 5, probe rc 5 with equal
    masked stderr. denied() with CliResult: rc 0 and rc 1 are always failures.
L13 sweep homes: every dir under WORK/homes/ and every WORK/tmp/*/home-* dir
    (scratch_home and fresh CLI homes) is copied whole into sweep/homes/<label>/.
L14 Sweep log files: each snapshot rewrites logs/<container_id>-<service>.log with the
    full current log of that container (a superset of earlier content), so nothing is
    lost and nothing is duplicated; a container that disappeared keeps its file.
L15 wipe_volumes removes only in-repo bind-mount source dirs that contain no
    git-tracked file (discovered from `inspect` of the containers before `down -v`).
L16 (r4) Saved CLI logins are URL-bound. Every successful `coffer login` run through
    c.cli records (WORK/homebind/<hash>, outside the home) the COFFER_URL it used. When
    a check drives an actor's OWN home against another URL (fixture homes are made in
    proxied F1; most rows use base_url), c.cli logs that actor in once into a sibling
    home `<home>~base|proxy|u<hash>` for that URL and uses it. A home= that is not the
    actor's own home (e.g. X18's root.home with no actor), and COFFER_TOKEN runs, are untouched. Fixture homes with no record count as proxy-bound.
L17 (r4) Setup logins (scratch_user / scratch_org) back off on 429 (Retry-After or
    exponential, up to 20 min in total) so a source limiter tripped by an earlier row
    (X7/X8) cannot fail setup. The login gate passes wait429=False to see the 429.
L18 (r4) audit_all(): SPEC sets no audit page maximum, and a build may cap `limit`
    (400 above its max) or truncate silently. Pages with limit=1000 and a seq cursor
    (`before`/`until`/`since` probed) and falls back to one page; `complete` is False
    when the result may be truncated (length equals a cap and no cursor advanced).
L19 (r4) expect(cond, msg, ok_msg=None): an ok line prints ok_msg, else "not(" msg ")"
    so ok lines never read as the failure wording.
"""
from __future__ import annotations

import base64
import concurrent.futures
import dataclasses
import datetime as _dt
import gzip
import hashlib
import http.client
import json as _json
import os
import re
import secrets as _secrets
import shutil
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Optional

import registry
from registry import Result


class HarnessError(RuntimeError):
    """The harness could not do what a check asked (runner records `error`)."""


class _Missing:
    def __repr__(self) -> str:
        return "MISSING"


MISSING = _Missing()

_NULL = "\x02NULL\x02"
_FS = "\x1f"
_RS = "\x1e"
LOG_BODY_MAX = 2048
LOG_BODY_HEAD = 512
REDACT_MIN = 6
SNAP_VERBS = {"down", "up", "rm", "restart", "stop", "kill", "create"}


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(t: Optional[_dt.datetime] = None) -> str:
    return (t or _utcnow()).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _read_json(p: Path, default):
    try:
        return _json.loads(Path(p).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json_atomic(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".tmp{os.getpid()}")
    tmp.write_text(_json.dumps(obj, indent=1, default=str), encoding="utf-8")
    os.replace(tmp, p)


def _kind_of(label: str) -> str:
    lo = label.lower()
    if "canary" in lo or "multi" in lo:
        return "canary"
    if lo.startswith("pw") or "pass" in lo:
        return "password"
    if "key" in lo and "token" not in lo:
        return "key"
    return "token"


# --------------------------------------------------------------------------
# records
# --------------------------------------------------------------------------

@dataclasses.dataclass
class Resp:
    status: int
    headers: dict
    body: bytes
    ms: float
    url: str
    error: Optional[str] = None

    def json(self) -> Any:
        return _json.loads(self.body)

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def ok(self) -> bool:
        return 200 <= self.status < 300


@dataclasses.dataclass
class CliResult:
    rc: int
    out: bytes
    err: bytes
    ms: float
    argv: list
    # r5: where the run happened, so a denial helper can re-run `whoami` in the same session
    home: str = ""
    url: str = ""
    env: dict = dataclasses.field(default_factory=dict, repr=False, compare=False)

    def json(self) -> Any:
        s = self.out.decode("utf-8")
        dec = _json.JSONDecoder()
        obj, end = dec.raw_decode(s.lstrip())
        if s.lstrip()[end:].strip():
            raise ValueError("more than one JSON document on stdout")
        return obj

    def text(self) -> str:
        return self.out.decode("utf-8", "replace")


@dataclasses.dataclass
class Actor:
    label: str
    kind: str
    email: Optional[str] = None
    password: Optional[str] = None
    user_id: Optional[str] = None
    org: Optional[str] = None
    role: Optional[str] = None
    secret: Optional[str] = None
    token_id: Optional[str] = None
    home: Optional[Path] = None


@dataclasses.dataclass
class Psql:
    rc: int
    out: str
    err: str
    rows: list


@dataclasses.dataclass
class Proc:
    rc: int
    out: bytes
    err: bytes
    ms: float


@dataclasses.dataclass
class Override:
    compose_rc: int
    compose_err: bytes
    ready: bool
    running: bool
    exit_code: Optional[int]
    restarts: int
    logs: bytes
    # r2 (G3): evidence that the override really recreated the server container
    cid_before: Optional[str] = None
    cid_after: Optional[str] = None
    started_before: Optional[str] = None
    started_after: Optional[str] = None
    status: Optional[str] = None
    compose_out: bytes = b""

    @property
    def recreated(self) -> bool:
        """True when a server container exists after the override and it is a new
        container or was (re)started after the pre-override one."""
        if not self.cid_after:
            return False
        if self.cid_before is None or self.cid_after != self.cid_before:
            return True
        return bool(self.started_after and self.started_after != self.started_before)


@dataclasses.dataclass
class Hit:
    source: str
    file: str
    label: str
    kind: str
    encoding: str
    offset: int


# --------------------------------------------------------------------------
# low-level process runner
# --------------------------------------------------------------------------

def _run(argv, *, cwd=None, env=None, stdin: bytes | None = b"", timeout: float = 300.0,
         stdout_path: Path | None = None) -> Proc:
    t0 = time.monotonic()
    out_f = None
    try:
        if stdout_path is not None:
            Path(stdout_path).parent.mkdir(parents=True, exist_ok=True)
            out_f = open(stdout_path, "wb")
        try:
            p = subprocess.Popen(list(argv), cwd=str(cwd) if cwd else None, env=env,
                                 stdin=subprocess.PIPE,
                                 stdout=out_f if out_f is not None else subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
        except OSError as e:
            return Proc(127, b"", f"{type(e).__name__}: {e}".encode(), (time.monotonic() - t0) * 1000)
        try:
            out, err = p.communicate(stdin or b"", timeout=timeout)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            _killpg(p)
            try:
                out, err = p.communicate(timeout=10)
            except Exception:
                out, err = b"", b""
            rc = 124
        return Proc(rc, out or b"", err or b"", (time.monotonic() - t0) * 1000)
    finally:
        if out_f is not None:
            out_f.close()


def _killpg(p: subprocess.Popen) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(p.pid, sig)
        except OSError:
            return
        try:
            p.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue


# --------------------------------------------------------------------------
# HTTP connection that can send any request line
# --------------------------------------------------------------------------

class _Conn(http.client.HTTPConnection):
    raw = False

    def _encode_request(self, request):  # request line as UTF-8, not ASCII
        return request.encode("utf-8", "surrogateescape")

    def _validate_path(self, url):
        if not self.raw:
            super()._validate_path(url)


_SAFE = "/?=&%:@!$'()*+,;~-._[]"


# --------------------------------------------------------------------------
# the sweep
# --------------------------------------------------------------------------

class Sweep:
    def __init__(self, ctx: "Context"):
        self.c = ctx
        self.root = ctx.out / "sweep"

    def needles(self, kinds=("canary", "token", "password")) -> list:
        seen = set()
        res = []
        for label, value, kind in self.c._all_secrets():
            if kind in kinds and value and (value, kind) not in seen:
                seen.add((value, kind))
                res.append((label, kind, value))
        return res

    def files(self, source: str) -> list:
        d = self.root / source
        if not d.exists():
            return []
        return sorted(p for p in d.rglob("*") if p.is_file())

    def _scan_bytes(self, data: bytes, needles, source, fname, hits, enc_list, suffix=""):
        for label, kind, value in needles:
            raw = value.encode("utf-8")
            if len(raw) < 12:
                continue
            forms = {"raw": raw, "hex": raw.hex().encode(), "HEX": raw.hex().upper().encode(),
                     "b64": base64.b64encode(raw)}
            for enc in enc_list:
                f = forms.get(enc)
                if f is None:
                    continue
                off = data.find(f)
                if off >= 0:
                    hits.append(Hit(source, fname + suffix, label, kind, enc, off))

    def scan(self, sources=("dumps", "logs", "backups", "homes"),
             kinds=("canary", "token", "password"), *, encodings=("raw", "hex", "HEX", "b64")) -> list:
        needles = self.needles(kinds)
        hits: list = []
        for src in sources:
            for p in self.files(src):
                try:
                    data = p.read_bytes()
                except OSError as e:
                    self.c.log("sweep: cannot read %s: %s", p, e)
                    continue
                rel = str(p.relative_to(self.root))
                self._scan_bytes(data, needles, src, rel, hits, encodings)
                if src == "backups":
                    layers = [(data, "")]
                    if data[:2] == b"\x1f\x8b":
                        try:
                            gz = gzip.decompress(data)
                            self._scan_bytes(gz, needles, src, rel, hits, encodings, "!gunzip")
                            layers.append((gz, "!gunzip"))
                        except Exception as e:  # noqa: BLE001
                            self.c.log("sweep: gunzip %s failed: %s", rel, e)
                    for blob, suf in layers:
                        if blob[:5] == b"PGDMP":
                            self._scan_bytes(self.c._pg_restore_text(blob), needles, src, rel, hits,
                                             encodings, suf + "!pg_restore")
        self.c.log("sweep.scan sources=%s kinds=%s needles=%d hits=%d", sources, kinds,
                   len(needles), len(hits))
        return hits


# --------------------------------------------------------------------------
# the context
# --------------------------------------------------------------------------

# ---------------- container discovery (shared with run.py / fixture.py) ----------------

def _label_dict(it: dict) -> dict:
    labels = it.get("Labels")
    if isinstance(labels, dict):
        return labels
    out = {}
    if isinstance(labels, str):
        for part in labels.split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def _engine_items(engine: str) -> list:
    p = _run([engine, "ps", "-a", "--no-trunc", "--format", "json"], timeout=60)
    if p.rc != 0:
        return []
    txt = p.out.decode("utf-8", "replace").strip()
    items: list = []
    try:
        v = _json.loads(txt) if txt else []
        items = v if isinstance(v, list) else [v]
    except ValueError:
        for line in txt.splitlines():
            try:
                items.append(_json.loads(line))
            except ValueError:
                pass
    return [i for i in items if isinstance(i, dict)]


def _names(it: dict) -> list:
    n = it.get("Names") or it.get("Name") or []
    if isinstance(n, str):
        n = [x.strip() for x in n.split(",")]
    return [str(x).lstrip("/") for x in n]


def discover_containers(engine: str, repo: Path, prefix=None) -> list:
    """[(id, service, item)] of the compose project rooted at `repo` (any state).
    Matches on compose labels: working_dir == repo, else project == basename(repo)
    (podman-compose and docker compose both default the project to the dir name),
    else the container name <project>_<svc>_N / <project>-<svc>-N."""
    repo = Path(repo).resolve()
    proj = re.sub(r"[^a-z0-9_-]", "", repo.name.lower())
    res = []
    for it in _engine_items(engine):
        lab = _label_dict(it)
        wd = lab.get("com.docker.compose.project.working_dir") or lab.get("io.podman.compose.working_dir") or ""
        pj = lab.get("com.docker.compose.project") or lab.get("io.podman.compose.project") or ""
        svc = lab.get("com.docker.compose.service") or lab.get("io.podman.compose.service") or ""
        mine = False
        if wd:
            try:
                mine = Path(wd).resolve() == repo
            except OSError:
                mine = False
        if not mine and pj and pj == proj:
            mine = True
        if not lab or (not svc and not pj and not wd):
            for nm in _names(it):
                m = re.match(rf"^{re.escape(proj)}[_-]([A-Za-z0-9.-]+?)[_-]\d+$", nm)
                if m:
                    mine = True
                    svc = svc or m.group(1)
        cid = it.get("Id") or it.get("ID") or it.get("id")
        if mine and cid:
            res.append((str(cid), svc or "unknown", it))
    return res


def discovery_diag(engine: str, repo: Path, prefix=None) -> str:
    """Short diagnostic for a failed discovery: compose ps output + engine ps names/labels."""
    parts = []
    if prefix:
        p = _run(list(prefix) + ["ps"], cwd=repo, timeout=60)
        parts.append(f"compose ps rc={p.rc} out={p.out.decode('utf-8','replace')[-600:]!r} "
                     f"err={p.err.decode('utf-8','replace')[-400:]!r}")
    proj = re.sub(r"[^a-z0-9_-]", "", Path(repo).resolve().name.lower())
    items = _engine_items(engine)
    near = [i for i in items if any(proj in n for n in _names(i))]
    parts.append(f"{engine} ps -a: {len(items)} containers; named like {proj!r}: " + "; ".join(
        f"{_names(i)} {i.get('State')} labels={sorted(_label_dict(i))[:6]}" for i in near[:6]))
    return " | ".join(parts)



class Context:
    def __init__(self, row: registry.Row, work: Path, out: Path):
        self.row = row
        self.id = row.id
        self.work = Path(work)
        self.out = Path(out)
        self.repo = self.work / "repo"
        self.tmp = self.work / "tmp" / self.id
        self.tmp.mkdir(parents=True, exist_ok=True)
        (self.out / "logs").mkdir(parents=True, exist_ok=True)
        self._logpath = self.out / "logs" / f"{self.id}.log"
        self._lock = threading.RLock()
        self.setup = _read_json(self.out / "setup.json", {}) or {}
        self.fx = _read_json(self.out / "fixture.json", {}) or {}
        self.state = _read_json(self.out / "state.json", {}) or {}
        port = self.setup.get("port") or self._env_file(self.repo / ".env").get("COFFER_PORT") or "8420"
        self.base_url = self.setup.get("base_url") or f"http://127.0.0.1:{port}"
        self.proxy_url = self.setup.get("proxy_url") or None
        self.controls = 0
        self.saw_5xx: list = []
        self._expects: list = []      # (ok, msg)
        self._error: Optional[str] = None
        self._mem_secrets: dict = {}  # value -> (label, kind)
        self._redact_list: list = []  # [(value, label)] longest first
        self._actors: dict = {}
        self._n = 0
        self._in_probe = False
        self._load_secrets()

    # ---------------- secrets / redaction ----------------

    def _load_secrets(self) -> None:
        p = self.out / "secrets.jsonl"
        try:
            for line in p.read_text(encoding="utf-8").splitlines():
                try:
                    d = _json.loads(line)
                except ValueError:
                    continue
                if d.get("value"):
                    self._mem_secrets.setdefault(d["value"], (d.get("label", "?"), d.get("kind", "token")))
        except OSError:
            pass
        for label, v, kind in self._fixture_secrets():
            self._mem_secrets.setdefault(v, (label, kind))
        self._rebuild_redact()

    def _fixture_secrets(self):
        fx = self.fx or {}
        for lab, u in (fx.get("users") or {}).items():
            for k, kind in (("password", "password"), ("initial_password", "password"), ("pat", "token")):
                v = (u or {}).get(k)
                if v:
                    yield (f"{'pw' if kind == 'password' else 'pat'}:{lab}", v, kind)
        for lab, t in (fx.get("tokens") or {}).items():
            v = (t or {}).get("token")
            if v:
                yield (f"token:{lab}", v, "token")
        for path, v in (fx.get("canaries") or {}).items():
            if v:
                yield (f"canary:{path}", v, "canary")
        if fx.get("multi_core"):
            yield ("canary:multi_core", fx["multi_core"], "canary")

    def _all_secrets(self):
        with self._lock:
            return [(lab, v, kind) for v, (lab, kind) in self._mem_secrets.items()]

    def _rebuild_redact(self) -> None:
        pairs = []
        for v, (lab, _k) in self._mem_secrets.items():
            if len(v) < REDACT_MIN:
                continue
            pairs.append((v, lab))
            esc = _json.dumps(v, ensure_ascii=False)[1:-1]
            if esc != v:
                pairs.append((esc, lab))
            esc2 = _json.dumps(v)[1:-1]
            if esc2 not in (v, esc):
                pairs.append((esc2, lab))
        pairs.sort(key=lambda x: -len(x[0]))
        self._redact_list = pairs

    def secret(self, label: str, value: str, kind: Optional[str] = None) -> str:
        if not value:
            return value
        kind = kind or _kind_of(label)
        with self._lock:
            if value in self._mem_secrets:
                return value
            self._mem_secrets[value] = (label, kind)
            self._rebuild_redact()
            p = self.out / "secrets.jsonl"
            try:
                fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(_json.dumps({"label": label, "value": value, "kind": kind},
                                        ensure_ascii=False) + "\n")
                os.chmod(p, 0o600)
            except OSError:
                pass
        return value

    def redact(self, s) -> str:
        if not isinstance(s, str):
            s = s.decode("utf-8", "replace") if isinstance(s, (bytes, bytearray)) else str(s)
        for v, lab in self._redact_list:
            if v in s:
                s = s.replace(v, f"«{lab}»")
        return s

    def _redact_data(self, obj):
        if obj is None:
            return None
        try:
            return _json.loads(self.redact(_json.dumps(obj, ensure_ascii=False, default=str)))
        except ValueError:
            return {"redacted": self.redact(str(obj))[:2000]}

    def _body_for_log(self, b: bytes | None) -> str:
        if not b:
            return ""
        txt = self.redact(b.decode("utf-8", "replace"))
        if len(b) > LOG_BODY_MAX:
            return (txt[:LOG_BODY_HEAD] + f"…[sha256={hashlib.sha256(b).hexdigest()} len={len(b)}]")
        return txt

    # ---------------- log / result ----------------

    def log(self, msg: str, *args) -> None:
        try:
            text = (msg % args) if args else str(msg)
        except (TypeError, ValueError):
            text = " ".join([str(msg)] + [str(a) for a in args])
        line = f"{_iso()} {self.redact(text)}\n"
        with self._lock:
            with open(self._logpath, "a", encoding="utf-8") as f:
                f.write(line)

    def expect(self, cond: bool, msg: str, ok_msg: str | None = None) -> bool:
        cond = bool(cond)
        with self._lock:
            self._expects.append((cond, self.redact(msg)))
        if cond:
            self.log("ASSERT ok   %s", ok_msg if ok_msg is not None else f"not({msg})")
        else:
            self.log("ASSERT FAIL %s", msg)
        return cond

    def error_once(self, msg: str) -> None:
        with self._lock:
            if self._error is None:
                self._error = self.redact(msg)
        self.log("HARNESS ERROR: %s", msg)

    def _ev(self, s: str) -> str:
        return " ".join(self.redact(s).split())[:300]

    def ok(self, evidence: str = "", data=None) -> Result:
        return Result("pass", self._ev(evidence), self._redact_data(data))

    def fail(self, evidence: str, data=None) -> Result:
        return Result("fail", self._ev(evidence), self._redact_data(data))

    def error(self, evidence: str, data=None) -> Result:
        ev = evidence if str(evidence).startswith("error:") else f"error: {evidence}"
        return Result("error", self._ev(ev), self._redact_data(data))

    def na(self, evidence: str) -> Result:
        return Result("na", self._ev(evidence))

    def done(self, pass_evidence: str = "", data=None) -> Result:
        with self._lock:
            err = self._error
            fails = [m for ok, m in self._expects if not ok]
            n = len(self._expects)
        if err is not None:
            return self.error(err, data)
        if fails:
            ev = "; ".join(fails[:3]) + (f" (+{len(fails) - 3} more)" if len(fails) > 3 else "")
            return self.fail(ev, data)
        if n == 0 and self.controls == 0:
            return self.error("no assertions", data)
        return self.ok(pass_evidence or f"{n} assertions ok", data)

    # ---------------- state ----------------

    def put(self, key: str, value) -> None:
        _json.dumps(value)  # must be JSON-serializable
        self.state[f"{self.id}.{key}"] = value
        self.save_state()

    def get(self, key: str, default=None):
        return self.state.get(key, default)

    def save_state(self) -> None:
        _write_json_atomic(self.out / "state.json", self.state)

    # ---------------- small helpers ----------------

    def now(self) -> _dt.datetime:
        return _utcnow()

    def _next(self) -> int:
        with self._lock:
            self._n += 1
            return self._n

    def _uniq(self) -> str:
        return f"{self.id.lower()}-{self._next()}{_secrets.token_hex(2)}"

    def junk_key(self) -> str:
        return f"JUNK_{self.id}_{self._next()}"

    def absent_slug(self) -> str:
        return f"zz-absent-{_secrets.token_hex(4)}"

    def absent_id(self) -> str:
        return _secrets.token_hex(16)

    @staticmethod
    def exit_for(status: int) -> int:
        return {200: 0, 201: 0, 202: 7, 400: 6, 413: 6, 422: 6, 401: 3, 403: 4,
                404: 5, 409: 8, 429: 10}.get(int(status), 1)

    def wait_until(self, pred: Callable[[], bool], timeout: float, every: float = 0.25) -> bool:
        end = time.monotonic() + timeout
        while True:
            try:
                if pred():
                    return True
            except Exception as e:
                self.log("wait_until predicate raised %s: %s", type(e).__name__, e)
            if time.monotonic() >= end:
                return False
            time.sleep(every)

    def parallel(self, fns: list, workers: int = 20) -> list:
        def wrap(fn):
            try:
                return fn()
            except Exception as e:  # noqa: BLE001
                return e
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            return list(ex.map(wrap, fns))

    # ---------------- HTTP ----------------

    def http(self, method: str, path: str, *, actor="anon", json=MISSING, body: bytes | None = None,
             headers: dict | None = None, query: dict | None = None, timeout: float = 15.0,
             base: str | None = None, raw_path: bool = False, _quiet: bool = False) -> Resp:
        if json is not MISSING and body is not None:
            raise ValueError("pass json= or body=, not both")
        a = self.actor(actor) if actor is not None else self.actor("anon")
        base = base or self.base_url
        u = urllib.parse.urlsplit(base)
        host, port = u.hostname or "127.0.0.1", u.port or 80
        prefix = u.path.rstrip("/")
        if raw_path:
            target = prefix + path
        else:
            target = prefix + urllib.parse.quote(path, safe=_SAFE)
        if query:
            target += ("&" if "?" in target else "?") + urllib.parse.urlencode(query, doseq=True)
        hdrs: dict = {}
        payload = body
        if json is not MISSING:
            payload = _json.dumps(json, ensure_ascii=False).encode()
            hdrs["Content-Type"] = "application/json"
        if a.kind != "anon" and a.secret:
            hdrs["Authorization"] = f"Bearer {a.secret}"
        if payload is not None or method.upper() in ("POST", "PUT", "PATCH"):
            hdrs["Content-Length"] = str(len(payload or b""))
        hdrs["Host"] = f"{host}:{port}"
        hdrs["Connection"] = "close"
        for k, v in (headers or {}).items():
            for existing in [h for h in hdrs if h.lower() == k.lower()]:
                del hdrs[existing]
            if v is not None:
                hdrs[k] = v
        url = f"{u.scheme or 'http'}://{host}:{port}{target}"
        t0 = time.monotonic()
        status, rh, rb, err = 0, {}, b"", None
        conn = _Conn(host, port, timeout=timeout)
        conn.raw = raw_path
        try:
            conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            for k, v in hdrs.items():
                if isinstance(v, str):
                    try:
                        v.encode("latin-1")
                    except UnicodeEncodeError:
                        v = v.encode("utf-8")
                conn.putheader(k, v)
            conn.endheaders(payload if payload else None)
            r = conn.getresponse()
            rb = r.read()
            status = r.status
            for k, v in r.getheaders():
                k = k.lower()
                rh[k] = f"{rh[k]}, {v}" if k in rh else v
        except (OSError, http.client.HTTPException, ValueError, socket.timeout) as e:
            status, err = 0, f"{type(e).__name__}: {e}"
        finally:
            try:
                conn.close()
            except Exception:
                pass
        ms = (time.monotonic() - t0) * 1000
        resp = Resp(status, rh, rb, ms, url, err)
        if status >= 500 and not _quiet:
            with self._lock:
                self.saw_5xx.append(f"{method} {path} -> {status}")
        if not _quiet:
            self.log("HTTP %s %s actor=%s -> %s %.0fms%s\n  req: %s\n  resp: %s", method, path, a.label,
                     status, ms, f" err={err}" if err else "", self._body_for_log(payload),
                     self._body_for_log(rb))
        return resp

    def api(self, method: str, path: str, **kw) -> Resp:
        return self.http(method, "/api/v1" + path, **kw)

    # ---------------- actors ----------------

    def actor(self, label_or_actor) -> Actor:
        if isinstance(label_or_actor, Actor):
            return label_or_actor
        lab = str(label_or_actor)
        if lab == "anon":
            return Actor("anon", "anon")
        if lab in self._actors:
            return self._actors[lab]
        users = (self.fx or {}).get("users") or {}
        if lab in users:
            u = users[lab] or {}
            email = u.get("email") or ("root@bench.test" if lab == "root" else lab + ".test")
            a = Actor(lab, "user", email, u.get("password"), u.get("user_id"),
                      u.get("org") or (None if lab == "root" else lab.split("@")[-1]),
                      u.get("role") or ("platform_admin" if lab == "root" else None),
                      u.get("pat"), None, Path(u["home"]) if u.get("home") else None)
            return a
        toks = (self.fx or {}).get("tokens") or {}
        if lab in toks:
            t = toks[lab] or {}
            return Actor(lab, "token", None, None, None, t.get("org") or "acme", None,
                         t.get("token"), t.get("id"), None)
        raise KeyError(f"unknown actor {lab!r}")

    def _org_owner(self, org: str) -> Actor:
        return self.actor(f"owner@{org}")

    def _pw(self) -> str:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
        return "".join(_secrets.choice(alphabet) for _ in range(16))

    def _login_raw(self, a: Actor, wait429: bool = True) -> None:
        r = self.api("POST", "/auth/token", json={"email": a.email, "password": a.password})
        waited, delay = 0.0, 5.0
        while r.status == 429 and wait429 and waited < 1200.0:
            ra = None
            try:
                ra = float((r.headers or {}).get("retry-after") or "")
            except ValueError:
                pass
            d = min(max(delay, ra or 0.0), 120.0, 1200.0 - waited)
            self.log("scratch login %s -> 429; backoff %.0fs (waited %.0fs)", a.label, d, waited)
            time.sleep(d)
            waited += d
            delay = min(delay * 2, 60.0)
            r = self.api("POST", "/auth/token", json={"email": a.email, "password": a.password})
        if r.status != 200 and r.status != 201:
            raise HarnessError(f"scratch login {a.label} -> {r.status}")
        try:
            d = r.json()
            tok = d["token"]
        except (ValueError, KeyError, TypeError):
            raise HarnessError(f"scratch login {a.label}: no token in response")
        a.secret = self.secret(f"pat:{a.label}", tok, "token")
        if not a.user_id:
            try:
                a.user_id = str((d.get("user") or {}).get("id") or "") or None
            except AttributeError:
                pass

    def _ensure_usable(self, a: Actor) -> None:
        """If the fresh account must change its password first, do it and log in again."""
        r = self.api("GET", "/projects", actor=a)
        if r.status in (200, 201):
            return
        if r.status in (401, 403, 409, 428):
            new = self.secret(f"pw:{a.label}", self._pw(), "password")
            pr = self.api("POST", "/auth/password", actor=a,
                          json={"current_password": a.password, "new_password": new})
            if pr.status in (200, 201, 204):
                a.password = new
                self._login_raw(a)
                return
            self.log("scratch %s: password change -> %s (continuing)", a.label, pr.status)

    def scratch_user(self, org: str, role: str = "member", *, grants: dict | None = None,
                     label: str | None = None, wait429: bool = True) -> Actor:
        owner = self._org_owner(org)
        local = self._uniq()
        email = f"{local}@{org}.test"
        lab = label or f"{local}@{org}"
        pw = self.secret(f"pw0:{lab}", self._pw(), "password")
        r = self.api("POST", "/members", actor=owner, json={"email": email, "role": role, "password": pw})
        if r.status not in (200, 201):
            raise HarnessError(f"scratch_user POST /members -> {r.status}")
        uid = None
        try:
            d = r.json()
            uid = d.get("id") or d.get("user_id") or (d.get("user") or {}).get("id")
        except (ValueError, AttributeError):
            pass
        if not uid:
            lr = self.api("GET", "/members", actor=owner)
            try:
                lst = lr.json()
                lst = lst.get("items", lst.get("members", lst)) if isinstance(lst, dict) else lst
                for m in lst or []:
                    if (m.get("email") or "").lower() == email:
                        uid = m.get("id") or m.get("user_id")
            except (ValueError, AttributeError):
                pass
        if not uid:
            raise HarnessError("scratch_user: no user id")
        a = Actor(lab, "user", email, pw, str(uid), org, role, None, None, None)
        for proj, level in (grants or {}).items():
            gr = self.api("PUT", f"/members/{uid}/grants/{proj}", actor=owner, json={"level": level})
            if gr.status not in (200, 201, 204):
                raise HarnessError(f"scratch_user grant {proj}={level} -> {gr.status}")
        self._login_raw(a, wait429)
        self._ensure_usable(a)
        self._actors[lab] = a
        return a

    def scratch_org(self, slug: str | None = None, wait429: bool = True) -> tuple:
        root = self.actor("root")
        slug = slug or self._uniq()
        email = f"owner-{slug}@{slug}.test"
        lab = f"owner@{slug}"
        pw = self.secret(f"pw0:{lab}", self._pw(), "password")
        r = self.api("POST", "/admin/orgs", actor=root,
                     json={"slug": slug, "owner_email": email, "owner_password": pw})
        if r.status not in (200, 201):
            raise HarnessError(f"scratch_org POST /admin/orgs -> {r.status}")
        a = Actor(lab, "user", email, pw, None, slug, "owner", None, None, None)
        self._login_raw(a, wait429)
        self._ensure_usable(a)
        self._actors[lab] = a
        return slug, a

    def scratch_project(self, actor="owner@acme", *, envs=(("dev", False),), slug=None) -> str:
        a = self.actor(actor)
        slug = slug or self._uniq()
        r = self.api("POST", "/projects", actor=a, json={"slug": slug})
        if r.status not in (200, 201):
            raise HarnessError(f"scratch_project POST /projects -> {r.status}")
        for e, prot in envs:
            er = self.api("POST", f"/projects/{slug}/envs", actor=a, json={"slug": e, "protected": bool(prot)})
            if er.status not in (200, 201):
                raise HarnessError(f"scratch_project POST envs {e} -> {er.status}")
        return slug

    def scratch_token(self, project: str, env: str, access: str, ttl_seconds: int = 3600,
                      *, actor="owner@acme", org: str = "acme") -> Actor:
        a = self.actor(actor)
        n = self._uniq()
        r = self.api("POST", "/tokens", actor=a, json={"project": project, "env": env, "access": access,
                                                       "ttl_seconds": int(ttl_seconds), "name": n})
        if r.status not in (200, 201):
            raise HarnessError(f"scratch_token POST /tokens -> {r.status}")
        try:
            d = r.json()
            tok, tid = d["token"], d.get("id")
        except (ValueError, KeyError, TypeError):
            raise HarnessError("scratch_token: no token in response")
        lab = f"tok:{n}"
        self.secret(f"token:{lab}", tok, "token")
        t = Actor(lab, "token", None, None, None, org, None, tok, str(tid) if tid is not None else None, None)
        self._actors[lab] = t
        return t

    def scratch_home(self, actor=None) -> Path:
        h = self.tmp / f"home-{self._next()}"
        h.mkdir(parents=True, mode=0o700)
        if actor is None:
            return h
        a = self.actor(actor)
        if not a.email or not a.password:
            raise HarnessError(f"scratch_home: {a.label} has no email/password")
        r = self.cli("login", "--email", a.email, home=h, stdin=(a.password + "\n").encode())
        if r.rc != 0:
            raise HarnessError(f"scratch_home: coffer login {a.label} rc={r.rc}")
        if a.label in self._actors:   # only scratch actors adopt the home
            a.home = h
        return h

    # ---------------- CLI ----------------

    def _bind_file(self, home: Path) -> Path:
        # kept OUTSIDE the home so file-mode / leftover checks on homes see only CLI files
        hid = hashlib.sha256(str(Path(home).resolve()).encode()).hexdigest()[:20]
        return self.work / "homebind" / hid

    def _bind_home(self, home: Path, url: str) -> None:
        try:
            f = self._bind_file(home)
            f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            f.write_text(url.rstrip("/") + "\n" + str(home) + "\n", encoding="utf-8")
        except OSError as e:
            self.log("homebind: record %s failed: %s", home, e)

    def _bound_url(self, home: Path) -> str | None:
        try:
            return self._bind_file(home).read_text(encoding="utf-8").splitlines()[0].strip() or None
        except (OSError, IndexError):
            pass
        # homes logged in before L16 existed: fixture homes were made in F1 (proxied)
        if self.proxy_url and Path(home).parent == self.work / "homes" and Path(home).name != "_calib":
            return self.proxy_url.rstrip("/")
        return None

    def _alt_alive(self, alt: Path, url: str) -> bool:
        cache = self.__dict__.setdefault("_alt_ok", {})
        key = (str(alt), url)
        if key not in cache:
            w = self.cli("whoami", home=alt, url=url)   # actor=None: never redirected
            cache[key] = w.rc != 3
        return cache[key]

    def _home_for_url(self, a: Actor, home: Path, url: str) -> Path:
        url = (url or "").rstrip("/")
        bound = self._bound_url(home)
        if bound is None or bound == url:
            return home
        if url == (self.base_url or "").rstrip("/"):
            tag = "base"
        elif self.proxy_url and url == self.proxy_url.rstrip("/"):
            tag = "proxy"
        else:
            tag = "u" + hashlib.sha256(url.encode()).hexdigest()[:8]
        alt = home.parent / f"{home.name}~{tag}"
        if self._bound_url(alt) == url:
            # r5 (S11): a runner rollback can delete the PAT saved in a reused alt home. Check the
            # session once per row with `whoami`; on rc 3 (401) log in again into the same home.
            if self._alt_alive(alt, url):
                return alt
            self.log("homebind: %s alt home %s is unauthenticated for %s; logging in again", a.label, alt, url)
        if not a.email or not a.password:
            self.log("homebind: %s home bound to %s, no password to log in to %s", a.label, bound, url)
            return home
        alt.mkdir(parents=True, exist_ok=True, mode=0o700)
        r = self.cli("login", "--email", a.email, home=alt, url=url, stdin=(a.password + "\n").encode())
        if r.rc != 0:
            self.log("homebind: %s login to %s in %s rc=%s; using original home", a.label, url, alt, r.rc)
            return home
        self.__dict__.setdefault("_alt_ok", {})[(str(alt), url)] = True
        self.log("homebind: %s home %s is bound to %s; using %s for %s", a.label, home, bound, alt, url)
        return alt

    def _cli_prep(self, args, actor, home, env, js, url, proxy):
        a = self.actor(actor) if actor is not None else self.actor("anon")
        cenv = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "TERM": "dumb"}
        if home is None:
            if a.kind == "user" and a.home:
                home = a.home
            else:
                home = self.tmp / f"home-anon-{self._next()}"
                home.mkdir(parents=True, mode=0o700)
                if a.kind in ("token", "user") and a.secret:
                    cenv["COFFER_TOKEN"] = a.secret
        default_home = home is not None and a.kind == "user" and a.home is not None \
            and Path(home) == Path(a.home)
        if url is None:
            if proxy is True or (proxy is None and self.row.proxied and self.proxy_url):
                url = self.proxy_url or self.base_url
            else:
                url = self.base_url
        cenv["COFFER_URL"] = url
        for k, v in (env or {}).items():
            if v is None:
                cenv.pop(k, None)
            else:
                cenv[k] = str(v)
        # L16: a saved CLI login is bound to the server URL it was made against (a CLI may
        # rightly refuse to send it elsewhere). When the actor's own home is bound to another
        # URL, use a sibling home logged in to this URL instead. `login` itself never swaps.
        if default_home and "COFFER_TOKEN" not in cenv and (not args or str(args[0]) != "login"):
            home = self._home_for_url(a, Path(home), cenv.get("COFFER_URL") or url)
        cenv["HOME"] = str(home)
        binp = (self.setup.get("cli") or {}).get("bin") or str(self.repo / "bin" / "coffer")
        argv = [binp]
        pos = (self.setup.get("cli") or {}).get("json_position") or "front"
        if js and pos == "front":
            argv.append("--json")
        argv += [str(x) for x in args]
        if js and pos != "front":
            argv.append("--json")
        self.tmp.mkdir(parents=True, exist_ok=True)
        return a, argv, cenv

    def cli(self, *args: str, actor=None, home: Path | None = None, stdin: bytes = b"",
            env: dict | None = None, json: bool = False, url: str | None = None,
            timeout: float = 60.0, proxy: bool | None = None) -> CliResult:
        a, argv, cenv = self._cli_prep(args, actor, home, env, json, url, proxy)
        if isinstance(stdin, str):
            stdin = stdin.encode()
        p = _run(argv, cwd=self.tmp, env=cenv, stdin=stdin, timeout=timeout)
        res = CliResult(p.rc, p.out, p.err, p.ms, argv, cenv.get("HOME", ""), cenv.get("COFFER_URL", ""),
                        dict(cenv))
        if p.rc == 0 and args and str(args[0]) == "login" and cenv.get("HOME"):
            self._bind_home(Path(cenv["HOME"]), cenv.get("COFFER_URL") or "")
        shown = ["coffer"] + argv[1:]
        self.log("CLI %s actor=%s home=%s url=%s -> rc=%s %.0fms stdin=%dB\n  out: %s\n  err: %s",
                 " ".join(shown), a.label, cenv.get("HOME"), cenv.get("COFFER_URL"), p.rc, p.ms,
                 len(stdin or b""), self._body_for_log(p.out), self._body_for_log(p.err))
        return res

    def cli_spawn(self, *args: str, actor=None, home=None, stdin=subprocess.PIPE,
                  env=None, json=False, url=None, proxy=None) -> subprocess.Popen:
        a, argv, cenv = self._cli_prep(args, actor, home, env, json, url, proxy)
        self.log("CLI-SPAWN %s actor=%s home=%s", " ".join(["coffer"] + argv[1:]), a.label, cenv.get("HOME"))
        return subprocess.Popen(argv, cwd=str(self.tmp), env=cenv, stdin=stdin, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)

    # ---------------- compose / scripts / containers ----------------

    def _prefix(self) -> list:
        return list(self.setup.get("compose") or ["podman", "compose"])

    def _engine(self) -> str:
        return self._prefix()[0]

    def _compose(self, *args, timeout=300.0, env=None, stdin: bytes = b"", stdout_path=None,
                 quiet=False) -> Proc:
        e = dict(os.environ)
        e.update({k: v for k, v in (env or {}).items() if v is not None})
        for k, v in (env or {}).items():
            if v is None:
                e.pop(k, None)
        argv = self._prefix() + [str(a) for a in args]
        p = _run(argv, cwd=self.repo, env=e, stdin=stdin, timeout=timeout, stdout_path=stdout_path)
        if not quiet:
            self.log("COMPOSE %s -> rc=%s %.0fms err: %s", " ".join(argv[2:] if len(argv) > 2 else argv),
                     p.rc, p.ms, self._body_for_log(p.err[-1500:]))
        return p

    def compose(self, *args: str, timeout: float = 300.0, env: dict | None = None) -> Proc:
        verb = next((a for a in args if not a.startswith("-")), "")
        if verb in SNAP_VERBS:
            self.sweep_snapshot(f"pre-compose-{verb}")
        return self._compose(*args, timeout=timeout, env=env)

    def script(self, name: str, *args: str, timeout: float = 300.0, stdin: bytes = b"") -> Proc:
        p = _run(["bash", f"./scripts/{name}"] + [str(a) for a in args], cwd=self.repo, env=dict(os.environ),
                 stdin=stdin, timeout=timeout)
        self.log("SCRIPT %s %s -> rc=%s %.0fms\n  out: %s\n  err: %s", name, " ".join(map(str, args)), p.rc,
                 p.ms, self._body_for_log(p.out[-1500:]), self._body_for_log(p.err[-1500:]))
        return p

    def wait_ready(self, timeout: float = 30.0) -> bool:
        last = [0]

        def ready():
            r = self.http("GET", "/readyz", timeout=3.0, _quiet=True)
            last[0] = r.status
            return r.status == 200
        ok = self.wait_until(ready, timeout, every=0.5)
        self.log("wait_ready(%ss) -> %s (last status %s)", timeout, ok, last[0])
        return ok

    def up(self, timeout: float = 240.0) -> Proc:
        self.sweep_snapshot("pre-up")
        p = self.script("up.sh", timeout=timeout)
        self.wait_ready(30.0)
        return p

    def down(self, timeout: float = 180.0) -> Proc:
        self.sweep_snapshot("pre-down")
        return self.script("down.sh", timeout=timeout)

    def _project_containers(self) -> list:
        """[(id, service, item)] for every container (any state) of the compose project.

        r2 fix (X1/O1-O4/X18/G3 on build-2): `podman-compose ps -q <svc>` and
        `ps -a --format json` do not work under podman-compose 1.6.0, so the old lookup
        found nothing and returned quietly. Primary source is now the ENGINE
        (`<engine> ps -a --format json`) filtered by compose labels (working_dir == repo,
        else project == basename(repo)), with the compose-ps output as a second source.
        The failing compose output is logged once per process."""
        res = discover_containers(self._engine(), self.repo, self._prefix())
        if not res and not getattr(self, "_disc_logged", False):
            self._disc_logged = True
            self.log("container discovery: nothing found for project %s; %s",
                     self.repo.name, discovery_diag(self._engine(), self.repo, self._prefix()))
        return res

    def container(self, service: str) -> str | None:
        hits = [(cid, it) for cid, svc, it in self._project_containers() if svc == service]
        if not hits:
            return None
        # prefer a running container, then the newest
        def key(h):
            it = h[1]
            st = str(it.get("State") or it.get("Status") or "").lower()
            return (1 if st.startswith("running") or st.startswith("up") else 0,
                    str(it.get("CreatedAt") or it.get("Created") or ""))
        hits.sort(key=key)
        return hits[-1][0]

    def inspect(self, service: str) -> dict | None:
        cid = self.container(service)
        if not cid:
            return None
        p = _run([self._engine(), "inspect", cid], timeout=60)
        if p.rc != 0:
            return None
        try:
            v = _json.loads(p.out)
            return v[0] if isinstance(v, list) and v else (v if isinstance(v, dict) else None)
        except ValueError:
            return None

    def _engine_logs(self, cid: str, since: float | None = None) -> bytes:
        argv = [self._engine(), "logs"]
        if since is not None:
            argv += ["--since", f"{since:.3f}"]
        argv.append(cid)
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        return p.stdout or b""

    def logs(self, service: str, *, since: float | None = None) -> bytes:
        cid = self.container(service)
        if not cid:
            self.log("logs(%s): no container", service)
            return b""
        try:
            return self._engine_logs(cid, since)
        except (OSError, subprocess.SubprocessError) as e:
            self.log("logs(%s) failed: %s", service, e)
            return b""

    def log_mark(self, service: str = "server") -> float:
        return time.time()

    def ps(self) -> list:
        p = _run(["ps", "-eo", "pid=,user=,args="], timeout=30)
        res = []
        for line in p.out.decode("utf-8", "replace").splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) >= 2:
                try:
                    res.append({"pid": int(parts[0]), "user": parts[1], "args": parts[2] if len(parts) > 2 else ""})
                except ValueError:
                    pass
        return res

    @staticmethod
    def _env_file(p: Path) -> dict:
        d: dict = {}
        try:
            txt = Path(p).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return d
        for line in txt.splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            if s.startswith("export "):
                s = s[7:].lstrip()
            k, v = s.split("=", 1)
            k, v = k.strip(), v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            d[k] = v
        return d

    def env_override(self, set: dict | None = None, unset: list = (), *, wait: float = 45.0) -> Override:
        if not self.row.destructive:
            raise HarnessError("env_override is only allowed in destructive rows")
        base = self.work / "ckpt" / self.id / "env"
        if not base.exists():
            base = self.work / "base.env"
        try:
            lines = base.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            raise HarnessError(f"env_override: no base .env: {e}")
        sets = dict(set or {})
        unset = list(unset or ())
        out_lines: list = []
        seen: list = []
        for line in lines:
            s = line.strip()
            key = None
            if s and not s.startswith("#") and "=" in s:
                key = (s[7:] if s.startswith("export ") else s).split("=", 1)[0].strip()
            if key in unset:
                continue
            if key in sets:
                out_lines.append(f"{key}={sets[key]}")
                seen.append(key)
                continue
            out_lines.append(line)
        for k, v in sets.items():
            if k not in seen and k not in unset:
                out_lines.append(f"{k}={v}")
        for k, v in sets.items():
            if "KEY" in k and len(str(v)) >= 12:
                self.secret(f"override:{k}", str(v), "key")
        self.sweep_snapshot("pre-env-override")
        (self.repo / ".env").write_text("\n".join(out_lines) + "\n", encoding="utf-8")
        self.log("env_override set=%s unset=%s", sorted(sets), unset)
        mark = time.time()
        ins0 = self.inspect("server") or {}
        cid_before = ins0.get("Id")
        started_before = str((ins0.get("State") or {}).get("StartedAt") or "") or None
        # r2 (X2/G3 on build-2): remove the old server container first, so a compose provider
        # that ignores --force-recreate cannot reuse the container with the old env baked in.
        if cid_before:
            _run([self._engine(), "rm", "-f", cid_before], timeout=120)
        p = self._compose("up", "-d", "--force-recreate", "--no-deps", "server", timeout=300)
        self.log("  compose up out: %s", self._body_for_log(p.out[-1500:]))
        ready, running, exit_code, restarts = False, False, None, 0
        if p.rc == 0:
            end = time.monotonic() + wait
            while time.monotonic() < end:
                r = self.http("GET", "/readyz", timeout=3.0, _quiet=True)
                if r.status == 200:
                    ready = True
                    break
                ins = self.inspect("server") or {}
                st = ins.get("State") or {}
                restarts = int(ins.get("RestartCount") or st.get("RestartCount") or 0)
                status = str(st.get("Status") or "").lower()
                if status in ("exited", "dead", "stopped") or restarts >= 2:
                    break
                time.sleep(0.5)
        ins = self.inspect("server") or {}
        st = ins.get("State") or {}
        running = bool(st.get("Running"))
        restarts = int(ins.get("RestartCount") or st.get("RestartCount") or restarts or 0)
        if not running and st.get("ExitCode") is not None:
            exit_code = int(st.get("ExitCode"))
        lg = self.logs("server", since=mark - 1)
        ov = Override(p.rc, p.err, ready, running, exit_code, restarts, lg,
                      cid_before=cid_before, cid_after=ins.get("Id"), started_before=started_before,
                      started_after=str(st.get("StartedAt") or "") or None,
                      status=str(st.get("Status") or "") or None, compose_out=p.out)
        self.log("env_override -> compose_rc=%s ready=%s running=%s exit=%s restarts=%s status=%s "
                 "cid %s -> %s recreated=%s\n  logs: %s",
                 p.rc, ready, running, exit_code, restarts, ov.status, (cid_before or "-")[:12],
                 (ov.cid_after or "-")[:12], ov.recreated, self._body_for_log(lg[-1500:]))
        if ov.cid_after is None:
            self.log("env_override: no server container after recreate; %s",
                     discovery_diag(self._engine(), self.repo, self._prefix()))
        return ov

    # ---------------- database ----------------

    def db_conn(self) -> dict:
        e = self._env_file(self.repo / ".env")
        return {"user": e.get("POSTGRES_USER") or "postgres", "password": e.get("POSTGRES_PASSWORD"),
                "db": e.get("POSTGRES_DB") or e.get("POSTGRES_USER") or "postgres", "service": "db"}

    def psql(self, sql: str, *, db: str | None = None, user: str | None = None,
             timeout: float = 60.0) -> Psql:
        dc = self.db_conn()
        user = user or dc["user"]
        db = db or dc["db"]
        p = self._compose("exec", "-T", "db", "psql", "-U", user, "-d", db, "-v", "ON_ERROR_STOP=1", "-X", "-q",
                          "-A", "-t", "-F", _FS, "-R", _RS, "-P", f"null={_NULL}",
                          stdin=sql.encode("utf-8"), timeout=timeout, quiet=True)
        out = p.out.decode("utf-8", "replace")
        err = p.err.decode("utf-8", "replace")
        rows = []
        body = out[:-1] if out.endswith("\n") else out
        if body:
            for rec in body.split(_RS):
                if rec.startswith("\n"):
                    rec = rec[1:]
                if rec == "":
                    continue
                rows.append([None if f == _NULL else f for f in rec.split(_FS)])
        self.log("PSQL user=%s db=%s rc=%s rows=%d\n  sql: %s\n  err: %s", user, db, p.rc, len(rows),
                 self.redact(sql)[:2000], self.redact(err)[:1500])
        return Psql(p.rc, out, err, rows)

    # ---------------- audit (L18) ----------------

    @staticmethod
    def _audit_items(v):
        if isinstance(v, dict):
            for k in ("items", "events", "entries", "audit", "data", "results"):
                if isinstance(v.get(k), list):
                    return v[k]
            return None
        return v if isinstance(v, list) else None

    def audit_list(self, actor, path: str = "/audit", query: dict | None = None):
        """GET an audit list as large as the server allows. -> (status, list|None, info).
        Tries limit=100000; on a 400 (a SPEC-legal cap) retries with 1000, then 500, 100.
        info.complete is False when the list length equals the limit sent or a round cap
        (500/1000/...) seen: the server may have truncated it, so callers must not read a
        shorter-than-history list as loss."""
        info: dict = {"tried": [], "complete": None, "resp": None}
        st, lst = None, None
        for lim in (100000, 1000, 500, 100):
            q = dict(query or {})
            q["limit"] = lim
            r = self.api("GET", path, actor=actor, query=q, timeout=120)
            info["tried"].append((lim, r.status))
            info["resp"] = r
            st = r.status
            if r.status == 400:
                continue
            try:
                lst = self._audit_items(r.json())
            except ValueError:
                lst = None
            info["limit"] = lim
            break
        if lst is not None:
            n = len(lst)
            info["complete"] = not (n >= info.get("limit", 0) or n in (100, 200, 250, 500, 1000, 2000, 5000, 10000))
        self.log("audit_list %s %s -> %s n=%s complete=%s tried=%s", getattr(self.actor(actor), "label", actor),
                 path, st, None if lst is None else len(lst), info["complete"], info["tried"])
        return st, lst, info

    def audit_event_tables(self) -> list:
        """DB tables that hold audit EVENT rows: a prev-hash column AND a hash column
        (the A5/A6 detector). Chain-head / pointer tables do not match. -> [(schema, table)]."""
        r = self.psql("SELECT table_schema, table_name, string_agg(column_name, ',') FROM information_schema.columns "
                      "WHERE table_schema NOT IN ('pg_catalog','information_schema') AND (table_schema, table_name) IN "
                      "(SELECT table_schema, table_name FROM information_schema.tables WHERE table_type='BASE TABLE') "
                      "GROUP BY 1,2 ORDER BY 1,2;")
        if r.rc != 0:
            raise HarnessError("information_schema query failed")
        out = []
        for row in r.rows:
            if len(row) < 3:
                continue
            cols = [x for x in (row[2] or "").split(",") if x]
            prev = [k for k in cols if re.search(r"prev.*hash", k, re.I)]
            hsh = [k for k in cols if re.search(r"hash", k, re.I) and k not in prev]
            if prev and hsh:
                out.append((row[0], row[1]))
        return out

    def audit_rows(self, tables=None) -> dict | None:
        """{"schema.table": [row_to_json text, ...sorted]} of every audit event row, via psql.
        None when the query fails."""
        tables = self.audit_event_tables() if tables is None else tables
        out = {}
        for sch, tab in tables:
            fq = '"' + sch.replace('"', '""') + '"."' + tab.replace('"', '""') + '"'
            r = self.psql(f"SELECT row_to_json(t)::text FROM {fq} t;", timeout=180)
            if r.rc != 0:
                return None
            out[f"{sch}.{tab}"] = sorted(row[0] for row in r.rows if row)
        return out

    def server_db_role(self) -> str | None:
        r = self.psql("SELECT DISTINCT a.usename, COALESCE(r.rolsuper, false) FROM pg_stat_activity a "
                      "LEFT JOIN pg_roles r ON r.rolname = a.usename WHERE a.datname = current_database() "
                      "AND a.pid <> pg_backend_pid() AND a.backend_type = 'client backend' "
                      "AND a.usename IS NOT NULL ORDER BY 1;")
        if r.rc != 0:
            return None
        nonsuper = [row[0] for row in r.rows if row and row[1] not in ("t", "true")]
        supers = [row[0] for row in r.rows if row and row[1] in ("t", "true")]
        if nonsuper:
            if len(nonsuper) > 1:
                self.log("server_db_role: several non-superuser roles %s; using %s", nonsuper, nonsuper[0])
            return nonsuper[0]
        return supers[0] if supers else None

    def _seq(self) -> int:
        m = self._manifest()
        return len(m.get("snapshots") or []) + 1

    def pg_dumpall(self, label: str) -> Path:
        d = self.out / "sweep" / "dumps"
        d.mkdir(parents=True, exist_ok=True)
        dest = d / f"{self._seq():04d}-{self.id}-{re.sub(r'[^A-Za-z0-9_.-]', '_', label)}.sql"
        p = self._compose("exec", "-T", "db", "pg_dumpall", "-U", self.db_conn()["user"],
                          stdout_path=dest, timeout=600, quiet=True)
        self.log("pg_dumpall %s -> rc=%s %s", label, p.rc, dest.name)
        if p.rc != 0:
            raise HarnessError(f"pg_dumpall rc={p.rc}: {self.redact(p.err.decode(errors='replace'))[:200]}")
        return dest

    def pg_dump_app(self, dest: Path) -> Path:
        dc = self.db_conn()
        p = self._compose("exec", "-T", "db", "pg_dump", "-U", dc["user"], "-Fc", dc["db"],
                          stdout_path=Path(dest), timeout=600, quiet=True)
        self.log("pg_dump_app -> rc=%s %s", p.rc, dest)
        if p.rc != 0:
            raise HarnessError(f"pg_dump rc={p.rc}")
        return Path(dest)

    def _pg_restore_text(self, data: bytes) -> bytes:
        p = self._compose("exec", "-T", "db", "pg_restore", "-f", "-", stdin=data, timeout=600, quiet=True)
        if p.rc != 0:
            self.log("pg_restore -f - rc=%s", p.rc)
        return p.out

    # ---------------- backups ----------------

    def backup(self, label: str) -> tuple:
        d = self.work / "backups"
        d.mkdir(parents=True, exist_ok=True)
        dest = d / f"{self.id}-{label}.bak"
        p = self.script("backup.sh", str(dest), timeout=600)
        if dest.exists():
            sb = self.out / "sweep" / "backups"
            sb.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dest, sb / dest.name)
        return p, dest

    def restore(self, path: Path) -> Proc:
        return self.script("restore.sh", str(path), timeout=600)

    def _bind_dirs(self) -> list:
        repo = self.repo.resolve()
        found = []
        for cid, svc, _ in self._project_containers():
            p = _run([self._engine(), "inspect", cid], timeout=60)
            try:
                info = _json.loads(p.out)
                info = info[0] if isinstance(info, list) else info
            except (ValueError, IndexError):
                continue
            for m in info.get("Mounts") or []:
                if (m.get("Type") or "") != "bind":
                    continue
                src = Path(m.get("Source") or "")
                try:
                    src.resolve().relative_to(repo)
                except ValueError:
                    continue
                if src.resolve() == repo or not src.is_dir():
                    continue
                g = _run(["git", "-C", str(repo), "ls-files", "--", str(src.resolve().relative_to(repo))],
                         timeout=30)
                if g.rc == 0 and not g.out.strip() and src not in found:
                    found.append(src)
        return found

    def wipe_volumes(self) -> Proc:
        self.sweep_snapshot("pre-wipe")
        dirs = self._bind_dirs()
        p = self._compose("down", "-v", timeout=300)
        for d in dirs:
            if self._engine() == "podman":
                r = _run(["podman", "unshare", "rm", "-rf", str(d)], timeout=120)
            else:
                shutil.rmtree(d, ignore_errors=True)
                r = Proc(0, b"", b"", 0)
            self.log("wipe_volumes: rm %s -> rc=%s", d, r.rc)
        return p

    # ---------------- positive controls ----------------

    @staticmethod
    def _succeeded(r) -> bool:
        if isinstance(r, Resp):
            return 200 <= r.status < 300
        if isinstance(r, CliResult):
            return r.rc in (0, 7)
        return False

    @staticmethod
    def _desc(r) -> str:
        if isinstance(r, Resp):
            return str(r.status) + (f" ({r.error})" if r.status == 0 and r.error else "")
        if isinstance(r, CliResult):
            return f"rc={r.rc}"
        return type(r).__name__

    def _run_req(self, req):
        try:
            return req()
        except HarnessError:
            raise
        except Exception as e:  # noqa: BLE001
            self.log("request closure raised %s: %s", type(e).__name__, e)
            return None

    def _is_5xx(self, r) -> bool:
        return isinstance(r, Resp) and r.status >= 500

    def control(self, req, *, expect=(200, 201, 202, 204), what: str = "") -> bool:
        r = self._run_req(req)
        if isinstance(r, Resp):
            ok = r.status in expect
        else:
            ok = isinstance(r, CliResult) and r.rc in ({self.exit_for(s) for s in expect} - {1})
        if ok:
            with self._lock:
                self.controls += 1
            self.log("CONTROL ok: %s (%s)", what, self._desc(r))
        else:
            self.error_once(f"control failed: {what} ({self._desc(r)})")
        return ok

    def _cli_session_dead(self, pr, what: str) -> bool:
        """r5 (S11): a CLI probe that answers rc 3 (401) where a 401 is not an accepted denial
        gets an actor-specific positive control: `whoami` in the same HOME/URL/env. If that
        also answers rc 3, the probe never reached authorization: record error, not fail."""
        if not isinstance(pr, CliResult) or pr.rc != 3 or not pr.env or not pr.argv:
            return False
        w = _run([pr.argv[0], "whoami"], cwd=self.tmp, env=pr.env, timeout=60)
        self.log("CONTROL whoami in probe session home=%s url=%s -> rc=%s", pr.home, pr.url, w.rc)
        if w.rc == 3:
            self.error_once(f"control failed: {what}: probe session unauthenticated "
                            f"(whoami rc=3 in home={Path(pr.home).name})")
            return True
        return False

    def denied(self, probe, control, *, allow=(401, 403, 404), what: str = "") -> bool:
        cr = self._run_req(control)
        if not self._succeeded(cr):
            self.error_once(f"control failed: {what} ({self._desc(cr)})")
            return False
        with self._lock:
            self.controls += 1
        self.log("CONTROL ok: %s (%s)", what, self._desc(cr))
        pr = self._run_req(probe)
        if isinstance(pr, Resp):
            if pr.status >= 500:
                with self._lock:
                    self.saw_5xx.append(f"denied-probe {what} -> {pr.status}")
                self.expect(False, f"{what}: got {pr.status} (5xx in denial probe)")
                return False
            if pr.status in allow:
                self.expect(True, f"{what}: denied {pr.status}")
                return True
            self.expect(False, f"{what}: got {self._desc(pr)} (want one of {list(allow)})")
            return False
        if isinstance(pr, CliResult):
            want = {self.exit_for(s) for s in allow} - {0, 1}
            if pr.rc in want:
                self.expect(True, f"{what}: denied rc={pr.rc}")
                return True
            if self._cli_session_dead(pr, what):
                return False
            self.expect(False, f"{what}: got rc={pr.rc} (want one of {sorted(want)})")
            return False
        self.expect(False, f"{what}: probe produced no response")
        return False

    _UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
    _TS = re.compile(r"\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?")

    def _mask(self, text: str, rid: str | None) -> str:
        if rid:
            text = text.replace(rid, "«X»")
        text = self._UUID.sub("«X»", text)
        text = self._TS.sub("«X»", text)
        if rid:
            for run in set(re.findall(r"[A-Za-z0-9_-]{16,}", rid)):
                text = text.replace(run, "«X»")
        return text

    def _masked(self, r) -> tuple:
        if isinstance(r, Resp):
            rid = r.headers.get("x-request-id")
            return self._mask(r.text(), rid), r.headers.get("content-type")
        if isinstance(r, CliResult):
            return self._mask(r.err.decode("utf-8", "replace"), None), None
        return None, None

    def _is404(self, r) -> bool:
        return (isinstance(r, Resp) and r.status == 404) or (isinstance(r, CliResult) and r.rc == 5)

    def same_404(self, probe, absent, control, *, what: str = "") -> bool:
        cr = self._run_req(control)
        if not self._succeeded(cr):
            self.error_once(f"control failed: {what} ({self._desc(cr)})")
            return False
        with self._lock:
            self.controls += 1
        self.log("CONTROL ok: %s (%s)", what, self._desc(cr))
        ar = self._run_req(absent)
        if self._is_5xx(ar):
            with self._lock:
                self.saw_5xx.append(f"same_404-absent {what} -> {ar.status}")
        if not self._is404(ar):
            self.error_once(f"absent target not 404: {what} ({self._desc(ar)})")
            return False
        pr = self._run_req(probe)
        if self._is_5xx(pr):
            with self._lock:
                self.saw_5xx.append(f"same_404-probe {what} -> {pr.status}")
            self.expect(False, f"{what}: got {pr.status} (5xx in 404 probe)")
            return False
        if not self._is404(pr):
            if self._cli_session_dead(pr, what):
                return False
            self.expect(False, f"{what}: got {self._desc(pr)} (want 404 like absent)")
            return False
        pm, pct = self._masked(pr)
        am, act = self._masked(ar)
        if pm != am or pct != act:
            self.expect(False, f"{what}: 404 differs from absent: body {pm[:80]!r} vs {am[:80]!r}"
                               + (f", content-type {pct!r} vs {act!r}" if pct != act else ""))
            return False
        self.expect(True, f"{what}: 404 identical to absent")
        return True

    # ---------------- sweep cache ----------------

    def _manifest(self) -> dict:
        return _read_json(self.out / "sweep" / "manifest.json", {}) or {"final": False, "snapshots": [], "needles": 0}

    def _db_up(self) -> bool:
        cid = self.container("db")
        if not cid:
            return False
        p = _run([self._engine(), "inspect", "-f", "{{.State.Running}}", cid], timeout=30)
        return p.rc == 0 and p.out.strip().lower() == b"true"

    def sweep_snapshot(self, label: str) -> None:
        root = self.out / "sweep"
        for d in ("dumps", "logs", "backups", "homes", "audit"):
            (root / d).mkdir(parents=True, exist_ok=True)
        with self._lock:
            m = self._manifest()
            seq = len(m.get("snapshots") or []) + 1
            dumped = None
            if self.repo.exists() and self._db_up():
                try:
                    dumped = self.pg_dumpall(label).name
                except HarnessError as e:
                    self.log("sweep_snapshot: %s", e)
            nlogs = 0
            if self.repo.exists():
                for cid, svc, _ in self._project_containers():
                    try:
                        data = self._engine_logs(cid)
                    except (OSError, subprocess.SubprocessError) as e:
                        self.log("sweep_snapshot logs %s: %s", cid[:12], e)
                        continue
                    f = root / "logs" / f"{cid}-{svc}.log"
                    try:
                        if not f.exists() or len(data) >= f.stat().st_size:
                            f.write_bytes(data)
                        else:  # container log shrank (rotation): keep old, append new
                            with open(f, "ab") as fh:
                                fh.write(b"\n--- snapshot " + label.encode() + b" ---\n" + data)
                        nlogs += 1
                    except OSError:
                        pass
            m.setdefault("snapshots", []).append({"seq": seq, "id": self.id, "label": label, "when": _iso(),
                                                  "dump": dumped, "logs": nlogs})
            m["needles"] = len(self._all_secrets())
            _write_json_atomic(root / "manifest.json", m)
        self.log("sweep_snapshot %s: dump=%s logs=%d", label, dumped, nlogs)

    def _copy_homes(self) -> None:
        dst = self.out / "sweep" / "homes"
        srcs = []
        hd = self.work / "homes"
        if hd.exists():
            srcs += [(p.name, p) for p in sorted(hd.iterdir()) if p.is_dir()]
        td = self.work / "tmp"
        if td.exists():
            for p in sorted(td.glob("*/home-*")):
                if p.is_dir():
                    srcs.append((f"{p.parent.name}-{p.name}", p))
        for lab, p in srcs:
            safe = re.sub(r"[^A-Za-z0-9@_.-]", "_", lab)
            try:
                shutil.copytree(p, dst / safe, symlinks=True, dirs_exist_ok=True)
            except (OSError, shutil.Error) as e:
                self.log("sweep: copy home %s failed: %s", lab, e)

    def _pull_audit(self) -> None:
        dst = self.out / "sweep" / "audit"
        targets = []
        for org in sorted(((self.fx or {}).get("orgs") or {}).keys()):
            targets.append((org, f"owner@{org}", "/audit"))
        targets.append(("platform", "root", "/admin/audit"))
        for name, lab, path in targets:
            try:
                a = self.actor(lab)
            except KeyError:
                self.log("sweep: no actor %s for audit", lab)
                continue
            st, lst, info = self.audit_list(a, path)
            r = info.get("resp")
            if lst is not None:
                items = lst
            else:
                try:
                    items = [{"_raw": r.text()}] if r is not None else []
                except (AttributeError, ValueError):
                    items = []
            self.log("sweep: audit %s -> %s, %d events, complete=%s", name, st, len(items), info.get("complete"))
            with open(dst / f"{name}.jsonl", "w", encoding="utf-8") as f:
                for it in items:
                    f.write(_json.dumps(it, ensure_ascii=False) + "\n")

    def sweep(self) -> Sweep:
        if self.id not in ("X1", "X6", "A3", "O5"):
            raise HarnessError("only sweep checks (X1 X6 A3 O5) may call c.sweep()")
        m = self._manifest()
        if not m.get("final"):
            self.sweep_snapshot("final")
            self._copy_homes()
            self._pull_audit()
            m = self._manifest()
            m["final"] = True
            m["needles"] = len(self._all_secrets())
            _write_json_atomic(self.out / "sweep" / "manifest.json", m)
        return Sweep(self)
