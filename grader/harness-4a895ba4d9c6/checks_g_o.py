"""Coffer grading checks: G2, O9, O2, O1, O3, O4, O6, O10, G3, O8, O7, O5.

Black-box only (CONTRACT.md v1). Uses lib.Context helpers; nothing reads build
source. Same commands, inputs and order for both builds.

Readings (stricter on the build where CONTRACT/GRADER leave room; identical for
both builds):
GO1  G2 reads setup.json only (up_rc == 0, up_ms <= 180000, readyz_status == 200).
     A missing key is a harness error, never a pass.
GO2  O9 scans git-tracked compose files (compose.yaml/yml, docker-compose.*) and
     Dockerfiles/Containerfiles (name Dockerfile*, Containerfile*, *.Dockerfile,
     *.Containerfile). `image:` values and FROM / COPY --from=<image> refs are
     judged. ${VAR...} is resolved from .env.example then .env (then the :-/-
     default); an unresolvable variable fails. A ref passes if it has a digest
     (@sha256:...) or a tag that is not `latest`. Stage names and `scratch` are
     skipped. ARG defaults before FROM are expanded. A compose service with
     `build:` and no `image:` is judged through its Dockerfile's FROM lines (the
     locally built image is not "pulled untagged"). Zero image refs -> error.
GO3  O2: the server's host pid (inspect State.Pid) and all its descendants are
     read from /proc/<pid>/status (Uid: real/eff/saved/fs); each uid is mapped
     back into the container namespace through /proc/<pid>/uid_map. Any
     container uid 0 fails. If /proc is unreadable, `podman|docker top <cid>
     user` is used as a fallback. No pid at all -> error.
GO4  O1: server identity = (Id, State.StartedAt, State.Pid, RestartCount) before
     and after; all four must match. `/readyz` is polled every 0.25 s after
     `compose stop db` returns; the first 503 must arrive within 10 s. Any other
     5xx (e.g. 500) fails. /healthz must stay 200 while db is down (it "returns
     200 while the process is up"). db is always restarted in `finally`.
     Recovery is waited for up to 60 s and must happen without a server restart.
GO5  O3: 20 in-flight PUTs to junk keys in a scratch project, each sending its
     headers and all but the last 8 body bytes before SIGTERM, and the rest
     0.5 s after. SIGTERM goes to the server container (`<engine> kill --signal
     TERM <cid>`, not `compose stop`, so no snapshot skews timing). "Clean" =
     a complete HTTP response with status 2xx, 4xx or 503 (5xx other than 503 is
     a fail); a reset / truncated response is not clean. Every 2xx PUT must be
     readable afterwards with the sent value (not lost). Exit = the host pid gone
     from /proc (fallback: inspect Running=false), measured from the kill, <= 10 s.
     The stack is brought back with up.sh.
GO6  O4: request log lines are JSON objects with method, route, status,
     duration_ms, request_id at top level; one level of nesting (e.g. {"req":
     {...}}) is accepted for each field. For 4 probe requests (2xx, 401, 404,
     out-of-surface 404) the response X-Request-Id must be present and exactly
     one JSON log line must carry that request_id with the matching status.
GO7  O5: c.sweep() scan of logs (all containers, all encodings) for canaries,
     tokens and passwords, plus a regex scan for any `cof_pat_`/`cof_st_` token
     shape and `Authorization: Bearer` / `Cookie:` header text. A scanner self-test
     (synthetic needle) and non-empty server logs are required, else error.
GO8  O6: 3 cycles of down.sh + up.sh. Each: down rc 0, /healthz unreachable after
     down (the outage was real), up rc 0, /readyz 200; no `ERROR:` line in the db
     log since the mark and no server log line containing "migrat" together with
     error/fail/panic. Data intact = every secret of every fixture env (all
     versions, sha256 of each value), members, audit counts non-decreasing and
     audit verify valid, compared with the state before cycle 1.
GO9  O10: scratch project with 1,000 secrets (20 parallel writers). List: 3
     warm-ups then 40 sequential GETs, each must return all 1,000 keys, p95 <
     300 ms. Gets: 1 warm-up round then 3 rounds of 50 simultaneous GETs (barrier),
     every value must match, p95 < 200 ms. p95 = nearest-rank.
GO10 G3: `git clone c.repo` into c.tmp, init-env.sh twice (rm .env between);
     both keys strict-base64 decode to 32 bytes, differ, and differ from the
     .env.example placeholder. Positive control: env_override() with no change
     must reach ready. Then env_override(COFFER_MASTER_KEY=<placeholder>) must
     NOT reach ready; ready=True -> fail (ship-blocker). A missing
     COFFER_MASTER_KEY line in .env.example -> fail (SPEC: all config documented).
GO11 O8: per CONTRACT §9. Additionally the refusal must be an exit (exit code
     != 0 / restarting / restarts >= 1) or a compose refusal; a server that stays
     running but unready is "did not exit". Bootstrap vars that boot because users
     exist are na-by-design (noted). COFFER_PORT booting because the compose file
     carries the SPEC-given default `${COFFER_PORT:-8420}` is ALSO counted as a
     fail under the strict reading (CONTRACT lists it as required with no
     exception) -- recorded explicitly in evidence so a reviewer can void it.
GO12 O7: before: snapshot of every project/env reachable by owner@acme and
     owner@globex (all non-deleted versions, value sha256), full audit lists
     (acme, globex, platform). backup -> wipe_volumes -> up -> wipe proof
     (owner@acme PAT no longer reads the canary) -> restore -> ready (90 s) ->
     after snapshot equal; every "before" audit event present unchanged in
     "after" (multiset containment); `audit verify` (CLI owner@acme, owner@globex)
     and `admin audit verify` (root) exit 0; API /audit/verify valid. A write+read
     of a junk key proves the restored data key still encrypts.

Local helpers added here (lib.py lacks them): _items, _p95, _slugs, _snapshot,
_audit_all, _raw_put_trickle, _host_pids, _uid_in_container.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path

import lib  # noqa: E402
from registry import Result, check, not_implemented  # noqa: F401


# --------------------------------------------------------------------------
# local helpers
# --------------------------------------------------------------------------

_LIST_KEYS = ("items", "data", "results", "secrets", "versions", "events", "entries", "audit",
              "projects", "envs", "environments", "members", "tokens", "orgs")


def _items(v):
    """Normalize a list-ish JSON response to a list (or None if not list-shaped)."""
    if isinstance(v, list):
        return v
    if isinstance(v, dict):
        for k in _LIST_KEYS:
            if isinstance(v.get(k), list):
                return v[k]
    return None


def _rj(r):
    try:
        return r.json()
    except (ValueError, AttributeError):
        return None


def _p95(xs):
    s = sorted(xs)
    if not s:
        return None
    k = max(0, -(-95 * len(s) // 100) - 1)  # nearest rank: ceil(0.95 n) - 1
    return s[k]


def _sha(s) -> str:
    if isinstance(s, str):
        s = s.encode("utf-8", "surrogatepass")
    return hashlib.sha256(s or b"").hexdigest()[:16]


def _slugs(lst):
    out = []
    for it in lst or []:
        if isinstance(it, str):
            out.append(it)
        elif isinstance(it, dict):
            s = it.get("slug") or it.get("name") or it.get("key")
            if s:
                out.append(str(s))
    return sorted(set(out))


def _vnum(it):
    if isinstance(it, dict):
        for k in ("version", "v", "number"):
            if k in it:
                try:
                    return int(it[k])
                except (TypeError, ValueError):
                    return None
    return None


def _deleted(it):
    if isinstance(it, dict):
        return bool(it.get("deleted") or it.get("tombstone") or it.get("is_deleted"))
    return False


def _snapshot(c, owners, *, fixture_only=False, workers=16):
    """{org/p/e/KEY: {version: sha|'<deleted>'}} plus problems list. Reads as each org's owner."""
    snap: dict = {}
    problems: list = []
    jobs = []
    for org, owner in owners:
        if fixture_only:
            projs = sorted(((c.fx.get("projects") or {}).get(org) or {}).items())
            pe = [(p, list(envs)) for p, envs in projs]
        else:
            r = c.api("GET", "/projects", actor=owner, timeout=30)
            plist = _items(_rj(r))
            if r.status != 200 or plist is None:
                problems.append(f"{org}: GET /projects -> {r.status}")
                continue
            pe = []
            for p in _slugs(plist):
                re_ = c.api("GET", f"/projects/{p}/envs", actor=owner, timeout=30)
                el = _items(_rj(re_))
                if re_.status != 200 or el is None:
                    problems.append(f"{org}/{p}: GET envs -> {re_.status}")
                    continue
                pe.append((p, _slugs(el)))
        for p, envs in pe:
            for e in envs:
                jobs.append((org, owner, p, e))

    def list_env(job):
        org, owner, p, e = job
        r = c.api("GET", f"/projects/{p}/envs/{e}/secrets", actor=owner, timeout=60)
        lst = _items(_rj(r))
        if r.status != 200 or lst is None:
            return job, None, f"{org}/{p}/{e}: list -> {r.status}"
        keys = sorted({str(it.get("key")) for it in lst if isinstance(it, dict) and it.get("key")})
        return job, keys, None

    key_jobs = []
    for res in c.parallel([(lambda j=j: list_env(j)) for j in jobs], workers=workers):
        if isinstance(res, Exception):
            problems.append(f"list raised {res!r}")
            continue
        job, keys, err = res
        if err:
            problems.append(err)
            continue
        for k in keys:
            key_jobs.append(job + (k,))

    def versions(job):
        org, owner, p, e, k = job
        base = f"/projects/{p}/envs/{e}/secrets/{k}"
        r = c.api("GET", base + "/versions", actor=owner, timeout=60)
        lst = _items(_rj(r))
        if r.status != 200 or lst is None:
            return job, None, f"{org}/{p}/{e}/{k}: versions -> {r.status}"
        vals = {}
        for it in lst:
            n = _vnum(it)
            if n is None:
                return job, None, f"{org}/{p}/{e}/{k}: unparseable version entry"
            if _deleted(it):
                vals[str(n)] = "<deleted>"
                continue
            rv = c.api("GET", f"{base}/versions/{n}", actor=owner, timeout=60)
            j = _rj(rv)
            if rv.status != 200 or not isinstance(j, dict) or "value" not in j:
                vals[str(n)] = f"<status {rv.status}>"
            else:
                vals[str(n)] = _sha(j["value"])
        return job, vals, None

    for res in c.parallel([(lambda j=j: versions(j)) for j in key_jobs], workers=workers):
        if isinstance(res, Exception):
            problems.append(f"versions raised {res!r}")
            continue
        job, vals, err = res
        if err:
            problems.append(err)
            continue
        org, _, p, e, k = job
        snap[f"{org}/{p}/{e}/{k}"] = vals
    return snap, problems


def _diff_snap(a: dict, b: dict) -> list:
    out = []
    for k in sorted(set(a) | set(b)):
        if k not in b:
            out.append(f"{k} missing after")
        elif k not in a:
            continue  # new keys are not a loss
        elif a[k] != b[k]:
            lost = [v for v in a[k] if a[k][v] != b[k].get(v)]
            out.append(f"{k} versions differ at {lost[:5]}")
    return out


def _audit_all(c, actor, path):
    """r4 (O6/O7): via lib.audit_list (limit 100000, falls back to 1000 on a 400 cap).
    -> (status, list|None, complete). complete False = may be truncated by a server cap."""
    st, lst, info = c.audit_list(actor, path)
    return st, lst, bool(info.get("complete"))


def _audit_sql(c):
    """r4: {"schema.table": sorted row_to_json} of the audit EVENT tables (prev-hash + hash
    columns), or (None, why)."""
    try:
        tabs = c.audit_event_tables()
    except lib.HarnessError as e:
        return None, str(e)
    if not tabs:
        return None, "no audit event table (prev-hash + hash columns) found"
    rows = c.audit_rows(tabs)
    if rows is None:
        return None, "audit row dump via psql failed"
    return rows, ""


def _canon(ev) -> str:
    return json.dumps(ev, sort_keys=True, ensure_ascii=False)


def _verify_api(c, actor, path):
    r = c.api("GET", path, actor=actor, timeout=120)
    j = _rj(r)
    valid = isinstance(j, dict) and j.get("valid") is True
    return r.status, valid, j


def _members(c, owner):
    r = c.api("GET", "/members", actor=owner, timeout=30)
    lst = _items(_rj(r))
    if r.status != 200 or lst is None:
        return None
    out = []
    for m in lst:
        if isinstance(m, dict):
            out.append(f"{m.get('email') or m.get('id')}:{m.get('role')}")
    return sorted(out)


def _proc_children() -> dict:
    kids: dict = {}
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            st = (p / "stat").read_text()
            ppid = int(st.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        kids.setdefault(ppid, []).append(int(p.name))
    return kids


def _host_pids(root_pid: int) -> list:
    kids = _proc_children()
    out, todo = [], [root_pid]
    while todo:
        x = todo.pop()
        if x in out:
            continue
        out.append(x)
        todo.extend(kids.get(x, []))
    return out


def _uid_in_container(host_uid: int, uid_map: str):
    """Map a host uid back to the container namespace via /proc/<pid>/uid_map."""
    for line in uid_map.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        inside, outside, count = (int(x) for x in parts)
        if outside <= host_uid < outside + count:
            return inside + (host_uid - outside)
    return None


def _strict_b64_32(v: str) -> bool:
    try:
        return len(base64.b64decode(v.strip(), validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def _env_get(path: Path, key: str):
    try:
        txt = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    val = None
    for line in txt.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        if s.startswith("export "):
            s = s[7:].lstrip()
        k, v = s.split("=", 1)
        if k.strip() != key:
            continue
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        else:
            v = re.sub(r"\s+#.*$", "", v)
        val = v
    return val


def _git(c, *args, timeout=120):
    return subprocess.run(["git", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout)


def _owners(c, orgs=("acme", "globex")):
    out = []
    for o in orgs:
        try:
            out.append((o, c.actor(f"owner@{o}")))
        except KeyError:
            c.error_once(f"fixture actor owner@{o} missing")
    return out


# --------------------------------------------------------------------------
# G2
# --------------------------------------------------------------------------

@check("G2")
def g2(c) -> Result:
    """up.sh returns 0 within 180 s and /readyz = 200 (observed during setup)"""
    s = c.setup or {}
    missing = [k for k in ("up_rc", "up_ms", "readyz_status") if k not in s]
    if missing:
        return c.error(f"setup.json lacks {missing}")
    rc, ms, rz = s.get("up_rc"), s.get("up_ms"), s.get("readyz_status")
    c.log("setup: up_rc=%s up_ms=%s readyz_status=%s", rc, ms, rz)
    c.expect(rc == 0, f"up.sh rc={rc} (want 0)")
    try:
        c.expect(float(ms) <= 180000, f"up.sh took {ms} ms (want <= 180000)")
    except (TypeError, ValueError):
        return c.error(f"setup up_ms not numeric: {ms!r}")
    c.expect(rz == 200, f"/readyz after up.sh -> {rz} (want 200)")
    return c.done(f"up.sh rc=0 in {float(ms) / 1000:.1f}s, /readyz 200",
                  {"up_rc": rc, "up_ms": ms, "readyz_status": rz})


# --------------------------------------------------------------------------
# O9
# --------------------------------------------------------------------------

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _resolve(s: str, env: dict):
    """Expand ${V}, ${V:-d}, ${V-d}, ${V:?e}, $V; returns (value, unresolved_names)."""
    bad = []

    def sub(m):
        name = m.group(1) or m.group(4)
        op, dflt = m.group(2), m.group(3)
        val = env.get(name)
        if op in (":-",) and not val:
            return dflt or ""
        if op == "-" and val is None:
            return dflt or ""
        if val is None or (op == ":?" and not val):
            bad.append(name)
            return ""
        return val
    out = _VAR.sub(sub, s)
    return out, bad


def _judge_ref(ref: str):
    """None if pinned, else a reason string."""
    ref = ref.strip().strip("\"'")
    if not ref:
        return "empty image reference"
    if "@sha256:" in ref or "@sha512:" in ref:
        return None
    last = ref.rsplit("/", 1)[-1]
    if ":" not in last:
        return "untagged"
    tag = last.rsplit(":", 1)[1]
    if not tag:
        return "empty tag"
    if tag.lower() == "latest":
        return ":latest"
    return None


def _dockerfile_refs(text: str, env: dict):
    """[(ref, why_skip_or_None, unresolved)] for FROM and COPY --from=<image>."""
    args: dict = {}
    stages: set = set()
    refs = []
    lines = []
    buf = ""
    for raw in text.splitlines():
        s = raw.rstrip()
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        lines.append((buf + s).strip())
        buf = ""
    if buf:
        lines.append(buf.strip())
    for s in lines:
        if not s or s.startswith("#"):
            continue
        toks = s.split()
        ins = toks[0].upper()
        if ins == "ARG" and len(toks) >= 2:
            for t in toks[1:]:
                if "=" in t:
                    k, v = t.split("=", 1)
                    v = v.strip("\"'")
                    args[k] = v
                else:
                    args.setdefault(t, env.get(t))
        elif ins == "FROM":
            rest = [t for t in toks[1:] if not t.startswith("--")]
            if not rest:
                refs.append(("", None, ["<no image>"]))
                continue
            img = rest[0]
            if len(rest) >= 3 and rest[1].lower() == "as":
                stages.add(rest[2].lower())
            val, bad = _resolve(img, {k: v for k, v in args.items() if v is not None})
            if val.lower() == "scratch" or val.lower() in stages:
                refs.append((val, "stage/scratch", []))
            else:
                refs.append((val, None, bad))
        elif ins == "COPY":
            for t in toks[1:]:
                if t.startswith("--from="):
                    src = t.split("=", 1)[1]
                    val, bad = _resolve(src, {k: v for k, v in args.items() if v is not None})
                    if val.isdigit() or val.lower() in stages:
                        continue
                    refs.append((val, None, bad))
    return refs


@check("O9")
def o9(c) -> Result:
    """No :latest and no untagged image in compose or Dockerfiles"""
    repo = c.repo
    g = _git(c, "-C", str(repo), "ls-files", "-z")
    if g.returncode != 0:
        return c.error(f"git ls-files rc={g.returncode}")
    files = [f for f in g.stdout.decode("utf-8", "replace").split("\0") if f]
    composes, dockerfiles = [], []
    for f in files:
        base = f.rsplit("/", 1)[-1]
        bl = base.lower()
        if re.fullmatch(r"(docker-)?compose(\.[\w.-]+)?\.ya?ml", bl):
            composes.append(f)
        elif (bl.startswith("dockerfile") or bl.startswith("containerfile")
              or bl.endswith(".dockerfile") or bl.endswith(".containerfile")):
            dockerfiles.append(f)
    c.log("compose files: %s", composes)
    c.log("dockerfiles: %s", dockerfiles)
    env: dict = {}
    for name in (".env.example", ".env"):
        p = repo / name
        if p.exists():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if s and not s.startswith("#") and "=" in s:
                    k, v = s.split("=", 1)
                    env.setdefault(k.strip().removeprefix("export ").strip(), v.strip().strip("\"'"))
    judged = []
    for f in composes:
        text = (repo / f).read_text(encoding="utf-8", errors="replace")
        for ln, line in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*(?:-\s*)?image\s*:\s*(.+?)\s*$", line)
            if not m:
                continue
            v = m.group(1)
            if not (v.startswith("'") or v.startswith('"')):
                v = re.sub(r"\s+#.*$", "", v)
            v = v.strip().strip("\"'")
            val, bad = _resolve(v, env)
            judged.append((f"{f}:{ln}", v, val, bad))
    for f in dockerfiles:
        text = (repo / f).read_text(encoding="utf-8", errors="replace")
        for val, skip, bad in _dockerfile_refs(text, env):
            if skip:
                c.log("skip %s in %s (%s)", val, f, skip)
                continue
            judged.append((f, val, val, bad))
    if not judged:
        return c.error("no image references found in compose files or Dockerfiles")
    found_pg = False
    for where, rawv, val, bad in judged:
        if bad:
            c.expect(False, f"{where}: image {rawv!r} has unresolvable variable(s) {bad}")
            continue
        why = _judge_ref(val)
        c.expect(why is None, f"{where}: image {val!r} {why}" if why else f"{where}: {val} pinned")
        if re.fullmatch(r"(docker\.io/)?(library/)?postgres:16(\.[\w.-]*)?(@sha256:\w+)?", val):
            found_pg = True
    c.log("postgres:16 seen: %s", found_pg)
    return c.done(f"{len(judged)} image refs pinned ({len(composes)} compose, {len(dockerfiles)} Dockerfiles)",
                  {"refs": [f"{w} {v}" for w, _, v, _ in judged][:60]})


# --------------------------------------------------------------------------
# O2
# --------------------------------------------------------------------------

@check("O2")
def o2(c) -> Result:
    """server container user is not uid 0"""
    ins = c.inspect("server")
    if not ins:
        return c.error("no server container to inspect")
    st = ins.get("State") or {}
    pid = int(st.get("Pid") or 0)
    cfg_user = (ins.get("Config") or {}).get("User")
    c.log("server Config.User=%r State.Pid=%s Running=%s", cfg_user, pid, st.get("Running"))
    if not st.get("Running") or pid <= 0:
        return c.error(f"server not running (pid={pid})")
    checked = 0
    rows = []
    try:
        uid_map = Path(f"/proc/{pid}/uid_map").read_text()
        for hp in _host_pids(pid):
            try:
                status = Path(f"/proc/{hp}/status").read_text()
                cmd = Path(f"/proc/{hp}/cmdline").read_bytes().replace(b"\0", b" ")[:120].decode("utf-8", "replace")
            except OSError:
                continue
            m = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", status, re.M)
            if not m:
                continue
            host_uids = [int(x) for x in m.groups()]
            cuids = [_uid_in_container(u, uid_map) for u in host_uids]
            rows.append(f"pid {hp} host_uids={host_uids} container_uids={cuids} {cmd}")
            c.log("pid %s host Uid=%s container Uid=%s cmd=%s", hp, host_uids, cuids, cmd)
            checked += 1
            c.expect(all(u is not None and u != 0 for u in cuids),
                     f"server pid {hp} runs as container uid {cuids} ({cmd.strip()[:60]})")
    except OSError as e:
        c.log("/proc read failed: %s; falling back to engine top", e)
    if checked == 0:
        cid = c.container("server")
        eng = (c.setup.get("compose") or ["podman"])[0]
        p = subprocess.run([eng, "top", cid, "user", "args"], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=60)
        txt = p.stdout.decode("utf-8", "replace")
        c.log("%s top -> rc=%s\n%s", eng, p.returncode, txt[:2000])
        lines = [ln for ln in txt.splitlines()[1:] if ln.strip()]
        if p.returncode != 0 or not lines:
            return c.error("could not read server process uids (/proc and top both failed)")
        for ln in lines:
            u = ln.split()[0]
            checked += 1
            rows.append(ln[:120])
            c.expect(u not in ("root", "0"), f"server process runs as {u}: {ln[:80]}")
    return c.done(f"{checked} server processes, none uid 0 (Config.User={cfg_user!r})", {"procs": rows[:20]})


# --------------------------------------------------------------------------
# O1
# --------------------------------------------------------------------------

def _server_ident(c):
    ins = c.inspect("server") or {}
    st = ins.get("State") or {}
    return {"id": ins.get("Id"), "started": st.get("StartedAt"), "pid": st.get("Pid"),
            "restarts": ins.get("RestartCount") or st.get("RestartCount") or 0}


@check("O1")
def o1(c) -> Result:
    """/healthz 200; db stop -> /readyz 503 <= 10 s; db start -> 200 without server restart"""
    h = c.http("GET", "/healthz", timeout=5)
    c.expect(h.status == 200, f"/healthz -> {h.status} (want 200)")
    r0 = c.http("GET", "/readyz", timeout=5)
    if r0.status != 200:
        return c.error(f"precondition: /readyz -> {r0.status} before db stop")
    before = _server_ident(c)
    c.log("server identity before: %s", before)
    if not before.get("id"):
        return c.error("no server container")
    data: dict = {"before": before}
    try:
        p = c.compose("stop", "db", timeout=120)
        if p.rc != 0:
            return c.error(f"compose stop db rc={p.rc}")
        t0 = time.monotonic()
        seen = []
        got503 = None
        while time.monotonic() - t0 < 10.0:
            r = c.http("GET", "/readyz", timeout=3.0)
            seen.append(r.status)
            if r.status == 503:
                got503 = time.monotonic() - t0
                break
            time.sleep(0.25)
        data["readyz_seen"] = seen[:40]
        c.expect(got503 is not None,
                 f"/readyz never 503 within 10 s of db stop (saw {sorted(set(seen))})")
        bad5 = [s for s in seen if s >= 500 and s != 503]
        c.expect(not bad5, f"/readyz returned {bad5[:3]} during db outage (only 503 allowed)")
        if got503 is not None:
            data["readyz_503_after_s"] = round(got503, 2)
        hh = c.http("GET", "/healthz", timeout=5)
        c.expect(hh.status == 200, f"/healthz with db down -> {hh.status} (want 200: process is up)")
    finally:
        ps = c.compose("start", "db", timeout=180)
        c.log("compose start db rc=%s", ps.rc)
    t1 = time.monotonic()
    rec_seen = []

    def ready():
        r = c.http("GET", "/readyz", timeout=3.0)
        rec_seen.append(r.status)
        return r.status == 200
    recovered = c.wait_until(ready, 60.0, every=0.5)
    data["recovery_s"] = round(time.monotonic() - t1, 1)
    c.expect(recovered, f"/readyz not 200 within 60 s of db start (last {rec_seen[-3:]})")
    bad5 = [s for s in rec_seen if s >= 500 and s != 503]
    c.expect(not bad5, f"/readyz returned {bad5[:3]} during recovery")
    after = _server_ident(c)
    data["after"] = after
    c.log("server identity after: %s", after)
    c.expect(after == before, f"server restarted during db outage: before={before} after={after}")
    if recovered:
        k = "acme/api/dev/CANARY"
        want = (c.fx.get("canaries") or {}).get(k)
        rr = c.api("GET", "/projects/api/envs/dev/secrets/CANARY", actor="owner@acme")
        j = _rj(rr)
        c.expect(rr.status == 200 and isinstance(j, dict) and j.get("value") == want,
                 f"after recovery owner GET {k} -> {rr.status} (value match={isinstance(j, dict) and j.get('value') == want})")
    return c.done(f"/healthz 200; readyz 503 after {data.get('readyz_503_after_s')}s; "
                  f"recovered in {data['recovery_s']}s, same server container", data)


# --------------------------------------------------------------------------
# O3
# --------------------------------------------------------------------------

def _raw_put_trickle(c, path, token, body: bytes, hold: int, gate: threading.Event,
                     started: threading.Barrier, timeout=30.0):
    """Send headers + body[:-hold], wait at `started`, then for `gate`, send the rest, read the reply."""
    from urllib.parse import urlsplit
    u = urlsplit(c.base_url)
    res = {"status": 0, "body": b"", "error": None, "phase": "connect"}
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        conn.putrequest("PUT", path, skip_accept_encoding=True)
        conn.putheader("Authorization", f"Bearer {token}")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        conn.send(body[:-hold])
        res["phase"] = "partial-sent"
    except (OSError, http.client.HTTPException) as e:
        res["error"] = f"{type(e).__name__}: {e}"
    try:
        started.wait(timeout=30)
    except threading.BrokenBarrierError:
        pass
    gate.wait(timeout=60)
    if res["error"] is None:
        try:
            conn.send(body[-hold:])
            res["phase"] = "sent"
            r = conn.getresponse()
            res["body"] = r.read()
            res["status"] = r.status
            res["phase"] = "done"
        except (OSError, http.client.HTTPException) as e:
            res["error"] = f"{type(e).__name__}: {e}"
    try:
        conn.close()
    except Exception:
        pass
    return res


@check("O3")
def o3(c) -> Result:
    """SIGTERM with 20 in-flight requests: clean completion or error; exit <= 10 s"""
    owner = c.actor("owner@acme")
    proj = c.scratch_project("owner@acme")
    ctl = c.api("PUT", f"/projects/{proj}/envs/dev/secrets/O3_CTL", actor=owner, json={"value": "o3-control"})
    if not c.control(lambda: ctl, what="PUT junk key in scratch project"):
        return c.done()
    ins = c.inspect("server") or {}
    cid, pid = ins.get("Id"), int((ins.get("State") or {}).get("Pid") or 0)
    if not cid or pid <= 0:
        return c.error("no running server container")
    n = 20
    vals = {}
    for i in range(n):
        vals[f"O3_K{i:02d}"] = c.secret(f"canary:o3-{i}", "o3" + secrets.token_hex(19))
    gate = threading.Event()
    started = threading.Barrier(n + 1)
    results: dict = {}

    def worker(k):
        body = json.dumps({"value": vals[k]}).encode()
        results[k] = _raw_put_trickle(c, f"/api/v1/projects/{proj}/envs/dev/secrets/{k}",
                                      owner.secret, body, 8, gate, started)
    ths = [threading.Thread(target=worker, args=(k,), daemon=True) for k in vals]
    for t in ths:
        t.start()
    try:
        started.wait(timeout=30)
    except threading.BrokenBarrierError:
        gate.set()
        return c.error("in-flight requests did not all start")
    time.sleep(0.3)
    eng = (c.setup.get("compose") or ["podman"])[0]
    t_kill = time.monotonic()
    kp = subprocess.run([eng, "kill", "--signal", "TERM", cid], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=30)
    c.log("%s kill --signal TERM %s -> rc=%s %s", eng, cid[:12], kp.returncode, kp.stderr[:300])
    if kp.returncode != 0:
        gate.set()
        for t in ths:
            t.join(35)
        c.up()
        return c.error(f"could not send SIGTERM (rc={kp.returncode})")
    exited_at = [None]

    def poll_exit():
        while time.monotonic() - t_kill < 20:
            if not Path(f"/proc/{pid}").exists():
                exited_at[0] = time.monotonic() - t_kill
                return
            time.sleep(0.1)
    pt = threading.Thread(target=poll_exit, daemon=True)
    pt.start()
    time.sleep(0.5)
    gate.set()
    for t in ths:
        t.join(40)
    pt.join(25)
    if exited_at[0] is None:
        st = (c.inspect("server") or {}).get("State") or {}
        c.log("after 20 s: pid %s still in /proc; inspect State=%s", pid,
              {k: st.get(k) for k in ("Status", "Running", "Pid", "ExitCode")})
    data = {"exit_s": None if exited_at[0] is None else round(exited_at[0], 2), "replies": {}}
    c.expect(exited_at[0] is not None and exited_at[0] <= 10.0,
             f"server process exit after SIGTERM: {data['exit_s']} s (want <= 10)")
    ok2xx = []
    for k in sorted(vals):
        r = results.get(k) or {"status": 0, "error": "thread did not finish", "phase": "?"}
        st = r["status"]
        data["replies"][k] = st if st else f"0:{r.get('phase')}:{(r.get('error') or '')[:40]}"
        c.log("in-flight %s -> status=%s phase=%s err=%s body=%s", k, st, r.get("phase"), r.get("error"),
              c.redact((r.get("body") or b"")[:300].decode("utf-8", "replace")))
        clean = (200 <= st < 300) or (400 <= st < 500) or st == 503
        c.expect(clean, f"in-flight PUT {k} -> {'status ' + str(st) if st else 'no response (' + str(r.get('error')) + ')'} "
                        f"(want completion or clean error)")
        if 200 <= st < 300:
            ok2xx.append(k)
    up = c.up()
    if not c.wait_ready(60):
        return c.error(f"stack did not come back after SIGTERM (up.sh rc={up.rc})")
    for k in ok2xx:
        r = c.api("GET", f"/projects/{proj}/envs/dev/secrets/{k}", actor=owner)
        j = _rj(r)
        c.expect(r.status == 200 and isinstance(j, dict) and j.get("value") == vals[k],
                 f"{k} acknowledged {results[k]['status']} but after restart GET -> {r.status} (lost write)")
    data["acked"] = len(ok2xx)
    return c.done(f"20 in-flight: {len(ok2xx)} completed, rest clean errors; exit {data['exit_s']} s", data)


# --------------------------------------------------------------------------
# O4
# --------------------------------------------------------------------------

_O4_FIELDS = ("method", "route", "status", "duration_ms", "request_id")


def _field(obj, name):
    if not isinstance(obj, dict):
        return None
    if name in obj:
        return obj[name]
    for v in obj.values():
        if isinstance(v, dict) and name in v:
            return v[name]
    return None


@check("O4")
def o4(c) -> Result:
    """Request logs JSON lines with method, route, status, duration_ms, request_id"""
    mark = c.log_mark("server")
    time.sleep(1.1)
    probes = [
        ("GET", "/api/v1/me", "owner@acme", 200),
        ("GET", "/api/v1/me", "anon", 401),
        ("GET", f"/api/v1/projects/{c.absent_slug()}/envs/dev/secrets", "owner@acme", 404),
        ("GET", "/zz-o4-out-of-surface", "anon", 404),
    ]
    resps = []
    for m, p, a, want in probes:
        r = c.http(m, p, actor=a)
        rid = r.headers.get("x-request-id")
        resps.append((m, p, a, want, r, rid))
        c.expect(r.status == want, f"{m} {p} as {a} -> {r.status} (want {want})")
        c.expect(bool(rid), f"{m} {p} -> no X-Request-Id header")
    time.sleep(2.0)
    raw = c.logs("server", since=mark - 1)
    lines = raw.decode("utf-8", "replace").splitlines()
    objs = []
    nonjson = 0
    for ln in lines:
        s = ln.strip()
        i = s.find("{")
        if i < 0:
            nonjson += 1 if s else 0
            continue
        try:
            o = json.loads(s)
        except ValueError:
            nonjson += 1
            continue
        if isinstance(o, dict):
            objs.append(o)
    c.log("server log lines since mark: %d, JSON objects: %d, non-JSON: %d", len(lines), len(objs), nonjson)
    if not lines:
        return c.error("no server log output since mark")
    reqlines = [o for o in objs if _field(o, "duration_ms") is not None
                or (_field(o, "method") is not None and _field(o, "status") is not None)]
    c.expect(bool(reqlines), "no JSON request log line (duration_ms or method+status) found")
    for o in reqlines:
        miss = [f for f in _O4_FIELDS if _field(o, f) is None]
        c.expect(not miss, f"request log line lacks {miss}: {json.dumps(o)[:150]}")
        dm = _field(o, "duration_ms")
        c.expect(isinstance(dm, (int, float)) and not isinstance(dm, bool),
                 f"duration_ms not numeric: {dm!r}")
    for m, p, a, want, r, rid in resps:
        if not rid:
            continue
        hit = [o for o in reqlines if str(_field(o, "request_id")) == rid]
        c.expect(len(hit) == 1, f"{m} {p}: {len(hit)} log lines with request_id={rid} (want 1)")
        if hit:
            o = hit[0]
            c.expect(str(_field(o, "status")) == str(r.status),
                     f"{m} {p}: log status={_field(o, 'status')} vs response {r.status}")
            c.expect(str(_field(o, "method")).upper() == m,
                     f"{m} {p}: log method={_field(o, 'method')}")
    sample = json.dumps(reqlines[0])[:400] if reqlines else None
    return c.done(f"{len(reqlines)} JSON request lines with all 5 fields; X-Request-Id matched for 4 probes",
                  {"sample": sample, "nonjson_lines": nonjson})


# --------------------------------------------------------------------------
# O6
# --------------------------------------------------------------------------

def _state_o6(c, owners):
    snap, probs = _snapshot(c, owners, fixture_only=True)
    mem = {o: _members(c, a) for o, a in owners}
    # r4: count audit events in SQL (SPEC sets no API page maximum; a build may cap limit).
    rows, why = _audit_sql(c)
    if rows is None:
        c.log("O6 audit SQL count unavailable: %s; using API lists", why)
        aud = {}
        for o, a in owners:
            st, lst, complete = _audit_all(c, a, "/audit")
            aud[o] = len(lst) if (st == 200 and lst is not None) else None
    else:
        aud = {t: len(v) for t, v in rows.items()}
    return snap, probs, mem, aud


@check("O6")
def o6(c) -> Result:
    """3x down/up: migrations idempotent, no errors, data intact"""
    owners = _owners(c)
    if not owners:
        return c.done()
    base, probs, mem0, aud0 = _state_o6(c, owners)
    if probs or not base:
        return c.error(f"baseline snapshot incomplete: {probs[:3]} keys={len(base)}")
    c.log("baseline: %d keys, members=%s, audit=%s", len(base), {k: len(v or []) for k, v in mem0.items()}, aud0)
    data = {"keys": len(base), "cycles": []}
    for cyc in range(1, 4):
        mark = time.time()
        d = c.down(timeout=240)
        c.expect(d.rc == 0, f"cycle {cyc}: down.sh rc={d.rc}")
        hz = c.http("GET", "/healthz", timeout=3)
        c.expect(hz.status == 0, f"cycle {cyc}: /healthz -> {hz.status} after down.sh (stack still up?)")
        u = c.script("up.sh", timeout=240)
        c.expect(u.rc == 0, f"cycle {cyc}: up.sh rc={u.rc}")
        rdy = c.wait_ready(30)
        c.expect(rdy, f"cycle {cyc}: /readyz not 200 after up.sh")
        if not rdy:
            break
        dblog = c.logs("db", since=mark).decode("utf-8", "replace")
        errs = [ln for ln in dblog.splitlines() if "ERROR:" in ln]
        c.expect(not errs, f"cycle {cyc}: db log ERROR: {errs[0][:160] if errs else ''}")
        slog = c.logs("server", since=mark).decode("utf-8", "replace")
        mig = [ln for ln in slog.splitlines()
               if re.search(r"migrat", ln, re.I) and re.search(r"error|fail|panic|fatal", ln, re.I)]
        c.expect(not mig, f"cycle {cyc}: server migration error: {mig[0][:160] if mig else ''}")
        snap, probs, mem, aud = _state_o6(c, owners)
        c.expect(not probs, f"cycle {cyc}: reads failed: {probs[:2]}")
        diff = _diff_snap(base, snap)
        c.expect(not diff, f"cycle {cyc}: data changed: {diff[:2]}")
        c.expect(mem == mem0, f"cycle {cyc}: members changed")
        for o in aud0:
            c.expect(aud.get(o) is not None and aud0[o] is not None and aud[o] >= aud0[o],
                     f"cycle {cyc}: {o} audit count {aud0[o]} -> {aud.get(o)}",
                     f"cycle {cyc}: {o} audit count {aud0[o]} -> {aud.get(o)} (non-decreasing)")
        for o, a in owners:
            st, valid, j = _verify_api(c, a, "/audit/verify")
            c.expect(st == 200 and valid, f"cycle {cyc}: {o} /audit/verify -> {st} {str(j)[:80]}")
        data["cycles"].append({"cycle": cyc, "down_rc": d.rc, "up_rc": u.rc, "up_ms": round(u.ms)})
    return c.done(f"3 down/up cycles clean; {len(base)} secrets (all versions) intact, audit verifies", data)


# --------------------------------------------------------------------------
# O10
# --------------------------------------------------------------------------

@check("O10")
def o10(c) -> Result:
    """(P1) list of 1,000 secrets p95 < 300 ms; 50 concurrent gets p95 < 200 ms"""
    owner = c.actor("owner@acme")
    proj = c.scratch_project("owner@acme")
    n = 1000
    keys = [f"O10_K{i:04d}" for i in range(n)]
    val = {k: f"o10-{k}-{secrets.token_hex(8)}" for k in keys}
    base = f"/projects/{proj}/envs/dev/secrets"
    res = c.parallel([(lambda k=k: c.api("PUT", f"{base}/{k}", actor=owner, json={"value": val[k]}, timeout=60))
                      for k in keys], workers=20)
    bad = [(k, r if isinstance(r, Exception) else r.status) for k, r in zip(keys, res)
           if isinstance(r, Exception) or not r.ok()]
    if bad:
        return c.error(f"seeding failed for {len(bad)} keys, first {bad[0]}")
    c.control(lambda: res[0], what="seed PUT")
    for _ in range(3):
        c.api("GET", base, actor=owner, timeout=60)
    lms = []
    for i in range(40):
        r = c.api("GET", base, actor=owner, timeout=60)
        lst = _items(_rj(r))
        cnt = len(lst) if lst is not None else None
        if not c.expect(r.status == 200 and cnt == n, f"list #{i} -> {r.status}, {cnt} items (want 1000)"):
            break
        lms.append(r.ms)
    p95l = _p95(lms)
    c.log("list ms: %s", [round(x) for x in lms])
    c.expect(p95l is not None and p95l < 300, f"list p95 = {p95l and round(p95l)} ms (want < 300)")
    pick = keys[::20][:50]

    def round_(measure):
        bar = threading.Barrier(len(pick))

        def one(k):
            bar.wait(timeout=30)
            return k, c.api("GET", f"{base}/{k}", actor=owner, timeout=60)
        out = c.parallel([(lambda k=k: one(k)) for k in pick], workers=len(pick))
        ms = []
        for item in out:
            if isinstance(item, Exception):
                c.expect(False, f"concurrent get raised {item!r}")
                continue
            k, r = item
            j = _rj(r)
            okv = r.status == 200 and isinstance(j, dict) and j.get("value") == val[k]
            if measure:
                c.expect(okv, f"concurrent GET {k} -> {r.status} (value match={okv})")
                ms.append(r.ms)
        return ms
    round_(False)
    gms = []
    for _ in range(3):
        gms += round_(True)
    p95g = _p95(gms)
    c.log("get ms: %s", [round(x) for x in sorted(gms)])
    c.expect(p95g is not None and p95g < 200, f"50-concurrent get p95 = {p95g and round(p95g)} ms (want < 200)")
    return c.done(f"list(1000) p95 {round(p95l or 0)} ms; 50-concurrent get p95 {round(p95g or 0)} ms",
                  {"list_p95_ms": p95l, "get_p95_ms": p95g, "list_n": len(lms), "get_n": len(gms),
                   "project": proj})


# --------------------------------------------------------------------------
# G3
# --------------------------------------------------------------------------

@check("G3")
def g3(c) -> Result:
    """init-env writes a real random master key; placeholder key -> server refuses"""
    d = c.tmp / "g3clone"
    g = _git(c, "clone", "-q", str(c.repo), str(d), timeout=300)
    if g.returncode != 0:
        return c.error(f"git clone rc={g.returncode}: {g.stderr[:200]!r}")
    placeholder = _env_get(d / ".env.example", "COFFER_MASTER_KEY")
    c.log(".env.example COFFER_MASTER_KEY present=%s len=%s", placeholder is not None,
          None if placeholder is None else len(placeholder))
    if placeholder is None:
        c.expect(False, ".env.example has no COFFER_MASTER_KEY line (placeholder undocumented)")
    keys = []
    for i in (1, 2):
        (d / ".env").unlink(missing_ok=True)
        p = subprocess.run(["bash", "./scripts/init-env.sh"], cwd=str(d), stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, timeout=120)
        k = _env_get(d / ".env", "COFFER_MASTER_KEY")
        bp = _env_get(d / ".env", "COFFER_BOOTSTRAP_ADMIN_PASSWORD")
        if k:
            c.secret(f"key:g3-run{i}", k, "key")
        if bp:
            c.secret(f"pw:g3-bootstrap{i}", bp, "password")
        c.log("init-env run %d rc=%s key_len=%s stdout=%s stderr=%s", i, p.returncode,
              len(k) if k else None, c.redact(p.stdout.decode("utf-8", "replace"))[:500],
              c.redact(p.stderr.decode("utf-8", "replace"))[:500])
        c.expect(p.returncode == 0, f"init-env.sh run {i} rc={p.returncode}")
        c.expect(bool(k), f"init-env.sh run {i}: no COFFER_MASTER_KEY in .env")
        if k:
            c.expect(_strict_b64_32(k), f"init-env.sh run {i}: master key is not base64 of 32 bytes (len {len(k)})")
            if placeholder is not None:
                c.expect(k != placeholder, f"init-env.sh run {i}: master key equals the .env.example placeholder")
        keys.append(k)
    if len(keys) == 2 and keys[0] and keys[1]:
        c.expect(keys[0] != keys[1], "init-env.sh wrote the same master key twice (not random)")
    ctl = c.env_override(set={}, wait=90)
    if not ctl.ready:
        c.error_once(f"control failed: unmodified .env did not boot (compose_rc={ctl.compose_rc}, exit={ctl.exit_code})")
        return c.done()
    # r2 (G3 on build-2): the control must show the override really recreated the server.
    if not ctl.recreated:
        c.error_once(f"control failed: override did not recreate the server container "
                     f"(cid {ctl.cid_before} -> {ctl.cid_after}, started {ctl.started_before} -> {ctl.started_after})")
        return c.done()
    c.control(lambda: c.http("GET", "/readyz"), what="unmodified .env boots (recreated container)")
    data = {"placeholder_len": None if placeholder is None else len(placeholder)}
    if placeholder is not None:
        ov = c.env_override(set={"COFFER_MASTER_KEY": placeholder}, wait=60)
        named = b"COFFER_MASTER_KEY" in (ov.logs or b"")
        crashed = (ov.exit_code not in (None, 0)) or ov.restarts >= 1 or \
            (str(ov.status or "").lower() in ("exited", "dead", "stopped") and ov.exit_code not in (None, 0))
        data.update({"compose_rc": ov.compose_rc, "ready": ov.ready, "running": ov.running,
                     "exit_code": ov.exit_code, "restarts": ov.restarts, "status": ov.status,
                     "recreated": ov.recreated, "log_names_key": named, "log_bytes": len(ov.logs or b"")})
        c.log("placeholder override: %s", data)
        c.expect(not ov.ready, "server BOOTED (/readyz 200) with the .env.example placeholder master key")
        if not ov.ready:
            # A non-ready server is only a refusal when there is evidence the server itself
            # refused: a container exists for this override AND it exited non-zero, crash-
            # looped, or logged a line naming COFFER_MASTER_KEY. Otherwise: no evidence.
            if not ov.recreated:
                c.error_once("placeholder override: no recreated server container to inspect "
                             f"(cid {ov.cid_before} -> {ov.cid_after}); refusal not evidenced")
            elif not (crashed or named):
                c.error_once(f"placeholder override: unready but no refusal evidence (exit={ov.exit_code} "
                             f"restarts={ov.restarts} status={ov.status} log names key={named})")
            else:
                c.expect(True, f"refused: exit={ov.exit_code} restarts={ov.restarts} log names key={named}")
        # recovery control: restored good .env must boot again on a recreated container
        rec = c.env_override(set={}, wait=90)
        data.update({"recovery_ready": rec.ready, "recovery_recreated": rec.recreated})
        if not (rec.ready and rec.recreated):
            c.error_once(f"recovery control failed: restored .env -> ready={rec.ready} recreated={rec.recreated} "
                         f"exit={rec.exit_code}")
        else:
            c.control(lambda: c.http("GET", "/readyz"), what="restored .env boots again (recovery)")
    return c.done("init-env keys random 32-byte, distinct; placeholder key -> server refused "
                  "(exit/crash/log evidence), recovered on the restored .env", data)


# --------------------------------------------------------------------------
# O8
# --------------------------------------------------------------------------

_O8_VARS = ("COFFER_MASTER_KEY", "COFFER_BOOTSTRAP_ADMIN_EMAIL", "COFFER_BOOTSTRAP_ADMIN_PASSWORD",
            "COFFER_PORT", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB")
_O8_BOOTSTRAP = ("COFFER_BOOTSTRAP_ADMIN_EMAIL", "COFFER_BOOTSTRAP_ADMIN_PASSWORD")
# r4: SPEC 5 binds 127.0.0.1:${COFFER_PORT:-8420}, a documented default, so booting with it
# unset is SPEC-conformant (never a fail); refusing is also accepted.
_O8_DEFAULTED = ("COFFER_PORT",)


@check("O8")
def o8(c) -> Result:
    """Unset each required env var -> non-zero exit naming it"""
    ctl = c.env_override(set={}, wait=90)
    if not ctl.ready:
        c.error_once(f"control failed: unmodified .env did not boot (compose_rc={ctl.compose_rc})")
        return c.done()
    c.control(lambda: c.http("GET", "/readyz"), what="unmodified .env boots")
    verdicts = {}
    for v in _O8_VARS:
        ov = c.env_override(unset=[v], wait=45)
        cerr = ov.compose_err.decode("utf-8", "replace")
        named_compose = ov.compose_rc != 0 and v in cerr
        named_logs = v.encode() in (ov.logs or b"")
        exited = (ov.exit_code not in (None, 0)) or ov.restarts >= 1 or not ov.running
        if named_compose:
            verdicts[v] = "pass: compose refused, names it"
        elif ov.ready:
            if v in _O8_BOOTSTRAP:
                verdicts[v] = "na-by-design: booted (users already exist)"
            elif v in _O8_DEFAULTED:
                verdicts[v] = "na-by-design: booted on the SPEC default (${COFFER_PORT:-8420})"
            else:
                verdicts[v] = "fail: booted with it unset"
        elif not named_logs:
            verdicts[v] = f"fail: refused but message does not name it (exit={ov.exit_code})"
        elif not exited:
            verdicts[v] = "fail: unready and named, but process did not exit"
        else:
            verdicts[v] = f"pass: exit={ov.exit_code} restarts={ov.restarts}, logs name it"
        c.log("O8 %s: compose_rc=%s ready=%s running=%s exit=%s restarts=%s -> %s", v, ov.compose_rc,
              ov.ready, ov.running, ov.exit_code, ov.restarts, verdicts[v])
        c.expect(not verdicts[v].startswith("fail"), f"unset {v}: {verdicts[v]}")
    return c.done("every required var refused with a named message: " +
                  ", ".join(f"{k}={v.split(':')[0]}" for k, v in verdicts.items()), {"verdicts": verdicts})


# --------------------------------------------------------------------------
# O7
# --------------------------------------------------------------------------

@check("O7")
def o7(c) -> Result:
    """backup -> wipe volume -> restore into fresh stack -> all intact; verify passes"""
    owners = _owners(c)
    if len(owners) != 2:
        return c.done()
    before, probs = _snapshot(c, owners)
    if probs or not before:
        return c.error(f"pre-backup snapshot incomplete: {probs[:3]} keys={len(before)}")
    canary_k = "acme/api/dev/CANARY"
    canary_v = (c.fx.get("canaries") or {}).get(canary_k)
    if not canary_v:
        return c.error("fixture canary missing")
    # r4: the audit comparison is on the DB event rows (every row, via psql), not on an API
    # list a server may cap (build saw 500 newest-first). The API lists are a control only.
    sql_before, why = _audit_sql(c)
    if sql_before is None:
        return c.error(f"pre-backup audit rows: {why}")
    for name, lab, path in (("acme", "owner@acme", "/audit"), ("globex", "owner@globex", "/audit"),
                            ("platform", "root", "/admin/audit")):
        st, lst, complete = _audit_all(c, lab, path)
        if st != 200 or lst is None:
            return c.error(f"pre-backup audit list {name} -> {st}")
        if not lst:
            return c.error(f"pre-backup audit list {name} is empty (control)")
        c.control(lambda: lib.CliResult(0, b"", b"", 0.0, []), what=f"pre-backup audit list {name}: {len(lst)} events")
    c.log("before: %d keys, audit rows %s", len(before), {k: len(v) for k, v in sql_before.items()})
    bp, path = c.backup("o7")
    size = path.stat().st_size if path.exists() else 0
    c.log("backup rc=%s size=%s", bp.rc, size)
    if not c.expect(bp.rc == 0 and size > 0, f"backup.sh rc={bp.rc}, file size {size}"):
        return c.done()
    wp = c.wipe_volumes()
    c.log("wipe_volumes rc=%s", wp.rc)
    up = c.up(timeout=240)
    if not c.wait_ready(60):
        return c.error(f"fresh stack after wipe not ready (up.sh rc={up.rc})")
    probe = c.api("GET", "/projects/api/envs/dev/secrets/CANARY", actor="owner@acme")
    pj = _rj(probe)
    if probe.status == 200 and isinstance(pj, dict) and pj.get("value") == canary_v:
        return c.error("wipe did not wipe: canary still readable before restore")
    c.log("wipe proof: owner GET canary before restore -> %s", probe.status)
    rp = c.restore(path)
    c.expect(rp.rc == 0, f"restore.sh rc={rp.rc}")
    ready = c.wait_ready(90)
    if not ready:
        c.log("not ready after restore; trying up.sh once")
        c.script("up.sh", timeout=240)
        ready = c.wait_ready(60)
    if not c.expect(ready, "stack not ready after restore"):
        return c.done()
    # r4: read the audit rows BEFORE any post-restore secret read (reads append events)
    sql_after, why = _audit_sql(c)
    if sql_after is None:
        c.error_once(f"post-restore audit rows: {why}")
    else:
        for t, rows_b in sql_before.items():
            aft: dict = {}
            for k in sql_after.get(t, []):
                aft[k] = aft.get(k, 0) + 1
            missing = 0
            for k in rows_b:
                if aft.get(k, 0) > 0:
                    aft[k] -= 1
                else:
                    missing += 1
            c.expect(missing == 0, f"audit table {t}: {missing}/{len(rows_b)} rows lost or changed by restore",
                     f"audit table {t}: all {len(rows_b)} pre-backup rows present byte-identical "
                     f"({len(sql_after.get(t, [])) - len(rows_b)} new)")
    for name, lab, path_ in (("acme", "owner@acme", "/audit"), ("globex", "owner@globex", "/audit"),
                             ("platform", "root", "/admin/audit")):
        st, lst, complete = _audit_all(c, lab, path_)
        c.expect(st == 200 and lst is not None, f"post-restore audit list {name} -> {st}",
                 f"post-restore audit list {name} -> 200 ({len(lst or [])} events)")
    after, probs2 = _snapshot(c, owners)
    c.expect(not probs2, f"post-restore reads failed: {probs2[:2]}")
    diff = _diff_snap(before, after)
    c.expect(not diff, f"{len(diff)} secrets differ after restore: {diff[:2]}")
    for lab in ("owner@acme", "owner@globex"):
        r = c.cli("audit", "verify", actor=lab, timeout=120)
        c.expect(r.rc == 0, f"{lab} `coffer audit verify` rc={r.rc} after restore")
        st, valid, j = _verify_api(c, lab, "/audit/verify")
        c.expect(st == 200 and valid, f"{lab} /audit/verify -> {st} {str(j)[:80]}")
    r = c.cli("admin", "audit", "verify", actor="root", timeout=120)
    c.expect(r.rc == 0, f"root `coffer admin audit verify` rc={r.rc} after restore")
    jk = c.junk_key()
    w = c.api("PUT", f"/projects/web/envs/dev/secrets/{jk}", actor="owner@acme", json={"value": "o7-post-restore"})
    rr = c.api("GET", f"/projects/web/envs/dev/secrets/{jk}", actor="owner@acme")
    c.expect(w.ok() and rr.status == 200 and (_rj(rr) or {}).get("value") == "o7-post-restore",
             f"post-restore write/read of junk key -> {w.status}/{rr.status}")
    return c.done(f"backup {size} B -> wipe -> restore: {len(before)} secrets (all versions) and all audit events intact; verify ok",
                  {"keys": len(before), "audit_rows": {k: len(v) for k, v in sql_before.items()}, "backup_bytes": size})


# --------------------------------------------------------------------------
# O5
# --------------------------------------------------------------------------

_TOKEN_SHAPE = re.compile(rb"cof_(?:pat|st)_[A-Za-z0-9_\-]{16,}")
_HDR_SHAPE = re.compile(rb"(?i)(authorization\"?\s*[:=]\s*\"?\s*bearer\s+[A-Za-z0-9_\-.]{8,}|\bcookie\"?\s*[:=]\s*\"?[^\s\"]{8,})")


@check("O5")
def o5(c) -> Result:
    """No Authorization, cookie, token, password or value in the logs"""
    sw = c.sweep()
    files = sw.files("logs")
    server_files = [f for f in files if f.name.endswith("-server.log")]
    total = sum(f.stat().st_size for f in files)
    c.log("log files: %d (%d server), %d bytes", len(files), len(server_files), total)
    if not server_files or not any(f.stat().st_size > 0 for f in server_files):
        return c.error("no non-empty server log in sweep cache")
    needles = sw.needles(("canary", "token", "password"))
    if not needles:
        return c.error("no needles registered")
    # scanner self-test on a synthetic buffer (positive control)
    lab, kind, val = next((n for n in needles if len(n[2].encode()) >= 12), (None, None, None))
    if lab is None:
        return c.error("no needle long enough to scan")
    test_hits: list = []
    sw._scan_bytes(b"xx" + base64.b64encode(val.encode()) + b"yy", [(lab, kind, val)], "selftest", "t", test_hits,
                   ("raw", "hex", "HEX", "b64"))
    if not test_hits:
        return c.error("scanner self-test found no hit")
    c.control(lambda: c.http("GET", "/healthz"), what="scanner self-test + server up")
    hits = sw.scan(sources=("logs",))
    for h in hits[:20]:
        c.log("HIT %s %s label=%s kind=%s enc=%s off=%s", h.source, h.file, h.label, h.kind, h.encoding, h.offset)
    c.expect(not hits, f"{len(hits)} secret hits in logs, first {hits[0].label} ({hits[0].kind}, {hits[0].encoding}) in {hits[0].file}"
             if hits else "no needle hits")
    shape_hits = []
    for f in files:
        try:
            b = f.read_bytes()
        except OSError:
            continue
        for rx, what in ((_TOKEN_SHAPE, "token-shaped string"), (_HDR_SHAPE, "auth/cookie header")):
            m = rx.search(b)
            if m:
                shape_hits.append(f"{what} in {f.name} @{m.start()}")
                c.log("SHAPE %s in %s at %d: %s", what, f.name, m.start(), c.redact(m.group(0)[:20].decode('utf-8', 'replace')) + "…")
    c.expect(not shape_hits, f"{shape_hits[0]}" if shape_hits else "no shapes")
    return c.done(f"{len(files)} log files ({total} B) clean of {len(needles)} needles and token/header shapes",
                  {"files": len(files), "bytes": total, "needles": len(needles)})
