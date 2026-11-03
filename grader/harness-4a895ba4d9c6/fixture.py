"""Coffer grading harness: setup (S0-S6), teardown, and the F1 fixture check.

Python 3.14 standard library only. Black-box: this file never reads build
source. It drives ./scripts/*, ./bin/coffer, and the HTTP API (SPEC 7.2).

Readings of CONTRACT.md where it is ambiguous. Each is the simplest one, and
each applies identically to both builds:

R1  Fixture CLI HOMEs live at WORK/homes/<label> (mode 0700), not under
    c.tmp, so they survive F1's per-check scratch dir. F1 passes `home=`
    explicitly on every c.cli call because fixture.json does not exist yet.
R2  `root` is also recorded in fixture.json "users" (role platform_admin,
    org null, password = the bootstrap password, its own CLI home + raw PAT),
    so lib can resolve the "root" label. root is not put through passwd.
R3  Users created with an initial password (both org owners, all six acme
    members) are onboarded as: `coffer login` (initial) -> `coffer passwd`
    -> `coffer login` (final). The second login keeps the HOME valid when a
    build revokes every PAT, including the current one, on a password change.
    If passwd does not exit 0, the step is recorded as a failure (F1 fails),
    `password` stays equal to `initial_password`, and the second login uses
    the initial password so later checks still have a usable fixture.
    The raw-API PAT (`pat`) is taken after onboarding, via POST /auth/token.
R4  Every canary value (including MULTI) goes to `coffer secrets set KEY`
    on stdin (no VALUE argument), never in argv. CANARY in acme/api/dev,
    acme/web/dev and both globex envs are set by the org owner. The
    acme/api/prod CANARY is set by writer@acme with --json (want exit 7);
    the change id is read from the JSON `change_id`, else from the last
    id-looking word on stdout. admin@acme approves it (want exit 0).
R5  Tokens are created by owner@acme with --json and `--name <label>`.
    TTLs: T_exp 1m, the others 7d. The token and id are taken from the
    JSON (any string starting `cof_st_`, and the `id` beside it); if the id
    is missing it is looked up in GET /tokens by name. T_exp.created_at is
    the harness UTC time right AFTER the create command returned
    (conservative), expires_at = created_at + 60 s.
R6  F1's verdict counts only the recorded CLI steps (rc vs want). Raw-API
    lookups (PATs, /me ids, org ids) never decide pass/fail; a missing one
    leaves the field null and later checks return error.
R7  S6 calibration logs root in with the CLI in WORK/homes/_calib (password
    on stdin) and runs `whoami` there with --json front, then end. It does not
    use COFFER_TOKEN (that is F11's subject). If no position parses, the
    json_position is "front" and cli.ok is False.
R8  setup() writes the bootstrap password (kind password), the master key
    (kind key) and the S6 raw root PAT (kind token) to OUT/secrets.jsonl in
    the CONTRACT 4 line format, mode 0600, because no Context exists yet.
R9  teardown() only removes in-repo bind-mount sources that are directories
    and are NOT tracked by git.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import secrets
import shutil
import signal
import socket
import string
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from registry import REGISTRY, Result, check

ALNUM = string.ascii_letters + string.digits
ACME_MEMBERS = [
    ("admin@acme", "admin"),
    ("admin2@acme", "admin"),
    ("writer@acme", "member"),
    ("reader@acme", "member"),
    ("viewer@acme", "member"),
    ("nogrant@acme", "member"),
]
ACME_GRANTS = [("writer@acme", "writer"), ("reader@acme", "reader"), ("viewer@acme", "viewer")]
TOKENS = [
    ("T_dev_r", "dev", "read", "7d"),
    ("T_dev_rw", "dev", "read-write", "7d"),
    ("T_prod_rw", "prod", "read-write", "7d"),
    ("T_exp", "dev", "read", "1m"),
    ("T_rev", "dev", "read", "7d"),
]
UUIDISH = re.compile(r"[A-Za-z0-9_-]{6,}")


# --------------------------------------------------------------------------
# small helpers (no lib dependency)
# --------------------------------------------------------------------------

def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _rand(n: int) -> str:
    return "".join(secrets.choice(ALNUM) for _ in range(n))


def _password() -> str:
    return "Pw" + _rand(22)


def _email(label: str) -> str:
    return label + ".test"


def _read_env(path: Path) -> dict:
    env = {}
    try:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            if k.startswith("export "):
                k = k[7:].strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            env[k] = v
    except OSError:
        pass
    return env


def _write_json(path: Path, obj, mode: int = 0o644) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False))
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _walk(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def _as_list(obj) -> list:
    """First list of dicts found in a JSON document (top-level or wrapped)."""
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        for v in obj.values():
            if isinstance(v, list) and all(isinstance(x, dict) for x in v):
                return v
    return []


def _json_or_none(data: bytes):
    try:
        return json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return None


class _Log:
    def __init__(self, path: Path):
        self.path = path
        self.redact: dict[str, str] = {}
        path.parent.mkdir(parents=True, exist_ok=True)

    def scrub(self, s: str) -> str:
        for label, val in sorted(self.redact.items(), key=lambda kv: -len(kv[1])):
            if val:
                s = s.replace(val, f"«{label}»")
        return s

    def __call__(self, msg: str) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(f"{_utc()} {self.scrub(msg)}\n")


def _proc(argv, *, cwd=None, timeout=300.0, env=None, stdin: bytes = b"", log: _Log | None = None):
    t0 = time.monotonic()
    try:
        p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    except OSError as e:
        if log:
            log(f"exec {argv!r} failed: {e}")
        return 127, b"", str(e).encode(), (time.monotonic() - t0) * 1000
    try:
        out, err = p.communicate(stdin, timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        out, err = p.communicate()
        rc = 124
    ms = (time.monotonic() - t0) * 1000
    if log:
        log(f"$ {' '.join(map(str, argv))} -> rc={rc} ms={ms:.0f}")
        if out:
            log("  stdout: " + out[-4000:].decode("utf-8", "replace"))
        if err:
            log("  stderr: " + err[-4000:].decode("utf-8", "replace"))
    return rc, out, err, ms


def _raw_http(port: int, method: str, path: str, obj=None, bearer: str | None = None, timeout=15.0):
    """(status, body bytes); status 0 on transport error."""
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        headers = {}
        body = None
        if obj is not None:
            body = json.dumps(obj).encode()
            headers["Content-Type"] = "application/json"
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, data
    except (OSError, http.client.HTTPException) as e:
        return 0, str(e).encode()


def _paths(run):
    work = Path(getattr(run, "work"))
    out = Path(getattr(run, "out"))
    repo = Path(getattr(run, "repo", None) or work / "repo")
    return work, out, repo


def _append_secret(out: Path, label: str, value: str, kind: str) -> None:
    if not value:
        return
    p = out / "secrets.jsonl"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps({"label": label, "value": value, "kind": kind}, ensure_ascii=False) + "\n")
    os.chmod(p, 0o600)


def _clean_cli_env(home: Path, url: str) -> dict:
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "TERM": "dumb", "COFFER_URL": url}


# --------------------------------------------------------------------------
# setup S0-S6
# --------------------------------------------------------------------------

PG_IMAGE_FQ = "docker.io/library/postgres:16"
PG_SHORT = "postgres:16"


def _images(engine: str, log) -> list:
    """Image store record: the postgres images (repo:tag id) plus the total image count.
    Unrelated host images are counted, not listed."""
    rc, o, e, _ = _proc([engine, "images", "--format", "{{.Repository}}:{{.Tag}} {{.ID}}"], timeout=60)
    if rc != 0:
        return [f"images rc={rc}"]
    allimg = [x.strip() for x in o.decode("utf-8", "replace").splitlines() if x.strip()]
    pg = sorted(x for x in allimg if re.search(r"(^|/)library/postgres:|^postgres:", x))
    return pg + [f"(total images: {len(allimg)})"]


def host_prep(st: dict, log) -> bool:
    """Same host prep for every build (see setup ENV step). Returns True when the
    positive control (non-TTY `<engine> create postgres:16`) succeeds."""
    engine = (st.get("compose") or ["podman"])[0]
    info: dict = {"engine": engine, "image": PG_IMAGE_FQ}
    st["env_prep"] = info
    info["images_before"] = _images(engine, log)
    if engine == "podman":
        # user-level short-name alias (podman reads $XDG_CONFIG_HOME/containers/registries.conf.d)
        cfg = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")) / "containers" / "registries.conf.d"
        try:
            cfg.mkdir(parents=True, exist_ok=True)
            (cfg / "000-coffer-grade-postgres.conf").write_text(
                '[aliases]\n"postgres" = "docker.io/library/postgres"\n', encoding="utf-8")
            info["alias_file"] = str(cfg / "000-coffer-grade-postgres.conf")
        except OSError as ex:
            info["alias_error"] = str(ex)
    rc = 1
    for attempt in (1, 2):  # rule 4: retry a network command once
        rc, o, e, ms = _proc([engine, "pull", "-q", PG_IMAGE_FQ], timeout=600, log=log)
        info[f"pull_rc_{attempt}"] = rc
        if rc == 0:
            break
        time.sleep(5)
    info["pull_rc"] = rc
    info["images_after"] = _images(engine, log)
    st["image_store"] = info["images_after"]
    # positive control: the exact SPEC short name, no TTY (stdin is a pipe, not a terminal)
    name = f"coffer-grade-ctl-{_rand(6)}"
    rc, o, e, _ = _proc([engine, "create", "--name", name, PG_SHORT, "true"], timeout=120, log=log)
    info["control_create_rc"] = rc
    info["control_err"] = e.decode("utf-8", "replace")[-400:]
    _proc([engine, "rm", "-f", name], timeout=60, log=log)
    if rc != 0:
        info["why"] = (f"VOID/ENV: positive control `{engine} create {PG_SHORT}` (no TTY) rc={rc}: "
                       f"{info['control_err'].strip()[:200]}")
        log("ENV prep FAILED: " + info["why"])
        return False
    log(f"ENV prep ok: pull rc={info['pull_rc']}, control create {PG_SHORT} rc=0, store={info['images_after']}")
    return True


def setup(run) -> dict:
    work, out, repo = _paths(run)
    out.mkdir(parents=True, exist_ok=True)
    log = _Log(out / "logs" / "setup.log")
    st: dict = {"started": _utc(), "failed_at": None, "static_ok": False}

    def save():
        _write_json(out / "setup.json", st)

    def fail(step: str, why: str):
        if st["failed_at"] is None:
            st["failed_at"] = step
            st["failed_why"] = why
        log(f"SETUP FAILED at {step}: {why}")

    try:
        # S0 clone
        bundle = str(getattr(run, "bundle"))
        rc, o, e, _ = _proc(["git", "clone", bundle, str(repo)], timeout=300, log=log)
        st["clone_rc"] = rc
        if rc == 0:
            rc2, o2, _, _ = _proc(["git", "-C", str(repo), "rev-parse", "HEAD"], log=log)
            st["commit"] = o2.decode().strip() if rc2 == 0 else None
            st["static_ok"] = True
        else:
            st["commit"] = None
            fail("S0", f"git clone rc={rc}")
        save()

        # S1 compose detection (always recorded)
        st["compose"] = None
        st["compose_version"] = None
        for prefix in (["podman", "compose"], ["docker", "compose"]):
            rc, o, e, _ = _proc(prefix + ["version"], timeout=60, log=log)
            if rc == 0:
                st["compose"] = prefix
                st["compose_version"] = (o or e).decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
                st["compose_version"] = st["compose_version"][0]
                break
        if st["compose"] is None:
            fail("S1", "neither podman compose nor docker compose works")
        save()
        if st["failed_at"]:
            return st

        # S2 init-env
        rc, o, e, _ = _proc(["bash", "./scripts/init-env.sh"], cwd=repo, timeout=120)
        envf = repo / ".env"
        env = _read_env(envf)
        for k in ("COFFER_BOOTSTRAP_ADMIN_PASSWORD", "COFFER_MASTER_KEY"):
            if env.get(k):
                log.redact[k] = env[k]
        log(f"$ ./scripts/init-env.sh -> rc={rc}")
        log("  stdout: " + o.decode("utf-8", "replace"))
        log("  stderr: " + e.decode("utf-8", "replace"))
        st["init_env_rc"] = rc
        st["env_keys"] = sorted(env)
        if envf.exists():
            shutil.copy2(envf, work / "base.env")
        _append_secret(out, "bootstrap_password", env.get("COFFER_BOOTSTRAP_ADMIN_PASSWORD", ""), "password")
        _append_secret(out, "master_key", env.get("COFFER_MASTER_KEY", ""), "key")
        if rc != 0 or not envf.exists():
            fail("S2", f"init-env.sh rc={rc} env_exists={envf.exists()}")
        elif not env.get("COFFER_BOOTSTRAP_ADMIN_PASSWORD"):
            fail("S2", "COFFER_BOOTSTRAP_ADMIN_PASSWORD missing from .env")
        port = int(env.get("COFFER_PORT") or 8420) if (env.get("COFFER_PORT") or "8420").isdigit() else 8420
        st["port"] = port
        st["base_url"] = f"http://127.0.0.1:{port}"
        save()
        if st["failed_at"]:
            return st

        # S3 build
        rc, o, e, ms = _proc(["bash", "./scripts/build.sh"], cwd=repo, timeout=1200, log=log)
        binp = repo / "bin" / "coffer"
        st["build_rc"] = rc
        st["build_ms"] = round(ms)
        st["bin_ok"] = binp.is_file() and os.access(binp, os.X_OK)
        if rc != 0 or not st["bin_ok"]:
            fail("S3", f"build.sh rc={rc} bin_ok={st['bin_ok']}")
        save()
        if st["failed_at"]:
            return st

        # ENV host prep (r2 fix for G2/G3/F*/S*/X*/A*/O* on build-1): SPEC mandates the
        # short name `postgres:16`. Rootless podman in short-name "enforcing" mode cannot
        # prompt without a TTY, and an image store emptied by an earlier prune made the
        # short name unresolvable. Identical for both builds: pin the alias, pre-pull the
        # fully-qualified image, record the image store, then a non-TTY positive control.
        # A failure here is the HOST, not the build: the round is VOID (failed_at ENV).
        envp = host_prep(st, log)
        save()
        if not envp:
            fail("ENV", st.get("env_prep", {}).get("why") or "host prep failed")
            st["void"] = True
            save()
            return st

        # S4 up. Null-reference fix (VALIDATION.md N1): the port must be free BEFORE up.sh,
        # otherwise a leftover server (an earlier arm, a stray process) answers /readyz and
        # G2 plus every runtime check would grade the wrong server.
        pre, _ = _raw_http(port, "GET", "/readyz", timeout=3.0)
        st["port_busy_before_up"] = pre != 0
        if pre != 0:
            log(f"S4: 127.0.0.1:{port} already answers (/readyz -> {pre}) before up.sh")
            fail("S4", f"port {port} already in use before up.sh (/readyz -> {pre})")
            save()
            return st
        rc, o, e, ms = _proc(["bash", "./scripts/up.sh"], cwd=repo, timeout=200, log=log)
        st["up_rc"] = rc
        st["up_ms"] = round(ms)
        status, _ = _raw_http(port, "GET", "/readyz")
        st["readyz_status"] = status
        log(f"GET /readyz -> {status}")
        if status != 200:
            fail("S4", f"up.sh rc={rc} readyz={status}")
        save()
        if st["failed_at"]:
            return st

        # S4b container discovery (r2 fix X1/O1-O4/X18): every container/log/sweep check
        # depends on finding the server and db containers. Fail setup if they cannot be found.
        try:
            import lib
            found = lib.discover_containers(st["compose"][0], repo, st["compose"])
            st["containers"] = {svc: cid[:12] for cid, svc, _ in found}
            log(f"S4b containers: {st['containers']}")
            has_compose = any((repo / n).is_file() for n in
                              ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"))
            st["compose_file"] = has_compose
            if not has_compose:
                # no compose file (SPEC 106 requires compose.yaml): container rows then error
                # individually ("no server container"); O9 grades the missing file.
                log("S4b: no compose file at repo root; container discovery skipped")
            elif "server" not in st["containers"] or "db" not in st["containers"]:
                log("S4b discovery diag: " + lib.discovery_diag(st["compose"][0], repo, st["compose"]))
                fail("S4b", f"compose services server/db not found among containers {st['containers']}")
                save()
                return st
        except Exception as ex:
            fail("S4b", f"container discovery raised {type(ex).__name__}: {ex}")
            save()
            return st
        save()

        # S5 proxy (failure here is not a setup failure; proxied checks see proxy_url None)
        st["proxy_url"] = None
        st["proxy_pid"] = None
        pport = port + 10000
        search = os.environ.get("PATH", "") + os.pathsep + str(Path.home() / ".local" / "bin")
        mitm = shutil.which("mitmdump", path=search)
        if not mitm:
            st["proxy_error"] = "mitmdump not found"
            log("S5: mitmdump not found")
        else:
            addon = work / "proxy_addon.py"
            addon.write_text(
                "import json, time\n"
                f"OUT = {str(out / 'proxy_urls.jsonl')!r}\n"
                "class W:\n"
                "    def response(self, flow):\n"
                "        try:\n"
                "            with open(OUT, 'a') as f:\n"
                "                f.write(json.dumps({'t': time.time(), 'method': flow.request.method,\n"
                "                    'url': flow.request.path,\n"
                "                    'status': flow.response.status_code if flow.response else None}) + '\\n')\n"
                "        except Exception:\n"
                "            pass\n"
                "addons = [W()]\n")
            plog = open(work / "proxy.log", "ab")
            p = subprocess.Popen(
                [mitm, "--mode", f"reverse:http://127.0.0.1:{port}", "--listen-host", "127.0.0.1",
                 "--listen-port", str(pport), "-w", str(work / "proxy.flows"), "-s", str(addon)],
                stdin=subprocess.DEVNULL, stdout=plog, stderr=plog, start_new_session=True)
            plog.close()
            listening = False
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and p.poll() is None:
                try:
                    with socket.create_connection(("127.0.0.1", pport), timeout=1):
                        listening = True
                        break
                except OSError:
                    time.sleep(0.25)
            if listening:
                st["proxy_url"] = f"http://127.0.0.1:{pport}"
                st["proxy_pid"] = p.pid
            else:
                st["proxy_error"] = f"mitmdump not listening (exit={p.poll()})"
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
            log(f"S5: proxy_url={st['proxy_url']} pid={st['proxy_pid']} err={st.get('proxy_error')}")
        save()

        # S6 root raw login + CLI calibration
        email = env.get("COFFER_BOOTSTRAP_ADMIN_EMAIL") or "root@bench.test"
        pw = env["COFFER_BOOTSTRAP_ADMIN_PASSWORD"]
        status, body = _raw_http(port, "POST", "/api/v1/auth/token", {"email": email, "password": pw})
        st["root_login_status"] = status
        doc = _json_or_none(body)
        if isinstance(doc, dict) and isinstance(doc.get("token"), str):
            log.redact["root_setup_pat"] = doc["token"]
            _append_secret(out, "root_setup_pat", doc["token"], "token")
        log(f"S6: POST /api/v1/auth/token as root -> {status}")
        cli = {"json_position": "front", "bin": str(repo / "bin" / "coffer"), "ok": False}
        home = work / "homes" / "_calib"
        home.mkdir(parents=True, exist_ok=True, mode=0o700)
        cenv = _clean_cli_env(home, st["base_url"])
        rc, o, e, _ = _proc([cli["bin"], "login", "--email", email], cwd=work, env=cenv,
                            stdin=(pw + "\n").encode(), timeout=60, log=log)
        cli["login_rc"] = rc
        tried = {}
        for pos in ("front", "end"):
            argv = [cli["bin"], "--json", "whoami"] if pos == "front" else [cli["bin"], "whoami", "--json"]
            rc, o, e, _ = _proc(argv, cwd=work, env=cenv, timeout=60, log=log)
            parsed = _json_or_none(o)
            tried[pos] = rc
            if isinstance(parsed, dict):
                cli["json_position"] = pos
                cli["ok"] = True
                break
        cli["tried"] = tried
        st["cli"] = cli
        save()
    except Exception as ex:  # never raise
        fail(st.get("failed_at") or "internal", f"{type(ex).__name__}: {ex}")
        save()
    st["finished"] = _utc()
    save()
    return st


# --------------------------------------------------------------------------
# teardown
# --------------------------------------------------------------------------

def _bind_dirs(repo: Path) -> list[Path]:
    found = []
    for name in ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"):
        f = repo / name
        if not f.exists():
            continue
        for line in f.read_text(errors="replace").splitlines():
            m = re.match(r"""^\s*(?:-\s*|source:\s*)["']?(\.{1,2}/[^:"'\s]*)""", line)
            if not m:
                continue
            p = (repo / m.group(1)).resolve()
            if p == repo.resolve() or repo.resolve() not in p.parents:
                continue
            if p.is_dir():
                tracked = subprocess.run(["git", "-C", str(repo), "ls-files", "--error-unmatch", str(p)],
                                         capture_output=True).returncode == 0
                if not tracked and p not in found:
                    found.append(p)
    return found


def teardown(run) -> dict:
    work, out, repo = _paths(run)
    log = _Log(out / "logs" / "setup.log")
    res: dict = {"started": _utc()}
    st = {}
    try:
        st = json.loads((out / "setup.json").read_text())
    except (OSError, ValueError):
        pass
    try:
        import lib
        ctx = lib.Context(REGISTRY["F1"], work, out)
        ctx.sweep_snapshot("teardown")
        res["snapshot"] = "ok"
    except Exception as ex:
        res["snapshot"] = f"failed: {type(ex).__name__}: {ex}"
    pid = st.get("proxy_pid")
    if pid:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(int(pid), sig)
            except OSError:
                break
            time.sleep(2)
        res["proxy"] = "stopped"
    if repo.exists():
        if (repo / "scripts" / "down.sh").exists():
            res["down_rc"] = _proc(["bash", "./scripts/down.sh"], cwd=repo, timeout=180, log=log)[0]
        prefix = st.get("compose") or ["podman", "compose"]
        res["down_v_rc"] = _proc(list(prefix) + ["down", "-v"], cwd=repo, timeout=300, log=log)[0]
        removed = []
        try:
            for d in _bind_dirs(repo):
                if prefix[0] == "podman":
                    rc = _proc(["podman", "unshare", "rm", "-rf", str(d)], timeout=120, log=log)[0]
                else:
                    shutil.rmtree(d, ignore_errors=True)
                    rc = 0
                removed.append([str(d), rc])
        except Exception as ex:
            res["bind_error"] = f"{type(ex).__name__}: {ex}"
        res["bind_removed"] = removed
    res["finished"] = _utc()
    log(f"teardown: {json.dumps(res)}")
    return res


# --------------------------------------------------------------------------
# F1: the fixture, entirely through the CLI
# --------------------------------------------------------------------------

@check("F1")
def f1(c) -> Result:
    work, out = Path(c.work), Path(c.out)
    homes = work / "homes"
    homes.mkdir(parents=True, exist_ok=True, mode=0o700)
    known: dict[str, str] = {}
    seen: set[str] = set()

    def sec(label: str, value: str) -> str:
        if value:
            known[label] = value
            c.secret(label, value)
        return value

    def scrub(s: str) -> str:
        for label, val in sorted(known.items(), key=lambda kv: -len(kv[1])):
            s = s.replace(val, f"«{label}»")
        return s

    def canary() -> str:
        while True:
            v = _rand(40)
            if v not in seen:
                seen.add(v)
                return v

    fx: dict = {"orgs": {}, "users": {}, "tokens": {},
                "projects": {"acme": {"api": ["dev", "prod"], "web": ["dev"]},
                             "globex": {"api": ["dev", "prod"]}},
                "protected": [["acme", "api", "prod"]],
                "canaries": {}, "multi_core": None, "changes": {}, "steps": [],
                "started": _utc()}

    def save():
        _write_json(out / "fixture.json", fx, 0o600)

    def home_of(label: str) -> Path:
        h = homes / label
        h.mkdir(parents=True, exist_ok=True, mode=0o700)
        return h

    def step(actor: str, args: list[str], *, stdin: bytes = b"", want: int = 0, js: bool = False):
        r = c.cli(*args, home=home_of(actor), stdin=stdin, json=js)
        rec = {"actor": actor, "argv": "coffer " + " ".join(args) + (" --json" if js else ""),
               "rc": r.rc, "want": want}
        if r.rc != want:
            rec["err"] = scrub((r.err or b"").decode("utf-8", "replace").strip())[:300]
        fx["steps"].append(rec)
        c.log(f"F1 step [{actor}] {rec['argv']} -> rc={r.rc} want={want}")
        return r

    def raw_login(label: str) -> None:
        u = fx["users"][label]
        r = c.http("POST", "/api/v1/auth/token", json={"email": u["email"], "password": u["password"]})
        doc = None
        try:
            doc = r.json()
        except ValueError:
            pass
        if isinstance(doc, dict) and isinstance(doc.get("token"), str):
            u["pat"] = sec(f"pat:{label}", doc["token"])
            user = doc.get("user") if isinstance(doc.get("user"), dict) else {}
            u["user_id"] = user.get("id") or user.get("user_id")
        else:
            c.log(f"F1 raw login {label} -> {r.status} (no token)")
            return
        if not u.get("user_id"):
            m = c.http("GET", "/api/v1/me", headers={"Authorization": f"Bearer {u['pat']}"})
            try:
                md = m.json()
                if isinstance(md, dict):
                    inner = md.get("user") if isinstance(md.get("user"), dict) else md
                    u["user_id"] = inner.get("id") or inner.get("user_id")
            except ValueError:
                pass

    def new_user(label: str, org: str, role: str) -> str:
        ip = sec(f"pw0:{label}", _password())
        fx["users"][label] = {"email": _email(label), "password": ip, "initial_password": ip,
                              "user_id": None, "org": org, "role": role, "pat": None,
                              "home": str(home_of(label))}
        return ip

    def onboard(label: str) -> None:
        u = fx["users"][label]
        ip = u["initial_password"]
        step(label, ["login", "--email", u["email"]], stdin=(ip + "\n").encode())
        fp = sec(f"pw:{label}", _password())
        r = step(label, ["passwd"], stdin=f"{ip}\n{fp}\n".encode())
        if r.rc == 0:
            u["password"] = fp
        step(label, ["login", "--email", u["email"]], stdin=(u["password"] + "\n").encode())
        raw_login(label)
        save()

    try:
        # --- root ----------------------------------------------------------
        env = _read_env(Path(c.repo) / ".env")
        rpw = env.get("COFFER_BOOTSTRAP_ADMIN_PASSWORD")
        remail = env.get("COFFER_BOOTSTRAP_ADMIN_EMAIL") or "root@bench.test"
        if not rpw:
            save()
            return c.error("bootstrap password missing from .env")
        sec("bootstrap_password", rpw)
        fx["users"]["root"] = {"email": remail, "password": rpw, "initial_password": rpw,
                               "user_id": None, "org": None, "role": "platform_admin",
                               "pat": None, "home": str(home_of("root"))}
        step("root", ["login", "--email", remail], stdin=(rpw + "\n").encode())
        raw_login("root")
        save()

        # --- orgs + owners ---------------------------------------------------
        for org in ("acme", "globex"):
            lbl = f"owner@{org}"
            ip = new_user(lbl, org, "owner")
            step("root", ["admin", "org", "create", org, "--owner-email", _email(lbl)],
                 stdin=(ip + "\n").encode())
        for org in ("acme", "globex"):
            onboard(f"owner@{org}")

        # --- acme members ---------------------------------------------------
        for lbl, role in ACME_MEMBERS:
            ip = new_user(lbl, "acme", role)
            step("owner@acme", ["member", "add", _email(lbl), "--role", role], stdin=(ip + "\n").encode())
        save()
        for lbl, _ in ACME_MEMBERS:
            onboard(lbl)

        # --- projects / envs / grants ---------------------------------------
        o = "owner@acme"
        step(o, ["project", "create", "api"])
        step(o, ["env", "create", "dev", "-p", "api"])
        step(o, ["env", "create", "prod", "-p", "api", "--protected"])
        step(o, ["project", "create", "web"])
        step(o, ["env", "create", "dev", "-p", "web"])
        for lbl, level in ACME_GRANTS:
            step(o, ["grant", "set", _email(lbl), "-p", "api", "--level", level])
        g = "owner@globex"
        step(g, ["project", "create", "api"])
        step(g, ["env", "create", "dev", "-p", "api"])
        step(g, ["env", "create", "prod", "-p", "api"])
        save()

        # --- canaries -------------------------------------------------------
        def plant(actor, org, proj, envn, key, value, want=0, js=False):
            path = f"{org}/{proj}/{envn}/{key}"
            fx["canaries"][path] = sec(f"canary:{path}", value)
            return step(actor, ["secrets", "set", key, "-p", proj, "-e", envn],
                        stdin=value.encode("utf-8"), want=want, js=js)

        plant(o, "acme", "api", "dev", "CANARY", canary())
        core = canary()
        fx["multi_core"] = sec("canary:multi_core", core)
        multi = core + '"' + "\\" + "$HOME" + "\n" + "\r\n" + "\U0001F600" + "\x01" + core[::-1]
        plant(o, "acme", "api", "dev", "MULTI", multi)
        plant(o, "acme", "web", "dev", "CANARY", canary())
        r = plant("writer@acme", "acme", "api", "prod", "CANARY", canary(), want=7, js=True)
        cid = None
        d = _json_or_none(r.out)
        if isinstance(d, dict):
            cid = d.get("change_id") or d.get("id")
        if not cid:
            words = UUIDISH.findall((r.out or b"").decode("utf-8", "replace"))
            cid = words[-1] if words else None
        fx["changes"]["fixture_prod"] = cid
        save()
        if cid:
            step("admin@acme", ["change", "approve", str(cid)])
        else:
            fx["steps"].append({"actor": "admin@acme", "argv": "coffer change approve <no change id>",
                                "rc": None, "want": 0, "err": "no change id from protected set"})
        plant(g, "globex", "api", "dev", "CANARY", canary())
        plant(g, "globex", "api", "prod", "CANARY", canary())
        save()

        # --- tokens ---------------------------------------------------------
        for name, envn, access, ttl in TOKENS:
            r = step(o, ["token", "create", "-p", "api", "-e", envn, "--access", access,
                         "--ttl", ttl, "--name", name], js=True)
            after = datetime.now(timezone.utc)
            tok, tid, server_exp = None, None, None
            d = _json_or_none(r.out)
            for node in _walk(d):
                for v in node.values():
                    if isinstance(v, str) and v.startswith("cof_st_"):
                        tok = v
                        tid = node.get("id") or node.get("token_id")
                        server_exp = node.get("expires_at")
                        break
                if tok:
                    break
            if not tok:
                m = re.search(r"cof_st_[A-Za-z0-9_\-]+", (r.out or b"").decode("utf-8", "replace"))
                tok = m.group(0) if m else None
            rec = {"id": tid, "token": sec(f"token:{name}", tok) if tok else None,
                   "project": "api", "env": envn, "access": access, "ttl": ttl, "name": name}
            if name == "T_exp":
                rec["created_at"] = after.isoformat().replace("+00:00", "Z")
                rec["expires_at"] = (after + timedelta(seconds=60)).isoformat().replace("+00:00", "Z")
                rec["server_expires_at"] = server_exp
            fx["tokens"][name] = rec
            save()
        # fill missing ids from GET /tokens by name
        if any(t["token"] and not t["id"] for t in fx["tokens"].values()) and fx["users"][o].get("pat"):
            lr = c.http("GET", "/api/v1/tokens", headers={"Authorization": f"Bearer {fx['users'][o]['pat']}"})
            try:
                rows = _as_list(lr.json())
            except ValueError:
                rows = []
            for t in fx["tokens"].values():
                if t["token"] and not t["id"]:
                    for row in rows:
                        if row.get("name") == t["name"]:
                            t["id"] = row.get("id")
        tr = fx["tokens"].get("T_rev", {})
        if tr.get("id"):
            step(o, ["token", "revoke", str(tr["id"])])
            tr["revoked_at"] = _utc()
        else:
            fx["steps"].append({"actor": o, "argv": "coffer token revoke <no T_rev id>",
                                "rc": None, "want": 0, "err": "no T_rev id"})
        save()

        # --- org ids (raw API as root) ---------------------------------------
        rpat = fx["users"]["root"].get("pat")
        if rpat:
            lr = c.http("GET", "/api/v1/admin/orgs", headers={"Authorization": f"Bearer {rpat}"})
            try:
                rows = _as_list(lr.json())
            except ValueError:
                rows = []
            for org in ("acme", "globex"):
                for row in rows:
                    if row.get("slug") == org:
                        fx["orgs"][org] = {"id": row.get("id")}
        for org in ("acme", "globex"):
            fx["orgs"].setdefault(org, {"id": None})
    except Exception as ex:
        fx["internal_error"] = f"{type(ex).__name__}: {ex}"
        fx["finished"] = _utc()
        save()
        raise
    fx["finished"] = _utc()
    save()

    bad = [s for s in fx["steps"] if s["rc"] != s["want"]]
    data = {"steps": len(fx["steps"]), "bad": len(bad),
            "missing_pat": [k for k, u in fx["users"].items() if not u.get("pat")],
            "missing_token": [k for k, t in fx["tokens"].items() if not t.get("token") or not t.get("id")]}
    if bad:
        b = bad[0]
        return c.fail(f"[{b['actor']}] {b['argv']} -> rc={b['rc']} want={b['want']}"
                      f"{': ' + b['err'] if b.get('err') else ''} (+{len(bad) - 1} more bad)", data)
    return c.ok(f"{len(fx['steps'])} CLI steps ok", data)
