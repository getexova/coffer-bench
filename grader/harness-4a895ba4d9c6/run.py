"""Coffer grading harness: the runner (CONTRACT.md §6, §7, §8).

    python3 -I run.py --bundle PATH --work DIR --out DIR [--only ID[,ID...]] [--list]

Python standard library only. Never reads a build's source; it only drives
fixture.setup/teardown, one subprocess per check, compose/psql in the db
container for checkpoint/rollback, and GET /readyz for the guard.

Readings chosen where CONTRACT.md is ambiguous (simplest reading, identical
for both builds):
 R1  Execution order = §6.1: setup -> non-na rows except E1 in ascending
     Row.order -> teardown -> E1 -> na rows. results.jsonl is written in that
     execution order, so G1 (order 0, na) is written with the other na rows
     at the end. Rows outside an --only closure are written as `skip` at
     their position; na rows are always written as `na`.
 R2  Setup failure step: fixture's setup dict key `failed_step` (or
     `failed_at`) wins if present; otherwise S0 if clone_rc != 0, S1 if no
     compose prefix, S2 if init_env_rc != 0, S3 if build_rc != 0 or not
     bin_ok, S4 if readyz_status != 200 (up_rc alone is judged by G2).
     Stack checks then record `error: setup failed at Sx`; static checks
     still run when S0 succeeded, else they record the same error.
 R3  The `base` checkpoint is taken right after F1; if F1 is not in the
     selected set it is taken right after setup (when setup succeeded).
 R4  The child writes its raw result to WORK/childres/<ID>.json; the parent
     applies, in order: runner-only status from a check -> error; pass with
     a 5xx seen and not allow_5xx -> fail; pass on a denial row with
     controls == 0 -> error: no positive control. 5xx inside denied/same_404
     probes is lib's job (it records a failed expect).
 R5  A destructive row whose checkpoint fails is not run: it records
     `error: checkpoint failed: ...` and rollback `n/a`.
 R6  Rollback succeeds when /readyz is 200 and, if fixture.json has the
     owner@acme PAT and the acme/api/dev/CANARY value, a raw-API GET returns
     that value. Without those fixture fields it is `ok (readyz only)`.
     A non-zero pg_restore rc is logged but verification decides.
 R7  The guard runs after every check except E1 while setup succeeded and
     the stack is not dead; otherwise `n/a`.
 R8  Summary: p0_possible = sum of points_possible over P0 rows (2 points)
     whose status is not na/skip. Verdict (full runs only): any blocker with
     fail/timeout -> NOT SHIPPABLE; else p0_pct >= 75 -> FIX-THEN-SHIP; else
     NOT SHIPPABLE. Never SHIP (G1 is manual). A blocker in error is listed
     in `errors` only, and the note says PROVISIONAL.
 R9  A module that fails to import does not stop the run: its rows record
     the child's import error. Only fixture.py failing to import makes setup
     fail at S0.
 R10 `--list` marks a check `stub` when its function's only global name is
     `not_implemented` (the stub shape), `impl` otherwise.
 R11 Processes a check starts with start_new_session=True (cli_spawn) leave
     the check's process group; the runner kills only the check's group.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import http.client
import importlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import registry  # noqa: E402
from registry import Result  # noqa: E402

DATA_MAX = 16 * 1024


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _first_line(s: str) -> str:
    s = str(s).strip()
    return s.splitlines()[0] if s else ""


def _write_json(path: Path, obj) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=1, default=str))
    os.replace(tmp, path)


def _read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def _parse_env(path: Path) -> dict:
    env = {}
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return env
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        env[k.strip()] = v
    return env


def _qi(name: str) -> str:
    """Quote a SQL identifier."""
    return '"' + str(name).replace('"', '""') + '"'


def _killpg(p: subprocess.Popen, grace: float = 5.0) -> None:
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        p.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _run(argv, *, cwd, timeout, stdin: bytes | None = None, stdout_path: Path | None = None):
    """Run argv (no shell) in its own session. Returns (rc, out, err); rc 124 on timeout."""
    out_f = open(stdout_path, "wb") if stdout_path else None
    try:
        try:
            p = subprocess.Popen(argv, cwd=str(cwd), stdin=subprocess.PIPE,
                                 stdout=out_f if out_f else subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
        except OSError as e:
            return 127, b"", str(e).encode()
        try:
            out, err = p.communicate(input=stdin or b"", timeout=timeout)
        except subprocess.TimeoutExpired:
            _killpg(p)
            return 124, b"", b"timeout"
        return p.returncode, out or b"", err or b""
    finally:
        if out_f:
            out_f.close()


# --------------------------------------------------------------------------
# child: one check in its own process
# --------------------------------------------------------------------------

def child_main(cid: str, work: Path, out: Path) -> int:
    res_path = work / "childres" / f"{cid}.json"
    payload = {"status": "error", "evidence": "error: child produced no result",
               "data": None, "controls": 0, "saw_5xx": []}

    def emit():
        res_path.parent.mkdir(parents=True, exist_ok=True)
        _write_json(res_path, payload)

    try:
        row = registry.REGISTRY[cid]
        import lib  # noqa: F401
        c = lib.Context(row, work, out)
    except BaseException as e:  # noqa: BLE001
        traceback.print_exc()
        payload["evidence"] = f"error: context: {type(e).__name__}: {_first_line(e)}"
        emit()
        return 0

    def red(s: str) -> str:
        fn = getattr(c, "redact", None)
        if callable(fn):
            try:
                return fn(s)
            except Exception:
                pass
        return s

    res = None
    try:
        importlib.import_module(registry.module_name(row))
        fn = registry.impl(cid)
        if fn is None:
            res = Result("error", "error: not implemented")
        else:
            res = fn(c)
            if res is None:
                res = Result("error", "error: check returned None")
            elif not isinstance(res, Result):
                res = Result("error", f"error: check returned {type(res).__name__}")
    except NotImplementedError:
        res = Result("error", "error: not implemented")
    except BaseException as e:  # noqa: BLE001  (SystemExit from a check is an error too)
        tb = traceback.format_exc()
        try:
            c.log("traceback:\n%s", tb)
        except Exception:
            sys.stderr.write(red(tb))
        res = Result("error", red(f"error: {type(e).__name__}: {_first_line(e)}"))

    data = res.data
    if data is not None:
        try:
            s = json.dumps(data, default=str)
            if len(s.encode()) > DATA_MAX:
                data = {"truncated": True, "bytes": len(s.encode())}
            else:
                data = json.loads(s)
        except Exception as e:
            data = {"unserializable": type(e).__name__}
    try:
        controls = int(getattr(c, "controls", 0) or 0)
    except Exception:
        controls = 0
    saw = [red(str(x))[:200] for x in list(getattr(c, "saw_5xx", []) or [])[:20]]
    payload.update(status=res.status, evidence=res.evidence, data=data,
                   controls=controls, saw_5xx=saw)

    # persist state (§3.9): prefer lib's own saver, else write c.state
    try:
        saver = getattr(c, "save_state", None)
        if callable(saver):
            saver()
        elif isinstance(getattr(c, "state", None), dict):
            _write_json(out / "state.json", c.state)
    except Exception as e:
        sys.stderr.write(f"state save failed: {type(e).__name__}\n")
    emit()
    return 0


# --------------------------------------------------------------------------
# parent: the runner
# --------------------------------------------------------------------------

class Runner:
    def __init__(self, bundle: Path, work: Path, out: Path, only):
        self.bundle = bundle
        self.work = work
        self.out = out
        self.repo = work / "repo"
        self.only = only
        self.selected = None if only is None else {r.id for r in registry.closure(only)}
        self.setup: dict = {}
        self.setup_failed: str | None = None
        self.dead = False
        self.base_ckpt: Path | None = None
        self.results: list[dict] = []
        self.started = _now_iso()
        self.compose_prefix: list[str] = []

    # ---- logging (runner-level, never secrets) ----
    def log(self, msg: str, *args) -> None:
        if args:
            try:
                msg = msg % args
            except Exception:
                msg = f"{msg} {args}"
        with open(self.out / "logs" / "run.log", "a") as f:
            f.write(f"{_now_iso()} {msg}\n")

    def _check_log(self, cid: str, msg: str) -> None:
        with open(self.out / "logs" / f"{cid}.log", "a") as f:
            f.write(f"{_now_iso()} [runner] {msg}\n")

    # ---- env / http ----
    def env(self) -> dict:
        return _parse_env(self.repo / ".env")

    def port(self) -> int:
        try:
            return int(self.env().get("COFFER_PORT") or 8420)
        except ValueError:
            return 8420

    def _get(self, path: str, headers=None, timeout=3.0):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.port(), timeout=timeout)
            conn.request("GET", path, headers=headers or {})
            r = conn.getresponse()
            body = r.read()
            conn.close()
            return r.status, body
        except Exception:
            return 0, b""

    def ready(self, timeout: float = 30.0) -> bool:
        end = time.monotonic() + timeout
        while True:
            if self._get("/readyz")[0] == 200:
                return True
            if time.monotonic() >= end:
                return False
            time.sleep(0.5)

    # ---- compose / db ----
    def compose(self, *args, timeout=300, stdin=None, stdout_path=None):
        if not self.compose_prefix:
            return 127, b"", b"no compose provider"
        return _run(self.compose_prefix + list(args), cwd=self.repo, timeout=timeout,
                    stdin=stdin, stdout_path=stdout_path)

    def dbinfo(self):
        e = self.env()
        return e.get("POSTGRES_USER") or "postgres", e.get("POSTGRES_DB") or "postgres"

    def psql(self, sql: str, db: str, stop_on_error=True, timeout=120):
        user, _ = self.dbinfo()
        return self.compose("exec", "-T", "db", "psql", "-U", user, "-d", db, "-X", "-q", "-A", "-t",
                            "-v", f"ON_ERROR_STOP={1 if stop_on_error else 0}",
                            stdin=sql.encode(), timeout=timeout)

    def script(self, name: str, timeout: float):
        return _run(["bash", f"./scripts/{name}"], cwd=self.repo, timeout=timeout)

    def snapshot(self, cid: str, label: str) -> None:
        try:
            import lib
            ctx = lib.Context(registry.REGISTRY[cid], self.work, self.out)
            ctx.sweep_snapshot(label)
        except Exception as e:
            self.log("sweep_snapshot %s failed: %s: %s", label, type(e).__name__, _first_line(e))

    def checkpoint(self, name: str) -> tuple[bool, str]:
        d = self.work / "ckpt" / name
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True)
        user, db = self.dbinfo()
        rc, _, err = self.compose("exec", "-T", "db", "pg_dumpall", "-U", user, "--globals-only",
                                  stdout_path=d / "globals.sql", timeout=300)
        if rc != 0:
            return False, f"pg_dumpall globals rc={rc}: {_first_line(err.decode(errors='replace'))}"
        rc, _, err = self.compose("exec", "-T", "db", "pg_dump", "-U", user, "-Fc", db,
                                  stdout_path=d / "app.dump", timeout=600)
        if rc != 0 or (d / "app.dump").stat().st_size == 0:
            return False, f"pg_dump rc={rc}: {_first_line(err.decode(errors='replace'))}"
        rc, out, err = self.psql("SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database "
                                 "WHERE datname=current_database();", db)
        owner = out.decode(errors="replace").strip()
        if rc != 0 or not owner:
            return False, f"owner query rc={rc}: {_first_line(err.decode(errors='replace'))}"
        (d / "owner").write_text(owner)
        try:
            shutil.copy2(self.repo / ".env", d / "env")
        except OSError as e:
            return False, f"copy .env: {e}"
        self._save_homebind(d)
        return True, "ok"

    # r5 (S11 on both builds): a CLI login made after a checkpoint leaves a PAT that the DB
    # rollback deletes, but its WORK/homebind record and its <home>~base/~proxy home survived
    # and later rows reused a dead token. The checkpoint now saves the homebind records, and
    # rollback drops every record that is new or changed since then, plus the alt home it names.
    def _save_homebind(self, d: Path) -> None:
        hb = self.work / "homebind"
        man = {}
        if hb.is_dir():
            for f in sorted(hb.iterdir()):
                try:
                    man[f.name] = f.read_text(encoding="utf-8")
                except OSError:
                    pass
        (d / "homebind.json").write_text(json.dumps(man), encoding="utf-8")

    def _restore_homebind(self, d: Path, cid: str) -> str:
        hb = self.work / "homebind"
        try:
            man = json.loads((d / "homebind.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            man = None   # checkpoint from before r5: treat every record as post-checkpoint
        dropped, homes = 0, 0
        if not hb.is_dir():
            return "homebind: none"
        for f in sorted(hb.iterdir()):
            try:
                cur = f.read_text(encoding="utf-8")
            except OSError:
                cur = None
            if man is not None and f.name in man and man[f.name] == cur:
                continue
            lines = (cur or "").splitlines()
            home = Path(lines[1].strip()) if len(lines) > 1 and lines[1].strip() else None
            try:
                f.unlink()
                dropped += 1
            except OSError as e:
                self.log("rollback %s: homebind drop %s failed: %s", cid, f.name, e)
                continue
            if home is not None:
                # a changed record means the home was logged in again after the checkpoint, so
                # its saved PAT is gone too: drop it like a new one. A primary fixture home keeps
                # its files and falls back to "proxy-bound"; lib's whoami check re-logs it if dead.
                if "~" in home.name and (self.work / "homes") in home.parents:
                    shutil.rmtree(home, ignore_errors=True)
                    if home.exists():
                        _run(["podman", "unshare", "rm", "-rf", str(home)], cwd=self.work, timeout=120)
                    homes += 1
                self.log("rollback %s: homebind invalidated %s", cid, home)
        return f"homebind: dropped {dropped} record(s), {homes} alt home(s)"

    def rollback(self, name: str, cid: str) -> str:
        d = self.work / "ckpt" / name
        if not (d / "app.dump").exists():
            return "failed: no checkpoint"
        self.snapshot(cid, f"pre-rollback-{cid if name != 'base' else 'base'}")
        try:
            shutil.copyfile(d / "env", self.repo / ".env")  # byte-for-byte
        except OSError as e:
            return f"failed: restore .env: {e}"
        user, db = self.dbinfo()
        self.compose("stop", "server", timeout=120)
        self.compose("up", "-d", "db", timeout=300)
        end = time.monotonic() + 60
        while True:
            rc, _, _ = self.compose("exec", "-T", "db", "pg_isready", "-U", user, timeout=15)
            if rc == 0:
                break
            if time.monotonic() >= end:
                return "failed: db not ready in 60 s"
            time.sleep(1)
        maint = "template1" if db == "postgres" else "postgres"
        rc, _, err = self.psql(f"DROP DATABASE IF EXISTS {_qi(db)} WITH (FORCE);", maint)
        if rc != 0:
            return f"failed: drop db: {_first_line(err.decode(errors='replace'))}"
        self.compose("exec", "-T", "db", "psql", "-U", user, "-d", maint, "-X", "-q",
                     "-v", "ON_ERROR_STOP=0", stdin=(d / "globals.sql").read_bytes(), timeout=300)
        owner = (d / "owner").read_text().strip()
        rc, _, err = self.psql(f"CREATE DATABASE {_qi(db)} OWNER {_qi(owner)};", maint)
        if rc != 0:
            return f"failed: create db: {_first_line(err.decode(errors='replace'))}"
        rc, _, err = self.compose("exec", "-T", "db", "pg_restore", "-U", user, "-d", db,
                                  stdin=(d / "app.dump").read_bytes(), timeout=900)
        if rc != 0:
            self.log("rollback %s for %s: pg_restore rc=%s: %s", name, cid, rc,
                     _first_line(err.decode(errors="replace")))
        # r2 fix (X2/G3 on build-2): `up -d` under podman-compose reuses the existing server
        # container, which still has the overridden env baked in. Remove the server container
        # and force-recreate it from the restored .env, then run up.sh. Log everything.
        self.log("rollback %s for %s: %s", name, cid, self._restore_homebind(d, cid))
        ok, how = self.recreate_server(cid)
        if not ok:
            return f"failed: not ready after up.sh ({how})"
        return self.verify()

    def _server_ids(self) -> list:
        try:
            import lib
            return [x[0] for x in lib.discover_containers(self.compose_prefix[0], self.repo, self.compose_prefix)
                    if x[1] == "server"]
        except Exception as e:
            self.log("discover server failed: %s: %s", type(e).__name__, _first_line(e))
            return []

    def recreate_server(self, cid: str) -> tuple[bool, str]:
        eng = (self.compose_prefix or ["podman"])[0]
        for sid in self._server_ids():
            _run([eng, "rm", "-f", sid], cwd=self.repo, timeout=120)
        rc1, o1, e1 = self.compose("up", "-d", "--force-recreate", "--no-deps", "server", timeout=300)
        rc, o, e = self.script("up.sh", timeout=240)
        if self.ready(60):
            return True, f"recreate rc={rc1} up.sh rc={rc}"
        # last resort: full down + up.sh (volumes kept)
        rc2, o2, e2 = self.script("down.sh", timeout=180)
        rc3, o3, e3 = self.script("up.sh", timeout=240)
        if self.ready(60):
            self._check_log(cid, f"recreate needed down.sh+up.sh (down rc={rc2} up rc={rc3})")
            return True, f"down+up rc={rc3}"
        self._diag(cid, [("compose up --force-recreate server", rc1, o1, e1), ("up.sh", rc, o, e),
                         ("down.sh", rc2, o2, e2), ("up.sh (2)", rc3, o3, e3)])
        return False, f"rc={rc3}"

    def _diag(self, cid: str, steps: list) -> None:
        eng = (self.compose_prefix or ["podman"])[0]
        lines = []
        for name, rc, o, e in steps:
            lines.append(f"  {name}: rc={rc}\n    out: {o.decode('utf-8','replace')[-1500:]}\n"
                         f"    err: {e.decode('utf-8','replace')[-1500:]}")
        try:
            import lib
            mine = lib.discover_containers(eng, self.repo, self.compose_prefix)
            lines.append(f"  project containers: " + "; ".join(
                f"{x[0][:12]} {x[1]} {x[2].get('State') or x[2].get('Status')} exit={x[2].get('ExitCode')}"
                for x in mine))
        except Exception as ex:
            lines.append(f"  project containers: discovery raised {type(ex).__name__}")
        for sid in self._server_ids()[-1:]:
            rc, o, e = _run([eng, "logs", "--tail", "60", sid], cwd=self.repo, timeout=60)
            lines.append(f"  server logs ({sid[:12]}): {(o + e).decode('utf-8','replace')[-3000:]}")
        self._check_log(cid, "recovery diagnostics:\n" + self._red("\n".join(lines)))

    def _red(self, s: str) -> str:
        try:
            import lib
            ctx = lib.Context(registry.REGISTRY["F1"], self.work, self.out)
            return ctx.redact(s)
        except Exception:
            return s

    def verify(self) -> str:
        fx = _read_json(self.out / "fixture.json", {}) or {}
        pat = ((fx.get("users") or {}).get("owner@acme") or {}).get("pat")
        canary = (fx.get("canaries") or {}).get("acme/api/dev/CANARY")
        if not pat or not canary:
            return "ok (readyz only; no fixture canary)"
        st, body = self._get("/api/v1/projects/api/envs/dev/secrets/CANARY",
                             headers={"Authorization": f"Bearer {pat}"}, timeout=15)
        try:
            val = json.loads(body).get("value")
        except Exception:
            val = None
        if st == 200 and val == canary:
            return "ok"
        return f"failed: canary read -> {st}{'' if st != 200 else ', value differs'}"

    def guard(self, cid: str) -> str:
        if self.setup_failed or self.dead:
            return "n/a"
        if self.ready(30):
            return "ok"
        rc, o, e = self.script("up.sh", timeout=240)
        if self.ready(30):
            return "upped"
        self._diag(cid, [("guard up.sh", rc, o, e)])
        if self.base_ckpt is not None:
            rb = self.rollback("base", cid)
            self._check_log(cid, f"guard rollback to base: {rb}")
            if rb.startswith("ok") and self.ready(30):
                return "rolled-back"
        self.dead = True
        self.log("stack unrecoverable after %s", cid)
        return "dead"

    # ---- child process ----
    def fresh_tmp(self, cid: str) -> None:
        t = self.work / "tmp" / cid
        if t.exists():
            shutil.rmtree(t, ignore_errors=True)
            if t.exists():
                _run(["podman", "unshare", "rm", "-rf", str(t)], cwd=self.work, timeout=120)
            if t.exists():
                n = 1
                while (t.parent / f"{cid}.old-{n}").exists():
                    n += 1
                t.rename(t.parent / f"{cid}.old-{n}")
        t.mkdir(parents=True)

    def run_child(self, row) -> tuple[dict, int]:
        cid = row.id
        self.fresh_tmp(cid)
        res_path = self.work / "childres" / f"{cid}.json"
        if res_path.exists():
            res_path.unlink()
        argv = [sys.executable, "-I", str(HERE / "run.py"), "--_child", cid,
                "--work", str(self.work), "--out", str(self.out)]
        t0 = time.monotonic()
        with open(self.work / "childlogs" / f"{cid}.out", "ab") as lf:
            p = subprocess.Popen(argv, cwd=str(self.work), stdin=subprocess.DEVNULL, stdout=lf,
                                 stderr=subprocess.STDOUT, start_new_session=True)
            try:
                p.wait(timeout=max(1, row.timeout))
                timed_out = False
            except subprocess.TimeoutExpired:
                timed_out = True
                _killpg(p)
        ms = int((time.monotonic() - t0) * 1000)
        if timed_out:
            self._check_log(cid, f"timeout after {row.timeout} s; process group killed")
            return {"status": "timeout", "evidence": f"timeout after {row.timeout} s",
                    "data": None, "controls": 0, "saw_5xx": []}, ms
        got = _read_json(res_path)
        if not isinstance(got, dict) or got.get("status") not in registry.STATUSES:
            return {"status": "error", "evidence": f"error: child exited rc={p.returncode} without a result",
                    "data": None, "controls": 0, "saw_5xx": []}, ms
        return got, ms

    # ---- result rows ----
    def record(self, row, raw: dict, *, ms=0, guard="n/a", rollback="n/a", started=None) -> dict:
        status = raw.get("status", "error")
        evidence = str(raw.get("evidence") or "")
        controls = int(raw.get("controls") or 0)
        saw = list(raw.get("saw_5xx") or [])
        if status == "skip" and self.selected is not None and row.id in self.selected:
            status, evidence = "error", "error: check returned runner-only status skip"
        if status == "pass" and saw and not row.allow_5xx:
            status, evidence = "fail", f"5xx seen: {saw[0]}"
        if status == "pass" and row.denial and controls == 0:
            status, evidence = "error", "error: no positive control"
        if status in ("na", "skip"):
            points = None
        else:
            points = row.points if status == "pass" else 0
        logrel = f"logs/{row.id}.log"
        rec = {"id": row.id, "status": status, "points_possible": row.points, "points": points,
               "blocker": row.blocker, "evidence": " ".join(evidence.split())[:300],
               "data": raw.get("data"), "ms": ms,
               "log": logrel if (self.out / logrel).exists() else None,
               "controls": controls, "saw_5xx": saw, "guard": guard, "rollback": rollback,
               "order": row.order, "started": started or _now_iso()}
        self.results.append(rec)
        with open(self.out / "results.jsonl", "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        self.log("%s %s %s", row.id, status, rec["evidence"][:120])
        return rec

    def run_row(self, row) -> None:
        cid = row.id
        started = _now_iso()
        if self.selected is not None and cid not in self.selected:
            self.record(row, {"status": "skip", "evidence": "not selected under --only"}, started=started)
            return
        if row.stack and self.setup_failed:
            self.record(row, {"status": "error", "evidence": f"error: setup failed at {self.setup_failed}"},
                        started=started)
            return
        if not row.stack and self.setup_failed == "S0":
            self.record(row, {"status": "error", "evidence": "error: setup failed at S0"}, started=started)
            return
        if row.stack and self.dead:
            self.record(row, {"status": "error", "evidence": "error: stack unrecoverable"}, started=started)
            return
        rb = "n/a"
        if row.destructive:
            ok, why = self.checkpoint(cid)
            if not ok:
                self._check_log(cid, f"checkpoint failed: {why}")
                self.record(row, {"status": "error", "evidence": f"error: checkpoint failed: {why}"},
                            started=started, guard=self.guard(cid))
                return
        raw, ms = self.run_child(row)
        if row.destructive:
            rb = self.rollback(cid, cid)
            self._check_log(cid, f"rollback: {rb}")
        guard = self.guard(cid) if cid != "E1" else "n/a"
        self.record(row, raw, ms=ms, guard=guard, rollback=rb, started=started)
        if cid == "F1":
            self.snapshot("F1", "after-F1")
            self.take_base()

    def take_base(self) -> None:
        if self.setup_failed or self.dead:
            return
        ok, why = self.checkpoint("base")
        self.base_ckpt = self.work / "ckpt" / "base" if ok else None
        self.log("base checkpoint: %s", why)

    # ---- setup / teardown ----
    @staticmethod
    def failed_step(s: dict) -> str | None:
        for k in ("failed_step", "failed_at"):
            if s.get(k):
                return str(s[k])
        if s.get("clone_rc") != 0:
            return "S0"
        if not s.get("compose"):
            return "S1"
        if s.get("init_env_rc") != 0:
            return "S2"
        if s.get("build_rc") != 0 or not s.get("bin_ok"):
            return "S3"
        if s.get("readyz_status") != 200:
            return "S4"
        return None

    def do_setup(self) -> None:
        try:
            import fixture
        except Exception as e:
            self.log("fixture import failed: %s: %s", type(e).__name__, _first_line(e))
            self.setup = {"error": f"fixture import: {type(e).__name__}"}
            self.setup_failed = "S0"
            return
        try:
            s = fixture.setup(self)
        except Exception as e:
            self.log("fixture.setup raised: %s\n%s", type(e).__name__, traceback.format_exc())
            s = _read_json(self.out / "setup.json", {}) or {}
            s.setdefault("error", f"setup raised {type(e).__name__}")
        self.setup = s if isinstance(s, dict) else {}
        if not (self.out / "setup.json").exists():
            _write_json(self.out / "setup.json", self.setup)
        self.compose_prefix = list(self.setup.get("compose") or [])
        self.setup_failed = self.failed_step(self.setup)
        self.log("setup done: failed_step=%s", self.setup_failed)

    def do_teardown(self) -> None:
        try:
            import fixture
            td = fixture.teardown(self)
            self.log("teardown: %s", json.dumps(td, default=str)[:500] if td is not None else None)
        except Exception as e:
            self.log("teardown failed: %s: %s", type(e).__name__, _first_line(e))
        pid = self.setup.get("proxy_pid")
        if isinstance(pid, int) and pid > 1:
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass

    # ---- the whole run ----
    def run(self) -> None:
        for d in ("logs", "sweep/dumps", "sweep/logs", "sweep/backups", "sweep/homes", "sweep/audit"):
            (self.out / d).mkdir(parents=True, exist_ok=True)
        for d in ("tmp", "ckpt", "childres", "childlogs", "backups"):
            (self.work / d).mkdir(parents=True, exist_ok=True)
        if not (self.out / "state.json").exists():
            _write_json(self.out / "state.json", {})
        (self.out / "results.jsonl").touch()
        for mod in registry.MODULES:
            try:
                importlib.import_module(mod[:-3])
            except Exception as e:
                self.log("module %s failed to import: %s: %s", mod, type(e).__name__, _first_line(e))

        rows = registry.ordered()
        main_rows = [r for r in rows if not r.na and r.id != "E1"]
        tore_down = False
        try:
            self.do_setup()
            if self.selected is not None and "F1" not in self.selected:
                self.take_base()
            for row in main_rows:
                self.run_row(row)
            self.do_teardown()
            tore_down = True
            e1 = registry.REGISTRY["E1"]
            self.run_row(e1)
            for row in rows:
                if row.na:
                    self.record(row, {"status": "na", "evidence": "manual; recorded na"})
        finally:
            if not tore_down:
                self.do_teardown()
            self.write_summary()

    def write_summary(self) -> None:
        res = self.results
        partial = self.selected is not None
        p0 = [r for r in res if r["points_possible"] == 2 and r["status"] not in ("na", "skip")]
        p0_possible = sum(r["points_possible"] for r in p0)
        p0_points = sum(r["points"] or 0 for r in p0)
        p1_points = sum(r["points"] or 0 for r in res if r["points_possible"] == 1)
        pct = round(100.0 * p0_points / p0_possible, 1) if p0_possible else None
        blockers_failed = [r["id"] for r in res if r["blocker"] and r["status"] in ("fail", "timeout")]
        errors = [r["id"] for r in res if r["status"] == "error"]
        timeouts = [r["id"] for r in res if r["status"] == "timeout"]
        missing = sorted(set(registry.REGISTRY) - {r["id"] for r in res})
        notes = ["G1 strict/assisted decided manually; SHIP possible only if G1 strict"]
        if partial:
            verdict = None
            notes.append("partial run (--only): no verdict")
        elif missing:
            verdict = None
            notes.append(f"incomplete run: {len(missing)} rows missing ({','.join(missing[:10])})")
        elif blockers_failed:
            verdict = "NOT SHIPPABLE"
        elif pct is not None and pct >= 75.0:
            verdict = "FIX-THEN-SHIP"
            if pct >= 90.0:
                notes.append("P0 >= 90%: SHIP if G1 strict")
        else:
            verdict = "NOT SHIPPABLE"
        if errors or timeouts:
            notes.append(f"PROVISIONAL: {len(errors) + len(timeouts)} errors")
        blk_err = [i for i in errors if registry.REGISTRY[i].blocker]
        if blk_err:
            notes.append(f"blockers in error (not passed, not failed): {','.join(blk_err)}")
        if self.setup_failed:
            notes.append(f"setup failed at {self.setup_failed}")
        if self.setup_failed == "ENV" or (self.setup or {}).get("void"):
            # r2: host/environment failure (e.g. postgres:16 positive control). Not the build.
            verdict = None
            notes.insert(0, "VOID/ENV: host prep positive control failed; re-run the round, no verdict")
        summary = {"commit": self.setup.get("commit"), "started": self.started, "finished": _now_iso(),
                   "partial": partial, "p0_possible": p0_possible, "p0_points": p0_points,
                   "p0_pct": pct, "p1_points": p1_points, "total_points": p0_points + p1_points,
                   "blockers_failed": blockers_failed, "errors": errors, "timeouts": timeouts,
                   "verdict": verdict, "verdict_note": "; ".join(notes)}
        _write_json(self.out / "summary.json", summary)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def do_list() -> int:
    try:
        registry.load_all()
    except Exception as e:
        print(f"import/registration error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    for r in registry.ordered():
        flags = "".join(f for f, on in (("B", r.blocker), ("D", r.destructive), ("s", not r.stack),
                                        ("p", r.proxied), ("d", r.denial), ("5", r.allow_5xx),
                                        ("n", r.na)) if on)
        if r.na:
            state = "na"
        else:
            fn = registry.impl(r.id)
            if fn is None:
                state = "stub"
            else:
                names = set(getattr(fn, "__code__", None).co_names) if hasattr(fn, "__code__") else set()
                state = "stub" if names == {"not_implemented"} else "impl"
        print(f"{r.order:4d} {r.id:4s} {r.points} {flags:6s} {r.timeout:5d} {r.module:15s} {r.title} {state}")
    return 0


def _empty_dir(p: Path) -> bool:
    p.mkdir(parents=True, exist_ok=True)
    return p.is_dir() and not any(p.iterdir())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="run.py")
    ap.add_argument("--bundle")
    ap.add_argument("--work")
    ap.add_argument("--out")
    ap.add_argument("--only")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--_child", dest="child", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)

    if a.child:
        if not a.work or not a.out:
            return 2
        return child_main(a.child, Path(a.work).resolve(), Path(a.out).resolve())
    if a.list:
        return do_list()
    if not a.bundle or not a.work or not a.out:
        print("--bundle, --work and --out are required", file=sys.stderr)
        return 2
    bundle = Path(a.bundle).resolve()
    if not bundle.is_file():
        print(f"bundle not found: {bundle}", file=sys.stderr)
        return 2
    work, out = Path(a.work).resolve(), Path(a.out).resolve()
    if work == out:
        print("--work and --out must differ", file=sys.stderr)
        return 2
    try:
        if not _empty_dir(work):
            print(f"--work {work} is not empty", file=sys.stderr)
            return 2
        if not _empty_dir(out):
            print(f"--out {out} is not empty", file=sys.stderr)
            return 2
    except OSError as e:
        print(f"cannot create dir: {e}", file=sys.stderr)
        return 2
    only = None
    if a.only:
        only = [x.strip() for x in a.only.split(",") if x.strip()]
        try:
            registry.closure(only)
        except KeyError as e:
            print(f"unknown ID in --only: {e}", file=sys.stderr)
            return 2
    try:
        Runner(bundle, work, out, only).run()
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
