"""Coffer grading checks: E3, E6, E1 (GRADER.md "E - Engineering").

Black-box only. These checks read deliverables GRADER names (CI workflow
files, git history) and run the SPEC section 5 script ./scripts/test.sh. They
never read application source.

Interpretations (same for both builds; where ambiguous, the stricter reading):

E3  "CI workflow runs lint, test and build" (SPEC section 6: "A GitHub Actions
    workflow runs lint, tests and build").
    - Only files COMMITTED at HEAD under .github/workflows/*.yml|*.yaml count
      (read with `git show HEAD:<path>`, so build-time files cannot count).
    - The workflow must be CI: its `on:` triggers include push or
      pull_request. A workflow it calls via a job-level
      `uses: ./.github/workflows/X.yml` counts as part of it.
    - Singular reading: ONE such workflow (plus what it calls) must cover all
      three of lint, test and build.
    - Coverage is decided from `run:` commands and `uses:` actions of steps,
      never from step or job names. Steps or jobs with `if: false` (or
      `${{ false }}`) do not count; full-line comments and echo/printf lines
      do not count.
    - One level of indirection is followed: `make T` (recipe of T in the
      committed Makefile), `npm|pnpm|yarn|bun [run] S` (script S in the
      committed package.json, also under the step's working-directory), and
      a repo-local `*.sh` script the step runs (its committed text). These are
      build/CI config named by the workflow, not application source.
    - No workflow files -> fail. Unparseable -> the categories it fails to
      show are simply missing (fail), never error.

E6  "More than 1 commit; the history is not a single dump" (git log --stat).
    - Commits reachable from HEAD of the default branch: count must be > 1.
    - "Single dump": over non-merge commits, lines added (git log --numstat)
      excluding lockfiles, binary files, vendored/third-party trees (any dir
      component vendor, node_modules, third_party, third-party, thirdparty,
      bower_components; .yarn/cache) and generated/minified files (*.pb.go,
      *_pb2.py, *_gen.go, *.min.js, *.map, ...) (r3-1); per-commit first-party
      and excluded counts are logged; if the largest single commit
      holds >= 80% of all added lines, the history is a dump -> fail. If no
      text lines were added at all, files-added share is used instead.
    - Fewer than 2 commits that add or change any file -> fail.

E1  "./scripts/test.sh exits 0 on a clean clone".
    - run.py does not hand the bundle path to checks, so the clean clone is
      `git clone <WORK/repo> <c.tmp>/e1`. WORK/repo was cloned from the bundle
      in setup S0, and git clone copies only committed objects, so the result
      is a clean checkout of the bundle's HEAD. Its HEAD sha must equal
      setup.json "commit", otherwise error. (Local-implementation note: lib.py
      has no "clean clone" helper, so this module does it itself.)
    - No init-env.sh, no build.sh beforehand: a clean clone, as GRADER says.
      The grader's environment is inherited, as for every SPEC script.
    - Timeout 1500 s (row timeout 1800 s). rc 0 -> pass; anything else, a
      missing script, or the timeout -> fail. The full redacted output is
      saved to OUT/logs/E1.testsh.txt.
    - Afterwards, best effort `<compose> down -v` in the e1 clone, so the
      grading host is left clean; its result does not affect the verdict.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

from registry import Result, check, not_implemented  # noqa: F401

import lib


# ----------------------------------------------------------------- git helper

def _git(c, *args: str, cwd: Path | None = None, timeout: float = 60.0) -> lib.Proc:
    env = dict(os.environ)
    env.update({"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "GIT_PAGER": "cat", "PAGER": "cat",
                "GIT_TERMINAL_PROMPT": "0"})
    argv = ["git", "-c", "core.quotepath=off", "-c", "color.ui=never"] + list(args)
    p = lib._run(argv, cwd=cwd or c.repo, env=env, stdin=b"", timeout=timeout)
    c.log("GIT %s -> rc=%s %.0fms err=%s", " ".join(args), p.rc, p.ms, p.err[-400:].decode("utf-8", "replace"))
    return p


def _show(c, path: str) -> str | None:
    p = _git(c, "show", f"HEAD:{path}")
    if p.rc != 0:
        return None
    return p.out.decode("utf-8", "replace")


# ======================================================================== E3

_FALSE_IF = re.compile(r"^\s*(false|\$\{\{\s*false\s*\}\}|'false'|\"false\")\s*$", re.I)

LINT_RE = re.compile(
    r"(golangci-lint|\bgo vet\b|\bstaticcheck\b|\beslint\b|\bruff\b|\bflake8\b|\bpylint\b|\bmypy\b|"
    r"\bclippy\b|\bgofmt\b\s+-[ld]|\bcargo fmt\b.*--check|\bprettier\b.*--check|\bblack\b.*--check|"
    r"\bbiome\b|\brubocop\b|\bshellcheck\b|\bhadolint\b|\btsc\b.*--noemit|\blint\b)", re.I)
LINT_USES = re.compile(r"(golangci-lint-action|super-linter|ruff-action|reviewdog|hadolint-action|"
                       r"action-shellcheck|eslint|lint)", re.I)
TEST_RE = re.compile(
    r"(scripts/test\.sh|\bgo test\b|\bcargo (nextest|test)\b|\bpytest\b|python3? -m (pytest|unittest)|"
    r"\b(npm|pnpm|yarn|bun)( run)? test\b|\bjest\b|\bvitest\b|\bmvn\b.*\b(test|verify)\b|"
    r"gradlew?\b.*\btest\b|\bmake test\b|\bdotnet test\b|\bdeno test\b|\bmix test\b|\brspec\b|\bnode --test\b)",
    re.I)
BUILD_RE = re.compile(
    r"(scripts/build\.sh|\bgo build\b|\bcargo build\b|\b(npm|pnpm|yarn|bun)( run)? build\b|"
    r"\b(docker|podman|buildah)\s+(buildx\s+)?build\b|\bcompose\b.*\bbuild\b|\bmake build\b|"
    r"\bmvn\b.*\b(package|install)\b|gradlew?\b.*\b(build|assemble)\b|\bdotnet (build|publish)\b|"
    r"\bdeno compile\b|\bgo install\b)", re.I)
BUILD_USES = re.compile(r"(docker/build-push-action|redhat-actions/buildah-build)", re.I)
TSC_BUILD = re.compile(r"\btsc\b(?!.*--noemit)", re.I)


def _strip_comment(line: str) -> str | None:
    """Drop full-line comments; drop trailing ' #...' outside quotes. None = skip line."""
    s = line.rstrip("\n").rstrip()
    if s.lstrip().startswith("#"):
        return None
    out, q = [], None
    for i, ch in enumerate(s):
        if q:
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _ind(s: str) -> int:
    return len(s) - len(s.lstrip(" "))


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def _parse_workflow(text: str) -> dict:
    """Minimal line-based extractor for GitHub Actions YAML (stdlib only).

    Returns {"triggers": set, "jobs": [{"name","if","uses","steps":[{"run","uses","if","wd"}]}]}
    """
    raw = text.splitlines()
    lines: list[str] = []
    # keep block-scalar bodies' blank lines out; comments stripped
    for ln in raw:
        s = _strip_comment(ln)
        if s is None or not s.strip():
            continue
        lines.append(s)

    triggers: set[str] = set()
    jobs: list[dict] = []
    n = len(lines)
    i = 0
    top_on = re.compile(r"""^(on|"on"|'on'|true)\s*:\s*(.*)$""")
    while i < n:
        s = lines[i]
        if _ind(s) == 0:
            m = top_on.match(s)
            if m:
                val = m.group(2).strip()
                if val:
                    for t in re.split(r"[\[\],\s]+", val):
                        if t:
                            triggers.add(_unquote(t))
                    i += 1
                    continue
                j = i + 1
                child = None
                while j < n and _ind(lines[j]) > 0:
                    ci = _ind(lines[j])
                    if child is None:
                        child = ci
                    if ci == child:
                        st = lines[j].strip()
                        if st.startswith("- "):
                            triggers.add(_unquote(st[2:]))
                        else:
                            triggers.add(_unquote(st.split(":", 1)[0]))
                    j += 1
                i = j
                continue
            if re.match(r"^jobs\s*:\s*$", s):
                j = i + 1
                jind = None
                cur = None
                while j < n and _ind(lines[j]) > 0:
                    ci = _ind(lines[j])
                    st = lines[j].strip()
                    if jind is None:
                        jind = ci
                    if ci == jind:
                        cur = {"name": st.split(":", 1)[0].strip(), "if": "", "uses": "", "steps": [],
                               "kind": None}
                        jobs.append(cur)
                        j += 1
                        continue
                    if cur is not None and ci > jind:
                        # job-level keys sit at the first indent deeper than jind
                        if cur["kind"] is None:
                            cur["kind"] = ci
                        if ci != cur["kind"]:
                            j += 1
                            continue
                        key, _, val = st.partition(":")
                        key = key.strip()
                        if key == "if":
                            cur["if"] = val
                        if key == "uses":
                            cur["uses"] = _unquote(val)
                        if key == "steps" and not val.strip():
                            sind = ci
                            k = j + 1
                            step = None
                            itemind = None
                            while k < n and _ind(lines[k]) > sind:
                                t = lines[k]
                                ti = _ind(t)
                                ts = t.strip()
                                if ts.startswith("-") and (itemind is None or ti == itemind):
                                    itemind = ti
                                    step = {"run": "", "uses": "", "if": "", "wd": ""}
                                    cur["steps"].append(step)
                                    ts = ts[1:].strip()
                                    if not ts:
                                        k += 1
                                        continue
                                    kind = ti + 2
                                else:
                                    kind = ti
                                if step is None:
                                    k += 1
                                    continue
                                sk, _, sv = ts.partition(":")
                                sk = sk.strip()
                                sv = sv.strip()
                                if sk == "run":
                                    if sv[:1] in ("|", ">"):
                                        body = []
                                        k2 = k + 1
                                        while k2 < n and _ind(lines[k2]) > kind:
                                            body.append(lines[k2].strip())
                                            k2 += 1
                                        step["run"] = "\n".join(body)
                                        k = k2
                                        continue
                                    step["run"] = _unquote(sv)
                                elif sk == "uses":
                                    step["uses"] = _unquote(sv)
                                elif sk == "if":
                                    step["if"] = sv
                                elif sk == "working-directory":
                                    step["wd"] = _unquote(sv)
                                k += 1
                            j = k
                            continue
                    j += 1
                i = j
                continue
        i += 1
    return {"triggers": triggers, "jobs": jobs}


def _cmd_lines(run: str) -> list[str]:
    out = []
    for ln in run.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        # split on shell separators so `echo x; go test` still counts `go test`
        for seg in re.split(r"\s*(?:;|&&|\|\|)\s*", s):
            seg = seg.strip()
            if not seg or re.match(r"^(echo|printf|:)\b", seg):
                continue
            out.append(seg)
    return out


def _make_recipe(c, target: str, cache: dict) -> str:
    if "Makefile" not in cache:
        cache["Makefile"] = _show(c, "Makefile") or _show(c, "makefile") or _show(c, "GNUmakefile") or ""
    mk = cache["Makefile"].splitlines()
    body, inside = [], False
    for ln in mk:
        if re.match(rf"^{re.escape(target)}\s*:(?!=)", ln):
            inside = True
            deps = ln.split(":", 1)[1]
            body.append(deps)
            continue
        if inside:
            if ln.startswith("\t"):
                body.append(ln.strip())
            elif ln.strip():
                inside = False
    return "\n".join(body)


def _pkg_script(c, wd: str, name: str, cache: dict) -> str:
    path = (wd.strip("./") + "/package.json") if wd and wd not in (".", "./") else "package.json"
    if path not in cache:
        cache[path] = _show(c, path) or ""
    try:
        return str((json.loads(cache[path] or "{}").get("scripts") or {}).get(name, ""))
    except (ValueError, AttributeError):
        return ""


def _expand(c, cmd: str, wd: str, cache: dict) -> list[tuple[str, str]]:
    """One level of indirection: returns [(via, text)]."""
    out = []
    m = re.search(r"\bmake\s+(?:-\S+\s+)*([A-Za-z0-9_.-]+)", cmd)
    if m:
        r = _make_recipe(c, m.group(1), cache)
        if r:
            out.append((f"make {m.group(1)}", r))
    m = re.search(r"\b(npm|pnpm|yarn|bun)\s+(?:run\s+)?([A-Za-z0-9:_.-]+)", cmd)
    if m and m.group(2) not in ("install", "ci", "i", "add", "exec", "dlx", "x"):
        r = _pkg_script(c, wd, m.group(2), cache)
        if r:
            out.append((f"{m.group(1)} {m.group(2)}", r))
    for sm in re.finditer(r"(?:^|[\s;&|(])(?:bash\s+|sh\s+)?(\.?/?[A-Za-z0-9_./-]+\.sh)\b", cmd):
        p = sm.group(1)
        norm = os.path.normpath(os.path.join(wd or ".", p)).lstrip("./") if not p.startswith("/") else None
        if not norm or norm.startswith(".."):
            continue
        key = "sh:" + norm
        if key not in cache:
            cache[key] = _show(c, norm) or ""
        if cache[key]:
            txt = "\n".join(_cmd_lines(cache[key]))
            out.append((norm, txt))
    return out


def _classify(c, wf: dict, fname: str, cache: dict) -> dict:
    found: dict[str, str] = {}

    def hit(cat: str, where: str):
        if cat not in found:
            found[cat] = where

    def scan_text(text: str, where: str, *, allow_tsc_build: bool = True):
        for ln in _cmd_lines(text):
            if LINT_RE.search(ln):
                hit("lint", f"{where}: {ln[:120]}")
            if TEST_RE.search(ln):
                hit("test", f"{where}: {ln[:120]}")
            if BUILD_RE.search(ln) or (allow_tsc_build and TSC_BUILD.search(ln)):
                hit("build", f"{where}: {ln[:120]}")

    for job in wf["jobs"]:
        if _FALSE_IF.match(job.get("if") or ""):
            c.log("E3 %s job %s disabled by if: %s", fname, job["name"], job["if"])
            continue
        for st in job["steps"]:
            if _FALSE_IF.match(st.get("if") or ""):
                c.log("E3 %s job %s step disabled by if: %s", fname, job["name"], st["if"])
                continue
            where = f"{fname}#{job['name']}"
            if st["uses"]:
                u = st["uses"]
                if LINT_USES.search(u):
                    hit("lint", f"{where}: uses {u}")
                if BUILD_USES.search(u):
                    hit("build", f"{where}: uses {u}")
            if st["run"]:
                scan_text(st["run"], where)
                for ln in _cmd_lines(st["run"]):
                    for via, txt in _expand(c, ln, st.get("wd") or "", cache):
                        scan_text(txt, f"{where} via {via}")
    return found


@check("E3")
def e3(c) -> Result:
    """CI workflow runs lint, test and build"""
    p = _git(c, "ls-tree", "-r", "--name-only", "HEAD", "--", ".github/workflows")
    if p.rc != 0:
        return c.error(f"git ls-tree failed rc={p.rc}")
    files = sorted(f for f in p.out.decode("utf-8", "replace").splitlines()
                   if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", f))
    c.log("E3 committed workflow files: %s", files)
    if not files:
        return c.fail("no committed .github/workflows/*.yml|*.yaml at HEAD")

    parsed: dict[str, dict] = {}
    cache: dict = {}
    for f in files:
        txt = _show(c, f)
        if txt is None:
            c.log("E3 could not read %s", f)
            continue
        c.log("E3 ---- %s (%d bytes) ----\n%s", f, len(txt), txt[:6000])
        parsed[f] = _parse_workflow(txt)
        c.log("E3 %s triggers=%s jobs=%s", f, sorted(parsed[f]["triggers"]),
              [(j["name"], len(j["steps"]), j["uses"]) for j in parsed[f]["jobs"]])

    per_file: dict[str, dict] = {}
    for f, wf in parsed.items():
        per_file[f] = _classify(c, wf, f, cache)
        c.log("E3 %s categories: %s", f, per_file[f])

    summary = []
    best = None
    for f, wf in parsed.items():
        trig = wf["triggers"] & {"push", "pull_request", "pull_request_target"}
        cov = dict(per_file[f])
        # include reusable workflows this one calls
        for job in wf["jobs"]:
            u = job.get("uses") or ""
            if u.startswith("./.github/workflows/") and not _FALSE_IF.match(job.get("if") or ""):
                callee = u[2:].split("@", 1)[0]
                for k, v in per_file.get(callee, {}).items():
                    cov.setdefault(k, v)
        missing = [k for k in ("lint", "test", "build") if k not in cov]
        summary.append({"file": f, "triggers": sorted(wf["triggers"]), "ci_trigger": bool(trig),
                        "covers": sorted(cov), "missing": missing})
        if trig and not missing:
            best = (f, cov)
            break
    data = {"workflows": summary}
    if best:
        f, cov = best
        c.expect(True, f"{f} (push/PR) runs lint, test, build")
        return c.done(f"{f}: lint[{cov['lint']}] test[{cov['test']}] build[{cov['build']}]", data)
    ci = [s for s in summary if s["ci_trigger"]]
    if not ci:
        c.expect(False, f"no workflow triggered on push/pull_request (files: {', '.join(files)})")
    else:
        top = max(ci, key=lambda s: len(s["covers"]))
        c.expect(False, f"no single CI workflow covers lint+test+build; best {top['file']} "
                        f"covers {top['covers']} missing {top['missing']}")
    return c.done("", data)


# ======================================================================== E6

LOCKFILES = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "go.sum", "cargo.lock", "poetry.lock",
             "uv.lock", "pipfile.lock", "composer.lock", "gemfile.lock", "bun.lockb", "bun.lock",
             "npm-shrinkwrap.json", "flake.lock", "mix.lock", "pubspec.lock", "packages.lock.json",
             "gradle.lockfile", "requirements.lock"}
# r3-1: vendored / third-party / generated content is not first-party history. A path is
# excluded when any directory component is one of VENDOR_DIRS, or its name matches GENERATED.
VENDOR_DIRS = {"vendor", "node_modules", "third_party", "third-party", "thirdparty", "bower_components"}
GENERATED = re.compile(r"(\.pb\.go|_pb2\.py|_pb2_grpc\.py|\.pb\.gw\.go|_gen\.go|\.gen\.go|\.min\.js|"
                       r"\.min\.css|\.js\.map|\.css\.map)$")


def _numstat_path(path: str) -> str:
    """numstat rename forms 'a/{b => c}/d' and 'a => b' -> the new path."""
    if "{" in path and " => " in path:
        path = re.sub(r"\{[^{}]*? => ([^{}]*)\}", r"\1", path)
    elif " => " in path:
        path = path.split(" => ")[-1]
    return path.replace("//", "/")


def _excluded(path: str) -> str | None:
    """-> 'lockfile' | 'vendor' | 'generated' | None for a (new-side) numstat path."""
    parts = [x for x in path.lower().split("/") if x]
    if not parts:
        return None
    if parts[-1] in LOCKFILES:
        return "lockfile"
    if any(d in VENDOR_DIRS for d in parts[:-1]) or parts[:2] == [".yarn", "cache"]:
        return "vendor"
    if GENERATED.search(parts[-1]):
        return "generated"
    return None
DUMP_SHARE = 0.80


@check("E6")
def e6(c) -> Result:
    """More than 1 commit; history is not a single dump"""
    p = _git(c, "rev-list", "--count", "HEAD")
    if p.rc != 0:
        return c.error(f"git rev-list failed rc={p.rc}")
    total_commits = int(p.out.decode().strip() or "0")
    st = _git(c, "log", "--stat", "--format=%h %ad %s", "--date=iso-strict", "HEAD", timeout=120)
    c.log("E6 git log --stat (first 12000 chars):\n%s", st.out.decode("utf-8", "replace")[:12000])

    p = _git(c, "log", "--no-merges", "--numstat", "--format=@@C %H %ct %s", "HEAD", timeout=120)
    if p.rc != 0:
        return c.error(f"git log --numstat failed rc={p.rc}")
    commits: list[dict] = []
    for ln in p.out.decode("utf-8", "replace").splitlines():
        if ln.startswith("@@C "):
            parts = ln[4:].split(" ", 2)
            commits.append({"sha": parts[0][:10], "ts": int(parts[1]) if len(parts) > 1 else 0,
                            "subject": parts[2][:80] if len(parts) > 2 else "", "lines": 0, "files": 0,
                            "changed": 0, "excl": {"lockfile": 0, "vendor": 0, "generated": 0}})
            continue
        if not ln.strip() or not commits:
            continue
        cols = ln.split("\t")
        if len(cols) < 3:
            continue
        add, _dele, path = cols[0], cols[1], cols[2]
        cur = commits[-1]
        cur["changed"] += 1
        if add == "-":
            continue
        try:
            a = int(add)
        except ValueError:
            continue
        why = _excluded(_numstat_path(path))
        if why:
            cur["excl"][why] += a
            continue
        cur["lines"] += a
        if a > 0:
            cur["files"] += 1

    nonmerge = len(commits)
    touching = [x for x in commits if x["changed"] > 0]
    tot_lines = sum(x["lines"] for x in commits)
    tot_files = sum(x["files"] for x in commits)
    if tot_lines > 0:
        big = max(commits, key=lambda x: x["lines"])
        share, unit = big["lines"] / tot_lines, "lines"
    elif tot_files > 0:
        big = max(commits, key=lambda x: x["files"])
        share, unit = big["files"] / tot_files, "files"
    else:
        big, share, unit = None, 1.0, "none"
    span_h = ((max(x["ts"] for x in commits) - min(x["ts"] for x in commits)) / 3600.0) if commits else 0.0
    data = {"commits": total_commits, "non_merge": nonmerge, "touching": len(touching),
            "added_lines_first_party": tot_lines,
            "excluded_lines": {k: sum(x["excl"][k] for x in commits) for k in ("lockfile", "vendor", "generated")},
            "largest_commit": big and big["sha"],
            "largest_subject": big and big["subject"], "largest_share": round(share, 3), "unit": unit,
            "span_hours": round(span_h, 2),
            "per_commit": [{"sha": x["sha"], "first_party_lines": x["lines"], "files": x["changed"],
                            "excluded": x["excl"]} for x in commits[:60]]}
    c.log("E6 summary: %s", data)

    c.expect(total_commits > 1, f"commits reachable from HEAD = {total_commits} (want > 1)")
    c.expect(len(touching) >= 2, f"commits that change files = {len(touching)} (want >= 2)")
    c.expect(share < DUMP_SHARE,
             f"largest commit {big and big['sha']} holds {share:.0%} of added {unit} "
             f"(first-party, dump threshold {DUMP_SHARE:.0%})")
    return c.done(f"{total_commits} commits ({nonmerge} non-merge) over {span_h:.1f} h; largest commit "
                  f"{big and big['sha']} = {share:.0%} of {tot_lines} first-party added lines (excl. lockfiles, vendor/, generated)", data)


# ======================================================================== E1

E1_TIMEOUT = 1500.0


@check("E1")
def e1(c) -> Result:
    """./scripts/test.sh exits 0 on a clean clone (after teardown)"""
    want = (c.setup or {}).get("commit")
    if not want:
        return c.error("setup.json has no commit (S0 failed?)")
    dest = c.tmp / "e1"
    p = _git(c, "clone", "--no-hardlinks", str(c.repo), str(dest), cwd=c.tmp, timeout=300)
    if p.rc != 0:
        time.sleep(2)
        p = _git(c, "clone", "--no-hardlinks", str(c.repo), str(dest), cwd=c.tmp, timeout=300)
    if p.rc != 0:
        return c.error(f"git clone of WORK/repo failed rc={p.rc}")
    h = _git(c, "rev-parse", "HEAD", cwd=dest)
    got = h.out.decode().strip()
    if got != want:
        return c.error(f"clean clone HEAD {got[:12]} != setup commit {want[:12]}")
    s = _git(c, "status", "--porcelain", "--ignored", cwd=dest)
    if s.out.strip():
        return c.error(f"fresh clone is not clean: {s.out.decode('utf-8', 'replace')[:200]}")
    script = dest / "scripts" / "test.sh"
    if not script.is_file():
        c.expect(False, "scripts/test.sh missing from the clean clone")
        return c.done()

    t0 = time.monotonic()
    pr = lib._run(["bash", "./scripts/test.sh"], cwd=dest, env=dict(os.environ), stdin=b"",
                  timeout=E1_TIMEOUT)
    secs = time.monotonic() - t0
    full = (b"===== stdout =====\n" + pr.out + b"\n===== stderr =====\n" + pr.err).decode("utf-8", "replace")
    try:
        (c.out / "logs" / "E1.testsh.txt").write_text(c.redact(full), encoding="utf-8")
    except OSError as e:
        c.log("could not write E1.testsh.txt: %s", e)
    c.log("E1 test.sh rc=%s %.1fs out=%dB err=%dB\n--- stdout tail ---\n%s\n--- stderr tail ---\n%s",
          pr.rc, secs, len(pr.out), len(pr.err),
          pr.out[-4000:].decode("utf-8", "replace"), pr.err[-4000:].decode("utf-8", "replace"))

    # best-effort cleanup of anything test.sh left running; never affects the verdict
    prefix = (c.setup or {}).get("compose")
    if prefix and any((dest / n).exists() for n in ("compose.yaml", "compose.yml", "docker-compose.yml")):
        d = lib._run(list(prefix) + ["down", "-v"], cwd=dest, env=dict(os.environ), stdin=b"", timeout=180)
        c.log("E1 cleanup compose down -v rc=%s", d.rc)

    tail = " ".join((pr.err or pr.out)[-300:].decode("utf-8", "replace").split())[-160:]
    data = {"rc": pr.rc, "seconds": round(secs, 1), "stdout_bytes": len(pr.out), "stderr_bytes": len(pr.err),
            "commit": want[:12], "full_output": "logs/E1.testsh.txt"}
    if pr.rc == 124:
        c.expect(False, f"./scripts/test.sh timed out after {int(E1_TIMEOUT)} s")
    else:
        c.expect(pr.rc == 0, f"./scripts/test.sh rc={pr.rc} after {secs:.0f} s (want 0); tail: {tail}")
    return c.done(f"./scripts/test.sh rc=0 in {secs:.0f} s on clean clone {want[:12]} "
                  f"({len(pr.out) + len(pr.err)} bytes output)", data)
