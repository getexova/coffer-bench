"""Coffer grading harness: the check registry.

Single source of truth for every GRADER.md ID. Python standard library only.
See CONTRACT.md for the full API. This file owns:
  - REGISTRY: dict id -> Row (all 85 GRADER IDs, G1..E6)
  - MODULES: module file -> the exact set of IDs it may register
  - @check(ID): the decorator check modules use
  - Result / not_implemented(): the result record
  - closure(ids): the --only dependency closure
"""
from __future__ import annotations

import dataclasses
import sys
from typing import Callable, Dict, FrozenSet, List, Optional, Tuple

# --------------------------------------------------------------------------
# Result record
# --------------------------------------------------------------------------

STATUSES = ("pass", "fail", "error", "na", "skip", "timeout")


@dataclasses.dataclass
class Result:
    """What a check returns (built via c.ok/c.fail/c.error/c.na/c.done, or
    directly). The runner adds id, ms, log, controls, guard, rollback."""
    status: str            # one of STATUSES (checks may return pass/fail/error/na only)
    evidence: str = ""     # ONE line, <= 300 chars, already redacted
    data: Optional[dict] = None   # optional small JSON-able detail (redacted)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"bad status {self.status!r}")
        self.evidence = " ".join(str(self.evidence).split())[:300]


def not_implemented(cid: str) -> Result:
    """What every stub returns."""
    return Result("error", "error: not implemented")


# --------------------------------------------------------------------------
# Registry rows
# --------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Row:
    id: str
    module: str            # file name that owns the check, e.g. "checks_f.py"; "na" for na IDs
    points: int            # gate = 0, P1 = 1, else 2
    blocker: bool          # GRADER.md ship-blocker
    order: int             # global run order (ascending, unique)
    timeout: int           # seconds, wall clock for the whole check subprocess
    destructive: bool      # runner wraps in checkpoint -> check -> snapshot -> rollback
    needs: Tuple[str, ...] # IDs (or setup tags) that must have run before this one
    title: str
    stack: bool = True     # needs the running compose stack (False = static/repo-only)
    proxied: bool = False  # c.cli() talks to the server through mitmdump (X18 capture)
    denial: bool = False   # a pass requires >= 1 recorded positive control
    allow_5xx: bool = False  # a 5xx seen by c.http does not auto-fail the check
    na: bool = False       # recorded as status "na" by the runner, never executed


# Setup tags (pseudo-needs). They always run; listed in needs for documentation.
SETUP_TAGS = ("setup",)

P1_IDS = {"F18", "X19", "X20", "O10", "E6"}
GATE_IDS = {"G1", "G2", "G3"}
BLOCKERS = {"G3", "S1", "S2", "S3", "S4", "S5", "S9", "S10", "S13", "S14", "S16",
            "S17", "X1", "X2", "X6", "X10", "A1", "A3", "A5", "O5", "O7"}
NA_IDS = {"G1", "E2", "E4", "E5"}

MODULES: Dict[str, FrozenSet[str]] = {
    "checks_g_o.py": frozenset(["G2", "G3"] + [f"O{i}" for i in range(1, 11)]),
    "checks_f.py": frozenset(f"F{i}" for i in range(2, 19)),
    "checks_s_a.py": frozenset(f"S{i}" for i in range(1, 13)),
    "checks_s_b.py": frozenset(f"S{i}" for i in range(13, 21)),
    "checks_x_a.py": frozenset(f"X{i}" for i in range(1, 11)),
    "checks_x_b.py": frozenset(f"X{i}" for i in range(11, 21)),
    "checks_a.py": frozenset(f"A{i}" for i in range(1, 9)),
    "checks_e.py": frozenset(["E1", "E3", "E6"]),
    "fixture.py": frozenset(["F1"]),
}

F_ALL = tuple(f"F{i}" for i in range(1, 19))

# (id, order, timeout, destructive, needs, title, extra-flags)
# Extra flags: s=static(stack False), p=proxied, d=denial, 5=allow_5xx
_T = [
    # --- gate / na -----------------------------------------------------------
    ("G1", 0, 0, False, (), "README quickstart verbatim on a fresh clone and user (manual, recorded na)", "s"),
    # --- phase 1: setup-owned F1 ------------------------------------------------
    ("F1", 100, 1200, False, ("setup",), "Fixture builds entirely via CLI; every command exits 0 (protected writes = 7)", "p"),
    # --- phase 2: static and setup-observed ---------------------------------------
    ("G2", 200, 60, False, ("setup",), "up.sh returns 0 within 180 s and /readyz = 200 (observed during setup)", ""),
    ("O9", 210, 60, False, ("setup",), "No :latest and no untagged image in compose or Dockerfiles", "s"),
    ("O2", 220, 60, False, ("setup",), "server container user is not uid 0", ""),
    ("X15", 230, 600, False, ("setup",), "osv-scanner over lockfiles: 0 High/Critical; lockfiles exist", "s"),
    ("X16", 240, 600, False, ("setup",), "gitleaks across full history: no findings beyond .env.example placeholders", "s"),
    ("X17", 250, 60, False, ("F1",), "CLI config: dir 0700, file 0600", ""),
    ("E3", 260, 60, False, ("setup",), "CI workflow runs lint, test and build", "s"),
    ("E6", 270, 60, False, ("setup",), "More than 1 commit; history is not a single dump", "s"),
    # --- phase 3: F block through the proxy, then X18 ------------------------------
    ("F2", 300, 180, False, ("F1",), "set -> get byte-exact: empty, 1 byte, 65,536 bytes, MULTI, stdin ending in \\n", "p"),
    ("F3", 305, 180, False, ("F1",), "65,537 bytes -> exit 6, nothing stored; bad keys -> exit 6", "p"),
    ("F4", 310, 180, False, ("F1",), "history v1..n; get --version k; rollback --to 1 creates v(n+1) = v1", "p"),
    ("F5", 315, 180, False, ("F1",), "delete -> get exit 5; tombstone in history; set again continues numbering", "p"),
    ("F6", 320, 180, False, ("F1",), "--expect-version stale -> exit 8, unchanged; correct -> succeeds", "p"),
    ("F7", 325, 300, False, ("F1",), "20 parallel unconditional sets -> 20 contiguous versions; final = highest", "p"),
    ("F8", 330, 180, False, ("F1",), "export dotenv byte-exact to the 7.1 escaping rule; sorted; LF; trailing newline", "p"),
    ("F9", 335, 180, False, ("F1",), "export json round-trips through jq to exact values", "p"),
    ("F10", 340, 300, False, ("F1",), "run: env injection, override, exit 42, 143, SIGTERM forwarding, stdin", "p"),
    ("F11", 345, 180, False, ("F1",), "COFFER_TOKEN with empty HOME works and creates no config file", "p"),
    ("F12", 350, 180, False, ("F1",), "Protected write by writer -> exit 7 + id; admin approves; audit shows both", "p"),
    ("F13", 355, 180, False, ("F1",), "reject -> value unchanged, status rejected", "p"),
    ("F14", 360, 180, False, ("F1",), "Two pending CRs on one key: approve first, second -> 409 / exit 8, stale", "p"),
    ("F15", 365, 180, False, ("F1",), "Protected delete and protected rollback both go through change requests", "p"),
    ("F16", 370, 180, False, ("F1",), "--json parses for list, get, history, token create, change list, audit list", "p"),
    ("F18", 375, 180, False, ("F1",), "Created user must change password before any other call; passwd works", "p"),
    ("F17", 380, 600, False, ("F1",), "Data survives down.sh + up.sh", "p"),
    ("X18", 390, 300, False, F_ALL, "No secret value or token in any URL (mitmdump capture of F block + request logs)", ""),
    # --- phase 4: S block -----------------------------------------------------------
    ("S1", 400, 300, False, ("F1",), "globex owner -> acme web and every route under it -> 404 identical to nonexistent", "d"),
    ("S2", 405, 300, False, ("F1",), "Colliding slug: globex api/dev returns only globex values; no acme canary ever", ""),
    ("S3", 410, 300, True, ("F1",), "IDOR with acme IDs by globex owner -> 404; acme state unchanged", "d"),
    ("S4", 415, 300, False, ("F1",), "Platform admin -> every org-scoped route 404; only /admin/* works", "d"),
    ("S5", 420, 300, False, ("F1",), "nogrant -> api -> 404 everywhere", "d"),
    ("S6", 425, 300, False, ("F1",), "viewer: list 200, values 403, writes 403", "d"),
    ("S7", 430, 300, False, ("F1",), "reader: get/export/run work; writes 403", "d"),
    ("S8", 435, 300, False, ("F1",), "writer: dev writes 200; prod -> 202", ""),
    ("S9", 440, 300, True, ("F1",), "Members: approve, member/grant/token management, audit list -> 403", "d"),
    ("S10", 445, 300, False, ("F1",), "Two-person rule: proposer cannot approve own CR as writer, admin, owner; admin2 can", "d"),
    ("S11", 450, 300, True, ("F1",), "Admin cannot create, promote, demote or remove an owner (403)", "d"),
    ("S12", 455, 300, False, ("F1",), "Last owner cannot demote or remove themselves -> 409", ""),
    ("S13", 460, 300, True, ("F1",), "Self-escalation via PATCH/POST with extra fields rejected or ignored; state re-read", ""),
    ("S14", 465, 300, False, ("F1",), "T_dev_rw -> api/prod, web, globex -> 404; T_dev_r writes 403", "d"),
    ("S15", 470, 180, False, ("F1",), "T_prod_rw set -> 202 (a token cannot skip approval)", ""),
    ("S16", 475, 300, True, ("F1",), "Service tokens -> approve, members, POST /tokens, audit, /auth/token -> 403/401", "d"),
    ("S17", 480, 300, False, ("F1",), "Revoked and expired tokens -> 401 on the next request (<= 1 s)", "d"),
    ("S18", 485, 300, False, ("F1",), "Removed user's PAT 401; lowered grant next request; revoked grant 404", "d"),
    ("S19", 490, 300, False, ("F1",), "Disabled org: PATs and tokens 401/403; other org unaffected", "d"),
    ("S20", 495, 300, False, ("F1",), "Only health + /auth/token unauthenticated; other paths 404; bad bearers 401", "d"),
    # --- phase 5: non-destructive X ------------------------------------------------------
    ("X5", 500, 180, False, ("F1",), "Password hashes argon2id / bcrypt>=12 / scrypt; 11-char password rejected", ""),
    # r4: X7 runs LAST of all stack rows (after the sweeps) so its deliberate failed logins
    # cannot leave a source limiter tripped for a later row. Timeout = up to 5 limiter
    # windows x 15 min + 15 min margin (build-2 measured ~12 pairs per window).
    ("X7", 985, 5400, False, ("F1",), "Unknown email vs wrong password: same status, same body, median latency within 25%", ""),
    ("X8", 501, 1200, False, ("F1",), "5 failures -> 429 even with correct password; another account unaffected", ""),
    ("X9", 515, 180, False, ("F1",), "JSON content type, nosniff, no-store on every /api/v1 response; no CORS", ""),
    ("X10", 502, 1800, True, ("F1",), "Injection payloads in every param and field -> 4xx, no 500, no foreign data", ""),
    ("X11", 525, 180, False, ("F1",), "Error shape {error:{code,message}}; no traces, paths or SQL in bodies", ""),
    ("X12", 530, 60, False, ("F1",), "2 MiB body -> 413 in < 1 s", ""),
    ("X13", 535, 120, False, ("F1",), "Logout revokes the PAT server-side (reuse -> 401)", "d"),
    ("X14", 540, 180, False, ("F1",), "Passwords never in argv (ps during login, member add, admin org create)", ""),
    ("X19", 545, 120, True, ("F1",), "(P1) Audit rows: UPDATE/DELETE as the server's DB role -> permission denied", ""),
    ("X20", 550, 120, False, ("F1",), "(P1) Password change revokes the user's other PATs", "d"),
    # --- phase 6: A (non-destructive) ------------------------------------------------------
    ("A1", 600, 600, False, ("F1",), "Every value read, write, CR, member/grant/token change and login emits an event", ""),
    ("A2", 605, 300, False, ("F1",), "Denials logged as denied in the actor's org log; no cross-org leak; platform log", ""),
    ("A4", 610, 120, False, ("F1",), "audit verify and admin audit verify pass on the untouched logs", ""),
    ("A7", 615, 180, False, ("F1",), "Filters --actor, --action, --since, --limit return the correct subsets", ""),
    ("A8", 620, 180, False, ("F1",), "Change-request lifecycle created/approved/rejected/stale all audited", ""),
    # --- phase 7: O runtime ------------------------------------------------------------------
    ("O1", 700, 300, False, ("F1",), "/healthz 200; db stop -> /readyz 503 <= 10 s; db start -> 200 without server restart", "5"),
    ("O3", 705, 300, False, ("F1",), "SIGTERM with 20 in-flight requests: clean completion or error; exit <= 10 s", "5"),
    ("O4", 710, 120, False, ("F1",), "Request logs JSON lines with method, route, status, duration_ms, request_id", ""),
    ("O6", 715, 900, False, ("F1",), "3x down/up: migrations idempotent, no errors, data intact", ""),
    ("O10", 720, 600, False, ("F1",), "(P1) list of 1,000 secrets p95 < 300 ms; 50 concurrent gets p95 < 200 ms", ""),
    # --- phase 8: env-override (destructive) ------------------------------------------------
    ("G3", 800, 600, True, ("setup",), "init-env writes a real random master key; placeholder key -> server refuses", "5"),
    ("X3", 805, 600, True, ("setup",), "Placeholder, short or missing master key -> refuse to start", "5"),
    ("O8", 810, 900, True, ("setup",), "Unset each required env var -> non-zero exit naming it", "5"),
    # --- phase 9: restore-class (destructive) -------------------------------------------------
    ("O7", 900, 900, True, ("F1",), "backup -> wipe volume -> restore into fresh stack -> all intact; verify passes", ""),
    ("X4", 905, 900, True, ("F1",), "Key rotation PREVIOUS+MASTER, then MASTER=new, then MASTER=old fails closed", "5"),
    ("X2", 910, 300, True, ("F1",), "AAD binding: copied ciphertext onto another key/env/org must fail to read", "5"),
    ("A5", 915, 300, True, ("F1",), "Tamper a mid-chain row -> verify exits 9 with first_invalid_seq = that row", ""),
    ("A6", 920, 300, True, ("F1",), "Delete a mid-chain row -> verify exits 9 at the following sequence", ""),
    # --- phase 10: sweeps ----------------------------------------------------------------------
    ("X1", 950, 900, False, ("F1",), "Canary sweep: canaries/tokens/passwords absent from dumps, logs, backups, CLI config", ""),
    ("X6", 955, 300, False, ("F1",), "Tokens not in the dump in plaintext", ""),
    ("A3", 960, 300, False, ("F1",), "No canary, token or password in any audit row", ""),
    ("O5", 965, 300, False, ("F1",), "No Authorization, cookie, token, password or value in the logs", ""),
    # --- phase 12: after teardown ----------------------------------------------------------------
    ("E1", 990, 1800, False, ("setup",), "./scripts/test.sh exits 0 on a clean clone (after teardown)", "s"),
    # --- na ----------------------------------------------------------------------------------------
    ("E2", 991, 0, False, (), "Tests include authorization tests (manual spot-check, recorded na)", "s"),
    ("E4", 992, 0, False, (), "docs/SECURITY.md threat model is complete and true (manual, recorded na)", "s"),
    ("E5", 993, 0, False, (), "ARCHITECTURE.md matches the code; DECISIONS.md exists (manual, recorded na)", "s"),
]


def _module_of(cid: str) -> str:
    if cid in NA_IDS:
        return "na"
    for mod, ids in MODULES.items():
        if cid in ids:
            return mod
    raise RuntimeError(f"no module for {cid}")


def _points(cid: str) -> int:
    if cid in GATE_IDS:
        return 0
    return 1 if cid in P1_IDS else 2


def _build() -> Dict[str, Row]:
    reg: Dict[str, Row] = {}
    for cid, order, timeout, destr, needs, title, flags in _T:
        if cid in reg:
            raise RuntimeError(f"duplicate registry row {cid}")
        reg[cid] = Row(
            id=cid, module=_module_of(cid), points=_points(cid), blocker=cid in BLOCKERS,
            order=order, timeout=timeout, destructive=destr, needs=tuple(needs), title=title,
            stack="s" not in flags, proxied="p" in flags, denial="d" in flags,
            allow_5xx="5" in flags, na=cid in NA_IDS,
        )
    return reg


REGISTRY: Dict[str, Row] = _build()

EXPECTED_IDS = (
    [f"G{i}" for i in range(1, 4)] + [f"F{i}" for i in range(1, 19)]
    + [f"S{i}" for i in range(1, 21)] + [f"X{i}" for i in range(1, 21)]
    + [f"A{i}" for i in range(1, 9)] + [f"O{i}" for i in range(1, 11)]
    + [f"E{i}" for i in range(1, 7)]
)


def _selfcheck() -> None:
    assert len(EXPECTED_IDS) == 85
    assert set(REGISTRY) == set(EXPECTED_IDS), set(REGISTRY) ^ set(EXPECTED_IDS)
    orders = [r.order for r in REGISTRY.values()]
    assert len(orders) == len(set(orders)), "orders must be unique"
    owned = set().union(*MODULES.values()) | NA_IDS
    assert owned == set(EXPECTED_IDS), owned ^ set(EXPECTED_IDS)
    for r in REGISTRY.values():
        for n in r.needs:
            assert n in REGISTRY or n in SETUP_TAGS, (r.id, n)
            if n in REGISTRY:
                assert REGISTRY[n].order < r.order, (r.id, n)
    assert {r.id for r in REGISTRY.values() if r.blocker} == BLOCKERS


_selfcheck()


def ordered(ids=None) -> List[Row]:
    """Rows sorted by order. ids=None -> all rows."""
    rows = REGISTRY.values() if ids is None else (REGISTRY[i] for i in ids)
    return sorted(rows, key=lambda r: r.order)


def closure(ids) -> List[Row]:
    """--only resolution: the given IDs plus, transitively, every registry ID
    in their needs. Setup tags are dropped (setup always runs). Unknown ID ->
    KeyError. Returned in run order."""
    seen = set()
    stack = list(ids)
    while stack:
        cid = stack.pop()
        if cid in SETUP_TAGS or cid in seen:
            continue
        if cid not in REGISTRY:
            raise KeyError(cid)
        seen.add(cid)
        stack.extend(REGISTRY[cid].needs)
    return ordered(seen)


# --------------------------------------------------------------------------
# @check decorator
# --------------------------------------------------------------------------

CheckFn = Callable[..., Result]
_IMPLS: Dict[str, CheckFn] = {}


class RegistryError(RuntimeError):
    pass


def check(cid: str) -> Callable[[CheckFn], CheckFn]:
    """Register fn(c) -> Result as the implementation of GRADER ID `cid`.

    Raises RegistryError at import time if: cid is not in REGISTRY; cid is an
    na ID; cid is already registered; or the decorated function's defining
    file is not the registry's module for cid."""
    def deco(fn: CheckFn) -> CheckFn:
        if cid not in REGISTRY:
            raise RegistryError(f"unknown check id {cid!r}")
        row = REGISTRY[cid]
        if row.na:
            raise RegistryError(f"{cid} is recorded na and may not be implemented")
        if cid in _IMPLS:
            raise RegistryError(f"duplicate implementation of {cid}")
        modfile = sys.modules[fn.__module__].__file__ or ""
        base = modfile.replace("\\", "/").rsplit("/", 1)[-1]
        if base != row.module:
            raise RegistryError(f"{cid} belongs to {row.module}, not {base}")
        _IMPLS[cid] = fn
        return fn
    return deco


def impl(cid: str) -> Optional[CheckFn]:
    """The registered function for cid, or None (runner records 'error: not implemented')."""
    return _IMPLS.get(cid)


def implemented() -> Dict[str, CheckFn]:
    return dict(_IMPLS)


def module_name(row: Row) -> str:
    """Importable module name for a row ("checks_f.py" -> "checks_f")."""
    return row.module[:-3] if row.module.endswith(".py") else row.module


def load_all(skip=()) -> List[str]:
    """Import every module file in MODULES except those named in `skip`
    (e.g. skip=("fixture.py",)). Used by --list and the runner's pre-flight.
    An import error propagates. Returns the non-na IDs with no implementation."""
    import importlib
    for mod in MODULES:
        if mod not in skip:
            importlib.import_module(mod[:-3])
    return [cid for cid, r in REGISTRY.items() if not r.na and cid not in _IMPLS]


if __name__ == "__main__":
    for r in ordered():
        flags = "".join(f for f, on in (("B", r.blocker), ("D", r.destructive), ("s", not r.stack),
                                        ("p", r.proxied), ("d", r.denial), ("5", r.allow_5xx),
                                        ("n", r.na)) if on)
        print(f"{r.order:4d} {r.id:4s} {r.points} {flags:6s} {r.timeout:5d} {r.module:15s} {r.title}")
