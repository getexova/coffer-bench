# Coffer grading harness: CONTRACT (v1)

This is the interface that three core authors (lib.py, fixture.py, run.py) and eight module authors (checks_*.py) code against **independently**. Nobody can ask anybody. If something here is ambiguous, pick the reading that is **stricter on the build and identical for both builds**, and write it down in your module's docstring.

Ground rules (apply to every file):
- Python 3.14 **standard library only**. The harness runs on the grading host as `grader1` or `grader2` and is started with `python3 -I run.py ...`. `run.py` puts its own directory first on `sys.path`. Never rely on the current directory.
- **Black-box only.** Checks may use the README, `./bin/coffer`, the HTTP API in SPEC §7.2, the scripts in SPEC §5, `psql` / `pg_dump` / `pg_dumpall` against the `db` container, container logs, `ps`, the compose CLI, and repo-level files GRADER.md tells us to inspect (compose.yaml, Dockerfiles, lockfiles, `.github/workflows/*`, git history, `.env.example`, `.env`). Never read application source to decide anything, and never edit any file in the clone except `.env` through `c.env_override` (runner-restored).
- **Identical treatment.** No branch may depend on which build is running. Calibration (§3.4) is measured once, recorded, and applied the same way for both builds.
- **Deterministic.** Fixed order, fixed inputs, no wall-clock-dependent branching except explicit timeouts. Random data (canaries, passwords, keys) comes from `secrets`. That is fine because checks compare against recorded values, never against constants.
- **Any 5xx fails the check** (GRADER: "Any 500 anywhere is a fail"). `c.http` and `c.cli` record every 5xx they see, and the runner turns a `pass` into `fail` if one was seen, unless the row has `allow_5xx`. A 5xx inside a `c.denied` or `c.same_404` probe is always a fail, even with `allow_5xx`.

Files and owners:

| file | owner | contents |
|---|---|---|
| `registry.py` | done (this delivery) | `REGISTRY`, `Row`, `Result`, `@check`, `closure`, `MODULES` |
| `lib.py` | core author A | `Context` (`c`) and every helper in §3, `Resp`, `CliResult`, `Actor`, `Sweep` |
| `fixture.py` | core author B | setup steps S0–S6 (§5) and the F1 check |
| `run.py` | core author C | CLI (§8), scheduler, subprocess isolation, checkpoint/rollback, guard, output |
| `checks_*.py` | module authors | check bodies, one function per ID, registered with `@check` |

---

## 1. Registry and the `@check` decorator (registry.py, already written)

```python
from registry import check, Result, not_implemented, REGISTRY, Row

@check("S5")
def s5(c) -> Result:
    ...
    return c.done()
```

- `@check(cid)` raises `registry.RegistryError` **at import time** if `cid` is not one of the 85 IDs, is an `na` ID (G1, E2, E4, E5), is already registered, or is decorated in a file other than `REGISTRY[cid].module`. Each module may register only its own IDs (`registry.MODULES`).
- A check function takes exactly one positional argument `c` (a `lib.Context`) and **returns a `registry.Result`**. Returning `None` counts as `error: check returned None`. An uncaught exception counts as `error: <ExcType>: <first line>` and the traceback goes to the check log. `NotImplementedError` counts as `error: not implemented`.
- Checks must not print. Use `c.log`.
- Checks must not call `sys.exit`, `os._exit`, `signal.signal` or `os.chdir`.
- `Row` fields: `id, module, points (gate 0 / P1 1 / else 2), blocker, order, timeout (s), destructive, needs (tuple), title, stack (needs running stack), proxied (CLI goes via mitmdump), denial (pass needs >= 1 positive control), allow_5xx, na`.
- `registry.closure(ids)` returns the `--only` closure (§7). `registry.ordered()` returns all rows in run order. `registry.load_all(skip=())` imports every module and returns the non-na IDs that have no implementation.

### 1.1 Result record

```python
@dataclass
class Result:
    status: str          # "pass" | "fail" | "error" | "na"   (checks never return "skip"/"timeout")
    evidence: str = ""   # one line, whitespace-collapsed, truncated to 300 chars, MUST be redacted
    data: dict | None = None   # optional small JSON-able detail, redacted, <= 16 KiB serialized
```

Meaning of the statuses:
- `pass`: the build did what GRADER requires.
- `fail`: the build violated it. The evidence names the first violation.
- `error`: the **harness** could not decide (a control failed, a precondition was missing, a prerequisite tool is absent, the stack is down, the check is not implemented). An `error` is not a build failure. It must be investigated before the result is final.
- `na`: recorded only for G1, E2, E4, E5 (manual) or when the GRADER item truly does not apply. Checks should almost never return it.
- `skip` (runner only): not selected under `--only`.
- `timeout` (runner only): the check subprocess exceeded `Row.timeout`.

The runner writes one JSON object per line to `OUT/results.jsonl`:

```json
{"id":"S5","status":"pass","points_possible":2,"points":2,"blocker":true,
 "evidence":"...","data":{...},"ms":1234,"log":"logs/S5.log",
 "controls":3,"saw_5xx":[],"guard":"ok","rollback":"ok|n/a|failed: ...",
 "order":420,"started":"2026-10-26T15:00:00Z"}
```

`points` = `points_possible` if the status is `pass`, else 0 (`na`/`skip` → `null`).

---

## 2. Conventions used by every helper

- **Actors** are named by label strings:
  - `"root"`: platform admin.
  - `"owner@acme"`, `"admin@acme"`, `"admin2@acme"`, `"writer@acme"`, `"reader@acme"`, `"viewer@acme"`, `"nogrant@acme"`, `"owner@globex"`.
  - Fixture tokens: `"T_dev_r"`, `"T_dev_rw"`, `"T_prod_rw"`, `"T_exp"`, `"T_rev"`.
  - `"anon"`: no `Authorization` header.
  - Scratch actors: any label returned by `c.scratch_user` / `c.scratch_token`.

  A label resolves to an `Actor` (§3.2). Each helper that takes `actor=` accepts a label or an `Actor`.
- **Emails**: label `"writer@acme"` ↔ email `writer@acme.test`. `"root"` ↔ `root@bench.test`.
- **Secrets for redaction.** Every password, token and canary the harness knows about is registered with `c.secret(label, value)`. Fixture values are pre-registered. Any value a check obtains (a token printed by `token create`, a scratch password) **must** be registered at once. Logs, evidence and `data` replace each registered value with `«label»`.
- **Bodies in logs** longer than 2048 bytes are written as the first 512 bytes, then `…[sha256=<hex> len=<n>]`.
- **Time.** `c.now()` returns a UTC `datetime`. Use `time.monotonic()` for durations.
- **Paths.** `c.repo` is the clone (`WORK/repo`). `c.out` is the output dir. `c.tmp` is a per-check scratch dir (`WORK/tmp/<ID>/`), created empty for every check run.

---

## 3. The context object `c` (lib.Context)

Constructed only by run.py: `lib.Context(row: registry.Row, work: Path, out: Path)`. It loads `OUT/setup.json`, `OUT/fixture.json` and `OUT/state.json`. Attributes:

| attribute | type | meaning |
|---|---|---|
| `c.id` | str | check ID |
| `c.row` | registry.Row | its registry row |
| `c.repo` | Path | the clone under test |
| `c.work`, `c.out`, `c.tmp` | Path | see §2 |
| `c.base_url` | str | `http://127.0.0.1:<COFFER_PORT>`, always direct to the server |
| `c.proxy_url` | str \| None | mitmdump reverse proxy URL, or None if the proxy is not running |
| `c.fx` | dict | parsed `fixture.json` (§5.2), read-only |
| `c.setup` | dict | parsed `setup.json` (§5.1), read-only |
| `c.state` | dict | persistent cross-check state (§3.9) |

### 3.1 HTTP

```python
class Resp:
    status: int            # 0 = transport error (connection refused / reset / timeout)
    headers: dict[str, str]   # lower-cased names; repeated headers joined with ", "
    body: bytes
    ms: float              # wall time of the request
    url: str               # full URL actually requested
    error: str | None      # transport error text when status == 0
    def json(self) -> Any            # json.loads(body); raises ValueError if not JSON
    def text(self) -> str            # body.decode("utf-8", "replace")
    def ok(self) -> bool             # 200 <= status < 300

def http(self, method: str, path: str, *, actor="anon", json=MISSING, body: bytes | None = None,
         headers: dict | None = None, query: dict | None = None, timeout: float = 15.0,
         base: str | None = None, raw_path: bool = False) -> Resp
def api(self, method: str, path: str, **kw) -> Resp
```

- `path` starts with `/`. `c.api("GET", "/projects")` is `c.http("GET", "/api/v1/projects")`. `c.http` uses `path` exactly as given, which you need for `/healthz` and for out-of-surface paths.
- `query` is URL-encoded with `urllib.parse.urlencode(query, doseq=True)` and appended.
- `raw_path=True` sends `path` byte-for-byte with no normalization or quoting. Use it for injection payloads such as `%00`, `../`, and homoglyphs. Implementation: `http.client.HTTPConnection.putrequest(method, path, skip_accept_encoding=True)`. `http.client` is used for everything, never `urllib.request`, so redirects are **not** followed.
- `json=` serializes with `json.dumps(obj, ensure_ascii=False).encode()` and sets `Content-Type: application/json`. `body=` sends the bytes as they are, with only the headers you give. Passing both raises `ValueError`.
- `actor` adds `Authorization: Bearer <actor.secret>` unless the actor is `anon`. An explicit `headers={"Authorization": ...}` wins (used for malformed bearers).
- **One fresh connection per call.** Thread-safe. Never raises on HTTP status. On transport failure it returns `Resp(status=0, error=...)`.
- `base=None` → `c.base_url`. Pass `base=c.proxy_url` to go through the proxy.
- Every call is written to the check log (method, path, actor label, status, ms, redacted request and response body). Any `status >= 500` is appended to `c.saw_5xx`.

### 3.2 Actors

```python
@dataclass
class Actor:
    label: str
    kind: str            # "user" | "token" | "anon"
    email: str | None
    password: str | None # current password (after any forced change)
    user_id: str | None
    org: str | None      # "acme" | "globex" | None (root, anon)
    role: str | None     # "platform_admin" | "owner" | "admin" | "member" | None
    secret: str | None   # bearer: the raw-API PAT for users, the token for service tokens
    token_id: str | None # service tokens only
    home: Path | None    # CLI HOME logged in as this user (fixture users only)

def actor(self, label_or_actor) -> Actor          # KeyError on unknown label
def scratch_user(self, org: str, role: str = "member", *, grants: dict[str, str] | None = None,
                 label: str | None = None) -> Actor
def scratch_org(self, slug: str | None = None) -> tuple[str, Actor]   # (org slug, its owner Actor)
def scratch_project(self, actor="owner@acme", *, envs=(("dev", False),), slug=None) -> str
def scratch_token(self, project: str, env: str, access: str, ttl_seconds: int = 3600,
                  *, actor="owner@acme", org: str = "acme") -> Actor
def scratch_home(self, actor=None) -> Path
```

- Fixture actors and fixture tokens are **shared and must never be mutated**. Do not log them out, change their passwords, remove them, change their role or grants, revoke their tokens, disable their org, or lock them out. If you need to do any of that, use a scratch actor.
- `scratch_user`: created over the raw API as the org's owner (`POST /members` with a fresh random 16-char password and the email `<c.id.lower()>-<n>@<org>.test`). It applies `grants` (`{project: level}`) through `PUT /members/{id}/grants/{project}`. It logs in through `POST /auth/token`. If any other call is then refused because a password change is required, it calls `POST /auth/password` with a new random password and logs in again. It returns an Actor with `home=None`. It raises `lib.HarnessError` if creation fails, which the runner records as `error`.
- `scratch_org`: created as root through `POST /admin/orgs`, with slug `<c.id.lower()>-<n>` and a scratch owner. Same password handling.
- `scratch_project`: `POST /projects` with slug `<c.id.lower()>-<n>`, then `POST /projects/{p}/envs` for each `(slug, protected)`. Returns the slug.
- `scratch_token`: `POST /tokens` as `actor`. Registers the token as a secret. The returned Actor has `kind="token"`.
- `scratch_home(actor=None)` returns a fresh empty dir under `c.tmp`. With an actor, it runs `coffer login --email ...` (password on stdin) in that HOME and returns it. Use it whenever a check logs in or out through the CLI.

### 3.3 CLI as an actor

```python
@dataclass
class CliResult:
    rc: int               # exit code; -N if killed by signal N; 124 if harness timeout
    out: bytes            # stdout, exact bytes
    err: bytes            # stderr, exact bytes
    ms: float
    argv: list[str]       # as executed, redacted when logged
    def json(self) -> Any            # json.loads(out); ValueError if not exactly one JSON doc
    def text(self) -> str

def cli(self, *args: str, actor=None, home: Path | None = None, stdin: bytes = b"",
        env: dict | None = None, json: bool = False, url: str | None = None,
        timeout: float = 60.0, proxy: bool | None = None) -> CliResult
def cli_spawn(self, *args: str, actor=None, home=None, stdin=subprocess.PIPE,
              env=None, json=False, url=None, proxy=None) -> subprocess.Popen
```

- Runs `c.repo/"bin"/"coffer"` with `args` and `cwd=c.tmp`. **Never through a shell.**
- **Isolated HOME.** The child environment is built from scratch, never inherited:
  `PATH=/usr/local/bin:/usr/bin:/bin`, `HOME=<home>`, `XDG_CONFIG_HOME` **unset**, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, `TERM=dumb`, `COFFER_URL=<url>`, then `env` overrides. A value of `None` in `env` removes that variable.
  - `home`: an explicit `home` wins. Otherwise, if `actor` is a fixture user, its fixture HOME is used. If `actor` is a token Actor, a fresh empty HOME is used and `COFFER_TOKEN=<token>` is set. If `actor` is None or `"anon"`, a fresh empty HOME is used.
  - `url`: an explicit `url` wins. Otherwise `c.proxy_url` is used when `proxy is True`, or when `proxy is None and c.row.proxied and c.proxy_url`. In every other case `c.base_url` is used.
- `json=True` adds the global `--json` flag at the **calibrated position** (`c.setup["cli"]["json_position"]`, `"front"` = right after `coffer`, `"end"` = after all args). Never put `--json` in `args` yourself.
- stdout is never a TTY (pipes). This is required for the "no added newline" rule.
- Passwords go on stdin as `password + "\n"` (two lines for `passwd`: `current\nnew\n`).
- `cli` is logged like `http`. If the build CLI prints an HTTP 5xx, the check sees it in rc/err. The harness does not try to parse that.
- `cli_spawn` returns a running `Popen` with `start_new_session=True` and stdout/stderr as PIPE. The caller must `communicate()` or kill it, and the runner kills the whole process group at the timeout. Use it for `run` signal tests (F10), `ps` during login (X14) and in-flight load (O3).
- `c.exit_for(status: int) -> int` maps an HTTP status to the SPEC exit code: 200/201→0, 202→7, 400/413/422→6, 401→3, 403→4, 404→5, 409→8, 429→10, else 1.

### 3.4 Calibration (done once by fixture.py, read by everyone)

`c.setup["cli"]` = `{"json_position": "front"|"end", "bin": "<abs path>", "ok": bool}`. fixture.py runs `coffer --json whoami` and `coffer whoami --json` as root once each and picks the **first** of `front`, `end` whose stdout parses as one JSON object (if both work, `front`). This is the only build-dependent choice. It is recorded and applied uniformly.

### 3.5 Database

```python
def psql(self, sql: str, *, db: str | None = None, user: str | None = None,
         timeout: float = 60.0) -> Psql
@dataclass
class Psql:
    rc: int; out: str; err: str
    rows: list[list[str]]     # parsed from -A -t -F '\x1f' output; NULL -> None
def pg_dumpall(self, label: str) -> Path    # full cluster dump as superuser into OUT/sweep/dumps/<seq>-<ID>-<label>.sql
def pg_dump_app(self, dest: Path) -> Path   # pg_dump -Fc of the app DB
def db_conn(self) -> dict                    # {"user","password","db","service":"db"} from .env
def server_db_role(self) -> str | None      # the role the server connects as
```

- Runs **inside the `db` container** with `c.compose("exec", "-T", "db", "psql", ...)`, `-v ON_ERROR_STOP=1 -X -q`, and SQL on stdin. The host never needs a published db port. The default user is `POSTGRES_USER` from `.env` (the superuser) and the default db is `POSTGRES_DB`.
- `user=` connects as that role (`psql -U role`, relying on the container's local trust auth; if that is refused, `rc != 0` and the check returns `error`).
- `server_db_role()` reads `SELECT DISTINCT usename FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend'` while the server is up. If exactly one non-superuser role is present, that role is returned. If only the superuser is present, the superuser is returned (the build uses the superuser, which X19 will then judge). If none are present, it returns None.
- Every `psql` call is logged with its SQL (redacted).

### 3.6 Compose, scripts, containers, logs

```python
def compose(self, *args: str, timeout: float = 300.0, env: dict | None = None) -> Proc
def script(self, name: str, *args: str, timeout: float = 300.0, stdin: bytes = b"") -> Proc  # ./scripts/<name>
def up(self, timeout: float = 240.0) -> Proc        # ./scripts/up.sh, then wait_ready
def down(self, timeout: float = 180.0) -> Proc      # snapshot logs, then ./scripts/down.sh
def wait_ready(self, timeout: float = 30.0) -> bool # polls GET /readyz every 0.5 s until 200
def container(self, service: str) -> str | None     # container id of a compose service
def inspect(self, service: str) -> dict | None      # `podman inspect` JSON of that container
def logs(self, service: str, *, since: float | None = None) -> bytes   # stdout+stderr, current container
def log_mark(self, service: str = "server") -> float   # a marker for logs(since=...)
def env_override(self, set: dict[str, str] | None = None, unset: list[str] = (),
                 *, wait: float = 45.0) -> Override
def ps(self) -> list[dict]                          # [{pid, user, args}] via `ps -eo pid=,user=,args=`
def parallel(self, fns: list[Callable[[], T]], workers: int = 20) -> list[T | Exception]
def wait_until(self, pred: Callable[[], bool], timeout: float, every: float = 0.25) -> bool
@dataclass
class Proc: rc: int; out: bytes; err: bytes; ms: float
```

- **Compose provider.** `c.setup["compose"]` = the argv prefix that setup detected, `["podman","compose"]` or `["docker","compose"]` (podman first). Every compose call is `prefix + list(args)` with `cwd=c.repo`, the inherited grader env plus `env`, and **no** `-p`/`-f` overrides. That way the harness addresses the same project the build's own scripts use.
- Scripts run with `cwd=c.repo`, through `bash`, with the grader's env.
- **Log preservation rule.** Anything that may remove or recreate a container (`down`, `env_override`, `compose("down"|"up"|"rm"|"restart"|"stop"...)`, rollback) must call `c.sweep_snapshot(label)` first. `c.down()`, `c.env_override()` and the runner do this automatically. If you call `c.compose` with one of those verbs, it also snapshots automatically.
- `env_override(set, unset)`: computes the new `.env` from the **checkpointed base `.env`** (not the current file), so successive calls in one check do not accumulate. It writes it, recreates only the `server` service (`compose up -d --force-recreate --no-deps server`), and then waits up to `wait` s until either `/readyz`=200 or the server container has exited or restarted at least twice. It returns:
  ```python
  @dataclass
  class Override:
      compose_rc: int; compose_err: bytes   # compose may itself refuse an unset var: that is a valid refusal
      ready: bool                            # /readyz reached 200
      running: bool                          # container running at the end of the wait
      exit_code: int | None; restarts: int
      logs: bytes                            # server logs since recreation
  ```
  Only destructive rows may call it. The runner restores `.env` and the stack (§6).
- `logs(service)` = `compose logs --no-color <service>` (stdout+stderr bytes).

### 3.7 Backups

```python
def backup(self, label: str) -> tuple[Proc, Path]    # ./scripts/backup.sh WORK/backups/<ID>-<label>.bak; copy into the sweep cache
def restore(self, path: Path) -> Proc                 # ./scripts/restore.sh <path>
def wipe_volumes(self) -> Proc   # snapshot; compose down -v; remove in-repo bind-mount dirs (via `podman unshare rm -rf`)
```
Every backup file is copied into `OUT/sweep/backups/`, where X1 scans it.

### 3.8 Positive controls: `denied` and `same_404`

A denial check that never proves its probe could have succeeded proves nothing. Both helpers run the **control first**, then the probe. Each `denied`/`same_404` call that runs a control successfully increments `c.controls`. For a row with `denial=True`, the runner downgrades a `pass` with `c.controls == 0` to `error: no positive control`.

```python
Req = Callable[[], Resp | CliResult]       # zero-arg closure that performs ONE request

def denied(self, probe: Req, control: Req, *, allow=(401, 403, 404), what: str = "") -> bool
def same_404(self, probe: Req, absent: Req, control: Req, *, what: str = "") -> bool
def control(self, req: Req, *, expect=(200, 201, 202, 204), what: str = "") -> bool
```

`denied(probe, control, allow, what)`:
1. Run `control()`. It must succeed: a Resp with a 2xx status, or a CliResult with rc 0 or 7. If it does not, call `c.error_once(f"control failed: {what}")`. That marks the check as **error** (not fail), whatever else happens. Return False, and do not run the probe.
2. Run `probe()`. For a Resp, a status in `allow` is a pass. For a CliResult, an rc in `{c.exit_for(s) for s in allow}` is a pass.
3. A 2xx, a 5xx, a transport error (status 0), or any other status records `c.expect(False, f"{what}: got {status}")` and returns False. For a CliResult, rc 0 and rc 1 are failures.
4. Return True on pass.

A control should be the **same route and the same kind of operation** done by an actor who is allowed, against the **same target**. For example, the control for "viewer GET value" is "reader GET value". When the probe is a write, the control may write to a junk key (`c.junk_key()`), never to a canary.

`same_404(probe, absent, control, what)`:
1. `control()` must succeed, as in `denied` step 1.
2. `absent()` targets a resource that does not exist (use `c.absent_slug()` / `c.absent_id()`). It must return **404**. Otherwise `error_once(f"absent target not 404: {what}")` and return False.
3. `probe()` must return 404, **and** its masked body must equal the masked body of `absent`. Masking applies these replacements, in this order, to the decoded text: the `X-Request-Id` header value, any UUID (`[0-9a-f]{8}-[0-9a-f]{4}-...`), any RFC3339 timestamp, and any 16+ char run of `[A-Za-z0-9_-]` that appears in that response's `X-Request-Id`. Each becomes `«X»`. The headers compared are `content-type` only. A mismatch → `c.expect(False, ...)`, return False.

`control(req, expect, what)` records a standalone positive control (counts toward `c.controls`). Use it when a check's own assertions imply the control, for example "the revoked token worked 1 s ago".

Helpers: `c.junk_key() -> str` (`JUNK_<ID>_<n>`), `c.absent_slug() -> str` (`zz-absent-<hex8>`), `c.absent_id() -> str` (32 hex chars).

### 3.9 State

`c.state` is a dict persisted at `OUT/state.json`. The runner loads it before each check and saves it after (the check runs in a subprocess).
- `c.put(key: str, value)` stores `state[f"{c.id}.{key}"] = value`. Values must be JSON-serializable and must not contain plaintext secrets. Store labels, not values.
- `c.get(key: str, default=None)` reads a fully qualified key such as `"F12.change_id"`, so a check can read another check's output. Treat a missing key as `error`, never as pass.
- Fixture-owned state lives in `c.fx`, not `c.state`.

### 3.10 Evidence log and the result

```python
def log(self, msg: str, *args) -> None      # appended to OUT/logs/<ID>.log, redacted, timestamped
def secret(self, label: str, value: str) -> str   # register for redaction + sweep; returns value
def expect(self, cond: bool, msg: str) -> bool    # record a sub-assertion; returns cond
def error_once(self, msg: str) -> None            # mark the check as harness-error (first message kept)
def ok(self, evidence: str = "", data=None) -> Result
def fail(self, evidence: str, data=None) -> Result
def error(self, evidence: str, data=None) -> Result
def na(self, evidence: str) -> Result
def done(self, pass_evidence: str = "", data=None) -> Result
```

`c.done()` builds the result from the recorded sub-assertions:
- If `error_once` was called → `error: <first error msg>`.
- Otherwise, if any `expect` was False → `fail` with evidence `"; ".join(first 3 failure msgs) + (" (+N more)" if more)`.
- Otherwise, if zero `expect`s were recorded and zero controls ran → `error: no assertions`.
- Otherwise → `pass` with `pass_evidence` (or `"N assertions ok"`).

Every assertion and its message also goes to the log. **Write an evidence string a grader can act on**, for example `viewer GET /projects/api/envs/dev/secrets/K -> 200 (want 403)`.

---

## 4. Sweep cache (X1, X6, A3, O5)

```text
OUT/sweep/
  dumps/<seq>-<ID>-<label>.sql        pg_dumpall snapshots (text, superuser)
  logs/<container_id>-<service>.log   one file per container id ever seen; appended, never truncated
  backups/<file>                      every backup.sh output
  homes/<label>/...                   copies of every CLI config dir (fixture + scratch homes)
  audit/<org-or-platform>.jsonl       full audit lists pulled via API (owner per org; root for platform)
  manifest.json                       {"final": bool, "snapshots":[{seq,id,label,when}], "needles": N}
OUT/secrets.jsonl                     {"label","value","kind": "canary|token|password|key"} (mode 0600)
```

- `c.sweep_snapshot(label: str) -> None`: pg_dumpall (when db is up), plus `logs` for every container currently in the compose project. Logs are keyed by **container id**, so a recreated container gets a new file and the old one is kept. Called automatically before every rollback, down, recreate, env_override and teardown, and once after F1.
- `c.sweep() -> Sweep`: the **first** call in a run takes a final snapshot (`label="final"`), copies every CLI home's config dir into `homes/`, pulls audit logs into `audit/`, and sets `manifest.final=true`. Later calls (the other sweep checks) reuse the cache and take no new snapshot. Sweep checks are `X1, X6, A3, O5`, and only they may call `c.sweep()`.
- `Sweep` API:
  ```python
  class Sweep:
      def needles(self, kinds=("canary","token","password")) -> list[tuple[str, str, str]]  # (label, kind, value)
      def files(self, source: str) -> list[Path]   # source in {"dumps","logs","backups","homes","audit"}
      def scan(self, sources=("dumps","logs","backups","homes"), kinds=("canary","token","password"),
               *, encodings=("raw","hex","HEX","b64")) -> list[Hit]
  @dataclass
  class Hit: source: str; file: str; label: str; kind: str; encoding: str; offset: int
  ```
  `scan` searches every file's raw bytes for every needle in each encoding (`raw` UTF-8, lowercase hex, uppercase hex, standard base64 of the exact value), skipping needles shorter than 12 bytes. Backups are scanned raw. If a backup is gzip (magic `1f8b`) it is also scanned decompressed. If it is a `pg_dump -Fc` archive (magic `PGDMP`), it is also scanned after `pg_restore -f -` run inside the db container. **Homes rule:** the CLI's own PAT is never a harness needle (the harness never sees it), so any needle hit in a home is a fail.
- Needles: every value registered with `c.secret`, every fixture canary, the MULTI canary's 40-char core, every fixture and scratch password (initial and changed), every token the harness saw, and the bootstrap admin password.
- The master key is **not** a needle for X1. A check may scan for kind `"key"` explicitly.
- Under `--only`, the sweep sees only the traffic of the selected closure. run.py sets `summary.partial=true`.

---

## 5. Setup and fixture (fixture.py)

fixture.py exposes:
```python
def setup(run) -> dict      # steps S0–S6 below; writes OUT/setup.json; never raises (records failures)
def teardown(run) -> dict   # snapshot, down.sh, compose down -v, remove in-repo bind dirs
@check("F1")
def f1(c) -> Result         # builds the fixture via CLI, writes OUT/fixture.json
```
`run` is run.py's `Runner` (attributes `work`, `out`, `bundle`, `repo`). fixture.py may call `lib` helpers through `lib.Context(registry.REGISTRY["F1"], work, out)`.

### 5.1 Setup steps (always run, even under `--only`)

| step | action | recorded in setup.json |
|---|---|---|
| S0 | `git clone <bundle> WORK/repo`, check out the bundle's HEAD (default branch), record the commit sha | `commit`, `clone_rc` |
| S1 | detect compose: `podman compose version` then `docker compose version` | `compose` (argv list), `compose_version` |
| S2 | `./scripts/init-env.sh` (stdout captured to setup.log, redacted). The bootstrap password is taken from `.env` `COFFER_BOOTSTRAP_ADMIN_PASSWORD`, never parsed from stdout, and registered as a secret. Copy `.env` to `WORK/base.env` | `init_env_rc`, `env_keys` (names only) |
| S3 | `./scripts/build.sh` (timeout 1200 s); `bin/coffer` exists and is executable | `build_rc`, `build_ms`, `bin_ok` |
| S4 | `./scripts/up.sh` timed (timeout 200 s), then `GET /readyz` | `up_rc`, `up_ms`, `readyz_status` (G2 reads these) |
| S5 | start `mitmdump --mode reverse:http://127.0.0.1:<port> --listen-host 127.0.0.1 --listen-port <port+10000> -w WORK/proxy.flows -s <addon writing OUT/proxy_urls.jsonl>` | `proxy_url`, `proxy_pid` |
| S6 | calibration (§3.4), the `root` login over the raw API | `cli` |

If S0–S4 fail, every `stack=True` check is recorded as `error: setup failed at <step>`. Static checks still run if S0 succeeded.

### 5.2 fixture.json (written by F1)

```json
{
  "orgs": {"acme": {"id": "..."}, "globex": {"id": "..."}},
  "users": {"<label>": {"email","password","initial_password","user_id","org","role","pat","home"}},
  "tokens": {"T_dev_r": {"id","token","project":"api","env":"dev","access":"read"}, "...": {}},
  "projects": {"acme": {"api": ["dev","prod"], "web": ["dev"]}, "globex": {"api": ["dev","prod"]}},
  "protected": [["acme","api","prod"]],
  "canaries": {"acme/api/dev/CANARY": "<40 chars>", "acme/api/prod/CANARY": "...", "acme/web/dev/CANARY": "...",
               "globex/api/dev/CANARY": "...", "globex/api/prod/CANARY": "...", "acme/api/dev/MULTI": "<full value>"},
  "multi_core": "<40 chars>",
  "changes": {"fixture_prod": "<change id>"},
  "steps": [{"argv": "...redacted...", "rc": 0, "want": 0}]
}
```
- `MULTI` = `core + '"' + '\\' + '$HOME' + '\n' + '\r\n' + '😀' + '\x01' + core[::-1]`, stored in acme/api/dev under key `MULTI`.
- Canaries are 40 chars from `[A-Za-z0-9]` (`secrets.choice`). The canary key is `CANARY` in each env.
- The acme prod canary is set by `writer` (exit 7, change id recorded) and approved by `admin`. The globex prod canary is set by the globex owner, and the same CR flow applies only if globex prod is protected (it is not).
- `pat`: a separate raw-API PAT from `POST /auth/token`, used by `c.http`. `home`: the CLI HOME where `coffer login` was run. The two sessions are independent, so logging out of one does not affect the other.
- Users created with an initial password go through `coffer passwd` in their home, and their raw login happens after that. `password` is the final password, `initial_password` the first. Both are secrets.
- `T_exp` is created with `--ttl 1m`. F1 records its `created_at` (`expires_at` = +60 s). S17 waits until 2 s past expiry.
- `T_rev` is created, then revoked through `coffer token revoke ID`.
- F1's verdict: `pass` iff every fixture CLI step exited with its expected code (0, or 7 for protected writes). Otherwise `fail` with the first bad step. Even if F1 fails, F1 still writes `fixture.json` with whatever it got. Later checks that miss a field return `error`.

---

## 6. Run order, isolation, checkpoint/rollback

### 6.1 Order
`setup` → checks in ascending `Row.order` (registry.py is authoritative) → `teardown` → E1 (fresh clone, after teardown, so the port is free) → na rows recorded.
Phases: 100 F1 · 200s static (G2 O9 O2 X15 X16 X17 E3 E6) · 300s F block via proxy (F17 last) then X18 · 400s S · 500s X non-destructive (+X10, X19 destructive) · 600s A · 700s O runtime · 800s env-override (G3 X3 O8) · 900s restore-class (O7 X4 X2 A5 A6) · 950s sweeps (X1 X6 A3 O5) · teardown · 990 E1 · na (G1 E2 E4 E5).
The builds are graded **one after the other**, never concurrently (shared port 8420).

### 6.2 Per-check isolation
- Each check runs as `python3 -I run.py --_child ID --work W --out O` in a new session (`start_new_session=True`). The child imports only `registry`, `lib` and `REGISTRY[ID].module`. On timeout the runner sends `SIGTERM` to the process group, then `SIGKILL` 5 s later, and records `timeout`.
- **Guard** after every check: `GET /readyz` == 200 within 30 s. Otherwise `./scripts/up.sh` once. If still not ready, rollback to the `base` checkpoint (taken right after F1). The result's `guard` field records `ok | upped | rolled-back | dead`. If `dead`, every later `stack=True` check is `error: stack unrecoverable`.

### 6.3 Checkpoint/rollback (rows with `destructive=True`)
Checkpoint (before the check):
1. `pg_dumpall --globals-only` → `WORK/ckpt/<ID>/globals.sql`
2. `pg_dump -Fc POSTGRES_DB` → `WORK/ckpt/<ID>/app.dump` (all pg tools run **inside** the db container via `compose exec -T db`, so the postgres:16 tool versions match; output is streamed to the host file); record the db owner (`SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()`).
3. copy `.env` → `WORK/ckpt/<ID>/env`.

Rollback (after the check, whatever the outcome, also after a timeout):
1. `c.sweep_snapshot(f"pre-rollback-{ID}")` (if the db is up).
2. Restore `.env` byte-for-byte.
3. `compose stop server`. Ensure `db` is running (`compose up -d db`) and accepting connections (`pg_isready` in the container, ≤ 60 s). If the db volume is gone, `compose up -d db` creates a fresh one.
4. As the superuser, connected to `postgres` (or `template1` if the app db is named `postgres`): `DROP DATABASE IF EXISTS <db> WITH (FORCE)`. Apply `globals.sql` with `ON_ERROR_STOP=0` (existing roles produce harmless errors). `CREATE DATABASE <db> OWNER <owner>`, then `pg_restore -d <db>` with `app.dump` on stdin (ownership preserved, no `--no-owner`).
5. `./scripts/up.sh` (recreates or starts the server). Wait for ready.
6. Verify: `GET /readyz` 200, **and** `owner@acme` raw-API GET of `acme/api/dev/CANARY` returns the recorded value. Pass → `rollback: ok`. Fail → `rollback: failed: <why>`, then the guard runs (which may roll back to `base`).

Non-destructive checks must still leave fixture state as it was: scratch actors only, junk keys only, never fixture tokens' revocation or fixture users' passwords. In the F block, any key a check writes in acme/api/dev or acme/api/prod must be prefixed `<ID>_` (for example `F4_HIST`). Canary keys (`CANARY`, `MULTI`) are read-only for everyone except F1.

---

## 7. `--only` and `needs`

- `--only F12,X18` → `registry.closure(["F12","X18"])`: those IDs plus, transitively, every registry ID in their `needs` (`X18` needs all of F1–F18). Setup always runs, and teardown always runs. E1 runs only if selected.
- Rows not in the closure are written to results.jsonl with status `skip`. `summary.partial=true`, and no verdict is computed for a partial run (`verdict: null`).
- `needs` controls **selection and order only**. A failed prerequisite does not skip its dependents. They run, and if a fixture field is missing they return `error`.

---

## 8. run.py CLI

```
python3 -I run.py --bundle PATH --work DIR --out DIR [--only ID[,ID...]] [--list]
```
- `--list`: import every module (`registry.load_all()`), print one line per row in run order (`order id points flags timeout module title`, flags `B`=blocker `D`=destructive `s`=static `p`=proxied `d`=denial `5`=allow_5xx `n`=na, then `impl`/`stub`), and exit 0. It needs no other argument. It exits 2 if any module fails to import or registers incorrectly.
- `--bundle` (required unless `--list`): the git bundle to grade.
- `--work` (required unless `--list`): created if missing, and must be empty. Exits 2 otherwise, never reuses a dirty tree.
- `--out` (required unless `--list`): created if missing, and must be empty. Exits 2 otherwise.
- `--only`: comma-separated IDs. An unknown ID exits 2.
- Exit code: 0 if the run completed (whatever the verdict), 1 if the harness itself crashed, 2 for usage errors.

### 8.1 Outputs
- `OUT/results.jsonl`: §1.1, one line per registry ID (85 lines in a full run), in run order.
- `OUT/summary.json`: `{"commit","started","finished","partial","p0_possible","p0_points","p0_pct","p1_points","total_points","blockers_failed":[ids],"errors":[ids],"timeouts":[ids],"verdict":"SHIP|FIX-THEN-SHIP|NOT SHIPPABLE|null","verdict_note"}`.
  - P0 points = the sum of `points` over rows with `points == 2`. `p0_possible` excludes `na` rows.
  - G1 is `na` (manual), so the harness never emits `SHIP`. Its best automatic verdict is `FIX-THEN-SHIP`, and `verdict_note` says "G1 strict/assisted decided manually; SHIP possible only if G1 strict".
  - Any `error` or `timeout` row → `verdict_note` includes "PROVISIONAL: N errors". The verdict is still computed with those rows at 0 points, and a blocker in error counts as **not passed but not failed**: it is listed in `errors`, not `blockers_failed`.
  - A blocker with status `fail` or `timeout` → NOT SHIPPABLE.
- `OUT/setup.json`, `OUT/fixture.json`, `OUT/state.json`, `OUT/logs/<ID>.log`, `OUT/logs/setup.log`, `OUT/sweep/...`, `OUT/proxy_urls.jsonl`.

---

## 9. Per-check notes for module authors (the non-obvious parts)

- **G2**: read `c.setup` (`up_rc == 0 and up_ms <= 180000 and readyz_status == 200`). Do not re-run up.sh.
- **G3**: in `c.tmp`, `git clone c.repo`, run `init-env.sh` twice (rm `.env` between), assert both `COFFER_MASTER_KEY`s base64-decode to 32 bytes, differ from each other and from `.env.example`'s. Then `env_override(set={"COFFER_MASTER_KEY": <placeholder from .env.example>})` → must not become ready. "Boots" means `ready` is True → fail.
- **X3**: three overrides: placeholder, a 16-byte base64 key, unset → each not `ready`.
- **O8**: for each required var in SPEC §5 (`COFFER_MASTER_KEY, COFFER_BOOTSTRAP_ADMIN_EMAIL, COFFER_BOOTSTRAP_ADMIN_PASSWORD, COFFER_PORT, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB`), `env_override(unset=[v])`. Pass for that var if (`compose_rc != 0` and `compose_err` names `v`) or (not `ready` and the server `logs` name `v`). The bootstrap vars only apply on an empty user table. If the server boots anyway with a bootstrap var unset because users already exist, that var counts as `na-by-design` and is noted, not failed.
- **X7/X8**: use **scratch users** (X7: rotate over 8 scratch users so no account reaches 5 failures; at most 4 wrong tries per account per 15 min).
- **S17**: assert that the token worked right before (control), revoke, then the **next** request within 1 s → 401.
- **S12/S19**: use `c.scratch_org()`, never acme or globex.
- **S3/S11/S13**: re-read acme state afterward (members, roles, grants, token list, change statuses) and compare with the state before.
- **X2/A5/A6**: SQL tampering as the superuser through `c.psql`. Discover tables and columns from `information_schema` (black-box schema discovery is allowed), never from source.
- **X19**: `c.psql("UPDATE <audit table> SET ... WHERE false", user=c.server_db_role())` is **not** a valid test. Target a real row and expect `permission denied` in `err`. Run it inside `BEGIN; ...; ROLLBACK;`.
- **O7**: `c.backup("o7")` → `c.wipe_volumes()` → `c.up()` with the same `.env` → `c.restore(path)` → guard ready → compare every canary, the history of every F-block key, `audit list` counts, and `audit verify`.
- **X15**: `osv-scanner scan source -r c.repo --format json`. 0 lockfiles found → fail. Severity comes from `database_specific.severity` or CVSS ≥ 7.0.
- **X16**: `gitleaks git c.repo --report-format json --report-path c.tmp/gl.json --no-banner`. Filter out findings whose file is `.env.example`.
- **E1**: run.py runs it after teardown. Do a fresh `git clone` of the bundle into `c.tmp/e1`, then `./scripts/test.sh` with timeout 1500 s. rc 0 → pass.
