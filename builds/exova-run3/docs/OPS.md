# Operations and packaging

The slice that makes Coffer runnable and verifiable: the container image, the compose stack,
the seven scripts, CI, the README quickstart, and the ops half of the shared test harness.

Files: `compose.yaml`, `Dockerfile`, `.dockerignore`, `.gitignore`, `.env.example`,
`scripts/{init-env,up,down,build,test,backup,restore}.sh`, `.github/workflows/ci.yml`,
`README.md`, `internal/testutil/ops.go` (plus edits in place to `internal/testutil/harness.go`).

## Topology

Two compose services, no `version:` key.

`db` is `postgres:16` with a named volume `db_data` for the data directory and a
compose-level healthcheck running `pg_isready -h 127.0.0.1`. It is **never published** to the
host: SPEC §5 publishes only the server's port, and a database on the host loopback is a wider
surface for no benefit.

`server` builds from `./Dockerfile`, `depends_on: db: condition: service_healthy`, and
publishes exactly `127.0.0.1:${COFFER_PORT:-8420}:8420`. Inside the container it runs with
`COFFER_BIND_ADDR=0.0.0.0` and `COFFER_PORT=8420`, so the mapping alone decides the host port
and `COFFER_PORT` in `.env` stays a host-side concern.

**Healthchecks live in compose, not the Dockerfile.** podman's default OCI image format
silently drops a `HEALTHCHECK` instruction, so an image-level check would be a no-op under
`podman compose` and would make a broken stack look healthy. Compose-level checks work under
both docker and podman. Verified: `docker compose config` renders both healthchecks, and
`docker compose ps` reports `Up (healthy)` for `db` after about 6 s.

The server retries its database connection at boot, so the stack still comes up on a runtime
that ignores `depends_on`; `/readyz` answers 503 with `{"status":"not_ready","reason":"database"}`
until the database is reachable and migrations are applied, and 200 with
`{"status":"ready"}` after.

Container-to-container connectivity by service name was measured, not assumed:

```
$ podman run --rm --network ws_default postgres:16 psql -h db -U coffer -d coffer -tAc 'select current_database(), version()'
coffer|PostgreSQL 16.15 (Debian 16.15-1.pgdg13+2) on x86_64-pc-linux-gnu
```

## Image

Two stages. The build stage is `golang:1.27.3-bookworm` with `CGO_ENABLED=0`, producing a
statically linked `bin/coffer` (`ldd` reports "not a dynamic executable"). The runtime stage is
`alpine:3.22` pinned by digest
`sha256:dc92f017beea8e7f43263073d717f7bc011228c95d5312e440deb4d035bb4eec`, with
`adduser -D -u 10001 coffer`, `USER 10001:10001`, and nothing beyond busybox — no curl, no bash,
no package additions. The healthcheck uses busybox `wget` accordingly.

The build stage copies the whole tree rather than splitting `go.mod`/`go.sum` into a cached
layer: a `COPY go.sum*` glob fails the build outright when `go.sum` is absent, and a missing
lockfile must not be the difference between a working image and a broken one. `.dockerignore`
keeps the context small and keeps `.env` out of the image entirely.

`ENTRYPOINT ["/usr/local/bin/coffer"]` with `CMD ["server"]`. Configuration is environment-only,
so the binary never receives flags. Verified: the image builds, and
`podman run --rm --entrypoint /bin/sh <img> -c 'id'` reports `uid=10001(coffer)`.

## Scripts

All seven are POSIX `sh` with `set -eu`, executable (0755), and independent of anything outside
the repository. None requires `jq`. Variables are quoted throughout.

| Script | Behaviour | Exit codes |
|---|---|---|
| `init-env.sh` | Creates `.env` from `.env.example`, generating the master key (`openssl rand -base64 32`, 44 chars decoding to exactly 32 bytes), the bootstrap admin password, and both database passwords. Sets mode 0600. Prints the admin password once. | 0 ok (including "already exists"), 1 failure |
| `up.sh` | Detects the compose command, builds, starts, then polls `/readyz` once a second for 180 s. | 0 on the first 200, 1 on failure or missing `.env` |
| `down.sh` | `compose down` with no `-v`, so the volume and all data survive. | 0 ok, 1 compose failure |
| `build.sh` | Produces `./bin/coffer` for linux/amd64 and prints which path it took. | 0 ok, 1 no toolchain / build failure |
| `test.sh` | Provisions a database if needed, runs `go test ./...`, tears down what it started. | 0 pass, non-zero test failure |
| `backup.sh FILE` | `pg_dump` from inside the `db` container, gzipped, to FILE. | 2 usage, 1 failure |
| `restore.sh FILE` | Restores FILE verbatim, then restarts the stack. | 2 usage, 1 failure |

### init-env.sh

Refuses to overwrite an existing `.env` and exits 0 after saying where it is: replacing the
master key would make every stored secret undecryptable. Placeholder substitution is done in
`awk` over `.env.example`, keyed on the placeholder value, so a value is generated per key
(`POSTGRES_PASSWORD` and `COFFER_APP_DB_PASSWORD` get different passwords). Database passwords
are hex so they are safe inside a `postgres://` URL and inside an `ALTER ROLE` statement. The
resulting file is checked for any remaining `KEY=REPLACE_ME…` line before it is moved into
place, and that check matches only assignment lines, because the comments in `.env.example`
legitimately mention the placeholder by name. Verified: `.env` is mode 0600, the master key is
44 characters decoding to 32 bytes, and a second run exits 0 without touching the file.

### up.sh

Detects `docker compose`, then `podman compose`, then `podman-compose`, then `docker-compose`,
and exports the choice. It reads `COFFER_PORT` from the environment first and `.env` second,
because that is the value compose interpolates for the published port.

It never parses `compose ps --format '{{.Name}}'`: that errors under podman-compose 1.6.0
(`can't evaluate field Name in type containers.psReporter`). Plain `compose ps` is used instead.

On failure it names the dependency rather than printing a bare timeout: the last `/readyz`
status and body, `compose ps`, then `compose logs --tail 40 server` and `--tail 40 db`, and if
the body reports the database it also runs `compose exec -T db pg_isready`. Verified both
paths against a stub server: 200 gives "Coffer is ready" and exit 0; 503 with
`{"status":"not_ready","reason":"database"}` gives "failing dependency: db", the last status
and body, `pg_isready`, and both log dumps, then exit 1. A missing `.env` exits 1 naming
`./scripts/init-env.sh`.

### down.sh

`compose down` and nothing else. Data survival was measured end to end: rows present, then
`down.sh`, then `up.sh`, then the same rows read back.

### build.sh

Uses the host `go` when present —
`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/coffer ./cmd/coffer` — and
prints `build path: host Go toolchain`. Otherwise it runs the pinned `golang:1.27.3-bookworm`
with `--userns=keep-id` under podman, caches in `/tmp`, and bind-mounts the repository.
**Not** `--user $(id -u):$(id -g)`: that fails with `go.sum: permission denied` on rootless
podman. Both paths write the same `./bin/coffer`. The container invocation is written out once
per runtime rather than assembled in a helper, so no argument is ever word-split or re-quoted.
Verified host path: 18,511,181 bytes, statically linked, `./bin/coffer --help` runs.

### test.sh

If `COFFER_TEST_DATABASE_URL` is set, it is used verbatim and nothing is started. Otherwise the
script starts a throwaway `postgres:16` container published on a random loopback port, waits on
`pg_isready`, exports the URL, runs `go test ./...`, and removes the container on exit. The
compose `db` service cannot be reused for this: it is not published to the host by design, and
opening a host port on the developer's stack to run tests would be worse than a second
container.

Without a host Go toolchain the suite runs inside the pinned golang image with
`--network host` so it can reach the loopback-published test database. Verified: the script
provisions, runs, and leaves zero containers behind.

### backup.sh / restore.sh

Both resolve `POSTGRES_USER` and `POSTGRES_DB` from `.env` with `sed`, never from the caller's
shell, and both fail clearly when the stack is not running rather than writing an empty file.

`backup.sh` uses the **container's** `pg_dump` (16.15), not the host's (17.11): a 17 dump can
carry settings a 16 server rejects. It writes the dump to a temporary file and compresses it
second rather than piping `pg_dump | gzip`, because POSIX sh has no `pipefail` and the pipeline
status would be gzip's alone — a failed `pg_dump` would leave a valid gzip of nothing behind.
It then rejects an empty dump, a dump without the PostgreSQL header, and an invalid gzip before
moving the file into place.

`restore.sh` stops `server`, drops and recreates the `public` schema, loads the dump with
`psql -v ON_ERROR_STOP=1`, and restarts the stack. It restores **verbatim** and deliberately
does **not** validate the audit hash chain: a restore must be able to reproduce a tampered dump
so that verification can report the tampering, so it cannot be the step that declares a restore
good. On success it prints the exact command `./bin/coffer audit verify` and states that the
restore is not complete until that command reports the chain valid. The dump carries no GRANTs
(it is taken with `--no-owner --no-privileges`), so the server's first boot after a restore
re-applies the role grants; until that boot finishes, nothing else should connect as
`coffer_app`.

Verified round trip: seed two rows, `backup.sh` (660 bytes, PostgreSQL 16.15 header, gzip
valid), drop the table, `restore.sh`, rows read back identical. Verified failure paths: no
argument exits 2, a missing directory exits 1, a stopped stack exits 1 and writes no file.

## internal/testutil

`harness.go` was extended in place, never forked; the ops-only helpers live in `ops.go`.

Changes in `harness.go`, each one fixing a real failure seen in a test run:

- **Bootstrap the platform admin.** `authapi.Bootstrap` existed but nothing called it in the
  harness, so every `PlatformAdminToken()` login returned 401 and every test needing an
  organization failed for a reason unrelated to the code under test.
- **Derive the master key and bootstrap password from the test DSN.** `go test ./...` runs each
  package as a separate process against one shared database. Random per-process values meant
  the first package created the admin and later packages could neither log in as it nor decrypt
  what it wrote. `stableSecret(dsn, label, n)` makes one run coherent.
- **Clear the must-change-password gate through the real route.** Accounts whose initial
  password is chosen by someone else are gated (SPEC §4 P1). `ChangePassword` signs in and
  calls the real `POST /api/v1/auth/password`, exactly as `coffer passwd` does; nothing is
  bypassed.
- **Resolve project slug vs id.** HTTP paths resolve a project by slug while store-level
  helpers need the id. `NewProject` returns the id and `ProjectSlug` translates through the
  real list route, so a caller can pass either.

`ops.go` adds `TestDatabaseURL`, `ResetSchema` (the same drop-and-recreate that `restore.sh`
performs, for testing a restore path), `ProbeReady`/`WaitReady`/`DescribeReady` for `/readyz`,
and `ServerBinary` for tests that drive a built binary.

## CI

`.github/workflows/ci.yml`, all actions pinned (`actions/checkout@v4.2.2`,
`actions/setup-go@v5.1.0`), Go 1.27.3:

- **lint** — `gofmt -l .` failing on any output, then `go vet ./...`.
- **test** — a `postgres:16` service container with a `pg_isready` health check, and
  `COFFER_TEST_DATABASE_URL` pointing at it, then `go test ./...`.
- **build** — `go build ./...`, then `./scripts/build.sh`, then a check that `./bin/coffer`
  exists and is executable.
- **govulncheck** — `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`.

The workflow was parsed to confirm four jobs and the expected action pins. It has not been
executed on GitHub.

## Configuration

Every variable in `docs/CONTRACTS.md` §10 appears in `.env.example` with a one-line comment and
a safe placeholder. `COFFER_MASTER_KEY` carries the literal
`REPLACE_ME_WITH_BASE64_32_BYTES`, which the server refuses to start with. Optional variables
are present with empty values; the server treats an empty value as unset.

`.env` holds the development/review values and is gitignored. `.env.production` holds real
credentials and is gitignored. `.env.example` is committed and contains key names and
placeholders only. `.gitignore` deliberately does **not** ignore `*.sql`: the migrations are
source and would otherwise vanish from the commit.

## Known limits

- `up.sh` and `restore.sh` call `compose build` and therefore require the tree to compile; a
  build failure is reported as such, with the compiler output.
- The audit-chain and performance targets in SPEC §5 are not exercised by this slice.
- Restoring into a stack whose `COFFER_MASTER_KEY` differs from the one that produced the dump
  succeeds at the SQL level and yields undecryptable values; nothing can detect that before a
  read fails.
