# Measured facts about this host and these images

Recorded from commands run on the build host before the shell became unavailable. Every line has
the command that produced it. Re-run these before relying on them again.

## Image pins

| Image | Evidence | Command |
|---|---|---|
| `golang:1.27.3-bookworm` | exists; used successfully for six `go build` runs | `podman manifest inspect docker.io/library/golang:1.27.3-bookworm` |
| `alpine:3.22` | index digest `sha256:dc92f017beea8e7f43263073d717f7bc011228c95d5312e440deb4d035bb4eec`; `FROM …@sha256:dc92f0…` built and ran | `podman manifest inspect docker.io/library/alpine:3.22` |
| `postgres:16` | present, server version `PostgreSQL 16.15 (Debian 16.15-1.pgdg13+2)` | `podman manifest inspect docker.io/library/postgres:16`; `SELECT version()` |

`go1.27.3` is the current stable toolchain, confirmed against `https://go.dev/VERSION?m=text`, and
the image builds code written with `go 1.27` in `go.mod`. Any note that the latest toolchain is
1.25.x is out of date.

## Toolchain and runtime behaviour

- `podman 5.8.9`, `podman-compose 1.6.0`, rootless (`podman info --format '{{.Host.Security.Rootless}}'`
  → `true`). `/usr/bin/docker` is a two-line shim that execs podman, so `docker compose` runs
  podman-compose.
- **`HEALTHCHECK` in a Dockerfile is silently dropped under podman's default OCI image format**
  (`HEALTHCHECK is not supported for OCI image format and will be ignored`). It works with
  `podman build --format docker`. Therefore all healthchecks live in `compose.yaml`, which works
  under both runtimes.
- `depends_on: condition: service_healthy` is honoured by podman-compose 1.6.0; both services
  reached `(healthy)`.
- **`docker compose ps --format '{{.Name}}'` errors** under podman-compose 1.6.0
  (`can't evaluate field Name in type containers.psReporter`). Plain `compose ps` works. Scripts
  must not use `--format`.
- `compose exec -T` carries binary bytes through the shim; `pg_dump | gzip` round-tripped and
  restored into a fresh volume with exit 0.
- A published port written as `127.0.0.1:${COFFER_PORT}:8420` binds loopback only
  (`ss -ltn` showed `127.0.0.1:18422`).
- Data survives `compose down` followed by `compose up` without `-v`.
- **Rootless podman build as a bind-mounted user:** `podman run --user $(id -u):$(id -g)` fails with
  `go.sum: permission denied`. `--userns=keep-id` works and produces the binary owned by the host
  user. `build.sh` must use `--userns=keep-id`.
- `CGO_ENABLED=0` yields a statically linked binary (`ldd` → `not a dynamic executable`), 5.2 MB.
- `openssl rand -base64 32` produces 44 characters that decode to exactly 32 bytes. No `jq` needed.
- The container's `pg_dump` is 16.15; the host client is 17.11. Backups must use the container's
  `pg_dump`, not the host's.

## Dependency audit

`govulncheck` over the real module closure (`pgx v5.11.0`, `x/crypto v0.58.0`): **0 vulnerabilities
in code we call**, 0 in imported packages, 1 in a required module that is not called
(GO-2026-5932, `x/crypto/openpgp`, unmaintained, not imported). Go 1.27.3 stdlib: 0 advisories.
`pgx` CVEs GO-2026-4771 and GO-2026-4772 are fixed at 5.9.0, GO-2026-5004 at 5.9.2; the pin is
above all three.

## Container-to-container networking: works

A compose-managed container reaches `db` by service name on this host:

```
[probe] | CONTAINER_TO_CONTAINER=OK
```

The probe ran `psql -h db -U coffer -d coffer -tAc "select 1"` from a service on the default compose
network, gated on `condition: service_healthy`.

`/proc/sys/net/ipv4/ip_forward` is `0` and firewalld is `inactive`, and same-bridge traffic still
works because forwarding only matters for traffic leaving the bridge. An earlier probe that used
`--network host` against a bridge IP timed out, which is why the first result looked like a compose
failure. It was the probe. The committed topology needs no workaround.

## Open, unmeasured

- Audit append throughput and both §5 p95 targets are unmeasured.
