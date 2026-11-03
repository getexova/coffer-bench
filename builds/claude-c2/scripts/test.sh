#!/usr/bin/env bash
# Run Coffer's test suite: .env.example coverage (check-env-docs.sh), gofmt check,
# go vet, go test -race ./...
#
# Database: tests use COFFER_TEST_DATABASE_URL. If it is not set, a throwaway
# postgres:16 container is started on a free 127.0.0.1 port and always removed
# on exit.
#
# Toolchain: local Go >= 1.26 if present; otherwise everything runs inside
# docker.io/library/golang:1.26.10-alpine3.24 (pinned by digest) via podman or docker.
#
# Env:
#   COFFER_TEST_DATABASE_URL  use this database instead of a throwaway container
#   COFFER_E2E=1              also run the end-to-end suite (go test -tags e2e ./test/e2e/...)
#   COFFER_TEST_IN_CONTAINER=1  force the containerised toolchain
#
# Usage: ./scripts/test.sh
set -euo pipefail
# shellcheck source=scripts/lib.sh source-path=SCRIPTDIR/..
source "$(dirname "$0")/lib.sh"

GO_IMAGE="docker.io/library/golang:1.26.10-alpine3.24@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308"  # keep in sync with Dockerfile
PG_IMAGE="docker.io/library/postgres:16"
REQUIRED_GO_MINOR=26

local_go_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local v
  v="$(go env GOVERSION 2>/dev/null || true)"
  [[ "$v" =~ ^go1\.([0-9]+) ]] || return 1
  (( BASH_REMATCH[1] >= REQUIRED_GO_MINOR ))
}

# Configuration docs (SPEC 5: every variable documented in .env.example). Cheap and
# host-only, so it runs first; CI's lint job runs the same script.
"$COFFER_ROOT/scripts/check-env-docs.sh"

use_container_go=0
if [[ "${COFFER_TEST_IN_CONTAINER:-0}" == "1" ]] || ! local_go_ok; then
  use_container_go=1
fi

runtime=""
if runtime="$(detect_runtime)"; then :; else runtime=""; fi

if [[ $use_container_go -eq 1 && -z "$runtime" ]]; then
  die "need either Go >= 1.${REQUIRED_GO_MINOR} or a container runtime (podman or docker) to run the tests"
fi

# --- Throwaway Postgres ------------------------------------------------------
pg_container=""
cleanup() {
  if [[ -n "$pg_container" ]]; then
    "$runtime" rm -f "$pg_container" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -z "${COFFER_TEST_DATABASE_URL:-}" ]]; then
  [[ -n "$runtime" ]] || die "COFFER_TEST_DATABASE_URL is not set and no container runtime (podman or docker) is available to start a throwaway postgres:16"
  pg_container="coffer-test-pg-$$-${RANDOM}"
  log "starting throwaway ${PG_IMAGE} (${pg_container})"
  "$runtime" run -d --rm --name "$pg_container" \
    -e POSTGRES_USER=coffer -e POSTGRES_PASSWORD=coffer -e POSTGRES_DB=postgres \
    -p 127.0.0.1::5432 \
    "$PG_IMAGE" >/dev/null
  # Discover the host port that was assigned.
  port=""
  for _ in $(seq 1 50); do
    port="$("$runtime" port "$pg_container" 5432/tcp 2>/dev/null | head -n1 | sed -E 's/.*:([0-9]+)$/\1/' || true)"
    [[ "$port" =~ ^[0-9]+$ ]] && break
    sleep 0.2
  done
  [[ "$port" =~ ^[0-9]+$ ]] || die "could not determine the port of the test database container"
  # Wait for readiness over TCP (the init phase listens on the unix socket only).
  start=$SECONDS
  until "$runtime" exec "$pg_container" pg_isready -q -h 127.0.0.1 -U coffer -d postgres >/dev/null 2>&1; do
    if (( SECONDS - start >= 90 )); then
      "$runtime" logs "$pg_container" >&2 || true
      die "test database did not become ready within 90s"
    fi
    sleep 0.5
  done
  export COFFER_TEST_DATABASE_URL="postgres://coffer:coffer@127.0.0.1:${port}/postgres?sslmode=disable"
  log "test database ready on 127.0.0.1:${port}"
fi

if [[ "${COFFER_E2E:-0}" == "1" ]]; then
  log "COFFER_E2E=1: building ./bin/coffer for the e2e suite"
  "$COFFER_ROOT/scripts/build.sh"
fi

# --- The checks (same script for local and containerised toolchains) ---------
read -r -d '' checks <<'SCRIPT' || true
set -eu
if [ -z "$(go list ./... 2>/dev/null)" ]; then
  echo "error: no Go packages found" >&2; exit 1
fi
fmt_out="$(go list -f '{{.Dir}}' ./... | xargs gofmt -l)"
if [ -n "$fmt_out" ]; then
  echo "error: files need gofmt:" >&2; echo "$fmt_out" >&2; exit 1
fi
echo "==> gofmt ok" >&2
go vet ./...
echo "==> go vet ok" >&2
race=""
if [ "$(CGO_ENABLED=1 go env CC 2>/dev/null)" != "" ] && command -v "$(go env CC)" >/dev/null 2>&1; then
  race="-race"
else
  echo "warning: no C compiler; running tests without -race" >&2
fi
if [ -n "$race" ]; then
  CGO_ENABLED=1 go test $race -count=1 ./...
else
  go test -count=1 ./...
fi
echo "==> unit/integration tests ok" >&2
if [ "${COFFER_E2E:-0}" = "1" ]; then
  if [ -d test/e2e ]; then
    go test -tags e2e -count=1 ./test/e2e/...
    echo "==> e2e tests ok" >&2
  else
    echo "error: COFFER_E2E=1 but test/e2e does not exist" >&2; exit 1
  fi
fi
SCRIPT

if [[ $use_container_go -eq 0 ]]; then
  log "using local $(go env GOVERSION)"
  sh -c "$checks"
else
  log "no suitable local Go; running tests inside ${GO_IMAGE} with ${runtime}"
  sel=()
  [[ "$runtime" == "podman" ]] && sel=(--security-opt label=disable)
  # Host networking so 127.0.0.1:<port> reaches the throwaway database.
  # The repo is mounted read-only; build/test caches live in the container.
  # Alpine has no C compiler by default, so the race detector is installed on the fly
  # when possible (needs network); otherwise tests run without -race.
  "$runtime" run --rm "${sel[@]}" --network host \
    -v "${COFFER_ROOT}:/src:ro" -w /src \
    -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod -e GOFLAGS=-buildvcs=false \
    -e COFFER_TEST_DATABASE_URL -e COFFER_E2E \
    "$GO_IMAGE" sh -c "apk add --no-cache build-base >/dev/null 2>&1 || true; $checks"
fi

log "all tests passed"
