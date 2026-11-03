#!/bin/sh
# Run the Go test suite. Exit 0 means the tests passed.
#
# Database:
#   * COFFER_TEST_DATABASE_URL set  -> use it as-is and start nothing.
#   * otherwise                     -> start a throwaway postgres:16 container published on
#                                      a random loopback port, run the tests against it, and
#                                      remove it on the way out.
#
# The compose `db` service is deliberately not published to the host (SPEC §5: the stack
# publishes only the server port), so the tests cannot reach it without a host port. A
# dedicated container uses the same pinned image and leaves the developer's stack alone.
#
# Toolchain: the host `go` when present, otherwise the pinned golang image bind-mounted the
# same way build.sh does it (--userns=keep-id under podman).
set -eu

go_image="golang:1.27.3-bookworm"
postgres_image="postgres:16"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

if [ ! -f go.mod ]; then
  printf 'error: go.mod not found in %s\n' "$repo_root" >&2
  exit 1
fi

detect_runtime() {
  if command -v podman >/dev/null 2>&1; then
    printf 'podman'
  elif command -v docker >/dev/null 2>&1; then
    printf 'docker'
  fi
}

random_hex() {
  # 16 random bytes as hex; no openssl dependency.
  od -An -tx1 -N16 /dev/urandom | tr -d ' \n'
}

test_db_url=${COFFER_TEST_DATABASE_URL:-}
db_container=""
db_runtime=""
started_db=0

cleanup() {
  if [ "$started_db" = "1" ] && [ -n "$db_container" ] && [ -n "$db_runtime" ]; then
    "$db_runtime" rm -f "$db_container" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

if [ -z "$test_db_url" ]; then
  db_runtime=$(detect_runtime)
  if [ -z "$db_runtime" ]; then
    printf 'error: no container runtime (podman or docker) found and COFFER_TEST_DATABASE_URL is not set.\n' >&2
    printf 'Set COFFER_TEST_DATABASE_URL to a PostgreSQL 16 URL, or install podman/docker.\n' >&2
    exit 1
  fi

  db_user="coffer_test"
  db_name="coffer_test"
  db_password=$(random_hex)
  db_container="coffer-test-db-$$"

  printf 'Starting a throwaway %s container (%s) for the tests via %s\n' \
    "$postgres_image" "$db_container" "$db_runtime"

  if ! "$db_runtime" run -d --rm \
      --name "$db_container" \
      -e POSTGRES_USER="$db_user" \
      -e POSTGRES_PASSWORD="$db_password" \
      -e POSTGRES_DB="$db_name" \
      -p 127.0.0.1::5432 \
      "$postgres_image" >/dev/null; then
    printf 'error: could not start the test database container.\n' >&2
    exit 1
  fi
  started_db=1

  waited=0
  while ! "$db_runtime" exec "$db_container" pg_isready -h 127.0.0.1 -U "$db_user" -d "$db_name" >/dev/null 2>&1; do
    waited=$((waited + 1))
    if [ "$waited" -ge 60 ]; then
      printf 'error: the test database did not become ready within 60 s.\n' >&2
      "$db_runtime" logs --tail 40 "$db_container" >&2 || true
      exit 1
    fi
    sleep 1
  done

  published=$("$db_runtime" port "$db_container" 5432 | tail -n 1)
  db_port=${published##*:}
  case $db_port in
    ''|*[!0-9]*)
      printf 'error: could not determine the published port of the test database (got: %s)\n' "$published" >&2
      exit 1
      ;;
  esac

  test_db_url="postgres://$db_user:$db_password@127.0.0.1:$db_port/$db_name?sslmode=disable"
  printf 'Test database ready on 127.0.0.1:%s\n' "$db_port"
else
  printf 'Using COFFER_TEST_DATABASE_URL from the environment.\n'
fi

export COFFER_TEST_DATABASE_URL="$test_db_url"

if command -v go >/dev/null 2>&1; then
  printf 'Running go test -p 1 ./... with the host Go toolchain (%s)\n' "$(go version 2>/dev/null || printf 'go')"
  go test -p 1 ./...
else
  test_runtime=${db_runtime:-$(detect_runtime)}
  if [ -z "$test_runtime" ]; then
    printf 'error: no Go toolchain and no container runtime found.\n' >&2
    exit 1
  fi
  printf 'Running go test -p 1 ./... inside %s via %s (no host Go toolchain found)\n' "$go_image" "$test_runtime"

  # --network host lets the test container reach the loopback-published test database.
  # COFFER_TEST_DATABASE_URL is passed by name so the URL never appears in argv.
  if [ "$test_runtime" = "podman" ]; then
    "$test_runtime" run --rm \
      --network host \
      --userns=keep-id \
      -v "$repo_root:/src:Z" \
      -w /src \
      -e CGO_ENABLED=0 \
      -e GOTOOLCHAIN=local \
      -e HOME=/tmp \
      -e GOPATH=/tmp/go \
      -e GOCACHE=/tmp/go-cache \
      -e GOMODCACHE=/tmp/go-mod-cache \
      -e COFFER_TEST_DATABASE_URL \
      "$go_image" \
      go test -p 1 ./...
  else
    "$test_runtime" run --rm \
      --network host \
      --user "$(id -u):$(id -g)" \
      -v "$repo_root:/src" \
      -w /src \
      -e CGO_ENABLED=0 \
      -e GOTOOLCHAIN=local \
      -e HOME=/tmp \
      -e GOPATH=/tmp/go \
      -e GOCACHE=/tmp/go-cache \
      -e GOMODCACHE=/tmp/go-mod-cache \
      -e COFFER_TEST_DATABASE_URL \
      "$go_image" \
      go test -p 1 ./...
  fi
fi

printf 'Tests passed.\n'
