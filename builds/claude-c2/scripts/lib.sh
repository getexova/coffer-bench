# shellcheck shell=bash
# Shared helpers for Coffer's ops scripts. Source it; do not execute it.
#
#   source "$(dirname "$0")/lib.sh"
#
# After sourcing, the current directory is the repository root.

set -euo pipefail

COFFER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export COFFER_ROOT
cd "$COFFER_ROOT"

log()  { printf '==> %s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Compose detection. Sets the array COMPOSE (e.g. (docker compose)).
#   COFFER_COMPOSE overrides, e.g. COFFER_COMPOSE="podman-compose".
# Order: docker compose (v2) -> podman compose -> docker-compose -> podman-compose.
# ---------------------------------------------------------------------------
COMPOSE=()
detect_compose() {
  if [[ ${#COMPOSE[@]} -gt 0 ]]; then return 0; fi
  if [[ -n "${COFFER_COMPOSE:-}" ]]; then
    read -r -a COMPOSE <<<"$COFFER_COMPOSE"
    return 0
  fi
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    COMPOSE=(podman compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  elif command -v podman-compose >/dev/null 2>&1; then
    COMPOSE=(podman-compose)
  else
    die "no compose implementation found: install Docker with the compose v2 plugin, or podman >= 4 with podman-compose (or set COFFER_COMPOSE)"
  fi
}

compose() {
  detect_compose
  # podman compose: suppress the "Executing external compose provider" banner.
  export PODMAN_COMPOSE_WARNING_LOGS="${PODMAN_COMPOSE_WARNING_LOGS:-false}"
  "${COMPOSE[@]}" "$@"
}

# compose_start_server: (re)create the server container from the current .env.
# Always --force-recreate: podman-compose (also behind `docker compose` /
# `podman compose` on podman hosts) hashes only compose.yaml, not the contents
# of env_file, so without it an edited .env (new master key, PAT TTL, ...) would
# silently never reach a running server. --no-deps leaves the db container alone
# (the caller has started it); the server retries the DB connection itself.
compose_start_server() {
  compose up -d --build --force-recreate --no-deps server
}

# compose_up_stack: start db (kept as is unless its own config changed), wait for
# it, then recreate the server with the current .env.
compose_up_stack() {
  compose up -d db
  wait_db_ready 120
  compose_start_server
}

# ---------------------------------------------------------------------------
# Container runtime detection (for one-off containers in build.sh / test.sh).
# COFFER_CONTAINER_RUNTIME overrides. Prefers podman, then docker.
# ---------------------------------------------------------------------------
detect_runtime() {
  if [[ -n "${COFFER_CONTAINER_RUNTIME:-}" ]]; then
    printf '%s\n' "$COFFER_CONTAINER_RUNTIME"
  elif command -v podman >/dev/null 2>&1; then
    printf 'podman\n'
  elif command -v docker >/dev/null 2>&1; then
    printf 'docker\n'
  else
    return 1
  fi
}

# ---------------------------------------------------------------------------
# .env helpers. .env is never sourced (it is data, not code): values are read
# with grep so that a hostile or malformed .env cannot execute commands.
# ---------------------------------------------------------------------------
require_env_file() {
  if [[ ! -f .env ]]; then
    die ".env not found in $COFFER_ROOT. Create it first with: ./scripts/init-env.sh"
  fi
}

# env_get NAME [DEFAULT] -> prints the value of NAME from .env (last occurrence wins).
env_get() {
  local name="$1" default="${2:-}" line
  line="$(grep -E "^${name}=" .env 2>/dev/null | tail -n 1 || true)"
  if [[ -z "$line" ]]; then
    printf '%s\n' "$default"
    return 0
  fi
  line="${line#*=}"
  line="${line%$'\r'}"
  # Strip one pair of surrounding quotes, if present.
  if [[ "$line" =~ ^\"(.*)\"$ ]] || [[ "$line" =~ ^\'(.*)\'$ ]]; then
    line="${BASH_REMATCH[1]}"
  fi
  if [[ -z "$line" ]]; then line="$default"; fi
  printf '%s\n' "$line"
}

coffer_port() {
  local port
  port="${COFFER_PORT:-$(env_get COFFER_PORT 8420)}"
  [[ "$port" =~ ^[0-9]+$ ]] || die "COFFER_PORT must be a number (got '$port')"
  printf '%s\n' "$port"
}

# ---------------------------------------------------------------------------
# Readiness
# ---------------------------------------------------------------------------

# wait_db_ready [TIMEOUT_SECONDS]: wait until pg_isready succeeds inside the db container.
wait_db_ready() {
  local timeout="${1:-120}" start
  start=$SECONDS
  # shellcheck disable=SC2016 # expanded inside the container
  until compose exec -T db sh -c 'pg_isready -q -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1; do
    if (( SECONDS - start >= timeout )); then
      compose logs --tail 50 db >&2 || true
      die "database did not become ready within ${timeout}s"
    fi
    sleep 1
  done
}

# wait_server_ready [TIMEOUT_SECONDS]: poll /readyz until it returns 200.
wait_server_ready() {
  local timeout="${1:-180}" port url start code
  command -v curl >/dev/null 2>&1 || die "curl is required (install curl)"
  port="$(coffer_port)"
  url="http://127.0.0.1:${port}/readyz"
  start=$SECONDS
  log "waiting for $url (timeout ${timeout}s)"
  while true; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null || true)"
    if [[ "$code" == "200" ]]; then
      log "Coffer is ready at http://127.0.0.1:${port}"
      return 0
    fi
    if (( SECONDS - start >= timeout )); then
      printf 'error: %s did not return 200 within %ss (last status: %s). Last server logs:\n' \
        "$url" "$timeout" "${code:-none}" >&2
      compose logs --tail 80 server >&2 || true
      exit 1
    fi
    sleep 1
  done
}
