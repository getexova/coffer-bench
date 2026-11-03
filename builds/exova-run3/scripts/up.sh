#!/bin/sh
# Start the Coffer stack and return 0 as soon as GET /readyz answers 200.
#
# Polls http://127.0.0.1:${COFFER_PORT:-8420}/readyz once a second for 180 seconds.
# On failure it names the dependency that is not ready and dumps the evidence, instead
# of printing a bare timeout.
set -eu

ready_timeout=180

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

env_file=".env"

if [ ! -f "$env_file" ]; then
  printf 'error: %s is missing. Run ./scripts/init-env.sh first.\n' "$env_file" >&2
  exit 1
fi

# Prefer `docker compose`, then `podman compose`, then the standalone podman-compose
# script. On hosts where /usr/bin/docker is a shim around podman, the first branch runs
# podman-compose and is correct.
detect_compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    printf 'docker compose'
  elif command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    printf 'podman compose'
  elif command -v podman-compose >/dev/null 2>&1; then
    printf 'podman-compose'
  elif command -v docker-compose >/dev/null 2>&1; then
    printf 'docker-compose'
  fi
}

COMPOSE=$(detect_compose)
if [ -z "$COMPOSE" ]; then
  printf 'error: no compose command found. Install docker compose or podman-compose.\n' >&2
  exit 1
fi
export COMPOSE

# The port lives in .env because that is what compose interpolates. An exported
# COFFER_PORT wins, then .env, then the default.
port=${COFFER_PORT:-}
if [ -z "$port" ]; then
  port=$(sed -n 's/^COFFER_PORT=//p' "$env_file" | tail -n 1)
fi
if [ -z "$port" ]; then
  port=8420
fi
case $port in
  *[!0-9]*)
    printf 'error: COFFER_PORT must be a number, got: %s\n' "$port" >&2
    exit 1
    ;;
esac

ready_url="http://127.0.0.1:$port/readyz"

tmp_dir=$(mktemp -d 2>/dev/null || printf '%s' "${TMPDIR:-/tmp}/coffer-up.$$")
mkdir -p "$tmp_dir"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

# Sets PROBE_CODE and PROBE_BODY. curl gives a real status code for a 503; wget only
# distinguishes success from failure, so the body may be empty on that path.
probe_ready() {
  PROBE_CODE=000
  PROBE_BODY=""
  if command -v curl >/dev/null 2>&1; then
    curl -sS --max-time 5 -o "$tmp_dir/body" -w '%{http_code}' "$ready_url" > "$tmp_dir/code" 2>/dev/null || true
    PROBE_CODE=$(cat "$tmp_dir/code" 2>/dev/null || true)
    PROBE_BODY=$(cat "$tmp_dir/body" 2>/dev/null || true)
  elif command -v wget >/dev/null 2>&1; then
    if wget -q -O "$tmp_dir/body" --timeout=5 "$ready_url" >/dev/null 2>&1; then
      PROBE_CODE=200
    else
      PROBE_CODE=000
    fi
    PROBE_BODY=$(cat "$tmp_dir/body" 2>/dev/null || true)
  else
    printf 'error: neither curl nor wget is available to probe %s\n' "$ready_url" >&2
    exit 1
  fi
  if [ -z "$PROBE_CODE" ]; then
    PROBE_CODE=000
  fi
  return 0
}

show_logs() {
  service=$1
  printf '\n--- %s logs --tail 40 %s ---\n' "$COMPOSE" "$service" >&2
  if $COMPOSE logs --tail 40 "$service" > "$tmp_dir/logs" 2>&1; then
    tail -n 40 "$tmp_dir/logs" >&2 || true
  elif $COMPOSE logs "$service" > "$tmp_dir/logs" 2>&1; then
    # Older podman-compose builds have no --tail; plain logs still tell the story.
    tail -n 40 "$tmp_dir/logs" >&2 || true
  else
    printf '(could not read logs for service %s)\n' "$service" >&2
  fi
}

printf 'Starting the Coffer stack with: %s\n' "$COMPOSE"

if ! $COMPOSE build; then
  printf '\nerror: "%s build" failed; the server image could not be built.\n' "$COMPOSE" >&2
  show_logs server
  exit 1
fi

if ! $COMPOSE up -d; then
  printf '\nerror: "%s up -d" failed; the stack did not start.\n' "$COMPOSE" >&2
  show_logs db
  show_logs server
  exit 1
fi

printf 'Waiting up to %s s for %s\n' "$ready_timeout" "$ready_url"

attempt=0
last_code=000
last_body=""
while [ "$attempt" -lt "$ready_timeout" ]; do
  attempt=$((attempt + 1))
  probe_ready
  last_code=$PROBE_CODE
  last_body=$PROBE_BODY
  if [ "$last_code" = "200" ]; then
    printf '\nCoffer is ready (after %s s).\n' "$attempt"
    printf 'API: http://127.0.0.1:%s/api/v1\n' "$port"
    printf 'Health: %s\n' "$ready_url"
    exit 0
  fi
  sleep 1
done

# Failed. Work out which dependency is at fault before printing anything else.
failing="unknown"
if [ "$last_code" = "000" ]; then
  failing="server (no HTTP response on $ready_url)"
elif printf '%s' "$last_body" | grep -q 'database'; then
  failing="db (the server is up but /readyz reports the database is unreachable)"
elif printf '%s' "$last_body" | grep -q 'migrations'; then
  failing="migrations (the server is up but /readyz reports migrations are not applied)"
fi

printf '\nerror: the stack was not ready within %s s.\n' "$ready_timeout" >&2
printf '  failing dependency: %s\n' "$failing" >&2
printf '  url:                %s\n' "$ready_url" >&2
printf '  last status:        %s\n' "$last_code" >&2
printf '  last body:          %s\n' "$last_body" >&2

printf '\n--- %s ps ---\n' "$COMPOSE" >&2
$COMPOSE ps >&2 || true

if [ "$last_code" = "503" ] && printf '%s' "$last_body" | grep -q 'database'; then
  printf '\n--- %s exec -T db pg_isready ---\n' "$COMPOSE" >&2
  $COMPOSE exec -T db pg_isready -h 127.0.0.1 >&2 || true
fi

show_logs server
show_logs db

printf '\nThe stack is still up so you can inspect it: "%s ps", "%s logs server".\n' "$COMPOSE" "$COMPOSE" >&2
printf 'Tear it down with ./scripts/down.sh.\n' >&2
exit 1
