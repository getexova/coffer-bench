#!/bin/sh
# Stop the Coffer stack and keep the data.
#
# Deliberately no `-v`: the db_data named volume holds every secret version and every
# audit event, and `down -v` would delete it. Data survives down.sh followed by up.sh.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

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

# ./scripts/up.sh refuses to start without .env, so a missing .env means no stack of ours
# was ever started and there is nothing to stop. Say so and exit 0 rather than letting
# compose fail on the missing env_file.
if [ ! -f .env ]; then
  printf 'No .env in %s, so no stack started by ./scripts/up.sh is running. Nothing to stop.\n' "$repo_root"
  exit 0
fi

printf 'Stopping the Coffer stack with: %s down\n' "$COMPOSE"

if ! $COMPOSE down; then
  printf 'error: "%s down" failed.\n' "$COMPOSE" >&2
  exit 1
fi

printf 'Stack stopped. The db_data volume was kept, so ./scripts/up.sh brings back\n'
printf 'every secret, version and audit event.\n'
