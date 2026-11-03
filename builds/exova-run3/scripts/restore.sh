#!/bin/sh
# Restore the Coffer database from a file produced by ./scripts/backup.sh.
#
# This restores the dump VERBATIM. It deliberately does NOT validate the audit hash chain:
# a restore has to be able to reproduce a tampered dump so that verification can report the
# tampering. A restore therefore cannot be the thing that declares a restore good. On
# success this script prints the one command that can, and says so.
#
# Steps: stop the server, drop and recreate the public schema, load the dump with
# ON_ERROR_STOP=1, then start the stack again.
#
# Note: the dump carries no GRANTs (it is taken with --no-owner --no-privileges), so the
# server's first boot after a restore re-applies the role grants. Until that boot finishes,
# nothing else should connect as the coffer_app role.
set -eu

usage() {
  printf 'usage: %s FILE\n' "$0" >&2
  printf '  Restores the Coffer database from a file written by ./scripts/backup.sh.\n' >&2
}

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  usage
  exit 2
fi

case $1 in
  -h|--help)
    usage
    exit 0
    ;;
esac

source_file=$1

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

env_file=".env"

if [ ! -f "$env_file" ]; then
  printf 'error: %s is missing. Run ./scripts/init-env.sh first.\n' "$env_file" >&2
  exit 1
fi

case $source_file in
  /*) source_path=$source_file ;;
  *) source_path="$repo_root/$source_file" ;;
esac

if [ ! -e "$source_path" ]; then
  printf 'error: %s does not exist; nothing to restore.\n' "$source_path" >&2
  exit 1
fi
if [ ! -f "$source_path" ]; then
  printf 'error: %s is not a regular file.\n' "$source_path" >&2
  exit 1
fi
if [ ! -r "$source_path" ]; then
  printf 'error: %s is not readable.\n' "$source_path" >&2
  exit 1
fi
if [ ! -s "$source_path" ]; then
  printf 'error: %s is empty; refusing to restore an empty dump.\n' "$source_path" >&2
  exit 1
fi
if ! gzip -t "$source_path" 2>/dev/null; then
  printf 'error: %s is not a valid gzip file. Use a file written by ./scripts/backup.sh.\n' "$source_path" >&2
  exit 1
fi

env_get() {
  sed -n "s/^$1=//p" "$env_file" | tail -n 1
}

postgres_user=$(env_get POSTGRES_USER)
postgres_db=$(env_get POSTGRES_DB)
if [ -z "$postgres_user" ] || [ -z "$postgres_db" ]; then
  printf 'error: POSTGRES_USER and POSTGRES_DB must both be set in %s\n' "$env_file" >&2
  exit 1
fi

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

if ! $COMPOSE exec -T db pg_isready -h 127.0.0.1 -U "$postgres_user" -d "$postgres_db" >/dev/null 2>&1; then
  printf 'error: the Coffer database is not reachable, so it cannot be restored into.\n' >&2
  printf 'Start the stack with ./scripts/up.sh and try again.\n' >&2
  exit 1
fi

printf 'Restoring %s into database %s. This replaces all current data.\n' "$source_path" "$postgres_db"

# Stop the server so no connection is holding locks or writing while the schema is
# replaced. A stack that was never started has no server to stop, which is fine.
printf 'Stopping server...\n'
$COMPOSE stop server >/dev/null 2>&1 || true

# Drop and recreate the schema. DROP ... CASCADE takes the tables, the triggers, the
# audit head rows and schema_migrations with it; the dump then recreates all of it.
printf 'Recreating the public schema...\n'
if ! $COMPOSE exec -T db psql \
      -U "$postgres_user" \
      -d "$postgres_db" \
      -v ON_ERROR_STOP=1 \
      -c 'DROP SCHEMA IF EXISTS public CASCADE;' \
      -c 'CREATE SCHEMA public;'; then
  printf 'error: could not recreate the public schema; the database is now empty.\n' >&2
  printf 'Fix the problem and re-run this script with the same FILE.\n' >&2
  exit 1
fi

# Load verbatim: no filtering, no rewriting, ON_ERROR_STOP so a partial restore fails
# loudly instead of leaving half the data in place.
printf 'Loading the dump...\n'
if ! gunzip -c "$source_path" | $COMPOSE exec -T db psql \
      -U "$postgres_user" \
      -d "$postgres_db" \
      -v ON_ERROR_STOP=1 \
      -q -o /dev/null; then
  printf 'error: loading the dump failed. The database is in a partial state.\n' >&2
  printf 'Re-run this script with the same FILE once the cause is fixed.\n' >&2
  exit 1
fi

# Start the stack again. The server re-applies the role grants at boot and only reports
# ready once the database is reachable and migrations are applied.
printf 'Starting the stack...\n'
if ! $COMPOSE up -d; then
  printf 'error: the stack did not restart after the restore.\n' >&2
  printf 'Run ./scripts/up.sh to see why.\n' >&2
  exit 1
fi

printf '\nRestore finished. The data was loaded exactly as it was in the dump.\n'
printf 'The audit hash chain was NOT checked: a restore must be able to reproduce a\n'
printf 'tampered dump so that verification can report it.\n\n'
printf 'The restore is not complete until this command reports the chain valid:\n\n'
printf '    ./bin/coffer audit verify\n\n'
printf 'If it reports an invalid chain, the dump itself was altered. Do not trust the\n'
printf 'restored data; restore a known-good backup instead.\n'
