#!/bin/sh
# Back up the Coffer database to FILE (gzip-compressed SQL).
#
# The dump is produced by the pg_dump that ships inside the postgres:16 container (16.15).
# The host client may be newer (17.x on this host), and a 17 dump can carry settings that a
# 16 server rejects on restore.
#
# The file contains only ciphertext for secret values: values are encrypted at rest with
# envelope encryption, and the master key is never in the database or the dump.
set -eu

usage() {
  printf 'usage: %s FILE\n' "$0" >&2
  printf '  Writes a gzip-compressed pg_dump of the Coffer database to FILE.\n' >&2
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

target=$1

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

env_file=".env"

if [ ! -f "$env_file" ]; then
  printf 'error: %s is missing. Run ./scripts/init-env.sh first.\n' "$env_file" >&2
  exit 1
fi

# Resolve the target to an absolute path before changing nothing else, so the error
# messages point somewhere useful.
case $target in
  /*) target_path=$target ;;
  *) target_path="$repo_root/$target" ;;
esac

target_dir=$(dirname -- "$target_path")
if [ ! -d "$target_dir" ]; then
  printf 'error: directory %s does not exist; cannot write %s\n' "$target_dir" "$target_path" >&2
  exit 1
fi
if [ ! -w "$target_dir" ]; then
  printf 'error: directory %s is not writable; cannot write %s\n' "$target_dir" "$target_path" >&2
  exit 1
fi
if [ -d "$target_path" ]; then
  printf 'error: %s is a directory; FILE must be a file path\n' "$target_path" >&2
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

# Fail clearly when the stack is not running, rather than writing an empty gzip file.
if ! $COMPOSE exec -T db pg_isready -h 127.0.0.1 -U "$postgres_user" -d "$postgres_db" >/dev/null 2>&1; then
  printf 'error: the Coffer database is not reachable, so there is nothing to back up.\n' >&2
  printf 'Start the stack with ./scripts/up.sh and try again.\n' >&2
  exit 1
fi

tmp_path="$target_path.tmp.$$"
tmp_raw="$target_path.raw.$$"
trap 'rm -f "$tmp_path" "$tmp_raw"' EXIT INT TERM

printf 'Backing up database %s to %s\n' "$postgres_db" "$target_path"

# The container's pg_dump over the container's unix socket, as the owner role. --no-owner
# and --no-privileges keep the dump restorable into a stack whose role names differ.
#
# The dump is written to a temporary file first and compressed second, rather than piped
# straight into gzip. POSIX sh has no pipefail, so in `pg_dump | gzip` the exit status
# would be gzip's alone: a failed pg_dump would still leave a perfectly valid gzip of
# nothing behind, and an empty backup is worse than no backup at all.
if ! $COMPOSE exec -T db pg_dump \
      -U "$postgres_user" \
      -d "$postgres_db" \
      --no-owner \
      --no-privileges > "$tmp_raw"; then
  printf 'error: pg_dump failed; %s was not written.\n' "$target_path" >&2
  exit 1
fi

if [ ! -s "$tmp_raw" ]; then
  printf 'error: pg_dump produced no output; %s was not written.\n' "$target_path" >&2
  exit 1
fi

# A pg_dump that succeeded always emits the header; without it the file is not a dump.
if ! grep -q 'PostgreSQL database dump' "$tmp_raw"; then
  printf 'error: the dump does not look like a PostgreSQL dump; %s was not written.\n' "$target_path" >&2
  printf 'First bytes received:\n' >&2
  head -c 200 "$tmp_raw" >&2 || true
  printf '\n' >&2
  exit 1
fi

if ! gzip -c "$tmp_raw" > "$tmp_path"; then
  printf 'error: could not compress the dump; %s was not written.\n' "$target_path" >&2
  exit 1
fi

if ! gzip -t "$tmp_path" 2>/dev/null; then
  printf 'error: the gzip stream is invalid; %s was not written.\n' "$target_path" >&2
  exit 1
fi

rm -f "$tmp_raw"

mv -f "$tmp_path" "$target_path"

size=$(wc -c < "$target_path" | tr -d ' ')
printf 'Wrote %s (%s bytes).\n' "$target_path" "$size"
printf 'The file holds only ciphertext: restoring it needs the same COFFER_MASTER_KEY.\n'
