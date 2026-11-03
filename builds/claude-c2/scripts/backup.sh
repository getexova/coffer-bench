#!/usr/bin/env bash
# Back up the Coffer database to FILE (pg_dump custom format, mode 0600).
#
# The dump contains only ciphertext: secret values are encrypted under per-project
# data keys, which are wrapped by COFFER_MASTER_KEY. The master key is NOT in the
# backup; store it separately -- without it the backup cannot be decrypted.
#
# Works while the stack is running (pg_dump takes a consistent snapshot); if the
# db service is not running it is started.
#
# Usage: ./scripts/backup.sh FILE
set -euo pipefail
orig_pwd="$PWD"
# shellcheck source=scripts/lib.sh source-path=SCRIPTDIR/..
source "$(dirname "$0")/lib.sh"

if [[ $# -ne 1 || -z "$1" || "$1" == -* ]]; then
  printf 'usage: %s FILE\n' "$0" >&2
  exit 2
fi
file="$1"
[[ "$file" == /* ]] || file="${orig_pwd}/${file}"
dir="$(dirname "$file")"
[[ -d "$dir" ]] || die "directory does not exist: $dir"

require_env_file
compose up -d db >/dev/null
wait_db_ready 120

umask 077
tmp="$(mktemp "${dir}/.coffer-backup.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

log "dumping database"
# Credentials are taken from the db container's own environment.
# shellcheck disable=SC2016 # expanded inside the container
compose exec -T db sh -c 'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-password' >"$tmp"

# Sanity check: custom-format dumps start with "PGDMP".
if [[ "$(head -c 5 "$tmp")" != "PGDMP" ]]; then
  die "pg_dump did not produce a valid custom-format dump"
fi

chmod 600 "$tmp"
mv -f "$tmp" "$file"
trap - EXIT
chmod 600 "$file"
log "backup written to $file ($(wc -c <"$file" | tr -d ' ') bytes, mode 0600)"
log "remember: restoring requires the same COFFER_MASTER_KEY"
