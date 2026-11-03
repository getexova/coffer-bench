#!/usr/bin/env bash
# Restore the Coffer database from FILE (created by ./scripts/backup.sh).
#
# DESTRUCTIVE on success: the current database is replaced by the contents of FILE.
# All or nothing: the current database is kept until FILE has been restored
# completely AND the server has become ready on it. Steps:
#   1. FILE is restored into a scratch database (coffer_restore_incoming) with
#      pg_restore --single-transaction --exit-on-error, while the server keeps
#      running on the current database. A truncated, corrupt or unreadable FILE
#      fails here and nothing else is touched.
#   2. The server is stopped and, in one transaction, the current database is
#      renamed to coffer_restore_previous and the scratch database to POSTGRES_DB.
#   3. The server is started. Once /readyz is 200 the previous database is dropped.
#      If the server does not become ready (for example COFFER_MASTER_KEY does not
#      match the backup: "master key does not match database"), the swap is undone,
#      the server is started on the previous database again, and the script fails.
# The server is restarted on every exit path once it has been stopped. Needs free
# disk space for a second copy of the database while it runs.
#
# The .env must hold the SAME COFFER_MASTER_KEY as the stack that produced the
# backup, otherwise the server refuses to start and the restore is rolled back. To
# restore onto a fresh machine:
#   ./scripts/init-env.sh, then copy COFFER_MASTER_KEY (or the whole .env) from the
#   original stack into .env, then ./scripts/restore.sh FILE.
#
# Usage: ./scripts/restore.sh FILE
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
[[ -f "$file" && -r "$file" ]] || die "cannot read backup file: $file"
[[ "$(head -c 5 "$file")" == "PGDMP" ]] || die "$file is not a pg_dump custom-format file (made by ./scripts/backup.sh)"

require_env_file
if grep -q '^COFFER_MASTER_KEY=REPLACE_ME' .env; then
  die ".env still contains the placeholder master key; put the master key of the backed-up stack in .env"
fi

# Fixed names (not derived from POSTGRES_DB, which may already be 63 bytes long).
incoming_db="coffer_restore_incoming"
previous_db="coffer_restore_previous"
rejected_db="coffer_restore_rejected"
ready_timeout="${COFFER_READY_TIMEOUT:-180}"

# db_psql [psql args...]: psql as the database owner, connected to template1 (never
# a database that is being dropped or renamed). SQL comes on stdin, so psql's
# :'var' / :"var" quoting applies. -v db=POSTGRES_DB and owner=POSTGRES_USER are set.
db_psql() {
  # shellcheck disable=SC2016 # expanded inside the container
  compose exec -T db sh -c 'exec psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d template1 -v db="$POSTGRES_DB" -v owner="$POSTGRES_USER" "$@"' sh "$@"
}
db_exists() { # db_exists NAME
  local n
  n="$(db_psql -tA -v name="$1" <<<"SELECT count(*) FROM pg_database WHERE datname = :'name';")"
  [[ "${n//[[:space:]]/}" == "1" ]]
}
drop_db() { # drop_db NAME
  db_psql -v name="$1" >/dev/null <<<'DROP DATABASE IF EXISTS :"name" WITH (FORCE);'
}
# rename_pair FROM1 TO1 FROM2 TO2: both renames in one transaction (all or nothing).
# Renaming needs no other sessions on the databases; terminate them and retry, since
# a terminated backend can take a moment to go away.
rename_pair() {
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if db_psql -v a="$1" -v a2="$2" -v b="$3" -v b2="$4" >/dev/null 2>&1 <<'SQL'
SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity
 WHERE datname IN (:'a', :'b') AND pid <> pg_backend_pid();
BEGIN;
ALTER DATABASE :"a" RENAME TO :"a2";
ALTER DATABASE :"b" RENAME TO :"b2";
COMMIT;
SQL
    then
      return 0
    fi
    sleep "$i"
  done
  return 1
}

server_stopped=0
# fd 3 = the original stderr. A signal that arrives during a redirected command runs
# the trap with that command's redirections still in place, so write to fd 3.
exec 3>&2
# shellcheck disable=SC2317 # invoked by the EXIT trap
# shellcheck disable=SC2329 # invoked via trap
on_exit() {
  local rc=$?
  if [[ $server_stopped -eq 1 ]]; then
    warn "restore did not finish; starting the server again" 2>&3
    compose_start_server >/dev/null 2>&1 || warn "could not start the server; run ./scripts/up.sh" 2>&3
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

log "starting db"
compose up -d db >/dev/null
wait_db_ready 120

# The database name as the db container (and so the server) sees it.
target_db="$(db_psql -tA <<<"SELECT :'db';")"
target_db="${target_db//[[:space:]]/}"
[[ -n "$target_db" ]] || die "could not determine POSTGRES_DB from the db container"
case "$target_db" in
  "$incoming_db" | "$previous_db" | "$rejected_db" | template0 | template1)
    die "POSTGRES_DB must not be '$target_db' (reserved by restore.sh)" ;;
esac

for leftover in "$incoming_db" "$rejected_db" "$previous_db"; do
  if db_exists "$leftover"; then
    warn "dropping leftover database '$leftover' from an earlier interrupted restore"
    drop_db "$leftover"
  fi
done

# --- 1. restore into the scratch database; the live database is untouched -------
log "restoring $file into scratch database $incoming_db (the current database is kept)"
db_psql -v name="$incoming_db" >/dev/null <<'SQL'
CREATE DATABASE :"name" OWNER :"owner" TEMPLATE template0 ENCODING 'UTF8';
SQL
# shellcheck disable=SC2016 # expanded inside the container
if ! compose exec -T db sh -c 'exec pg_restore --no-owner --no-privileges --exit-on-error --single-transaction -U "$POSTGRES_USER" -d "$1"' sh "$incoming_db" <"$file"; then
  drop_db "$incoming_db" || true
  die "pg_restore failed: $file is truncated, corrupt or not a Coffer backup. Nothing was changed; the current database and server are untouched."
fi

# --- 2. swap it in --------------------------------------------------------------
log "stopping server"
server_stopped=1
compose stop server >/dev/null 2>&1 || true

had_previous=0
if db_exists "$target_db"; then
  had_previous=1
  log "swapping databases: $target_db -> $previous_db, $incoming_db -> $target_db"
  rename_pair "$target_db" "$previous_db" "$incoming_db" "$target_db" ||
    die "could not swap the restored database in (other sessions kept connecting?). Nothing was changed; $incoming_db holds the restored copy."
else
  log "no current database; renaming $incoming_db -> $target_db"
  db_psql -v a="$incoming_db" -v a2="$target_db" >/dev/null <<<'ALTER DATABASE :"a" RENAME TO :"a2";'
fi

# --- 3. start the server on the restored database ---------------------------------
log "starting server"
if compose_start_server && (wait_server_ready "$ready_timeout"); then
  server_stopped=0
  if [[ $had_previous -eq 1 ]]; then
    drop_db "$previous_db" || warn "could not drop $previous_db (the pre-restore database); drop it manually"
  fi
  log "restore complete"
  exit 0
fi

if [[ $had_previous -eq 0 ]]; then
  die "the server did not become ready on the restored database (does COFFER_MASTER_KEY match the backup?). There was no previous database to roll back to."
fi

warn "the server did not become ready on the restored database; rolling back to the previous database"
compose stop server >/dev/null 2>&1 || true
rename_pair "$target_db" "$rejected_db" "$previous_db" "$target_db" ||
  die "rollback failed: the previous database is still named $previous_db; rename it to $target_db by hand"
drop_db "$rejected_db" || true
compose_start_server
server_stopped=0
(wait_server_ready "$ready_timeout") || warn "the server is not ready on the previous database either"
die "restore failed and was rolled back; the previous database is in place. Check that COFFER_MASTER_KEY in .env is the key of the stack that made $file (server log above)."
