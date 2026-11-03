#!/usr/bin/env bash
# Ops lifecycle smoke test for the compose stack and the ops scripts.
#
# Runs against a PRIVATE copy of this checkout (its own compose project, port and
# volume), so it never touches a stack started from the checkout itself. It checks:
#   1. init-env.sh + up.sh -> /readyz 200, seed a secret
#   2. a changed .env value (COFFER_PAT_TTL) reaches the server after up.sh
#   3. master-key rotation: NEW + PREVIOUS, up.sh -> "master key rotated", value intact
#   4. PREVIOUS removed, up.sh -> value intact; down.sh + up.sh -> value intact
#   5. restore of a truncated backup fails and changes nothing (server ready, data intact)
#   6. restore of a pre-rotation backup with only the NEW key is refused
#      ("master key does not match database") and rolled back (data intact); with the
#      OLD key it reproduces the value
# The private stack and its volume are always removed on exit.
#
# Usage: ./scripts/ops-smoke.sh
# Env:   COFFER_SMOKE_PORT (default: a free loopback port), COFFER_COMPOSE as for up.sh
set -euo pipefail
# shellcheck source=scripts/lib.sh source-path=SCRIPTDIR/..
source "$(dirname "$0")/lib.sh"

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required (JSON parsing)"

free_port() {
  python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}
port="${COFFER_SMOKE_PORT:-$(free_port)}"
[[ "$port" =~ ^[0-9]+$ ]] || die "bad COFFER_SMOKE_PORT"

parent="$(mktemp -d "${TMPDIR:-/tmp}/coffer-ops-smoke.XXXXXX")"
# Directory basename = compose project name: unique and lowercase.
work="${parent}/coffersmoke$$"
mkdir -p "$work"
tar -C "$COFFER_ROOT" --exclude=./.git --exclude=./bin --exclude=./.env --exclude='./.env.tmp.*' -cf - . | tar -C "$work" -xf -
log "private copy: $work (port $port)"

# in_copy CMD...: run CMD with lib.sh sourced inside the private copy.
in_copy() {
  (cd "$work" && bash -c 'source scripts/lib.sh; "$@"' in_copy "$@")
}
cleanup() {
  local rc=$?
  if [[ $rc -ne 0 && -d "$work" ]]; then
    in_copy compose logs --tail 60 server >&2 2>&1 || true
  fi
  in_copy compose down -v >/dev/null 2>&1 || true
  rm -rf "$parent"
  exit "$rc"
}
trap cleanup EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'ok   %s\n' "$*" >&2; }

env_set() { # env_set NAME VALUE (replace or append, in the copy's .env)
  local f="$work/.env"
  grep -v -E "^$1=" "$f" >"$f.new" || true
  printf '%s=%s\n' "$1" "$2" >>"$f.new"
  chmod 600 "$f.new" && mv -f "$f.new" "$f"
}
env_del() {
  local f="$work/.env"
  grep -v -E "^$1=" "$f" >"$f.new" || true
  chmod 600 "$f.new" && mv -f "$f.new" "$f"
}
env_val() { grep -E "^$1=" "$work/.env" | tail -n1 | cut -d= -f2-; }

base="http://127.0.0.1:${port}/api/v1"
TOKEN=""
resp="" code=""
api() { # api METHOD PATH [JSON] -> sets $resp (body) and $code (HTTP status); no subshell
  local m="$1" p="$2" d="${3:-}" out
  out="$(mktemp)"
  local args=(-s -o "$out" -w '%{http_code}' -X "$m" -H 'Content-Type: application/json')
  if [[ -n "$TOKEN" ]]; then args+=(-H "Authorization: Bearer ${TOKEN}"); fi
  if [[ -n "$d" ]]; then args+=(--data-binary "$d"); fi
  code="$(curl "${args[@]}" "${base}${p}" || true)"
  resp="$(cat "$out")"
  rm -f "$out"
}
jget() { python3 -I -c 'import sys,json;d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d[k]
sys.stdout.write(d)' "$1" <<<"$resp"; }
login() { # login EMAIL PASSWORD -> sets TOKEN and $expires_at
  TOKEN=""
  api POST /auth/token "$(python3 -I -c 'import json,sys;print(json.dumps({"email":sys.argv[1],"password":sys.argv[2]}))' "$1" "$2")"
  [[ "$code" == "201" || "$code" == "200" ]] || fail "login $1: HTTP $code"
  TOKEN="$(jget token)"
  expires_at="$(jget expires_at)"
}
secret_value() { # prints the current value of SMOKE_KEY (exact, no newline added)
  api GET /projects/web/envs/dev/secrets/SMOKE_KEY
  [[ "$code" == "200" ]] || fail "get secret: HTTP $code"
  jget value
}
server_logs() { in_copy compose logs server 2>&1; }

# --- 1. fresh stack ----------------------------------------------------------
(cd "$work" && ./scripts/init-env.sh >/dev/null)
env_set COFFER_PORT "$port"
(cd "$work" && ./scripts/up.sh) || fail "up.sh on a fresh stack"
pass "init-env.sh + up.sh: ready"

admin_pw="$(env_val COFFER_BOOTSTRAP_ADMIN_PASSWORD)"
owner_pw="smoke-owner-password-123"
# shellcheck disable=SC2016 # literal $ on purpose (exact bytes)
value='p@ss "w0rd" $HOME \n ünïcødé'
login admin@example.com "$admin_pw"
api POST /admin/orgs "{\"slug\":\"smoke\",\"owner_email\":\"owner@smoke.test\",\"owner_password\":\"$owner_pw\"}"
[[ "$code" == "201" || "$code" == "200" ]] || fail "create org: HTTP $code"
login owner@smoke.test "$owner_pw"
api POST /projects '{"slug":"web"}'
[[ "$code" == "201" || "$code" == "200" ]] || fail "create project: HTTP $code"
api POST /projects/web/envs '{"slug":"dev","protected":false}'
[[ "$code" == "201" || "$code" == "200" ]] || fail "create env: HTTP $code"
json_value="$(python3 -I -c 'import json,sys;print(json.dumps({"value":sys.argv[1]}))' "$value")"
api PUT /projects/web/envs/dev/secrets/SMOKE_KEY "$json_value"
[[ "$code" == "200" ]] || fail "set secret: HTTP $code"
[[ "$(secret_value)" == "$value" ]] || fail "secret round trip"
pass "seeded org, project, env and secret"

# --- 2. .env changes are applied by up.sh --------------------------------------
env_set COFFER_PAT_TTL 2h
(cd "$work" && ./scripts/up.sh) || fail "up.sh after .env change"
login owner@smoke.test "$owner_pw"
exp="$expires_at"
hours="$(python3 -I -c 'import sys,datetime as d
e=d.datetime.fromisoformat(sys.argv[1].replace("Z","+00:00"))
print(round((e-d.datetime.now(d.timezone.utc)).total_seconds()/3600))' "$exp")"
[[ "$hours" == "2" ]] || fail "COFFER_PAT_TTL=2h not applied by up.sh (token lifetime ~${hours}h)"
pass "changed .env value reaches the server after up.sh"

backup_old="${parent}/pre-rotation.dump"
(cd "$work" && ./scripts/backup.sh "$backup_old") >/dev/null 2>&1 || fail "backup.sh"
pass "backup.sh"

# --- 3. master-key rotation --------------------------------------------------
old_key="$(env_val COFFER_MASTER_KEY)"
new_key="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
env_set COFFER_MASTER_KEY "$new_key"
env_set COFFER_MASTER_KEY_PREVIOUS "$old_key"
(cd "$work" && ./scripts/up.sh) || fail "up.sh with NEW + PREVIOUS"
server_logs | grep -q 'master key rotated' || fail "no 'master key rotated' log line after up.sh with PREVIOUS"
[[ "$(secret_value)" == "$value" ]] || fail "value changed after rotation"
pass "rotation: data keys re-wrapped, value intact"

# --- 4. old key no longer needed --------------------------------------------
env_del COFFER_MASTER_KEY_PREVIOUS
(cd "$work" && ./scripts/up.sh) || fail "up.sh with NEW only after rotation"
[[ "$(secret_value)" == "$value" ]] || fail "value after removing PREVIOUS"
(cd "$work" && ./scripts/down.sh && ./scripts/up.sh) || fail "down.sh + up.sh with NEW only"
[[ "$(secret_value)" == "$value" ]] || fail "value after down.sh + up.sh"
pass "PREVIOUS removed; data survives down.sh + up.sh"

# --- 5. a truncated backup is rejected before anything is changed ------------
api PUT /projects/web/envs/dev/secrets/SMOKE_AFTER '{"value":"written-after-backup"}'
[[ "$code" == "200" ]] || fail "set SMOKE_AFTER: HTTP $code"
trunc="${parent}/truncated.dump"
head -c 5000 "$backup_old" >"$trunc"
if (cd "$work" && ./scripts/restore.sh "$trunc") >"${parent}/restore-trunc.log" 2>&1; then
  fail "restore of a truncated backup reported success"
fi
grep -q 'Nothing was changed' "${parent}/restore-trunc.log" || { cat "${parent}/restore-trunc.log" >&2; fail "truncated restore: no 'Nothing was changed' message"; }
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/readyz" || true)"
[[ "$code" == "200" ]] || fail "server not ready after a failed (truncated) restore: /readyz $code"
[[ "$(secret_value)" == "$value" ]] || fail "value changed by a failed (truncated) restore"
api GET /projects/web/envs/dev/secrets/SMOKE_AFTER
[[ "$code" == "200" ]] || fail "data written after the backup lost by a failed (truncated) restore: HTTP $code"
pass "restore of a truncated backup fails and changes nothing (same PAT still valid)"

# --- 6. restore needs the matching master key, and a refused one is rolled back
if (cd "$work" && COFFER_READY_TIMEOUT=25 ./scripts/restore.sh "$backup_old") >"${parent}/restore-wrongkey.log" 2>&1; then
  fail "restore of a pre-rotation backup with only the NEW key reported success"
fi
grep -q 'master key does not match database' "${parent}/restore-wrongkey.log" || { cat "${parent}/restore-wrongkey.log" >&2; fail "wrong-key refusal not logged"; }
grep -q 'rolled back' "${parent}/restore-wrongkey.log" || fail "wrong-key restore: no rollback message"
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/readyz" || true)"
[[ "$code" == "200" ]] || fail "server not ready after a rolled-back restore: /readyz $code"
api GET /projects/web/envs/dev/secrets/SMOKE_AFTER
[[ "$code" == "200" ]] || fail "rolled-back restore lost data written after the backup: HTTP $code"
pass "restore with the wrong master key is refused and rolled back (data intact)"
env_set COFFER_MASTER_KEY "$old_key"
(cd "$work" && ./scripts/restore.sh "$backup_old") >/dev/null 2>&1 || fail "restore.sh with the OLD key"
login owner@smoke.test "$owner_pw"
[[ "$(secret_value)" == "$value" ]] || fail "value after restore"
api GET /projects/web/envs/dev/secrets/SMOKE_AFTER
[[ "$code" == "404" ]] || fail "restore did not replace the database (SMOKE_AFTER: HTTP $code, want 404)"
api GET /audit/verify
[[ "$code" == "200" && "$resp" == *'"valid":true'* ]] || fail "audit chain after restore: HTTP $code $resp"
# shellcheck disable=SC2016 # expanded inside the container
in_copy compose exec -T db sh -c 'exec psql -XtA -U "$POSTGRES_USER" -d template1' \
  <<<"SELECT datname FROM pg_database WHERE datname LIKE 'coffer_restore_%';" >"${parent}/leftover-dbs" ||
  fail "could not list databases"
[[ ! -s "${parent}/leftover-dbs" ]] || fail "restore left scratch databases behind: $(cat "${parent}/leftover-dbs")"
pass "restore with the matching key reproduces the secret; audit chain verifies; no scratch DBs left"

log "ops smoke test passed"
