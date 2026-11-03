#!/usr/bin/env bash
# Create .env from .env.example with freshly generated secrets:
#   COFFER_MASTER_KEY               32 random bytes, base64
#   COFFER_BOOTSTRAP_ADMIN_PASSWORD 32 random URL-safe characters
#   POSTGRES_PASSWORD               32 random URL-safe characters
# The admin password is printed once. .env is created with mode 0600.
#
# Usage: ./scripts/init-env.sh [--force]
set -euo pipefail
# shellcheck source=scripts/lib.sh source-path=SCRIPTDIR/..
source "$(dirname "$0")/lib.sh"

force=0
for arg in "$@"; do
  case "$arg" in
    --force|-f) force=1 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'usage: %s [--force]\n' "$0" >&2; exit 2 ;;
  esac
done

[[ -f .env.example ]] || die ".env.example not found in $COFFER_ROOT"
if [[ -e .env && $force -ne 1 ]]; then
  die ".env already exists; refusing to overwrite it (it holds the master key). Use --force to replace it."
fi
if [[ -e .env ]]; then
  warn "replacing existing .env. An existing database volume keeps its old Postgres password and"
  warn "its data stays encrypted under the OLD master key; run ./scripts/down.sh and remove the"
  warn "volume first, or the server will not start. (Backup of the old file: none is made.)"
fi

# rand_bytes_b64 N: N random bytes, standard base64, one line.
rand_bytes_b64() {
  local n="$1" out=""
  if command -v openssl >/dev/null 2>&1; then
    out="$(openssl rand -base64 "$n" 2>/dev/null | tr -d '\n' || true)"
  fi
  if [[ -z "$out" ]]; then
    out="$(head -c "$n" /dev/urandom | base64 | tr -d '\n')"
  fi
  printf '%s' "$out"
}

# rand_urlsafe LEN: LEN characters from [A-Za-z0-9_-].
rand_urlsafe() {
  local len="$1" out=""
  while [[ ${#out} -lt $len ]]; do
    out+="$(rand_bytes_b64 48 | tr '+/' '-_' | tr -d '=')"
  done
  printf '%s' "${out:0:len}"
}

master_key="$(rand_bytes_b64 32)"
admin_password="$(rand_urlsafe 32)"
pg_password="$(rand_urlsafe 32)"

# Sanity checks on what we generated.
[[ ${#master_key} -eq 44 ]] || die "failed to generate master key"
[[ "$admin_password" =~ ^[A-Za-z0-9_-]{32}$ ]] || die "failed to generate admin password"
[[ "$pg_password" =~ ^[A-Za-z0-9_-]{32}$ ]] || die "failed to generate postgres password"

for key in COFFER_MASTER_KEY COFFER_BOOTSTRAP_ADMIN_PASSWORD POSTGRES_PASSWORD; do
  n="$(grep -cE "^${key}=" .env.example || true)"
  [[ "$n" -eq 1 ]] || die ".env.example must contain exactly one ${key}= line (found $n)"
done

umask 077
tmp="$(mktemp "${COFFER_ROOT}/.env.tmp.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

# Values are passed through the environment (not awk -v) so no escape processing occurs.
CK_MASTER="$master_key" CK_ADMIN="$admin_password" CK_PG="$pg_password" \
awk '
  /^COFFER_MASTER_KEY=/               { print "COFFER_MASTER_KEY=" ENVIRON["CK_MASTER"]; next }
  /^COFFER_BOOTSTRAP_ADMIN_PASSWORD=/ { print "COFFER_BOOTSTRAP_ADMIN_PASSWORD=" ENVIRON["CK_ADMIN"]; next }
  /^POSTGRES_PASSWORD=/               { print "POSTGRES_PASSWORD=" ENVIRON["CK_PG"]; next }
  { print }
' .env.example >"$tmp"

chmod 600 "$tmp"
mv -f "$tmp" .env
trap - EXIT
chmod 600 .env

admin_email="$(env_get COFFER_BOOTSTRAP_ADMIN_EMAIL)"

cat <<EOF
Wrote $COFFER_ROOT/.env (mode 0600) with a new master key, admin password and Postgres password.

  Platform admin email:    ${admin_email}
  Platform admin password: ${admin_password}

This password is shown only once (it is also stored in .env as COFFER_BOOTSTRAP_ADMIN_PASSWORD).
Back up COFFER_MASTER_KEY from .env somewhere safe and separate from database backups:
without it, encrypted secrets cannot be recovered.
EOF
if [[ -z "${COFFER_FROM_UP:-}" ]]; then
  echo "Next: ./scripts/up.sh"
fi
