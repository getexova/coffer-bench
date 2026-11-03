#!/bin/sh
# Create .env from .env.example with freshly generated secrets, and print the platform
# admin password exactly once.
#
# Generated values:
#   COFFER_MASTER_KEY           base64 of 32 random bytes (44 characters)
#   COFFER_BOOTSTRAP_ADMIN_PASSWORD  24 random bytes, base64 (32 characters)
#   POSTGRES_PASSWORD          hex (safe inside a connection URL and inside SQL)
#   COFFER_APP_DB_PASSWORD     hex, same reason
#
# An existing .env is never overwritten: it holds a master key, and replacing it would
# make every stored secret undecryptable.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

env_file=".env"
example_file=".env.example"

if [ ! -f "$example_file" ]; then
  printf 'error: %s is missing; cannot create %s\n' "$example_file" "$env_file" >&2
  exit 1
fi

if [ -e "$env_file" ]; then
  printf '%s already exists: %s/%s\n' "$env_file" "$repo_root" "$env_file"
  printf 'Leaving it untouched. Delete it by hand if you really want a new master key\n'
  printf 'and a new bootstrap admin password.\n'
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  printf 'error: openssl is required to generate secrets and was not found in PATH\n' >&2
  exit 1
fi

# 32 bytes -> 44 base64 characters, which decodes back to exactly 32 bytes.
master_key=$(openssl rand -base64 32)
master_key=$(printf '%s' "$master_key" | tr -d '\n')
if [ "${#master_key}" -ne 44 ]; then
  printf 'error: generated master key is %s characters, expected 44\n' "${#master_key}" >&2
  exit 1
fi

# 24 bytes -> 32 base64 characters, no padding, no character that needs escaping in a
# .env file. Well above the 12-character minimum for the admin password.
admin_password=$(openssl rand -base64 24 | tr -d '\n')
if [ "${#admin_password}" -lt 12 ]; then
  printf 'error: generated admin password is shorter than 12 characters\n' >&2
  exit 1
fi

# Hex: safe in a postgres:// URL and in an ALTER ROLE ... PASSWORD statement.
db_password=$(openssl rand -hex 24)
app_db_password=$(openssl rand -hex 24)

# Create the file with 0600 from the first byte, never world-readable.
umask 077
tmp_file="$env_file.tmp.$$"
trap 'rm -f "$tmp_file"' EXIT INT TERM

MASTER_KEY="$master_key" \
ADMIN_PASSWORD="$admin_password" \
DB_PASSWORD="$db_password" \
APP_DB_PASSWORD="$app_db_password" \
awk '
  BEGIN {
    master = ENVIRON["MASTER_KEY"]
    admin  = ENVIRON["ADMIN_PASSWORD"]
    dbpw   = ENVIRON["DB_PASSWORD"]
    apppw  = ENVIRON["APP_DB_PASSWORD"]
  }
  {
    line = $0
    if (substr(line, 1, 1) == "#") { print line; next }
    eq = index(line, "=")
    if (eq == 0) { print line; next }
    name  = substr(line, 1, eq - 1)
    value = substr(line, eq + 1)
    if (value == "REPLACE_ME_WITH_BASE64_32_BYTES") {
      value = master
    } else if (value == "REPLACE_ME_WITH_A_12_CHAR_PASSWORD") {
      value = admin
    } else if (value == "REPLACE_ME_WITH_A_DB_PASSWORD") {
      if (name == "POSTGRES_PASSWORD") { value = dbpw }
      else if (name == "COFFER_APP_DB_PASSWORD") { value = apppw }
    }
    print name "=" value
  }
' "$example_file" > "$tmp_file"

# Never leave a half-substituted .env behind: the server refuses the placeholder, and a
# missing DB password is worse than a clear failure here. Only an unsubstituted value
# counts — comments in .env.example legitimately mention REPLACE_ME_* by name.
if grep -q '^[A-Za-z_][A-Za-z0-9_]*=REPLACE_ME' "$tmp_file"; then
  printf 'error: could not substitute every placeholder in %s:\n' "$example_file" >&2
  grep '^[A-Za-z_][A-Za-z0-9_]*=REPLACE_ME' "$tmp_file" >&2 || true
  exit 1
fi

chmod 600 "$tmp_file"
mv -f "$tmp_file" "$env_file"
chmod 600 "$env_file"

admin_email=$(sed -n 's/^COFFER_BOOTSTRAP_ADMIN_EMAIL=//p' "$env_file" | tail -n 1)
if [ -z "$admin_email" ]; then
  admin_email="admin@coffer.local"
fi

printf '\nWrote %s/%s (mode 0600) with a new master key and new database passwords.\n\n' "$repo_root" "$env_file"
printf 'Platform admin email:    %s\n' "$admin_email"
printf 'Platform admin password: %s\n' "$admin_password"
printf '\nThis password is printed once. It is also in %s in plaintext; nothing else\n' "$env_file"
printf 'stores it. Copy it somewhere safe now.\n'
printf '\nNext: ./scripts/up.sh\n'
