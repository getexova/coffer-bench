#!/usr/bin/env bash
# Check that every environment variable read by the server or by the ops scripts is
# documented in .env.example (SPEC 5: "all documented in .env.example").
#
# Server: names passed to the config package's get()/lookup() and os.Getenv in
# non-test server code. CLI: COFFER_* names passed to env()/Getenv in the CLI.
# e2e suite: COFFER_* names passed to envOr()/Getenv in test/e2e.
# Scripts: ${COFFER_*} / ${POSTGRES_*} references in scripts/ and compose.yaml.
#
# test.sh runs this check too, so a missing entry fails locally, not only in CI.
#
# Usage: ./scripts/check-env-docs.sh
set -euo pipefail
# shellcheck source=scripts/lib.sh source-path=SCRIPTDIR/..
source "$(dirname "$0")/lib.sh"

[[ -f .env.example ]] || die ".env.example not found"

server_vars="$(
  find cmd/coffer-server internal/server -name '*.go' ! -name '*_test.go' ! -path '*/testutil/*' -print0 |
    xargs -0 grep -hoE '\b(get|lookup|Getenv|LookupEnv)\("[A-Z][A-Z0-9_]*"' |
    sed -E 's/.*\("([A-Z0-9_]+)"/\1/'
)"
client_vars="$(
  find cmd/coffer internal/cli test/e2e -name '*.go' -print0 |
    xargs -0 grep -hoE '\b(env|envOr|Getenv|LookupEnv)\("COFFER_[A-Z0-9_]+"' |
    sed -E 's/.*\("([A-Z0-9_]+)"/\1/'
)"
script_vars="$(
  grep -hoE '\$\{?(COFFER|POSTGRES)_[A-Z0-9_]+' scripts/*.sh compose.yaml |
    sed -E 's/^\$\{?//' | grep -vxE 'COFFER_ROOT'
)"

missing=0
while read -r v; do
  [[ -n "$v" ]] || continue
  # Documented = appears as KEY=, #KEY= or "# KEY  description" in .env.example.
  if ! grep -qE "^#? ?${v}([= ]|$)" .env.example; then
    printf 'undocumented in .env.example: %s\n' "$v" >&2
    missing=1
  fi
done < <(printf '%s\n%s\n%s\n' "$server_vars" "$client_vars" "$script_vars" | sort -u)

[[ $missing -eq 0 ]] || die "document the variables above in .env.example"
log ".env.example documents every variable read by the server, the CLI, the e2e suite and the scripts"
