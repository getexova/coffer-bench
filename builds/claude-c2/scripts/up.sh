#!/usr/bin/env bash
# Build and start the Coffer stack (server + db), then wait until
# http://127.0.0.1:${COFFER_PORT}/readyz returns 200. Fails after 180 s.
#
# The server container is always recreated, so every change to .env (for example
# a master-key rotation, see README "Master key rotation") is applied. The db
# container and its data volume are kept.
#
# If .env does not exist yet, it is created first with ./scripts/init-env.sh (which
# prints the generated admin password once). Once the server is ready, the CLI is
# built into ./bin/coffer with ./scripts/build.sh, so the README quickstart needs no
# separate build step. Set COFFER_SKIP_CLI_BUILD=1 to skip that.
#
# Usage: ./scripts/up.sh
set -euo pipefail
# shellcheck source=scripts/lib.sh source-path=SCRIPTDIR/..
source "$(dirname "$0")/lib.sh"

if [[ $# -gt 0 ]]; then
  printf 'usage: %s   (takes no arguments)\n' "$0" >&2
  exit 2
fi

if [[ ! -f .env ]]; then
  log "no .env found; creating one with ./scripts/init-env.sh"
  COFFER_FROM_UP=1 ./scripts/init-env.sh
fi
require_env_file
if grep -q '^COFFER_MASTER_KEY=REPLACE_ME' .env; then
  die ".env still contains the placeholder master key. Generate a real .env with: ./scripts/init-env.sh --force"
fi

detect_compose
log "starting stack with: ${COMPOSE[*]}"
compose_up_stack
wait_server_ready "${COFFER_READY_TIMEOUT:-180}"

if [[ "${COFFER_SKIP_CLI_BUILD:-0}" != "1" ]]; then
  ./scripts/build.sh
fi
