#!/usr/bin/env bash
# Stop the Coffer stack. Data is kept: the Postgres volume is NOT removed.
#
# Usage: ./scripts/down.sh
set -euo pipefail
# shellcheck source=scripts/lib.sh source-path=SCRIPTDIR/..
source "$(dirname "$0")/lib.sh"

if [[ $# -gt 0 ]]; then
  printf 'usage: %s   (takes no arguments; volumes are always kept)\n' "$0" >&2
  exit 2
fi
compose down
log "stack stopped (data volume kept)"
