#!/usr/bin/env bash
# Build the Coffer CLI as ./bin/coffer (static, linux/amd64).
#
# Uses a local Go toolchain if it satisfies go.mod (>= 1.26); otherwise builds
# inside docker.io/library/golang:1.26.10-alpine3.24 (pinned by digest) with podman or docker.
#
# Usage: ./scripts/build.sh [--server]
#   --server   also build ./bin/coffer-server
# Env: COFFER_BUILD_IN_CONTAINER=1 forces the container build.
set -euo pipefail
# shellcheck source=scripts/lib.sh source-path=SCRIPTDIR/..
source "$(dirname "$0")/lib.sh"

GO_IMAGE="docker.io/library/golang:1.26.10-alpine3.24@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308"  # keep in sync with Dockerfile
REQUIRED_GO_MINOR=26

build_server=0
for arg in "$@"; do
  case "$arg" in
    --server) build_server=1 ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'usage: %s [--server]\n' "$0" >&2; exit 2 ;;
  esac
done

targets=("coffer:./cmd/coffer")
if [[ $build_server -eq 1 ]]; then
  targets+=("coffer-server:./cmd/coffer-server")
fi

# local_go_ok: true if `go` exists and is go1.N with N >= REQUIRED_GO_MINOR (major 1).
local_go_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local v
  v="$(go env GOVERSION 2>/dev/null || true)"   # e.g. go1.26.3, go1.27rc1
  [[ "$v" =~ ^go1\.([0-9]+) ]] || return 1
  (( BASH_REMATCH[1] >= REQUIRED_GO_MINOR ))
}

mkdir -p bin

if [[ "${COFFER_BUILD_IN_CONTAINER:-0}" != "1" ]] && local_go_ok; then
  log "building with local $(go env GOVERSION)"
  for t in "${targets[@]}"; do
    name="${t%%:*}" pkg="${t#*:}"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -buildvcs=false -ldflags "-s -w" -o "bin/${name}" "$pkg"
    log "built bin/${name}"
  done
  exit 0
fi

runtime="$(detect_runtime)" || die "no Go >= 1.${REQUIRED_GO_MINOR} toolchain and no container runtime (podman or docker) found; install one of them"
log "no suitable local Go toolchain; building inside ${GO_IMAGE} with ${runtime}"

# Build script executed inside the container. Output goes to a container-private
# directory and is then streamed out with tar, so file ownership on the host is
# always the invoking user's (works for rootless podman and rootful docker alike).
# shellcheck disable=SC2016 # expanded inside the container
inner='set -eu
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-buildvcs=false
mkdir -p /out
for t in "$@"; do
  name="${t%%:*}"; pkg="${t#*:}"
  go build -trimpath -ldflags "-s -w" -o "/out/${name}" "$pkg" >&2
done
tar -C /out -cf - .'

sel=()
if [[ "$runtime" == "podman" ]]; then
  sel=(--security-opt label=disable)   # allow reading the bind mount under SELinux
fi

"$runtime" run --rm "${sel[@]}" \
  -v "${COFFER_ROOT}:/src:ro" -w /src \
  -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod \
  "$GO_IMAGE" sh -c "$inner" sh "${targets[@]}" | tar -C bin -xf -

for t in "${targets[@]}"; do
  name="${t%%:*}"
  [[ -x "bin/${name}" ]] || die "container build did not produce bin/${name}"
  log "built bin/${name}"
done
