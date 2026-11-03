#!/bin/sh
# Build ./bin/coffer for Linux x86_64.
#
# Path 1 (preferred): the host Go toolchain, with CGO disabled so the binary is static.
# Path 2 (fallback): the pinned golang:1.27.3-bookworm image, bind-mounting the repo.
#
# The container path uses --userns=keep-id under podman. `--user $(id -u):$(id -g)` does
# NOT work for a rootless podman bind-mount build: Go cannot write the module cache into
# the mounted tree and fails with `go.sum: permission denied`.
set -eu

go_package="./cmd/coffer"
output="bin/coffer"
go_image="golang:1.27.3-bookworm"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

if [ ! -f go.mod ]; then
  printf 'error: go.mod not found in %s\n' "$repo_root" >&2
  exit 1
fi

if [ ! -d cmd/coffer ]; then
  printf 'error: %s is missing; the CLI package has not been built yet\n' "$go_package" >&2
  exit 1
fi

mkdir -p bin

detect_runtime() {
  if command -v podman >/dev/null 2>&1; then
    printf 'podman'
  elif command -v docker >/dev/null 2>&1; then
    printf 'docker'
  fi
}

if command -v go >/dev/null 2>&1; then
  printf 'build path: host Go toolchain (%s)\n' "$(go version 2>/dev/null || printf 'go (version unavailable)')"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$output" "$go_package"
  built_with="the host Go toolchain"
else
  runtime=$(detect_runtime)
  if [ -z "$runtime" ]; then
    printf 'error: no Go toolchain and no container runtime (podman or docker) found.\n' >&2
    printf 'Install Go 1.27+ or podman/docker, then re-run ./scripts/build.sh.\n' >&2
    exit 1
  fi
  printf 'build path: container image %s via %s (no host Go toolchain found)\n' "$go_image" "$runtime"

  # The whole argument list is written out once per runtime rather than assembled in a
  # helper: nothing here is word-split or re-quoted, which is where shell scripts of this
  # shape usually break. --userns=keep-id under podman maps the container user to the host
  # user so the bind-mounted tree stays writable; :Z relabels it for SELinux hosts.
  if [ "$runtime" = "podman" ]; then
    "$runtime" run --rm \
      --userns=keep-id \
      -v "$repo_root:/src:Z" \
      -w /src \
      -e CGO_ENABLED=0 \
      -e GOTOOLCHAIN=local \
      -e HOME=/tmp \
      -e GOPATH=/tmp/go \
      -e GOCACHE=/tmp/go-cache \
      -e GOMODCACHE=/tmp/go-mod-cache \
      "$go_image" \
      go build -trimpath -o "$output" "$go_package"
  else
    "$runtime" run --rm \
      --user "$(id -u):$(id -g)" \
      -v "$repo_root:/src" \
      -w /src \
      -e CGO_ENABLED=0 \
      -e GOTOOLCHAIN=local \
      -e HOME=/tmp \
      -e GOPATH=/tmp/go \
      -e GOCACHE=/tmp/go-cache \
      -e GOMODCACHE=/tmp/go-mod-cache \
      "$go_image" \
      go build -trimpath -o "$output" "$go_package"
  fi
  built_with="the $go_image container via $runtime"
fi

if [ ! -f "$output" ]; then
  printf 'error: %s was not produced by the build\n' "$output" >&2
  exit 1
fi

chmod 755 "$output"

size=$(wc -c < "$output" | tr -d ' ')
printf 'Built ./%s (%s bytes, linux/amd64, CGO disabled) with %s.\n' "$output" "$size" "$built_with"
