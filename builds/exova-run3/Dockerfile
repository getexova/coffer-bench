# syntax=docker/dockerfile:1
#
# Coffer server image. Two stages: a pinned Go toolchain builds a static binary, and a
# pinned Alpine image runs it as a non-root user with nothing but busybox alongside.
#
# There is deliberately no HEALTHCHECK instruction here. podman's default OCI image
# format silently drops HEALTHCHECK, so an image-level check would be a no-op on this
# host and would make the service look unhealthy/healthy by accident. compose.yaml owns
# both healthchecks (db via pg_isready, server via /healthz) for docker and podman alike.

FROM golang:1.27.3-bookworm AS build

WORKDIR /src

# CGO off gives a statically linked binary that runs on Alpine with no libc shims.
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOTOOLCHAIN=local

# The whole tree is copied in one layer rather than splitting go.mod/go.sum into a cached
# dependency layer: a `COPY go.sum*` glob fails the build outright when go.sum is absent,
# and a missing lockfile must not be the difference between a working image and a broken
# one. .dockerignore keeps the context small and keeps .env out of the image.
COPY . .

# -trimpath keeps build paths out of the binary; the output lands outside the source tree
# so the runtime stage copies exactly one file.
RUN go build -trimpath -o /out/bin/coffer ./cmd/coffer

FROM alpine:3.22@sha256:dc92f017beea8e7f43263073d717f7bc011228c95d5312e440deb4d035bb4eec

# No shell tools beyond busybox: no curl, no bash, no package manager additions.
RUN adduser -D -u 10001 -h /home/coffer coffer

COPY --from=build /out/bin/coffer /usr/local/bin/coffer

# Inside the container the process must listen on all interfaces for the port mapping to
# reach it; compose also sets these explicitly.
ENV COFFER_BIND_ADDR=0.0.0.0 \
    COFFER_PORT=8420

USER 10001:10001
WORKDIR /home/coffer

EXPOSE 8420

# Config is environment-only (SPEC §5), so the only argument the binary ever gets is the
# server subcommand.
ENTRYPOINT ["/usr/local/bin/coffer"]
CMD ["server"]
