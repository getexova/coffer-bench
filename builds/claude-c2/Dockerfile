# syntax=docker/dockerfile:1
#
# Coffer server image.
#   builder: official Go toolchain, pinned to an exact version and digest
#   runtime: distroless static, non-root (UID/GID 65532), no shell, no package manager,
#            pinned by digest ("nonroot" alone is a moving tag)
#
# Bump both together (and GO_IMAGE in scripts/build.sh + scripts/test.sh):
#   podman pull IMAGE:TAG && podman inspect --format "{{.Digest}}" IMAGE:TAG
# or read the Docker-Content-Digest header of the registry manifest index.
#
# Fully-qualified image names are used so podman (short-name-mode=enforcing) never
# has to prompt.

FROM docker.io/library/golang:1.26.10-alpine3.24@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS builder

WORKDIR /src

# Dependency layer: only re-downloaded when go.mod / go.sum change.
# (go.su[m] makes the COPY succeed even before go.sum exists.)
COPY go.mod go.su[m] ./
RUN go mod download && go mod verify

COPY . .

ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -trimpath -buildvcs=false -ldflags "-s -w" \
      -o /out/coffer-server ./cmd/coffer-server

# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /out/coffer-server /coffer-server

USER 65532:65532
EXPOSE 8420

# Exit 0 only when /readyz returns 200 (no shell or curl in the image).
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/coffer-server", "healthcheck"]

ENTRYPOINT ["/coffer-server"]
