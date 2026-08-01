# syntax=docker/dockerfile:1

# --platform=$BUILDPLATFORM keeps the toolchain native and cross-compiles to
# the target below. Without it, buildx runs this whole stage under QEMU
# emulation for every non-native architecture.
#
# Pinned by digest, not just tag: a tag can be repointed by the publisher.
# The tag stays for readability and so Dependabot can see what to bump.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src

# Dependencies change far less often than source, so resolve them in their own
# layer and keep the module cache between builds.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Stamped by the release workflow so a running container can report what it
# is. A local `docker build .` leaves it as "dev".
ARG VERSION=dev

# TARGETARCH comes from buildx and is what makes the multi-arch release build
# cross-compile instead of emulating.
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/webhook ./cmd/route53-dnsweaver-webhook

# distroless/static carries the CA bundle the AWS SDK needs for TLS and little
# else: no shell, no package manager, and an unprivileged default user.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

COPY --from=build /out/webhook /usr/local/bin/webhook

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/webhook"]
