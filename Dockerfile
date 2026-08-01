# syntax=docker/dockerfile:1

# There is no build stage here on purpose. GoReleaser has already compiled the
# binary for every platform and lays them out in the build context as
# <os>/<arch>/<binary>, so this image copies the exact bytes that get published
# in the archives. Compiling again here would produce a second, different
# binary of the same commit under whatever Go toolchain the base image happens
# to carry, and the published SBOM and signature would only describe one of
# them.
#
# The consequence: `docker build .` no longer works on its own, because the
# context it needs is assembled by GoReleaser. To build the image locally:
#
#   goreleaser release --snapshot --clean --skip=archive,nfpm,sbom,sign
#
# distroless/static carries the CA bundle the AWS SDK needs for TLS and little
# else: no shell, no package manager, and an unprivileged default user.
#
# Pinned by digest, not just tag: a tag can be repointed by the publisher.
# The tag stays for readability and so Dependabot can see what to bump.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

# Set by buildx for each platform in the manifest, and matches the directory
# layout GoReleaser builds in the context.
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/route53-dnsweaver-webhook /usr/local/bin/webhook

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/webhook"]
