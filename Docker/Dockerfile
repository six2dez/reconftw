# syntax=docker/dockerfile:1.4
#
# reconFTW v2 — multi-stage image (Phase 11, DOCK-01..07).
#
#   gobuild stage  : cross-compiles the v2 binary FOR the target platform
#                    (TARGETOS/TARGETARCH) ON the build platform (F5).
#   builder stage  : golang:bookworm + build deps + uv → runs `reconftw install`
#                    to populate every orchestrated tool (DOCK-04).
#   final stage    : debian:bookworm-slim (D-07 — distroless/Alpine rejected,
#                    see Docker/README.md) with only the runtime deps + the
#                    installed tools, running as a NON-ROOT user (DOCK-07) with
#                    cap_net_raw granted to naabu + nmap via setcap.
#
# Tools install under /opt (GOPATH=/opt/go, uv → /opt/uv) so the non-root
# `reconftw` user can execute them — /root is 0700 and unusable post-USER-switch.
#
# Build (multi-arch) from the REPO ROOT (context = . for Docker/entrypoint.sh
# and the Go sources). NO host-side `make build` is needed or wanted: the image
# compiles its own binary per platform.
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f Docker/Dockerfile -t ghcr.io/six2dez/reconftw:latest .
#
# Pass VERSION/COMMIT_SHA/BUILD_DATE to stamp the binary the way `make build`
# does; without them `reconftw version` reports the source defaults
# (dev/unknown/unknown), exactly as a plain `go build` would.

ARG GO_VERSION=1.25.13
ARG DEBIAN_CODENAME=bookworm

########################################################################
### gobuild — cross-compile the v2 binary for the TARGET platform (F5)
########################################################################
#
# `--platform=$BUILDPLATFORM` pins this stage to the NATIVE runner while
# GOOS/GOARCH select the output, so an arm64 image is cross-compiled in
# seconds instead of compiled under QEMU emulation for minutes.
#
# This stage exists because the image used to copy in a host-built `bin/`
# artefact — a single binary produced once on the amd64 CI runner — for EVERY
# platform, so the published linux/arm64 image shipped an amd64 binary and died
# with `exec format error` on real ARM64 hardware.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-${DEBIAN_CODENAME} AS gobuild

# Supplied by BuildKit for the platform currently being built.
ARG TARGETOS
ARG TARGETARCH

# Build metadata. Defaults mirror the source defaults in cmd/reconftw/main.go
# (Version="dev", CommitSHA="unknown", BuildDate="unknown") so an un-stamped
# local build behaves like `go build`, not like a build with empty fields.
ARG VERSION=dev
ARG COMMIT_SHA=unknown
ARG BUILD_DATE=unknown

WORKDIR /src

# Modules first, in their own layer: source edits then do not invalidate the
# (large) module download cache.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# Only what ./cmd/reconftw actually needs. `go list -deps ./cmd/reconftw`
# resolves exclusively into cmd/ and internal/, and every //go:embed target
# (internal/core/backend/tools.lock, internal/mcp/openapi.json,
# internal/store/sqlc/schema.sql) lives under internal/.
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# CGO_ENABLED=0 is required for a cross-compile without a target C toolchain,
# and is safe here: the only SQLite driver in the tree is modernc.org/sqlite,
# which is pure Go.
#
# The -ldflags and -trimpath below MUST stay identical to the Makefile `build`
# target (Makefile:78-81) or `reconftw version` reports different values
# depending on how the binary was produced.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.CommitSHA=${COMMIT_SHA} -X main.BuildDate=${BUILD_DATE}" \
    -trimpath -o /out/reconftw ./cmd/reconftw

##################################################
### Builder — full toolchain + `reconftw install`
##################################################
FROM golang:${GO_VERSION}-${DEBIAN_CODENAME} AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    GOPATH=/opt/go \
    UV_TOOL_DIR=/opt/uv/tools \
    UV_TOOL_BIN_DIR=/opt/uv/bin \
    PATH=/opt/go/bin:/opt/uv/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin

# Build-time system deps for compiling/installing the tool zoo.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip curl git build-essential libpcap-dev libssl-dev \
    cmake ruby nmap whois jq exiftool ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv (Python tool manager) from the official image — avoids the network
# bootstrap path (and its placeholder SHA pin) during the build.
#
# Pinned by DIGEST, not by :latest. A floating tag means two builds of the same
# commit can ship different uv binaries, and it hands whoever controls that tag
# an unreviewed write into the image — the same supply-chain exposure the
# checksum pins elsewhere in this repo exist to prevent.
#
# To move it: docker buildx imagetools inspect ghcr.io/astral-sh/uv:<version>
COPY --from=ghcr.io/astral-sh/uv@sha256:2d890623d310b57771ce840f0da5eed5fc6d657da05ffaa45d82797b53fa3abc /uv /usr/local/bin/uv

# The v2 binary built by the gobuild stage FOR THIS PLATFORM. Because builder
# is not pinned to $BUILDPLATFORM, an arm64 image runs this stage emulated —
# and this binary is a real arm64 binary, so `reconftw install` below actually
# executes instead of failing with `exec format error`.
COPY --from=gobuild /out/reconftw /usr/local/bin/reconftw

# RUST DECISION (F5): Rust/Cargo is deliberately NOT installed here, so the one
# kind=rust tool in tools.lock — `smugglex` (HTTP request smuggling, VULN-07) —
# is EXCLUDED from this image via `--without rust`.
#
# Why excluded rather than installed:
#   1. installer.bootstrapRust verifies rustup-init against rustupInitSHA256,
#      which is still a 64-zero fail-closed placeholder (bootstrap.go:44) — that
#      path aborts by design and F15/plan 15-08 owns fixing it.
#   2. The alternative, Debian bookworm's `cargo` (1.63, 2022), then makes
#      `cargo install smugglex` compile a crate from source INSIDE the builder —
#      under QEMU for the arm64 image, on an old toolchain.
# Leaving Rust absent while still asking the installer for rust tools is the one
# option that is NOT acceptable: the build would silently log a failed optional
# tool and the image would claim to ship a scanner it does not have.
#
# This exclusion is observable at runtime, which is the condition for taking it:
# `reconftw health-check` enumerates the FULL embedded registry (backend.Default,
# unfiltered by --without), so smugglex shows up as
#   [WARN] tool.smugglex (required)
# plus a `missing: ... smugglex ...` summary line. smugglex is critical=false, so
# health-check still exits 0 and the container HEALTHCHECK stays green — the tool
# is reported absent rather than presumed present.
#
# Install every other tool from tools.lock. Non-interactive (no TTY) for the
# build context. Go + uv are already present, so the installer's bootstrap steps
# short-circuit and never hit the (fail-closed) placeholder SHA pins.
RUN --mount=type=cache,target=/opt/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/uv \
    reconftw install --non-interactive --without rust

##################################################
### Final — slim runtime, non-root, setcap
##################################################
FROM debian:${DEBIAN_CODENAME}-slim AS final

ENV GOPATH=/opt/go \
    UV_TOOL_BIN_DIR=/opt/uv/bin \
    PATH=/opt/go/bin:/opt/uv/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin

# Runtime deps only. libcap2-bin provides `setcap` (D-08) and MUST be in the
# FINAL stage; python3 + libpcap0.8 support the Python + capture-based tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 libpcap0.8 ca-certificates curl git nmap whois jq exiftool libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Bring over the Go SDK (some tools shell out to `go`), installed tool trees,
# and the reconftw binary. ALL COPY --from=builder lines MUST precede the
# setcap RUNs below — Docker COPY strips the security.capability xattr, so a
# capability granted in the builder would be silently lost (RESEARCH Pitfall 1).
COPY --from=builder /usr/local/go /usr/local/go
COPY --from=builder /opt/go /opt/go
COPY --from=builder /opt/uv /opt/uv
COPY --from=builder /usr/local/bin/uv /usr/local/bin/uv
COPY --from=builder /usr/local/bin/reconftw /usr/local/bin/reconftw

# CRITICAL (D-08): grant raw-socket capability to naabu + nmap AFTER the last
# COPY, in the final stage. `|| true` keeps the build resilient if a tool is
# absent on a given arch; runtimes that filter file caps need `--cap-add=NET_RAW`.
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap 2>/dev/null || true
RUN setcap cap_net_raw,cap_net_admin+eip /opt/go/bin/naabu 2>/dev/null || true

# Non-root user (DOCK-07). /workspace is its home + working dir, pre-created and
# owned at build time so nothing needs root at runtime. /opt is world-rX so the
# tools remain executable for the non-root user.
RUN groupadd -r reconftw \
    && useradd -r -g reconftw -d /workspace -s /bin/bash reconftw \
    && mkdir -p /workspace \
    && chown -R reconftw:reconftw /workspace \
    && chmod -R a+rX /opt/go /opt/uv

COPY Docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /workspace
USER reconftw

HEALTHCHECK --interval=60s --timeout=30s --retries=3 \
    CMD /usr/local/bin/reconftw health-check || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--help"]
