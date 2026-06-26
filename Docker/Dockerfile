# syntax=docker/dockerfile:1.4
#
# reconFTW v2 — multi-stage image (Phase 11, DOCK-01..07).
#
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
# Build (multi-arch) from the REPO ROOT (context = ., so `bin/reconftw` is
# available — build it first with `make build`):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f Docker/Dockerfile -t ghcr.io/six2dez/reconftw:latest .

ARG GO_VERSION=1.25.0
ARG DEBIAN_CODENAME=bookworm

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
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# The pre-built v2 binary (built by `make build` before `docker build`); the
# image therefore ships exactly the tagged binary rather than a Docker rebuild.
COPY bin/reconftw /usr/local/bin/reconftw

# Install every tool from tools.lock. Non-interactive (no TTY) for the build
# context. Go + uv are already present, so the installer's bootstrap steps
# short-circuit and never hit the (fail-closed) placeholder SHA pins.
RUN --mount=type=cache,target=/opt/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/uv \
    reconftw install --non-interactive

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
