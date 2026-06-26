# reconFTW v2 Docker image

Multi-stage image shipping the v2 Go binary plus all 95+ orchestrated tools.
Published to `ghcr.io/six2dez/reconftw` (and Docker Hub `six2dez/reconftw`) for
`linux/amd64` and `linux/arm64`.

## Base image

The final stage is **`debian:bookworm-slim`** (chosen per decision D-07).

- **Distroless was rejected.** A distroless base has no shell, no Python
  runtime, and no package manager — which is incompatible with reconFTW's tool
  zoo: 23 Python (uv) tools, 6 system packages, and 2 repo-clone `python_venv`
  tools all need a real userland. DOCK-04 ("all 70+ tools in the image") makes
  distroless infeasible here, even though Go binaries alone would favor it.
- **Alpine/musl was rejected** for the *image base*: glibc-assuming Go/CGO tools
  and Python wheel compatibility cause real pain across a heterogeneous toolset.
  (A static musl **binary** is still produced for Alpine *hosts* via GoReleaser —
  that is separate from the container base.)
- The **builder** stage uses `golang:bookworm` so the Go SDK is present while
  `reconftw install` compiles `go install` tools.

## Capability grants (setcap)

`naabu` and `nmap` need raw sockets for SYN scanning. Rather than run the whole
container as root, the build grants just those two binaries
`cap_net_raw,cap_net_admin+eip` via `setcap` in the **final** stage, *after* all
`COPY --from=builder` instructions (Docker `COPY` strips the `security.capability`
xattr, so granting earlier would silently lose the capability).

Some runtimes (rootless Docker, certain Kubernetes runtimes, gVisor) filter
file capabilities at container start. If raw-socket scanning fails, add the
capability at run time:

```bash
docker run --rm --cap-add=NET_RAW ghcr.io/six2dez/reconftw:latest subs --target example.com
```

## Non-root operation

The image runs as the unprivileged user **`reconftw`** (DOCK-07). Its home and
working directory is `/workspace` (pre-created and owned at build time). Tools
live under `/opt/go` and `/opt/uv` (world-readable/executable) so the non-root
user can run them — they are deliberately **not** under `/root` (mode `0700`).

Mount your output directory to `/workspace`:

```bash
docker run --rm -v "$PWD/recon:/workspace" ghcr.io/six2dez/reconftw:latest all --target example.com
```

## Multi-arch build

The binary is built first (`make build` → `bin/reconftw`), then baked in. Build
from the **repo root** (the Dockerfile copies `bin/reconftw` from the context):

```bash
make build
docker buildx build --platform linux/amd64,linux/arm64 \
  -f Docker/Dockerfile -t ghcr.io/six2dez/reconftw:latest .
```

CI does this in `.github/workflows/docker_nightly.yml` (nightly cron, release,
and `v*` tag push), tagging each image with semver + `latest` + the git SHA.

## Image size

The builder stage is large (~3–4 GB — Go SDK + every tool's build deps), but it
is **not shipped**: the final stage copies only the installed binaries + slim
runtime deps. Measure the final image after a real build and update this line:

```bash
docker image ls ghcr.io/six2dez/reconftw:latest   # expect roughly 1–2 GB
```
