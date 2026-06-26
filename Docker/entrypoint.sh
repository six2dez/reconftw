#!/bin/bash
# reconFTW v2 container entrypoint (Phase 11, DOCK-07 — non-root).
#
# Runs as the unprivileged `reconftw` user; /workspace is its home + working
# dir (pre-created and owned at build time), so nothing here needs root.
set -euo pipefail

HOME_DIR="${HOME:-/workspace}"

# Accept GitHub tokens at runtime instead of baking them into the image.
# Supported inputs:
#   GITHUB_TOKENS="ghp_aaaa\nghp_bbbb"   (literal newline-separated tokens)
#   GITHUB_TOKENS=/path/to/file          (path to a file inside the container)
if [[ -n "${GITHUB_TOKENS:-}" ]]; then
    target="${HOME_DIR}/.github_tokens"
    if [[ -f "${GITHUB_TOKENS}" ]]; then
        cp -f -- "${GITHUB_TOKENS}" "${target}"
    else
        printf '%b\n' "${GITHUB_TOKENS}" >"${target}"
    fi
    chmod 600 "${target}"
fi

# Hand off to the v2 binary (on PATH at /usr/local/bin/reconftw). CMD ["--help"]
# supplies the default arguments when none are given.
exec reconftw "$@"
