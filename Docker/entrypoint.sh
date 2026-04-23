#!/bin/bash
# Generate Axiom SSH keys at runtime if they don't exist
if [[ "${INSTALL_AXIOM}" == "true" ]] && [[ ! -f /root/.ssh/axiom_rsa ]]; then
    mkdir -p /root/.ssh /root/.axiom/configs
    ssh-keygen -b 4096 -t rsa -f /root/.ssh/axiom_rsa -q -N ""
    cat /root/.ssh/axiom_rsa.pub > /root/.axiom/configs/authorized_keys
fi

# Accept GitHub tokens at runtime instead of baking them into the image.
# Supported inputs:
#   GITHUB_TOKENS="ghp_aaaa\nghp_bbbb"   (literal newline-separated tokens)
#   GITHUB_TOKENS=/path/to/file          (path to a file inside the container)
# Writes them to the location reconftw.cfg expects (${tools}/.github_tokens).
if [[ -n "${GITHUB_TOKENS:-}" ]]; then
    mkdir -p /root/Tools
    target=/root/Tools/.github_tokens
    if [[ -f "$GITHUB_TOKENS" ]]; then
        cp -f -- "$GITHUB_TOKENS" "$target"
    else
        printf '%b\n' "$GITHUB_TOKENS" > "$target"
    fi
    chmod 600 "$target"
fi

exec ./reconftw.sh "$@"
