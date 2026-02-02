#!/bin/bash
# Run all reconFTW tests
# Requires: bats-core (https://github.com/bats-core/bats-core)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BATS="${BATS:-bats}"

if ! command -v "$BATS" >/dev/null 2>&1; then
    echo "bats-core not found. Install: https://github.com/bats-core/bats-core"
    echo "  brew install bats-core  (macOS)"
    echo "  apt install bats        (Debian/Ubuntu)"
    exit 1
fi

echo "Running unit tests..."
"$BATS" "$SCRIPT_DIR"/unit/*.bats

if [[ "${1:-}" == "--all" ]]; then
    echo "Running integration tests..."
    "$BATS" "$SCRIPT_DIR"/integration/*.bats
fi

echo "All tests passed."
