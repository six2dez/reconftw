#!/usr/bin/env bash
# Run reconFTW tests by scope.
# Requires: bats-core (https://github.com/bats-core/bats-core)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BATS="${BATS:-bats}"
MODE="${1:---unit}"

usage() {
    cat <<EOF
Usage: $0 [--unit|--smoke|--integration|--all]
  --unit         Run only unit tests
  --smoke        Run integration smoke subset
  --integration  Run full integration suite
  --all          Run unit + full integration suites
EOF
}

if ! command -v "$BATS" >/dev/null 2>&1; then
    echo "bats-core not found. Install: https://github.com/bats-core/bats-core"
    echo "  brew install bats-core  (macOS)"
    echo "  apt install bats        (Debian/Ubuntu)"
    exit 1
fi

if [[ -z "${BATS_SHELL:-}" ]]; then
    for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash /bin/bash; do
        if [[ -x "$candidate" ]]; then
            major="$("$candidate" -lc 'echo "${BASH_VERSINFO[0]}"' 2>/dev/null || echo 0)"
            if [[ "$major" =~ ^[0-9]+$ ]] && [[ "$major" -ge 4 ]]; then
                export BATS_SHELL="$candidate"
                break
            fi
        fi
    done
fi

run_unit() {
    echo "Running unit tests..."
    "$BATS" "$SCRIPT_DIR"/unit/*.bats
}

run_smoke() {
    echo "Running integration smoke tests..."
    "$BATS" \
        "$SCRIPT_DIR"/integration/test_smoke.bats \
        "$SCRIPT_DIR"/integration/test_report_only.bats \
        "$SCRIPT_DIR"/integration/test_export_cli.bats \
        "$SCRIPT_DIR"/integration/test_monitor_mode.bats
}

run_integration() {
    echo "Running full integration tests..."
    "$BATS" "$SCRIPT_DIR"/integration/*.bats
}

case "$MODE" in
    --unit)
        run_unit
        ;;
    --smoke)
        run_smoke
        ;;
    --integration)
        run_integration
        ;;
    --all)
        run_unit
        run_integration
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        echo "Unknown option: $MODE"
        usage
        exit 2
        ;;
esac

echo "Tests passed for mode: $MODE"
