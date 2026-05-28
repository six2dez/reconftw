#!/usr/bin/env bash
# Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 5 (W20).
#
# Local per-file ≥90% coverage gate for the XCUT-03 critical paths.
# Run via `make coverage-critical`. Mirrors the CI yaml step exactly so
# a local pre-commit run catches regressions before push.
#
# Files added incrementally as plans land. A file that does not yet
# exist (a future-plan critical path) is skipped silently — the gate
# only enforces what is already on disk.
set -euo pipefail

GATE="${GATE:-90.0}"

CRITICAL_FILES=(
    "internal/core/log/redactor.go"
    "internal/core/log/redacting_handler.go"
    "internal/core/output/atomic.go"
    "internal/core/output/scope.go"
    "internal/core/checkpoint/store.go"
)

# Refresh coverage profile from the kernel package set.
if [ ! -f coverage.out ] || [ "${REFRESH_COVERAGE:-1}" = "1" ]; then
    go test -race -coverprofile=coverage.out -covermode=atomic ./internal/core/... >/dev/null
fi

FAIL=0
for f in "${CRITICAL_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "skip (file absent): $f"
        continue
    fi
    PCT=$(go tool cover -func=coverage.out \
        | awk -v f="$f" '$1 ~ f { gsub("%","",$NF); sum+=$NF; n++ } END { if (n>0) printf "%.2f", sum/n; else print "100" }')
    echo "$f: ${PCT}%"
    if ! awk -v pct="$PCT" -v gate="$GATE" 'BEGIN { exit (pct+0 < gate ? 1 : 0) }'; then
        echo "  XCUT-03 FAIL: $f below ${GATE}% gate"
        FAIL=1
    fi
done

if [ "$FAIL" -ne 0 ]; then
    echo "::error::one or more critical files failed the XCUT-03 ≥${GATE}% coverage gate"
    exit 1
fi
echo "OK: all critical files at or above ${GATE}%"
