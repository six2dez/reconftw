#!/usr/bin/env bash
# Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 5 (W20);
#         extended in .planning/phases/14-cutover-and-migration/14-03-PLAN.md
#         Task 1 to cover ALL FOUR XCUT-03 SPEC critical paths.
#
# Local per-file ≥90% coverage gate for the XCUT-03 critical paths:
#   1. Scheduler        — internal/core/scheduler/*.go
#   2. Scope filter     — internal/core/output/scope.go
#   3. Checkpoint       — internal/core/checkpoint/*.go
#   4. Secret redaction — internal/core/log/{redactor,redacting_handler,secret}.go
# Run via `make coverage-critical`. Mirrors the CI yaml step exactly so a
# local pre-commit run catches regressions before push.
#
# ── XCUT-03 metric definition (branch == statement) ──────────────────────────
# Go has NO native branch coverage: `go test -cover` measures STATEMENT
# coverage, which is the ecosystem norm. This gate therefore satisfies
# XCUT-03's "branch coverage" requirement as Go STATEMENT coverage. No
# external branch-coverage dependency is added (verify: `go.mod` gains nothing
# for this gate) — the verifier compares like-for-like against statement %.
#
# ── Offline / resolvers exclusion ────────────────────────────────────────────
# The coverage profile is generated ONLY from the packages that OWN the
# critical files (log, output, checkpoint, scheduler). internal/core/resolvers
# is deliberately EXCLUDED: its tests hang on hosts that block outbound UDP/53
# (MASS-DNS), so a `./internal/core/...` profile would make this gate
# un-runnable offline. resolvers holds no critical-path file; the lib-wide gate
# (scripts/coverage-lib.sh) documents the resolvers measurement caveat.
#
# Files added incrementally as plans land. A file that does not yet exist
# (a future-plan critical path) is skipped silently — the gate only enforces
# what is already on disk.
set -euo pipefail

GATE="${GATE:-90.0}"

CRITICAL_FILES=(
    # Secret redaction (log)
    "internal/core/log/redactor.go"
    "internal/core/log/redacting_handler.go"
    "internal/core/log/secret.go"
    # Scope filter + atomic writer (output)
    "internal/core/output/atomic.go"
    "internal/core/output/scope.go"
    # Checkpoint store (ALL checkpoint/*.go, not just store.go)
    "internal/core/checkpoint/store.go"
    "internal/core/checkpoint/hash.go"
    "internal/core/checkpoint/migrations.go"
    "internal/core/checkpoint/interface.go"
    # Scheduler (the whole package — previously MISSING from the gate)
    "internal/core/scheduler/scheduler.go"
    "internal/core/scheduler/heartbeat.go"
    "internal/core/scheduler/policy.go"
)

# Packages that own the critical files. resolvers is EXCLUDED by construction
# (see header) so the profile builds + runs offline without the UDP/53 hang.
CRITICAL_PKGS=(
    "./internal/core/log/..."
    "./internal/core/output/..."
    "./internal/core/checkpoint/..."
    "./internal/core/scheduler/..."
)

# Refresh coverage profile from the critical-path package set.
if [ ! -f coverage.out ] || [ "${REFRESH_COVERAGE:-1}" = "1" ]; then
    go test -race -coverprofile=coverage.out -covermode=atomic "${CRITICAL_PKGS[@]}" >/dev/null
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
