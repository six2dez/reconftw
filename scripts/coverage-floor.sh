#!/usr/bin/env bash
# coverage-floor.sh — aggregate statement-coverage FLOOR per package set, driven
# by a ratchet file. Run via `make coverage-floor`; wired into the CI
# `integration` job and into `make ci`.
#
# WHY A THIRD COVERAGE GATE. coverage-critical.sh gates 13 kernel files at 90%
# and coverage-lib.sh gates internal/core/... at 75%. Neither looks at
# internal/modules/... (every tool wrapper, parser and arg vector — the code
# that shipped the puredns `-rt` defect) or internal/store/... (the sqlc layer
# the report, monitor and SARIF paths read). Those two trees carried 52.9% and
# 26.6% with NOTHING asserting they stay there, so a change that deleted half
# their tests would have been green. This gate is the floor under that.
#
# WHY A RATCHET FILE, NOT A CONSTANT. The floors live in
# scripts/coverage-floor.ratchet, one line per package set, so raising one is a
# one-line diff that reviewers can see, and lowering one is a diff that has to
# justify itself. The script itself holds no number.
#
# WHY -short, A TIMEOUT AND A -skip. internal/modules/subdomains contains
# TestGenResolversCallsDnsvalidator, which launches the REAL dnsvalidator when
# it is on PATH and runs until the 600s timeout kills the whole package (project
# memory: "go test -race no pasa en caja aprovisionada"). It is skipped BY NAME
# here so the gate reports the same number on a provisioned box and on a CI
# runner. -short keeps the long-running variants out for the same reason. The
# floors were measured under exactly these flags; measure the same way when
# raising them.
#
# Environment:
#   COVERAGE_FLOOR_RATCHET   ratchet file            (default scripts/coverage-floor.ratchet)
#   COVERAGE_FLOOR_PROFILE_DIR  where profiles land  (default a mktemp dir, removed)
#   COVERAGE_FLOOR_SKIP      -skip pattern           (default TestGenResolversCallsDnsvalidator)
#   COVERAGE_FLOOR_TIMEOUT   go test -timeout        (default 600s)
#
# Modes:
#   --list       print the ratchet's (floor, packages) lines and exit 0
#   --measure    print the measured aggregate per line, no gate (for raising
#                the ratchet)
set -euo pipefail
export LC_ALL=C

cd "$(dirname "${BASH_SOURCE[0]}")/.."

RATCHET="${COVERAGE_FLOOR_RATCHET:-scripts/coverage-floor.ratchet}"
SKIP="${COVERAGE_FLOOR_SKIP:-TestGenResolversCallsDnsvalidator}"
TIMEOUT="${COVERAGE_FLOOR_TIMEOUT:-600s}"
MODE="gate"
for arg in "$@"; do
    case "$arg" in
        --list) MODE="list" ;;
        --measure) MODE="measure" ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "coverage-floor: unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

if [ ! -f "$RATCHET" ]; then
    echo "::error::coverage-floor: ratchet file $RATCHET not found — a gate with no floor is not a gate"
    exit 2
fi

# Parse the ratchet: skip blank/comment lines; first field is the floor, the
# rest are package patterns. An unparseable line is a hard error, never a skip.
FLOORS=()
PKGSETS=()
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    case "$line" in
        '' | '#'*) continue ;;
    esac
    # shellcheck disable=SC2086 # intentional word-split of the ratchet line
    set -- $line
    floor="$1"
    shift
    if ! printf '%s' "$floor" | grep -Eq '^[0-9]+(\.[0-9]+)?$' || [ "$#" -eq 0 ]; then
        echo "::error::coverage-floor: $RATCHET:$lineno is not '<floor-pct> <package>...': $line"
        exit 2
    fi
    FLOORS+=("$floor")
    PKGSETS+=("$*")
done <"$RATCHET"

if [ "${#FLOORS[@]}" -eq 0 ]; then
    echo "::error::coverage-floor: $RATCHET declares no floors — the gate would pass vacuously"
    exit 2
fi

if [ "$MODE" = "list" ]; then
    for i in "${!FLOORS[@]}"; do
        echo "${FLOORS[$i]} ${PKGSETS[$i]}"
    done
    exit 0
fi

if ! command -v go >/dev/null 2>&1; then
    echo "::error::coverage-floor: 'go' not on PATH"
    exit 2
fi

OWN_DIR=0
if [ -n "${COVERAGE_FLOOR_PROFILE_DIR:-}" ]; then
    PROFILE_DIR="$COVERAGE_FLOOR_PROFILE_DIR"
    mkdir -p "$PROFILE_DIR"
else
    PROFILE_DIR="$(mktemp -d)"
    OWN_DIR=1
fi
cleanup() { [ "$OWN_DIR" -eq 1 ] && rm -rf "$PROFILE_DIR"; }
trap cleanup EXIT

echo "coverage-floor: ratchet $RATCHET (-short -timeout $TIMEOUT -skip '$SKIP')"

failed=0
for i in "${!FLOORS[@]}"; do
    floor="${FLOORS[$i]}"
    pkgs="${PKGSETS[$i]}"
    profile="$PROFILE_DIR/floor-$i.out"

    # shellcheck disable=SC2086 # package patterns are deliberately split
    if ! go test -short -count=1 -timeout "$TIMEOUT" -skip "$SKIP" \
        -covermode=atomic -coverprofile="$profile" $pkgs >"$profile.log" 2>&1; then
        echo "::error::coverage-floor: go test failed for [$pkgs] — a failing suite has no coverage to assert"
        tail -n 30 "$profile.log"
        failed=1
        continue
    fi

    # The profile must exist AND carry blocks. An empty profile parses to a
    # total of nothing, and "nothing" compared to a floor must not read as 0%
    # or as 100% — it is the measurement failing, which is an error here.
    if [ ! -s "$profile" ] || [ "$(grep -vc '^mode:' "$profile" || true)" -eq 0 ]; then
        echo "::error::coverage-floor: no coverage blocks were recorded for [$pkgs] — nothing was measured"
        failed=1
        continue
    fi

    pct="$(go tool cover -func="$profile" | awk '/^total:/ { gsub("%", "", $NF); print $NF }')"
    if [ -z "$pct" ]; then
        echo "::error::coverage-floor: could not read a total from $profile"
        failed=1
        continue
    fi

    if [ "$MODE" = "measure" ]; then
        printf '  %-28s measured %6s%%   (ratchet floor %s%%)\n' "$pkgs" "$pct" "$floor"
        continue
    fi

    if awk -v pct="$pct" -v floor="$floor" 'BEGIN { exit (pct + 0 < floor + 0 ? 1 : 0) }'; then
        printf '  OK    %-28s %6s%%  >= floor %s%%\n' "$pkgs" "$pct" "$floor"
    else
        printf '  FAIL  %-28s %6s%%  <  floor %s%%\n' "$pkgs" "$pct" "$floor"
        echo "::error::coverage-floor: [$pkgs] aggregate ${pct}% is below the ${floor}% floor in $RATCHET. Add tests, or lower the floor in a commit that says why."
        failed=1
    fi
done

if [ "$MODE" = "measure" ]; then
    exit 0
fi
if [ "$failed" -ne 0 ]; then
    exit 1
fi
echo "coverage-floor: every package set is at or above its ratchet floor"
