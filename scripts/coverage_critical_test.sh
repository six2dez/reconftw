#!/usr/bin/env bash
# Source: .planning/phases/15-release-gates-run-isolation-store-integrity/15-07-PLAN.md
#         Task 1 (F16).
#
# Self-test for scripts/coverage-critical.sh. Run via `make coverage-critical-selftest`.
#
# A gate that cannot fail is worse than no gate: it manufactures confidence.
# scripts/coverage-critical.sh spent its whole life unable to fail for two
# independent reasons (unweighted per-function averaging, and `print "100"` on an
# empty measurement), and nothing noticed because nobody ever fed it an input it
# was supposed to reject. This script feeds it exactly those inputs.
#
# Three cases, each asserting the gate's EXIT STATUS, not just its output:
#
#   1. FALSE-GREEN CASE — a synthetic profile on which the OLD `sum/n` logic
#      scores ABOVE the gate and the new statement-weighted logic scores BELOW.
#      Both numbers are computed and printed. The old number is produced by
#      running the literal old pipeline (`go tool cover -func` + the exact awk
#      one-liner that was deleted), not by re-describing it, so the claim
#      "this input used to pass" is checked rather than asserted.
#   2. ZERO-STATEMENTS CASE — a profile with no entry for a listed file that
#      exists on disk. The old logic printed a perfect 100 here; the new gate
#      must fail with an actionable message.
#   3. HEALTHY CASE — a fully covered profile. The gate must exit 0, otherwise
#      cases 1 and 2 prove nothing (a gate that always fails is also useless).
#
# No `go test` is run: the profiles are synthesised, and `REFRESH_COVERAGE=0`
# plus CRITICAL_COVERAGE_PROFILE point the gate at them. The real coverage.out
# is never read or written.
set -euo pipefail
export LC_ALL=C

cd "$(dirname "${BASH_SOURCE[0]}")/.."

GATE_SCRIPT="scripts/coverage-critical.sh"
SELFTEST_GATE="90.0"

if ! command -v go >/dev/null 2>&1; then
    # Case 1 compares against the real `go tool cover -func` output. Skipping it
    # would leave a self-test that only ever proves the easy half, so refuse
    # loudly instead of reporting a partial pass.
    echo "::error::coverage_critical_test: 'go' not on PATH — cannot verify the old-vs-new comparison"
    exit 2
fi

MODULE=$(awk '$1 == "module" { print $2; exit }' go.mod)
if [ -z "$MODULE" ]; then
    echo "::error::coverage_critical_test: could not read the module path from go.mod"
    exit 2
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ── Critical file list: read from the gate itself ────────────────────────────
# Never a second copy. A hand-maintained duplicate here would reintroduce, in
# the test, the very divergence this plan removed from CI.
CRITICAL_FILES=()
while IFS= read -r line; do
    [ -n "$line" ] || continue
    CRITICAL_FILES+=("$line")
done < <(bash "$GATE_SCRIPT" --list-files)

if [ "${#CRITICAL_FILES[@]}" -eq 0 ]; then
    echo "::error::coverage_critical_test: $GATE_SCRIPT --list-files produced nothing"
    exit 2
fi

# ── Helpers ──────────────────────────────────────────────────────────────────

# func_lines FILE — the 1-based line number of every top-level func declaration.
# `go tool cover -func` attributes a coverage block to the function whose AST
# span contains the block's START line, and a func's declaration line is always
# inside its own span, so emitting blocks at these lines is enough to control
# each function's reported percentage exactly.
func_lines() {
    grep -nE '^func ' "$1" | cut -d: -f1
}

# emit_full_block FILE — one fully-covered 1-statement block per top-level func.
# A file with no func declarations emits nothing, which is the truth: it has no
# executable statements.
emit_full_block() {
    local file="$1" line
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        printf '%s/%s:%s.1,%s.9 1 1\n' "$MODULE" "$file" "$line" "$line"
    done < <(func_lines "$file")
}

# synth_profile OUT [SKIP_FILE] — a profile in which every critical file present
# on disk is at 100%, except SKIP_FILE which is omitted entirely.
synth_profile() {
    local out="$1" skip="${2:-}" f
    : >"$out"
    printf 'mode: atomic\n' >>"$out"
    for f in "${CRITICAL_FILES[@]}"; do
        [ -f "$f" ] || continue
        [ "$f" = "$skip" ] && continue
        emit_full_block "$f" >>"$out"
    done
}

# naive_old_pct PROFILE FILE — the DELETED implementation, verbatim:
#   go tool cover -func | awk '$1 ~ f { sum += pct; n++ } END { sum/n or 100 }'
# Kept here as the control. If this ever stops reproducing the old numbers the
# comparison below is meaningless, so it must stay byte-faithful.
naive_old_pct() {
    go tool cover -func="$1" \
        | awk -v f="$2" '$1 ~ f { gsub("%","",$NF); sum+=$NF; n++ } END { if (n>0) printf "%.2f", sum/n; else print "100" }'
}

# run_gate PROFILE -> exit status of the gate, output captured in GATE_OUTPUT.
GATE_OUTPUT=""
run_gate() {
    local profile="$1" status=0
    GATE_OUTPUT=$(REFRESH_COVERAGE=0 CRITICAL_COVERAGE_PROFILE="$profile" GATE="$SELFTEST_GATE" \
        bash "$GATE_SCRIPT" 2>&1) || status=$?
    return "$status"
}

above_gate() {
    awk -v pct="$1" -v gate="$SELFTEST_GATE" 'BEGIN { exit (pct + 0 >= gate ? 0 : 1) }'
}

fail() {
    echo "::error::$*"
    echo "--- gate output ---"
    echo "$GATE_OUTPUT"
    echo "-------------------"
    exit 1
}

# ── Pick the subject file: first critical file with >=2 top-level funcs ──────
# Two functions are enough to build the false green (see case 1), and choosing
# dynamically keeps the test working when the file list changes.
SUBJECT=""
for f in "${CRITICAL_FILES[@]}"; do
    [ -f "$f" ] || continue
    if [ "$(func_lines "$f" | wc -l | tr -d ' ')" -ge 2 ]; then
        SUBJECT="$f"
        break
    fi
done
if [ -z "$SUBJECT" ]; then
    echo "::error::coverage_critical_test: no critical file with >=2 top-level funcs to build the false-green case"
    exit 2
fi

echo "coverage-critical self-test"
echo "  gate:    ${SELFTEST_GATE}%"
echo "  subject: $SUBJECT"
echo

# =============================================================================
# Case 3 first: the healthy baseline. If a fully covered profile does not pass,
# the two failure cases below cannot be attributed to what they claim.
# =============================================================================
HEALTHY="$WORK/healthy.out"
synth_profile "$HEALTHY"
if ! run_gate "$HEALTHY"; then
    fail "case HEALTHY: the gate rejected a fully covered profile (expected exit 0)"
fi
echo "PASS  case HEALTHY: fully covered profile -> gate exits 0"

# =============================================================================
# Case 1: the false green. SUBJECT gets two functions:
#   * every func except the last  -> 1 statement, covered      -> 100%
#   * the last func               -> 85 of 100 statements covered -> 85%
# Unweighted per-function mean is therefore >=92.5% (PASSES a 90% gate) while
# the statement-weighted figure is ~85% (FAILS it). That 85% is deliberate: the
# textbook "1 covered + 99 uncovered" example yields a naive 50%, which the old
# logic would also have rejected and so proves nothing about the false green.
# =============================================================================
BIG_LINE=$(func_lines "$SUBJECT" | tail -1)
FALSE_GREEN="$WORK/false-green.out"
synth_profile "$FALSE_GREEN" "$SUBJECT"
{
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        [ "$line" = "$BIG_LINE" ] && continue
        printf '%s/%s:%s.1,%s.9 1 1\n' "$MODULE" "$SUBJECT" "$line" "$line"
    done < <(func_lines "$SUBJECT")
    printf '%s/%s:%s.1,%s.9 85 1\n' "$MODULE" "$SUBJECT" "$BIG_LINE" "$BIG_LINE"
    printf '%s/%s:%s.10,%s.19 15 0\n' "$MODULE" "$SUBJECT" "$BIG_LINE" "$BIG_LINE"
} >>"$FALSE_GREEN"

NAIVE=$(naive_old_pct "$FALSE_GREEN" "$SUBJECT")
WEIGHTED=$(awk -v m="$MODULE/$SUBJECT:" '
    index($1, m) == 1 { t += $2; if ($3 + 0 > 0) c += $2 }
    END { if (t > 0) printf "%.2f", 100 * c / t; else print "0.00" }' "$FALSE_GREEN")

echo "  false-green profile: old naive sum/n = ${NAIVE}%   new statement-weighted = ${WEIGHTED}%"

if ! above_gate "$NAIVE"; then
    fail "case FALSE-GREEN: the old naive computation scored ${NAIVE}%, which is NOT above the ${SELFTEST_GATE}% gate — this input would not have been a false green, so it proves nothing"
fi
if above_gate "$WEIGHTED"; then
    fail "case FALSE-GREEN: the statement-weighted figure ${WEIGHTED}% is above the gate — the synthetic profile is not actually under-covered"
fi
if run_gate "$FALSE_GREEN"; then
    fail "case FALSE-GREEN: the gate PASSED a profile at ${WEIGHTED}% weighted coverage (old logic scored it ${NAIVE}%) — it is still not statement-weighted"
fi
case "$GATE_OUTPUT" in
    *"$SUBJECT"*) ;;
    *) fail "case FALSE-GREEN: the gate failed but never named $SUBJECT" ;;
esac
echo "PASS  case FALSE-GREEN: old logic ${NAIVE}% (would PASS) vs new ${WEIGHTED}% (gate exits non-zero)"

# =============================================================================
# Case 2: zero measured statements. SUBJECT exists on disk and declares funcs,
# but has no entry in the profile — code moved, a file was renamed, or a package
# fell out of CRITICAL_PKGS. The old logic's `else print "100"` scored this a
# perfect 100 and passed.
# =============================================================================
EMPTY="$WORK/zero-statements.out"
synth_profile "$EMPTY" "$SUBJECT"

NAIVE_EMPTY=$(naive_old_pct "$EMPTY" "$SUBJECT")
if ! above_gate "$NAIVE_EMPTY"; then
    fail "case ZERO-STATEMENTS: the old logic scored ${NAIVE_EMPTY}% on a profile with no entry for $SUBJECT — expected the 100 it used to print"
fi
if run_gate "$EMPTY"; then
    fail "case ZERO-STATEMENTS: the gate PASSED a profile containing no measurement at all for $SUBJECT (old logic scored it ${NAIVE_EMPTY}%)"
fi
case "$GATE_OUTPUT" in
    *"zero measured statements"*) ;;
    *) fail "case ZERO-STATEMENTS: the gate failed but not with the actionable zero-statements message" ;;
esac
echo "PASS  case ZERO-STATEMENTS: old logic ${NAIVE_EMPTY}% (would PASS) vs new gate exits non-zero"

echo
echo "OK: coverage-critical.sh fails on both inputs the old implementation passed."
