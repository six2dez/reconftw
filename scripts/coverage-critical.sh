#!/usr/bin/env bash
# Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 5 (W20);
#         extended in .planning/phases/14-cutover-and-migration/14-03-PLAN.md
#         Task 1 to cover ALL FOUR XCUT-03 SPEC critical paths;
#         rewritten in .planning/phases/15-.../15-07-PLAN.md Task 1 (F16) to be
#         statement-weighted and capable of failing.
#
# Per-file >=90% coverage gate for the XCUT-03 critical paths:
#   1. Scheduler        — internal/core/scheduler/*.go
#   2. Scope filter     — internal/core/output/{scope,filter}.go
#   3. Checkpoint       — internal/core/checkpoint/*.go
#   4. Secret redaction — internal/core/log/{redactor,redacting_handler,secret}.go
#
# This script is the SINGLE SOURCE OF TRUTH for the gate. .github/workflows/ci.yml
# invokes `make coverage-critical`; it does NOT carry its own copy of the file
# list, the package list, the threshold or the arithmetic. The two lists had
# already drifted (CI enforced 5 files, this script 13) — deleting the duplicate
# is what removes the drift class, not re-synchronising it.
#
# ── XCUT-03 metric definition (branch == statement) ──────────────────────────
# Go has NO native branch coverage: `go test -cover` measures STATEMENT
# coverage, which is the ecosystem norm. This gate therefore satisfies
# XCUT-03's "branch coverage" requirement as Go STATEMENT coverage. No
# external branch-coverage dependency is added (verify: `go.mod` gains nothing
# for this gate) — the verifier compares like-for-like against statement %.
#
# ── Why the coverprofile is parsed directly (F16) ────────────────────────────
# The previous implementation ran `go tool cover -func` and took the UNWEIGHTED
# arithmetic mean of the per-function percentages. A one-line getter at 100% then
# offset a hundred-line security function at 10%, so the gate reported a number
# nobody could act on and, worse, PASSED files that were genuinely below the
# threshold. Measured on this tree at the time of the rewrite:
#
#   internal/core/output/atomic.go       naive 91.16%   weighted 83.95%
#   internal/core/checkpoint/store.go    naive 92.47%   weighted 89.74%
#   internal/core/scheduler/heartbeat.go naive 93.75%   weighted 88.00%
#
# All three passed a 90% gate while below it. Every non-header line of a
# coverprofile is `file.go:startLine.col,endLine.col numStmts count`, so the
# only honest per-file number is  100 * SUM(numStmts where count>0) / SUM(numStmts).
# That is what this script computes.
#
# The second half of the same bug was the empty-match fallback: when the awk
# filter matched no lines at all it emitted a perfect score, so a file with NO
# entries in the profile passed. Dropping a package from CRITICAL_PKGS, or moving
# code out of a listed file, therefore turned the gate green. Zero measured
# statements is now a FAILURE (see the ZERO-STATEMENTS POLICY below).
#
# ── Offline / resolvers exclusion ────────────────────────────────────────────
# The coverage profile is generated ONLY from the packages that OWN the
# critical files (log, output, checkpoint, scheduler). internal/core/resolvers
# is deliberately EXCLUDED: its tests hang on hosts that block outbound UDP/53
# (MASS-DNS), so a `./internal/core/...` profile would make this gate
# un-runnable offline. resolvers holds no critical-path file; the lib-wide gate
# (scripts/coverage-lib.sh) documents the resolvers measurement caveat.
#
# ── ZERO-STATEMENTS POLICY ───────────────────────────────────────────────────
# A listed file with no statements in the profile is resolved as follows:
#   * file absent from disk            -> skip (deliberate: files are added to
#                                        the list as plans land; the header has
#                                        documented this since Phase 3).
#   * file present, its PACKAGE has no
#     blocks in the profile at all     -> FAIL (the package is not being
#                                        measured — the exact false green F16
#                                        describes).
#   * file present, package measured,
#     file declares no `func`          -> skip, reported as declaration-only.
#                                        internal/core/checkpoint/interface.go
#                                        is the real instance: an interface and
#                                        a compile-time assertion, zero
#                                        executable statements by construction.
#   * file present, package measured,
#     file declares `func`s            -> FAIL (code that should have been
#                                        measured was not).
#
# ── Environment ──────────────────────────────────────────────────────────────
#   GATE                       threshold percentage           (default 90.0)
#   REFRESH_COVERAGE           1 = regenerate the profile      (default 1)
#                              0 = use CRITICAL_COVERAGE_PROFILE as-is; the
#                                  profile MUST already exist (a missing one is
#                                  a hard error, never a silent `go test`).
#   CRITICAL_COVERAGE_PROFILE  coverprofile path              (default coverage.out)
#
# `bash scripts/coverage-critical.sh --list-files` prints CRITICAL_FILES, one per
# line, and exits. scripts/coverage_critical_test.sh consumes that instead of
# keeping its own copy — same anti-duplication rule the CI workflow now follows.
set -euo pipefail

# Force C locale so the percentage arithmetic uses '.' as the decimal separator
# regardless of the host LC_NUMERIC (a comma would truncate every comparison).
export LC_ALL=C

GATE="${GATE:-90.0}"
PROFILE="${CRITICAL_COVERAGE_PROFILE:-coverage.out}"

CRITICAL_FILES=(
    # Secret redaction (log)
    "internal/core/log/redactor.go"
    "internal/core/log/redacting_handler.go"
    "internal/core/log/secret.go"
    # Scope filter + atomic writer (output)
    "internal/core/output/atomic.go"
    "internal/core/output/scope.go"
    # filter.go is the aggregator side of the scope contract: it decides which
    # records reach an artefact. It was missing from BOTH the local and the CI
    # list until 15-07 — an untested branch here either leaks out-of-scope
    # findings or silently discards in-scope ones, and both have already shipped
    # in this repo. internal/core/output is already in CRITICAL_PKGS, so adding
    # it costs no extra package (and no network dependency).
    "internal/core/output/filter.go"
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

# Machine-readable file list for scripts/coverage_critical_test.sh.
if [ "${1:-}" = "--list-files" ]; then
    printf '%s\n' "${CRITICAL_FILES[@]}"
    exit 0
fi

if [ "${REFRESH_COVERAGE:-1}" = "1" ]; then
    go test -race -coverprofile="$PROFILE" -covermode=atomic "${CRITICAL_PKGS[@]}" >/dev/null
elif [ ! -f "$PROFILE" ]; then
    echo "::error::REFRESH_COVERAGE=0 but coverage profile '$PROFILE' does not exist."
    echo "  Refusing to fall back to 'go test': a gate that silently changes what it"
    echo "  measured is how the previous implementation produced false greens."
    exit 2
fi

# Coverprofile paths are import paths (module prefix + relative path). Read the
# module path straight out of go.mod rather than shelling out to `go list -m`,
# so --list-files and the parsing below stay usable without a Go toolchain.
MODULE=$(awk '$1 == "module" { print $2; exit }' go.mod)

CRITICAL_FILES_LIST=$(printf '%s\n' "${CRITICAL_FILES[@]}")
export CRITICAL_FILES_LIST

# One pass over the profile. Emits, per critical file:
#   <file> <TAB> <coveredStatements> <TAB> <totalStatements> <TAB> <blocksInItsPackage>
# The package-block count is what lets the caller tell "this package was never
# measured" (a real failure) from "this file has no executable code" (fine).
#
# Matching is on the EXACT path, split at the last ':' — not awk's `$1 ~ f`
# regex containment, which would let checkpoint/store.go absorb the blocks of a
# hypothetical checkpoint/store_extra.go and inflate its score.
read_profile() {
    awk -v module="$MODULE" '
    function dirof(p,   i) {
        for (i = length(p); i > 0; i--) {
            if (substr(p, i, 1) == "/") return substr(p, 1, i - 1)
        }
        return "."
    }
    BEGIN {
        nf = split(ENVIRON["CRITICAL_FILES_LIST"], wf, "\n")
        for (i = 1; i <= nf; i++) {
            if (wf[i] == "") continue
            want[wf[i]] = 1
            covered[wf[i]] = 0
            total[wf[i]] = 0
            pkgof[wf[i]] = dirof(wf[i])
        }
        prefix = module "/"
        plen = length(prefix)
    }
    /^mode:/ { next }
    NF < 3 { next }
    {
        spec = $1
        colon = 0
        for (j = length(spec); j > 0; j--) {
            if (substr(spec, j, 1) == ":") { colon = j; break }
        }
        if (colon == 0) next
        path = substr(spec, 1, colon - 1)
        if (plen > 1 && substr(path, 1, plen) == prefix) path = substr(path, plen + 1)

        pkgblocks[dirof(path)]++

        if (path in want) {
            total[path] += $2
            if ($3 + 0 > 0) covered[path] += $2
        }
    }
    END {
        for (i = 1; i <= nf; i++) {
            f = wf[i]
            if (f == "") continue
            printf "%s\t%d\t%d\t%d\n", f, covered[f], total[f], pkgblocks[pkgof[f]] + 0
        }
    }
    ' "$PROFILE"
}

FAIL=0
while IFS=$'\t' read -r f cov tot pkgblocks; do
    [ -n "$f" ] || continue

    if [ ! -f "$f" ]; then
        echo "skip (file absent): $f"
        continue
    fi

    if [ "$tot" -eq 0 ]; then
        if [ "$pkgblocks" -gt 0 ] && ! grep -qE '^func ' "$f"; then
            echo "skip (declaration-only, no executable statements): $f"
            continue
        fi
        if [ "$pkgblocks" -eq 0 ]; then
            echo "::error::FAIL: $f has zero measured statements and its package"
            echo "  contributed NO blocks to $PROFILE — is $(dirname "$f") covered by CRITICAL_PKGS?"
        else
            echo "::error::FAIL: $f has zero measured statements although its package was"
            echo "  measured — its functions moved, were renamed, or are excluded from the build."
        fi
        FAIL=1
        continue
    fi

    PCT=$(awk -v c="$cov" -v t="$tot" 'BEGIN { printf "%.2f", 100 * c / t }')
    printf '%s: %s%% (%s/%s statements)\n' "$f" "$PCT" "$cov" "$tot"
    if ! awk -v pct="$PCT" -v gate="$GATE" 'BEGIN { exit (pct + 0 < gate ? 1 : 0) }'; then
        echo "  XCUT-03 FAIL: $f below ${GATE}% gate"
        FAIL=1
    fi
done < <(read_profile)

if [ "$FAIL" -ne 0 ]; then
    echo "::error::one or more critical files failed the XCUT-03 >=${GATE}% coverage gate"
    echo "  These are statement-weighted figures read straight from $PROFILE."
    echo "  Do NOT lower GATE to make this pass — add tests for the uncovered statements."
    exit 1
fi
echo "OK: all critical files at or above ${GATE}% (statement-weighted)"
