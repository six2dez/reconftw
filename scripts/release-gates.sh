#!/usr/bin/env bash
#
# release-gates.sh — phase 15 plan 17. ONE command that runs the twelve
# acceptance gates plus the regression guard, and fails when any of them fails.
#
# Source: .planning/phases/15-release-gates-run-isolation-store-integrity/
#         15-CONTEXT.md ("Acceptance gates — the definition of done" and
#         "Regression guard — checks that already pass and must stay green").
#
# These twelve gates are the precondition for the Phase 14 cutover — the point
# at which the shipping bash implementation is replaced by the Go one. Before
# this script existed, sign-off was a prose checklist: a claim, not a
# reproducible result. Everything below is an executed command with an asserted
# outcome.
#
# ─────────────────────────────────────────────────────────────────────────────
# THE FALSE-GREEN COUNTERMEASURE
#
# `go test -run <pattern>` exits 0 when its pattern matches NOTHING and prints
# `[no tests to run]`. This repo shipped a CI gate running
# `-run TestKernelDemoEndToEnd` against a test deleted in Phase 4; the job was
# green for months while executing zero tests. Every gate invocation below
# therefore COUNTS `--- PASS` lines and fails when the count is zero. A gate
# that cannot fail is worse than no gate, because it manufactures confidence.
#
# ─────────────────────────────────────────────────────────────────────────────
# THE TWO CI-BREAK CLASSES `go test ./...` CANNOT CATCH (project memory)
#
#  1. A clean PATH. `health-check` exits 1 BY DESIGN when tools are absent, so
#     running it under a developer's populated PATH proves nothing about a
#     user's machine. See gate_clean_path_healthcheck below for why the
#     assertion is on OUTPUT and not on the exit code.
#  2. Per-package coverage. `make coverage-critical` measures a specific file
#     set with statement weighting and can fail while `go test ./...` is green.
#
# ─────────────────────────────────────────────────────────────────────────────
# WHY EVERY STEP RUNS EVEN AFTER ONE FAILS
#
# The script does NOT abort on the first failing step. It records each outcome
# and exits non-zero at the end if any step FAILED. Aborting early would leave
# most of the thirteen gate rows unreported, and a sign-off document listing
# "gate 4: FAIL, gates 5-12: unknown" is not evidence of anything. `--fail-fast`
# restores stop-on-first-failure for a tight local loop.
#
# Usage:
#   bash scripts/release-gates.sh [--with-docker] [--fail-fast] [--gates-only]
#
#   --with-docker  also run acceptance gate 11 (ARM64 `docker run`). OFF by
#                  default so the script runs on a machine without Docker/QEMU.
#                  When absent, gate 11 is reported SKIPPED WITH ITS REASON —
#                  never PASS, never omitted.
#   --fail-fast    stop at the first failing step.
#   --gates-only   skip the regression guard and run only the gate assertions.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WITH_DOCKER=0
FAIL_FAST=0
GATES_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --with-docker) WITH_DOCKER=1 ;;
        --fail-fast) FAIL_FAST=1 ;;
        --gates-only) GATES_ONLY=1 ;;
        -h | --help)
            sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "release-gates: unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

# ─── result recording ───────────────────────────────────────────────────────
#
# Parallel arrays rather than an associative array: ordered output matters more
# than lookup, and bash 3.2 (macOS system bash) has no `declare -A`.
STEP_NAMES=()
STEP_STATUS=()
STEP_NOTES=()
FAILED=0

LOGDIR="$(mktemp -d "${TMPDIR:-/tmp}/reconftw-release-gates.XXXXXX")"
trap 'rm -rf "$LOGDIR"' EXIT

record() {
    STEP_NAMES+=("$1")
    STEP_STATUS+=("$2")
    STEP_NOTES+=("${3:-}")
    if [ "$2" = "FAIL" ]; then
        FAILED=1
        if [ "$FAIL_FAST" = "1" ]; then
            summary
            echo "release-gates: --fail-fast, stopping at first failure." >&2
            exit 1
        fi
    fi
}

banner() { printf '\n\033[1m── %s\033[0m\n' "$1"; }

# run_step <name> <command...>
#
# Runs a command, captures its output, and records PASS/FAIL. The exit status is
# captured with `|| rc=$?` rather than being read after the fact: under
# `set -e`, a command inside an `if` condition has its errexit SUPPRESSED, and
# this project has already shipped a CI gate that was permanently green for
# exactly that reason.
run_step() {
    local name="$1"
    shift
    local log
    log="$LOGDIR/$(echo "$name" | tr -c 'A-Za-z0-9' '_').log"
    banner "$name"
    local rc=0
    "$@" >"$log" 2>&1 || rc=$?
    tail -n 20 "$log" || true
    if [ "$rc" -eq 0 ]; then
        record "$name" PASS
    else
        record "$name" FAIL "exit $rc — full log: $log"
    fi
}

# run_step_expect_empty_stdout <name> <command...>
#
# For gofumpt -l, whose contract is "prints nothing when clean" and which exits
# 0 either way.
run_step_expect_empty_stdout() {
    local name="$1"
    shift
    local log
    log="$LOGDIR/$(echo "$name" | tr -c 'A-Za-z0-9' '_').log"
    banner "$name"
    local rc=0
    "$@" >"$log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        cat "$log"
        record "$name" FAIL "exit $rc"
        return
    fi
    if [ -s "$log" ]; then
        cat "$log"
        record "$name" FAIL "produced output when it must produce none — see $log"
        return
    fi
    record "$name" PASS
}

# require_tool <binary> <step-name> — records SKIPPED and returns 1 when absent.
#
# A missing tool is reported SKIPPED, never PASS. It does not set FAILED,
# because "govulncheck is not installed on this laptop" is a different fact from
# "govulncheck found a reachable vulnerability" and conflating them destroys the
# value of the summary. The SKIPPED count is printed separately so a sign-off
# reader can see the run was not complete.
require_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    fi
    record "$2" SKIPPED "$1 is not installed on this machine"
    return 1
}

# ─── the gate assertions ────────────────────────────────────────────────────
#
# gate <label> <-run pattern> <package...>
#
# Runs the named tests verbosely, then COUNTS `--- PASS` lines. Zero matches is
# a FAILURE with an explicit "no tests ran" message. This is the direct
# countermeasure to T-15-17-01 and is demonstrated, not assumed: renaming a
# cited test so the pattern matches nothing must fail this script.
gate() {
    local label="$1" pattern="$2"
    shift 2
    local log
    log="$LOGDIR/$(echo "$label" | tr -c 'A-Za-z0-9' '_').log"
    banner "$label"
    local rc=0
    go test -count=1 -run "$pattern" -v "$@" >"$log" 2>&1 || rc=$?

    local passes
    passes="$(grep -c -- '--- PASS' "$log" || true)"
    local fails
    fails="$(grep -c -- '--- FAIL' "$log" || true)"

    echo "  pattern : $pattern"
    echo "  packages: $*"
    echo "  --- PASS: $passes    --- FAIL: $fails    go exit: $rc"

    if [ "$passes" -eq 0 ]; then
        grep -n 'no tests to run' "$log" || tail -n 20 "$log" || true
        record "$label" FAIL \
            "NO TESTS RAN. \`go test -run\` exits 0 on a pattern that matches nothing; the cited test was renamed, moved or deleted. Log: $log"
        return
    fi
    if [ "$rc" -ne 0 ] || [ "$fails" -ne 0 ]; then
        grep -n -- '--- FAIL' "$log" | head -n 20 || true
        record "$label" FAIL "$fails failing test(s), go exit $rc — full log: $log"
        return
    fi
    record "$label" PASS "$passes test(s)/subtest(s) passed"
}

# ─── the clean-PATH health-check (CI-break class 1) ─────────────────────────
#
# THE ASSERTION, stated explicitly because getting it wrong in either direction
# produces a useless gate:
#
#   `health-check` EXITS 1 BY DESIGN when critical tools are absent, which is
#   the normal state of a clean checkout. Treating exit 1 as failure makes this
#   step permanently red; ignoring the result entirely makes it permanently
#   green even if the subcommand were reduced to a no-op. So the exit code is
#   NOT asserted, and the OUTPUT is: it must name at least one missing tool by
#   name, and it must not panic or print a Go stack trace.
gate_clean_path_healthcheck() {
    local label="CI-break class 1: clean-PATH health-check"
    banner "$label"
    local log="$LOGDIR/clean_path_healthcheck.log"
    local bindir="$LOGDIR/bin"
    mkdir -p "$bindir"

    if ! go build -o "$bindir/reconftw" ./cmd/reconftw >"$log" 2>&1; then
        cat "$log"
        record "$label" FAIL "could not build the binary"
        return
    fi

    # PATH reduced to the system defaults ONLY — nothing from $GOPATH/bin,
    # /usr/local/bin or a Homebrew prefix. Not emptied: the binary still needs a
    # working system, and an empty PATH would test "cannot exec anything".
    local out
    out="$(cd "$LOGDIR" && PATH=/usr/bin:/bin:/usr/sbin:/sbin "$bindir/reconftw" health-check 2>&1 || true)"
    printf '%s\n' "$out" >"$log"
    printf '%s\n' "$out" | tail -n 5

    if printf '%s' "$out" | grep -q 'panic:'; then
        record "$label" FAIL "health-check PANICKED on a machine with no tools installed"
        return
    fi
    if ! printf '%s' "$out" | grep -q 'missing'; then
        record "$label" FAIL \
            "health-check reported nothing as missing under a reduced PATH — either the tool probe stopped running or the reduced PATH did not take effect"
        return
    fi
    if ! printf '%s' "$out" | grep -Eq 'subfinder|httpx|dnsx'; then
        record "$label" FAIL "health-check did not NAME a missing tool — an operator cannot act on it"
        return
    fi
    record "$label" PASS "named missing tools; exit code deliberately not asserted (exits 1 by design)"
}

# ─── acceptance gate 11 (WORKFLOW-OWNED) ────────────────────────────────────
#
# Gate 11 is the ONE gate with no Go test behind it. Its owner is
# .github/workflows/docker_nightly.yml, job `docker`, step
# `Verify image health (linux/arm64)` — shipped by plan 15-06. The `--with-docker`
# path below mirrors that step locally.
#
# When the flag is absent the summary says SKIPPED WITH ITS REASON. It is never
# PASS and never silently omitted: signing off eleven gates with one unrun must
# be visible as such (T-15-17-02).
gate11_docker_arm64() {
    local label="Gate 11: docker run --platform linux/arm64 reconftw version"

    if [ "$WITH_DOCKER" != "1" ]; then
        record "$label" SKIPPED \
            "docker: --with-docker not passed. Enforced in CI by .github/workflows/docker_nightly.yml job \`docker\`, step \`Verify image health (linux/arm64)\`."
        return
    fi

    banner "$label"
    if ! command -v docker >/dev/null 2>&1; then
        record "$label" SKIPPED "docker: the docker CLI is not installed"
        return
    fi
    if ! docker info >/dev/null 2>&1; then
        record "$label" SKIPPED "docker: the CLI is present but the daemon is not reachable"
        return
    fi

    local log="$LOGDIR/gate11_docker.log"
    local rc=0
    docker buildx build --platform linux/arm64 -f Docker/Dockerfile \
        -t reconftw:arm64-gate --load . >"$log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        tail -n 30 "$log"
        record "$label" FAIL "buildx build failed (exit $rc) — full log: $log"
        return
    fi

    local out
    out="$(docker run --rm --platform linux/arm64 reconftw:arm64-gate version 2>&1)" || rc=$?
    printf '%s\n' "$out"
    if [ "$rc" -ne 0 ]; then
        record "$label" FAIL "docker run exited $rc (an image carrying the wrong architecture fails here with 'exec format error' — which is the point)"
        return
    fi
    if ! printf '%s' "$out" | grep -Eq '^reconftw version [^[:space:]]+$'; then
        record "$label" FAIL "the arm64 image did not print a version string"
        return
    fi
    if ! printf '%s' "$out" | grep -Eq '^[[:space:]]*platform:[[:space:]]+linux/arm64$'; then
        record "$label" FAIL "the image printed a platform other than linux/arm64 — runtime.GOARCH is fixed at COMPILE time, so this is the ARM64 binary check"
        return
    fi
    record "$label" PASS "arm64 image printed a version and platform: linux/arm64"
}

# ─── summary ────────────────────────────────────────────────────────────────
summary() {
    local pass=0 fail=0 skip=0 i
    printf '\n\033[1m═══ release gates summary ═══\033[0m\n\n'
    for i in "${!STEP_NAMES[@]}"; do
        case "${STEP_STATUS[$i]}" in
            PASS) pass=$((pass + 1)) ;;
            FAIL) fail=$((fail + 1)) ;;
            SKIPPED) skip=$((skip + 1)) ;;
        esac
        printf '  [%-7s] %s\n' "${STEP_STATUS[$i]}" "${STEP_NAMES[$i]}"
        if [ -n "${STEP_NOTES[$i]}" ]; then
            printf '            %s\n' "${STEP_NOTES[$i]}"
        fi
    done
    printf '\n  %d PASS, %d FAIL, %d SKIPPED\n\n' "$pass" "$fail" "$skip"
    if [ "$skip" -gt 0 ]; then
        echo "  NOTE: a SKIPPED step was NOT executed. It is not a pass."
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
# 1. REGRESSION GUARD — the eight commands 15-CONTEXT.md lists as already-green
#    and required to stay green.
# ═════════════════════════════════════════════════════════════════════════════

if [ "$GATES_ONLY" != "1" ]; then
    run_step "guard: go build ./..." go build ./...
    run_step "guard: go vet ./..." go vet ./...
    run_step "guard: go mod verify" go mod verify
    run_step "guard: go test -race -count=1 ./..." go test -race -count=1 ./...

    if require_tool govulncheck "guard: govulncheck ./..."; then
        run_step "guard: govulncheck ./..." govulncheck ./...
    fi
    if require_tool gofumpt "guard: gofumpt -l . (must print nothing)"; then
        run_step_expect_empty_stdout "guard: gofumpt -l . (must print nothing)" gofumpt -l .
    fi

    run_step "guard: git diff --check" git diff --check
    run_step "guard: make integration-smoke" make integration-smoke

    # ═════════════════════════════════════════════════════════════════════════
    # 2. THE TWO CI-BREAK CLASSES `go test ./...` CANNOT CATCH
    # ═════════════════════════════════════════════════════════════════════════

    # The self-test runs FIRST — verify the coverage gate can still fail, then
    # let it judge. Same order as .github/workflows/ci.yml.
    run_step "CI-break class 2: make coverage-critical-selftest" make coverage-critical-selftest
    run_step "CI-break class 2: make coverage-critical" env REFRESH_COVERAGE=1 make coverage-critical

    gate_clean_path_healthcheck
fi

# ═════════════════════════════════════════════════════════════════════════════
# 3. THE TWELVE TEST-OWNED ACCEPTANCE GATES
#
#    One named `go test -run` invocation per row of the thirteen-row gate table
#    in 15-17-SUMMARY.md. Each asserts `--- PASS` > 0, so a renamed or deleted
#    test fails the script instead of silently passing.
#
#    Gate 3 has TWO rows (artefact clause and report clause) and gate 11 is the
#    workflow-owned row, which is why twelve gates produce thirteen rows and
#    twelve `go test` invocations.
# ═════════════════════════════════════════════════════════════════════════════

# Gate 1 — "Dry-run leaves filesystem and DB byte-for-byte unchanged."
# Two levels in one invocation: the six MCP handlers (package) and the real
# binary (process). Documented as a shared invocation per the plan: they are one
# gate CLAUSE, asserted at two levels, not two rows.
gate "Gate 1: dry-run mutates nothing" \
    'TestDryRunHandlersCreateNothing|TestDryRunTakesNoWorkspaceLock|TestE2EBinaryDryRunHasNoSideEffects|TestE2EBinaryDryRunWithoutOutputFlagCreatesNothing' \
    ./internal/mcp/handlers/ ./cmd/reconftw/

# Gate 2 — "/24, /16 and a bare IP get different workspaces."
# Identity layer + workspace layer + the assembled binary.
gate "Gate 2: /24, /16 and a bare IP get distinct workspaces" \
    'TestCanonicalTargetIDDistinctPrefixes|TestWorkspaceInitDistinctPrefixes|TestReleaseGate2DistinctWorkspacesThroughTheBinary' \
    ./internal/core/output/ ./cmd/reconftw/

# Gate 3, ARTEFACT clause — "an empty run B produces an empty artefact".
#
# SIX artefact classes, closed by THREE different mechanisms. Citing one
# `findings` test for all six would be a FAIL of this gate, not a pass:
#   findings + waf     -> the MERGE           (TestMergeStage*EmptyRunPublishesEmptyArtefact,
#                                              TestGate3WebProducerToMergedFindings)
#   subdomains         -> MergeAllSubdomains  (TestGate3SubdomainsProducerToMergedArtefact)
#   hosts/fuzz/origins/urls -> their own direct producer, because the merge is
#                        BARRED from truncating them (directArtefactWriterStages)
#                                             (Test*ArtefactEmptied*)
#
# KNOWN LIMITATION, verbatim from plan 15-13's SUMMARY — this gate is NOT fully
# green:
#
#   Gate 3 is NOT fully green on `hosts`. In a subs-only or passive run
#   web.httpx never runs, so a previous run's artefacts/hosts.jsonl survives
#   even though subdomains.geo ran and found nothing. The empty publish is
#   deliberately assigned to httpx alone: giving it to geo instead would erase
#   web hosts that no producer in that run examined, which is strictly worse.
#   This is a real staleness window on the subs-only path and must be reported
#   as such rather than folded into a green gate-3 row.
gate "Gate 3a: empty run publishes an EMPTY artefact (all six classes, three mechanisms)" \
    'TestGate3WebProducerToMergedFindings|TestGate3SubdomainsProducerToMergedArtefact|TestMergeStageFindingsEmptyRunPublishesEmptyArtefact|TestMergeStageWafEmptyRunPublishesEmptyArtefact|TestHostsArtefactEmptiedByHTTPXOverGeoRecords|TestFuzzArtefactEmptiedWhenProducerFindsNothing|TestOriginsArtefactEmptiedWhenProducerFindsNothing|TestUrlsArtefactEmptiedOnAllThreeProducerPaths|TestDirectArtefactWriterStagesComplete' \
    ./internal/modules/web/ ./internal/modules/subdomains/

# Gate 3, REPORT clause — "…and an empty report". Owned by plan 15-11 Task 3;
# cited here, NOT re-implemented. It drives artefact -> ingest ->
# artefact-emptied -> ingest -> render and asserts against the parsed file.
gate "Gate 3b: empty run renders an EMPTY report" \
    'TestGate3EmptyRunRendersEmptyReport|TestRenderAll_ScanWithNoObservationsRendersEmptyReport' \
    ./internal/core/report/

# Gate 4 — "Two simultaneous runs on the same target are isolated, or the second
# is rejected." Three levels: the cross-PROCESS flock primitive, the real
# handlers with a FORCED overlap, and the assembled binary.
gate "Gate 4: concurrent runs on one target are rejected; different targets are not serialised" \
    'TestLockCrossProcessContention|TestConcurrentRunsOnOneTargetRejectSecond|TestConcurrentRunsOnDifferentTargetsBothProceed|TestWorkspaceLockReleasedAfterFailedRun|TestE2EBinaryRejectsRunOnALockedWorkspace' \
    ./internal/core/output/ ./internal/mcp/handlers/ ./cmd/reconftw/

# Gate 5 — "A tool exiting with code 7 fails the task, and no partial or stale
# output is ingested." The backend contract, the closed ratchet that proves
# every call site consumes it, and the per-module exit-7 tests.
gate "Gate 5: a tool exiting 7 fails its task and no stale output is ingested" \
    'TestLocalBackend_Stream_NonZeroExit_SurfacesTerminalError|TestLocalBackend_Stream_NonZeroExit_DrainAgrees|TestStreamContract$|TestStreamContractRatchetIsClosed|ExitSevenErrors' \
    ./internal/core/backend/ ./internal/modules/ ./internal/modules/web/ \
    ./internal/modules/subdomains/ ./internal/modules/vulns/ ./internal/modules/osint/

# Gate 6 — "The first MCP report call works, explicit config is honoured, and
# shutdown cancels scans." Three clauses, three named owners (15-15).
gate "Gate 6: first MCP report works, explicit config honoured, shutdown cancels scans" \
    'TestFirstReportCallOnAPreRegisteredSessionSucceeds|TestScanToolCreatesTheWorkspaceUnderTheStartupDataDir|TestReportToolHonoursTheStartupDataDir|TestShutdownCancelsInFlightScans|TestStartLinksItsContextToInFlightScans' \
    ./internal/mcp/

# Gate 7 — "An injected failure during ingest leaves no completed scan and no
# partial data."
gate "Gate 7: an injected ingest failure leaves no completed scan and no partial data" \
    'TestScanIntoStoreInjectedFailureLeavesNoCompletedScanAndNoPartialData|TestScanIntoStoreTerminalStates|TestScanIntoStoreCountersCountCommittedRowsNotInputLines' \
    ./internal/core/ingest/

# Gate 8 — "A finding present on two targets keeps independent triage and
# lifecycle."
gate "Gate 8: a finding on two targets keeps independent triage and lifecycle" \
    'TestFindingIdentityIsTargetScoped|TestUpsertFindingConflictMatchesDedupIndex' \
    ./internal/store/sqlc/

# Gate 9 — "A report contains exclusively the requested scan's observations."
gate "Gate 9: a report contains only the requested scan's observations" \
    'TestRenderAll_Gate9_ScanWithZeroURLsRendersZeroURLs|TestRenderAll_Gate9_ScanAStillRendersItsURLs|TestE2EReportDoesNotLeakAnotherTarget|TestE2EReportOfSecondScanExcludesVanishedAsset' \
    ./internal/core/report/

# Gate 10 — "Restarting monitor preserves baseline, suppression and generation."
# One test, three assertions, across two separate RunMonitorAsync invocations
# over one on-disk state.db — a real state boundary, not two passes over one
# in-memory run.
gate "Gate 10: restarting monitor preserves baseline, suppression and generation" \
    'TestMonitorRestartPreservesBaselineSuppressionAndGeneration|TestMonitorTwoCyclesDoNotSelfDeadlock' \
    ./internal/mcp/handlers/

# Gate 11 — WORKFLOW-OWNED. Not a `go test` invocation.
gate11_docker_arm64

# Gate 12 — "A clean checkout builds and runs the full suite." The build half is
# the guard's `go build ./...` above; the RUN half is here.
gate "Gate 12: a clean checkout builds and runs (version, --help, clean-PATH health-check)" \
    'TestReleaseGate12CleanTreeBuildsAndRuns|TestE2EBinaryVersionAndConfig|TestE2EBinaryHealthCheckIsSelfConsistent' \
    ./cmd/reconftw/

# ═════════════════════════════════════════════════════════════════════════════

summary

if [ "$FAILED" -ne 0 ]; then
    echo "release-gates: FAILED — the Phase 14 cutover is not signed off." >&2
    exit 1
fi
echo "release-gates: all executed steps passed. Read the SKIPPED list above before signing off."
