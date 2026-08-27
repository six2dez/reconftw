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
# therefore asserts on `--- PASS` lines. A gate that cannot fail is worse than
# no gate, because it manufactures confidence.
#
# WHY COUNTING WAS NOT ENOUGH (phase 17, TC-D)
#
# The first version of that countermeasure COUNTED `--- PASS` lines and failed
# only when the count was zero. That answers "did anything run"; it does not
# answer "did the cited things run". A gate citing nine tests passed with eight
# of them deleted — the same false green one order of magnitude smaller, inside
# the very mechanism built to stop it. The rule is now BY NAME: every test the
# `-run` pattern cites must produce its own `--- PASS`, and the FAIL note lists
# the ones that did not, because an operator needs to know WHICH cited test
# vanished rather than that a count came up short. See gate_verdict below for
# the exact classification of exact-name versus substring citations. The idiom
# is the one `make realtools-args` already proved; do not re-derive the weaker
# counting version.
#
# WHY A FAILING RUN KEEPS ITS LOGS
#
# The EXIT trap used to be an unconditional `rm -rf "$LOGDIR"`, which deleted
# the directory every FAIL note points at (`full log: $LOGDIR/...`). The one
# artefact a failing run exists to produce was destroyed on the way out. The
# directory is now RETAINED when any step FAILED and removed when none did, and
# the path is printed in both cases. See cleanup_logdir.
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
CENSUS_VERDICT=0
CENSUS_RC=0
GATE_VERDICT=0
GATE_PATTERN=""
GATE_RC=0
NUCLEI_COV_VERDICT=0
NUCLEI_COV_WS=""

for arg in "$@"; do
    case "$arg" in
        --with-docker) WITH_DOCKER=1 ;;
        --fail-fast) FAIL_FAST=1 ;;
        --gates-only) GATES_ONLY=1 ;;
        --census-verdict) CENSUS_VERDICT=1 ;;
        # --gate-verdict <-run pattern> [go exit code]: read a `go test -v` log on
        # stdin and print this script's gate verdict for it. Exposed as a mode for
        # the same reason --census-verdict is — the gates themselves need the
        # 70-tool runtime and can never run in CI, but the RULE that decides them
        # is pure parsing and belongs in the suite that runs on every push.
        --gate-verdict) GATE_VERDICT=1 ;;
        # --nuclei-coverage-verdict <workspace>: print this script's nuclei
        # coverage verdict for a run's workspace. Exposed as a mode for the same
        # reason the two above are — judging a real workspace needs a real scan,
        # but the RULE that decides it is pure parsing and belongs in the suite
        # that runs on every push (cmd/reconftw/release_gates_test.go).
        --nuclei-coverage-verdict) NUCLEI_COV_VERDICT=1 ;;
        # A bare number is the run's exit code, for whichever verdict mode is active.
        [0-9] | [0-9][0-9] | [0-9][0-9][0-9])
            if [ "$CENSUS_VERDICT" = "1" ]; then
                CENSUS_RC="$arg"
            elif [ "$GATE_VERDICT" = "1" ]; then
                GATE_RC="$arg"
            else
                echo "release-gates: unknown argument: $arg" >&2
                exit 2
            fi
            ;;
        -h | --help)
            sed -n '/^# Usage:/,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            if [ "$GATE_VERDICT" = "1" ] && [ -z "$GATE_PATTERN" ]; then
                GATE_PATTERN="$arg"
            elif [ "$NUCLEI_COV_VERDICT" = "1" ] && [ -z "$NUCLEI_COV_WS" ]; then
                NUCLEI_COV_WS="$arg"
            else
                echo "release-gates: unknown argument: $arg" >&2
                exit 2
            fi
            ;;
    esac
done

# ─── the arg-vector census parser ───────────────────────────────────────────
#
# THIS IS THE SEAM THE RULE LIVES ON, and it is exposed as a mode
# (`--census-verdict`) so cmd/reconftw/release_gates_test.go can test it in CI,
# where the gate itself can never run. Reads the realtools output on stdin, takes
# the run's exit code as $1, and prints one line:
#
#	PASS <note>  |  FAIL <note>  |  SKIPPED <note>
#
# THE RULE THAT MATTERS: A PARTIAL RUN IS NOT A PASS. "37 PASS / 0 FAIL / 9
# SKIPPED" reads like success while nine tools were never probed at all. The
# gate therefore PASSES only when every census line reports mode=REFERENCE —
# which is the mode in which the Go-side ratchet
# (internal/core/backend/realtools_census_test.go) has asserted, in both
# directions, that the skipped set is EXACTLY the known-absent list. Any census
# line reporting NOT_EXECUTED means the box has no tool tree and the gate is
# SKIPPED, never passed; anything else, or a non-zero exit, is a FAIL.
# census_tools flattens every <field>_tools= list into one sorted, DEDUPED set.
# The realtools target prints the census twice — once echoing the captured
# output, once grepping it — so a naive join reports every tool twice and the
# gate's own summary becomes unreadable.
#
# 18-06: the field name is now a PARAMETER, because the census reports three of
# them. The grep is anchored on a leading space so a field name cannot match
# INSIDE A LONGER ONE — e.g. `tools=` matching `absent_tools=` and
# `unresolvable_tools=` alike, which would make the three states report
# identically and re-create the exact conflation this change removes.
#
# The anchor is right; its stated reason was not. It used to claim `absent_tools=`
# could match `unresolvable_tools=`, and `absent` is not a substring of
# `unresolvable`, so the example was impossible. Corrected rather than dropped:
# a guard justified by an impossible example is one nobody can check.
census_tools() {
    local field="$2"
    local flat
    flat="$(printf '%s\n' "$1" | grep -oE "(^| )${field}_tools=[^ ]*" | sed "s/.*${field}_tools=//" \
        | tr ',' '\n' | grep -v '^$' | grep -v '^(none)$' | LC_ALL=C sort -u | paste -sd' ' -)"
    echo "${flat:-(none)}"
}

# census_skipped_tools is the UNION — every tool whose arg vector this run did
# not verify, whatever the reason. Kept under its original name and meaning
# because that is what a sign-off reader needs first: how much was not checked.
census_skipped_tools() {
    census_tools "$1" skipped
}

# census_state_breakdown renders the two states SEPARATELY, with their different
# remedies named.
#
# WHY THIS MATTERS AND IS NOT COSMETIC. Until 18-02 the registry could not tell
# "not installed" from "installed but the declared entry point is missing", so
# every skip read as "install it". Eight tools carried an "observed absent"
# reason for months while their clones sat on disk. The reconbox3 figure of
# "29 tools absent" that pre-cutover checklist item #11 rests on inherits that
# conflation and CANNOT be read as 29 uninstalled tools.
#
# The union above is unchanged; this is additive.
census_state_breakdown() {
    local out="$1"
    local absent unresolvable
    absent="$(census_tools "$out" absent)"
    unresolvable="$(census_tools "$out" unresolvable)"
    if [ "$absent" = "(none)" ] && [ "$unresolvable" = "(none)" ]; then
        echo "nothing unavailable"
        return
    fi
    echo "NOT INSTALLED (install them): ${absent} | INSTALLED BUT UNRESOLVABLE (repair that one clone): ${unresolvable}"
}

argvector_census_verdict() {
    local rc="${1:-0}"
    local out
    out="$(cat)"

    local census
    census="$(printf '%s\n' "$out" | grep -c 'REALTOOLS_CENSUS test=' || true)"
    if [ "$census" -eq 0 ]; then
        echo "FAIL no REALTOOLS_CENSUS line was emitted — the run reported no skip census at all, so its coverage is unknown"
        return
    fi

    if printf '%s\n' "$out" | grep -q 'REALTOOLS_CENSUS .*mode=NOT_EXECUTED'; then
        local why
        why="$(printf '%s\n' "$out" | grep -m1 'REALTOOLS_CENSUS_REASON' | sed 's/.*REALTOOLS_CENSUS_REASON test=[^ ]* //')"
        echo "SKIPPED the tool tree is not installed on this box, so no arg vector was verified: ${why:-no reason recorded}"
        return
    fi

    local nonref
    nonref="$(printf '%s\n' "$out" | grep 'REALTOOLS_CENSUS test=' | grep -vc 'mode=REFERENCE' || true)"
    if [ "$nonref" -ne 0 ]; then
        echo "FAIL $nonref census line(s) did not run in REFERENCE mode, so the known-absent ratchet was NOT enforced — a partial run is not a pass"
        return
    fi

    if [ "$rc" -ne 0 ]; then
        echo "FAIL the arg-vector probes failed (exit $rc); unverified tools were: $(census_skipped_tools "$out") [$(census_state_breakdown "$out")]"
        return
    fi

    echo "PASS $census probe(s) ran in REFERENCE mode; unverified set matched the known-unavailable list exactly: $(census_skipped_tools "$out") [$(census_state_breakdown "$out")]"
}

if [ "$CENSUS_VERDICT" = "1" ]; then
    argvector_census_verdict "$CENSUS_RC"
    exit 0
fi

# ─── the nuclei coverage rule (plan 17-05, requirement TC-A) ────────────────
#
# WHY THIS GATE EXISTS. The 2026-08-24 parity verdict was signed BLOCKED because
# "nuclei ran and exited 0" was compatible with nuclei having executed 49
# templates or 13,000, and nothing in the workspace could tell those apart. The
# run's 49 distinct template IDs is a MATCH count, not an execution count, so it
# could not arbitrate. Every nuclei group now writes
# <workspace>/logs/nuclei-coverage.jsonl; this rule is what makes a silent
# regression in that number FAIL instead of scroll past.
#
# READ THE PROXY DECLARATION BEFORE READING THE NUMBERS. requests_sent is a
# PROXY for template execution, not a count of it — it bounds coverage at the
# AGGREGATE level only, and per-template execution is NOT bounded by a production
# record. The record says so in its own execution_basis field, and this gate
# FAILS a record that has dropped that declaration, because an undeclared proxy
# read as a count is the exact error that produced the 49-template misreading.
#
# ── THE THRESHOLD, AND WHERE THE NUMBER COMES FROM ─────────────────────────
#
# NUCLEI_COVERAGE_MIN_PCT is the minimum acceptable requests_sent/requests_planned
# ratio. A threshold with no derivation is a number someone later "adjusts" to
# turn a red gate green (T-17-05-02), so here is the derivation, from measured
# fixture runs recorded in
# .planning/phases/17-tool-contract-coverage-integrity/17-05-NUCLEI-COVERAGE.md:
#
#   HEALTHY FLOOR, measured. Probe arm F1 (`nuclei-coverage-probe.sh
#   --full-tree`): the full production vector, 10,683 templates loaded in
#   directory mode against one responsive loopback host, sent 18,481 of 18,715
#   planned requests = 98.75%. The small-template arms (A3, B1-B5, D1, D2) all
#   sent 3 of 3 = 100%.
#
#   COLLAPSED CASE, measured. Probe arms G1/G2 (`--cost --bound 420`): the same
#   vector against ONE blackholed host reached 778 of 18,715 = 4.2% before the
#   bound. That is what a coverage collapse actually looks like.
#
#   THE CHOICE. 50% sits 48.75 points below the measured healthy floor and 45.8
#   points above the measured collapse — deliberately far from BOTH, because a
#   threshold hugging the healthy floor turns ordinary partial failure into a red
#   gate and teaches readers to ignore it. At twelve hosts, 50% means half the
#   scan's whole request budget never went out, which is unambiguous.
#
# WHAT IS DELIBERATELY *NOT* GATED, and why. filter_selected vs templates_loaded
# is the other natural ratio, and it is NOT asserted here: the only measurement
# of it (13,143 selected -> 10,683 loaded) comes from a probe that passes -ni to
# avoid third-party OAST registration, so the gap it shows is the probe's, not
# production's. Gating on an unmeasured ratio would be inventing a threshold,
# which is the thing the paragraph above exists to prevent. The two numbers are
# REPORTED in the note instead, so the ratio becomes measurable on real runs and
# a future plan can derive a threshold from data.
NUCLEI_COVERAGE_MIN_PCT=50

# cov_field <json-line> <field> — the raw token for a field: a number, `null`, or
# EMPTY when the field is absent from the record entirely.
#
# The three are different facts and this gate treats them differently: a number
# is an observation, `null` is nuclei declining to report (which fails the gate,
# because a run that cannot say what it loaded has not accounted for itself), and
# EMPTY means the record shape changed under us. Reporting the last as 0 would
# reproduce this phase's entire defect class inside its own gate.
#
# ALWAYS EXITS 0. This script runs under `set -euo pipefail`, and grep exits 1
# when it matches nothing — so the obvious one-liner made an ABSENT field abort
# the whole function mid-loop, printing NO verdict at all and exiting 1. A
# checker that says nothing and returns non-zero is indistinguishable from a
# crash, and it was found only because the absent-field case was actually run
# rather than reasoned about. The `|| true` is load-bearing; do not remove it.
cov_field() {
    local raw
    raw="$(printf '%s' "$1" | grep -o "\"$2\":[^,}]*" | head -1 || true)"
    [ -n "$raw" ] || return 0
    # Strip the key, then the surrounding quotes of a string value, so `group`
    # reads `normal` rather than `"normal"` in the note a human has to act on.
    printf '%s' "$raw" | sed "s/^\"$2\"://; s/^\"//; s/\"$//"
}

# nuclei_coverage_verdict <workspace> — prints exactly one line:
#   PASS <note>  |  FAIL <note>  |  SKIPPED <note>
nuclei_coverage_verdict() {
    local ws="${1:-}"
    local cov="$ws/logs/nuclei-coverage.jsonl"
    local toollog="$ws/logs/tools.jsonl"

    if [ -z "$ws" ] || [ ! -d "$ws" ]; then
        echo "SKIPPED no workspace supplied — export RECONFTW_WORKSPACE=<workspace> to judge a real run; an unjudged run is never a pass"
        return
    fi

    if [ ! -f "$cov" ]; then
        # A run in which nuclei never ran at all is SKIPPED, not FAILED — there
        # is nothing to account for. A run in which nuclei DID run and wrote no
        # account is exactly the 2026-08-24 state and FAILS. tools.jsonl is what
        # tells them apart, so a missing tools.jsonl cannot be read either way.
        if [ ! -f "$toollog" ]; then
            echo "SKIPPED no coverage record and no tool log at \`$ws/logs/\` — whether nuclei ran at all is unknown, so this is not evidence of anything"
            return
        fi
        if grep -q '"tool":"nuclei"' "$toollog" 2>/dev/null; then
            echo "FAIL nuclei WAS invoked (it appears in $toollog) and wrote NO coverage record — the run cannot say how many templates it covered, which is the 2026-08-24 BLOCKED state exactly"
            return
        fi
        echo "SKIPPED nuclei was not invoked in this run, so there is no coverage to judge"
        return
    fi

    local n
    n="$(grep -c . "$cov" 2>/dev/null || true)"
    if [ "${n:-0}" -eq 0 ]; then
        echo "FAIL the coverage record at \`$cov\` is EMPTY — a present-but-empty record is not an account"
        return
    fi

    local line group basis loaded selected sent planned dropped early
    local worst_pct=101 worst_note="" reported=""
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        group="$(cov_field "$line" group || true)"
        basis="$(printf '%s' "$line" | grep -c '"execution_basis":"[^"]' || true)"
        loaded="$(cov_field "$line" templates_loaded || true)"
        selected="$(cov_field "$line" filter_selected || true)"
        sent="$(cov_field "$line" requests_sent || true)"
        planned="$(cov_field "$line" requests_planned || true)"
        dropped="$(cov_field "$line" hosts_dropped || true)"
        early="$(printf '%s' "$line" | grep -c '"terminated_early":true' || true)"

        # THE EXTRACTOR MUST BE PROVEN NON-EMPTY BEFORE ANY VERDICT RESTS ON IT.
        # A checker earlier in this phase extracted 0-byte commands and ran them;
        # `sh -c ""` exits 0, so it reported PASS having run nothing. If a field
        # is absent the shape changed, and this gate says so instead of deciding.
        if [ -z "$loaded" ] || [ -z "$sent" ] || [ -z "$planned" ]; then
            echo "FAIL the record shape changed: group \`${group:-?}\` is missing templates_loaded, requests_sent or requests_planned entirely (not null — ABSENT), so this gate cannot judge it and will not pretend to"
            return
        fi

        if [ "${basis:-0}" -eq 0 ]; then
            echo "FAIL group \`${group:-?}\` carries no execution_basis — the record states coverage numbers without declaring that requests_sent is a PROXY for execution, and an undeclared proxy read as a count is what produced the 49-template misreading"
            return
        fi

        if [ "${early:-0}" -ne 0 ]; then
            echo "FAIL group \`${group:-?}\` is marked terminated_early — its coverage is partial by definition, and a partial scan is not a pass"
            return
        fi

        if [ "$loaded" = "null" ] || [ "$sent" = "null" ] || [ "$planned" = "null" ]; then
            echo "FAIL group \`${group:-?}\` reports templates_loaded=$loaded requests_sent=$sent requests_planned=$planned — a null is UNKNOWN, and a run that cannot say what it loaded or sent has not accounted for itself"
            return
        fi

        if [ "$planned" -le 0 ]; then
            echo "FAIL group \`${group:-?}\` planned $planned requests — a nuclei group with no request budget loaded no usable template set"
            return
        fi

        local pct=$((sent * 100 / planned))
        reported="$reported ${group:-?}:${sent}/${planned}(${pct}%,loaded=${loaded},selected=${selected:-absent},dropped=${dropped})"
        if [ "$pct" -lt "$worst_pct" ]; then
            worst_pct="$pct"
            worst_note="${group:-?}"
        fi
    done <"$cov"

    if [ "$worst_pct" -lt "$NUCLEI_COVERAGE_MIN_PCT" ]; then
        echo "FAIL group \`$worst_note\` sent only ${worst_pct}% of its planned requests (floor ${NUCLEI_COVERAGE_MIN_PCT}%, derived from a measured 98.75% healthy / 4.2% collapsed) —$reported"
        return
    fi

    echo "PASS $n group record(s), worst executed fraction ${worst_pct}% (floor ${NUCLEI_COVERAGE_MIN_PCT}%) —$reported"
}

if [ "$NUCLEI_COV_VERDICT" = "1" ]; then
    nuclei_coverage_verdict "$NUCLEI_COV_WS"
    exit 0
fi

# ─── the by-name gate rule ──────────────────────────────────────────────────
#
# gate_expected_tests <-run pattern> — the test names a gate's pattern CITES.
#
# `go test -run` takes one unanchored regexp alternation, so a gate citing nine
# tests is a single string. Splitting on `|` and stripping the `^`/`$` anchors
# yields the names the gate claims to run.
gate_expected_tests() {
    printf '%s\n' "$1" | tr '|' '\n' | sed 's/^\^//; s/\$$//' | grep -v '^[[:space:]]*$' || true
}

# gate_passed_names — the test names that reported `--- PASS`, read on stdin.
#
# Subtest lines (`    --- PASS: TestX/sub`) are KEPT: a substring citation can be
# satisfied by one, while an exact citation never is, because Go prints a
# separate top-level line for the parent when it passes.
gate_passed_names() {
    sed -nE 's/^[[:space:]]*--- PASS: ([^[:space:]]+).*/\1/p' | LC_ALL=C sort -u
}

# gate_verdict <-run pattern> <go exit code>  — reads a `go test -v` log on
# stdin, prints exactly one line:   PASS <note>  |  FAIL <note>
#
# THE RULE, stated so the next reader does not re-derive the weaker version.
# Each alternative of the pattern is classified and asserted:
#
#   EXACT citation     — matches ^Test[A-Za-z0-9_]*$ after anchor stripping.
#                        Satisfied ONLY by a `--- PASS: <name>` line for that
#                        exact name. This is what distinguishes a passing
#                        TestStreamContractRatchetIsClosed from the separately
#                        cited TestStreamContract$, which a prefix match would
#                        silently conflate.
#   SUBSTRING citation — anything else, e.g. `ExitSevenErrors`, which
#                        legitimately names a suffix shared by six per-module
#                        tests. Satisfied by any passing test whose name
#                        CONTAINS it, AND reported as a substring citation in the
#                        note: "at least one of an unknown number ran" is a
#                        weaker fact than "this test ran", and a reader must not
#                        have to guess which kind they are looking at.
#
# A gate FAILS when any citation is unsatisfied, and the note NAMES the missing
# ones — the idiom `make realtools-args` already proved. Counting `--- PASS`
# lines and failing only at zero let a nine-test gate pass on one.
gate_verdict() {
    local pattern="$1" rc="${2:-0}" out
    out="$(cat)"

    local passes fails passed
    passes="$(printf '%s\n' "$out" | grep -c -- '--- PASS' || true)"
    fails="$(printf '%s\n' "$out" | grep -c -- '--- FAIL' || true)"
    passed="$(printf '%s\n' "$out" | gate_passed_names)"

    if [ "$passes" -eq 0 ]; then
        echo "FAIL NO TESTS RAN. \`go test -run\` exits 0 on a pattern that matches nothing; the cited test was renamed, moved or deleted (go exit $rc)"
        return
    fi

    local missing="" substrings="" name cited=0
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        cited=$((cited + 1))
        if printf '%s' "$name" | grep -qE '^Test[A-Za-z0-9_]*$'; then
            printf '%s\n' "$passed" | grep -qx -- "$name" || missing="$missing $name"
        else
            substrings="$substrings $name"
            printf '%s\n' "$passed" | grep -qF -- "$name" || missing="$missing $name"
        fi
    done <<EOF
$(gate_expected_tests "$pattern")
EOF

    # A citation list that came out EMPTY would make every check below vacuously
    # true — the by-name rule would report PASS having asserted nothing at all.
    # That is the same shape as the extraction bug that produced 0-byte command
    # files during this phase's planning and reported PASS having run nothing, so
    # the harness asserts on ITSELF before it asserts on the log.
    if [ "$cited" -eq 0 ]; then
        echo "FAIL the -run pattern '$pattern' parsed to ZERO cited test names, so the by-name assertion would have checked nothing and passed vacuously"
        return
    fi

    if [ -n "$missing" ]; then
        echo "FAIL these cited test(s) never reported --- PASS:$missing (only $passes PASS line(s) seen, go exit $rc). A gate citing N tests must not pass on one of them"
        return
    fi
    if [ "$rc" -ne 0 ] || [ "$fails" -ne 0 ]; then
        echo "FAIL $fails failing test(s), go exit $rc"
        return
    fi
    echo "PASS every cited test reported --- PASS ($passes PASS line(s)${substrings:+; substring citation(s):$substrings})"
}

if [ "$GATE_VERDICT" = "1" ]; then
    if [ -z "$GATE_PATTERN" ]; then
        echo "release-gates: --gate-verdict needs a -run pattern" >&2
        exit 2
    fi
    gate_verdict "$GATE_PATTERN" "$GATE_RC"
    exit 0
fi

# ─── result recording ───────────────────────────────────────────────────────
#
# Parallel arrays rather than an associative array: ordered output matters more
# than lookup, and bash 3.2 (macOS system bash) has no `declare -A`.
STEP_NAMES=()
STEP_STATUS=()
STEP_NOTES=()
FAILED=0

LOGDIR="$(mktemp -d "${TMPDIR:-/tmp}/reconftw-release-gates.XXXXXX")"

# cleanup_logdir — RETAIN on failure, remove on a full pass, print the path either
# way.
#
# The trap here was `rm -rf "$LOGDIR"` unconditionally. Every FAIL note this
# script emits ends with `full log: $LOGDIR/<step>.log`, so the trap deleted the
# exact artefact the failure output told the reader to open; by the time anyone
# read the summary those paths were gone. Dropping the trap outright is not the
# fix either — one retained temp directory per run is a real cost on a box where
# this is run repeatedly — so which case keeps and which case cleans is stated
# rather than implied.
#
# mktemp -d creates the directory mode 0700 and nothing below widens it. These
# logs carry tool output and must not become readable to other users of a shared
# $TMPDIR, so do not add a chmod here.
cleanup_logdir() {
    if [ "$FAILED" -ne 0 ]; then
        printf '\nlogs RETAINED (a step FAILED): %s\n' "$LOGDIR"
        return
    fi
    rm -rf "$LOGDIR"
    printf '\nlogs removed (every step passed): %s\n' "$LOGDIR"
}
trap cleanup_logdir EXIT

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
# Runs the named tests verbosely, then requires EVERY test the pattern cites to
# have reported `--- PASS` (see gate_verdict for the rule and its two citation
# kinds). This is the direct countermeasure to T-15-17-01 and is demonstrated,
# not assumed: deleting or renaming any ONE of a gate's cited tests must fail
# this script, and cmd/reconftw/release_gates_test.go asserts exactly that
# against the `--gate-verdict` seam.
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

    # The decision is delegated to gate_verdict so the rule this script enforces
    # and the rule cmd/reconftw/release_gates_test.go asserts are the SAME code
    # path, not two implementations that agree until one of them drifts.
    local verdict status note
    verdict="$(gate_verdict "$pattern" "$rc" <"$log")"
    status="${verdict%% *}"
    note="${verdict#* }"

    if [ "$status" = "PASS" ]; then
        record "$label" PASS "$note"
        return
    fi
    grep -n 'no tests to run' "$log" || grep -n -- '--- FAIL' "$log" | head -n 20 || tail -n 20 "$log" || true
    record "$label" FAIL "$note — full log: $log"
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

# ─── the arg-vector gate ────────────────────────────────────────────────────
#
# NOT ATTACHED TO `make ci`, ON PURPOSE. CI runners carry no tool tree, so this
# would be permanently SKIPPED there — and a gate that is always skipped teaches
# every reader to ignore the skip column, which is the one column this script
# exists to make meaningful. Do not "helpfully" add it to the ci target.
#
# It runs here, plus one mandatory manual run on a provisioned box before
# cutover, which is the same posture gate 11 ended up in for the same reason.
gate_argvector() {
    local label="Gate 13: real-tool arg vectors (make realtools-args, REFERENCE mode)"
    banner "$label"

    local log="$LOGDIR/gate13_argvector.log"
    local rc=0
    REALTOOLS_REFERENCE=1 make realtools-args >"$log" 2>&1 || rc=$?

    local verdict
    verdict="$(argvector_census_verdict "$rc" <"$log")"
    local status="${verdict%% *}"
    local note="${verdict#* }"

    # Print the skipped NAMES here so a sign-off reader sees them without opening
    # a log. "9 skipped" is not actionable; "9 skipped: arjun dnscewl …" is.
    grep 'REALTOOLS_CENSUS test=' "$log" | sed 's/^ *//' || true

    # 18-06: and the per-tool reason for every UNRESOLVABLE one, which always
    # names the path that was looked for. "installed but unresolvable" without
    # the path is a verdict an operator cannot act on.
    grep 'REALTOOLS_UNRESOLVABLE ' "$log" | sed 's/^ *//' || true

    case "$status" in
        PASS) record "$label" PASS "$note" ;;
        SKIPPED) record "$label" SKIPPED "$note" ;;
        *)
            tail -n 30 "$log"
            record "$label" FAIL "$note — full log: $log"
            ;;
    esac
}

# ─── the nuclei coverage gate (plan 17-05, requirement TC-A) ────────────────
#
# TWO halves, because either alone is a false green. The first cites the tests
# that prove the record cannot silently degrade — delete or rename any one of
# them and the by-name rule fails this gate. The second applies the coverage RULE
# to a real workspace when one is supplied, and records SKIPPED (never PASS) when
# one is not: this script's whole posture is that an unjudged step is not a
# passed step.
gate_nuclei_coverage() {
    gate "Gate 14a: a nuclei run accounts for what it covered" \
        'TestNucleiCoverageEndToEnd|TestNucleiCoverageRecordsHostDrops|TestNucleiCoverageWrittenOnTerminatedGroup|TestNucleiCoverageProxyDeclarationEnforced|TestNucleiCoverageUnknownIsNotZero|TestNucleiCoverageParsesRealStatsLine|TestNucleiCoverageParsesRealSkipNotice|TestNucleiCoverageParsesRealTemplateList|TestNucleiCoverageRecordStaysSmall' \
        ./internal/modules/web/

    local label="Gate 14b: a real run's nuclei coverage is above the derived floor"
    banner "$label"
    local verdict status note
    verdict="$(nuclei_coverage_verdict "${RECONFTW_WORKSPACE:-}")"
    status="${verdict%% *}"
    note="${verdict#* }"
    echo "  workspace: ${RECONFTW_WORKSPACE:-(none supplied)}"
    echo "  floor    : ${NUCLEI_COVERAGE_MIN_PCT}% of planned requests actually sent"
    case "$status" in
        PASS) record "$label" PASS "$note" ;;
        SKIPPED) record "$label" SKIPPED "$note" ;;
        *) record "$label" FAIL "$note" ;;
    esac
}

# Gate 12 — "A clean checkout builds and runs the full suite." The build half is
# the guard's `go build ./...` above; the RUN half is here.
gate "Gate 12: a clean checkout builds and runs (version, --help, clean-PATH health-check)" \
    'TestReleaseGate12CleanTreeBuildsAndRuns|TestE2EBinaryVersionAndConfig|TestE2EBinaryHealthCheckIsSelfConsistent' \
    ./cmd/reconftw/
gate_nuclei_coverage
# Gate 13 runs last: it is the slowest step and the only one that shells out to make.
gate_argvector

# ═════════════════════════════════════════════════════════════════════════════

summary

if [ "$FAILED" -ne 0 ]; then
    echo "release-gates: FAILED — the Phase 14 cutover is not signed off." >&2
    exit 1
fi
echo "release-gates: all executed steps passed. Read the SKIPPED list above before signing off."
