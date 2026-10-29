#!/usr/bin/env bash
# Self-test for scripts/release-gates.sh. Run via `make release-gates-selftest`.
#
# WHAT IT PROVES, AND WHY A SOURCE READ WOULD NOT DO.
#
# This repo's standing precedent (phase 15, finding F19) is that two independent
# code reads certified a fix that was inert in production. So the exit-code
# contract of --require-all / --delegate is DRIVEN here, against the real script,
# with a stub `go` that answers every `go test` in milliseconds and a stub tool
# tree that is deliberately absent — i.e. exactly the shape of a CI runner.
#
# Cases, each asserting the script's EXIT STATUS and the summary's wording:
#
#   DEFAULT      no flags: the three gates a CI runner cannot run (11, 13, 14b)
#                are SKIPPED and the run still exits 0. This is the local
#                developer loop and must stay lenient.
#   REQUIRE-ALL  --require-all: the SAME run exits non-zero and NAMES all three
#                unexecuted gates. A green run with a hole in it is the false
#                green this script exists to refuse.
#   DELEGATED    --require-all --delegate 11 --delegate 13 --delegate 14b: exits
#                0, every one of the three rows reads DELEGATED and carries a
#                pointer to where it IS enforced, and summary.txt in --logdir
#                holds the same rows after the run.
#   PARTIAL      --require-all --delegate 11 --delegate 13 (14b NOT delegated):
#                exits non-zero naming ONLY gate 14b. Delegating two gates must
#                not launder the third.
#   NO-OVERRIDE  --require-all --delegate 14b with a workspace whose coverage
#                record is empty: gate 14b FAILS and the run exits non-zero.
#                Delegation stands in for a verdict that could not be reached;
#                it never replaces one that was.
#   STILL-FAILS  --require-all with a `go` that fails everything: non-zero, as a
#                sanity floor under the cases above (a harness in which nothing
#                can fail proves nothing).
#
# No real `go test` is run; no network; no tools. ~2 seconds.
set -euo pipefail
export LC_ALL=C

cd "$(dirname "${BASH_SOURCE[0]}")/.."
SCRIPT="scripts/release-gates.sh"

for need in make sed grep tee mktemp; do
    if ! command -v "$need" >/dev/null 2>&1; then
        echo "::error::release_gates_test: '$need' is required and not on PATH"
        exit 2
    fi
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ── stub `go` ────────────────────────────────────────────────────────────────
# All-pass: echoes a `--- PASS` line for every name the -run pattern cites, and
# for `-tags realtools` prints everything `make realtools-args` asserts on, with
# every census line in NOT_EXECUTED mode — a box with no tool tree, which is what
# a CI runner is and what gate 13 must report as SKIPPED (never PASS).
STUB_OK="$WORK/ok"
mkdir -p "$STUB_OK"
cat >"$STUB_OK/go" <<'EOF'
#!/bin/sh
case " $* " in
  *" -tags realtools "*)
    for t in TestRealToolArgVectors TestRealtoolsVulnsPhase6 TestRealtoolsOSINTPhase7 TestRealtoolsFixedArgVectors; do
      echo "=== RUN   $t"
      echo "REALTOOLS_CENSUS test=$t mode=NOT_EXECUTED present=0 skipped=0 skipped_tools=(none)"
      echo "REALTOOLS_CENSUS_REASON test=$t no tool tree on this box (stub)"
      echo "--- PASS: $t (0.00s)"
    done
    for t in TestEveryRegisteredTaskIsAccountedFor TestToolsJsonlCoverage TestRegulatorDispatchesThroughTheRunner; do
      echo "=== RUN   $t"
      echo "--- PASS: $t (0.00s)"
    done
    echo "ARGV_COVERAGE registered=1 driven=1"
    echo "TOOLS_JSONL_COVERAGE tools=stub"
    echo PASS
    exit 0
    ;;
esac
pattern=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-run" ]; then pattern="$a"; fi
  prev="$a"
done
if [ -n "$pattern" ]; then
  echo "$pattern" | tr '|' '\n' | sed 's/^\^//; s/\$$//' | while read -r n; do
    [ -n "$n" ] || continue
    echo "=== RUN   $n"
    echo "--- PASS: $n (0.00s)"
  done
fi
echo PASS
exit 0
EOF
chmod 0700 "$STUB_OK/go"

STUB_BAD="$WORK/bad"
mkdir -p "$STUB_BAD"
printf '#!/bin/sh\necho "stub go: everything fails" >&2\nexit 1\n' >"$STUB_BAD/go"
chmod 0700 "$STUB_BAD/go"

# A PATH with no recon tooling and nothing from GOPATH/bin, so the real `go` and
# the real tools can never leak into a case. /usr/bin carries make, sed, grep.
MINIMAL_PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# run_case NAME STUBDIR [args...] -> exit status in RC, output in OUT, logdir in LOGDIR
RC=0
OUT=""
LOGDIR=""
run_case() {
    local name="$1" stub="$2"
    shift 2
    LOGDIR="$WORK/logs-$name"
    RC=0
    OUT=$(env -i PATH="$stub:$MINIMAL_PATH" HOME="$WORK" TMPDIR="$WORK" \
        ${CASE_ENV:+"$CASE_ENV"} \
        bash "$SCRIPT" --gates-only --logdir "$LOGDIR" "$@" 2>&1) || RC=$?
}

fail() {
    echo "::error::$*"
    echo "--- script output ---"
    echo "$OUT"
    echo "---------------------"
    exit 1
}

# row STATUS GATE-PREFIX — does the summary carry `[STATUS ...] Gate N` for that gate?
row() {
    printf '%s\n' "$OUT" | grep -Eq "^\s*\[$1\s*\] $2"
}

echo "release-gates self-test (stub go, no tool tree)"
echo

# ── DEFAULT ─────────────────────────────────────────────────────────────────
CASE_ENV=""
run_case default "$STUB_OK"
[ "$RC" -eq 0 ] || fail "case DEFAULT: expected exit 0 without --require-all, got $RC"
for g in "Gate 11" "Gate 13" "Gate 14b"; do
    row SKIPPED "$g" || fail "case DEFAULT: $g should be SKIPPED on a box with no docker, no tools and no workspace"
done
printf '%s\n' "$OUT" | grep -q 'pass --require-all to make this fatal' \
    || fail "case DEFAULT: the summary must say how to make the unexecuted gates fatal"
[ -f "$LOGDIR/summary.txt" ] || fail "case DEFAULT: $LOGDIR/summary.txt was not written"
echo "PASS  case DEFAULT: 3 SKIPPED gates, exit 0, summary.txt written"

# ── REQUIRE-ALL ─────────────────────────────────────────────────────────────
run_case requireall "$STUB_OK" --require-all
[ "$RC" -ne 0 ] || fail "case REQUIRE-ALL: exit 0 with three unexecuted gates — --require-all is inert"
for g in "Gate 11" "Gate 13" "Gate 14b"; do
    printf '%s\n' "$OUT" | grep -q "^    - $g" || fail "case REQUIRE-ALL: the summary does not list '$g' under the unexecuted gates"
done
printf '%s\n' "$OUT" | grep -q -- '--require-all: these gate(s) did not execute' \
    || fail "case REQUIRE-ALL: the final line does not explain WHY the run failed"
printf '%s\n' "$OUT" | grep -q 'logs KEPT (caller-owned --logdir)' \
    || fail "case REQUIRE-ALL: --logdir must be reported as kept"
[ -f "$LOGDIR/gate13_argvector.log" ] || fail "case REQUIRE-ALL: gate13_argvector.log missing from --logdir"
echo "PASS  case REQUIRE-ALL: exit $RC, names Gate 11 / 13 / 14b"

# The env-var spelling must be the same switch, not a second implementation.
CASE_ENV="RELEASE_GATES_REQUIRE_ALL=1"
run_case requireall-env "$STUB_OK"
CASE_ENV=""
[ "$RC" -ne 0 ] || fail "case REQUIRE-ALL (env): RELEASE_GATES_REQUIRE_ALL=1 did not fail the run"
echo "PASS  case REQUIRE-ALL (env): RELEASE_GATES_REQUIRE_ALL=1 behaves like the flag"

# ── DELEGATED ───────────────────────────────────────────────────────────────
run_case delegated "$STUB_OK" --require-all --delegate 11 --delegate=13 --delegate 14b
[ "$RC" -eq 0 ] || fail "case DELEGATED: expected exit 0 with all three gates delegated, got $RC"
for g in "Gate 11" "Gate 13" "Gate 14b"; do
    row DELEGATED "$g" || fail "case DELEGATED: $g is not reported DELEGATED"
done
printf '%s\n' "$OUT" | grep -q 'docker_nightly.yml' || fail "case DELEGATED: gate 11's row carries no pointer to docker_nightly.yml"
printf '%s\n' "$OUT" | grep -q 'make release-gates-provisioned' || fail "case DELEGATED: the operator-delegated rows carry no make target"
printf '%s\n' "$OUT" | grep -q 'every gate was executed or explicitly delegated' \
    || fail "case DELEGATED: the closing line does not state that nothing was silently skipped"
grep -q '^\s*\[DELEGATED\s*\] Gate 13' "$LOGDIR/summary.txt" \
    || fail "case DELEGATED: summary.txt does not hold the DELEGATED rows"
echo "PASS  case DELEGATED: exit 0, 3 DELEGATED rows with pointers, summary.txt matches"

# ── PARTIAL ─────────────────────────────────────────────────────────────────
run_case partial "$STUB_OK" --require-all --delegate 11 --delegate 13
[ "$RC" -ne 0 ] || fail "case PARTIAL: delegating 11 and 13 must not launder an undelegated 14b"
printf '%s\n' "$OUT" | grep -q '^    - Gate 14b' || fail "case PARTIAL: gate 14b not named as unexecuted"
if printf '%s\n' "$OUT" | grep -Eq '^    - Gate 1[13]:'; then
    fail "case PARTIAL: a delegated gate is listed as unexecuted"
fi
echo "PASS  case PARTIAL: exit $RC, only Gate 14b named"

# ── NO-OVERRIDE ─────────────────────────────────────────────────────────────
WS="$WORK/ws"
mkdir -p "$WS/logs"
: >"$WS/logs/nuclei-coverage.jsonl"
CASE_ENV="RECONFTW_WORKSPACE=$WS"
run_case nooverride "$STUB_OK" --require-all --delegate 11 --delegate 13 --delegate 14b
CASE_ENV=""
[ "$RC" -ne 0 ] || fail "case NO-OVERRIDE: an EMPTY coverage record passed because 14b was delegated — delegation overrode a verdict"
row FAIL "Gate 14b" || fail "case NO-OVERRIDE: gate 14b should be FAIL on an empty coverage record"
if row DELEGATED "Gate 14b"; then
    fail "case NO-OVERRIDE: gate 14b reported DELEGATED although it was judged"
fi
echo "PASS  case NO-OVERRIDE: a judged gate keeps its FAIL under --delegate"

# ── STILL-FAILS ─────────────────────────────────────────────────────────────
run_case stillfails "$STUB_BAD" --require-all --delegate 11 --delegate 13 --delegate 14b
[ "$RC" -ne 0 ] || fail "case STILL-FAILS: every go test failed and the run exited 0"
row FAIL "Gate 1:" || fail "case STILL-FAILS: gate 1 should be FAIL with a failing go"
echo "PASS  case STILL-FAILS: exit $RC with a failing go"

echo
echo "OK: release-gates.sh fails on an unexecuted gate under --require-all, passes on an explicit delegation, and never lets delegation override a verdict."
