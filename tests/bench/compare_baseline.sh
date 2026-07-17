#!/usr/bin/env bash
# tests/bench/compare_baseline.sh — throughput regression gate (XCUT-01).
#
# Asserts Go v2 runs within MAX_DEGRADATION_PCT (default 10%) of the bash v1
# baseline. This is an OPERATOR-RUN benchmark — it needs the full external
# toolchain + a real network host (this box blocks UDP/53) — and is deliberately
# NOT wired into `make ci` (see the Makefile `ci:` target). Only the offline
# --self-check below runs without a live scan.
#
# ── Operator capture procedure (real baseline, on an 8-core/16GB reference host) ─
#   1. Baseline (bash v1, frozen ref — same worktree as scripts/parity-full.sh):
#        git worktree add ../reconftw-v1-baseline v4.1
#        ( cd ../reconftw-v1-baseline && time ./reconftw.sh -d <target> -r )
#      Record the wall-clock seconds into tests/bench/baseline_metrics.json
#      under "total_duration_sec".
#   2. Current (Go v2), against the SAME ~1000-subdomain target:
#        time ./bin/reconftw recon --target <target> --no-update
#      Write {"total_duration_sec": <sec>} to current_perf_summary.json.
#   3. Gate:
#        tests/bench/compare_baseline.sh tests/bench/baseline_metrics.json current_perf_summary.json
#      → [OK] if current ≤ baseline + 10%; [FAIL] (exit 1) otherwise.
#
# Offline self-check (no live scan, proves the gate discriminates at 10%):
#        tests/bench/compare_baseline.sh --self-check
set -euo pipefail

# --self-check: prove the gate PASSES a within-10% pair and FAILS a >10% pair,
# using canned temp JSON only. Exercises the built-in default gate (10%).
if [[ "${1:-}" == "--self-check" ]]; then
    unset MAX_DEGRADATION_PCT # exercise the built-in :-10 default
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/bench-selfcheck.XXXXXX")
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT
    printf '{"total_duration_sec": 600}\n' >"$tmp/base.json"
    printf '{"total_duration_sec": 640}\n' >"$tmp/ok.json"   # +6.7% → within 10% → OK
    printf '{"total_duration_sec": 690}\n' >"$tmp/fail.json" # +15%  → over 10% (but under old 20%) → FAIL
    rc=0
    echo "== compare_baseline --self-check (offline, default 10% gate) =="
    if "$0" "$tmp/base.json" "$tmp/ok.json"; then
        echo "  ok   within-10% pair → PASS (exit 0)"
    else
        echo "  FAIL within-10% pair should have PASSED" >&2
        rc=1
    fi
    if "$0" "$tmp/base.json" "$tmp/fail.json"; then
        echo "  FAIL >10% pair should have FAILED but passed (gate looser than 10%?)" >&2
        rc=1
    else
        echo "  ok   >10% pair → FAIL (exit 1)"
    fi
    if [[ $rc -eq 0 ]]; then
        echo "SELF-CHECK: PASS — gate discriminates at the 10% threshold offline."
    else
        echo "SELF-CHECK: FAIL" >&2
    fi
    exit $rc
fi

BASELINE_FILE="${1:-tests/bench/baseline_metrics.json}"
CURRENT_FILE="${2:-}"
MAX_DEGRADATION_PCT="${MAX_DEGRADATION_PCT:-10}"

if [[ -z "${CURRENT_FILE}" ]]; then
    echo "Usage: $0 <baseline_json> <current_perf_summary_json>   (or: $0 --self-check)"
    exit 2
fi

if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "[INFO] Baseline file not found ($BASELINE_FILE); skipping regression gate"
    exit 0
fi

if [[ ! -f "$CURRENT_FILE" ]]; then
    echo "[INFO] Current perf summary not found ($CURRENT_FILE); skipping regression gate"
    exit 0
fi

base_total=$(jq -r '.total_duration_sec // 0' "$BASELINE_FILE" 2>/dev/null || echo 0)
cur_total=$(jq -r '.total_duration_sec // 0' "$CURRENT_FILE" 2>/dev/null || echo 0)

if [[ "$base_total" -le 0 || "$cur_total" -le 0 ]]; then
    echo "[INFO] Non-positive timings in baseline/current; skipping regression gate"
    exit 0
fi

allowed=$((base_total + (base_total * MAX_DEGRADATION_PCT / 100)))
if [[ "$cur_total" -gt "$allowed" ]]; then
    echo "[FAIL] Runtime regression: current=${cur_total}s baseline=${base_total}s allowed=${allowed}s"
    exit 1
fi

echo "[OK] Runtime within threshold: current=${cur_total}s baseline=${base_total}s allowed=${allowed}s"
