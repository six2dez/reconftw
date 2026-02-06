#!/usr/bin/env bash
set -euo pipefail

BASELINE_FILE="${1:-tests/bench/baseline_metrics.json}"
CURRENT_FILE="${2:-}"
MAX_DEGRADATION_PCT="${MAX_DEGRADATION_PCT:-20}"

if [[ -z "${CURRENT_FILE}" ]]; then
  echo "Usage: $0 <baseline_json> <current_perf_summary_json>"
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

allowed=$(( base_total + (base_total * MAX_DEGRADATION_PCT / 100) ))
if [[ "$cur_total" -gt "$allowed" ]]; then
  echo "[FAIL] Runtime regression: current=${cur_total}s baseline=${base_total}s allowed=${allowed}s"
  exit 1
fi

echo "[OK] Runtime within threshold: current=${cur_total}s baseline=${base_total}s allowed=${allowed}s"
