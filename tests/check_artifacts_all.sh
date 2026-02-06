#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="${1:-Recon}"
CHECKER="${2:-./tests/check_artifacts.sh}"

if [[ ! -x "$CHECKER" ]]; then
  echo "[FAIL] Checker not found or not executable: $CHECKER"
  exit 2
fi

if [[ ! -d "$BASE_DIR" ]]; then
  echo "[FAIL] Base directory not found: $BASE_DIR"
  exit 2
fi

mapfile -t targets < <(find "$BASE_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort)

if [[ ${#targets[@]} -eq 0 ]]; then
  echo "[WARN] No targets found under: $BASE_DIR"
  exit 0
fi

ok_count=0
fail_count=0
failed_targets=()

for t in "${targets[@]}"; do
  echo
  echo "=== Checking target: $t ==="
  if "$CHECKER" "$t"; then
    ok_count=$((ok_count + 1))
  else
    fail_count=$((fail_count + 1))
    failed_targets+=("$t")
  fi
done

echo
echo "=== Summary ==="
echo "Total targets: ${#targets[@]}"
echo "Passed: $ok_count"
echo "Failed: $fail_count"

if [[ $fail_count -gt 0 ]]; then
  echo "Failed targets:"
  for t in "${failed_targets[@]}"; do
    echo "- $t"
  done
  exit 1
fi

echo "[OK] All targets passed artifact checks."
