#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target-domain>"
  echo "Example: $0 example.com"
  exit 2
fi

TARGET="$1"
BASE="Recon/$TARGET"

ok() { printf "[OK] %s\n" "$1"; }
warn() { printf "[WARN] %s\n" "$1"; }
fail() { printf "[FAIL] %s\n" "$1"; exit 1; }

require_file() {
  local f="$1"
  [[ -f "$f" ]] || fail "Missing file: $f"
  ok "Found file: $f"
}

check_json_file() {
  local f="$1"
  require_file "$f"
  jq -e . "$f" >/dev/null 2>&1 || fail "Invalid JSON: $f"
  ok "Valid JSON: $f"
}

check_jsonl_file() {
  local f="$1"
  require_file "$f"
  if [[ ! -s "$f" ]]; then
    warn "Empty JSONL: $f"
    return 0
  fi
  local bad
  bad=$(jq -c . "$f" >/dev/null 2>&1; echo $?)
  [[ "$bad" -eq 0 ]] || fail "Invalid JSONL lines: $f"
  ok "Valid JSONL: $f"
}

check_csv_header() {
  local f="$1"
  local h="$2"
  require_file "$f"
  local got
  got="$(head -n1 "$f")"
  [[ "$got" == "$h" ]] || fail "CSV header mismatch in $f (got: '$got', expected: '$h')"
  ok "CSV header ok: $f"
}

[[ -d "$BASE" ]] || fail "Target directory not found: $BASE"
ok "Target directory: $BASE"

command -v jq >/dev/null 2>&1 || fail "jq is required"
ok "jq available"

check_json_file "$BASE/.log/perf_summary.json"
check_json_file "$BASE/report/report.json"
require_file "$BASE/report/index.html"
ok "HTML report exists: $BASE/report/index.html"
check_json_file "$BASE/report/latest/report.json"
require_file "$BASE/report/latest/index.html"
ok "Latest HTML report exists: $BASE/report/latest/index.html"

check_jsonl_file "$BASE/report/findings_normalized.jsonl"
check_jsonl_file "$BASE/report/export_all.jsonl"

check_csv_header "$BASE/report/subdomains.csv" "subdomain"
check_csv_header "$BASE/report/webs.csv" "url,scheme,host"
check_csv_header "$BASE/report/hosts.csv" "ip"
check_csv_header "$BASE/report/findings.csv" "tool,severity,template_id,name,target,host,finding_type,matcher_name"

if [[ -f "$BASE/.incremental/history/latest/delta.json" ]]; then
  check_json_file "$BASE/.incremental/history/latest/delta.json"
else
  warn "No monitor delta file (run monitor/incremental to generate): $BASE/.incremental/history/latest/delta.json"
fi

if [[ -f "$BASE/.incremental/history/latest/alerts.json" ]]; then
  check_json_file "$BASE/.incremental/history/latest/alerts.json"
else
  warn "No monitor alerts file (run monitor/incremental to generate): $BASE/.incremental/history/latest/alerts.json"
fi

for sev in info low medium high critical; do
  f="$BASE/nuclei_output/${sev}_json.txt"
  if [[ -f "$f" ]]; then
    check_jsonl_file "$f"
  fi
done

ok "Artifact checks completed successfully for $TARGET"
