#!/usr/bin/env bats

setup() {
  source "$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/../helpers/common.bash"
  setup_recon_env

  export TEST_DIR="$(mktemp -d)"
  export domain="example.com"
  export dir="$TEST_DIR/$domain"
  mkdir -p "$dir"/{subdomains,webs,hosts,nuclei_output,report,.log}
  cd "$dir"

  echo "a.example.com" > subdomains/subdomains.txt
  echo "https://a.example.com" > webs/webs_all.txt
  echo "1.1.1.1" > hosts/ips.txt
  echo '{"template-id":"tpl-h","matcher-name":"m1","type":"http","info":{"severity":"high","name":"High finding","tags":["x"]},"matched-at":"https://a.example.com","host":"a.example.com"}' > nuclei_output/high_json.txt
  echo '{"type":"finding","value":"test","ts":"2026-01-01","source":"unit"}' > assets.jsonl
  runtime="1 minutes 0 seconds"
}

teardown() {
  cd /
  rm -rf "$TEST_DIR"
}

@test "export_findings_jsonl creates normalized and merged jsonl" {
  run export_findings_jsonl
  [ "$status" -eq 0 ]
  [ -f report/findings_normalized.jsonl ]
  [ -f report/export_all.jsonl ]
  grep -q '"tool":"nuclei"' report/findings_normalized.jsonl
}

@test "export_csv_artifacts writes expected csv files" {
  run export_csv_artifacts
  [ "$status" -eq 0 ]
  [ -f report/subdomains.csv ]
  [ -f report/webs.csv ]
  [ -f report/hosts.csv ]
  [ -f report/findings.csv ]
  head -n1 report/findings.csv | grep -q "tool,severity"
}

@test "export_reports honors EXPORT_FORMAT=all" {
  export EXPORT_FORMAT="all"
  run export_reports
  [ "$status" -eq 0 ]
  [ -f report/index.html ]
  [ -f report/report.json ]
  [ -f report/findings.csv ]
  [ -f report/export_all.jsonl ]
}
