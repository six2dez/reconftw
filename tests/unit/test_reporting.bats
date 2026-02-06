#!/usr/bin/env bats

setup() {
  source "$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/../helpers/common.bash"
  setup_recon_env

  export TEST_DIR="$(mktemp -d)"
  export domain="example.com"
  export dir="$TEST_DIR/$domain"
  mkdir -p "$dir"/{subdomains,webs,hosts,nuclei_output,screenshots,report,.log,.incremental/history}
  cd "$dir"

  echo "a.example.com" > subdomains/subdomains.txt
  echo "https://a.example.com" > webs/webs_all.txt
  echo "1.1.1.1" > hosts/ips.txt
  echo "[tpl-c] [http] [critical] https://a.example.com" > nuclei_output/critical.txt
  echo '{"template-id":"tpl-c","info":{"severity":"critical"},"matched-at":"https://a.example.com"}' > nuclei_output/critical_json.txt
  echo "20 a.example.com" > hotlist.txt
  runtime="5 minutes 0 seconds"
}

teardown() {
  cd /
  rm -rf "$TEST_DIR"
}

@test "generate_consolidated_report creates json and html" {
  run generate_consolidated_report
  [ "$status" -eq 0 ]
  [ -f report/report.json ]
  [ -f report/index.html ]
  [ -f report/latest/report.json ]
  [ -f report/latest/index.html ]
  grep -q '"domain":"example.com"' report/report.json
}

@test "report includes delta_since_last when monitor data exists" {
  mkdir -p .incremental/history/prev
  cat > .incremental/history/prev/delta.json <<JSON
{"deltas":{"subdomains_new":1,"webs_new":1,"high_findings_new":0,"critical_findings_new":1}}
JSON
  cat > .incremental/history/prev/alerts.json <<JSON
{"alerts":{"critical_new":1,"high_new":0,"subdomains_new":1,"webs_new":1}}
JSON
  ln -s prev .incremental/history/latest

  run generate_consolidated_report
  [ "$status" -eq 0 ]
  grep -q '"delta_since_last"' report/report.json
  grep -q '"alerts_last"' report/report.json
}
