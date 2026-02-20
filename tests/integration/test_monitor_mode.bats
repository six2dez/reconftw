#!/usr/bin/env bats

setup() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export TEST_DIR="$BATS_TEST_TMPDIR/monitor_int"
  export domain="example.com"
  export dir="$TEST_DIR/$domain"
  mkdir -p "$dir"/{subdomains,webs,nuclei_output,report,.incremental/history,.log}
  cd "$dir"

  # shellcheck source=/dev/null
  source "$SCRIPTPATH/reconftw.sh" --source-only
  export MONITOR_MODE=true
  export ALERT_SUPPRESSION=true
}

teardown() {
  cd /
  rm -rf "$TEST_DIR"
}

@test "monitor_snapshot creates history and delta artifacts" {
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle1/subdomains/subdomains.txt" subdomains/subdomains.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle1/webs/webs_all.txt" webs/webs_all.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle1/nuclei_output/high.txt" nuclei_output/high.txt
  : > nuclei_output/critical.txt
  MONITOR_CYCLE=1 monitor_snapshot

  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle2/subdomains/subdomains.txt" subdomains/subdomains.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle2/webs/webs_all.txt" webs/webs_all.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle2/nuclei_output/high.txt" nuclei_output/high.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle2/nuclei_output/critical.txt" nuclei_output/critical.txt
  MONITOR_CYCLE=2 run monitor_snapshot
  [ "$status" -eq 0 ]

  latest_dir=".incremental/history/$(readlink .incremental/history/latest)"
  [ -f "$latest_dir/delta.json" ]
  [ -f "$latest_dir/alerts.json" ]
}
