#!/usr/bin/env bats

setup() {
  source "$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/../helpers/common.bash"
  setup_recon_env

  export TEST_DIR="$(mktemp -d)"
  export domain="example.com"
  export dir="$TEST_DIR/$domain"
  export MONITOR_MODE=true
  export ALERT_SUPPRESSION=true
  export ALERT_SEEN_FILE="$dir/.incremental/alerts_seen.hashes"
  mkdir -p "$dir"/{subdomains,webs,nuclei_output,.incremental/history,report,.log}
  cd "$dir"
  runtime="1 minutes 0 seconds"
}

teardown() {
  cd /
  rm -rf "$TEST_DIR"
}

@test "monitor_snapshot creates baseline and latest pointer" {
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle1/subdomains/subdomains.txt" subdomains/subdomains.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle1/webs/webs_all.txt" webs/webs_all.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle1/nuclei_output/high.txt" nuclei_output/high.txt
  : > nuclei_output/critical.txt

  export MONITOR_CYCLE=1
  run monitor_snapshot
  [ "$status" -eq 0 ]
  [ -L .incremental/history/latest ] || [ -d .incremental/history/latest ]

  latest_dir=".incremental/history/$(readlink .incremental/history/latest)"
  [ -f "$latest_dir/delta.json" ]
}

@test "monitor_snapshot detects deltas between cycles" {
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle1/subdomains/subdomains.txt" subdomains/subdomains.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle1/webs/webs_all.txt" webs/webs_all.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle1/nuclei_output/high.txt" nuclei_output/high.txt
  : > nuclei_output/critical.txt
  export MONITOR_CYCLE=1
  monitor_snapshot

  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle2/subdomains/subdomains.txt" subdomains/subdomains.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle2/webs/webs_all.txt" webs/webs_all.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle2/nuclei_output/high.txt" nuclei_output/high.txt
  cp "$SCRIPTPATH/tests/fixtures/monitor_cycle2/nuclei_output/critical.txt" nuclei_output/critical.txt
  export MONITOR_CYCLE=2
  run monitor_snapshot
  [ "$status" -eq 0 ]

  latest_dir=".incremental/history/$(readlink .incremental/history/latest)"
  [ -f "$latest_dir/subdomains_new.txt" ]
  [ -f "$latest_dir/webs_new.txt" ]
  grep -q "c.example.com" "$latest_dir/subdomains_new.txt"
}

@test "alert fingerprint suppression deduplicates repeated alerts" {
  export ALERT_SEEN_FILE="$dir/.incremental/alerts_seen.hashes"
  run _monitor_mark_alert_seen "critical" "https://a.example.com"
  [ "$status" -eq 0 ]
  run _monitor_mark_alert_seen "critical" "https://a.example.com"
  [ "$status" -eq 1 ]
}

@test "monitor_snapshot honors MONITOR_MIN_SEVERITY=medium and includes medium deltas" {
  mkdir -p nuclei_output
  export MONITOR_MIN_SEVERITY="medium"

  printf 'a.example.com\n' > subdomains/subdomains.txt
  printf 'https://a.example.com\n' > webs/webs_all.txt
  printf '[tpl-c] [http] [critical] https://a.example.com\n' > nuclei_output/critical.txt
  printf '[tpl-m] [http] [medium] https://a.example.com\n' > nuclei_output/medium.txt

  export MONITOR_CYCLE=1
  monitor_snapshot

  printf 'b.example.com\n' >> subdomains/subdomains.txt
  printf 'https://b.example.com\n' >> webs/webs_all.txt
  printf '[tpl-m] [http] [medium] https://b.example.com\n' >> nuclei_output/medium.txt

  export MONITOR_CYCLE=2
  run monitor_snapshot
  [ "$status" -eq 0 ]

  latest_dir=".incremental/history/$(readlink .incremental/history/latest)"
  [ -f "$latest_dir/medium_new.txt" ]
  grep -q "b.example.com" "$latest_dir/medium_new.txt"
}
