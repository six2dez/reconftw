#!/usr/bin/env bats

setup() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export TEST_DOMAIN="exportcli.example.com"
  export TARGET_DIR="$SCRIPTPATH/Recon/$TEST_DOMAIN"
  mkdir -p "$TARGET_DIR"/{subdomains,webs,hosts,nuclei_output,report,.log}
  echo "a.$TEST_DOMAIN" > "$TARGET_DIR/subdomains/subdomains.txt"
  echo "https://a.$TEST_DOMAIN" > "$TARGET_DIR/webs/webs_all.txt"
  echo "1.1.1.1" > "$TARGET_DIR/hosts/ips.txt"
  echo '{"template-id":"tpl-h","matcher-name":"m1","type":"http","info":{"severity":"high","name":"h"},"matched-at":"https://a.'"$TEST_DOMAIN"'"}' > "$TARGET_DIR/nuclei_output/high_json.txt"
}

after_each() {
  rm -rf "$TARGET_DIR"
}

@test "export cli json creates jsonl artifacts" {
  run timeout 30 bash "$SCRIPTPATH/reconftw.sh" -d "$TEST_DOMAIN" --report-only --export json
  [ "$status" -eq 0 ]
  [ -f "$TARGET_DIR/report/findings_normalized.jsonl" ]
}

@test "export cli csv creates csv artifacts" {
  run timeout 30 bash "$SCRIPTPATH/reconftw.sh" -d "$TEST_DOMAIN" --report-only --export csv
  [ "$status" -eq 0 ]
  [ -f "$TARGET_DIR/report/findings.csv" ]
}
