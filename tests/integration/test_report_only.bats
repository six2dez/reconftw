#!/usr/bin/env bats

setup() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export TEST_DOMAIN="reportonly.example.com"
  export TARGET_DIR="$SCRIPTPATH/Recon/$TEST_DOMAIN"
  mkdir -p "$TARGET_DIR"/{subdomains,webs,hosts,nuclei_output,report,.log}
  echo "a.$TEST_DOMAIN" > "$TARGET_DIR/subdomains/subdomains.txt"
  echo "https://a.$TEST_DOMAIN" > "$TARGET_DIR/webs/webs_all.txt"
  echo "1.1.1.1" > "$TARGET_DIR/hosts/ips.txt"
  echo '{"template-id":"tpl-c","info":{"severity":"critical"},"matched-at":"https://a.'"$TEST_DOMAIN"'"}' > "$TARGET_DIR/nuclei_output/critical_json.txt"
  echo "[tpl-c] [http] [critical] https://a.$TEST_DOMAIN" > "$TARGET_DIR/nuclei_output/critical.txt"
}

after_each() {
  rm -rf "$TARGET_DIR"
}

@test "report-only rebuilds report artifacts" {
  run timeout 30 bash "$SCRIPTPATH/reconftw.sh" -d "$TEST_DOMAIN" --report-only --export all
  [ "$status" -eq 0 ]
  [ -f "$TARGET_DIR/report/report.json" ]
  [ -f "$TARGET_DIR/report/index.html" ]
  [ -f "$TARGET_DIR/report/findings.csv" ]
}
