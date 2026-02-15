#!/usr/bin/env bats

setup() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export LOGFILE="/dev/null"
  export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''

  export TEST_DIR="$BATS_TEST_TMPDIR/reconftw_new_tools"
  mkdir -p "$TEST_DIR"
  export dir="$TEST_DIR/target.example.com"
  export called_fn_dir="$dir/.called_fn"
  mkdir -p "$called_fn_dir" "$dir"
  cd "$dir"

  export MOCK_BIN="$TEST_DIR/mockbin"
  mkdir -p "$MOCK_BIN"
  export PATH="$MOCK_BIN:$PATH"

  source "$project_root/reconftw.sh" --source-only

  export domain="target.example.com"
  export DIFF=false
  export AXIOM=false
}

teardown() {
  [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

@test "ssti uses TInjA engine and writes compatible output" {
  mkdir -p gf .tmp vulns
  printf 'https://target.example.com/?q=test\n' > gf/ssti.txt

  cat > "$MOCK_BIN/TInjA" <<'SH'
#!/usr/bin/env bash
report_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reportpath)
      report_dir="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$report_dir"
printf '%s\n' '{"url":"https://target.example.com/?q=FUZZ","isWebpageVulnerable":true,"certainty":"high","parameters":[]}' > "${report_dir}/mock_Report.jsonl"
SH
  chmod +x "$MOCK_BIN/TInjA"

  export SSTI=true
  export SSTI_ENGINE="TInjA"
  export TInjA_RATELIMIT=0
  export TInjA_TIMEOUT=15
  export DEEP=false
  export DEEP_LIMIT=500

  run ssti
  [ "$status" -eq 0 ]
  [ -s "vulns/ssti.txt" ]
  grep -q "target.example.com" "vulns/ssti.txt"
}

@test "brokenLinks supports second-order engine" {
  mkdir -p webs .tmp vulns
  printf 'https://target.example.com\n' > webs/webs_all.txt
  printf '{"LogNon200Queries":{"script":"src"}}\n' > "$TEST_DIR/takeover.json"

  cat > "$MOCK_BIN/second-order" <<'SH'
#!/usr/bin/env bash
out_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -output)
      out_dir="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$out_dir"
printf '%s\n' '{"https://target.example.com":{"script[src]":["https://cdn.dead.example.org/app.js"]}}' > "${out_dir}/non-200-url-attributes.json"
SH
  chmod +x "$MOCK_BIN/second-order"

  export BROKENLINKS=true
  export BROKENLINKS_ENGINE="second-order"
  export SECOND_ORDER_CONFIG="$TEST_DIR/takeover.json"
  export SECOND_ORDER_DEPTH=1
  export SECOND_ORDER_THREADS=4
  export SECOND_ORDER_INSECURE=false

  run brokenLinks
  [ "$status" -eq 0 ]
  [ -s "vulns/brokenLinks.txt" ]
  grep -q "cdn.dead.example.org" "vulns/brokenLinks.txt"
}

@test "favirecon_tech stores normalized technology findings" {
  mkdir -p webs .tmp
  printf 'https://target.example.com\n' > webs/webs_all.txt

  cat > "$MOCK_BIN/favirecon" <<'SH'
#!/usr/bin/env bash
outfile=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      outfile="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s\n' '{"URL":"https://target.example.com","Name":"GitLab","Hash":"12345"}' > "$outfile"
SH
  chmod +x "$MOCK_BIN/favirecon"

  export FAVIRECON=true
  export FAVIRECON_CONCURRENCY=10
  export FAVIRECON_TIMEOUT=10
  export FAVIRECON_RATE_LIMIT=0

  run favirecon_tech
  [ "$status" -eq 0 ]
  [ -s "webs/favirecon.txt" ]
  grep -q "GitLab" "webs/favirecon.txt"
}

@test "apileaks integrates postleaksNg output" {
  mkdir -p osint
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/SwaggerSpy/venv/bin" "$tools/SwaggerSpy" "$tools/postleaksNg/.venv/bin"

  cat > "$MOCK_BIN/porch-pirate" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'https://postman.initial.example.com/api'
SH
  chmod +x "$MOCK_BIN/porch-pirate"

  cat > "$tools/SwaggerSpy/venv/bin/python3" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'URL https://swagger.example.com/openapi.json'
SH
  chmod +x "$tools/SwaggerSpy/venv/bin/python3"
  printf '%s\n' 'print("mock")' > "$tools/SwaggerSpy/swaggerspy.py"

  cat > "$tools/postleaksNg/.venv/bin/postleaksNg" <<'SH'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      out="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$out"
printf '%s\n' '{"url":"https://postman.new.example.com/path"}' > "$out/postleaks.json"
SH
  chmod +x "$tools/postleaksNg/.venv/bin/postleaksNg"

  cat > "$MOCK_BIN/trufflehog" <<'SH'
#!/usr/bin/env bash
printf '%s\n' '{"DetectorName":"mock"}'
SH
  chmod +x "$MOCK_BIN/trufflehog"

  export API_LEAKS=true
  export OSINT=true
  export API_LEAKS_POSTLEAKS=true
  export POSTLEAKS_THREADS=2

  run apileaks
  [ "$status" -eq 0 ]
  [ -s "osint/postman_leaks.txt" ]
  grep -q "postman.new.example.com" "osint/postman_leaks.txt"
}

@test "nuclei_dast is forced on when VULNS_GENERAL=true" {
  mkdir -p webs .tmp gf vulns nuclei_output
  printf 'https://target.example.com\n' > webs/webs_all.txt

  # Mock nuclei: write one JSON line when -o <file> is used; no-op for update calls.
  cat > "$MOCK_BIN/nuclei" <<'SH'
#!/usr/bin/env bash
outfile=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      outfile="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$outfile" ]]; then
  mkdir -p "$(dirname "$outfile")"
  printf '%s\n' '{"template-id":"mock-dast","type":"http","info":{"severity":"high"},"host":"https://target.example.com","matched-at":"https://target.example.com/"}' > "$outfile"
fi
exit 0
SH
  chmod +x "$MOCK_BIN/nuclei"

  export VULNS_GENERAL=true
  export NUCLEI_DAST=false
  export NUCLEI_RATELIMIT=10
  export DEEP=false
  export DEEP_LIMIT2=1500
  export NUCLEI_TEMPLATES_PATH="$TEST_DIR/nuclei-templates"
  mkdir -p "$NUCLEI_TEMPLATES_PATH/dast"

  run nuclei_dast
  [ "$status" -eq 0 ]
  [ -s "nuclei_output/dast_json.txt" ]
  [ -s "vulns/nuclei_dast.txt" ]
  grep -q "mock-dast" "vulns/nuclei_dast.txt"
}
