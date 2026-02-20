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
  mkdir -p "$tools/SwaggerSpy/venv/bin" "$tools/SwaggerSpy"

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

  cat > "$MOCK_BIN/postleaksNg" <<'SH'
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
  chmod +x "$MOCK_BIN/postleaksNg"

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

@test "github_leaks searches GitHub-wide secrets with ghleaks" {
  mkdir -p osint
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/ghleaks"

  # Create mock ghleaks binary
  cat > "$tools/ghleaks/ghleaks" <<'SH'
#!/usr/bin/env bash
report=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report)
      report="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$report" ]]; then
  printf '%s\n' '{"RuleID":"generic-api-key","Match":"AKIA1234567890ABCDEF","File":"config.yml","URL":"https://github.com/example/repo/blob/main/config.yml"}' > "$report"
fi
SH
  chmod +x "$tools/ghleaks/ghleaks"

  # Create GitHub tokens file
  printf '%s\n' 'ghp_mock_token_12345' > "$TEST_DIR/.github_tokens"
  export GITHUB_TOKENS="$TEST_DIR/.github_tokens"

  export GITHUB_LEAKS=true
  export OSINT=true
  export DEEP=false
  export GHLEAKS_THREADS=2

  run github_leaks
  [ "$status" -eq 0 ]
  [ -s "osint/github_leaks.json" ]
  grep -q "generic-api-key" "osint/github_leaks.json"
}

@test "github_leaks adds --exhaustive flag in DEEP mode" {
  mkdir -p osint
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/ghleaks"

  # Create mock ghleaks that records its arguments
  cat > "$tools/ghleaks/ghleaks" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$@" > /tmp/ghleaks_args.txt
report=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report)
      report="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$report" ]]; then
  printf '%s\n' '{}' > "$report"
fi
SH
  chmod +x "$tools/ghleaks/ghleaks"

  printf '%s\n' 'ghp_mock_token_12345' > "$TEST_DIR/.github_tokens"
  export GITHUB_TOKENS="$TEST_DIR/.github_tokens"

  export GITHUB_LEAKS=true
  export OSINT=true
  export DEEP=true
  export GHLEAKS_THREADS=2

  run github_leaks
  [ "$status" -eq 0 ]
  grep -q "\-\-exhaustive" /tmp/ghleaks_args.txt
  rm -f /tmp/ghleaks_args.txt
}

@test "service_fingerprint writes fingerprintx artifacts from naabu input" {
  mkdir -p hosts .tmp
  printf '%s\n' '10.10.10.10:22' > hosts/naabu_open.txt

  cat > "$MOCK_BIN/fingerprintx" <<'SH'
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
printf '%s\n' '{"host":"10.10.10.10","port":22,"protocol":"ssh"}' > "$outfile"
SH
  chmod +x "$MOCK_BIN/fingerprintx"

  export SERVICE_FINGERPRINT=true
  export SERVICE_FINGERPRINT_ENGINE="fingerprintx"
  export SERVICE_FINGERPRINT_TIMEOUT_MS=500
  export AXIOM=false

  run service_fingerprint
  [ "$status" -eq 0 ]
  [ -s "hosts/fingerprintx.jsonl" ]
  [ -s "hosts/fingerprintx.txt" ]
  grep -q "10.10.10.10:22" "hosts/fingerprintx.txt"
}

@test "spraying supports brutus engine with fingerprintx json input" {
  mkdir -p hosts vulns .tmp
  printf '%s\n' 'Host: 10.10.10.10 () Ports: 22/open/tcp//ssh///' > hosts/portscan_active.gnmap
  printf '%s\n' '{"host":"10.10.10.10","port":22,"protocol":"ssh"}' > hosts/fingerprintx.jsonl

  cat > "$MOCK_BIN/brutus" <<'SH'
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
cat >/dev/null
printf '%s\n' '{"protocol":"ssh","target":"10.10.10.10:22","username":"root","password":"toor"}' > "$outfile"
SH
  chmod +x "$MOCK_BIN/brutus"

  export SPRAY=true
  export SPRAY_ENGINE="brutus"
  export SPRAY_BRUTUS_ONLY_DEEP=false
  export DEEP=false

  run spraying
  [ "$status" -eq 0 ]
  [ -s "vulns/brutus.jsonl" ]
  grep -q "10.10.10.10:22" "vulns/brutus.jsonl"
}

@test "llm_probe writes julius jsonl output" {
  mkdir -p webs .tmp
  printf '%s\n' 'https://llm.target.example.com' > webs/webs_all.txt

  cat > "$MOCK_BIN/julius" <<'SH'
#!/usr/bin/env bash
printf '%s\n' '{"target":"https://llm.target.example.com","provider":"openai-compatible","probe":"chat-completions"}'
SH
  chmod +x "$MOCK_BIN/julius"

  export LLM_PROBE=true
  export LLM_PROBE_AUGUSTUS=false

  run llm_probe
  [ "$status" -eq 0 ]
  [ -s "webs/llm_probe.jsonl" ]
  [ -s "webs/llm_probe.txt" ]
  grep -q "openai-compatible" "webs/llm_probe.txt"
}

@test "param_discovery uses axiom arjun when AXIOM=true" {
  mkdir -p webs .tmp
  printf '%s\n' 'https://target.example.com/path' > webs/url_extract_nodupes.txt

  cat > "$MOCK_BIN/axiom-scan" <<'SH'
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
printf '%s\n' 'https://target.example.com/path?a=1&b=2' > "$outfile"
printf '%s\n' ' Scanning 0/1: https://target.example.com/path'
printf '%s\n' ' Parameters found: a, b'
exit 0
SH
  chmod +x "$MOCK_BIN/axiom-scan"

  export AXIOM=true
  export AXIOM_EXTRA_ARGS=""
  export PARAM_DISCOVERY=true
  export ARJUN_THREADS=5

  run param_discovery
  [ "$status" -eq 0 ]
  [ -s "webs/params_discovered.txt" ]
  grep -q "URL: https://target.example.com/path?a=1&b=2" "webs/params_discovered.txt"
  grep -q "PARAM: a" "webs/params_discovered.txt"
  grep -q "PARAM: b" "webs/params_discovered.txt"
}

@test "param_discovery falls back to local arjun when axiom arjun fails" {
  mkdir -p webs .tmp
  printf '%s\n' 'https://target.example.com/path' > webs/url_extract_nodupes.txt

  cat > "$MOCK_BIN/axiom-scan" <<'SH'
#!/usr/bin/env bash
exit 1
SH
  chmod +x "$MOCK_BIN/axiom-scan"

  cat > "$MOCK_BIN/arjun" <<'SH'
#!/usr/bin/env bash
outfile=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -oT)
      outfile="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s\n' 'https://target.example.com/path?x=1' > "$outfile"
exit 0
SH
  chmod +x "$MOCK_BIN/arjun"

  export AXIOM=true
  export AXIOM_EXTRA_ARGS=""
  export PARAM_DISCOVERY=true
  export ARJUN_THREADS=5

  run param_discovery
  [ "$status" -eq 0 ]
  [[ "$output" == *"falling back to local arjun"* ]]
  [ -s "webs/params_discovered.txt" ]
  grep -q "URL: https://target.example.com/path?x=1" "webs/params_discovered.txt"
  grep -q "PARAM: x" "webs/params_discovered.txt"
}

@test "param_discovery local mode uses arjun text output" {
  mkdir -p webs .tmp
  printf '%s\n' 'https://target.example.com/path' > webs/url_extract_nodupes.txt

  cat > "$MOCK_BIN/arjun" <<'SH'
#!/usr/bin/env bash
outfile=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -oT)
      outfile="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s\n' 'http://testaspnet.vulnweb.com/login.aspx?__VIEWSTATE=3698&token=abc' > "$outfile"
exit 0
SH
  chmod +x "$MOCK_BIN/arjun"

  export AXIOM=false
  export PARAM_DISCOVERY=true
  export ARJUN_THREADS=5

  run param_discovery
  [ "$status" -eq 0 ]
  [ -s "webs/params_discovered.txt" ]
  grep -q "URL: http://testaspnet.vulnweb.com/login.aspx?__VIEWSTATE=3698&token=abc" "webs/params_discovered.txt"
  grep -q "PARAM: __VIEWSTATE" "webs/params_discovered.txt"
  grep -q "PARAM: token" "webs/params_discovered.txt"
}
