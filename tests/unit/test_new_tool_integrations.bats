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

@test "apileaks merges scoped leak URLs into url_extract" {
  mkdir -p osint
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/SwaggerSpy/venv/bin" "$tools/SwaggerSpy"
  export outOfScope_file="$TEST_DIR/out_of_scope.txt"
  printf '%s\n' 'swagger.target.example.com' > "$outOfScope_file"

  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
  quiet=true
  shift
fi
outfile="$1"
mkdir -p "$(dirname "$outfile")"
touch "$outfile"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fxq -- "$line" "$outfile"; then
    printf '%s\n' "$line" >> "$outfile"
    if [[ "$quiet" != true ]]; then
      printf '%s\n' "$line"
    fi
  fi
done
SH
  chmod +x "$MOCK_BIN/anew"

  cat > "$MOCK_BIN/urless" <<'SH'
#!/usr/bin/env bash
cat
SH
  chmod +x "$MOCK_BIN/urless"

  cat > "$MOCK_BIN/porch-pirate" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'https://api.target.example.com/v1/users?first=1'
SH
  chmod +x "$MOCK_BIN/porch-pirate"

  cat > "$tools/SwaggerSpy/venv/bin/python3" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'URL https://swagger.target.example.com/openapi.json'
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
printf '%s\n' '{"url":"https://postman.target.example.com/path?token=1"}' > "$out/postleaks.json"
printf '%s\n' '{"url":"https://outside.example.net/path?next=target.example.com"}' > "$out/postleaks-outside.json"
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
  grep -q "postman.target.example.com" "osint/postman_leaks.txt"
  [ -s "webs/url_extract.txt" ]
  grep -q '^https://api.target.example.com/v1/users?first=1$' "webs/url_extract.txt"
  grep -q '^https://postman.target.example.com/path?token=1$' "webs/url_extract.txt"
  ! grep -q 'outside.example.net' "webs/url_extract.txt"
  ! grep -q 'swagger.target.example.com' "webs/url_extract.txt"
}

@test "jschecks merges only scoped JS-discovered URLs into url_extract" {
  mkdir -p js webs .tmp subdomains
  printf '%s\n' 'https://target.example.com/app.js' > .tmp/url_extract_js.txt
  printf '%s\n' 'target.example.com' > subdomains/subdomains.txt
  export outOfScope_file="$TEST_DIR/out_of_scope_js.txt"
  printf '%s\n' 'graphql.target.example.com' > "$outOfScope_file"

  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
  quiet=true
  shift
fi
outfile="$1"
mkdir -p "$(dirname "$outfile")"
touch "$outfile"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fxq -- "$line" "$outfile"; then
    printf '%s\n' "$line" >> "$outfile"
    if [[ "$quiet" != true ]]; then
      printf '%s\n' "$line"
    fi
  fi
done
SH
  chmod +x "$MOCK_BIN/anew"

  cat > "$MOCK_BIN/urless" <<'SH'
#!/usr/bin/env bash
cat
SH
  chmod +x "$MOCK_BIN/urless"

  cat > "$MOCK_BIN/subjs" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'https://api.target.example.com/v1/users?id=1'
printf '%s\n' 'https://outside.example.net/relay?next=target.example.com'
printf '%s\n' 'https://target.example.com/logo.png'
printf '%s\n' 'https://target.example.com/app2.js'
SH
  chmod +x "$MOCK_BIN/subjs"

  cat > "$MOCK_BIN/httpx" <<'SH'
#!/usr/bin/env bash
while IFS= read -r url; do
  [[ -z "$url" ]] && continue
  printf '%s [200] [text/javascript]\n' "$url"
done
SH
  chmod +x "$MOCK_BIN/httpx"

  cat > "$MOCK_BIN/interlace" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  chmod +x "$MOCK_BIN/interlace"

  cat > "$MOCK_BIN/xnLinkFinder" <<'SH'
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
printf '%s\n' 'https://graphql.target.example.com/query' > "$outfile"
printf '%s\n' 'https://evil.example.org/path?host=target.example.com' >> "$outfile"
SH
  chmod +x "$MOCK_BIN/xnLinkFinder"

  cat > "$MOCK_BIN/jsluice" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  chmod +x "$MOCK_BIN/jsluice"

  cat > "$MOCK_BIN/mantra" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  chmod +x "$MOCK_BIN/mantra"

  cat > "$MOCK_BIN/trufflehog" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  chmod +x "$MOCK_BIN/trufflehog"

  export JSCHECKS=true
  export AXIOM=false
  export HTTPX_TIMEOUT=5
  export HTTPX_THREADS=5
  export HTTPX_RATELIMIT=0
  export INTERLACE_THREADS=2
  export XNLINKFINDER_DEPTH=1

  run jschecks
  [ "$status" -eq 0 ]
  [ -s "webs/url_extract.txt" ]
  grep -q '^https://api.target.example.com/v1/users?id=1$' "webs/url_extract.txt"
  ! grep -q 'outside.example.net' "webs/url_extract.txt"
  ! grep -q 'graphql.target.example.com' "webs/url_extract.txt"
}

@test "s3buckets uses cloud_enum and writes cloud_enum artifacts" {
  mkdir -p subdomains .tmp
  printf '%s\n' 'target.example.com' > subdomains/subdomains.txt

  export S3BUCKETS=true
  export CLOUD_ENUM_S3_PROFILE="optimized"
  export CLOUD_ENUM_S3_THREADS=7
  export ASSET_STORE=false
  export AXIOM=false
  export multi=""
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/cloud_enum/venv/bin" "$tools/cloud_enum/enum_tools"
  printf '%s\n' 'corp' > "$tools/cloud_enum/enum_tools/fuzz.txt"

  printf '%s\n' '1.1.1.1' > "$TEST_DIR/resolvers.txt"
  export resolvers="$TEST_DIR/resolvers.txt"

  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
  quiet=true
  shift
fi
outfile="$1"
touch "$outfile"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fxq -- "$line" "$outfile"; then
    printf '%s\n' "$line" >> "$outfile"
    if [[ "$quiet" != true ]]; then
      printf '%s\n' "$line"
    fi
  fi
done
SH
  chmod +x "$MOCK_BIN/anew"

  cat > "$MOCK_BIN/unfurl" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "format" ]] && [[ "${2:-}" == "%r" ]]; then
  while IFS= read -r line; do
    printf '%s\n' "${line%%.*}"
  done
else
  cat
fi
SH
  chmod +x "$MOCK_BIN/unfurl"

  cat > "$MOCK_BIN/s3scanner" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'scan-bucket'
SH
  chmod +x "$MOCK_BIN/s3scanner"

  cat > "$MOCK_BIN/trufflehog" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TEST_DIR/trufflehog_calls.txt"
printf '%s\n' '{"DetectorName":"mock"}'
SH
  chmod +x "$MOCK_BIN/trufflehog"

  cat > "$tools/cloud_enum/cloud_enum.py" <<'PY'
print("mock")
PY

  cat > "$tools/cloud_enum/venv/bin/python3" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$TEST_DIR/cloud_enum_args.txt"
logfile=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -l)
      logfile="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$logfile")"
cat > "$logfile" <<'JSON'
#### CLOUD_ENUM TEST ####
{"platform":"aws","msg":"OPEN S3 BUCKET","target":"http://demo.s3.amazonaws.com","access":"public"}
{"platform":"gcp","msg":"OPEN GOOGLE BUCKET","target":"http://storage.googleapis.com/public-gcp","access":"public"}
{"platform":"gcp","msg":"Protected Google Bucket","target":"http://storage.googleapis.com/protected-gcp","access":"protected"}
JSON
exit 0
SH
  chmod +x "$tools/cloud_enum/venv/bin/python3"

  run s3buckets
  [ "$status" -eq 0 ]
  [ -s "subdomains/.cloud_enum_s3.jsonl" ]
  grep -q 'demo.s3.amazonaws.com' "subdomains/.cloud_enum_s3.jsonl"
  grep -q 'storage.googleapis.com/public-gcp' "subdomains/.cloud_enum_s3.jsonl"
  [ -s "subdomains/cloud_assets.txt" ]
  grep -q '^http://demo.s3.amazonaws.com$' "subdomains/cloud_assets.txt"
  [ -s "subdomains/cloud_enum_buckets_trufflehog.txt" ]
  grep -q -- '--bucket=demo' "$TEST_DIR/trufflehog_calls.txt"
  grep -q -- '--project-id=public-gcp' "$TEST_DIR/trufflehog_calls.txt"
  grep -Eq -- '(^| )-qs( |$)' "$TEST_DIR/cloud_enum_args.txt"
  grep -Eq -- "(^| )-m $tools/cloud_enum/enum_tools/fuzz.txt( |$)" "$TEST_DIR/cloud_enum_args.txt"
  grep -Eq -- "(^| )-b $tools/cloud_enum/enum_tools/fuzz.txt( |$)" "$TEST_DIR/cloud_enum_args.txt"
}

@test "s3buckets falls back to uv run when local venv is missing" {
  mkdir -p subdomains .tmp
  printf '%s\n' 'target.example.com' > subdomains/subdomains.txt

  export S3BUCKETS=true
  export CLOUD_ENUM_S3_PROFILE="optimized"
  export CLOUD_ENUM_S3_THREADS=7
  export ASSET_STORE=false
  export AXIOM=false
  export multi=""
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/cloud_enum"
  printf '%s\n' 'print("mock")' > "$tools/cloud_enum/cloud_enum.py"
  printf '%s\n' 'dnspython' > "$tools/cloud_enum/requirements.txt"

  printf '%s\n' '1.1.1.1' > "$TEST_DIR/resolvers.txt"
  export resolvers="$TEST_DIR/resolvers.txt"

  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
  quiet=true
  shift
fi
outfile="$1"
touch "$outfile"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fxq -- "$line" "$outfile"; then
    printf '%s\n' "$line" >> "$outfile"
    if [[ "$quiet" != true ]]; then
      printf '%s\n' "$line"
    fi
  fi
done
SH
  chmod +x "$MOCK_BIN/anew"

  cat > "$MOCK_BIN/unfurl" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "format" ]] && [[ "${2:-}" == "%r" ]]; then
  while IFS= read -r line; do
    printf '%s\n' "${line%%.*}"
  done
else
  cat
fi
SH
  chmod +x "$MOCK_BIN/unfurl"

  cat > "$MOCK_BIN/s3scanner" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'scan-bucket'
SH
  chmod +x "$MOCK_BIN/s3scanner"

  cat > "$MOCK_BIN/trufflehog" <<'SH'
#!/usr/bin/env bash
printf '%s\n' '{"DetectorName":"mock"}'
SH
  chmod +x "$MOCK_BIN/trufflehog"

  cat > "$MOCK_BIN/uv" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$TEST_DIR/cloud_enum_uv_args.txt"
logfile=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -l)
      logfile="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$logfile")"
cat > "$logfile" <<'JSON'
{"platform":"aws","msg":"OPEN S3 BUCKET","target":"http://demo.s3.amazonaws.com","access":"public"}
JSON
exit 0
SH
  chmod +x "$MOCK_BIN/uv"

  run s3buckets
  [ "$status" -eq 0 ]
  [[ "$output" != *"runtime missing"* ]]
  [ -s "$TEST_DIR/cloud_enum_uv_args.txt" ]
  grep -Eq -- '(^| )run( |$)' "$TEST_DIR/cloud_enum_uv_args.txt"
  grep -Fq -- "--directory $tools/cloud_enum" "$TEST_DIR/cloud_enum_uv_args.txt"
  grep -Eq -- '(^| )-f json( |$)' "$TEST_DIR/cloud_enum_uv_args.txt"
  grep -Eq -- "(^| )-m $tools/cloud_enum/cloud_enum.py( |$)" "$TEST_DIR/cloud_enum_uv_args.txt"
  grep -Eq -- "(^| )-b $tools/cloud_enum/cloud_enum.py( |$)" "$TEST_DIR/cloud_enum_uv_args.txt"
  [ -s "subdomains/.cloud_enum_s3.jsonl" ]
  grep -q 'demo.s3.amazonaws.com' "subdomains/.cloud_enum_s3.jsonl"
}

@test "s3buckets exhaustive profile uses cloud_enum fuzz.txt mutations" {
  mkdir -p subdomains .tmp
  printf '%s\n' 'target.example.com' > subdomains/subdomains.txt

  export S3BUCKETS=true
  export CLOUD_ENUM_S3_PROFILE="exhaustive"
  export CLOUD_ENUM_S3_THREADS=7
  export ASSET_STORE=false
  export AXIOM=false
  export multi=""
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/cloud_enum/venv/bin" "$tools/cloud_enum/enum_tools"
  printf '%s\n' 'corp' > "$tools/cloud_enum/enum_tools/fuzz.txt"

  printf '%s\n' '1.1.1.1' > "$TEST_DIR/resolvers.txt"
  export resolvers="$TEST_DIR/resolvers.txt"

  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
  quiet=true
  shift
fi
outfile="$1"
touch "$outfile"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fxq -- "$line" "$outfile"; then
    printf '%s\n' "$line" >> "$outfile"
    if [[ "$quiet" != true ]]; then
      printf '%s\n' "$line"
    fi
  fi
done
SH
  chmod +x "$MOCK_BIN/anew"

  cat > "$MOCK_BIN/unfurl" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "format" ]] && [[ "${2:-}" == "%r" ]]; then
  while IFS= read -r line; do
    printf '%s\n' "${line%%.*}"
  done
else
  cat
fi
SH
  chmod +x "$MOCK_BIN/unfurl"

  cat > "$MOCK_BIN/s3scanner" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'scan-bucket'
SH
  chmod +x "$MOCK_BIN/s3scanner"

  cat > "$MOCK_BIN/trufflehog" <<'SH'
#!/usr/bin/env bash
printf '%s\n' '{"DetectorName":"mock"}'
SH
  chmod +x "$MOCK_BIN/trufflehog"

  cat > "$tools/cloud_enum/cloud_enum.py" <<'PY'
print("mock")
PY

  cat > "$tools/cloud_enum/venv/bin/python3" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$TEST_DIR/cloud_enum_args_exhaustive.txt"
logfile=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -l)
      logfile="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
mkdir -p "$(dirname "$logfile")"
cat > "$logfile" <<'JSON'
{"platform":"aws","msg":"OPEN S3 BUCKET","target":"http://demo.s3.amazonaws.com","access":"public"}
JSON
exit 0
SH
  chmod +x "$tools/cloud_enum/venv/bin/python3"

  run s3buckets
  [ "$status" -eq 0 ]
  grep -Fq -- "-m $tools/cloud_enum/enum_tools/fuzz.txt" "$TEST_DIR/cloud_enum_args_exhaustive.txt"
  grep -Fq -- "-b $tools/cloud_enum/enum_tools/fuzz.txt" "$TEST_DIR/cloud_enum_args_exhaustive.txt"
  ! grep -Eq -- '(^| )-qs( |$)' "$TEST_DIR/cloud_enum_args_exhaustive.txt"
}

@test "s3buckets continues with s3scanner when cloud_enum fails" {
  mkdir -p subdomains .tmp
  printf '%s\n' 'target.example.com' > subdomains/subdomains.txt

  export S3BUCKETS=true
  export CLOUD_ENUM_S3_PROFILE="optimized"
  export CLOUD_ENUM_S3_THREADS=7
  export ASSET_STORE=false
  export AXIOM=false
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/cloud_enum/venv/bin" "$tools/cloud_enum"

  printf '%s\n' '1.1.1.1' > "$TEST_DIR/resolvers.txt"
  export resolvers="$TEST_DIR/resolvers.txt"

  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
  quiet=true
  shift
fi
outfile="$1"
touch "$outfile"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fxq -- "$line" "$outfile"; then
    printf '%s\n' "$line" >> "$outfile"
    if [[ "$quiet" != true ]]; then
      printf '%s\n' "$line"
    fi
  fi
done
SH
  chmod +x "$MOCK_BIN/anew"

  cat > "$MOCK_BIN/unfurl" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "format" ]] && [[ "${2:-}" == "%r" ]]; then
  while IFS= read -r line; do
    printf '%s\n' "${line%%.*}"
  done
else
  cat
fi
SH
  chmod +x "$MOCK_BIN/unfurl"

  cat > "$MOCK_BIN/s3scanner" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'scan-bucket-fallback'
SH
  chmod +x "$MOCK_BIN/s3scanner"

  cat > "$MOCK_BIN/trufflehog" <<'SH'
#!/usr/bin/env bash
printf '%s\n' '{"DetectorName":"mock"}'
SH
  chmod +x "$MOCK_BIN/trufflehog"

  cat > "$tools/cloud_enum/cloud_enum.py" <<'PY'
print("mock")
PY

  cat > "$tools/cloud_enum/venv/bin/python3" <<'SH'
#!/usr/bin/env bash
exit 1
SH
  chmod +x "$tools/cloud_enum/venv/bin/python3"

  run s3buckets
  [ "$status" -eq 0 ]
  [ -f "subdomains/.cloud_enum_s3.jsonl" ]
  [ ! -s "subdomains/.cloud_enum_s3.jsonl" ]
  [ -s "subdomains/s3buckets.txt" ]
  grep -q '^scan-bucket-fallback$' "subdomains/s3buckets.txt"
}

@test "cloud_enum_scan uses local cloud_enum runtime with optimized quickscan flags" {
  mkdir -p osint
  export OSINT=true
  export CLOUD_ENUM=true
  export ASSET_STORE=false
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/cloud_enum/venv/bin" "$tools/cloud_enum"

  printf '%s\n' '1.1.1.1' > "$TEST_DIR/resolvers.txt"
  export resolvers="$TEST_DIR/resolvers.txt"

  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
  quiet=true
  shift
fi
outfile="$1"
touch "$outfile"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fxq -- "$line" "$outfile"; then
    printf '%s\n' "$line" >> "$outfile"
    if [[ "$quiet" != true ]]; then
      printf '%s\n' "$line"
    fi
  fi
done
SH
  chmod +x "$MOCK_BIN/anew"

  cat > "$MOCK_BIN/unfurl" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "format" ]] && [[ "${2:-}" == "%r" ]]; then
  while IFS= read -r line; do
    printf '%s\n' "${line%%.*}"
  done
else
  cat
fi
SH
  chmod +x "$MOCK_BIN/unfurl"

  cat > "$tools/cloud_enum/cloud_enum.py" <<'PY'
print("mock")
PY

  cat > "$tools/cloud_enum/venv/bin/python3" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$TEST_DIR/cloud_enum_scan_args.txt"
printf '%s\n' 'OPEN S3 BUCKET: http://demo.s3.amazonaws.com'
exit 0
SH
  chmod +x "$tools/cloud_enum/venv/bin/python3"

  run cloud_enum_scan
  [ "$status" -eq 0 ]
  [ -s "osint/cloud_enum.txt" ]
  grep -q 'OPEN S3 BUCKET' "osint/cloud_enum.txt"
  grep -q -- 'cloud_enum.py' "$TEST_DIR/cloud_enum_scan_args.txt"
  grep -Eq -- '(^| )-qs( |$)' "$TEST_DIR/cloud_enum_scan_args.txt"
  grep -Eq -- "(^| )-m $tools/cloud_enum/cloud_enum.py( |$)" "$TEST_DIR/cloud_enum_scan_args.txt"
  grep -Eq -- "(^| )-b $tools/cloud_enum/cloud_enum.py( |$)" "$TEST_DIR/cloud_enum_scan_args.txt"
}

@test "cloud_enum_scan falls back to uv run when local venv is missing" {
  mkdir -p osint
  export OSINT=true
  export CLOUD_ENUM=true
  export ASSET_STORE=false
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/cloud_enum"
  printf '%s\n' 'print("mock")' > "$tools/cloud_enum/cloud_enum.py"
  printf '%s\n' 'dnspython' > "$tools/cloud_enum/requirements.txt"

  printf '%s\n' '1.1.1.1' > "$TEST_DIR/resolvers.txt"
  export resolvers="$TEST_DIR/resolvers.txt"

  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
  quiet=true
  shift
fi
outfile="$1"
touch "$outfile"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fxq -- "$line" "$outfile"; then
    printf '%s\n' "$line" >> "$outfile"
    if [[ "$quiet" != true ]]; then
      printf '%s\n' "$line"
    fi
  fi
done
SH
  chmod +x "$MOCK_BIN/anew"

  cat > "$MOCK_BIN/unfurl" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "format" ]] && [[ "${2:-}" == "%r" ]]; then
  while IFS= read -r line; do
    printf '%s\n' "${line%%.*}"
  done
else
  cat
fi
SH
  chmod +x "$MOCK_BIN/unfurl"

  cat > "$MOCK_BIN/uv" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$TEST_DIR/cloud_enum_scan_uv_args.txt"
printf '%s\n' 'OPEN S3 BUCKET: http://demo.s3.amazonaws.com'
exit 0
SH
  chmod +x "$MOCK_BIN/uv"

  run cloud_enum_scan
  [ "$status" -eq 0 ]
  [[ "$output" != *"runtime not found"* ]]
  [ -s "osint/cloud_enum.txt" ]
  grep -q 'OPEN S3 BUCKET' "osint/cloud_enum.txt"
  [ -s "$TEST_DIR/cloud_enum_scan_uv_args.txt" ]
  grep -Eq -- '(^| )run( |$)' "$TEST_DIR/cloud_enum_scan_uv_args.txt"
  grep -Fq -- "--directory $tools/cloud_enum" "$TEST_DIR/cloud_enum_scan_uv_args.txt"
  grep -Eq -- '(^| )-qs( |$)' "$TEST_DIR/cloud_enum_scan_uv_args.txt"
  grep -Eq -- "(^| )-m $tools/cloud_enum/cloud_enum.py( |$)" "$TEST_DIR/cloud_enum_scan_uv_args.txt"
  grep -Eq -- "(^| )-b $tools/cloud_enum/cloud_enum.py( |$)" "$TEST_DIR/cloud_enum_scan_uv_args.txt"
}

@test "cloud_enum_scan exhaustive profile uses local fuzz mutations file" {
  mkdir -p osint
  export OSINT=true
  export CLOUD_ENUM=true
  export ASSET_STORE=false
  export CLOUD_ENUM_S3_PROFILE="exhaustive"
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/cloud_enum/venv/bin" "$tools/cloud_enum/enum_tools"
  printf '%s\n' 'corp' > "$tools/cloud_enum/enum_tools/fuzz.txt"

  printf '%s\n' '1.1.1.1' > "$TEST_DIR/resolvers.txt"
  export resolvers="$TEST_DIR/resolvers.txt"

  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
  quiet=true
  shift
fi
outfile="$1"
touch "$outfile"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fxq -- "$line" "$outfile"; then
    printf '%s\n' "$line" >> "$outfile"
    if [[ "$quiet" != true ]]; then
      printf '%s\n' "$line"
    fi
  fi
done
SH
  chmod +x "$MOCK_BIN/anew"

  cat > "$MOCK_BIN/unfurl" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "format" ]] && [[ "${2:-}" == "%r" ]]; then
  while IFS= read -r line; do
    printf '%s\n' "${line%%.*}"
  done
else
  cat
fi
SH
  chmod +x "$MOCK_BIN/unfurl"

  cat > "$tools/cloud_enum/cloud_enum.py" <<'PY'
print("mock")
PY

  cat > "$tools/cloud_enum/venv/bin/python3" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$TEST_DIR/cloud_enum_scan_exhaustive_args.txt"
printf '%s\n' 'OPEN S3 BUCKET: http://demo.s3.amazonaws.com'
exit 0
SH
  chmod +x "$tools/cloud_enum/venv/bin/python3"

  run cloud_enum_scan
  [ "$status" -eq 0 ]
  [ -s "osint/cloud_enum.txt" ]
  grep -q 'OPEN S3 BUCKET' "osint/cloud_enum.txt"
  grep -Fq -- "-m $tools/cloud_enum/enum_tools/fuzz.txt" "$TEST_DIR/cloud_enum_scan_exhaustive_args.txt"
  grep -Fq -- "-b $tools/cloud_enum/enum_tools/fuzz.txt" "$TEST_DIR/cloud_enum_scan_exhaustive_args.txt"
  ! grep -Eq -- '(^| )-qs( |$)' "$TEST_DIR/cloud_enum_scan_exhaustive_args.txt"
}

@test "cloud_enum_scan exhaustive downgrades to optimized when fuzz file is missing" {
  mkdir -p osint
  export OSINT=true
  export CLOUD_ENUM=true
  export ASSET_STORE=false
  export CLOUD_ENUM_S3_PROFILE="exhaustive"
  export tools="$TEST_DIR/tools"
  mkdir -p "$tools/cloud_enum/venv/bin" "$tools/cloud_enum"

  printf '%s\n' '1.1.1.1' > "$TEST_DIR/resolvers.txt"
  export resolvers="$TEST_DIR/resolvers.txt"

  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
  quiet=true
  shift
fi
outfile="$1"
touch "$outfile"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fxq -- "$line" "$outfile"; then
    printf '%s\n' "$line" >> "$outfile"
    if [[ "$quiet" != true ]]; then
      printf '%s\n' "$line"
    fi
  fi
done
SH
  chmod +x "$MOCK_BIN/anew"

  cat > "$MOCK_BIN/unfurl" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "format" ]] && [[ "${2:-}" == "%r" ]]; then
  while IFS= read -r line; do
    printf '%s\n' "${line%%.*}"
  done
else
  cat
fi
SH
  chmod +x "$MOCK_BIN/unfurl"

  cat > "$tools/cloud_enum/cloud_enum.py" <<'PY'
print("mock")
PY

  cat > "$tools/cloud_enum/venv/bin/python3" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$TEST_DIR/cloud_enum_scan_missing_fuzz_args.txt"
exit 0
SH
  chmod +x "$tools/cloud_enum/venv/bin/python3"

  run cloud_enum_scan
  [ "$status" -eq 0 ]
  grep -q "using optimized" <<<"$output"
  [ -s "$TEST_DIR/cloud_enum_scan_missing_fuzz_args.txt" ]
  grep -Eq -- '(^| )-qs( |$)' "$TEST_DIR/cloud_enum_scan_missing_fuzz_args.txt"
  grep -Eq -- "(^| )-m $tools/cloud_enum/cloud_enum.py( |$)" "$TEST_DIR/cloud_enum_scan_missing_fuzz_args.txt"
  grep -Eq -- "(^| )-b $tools/cloud_enum/cloud_enum.py( |$)" "$TEST_DIR/cloud_enum_scan_missing_fuzz_args.txt"
}

@test "multi_osint executes cloud_enum_scan for each target" {
  export multi="multi-osint-test"
  export list="$TEST_DIR/targets.txt"
  printf '%s\n' 'one.example.com' 'two.example.com' > "$list"
  export SCRIPTPATH="$TEST_DIR"

  domain_info() { :; }
  ip_info() { :; }
  emails() { :; }
  google_dorks() { :; }
  github_repos() { :; }
  github_leaks() { :; }
  metadata() { :; }
  apileaks() { :; }
  third_party_misconfigs() { :; }
  zonetransfer() { :; }
  cloud_enum_scan() { printf '%s\n' "$domain" >> "$TEST_DIR/cloud_enum_scan_calls.txt"; }
  init_dns_resolver() { :; }
  enable_command_trace() { :; }
  end() { :; }

  run multi_osint
  [ "$status" -eq 0 ]
  [ -s "$TEST_DIR/cloud_enum_scan_calls.txt" ]
  [ "$(wc -l < "$TEST_DIR/cloud_enum_scan_calls.txt")" -eq 2 ]
  grep -q '^one.example.com$' "$TEST_DIR/cloud_enum_scan_calls.txt"
  grep -q '^two.example.com$' "$TEST_DIR/cloud_enum_scan_calls.txt"
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

@test "service_fingerprint writes nerva artifacts from naabu input" {
  mkdir -p hosts .tmp
  printf '%s\n' '10.10.10.10:22' > hosts/naabu_open.txt

  cat > "$MOCK_BIN/nerva" <<'SH'
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
  chmod +x "$MOCK_BIN/nerva"

  export SERVICE_FINGERPRINT=true
  export SERVICE_FINGERPRINT_ENGINE="nerva"
  export SERVICE_FINGERPRINT_TIMEOUT_MS=500
  export AXIOM=false

  run service_fingerprint
  [ "$status" -eq 0 ]
  [ -s "hosts/service_fingerprints.jsonl" ]
  [ -s "hosts/service_fingerprints.txt" ]
  grep -q "10.10.10.10:22" "hosts/service_fingerprints.txt"
}

@test "spraying supports brutus engine with service fingerprint json input" {
  mkdir -p hosts vulns .tmp
  printf '%s\n' 'Host: 10.10.10.10 () Ports: 22/open/tcp//ssh///' > hosts/portscan_active.gnmap
  printf '%s\n' '{"host":"10.10.10.10","port":22,"protocol":"ssh"}' > hosts/service_fingerprints.jsonl

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

@test "param_discovery skips in non-deep mode" {
  mkdir -p webs .tmp
  printf '%s\n' 'https://target.example.com/path' > webs/url_extract_nodupes.txt

  cat > "$MOCK_BIN/arjun" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  chmod +x "$MOCK_BIN/arjun"

  export DEEP=false
  export PARAM_DISCOVERY=true
  export ARJUN_THREADS=5

  run param_discovery
  [ "$status" -eq 0 ]
  [[ "$output" == *"SKIP"* ]]
}

@test "param_discovery runs in deep mode with arjun text output" {
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

  export DEEP=true
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

@test "well_known_pivots probes newly discovered subdomains into webs.txt" {
  mkdir -p webs .tmp subdomains
  printf '%s\n' 'https://target.example.com' > webs/webs_all.txt

  _resolve_domains() {
    cat "$1" > "$2"
  }

  cat > "$MOCK_BIN/curl" <<'SH'
#!/usr/bin/env bash
url="${@: -1}"
case "$url" in
  *"/.well-known/security.txt"|*"/security.txt")
    printf '%s\n' 'Contact: security@auth.target.example.com'
    ;;
  *)
    printf '%s\n' ''
    ;;
esac
SH
  chmod +x "$MOCK_BIN/curl"

  cat > "$MOCK_BIN/httpx" <<'SH'
#!/usr/bin/env bash
while IFS= read -r host; do
  [[ -z "$host" ]] && continue
  printf '%s 200\n' "https://${host}"
done
SH
  chmod +x "$MOCK_BIN/httpx"

  export WELLKNOWN_PIVOTS=true
  export HTTPX_THREADS=5
  export HTTPX_RATELIMIT=0
  export HTTPX_TIMEOUT=5

  run well_known_pivots
  [ "$status" -eq 0 ]
  [ -s "subdomains/subdomains.txt" ]
  [ -s "webs/webs.txt" ]
  grep -q '^auth.target.example.com$' "subdomains/subdomains.txt"
  grep -q '^https://auth.target.example.com$' "webs/webs.txt"
}

@test "wordlist_gen_roboxtractor skips in non-DEEP mode with explicit mode reason" {
  mkdir -p webs .tmp gf
  printf '%s\n' 'https://target.example.com' > webs/webs_all.txt

  export ROBOTSWORDLIST=true
  export DEEP=false

  run wordlist_gen_roboxtractor
  [ "$status" -eq 0 ]
  [[ "$output" == *"SKIP"* ]]
  [[ "$output" == *"reason: mode"* ]]
  [ -f "$called_fn_dir/.skip_wordlist_gen_roboxtractor" ]
  [ -f "$called_fn_dir/.status_reason_wordlist_gen_roboxtractor" ]
  [ "$(cat "$called_fn_dir/.status_reason_wordlist_gen_roboxtractor")" = "mode" ]
}

@test "wordlist_gen_roboxtractor runs in DEEP mode and writes robots wordlist" {
  mkdir -p webs .tmp gf
  printf '%s\n' 'https://target.example.com' > webs/webs_all.txt

  cat > "$MOCK_BIN/roboxtractor" <<'SH'
#!/usr/bin/env bash
while IFS= read -r url; do
  [[ -z "$url" ]] && continue
  printf '%s/robots-path\n' "${url%/}"
done
SH
  chmod +x "$MOCK_BIN/roboxtractor"

  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
quiet=false
if [[ "${1:-}" == "-q" ]]; then
  quiet=true
  shift
fi
outfile="$1"
touch "$outfile"
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fxq -- "$line" "$outfile"; then
    printf '%s\n' "$line" >> "$outfile"
    if [[ "$quiet" != true ]]; then
      printf '%s\n' "$line"
    fi
  fi
done
exit 0
SH
  chmod +x "$MOCK_BIN/anew"

  export ROBOTSWORDLIST=true
  export DEEP=true
  export PROXY=false

  run wordlist_gen_roboxtractor
  [ "$status" -eq 0 ]
  [ -s "webs/robots_wordlist.txt" ]
  grep -q "https://target.example.com/robots-path" "webs/robots_wordlist.txt"
}
