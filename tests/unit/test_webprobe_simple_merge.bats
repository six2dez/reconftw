#!/usr/bin/env bats

setup() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export LOGFILE="/dev/null"
  export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''

  export TEST_DIR="$BATS_TEST_TMPDIR/reconftw_webprobe_merge"
  mkdir -p "$TEST_DIR"
  export dir="$TEST_DIR/example.com"
  export called_fn_dir="$dir/.called_fn"
  mkdir -p "$called_fn_dir" "$dir"
  cd "$dir"

  export MOCK_BIN="$TEST_DIR/mockbin"
  mkdir -p "$MOCK_BIN"
  export PATH="$MOCK_BIN:$PATH"

  source "$project_root/reconftw.sh" --source-only
  export domain="example.com"
  export DIFF=false
  export AXIOM=false
  export WEBPROBESIMPLE=true
  export HTTPX_FLAGS=""
  export HTTPX_THREADS=10
  export HTTPX_RATELIMIT=0
  export HTTPX_TIMEOUT=10
}

teardown() {
  [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

@test "webprobe_simple merges current probe output with prior web_full_info cache" {
  mkdir -p .tmp webs subdomains
  printf "a.example.com\n" > subdomains/subdomains.txt
  printf '%s\n' '{"input":"old","url":"https://old.example.com"}' > .tmp/web_full_info.txt

  cat > "$MOCK_BIN/httpx" <<'SH'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      out="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s\n' '{"input":"new","url":"https://new.example.com"}' > "$out"
SH
  chmod +x "$MOCK_BIN/httpx"

  run webprobe_simple
  [ "$status" -eq 0 ]
  [ -s "webs/web_full_info.txt" ]
  grep -q "old.example.com" "webs/web_full_info.txt"
  grep -q "new.example.com" "webs/web_full_info.txt"
}

@test "webprobe_simple works when prior web_full_info cache is missing" {
  mkdir -p .tmp webs subdomains
  rm -f .tmp/web_full_info.txt
  printf "a.example.com\n" > subdomains/subdomains.txt

  cat > "$MOCK_BIN/httpx" <<'SH'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      out="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s\n' '{"input":"new","url":"https://new.example.com"}' > "$out"
SH
  chmod +x "$MOCK_BIN/httpx"

  run webprobe_simple
  [ "$status" -eq 0 ]
  [ -s "webs/web_full_info.txt" ]
  grep -q "new.example.com" "webs/web_full_info.txt"
}

@test "webprobe_simple falls back when cache contains non-JSON" {
  mkdir -p .tmp webs subdomains
  printf "a.example.com\n" > subdomains/subdomains.txt
  printf '%s\n' 'NOT_JSON' > .tmp/web_full_info.txt

  cat > "$MOCK_BIN/httpx" <<'SH'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      out="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s\n' '{"input":"new","url":"https://new.example.com"}' > "$out"
SH
  chmod +x "$MOCK_BIN/httpx"

  run webprobe_simple
  [ "$status" -eq 0 ]
  [ -s "webs/web_full_info.txt" ]
  grep -q "new.example.com" "webs/web_full_info.txt"
  ! grep -q "NOT_JSON" ".tmp/web_full_info.txt"
}

@test "webprobe_simple promotes URL list output into webs/webs.txt and webs_all" {
  mkdir -p .tmp webs subdomains
  printf "a.example.com\n" > subdomains/subdomains.txt

  cat > "$MOCK_BIN/httpx" <<'SH'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      out="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s\n' "https://a.example.com" "https://b.example.com" > "$out"
SH
  chmod +x "$MOCK_BIN/httpx"

  run webprobe_simple
  [ "$status" -eq 0 ]
  [ -s "webs/webs.txt" ]
  grep -q "https://a.example.com" "webs/webs.txt"
  grep -q "https://b.example.com" "webs/webs.txt"
  [ -s "webs/webs_all.txt" ]
  grep -q "https://a.example.com" "webs/webs_all.txt"
  grep -q "https://b.example.com" "webs/webs_all.txt"
}
