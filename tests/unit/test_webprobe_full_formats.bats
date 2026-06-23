#!/usr/bin/env bats

setup() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export LOGFILE="/dev/null"
  export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''

  export TEST_DIR="$BATS_TEST_TMPDIR/reconftw_webprobe_full"
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
  export WEBPROBEFULL=true
  export WEBPROBE_PORTS="80,443,8080,8443"
  export PROXY=false
  export HTTPX_UNCOMMONPORTS_THREADS=10
  export HTTPX_RATELIMIT=0
  export HTTPX_UNCOMMONPORTS_TIMEOUT=10
}

teardown() {
  [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

@test "webprobe_full splits common and uncommon JSON results and updates webs_all" {
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
cat > "$out" <<'JSON'
{"url":"https://app.example.com","port":"443","status_code":200,"title":"ok","webserver":"nginx","tech":["nginx"]}
{"url":"http://api.example.com","port":"80","status_code":200,"title":"ok","webserver":"nginx","tech":["nginx"]}
{"url":"https://edge.example.com:8443","port":"8443","status_code":200,"title":"ok","webserver":"nginx","tech":["nginx"]}
JSON
SH
  chmod +x "$MOCK_BIN/httpx"

  run webprobe_full
  [ "$status" -eq 0 ]
  [ -s "webs/webs.txt" ]
  grep -q "https://app.example.com" "webs/webs.txt"
  grep -q "http://api.example.com" "webs/webs.txt"
  ! grep -q "edge.example.com:8443" "webs/webs.txt"

  [ -s "webs/webs_uncommon_ports.txt" ]
  grep -q "https://edge.example.com:8443" "webs/webs_uncommon_ports.txt"

  [ -s "webs/web_full_info.txt" ]
  grep -q "\"port\":\"443\"" "webs/web_full_info.txt"
  grep -q "\"port\":\"80\"" "webs/web_full_info.txt"
  ! grep -q "\"port\":\"8443\"" "webs/web_full_info.txt"

  [ -s "webs/web_full_info_uncommon.txt" ]
  grep -q "\"port\":\"8443\"" "webs/web_full_info_uncommon.txt"

  [ -s "webs/webs_all.txt" ]
  grep -q "https://app.example.com" "webs/webs_all.txt"
  grep -q "http://api.example.com" "webs/webs_all.txt"
  grep -q "https://edge.example.com:8443" "webs/webs_all.txt"
}

@test "webprobe_full passes WEBPROBE_PORTS (including 80 and 443) to httpx command" {
  mkdir -p .tmp webs subdomains
  printf "a.example.com\n" > subdomains/subdomains.txt
  export ARGS_LOG="$TEST_DIR/httpx.args"

  cat > "$MOCK_BIN/httpx" <<'SH'
#!/usr/bin/env bash
out=""
printf '%s\n' "$@" > "$ARGS_LOG"
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
printf '%s\n' '{"url":"https://app.example.com","port":"443","status_code":200,"title":"ok","webserver":"nginx","tech":["nginx"]}' > "$out"
SH
  chmod +x "$MOCK_BIN/httpx"

  run webprobe_full
  [ "$status" -eq 0 ]
  grep -q "^-p$" "$ARGS_LOG"
  grep -q "^80,443,8080,8443$" "$ARGS_LOG"
}

@test "webprobe_full emits RUN notice before httpx" {
  mkdir -p .tmp webs subdomains
  printf "a.example.com\nb.example.com\n" > subdomains/subdomains.txt

  cat > "$MOCK_BIN/httpx" <<'SH'
#!/usr/bin/env bash
sleep 1
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '%s\n' '{"url":"https://app.example.com","port":"443","status_code":200,"title":"ok","webserver":"nginx","tech":["nginx"]}' > "$out"
SH
  chmod +x "$MOCK_BIN/httpx"

  run webprobe_full
  [ "$status" -eq 0 ]
  [[ "$output" == *"RUN"* ]]
  [[ "$output" == *"webprobe_full"* ]]
  [[ "$output" == *"httpx probing 2 hosts"* ]]
}

@test "webprobe_full caps host list when above WEBPROBE_MAX_HOSTS" {
  mkdir -p .tmp webs subdomains
  export domain="example.com"
  export WEBPROBE_MAX_HOSTS=3
  export WEBPROBE_INCLUDE_UNCOMMON_PORTS=false
  export WEBPROBE_PORTS_COMMON="80,443"
  export DEEP=false
  for i in $(seq 1 10); do printf 'host%02d.example.com\n' "$i"; done > subdomains/subdomains.txt

  cat > "$MOCK_BIN/httpx" <<'SH'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '%s\n' '{"url":"https://example.com","port":"443","status_code":200,"title":"ok","webserver":"nginx","tech":["nginx"]}' > "$out"
SH
  chmod +x "$MOCK_BIN/httpx"

  run webprobe_full
  [ "$status" -eq 0 ]
  [ -f ".tmp/webprobe_hosts.txt" ]
  [ "$(wc -l <.tmp/webprobe_hosts.txt | tr -d ' ')" -le 3 ]
  grep -qx 'example.com' .tmp/webprobe_hosts.txt
}

@test "webprobe_full fails when httpx output is not JSON" {
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
printf '%s\n' "https://app.example.com" "https://edge.example.com:8443" > "$out"
SH
  chmod +x "$MOCK_BIN/httpx"

  run webprobe_full
  [ "$status" -eq 1 ]
  [ -f "$called_fn_dir/.status_webprobe_full" ]
  grep -q "^FAIL$" "$called_fn_dir/.status_webprobe_full"
}
