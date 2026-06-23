#!/usr/bin/env bats

setup() {
  source "$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/../helpers/common.bash"
  setup_recon_env
  PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
}

@test "apply_performance_profile low caps dnsx and naabu" {
  export PERF_PROFILE="low"
  export DEEP=false
  export WORKLOAD_SAFE=true
  export DNSX_RATE_LIMIT=100
  export DNSX_THREADS=20
  export NAABU_RATE=500

  run apply_performance_profile
  [ "$status" -eq 0 ]
  [[ "$DNSX_RATE_LIMIT" -le 50 ]]
  [[ "$NAABU_RATE" -le 150 ]]
  [[ "$DNSX_THREADS" -le 10 ]]
}

@test "sub_permut default rounds is 1 not 2" {
  grep -q 'SUBPERMUTE_ROUNDS:-1' "$PROJECT_ROOT/modules/subdomains.sh"
}

@test "reconftw.cfg disables heavy subdomain modules by default" {
  grep -q '^SUBPERMUTE=false' "$PROJECT_ROOT/reconftw.cfg"
  grep -q '^SUBREGEXPERMUTE=false' "$PROJECT_ROOT/reconftw.cfg"
  grep -q '^export AI_REMOTE_ONLY=true' "$PROJECT_ROOT/reconftw.cfg"
  grep -q '^WEBPROBE_INCLUDE_UNCOMMON_PORTS=false' "$PROJECT_ROOT/reconftw.cfg"
  grep -q '^FUZZ=false' "$PROJECT_ROOT/reconftw.cfg"
}

@test "apply_performance_profile workload_safe caps httpx rate and webprobe ports" {
  export PERF_PROFILE="low"
  export DEEP=false
  export WORKLOAD_SAFE=true
  export WEBPROBE_INCLUDE_UNCOMMON_PORTS=false
  export WEBPROBE_PORTS_COMMON="80,443"
  export WEBPROBE_PORTS="80,443,8080"
  export HTTPX_RATELIMIT=150

  run apply_performance_profile
  [ "$status" -eq 0 ]
  [ "$WEBPROBE_PORTS" = "80,443" ]
  [[ "$HTTPX_RATELIMIT" -le 80 ]]
}

@test "secrets.cfg.example documents API keys and AI settings" {
  [ -f "$PROJECT_ROOT/secrets.cfg.example" ]
  grep -q 'SHODAN_API_KEY' "$PROJECT_ROOT/secrets.cfg.example"
  grep -q 'PDCP_API_KEY' "$PROJECT_ROOT/secrets.cfg.example"
  grep -q 'AI_BASE_URL' "$PROJECT_ROOT/secrets.cfg.example"
  grep -q 'GITHUB_TOKENS' "$PROJECT_ROOT/secrets.cfg.example"
  grep -q 'chmod 600' "$PROJECT_ROOT/secrets.cfg.example"
}

@test "lib config.sh exports AI vars after secrets load" {
  local tmp
  tmp="$(mktemp -d)"
  printf '%s\n' 'AI_BASE_URL="http://test.local/v1"' 'AI_API_KEY="sk-test"' > "$tmp/secrets.cfg"
  printf '%s\n' 'tools=/tmp/tools' 'reconftw_version=test' > "$tmp/reconftw.cfg"
  # shellcheck source=/dev/null
  source "$PROJECT_ROOT/lib/config.sh"
  SCRIPTPATH="$tmp"
  # shellcheck source=/dev/null
  . "$tmp/reconftw.cfg"
  # shellcheck source=/dev/null
  . "$tmp/secrets.cfg"
  export_reconftw_runtime_env
  run bash -c '[[ -n "${AI_BASE_URL:-}" && -n "${AI_API_KEY:-}" ]]'
  [ "$status" -eq 0 ]
  rm -rf "$tmp"
}
