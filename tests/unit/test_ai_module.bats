#!/usr/bin/env bats

setup() {
  source "$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/../helpers/common.bash"
  PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
}

@test "built-in AI module files exist" {
  [ -f "$PROJECT_ROOT/lib/ai/cli.py" ]
  [ -f "$PROJECT_ROOT/lib/ai/providers/base.py" ]
  [ -f "$PROJECT_ROOT/lib/ai/providers/pydantic_ai_provider.py" ]
  [ -f "$PROJECT_ROOT/data/ai/prompts.json" ]
}

@test "python AI unit tests pass" {
  local py=python3
  if [[ -x "$PROJECT_ROOT/.venv/bin/python3" ]]; then
    py="$PROJECT_ROOT/.venv/bin/python3"
  fi
  run "$py" "$PROJECT_ROOT/tests/unit/python/test_ai_providers.py"
  [ "$status" -eq 0 ]
}

@test "modes end() prefers built-in ai cli over legacy reconftw_ai" {
  source "$PROJECT_ROOT/reconftw.cfg"
  source "$PROJECT_ROOT/modules/core.sh"
  source "$PROJECT_ROOT/modules/utils.sh"
  source "$PROJECT_ROOT/lib/common.sh"
  source "$PROJECT_ROOT/modules/modes.sh"
  export SCRIPTPATH="$PROJECT_ROOT"
  export tools="/tmp/reconftw-tools-missing"
  export opt_ai=true
  export AI_PROVIDER=mock
  export domain="example.com"
  export dir="$(mktemp -d)/example.com"
  mkdir -p "$dir"/{osint,subdomains,hosts,webs,ai_result}
  echo "admin@example.com" > "$dir/osint/emails.txt"
  export DEBUG_LOG="/dev/null"
  export LOGFILE="$(mktemp)"
  export OUTPUT_VERBOSITY=1
  export PRESERVE=true
  export REMOVETMP=false
  export REMOVELOG=false
  export FARADAY=false
  export NO_REPORT=true
  export global_start=$(date +%s)

  notification() { :; }

  export AI_EXECUTABLE=python3

  run end
  [ "$status" -eq 0 ]
  grep -q "Analyzing with" "$LOGFILE"
  compgen -G "$dir/ai_result/reconftw_analysis_*" >/dev/null
}

@test "ai analysis skipped when not configured" {
  source "$PROJECT_ROOT/reconftw.cfg"
  source "$PROJECT_ROOT/modules/core.sh"
  source "$PROJECT_ROOT/modules/utils.sh"
  source "$PROJECT_ROOT/lib/common.sh"
  source "$PROJECT_ROOT/modules/modes.sh"
  export SCRIPTPATH="$PROJECT_ROOT"
  export opt_ai=true
  export AI_PROVIDER=openai_compatible
  export AI_BASE_URL=""
  unset OPENAI_API_KEY AI_API_KEY ANTHROPIC_API_KEY
  export domain="example.com"
  export dir="$(mktemp -d)/example.com"
  mkdir -p "$dir"
  export LOGFILE="$(mktemp)"

  notification() { :; }
  print_notice() { :; }
  _print_section() { :; }
  _print_status() { :; }

  run _run_ai_analysis
  [ "$status" -eq 0 ]
  grep -q "ai_analysis skipped" "$LOGFILE"
}

@test "secrets.cfg overrides empty AI_BASE_URL from reconftw.cfg" {
  local tmp_secrets
  tmp_secrets="$(mktemp)"
  printf '%s\n' 'AI_BASE_URL="http://127.0.0.1:9999/v1"' 'AI_MODEL="test-model"' >"$tmp_secrets"
  source "$PROJECT_ROOT/reconftw.cfg"
  source "$tmp_secrets"
  source "$PROJECT_ROOT/lib/config.sh"
  export_reconftw_runtime_env
  [ "$AI_BASE_URL" = "http://127.0.0.1:9999/v1" ]
  [ "$AI_MODEL" = "test-model" ]
  rm -f "$tmp_secrets"
}

@test "start logs ai preflight when -y is set" {
  source "$PROJECT_ROOT/reconftw.cfg"
  source "$PROJECT_ROOT/modules/core.sh"
  source "$PROJECT_ROOT/modules/utils.sh"
  source "$PROJECT_ROOT/lib/common.sh"
  source "$PROJECT_ROOT/modules/modes.sh"
  export SCRIPTPATH="$PROJECT_ROOT"
  export opt_ai=true
  export AI_PROVIDER=mock
  export domain="bats_ai_preflight_$$"
  export DEEP=false
  export MONITOR_MODE=false
  export upgrade_before_running=false
  export AXIOM=false

  notification() { :; }
  validate_config() { return 0; }
  apply_performance_profile() { :; }
  check_disk_space() { return 0; }
  incremental_init() { :; }
  plugins_load() { :; }
  plugins_emit() { :; }
  init_dns_resolver() { :; }
  rotate_logs() { :; }
  enable_command_trace() { :; }
  tools_installed() { :; }

  start
  grep -rq "ai_analysis scheduled" "$PROJECT_ROOT/Recon/$domain/.log"
  rm -rf "$PROJECT_ROOT/Recon/$domain"
}
