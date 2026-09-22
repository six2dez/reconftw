#!/usr/bin/env bats
#
# Coverage for the proxychains integration (#1041).
#
# The wrapping happens in run_command, the single gate every external tool goes
# through, so these tests drive run_command rather than any one module.
#
# The property that matters is not "does it prepend proxychains" — it is that
# the tools proxychains CANNOT carry are never wrapped, and that a missing
# binary does not silently produce an un-proxied request. An operator turns this
# on precisely because they do not want those packets leaving directly.

setup() {
  source "$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/../helpers/common.bash"
  setup_recon_env

  export TEST_DIR="$(mktemp -d)"
  cd "$TEST_DIR"

  # A stub `proxychains4` that records how it was invoked instead of proxying.
  mkdir -p bin
  cat > bin/proxychains4 <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$PC_CALLS"
# Drop proxychains' own flags and run whatever it was asked to wrap.
while [[ $# -gt 0 ]]; do
  case "$1" in
    -q) shift ;;
    -f) shift 2 ;;
    *) break ;;
  esac
done
exec "$@"
STUB
  chmod +x bin/proxychains4
  export PATH="$TEST_DIR/bin:$PATH"
  export PC_CALLS="$TEST_DIR/pc_calls.txt"
  : > "$PC_CALLS"

  # An ordinary tool to be wrapped, and a DNS tool that must not be.
  cat > bin/httpx <<'STUB'
#!/usr/bin/env bash
echo "httpx ran"
STUB
  cat > bin/puredns <<'STUB'
#!/usr/bin/env bash
echo "puredns ran"
STUB
  chmod +x bin/httpx bin/puredns

  export PROXYCHAINS_BIN="" PROXYCHAINS_CONF="" PROXYCHAINS_EXCLUDE=""
  export DRY_RUN=false ADAPTIVE_RATE_LIMIT=false DEBUG_LOG=""
}

teardown() {
  cd /
  rm -rf "$TEST_DIR"
}

@test "PROXYCHAINS=false leaves the command untouched" {
  export PROXYCHAINS=false
  run run_command httpx -silent
  [ "$status" -eq 0 ] \
    && [ "$output" = "httpx ran" ] \
    && [ ! -s "$PC_CALLS" ]
}

@test "PROXYCHAINS=true wraps an ordinary tool" {
  export PROXYCHAINS=true
  run run_command httpx -silent
  [ "$status" -eq 0 ] \
    && [ -s "$PC_CALLS" ] \
    && grep -q 'httpx' "$PC_CALLS"
}

@test "PROXYCHAINS_CONF is passed through as -f" {
  export PROXYCHAINS=true
  export PROXYCHAINS_CONF="$TEST_DIR/chain.conf"
  : > "$PROXYCHAINS_CONF"
  run run_command httpx -silent
  [ "$status" -eq 0 ] && grep -q -- "-f $PROXYCHAINS_CONF" "$PC_CALLS"
}

@test "mass-DNS tools are never wrapped: proxychains cannot carry their UDP" {
  export PROXYCHAINS=true
  run run_command puredns resolve
  # It must still run, and it must not have gone through the chain.
  [ "$status" -eq 0 ] \
    && [ "$output" = "puredns ran" ] \
    && [ ! -s "$PC_CALLS" ]
}

@test "PROXYCHAINS_EXCLUDE adds tools to the never-wrap list" {
  export PROXYCHAINS=true
  export PROXYCHAINS_EXCLUDE="httpx"
  run run_command httpx -silent
  [ "$status" -eq 0 ] \
    && [ "$output" = "httpx ran" ] \
    && [ ! -s "$PC_CALLS" ]
}

@test "a missing proxychains binary fails the command instead of running it direct" {
  export PROXYCHAINS=true
  export PROXYCHAINS_BIN="proxychains-that-does-not-exist"
  run run_command httpx -silent
  # The tool must NOT have run: an un-proxied request is the one outcome the
  # operator enabled this to prevent.
  [ "$status" -ne 0 ] && [ "${output}" != "httpx ran" ]
}
