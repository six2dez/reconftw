#!/usr/bin/env bats

setup() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''

  export TEST_DIR="$BATS_TEST_TMPDIR/reconftw_sub_tls"
  mkdir -p "$TEST_DIR"

  export dir="$TEST_DIR/example.com"
  export called_fn_dir="$dir/.called_fn"
  mkdir -p "$called_fn_dir" "$dir"
  cd "$dir"

  mkdir -p .tmp subdomains webs

  export domain="example.com"
  export DIFF=false
  export AXIOM=false
  export DEEP=false
  export TLSX_THREADS=1
  export TLS_PORTS="443"
  export RESOLVER_IQ=false
  export INSCOPE=false

  export LOGFILE="$dir/.tmp/test.log"
  : >"$LOGFILE"

  export MOCK_BIN="$TEST_DIR/mockbin"
  mkdir -p "$MOCK_BIN"
  export PATH="$MOCK_BIN:$PATH"

  cat > "$MOCK_BIN/tlsx" <<'SH'
#!/usr/bin/env bash
# Emit non-matching output; keep it non-empty so grep filters run.
echo "https://notexample.invalid"
SH
  chmod +x "$MOCK_BIN/tlsx"

  source "$project_root/reconftw.sh" --source-only
  export DOMAIN_ESCAPED
  DOMAIN_ESCAPED=$(escape_domain_regex "$domain")
}

teardown() {
  [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

@test "sub_tls does not raise ERR trap when tlsx output has no matches" {
  printf "a.%s\n" "$domain" > subdomains/subdomains.txt

  set -E
  trap 'echo "ERR($?) :: $BASH_COMMAND" >>"$LOGFILE"' ERR

  sub_tls
  [ "$?" -eq 0 ]

  # Our trap should stay empty for this scenario (no-match is not an error).
  ! grep -q '^ERR\\(' "$LOGFILE"
  [ -f ".tmp/subdomains_tlsx_clean.txt" ]
}

