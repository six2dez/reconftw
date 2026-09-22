#!/usr/bin/env bats
#
# Coverage for the Lunar domain-exposure enrichment (#1042).
#
# The API is free and unauthenticated, so the failure worth guarding is not
# credentials — it is publishing a file that is not exposure data. A 200 from an
# outage page, a captive portal, or a rate-limit interstitial is still a 200, and
# writing its body to osint/lunar_exposure.json makes every downstream consumer
# guess. These tests pin the staging contract: the artefact appears only when the
# response is both 200 AND parseable JSON, and a failed query never replaces a
# good result from a previous run.

setup() {
  source "$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/../helpers/common.bash"
  setup_recon_env

  export TEST_DIR="$(mktemp -d)"
  export domain="example.com"
  export dir="$TEST_DIR/$domain"
  export called_fn_dir="$dir/.called_fn"
  mkdir -p "$dir/osint" "$called_fn_dir"
  cd "$dir"

  export OSINT=true LUNAR_EXPOSURE=true DIFF=false LUNAR_TIMEOUT=5

  # Stub curl: honours -o and -w '%{http_code}' the way the function relies on.
  mkdir -p "$TEST_DIR/bin"
  cat > "$TEST_DIR/bin/curl" <<'STUB'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n "$out" ]] && printf '%s' "${FAKE_BODY:-}" > "$out"
printf '%s' "${FAKE_CODE:-200}"
STUB
  chmod +x "$TEST_DIR/bin/curl"
  export PATH="$TEST_DIR/bin:$PATH"
  export DRY_RUN=false ADAPTIVE_RATE_LIMIT=false DEBUG_LOG=""
}

teardown() {
  cd /
  rm -rf "$TEST_DIR"
}

@test "a 200 with JSON is published as the exposure artefact" {
  export FAKE_CODE=200
  export FAKE_BODY='{"domain":"example.com","exposures":3}'
  lunar_exposure
  [ -f "$dir/osint/lunar_exposure.json" ] \
    && jq -e '.exposures == 3' "$dir/osint/lunar_exposure.json" >/dev/null
}

@test "a non-200 writes no artefact" {
  export FAKE_CODE=503
  export FAKE_BODY='upstream unavailable'
  lunar_exposure
  [ ! -f "$dir/osint/lunar_exposure.json" ]
}

@test "a 200 carrying a non-JSON body writes no artefact" {
  export FAKE_CODE=200
  export FAKE_BODY='<html><body>rate limited</body></html>'
  lunar_exposure
  [ ! -f "$dir/osint/lunar_exposure.json" ]
}

@test "a failed query does not replace a previous good result" {
  printf '%s' '{"domain":"example.com","exposures":7}' > "$dir/osint/lunar_exposure.json"
  export FAKE_CODE=500
  export FAKE_BODY='boom'
  lunar_exposure
  jq -e '.exposures == 7' "$dir/osint/lunar_exposure.json" >/dev/null
}

@test "disabled by default: LUNAR_EXPOSURE=false performs no query" {
  export LUNAR_EXPOSURE=false
  lunar_exposure
  [ ! -f "$dir/osint/lunar_exposure.json" ]
}

@test "an IP target is skipped: the API takes domains" {
  export domain="203.0.113.10"
  export FAKE_CODE=200
  export FAKE_BODY='{"domain":"203.0.113.10"}'
  lunar_exposure
  [ ! -f "$dir/osint/lunar_exposure.json" ]
}
