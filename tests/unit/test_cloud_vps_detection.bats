#!/usr/bin/env bats
#
# Regression coverage for issue #1050.
#
# _is_cloud_vps() decides whether a metadata service exists at link-local
# 169.254.169.254. _can_use_puredns() consumes that answer to pick the DNS
# resolver, so a false negative is not cosmetic: DNS_RESOLVER=auto silently
# downgrades puredns to dnsx on precisely the cloud hosts puredns is for.
#
# The old probe was `curl -sf`. IMDSv2 — the default on new EC2 instances since
# 2019 — answers an unauthenticated GET with 401, and `-f` maps any >=400 status
# to exit 22. A live metadata service was therefore read as no metadata service.
#
# These tests drive a stub `curl` so they assert the BRANCHING on HTTP status
# rather than reaching the network, which unit-fast cannot do anyway.
#
# ASSERTION STYLE: `run` captures status, so each case asserts on $status
# directly; the suite restores errexit via tests/helpers/common.bash.

setup() {
    source "$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/../helpers/common.bash"
    setup_recon_env

    TEST_DIR="$(mktemp -d)"
    export TEST_DIR
    cd "$TEST_DIR"

    # Stub curl: emulate a response by echoing $STUB_HTTP_CODE for -w '%{http_code}'.
    # '000' is what real curl reports when no HTTP response arrived at all.
    #
    # It MUST honour -f, or these tests are decoration: the bug under test is
    # precisely that -f maps a >=400 status to exit 22. A stub that ignored -f
    # would keep reporting success for the old `curl -sf` probe, so reinstating
    # the bug would leave every test below green. Verified by mutation, not
    # assumed — see the note on the IMDSv2 case.
    mkdir -p bin
    cat > bin/curl <<'STUB'
#!/usr/bin/env bash
fail_on_error=0
for _a in "$@"; do
  case "$_a" in
    -f | --fail) fail_on_error=1 ;;
    -*f*) [[ "$_a" != --* ]] && fail_on_error=1 ;;
  esac
done
code="${STUB_HTTP_CODE:-000}"
printf '%s' "$code"
if [[ "$fail_on_error" -eq 1 ]] && [[ "$code" =~ ^[45][0-9][0-9]$ ]]; then
  exit 22
fi
[[ "$code" == "000" ]] && exit 7
exit 0
STUB
    chmod +x bin/curl
    export PATH="$TEST_DIR/bin:$PATH"

    export DRY_RUN=false
}

teardown() {
    cd /
    rm -rf "$TEST_DIR"
}

@test "_is_cloud_vps detects AWS IMDSv2, which answers an unauthenticated GET with 401 (issue #1050)" {
    # The exact case the issue reports. `curl -sf` returned exit 22 here and the
    # instance was misclassified as a non-cloud NAT network.
    export STUB_HTTP_CODE="401"
    run _is_cloud_vps
    [ "$status" -eq 0 ]
}

@test "_is_cloud_vps detects a metadata service that answers 403" {
    export STUB_HTTP_CODE="403"
    run _is_cloud_vps
    [ "$status" -eq 0 ]
}

@test "_is_cloud_vps still detects a plain IMDSv1-style 200" {
    export STUB_HTTP_CODE="200"
    run _is_cloud_vps
    [ "$status" -eq 0 ]
}

@test "_is_cloud_vps returns false when nothing answers at 169.254.169.254" {
    # No HTTP response at all: the non-cloud case, which must stay false so a
    # home/office network is never handed to puredns.
    export STUB_HTTP_CODE="000"
    run _is_cloud_vps
    [ "$status" -ne 0 ]
}

@test "_is_cloud_vps returns false when curl produces no output" {
    export STUB_HTTP_CODE=""
    run _is_cloud_vps
    [ "$status" -ne 0 ]
}

@test "_is_cloud_vps short-circuits to false under DRY_RUN" {
    export DRY_RUN=true
    export STUB_HTTP_CODE="200"
    run _is_cloud_vps
    [ "$status" -ne 0 ]
}

@test "_can_use_puredns now says yes for a private-IP EC2 box behind IMDSv2" {
    # The end-to-end consequence of the fix: private IP + IMDSv2 401 is a cloud
    # VPS with 1:1 NAT, which is safe for puredns. Before the fix this returned
    # false and the run silently fell back to dnsx.
    export STUB_HTTP_CODE="401"
    run _can_use_puredns "10.0.0.5"
    [ "$status" -eq 0 ]
}
