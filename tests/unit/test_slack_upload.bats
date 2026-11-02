#!/usr/bin/env bats

# Slack sunset files.upload on 2025-11-12. sendToNotify() now does the three-step
# external upload instead. These cases pin the contract that replaced it: which
# endpoints are called, in what order, with which fields, and that a failure at
# either step is reported rather than passed off as a success.

setup() {
    export SCRIPTPATH
    SCRIPTPATH="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
    TEST_DIR="$BATS_TEST_TMPDIR/slack"
    mkdir -p "$TEST_DIR/bin"
    export CALLS="$TEST_DIR/calls"
    : >"$CALLS"

    export domain="example.com"
    export LOGFILE="$TEST_DIR/run.log"
    : >"$LOGFILE"

    # A notify config with neither telegram nor discord, so only the Slack branch runs.
    export NOTIFY_CONFIG="$TEST_DIR/provider-config.yaml"
    printf 'slack:\n  slack_webhook_url: ""\n' >"$NOTIFY_CONFIG"

    export slack_channel="C0123456789"
    export slack_auth="xoxb-test-token-value"

    export PAYLOAD="$TEST_DIR/recon.zip"
    printf 'reconftw-zip-payload' >"$PAYLOAD" # 20 bytes

    cat >"$TEST_DIR/bin/curl" <<'MOCK'
#!/bin/bash
printf '%s\n' "$*" >>"$CALLS"
url=""
for arg in "$@"; do
    case "$arg" in
        https://*) url="$arg" ;;
    esac
done
case "$url" in
    *files.getUploadURLExternal*)
        if [[ "${GETURL_FAIL:-false}" == true ]]; then
            printf '{"ok":false,"error":"invalid_auth"}'
        else
            printf '{"ok":true,"upload_url":"https://files.slack.test/upload/abc","file_id":"F0PINNED"}'
        fi
        ;;
    *files.completeUploadExternal*)
        if [[ "${COMPLETE_FAIL:-false}" == true ]]; then
            printf '{"ok":false,"error":"channel_not_found"}'
        else
            printf '{"ok":true,"files":[{"id":"F0PINNED"}]}'
        fi
        ;;
    *files.slack.test*) : ;;
esac
exit 0
MOCK
    chmod +x "$TEST_DIR/bin/curl"
    export PATH="$TEST_DIR/bin:$PATH"

    source "$SCRIPTPATH/reconftw.sh" --source-only

    # Stub presentation only; sendToNotify, run_command and jq stay real.
    notification() { :; }
    _print_status() { :; }
    _print_msg() { printf '%s %s\n' "$1" "${*:2}"; }
    export DRY_RUN=false PROXYCHAINS=false ADAPTIVE_RATE_LIMIT=false DEBUG_LOG=""
}

@test "the sunset files.upload endpoint is never called" {
    sendToNotify "$PAYLOAD"
    ! grep -q 'api/files.upload' "$CALLS"
}

@test "the three steps run in order against the documented endpoints" {
    sendToNotify "$PAYLOAD"
    [ "$(wc -l <"$CALLS" | tr -d ' ')" -eq 3 ]
    [[ "$(sed -n 1p "$CALLS")" == *files.getUploadURLExternal* ]]
    [[ "$(sed -n 2p "$CALLS")" == *https://files.slack.test/upload/abc* ]]
    [[ "$(sed -n 3p "$CALLS")" == *files.completeUploadExternal* ]]
}

@test "step one sends the real byte length and the basename" {
    sendToNotify "$PAYLOAD"
    local first
    first=$(sed -n 1p "$CALLS")
    # 'reconftw-zip-payload' is 20 bytes; a padded or wrong length is what Slack rejects
    [[ "$first" == *"length=20"* ]]
    [[ "$first" == *"filename=recon.zip"* ]]
    [[ "$first" != *"length= "* ]]
}

@test "step two posts the raw bytes, not a multipart form" {
    sendToNotify "$PAYLOAD"
    local second
    second=$(sed -n 2p "$CALLS")
    [[ "$second" == *"--data-binary @$PAYLOAD"* ]]
    [[ "$second" == *"Content-Type: application/octet-stream"* ]]
    [[ "$second" != *"-F "* ]]
}

@test "step three carries the returned file_id, the channel and the comment" {
    sendToNotify "$PAYLOAD"
    local third
    third=$(sed -n 3p "$CALLS")
    [[ "$third" == *'"id":"F0PINNED"'* ]]
    [[ "$third" == *'"title":"recon.zip"'* ]]
    [[ "$third" == *"channels=$slack_channel"* ]]
    [[ "$third" == *"initial_comment=reconftw zip file"* ]]
}

@test "a failure to get an upload URL warns and skips the remaining steps" {
    export GETURL_FAIL=true
    run sendToNotify "$PAYLOAD"
    [ "$(wc -l <"$CALLS" | tr -d ' ')" -eq 1 ]
    [[ "$output" == *"WARN"*"could not get an upload URL"* ]]
    [[ "$output" == *"invalid_auth"* ]]
}

@test "an upload that is never shared is reported, not treated as a success" {
    export COMPLETE_FAIL=true
    run sendToNotify "$PAYLOAD"
    [ "$(wc -l <"$CALLS" | tr -d ' ')" -eq 3 ]
    [[ "$output" == *"WARN"*"not shared"* ]]
    [[ "$output" == *"channel_not_found"* ]]
}

@test "dry run makes no request and raises no warning" {
    export DRY_RUN=true
    run sendToNotify "$PAYLOAD"
    [ ! -s "$CALLS" ]
    [[ "$output" != *"WARN"* ]]
}

@test "the bot token is redacted from dry-run previews" {
    run redact_secrets "curl -H 'Authorization: Bearer ${slack_auth}' https://slack.com/api/files.getUploadURLExternal"
    [[ "$output" != *"xoxb-test-token-value"* ]]
    [[ "$output" == *"REDACTED"* ]]
}
