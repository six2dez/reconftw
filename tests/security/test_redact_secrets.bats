#!/usr/bin/env bats

# Regression tests for redact_secrets() + register_secret() — Naxus finding #3
# (dry-run/xtrace redaction of GH_TOKEN, telegram_key, discord_url).

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

    # Extract only the redaction helpers from core.sh so the test does not
    # need reconftw.cfg, logfile, or the full reconftw.sh bootstrap.
    awk '/^REDACT_VARS=\(/,/^\)/ {print}
         /^REGISTERED_SECRETS=\(\)$/ {print}
         /^function register_secret\(\)/,/^}$/ {print}
         /^function redact_secrets\(\)/,/^}$/ {print}' \
        "$project_root/modules/core.sh" > "$BATS_TMPDIR/_redact.sh"
    # shellcheck source=/dev/null
    source "$BATS_TMPDIR/_redact.sh"
}

@test "redact_secrets replaces registered values with [REDACTED]" {
    register_secret "ghp_supersecrettokenvalue_abc"
    result=$(redact_secrets "ghleaks --token ghp_supersecrettokenvalue_abc")
    [[ "$result" == *"[REDACTED]"* ]]
    [[ "$result" != *"ghp_supersecrettokenvalue_abc"* ]]
}

@test "redact_secrets replaces env-var values via REDACT_VARS indirection" {
    GH_TOKEN="ghp_envvar_aaaaaaaaaaaaaaaaaaaaaaaa"
    result=$(redact_secrets "curl -H 'Authorization: token ghp_envvar_aaaaaaaaaaaaaaaaaaaaaaaa'")
    [[ "$result" == *"[REDACTED]"* ]]
    [[ "$result" != *"ghp_envvar_aaaaaaaaaaaaaaaaaaaaaaaa"* ]]
}

@test "redact_secrets redacts telegram_key from local scope via REDACT_VARS" {
    telegram_key="bot123:AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    result=$(redact_secrets "https://api.telegram.org/botbot123:AAAAAAAAAAAAAAAAAAAAAAAAAAAA/sendMessage")
    [[ "$result" == *"[REDACTED]"* ]]
}

@test "redact_secrets redacts discord_url" {
    discord_url="https://discord.com/api/webhooks/1234567890/very-secret-token-xyz"
    result=$(redact_secrets "curl $discord_url")
    [[ "$result" == *"[REDACTED]"* ]]
    [[ "$result" != *"very-secret-token-xyz"* ]]
}

@test "redact_secrets leaves short strings untouched" {
    register_secret "x"
    result=$(redact_secrets "benign short text x stays")
    [[ "$result" == *"x stays"* ]]
}

@test "register_secret deduplicates repeated values" {
    local before=${#REGISTERED_SECRETS[@]}
    register_secret "some-repeated-value-1234"
    register_secret "some-repeated-value-1234"
    register_secret "some-repeated-value-1234"
    local after=${#REGISTERED_SECRETS[@]}
    [ "$((after - before))" -eq 1 ]
}
