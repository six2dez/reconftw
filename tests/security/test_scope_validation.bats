#!/usr/bin/env bats

# Regression tests for the scope/SSRF helpers added to lib/validation.sh.
# Covers Naxus audit findings #7 (substring bypass) and #8 (userinfo SSRF).

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    # shellcheck source=/dev/null
    source "$project_root/lib/validation.sh"
}

@test "is_in_scope_host accepts the apex domain itself" {
    run is_in_scope_host "example.com" "example.com"
    [ "$status" -eq 0 ]
}

@test "is_in_scope_host accepts a subdomain" {
    run is_in_scope_host "api.example.com" "example.com"
    [ "$status" -eq 0 ]
}

@test "is_in_scope_host accepts a deep subdomain" {
    run is_in_scope_host "foo.bar.example.com" "example.com"
    [ "$status" -eq 0 ]
}

@test "is_in_scope_host is case-insensitive" {
    run is_in_scope_host "SUB.Example.COM" "example.com"
    [ "$status" -eq 0 ]
}

@test "is_in_scope_host rejects substring look-alike (exampleXcom.evil)" {
    run is_in_scope_host "exampleXcom.evil" "example.com"
    [ "$status" -ne 0 ]
}

@test "is_in_scope_host rejects prefix look-alike (badexample.com)" {
    run is_in_scope_host "badexample.com" "example.com"
    [ "$status" -ne 0 ]
}

@test "is_in_scope_host rejects unrelated domain" {
    run is_in_scope_host "attacker.test" "example.com"
    [ "$status" -ne 0 ]
}

@test "filter_in_scope_urls passes http and https targets on the apex" {
    result=$(printf '%s\n' "http://example.com/" "https://example.com/x" | filter_in_scope_urls "example.com")
    [[ "$result" == *"http://example.com/"* ]]
    [[ "$result" == *"https://example.com/x"* ]]
}

@test "filter_in_scope_urls drops URLs with userinfo (SSRF bypass block)" {
    result=$(printf '%s\n' "http://victim.example.com@attacker.test:8080/" | filter_in_scope_urls "example.com")
    [ -z "$result" ]
}

@test "filter_in_scope_urls drops URLs with user:pass@host" {
    result=$(printf '%s\n' "http://user:pass@example.com/" | filter_in_scope_urls "example.com")
    [ -z "$result" ]
}

@test "filter_in_scope_urls drops off-scope with target as query (attacker.test/?cb=example.com)" {
    result=$(printf '%s\n' "http://attacker.test/?cb=example.com" | filter_in_scope_urls "example.com")
    [ -z "$result" ]
}

@test "filter_in_scope_urls drops non-http schemes" {
    result=$(printf '%s\n' "ftp://example.com/" "file:///etc/passwd" | filter_in_scope_urls "example.com")
    [ -z "$result" ]
}

@test "filter_in_scope_urls drops substring look-alike hosts" {
    result=$(printf '%s\n' "https://exampleXcom.evil/" | filter_in_scope_urls "example.com")
    [ -z "$result" ]
}

@test "filter_in_scope_hosts rejects substring look-alike on raw hostnames" {
    result=$(printf '%s\n' "exampleXcom.evil" "api.example.com" | filter_in_scope_hosts "example.com")
    [[ "$result" == "api.example.com" ]]
}

@test "is_in_scope_url returns the sanitized URL on match" {
    run is_in_scope_url "https://api.example.com/path" "example.com"
    [ "$status" -eq 0 ]
    [[ "$output" == *"api.example.com"* ]]
}

@test "is_in_scope_url rejects userinfo" {
    run is_in_scope_url "http://victim.example.com@127.0.0.1:8080/" "example.com"
    [ "$status" -ne 0 ]
}
