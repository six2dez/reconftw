#!/usr/bin/env bats

# Unit tests for validation functions in lib/validation.sh

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export tools="$HOME/Tools"
    export LOGFILE="/dev/null"
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
    export NOTIFICATION=false
    export AXIOM=false
    source "$project_root/reconftw.cfg" 2>/dev/null || true
    export SCRIPTPATH="$project_root"
    source "$project_root/reconftw.sh" --source-only
}

# validate_domain tests
@test "validate_domain accepts valid domain" {
    run validate_domain "example.com"
    [ "$status" -eq 0 ]
}

@test "validate_domain accepts subdomain" {
    run validate_domain "sub.example.com"
    [ "$status" -eq 0 ]
}

@test "validate_domain accepts deep subdomain" {
    run validate_domain "a.b.c.example.com"
    [ "$status" -eq 0 ]
}

@test "validate_domain rejects empty string" {
    run validate_domain ""
    [ "$status" -ne 0 ]
}

@test "validate_domain rejects domain with semicolon" {
    run validate_domain "example.com;ls"
    [ "$status" -ne 0 ]
}

@test "validate_domain rejects domain with pipe" {
    run validate_domain "example.com|cat"
    [ "$status" -ne 0 ]
}

@test "validate_domain rejects domain with backticks" {
    run validate_domain 'example`id`.com'
    [ "$status" -ne 0 ]
}

# validate_ipv4 tests
@test "validate_ipv4 accepts valid IP" {
    run validate_ipv4 "192.168.1.1"
    [ "$status" -eq 0 ]
}

@test "validate_ipv4 accepts 0.0.0.0" {
    run validate_ipv4 "0.0.0.0"
    [ "$status" -eq 0 ]
}

@test "validate_ipv4 accepts 255.255.255.255" {
    run validate_ipv4 "255.255.255.255"
    [ "$status" -eq 0 ]
}

@test "validate_ipv4 rejects IP with octet > 255" {
    run validate_ipv4 "256.1.1.1"
    [ "$status" -ne 0 ]
}

@test "validate_ipv4 rejects incomplete IP" {
    run validate_ipv4 "192.168.1"
    [ "$status" -ne 0 ]
}

@test "validate_ipv4 rejects IP with letters" {
    run validate_ipv4 "192.168.1.abc"
    [ "$status" -ne 0 ]
}

@test "validate_ipv4 rejects empty string" {
    run validate_ipv4 ""
    [ "$status" -ne 0 ]
}

# validate_boolean tests
@test "validate_boolean accepts true" {
    run validate_boolean "true"
    [ "$status" -eq 0 ]
}

@test "validate_boolean accepts false" {
    run validate_boolean "false"
    [ "$status" -eq 0 ]
}

@test "validate_boolean accepts TRUE (case insensitive)" {
    run validate_boolean "TRUE"
    [ "$status" -eq 0 ]
}

@test "validate_boolean accepts FALSE (case insensitive)" {
    run validate_boolean "FALSE"
    [ "$status" -eq 0 ]
}

@test "validate_boolean rejects yes" {
    run validate_boolean "yes"
    [ "$status" -ne 0 ]
}

@test "validate_boolean rejects 1" {
    run validate_boolean "1"
    [ "$status" -ne 0 ]
}

@test "validate_boolean rejects empty" {
    run validate_boolean ""
    [ "$status" -ne 0 ]
}

@test "validate_boolean rejects random string" {
    run validate_boolean "maybe"
    [ "$status" -ne 0 ]
}
