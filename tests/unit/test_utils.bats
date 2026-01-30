#!/usr/bin/env bats

# Unit tests for reconFTW utility functions

setup() {
    export SCRIPTPATH="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    # Set minimal required variables before sourcing
    export tools="$HOME/Tools"
    export LOGFILE="/dev/null"
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
    export NOTIFICATION=false
    export AXIOM=false
    # Source the config first, then the script
    source "$SCRIPTPATH/reconftw.cfg" 2>/dev/null || true
    source "$SCRIPTPATH/reconftw.sh" --source-only 2>/dev/null || true
}

@test "getElapsedTime calculates zero duration" {
    getElapsedTime 100 100
    [ "$runtime" = "0 seconds" ]
}

@test "getElapsedTime calculates seconds" {
    getElapsedTime 0 45
    [[ "$runtime" == *"45 seconds"* ]]
}

@test "getElapsedTime calculates minutes and seconds" {
    getElapsedTime 0 125
    [[ "$runtime" == *"2 minutes"* ]]
    [[ "$runtime" == *"5 seconds"* ]]
}

@test "getElapsedTime calculates hours" {
    getElapsedTime 0 3661
    [[ "$runtime" == *"1 hours"* ]]
    [[ "$runtime" == *"1 minutes"* ]]
}

@test "check_disk_space returns success when threshold is 0" {
    run check_disk_space 0 "."
    [ "$status" -eq 0 ]
}

@test "check_disk_space returns success for reasonable threshold" {
    run check_disk_space 1 "."
    [ "$status" -eq 0 ]
}

@test "check_disk_space returns failure for unreasonably large threshold" {
    run check_disk_space 999999 "."
    [ "$status" -ne 0 ]
}

@test "validate_config succeeds with default config" {
    export VULNS_GENERAL=false
    export SUBDOMAINS_GENERAL=true
    export FFUF_THREADS=40
    export HTTPX_THREADS=50
    run validate_config
    [ "$status" -eq 0 ]
}

@test "validate_config warns when VULNS without SUBDOMAINS" {
    export VULNS_GENERAL=true
    export SUBDOMAINS_GENERAL=false
    run validate_config
    [[ "$output" == *"WARN"* ]]
}

@test "validate_config fails on non-numeric threads" {
    export FFUF_THREADS="abc"
    run validate_config
    [ "$status" -ne 0 ]
    [[ "$output" == *"ERROR"* ]]
}

@test "error codes are defined" {
    [ "$E_SUCCESS" -eq 0 ]
    [ "$E_GENERAL" -eq 1 ]
    [ "$E_MISSING_DEP" -eq 2 ]
    [ "$E_INVALID_INPUT" -eq 3 ]
    [ "$E_CONFIG" -eq 8 ]
}
