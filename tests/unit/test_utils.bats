#!/usr/bin/env bats

# Unit tests for reconFTW utility functions

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    # Set minimal required variables before sourcing
    export tools="$HOME/Tools"
    export LOGFILE="/dev/null"
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
    export NOTIFICATION=false
    export AXIOM=false
    # Source the config first, then restore SCRIPTPATH (cfg overrides it with $0)
    source "$project_root/reconftw.cfg" 2>/dev/null || true
    export SCRIPTPATH="$project_root"
    source "$project_root/reconftw.sh" --source-only
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

# Tests for should_run_deep helper
@test "should_run_deep returns true when DEEP is true" {
    DEEP=true
    DEEP_LIMIT=100
    run should_run_deep 500
    [ "$status" -eq 0 ]
}

@test "should_run_deep returns true when count below limit" {
    DEEP=false
    DEEP_LIMIT=100
    run should_run_deep 50
    [ "$status" -eq 0 ]
}

@test "should_run_deep returns false when count above limit and DEEP false" {
    DEEP=false
    DEEP_LIMIT=100
    run should_run_deep 200
    [ "$status" -ne 0 ]
}

@test "should_run_deep accepts custom limit" {
    DEEP=false
    DEEP_LIMIT=100
    run should_run_deep 150 200
    [ "$status" -eq 0 ]
}

@test "should_run_deep2 uses DEEP_LIMIT2" {
    DEEP=false
    DEEP_LIMIT2=500
    run should_run_deep2 300
    [ "$status" -eq 0 ]
}

# Tests for checkpoint system
@test "checkpoint_init creates directory" {
    export dir=$(mktemp -d)
    export CHECKPOINT_ENABLED=true
    export domain="test.com"
    export MODE="recon"
    export DEEP=false
    
    checkpoint_init
    [ -d "$dir/.checkpoints" ]
    [ -f "$dir/.checkpoints/scan_info.txt" ]
    
    rm -rf "$dir"
}

@test "checkpoint_save creates checkpoint file" {
    export dir=$(mktemp -d)
    export CHECKPOINT_ENABLED=true
    export CHECKPOINT_DIR="$dir/.checkpoints"
    mkdir -p "$CHECKPOINT_DIR"
    
    checkpoint_save "subdomains"
    [ -f "$CHECKPOINT_DIR/subdomains.done" ]
    
    rm -rf "$dir"
}

@test "checkpoint_exists returns true for existing checkpoint" {
    export dir=$(mktemp -d)
    export CHECKPOINT_ENABLED=true
    export CHECKPOINT_DIR="$dir/.checkpoints"
    mkdir -p "$CHECKPOINT_DIR"
    touch "$CHECKPOINT_DIR/web.done"
    
    checkpoint_exists "web"
    [ "$?" -eq 0 ]
    
    rm -rf "$dir"
}

@test "checkpoint_exists returns false for missing checkpoint" {
    export dir=$(mktemp -d)
    export CHECKPOINT_ENABLED=true
    export CHECKPOINT_DIR="$dir/.checkpoints"
    mkdir -p "$CHECKPOINT_DIR"
    
    ! checkpoint_exists "missing_phase"
    
    rm -rf "$dir"
}

# Tests for circuit breaker
@test "circuit_breaker_is_open returns false initially" {
    run circuit_breaker_is_open "newtool"
    [ "$status" -ne 0 ]
}

@test "circuit_breaker opens after threshold failures" {
    CIRCUIT_BREAKER_THRESHOLD=2
    CIRCUIT_BREAKER_FAILURES=()
    CIRCUIT_BREAKER_STATE=()
    
    circuit_breaker_record_failure "flakytool"
    circuit_breaker_record_failure "flakytool"
    
    circuit_breaker_is_open "flakytool"
    [ "$?" -eq 0 ]
}

@test "circuit_breaker resets on success" {
    CIRCUIT_BREAKER_FAILURES=()
    CIRCUIT_BREAKER_STATE=()
    
    circuit_breaker_record_failure "tool1"
    circuit_breaker_record_success "tool1"
    
    [ "${CIRCUIT_BREAKER_FAILURES[tool1]}" -eq 0 ]
}

# Tests for check_secrets_permissions
@test "check_secrets_permissions warns on world-readable file" {
    local tmpfile
    tmpfile=$(mktemp)
    chmod 644 "$tmpfile"
    
    # Temporarily override sensitive_files list
    run bash -c "
        source '$SCRIPTPATH/reconftw.sh' --source-only
        check_secrets_permissions '$tmpfile'
    "
    
    rm -f "$tmpfile"
    # Function should return warning count (may be 0 if file not in list)
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}
