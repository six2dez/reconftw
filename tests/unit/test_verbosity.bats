#!/usr/bin/env bats
# Tests for OUTPUT_VERBOSITY gating across core functions

setup() {
    TEST_DIR=$(mktemp -d)
    cd "$TEST_DIR" || exit 1

    # Minimal color vars
    bred=""
    bblue=""
    bgreen=""
    byellow=""
    yellow=""
    reset=""
    cyan=""
    green=""
    red=""
    blue=""

    # Stubs for sourced modules
    SCRIPTPATH="${BATS_TEST_DIRNAME}/../.."
    LOGFILE="/dev/null"
    NOTIFICATION=false
    DIFF=false
    domain="test.com"
    called_fn_dir="$TEST_DIR/.called_fn"
    mkdir -p "$called_fn_dir"

    # Stubs for functions used by start_func/end_func
    getElapsedTime() { runtime="0s"; }
    record_func_timing() { :; }
    log_json() { :; }

    # Source common.sh (skip re-source guard)
    _COMMON_SH_LOADED=""
    source "${BATS_TEST_DIRNAME}/../../lib/common.sh"

    # Extract individual functions from core.sh using sed
    local corefile="${BATS_TEST_DIRNAME}/../../modules/core.sh"

    # Extract notification function
    eval "$(sed -n '/^function notification()/,/^}/p' "$corefile")"
    # Extract start_func
    eval "$(sed -n '/^function start_func()/,/^}/p' "$corefile")"
    # Extract end_func
    eval "$(sed -n '/^function end_func()/,/^}/p' "$corefile")"
    # Extract progress_step
    eval "$(sed -n '/^function progress_step()/,/^}/p' "$corefile")"
}

teardown() {
    cd /
    rm -rf "$TEST_DIR"
}

###############################################################################
# notification() verbosity tests
###############################################################################

@test "notification suppresses info at verbosity 1" {
    OUTPUT_VERBOSITY=1
    run notification "hello world" info
    [ "$status" -eq 0 ]
    [[ "$output" == "" ]]
}

@test "notification suppresses info at verbosity 0" {
    OUTPUT_VERBOSITY=0
    run notification "hello world" info
    [ "$status" -eq 0 ]
    [[ "$output" == "" ]]
}

@test "notification shows errors at verbosity 0" {
    OUTPUT_VERBOSITY=0
    run notification "something broke" error
    [ "$status" -eq 0 ]
    [[ "$output" == *"something broke"* ]]
}

@test "notification shows all at verbosity 2" {
    OUTPUT_VERBOSITY=2
    run notification "detail info" info
    [ "$status" -eq 0 ]
    [[ "$output" == *"detail info"* ]]
}

###############################################################################
# skip_notification() verbosity tests
###############################################################################

@test "skip_notification prints at verbosity 1" {
    OUTPUT_VERBOSITY=1
    run skip_notification "disabled"
    [ "$status" -eq 0 ]
    [[ "$output" == *"SKIP"* ]]
}

@test "skip_notification suppressed at verbosity 0" {
    OUTPUT_VERBOSITY=0
    run skip_notification "disabled"
    [ "$status" -eq 0 ]
    [[ "$output" == "" ]]
}

###############################################################################
# start_func / end_func verbosity tests
###############################################################################

@test "start_func silent at verbosity 1" {
    OUTPUT_VERBOSITY=1
    run start_func "test_fn" "Testing function"
    [ "$status" -eq 0 ]
    # start_func no longer produces visible output (only logs)
    [[ "$output" == "" ]]
}

@test "start_func hides rule at verbosity 0" {
    OUTPUT_VERBOSITY=0
    run start_func "test_fn" "Testing function"
    [ "$status" -eq 0 ]
    [[ "$output" != *"──"* ]]
}

@test "end_func shows status at verbosity 1" {
    OUTPUT_VERBOSITY=1
    start=1
    run end_func "Results" "test_fn"
    [ "$status" -eq 0 ]
    [[ "$output" == *"OK"* ]]
}

@test "end_func hides status at verbosity 0" {
    OUTPUT_VERBOSITY=0
    start=1
    run end_func "Results" "test_fn"
    [ "$status" -eq 0 ]
    [[ "$output" != *"OK"* ]]
}

###############################################################################
# progress_step() verbosity tests
###############################################################################

@test "progress_step prints at verbosity 1" {
    OUTPUT_VERBOSITY=1
    _PROGRESS_TOTAL_STEPS=10
    _PROGRESS_CURRENT_STEP=0
    _PROGRESS_START_TIME=$(date +%s)
    run progress_step "scanning"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Progress"* ]]
}

@test "progress_step suppressed at verbosity 0" {
    OUTPUT_VERBOSITY=0
    _PROGRESS_TOTAL_STEPS=10
    _PROGRESS_CURRENT_STEP=0
    _PROGRESS_START_TIME=$(date +%s)
    run progress_step "scanning"
    [ "$status" -eq 0 ]
    [[ "$output" == "" ]]
}
