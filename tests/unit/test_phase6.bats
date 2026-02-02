#!/usr/bin/env bats

# Unit tests for Phase 6 features (Incremental, Dry-Run, Adaptive Rate)

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export SCRIPTPATH="$project_root"
    export LOGFILE="/dev/null"
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
    source "$project_root/reconftw.sh" --source-only
}

@test "run_command executes command in normal mode" {
    run run_command echo "hello"
    [ "$status" -eq 0 ]
    [ "$output" = "hello" ]
}

@test "run_command prints command in dry-run mode" {
    export DRY_RUN="true"
    run run_command echo "hello"
    [ "$status" -eq 0 ]
    [[ "$output" == *"[DRY-RUN] Would execute: echo hello"* ]]
}

@test "incremental_init creates directory structure" {
    export INCREMENTAL_MODE="true"
    export INCREMENTAL_DIR=".tmp_incremental"
    run incremental_init
    [ "$status" -eq 0 ]
    [ -d "$INCREMENTAL_DIR/previous" ]
    rm -rf "$INCREMENTAL_DIR"
}

@test "incremental_diff finds new items" {
    export INCREMENTAL_MODE="true"
    export INCREMENTAL_DIR=".tmp_incremental"
    mkdir -p "$INCREMENTAL_DIR/previous"
    
    echo "item1" > "$INCREMENTAL_DIR/previous/test_latest.txt"
    echo "item1" > "current.txt"
    echo "item2" >> "current.txt"
    
    run incremental_diff "test" "current.txt" "new.txt"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Incremental mode test: 1 new"* ]]
    [ "$(cat new.txt)" = "item2" ]
    
    rm -rf "$INCREMENTAL_DIR" "current.txt" "new.txt"
}

@test "detect_rate_limit_error detects 429" {
    run detect_rate_limit_error "Error: 429 Too Many Requests"
    [ "$status" -eq 0 ]
}

@test "detect_rate_limit_error ignores normal output" {
    run detect_rate_limit_error "Found 10 subdomains"
    [ "$status" -eq 1 ]
}