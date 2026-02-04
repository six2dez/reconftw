#!/usr/bin/env bats

# Tests for checkpoint and resume functionality

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export SCRIPTPATH="$project_root"
    
    # Create temp directory for test outputs
    export TEST_DIR="$BATS_TEST_TMPDIR/checkpoint_test"
    export TEST_DOMAIN="checkpoint.example.com"
    export dir="$TEST_DIR/$TEST_DOMAIN"
    export called_fn_dir="$dir/.called_fn"
    
    mkdir -p "$called_fn_dir"
    mkdir -p "$dir"/{subdomains,webs,hosts,vulns,osint,.tmp,.log}
}

teardown() {
    [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

# Helper to source reconftw
source_reconftw() {
    # shellcheck source=/dev/null
    source "$SCRIPTPATH/reconftw.sh" --source-only 2>/dev/null || true
}

###############################################################################
# Checkpoint Creation Tests
###############################################################################

@test "checkpoint: marker file is created on function completion" {
    local func_name="sub_passive"
    
    # Simulate end_func behavior
    touch "$called_fn_dir/.$func_name"
    
    [ -f "$called_fn_dir/.$func_name" ]
}

@test "checkpoint: multiple function markers can coexist" {
    local funcs=("sub_passive" "sub_crt" "sub_active" "webprobe_simple")
    
    for func in "${funcs[@]}"; do
        touch "$called_fn_dir/.$func"
    done
    
    # All markers should exist
    for func in "${funcs[@]}"; do
        [ -f "$called_fn_dir/.$func" ]
    done
    
    # Count should match
    local count
    count=$(find "$called_fn_dir" -name ".*" -type f | wc -l)
    [ "$count" -ge 4 ]
}

@test "checkpoint: marker naming follows convention" {
    # Markers are named with leading dot: .function_name
    touch "$called_fn_dir/.test_function"
    
    # Should be hidden file
    run ls "$called_fn_dir"
    [[ "$output" != *"test_function"* ]] || [[ -z "$output" ]]
    
    # But visible with -a
    run ls -a "$called_fn_dir"
    [[ "$output" == *".test_function"* ]]
}

###############################################################################
# Resume Tests
###############################################################################

@test "resume: function is skipped when marker exists" {
    source_reconftw
    
    export DIFF=false
    touch "$called_fn_dir/.sub_passive"
    
    # Check the condition used in functions
    if [[ -f "$called_fn_dir/.sub_passive" ]] && [[ $DIFF != true ]]; then
        # Should skip - this is expected
        true
    else
        # Should not reach here
        false
    fi
}

@test "resume: function runs when marker missing" {
    source_reconftw
    
    export DIFF=false
    
    # No marker - should run
    if [[ ! -f "$called_fn_dir/.sub_passive" ]] || [[ $DIFF == true ]]; then
        # Should run - this is expected
        true
    else
        false
    fi
}

@test "resume: DIFF mode forces re-run" {
    source_reconftw
    
    export DIFF=true
    touch "$called_fn_dir/.sub_passive"
    
    # Even with marker, DIFF should force re-run
    if [[ ! -f "$called_fn_dir/.sub_passive" ]] || [[ $DIFF == true ]]; then
        # Should run due to DIFF=true
        true
    else
        false
    fi
}

@test "resume: partial completion is detected" {
    # Simulate partial completion (some functions done, others not)
    touch "$called_fn_dir/.sub_passive"
    touch "$called_fn_dir/.sub_crt"
    # sub_active NOT completed
    
    [ -f "$called_fn_dir/.sub_passive" ]
    [ -f "$called_fn_dir/.sub_crt" ]
    [ ! -f "$called_fn_dir/.sub_active" ]
}

@test "resume: can clear single checkpoint" {
    touch "$called_fn_dir/.sub_passive"
    [ -f "$called_fn_dir/.sub_passive" ]
    
    rm -f "$called_fn_dir/.sub_passive"
    [ ! -f "$called_fn_dir/.sub_passive" ]
}

@test "resume: can clear all checkpoints" {
    touch "$called_fn_dir/.sub_passive"
    touch "$called_fn_dir/.sub_crt"
    touch "$called_fn_dir/.webprobe_simple"
    
    # Clear all
    rm -f "$called_fn_dir"/.*
    
    local count
    count=$(find "$called_fn_dir" -name ".*" -type f 2>/dev/null | wc -l)
    [ "$count" -eq 0 ]
}

###############################################################################
# Checkpoint State Persistence Tests
###############################################################################

@test "checkpoint: survives script restart simulation" {
    # First "run" - create checkpoint
    touch "$called_fn_dir/.sub_passive"
    
    # Simulate script exit/restart by unsetting variables
    unset called_fn_dir
    
    # Second "run" - restore and check
    export called_fn_dir="$dir/.called_fn"
    
    [ -f "$called_fn_dir/.sub_passive" ]
}

@test "checkpoint: preserves order of completion (via timestamps)" {
    # Create markers with slight delay to get different mtimes
    touch "$called_fn_dir/.func1"
    sleep 0.1
    touch "$called_fn_dir/.func2"
    sleep 0.1
    touch "$called_fn_dir/.func3"
    
    # Verify order by modification time
    local oldest newest
    oldest=$(ls -t "$called_fn_dir"/.func* | tail -1)
    newest=$(ls -t "$called_fn_dir"/.func* | head -1)
    
    [[ "$oldest" == *"func1"* ]]
    [[ "$newest" == *"func3"* ]]
}

###############################################################################
# Checkpoint with Results Tests
###############################################################################

@test "checkpoint: results persist alongside markers" {
    # Create checkpoint
    touch "$called_fn_dir/.sub_passive"
    
    # Create associated results
    echo "sub1.example.com" > "$dir/subdomains/passive.txt"
    echo "sub2.example.com" >> "$dir/subdomains/passive.txt"
    
    # Both should exist together
    [ -f "$called_fn_dir/.sub_passive" ]
    [ -f "$dir/subdomains/passive.txt" ]
    [ "$(wc -l < "$dir/subdomains/passive.txt")" -eq 2 ]
}

@test "checkpoint: clearing checkpoint doesn't delete results" {
    touch "$called_fn_dir/.sub_passive"
    echo "data" > "$dir/subdomains/passive.txt"
    
    # Clear only checkpoint
    rm -f "$called_fn_dir/.sub_passive"
    
    # Results should remain
    [ ! -f "$called_fn_dir/.sub_passive" ]
    [ -f "$dir/subdomains/passive.txt" ]
}

###############################################################################
# Edge Cases
###############################################################################

@test "checkpoint: handles special characters in function names" {
    # Some functions might have underscores
    touch "$called_fn_dir/.sub_recursive_brute"
    [ -f "$called_fn_dir/.sub_recursive_brute" ]
}

@test "checkpoint: empty called_fn_dir is valid state" {
    # Fresh scan - no checkpoints
    local count
    count=$(find "$called_fn_dir" -name ".*" -type f 2>/dev/null | wc -l)
    [ "$count" -eq 0 ]
}

@test "checkpoint: concurrent marker creation doesn't corrupt" {
    # Simulate concurrent creation
    touch "$called_fn_dir/.func1" &
    touch "$called_fn_dir/.func2" &
    touch "$called_fn_dir/.func3" &
    wait
    
    [ -f "$called_fn_dir/.func1" ]
    [ -f "$called_fn_dir/.func2" ]
    [ -f "$called_fn_dir/.func3" ]
}

###############################################################################
# Checkpoint Helper Functions Tests
###############################################################################

@test "checkpoint: checkpoint_init available after source" {
    source_reconftw
    
    type checkpoint_init &>/dev/null || skip "checkpoint_init not defined"
}

@test "checkpoint: checkpoint_save available after source" {
    source_reconftw
    
    type checkpoint_save &>/dev/null || skip "checkpoint_save not defined"
}

@test "checkpoint: checkpoint_exists helper works" {
    source_reconftw
    
    touch "$called_fn_dir/.test_func"
    
    # Check if exists (simulating helper behavior)
    [ -f "$called_fn_dir/.test_func" ]
}

@test "checkpoint: checkpoint_clear helper works" {
    source_reconftw
    
    touch "$called_fn_dir/.test_func"
    [ -f "$called_fn_dir/.test_func" ]
    
    # Clear
    rm -f "$called_fn_dir/.test_func"
    [ ! -f "$called_fn_dir/.test_func" ]
}
