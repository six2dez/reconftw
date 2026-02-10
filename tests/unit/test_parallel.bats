#!/usr/bin/env bats
# Tests for lib/parallel.sh parallel execution utilities

setup() {
    # Source common library (needed for _print_status used by parallel output)
    source "${BATS_TEST_DIRNAME}/../../lib/common.sh"
    # Source the parallel library
    source "${BATS_TEST_DIRNAME}/../../lib/parallel.sh"

    # Create temp directory for tests
    TEST_DIR=$(mktemp -d)
    cd "$TEST_DIR" || exit 1

    # Set up mock variables
    yellow=""
    reset=""
    bred=""
    bblue=""
    bgreen=""
    cyan=""
    VERBOSE=false
    PARALLEL_LOG_MODE="summary"
    PARALLEL_TAIL_LINES=20
    OUTPUT_VERBOSITY=1
}

teardown() {
    cd /
    rm -rf "$TEST_DIR"
}

###############################################################################
# parallel_run tests
###############################################################################

@test "parallel_run executes single command" {
    run parallel_run 2 "echo hello > out1.txt"
    [ "$status" -eq 0 ]
    [ -f "out1.txt" ]
    [ "$(cat out1.txt)" = "hello" ]
}

@test "parallel_run executes multiple commands" {
    run parallel_run 2 "echo a > a.txt" "echo b > b.txt" "echo c > c.txt"
    [ "$status" -eq 0 ]
    [ -f "a.txt" ]
    [ -f "b.txt" ]
    [ -f "c.txt" ]
}

@test "parallel_run respects job limit" {
    # This test verifies commands complete (timing would be flaky)
    run parallel_run 2 "sleep 0.1 && echo 1 > 1.txt" "sleep 0.1 && echo 2 > 2.txt" "sleep 0.1 && echo 3 > 3.txt"
    [ "$status" -eq 0 ]
    [ -f "1.txt" ]
    [ -f "2.txt" ]
    [ -f "3.txt" ]
}

###############################################################################
# parallel_funcs tests
###############################################################################

@test "parallel_funcs runs functions" {
    # Define test functions
    func1() { echo "func1" > func1.txt; }
    func2() { echo "func2" > func2.txt; }
    
    run parallel_funcs 2 func1 func2
    [ "$status" -eq 0 ]
    [ -f "func1.txt" ]
    [ -f "func2.txt" ]
}

@test "parallel_funcs skips undefined functions" {
    func1() { echo "exists" > exists.txt; }
    
    run parallel_funcs 2 func1 undefined_function_xyz
    # Should complete (skipping the undefined one)
    [ -f "exists.txt" ]
}

@test "parallel_funcs returns failure count" {
    success_func() { return 0; }
    fail_func() { return 1; }
    
    run parallel_funcs 2 success_func fail_func
    # Status should be non-zero (1 failure)
    [ "$status" -eq 1 ]
}

@test "parallel_funcs buffers output per function" {
    PARALLEL_LOG_MODE="full"
    func_a() { echo "A1"; sleep 0.05; echo "A2"; }
    func_b() { echo "B1"; sleep 0.05; echo "B2"; }

    run parallel_funcs 2 func_a func_b
    [ "$status" -eq 0 ]
    [[ "$output" == *"A1"* ]]
    [[ "$output" == *"A2"* ]]
    [[ "$output" == *"B1"* ]]
    [[ "$output" == *"B2"* ]]
}

@test "parallel_funcs cleans temporary buffered output" {
    func_ok() { echo "ok"; }

    run parallel_funcs 2 func_ok
    [ "$status" -eq 0 ]
    [ ! -d "/tmp/reconftw_parallel.$$" ]
}

###############################################################################
# parallel_batch tests
###############################################################################

@test "parallel_batch runs functions in batches" {
    func1() { echo "1" >> order.txt; sleep 0.1; }
    func2() { echo "2" >> order.txt; sleep 0.1; }
    func3() { echo "3" >> order.txt; sleep 0.1; }
    func4() { echo "4" >> order.txt; }
    
    run parallel_batch 2 func1 func2 func3 func4
    [ "$status" -eq 0 ]
    # All functions should have run
    [ "$(wc -l < order.txt | tr -d ' ')" -eq 4 ]
}

###############################################################################
# get_running_jobs tests
###############################################################################

@test "get_running_jobs returns 0 when no jobs" {
    result=$(get_running_jobs)
    [ "$result" -eq 0 ]
}

@test "get_running_jobs counts background jobs" {
    sleep 0.5 &
    sleep 0.5 &
    result=$(get_running_jobs)
    # Should be at least 1 (timing dependent)
    [ "$result" -ge 1 ]
    wait
}

###############################################################################
# cleanup_parallel_jobs tests
###############################################################################

@test "cleanup_parallel_jobs clears PID array" {
    _PARALLEL_PIDS=(12345 67890)
    cleanup_parallel_jobs
    [ "${#_PARALLEL_PIDS[@]}" -eq 0 ]
}

###############################################################################
# Integration tests
###############################################################################

@test "parallel functions work with shared output file" {
    append_func() {
        local id="$1"
        echo "$id" >> shared.txt
    }
    
    # Simulate multiple parallel writes
    ( append_func "a" ) &
    ( append_func "b" ) &
    ( append_func "c" ) &
    wait
    
    # All should be written
    [ "$(wc -l < shared.txt | tr -d ' ')" -eq 3 ]
}

@test "parallel_run handles empty command list" {
    run parallel_run 2
    [ "$status" -eq 0 ]
}

@test "parallel_funcs handles empty function list" {
    run parallel_funcs 2
    [ "$status" -eq 0 ]
}

###############################################################################
# PARALLEL_LOG_MODE tests
###############################################################################

@test "summary mode shows [OK] for successful jobs" {
    PARALLEL_LOG_MODE="summary"
    ok_func() { echo "all good"; }

    run parallel_funcs 2 ok_func
    [ "$status" -eq 0 ]
    [[ "$output" == *"OK"* ]]
    [[ "$output" == *"ok_func"* ]]
}

@test "summary mode shows [FAIL] with last 5 lines on failure" {
    PARALLEL_LOG_MODE="summary"
    OUTPUT_VERBOSITY=2
    bad_func() { echo "line1"; echo "line2"; echo "line3"; echo "line4"; echo "error here"; return 1; }

    run parallel_funcs 2 bad_func
    [ "$status" -eq 1 ]
    [[ "$output" == *"FAIL"* ]]
    [[ "$output" == *"error here"* ]]
}

@test "tail mode shows last N lines of output" {
    PARALLEL_LOG_MODE="tail"
    PARALLEL_TAIL_LINES=3
    chatty_func() { for i in $(seq 1 10); do echo "line$i"; done; }

    run parallel_funcs 2 chatty_func
    [ "$status" -eq 0 ]
    [[ "$output" == *"OK"* ]]
    [[ "$output" == *"line10"* ]]
    [[ "$output" == *"line9"* ]]
    [[ "$output" == *"line8"* ]]
}

@test "full mode shows complete output" {
    PARALLEL_LOG_MODE="full"
    verbose_func() { echo "start"; echo "middle"; echo "end"; }

    run parallel_funcs 2 verbose_func
    [ "$status" -eq 0 ]
    [[ "$output" == *"verbose_func"* ]]
    [[ "$output" == *"start"* ]]
    [[ "$output" == *"middle"* ]]
    [[ "$output" == *"end"* ]]
}

@test "batch summary line is suppressed in summary mode at normal verbosity" {
    PARALLEL_LOG_MODE="summary"
    OUTPUT_VERBOSITY=1
    fast_func() { echo "done"; }

    run parallel_funcs 2 fast_func
    [ "$status" -eq 0 ]
    [[ "$output" != *"batch:"* ]]
    [[ "$output" != *"jobs"* ]]
}

@test "batch summary line is shown in summary mode at verbose" {
    PARALLEL_LOG_MODE="summary"
    OUTPUT_VERBOSITY=2
    fast_func() { echo "done"; }

    run parallel_funcs 2 fast_func
    [ "$status" -eq 0 ]
    [[ "$output" == *"batch:"* ]] || [[ "$output" == *"ok:"* ]]
}

@test "batch summary line is shown in tail mode" {
    PARALLEL_LOG_MODE="tail"
    OUTPUT_VERBOSITY=1
    fast_func() { echo "done"; }

    run parallel_funcs 2 fast_func
    [ "$status" -eq 0 ]
    [[ "$output" == *"batch:"* ]] || [[ "$output" == *"ok:"* ]]
}

@test "quiet mode suppresses OK output in summary" {
    PARALLEL_LOG_MODE="summary"
    OUTPUT_VERBOSITY=0
    quiet_func() { echo "shh"; }

    run parallel_funcs 2 quiet_func
    [ "$status" -eq 0 ]
    # Should NOT show OK in quiet mode
    [[ "$output" != *"OK"* ]]
}

@test "quiet mode still shows failures" {
    PARALLEL_LOG_MODE="summary"
    OUTPUT_VERBOSITY=0
    fail_quiet() { echo "broken"; return 1; }

    run parallel_funcs 2 fail_quiet
    [ "$status" -eq 1 ]
    [[ "$output" == *"FAIL"* ]]
}
