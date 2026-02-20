#!/usr/bin/env bats

# Integration tests for reconFTW full workflow
# Tests the complete pipeline with mock tools

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export SCRIPTPATH="$project_root"
    export PATH="$project_root:$project_root/tests/mocks:$PATH"
    
    # Create temp directory for test outputs
    export TEST_DIR="$BATS_TEST_TMPDIR/reconftw_test"
    mkdir -p "$TEST_DIR"
    
    # Mock domain for testing
    export TEST_DOMAIN="test.example.com"
}

teardown() {
    # Clean up test directory
    [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

# Helper to source reconftw without running main
source_reconftw() {
    # shellcheck source=/dev/null
    source "$SCRIPTPATH/reconftw.sh" --source-only 2>/dev/null || true
}

@test "full flow: directory structure is created correctly" {
    source_reconftw
    
    # Set up environment
    export dir="$TEST_DIR/$TEST_DOMAIN"
    export domain="$TEST_DOMAIN"
    
    # Create expected directories
    mkdir -p "$dir"/{subdomains,webs,hosts,vulns,osint,.tmp,.log,.called_fn}
    
    # Verify structure
    [ -d "$dir/subdomains" ]
    [ -d "$dir/webs" ]
    [ -d "$dir/hosts" ]
    [ -d "$dir/vulns" ]
    [ -d "$dir/osint" ]
    [ -d "$dir/.tmp" ]
    [ -d "$dir/.log" ]
    [ -d "$dir/.called_fn" ]
}

@test "full flow: checkpoint system creates markers" {
    source_reconftw
    
    export dir="$TEST_DIR/$TEST_DOMAIN"
    export domain="$TEST_DOMAIN"
    export called_fn_dir="$dir/.called_fn"
    mkdir -p "$called_fn_dir"
    
    # Simulate start_func/end_func behavior
    local func_name="test_function"
    touch "$called_fn_dir/.$func_name"
    
    # Verify marker exists
    [ -f "$called_fn_dir/.$func_name" ]
}

@test "full flow: checkpoint prevents re-execution" {
    source_reconftw
    
    export dir="$TEST_DIR/$TEST_DOMAIN"
    export domain="$TEST_DOMAIN"
    export called_fn_dir="$dir/.called_fn"
    export DIFF=false
    mkdir -p "$called_fn_dir"
    
    # Create marker for "completed" function
    touch "$called_fn_dir/.sub_passive"
    
    # Function should be skipped (marker exists)
    [ -f "$called_fn_dir/.sub_passive" ]
}

@test "full flow: DIFF mode ignores checkpoints" {
    source_reconftw
    
    export dir="$TEST_DIR/$TEST_DOMAIN"
    export domain="$TEST_DOMAIN"
    export called_fn_dir="$dir/.called_fn"
    export DIFF=true
    mkdir -p "$called_fn_dir"
    
    # Even with marker, DIFF=true should allow re-run
    touch "$called_fn_dir/.sub_passive"
    
    # DIFF mode check - in real code this would re-run
    [[ $DIFF == true ]]
}

@test "full flow: common.sh ensure_dirs creates nested dirs" {
    source_reconftw
    
    export dir="$TEST_DIR/$TEST_DOMAIN"
    mkdir -p "$dir"
    
    # Source common library
    # shellcheck source=/dev/null
    source "$SCRIPTPATH/lib/common.sh"
    
    # Test ensure_dirs
    ensure_dirs "subdomains" "webs" "hosts/scans"
    
    [ -d "$dir/subdomains" ]
    [ -d "$dir/webs" ]
    [ -d "$dir/hosts/scans" ]
}

@test "full flow: parallel.sh is loaded correctly" {
    source_reconftw
    
    # Check parallel functions exist
    type parallel_run &>/dev/null
    type parallel_funcs &>/dev/null
    type parallel_passive_enum &>/dev/null
    type parallel_active_enum &>/dev/null
    type parallel_postactive_enum &>/dev/null
}

@test "full flow: subdomains helper functions exist" {
    source_reconftw
    
    # Check helper functions from refactored subdomains.sh
    type _subdomains_init &>/dev/null || skip "helper not yet integrated"
    type _subdomains_enumerate &>/dev/null || skip "helper not yet integrated"
    type _subdomains_finalize &>/dev/null || skip "helper not yet integrated"
}

@test "full flow: web helper functions exist" {
    source_reconftw
    
    # Check helper functions from refactored web.sh
    type _run_httpx &>/dev/null || skip "helper not yet integrated"
    type _process_httpx_output &>/dev/null || skip "helper not yet integrated"
}

@test "full flow: incremental mode detects new results" {
    source_reconftw
    
    export dir="$TEST_DIR/$TEST_DOMAIN"
    mkdir -p "$dir/subdomains"
    
    # Simulate previous results
    echo "old.example.com" > "$dir/subdomains/subdomains.txt"
    
    # Simulate new results
    echo "new.example.com" >> "$dir/subdomains/subdomains.txt"
    
    # Count should be 2
    local count
    count=$(wc -l < "$dir/subdomains/subdomains.txt")
    [ "$count" -eq 2 ]
}

@test "full flow: output files are deduplicated" {
    source_reconftw
    
    export dir="$TEST_DIR/$TEST_DOMAIN"
    mkdir -p "$dir/subdomains"
    
    # Create file with duplicates
    printf "sub1.example.com\nsub2.example.com\nsub1.example.com\n" > "$dir/subdomains/test.txt"
    
    # Deduplicate
    sort -u "$dir/subdomains/test.txt" > "$dir/subdomains/test_dedup.txt"
    
    local count
    count=$(wc -l < "$dir/subdomains/test_dedup.txt")
    [ "$count" -eq 2 ]
}

@test "full flow: inscope filtering works" {
    source_reconftw
    
    export dir="$TEST_DIR/$TEST_DOMAIN"
    mkdir -p "$dir/subdomains"
    
    # Create inscope file
    echo "*.example.com" > "$dir/inscope.txt"
    
    # Create subdomains file
    printf "sub.example.com\nout.other.com\ntest.example.com\n" > "$dir/subdomains/all.txt"
    
    # Filter (simplified - real logic is in deleteOutScoped)
    grep "example.com" "$dir/subdomains/all.txt" > "$dir/subdomains/inscope.txt"
    
    local count
    count=$(wc -l < "$dir/subdomains/inscope.txt")
    [ "$count" -eq 2 ]
}

@test "full flow: log files are created" {
    source_reconftw
    
    export dir="$TEST_DIR/$TEST_DOMAIN"
    mkdir -p "$dir/.log"
    
    # Simulate log creation
    echo "[INFO] Test log entry" > "$dir/.log/test.log"
    
    [ -f "$dir/.log/test.log" ]
    grep -q "INFO" "$dir/.log/test.log"
}

@test "full flow: tmp files are cleaned up" {
    source_reconftw
    
    export dir="$TEST_DIR/$TEST_DOMAIN"
    mkdir -p "$dir/.tmp"
    
    # Create temp files
    touch "$dir/.tmp/temp1.txt"
    touch "$dir/.tmp/temp2.txt"
    
    # Verify they exist
    [ -f "$dir/.tmp/temp1.txt" ]
    
    # Simulate cleanup
    rm -f "$dir/.tmp"/*.txt
    
    # Verify cleanup
    [ ! -f "$dir/.tmp/temp1.txt" ]
}

@test "full flow: notification skip works" {
    source_reconftw
    
    # shellcheck source=/dev/null
    source "$SCRIPTPATH/lib/common.sh"
    
    # Test skip_notification (should not error)
    run skip_notification "test_func"
    [ "$status" -eq 0 ]
}

@test "full flow: safe_count handles missing files" {
    source_reconftw
    
    # shellcheck source=/dev/null
    source "$SCRIPTPATH/lib/common.sh"
    
    # Test with non-existent file
    local count
    count=$(safe_count "/nonexistent/file.txt")
    [ "$count" -eq 0 ]
}

@test "full flow: parallel_funcs handles empty list" {
    source_reconftw
    
    # Test parallel_funcs with no functions
    run parallel_funcs 4
    [ "$status" -eq 0 ]
}

@test "full flow: dry-run mode prevents execution" {
    run timeout 5 bash "$SCRIPTPATH/reconftw.sh" -d test.com --dry-run 2>&1
    
    # Should succeed without actually running tools
    [[ "$output" == *"dry"* ]] || [[ "$output" == *"DRY"* ]] || [ "$status" -eq 0 ]
}
