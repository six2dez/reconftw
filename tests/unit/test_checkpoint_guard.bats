#!/usr/bin/env bats

# Checkpoint guard: a function whose $called_fn_dir/.<name> sentinel exists must
# not run again unless DIFF=true. nuclei_check/test_ssl gate through
# should_run() (lib/common.sh) and metadata through the inline guard; this
# proves all three honour the sentinel by watching start_func's log line.

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export SCRIPTPATH="$project_root"
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''

    export TEST_DIR="$BATS_TEST_TMPDIR/reconftw_guard"
    export dir="$TEST_DIR/target.example.com"
    export called_fn_dir="$dir/.called_fn"
    mkdir -p "$called_fn_dir" "$dir"
    cd "$dir"
    export LOGFILE="$TEST_DIR/log.txt"
    : >"$LOGFILE"

    # Empty PATH dir first so no real nuclei/testssl/exifray is reachable
    export MOCK_BIN="$TEST_DIR/mockbin"
    mkdir -p "$MOCK_BIN"
    export PATH="$MOCK_BIN:$PATH"

    source "$project_root/reconftw.sh" --source-only

    export domain="target.example.com"
    export DIFF=false
    export AXIOM=false
    export OSINT=true
    export NUCLEICHECK=true
    export TEST_SSL=true
    export METADATA=true
    export MIN_DISK_SPACE_GB=0
    export tools="$TEST_DIR/tools"
    export NUCLEI_TEMPLATES_PATH="$TEST_DIR/no-templates"
}

teardown() {
    [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

_started() { grep -q "Start function: $1" "$LOGFILE"; }

@test "nuclei_check skips when its checkpoint exists" {
    touch "$called_fn_dir/.nuclei_check"
    run nuclei_check
    [ "$status" -eq 0 ]
    ! _started nuclei_check
    [[ "$output" != *"nuclei binary not found"* ]]
}

@test "nuclei_check runs again when DIFF=true despite the checkpoint" {
    touch "$called_fn_dir/.nuclei_check"
    export DIFF=true
    run nuclei_check
    # The guard is passed: the next gate (nuclei binary) is reached
    [[ "$output" == *"nuclei binary not found"* ]]
}

@test "test_ssl skips when its checkpoint exists" {
    touch "$called_fn_dir/.test_ssl"
    run test_ssl
    [ "$status" -eq 0 ]
    ! _started test_ssl
}

@test "test_ssl runs when the checkpoint is absent" {
    run test_ssl
    _started test_ssl
}

@test "metadata skips when its checkpoint exists" {
    touch "$called_fn_dir/.metadata"
    run metadata
    [ "$status" -eq 0 ]
    ! _started metadata
}

@test "metadata runs when the checkpoint is absent" {
    run metadata
    _started metadata
}
