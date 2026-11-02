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

    # Make the tools under test genuinely unreachable. Prepending an empty
    # directory does NOT do that: on a provisioned box ~/go/bin/nuclei stayed on
    # PATH, the "binary not found" branch never ran, and this file only passed on
    # CI's toolless runner. Drop every PATH entry that actually provides one.
    export MOCK_BIN="$TEST_DIR/mockbin"
    mkdir -p "$MOCK_BIN"
    local _kept="" _dir _tool _keep
    local IFS=:
    for _dir in $PATH; do
        [[ -z "$_dir" ]] && continue
        _keep=true
        for _tool in nuclei testssl.sh exiftool; do
            [[ -x "$_dir/$_tool" ]] && _keep=false
        done
        [[ "$_keep" == true ]] && _kept="${_kept:+$_kept:}$_dir"
    done
    unset IFS
    export PATH="$MOCK_BIN:$_kept"
    for _tool in nuclei testssl.sh exiftool; do
        command -v "$_tool" >/dev/null 2>&1 && {
            echo "setup: $_tool is still reachable at $(command -v "$_tool")" >&2
            return 1
        }
    done

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
