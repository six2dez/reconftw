#!/usr/bin/env bats

# Smoke tests for reconFTW - basic functionality checks

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export SCRIPTPATH="$project_root"
    export PATH="$project_root:$PATH"
}

@test "reconftw.sh is executable" {
    [ -x "$SCRIPTPATH/reconftw.sh" ]
}

@test "reconftw.sh --help exits successfully" {
    run timeout 10 bash "$SCRIPTPATH/reconftw.sh" --help
    [ "$status" -eq 0 ]
}

@test "reconftw.sh --help shows usage" {
    run timeout 10 bash "$SCRIPTPATH/reconftw.sh" --help
    [[ "$output" == *"Usage"* ]] || [[ "$output" == *"usage"* ]] || [[ "$output" == *"-d"* ]]
}

@test "all modules are loadable" {
    for module in utils core osint subdomains web vulns axiom modes; do
        [ -f "$SCRIPTPATH/modules/${module}.sh" ]
    done
}

@test "lib/validation.sh is loadable" {
    [ -f "$SCRIPTPATH/lib/validation.sh" ]
}

@test "reconftw.cfg exists and is readable" {
    [ -r "$SCRIPTPATH/reconftw.cfg" ]
}

@test "source-only mode works without side effects" {
    run timeout 10 bash -c "source '$SCRIPTPATH/reconftw.sh' --source-only && echo 'OK'"
    [ "$status" -eq 0 ]
    [[ "$output" == *"OK"* ]]
}

@test "sanitize_domain function is available after source" {
    run timeout 10 bash -c "source '$SCRIPTPATH/reconftw.sh' --source-only && type sanitize_domain"
    [ "$status" -eq 0 ]
}

@test "validate_domain function is available after source" {
    run timeout 10 bash -c "source '$SCRIPTPATH/reconftw.sh' --source-only && type validate_domain"
    [ "$status" -eq 0 ]
}

@test "should_run_deep function is available after source" {
    run timeout 10 bash -c "source '$SCRIPTPATH/reconftw.sh' --source-only && type should_run_deep"
    [ "$status" -eq 0 ]
}

@test "checkpoint functions are available after source" {
    run timeout 10 bash -c "source '$SCRIPTPATH/reconftw.sh' --source-only && type checkpoint_init && type checkpoint_save"
    [ "$status" -eq 0 ]
}

@test "circuit_breaker functions are available after source" {
    run timeout 10 bash -c "source '$SCRIPTPATH/reconftw.sh' --source-only && type circuit_breaker_is_open"
    [ "$status" -eq 0 ]
}

@test "invalid domain is sanitized" {
    run timeout 10 bash "$SCRIPTPATH/reconftw.sh" -d "; rm -rf /" --dry-run 2>&1
    # Domain should be sanitized - dangerous chars removed
    [[ "$output" == *"sanitized"* ]] || [[ "$output" == *"rm-rf"* ]]
    # Should NOT execute any dangerous command
    [[ "$output" != *"cannot remove"* ]]
}

@test "missing list file shows error" {
    run timeout 5 bash "$SCRIPTPATH/reconftw.sh" -l "/nonexistent/file.txt" --dry-run 2>&1
    [ "$status" -ne 0 ]
    [[ "$output" == *"ERROR"* ]] || [[ "$output" == *"not found"* ]] || [[ "$output" == *"not readable"* ]]
}

@test "missing inscope file shows error" {
    run timeout 5 bash "$SCRIPTPATH/reconftw.sh" -d test.com -i "/nonexistent/inscope.txt" --dry-run 2>&1
    [ "$status" -ne 0 ]
    [[ "$output" == *"ERROR"* ]] || [[ "$output" == *"not found"* ]]
}

@test "invalid custom function shows error" {
    run timeout 5 bash "$SCRIPTPATH/reconftw.sh" -d test.com -c "nonexistent_function_xyz" 2>&1
    [ "$status" -ne 0 ]
    [[ "$output" == *"not defined"* ]] || [[ "$output" == *"Error"* ]]
}
