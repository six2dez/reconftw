#!/usr/bin/env bats

# reconftw.sh sets IFS=$'\n\t' process-wide, so a space-separated flag string
# expanded unquoted ($GOTATOR_FLAGS) reaches the tool as ONE argument.
# The *_FLAGS / *_EXTRA_ARGS settings are therefore bash arrays, and
# lib/common.sh:_as_array converts legacy scalar strings for compatibility.

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export SCRIPTPATH="$project_root"
    export LOGFILE=/dev/null
    IFS=$'\n\t'
    source "$project_root/reconftw.cfg" 2>/dev/null || true
    export SCRIPTPATH="$project_root"
    source "$project_root/lib/validation.sh"
    source "$project_root/lib/common.sh"
}

@test "unquoted scalar expansion under IFS=newline/tab yields ONE word (the defect being guarded)" {
    local legacy=" -depth 1 -numbers 3 -mindup -adv -md"
    # shellcheck disable=SC2086
    set -- $legacy
    [ "$#" -eq 1 ]
}

@test "reconftw.cfg: GOTATOR_FLAGS is a 7-element array whose SECOND element is 1" {
    [[ "$(declare -p GOTATOR_FLAGS)" == "declare -a"* ]]
    [ "${#GOTATOR_FLAGS[@]}" -eq 7 ]
    [ "${GOTATOR_FLAGS[1]}" = "1" ]
    [ "${GOTATOR_FLAGS[0]}" = "-depth" ]
    [ "${GOTATOR_FLAGS[6]}" = "-md" ]
    set -- "${GOTATOR_FLAGS[@]}"
    [ "$#" -eq 7 ]
}

@test "reconftw.cfg: NUCLEI_EXTRA_ARGS, NUCLEI_DAST_EXTRA_ARGS and AXIOM_EXTRA_ARGS are empty arrays" {
    local v
    for v in NUCLEI_EXTRA_ARGS NUCLEI_DAST_EXTRA_ARGS AXIOM_EXTRA_ARGS; do
        [[ "$(declare -p "$v")" == "declare -a"* ]]
        local -n ref="$v"
        [ "${#ref[@]}" -eq 0 ]
        unset -n ref
    done
}

@test "_as_array splits a legacy scalar on spaces despite IFS=newline/tab" {
    unset GOTATOR_FLAGS
    GOTATOR_FLAGS=" -depth 1 -numbers 3 -mindup -adv -md"
    _as_array GOTATOR_FLAGS
    [[ "$(declare -p GOTATOR_FLAGS)" == "declare -a"* ]]
    [ "${#GOTATOR_FLAGS[@]}" -eq 7 ]
    [ "${GOTATOR_FLAGS[1]}" = "1" ]
}

@test "_as_array splits an exported legacy scalar (export cannot hold arrays)" {
    unset NUCLEI_EXTRA_ARGS
    export NUCLEI_EXTRA_ARGS="-etags openssh,ssl -eid foo"
    _as_array NUCLEI_EXTRA_ARGS
    [ "${#NUCLEI_EXTRA_ARGS[@]}" -eq 4 ]
    [ "${NUCLEI_EXTRA_ARGS[1]}" = "openssh,ssl" ]
}

@test "_as_array splits a string assigned over an existing array (custom config after reconftw.cfg)" {
    # GOTATOR_FLAGS is already an array from reconftw.cfg; a legacy custom
    # config does a plain string assignment, which only replaces element 0
    # and leaves the 6 stale default elements behind it.
    GOTATOR_FLAGS=" -depth 2 -numbers 5"
    [ "${#GOTATOR_FLAGS[@]}" -eq 7 ]
    _as_array GOTATOR_FLAGS
    [ "${#GOTATOR_FLAGS[@]}" -eq 4 ]
    [ "${GOTATOR_FLAGS[1]}" = "2" ]
    [ "${GOTATOR_FLAGS[3]}" = "5" ]
}

@test "_as_array is a no-op for a proper array and preserves elements with spaces" {
    NUCLEI_EXTRA_ARGS=(-H "User-Agent: x y")
    _as_array NUCLEI_EXTRA_ARGS
    [ "${#NUCLEI_EXTRA_ARGS[@]}" -eq 2 ]
    [ "${NUCLEI_EXTRA_ARGS[1]}" = "User-Agent: x y" ]
}

@test "_as_array turns unset and empty scalars into empty arrays" {
    unset AXIOM_EXTRA_ARGS
    _as_array AXIOM_EXTRA_ARGS
    [[ "$(declare -p AXIOM_EXTRA_ARGS)" == "declare -a"* ]]
    [ "${#AXIOM_EXTRA_ARGS[@]}" -eq 0 ]
    unset NUCLEI_DAST_EXTRA_ARGS
    NUCLEI_DAST_EXTRA_ARGS=""
    _as_array NUCLEI_DAST_EXTRA_ARGS
    [ "${#NUCLEI_DAST_EXTRA_ARGS[@]}" -eq 0 ]
}

@test "_normalize_flag_arrays converts every flag variable at once" {
    unset GOTATOR_FLAGS NUCLEI_EXTRA_ARGS NUCLEI_DAST_EXTRA_ARGS AXIOM_EXTRA_ARGS
    GOTATOR_FLAGS="-depth 1"
    NUCLEI_EXTRA_ARGS="-etags openssh"
    NUCLEI_DAST_EXTRA_ARGS=""
    AXIOM_EXTRA_ARGS="--rm-logs"
    _normalize_flag_arrays
    [ "${#GOTATOR_FLAGS[@]}" -eq 2 ]
    [ "${#NUCLEI_EXTRA_ARGS[@]}" -eq 2 ]
    [ "${#NUCLEI_DAST_EXTRA_ARGS[@]}" -eq 0 ]
    [ "${#AXIOM_EXTRA_ARGS[@]}" -eq 1 ]
    [ "${AXIOM_EXTRA_ARGS[0]}" = "--rm-logs" ]
}
