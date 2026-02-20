#!/usr/bin/env bats

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export tools="$HOME/Tools"
    export LOGFILE="/dev/null"
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
    export NOTIFICATION=false
    export AXIOM=false

    source "$project_root/reconftw.cfg" 2>/dev/null || true
    export SCRIPTPATH="$project_root"
    source "$project_root/reconftw.sh" --source-only
}

@test "_select_permutations_wordlist returns full list when mode=full" {
    export PERMUTATIONS_WORDLIST_MODE="full"
    export PERMUTATIONS_SHORT_THRESHOLD=100
    export DEEP=false
    tmpfile=$(mktemp)
    printf "a.example.com\n" >"$tmpfile"

    result=$(_select_permutations_wordlist "$tmpfile")
    [ "$result" = "${WORDLISTS_DIR}/permutations_list.txt" ]

    rm -f "$tmpfile"
}

@test "_select_permutations_wordlist returns short list when mode=short" {
    export PERMUTATIONS_WORDLIST_MODE="short"
    export PERMUTATIONS_SHORT_THRESHOLD=100
    export DEEP=false
    tmpfile=$(mktemp)
    printf "a.example.com\n" >"$tmpfile"

    result=$(_select_permutations_wordlist "$tmpfile")
    [ "$result" = "${WORDLISTS_DIR}/permutations_list_short.txt" ]

    rm -f "$tmpfile"
}

@test "_select_permutations_wordlist auto uses full list in DEEP mode" {
    export PERMUTATIONS_WORDLIST_MODE="auto"
    export PERMUTATIONS_SHORT_THRESHOLD=100
    export DEEP=true
    tmpfile=$(mktemp)
    for i in $(seq 1 200); do echo "a${i}.example.com"; done >"$tmpfile"

    result=$(_select_permutations_wordlist "$tmpfile")
    [ "$result" = "${WORDLISTS_DIR}/permutations_list.txt" ]

    rm -f "$tmpfile"
}

@test "_select_permutations_wordlist auto uses threshold (<= threshold => full, > threshold => short)" {
    export PERMUTATIONS_WORDLIST_MODE="auto"
    export PERMUTATIONS_SHORT_THRESHOLD=100
    export DEEP=false

    small=$(mktemp)
    for i in $(seq 1 50); do echo "a${i}.example.com"; done >"$small"
    result=$(_select_permutations_wordlist "$small")
    [ "$result" = "${WORDLISTS_DIR}/permutations_list.txt" ]
    rm -f "$small"

    large=$(mktemp)
    for i in $(seq 1 150); do echo "a${i}.example.com"; done >"$large"
    result=$(_select_permutations_wordlist "$large")
    [ "$result" = "${WORDLISTS_DIR}/permutations_list_short.txt" ]
    rm -f "$large"
}

