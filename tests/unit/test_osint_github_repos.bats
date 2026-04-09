#!/usr/bin/env bats

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

    TEST_DIR="$(mktemp -d)"
    MOCK_BIN="${TEST_DIR}/mockbin"
    ORIG_PATH="$PATH"
    mkdir -p "$MOCK_BIN"

    export PATH="${MOCK_BIN}:$ORIG_PATH"
    export SCRIPTPATH="$project_root"
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
    export NOTIFICATION=false
    export OUTPUT_VERBOSITY=1
    export domain="target.example.com"
    export AXIOM=false
    export DIFF=false
    export GITHUB_REPOS=true
    export OSINT=true
    export INTERLACE_THREADS=1

    export dir="${TEST_DIR}/target.example.com"
    export called_fn_dir="${dir}/.called_fn"
    export LOGFILE="${dir}/.tmp/test.log"
    export tools="${TEST_DIR}/tools"
    export GITHUB_TOKENS="${TEST_DIR}/github_tokens.txt"
    export INTERLACE_LOG="${TEST_DIR}/interlace_calls.log"

    mkdir -p "${dir}/.tmp" "$called_fn_dir" "${tools}/titus/dist"
    cd "$dir" || exit 1
    : >"$LOGFILE"
    : >"$INTERLACE_LOG"
    printf '%s\n' 'ghp_test_token' >"$GITHUB_TOKENS"

    # shellcheck source=/dev/null
    source "$project_root/reconftw.cfg" 2>/dev/null || true
    export SCRIPTPATH="$project_root"
    export tools="${TEST_DIR}/tools"
    export GITHUB_TOKENS="${TEST_DIR}/github_tokens.txt"
    export GITHUB_REPOS=true
    export OSINT=true
    export DIFF=false
    export INTERLACE_THREADS=1
    export OUTPUT_VERBOSITY=1
    export NOTIFICATION=false

    # shellcheck source=/dev/null
    source "$project_root/reconftw.sh" --source-only

    create_mock_unfurl
    create_mock_enumerepo
    create_mock_interlace
    create_mock_titus
}

teardown() {
    PATH="$ORIG_PATH"
    cd /
    rm -rf "$TEST_DIR"
}

create_mock_unfurl() {
    cat >"${MOCK_BIN}/unfurl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'acme'
EOF
    chmod +x "${MOCK_BIN}/unfurl"
}

create_mock_enumerepo() {
    cat >"${MOCK_BIN}/enumerepo" <<'EOF'
#!/usr/bin/env bash
outfile=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)
            outfile="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done
mkdir -p "$(dirname "$outfile")"
printf '%s\n' '[{"repos":[{"url":"https://github.com/acme/mockrepo"}]}]' >"$outfile"
EOF
    chmod +x "${MOCK_BIN}/enumerepo"
}

create_mock_interlace() {
    cat >"${MOCK_BIN}/interlace" <<'EOF'
#!/usr/bin/env bash
cmd=""
outdir=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c)
            cmd="$2"
            shift 2
            ;;
        -o)
            outdir="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

printf '%s\n' "$cmd" >>"${INTERLACE_LOG}"

if [[ "$cmd" == git\ clone* ]]; then
    mkdir -p ".tmp/github_repos/mockrepo"
elif [[ "$cmd" == *"scan --format json"* && "$cmd" == *"titus"* ]]; then
    mkdir -p ".tmp/github"
    printf '%s\n' '{"engine":"titus","repo":"mockrepo"}' >".tmp/github/titus__mockrepo.json"
elif [[ "$cmd" == trufflehog\ git* ]]; then
    mkdir -p "${outdir:-.tmp/github}"
    printf '%s\n' '{"engine":"trufflehog","repo":"mockrepo"}' >"${outdir:-.tmp/github}/trufflehog__mockrepo.json"
fi
EOF
    chmod +x "${MOCK_BIN}/interlace"
}

create_mock_titus() {
    cat >"${MOCK_BIN}/titus" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '{"engine":"titus","repo":"mockrepo"}'
EOF
    chmod +x "${MOCK_BIN}/titus"
    cp "${MOCK_BIN}/titus" "${tools}/titus/dist/titus"
    chmod +x "${tools}/titus/dist/titus"
}

@test "github_repos falls back to titus for unknown secrets engine" {
    export SECRETS_ENGINE="bogus"
    export SECRETS_SCAN_GIT_HISTORY=true
    export SECRETS_VALIDATE=false

    run github_repos

    [ "$status" -eq 0 ]
    [[ "$output" == *"Unknown SECRETS_ENGINE='bogus', using titus"* ]]
    [ -s "$INTERLACE_LOG" ]
    grep -q "scan --format json" "$INTERLACE_LOG"
    grep -q "titus" "$INTERLACE_LOG"
    grep -q "trufflehog git" "$INTERLACE_LOG"
    ! grep -q "noseyparker" "$INTERLACE_LOG"
    [ -s "osint/github_company_secrets.json" ]

    run jq -s 'map(.engine) | sort == ["titus","trufflehog"]' osint/github_company_secrets.json
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}

@test "github_repos uses titus without fallback warning when explicitly configured" {
    export SECRETS_ENGINE="titus"
    export SECRETS_SCAN_GIT_HISTORY=true
    export SECRETS_VALIDATE=false

    run github_repos

    [ "$status" -eq 0 ]
    [[ "$output" != *"Unknown SECRETS_ENGINE="* ]]
    [ -s "$INTERLACE_LOG" ]
    grep -q "scan --format json" "$INTERLACE_LOG"
    grep -q "titus" "$INTERLACE_LOG"
    grep -q "trufflehog git" "$INTERLACE_LOG"
    ! grep -q "noseyparker" "$INTERLACE_LOG"
    [ -s "osint/github_company_secrets.json" ]

    run jq -s 'map(.engine) | sort == ["titus","trufflehog"]' osint/github_company_secrets.json
    [ "$status" -eq 0 ]
    [ "$output" = "true" ]
}
