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

    # shellcheck source=/dev/null
    source "$project_root/reconftw.cfg" 2>/dev/null || true
    # shellcheck source=/dev/null
    source "$project_root/reconftw.sh" --source-only

    export domain="example.com"
    export dir="${TEST_DIR}/target"
    export called_fn_dir="${dir}/.called_fn"
    export LOGFILE="${dir}/.tmp/test.log"
    export outOfScope_file="${dir}/outscope.txt"
    export AXIOM=false
    export DIFF=false
    export DEEP=false
    export INSCOPE=false
    export RESOLVER_IQ=false
    export SUBBRUTE=true
    export SUBIAPERMUTE=true
    export subs_wordlist="${dir}/wordlist.txt"
    export subs_wordlist_big="${dir}/wordlist_big.txt"
    export SUBWIZ_CALLED_FILE="${dir}/.tmp/subwiz.called"

    mkdir -p "${dir}/.tmp" "${dir}/subdomains" "${dir}/webs" "$called_fn_dir"
    cd "$dir" || exit 1
    : >"$LOGFILE"
    : >"$outOfScope_file"
    printf "www\napi\n" >"$subs_wordlist"
    cp "$subs_wordlist" "$subs_wordlist_big"

    DOMAIN_ESCAPED=$(escape_domain_regex "$domain")
    DOMAIN_MATCH_REGEX=$(domain_match_regex "$domain")
    export DOMAIN_ESCAPED DOMAIN_MATCH_REGEX

    create_mock_anew
    create_mock_dnsx
    create_mock_subwiz

    _resolve_domains() {
        cat "$1" >"$2"
    }

    _bruteforce_domains() {
        local _wordlist="$1"
        local _domain="$2"
        local _output="$3"
        : >"$_output"
        printf "dev.%s\n%s\nexample.org\n" "$_domain" "$_domain" >"$_output"
        return 0
    }
}

teardown() {
    PATH="$ORIG_PATH"
    cd /
    rm -rf "$TEST_DIR"
}

create_mock_anew() {
    cat >"${MOCK_BIN}/anew" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
quiet=false
if [[ "${1:-}" == "-q" ]]; then
    quiet=true
    shift
fi
target="${1:-}"
touch "$target"
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if ! grep -Fxq "$line" "$target"; then
        echo "$line" >>"$target"
        if [[ "$quiet" != true ]]; then
            echo "$line"
        fi
    fi
done
exit 0
EOF
    chmod +x "${MOCK_BIN}/anew"
}

create_mock_dnsx() {
    cat >"${MOCK_BIN}/dnsx" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod +x "${MOCK_BIN}/dnsx"
}

create_mock_subwiz() {
    cat >"${MOCK_BIN}/subwiz" <<'EOF'
#!/usr/bin/env bash
touch "${SUBWIZ_CALLED_FILE:-/tmp/subwiz.called}"
exit 0
EOF
    chmod +x "${MOCK_BIN}/subwiz"
}

@test "sub_active filters exact domain and subdomains with robust matcher" {
    cat > .tmp/source_subs.txt <<'EOF'
api.example.com
example.com
badexample.com
foo.example.net
EOF

    run sub_active

    [ "$status" -eq 0 ]
    [ -f "subdomains/subdomains.txt" ]
    grep -qx "api.example.com" "subdomains/subdomains.txt"
    grep -qx "example.com" "subdomains/subdomains.txt"
    ! grep -qx "badexample.com" "subdomains/subdomains.txt" || false
    ! grep -qx "foo.example.net" "subdomains/subdomains.txt" || false
    [ "$(wc -l < "subdomains/subdomains.txt" | tr -d ' ')" -eq 2 ]
}

@test "sub_brute appends only in-scope brute-force matches" {
    run sub_brute

    [ "$status" -eq 0 ]
    [ -f "subdomains/subdomains.txt" ]
    grep -qx "dev.example.com" "subdomains/subdomains.txt"
    grep -qx "example.com" "subdomains/subdomains.txt"
    ! grep -qx "example.org" "subdomains/subdomains.txt" || false
    [ "$(wc -l < "subdomains/subdomains.txt" | tr -d ' ')" -eq 2 ]
}

@test "sub_ia_permut skips cleanly when seed subdomains are empty" {
    : > "subdomains/subdomains.txt"
    rm -f "$SUBWIZ_CALLED_FILE"

    run sub_ia_permut

    [ "$status" -eq 0 ]
    [ ! -f "$SUBWIZ_CALLED_FILE" ]
    grep -q "no_seed_subdomains" "$LOGFILE"
}
