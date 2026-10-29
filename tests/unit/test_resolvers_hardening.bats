#!/usr/bin/env bats

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

    TEST_DIR="$(mktemp -d)"
    export TEST_DIR
    MOCK_BIN="${TEST_DIR}/mockbin"
    ORIG_PATH="$PATH"
    mkdir -p "$MOCK_BIN"

    export PATH="${MOCK_BIN}:$ORIG_PATH"
    export SCRIPTPATH="$project_root"
    export LOGFILE="${TEST_DIR}/test.log"
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
    export NOTIFICATION=false
    export OUTPUT_VERBOSITY=1
    export AXIOM=false
    export generate_resolvers=false
    export update_resolvers=true
    export DNS_RESOLVER_SELECTED=""
    export CACHE_DIR="${TEST_DIR}/cache"
    export tools="${TEST_DIR}/tools"
    export resolvers="${TEST_DIR}/resolvers.txt"
    export resolvers_trusted="${TEST_DIR}/resolvers_trusted.txt"
    export DNS_HEARTBEAT_INTERVAL_SECONDS=20
    export DNS_BRUTE_TIMEOUT=0
    export DNS_RESOLVE_TIMEOUT=0
    export TIMEOUT_CMD="timeout"

    mkdir -p "$tools"
    : >"$LOGFILE"

    # shellcheck source=/dev/null
    source "$project_root/reconftw.cfg" 2>/dev/null || true
    # shellcheck source=/dev/null
    source "$project_root/reconftw.sh" --source-only

    # reconftw.cfg overwrites the paths above with the operator's real ones
    # (~/Tools, the repo .cache). Re-pin them so no test reads or writes the
    # real resolver files or the real download cache.
    export CACHE_DIR="${TEST_DIR}/cache"
    export tools="${TEST_DIR}/tools"
    export resolvers="${TEST_DIR}/resolvers.txt"
    export resolvers_trusted="${TEST_DIR}/resolvers_trusted.txt"
    # reconftw.cfg also prepends ~/go/bin, ~/.local/bin and ~/.cargo/bin to PATH,
    # which put a real puredns ahead of the mock on any provisioned box.
    export PATH="${MOCK_BIN}:$PATH"
}

teardown() {
    PATH="$ORIG_PATH"
    cd /
    rm -rf "$TEST_DIR"
}

@test "resolvers_update refreshes when resolvers_trusted is missing" {
    printf '1.1.1.1\n' >"$resolvers"
    rm -f "$resolvers_trusted"

    cached_download_typed() {
        printf '%s -> %s\n' "$1" "$2" >>"${TEST_DIR}/download_calls.log"
        printf '1.1.1.1\n' >"$2"
        return 0
    }

    run resolvers_update

    [ "$status" -eq 0 ]
    [ -s "$resolvers_trusted" ]
    grep -Fq "$resolvers_trusted_url" "${TEST_DIR}/download_calls.log"
}

@test "resolvers_update fails fast when resolver download fails" {
    rm -f "$resolvers" "$resolvers_trusted"

    cached_download_typed() {
        return 1
    }

    run resolvers_update

    [ "$status" -ne 0 ]
    [[ "$output" != *"Resolvers updated"* ]]
}

@test "cached_download_typed uses strict curl flags for resolvers cache type" {
    cat >"${MOCK_BIN}/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" > "${TEST_DIR}/curl_args.log"
output_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)
            output_file="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done
printf '8.8.8.8\n' > "$output_file"
EOF
    chmod +x "${MOCK_BIN}/curl"

    run cached_download_typed "https://example.com/resolvers.txt" "${TEST_DIR}/out_resolvers.txt" "resolvers.txt" "resolvers"

    [ "$status" -eq 0 ]
    [ -s "${TEST_DIR}/out_resolvers.txt" ]
    grep -q -- "--connect-timeout 10" "${TEST_DIR}/curl_args.log"
    grep -q -- "--max-time 120" "${TEST_DIR}/curl_args.log"
    grep -q -- "--retry 2" "${TEST_DIR}/curl_args.log"
    grep -q -- "--retry-delay 2" "${TEST_DIR}/curl_args.log"
    grep -q -- "--retry-connrefused" "${TEST_DIR}/curl_args.log"
}

@test "cached_download_typed in dry-run neither downloads nor copies a missing file" {
    cat >"${MOCK_BIN}/curl" <<'EOF'
#!/usr/bin/env bash
touch "${TEST_DIR}/curl_was_called"
EOF
    chmod +x "${MOCK_BIN}/curl"
    DRY_RUN=true
    OUTPUT_VERBOSITY=0

    run cached_download_typed "https://example.com/resolvers.txt" "${TEST_DIR}/missing_dir/resolvers.txt" "resolvers.txt" "resolvers"

    # Explicit failures: a bare [[ ]] in the middle of a bats test does not fail it.
    if [ "$status" -ne 0 ]; then echo "status=$status"; return 1; fi
    if [ -e "${TEST_DIR}/curl_was_called" ]; then echo "curl ran in dry-run"; return 1; fi
    if [[ "$output" == *"cp:"* ]]; then echo "cp error leaked: $output"; return 1; fi
    if [ -e "${CACHE_DIR}/resolvers/resolvers.txt" ]; then echo "dry-run wrote the cache"; return 1; fi
}

@test "_bruteforce_domains fails fast when required resolver files are missing" {
    export DNS_RESOLVER="puredns"
    rm -f "$resolvers" "$resolvers_trusted"
    printf 'www\napi\n' > "${TEST_DIR}/words.txt"

    cat >"${MOCK_BIN}/puredns" <<'EOF'
#!/usr/bin/env bash
touch "${TEST_DIR}/puredns_called"
exit 0
EOF
    chmod +x "${MOCK_BIN}/puredns"

    run _bruteforce_domains "${TEST_DIR}/words.txt" "example.com" "${TEST_DIR}/brute_out.txt"

    [ "$status" -ne 0 ]
    [ ! -f "${TEST_DIR}/puredns_called" ]
}

@test "_resolve_domains fails fast for dnsx when trusted resolvers file is missing" {
    export DNS_RESOLVER="dnsx"
    printf '1.1.1.1\n' > "$resolvers"
    rm -f "$resolvers_trusted"
    printf 'example.com\n' > "${TEST_DIR}/resolve_in.txt"

    cat >"${MOCK_BIN}/dnsx" <<'EOF'
#!/usr/bin/env bash
touch "${TEST_DIR}/dnsx_called"
exit 0
EOF
    chmod +x "${MOCK_BIN}/dnsx"

    run _resolve_domains "${TEST_DIR}/resolve_in.txt" "${TEST_DIR}/resolve_out.txt"

    [ "$status" -ne 0 ]
    [ ! -f "${TEST_DIR}/dnsx_called" ]
}

@test "_bruteforce_domains uses heartbeat path and skips timeout wrapper when DNS_BRUTE_TIMEOUT=0" {
    export DNS_RESOLVER="puredns"
    export DNS_BRUTE_TIMEOUT=0
    export DNS_HEARTBEAT_INTERVAL_SECONDS=17
    printf '1.1.1.1\n' > "$resolvers"
    printf '1.1.1.1\n' > "$resolvers_trusted"
    printf 'www\n' > "${TEST_DIR}/words.txt"

    run_with_heartbeat() {
        local label="$1"
        shift
        printf '%s\n' "$label" > "${TEST_DIR}/heartbeat_label.log"
        if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
            printf '%s\n' "$1" > "${TEST_DIR}/heartbeat_interval.log"
            shift
        fi
        "$@"
    }

    cat >"${MOCK_BIN}/timeout" <<'EOF'
#!/usr/bin/env bash
touch "${TEST_DIR}/timeout_called"
exit 0
EOF
    chmod +x "${MOCK_BIN}/timeout"

    cat >"${MOCK_BIN}/puredns" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -w)
            output_file="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done
printf 'dev.example.com\n' > "$output_file"
EOF
    chmod +x "${MOCK_BIN}/puredns"

    run _bruteforce_domains "${TEST_DIR}/words.txt" "example.com" "${TEST_DIR}/brute_out.txt"

    [ "$status" -eq 0 ]
    [ -f "${TEST_DIR}/heartbeat_label.log" ]
    [ -f "${TEST_DIR}/heartbeat_interval.log" ]
    [ "$(cat "${TEST_DIR}/heartbeat_interval.log")" = "17" ]
    [ ! -f "${TEST_DIR}/timeout_called" ]
}
