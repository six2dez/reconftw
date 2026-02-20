#!/usr/bin/env bats

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

    TEST_DIR="$(mktemp -d)"
    MOCK_BIN="${TEST_DIR}/mockbin"
    ORIG_PATH="$PATH"

    mkdir -p "$MOCK_BIN"
    cd "$TEST_DIR" || exit 1

    export tools="${tools:-$HOME/Tools}"
    export LOGFILE="${TEST_DIR}/test.log"
    export called_fn_dir="${TEST_DIR}/.called_fn"
    export SCRIPTPATH="$project_root"
    export AXIOM=false
    export NOTIFICATION=false
    export DIFF=false
    export ASN_ENUM=true
    export domain="example.com"
    export DOMAIN_ESCAPED="example\\.com"
    export PDCP_API_KEY=""
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''

    touch "$LOGFILE"
    mkdir -p "$called_fn_dir"

    # shellcheck source=/dev/null
    source "$project_root/reconftw.cfg" 2>/dev/null || true
    # shellcheck source=/dev/null
    source "$project_root/reconftw.sh" --source-only

    PATH="${MOCK_BIN}:$ORIG_PATH"
    export PATH

    create_mock_anew
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
mkdir -p "$(dirname "$target")"
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
EOF
    chmod +x "${MOCK_BIN}/anew"
}

create_mock_asnmap() {
    cat >"${MOCK_BIN}/asnmap" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
calls_file="${ASNMAP_MOCK_CALLS:-/tmp/asnmap_calls}"
echo "KEY=${PDCP_API_KEY:-}" >>"$calls_file"
scenario="${ASNMAP_MOCK_SCENARIO:-success}"

case "$scenario" in
    success)
        cat <<'JSON'
{"cidr":"1.1.1.0/24","as_number":"AS13335","domains":["api.example.com"]}
JSON
        ;;
    timeout)
        exit 124
        ;;
    fail)
        exit 2
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "${MOCK_BIN}/asnmap"
}

@test "sub_asn skips ASN enumeration when PDCP_API_KEY is unset and logs it" {
    create_mock_asnmap
    export ASNMAP_MOCK_CALLS="${TEST_DIR}/asnmap_calls.log"
    export PDCP_API_KEY=""

    run sub_asn

    [ "$status" -eq 0 ]
    [[ "$output" == *"PDCP_API_KEY is not set"* ]]
    grep -q "PDCP_API_KEY is not set" "$LOGFILE"
    [ ! -s "$ASNMAP_MOCK_CALLS" ]
}

@test "sub_asn runs asnmap with PDCP_API_KEY and writes ASN outputs" {
    create_mock_asnmap
    export ASNMAP_MOCK_CALLS="${TEST_DIR}/asnmap_calls.log"
    export ASNMAP_MOCK_SCENARIO="success"
    export PDCP_API_KEY="pdcp_test_key"

    run sub_asn

    [ "$status" -eq 0 ]
    [ -s "hosts/asn_cidrs.txt" ]
    [ -s "hosts/asn_numbers.txt" ]
    grep -q "1.1.1.0/24" "hosts/asn_cidrs.txt"
    grep -q "AS13335" "hosts/asn_numbers.txt"
    grep -q "KEY=pdcp_test_key" "$ASNMAP_MOCK_CALLS"
}

@test "sub_asn handles asnmap timeout and logs warning" {
    create_mock_asnmap
    export ASNMAP_MOCK_CALLS="${TEST_DIR}/asnmap_calls.log"
    export ASNMAP_MOCK_SCENARIO="timeout"
    export PDCP_API_KEY="pdcp_test_key"

    run sub_asn

    [ "$status" -eq 0 ]
    [[ "$output" == *"timed out after 120s"* ]]
    grep -q "timed out after 120s" "$LOGFILE"
    [ ! -s "hosts/asn_cidrs.txt" ]
    [ ! -s "hosts/asn_numbers.txt" ]
}

@test "sub_asn continues silently when asnmap returns exit 0 with no ASN data" {
    create_mock_asnmap
    export ASNMAP_MOCK_CALLS="${TEST_DIR}/asnmap_calls.log"
    export ASNMAP_MOCK_SCENARIO="empty"
    export PDCP_API_KEY="pdcp_test_key"

    run sub_asn

    [ "$status" -eq 0 ]
    [[ "$output" != *"no ASN data"* ]]
    ! grep -q "no ASN data" "$LOGFILE"
    [ ! -s "hosts/asn_cidrs.txt" ]
    [ ! -s "hosts/asn_numbers.txt" ]
}

@test "sub_asn skips when asnmap is not installed and logs it" {
    PATH="/usr/bin:/bin:${MOCK_BIN}"
    export PATH
    export PDCP_API_KEY="pdcp_test_key"
    rm -f "${MOCK_BIN}/asnmap"

    run sub_asn

    [ "$status" -eq 0 ]
    [[ "$output" == *"asnmap not installed"* ]]
    grep -q "asnmap not installed" "$LOGFILE"
}
