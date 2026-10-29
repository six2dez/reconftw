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
    export domain="example.com"
    export AXIOM=false
    export DIFF=false
    export DOMAIN_INFO=true
    export OSINT=true

    export dir="${TEST_DIR}/target"
    export called_fn_dir="${dir}/.called_fn"
    export LOGFILE="${dir}/.tmp/test.log"
    export tools="${TEST_DIR}/tools"

    mkdir -p "${dir}/.tmp" "$called_fn_dir" "${tools}/msftrecon/venv/bin" \
        "${tools}/msftrecon/msftrecon" "${tools}/Scopify/venv/bin" "${tools}/Scopify"
    cd "$dir" || exit 1
    : >"$LOGFILE"

    # shellcheck source=/dev/null
    source "$project_root/reconftw.cfg" 2>/dev/null || true
    # reconftw.cfg prepends ~/go/bin, ~/.local/bin and ~/.cargo/bin: put the
    # mocks back in front so a dev box with real tools stays hermetic.
    export PATH="${MOCK_BIN}:$PATH"
    export SCRIPTPATH="$project_root"
    export tools="${TEST_DIR}/tools"
    # shellcheck source=/dev/null
    source "$project_root/reconftw.sh" --source-only

    create_mock_whois
    create_mock_unfurl
    create_mock_msftrecon_python
    create_mock_scopify_python
    touch "${tools}/msftrecon/msftrecon/msftrecon.py" "${tools}/Scopify/scopify.py"
}

teardown() {
    PATH="$ORIG_PATH"
    cd /
    rm -rf "$TEST_DIR"
}

create_mock_whois() {
    cat >"${MOCK_BIN}/whois" <<'EOF'
#!/usr/bin/env bash
echo "Domain Name: EXAMPLE.COM"
exit 0
EOF
    chmod +x "${MOCK_BIN}/whois"
}

create_mock_unfurl() {
    cat >"${MOCK_BIN}/unfurl" <<'EOF'
#!/usr/bin/env bash
echo "example"
exit 0
EOF
    chmod +x "${MOCK_BIN}/unfurl"
}

create_mock_msftrecon_python() {
    cat >"${tools}/msftrecon/venv/bin/python3" <<'EOF'
#!/usr/bin/env bash
echo "Traceback (most recent call last):" >&2
echo "msftrecon failure" >&2
exit 1
EOF
    chmod +x "${tools}/msftrecon/venv/bin/python3"
}

create_mock_scopify_python() {
    cat >"${tools}/Scopify/venv/bin/python3" <<'EOF'
#!/usr/bin/env bash
echo "scopify-result"
exit 0
EOF
    chmod +x "${tools}/Scopify/venv/bin/python3"
}

@test "domain_info handles msftrecon failure with fail-soft warning and empty artifact" {
    run domain_info

    [ "$status" -eq 0 ]
    [ -f "osint/azure_tenant_domains.txt" ]
    [ ! -s "osint/azure_tenant_domains.txt" ]
    [[ "$output" == *"msftrecon failed, continuing"* ]]
    [[ "$output" != *"Traceback (most recent call last):"* ]]
    grep -q "domain_info: msftrecon failed" "$LOGFILE"
}
