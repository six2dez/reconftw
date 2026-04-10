#!/usr/bin/env bats

setup() {
    TEST_DIR=$(mktemp -d)
    ORIG_PATH="$PATH"
    MOCK_BIN="$TEST_DIR/mockbin"
    UV_TOOL_DIR="$TEST_DIR/uv-tools"
    INTERLACE_BIN_DIR="$UV_TOOL_DIR/interlace/bin"
    COLORCLASS_DIR="$UV_TOOL_DIR/interlace/lib/python3.12/site-packages/colorclass"
    COLORCLASS_CODES="$COLORCLASS_DIR/codes.py"

    mkdir -p "$MOCK_BIN" "$INTERLACE_BIN_DIR" "$COLORCLASS_DIR"
    export PATH="$MOCK_BIN:$PATH"
    export UV_TOOL_DIR COLORCLASS_DIR COLORCLASS_CODES

    : >"$COLORCLASS_DIR/__init__.py"
    printf '%s\n' 'from collections import Mapping' >"$COLORCLASS_CODES"

    create_mock_uv

    local installfile="${BATS_TEST_DIRNAME}/../../install.sh"
    eval "$(sed -n '/^function interlace_tool_python()/,/^}/p' "$installfile")"
    eval "$(sed -n '/^function interlace_colorclass_codes_path()/,/^}/p' "$installfile")"
    eval "$(sed -n '/^function interlace_colorclass_imports_ok()/,/^}/p' "$installfile")"
    eval "$(sed -n '/^function ensure_interlace_colorclass_healthy()/,/^}/p' "$installfile")"
}

teardown() {
    PATH="$ORIG_PATH"
    rm -rf "$TEST_DIR"
}

create_mock_uv() {
    cat >"$MOCK_BIN/uv" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "tool" && "${2:-}" == "dir" ]]; then
    printf '%s\n' "$UV_TOOL_DIR"
    exit 0
fi

echo "unexpected uv call: $*" >&2
exit 1
EOF
    chmod +x "$MOCK_BIN/uv"

    cat >"$INTERLACE_BIN_DIR/python" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "-c" ]]; then
    echo "unexpected python invocation: $*" >&2
    exit 1
fi

code="${2:-}"
if [[ "$code" == *'find_spec("colorclass")'* ]]; then
    printf '%s\n' "$COLORCLASS_CODES"
    exit 0
fi

if [[ "$code" == 'import colorclass' ]]; then
    if grep -q 'from collections.abc import Mapping' "$COLORCLASS_CODES"; then
        exit 0
    fi
    echo "ImportError: cannot import name 'Mapping' from 'collections'" >&2
    exit 1
fi

echo "unexpected python code: $code" >&2
exit 1
EOF
    chmod +x "$INTERLACE_BIN_DIR/python"
}

@test "ensure_interlace_colorclass_healthy patches broken installed colorclass" {
    run ensure_interlace_colorclass_healthy

    [ "$status" -eq 0 ]
    grep -Fq 'from collections.abc import Mapping' "$COLORCLASS_CODES"
    ! grep -Fq 'from collections import Mapping' "$COLORCLASS_CODES"
    [ ! -e "${COLORCLASS_CODES}.bak" ]
}

@test "ensure_interlace_colorclass_healthy fails when installed tool python is missing" {
    rm -f "$INTERLACE_BIN_DIR/python"

    run ensure_interlace_colorclass_healthy

    [ "$status" -ne 0 ]
}
