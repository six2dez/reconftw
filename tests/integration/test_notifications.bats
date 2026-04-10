#!/usr/bin/env bats

setup() {
    SCRIPTPATH="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export SCRIPTPATH
    TEST_DIR="$BATS_TEST_TMPDIR/reconftw_notifications"
    MOCK_BIN="$TEST_DIR/mockbin"
    mkdir -p "$TEST_DIR" "$MOCK_BIN"

    cat >"$MOCK_BIN/notify" <<'EOF'
#!/usr/bin/env bash
cat >>"${NOTIFY_LOG}"
EOF
    chmod +x "$MOCK_BIN/notify"
}

teardown() {
    [[ -n "${TARGET_DOMAIN:-}" ]] && rm -rf "$SCRIPTPATH/Recon/$TARGET_DOMAIN"
    [[ -d "${TEST_DIR:-}" ]] && rm -rf "$TEST_DIR"
}

@test "NOTIFICATION=true sends function notifications through notify" {
    TARGET_DOMAIN="notify-${RANDOM}.example.com"
    local cfg="$TEST_DIR/notification.cfg"
    local notify_log="$TEST_DIR/notification.log"

    cat >"$cfg" <<'EOF'
NOTIFICATION=true
SOFT_NOTIFICATION=false
OUTPUT_VERBOSITY=2
EOF

    run env PATH="$MOCK_BIN:$PATH" NOTIFY_LOG="$notify_log" SKIP_CRITICAL_CHECK=true timeout 60 \
        bash "$SCRIPTPATH/reconftw.sh" -d "$TARGET_DOMAIN" -s --dry-run --no-report --no-banner -f "$cfg" 2>&1

    [ "$status" -eq 0 ]
    [ -s "$notify_log" ]
    grep -Fq "$TARGET_DOMAIN" "$notify_log"
}

@test "SOFT_NOTIFICATION=true still sends final notification" {
    TARGET_DOMAIN="softnotify-${RANDOM}.example.com"
    local cfg="$TEST_DIR/soft-notification.cfg"
    local notify_log="$TEST_DIR/soft-notification.log"

    cat >"$cfg" <<'EOF'
NOTIFICATION=false
SOFT_NOTIFICATION=true
OUTPUT_VERBOSITY=1
EOF

    run env PATH="$MOCK_BIN:$PATH" NOTIFY_LOG="$notify_log" SKIP_CRITICAL_CHECK=true timeout 60 \
        bash "$SCRIPTPATH/reconftw.sh" -d "$TARGET_DOMAIN" -s --dry-run --no-report --no-banner -f "$cfg" 2>&1

    [ "$status" -eq 0 ]
    [ -s "$notify_log" ]
    grep -Fq "Finished Recon on: $TARGET_DOMAIN" "$notify_log"
}
