#!/usr/bin/env bats

# Security tests for command injection prevention

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

# Command injection via domain parameter
# sanitize_domain contract (modules/utils.sh): it STRIPS every character outside
# [a-z0-9.-] and returns 0; it fails only when nothing usable is left. Callers
# consume stdout via domain=$(sanitize_domain ...), so these tests assert on
# stdout alone (stderr carries an INFO notice that quotes the raw input): rc 0,
# the exact neutralised value, and nothing outside the whitelist.
@test "sanitize_domain blocks semicolon injection" {
    local out rc=0
    out=$(sanitize_domain "example.com;whoami" 2>/dev/null) || rc=$?
    [ "$rc" -eq 0 ]
    [ "$out" = "example.comwhoami" ]
    [[ "$out" =~ ^[a-z0-9.-]+$ ]]
}

@test "sanitize_domain blocks pipe injection" {
    local out rc=0
    out=$(sanitize_domain "example.com|cat /etc/passwd" 2>/dev/null) || rc=$?
    [ "$rc" -eq 0 ]
    [ "$out" = "example.comcat" ]
    [[ "$out" =~ ^[a-z0-9.-]+$ ]]
}

@test "sanitize_domain blocks backtick injection" {
    local out rc=0
    out=$(sanitize_domain 'example.com`id`' 2>/dev/null) || rc=$?
    [ "$rc" -eq 0 ]
    [ "$out" = "example.comid" ]
    [[ "$out" =~ ^[a-z0-9.-]+$ ]]
}

@test "sanitize_domain blocks dollar substitution" {
    local out rc=0
    out=$(sanitize_domain 'example.com$(touch "$BATS_TEST_TMPDIR/pwned")' 2>/dev/null) || rc=$?
    [ "$rc" -eq 0 ]
    # Everything from the first "/" on is cut as a URL path, the rest stripped.
    [ "$out" = "example.comtouchbatstesttmpdir" ]
    [[ "$out" =~ ^[a-z0-9.-]+$ ]]
    # The substitution must never be evaluated.
    [ ! -e "$BATS_TEST_TMPDIR/pwned" ]
}

@test "sanitize_domain blocks ampersand injection" {
    local out rc=0
    out=$(sanitize_domain "example.com&rm -rf /" 2>/dev/null) || rc=$?
    [ "$rc" -eq 0 ]
    [ "$out" = "example.comrm-rf" ]
    [[ "$out" =~ ^[a-z0-9.-]+$ ]]
}

@test "sanitize_domain blocks newline injection" {
    local out rc=0
    out=$(sanitize_domain $'example.com\nwhoami' 2>/dev/null) || rc=$?
    [ "$rc" -eq 0 ]
    [ "$out" = "example.comwhoami" ]
    [[ "$out" =~ ^[a-z0-9.-]+$ ]]
    # Exactly one line: no second command/target can be smuggled through.
    [ "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" -eq 1 ]
}

@test "sanitize_domain blocks redirect injection" {
    local out rc=0
    out=$(sanitize_domain "example.com>/etc/passwd" 2>/dev/null) || rc=$?
    [ "$rc" -eq 0 ]
    [ "$out" = "example.com" ]
    [[ "$out" =~ ^[a-z0-9.-]+$ ]]
}

# IP/CIDR injection tests
@test "sanitize_ip blocks semicolon injection" {
    run sanitize_ip "192.168.1.1;whoami"
    [ "$status" -eq 0 ]
    [[ "$output" != *";"* ]]
}

@test "sanitize_ip blocks command substitution" {
    run sanitize_ip '192.168.1.1$(id)'
    [ "$status" -eq 0 ]
    [[ "$output" != *"$"* ]]
}

@test "sanitize_ip allows valid CIDR" {
    result=$(sanitize_ip "192.168.1.0/24")
    [ "$result" = "192.168.1.0/24" ]
}

# Interlace input sanitization
@test "sanitize_interlace_input removes dangerous chars" {
    local tmpfile
    tmpfile=$(mktemp)
    echo 'safe.domain.com' > "$tmpfile"
    echo 'evil;rm -rf /' >> "$tmpfile"
    echo '$(whoami).attacker.com' >> "$tmpfile"
    
    sanitize_interlace_input "$tmpfile"
    
    # Check no dangerous chars remain
    ! grep -q '[;|&$`]' "$tmpfile" || false
    rm -f "$tmpfile"
}

# Path traversal tests
@test "outscope file handles path traversal attempt" {
    local tmpfile scopefile
    tmpfile=$(mktemp)
    scopefile=$(mktemp)
    
    echo "safe.example.com" > "$tmpfile"
    echo "../../../etc/passwd" >> "$tmpfile"
    echo "*.outscoped.com" > "$scopefile"
    
    # Should not crash
    deleteOutScoped "$scopefile" "$tmpfile"
    
    rm -f "$tmpfile" "$scopefile"
}

# deleteOutScoped anchoring: an out-of-scope entry must match the WHOLE host,
# never a substring, while still handling URL lists (scheme/port/path).
@test "deleteOutScoped anchors non-wildcard entries to the whole hostname" {
    local tmpfile scopefile
    tmpfile=$(mktemp)
    scopefile=$(mktemp)
    echo "dev.example.com" > "$scopefile"
    printf '%s\n' \
        "dev.example.com" \
        "xdev.example.com" \
        "dev.example.com.cdn.net" \
        "api.dev.example.com" \
        "DEV.EXAMPLE.COM" \
        "inscope.example.com" > "$tmpfile"
    deleteOutScoped "$scopefile" "$tmpfile"
    run cat "$tmpfile"
    [[ "$output" != *$'\n'"dev.example.com"* ]] && [[ "$output" != "dev.example.com"* ]]
    grep -qx 'xdev.example.com' "$tmpfile"
    grep -qx 'dev.example.com.cdn.net' "$tmpfile"
    grep -qx 'api.dev.example.com' "$tmpfile"
    grep -qx 'inscope.example.com' "$tmpfile"
    ! grep -qix 'dev.example.com' "$tmpfile" || false
    [ "$(wc -l < "$tmpfile" | tr -d ' ')" -eq 4 ]
    rm -f "$tmpfile" "$scopefile"
}

@test "deleteOutScoped matches URL lists by host (scheme, port and path tolerated)" {
    local tmpfile scopefile
    tmpfile=$(mktemp)
    scopefile=$(mktemp)
    echo "dev.example.com" > "$scopefile"
    printf '%s\n' \
        "https://dev.example.com" \
        "http://dev.example.com:8080/admin?x=1" \
        "https://xdev.example.com/" \
        "https://dev.example.com.cdn.net:443/" \
        "https://ok.example.com:8443/dev.example.com" > "$tmpfile"
    deleteOutScoped "$scopefile" "$tmpfile"
    [ "$(wc -l < "$tmpfile" | tr -d ' ')" -eq 3 ]
    grep -qx 'https://xdev.example.com/' "$tmpfile"
    grep -qx 'https://dev.example.com.cdn.net:443/' "$tmpfile"
    grep -qx 'https://ok.example.com:8443/dev.example.com' "$tmpfile"
    rm -f "$tmpfile" "$scopefile"
}

@test "deleteOutScoped wildcard entries keep suffix semantics but stay host-anchored" {
    local tmpfile scopefile
    tmpfile=$(mktemp)
    scopefile=$(mktemp)
    echo "*.example.com" > "$scopefile"
    printf '%s\n' \
        "a.example.com" \
        "https://b.example.com:443/x" \
        "example.com" \
        "notexample.com" \
        "a.example.com.evil.net" > "$tmpfile"
    deleteOutScoped "$scopefile" "$tmpfile"
    [ "$(wc -l < "$tmpfile" | tr -d ' ')" -eq 3 ]
    grep -qx 'example.com' "$tmpfile"
    grep -qx 'notexample.com' "$tmpfile"
    grep -qx 'a.example.com.evil.net' "$tmpfile"
    rm -f "$tmpfile" "$scopefile"
}

@test "deleteOutScoped returns 0 and empties the file when every line is out of scope" {
    local tmpfile scopefile
    tmpfile=$(mktemp)
    scopefile=$(mktemp)
    printf '%s\n' "a.example.com" "b.example.com" > "$scopefile"
    printf '%s\n' "a.example.com" "https://b.example.com" > "$tmpfile"
    run deleteOutScoped "$scopefile" "$tmpfile"
    [ "$status" -eq 0 ]
    [ ! -s "$tmpfile" ]
    rm -f "$tmpfile" "$scopefile"
}
