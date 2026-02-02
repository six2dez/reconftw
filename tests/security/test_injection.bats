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
@test "sanitize_domain blocks semicolon injection" {
    run sanitize_domain "example.com;whoami"
    [ "$status" -eq 0 ]
    [[ "$output" != *";"* ]]
}

@test "sanitize_domain blocks pipe injection" {
    run sanitize_domain "example.com|cat /etc/passwd"
    [ "$status" -ne 0 ]
}

@test "sanitize_domain blocks backtick injection" {
    run sanitize_domain 'example.com`id`'
    [ "$status" -ne 0 ]
}

@test "sanitize_domain blocks dollar substitution" {
    run sanitize_domain 'example.com$(whoami)'
    [ "$status" -ne 0 ]
}

@test "sanitize_domain blocks ampersand injection" {
    run sanitize_domain "example.com&rm -rf /"
    [ "$status" -ne 0 ]
}

@test "sanitize_domain blocks newline injection" {
    result=$(printf 'example.com\nwhoami' | xargs -I{} bash -c 'sanitize_domain "{}"' 2>&1) || true
    [[ "$result" != *$'\n'* ]] || [ -z "$result" ]
}

@test "sanitize_domain blocks redirect injection" {
    run sanitize_domain "example.com>/etc/passwd"
    [ "$status" -ne 0 ]
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
    ! grep -q '[;|&$`]' "$tmpfile"
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
