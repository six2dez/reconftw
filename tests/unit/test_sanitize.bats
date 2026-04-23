#!/usr/bin/env bats

# Unit tests for reconFTW sanitization functions

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export tools="$HOME/Tools"
    export LOGFILE="/dev/null"
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
    export NOTIFICATION=false
    export AXIOM=false
    source "$project_root/reconftw.cfg" 2>/dev/null || true
    # Restore SCRIPTPATH after cfg overrides it with $0
    export SCRIPTPATH="$project_root"
    source "$project_root/reconftw.sh" --source-only
}

@test "sanitize_domain accepts valid domain" {
    result=$(sanitize_domain "example.com")
    [ "$result" = "example.com" ]
}

@test "sanitize_domain accepts subdomain" {
    result=$(sanitize_domain "sub.example.com")
    [ "$result" = "sub.example.com" ]
}

@test "sanitize_domain converts to lowercase" {
    result=$(sanitize_domain "EXAMPLE.COM")
    [ "$result" = "example.com" ]
}

@test "sanitize_domain handles mixed case" {
    result=$(sanitize_domain "Sub.ExAmPlE.CoM")
    [ "$result" = "sub.example.com" ]
}

@test "sanitize_domain rejects command injection attempt" {
    run sanitize_domain '; rm -rf /'
    [ "$status" -ne 0 ]
}

@test "sanitize_domain rejects pipe injection" {
    run sanitize_domain 'example.com | cat /etc/passwd'
    [ "$status" -ne 0 ]
}

@test "sanitize_domain rejects backtick injection" {
    run sanitize_domain 'example.com`whoami`'
    [ "$status" -ne 0 ]
}

@test "sanitize_domain handles empty input" {
    run sanitize_domain ""
    [ "$status" -ne 0 ]
}

@test "sanitize_domain handles only dots" {
    run sanitize_domain "..."
    [ "$status" -ne 0 ]
}

@test "sanitize_domain strips leading/trailing dots" {
    result=$(sanitize_domain ".example.com.")
    [ "$result" = "example.com" ]
}

@test "sanitize_domain strips leading/trailing hyphens" {
    result=$(sanitize_domain "-example.com-")
    [ "$result" = "example.com" ]
}

@test "sanitize_domain strips https:// scheme" {
    result=$(sanitize_domain "https://example.com")
    [ "$result" = "example.com" ]
}

@test "sanitize_domain strips http:// scheme with subdomain" {
    result=$(sanitize_domain "http://sub.example.com")
    [ "$result" = "sub.example.com" ]
}

@test "sanitize_domain strips path" {
    result=$(sanitize_domain "https://example.com/path/to/x")
    [ "$result" = "example.com" ]
}

@test "sanitize_domain strips port" {
    result=$(sanitize_domain "https://example.com:8443")
    [ "$result" = "example.com" ]
}

@test "sanitize_domain strips query and fragment" {
    result=$(sanitize_domain "https://example.com?q=1#frag")
    [ "$result" = "example.com" ]
}

@test "sanitize_domain strips userinfo" {
    result=$(sanitize_domain "https://user:pass@example.com/")
    [ "$result" = "example.com" ]
}

@test "sanitize_domain handles @ in path (not userinfo)" {
    result=$(sanitize_domain "https://example.com/path@x")
    [ "$result" = "example.com" ]
}

@test "sanitize_domain rejects URL with invalid IP octet" {
    run sanitize_domain "https://1.2.3.999/"
    [ "$status" -ne 0 ]
}

@test "sanitize_domain accepts URL with valid IP" {
    result=$(sanitize_domain "https://1.2.3.4:8080/")
    [ "$result" = "1.2.3.4" ]
}

@test "sanitize_domain normalizes URL with all parts" {
    result=$(sanitize_domain "https://user:pass@sub.example.com:8443/path?q=1#f")
    [ "$result" = "sub.example.com" ]
}

@test "sanitize_interlace_input removes shell metacharacters" {
    local tmpfile
    tmpfile=$(mktemp)
    local outfile
    outfile=$(mktemp)
    printf "safe-target.com\n; rm -rf /\nhttps://good.com\n\$(whoami)\n" > "$tmpfile"
    sanitize_interlace_input "$tmpfile" "$outfile"
    # Should only contain the safe lines
    run grep -c ';' "$outfile"
    [ "$output" = "0" ]
    run grep -c 'safe-target.com' "$outfile"
    [ "$output" = "1" ]
    rm -f "$tmpfile" "$outfile"
}

@test "sanitize_interlace_input handles in-place mode" {
    local tmpfile
    tmpfile=$(mktemp)
    printf "safe.com\n;bad\ngood.org\n" > "$tmpfile"
    sanitize_interlace_input "$tmpfile"
    run grep -c ';' "$tmpfile"
    [ "$output" = "0" ]
    run grep -c 'safe.com' "$tmpfile"
    [ "$output" = "1" ]
    rm -f "$tmpfile"
}

@test "deleteOutScoped removes matching entries" {
    local scopefile
    scopefile=$(mktemp)
    local targetfile
    targetfile=$(mktemp)
    printf "outofscope.com\n" > "$scopefile"
    printf "inscope.com\noutofscope.com\nanother.com\n" > "$targetfile"
    deleteOutScoped "$scopefile" "$targetfile"
    run grep -c 'outofscope.com' "$targetfile"
    [ "$output" = "0" ]
    run grep -c 'inscope.com' "$targetfile"
    [ "$output" = "1" ]
    rm -f "$scopefile" "$targetfile"
}

@test "deleteOutScoped handles wildcard patterns" {
    local scopefile
    scopefile=$(mktemp)
    local targetfile
    targetfile=$(mktemp)
    printf "*.outofscope.com\n" > "$scopefile"
    printf "sub.outofscope.com\ninscope.com\n" > "$targetfile"
    deleteOutScoped "$scopefile" "$targetfile"
    run grep -c 'outofscope.com' "$targetfile"
    [ "$output" = "0" ]
    rm -f "$scopefile" "$targetfile"
}

@test "deleteOutScoped handles regex metacharacters safely" {
    local scopefile
    scopefile=$(mktemp)
    local targetfile
    targetfile=$(mktemp)
    # The dot in domain names is a regex metacharacter
    printf "test.example.com\n" > "$scopefile"
    printf "test.example.com\ntestXexampleXcom\n" > "$targetfile"
    deleteOutScoped "$scopefile" "$targetfile"
    # test.example.com should be removed, testXexampleXcom should remain
    run grep -c 'testXexampleXcom' "$targetfile"
    [ "$output" = "1" ]
    rm -f "$scopefile" "$targetfile"
}
