#!/usr/bin/env bats

# Extended unit tests for validation functions in lib/validation.sh
# Covers: validate_integer, validate_port, sanitize_path,
#         sanitize_interlace_input, is_empty, is_numeric,
#         and corrects validate_boolean coverage gaps.

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

# ─────────────────────────────────────────────────────────────────────────────
# validate_boolean — full coverage (implementation accepts: true|false|1|0|yes|no)
# ─────────────────────────────────────────────────────────────────────────────

@test "validate_boolean accepts 'true'" {
    run validate_boolean "true"
    [ "$status" -eq 0 ]
}

@test "validate_boolean accepts 'false'" {
    run validate_boolean "false"
    [ "$status" -eq 0 ]
}

@test "validate_boolean accepts '1'" {
    run validate_boolean "1"
    [ "$status" -eq 0 ]
}

@test "validate_boolean accepts '0'" {
    run validate_boolean "0"
    [ "$status" -eq 0 ]
}

@test "validate_boolean accepts 'yes'" {
    run validate_boolean "yes"
    [ "$status" -eq 0 ]
}

@test "validate_boolean accepts 'no'" {
    run validate_boolean "no"
    [ "$status" -eq 0 ]
}

@test "validate_boolean rejects empty string" {
    run validate_boolean ""
    [ "$status" -ne 0 ]
}

@test "validate_boolean rejects 'maybe'" {
    run validate_boolean "maybe"
    [ "$status" -ne 0 ]
}

@test "validate_boolean rejects 'TRUE' (case-sensitive)" {
    run validate_boolean "TRUE"
    [ "$status" -ne 0 ]
}

@test "validate_boolean rejects 'YES' (case-sensitive)" {
    run validate_boolean "YES"
    [ "$status" -ne 0 ]
}

@test "validate_boolean rejects '2'" {
    run validate_boolean "2"
    [ "$status" -ne 0 ]
}

@test "validate_boolean rejects whitespace-padded value" {
    run validate_boolean " true"
    [ "$status" -ne 0 ]
}

# ─────────────────────────────────────────────────────────────────────────────
# validate_integer
# ─────────────────────────────────────────────────────────────────────────────

@test "validate_integer accepts positive integer" {
    run validate_integer "42"
    [ "$status" -eq 0 ]
}

@test "validate_integer accepts zero" {
    run validate_integer "0"
    [ "$status" -eq 0 ]
}

@test "validate_integer accepts negative integer" {
    run validate_integer "-5"
    [ "$status" -eq 0 ]
}

@test "validate_integer accepts large integer" {
    run validate_integer "65535"
    [ "$status" -eq 0 ]
}

@test "validate_integer rejects float" {
    run validate_integer "3.14"
    [ "$status" -ne 0 ]
}

@test "validate_integer rejects empty string" {
    run validate_integer ""
    [ "$status" -ne 0 ]
}

@test "validate_integer rejects letters" {
    run validate_integer "abc"
    [ "$status" -ne 0 ]
}

@test "validate_integer rejects alphanumeric" {
    run validate_integer "10abc"
    [ "$status" -ne 0 ]
}

@test "validate_integer respects min bound — value below min fails" {
    run validate_integer "5" "10"
    [ "$status" -ne 0 ]
}

@test "validate_integer respects min bound — value at min passes" {
    run validate_integer "10" "10"
    [ "$status" -eq 0 ]
}

@test "validate_integer respects min bound — value above min passes" {
    run validate_integer "15" "10"
    [ "$status" -eq 0 ]
}

@test "validate_integer respects max bound — value above max fails" {
    run validate_integer "200" "" "100"
    [ "$status" -ne 0 ]
}

@test "validate_integer respects max bound — value at max passes" {
    run validate_integer "100" "" "100"
    [ "$status" -eq 0 ]
}

@test "validate_integer respects both bounds — value within range passes" {
    run validate_integer "50" "1" "100"
    [ "$status" -eq 0 ]
}

@test "validate_integer respects both bounds — value below range fails" {
    run validate_integer "0" "1" "100"
    [ "$status" -ne 0 ]
}

@test "validate_integer respects both bounds — value above range fails" {
    run validate_integer "101" "1" "100"
    [ "$status" -ne 0 ]
}

# ─────────────────────────────────────────────────────────────────────────────
# validate_port
# ─────────────────────────────────────────────────────────────────────────────

@test "validate_port accepts port 1 (minimum)" {
    run validate_port "1"
    [ "$status" -eq 0 ]
}

@test "validate_port accepts port 80" {
    run validate_port "80"
    [ "$status" -eq 0 ]
}

@test "validate_port accepts port 443" {
    run validate_port "443"
    [ "$status" -eq 0 ]
}

@test "validate_port accepts port 8080" {
    run validate_port "8080"
    [ "$status" -eq 0 ]
}

@test "validate_port accepts port 65535 (maximum)" {
    run validate_port "65535"
    [ "$status" -eq 0 ]
}

@test "validate_port rejects port 0 (below minimum)" {
    run validate_port "0"
    [ "$status" -ne 0 ]
}

@test "validate_port rejects port 65536 (above maximum)" {
    run validate_port "65536"
    [ "$status" -ne 0 ]
}

@test "validate_port rejects negative port" {
    run validate_port "-1"
    [ "$status" -ne 0 ]
}

@test "validate_port rejects non-numeric string" {
    run validate_port "http"
    [ "$status" -ne 0 ]
}

@test "validate_port rejects empty string" {
    run validate_port ""
    [ "$status" -ne 0 ]
}

@test "validate_port rejects float port" {
    run validate_port "80.5"
    [ "$status" -ne 0 ]
}

# ─────────────────────────────────────────────────────────────────────────────
# sanitize_path
# ─────────────────────────────────────────────────────────────────────────────

@test "sanitize_path returns clean path unchanged" {
    result="$(sanitize_path "/home/user/recon")"
    [ "$result" = "/home/user/recon" ]
}

@test "sanitize_path strips trailing slash" {
    result="$(sanitize_path "/home/user/recon/")"
    [ "$result" = "/home/user/recon" ]
}

@test "sanitize_path strips multiple trailing slashes" {
    result="$(sanitize_path "/home/user/recon///")"
    [ "$result" = "/home/user/recon" ]
}

@test "sanitize_path preserves root slash" {
    result="$(sanitize_path "/")"
    [ "$result" = "/" ]
}

@test "sanitize_path normalizes double slashes in middle" {
    result="$(sanitize_path "/home//user/recon")"
    [ "$result" = "/home/user/recon" ]
}

@test "sanitize_path removes control characters" {
    # Tab character should be stripped
    result="$(sanitize_path $'/home/user/rec\ton')"
    [[ "$result" != *$'\t'* ]]
}

@test "sanitize_path handles relative path" {
    result="$(sanitize_path "Recon/example.com")"
    [ "$result" = "Recon/example.com" ]
}

# ─────────────────────────────────────────────────────────────────────────────
# sanitize_interlace_input
# ─────────────────────────────────────────────────────────────────────────────

@test "sanitize_interlace_input keeps safe domains" {
    local tmpfile
    tmpfile="$(mktemp)"
    printf 'example.com\nsub.target.org\n' > "$tmpfile"
    sanitize_interlace_input "$tmpfile"
    grep -q "example.com" "$tmpfile"
    grep -q "sub.target.org" "$tmpfile"
    rm -f "$tmpfile"
}

@test "sanitize_interlace_input removes semicolon lines" {
    local tmpfile
    tmpfile="$(mktemp)"
    printf 'safe.com\nevil;rm -rf /\n' > "$tmpfile"
    sanitize_interlace_input "$tmpfile"
    ! grep -q ";" "$tmpfile"
    rm -f "$tmpfile"
}

@test "sanitize_interlace_input removes pipe lines" {
    local tmpfile
    tmpfile="$(mktemp)"
    printf 'safe.com\nevil|whoami\n' > "$tmpfile"
    sanitize_interlace_input "$tmpfile"
    ! grep -q "|" "$tmpfile"
    rm -f "$tmpfile"
}

@test "sanitize_interlace_input removes dollar-substitution lines" {
    local tmpfile
    tmpfile="$(mktemp)"
    printf 'safe.com\n$(id).attacker.com\n' > "$tmpfile"
    sanitize_interlace_input "$tmpfile"
    ! grep -q '\$' "$tmpfile"
    rm -f "$tmpfile"
}

@test "sanitize_interlace_input removes backtick lines" {
    local tmpfile
    tmpfile="$(mktemp)"
    printf 'safe.com\n`id`.evil.com\n' > "$tmpfile"
    sanitize_interlace_input "$tmpfile"
    ! grep -q '`' "$tmpfile"
    rm -f "$tmpfile"
}

@test "sanitize_interlace_input in-place edit preserves safe lines" {
    local tmpfile
    tmpfile="$(mktemp)"
    printf 'clean1.com\nclean2.com\nevil;cmd\n' > "$tmpfile"
    sanitize_interlace_input "$tmpfile"
    local count
    count="$(wc -l < "$tmpfile")"
    [ "$count" -eq 2 ]
    rm -f "$tmpfile"
}

@test "sanitize_interlace_input supports separate output file" {
    local infile outfile
    infile="$(mktemp)"
    outfile="$(mktemp)"
    printf 'safe.com\nevil;cmd\n' > "$infile"
    sanitize_interlace_input "$infile" "$outfile"
    grep -q "safe.com" "$outfile"
    ! grep -q ";" "$outfile"
    rm -f "$infile" "$outfile"
}

# ─────────────────────────────────────────────────────────────────────────────
# is_empty
# ─────────────────────────────────────────────────────────────────────────────

@test "is_empty returns 0 for empty string" {
    run is_empty ""
    [ "$status" -eq 0 ]
}

@test "is_empty returns 0 for whitespace-only string" {
    run is_empty "   "
    [ "$status" -eq 0 ]
}

@test "is_empty returns 1 for non-empty string" {
    run is_empty "hello"
    [ "$status" -ne 0 ]
}

@test "is_empty returns 1 for string with leading whitespace" {
    run is_empty "  value"
    [ "$status" -ne 0 ]
}

@test "is_empty returns 1 for zero string '0'" {
    run is_empty "0"
    [ "$status" -ne 0 ]
}

# ─────────────────────────────────────────────────────────────────────────────
# is_numeric
# ─────────────────────────────────────────────────────────────────────────────

@test "is_numeric returns 0 for positive integer" {
    run is_numeric "42"
    [ "$status" -eq 0 ]
}

@test "is_numeric returns 0 for zero" {
    run is_numeric "0"
    [ "$status" -eq 0 ]
}

@test "is_numeric returns 0 for negative integer" {
    run is_numeric "-10"
    [ "$status" -eq 0 ]
}

@test "is_numeric returns 0 for float" {
    run is_numeric "3.14"
    [ "$status" -eq 0 ]
}

@test "is_numeric returns 0 for negative float" {
    run is_numeric "-2.5"
    [ "$status" -eq 0 ]
}

@test "is_numeric returns 1 for empty string" {
    run is_numeric ""
    [ "$status" -ne 0 ]
}

@test "is_numeric returns 1 for alphabetic string" {
    run is_numeric "abc"
    [ "$status" -ne 0 ]
}

@test "is_numeric returns 1 for alphanumeric string" {
    run is_numeric "12abc"
    [ "$status" -ne 0 ]
}

@test "is_numeric returns 1 for string with spaces" {
    run is_numeric "1 2"
    [ "$status" -ne 0 ]
}

@test "is_numeric returns 1 for double dot (malformed float)" {
    run is_numeric "1.2.3"
    [ "$status" -ne 0 ]
}
