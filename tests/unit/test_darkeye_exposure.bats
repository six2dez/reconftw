#!/usr/bin/env bats

setup() {
    export SCRIPTPATH="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
    TEST_DIR=$(mktemp -d)
    export dir="$TEST_DIR/target" domain="example.com"
    export called_fn_dir="$dir/.called_fn" LOGFILE="$TEST_DIR/run.log"
    mkdir -p "$dir/osint" "$called_fn_dir" "$TEST_DIR/bin"
    export DARKEYE_EXPOSURE=true OSINT=true DIFF=false DRY_RUN=false
    export DARKEYE_HIBR_API_KEY=synthetic-hibr DARKEYE_BREACHHOUSE_API_KEY=synthetic-bh
    export DARKEYE_MAX_PAGES=5 DARKEYE_LIMIT=25 DARKEYE_MAX_RECORDS=100 DARKEYE_TIMEOUT=30
    export CALLS="$TEST_DIR/calls" FIXTURES="$TEST_DIR"
    : >"$CALLS"
    printf '%s' '{"sources":[{"id_source":"a","leak_type":"ransomware_leak","post_title":"Example","website":"example.com","password":"DO_NOT_KEEP","link":"http://hidden.onion"}],"has_next":false}' >"$TEST_DIR/hibr"
    printf '%s' '{"ransomware":{"results":[{"id":"b","website":"sub.example.com","name":"Example"}]},"breaches":{"results":[]},"stealers":{"results":[]},"leads":{"results":[]}}' >"$TEST_DIR/bh"
    cat >"$TEST_DIR/bin/curl" <<'MOCK'
#!/bin/bash
printf '%s\n' "$*" >>"$CALLS"
out=""
while (($#)); do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -H) if [[ "$2" == @* ]]; then
                [[ $(stat -c %a "${2#@}") == 600 ]] || exit 9
            fi
            shift 2 ;;
        https://*) url="$1"; shift ;;
        *) shift ;;
    esac
done
if [[ "$url" == *haveibeenransom* ]]; then
    [[ "${HIBR_FAIL:-false}" == true ]] && { printf 401; exit; }
    if [[ "$url" == */2 && -f "$FIXTURES/hibr2" ]]; then
        cat "$FIXTURES/hibr2" >"$out"
    else
        cat "$FIXTURES/hibr" >"$out"
    fi
else
    [[ "${BH_FAIL:-false}" == true ]] && { printf 429; exit; }
    cat "$FIXTURES/bh" >"$out"
fi
printf 200
MOCK
    chmod +x "$TEST_DIR/bin/curl"
    export PATH="$TEST_DIR/bin:$PATH"
    source "$SCRIPTPATH/reconftw.sh" --source-only
    # Aislar sólo la presentación; usar validación, run_command y módulo reales.
    start_func() { :; }
    end_func() { touch "$called_fn_dir/.$2"; }
    skip_notification() { :; }
    _print_msg() { printf '%s\n' "$*"; }
    ensure_dirs() { mkdir -p "$dir/osint"; }
    export PROXYCHAINS=false ADAPTIVE_RATE_LIMIT=false DEBUG_LOG=""
}

teardown() { rm -rf "$TEST_DIR"; }

@test "both products produce one metadata-only DarkEye result and no secret in argv" {
    run darkeye_exposure
    [ "$status" -eq 0 ]
    jq -e '.source == "DarkEye" and (.records|length) == 2 and (.errors|length) == 0' "$dir/osint/darkeye.json"
    ! grep -Eq 'DO_NOT_KEEP|hidden.onion|synthetic-' "$dir/osint/darkeye.json" "$CALLS"
    [ -f "$called_fn_dir/.darkeye_exposure" ]
    [ "$(stat -c %a "$dir/osint/darkeye.json")" = 600 ]
    [ -z "$(find "$dir/osint" -name '.darkeye.*')" ]
}

@test "either product key works independently" {
    export DARKEYE_BREACHHOUSE_API_KEY=""
    darkeye_exposure
    jq -e '.records | all(.product == "HaveIBeenRansom")' "$dir/osint/darkeye.json"
    export DARKEYE_HIBR_API_KEY="" DARKEYE_BREACHHOUSE_API_KEY=synthetic-bh DIFF=true
    darkeye_exposure
    jq -e '.records | all(.product == "Breach House")' "$dir/osint/darkeye.json"
}

@test "one failed product saves the other without checkpoint" {
    export HIBR_FAIL=true
    run darkeye_exposure
    [ "$status" -eq 1 ]
    jq -e '(.records|length) == 1 and .errors.HaveIBeenRansom != null' "$dir/osint/darkeye.json"
    [ ! -e "$called_fn_dir/.darkeye_exposure" ]
}

@test "all failures preserve earlier output" {
    printf prior >"$dir/osint/darkeye.json"
    export HIBR_FAIL=true BH_FAIL=true
    run darkeye_exposure
    [ "$status" -eq 1 ]
    [ "$(cat "$dir/osint/darkeye.json")" = prior ]
}

@test "invalid JSON and invalid response shape are errors rather than no exposure" {
    printf '<html>error</html>' >"$TEST_DIR/hibr"
    printf '{}' >"$TEST_DIR/bh"
    run darkeye_exposure
    [ "$status" -eq 1 ]
    [ ! -f "$dir/osint/darkeye.json" ]
}

@test "disabled, dry run and absent keys do not query or checkpoint" {
    export DARKEYE_EXPOSURE=false
    darkeye_exposure
    export DARKEYE_EXPOSURE=true DRY_RUN=true
    darkeye_exposure
    export DRY_RUN=false DARKEYE_HIBR_API_KEY="" DARKEYE_BREACHHOUSE_API_KEY=""
    darkeye_exposure
    [ ! -s "$CALLS" ]
    [ ! -f "$called_fn_dir/.darkeye_exposure" ]
}

@test "wildcards, URLs and IPs are rejected before a request" {
    for value in '*.example.com' 'example.com?' 'https://example.com' '192.0.2.1' 'example.com;echo'; do
        export domain="$value"
        run darkeye_exposure
        [ "$status" -ne 0 ]
    done
    [ ! -s "$CALLS" ]
}

@test "empty intermediate HIBR page with has_next still advances" {
    printf '{"sources":[],"has_next":true}' >"$TEST_DIR/hibr"
    printf '{"sources":[{"id_source":"page2","leak_type":"traditional_breach"}],"has_next":false}' >"$TEST_DIR/hibr2"
    darkeye_exposure
    jq -e '.records | any(.id == "page2" and .category == "breach")' "$dir/osint/darkeye.json"
    [ "$(wc -l <"$CALLS")" -eq 3 ]
}

@test "pagination supports documented results and deduplicates repeated records" {
    printf '{"results":[{"id_source":"a"}],"pagination":{"has_next":true}}' >"$TEST_DIR/hibr"
    printf '{"results":[{"id_source":"a"}],"pagination":{"has_next":false}}' >"$TEST_DIR/hibr2"
    export DARKEYE_BREACHHOUSE_API_KEY=""
    darkeye_exposure
    jq -e '(.records|length) == 1 and .truncated == false' "$dir/osint/darkeye.json"
}

@test "page and record limits report truncation" {
    printf '{"sources":[{"id_source":"a"},{"id_source":"b"}],"has_next":true}' >"$TEST_DIR/hibr"
    export DARKEYE_MAX_PAGES=1 DARKEYE_MAX_RECORDS=1 DARKEYE_BREACHHOUSE_API_KEY=""
    darkeye_exposure
    jq -e '(.records|length) == 1 and .truncated == true' "$dir/osint/darkeye.json"
    [ "$(wc -l <"$CALLS")" -eq 1 ]
}

@test "Breach House filters adjacent hostnames and retains all four categories" {
    printf '%s' '{"ransomware":[{"id":"yes1","website":"sub.example.com"},{"id":"no1","website":"notexample.com"},{"id":"no2","website":"example.com.attacker.test"}],"breaches":[{"id":"yes2","name":"Incident at example.com."},{"id":"no3","name":"notexample.com"},{"id":"no4","name":"example.com.attacker.test"}],"leads":[{"id":"yes3","website":"example.com"}],"stealers":[{"id":"yes4","website":"EXAMPLE.COM."}]}' >"$TEST_DIR/bh"
    export DARKEYE_HIBR_API_KEY=""
    darkeye_exposure
    jq -e '(.records|length) == 4 and ([.records[].category]|sort) == ["breach","leads","ransomware","stealer"]' "$dir/osint/darkeye.json"
}

@test "valid empty responses create an empty result" {
    printf '{"sources":[],"has_next":false}' >"$TEST_DIR/hibr"
    printf '{"ransomware":[],"breaches":[],"leads":[],"stealers":[]}' >"$TEST_DIR/bh"
    darkeye_exposure
    jq -e '(.records|length) == 0 and (.errors|length) == 0' "$dir/osint/darkeye.json"
}

@test "invalid bounds and header injection are rejected" {
    export DARKEYE_MAX_PAGES=0
    run darkeye_exposure
    [ "$status" -eq 1 ]
    export DARKEYE_MAX_PAGES=5 DARKEYE_HIBR_API_KEY=$'key\r\nInjected: yes'
    run darkeye_exposure
    [ "$status" -eq 1 ]
    [ ! -s "$CALLS" ]
}

@test "completed checkpoint skips requests unless DIFF is enabled" {
    touch "$called_fn_dir/.darkeye_exposure"
    darkeye_exposure
    [ ! -s "$CALLS" ]
    export DIFF=true
    darkeye_exposure
    [ -s "$CALLS" ]
}

@test "failed DIFF refresh clears an earlier completion checkpoint" {
    touch "$called_fn_dir/.darkeye_exposure"
    export DIFF=true HIBR_FAIL=true
    run darkeye_exposure
    [ "$status" -eq 1 ]
    [ ! -f "$called_fn_dir/.darkeye_exposure" ]
    jq -e '(.records|length) == 1 and (.errors|length) == 1' "$dir/osint/darkeye.json"
}
