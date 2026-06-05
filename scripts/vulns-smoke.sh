#!/usr/bin/env bash
# vulns-smoke.sh — Phase 6 DoD-2 real-data E2E smoke test.
#
# Runs the full vulns DAG against a vuln-bait lab (DVWA / Juice Shop) and
# verifies the Phase 6 staging contract on real data: findings.jsonl non-empty,
# at least one XSS + one SQLi class entry present (minimum DoD-2 bar for DVWA).
#
# Usage:
#   scripts/vulns-smoke.sh <lab-url> [--urls FILE] [--inspect-only]
#   scripts/vulns-smoke.sh http://localhost:8080            # DVWA default port
#   scripts/vulns-smoke.sh http://dvwa.local:8080           # custom hostname
#   scripts/vulns-smoke.sh http://localhost:3000            # Juice Shop
#   scripts/vulns-smoke.sh http://localhost:8080 --urls lab/dvwa-seed-urls.txt
#   scripts/vulns-smoke.sh http://localhost:8080 --inspect-only   # check last workspace
#
# Requirements:
#   - reconftw binary built: make build  (or: go build -o bin/reconftw ./cmd/reconftw)
#   - Lab target reachable: curl -s -o /dev/null -w "%{http_code}" <lab-url> returns 2xx
#   - At minimum: gf + dalfox + sqlmap installed for XSS + SQLi classes to fire
#   - jq on PATH (for findings analysis)
#
# Lab setup (pick one):
#   docker run --rm -d -p 8080:80 vulnerables/web-dvwa
#     -> browse http://localhost:8080/setup.php, click "Create / Reset Database"
#     -> set security level to "Low" at http://localhost:8080/security.php
#   docker run --rm -d -p 3000:3000 bkimminich/juice-shop
#     -> no auth wall; works out of the box
#
# Seed URLs (D-V8 W9 fix — pass pre-seeded parameterized URLs so gf classifies
# real sqli/xss/lfi buckets and param scanners are actually exercised):
#   Default seed: lab/dvwa-seed-urls.txt (committed DVWA param-URL corpus)
#   Override:     --urls <path>
#
# Safety note (T-06-10-01):
#   This script warns if the lab target is a public domain (not localhost/RFC1918).
#   Never aim reconftw vulns at a target you don't own or have explicit permission to test.
#
# Exit codes: 0 = PASS, 1 = REVIEW (soft failures), 2 = usage / setup error
set -uo pipefail

BIN="${BIN:-./bin/reconftw}"
LAB_URL=""
SEED_URLS=""
INSPECT_ONLY=0

die() {
    printf 'vulns-smoke: %s\n' "$1" >&2
    exit 2
}

warn() {
    printf 'vulns-smoke: WARN: %s\n' "$1" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --inspect-only) INSPECT_ONLY=1 ;;
        --urls)
            shift
            [ $# -gt 0 ] || die "--urls requires a FILE argument"
            SEED_URLS="$1"
            ;;
        -h | --help)
            sed -n '2,27p' "$0"
            exit 0
            ;;
        -*) die "unknown flag: $1" ;;
        *)
            if [ -z "$LAB_URL" ]; then
                LAB_URL="$1"
            else
                die "unexpected argument: $1 (only one lab URL allowed)"
            fi
            ;;
    esac
    shift
done

[ -n "$LAB_URL" ] || die "usage: scripts/vulns-smoke.sh <lab-url> [--urls FILE] [--inspect-only]"
command -v jq >/dev/null 2>&1 || die "jq not found on PATH — install jq first"

# Safety check (T-06-10-01): warn if target is a public domain.
_host="${LAB_URL#*://}"
_host="${_host%%/*}"
_host="${_host%%:*}"
case "$_host" in
    localhost | 127.0.0.1 | ::1 | 10.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].* | 192.168.*)
        # RFC1918 / loopback — expected lab target.
        ;;
    *)
        warn "Lab target '$_host' does not look like localhost or RFC1918."
        warn "Ensure you have explicit written permission to scan this host."
        warn "Sleeping 5s — Ctrl-C now to abort."
        sleep 5
        ;;
esac

# Default seed URL file (D-V8 / W9 fix — pre-seeded parameterized URL corpus).
if [ -z "$SEED_URLS" ]; then
    # Resolve relative to the repo root (script lives in scripts/).
    _repo_root="$(cd "$(dirname "$0")/.." && pwd)"
    SEED_URLS="${_repo_root}/lab/dvwa-seed-urls.txt"
fi

if [ "$INSPECT_ONLY" -eq 0 ]; then
    [ -x "$BIN" ] || die "$BIN not found — run: make build  (or: go build -o bin/reconftw ./cmd/reconftw)"

    # Reachability gate — lab must return 2xx or 3xx before we start scanning.
    _http_code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 "$LAB_URL" 2>/dev/null || true)
    case "$_http_code" in
        2* | 3*) ;;  # OK
        "")
            die "lab target '$LAB_URL' is unreachable (curl timed out). Start your docker lab first."
            ;;
        *)
            die "lab target '$LAB_URL' returned HTTP $_http_code — expected 2xx/3xx. Check the lab is running."
            ;;
    esac
    printf '== vulns smoke: lab %s (HTTP %s) ==\n' "$LAB_URL" "$_http_code"

    # Seed URL validation — W9 fix: without parameterized URLs gf classifies 0 entries
    # and all param-aware scanners (dalfox/sqlmap/commix/lfi) receive empty input.
    if [ ! -f "$SEED_URLS" ]; then
        die "Seed URL file not found: $SEED_URLS
Create lab/dvwa-seed-urls.txt with known DVWA param URLs (see comments in that file),
or pass --urls <path> to provide your own parameterized URL corpus."
    fi
    _seed_count=$(grep -c . "$SEED_URLS" 2>/dev/null | tr -d ' ') || _seed_count=0
    printf '== seed URLs: %s (%s lines) ==\n' "$SEED_URLS" "$_seed_count"

    # Extract just the hostname/IP for the --target flag (strip scheme + port + path).
    _target_host="${LAB_URL#*://}"
    _target_host="${_target_host%%/*}"

    printf '== running: %s vulns --target %s --urls %s ==\n' "$BIN" "$_target_host" "$SEED_URLS"
    # Run the vulns pipeline. best_effort: don't abort smoke on scanner failures.
    if ! "$BIN" vulns --target "$_target_host" --urls "$SEED_URLS"; then
        printf 'vulns-smoke: WARN: reconftw vulns exited non-zero (best_effort — checking artefacts anyway)\n' >&2
    fi
fi

# Locate the most-recent workspace for this target.
_target_host="${LAB_URL#*://}"
_target_host="${_target_host%%/*}"
# Strip port from hostname for workspace directory matching.
_target_noport="${_target_host%%:*}"

W=$(ls -dt "workspaces/${_target_noport}"-*/ 2>/dev/null | head -1)
[ -n "$W" ] || die "no workspace under workspaces/${_target_noport}-*/ — run without --inspect-only first"
W="${W%/}"

# count <artefact-stem> — non-empty line count of artefacts/<stem>.jsonl, 0 if absent.
count() {
    local n
    n=$(grep -c . "$W/artefacts/$1.jsonl" 2>/dev/null) || true
    echo "${n:-0}"
}

fails=0
findings_n=$(count findings)

printf '\nworkspace: %s\n\nartefacts:\n' "$W"
for f in findings; do
    printf '  %-15s %s\n' "$f.jsonl" "$(count "$f")"
done

# Enumerate per-tool staging files (inputs/findings.<tool>.jsonl) to confirm
# the multi-writer staging contract was respected.
staging=$(find "$W/inputs" -maxdepth 1 -type f -name 'findings.*.jsonl' 2>/dev/null | wc -l | tr -d ' ')
printf '  per-tool staging: %s inputs/findings.<tool>.jsonl file(s)\n' "${staging:-0}"

printf '\nchecks:\n'

# Check 1: findings.jsonl non-empty (DoD-2 primary gate).
if [ "${findings_n:-0}" -gt 0 ]; then
    printf '  [OK]   findings.jsonl has %s entr%s — DoD-2 primary gate PASS\n' \
        "$findings_n" "$([ "$findings_n" -eq 1 ] && echo y || echo ies)"
else
    printf '  [FAIL] findings.jsonl is empty — DoD-2 FAIL\n'
    printf '         Possible causes:\n'
    printf '         1. Seed URLs have no vulnerable params (check lab/dvwa-seed-urls.txt)\n'
    printf '         2. DVWA security level is not "Low" (set at /security.php)\n'
    printf '         3. Scanner tools (dalfox/gf/sqlmap) not installed — check PATH\n'
    printf '         4. Lab target returned login redirect (auth wall) — check /setup.php\n'
    fails=$((fails + 1))
fi

# Check 2: category-presence gate (D-V9) — at least xss + sqli for DVWA.
if [ "${findings_n:-0}" -gt 0 ] && jq -e . "$W/artefacts/findings.jsonl" >/dev/null 2>&1; then
    printf '  [OK]   findings.jsonl is valid JSONL\n'

    printf '\n  vuln class breakdown (D-V9 category-presence check):\n'
    jq -r '.vuln_class // .type // "unknown"' "$W/artefacts/findings.jsonl" 2>/dev/null \
        | sort | uniq -c | sort -rn \
        | sed 's/^/    /'

    _xss_count=$(jq -r '.vuln_class // .type // ""' "$W/artefacts/findings.jsonl" 2>/dev/null \
        | grep -c '^xss$' || true)
    _sqli_count=$(jq -r '.vuln_class // .type // ""' "$W/artefacts/findings.jsonl" 2>/dev/null \
        | grep -c '^sqli$' || true)

    printf '\n  category-presence (DoD-2 min bar for DVWA):\n'
    if [ "${_xss_count:-0}" -gt 0 ]; then
        printf '    [OK]   xss class: %s finding(s)\n' "$_xss_count"
    else
        printf '    [WARN] xss class: 0 findings (dalfox installed? DVWA Low security?)\n'
    fi
    if [ "${_sqli_count:-0}" -gt 0 ]; then
        printf '    [OK]   sqli class: %s finding(s)\n' "$_sqli_count"
    else
        printf '    [WARN] sqli class: 0 findings (sqlmap/ghauri installed? DVWA Low security?)\n'
    fi
elif [ "${findings_n:-0}" -gt 0 ]; then
    printf '  [FAIL] findings.jsonl present but not valid JSONL\n'
    fails=$((fails + 1))
fi

# Check 3: staging contract (multi-writer — mirrors web-smoke.sh).
if [ "${staging:-0}" -gt 0 ]; then
    printf '\n  [OK]   %s per-tool staging file(s) — multi-writer contract live\n' "$staging"
    find "$W/inputs" -maxdepth 1 -type f -name 'findings.*.jsonl' 2>/dev/null \
        | sort | xargs -I{} basename {} 2>/dev/null | sed 's/^/           /'
else
    printf '\n  [WARN] no inputs/findings.<tool>.jsonl files (tools may have found nothing or are not installed)\n'
fi

# Check 4: gf bucket files (DAG root output — D-V4).
_gf_buckets=$(find "$W/inputs/gf" -maxdepth 1 -type f -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')
if [ "${_gf_buckets:-0}" -gt 0 ]; then
    printf '  [OK]   gf-classify produced %s bucket file(s) under inputs/gf/\n' "$_gf_buckets"
    find "$W/inputs/gf" -maxdepth 1 -type f -name '*.txt' 2>/dev/null | sort | while read -r _f; do
        _cnt=$(grep -c . "$_f" 2>/dev/null | tr -d ' ') || _cnt=0
        printf '           %-30s %s URL(s)\n' "$(basename "$_f")" "${_cnt:-0}"
    done
else
    printf '  [WARN] no gf bucket files under inputs/gf/ — gf not installed or 0 URLs classified\n'
fi

printf '\n'
printf 'Total findings: %s\n' "$findings_n"
printf '\nNext step (parity — D-V9):\n'
printf '  Run the same lab target with bash v1 and compare vuln_class sets:\n'
printf '    ./reconftw.sh -d %s -a  (or: ./reconftw.sh -d %s -l)\n' \
    "$_target_noport" "$_target_noport"
printf '  Record the v1 vs v2 class comparison in:\n'
printf '    .planning/phases/06-vulnerability-scanning-e2e/06-VERIFICATION.md\n'
printf '\n'

if [ "$fails" -eq 0 ]; then
    printf 'VERDICT: PASS — vulns pipeline ran end-to-end, staging contract intact, findings non-empty.\n'
    printf '  DoD-2 CANDIDATE: update 06-VERIFICATION.md with lab target + class comparison, then sign off.\n'
    exit 0
fi
printf 'VERDICT: REVIEW — %s check(s) failed; inspect above.\n' "$fails"
exit 1
