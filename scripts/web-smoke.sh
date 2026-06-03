#!/usr/bin/env bash
# Quick web-pipeline smoke for v2 reconftw — runs the full web DAG on a SMALL
# host seed (NO subdomain enumeration) and verifies the Phase 5 staging contract
# on real data in minutes. With no hosts it seeds the apex + www.
#
# Usage:
#   scripts/web-smoke.sh <target> [host ...]
#   scripts/web-smoke.sh <target> --inspect-only   # skip the run, check latest workspace
#
# Verdict PASS = probe produced hosts, urldedup emitted valid urls.jsonl, per-tool
# staging files exist (inputs/{urls,findings,waf}.<tool>.jsonl), and every probed
# host is in scope. Exit 0 = PASS, 1 = REVIEW, 2 = usage/setup error.
#
# Run from the repo root. Override the binary with BIN=/path/to/reconftw.
set -uo pipefail

BIN="${BIN:-./bin/reconftw}"
TARGET=""
INSPECT_ONLY=0
HOSTS=()

die() {
    printf 'web-smoke: %s\n' "$1" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --inspect-only) INSPECT_ONLY=1 ;;
        -h | --help)
            sed -n '2,13p' "$0"
            exit 0
            ;;
        -*) die "unknown flag: $1" ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
            else
                HOSTS+=("$1")
            fi
            ;;
    esac
    shift
done

[ -n "$TARGET" ] || die "usage: scripts/web-smoke.sh <target> [host ...] [--inspect-only]"
command -v jq >/dev/null 2>&1 || die "jq not found on PATH"

if [ "$INSPECT_ONLY" -eq 0 ]; then
    [ -x "$BIN" ] || die "$BIN not found — run: make build"
    if [ "${#HOSTS[@]}" -eq 0 ]; then
        HOSTS=("https://${TARGET}" "https://www.${TARGET}")
    fi
    SEED=$(mktemp)
    printf '%s\n' "${HOSTS[@]}" >"$SEED"
    printf '== web smoke: %s (%s seed host(s), takes minutes) ==\n' "$TARGET" "${#HOSTS[@]}"
    if ! "$BIN" web --target "$TARGET" --hosts "$SEED"; then
        rm -f "$SEED"
        die "v2 web run failed"
    fi
    rm -f "$SEED"
fi

W=$(ls -dt "workspaces/${TARGET}"-*/ 2>/dev/null | head -1)
[ -n "$W" ] || die "no workspace under workspaces/${TARGET}-*/ — run without --inspect-only"
W="${W%/}"

# count <artefact-stem> — non-empty line count of artefacts/<stem>.jsonl, 0 if absent.
count() {
    local n
    n=$(grep -c . "$W/artefacts/$1.jsonl" 2>/dev/null) || true
    echo "${n:-0}"
}

fails=0
hosts_n=$(count hosts)
urls_n=$(count urls)

printf '\nworkspace: %s\n\nartefacts:\n' "$W"
for f in hosts urls findings waf origins fuzz favicons vhosts js_secrets; do
    printf '  %-13s %s\n' "$f.jsonl" "$(count "$f")"
done

printf '\nchecks:\n'

if [ "$hosts_n" -gt 0 ]; then
    printf '  [OK]   probe produced %s host record(s)\n' "$hosts_n"
else
    printf '  [FAIL] hosts.jsonl empty — web probed nothing (seed / network?)\n'
    fails=$((fails + 1))
fi

staging=$(find "$W/inputs" -maxdepth 1 -type f \( -name 'urls.*.jsonl' -o -name 'findings.*.jsonl' -o -name 'waf.*.jsonl' \) 2>/dev/null | wc -l | tr -d ' ')
if [ "${staging:-0}" -gt 0 ]; then
    printf '  [OK]   %s per-tool staging file(s) — multi-writer contract live\n' "$staging"
    find "$W/inputs" -maxdepth 1 -type f \( -name 'urls.*.jsonl' -o -name 'findings.*.jsonl' -o -name 'waf.*.jsonl' \) -exec basename {} \; 2>/dev/null | sort | sed 's/^/           /'
else
    printf '  [WARN] no inputs/{urls,findings,waf}.<tool>.jsonl (tools may have found nothing)\n'
fi

if [ -s "$W/artefacts/urls.jsonl" ]; then
    if jq -e . "$W/artefacts/urls.jsonl" >/dev/null 2>&1; then
        printf '  [OK]   urls.jsonl valid JSONL — urldedup union of %s url(s)\n' "$urls_n"
    else
        printf '  [FAIL] urls.jsonl present but not valid JSONL\n'
        fails=$((fails + 1))
    fi
else
    printf '  [WARN] urls.jsonl empty (no URLs discovered for this seed)\n'
fi

esc="${TARGET//./\\.}"
oos=$(jq -r '.host // empty' "$W/artefacts/hosts.jsonl" 2>/dev/null | sort -u | grep -vE "(^|\.)${esc}\$" || true)
if [ -n "$oos" ]; then
    printf '  [FAIL] out-of-scope host(s) in hosts.jsonl:\n'
    printf '%s\n' "$oos" | sed 's/^/           /'
    fails=$((fails + 1))
else
    printf '  [OK]   all probed hosts in scope\n'
fi

printf '\n'
if [ "$fails" -eq 0 ]; then
    printf 'VERDICT: PASS — web pipeline ran end-to-end, staging contract intact, scope clean.\n'
    exit 0
fi
printf 'VERDICT: REVIEW — %s check(s) failed; inspect above.\n' "$fails"
exit 1
