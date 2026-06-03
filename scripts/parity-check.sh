#!/usr/bin/env bash
# DoD-2 leg(b) web-pipeline parity: v2 (Go) vs v1 (bash) for one target.
#
# Phase 5 is the WEB pipeline, so this isolates it: v2 `reconftw web` is seeded
# with v1's already-probed host set (Recon/<target>/webs/webs_all.txt) so BOTH
# engines process the SAME hosts. It then compares per-category counts (hosts /
# urls / findings) within a tolerance, checks scope, and samples JS-secret
# redaction. Comparing full end-to-end instead (v1 -r vs v2 subs+web) conflates
# the web pipeline with subdomain-source variance — not what Phase 5 ships.
#
# Prereqs (run first):
#   make build                       # builds ./bin/reconftw
#   ./reconftw.sh -d <target> -w     # v1 reference under Recon/<target>/webs/
#
# Usage:
#   scripts/parity-check.sh <target> [--compare-only] [--seed FILE] [--threshold PCT]
#     --compare-only   skip the v2 web run; compare the latest existing workspace
#     --seed FILE      host seed for v2 web (default: v1 webs_all.txt)
#     --threshold PCT  per-category tolerance, default 5
#
# Exit: 0 = PASS (all categories within tolerance + scope clean); 1 = REVIEW.
#
# NOTE: no `set -e` on purpose — grep/jq counters return non-zero on empty input
# by design; the script handles those explicitly and decides the verdict itself.
set -uo pipefail

BIN="./bin/reconftw"
TARGET=""
COMPARE_ONLY=0
SEED=""
THRESHOLD=5

die() {
    printf 'parity-check: %s\n' "$1" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --compare-only) COMPARE_ONLY=1 ;;
        --seed)
            shift
            SEED="${1:-}"
            ;;
        --threshold)
            shift
            THRESHOLD="${1:-5}"
            ;;
        -h | --help)
            sed -n '2,28p' "$0"
            exit 0
            ;;
        -*) die "unknown flag: $1" ;;
        *) TARGET="$1" ;;
    esac
    shift
done

[ -n "$TARGET" ] || die "usage: scripts/parity-check.sh <target> [--compare-only] [--seed FILE] [--threshold PCT]"
command -v jq >/dev/null 2>&1 || die "jq not found on PATH"

V1DIR="Recon/${TARGET}"
V1HOSTS="${V1DIR}/webs/webs_all.txt"
V1URLS="${V1DIR}/webs/url_extract.txt"
V1NUCLEI="${V1DIR}/nuclei_output"

[ -s "$V1HOSTS" ] || die "v1 reference missing: $V1HOSTS — run: ./reconftw.sh -d ${TARGET} -w"

SEED="${SEED:-$V1HOSTS}"

# count_lines <file> — non-empty line count, 0 when missing/empty.
count_lines() {
    [ -f "$1" ] || {
        echo 0
        return
    }
    local n
    n=$(grep -c . "$1" 2>/dev/null) || true
    echo "${n:-0}"
}

# uniq_hosts <jsonl> — sorted-unique .host values.
uniq_hosts() {
    jq -r '.host // empty' "$1" 2>/dev/null | sort -u
}

if [ "$COMPARE_ONLY" -eq 0 ]; then
    [ -x "$BIN" ] || die "$BIN not found — run: make build"
    [ -s "$SEED" ] || die "seed host file empty/missing: $SEED"
    printf '== v2 web run (seed=%s, %s hosts) ==\n' "$SEED" "$(count_lines "$SEED")"
    "$BIN" web --target "$TARGET" --hosts "$SEED" || die "v2 web run failed"
fi

# Latest v2 workspace for this target (each run mints workspaces/<slug>-<ts>/).
W=$(ls -dt "workspaces/${TARGET}"-*/ 2>/dev/null | head -1)
[ -n "$W" ] || die "no workspace under workspaces/${TARGET}-*/ — run without --compare-only"
W="${W%/}"

V2HOSTS_F="$W/artefacts/hosts.jsonl"
V2URLS_F="$W/artefacts/urls.jsonl"
V2FIND_F="$W/artefacts/findings.jsonl"
V2JSSEC_F="$W/artefacts/js_secrets.jsonl"

v2_hosts=$(uniq_hosts "$V2HOSTS_F" | grep -c . 2>/dev/null) || true
v1_hosts=$(sed 's#https\?://##; s#[:/].*##' "$V1HOSTS" 2>/dev/null | sort -u | grep -c . 2>/dev/null) || true
v2_urls=$(count_lines "$V2URLS_F")
v1_urls=$(count_lines "$V1URLS")
v2_find=$(count_lines "$V2FIND_F")
v1_find=$(find "$V1NUCLEI" -type f -name '*_json.txt' -exec cat {} + 2>/dev/null | grep -c . 2>/dev/null) || true

v2_hosts=${v2_hosts:-0}
v1_hosts=${v1_hosts:-0}
v1_find=${v1_find:-0}

fails=0

row() {
    local label="$1" v2="$2" v1="$3"
    if [ "$v1" -le 0 ]; then
        printf '  %-9s v2=%-7s v1=%-7s  (v1=0 — eyeball)\n' "$label" "$v2" "$v1"
        return
    fi
    local d=$(((v2 - v1) * 100 / v1))
    local ad=${d#-}
    local verdict="OK"
    if [ "$ad" -gt "$THRESHOLD" ]; then
        verdict="OUT (>${THRESHOLD}%)"
        fails=$((fails + 1))
    fi
    printf '  %-9s v2=%-7s v1=%-7s  d=%+d%%  %s\n' "$label" "$v2" "$v1" "$d" "$verdict"
}

printf '\n===== parity: %s =====\n' "$TARGET"
printf 'v2 workspace : %s\n' "$W"
printf 'v1 reference : %s\n' "$V1DIR"
printf 'seed / tol   : %s / ±%s%%\n\n' "$SEED" "$THRESHOLD"
row hosts "$v2_hosts" "$v1_hosts"
row urls "$v2_urls" "$v1_urls"
row findings "$v2_find" "$v1_find"

esc="${TARGET//./\\.}"
oos=$(uniq_hosts "$V2HOSTS_F" | grep -vE "(^|\.)${esc}\$" || true)
printf '\nscope (out-of-scope hosts, want none):\n'
if [ -n "$oos" ]; then
    printf '%s\n' "$oos" | sed 's/^/  OOS: /'
    fails=$((fails + 1))
else
    printf '  OK — all hosts in scope\n'
fi

if [ -s "$V2JSSEC_F" ]; then
    printf '\njs_secrets sample (confirm values are redacted, not raw):\n'
    jq -c '.' "$V2JSSEC_F" 2>/dev/null | head -3 | sed 's/^/  /'
fi

printf '\n'
if [ "$fails" -eq 0 ]; then
    printf 'VERDICT: PASS — categories within ±%s%%, scope clean.\n' "$THRESHOLD"
    exit 0
fi
printf 'VERDICT: REVIEW — %s check(s) flagged; inspect before sign-off.\n' "$fails"
exit 1
