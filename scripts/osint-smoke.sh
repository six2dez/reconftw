#!/usr/bin/env bash
# osint-smoke.sh — Phase 7 DoD-2 real-data E2E smoke test (D-O7).
#
# Drives `reconftw osint --target <TARGET>` against a REAL public known-footprint
# target on the dev Mac and verifies the Phase 7 OSINT contract on real output:
#   - findings.jsonl exists with >=1 osint-class entry (class=="osint")
#   - category-presence SOFT gate (D-O6): every OSINT category v1 produces that is
#     key-available is PRESENT in v2 output; absent categories are LOGGED as
#     key-gated/best_effort skips (NOT failures). Finding COUNTS are NOT gated —
#     GitHub/dork/external-API results are non-deterministic and change daily.
#   - XCUT-07 SECRET-LEAK GUARD (the #1 correctness requirement): greps the entire
#     findings.jsonl + run log for any raw secret pattern (ghp_, AKIA, xoxb-, etc.)
#     and FAILS if any unredacted secret appears; secret-bearing entries must show
#     value_redacted="***".
#
# OSINT is HTTP/API-based (whois, GitHub API, dork engines, cloud probes) → it needs
# NO mass-DNS, so a real run works on the dev Mac despite the UDP/53 block (D-O7).
# PD tools are passed -duc by the Tasks to avoid update-check hangs.
#
# Many sources are key-gated (GITHUB_TOKEN(S)/SHODAN_API_KEY/WHOISXML_API/PDCP_API_KEY).
# Absent keys → LOGGED best_effort skip (D-O8) — that is EXPECTED on a keyless dev Mac
# and is NOT a failure. The script records which categories ran vs key-skipped.
#
# Usage:
#   scripts/osint-smoke.sh [TARGET] [--inspect-only]
#   scripts/osint-smoke.sh                     # default target example.com (D-O7)
#   scripts/osint-smoke.sh example.net           # alternate canonical target
#   scripts/osint-smoke.sh example.com --inspect-only   # re-check last workspace
#
# Run from the repo root. Override the binary with BIN=/path/to/reconftw.
#
# Exit codes: 0 = PASS, 1 = REVIEW (soft failures), 2 = usage / setup error,
#             3 = SECRET LEAK (XCUT-07 hard fail — never ship).
set -uo pipefail

BIN="${BIN:-./bin/reconftw}"
TARGET=""
INSPECT_ONLY=0

die() {
    printf 'osint-smoke: %s\n' "$1" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --inspect-only) INSPECT_ONLY=1 ;;
        -h | --help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
        -*) die "unknown flag: $1" ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
            else
                die "unexpected argument: $1 (only one target allowed)"
            fi
            ;;
    esac
    shift
done

# Default DoD-2 anchor target (D-O7).
[ -n "$TARGET" ] || TARGET="example.com"
command -v jq >/dev/null 2>&1 || die "jq not found on PATH — install jq first"

if [ "$INSPECT_ONLY" -eq 0 ]; then
    [ -x "$BIN" ] || die "$BIN not found — run: make build  (or: go build -o bin/reconftw ./cmd/reconftw)"
    printf '== osint smoke: real DoD-2 run against %s (D-O7 — HTTP/API, no mass-DNS) ==\n' "$TARGET"
    printf '== key-gated sources (GitHub/Shodan/WhoisXML/PDCP) skip best_effort when keys absent (D-O8) ==\n'
    # best_effort: a tool failing / a missing key logs a warning and the run COMPLETES.
    # Do NOT abort the smoke on a non-zero exit — inspect artefacts regardless.
    if ! "$BIN" osint --target "$TARGET"; then
        printf 'osint-smoke: WARN: reconftw osint exited non-zero (best_effort — checking artefacts anyway)\n' >&2
    fi
fi

# Locate the most-recent workspace for this target. WorkspaceInit may suffix the
# domain (workspaces/<domain>-<id>/) or use the bare domain — match both.
W=$(ls -dt "workspaces/${TARGET}"-*/ "workspaces/${TARGET}/" 2>/dev/null | head -1)
[ -n "$W" ] || die "no workspace under workspaces/${TARGET}*/ — run without --inspect-only first"
W="${W%/}"

FINDINGS="$W/artefacts/findings.jsonl"
RUNLOG="$W/run.log"

# count <artefact-stem> — non-empty line count of artefacts/<stem>.jsonl, 0 if absent.
count() {
    local n
    n=$(grep -c . "$W/artefacts/$1.jsonl" 2>/dev/null) || true
    echo "${n:-0}"
}

fails=0
findings_n=$(count findings)

printf '\nworkspace: %s\n\nartefacts:\n' "$W"
printf '  %-15s %s\n' "findings.jsonl" "$findings_n"

# Per-tool staging files (inputs/findings.<tool>.jsonl) — multi-writer contract.
staging=$(find "$W/inputs" -maxdepth 1 -type f -name 'findings.*.jsonl' 2>/dev/null | wc -l | tr -d ' ')
printf '  per-tool staging: %s inputs/findings.<tool>.jsonl file(s)\n' "${staging:-0}"

printf '\nchecks:\n'

# ---------------------------------------------------------------------------
# Check 1: findings.jsonl has >=1 osint-class entry (DoD-2 primary gate).
# ---------------------------------------------------------------------------
osint_n=0
if [ "${findings_n:-0}" -gt 0 ] && jq -e . "$FINDINGS" >/dev/null 2>&1; then
    printf '  [OK]   findings.jsonl is valid JSONL (%s entr%s)\n' \
        "$findings_n" "$([ "$findings_n" -eq 1 ] && echo y || echo ies)"
    osint_n=$(jq -r 'select(.class=="osint") | .source' "$FINDINGS" 2>/dev/null | grep -c . || true)
    if [ "${osint_n:-0}" -gt 0 ]; then
        printf '  [OK]   %s osint-class entr%s (class=="osint") — DoD-2 primary gate PASS\n' \
            "$osint_n" "$([ "$osint_n" -eq 1 ] && echo y || echo ies)"
    else
        printf '  [FAIL] no class=="osint" entries — DoD-2 FAIL (all sources key-skipped or no output?)\n'
        fails=$((fails + 1))
    fi
elif [ "${findings_n:-0}" -gt 0 ]; then
    printf '  [FAIL] findings.jsonl present but not valid JSONL\n'
    fails=$((fails + 1))
else
    printf '  [FAIL] findings.jsonl is empty — DoD-2 FAIL\n'
    printf '         Expected on a keyless dev Mac if EVERY source is key-gated; but key-free\n'
    printf '         sources (domain_info/whois, ip_info, emails, spoofy, cmseek) should still emit.\n'
    printf '         Check: tools on PATH? network reachable? target resolvable via system DNS?\n'
    fails=$((fails + 1))
fi

# ---------------------------------------------------------------------------
# Check 2: XCUT-07 secret-leak guard — THE #1 correctness requirement.
# Grep findings.jsonl AND run.log for any raw secret pattern. Any hit = hard fail.
# Secret-bearing entries MUST show value_redacted="***" (never the raw token).
# ---------------------------------------------------------------------------
printf '\n  XCUT-07 secret-leak guard (findings.jsonl + run.log):\n'
# High-signal raw-secret prefixes/patterns. Tuned to avoid the redaction marker
# "***" itself. AKIA = AWS key, ghp_/gho_/ghs_/github_pat_ = GitHub tokens,
# xox[baprs]- = Slack, sk-/sk_live = OpenAI/Stripe, AIza = Google API key.
SECRET_RE='ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
leak_hit=0
for f in "$FINDINGS" "$RUNLOG"; do
    [ -f "$f" ] || continue
    if grep -nEa "$SECRET_RE" "$f" >/dev/null 2>&1; then
        printf '    [LEAK] raw secret pattern found in %s:\n' "$f"
        # Show the offending lines with the secret partially masked for the report.
        grep -nEa "$SECRET_RE" "$f" 2>/dev/null | head -10 \
            | sed -E 's/(ghp_|gho_|ghs_|github_pat_|AKIA|xox[baprs]-|sk-|sk_live_|AIza)[A-Za-z0-9_/+-]+/\1<REDACTED-BY-SMOKE>/g' \
            | sed 's/^/           /'
        leak_hit=1
    fi
done
# Sanity: confirm the redaction marker is actually present on secret-emitting records.
redacted_n=0
if [ -f "$FINDINGS" ]; then
    redacted_n=$(jq -r 'select(.value_redacted=="***") | .source' "$FINDINGS" 2>/dev/null | grep -c . || true)
fi
if [ "$leak_hit" -eq 1 ]; then
    printf '    [FAIL] XCUT-07 VIOLATION — a raw unredacted secret reached the artefact/log.\n'
    printf '           This is the #1 correctness requirement. Do NOT sign off. Exiting 3.\n'
    exit 3
fi
printf '    [OK]   no raw secret pattern in findings.jsonl or run.log (XCUT-07 clean)\n'
printf '    [INFO] %s record(s) carry value_redacted="***" (secret-emitting sources redacted)\n' "${redacted_n:-0}"

# ---------------------------------------------------------------------------
# Check 3: category-presence SOFT gate (D-O6). COUNTS NOT GATED.
# Build the v1 OSINT category baseline (the distinct source/category set the v2
# Task registry produces — the structural mirror of v1 modes.sh:657, minus the
# EXCLUDED zonetransfer which is a subdomains-module function, D-O10). Compare to
# the categories actually present in this real run. Absent categories are LOGGED
# as key-gated/best_effort skips, NOT failures.
# ---------------------------------------------------------------------------
printf '\n  category-presence soft gate (D-O6 — counts NOT gated):\n'

# v1 OSINT category baseline (every category the osint module can emit; the
# key-free subset MUST appear, the key-gated subset MAY skip without keys).
# zonetransfer is EXCLUDED (D-O10 — lives in the subs module, NOT a regression).
V1_CATEGORIES="whois dns-ns dns-mx dns-txt dns-soa cidr asn geo email leaked-secret \
repo workflow-secret-exposure cloud-bucket-s3 cloud-bucket-gcp cloud-bucket-azure \
postman-leak swagger-leak spoofable azure-tenant cms cms-favicon graphql-introspection \
custom-wordlist doc-metadata misconfig dork"

if [ "${osint_n:-0}" -gt 0 ]; then
    PRESENT_CATS=$(jq -r 'select(.class=="osint") | .category // empty' "$FINDINGS" 2>/dev/null | sort -u)
    PRESENT_SRCS=$(jq -r 'select(.class=="osint") | .source // empty' "$FINDINGS" 2>/dev/null | sort -u)

    printf '\n  category breakdown (present in this real run):\n'
    jq -r 'select(.class=="osint") | .category // "uncategorized"' "$FINDINGS" 2>/dev/null \
        | sort | uniq -c | sort -rn | sed 's/^/    /'

    printf '\n  source breakdown:\n'
    jq -r 'select(.class=="osint") | .source // "unknown"' "$FINDINGS" 2>/dev/null \
        | sort | uniq -c | sort -rn | sed 's/^/    /'

    printf '\n  v1-baseline category coverage:\n'
    n_present=0
    n_absent=0
    for cat in $V1_CATEGORIES; do
        if printf '%s\n' "$PRESENT_CATS" | grep -qx "$cat"; then
            printf '    [PRESENT] %s\n' "$cat"
            n_present=$((n_present + 1))
        else
            # Absent: log as a (likely key-gated / best_effort) skip — NOT a failure (D-O6/D-O8).
            printf '    [skip]    %s  (absent — key-gated source or 0 results; best_effort, NOT a failure)\n' "$cat"
            n_absent=$((n_absent + 1))
        fi
    done
    printf '\n  [OK]   category-presence soft gate: %s present, %s absent/key-skipped (counts NOT gated, D-O6)\n' \
        "$n_present" "$n_absent"
else
    printf '  [WARN] no osint-class entries to evaluate category presence against\n'
fi

# ---------------------------------------------------------------------------
# Check 4: multi-writer staging contract (mirrors web/vulns smoke).
# ---------------------------------------------------------------------------
printf '\n  staging contract:\n'
if [ "${staging:-0}" -gt 0 ]; then
    printf '    [OK]   %s per-tool staging file(s) — multi-writer contract live\n' "$staging"
    find "$W/inputs" -maxdepth 1 -type f -name 'findings.*.jsonl' 2>/dev/null \
        | sort | while read -r _f; do
        _c=$(grep -c . "$_f" 2>/dev/null | tr -d ' ') || _c=0
        printf '           %-40s %s record(s)\n' "$(basename "$_f")" "${_c:-0}"
    done
else
    printf '    [WARN] no inputs/findings.<tool>.jsonl files (sources found nothing / key-gated / not installed)\n'
fi

# ---------------------------------------------------------------------------
# zonetransfer-exclusion note (D-O10) — printed for the acceptance record.
# ---------------------------------------------------------------------------
printf '\n  note (D-O10): zonetransfer is EXCLUDED from OSINT — it is a subdomains-module\n'
printf '         function (ported in Phase 4). Its absence here is NOT a regression.\n'

printf '\n'
printf 'Total findings: %s  (osint-class: %s)\n' "$findings_n" "${osint_n:-0}"
printf '\nNext step (DoD-2 sign-off): the maintainer reviews findings.jsonl + run.log for\n'
printf '  the XCUT-07 redaction confirmation and category presence, then records the\n'
printf '  result in .planning/phases/07-osint-e2e/07-ACCEPTANCE.md.\n\n'

if [ "$fails" -eq 0 ]; then
    printf 'VERDICT: PASS — osint pipeline ran end-to-end, osint-class findings present,\n'
    printf '  no secret leak (XCUT-07 clean), category-presence soft gate evaluated.\n'
    exit 0
fi
printf 'VERDICT: REVIEW — %s check(s) failed; inspect above.\n' "$fails"
exit 1
