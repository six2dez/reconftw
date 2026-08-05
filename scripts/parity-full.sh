#!/usr/bin/env bash
# scripts/parity-full.sh — OPERATOR-RUN bash-v1 vs Go-v2 CORE-SET parity harness (D-05 / CUT-11).
#
# Generalises scripts/parity-check.sh (WEB-only, per-category COUNTS) to a full
# CORE-SET DIFF across the three sets that matter for a bash→Go cutover sign-off:
#
#     1. subdomain set   v2 artefacts/subdomains.jsonl .subdomain   vs  v1 Recon/<t>/subdomains/subdomains.txt
#     2. live-host set   v2 artefacts/hosts.jsonl .host             vs  v1 Recon/<t>/webs/webs_all.txt (+ subdomains_alive.txt)
#     3. finding classes v2 artefacts/findings.jsonl grouped .class vs  v1 Recon/<t>/nuclei_output/ + vulns/*
#
# Each set is compared as a SET DIFFERENCE (LC_ALL=C sort + comm), emitting
# ADDED (v2-only) and REMOVED (v1-only, i.e. potential regressions) lists — NOT
# field-level per-finding diffs (D-05: per-finding diffing is too noisy).
#
# ─────────────────────────────────────────────────────────────────────────────
# ⚠ OPERATOR-RUN, NEVER WIRED INTO CI.
# ─────────────────────────────────────────────────────────────────────────────
# This harness runs two full recon engines against a live target over the
# network. Its results are inherently nondeterministic (passive-source flux,
# rate limits, DNS timing), so it MUST NOT run in CI — a live/nondeterministic
# assertion would produce flaky failures. It is an operator procedure: run it by
# hand on a proper host, then eyeball + sign off the markdown/JSON report. The
# ONLY parts exercised in CI/offline are `--help` and `--self-check` (which use
# canned fixtures and touch no network). See T-14-04-02 in 14-04-PLAN.md.
#
# ─────────────────────────────────────────────────────────────────────────────
# FROZEN LEGACY CHECKOUT (reproducible A/B baseline — D-05)
# ─────────────────────────────────────────────────────────────────────────────
# bash v1 is driven from a `git worktree` checkout pinned to a versioned ref —
# NOT the working tree and NOT a drifting installed binary — so the baseline is
# reproducible run-to-run:
#
#     git worktree add ../reconftw-v1-baseline "${LEGACY_REF:-v4.1}"
#
# LEGACY_REF defaults to the pinned tag v4.1 (latest v1 release) and is
# overridable so that, post-cutover, it can point at archive/v1.x.
#
# ─────────────────────────────────────────────────────────────────────────────
# NONDETERMINISM EXCLUSION LIST (tolerance = "core sets match within noise")
# ─────────────────────────────────────────────────────────────────────────────
# The following differences are EXPECTED and are EXCLUDED from the pass/fail
# judgement — they are noise, not regressions:
#   • ordering          — sets are sorted before diffing; order never matters.
#   • timestamps        — run times, file mtimes, report generation time.
#   • passive-source variance — crt.sh / other passive sources return a slightly
#                         different set on every run (their own caches churn).
#   • rate-limit counts — httpx/nuclei counts shift with adaptive rate limiting.
#   • screenshot binaries — image bytes differ; never compared.
#   • transient DNS      — a resolver returning SERVFAIL on one run, OK the next.
# Because of these, a NON-EMPTY added/removed list is NOT automatically a FAIL:
# the harness flags REVIEW when the removed-ratio exceeds --tolerance and leaves
# the final call to the operator. Exact set equality is never required.
#
# ─────────────────────────────────────────────────────────────────────────────
# PREREQS & LOCAL-BOX CAVEATS
# ─────────────────────────────────────────────────────────────────────────────
#   • Needs the FULL external toolchain (subfinder/puredns/httpx/nuclei/…) AND a
#     real network host. A dev laptop is not a valid parity host.
#   • This macOS box BLOCKS UDP/53 (MASS-DNS: puredns/massdns/dnsx cannot
#     resolve) → the subdomain-set leg is UNVALIDATABLE locally. Run on a host
#     with working outbound DNS.
#   • Pass `-duc` to ProjectDiscovery tools (httpx/nuclei/…) or they hang on the
#     update-check when run non-interactively (the reconftw v2 binary has no
#     --no-update flag; -duc is applied to the PD tools internally by v2).
#   • Any shell copy inside the harness uses `\cp -f` to dodge the macOS `cp -i`
#     interactive-alias trap (MEMORY: it silently stalls execute-phase).
#
# ─────────────────────────────────────────────────────────────────────────────
# USAGE
# ─────────────────────────────────────────────────────────────────────────────
#   scripts/parity-full.sh --self-check
#       Offline: validate the extraction + set-diff logic on canned fixtures.
#       Touches NO network, NO worktree, NO scan. This is the acceptance gate.
#
#   scripts/parity-full.sh <target> [options]
#       Full operator run: set up the frozen v1 worktree, run v1 + v2 against
#       <target>, diff the three core sets, emit workspaces/<target>/parity-report.{md,json}.
#
#   Options:
#     --legacy-ref REF   frozen v1 git ref for the worktree   (env LEGACY_REF, default v4.1)
#     --baseline-dir DIR path for the v1 worktree checkout     (env BASELINE_DIR, default ../reconftw-v1-baseline)
#     --out DIR          report output dir                     (default workspaces/<target>)
#     --tolerance PCT    removed-ratio REVIEW threshold        (default 10)
#     --compare-only     skip both scans; diff existing v1 Recon/ + latest v2 workspace
#     --self-check       run the offline fixture self-test and exit
#     -h, --help         show this header and exit
#
# Exit codes (parity-check.sh convention): 0 = PASS, 1 = REVIEW, 2 = error.
#
# NOTE: no `set -e` on purpose — grep/comm/jq return non-zero on empty input by
# design; the harness handles those explicitly and decides the verdict itself.
set -uo pipefail

BIN="./bin/reconftw"
TARGET=""
LEGACY_REF="${LEGACY_REF:-v4.1}"
BASELINE_DIR="${BASELINE_DIR:-../reconftw-v1-baseline}"
OUT_DIR=""
TOLERANCE=10
COMPARE_ONLY=0
SELF_CHECK=0

die() {
    printf 'parity-full: %s\n' "$1" >&2
    exit 2
}

usage() {
    # Print the leading comment block only (line 2 until the first non-# line),
    # stripping the leading "# " so --help shows just the documented header.
    awk 'NR==1 {next} /^#/ {sub(/^# ?/,""); print; next} {exit}' "$0"
}

# ── shared extraction / normalisation helpers (generalised from parity-check.sh) ──

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

# extract_v2_field <jsonl> <jq_filter> — sorted-unique values of a JSONL field.
# e.g. extract_v2_field artefacts/subdomains.jsonl '.subdomain // .host'
extract_v2_field() {
    [ -f "$1" ] || return 0
    jq -r "${2} // empty" "$1" 2>/dev/null | sed '/^[[:space:]]*$/d' | LC_ALL=C sort -u
}

# normalize_hosts <file> — strip scheme/port/path, lowercase, sorted-unique.
# Turns v1 URL-shaped lists (https://h:443/x) into bare hostnames for host-set diff.
normalize_hosts() {
    [ -f "$1" ] || return 0
    sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#[:/].*$##' "$1" 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' | sed '/^[[:space:]]*$/d' | LC_ALL=C sort -u
}

# normalize_plain <file> — lowercase, trim, sorted-unique (subdomain lists).
normalize_plain() {
    [ -f "$1" ] || return 0
    tr '[:upper:]' '[:lower:]' <"$1" 2>/dev/null | sed 's/[[:space:]]//g; /^$/d' | LC_ALL=C sort -u
}

# v2_finding_classes <jsonl> — sorted-unique finding labels. Prefers the nuclei
# .template_id (the fine-grained common unit both engines emit) so nuclei findings
# compare like-for-like against v1's template-ids, falling back to vuln_class/class/
# type/severity for non-nuclei findings (xss/osint). Filtering by the coarse .type
# collapsed all 271 nuclei findings to a single "nuclei-finding" class vs v1's 77.
v2_finding_classes() {
    [ -f "$1" ] || return 0
    jq -r '(.template_id // .vuln_class // .class // .type // .severity) // empty' "$1" 2>/dev/null \
        | sed '/^[[:space:]]*$/d' | LC_ALL=C sort -u
}

# json_array_from_file <file> — emit a JSON string array of the file's lines.
json_array_from_file() {
    if [ -s "$1" ]; then
        jq -R -s 'split("\n") | map(select(length > 0))' <"$1"
    else
        printf '[]'
    fi
}

# ── core-set diff: writes ADDED/REMOVED/COMMON temp files, prints a table row ──
# Globals set for the report: DIFF_<n>_{common,added,removed,v1,v2,verdict}
CORE_FAILS=0

core_set_diff() {
    # $1 label  $2 v2set-file(sorted)  $3 v1set-file(sorted)  $4 report-slug
    local label="$1" v2set="$2" v1set="$3" slug="$4"
    local wdir="${5:-.}"
    local common added removed
    local common_f="${wdir}/.parity_${slug}_common"
    local added_f="${wdir}/.parity_${slug}_added"
    local removed_f="${wdir}/.parity_${slug}_removed"

    # comm needs sorted input; both sides are already LC_ALL=C sort -u.
    # comm columns for `comm v2set v1set`: -23 = unique to file1 (v2) ; -13 = unique to file2 (v1).
    comm -12 "$v2set" "$v1set" >"$common_f" 2>/dev/null || true
    comm -23 "$v2set" "$v1set" >"$added_f" 2>/dev/null || true   # v2-only (added)
    comm -13 "$v2set" "$v1set" >"$removed_f" 2>/dev/null || true # v1-only (removed / regression)

    common=$(count_lines "$common_f")
    added=$(count_lines "$added_f")
    removed=$(count_lines "$removed_f")
    local v1total=$((common + removed))
    local v2total=$((common + added))

    local verdict="OK"
    if [ "$v1total" -gt 0 ]; then
        local rratio=$((removed * 100 / v1total))
        if [ "$rratio" -gt "$TOLERANCE" ]; then
            verdict="REVIEW (removed ${rratio}% > ${TOLERANCE}%)"
            CORE_FAILS=$((CORE_FAILS + 1))
        fi
    fi

    printf '  %-14s v2=%-6s v1=%-6s  common=%-6s +added=%-6s -removed=%-6s  %s\n' \
        "$label" "$v2total" "$v1total" "$common" "$added" "$removed" "$verdict"

    # publish for the report emitter
    printf '%s' "$common_f" >"${wdir}/.parity_${slug}_common_f"
    printf '%s' "$added_f" >"${wdir}/.parity_${slug}_added_f"
    printf '%s' "$removed_f" >"${wdir}/.parity_${slug}_removed_f"
    eval "DIFF_${slug}_common=${common}"
    eval "DIFF_${slug}_added=${added}"
    eval "DIFF_${slug}_removed=${removed}"
    eval "DIFF_${slug}_v1=${v1total}"
    eval "DIFF_${slug}_v2=${v2total}"
    eval "DIFF_${slug}_verdict=\"${verdict}\""
}

# ── report emitters (markdown + JSON, for operator sign-off) ──

emit_markdown() {
    # $1 out.md  $2 target  $3 workdir(for the temp diff files)  $4 v2ws  $5 v1dir
    local md="$1" target="$2" wdir="$3" v2ws="$4" v1dir="$5"
    local verdict_word="PASS"
    [ "$CORE_FAILS" -gt 0 ] && verdict_word="REVIEW"
    {
        printf '# Parity report — %s\n\n' "$target"
        printf -- '- Generated : %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
        printf -- '- v2 workspace : `%s`\n' "$v2ws"
        printf -- '- v1 reference : `%s`  (frozen ref `%s`)\n' "$v1dir" "$LEGACY_REF"
        printf -- '- Tolerance : removed-ratio ≤ %s%% per core set\n' "$TOLERANCE"
        printf -- '- Machine verdict : **%s**  (added/removed are noise-tolerant — see exclusion list)\n\n' "$verdict_word"
        printf '## Core-set summary\n\n'
        printf '| core set | v2 | v1 | common | +added (v2-only) | -removed (v1-only) | verdict |\n'
        printf '|---|--:|--:|--:|--:|--:|---|\n'
        local slug label
        for pair in "subdomains:subdomain set" "hosts:live-host set" "findings:finding classes"; do
            slug="${pair%%:*}"
            label="${pair#*:}"
            printf '| %s | %s | %s | %s | %s | %s | %s |\n' "$label" \
                "$(eval "echo \${DIFF_${slug}_v2:-0}")" "$(eval "echo \${DIFF_${slug}_v1:-0}")" \
                "$(eval "echo \${DIFF_${slug}_common:-0}")" "$(eval "echo \${DIFF_${slug}_added:-0}")" \
                "$(eval "echo \${DIFF_${slug}_removed:-0}")" "$(eval "echo \${DIFF_${slug}_verdict:-OK}")"
        done
        printf '\n## Removed items (v1 had, v2 missing — review first)\n\n'
        for slug in subdomains hosts findings; do
            printf '### %s\n\n```\n' "$slug"
            local rf="${wdir}/.parity_${slug}_removed"
            if [ -s "$rf" ]; then head -50 "$rf"; else printf '(none)\n'; fi
            printf '```\n\n'
        done
        printf '## Added items (v2 has, v1 did not)\n\n'
        for slug in subdomains hosts findings; do
            printf '### %s\n\n```\n' "$slug"
            local af="${wdir}/.parity_${slug}_added"
            if [ -s "$af" ]; then head -50 "$af"; else printf '(none)\n'; fi
            printf '```\n\n'
        done
        printf '## Operator sign-off (fill in on the live host)\n\n'
        printf -- '- [ ] Reviewed removed lists; confirmed each is nondeterminism (see exclusion list), not a regression\n'
        printf -- '- [ ] Lab target result : __________________________  (TODO: paste verdict)\n'
        printf -- '- [ ] Canonical target(s) result : _______________  (TODO: 2-3 public, best-effort)\n'
        printf -- '- [ ] Signed off by : __________  date : __________\n'
    } >"$md"
}

emit_json() {
    # $1 out.json  $2 target  $3 workdir  $4 v2ws  $5 v1dir
    local js="$1" target="$2" wdir="$3" v2ws="$4" v1dir="$5"
    local verdict_word="PASS"
    [ "$CORE_FAILS" -gt 0 ] && verdict_word="REVIEW"
    jq -n \
        --arg target "$target" \
        --arg generated "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --arg v2ws "$v2ws" --arg v1dir "$v1dir" --arg ref "$LEGACY_REF" \
        --argjson tol "$TOLERANCE" --arg verdict "$verdict_word" \
        --argjson sub_added "$(json_array_from_file "${wdir}/.parity_subdomains_added")" \
        --argjson sub_removed "$(json_array_from_file "${wdir}/.parity_subdomains_removed")" \
        --argjson host_added "$(json_array_from_file "${wdir}/.parity_hosts_added")" \
        --argjson host_removed "$(json_array_from_file "${wdir}/.parity_hosts_removed")" \
        --argjson find_added "$(json_array_from_file "${wdir}/.parity_findings_added")" \
        --argjson find_removed "$(json_array_from_file "${wdir}/.parity_findings_removed")" \
        '{
          target: $target, generated: $generated, verdict: $verdict,
          v2_workspace: $v2ws, v1_reference: $v1dir, legacy_ref: $ref,
          tolerance_pct: $tol,
          core_sets: {
            subdomains: { added: $sub_added,  removed: $sub_removed },
            hosts:      { added: $host_added, removed: $host_removed },
            findings:   { added: $find_added, removed: $find_removed }
          },
          operator_signoff: {
            lab_target_result: "TODO",
            canonical_targets_result: "TODO",
            signed_off_by: "TODO", date: "TODO"
          }
        }' >"$js"
}

# ── OFFLINE self-check: exercise the real extraction + diff logic on fixtures ──
self_check() {
    command -v jq >/dev/null 2>&1 || die "jq not found on PATH (required for --self-check)"
    local tmp
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/parity-selfcheck.XXXXXX") || die "mktemp failed"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT

    mkdir -p "$tmp/ws/artefacts" "$tmp/v1/subdomains" "$tmp/v1/webs"

    # v2 canned artefacts (JSONL) — note deliberate a/b/c/d and mixed class fields.
    printf '%s\n' \
        '{"subdomain":"a.t.com"}' '{"subdomain":"b.t.com"}' \
        '{"subdomain":"c.t.com"}' '{"subdomain":"d.t.com"}' >"$tmp/ws/artefacts/subdomains.jsonl"
    printf '%s\n' \
        '{"host":"a.t.com","ip":"1.1.1.1"}' '{"host":"b.t.com","ip":"1.1.1.2"}' \
        '{"host":"c.t.com","ip":"1.1.1.3"}' >"$tmp/ws/artefacts/hosts.jsonl"
    printf '%s\n' \
        '{"class":"exposure"}' '{"vuln_class":"xss"}' '{"severity":"high","type":"cve"}' \
        >"$tmp/ws/artefacts/findings.jsonl"

    # v1 canned reference (bash .txt shapes). Note: e is v1-only, d is v2-only.
    printf '%s\n' 'a.t.com' 'B.t.com' 'c.t.com' 'e.t.com' >"$tmp/v1/subdomains/subdomains.txt"
    printf '%s\n' 'https://a.t.com/' 'https://b.t.com:443/x' 'http://c.t.com' >"$tmp/v1/webs/webs_all.txt"
    mkdir -p "$tmp/v1/nuclei_output"
    printf '%s\n' 'exposure' 'xss' >"$tmp/v1/.v1classes" # v1 class labels (cve is v2-only)

    local v2sub v1sub v2host v1host v2find
    v2sub="$tmp/v2sub"
    v1sub="$tmp/v1sub"
    v2host="$tmp/v2host"
    v1host="$tmp/v1host"
    v2find="$tmp/v2find"
    local v1find="$tmp/v1find"
    extract_v2_field "$tmp/ws/artefacts/subdomains.jsonl" '.subdomain // .host' >"$v2sub"
    normalize_plain "$tmp/v1/subdomains/subdomains.txt" >"$v1sub"
    extract_v2_field "$tmp/ws/artefacts/hosts.jsonl" '.host' >"$v2host"
    normalize_hosts "$tmp/v1/webs/webs_all.txt" >"$v1host"
    v2_finding_classes "$tmp/ws/artefacts/findings.jsonl" >"$v2find"
    normalize_plain "$tmp/v1/.v1classes" >"$v1find"

    echo "== self-check: core-set diff on canned fixtures (no network) =="
    CORE_FAILS=0
    core_set_diff "subdomain set" "$v2sub" "$v1sub" "subdomains" "$tmp"
    core_set_diff "live-host set" "$v2host" "$v1host" "hosts" "$tmp"
    core_set_diff "finding class" "$v2find" "$v1find" "findings" "$tmp"

    local fail=0
    assert_eq() { # $1 desc $2 got $3 want
        if [ "$2" = "$3" ]; then
            printf '  ok   %s (=%s)\n' "$1" "$3"
        else
            printf '  FAIL %s: got %s want %s\n' "$1" "$2" "$3" >&2
            fail=1
        fi
    }
    # subdomains: common a,b,c=3 ; added d=1 ; removed e=1
    assert_eq "subdomains.common" "$DIFF_subdomains_common" 3
    assert_eq "subdomains.added" "$DIFF_subdomains_added" 1
    assert_eq "subdomains.removed" "$DIFF_subdomains_removed" 1
    assert_eq "subdomains.added==d.t.com" "$(cat "$tmp/.parity_subdomains_added")" "d.t.com"
    assert_eq "subdomains.removed==e.t.com" "$(cat "$tmp/.parity_subdomains_removed")" "e.t.com"
    # hosts: v2 {a,b,c} vs v1 {a,b,c} → common 3, none added/removed (scheme/port stripped)
    assert_eq "hosts.common" "$DIFF_hosts_common" 3
    assert_eq "hosts.added" "$DIFF_hosts_added" 0
    assert_eq "hosts.removed" "$DIFF_hosts_removed" 0
    # findings: v2 classes {exposure,xss,cve} vs v1 {exposure,xss} → added cve, removed 0
    assert_eq "findings.added" "$DIFF_findings_added" 1
    assert_eq "findings.removed" "$DIFF_findings_removed" 0
    assert_eq "findings.added==cve" "$(cat "$tmp/.parity_findings_added")" "cve"

    # exercise the report emitters too (they must produce valid md + JSON offline)
    emit_markdown "$tmp/parity-report.md" "selfcheck.t.com" "$tmp" "$tmp/ws" "$tmp/v1"
    emit_json "$tmp/parity-report.json" "selfcheck.t.com" "$tmp" "$tmp/ws" "$tmp/v1"
    if jq -e . "$tmp/parity-report.json" >/dev/null 2>&1; then
        printf '  ok   parity-report.json is valid JSON\n'
    else
        printf '  FAIL parity-report.json is not valid JSON\n' >&2
        fail=1
    fi
    [ -s "$tmp/parity-report.md" ] && printf '  ok   parity-report.md emitted (%s bytes)\n' "$(wc -c <"$tmp/parity-report.md" | tr -d ' ')"

    echo
    if [ "$fail" -eq 0 ]; then
        echo "SELF-CHECK: PASS — extraction + set-diff + report logic correct offline."
        return 0
    fi
    echo "SELF-CHECK: FAIL — diff logic mismatch (see above)." >&2
    return 1
}

# ── argument parse ──
while [ $# -gt 0 ]; do
    case "$1" in
        --self-check) SELF_CHECK=1 ;;
        --compare-only) COMPARE_ONLY=1 ;;
        --legacy-ref)
            shift
            LEGACY_REF="${1:-}"
            ;;
        --baseline-dir)
            shift
            BASELINE_DIR="${1:-}"
            ;;
        --out)
            shift
            OUT_DIR="${1:-}"
            ;;
        --tolerance)
            shift
            TOLERANCE="${1:-10}"
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        -*) die "unknown flag: $1" ;;
        *) TARGET="$1" ;;
    esac
    shift
done

if [ "$SELF_CHECK" -eq 1 ]; then
    self_check
    exit $?
fi

[ -n "$TARGET" ] || die "usage: scripts/parity-full.sh <target> [--legacy-ref REF] [--compare-only] | --self-check | --help"
command -v jq >/dev/null 2>&1 || die "jq not found on PATH"
command -v git >/dev/null 2>&1 || die "git not found on PATH"

V1DIR="${BASELINE_DIR%/}/Recon/${TARGET}"

# ── set up the frozen legacy checkout (D-05) and run bash v1 ──
if [ "$COMPARE_ONLY" -eq 0 ]; then
    [ -x "$BIN" ] || die "$BIN not found — run: make build"
    if [ ! -d "${BASELINE_DIR}/.git" ] && [ ! -f "${BASELINE_DIR}/reconftw.sh" ]; then
        printf '== frozen v1 worktree: git worktree add %s %s ==\n' "$BASELINE_DIR" "$LEGACY_REF"
        git worktree add "$BASELINE_DIR" "$LEGACY_REF" \
            || die "git worktree add failed — is '$LEGACY_REF' a valid ref? (default pin: v4.1)"
    else
        printf '== reusing existing v1 baseline checkout at %s (ref pin: %s) ==\n' "$BASELINE_DIR" "$LEGACY_REF"
    fi

    printf '== v1 (bash, frozen %s) run against %s ==\n' "$LEGACY_REF" "$TARGET"
    printf '   (needs full toolchain + working UDP/53; pass -duc equivalents where prompted)\n'
    (cd "$BASELINE_DIR" && ./reconftw.sh -d "$TARGET" -r) || die "v1 baseline run failed"

    printf '== v2 (Go) run against %s ==\n' "$TARGET"
    "$BIN" recon --target "$TARGET" || die "v2 run failed"
fi

# ── locate the two output trees ──
W=$(ls -dt "workspaces/${TARGET}"-*/ "workspaces/${TARGET}/" 2>/dev/null | head -1)
[ -n "$W" ] || die "no v2 workspace under workspaces/${TARGET}-*/ — run without --compare-only"
W="${W%/}"
[ -d "$V1DIR" ] || die "v1 reference dir missing: $V1DIR — run the harness without --compare-only, or point --baseline-dir at a completed v1 Recon parent"

OUT_DIR="${OUT_DIR:-$W}"
mkdir -p "$OUT_DIR"

# ── extract the three v2/v1 core sets ──
WORK=$(mktemp -d "${TMPDIR:-/tmp}/parity-full.XXXXXX") || die "mktemp failed"
# shellcheck disable=SC2064
trap "rm -rf '$WORK'" EXIT

extract_v2_field "$W/artefacts/subdomains.jsonl" '.subdomain // .host' >"$WORK/v2_sub"
normalize_plain "$V1DIR/subdomains/subdomains.txt" >"$WORK/v1_sub"

extract_v2_field "$W/artefacts/hosts.jsonl" '.host' >"$WORK/v2_host"
{
    normalize_hosts "$V1DIR/webs/webs_all.txt"
    normalize_plain "$V1DIR/subdomains/subdomains_alive.txt"
} \
    | LC_ALL=C sort -u >"$WORK/v1_host"

v2_finding_classes "$W/artefacts/findings.jsonl" >"$WORK/v2_find"
# v1 finding-class proxy: nuclei template ids + vulns/* basenames, class-ish tokens.
{
    find "$V1DIR/nuclei_output" -type f -name '*_json.txt' -exec cat {} + 2>/dev/null \
        | jq -r '.["template-id"]? // .info.tags[]? // empty' 2>/dev/null
    find "$V1DIR/vulns" -type f 2>/dev/null | sed -E 's#.*/##; s/\.[a-z]+$//'
} | sed '/^[[:space:]]*$/d' | LC_ALL=C sort -u >"$WORK/v1_find"

# ── diff + report ──
printf '\n===== CORE-SET PARITY: %s =====\n' "$TARGET"
printf 'v2 workspace : %s\n' "$W"
printf 'v1 reference : %s  (frozen %s)\n' "$V1DIR" "$LEGACY_REF"
printf 'tolerance    : removed-ratio ≤ %s%%  (noise-excluded — see header)\n\n' "$TOLERANCE"

CORE_FAILS=0
core_set_diff "subdomain set" "$WORK/v2_sub" "$WORK/v1_sub" "subdomains" "$WORK"
core_set_diff "live-host set" "$WORK/v2_host" "$WORK/v1_host" "hosts" "$WORK"
core_set_diff "finding class" "$WORK/v2_find" "$WORK/v1_find" "findings" "$WORK"

# anchored scope check on the v2 host set (reused idiom from parity-check.sh)
esc="${TARGET//./\\.}"
oos=$(extract_v2_field "$W/artefacts/hosts.jsonl" '.host' | grep -vE "(^|\.)${esc}\$" || true)
printf '\nscope (out-of-scope v2 hosts, want none):\n'
if [ -n "$oos" ]; then
    printf '%s\n' "$oos" | sed 's/^/  OOS: /'
    CORE_FAILS=$((CORE_FAILS + 1))
else
    printf '  OK — all v2 hosts in scope\n'
fi

emit_markdown "$OUT_DIR/parity-report.md" "$TARGET" "$WORK" "$W" "$V1DIR"
emit_json "$OUT_DIR/parity-report.json" "$TARGET" "$WORK" "$W" "$V1DIR"
printf '\nreports written:\n  %s\n  %s\n' "$OUT_DIR/parity-report.md" "$OUT_DIR/parity-report.json"

printf '\n'
if [ "$CORE_FAILS" -eq 0 ]; then
    printf 'VERDICT: PASS — core sets within ±%s%% removed-ratio, scope clean. Operator sign-off still required.\n' "$TOLERANCE"
    exit 0
fi
printf 'VERDICT: REVIEW — %s core set(s)/scope flagged; inspect the report before sign-off.\n' "$CORE_FAILS"
exit 1
