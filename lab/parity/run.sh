#!/usr/bin/env bash
# lab/parity/run.sh — offline parity lab driver: v2 (Go) [and v1 (bash)] vs ground truth.
#
# Brings up the lab (CoreDNS for the fake zone lab.test + a deterministic httpd,
# both on 127.0.0.1), waits for health, runs reconFTW v2 against lab.test, runs
# v1 too when --with-v1 is given, then diffs the three core sets exactly the way
# scripts/parity-full.sh does (LC_ALL=C sort + comm, removed-ratio vs tolerance):
#
#     1. subdomain set   v2 artefacts/subdomains.jsonl .subdomain   | v1 subdomains/subdomains.txt
#     2. live-host set   v2 artefacts/hosts.jsonl .host             | v1 webs/webs_all.txt (+subdomains_alive.txt)
#     3. finding classes v2 artefacts/findings.jsonl .template_id   | v1 nuclei_output/*_json.txt .template-id
#
# Unlike parity-full.sh the lab has a GROUND TRUTH (expected/*.txt), so v2 can be
# judged on its own: every set is compared against expected/, and against v1
# when v1 ran. Verdict words and semantics are parity-full's (OK / REVIEW /
# NO-BASELINE / EMPTY-BOTH), with the lab-specific additions:
#   • wildcard leak  — any expected/wildcard_only.txt name in a subdomain set = FAIL
#   • bonus tier     — expected/subdomains_bonus.txt (crawl-only names) is excluded
#                      from the v2-vs-v1 diff and never required (documented noise)
#   • apex           — lab.test itself is excluded from every set
# Default tolerance is 0%: the lab is deterministic, so a missing item is a defect,
# not noise. --tolerance raises it when you are deliberately comparing engines
# with different stage compositions.
#
# Usage:
#   lab/parity/run.sh [options]
#     --with-v1            also run bash v1 (./reconftw.sh -d lab.test -r -f <overlay>)
#     --mode recon|all     v2 subcommand (and v1 -r / -a); default recon
#     --tolerance PCT      removed-ratio threshold per set; default 0
#     --compare-only       skip the lab and the scans; diff what is on disk
#     --skip-up            lab already running: do not `docker compose up`
#     --keep-up            leave the containers running at exit
#     --render-only        render out/lab.generated.toml + out/v1-overlay.generated.cfg,
#                          validate the TOML with `reconftw config show`, exit (no docker)
#     --v2-bin PATH        use a prebuilt binary instead of `go run ./cmd/reconftw`
#     --allow-no-system-dns  continue even if the OS resolver cannot resolve *.lab.test
#     -h, --help           this header
#
# Prereqs: docker (compose v2), go, jq, dig (or host), curl; the recon tools on
# PATH (`go run ./cmd/reconftw install --profile core` + tlsx csprecon katana ffuf);
# and the OS resolver pointed at the lab DNS for lab.test — see system-dns.sh.
#
# Output: lab/parity/out/REPORT.md, out/report.json, out/v2.log[, out/v1.log],
# out/workspaces/<slug>/ (v2). v1 writes to Recon/lab.test/ at the repo root as
# always; a pre-existing tree is MOVED to out/.archive/ first, never deleted.
#
# Exit: 0 = PASS (every gated set OK, no wildcard leak, scope clean); 1 = FAIL;
# 2 = usage/environment error.
#
# NOTE: no `set -e` on purpose (same reason as scripts/parity-*.sh): grep/comm/jq
# return non-zero on empty input by design; the verdict is decided explicitly.
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$LAB_DIR/../.." && pwd)"
OUT="$LAB_DIR/out"
TARGET="lab.test"
COMPOSE=(docker compose -f "$LAB_DIR/docker-compose.yml")

WITH_V1=0
MODE="recon"
TOLERANCE=0
COMPARE_ONLY=0
SKIP_UP=0
KEEP_UP=0
RENDER_ONLY=0
V2_BIN=""
ALLOW_NO_SYSDNS=0

die() {
    printf 'parity-lab: %s\n' "$1" >&2
    exit 2
}
log() { printf '[lab] %s\n' "$*"; }

usage() { awk 'NR==1 {next} /^#/ {sub(/^# ?/,""); print; next} {exit}' "$0"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --with-v1) WITH_V1=1 ;;
        --mode)
            shift
            MODE="${1:-recon}"
            ;;
        --tolerance)
            shift
            TOLERANCE="${1:-0}"
            ;;
        --compare-only) COMPARE_ONLY=1 ;;
        --skip-up) SKIP_UP=1 ;;
        --keep-up) KEEP_UP=1 ;;
        --render-only) RENDER_ONLY=1 ;;
        --v2-bin)
            shift
            V2_BIN="${1:-}"
            ;;
        --allow-no-system-dns) ALLOW_NO_SYSDNS=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
    shift
done

case "$MODE" in recon | all) ;; *) die "--mode must be recon or all" ;; esac
case "$TOLERANCE" in '' | *[!0-9]*) die "--tolerance must be an integer percentage" ;; esac

mkdir -p "$OUT"

# ── helpers (ported from scripts/parity-full.sh so the semantics stay identical) ──

count_lines() {
    [ -f "$1" ] || {
        echo 0
        return
    }
    local n
    n=$(grep -c . "$1" 2>/dev/null) || true
    echo "${n:-0}"
}

# strip_comments <file> — expected/*.txt without comments/blanks, lowercase, sorted-unique.
strip_comments() {
    [ -f "$1" ] || return 0
    sed 's/#.*//; s/[[:space:]]//g; /^$/d' "$1" | tr '[:upper:]' '[:lower:]' | LC_ALL=C sort -u
}

extract_v2_field() {
    [ -f "$1" ] || return 0
    jq -r "${2} // empty" "$1" 2>/dev/null | sed '/^[[:space:]]*$/d' | LC_ALL=C sort -u
}

normalize_hosts() {
    [ -f "$1" ] || return 0
    sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#[:/].*$##' "$1" 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' | sed '/^[[:space:]]*$/d' | LC_ALL=C sort -u
}

normalize_plain() {
    [ -f "$1" ] || return 0
    tr '[:upper:]' '[:lower:]' <"$1" 2>/dev/null | sed 's/[[:space:]]//g; /^$/d' | LC_ALL=C sort -u
}

v2_finding_classes() {
    [ -f "$1" ] || return 0
    jq -r '(.template_id // .vuln_class // .class // .type // .severity) // empty' "$1" 2>/dev/null \
        | sed '/^[[:space:]]*$/d' | LC_ALL=C sort -u
}

# drop_names <names-file> — filter stdin, removing every line present in names-file.
drop_names() {
    if [ -s "$1" ]; then grep -vxF -f "$1"; else cat; fi
}

json_array_from_file() {
    if [ -s "$1" ]; then
        jq -R -s 'split("\n") | map(select(length > 0))' <"$1"
    else
        printf '[]'
    fi
}

# core_set_diff <label> <left-set> <right-set> <slug> — parity-full's diff, verbatim
# semantics: left = candidate (v2 or v1), right = reference (expected or v1).
# "removed" = reference-only (the regression side). Sets CORE_FAILS, DIFF_<slug>_*.
CORE_FAILS=0
core_set_diff() {
    local label="$1" lset="$2" rset="$3" slug="$4"
    local common_f="$WORK/.d_${slug}_common" added_f="$WORK/.d_${slug}_added" removed_f="$WORK/.d_${slug}_removed"
    comm -12 "$lset" "$rset" >"$common_f" 2>/dev/null || true
    comm -23 "$lset" "$rset" >"$added_f" 2>/dev/null || true
    comm -13 "$lset" "$rset" >"$removed_f" 2>/dev/null || true
    local common added removed
    common=$(count_lines "$common_f")
    added=$(count_lines "$added_f")
    removed=$(count_lines "$removed_f")
    local rtotal=$((common + removed)) ltotal=$((common + added))
    local verdict="OK"
    if [ "$rtotal" -eq 0 ]; then
        if [ "$ltotal" -gt 0 ]; then verdict="NO-BASELINE (reference empty, candidate has ${ltotal})"; else verdict="EMPTY-BOTH"; fi
        CORE_FAILS=$((CORE_FAILS + 1))
    else
        local rratio=$((removed * 100 / rtotal))
        if [ "$rratio" -gt "$TOLERANCE" ]; then
            verdict="FAIL (removed ${rratio}% > ${TOLERANCE}%)"
            CORE_FAILS=$((CORE_FAILS + 1))
        fi
    fi
    printf '  %-26s cand=%-5s ref=%-5s common=%-5s +added=%-5s -removed=%-5s %s\n' \
        "$label" "$ltotal" "$rtotal" "$common" "$added" "$removed" "$verdict"
    eval "DIFF_${slug}_common=${common}; DIFF_${slug}_added=${added}; DIFF_${slug}_removed=${removed}"
    eval "DIFF_${slug}_l=${ltotal}; DIFF_${slug}_r=${rtotal}; DIFF_${slug}_verdict=\"${verdict}\""
    ROWS+=("${slug}|${label}")
}

# ── environment ──────────────────────────────────────────────────────────────

need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found on PATH"; }

# system_resolves <name> — does the OS resolver (what httpx/nuclei/katana use)
# resolve the name? Tries getent (Linux), dscacheutil (macOS), python3.
system_resolves() {
    local name="$1"
    if command -v getent >/dev/null 2>&1; then
        getent hosts "$name" >/dev/null 2>&1 && return 0
    fi
    if command -v dscacheutil >/dev/null 2>&1; then
        dscacheutil -q host -a name "$name" 2>/dev/null | grep -q 'ip_address' && return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -I -c 'import socket,sys; socket.gethostbyname(sys.argv[1])' "$name" >/dev/null 2>&1 && return 0
    fi
    return 1
}

lab_dns_answers() {
    if command -v dig >/dev/null 2>&1; then
        dig +short +time=2 +tries=1 @127.0.0.1 "www.${TARGET}" A 2>/dev/null | grep -q '^127\.0\.0\.1$'
    elif command -v host >/dev/null 2>&1; then
        host -W 2 "www.${TARGET}" 127.0.0.1 2>/dev/null | grep -q '127\.0\.0\.1'
    else
        die "need dig or host to probe the lab DNS"
    fi
}

lab_http_answers() {
    curl -fsS -m 3 -H "Host: www.${TARGET}" "http://127.0.0.1/healthz" 2>/dev/null | grep -q '^ok$'
}

wait_for_lab() {
    local i
    for i in $(seq 1 30); do
        if lab_dns_answers && lab_http_answers; then
            log "lab healthy (dns + http) after ${i} probe(s)"
            return 0
        fi
        sleep 2
    done
    die "lab did not become healthy in 60s — docker compose logs: ${COMPOSE[*]} logs"
}

render_templates() {
    sed "s#@LAB_DIR@#${LAB_DIR}#g" "$LAB_DIR/lab.toml" >"$OUT/lab.generated.toml"
    sed "s#@LAB_DIR@#${LAB_DIR}#g" "$LAB_DIR/v1-overlay.cfg" >"$OUT/v1-overlay.generated.cfg"
    strip_comments "$LAB_DIR/expected/seed.txt" >"$OUT/seed.txt"
    log "rendered $OUT/lab.generated.toml, $OUT/v1-overlay.generated.cfg, $OUT/seed.txt"
}

v2_cmd() {
    if [ -n "$V2_BIN" ]; then
        printf '%s\n' "$V2_BIN"
    else
        printf 'go run ./cmd/reconftw\n'
    fi
}

validate_v2_config() {
    # `config show` loads the full 8-source chain with the rendered file as layer
    # 5 and runs the validators — the cheapest proof the TOML is well-formed.
    log "validating lab.generated.toml via: $(v2_cmd) config show --config …"
    (cd "$REPO" && $(v2_cmd) config show --config "$OUT/lab.generated.toml" >"$OUT/config.effective.toml" 2>"$OUT/config.validate.log") \
        || die "lab.generated.toml rejected by the v2 loader — see $OUT/config.validate.log"
    grep -q "resolvers.*${LAB_DIR}/resolvers.txt" "$OUT/config.effective.toml" \
        || die "effective config does not point resolvers at the lab file — see $OUT/config.effective.toml"
    log "effective config written to $OUT/config.effective.toml"
}

# archive_dir <dir> <label> — MOVE (never delete) a previous tree aside.
archive_dir() {
    [ -e "$1" ] || return 0
    local dest
    dest="$OUT/.archive/$(date -u +'%Y%m%dT%H%M%SZ')"
    mkdir -p "$dest" || die "cannot create $dest"
    mv "$1" "$dest/$2" || die "cannot archive $1 (a live run holding it?)"
    log "archived previous $2 -> $dest/$2"
}

# ── v2 ──────────────────────────────────────────────────────────────────────

# v2 workspace slug = readableSlug(canonical) + "-" + sha256("domain\0" + canonical)[:8]
# (internal/core/output/identity.go targetSlug). Computed here so the passive
# seed can be planted BEFORE boot; WorkspaceInit's MkdirAll tolerates the dir.
v2_slug() {
    local h
    h=$(printf 'domain\0%s' "$TARGET" | shasum -a 256 | cut -c1-8)
    printf '%s-%s\n' "$TARGET" "$h"
}

V2_WS="$OUT/workspaces/$(v2_slug)"

run_v2() {
    archive_dir "$V2_WS" "v2-workspace"
    mkdir -p "$V2_WS/inputs"
    cp "$OUT/seed.txt" "$V2_WS/inputs/passive.labseed.txt"
    log "v2 seed planted: $V2_WS/inputs/passive.labseed.txt ($(count_lines "$OUT/seed.txt") names)"
    log "v2: $(v2_cmd) $MODE --target $TARGET --config $OUT/lab.generated.toml -o $OUT/workspaces"
    local t0 t1 rc
    t0=$(date +%s)
    (cd "$REPO" && $(v2_cmd) "$MODE" --target "$TARGET" --config "$OUT/lab.generated.toml" -o "$OUT/workspaces" --no-color) \
        >"$OUT/v2.log" 2>&1
    rc=$?
    t1=$(date +%s)
    V2_RC=$rc
    V2_SECS=$((t1 - t0))
    log "v2 finished rc=$rc in ${V2_SECS}s (log: $OUT/v2.log)"
    [ -d "$V2_WS/artefacts" ] || die "v2 workspace has no artefacts/ at $V2_WS — see $OUT/v2.log"
}

# ── v1 ──────────────────────────────────────────────────────────────────────

V1_DIR="$REPO/Recon/$TARGET"

run_v1() {
    [ -x "$REPO/reconftw.sh" ] || die "v1 entry point $REPO/reconftw.sh not executable"
    archive_dir "$V1_DIR" "v1-Recon-$TARGET"
    mkdir -p "$V1_DIR/.tmp"
    # sub_active merges .tmp/*_subs.txt (modules/subdomains.sh) — the seed lands there.
    cp "$OUT/seed.txt" "$V1_DIR/.tmp/labseed_subs.txt"
    local flag="-r"
    [ "$MODE" = "all" ] && flag="-a"
    log "v1: ./reconftw.sh -d $TARGET $flag -f $OUT/v1-overlay.generated.cfg"
    local t0 t1 rc
    t0=$(date +%s)
    (cd "$REPO" && ./reconftw.sh -d "$TARGET" "$flag" -f "$OUT/v1-overlay.generated.cfg" --no-color --quiet) \
        >"$OUT/v1.log" 2>&1
    rc=$?
    t1=$(date +%s)
    V1_RC=$rc
    V1_SECS=$((t1 - t0))
    log "v1 finished rc=$rc in ${V1_SECS}s (log: $OUT/v1.log)"
    [ -d "$V1_DIR/subdomains" ] || die "v1 produced no $V1_DIR/subdomains — see $OUT/v1.log"
}

# ── compare ─────────────────────────────────────────────────────────────────

WORK=""
ROWS=()
V2_RC="${V2_RC:-n/a}"
V2_SECS="${V2_SECS:-0}"
V1_RC="${V1_RC:-n/a}"
V1_SECS="${V1_SECS:-0}"

compare() {
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/parity-lab.XXXXXX") || die "mktemp failed"
    # shellcheck disable=SC2064
    trap "rm -rf '$WORK'" RETURN

    printf '%s\n' "$TARGET" >"$WORK/apex"
    strip_comments "$LAB_DIR/expected/subdomains.txt" >"$WORK/exp_sub"
    strip_comments "$LAB_DIR/expected/subdomains_bonus.txt" >"$WORK/exp_bonus"
    strip_comments "$LAB_DIR/expected/wildcard_only.txt" >"$WORK/exp_wild"
    strip_comments "$LAB_DIR/expected/hosts.txt" >"$WORK/exp_host"
    strip_comments "$LAB_DIR/expected/findings.txt" >"$WORK/exp_find"

    extract_v2_field "$V2_WS/artefacts/subdomains.jsonl" '.subdomain // .host' | drop_names "$WORK/apex" >"$WORK/v2_sub"
    extract_v2_field "$V2_WS/artefacts/hosts.jsonl" '.host' | drop_names "$WORK/apex" >"$WORK/v2_host"
    v2_finding_classes "$V2_WS/artefacts/findings.jsonl" >"$WORK/v2_find"

    local have_v1=0
    if [ -d "$V1_DIR/subdomains" ]; then
        have_v1=1
        normalize_plain "$V1_DIR/subdomains/subdomains.txt" | drop_names "$WORK/apex" >"$WORK/v1_sub"
        {
            normalize_hosts "$V1_DIR/webs/webs_all.txt"
            normalize_plain "$V1_DIR/subdomains/subdomains_alive.txt"
        } | LC_ALL=C sort -u | drop_names "$WORK/apex" >"$WORK/v1_host"
        find "$V1_DIR/nuclei_output" -type f -name '*_json.txt' -exec cat {} + 2>/dev/null \
            | jq -r '.["template-id"]? // empty' 2>/dev/null | sed '/^[[:space:]]*$/d' | LC_ALL=C sort -u >"$WORK/v1_find"
    fi

    printf '\n===== PARITY LAB: %s  (mode=%s, tolerance=%s%%) =====\n' "$TARGET" "$MODE" "$TOLERANCE"
    printf 'v2 workspace : %s\n' "$V2_WS"
    [ "$have_v1" -eq 1 ] && printf 'v1 reference : %s\n' "$V1_DIR"
    printf '\n-- v2 vs ground truth (expected/) --\n'
    core_set_diff "subdomains v2/expected" "$WORK/v2_sub" "$WORK/exp_sub" "v2x_sub"
    core_set_diff "hosts      v2/expected" "$WORK/v2_host" "$WORK/exp_host" "v2x_host"
    core_set_diff "findings   v2/expected" "$WORK/v2_find" "$WORK/exp_find" "v2x_find"

    if [ "$have_v1" -eq 1 ]; then
        printf '\n-- v1 vs ground truth (expected/) --\n'
        core_set_diff "subdomains v1/expected" "$WORK/v1_sub" "$WORK/exp_sub" "v1x_sub"
        core_set_diff "hosts      v1/expected" "$WORK/v1_host" "$WORK/exp_host" "v1x_host"
        core_set_diff "findings   v1/expected" "$WORK/v1_find" "$WORK/exp_find" "v1x_find"
        printf '\n-- v2 vs v1 (bonus/crawl-only tier excluded from both sides) --\n'
        drop_names "$WORK/exp_bonus" <"$WORK/v2_sub" >"$WORK/v2_sub_nb"
        drop_names "$WORK/exp_bonus" <"$WORK/v1_sub" >"$WORK/v1_sub_nb"
        drop_names "$WORK/exp_bonus" <"$WORK/v2_host" >"$WORK/v2_host_nb"
        drop_names "$WORK/exp_bonus" <"$WORK/v1_host" >"$WORK/v1_host_nb"
        core_set_diff "subdomains v2/v1" "$WORK/v2_sub_nb" "$WORK/v1_sub_nb" "v21_sub"
        core_set_diff "hosts      v2/v1" "$WORK/v2_host_nb" "$WORK/v1_host_nb" "v21_host"
        core_set_diff "findings   v2/v1" "$WORK/v2_find" "$WORK/v1_find" "v21_find"
    fi

    # Lab-specific checks.
    EXTRA_FAILS=0
    WILD_V2=$(comm -12 "$WORK/v2_sub" "$WORK/exp_wild" | tr '\n' ' ')
    WILD_V1=""
    [ "$have_v1" -eq 1 ] && WILD_V1=$(comm -12 "$WORK/v1_sub" "$WORK/exp_wild" | tr '\n' ' ')
    printf '\nwildcard leak (want none): v2=[%s] v1=[%s]\n' "$WILD_V2" "$WILD_V1"
    [ -n "$WILD_V2$WILD_V1" ] && EXTRA_FAILS=$((EXTRA_FAILS + 1))

    local esc="${TARGET//./\\.}"
    OOS=$(grep -vE "(^|\.)${esc}\$" "$WORK/v2_host" || true)
    printf 'scope (out-of-scope v2 hosts, want none): [%s]\n' "$(printf '%s' "$OOS" | tr '\n' ' ')"
    [ -n "$OOS" ] && EXTRA_FAILS=$((EXTRA_FAILS + 1))

    BONUS_V2=$(comm -12 "$WORK/v2_sub" "$WORK/exp_bonus" | tr '\n' ' ')
    printf 'bonus tier found by v2 (informational): [%s]\n' "$BONUS_V2"

    TOTAL_FAILS=$((CORE_FAILS + EXTRA_FAILS))
    emit_report "$have_v1"
}

emit_report() {
    local have_v1="$1" md="$OUT/REPORT.md" js="$OUT/report.json" verdict="PASS"
    [ "$TOTAL_FAILS" -gt 0 ] && verdict="FAIL"
    {
        printf '# Parity lab report — %s\n\n' "$TARGET"
        printf -- '- Generated : %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
        printf -- '- Mode : `%s`   Tolerance : removed-ratio ≤ %s%% per set (lab default 0%%: deterministic target)\n' "$MODE" "$TOLERANCE"
        printf -- '- v2 workspace : `%s`  (rc=%s, %ss)\n' "$V2_WS" "$V2_RC" "$V2_SECS"
        if [ "$have_v1" -eq 1 ]; then printf -- '- v1 reference : `%s`  (rc=%s, %ss)\n' "$V1_DIR" "$V1_RC" "$V1_SECS"; else printf -- '- v1 : not run (pass --with-v1)\n'; fi
        printf -- '- Ground truth : `lab/parity/expected/*.txt`\n'
        printf -- '- Verdict : **%s**  (%s set failure(s), %s lab check failure(s))\n\n' "$verdict" "$CORE_FAILS" "$EXTRA_FAILS"
        printf '## Sets\n\n| comparison | candidate | reference | common | +added | -removed | verdict |\n|---|--:|--:|--:|--:|--:|---|\n'
        local row slug label
        for row in "${ROWS[@]}"; do
            slug="${row%%|*}"
            label="${row#*|}"
            printf '| %s | %s | %s | %s | %s | %s | %s |\n' "$label" \
                "$(eval "echo \${DIFF_${slug}_l}")" "$(eval "echo \${DIFF_${slug}_r}")" \
                "$(eval "echo \${DIFF_${slug}_common}")" "$(eval "echo \${DIFF_${slug}_added}")" \
                "$(eval "echo \${DIFF_${slug}_removed}")" "$(eval "echo \${DIFF_${slug}_verdict}")"
        done
        printf '\n## Lab checks\n\n'
        printf -- '- wildcard leak (expected/wildcard_only.txt present in a subdomain set): v2=[%s] v1=[%s] → %s\n' "$WILD_V2" "$WILD_V1" "$([ -z "$WILD_V2$WILD_V1" ] && echo PASS || echo FAIL)"
        printf -- '- scope (v2 hosts outside %s): [%s] → %s\n' "$TARGET" "$(printf '%s' "$OOS" | tr '\n' ' ')" "$([ -z "$OOS" ] && echo PASS || echo FAIL)"
        printf -- '- bonus tier (crawl-only names, informational): v2 found [%s]\n' "$BONUS_V2"
        printf '\n## Removed items (reference had, candidate missing — review first)\n\n'
        for row in "${ROWS[@]}"; do
            slug="${row%%|*}"
            printf '### %s\n\n```\n' "${row#*|}"
            if [ -s "$WORK/.d_${slug}_removed" ]; then head -50 "$WORK/.d_${slug}_removed"; else printf '(none)\n'; fi
            printf '```\n\n'
        done
        printf '## Added items (candidate has, reference did not)\n\n'
        for row in "${ROWS[@]}"; do
            slug="${row%%|*}"
            printf '### %s\n\n```\n' "${row#*|}"
            if [ -s "$WORK/.d_${slug}_added" ]; then head -50 "$WORK/.d_${slug}_added"; else printf '(none)\n'; fi
            printf '```\n\n'
        done
        printf '## Noise exclusions applied\n\n'
        printf -- '- apex `%s` removed from every set\n- bonus/crawl-only tier excluded from the v2-vs-v1 diff\n- ordering (sets are sorted), timestamps, screenshots, counts: never compared\n' "$TARGET"
    } >"$md"

    local sets='{}'
    for row in "${ROWS[@]}"; do
        slug="${row%%|*}"
        sets=$(jq -n --argjson s "$sets" --arg k "$slug" --arg label "${row#*|}" \
            --arg v "$(eval "echo \${DIFF_${slug}_verdict}")" \
            --argjson added "$(json_array_from_file "$WORK/.d_${slug}_added")" \
            --argjson removed "$(json_array_from_file "$WORK/.d_${slug}_removed")" \
            '$s + {($k): {label: $label, verdict: $v, added: $added, removed: $removed}}')
    done
    jq -n --arg target "$TARGET" --arg mode "$MODE" --argjson tol "$TOLERANCE" --arg verdict "$verdict" \
        --arg generated "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg v2ws "$V2_WS" --arg v2rc "$V2_RC" --arg v1rc "$V1_RC" \
        --arg wild_v2 "$WILD_V2" --arg wild_v1 "$WILD_V1" --arg oos "$OOS" --arg bonus "$BONUS_V2" --argjson sets "$sets" \
        '{target:$target, mode:$mode, tolerance_pct:$tol, verdict:$verdict, generated:$generated,
          v2_workspace:$v2ws, v2_rc:$v2rc, v1_rc:$v1rc,
          lab_checks:{wildcard_leak_v2:$wild_v2, wildcard_leak_v1:$wild_v1, out_of_scope:$oos, bonus_found:$bonus},
          sets:$sets}' >"$js"
    printf '\nreports written:\n  %s\n  %s\n' "$md" "$js"
}

# ── main ────────────────────────────────────────────────────────────────────

need jq
need curl
need go

render_templates
if [ "$RENDER_ONLY" -eq 1 ]; then
    validate_v2_config
    log "render-only: done"
    exit 0
fi

if [ "$COMPARE_ONLY" -eq 0 ]; then
    need docker
    validate_v2_config

    if [ "$SKIP_UP" -eq 0 ]; then
        log "bringing the lab up: ${COMPOSE[*]} up -d --build"
        "${COMPOSE[@]}" up -d --build >"$OUT/compose.log" 2>&1 || die "docker compose up failed — see $OUT/compose.log"
        if [ "$KEEP_UP" -eq 0 ]; then
            # shellcheck disable=SC2064
            trap "'${COMPOSE[0]}' compose -f '$LAB_DIR/docker-compose.yml' down >/dev/null 2>&1 || true" EXIT
        fi
    fi
    wait_for_lab

    if system_resolves "www.${TARGET}"; then
        log "OS resolver resolves www.${TARGET} (httpx/nuclei/katana will reach the lab)"
    elif [ "$ALLOW_NO_SYSDNS" -eq 1 ]; then
        log "WARNING: OS resolver cannot resolve *.${TARGET}; web stages will find nothing (--allow-no-system-dns given)"
    else
        die "the OS resolver cannot resolve www.${TARGET}. The web tools use the system resolver, not the lab
  resolvers file. Point the OS at the lab DNS for this zone:  sudo lab/parity/system-dns.sh install
  (Linux: dummy iface + resolvectl; macOS: /etc/resolver/${TARGET}), or pass --allow-no-system-dns."
    fi

    run_v2
    [ "$WITH_V1" -eq 1 ] && run_v1
fi

compare

printf '\n'
if [ "$TOTAL_FAILS" -eq 0 ]; then
    printf 'VERDICT: PASS — every gated set within %s%%, no wildcard leak, scope clean.\n' "$TOLERANCE"
    exit 0
fi
printf 'VERDICT: FAIL — %s set(s) and %s lab check(s) flagged; read %s/REPORT.md\n' "$CORE_FAILS" "$EXTRA_FAILS" "$OUT"
exit 1
