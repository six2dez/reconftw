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
#     --no-archive       do NOT archive a pre-existing v2 workspace before scanning.
#                        Archival is ON by default — see ARCHIVE_WS below for why a
#                        re-run over old checkpoints fabricates the parity number.
#     --baseline-dir DIR path for the v1 worktree checkout     (env BASELINE_DIR, default ../reconftw-v1-baseline)
#     --out DIR          report output dir                     (default workspaces/<target>)
#     --tolerance PCT    removed-ratio REVIEW threshold        (default 10)
#     --compare-only     skip both scans; diff existing v1 Recon/ + latest v2 workspace
#     --v2-only          skip the v1 leg; run v2 and diff against the BANKED v1 tree
#                        at <baseline-dir>/Recon/<target>. The v1 leg is the
#                        expensive half (10h+ on a real target) and its output does
#                        not change between v2 iterations, so re-running it to
#                        re-test v2 is pure waste. --compare-only skips BOTH legs,
#                        which is not the same thing.
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
V2_ONLY=0
# ARCHIVE_WS: archive any pre-existing v2 workspace before the scan.
#
# DEFAULT ON, DELIBERATELY. This script exists to produce a COMPARABLE
# measurement, and a re-run over a previous run's workspace cannot produce one:
# Scheduler.runOne returns early on a Checkpoint.Done hit, so completed tasks are
# SKIPPED and a partial v2 tree is compared against v1's complete one. That is
# not a small error — it is a fabricated number, and it looks exactly like a real
# regression. Opting out must therefore be explicit (--no-archive), and the
# assertion below refuses to run if the archive did not actually happen.
ARCHIVE_WS=1
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
        # Attribution only when something is not OK: a clean run does not need the
        # run's own logs pasted under it, and a REVIEW verdict is exactly where the
        # next investigation used to start from zero.
        if [ "$CORE_FAILS" -gt 0 ]; then
            attribution_section "$v2ws"
        fi
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

# ── workspace archival, baseline immutability, and run attribution ───────────

# archive_workspaces <target> — MOVE every pre-existing workspace for target to a
# timestamped archive path. Never deletes: the previous tree is evidence, and the
# phase-15 record is full of failed runs whose leftovers turned out to be the only
# copy of something.
#
# The WHOLE directory moves, not just checkpoints.db. Stale artefacts matter too:
# web.httpx prefers a prior non-empty artefacts/hosts.jsonl in its own input
# precedence, so a leftover host list would feed the next run and the parity
# number would describe a mixture of two runs. Removing only the checkpoint
# database fixes the visible hazard and leaves that one.
archive_workspaces() {
    local target="$1" stamp archive moved=0 w
    stamp="$(date -u +'%Y%m%dT%H%M%SZ')"
    archive="workspaces/.archive/${target}-${stamp}"

    for w in $(ls -d "workspaces/${target}"-*/ "workspaces/${target}/" 2>/dev/null); do
        w="${w%/}"
        case "$w" in
            workspaces/.archive*) continue ;;
        esac
        mkdir -p "$archive" || die "cannot create archive dir $archive"
        mv "$w" "$archive/" || die "cannot archive $w to $archive (a live run holding it?)"
        printf '   archived %s -> %s/\n' "$w" "$archive"
        moved=$((moved + 1))
    done
    if [ "$moved" -eq 0 ]; then
        printf '   no pre-existing workspace for %s — nothing to archive\n' "$target"
    fi
    LAST_ARCHIVE="$archive"
}

# assert_no_workspace <target> — refuse to scan while a workspace survives.
#
# A silently-failed archive is worse than no archive, because the operator now
# believes the run was clean.
assert_no_workspace() {
    local target="$1" w leftovers=""
    for w in $(ls -d "workspaces/${target}"-*/ "workspaces/${target}/" 2>/dev/null); do
        w="${w%/}"
        case "$w" in
            workspaces/.archive*) continue ;;
        esac
        # A leftover .run.lock FILE is normal: the lock is an advisory flock the
        # kernel releases on process death, so the file routinely outlives its
        # run. Only checkpoints.db or artefacts/ mean state that would change the
        # measurement; a bare lock file does not.
        if [ -f "$w/checkpoints.db" ] || [ -d "$w/artefacts" ]; then
            leftovers="$leftovers $w"
        fi
    done
    [ -z "$leftovers" ] || die "workspace still present after archival:$leftovers
  A silently-failed archive is WORSE than no archive: the run would reuse those checkpoints,
  skip completed tasks, and report a partial tree as a parity result. Move it by hand and re-run."
}

# baseline_fingerprint <dir> — file count and total byte size.
#
# Deliberately NOT a checksum: the banked baseline is 1.3 GB and cost ten hours,
# with no second copy. Five seconds of counting is the right price for detecting
# a write into it; twenty minutes of hashing is not.
baseline_fingerprint() {
    local d="$1"
    [ -d "$d" ] || {
        echo "MISSING"
        return
    }
    local n b
    n="$(find "$d" -type f 2>/dev/null | wc -l | tr -d ' ')"
    b="$(find "$d" -type f -exec wc -c {} + 2>/dev/null | tail -1 | awk '{print $1}')"
    echo "${n}:${b:-0}"
}

# attribution_section <v2ws> — explain a non-OK core set from the RUN'S OWN
# records rather than from inference.
#
# Before plans 16-01 and 16-02 a REVIEW verdict was a dead end: three numbers and
# no way to attribute them without reproducing the run by hand. The run now
# carries its own explanation — logs/tools.jsonl names every invocation with its
# argv, exit code and outcome, and every task that produced nothing reports SKIP
# with a reason. This reads them.
attribution_section() {
    local ws="$1" log="$1/logs/tools.jsonl"

    printf '\n## Attribution — what the run itself recorded\n\n'

    if [ ! -f "$log" ]; then
        printf 'NO TOOL LOG PRESENT at `%s`.\n\n' "$log"
        printf 'An absent log and a clean log render identically once summarised, so this says which\n'
        printf 'one it is: nothing below is evidence of a clean run — there is simply no record.\n'
        return
    fi

    printf -- '- tool log : `%s`\n\n' "$log"

    printf '### Tool invocations that did not succeed\n\n'
    local bad
    bad="$(grep -c '"outcome":"\(exit_non_zero\|dispatch_failed\|timeout\)"' "$log" 2>/dev/null || true)"
    if [ "${bad:-0}" -eq 0 ]; then
        printf 'None — every recorded invocation ended with outcome `success`.\n\n'
    else
        printf '```\n'
        grep '"outcome":"\(exit_non_zero\|dispatch_failed\|timeout\)"' "$log" | head -40
        printf '```\n\n'
    fi

    printf '### Invocations that started and never ended (the hang shape)\n\n'
    local unterminated
    unterminated="$(awk '
        /"phase":"start"/ { if (match($0, /"id":"[^"]+"/)) { id=substr($0, RSTART+6, RLENGTH-7); starts[id]=$0 } }
        /"phase":"end"/   { if (match($0, /"id":"[^"]+"/)) { id=substr($0, RSTART+6, RLENGTH-7); delete starts[id] } }
        END { for (id in starts) print starts[id] }
    ' "$log" 2>/dev/null)"
    if [ -z "$unterminated" ]; then
        printf 'None — every start record has a matching end record.\n\n'
    else
        printf 'A start with no end means the process was still running when the run ended.\n\n```\n%s\n```\n\n' "$unterminated"
    fi

    printf '### Tasks that reported SKIP, with the reason they gave\n\n'
    local skips=""
    [ -f "$ws/logs/run.log" ] && skips="$(grep -i 'skip' "$ws/logs/run.log" 2>/dev/null | head -40 || true)"
    if [ -z "$skips" ]; then
        printf 'No SKIP lines found in `%s/logs/run.log` (or the file is absent).\n\n' "$ws"
    else
        printf '```\n%s\n```\n\n' "$skips"
    fi

    printf '### Passive sources: zero-contribution and timeout check\n\n'
    printf 'crt.sh rate-limits after repeated runs against the same target — `subdomains.passive.crt`\n'
    printf 'failed at exactly 1m00s in the 2026-08-20 run, a timeout shape. A subdomain-set change\n'
    printf 'caused by a rate-limited source must stay distinguishable from a real regression, so the\n'
    printf 'per-source records are listed rather than retried or slept around.\n\n'
    local src
    for src in crt subfinder github-subdomains gitlab-subdomains urlfinder; do
        if grep -q "\"tool\":\"${src}\"" "$log" 2>/dev/null; then
            printf -- '- `%s` : %s\n' "$src" "$(grep "\"tool\":\"${src}\"" "$log" | head -3 | tr '\n' ' ')"
        else
            printf -- '- `%s` : no invocation recorded\n' "$src"
        fi
    done

    printf '\n**These associations are a GUESS.** The log says which tools failed; it does not say which\n'
    printf 'core set each failure explains. An attribution that reads as certain and is not would be the\n'
    printf 'same defect class this phase exists to close.\n'
}

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

    # ── the plan-16-06 assertions: archival, evidence preservation, baseline
    #    immutability, and attribution rendering. None needs the real binary, the
    #    real baseline or the network — this is the only part of plan 16-06 that
    #    can be verified without reconbox3, so it has to carry the logic.
    local sc_tmp sc_fail=0
    sc_tmp="$(mktemp -d)" || die "mktemp -d failed"
    (
        cd "$sc_tmp" || exit 1
        mkdir -p "workspaces/selfcheck-tgt-abc/artefacts"
        : >"workspaces/selfcheck-tgt-abc/checkpoints.db"
        : >"workspaces/selfcheck-tgt-abc/.run.lock"
        echo "MARKER" >"workspaces/selfcheck-tgt-abc/artefacts/marker.txt"
    )

    # 1. archival MOVES the workspace, and the assertion then passes.
    (
        cd "$sc_tmp" || exit 1
        archive_workspaces "selfcheck-tgt" >/dev/null 2>&1
        assert_no_workspace "selfcheck-tgt" >/dev/null 2>&1
    )
    if [ $? -eq 0 ]; then
        echo "  archival: workspace moved and assertion passes .......... PASS"
    else
        echo "  archival: workspace moved and assertion passes .......... FAIL"
        sc_fail=$((sc_fail + 1))
    fi

    # 2. THE ARCHIVE IS A MOVE, NOT A DELETE. Asserted on a seeded marker FILE,
    #    not on the directory existing — a delete-then-mkdir would satisfy the
    #    weaker check and destroy the evidence this contract exists to keep.
    if [ -n "$(find "$sc_tmp/workspaces/.archive" -name marker.txt 2>/dev/null)" ]; then
        echo "  archival: previous run's files survive under .archive/ ... PASS"
    else
        echo "  archival: previous run's files survive under .archive/ ... FAIL"
        sc_fail=$((sc_fail + 1))
    fi

    # 3. A workspace that could NOT be archived must make the script die.
    (
        cd "$sc_tmp" || exit 1
        mkdir -p "workspaces/selfcheck-stuck-xyz/artefacts"
        : >"workspaces/selfcheck-stuck-xyz/checkpoints.db"
        assert_no_workspace "selfcheck-stuck" >/dev/null 2>&1
    )
    if [ $? -ne 0 ]; then
        echo "  archival: an un-archived workspace is refused ............ PASS"
    else
        echo "  archival: an un-archived workspace is refused ............ FAIL"
        sc_fail=$((sc_fail + 1))
    fi

    # 4. The baseline fingerprint detects a write into the banked tree.
    local fp_a fp_b
    mkdir -p "$sc_tmp/baseline"
    echo "one" >"$sc_tmp/baseline/a.txt"
    fp_a="$(baseline_fingerprint "$sc_tmp/baseline")"
    echo "two" >"$sc_tmp/baseline/b.txt"
    fp_b="$(baseline_fingerprint "$sc_tmp/baseline")"
    if [ "$fp_a" != "$fp_b" ]; then
        echo "  baseline: a write into the tree changes the fingerprint .. PASS ($fp_a -> $fp_b)"
    else
        echo "  baseline: a write into the tree changes the fingerprint .. FAIL"
        sc_fail=$((sc_fail + 1))
    fi

    # 5. Attribution renders a failed invocation AND an unterminated start.
    local att
    mkdir -p "$sc_tmp/ws/logs"
    {
        echo '{"id":"1","phase":"start","tool":"httpx","argv":["-json"]}'
        echo '{"id":"1","phase":"end","exit_code":0,"outcome":"success"}'
        echo '{"id":"2","phase":"start","tool":"subzy","argv":["run"]}'
        echo '{"id":"2","phase":"end","exit_code":1,"outcome":"exit_non_zero","stderr_tail":"unknown flag"}'
        echo '{"id":"3","phase":"start","tool":"nuclei","argv":["-duc"]}'
    } >"$sc_tmp/ws/logs/tools.jsonl"
    att="$(attribution_section "$sc_tmp/ws")"
    if printf '%s' "$att" | grep -q 'exit_non_zero'; then
        echo "  attribution: a failed invocation is reported ............. PASS"
    else
        echo "  attribution: a failed invocation is reported ............. FAIL"
        sc_fail=$((sc_fail + 1))
    fi
    if printf '%s' "$att" | grep -q '"tool":"nuclei"'; then
        echo "  attribution: an unterminated start is reported ........... PASS"
    else
        echo "  attribution: an unterminated start is reported ........... FAIL"
        sc_fail=$((sc_fail + 1))
    fi

    # 6. An ABSENT log says so. An absent log and a clean log render identically
    #    once summarised, and only one of them is evidence.
    mkdir -p "$sc_tmp/empty_ws"
    if attribution_section "$sc_tmp/empty_ws" | grep -q 'NO TOOL LOG PRESENT'; then
        echo "  attribution: an ABSENT log is named, not left blank ...... PASS"
    else
        echo "  attribution: an ABSENT log is named, not left blank ...... FAIL"
        sc_fail=$((sc_fail + 1))
    fi

    rm -rf "$sc_tmp"
    if [ "$sc_fail" -gt 0 ]; then
        die "$sc_fail plan-16-06 self-check assertion(s) failed"
    fi

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
        --v2-only) V2_ONLY=1 ;;
        --no-archive) ARCHIVE_WS=0 ;;
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

[ -n "$TARGET" ] || die "usage: scripts/parity-full.sh <target> [--legacy-ref REF] [--v2-only|--compare-only] | --self-check | --help"

if [ "$COMPARE_ONLY" -eq 1 ] && [ "$V2_ONLY" -eq 1 ]; then
    die "--compare-only and --v2-only are mutually exclusive: the first runs neither leg, the second runs v2"
fi
command -v jq >/dev/null 2>&1 || die "jq not found on PATH"
command -v git >/dev/null 2>&1 || die "git not found on PATH"

V1DIR="${BASELINE_DIR%/}/Recon/${TARGET}"

# ── set up the frozen legacy checkout (D-05) and run bash v1 ──
if [ "$COMPARE_ONLY" -eq 0 ]; then
    [ -x "$BIN" ] || die "$BIN not found — run: make build"

    if [ "$V2_ONLY" -eq 1 ]; then
        # Reuse the banked v1 tree. Assert it exists BEFORE burning hours on the v2
        # leg — discovering the baseline is missing after the v2 scan would waste
        # exactly what this flag exists to save.
        [ -d "$V1DIR" ] || die "--v2-only needs a completed v1 baseline at $V1DIR (point --baseline-dir at its Recon parent)"
        printf '== v1 leg SKIPPED (--v2-only): reusing banked baseline at %s ==\n' "$V1DIR"
    else
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
    fi

    # Archive BEFORE the scan: see ARCHIVE_WS for why a re-run over old
    # checkpoints fabricates the number rather than perturbing it.
    if [ "$ARCHIVE_WS" -eq 1 ]; then
        printf '== archiving any pre-existing v2 workspace for %s ==\n' "$TARGET"
        archive_workspaces "$TARGET"
        assert_no_workspace "$TARGET"
    else
        printf '== --no-archive: NOT archiving. A leftover checkpoints.db will make completed tasks\n'
        printf '   SKIP and the parity number describe a PARTIAL tree. You asked for this explicitly.\n'
    fi

    BASELINE_FP_BEFORE="$(baseline_fingerprint "$V1DIR")"
    printf '== banked v1 baseline fingerprint: %s ==\n' "$BASELINE_FP_BEFORE"

    printf '== v2 (Go) run against %s ==\n' "$TARGET"
    "$BIN" recon --target "$TARGET" || die "v2 run failed"

    BASELINE_FP_AFTER="$(baseline_fingerprint "$V1DIR")"
    if [ "$BASELINE_FP_BEFORE" != "$BASELINE_FP_AFTER" ]; then
        die "THE BANKED v1 BASELINE CHANGED during the v2 run: $V1DIR
  before=$BASELINE_FP_BEFORE after=$BASELINE_FP_AFTER
  Something wrote into the baseline, so the comparison is void. That tree cost ten hours and
  there is no second copy — stop and find out what wrote to it before running anything else."
    fi
    printf '== baseline unchanged (%s) ==\n' "$BASELINE_FP_AFTER"
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
