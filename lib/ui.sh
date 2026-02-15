#!/usr/bin/env bash
# lib/ui.sh - UI presentation layer for reconFTW
# Provides TTY detection, color management, progress, batch layout, counters

[[ -n "${_UI_SH_LOADED:-}" ]] && return 0
declare -r _UI_SH_LOADED=1

# Global state
_UI_IS_TTY=false
_UI_NO_COLOR=false
_UI_LOG_FORMAT="plain"

_UI_OK_COUNT=0
_UI_WARN_COUNT=0
_UI_FAIL_COUNT=0
_UI_SKIP_COUNT=0
_UI_CACHE_COUNT=0

# Dry-run tracking
_UI_DRYRUN_COUNT=0
_UI_DRYRUN_COMMANDS=()
_UI_DRYRUN_FULL_COMMANDS=()
_UI_DRYRUN_SHARED_FILE=""
_UI_LIVE_ACTIVE=false

ui_init() {
    # TTY detection
    if [[ -t 1 ]]; then
        _UI_IS_TTY=true
    else
        _UI_IS_TTY=false
    fi

    # NO_COLOR convention + TERM=dumb + non-TTY default
    if [[ -n "${NO_COLOR:-}" ]] || [[ "${TERM:-}" == "dumb" ]] || [[ "$_UI_IS_TTY" != true ]]; then
        _UI_NO_COLOR=true
    fi

    if [[ "$_UI_NO_COLOR" == true ]]; then
        # shellcheck disable=SC2034  # Color vars used by modules that source this file
        bred="" bgreen="" bblue="" byellow="" yellow="" reset=""
        # shellcheck disable=SC2034
        red="" blue="" green="" cyan=""
    fi

    _UI_LOG_FORMAT="${LOG_FORMAT:-plain}"
}

ui_is_tty() {
    [[ "$_UI_IS_TTY" == true ]]
}

ui_live_progress_begin() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    ui_is_tty || return 0
    _UI_LIVE_ACTIVE=true
}

ui_live_progress_update() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    ui_is_tty || return 0
    local line="$1"
    _UI_LIVE_ACTIVE=true
    printf "\r  %b%s%b\033[K" "${bblue:-}" "$line" "${reset:-}"
}

ui_live_progress_break() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    ui_is_tty || return 0
    [[ "$_UI_LIVE_ACTIVE" == true ]] || return 0
    printf "\r\033[K"
}

ui_live_progress_end() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    ui_is_tty || return 0
    if [[ "$_UI_LIVE_ACTIVE" == true ]]; then
        printf "\r\033[K"
    fi
    _UI_LIVE_ACTIVE=false
}

ui_count_inc() {
    case "$1" in
        OK)   ((_UI_OK_COUNT++))   || true ;;
        WARN) ((_UI_WARN_COUNT++)) || true ;;
        FAIL) ((_UI_FAIL_COUNT++)) || true ;;
        SKIP) ((_UI_SKIP_COUNT++)) || true ;;
        CACHE) ((_UI_CACHE_COUNT++)) || true ;;
    esac
}

ui_counts_summary() {
    printf "OK:%d WARN:%d FAIL:%d SKIP:%d CACHE:%d" \
        "$_UI_OK_COUNT" "$_UI_WARN_COUNT" "$_UI_FAIL_COUNT" "$_UI_SKIP_COUNT" "$_UI_CACHE_COUNT"
}

ui_header() {
    local target="${domain:-unknown}"
    local profile="${CUSTOM_CONFIG:-default}"
    local parallel="${PARALLEL_MODE:-true}"
    local threads="${PARALLEL_MAX_JOBS:-4}"
    local outdir="${dir:-unknown}"
    local started
    started=$(date +'%Y-%m-%d %H:%M:%S')
    local mode_label="FULL"
    case "${opt_mode:-r}" in
        n) mode_label="OSINT-ONLY" ;;
        w) mode_label="WEB" ;;
        s) mode_label="SUBDOMAINS" ;;
        p) mode_label="PASSIVE" ;;
        a) mode_label="ALL" ;;
        z) mode_label="ZEN" ;;
    esac

    local header_line
    header_line=$(printf "reconftw %s by @six2dez | Authorized testing only" "${reconftw_version:-}")
    local header_rule=""
    local i
    for ((i = 0; i < ${#header_line}; i++)); do
        header_rule+="─"
    done
    printf "%b%s%b\n" "${bgreen:-}" "$header_rule" "${reset:-}"
    printf "%b%s%b\n" "${bgreen:-}" "$header_line" "${reset:-}"
    printf "%b%s%b\n" "${bgreen:-}" "$header_rule" "${reset:-}"
    printf "Mode: %s | Target: %s | Profile: %s | Parallel: %s | Jobs: %s\n" \
        "$mode_label" "$target" "$(basename "${profile}")" "$parallel" "$threads"
    printf "Output: %s\n" "$outdir"
    if [[ -n "${RECON_BEHIND_NAT:-}" ]] || [[ -n "${DNS_RESOLVER_SELECTED:-}" ]]; then
        printf "Network: behind_nat=%s | DNS: %s\n" "${RECON_BEHIND_NAT:-unknown}" "${DNS_RESOLVER_SELECTED:-unknown}"
    fi
    if [[ -n "${PERF_PROFILE_INFO:-}" ]] || [[ -n "${DISK_SPACE_INFO:-}" ]]; then
        local info_line=""
        if [[ -n "${PERF_PROFILE_INFO:-}" ]]; then
            info_line="${PERF_PROFILE_INFO}"
        fi
        if [[ -n "${DISK_SPACE_INFO:-}" ]]; then
            if [[ -n "$info_line" ]]; then
                info_line="${info_line} | ${DISK_SPACE_INFO}"
            else
                info_line="${DISK_SPACE_INFO}"
            fi
        fi
        printf "System: %s\n" "$info_line"
    fi
    printf "Started: %s\n\n" "$started"
}

ui_section() {
    _print_section "$1"
}

ui_progress() {
    local step="$1" current="$2" total="$3" pct="$4" eta="$5"
    local counters
    counters=$(ui_counts_summary)

    if ui_is_tty; then
        ui_live_progress_begin
        ui_live_progress_update "▸ [${current}/${total}] ${pct}% | ETA: ${eta} | ${step} | ${counters}"
    else
        :
    fi
}

ui_batch_start() {
    local label="$1" total_jobs="$2" batch_num="${3:-}" batch_total="${4:-}"
    ui_live_progress_break

    if ui_is_tty; then
        printf "\n"
    fi

    local batch_label=""
    if [[ -n "$batch_num" ]] && [[ -n "$batch_total" ]]; then
        batch_label="Batch ${batch_num}/${batch_total}: "
    fi

    printf "  %b── %s%s [%d jobs] ──%b\n" \
        "${bgreen:-}" "$batch_label" "$label" "$total_jobs" "${reset:-}"
}

ui_batch_row() {
    local badge="$1" task="$2" duration="$3" detail="${4:-}"
    if declare -F print_task >/dev/null 2>&1; then
        print_task "$badge" "$task" "$duration" "$detail"
    else
        printf "    [%s] %s %ss\n" "$badge" "$task" "$duration"
    fi
}

ui_batch_end() {
    local ok="$1" warn="$2" fail="$3" elapsed="$4"
    local skip="${5:-0}" cache="${6:-0}"
    local completed="${7:-0}" total="${8:-0}"
    ui_live_progress_break
    printf "  %b── ok:%d warn:%d fail:%d skip:%d cache:%d │ %d/%d completed │ %ds elapsed ──%b\n" \
        "${bgreen:-}" "$ok" "$warn" "$fail" "$skip" "$cache" "$completed" "$total" "$elapsed" "${reset:-}"
}

ui_summary() {
    local target="$1" duration="$2" outdir="$3" mode_label="$4"
    local subs="${5:-0}" webs="${6:-0}"
    local crit="${7:-0}" high="${8:-0}" med="${9:-0}" low="${10:-0}" info="${11:-0}"
    local debug_log="${DEBUG_LOG:-}"

    ui_live_progress_end
    printf "\n"
    printf "RESULTS  %s\n" "$target"
    printf "Mode: %s\n" "$mode_label"
    printf "Subdomains: %s\n" "$subs"
    printf "Web hosts: %s\n" "$webs"
    printf "Findings: C %d | H %d | M %d | L %d | I %d\n" \
        "$crit" "$high" "$med" "$low" "$info"
    printf "Duration: %s\n" "$duration"
    printf "Output: %s\n" "$outdir"
    if [[ -n "$debug_log" ]] && (( _UI_FAIL_COUNT > 0 || _UI_WARN_COUNT > 0 )); then
        printf "Debug log: %s\n" "$debug_log"
    fi
    printf "\n"
}

ui_module_end() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    local module="$1"
    shift
    if [[ $# -gt 0 ]]; then
        local files_list
        files_list=$(printf '%s, ' "$@")
        files_list="${files_list%, }"
        printf "  %bOutput:%b %s\n\n" "${bblue:-}" "${reset:-}" "$files_list"
    fi
    _print_module_end "$module"
}

ui_json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//"/\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf "%s" "$s"
}

ui_log_jsonl() {
    [[ "$_UI_LOG_FORMAT" != "jsonl" ]] && return 0
    local level="$1" module="$2" message="$3"
    shift 3

    local ts lvl mod msg dom
    ts=$(date -Iseconds)
    lvl=$(ui_json_escape "$level")
    mod=$(ui_json_escape "$module")
    msg=$(ui_json_escape "$message")
    dom=$(ui_json_escape "${domain:-}")

    local extra=""
    local kv key val
    for kv in "$@"; do
        if [[ "$kv" =~ ^([^=]+)=(.*)$ ]]; then
            key=$(ui_json_escape "${BASH_REMATCH[1]}")
            val=$(ui_json_escape "${BASH_REMATCH[2]}")
            extra+="\",\"${key}\":\"${val}"
        fi
    done

    printf '{"ts":"%s","level":"%s","module":"%s","msg":"%s","domain":"%s"%s}\n' \
        "$ts" "$lvl" "$mod" "$msg" "$dom" "$extra"
}

# Track dry-run commands for module-level summaries
# Usage: ui_dryrun_track "tool_name" "full command string"
ui_dryrun_track() {
    local tool_name="$1"
    local full_command="$2"
    local redacted_command

    # Normalize whitespace: replace newlines with spaces, squeeze multiple spaces
    local normalized_command
    normalized_command=$(echo "$full_command" | tr '\n' ' ' | tr -s ' ')
    redacted_command="$normalized_command"

    # Use centralized redaction when available.
    if declare -F redact_secrets >/dev/null 2>&1; then
        redacted_command=$(redact_secrets "$redacted_command")
    fi
    # Fallback masking for common inline secrets shown in command args.
    redacted_command=$(echo "$redacted_command" \
        | sed -E 's/(-token-string[[:space:]]+)[^[:space:]]+/\1[REDACTED]/g' \
        | sed -E 's/([?&]apiKey=)[^&[:space:]]+/\1[REDACTED]/g' \
        | sed -E 's/(Authorization:[[:space:]]*Bearer[[:space:]])[^[:space:]]+/\1[REDACTED]/g')

    ((_UI_DRYRUN_COUNT++)) || true
    _UI_DRYRUN_COMMANDS+=("$tool_name")
    _UI_DRYRUN_FULL_COMMANDS+=("$redacted_command")

    # Shared module-local dry-run log (visible from parallel subshells)
    if [[ -n "${_UI_DRYRUN_SHARED_FILE:-}" ]]; then
        printf "%s\t%s\n" "$tool_name" "$redacted_command" >>"${_UI_DRYRUN_SHARED_FILE}" 2>/dev/null || true
    fi

    # Immediate output only if verbose (OUTPUT_VERBOSITY >= 2)
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[DRY-RUN]%b %s\n" "${yellow:-}" "${reset:-}" "$redacted_command"
    fi
}

# Show dry-run summary at end of module
# Usage: ui_dryrun_summary
ui_dryrun_summary() {
    [[ "${DRY_RUN:-false}" != "true" ]] && return 0
    [[ "$_UI_DRYRUN_COUNT" -eq 0 ]] && return 0
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0

    local -a summary_tools=()
    local -a summary_cmds=()
    local unique_tools

    if [[ -n "${_UI_DRYRUN_SHARED_FILE:-}" ]] && [[ -f "${_UI_DRYRUN_SHARED_FILE}" ]]; then
        while IFS=$'\t' read -r t c; do
            [[ -n "$t" ]] && summary_tools+=("$t")
            [[ -n "$c" ]] && summary_cmds+=("$c")
        done <"${_UI_DRYRUN_SHARED_FILE}"
    fi

    # Fallback when shared file isn't available
    if [[ ${#summary_tools[@]} -eq 0 ]]; then
        summary_tools=("${_UI_DRYRUN_COMMANDS[@]}")
        summary_cmds=("${_UI_DRYRUN_FULL_COMMANDS[@]}")
    fi

    _UI_DRYRUN_COUNT=${#summary_cmds[@]}
    [[ "$_UI_DRYRUN_COUNT" -eq 0 ]] && return 0

    # Deduplicate and sort tool names
    unique_tools=$(printf "%s\n" "${summary_tools[@]}" 2>/dev/null | sed '/^$/d' | sort -u | tr '\n' ', ' | sed 's/,$//' | sed 's/,/, /g')

    # Truncate if too long (> 100 chars)
    if [[ ${#unique_tools} -gt 100 ]]; then
        unique_tools="${unique_tools:0:97}..."
    fi

    printf "  %b[DRY-RUN]%b Would execute %d commands: %s\n" \
        "${byellow:-}" "${reset:-}" "$_UI_DRYRUN_COUNT" "$unique_tools"

    # Verbose: show individual commands
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "  Full command list:\n"
        local cmd
        for cmd in "${summary_cmds[@]}"; do
            printf "    - %s\n" "$cmd"
        done
    fi
}

# Reset dry-run tracking (called at module start)
# Usage: ui_dryrun_reset
ui_dryrun_reset() {
    _UI_DRYRUN_COUNT=0
    _UI_DRYRUN_COMMANDS=()
    _UI_DRYRUN_FULL_COMMANDS=()
    _UI_DRYRUN_SHARED_FILE="${dir:-/tmp}/.tmp/.dryrun_commands.${PPID:-$$}.${RANDOM}.log"
    mkdir -p "$(dirname "$_UI_DRYRUN_SHARED_FILE")" 2>/dev/null || true
    : >"$_UI_DRYRUN_SHARED_FILE" 2>/dev/null || true
    export _UI_DRYRUN_SHARED_FILE
}
