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

ui_count_inc() {
    case "$1" in
        OK)   ((_UI_OK_COUNT++))   || true ;;
        WARN) ((_UI_WARN_COUNT++)) || true ;;
        FAIL) ((_UI_FAIL_COUNT++)) || true ;;
        SKIP) ((_UI_SKIP_COUNT++)) || true ;;
    esac
}

ui_counts_summary() {
    printf "OK:%d WARN:%d FAIL:%d SKIP:%d" \
        "$_UI_OK_COUNT" "$_UI_WARN_COUNT" "$_UI_FAIL_COUNT" "$_UI_SKIP_COUNT"
}

ui_header() {
    local target="${domain:-unknown}"
    local profile="${CUSTOM_CONFIG:-default}"
    local parallel="${PARALLEL_MODE:-true}"
    local threads="${PARALLEL_MAX_JOBS:-4}"
    local outdir="${dir:-unknown}"
    local started
    started=$(date +'%Y-%m-%d %H:%M:%S')

    printf "\n%b───────────────────────────────────────────────────────────────%b\n" "${bgreen:-}" "${reset:-}"
    printf "  Target:   %b%s%b\n" "${bred:-}" "$target" "${reset:-}"
    printf "  Profile:  %s │ Parallel: %s │ Jobs: %s\n" \
        "$(basename "${profile}")" "$parallel" "$threads"
    printf "  Output:   %s\n" "$outdir"
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
        printf "  Info:     %s\n" "$info_line"
    fi
    printf "  Started:  %s\n" "$started"
    printf "%b───────────────────────────────────────────────────────────────%b\n\n" "${bgreen:-}" "${reset:-}"
}

ui_section() {
    _print_section "$1"
}

ui_progress() {
    local step="$1" current="$2" total="$3" pct="$4" eta="$5"
    local counters
    counters=$(ui_counts_summary)

    if ui_is_tty; then
        printf "\r  %b▸ [%d/%d] %d%% │ ETA: %s │ %s │ %s%b\033[K" \
            "${bblue:-}" "$current" "$total" "$pct" "$eta" "$step" "$counters" "${reset:-}"
    else
        printf "[%s] [%d/%d] %d%% | ETA: %s | %s | %s\n" \
            "$(date +'%H:%M:%S')" "$current" "$total" "$pct" "$eta" "$step" "$counters"
    fi
}

ui_batch_start() {
    local label="$1" total_jobs="$2" batch_num="${3:-}" batch_total="${4:-}"

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
    local color dots

    case "$badge" in
        OK)   color="${bgreen:-}" ;;
        FAIL) color="${bred:-}" ;;
        WARN) color="${yellow:-}" ;;
        SKIP) color="${yellow:-}" ;;
        *)    color="" ;;
    esac

    local task_len=${#task}
    local dot_count=$((34 - task_len))
    ((dot_count < 2)) && dot_count=2
    dots=$(printf '%*s' "$dot_count" '' | tr ' ' '.')

    if [[ -n "$detail" ]]; then
        printf "    %b[%-4s]%b %s %s %4ss → %s\n" \
            "$color" "$badge" "${reset:-}" "$task" "$dots" "$duration" "$detail"
    else
        printf "    %b[%-4s]%b %s %s %4ss\n" \
            "$color" "$badge" "${reset:-}" "$task" "$dots" "$duration"
    fi
}

ui_batch_end() {
    local ok="$1" warn="$2" fail="$3" elapsed="$4"
    printf "  %b── ok:%d warn:%d fail:%d │ %ds elapsed ──%b\n" \
        "${bgreen:-}" "$ok" "$warn" "$fail" "$elapsed" "${reset:-}"
}

ui_summary() {
    local target="$1" duration="$2" outdir="$3"
    local subs="${4:-0}" webs="${5:-0}"
    local crit="${6:-0}" high="${7:-0}" med="${8:-0}" low="${9:-0}" info="${10:-0}"

    printf "\n"
    _print_rule
    printf "  %bRESULTS: %s%b\n" "${bblue:-}" "$target" "${reset:-}"
    _print_rule
    printf "  Subdomains:     %s\n" "$subs"
    printf "  Web hosts:      %s\n" "$webs"
    printf "  Vulnerabilities: %b🔴 %d%b │ %b🟠 %d%b │ %b🟡 %d%b │ %b🔵 %d%b │ %bℹ️  %d%b\n" \
        "${bred:-}" "$crit" "${reset:-}" \
        "${yellow:-}" "$high" "${reset:-}" \
        "${yellow:-}" "$med" "${reset:-}" \
        "${bblue:-}" "$low" "${reset:-}" \
        "${cyan:-}" "$info" "${reset:-}"
    printf "  Duration:       %s\n" "$duration"
    printf "  Output:         %s\n" "$outdir"
    _print_rule
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
