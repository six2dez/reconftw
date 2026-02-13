#!/usr/bin/env bash
# lib/common.sh - Common utility functions to reduce code duplication
# Part of reconFTW refactoring - Phase 2

# Prevent multiple sourcing
[[ -n "$_COMMON_SH_LOADED" ]] && return 0
declare -r _COMMON_SH_LOADED=1
declare -a INCIDENTS_LEVELS=()
declare -a INCIDENTS_ITEMS=()

###############################################################################
# Directory Management
###############################################################################

# Create directories with error handling
# Usage: ensure_dirs dir1 [dir2 ...]
# Returns: 0 on success, 1 on failure
ensure_dirs() {
    if [[ $# -eq 0 ]]; then
        return 0
    fi
    if ! mkdir -p "$@" 2>/dev/null; then
        _print_error "Failed to create directories: $*"
        return 1
    fi
    return 0
}

# Create standard reconftw working directories
# Usage: ensure_workdirs
ensure_workdirs() {
    ensure_dirs .tmp webs subdomains hosts vulns osint fuzzing js screenshots
}

###############################################################################
# File Operations
###############################################################################

# Safely backup a file if it exists and has content
# Usage: safe_backup source [destination]
# Default destination: .tmp/$(basename source).bak
safe_backup() {
    local src="$1"
    local dst="${2:-.tmp/$(basename "$1").bak}"
    if [[ -s "$src" ]]; then
        cp "$src" "$dst" 2>/dev/null || return 1
    fi
    return 0
}

# Append unique lines to a file using anew (falls back to cat if anew unavailable)
# Usage: dedupe_append filename
# Reads from stdin
dedupe_append() {
    local file="$1"
    if command -v anew &>/dev/null; then
        anew -q "$file" 2>/dev/null
    else
        # Fallback: simple append (no dedup)
        cat >> "$file"
    fi
}

# Count non-empty lines in a file safely
# Usage: count_lines filename
# Returns: line count (0 if file doesn't exist or is empty)
count_lines() {
    local file="$1"
    if [[ -s "$file" ]]; then
        sed '/^$/d' "$file" | wc -l | tr -d ' '
    else
        echo 0
    fi
}

# Count lines from stdin, with fallback to 0 on failure
# Usage: result=$(command | count_lines_stdin)
count_lines_stdin() {
    local count
    count=$(sed '/^$/d' | wc -l | tr -d ' ') || count=0
    echo "${count:-0}"
}

###############################################################################
# Output Primitives
###############################################################################

# Format duration in seconds to human-friendly form: 0s, 6s, 1m 23s, 19m 04s
# Usage: format_duration 83
format_duration() {
    local input="${1:-0}"
    if [[ "$input" =~ [a-zA-Z] ]] && ! [[ "$input" =~ ^[0-9]+$ ]]; then
        printf "%s" "$input"
        return 0
    fi
    if [[ "$input" =~ ^[0-9]+s$ ]]; then
        input="${input%s}"
    fi
    if ! [[ "$input" =~ ^[0-9]+$ ]]; then
        input=0
    fi
    local total="$input"
    local mins=$((total / 60))
    local secs=$((total % 60))
    if ((mins > 0)); then
        printf "%dm %02ds" "$mins" "$secs"
    else
        printf "%ds" "$secs"
    fi
}

_ui_live_break_if_needed() {
    if declare -F ui_live_progress_break >/dev/null 2>&1; then
        ui_live_progress_break
    fi
}

# Print a normalized task/status line
# Usage: print_task STATE module duration_seconds reason
print_task() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    _ui_live_break_if_needed
    local state="$1" module="$2" duration="${3:-0}" reason="${4:-}"
    local color=""
    local dim_color="${blue:-}"
    local duration_fmt
    duration_fmt=$(format_duration "$duration")

    case "$state" in
        OK) color="${bgreen:-}" ;;
        WARN) color="${yellow:-}" ;;
        FAIL) color="${bred:-}" ;;
        SKIP|CACHE) color="${dim_color:-}" ;;
        INFO) color="${bblue:-}" ;;
        *) color="${bblue:-}" ;;
    esac

    local module_pad=26
    local mod="$module"
    local pad=$((module_pad - ${#mod}))
    ((pad < 1)) && pad=1
    local spaces
    spaces=$(printf '%*s' "$pad" "")

    printf "%b%-5s%b %s%s %6s" "$color" "$state" "${reset:-}" "$mod" "$spaces" "$duration_fmt"
    if [[ -n "$reason" ]]; then
        printf " (%s)" "$reason"
    fi
    printf "\n"
}

record_incident() {
    local level="$1" module="$2" reason="$3"
    [[ -z "$module" ]] && return 0
    [[ -z "$reason" ]] && return 0
    reason=${reason//\\n/ }
    reason=${reason//$'\n'/ }
    INCIDENTS_LEVELS+=("$level")
    INCIDENTS_ITEMS+=("${module} — ${reason}")
}

print_incidents() {
    local debug_log="${1:-}"
    local count=${#INCIDENTS_ITEMS[@]}
    ((count == 0)) && return 0
    printf "\nINCIDENTS (actionable)\n"
    local i
    for i in "${!INCIDENTS_ITEMS[@]}"; do
        printf "%d. %s\n" "$((i + 1))" "${INCIDENTS_ITEMS[$i]}"
    done
    if [[ -n "$debug_log" ]] && [[ -s "$debug_log" ]]; then
        printf "Debug log: %s\n" "$debug_log"
    fi
    printf "\n"
}

# Print a compact artifacts line
# Usage: print_artifacts "file1" ["file2"...]
print_artifacts() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    local items="$*"
    [[ -z "$items" ]] && return 0
    printf "Artifacts: %s\n" "$items"
}

# Print a notice line without affecting counters
# Usage: print_notice LEVEL module message
print_notice() {
    local level="$1" module="$2" message="$3"
    [[ -z "$module" ]] && module="notice"
    if [[ "$level" == "FAIL" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]]; then
        (OUTPUT_VERBOSITY=1; print_task "$level" "$module" "0" "$message")
    else
        print_task "$level" "$module" "0" "$message"
    fi
}

# Formatted WARN message without color codes
# Usage: print_warnf "message %s" "arg"
print_warnf() {
    local fmt="$1"
    shift
    local msg
    printf -v msg "$fmt" "$@"
    _print_msg WARN "$msg"
}

# Formatted FAIL message (stderr, always visible)
# Usage: print_errorf "message %s" "arg"
print_errorf() {
    local fmt="$1"
    shift
    local msg
    printf -v msg "$fmt" "$@"
    _print_error "$msg"
}

# Generic message with [LEVEL] prefix (INFO/WARN/FAIL/OK)
# Usage: _print_msg WARN "something happened"
_print_msg() {
    local level="$1"
    shift
    local msg="$*"
    local color

    if [[ "$level" == "WARN" ]]; then
        if [[ "$msg" == *"already processed"* ]]; then
            _print_status CACHE "${FUNCNAME[1]:-module}" "0s"
            if [[ -n "${called_fn_dir:-}" ]]; then
                : >"${called_fn_dir}/.cache_${FUNCNAME[1]:-module}" 2>/dev/null || true
            fi
            return 0
        fi
        if [[ "$msg" == *"skipped"* ]]; then
            _print_status SKIP "${FUNCNAME[1]:-module}" "0s"
            if [[ -n "${called_fn_dir:-}" ]]; then
                : >"${called_fn_dir}/.skip_${FUNCNAME[1]:-module}" 2>/dev/null || true
            fi
            return 0
        fi
    fi
    
    case "$level" in
        OK|SUCCESS) color="${bgreen:-}" ;;
        WARN) color="${yellow:-}" ;;
        FAIL|ERROR) color="${bred:-}" ;;
        INFO) color="${bblue:-}" ;;
        *) color="${bblue:-}" ;;
    esac
    if [[ "$level" == "INFO" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -lt 2 ]]; then
        return 0
    fi
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    _ui_live_break_if_needed
    printf "%b[%s]%b %s\n" "$color" "$level" "${reset:-}" "$msg"
}

# Module start message with timestamp
# Usage: _print_module_start "OSINT"
_print_module_start() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    if declare -F ui_live_progress_end >/dev/null 2>&1; then
        ui_live_progress_end
    fi
    local title="${1^^}"
    local ts
    ts=$(date +'%Y-%m-%d %H:%M:%S')

    # Reset dry-run tracking for new module
    if declare -F ui_dryrun_reset >/dev/null 2>&1; then
        ui_dryrun_reset
    fi

    printf "\n%b── %s ───────────────────────────────────────────────────────────────%b\n" \
        "${bgreen:-}" "$title" "${reset:-}"
    printf "Started: %s\n" "$ts"
}

# Module end message with timestamp
# Usage: _print_module_end "OSINT"
_print_module_end() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    if declare -F ui_live_progress_end >/dev/null 2>&1; then
        ui_live_progress_end
    fi
    local title="${1^^}"
    local ts
    ts=$(date +'%Y-%m-%d %H:%M:%S')

    # Show dry-run summary before completion timestamp
    if declare -F ui_dryrun_summary >/dev/null 2>&1; then
        ui_dryrun_summary
    fi

    printf "Completed: %s\n" "$ts"
}

# Section header for major phases (OSINT, Subdomains, Web, Vulns, etc.)
# Usage: _print_section "OSINT"
_print_section() {
    _print_module_start "$1"
}

# Compact status line with dot-fill and right-aligned detail
# Usage: _print_status OK "sub_passive" "12s"
#        _print_status SKIP "sub_crt" "(disabled)"
_print_status() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    local badge="$1" text="$2" detail="${3:-}"
    local duration="0"
    local reason=""

    if [[ -n "$detail" ]]; then
        if [[ "$detail" =~ ^[0-9]+$ ]]; then
            duration="$detail"
        elif [[ "$detail" =~ ^[0-9]+s$ ]]; then
            duration="${detail%s}"
        elif [[ "$detail" =~ ^[0-9]+m ]]; then
            duration="$detail"
        else
            reason="${detail}"
        fi
    fi

    if [[ "$badge" == "CACHE" ]] && [[ "${SHOW_CACHE:-false}" != "true" ]]; then
        if declare -F ui_count_inc >/dev/null 2>&1; then
            ui_count_inc "$badge"
        fi
        return 0
    fi
    if [[ "$badge" == "INFO" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -lt 2 ]]; then
        return 0
    fi

    if declare -F ui_count_inc >/dev/null 2>&1; then
        ui_count_inc "$badge"
    fi
    print_task "$badge" "$text" "$duration" "$reason"
    if [[ "$badge" == "FAIL" ]]; then
        [[ -z "$reason" ]] && reason="see debug.log"
        record_incident "FAIL" "$text" "$reason"
    elif [[ "$badge" == "WARN" ]] && [[ -n "$reason" ]]; then
        record_incident "WARN" "$text" "$reason"
    fi
}

# Error that always shows (even in quiet mode)
# Usage: _print_error "something failed"
_print_error() {
    local msg="$1"
    _ui_live_break_if_needed
    printf "%b[FAIL]%b %s\n" "${bred:-}" "${reset:-}" "$msg" >&2
}

# Thin decorative rule (replaces heavy ###...### separators)
# Usage: _print_rule
_print_rule() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    printf "%b──────────────────────────────────────────────────────────────%b\n" "${bgreen:-}" "${reset:-}"
}

###############################################################################
# Notifications
###############################################################################

# Show skip notification for disabled/already-processed functions
# Usage: skip_notification reason
# reason: "disabled" | "processed" | custom message
skip_notification() {
    local func_name="${FUNCNAME[1]:-unknown}"
    local reason="${1:-mode or configuration settings}"
    local badge="SKIP"
    local reason_code="config"

    case "$reason" in
        disabled)
            reason="mode or configuration settings"
            ;;
        processed)
            reason="already processed"
            badge="CACHE"
            reason_code="cache"
            ;;
        noinput)
            reason="missing required input data"
            reason_code="noinput"
            ;;
    esac

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        _print_status "$badge" "$func_name" "0s"
        if [[ "$badge" == "SKIP" ]]; then
            printf "         reason: %s\n" "$reason_code"
        elif [[ "$badge" == "CACHE" ]] && [[ "${SHOW_CACHE:-false}" == "true" ]]; then
            printf "         reason: %s\n" "$reason_code"
        fi
        if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
            if [[ "$badge" == "CACHE" ]]; then
                _print_msg INFO "${func_name} already processed. To force re-run, delete: ${called_fn_dir:-.}/.${func_name}"
            else
                _print_msg INFO "${func_name} skipped: ${reason}"
            fi
        fi
    fi

    # Emit skip marker for parent process (parallel mode)
    if [[ -n "${called_fn_dir:-}" ]]; then
        printf "%s\n" "$reason_code" >"${called_fn_dir}/.status_reason_${func_name}" 2>/dev/null || true
        if [[ "$badge" == "CACHE" ]]; then
            : >"${called_fn_dir}/.cache_${func_name}" 2>/dev/null || true
        else
            : >"${called_fn_dir}/.skip_${func_name}" 2>/dev/null || true
        fi
    fi
}

# Compatibility: map pt_msg_warn to new status model
pt_msg_warn() {
    local msg="$*"
    if [[ "$msg" == *"already processed"* ]]; then
        _print_status CACHE "${FUNCNAME[1]:-module}" "0s"
        if [[ -n "${called_fn_dir:-}" ]]; then
            : >"${called_fn_dir}/.cache_${FUNCNAME[1]:-module}" 2>/dev/null || true
        fi
    elif [[ "$msg" == *"skipped"* ]]; then
        _print_status SKIP "${FUNCNAME[1]:-module}" "0s"
        if [[ -n "${called_fn_dir:-}" ]]; then
            : >"${called_fn_dir}/.skip_${FUNCNAME[1]:-module}" 2>/dev/null || true
        fi
    else
        _print_status WARN "${FUNCNAME[1]:-module}" "0s"
        _print_msg WARN "$msg"
    fi
}

# Wrapper for skip notification when function is disabled
# Usage: skip_if_disabled && return
skip_if_disabled() {
    skip_notification "disabled"
}

# Wrapper for skip notification when function was already processed
# Usage: skip_if_processed && return  
skip_if_processed() {
    skip_notification "processed"
}

###############################################################################
# Command Execution Helpers
###############################################################################

# Execute a command with optional dry-run support and logging
# Usage: run_tool tool_name command [args...]
# Respects DRY_RUN and LOGFILE variables
run_tool() {
    local name="$1"
    shift

    if [[ ${DRY_RUN:-false} == true ]]; then
        local full_cmd="$name $*"

        # Track command for module summary
        if declare -F ui_dryrun_track >/dev/null 2>&1; then
            ui_dryrun_track "$name" "$full_cmd"
        else
            # Fallback to old behavior if ui_dryrun_track not available
            printf "%b[DRY-RUN] Would execute: %s %s%b\n" "${cyan:-}" "$name" "$*" "${reset:-}"
        fi
        return 0
    fi

    # Log the command if LOGFILE is set
    if [[ -n "${LOGFILE:-}" ]]; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Running: $name $*" >> "$LOGFILE"
    fi

    "$@"
}

# Remove ANSI/control sequences from a text stream.
# Usage: some_command | strip_ansi_stream
strip_ansi_stream() {
    # CSI + OSC sequence stripping, keeping regular text intact.
    sed -E $'s/\x1B\\[[0-9;?]*[ -/]*[@-~]//g; s/\x1B\\][^\a]*(\a|\x1B\\\\)//g'
}

# Run a command with periodic heartbeat status lines for long-running tasks.
# Usage: run_with_heartbeat "label" [interval_seconds] command [args...]
run_with_heartbeat() {
    local label="${1:-task}"
    shift
    local interval="${HEARTBEAT_INTERVAL_SECONDS:-20}"
    if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
        interval="$1"
        shift
    fi

    if [[ $# -eq 0 ]]; then
        return 1
    fi

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        run_command "$@"
        return $?
    fi

    local start_ts now_ts elapsed last_hb
    local use_live=false
    start_ts=$(date +%s)
    last_hb="$start_ts"

    local hb_log="/dev/null"
    if [[ -n "${LOGFILE:-}" ]]; then
        hb_log="$LOGFILE"
    fi

    run_command "$@" >>"$hb_log" 2>&1 &
    local cmd_pid=$!

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        if declare -F ui_is_tty >/dev/null 2>&1 && ui_is_tty && declare -F ui_live_progress_begin >/dev/null 2>&1; then
            use_live=true
            ui_live_progress_begin
            if declare -F ui_live_progress_update >/dev/null 2>&1; then
                ui_live_progress_update "Running: ${label} | elapsed 0s | ETA: --"
            fi
        else
            printf "Started: %s\n" "$label"
        fi
    fi

    while kill -0 "$cmd_pid" 2>/dev/null; do
        sleep 1
        now_ts=$(date +%s)
        if ((now_ts - last_hb >= interval)); then
            elapsed=$((now_ts - start_ts))
            if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]] && [[ "$use_live" == true ]] && declare -F ui_live_progress_update >/dev/null 2>&1; then
                ui_live_progress_update "Running: ${label} | elapsed $(format_duration "$elapsed") | ETA: --"
            fi
            last_hb="$now_ts"
        fi
    done

    wait "$cmd_pid"
    local rc=$?
    elapsed=$(($(date +%s) - start_ts))

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        if [[ "$use_live" == true ]] && declare -F ui_live_progress_end >/dev/null 2>&1; then
            ui_live_progress_end
        else
            printf "Completed: %s (%s)\n" "$label" "$(format_duration "$elapsed")"
        fi
    fi

    return "$rc"
}

# Shell-string variant for commands that require complex redirections.
# Usage: run_with_heartbeat_shell "label" "command string"
run_with_heartbeat_shell() {
    local label="${1:-task}"
    local shell_cmd="${2:-}"
    if [[ -z "$shell_cmd" ]]; then
        return 1
    fi
    run_with_heartbeat "$label" /bin/bash -lc "$shell_cmd"
}

# Execute command and capture line count result with validation
# Usage: NUMOFLINES=$(safe_count "command | pipeline")
# Always returns a valid number (0 on failure)
safe_count() {
    local result
    result=$(eval "$1" 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ') || result=0
    [[ "$result" =~ ^[0-9]+$ ]] || result=0
    echo "$result"
}

###############################################################################
# Pipeline Helpers
###############################################################################

# Process results: deduplicate, count new entries, and return count
# Usage: NUMOFLINES=$(process_results input_file output_file)
process_results() {
    local input="$1"
    local output="$2"
    local count=0
    
    if [[ -s "$input" ]]; then
        if command -v anew &>/dev/null; then
            count=$(anew "$output" < "$input" 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')
        else
            count=$(cat "$input" >> "$output" && wc -l < "$input" | tr -d ' ')
        fi
    fi
    
    [[ "$count" =~ ^[0-9]+$ ]] || count=0
    echo "$count"
}

# Filter results by domain and process
# Usage: NUMOFLINES=$(filter_and_process input_file output_file domain)
filter_and_process() {
    local input="$1"
    local output="$2"
    local domain="$3"
    local count=0
    
    if [[ -s "$input" ]]; then
        local escaped
        escaped=$(escape_domain_regex "$domain")
        count=$(grep "\\.${escaped}$\\|^${escaped}$" "$input" 2>/dev/null \
            | anew "$output" 2>/dev/null \
            | sed '/^$/d' \
            | wc -l | tr -d ' ')
    fi
    
    [[ "$count" =~ ^[0-9]+$ ]] || count=0
    echo "$count"
}

###############################################################################
# Domain Matching Helpers
###############################################################################

# Escape a domain name for safe use in grep regex patterns
# Dots are literal in domain names but regex metacharacters
# Usage: escaped=$(escape_domain_regex "example.com")
escape_domain_regex() {
    printf '%s' "$1" | sed 's/[.[\*^$()+?{|]/\\&/g'
}

# Grep lines matching a domain (as subdomain or exact match) with proper escaping
# Usage: grep_domain input_file domain [extra_grep_flags...]
# Matches: "*.domain" and "domain" exactly (anchored)
grep_domain() {
    local input="$1"
    local raw_domain="$2"
    shift 2
    local escaped
    escaped=$(escape_domain_regex "$raw_domain")
    grep "$@" "\.${escaped}$\|^${escaped}$" "$input"
}

###############################################################################
# Axiom/Local Execution Helper
###############################################################################

# Run a tool command, automatically choosing between local and axiom-scan
# Usage: run_scan <input_file> <output_file> <tool_name> [tool_args...]
# Example: run_scan .tmp/input.txt .tmp/output.txt subfinder -silent
# With AXIOM: axiom-scan input -m tool args -o output $AXIOM_EXTRA_ARGS
# Without:    tool args < input > output (or with -o flag)
run_scan() {
    local input="$1"
    local output="$2"
    local tool="$3"
    shift 3

    if [[ ${AXIOM:-false} == true ]]; then
        axiom-scan "$input" -m "$tool" "$@" -o "$output" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
    else
        "$tool" "$@" -o "$output" <"$input" 2>>"$LOGFILE" >/dev/null
    fi
}

###############################################################################
# Function Gate Helper
###############################################################################

# Check if a function should run based on its flag and checkpoint
# Usage: if should_run "FLAG_VAR_NAME"; then ... fi
# Replaces the repeated pattern:
#   if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FLAG == true ]]; then
should_run() {
    local flag_var="$1"
    local func_name="${FUNCNAME[1]:-unknown}"
    local checkpoint_file="${called_fn_dir:-.}/.${func_name}"

    # Check if feature flag is enabled
    if [[ "${!flag_var:-false}" != true ]]; then
        return 1
    fi

    # Check if already processed (unless DIFF mode)
    if [[ -f "$checkpoint_file" ]] && [[ ${DIFF:-false} != true ]]; then
        return 1
    fi

    return 0
}

###############################################################################
# Validation Helpers
###############################################################################

# Check if we should run a function (not already processed or DIFF mode)
# Usage: if should_run_function; then ... fi
should_run_function() {
    local func_name="${FUNCNAME[1]:-unknown}"
    local checkpoint_file="${called_fn_dir:-.}/.${func_name}"
    
    # Run if checkpoint doesn't exist or we're in DIFF mode
    [[ ! -f "$checkpoint_file" ]] || [[ ${DIFF:-false} == true ]]
}

# Standard function gate check - combines enabled check with checkpoint
# Usage: if ! gate_function ENABLED_VAR; then skip_notification "disabled"; return; fi
gate_function() {
    local enabled_var="$1"
    local func_name="${FUNCNAME[1]:-unknown}"
    
    # Check if the feature is enabled
    if [[ "${!enabled_var:-false}" != true ]]; then
        return 1
    fi
    
    # Check if already processed (unless DIFF mode)
    if ! should_run_function; then
        return 1
    fi
    
    return 0
}
