#!/usr/bin/env bash
# lib/common.sh - Common utility functions to reduce code duplication
# Part of reconFTW refactoring - Phase 2

# Prevent multiple sourcing
[[ -n "$_COMMON_SH_LOADED" ]] && return 0
declare -r _COMMON_SH_LOADED=1

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

# Generic message with [LEVEL] prefix (INFO/WARN/FAIL/OK)
# Usage: _print_msg WARN "something happened"
_print_msg() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    local level="$1"
    shift
    local msg="$*"
    local color
    
    case "$level" in
        OK|SUCCESS) color="${bgreen:-}" ;;
        WARN) color="${yellow:-}" ;;
        FAIL|ERROR) color="${bred:-}" ;;
        INFO) color="${bblue:-}" ;;
        *) color="${bblue:-}" ;;
    esac
    
    printf "%b[%s]%b %s\n" "$color" "$level" "${reset:-}" "$msg"
}

# Module start message with timestamp
# Usage: _print_module_start "OSINT"
_print_module_start() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    local title="${1^^}"
    local ts
    ts=$(date +'%Y-%m-%d %H:%M:%S')
    printf "\n%b── %s %s%b\n" "${bgreen:-}" "$title" "──────────────────────────────────────────────────────────────" "${reset:-}"
    _print_msg "INFO" "${title} started at ${ts}"
}

# Module end message with timestamp
# Usage: _print_module_end "OSINT"
_print_module_end() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    local title="${1^^}"
    local ts
    ts=$(date +'%Y-%m-%d %H:%M:%S')
    _print_msg "INFO" "${title} completed at ${ts}"
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
    local color
    
    # Special handling for SKIP to be more discrete
    if [[ "$badge" == "SKIP" ]]; then
        local text_len=${#text}
        local dot_count=$((50 - text_len))
        ((dot_count < 2)) && dot_count=2
        local dots
        dots=$(printf '%*s' "$dot_count" '' | tr ' ' '.')
        
        # Grey/dim style for SKIP if supported, otherwise blue
        local skip_color="${bblue:-}"
        
        if [[ -n "$detail" ]]; then
            printf "  %s %s %b[SKIP]%b %s\n" "$text" "$dots" "$skip_color" "${reset:-}" "$detail"
        else
            printf "  %s %s %b[SKIP]%b\n" "$text" "$dots" "$skip_color" "${reset:-}"
        fi
        return
    fi

    case "$badge" in
        OK)   color="${bgreen:-}" ;;
        FAIL) color="${bred:-}" ;;
        WARN) color="${yellow:-}" ;;
        *)    color="${bblue:-}" ;;
    esac
    
    if [[ -n "$detail" ]]; then
        local text_len=${#text}
        local dot_count=$((40 - text_len))
        ((dot_count < 2)) && dot_count=2
        local dots
        dots=$(printf '%*s' "$dot_count" '' | tr ' ' '.')
        printf "  %b[%-4s]%b %s %s %6s\n" "$color" "$badge" "${reset:-}" "$text" "$dots" "$detail"
    else
        printf "  %b[%-4s]%b %s\n" "$color" "$badge" "${reset:-}" "$text"
    fi
}

# Error that always shows (even in quiet mode)
# Usage: _print_error "something failed"
_print_error() {
    local msg="$1"
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

    case "$reason" in
        disabled)
            reason="mode or configuration settings"
            ;;
        processed)
            reason="already processed"
            ;;
    esac

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        _print_status SKIP "$func_name"
        if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
            printf "         %s\n" "$reason"
            if [[ "$reason" == "already processed" ]]; then
                printf "         To force re-run, delete: %s/.%s\n" "${called_fn_dir:-.}" "$func_name"
            fi
        fi
    fi

    # Track skip for summary if UI layer is available
    if declare -F ui_count_inc >/dev/null 2>&1; then
        ui_count_inc SKIP
    fi

    # Emit skip marker for parent process (parallel mode)
    if [[ -n "${called_fn_dir:-}" ]]; then
        : >"${called_fn_dir}/.skip_${func_name}" 2>/dev/null || true
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
        printf "%b[DRY-RUN] Would execute: %s %s%b\n" "${cyan:-}" "$name" "$*" "${reset:-}"
        return 0
    fi
    
    # Log the command if LOGFILE is set
    if [[ -n "${LOGFILE:-}" ]]; then
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Running: $name $*" >> "$LOGFILE"
    fi
    
    "$@"
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
