#!/bin/bash
# reconFTW - Utility functions module
# Contains: deleteOutScoped, cleanup, rotate_logs, sanitization, validation,
#           getElapsedTime, retry, disk check, rate limiting, caching
# This file is sourced by reconftw.sh - do not execute directly
[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by reconftw.sh" >&2
    exit 1
}

###############################################################################################################
########################################## OPTIONS & MGMT #####################################################
###############################################################################################################

function deleteOutScoped() {
    if [[ -s "$1" ]]; then
        while IFS= read -r outscoped; do
            [[ -z "$outscoped" ]] && continue
            # Escape regex metacharacters to prevent injection
            local escaped
            escaped=$(printf '%s' "$outscoped" | sed 's/[.[\*^$()+?{|\\]/\\&/g')
            if grep -q "^[*]" <<<"$outscoped"; then
                escaped=$(printf '%s' "${outscoped:1}" | sed 's/[.[\*^$()+?{|\\]/\\&/g')
                sed_i "/${escaped}$/d" "$2"
            else
                sed_i "/${escaped}/d" "$2"
            fi
        done <"$1"
    fi
}

function cleanup_on_exit() {
    printf "\n%b[%s] Interrupted. Cleaning up...%b\n" "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
    # Clean temporary chunk files
    rm -rf -- "${dir:-.}/.tmp/chunks" 2>/dev/null
    # Kill any background processes we spawned
    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
    # Log the interruption
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Interrupted by signal" >>"${LOGFILE:-/dev/null}"
    exit 130
}

function rotate_logs() {
    local log_dir="$1"
    local max_logs="${2:-10}"
    local max_age_days="${3:-30}"

    [[ ! -d "$log_dir" ]] && return 0

    # Delete logs older than max_age_days
    find "$log_dir" -name "*.txt" -type f -mtime +"${max_age_days}" -delete 2>/dev/null || true

    # If still too many, keep only the newest max_logs
    local count
    count=$(find "$log_dir" -name "*.txt" -type f 2>/dev/null | wc -l)
    if [[ $count -gt $max_logs ]]; then
        find "$log_dir" -name "*.txt" -type f -printf '%T@ %p\n' 2>/dev/null \
            | sort -n | head -n $((count - max_logs)) | cut -d' ' -f2- \
            | xargs -r rm -f -- 2>/dev/null || true
    fi
}

function sanitize_interlace_input() {
    # Remove lines containing shell metacharacters that could be exploited
    # via interlace template substitution (_target_, _output_, _cleantarget_)
    local infile="$1"
    local outfile="${2:-$1}"
    if [[ "$infile" == "$outfile" ]]; then
        local tmpfile
        tmpfile=$(mktemp)
        grep -v '[;|&$`\\(){}]' "$infile" >"$tmpfile" 2>/dev/null || true
        mv "$tmpfile" "$outfile"
    else
        grep -v '[;|&$`\\(){}]' "$infile" >"$outfile" 2>/dev/null || true
    fi
}

function validate_config() {
    local warnings=0
    local errors=0

    # Check conflicting configs
    if [[ ${VULNS_GENERAL:-false} == true && ${SUBDOMAINS_GENERAL:-false} == false ]]; then
        printf "%b[WARN] VULNS_GENERAL=true but SUBDOMAINS_GENERAL=false -- vulnerability scans need subdomain data%b\n" "$yellow" "$reset"
        warnings=$((warnings + 1))
    fi

    # Validate numeric thread/rate variables
    for var in FFUF_THREADS HTTPX_THREADS DALFOX_THREADS KATANA_THREADS HTTPX_RATELIMIT NUCLEI_RATELIMIT FFUF_RATELIMIT; do
        if [[ -n "${!var:-}" && ! "${!var}" =~ ^[0-9]+$ ]]; then
            printf "%b[ERROR] %s must be numeric, got: %s%b\n" "$bred" "$var" "${!var}" "$reset"
            errors=$((errors + 1))
        fi
    done

    # Check Axiom tool availability if enabled
    if [[ ${AXIOM:-false} == true ]] && ! command -v axiom-scan >/dev/null 2>&1; then
        printf "%b[WARN] AXIOM=true but axiom-scan not found in PATH%b\n" "$yellow" "$reset"
        warnings=$((warnings + 1))
    fi

    if [[ $errors -gt 0 ]]; then
        printf "%b[ERROR] Configuration has %d error(s). Please fix before running.%b\n" "$bred" "$errors" "$reset"
        return $E_CONFIG
    fi
    if [[ $warnings -gt 0 ]]; then
        printf "%b[INFO] Configuration has %d warning(s).%b\n" "$yellow" "$warnings" "$reset"
    fi
    return 0
}

function getElapsedTime {
    runtime=""
    local T=$2-$1
    local D=$((T / 60 / 60 / 24))
    local H=$((T / 60 / 60 % 24))
    local M=$((T / 60 % 60))
    local S=$((T % 60))
    ((D > 0)) && runtime="$runtime$D days, "
    ((H > 0)) && runtime="$runtime$H hours, "
    ((M > 0)) && runtime="$runtime$M minutes, "
    runtime="$runtime$S seconds."
}

# Retry with exponential backoff
# Usage: retry_with_backoff <max_attempts> <command> [args...]
# Example: retry_with_backoff 3 curl -s "https://example.com"
function retry_with_backoff() {
    local max_attempts="$1"
    shift
    local attempt=1
    local delay=1
    local max_delay=60

    while [ $attempt -le "$max_attempts" ]; do
        if "$@"; then
            return 0
        fi

        if [ $attempt -lt "$max_attempts" ]; then
            printf "%b[%s] Attempt %d/%d failed. Retrying in %d seconds...%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$attempt" "$max_attempts" "$delay" "$reset" >>"$LOGFILE"
            sleep "$delay"

            # Exponential backoff with max cap
            delay=$((delay * 2))
            if [ $delay -gt $max_delay ]; then
                delay=$max_delay
            fi
        fi

        attempt=$((attempt + 1))
    done

    printf "%b[%s] Command failed after %d attempts: %s%b\n" \
        "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$max_attempts" "$*" "$reset" >>"$LOGFILE"
    return 1
}

# Check available disk space
# Usage: check_disk_space <required_gb> <path>
# Returns 0 if enough space, 1 otherwise
function check_disk_space() {
    local required_gb="$1"
    local check_path="${2:-.}"

    # Get available space in GB
    local available_gb
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        available_gb=$(df -g "$check_path" | awk 'NR==2 {print $4}')
    else
        # Linux
        available_gb=$(df -BG "$check_path" | awk 'NR==2 {gsub(/G/, "", $4); print $4}')
    fi

    if [ -z "$available_gb" ] || [ "$available_gb" -lt "$required_gb" ]; then
        printf "%b[%s] WARNING: Insufficient disk space. Required: %dGB, Available: %dGB at %s%b\n" \
            "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$required_gb" "${available_gb:-0}" "$check_path" "$reset"
        return 1
    fi

    printf "%b[%s] Disk space OK: %dGB available at %s%b\n" \
        "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$available_gb" "$check_path" "$reset"
    return 0
}

# Show progress bar for operations
# Usage: progress_bar <current> <total> <message>
function progress_bar() {
    local current=$1
    local total=$2
    local message="${3:-Processing}"
    local width=50

    # Calculate percentage
    local percent=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))

    # Build progress bar
    local bar=""
    for ((i = 0; i < filled; i++)); do bar="${bar}█"; done
    for ((i = 0; i < empty; i++)); do bar="${bar}░"; done

    # Print progress (using \r to overwrite the line)
    printf "\r%b[%s] %s [%s] %d%% (%d/%d)%b" \
        "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$message" "$bar" "$percent" "$current" "$total" "$reset"

    # Print newline when complete
    if [ "$current" -eq "$total" ]; then
        printf "\n"
    fi
}

# Execute command in dry-run mode if enabled
# Usage: run_command <command> [args...]
function run_command() {
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        printf "%b[DRY-RUN] Would execute: %s%b\n" "$yellow" "$*" "$reset"
        return 0
    fi

    if [[ "${ADAPTIVE_RATE_LIMIT:-false}" == "true" ]]; then
        run_with_adaptive_rate "$@"
    else
        "$@"
    fi
}

# Cross-platform sed_i wrapper
# Usage: sed_i 's/old/new/g' file.txt
# Works on both macOS (BSD sed) and Linux (GNU sed)
function sed_i() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: sed_i 'pattern' file" >&2
        return 1
    fi

    local pattern="$1"
    local file="$2"

    # Check if we're using GNU sed or BSD sed
    if sed --version >/dev/null 2>&1; then
        # GNU sed (Linux or installed via brew on macOS)
        sed -i "$pattern" "$file"
    else
        # BSD sed (default macOS)
        sed -i '' "$pattern" "$file"
    fi
}

###############################################################################################################
#################################### RATE LIMITING ADAPTATIVO #################################################
###############################################################################################################

# Adaptive rate limiting - detects rate limit errors and adjusts automatically
# Global variables for rate limiting
ADAPTIVE_RATE_LIMIT=${ADAPTIVE_RATE_LIMIT:-false}
CURRENT_RATE_LIMIT=${NUCLEI_RATELIMIT:-150}
MIN_RATE_LIMIT=10
MAX_RATE_LIMIT=500
RATE_LIMIT_BACKOFF_FACTOR=0.5
RATE_LIMIT_INCREASE_FACTOR=1.2

# Detect rate limit errors in command output
# Usage: detect_rate_limit_error <output_file_or_string>
function detect_rate_limit_error() {
    local output="$1"

    # Check for common rate limit indicators
    if grep -qiE "(429|too many requests|rate limit|limit exceeded|503|service unavailable)" <<<"$output"; then
        return 0 # Rate limit detected
    fi
    return 1 # No rate limit detected
}

# Adjust rate limit based on errors
# Usage: adjust_rate_limit <increase|decrease>
function adjust_rate_limit() {
    local action="$1"

    [[ "$ADAPTIVE_RATE_LIMIT" != "true" ]] && return 0

    case "$action" in
        decrease)
            local new_limit=$(awk "BEGIN {printf \"%.0f\", $CURRENT_RATE_LIMIT * $RATE_LIMIT_BACKOFF_FACTOR}")
            if [ "$new_limit" -lt "$MIN_RATE_LIMIT" ]; then
                new_limit=$MIN_RATE_LIMIT
            fi
            CURRENT_RATE_LIMIT=$new_limit
            printf "%b[%s] Rate limit decreased to %d req/s due to errors%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$CURRENT_RATE_LIMIT" "$reset" | tee -a "$LOGFILE"
            ;;
        increase)
            local new_limit=$(awk "BEGIN {printf \"%.0f\", $CURRENT_RATE_LIMIT * $RATE_LIMIT_INCREASE_FACTOR}")
            if [ "$new_limit" -gt "$MAX_RATE_LIMIT" ]; then
                new_limit=$MAX_RATE_LIMIT
            fi
            CURRENT_RATE_LIMIT=$new_limit
            printf "%b[%s] Rate limit increased to %d req/s%b\n" \
                "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$CURRENT_RATE_LIMIT" "$reset" >>"$LOGFILE"
            ;;
    esac

    # Update tool-specific rate limits
    NUCLEI_RATELIMIT=$CURRENT_RATE_LIMIT
    FFUF_RATELIMIT=$CURRENT_RATE_LIMIT
    HTTPX_RATELIMIT=$CURRENT_RATE_LIMIT
}

# Execute command with adaptive rate limiting
# Usage: run_with_adaptive_rate <command> [args...]
function run_with_adaptive_rate() {
    [[ "$ADAPTIVE_RATE_LIMIT" != "true" ]] && {
        "$@"
        return $?
    }

    local max_retries=3
    local retry=0
    local temp_output=$(mktemp)

    while [ $retry -lt $max_retries ]; do
        if "$@" 2>&1 | tee "$temp_output"; then
            # Command succeeded, check if we can increase rate
            if [ $retry -eq 0 ]; then
                adjust_rate_limit increase
            fi
            rm -f "$temp_output"
            return 0
        fi

        # Check if failure was due to rate limiting
        if detect_rate_limit_error "$(cat "$temp_output")"; then
            adjust_rate_limit decrease
            retry=$((retry + 1))
            if [ $retry -lt $max_retries ]; then
                printf "%b[%s] Retrying with lower rate limit (%d/%d)...%b\n" \
                    "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$retry" "$max_retries" "$reset" | tee -a "$LOGFILE"
                sleep 2
            fi
        else
            # Non rate-limit error, don't retry
            rm -f "$temp_output"
            return 1
        fi
    done

    rm -f "$temp_output"
    return 1
}

###############################################################################################################
####################################### SECURITY ################################################
###############################################################################################################

# Sanitize domain input to prevent command injection
# Usage: sanitize_domain <domain>
# Returns: sanitized domain string (lowercase)
function sanitize_domain() {
    local input_domain="$1"

    # Remove any characters that are not alphanumeric, dots, or hyphens
    # This prevents command injection via malicious domain names
    local sanitized
    sanitized=$(echo "$input_domain" | tr -cd 'a-zA-Z0-9.-')

    # Convert to lowercase for consistency
    sanitized=$(echo "$sanitized" | tr '[:upper:]' '[:lower:]')

    # Remove leading/trailing dots and hyphens
    sanitized=$(echo "$sanitized" | sed 's/^[.-]*//; s/[.-]*$//')

    # Check if domain is empty after sanitization
    if [[ -z "$sanitized" ]]; then
        printf "%b[%s] ERROR: Invalid domain after sanitization: '%s'%b\n" \
            "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$input_domain" "$reset" >&2
        return 1
    fi

    # Check for basic domain format (at least one dot for TLD)
    if [[ ! "$sanitized" =~ \. ]]; then
        printf "%b[%s] WARNING: Domain '%s' has no TLD, may be invalid%b\n" \
            "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$sanitized" "$reset" >&2
    fi

    # If sanitization removed characters, warn user
    if [[ "$input_domain" != "$sanitized" ]]; then
        printf "%b[%s] INFO: Domain sanitized from '%s' to '%s'%b\n" \
            "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$input_domain" "$sanitized" "$reset" >&2
    fi

    echo "$sanitized"
    return 0
}

# Validate and sanitize IP/CIDR input
# Usage: sanitize_ip <ip_or_cidr>
function sanitize_ip() {
    local input="$1"

    # Allow digits, dots, and slash for CIDR
    local sanitized=$(echo "$input" | tr -cd '0-9./,')

    if [[ -z "$sanitized" ]]; then
        printf "%b[%s] ERROR: Invalid IP/CIDR after sanitization: '%s'%b\n" \
            "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$input" "$reset" >&2
        return 1
    fi

    echo "$sanitized"
    return 0
}

###############################################################################################################
####################################### DEEP/AXIOM HELPERS ####################################################
###############################################################################################################

# Check if we should run in DEEP mode based on flag or item count
# Usage: should_run_deep <count> [limit]
# Returns: 0 if should run deep, 1 otherwise
function should_run_deep() {
    local count="${1:-0}"
    local limit="${2:-$DEEP_LIMIT}"

    [[ "$DEEP" == true ]] && return 0
    [[ "$count" -le "$limit" ]] && return 0
    return 1
}

# Check if we should run in DEEP mode with custom limit
# Usage: should_run_deep2 <count>
# Returns: 0 if should run deep, 1 otherwise
function should_run_deep2() {
    local count="${1:-0}"
    should_run_deep "$count" "${DEEP_LIMIT2:-500}"
}

###############################################################################################################
####################################### CACHÉ DE RECURSOS #####################################################
###############################################################################################################

CACHE_DIR="${SCRIPTPATH}/.cache"
CACHE_MAX_AGE_DAYS=30 # 1 month

# Initialize cache directory
function cache_init() {
    mkdir -p "$CACHE_DIR"/{wordlists,resolvers,tools}
}

# Check if cached file is still valid (less than 30 days old)
# Usage: cache_is_valid <cache_file>
# Returns: 0 if valid, 1 if expired or missing
function cache_is_valid() {
    local cache_file="$1"

    [[ ! -f "$cache_file" ]] && return 1

    # Get file age in days
    local file_age_seconds
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        file_age_seconds=$(($(date +%s) - $(stat -f %m "$cache_file")))
    else
        # Linux
        file_age_seconds=$(($(date +%s) - $(stat -c %Y "$cache_file")))
    fi

    local file_age_days=$((file_age_seconds / 86400))

    if [ $file_age_days -lt $CACHE_MAX_AGE_DAYS ]; then
        printf "%b[%s] Using cached file (age: %d days): %s%b\n" \
            "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$file_age_days" "$(basename "$cache_file")" "$reset" >>"$LOGFILE"
        return 0
    else
        printf "%b[%s] Cache expired (age: %d days): %s%b\n" \
            "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$file_age_days" "$(basename "$cache_file")" "$reset" >>"$LOGFILE"
        return 1
    fi
}

# Download file with caching support
# Usage: cached_download <url> <destination> [cache_name]
# If cache exists and is valid, copies from cache instead of downloading
function cached_download() {
    local url="$1"
    local destination="$2"
    local cache_name="${3:-$(basename "$url")}"
    local cache_file="$CACHE_DIR/$cache_name"

    cache_init

    # Check if we have valid cached version
    if cache_is_valid "$cache_file"; then
        cp "$cache_file" "$destination"
        return 0
    fi

    # Download fresh copy
    printf "%b[%s] Downloading: %s%b\n" \
        "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$(basename "$url")" "$reset"

    if curl -sL "$url" -o "$destination"; then
        # Save to cache for future use
        cp "$destination" "$cache_file"
        printf "%b[%s] Cached for future use: %s%b\n" \
            "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$cache_name" "$reset" >>"$LOGFILE"
        return 0
    else
        printf "%b[%s] Download failed: %s%b\n" \
            "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$url" "$reset" >&2
        return 1
    fi
}

# Clear old cache files
# Usage: cache_clean [max_age_days]
function cache_clean() {
    local max_age="${1:-$CACHE_MAX_AGE_DAYS}"

    [[ ! -d "$CACHE_DIR" ]] && return 0

    local cleaned=0
    while IFS= read -r -d '' file; do
        local file_age_seconds
        if [[ "$OSTYPE" == "darwin"* ]]; then
            file_age_seconds=$(($(date +%s) - $(stat -f %m "$file")))
        else
            file_age_seconds=$(($(date +%s) - $(stat -c %Y "$file")))
        fi

        local file_age_days=$((file_age_seconds / 86400))

        if [ $file_age_days -gt $max_age ]; then
            rm -f "$file"
            cleaned=$((cleaned + 1))
        fi
    done < <(find "$CACHE_DIR" -type f -print0 2>/dev/null)

    if [ $cleaned -gt 0 ]; then
        printf "%b[%s] Cleaned %d expired cache files%b\n" \
            "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$cleaned" "$reset"
    fi
}

###############################################################################################################
####################################### CHECKPOINT SYSTEM #####################################################
###############################################################################################################

# Checkpoint system for scan recovery
# Allows resuming scans from the last completed phase after interruption
CHECKPOINT_DIR=""
CHECKPOINT_ENABLED=${CHECKPOINT_ENABLED:-true}

# Initialize checkpoint system for a scan
# Usage: checkpoint_init
function checkpoint_init() {
    [[ "$CHECKPOINT_ENABLED" != "true" ]] && return 0
    [[ -z "${dir:-}" ]] && return 1

    CHECKPOINT_DIR="${dir}/.checkpoints"
    mkdir -p "$CHECKPOINT_DIR"

    # Save scan metadata
    {
        echo "domain=${domain:-unknown}"
        echo "started=$(date -Iseconds)"
        echo "mode=${MODE:-unknown}"
        echo "deep=${DEEP:-false}"
    } >"$CHECKPOINT_DIR/scan_info.txt"

    printf "%b[%s] Checkpoint system initialized%b\n" \
        "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset" >>"${LOGFILE:-/dev/null}"
}

# Save a checkpoint after completing a phase
# Usage: checkpoint_save <phase_name>
function checkpoint_save() {
    [[ "$CHECKPOINT_ENABLED" != "true" ]] && return 0
    [[ -z "$CHECKPOINT_DIR" ]] && return 1

    local phase="$1"
    local checkpoint_file="$CHECKPOINT_DIR/${phase}.done"

    # Save phase completion with timestamp
    {
        echo "phase=$phase"
        echo "completed=$(date -Iseconds)"
        echo "status=completed"
    } >"$checkpoint_file"

    printf "%b[%s] Checkpoint saved: %s%b\n" \
        "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$phase" "$reset" >>"${LOGFILE:-/dev/null}"
}

# Check if a phase checkpoint exists (already completed)
# Usage: checkpoint_exists <phase_name>
# Returns: 0 if checkpoint exists, 1 if not
function checkpoint_exists() {
    [[ "$CHECKPOINT_ENABLED" != "true" ]] && return 1
    [[ -z "$CHECKPOINT_DIR" ]] && return 1

    local phase="$1"
    [[ -f "$CHECKPOINT_DIR/${phase}.done" ]]
}

# List completed checkpoints
# Usage: checkpoint_list
function checkpoint_list() {
    [[ -z "$CHECKPOINT_DIR" ]] && return 1
    [[ ! -d "$CHECKPOINT_DIR" ]] && return 1

    printf "%b[%s] Completed phases:%b\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
    for f in "$CHECKPOINT_DIR"/*.done; do
        [[ -f "$f" ]] || continue
        local phase
        phase=$(basename "$f" .done)
        local completed
        completed=$(grep "^completed=" "$f" 2>/dev/null | cut -d= -f2)
        printf "  - %s (completed: %s)\n" "$phase" "${completed:-unknown}"
    done
}

# Clear all checkpoints (for fresh scan)
# Usage: checkpoint_clear
function checkpoint_clear() {
    [[ -z "$CHECKPOINT_DIR" ]] && return 1

    rm -rf "$CHECKPOINT_DIR"
    mkdir -p "$CHECKPOINT_DIR"

    printf "%b[%s] Checkpoints cleared%b\n" \
        "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
}

###############################################################################################################
####################################### CIRCUIT BREAKER #######################################################
###############################################################################################################

# Circuit breaker pattern for unreliable external tools
# Prevents repeated calls to tools that are consistently failing
declare -A CIRCUIT_BREAKER_FAILURES
declare -A CIRCUIT_BREAKER_STATE
CIRCUIT_BREAKER_THRESHOLD=${CIRCUIT_BREAKER_THRESHOLD:-3}
CIRCUIT_BREAKER_TIMEOUT=${CIRCUIT_BREAKER_TIMEOUT:-300}  # 5 minutes

# Check if a tool's circuit breaker is open (should skip)
# Usage: circuit_breaker_is_open <tool_name>
# Returns: 0 if open (skip tool), 1 if closed (run tool)
function circuit_breaker_is_open() {
    local tool="$1"
    local state="${CIRCUIT_BREAKER_STATE[$tool]:-closed}"
    local failures="${CIRCUIT_BREAKER_FAILURES[$tool]:-0}"

    if [[ "$state" == "open" ]]; then
        # Check if timeout has passed
        local opened_at="${CIRCUIT_BREAKER_STATE[${tool}_opened]:-0}"
        local now
        now=$(date +%s)
        if (( now - opened_at > CIRCUIT_BREAKER_TIMEOUT )); then
            # Reset to half-open (allow one retry)
            CIRCUIT_BREAKER_STATE[$tool]="half-open"
            return 1  # Allow retry
        fi
        printf "%b[%s] Circuit breaker OPEN for %s (skipping)%b\n" \
            "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$tool" "$reset" >>"${LOGFILE:-/dev/null}"
        return 0  # Skip
    fi

    return 1  # Run tool
}

# Record a tool failure
# Usage: circuit_breaker_record_failure <tool_name>
function circuit_breaker_record_failure() {
    local tool="$1"
    local failures="${CIRCUIT_BREAKER_FAILURES[$tool]:-0}"
    failures=$((failures + 1))
    CIRCUIT_BREAKER_FAILURES[$tool]=$failures

    if (( failures >= CIRCUIT_BREAKER_THRESHOLD )); then
        CIRCUIT_BREAKER_STATE[$tool]="open"
        CIRCUIT_BREAKER_STATE[${tool}_opened]=$(date +%s)
        printf "%b[%s] Circuit breaker OPENED for %s after %d failures%b\n" \
            "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$tool" "$failures" "$reset"
    fi
}

# Record a tool success (reset failure count)
# Usage: circuit_breaker_record_success <tool_name>
function circuit_breaker_record_success() {
    local tool="$1"
    CIRCUIT_BREAKER_FAILURES[$tool]=0
    CIRCUIT_BREAKER_STATE[$tool]="closed"
}
