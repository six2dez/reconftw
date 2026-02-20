#!/bin/bash
# reconFTW - Core framework module
# Contains: UI wrappers, banner, version check, tools check, logging,
#           output/notification, lifecycle (start_func/end_func), plugins, assets
# This file is sourced by reconftw.sh - do not execute directly

# shellcheck disable=SC2154  # Variables defined in reconftw.cfg

[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by reconftw.sh" >&2
    exit 1
}

# pt_header kept as no-op for backward compatibility (used by help())
pt_header() { :; }

# Ensure a safe default for early log redirections
# If LOGFILE is unset or empty, send logs to /dev/null until later initialization
: "${LOGFILE:=/dev/null}"

# List of environment variables containing secrets that should be redacted in logs
REDACT_VARS=(
    "SHODAN_API_KEY"
    "WHOISXML_API"
    "PDCP_API_KEY"
    "GITHUB_TOKEN"
    "GITLAB_TOKEN"
    "DISCORD_WEBHOOK_URL"
    "SLACK_WEBHOOK_URL"
    "slack_auth"
    "XSS_SERVER"
    "COLLAB_SERVER"
)

# redact_secrets()
# Description: Redacts sensitive values from a string
# Arguments: $1 - String to redact
# Returns: Redacted string via stdout
function redact_secrets() {
    local text="$1"
    local redacted="$text"
    
    for var in "${REDACT_VARS[@]}"; do
        local value="${!var:-}"
        if [[ -n "$value" && ${#value} -gt 4 ]]; then
            # Replace the secret with [REDACTED]
            redacted="${redacted//$value/[REDACTED]}"
        fi
    done
    
    echo "$redacted"
}

enable_command_trace() {
    # Enable bash xtrace to the current LOGFILE when SHOW_COMMANDS=true
    # WARNING: This may log sensitive data. Use redact_secrets() when reviewing logs.
    if [[ ${SHOW_COMMANDS:-false} != true ]]; then
        return
    fi
    [[ -z ${LOGFILE:-} ]] && return

    _print_status WARN "Command tracing enabled" "Logs may contain sensitive data"

    # Close any previous trace descriptor (native bash {varname} redirect syntax)
    if [[ -n ${TRACE_FD:-} ]]; then
        exec {TRACE_FD}>&- 2>/dev/null || true
    fi

    # Open a new descriptor against the active log
    if ! exec {TRACE_FD}>>"$LOGFILE"; then
        return
    fi
    export BASH_XTRACEFD=$TRACE_FD
    export PS4='+ ${BASH_SOURCE##*/}:${LINENO}: '
    set -x
}

function banner_grabber() {
    local banner_file="${SCRIPTPATH}/banners.txt"

    # Check if the banner file exists
    if [[ ! -f $banner_file ]]; then
        echo "Banner file not found: $banner_file" >&2
        return 1
    fi

    # Source the banner file
    # shellcheck source=/dev/null
    source "$banner_file"

    # Collect all banner variable names
    mapfile -t banner_vars < <(compgen -A variable | grep '^banner[0-9]\+$')

    # Check if any banners are available
    if [[ ${#banner_vars[@]} -eq 0 ]]; then
        echo "No banners found in $banner_file" >&2
        return 1
    fi

    # Select a random banner
    local rand_index=$((RANDOM % ${#banner_vars[@]}))
    local banner_var="${banner_vars[$rand_index]}"
    local banner_code="${!banner_var}"

    # Output the banner code
    printf "%b\n" "$banner_code"
}

function banner() {
    local banner_code
    if banner_code=$(banner_grabber); then
        printf "\n%b%s" "$bgreen" "$banner_code"
    else
        printf "\n%bFailed to load banner.%b\n" "$bgreen" "$reset"
    fi
}

###############################################################################################################
################################################### TOOLS #####################################################
###############################################################################################################

function check_version() {

    # Check if git is installed
    if ! command -v git >/dev/null 2>&1; then
        _print_error "Git is not installed. Cannot check for updates"
        return 1
    fi

    # Check if current directory is a git repository
    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        _print_error "Current directory is not a git repository. Cannot check for updates"
        return 1
    fi

    # Fetch updates with a timeout (supports gtimeout on macOS)
    if ! { [[ -n $TIMEOUT_CMD ]] && $TIMEOUT_CMD 10 git fetch >/dev/null 2>&1; } && ! git fetch >/dev/null 2>&1; then
        _print_error "Unable to check updates (git fetch timed out)"
        return 1
    fi

    # Get current branch name
    local BRANCH
    BRANCH=$(git rev-parse --abbrev-ref HEAD)

    # Get upstream branch
    local UPSTREAM
    UPSTREAM=$(git rev-parse --abbrev-ref --symbolic-full-name "@{u}" 2>/dev/null)
    if [[ -z $UPSTREAM ]]; then
        _print_error "No upstream branch set for '${BRANCH}'. Cannot check for updates"
        return 1
    fi

    # Get local and remote commit hashes
    local LOCAL REMOTE
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse "$UPSTREAM")

    # Compare local and remote hashes
    if [[ $LOCAL != "$REMOTE" ]]; then
        _print_status WARN "New version available" "Run ./install.sh to update"
    fi
}

function tools_installed() {
    local all_installed=true
    local missing_tools=()

    # Some vendored wordlists are stored compressed to keep the repo small.
    # Expand them on-demand before checking tool/file presence.
    ensure_wordlist_file "${subs_wordlist:-}" || true

    # Check environment variables
    local env_vars=("GOPATH" "GOROOT" "PATH")
    for var in "${env_vars[@]}"; do
        if [[ -z ${!var} ]]; then
            _print_status FAIL "${var} variable"
            all_installed=false
            missing_tools+=("$var environment variable")
        fi
    done

    # Define tools and their paths/commands
    declare -A tools_files=(
        ["dorks_hunter"]="${tools}/dorks_hunter/dorks_hunter.py"
        ["dorks_hunter_python"]="${tools}/dorks_hunter/venv/bin/python3"
        ["testssl.sh"]="${tools}/testssl.sh/testssl.sh"
        ["CMSeeK"]="${tools}/CMSeeK/cmseek.py"
        ["CMSeeK_python"]="${tools}/CMSeeK/venv/bin/python3"
        ["OneListForAll"]="$fuzz_wordlist"
        ["lfi_wordlist"]="$lfi_wordlist"
        ["ssti_wordlist"]="$ssti_wordlist"
        ["subs_wordlist"]="$subs_wordlist"
        ["subs_wordlist_big"]="$subs_wordlist_big"
        ["resolvers"]="$resolvers"
        ["resolvers_trusted"]="$resolvers_trusted"
        ["getjswords"]="${tools}/getjswords.py"
        ["JSA"]="${tools}/JSA/jsa.py"
        ["JSA_python"]="${tools}/JSA/venv/bin/python3"
        ["CloudHunter"]="${tools}/CloudHunter/cloudhunter.py"
        ["CloudHunter_python"]="${tools}/CloudHunter/venv/bin/python3"
        ["nmap-parse-output"]="${tools}/ultimate-nmap-parser/ultimate-nmap-parser.sh"
        ["regulator"]="${tools}/regulator/main.py"
        ["regulator_python"]="${tools}/regulator/venv/bin/python3"
        ["nomore403"]="${tools}/nomore403/nomore403"
        ["ffufPostprocessing"]="${tools}/ffufPostprocessing/ffufPostprocessing"
        ["spoofy"]="${tools}/Spoofy/spoofy.py"
        ["spoofy_python"]="${tools}/Spoofy/venv/bin/python3"
        ["swaggerspy"]="${tools}/SwaggerSpy/swaggerspy.py"
        ["swaggerspy_python"]="${tools}/SwaggerSpy/venv/bin/python3"
        ["LeakSearch"]="${tools}/LeakSearch/LeakSearch.py"
        ["LeakSearch_python"]="${tools}/LeakSearch/venv/bin/python3"
        ["msftrecon"]="${tools}/msftrecon/msftrecon/msftrecon.py"
        ["msftrecon_python"]="${tools}/msftrecon/venv/bin/python3"
        ["Scopify"]="${tools}/Scopify/scopify.py"
        ["Scopify_python"]="${tools}/Scopify/venv/bin/python3"
        ["EmailHarvester"]="${tools}/EmailHarvester/EmailHarvester.py"
        ["EmailHarvester_python"]="${tools}/EmailHarvester/venv/bin/python3"
        ["metagoofil"]="${tools}/metagoofil/metagoofil.py"
        ["metagoofil_python"]="${tools}/metagoofil/venv/bin/python3"
        ["reconftw_ai"]="${tools}/reconftw_ai/reconftw_ai.py"
        ["reconftw_ai_python"]="${tools}/reconftw_ai/venv/bin/python3"
        ["ghleaks"]="${tools}/ghleaks/ghleaks"
    )

    declare -A tools_folders=(
        ["nuclei-templates"]="${NUCLEI_TEMPLATES_PATH}"
    )

    declare -A tools_commands=(
        ["python3"]="python3"
        ["curl"]="curl"
        ["wget"]="wget"
        ["zip"]="zip"
        ["gzip"]="gzip"
        ["nmap"]="nmap"
        ["dig"]="dig"
        ["timeout"]="${TIMEOUT_CMD:-timeout}"
        ["brutespray"]="brutespray"
        ["xnLinkFinder"]="xnLinkFinder"
        ["xnldorker"]="xnldorker"
        ["urlfinder"]="urlfinder"
        ["github-endpoints"]="github-endpoints"
        ["github-subdomains"]="github-subdomains"
        ["gitlab-subdomains"]="gitlab-subdomains"
        ["katana"]="katana"
        ["wafw00f"]="wafw00f"
        ["dnsvalidator"]="dnsvalidator"
        ["whois"]="whois"
        ["dnsx"]="dnsx"
        ["gotator"]="gotator"
        ["Nuclei"]="nuclei"
        ["gf"]="gf"
        ["postleaksNg"]="postleaksNg"
        ["Gxss"]="Gxss"
        ["subjs"]="subjs"
        ["ffuf"]="ffuf"
        ["Massdns"]="massdns"
        ["qsreplace"]="qsreplace"
        ["interlace"]="interlace"
        ["Anew"]="anew"
        ["unfurl"]="unfurl"
        ["crlfuzz"]="crlfuzz"
        ["Httpx"]="httpx"
        ["jq"]="jq"
        ["notify"]="notify"
        ["dalfox"]="dalfox"
        ["puredns"]="puredns"
        ["analyticsrelationships"]="analyticsrelationships"
        ["mapcidr"]="mapcidr"
        ["cdncheck"]="cdncheck"
        ["interactsh-client"]="interactsh-client"
        ["tlsx"]="tlsx"
        ["smap"]="smap"
	    ["gitdorks_go"]="gitdorks_go"
	    ["smugglex"]="smugglex"
	    ["dsieve"]="dsieve"
        ["inscope"]="inscope"
        ["enumerepo"]="enumerepo"
        ["Web-Cache-Vulnerability-Scanner"]="Web-Cache-Vulnerability-Scanner"
        ["subfinder"]="subfinder"
        ["ghauri"]="ghauri"
        ["hakip2host"]="hakip2host"
        ["crt"]="crt"
        ["gitleaks"]="gitleaks"
        ["trufflehog"]="trufflehog"
        ["s3scanner"]="s3scanner"
        ["mantra"]="mantra"
        ["nmapurls"]="nmapurls"
	    ["naabu"]="naabu"
	    ["porch-pirate"]="porch-pirate"
	    ["shortscan"]="shortscan"
        ["cewler"]="cewler"
        ["hakoriginfinder"]="hakoriginfinder"
        ["sourcemapper"]="sourcemapper"
        ["jsluice"]="jsluice"
        ["commix"]="commix"
        ["waymore"]="waymore"
        ["urless"]="urless"
        ["dnstake"]="dnstake"
        ["cent"]="cent"
        ["csprecon"]="csprecon"
        ["VhostFinder"]="VhostFinder"
        ["grpcurl"]="grpcurl"
        ["arjun"]="arjun"
        ["gqlspection"]="gqlspection"
        ["cloud_enum"]="cloud_enum"
        ["toxicache"]="toxicache"
        ["favirecon"]="favirecon"
        ["TInjA"]="TInjA"
        ["second-order"]="second-order"
    )

    # Check for tool files
    for tool in "${!tools_files[@]}"; do
        if [[ ! -f ${tools_files[$tool]} ]]; then
            #			printf "%b [*] %s\t\t[NO]%b\n" "$bred" "$tool" "$reset"
            all_installed=false
            missing_tools+=("$tool")
        fi
    done

    # Check for tool folders
    for folder in "${!tools_folders[@]}"; do
        if [[ ! -d ${tools_folders[$folder]} ]]; then
            # printf "%b [*] %s\t\t[NO]%b\n" "$bred" "$folder" "$reset"
            all_installed=false
            missing_tools+=("$folder") # Correctly pushing the folder name
        fi
    done

    # Check for tool commands
    for tool in "${!tools_commands[@]}"; do
        if ! command -v "${tools_commands[$tool]}" >/dev/null 2>&1; then
            #			printf "%b [*] %s\t\t[NO]%b\n" "$bred" "$tool" "$reset"
            all_installed=false
            missing_tools+=("$tool")
        fi
    done

    if [[ $all_installed == true ]]; then
        : # Tools check OK, no output
    else
        if (( ${#missing_tools[@]} == 1 )); then
            _print_msg WARN "Pending tool: ${missing_tools[0]}"
        else
            _print_msg WARN "Pending tools: ${missing_tools[*]}"
        fi
    fi

    if [[ $CHECK_TOOLS_OR_EXIT == true && $all_installed != true ]]; then
        exit 2
    fi
}

###############################################################################################################
#################################### CRITICAL DEPENDENCIES CHECK ##############################################
###############################################################################################################

# Check critical dependencies required for basic operation
# This performs a quick check of essential tools before starting
function check_critical_dependencies() {
    local critical_tools=(
        "bash:Bash shell"
        "python3:Python 3"
        "curl:Curl"
        "git:Git"
        "jq:JQ JSON processor"
    )

    local missing_critical=()

    for item in "${critical_tools[@]}"; do
        local tool="${item%%:*}"
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_critical+=("$tool")
        fi
    done

    if (( ${#missing_critical[@]} > 0 )); then
        _print_msg WARN "Missing critical dependencies: ${missing_critical[*]}"
        return 1
    fi

    return 0
}


###############################################################################################################
####################################### LOGGING ##################################################
###############################################################################################################

# Structured JSON logging (optional, controlled by STRUCTURED_LOGGING config)
STRUCTURED_LOGGING=${STRUCTURED_LOGGING:-false}
STRUCTURED_LOG_FILE=""

# Initialize structured logging
function log_init() {
    [[ "$STRUCTURED_LOGGING" != "true" ]] && return 0

    STRUCTURED_LOG_FILE="${dir}/.log/structured_$(date +%Y%m%d_%H%M%S).jsonl"
    mkdir -p "$(dirname "$STRUCTURED_LOG_FILE")"

    _print_status OK "Structured logging enabled" "$STRUCTURED_LOG_FILE"
}

# Log structured JSON event
# Usage: log_json <level> <function> <message> [key1=val1] [key2=val2] ...
function log_json() {
    [[ "$STRUCTURED_LOGGING" != "true" ]] && return 0
    [[ -z "$STRUCTURED_LOG_FILE" ]] && return 0

    local level="$1"
    local function="$2"
    local message="$3"
    shift 3

    # Build JSON object
    local json_obj
    json_obj=$(jq -n \
        --arg ts "$(date -Iseconds)" \
        --arg lvl "$level" \
        --arg fn "$function" \
        --arg msg "$message" \
        --arg domain "${domain:-N/A}" \
        '{timestamp:$ts, level:$lvl, function:$fn, message:$msg, domain:$domain}')

    # Add extra key-value pairs if provided
    for kv in "$@"; do
        if [[ "$kv" =~ ^([^=]+)=(.+)$ ]]; then
            local key="${BASH_REMATCH[1]}"
            local val="${BASH_REMATCH[2]}"
            json_obj=$(echo "$json_obj" | jq --arg k "$key" --arg v "$val" '. + {($k): $v}')
        fi
    done

    echo "$json_obj" >>"$STRUCTURED_LOG_FILE"
}

# Convenience wrappers for different log levels
function log_info() {
    log_json "INFO" "${FUNCNAME[1]:-main}" "$@"
}

function log_warn() {
    log_json "WARN" "${FUNCNAME[1]:-main}" "$@"
}

function log_error() {
    log_json "ERROR" "${FUNCNAME[1]:-main}" "$@"
}

function log_success() {
    log_json "SUCCESS" "${FUNCNAME[1]:-main}" "$@"
}

###############################################################################################################
############################################ PROGRESS / ETA ###################################################
###############################################################################################################

_PROGRESS_TOTAL_STEPS=0
_PROGRESS_CURRENT_STEP=0
_PROGRESS_START_TIME=0

# Initialize progress tracking
# Usage: progress_init <total_steps> [total_est_seconds]
function progress_init() {
    _PROGRESS_TOTAL_STEPS=${1:-0}
    _PROGRESS_CURRENT_STEP=0
    _PROGRESS_START_TIME=$(date +%s)
    _PROGRESS_TOTAL_EST=${2:-0}
}

# Adjust total progress steps at runtime (for conditional stage skipping)
# Usage: progress_adjust_total <delta_steps>
function progress_adjust_total() {
    local delta="${1:-0}"
    _PROGRESS_TOTAL_STEPS=$((_PROGRESS_TOTAL_STEPS + delta))
    if [[ $_PROGRESS_TOTAL_STEPS -lt 1 ]]; then
        _PROGRESS_TOTAL_STEPS=1
    fi
}

# Advance progress and display ETA
# Usage: progress_step <step_name>
function progress_step() {
    ((_PROGRESS_CURRENT_STEP++)) || true
    local step_name="${1:-}"
    local now elapsed remaining_steps avg_per_step eta_seconds eta_display pct

    now=$(date +%s)
    elapsed=$((now - _PROGRESS_START_TIME))
    pct=0
    eta_display="calculating..."

    if [[ $_PROGRESS_TOTAL_STEPS -gt 0 ]]; then
        pct=$(( (_PROGRESS_CURRENT_STEP * 100) / _PROGRESS_TOTAL_STEPS ))
        remaining_steps=$((_PROGRESS_TOTAL_STEPS - _PROGRESS_CURRENT_STEP))

        if [[ $_PROGRESS_CURRENT_STEP -gt 0 ]] && [[ $elapsed -gt 0 ]]; then
            avg_per_step=$((elapsed / _PROGRESS_CURRENT_STEP))
            eta_seconds=$((remaining_steps * avg_per_step))
            if [[ $eta_seconds -ge 3600 ]]; then
                eta_display="~$((eta_seconds / 3600))h $((eta_seconds % 3600 / 60))m"
            elif [[ $eta_seconds -ge 60 ]]; then
                eta_display="~$((eta_seconds / 60))m"
            else
                eta_display="~${eta_seconds}s"
            fi
        fi
    fi

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        if declare -F ui_progress >/dev/null 2>&1; then
            ui_progress "$step_name" "$_PROGRESS_CURRENT_STEP" "$_PROGRESS_TOTAL_STEPS" "$pct" "$eta_display"
        else
            printf "%b[%s] Progress: [%d/%d] %d%% | ETA: %s | %s%b\n" \
                "$bblue" "$(date +'%H:%M:%S')" \
                "$_PROGRESS_CURRENT_STEP" "$_PROGRESS_TOTAL_STEPS" \
                "$pct" "$eta_display" "$step_name" "$reset"
        fi
    fi
}

# Module-level progress tracker
# Usage: progress_module "OSINT"
# Shows: [3/7] 43% | OSINT complete | OK:8 WARN:0 FAIL:0 SKIP:2
_PROGRESS_MODULE_CURRENT=0
_PROGRESS_MODULE_TOTAL=0

function progress_module_init() {
    _PROGRESS_MODULE_TOTAL=${1:-0}
    _PROGRESS_MODULE_CURRENT=0
}

function progress_module() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    ((_PROGRESS_MODULE_CURRENT++)) || true
    local module_name="${1:-}"
    local pct=0
    if [[ $_PROGRESS_MODULE_TOTAL -gt 0 ]]; then
        pct=$((_PROGRESS_MODULE_CURRENT * 100 / _PROGRESS_MODULE_TOTAL))
    fi
    local counters=""
    if declare -F ui_counts_summary >/dev/null 2>&1; then
        counters=$(ui_counts_summary)
    fi
    printf "  %b[%d/%d] %d%% │ %s complete │ %s%b\n\n" \
        "${bblue:-}" "$_PROGRESS_MODULE_CURRENT" "$_PROGRESS_MODULE_TOTAL" "$pct" \
        "$module_name" "$counters" "${reset:-}"
}

###############################################################################################################
######################################### INCREMENTAL MODE ####################################################
###############################################################################################################

# Incremental mode - only scan new assets since last run
# This mode compares current results with previous runs and only processes new findings

INCREMENTAL_MODE=${INCREMENTAL_MODE:-false}
INCREMENTAL_DIR=".incremental"

# Initialize incremental mode structure
function incremental_init() {
    [[ "$INCREMENTAL_MODE" != "true" ]] && return 0

    mkdir -p "$INCREMENTAL_DIR"/{subdomains,webs,hosts,vulns,previous}

    print_notice INFO "incremental" "Incremental mode enabled - will only process new findings"
}

# Save current state for next incremental run
# Usage: incremental_save <type> <file>
function incremental_save() {
    [[ "$INCREMENTAL_MODE" != "true" ]] && return 0

    local type="$1"
    local file="$2"

    if [[ -s "$file" ]]; then
        cp "$file" "$INCREMENTAL_DIR/previous/${type}_$(date +%Y%m%d_%H%M%S).txt"
        cp "$file" "$INCREMENTAL_DIR/previous/${type}_latest.txt"
        printf "%b[%s] Saved %s state for incremental mode%b\n" \
            "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$type" "$reset" >>"$LOGFILE"
    fi
}

# Get new items compared to previous run
# Usage: incremental_diff <type> <current_file> <output_file>
# Returns: 0 if new items found, 1 if no new items
function incremental_diff() {
    [[ "$INCREMENTAL_MODE" != "true" ]] && {
        cp "$2" "$3" 2>/dev/null
        return 0
    }

    local type="$1"
    local current_file="$2"
    local output_file="$3"
    local previous_file="$INCREMENTAL_DIR/previous/${type}_latest.txt"

    if [[ ! -f "$previous_file" ]]; then
        # First run, all items are new
        cp "$current_file" "$output_file" 2>/dev/null
        local count
        count=$(wc -l <"$output_file" 2>/dev/null || echo 0)
        print_notice INFO "incremental" "First run for ${type}: ${count} items total"
        return 0
    fi

    # Compare and get only new items
    if [[ -s "$current_file" ]]; then
        comm -13 <(sort -u "$previous_file") <(sort -u "$current_file") | sed '/^$/d' >"$output_file"
        local new_count total_count previous_count
        new_count=$(wc -l <"$output_file" 2>/dev/null || echo 0)
        total_count=$(wc -l <"$current_file" 2>/dev/null || echo 0)
        previous_count=$(wc -l <"$previous_file" 2>/dev/null || echo 0)

        print_notice INFO "incremental" "${type}: ${new_count} new (previous: ${previous_count}, total: ${total_count})"

        if [[ $new_count -eq 0 ]]; then
            return 1 # No new items
        fi
        return 0 # New items found
    else
        touch "$output_file"
        return 1
    fi
}

# Generate incremental report
function incremental_report() {
    [[ "$INCREMENTAL_MODE" != "true" ]] && return 0

    local report_file
    local new_subs new_webs
    local subs_diff webs_diff
    report_file="$INCREMENTAL_DIR/incremental_report_$(date +%Y%m%d_%H%M%S).txt"

    subs_diff="$(mktemp 2>/dev/null || echo /tmp/incremental_subs.$$)"
    webs_diff="$(mktemp 2>/dev/null || echo /tmp/incremental_webs.$$)"
    : >"$subs_diff"
    : >"$webs_diff"

    if [[ -f "$INCREMENTAL_DIR/previous/subdomains_latest.txt" ]]; then
        comm -13 <(sort -u "$INCREMENTAL_DIR/previous/subdomains_latest.txt" 2>/dev/null || true) \
            <(sort -u "subdomains/subdomains.txt" 2>/dev/null || true) >"$subs_diff"
        new_subs=$(wc -l <"$subs_diff" | tr -d ' ')
    else
        new_subs=0
    fi

    if [[ -f "$INCREMENTAL_DIR/previous/webs_latest.txt" ]]; then
        comm -13 <(sort -u "$INCREMENTAL_DIR/previous/webs_latest.txt" 2>/dev/null || true) \
            <(sort -u "webs/webs.txt" 2>/dev/null || true) >"$webs_diff"
        new_webs=$(wc -l <"$webs_diff" | tr -d ' ')
    else
        new_webs=0
    fi

    {
        echo "==============================================="
        echo "Incremental Scan Report"
        echo "Domain: $domain"
        echo "Date: $(date +'%Y-%m-%d %H:%M:%S')"
        echo "==============================================="
        echo ""
        echo "New Subdomains: $new_subs"
        if [[ $new_subs -gt 0 ]]; then
            echo "---"
            head -20 "$subs_diff"
            [[ $new_subs -gt 20 ]] && echo "... and $((new_subs - 20)) more"
            echo ""
        fi
        echo "New Webs: $new_webs"
        if [[ $new_webs -gt 0 ]]; then
            echo "---"
            head -20 "$webs_diff"
            [[ $new_webs -gt 20 ]] && echo "... and $((new_webs - 20)) more"
            echo ""
        fi
        echo "==============================================="
        echo "Full report saved to: $report_file"
        echo "==============================================="
    } >"$report_file"

    rm -f "$subs_diff" "$webs_diff" 2>/dev/null || true
    _print_status INFO "incremental_report" "subs ${new_subs}, webs ${new_webs} -> ${report_file}"
}

# Hash helper for alert fingerprinting.
_hash_string() {
    local input="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$input" | sha256sum | awk '{print $1}'
    else
        printf '%s' "$input" | shasum -a 256 | awk '{print $1}'
    fi
}

_monitor_severity_rank() {
    case "${1,,}" in
        critical) echo 5 ;;
        high) echo 4 ;;
        medium) echo 3 ;;
        low) echo 2 ;;
        info) echo 1 ;;
        *) echo 0 ;;
    esac
}

_monitor_selected_severities() {
    local min_sev="${MONITOR_MIN_SEVERITY:-high}"
    local min_rank
    min_rank=$(_monitor_severity_rank "$min_sev")
    if [[ "$min_rank" -eq 0 ]]; then
        log_note "monitor: invalid MONITOR_MIN_SEVERITY='${min_sev}', defaulting to high" "${FUNCNAME[0]}" "${LINENO}"
        min_rank=4
    fi

    local sev rank
    for sev in critical high medium low info; do
        rank=$(_monitor_severity_rank "$sev")
        if ((rank >= min_rank)); then
            printf '%s\n' "$sev"
        fi
    done
}

_monitor_mark_alert_seen() {
    local category="$1"
    local value="$2"
    local seen_file="${ALERT_SEEN_FILE:-.incremental/alerts_seen.hashes}"
    local fp
    fp=$(_hash_string "${category}|${value}")
    mkdir -p "$(dirname "$seen_file")"
    touch "$seen_file"

    if [[ "${ALERT_SUPPRESSION:-true}" == "true" ]] && grep -Fxq "$fp" "$seen_file"; then
        return 1
    fi
    echo "$fp" >>"$seen_file"
    return 0
}

_monitor_alert_summary() {
    local snap="$1"
    local critical_u=0 high_u=0 medium_u=0 low_u=0 info_u=0
    local critical_s=0 high_s=0 medium_s=0 low_s=0 info_s=0
    local nuclei_u=0 nuclei_s=0 subs_u=0 webs_u=0 subs_s=0 webs_s=0
    local line

    local sev
    while IFS= read -r sev; do
        [[ -z "$sev" ]] && continue
        local sev_u=0 sev_s=0
        local sev_file="$snap/${sev}_new.txt"
        if [[ -s "$sev_file" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                if _monitor_mark_alert_seen "$sev" "$line"; then
                    ((sev_u++))
                else
                    ((sev_s++))
                fi
            done <"$sev_file"
        fi
        case "$sev" in
            critical) critical_u=$sev_u; critical_s=$sev_s ;;
            high) high_u=$sev_u; high_s=$sev_s ;;
            medium) medium_u=$sev_u; medium_s=$sev_s ;;
            low) low_u=$sev_u; low_s=$sev_s ;;
            info) info_u=$sev_u; info_s=$sev_s ;;
        esac
        nuclei_u=$((nuclei_u + sev_u))
        nuclei_s=$((nuclei_s + sev_s))
    done < <(_monitor_selected_severities)

    if [[ -s "$snap/subdomains_new.txt" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if _monitor_mark_alert_seen "subdomain" "$line"; then ((subs_u++)); else ((subs_s++)); fi
        done <"$snap/subdomains_new.txt"
    fi
    if [[ -s "$snap/webs_new.txt" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if _monitor_mark_alert_seen "web" "$line"; then ((webs_u++)); else ((webs_s++)); fi
        done <"$snap/webs_new.txt"
    fi

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg ts "$(date -Iseconds)" \
            --arg cycle "${MONITOR_CYCLE:-0}" \
            --arg min_sev "${MONITOR_MIN_SEVERITY:-high}" \
            --argjson nuclei_new "$nuclei_u" \
            --argjson critical_new "$critical_u" \
            --argjson high_new "$high_u" \
            --argjson medium_new "$medium_u" \
            --argjson low_new "$low_u" \
            --argjson info_new "$info_u" \
            --argjson subdomains_new "$subs_u" \
            --argjson webs_new "$webs_u" \
            --argjson nuclei_suppressed "$nuclei_s" \
            --argjson critical_suppressed "$critical_s" \
            --argjson high_suppressed "$high_s" \
            --argjson medium_suppressed "$medium_s" \
            --argjson low_suppressed "$low_s" \
            --argjson info_suppressed "$info_s" \
            --argjson subdomains_suppressed "$subs_s" \
            --argjson webs_suppressed "$webs_s" \
            '{
                timestamp:$ts,
                cycle:($cycle|tonumber),
                monitor_min_severity:$min_sev,
                alerts:{
                    nuclei_new:$nuclei_new,
                    critical_new:$critical_new,
                    high_new:$high_new,
                    medium_new:$medium_new,
                    low_new:$low_new,
                    info_new:$info_new,
                    subdomains_new:$subdomains_new,
                    webs_new:$webs_new
                },
                suppressed:{
                    nuclei:$nuclei_suppressed,
                    critical:$critical_suppressed,
                    high:$high_suppressed,
                    medium:$medium_suppressed,
                    low:$low_suppressed,
                    info:$info_suppressed,
                    subdomains:$subdomains_suppressed,
                    webs:$webs_suppressed
                }
            }' >"$snap/alerts.json"
    fi

    printf '%s %s %s %s %s %s %s %s\n' \
        "$nuclei_u" "$subs_u" "$webs_u" "$nuclei_s" \
        "$subs_s" "$webs_s" "$critical_u" "$high_u"
}

# Monitor snapshots and delta tracking.
# Stores historical snapshots under .incremental/history/<timestamp>/ and computes deltas vs latest.
function monitor_snapshot() {
    [[ "${MONITOR_MODE:-false}" != "true" ]] && return 0

    ensure_dirs .incremental/history || return 1
    local ts snap prev_link prev_dir
    ts=$(date +%Y%m%d_%H%M%S)
    snap=".incremental/history/${ts}"
    mkdir -p "$snap"

    # Snapshot key artifacts for this cycle.
    local src
    for src in \
        "subdomains/subdomains.txt" \
        "webs/webs_all.txt" \
        "report/report.json" \
        "hotlist.txt"; do
        if [[ -s "$src" ]]; then
            cp "$src" "$snap/$(basename "$src")"
        fi
    done
    local -a monitor_severities=()
    mapfile -t monitor_severities < <(_monitor_selected_severities)
    local sev
    for sev in "${monitor_severities[@]}"; do
        if [[ -s "nuclei_output/${sev}.txt" ]]; then
            cp "nuclei_output/${sev}.txt" "$snap/${sev}.txt"
        fi
    done

    prev_link=".incremental/history/latest"
    prev_dir=""
    if [[ -L "$prev_link" || -d "$prev_link" ]]; then
        prev_dir=$(cd "$prev_link" 2>/dev/null && pwd -P || true)
    fi

    local subs_new=0 webs_new=0
    local critical_new=0 high_new=0 medium_new=0 low_new=0 info_new=0
    local nuclei_new_total=0 delta_total=0
    if [[ -n "$prev_dir" ]]; then
        if [[ -s "$snap/subdomains.txt" ]] && [[ -s "$prev_dir/subdomains.txt" ]]; then
            comm -13 <(sort -u "$prev_dir/subdomains.txt") <(sort -u "$snap/subdomains.txt") >"$snap/subdomains_new.txt"
            subs_new=$(wc -l <"$snap/subdomains_new.txt" 2>/dev/null | tr -d ' ')
        fi
        if [[ -s "$snap/webs_all.txt" ]] && [[ -s "$prev_dir/webs_all.txt" ]]; then
            comm -13 <(sort -u "$prev_dir/webs_all.txt") <(sort -u "$snap/webs_all.txt") >"$snap/webs_new.txt"
            webs_new=$(wc -l <"$snap/webs_new.txt" 2>/dev/null | tr -d ' ')
        fi
        for sev in "${monitor_severities[@]}"; do
            local sev_new_file="$snap/${sev}_new.txt"
            local sev_count=0
            if [[ -s "$snap/${sev}.txt" ]] && [[ -s "$prev_dir/${sev}.txt" ]]; then
                comm -13 <(sort -u "$prev_dir/${sev}.txt") <(sort -u "$snap/${sev}.txt") >"$sev_new_file"
                sev_count=$(wc -l <"$sev_new_file" 2>/dev/null | tr -d ' ')
            fi
            case "$sev" in
                critical) critical_new=$sev_count ;;
                high) high_new=$sev_count ;;
                medium) medium_new=$sev_count ;;
                low) low_new=$sev_count ;;
                info) info_new=$sev_count ;;
            esac
            nuclei_new_total=$((nuclei_new_total + sev_count))
        done
    else
        # Baseline cycle: don't alert as "new", just record baseline.
        subs_new=0
        webs_new=0
        critical_new=0
        high_new=0
        medium_new=0
        low_new=0
        info_new=0
        nuclei_new_total=0
    fi

    subs_new=${subs_new:-0}
    webs_new=${webs_new:-0}
    critical_new=${critical_new:-0}
    high_new=${high_new:-0}
    medium_new=${medium_new:-0}
    low_new=${low_new:-0}
    info_new=${info_new:-0}
    nuclei_new_total=${nuclei_new_total:-0}
    delta_total=$((subs_new + webs_new + nuclei_new_total))
    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg ts "$(date -Iseconds)" \
            --arg cycle "${MONITOR_CYCLE:-0}" \
            --arg baseline "$( [[ -z "$prev_dir" ]] && echo true || echo false )" \
            --arg min_sev "${MONITOR_MIN_SEVERITY:-high}" \
            --argjson subs_new "$subs_new" \
            --argjson webs_new "$webs_new" \
            --argjson critical_new "$critical_new" \
            --argjson high_new "$high_new" \
            --argjson medium_new "$medium_new" \
            --argjson low_new "$low_new" \
            --argjson info_new "$info_new" \
            --argjson nuclei_new_total "$nuclei_new_total" \
            --argjson total_new "$delta_total" \
            '{
                timestamp:$ts,
                cycle:($cycle|tonumber),
                baseline:($baseline=="true"),
                monitor_min_severity:$min_sev,
                deltas:{
                    subdomains_new:$subs_new,
                    webs_new:$webs_new,
                    high_findings_new:$high_new,
                    critical_findings_new:$critical_new,
                    medium_findings_new:$medium_new,
                    low_findings_new:$low_new,
                    info_findings_new:$info_new,
                    nuclei_findings_new_total:$nuclei_new_total,
                    total_new:$total_new
                }
            }' >"$snap/delta.json"
    fi

    if [[ -z "$prev_dir" ]]; then
        notification "Monitor baseline snapshot stored (${snap})" info
    elif [[ "$delta_total" -gt 0 ]]; then
        local alert_stats nuclei_u subs_u webs_u nuclei_s subs_s webs_s critical_u high_u
        alert_stats=$(_monitor_alert_summary "$snap")
        read -r nuclei_u subs_u webs_u nuclei_s subs_s webs_s critical_u high_u <<<"$alert_stats"

        if [[ "${nuclei_u:-0}" -gt 0 ]]; then
            notification "[ALERT] New nuclei findings (>=${MONITOR_MIN_SEVERITY:-high}): ${nuclei_u:-0}" warn
        fi
        if [[ "${critical_u:-0}" -gt 0 || "${high_u:-0}" -gt 0 ]]; then
            notification "[ALERT] New high-impact findings: critical=${critical_u:-0}, high=${high_u:-0}" warn
        fi
        if [[ "${subs_u:-0}" -gt 0 || "${webs_u:-0}" -gt 0 ]]; then
            notification "New assets detected: subdomains=${subs_u:-0}, webs=${webs_u:-0}" good
        fi
        if [[ "${nuclei_u:-0}" -eq 0 && "${subs_u:-0}" -eq 0 && "${webs_u:-0}" -eq 0 ]]; then
            notification "Monitor detected deltas but all were suppressed by fingerprint history" info
        fi
    else
        notification "Monitor cycle: no changes detected" info
    fi

    # Update latest snapshot pointer.
    if [[ -L "$prev_link" || -d "$prev_link" ]]; then
        rm -rf -- "$prev_link"
    fi
    ln -s "$ts" "$prev_link" 2>/dev/null || {
        cp -R "$snap" "$prev_link"
    }

    return 0
}

# Check if incremental mode should skip heavy operations
# Usage: incremental_should_skip
# Returns: 0 to skip, 1 to continue
function incremental_should_skip() {
    [[ "$INCREMENTAL_MODE" != "true" ]] && return 1 # Don't skip

    # Check if we have new findings
    local new_subs new_webs
    new_subs=$(cat .tmp/subs_new_count 2>/dev/null || echo 1)
    new_webs=$(cat .tmp/webs_new_count 2>/dev/null || echo 1)

    if [[ $new_subs -eq 0 && $new_webs -eq 0 ]]; then
        print_notice WARN "incremental" "No new assets found, skipping heavy scans"
        return 0 # Skip
    fi

    return 1 # Don't skip
}

###############################################################################################################

function zipSnedOutputFolder {
    zip_name1=$(date +"%Y_%m_%d-%H.%M.%S")
    zip_name="${zip_name1}_${domain}.zip" 2>>"$LOGFILE" >/dev/null
    (cd "$dir" && zip -r "$zip_name" .) 2>>"$LOGFILE" >/dev/null
    echo "Sending zip file "${dir}/${zip_name}""
    if [[ -s "${dir}/$zip_name" ]]; then
        sendToNotify "$dir/$zip_name"
        rm -f "${dir}/$zip_name"
    else
        notification "No Zip file to send" warn
    fi
}

function isAsciiText {
    # shellcheck disable=SC2034  # IS_ASCII is consumed by callers after invoking this helper
    IS_ASCII=$([[ $(file "$1" | grep -o 'ASCII text$') == "ASCII text" ]] && echo "True" || echo "False")
}

function output() {
    mkdir -p "$dir_output"
    # Ensure both $dir and $dir_output are absolute paths
    dir="$(realpath "$dir")"
    dir_output="$(realpath "$dir_output")"

    # Prevent accidental deletion if $dir_output is a parent of $dir
    if [[ $dir == "$dir_output"* ]]; then
        _print_error "Output directory is a parent of the working directory. Aborting to prevent data loss."
        return 1
    fi

    cp -r "$dir" "$dir_output"

    # Only delete if source and destination are clearly different and safe
    # Safety: refuse to delete outside of Recon/ directory
    if [[ "$(dirname "$dir")" != "$dir_output" ]]; then
        if [[ "$dir" == "${SCRIPTPATH}/Recon/"* ]]; then
            rm -rf -- "$dir"
        else
            _print_error "Refusing to delete directory outside Recon/: $dir"
            return 1
        fi
    fi
}

function remove_big_files() {
    rm -rf .tmp/gotator*.txt 2>>"$LOGFILE"
    rm -rf .tmp/brute_recursive_wordlist.txt 2>>"$LOGFILE"
    rm -rf .tmp/subs_dns_tko.txt 2>>"$LOGFILE"
    rm -rf .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/brute_dns_tko.txt .tmp/scrap_subs.txt .tmp/analytics_subs_clean.txt .tmp/gotator1.txt .tmp/gotator2.txt .tmp/passive_recursive.txt .tmp/brute_recursive_wordlist.txt .tmp/gotator1_recursive.txt .tmp/gotator2_recursive.txt 2>>"$LOGFILE"
    find .tmp -type f -size +200M -exec rm -f {} + 2>>"$LOGFILE"
}

function notification() {
    if [[ -n $1 ]] && [[ -n $2 ]]; then
        if [[ $NOTIFICATION == true ]]; then
            NOTIFY="notify -silent"
        else
            NOTIFY=""
        fi
        local level="INFO"
        case $2 in
            info) level="INFO" ;;
            warn) level="WARN" ;;
            error) level="FAIL" ;;
            good) level="OK" ;;
        esac
 
        if declare -F ui_log_jsonl >/dev/null 2>&1; then
            local ui_level="INFO"
            case "$2" in
                info) ui_level="INFO" ;;
                warn) ui_level="WARN" ;;
                error) ui_level="ERROR" ;;
                good) ui_level="SUCCESS" ;;
            esac
            ui_log_jsonl "$ui_level" "${FUNCNAME[1]:-main}" "$1"
        fi

        # Quiet mode (OUTPUT_VERBOSITY==0): only print errors to terminal
        # Normal mode (OUTPUT_VERBOSITY==1): only print warn/error to terminal
        # Verbose mode (OUTPUT_VERBOSITY>=2): print everything
        local should_print=false
        case "$2" in
            error)      should_print=true ;;
            warn)       [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]] && should_print=true ;;
            info|good)  [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && should_print=true ;;
        esac

        if [[ "$should_print" != true ]]; then
            # Still send to notify if enabled, just skip terminal print
            if [[ -n $NOTIFY ]]; then
                printf "%s" "[${level}] ${1} - ${domain}" | $NOTIFY >/dev/null 2>&1
            fi
            return 0
        fi
 
        # Print to terminal in structured format (no counters)
        print_notice "$level" "${FUNCNAME[1]:-notice}" "$1"
        if [[ "$level" == "WARN" || "$level" == "FAIL" ]]; then
            record_incident "$level" "${FUNCNAME[1]:-notice}" "$1"
        fi
 
        # Send to notify if notifications are enabled
        if [[ -n $NOTIFY ]]; then
            # Remove color codes for the notification
            printf "%s" "[${level}] ${1} - ${domain}" | $NOTIFY >/dev/null 2>&1
        fi
    fi
}

function transfer {
    if [[ $# -eq 0 ]]; then
        echo "No arguments specified.\nUsage:\n transfer <file|directory>\n ... | transfer <file_name>" >&2
        return 1
    fi

    if tty -s; then
        file="$1"
        file_name=$(basename "$file")
        if [[ ! -e $file ]]; then
            echo "$file: No such file or directory" >&2
            return 1
        fi
        run_command tar -czvf /tmp/$file_name $file >/dev/null 2>&1 && run_command curl -s https://bashupload.com/$file.tgz --data-binary @/tmp/$file_name | grep wget
    else
        file_name=$1
        run_command tar -czvf /tmp/$file_name $file >/dev/null 2>&1 && run_command curl -s https://bashupload.com/$file.tgz --data-binary @/tmp/$file_name | grep wget
    fi
}

function sendToNotify {
    if [[ -z $1 ]]; then
        _print_status WARN "No file provided to send"
    else
        if [[ -z $NOTIFY_CONFIG ]]; then
            NOTIFY_CONFIG=~/.config/notify/provider-config.yaml
        fi
        if [[ -n "$(find "${1}" -prune -size +8000000c)" ]]; then
            printf '%s is larger than 8MB, sending over external service\n' "${1}"
            transfer "${1}" | notify -silent
            return 0
        fi
        if grep -q '^ telegram\|^telegram\|^    telegram' $NOTIFY_CONFIG; then
            notification "Sending ${domain} data over Telegram" info
            telegram_chat_id=$(sed -n '/^telegram:/,/^[^ ]/p' ${NOTIFY_CONFIG} | sed -n 's/^[ ]*telegram_chat_id:[ ]*"\([^"]*\)".*/\1/p')
            telegram_key=$(sed -n '/^telegram:/,/^[^ ]/p' ${NOTIFY_CONFIG} | sed -n 's/^[ ]*telegram_api_key:[ ]*"\([^"]*\)".*/\1/p')
            run_command curl -F "chat_id=${telegram_chat_id}" -F "document=@${1}" https://api.telegram.org/bot${telegram_key}/sendDocument 2>>"$LOGFILE" >/dev/null
        fi
        if grep -q '^ discord\|^discord\|^    discord' $NOTIFY_CONFIG; then
            notification "Sending ${domain} data over Discord" info
            discord_url=$(sed -n '/^discord:/,/^[^ ]/p' ${NOTIFY_CONFIG} | sed -n 's/^[ ]*discord_webhook_url:[ ]*"\([^"]*\)".*/\1/p')
            run_command curl -v -i -H "Accept: application/json" -H "Content-Type: multipart/form-data" -X POST -F 'payload_json={"username": "test", "content": "hello"}' -F file1=@${1} $discord_url 2>>"$LOGFILE" >/dev/null
        fi
        if [[ -n $slack_channel ]] && [[ -n $slack_auth ]]; then
            notification "Sending ${domain} data over Slack" info
            run_command curl -F file=@${1} -F "initial_comment=reconftw zip file" -F channels=${slack_channel} -H "Authorization: Bearer ${slack_auth}" https://slack.com/api/files.upload 2>>"$LOGFILE" >/dev/null
        fi
    fi
}

function start_func() {
    current_date=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$current_date] Start function: ${1} " >>"${LOGFILE}"
    start=$(date +%s)
    log_json "INFO" "${1}" "Function started" "description=${2}"
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "INFO" "${1}" "Function started" "description=${2}"
    fi
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        _print_msg "INFO" "Running ${1}..."
    fi
}

function end_func() {
    local message="${1:-}"
    local fn="${2:-${FUNCNAME[1]:-unknown}}"
    local status="${3:-}"

    # Backward-compatible status handling:
    # - end_func "msg" "func" warn
    # - end_func "msg" warn
    if [[ -n "$status" ]]; then
        case "$status" in
            info|warn|error|good|OK|WARN|FAIL|SKIP|SKIP_CONFIG|SKIP_NOINPUT|CACHE_HIT)
                ;; # keep as-is
            *)
                status="OK"
                ;;
        esac
    else
        case "$fn" in
            info|warn|error|good|OK|WARN|FAIL|SKIP|SKIP_CONFIG|SKIP_NOINPUT|CACHE_HIT)
                status="$fn"
                fn="${FUNCNAME[1]:-unknown}"
                ;;
            *)
                status="OK"
                ;;
        esac
    fi

    touch "$called_fn_dir/.${fn}"
    end=$(date +%s)
    getElapsedTime "$start" "$end"
    record_func_timing "${fn}" "$((end - start))"
    local duration=$((end - start))
    local end_date
    end_date=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$end_date] End function: ${fn} " >>"${LOGFILE}"
    local badge="OK"
    local reason_code=""
    case "$status" in
        info|INFO) badge="INFO" ;;
        warn|WARN) badge="WARN" ;;
        error|ERROR) badge="FAIL" ;;
        good|SUCCESS) badge="OK" ;;
        OK|FAIL|SKIP|CACHE) badge="$status" ;;
        SKIP_CONFIG) badge="SKIP"; reason_code="config" ;;
        SKIP_NOINPUT) badge="SKIP"; reason_code="noinput" ;;
        CACHE_HIT) badge="CACHE"; reason_code="cache" ;;
    esac

    # Auto-normalize common "no input" skip patterns when caller didn't set explicit status.
    if [[ "$badge" == "OK" ]] && [[ -n "$message" ]]; then
        local msg_lc
        msg_lc=$(printf "%s" "$message" | tr '[:upper:]' '[:lower:]')
        if [[ "$msg_lc" == no\ * ]] && [[ "$msg_lc" == *"skip"* ]]; then
            badge="SKIP"
            reason_code="noinput"
        elif [[ "$msg_lc" == *"missing url candidates"* ]]; then
            badge="SKIP"
            reason_code="noinput"
        fi
    fi

    # Persist per-function final status for parallel aggregator.
    if [[ -n "${called_fn_dir:-}" ]]; then
        printf "%s\n" "$badge" >"${called_fn_dir}/.status_${fn}" 2>/dev/null || true
        if [[ -n "$reason_code" ]]; then
            printf "%s\n" "$reason_code" >"${called_fn_dir}/.status_reason_${fn}" 2>/dev/null || true
        fi
    fi

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        _print_status "$badge" "${fn}" "${duration}s"
        if [[ -n "$reason_code" ]] && { [[ "$badge" != "CACHE" ]] || [[ "${SHOW_CACHE:-false}" == "true" ]]; }; then
            printf "         reason: %s\n" "$reason_code"
        fi
        # Show detail line for non-OK statuses when message is present
        if [[ -n "$message" ]] && [[ "$badge" != "OK" && "$badge" != "INFO" ]]; then
            printf "         %s\n" "$message"
            if [[ "$badge" == "FAIL" || "$badge" == "WARN" ]]; then
                record_incident "$badge" "$fn" "$message"
            fi
        fi
    fi
    log_json "SUCCESS" "${fn}" "Function completed" "runtime=${runtime}" "duration_sec=${duration}"
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "SUCCESS" "${fn}" "Function completed" "runtime=${runtime}" "duration_sec=${duration}"
    fi

    :
}

function start_subfunc() {
    current_date=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$current_date] Start subfunction: ${1} " >>"${LOGFILE}"
    start_sub=$(date +%s)
    log_json "INFO" "${1}" "Subfunction started" "description=${2}"
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "INFO" "${1}" "Subfunction started" "description=${2}"
    fi
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        _print_msg "INFO" "Running ${1}..."
    fi
}

function end_subfunc() {
    touch "$called_fn_dir/.${2}"
    end_sub=$(date +%s)
    getElapsedTime "$start_sub" "$end_sub"
    local duration=$((end_sub - start_sub))
    local status="${3:-OK}"
    local badge="$status"
    local reason_code=""
    case "$status" in
        SKIP_CONFIG) badge="SKIP"; reason_code="config" ;;
        SKIP_NOINPUT) badge="SKIP"; reason_code="noinput" ;;
        CACHE_HIT) badge="CACHE"; reason_code="cache" ;;
    esac

    # Persist per-subfunction final status for parallel aggregator.
    if [[ -n "${called_fn_dir:-}" ]]; then
        printf "%s\n" "$badge" >"${called_fn_dir}/.status_${2}" 2>/dev/null || true
        if [[ -n "$reason_code" ]]; then
            printf "%s\n" "$reason_code" >"${called_fn_dir}/.status_reason_${2}" 2>/dev/null || true
        fi
    fi

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        _print_status "$badge" "${2}" "${duration}s"
        if [[ -n "$reason_code" ]] && { [[ "$badge" != "CACHE" ]] || [[ "${SHOW_CACHE:-false}" == "true" ]]; }; then
            printf "         reason: %s\n" "$reason_code"
        fi
    fi
    local end_sub_date
    end_sub_date=$(date +'%Y-%m-%d %H:%M:%S')
    echo "[$end_sub_date] End subfunction: ${1} " >>"${LOGFILE}"
    log_json "SUCCESS" "${2}" "Subfunction completed" "runtime=${runtime}" "duration_sec=${duration}"
    if declare -F ui_log_jsonl >/dev/null 2>&1; then
        ui_log_jsonl "SUCCESS" "${2}" "Subfunction completed" "runtime=${runtime}" "duration_sec=${duration}"
    fi
    :
}

function check_inscope() {
    cat "$1" | inscope >"${1}_tmp" && cp "${1}_tmp" "$1" && rm -f "${1}_tmp"
}

function maybe_update_nuclei() {
    # Update nuclei templates once per run per target directory
    mkdir -p .tmp
    local stamp_file=".tmp/.nuclei_updated"
    if [[ ! -f $stamp_file ]]; then
        if [[ -n ${NUCLEI_TEMPLATES_PATH-} ]]; then
            run_command nuclei -update-templates -update-template-dir "${NUCLEI_TEMPLATES_PATH}" 2>>"$LOGFILE" >/dev/null || true # non-fatal: template update failure shouldn't block scan
        else
            run_command nuclei -update 2>>"$LOGFILE" >/dev/null || true # non-fatal: template update failure shouldn't block scan
        fi
        touch "$stamp_file"
    fi
}

# Plugin framework
function plugins_load() {
    local plugdir="${SCRIPTPATH}/plugins"
    if [[ -d $plugdir ]]; then
        for f in "$plugdir"/*.sh; do
            # shellcheck source=/dev/null
            [[ -f $f ]] && source "$f" || true
        done
    fi
}

function plugins_emit() {
    local event="$1"
    shift || true
    if declare -F reconftw_plugins >/dev/null 2>&1; then
        reconftw_plugins "$event" "$@" || true
    fi
}

# Asset store
function append_asset() {
    # Usage: append_asset type key value extras...
    [[ $ASSET_STORE != true ]] && return 0
    local type="$1"
    shift
    local key="$1"
    shift
    local val="$1"
    shift
    local now
    now=$(date +'%Y-%m-%d %H:%M:%S')
    mkdir -p .tmp
    printf '{"type":"%s","%s":"%s","ts":"%s","source":"%s"}\n' \
        "$type" "$key" "${val//\"/\\\"}" "$now" "${FUNCNAME[1]}" >>assets.jsonl 2>/dev/null
}

function append_assets_from_file() {
    # Usage: append_assets_from_file type key file
    [[ $ASSET_STORE != true ]] && return 0
    local type="$1"
    local key="$2"
    local file="$3"
    [[ ! -s $file ]] && return 0
    while IFS= read -r line; do
        [[ -z $line ]] && continue
        append_asset "$type" "$key" "$line"
    done <"$file"
}

# Chunk helper
function process_in_chunks() {
    # process_in_chunks <file> <chunk_size> <command with _chunk_ placeholder>
    local infile="$1"
    local chunksize="$2"
    shift 2
    [[ ! -s $infile ]] && return 0
    local lines
    lines=$(wc -l <"$infile" 2>/dev/null || echo 0)
    if [[ $lines -le $chunksize ]]; then
        bash -lc "$*"
        return $?
    fi
    mkdir -p .tmp/chunks
    split -l "$chunksize" -d "$infile" .tmp/chunks/part_
    for part in .tmp/chunks/part_*; do
        local cmd
        cmd="${*//_chunk_/\"$part\"}"
        bash -lc "$cmd"
    done
}

###############################################################################################################
########################################## HEALTH CHECK #######################################################
###############################################################################################################

# Performance timing storage
declare -A FUNC_TIMINGS 2>/dev/null || true

function record_func_timing() {
    # Usage: record_func_timing function_name duration_seconds
    local fn="$1"
    local dur="$2"
    FUNC_TIMINGS["$fn"]=$dur 2>/dev/null || true
}

function print_timing_summary() {
    # Print sorted timing summary of all recorded functions (verbose only)
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 2 ]] && return 0
    if [[ ${#FUNC_TIMINGS[@]} -eq 0 ]] 2>/dev/null; then
        return 0
    fi

    printf "\n%b#######################################################################%b\n" "$bgreen" "$reset"
    printf "%b[%s] Performance Timing Summary%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"

    local total=0
    local fn dur
    local -a sorted_entries=()

    # First pass: calculate total and collect entries
    for fn in "${!FUNC_TIMINGS[@]}"; do
        dur=${FUNC_TIMINGS[$fn]}
        # Ensure dur is numeric
        if [[ "$dur" =~ ^[0-9]+$ ]]; then
            total=$((total + dur))
            sorted_entries+=("$dur|$fn")
        fi
    done

    # Sort entries by duration (descending) and print
    printf '%s\n' "${sorted_entries[@]}" | sort -t'|' -k1 -rn | while IFS='|' read -r dur fn; do
        local pct=0
        if [[ $total -gt 0 ]] && [[ "$dur" =~ ^[0-9]+$ ]]; then
            pct=$((dur * 100 / total))
        fi
        local mins=$((dur / 60))
        local secs=$((dur % 60))
        printf "  %-35s %3dm %02ds  (%2d%%)\n" "$fn" "$mins" "$secs" "$pct"
    done

    local total_mins=$((total / 60))
    local total_secs=$((total % 60))
    printf "\n  %-35s %3dm %02ds\n" "TOTAL" "$total_mins" "$total_secs"
    printf "%b#######################################################################%b\n\n" "$bgreen" "$reset"
}

# Write machine-readable performance summary for dashboards/automation.
# Output: .log/perf_summary.json
function write_perf_summary() {
    local summary_file="${dir}/.log/perf_summary.json"
    local total=0
    local fn dur

    for fn in "${!FUNC_TIMINGS[@]}"; do
        dur=${FUNC_TIMINGS[$fn]}
        [[ "$dur" =~ ^[0-9]+$ ]] || continue
        total=$((total + dur))
    done

    local subs_count webs_count hosts_count findings_count
    subs_count=$(count_lines "${dir}/subdomains/subdomains.txt")
    webs_count=$(count_lines "${dir}/webs/webs_all.txt")
    hosts_count=$(count_lines "${dir}/hosts/ips.txt")
    if [[ -d "${dir}/nuclei_output" ]]; then
        findings_count=$(find "${dir}/nuclei_output" -type f -name '*_json.txt' -exec cat {} + 2>/dev/null | wc -l | tr -d ' ')
    else
        findings_count=0
    fi
    subs_count=${subs_count:-0}
    webs_count=${webs_count:-0}
    hosts_count=${hosts_count:-0}
    findings_count=${findings_count:-0}

    # Build top functions by duration.
    local top_json="[]"
    local -a sorted_entries=()
    for fn in "${!FUNC_TIMINGS[@]}"; do
        dur=${FUNC_TIMINGS[$fn]}
        [[ "$dur" =~ ^[0-9]+$ ]] || continue
        sorted_entries+=("$dur|$fn")
    done
    if [[ ${#sorted_entries[@]} -gt 0 ]]; then
        top_json=$(printf '%s\n' "${sorted_entries[@]}" \
            | sort -t'|' -k1 -rn \
            | head -n 15 \
            | awk -F'|' '{printf "{\"function\":\"%s\",\"duration_sec\":%s}\n",$2,$1}' \
            | jq -s '.')
    fi

    if command -v jq >/dev/null 2>&1; then
        jq -n \
            --arg ts "$(date -Iseconds)" \
            --arg domain "${domain:-unknown}" \
            --arg mode "${opt_mode:-unknown}" \
            --arg profile "${PERF_PROFILE:-balanced}" \
            --argjson total_sec "${total:-0}" \
            --argjson subdomains "${subs_count:-0}" \
            --argjson webs "${webs_count:-0}" \
            --argjson hosts "${hosts_count:-0}" \
            --argjson findings "${findings_count:-0}" \
            --argjson top "${top_json}" \
            '{
                timestamp:$ts,
                domain:$domain,
                mode:$mode,
                perf_profile:$profile,
                total_duration_sec:$total_sec,
                counts:{
                  subdomains:$subdomains,
                  webs:$webs,
                  hosts:$hosts,
                  findings:$findings
                },
                top_functions:$top
            }' >"$summary_file"
    else
        printf '{"timestamp":"%s","domain":"%s","mode":"%s","perf_profile":"%s","total_duration_sec":%s}\n' \
            "$(date -Iseconds)" "${domain:-unknown}" "${opt_mode:-unknown}" "${PERF_PROFILE:-balanced}" "${total:-0}" >"$summary_file"
    fi
}

# Strip control characters except tabs/newlines (pre-jq sanitation)
sanitize_control_chars() {
    LC_ALL=C tr -d '\000-\010\013\014\016-\037'
}

# Generate consolidated JSON + HTML report for the current scan.
# Outputs:
#   - report/report.json
#   - report/index.html
function generate_consolidated_report() {
    ensure_dirs report || return 1

    local report_json="report/report.json"
    local report_html="report/index.html"
    local subs_count webs_count hosts_count screenshots_count findings_total
    local sev_info sev_low sev_medium sev_high sev_critical
    local top_assets_json timeline_json links_json monitor_delta_json monitor_alerts_json

    subs_count=$(count_lines "subdomains/subdomains.txt")
    webs_count=$(count_lines "webs/webs_all.txt")
    hosts_count=$(count_lines "hosts/ips.txt")
    screenshots_count=$(find screenshots -type f -name '*.png' 2>/dev/null | wc -l | tr -d ' ')

    sev_info=$(count_lines "nuclei_output/info_json.txt")
    sev_low=$(count_lines "nuclei_output/low_json.txt")
    sev_medium=$(count_lines "nuclei_output/medium_json.txt")
    sev_high=$(count_lines "nuclei_output/high_json.txt")
    sev_critical=$(count_lines "nuclei_output/critical_json.txt")

    subs_count=${subs_count:-0}
    webs_count=${webs_count:-0}
    hosts_count=${hosts_count:-0}
    screenshots_count=${screenshots_count:-0}
    sev_info=${sev_info:-0}
    sev_low=${sev_low:-0}
    sev_medium=${sev_medium:-0}
    sev_high=${sev_high:-0}
    sev_critical=${sev_critical:-0}
    findings_total=$((sev_info + sev_low + sev_medium + sev_high + sev_critical))

    # Top assets from hotlist (if present)
    if [[ -s hotlist.txt ]] && command -v jq >/dev/null 2>&1; then
        top_assets_json=$(head -n "${HOTLIST_TOP:-50}" hotlist.txt \
            | awk '{score=$1;$1=""; sub(/^ /,"",$0); printf "{\"asset\":\"%s\",\"score\":%s}\n",$0,score}' \
            | jq -s '.')
    else
        top_assets_json="[]"
    fi

    # Timeline from structured log (preferred) or fallback from text log.
    if [[ -n "${STRUCTURED_LOG_FILE:-}" ]] && [[ -s "${STRUCTURED_LOG_FILE}" ]] && command -v jq >/dev/null 2>&1; then
        timeline_json=$(tail -n 80 "${STRUCTURED_LOG_FILE}" \
            | sanitize_control_chars \
            | jq -s 'map({timestamp:(.timestamp // ""), level:(.level // "INFO"), function:(.function // "unknown"), message:(.message // "")})')
    elif [[ -s "${LOGFILE:-}" ]] && command -v jq >/dev/null 2>&1; then
        timeline_json=$(tail -n 80 "${LOGFILE}" \
            | sanitize_control_chars \
            | awk -F'] ' '{
                ts=$1; gsub(/^\[/,"",ts);
                msg=$2;
                if (msg ~ /Start function:/) { print "{\"timestamp\":\"" ts "\",\"level\":\"INFO\",\"function\":\"" msg "\",\"message\":\"started\"}" }
                else if (msg ~ /End function:/) { print "{\"timestamp\":\"" ts "\",\"level\":\"SUCCESS\",\"function\":\"" msg "\",\"message\":\"completed\"}" }
            }' \
            | jq -s '.')
    else
        timeline_json="[]"
    fi

    # Quick links to important output files.
    if command -v jq >/dev/null 2>&1; then
        local link_path exists
        links_json=$(
            {
                for entry in \
                    "Subdomains|subdomains/subdomains.txt" \
                    "Web Targets|webs/webs_all.txt" \
                    "Takeovers|webs/takeover.txt" \
                    "Nuclei Critical|nuclei_output/critical.txt" \
                    "Nuclei High|nuclei_output/high.txt" \
                    "Hotlist|hotlist.txt" \
                    "Performance Summary|.log/perf_summary.json" \
                    "Assets JSONL|assets.jsonl" \
                    "Screenshots Changed|screenshots/diff_changed.txt" \
                    "Latest Report JSON|report/latest/report.json" \
                    "Latest Report HTML|report/latest/index.html"; do
                    link_path="${entry#*|}"
                    exists=false
                    [[ -s "$link_path" ]] && exists=true
                    printf '{"name":"%s","path":"%s","exists":%s}\n' "${entry%%|*}" "$link_path" "$exists"
                done
            } | jq -s '.'
        )
    else
        links_json="[]"
    fi

    if command -v jq >/dev/null 2>&1; then
        if [[ -s ".incremental/history/latest/delta.json" ]]; then
            monitor_delta_json=$(cat ".incremental/history/latest/delta.json")
        else
            monitor_delta_json='{}'
        fi
        if [[ -s ".incremental/history/latest/alerts.json" ]]; then
            monitor_alerts_json=$(cat ".incremental/history/latest/alerts.json")
        else
            monitor_alerts_json='{}'
        fi

        jq -n \
            --arg generated_at "$(date -Iseconds)" \
            --arg domain "${domain:-unknown}" \
            --arg mode "${opt_mode:-unknown}" \
            --arg runtime "${runtime:-unknown}" \
            --arg profile "${PERF_PROFILE:-balanced}" \
            --arg quick_rescan "${QUICK_RESCAN:-false}" \
            --arg incremental "${INCREMENTAL_MODE:-false}" \
            --arg parallel "${PARALLEL_MODE:-true}" \
            --arg axiom "${AXIOM:-false}" \
            --argjson subs "$subs_count" \
            --argjson webs "$webs_count" \
            --argjson hosts "$hosts_count" \
            --argjson screenshots "$screenshots_count" \
            --argjson findings_total "$findings_total" \
            --argjson sev_info "$sev_info" \
            --argjson sev_low "$sev_low" \
            --argjson sev_medium "$sev_medium" \
            --argjson sev_high "$sev_high" \
            --argjson sev_critical "$sev_critical" \
            --argjson top_assets "$top_assets_json" \
            --argjson timeline "$timeline_json" \
            --argjson links "$links_json" \
            --argjson delta "$monitor_delta_json" \
            --argjson alerts "$monitor_alerts_json" \
            '{
                generated_at:$generated_at,
                domain:$domain,
                mode:$mode,
                runtime:$runtime,
                metadata:{
                    perf_profile:$profile,
                    quick_rescan:($quick_rescan == "true"),
                    incremental:($incremental == "true"),
                    parallel:($parallel != "false"),
                    axiom:($axiom == "true")
                },
                summary:{
                    subdomains:$subs,
                    webs:$webs,
                    hosts:$hosts,
                    screenshots:$screenshots,
                    findings_total:$findings_total
                },
                severities:{
                    info:$sev_info,
                    low:$sev_low,
                    medium:$sev_medium,
                    high:$sev_high,
                    critical:$sev_critical
                },
                top_assets:$top_assets,
                timeline:$timeline,
                links:$links,
                delta_since_last:$delta,
                alerts_last:$alerts
            }' >"$report_json"
    else
        printf '{"generated_at":"%s","domain":"%s","mode":"%s","runtime":"%s"}\n' \
            "$(date -Iseconds)" "${domain:-unknown}" "${opt_mode:-unknown}" "${runtime:-unknown}" >"$report_json"
    fi

    # HTML renderer with inlined JSON payload.
    local report_payload
    report_payload=$(jq -c '.' "$report_json" 2>/dev/null || echo '{}')
    cat >"$report_html" <<EOF
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>reconFTW Report - ${domain}</title>
  <style>
    :root{--bg:#0b1320;--card:#111c2d;--text:#e8f0ff;--muted:#9ab0cc;--acc:#40c4ff;--ok:#32d583;--warn:#fdb022;--bad:#f97066}
    body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;background:linear-gradient(160deg,#0b1320,#0f1e35);color:var(--text)}
    .wrap{max-width:1100px;margin:0 auto;padding:20px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
    .card{background:var(--card);border:1px solid #1b2a44;border-radius:14px;padding:14px}
    h1,h2{margin:.2rem 0 .6rem}
    .muted{color:var(--muted);font-size:.92rem}
    .kpi{font-size:1.6rem;font-weight:700}
    table{width:100%;border-collapse:collapse}
    th,td{padding:8px;border-bottom:1px solid #213451;text-align:left;font-size:.93rem}
    a{color:var(--acc);text-decoration:none}
    .sev{display:flex;gap:10px;flex-wrap:wrap}
    .pill{padding:4px 10px;border-radius:999px;background:#15243b}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>reconFTW Consolidated Report</h1>
    <div class="muted" id="meta"></div>
    <div class="grid" id="kpis"></div>
    <h2>Severities</h2>
    <div class="sev" id="severities"></div>
    <h2>Top Assets</h2>
    <div class="card"><table><thead><tr><th>Asset</th><th>Score</th></tr></thead><tbody id="topAssets"></tbody></table></div>
    <h2>Delta Since Last Run</h2>
    <div class="sev" id="delta"></div>
    <h2>Timeline</h2>
    <div class="card"><table><thead><tr><th>Timestamp</th><th>Level</th><th>Function</th><th>Message</th></tr></thead><tbody id="timeline"></tbody></table></div>
    <h2>Quick Links</h2>
    <div class="card"><table><thead><tr><th>Name</th><th>Path</th></tr></thead><tbody id="links"></tbody></table></div>
  </div>
  <script>
    const REPORT = ${report_payload};
    const s = REPORT.summary || {};
    const sev = REPORT.severities || {};
    document.getElementById('meta').textContent =
      "Domain: " + (REPORT.domain||"n/a") + " | Mode: " + (REPORT.mode||"n/a") + " | Runtime: " + (REPORT.runtime||"n/a") + " | Generated: " + (REPORT.generated_at||"");
    const kpis = [
      ["Subdomains", s.subdomains||0],["Webs", s.webs||0],["Hosts", s.hosts||0],["Screenshots", s.screenshots||0],["Findings", s.findings_total||0]
    ];
    document.getElementById('kpis').innerHTML = kpis.map(([k,v]) => '<div class="card"><div class="muted">'+k+'</div><div class="kpi">'+v+'</div></div>').join('');
    document.getElementById('severities').innerHTML =
      [["Critical",sev.critical||0],["High",sev.high||0],["Medium",sev.medium||0],["Low",sev.low||0],["Info",sev.info||0]]
      .map(([k,v]) => '<span class="pill">'+k+': '+v+'</span>').join('');
    document.getElementById('topAssets').innerHTML = (REPORT.top_assets||[]).map(x => '<tr><td>'+x.asset+'</td><td>'+x.score+'</td></tr>').join('') || '<tr><td colspan="2">No data</td></tr>';
    const d = (REPORT.delta_since_last && REPORT.delta_since_last.deltas) ? REPORT.delta_since_last.deltas : {};
    document.getElementById('delta').innerHTML =
      [["New Subdomains",d.subdomains_new||0],["New Webs",d.webs_new||0],["New High",d.high_findings_new||0],["New Critical",d.critical_findings_new||0]]
      .map(([k,v]) => '<span class="pill">'+k+': '+v+'</span>').join('');
    document.getElementById('timeline').innerHTML = (REPORT.timeline||[]).slice(-40).reverse().map(x =>
      '<tr><td>'+ (x.timestamp||'') +'</td><td>'+ (x.level||'') +'</td><td>'+ (x.function||'') +'</td><td>'+ (x.message||'') +'</td></tr>'
    ).join('') || '<tr><td colspan="4">No data</td></tr>';
    document.getElementById('links').innerHTML = (REPORT.links||[]).map(x => {
      const mark = x.exists ? 'ok' : 'missing';
      return '<tr><td>'+x.name+' ('+mark+')</td><td><a href="../'+x.path+'">'+x.path+'</a></td></tr>';
    }).join('');
  </script>
</body>
</html>
EOF

    # Stable latest report paths for automation/UI.
    mkdir -p report/latest
    cp "$report_json" report/latest/report.json 2>/dev/null || true
    cp "$report_html" report/latest/index.html 2>/dev/null || true

    notification "Consolidated report generated at report/index.html" info
}

# Escape a value for CSV output.
_csv_escape() {
    local v="${1:-}"
    v=${v//\"/\"\"}
    printf '"%s"' "$v"
}

# Normalize findings into line-delimited JSON for downstream automation.
# Outputs:
#   - report/findings_normalized.jsonl
#   - report/assets.jsonl (copy of assets.jsonl if present)
#   - report/export_all.jsonl (assets + normalized findings)
function export_findings_jsonl() {
    ensure_dirs report || return 1
    local out_norm="report/findings_normalized.jsonl"
    local out_assets="report/assets.jsonl"
    local out_merged="report/export_all.jsonl"
    : >"$out_norm"

    local sev f
    for sev in info low medium high critical; do
        f="nuclei_output/${sev}_json.txt"
        [[ -s "$f" ]] || continue
        if command -v jq >/dev/null 2>&1; then
            jq -c --arg sev "$sev" '
                {
                  type:"finding",
                  tool:"nuclei",
                  severity:(.info.severity // $sev),
                  template_id:(.["template-id"] // ""),
                  matcher_name:(.["matcher-name"] // ""),
                  finding_type:(.type // ""),
                  target:(.["matched-at"] // .host // ""),
                  host:(.host // ""),
                  name:(.info.name // ""),
                  tags:(.info.tags // []),
                  extracted_results:(.["extracted-results"] // []),
                  source_file:input_filename
                }' "$f" >>"$out_norm" 2>/dev/null || true
        else
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                printf '{"type":"finding","tool":"nuclei","severity":"%s","raw":"%s"}\n' \
                    "$sev" "$(printf '%s' "$line" | sed 's/"/\\"/g')" >>"$out_norm"
            done <"$f"
        fi
    done

    if [[ -s assets.jsonl ]]; then
        cp assets.jsonl "$out_assets"
    else
        : >"$out_assets"
    fi

    cat "$out_assets" "$out_norm" >"$out_merged" 2>/dev/null || true
}

# Export CSV artifacts for quick triage.
# Outputs:
#   - report/subdomains.csv
#   - report/webs.csv
#   - report/hosts.csv
#   - report/findings.csv
function export_csv_artifacts() {
    ensure_dirs report || return 1

    # Subdomains CSV
    {
        printf "subdomain\n"
        if [[ -s subdomains/subdomains.txt ]]; then
            while IFS= read -r sub; do
                [[ -z "$sub" ]] && continue
                _csv_escape "$sub"; printf "\n"
            done <subdomains/subdomains.txt
        fi
    } >report/subdomains.csv

    # Webs CSV
    {
        printf "url,scheme,host\n"
        if [[ -s webs/webs_all.txt ]]; then
            while IFS= read -r url; do
                [[ -z "$url" ]] && continue
                local scheme host
                scheme=$(printf '%s' "$url" | awk -F:// '{print $1}')
                host=$(printf '%s' "$url" | awk -F/ '{print $3}' | sed 's/:.*$//')
                _csv_escape "$url"; printf ","
                _csv_escape "$scheme"; printf ","
                _csv_escape "$host"; printf "\n"
            done <webs/webs_all.txt
        fi
    } >report/webs.csv

    # Hosts CSV
    {
        printf "ip\n"
        if [[ -s hosts/ips.txt ]]; then
            while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                _csv_escape "$ip"; printf "\n"
            done <hosts/ips.txt
        fi
    } >report/hosts.csv

    # Findings CSV (prefer normalized JSONL)
    if [[ ! -s report/findings_normalized.jsonl ]]; then
        export_findings_jsonl
    fi
    if command -v jq >/dev/null 2>&1 && [[ -s report/findings_normalized.jsonl ]]; then
        {
            printf "tool,severity,template_id,name,target,host,finding_type,matcher_name\n"
            jq -r '[.tool,.severity,.template_id,.name,.target,.host,.finding_type,.matcher_name] | @csv' report/findings_normalized.jsonl
        } >report/findings.csv
    else
        {
            printf "raw\n"
            [[ -s report/findings_normalized.jsonl ]] && while IFS= read -r line; do _csv_escape "$line"; printf "\n"; done <report/findings_normalized.jsonl
        } >report/findings.csv
    fi
}

# Export clean text artifacts for copy/paste workflows.
# Outputs:
#   - report/subdomains_clean.txt
#   - report/webs_clean.txt
#   - report/ips_clean.txt
function export_clean_text_artifacts() {
    ensure_dirs report || return 1

    if [[ -s subdomains/subdomains.txt ]]; then
        sed '/^$/d' subdomains/subdomains.txt | sort -u >report/subdomains_clean.txt
    else
        : >report/subdomains_clean.txt
    fi

    if [[ -s webs/webs_all.txt ]]; then
        sed '/^$/d' webs/webs_all.txt | sort -u >report/webs_clean.txt
    else
        : >report/webs_clean.txt
    fi

    cat hosts/ips.txt hosts/ips_v6.txt 2>/dev/null | sed '/^$/d' | sort -u >report/ips_clean.txt
}

# Export orchestrator.
# EXPORT_FORMAT values: json | html | csv | all
function export_reports() {
    local fmt="${EXPORT_FORMAT:-}"
    [[ -z "$fmt" ]] && return 0

    # Ensure base consolidated report exists for all export types.
    [[ -s report/report.json && -s report/index.html ]] || generate_consolidated_report || true

    case "$fmt" in
        json)
            export_findings_jsonl
            export_clean_text_artifacts
            notification "Exported JSON artifacts under report/" info
            ;;
        html)
            export_clean_text_artifacts
            notification "Exported HTML report at report/index.html" info
            ;;
        csv)
            export_findings_jsonl
            export_csv_artifacts
            export_clean_text_artifacts
            notification "Exported CSV artifacts under report/" info
            ;;
        all)
            export_findings_jsonl
            export_csv_artifacts
            export_clean_text_artifacts
            notification "Exported JSONL + CSV + HTML artifacts under report/" info
            ;;
        *)
            notification "Unknown EXPORT_FORMAT '$fmt' (expected json|html|csv|all)" warn
            ;;
    esac
}

function health_check() {
    local failures=0
    local warnings=0

    _print_section "Health Check"

    # 1. Check critical tools
    _print_status INFO "Checking critical tools..."
    local critical_tools=("bash" "python3" "curl" "git" "jq")
    for tool in "${critical_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            _print_status OK "$tool"
        else
            _print_status FAIL "$tool" "not found"
            ((failures++))
        fi
    done

    # 2. Check key recon tools
    _print_status INFO "Checking recon tools..."
    local recon_tools=("subfinder" "httpx" "nuclei" "ffuf" "dnsx" "anew" "notify" "nmap" "nmapurls")
    for tool in "${recon_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            _print_status OK "$tool"
        else
            _print_status WARN "$tool" "not found"
            ((warnings++))
        fi
    done

    # 3. Check network connectivity
    _print_status INFO "Checking network connectivity..."
    if run_command curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" "https://www.google.com" | grep -q "200\|301\|302"; then
        _print_status OK "Internet connectivity"
    else
        _print_status WARN "No internet connectivity"
        ((warnings++))
    fi

    # 4. Check disk space
    _print_status INFO "Checking disk space..."
    local avail_gb
    avail_gb=$(df -Pk . 2>/dev/null | awk 'NR==2 {print int($4 / 1024 / 1024)}')
    avail_gb=${avail_gb:-0}

    if [[ ${avail_gb} -ge 5 ]]; then
        _print_status OK "Disk space" "${avail_gb} GB available"
    elif [[ ${avail_gb} -ge 1 ]]; then
        _print_status WARN "Disk space" "Only ${avail_gb} GB available (recommend 5+ GB)"
        ((warnings++))
    else
        _print_status FAIL "Disk space" "Less than 1 GB available"
        ((failures++))
    fi

    # 5. Check resolver files
    _print_status INFO "Checking resolver files..."
    local resolvers_path="${resolvers:-${SCRIPTPATH}/resolvers.txt}"
    if [[ -s "$resolvers_path" ]]; then
        local count
        count=$(wc -l <"$resolvers_path")
        _print_status OK "Resolvers file" "${resolvers_path} (${count} entries)"
    else
        _print_status WARN "Resolvers file" "not found or empty: ${resolvers_path}"
        ((warnings++))
    fi

    # 6. Check API key status
    _print_status INFO "Checking API keys..."
    local -A api_keys=(
        ["SHODAN_API_KEY"]="${SHODAN_API_KEY:-}"
        ["WHOISXML_API"]="${WHOISXML_API:-}"
        ["GITHUB_TOKEN"]="${GITHUB_TOKEN:-}"
        ["VIRUSTOTAL_API_KEY"]="${VIRUSTOTAL_API_KEY:-}"
    )
    for key_name in "${!api_keys[@]}"; do
        if [[ -n "${api_keys[$key_name]}" ]]; then
            _print_status OK "$key_name" "configured"
        else
            _print_status INFO "$key_name" "not set"
        fi
    done

    # Summary
    _print_rule
    if [[ $failures -gt 0 ]]; then
        _print_status FAIL "Health check" "${failures} FAILURES, ${warnings} warnings"
    elif [[ $warnings -gt 0 ]]; then
        _print_status WARN "Health check" "PASSED with ${warnings} warnings"
    else
        _print_status OK "Health check" "ALL PASSED"
    fi

    return $failures
}
