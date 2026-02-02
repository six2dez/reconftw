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

# --------------------------------------
# Classic UI wrappers (no tput/icons)
# --------------------------------------

pt_header() { :; }
pt_msg_run() { printf "\n%b[%s] %s%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$1" "$reset"; }
pt_msg_ok() { printf "\n%b[%s] %s%b\n" "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$1" "$reset"; }
pt_msg_warn() { printf "\n%b[%s] %s%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$1" "$reset"; }
pt_msg_err() { printf "\n%b[%s] %s%b\n" "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$1" "$reset"; }

# Ensure a safe default for early log redirections
# If LOGFILE is unset or empty, send logs to /dev/null until later initialization
: "${LOGFILE:=/dev/null}"

enable_command_trace() {
    # Enable bash xtrace to the current LOGFILE when SHOW_COMMANDS=true
    if [[ ${SHOW_COMMANDS:-false} != true ]]; then
        return
    fi
    [[ -z ${LOGFILE:-} ]] && return

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
        printf "\n %s                                 by @six2dez%b\n" "$reconftw_version" "$reset"
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
        printf "\n%bGit is not installed. Cannot check for updates.%b\n\n" "$bred" "$reset"
        return 1
    fi

    # Check if current directory is a git repository
    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        printf "\n%bCurrent directory is not a git repository. Cannot check for updates.%b\n\n" "$bred" "$reset"
        return 1
    fi

    # Fetch updates with a timeout (supports gtimeout on macOS)
    if ! { [[ -n $TIMEOUT_CMD ]] && $TIMEOUT_CMD 10 git fetch >/dev/null 2>&1; } && ! git fetch >/dev/null 2>&1; then
        printf "\n%bUnable to check updates (git fetch timed out).%b\n\n" "$bred" "$reset"
        return 1
    fi

    # Get current branch name
    local BRANCH
    BRANCH=$(git rev-parse --abbrev-ref HEAD)

    # Get upstream branch
    local UPSTREAM
    UPSTREAM=$(git rev-parse --abbrev-ref --symbolic-full-name "@{u}" 2>/dev/null)
    if [[ -z $UPSTREAM ]]; then
        printf "\n%bNo upstream branch set for '%s'. Cannot check for updates.%b\n\n" "$bred" "$BRANCH" "$reset"
        return 1
    fi

    # Get local and remote commit hashes
    local LOCAL REMOTE
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse "$UPSTREAM")

    # Compare local and remote hashes
    if [[ $LOCAL != "$REMOTE" ]]; then
        printf "\n%bThere is a new version available. Run ./install.sh to get the latest version.%b\n\n" "$yellow" "$reset"
    fi
}

function tools_installed() {
    # Check if all tools are installed
    printf "\n\n%b#######################################################################%b\n" "$bgreen" "$reset"
    printf "%b[%s] Checking installed tools %b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"

    local all_installed=true
    local missing_tools=()

    # Check environment variables
    local env_vars=("GOPATH" "GOROOT" "PATH")
    for var in "${env_vars[@]}"; do
        if [[ -z ${!var} ]]; then
            printf "%b [*] %s variable\t\t[NO]%b\n" "$bred" "$var" "$reset"
            all_installed=false
            missing_tools+=("$var environment variable")
        fi
    done

    # Define tools and their paths/commands
    declare -A tools_files=(
        ["dorks_hunter"]="${tools}/dorks_hunter/dorks_hunter.py"
        ["dorks_hunter_python"]="${tools}/dorks_hunter/venv/bin/python3"
        ["fav-up"]="${tools}/fav-up/favUp.py"
        ["fav-up_python"]="${tools}/fav-up/venv/bin/python3"
        ["Corsy"]="${tools}/Corsy/corsy.py"
        ["Corsy_python"]="${tools}/Corsy/venv/bin/python3"
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
        ["pydictor"]="${tools}/pydictor/pydictor.py"
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
        ["Oralyzer"]="${tools}/Oralyzer/oralyzer.py"
        ["Oralyzer_python"]="${tools}/Oralyzer/venv/bin/python3"
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
    )

    declare -A tools_folders=(
        ["NUCLEI_TEMPLATES_PATH"]="${NUCLEI_TEMPLATES_PATH}"
    )

    declare -A tools_commands=(
        ["python3"]="python3"
        ["curl"]="curl"
        ["wget"]="wget"
        ["zip"]="zip"
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
        ["ppmap"]="ppmap"
        ["cdncheck"]="cdncheck"
        ["interactsh-client"]="interactsh-client"
        ["tlsx"]="tlsx"
        ["smap"]="smap"
        ["gitdorks_go"]="gitdorks_go"
        ["ripgen"]="ripgen"
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
        ["porch-pirate"]="porch-pirate"
        ["shortscan"]="shortscan"
        ["sns"]="sns"
        ["sourcemapper"]="sourcemapper"
        ["jsluice"]="jsluice"
        ["commix"]="commix"
        ["urless"]="urless"
        ["dnstake"]="dnstake"
        ["cent"]="cent"
        ["csprecon"]="csprecon"
        ["VhostFinder"]="VhostFinder"
        ["grpcurl"]="grpcurl"
        ["arjun"]="arjun"
        ["gqlspection"]="gqlspection"
        ["cloud_enum"]="cloud_enum"
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
        printf "%b\n Good! All tools are installed! %b\n\n" "$bgreen" "$reset"
    else
        printf "\n%bSome tools or directories are missing:%b\n\n" "$yellow" "$reset"
        for tool in "${missing_tools[@]}"; do
            printf "%b - %s %b\n" "$bred" "$tool" "$reset"
        done
        printf "\n%bTry running the installer script again: ./install.sh%b\n" "$yellow" "$reset"
        printf "%bIf it fails, try installing the missing tools manually.%b\n" "$yellow" "$reset"
        printf "%bEnsure that the %b\$tools%b variable is correctly set at the start of this script.%b\n" "$yellow" "$bred" "$yellow" "$reset"
        printf "%bIf you need assistance, feel free to contact me! :D%b\n\n" "$yellow" "$reset"
    fi

    printf "%b[%s] Tools check finished%b\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
    printf "%b#######################################################################\n%b" "$bgreen" "$reset"

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
    local all_critical_ok=true

    printf "\n%b#######################################################################%b\n" "$bgreen" "$reset"
    printf "%b[%s] Checking critical dependencies%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"

    for item in "${critical_tools[@]}"; do
        local tool="${item%%:*}"
        local description="${item#*:}"

        if ! command -v "$tool" >/dev/null 2>&1; then
            printf "%b [✗] %s (%s) - MISSING%b\n" "$bred" "$description" "$tool" "$reset"
            missing_critical+=("$tool")
            all_critical_ok=false
        else
            local version=""
            case "$tool" in
                "python3")
                    version=$($tool --version 2>&1 | head -n1)
                    ;;
                "bash")
                    version="$BASH_VERSION"
                    ;;
                *)
                    version=$($tool --version 2>&1 | head -n1 || echo "installed")
                    ;;
            esac
            printf "%b [✓] %s (%s) - %s%b\n" "$bgreen" "$description" "$tool" "$version" "$reset"
        fi
    done

    printf "\n"

    if [[ $all_critical_ok == false ]]; then
        printf "%b[%s] ERROR: Critical dependencies missing!%b\n" "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
        printf "%bThe following tools are required for reconFTW to function:%b\n" "$yellow" "$reset"
        for tool in "${missing_critical[@]}"; do
            printf "%b  - %s%b\n" "$bred" "$tool" "$reset"
        done
        printf "\n%bPlease install these tools and try again.%b\n" "$yellow" "$reset"
        printf "%bYou can run: ./install.sh to install all dependencies.%b\n" "$yellow" "$reset"
        printf "%b#######################################################################%b\n\n" "$bgreen" "$reset"
        exit 1
    else
        printf "%b[%s] All critical dependencies are installed%b\n" "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
        printf "%b#######################################################################%b\n\n" "$bgreen" "$reset"
    fi
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

    printf "%b[%s] Structured logging enabled: %s%b\n" \
        "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$STRUCTURED_LOG_FILE" "$reset"
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

    printf "%b[%s] Incremental mode enabled - will only process new findings%b\n" \
        "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
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
        printf "%b[%s] Incremental mode: First run for %s - %d items total%b\n" \
            "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$type" "$count" "$reset"
        return 0
    fi

    # Compare and get only new items
    if [[ -s "$current_file" ]]; then
        comm -13 <(sort -u "$previous_file") <(sort -u "$current_file") | sed '/^$/d' >"$output_file"
        local new_count total_count previous_count
        new_count=$(wc -l <"$output_file" 2>/dev/null || echo 0)
        total_count=$(wc -l <"$current_file" 2>/dev/null || echo 0)
        previous_count=$(wc -l <"$previous_file" 2>/dev/null || echo 0)

        printf "%b[%s] Incremental mode %s: %d new (previous: %d, total: %d)%b\n" \
            "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$type" "$new_count" "$previous_count" "$total_count" "$reset"

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

    local report_file="$INCREMENTAL_DIR/incremental_report_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "==============================================="
        echo "Incremental Scan Report"
        echo "Domain: $domain"
        echo "Date: $(date +'%Y-%m-%d %H:%M:%S')"
        echo "==============================================="
        echo ""

        # Subdomain changes
        if [[ -f "$INCREMENTAL_DIR/previous/subdomains_latest.txt" ]]; then
            local new_subs=$(comm -13 <(sort -u "$INCREMENTAL_DIR/previous/subdomains_latest.txt" 2>/dev/null || touch /tmp/empty) \
                <(sort -u "subdomains/subdomains.txt" 2>/dev/null || touch /tmp/empty) | wc -l)
            echo "New Subdomains: $new_subs"
            if [[ $new_subs -gt 0 ]]; then
                echo "---"
                comm -13 <(sort -u "$INCREMENTAL_DIR/previous/subdomains_latest.txt" 2>/dev/null || touch /tmp/empty) \
                    <(sort -u "subdomains/subdomains.txt" 2>/dev/null || touch /tmp/empty) | head -20
                [[ $new_subs -gt 20 ]] && echo "... and $((new_subs - 20)) more"
                echo ""
            fi
        fi

        # Web changes
        if [[ -f "$INCREMENTAL_DIR/previous/webs_latest.txt" ]]; then
            local new_webs=$(comm -13 <(sort -u "$INCREMENTAL_DIR/previous/webs_latest.txt" 2>/dev/null || touch /tmp/empty) \
                <(sort -u "webs/webs.txt" 2>/dev/null || touch /tmp/empty) | wc -l)
            echo "New Webs: $new_webs"
            if [[ $new_webs -gt 0 ]]; then
                echo "---"
                comm -13 <(sort -u "$INCREMENTAL_DIR/previous/webs_latest.txt" 2>/dev/null || touch /tmp/empty) \
                    <(sort -u "webs/webs.txt" 2>/dev/null || touch /tmp/empty) | head -20
                [[ $new_webs -gt 20 ]] && echo "... and $((new_webs - 20)) more"
                echo ""
            fi
        fi

        echo "==============================================="
        echo "Full report saved to: $report_file"
        echo "==============================================="
    } | tee "$report_file"

    printf "%b[%s] Incremental report generated: %s%b\n" \
        "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$report_file" "$reset"
}

# Check if incremental mode should skip heavy operations
# Usage: incremental_should_skip
# Returns: 0 to skip, 1 to continue
function incremental_should_skip() {
    [[ "$INCREMENTAL_MODE" != "true" ]] && return 1 # Don't skip

    # Check if we have new findings
    local new_subs=$(cat .tmp/subs_new_count 2>/dev/null || echo 1)
    local new_webs=$(cat .tmp/webs_new_count 2>/dev/null || echo 1)

    if [[ $new_subs -eq 0 && $new_webs -eq 0 ]]; then
        printf "%b[%s] Incremental mode: No new assets found, skipping heavy scans%b\n" \
            "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
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
    IS_ASCII="False"
    if [[ $(file $1 | grep -o 'ASCII text$') == "ASCII text" ]]; then
        IS_ASCII="True"
    else
        IS_ASCII="False"
    fi
}

function output() {
    mkdir -p "$dir_output"
    # Ensure both $dir and $dir_output are absolute paths
    dir="$(realpath "$dir")"
    dir_output="$(realpath "$dir_output")"

    # Prevent accidental deletion if $dir_output is a parent of $dir
    if [[ $dir == "$dir_output"* ]]; then
        echo "[!] Output directory is a parent of the working directory. Aborting to prevent data loss."
        return 1
    fi

    cp -r "$dir" "$dir_output"

    # Only delete if source and destination are clearly different and safe
    # Safety: refuse to delete outside of Recon/ directory
    if [[ "$(dirname "$dir")" != "$dir_output" ]]; then
        if [[ "$dir" == "${SCRIPTPATH}/Recon/"* ]]; then
            rm -rf -- "$dir"
        else
            echo "[!] Refusing to delete directory outside Recon/: $dir"
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
        if [[ -z $3 ]]; then
            current_date=$(date +'%Y-%m-%d %H:%M:%S')
        else
            current_date="$3"
        fi

        case $2 in
            info)
                text="\n${bblue}[$current_date] ${1} ${reset}"
                ;;
            warn)
                text="\n${yellow}[$current_date] ${1} ${reset}"
                ;;
            error)
                text="\n${bred}[$current_date] ${1} ${reset}"
                ;;
            good)
                text="\n${bgreen}[$current_date] ${1} ${reset}"
                ;;
        esac

        # Print to terminal
        printf "${text}\n"

        # Send to notify if notifications are enabled
        if [[ -n $NOTIFY ]]; then
            # Remove color codes for the notification
            clean_text=$(printf "%b" "${text} - ${domain}" | sed 's/\x1B\[[0-9;]*[JKmsu]//g')
            printf "%s" "${clean_text}" | $NOTIFY >/dev/null 2>&1
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
        tar -czvf /tmp/$file_name $file >/dev/null 2>&1 && curl -s https://bashupload.com/$file.tgz --data-binary @/tmp/$file_name | grep wget
    else
        file_name=$1
        tar -czvf /tmp/$file_name $file >/dev/null 2>&1 && curl -s https://bashupload.com/$file.tgz --data-binary @/tmp/$file_name | grep wget
    fi
}

function sendToNotify {
    if [[ -z $1 ]]; then
        printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] No file provided to send ${reset}\n"
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
            notification "[$(date +'%Y-%m-%d %H:%M:%S')] Sending ${domain} data over Telegram" info
            telegram_chat_id=$(sed -n '/^telegram:/,/^[^ ]/p' ${NOTIFY_CONFIG} | sed -n 's/^[ ]*telegram_chat_id:[ ]*"\([^"]*\)".*/\1/p')
            telegram_key=$(sed -n '/^telegram:/,/^[^ ]/p' ${NOTIFY_CONFIG} | sed -n 's/^[ ]*telegram_api_key:[ ]*"\([^"]*\)".*/\1/p')
            curl -F "chat_id=${telegram_chat_id}" -F "document=@${1}" https://api.telegram.org/bot${telegram_key}/sendDocument 2>>"$LOGFILE" >/dev/null
        fi
        if grep -q '^ discord\|^discord\|^    discord' $NOTIFY_CONFIG; then
            notification "[$(date +'%Y-%m-%d %H:%M:%S')] Sending ${domain} data over Discord" info
            discord_url=$(sed -n '/^discord:/,/^[^ ]/p' ${NOTIFY_CONFIG} | sed -n 's/^[ ]*discord_webhook_url:[ ]*"\([^"]*\)".*/\1/p')
            curl -v -i -H "Accept: application/json" -H "Content-Type: multipart/form-data" -X POST -F 'payload_json={"username": "test", "content": "hello"}' -F file1=@${1} $discord_url 2>>"$LOGFILE" >/dev/null
        fi
        if [[ -n $slack_channel ]] && [[ -n $slack_auth ]]; then
            notification "[$(date +'%Y-%m-%d %H:%M:%S')] Sending ${domain} data over Slack" info
            curl -F file=@${1} -F "initial_comment=reconftw zip file" -F channels=${slack_channel} -H "Authorization: Bearer ${slack_auth}" https://slack.com/api/files.upload 2>>"$LOGFILE" >/dev/null
        fi
    fi
}

function start_func() {
    printf "${bgreen}#######################################################################"
    notification "${2}" info
    echo "[$current_date] Start function: ${1} " >>"${LOGFILE}"
    start=$(date +%s)
}

function end_func() {
    touch "$called_fn_dir/.${2}"
    end=$(date +%s)
    getElapsedTime "$start" "$end"
    # Record timing for performance summary
    record_func_timing "${2}" "$((end - start))"
    notification "${2} Finished in ${runtime}" info
    echo "[$current_date] End function: ${2} " >>"${LOGFILE}"
    printf "${bblue}[$current_date] ${1} ${reset}\n"
    printf "${bgreen}#######################################################################${reset}\n"
}

function start_subfunc() {
    notification "     ${2}" info
    echo "[$current_date] Start subfunction: ${1} " >>"${LOGFILE}"
    start_sub=$(date +%s)
}

function end_subfunc() {
    touch "$called_fn_dir/.${2}"
    end_sub=$(date +%s)
    getElapsedTime "$start_sub" "$end_sub"
    notification "     ${1} in ${runtime}" good
    echo "[$current_date] End subfunction: ${1} " >>"${LOGFILE}"
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
            nuclei -update-templates -update-template-dir "${NUCLEI_TEMPLATES_PATH}" 2>>"$LOGFILE" >/dev/null || true # non-fatal: template update failure shouldn't block scan
        else
            nuclei -update 2>>"$LOGFILE" >/dev/null || true # non-fatal: template update failure shouldn't block scan
        fi
        touch "$stamp_file"
    fi
}

# Plugin framework
PLUGINS_LOADED=false
function plugins_load() {
    local plugdir="${SCRIPTPATH}/plugins"
    if [[ -d $plugdir ]]; then
        for f in "$plugdir"/*.sh; do
            [[ -f $f ]] && source "$f" || true
        done
    fi
    PLUGINS_LOADED=true
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
    # Print sorted timing summary of all recorded functions
    if [[ ${#FUNC_TIMINGS[@]} -eq 0 ]] 2>/dev/null; then
        return 0
    fi

    printf "\n%b#######################################################################%b\n" "$bgreen" "$reset"
    printf "%b[%s] Performance Timing Summary%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"

    local total=0
    local fn dur

    # Collect and sort by duration (descending)
    for fn in "${!FUNC_TIMINGS[@]}"; do
        dur=${FUNC_TIMINGS[$fn]}
        total=$((total + dur))
        printf "%s %s\n" "$dur" "$fn"
    done | sort -rn | while read -r dur fn; do
        local pct=0
        if [[ $total -gt 0 ]]; then
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

function health_check() {
    local failures=0
    local warnings=0

    printf "\n%b#######################################################################%b\n" "$bgreen" "$reset"
    printf "%b[%s] reconFTW Health Check%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"

    # 1. Check critical tools
    printf "%b[*] Checking critical tools...%b\n" "$yellow" "$reset"
    local critical_tools=("bash" "python3" "curl" "git" "jq")
    for tool in "${critical_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf "  %b[OK]%b %s\n" "$bgreen" "$reset" "$tool"
        else
            printf "  %b[FAIL]%b %s not found\n" "$bred" "$reset" "$tool"
            ((failures++))
        fi
    done

    # 2. Check key recon tools
    printf "\n%b[*] Checking recon tools...%b\n" "$yellow" "$reset"
    local recon_tools=("subfinder" "httpx" "nuclei" "naabu" "ffuf" "dnsx" "anew" "notify")
    for tool in "${recon_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf "  %b[OK]%b %s\n" "$bgreen" "$reset" "$tool"
        else
            printf "  %b[WARN]%b %s not found\n" "$byellow" "$reset" "$tool"
            ((warnings++))
        fi
    done

    # 3. Check network connectivity
    printf "\n%b[*] Checking network connectivity...%b\n" "$yellow" "$reset"
    if curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" "https://www.google.com" | grep -q "200\|301\|302"; then
        printf "  %b[OK]%b Internet connectivity\n" "$bgreen" "$reset"
    else
        printf "  %b[WARN]%b No internet connectivity\n" "$byellow" "$reset"
        ((warnings++))
    fi

    # 4. Check disk space
    printf "\n%b[*] Checking disk space...%b\n" "$yellow" "$reset"
    local avail_gb
    avail_gb=$(df -BG . 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4}' || df -g . 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    if [[ ${avail_gb:-0} -ge 5 ]]; then
        printf "  %b[OK]%b %s GB available\n" "$bgreen" "$reset" "$avail_gb"
    elif [[ ${avail_gb:-0} -ge 1 ]]; then
        printf "  %b[WARN]%b Only %s GB available (recommend 5+ GB)\n" "$byellow" "$reset" "$avail_gb"
        ((warnings++))
    else
        printf "  %b[FAIL]%b Less than 1 GB available\n" "$bred" "$reset"
        ((failures++))
    fi

    # 5. Check resolver files
    printf "\n%b[*] Checking resolver files...%b\n" "$yellow" "$reset"
    local resolvers_path="${resolvers:-${SCRIPTPATH}/resolvers.txt}"
    if [[ -s "$resolvers_path" ]]; then
        local count
        count=$(wc -l <"$resolvers_path")
        printf "  %b[OK]%b Resolvers file: %s (%s entries)\n" "$bgreen" "$reset" "$resolvers_path" "$count"
    else
        printf "  %b[WARN]%b Resolvers file not found or empty: %s\n" "$byellow" "$reset" "$resolvers_path"
        ((warnings++))
    fi

    # 6. Check API key status
    printf "\n%b[*] Checking API keys...%b\n" "$yellow" "$reset"
    local -A api_keys=(
        ["SHODAN_API_KEY"]="${SHODAN_API_KEY:-}"
        ["WHOISXML_API"]="${WHOISXML_API:-}"
        ["GITHUB_TOKEN"]="${GITHUB_TOKEN:-}"
        ["VIRUSTOTAL_API_KEY"]="${VIRUSTOTAL_API_KEY:-}"
    )
    for key_name in "${!api_keys[@]}"; do
        if [[ -n "${api_keys[$key_name]}" ]]; then
            printf "  %b[OK]%b %s configured\n" "$bgreen" "$reset" "$key_name"
        else
            printf "  %b[INFO]%b %s not set\n" "$bblue" "$reset" "$key_name"
        fi
    done

    # Summary
    printf "\n%b#######################################################################%b\n" "$bgreen" "$reset"
    if [[ $failures -gt 0 ]]; then
        printf "%b[%s] Health check: %d FAILURES, %d warnings%b\n" \
            "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$failures" "$warnings" "$reset"
    elif [[ $warnings -gt 0 ]]; then
        printf "%b[%s] Health check: PASSED with %d warnings%b\n" \
            "$byellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$warnings" "$reset"
    else
        printf "%b[%s] Health check: ALL PASSED%b\n" \
            "$bgreen" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
    fi
    printf "%b#######################################################################%b\n\n" "$bgreen" "$reset"

    return $failures
}
