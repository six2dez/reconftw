#!/bin/bash
# shellcheck disable=SC2154,SC2034

# Safer bash defaults
set -o pipefail
set -E
set +e
IFS=$'\n\t'

# Detect if the script is being run in MacOS with Homebrew Bash
if [[ $OSTYPE == "darwin"* && $BASH != "/opt/homebrew/bin/bash" ]]; then
    exec /opt/homebrew/bin/bash "$0" "$@"
fi

# Load main configuration
CONFIG_FILE="./reconftw.cfg"

if [[ ! -f $CONFIG_FILE ]]; then
    printf "%b[!] Config file reconftw.cfg not found.%b\n" "$bred" "$reset"
    exit 1
fi

# shellcheck source=./reconftw.cfg
if ! source "$CONFIG_FILE"; then
    printf "[!] Failed to parse config file %s. Check for syntax errors.\n" "$CONFIG_FILE" >&2
    exit 1
fi

# Initialize variables
dir="${tools}"
double_check=false

# ARM Detection
ARCH=$(uname -m)

# macOS Detection
IS_MAC=$([[ $OSTYPE == "darwin"* ]] && echo "True" || echo "False")

# timeout/gtimeout compatibility
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
else
    TIMEOUT_CMD=""
fi

# Globals for CLI overrides
FORCE_UPDATE=${FORCE_UPDATE:-false}
VERBOSE=${VERBOSE:-false}
LOGFILE=${LOGFILE-}
DRY_RUN=${DRY_RUN:-false}
TOOLS_ONLY=${TOOLS_ONLY:-false}

# If LOGFILE provided via env/flag, tee all output
if [[ -n ${LOGFILE} ]]; then
    exec > >(tee -a "${LOGFILE}") 2>&1
fi

# Helper: run with timeout seconds if available
run_to() {
    local secs=$1
    shift || true
    if [[ -n $TIMEOUT_CMD ]]; then "$TIMEOUT_CMD" "$secs" "$@"; else "$@"; fi
}

# Helper: optionally dry-run
run_cmd() {
    if [[ $DRY_RUN == "true" ]]; then
        printf "%s\n" "[DRY-RUN] $*"
        return 0
    fi
    "$@"
}

# Helper: quiet run (respect VERBOSE)
q() {
    if [[ $DRY_RUN == "true" ]]; then
        printf "%s\n" "[DRY-RUN] $*"
        return 0
    fi
    if [[ $VERBOSE == "true" ]]; then "$@"; else { "$@"; } &>/dev/null; fi
}

# Helper: quiet run with timeout
q_to() {
    local secs=$1
    shift || true
    if [[ $DRY_RUN == "true" ]]; then
        printf "%s\n" "[DRY-RUN] (to ${secs}) $*"
        return 0
    fi
    if [[ -n $TIMEOUT_CMD ]]; then
        if [[ $VERBOSE == "true" ]]; then "$TIMEOUT_CMD" "$secs" "$@"; else { "$TIMEOUT_CMD" "$secs" "$@"; } &>/dev/null; fi
    else
        if [[ $VERBOSE == "true" ]]; then "$@"; else { "$@"; } &>/dev/null; fi
    fi
}

# Helper: retry with linear backoff
retry() {
    local attempts=$1
    local delay=$2
    shift 2
    local n=0
    until "$@"; do
        n=$((n + 1))
        if ((n >= attempts)); then return 1; fi
        sleep $((delay * n))
    done
}

ensure_git_dir() {
    local _path="$1"
    if [[ -d "$_path" && ! -d "$_path/.git" ]]; then
        rm -rf "$_path" 2>/dev/null || true
    fi
}

# Install Rust toolchain, uv package manager, smugglex, and shodan CLI.
# Called from install_apt/install_yum/install_pacman/install_brew to avoid duplication.
install_rust_uv() {
    local _tmpfile
    # Install rustup via downloaded script (verify before executing)
    _tmpfile=$(mktemp "${TMPDIR:-/tmp}/rustup_install.XXXXXX")
    if curl -sSf https://sh.rustup.rs -o "$_tmpfile" 2>/dev/null; then
        sh "$_tmpfile" -y >/dev/null 2>&1
    else
        msg_warn "[!] Failed to download rustup installer"
    fi
    rm -f "$_tmpfile"

    # shellcheck source=/dev/null
    source "${HOME}/.cargo/env" 2>/dev/null || true
    cargo install smugglex &>/dev/null

    # Install uv via downloaded script (verify before executing)
    _tmpfile=$(mktemp "${TMPDIR:-/tmp}/uv_install.XXXXXX")
    if curl -LsSf https://astral.sh/uv/install.sh -o "$_tmpfile" 2>/dev/null; then
        sh "$_tmpfile" &>/dev/null
    else
        msg_warn "[!] Failed to download uv installer"
    fi
    rm -f "$_tmpfile"

    # shellcheck source=/dev/null
    source "${HOME}/.local/bin/env" 2>/dev/null || export PATH="${HOME}/.local/bin:$PATH"
    uv tool update-shell &>/dev/null || true
    # Install shodan CLI via uv
    uv tool install shodan --force &>/dev/null || uv tool upgrade shodan &>/dev/null || true
}

# Non-fatal error trap: log and continue
trap 'rc=$?; ts=$(date +"%Y-%m-%d %H:%M:%S"); cmd=${BASH_COMMAND}; loc_ln=${BASH_LINENO[0]:-0}; msg="[$ts] install.sh ERR($rc) @ line ${loc_ln} :: ${cmd}"; if [[ -n "${LOGFILE:-}" ]]; then echo "$msg" >>"$LOGFILE"; else echo "$msg" >&2; fi' ERR

# -------------------------------
# Minimal UI helpers (classic style)
# -------------------------------

header() { printf "%bRunning: %s%b\n" "$bblue" "$1" "$reset"; }
msg_run() { printf "%b%s%b\n" "$yellow" "$1" "$reset"; }
msg_ok() { printf "%b%s%b\n" "$bgreen" "$1" "$reset"; }
msg_warn() { printf "%b%s%b\n" "$yellow" "$1" "$reset"; }
msg_err() { printf "%b%s%b\n" "$red" "$1" "$reset"; }

with_spinner() {
    local _msg="$1"
    shift
    if [[ $DRY_RUN == "true" ]]; then
        printf "%s\n" "[DRY-RUN] ${_msg}"
        printf "%s\n" "[DRY-RUN] $*"
        return 0
    fi
    if [[ $VERBOSE == "true" ]]; then
        [[ -n $_msg ]] && printf "%s\n" "$_msg"
        "$@"
        return $?
    fi
    if [[ ! -t 1 ]]; then
        [[ -n $_msg ]] && printf "%s ... " "$_msg"
        "$@" >/dev/null 2>&1
        local exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            printf "done\n"
        else
            printf "failed\n"
        fi
        return $exit_code
    fi
    local spinner="|/-\\"
    local spinner_len=4
    local i=0
    [[ -n $_msg ]] && printf "%s " "$_msg"
    "$@" &
    local cmd_pid=$!
    while kill -0 "$cmd_pid" 2>/dev/null; do
        printf "\r%s %s" "$_msg" "${spinner:i:1}"
        i=$(((i + 1) % spinner_len))
        sleep 0.1
    done
    wait "$cmd_pid"
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        printf "\r%s done\n" "$_msg"
    else
        printf "\r%s failed\n" "$_msg"
    fi
    return $exit_code
}

# Basic network precheck
check_network() {
    printf "%bRunning: Network precheck%b\n" "$bblue" "$reset"
    local _net_ok=true
    # Silence successful output; show message only on failure. Use q_to to respect --verbose.
    if ! q_to 5 bash -lc 'getent hosts github.com >/dev/null 2>&1 || dig +short github.com >/dev/null 2>&1 || nslookup github.com >/dev/null 2>&1'; then
        printf "%b[!] DNS resolution for github.com failed. Check your network.%b\n" "$bred" "$reset"
        _net_ok=false
    fi
    if ! q_to 10 curl -I -s https://github.com >/dev/null 2>&1; then
        printf "%b[!] HTTPS connectivity to github.com failed. Installer may fail.%b\n" "$yellow" "$reset"
        _net_ok=false
    fi
    if [[ $_net_ok == true ]]; then
        printf "%bNetwork OK%b\n" "$bgreen" "$reset"
    fi
}

# Check Bash version
BASH_VERSION_NUM=$(bash --version | awk 'NR==1{print $4}' | cut -d'.' -f1)
if [[ $BASH_VERSION_NUM -lt 4 ]]; then
    printf "%bYour Bash version is lower than 4, please update.%b\n" "$bred" "$reset"
    if [[ $IS_MAC == "True" ]]; then
        printf "%bFor macOS, run 'brew install bash' and rerun the installer in a new terminal.%b\n" "$yellow" "$reset"
    fi
    exit 1
fi

# Load pinned versions from manifest file
VERSIONS_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config/tool_versions.txt"
declare -A TOOL_VERSIONS=()
if [[ -f "$VERSIONS_FILE" ]]; then
    local_section=""
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ -z "$line" || "$line" == \#* ]] && continue
        # Track section headers
        if [[ "$line" == "[repos]" ]]; then
            local_section="repos"
            continue
        fi
        if [[ "$line" == *=* ]]; then
            local_key="${line%%=*}"
            local_val="${line#*=}"
            # Prefix repo keys to avoid collisions with go tool names
            if [[ "$local_section" == "repos" ]]; then
                TOOL_VERSIONS["repo:${local_key}"]="$local_val"
            else
                TOOL_VERSIONS["${local_key}"]="$local_val"
            fi
        fi
    done < "$VERSIONS_FILE"
fi

# Helper: get pinned version for a tool (returns "latest" if not found)
get_tool_version() {
    local tool="$1"
    local prefix="${2:-}"  # optional prefix like "repo:"
    local ver="${TOOL_VERSIONS[${prefix}${tool}]:-latest}"
    echo "$ver"
}

# Declare Go tools: name -> module path (version resolved from config/tool_versions.txt)
declare -A gotools=(
    ["gf"]="github.com/tomnomnom/gf"
    ["brutespray"]="github.com/x90skysn3k/brutespray"
    ["qsreplace"]="github.com/tomnomnom/qsreplace"
    ["ffuf"]="github.com/ffuf/ffuf/v2"
    ["github-subdomains"]="github.com/gwen001/github-subdomains"
    ["gitlab-subdomains"]="github.com/gwen001/gitlab-subdomains"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    ["anew"]="github.com/tomnomnom/anew"
    ["notify"]="github.com/projectdiscovery/notify/cmd/notify"
    ["unfurl"]="github.com/tomnomnom/unfurl"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx"
    ["github-endpoints"]="github.com/gwen001/github-endpoints"
    ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx"
    ["subjs"]="github.com/lc/subjs"
    ["Gxss"]="github.com/KathanP19/Gxss"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana"
    ["crlfuzz"]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz"
    ["dalfox"]="github.com/hahwul/dalfox/v2"
    ["puredns"]="github.com/d3mondev/puredns/v2"
    ["interactsh-client"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client"
    ["analyticsrelationships"]="github.com/Josue87/analyticsrelationships"
    ["gotator"]="github.com/Josue87/gotator"
    ["roboxtractor"]="github.com/Josue87/roboxtractor"
    ["mapcidr"]="github.com/projectdiscovery/mapcidr/cmd/mapcidr"
    ["cdncheck"]="github.com/projectdiscovery/cdncheck/cmd/cdncheck"
    ["asnmap"]="github.com/projectdiscovery/asnmap/cmd/asnmap"
    ["dnstake"]="github.com/pwnesia/dnstake/cmd/dnstake"
    ["tlsx"]="github.com/projectdiscovery/tlsx/cmd/tlsx"
    ["gitdorks_go"]="github.com/damit5/gitdorks_go"
    ["smap"]="github.com/s0md3v/smap/cmd/smap"
    ["dsieve"]="github.com/trickest/dsieve"
    ["inscope"]="github.com/tomnomnom/hacks/inscope"
    ["enumerepo"]="github.com/trickest/enumerepo"
    ["Web-Cache-Vulnerability-Scanner"]="github.com/Hackmanit/Web-Cache-Vulnerability-Scanner"
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    ["hakip2host"]="github.com/hakluke/hakip2host"
    ["mantra"]="github.com/Brosck/mantra"
    ["crt"]="github.com/cemulus/crt"
    ["s3scanner"]="github.com/sa7mon/s3scanner"
    ["nmapurls"]="github.com/sdcampbell/nmapurls"
    ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu"
    ["shortscan"]="github.com/bitquark/shortscan/cmd/shortscan"
    ["hakoriginfinder"]="github.com/hakluke/hakoriginfinder"
    ["sourcemapper"]="github.com/denandz/sourcemapper"
    ["jsluice"]="github.com/BishopFox/jsluice/cmd/jsluice"
    ["urlfinder"]="github.com/projectdiscovery/urlfinder/cmd/urlfinder"
    ["cent"]="github.com/xm1k3/cent"
    ["csprecon"]="github.com/edoardottt/csprecon/cmd/csprecon"
    ["VhostFinder"]="github.com/wdahlenburg/VhostFinder"
    ["misconfig-mapper"]="github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper"
    ["grpcurl"]="github.com/fullstorydev/grpcurl/cmd/grpcurl"
    ["toxicache"]="github.com/xhzeem/toxicache"
    ["favirecon"]="github.com/edoardottt/favirecon/cmd/favirecon"
    ["second-order"]="github.com/mhmdiaa/second-order"
    ["TInjA"]="github.com/Hackmanit/TInjA"
    ["nerva"]="github.com/praetorian-inc/nerva/cmd/nerva"
    ["brutus"]="github.com/praetorian-inc/brutus/cmd/brutus"
    ["julius"]="github.com/praetorian-inc/julius/cmd/julius"
    ["titus"]="github.com/praetorian-inc/titus/cmd/titus"
)

# Declare uv tool-managed Python tools and their GitHub paths
declare -A pipxtools=(
    ["dnsvalidator"]="vortexau/dnsvalidator"
    ["interlace"]="codingo/Interlace"
    ["wafw00f"]="EnableSecurity/wafw00f"
    ["commix"]="commixproject/commix"
    ["waymore"]="xnl-h4ck3r/waymore"
    ["urless"]="xnl-h4ck3r/urless"
    ["ghauri"]="r0oth3x49/ghauri"
    ["xnLinkFinder"]="xnl-h4ck3r/xnLinkFinder"
    ["xnldorker"]="xnl-h4ck3r/xnldorker"
    ["porch-pirate"]="MandConsultingGroup/porch-pirate"
    ["p1radup"]="iambouali/p1radup"
    ["subwiz"]="hadriansecurity/subwiz"
    ["arjun"]="s0md3v/Arjun"
    ["gqlspection"]="doyensec/GQLSpection"
    ["postleaksNg"]="six2dez/postleaksNG"
    ["cewler"]="roys/cewler"
)

# Declare repositories and their paths
declare -A repos=(
    ["dorks_hunter"]="six2dez/dorks_hunter"
    ["gf"]="tomnomnom/gf"
    ["Gf-Patterns"]="1ndianl33t/Gf-Patterns"
    ["sus_params"]="g0ldencybersec/sus_params"
    ["CMSeeK"]="Tuhinshubhra/CMSeeK"
    ["massdns"]="blechschmidt/massdns"
    ["testssl.sh"]="drwetter/testssl.sh"
    ["JSA"]="w9w/JSA"
    ["cloud_enum"]="initstring/cloud_enum"
    ["ultimate-nmap-parser"]="shifty0g/ultimate-nmap-parser"
    ["gitdorks_go"]="damit5/gitdorks_go"
    ["Web-Cache-Vulnerability-Scanner"]="Hackmanit/Web-Cache-Vulnerability-Scanner"
    ["regulator"]="cramppet/regulator"
    ["gitleaks"]="gitleaks/gitleaks"
    ["ghleaks"]="dinosn/ghleaks"
    ["trufflehog"]="trufflesecurity/trufflehog"
    ["nomore403"]="devploit/nomore403"
    ["SwaggerSpy"]="UndeadSec/SwaggerSpy"
    ["LeakSearch"]="JoelGMSec/LeakSearch"
    ["ffufPostprocessing"]="Damian89/ffufPostprocessing"
    ["misconfig-mapper"]="intigriti/misconfig-mapper"
    ["Spoofy"]="MattKeeley/Spoofy"
    ["msftrecon"]="Arcanum-Sec/msftrecon"
    ["Scopify"]="Arcanum-Sec/Scopify"
    ["metagoofil"]="opsdisk/metagoofil"
    ["EmailHarvester"]="maldevel/EmailHarvester"
    ["reconftw_ai"]="six2dez/reconftw_ai"
    ["gato"]="praetorian-inc/gato"
    ["SSTImap"]="vladko312/SSTImap"
)

# Function to display the banner
function banner() {
    printf "\n"
    cat <<EOF

  ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █   █████▒▄▄▄█████▓ █     █░
 ▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▓██   ▒ ▓  ██▒ ▓▒▓█░ █ ░█░
 ▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒▒████ ░ ▒ ▓██░ ▒░▒█░ █ ░█
 ▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒░▓█▒  ░ ░ ▓██▓ ░ ░█░ █ ░█
 ░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░░▒█░      ▒██▒ ░ ░░██▒██▓
 ░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒  ▒ ░      ▒ ░░   ░ ▓░▒ ▒
   ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░ ░          ░      ▒ ░ ░
   ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░  ░ ░      ░        ░   ░
    ░        ░  ░░ ░          ░ ░           ░                      ░

 ${reconftw_version}                                         by @six2dez

EOF
}

# Function to install Go tools
function install_tools() {
    header "Installing Golang tools (${#gotools[@]})"

    local go_step=0
    local failed_tools=()
    local total_go=${#gotools[@]}
    local go_ok=0 go_skip=0 go_fail=0
    for gotool in "${!gotools[@]}"; do
        ((++go_step))
        # Build go install command with pinned version from manifest
        local _go_ver
        _go_ver=$(get_tool_version "$gotool")
        local _go_cmd="go install -v ${gotools[$gotool]}@${_go_ver}"
        # Always run go install so already-present binaries also get updated.
        if q bash -lc "$_go_cmd"; then
            ((++go_ok))
            msg_ok "[$go_step/$total_go] ${gotool} installed"
        else
            # If the binary is already present, the upgrade failed but the tool still works.
            # Treat this as a warning rather than a hard failure.
            if command -v "$gotool" >/dev/null 2>&1; then
                ((++go_skip))
                msg_warn "[$go_step/$total_go] ${gotool} upgrade failed (existing binary kept)"
            else
                failed_tools+=("$gotool")
                ((++go_fail))
                double_check=true
                msg_err "[$go_step/$total_go] ${gotool} failed"
            fi
        fi
    done

    header "Installing uv tools (${#pipxtools[@]})"

    local pipx_step=0
    local failed_pipx_tools=()
    local total_px=${#pipxtools[@]}
    local px_ok=0 px_skip=0 px_fail=0

    for pipxtool in "${!pipxtools[@]}"; do
        ((++pipx_step))

        # Always use git+https URL for both install and upgrade to avoid PyPI lookups
        # which fail for tools not on PyPI. Pin to version from manifest.
        local _px_ver
        _px_ver=$(get_tool_version "$pipxtool")
        local tool_url="git+https://github.com/${pipxtools[$pipxtool]}"
        if [[ "$_px_ver" != "latest" && "$_px_ver" != "HEAD" ]]; then
            tool_url="${tool_url}@${_px_ver}"
        fi
        
        # Prepare arguments array
        local tool_args=()

        # Special case for postleaksNg to fix jellyfish dependency issue
        if [[ "$pipxtool" == "postleaksNg" ]]; then
             tool_args+=("--with" "jellyfish>=1.1.3")
        fi

        # Always force install/reinstall from the git URL
        # This handles both initial install and upgrades correctly
        if q uv tool install "${tool_args[@]}" "$tool_url" --force; then
             ((++px_ok))
             msg_ok "[$pipx_step/$total_px] ${pipxtool} ready"
        else
             failed_pipx_tools+=("$pipxtool")
             ((++px_fail))
             double_check=true
             msg_err "[$pipx_step/$total_px] ${pipxtool} failed"
        fi
    done

    header "Installing repositories (${#repos[@]})"

    local repos_step=0
    local failed_repos=()
    local total_repo=${#repos[@]}
    local repo_ok=0 repo_skip=0 repo_fail=0

    install_repo_requirements() {
        if [[ -s "requirements.txt" ]]; then
            if [[ ! -d "venv" ]]; then
                uv venv venv &>/dev/null
            fi
            if ! uv pip install --upgrade -r requirements.txt --python venv/bin/python3 &>/dev/null; then
                return 1
            fi
            if [[ $1 == "dorks_hunter" ]]; then
                uv pip install --upgrade xnldorker --python venv/bin/python3 &>/dev/null || true
            fi
        fi
        return 0
    }

    for repo in "${!repos[@]}"; do
        ((++repos_step))
        if [[ $upgrade_tools == "false" ]]; then
            if [[ -d "${dir}/${repo}" ]]; then
                # Keep Python deps updated even when repository sync is skipped.
                if ! ( cd "${dir}/${repo}" && install_repo_requirements "$repo" ); then
                    msg_err "[$repos_step/$total_repo] $repo: pip requirements failed"
                    failed_repos+=("$repo")
                    ((++repo_fail))
                    double_check=true
                fi
                ((++repo_skip))
                msg_warn "[$repos_step/$total_repo] $repo already present at ${dir}/${repo}"
                continue
            fi
        fi
        # Clone the repository (check for .git to detect incomplete clones)
        if [[ ! -d "${dir}/${repo}/.git" ]]; then
            msg_run "[$repos_step/${#repos[@]}] $repo (clone)"
            retry 3 3 q_to 180 git clone --filter="blob:none" "https://github.com/${repos[$repo]}" "${dir}/${repo}"
            exit_status=$?
            if [[ $exit_status -ne 0 ]]; then
                msg_err "[$repos_step/$total_repo] $repo clone failed"
                failed_repos+=("$repo")
                ((++repo_fail))
                double_check=true
                continue
            fi
            ((++repo_ok))
        fi

        # Navigate to the repository directory
        cd "${dir}/${repo}" || {
            msg_err "[$repos_step/$total_repo] $repo: cannot enter ${dir}/${repo}"
            failed_repos+=("$repo")
            ((++repo_fail))
            double_check=true
            continue
        }

        # Pull the latest changes
        msg_run "[$repos_step/${#repos[@]}] $repo (pull)"
        retry 3 3 q_to 60 git pull
        exit_status=$?
        if [[ $exit_status -ne 0 ]]; then
            msg_err "[$repos_step/$total_repo] $repo pull failed"
            failed_repos+=("$repo")
            ((++repo_fail))
            double_check=true
            continue
        fi

        # Checkout pinned version from manifest if available
        local _repo_ver
        _repo_ver=$(get_tool_version "$repo" "repo:")
        if [[ "$_repo_ver" != "latest" && "$_repo_ver" != "HEAD" ]]; then
            git fetch --tags &>/dev/null || true
            if ! git checkout "$_repo_ver" &>/dev/null; then
                msg_warn "[$repos_step/$total_repo] $repo: could not checkout $_repo_ver, staying on HEAD"
            fi
        fi

        # Install requirements inside a virtual environment
        if ! install_repo_requirements "$repo"; then
            msg_err "[$repos_step/$total_repo] $repo: pip requirements failed"
            failed_repos+=("$repo")
            ((++repo_fail))
            double_check=true
        fi

        # Special handling for certain repositories (verify build exit codes)
        case "$repo" in
            "massdns")
                if ! make &>/dev/null; then
                    msg_warn "[$repos_step/$total_repo] $repo: make failed"
                else
                    strip -s bin/massdns 2>/dev/null || true
                    $SUDO cp bin/massdns /usr/local/bin/ &>/dev/null
                fi
                ;;
            "gitleaks")
                if ! make build &>/dev/null; then
                    msg_warn "[$repos_step/$total_repo] $repo: make build failed"
                else
                    $SUDO cp ./gitleaks /usr/local/bin/ &>/dev/null
                fi
                ;;
            "ghleaks")
                if ! go build -o ghleaks . &>/dev/null; then
                    msg_warn "[$repos_step/$total_repo] $repo: go build failed"
                else
                    chmod +x ./ghleaks
                fi
                ;;
            "nomore403")
                go get &>/dev/null || true
                if ! go build &>/dev/null; then
                    msg_warn "[$repos_step/$total_repo] $repo: go build failed"
                else
                    chmod +x ./nomore403
                fi
                ;;
            "ffufPostprocessing")
                git reset --hard origin/master &>/dev/null
                git pull &>/dev/null
                if ! go build -o ffufPostprocessing main.go &>/dev/null; then
                    msg_warn "[$repos_step/$total_repo] $repo: go build failed"
                else
                    chmod +x ./ffufPostprocessing
                fi
                ;;
            "trufflehog")
                go install &>/dev/null || msg_warn "[$repos_step/$total_repo] $repo: go install failed"
                ;;
            "gato")
                if [[ ! -d "venv" ]]; then
                    uv venv venv &>/dev/null || true
                fi
                uv pip install --upgrade -e . --python venv/bin/python3 &>/dev/null || true
                ;;
            "SSTImap")
                if [[ ! -d "venv" ]]; then
                    uv venv venv &>/dev/null || true
                fi
                uv pip install --upgrade -r requirements.txt --python venv/bin/python3 &>/dev/null || true
                ;;
        esac

        # Copy gf patterns if applicable
        if [[ $repo == "gf" ]]; then
            cp -r examples "${HOME}/.gf" &>/dev/null || true
        elif [[ $repo == "Gf-Patterns" ]]; then
            cp ./*.json "${HOME}/.gf" &>/dev/null || true
        elif [[ $repo == "sus_params" ]]; then
            for f in ./gf-patterns/*.json; do
                base=$(basename "$f")
                dest="${HOME}/.gf/$base"
                cat "$f" | anew -q "$dest" >/dev/null || true
            done
        fi

        # Return to the main directory
        cd "$dir" || {
            msg_err "Failed to navigate back to directory '$dir'"
            exit 1
        }

        msg_ok "[$repos_step/$total_repo] $repo ready"
    done

    # Initialize tool configs on first run
    q command -v notify >/dev/null 2>&1 && q notify || true
    q command -v subfinder >/dev/null 2>&1 && q subfinder || true
    mkdir -p ${NUCLEI_TEMPLATES_PATH} &>/dev/null
    #cent init -f &>/dev/null
    #cent -p ${NUCLEI_TEMPLATES_PATH} &>/dev/null

    # Installation summary
    printf "\n%b--- Tool Installation Summary ---%b\n" "$bblue" "$reset"
    printf "  Go tools:  %b%d OK%b, %d skipped, %b%d failed%b (of %d)\n" \
        "$bgreen" "$go_ok" "$reset" "$go_skip" \
        "$([[ $go_fail -gt 0 ]] && echo "$red" || echo "$bgreen")" "$go_fail" "$reset" "$total_go"
    printf "  uv tools:  %b%d OK%b, %b%d failed%b (of %d)\n" \
        "$bgreen" "$px_ok" "$reset" \
        "$([[ $px_fail -gt 0 ]] && echo "$red" || echo "$bgreen")" "$px_fail" "$reset" "$total_px"
    printf "  Repos:     %b%d OK%b, %d skipped, %b%d failed%b (of %d)\n" \
        "$bgreen" "$repo_ok" "$reset" "$repo_skip" \
        "$([[ $repo_fail -gt 0 ]] && echo "$red" || echo "$bgreen")" "$repo_fail" "$reset" "$total_repo"

    local _total_fail=$(( go_fail + px_fail + repo_fail ))
    if [[ $_total_fail -gt 0 ]]; then
        printf "\n%bFailed items:%b\n" "$red" "$reset"
        [[ ${#failed_tools[@]} -gt 0 ]] && printf "  Go:    %s\n" "${failed_tools[*]}"
        [[ ${#failed_pipx_tools[@]} -gt 0 ]] && printf "  uv:    %s\n" "${failed_pipx_tools[*]}"
        [[ ${#failed_repos[@]} -gt 0 ]] && printf "  Repos: %s\n" "${failed_repos[*]}"
        printf "\n%bRe-run install.sh to retry failed items.%b\n" "$yellow" "$reset"
    fi
}

# Function to reset git proxy settings
function reset_git_proxies() {
    git config --global --unset http.proxy || true
    git config --global --unset https.proxy || true
}

# Function to check for updates
function check_updates() {
    printf "%bRunning: Looking for new reconFTW version%b\n" "$bblue" "$reset"

    if { [[ -n $TIMEOUT_CMD ]] && $TIMEOUT_CMD 10 git fetch; } || git fetch; then
        local BRANCH
        BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "HEAD")
        HEADHASH=$(git rev-parse HEAD 2>/dev/null || true)
        # Skip auto-update if no upstream (detached HEAD or no tracking branch)
        if ! git rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
            printf "%bNo upstream configured (detached HEAD). Skipping auto-update.%b\n" "$yellow" "$reset"
            return 0
        fi
        UPSTREAMHASH=$(git rev-parse "@{u}")

        if [[ $HEADHASH != "$UPSTREAMHASH" ]]; then
            local cfg_backup="" cfg_backup_ts=""
            if git status --porcelain | grep -q .; then
                if [[ $FORCE_UPDATE == "true" ]]; then
                    printf "%bLocal changes detected; forcing update.%b\n" "$yellow" "$reset"
                else
                    printf "%bLocal changes detected. Skipping auto-update. Re-run with --force-update to override.%b\n" "$yellow" "$reset"
                    return 0
                fi
            fi
            printf "%bA new version is available. Updating...%b\n" "$yellow" "$reset"
            if git status --porcelain | grep -q 'reconftw.cfg$'; then
                cfg_backup_ts=$(date +%Y%m%d_%H%M%S)
                cfg_backup="reconftw.cfg.bak.${cfg_backup_ts}"
                cp reconftw.cfg "$cfg_backup"
                printf "%breconftw.cfg has been backed up to %s%b\n" "$yellow" "$cfg_backup" "$reset"
            fi
            git stash --include-untracked &>/dev/null || true
            run_to 60 git pull &>/dev/null
            git stash pop &>/dev/null || true
            printf "%bUpdated! Running the new installer version...%b\n" "$bgreen" "$reset"

            # Show config diff against new default
            if [[ -n $cfg_backup && -f reconftw.cfg ]]; then
                mkdir -p .tmp
                cfg_diff_file=".tmp/reconftw_cfg_diff_${cfg_backup_ts}.patch"
                if diff -u "$cfg_backup" reconftw.cfg >"$cfg_diff_file"; then
                    printf "%bConfig unchanged between versions (diff: %s).%b\n" "$yellow" "$cfg_diff_file" "$reset"
                else
                    printf "%bConfig differences saved to %s (old -> new).%b\n" "$yellow" "$cfg_diff_file" "$reset"
                fi
            fi
        else
            printf "%breconFTW is already up to date!%b\n" "$bgreen" "$reset"
            # If config is locally modified, still provide a diff against current default
            if ! git diff --quiet -- reconftw.cfg; then
                local cfg_diff_ts cfg_diff_file
                cfg_diff_ts=$(date +%Y%m%d_%H%M%S)
                mkdir -p .tmp
                cfg_diff_file=".tmp/reconftw_cfg_diff_${cfg_diff_ts}.patch"
                if git diff HEAD --unified -- reconftw.cfg >"$cfg_diff_file"; then
                    printf "%bLocal reconftw.cfg differs from default; diff saved to %s.%b\n" "$yellow" "$cfg_diff_file" "$reset"
                fi
            fi
        fi
    else
        printf "\n%b[!] Unable to check for updates.%b\n" "$bred" "$reset"
    fi
}

# Function to install Golang
function install_golang_version() {
    local version="go1.23.6"
    local latest_version
    latest_version=$(curl -s https://go.dev/VERSION?m=text | head -1 || echo "go1.23.6")
    if [[ $latest_version == g* ]]; then
        version="$latest_version"
    fi

    printf "%bRunning: Installing/Updating Golang(%s) %b\n" "$bblue" "$version" "$reset"

    if [[ $install_golang == "true" ]]; then
        local current_version=""
        if command -v go &>/dev/null; then
            current_version="$(go version | awk '{print $3}')"
        fi

        if [[ -n $current_version && $version == "$current_version" ]]; then
            printf "%bGolang is already installed and up to date.%b\n" "$bgreen" "$reset"
        else
            local archive_suffix=""

            case "$ARCH" in
                arm64 | aarch64)
                    if [[ $IS_MAC == "True" ]]; then
                        archive_suffix="darwin-arm64"
                    else
                        archive_suffix="linux-arm64"
                    fi
                    ;;
                armv6l | armv7l)
                    archive_suffix="linux-armv6l"
                    ;;
                amd64 | x86_64)
                    if [[ $IS_MAC == "True" ]]; then
                        archive_suffix="darwin-amd64"
                    else
                        archive_suffix="linux-amd64"
                    fi
                    ;;
                *)
                    msg_err "[!] Unsupported architecture. Please install go manually."
                    return 1
                    ;;
            esac

            local archive_url="https://dl.google.com/go/${version}.${archive_suffix}.tar.gz"
            local archive_path="/tmp/${version}.${archive_suffix}.tar.gz"

            if ! wget "$archive_url" -O "$archive_path" &>/dev/null; then
                msg_err "[!] Failed to download Golang archive from ${archive_url}"
                return 1
            fi

            # Verify SHA256 checksum from go.dev
            local expected_sha256
            expected_sha256=$(curl -sL "${archive_url}.sha256" 2>/dev/null || true)
            if [[ -n $expected_sha256 ]]; then
                local actual_sha256
                if command -v sha256sum &>/dev/null; then
                    actual_sha256=$(sha256sum "$archive_path" | awk '{print $1}')
                elif command -v shasum &>/dev/null; then
                    actual_sha256=$(shasum -a 256 "$archive_path" | awk '{print $1}')
                fi
                if [[ -n ${actual_sha256:-} && $actual_sha256 != "$expected_sha256" ]]; then
                    msg_err "[!] SHA256 checksum mismatch for Go archive (expected: ${expected_sha256}, got: ${actual_sha256})"
                    rm -f "$archive_path"
                    return 1
                fi
            else
                msg_warn "[!] Could not fetch SHA256 checksum for Go archive; skipping verification"
            fi

            local tmp_unpack
            tmp_unpack=$(mktemp -d 2>/dev/null || mktemp -d -t goinstall)
            trap 'rm -rf "$tmp_unpack" "$archive_path"' RETURN
            if ! tar -C "$tmp_unpack" -xzf "$archive_path" &>/dev/null; then
                msg_err "[!] Failed to extract ${archive_path}"
                return 1
            fi

            if [[ ! -d "${tmp_unpack}/go" ]]; then
                msg_err "[!] Extracted archive missing 'go' directory"
                return 1
            fi

            local go_backup=""
            if [[ -d /usr/local/go ]]; then
                go_backup="/usr/local/go.reconftw.$(date +%s)"
                if ! $SUDO mv /usr/local/go "$go_backup" &>/dev/null; then
                    msg_warn "[!] Unable to backup existing /usr/local/go; attempting in-place overwrite."
                    go_backup=""
                    if ! ($SUDO rm -rf /usr/local/go &>/dev/null); then
                        msg_warn "[!] Failed to remove existing /usr/local/go; installation may overwrite partially."
                    fi
                fi
            fi
            if ! $SUDO mv "${tmp_unpack}/go" /usr/local/go; then
                msg_err "[!] Failed to move Golang into /usr/local/go"
                if [[ -n $go_backup && -d $go_backup ]]; then
                    $SUDO mv "$go_backup" /usr/local/go &>/dev/null || msg_warn "[!] Unable to restore previous Golang installation from backup."
                fi
                return 1
            fi
            if [[ -n $go_backup ]]; then
                $SUDO rm -rf "$go_backup" &>/dev/null
            fi

            # tmp_unpack and archive_path cleaned up by RETURN trap
            $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/ 2>/dev/null
        fi

        export GOROOT=/usr/local/go
        export GOPATH="${HOME}/go"
        export PATH="$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH"

        if [[ -n ${profile_shell:-} ]]; then
            local profile_path="${HOME}/${profile_shell}"
            local marker="# Golang environment variables (reconFTW)"

            # Remove ALL previous golang env blocks (old-style and reconFTW-style)
            # to prevent duplicates from accumulating across runs
            if [[ -f "$profile_path" ]] && grep -q '^# Golang environment variables' "$profile_path" 2>/dev/null; then
                local tmp_profile
                tmp_profile=$(mktemp)
                awk '
                    /^# Golang environment variables/ { skip = 3; next }
                    skip > 0 && /^export (GOROOT|GOPATH|PATH)=/ { skip--; next }
                    skip > 0 { skip = 0 }
                    { print }
                ' "$profile_path" > "$tmp_profile" && mv "$tmp_profile" "$profile_path"
            fi

            # Append single canonical block
            {
                printf '\n%s\n' "$marker"
                printf 'export GOROOT=/usr/local/go\n'
                printf 'export GOPATH=$HOME/go\n'
                printf 'export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH\n'
            } >>"$profile_path"
        fi
    else
        msg_warn "Golang will not be configured according to the user's preferences (install_golang=false in reconftw.cfg)."
    fi

    if ! command -v go &>/dev/null; then
        msg_err "[!] Go binary not found in PATH. Please install Go or enable install_golang in reconftw.cfg."
        return 1
    fi

    local detected_gopath detected_goroot
    detected_gopath="${GOPATH:-$(go env GOPATH 2>/dev/null || true)}"
    detected_goroot="${GOROOT:-$(go env GOROOT 2>/dev/null || true)}"

    if [[ -z $detected_gopath || -z $detected_goroot ]]; then
        msg_warn "Go environment variables not fully configured. Ensure GOPATH and GOROOT are set or available via 'go env'."
    fi
}

# Function to install system packages based on OS
function install_system_packages() {

    if [[ -f /etc/debian_version ]]; then
        install_apt
    elif [[ -f /etc/redhat-release ]]; then
        install_yum
    elif [[ -f /etc/arch-release ]]; then
        install_pacman
    elif [[ $IS_MAC == "True" ]]; then
        install_brew
    elif [[ -f /etc/os-release ]]; then
        install_yum # Assuming RedHat-based
    else
        printf "%b[!] Unsupported OS. Please install dependencies manually.%b\n" "$bred" "$reset"
        exit 1
    fi
}

# Function to install required packages for Debian-based systems
function install_apt() {
    $SUDO apt-get update -y &>/dev/null
    $SUDO apt-get install -y python3 build-essential gcc cmake ruby whois git curl libpcap-dev wget zip python3-dev pv dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq apt-transport-https lynx medusa xvfb libxml2-utils procps bsdmainutils libdata-hexdump-perl libimage-exiftool-perl &>/dev/null
    # Move chromium browser dependencies (required by `nuclei -headless -id screenshot`) into a separate apt install command, and add a fallback for Ubuntu 24.04 (where `libasound2` is renamed to `libasound2t64`)
    $SUDO apt-get install -y libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon-x11-0 libxcomposite-dev libxdamage1 libxrandr2 libgbm-dev libpangocairo-1.0-0 libasound2 &>/dev/null \
        || $SUDO apt-get install -y libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon-x11-0 libxcomposite-dev libxdamage1 libxrandr2 libgbm-dev libpangocairo-1.0-0 libasound2t64 &>/dev/null
    install_rust_uv
}

# Function to install required packages for macOS
function install_brew() {
    if command -v brew &>/dev/null; then
        printf "%bbrew is already installed.%b\n" "$bgreen" "$reset"
    else
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew update &>/dev/null
    brew install --formula bash coreutils gnu-getopt gnu-sed python uv massdns jq gcc cmake ruby git curl wget zip pv bind whois exiftool nmap lynx medusa &>/dev/null
    brew install rustup &>/dev/null
    rustup-init -y &>/dev/null
    cargo install smugglex &>/dev/null
    uv tool update-shell &>/dev/null || true
    # Install shodan CLI via uv
    uv tool install shodan --force &>/dev/null || uv tool upgrade shodan &>/dev/null || true
}

# Function to install required packages for RedHat-based systems
function install_yum() {
    $SUDO yum groupinstall "Development Tools" -y &>/dev/null
    # Base install first (python3 may be 3.6 on older EL)
    $SUDO yum install -y epel-release &>/dev/null || true
    $SUDO yum install -y python3 gcc cmake ruby git curl libpcap whois perl-Image-ExifTool wget zip pv bind-utils openssl-devel libffi-devel libxml2-devel libxslt-devel zlib-devel nmap jq lynx medusa xorg-x11-server-xvfb &>/dev/null

    # Ensure Python >= 3.7 on yum-based systems
    if ! python3 - <<-'PYCHK' &>/dev/null; then
		import sys; raise SystemExit(0 if sys.version_info >= (3,7) else 1)
	PYCHK

        # Try DNF/YUM module streams (EL8+/EL9+) for newer Python
        if command -v dnf &>/dev/null || $SUDO yum -y module list python38 &>/dev/null; then
            # Prefer 3.9, then 3.8
            if command -v dnf &>/dev/null; then
                $SUDO dnf -y module install python39 &>/dev/null || $SUDO dnf -y module install python38 &>/dev/null || true
            else
                $SUDO yum -y module install python39 &>/dev/null || $SUDO yum -y module install python38 &>/dev/null || true
            fi
        fi

        # Amazon Linux 2 path
        if command -v amazon-linux-extras &>/dev/null; then
            $SUDO amazon-linux-extras install -y python3.8 &>/dev/null || true
        fi

        # EL7 fallback via IUS (best-effort)
        REL_VER=$( (cat /etc/redhat-release 2>/dev/null || cat /etc/centos-release 2>/dev/null) || true)
        if [[ $REL_VER == *" 7."* ]]; then
            $SUDO yum install -y https://repo.ius.io/ius-release-el7.rpm &>/dev/null || true
            $SUDO yum install -y python37u python37u-pip python37u-devel &>/dev/null || true
        fi

        # If python3.9/3.8/3.7 binaries exist, prefer the newest by creating a higher-priority symlink
        if ! python3 - <<-'PYCHK' &>/dev/null; then
			import sys; raise SystemExit(0 if sys.version_info >= (3,7) else 1)
		PYCHK

            NEW_PY=""
            for cand in /usr/bin/python3.11 /usr/bin/python3.10 /usr/bin/python3.9 /usr/bin/python3.8 /usr/bin/python3.7; do
                [[ -x $cand ]] && NEW_PY="$cand" && break
            done
            if [[ -n $NEW_PY ]]; then
                $SUDO ln -sf "$NEW_PY" /usr/local/bin/python3 2>/dev/null || true
                export PATH="/usr/local/bin:$PATH"
            fi
        fi
    fi

    install_rust_uv
}

# Function to install required packages for Arch-based systems
function install_pacman() {
    $SUDO pacman -Sy --noconfirm python base-devel gcc cmake ruby git curl libpcap whois perl-image-exiftool wget zip pv bind openssl libffi libxml2 libxslt zlib nmap jq lynx medusa xorg-server-xvfb &>/dev/null
    install_rust_uv
}

# Setup reconftw venv for python-only helpers (e.g., getjswords)
function setup_reconftw_venv() {
    local root_dir="${SCRIPTPATH:-$(pwd)}"
    local venv_dir="${root_dir}/.venv"
    if ! command -v python3 >/dev/null 2>&1; then
        msg_warn "[!] python3 not found; skipping reconftw venv setup"
        return 0
    fi
    if [[ ! -d "$venv_dir" ]]; then
        uv venv "$venv_dir" &>/dev/null || {
            msg_warn "[!] Failed to create venv at ${venv_dir}"
            return 0
        }
    fi
    uv pip install jsbeautifier requests --python "${venv_dir}/bin/python3" &>/dev/null || {
        msg_warn "[!] Failed to install getjswords deps in ${venv_dir}"
    }
}

# Function to perform initial setup
function initial_setup() {
    banner
    reset_git_proxies

    if [[ $TOOLS_ONLY == "true" ]]; then
        header "Tools-only mode"
        with_spinner "Installing/validating Golang" install_golang_version
        mkdir -p ${HOME}/.gf
        mkdir -p "$tools"
        mkdir -p ${HOME}/.config/notify/
        mkdir -p ${HOME}/.config/nuclei/
        touch "${dir}/.github_tokens"
        touch "${dir}/.gitlab_tokens"

        q uv tool update-shell
        export PATH="${HOME}/.local/bin:${PATH}"

        install_tools
        setup_reconftw_venv
        return
    fi

    header "Install/Update"
    with_spinner "Checking for updates" check_updates
    with_spinner "Installing system packages" install_system_packages
    check_network
    with_spinner "Installing/validating Golang" install_golang_version
    mkdir -p ${HOME}/.gf
    mkdir -p "$tools"
    mkdir -p ${HOME}/.config/notify/
    mkdir -p ${HOME}/.config/nuclei/
    touch "${dir}/.github_tokens"
    touch "${dir}/.gitlab_tokens"

    q uv tool update-shell
    # Ensure $HOME/.local/bin is available now even if profile isn't sourced
    export PATH="${HOME}/.local/bin:${PATH}"
    # Do not source user shell profiles here to avoid errors like 'PS1: unbound variable'
    # in non-interactive shells with 'set -u'. PATH for this process is already updated.

    install_tools
    setup_reconftw_venv

    # Repositories with special configurations
    header "Configuring special repositories"

    # Nuclei Templates (opt-out with MANAGE_NUCLEI_TEMPLATES=false)
    MANAGE_NUCLEI_TEMPLATES=${MANAGE_NUCLEI_TEMPLATES:-true}
    if [[ $MANAGE_NUCLEI_TEMPLATES == "true" ]]; then
        ensure_git_dir "${NUCLEI_TEMPLATES_PATH}"
        if [[ ! -d ${NUCLEI_TEMPLATES_PATH} ]]; then
            q mkdir -p "${NUCLEI_TEMPLATES_PATH}"
            with_spinner "Cloning nuclei-templates" retry 3 3 q_to 300 git clone https://github.com/projectdiscovery/nuclei-templates "${NUCLEI_TEMPLATES_PATH}" || true
        else
            with_spinner "Updating nuclei-templates" retry 3 3 q_to 120 git -C "${NUCLEI_TEMPLATES_PATH}" pull || true
        fi
        ensure_git_dir "${NUCLEI_TEMPLATES_PATH}/extra_templates"
    fi
    with_spinner "Nuclei template update" nuclei -update-templates -update-template-dir "${NUCLEI_TEMPLATES_PATH}" >/dev/null 2>&1 || true

    # sqlmap
    ensure_git_dir "${dir}/sqlmap"
    if [[ ! -d "${dir}/sqlmap" ]]; then
        #printf "${yellow}Cloning sqlmap...\n"
        if ! retry 3 3 q_to 120 git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "${dir}/sqlmap"; then true; fi
    else
        #printf "${yellow}Updating sqlmap...\n"
        if ! retry 3 3 q_to 60 git -C "${dir}/sqlmap" pull; then true; fi
    fi

    # massdns
    ensure_git_dir "${dir}/massdns"
    if [[ ! -d "${dir}/massdns" ]]; then
        #printf "${yellow}Cloning and compiling massdns...\n"
        if ! retry 3 3 q_to 120 git clone https://github.com/blechschmidt/massdns.git "${dir}/massdns"; then true; fi
        q make -C "${dir}/massdns"
        strip -s "${dir}/massdns/bin/massdns" 2>/dev/null
        $SUDO cp "${dir}/massdns/bin/massdns" /usr/local/bin/ 2>/dev/null
    else
        #printf "${yellow}Updating massdns...\n"
        if ! retry 3 3 q_to 60 git -C "${dir}/massdns" pull; then true; fi
    fi

    # gf patterns are already handled by install_tools() via repos array
    # (gf, Gf-Patterns, sus_params repos clone/pull and copy patterns)

    header "Downloading required files"

    mkdir -p ${HOME}/.config/notify
    # Download required files with error handling
	    declare -A downloads=(
	        ["notify_provider_config"]="https://gist.githubusercontent.com/six2dez/23a996bca189a11e88251367e6583053/raw ${HOME}/.config/notify/provider-config.yaml"
	        ["getjswords"]="https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py ${tools}/getjswords.py"
	        ["subdomains_huge"]="https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt ${subs_wordlist_big}"
	        ["trusted_resolvers"]="https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw ${resolvers_trusted}"
	        ["resolvers"]="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt ${resolvers}"
	        ["axiom_config"]="https://gist.githubusercontent.com/six2dez/6e2d9f4932fd38d84610eb851014b26e/raw ${tools}/axiom_config.sh"
	    )

    local dl_step=0
    local total_dl=${#downloads[@]}
    for key in "${!downloads[@]}"; do
        ((++dl_step))
        url="${downloads[$key]% *}"
        destination="${downloads[$key]#* }"

        # Skip download if provider-config.yaml already exists
        if [[ $key == "notify_provider_config" && -f $destination ]]; then
            msg_warn "[$dl_step/$total_dl] $key skipped (already exists)"
            continue
        fi

        # Ensure destination directory exists
        mkdir -p "$(dirname "$destination")" 2>/dev/null || true

        if with_spinner "[$dl_step/$total_dl] Fetching $key" retry 3 3 q_to 120 wget -q -O "$destination" "$url"; then
            msg_ok "[$dl_step/$total_dl] $key fetched"
        else
            msg_err "[$dl_step/$total_dl] Failed to download $key from $url"
            continue
        fi
    done

    # (removed) kiterunner routes tarball handling

    # Make axiom_config.sh executable
    chmod +x "${tools}/axiom_config.sh" || {
        printf "%b[!] Failed to make axiom_config.sh executable.%b\n" "$red" "$reset"
    }

    header "Final configuration"

    # Update resolvers if generate_resolvers is true
    if [[ $generate_resolvers == true ]]; then
        if [[ ! -s $resolvers || $(find "$resolvers" -mtime +1 -print) ]]; then
            printf "%bChecking resolvers lists...\nAccurate resolvers are the key to great results.\nThis may take around 10 minutes if it's not updated.%b\n" "$yellow" "$reset"
            rm -f "$resolvers" &>/dev/null
            dnsvalidator -tL https://public-dns.info/nameservers.txt -threads "$DNSVALIDATOR_THREADS" -o "$resolvers" &>/dev/null
            dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads "$DNSVALIDATOR_THREADS" -o tmp_resolvers &>/dev/null

            if [[ -s "tmp_resolvers" ]]; then
                cat tmp_resolvers | anew -q "$resolvers"
                rm -f tmp_resolvers &>/dev/null
            fi

            [[ ! -s $resolvers ]] && wget -q -O "$resolvers" https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
            [[ ! -s $resolvers_trusted ]] && wget -q -O "$resolvers_trusted" https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw/trusted_resolvers.txt
            printf "%bResolvers updated.%b\n" "$yellow" "$reset"
        fi
        generate_resolvers=false
    else
        if [[ -s $resolvers && $(find "$resolvers" -mtime +1 -print) ]]; then
            printf "%bChecking resolvers lists...\nAccurate resolvers are the key to great results.\nDownloading new resolvers.%b\n" "$yellow" "$reset"
            wget -q -O "$resolvers" https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
            wget -q -O "$resolvers_trusted" https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw/trusted_resolvers.txt
            printf "%bResolvers updated.%b\n" "$yellow" "$reset"
        fi
    fi

    # Strip all Go binaries and copy to /usr/local/bin (files only)
    find "${GOPATH}/bin" -type f -perm -u+x -exec strip -s {} \; 2>/dev/null || true
    find "${GOPATH}/bin" -type f -perm -u+x -exec $SUDO cp {} /usr/local/bin/ \; 2>/dev/null || true

    # Final reminders (classic output)
    local final_reminder
    final_reminder="$(
        cat <<EOF
Remember to set your API keys:
- subfinder (${HOME}/.config/subfinder/provider-config.yaml)
- GitHub (${HOME}/Tools/.github_tokens)
- GitLab (${HOME}/Tools/.gitlab_tokens)
- SSRF Server (COLLAB_SERVER in reconftw.cfg or env var)
- Blind XSS Server (XSS_SERVER in reconftw.cfg or env var)
- notify (${HOME}/.config/notify/provider-config.yaml)
- WHOISXML API (WHOISXML_API in reconftw.cfg or env var)
EOF
    )"
    printf "%b%s%b\n" "$yellow" "$final_reminder" "$reset"
    printf "%bFinished!%b\n" "$bgreen" "$reset"
    printf "%b#######################################################################%b\n" "$bgreen" "$reset"
}

# Function to display additional help
function show_additional_help() {
    cat <<USAGE
Usage: $0 [OPTIONS]

Options:
  -h, --help          Show this help and exit
  --tools             Only install/upgrade tools and exit
  --verbose           Show detailed installer output (overrides DEBUG_STD/DEBUG_ERROR)
  --log <file>        Tee all installer output to <file>
  --force-update      Force git reset/pull even with local changes
  --dry-run           Print actions without executing changes

Without options, the script checks for updates and installs all dependencies.
USAGE
    exit 0
}

# Function to handle installation arguments
function handle_install_arguments() {
    printf "\n%breconFTW installer/updater script%b\n" "$bgreen" "$reset"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h | --help)
                show_additional_help
                ;;
            --tools)
                TOOLS_ONLY=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                DEBUG_STD=""
                DEBUG_ERROR=""
                shift
                ;;
            --log)
                LOGFILE="$2"
                shift 2 || true
                ;;
            --force-update)
                FORCE_UPDATE=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            *)
                printf "%bError: Invalid argument '%s'%b\n" "$bred" "$1" "$reset"
                echo "Use -h or --help for usage information."
                exit 1
                ;;
        esac
    done

    printf "%bThis may take some time. Grab a coffee!%b\n" "$yellow" "$reset"

    # Determine if the script is run as root
    if [[ "$(id -u)" -eq 0 ]]; then
        SUDO=""
    else
        if ! sudo -n true 2>/dev/null; then
            printf "%bIt is strongly recommended to add your user to sudoers.%b\n" "$bred" "$reset"
            printf "%bThis will avoid prompts for sudo password during installation and scans.%b\n" "$bred" "$reset"
            printf "%bRun the following command to add your user to sudoers:%b\n" "$bred" "$reset"
            printf "%becho \"%s  ALL=(ALL:ALL) NOPASSWD: ALL\" | sudo tee /etc/sudoers.d/reconFTW%b\n\n" "$bred" "$USER" "$reset"
        fi
        SUDO="sudo"
    fi
}

# Invoke main functions
handle_install_arguments "$@"
initial_setup
