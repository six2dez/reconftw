#!/bin/bash

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

source "$CONFIG_FILE"

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

# Non-fatal error trap: log and continue
trap 'rc=$?; ts=$(date +"%Y-%m-%d %H:%M:%S"); cmd=${BASH_COMMAND}; loc_ln=${BASH_LINENO[0]:-0}; msg="[$ts] install.sh ERR($rc) @ line ${loc_ln} :: ${cmd}"; if [[ -n "${LOGFILE:-}" ]]; then echo "$msg" >>"$LOGFILE"; else echo "$msg" >&2; fi' ERR

# -------------------------------
# Minimal UI helpers (classic style)
# -------------------------------

header() { printf "%bRunning: %s%b\n" "$bblue" "$1" "$reset"; }
msg_run() { printf "%b%s%b\n" "$yellow" "$1" "$reset"; }
msg_ok() { printf "%b%s%b\n" "$yellow" "$1" "$reset"; }
msg_warn() { printf "%b%s%b\n" "$yellow" "$1" "$reset"; }
msg_err() { printf "%b%s%b\n" "$red" "$1" "$reset"; }

# Progress helper (simple spinner output)
progress_update() { :; }
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

# Keep arrays defined for potential later use, but classic UI prints a short summary only
declare -a INST_GO_OK INST_GO_SKIP INST_GO_FAIL
declare -a INST_PX_OK INST_PX_SKIP INST_PX_FAIL
declare -a REPOS_CLONED REPOS_SKIPPED REPOS_FAIL

# Basic network precheck
check_network() {
	printf "%bRunning: Network precheck%b\n" "$bblue" "$reset"
	# Silence successful output; show message only on failure. Use q_to to respect --verbose.
	if ! q_to 5 bash -lc 'getent hosts github.com >/dev/null 2>&1 || dig +short github.com >/dev/null 2>&1 || nslookup github.com >/dev/null 2>&1'; then
		printf "%b[!] DNS resolution for github.com failed. Check your network.%b\n" "$bred" "$reset"
	fi
	if ! q_to 10 curl -I -s https://github.com >/dev/null 2>&1; then
		printf "%b[!] HTTPS connectivity to github.com failed. Installer may fail.%b\n" "$yellow" "$reset"
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

# Declare Go tools and their installation commands
declare -A gotools=(
	["gf"]="go install -v github.com/tomnomnom/gf@latest"
	["brutespray"]="go install -v github.com/x90skysn3k/brutespray@latest"
	["qsreplace"]="go install -v github.com/tomnomnom/qsreplace@latest"
	["ffuf"]="go install -v github.com/ffuf/ffuf/v2@latest"
	["github-subdomains"]="go install -v github.com/gwen001/github-subdomains@latest"
	["gitlab-subdomains"]="go install -v github.com/gwen001/gitlab-subdomains@latest"
	["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
	["anew"]="go install -v github.com/tomnomnom/anew@latest"
	["notify"]="go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
	["unfurl"]="go install -v github.com/tomnomnom/unfurl@v0.3.0"
	["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
	["github-endpoints"]="go install -v github.com/gwen001/github-endpoints@latest"
	["dnsx"]="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
	["subjs"]="go install -v github.com/lc/subjs@latest"
	["Gxss"]="go install -v github.com/KathanP19/Gxss@latest"
	["katana"]="go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
	["crlfuzz"]="go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
	["dalfox"]="go install -v github.com/hahwul/dalfox/v2@latest"
	["puredns"]="go install -v github.com/d3mondev/puredns/v2@latest"
	["interactsh-client"]="go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
	["analyticsrelationships"]="go install -v github.com/Josue87/analyticsrelationships@latest"
	["gotator"]="go install -v github.com/Josue87/gotator@latest"
	["roboxtractor"]="go install -v github.com/Josue87/roboxtractor@latest"
	["mapcidr"]="go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
	["cdncheck"]="go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
	["dnstake"]="go install -v github.com/pwnesia/dnstake/cmd/dnstake@latest"
	["tlsx"]="go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
	["gitdorks_go"]="go install -v github.com/damit5/gitdorks_go@latest"
	["smap"]="go install -v github.com/s0md3v/smap/cmd/smap@latest"
	["dsieve"]="go install -v github.com/trickest/dsieve@master"
	["inscope"]="go install -v github.com/tomnomnom/hacks/inscope@latest"
	["enumerepo"]="go install -v github.com/trickest/enumerepo@latest"
	["Web-Cache-Vulnerability-Scanner"]="go install -v github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest"
	["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
	["hakip2host"]="go install -v github.com/hakluke/hakip2host@latest"
	["mantra"]="go install -v github.com/Brosck/mantra@latest"
	["crt"]="go install -v github.com/cemulus/crt@latest"
	["s3scanner"]="go install -v github.com/sa7mon/s3scanner@latest"
	["nmapurls"]="go install -v github.com/sdcampbell/nmapurls@latest"
	["shortscan"]="go install -v github.com/bitquark/shortscan/cmd/shortscan@latest"
	["sns"]="go install github.com/sw33tLie/sns@latest"
	["ppmap"]="go install -v github.com/kleiton0x00/ppmap@latest"
	["sourcemapper"]="go install -v github.com/denandz/sourcemapper@latest"
	["jsluice"]="go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest"
	["urlfinder"]="go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
	["cent"]="go install -v github.com/xm1k3/cent@latest"
	["csprecon"]="go install github.com/edoardottt/csprecon/cmd/csprecon@latest"
	["VhostFinder"]="go install -v github.com/wdahlenburg/VhostFinder@latest"
	["misconfig-mapper"]="go install github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper@latest"
	["grpcurl"]="go install -v github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
)

# Declare pipx tools and their paths
declare -A pipxtools=(
	["dnsvalidator"]="vortexau/dnsvalidator"
	["interlace"]="codingo/Interlace"
	["wafw00f"]="EnableSecurity/wafw00f"
	["commix"]="commixproject/commix"
	["urless"]="xnl-h4ck3r/urless"
	["ghauri"]="r0oth3x49/ghauri"
	["xnLinkFinder"]="xnl-h4ck3r/xnLinkFinder"
	["xnldorker"]="xnl-h4ck3r/xnldorker"
	["porch-pirate"]="MandConsultingGroup/porch-pirate"
	["p1radup"]="iambouali/p1radup"
	["subwiz"]="hadriansecurity/subwiz"
	["arjun"]="s0md3v/Arjun"
	["gqlspection"]="doyensec/GQLSpection"
	["cloud_enum"]="initstring/cloud_enum"
)

# Declare repositories and their paths
declare -A repos=(
	["dorks_hunter"]="six2dez/dorks_hunter"
	["gf"]="tomnomnom/gf"
	["Gf-Patterns"]="1ndianl33t/Gf-Patterns"
	["sus_params"]="g0ldencybersec/sus_params"
	["Corsy"]="s0md3v/Corsy"
	["CMSeeK"]="Tuhinshubhra/CMSeeK"
	["fav-up"]="pielco11/fav-up"
	["massdns"]="blechschmidt/massdns"
	["Oralyzer"]="r0075h3ll/Oralyzer"
	["testssl.sh"]="drwetter/testssl.sh"
	["JSA"]="w9w/JSA"
	["CloudHunter"]="belane/CloudHunter"
	["ultimate-nmap-parser"]="shifty0g/ultimate-nmap-parser"
	["pydictor"]="LandGrey/pydictor"
	["gitdorks_go"]="damit5/gitdorks_go"
	["Web-Cache-Vulnerability-Scanner"]="Hackmanit/Web-Cache-Vulnerability-Scanner"
	["regulator"]="cramppet/regulator"
	["gitleaks"]="gitleaks/gitleaks"
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
)

# Function to display the banner
function banner() {
	tput clear
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
		if [[ $upgrade_tools == "false" ]]; then
			if command -v "$gotool" &>/dev/null; then
				INST_GO_SKIP+=("$gotool")
				((++go_skip))
				progress_update "Go tools" "$go_step" "$total_go" "$go_ok" "$go_skip" "$go_fail"
				[[ $COMPACT != "true" ]] && msg_warn "[$go_step/$total_go] ${gotool} already installed"
				continue
			fi
		fi

		# Install the Go tool
		if q bash -lc "${gotools[$gotool]}"; then
			INST_GO_OK+=("$gotool")
			((++go_ok))
			progress_update "Go tools" "$go_step" "$total_go" "$go_ok" "$go_skip" "$go_fail"
			[[ $COMPACT != "true" ]] && msg_ok "[$go_step/$total_go] ${gotool} installed"
		else
			failed_tools+=("$gotool")
			INST_GO_FAIL+=("$gotool")
			((++go_fail))
			double_check=true
			progress_update "Go tools" "$go_step" "$total_go" "$go_ok" "$go_skip" "$go_fail"
			msg_err "[$go_step/$total_go] ${gotool} failed"
		fi
	done
	[[ $COMPACT == "true" && $IS_TTY -eq 1 ]] && printf "\n"

	header "Installing pipx tools (${#pipxtools[@]})"

	local pipx_step=0
	local failed_pipx_tools=()
	local total_px=${#pipxtools[@]}
	local px_ok=0 px_skip=0 px_fail=0

	for pipxtool in "${!pipxtools[@]}"; do
		((++pipx_step))
		if [[ $upgrade_tools == "false" ]]; then
			if command -v "$pipxtool" &>/dev/null; then
				INST_PX_SKIP+=("$pipxtool")
				((++px_skip))
				progress_update "pipx tools" "$pipx_step" "$total_px" "$px_ok" "$px_skip" "$px_fail"
				[[ $COMPACT != "true" ]] && msg_warn "[$pipx_step/$total_px] ${pipxtool} already installed"
				continue
			fi
		fi

		# Install the pipx tool
		q pipx install "git+https://github.com/${pipxtools[$pipxtool]}"
		exit_status=$?
		if [[ $exit_status -ne 0 ]]; then
			failed_pipx_tools+=("$pipxtool")
			INST_PX_FAIL+=("$pipxtool")
			((++px_fail))
			double_check=true
			progress_update "pipx tools" "$pipx_step" "$total_px" "$px_ok" "$px_skip" "$px_fail"
			msg_err "[$pipx_step/$total_px] ${pipxtool} install failed"
			continue
		fi

		# Upgrade the pipx tool
		q pipx upgrade "${pipxtool}"
		exit_status=$?
		if [[ $exit_status -ne 0 ]]; then
			failed_pipx_tools+=("$pipxtool")
			INST_PX_FAIL+=("$pipxtool")
			((++px_fail))
			double_check=true
			progress_update "pipx tools" "$pipx_step" "$total_px" "$px_ok" "$px_skip" "$px_fail"
			msg_err "[$pipx_step/$total_px] ${pipxtool} upgrade failed"
			continue
		fi

		INST_PX_OK+=("$pipxtool")
		((++px_ok))
		progress_update "pipx tools" "$pipx_step" "$total_px" "$px_ok" "$px_skip" "$px_fail"
		[[ $COMPACT != "true" ]] && msg_ok "[$pipx_step/$total_px] ${pipxtool} ready"
	done
	[[ $COMPACT == "true" && $IS_TTY -eq 1 ]] && printf "\n"

	header "Installing repositories (${#repos[@]})"

	local repos_step=0
	local failed_repos=()
	local total_repo=${#repos[@]}
	local repo_ok=0 repo_skip=0 repo_fail=0

	for repo in "${!repos[@]}"; do
		((++repos_step))
		if [[ $upgrade_tools == "false" ]]; then
			if [[ -d "${dir}/${repo}" ]]; then
				REPOS_SKIPPED+=("$repo")
				((++repo_skip))
				progress_update "repos" "$repos_step" "$total_repo" "$repo_ok" "$repo_skip" "$repo_fail"
				[[ $COMPACT != "true" ]] && msg_warn "[$repos_step/$total_repo] $repo already present at ${dir}/${repo}"
				continue
			fi
		fi
		# Clone the repository
		if [[ ! -d "${dir}/${repo}" || -z "$(ls -A "${dir}/${repo}")" ]]; then
			msg_run "[$repos_step/${#repos[@]}] $repo (clone)"
			if retry 3 3 q_to 180 git clone --filter="blob:none" "https://github.com/${repos[$repo]}" "${dir}/${repo}"; then
				exit_status=0
			else
				exit_status=$?
			fi
			if [[ $exit_status -ne 0 ]]; then
				msg_err "[$repos_step/$total_repo] $repo clone failed"
				failed_repos+=("$repo")
				REPOS_FAIL+=("$repo")
				((++repo_fail))
				double_check=true
				continue
			fi
			REPOS_CLONED+=("$repo")
			((++repo_ok))
			progress_update "repos" "$repos_step" "$total_repo" "$repo_ok" "$repo_skip" "$repo_fail"
		fi

		# Navigate to the repository directory
		cd "${dir}/${repo}" || {
			msg_err "[$repos_step/$total_repo] $repo: cannot enter ${dir}/${repo}"
			failed_repos+=("$repo")
			REPOS_FAIL+=("$repo")
			((++repo_fail))
			double_check=true
			continue
		}

		# Pull the latest changes
		msg_run "[$repos_step/${#repos[@]}] $repo (pull)"
		if retry 3 3 q_to 60 git pull; then
			exit_status=0
		else
			exit_status=$?
		fi
		if [[ $exit_status -ne 0 ]]; then
			msg_err "[$repos_step/$total_repo] $repo pull failed"
			failed_repos+=("$repo")
			REPOS_FAIL+=("$repo")
			((++repo_fail))
			double_check=true
			continue
		fi

		# Install requirements inside a virtual environment
		if [[ -s "requirements.txt" ]]; then
			if [[ ! -f "venv/bin/activate" ]]; then
				python3 -m venv venv &>/dev/null
			fi
			# shellcheck disable=SC1091
			source venv/bin/activate
			if ! pip3 install --upgrade -r requirements.txt &>/dev/null; then
				msg_err "[$repos_step/$total_repo] $repo: pip requirements failed"
				failed_repos+=("$repo")
				REPOS_FAIL+=("$repo")
				((++repo_fail))
				double_check=true
			fi
			if [ "$repo" = "dorks_hunter" ]; then
				source venv/bin/activate
				pip install xnldorker &>/dev/null || true
			fi
			deactivate || true
		fi

		# Special handling for certain repositories
		case "$repo" in
		"massdns")
			make &>/dev/null && strip -s bin/massdns && $SUDO cp bin/massdns /usr/local/bin/ &>/dev/null
			;;
		"gitleaks")
			make build &>/dev/null && $SUDO cp ./gitleaks /usr/local/bin/ &>/dev/null
			;;
		"nomore403")
			go get &>/dev/null
			go build &>/dev/null
			chmod +x ./nomore403
			;;
		"ffufPostprocessing")
			git reset --hard origin/master &>/dev/null
			git pull &>/dev/null
			go build -o ffufPostprocessing main.go &>/dev/null
			chmod +x ./ffufPostprocessing
			;;
		"trufflehog")
			go install &>/dev/null
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
	[[ $COMPACT == "true" && $IS_TTY -eq 1 ]] && printf "\n"

	# Notify and ensure subfinder is installed twice (as per original script)
	# Guard with command checks to avoid aborting under set -e
	q command -v notify >/dev/null 2>&1 && q notify || true
	q command -v subfinder >/dev/null 2>&1 && q subfinder || true
	q command -v subfinder >/dev/null 2>&1 && q subfinder || true
	mkdir -p ${NUCLEI_TEMPLATES_PATH} &>/dev/null
	#cent init -f &>/dev/null
	#cent -p ${NUCLEI_TEMPLATES_PATH} &>/dev/null

	# Handle failed installations
	if [[ ${#failed_tools[@]} -ne 0 ]]; then
		printf "\n%bFailed to install the following Go tools: %s%b\n" "$red" "${failed_tools[*]}" "$reset"
	fi

	if [[ ${#failed_pipx_tools[@]} -ne 0 ]]; then
		printf "\n%bFailed to install the following pipx tools: %s%b\n" "$red" "${failed_pipx_tools[*]}" "$reset"
	fi

	if [[ ${#failed_repos[@]} -ne 0 ]]; then
		printf "\n%bFailed to clone or update the following repositories:%b\n%s\n" "$red" "$reset" "${failed_repos[*]}"
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
		BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "HEAD")
		HEADHASH=$(git rev-parse HEAD 2>/dev/null || true)
		# Skip auto-update if no upstream (detached HEAD or no tracking branch)
		if ! git rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
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
			git reset --hard &>/dev/null
			run_to 60 git pull &>/dev/null
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
    local version="go1.25.3"
    local latest_version
    latest_version=$(curl -s https://go.dev/VERSION?m=text | head -1 || echo "go1.20.7")
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

            local tmp_unpack
            tmp_unpack=$(mktemp -d 2>/dev/null || mktemp -d -t goinstall)
            if ! tar -C "$tmp_unpack" -xzf "$archive_path" &>/dev/null; then
                msg_err "[!] Failed to extract ${archive_path}"
                rm -rf "$tmp_unpack"
                return 1
            fi

            if [[ ! -d "${tmp_unpack}/go" ]]; then
                msg_err "[!] Extracted archive missing 'go' directory"
                rm -rf "$tmp_unpack"
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
                rm -rf "$tmp_unpack"
                return 1
            fi
            if [[ -n $go_backup ]]; then
                $SUDO rm -rf "$go_backup" &>/dev/null
            fi

            rm -rf "$tmp_unpack"
            rm -f "$archive_path" 2>/dev/null

            $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/ 2>/dev/null
        fi

        export GOROOT=/usr/local/go
        export GOPATH="${HOME}/go"
        export PATH="$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH"

        if [[ -n ${profile_shell:-} ]]; then
            local profile_path="${HOME}/${profile_shell}"
            local marker="# Golang environment variables (reconFTW)"
            if ! grep -Fq "$marker" "$profile_path" 2>/dev/null; then
                {
                    printf '\n%s\n' "$marker"
                    printf 'export GOROOT=/usr/local/go\n'
                    printf 'export GOPATH=$HOME/go\n'
                    printf 'export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH\n'
                } >>"$profile_path"
            fi
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
	$SUDO apt-get install -y python3 python3-pip python3-venv pipx python3-virtualenv build-essential gcc cmake ruby whois git curl libpcap-dev wget zip python3-dev pv dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq apt-transport-https lynx medusa xvfb libxml2-utils procps bsdmainutils libdata-hexdump-perl &>/dev/null
	# Move chromium browser dependencies (required by `nuclei -headless -id screenshot`) into a separate apt install command, and add a fallback for Ubuntu 24.04 (where `libasound2` is renamed to `libasound2t64`)
	$SUDO apt-get install -y libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon-x11-0 libxcomposite-dev libxdamage1 libxrandr2 libgbm-dev libpangocairo-1.0-0 libasound2 &>/dev/null ||
		$SUDO apt-get install -y libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon-x11-0 libxcomposite-dev libxdamage1 libxrandr2 libgbm-dev libpangocairo-1.0-0 libasound2t64 &>/dev/null
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	source "${HOME}/.cargo/env"
	cargo install ripgen &>/dev/null
	cargo install smugglex &>/dev/null
	pipx ensurepath -f &>/dev/null
	# Install jsbeautifier and shodan CLI in isolated environments to avoid PEP 668 conflicts
	pipx install jsbeautifier &>/dev/null || true
	pipx install shodan &>/dev/null || pipx upgrade shodan &>/dev/null || true
}

# Function to install required packages for macOS
function install_brew() {
	if command -v brew &>/dev/null; then
		printf "%bbrew is already installed.%b\n" "$bgreen" "$reset"
	else
		/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
	fi
	brew update &>/dev/null
	brew install --formula bash coreutils gnu-getopt gnu-sed python pipx massdns jq gcc cmake ruby git curl wget zip pv bind whois nmap lynx medusa shodan &>/dev/null
	brew install rustup &>/dev/null
	rustup-init -y &>/dev/null
	cargo install ripgen &>/dev/null
	cargo install smugglex &>/dev/null
}

# Function to install required packages for RedHat-based systems
function install_yum() {
	$SUDO yum groupinstall "Development Tools" -y &>/dev/null
	# Base install first (python3 may be 3.6 on older EL)
	$SUDO yum install -y epel-release &>/dev/null || true
	$SUDO yum install -y python3 python3-pip gcc cmake ruby git curl libpcap whois wget pipx zip pv bind-utils openssl-devel libffi-devel libxml2-devel libxslt-devel zlib-devel nmap jq lynx medusa xorg-x11-server-xvfb &>/dev/null

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

	# Ensure pipx uses the selected python3
	export PIPX_DEFAULT_PYTHON="$(command -v python3 || echo python3)"

	# Ensure pipx is present even on older EL (install via pip if the rpm doesn't exist)
	if ! command -v pipx &>/dev/null; then
		python3 -m pip install --user -U pip pipx &>/dev/null || true
		export PATH="$HOME/.local/bin:$PATH"
	fi
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	source "${HOME}/.cargo/env"
	cargo install ripgen &>/dev/null
	cargo install smugglex &>/dev/null
	# Ensure pipx path and install shodan CLI
	pipx ensurepath -f &>/dev/null || true
	pipx install shodan &>/dev/null || pipx upgrade shodan &>/dev/null || true
}

# Function to install required packages for Arch-based systems
function install_pacman() {
	$SUDO pacman -Sy --noconfirm python python-pip base-devel gcc cmake ruby git curl libpcap python-pipx whois wget zip pv bind openssl libffi libxml2 libxslt zlib nmap jq lynx medusa xorg-server-xvfb &>/dev/null
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	source "${HOME}/.cargo/env"
	cargo install ripgen &>/dev/null
	cargo install smugglex &>/dev/null
	# Ensure pipx path and install shodan CLI
	pipx ensurepath -f &>/dev/null || true
	pipx install shodan &>/dev/null || pipx upgrade shodan &>/dev/null || true
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

		q pipx ensurepath
		export PATH="${HOME}/.local/bin:${PATH}"

		install_tools
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

	q pipx ensurepath
	# Ensure $HOME/.local/bin is available now even if profile isn't sourced
	export PATH="${HOME}/.local/bin:${PATH}"
	# Do not source user shell profiles here to avoid errors like 'PS1: unbound variable'
	# in non-interactive shells with 'set -u'. PATH for this process is already updated.

	install_tools

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

	# gf patterns
	if [[ ! -d "$HOME/.gf" ]]; then
		#printf "${yellow}Installing gf patterns...\n"
		ensure_git_dir "${dir}/gf"
		if ! retry 3 3 q_to 120 git clone https://github.com/tomnomnom/gf.git "${dir}/gf"; then true; fi
		cp -r "${dir}/gf/examples" ~/.gf 2>/dev/null || true
		ensure_git_dir "${dir}/Gf-Patterns"
		if ! retry 3 3 q_to 120 git clone https://github.com/1ndianl33t/Gf-Patterns "${dir}/Gf-Patterns"; then true; fi
		cp "${dir}/Gf-Patterns"/*.json ~/.gf/ 2>/dev/null || true
	else
		#printf "${yellow}Updating gf patterns...\n"
		ensure_git_dir "${dir}/Gf-Patterns"
		if ! retry 3 3 q_to 60 git -C "${dir}/Gf-Patterns" pull; then true; fi
	fi

	header "Downloading required files"

	mkdir -p ${HOME}/.config/notify
	# Download required files with error handling
	declare -A downloads=(
		["notify_provider_config"]="https://gist.githubusercontent.com/six2dez/23a996bca189a11e88251367e6583053/raw ${HOME}/.config/notify/provider-config.yaml"
		["getjswords"]="https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py ${tools}/getjswords.py"
		["subdomains_huge"]="https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt ${subs_wordlist_big}"
		["trusted_resolvers"]="https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw ${resolvers_trusted}"
		["resolvers"]="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt ${resolvers}"
		["subs_wordlist"]="https://gist.github.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw ${subs_wordlist}"
		["permutations_list"]="https://gist.github.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw ${tools}/permutations_list.txt"
		["fuzz_wordlist"]="https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt ${fuzz_wordlist}"
		["lfi_wordlist"]="https://gist.githubusercontent.com/six2dez/a89a0c7861d49bb61a09822d272d5395/raw ${lfi_wordlist}"
		["ssti_wordlist"]="https://gist.githubusercontent.com/six2dez/ab5277b11da7369bf4e9db72b49ad3c1/raw ${ssti_wordlist}"
		["headers_inject"]="https://gist.github.com/six2dez/d62ab8f8ffd28e1c206d401081d977ae/raw ${tools}/headers_inject.txt"
		["axiom_config"]="https://gist.githubusercontent.com/six2dez/6e2d9f4932fd38d84610eb851014b26e/raw ${tools}/axiom_config.sh"
		["jsluice_patterns"]="https://gist.githubusercontent.com/six2dez/2aafa8dc2b682bb0081684e71900e747/raw ${tools}/jsluice_patterns.json"
	)

	for key in "${!downloads[@]}"; do
		url="${downloads[$key]% *}"
		destination="${downloads[$key]#* }"

		# Skip download if provider-config.yaml already exists
		if [[ $key == "notify_provider_config" && -f $destination ]]; then
			printf "[%bSKIPPING%b] %s as it already exists at %s.\n" "$yellow" "$reset" "$key" "$destination"
			continue
		fi

		# Ensure destination directory exists
		mkdir -p "$(dirname "$destination")" 2>/dev/null || true

		if with_spinner "Fetching $key" retry 3 3 q_to 120 wget -q -O "$destination" "$url"; then
			:
		else
			msg_err "Failed to download $key from $url"
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
	final_reminder="$(cat <<EOF
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
