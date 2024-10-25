#!/usr/bin/env bash

# Enable strict error handling
#IFS=$'\n\t'

# Load main configuration
CONFIG_FILE="./reconftw.cfg"

if [[ ! -f $CONFIG_FILE ]]; then
	echo -e "${bred}[!] Config file reconftw.cfg not found.${reset}"
	exit 1
fi

source "$CONFIG_FILE"

# Initialize variables
dir="${tools}"
double_check=false

# ARM Detection
ARCH=$(uname -m)
case "$ARCH" in
amd64 | x86_64)
	IS_ARM="False"
	;;
arm64 | armv6l | aarch64)
	IS_ARM="True"
	if [[ $ARCH == "arm64" ]]; then
		RPI_4="True"
		RPI_3="False"
	else
		RPI_4="False"
		RPI_3="True"
	fi
	;;
*)
	IS_ARM="False"
	;;
esac

# macOS Detection
IS_MAC=$([[ $OSTYPE == "darwin"* ]] && echo "True" || echo "False")

# Check Bash version
BASH_VERSION_NUM=$(bash --version | awk 'NR==1{print $4}' | cut -d'.' -f1)
if [[ $BASH_VERSION_NUM -lt 4 ]]; then
	echo -e "${bred}Your Bash version is lower than 4, please update.${reset}"
	if [[ $IS_MAC == "True" ]]; then
		echo -e "${yellow}For macOS, run 'brew install bash' and rerun the installer in a new terminal.${reset}"
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
	["gau"]="go install -v github.com/lc/gau/v2/cmd/gau@latest"
	["mantra"]="go install -v github.com/MrEmpy/mantra@latest"
	["crt"]="go install -v github.com/cemulus/crt@latest"
	["s3scanner"]="go install -v github.com/sa7mon/s3scanner@latest"
	["nmapurls"]="go install -v github.com/sdcampbell/nmapurls@latest"
	["shortscan"]="go install -v github.com/bitquark/shortscan/cmd/shortscan@latest"
	["sns"]="go install github.com/sw33tLie/sns@latest"
	["ppmap"]="go install -v github.com/kleiton0x00/ppmap@latest"
	["sourcemapper"]="go install -v github.com/denandz/sourcemapper@latest"
	["jsluice"]="go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest"
)

# Declare repositories and their paths
declare -A repos=(
	["dorks_hunter"]="six2dez/dorks_hunter"
	["dnsvalidator"]="vortexau/dnsvalidator"
	["interlace"]="codingo/Interlace"
	["wafw00f"]="EnableSecurity/wafw00f"
	["gf"]="tomnomnom/gf"
	["Gf-Patterns"]="1ndianl33t/Gf-Patterns"
	["Corsy"]="s0md3v/Corsy"
	["CMSeeK"]="Tuhinshubhra/CMSeeK"
	["fav-up"]="pielco11/fav-up"
	["massdns"]="blechschmidt/massdns"
	["Oralyzer"]="r0075h3ll/Oralyzer"
	["testssl"]="drwetter/testssl.sh"
	["commix"]="commixproject/commix"
	["JSA"]="w9w/JSA"
	["CloudHunter"]="belane/CloudHunter"
	["ultimate-nmap-parser"]="shifty0g/ultimate-nmap-parser"
	["pydictor"]="LandGrey/pydictor"
	["gitdorks_go"]="damit5/gitdorks_go"
	["urless"]="xnl-h4ck3r/urless"
	["smuggler"]="defparam/smuggler"
	["Web-Cache-Vulnerability-Scanner"]="Hackmanit/Web-Cache-Vulnerability-Scanner"
	["regulator"]="cramppet/regulator"
	["ghauri"]="r0oth3x49/ghauri"
	["gitleaks"]="gitleaks/gitleaks"
	["trufflehog"]="trufflesecurity/trufflehog"
	["nomore403"]="devploit/nomore403"
	["SwaggerSpy"]="UndeadSec/SwaggerSpy"
	["LeakSearch"]="JoelGMSec/LeakSearch"
	["ffufPostprocessing"]="Damian89/ffufPostprocessing"
	["misconfig-mapper"]="intigriti/misconfig-mapper"
	["Spoofy"]="MattKeeley/Spoofy"
	["Waymore"]="xnl-h4ck3r/waymore"
	["xnLinkFinder"]="xnl-h4ck3r/xnLinkFinder"
	["porch-pirate"]="MandConsultingGroup/porch-pirate"
	["MetaFinder"]="Josue87/MetaFinder"
	["EmailFinder"]="Josue87/EmailFinder"
)

# Function to display the banner
function banner() {
	tput clear
	cat <<"EOF"

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
	echo -e "${bblue}Running: Installing Golang tools (${#gotools[@]})${reset}\n"

	local go_step=0
	local failed_tools=()
	for gotool in "${!gotools[@]}"; do
		((go_step++))
		if [[ $upgrade_tools == "false" ]]; then
			if command -v "$gotool" &>/dev/null; then
				echo -e "[${yellow}SKIPPING${reset}] $gotool already installed at $(command -v "$gotool")"
				continue
			fi
		fi

		# Install the Go tool
		eval "${gotools[$gotool]}" &>/dev/null
		exit_status=$?
		if [[ $exit_status -eq 0 ]]; then
			echo -e "${yellow}$gotool installed (${go_step}/${#gotools[@]})${reset}"
		else
			echo -e "${red}Unable to install $gotool, try manually (${go_step}/${#gotools[@]})${reset}"
			failed_tools+=("$gotool")
			double_check=true
		fi
	done

	echo -e "\n${bblue}Running: Installing repositories (${#repos[@]})${reset}\n"

	local repos_step=0
	local failed_repos=()

	for repo in "${!repos[@]}"; do
		((repos_step++))
		if [[ $upgrade_tools == "false" ]]; then
			if [[ -d "${dir}/${repo}" ]]; then
				echo -e "[${yellow}SKIPPING${reset}] Repository $repo already cloned in ${dir}/${repo}"
				continue
			fi
		fi
		# Clone the repository
		if [[ ! -d "${dir}/${repo}" || -z "$(ls -A "${dir}/${repo}")" ]]; then
			git clone --filter="blob:none" "https://github.com/${repos[$repo]}" "${dir}/${repo}" #&>/dev/null
			exit_status=$?
			if [[ $exit_status -ne 0 ]]; then
				echo -e "${red}Unable to clone repository $repo.${reset}"
				failed_repos+=("$repo")
				double_check=true
				continue
			fi
		fi

		# Navigate to the repository directory
		cd "${dir}/${repo}" || {
			echo -e "${red}Failed to navigate to directory '${dir}/${repo}'${reset}"
			failed_repos+=("$repo")
			double_check=true
			continue
		}

		# Pull the latest changes
		git pull &>/dev/null
		exit_status=$?
		if [[ $exit_status -ne 0 ]]; then
			echo -e "${red}Failed to pull updates for repository $repo.${reset}"
			failed_repos+=("$repo")
			double_check=true
			continue
		fi

		# Install dependencies if setup.py exists
		if [[ -f "setup.py" ]]; then
			eval "$SUDO pip3 install . $DEBUG_STD" &>/dev/null
		fi

		# Special handling for certain repositories
		case "$repo" in
		"massdns")
			make &>/dev/null && strip -s bin/massdns && "$SUDO" cp bin/massdns /usr/local/bin/ &>/dev/null
			;;
		"gitleaks")
			make build &>/dev/null && "$SUDO" cp ./gitleaks /usr/local/bin/ &>/dev/null
			;;
		"nomore403")
			go get &>/dev/null
			go build &>/dev/null
			chmod +x ./nomore403
			;;
		"ffufPostprocessing")
			git reset --hard origin/main &>/dev/null
			git pull &>/dev/null
			go build -o ffufPostprocessing main.go &>/dev/null
			chmod +x ./ffufPostprocessing
			;;
		"misconfig-mapper")
			git reset --hard origin/main &>/dev/null
			git pull &>/dev/null
			go build -o misconfig-mapper &>/dev/null
			chmod +x ./misconfig-mapper
			;;
		esac

		# Copy gf patterns if applicable
		if [[ $repo == "gf" ]]; then
			cp -r examples ${HOME}/.gf &>/dev/null
		elif [[ $repo == "Gf-Patterns" ]]; then
			mv ./*.json ${HOME}/.gf &>/dev/null
		fi

		# Return to the main directory
		cd "$dir" || {
			echo -e "${red}Failed to navigate back to directory '$dir'.${reset}"
			exit 1
		}

		echo -e "${yellow}$repo installed (${repos_step}/${#repos[@]})${reset}"
	done

	# Notify and ensure subfinder is installed twice (as per original script)
	notify &>/dev/null
	subfinder &>/dev/null
	subfinder &>/dev/null

	# Handle failed installations
	if [[ ${#failed_tools[@]} -ne 0 ]]; then
		echo -e "\n${red}Failed to install the following Go tools: ${failed_tools[*]}${reset}"
	fi

	if [[ ${#failed_repos[@]} -ne 0 ]]; then
		echo -e "\n${red}Failed to clone or update the following repositories:\n${failed_repos[*]}${reset}"
	fi
}

# Function to reset git proxy settings
function reset_git_proxies() {
	git config --global --unset http.proxy || true
	git config --global --unset https.proxy || true
}

# Function to check for updates
function check_updates() {
	echo -e "${bblue}Running: Looking for new reconFTW version${reset}\n"

	if timeout 10 git fetch; then
		BRANCH=$(git rev-parse --abbrev-ref HEAD)
		HEADHASH=$(git rev-parse HEAD)
		UPSTREAMHASH=$(git rev-parse "${BRANCH}@{upstream}")

		if [[ $HEADHASH != "$UPSTREAMHASH" ]]; then
			echo -e "${yellow}A new version is available. Updating...${reset}\n"
			if git status --porcelain | grep -q 'reconftw.cfg$'; then
				mv reconftw.cfg reconftw.cfg_bck
				echo -e "${yellow}reconftw.cfg has been backed up to reconftw.cfg_bck${reset}\n"
			fi
			git reset --hard &>/dev/null
			git pull &>/dev/null
			echo -e "${bgreen}Updated! Running the new installer version...${reset}\n"
		else
			echo -e "${bgreen}reconFTW is already up to date!${reset}\n"
		fi
	else
		echo -e "\n${bred}[!] Unable to check for updates.${reset}\n"
	fi
}

# Function to install Golang
function install_golang_version() {
	local version="go1.20.7"
	local latest_version
	latest_version=$(curl -s https://go.dev/VERSION?m=text | head -1 || echo "go1.20.7")
	if [[ $latest_version == g* ]]; then
		version="$latest_version"
	fi

	echo -e "${bblue}Running: Installing/Updating Golang($version) ${reset}\n"

	if [[ $install_golang == "true" ]]; then
		if command -v go &>/dev/null && [[ $version == "$(go version | awk '{print $3}')" ]]; then
			echo -e "${bgreen}Golang is already installed and up to date.${reset}\n"
		else
			"$SUDO" rm -rf /usr/local/go &>/dev/null || true

			case "$ARCH" in
			arm64 | aarch64)
				if [[ $RPI_4 == "True" ]]; then
					wget "https://dl.google.com/go/${version}.linux-arm64.tar.gz" -O "/tmp/${version}.linux-arm64.tar.gz" &>/dev/null
					"$SUDO" tar -C /usr/local -xzf "/tmp/${version}.linux-arm64.tar.gz" &>/dev/null
				elif [[ $RPI_3 == "True" ]]; then
					wget "https://dl.google.com/go/${version}.linux-armv6l.tar.gz" -O "/tmp/${version}.linux-armv6l.tar.gz" &>/dev/null
					"$SUDO" tar -C /usr/local -xzf "/tmp/${version}.linux-armv6l.tar.gz" &>/dev/null
				fi
				;;
			*)
				if [[ $IS_MAC == "True" ]]; then
					if [[ $IS_ARM == "True" ]]; then
						wget "https://dl.google.com/go/${version}.darwin-arm64.tar.gz" -O "/tmp/${version}.darwin-arm64.tar.gz" &>/dev/null
						"$SUDO" tar -C /usr/local -xzf "/tmp/${version}.darwin-arm64.tar.gz" &>/dev/null
					else
						wget "https://dl.google.com/go/${version}.darwin-amd64.tar.gz" -O "/tmp/${version}.darwin-amd64.tar.gz" &>/dev/null
						"$SUDO" tar -C /usr/local -xzf "/tmp/${version}.darwin-amd64.tar.gz" &>/dev/null
					fi
				else
					wget "https://dl.google.com/go/${version}.linux-amd64.tar.gz" -O "/tmp/${version}.linux-amd64.tar.gz" &>/dev/null
					"$SUDO" tar -C /usr/local -xzf "/tmp/${version}.linux-amd64.tar.gz" &>/dev/null
				fi
				;;
			esac

			"$SUDO" ln -sf /usr/local/go/bin/go /usr/local/bin/
			export GOROOT=/usr/local/go
			export GOPATH="${HOME}/go"
			export PATH="$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH"

			# Append Go environment variables to shell profile
			cat <<EOF >>${HOME}/"${profile_shell}"

# Golang environment variables
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.local/bin:\$PATH
EOF
		fi
	else
		echo -e "${byellow}Golang will not be configured according to the user's preferences (install_golang=false in reconftw.cfg).${reset}\n"
	fi

	# Validate Go environment variables
	if [[ -z ${GOPATH-} ]]; then
		echo -e "${bred}GOPATH environment variable not detected. Add Golang environment variables to your \$HOME/.bashrc or \$HOME/.zshrc:${reset}"
		echo -e "export GOROOT=/usr/local/go"
		echo -e 'export GOPATH=$HOME/go'
		echo -e "export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n"
		exit 1
	fi

	if [[ -z ${GOROOT-} ]]; then
		echo -e "${bred}GOROOT environment variable not detected. Add Golang environment variables to your \$HOME/.bashrc or \$HOME/.zshrc:${reset}"
		echo -e "export GOROOT=/usr/local/go"
		echo -e 'export GOPATH=$HOME/go'
		echo -e "export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n"
		exit 1
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
		echo -e "${bred}[!] Unsupported OS. Please install dependencies manually.${reset}"
		exit 1
	fi
}

# Function to install required packages for Debian-based systems
function install_apt() {
	"$SUDO" apt update -y &>/dev/null
	"$SUDO" DEBIAN_FRONTEND="noninteractive" apt install -y chromium-browser python3 python3-pip python3-virtualenv build-essential gcc cmake ruby whois git curl libpcap-dev wget zip python3-dev pv dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq apt-transport-https lynx medusa xvfb libxml2-utils procps bsdmainutils libdata-hexdump-perl libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon-x11-0 libxcomposite-dev libxdamage1 libxrandr2 libgbm-dev libpangocairo-1.0-0 libasound2 &>/dev/null
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	source "${HOME}/.cargo/env"
	cargo install ripgen &>/dev/null
}

# Function to install required packages for macOS
function install_brew() {
	if command -v brew &>/dev/null; then
		echo -e "${bgreen}brew is already installed.${reset}\n"
	else
		/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
	fi
	brew update &>/dev/null
	brew install --cask chromium &>/dev/null
	brew install bash coreutils python massdns jq gcc cmake ruby git curl libpcap-dev wget zip python3-dev pv dnsutils whois libssl-dev libffi-dev libxml2-dev libxslt-dev zlib libnss3 atk bridge2.0 cups xkbcommon xcomposite xdamage xrandr gbm pangocairo alsa libxml2-utils &>/dev/null
	brew install rustup &>/dev/null
	rustup-init -y &>/dev/null
	cargo install ripgen &>/dev/null
}

# Function to install required packages for RedHat-based systems
function install_yum() {
	"$SUDO" yum groupinstall "Development Tools" -y &>/dev/null
	"$SUDO" yum install -y python3 python3-pip gcc cmake ruby git curl libpcap whois wget zip pv bind-utils openssl-devel libffi-devel libxml2-devel libxslt-devel zlib-devel nmap jq lynx medusa xorg-x11-server-xvfb &>/dev/null
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	source "${HOME}/.cargo/env"
	cargo install ripgen &>/dev/null
}

# Function to install required packages for Arch-based systems
function install_pacman() {
	"$SUDO" pacman -Sy --noconfirm python python-pip base-devel gcc cmake ruby git curl libpcap whois wget zip pv bind openssl libffi libxml2 libxslt zlib nmap jq lynx medusa xorg-server-xvfb &>/dev/null
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	source "${HOME}/.cargo/env"
	cargo install ripgen &>/dev/null
}

# Function to perform initial setup
function initial_setup() {
	banner
	reset_git_proxies

	echo -e "${bblue}Running: Checking for updates${reset}\n"
	check_updates

	echo -e "${bblue}Running: Installing system packages${reset}\n"
	install_system_packages

	install_golang_version

	echo -e "${bblue}Running: Installing Python requirements${reset}\n"
	mkdir -p ${HOME}/.gf
	mkdir -p "$tools"
	mkdir -p ${HOME}/.config/notify/
	mkdir -p ${HOME}/.config/nuclei/
	touch "${dir}/.github_tokens"
	touch "${dir}/.gitlab_tokens"

	wget -N -c https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py &>/dev/null
	python3 /tmp/get-pip.py &>/dev/null
	rm -f /tmp/get-pip.py

	install_tools

	# Repositorios con configuraciones especiales
	printf "${bblue}\nRunning: Configuring special repositories${reset}\n"

	# Nuclei Templates
	if [[ ! -d ${NUCLEI_TEMPLATES_PATH} ]]; then
		#printf "${yellow}Cloning Nuclei templates...${reset}\n"
		eval git clone https://github.com/projectdiscovery/nuclei-templates.git "${NUCLEI_TEMPLATES_PATH}" $DEBUG_STD
		eval git clone https://github.com/geeknik/the-nuclei-templates.git "${NUCLEI_TEMPLATES_PATH}/extra_templates" $DEBUG_STD
		eval git clone https://github.com/projectdiscovery/fuzzing-templates ${tools}/fuzzing-templates $DEBUG_STD
		eval nuclei -update-templates update-template-dir "${NUCLEI_TEMPLATES_PATH}" $DEBUG_STD
	else
		#printf "${yellow}Updating Nuclei templates...${reset}\n"
		eval git -C "${NUCLEI_TEMPLATES_PATH}" pull $DEBUG_STD
		eval git -C "${NUCLEI_TEMPLATES_PATH}/extra_templates" pull $DEBUG_STD
		eval git -C "${tools}/fuzzing-templates" pull $DEBUG_STD
	fi

	# sqlmap
	if [[ ! -d "${dir}/sqlmap" ]]; then
		#printf "${yellow}Cloning sqlmap...${reset}\n"
		eval git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "${dir}/sqlmap" $DEBUG_STD
	else
		#printf "${yellow}Updating sqlmap...${reset}\n"
		eval git -C "${dir}/sqlmap" pull $DEBUG_STD
	fi

	# testssl.sh
	if [[ ! -d "${dir}/testssl.sh" ]]; then
		#printf "${yellow}Cloning testssl.sh...${reset}\n"
		eval git clone --depth 1 https://github.com/drwetter/testssl.sh.git "${dir}/testssl.sh" $DEBUG_STD
	else
		#printf "${yellow}Updating testssl.sh...${reset}\n"
		eval git -C "${dir}/testssl.sh" pull $DEBUG_STD
	fi

	# massdns
	if [[ ! -d "${dir}/massdns" ]]; then
		#printf "${yellow}Cloning and compiling massdns...${reset}\n"
		eval git clone https://github.com/blechschmidt/massdns.git "${dir}/massdns" $DEBUG_STD
		eval make -C "${dir}/massdns" $DEBUG_STD
		eval strip -s "${dir}/massdns/bin/massdns" $DEBUG_ERROR
		eval $SUDO cp "${dir}/massdns/bin/massdns" /usr/local/bin/ $DEBUG_ERROR
	else
		#printf "${yellow}Updating massdns...${reset}\n"
		eval git -C "${dir}/massdns" pull $DEBUG_STD
	fi

	# Interlace
	if [[ ! -d "${dir}/interlace" ]]; then
		#printf "${yellow}Cloning Interlace...${reset}\n"
		eval git clone https://github.com/codingo/Interlace.git "${dir}/interlace" $DEBUG_STD
		eval cd "${dir}/interlace" && eval $SUDO python3 setup.py install $DEBUG_STD
	else
		#printf "${yellow}Updating Interlace...${reset}\n"
		eval git -C "${dir}/interlace" pull $DEBUG_STD
	fi

	# wafw00f
	if [[ ! -d "${dir}/wafw00f" ]]; then
		#printf "${yellow}Cloning wafw00f...${reset}\n"
		eval git clone https://github.com/EnableSecurity/wafw00f.git "${dir}/wafw00f" $DEBUG_STD
		eval cd "${dir}/wafw00f" && eval $SUDO python3 setup.py install $DEBUG_STD
	else
		#printf "${yellow}Updating wafw00f...${reset}\n"
		eval git -C "${dir}/wafw00f" pull $DEBUG_STD
	fi

	# gf patterns
	if [[ ! -d "$HOME/.gf" ]]; then
		#printf "${yellow}Installing gf patterns...${reset}\n"
		eval git clone https://github.com/tomnomnom/gf.git "${dir}/gf" $DEBUG_STD
		eval cp -r "${dir}/gf/examples" ~/.gf $DEBUG_ERROR
		eval git clone https://github.com/1ndianl33t/Gf-Patterns "${dir}/Gf-Patterns" $DEBUG_STD
		eval cp "${dir}/Gf-Patterns"/*.json ~/.gf/ $DEBUG_ERROR
	else
		#printf "${yellow}Updating gf patterns...${reset}\n"
		eval git -C "${dir}/Gf-Patterns" pull $DEBUG_STD
	fi

	echo -e "\n${bblue}Running: Downloading required files${reset}\n"

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
	)

	for key in "${!downloads[@]}"; do
		url="${downloads[$key]% *}"
		destination="${downloads[$key]#* }"
		wget -q -O "$destination" "$url" || {
			echo -e "${red}[!] Failed to download $key from $url.${reset}"
			continue
		}
	done

	# Make axiom_config.sh executable
	chmod +x "${tools}/axiom_config.sh" || {
		echo -e "${red}[!] Failed to make axiom_config.sh executable.${reset}"
	}

	echo -e "${bblue}Running: Performing last configurations${reset}\n"

	# Update resolvers if generate_resolvers is true
	if [[ $generate_resolvers == true ]]; then
		if [[ ! -s $resolvers || $(find "$resolvers" -mtime +1 -print) ]]; then
			echo -e "${yellow}Checking resolvers lists...\nAccurate resolvers are the key to great results.\nThis may take around 10 minutes if it's not updated.${reset}\n"
			rm -f "$resolvers" &>/dev/null
			dnsvalidator -tL https://public-dns.info/nameservers.txt -threads "$DNSVALIDATOR_THREADS" -o "$resolvers" &>/dev/null
			dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads "$DNSVALIDATOR_THREADS" -o tmp_resolvers &>/dev/null

			if [[ -s "tmp_resolvers" ]]; then
				cat tmp_resolvers | anew -q "$resolvers"
				rm -f tmp_resolvers &>/dev/null
			fi

			[[ ! -s $resolvers ]] && wget -q -O "$resolvers" https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
			[[ ! -s $resolvers_trusted ]] && wget -q -O "$resolvers_trusted" https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw/trusted_resolvers.txt
			echo -e "${yellow}Resolvers updated.${reset}\n"
		fi
		generate_resolvers=false
	else
		if [[ -s $resolvers && $(find "$resolvers" -mtime +1 -print) ]]; then
			echo -e "${yellow}Checking resolvers lists...\nAccurate resolvers are the key to great results.\nDownloading new resolvers.${reset}\n"
			wget -q -O "$resolvers" https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
			wget -q -O "$resolvers_trusted" https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw/trusted_resolvers.txt
			echo -e "${yellow}Resolvers updated.${reset}\n"
		fi
	fi

	# Strip all Go binaries and copy to /usr/local/bin
	strip -s "${GOPATH}/bin/"* &>/dev/null || true
	"$SUDO" cp "${GOPATH}/bin/"* /usr/local/bin/ &>/dev/null || true

	# Final reminders
	echo -e "${yellow}Remember to set your API keys:\n- subfinder (${HOME}/.config/subfinder/provider-config.yaml)\n- GitHub (${HOME}/Tools/.github_tokens)\n- GitLab (${HOME}/Tools/.gitlab_tokens)\n- SSRF Server (COLLAB_SERVER in reconftw.cfg or env var)\n- Waymore (${HOME}/.config/waymore/config.yml)\n- Blind XSS Server (XSS_SERVER in reconftw.cfg or env var)\n- notify (${HOME}/.config/notify/provider-config.yaml)\n- WHOISXML API (WHOISXML_API in reconftw.cfg or env var)\n${reset}"
	echo -e "${bgreen}Finished!${reset}\n"
	echo -e "${bgreen}#######################################################################${reset}"
}

# Function to display additional help
function show_additional_help() {
	echo "Usage: $0 [OPTION]"
	echo "Run the script with specified options."
	echo ""
	echo "  -h, --help       Display this help and exit."
	echo "  --tools          Install the tools before running, useful for upgrading."
	echo ""
	echo "  ****             Without any arguments, the script will update reconftw"
	echo "                   and install all dependencies and requirements."
	exit 0
}

# Function to handle installation arguments
function handle_install_arguments() {
	echo -e "\n${bgreen}reconFTW installer/updater script${reset}\n"

	while [[ $# -gt 0 ]]; do
		case "$1" in
		-h | --help)
			show_additional_help
			;;
		--tools)
			install_tools
			shift
			;;
		*)
			echo -e "${bred}Error: Invalid argument '$1'${reset}"
			echo "Use -h or --help for usage information."
			exit 1
			;;
		esac
	done

	echo -e "${yellow}This may take some time. Grab a coffee!${reset}\n"

	# Determine if the script is run as root
	if [[ "$(id -u)" -eq 0 ]]; then
		SUDO=""
	else
		if ! sudo -n true 2>/dev/null; then
			echo -e "${bred}It is strongly recommended to add your user to sudoers.${reset}"
			echo -e "${bred}This will avoid prompts for sudo password during installation and scans.${reset}"
			echo -e "${bred}Run the following command to add your user to sudoers:${reset}"
			echo -e "${bred}echo \"${USER}  ALL=(ALL:ALL) NOPASSWD: ALL\" | sudo tee /etc/sudoers.d/reconFTW${reset}\n"
		fi
		SUDO="sudo"
	fi
}

# Invoke main functions
handle_install_arguments "$@"
initial_setup
