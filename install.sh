#!/usr/bin/env bash

. ./reconftw.cfg

dir=${tools}
double_check=false

# ARM Detection
ARCH=$(uname -m)
case $ARCH in
amd64 | x86_64) IS_ARM="False" ;;
arm64 | armv6l)
	IS_ARM="True"
	RPI_4=$([[ $ARCH == "arm64" ]] && echo "True" || echo "False")
	RPI_3=$([[ $ARCH == "arm64" ]] && echo "False" || echo "True")
	;;
esac

#Mac Osx Detecting
IS_MAC=$([[ $OSTYPE == "darwin"* ]] && echo "True" || echo "False")

BASH_VERSION=$(bash --version | awk 'NR==1{print $4}' | cut -d'.' -f1)
if [[ ${BASH_VERSION} -lt 4 ]]; then
	printf "${bred} Your Bash version is lower than 4, please update${reset}\n"
	printf "%s Your Bash version is lower than 4, please update%s\n" "${bred}" "${reset}" >&2
	if [[ "True" == "$IS_MAC" ]]; then
		printf "${yellow} For MacOS run 'brew install bash' and rerun installer in a new terminal${reset}\n\n"
		exit 1
	fi
fi

# Declaring Go tools and their installation commands
declare -A gotools
gotools["gf"]="go install -v github.com/tomnomnom/gf@latest"
gotools["qsreplace"]="go install -v github.com/tomnomnom/qsreplace@latest"
gotools["amass"]="go install -v github.com/owasp-amass/amass/v3/...@master"
gotools["ffuf"]="go install -v github.com/ffuf/ffuf/v2@latest"
gotools["github-subdomains"]="go install -v github.com/gwen001/github-subdomains@latest"
gotools["gitlab-subdomains"]="go install -v github.com/gwen001/gitlab-subdomains@latest"
gotools["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
gotools["anew"]="go install -v github.com/tomnomnom/anew@latest"
gotools["notify"]="go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
gotools["unfurl"]="go install -v github.com/tomnomnom/unfurl@v0.3.0"
gotools["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
gotools["github-endpoints"]="go install -v github.com/gwen001/github-endpoints@latest"
gotools["dnsx"]="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
gotools["subjs"]="go install -v github.com/lc/subjs@latest"
gotools["Gxss"]="go install -v github.com/KathanP19/Gxss@latest"
gotools["katana"]="go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
gotools["crlfuzz"]="go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
gotools["dalfox"]="go install -v github.com/hahwul/dalfox/v2@latest"
gotools["puredns"]="go install -v github.com/d3mondev/puredns/v2@latest"
gotools["interactsh-client"]="go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
gotools["analyticsrelationships"]="go install -v github.com/Josue87/analyticsrelationships@latest"
gotools["gotator"]="go install -v github.com/Josue87/gotator@latest"
gotools["roboxtractor"]="go install -v github.com/Josue87/roboxtractor@latest"
gotools["mapcidr"]="go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
gotools["cdncheck"]="go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
gotools["dnstake"]="go install -v github.com/pwnesia/dnstake/cmd/dnstake@latest"
gotools["tlsx"]="go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
gotools["gitdorks_go"]="go install -v github.com/damit5/gitdorks_go@latest"
gotools["smap"]="go install -v github.com/s0md3v/smap/cmd/smap@latest"
gotools["dsieve"]="go install -v github.com/trickest/dsieve@master"
gotools["inscope"]="go install -v github.com/tomnomnom/hacks/inscope@latest"
gotools["enumerepo"]="go install -v github.com/trickest/enumerepo@latest"
gotools["Web-Cache-Vulnerability-Scanner"]="go install -v github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest"
gotools["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
gotools["hakip2host"]="go install -v github.com/hakluke/hakip2host@latest"
gotools["gau"]="go install -v github.com/lc/gau/v2/cmd/gau@latest"
gotools["mantra"]="go install -v github.com/MrEmpy/mantra@latest"
gotools["crt"]="go install -v github.com/cemulus/crt@latest"
gotools["s3scanner"]="go install -v github.com/sa7mon/s3scanner@latest"
gotools["nmapurls"]="go install -v github.com/sdcampbell/nmapurls@latest"
gotools["shortscan"]="go install -v github.com/bitquark/shortscan/cmd/shortscan@latest"
gotools["sns"]="go install github.com/sw33tLie/sns@latest"
gotools["ppmap"]="go install -v github.com/kleiton0x00/ppmap@latest"

# Declaring repositories and their paths
declare -A repos
repos["dorks_hunter"]="six2dez/dorks_hunter"
repos["dnsvalidator"]="vortexau/dnsvalidator"
repos["interlace"]="codingo/Interlace"
repos["brutespray"]="x90skysn3k/brutespray"
repos["wafw00f"]="EnableSecurity/wafw00f"
repos["gf"]="tomnomnom/gf"
repos["Gf-Patterns"]="1ndianl33t/Gf-Patterns"
repos["xnLinkFinder"]="xnl-h4ck3r/xnLinkFinder"
repos["waymore"]="xnl-h4ck3r/waymore"
repos["Corsy"]="s0md3v/Corsy"
repos["CMSeeK"]="Tuhinshubhra/CMSeeK"
repos["fav-up"]="pielco11/fav-up"
repos["massdns"]="blechschmidt/massdns"
repos["Oralyzer"]="r0075h3ll/Oralyzer"
repos["testssl"]="drwetter/testssl.sh"
repos["commix"]="commixproject/commix"
repos["JSA"]="w9w/JSA"
repos["cloud_enum"]="initstring/cloud_enum"
repos["ultimate-nmap-parser"]="shifty0g/ultimate-nmap-parser"
repos["pydictor"]="LandGrey/pydictor"
repos["gitdorks_go"]="damit5/gitdorks_go"
repos["urless"]="xnl-h4ck3r/urless"
repos["smuggler"]="defparam/smuggler"
repos["Web-Cache-Vulnerability-Scanner"]="Hackmanit/Web-Cache-Vulnerability-Scanner"
repos["regulator"]="cramppet/regulator"
repos["ghauri"]="r0oth3x49/ghauri"
repos["gitleaks"]="gitleaks/gitleaks"
repos["trufflehog"]="trufflesecurity/trufflehog"
repos["dontgo403"]="devploit/dontgo403"
repos["SwaggerSpy"]="UndeadSec/SwaggerSpy"
repos["LeakSearch"]="JoelGMSec/LeakSearch"

function banner() {
	tput clear
	printf "\n${bgreen}"
	printf "  ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █   █████▒▄▄▄█████▓ █     █░\n"
	printf " ▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▓██   ▒ ▓  ██▒ ▓▒▓█░ █ ░█░\n"
	printf " ▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒▒████ ░ ▒ ▓██░ ▒░▒█░ █ ░█ \n"
	printf " ▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒░▓█▒  ░ ░ ▓██▓ ░ ░█░ █ ░█ \n"
	printf " ░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░░▒█░      ▒██▒ ░ ░░██▒██▓ \n"
	printf " ░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒  ▒ ░      ▒ ░░   ░ ▓░▒ ▒  \n"
	printf "   ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░ ░          ░      ▒ ░ ░  \n"
	printf "   ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░  ░ ░      ░        ░   ░  \n"
	printf "    ░        ░  ░░ ░          ░ ░           ░                      ░    \n"
	printf "                 ░                                                      \n"
	printf " ${reconftw_version}                                         by @six2dez\n"
}

# This function installs various tools and repositories as per the configuration.
function install_tools() {

	eval pip3 install -I -r requirements.txt $DEBUG_STD

	printf "${bblue} Running: Installing Golang tools (${#gotools[@]})${reset}\n\n"
	go env -w GO111MODULE=auto
	go_step=0
	for gotool in "${!gotools[@]}"; do
		go_step=$((go_step + 1))
		if [[ $upgrade_tools == "false" ]]; then
			res=$(command -v "$gotool") && {
				echo -e "[${yellow}SKIPPING${reset}] $gotool already installed in...${blue}${res}${reset}"
				continue
			}
		fi
		eval ${gotools[$gotool]} $DEBUG_STD
		exit_status=$?
		if [[ $exit_status -eq 0 ]]; then
			printf "${yellow} $gotool installed (${go_step}/${#gotools[@]})${reset}\n"
		else
			printf "${red} Unable to install $gotool, try manually (${go_step}/${#gotools[@]})${reset}\n"
			double_check=true
		fi
	done

	printf "${bblue}\n Running: Installing repositories (${#repos[@]})${reset}\n\n"

	# Repos with special configs
	eval git clone https://github.com/projectdiscovery/nuclei-templates ${NUCLEI_TEMPLATES_PATH} $DEBUG_STD
	eval git clone https://github.com/geeknik/the-nuclei-templates.git ${NUCLEI_TEMPLATES_PATH}/extra_templates $DEBUG_STD
	eval git clone https://github.com/projectdiscovery/fuzzing-templates ${tools}/fuzzing-templates $DEBUG_STD
	eval nuclei -update-templates update-template-dir ${NUCLEI_TEMPLATES_PATH} $DEBUG_STD
	cd "${dir}" || {
		echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}
	eval git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "${dir}"/sqlmap $DEBUG_STD
	eval git clone --depth 1 https://github.com/drwetter/testssl.sh.git "${dir}"/testssl.sh $DEBUG_STD
	eval $SUDO git clone https://gitlab.com/exploit-database/exploitdb /opt/exploitdb $DEBUG_STD

	# Standard repos installation
	repos_step=0
	for repo in "${!repos[@]}"; do
		repos_step=$((repos_step + 1))
		if [[ $upgrade_tools == "false" ]]; then
			unset is_installed
			unset is_need_dl
			[[ $repo == "Gf-Patterns" ]] && is_need_dl=1
			[[ $repo == "gf" ]] && is_need_dl=1
			res=$(command -v "$repo") && is_installed=1
			[[ -z $is_need_dl ]] && [[ -n $is_installed ]] && {
				# HERE: not installed yet.
				echo -e "[${yellow}SKIPPING${reset}] $repo already installed in...${blue}${res}${reset}"
				continue
			}
		fi
		eval git clone https://github.com/${repos[$repo]} "${dir}"/$repo $DEBUG_STD
        eval cd "${dir}"/$repo $DEBUG_STD
		eval git pull $DEBUG_STD
		exit_status=$?
		if [[ $exit_status -eq 0 ]]; then
			printf "${yellow} $repo installed (${repos_step}/${#repos[@]})${reset}\n"
		else
			printf "${red} Unable to install $repo, try manually (${repos_step}/${#repos[@]})${reset}\n"
			double_check=true
		fi
		if ([[ -z $is_installed ]] && [[ $upgrade_tools == "false" ]]) || [[ $upgrade_tools == "true" ]]; then
            if [[ -s "requirements.txt" ]]; then
                eval $SUDO pip3 install -r requirements.txt $DEBUG_STD
            fi
            if [[ -s "setup.py" ]]; then
                eval $SUDO pip3 install . $DEBUG_STD
            fi
            if [[ "massdns" == "$repo" ]]; then
                eval make $DEBUG_STD && strip -s bin/massdns && eval $SUDO cp bin/massdns /usr/local/bin/ $DEBUG_ERROR
            fi
            if [[ "gitleaks" == "$repo" ]]; then
                eval make build $DEBUG_STD && eval $SUDO cp ./gitleaks /usr/local/bin/ $DEBUG_ERROR
            fi
            if [[ "dontgo403" == "$repo" ]]; then
                eval go get $DEBUG_STD && eval go build $DEBUG_STD && eval chmod +x ./dontgo403 $DEBUG_STD
            fi
        fi
		if [[ "gf" == "$repo" ]]; then
            eval cp -r examples ~/.gf $DEBUG_ERROR
        elif [[ "Gf-Patterns" == "$repo" ]]; then
            eval mv ./*.json ~/.gf $DEBUG_ERROR
        fi
        cd "${dir}" || {
			echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"
			exit 1
		}
	done

	eval notify $DEBUG_STD
	eval subfinder $DEBUG_STD
	eval subfinder $DEBUG_STD
}

banner

show_help() {
    echo "Usage: $0 [OPTION]"
    echo "Run the script with specified options."
    echo ""
    echo "  -h, --help       Display this help and exit."
    echo "  --tools          Install the tools before running, useful for upgrading."
	echo "                                                                          "
    echo "  ****             Without any arguments, the script will update reconftw"
    echo "                   and install all dependencies and requirements."
    exit 0
}

printf "\n${bgreen} reconFTW installer/updater script ${reset}\n\n"

# Parse command-line arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        --tools)
            install_tools
            shift
            ;;
        *)
            echo "Error: Invalid argument '$1'"
            echo "Use -h or --help for usage information."
            exit 1
            ;;
    esac
done

printf "${yellow} This may take time. So, go grab a coffee! ${reset}\n\n"

if [[ $(id -u | grep -o '^0$') == "0" ]]; then
	SUDO=""
else
	if sudo -n false 2>/dev/null; then
		printf "${bred} Is strongly recommended to add your user to sudoers${reset}\n"
		printf "${bred} This will avoid prompts for sudo password in the middle of the installation${reset}\n"
		printf "${bred} And more important, in the middle of the scan (needed for nmap SYN scan)${reset}\n\n"
		printf "${bred} echo \"${USERNAME}  ALL=(ALL:ALL) NOPASSWD: ALL\" > /etc/sudoers.d/reconFTW${reset}\n\n"
	fi
	SUDO="sudo"
fi

install_apt() {
	eval $SUDO apt update -y $DEBUG_STD
	eval $SUDO DEBIAN_FRONTEND="noninteractive" apt install chromium-browser -y $DEBUG_STD
	eval $SUDO DEBIAN_FRONTEND="noninteractive" apt install chromium -y $DEBUG_STD
	eval $SUDO DEBIAN_FRONTEND="noninteractive" apt install python3 python3-pip python3-virtualenv build-essential gcc cmake ruby whois git curl libpcap-dev wget zip python3-dev pv dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq apt-transport-https lynx medusa xvfb libxml2-utils procps bsdmainutils libdata-hexdump-perl -y $DEBUG_STD
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	eval source "${HOME}/.cargo/env $DEBUG_STD"
	eval cargo install ripgen $DEBUG_STD
	eval source "${HOME}/.cargo/env $DEBUG_STD"
}

install_brew() {
	if brew --version &>/dev/null; then
		printf "${bgreen} brew is already installed ${reset}\n\n"
	else
		/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
	fi
	eval brew update -$DEBUG_STD
	eval brew install --cask chromium $DEBUG_STD
	eval brew install bash coreutils python massdns jq gcc cmake ruby git curl libpcap-dev wget zip python3-dev pv dnsutils whois libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq apt-transport-https lynx medusa xvfb libxml2-utils libdata-hexdump-perl gnu-getopt $DEBUG_STD
	export PATH="/opt/homebrew/opt/gnu-getopt/bin:$PATH"
	echo 'export PATH="/opt/homebrew/opt/gnu-getopt/bin:$PATH"' >>~/.zshrc
	brew install rustup
	rustup-init
	eval cargo install ripgen $DEBUG_STD
}

install_yum() {
	eval $SUDO yum groupinstall "Development Tools" -y $DEBUG_STD
	eval $SUDO yum install python3 python3-pip gcc cmake ruby git curl libpcap-dev wget whois zip python3-devel pv bind-utils libopenssl-devel libffi-devel libxml2-devel libxslt-devel zlib-devel nmap jq lynx medusa xorg-x11-server-xvfb -y $DEBUG_STD
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	eval source "${HOME}/.cargo/env $DEBUG_STD"
	eval cargo install ripgen $DEBUG_STD
}

install_pacman() {
	eval $SUDO pacman -Sy install python python-pip base-devel gcc cmake ruby git curl libpcap whois wget zip pv bind openssl libffi libxml2 libxslt zlib nmap jq lynx medusa xorg-server-xvfb -y $DEBUG_STD
	curl https://sh.rustup.rs -sSf | sh -s -- -y >/dev/null 2>&1
	eval source "${HOME}/.cargo/env $DEBUG_STD"
	eval cargo install ripgen $DEBUG_STD
}

eval git config --global --unset http.proxy $DEBUG_STD
eval git config --global --unset https.proxy $DEBUG_STD

printf "${bblue} Running: Looking for new reconFTW version${reset}\n\n"

timeout 10 git fetch
exit_status=$?
if [[ ${exit_status} -eq 0 ]]; then

	BRANCH=$(git rev-parse --abbrev-ref HEAD)
	HEADHASH=$(git rev-parse HEAD)
	UPSTREAMHASH=$(git rev-parse "${BRANCH}@{upstream}")

	if [[ $HEADHASH != "$UPSTREAMHASH" ]]; then
		printf "${yellow} There is a new version, updating...${reset}\n\n"
		if git status --porcelain | grep -q 'reconftw.cfg$'; then
			mv reconftw.cfg reconftw.cfg_bck
			printf "${yellow} reconftw.cfg has been backed up in reconftw.cfg_bck${reset}\n\n"
		fi
		eval git reset --hard $DEBUG_STD
		eval git pull $DEBUG_STD
		printf "${bgreen} Updated! Running new installer version...${reset}\n\n"
	else
		printf "${bgreen} reconFTW is already up to date!${reset}\n\n"
	fi
else
	printf "\n${bred} Unable to check updates ${reset}\n\n"
fi

printf "${bblue} Running: Installing system packages ${reset}\n\n"
if [[ -f /etc/debian_version ]]; then
    install_apt
elif [[ -f /etc/redhat-release ]]; then
    install_yum
elif [[ -f /etc/arch-release ]]; then
    install_pacman
elif [[ "True" == "$IS_MAC" ]]; then
    install_brew
elif [[ -f /etc/os-release ]]; then
	install_yum #/etc/os-release fall in yum for some RedHat and Amazon Linux instances
fi

# Installing latest Golang version
version=$(curl -L -s https://golang.org/VERSION?m=text | head -1)
[[ $version == g* ]] || version="go1.20.7"

printf "${bblue} Running: Installing/Updating Golang ${reset}\n\n"
if [[ $install_golang == "true" ]]; then
    if [[ $(eval type go $DEBUG_ERROR | grep -o 'go is') == "go is" ]] && [[ $version == $(go version | cut -d " " -f3) ]]; then
        printf "${bgreen} Golang is already installed and updated ${reset}\n\n"
    else
        eval $SUDO rm -rf /usr/local/go $DEBUG_STD
        if [[ "True" == "$IS_ARM" ]]; then
            if [[ "True" == "$RPI_3" ]]; then
                eval wget "https://dl.google.com/go/${version}.linux-armv6l.tar.gz" -O /tmp/${version}.linux-armv6l.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf /tmp/"${version}.linux-armv6l.tar.gz" $DEBUG_STD
            elif [[ "True" == "$RPI_4" ]]; then
                eval wget "https://dl.google.com/go/${version}.linux-arm64.tar.gz" -O /tmp/${version}.linux-arm64.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf /tmp/"${version}.linux-arm64.tar.gz" $DEBUG_STD
            fi
        elif [[ "True" == "$IS_MAC" ]]; then
            if [[ "True" == "$IS_ARM" ]]; then
                eval wget "https://dl.google.com/go/${version}.darwin-arm64.tar.gz" -O /tmp/${version}.darwin-arm64.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf /tmp/"${version}.darwin-arm64.tar.gz" $DEBUG_STD
            else
                eval wget "https://dl.google.com/go/${version}.darwin-amd64.tar.gz" -O /tmp/${version}.darwin-amd64.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf /tmp/"${version}.darwin-amd64.tar.gz" $DEBUG_STD
            fi
        else
            eval wget "https://dl.google.com/go/${version}.linux-amd64.tar.gz" -O /tmp/${version}.linux-amd64.tar.gz $DEBUG_STD
            eval $SUDO tar -C /usr/local -xzf /tmp/"${version}.linux-amd64.tar.gz" $DEBUG_STD
        fi
        eval $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/
        #rm -rf $version*
        export GOROOT=/usr/local/go
        export GOPATH=${HOME}/go
        export PATH=$GOPATH/bin:$GOROOT/bin:${HOME}/.local/bin:$PATH
        cat <<EOF >>~/"${profile_shell}"

# Golang vars
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.local/bin:\$PATH
EOF
	fi
else
	printf "${byellow} Golang will not be configured according to the user's prefereneces (reconftw.cfg install_golang var)${reset}\n"
fi

[ -n "$GOPATH" ] || {
	printf "${bred} GOPATH env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"
	exit 1
}
[ -n "$GOROOT" ] || {
	printf "${bred} GOROOT env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"
	exit 1
}

printf "${bblue} Running: Installing requirements ${reset}\n\n"

mkdir -p ~/.gf
mkdir -p $tools
mkdir -p ~/.config/notify/
mkdir -p ~/.config/amass/
mkdir -p ~/.config/nuclei/
touch "${dir}"/.github_tokens
touch "${dir}"/.gitlab_tokens

eval wget -N -c https://bootstrap.pypa.io/get-pip.py $DEBUG_STD && eval python3 get-pip.py $DEBUG_STD
eval rm -f get-pip.py $DEBUG_STD

install_tools

printf "${bblue}\n Running: Downloading required files ${reset}\n\n"
## Downloads
[[ ! -f ~/.config/amass/config.ini ]] && wget -q -O ~/.config/amass/config.ini https://raw.githubusercontent.com/owasp-amass/amass/master/examples/config.ini
[[ ! -f ~/.config/notify/provider-config.yaml ]] && wget -q -O ~/.config/notify/provider-config.yaml https://gist.githubusercontent.com/six2dez/23a996bca189a11e88251367e6583053/raw
#wget -q -O - https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json > ~/.gf/potential.json - Removed
wget -q -O - https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py >${tools}/getjswords.py
wget -q -O - https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt >${subs_wordlist_big}
wget -q -O - https://raw.githubusercontent.com/six2dez/resolvers_reconftw/main/resolvers_trusted.txt >${resolvers_trusted}
wget -q -O - https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt >${resolvers}
wget -q -O - https://gist.github.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw >${subs_wordlist}
wget -q -O - https://gist.github.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw >${tools}/permutations_list.txt
wget -q -O - https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt >${fuzz_wordlist}
wget -q -O - https://gist.githubusercontent.com/six2dez/a89a0c7861d49bb61a09822d272d5395/raw >${lfi_wordlist}
wget -q -O - https://gist.githubusercontent.com/six2dez/ab5277b11da7369bf4e9db72b49ad3c1/raw >${ssti_wordlist}
wget -q -O - https://gist.github.com/six2dez/d62ab8f8ffd28e1c206d401081d977ae/raw >${tools}/headers_inject.txt
wget -q -O - https://gist.githubusercontent.com/six2dez/6e2d9f4932fd38d84610eb851014b26e/raw >${tools}/axiom_config.sh
eval $SUDO chmod +x ${tools}/axiom_config.sh

## Last check
if [[ $double_check == "true" ]]; then
	printf "${bblue} Running: Double check for installed tools ${reset}\n\n"
	go_step=0
	for gotool in "${!gotools[@]}"; do
		go_step=$((go_step + 1))
		eval type -P $gotool $DEBUG_STD || { eval ${gotools[$gotool]} $DEBUG_STD; }
		exit_status=$?
	done
	repos_step=0
	for repo in "${!repos[@]}"; do
		repos_step=$((repos_step + 1))
		eval cd "${dir}"/$repo $DEBUG_STD || { eval git clone https://github.com/${repos[$repo]} "${dir}"/$repo $DEBUG_STD && cd "${dir}"/$repo || {
			echo "Failed to cd directory '$dir'"
			exit 1
		}; }
		eval git pull $DEBUG_STD
		exit_status=$?
        if [[ -s "setup.py" ]]; then
            eval $SUDO python3 setup.py install $DEBUG_STD
        fi
        if [[ "massdns" == "$repo" ]]; then
            eval make $DEBUG_STD && strip -s bin/massdns && eval $SUDO cp bin/massdns /usr/local/bin/ $DEBUG_ERROR
        elif [[ "gf" == "$repo" ]]; then
            eval cp -r examples ~/.gf $DEBUG_ERROR
        elif [[ "Gf-Patterns" == "$repo" ]]; then
            eval mv ./*.json ~/.gf $DEBUG_ERROR
        elif [[ "trufflehog" == "$repo" ]]; then
            eval go install $DEBUG_STD
        fi
        cd "${dir}" || {
			echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"
			exit 1
		}
	done
fi

printf "${bblue} Running: Performing last configurations ${reset}\n\n"
## Last steps
if [[ $generate_resolvers == true ]]; then
    if [[ ! -s $resolvers ]] || [[ $(find "$resolvers" -mtime +1 -print) ]]; then
        printf "${reset}\n\nChecking resolvers lists...\n Accurate resolvers are the key to great results\n This may take around 10 minutes if it's not updated\n\n"
        eval rm -f $resolvers 2>>"${LOGFILE}"
        dnsvalidator -tL https://public-dns.info/nameservers.txt -threads $DNSVALIDATOR_THREADS -o $resolvers &>/dev/null
        dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads $DNSVALIDATOR_THREADS -o tmp_resolvers &>/dev/null
        [[ -s "tmp_resolvers" ]] && cat tmp_resolvers | anew -q $resolvers
        [[ -s "tmp_resolvers" ]] && rm -f tmp_resolvers &>/dev/null
        [[ ! -s $resolvers ]] && wget -q -O - https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt >${resolvers}
        [[ ! -s $resolvers_trusted ]] && wget -q -O - https://raw.githubusercontent.com/six2dez/resolvers_reconftw/main/resolvers_trusted.txt >${resolvers_trusted}
		printf "${yellow} Resolvers updated\n ${reset}\n\n"
	fi
	generate_resolvers=false
else
	[[ ! -s $resolvers ]] || if [[ $(find "$resolvers" -mtime +1 -print) ]]; then
		${reset}"\n\nChecking resolvers lists...\n Accurate resolvers are the key to great results\n Downloading new resolvers ${reset}\n\n"
		wget -q -O - https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt >${resolvers}
		wget -q -O - https://raw.githubusercontent.com/six2dez/resolvers_reconftw/main/resolvers_trusted.txt >${resolvers_trusted}
		printf "${yellow} Resolvers updated\n ${reset}\n\n"
	fi
fi

## Stripping all Go binaries
eval strip -s "$HOME"/go/bin/* $DEBUG_STD

eval $SUDO cp "$HOME"/go/bin/* /usr/local/bin/ $DEBUG_STD


printf "${yellow} Remember set your api keys:\n - amass (~/.config/amass/config.ini)\n - subfinder (~/.config/subfinder/provider-config.yaml)\n - GitLab (~/Tools/.gitlab_tokens)\n - SSRF Server (COLLAB_SERVER in reconftw.cfg or env var) \n - Blind XSS Server (XSS_SERVER in reconftw.cfg or env var) \n - notify (~/.config/notify/provider-config.yaml) \n - WHOISXML API (WHOISXML_API in reconftw.cfg or env var)\n\n${reset}"
printf "${bgreen} Finished!${reset}\n\n"
printf "\n\n${bgreen}#######################################################################${reset}\n"
