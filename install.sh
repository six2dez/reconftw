#!/usr/bin/env bash

. ./reconftw.cfg

dir=${tools}
double_check=false

# ARM Detection
if [ -s "/proc/cpuinfo" ]; then
    if grep -q "Raspberry Pi 3"  /proc/cpuinfo; then
        IS_ARM="True"
        RPI_3="True"
        RPI_4="False"
    elif grep -q "Raspberry Pi 4"  /proc/cpuinfo; then
        IS_ARM="True"
        RPI_4="True"
        RPI_3="False"
    else
        IS_ARM="False"
    fi
elif grep -iq "arm" <<< "$(/usr/bin/arch)";then
    IS_ARM="True"
else
    IS_ARM="False"
fi

#Mac Osx Detecting
if [[ "$OSTYPE" == "darwin"* ]]; then
    IS_MAC="True"
else
    IS_MAC="False"
fi

# Check Bash version
BASH_VERSION=$(bash --version | awk 'NR==1{print $4}' | cut -d'.' -f1)
if [ ${BASH_VERSION} -lt 4 ]; then
     printf "${bred} Your Bash version is lower than 4, please update${reset}\n"
    if [ "True" = "$IS_MAC" ]; then
        printf "${yellow} For MacOS run 'brew install bash' and rerun installer in a new terminal${reset}\n\n"
        exit 1;
    fi
fi

declare -A gotools
gotools["gf"]="go install -v github.com/tomnomnom/gf@latest"
gotools["qsreplace"]="go install -v github.com/tomnomnom/qsreplace@latest"
gotools["Amass"]="go install -v github.com/OWASP/Amass/v3/...@master"
gotools["ffuf"]="go install -v github.com/ffuf/ffuf@latest"
gotools["github-subdomains"]="go install -v github.com/gwen001/github-subdomains@latest"
gotools["waybackurls"]="go install -v github.com/tomnomnom/waybackurls@latest"
gotools["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
gotools["anew"]="go install -v github.com/tomnomnom/anew@latest"
gotools["notify"]="go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
gotools["unfurl"]="go install -v github.com/tomnomnom/unfurl@latest"
gotools["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
gotools["github-endpoints"]="go install -v github.com/gwen001/github-endpoints@latest"
gotools["dnsx"]="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
gotools["gau"]="go install -v github.com/lc/gau/v2/cmd/gau@latest"
gotools["subjs"]="go install -v github.com/lc/subjs@latest"
gotools["Gxss"]="go install -v github.com/KathanP19/Gxss@latest"
gotools["gospider"]="go install -v github.com/jaeles-project/gospider@latest"
gotools["crlfuzz"]="go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
gotools["dalfox"]="go install -v github.com/hahwul/dalfox/v2@latest"
gotools["puredns"]="go install -v github.com/d3mondev/puredns/v2@latest"
gotools["interactsh-client"]="go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
gotools["analyticsrelationships"]="go install -v github.com/Josue87/analyticsrelationships@latest"
gotools["gotator"]="go install -v github.com/Josue87/gotator@latest"
gotools["roboxtractor"]="go install -v github.com/Josue87/roboxtractor@latest"
gotools["mapcidr"]="go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
gotools["ipcdn"]="go install -v github.com/six2dez/ipcdn@latest"
gotools["dnstake"]="go install -v github.com/pwnesia/dnstake/cmd/dnstake@latest"
gotools["gowitness"]="go install -v github.com/sensepost/gowitness@latest"
gotools["cero"]="go install -v github.com/glebarez/cero@latest"
gotools["gitdorks_go"]="go install -v github.com/damit5/gitdorks_go@latest"

declare -A repos
repos["degoogle_hunter"]="six2dez/degoogle_hunter"
repos["pwndb"]="davidtavarez/pwndb"
repos["dnsvalidator"]="vortexau/dnsvalidator"
repos["theHarvester"]="laramies/theHarvester"
repos["brutespray"]="x90skysn3k/brutespray"
repos["wafw00f"]="EnableSecurity/wafw00f"
repos["gf"]="tomnomnom/gf"
repos["Gf-Patterns"]="1ndianl33t/Gf-Patterns"
repos["ctfr"]="UnaPibaGeek/ctfr"
repos["LinkFinder"]="dark-warlord14/LinkFinder"
repos["Corsy"]="s0md3v/Corsy"
repos["CMSeeK"]="Tuhinshubhra/CMSeeK"
repos["fav-up"]="pielco11/fav-up"
repos["Interlace"]="codingo/Interlace"
repos["massdns"]="blechschmidt/massdns"
repos["Oralyzer"]="r0075h3ll/Oralyzer"
repos["testssl"]="drwetter/testssl.sh"
repos["commix"]="commixproject/commix"
repos["JSA"]="w9w/JSA"
repos["cloud_enum"]="initstring/cloud_enum"
repos["ultimate-nmap-parser"]="shifty0g/ultimate-nmap-parser"
repos["pydictor"]="LandGrey/pydictor"
repos["gitdorks_go"]="damit5/gitdorks_go"

printf "\n\n${bgreen}#######################################################################${reset}\n"
printf "${bgreen} reconFTW installer/updater script ${reset}\n\n"
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

install_apt(){
    eval $SUDO apt update -y $DEBUG_STD
    eval $SUDO DEBIAN_FRONTEND="noninteractive" apt install chromium-browser -y $DEBUG_STD
    eval $SUDO DEBIAN_FRONTEND="noninteractive" apt install chromium -y $DEBUG_STD
    eval $SUDO DEBIAN_FRONTEND="noninteractive" apt install python3 python3-pip build-essential gcc cmake ruby git curl libpcap-dev wget zip python3-dev pv dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq apt-transport-https lynx tor medusa xvfb libxml2-utils procps bsdmainutils libdata-hexdump-perl -y $DEBUG_STD
    eval $SUDO systemctl enable tor $DEBUG_STD
    eval wget https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_amd64.deb $DEBUG_STD
    eval $SUDO dpkg -i nrich_latest_amd64.deb $DEBUG_STD
    eval $SUDO rm -rf nrich_latest_amd64.deb  $DEBUG_STD
}

install_brew(){
    if brew --version &>/dev/null; then
	printf "${bgreen} brew is already installed ${reset}\n\n"
    else
	/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    eval brew update -$DEBUG_STD
    eval brew install --cask chromium $DEBUG_STD
    eval brew install bash coreutils python massdns jq gcc cmake ruby git curl libpcap-dev wget zip python3-dev pv dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq apt-transport-https lynx tor medusa xvfb libxml2-utils libdata-hexdump-perl $DEBUG_STD
    eval brew services start tor $DEBUG_STD
    eval wget  https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_darwin $DEBUG_STD
    eval $SUDO sudo installer -pkg nrich_latest_darwin -target / $DEBUG_STD
}

install_yum(){
    eval $SUDO yum groupinstall "Development Tools" -y $DEBUG_STD
    eval $SUDO yum install python3 python3-pip gcc cmake ruby git curl libpcap-dev wget zip python3-devel pv bind-utils libopenssl-devel libffi-devel libxml2-devel libxslt-devel zlib-devel nmap jq lynx tor medusa xorg-x11-server-xvfb -y $DEBUG_STD
    eval wget https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_amd64.rpm $DEBUG_STD
    eval $SUDO yum localinstall nrich_latest_amd64.rpm -y $DEBUG_STD
}

install_pacman(){
    eval $SUDO pacman -Sy install python python-pip base-devel gcc cmake ruby git curl libpcap wget zip pv bind openssl libffi libxml2 libxslt zlib nmap jq lynx tor medusa xorg-server-xvfb -y $DEBUG_STD
    eval $SUDO systemctl enable --now tor.service $DEBUG_STD
}

eval git config --global --unset http.proxy $DEBUG_STD
eval git config --global --unset https.proxy $DEBUG_STD

printf "${bblue} Running: Looking for new reconFTW version${reset}\n\n"

eval git fetch $DEBUG_STD
BRANCH=$(git rev-parse --abbrev-ref HEAD)
HEADHASH=$(git rev-parse HEAD)
UPSTREAMHASH=$(git rev-parse ${BRANCH}@{upstream})

if [ "$HEADHASH" != "$UPSTREAMHASH" ]
then
    printf "${yellow} There is a new version, updating...${reset}\n\n"
    if [ -n "$(git status --porcelain | egrep 'reconftw.cfg$')" ]; then
        mv reconftw.cfg reconftw.cfg_bck
        printf "${yellow} reconftw.cfg has been backed up in reconftw.cfg_bck${reset}\n\n"
    fi
    eval git reset --hard $DEBUG_STD
    eval git pull $DEBUG_STD
    printf "${bgreen} Updated! Running new installer version...${reset}\n\n"
else
    printf "${bgreen} reconFTW is already up to date!${reset}\n\n"
fi

printf "${bblue} Running: Installing system packages ${reset}\n\n"
if [ -f /etc/debian_version ]; then install_apt;
elif [ -f /etc/redhat-release ]; then install_yum;
elif [ -f /etc/arch-release ]; then install_pacman;
elif [ "True" = "$IS_MAC" ]; then install_brew;
elif [ -f /etc/os-release ]; then install_yum;  #/etc/os-release fall in yum for some RedHat and Amazon Linux instances
fi

# Installing latest Golang version
version=$(curl -L -s https://golang.org/VERSION?m=text)
#version="go1.17.6"
printf "${bblue} Running: Installing/Updating Golang ${reset}\n\n"
if [[ $(eval type go $DEBUG_ERROR | grep -o 'go is') == "go is" ]] && [ "$version" = $(go version | cut -d " " -f3) ]
    then
        printf "${bgreen} Golang is already installed and updated ${reset}\n\n"
    else
        eval $SUDO rm -rf /usr/local/go $DEBUG_STD
        if [ "True" = "$IS_ARM" ]; then
            if [ "True" = "$RPI_3" ]; then
                eval wget https://dl.google.com/go/${version}.linux-armv6l.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf ${version}.linux-armv6l.tar.gz $DEBUG_STD
            elif [ "True" = "$RPI_4" ]; then
                eval wget https://dl.google.com/go/${version}.linux-arm64.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf ${version}.linux-arm64.tar.gz $DEBUG_STD
            fi
        elif [ "True" = "$IS_MAC" ]; then
            if [ "True" = "$IS_ARM" ]; then
                eval wget https://dl.google.com/go/${version}.darwin-arm64.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf ${version}.darwin-arm64.tar.gz $DEBUG_STD
            else
                eval wget https://dl.google.com/go/${version}.darwin-amd64.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf ${version}.darwin-amd64.tar.gz $DEBUG_STD
            fi
        else
            eval wget https://dl.google.com/go/${version}.linux-amd64.tar.gz $DEBUG_STD
            eval $SUDO tar -C /usr/local -xzf ${version}.linux-amd64.tar.gz $DEBUG_STD
        fi
        eval $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/
        rm -rf $version*
        export GOROOT=/usr/local/go
        export GOPATH=$HOME/go
        export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH
cat << EOF >> ~/${profile_shell}

# Golang vars
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.local/bin:\$PATH
EOF

fi

[ -n "$GOPATH" ] || { printf "${bred} GOPATH env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }
[ -n "$GOROOT" ] || { printf "${bred} GOROOT env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }

printf "${bblue} Running: Installing requirements ${reset}\n\n"

mkdir -p ~/.gf
mkdir -p $tools
mkdir -p ~/.config/notify/
mkdir -p ~/.config/amass/
mkdir -p ~/.config/nuclei/
touch $dir/.github_tokens

eval wget -N -c https://bootstrap.pypa.io/get-pip.py $DEBUG_STD && eval python3 get-pip.py $DEBUG_STD
eval rm -f get-pip.py $DEBUG_STD
#eval ln -s /usr/local/bin/pip3 /usr/local/bin/pip3 $DEBUG_STD
eval pip3 install -I -r requirements.txt $DEBUG_STD

printf "${bblue} Running: Installing Golang tools (${#gotools[@]})${reset}\n\n"
go env -w GO111MODULE=auto
go_step=0
for gotool in "${!gotools[@]}"; do
    go_step=$((go_step + 1))
    eval ${gotools[$gotool]} $DEBUG_STD
    exit_status=$?
    if [ $exit_status -eq 0 ]
    then
        printf "${yellow} $gotool installed (${go_step}/${#gotools[@]})${reset}\n"
    else
        printf "${red} Unable to install $gotool, try manually (${go_step}/${#gotools[@]})${reset}\n"
        double_check=true
    fi
done

printf "${bblue}\n Running: Installing repositories (${#repos[@]})${reset}\n\n"

# Repos with special configs
eval git clone https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates $DEBUG_STD
eval git clone https://github.com/geeknik/the-nuclei-templates.git ~/nuclei-templates/extra_templates $DEBUG_STD
eval wget -nc -O ~/nuclei-templates/ssrf_nagli.yaml https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml $DEBUG_STD
eval wget -nc -O ~/nuclei-templates/sap-redirect_nagli.yaml https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/sap-redirect.yaml $DEBUG_STD
eval nuclei -update-templates $DEBUG_STD
cd ~/nuclei-templates/extra_templates && eval git pull $DEBUG_STD
cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
eval git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git $dir/sqlmap $DEBUG_STD
eval git clone --depth 1 https://github.com/drwetter/testssl.sh.git $dir/testssl.sh $DEBUG_STD
eval $SUDO git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb $DEBUG_STD
eval $SUDO ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit $DEBUG_STD

# Standard repos installation
repos_step=0
for repo in "${!repos[@]}"; do
    repos_step=$((repos_step + 1))
    eval git clone https://github.com/${repos[$repo]} $dir/$repo $DEBUG_STD
    eval cd $dir/$repo $DEBUG_STD
    eval git pull $DEBUG_STD
    exit_status=$?
    if [ $exit_status -eq 0 ]
    then
        printf "${yellow} $repo installed (${repos_step}/${#repos[@]})${reset}\n"
    else
        printf "${red} Unable to install $repo, try manually (${repos_step}/${#repos[@]})${reset}\n"
        double_check=true
    fi
    if [ -s "setup.py" ]; then
        eval $SUDO pip3 install . $DEBUG_STD
    fi
    if [ -s "requirements.txt" ]; then
        eval $SUDO pip3 install -r requirements.txt $DEBUG_STD
        # eval $SUDO python3 setup.py install --record files.txt $DEBUG_STD
        # [ -s "files.txt" ] && eval xargs rm -rf < files.txt $DEBUG_STD
        # eval $SUDO pip3 install . $DEBUG_STD
    fi
    if [ "massdns" = "$repo" ]; then
            eval make $DEBUG_STD && strip -s bin/massdns && eval $SUDO cp bin/massdns /usr/local/bin/ $DEBUG_ERROR
    elif [ "gf" = "$repo" ]; then
            eval cp -r examples ~/.gf $DEBUG_ERROR
    elif [ "Gf-Patterns" = "$repo" ]; then
            eval mv *.json ~/.gf $DEBUG_ERROR
    fi
    cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
done

if [ "True" = "$IS_ARM" ]; then
    if [ "True" = "$RPI_3" ]; then
        eval wget -N -c https://github.com/Edu4rdSHL/unimap/releases/latest/download/unimap-armv7 $DEBUG_STD
        eval wget -N -c https://github.com/dwisiswant0/ppfuzz/releases/download/v1.0.1/ppfuzz-v1.0.1-armv7-unknown-linux-gnueabihf.tar.gz $DEBUG_STD
        eval $SUDO tar -C /usr/local/bin/ -xzf ppfuzz-v1.0.1-armv7-unknown-linux-gnueabihf.tar.gz  $DEBUG_STD
        eval $SUDO rm -rf ppfuzz-v1.0.1-armv7-unknown-linux-gnueabihf.tar.gz  $DEBUG_STD
        eval $SUDO mv unimap-armv7 /usr/local/bin/unimap
    elif [ "True" = "$RPI_4" ] || [ "True" = "$IS_MAC" ]; then
        eval wget -N -c https://github.com/Edu4rdSHL/unimap/releases/latest/download/unimap-aarch64 $DEBUG_STD
        eval wget -N -c https://github.com/dwisiswant0/ppfuzz/releases/download/v1.0.1/ppfuzz-v1.0.1-aarch64-unknown-linux-gnueabihf.tar.gz $DEBUG_STD
        eval $SUDO tar -C /usr/local/bin/ -xzf ppfuzz-v1.0.1-aarch64-unknown-linux-gnueabihf.tar.gz  $DEBUG_STD
        eval $SUDO rm -rf ppfuzz-v1.0.1-aarch64-unknown-linux-gnueabihf.tar.gz  $DEBUG_STD
        eval $SUDO mv unimap-aarch64 /usr/local/bin/unimap
    fi
elif [ "True" = "$IS_MAC" ]; then
    eval wget -N -c https://github.com/Edu4rdSHL/unimap/releases/latest/download/unimap-osx $DEBUG_STD
    eval wget -N -c https://github.com/dwisiswant0/ppfuzz/releases/download/v1.0.1/ppfuzz-v1.0.1-x86_64-apple-darwin.tar.gz $DEBUG_STD
    eval $SUDO tar -C /usr/local/bin/ -xzf ppfuzz-v1.0.1-x86_64-apple-darwin.tar.gz  $DEBUG_STD
    eval $SUDO rm -rf ppfuzz-v1.0.1-x86_64-apple-darwin.tar.gz  $DEBUG_STD
    eval $SUDO mv unimap-osx /usr/local/bin/unimap
else
    eval wget -N -c https://github.com/Edu4rdSHL/unimap/releases/download/0.4.0/unimap-linux $DEBUG_STD
    eval wget -N -c https://github.com/dwisiswant0/ppfuzz/releases/download/v1.0.1/ppfuzz-v1.0.1-x86_64-unknown-linux-musl.tar.gz $DEBUG_STD
    eval $SUDO tar -C /usr/local/bin/ -xzf ppfuzz-v1.0.1-x86_64-unknown-linux-musl.tar.gz  $DEBUG_STD
    eval $SUDO rm -rf ppfuzz-v1.0.1-x86_64-unknown-linux-musl.tar.gz  $DEBUG_STD
    eval $SUDO mv unimap-linux /usr/local/bin/unimap
fi
eval $SUDO chmod 755 /usr/local/bin/unimap
eval $SUDO strip -s /usr/local/bin/unimap $DEBUG_STD
eval $SUDO chmod 755 /usr/local/bin/ppfuzz
eval $SUDO strip -s /usr/local/bin/ppfuzz $DEBUG_STD
eval $SUDO chmod +x $tools/degoogle_hunter/degoogle_hunter.sh
eval notify $DEBUG_STD

printf "${bblue}\n Running: Downloading required files ${reset}\n\n"
## Downloads
eval wget -nc -O ~/.config/amass/config.ini https://raw.githubusercontent.com/OWASP/Amass/master/examples/config.ini $DEBUG_STD
eval wget -nc -O ~/.gf/potential.json https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json $DEBUG_STD
eval wget -nc -O ~/.config/notify/provider-config.yaml https://gist.githubusercontent.com/six2dez/23a996bca189a11e88251367e6583053/raw $DEBUG_STD
eval wget -nc -O getjswords.py https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py $DEBUG_STD
eval wget -nc -O subdomains_big.txt https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt $DEBUG_STD
eval wget -O resolvers_trusted.txt https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt $DEBUG_STD
eval wget -O subdomains.txt https://gist.github.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw $DEBUG_STD
eval wget -O permutations_list.txt https://gist.github.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw $DEBUG_STD
eval wget -nc -O fuzz_wordlist.txt https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt $DEBUG_STD
eval wget -O lfi_wordlist.txt https://gist.githubusercontent.com/six2dez/a89a0c7861d49bb61a09822d272d5395/raw $DEBUG_STD
eval wget -O ssti_wordlist.txt https://gist.githubusercontent.com/six2dez/ab5277b11da7369bf4e9db72b49ad3c1/raw $DEBUG_STD
eval wget -O headers_inject.txt https://gist.github.com/six2dez/d62ab8f8ffd28e1c206d401081d977ae/raw $DEBUG_STD
eval wget -O axiom_config.sh https://gist.githubusercontent.com/six2dez/6e2d9f4932fd38d84610eb851014b26e/raw $DEBUG_STD
eval wget -O ~/nuclei-templates/extra_templates/ssrf.yaml https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml $DEBUG_STD
eval wget -O ~/nuclei-templates/extra_templates/sap-redirect.yaml https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/sap-redirect.yaml $DEBUG_STD
eval $SUDO chmod +x $tools/axiom_config.sh

## Last check
if [ "$double_check" = "true" ]; then
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
        eval cd $dir/$repo $DEBUG_STD || { eval git clone https://github.com/${repos[$repo]} $dir/$repo $DEBUG_STD && cd $dir/$repo; }
        eval git pull $DEBUG_STD
        exit_status=$?
        if [ -s "setup.py" ]; then
            eval $SUDO python3 setup.py install $DEBUG_STD
        fi
        if [ "massdns" = "$repo" ]; then
                eval make $DEBUG_STD && strip -s bin/massdns && eval $SUDO cp bin/massdns /usr/local/bin/ $DEBUG_ERROR
        elif [ "gf" = "$repo" ]; then
                eval cp -r examples ~/.gf $DEBUG_ERROR
        elif [ "Gf-Patterns" = "$repo" ]; then
                eval mv *.json ~/.gf $DEBUG_ERROR
        fi
        cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
    done
fi

# BBRF Setup
if [ ! -d "$HOME/.bbrf/" ] ; then
    mkdir $HOME/.bbrf/
fi
if  [ -d "$HOME/.bbrf/" ] && [ ! -s "$HOME/.bbrf/config.json" ]; then
    cat > $HOME/.bbrf/config.json << EOF
{
    "username": "$BBRF_USERNAME",
    "password": "$BBRF_PASSWORD",
    "couchdb": "https://$BBRF_SERVER/bbrf",
    "slack_token": "<a slack token to receive notifications>",
    "discord_webhook": "<your discord webhook if you want one>",
    "ignore_ssl_errors": false
}
EOF
fi

printf "${bblue} Running: Performing last configurations ${reset}\n\n"
## Last steps
if [ "$generate_resolvers" = true ]; then
	if [ ! -s "$resolvers" ] || [[ $(find "$resolvers" -mtime +1 -print) ]] ; then
		 ${reset}\n\n"Checking resolvers lists...\n Accurate resolvers are the key to great results\n This may take around 10 minutes if it's not updated ${reset}\n\n"
		eval rm -f $resolvers 2>>"$LOGFILE"
		dnsvalidator -tL https://public-dns.info/nameservers.txt -threads $DNSVALIDATOR_THREADS -o $resolvers &>/dev/null
		dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads $DNSVALIDATOR_THREADS -o tmp_resolvers &>/dev/null
		[ -s "tmp_resolvers" ] && cat tmp_resolvers | anew -q $resolvers
		[ -s "tmp_resolvers" ] && rm -f tmp_resolvers &>/dev/null
		[ ! -s "$resolvers" ] && wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O $resolvers &>/dev/null
        [ ! -s "$resolvers_trusted" ] && wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers_trusted.txt -O $resolvers_trusted &>/dev/null
		printf "${yellow} Resolvers updated\n ${reset}\n\n"
	fi
	generate_resolvers=false
else
	[ ! -s "$resolvers" ] || if [[ $(find "$resolvers" -mtime +1 -print) ]] ; then
		 ${reset}"\n\nChecking resolvers lists...\n Accurate resolvers are the key to great results\n Downloading new resolvers ${reset}\n\n"
		wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O $resolvers &>/dev/null
        wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers_trusted.txt -O $resolvers_trusted &>/dev/null
		printf "${yellow} Resolvers updated\n ${reset}\n\n"
	fi
fi

eval h8mail -g $DEBUG_STD

## Stripping all Go binaries
eval strip -s $HOME/go/bin/* $DEBUG_STD

eval $SUDO cp $HOME/go/bin/* /usr/local/bin/ $DEBUG_STD

printf "${yellow} Remember set your api keys:\n - amass (~/.config/amass/config.ini)\n - GitHub (~/Tools/.github_tokens)\n - SSRF Server (COLLAB_SERVER in reconftw.cfg or env var) \n - Blind XSS Server (XSS_SERVER in reconftw.cfg or env var) \n - notify (~/.config/notify/provider-config.yaml) \n - theHarvester (~/Tools/theHarvester/api-keys.yaml or /etc/theHarvester/api-keys.yaml)\n - H8mail (~/Tools/h8mail_config.ini)\n - WHOISXML API (WHOISXML_API in reconftw.cfg or env var)\n\n\n${reset}"
printf "${bgreen} Finished!${reset}\n\n"
printf "\n\n${bgreen}#######################################################################${reset}\n"
