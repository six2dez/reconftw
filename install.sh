#!/bin/bash

. ./reconftw.cfg

declare -A gotools
gotools["gf"]="go get -v github.com/tomnomnom/gf"
gotools["qsreplace"]="go get -v github.com/tomnomnom/qsreplace"
gotools["Amass"]="GO111MODULE=on go get -v github.com/OWASP/Amass/v3/..."
gotools["ffuf"]="go get -u github.com/ffuf/ffuf"
gotools["assetfinder"]="go get -v github.com/tomnomnom/assetfinder"
gotools["github-subdomains"]="go get -u github.com/gwen001/github-subdomains"
gotools["cf-check"]="go get -v github.com/dwisiswant0/cf-check"
gotools["waybackurls"]="go get -v github.com/tomnomnom/hacks/waybackurls"
gotools["nuclei"]="GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
gotools["anew"]="go get -v github.com/tomnomnom/anew"
gotools["notify"]="GO111MODULE=on go get -v github.com/projectdiscovery/notify/cmd/notify"
gotools["mildew"]="go get -u github.com/daehee/mildew/cmd/mildew"
gotools["dirdar"]="go get -u github.com/m4dm0e/dirdar"
gotools["unfurl"]="go get -v github.com/tomnomnom/unfurl"
gotools["httpx"]="GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx"
gotools["github-endpoints"]="go get -u github.com/gwen001/github-endpoints"
gotools["dnsx"]="GO111MODULE=on go get -v github.com/projectdiscovery/dnsx/cmd/dnsx"
gotools["subfinder"]="GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
gotools["gau"]="go get -v github.com/lc/gau"
gotools["subjs"]="GO111MODULE=on go get -u -v github.com/lc/subjs"
gotools["Gxss"]="go get -v github.com/KathanP19/Gxss"
gotools["shuffledns"]="GO111MODULE=on go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns"
gotools["gospider"]="go get -u github.com/jaeles-project/gospider"
gotools["crobat"]="go get -v github.com/cgboal/sonarsearch/crobat"
gotools["crlfuzz"]="GO111MODULE=on go get -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz"
gotools["gowitness"]="go get -u github.com/sensepost/gowitness"

declare -A repos
repos["degoogle_hunter"]="six2dez/degoogle_hunter"
repos["pwndb"]="davidtavarez/pwndb"
repos["dnsvalidator"]="vortexau/dnsvalidator"
repos["dnsrecon"]="darkoperator/dnsrecon"
repos["theHarvester"]="laramies/theHarvester"
repos["brutespray"]="x90skysn3k/brutespray"
repos["wafw00f"]="EnableSecurity/wafw00f"
repos["Arjun"]="s0md3v/Arjun"
repos["gf"]="tomnomnom/gf"
repos["Gf-Patterns"]="1ndianl33t/Gf-Patterns"
repos["XSStrike"]="s0md3v/XSStrike"
repos["github-search"]="gwen001/github-search"
repos["crtfinder"]="eslam3kl/crtfinder"
repos["LinkFinder"]="dark-warlord14/LinkFinder"
repos["dnsgen"]="ProjectAnte/dnsgen"
repos["ParamSpider"]="devanshbatham/ParamSpider"
repos["Corsy"]="s0md3v/Corsy"
repos["CMSeeK"]="Tuhinshubhra/CMSeeK"
repos["fav-up"]="pielco11/fav-up"
repos["Interlace"]="codingo/Interlace"
repos["massdns"]="blechschmidt/massdns"
repos["OpenRedireX"]="devanshbatham/OpenRedireX"
repos["GitDorker"]="obheda12/GitDorker"
repos["testssl"]="drwetter/testssl.sh"
repos["S3Scanner"]="sa7mon/S3Scanner"

dir=${tools}

if grep -q "ARMv"  /proc/cpuinfo
then
   IS_ARM="True";
else
   IS_ARM="False";
fi

if [[ $(id -u | grep -o '^0$') == "0" ]]; then
    SUDO=" "
else
    SUDO="sudo"
fi

printf "\n\n${bgreen}#######################################################################\n"
printf "${bgreen} reconFTW installer/updater script ${reset}\n\n"
printf "${yellow} This may take time.So, go grab a coffee ! ${reset}\n\n"
install_apt(){
    eval $SUDO apt install chromium-browser -y $DEBUG_STD
    eval $SUDO apt install chromium -y $DEBUG_STD
    eval $SUDO apt install python3 python3-pip ruby git curl libpcap-dev wget python-dev python3-dev dnsutils build-essential xvfb libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq python3-shodan apt-transport-https lynx tor -y $DEBUG_STD
    eval $SUDO systemctl enable tor $DEBUG_STD
}

install_yum(){
    eval $SUDO yum install python3 python3-pip ruby git curl libpcap-devel chromium wget openssl-devel bind-utils python3-devel lynx libxslt-devel libffi-devel xorg-x11-server-Xvfb libxml2-devel nmap zlib-devel jq python-shodan -y $DEBUG_STD
}

install_pacman(){
    eval $SUDO pacman -Sy install python python-pip dnsutils ruby curl git libpcap nmap chromium wget jq xorg-server-xvfb tor lynx -y $DEBUG_STD
    eval $SUDO systemctl enable --now tor.service $DEBUG_STD
}

printf "${bblue} Running: Installing system packages ${reset}\n\n"
if [ -f /etc/debian_version ]; then install_apt;
elif [ -f /etc/redhat-release ]; then install_yum;
elif [ -f /etc/arch-release ]; then install_pacman;
elif [ -f /etc/os-release ]; then install_yum;  #/etc/os-release fall in yum for some RedHat and Amazon Linux instances
fi

printf "${bblue} Running: Looking for new reconFTW version${reset}\n\n"
eval git fetch $DEBUG_STD
if [ -n "$(git status --porcelain | egrep -v '^\?\?')" ]; then
    printf "${yellow} There is a new version, updating...${reset}\n\n"
    if [ -n "$(git status --porcelain | egrep 'reconftw.cfg$')" ]; then
        mv reconftw.cfg reconftw.cfg_bck
        printf "${yellow} reconftw.cfg has been backed up in reconftw.cfg_bck${reset}\n\n"
    fi
    eval git reset --hard $DEBUG_STD
    eval git pull $DEBUG_STD
    printf "${bgreen} Updated! Running new installer version...${reset}\n\n"
    exec "$0"
    exit 1
fi

# Installing latest Golang version
#version=$(curl -s https://golang.org/VERSION?m=text)
version=go1.15.10
eval type -P go $DEBUG_STD || { golang_installed=false; }
printf "${bblue} Running: Installing/Updating Golang ${reset}\n\n"
if [[ $(eval type go $DEBUG_ERROR | grep -o 'go is') == "go is" ]] && [ "$version" = $(go version | cut -d " " -f3) ]
    then
        printf "${bgreen} Golang is already installed and updated ${reset}\n\n"
    else
        eval $SUDO rm -rf /usr/local/go $DEBUG_STD
        if [ "True" = "$IS_ARM" ]; then
            eval wget https://dl.google.com/go/${version}.linux-armv6l.tar.gz $DEBUG_STD
            eval $SUDO tar -C /usr/local -xzf ${version}.linux-armv6l.tar.gz $DEBUG_STD
        else
            eval wget https://dl.google.com/go/${version}.linux-amd64.tar.gz $DEBUG_STD
            eval $SUDO tar -C /usr/local -xzf ${version}.linux-amd64.tar.gz $DEBUG_STD
        fi
        eval $SUDO cp /usr/local/go/bin/go /usr/bin
        rm -rf go$LATEST_GO*
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
touch $dir/.github_tokens

eval pip3 install -U -r requirements.txt $DEBUG_STD

printf "${bblue} Running: Installing Golang tools ${reset}\n\n"
for gotool in "${!gotools[@]}"; do
    eval ${gotools[$gotool]} $DEBUG_STD
    sleep 2
done

printf "${bblue} Running: Installing repositories ${reset}\n\n"

# Repos with special configs
eval git clone https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates $DEBUG_STD
eval nuclei -update-templates $DEBUG_STD
sed -i 's/^miscellaneous/#miscellaneous/' ~/nuclei-templates/.nuclei-ignore
eval git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git $dir/sqlmap $DEBUG_STD
eval git clone --depth 1 https://github.com/drwetter/testssl.sh.git $dir/testssl.sh $DEBUG_STD

# Standard repos installation
for repo in "${!repos[@]}"; do
    eval git clone https://github.com/${repos[$repo]} $dir/$repo $DEBUG_STD
    cd $dir/$repo
    eval git pull $DEBUG_STD
    if [ -s "setup.py" ]; then
        eval $SUDO python3 setup.py install $DEBUG_STD
    fi
    if [ "massdns" = "$repo" ]; then
            eval make $DEBUG_STD && strip -s bin/massdns && eval $SUDO cp bin/massdns /usr/bin/ $DEBUG_ERROR
    elif [ "gf" = "$repo" ]; then
            eval cp -r examples ~/.gf $DEBUG_ERROR
    elif [ "Gf-Patterns" = "$repo" ]; then
            eval mv *.json ~/.gf $DEBUG_ERROR
    fi
    cd $dir
    sleep 2
done

if [ "True" = "$IS_ARM" ]
    then
        eval wget -N -c https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-rpi  $DEBUG_STD
        eval $SUDO mv findomain-rpi /usr/local/bin/findomain
    else
        eval wget -N -c https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux  $DEBUG_STD
        eval $SUDO mv findomain-linux /usr/local/bin/findomain
fi
eval $SUDO chmod 755 /usr/local/bin/findomain
eval subfinder $DEBUG_STD

printf "${bblue} Running: Downloading required files ${reset}\n\n"
## Downloads
eval wget -nc -O ~/.config/amass/config.ini https://raw.githubusercontent.com/OWASP/Amass/master/examples/config.ini $DEBUG_STD
eval wget -nc -O ~/.gf/potential.json https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json $DEBUG_STD
eval wget -nc -O ~/.config/notify/notify.conf https://gist.githubusercontent.com/six2dez/23a996bca189a11e88251367e6583053/raw/a66c4d8cf47a3bc95f5e9ba84773428662ea760c/notify_sample.conf $DEBUG_ERROR
eval wget -N -c https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py $DEBUG_STD
eval wget -N -c https://s3.amazonaws.com/assetnote-wordlists/data/manual/best-dns-wordlist.txt $DEBUG_STD && cp best-dns-wordlist.txt subdomains_big.txt
eval wget -N -c https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt $DEBUG_STD && cp all.txt subdomains_big2.txt
eval wget -N -c https://gist.githubusercontent.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw/1bcdf2d61df08e66fd2d63b6a840f02c3a2ae24c/subdomains.txt $DEBUG_STD
eval wget -N -c https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw/137bb6b60c616552c705e93a345c06cec3a2cb1f/permutations_list.txt $DEBUG_STD
eval wget -N -c https://gist.githubusercontent.com/h4ms1k/adcc340495d418fcd72ec727a116fea2/raw/ea0774de5e27f9bc855207b175249edae2e9ccef/asyncio_ssrf.py $DEBUG_STD && cp asyncio_ssrf.py ssrf.py
eval wget -N -c https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt $DEBUG_STD && cp onelistforallmicro.txt fuzz_wordlist.txt
eval wget -N -c https://raw.githubusercontent.com/xmendez/wfuzz/master/wordlist/vulns/dirTraversal-nix.txt $DEBUG_STD && cp dirTraversal-nix.txt lfi_wordlist.txt

printf "${bblue} Running: Performing last configurations ${reset}\n\n"
## Last steps
eval cat subdomains_big2.txt $DEBUG_ERROR | anew -q subdomains_big.txt
eval rm subdomains_big2.txt $DEBUG_ERROR
if [ ! -s "resolvers.txt" ]; then
    printf "${yellow} Generating personlized resolvers ${reset}\n\n"
    eval dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt $DEBUG_STD
fi
eval h8mail -g $DEBUG_STD

## Stripping all Go binaries
eval strip -s $HOME/go/bin/* $DEBUG_STD

printf "${yellow} Remember set your api keys:\n - amass (~/.config/amass/config.ini)\n - subfinder (~/.config/subfinder/config.yaml)\n - GitHub (~/Tools/.github_tokens)\n - SHODAN (SHODAN_API_KEY in reconftw.cfg)\n - SSRF Server (COLLAB_SERVER in reconftw.cfg) \n - Blind XSS Server (XSS_SERVER in reconftw.cfg) \n - theHarvester (~/Tools/theHarvester/api-keys.yml)\n - H8mail (~/Tools/h8mail_config.ini)\n\n${reset}"
printf "${bgreen} Finished!${reset}\n\n"
printf "\n\n${bgreen}#######################################################################\n"
