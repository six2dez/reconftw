#!/bin/bash

bgreen='\033[1;32m'
yellow='\033[0;33m'
reset='\033[0m'
bred='\033[1;31m'

DEBUG_STD="&>/dev/null"
DEBUG_ERROR="2>/dev/null"
SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

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
printf "${bgreen} reconftw installer script (apt/rpm/pacman compatible)${reset}\n\n"

install_apt(){
    eval $SUDO apt install chromium-browser -y $DEBUG_STD
    eval $SUDO apt install chromium -y $DEBUG_STD
    eval $SUDO apt install python3 python3-pip ruby git curl libpcap-dev wget python-dev python3-dev dnsutils build-essential xvfb libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq -y $DEBUG_STD
}

install_yum(){
    eval $SUDO yum install python3 python3-pip ruby git curl libpcap-devel chromium wget openssl-devel bind-utils python3-devel libxslt-devel libffi-devel xorg-x11-server-Xvfb libxml2-devel nmap zlib-devel jq -y $DEBUG_STD
}

install_pacman(){
    eval $SUDO pacman -Sy install python python-pip dnsutils ruby curl git libpcap nmap chromium wget jq xorg-server-xvfb -y $DEBUG_STD
}

#installing latest Golang version
if [[ $(eval type go $DEBUG_ERROR | grep -o 'go is') == "go is" ]]
    then
        printf "${bgreen} Golang is already installed ${reset}\n\n"
    else
        printf "${bgreen} Installing Golang ${reset}\n"
        if [ "True" = "$IS_ARM" ]; then
            LATEST_GO=$(wget -qO- https://golang.org/dl/ | grep -oP 'go([0-9\.]+)\.linux-armv6l\.tar\.gz' | head -n 1 | grep -oP 'go[0-9\.]+' | grep -oP '[0-9\.]+' | head -c -2)
            eval wget https://dl.google.com/go/go$LATEST_GO.linux-armv6l.tar.gz $DEBUG_STD
            eval $SUDO tar -C /usr/local -xzf go$LATEST_GO.linux-armv6l.tar.gz $DEBUG_STD
            $SUDO cp /usr/local/go/bin/go /usr/bin
        else
            LATEST_GO=$(wget -qO- https://golang.org/dl/ | grep -oP 'go([0-9\.]+)\.linux-amd64\.tar\.gz' | head -n 1 | grep -oP 'go[0-9\.]+' | grep -oP '[0-9\.]+' | head -c -2)
            eval wget https://dl.google.com/go/go$LATEST_GO.linux-amd64.tar.gz $DEBUG_STD
            eval $SUDO tar -C /usr/local -xzf go$LATEST_GO.linux-amd64.tar.gz $DEBUG_STD
            $SUDO cp /usr/local/go/bin/go /usr/bin
        fi
        rm -rf go$LATEST_GO*
if [ -f ~/.bashrc ]
then
cat << EOF >> ~/.bashrc

# Golang vars
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH
EOF
fi

if [ -f ~/.zshrc ]
then
cat << EOF >> ~/.zshrc

# Golang vars
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH
EOF
fi
printf "${yellow} Golang installed! Open a new terminal and run again this script ${reset}\n"
exit
fi

[ -n "$GOPATH" ] || { printf "${bred} GOPATH env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }
[ -n "$GOROOT" ] || { printf "${bred} GOROOT env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }


if [ -f /etc/debian_version ]; then install_apt;
elif [ -f /etc/redhat-release ]; then install_yum;
elif [ -f /etc/arch-release ]; then install_pacman;
elif [ -f /etc/os-release ]; then install_yum;  #/etc/os-release fall in yum for some RedHat and Amazon Linux instances
fi

printf "${bgreen} System packages installed${reset}\n\n"

if ! command -v phantomjs &> /dev/null
then
    cd /opt
    if [ "True" = "$IS_ARM" ]; then
        eval $SUDO mkdir -p phantomjs-armv6-rpi-v2.1.1 && cd phantomjs-armv6-rpi-v2.1.1 $DEBUG_STD
        eval $SUDO wget https://github.com/piksel/phantomjs-raspberrypi/releases/download/v2.1.1-r/phantomjs-armv6-rpi-v2.1.1.tar.xz $DEBUG_STD
        eval $SUDO tar xvf phantomjs-armv6-rpi-v2.1.1.tar.xz $DEBUG_STD
        eval $SUDO ln -s /opt/phantomjs-armv6-rpi-v2.1.1/bin/phantomjs /usr/local/bin/phantomjs $DEBUG_STD
    else
        eval $SUDO wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2 $DEBUG_STD
        eval $SUDO tar xvf phantomjs-2.1.1-linux-x86_64.tar.bz2 $DEBUG_STD
        eval $SUDO ln -s /opt/phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin/phantomjs $DEBUG_STD
    fi
    cd $SCRIPTPATH
fi

[ ! -d "~/.gf" ] && mkdir -p ~/.gf
[ ! -d "~/Tools" ] && mkdir -p ~/Tools
dir=~/Tools

eval pip3 install -r requirements.txt $DEBUG_STD
printf "${bgreen} Requirements installed\n\nInstallation begins!\n\n${reset}"
eval go get -v github.com/tomnomnom/gf $DEBUG_STD
eval go get -v github.com/tomnomnom/qsreplace $DEBUG_STD
eval GO111MODULE=on go get -v github.com/OWASP/Amass/v3/... $DEBUG_STD
eval go get -v github.com/ffuf/ffuf $DEBUG_STD
eval go get -v github.com/tomnomnom/assetfinder $DEBUG_STD
eval GO111MODULE=on go get -v github.com/projectdiscovery/naabu/v2/cmd/naabu $DEBUG_STD
printf "${bgreen} 10%% done${reset}\n\n"
eval go get -v github.com/tomnomnom/hacks/waybackurls $DEBUG_STD
eval GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei $DEBUG_STD
eval go get -v github.com/tomnomnom/anew $DEBUG_STD
eval GO111MODULE=on go get -v github.com/projectdiscovery/notify/cmd/notify $DEBUG_STD
printf "${bgreen} 20%% done${reset}\n\n"
eval go get -v github.com/tomnomnom/unfurl $DEBUG_STD
eval git clone https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates $DEBUG_STD
eval git clone https://github.com/eslam3kl/crtfinder $dir/crtfinder $DEBUG_STD
eval nuclei -update-templates $DEBUG_STD
eval go get -v github.com/haccer/subjack $DEBUG_STD
eval git clone https://github.com/haccer/subjack $dir/subjack $DEBUG_STD
eval GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx $DEBUG_STD
printf "${bgreen} 30%% done${reset}\n\n"
eval go get -u github.com/gwen001/github-endpoints $DEBUG_STD
eval git clone https://github.com/s0md3v/XSStrike $dir/XSStrike $DEBUG_STD
eval git clone https://github.com/1ndianl33t/Gf-Patterns $dir/Gf-Patterns $DEBUG_STD
eval git clone https://github.com/tomnomnom/gf $dir/gf $DEBUG_STD
cp -r $dir/gf/examples ~/.gf
cp $dir/Gf-Patterns/*.json ~/.gf
printf "${bgreen} 40%% done${reset}\n\n"
eval GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder $DEBUG_STD
eval go get -v github.com/lc/gau $DEBUG_STD
eval GO111MODULE=on go get -u -v github.com/lc/subjs $DEBUG_STD
eval go get -v github.com/KathanP19/Gxss $DEBUG_STD
eval git clone https://github.com/blechschmidt/massdns $dir/massdns $DEBUG_STD
printf "${bgreen} 50%% done${reset}\n\n"
eval git clone https://github.com/devanshbatham/ParamSpider $dir/ParamSpider $DEBUG_STD
eval git clone https://github.com/dark-warlord14/LinkFinder $dir/LinkFinder $DEBUG_STD
eval git clone https://github.com/six2dez/degoogle_hunter $dir/degoogle_hunter $DEBUG_STD
eval git clone https://github.com/s0md3v/Arjun $dir/Arjun $DEBUG_STD
eval GO111MODULE=on go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns $DEBUG_STD
eval go get -u github.com/jaeles-project/gospider $DEBUG_STD
eval go get -v github.com/cgboal/sonarsearch/crobat $DEBUG_STD
eval GO111MODULE=on go get -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz $DEBUG_STD
printf "${bgreen} 60%% done${reset}\n\n"
eval git clone https://github.com/Tuhinshubhra/CMSeeK $dir/CMSeeK $DEBUG_STD
eval git clone https://github.com/pielco11/fav-up $dir/fav-up $DEBUG_STD
eval git clone https://github.com/s0md3v/Corsy $dir/Corsy $DEBUG_STD
eval git clone https://github.com/Threezh1/JSFinder $dir/JSFinder $DEBUG_STD
eval git clone https://github.com/codingo/Interlace $dir/Interlace $DEBUG_STD
eval git clone https://github.com/gwen001/github-search $dir/github-search $DEBUG_STD
eval git clone https://github.com/obheda12/GitDorker $dir/GitDorker $DEBUG_STD
printf "${bgreen} 70%% done${reset}\n\n"
eval git clone https://github.com/ProjectAnte/dnsgen $dir/dnsgen $DEBUG_STD
eval git clone https://github.com/drwetter/testssl.sh $dir/testssl.sh $DEBUG_STD
eval git clone https://github.com/maaaaz/webscreenshot $dir/webscreenshot $DEBUG_STD

printf "${bgreen} 80%% done${reset}\n\n"
if [ "True" = "$IS_ARM" ]
    then
        eval wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-rpi $DEBUG_STD
        $SUDO mv findomain-rpi /usr/local/bin/findomain
    else
        eval wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux $DEBUG_STD
        $SUDO mv findomain-linux /usr/local/bin/findomain
fi

$SUDO chmod 755 /usr/local/bin/findomain
cd $dir/massdns; eval make $DEBUG_STD
$SUDO cp $dir/massdns/bin/massdns /usr/bin/

cd $dir/Interlace && eval $SUDO python3 setup.py install $DEBUG_STD
cd $dir/LinkFinder && eval $SUDO python3 setup.py install $DEBUG_STD
cd $dir/dnsgen && eval $SUDO python3 setup.py install $DEBUG_STD
cd $dir
eval git clone https://github.com/devanshbatham/OpenRedireX $dir/OpenRedireX $DEBUG_STD
printf "${bgreen} 90%% done${reset}\n\n"
eval subfinder $DEBUG_STD
eval notify $DEBUG_STD
mkdir -p ~/.config/amass/
eval wget -nc -O ~/.config/amass/config.ini https://raw.githubusercontent.com/OWASP/Amass/master/examples/config.ini $DEBUG_STD
cd ~/.gf; eval wget -O potential.json https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json $DEBUG_STD; cd $dir
touch $dir/.github_tokens
eval wget -O getjswords.py https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py $DEBUG_STD
eval wget -O subdomains.txt https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt $DEBUG_STD
eval wget -O resolvers.txt https://raw.githubusercontent.com/BBerastegui/fresh-dns-servers/master/resolvers.txt $DEBUG_STD
eval wget -O permutations_list.txt https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw/137bb6b60c616552c705e93a345c06cec3a2cb1f/permutations_list.txt $DEBUG_STD
eval wget -O ssrf.py https://gist.githubusercontent.com/h4ms1k/adcc340495d418fcd72ec727a116fea2/raw/ea0774de5e27f9bc855207b175249edae2e9ccef/asyncio_ssrf.py $DEBUG_STD
eval wget -O fuzz_wordlist.txt https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt $DEBUG_STD

sed -i 's/^miscellaneous/#miscellaneous/' ~/nuclei-templates/.nuclei-ignore

#stripping all Go binaries
eval strip -s $HOME/go/bin/* $DEBUG_STD

printf "${yellow} Remember set your api keys:\n - amass (~/.config/amass/config.ini)\n - subfinder (~/.config/subfinder/config.yaml)\n - GitHub (${dir}/.github_tokens)\n - favup (shodan init SHODANPAIDAPIKEY)\n - SSRF Server (COLLAB_SERVER env var) \n - Blind XSS Server (XSS_SERVER env var)\n\n${reset}"

printf "${bgreen} Finished!${reset}\n\n"
printf "\n\n${bgreen}#######################################################################\n"
