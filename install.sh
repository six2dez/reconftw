#!/bin/bash
#GOROOT=$(which go)

bgreen='\033[1;32m'
yellow='\033[0;33m'
reset='\033[0m'
bred='\033[1;31m'

DEBUG_STD="&>/dev/null"
DEBUG_ERROR="2>/dev/null"

if grep -q "ARMv"  /proc/cpuinfo
then
   IS_ARM="True";
else
   IS_ARM="False";
fi

if ! test `which sudo`; then
    SUDO=" "
else
    SUDO="sudo"
fi

printf "\n\n${bgreen}#######################################################################\n"
printf "${bgreen} reconftw installer script (apt/rpm/pacman compatible)${reset}\n\n"

install_apt(){
    eval $SUDO apt update -y $DEBUG_STD
    eval $SUDO apt install python3 python3-pip ruby git libpcap-dev chromium-browser wget python-dev python3-dev build-essential libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap -y $DEBUG_STD
}

install_yum(){
    eval $SUDO yum update -y $DEBUG_STD
    eval $SUDO yum install python3 python3-pip ruby git libpcap-devel chromium wget openssl-devel python3-devel libxslt-devel libffi-devel libxml2-devel nmap zlib-devel -y $DEBUG_STD
}

install_pacman(){
    eval $SUDO pacman -Syu -y $DEBUG_STD
    eval $SUDO pacman -Sy install python python-pip ruby git libpcap nmap chromium wget -y $DEBUG_STD
}

#installing latest Golang version
if [[ $(type go | grep -o 'go is') == "go is" ]]
    then
        printf "${bgreen} Golang is already installed ${reset}\n"
    else
        printf "${bgreen} Installing Golang ${reset}\n"
        if [ "True" = "$IS_ARM" ]; then
            LATEST_GO=$(wget -qO- https://golang.org/dl/ | grep -oP 'go([0-9\.]+)\.linux-armv6l\.tar\.gz' | head -n 1 | grep -oP 'go[0-9\.]+' | grep -oP '[0-9\.]+' | head -c -2)
            wget https://dl.google.com/go/go$LATEST_GO.linux-armv6l.tar.gz
            $SUDO tar -C /usr/local -xzf go$LATEST_GO.linux-armv6l.tar.gz
            $SUDO cp /usr/local/go/bin/go /usr/bin
        else
            LATEST_GO=$(wget -qO- https://golang.org/dl/ | grep -oP 'go([0-9\.]+)\.linux-amd64\.tar\.gz' | head -n 1 | grep -oP 'go[0-9\.]+' | grep -oP '[0-9\.]+' | head -c -2)
            wget https://dl.google.com/go/go$LATEST_GO.linux-amd64.tar.gz
            $SUDO tar -C /usr/local -xzf go$LATEST_GO.linux-amd64.tar.gz
            $SUDO cp /usr/local/go/bin/go /usr/bin
        fi
        rm -rf go$LATEST_GO*
fi

[ -n "$GOPATH" ] || { printf "${bred} GOPATH env var no detected, install and configure Golang before run this script\n Check https://golang.org/doc/install\n"; exit 1; }
[ -n "$GOROOT" ] || { printf "${bred} GOROOT env var no detected, install and configure Golang before run this script\n Check https://golang.org/doc/install\n"; exit 1; }

if [ -f /etc/debian_version ]; then install_apt;
elif [ -f /etc/redhat-release ]; then install_yum;
elif [ -f /etc/arch-release ]; then install_pacman;
elif [ -f /etc/os-release ]; then install_yum;  #/etc/os-release fall in yum for some RedHat and Amazon Linux instances
fi

#test -f /etc/gentoo-release && install_emerge
#test -f /etc/SuSE-release && install_zypp

[ ! -d "~/.gf" ] && mkdir -p ~/.gf
[ ! -d "~/Tools" ] && mkdir -p ~/Tools
dir=~/Tools

eval go get -v github.com/tomnomnom/gf $DEBUG_STD
eval go get -v github.com/tomnomnom/qsreplace $DEBUG_STD
eval GO111MODULE=on go get -v github.com/OWASP/Amass/v3/... $DEBUG_STD
eval go get -v github.com/ffuf/ffuf $DEBUG_STD
eval go get -v github.com/tomnomnom/assetfinder $DEBUG_STD
eval GO111MODULE=on go get -v github.com/projectdiscovery/naabu/v2/cmd/naabu $DEBUG_STD
printf "${bgreen} 10%% done${reset}\n\n"
eval go get -v github.com/tomnomnom/hacks/waybackurls $DEBUG_STD
eval GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei $DEBUG_STD
eval go get -v github.com/michenriksen/aquatone $DEBUG_STD
eval go get -v github.com/tomnomnom/anew $DEBUG_STD
printf "${bgreen} 20%% done${reset}\n\n"
eval go get -v github.com/tomnomnom/unfurl $DEBUG_STD
eval git clone https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates $DEBUG_STD
eval nuclei -update-templates $DEBUG_STD
eval go get -v github.com/haccer/subjack $DEBUG_STD
eval git clone https://github.com/haccer/subjack $dir/subjack $DEBUG_STD
eval GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx $DEBUG_STD
printf "${bgreen} 30%% done${reset}\n\n"
eval git clone https://github.com/1ndianl33t/Gf-Patterns $dir/Gf-Patterns $DEBUG_STD
eval git clone https://github.com/tomnomnom/gf $dir/gf $DEBUG_STD
cp -r $dir/gf/examples ~/.gf
cp $dir/Gf-Patterns/*.json ~/.gf
printf "${bgreen} 40%% done${reset}\n\n"
eval GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder $DEBUG_STD
eval go get -v github.com/hahwul/dalfox $DEBUG_STD
eval go get -v github.com/lc/gau $DEBUG_STD
eval GO111MODULE=on go get -u -v github.com/lc/subjs $DEBUG_STD
eval go get -v github.com/KathanP19/Gxss $DEBUG_STD
eval git clone https://github.com/blechschmidt/massdns $dir/massdns $DEBUG_STD
printf "${bgreen} 50%% done${reset}\n\n"
eval git clone https://github.com/devanshbatham/ParamSpider $dir/ParamSpider $DEBUG_STD
eval git clone https://github.com/six2dez/OneListForAll $dir/OneListForAll $DEBUG_STD
eval git clone https://github.com/dark-warlord14/LinkFinder $dir/LinkFinder $DEBUG_STD
eval GO111MODULE=on go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns $DEBUG_STD
eval go get -v github.com/hakluke/hakrawler $DEBUG_STD
eval go get -v github.com/cgboal/sonarsearch/crobat $DEBUG_STD
printf "${bgreen} 60%% done${reset}\n\n"
eval git clone https://github.com/six2dez/degoogle_hunter $dir/degoogle_hunter $DEBUG_STD
eval git clone https://github.com/s0md3v/Arjun $dir/Arjun $DEBUG_STD
eval git clone https://github.com/pielco11/fav-up $dir/fav-up $DEBUG_STD
eval git clone https://github.com/s0md3v/Corsy $dir/Corsy $DEBUG_STD
eval git clone https://github.com/nsonaniya2010/SubDomainizer $dir/SubDomainizer $DEBUG_STD
eval git clone https://github.com/codingo/Interlace $dir/Interlace $DEBUG_STD
eval git clone https://github.com/m4ll0k/SecretFinder $dir/SecretFinder $DEBUG_STD
eval git clone https://github.com/gwen001/github-search $dir/github-search $DEBUG_STD
eval git clone https://github.com/six2dez/degoogle_hunter $dir/degoogle_hunter $DEBUG_STD
printf "${bgreen} 70%% done${reset}\n\n"
eval git clone https://github.com/drwetter/testssl.sh $dir/testssl.sh $DEBUG_STD
eval pip3 install dnsgen $DEBUG_STD

if [ "True" = "$IS_ARM" ]
    then
        eval git clone https://github.com/tillson/git-hound $dir/git-hound $DEBUG_STD
        cd $dir/git-hound && go build && chmod 754 git-hound && mv $dir/git-hound/git-hound /usr/local/bin  && cd $dir
    else
        eval wget https://github.com/tillson/git-hound/releases/download/v1.3/git-hound_1.3_Linux_x86_64.tar.gz $DEBUG_STD
        tar -xf git-hound_1.3_Linux_x86_64.tar.gz git-hound
        rm -f git-hound_1.3_Linux_x86_64.tar.gz
        $SUDO mv git-hound /usr/local/bin/git-hound
        $SUDO chmod 755 /usr/local/bin/git-hound
fi
printf "${bgreen} 80%% done${reset}\n\n"
eval git clone https://github.com/m8r0wn/pymeta $dir/pymeta $DEBUG_STD
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

eval find $dir -name 'requirements.txt' -exec pip3 install --user -r {} \; $DEBUG_STD
cd $dir/Interlace && $SUDO python3 setup.py install
cd $dir/LinkFinder && $SUDO python3 setup.py install
cd $dir
$SUDO python3 $dir/pymeta/setup.py install
eval git clone https://github.com/devanshbatham/OpenRedireX $dir/OpenRedireX $DEBUG_STD
printf "${bgreen} 90%% done${reset}\n\n"
cd ~/.gf; eval wget -O potential.json https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json $DEBUG_STD; cd $dir
eval wget -O github-endpoints.py https://gist.githubusercontent.com/six2dez/d1d516b606557526e9a78d7dd49cacd3/raw/8e7f1e1139ba3501d15dcd2ad82338d303f0b404/github-endpoints.py $DEBUG_STD
eval wget -O getjswords.py https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py $DEBUG_STD
eval wget -O subdomains.txt https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt $DEBUG_STD
eval wget -O resolvers.txt https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt $DEBUG_STD
eval wget -O permutations_list.txt https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw/137bb6b60c616552c705e93a345c06cec3a2cb1f/permutations_list.txt $DEBUG_STD
eval wget -O ssrf.py https://gist.githubusercontent.com/h4ms1k/adcc340495d418fcd72ec727a116fea2/raw/ea0774de5e27f9bc855207b175249edae2e9ccef/asyncio_ssrf.py $DEBUG_STD
eval wget -O all_requirements.txt https://gist.githubusercontent.com/detonxx/92118db85d97f6edb54a0a427ae96a2e/raw/95c0517bdcd1467e9a82992097b7c3e66afccfab/all_requirements.txt $DEBUG_STD
eval pip3 install -r $dir/all_requirements.txt $DEBUG_STD

printf "${yellow} Remember set your api keys:\n - amass (~/.config/amass/config.ini)\n - subfinder (~/.config/subfinder/config.yaml)\n - git-hound (~/.githound/config.yml)\n - github-endpoints.py ($tools/.github_tokens or GITHUB_TOKEN env var)\n - favup (shodan init SHODANPAIDAPIKEY)\n - SSRF Server (COLLAB_SERVER env var) ${reset}\n"

printf "${bgreen} Finished!${reset}\n\n"
printf "\n\n${bgreen}#######################################################################\n"
