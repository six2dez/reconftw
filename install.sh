#!/bin/bash
GOROOT=$(which go)

bgreen='\033[1;32m'
yellow='\033[0;33m'
reset='\033[0m'	
bred='\033[1;31m'

printf "\n\n${bgreen}#######################################################################\n"
printf "${bgreen} reconftw installer script (apt/rpm/pacman compatible)${reset}\n\n"

install_apt(){
    sudo apt update -y &>/dev/null
    sudo apt install python3 python3-pip ruby git libpcap-dev chromium-browser wget python-dev python3-dev build-essential libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap make python-pip -y &>/dev/null
}

install_yum(){
    sudo yum update -y &>/dev/null
    sudo yum install python3 python3-pip ruby git libpcap-devel chromium wget openssl-devel python3-devel libxslt-devel libffi-devel libxml2-devel nmap zlib-devel -y &>/dev/null
}

install_pacman(){
    sudo pacman -Syu -y &>/dev/null
    sudo pacman -Sy install python python-pip ruby git libpcap nmap chromium wget -y &>/dev/null
}

type go >/dev/null 2>&1 || { printf "${bred} Golang no detected, install and configure it before run this script\n Check https://golang.org/doc/install\n"; exit 1; }
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

go get -v github.com/tomnomnom/gf &>/dev/null
go get -v github.com/tomnomnom/qsreplace &>/dev/null
GO111MODULE=on go get -v github.com/OWASP/Amass/v3/... &>/dev/null
go get -v github.com/ffuf/ffuf &>/dev/null
go get -v github.com/tomnomnom/assetfinder &>/dev/null
GO111MODULE=on go get -v github.com/projectdiscovery/naabu/v2/cmd/naabu &>/dev/null
printf "${bgreen} 10%% done${reset}\n\n"
go get -v github.com/tomnomnom/hacks/waybackurls &>/dev/null
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei &>/dev/null
go get -v github.com/michenriksen/aquatone &>/dev/null
go get -v github.com/tomnomnom/anew &>/dev/null
printf "${bgreen} 20%% done${reset}\n\n"
go get -v github.com/tomnomnom/unfurl &>/dev/null
git clone https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates &>/dev/null
nuclei -update-templates &>/dev/null
go get -v github.com/haccer/subjack &>/dev/null
git clone https://github.com/haccer/subjack $dir/subjack &>/dev/null
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx &>/dev/null
printf "${bgreen} 30%% done${reset}\n\n"
git clone https://github.com/1ndianl33t/Gf-Patterns $dir/Gf-Patterns &>/dev/null
git clone https://github.com/tomnomnom/gf $dir/gf &>/dev/null
cp -r $dir/gf/examples ~/.gf
cp $dir/Gf-Patterns/*.json ~/.gf
printf "${bgreen} 40%% done${reset}\n\n"
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder &>/dev/null
go get -v github.com/hahwul/dalfox &>/dev/null
go get -v github.com/lc/gau &>/dev/null
GO111MODULE=on go get -u -v github.com/lc/subjs &>/dev/null
go get -v github.com/KathanP19/Gxss &>/dev/null
git clone https://github.com/blechschmidt/massdns $dir/massdns &>/dev/null
printf "${bgreen} 50%% done${reset}\n\n"
git clone https://github.com/devanshbatham/ParamSpider $dir/ParamSpider &>/dev/null
git clone https://github.com/six2dez/OneListForAll $dir/OneListForAll &>/dev/null
git clone https://github.com/dark-warlord14/LinkFinder $dir/LinkFinder &>/dev/null
GO111MODULE=on go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns &>/dev/null
go get -v github.com/hakluke/hakrawler
go get -v github.com/cgboal/sonarsearch/crobat &>/dev/null
printf "${bgreen} 60%% done${reset}\n\n"
git clone https://github.com/six2dez/degoogle_hunter $dir/degoogle_hunter &>/dev/null
git clone https://github.com/s0md3v/Arjun $dir/Arjun &>/dev/null
git clone https://github.com/pielco11/fav-up $dir/fav-up &>/dev/null
git clone https://github.com/s0md3v/Corsy $dir/Corsy &>/dev/null
git clone https://github.com/nsonaniya2010/SubDomainizer $dir/SubDomainizer &>/dev/null
git clone https://github.com/codingo/Interlace $dir/Interlace &>/dev/null
git clone https://github.com/m4ll0k/SecretFinder $dir/SecretFinder &>/dev/null
git clone https://github.com/gwen001/github-search $dir/github-search &>/dev/null
printf "${bgreen} 70%% done${reset}\n\n"
git clone https://github.com/drwetter/testssl.sh $dir/testssl.sh &>/dev/null
sudo pip3 install dnsgen &>/dev/null
wget https://github.com/tillson/git-hound/releases/download/v1.3/git-hound_1.3_Linux_x86_64.tar.gz &>/dev/null
tar -xf git-hound_1.3_Linux_x86_64.tar.gz git-hound
rm -f git-hound_1.3_Linux_x86_64.tar.gz
sudo mv git-hound /usr/local/bin/git-hound
sudo chmod 755 /usr/local/bin/git-hound
printf "${bgreen} 80%% done${reset}\n\n"
wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux &>/dev/null
sudo mv findomain-linux /usr/local/bin/findomain
sudo chmod 755 /usr/local/bin/findomain
cd $dir/massdns; make &>/dev/null
sudo cp $dir/massdns/bin/massdns /usr/bin/
sudo pip3 install mmh3==2.5.1
find $dir -name 'requirements.txt' -exec pip3 install --user -r {} \; &>/dev/null
cd $dir/Interlace && sudo python3 setup.py install
cd $dir/LinkFinder && python3 setup.py install
git clone https://github.com/devanshbatham/OpenRedireX $dir/OpenRedireX &>/dev/null
printf "${bgreen} 90%% done${reset}\n\n"
cd ~/.gf; wget -O potential.json https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json &>/dev/null; cd $dir
wget -O github-endpoints.py https://gist.githubusercontent.com/six2dez/d1d516b606557526e9a78d7dd49cacd3/raw/8e7f1e1139ba3501d15dcd2ad82338d303f0b404/github-endpoints.py &>/dev/null
wget -O getjswords.py https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py &>/dev/null
wget -O subdomains.txt https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt &>/dev/null
wget -O resolvers.txt https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt &>/dev/null
wget -O permutations_list.txt https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw/137bb6b60c616552c705e93a345c06cec3a2cb1f/permutations_list.txt &>/dev/null
wget -O ssrf.py https://gist.githubusercontent.com/h4ms1k/adcc340495d418fcd72ec727a116fea2/raw/ea0774de5e27f9bc855207b175249edae2e9ccef/asyncio_ssrf.py &>/dev/null


printf "${yellow} Remember set your api keys:\n - amass (~/.config/amass/config.ini)\n - subfinder (~/.config/subfinder/config.yaml)\n - git-hound (~/.githound/config.yml)\n - github-endpoints.py ($tools/.github_tokens or GITHUB_TOKEN env var)\n - favup (shodan init SHODANPAIDAPIKEY)\n - SSRF Server (COLLAB_SERVER env var) ${reset}\n"

printf "${bgreen} Finished!${reset}\n\n"
printf "\n\n${bgreen}#######################################################################\n"
