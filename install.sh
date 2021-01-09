#!/bin/bash

bgreen='\033[1;32m'
reset='\033[0m'	

printf "\n\n${bgreen}#######################################################################\n"
printf "${bgreen} Install script (Kali Linux based)${reset}\n\n"

sudo apt update -y &>/dev/null
sudo apt install python3 python3-pip ruby screen git libpcap-dev chromium-browser -y &>/dev/null
[ ! -d "~/.gf" ] && mkdir -p ~/.gf
[ ! -d "~/Tools" ] && mkdir -p ~/Tools
dir=~/Tools

go get -u github.com/tomnomnom/gf &>/dev/null
GO111MODULE=on go get -v github.com/OWASP/Amass/v3/... &>/dev/null
go get -u github.com/ffuf/ffuf &>/dev/null
go get -u github.com/tomnomnom/assetfinder &>/dev/null
GO111MODULE=on go get -v github.com/projectdiscovery/naabu/v2/cmd/naabu &>/dev/null
go get -u github.com/tomnomnom/hacks/waybackurls &>/dev/null
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei &>/dev/null
GO111MODULE=on go get -v github.com/projectdiscovery/dnsx/cmd/dnsx &>/dev/null
go get -u github.com/michenriksen/aquatone &>/dev/null
go get -u github.com/tomnomnom/anew &>/dev/null
go get -u github.com/tomnomnom/unfurl &>/dev/null
printf "${bgreen} 25%% done${reset}\n\n"
git clone https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates &>/dev/null
nuclei -update-templates &>/dev/null
go get -u github.com/haccer/subjack &>/dev/null
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx &>/dev/null
git clone https://github.com/haccer/subjack $dir/subjack &>/dev/null
git clone https://github.com/1ndianl33t/Gf-Patterns $dir/Gf-Patterns &>/dev/null
cp -r $GOPATH/src/github.com/tomnomnom/gf/examples ~/.gf
mv $dir/Gf-Patterns/*.json ~/.gf
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder &>/dev/null
printf "${bgreen} 50%% done${reset}\n\n"
go get -u github.com/hahwul/dalfox &>/dev/null
go get -u github.com/lc/gau &>/dev/null
go get -u github.com/KathanP19/Gxss &>/dev/null
git clone https://github.com/blechschmidt/massdns $dir/massdns &>/dev/null
git clone https://github.com/devanshbatham/ParamSpider $dir/ParamSpider &>/dev/null
git clone https://github.com/maurosoria/dirsearch $dir/dirsearch &>/dev/null
GO111MODULE=on go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns &>/dev/null
go get -u github.com/cgboal/sonarsearch/crobat &>/dev/null
git clone https://github.com/KathanP19/JSFScan.sh $dir/JSFScan.sh &>/dev/null
git clone https://github.com/six2dez/degoogle_hunter $dir/degoogle_hunter &>/dev/null
git clone https://github.com/s0md3v/Arjun $dir/Arjun &>/dev/null
git clone https://github.com/pielco11/fav-up $dir/fav-up &>/dev/null
printf "${bgreen} 75%% done${reset}\n\n"
git clone https://github.com/chenjj/CORScanner $dir/CORScanner &>/dev/null
git clone https://github.com/drwetter/testssl.sh $dir/testssl.sh &>/dev/null
pip3 install dnsgen &>/dev/null
sudo chmod +x $dir/JSFScan.sh/install.sh && $dir/JSFScan.sh/install.sh &>/dev/null
wget https://github.com/ezekg/git-hound/releases/download/1.0.0/git-hound_linux_amd64 &>/dev/null
sudo mv git-hound_linux_amd64 /usr/local/bin/git-hound
sudo chmod 755 /usr/local/bin/git-hound
wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux &>/dev/null
sudo mv findomain-linux /usr/local/bin/findomain
sudo chmod 755 /usr/local/bin/findomain
cd $dir/massdns; make &>/dev/null
sudo cp $dir/massdns/bin/massdns /usr/bin/
cd ~/.gf; wget https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json &>/dev/null; cd $dir
wget -O subdomains.txt https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt &>/dev/null
wget -O resolvers.txt https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt &>/dev/null

printf "${bgreen} Finished!${reset}\n\n"
printf "\n\n${bgreen}#######################################################################\n"
