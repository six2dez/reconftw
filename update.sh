#!/bin/bash

#@TODO:
    # - Update testssl.sh
    # - Update Go packages
    # - Get git-hound latest version

bred='\033[1;31m'
bblue='\033[1;34m'
bgreen='\033[1;32m'
reset='\033[0m'

[ ! -d "~/.gf" ] && mkdir -p ~/.gf
[ ! -d "~/Tools" ] && mkdir -p ~/Tools
dir=~/Tools

if [ -f /etc/debian_version ]; then sudo apt install git wget;
elif [ -f /etc/redhat-release ]; then sudo yum install git wget;
elif [ -f /etc/arch-release ]; then sudo pacman -Sy install git wget;
#/etc/os-release fall in yum for some RedHat and Amazon Linux instances
elif [ -f /etc/os-release ]; then sudo yum install git wget;
fi

#Tools to be updated
repos="s0md3v/Arjun six2dez/degoogle_hunter 1ndianl33t/Gf-Patterns gwen001/github-search dark-warlord14/LinkFinder projectdiscovery/nuclei-templates devanshbatham/ParamSpider nsonaniya2010/SubDomainizer haccer/subjack s0md3v/Corsy pielco11/fav-up tomnomnom/gf codingo/Interlace blechschmidt/massdns six2dez/OneListForAll m4ll0k/SecretFinder devanshbatham/OpenRedireX"

printf "\n${bgreen}--==[ ************************************************************************************ ]==--\n"
printf "${bred}                reconftw updater script (apt/rpm/pacman compatible)${reset}\n"
printf "\n${bgreen}--==[ ************************************************************************************ ]==--\n"

for repo in ${repos}; do
    printf "${bgreen}#######################################################################\n"
    printf "${bblue} Updating ${repo} ${reset}\n"
    if [ ! -d "$dir/$(basename $repo)" ]; then
        git clone https://github.com/$repo "$dir/$(basename $repo)" &>/dev/null
    else
        cd "$dir/$(basename $repo)"
        git pull origin master &>/dev/null
        if [ "massdns" = "$(basename $repo)" ]; then
            make &>/dev/null && sudo cp bin/massdns /usr/bin/
        elif [ "Gf-Patterns" = "$(basename $repo)" ]; then
            cp *.json ~/.gf
        elif [ "gf" = "$(basename $repo)" ]; then
            cp -r examples ~/.gf
        elif [ "Interlace" = "$(basename $repo)" ] || [ "LinkFinder" = "$(basename $repo)" ]; then
            sudo python3 setup.py install &>/dev/null
        fi
    fi
    printf "${bblue}\n Updating ${repo} is finished ${reset}\n"
    printf "${bgreen}#######################################################################\n"
done

printf "${bgreen}#######################################################################\n"
printf "${bblue} Updating Files \n"
sudo wget -N -c -O /usr/local/bin/findomain https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux  &>/dev/null
wget -N -c -O ~/.gf/potential.json https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json &>/dev/null
wget -N -c -O $dir/github-endpoints.py https://gist.githubusercontent.com/six2dez/d1d516b606557526e9a78d7dd49cacd3/raw/8e7f1e1139ba3501d15dcd2ad82338d303f0b404/github-endpoints.py &>/dev/null
wget -N -c -O $dir/getjswords.py https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py &>/dev/null
wget -N -c -O $dir/subdomains.txt https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt &>/dev/null
wget -N -c -O $dir/resolvers.txt https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt &>/dev/null
wget -N -c -O $dir/permutations_list.txt https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw/137bb6b60c616552c705e93a345c06cec3a2cb1f/permutations_list.txt &>/dev/null
wget -N -c -O $dir/ssrf.py https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/ssrf.py &>/dev/null

nuclei -update-templates &>/dev/null

#Updating installed python packages
cat $dir/*/requirements.txt | grep -v "=" | uniq | xargs pip3 install -U

printf "\n${bgreen}--==[ ************************************************************************************ ]==--\n"
printf "${bred}                You are up to date, happy hacking${reset}\n"
printf "\n${bgreen}--==[ ************************************************************************************ ]==--\n"
