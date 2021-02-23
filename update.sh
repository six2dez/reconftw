#!/bin/bash

#@TODO:
    # - Update testssl.sh
    # - Update Go packages

bred='\033[1;31m'
bblue='\033[1;34m'
bgreen='\033[1;32m'
reset='\033[0m'

DEBUG_STD="&>/dev/null"
DEBUG_ERROR="2>/dev/null"

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

[ ! -d "~/.gf" ] && mkdir -p ~/.gf
[ ! -d "~/Tools" ] && mkdir -p ~/Tools
dir=~/Tools

if [ -f /etc/debian_version ]; then $SUDO apt install git wget;
elif [ -f /etc/redhat-release ]; then $SUDO yum install git wget;
elif [ -f /etc/arch-release ]; then $SUDO pacman -Sy install git wget;
#/etc/os-release fall in yum for some RedHat and Amazon Linux instances
elif [ -f /etc/os-release ]; then $SUDO yum install git wget;
fi

#Updating installed python packages
printf "${bgreen}#######################################################################\n"
printf "${bblue} Updating installed python packages \n"
eval pip3 install -U -r requirements.txt $DEBUG_STD
printf "${bblue}\n Updating installed python packages is finished ${reset}\n"
printf "${bgreen}#######################################################################\n"

#Tools to be updated
repos="six2dez/degoogle_hunter s0md3v/Arjun sqlmapproject/sqlmap 1ndianl33t/Gf-Patterns s0md3v/XSStrike gwen001/github-search eslam3kl/crtfinder dark-warlord14/LinkFinder maaaaz/webscreenshot ProjectAnte/dnsgen devanshbatham/ParamSpider Threezh1/JSFinder s0md3v/Corsy Tuhinshubhra/CMSeeK pielco11/fav-up tomnomnom/gf codingo/Interlace blechschmidt/massdns devanshbatham/OpenRedireX obheda12/GitDorker"
printf "\n${bgreen}--==[ ************************************************************************************ ]==--\n"
printf "${bred}                reconftw updater script (apt/rpm/pacman compatible)${reset}\n"
printf "\n${bgreen}--==[ ************************************************************************************ ]==--\n"

for repo in ${repos}; do
    printf "${bgreen}#######################################################################\n"
    printf "${bblue} Updating ${repo} ${reset}\n"
    if [ ! -d "$dir/$(basename $repo)" ]; then
        eval git clone https://github.com/$repo "$dir/$(basename $repo)" $DEBUG_STD
    else
        cd "$dir/$(basename $repo)"
        eval git pull origin master $DEBUG_STD
        if [ "massdns" = "$(basename $repo)" ]; then
            make && $SUDO cp bin/massdns /usr/bin/
        elif [ "Gf-Patterns" = "$(basename $repo)" ]; then
            cp *.json ~/.gf
        elif [ "gf" = "$(basename $repo)" ]; then
            cp -r examples ~/.gf
        elif [ "Interlace" = "$(basename $repo)" ] || [ "LinkFinder" = "$(basename $repo)" ]; then
            eval $SUDO python3 setup.py install $DEBUG_STD
        elif [ "LinkFinder" = "$(basename $repo)" ] || [ "LinkFinder" = "$(basename $repo)" ]; then
            eval $SUDO python3 setup.py install $DEBUG_STD
        elif [ "dnsgen" = "$(basename $repo)" ] || [ "LinkFinder" = "$(basename $repo)" ]; then
            eval $SUDO python3 setup.py install $DEBUG_STD
        elif [ "Arjun" = "$(basename $repo)" ] || [ "LinkFinder" = "$(basename $repo)" ]; then
            eval $SUDO python3 setup.py install $DEBUG_STD
        fi
#        if [ "True" = "$IS_ARM" ] && [ "git-hound" = "$(basename $repo)" ]
#            then
#                go build && chmod 754 git-hound && $SUDO mv git-hound /usr/local/bin/
#        fi
    fi
    printf "${bblue}\n Updating ${repo} is finished ${reset}\n"
    printf "${bgreen}#######################################################################\n"
done


printf "${bgreen}#######################################################################\n"
printf "${bblue} Updating Files \n"
if [ "True" = "$IS_ARM" ]
    then
        eval wget -N -c https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-rpi  $DEBUG_STD
        $SUDO mv findomain-rpi /usr/local/bin/findomain
    else
        eval wget -N -c https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux  $DEBUG_STD
        $SUDO mv findomain-linux /usr/local/bin/findomain
fi
$SUDO chmod 754 /usr/local/bin/findomain

eval wget -N -c -O ~/.gf/potential.json https://raw.githubusercontent.com/devanshbatham/ParamSpider/master/gf_profiles/potential.json $DEBUG_STD
eval wget -N -c -O ~/.config/amass/config.ini https://raw.githubusercontent.com/OWASP/Amass/master/examples/config.ini $DEBUG_STD
eval wget -N -C -O ~/.config/notify/notify.conf https://gist.githubusercontent.com/six2dez/23a996bca189a11e88251367e6583053/raw/a66c4d8cf47a3bc95f5e9ba84773428662ea760c/notify_sample.conf $DEBUG_ERROR
eval wget -N -c -O $dir/getjswords.py https://raw.githubusercontent.com/m4ll0k/Bug-Bounty-Toolz/master/getjswords.py $DEBUG_STD
eval wget -N -c -O $dir/subdomains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt $DEBUG_STD
eval wget -N -c -O $dir/subdomains_big.txt https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt $DEBUG_STD
eval wget -N -c -O $dir/resolvers.txt https://raw.githubusercontent.com/BBerastegui/fresh-dns-servers/master/resolvers.txt $DEBUG_STD
eval wget -N -c -O $dir/permutations_list.txt https://gist.githubusercontent.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw/137bb6b60c616552c705e93a345c06cec3a2cb1f/permutations_list.txt $DEBUG_STD
eval wget -N -c -O $dir/ssrf.py https://gist.githubusercontent.com/h4ms1k/adcc340495d418fcd72ec727a116fea2/raw/ea0774de5e27f9bc855207b175249edae2e9ccef/asyncio_ssrf.py $DEBUG_STD
eval wget -N -c -O $dir/fuzz_wordlist.txt https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt $DEBUG_STD
eval wget -N -c -O $dir/lfi_wordlist.txt https://raw.githubusercontent.com/xmendez/wfuzz/master/wordlist/vulns/dirTraversal-nix.txt $DEBUG_STD


printf "${bblue}\n Updating Files is finished ${reset}\n"
printf "${bgreen}#######################################################################\n"

#Updating Nuclei templates
printf "${bgreen}#######################################################################\n"
printf "${bblue} Updating Nuclei templates \n"
eval nuclei -update-templates $DEBUG_STD
sed -i 's/^miscellaneous/#miscellaneous/' ~/nuclei-templates/.nuclei-ignore
printf "${bblue}\n Updating Nuclei templates is finished ${reset}\n"
printf "${bgreen}#######################################################################\n"

#Updating Golang
printf "${bgreen}#######################################################################\n"
printf "${bblue} Updating Golang \n"
LATEST_GO=$(curl https://golang.org/VERSION?m=text)
if [ "$LATEST_GO" =  $(go version | cut -d " " -f3) ]; then
    printf "${bblue}\n Golang is up to date ${reset}\n"
else
    if [ "True" = "$IS_ARM" ]; then
        wget https://dl.google.com/go/$LATEST_GO.linux-armv6l.tar.gz
        $SUDO tar -C /usr/local -xzf $LATEST_GO.linux-armv6l.tar.gz
    else
        wget https://dl.google.com/go/$LATEST_GO.linux-amd64.tar.gz
        $SUDO tar -C /usr/local -xzf $LATEST_GO.linux-amd64.tar.gz
    fi
    $SUDO cp /usr/local/go/bin/go /usr/bin
    eval rm -rf $LATEST_GO* $DEBUG_STD
fi
printf "${bblue}\n Updating Golang is finished ${reset}\n"
printf "${bgreen}#######################################################################\n"

#stripping all Go binaries
eval strip -s $HOME/go/bin/* $DEBUG_STD

printf "\n${bgreen}--==[ ************************************************************************************ ]==--\n"
printf "${bred}                You are up to date, happy hacking${reset}\n"
printf "\n${bgreen}--==[ ************************************************************************************ ]==--\n"
