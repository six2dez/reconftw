#!/bin/bash

bred='\033[1;31m'
bblue='\033[1;34m'
bgreen='\033[1;32m'
yellow='\033[0;33m'
red='\033[0;31m'
blue='\033[0;34m'
green='\033[0;32m'
reset='\033[0m'

tools=~/Tools
DEBUG_STD="&>/dev/null"
DEBUG_ERROR="2>/dev/null"
SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# Uncomment this only if it is not already in your env .bashrc or .zshrc
#GITHUB_TOKEN=XXXXXXXXXXXXXXXXX
#COLLAB_SERVER=XXXXXXXXXXXXXXXXX
#XSS_SERVER=XXXXXXXXXXXXXXXXX


banner(){
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
	printf "			                                     by @six2dez${reset}\n"
}

start(){
	tools_installed
	if [ -z "$domain" ]
	then
		printf "\n\n${bred} No domain or list provided ${reset}\n\n"
		exit
	fi

	dir=$SCRIPTPATH/Recon/$domain
	called_fn_dir=$dir/.called_fn

	if [ ! -d "$called_fn_dir" ]
	then
		mkdir -p $called_fn_dir
	fi

	if [ ! -d "$dir" ]
	then
		mkdir -p $dir
	fi

	if [ -n "$list" ]
	then
		cp $list $dir/${domain}_probed.txt
	fi
	fuzz_wordlist=$tools/fuzz_wordlist.txt
	cd $dir
	printf "\n"
	printf "${bred} Target: ${domain}\n\n"
}

function tools_installed(){

	printf "\n\n${bgreen}#######################################################################\n"
	printf "${bblue} Checking installed tools ${reset}\n\n"

	allinstalled=true

	[ -n "$GOPATH" ] || { printf "${bred} [*] GOPATH var		[NO]\n"; allinstalled=false;}
	[ -n "$GOROOT" ] || { printf "${bred} [*] GOROOT var		[NO]\n"; allinstalled=false;}
	[ -n "$PATH" ] || { printf "${bred} [*] PATH var		[NO]\n"; allinstalled=false;}
	[ -f $tools/degoogle_hunter/degoogle.py ] || { printf "${bred} [*] degoogle		[NO]\n"; allinstalled=false;}
	[ -f $tools/ParamSpider/paramspider.py ] || { printf "${bred} [*] Paramspider	[NO]\n"; allinstalled=false;}
	[ -f $tools/Arjun/arjun.py ] || { printf "${bred} [*] Arjun		[NO]\n"; allinstalled=false;}
	[ -f $tools/fav-up/favUp.py ] || { printf "${bred} [*] fav-up		[NO]\n"; allinstalled=false;}
	[ -f $tools/Corsy/corsy.py ] || { printf "${bred} [*] Corsy		[NO]\n"; allinstalled=false;}
	[ -f $tools/testssl.sh/testssl.sh ] || { printf "${bred} [*] testssl		[NO]\n"; allinstalled=false;}
	[ -f $tools/JSFinder/JSFinder.py ] || { printf "${bred} [*] JSFinder	[NO]\n"; allinstalled=false;}
	[ -f $tools/CMSeeK/cmseek.py ] || { printf "${bred} [*] CMSeeK	[NO]\n"; allinstalled=false;}
	[ -f $tools/fuzz_wordlist.txt ] || { printf "${bred} [*] OneListForAll	[NO]\n"; allinstalled=false;}
	[ -f $tools/LinkFinder/linkfinder.py ] || { printf "${bred} [*] LinkFinder	        [NO]\n"; allinstalled=false;}
	[ -f $tools/github-endpoints.py ] || { printf "${bred} [*] github-endpoints   [NO]\n"; allinstalled=false;}
	[ -f $tools/degoogle_hunter/degoogle_hunter.sh ] || { printf "${bred} [*] degoogle_hunter   [NO]\n"; allinstalled=false;}
	[ -f $tools/github-search/github-endpoints.py ] || { printf "${bred} [*] github-search	[NO]\n"; allinstalled=false;}
	[ -f $tools/getjswords.py ] || { printf "${bred} [*] getjswords   	[NO]\n"; allinstalled=false;}
	[ -f $tools/subdomains.txt ] || { printf "${bred} [*] subdomains   	[NO]\n"; allinstalled=false;}
	[ -f $tools/resolvers.txt ] || { printf "${bred} [*] resolvers   	[NO]\n"; allinstalled=false;}
	eval type -P hakrawler $DEBUG_STD || { printf "${bred} [*] hakrawler		[NO]\n"; allinstalled=false;}
	eval type -P subfinder $DEBUG_STD || { printf "${bred} [*] Subfinder		[NO]\n"; allinstalled=false;}
	eval type -P assetfinder $DEBUG_STD || { printf "${bred} [*] Assetfinder		[NO]\n"; allinstalled=false;}
	eval type -P findomain $DEBUG_STD || { printf "${bred} [*] Findomain		[NO]\n"; allinstalled=false;}
	eval type -P amass $DEBUG_STD || { printf "${bred} [*] Amass		[NO]\n"; allinstalled=false;}
	eval type -P crobat $DEBUG_STD || { printf "${bred} [*] Crobat		[NO]\n"; allinstalled=false;}
	eval type -P waybackurls $DEBUG_STD || { printf "${bred} [*] Waybackurls		[NO]\n"; allinstalled=false;}
	eval type -P gau $DEBUG_STD || { printf "${bred} [*] Gau		[NO]\n"; allinstalled=false;}
	eval type -P shuffledns $DEBUG_STD || { printf "${bred} [*] ShuffleDns		[NO]\n"; allinstalled=false;}
	eval type -P subjack $DEBUG_STD || { printf "${bred} [*] Subjack		[NO]\n"; allinstalled=false;}
	[ -f $tools/subjack/fingerprints.json ] || { printf "${bred} [*] Subjack fingers 	[NO]\n"; allinstalled=false;}
	eval type -P nuclei $DEBUG_STD || { printf "${bred} [*] Nuclei		[NO]\n"; allinstalled=false;}
	[ -d ~/nuclei-templates ] || { printf "${bred} [*] Nuclei templates    [NO]\n"; allinstalled=false;}
	eval type -P aquatone $DEBUG_STD || { printf "${bred} [*] Aquatone		[NO]\n"; allinstalled=false;}
	eval type -P naabu $DEBUG_STD || { printf "${bred} [*] Naabu		[NO]\n"; allinstalled=false;}
	eval type -P gf $DEBUG_STD || { printf "${bred} [*] Gf		[NO]\n"; allinstalled=false;}
	eval type -P Gxss $DEBUG_STD || { printf "${bred} [*] Gxss		[NO]\n"; allinstalled=false;}
	eval type -P subjs $DEBUG_STD || { printf "${bred} [*] subjs		[NO]\n"; allinstalled=false;}
	eval type -P dalfox $DEBUG_STD || { printf "${bred} [*] dalfox		[NO]\n"; allinstalled=false;}
	eval type -P git-hound $DEBUG_STD || { printf "${bred} [*] git-hound		[NO]\n"; allinstalled=false;}
	eval type -P ffuf $DEBUG_STD || { printf "${bred} [*] ffuf		[NO]\n"; allinstalled=false;}
	eval type -P massdns $DEBUG_STD || { printf "${bred} [*] Massdns		[NO]\n"; allinstalled=false;}
	eval type -P qsreplace $DEBUG_STD || { printf "${bred} [*] qsreplace		[NO]\n"; allinstalled=false;}
	eval type -P interlace $DEBUG_STD || { printf "${bred} [*] interlace		[NO]\n"; allinstalled=false;}
	eval type -P dnsgen $DEBUG_STD || { printf "${bred} [*] DnsGen		[NO]\n"; allinstalled=false;}
	eval type -P pymeta $DEBUG_STD || { printf "${bred} [*] pymeta		[NO]\n"; allinstalled=false;}
	eval type -P anew $DEBUG_STD || { printf "${bred} [*] Anew		[NO]\n"; allinstalled=false;}
	eval type -P unfurl $DEBUG_STD || { printf "${bred} [*] unfurl		[NO]\n"; allinstalled=false;}
	eval type -P crlfuzz $DEBUG_STD || { printf "${bred} [*] crlfuzz		[NO]\n"; allinstalled=false;}
	eval type -P httpx $DEBUG_STD || { printf "${bred} [*] Httpx		[NO]\n${reset}"; allinstalled=false;}
	eval type -P jq $DEBUG_STD || { printf "${bred} [*] jq			[NO]\n${reset}"; allinstalled=false;}

	if [ "${allinstalled}" = true ] ; then
		printf "${bgreen} Good! All installed! ${reset}\n\n"
	else
		printf "\n${yellow} Try running the installer script again ./install.sh"
		printf "\n${yellow} If it fails for any reason try to install manually the tools missed"
		printf "\n${yellow} Finally remember to set the ${bred}\$tools${yellow} variable at the start of this script"
		printf "\n${yellow} If nothing works and the world is gonna end you can always ping me :D ${reset}\n\n"
	fi

	printf "${bblue} Tools check finished\n"
	printf "${bgreen}#######################################################################\n"
}

function tools_full(){

	printf "\n\n${bgreen}#######################################################################\n"
	printf "${bblue} Checking installed tools ${reset}\n\n"
	[ -n "$GOPATH" ] && printf "${bgreen}[*] GOPATH var		[YES]\n" || { printf "${bred} [*] GOPATH var		[NO]\n"; }
	[ -n "$GOROOT" ] && printf "${bgreen}[*] GOROOT var		[YES]\n" || { printf "${bred} [*] GOROOT var		[NO]\n"; }
	[ -n "$PATH" ] && printf "${bgreen}[*] PATH var		[YES]\n" || { printf "${bred} [*] PATH var		[NO]\n"; }
	[ -f $tools/degoogle_hunter/degoogle.py ] && printf "${bgreen}[*] degoogle		[YES]\n" || printf "${bred} [*] degoogle		[NO]\n"
	[ -f $tools/ParamSpider/paramspider.py ] && printf "${bgreen}[*] Paramspider		[YES]\n" || printf "${bred} [*] Paramspider	[NO]\n"
	[ -f $tools/Arjun/arjun.py ] && printf "${bgreen}[*] Arjun		[YES]\n" || printf "${bred} [*] Arjun		[NO]\n"
	[ -f $tools/fav-up/favUp.py ] && printf "${bgreen}[*] fav-up		[YES]\n" || printf "${bred} [*] fav-up		[NO]\n"
	[ -f $tools/Corsy/corsy.py ] && printf "${bgreen}[*] Corsy		[YES]\n" || printf "${bred} [*] Corsy		[NO]\n"
	[ -f $tools/testssl.sh/testssl.sh ] && printf "${bgreen}[*] testssl		[YES]\n" || printf "${bred} [*] testssl		[NO]\n"
	[ -f $tools/JSFinder/JSFinder.py ] && printf "${bgreen}[*] JSFinder		[YES]\n" || printf "${bred} [*] JSFinder	[NO]\n"
	[ -f $tools/CMSeeK/cmseek.py ] && printf "${bgreen}[*] CMSeeK		[YES]\n" || printf "${bred} [*] CMSeeK	[NO]\n"
	[ -f $tools/fuzz_wordlist.txt ] && printf "${bgreen}[*] OneListForAll	[YES]\n" || printf "${bred} [*] OneListForAll	[NO]\n"
	[ -f $tools/LinkFinder/linkfinder.py ] && printf "${bgreen}[*] LinkFinder	        [YES]\n" || printf "${bred} [*] LinkFinder	        [NO]\n"
	[ -f $tools/github-endpoints.py ] && printf "${bgreen}[*] github-endpoints	[YES]\n" || printf "${bred} [*] github-endpoints[NO]\n"
	[ -f $tools/degoogle_hunter/degoogle_hunter.sh ] && printf "${bgreen}[*] degoogle_hunter	[YES]\n" || printf "${bred} [*] degoogle_hunter	[NO]\n"
	[ -f $tools/github-search/github-endpoints.py ] && printf "${bgreen}[*] github-search	[YES]\n" || printf "${bred} [*] github-search	[NO]\n"
	[ -f $tools/getjswords.py ] && printf "${bgreen}[*] getjswords.py	[YES]\n" || printf "${bred} [*] getjswords.py	[NO]\n"
	[ -f $tools/subdomains.txt ] && printf "${bgreen}[*] subdomains.txt	[YES]\n" || printf "${bred} [*] subdomains.txt	[NO]\n"
	[ -f $tools/resolvers.txt ] && printf "${bgreen}[*] resolvers.txt	[YES]\n" || printf "${bred} [*] resolvers.txt	[NO]\n"
	eval type -P hakrawler $DEBUG_STD && printf "${bgreen}[*] hakrawler		[YES]\n" || { printf "${bred} [*] hakrawler		[NO]\n"; }
	eval type -P subfinder $DEBUG_STD && printf "${bgreen}[*] Subfinder		[YES]\n" || { printf "${bred} [*] Subfinder		[NO]\n"; }
	eval type -P assetfinder $DEBUG_STD && printf "${bgreen}[*] Assetfinder		[YES]\n" || { printf "${bred} [*] Assetfinder	[NO]\n"; }
	eval type -P findomain $DEBUG_STD && printf "${bgreen}[*] Findomain		[YES]\n" || { printf "${bred} [*] Findomain		[NO]\n"; }
	eval type -P amass $DEBUG_STD && printf "${bgreen}[*] Amass		[YES]\n" || { printf "${bred} [*] Amass		[NO]\n"; }
	eval type -P crobat $DEBUG_STD && printf "${bgreen}[*] Crobat		[YES]\n" || { printf "${bred} [*] Crobat		[NO]\n"; }
	eval type -P waybackurls $DEBUG_STD && printf "${bgreen}[*] Waybackurls		[YES]\n" || { printf "${bred} [*] Waybackurls	[NO]\n"; }
	eval type -P gau $DEBUG_STD && printf "${bgreen}[*] Gau		        [YES]\n" || { printf "${bred} [*] Gau		[NO]\n"; }
	eval type -P shuffledns $DEBUG_STD && printf "${bgreen}[*] ShuffleDns		[YES]\n" || { printf "${bred} [*] ShuffleDns		[NO]\n"; }
	eval type -P subjack $DEBUG_STD && printf "${bgreen}[*] Subjack		[YES]\n" || { printf "${bred} [*] Subjack		[NO]\n"; }
	[ -f $tools/subjack/fingerprints.json ] && printf "${bgreen}[*] Subjack fings	[YES]\n" || printf "${bred} [*] Subjack fings	[NO]\n"
	eval type -P nuclei $DEBUG_STD && printf "${bgreen}[*] Nuclei		[YES]\n" || { printf "${bred} [*] Nuclei		[NO]\n"; }
	[ -d ~/nuclei-templates ] && printf "${bgreen}[*] Nuclei templates  	[YES]\n" || printf "${bred} [*] Nuclei templates  	[NO]\n"
	eval type -P aquatone $DEBUG_STD && printf "${bgreen}[*] Aquatone		[YES]\n" || { printf "${bred} [*] Aquatone		[NO]\n"; }
	eval type -P naabu $DEBUG_STD && printf "${bgreen}[*] Naabu		[YES]\n" || { printf "${bred} [*] Naabu		[NO]\n"; }
	eval type -P gf $DEBUG_STD && printf "${bgreen}[*] Gf		        [YES]\n" || { printf "${bred} [*] Gf			[NO]\n"; }
	eval type -P Gxss $DEBUG_STD && printf "${bgreen}[*] Gxss		[YES]\n" || { printf "${bred} [*] Gxss		[NO]\n"; }
	eval type -P subjs $DEBUG_STD && printf "${bgreen}[*] subjs		[YES]\n" || { printf "${bred} [*] subjs		[NO]\n"; }
	eval type -P dalfox $DEBUG_STD && printf "${bgreen}[*] dalfox		[YES]\n" || { printf "${bred} [*] dalfox		[NO]\n"; }
	eval type -P git-hound $DEBUG_STD && printf "${bgreen}[*] git-hound		[YES]\n" || { printf "${bred} [*] git-hound		[NO]\n"; }
	eval type -P ffuf $DEBUG_STD && printf "${bgreen}[*] ffuf		[YES]\n" || { printf "${bred} [*] ffuf		[NO]\n"; }
	eval type -P massdns $DEBUG_STD && printf "${bgreen}[*] Massdns		[YES]\n" || { printf "${bred} [*] Massdns		[NO]\n"; }
	eval type -P qsreplace $DEBUG_STD && printf "${bgreen}[*] qsreplace		[YES]\n" || { printf "${bred} [*] qsreplace		[NO]\n"; }
	eval type -P interlace $DEBUG_STD && printf "${bgreen}[*] interlace		[YES]\n" || { printf "${bred} [*] interlace		[NO]\n"; }
	eval type -P dnsgen $DEBUG_STD && printf "${bgreen}[*] DnsGen		[YES]\n" || { printf "${bred} [*] DnsGen		[NO]\n"; }
	eval type -P pymeta $DEBUG_STD && printf "${bgreen}[*] pymeta		[YES]\n" || { printf "${bred} [*] pymeta		[NO]\n"; }
	eval type -P anew $DEBUG_STD && printf "${bgreen}[*] Anew		[YES]\n" || { printf "${bred} [*] Anew		[NO]\n"; }
	eval type -P unfurl $DEBUG_STD && printf "${bgreen}[*] unfurl		[YES]\n" || { printf "${bred} [*] unfurl		[NO]\n"; }
	eval type -P crlfuzz $DEBUG_STD && printf "${bgreen}[*] crlfuzz		[YES]\n" || { printf "${bred} [*] crlfuzz		[NO]\n"; }
	eval type -P httpx $DEBUG_STD && printf "${bgreen}[*] Httpx		[YES]\n${reset}" || { printf "${bred} [*] Httpx		[NO]\n${reset}"; }
	eval type -P jq $DEBUG_STD && printf "${bgreen}[*] jq			[YES]\n${reset}" || { printf "${bred} [*] jq			[NO]\n${reset}"; }

	printf "\n${yellow} If any tool is not installed under $tools, I trust in your ability to install it :D\n Also remember to set the ${bred}\$tools${yellow} variable at the start of this script.\n If you have any problem you can always ping me ;) ${reset}\n\n"
	printf "${bblue} Tools check finished\n"
	printf "${bgreen}#######################################################################\n"
}

dorks(){
	printf "${bgreen}#######################################################################\n"
	printf "${bblue} Performing Google Dorks ${reset}\n\n"

	$tools/degoogle_hunter/degoogle_hunter.sh $domain | tee ${domain}_dorks.txt
	sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" ${domain}_dorks.txt

	printf "${bblue} Finished : ${bblue} Happy hunting! ${reset}\n"
	printf "${bgreen}#######################################################################\n"
}

subdomains_full(){
	NUMOFLINES_subs="0"
	NUMOFLINES_probed="0"
	printf "${bgreen}#######################################################################\n\n"
	printf "${bblue} Subdomain Enumeration\n\n"
	sub_passive
	sub_brute
	sub_dns
	sub_scraping
	sub_permut
	webprobe_simple
	eval rm -f *_subs.txt $DEBUG_ERROR
	if [ -f "${domain}_subdomains.txt" ]
		then
			deleteOutScoped $outOfScope_file ${domain}_subdomains.txt
			NUMOFLINES_subs=$(wc -l < ${domain}_subdomains.txt)
	fi
	if [ -f "${domain}_probed.txt" ]
		then
			deleteOutScoped $outOfScope_file ${domain}_probed.txt
			NUMOFLINES_probed=$(wc -l < ${domain}_probed.txt)
	fi
	printf "${bblue}\n Final results: ${reset}\n"
	printf "${bred}\n - ${NUMOFLINES_subs} alive subdomains${reset}\n\n"
	eval cat ${domain}_subdomains.txt $DEBUG_ERROR | sort
	printf "${bred}\n - ${NUMOFLINES_probed} web probed${reset}\n\n"
	eval cat ${domain}_probed.txt $DEBUG_ERROR | sort
	printf "${bblue}\n Subdomain Enumeration Finished\n"
	printf "${bblue} Results are saved in ${domain}_subdomains.txt and ${domain}_probed.txt${reset}\n"
	printf "${bgreen}#######################################################################\n\n"
}

sub_passive(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			start=`date +%s`
			printf "${yellow} Running : Passive Subdomain Enumeration 1/6${reset}\n"
			eval subfinder -d $domain -o subfinder.txt $DEBUG_STD
			assetfinder --subs-only $domain | anew -q assetfinder.txt
			eval amass enum -passive -d $domain -o amass.txt $DEBUG_STD
			eval findomain --quiet -t $domain -u findomain.txt $DEBUG_STD
			crobat -s $domain | anew -q crobat.txt
			timeout 5m waybackurls $domain | unfurl -u domains | anew -q waybackurls.txt
			eval cat subfinder.txt assetfinder.txt amass.txt findomain.txt crobat.txt waybackurls.txt $DEBUG_ERROR | sed "s/*.//" | anew -q passive_subs.txt && touch $called_fn_dir/.${FUNCNAME[0]}
			eval rm subfinder.txt assetfinder.txt amass.txt findomain.txt crobat.txt waybackurls.txt $DEBUG_ERROR
			NUMOFLINES=$(wc -l < passive_subs.txt)
			end=`date +%s`
			getElapsedTime $start $end
			printf "${green} ${NUMOFLINES} subdomains found in ${runtime}${reset}\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

sub_brute(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			start=`date +%s`
			printf "${yellow} Running : Bruteforce Subdomain Enumeration 2/6${reset}\n"
			eval shuffledns -d $domain -w $tools/subdomains.txt -r $tools/resolvers.txt -o active_tmp.txt $DEBUG_STD
			cat active_tmp.txt | sed "s/*.//" | anew -q brute_subs.txt && touch $called_fn_dir/.${FUNCNAME[0]}
			eval rm active_tmp.txt $DEBUG_ERROR
			NUMOFLINES=$(wc -l < brute_subs.txt)
			end=`date +%s`
			getElapsedTime $start $end
			printf "${green} ${NUMOFLINES} subdomains found in ${runtime}${reset}\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

sub_dns(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			start=`date +%s`
			printf "${yellow} Running : Active Subdomain Enumeration 3/6${reset}\n"
			cat *_subs.txt | anew -q tmp_subs_resolution.txt
			deleteOutScoped $outOfScope_file tmp_subs_resolution.txt
			eval shuffledns -d $domain -list tmp_subs_resolution.txt -r $tools/resolvers.txt -o ${domain}_subdomains.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			NUMOFLINES=$(wc -l < ${domain}_subdomains.txt)
			end=`date +%s`
			getElapsedTime $start $end
			printf "${green} ${NUMOFLINES} subdomains found in ${runtime}${reset}\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

sub_scraping(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			start=`date +%s`
			printf "${yellow} Running : JS scraping subdomain search 4/6${reset}\n"
			touch JS_subs.txt
			cat ${domain}_subdomains.txt | httpx -follow-redirects -status-code -vhost -threads 100 -silent | sort -u | grep "[200]" | cut -d [ -f1 | sort -u | sed 's/[[:blank:]]*$//' | anew -q ${domain}_probed_tmp.txt
			eval python3 $tools/JSFinder/JSFinder.py -f ${domain}_probed_tmp.txt -os JS_subs.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			if [[ $(cat JS_subs.txt | wc -l) -gt 0 ]]
			then
				NUMOFLINES=$(wc -l < JS_subs.txt)
				cat JS_subs.txt | eval shuffledns -d $domain -r $tools/resolvers.txt -o JS_subs_temp.txt $DEBUG_STD
				cat JS_subs_temp.txt | anew -q ${domain}_subdomains.txt
				eval rm JS_subs_temp.txt ${domain}_probed_tmp.txt $DEBUG_ERROR
			else
				NUMOFLINES=0
			fi
			end=`date +%s`
			getElapsedTime $start $end
			printf "${green} ${NUMOFLINES} subdomains found in ${runtime}${reset}\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

sub_permut(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			start=`date +%s`
			printf "${yellow} Running : Permutations Subdomain Enumeration 5/6${reset}\n"
			if [[ $(cat tmp_subs_resolution.txt | wc -l) -le 100 ]]
				then
					eval dnsgen tmp_subs_resolution.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $tools/resolvers.txt -o permute1_tmp.txt $DEBUG_STD
					cat permute1_tmp.txt | anew -q permute1.txt
					eval dnsgen permute1.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $tools/resolvers.txt -o permute2_tmp.txt $DEBUG_STD
					cat permute2_tmp.txt | anew -q permute2.txt
					cat permute1.txt permute2.txt | anew -q permute_subs.txt
					eval rm permute1.txt permute1_tmp.txt permute2.txt permute2_tmp.txt tmp_subs_resolution.txt $DEBUG_ERROR && touch $called_fn_dir/.${FUNCNAME[0]}
				elif [[ $(cat tmp_subs_resolution.txt | wc -l) -le 200 ]]
		  		then
					eval dnsgen tmp_subs_resolution.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $tools/resolvers.txt -o permute_tmp.txt $DEBUG_STD
					cat permute_tmp.txt | anew -q permute_subs.txt
					eval rm permute_tmp.txt tmp_subs_resolution.txt $DEBUG_ERROR  && touch $called_fn_dir/.${FUNCNAME[0]}
				else
		  			printf "\n${bred} Skipping Permutations: Too Much Subdomains${reset}\n"
			fi
			if [ -f "permute_subs.txt" ]
			then
				deleteOutScoped $outOfScope_file permute_subs.txt
				NUMOFLINES=$(wc -l < permute_subs.txt)
				cat permute_subs.txt | anew -q ${domain}_subdomains.txt
			else
				NUMOFLINES=0
			fi
			end=`date +%s`
			getElapsedTime $start $end
			printf "${green} ${NUMOFLINES} subdomains found in ${runtime}${reset}\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

webprobe_simple(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			start=`date +%s`
			printf "${yellow} Running : Http probing 6/6${reset}\n\n"
			cat ${domain}_subdomains.txt | httpx -follow-redirects -status-code -vhost -threads 100 -silent | sort -u | grep "[200]" | cut -d [ -f1 | sort -u | sed 's/[[:blank:]]*$//' | anew -q ${domain}_probed.txt && touch $called_fn_dir/.${FUNCNAME[0]}
			if [ -f "${domain}_probed.txt" ]
			then
				deleteOutScoped $outOfScope_file ${domain}_probed.txt
				NUMOFLINES=$(wc -l < ${domain}_probed.txt)
			else
				NUMOFLINES=0
			fi
			end=`date +%s`
			getElapsedTime $start $end
			printf "${green} ${NUMOFLINES} subdomains resolved in ${runtime}${reset}\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

subtakeover(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Subdomain Takeover ${reset}\n\n"
			start=`date +%s`
			eval subjack -w ${domain}_subdomains.txt -a -ssl -t 50 -v -c $tools/subjack/fingerprints.json -ssl -o ${domain}_all-takeover-checks.txt $DEBUG_STD;
			grep -v "Not Vulnerable" <${domain}_all-takeover-checks.txt > ${domain}_takeover.txt
			eval rm ${domain}_all-takeover-checks.txt $DEBUG_ERROR && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ -f "${domain}_takeover.txt" ]
			then
				NUMOFLINES=$(wc -l < ${domain}_takeover.txt)
			else
				NUMOFLINES=0
			fi
			printf "${bred}\n Subtko: ${NUMOFLINES} subdomains in ${runtime}${reset}\n\n"
			eval cat ${domain}_takeover.txt $DEBUG_ERROR
			printf "${bblue}\n Subdomain Takeover Finished\n"
			printf "${bblue} Results are saved in ${domain}_takeover.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

webprobe_full(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} ${bgreen} Web Probe ${reset}\n\n"
			printf "${yellow} Running : Http probing non standard ports${reset}\n\n"
			start=`date +%s`
			cat ${domain}_subdomains.txt | httpx -ports 81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55672 -follow-redirects -status-code -vhost -threads 100 -silent | sort -u | grep "[200]" | cut -d [ -f1 | sort -u | sed 's/[[:blank:]]*$//' | anew -q ${domain}_probed_uncommon_ports.txt && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			NUMOFLINES=$(wc -l < ${domain}_probed_uncommon_ports.txt)
			printf "${bred}\n Uncommon web ports: ${NUMOFLINES} subdomains in ${runtime}${reset}\n\n"
			eval cat ${domain}_probed_uncommon_ports.txt $DEBUG_ERROR
			printf "${bblue}\n Web Probe Finished\n"
			printf "${bblue} Results are saved in ${domain}_takeover.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

screenshot(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} ${bgreen} Web Screenshot ${reset}\n\n"
			start=`date +%s`
			cat ${domain}_probed.txt | aquatone -out screenshots -threads 8 -silent && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Web Screenshot Finished in ${runtime}\n"
			printf "${bblue} Results are saved in in screenshots/aquatone_report.html folder${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

metadata(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} ${bgreen} Metadata Checks ${reset}\n\n"
			start=`date +%s`
			mkdir -p $dir/metadata
			pymeta -d ${domain} -s all -m 500 -j 5 -o $dir/metadata -f ${domain}_metadata.csv && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Metadata Checks  Finished in ${runtime}\n"
			printf "${bblue} Results are saved in in metadata folder and ${domain}_metadata.csv ${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

portscan(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Port Scan ${reset}\n\n"
			start=`date +%s`
			naabu -top-ports 1000 -silent -exclude-cdn -nmap-cli 'nmap -sV --script /usr/share/nmap/scripts/vulners.nse,http-title.nse --min-rate 40000 -T4 --max-retries 2' -iL ${domain}_subdomains.txt > ${domain}_portscan.txt;
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bred}\n Port scan results in ${runtime}${reset}\n\n"
			eval cat ${domain}_portscan.txt $DEBUG_ERROR && touch $called_fn_dir/.${FUNCNAME[0]}
			printf "\n"
			printf "${bblue}\n Port Scan Finished\n"
			printf "${bblue} Results are saved in in ${domain}_portscan.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

nuclei_check(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Template Scanning with Nuclei ${reset}\n\n"
			start=`date +%s`
			printf "${yellow} Running : Nuclei Technologies${reset}\n\n"
			cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/technologies/ -o ${domain}_nuclei_technologies.txt;
			printf "${yellow}\n\n Running : Nuclei Tokens${reset}\n\n"
			cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/exposed-tokens/ -o ${domain}_nuclei_tokens.txt;
			printf "${yellow}\n\n Running : Nuclei Exposures${reset}\n\n"
			cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/exposures/ -o ${domain}_nuclei_exposures.txt;
			printf "${yellow}\n\n Running : Nuclei CVEs ${reset}\n\n"
			cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/cves/ -o ${domain}_nuclei_cves.txt;
			printf "${yellow}\n\n Running : Nuclei Default Creds ${reset}\n\n"
			cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/default-logins/ -o ${domain}_nuclei_default_creds.txt;
			printf "${yellow}\n\n Running : Nuclei SubTko ${reset}\n\n"
			cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/takeovers/ -o ${domain}_nuclei_subtko.txt;
			printf "${yellow}\n\n Running : Nuclei DNS ${reset}\n\n"
			cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/dns/ -o ${domain}_nuclei_dns.txt;
			printf "${yellow}\n\n Running : Nuclei Miscellaneous ${reset}\n\n"
			cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/miscellaneous/ -o ${domain}_nuclei_miscellaneous.txt;
			printf "${yellow}\n\n Running : Nuclei Panels ${reset}\n\n"
			cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/exposed-panels/ -o ${domain}_nuclei_panels.txt;
			printf "${yellow}\n\n Running : Nuclei Security Misconfiguration ${reset}\n\n"
			cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/misconfiguration/ -o ${domain}_nuclei_misconfigurations.txt;
			printf "${yellow}\n\n Running : Nuclei Vulnerabilites ${reset}\n\n"
			cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/vulnerabilities/ -o ${domain}_nuclei_vulnerabilities.txt && touch $called_fn_dir/.${FUNCNAME[0]};
			printf "\n\n"
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Port Scan Finished in ${runtime}\n"
			printf "${bblue} Results are saved in in ${domain}_nuclei_*.txt files${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

urlchecks(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} URL Extraction ${reset}\n\n"
			start=`date +%s`
			cat ${domain}_probed.txt | waybackurls | anew -q ${domain}_url_extract.txt
			cat ${domain}_probed.txt | gau | anew -q ${domain}_url_extract.txt
			cat ${domain}_probed.txt | hakrawler -depth 2 -scope subs -plain -insecure | anew -q ${domain}_url_extract.txt
			if [ -n "$GITHUB_TOKEN" ]; then
				python3 $tools/github-endpoints.py -d $domain -t $GITHUB_TOKEN | anew -q ${domain}_url_extract.txt  && touch $called_fn_dir/.${FUNCNAME[0]}
			else
				python3 $tools/github-endpoints.py -d $domain | anew -q ${domain}_url_extract.txt  && touch $called_fn_dir/.${FUNCNAME[0]}
			fi
			end=`date +%s`
			getElapsedTime $start $end
			NUMOFLINES=$(wc -l < ${domain}_url_extract.txt)
			printf "${bblue}\n URL Extraction Finished\n"
			printf "${bblue}\n ${NUMOFLINES} in ${runtime}\n"
			printf "${bblue} Results are saved in in ${domain}_url_extract.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

url_gf(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Vulnerable Pattern Search ${reset}\n\n"
			start=`date +%s`
			gf xss ${domain}_url_extract.txt | qsreplace -a | anew -q ${domain}_xss.txt;
			gf ssti ${domain}_url_extract.txt | qsreplace -a | anew -q ${domain}_ssti.txt;
			gf ssrf ${domain}_url_extract.txt | qsreplace -a | anew -q ${domain}_ssrf.txt;
			gf sqli ${domain}_url_extract.txt | qsreplace -a | anew -q ${domain}_sqli.txt;
			gf redirect ${domain}_url_extract.txt | qsreplace -a | anew -q ${domain}_redirect.txt;
			gf rce ${domain}_url_extract.txt | qsreplace -a | anew -q ${domain}_rce.txt;
			gf potential ${domain}_url_extract.txt | qsreplace -a | anew -q ${domain}_potential.txt;
			gf lfi ${domain}_url_extract.txt | qsreplace -a | anew -q ${domain}_lfi.txt && touch $called_fn_dir/.${FUNCNAME[0]};
			end=`date +%s`
			getElapsedTime $start $end
			cat ${domain}_url_extract.txt | unfurl -u format %s://%d%p | anew -q ${domain}_url_endpoints.txt
			printf "${bblue}\n Vulnerable Pattern Search Finished in ${runtime}\n"
			printf "${bblue} Results are saved in in ${domain}_*gfpattern*.txt files${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

jschecks(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Javascript Scan ${reset}\n\n"
			start=`date +%s`
			printf "${yellow} Running : Fetching Urls 1/5${reset}\n"
			cat ${domain}_url_extract.txt | grep -iE "\.js$" | anew -q ${domain}_jsfile_links.txt;
			cat ${domain}_url_extract.txt | subjs | anew -q ${domain}_jsfile_links.txt;
			printf "${yellow} Running : Resolving JS Urls 2/5${reset}\n"
			cat ${domain}_jsfile_links.txt | httpx -follow-redirects -silent -status-code | grep "[200]" | cut -d ' ' -f1 | anew -q ${domain}_js_livelinks.txt
			printf "${yellow} Running : Gathering endpoints 3/5${reset}\n"
			interlace -tL ${domain}_js_livelinks.txt -threads 10 -c "python3 $tools/LinkFinder/linkfinder.py -d -i _target_ -o cli >> ${domain}_js_endpoints.txt" &>/dev/null
			sed -i '/^Running against/d; /^Invalid input/d; /^$/d' ${domain}_js_endpoints.txt
			printf "${yellow} Running : Gathering secrets 4/5${reset}\n"
			cat ${domain}_js_livelinks.txt | nuclei -silent -t ~/nuclei-templates/exposed-tokens/ -o ${domain}_js_secrets.txt
			printf "${yellow} Running : Building wordlist 5/5${reset}\n"
			cat ${domain}_js_livelinks.txt | python3 $tools/getjswords.py | anew -q ${domain}_js_Wordlist.txt && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Javascript Scan Finished in ${runtime}\n"
			printf "${bblue} Results are saved in in ${domain}_js_*.txt files${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

params(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Parameter Discovery ${reset}\n"
			start=`date +%s`
			printf "${yellow}\n\n Running : Finding params with paramspider${reset}\n"
			interlace -tL ${domain}_probed.txt -threads 10 -c "python3 $tools/ParamSpider/paramspider.py -d _target_ -l high -q --exclude jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,js" &>/dev/null
			find output/ -name '*.txt' -exec cat {} \; | anew -q ${domain}_param.txt
			sed '/^FUZZ/d' -i ${domain}_param.txt
			eval rm -rf output/ $DEBUG_ERROR
			printf "${yellow}\n\n Running : Checking ${domain} with Arjun${reset}\n"
			eval python3 $tools/Arjun/arjun.py -i ${domain}_param.txt -t 20 -o ${domain}_arjun.json $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Parameter Discovery Finished in ${runtime}\n"
			printf "${bblue} Results are saved in in ${domain}_param.txt and ${domain}_arjun.json${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

xss(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} XSS Analysis ${reset}\n\n"
			start=`date +%s`
			# Set your own blind xss server, I will not advice you if I receive some data in my server :P
			# Xsstrike
			# Xsstrike blind payload defined in $tools/xsstrike/core/config.py
			# python xsstrike.py --seeds ${domain}_xss.txt -t 30 --timeout=4 --blind --skip
			if [ -n "$XSS_SERVER" ]; then
				cat ${domain}_xss.txt | Gxss -c 100 -p Xss | sort -u | eval dalfox -b six2dez.xss.ht pipe -o ${domain}_dalfox_xss.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
				end=`date +%s`
				getElapsedTime $start $end
			else
				printf "${bblue}\n No XSS_SERVER defined, blind xss skipped\n"
				cat ${domain}_xss.txt | Gxss -c 100 -p Xss | sort -u | eval dalfox pipe -o ${domain}_dalfox_xss.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
				end=`date +%s`
				getElapsedTime $start $end
			fi
			printf "${bblue} Results are saved in in ${domain}_dalfox_xss.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

github(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} GitHub Scanning ${reset}\n\n"
			start=`date +%s`
			cat ${domain}_probed.txt | git-hound --dig-files --dig-commits --threads 100 | tee ${domain}_gitrecon.txt && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n GitHub Scanning Finished in ${runtime}\n"
			printf "${bblue} Results are saved in in ${domain}_gitrecon.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

favicon(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} FavIcon Hash Extraction ${reset}\n\n"
			start=`date +%s`
			cd $tools/fav-up
			eval python3 favUp.py -w $domain -sc -o favicontest.json $DEBUG_STD
			mv favicontest.json $dir/favicontest.json
			cd $dir
			cat favicontest.json | jq > ${domain}_favicontest.txt
			rm favicontest.json
			eval cat ${domain}_favicontest.txt $DEBUG_ERROR | grep found_ips && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n FavIcon Hash Extraction Finished in ${runtime}\n"
			printf "${bblue} Results are saved in in ${domain}_favicontest.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

fuzz(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Directory Fuzzing ${reset}\n"
			printf "${yellow}\n\n Fuzzing subdomains with ${fuzz_wordlist}${reset}\n"
			start=`date +%s`
			mkdir -p $dir/fuzzing
			for sub in $(cat ${domain}_probed.txt); do
				printf "${yellow}\n\n Running: Fuzzing in ${sub}${reset}\n"
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				ffuf -mc all -ac -sf -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -w $fuzz_wordlist -maxtime 900 -u $sub/FUZZ -or -o $dir/fuzzing/${sub_out}.tmp $DEBUG_STD
				cat $dir/fuzzing/${sub_out}.tmp | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' | sed 's/\"//g' | anew -q $dir/fuzzing/${sub_out}.txt
				eval rm ${sub_out}.tmp $DEBUG_ERROR
			done
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Directory Fuzzing Finished in ${runtime}\n"
			printf "${bblue} Results are saved in fuzzing/*subdomain*.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

cms_scanner(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} CMS Scanner ${reset}\n"
			start=`date +%s`
			mkdir -p $dir/cms
			tr '\n' ',' < ${domain}_probed.txt > ${domain}_cms.txt
			eval python3 $tools/CMSeeK/cmseek.py -l ${domain}_cms.txt --batch -r $DEBUG_STD
			for sub in $(cat ${domain}_probed.txt); do
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				mv $tools/CMSeeK/Result/${sub_out} $dir/cms/
			done
			eval rm ${domain}_cms.txt $DEBUG_ERROR
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n CMS Scanner finished in ${runtime}\n"
			printf "${bblue} Results are saved in cms/*subdomain* folder${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

cors(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} CORS Scan ${reset}\n\n"
			start=`date +%s`
			eval python3 $tools/Corsy/corsy.py -i ${domain}_probed.txt -t 200 > ${domain}_cors.txt $DEBUG_STD
			eval cat ${domain}_cors.txt $DEBUG_ERROR && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n CORS Scan Finished in ${runtime}\n"
			printf "${bblue} Results are saved in ${domain}_cors.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

test_ssl(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} SSL Test ${reset}\n"
			start=`date +%s`
			$tools/testssl.sh/testssl.sh --quiet --color 0 -U -iL ${domain}_subdomains.txt > ${domain}_testssl.txt && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n SSL Test Finished in ${runtime}\n"
			printf "${bblue} Results are saved in ${domain}_testssl.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

open_redirect(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Open redirects checks ${reset}\n"
			start=`date +%s`
			cat ${domain}_redirect.txt | qsreplace FUZZ | anew -q test_redirect.txt
			eval python3 $tools/OpenRedireX/openredirex.py -l test_redirect.txt --keyword FUZZ > ${domain}_openredirex.txt $DEBUG_STD
			eval rm test_redirect.txt $DEBUG_ERROR && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Open Redirects Finished in ${runtime}\n"
			printf "${bblue} Results are saved in ${domain}_openredirex.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

ssrf_checks(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} SSRF checks ${reset}\n"
			if [ -n "$COLLAB_SERVER" ]; then
				start=`date +%s`
				eval cat ${domain}_ssrf.txt $DEBUG_ERROR | eval python3 $tools/ssrf.py $COLLAB_SERVER > ${domain}_ssrf_confirmed.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
				end=`date +%s`
				getElapsedTime $start $end
				printf "${bblue}\n SSRF Finished in ${runtime}\n"
			else
				printf "${bblue}\n No COLLAB_SERVER defined\n"
			fi
			printf "${bblue} Results are saved in ${domain}_ssrf_confirmed.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

crlf_checks(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} CRLF checks ${reset}\n"
			start=`date +%s`
			eval crlfuzz -l ${domain}_probed.txt -o ${domain}_crlf.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n CRLF Finished in ${runtime}${reset}\n"
			printf "${bblue} Results are saved in ${domain}_crlf.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${NUMOFLINES} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

deleteOutScoped(){
	if [ -z "$1" ]
	then
		cat $1 | while read outscoped
		do
			if  grep -q  "^[*]" <<< $outscoped
			then
				outscoped="${outscoped:1}"
				sed -i /"$outscoped$"/d  $2
			else
			sed -i /$outscoped/d  $2
			fi
		done
	fi
}

function getElapsedTime {
	runtime=""
	local T=$2-$1
	local D=$((T/60/60/24))
	local H=$((T/60/60%24))
	local M=$((T/60%60))
	local S=$((T%60))
	(( $D > 0 )) && runtime="$runtime$D days, "
	(( $H > 0 )) && runtime="$runtime$H hours, "
	(( $M > 0 )) && runtime="$runtime$M minutes, "
	runtime="$runtime$S seconds."
	#echo "$retVal"
}

end(){
	if [ -n "$dir_output" ]
	then
		output
		finaldir=$dir_output
	fi
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Finished Recon on: ${domain} under ${finaldir} ${reset}\n"
	printf "${bgreen}#######################################################################\n"
}

all(){
	if [ -n "$list" ]
	then
		for domain in $(cat $list); do
			start
			dorks
			subdomains_full
			subtakeover
			webprobe_full
			screenshot
#			metadata
			portscan
			nuclei_check
			github
			favicon
			cms_scanner
			fuzz
			cors
			urlchecks
			url_gf
			open_redirect
			ssrf_checks
			crlf_checks
			jschecks
			params
			xss
			test_ssl
			end
		done
	else
		start
		dorks
		subdomains_full
		subtakeover
		webprobe_full
		screenshot
#		metadata
		portscan
		nuclei_check
		github
		favicon
		cms_scanner
		fuzz
		cors
		urlchecks
		url_gf
		open_redirect
		ssrf_checks
		crlf_checks
		jschecks
		params
		xss
		test_ssl
		end
	fi
}

help(){
	printf "\n Usage: $0 [-h] [-i] [-d DOMAIN] [-l list.txt] [-x oos.txt] [-a] [-g] [-w] "
	printf "\n           	      [-t] [-s] [--sp] [--sb] [--sr] [--ss] [--sw] [-v] [-o OUTPUT]\n\n"
	printf " ${bblue}TARGET OPTIONS${reset}\n"
	printf "   -d DOMAIN        Target domain\n"
	printf "   -l list.txt      Targets list, one per line\n"
	printf "   -x oos.txt       Exclude subdomains list (Out Of Scope)\n"
	printf " \n"
	printf " ${bblue}MODE OPTIONS${reset}\n"
	printf "   -a               Perform all checks\n"
	printf "   -s               Full subdomains scan (Subs, tko and probe)\n"
	printf "   -g               Google dorks searchs\n"
	printf "   -w               Perform web checks only without subs ${yellow}(-l required)${reset}\n"
	printf "   -t               Check subdomain takeover ${yellow}(-l required)${reset}\n"
	printf "   -i               Check all needed tools\n"
	printf "   -v               Debug/verbose mode, no file descriptor redir\n"
	printf "   -h               Show this help\n"
	printf " \n"
	printf " ${bblue}SUBDOMAIN OPTIONS${reset}\n"
	printf "   --sp             Passive subdomain scans\n"
	printf "   --sb             Bruteforce subdomain resolution \n"
	printf "   --sr             Subdomain permutations and resolution ${yellow}(-l required)${reset}\n"
	printf "   --ss             Subdomain scan by scraping ${yellow}(-l required)${reset}\n"
	printf " \n"
	printf " ${bblue}OUTPUT OPTIONS${reset}\n"
	printf "   -o output/path   Define output folder\n"
	printf " \n"
	printf " ${bblue}USAGE EXAMPLES${reset}\n"
	printf " Full recon with custom output and excluded subdomains list:\n"
	printf " ./reconftw.sh -d example.com -x out.txt -a -o custom/path\n"
	printf " \n"
	printf " Full Subdomain scanning with multiple targets:\n"
	printf " ./reconftw.sh -l targets.txt -s\n"
	printf " \n"
	printf " Permutations subdomain scan:\n"
	printf " ./reconftw.sh -d example.com -l targets.txt --sr\n"
	printf " \n"
	printf " Web scanning for subdomain list:\n"
	printf " ./reconftw.sh -d example.com -l targets.txt -w\n"
}

output(){
	mkdir -p $dir_output
	mv $dir $dir_output
}

banner

if [ -z "$1" ]
then
   help
   tools_installed
   exit
fi

while getopts ":hd:-:l:x:vaisxwgto:" opt; do
	verbose=$@
	if [[ $verbose == *"-v"* ]]; then
  		unset DEBUG_STD
		unset DEBUG_ERROR
	fi
	case ${opt} in
		d ) domain=$OPTARG
			;;
		l ) list=$OPTARG
			;;
		x ) outOfScope_file=$OPTARG
			;;
		s ) if [ -n "$list" ]
			then
				for domain in $(cat $list); do
					start
					subdomains_full
					subtakeover
					end
				done
			else
				start
				subdomains_full
				subtakeover
				end
			fi
			exit
			;;
		a ) all
			exit
			;;
		w ) start
			if [ -n "$list" ]
			then
				cp $list $dir/${domain}_probed.txt
			fi
			nuclei_check
			cms_scanner
			fuzz
			cors
			urlchecks
			url_gf
			open_redirect
			ssrf_checks
			crlf_checks
			jschecks
			params
			xss
			test_ssl
			end
			exit
			;;
		t ) start
			if [ -n "$list" ]
			then
				cp $list $dir/${domain}_subdomains.txt
			fi
			subtakeover
			end
			;;
		g ) start
			dorks
			end
			;;
		i ) tools_full
			exit
			;;
		-)  case "${OPTARG}" in
				sp)	if [ -n "$list" ]
					then
						for domain in $(cat $list); do
							start
							sub_passive
							sub_dns
							webprobe_simple
							end
						done
					else
						start
						sub_passive
						sub_dns
						webprobe_simple
						end
					fi
					exit
					;;
				sb)	if [ -n "$list" ]
					then
						for domain in $(cat $list); do
							start
							sub_brute
							sub_dns
							webprobe_simple
							end
						done
					else
						start
						sub_brute
						sub_dns
						webprobe_simple
						end
					fi
					exit
					;;
				sr) start
					cp $list $dir/${domain}_subdomains.txt
					sub_permut
					end
					exit
					;;
				ss)	start
					cp $list $dir/${domain}_subdomains.txt
					sub_scraping
					end
					exit
					;;
			esac;;
		o ) dir_output=$OPTARG
			output
			;;
		\? | h | : | * )
			help
			;;
	esac
done
shift $((OPTIND -1))
