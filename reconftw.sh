#!/usr/bin/env bash

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
	printf " ${reconftw_version}                                 by @six2dez${reset}\n"
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
	[ -f "$tools/uDork/uDork.sh" ] || { printf "${bred} [*] uDork		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/brutespray/brutespray.py" ] || { printf "${bred} [*] brutespray	[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/dnsrecon/dnsrecon.py" ] || { printf "${bred} [*] dnsrecon	[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/fav-up/favUp.py" ] || { printf "${bred} [*] fav-up		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/Corsy/corsy.py" ] || { printf "${bred} [*] Corsy		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/testssl.sh/testssl.sh" ] || { printf "${bred} [*] testssl		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/CMSeeK/cmseek.py" ] || { printf "${bred} [*] CMSeeK		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/ctfr/ctfr.py" ] || { printf "${bred} [*] ctfr		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/fuzz_wordlist.txt" ] || { printf "${bred} [*] OneListForAll	[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/LinkFinder/linkfinder.py" ] || { printf "${bred} [*] LinkFinder		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/GitDorker/GitDorker.py" ] || { printf "${bred} [*] GitDorker		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/commix/commix.py" ] || { printf "${bred} [*] commix		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/getjswords.py" ] || { printf "${bred} [*] getjswords   	[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/JSA/jsa.py" ] || { printf "${bred} [*] JSA		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/cloud_enum/cloud_enum.py" ] || { printf "${bred} [*] cloud_enum		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/ultimate-nmap-parser/ultimate-nmap-parser.sh" ] || { printf "${bred} [*] nmap-parse-output		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/pydictor/pydictor.py" ] || { printf "${bred} [*] pydictor   	[NO]${reset}\n"; allinstalled=false;}
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
	type -P waybackurls &>/dev/null || { printf "${bred} [*] Waybackurls	[NO]${reset}\n"; allinstalled=false;}
	type -P gau &>/dev/null || { printf "${bred} [*] gau		[NO]${reset}\n"; allinstalled=false;}
	type -P dnsx &>/dev/null || { printf "${bred} [*] dnsx		[NO]${reset}\n"; allinstalled=false;}
	type -P gotator &>/dev/null || { printf "${bred} [*] gotator		[NO]${reset}\n"; allinstalled=false;}
	type -P cf-check &>/dev/null || { printf "${bred} [*] Cf-check		[NO]${reset}\n"; allinstalled=false;}
	type -P nuclei &>/dev/null || { printf "${bred} [*] Nuclei		[NO]${reset}\n"; allinstalled=false;}
	[ -d ~/nuclei-templates ] || { printf "${bred} [*] Nuclei templates	[NO]${reset}\n"; allinstalled=false;}
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
	type -P unimap &>/dev/null || { printf "${bred} [*] unimap		[NO]${reset}\n${reset}"; allinstalled=false;}
	type -P resolveDomains &>/dev/null || { printf "${bred} [*] resolveDomains	[NO]${reset}\n"; allinstalled=false;}
	type -P emailfinder &>/dev/null || { printf "${bred} [*] emailfinder	[NO]${reset}\n"; allinstalled=false;}
	type -P analyticsrelationships &>/dev/null || { printf "${bred} [*] analyticsrelationships	[NO]${reset}\n"; allinstalled=false;}
	type -P mapcidr &>/dev/null || { printf "${bred} [*] mapcidr		[NO]${reset}\n"; allinstalled=false;}
	type -P ppfuzz &>/dev/null || { printf "${bred} [*] ppfuzz		[NO]${reset}\n"; allinstalled=false;}
	type -P searchsploit &>/dev/null || { printf "${bred} [*] searchsploit	[NO]${reset}\n"; allinstalled=false;}
	type -P clouddetect &>/dev/null || { printf "${bred} [*] clouddetect	[NO]${reset}\n"; allinstalled=false;}
	type -P interactsh-client &>/dev/null || { printf "${bred} [*] interactsh-client	[NO]${reset}\n"; allinstalled=false;}
	type -P uro &>/dev/null || { printf "${bred} [*] uro		[NO]${reset}\n"; allinstalled=false;}
	type -P cero &>/dev/null || { printf "${bred} [*] cero		[NO]${reset}\n"; allinstalled=false;}
	type -P bbrf &>/dev/null || { printf "${bred} [*] bbrf		[NO]${reset}\n"; allinstalled=false;}
	
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
		start_func ${FUNCNAME[0]} "Google Dorks in process"
		eval sed -i "s/^cookies=\"c_user=HEREYOUCOOKIE; xs=HEREYOUCOOKIE;\"/cookies=\"${UDORK_COOKIE}\"/" $tools/uDork/uDork.sh 2>>"$LOGFILE" &>/dev/null
		cd "$tools/uDork" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		./uDork.sh $domain -f $tools/custom_udork.txt -o $dir/osint/dorks.txt &> /dev/null
		[ -s "$dir/osint/dorks.txt" ] && sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" $dir/osint/dorks.txt 2>>"$LOGFILE" &>/dev/null
		cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		end_func "Results are saved in $domain/osint/dorks.txt" ${FUNCNAME[0]}
	else
		if [ "$GOOGLE_DORKS" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} are already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function github_dorks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$GITHUB_DORKS" = true ] && [ "$OSINT" = true ]; then
		start_func ${FUNCNAME[0]} "Github Dorks in process"
		if [ -s "${GITHUB_TOKENS}" ]; then
			if [ "$DEEP" = true ]; then
				python3 "$tools/GitDorker/GitDorker.py" -tf "${GITHUB_TOKENS}" -e "$GITDORKER_THREADS" -q "$domain" -p -ri -d "$tools/GitDorker/Dorks/alldorksv3" 2>>"$LOGFILE" | grep "\[+\]" | grep "git" | anew -q osint/gitdorks.txt
			else
				python3 "$tools/GitDorker/GitDorker.py" -tf "${GITHUB_TOKENS}" -e "$GITDORKER_THREADS" -q "$domain" -p -ri -d "$tools/GitDorker/Dorks/medium_dorks.txt" 2>>"$LOGFILE" | grep "\[+\]" | grep "git" | anew -q osint/gitdorks.txt
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
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function metadata(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$METADATA" = true ] && [ "$OSINT" = true ] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Scanning metadata in public files"
		metafinder -d "$domain" -l $METAFINDER_LIMIT -o osint -go -bi -ba 2>>"$LOGFILE" &>/dev/null
		mv "osint/${domain}/"*".txt" "osint/" 2>>"$LOGFILE"
		rm -rf "osint/${domain}" 2>>"$LOGFILE"
		end_func "Results are saved in $domain/osint/[software/authors/metadata_results].txt" ${FUNCNAME[0]}
	else
		if [ "$METADATA" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function emails(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$EMAILS" = true ] && [ "$OSINT" = true ] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Searching emails/users/passwords leaks"
		emailfinder -d $domain 2>>"$LOGFILE" | anew -q .tmp/emailfinder.txt
		[ -s ".tmp/emailfinder.txt" ] && cat .tmp/emailfinder.txt | awk 'matched; /^-----------------$/ { matched = 1 }' | anew -q osint/emails.txt
		cd "$tools/theHarvester" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		python3 theHarvester.py -d $domain -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, netcraft, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye" 2>>"$LOGFILE" > $dir/.tmp/harvester.txt
		cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		if [ -s ".tmp/harvester.txt" ]; then
			cat .tmp/harvester.txt | awk '/Emails/,/Hosts/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q osint/emails.txt
			cat .tmp/harvester.txt | awk '/Users/,/IPs/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q osint/users.txt
			cat .tmp/harvester.txt | awk '/Links/,/Users/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q osint/linkedin.txt
		fi
		h8mail -t $domain -q domain --loose -c $tools/h8mail_config.ini -j .tmp/h8_results.json 2>>"$LOGFILE" &>/dev/null
		[ -s ".tmp/h8_results.json" ] && cat .tmp/h8_results.json | jq -r '.targets[0] | .data[] | .[]' | cut -d '-' -f2 | anew -q osint/h8mail.txt

		PWNDB_STATUS=$(timeout 30s curl -Is --socks5-hostname localhost:9050 http://pwndb2am4tzkvold.onion | grep HTTP | cut -d ' ' -f2)

		if [ "$PWNDB_STATUS" = 200 ]; then
			cd "$tools/pwndb" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			python3 pwndb.py --target "@${domain}" | sed '/^[-]/d' | anew -q $dir/osint/passwords.txt
			cd "$dir" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			[ -s "osint/passwords.txt" ] && sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" osint/passwords.txt
			[ -s "osint/passwords.txt" ] && sed -i '1,2d' osint/passwords.txt
		else
			text="${yellow}\n pwndb is currently down :(\n\n Check xjypo5vzgmo7jca6b322dnqbsdnp3amd24ybx26x5nxbusccjkm4pwid.onion${reset}\n"
			printf "${text}" && printf "${text}" | $NOTIFY
		fi
		end_func "Results are saved in $domain/osint/[emails/users/h8mail/passwords].txt" ${FUNCNAME[0]}
	else
		if [ "$EMAILS" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi

	fi
}

function domain_info(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$DOMAIN_INFO" = true ] && [ "$OSINT" = true ] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Searching domain info (whois, registrant name/email domains)"
		lynx -dump "https://domainbigdata.com/${domain}" | tail -n +19 > osint/domain_info_general.txt
		if [ -s "osint/domain_info_general.txt" ]; then
			cat osint/domain_info_general.txt | grep '/nj/' | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_name.txt
			cat osint/domain_info_general.txt | grep '/mj/' | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_email.txt
			cat osint/domain_info_general.txt | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | grep "https://domainbigdata.com" | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_ip.txt
		fi
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
		amass intel -d ${domain} -whois -o osint/domain_info_reverse_whois.txt 2>>"$LOGFILE" &>/dev/null
		end_func "Results are saved in $domain/osint/domain_info_[general/name/email/ip].txt" ${FUNCNAME[0]}
	else
		if [ "$DOMAIN_INFO" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function ip_info(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$IP_INFO" = true ] && [ "$OSINT" = true ] && [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Searching ip info"
		if [ -n "$WHOISXML_API" ]; then
			curl "https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ip=${domain}" 2>/dev/null | jq -r '.result[].name' 2>>"$LOGFILE" | sed -e "s/$/ ${ip}/" | anew -q osint/ip_${domain}_relations.txt
			curl "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOISXML_API}&domainName=${domain}&outputFormat=json&da=2&registryRawText=1&registrarRawText=1&ignoreRawTexts=1" 2>/dev/null | jq 2>>"$LOGFILE" | anew -q osint/ip_${domain}_whois.txt
			curl "https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ipAddress=${domain}" 2>/dev/null | jq -r '.ip,.location' 2>>"$LOGFILE" | anew -q osint/ip_${domain}_location.txt
			end_func "Results are saved in $domain/osint/ip_[domain_relations|whois|location].txt" ${FUNCNAME[0]}
		else
			printf "\n${yellow} No WHOISXML_API var defined, skipping function ${reset}\n"
		fi
	else
		if [ "$IP_INFO" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
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
	! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Subdomain Enumeration $domain\n\n"
	[[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Scanning IP $domain\n\n"
	[ -s "subdomains/subdomains.txt" ] && cp subdomains/subdomains.txt .tmp/subdomains_old.txt
	[ -s "webs/webs.txt" ] && cp webs/webs.txt .tmp/probed_old.txt

	resolvers_update

	[ -s "${inScope_file}" ] && cat ${inScope_file} | anew -q subdomains/subdomains.txt

	if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && [ "$SUBDOMAINS_GENERAL" = true ]; then
		sub_passive
		sub_crt
		sub_active
		sub_brute
		sub_permut
		sub_recursive
		sub_dns
		sub_scraping
		sub_analytics
	else 
		notification "IP/CIDR detected, subdomains search skipped" info
		echo $domain | anew -q subdomains/subdomains.txt
	fi

	if [ "$BBRF_CONNECTION" = true ]; then
		[ -s "subdomains/subdomains.txt" ] && cat subdomains/subdomains.txt | bbrf domain add - 2>>"$LOGFILE" &>/dev/null
	fi

	webprobe_simple
	if [ -s "subdomains/subdomains.txt" ]; then
		deleteOutScoped $outOfScope_file subdomains/subdomains.txt
		NUMOFLINES_subs=$(cat subdomains/subdomains.txt 2>>"$LOGFILE" | anew .tmp/subdomains_old.txt | wc -l)
	fi
	if [ -s "webs/webs.txt" ]; then
		deleteOutScoped $outOfScope_file webs/webs.txt
		NUMOFLINES_probed=$(cat webs/webs.txt 2>>"$LOGFILE" | anew .tmp/probed_old.txt | wc -l)
	fi
	printf "${bblue}\n Total subdomains: ${reset}\n\n"
	notification "- ${NUMOFLINES_subs} alive" good
	[ -s "subdomains/subdomains.txt" ] && cat subdomains/subdomains.txt | sort
	notification "- ${NUMOFLINES_probed} new web probed" good
	[ -s "webs/webs.txt" ] && cat webs/webs.txt | sort
	notification "Subdomain Enumeration Finished" good
	printf "${bblue} Results are saved in $domain/subdomains/subdomains.txt and webs/webs.txt${reset}\n"
	printf "${bgreen}#######################################################################\n\n"
}

function sub_passive(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBPASSIVE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Passive Subdomain Enumeration"
		if [ ! "$AXIOM" = true ]; then
			subfinder -d $domain -all -o .tmp/subfinder_psub.txt 2>>"$LOGFILE" &>/dev/null
			assetfinder --subs-only $domain 2>>"$LOGFILE" | anew -q .tmp/assetfinder_psub.txt
			amass enum -passive -d $domain -config $AMASS_CONFIG -o .tmp/amass_psub.txt 2>>"$LOGFILE" &>/dev/null
			findomain --quiet -t $domain -u .tmp/findomain_psub.txt 2>>"$LOGFILE" &>/dev/null
			timeout 10m waybackurls $domain | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/waybackurls_psub.txt
			timeout 10m gau --subs --threads $GAUPLUS_THREADS $domain | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/gau_psub.txt
		else
			axiom-scan $list -m subfinder -all -o .tmp/subfinder_psub.txt 2>>"$LOGFILE" &>/dev/null
			axiom-scan $list -m assetfinder -o .tmp/assetfinder_psub.txt 2>>"$LOGFILE" &>/dev/null
			axiom-scan $list -m amass -passive -o .tmp/amass_psub.txt 2>>"$LOGFILE" &>/dev/null
			axiom-scan $list -m findomain -o .tmp/findomain_psub.txt 2>>"$LOGFILE" &>/dev/null
			axiom-scan $list -m waybackurls -o .tmp/waybackurls_psub_tmp.txt 2>>"$LOGFILE" &>/dev/null
			[ -s ".tmp/waybackurls_psub_tmp.txt" ] && cat .tmp/waybackurls_psub_tmp.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/waybackurls_psub.txt
			axiom-scan $list -m gau -o .tmp/gau_psub_tmp.txt 2>>"$LOGFILE" &>/dev/null
			[ -s ".tmp/gau_psub_tmp.txt" ] && cat .tmp/gau_psub_tmp.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/gau_psub.txt
		fi
		crobat -s $domain 2>>"$LOGFILE" | anew -q .tmp/crobat_psub.txt
		if [ -s "${GITHUB_TOKENS}" ]; then
			if [ "$DEEP" = true ]; then
				github-subdomains -d $domain -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" &>/dev/null
			else
				github-subdomains -d $domain -k -q -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" &>/dev/null
			fi
		fi
		curl -s -k "https://jldc.me/anubis/subdomains/${domain}" 2>>"$LOGFILE" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sed '/^\./d' | anew -q .tmp/curl_psub.txt
		curl -s -k "https://dns.bufferover.run/dns?q=.${domain}" 2>>"$LOGFILE" | jq -r '.FDNS_A'[],'.RDNS'[] 2>>"$LOGFILE" | cut -d ',' -f2 | grep -F ".$domain" | anew -q .tmp/curl_psub.txt
		curl -s -k "https://tls.bufferover.run/dns?q=.${domain}" 2>>"$LOGFILE" | jq -r .Results[] 2>>"$LOGFILE" | cut -d ',' -f3 | grep -F ".$domain" | anew -q .tmp/curl_psub.txt
		NUMOFLINES=$(cat .tmp/*_psub.txt 2>>"$LOGFILE" | sed "s/*.//" | anew .tmp/passive_subs.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (passive)" ${FUNCNAME[0]}
	else
		if [ "$SUBPASSIVE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_crt(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBCRT" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Crtsh Subdomain Enumeration"
		if [ ! "$AXIOM" = true ]; then
			python3 $tools/ctfr/ctfr.py -d $domain -o .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" &>/dev/null
		else
			echo "python3 -u /home/op/recon/ctfr/ctfr.py -d ${domain} -o ${domain}_ctfr.txt; cat ${domain}_ctfr.txt" > .tmp/sub_ctrf_commands.txt
			axiom-scan .tmp/sub_ctrf_commands.txt -m exec -o .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" &>/dev/null
		fi
		eval sed -i '1,11d' .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" &>/dev/null
		NUMOFLINES=$(cat .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" | anew .tmp/crtsh_subs.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (cert transparency)" ${FUNCNAME[0]}
	else
		if [ "$SUBCRT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_active(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Active Subdomain Enumeration"
		cat .tmp/*_subs.txt 2>>"$LOGFILE" | anew -q .tmp/subs_no_resolved.txt
		deleteOutScoped $outOfScope_file .tmp/subs_no_resolved.txt
		if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/subs_no_resolved.txt" ] && puredns resolve .tmp/subs_no_resolved.txt -w .tmp/subdomains_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT &>/dev/null
		else
			[ -s ".tmp/subs_no_resolved.txt" ] && axiom-scan .tmp/subs_no_resolved.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/subdomains_tmp.txt 2>>"$LOGFILE" &>/dev/null
			echo $domain | dnsx -retry 3 -silent 2>>"$LOGFILE" | anew -q .tmp/subdomains_tmp.txt
		fi
		echo $domain | dnsx -retry 3 -silent -r $resolvers_trusted 2>>"$LOGFILE" | anew -q .tmp/subdomains_tmp.txt

		if [ "$DEEP" = true ]; then
			cat .tmp/subdomains_tmp.txt | cero -p 21,22,25,80,110,135,143,261,271,324,443,448,465,563,614,631,636,664,684,695,832,853,854,990,993,989,990,992,993,994,995,1129,1131,1184,2083,2087,2089,2096,2221,2252,2376,2381,2478,2479,2482,2484,2679,2762,3077,3078,3183,3191,3220,3269,3306,3410,3424,3471,3496,3509,3529,3539,3535,3660,36611,3713,3747,3766,3864,3885,3995,3896,4031,4036,4062,4064,4081,4083,4116,4335,4336,4536,4590,4740,4843,4843,4849,5443,5007,5061,5321,5349,5671,5783,5868,5986,5989,5990,6209,6251,6443,6513,6514,6619,6697,6771,6697,7202,7443,7673,7674,7677,7775,8243,8443,8991,8989,9089,9295,9318,9443,9444,9614,9802,10161,10162,11751,12013,12109,14143,15002,16995,41230,16993,20003 2>>"$LOGFILE" | sed 's/^*.//' | grep -iv "." | anew -q .tmp/subdomains_tmp.txt
		else
			cat .tmp/subdomains_tmp.txt | cero 2>>"$LOGFILE" | sed 's/^*.//' | grep -iv "." | anew -q .tmp/subdomains_tmp.txt
		fi
		NUMOFLINES=$(cat .tmp/subdomains_tmp.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (active resolution)" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function sub_dns(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : DNS Subdomain Enumeration"
		if [ ! "$AXIOM" = true ]; then
			[ -s "subdomains/subdomains.txt" ] && dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -resp -silent -l subdomains/subdomains.txt -o subdomains/subdomains_dnsregs.txt -r $resolvers_trusted 2>>"$LOGFILE" &>/dev/null
			[ -s "subdomains/subdomains_dnsregs.txt" ] && cat subdomains/subdomains_dnsregs.txt | cut -d '[' -f2 | sed 's/.$//' | grep ".$domain$" | anew -q .tmp/subdomains_dns.txt
			[ -s ".tmp/subdomains_dns.txt" ] && puredns resolve .tmp/subdomains_dns.txt -w .tmp/subdomains_dns_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			[ -s "subdomains/subdomains.txt" ] && axiom-scan subdomains/subdomains.txt -m dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -resp -o subdomains/subdomains_dnsregs.txt 2>>"$LOGFILE" &>/dev/null
			[ -s "subdomains/subdomains_dnsregs.txt" ] && cat subdomains/subdomains_dnsregs.txt | cut -d '[' -f2 | sed 's/.$//' | grep ".$domain$" | anew -q .tmp/subdomains_dns.txt
			[ -s ".tmp/subdomains_dns.txt" ] && axiom-scan .tmp/subdomains_dns.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" &>/dev/null
		fi

		NUMOFLINES=$(cat .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (dns resolution)" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function sub_brute(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBBRUTE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Bruteforce Subdomain Enumeration"
		if [ ! "$AXIOM" = true ]; then
			if [ "$DEEP" = true ]; then
				puredns bruteforce $subs_wordlist_big $domain -w .tmp/subs_brute.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
			else
				puredns bruteforce $subs_wordlist $domain -w .tmp/subs_brute.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
			fi
			[ -s ".tmp/subs_brute.txt" ] && puredns resolve .tmp/subs_brute.txt -w .tmp/subs_brute_valid.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			if [ "$DEEP" = true ]; then
				axiom-scan $subs_wordlist_big -m puredns-single $domain -r /home/op/lists/resolvers.txt -o .tmp/subs_brute.txt 2>>"$LOGFILE" &>/dev/null
			else
				axiom-scan $subs_wordlist -m puredns-single $domain -r /home/op/lists/resolvers.txt -o .tmp/subs_brute.txt 2>>"$LOGFILE" &>/dev/null
			fi
			[ -s ".tmp/subs_brute.txt" ] && axiom-scan .tmp/subs_brute.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/subs_brute_valid.txt 2>>"$LOGFILE" &>/dev/null
		fi
		NUMOFLINES=$(cat .tmp/subs_brute_valid.txt 2>>"$LOGFILE" | sed "s/*.//" | grep ".$domain$" | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (bruteforce)" ${FUNCNAME[0]}
	else
		if [ "$SUBBRUTE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_scraping(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBSCRAPING" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Source code scraping subdomain search"
		touch .tmp/scrap_subs.txt
		if [ -s "$dir/subdomains/subdomains.txt" ]; then
			if [ ! "$AXIOM" = true ]; then
				cat subdomains/subdomains.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp_scrap.txt
				[ -s ".tmp/probed_tmp_scrap.txt" ] && cat .tmp/probed_tmp_scrap.txt | httpx -tls-grab -tls-probe -csp-probe -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$domain$" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
				if [ "$DEEP" = true ]; then
					[ -s ".tmp/probed_tmp_scrap.txt" ] && gospider -S .tmp/probed_tmp_scrap.txt --js -t $GOSPIDER_THREADS -d 3 --sitemap --robots -w -r > .tmp/gospider.txt
				else
					[ -s ".tmp/probed_tmp_scrap.txt" ] && gospider -S .tmp/probed_tmp_scrap.txt --js -t $GOSPIDER_THREADS -d 2 --sitemap --robots -w -r > .tmp/gospider.txt
				fi
				sed -i '/^.\{2048\}./d' .tmp/gospider.txt
				[ -s ".tmp/gospider.txt" ] && cat .tmp/gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains 2>>"$LOGFILE" | grep ".$domain$" | anew -q .tmp/scrap_subs.txt
				[ -s ".tmp/scrap_subs.txt" ] && puredns resolve .tmp/scrap_subs.txt -w .tmp/scrap_subs_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
				NUMOFLINES=$(cat .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | tee .tmp/diff_scrap.txt | wc -l)
				[ -s ".tmp/diff_scrap.txt" ] && cat .tmp/diff_scrap.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp_scrap.txt
			else
				axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -o .tmp/probed_tmp_scrap1.txt 2>>"$LOGFILE" &>/dev/null
				[ -s ".tmp/probed_tmp_scrap1.txt" ] && cat .tmp/probed_tmp_scrap1.txt | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp_scrap.txt
				axiom-scan .tmp/probed_tmp_scrap.txt -m httpx -tls-grab -tls-probe -csp-probe -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -o .tmp/probed_tmp_scrap2.txt 2>>"$LOGFILE" &>/dev/null
				[ -s ".tmp/probed_tmp_scrap2.txt" ] && cat .tmp/probed_tmp_scrap2.txt | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$domain$" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
				if [ "$DEEP" = true ]; then
					[ -s ".tmp/probed_tmp_scrap.txt" ] && axiom-scan .tmp/probed_tmp_scrap.txt -m gospider --js -d 3 --sitemap --robots -w -r -o .tmp/gospider 2>>"$LOGFILE" &>/dev/null
				else
					[ -s ".tmp/probed_tmp_scrap.txt" ] && axiom-scan .tmp/probed_tmp_scrap.txt -m gospider --js -d 2 --sitemap --robots -w -r -o .tmp/gospider 2>>"$LOGFILE" &>/dev/null
				fi
				NUMFILES=0
				touch .tmp/gospider.txt
				[[ -d .tmp/gospider/ ]] && NUMFILES=$(find .tmp/gospider/ -type f | wc -l)
				[[ $NUMFILES -gt 0 ]] && cat .tmp/gospider/* | sed '/^.\{2048\}./d' | anew -q .tmp/gospider.txt
				grep -Eo 'https?://[^ ]+' .tmp/gospider.txt | sed 's/]$//' | unfurl -u domains 2>>"$LOGFILE" | grep ".$domain$" | anew -q .tmp/scrap_subs.txt
				[ -s ".tmp/scrap_subs.txt" ] && axiom-scan .tmp/scrap_subs.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" &>/dev/null
				NUMOFLINES=$(cat .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | tee .tmp/diff_scrap.txt | wc -l)
				axiom-scan .tmp/diff_scrap.txt -m httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -o .tmp/probed_tmp_scrap4.txt 2>>"$LOGFILE" &>/dev/null
				[ -s ".tmp/probed_tmp_scrap4.txt" ] && cat .tmp/probed_tmp_scrap4.txt | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp_scrap.txt
			fi
			end_subfunc "${NUMOFLINES} new subs (code scraping)" ${FUNCNAME[0]}
		else
			end_subfunc "No subdomains to search (code scraping)" ${FUNCNAME[0]}
		fi
	else
		if [ "$SUBSCRAPING" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_analytics(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBANALYTICS" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Analytics Subdomain Enumeration"
		if [ -s ".tmp/probed_tmp_scrap.txt" ]; then
			mkdir -p .tmp/output_analytics/
			cat .tmp/probed_tmp_scrap.txt | analyticsrelationships >> .tmp/analytics_subs_tmp.txt 2>>"$LOGFILE" &>/dev/null
			[ -s ".tmp/analytics_subs_tmp.txt" ] && cat .tmp/analytics_subs_tmp.txt | grep "\.$domain$\|^$domain$" | sed "s/|__ //" | anew -q .tmp/analytics_subs_clean.txt
			if [ ! "$AXIOM" = true ]; then
				[ -s ".tmp/analytics_subs_clean.txt" ] && puredns resolve .tmp/analytics_subs_clean.txt -w .tmp/analytics_subs_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
			else
				[ -s ".tmp/analytics_subs_clean.txt" ] && axiom-scan .tmp/analytics_subs_clean.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/analytics_subs_resolved.txt 2>>"$LOGFILE" &>/dev/null
			fi
		fi
		NUMOFLINES=$(cat .tmp/analytics_subs_resolved.txt 2>>"$LOGFILE" | anew subdomains/subdomains.txt |  wc -l)
		end_subfunc "${NUMOFLINES} new subs (analytics relationship)" ${FUNCNAME[0]}
	else
		if [ "$SUBANALYTICS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_permut(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBPERMUTE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Permutations Subdomain Enumeration"
		if [ "$DEEP" = true ] || [ "$(cat subdomains/subdomains.txt | wc -l)" -le $DEEP_LIMIT ] ; then
			[ -s "subdomains/subdomains.txt" ] && gotator -sub subdomains/subdomains.txt -perm $tools/permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md 2>>"$LOGFILE" > .tmp/gotator1.txt
		elif [ "$(cat .tmp/subs_no_resolved.txt | wc -l)" -le $DEEP_LIMIT2 ]; then
			[ -s ".tmp/subs_no_resolved.txt" ] && gotator -sub .tmp/subs_no_resolved.txt -perm $tools/permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md 2>>"$LOGFILE" > .tmp/gotator1.txt
		else
			end_subfunc "Skipping Permutations: Too Many Subdomains" ${FUNCNAME[0]}
			return 1
		fi
		if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/gotator1.txt" ] && puredns resolve .tmp/gotator1.txt -w .tmp/permute1_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			[ -s ".tmp/gotator1.txt" ] && axiom-scan .tmp/gotator1.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute1_tmp.txt 2>>"$LOGFILE" &>/dev/null
		fi
		[ -s ".tmp/permute1_tmp.txt" ] && cat .tmp/permute1_tmp.txt | anew -q .tmp/permute1.txt
		[ -s ".tmp/permute1.txt" ] && gotator -sub .tmp/permute1.txt -perm $tools/permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md 2>>"$LOGFILE" > .tmp/gotator2.txt
		if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/gotator2.txt" ] && puredns resolve .tmp/gotator2.txt -w .tmp/permute2_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			[ -s ".tmp/gotator2.txt" ] && axiom-scan .tmp/gotator2.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute2_tmp.txt 2>>"$LOGFILE" &>/dev/null
		fi
		[ -s ".tmp/permute2_tmp.txt" ] && cat .tmp/permute2_tmp.txt | anew -q .tmp/permute2.txt
		cat .tmp/permute1.txt .tmp/permute2.txt 2>>"$LOGFILE" | anew -q .tmp/permute_subs.txt

		if [ -s ".tmp/permute_subs.txt" ]; then
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
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_recursive(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBRECURSIVE" = true ] && [ -s "subdomains/subdomains.txt" ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Subdomains recursive search"
		# Passive recursive
		if [ "$SUB_RECURSIVE_PASSIVE" = true ]; then
			if [ ! "$AXIOM" = true ]; then
				for sub in $( ( cat subdomains/subdomains.txt | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat subdomains/subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
					subfinder -d $sub -all -silent 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
					assetfinder --subs-only $sub 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
					amass enum -passive -d $sub -config $AMASS_CONFIG 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
					findomain --quiet -t $sub 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
				done
				[ -s ".tmp/passive_recursive.txt" ] && puredns resolve .tmp/passive_recursive.txt -w .tmp/passive_recurs_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
			else
				for sub in $( ( cat subdomains/subdomains.txt | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat subdomains/subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
					echo $sub | anew -q .tmp/sub_pass_recur_target.com
				done
				if [ -s ".tmp/sub_pass_recur_target.com" ]; then
					axiom-scan .tmp/sub_pass_recur_target.com -m subfinder -all -o .tmp/subfinder_prec.txt 2>>"$LOGFILE" &>/dev/null
					axiom-scan .tmp/sub_pass_recur_target.com -m assetfinder -o .tmp/assetfinder_prec.txt 2>>"$LOGFILE" &>/dev/null
					axiom-scan .tmp/sub_pass_recur_target.com -m amass -passive -o .tmp/amass_prec.txt 2>>"$LOGFILE" &>/dev/null
					axiom-scan .tmp/sub_pass_recur_target.com -m findomain -o .tmp/findomain_prec.txt 2>>"$LOGFILE" &>/dev/null
				fi
				cat .tmp/*_prec.txt 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
				[ -s ".tmp/passive_recursive.txt" ] && axiom-scan .tmp/passive_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" &>/dev/null
			fi
		fi
		# Bruteforce recursive
		if [[ $(cat subdomains/subdomains.txt | wc -l) -le $DEEP_LIMIT ]] && [ "$SUB_RECURSIVE_BRUTE" = true ] ; then
			echo "" > .tmp/brute_recursive_wordlist.txt
			for sub in $(cat subdomains/subdomains.txt); do
				sed "s/$/.$sub/" $subs_wordlist >> .tmp/brute_recursive_wordlist.txt
			done
			if [ ! "$AXIOM" = true ]; then
				[ -s ".tmp/brute_recursive_wordlist.txt" ] && puredns resolve .tmp/brute_recursive_wordlist.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -w .tmp/brute_recursive_result.txt 2>>"$LOGFILE" &>/dev/null
			else
				[ -s ".tmp/brute_recursive_wordlist.txt" ] && axiom-scan .tmp/brute_recursive_wordlist.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/brute_recursive_result.txt 2>>"$LOGFILE" &>/dev/null
			fi
			[ -s ".tmp/brute_recursive_result.txt" ] && cat .tmp/brute_recursive_result.txt | anew -q .tmp/brute_recursive.txt
			[ -s ".tmp/brute_recursive.txt" ] && gotator -sub .tmp/brute_recursive.txt -perm $tools/permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md 2>>"$LOGFILE" > .tmp/gotator1_recursive.txt
			if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/gotator1_recursive.txt" ] && puredns resolve .tmp/gotator1_recursive.txt -w .tmp/permute1_recursive_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
			else
				[ -s ".tmp/gotator1_recursive.txt" ] && axiom-scan .tmp/gotator1_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute1_recursive_tmp.txt 2>>"$LOGFILE" &>/dev/null
			fi
			[ -s ".tmp/permute1_recursive_tmp.txt" ] && cat .tmp/permute1_recursive_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute1_recursive.txt
			[ -s ".tmp/permute1_recursive.txt" ] && gotator -sub .tmp/permute1_recursive.txt -perm $tools/permutations_list.txt -depth 1 -numbers 10 -mindup -adv -md 2>>"$LOGFILE" > .tmp/gotator2_recursive.txt
			if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/gotator2_recursive.txt" ] && puredns resolve .tmp/gotator2_recursive.txt -w .tmp/permute2_recursive_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
			else
				[ -s ".tmp/gotator2_recursive.txt" ] && axiom-scan .tmp/gotator2_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt -o .tmp/permute2_recursive_tmp.txt 2>>"$LOGFILE" &>/dev/null
			fi
			cat .tmp/permute1_recursive.txt .tmp/permute2_recursive_tmp.txt 2>>"$LOGFILE" | anew -q .tmp/permute_recursive.txt
			#eval rm -rf .tmp/gotator*.txt 2>>"$LOGFILE"
			#eval rm -rf .tmp/brute_recursive_wordlist.txt 2>>"$LOGFILE"
			#eval rm -rf .tmp/permute*.txt 2>>"$LOGFILE"
		else
			end_subfunc "Skipping Recursive BF: Too Many Subdomains" ${FUNCNAME[0]}
		fi
		NUMOFLINES=$(cat .tmp/passive_recurs_tmp.txt .tmp/permute_recursive.txt .tmp/brute_recursive.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (recursive)" ${FUNCNAME[0]}
	else
		if [ "$SUBRECURSIVE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function subtakeover(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBTAKEOVER" = true ]; then
		start_func ${FUNCNAME[0]} "Looking for possible subdomain and DNS takeover"
		touch .tmp/tko.txt
		if [ ! "$AXIOM" = true ]; then
			cat subdomains/subdomains.txt webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | nuclei -silent -t ~/nuclei-templates/takeovers/ -r $resolvers_trusted -retries 3 -o .tmp/tko.txt
		else
			cat webs/webs.txt subdomains/subdomains.txt webs/webs_uncommon_ports.txt 2>>"$LOGFILE" | anew -q .tmp/webs_subs.txt
			[ -s ".tmp/webs_subs.txt" ] && axiom-scan .tmp/webs_subs.txt -m nuclei -w /home/op/recon/nuclei/takeovers/ -retries 3 -o .tmp/tko.txt 2>>"$LOGFILE" &>/dev/null
		fi

		# DNS_TAKEOVER
		cat .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/scrap_subs.txt .tmp/analytics_subs_clean.txt .tmp/passive_recursive.txt 2>/dev/null | anew -q .tmp/subs_dns_tko.txt
		cat .tmp/subs_dns_tko.txt 2>/dev/null | dnstake -c $DNSTAKE_THREADS -s 2>>"$LOGFILE" | anew -q .tmp/tko.txt
		
		NUMOFLINES=$(cat .tmp/tko.txt 2>>"$LOGFILE" | anew webs/takeover.txt | wc -l)
		if [ "$NUMOFLINES" -gt 0 ]; then
			notification "${NUMOFLINES} new possible takeovers found" info
		fi
		if [ "$BBRF_CONNECTION" = true ]; then
			[ -s "webs/takeover.txt" ] && cat webs/takeover.txt | grep -Eo 'https?://[^ ]+' | bbrf url add - -t subtko:true 2>>"$LOGFILE" &>/dev/null
		fi
		end_func "Results are saved in $domain/webs/takeover.txt" ${FUNCNAME[0]}
	else
		if [ "$SUBTAKEOVER" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function zonetransfer(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$ZONETRANSFER" = true ] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Zone transfer check"
		python3 $tools/dnsrecon/dnsrecon.py -d $domain -a -j subdomains/zonetransfer.json 2>>"$LOGFILE" &>/dev/null
		if [ -s "subdomains/zonetransfer.json" ]; then
			if grep -q "\"zone_transfer\"\: \"success\"" subdomains/zonetransfer.json ; then notification "Zone transfer found on ${domain}!" info; fi
		fi
		end_func "Results are saved in $domain/subdomains/zonetransfer.txt" ${FUNCNAME[0]}
	else
		if [ "$ZONETRANSFER" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function s3buckets(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$S3BUCKETS" = true ] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "AWS S3 buckets search"

		# S3Scanner
		if [ ! "$AXIOM" = true ]; then
			[ -s "subdomains/subdomains.txt" ] && s3scanner scan -f subdomains/subdomains.txt | grep -iv "not_exist" | grep -iv "Warning:" | grep -iv "invalid_name" | anew -q .tmp/s3buckets.txt
		else
			axiom-scan webs/webs.txt -m s3scanner -o .tmp/s3buckets_tmp.txt 2>>"$LOGFILE" &>/dev/null
			[ -s ".tmp/s3buckets_tmp.txt" ] && cat .tmp/s3buckets_tmp.txt | grep -iv "not_exist" | grep -iv "Warning:" | anew -q .tmp/s3buckets.txt
		fi
		# Cloudenum
		keyword=${domain%%.*}
		python3 ~/Tools/cloud_enum/cloud_enum.py -k $keyword -qs -l .tmp/output_cloud.txt 2>>"$LOGFILE" &>/dev/null

		NUMOFLINES1=$(cat .tmp/output_cloud.txt 2>>"$LOGFILE" | sed '/^#/d' | sed '/^$/d' | anew subdomains/cloud_assets.txt | wc -l)
		if [ "$NUMOFLINES1" -gt 0 ]; then
			notification "${NUMOFLINES} new cloud assets found" info
		fi
		NUMOFLINES2=$(cat .tmp/s3buckets.txt 2>>"$LOGFILE" | anew subdomains/s3buckets.txt | wc -l)
		if [ "$NUMOFLINES2" -gt 0 ]; then
			notification "${NUMOFLINES} new S3 buckets found" info
		fi

		if [ "$BBRF_CONNECTION" = true ]; then
			[ -s "subdomains/cloud_assets.txt" ] && cat subdomains/cloud_assets.txt | grep -Eo 'https?://[^ ]+' | sed 's/[ \t]*$//' | bbrf url add - -t cloud_assets:true 2>>"$LOGFILE" &>/dev/null
			[ -s "subdomains/s3buckets.txt" ] && cat subdomains/s3buckets.txt | cut -d'|' -f1 | sed 's/[ \t]*$//' | bbrf domain update - -t s3bucket:true 2>>"$LOGFILE" &>/dev/null
		fi

		end_func "Results are saved in subdomains/s3buckets.txt and subdomains/cloud_assets.txt" ${FUNCNAME[0]}
	else
		if [ "$S3BUCKETS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

###############################################################################################################
########################################### WEB DETECTION #####################################################
###############################################################################################################

function webprobe_simple(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WEBPROBESIMPLE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Http probing $domain"
		if [ -s ".tmp/probed_tmp_scrap.txt" ]; then
			mv .tmp/probed_tmp_scrap.txt .tmp/probed_tmp.txt
		else
			if [ ! "$AXIOM" = true ]; then
				if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then 
					cat subdomains/subdomains.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | anew -q .tmp/probed_tmp.txt
				else
					cat subdomains/subdomains.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep "$domain$" | anew -q .tmp/probed_tmp.txt
				fi
			else
				axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -random-agent -threads $HTTPX_THREADS -status-code -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -o .tmp/probed_tmp_.txt 2>>"$LOGFILE" &>/dev/null
				if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then 
					[ -s ".tmp/probed_tmp_.txt" ] && cat .tmp/probed_tmp_.txt | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_tmp.txt
				else
					[ -s ".tmp/probed_tmp_.txt" ] && cat .tmp/probed_tmp_.txt | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | anew -q .tmp/probed_tmp.txt
				fi
			fi
		fi
		if [ -s ".tmp/probed_tmp.txt" ]; then
			cat .tmp/web_full_info.txt | anew -q webs/web_full_info.txt
			deleteOutScoped $outOfScope_file .tmp/probed_tmp.txt
			NUMOFLINES=$(cat .tmp/probed_tmp.txt 2>>"$LOGFILE" | anew webs/webs.txt | wc -l)
			end_subfunc "${NUMOFLINES} new websites resolved" ${FUNCNAME[0]}
			if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/webs.txt| wc -l) -le $DEEP_LIMIT2 ]]; then
				notification "Sending websites to proxy" info
				ffuf -mc all -fc 404 -w webs/webs.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" &>/dev/null
			fi
			if [ "$BBRF_CONNECTION" = true ]; then
				[ -s "webs/webs.txt" ] && cat webs/webs.txt | bbrf url add - 2>>"$LOGFILE" &>/dev/null
			fi
		else
			end_subfunc "No new websites to probe" ${FUNCNAME[0]}
		fi
	else
		if [ "$WEBPROBESIMPLE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function webprobe_full(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WEBPROBEFULL" = true ]; then
		start_func ${FUNCNAME[0]} "Http probing non standard ports"
		if [ -s "subdomains/subdomains.txt" ]; then
			if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
				sudo nmap -iL subdomains/subdomains.txt -p $UNCOMMON_PORTS_WEB -oG .tmp/uncommon_nmap.gnmap 2>>"$LOGFILE" &>/dev/null
				cat .tmp/uncommon_nmap.gnmap | egrep -v "^#|Status: Up" | cut -d' ' -f2,4- | grep "open" | sed -e 's/\/.*$//g' | sed -e "s/ /:/g" | sort -u | anew -q .tmp/nmap_uncommonweb.txt
			else
				if [ ! "$AXIOM" = true ]; then
					sudo unimap --fast-scan -f subdomains/subdomains.txt --ports $UNCOMMON_PORTS_WEB -q -k --url-output 2>>"$LOGFILE" | anew -q .tmp/nmap_uncommonweb.txt
				else
					axiom-scan subdomains/subdomains.txt -m unimap --fast-scan --ports $UNCOMMON_PORTS_WEB -q -k --url-output -o .tmp/nmap_uncommonweb.txt 2>>"$LOGFILE" &>/dev/null
				fi
			fi
		fi
		if [ ! "$AXIOM" = true ]; then
			if [ -s ".tmp/nmap_uncommonweb.txt" ]; then
				if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then 
					cat .tmp/nmap_uncommonweb.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info_uncommon.txt | cut -d ' ' -f1 | anew -q .tmp/probed_uncommon_ports_tmp.txt
				else
					cat .tmp/nmap_uncommonweb.txt | httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info_uncommon.txt | cut -d ' ' -f1 | grep "$domain" | anew -q .tmp/probed_uncommon_ports_tmp.txt
				fi
			fi
			[ -s ".tmp/web_full_info_uncommon.txt" ] && cat .tmp/web_full_info_uncommon.txt | anew -q webs/web_full_info_uncommon.txt
		else
			if [ -s ".tmp/nmap_uncommonweb.txt" ]; then
				axiom-scan .tmp/nmap_uncommonweb.txt -m httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -o .tmp/probed_uncommon_ports_tmp_.txt 2>>"$LOGFILE" &>/dev/null
				if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then 
					[ -s ".tmp/probed_uncommon_ports_tmp_.txt" ] && cat .tmp/probed_uncommon_ports_tmp_.txt | anew .tmp/web_full_info_uncommon.txt | cut -d ' ' -f1 | anew -q .tmp/probed_uncommon_ports_tmp.txt
				else
					[ -s ".tmp/probed_uncommon_ports_tmp_.txt" ] && cat .tmp/probed_uncommon_ports_tmp_.txt | anew .tmp/web_full_info_uncommon.txt | cut -d ' ' -f1 | grep ".$domain$" | anew -q .tmp/probed_uncommon_ports_tmp.txt
				fi
			fi
			[ -s ".tmp/web_full_info_uncommon.txt" ] && cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | anew -q webs/web_full_info_uncommon.txt
		fi
		NUMOFLINES=$(cat .tmp/probed_uncommon_ports_tmp.txt 2>>"$LOGFILE" | anew webs/webs_uncommon_ports.txt | wc -l)
		notification "Uncommon web ports: ${NUMOFLINES} new websites" good
		[ -s "webs/webs_uncommon_ports.txt" ] && cat webs/webs_uncommon_ports.txt
		rm -rf "unimap_logs" 2>>"$LOGFILE"
		end_func "Results are saved in $domain/webs/webs_uncommon_ports.txt" ${FUNCNAME[0]}
		if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/webs_uncommon_ports.txt| wc -l) -le $DEEP_LIMIT2 ]]; then
			notification "Sending websites uncommon ports to proxy" info
			ffuf -mc all -fc 404 -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" &>/dev/null
		fi
		if [ "$BBRF_CONNECTION" = true ]; then
			[ -s "webs/webs_uncommon_ports.txt" ] && cat webs/webs_uncommon_ports.txt | bbrf url add - 2>>"$LOGFILE" &>/dev/null
		fi
	else
		if [ "$WEBPROBEFULL" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function screenshot(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WEBSCREENSHOT" = true ]; then
		start_func ${FUNCNAME[0]} "Web Screenshots"
		cat webs/webs.txt webs/webs_uncommon_ports.txt 2>>"$LOGFILE" | anew -q .tmp/webs_screenshots.txt
		if [ ! "$AXIOM" = true ]; then
			#[ -s ".tmp/webs_screenshots.txt" ] && webscreenshot -i .tmp/webs_screenshots.txt -w $WEBSCREENSHOT_THREADS -o screenshots 2>>"$LOGFILE" &>/dev/null
			[ -s ".tmp/webs_screenshots.txt" ] && gowitness file -f .tmp/webs_screenshots.txt -t $GOWITNESS_THREADS --disable-logging 2>>"$LOGFILE"
		else
			[ "$AXIOM_SCREENSHOT_MODULE" = "webscreenshot" ] && axiom-scan .tmp/webs_screenshots.txt -m $AXIOM_SCREENSHOT_MODULE -w $WEBSCREENSHOT_THREADS -o screenshots 2>>"$LOGFILE" &>/dev/null
			[ "$AXIOM_SCREENSHOT_MODULE" != "webscreenshot" ] && axiom-scan .tmp/webs_screenshots.txt -m $AXIOM_SCREENSHOT_MODULE -o screenshots 2>>"$LOGFILE" &>/dev/null
		fi
		end_func "Results are saved in $domain/screenshots folder" ${FUNCNAME[0]}
	else
		if [ "$WEBSCREENSHOT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

###############################################################################################################
############################################# HOST SCAN #######################################################
###############################################################################################################

function favicon(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$FAVICON" = true ] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Favicon Ip Lookup"
		cd "$tools/fav-up" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		python3 favUp.py -w "$domain" -sc -o favicontest.json 2>>"$LOGFILE" &>/dev/null
		if [ -s "favicontest.json" ]; then
			cat favicontest.json | jq -r '.found_ips' 2>>"$LOGFILE" | grep -v "not-found" > favicontest.txt
			sed -i "s/|/\n/g" favicontest.txt
			cat favicontest.txt 2>>"$LOGFILE"
			mv favicontest.txt $dir/hosts/favicontest.txt 2>>"$LOGFILE"
			rm -f favicontest.json 2>>"$LOGFILE"
		fi
		cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		end_func "Results are saved in hosts/favicontest.txt" ${FUNCNAME[0]}
	else
		if [ "$FAVICON" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function portscan(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$PORTSCANNER" = true ]; then
		start_func ${FUNCNAME[0]} "Port scan"
		#interlace -tL subdomains/subdomains.txt -threads 50 -c 'echo "_target_ $(dig +short a _target_ | tail -n1)" | anew -q _output_' -o .tmp/subs_ips.txt
		if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			[ -s "subdomains/subdomains.txt" ] && resolveDomains -d subdomains/subdomains.txt -t $RESOLVE_DOMAINS_THREADS 2>>"$LOGFILE" | anew -q .tmp/subs_ips.txt
			[ -s ".tmp/subs_ips.txt" ] && awk '{ print $2 " " $1}' .tmp/subs_ips.txt | sort -k2 -n | anew -q hosts/subs_ips_vhosts.txt
			[ -s "hosts/subs_ips_vhosts.txt" ] && cat hosts/subs_ips_vhosts.txt | cut -d ' ' -f1 | grep -Eiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q hosts/ips.txt
		else echo $domain | grep -Eiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q hosts/ips.txt
		fi
		if [ ! "$AXIOM" = true ]; then
			[ -s "hosts/ips.txt" ] && cat hosts/ips.txt | cf-check | grep -Eiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q .tmp/ips_nowaf.txt	
		else
			[ -s "hosts/subs_ips_vhosts.txt" ] && cat hosts/subs_ips_vhosts.txt | cut -d ' ' -f1 | grep -Eiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q hosts/ips.txt
			[ -s "hosts/ips.txt" ] && axiom-scan hosts/ips.txt -m cf-check -o .tmp/ips_nowaf_.txt 2>>"$LOGFILE" &>/dev/null
			[ -s ".tmp/ips_nowaf_.txt" ] && cat .tmp/ips_nowaf_.txt | grep -Eiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q .tmp/ips_nowaf.txt
		fi
		printf "${bblue}\n Resolved IP addresses (No WAF) ${reset}\n\n";
		[ -s ".tmp/ips_nowaf.txt" ] && cat .tmp/ips_nowaf.txt | sort
		printf "${bblue}\n Scanning ports... ${reset}\n\n";
		if [ "$PORTSCAN_PASSIVE" = true ] && [ ! -f "hosts/portscan_passive.txt" ] && [ -s "hosts/ips.txt" ] ; then
			for sub in $(cat hosts/ips.txt); do
				shodan host $sub 2>/dev/null >> hosts/portscan_passive.txt && echo -e "\n\n#######################################################################\n\n" >> hosts/portscan_passive.txt
			done
		fi
		if [ "$PORTSCAN_ACTIVE" = true ]; then
			if [ ! "$AXIOM" = true ]; then
				[ -s ".tmp/ips_nowaf.txt" ] && sudo nmap --top-ports 200 -sV -n --max-retries 2 -Pn --open -iL .tmp/ips_nowaf.txt -oA hosts/portscan_active 2>>"$LOGFILE" &>/dev/null
			else
				[ -s ".tmp/ips_nowaf.txt" ] && axiom-scan .tmp/ips_nowaf.txt -m nmapx --top-ports 200 -sV -n -Pn --open --max-retries 2 -o hosts/portscan_active.gnmap 2>>"$LOGFILE" &>/dev/null
				[ -s "hosts/portscan_active.gnmap" ] && cat hosts/portscan_active.gnmap | egrep -v "^#|Status: Up" | cut -d' ' -f2,4- | sed -n -e 's/Ignored.*//p' | awk '{print "Host: " $1 " Ports: " NF-1; $1=""; for(i=2; i<=NF; i++) { a=a" "$i; }; split(a,s,","); for(e in s) { split(s[e],v,"/"); printf "%-8s %s/%-7s %s\n" , v[2], v[3], v[1], v[5]}; a="" }' > hosts/portscan_active.txt 2>>"$LOGFILE" &>/dev/null
			fi
		fi
		if [ "$BBRF_CONNECTION" = true ]; then
			[ -s "hosts/subs_ips_vhosts.txt" ] && cat subs_ips_vhosts.txt | awk '{print $2,$1}' | sed -e 's/\s\+/:/g' | bbrf domain add -
			[ -s "hosts/subs_ips_vhosts.txt" ] && cat subs_ips_vhosts.txt | sed -e 's/\s\+/:/g' | bbrf ip add -
			[ -s "hosts/portscan_active.xml" ] && $tools/ultimate-nmap-parser/ultimate-nmap-parser.sh hosts/portscan_active.gnmap --csv 2>>"$LOGFILE" &>/dev/null
			[ -s "parsed_nmap.csv" ] && mv parsed_nmap.csv .tmp/parsed_nmap.csv && cat .tmp/parsed_nmap.csv | tail -n +2 | cut -d',' -f1,2,5,6 | sed -e 's/,/:/g' | sed 's/\:$//' | bbrf service add - && rm -f parsed_nmap.csv
		fi
		[ -s "hosts/portscan_active.xml" ] && searchsploit --nmap hosts/portscan_active.xml 2>>"$LOGFILE" > hosts/searchsploit.txt
		end_func "Results are saved in hosts/portscan_[passive|active].txt" ${FUNCNAME[0]}
	else
		if [ "$PORTSCANNER" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function cloudprovider(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CLOUD_IP" = true ]; then
		start_func ${FUNCNAME[0]} "Cloud provider check"
		if [ -s "$dir/hosts/ips.txt" ]; then
			for ip in $( cat "$dir/hosts/ips.txt" ); do 
				echo "$( echo -n ${ip} && echo -n " " && clouddetect -ip=${ip} )" | grep -iv "Error" | anew -q $dir/hosts/cloud_providers.txt
			done
		fi
		end_func "Results are saved in hosts/cloud_providers.txt" ${FUNCNAME[0]}
	else
		if [ "$CLOUD_IP" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

###############################################################################################################
############################################# WEB SCAN ########################################################
###############################################################################################################

function waf_checks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WAF_DETECTION" = true ]; then
		start_func ${FUNCNAME[0]} "Website's WAF detection"
		if [ -s "./webs/webs.txt" ]; then
			if [ ! "$AXIOM" = true ]; then
				wafw00f -i webs/webs.txt -o .tmp/wafs.txt 2>>"$LOGFILE" &>/dev/null
			else
				axiom-scan webs/webs.txt -m wafw00f -o .tmp/wafs.txt 2>>"$LOGFILE" &>/dev/null
			fi
			if [ -s ".tmp/wafs.txt" ]; then
				cat .tmp/wafs.txt | sed -e 's/^[ \t]*//' -e 's/ \+ /\t/g' -e '/(None)/d' | tr -s "\t" ";" > webs/webs_wafs.txt
				NUMOFLINES=$(cat webs/webs_wafs.txt 2>>"$LOGFILE" | wc -l)
				notification "${NUMOFLINES} websites protected by waf" info
				if [ "$BBRF_CONNECTION" = true ]; then
					[ -s "webs/webs_wafs.txt" ] && cat webs/webs_wafs.txt | bbrf url add - -t waf:true 2>>"$LOGFILE" &>/dev/null
				fi
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
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function nuclei_check(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$NUCLEICHECK" = true ]; then
		start_func ${FUNCNAME[0]} "Templates based web scanner"
		nuclei -update-templates 2>>"$LOGFILE" &>/dev/null
		mkdir -p nuclei_output
		if [ ! "$AXIOM" = true ]; then
			set -f                      # avoid globbing (expansion of *).
			array=(${NUCLEI_SEVERITY//,/ })
			for i in "${!array[@]}"
			do
				crit=${array[i]}
				printf "${yellow}\n Running : Nuclei $crit ${reset}\n\n"
				cat subdomains/subdomains.txt webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | nuclei -silent -t ~/nuclei-templates/ -severity $crit -retries 3 -r $resolvers_trusted -o nuclei_output/${crit}.txt
			done
			printf "\n\n"
		else
			[ ! -s ".tmp/webs_subs.txt" ] && cat subdomains/subdomains.txt webs/webs.txt webs/webs_uncommon_ports.txt 2>>"$LOGFILE" | anew -q .tmp/webs_subs.txt
			if [ -s ".tmp/webs_subs.txt" ]; then
				set -f                      # avoid globbing (expansion of *).
				array=(${NUCLEI_SEVERITY//,/ })
				for i in "${!array[@]}"
				do
					crit=${array[i]}
					printf "${yellow}\n Running : Nuclei $crit ${reset}\n\n"
					axiom-scan .tmp/webs_subs.txt -m nuclei -severity ${crit} -o nuclei_output/${crit}.txt 2>>"$LOGFILE" &>/dev/null
				done
				printf "\n\n"
			fi
		fi
		if [ "$BBRF_CONNECTION" = true ]; then
			[ -s "nuclei_output/info.txt" ] && cat nuclei_output/info.txt | cut -d' ' -f6 | sort -u | bbrf url add - -t nuclei:${crit} 2>>"$LOGFILE" &>/dev/null
			[ -s "nuclei_output/low.txt" ] && cat nuclei_output/low.txt | cut -d' ' -f6 | sort -u | bbrf url add - -t nuclei:${crit} 2>>"$LOGFILE" &>/dev/null
			[ -s "nuclei_output/medium.txt" ] && cat nuclei_output/medium.txt | cut -d' ' -f6 | sort -u | bbrf url add - -t nuclei:${crit} 2>>"$LOGFILE" &>/dev/null
			[ -s "nuclei_output/high.txt" ] && cat nuclei_output/high.txt | cut -d' ' -f6 | sort -u | bbrf url add - -t nuclei:${crit} 2>>"$LOGFILE" &>/dev/null
			[ -s "nuclei_output/critical.txt" ] && cat nuclei_output/critical.txt | cut -d' ' -f6 | sort -u | bbrf url add - -t nuclei:${crit} 2>>"$LOGFILE" &>/dev/null
		fi
		end_func "Results are saved in $domain/nuclei_output folder" ${FUNCNAME[0]}
	else
		if [ "$NUCLEICHECK" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function fuzz(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$FUZZ" = true ]; then
		start_func ${FUNCNAME[0]} "Web directory fuzzing"
		if [ -s "webs/webs.txt" ]; then
			mkdir -p $dir/fuzzing
			if [ ! "$AXIOM" = true ]; then
				interlace -tL webs/webs.txt -threads 10 -c "ffuf ${FFUF_FLAGS} -t ${FFUF_THREADS}  -H \"${HEADER}\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u  _target_/FUZZ -of csv -o _output_/_cleantarget_.csv" -o fuzzing 2>>"$LOGFILE" &>/dev/null
				for sub in $(cat webs/webs.txt); do
					sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
					[ -s "$dir/fuzzing/${sub_out}.csv" ] && cat $dir/fuzzing/${sub_out}.csv | cut -d ',' -f2,5,6 | tr ',' ' ' | awk '{ print $2 " " $3 " " $1}' | tail -n +2 | sort -k1 | anew -q $dir/fuzzing/${sub_out}.txt
					rm -f $dir/fuzzing/${sub_out}.csv 2>>"$LOGFILE"
				done
				find $dir/fuzzing/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | anew -q $dir/fuzzing/fuzzing_full.txt
			else
				axiom-scan webs/webs.txt -m ffuf -w /home/op/lists/onelistforallmicro.txt -H \"${HEADER}\" $FFUF_FLAGS -maxtime $FFUF_MAXTIME -o $dir/fuzzing/ffuf-content.csv 2>>"$LOGFILE" &>/dev/null
				grep -v "FUZZ,url,redirectlocation" $dir/fuzzing/ffuf-content.csv | awk -F "," '{print $2" "$5" "$6}' | sort > $dir/fuzzing/ffuf-content.tmp
				for sub in $(cat webs/webs.txt); do
					sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
					grep "$sub" $dir/fuzzing/ffuf-content.tmp | awk '{print $2" "$3" "$1}' | sort -k1 | anew -q $dir/fuzzing/${sub_out}.txt
				done
				find $dir/fuzzing/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | anew -q $dir/fuzzing/fuzzing_full.txt
				rm -f $dir/fuzzing/ffuf-content.tmp $dir/fuzzing/ffuf-content.csv
			fi
			end_func "Results are saved in $domain/fuzzing/*subdomain*.txt" ${FUNCNAME[0]}
		else
			end_func "No $domain/web/webs.txts file found, fuzzing skipped " ${FUNCNAME[0]}
		fi
	else
		if [ "$FUZZ" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function cms_scanner(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CMS_SCANNER" = true ]; then
		start_func ${FUNCNAME[0]} "CMS Scanner"
		mkdir -p $dir/cms && rm -rf $dir/cms/*
		if [ -s "./webs/webs.txt" ]; then
			tr '\n' ',' < webs/webs.txt > .tmp/cms.txt
			timeout -k 30 $CMSSCAN_TIMEOUT python3 $tools/CMSeeK/cmseek.py -l .tmp/cms.txt --batch -r 2>>"$LOGFILE" &>/dev/null
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
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function urlchecks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$URL_CHECK" = true ]; then
		start_func ${FUNCNAME[0]} "URL Extraction"
		mkdir -p js
		if [ -s "webs/webs.txt" ]; then
			if [ ! "$AXIOM" = true ]; then
				if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
					cat webs/webs.txt | waybackurls | anew -q .tmp/url_extract_tmp.txt
					cat webs/webs.txt | gau --subs --threads $GAUPLUS_THREADS | anew -q .tmp/url_extract_tmp.txt
				fi
				diff_webs=$(diff <(sort -u .tmp/probed_tmp.txt 2>>"$LOGFILE") <(sort -u webs/webs.txt 2>>"$LOGFILE") | wc -l)
				if [ $diff_webs != "0" ] || [ ! -s ".tmp/gospider.txt" ]; then
					if [ "$DEEP" = true ]; then
						gospider -S webs/webs.txt --js -t $GOSPIDER_THREADS -d 3 --sitemap --robots -w -r > .tmp/gospider.txt
					else
						gospider -S webs/webs.txt --js -t $GOSPIDER_THREADS -d 2 --sitemap --robots -w -r > .tmp/gospider.txt
					fi
				fi
				sed -i '/^.\{2048\}./d' .tmp/gospider.txt
				if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
					[ -s ".tmp/gospider.txt" ] && cat .tmp/gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | anew -q .tmp/url_extract_tmp.txt
				else
					[ -s ".tmp/gospider.txt" ] && cat .tmp/gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | grep "$domain" | anew -q .tmp/url_extract_tmp.txt
				fi
			else
				if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
					axiom-scan webs/webs.txt -m waybackurls -o .tmp/url_extract_way_tmp.txt 2>>"$LOGFILE" &>/dev/null
					[ -s ".tmp/url_extract_way_tmp.txt" ] && cat .tmp/url_extract_way_tmp.txt | anew -q .tmp/url_extract_tmp.txt
					axiom-scan webs/webs.txt -m gau -o .tmp/url_extract_gau_tmp.txt 2>>"$LOGFILE" &>/dev/null
					[ -s ".tmp/url_extract_gau_tmp.txt" ] && cat .tmp/url_extract_gau_tmp.txt | anew -q .tmp/url_extract_tmp.txt
				fi
				diff_webs=$(diff <(sort -u .tmp/probed_tmp.txt) <(sort -u webs/webs.txt) | wc -l)
				if [ $diff_webs != "0" ] || [ ! -s ".tmp/gospider.txt" ]; then
					if [ "$DEEP" = true ]; then
						axiom-scan webs/webs.txt -m gospider --js -d 3 --sitemap --robots -w -r -o .tmp/gospider 2>>"$LOGFILE" &>/dev/null
					else
						axiom-scan webs/webs.txt -m gospider --js -d 2 --sitemap --robots -w -r -o .tmp/gospider 2>>"$LOGFILE" &>/dev/null
					fi
					[[ -d .tmp/gospider/ ]] && cat .tmp/gospider/* 2>>"$LOGFILE" | sed '/^.\{2048\}./d' | anew -q .tmp/gospider.txt
				fi
				[[ -d .tmp/gospider/ ]] && NUMFILES=$(find .tmp/gospider/ -type f | wc -l)
				[[ $NUMFILES -gt 0 ]] && cat .tmp/gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | grep ".$domain" | anew -q .tmp/url_extract_tmp.txt
			fi
			if [ -s "${GITHUB_TOKENS}" ]; then
				github-endpoints -q -k -d $domain -t ${GITHUB_TOKENS} -o .tmp/github-endpoints.txt 2>>"$LOGFILE" &>/dev/null
				[ -s ".tmp/github-endpoints.txt" ] && cat .tmp/github-endpoints.txt | anew -q .tmp/url_extract_tmp.txt
			fi
			[ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | grep "${domain}" | grep -Ei "\.(js)" | anew -q js/url_extract_js.txt
			if [ "$DEEP" = true ]; then
				[ -s "js/url_extract_js.txt" ] && cat js/url_extract_js.txt | python3 $tools/JSA/jsa.py | anew -q .tmp/url_extract_tmp.txt
			fi
			[ -s ".tmp/url_extract_tmp.txt" ] &&  cat .tmp/url_extract_tmp.txt | grep "${domain}" | grep "=" | qsreplace -a 2>>"$LOGFILE" | grep -Eiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | anew -q .tmp/url_extract_tmp2.txt
			[ -s ".tmp/url_extract_tmp2.txt" ] && cat .tmp/url_extract_tmp2.txt | uro | anew -q .tmp/url_extract_uddup.txt 2>>"$LOGFILE" &>/dev/null
			NUMOFLINES=$(cat .tmp/url_extract_uddup.txt 2>>"$LOGFILE" | anew webs/url_extract.txt | wc -l)
			notification "${NUMOFLINES} new urls with params" info
			end_func "Results are saved in $domain/webs/url_extract.txt" ${FUNCNAME[0]}
			if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/url_extract.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
				notification "Sending urls to proxy" info
				ffuf -mc all -fc 404 -w webs/url_extract.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" &>/dev/null
			fi
		fi
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function url_gf(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$URL_GF" = true ]; then
		start_func ${FUNCNAME[0]} "Vulnerable Pattern Search"
		mkdir -p gf
		if [ -s "webs/url_extract.txt" ]; then
			gf xss webs/url_extract.txt | anew -q gf/xss.txt
			gf ssti webs/url_extract.txt | anew -q gf/ssti.txt
			gf ssrf webs/url_extract.txt | anew -q gf/ssrf.txt
			gf sqli webs/url_extract.txt | anew -q gf/sqli.txt
			gf redirect webs/url_extract.txt | anew -q gf/redirect.txt
			[ -s "gf/ssrf.txt" ] && cat gf/ssrf.txt | anew -q gf/redirect.txt
			gf rce webs/url_extract.txt | anew -q gf/rce.txt
			gf potential webs/url_extract.txt | cut -d ':' -f3-5 |anew -q gf/potential.txt
			[ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | grep -Eiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | unfurl -u format %s://%d%p 2>>"$LOGFILE" | anew -q gf/endpoints.txt
			gf lfi webs/url_extract.txt | anew -q gf/lfi.txt
		fi
		end_func "Results are saved in $domain/gf folder" ${FUNCNAME[0]}
	else
		if [ "$URL_GF" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function url_ext(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$URL_EXT" = true ]; then
		if [ -s ".tmp/url_extract_tmp.txt" ]; then
			start_func ${FUNCNAME[0]} "Urls by extension"
			ext=("7z" "achee" "action" "adr" "apk" "arj" "ascx" "asmx" "asp" "aspx" "axd" "backup" "bak" "bat" "bin" "bkf" "bkp" "bok" "cab" "cer" "cfg" "cfm" "cfml" "cgi" "cnf" "conf" "config" "cpl" "crt" "csr" "csv" "dat" "db" "dbf" "deb" "dmg" "dmp" "doc" "docx" "drv" "email" "eml" "emlx" "env" "exe" "gadget" "gz" "html" "ica" "inf" "ini" "iso" "jar" "java" "jhtml" "json" "jsp" "key" "log" "lst" "mai" "mbox" "mbx" "md" "mdb" "msg" "msi" "nsf" "ods" "oft" "old" "ora" "ost" "pac" "passwd" "pcf" "pdf" "pem" "pgp" "php" "php3" "php4" "php5" "phtm" "phtml" "pkg" "pl" "plist" "pst" "pwd" "py" "rar" "rb" "rdp" "reg" "rpm" "rtf" "sav" "sh" "shtm" "shtml" "skr" "sql" "swf" "sys" "tar" "tar.gz" "tmp" "toast" "tpl" "txt" "url" "vcd" "vcf" "wml" "wpd" "wsdl" "wsf" "xls" "xlsm" "xlsx" "xml" "xsd" "yaml" "yml" "z" "zip")
			#echo "" > webs/url_extract.txt
			for t in "${ext[@]}"; do
				NUMOFLINES=$(cat .tmp/url_extract_tmp.txt | grep -Ei "\.(${t})($|\/|\?)" | sort -u | wc -l)
				if [[ ${NUMOFLINES} -gt 0 ]]; then
					echo -e "\n############################\n + ${t} + \n############################\n" >> webs/urls_by_ext.txt
					cat .tmp/url_extract_tmp.txt | grep -Ei "\.(${t})($|\/|\?)" >> webs/urls_by_ext.txt
					if [ "$BBRF_CONNECTION" = true ]; then
						cat .tmp/url_extract_tmp.txt | grep -Ei "\.(${t})($|\/|\?)" | bbrf url add - 2>>"$LOGFILE" &>/dev/null
					fi
				fi
			done
			end_func "Results are saved in $domain/webs/urls_by_ext.txt" ${FUNCNAME[0]}
		fi
	else
		if [ "$URL_EXT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function jschecks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$JSCHECKS" = true ]; then
		start_func ${FUNCNAME[0]} "Javascript Scan"
		if [ -s "js/url_extract_js.txt" ]; then
			printf "${yellow} Running : Fetching Urls 1/5${reset}\n"
			if [ ! "$AXIOM" = true ]; then
				cat js/url_extract_js.txt | subjs -ua "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -c 40 | grep "$domain" | anew -q .tmp/subjslinks.txt
			else
				axiom-scan js/url_extract_js.txt -m subjs -o .tmp/subjslinks.txt 2>>"$LOGFILE" &>/dev/null							
			fi
			[ -s .tmp/subjslinks.txt ] && cat .tmp/subjslinks.txt | egrep -iv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)" | anew -q js/nojs_links.txt
			[ -s .tmp/subjslinks.txt ] && cat .tmp/subjslinks.txt | grep -iE "\.js" | anew -q js/url_extract_js.txt
			printf "${yellow} Running : Resolving JS Urls 2/5${reset}\n"
			if [ ! "$AXIOM" = true ]; then
				[ -s "js/url_extract_js.txt" ] && cat js/url_extract_js.txt | httpx -follow-redirects -random-agent -silent -timeout $HTTPX_TIMEOUT -threads $HTTPX_THREADS -status-code -retries 2 -no-color | grep "[200]" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
			else
				[ -s "js/url_extract_js.txt" ] && axiom-scan js/url_extract_js.txt -m httpx -follow-host-redirects -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -no-color -o .tmp/js_livelinks.txt 2>>"$LOGFILE" &>/dev/null
				[ -s ".tmp/js_livelinks.txt" ] && cat .tmp/js_livelinks.txt | anew .tmp/web_full_info.txt | grep "[200]" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
			fi
			printf "${yellow} Running : Gathering endpoints 3/5${reset}\n"
			if [ -s "js/js_livelinks.txt" ]; then
				if [ ! "$AXIOM" = true ]; then
					interlace -tL js/js_livelinks.txt -threads 10 -c "python3 $tools/LinkFinder/linkfinder.py -d -i _target_ -o cli >> .tmp/js_endpoints.txt" &>/dev/null
				else
					axiom-scan js/js_livelinks.txt -m linkfinder -o .tmp/js_endpoints.txt 2>>"$LOGFILE" &>/dev/null			
				fi
			fi
			if [ -s ".tmp/js_endpoints.txt" ]; then
				sed -i '/^\//!d' .tmp/js_endpoints.txt
				cat .tmp/js_endpoints.txt | anew -q js/js_endpoints.txt
			fi
			printf "${yellow} Running : Gathering secrets 4/5${reset}\n"
			if [ ! "$AXIOM" = true ]; then
				[ -s "js/js_livelinks.txt" ] && cat js/js_livelinks.txt | nuclei -silent -t ~/nuclei-templates/ -tags exposure,token -r $resolvers_trusted -retries 3 -o js/js_secrets.txt 2>>"$LOGFILE" &>/dev/null
			else
				[ -s "js/js_livelinks.txt" ] && axiom-scan js/js_livelinks.txt -m nuclei -w /home/op/recon/nuclei/exposures/tokens/ -retries 3 -o js/js_secrets.txt 2>>"$LOGFILE" &>/dev/null
			fi
			printf "${yellow} Running : Building wordlist 5/5${reset}\n"
			[ -s "js/js_livelinks.txt" ] && cat js/js_livelinks.txt | python3 $tools/getjswords.py 2>>"$LOGFILE" | anew -q webs/dict_words.txt
			end_func "Results are saved in $domain/js folder" ${FUNCNAME[0]}
		else
			end_func "No JS urls found for $domain, function skipped" ${FUNCNAME[0]}
		fi
	else
		if [ "$JSCHECKS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function wordlist_gen(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WORDLIST" = true ];	then
		start_func ${FUNCNAME[0]} "Wordlist generation"
		if [ -s ".tmp/url_extract_tmp.txt" ]; then
			cat .tmp/url_extract_tmp.txt | unfurl -u keys 2>>"$LOGFILE" | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q webs/dict_params.txt
			cat .tmp/url_extract_tmp.txt | unfurl -u values 2>>"$LOGFILE" | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q webs/dict_values.txt
			cat .tmp/url_extract_tmp.txt | tr "[:punct:]" "\n" | anew -q webs/dict_words.txt
		fi
		[ -s ".tmp/js_endpoints.txt" ] && cat .tmp/js_endpoints.txt | unfurl -u format %s://%d%p 2>>"$LOGFILE" | anew -q webs/all_paths.txt
		[ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | unfurl -u format %s://%d%p 2>>"$LOGFILE" | anew -q webs/all_paths.txt
		end_func "Results are saved in $domain/webs/dict_[words|paths].txt" ${FUNCNAME[0]}
		if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/all_paths.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
			notification "Sending urls to proxy" info
			ffuf -mc all -fc 404 -w webs/all_paths.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" &>/dev/null
		fi
	else
		if [ "$WORDLIST" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function wordlist_gen_roboxtractor(){
	if  { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$ROBOTSWORDLIST" = true ]; then
		start_func ${FUNCNAME[0]} "Robots wordlist generation"
		if [ -s "webs/webs.txt" ]; then
			cat webs/webs.txt | roboxtractor -m 1 -wb 2>>"$LOGFILE" | anew -q webs/robots_wordlist.txt
		fi
		end_func "Results are saved in $domain/webs/robots_wordlist.txt" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function password_dict(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$PASSWORD_DICT" = true ];	then
		start_func ${FUNCNAME[0]} "Password dictionary generation"
		word=${domain%%.*}
		python3 $tools/pydictor/pydictor.py -extend $word --leet 0 1 2 11 21 --len ${PASSWORD_MIN_LENGTH} ${PASSWORD_MAX_LENGTH} -o webs/password_dict.txt 2>>"$LOGFILE" &>/dev/null
		end_func "Results are saved in $domain/webs/password_dict.txt" ${FUNCNAME[0]}
	else
		if [ "$PASSWORD_DICT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

###############################################################################################################
######################################### VULNERABILITIES #####################################################
###############################################################################################################

function brokenLinks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$BROKENLINKS" = true ] ; then
		start_func ${FUNCNAME[0]} "Broken links checks"
		if [ ! "$AXIOM" = true ]; then
			if [ ! -s ".tmp/gospider.txt" ]; then
				if [ "$DEEP" = true ]; then
					[ -s "webs/webs.txt" ] && gospider -S webs/webs.txt --js -t $GOSPIDER_THREADS -d 3 --sitemap --robots -w -r > .tmp/gospider.txt
				else
					[ -s "webs/webs.txt" ] && gospider -S webs/webs.txt --js -t $GOSPIDER_THREADS -d 2 --sitemap --robots -w -r > .tmp/gospider.txt
				fi
			fi
			[ -s ".tmp/gospider.txt" ] && sed -i '/^.\{2048\}./d' .tmp/gospider.txt
		else
			if [ ! -s ".tmp/gospider.txt" ]; then
				if [ "$DEEP" = true ]; then
					[ -s "webs/webs.txt" ] && axiom-scan webs/webs.txt -m gospider --js -d 3 --sitemap --robots -w -r -o .tmp/gospider 2>>"$LOGFILE" &>/dev/null
				else
					[ -s "webs/webs.txt" ] && axiom-scan webs/webs.txt -m gospider --js -d 2 --sitemap --robots -w -r -o .tmp/gospider 2>>"$LOGFILE" &>/dev/null
				fi
				cat .tmp/gospider/* | sed '/^.\{2048\}./d' | anew -q .tmp/gospider.txt
			fi
		fi
		[ -s ".tmp/gospider.txt" ] && cat .tmp/gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | sort -u | httpx -follow-redirects -H "${HEADER}" -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -no-color | grep "\[4" | cut -d ' ' -f1 | anew -q .tmp/brokenLinks_total.txt
		NUMOFLINES=$(cat .tmp/brokenLinks_total.txt 2>>"$LOGFILE" | anew webs/brokenLinks.txt | wc -l)
		notification "${NUMOFLINES} new broken links found" info
		end_func "Results are saved in webs/brokenLinks.txt" ${FUNCNAME[0]}
	else
		if [ "$BROKENLINKS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function xss(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$XSS" = true ] && [ -s "gf/xss.txt" ]; then
		start_func ${FUNCNAME[0]} "XSS Analysis"
		[ -s "gf/xss.txt" ] && cat gf/xss.txt | qsreplace FUZZ | Gxss -c 100 -p Xss | qsreplace FUZZ | anew -q .tmp/xss_reflected.txt
		if [ ! "$AXIOM" = true ]; then		
			if [ "$DEEP" = true ]; then
				if [ -n "$XSS_SERVER" ]; then
					[ -s ".tmp/xss_reflected.txt" ] && cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --mass --mass-worker 100 --multicast --skip-bav -b ${XSS_SERVER} -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
				else
					printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
					[ -s ".tmp/xss_reflected.txt" ] && cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --mass --mass-worker 100 --multicast --skip-bav -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
				fi
			else
				if [[ $(cat .tmp/xss_reflected.txt | wc -l) -le $DEEP_LIMIT ]]; then
					if [ -n "$XSS_SERVER" ]; then
						cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --mass --mass-worker 100 --multicast --skip-bav --skip-grepping --skip-mining-all --skip-mining-dict -b ${XSS_SERVER} -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
					else
						printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
						cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --mass --mass-worker 100 --multicast --skip-bav --skip-grepping --skip-mining-all --skip-mining-dict -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
					fi
				else
					printf "${bred} Skipping XSS: Too many URLs to test, try with --deep flag${reset}\n"
				fi
			fi
		else
			if [ "$DEEP" = true ]; then
				if [ -n "$XSS_SERVER" ]; then
					[ -s ".tmp/xss_reflected.txt" ] && axiom-scan .tmp/xss_reflected.txt -m dalfox --mass --mass-worker 100 --multicast --skip-bav -b ${XSS_SERVER} -w $DALFOX_THREADS -o vulns/xss.txt 2>>"$LOGFILE" &>/dev/null
				else
					printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
					[ -s ".tmp/xss_reflected.txt" ] && axiom-scan .tmp/xss_reflected.txt -m dalfox --mass --mass-worker 100 --multicast --skip-bav -w $DALFOX_THREADS -o vulns/xss.txt 2>>"$LOGFILE" &>/dev/null
				fi
			else
				if [[ $(cat .tmp/xss_reflected.txt | wc -l) -le $DEEP_LIMIT ]]; then
					if [ -n "$XSS_SERVER" ]; then
						axiom-scan .tmp/xss_reflected.txt -m dalfox --mass --mass-worker 100 --multicast --skip-bav --skip-grepping --skip-mining-all --skip-mining-dict -b ${XSS_SERVER} -w $DALFOX_THREADS -o vulns/xss.txt 2>>"$LOGFILE" &>/dev/null
					else
						printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
						axiom-scan .tmp/xss_reflected.txt -m dalfox --mass --mass-worker 100 --multicast --skip-bav --skip-grepping --skip-mining-all --skip-mining-dict -w $DALFOX_THREADS -o vulns/xss.txt 2>>"$LOGFILE" &>/dev/null
					fi
				else
					printf "${bred} Skipping XSS: Too many URLs to test, try with --deep flag${reset}\n"
				fi
			fi
		fi
		end_func "Results are saved in vulns/xss.txt" ${FUNCNAME[0]}
	else
		if [ "$XSS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/xss.txt" ]; then
				printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to XSS ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function cors(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CORS" = true ]; then
		start_func ${FUNCNAME[0]} "CORS Scan"
		python3 $tools/Corsy/corsy.py -i webs/webs.txt > webs/cors.txt 2>>"$LOGFILE" &>/dev/null
		[ -s "webs/cors.txt" ] && cat webs/cors.txt
		end_func "Results are saved in webs/cors.txt" ${FUNCNAME[0]}
	else
		if [ "$CORS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function open_redirect(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$OPEN_REDIRECT" = true ] && [ -s "gf/redirect.txt" ]; then
		start_func ${FUNCNAME[0]} "Open redirects checks"
		if [ "$DEEP" = true ] || [[ $(cat gf/redirect.txt | wc -l) -le $DEEP_LIMIT ]]; then
			cat gf/redirect.txt | qsreplace FUZZ | anew -q .tmp/tmp_redirect.txt
			python3 $tools/Oralyzer/oralyzer.py -l .tmp/tmp_redirect.txt -p $tools/Oralyzer/payloads.txt > vulns/redirect.txt
			sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" vulns/redirect.txt
			end_func "Results are saved in vulns/redirect.txt" ${FUNCNAME[0]}
		else
			end_func "Skipping Open redirects: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
			printf "${bgreen}#######################################################################${reset}\n"
		fi
	else
		if [ "$OPEN_REDIRECT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/redirect.txt" ]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to Open Redirect ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function ssrf_checks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SSRF_CHECKS" = true ] && [ -s "gf/ssrf.txt" ]; then
		start_func ${FUNCNAME[0]} "SSRF checks"
		if [ -z "$COLLAB_SERVER" ]; then
			interactsh-client &>.tmp/ssrf_callback.txt &
			sleep 2
			COLLAB_SERVER_FIX=$(cat .tmp/ssrf_callback.txt | tail -n1 | cut -c 16-)
			COLLAB_SERVER_URL="http://$COLLAB_SERVER_FIX"
			INTERACT=true
		else
			COLLAB_SERVER_FIX=$(echo ${COLLAB_SERVER} | sed -r "s/https?:\/\///")
			INTERACT=false
		fi
		if [ "$DEEP" = true ] || [[ $(cat gf/ssrf.txt | wc -l) -le $DEEP_LIMIT ]]; then
			cat gf/ssrf.txt | qsreplace ${COLLAB_SERVER_FIX} | anew -q .tmp/tmp_ssrf.txt
			cat gf/ssrf.txt | qsreplace ${COLLAB_SERVER_URL} | anew -q .tmp/tmp_ssrf.txt
			ffuf -v -H "${HEADER}" -t $FFUF_THREADS -w .tmp/tmp_ssrf.txt -u FUZZ 2>>"$LOGFILE" | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssrf_requests_url.txt
			ffuf -v -w .tmp/tmp_ssrf.txt:W1,$tools/headers_inject.txt:W2 -H "${HEADER}" -H "W2: ${COLLAB_SERVER_FIX}" -t $FFUF_THREADS -u W1 2>>"$LOGFILE" | anew -q vulns/ssrf_requests_headers.txt
			ffuf -v -w .tmp/tmp_ssrf.txt:W1,$tools/headers_inject.txt:W2 -H "${HEADER}" -H "W2: ${COLLAB_SERVER_URL}" -t $FFUF_THREADS -u W1 2>>"$LOGFILE" | anew -q vulns/ssrf_requests_headers.txt
			sleep 5
			[ -s ".tmp/ssrf_callback.txt" ] && cat .tmp/ssrf_callback.txt | tail -n+11 | anew -q vulns/ssrf_callback.txt && NUMOFLINES=$(cat .tmp/ssrf_callback.txt | tail -n+12 | wc -l)
			[ "$INTERACT" = true ] && notification "SSRF: ${NUMOFLINES} callbacks received" info
			end_func "Results are saved in vulns/ssrf_*" ${FUNCNAME[0]}
		else
			end_func "Skipping SSRF: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
		pkill -f interactsh-client &
	else
		if [ "$SSRF_CHECKS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/ssrf.txt" ]; then
				printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SSRF ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function crlf_checks(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CRLF_CHECKS" = true ]; then
		start_func ${FUNCNAME[0]} "CRLF checks"
		if [ "$DEEP" = true ] || [[ $(cat webs/webs.txt | wc -l) -le $DEEP_LIMIT ]]; then
			crlfuzz -l webs/webs.txt -o vulns/crlf.txt 2>>"$LOGFILE" &>/dev/null
			end_func "Results are saved in vulns/crlf.txt" ${FUNCNAME[0]}
		else
			end_func "Skipping CRLF: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [ "$CRLF_CHECKS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function lfi(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$LFI" = true ] && [ -s "gf/lfi.txt" ]; then
		start_func ${FUNCNAME[0]} "LFI checks"
		if [ -s "gf/lfi.txt" ]; then
			cat gf/lfi.txt | qsreplace FUZZ | anew -q .tmp/tmp_lfi.txt
			if [ "$DEEP" = true ] || [[ $(cat .tmp/tmp_lfi.txt | wc -l) -le $DEEP_LIMIT ]]; then
				interlace -tL .tmp/tmp_lfi.txt -threads 10 -c "ffuf -v -r -t ${FFUF_THREADS} -H \"${HEADER}\" -w ${lfi_wordlist} -u \"_target_\" -mr \"root:\" " 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/lfi.txt
				end_func "Results are saved in vulns/lfi.txt" ${FUNCNAME[0]}
			else
				end_func "Skipping LFI: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
			fi
		fi
	else
		if [ "$LFI" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/lfi.txt" ]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to LFI ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function ssti(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SSTI" = true ] && [ -s "gf/ssti.txt" ]; then
		start_func ${FUNCNAME[0]} "SSTI checks"
		if [ -s "gf/ssti.txt" ]; then
			cat gf/ssti.txt | qsreplace FUZZ | anew -q .tmp/tmp_ssti.txt
			if [ "$DEEP" = true ] || [[ $(cat .tmp/tmp_ssti.txt | wc -l) -le $DEEP_LIMIT ]]; then
				interlace -tL .tmp/tmp_ssti.txt -threads 10 -c "ffuf -v -r -t ${FFUF_THREADS} -H \"${HEADER}\" -w ${ssti_wordlist} -u \"_target_\" -mr \"ssti49\" " 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssti.txt
				end_func "Results are saved in vulns/ssti.txt" ${FUNCNAME[0]}
			else
				end_func "Skipping SSTI: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
			fi
		fi
	else
		if [ "$SSTI" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/ssti.txt" ]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SSTI ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sqli(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SQLI" = true ] && [ -s "gf/sqli.txt" ]; then
		start_func ${FUNCNAME[0]} "SQLi checks"

		cat gf/sqli.txt | qsreplace FUZZ | anew -q .tmp/tmp_sqli.txt
		if [ "$DEEP" = true ] || [[ $(cat .tmp/tmp_sqli.txt | wc -l) -le $DEEP_LIMIT ]]; then
			interlace -tL .tmp/tmp_sqli.txt -threads 10 -c "python3 $tools/sqlmap/sqlmap.py -u _target_ -b --batch --disable-coloring --random-agent --output-dir=_output_" -o vulns/sqlmap &>/dev/null
			end_func "Results are saved in vulns/sqlmap folder" ${FUNCNAME[0]}
		else
			end_func "Skipping SQLi: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [ "$SQLI" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/sqli.txt" ]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SQLi ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function test_ssl(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$TEST_SSL" = true ]; then
		start_func ${FUNCNAME[0]} "SSL Test"
		$tools/testssl.sh/testssl.sh --quiet --color 0 -U -iL hosts/ips.txt 2>>"$LOGFILE" > hosts/testssl.txt
		end_func "Results are saved in hosts/testssl.txt" ${FUNCNAME[0]}
	else
		if [ "$TEST_SSL" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function spraying(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SPRAY" = true ]; then
		start_func ${FUNCNAME[0]} "Password spraying"
		cd "$tools/brutespray" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		python3 brutespray.py --file $dir/hosts/portscan_active.gnmap --threads $BRUTESPRAY_THREADS --hosts $BRUTESPRAY_CONCURRENCE -o $dir/hosts/brutespray 2>>"$LOGFILE" &>/dev/null
		cd "$dir" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		end_func "Results are saved in hosts/brutespray folder" ${FUNCNAME[0]}
	else
		if [ "$SPRAY" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function command_injection(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$COMM_INJ" = true ] && [ -s "gf/rce.txt" ]; then
		start_func ${FUNCNAME[0]} "Command Injection checks"
		[ -s "gf/rce.txt" ] && cat gf/rce.txt | qsreplace FUZZ | anew -q .tmp/tmp_rce.txt
		if [ "$DEEP" = true ] || [[ $(cat .tmp/tmp_rce.txt | wc -l) -le $DEEP_LIMIT ]]; then
			[ -s ".tmp/tmp_rce.txt" ] && python3 $tools/commix/commix.py --batch -m .tmp/tmp_rce.txt --output-dir vulns/command_injection.txt 2>>"$LOGFILE" &>/dev/null
			end_func "Results are saved in vulns/command_injection folder" ${FUNCNAME[0]}
		else
			end_func "Skipping Command injection: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [ "$COMM_INJ" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "gf/rce.txt" ]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to Command Injection ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function prototype_pollution(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$PROTO_POLLUTION" = true ] ; then
		start_func ${FUNCNAME[0]} "Prototype Pollution checks"
		if [ "$DEEP" = true ] || [[ $(cat webs/url_extract.txt | wc -l) -le $DEEP_LIMIT ]]; then
			[ -s "webs/url_extract.txt" ] && ppfuzz -l webs/url_extract.txt -c $PPFUZZ_THREADS 2>/dev/null | anew -q .tmp/prototype_pollution.txt
			[ -s ".tmp/prototype_pollution.txt" ] && cat .tmp/prototype_pollution.txt | sed -e '1,8d' | sed '/^\[ERR/d' | anew -q vulns/prototype_pollution.txt
			end_func "Results are saved in vulns/prototype_pollution.txt" ${FUNCNAME[0]}
		else
			end_func "Skipping Prototype Pollution: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [ "$PROTO_POLLUTION" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
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
	if [ -s "$SCRIPTPATH/$zip_name" ]; then
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
	cp -r $dir $dir_output
	rm -rf $dir
}

function remove_big_files(){
	eval rm -rf .tmp/gotator*.txt 2>>"$LOGFILE"
	eval rm -rf .tmp/brute_recursive_wordlist.txt 2>>"$LOGFILE"
	eval rm -rf .tmp/subs_dns_tko.txt  2>>"$LOGFILE"
	eval rm -rf .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/brute_dns_tko.txt .tmp/scrap_subs.txt .tmp/analytics_subs_clean.txt .tmp/gotator1.txt .tmp/gotator2.txt .tmp/passive_recursive.txt .tmp/brute_recursive_wordlist.txt .tmp/gotator1_recursive.txt .tmp/gotator2_recursive.txt 2>>"$LOGFILE"
	eval find .tmp -type f -size +200M -exec rm -f {} + 2>>"$LOGFILE"
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
			NOTIFY_CONFIG=~/.config/notify/provider-config.yaml
		fi
		if grep -q '^ telegram\|^telegram\|^    telegram' $NOTIFY_CONFIG ; then
			notification "Sending ${domain} data over Telegram" info
			telegram_chat_id=$(cat ${NOTIFY_CONFIG} | grep '^    telegram_chat_id\|^telegram_chat_id\|^    telegram_chat_id' | xargs | cut -d' ' -f2)
			telegram_key=$(cat ${NOTIFY_CONFIG} | grep '^    telegram_api_key\|^telegram_api_key\|^    telegram_apikey' | xargs | cut -d' ' -f2 )
			curl -F document=@${1} "https://api.telegram.org/bot${telegram_key}/sendDocument?chat_id=${telegram_chat_id}" &>/dev/null
		fi
		if grep -q '^ discord\|^discord\|^    discord' $NOTIFY_CONFIG ; then
			notification "Sending ${domain} data over Discord" info
			discord_url=$(cat ${NOTIFY_CONFIG} | grep '^ discord_webhook_url\|^discord_webhook_url\|^    discord_webhook_url' | xargs | cut -d' ' -f2)
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
	notification "${2}" info
	echo "Start function ${1} $(date +"%F") $(date +"%T")" >> ${LOGFILE}
	start=$(date +%s)
}

function end_func(){
	touch $called_fn_dir/.${2}
	end=$(date +%s)
	getElapsedTime $start $end
	notification "${2} Finished in ${runtime}" info
	echo "End function ${2} $(date +"%F") $(date +"%T")" >> ${LOGFILE}
	printf "${bblue} ${1} ${reset}\n"
	printf "${bgreen}#######################################################################${reset}\n"
}

function start_subfunc(){
	notification "${2}" warn
	echo "Start subfunction ${1} $(date +"%F") $(date +"%T")" >> ${LOGFILE}
	start_sub=$(date +%s)
}

function end_subfunc(){
	touch $called_fn_dir/.${2}
	end_sub=$(date +%s)
	getElapsedTime $start_sub $end_sub
	notification "${1} in ${runtime}" good
	echo "End subfunction ${1} $(date +"%F") $(date +"%T")" >> ${LOGFILE}
}

function resolvers_update(){
	if [ "$update_resolvers" = true ]; then
		if [ ! "$AXIOM" = true ]; then	
			if [[ $(find "$resolvers" -mtime +1 -print) ]]; then
				notification "Resolvers seem older than 1 day\n Generating custom resolvers..." warn
				eval rm -f $resolvers 2>>"$LOGFILE"
				dnsvalidator -tL https://public-dns.info/nameservers.txt -threads $DNSVALIDATOR_THREADS -o $resolvers &>/dev/null
				dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads $DNSVALIDATOR_THREADS -o tmp_resolvers &>/dev/null
				cat tmp_resolvers | anew -q $resolvers
				rm -f tmp_resolvers &>/dev/null
				[ ! -s "$resolvers" ] && wget -O $resolvers https://raw.githubusercontent.com/proabiral/Fresh-Resolvers/master/resolvers.txt &>/dev/null
				notification "Updated\n" good
	  		fi
		else
			notification "Checking resolvers lists...\n Accurate resolvers are the key to great results\n This may take around 10 minutes if it's not updated" warn
			# shellcheck disable=SC2016
			axiom-exec 'if [ \$(find "/home/op/lists/resolvers.txt" -mtime +1 -print) ] || [ \$(cat /home/op/lists/resolvers.txt | wc -l) -le 40 ] ; then dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o /home/op/lists/resolvers.txt ; fi' &>/dev/null
			notification "Updated\n" good
			axiom-exec 'wget -O /home/op/lists/resolvers_trusted.txt https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw' &>/dev/null
			axiom-exec 'wget -O /home/op/lists/onelistforallmicro.txt https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt' &>/dev/null

		fi
		update_resolvers=false
	fi
}

function ipcidr_target(){
	if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		echo $1 | mapcidr -silent | anew -q target_reconftw_ipcidr.txt
		if [ -s "./target_reconftw_ipcidr.txt" ]; then 
			[ "$REVERSE_IP" = true ] && cat ./target_reconftw_ipcidr.txt | dnsx -ptr -resp-only -silent -retry 3 | unfurl -u domains 2>/dev/null | sed 's/\.$//' | anew -q ./target_reconftw_ipcidr.txt
			if [[ $(cat ./target_reconftw_ipcidr.txt | wc -l) -eq 1 ]]; then
				domain=$(cat ./target_reconftw_ipcidr.txt)
			elif [[ $(cat ./target_reconftw_ipcidr.txt | wc -l) -gt 1 ]]; then
				unset domain
				list=${PWD}/target_reconftw_ipcidr.txt
			fi
		fi
		if [ -n "$2" ]; then
			cat $list | anew -q $2
			sed -i '/\/[0-9]*$/d' $2
		fi
	fi
}

function axiom_lauch(){
	# let's fire up a FLEET!
	if [ "$AXIOM_FLEET_LAUNCH" = true ] && [ -n "$AXIOM_FLEET_NAME" ] && [ -n "$AXIOM_FLEET_COUNT" ]; then
		start_func ${FUNCNAME[0]} "Launching our Axiom fleet"
		python3 -m pip install --upgrade linode-cli 2>>"$LOGFILE" &>/dev/null
		# Check to see if we have a fleet already, if so, SKIP THIS!
		NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME")
		if [[ $NUMOFNODES -ge $AXIOM_FLEET_COUNT ]]; then
			axiom-select "$AXIOM_FLEET_NAME*"
			end_func "Axiom fleet $AXIOM_FLEET_NAME already has $NUMOFNODES instances"
		else
			if [[ $NUMOFNODES -eq 0 ]]; then
				startcount=$AXIOM_FLEET_COUNT
			else
				startcount=$((AXIOM_FLEET_COUNT-NUMOFNODES))
			fi
			AXIOM_ARGS=" -i $startcount"
			# Temporarily disabled multiple axiom regions
			# [ -n "$AXIOM_FLEET_REGIONS" ] && axiom_args="$axiom_args --regions=\"$AXIOM_FLEET_REGIONS\" "

			echo "axiom-fleet ${AXIOM_FLEET_NAME} ${AXIOM_ARGS}"
			axiom-fleet ${AXIOM_FLEET_NAME} ${AXIOM_ARGS}
			axiom-select "$AXIOM_FLEET_NAME*"
			if [ -n "$AXIOM_POST_START" ]; then
				eval "$AXIOM_POST_START" 2>>"$LOGFILE" &>/dev/null
			fi

			NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME" )
			echo "Axiom fleet $AXIOM_FLEET_NAME launched w/ $NUMOFNODES instances" | $NOTIFY
			end_func "Axiom fleet $AXIOM_FLEET_NAME launched w/ $NUMOFNODES instances"
		fi
	fi
}

function axiom_shutdown(){
	if [ "$AXIOM_FLEET_LAUNCH" = true ] && [ "$AXIOM_FLEET_SHUTDOWN" = true ] && [ -n "$AXIOM_FLEET_NAME" ]; then
		#if [ "$mode" == "subs_menu" ] || [ "$mode" == "list_recon" ] || [ "$mode" == "passive" ] || [ "$mode" == "all" ]; then
		if [ "$mode" == "subs_menu" ] || [ "$mode" == "passive" ] || [ "$mode" == "all" ]; then
			notification "Automatic Axiom fleet shutdown is not enabled in this mode" info
			return
		fi
		eval axiom-rm -f "$AXIOM_FLEET_NAME*"
		echo "Axiom fleet $AXIOM_FLEET_NAME shutdown" | $NOTIFY
		notification "Axiom fleet $AXIOM_FLEET_NAME shutdown" info
	fi
}

function axiom_selected(){

	if [[ ! $(axiom-ls | tail -n +2 | sed '$ d' | wc -l) -gt 0 ]]; then
		notification "\n\n${bred} No axiom instances running ${reset}\n\n" error
		exit
	fi

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

	if [[ $(id -u | grep -o '^0$') == "0" ]]; then
    	SUDO=" "
	else
    	SUDO="sudo"
	fi
	
	printf "\n${bgreen}#######################################################################${reset}"
	notification "Recon succesfully started on ${domain}" good
	[ "$SOFT_NOTIFICATION" = true ] && echo "Recon succesfully started on ${domain}" | notify -silent
	printf "${bgreen}#######################################################################${reset}\n"
	tools_installed

	#[[ -n "$domain" ]] && ipcidr_target $domain


	if [ -z "$domain" ]; then
		if [ -n "$list" ]; then
			if [ -z "$domain" ]; then
				domain="Multi"
				dir="$SCRIPTPATH/Recon/$domain"
				called_fn_dir="$dir"/.called_fn
			fi
			if [[ "$list" = /* ]]; then
				install -D "$list" "$dir"/webs/webs.txt
			else
				install -D "$SCRIPTPATH"/"$list" "$dir"/webs/webs.txt
			fi
		fi
	else
		dir="$SCRIPTPATH/Recon/$domain"
		called_fn_dir="$dir"/.called_fn
	fi

	if [ -z "$domain" ]; then
		notification "\n\n${bred} No domain or list provided ${reset}\n\n" error
		exit
	fi

	if [ ! -d "$called_fn_dir" ]; then
		mkdir -p "$called_fn_dir"
	fi
	mkdir -p "$dir"
	cd "$dir"  || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	if [ "$AXIOM" = true ]; then
		if [ -n "$domain" ]; then
			echo "$domain" | anew -q target.txt
			list="${dir}/target.txt"
		fi
	fi
	mkdir -p .tmp .log osint subdomains webs hosts vulns

	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "Start ${NOW} ${NOWT}" > ${LOGFILE}
	if [ -n "$findomain_virustotal_token" ]; then
		VT_API_KEY=$findomain_virustotal_token
	fi

	if [ "$BBRF_CONNECTION" = true ]; then
		program_bbrf=$(echo $domain | awk -F. '{print $1"_"$2}') 2>>"$LOGFILE" &>/dev/null
		bbrf new ${program_bbrf} 2>>"$LOGFILE" &>/dev/null
		bbrf use ${program_bbrf} 2>>"$LOGFILE" &>/dev/null
		bbrf inscope add "*.${domain}" 2>>"$LOGFILE" &>/dev/null
	fi

	printf "\n"
	printf "${bred} Target: ${domain}\n\n"
}

function end(){

	find $dir -type f -empty -print | grep -v '.called_fn' | grep -v '.log' | grep -v '.tmp' | xargs rm -f &>/dev/null
	find $dir -type d -empty -print -delete &>/dev/null

	echo "End $(date +"%F") $(date +"%T")" >> ${LOGFILE}

	if [ ! "$PRESERVE" = true ]; then
		find $dir -type f -empty | grep -v "called_fn" | xargs rm -f &>/dev/null
		find $dir -type d -empty | grep -v "called_fn" | xargs rm -rf &>/dev/null
	fi

	if [ "$REMOVETMP" = true ]; then
		rm -rf $dir/.tmp
	fi

    if [ "$REMOVELOG" = true ]; then
            rm -rf $dir/.log
    fi 

	if [ -n "$dir_output" ]; then
		output
		finaldir=$dir_output
	else
		finaldir=$dir
	fi
	#Zip the output folder and send it via tg/discord/slack
	if [ "$SENDZIPNOTIFY" = true ]; then
		zipSnedOutputFolder
	fi
	global_end=$(date +%s)
	getElapsedTime $global_start $global_end
	printf "${bgreen}#######################################################################${reset}\n"
	notification "Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" good
	[ "$SOFT_NOTIFICATION" = true ] && echo "Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" | notify -silent
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
	ip_info
	emails
	google_dorks
	github_dorks
	metadata
	SUBSCRAPING=false
	WEBPROBESIMPLE=false

	if [ "$AXIOM" = true ]; then
		axiom_lauch
		axiom_selected
	fi

	subdomains_full
	remove_big_files
	favicon
	PORTSCAN_ACTIVE=false
	portscan
	
	if [ "$AXIOM" = true ]; then
		axiom_shutdown
	fi

	cloudprovider
	end
}

function all(){
	start
	recon
	vulns
	end
}

function osint(){
	domain_info
	ip_info
	emails
	google_dorks
	github_dorks
	metadata
	zonetransfer
	favicon
}

function vulns(){
	if [ "$VULNS_GENERAL" = true ]; then
		cors
		open_redirect
		ssrf_checks
		crlf_checks
		lfi
		ssti
		sqli
		xss
		command_injection
		prototype_pollution
		spraying
		brokenLinks
		test_ssl
	fi
}

function multi_osint(){

	global_start=$(date +%s)

	if [ "$NOTIFICATION" = true ]; then
		NOTIFY="notify -silent"
	else
	    NOTIFY=""
	fi

	if [[ $(id -u | grep -o '^0$') == "0" ]]; then
    	SUDO=" "
	else
    	SUDO="sudo"
	fi

	#[[ -n "$domain" ]] && ipcidr_target $domain

	if [ -s "$list" ]; then
		sed -i 's/\r$//' $list
		targets=$(cat $list)
	else
		notification "Target list not provided" error
		exit
	fi

	workdir=$SCRIPTPATH/Recon/$multi
	mkdir -p $workdir  || { echo "Failed to create directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	mkdir -p .tmp .called_fn osint subdomains webs hosts vulns

	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "Start ${NOW} ${NOWT}" > ${LOGFILE}

	for domain in $targets; do
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		mkdir -p $dir
		cd "$dir"  || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		mkdir -p .tmp .called_fn osint subdomains webs hosts vulns
		NOW=$(date +"%F")
		NOWT=$(date +"%T")
		LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
		touch .log/${NOW}_${NOWT}.txt
		echo "Start ${NOW} ${NOWT}" > ${LOGFILE}
		domain_info
		ip_info
		emails
		google_dorks
		github_dorks
		metadata
		zonetransfer
		favicon
	done
	cd "$workdir" || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	dir=$workdir
	domain=$multi
	end
}


function recon(){
	domain_info
	ip_info
	emails
	google_dorks
	github_dorks
	metadata
	zonetransfer
	favicon

	if [ "$AXIOM" = true ]; then
		axiom_lauch
		axiom_selected
	fi

	subdomains_full
	subtakeover
	remove_big_files
	webprobe_full
	s3buckets
	screenshot
	portscan
	waf_checks
	nuclei_check
	fuzz
	urlchecks
	jschecks

	if [ "$AXIOM" = true ]; then
		axiom_shutdown
	fi

	cloudprovider
	cms_scanner
	url_gf
	wordlist_gen
	wordlist_gen_roboxtractor
	password_dict
	url_ext
}

function multi_recon(){


	global_start=$(date +%s)

	if [ "$NOTIFICATION" = true ]; then
		NOTIFY="notify -silent"
	else
	    NOTIFY=""
	fi

	if [[ $(id -u | grep -o '^0$') == "0" ]]; then
    	SUDO=" "
	else
    	SUDO="sudo"
	fi

	#[[ -n "$domain" ]] && ipcidr_target $domain

	if [ -s "$list" ]; then
		 sed -i 's/\r$//' $list
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
	LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "Start ${NOW} ${NOWT}" > ${LOGFILE}

	[ -n "$flist" ] && LISTTOTAL=$(cat "$flist" | wc -l )

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
		echo "Start ${NOW} ${NOWT}" > ${LOGFILE}
		loopstart=$(date +%s)

		domain_info
		ip_info
		emails
		google_dorks
		github_dorks
		metadata
		zonetransfer
		favicon
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen} $domain finished 1st loop in ${runtime}  $currently ${reset}\n"
		if [ -n "$flist" ]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done
	cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

	if [ "$AXIOM" = true ]; then
		axiom_lauch
		axiom_selected
	fi

	for domain in $targets; do
		loopstart=$(date +%s)
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		cd "$dir"  || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		subdomains_full
		subtakeover
		remove_big_files
		webprobe_full
		screenshot
		portscan
		cloudprovider
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen} $domain finished 2nd loop in ${runtime}  $currently ${reset}\n"
		if [ -n "$flist" ]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
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
	NUMOFLINES_ips_total=$(find . -type f -name 'ips.txt' -exec cat {} + | anew hosts/ips.txt | wc -l)
	NUMOFLINES_cloudsprov_total=$(find . -type f -name 'cloud_providers.txt' -exec cat {} + | anew hosts/cloud_providers.txt | wc -l)
	find . -type f -name 'portscan_active.txt' -exec cat {} + > hosts/portscan_active.txt 2>>"$LOGFILE" &>/dev/null
	find . -type f -name 'portscan_active.gnmap' -exec cat {} + > hosts/portscan_active.gnmap 2>>"$LOGFILE" &>/dev/null
	find . -type f -name 'portscan_passive.txt' -exec cat {} + > hosts/portscan_passive.txt 2>>"$LOGFILE" &>/dev/null

	notification "- ${NUMOFLINES_users_total} total users found" good
	notification "- ${NUMOFLINES_pwndb_total} total creds leaked" good
	notification "- ${NUMOFLINES_software_total} total software found" good
	notification "- ${NUMOFLINES_authors_total} total authors found" good
	notification "- ${NUMOFLINES_subs_total} total subdomains" good
	notification "- ${NUMOFLINES_subtko_total} total probably subdomain takeovers" good
	notification "- ${NUMOFLINES_webs_total} total websites" good
	notification "- ${NUMOFLINES_ips_total} total ips" good
	notification "- ${NUMOFLINES_cloudsprov_total} total IPs belongs to cloud" good
	s3buckets
	waf_checks
	nuclei_check
	for domain in $targets; do
		loopstart=$(date +%s)
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		cd "$dir" || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		loopstart=$(date +%s)
		fuzz
		urlchecks
		jschecks
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen} $domain finished 3rd loop in ${runtime}  $currently ${reset}\n"
		if [ -n "$flist" ]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done

	if [ "$AXIOM" = true ]; then
		axiom_shutdown
	fi

	for domain in $targets; do
		loopstart=$(date +%s)
		dir=$workdir/targets/$domain
        called_fn_dir=$dir/.called_fn 
		cd "$dir" || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		cms_scanner
		url_gf
		wordlist_gen
		wordlist_gen_roboxtractor
		password_dict
		url_ext
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen} $domain finished final loop in ${runtime}  $currently ${reset}\n"
		if [ -n "$flist" ]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done
	cd "$workdir" || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	dir=$workdir
	domain=$multi
	end
}

function subs_menu(){
	start

	if [ "$AXIOM" = true ]; then
		axiom_lauch
		axiom_selected
	fi

	subdomains_full
	subtakeover
	remove_big_files
	webprobe_full
	screenshot
	zonetransfer
	s3buckets

	if [ "$AXIOM" = true ]; then
		axiom_shutdown
	fi

	end
}

function webs_menu(){
	subtakeover
	remove_big_files
	screenshot
	waf_checks
	nuclei_check
	cms_scanner
	fuzz
	urlchecks
	jschecks
	url_gf
	wordlist_gen
	wordlist_gen_roboxtractor
	password_dict
	url_ext
	vulns
	end
}

function help(){
	printf "\n Usage: $0 [-d domain.tld] [-m name] [-l list.txt] [-x oos.txt] [-i in.txt] "
	printf "\n           	      [-r] [-s] [-p] [-a] [-w] [-n] [-i] [-h] [-f] [--deep] [-o OUTPUT]\n\n"
	printf " ${bblue}TARGET OPTIONS${reset}\n"
	printf "   -d domain.tld     Target domain\n"
	printf "   -m company        Target company name\n"
	printf "   -l list.txt       Targets list, one per line\n"
	printf "   -x oos.txt        Exclude subdomains list (Out Of Scope)\n"
	printf "   -i in.txt         Include subdomains list\n"
	printf " \n"
	printf " ${bblue}MODE OPTIONS${reset}\n"
	printf "   -r, --recon       Recon - Full recon process (only recon without attacks)\n"
	printf "   -s, --subdomains  Subdomains - Search subdomains, check tko and web probe\n"
	printf "   -p, --passive     Passive - Performs only passive steps \n"
	printf "   -a, --all         All - Perform all checks and exploitations\n"
	printf "   -w, --web         Web - Just web checks from list provided\n"
	printf "   -n, --osint       OSINT - Just checks public intel info\n"
	printf "   -h                Help - Show this help\n"
	printf " \n"
	printf " ${bblue}GENERAL OPTIONS${reset}\n"
	printf "   --deep            Deep scan (Enable some slow options for deeper scan)\n"
	printf "   -f confile_file   Alternate reconftw.cfg file\n"
	printf "   -o output/path    Define output folder\n"
	printf "   -v, --vps         Axiom distributed VPS \n"
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

PROGARGS=$(getopt -o 'd:m:l:x:i:o:f:c:rspanwvh::' --long 'domain:,list:,recon,subdomains,passive,all,web,osint,deep,help,vps' -n 'reconFTW' -- "$@")


# Note the quotes around "$PROGARGS": they are essential!
eval set -- "$PROGARGS"
unset PROGARGS

while true; do
    case "$1" in
        '-d'|'--domain')
            domain=$2
			ipcidr_target $2
            shift 2
            continue
            ;;
        '-m')
            multi=$2
            shift 2
            continue
            ;;
        '-l'|'--list')
			list=$2
			for domain in $(cat $list); do
				ipcidr_target $domain $list
			done
            shift 2
            continue
            ;;
        '-x')
            outOfScope_file=$2
            shift 2
            continue
            ;;
        '-i')
            inScope_file=$2
            shift 2
            continue
            ;;

        # modes
        '-r'|'--recon')
            opt_mode='r'
            shift
            continue
            ;;
        '-s'|'--subdomains')
            opt_mode='s'
            shift
            continue
            ;;
        '-p'|'--passive')
            opt_mode='p'
            shift
            continue
            ;;
        '-a'|'--all')
            opt_mode='a'
            shift
            continue
            ;;
        '-w'|'--web')
            opt_mode='w'
            shift
            continue
            ;;
        '-n'|'--osint')
            opt_mode='n'
            shift
            continue
            ;;
		'-c')
			custom_function=$2
			opt_mode='c'
            shift 2
            continue
            ;;
        # extra stuff
        '-o')
			if [[ "$2" != /* ]]; then
            	dir_output=$PWD/$2
			else
				dir_output=$2
			fi
            shift 2
            continue
            ;;
		'-v'|'--vps')
			type -P axiom-ls &>/dev/null || { printf "\n Axiom is needed for this mode and is not installed \n You have to install it manually \n" && exit; allinstalled=false;}
			AXIOM=true
            shift
            continue
            ;;
        '-f')
			config_file=$2
            shift 2
            continue
            ;;
        '--deep')
            opt_deep=true
            shift
            continue
            ;;

        '--')
			shift
			break
		    ;;
        '--help'| '-h'| *)
            # echo "Unknown argument: $1"
            . ./reconftw.cfg
			banner
            help
			tools_installed
			exit 1
		    ;;
    esac
done

# This is the first thing to do to read in alternate config
if [ -s "$config_file" ]; then
    . "${config_file}"
else
	SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
    . "$SCRIPTPATH"/reconftw.cfg
fi

if [ $opt_deep ]; then
    DEEP=true
fi

if [ -n "$outOfScope_file" ]; then
    isAsciiText $outOfScope_file
    if [ "False" = "$IS_ASCII" ]
    then
        printf "\n\n${bred} Out of Scope file is not a text file${reset}\n\n"
        exit
    fi
fi

if [ -n "$inScope_file" ]; then
    isAsciiText $inScope_file
    if [ "False" = "$IS_ASCII" ]
    then
        printf "\n\n${bred} In Scope file is not a text file${reset}\n\n"
        exit
    fi
fi

startdir=${PWD}

banner

check_version

startdir=${PWD}
if [ -n "$list" ]; then
	if [[ "$list" = ./* ]]; then
		flist="${startdir}/${list:2}"
	elif [[ "$list" = ~* ]]; then
		flist="${HOME}/${list:2}"
	elif [[ "$list" = /* ]]; then
		flist=$list
	else
		flist="$startdir/$list"
	fi
else
	flist=''
fi

case $opt_mode in
        'r')
            if [ -n "$multi" ];	then
				if [ "$AXIOM" = true ]; then
					mode="multi_recon"
				fi
				multi_recon
				exit
			fi
			if [ -n "$list" ]; then
				if [ "$AXIOM" = true ]; then
					mode="list_recon"
				fi
				sed -i 's/\r$//' $list
				for domain in $(cat $list); do
					start
					recon
					end
				done
			else
				if [ "$AXIOM" = true ]; then
					mode="recon"
				fi
				start
				recon
				end
			fi
            ;;
        's')
            if [ -n "$list" ]; then
				if [ "$AXIOM" = true ]; then
					mode="subs_menu"
				fi
				sed -i 's/\r$//' $list
				for domain in $(cat $list); do
					subs_menu
				done
			else
				subs_menu
			fi
            ;;
        'p')
            if [ -n "$list" ]; then
				if [ "$AXIOM" = true ]; then
					mode="passive"
				fi
				sed -i 's/\r$//' $list
				for domain in $(cat $list); do
					passive
				done
			else
				passive
			fi
            ;;
        'a')
			export VULNS_GENERAL=true
            if [ -n "$list" ]; then
				if [ "$AXIOM" = true ]; then
					mode="all"
				fi
				sed -i 's/\r$//' $list
				for domain in $(cat $list); do
					all
				done
			else
				all
			fi
            ;;
        'w')
			if [ -n "$list" ]; then
				start
				if [[ "$list" = /* ]]; then
					cp $list $dir/webs/webs.txt
				else
					cp $SCRIPTPATH/$list $dir/webs/webs.txt
				fi
			else
				printf "\n\n${bred} Web mode needs a website list file as target (./reconftw.sh -l target.txt -w) ${reset}\n\n"
				exit
			fi
			webs_menu
			exit
            ;;
        'n')
			PRESERVE=true
			if [ -n "$multi" ];	then
				multi_osint
				exit
			fi
			if [ -n "$list" ]; then
				sed -i 's/\r$//' $list
				for domain in $(cat $list); do
					start
					osint
					end
				done
			else
				start
				osint
				end
			fi
			;;
		'c')
			export DIFF=true
			dir="$SCRIPTPATH/Recon/$domain"
			cd $dir || { echo "Failed to cd directory '$dir'"; exit 1; }
			$custom_function
			cd $SCRIPTPATH || { echo "Failed to cd directory '$dir'"; exit 1; }
			exit
            ;;
        # No mode selected.  EXIT!
        *)
            help
            tools_installed
            exit 1
            ;;
esac
