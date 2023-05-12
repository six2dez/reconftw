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
	timeout 10 git fetch
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

	[ -n "$GOPATH" ] || { printf "${bred} [*] GOPATH var			[NO]${reset}\n"; allinstalled=false;}
	[ -n "$GOROOT" ] || { printf "${bred} [*] GOROOT var			[NO]${reset}\n"; allinstalled=false;}
	[ -n "$PATH" ] || { printf "${bred} [*] PATH var			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/dorks_hunter/dorks_hunter.py" ] || { printf "${bred} [*] dorks_hunter		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/brutespray/brutespray.py" ] || { printf "${bred} [*] brutespray			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/fav-up/favUp.py" ] || { printf "${bred} [*] fav-up			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/Corsy/corsy.py" ] || { printf "${bred} [*] Corsy			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/testssl.sh/testssl.sh" ] || { printf "${bred} [*] testssl			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/CMSeeK/cmseek.py" ] || { printf "${bred} [*] CMSeeK			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/ctfr/ctfr.py" ] || { printf "${bred} [*] ctfr			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/fuzz_wordlist.txt" ] || { printf "${bred} [*] OneListForAll		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/xnLinkFinder/xnLinkFinder.py" ] || { printf "${bred} [*] xnLinkFinder		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/waymore/waymore.py" ] || { printf "${bred} [*] waymore		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/commix/commix.py" ] || { printf "${bred} [*] commix			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/getjswords.py" ] || { printf "${bred} [*] getjswords   		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/JSA/jsa.py" ] || { printf "${bred} [*] JSA			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/cloud_enum/cloud_enum.py" ] || { printf "${bred} [*] cloud_enum			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/ultimate-nmap-parser/ultimate-nmap-parser.sh" ] || { printf "${bred} [*] nmap-parse-output		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/pydictor/pydictor.py" ] || { printf "${bred} [*] pydictor   		[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/urless/urless.py" ] || { printf "${bred} [*] urless			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/smuggler/smuggler.py" ] || { printf "${bred} [*] smuggler			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/regulator/main.py" ] || { printf "${bred} [*] regulator			[NO]${reset}\n"; allinstalled=false;}
	[ -f "$tools/Infoga/infoga.py" ] || { printf "${bred} [*] infoga			[NO]${reset}\n"; allinstalled=false;}
	which github-endpoints &>/dev/null || { printf "${bred} [*] github-endpoints		[NO]${reset}\n"; allinstalled=false;}
	which github-subdomains &>/dev/null || { printf "${bred} [*] github-subdomains		[NO]${reset}\n"; allinstalled=false;}
	which gitlab-subdomains &>/dev/null || { printf "${bred} [*] gitlab-subdomains		[NO]${reset}\n"; allinstalled=false;}
	which katana &>/dev/null || { printf "${bred} [*] katana			[NO]${reset}\n"; allinstalled=false;}
	which wafw00f &>/dev/null || { printf "${bred} [*] wafw00f			[NO]${reset}\n"; allinstalled=false;}
	which dnsvalidator &>/dev/null || { printf "${bred} [*] dnsvalidator		[NO]${reset}\n"; allinstalled=false;}
	which gowitness &>/dev/null || { printf "${bred} [*] gowitness			[NO]${reset}\n"; allinstalled=false;}
	which amass &>/dev/null || { printf "${bred} [*] Amass			[NO]${reset}\n"; allinstalled=false;}
	which dnsx &>/dev/null || { printf "${bred} [*] dnsx			[NO]${reset}\n"; allinstalled=false;}
	which gotator &>/dev/null || { printf "${bred} [*] gotator			[NO]${reset}\n"; allinstalled=false;}
	which nuclei &>/dev/null || { printf "${bred} [*] Nuclei			[NO]${reset}\n"; allinstalled=false;}
	[ -d ~/nuclei-templates ] || { printf "${bred} [*] Nuclei templates	[NO]${reset}\n"; allinstalled=false;}
	which gf &>/dev/null || { printf "${bred} [*] Gf				[NO]${reset}\n"; allinstalled=false;}
	which Gxss &>/dev/null || { printf "${bred} [*] Gxss			[NO]${reset}\n"; allinstalled=false;}
	which subjs &>/dev/null || { printf "${bred} [*] subjs			[NO]${reset}\n"; allinstalled=false;}
	which ffuf &>/dev/null || { printf "${bred} [*] ffuf			[NO]${reset}\n"; allinstalled=false;}
	which massdns &>/dev/null || { printf "${bred} [*] Massdns			[NO]${reset}\n"; allinstalled=false;}
	which qsreplace &>/dev/null || { printf "${bred} [*] qsreplace			[NO]${reset}\n"; allinstalled=false;}
	which interlace &>/dev/null || { printf "${bred} [*] interlace			[NO]${reset}\n"; allinstalled=false;}
	which anew &>/dev/null || { printf "${bred} [*] Anew			[NO]${reset}\n"; allinstalled=false;}
	which unfurl &>/dev/null || { printf "${bred} [*] unfurl			[NO]${reset}\n"; allinstalled=false;}
	which crlfuzz &>/dev/null || { printf "${bred} [*] crlfuzz			[NO]${reset}\n"; allinstalled=false;}
	which httpx &>/dev/null || { printf "${bred} [*] Httpx			[NO]${reset}\n${reset}"; allinstalled=false;}
	which jq &>/dev/null || { printf "${bred} [*] jq				[NO]${reset}\n${reset}"; allinstalled=false;}
	which notify &>/dev/null || { printf "${bred} [*] notify			[NO]${reset}\n${reset}"; allinstalled=false;}
	which dalfox &>/dev/null || { printf "${bred} [*] dalfox			[NO]${reset}\n${reset}"; allinstalled=false;}
	which puredns &>/dev/null || { printf "${bred} [*] puredns			[NO]${reset}\n${reset}"; allinstalled=false;}
	which unimap &>/dev/null || { printf "${bred} [*] unimap			[NO]${reset}\n${reset}"; allinstalled=false;}
	which emailfinder &>/dev/null || { printf "${bred} [*] emailfinder		[NO]${reset}\n"; allinstalled=false;}
	which analyticsrelationships &>/dev/null || { printf "${bred} [*] analyticsrelationships	[NO]${reset}\n"; allinstalled=false;}
	which mapcidr &>/dev/null || { printf "${bred} [*] mapcidr			[NO]${reset}\n"; allinstalled=false;}
	which ppfuzz &>/dev/null || { printf "${bred} [*] ppfuzz			[NO]${reset}\n"; allinstalled=false;}
	which searchsploit &>/dev/null || { printf "${bred} [*] searchsploit		[NO]${reset}\n"; allinstalled=false;}
	which cdncheck &>/dev/null || { printf "${bred} [*] cdncheck			[NO]${reset}\n"; allinstalled=false;}
	which interactsh-client &>/dev/null || { printf "${bred} [*] interactsh-client		[NO]${reset}\n"; allinstalled=false;}
	which tlsx &>/dev/null || { printf "${bred} [*] tlsx			[NO]${reset}\n"; allinstalled=false;}
	which bbrf &>/dev/null || { printf "${bred} [*] bbrf			[NO]${reset}\n"; allinstalled=false;}
	which smap &>/dev/null || { printf "${bred} [*] smap			[NO]${reset}\n"; allinstalled=false;}
	which gitdorks_go &>/dev/null || { printf "${bred} [*] gitdorks_go		[NO]${reset}\n"; allinstalled=false;}
	which ripgen &>/dev/null || { printf "${bred} [*] ripgen			[NO]${reset}\n${reset}"; allinstalled=false;}
	which dsieve &>/dev/null || { printf "${bred} [*] dsieve			[NO]${reset}\n${reset}"; allinstalled=false;}
	which inscope &>/dev/null || { printf "${bred} [*] inscope			[NO]${reset}\n${reset}"; allinstalled=false;}
	which enumerepo &>/dev/null || { printf "${bred} [*] enumerepo			[NO]${reset}\n${reset}"; allinstalled=false;}
	which trufflehog &>/dev/null || { printf "${bred} [*] trufflehog			[NO]${reset}\n${reset}"; allinstalled=false;}
	which Web-Cache-Vulnerability-Scanner &>/dev/null || { printf "${bred} [*] Web-Cache-Vulnerability-Scanner [NO]${reset}\n"; allinstalled=false;}
	which subfinder &>/dev/null || { printf "${bred} [*] subfinder			[NO]${reset}\n${reset}"; allinstalled=false;}
	which byp4xx &>/dev/null || { printf "${bred} [*] byp4xx			[NO]${reset}\n${reset}"; allinstalled=false;}
	which ghauri &>/dev/null || { printf "${bred} [*] ghauri			[NO]${reset}\n${reset}"; allinstalled=false;}
	which hakip2host &>/dev/null || { printf "${bred} [*] hakip2host			[NO]${reset}\n${reset}"; allinstalled=false;}
	which gau &>/dev/null || { printf "${bred} [*] gau			[NO]${reset}\n${reset}"; allinstalled=false;}
	which subgpt &>/dev/null || { printf "${bred} [*] subgpt			[NO]${reset}\n${reset}"; allinstalled=false;}
	
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
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$GOOGLE_DORKS" = true ] && [ "$OSINT" = true ]; then
		python3 $tools/dorks_hunter/dorks_hunter.py -d $domain -o osint/dorks.txt
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
				gitdorks_go -gd $tools/gitdorks_go/Dorks/medium_dorks.txt -nws 20 -target $domain -tf "${GITHUB_TOKENS}" -ew 3 | anew -q osint/gitdorks.txt
			else
				gitdorks_go -gd $tools/gitdorks_go/Dorks/smalldorks.txt -nws 20 -target $domain -tf "${GITHUB_TOKENS}" -ew 3 | anew -q osint/gitdorks.txt
			fi
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

function github_repos(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$GITHUB_REPOS" = true ] && [ "$OSINT" = true ]; then
		start_func ${FUNCNAME[0]} "Github Repos analysis in process"

		if [ -s "${GITHUB_TOKENS}" ]; then
			GH_TOKEN=$(cat ${GITHUB_TOKENS} | head -1)
			echo $domain | unfurl format %r > .tmp/company_name.txt
			enumerepo -token-string ${GH_TOKEN} -usernames .tmp/company_name.txt -o .tmp/company_repos.txt 2>>"$LOGFILE" &>/dev/null
			[ -s .tmp/company_repos.txt ] && cat .tmp/company_repos.txt | jq -r '.[].repos[]|.url' > .tmp/company_repos_url.txt 2>>"$LOGFILE" &>/dev/null
			interlace -tL .tmp/company_repos_url.txt -threads ${INTERLACE_THREADS} -c "trufflehog git _target_ -j | jq -c > _output_/_cleantarget_" -o .tmp/github/ 2>>"$LOGFILE" &>/dev/null
			cat .tmp/github/* | jq -c | jq -r > osint/github_company_secrets.json 2>>"$LOGFILE" &>/dev/null
		else
			printf "\n${bred} Required file ${GITHUB_TOKENS} not exists or empty${reset}\n"
		fi
		end_func "Results are saved in $domain/osint/github_company_secrets.json" ${FUNCNAME[0]}
	else
		if [ "$GITHUB_REPOS" = false ] || [ "$OSINT" = false ]; then
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
			if [ "$METADATA" = false ] || [ "$OSINT" = false ]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi
}

function emails(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$EMAILS" = true ] && [ "$OSINT" = true ] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Searching emails/users/passwords leaks"
		emailfinder -d $domain 2>>"$LOGFILE" | anew -q .tmp/emailfinder.txt
		[ -s ".tmp/emailfinder.txt" ] && cat .tmp/emailfinder.txt | grep "@" | grep -iv "|_" | anew -q osint/emails.txt

		
		cd "$tools/Infoga" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		python3 infoga.py --domain $domain --source all --report $dir/.tmp/infoga.txt 2>>"$LOGFILE" &>/dev/null
		cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		[ -s ".tmp/infoga.txt" ] && cat .tmp/infoga.txt | cut -d " " -f3 | grep -v "-" | anew -q osint/emails.txt

# COMMENTED THEHARVESTER, H8MAIL AND PWNDB AS THEY'RE NOT WORKING AS EXPECTED
#		cd "$tools/theHarvester" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
#		python3 theHarvester.py -d $domain -b all -f $dir/.tmp/harvester.json 2>>"$LOGFILE" &>/dev/null
#		cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
#		if [ -s ".tmp/harvester.json" ]; then
#			cat .tmp/harvester.json | jq -r 'try .emails[]' 2>/dev/null | anew -q osint/emails.txt
#			cat .tmp/harvester.json | jq -r 'try .linkedin_people[]' 2>/dev/null | anew -q osint/employees.txt
#			cat .tmp/harvester.json | jq -r 'try .linkedin_links[]' 2>/dev/null | anew -q osint/linkedin.txt
#		fi
#		h8mail -t $domain -q domain --loose -c $tools/h8mail_config.ini -j .tmp/h8_results.json 2>>"$LOGFILE" &>/dev/null
#		[ -s ".tmp/h8_results.json" ] && cat .tmp/h8_results.json | jq -r '.targets[0] | .data[] | .[]' | awk '{print $12}' | anew -q osint/h8mail.txt
#
#		PWNDB_STATUS=$(timeout 30s curl -Is --socks5-hostname localhost:9050 http://pwndb2am4tzkvold.onion | grep HTTP | cut -d ' ' -f2)
#
#		if [ "$PWNDB_STATUS" = 200 ]; then
#			cd "$tools/pwndb" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
#			python3 pwndb.py --target "@${domain}" | sed '/^[-]/d' | anew -q $dir/osint/passwords.txt
#			cd "$dir" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
#			[ -s "osint/passwords.txt" ] && sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" osint/passwords.txt
#			[ -s "osint/passwords.txt" ] && sed -i '1,2d' osint/passwords.txt
#		else
#			text="${yellow}\n pwndb is currently down :(\n\n Check xjypo5vzgmo7jca6b322dnqbsdnp3amd24ybx26x5nxbusccjkm4pwid.onion${reset}\n"
#			printf "${text}" && printf "${text}" | $NOTIFY
#		fi

		end_func "Results are saved in $domain/osint/emails.txt" ${FUNCNAME[0]}
	else
		if [ "$EMAILS" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [ "$EMAILS" = false ] || [ "$OSINT" = false ]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi
}

function domain_info(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$DOMAIN_INFO" = true ] && [ "$OSINT" = true ] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Searching domain info (whois, registrant name/email domains)"
		whois -H $domain > osint/domain_info_general.txt
		if [ "$DEEP" = true ] || [ "$REVERSE_WHOIS" = true ]; then
			timeout -k $AMASS_INTEL_TIMEOUT amass intel -d ${domain} -whois -timeout $AMASS_INTEL_TIMEOUT -o osint/domain_info_reverse_whois.txt 2>>"$LOGFILE" &>/dev/null
		fi
		end_func "Results are saved in $domain/osint/domain_info_[general/name/email/ip].txt" ${FUNCNAME[0]}
	else
		if [ "$DOMAIN_INFO" = false ] || [ "$OSINT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [ "$DOMAIN_INFO" = false ] || [ "$OSINT" = false ]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi
}

function ip_info(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$IP_INFO" = true ] && [ "$OSINT" = true ] && [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Searching ip info"
		if [ -n "$WHOISXML_API" ]; then
			curl "https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ip=${domain}" 2>/dev/null | jq -r '.result[].name' 2>>"$LOGFILE" | sed -e "s/$/ ${domain}/" | anew -q osint/ip_${domain}_relations.txt
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
			if [ "$IP_INFO" = false ] || [ "$OSINT" = false ]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
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

	if ( [ ! -f "$called_fn_dir/.sub_active" ] || [ ! -f "$called_fn_dir/.sub_brute" ] || [ ! -f "$called_fn_dir/.sub_permut" ] || [ ! -f "$called_fn_dir/.sub_recursive_brute" ] )  || [ "$DIFF" = true ] ; then
		resolvers_update
	fi

	[ -s "${inScope_file}" ] && cat ${inScope_file} | anew -q subdomains/subdomains.txt

	if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && [ "$SUBDOMAINS_GENERAL" = true ]; then
		sub_passive
		sub_crt
		sub_active
		sub_noerror
		sub_brute
		sub_permut
		sub_regex_permut
		sub_gpt
		sub_recursive_passive
		sub_recursive_brute
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
		[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file subdomains/subdomains.txt
		NUMOFLINES_subs=$(cat subdomains/subdomains.txt 2>>"$LOGFILE" | anew .tmp/subdomains_old.txt | sed '/^$/d' | wc -l)
	fi
	if [ -s "webs/webs.txt" ]; then
		[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file webs/webs.txt
		NUMOFLINES_probed=$(cat webs/webs.txt 2>>"$LOGFILE" | anew .tmp/probed_old.txt | sed '/^$/d' | wc -l)
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
			[[ $RUNAMASS == true ]] && timeout -k $AMASS_ENUM_TIMEOUT amass enum -passive -d $domain -config $AMASS_CONFIG -timeout $AMASS_ENUM_TIMEOUT -json .tmp/amass_json.json 2>>"$LOGFILE" &>/dev/null
			[ -s ".tmp/amass_json.json" ] && cat .tmp/amass_json.json | jq -r '.name' | anew -q .tmp/amass_psub.txt
			[[ $RUNSUBFINDER == true ]] && subfinder -all -d $domain -silent -o .tmp/subfinder_psub.txt 2>>"$LOGFILE" &>/dev/null
		else
			echo $domain > .tmp/amass_temp_axiom.txt
			[[ $RUNAMASS == true ]] && axiom-scan .tmp/amass_temp_axiom.txt -m amass -passive -o .tmp/amass_psub.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			[[ $RUNSUBFINDER == true ]] && axiom-scan .tmp/amass_temp_axiom.txt -m subfinder -all -silent -o .tmp/subfinder_psub.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi
		if [ -s "${GITHUB_TOKENS}" ]; then
			if [ "$DEEP" = true ]; then
				github-subdomains -d $domain -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" &>/dev/null
			else
				github-subdomains -d $domain -k -q -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" &>/dev/null
			fi
		fi
		if [ -s "${GITLAB_TOKENS}" ]; then
			gitlab-subdomains -d $domain -t $GITLAB_TOKENS -o .tmp/gitlab_subdomains_psub.txt 2>>"$LOGFILE" &>/dev/null
		fi
		if [ "$INSCOPE" = true ]; then
			check_inscope .tmp/amass_psub.txt 2>>"$LOGFILE" &>/dev/null
			check_inscope .tmp/subfinder_psub.txt 2>>"$LOGFILE" &>/dev/null
			check_inscope .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" &>/dev/null
			check_inscope .tmp/gitlab_subdomains_psub.txt 2>>"$LOGFILE" &>/dev/null
		fi
		NUMOFLINES=$(find .tmp -type f -iname "*_psub.txt" -exec cat {} + | sed "s/*.//" | anew .tmp/passive_subs.txt | sed '/^$/d' | wc -l)
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
		python3 $tools/ctfr/ctfr.py -d $domain -o .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" &>/dev/null
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" &>/dev/null
		NUMOFLINES=$(cat .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" | sed 's/\*.//g' | anew .tmp/crtsh_subs.txt | sed '/^$/d' | wc -l)
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
		find .tmp -type f -iname "*_subs.txt" -exec cat {} + | anew -q .tmp/subs_no_resolved.txt
		[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/subs_no_resolved.txt
		if [ ! "$AXIOM" = true ]; then
			resolvers_update_quick_local
			[ -s ".tmp/subs_no_resolved.txt" ] && puredns resolve .tmp/subs_no_resolved.txt -w .tmp/subdomains_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/subs_no_resolved.txt" ] && axiom-scan .tmp/subs_no_resolved.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subdomains_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi
		echo $domain | dnsx -retry 3 -silent -r $resolvers_trusted 2>>"$LOGFILE" | anew -q .tmp/subdomains_tmp.txt
		if [ "$DEEP" = true ]; then
			cat .tmp/subdomains_tmp.txt | tlsx -san -cn -silent -ro -c $TLSX_THREADS -p $TLS_PORTS | anew -q .tmp/subdomains_tmp.txt
		else
			cat .tmp/subdomains_tmp.txt | tlsx -san -cn -silent -ro -c $TLSX_THREADS | anew -q .tmp/subdomains_tmp.txt
		fi
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/subdomains_tmp.txt 2>>"$LOGFILE" &>/dev/null
		NUMOFLINES=$(cat .tmp/subdomains_tmp.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} subs DNS resolved from passive" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function sub_noerror(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBNOERROR" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Checking NOERROR DNS response"
		if [[ $(echo "${RANDOM}thistotallynotexist${RANDOM}.$domain" | dnsx -r $resolvers -rcode noerror,nxdomain -retry 3 -silent | cut -d' ' -f2) == "[NXDOMAIN]" ]]; then 
			resolvers_update_quick_local
			if [ "$DEEP" = true ]; then
				dnsx -d $domain -r $resolvers -silent -rcode noerror -w $subs_wordlist_big | cut -d' ' -f1 | anew -q .tmp/subs_noerror.txt 2>>"$LOGFILE" &>/dev/null
			else
				dnsx -d $domain -r $resolvers -silent -rcode noerror -w $subs_wordlist | cut -d' ' -f1 | anew -q .tmp/subs_noerror.txt 2>>"$LOGFILE" &>/dev/null
			fi
			[[ "$INSCOPE" = true ]] && check_inscope .tmp/subs_noerror.txt 2>>"$LOGFILE" &>/dev/null
			NUMOFLINES=$(cat .tmp/subs_noerror.txt 2>>"$LOGFILE" | sed "s/*.//" | grep ".$domain$" | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
			end_subfunc "${NUMOFLINES} new subs (DNS noerror)" ${FUNCNAME[0]}
		else 
			printf "\n${yellow} Detected DNSSEC black lies, skipping this technique ${reset}\n" 
		fi
	else
		if [ "$SUBBRUTE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_dns(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : DNS Subdomain Enumeration and PTR search"
		if [ ! "$AXIOM" = true ]; then
			[ -s "subdomains/subdomains.txt" ] && cat subdomains/subdomains.txt | dnsx -r $resolvers_trusted -a -aaaa -cname -ns -ptr -mx -soa -silent -retry 3 -json -o subdomains/subdomains_dnsregs.json 2>>"$LOGFILE" &>/dev/null
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[], try .aaaa[], try .cname[], try .ns[], try .ptr[], try .mx[], try .soa[]' 2>/dev/null | grep ".$domain$" | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[]' | sort -u | dnsx -retry 3 -silent -ptr -r $resolvers_trusted -resp-only 2>/dev/null | grep ".$domain$" | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try "\(.host) - \(.a[])"' 2>/dev/null | sort -u -k2 | anew -q subdomains/subdomains_ips.txt
			resolvers_update_quick_local
			[ -s ".tmp/subdomains_dns.txt" ] && puredns resolve .tmp/subdomains_dns.txt -w .tmp/subdomains_dns_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			[ -s "subdomains/subdomains.txt" ] && axiom-scan subdomains/subdomains.txt -m dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -json -o subdomains/subdomains_dnsregs.json $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[]' | sort -u | anew -q .tmp/subdomains_dns_a_records.txt
			[ -s ".tmp/subdomains_dns_a_records.txt" ] && axiom-scan .tmp/subdomains_dns_a_records.txt -m dnsx -retry 3 -ptr -resp-only -o .tmp/subdomains_dns_ptr_reverse.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null 
			[ -s ".tmp/subdomains_dns_ptr_reverse.txt" ] && cat .tmp/subdomains_dns_ptr_reverse.txt | grep ".$domain$" | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[], try .aaaa[], try .cname[], try .ns[], try .ptr[], try .mx[], try .soa[]' 2>/dev/null | grep ".$domain$" | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try "\(.host) - \(.a[])"' 2>/dev/null | sort -u -k2 | anew -q subdomains/subdomains_ips.txt
			resolvers_update_quick_axiom
			[ -s ".tmp/subdomains_dns.txt" ] && axiom-scan .tmp/subdomains_dns.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subdomains_dns_resolved.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" &>/dev/null
		NUMOFLINES=$(cat .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (dns resolution)" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function sub_brute(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBBRUTE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Bruteforce Subdomain Enumeration"
		if [ ! "$AXIOM" = true ]; then
			resolvers_update_quick_local
			if [ "$DEEP" = true ]; then
				puredns bruteforce $subs_wordlist_big $domain -w .tmp/subs_brute.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
			else
				puredns bruteforce $subs_wordlist $domain -w .tmp/subs_brute.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
			fi
			[ -s ".tmp/subs_brute.txt" ] && puredns resolve .tmp/subs_brute.txt -w .tmp/subs_brute_valid.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			resolvers_update_quick_axiom
			if [ "$DEEP" = true ]; then
				axiom-scan $subs_wordlist_big -m puredns-single $domain -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subs_brute.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			else
				axiom-scan $subs_wordlist -m puredns-single $domain -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subs_brute.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			fi
			[ -s ".tmp/subs_brute.txt" ] && axiom-scan .tmp/subs_brute.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subs_brute_valid.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/subs_brute_valid.txt 2>>"$LOGFILE" &>/dev/null
		NUMOFLINES=$(cat .tmp/subs_brute_valid.txt 2>>"$LOGFILE" | sed "s/*.//" | grep ".$domain$" | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
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
			if [[ $(cat subdomains/subdomains.txt | wc -l) -le $DEEP_LIMIT ]] || [ "$DEEP" = true ] ; then
				if [ ! "$AXIOM" = true ]; then
					resolvers_update_quick_local
					cat subdomains/subdomains.txt | httpx -follow-host-redirects -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info1.txt 2>>"$LOGFILE" &>/dev/null
					[ -s ".tmp/web_full_info1.txt" ] && cat .tmp/web_full_info1.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | sed "s/*.//" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
					[ -s ".tmp/probed_tmp_scrap.txt" ] && cat .tmp/probed_tmp_scrap.txt | httpx -tls-grab -tls-probe -csp-probe -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info2.txt 2>>"$LOGFILE" &>/dev/null
					[ -s ".tmp/web_full_info2.txt" ] && cat .tmp/web_full_info2.txt | jq -r 'try ."tls-grab"."dns_names"[],try .csp.domains[],try .url' 2>/dev/null | grep "$domain" | sed "s/*.//" | sort -u | httpx -silent | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt

					if [ "$DEEP" = true ]; then
						[ -s ".tmp/probed_tmp_scrap.txt" ] && katana -silent -list .tmp/probed_tmp_scrap.txt -jc -kf all -c $KATANA_THREADS -d 3 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" &>/dev/null
					else
						[ -s ".tmp/probed_tmp_scrap.txt" ] && katana -silent -list .tmp/probed_tmp_scrap.txt -jc -kf all -c $KATANA_THREADS -d 2 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" &>/dev/null
					fi
				else
					resolvers_update_quick_axiom
					axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info1.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
					[ -s ".tmp/web_full_info1.txt" ] && cat .tmp/web_full_info1.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | sed "s/*.//" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
					[ -s ".tmp/probed_tmp_scrap.txt" ] && axiom-scan .tmp/probed_tmp_scrap.txt -m httpx -tls-grab -tls-probe -csp-probe -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info2.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
					[ -s ".tmp/web_full_info2.txt" ] && cat .tmp/web_full_info2.txt | jq -r 'try ."tls-grab"."dns_names"[],try .csp.domains[],try .url' 2>/dev/null | grep "$domain" | sed "s/*.//" | sort -u | httpx -silent | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
					if [ "$DEEP" = true ]; then
						[ -s ".tmp/probed_tmp_scrap.txt" ] && axiom-scan .tmp/probed_tmp_scrap.txt -m katana -jc -kf all -d 3 -fs rdn -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
					else
						[ -s ".tmp/probed_tmp_scrap.txt" ] && axiom-scan .tmp/probed_tmp_scrap.txt -m katana -jc -kf all -d 2 -fs rdn -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
					fi
				fi
				sed -i '/^.\{2048\}./d' .tmp/katana.txt
				[ -s ".tmp/katana.txt" ] && cat .tmp/katana.txt | unfurl -u domains 2>>"$LOGFILE" | grep ".$domain$" | anew -q .tmp/scrap_subs.txt
				[ -s ".tmp/scrap_subs.txt" ] && puredns resolve .tmp/scrap_subs.txt -w .tmp/scrap_subs_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
				if [ "$INSCOPE" = true ]; then
					check_inscope .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" &>/dev/null
				fi
				NUMOFLINES=$(cat .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | anew subdomains/subdomains.txt | tee .tmp/diff_scrap.txt | sed '/^$/d' | wc -l)
				[ -s ".tmp/diff_scrap.txt" ] && cat .tmp/diff_scrap.txt | httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info3.txt 2>>"$LOGFILE" &>/dev/null
				[ -s ".tmp/web_full_info3.txt" ] && cat .tmp/web_full_info3.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | sed "s/*.//" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
				cat .tmp/web_full_info1.txt .tmp/web_full_info2.txt .tmp/web_full_info3.txt 2>>"$LOGFILE" | jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"$LOGFILE" > .tmp/web_full_info.txt
				end_subfunc "${NUMOFLINES} new subs (code scraping)" ${FUNCNAME[0]}
			else
				end_subfunc "Skipping Subdomains Web Scraping: Too Many Subdomains" ${FUNCNAME[0]}
			fi
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
			cat .tmp/probed_tmp_scrap.txt | analyticsrelationships -ch >> .tmp/analytics_subs_tmp.txt 2>>"$LOGFILE" &>/dev/null
			[ -s ".tmp/analytics_subs_tmp.txt" ] && cat .tmp/analytics_subs_tmp.txt | grep "\.$domain$\|^$domain$" | sed "s/|__ //" | anew -q .tmp/analytics_subs_clean.txt
			if [ ! "$AXIOM" = true ]; then
				resolvers_update_quick_local
				[ -s ".tmp/analytics_subs_clean.txt" ] && puredns resolve .tmp/analytics_subs_clean.txt -w .tmp/analytics_subs_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
			else
				resolvers_update_quick_axiom
				[ -s ".tmp/analytics_subs_clean.txt" ] && axiom-scan .tmp/analytics_subs_clean.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/analytics_subs_resolved.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			fi
		fi
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/analytics_subs_resolved.txt 2>>"$LOGFILE" &>/dev/null
		NUMOFLINES=$(cat .tmp/analytics_subs_resolved.txt 2>>"$LOGFILE" | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
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
			if [ "$PERMUTATIONS_OPTION" = "gotator" ] ; then
				[ -s "subdomains/subdomains.txt" ] && gotator -sub subdomains/subdomains.txt -perm $tools/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1.txt
			else
				[ -s "subdomains/subdomains.txt" ] && ripgen -d subdomains/subdomains.txt -w $tools/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1.txt
			fi
		elif [ "$(cat .tmp/subs_no_resolved.txt | wc -l)" -le $DEEP_LIMIT2 ]; then
			if [ "$PERMUTATIONS_OPTION" = "gotator" ] ; then
				[ -s ".tmp/subs_no_resolved.txt" ] && gotator -sub .tmp/subs_no_resolved.txt -perm $tools/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1.txt
			else
				[ -s ".tmp/subs_no_resolved.txt" ] && ripgen -d .tmp/subs_no_resolved.txt -w $tools/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1.txt
			fi
		else
			end_subfunc "Skipping Permutations: Too Many Subdomains" ${FUNCNAME[0]}
			return 1
		fi
		if [ ! "$AXIOM" = true ]; then
			resolvers_update_quick_local
			[ -s ".tmp/gotator1.txt" ] && puredns resolve .tmp/gotator1.txt -w .tmp/permute1.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/gotator1.txt" ] && axiom-scan .tmp/gotator1.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute1.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi
		
		if [ "$PERMUTATIONS_OPTION" = "gotator" ] ; then
			[ -s ".tmp/permute1.txt" ] && gotator -sub .tmp/permute1.txt -perm $tools/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator2.txt
		else
			[ -s ".tmp/permute1.txt" ] && ripgen -d .tmp/permute1.txt -w $tools/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator2.txt
		fi

		if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/gotator2.txt" ] && puredns resolve .tmp/gotator2.txt -w .tmp/permute2.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			[ -s ".tmp/gotator2.txt" ] && axiom-scan .tmp/gotator2.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute2.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi
		cat .tmp/permute1.txt .tmp/permute2.txt 2>>"$LOGFILE" | anew -q .tmp/permute_subs.txt

		if [ -s ".tmp/permute_subs.txt" ]; then
			[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/permute_subs.txt
			[[ "$INSCOPE" = true ]] && check_inscope .tmp/permute_subs.txt 2>>"$LOGFILE" &>/dev/null
			NUMOFLINES=$(cat .tmp/permute_subs.txt 2>>"$LOGFILE" | grep ".$domain$" | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
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

function sub_regex_permut(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBREGEXPERMUTE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Permutations by regex analysis"
		cd "$tools/regulator" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		python3 main.py -t $domain -f ${dir}/subdomains/subdomains.txt -o ${dir}/.tmp/${domain}.brute
		cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

		if [ ! "$AXIOM" = true ]; then
			resolvers_update_quick_local
			[ -s ".tmp/${domain}.brute" ] && puredns resolve .tmp/${domain}.brute -w .tmp/regulator.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/${domain}.brute" ] && axiom-scan .tmp/${domain}.brute -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/regulator.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi
		
		if [ -s ".tmp/regulator.txt" ]; then
			[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/regulator.txt
			[[ "$INSCOPE" = true ]] && check_inscope .tmp/regulator.txt 2>>"$LOGFILE" &>/dev/null
			NUMOFLINES=$(cat .tmp/regulator.txt 2>>"$LOGFILE" | grep ".$domain$" | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		else
			NUMOFLINES=0
		fi
		end_subfunc "${NUMOFLINES} new subs (permutations)" ${FUNCNAME[0]}
	else
		if [ "$SUBREGEXPERMUTE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_gpt(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBGPT" = true ] && [ -s "$SUBGPT_COOKIE" ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Permutations by BingGPT prediction"
		subgpt -i ${dir}/subdomains/subdomains.txt -c $SUBGPT_COOKIE --dont-resolve -o ${dir}/.tmp/gpt_subs.txt 2>>"$LOGFILE"
		if [ ! "$AXIOM" = true ]; then
			resolvers_update_quick_local
			[ -s "${dir}/.tmp/gpt_subs.txt" ] && puredns resolve ${dir}/.tmp/gpt_subs.txt -w .tmp/gpt_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			resolvers_update_quick_axiom
			[ -s "${dir}/.tmp/gpt_subs.txt" ] && axiom-scan ${dir}/.tmp/gpt_subs.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/gpt_resolved.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi
		
		if [ -s ".tmp/gpt_resolved.txt" ]; then
			[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/gpt_resolved.txt
			[[ "$INSCOPE" = true ]] && check_inscope .tmp/gpt_resolved.txt 2>>"$LOGFILE" &>/dev/null
			NUMOFLINES=$(cat .tmp/gpt_resolved.txt 2>>"$LOGFILE" | grep ".$domain$" | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		else
			NUMOFLINES=0
		fi
		end_subfunc "${NUMOFLINES} new subs (permutations)" ${FUNCNAME[0]}
	else
		if [ "$SUBGPT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [ ! -s "$SUBGPT_COOKIE" ]; then
			printf "\n${yellow} ${FUNCNAME[0]} SUBGPT_COOKIE not defined on config file (reconftw.cfg by default) ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_recursive_passive(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUB_RECURSIVE_PASSIVE" = true ] && [ -s "subdomains/subdomains.txt" ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Subdomains recursive search passive"
		# Passive recursive
		[ -s "subdomains/subdomains.txt" ] && dsieve -if subdomains/subdomains.txt -f 3 -top $DEEP_RECURSIVE_PASSIVE > .tmp/subdomains_recurs_top.txt
		if [ ! "$AXIOM" = true ]; then
			resolvers_update_quick_local
			[ -s ".tmp/subdomains_recurs_top.txt" ] && timeout -k $AMASS_ENUM_TIMEOUT amass enum -passive -df .tmp/subdomains_recurs_top.txt -nf subdomains/subdomains.txt -config $AMASS_CONFIG -timeout $AMASS_ENUM_TIMEOUT 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
			[ -s ".tmp/passive_recursive.txt" ] && puredns resolve .tmp/passive_recursive.txt -w .tmp/passive_recurs_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/subdomains_recurs_top.txt" ] && axiom-scan .tmp/subdomains_recurs_top.txt -m amass -passive -o .tmp/amass_prec.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			[ -s ".tmp/amass_prec.txt" ] &&  cat .tmp/amass_prec.txt | anew -q .tmp/passive_recursive.txt
			[ -s ".tmp/passive_recursive.txt" ] && axiom-scan .tmp/passive_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/passive_recurs_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" &>/dev/null
		NUMOFLINES=$(cat .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | sed '/^$/d' | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (recursive)" ${FUNCNAME[0]}
	else
		if [ "$SUB_RECURSIVE_PASSIVE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_recursive_brute(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUB_RECURSIVE_BRUTE" = true ] && [ -s "subdomains/subdomains.txt" ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Subdomains recursive search active"
		if [[ $(cat subdomains/subdomains.txt | wc -l) -le $DEEP_LIMIT ]] ; then
			[ ! -s ".tmp/subdomains_recurs_top.txt" ] && dsieve -if subdomains/subdomains.txt -f 3 -top $DEEP_RECURSIVE_PASSIVE > .tmp/subdomains_recurs_top.txt
			ripgen -d .tmp/subdomains_recurs_top.txt -w $subs_wordlist > .tmp/brute_recursive_wordlist.txt
			if [ ! "$AXIOM" = true ]; then
				resolvers_update_quick_local
				[ -s ".tmp/brute_recursive_wordlist.txt" ] && puredns resolve .tmp/brute_recursive_wordlist.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -w .tmp/brute_recursive_result.txt 2>>"$LOGFILE" &>/dev/null
			else
				resolvers_update_quick_axiom
				[ -s ".tmp/brute_recursive_wordlist.txt" ] && axiom-scan .tmp/brute_recursive_wordlist.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/brute_recursive_result.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			fi
			[ -s ".tmp/brute_recursive_result.txt" ] && cat .tmp/brute_recursive_result.txt | anew -q .tmp/brute_recursive.txt

			if [ "$PERMUTATIONS_OPTION" = "gotator" ] ; then
				[ -s ".tmp/brute_recursive.txt" ] && gotator -sub .tmp/brute_recursive.txt -perm $tools/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1_recursive.txt
			else
				[ -s ".tmp/brute_recursive.txt" ] && ripgen -d .tmp/brute_recursive.txt -w $tools/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1_recursive.txt
			fi
			
			if [ ! "$AXIOM" = true ]; then
				[ -s ".tmp/gotator1_recursive.txt" ] && puredns resolve .tmp/gotator1_recursive.txt -w .tmp/permute1_recursive.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
			else
				[ -s ".tmp/gotator1_recursive.txt" ] && axiom-scan .tmp/gotator1_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute1_recursive.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			fi

			if [ "$PERMUTATIONS_OPTION" = "gotator" ] ; then
				[ -s ".tmp/permute1_recursive.txt" ] && gotator -sub .tmp/permute1_recursive.txt -perm $tools/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator2_recursive.txt
			else
				[ -s ".tmp/permute1_recursive.txt" ] && ripgen -d .tmp/permute1_recursive.txt -w $tools/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator2_recursive.txt
			fi
			
			if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/gotator2_recursive.txt" ] && puredns resolve .tmp/gotator2_recursive.txt -w .tmp/permute2_recursive.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
			else
				[ -s ".tmp/gotator2_recursive.txt" ] && axiom-scan .tmp/gotator2_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute2_recursive.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			fi
			cat .tmp/permute1_recursive.txt .tmp/permute2_recursive.txt 2>>"$LOGFILE" | anew -q .tmp/permute_recursive.txt
		else
			end_subfunc "skipped in this mode or defined in reconftw.cfg" ${FUNCNAME[0]}
		fi
		if [ "$INSCOPE" = true ]; then
			check_inscope .tmp/permute_recursive.txt 2>>"$LOGFILE" &>/dev/null
			check_inscope .tmp/brute_recursive.txt 2>>"$LOGFILE" &>/dev/null
		fi

		# Last validation
		cat .tmp/permute_recursive.txt .tmp/brute_recursive.txt 2>>"$LOGFILE" | anew -q .tmp/brute_perm_recursive.txt
		if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/brute_recursive.txt" ] && puredns resolve .tmp/brute_perm_recursive.txt -w .tmp/brute_perm_recursive_final.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			[ -s ".tmp/brute_recursive.txt" ] && axiom-scan .tmp/brute_perm_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/brute_perm_recursive_final.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi

		NUMOFLINES=$(cat .tmp/brute_perm_recursive_final.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | sed '/^$/d' | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (recursive)" ${FUNCNAME[0]}
	else
		if [ "$SUB_RECURSIVE_BRUTE" = false ]; then
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
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ ! "$AXIOM" = true ]; then
			cat subdomains/subdomains.txt .tmp/webs_all.txt 2>/dev/null | nuclei -silent -nh -tags takeover -severity low,medium,high,critical -r $resolvers_trusted -retries 3 -rl $NUCLEI_RATELIMIT -o .tmp/tko.txt
		else
			cat subdomains/subdomains.txt .tmp/webs_all.txt 2>>"$LOGFILE" | sed '/^$/d' | anew -q .tmp/webs_subs.txt
			[ -s ".tmp/webs_subs.txt" ] && axiom-scan .tmp/webs_subs.txt -m nuclei -tags takeover -nh -severity low,medium,high,critical -retries 3 -rl $NUCLEI_RATELIMIT -o .tmp/tko.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi

		# DNS_TAKEOVER
		cat .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/scrap_subs.txt .tmp/analytics_subs_clean.txt .tmp/passive_recursive.txt 2>/dev/null | anew -q .tmp/subs_dns_tko.txt
		cat .tmp/subs_dns_tko.txt 2>/dev/null | dnstake -c $DNSTAKE_THREADS -s 2>>"$LOGFILE" | sed '/^$/d' | anew -q .tmp/tko.txt

		sed -i '/^$/d' .tmp/tko.txt

		NUMOFLINES=$(cat .tmp/tko.txt 2>>"$LOGFILE" | anew webs/takeover.txt | sed '/^$/d' | wc -l)
		if [ "$NUMOFLINES" -gt 0 ]; then
			notification "${NUMOFLINES} new possible takeovers found" info
		fi
		if [ "$BBRF_CONNECTION" = true ]; then
			[ -s "webs/takeover.txt" ] && cat webs/takeover.txt | grep -aEo 'https?://[^ ]+' | bbrf url add - -t subtko:true 2>>"$LOGFILE" &>/dev/null
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
		for ns in $(dig +short ns "$domain"); do dig axfr "$domain" @"$ns" >> subdomains/zonetransfer.txt; done
		if [ -s "subdomains/zonetransfer.txt" ]; then
			if ! grep -q "Transfer failed" subdomains/zonetransfer.txt ; then notification "Zone transfer found on ${domain}!" info; fi
		fi
		end_func "Results are saved in $domain/subdomains/zonetransfer.txt" ${FUNCNAME[0]}
	else
		if [ "$ZONETRANSFER" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [ "$ZONETRANSFER" = false ]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi
}

function s3buckets(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$S3BUCKETS" = true ] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "AWS S3 buckets search"
		# S3Scanner
		if [ ! "$AXIOM" = true ]; then
			[ -s "subdomains/subdomains.txt" ] && s3scanner scan -f subdomains/subdomains.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt
		else
			axiom-scan subdomains/subdomains.txt -m s3scanner -o .tmp/s3buckets_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			[ -s ".tmp/s3buckets_tmp.txt" ] && cat .tmp/s3buckets_tmp.txt .tmp/s3buckets_tmp2.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt && sed -i '/^$/d' .tmp/s3buckets.txt
		fi
		# Cloudenum
		keyword=${domain%%.*}
		python3 ~/Tools/cloud_enum/cloud_enum.py -k $keyword -qs -l .tmp/output_cloud.txt 2>>"$LOGFILE" &>/dev/null

		NUMOFLINES1=$(cat .tmp/output_cloud.txt 2>>"$LOGFILE" | sed '/^#/d' | sed '/^$/d' | anew subdomains/cloud_assets.txt | wc -l)
		if [ "$NUMOFLINES1" -gt 0 ]; then
			notification "${NUMOFLINES1} new cloud assets found" info
		fi
		NUMOFLINES2=$(cat .tmp/s3buckets.txt 2>>"$LOGFILE" | grep -aiv "not_exist" | grep -aiv "Warning:" | grep -aiv "invalid_name" | grep -aiv "^http" | awk 'NF' | anew subdomains/s3buckets.txt | sed '/^$/d' | wc -l)
		if [ "$NUMOFLINES2" -gt 0 ]; then
			notification "${NUMOFLINES2} new S3 buckets found" info
		fi

		if [ "$BBRF_CONNECTION" = true ]; then
			[ -s "subdomains/cloud_assets.txt" ] && cat subdomains/cloud_assets.txt | grep -aEo 'https?://[^ ]+' | sed 's/[ \t]*$//' | bbrf url add - -t cloud_assets:true 2>>"$LOGFILE" &>/dev/null
			[ -s "subdomains/s3buckets.txt" ] && cat subdomains/s3buckets.txt | cut -d'|' -f1 | sed 's/[ \t]*$//' | bbrf domain update - -t s3bucket:true 2>>"$LOGFILE" &>/dev/null
		fi

		end_func "Results are saved in subdomains/s3buckets.txt and subdomains/cloud_assets.txt" ${FUNCNAME[0]}
	else
		if [ "$S3BUCKETS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [ "$S3BUCKETS" = false ]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi
}

###############################################################################################################
########################################### WEB DETECTION #####################################################
###############################################################################################################

function webprobe_simple(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WEBPROBESIMPLE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Http probing $domain"
		if [ ! "$AXIOM" = true ]; then
			cat subdomains/subdomains.txt | httpx ${HTTPX_FLAGS} -no-color -json -random-agent -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -retries 2 -timeout $HTTPX_TIMEOUT -o .tmp/web_full_info_probe.txt 2>>"$LOGFILE" &>/dev/null
		else
			axiom-scan subdomains/subdomains.txt -m httpx ${HTTPX_FLAGS} -no-color -json -random-agent -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -retries 2 -timeout $HTTPX_TIMEOUT -o .tmp/web_full_info_probe.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
		fi
		cat .tmp/web_full_info.txt .tmp/web_full_info_probe.txt webs/web_full_info.txt 2>>"$LOGFILE" | jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"$LOGFILE" > webs/web_full_info.txt
		[ -s "webs/web_full_info.txt" ] && cat webs/web_full_info.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | sed "s/*.//" | anew -q .tmp/probed_tmp.txt
		[ -s "webs/web_full_info.txt" ] && cat webs/web_full_info.txt | jq -r 'try . |"\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' | anew -q webs/web_full_info_plain.txt
		[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/probed_tmp.txt
		NUMOFLINES=$(cat .tmp/probed_tmp.txt 2>>"$LOGFILE" | anew webs/webs.txt | sed '/^$/d' | wc -l)
		cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		end_subfunc "${NUMOFLINES} new websites resolved" ${FUNCNAME[0]}
		if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/webs.txt| wc -l) -le $DEEP_LIMIT2 ]]; then
			notification "Sending websites to proxy" info
			ffuf -mc all -w webs/webs.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" &>/dev/null
		fi
		if [ "$BBRF_CONNECTION" = true ]; then
			[ -s "webs/webs.txt" ] && cat webs/webs.txt | bbrf url add - 2>>"$LOGFILE" &>/dev/null
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
			if [ "$NMAP_WEBPROBE" = true ]; then
				if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
					$SUDO nmap -iL subdomains/subdomains.txt -p $UNCOMMON_PORTS_WEB -oG .tmp/uncommon_nmap.gnmap 2>>"$LOGFILE" &>/dev/null
					cat .tmp/uncommon_nmap.gnmap | egrep -v "^#|Status: Up" | cut -d' ' -f2,4- | grep "open" | sed -e 's/\/.*$//g' | sed -e "s/ /:/g" | sort -u | anew -q .tmp/nmap_uncommonweb.txt
				else
					if [ ! "$AXIOM" = true ]; then
						$SUDO unimap --fast-scan -f subdomains/subdomains.txt --ports $UNCOMMON_PORTS_WEB -q -k --url-output 2>>"$LOGFILE" | anew -q .tmp/nmap_uncommonweb.txt
					else
						axiom-scan subdomains/subdomains.txt -m unimap --fast-scan --ports $UNCOMMON_PORTS_WEB -q -k --url-output -o .tmp/nmap_uncommonweb.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
					fi
				fi
			fi
		fi
		if [ "$NMAP_WEBPROBE" = true ]; then
			if [ ! "$AXIOM" = true ]; then
				if [ -s ".tmp/nmap_uncommonweb.txt" ]; then
					cat .tmp/nmap_uncommonweb.txt | httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" &>/dev/null
				fi
			else
				if [ -s ".tmp/nmap_uncommonweb.txt" ]; then
					axiom-scan .tmp/nmap_uncommonweb.txt -m httpx -follow-host-redirects -H \"${HEADER}\" -status-code -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info_uncommon.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
				fi
			fi
		else
			if [ ! "$AXIOM" = true ]; then
				if [ -s "subdomains/subdomains.txt" ]; then
					cat subdomains/subdomains.txt | httpx -follow-host-redirects -random-agent -status-code -p $UNCOMMON_PORTS_WEB -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" &>/dev/null
				fi
			else
				if [ -s "subdomains/subdomains.txt" ]; then
					axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -H \"${HEADER}\" -status-code -p $UNCOMMON_PORTS_WEB -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info_uncommon.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
				fi
			fi
		fi
		[ -s ".tmp/web_full_info_uncommon.txt" ] && cat .tmp/web_full_info_uncommon.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | sed "s/*.//" | anew -q .tmp/probed_uncommon_ports_tmp.txt
		[ -s ".tmp/web_full_info_uncommon.txt" ] && cat .tmp/web_full_info_uncommon.txt | jq -r 'try . |"\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' | anew -q webs/web_full_info_uncommon_plain.txt
		if [ -s ".tmp/web_full_info_uncommon.txt" ]; then
			if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then 
				cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | anew -q webs/web_full_info_uncommon.txt
			else
				cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | grep "$domain" | anew -q webs/web_full_info_uncommon.txt
			fi
		fi
		NUMOFLINES=$(cat .tmp/probed_uncommon_ports_tmp.txt 2>>"$LOGFILE" | anew webs/webs_uncommon_ports.txt | sed '/^$/d' | wc -l)
		notification "Uncommon web ports: ${NUMOFLINES} new websites" good
		[ -s "webs/webs_uncommon_ports.txt" ] && cat webs/webs_uncommon_ports.txt
		cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		rm -rf "unimap_logs" 2>>"$LOGFILE"
		end_func "Results are saved in $domain/webs/webs_uncommon_ports.txt" ${FUNCNAME[0]}
		if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/webs_uncommon_ports.txt| wc -l) -le $DEEP_LIMIT2 ]]; then
			notification "Sending websites with uncommon ports to proxy" info
			ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" &>/dev/null
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
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/webs_all.txt" ] && gowitness file -f .tmp/webs_all.txt -t $GOWITNESS_THREADS --disable-logging 2>>"$LOGFILE"
		else
			axiom-scan .tmp/webs_all.txt -m gowitness -t $GOWITNESS_THREADS --disable-logging -o screenshots $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
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

function virtualhosts(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$VIRTUALHOSTS" = true ]; then
		start_func ${FUNCNAME[0]} "Virtual Hosts dicovery"
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ -s ".tmp/webs_all.txt" ]; then
			mkdir -p $dir/virtualhosts $dir/.tmp/virtualhosts
			interlace -tL .tmp/webs_all.txt -threads ${INTERLACE_THREADS} -c "ffuf -ac -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -H \"Host: FUZZ._cleantarget_\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u  _target_ -of json -o _output_/_cleantarget_.json" -o $dir/.tmp/virtualhosts 2>>"$LOGFILE" &>/dev/null
			for sub in $(cat .tmp/webs_all.txt); do
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				[ -s "$dir/.tmp/virtualhosts/${sub_out}.json" ] && cat $dir/.tmp/virtualhosts/${sub_out}.json | jq -r 'try .results[] | "\(.status) \(.length) \(.url)"' | sort | anew -q $dir/virtualhosts/${sub_out}.txt
			done
			find $dir/virtualhosts/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | anew -q $dir/virtualhosts/virtualhosts_full.txt
			end_func "Results are saved in $domain/virtualhosts/*subdomain*.txt" ${FUNCNAME[0]}
		else
			end_func "No $domain/web/webs.txts file found, fuzzing skipped " ${FUNCNAME[0]}
		fi
	else
		if [ "$VIRTUALHOSTS" = false ]; then
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
			cat favicontest.json | jq -r 'try .found_ips' 2>>"$LOGFILE" | grep -v "not-found" > favicontest.txt
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
			if [ "$FAVICON" = false ]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi
}

function portscan(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$PORTSCANNER" = true ]; then
		start_func ${FUNCNAME[0]} "Port scan"
		if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try . | "\(.host) \(.a[0])"' | anew -q .tmp/subs_ips.txt
			[ -s ".tmp/subs_ips.txt" ] && awk '{ print $2 " " $1}' .tmp/subs_ips.txt | sort -k2 -n | anew -q hosts/subs_ips_vhosts.txt
			[ -s "hosts/subs_ips_vhosts.txt" ] && cat hosts/subs_ips_vhosts.txt | cut -d ' ' -f1 | grep -aEiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q hosts/ips.txt
		else echo $domain | grep -aEiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q hosts/ips.txt
		fi
		[ ! -s "hosts/cdn_providers.txt" ] && cat hosts/ips.txt 2>/dev/null | cdncheck -silent -resp -nc 2>/dev/null > hosts/cdn_providers.txt
		[ -s "hosts/ips.txt" ] && comm -23 <(cat hosts/ips.txt | sort -u) <(cat hosts/cdn_providers.txt | cut -d'[' -f1 | sed 's/[[:space:]]*$//' | sort -u) | grep -aEiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u | anew -q .tmp/ips_nocdn.txt
		printf "${bblue}\n Resolved IP addresses (No CDN) ${reset}\n\n";
		[ -s ".tmp/ips_nocdn.txt" ] && cat .tmp/ips_nocdn.txt | sort
		printf "${bblue}\n Scanning ports... ${reset}\n\n";
		if [ "$PORTSCAN_PASSIVE" = true ] && [ ! -f "hosts/portscan_passive.txt" ] && [ -s ".tmp/ips_nocdn.txt" ] ; then
			smap -iL .tmp/ips_nocdn.txt > hosts/portscan_passive.txt
		fi
		if [ "$PORTSCAN_ACTIVE" = true ]; then
			if [ ! "$AXIOM" = true ]; then
				[ -s ".tmp/ips_nocdn.txt" ] && $SUDO nmap --top-ports 200 -sV -n --max-retries 2 -Pn --open -iL .tmp/ips_nocdn.txt -oA hosts/portscan_active 2>>"$LOGFILE" &>/dev/null
			else
				[ -s ".tmp/ips_nocdn.txt" ] && axiom-scan .tmp/ips_nocdn.txt -m nmapx --top-ports 200 -sV -n -Pn --open --max-retries 2 -o hosts/portscan_active.gnmap $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
				[ -s "hosts/portscan_active.gnmap" ] && cat hosts/portscan_active.gnmap | egrep -v "^#|Status: Up" | cut -d' ' -f2,4- | sed -n -e 's/Ignored.*//p' | awk '{print "Host: " $1 " Ports: " NF-1; $1=""; for(i=2; i<=NF; i++) { a=a" "$i; }; split(a,s,","); for(e in s) { split(s[e],v,"/"); printf "%-8s %s/%-7s %s\n" , v[2], v[3], v[1], v[5]}; a="" }' > hosts/portscan_active.txt 2>>"$LOGFILE" &>/dev/null
			fi
		fi
		if [ "$BBRF_CONNECTION" = true ]; then
			[ -s "hosts/subs_ips_vhosts.txt" ] && cat hosts/subs_ips_vhosts.txt | awk '{print $2,$1}' | sed -e 's/\s\+/:/g' | bbrf domain add -
			[ -s "hosts/subs_ips_vhosts.txt" ] && cat hosts/subs_ips_vhosts.txt | sed -e 's/\s\+/:/g' | bbrf ip add -
			[ -s "hosts/portscan_active.xml" ] && $tools/ultimate-nmap-parser/ultimate-nmap-parser.sh hosts/portscan_active.gnmap --csv 2>>"$LOGFILE" &>/dev/null
			[ -s "parsed_nmap.csv" ] && mv parsed_nmap.csv .tmp/parsed_nmap.csv && cat .tmp/parsed_nmap.csv | tail -n +2 | cut -d',' -f1,2,5,6 | sed -e 's/,/:/g' | sed 's/\:$//' | bbrf service add - && rm -f parsed_nmap.csv
		fi
		[ -s "hosts/portscan_active.xml" ] && searchsploit --nmap hosts/portscan_active.xml 2>/dev/null > hosts/searchsploit.txt
		end_func "Results are saved in hosts/portscan_[passive|active].txt" ${FUNCNAME[0]}
	else
		if [ "$PORTSCANNER" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function cdnprovider(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CDN_IP" = true ]; then
		start_func ${FUNCNAME[0]} "CDN provider check"
		[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try . | .a[]' | grep -aEiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u > .tmp/ips_cdn.txt
		[ -s ".tmp/ips_cdn.txt" ] && cat .tmp/ips_cdn.txt | cdncheck -silent -resp -nc | anew -q $dir/hosts/cdn_providers.txt
		end_func "Results are saved in hosts/cdn_providers.txt" ${FUNCNAME[0]}
	else
		if [ "$CDN_IP" = false ]; then
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
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ -s ".tmp/webs_all.txt" ]; then
			if [ ! "$AXIOM" = true ]; then
				wafw00f -i .tmp/webs_all.txt -o .tmp/wafs.txt 2>>"$LOGFILE" &>/dev/null
			else
				axiom-scan .tmp/webs_all.txt -m wafw00f -o .tmp/wafs.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			fi
			if [ -s ".tmp/wafs.txt" ]; then
				cat .tmp/wafs.txt | sed -e 's/^[ \t]*//' -e 's/ \+ /\t/g' -e '/(None)/d' | tr -s "\t" ";" > webs/webs_wafs.txt
				NUMOFLINES=$(cat webs/webs_wafs.txt 2>>"$LOGFILE" | sed '/^$/d' | wc -l)
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
		if [ "$WAF_DETECTION" = false ]; then
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
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		[ ! -s ".tmp/webs_subs.txt" ] && cat subdomains/subdomains.txt .tmp/webs_all.txt 2>>"$LOGFILE" | anew -q .tmp/webs_subs.txt
		if [ ! "$AXIOM" = true ]; then
			set -f                      # avoid globbing (expansion of *).
			array=(${NUCLEI_SEVERITY//,/ })
			for i in "${!array[@]}"
			do
				crit=${array[i]}
				printf "${yellow}\n Running : Nuclei $crit ${reset}\n\n"
				cat .tmp/webs_subs.txt 2>/dev/null | nuclei $NUCLEI_FLAGS -severity $crit -nh -r $resolvers_trusted -rl $NUCLEI_RATELIMIT -o nuclei_output/${crit}.txt
			done
			printf "\n\n"
		else
			if [ -s ".tmp/webs_subs.txt" ]; then
				set -f                      # avoid globbing (expansion of *).
				array=(${NUCLEI_SEVERITY//,/ })
				for i in "${!array[@]}"
				do
					crit=${array[i]}
					printf "${yellow}\n Running : Nuclei $crit ${reset}\n\n"
					axiom-scan .tmp/webs_subs.txt -m nuclei -severity ${crit} -nh -rl $NUCLEI_RATELIMIT -o nuclei_output/${crit}.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
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
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ -s ".tmp/webs_all.txt" ]; then
			mkdir -p $dir/fuzzing $dir/.tmp/fuzzing
			if [ ! "$AXIOM" = true ]; then
				interlace -tL .tmp/webs_all.txt -threads ${INTERLACE_THREADS} -c "ffuf ${FFUF_FLAGS} -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u _target_/FUZZ -of json -o _output_/_cleantarget_.json" -o $dir/.tmp/fuzzing 2>>"$LOGFILE" &>/dev/null
				for sub in $(cat .tmp/webs_all.txt); do
					sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
					[ -s "$dir/.tmp/fuzzing/${sub_out}.json" ] && cat $dir/.tmp/fuzzing/${sub_out}.json | jq -r 'try .results[] | "\(.status) \(.length) \(.url)"' | sort | anew -q $dir/fuzzing/${sub_out}.txt
				done
				find $dir/fuzzing/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | anew -q $dir/fuzzing/fuzzing_full.txt
			else
				axiom-exec 'wget -q -O - https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt > /home/op/lists/fuzz_wordlist.txt' &>/dev/null
				axiom-scan .tmp/webs_all.txt -m ffuf -w /home/op/lists/fuzz_wordlist.txt -H "${HEADER}" $FFUF_FLAGS -s -maxtime $FFUF_MAXTIME -o $dir/fuzzing/ffuf-content.csv $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
				grep -v "FUZZ,url,redirectlocation" $dir/fuzzing/ffuf-content.csv 2>>"$LOGFILE" | awk -F "," '{print $2" "$5" "$6}' | sort > $dir/fuzzing/ffuf-content.tmp
				for sub in $(cat .tmp/webs_all.txt); do
					sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
					grep "$sub" $dir/fuzzing/ffuf-content.tmp | awk '{print $2" "$3" "$1}' | sort -k1 | anew -q $dir/fuzzing/${sub_out}.txt
				done
				find $dir/fuzzing/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | anew -q $dir/fuzzing/fuzzing_full.txt
				rm -f $dir/fuzzing/ffuf-content.tmp $dir/fuzzing/ffuf-content.csv
			fi
			sort --numeric-sort --reverse -t ' ' -k1 -k2 -o $dir/fuzzing/fuzzing_full.txt{,}
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
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ -s ".tmp/webs_all.txt" ]; then
			tr '\n' ',' < .tmp/webs_all.txt > .tmp/cms.txt
			timeout -k $CMSSCAN_TIMEOUT python3 $tools/CMSeeK/cmseek.py -l .tmp/cms.txt --batch -r 2>>"$LOGFILE" &>/dev/null
			exit_status=$?
			if [[ $exit_status -eq 125 ]]; then
				echo "TIMEOUT cmseek.py - investigate manually for $dir" >> "$LOGFILE"
				end_func "TIMEOUT cmseek.py - investigate manually for $dir" ${FUNCNAME[0]}
				return
			elif [[ $exit_status -ne 0 ]]; then
				echo "ERROR cmseek.py - investigate manually for $dir" >> "$LOGFILE"
				end_func "ERROR cmseek.py - investigate manually for $dir" ${FUNCNAME[0]}
				return
			fi	# otherwise Assume we have a successfully exited cmseek
			for sub in $(cat .tmp/webs_all.txt); do
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				cms_id=$(cat $tools/CMSeeK/Result/${sub_out}/cms.json 2>/dev/null | jq -r 'try .cms_id')
				if [ -z "$cms_id" ]; then
					rm -rf $tools/CMSeeK/Result/${sub_out}
				else
					mv -f $tools/CMSeeK/Result/${sub_out} $dir/cms/ 2>>"$LOGFILE"
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
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ -s ".tmp/webs_all.txt" ]; then
			if [ ! "$AXIOM" = true ]; then
				if [ "$URL_CHECK_PASSIVE" = true ]; then
					if [ "$DEEP" = true ]; then
						cat .tmp/webs_all.txt | unfurl -u domains > .tmp/waymore_input.txt
						python3 $tools/waymore/waymore.py -i .tmp/waymore_input.txt -mode U -f -oU .tmp/url_extract_tmp.txt 2>>"$LOGFILE" &>/dev/null
					else
						cat .tmp/webs_all.txt | gau --threads $GAU_THREADS | anew -q .tmp/url_extract_tmp.txt
					fi
					if [ -s "${GITHUB_TOKENS}" ]; then
						github-endpoints -q -k -d $domain -t ${GITHUB_TOKENS} -o .tmp/github-endpoints.txt 2>>"$LOGFILE" &>/dev/null
						[ -s ".tmp/github-endpoints.txt" ] && cat .tmp/github-endpoints.txt | anew -q .tmp/url_extract_tmp.txt
					fi
				fi
				diff_webs=$(diff <(sort -u .tmp/probed_tmp.txt 2>>"$LOGFILE") <(sort -u .tmp/webs_all.txt 2>>"$LOGFILE") | wc -l)
				if [ $diff_webs != "0" ] || [ ! -s ".tmp/katana.txt" ]; then
					if [ "$URL_CHECK_ACTIVE" = true ]; then
						if [ "$DEEP" = true ]; then
							katana -silent -list .tmp/webs_all.txt -jc -kf all -c $KATANA_THREADS -d 3 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" &>/dev/null
						else
							katana -silent -list .tmp/webs_all.txt -jc -kf all -c $KATANA_THREADS -d 2 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" &>/dev/null
						fi
					fi
				fi
			else
				if [ "$URL_CHECK_PASSIVE" = true ]; then
					if [ "$DEEP" = true ]; then
						cat .tmp/webs_all.txt | unfurl -u domains > .tmp/waymore_input.txt
						axiom-scan .tmp/waymore_input.txt -m waymore -o .tmp/url_extract_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
					else
						axiom-scan .tmp/webs_all.txt -m gau -o .tmp/url_extract_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
						fi
					if [ -s "${GITHUB_TOKENS}" ]; then
						github-endpoints -q -k -d $domain -t ${GITHUB_TOKENS} -o .tmp/github-endpoints.txt 2>>"$LOGFILE" &>/dev/null
						[ -s ".tmp/github-endpoints.txt" ] && cat .tmp/github-endpoints.txt | anew -q .tmp/url_extract_tmp.txt
					fi
				fi
				diff_webs=$(diff <(sort -u .tmp/probed_tmp.txt) <(sort -u .tmp/webs_all.txt) | wc -l)
				if [ $diff_webs != "0" ] || [ ! -s ".tmp/katana.txt" ]; then
					if [ "$URL_CHECK_ACTIVE" = true ]; then
						if [ "$DEEP" = true ]; then
							axiom-scan .tmp/webs_all.txt -m katana -jc -kf all -d 3 -fs rdn -fs rdn -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
						else
							axiom-scan .tmp/webs_all.txt -m katana -jc -kf all -d 2 -fs rdn -fs rdn -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
						fi	
					fi
				fi
			fi
			[ -s ".tmp/katana.txt" ] && sed -i '/^.\{2048\}./d' .tmp/katana.txt
			[ -s ".tmp/katana.txt" ] && cat .tmp/katana.txt | anew -q .tmp/url_extract_tmp.txt
			[ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | grep "${domain}" | grep -aEi "\.(js)" | anew -q .tmp/url_extract_js.txt
			if [ "$DEEP" = true ]; then
				[ -s ".tmp/url_extract_js.txt" ] && interlace -tL .tmp/url_extract_js.txt -threads 10 -c "python3 $tools/JSA/jsa.py -f target | anew -q .tmp/url_extract_tmp.txt" &>/dev/null
			fi
			[ -s ".tmp/url_extract_tmp.txt" ] &&  cat .tmp/url_extract_tmp.txt | grep "${domain}" | grep "=" | qsreplace -a 2>>"$LOGFILE" | grep -aEiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | anew -q .tmp/url_extract_tmp2.txt
			[ -s ".tmp/url_extract_tmp2.txt" ] && cat .tmp/url_extract_tmp2.txt | python3 $tools/urless/urless.py | anew -q .tmp/url_extract_uddup.txt 2>>"$LOGFILE" &>/dev/null
			NUMOFLINES=$(cat .tmp/url_extract_uddup.txt 2>>"$LOGFILE" | anew webs/url_extract.txt | sed '/^$/d' | wc -l)
			notification "${NUMOFLINES} new urls with params" info
			end_func "Results are saved in $domain/webs/url_extract.txt" ${FUNCNAME[0]}
			if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/url_extract.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
				notification "Sending urls to proxy" info
				ffuf -mc all -w webs/url_extract.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" &>/dev/null
			fi
		fi
	else
		if [ "$URL_CHECK" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
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
			[ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | grep -aEiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | unfurl -u format %s://%d%p 2>>"$LOGFILE" | anew -q gf/endpoints.txt
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
				NUMOFLINES=$(cat .tmp/url_extract_tmp.txt | grep -aEi "\.(${t})($|\/|\?)" | sort -u | sed '/^$/d' | wc -l)
				if [[ ${NUMOFLINES} -gt 0 ]]; then
					echo -e "\n############################\n + ${t} + \n############################\n" >> webs/urls_by_ext.txt
					cat .tmp/url_extract_tmp.txt | grep -aEi "\.(${t})($|\/|\?)" >> webs/urls_by_ext.txt
					if [ "$BBRF_CONNECTION" = true ]; then
						cat .tmp/url_extract_tmp.txt | grep -aEi "\.(${t})($|\/|\?)" | bbrf url add - 2>>"$LOGFILE" &>/dev/null
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
		if [ -s ".tmp/url_extract_js.txt" ]; then
			printf "${yellow} Running : Fetching Urls 1/5${reset}\n"
			if [ ! "$AXIOM" = true ]; then
				cat .tmp/url_extract_js.txt | subjs -ua "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -c 40 | grep "$domain" | anew -q .tmp/subjslinks.txt
			else
				axiom-scan .tmp/url_extract_js.txt -m subjs -o .tmp/subjslinks.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			fi
			[ -s ".tmp/subjslinks.txt" ] && cat .tmp/subjslinks.txt | egrep -iv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)" | anew -q js/nojs_links.txt
			[ -s ".tmp/subjslinks.txt" ] && cat .tmp/subjslinks.txt | grep -iE "\.js($|\?)" | anew -q .tmp/url_extract_js.txt
			cat .tmp/url_extract_js.txt | python3 $tools/urless/urless.py | anew -q js/url_extract_js.txt 2>>"$LOGFILE" &>/dev/null
			printf "${yellow} Running : Resolving JS Urls 2/5${reset}\n"
			if [ ! "$AXIOM" = true ]; then
				[ -s "js/url_extract_js.txt" ] && cat js/url_extract_js.txt | httpx -follow-redirects -random-agent -silent -timeout $HTTPX_TIMEOUT -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -status-code -content-type -retries 2 -no-color | grep "[200]" | grep "javascript" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
			else
				[ -s "js/url_extract_js.txt" ] && axiom-scan js/url_extract_js.txt -m httpx -follow-host-redirects -H \"${HEADER}\" -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -content-type -retries 2 -no-color -o .tmp/js_livelinks.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
				[ -s ".tmp/js_livelinks.txt" ] && cat .tmp/js_livelinks.txt | anew .tmp/web_full_info.txt | grep "[200]" | grep "javascript" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
			fi
			printf "${yellow} Running : Gathering endpoints 3/5${reset}\n"
			[ -s "js/js_livelinks.txt" ] && python3 $tools/xnLinkFinder/xnLinkFinder.py -i js/js_livelinks.txt -sf subdomains/subdomains.txt -d $XNLINKFINDER_DEPTH -o .tmp/js_endpoints.txt 2>>"$LOGFILE" &>/dev/null
			[ -s "parameters.txt" ] && rm -f parameters.txt 2>>"$LOGFILE" &>/dev/null
			if [ -s ".tmp/js_endpoints.txt" ]; then
				sed -i '/^\//!d' .tmp/js_endpoints.txt
				cat .tmp/js_endpoints.txt | anew -q js/js_endpoints.txt
			fi
			printf "${yellow} Running : Gathering secrets 4/5${reset}\n"
			if [ ! "$AXIOM" = true ]; then
				[ -s "js/js_livelinks.txt" ] && cat js/js_livelinks.txt | nuclei -silent -t ~/nuclei-templates/ $NUCLEI_FLAGS_JS -nh -r $resolvers_trusted -retries 3 -rl $NUCLEI_RATELIMIT -o js/js_secrets.txt 2>>"$LOGFILE" &>/dev/null
			else
				[ -s "js/js_livelinks.txt" ] && axiom-scan js/js_livelinks.txt -m nuclei $NUCLEI_FLAGS_JS -retries 3 -nh -rl $NUCLEI_RATELIMIT -o js/js_secrets.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
			fi
			printf "${yellow} Running : Building wordlist 5/5${reset}\n"
			[ -s "js/js_livelinks.txt" ] && interlace -tL js/js_livelinks.txt -threads ${INTERLACE_THREADS}  -c "python3 $tools/getjswords.py '_target_' | anew -q webs/dict_words.txt" 2>>"$LOGFILE" &>/dev/null
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
			ffuf -mc all -w webs/all_paths.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" &>/dev/null
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
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ -s ".tmp/webs_all.txt" ]; then
			cat .tmp/webs_all.txt | roboxtractor -m 1 -wb 2>/dev/null | anew -q webs/robots_wordlist.txt
		fi
		end_func "Results are saved in $domain/webs/robots_wordlist.txt" ${FUNCNAME[0]}
	else
		if [ "$ROBOTSWORDLIST" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
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
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ ! "$AXIOM" = true ]; then
			if [ ! -s ".tmp/katana.txt" ]; then
				if [ "$DEEP" = true ]; then
					[ -s ".tmp/webs_all.txt" ] && katana -silent -list .tmp/webs_all.txt -jc -kf all -c $KATANA_THREADS -d 3 -o .tmp/katana.txt 2>>"$LOGFILE" &>/dev/null
				else
					[ -s ".tmp/webs_all.txt" ] && katana -silent -list .tmp/webs_all.txt -jc -kf all -c $KATANA_THREADS -d 2 -o .tmp/katana.txt 2>>"$LOGFILE" &>/dev/null
				fi
			fi
			[ -s ".tmp/katana.txt" ] && sed -i '/^.\{2048\}./d' .tmp/katana.txt
		else
			if [ ! -s ".tmp/katana.txt" ]; then
				if [ "$DEEP" = true ]; then
					[ -s ".tmp/webs_all.txt" ] && axiom-scan .tmp/webs_all.txt -m katana -jc -kf all -d 3 -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
				else
					[ -s ".tmp/webs_all.txt" ] && axiom-scan .tmp/webs_all.txt -m katana -jc -kf all -d 2 -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
				fi
				[ -s ".tmp/katana.txt" ] && sed -i '/^.\{2048\}./d' .tmp/katana.txt
			fi
		fi
		[ -s ".tmp/katana.txt" ] && cat .tmp/katana.txt | sort -u | httpx -follow-redirects -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -no-color | grep "\[4" | cut -d ' ' -f1 | anew -q .tmp/brokenLinks_total.txt
		NUMOFLINES=$(cat .tmp/brokenLinks_total.txt 2>>"$LOGFILE" | anew vulns/brokenLinks.txt | sed '/^$/d' | wc -l)
		notification "${NUMOFLINES} new broken links found" info
		end_func "Results are saved in vulns/brokenLinks.txt" ${FUNCNAME[0]}
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
		[ -s "gf/xss.txt" ] && cat gf/xss.txt | qsreplace FUZZ | sed '/FUZZ/!d' | Gxss -c 100 -p Xss | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/xss_reflected.txt
		if [ ! "$AXIOM" = true ]; then		
			if [ "$DEEP" = true ]; then
				if [ -n "$XSS_SERVER" ]; then
					[ -s ".tmp/xss_reflected.txt" ] && cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --only-poc r --ignore-return 302,404,403 --skip-bav -b ${XSS_SERVER} -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
				else
					printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
					[ -s ".tmp/xss_reflected.txt" ] && cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --only-poc r --ignore-return 302,404,403 --skip-bav -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
				fi
			else
				if [[ $(cat .tmp/xss_reflected.txt | wc -l) -le $DEEP_LIMIT ]]; then
					if [ -n "$XSS_SERVER" ]; then
						cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --skip-bav --skip-mining-dom --skip-mining-dict --only-poc r --ignore-return 302,404,403 -b ${XSS_SERVER} -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
					else
						printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
						cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --skip-bav --skip-mining-dom --skip-mining-dict --only-poc r --ignore-return 302,404,403 -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
					fi
				else
					printf "${bred} Skipping XSS: Too many URLs to test, try with --deep flag${reset}\n"
				fi
			fi
		else
			if [ "$DEEP" = true ]; then
				if [ -n "$XSS_SERVER" ]; then
					[ -s ".tmp/xss_reflected.txt" ] && axiom-scan .tmp/xss_reflected.txt -m dalfox --skip-bav -b ${XSS_SERVER} -w $DALFOX_THREADS -o vulns/xss.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
				else
					printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
					[ -s ".tmp/xss_reflected.txt" ] && axiom-scan .tmp/xss_reflected.txt -m dalfox --skip-bav -w $DALFOX_THREADS -o vulns/xss.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
				fi
			else
				if [[ $(cat .tmp/xss_reflected.txt | wc -l) -le $DEEP_LIMIT ]]; then
					if [ -n "$XSS_SERVER" ]; then
						axiom-scan .tmp/xss_reflected.txt -m dalfox --skip-bav --skip-grepping --skip-mining-all --skip-mining-dict -b ${XSS_SERVER} -w $DALFOX_THREADS -o vulns/xss.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
					else
						printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
						axiom-scan .tmp/xss_reflected.txt -m dalfox --skip-bav --skip-grepping --skip-mining-all --skip-mining-dict -w $DALFOX_THREADS -o vulns/xss.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" &>/dev/null
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
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		[ -s ".tmp/webs_all.txt" ] && python3 $tools/Corsy/corsy.py -i .tmp/webs_all.txt -o vulns/cors.txt 2>>"$LOGFILE" &>/dev/null
		end_func "Results are saved in vulns/cors.txt" ${FUNCNAME[0]}
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
			cat gf/redirect.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_redirect.txt
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
			COLLAB_SERVER_FIX="FFUFHASH.$(cat .tmp/ssrf_callback.txt | tail -n1 | cut -c 16-)"
			COLLAB_SERVER_URL="http://$COLLAB_SERVER_FIX"
			INTERACT=true
		else
			COLLAB_SERVER_FIX="FFUFHASH.$(echo ${COLLAB_SERVER} | sed -r "s/https?:\/\///")"
			INTERACT=false
		fi
		if [ "$DEEP" = true ] || [[ $(cat gf/ssrf.txt | wc -l) -le $DEEP_LIMIT ]]; then
			cat gf/ssrf.txt | qsreplace ${COLLAB_SERVER_FIX} | anew -q .tmp/tmp_ssrf.txt
			cat gf/ssrf.txt | qsreplace ${COLLAB_SERVER_URL} | anew -q .tmp/tmp_ssrf.txt
			ffuf -v -H "${HEADER}" -t $FFUF_THREADS -rate $FFUF_RATELIMIT -w .tmp/tmp_ssrf.txt -u FUZZ 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssrf_requested_url.txt
			ffuf -v -w .tmp/tmp_ssrf.txt:W1,$tools/headers_inject.txt:W2 -H "${HEADER}" -H "W2: ${COLLAB_SERVER_FIX}" -t $FFUF_THREADS -rate $FFUF_RATELIMIT -u W1 2>/dev/null | anew -q vulns/ssrf_requested_headers.txt
			ffuf -v -w .tmp/tmp_ssrf.txt:W1,$tools/headers_inject.txt:W2 -H "${HEADER}" -H "W2: ${COLLAB_SERVER_URL}" -t $FFUF_THREADS -rate $FFUF_RATELIMIT -u W1 2>/dev/null | anew -q vulns/ssrf_requested_headers.txt
			sleep 5
			[ -s ".tmp/ssrf_callback.txt" ] && cat .tmp/ssrf_callback.txt | tail -n+11 | anew -q vulns/ssrf_callback.txt && NUMOFLINES=$(cat .tmp/ssrf_callback.txt | tail -n+12 | sed '/^$/d' | wc -l)
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
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ "$DEEP" = true ] || [[ $(cat .tmp/webs_all.txt | wc -l) -le $DEEP_LIMIT ]]; then
			crlfuzz -l .tmp/webs_all.txt -o vulns/crlf.txt 2>>"$LOGFILE" &>/dev/null
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
			cat gf/lfi.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_lfi.txt
			if [ "$DEEP" = true ] || [[ $(cat .tmp/tmp_lfi.txt | wc -l) -le $DEEP_LIMIT ]]; then
				interlace -tL .tmp/tmp_lfi.txt -threads ${INTERLACE_THREADS} -c "ffuf -v -r -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w ${lfi_wordlist} -u \"_target_\" -mr \"root:\" " 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/lfi.txt
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
			cat gf/ssti.txt | qsreplace FUZZ | sed '/FUZZ/!d'  | anew -q .tmp/tmp_ssti.txt
			if [ "$DEEP" = true ] || [[ $(cat .tmp/tmp_ssti.txt | wc -l) -le $DEEP_LIMIT ]]; then
				interlace -tL .tmp/tmp_ssti.txt -threads ${INTERLACE_THREADS} -c "ffuf -v -r -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w ${ssti_wordlist} -u \"_target_\" -mr \"ssti49\" " 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssti.txt
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

		cat gf/sqli.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_sqli.txt
		if [ "$DEEP" = true ] || [[ $(cat .tmp/tmp_sqli.txt | wc -l) -le $DEEP_LIMIT ]]; then
			if [ "$SQLMAP" = true ];then
				python3 $tools/sqlmap/sqlmap.py -m .tmp/tmp_sqli.txt -b -o --smart --batch --disable-coloring --random-agent --output-dir=vulns/sqlmap 2>>"$LOGFILE" &>/dev/null
			fi
			if [ "$GHAURI" = true ];then
				interlace -tL .tmp/tmp_sqli.txt -threads ${INTERLACE_THREADS} -c "ghauri -u _target_ --batch -H \"${HEADER}\" --force-ssl >> vulns/ghauri_log.txt" 2>>"$LOGFILE" &>/dev/null
			fi
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
		$tools/testssl.sh/testssl.sh --quiet --color 0 -U -iL hosts/ips.txt 2>>"$LOGFILE" > vulns/testssl.txt
		end_func "Results are saved in vulns/testssl.txt" ${FUNCNAME[0]}
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
		python3 brutespray.py --file $dir/hosts/portscan_active.gnmap --threads $BRUTESPRAY_THREADS --hosts $BRUTESPRAY_CONCURRENCE -o $dir/vulns/brutespray 2>>"$LOGFILE" &>/dev/null
		cd "$dir" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		end_func "Results are saved in vulns/brutespray folder" ${FUNCNAME[0]}
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
		[ -s "gf/rce.txt" ] && cat gf/rce.txt | qsreplace FUZZ | sed '/FUZZ/!d'  | anew -q .tmp/tmp_rce.txt
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

function 4xxbypass(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$BYPASSER4XX" = true ]; then
		if [[ $(cat fuzzing/fuzzing_full.txt 2>/dev/null | grep -E '^4' | grep -Ev '^404' | cut -d ' ' -f3 | wc -l) -le 1000 ]] || [ "$DEEP" = true ]; then
			start_func "403 bypass"
			cat $dir/fuzzing/fuzzing_full.txt 2>/dev/null | grep -E '^4' | grep -Ev '^404' | cut -d ' ' -f3 > $dir/.tmp/403test.txt
			cd "$tools/byp4xx" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			byp4xx -threads $BYP4XX_THREADS $dir/.tmp/403test.txt > $dir/.tmp/byp4xx.txt
			cd "$dir" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			[ -s ".tmp/byp4xx.txt" ] && cat .tmp/byp4xx.txt | anew -q vulns/byp4xx.txt
			end_func "Results are saved in vulns/byp4xx.txt" ${FUNCNAME[0]}
		else
			notification "Too many urls to bypass, skipping" warn
		fi
	else
		if [ "$BYPASSER4XX" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
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

function smuggling(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SMUGGLING" = true ] ; then
		start_func ${FUNCNAME[0]} "HTTP Request Smuggling checks"
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ "$DEEP" = true ] || [[ $(cat .tmp/webs_all.txt | wc -l) -le $DEEP_LIMIT ]]; then
			cd "$tools/smuggler" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			cat $dir/.tmp/webs_all.txt | python3 smuggler.py -q --no-color 2>/dev/null | anew -q $dir/.tmp/smuggling.txt
			cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			[ -s ".tmp/smuggling.txt" ] && cat .tmp/smuggling.txt | anew -q vulns/smuggling.txt
			end_func "Results are saved in vulns/smuggling.txt" ${FUNCNAME[0]}
		else
			end_func "Skipping Prototype Pollution: Too many webs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [ "$SMUGGLING" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function webcache(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WEBCACHE" = true ] ; then
		start_func ${FUNCNAME[0]} "Web Cache Poisoning checks"
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ "$DEEP" = true ] || [[ $(cat .tmp/webs_all.txt | wc -l) -le $DEEP_LIMIT ]]; then
			cd "$tools/Web-Cache-Vulnerability-Scanner" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			Web-Cache-Vulnerability-Scanner -u file:$dir/.tmp/webs_all.txt -v 0 2>/dev/null | anew -q $dir/.tmp/webcache.txt
			cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			[ -s ".tmp/webcache.txt" ] && cat .tmp/webcache.txt | anew -q vulns/webcache.txt
			end_func "Results are saved in vulns/webcache.txt" ${FUNCNAME[0]}
		else
			end_func "Web Cache Poisoning: Too many webs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [ "$WEBCACHE" = false ]; then
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
	if [ -s "$1" ]; then
		cat $1 | while read outscoped
		do
			if grep -q "^[*]" <<< $outscoped
			then
				outscoped="${outscoped:1}"
				sed -i /"$outscoped$"/d $2
			else
				sed -i /$outscoped/d $2
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
	(cd $dir && zip -r "$zip_name" .)

	echo "Sending zip file "${dir}/${zip_name}""
	if [ -s "${dir}/$zip_name" ]; then
		sendToNotify "$dir/$zip_name"
		rm -f "${dir}/$zip_name"
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
	[[ "$(dirname $dir)" != "$dir_output" ]] && rm -rf "$dir"
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

function transfer { 
	if [ $# -eq 0 ]; then 
		echo "No arguments specified.\nUsage:\n transfer <file|directory>\n ... | transfer <file_name>">&2
		return 1
	fi
	if tty -s; then 
		file="$1"
		file_name=$(basename "$file")
		if [ ! -e "$file" ]; then 
			echo "$file: No such file or directory">&2
			return 1
		fi
		if [ -d "$file" ]; then
			file_name="$file_name.zip"
			(cd "$file"&&zip -r -q - .) | curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
		else 
			cat "$file" | curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
		fi
	else
		file_name=$1
		curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
	fi
}

function sendToNotify {
	if [[ -z "$1" ]]; then
		printf "\n${yellow} no file provided to send ${reset}\n"
	else
		if [[ -z "$NOTIFY_CONFIG" ]]; then
			NOTIFY_CONFIG=~/.config/notify/provider-config.yaml
		fi
		if [ -n "$(find "${1}" -prune -size +8000000c)" ]; then
    		printf '%s is larger than 8MB, sending over transfer.sh\n' "${1}"
			transfer "${1}" | notify
			return 0
		fi
		if grep -q '^ telegram\|^telegram\|^    telegram' $NOTIFY_CONFIG ; then
			notification "Sending ${domain} data over Telegram" info
			telegram_chat_id=$(cat ${NOTIFY_CONFIG} | grep '^    telegram_chat_id\|^telegram_chat_id\|^    telegram_chat_id' | xargs | cut -d' ' -f2)
			telegram_key=$(cat ${NOTIFY_CONFIG} | grep '^    telegram_api_key\|^telegram_api_key\|^    telegram_apikey' | xargs | cut -d' ' -f2 )
			curl -F document=@${1} "https://api.telegram.org/bot${telegram_key}/sendDocument?chat_id=${telegram_chat_id}" 2>>"$LOGFILE" &>/dev/null
		fi
		if grep -q '^ discord\|^discord\|^    discord' $NOTIFY_CONFIG ; then
			notification "Sending ${domain} data over Discord" info
			discord_url=$(cat ${NOTIFY_CONFIG} | grep '^ discord_webhook_url\|^discord_webhook_url\|^    discord_webhook_url' | xargs | cut -d' ' -f2)
			curl -v -i -H "Accept: application/json" -H "Content-Type: multipart/form-data" -X POST -F file1=@${1} $discord_url 2>>"$LOGFILE" &>/dev/null
		fi
		if [[ -n "$slack_channel" ]] && [[ -n "$slack_auth" ]]; then
			notification "Sending ${domain} data over Slack" info
			curl -F file=@${1} -F "initial_comment=reconftw zip file" -F channels=${slack_channel} -H "Authorization: Bearer ${slack_auth}" https://slack.com/api/files.upload 2>>"$LOGFILE" &>/dev/null
		fi
	fi
}

function start_func(){
	printf "${bgreen}#######################################################################"
	notification "${2}" info
	echo "[ $(date +"%F %T") ] Start function : ${1} " >> "${LOGFILE}"
	start=$(date +%s)
}

function end_func(){
	touch $called_fn_dir/.${2}
	end=$(date +%s)
	getElapsedTime $start $end
	notification "${2} Finished in ${runtime}" info
	echo "[ $(date +"%F %T") ] End function : ${2} " >> "${LOGFILE}"
	printf "${bblue} ${1} ${reset}\n"
	printf "${bgreen}#######################################################################${reset}\n"
}

function start_subfunc(){
	notification "${2}" warn
	echo "[ $(date +"%F %T") ] Start subfunction : ${1} " >> "${LOGFILE}"
	start_sub=$(date +%s)
}

function end_subfunc(){
	touch $called_fn_dir/.${2}
	end_sub=$(date +%s)
	getElapsedTime $start_sub $end_sub
	notification "${1} in ${runtime}" good
	echo "[ $(date +"%F %T") ] End subfunction : ${1} " >> "${LOGFILE}"
}

function check_inscope(){
	cat $1 | inscope > $1_tmp && cp $1_tmp $1 && rm -f $1_tmp
}

function resolvers_update(){
	if [ "$generate_resolvers" = true ]; then
		if [ ! "$AXIOM" = true ]; then	
			if [ ! -s "$resolvers" ] || [[ $(find "$resolvers" -mtime +1 -print) ]] ; then
				notification "Resolvers seem older than 1 day\n Generating custom resolvers..." warn
				eval rm -f $resolvers 2>>"$LOGFILE"
				dnsvalidator -tL https://public-dns.info/nameservers.txt -threads $DNSVALIDATOR_THREADS -o $resolvers 2>>"$LOGFILE" &>/dev/null
				dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads $DNSVALIDATOR_THREADS -o tmp_resolvers 2>>"$LOGFILE" &>/dev/null
				[ -s "tmp_resolvers" ] && cat tmp_resolvers | anew -q $resolvers
				[ -s "tmp_resolvers" ] && rm -f tmp_resolvers 2>>"$LOGFILE" &>/dev/null
				[ ! -s "$resolvers" ] && wget -q -O - ${resolvers_url} > $resolvers
				[ ! -s "$resolvers_trusted" ] && wget -q -O - ${resolvers_trusted_url} > $resolvers_trusted
				notification "Updated\n" good
	  		fi
		else
			notification "Checking resolvers lists...\n Accurate resolvers are the key to great results\n This may take around 10 minutes if it's not updated" warn
			# shellcheck disable=SC2016
			axiom-exec 'if [ $(find "/home/op/lists/resolvers.txt" -mtime +1 -print) ] || [ $(cat /home/op/lists/resolvers.txt | wc -l) -le 40 ] ; then dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o /home/op/lists/resolvers.txt ; fi' &>/dev/null
			axiom-exec "wget -q -O - ${resolvers_url} > /home/op/lists/resolvers.txt" 2>>"$LOGFILE" &>/dev/null
			axiom-exec "wget -q -O - ${resolvers_trusted_url} > /home/op/lists/resolvers_trusted.txt" 2>>"$LOGFILE" &>/dev/null
			notification "Updated\n" good
		fi
		generate_resolvers=false
	else
	
		if  [ ! -s "$resolvers" ] || [[ $(find "$resolvers" -mtime +1 -print) ]] ; then
			notification "Resolvers seem older than 1 day\n Downloading new resolvers..." warn
			wget -q -O - ${resolvers_url} > $resolvers
			wget -q -O - ${resolvers_trusted_url} > $resolvers_trusted
			notification "Resolvers updated\n" good
		fi
	fi
}

function resolvers_update_quick_local(){
	if [ "$update_resolvers" = true ]; then
		wget -q -O - ${resolvers_url} > $resolvers
		wget -q -O - ${resolvers_trusted_url} > $resolvers_trusted
	fi
}

function resolvers_update_quick_axiom(){
	axiom-exec "wget -q -O - ${resolvers_url} > /home/op/lists/resolvers.txt" 2>>"$LOGFILE" &>/dev/null
	axiom-exec "wget -q -O - ${resolvers_trusted_url} > /home/op/lists/resolvers_trusted.txt" 2>>"$LOGFILE" &>/dev/null
}

function ipcidr_target(){
	IP_CIDR_REGEX='(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?))(\/([8-9]|[1-2][0-9]|3[0-2]))([^0-9.]|$)|(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$)'
	if [[ $1 =~ ^$IP_CIDR_REGEX ]]; then
		echo $1 | mapcidr -silent | anew -q target_reconftw_ipcidr.txt
		if [ -s "./target_reconftw_ipcidr.txt" ]; then 
			[ "$REVERSE_IP" = true ] && cat ./target_reconftw_ipcidr.txt | hakip2host | cut -d' ' -f 3 | unfurl -u domains 2>/dev/null | sed 's/\.$//' | anew -q ./target_reconftw_ipcidr.txt
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
	echo "Start ${NOW} ${NOWT}" > "${LOGFILE}"

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

	find $dir -type f -empty -print | grep -v '.called_fn' | grep -v '.log' | grep -v '.tmp' | xargs rm -f 2>>"$LOGFILE" &>/dev/null
	find $dir -type d -empty -print -delete 2>>"$LOGFILE" &>/dev/null

	echo "End $(date +"%F") $(date +"%T")" >> "${LOGFILE}"

	if [ ! "$PRESERVE" = true ]; then
		find $dir -type f -empty | grep -v "called_fn" | xargs rm -f 2>>"$LOGFILE" &>/dev/null
		find $dir -type d -empty | grep -v "called_fn" | xargs rm -rf 2>>"$LOGFILE" &>/dev/null
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
	github_repos
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
	cdnprovider
	PORTSCAN_ACTIVE=false
	portscan
	
	if [ "$AXIOM" = true ]; then
		axiom_shutdown
	fi

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
	github_repos
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
		smuggling
		webcache
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
	echo "Start ${NOW} ${NOWT}" > "${LOGFILE}"

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
		echo "Start ${NOW} ${NOWT}" > "${LOGFILE}"
		domain_info
		ip_info
		emails
		google_dorks
		github_dorks
		github_repos
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
	github_repos
	metadata
	zonetransfer
	favicon

	if [ "$AXIOM" = true ]; then
		axiom_lauch
		axiom_selected
	fi

	subdomains_full
	webprobe_full
	subtakeover
	remove_big_files
	s3buckets
	screenshot
#	virtualhosts
	cdnprovider
	portscan
	waf_checks
	nuclei_check
	fuzz
	urlchecks
	jschecks

	if [ "$AXIOM" = true ]; then
		axiom_shutdown
	fi

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
	echo "Start ${NOW} ${NOWT}" > "${LOGFILE}"

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
		echo "Start ${NOW} ${NOWT}" > "${LOGFILE}"
		loopstart=$(date +%s)

		domain_info
		ip_info
		emails
		google_dorks
		github_dorks
		github_repos
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
		webprobe_full
		subtakeover
		remove_big_files
		screenshot
#		virtualhosts
		cdnprovider
		portscan
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
	NUMOFLINES_users_total=$(find . -type f -name 'users.txt' -exec cat {} + | anew osint/users.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_pwndb_total=$(find . -type f -name 'passwords.txt' -exec cat {} + | anew osint/passwords.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_software_total=$(find . -type f -name 'software.txt' -exec cat {} + | anew osint/software.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_authors_total=$(find . -type f -name 'authors.txt' -exec cat {} + | anew osint/authors.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_subs_total=$(find . -type f -name 'subdomains.txt' -exec cat {} + | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_subtko_total=$(find . -type f -name 'takeover.txt' -exec cat {} + | anew webs/takeover.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_webs_total=$(find . -type f -name 'webs.txt' -exec cat {} + | anew webs/webs.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_webs_total=$(find . -type f -name 'webs_uncommon_ports.txt' -exec cat {} + | anew webs/webs_uncommon_ports.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_ips_total=$(find . -type f -name 'ips.txt' -exec cat {} + | anew hosts/ips.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_cloudsprov_total=$(find . -type f -name 'cdn_providers.txt' -exec cat {} + | anew hosts/cdn_providers.txt | sed '/^$/d' | wc -l)
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
	webprobe_full
	subtakeover
	remove_big_files
	screenshot
#	virtualhosts
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
#	virtualhosts
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
	printf "   -l list.txt       Targets list (One on each line)\n"
	printf "   -x oos.txt        Exclude subdomains list (Out Of Scope)\n"
	printf "   -i in.txt         Include subdomains list\n"
	printf " \n"
	printf " ${bblue}MODE OPTIONS${reset}\n"
	printf "   -r, --recon       Recon - Perform full recon process (without attacks)\n"
	printf "   -s, --subdomains  Subdomains - Perform Subdomain Enumeration, Web probing and check for sub-tko\n"
	printf "   -p, --passive     Passive - Perform only passive steps\n"
	printf "   -a, --all         All - Perform all checks and active exploitations\n"
	printf "   -w, --web         Web - Perform web checks from list of subdomains\n"
	printf "   -n, --osint       OSINT - Check for public intel data\n"
	printf "   -c                Launches specific function against target\n"
	printf "   -h                Help - Show help section\n"
	printf " \n"
	printf " ${bblue}GENERAL OPTIONS${reset}\n"
	printf "   --deep            Deep scan (Enable some slow options for deeper scan)\n"
	printf "   -f config_file    Alternate reconftw.cfg file\n"
	printf "   -o output/path    Define output folder\n"
	printf "   -v, --vps         Axiom distributed VPS \n"
	printf "   -q                Rate limit in requests per second \n"
	printf " \n"
	printf " ${bblue}USAGE EXAMPLES${reset}\n"
	printf " ${byellow}Perform full recon (without attacks):${reset}\n"
	printf " ./reconftw.sh -d example.com -r\n"
	printf " \n"
	printf " ${byellow}Perform subdomain enumeration on multiple targets:${reset}\n"
	printf " ./reconftw.sh -l targets.txt -s\n"
	printf " \n"
	printf " ${byellow}Perform Web based scanning on a subdomains list:${reset}\n"
	printf " ./reconftw.sh -d example.com -l targets.txt -w\n"
	printf " \n"
	printf " ${byellow}Multidomain recon:${reset}\n"
	printf " ./reconftw.sh -m company -l domainlist.txt -r\n"
	printf " \n"
	printf " ${byellow}Perform full recon (with active attacks) along Out-Of-Scope subdomains list:${reset}\n"
	printf " ./reconftw.sh -d example.com -x out.txt -a\n"
	printf " \n"
	printf " ${byellow}Perform full recon and store output to specified directory:${reset}\n"
	printf " ./reconftw.sh -d example.com -r -o custom/path\n"
	printf " \n"
	printf " ${byellow}Start the web server:${reset}\n"
	printf " ./reconftw.sh --web-server start\n"
	printf " \n"
	printf " ${byellow}Stop the web server:${reset}\n"
	printf " ./reconftw.sh --web-server stop\n"
}

###############################################################################################################
############################################# WEB SERVER ######################################################
###############################################################################################################

# webserver initialization, thanks @lur1el, @d3vchac, @mx61tt and @dd4n1b0y <3


function webserver(){
	printf "${bgreen} Web Interface    by @lur1el, @d3vchac, @mx61tt and @dd4n1b0y ${reset}\n"
	ver=$(python3 -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
	
    if [ "$ver" -lt "31" ]; then
        echo "The web interface requires python 3.10 or greater"
        exit 1
    fi

	if [ "$1" == "start" ]; then
		ipAddress=$(hostname -I | cut -d ' ' -f1 | sed -e 's/ //') 

		if [ "$ipAddress" != "" ]; then
			printf "\n ${bblue}Starting web server... ${reset}\n"
			cd $SCRIPTPATH/web || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			$SUDO source $SCRIPTPATH/web/.venv/bin/activate
			$SUDO screen -S ReconftwWebserver -X kill &>/dev/null
			$SUDO screen -dmS ReconftwWebserver python3 manage.py runserver $ipAddress:8001 &>/dev/null
			$SUDO service redis-server start &>/dev/null
			$SUDO screen -S ReconftwCelery -X kill &>/dev/null
			$SUDO screen -dmS ReconftwCelery python3 -m celery -A web worker -l info -P prefork -Q run_scans,default &>/dev/null
			printf " ${bblue}Web server started! ${reset}\n"
			printf " ${bblue}Service Address: http://$ipAddress:8001${reset}\n"
		else
			printf "\n"
			printf " ${red}Server IP address not found.${reset}\n"
			printf "\n"
			printf " ${bblue}Check if the server has internet connection.${reset}\n"
		fi
	elif [ "$1" == "stop" ]; then
		printf "\n ${bblue}Stoping web server... ${reset}\n"
		# $SUDO service postgresql stop
		$SUDO screen -S ReconftwWebserver -X kill &>/dev/null
		$SUDO service redis-server stop &>/dev/null
		$SUDO screen -S ReconftwCelery -X kill &>/dev/null
		printf " ${bblue}Web server stoped! ${reset}\n"
	else
		printf "\n"
		printf " ${red}Invalid action${reset}\n"
		printf "\n"
		printf " ${bblue}Valid actions: start/stop${reset}\n"
	fi
}

###############################################################################################################
########################################### START SCRIPT  #####################################################
###############################################################################################################

# macOS PATH initialization, thanks @0xtavian <3
if [[ "$OSTYPE" == "darwin"* ]]; then
	PATH="/usr/local/opt/gnu-getopt/bin:$PATH"
	PATH="/usr/local/opt/coreutils/libexec/gnubin:$PATH"
fi

PROGARGS=$(getopt -o 'd:m:l:x:i:o:f:q:c:rspanwvh::' --long 'domain:,list:,recon,subdomains,passive,all,web,osint,deep,web-server,help,vps' -n 'reconFTW' -- "$@")


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
			for t in $(cat $list); do
				ipcidr_target $t $list
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
			which axiom-ls &>/dev/null || { printf "\n Axiom is needed for this mode and is not installed \n You have to install it manually \n" && exit; allinstalled=false;}
			AXIOM=true
            shift
            continue
            ;;
        '-f')
			CUSTOM_CONFIG=$2
            shift 2
            continue
            ;;
		'-q')
			rate_limit=$2
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
        '--web-server')
            . ./reconftw.cfg
			banner
			webserver $3
			exit 1
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
SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
. "$SCRIPTPATH"/reconftw.cfg
if [ -s "$CUSTOM_CONFIG" ]; then
    . "${CUSTOM_CONFIG}"
fi

if [ $opt_deep ]; then
    DEEP=true
fi

if [ $rate_limit ]; then
    NUCLEI_RATELIMIT=$rate_limit
	FFUF_RATELIMIT=$rate_limit
	HTTPX_RATELIMIT=$rate_limit
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

if [[ $(id -u | grep -o '^0$') == "0" ]]; then
    SUDO=" "
else
    SUDO="sudo"
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
			LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
			called_fn_dir=$dir/.called_fn 
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

