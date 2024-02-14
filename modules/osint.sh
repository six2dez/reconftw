#!/usr/bin/env bash

source "$1"

###############################################################################################################
################################################### OSINT #####################################################
###############################################################################################################

function google_dorks() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GOOGLE_DORKS == true ]] && [[ $OSINT == true ]]; then
		python3 ${tools}/dorks_hunter/dorks_hunter.py -d "$domain" -o osint/dorks.txt || {
			echo "dorks_hunter command failed"
			exit 1
		}
		end_func "Results are saved in $domain/osint/dorks.txt" "${FUNCNAME[0]}"
	else
		if [[ $GOOGLE_DORKS == false ]] || [[ $OSINT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} are already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function github_dorks() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GITHUB_DORKS == true ]] && [[ $OSINT == true ]]; then
		start_func "${FUNCNAME[0]}" "Github Dorks in process"
		if [[ -s ${GITHUB_TOKENS} ]]; then
			if [[ $DEEP == true ]]; then
				gitdorks_go -gd ${tools}/gitdorks_go/Dorks/medium_dorks.txt -nws 20 -target "$domain" -tf "${GITHUB_TOKENS}" -ew 3 | anew -q osint/gitdorks.txt || {
					echo "gitdorks_go/anew command failed"
					exit 1
				}
			else
				gitdorks_go -gd ${tools}/gitdorks_go/Dorks/smalldorks.txt -nws 20 -target $domain -tf "${GITHUB_TOKENS}" -ew 3 | anew -q osint/gitdorks.txt || {
					echo "gitdorks_go/anew command failed"
					exit 1
				}
			fi
		else
			printf "\n${bred} Required file ${GITHUB_TOKENS} not exists or empty${reset}\n"
		fi
		end_func "Results are saved in $domain/osint/gitdorks.txt" "${FUNCNAME[0]}"
	else
		if [[ $GITHUB_DORKS == false ]] || [[ $OSINT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function github_repos() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GITHUB_REPOS == true ]] && [[ $OSINT == true ]]; then
		start_func "${FUNCNAME[0]}" "Github Repos analysis in process"

		if [[ -s ${GITHUB_TOKENS} ]]; then
			GH_TOKEN=$(cat ${GITHUB_TOKENS} | head -1)
			echo $domain | unfurl format %r >.tmp/company_name.txt
			enumerepo -token-string "${GH_TOKEN}" -usernames .tmp/company_name.txt -o .tmp/company_repos.txt 2>>"$LOGFILE" >/dev/null
			[ -s ".tmp/company_repos.txt" ] && jq -r '.[].repos[]|.url' <.tmp/company_repos.txt >.tmp/company_repos_url.txt 2>>"$LOGFILE"
			mkdir -p .tmp/github_repos 2>>"$LOGFILE" >>"$LOGFILE"
			mkdir -p .tmp/github 2>>"$LOGFILE" >>"$LOGFILE"
			[ -s ".tmp/company_repos_url.txt" ] && interlace -tL .tmp/company_repos_url.txt -threads ${INTERLACE_THREADS} -c "git clone _target_  .tmp/github_repos/_cleantarget_" 2>>"$LOGFILE" >/dev/null 2>&1
			[ -d ".tmp/github/" ] && ls .tmp/github_repos >.tmp/github_repos_folders.txt
			[ -s ".tmp/github_repos_folders.txt" ] && interlace -tL .tmp/github_repos_folders.txt -threads ${INTERLACE_THREADS} -c "gitleaks detect --source .tmp/github_repos/_target_ --no-banner --no-color -r .tmp/github/gh_secret_cleantarget_.json" 2>>"$LOGFILE" >/dev/null
			[ -s ".tmp/company_repos_url.txt" ] && interlace -tL .tmp/company_repos_url.txt -threads ${INTERLACE_THREADS} -c "trufflehog git _target_ -j 2>&1 | jq -c > _output_/_cleantarget_" -o .tmp/github/ >>"$LOGFILE" 2>&1
			if [[ -d ".tmp/github/" ]]; then
				cat .tmp/github/* 2>/dev/null | jq -c | jq -r >osint/github_company_secrets.json 2>>"$LOGFILE"
			fi
		else
			printf "\n${bred} Required file ${GITHUB_TOKENS} not exists or empty${reset}\n"
		fi
		end_func "Results are saved in $domain/osint/github_company_secrets.json" ${FUNCNAME[0]}
	else
		if [[ $GITHUB_REPOS == false ]] || [[ $OSINT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function metadata() {

	if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ ${DIFF} == true ]]; } && [[ ${METADATA} == true ]] && [[ ${OSINT} == true ]] && ! [[ ${domain} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Scanning metadata in public files"
		metafinder -d "$domain" -l $METAFINDER_LIMIT -o osint -go -bi -ba &>>"$LOGFILE" || {
			echo "metafinder command failed"
			exit 1
		}
		mv "osint/${domain}/"*".txt" "osint/" 2>>"$LOGFILE"
		rm -rf "osint/${domain}" 2>>"$LOGFILE"
		end_func "Results are saved in $domain/osint/[software/authors/metadata_results].txt" ${FUNCNAME[0]}
	else
		if [[ $METADATA == false ]] || [[ $OSINT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [[ $METADATA == false ]] || [[ $OSINT == false ]]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi

}

function apileaks() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $API_LEAKS == true ]] && [[ $OSINT == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Scanning for leaks in APIs public directories"

		porch-pirate -s "$domain" --dump 2>>"$LOGFILE" >${dir}/osint/postman_leaks.txt || {
			echo "porch-pirate command failed (probably by rate limit)"
		}
		pushd "${tools}/SwaggerSpy" >/dev/null || {
			echo "Failed to pushd to ${tools}/SwaggerSpy in ${FUNCNAME[0]} @ line ${LINENO}"
		}
		python3 swaggerspy.py $domain 2>>"$LOGFILE" | grep -i "[*]\|URL" >${dir}/osint/swagger_leaks.txt

		popd >/dev/null || {
			echo "Failed to popd in ${FUNCNAME[0]} @ line ${LINENO}"
		}

		[ -s "osint/postman_leaks.txt" ] && trufflehog filesystem ${dir}/osint/postman_leaks.txt -j | jq -c | anew -q ${dir}/osint/postman_leaks_trufflehog.json
		[ -s "osint/swagger_leaks.txt" ] && trufflehog filesystem ${dir}/osint/swagger_leaks.txt -j | jq -c | anew -q ${dir}/osint/swagger_leaks_trufflehog.json

		end_func "Results are saved in $domain/osint/[software/authors/metadata_results].txt" ${FUNCNAME[0]}
	else
		if [[ $API_LEAKS == false ]] || [[ $OSINT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [[ $API_LEAKS == false ]] || [[ $OSINT == false ]]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi

}

function emails() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $EMAILS == true ]] && [[ $OSINT == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Searching emails/users/passwords leaks"
		emailfinder -d $domain 2>>"$LOGFILE" | anew -q .tmp/emailfinder.txt || {
			echo "emailfinder command failed"
			exit 1
		}
		[ -s ".tmp/emailfinder.txt" ] && cat .tmp/emailfinder.txt | grep "@" | grep -iv "|_" | anew -q osint/emails.txt

		pushd "${tools}/LeakSearch" >/dev/null || {
			echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"
		}

		python3 LeakSearch.py -k $domain -o ${dir}/.tmp/passwords.txt 2>>"$LOGFILE" || {
			echo "LeakSearch command failed"
		}

		popd >/dev/null || {
			echo "Failed to popd in ${FUNCNAME[0]} @ line ${LINENO}"
		}

		[ -s ".tmp/passwords.txt" ] && cat .tmp/passwords.txt | anew -q osint/passwords.txt

		end_func "Results are saved in $domain/osint/emails|passwords.txt" ${FUNCNAME[0]}
	else
		if [[ $EMAILS == false ]] || [[ $OSINT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [[ $EMAILS == false ]] || [[ $OSINT == false ]]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi

}

function domain_info() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $DOMAIN_INFO == true ]] && [[ $OSINT == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Searching domain info (whois, registrant name/email domains)"
		whois -H $domain >osint/domain_info_general.txt || { echo "whois command failed"; }
		if [[ $DEEP == true ]] || [[ $REVERSE_WHOIS == true ]]; then
			timeout -k 1m ${AMASS_INTEL_TIMEOUT}m amass intel -d ${domain} -whois -timeout $AMASS_INTEL_TIMEOUT -o osint/domain_info_reverse_whois.txt 2>>"$LOGFILE" >>/dev/null
		fi

		curl -s "https://aadinternals.azurewebsites.net/api/tenantinfo?domainName=${domain}" -H "Origin: https://aadinternals.com" | jq -r .domains[].name >osint/azure_tenant_domains.txt

		end_func "Results are saved in $domain/osint/domain_info_[general/name/email/ip].txt" ${FUNCNAME[0]}
	else
		if [[ $DOMAIN_INFO == false ]] || [[ $OSINT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [[ $DOMAIN_INFO == false ]] || [[ $OSINT == false ]]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi

}

function ip_info() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $IP_INFO == true ]] && [[ $OSINT == true ]] && [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Searching ip info"
		if [[ -n $WHOISXML_API ]]; then
			curl "https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ip=${domain}" 2>/dev/null | jq -r '.result[].name' 2>>"$LOGFILE" | sed -e "s/$/ ${domain}/" | anew -q osint/ip_${domain}_relations.txt
			curl "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOISXML_API}&domainName=${domain}&outputFormat=json&da=2&registryRawText=1&registrarRawText=1&ignoreRawTexts=1" 2>/dev/null | jq 2>>"$LOGFILE" | anew -q osint/ip_${domain}_whois.txt
			curl "https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ipAddress=${domain}" 2>/dev/null | jq -r '.ip,.location' 2>>"$LOGFILE" | anew -q osint/ip_${domain}_location.txt
			end_func "Results are saved in $domain/osint/ip_[domain_relations|whois|location].txt" ${FUNCNAME[0]}
		else
			printf "\n${yellow} No WHOISXML_API var defined, skipping function ${reset}\n"
		fi
	else
		if [[ $IP_INFO == false ]] || [[ $OSINT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [[ $IP_INFO == false ]] || [[ $OSINT == false ]]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi

}
