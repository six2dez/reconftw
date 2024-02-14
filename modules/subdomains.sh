#!/usr/bin/env bash

source "$1"

###############################################################################################################
############################################### SUBDOMAINS ####################################################
###############################################################################################################

function subdomains_full() {
	NUMOFLINES_subs="0"
	NUMOFLINES_probed="0"
	printf "${bgreen}#######################################################################\n\n"
	! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Subdomain Enumeration $domain\n\n"
	[[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Scanning IP $domain\n\n"
	[ -s "subdomains/subdomains.txt" ] && cp subdomains/subdomains.txt .tmp/subdomains_old.txt
	[ -s "webs/webs.txt" ] && cp webs/webs.txt .tmp/probed_old.txt

	if ([[ ! -f "$called_fn_dir/.sub_active" ]] || [[ ! -f "$called_fn_dir/.sub_brute" ]] || [[ ! -f "$called_fn_dir/.sub_permut" ]] || [[ ! -f "$called_fn_dir/.sub_recursive_brute" ]]) || [[ $DIFF == true ]]; then
		resolvers_update
	fi

	[ -s "${inScope_file}" ] && cat ${inScope_file} | anew -q subdomains/subdomains.txt

	if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && [[ $SUBDOMAINS_GENERAL == true ]]; then
		sub_passive
		sub_crt
		sub_active
		sub_noerror
		sub_brute
		sub_permut
		sub_regex_permut
		#sub_gpt
		sub_recursive_passive
		sub_recursive_brute
		sub_dns
		sub_scraping
		sub_analytics
	else
		notification "IP/CIDR detected, subdomains search skipped" info
		echo $domain | anew -q subdomains/subdomains.txt
	fi

	webprobe_simple
	if [[ -s "subdomains/subdomains.txt" ]]; then
		[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file subdomains/subdomains.txt
		NUMOFLINES_subs=$(cat subdomains/subdomains.txt 2>>"$LOGFILE" | anew .tmp/subdomains_old.txt | sed '/^$/d' | wc -l)
	fi
	if [[ -s "webs/webs.txt" ]]; then
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

function sub_passive() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBPASSIVE == true ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Passive Subdomain Enumeration"

		if [[ $RUNAMASS == true ]]; then
			timeout -k 1m ${AMASS_ENUM_TIMEOUT} amass enum -passive -d $domain -config $AMASS_CONFIG -timeout $AMASS_ENUM_TIMEOUT -json .tmp/amass_json.json 2>>"$LOGFILE" >>/dev/null
		fi
		[ -s ".tmp/amass_json.json" ] && cat .tmp/amass_json.json | jq -r '.name' | anew -q .tmp/amass_psub.txt
		[[ $RUNSUBFINDER == true ]] && subfinder -all -d "$domain" -silent -o .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null

		if [[ -s ${GITHUB_TOKENS} ]]; then
			if [[ $DEEP == true ]]; then
				github-subdomains -d $domain -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
			else
				github-subdomains -d $domain -k -q -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
			fi
		fi
		if [[ -s ${GITLAB_TOKENS} ]]; then
			gitlab-subdomains -d "$domain" -t "$GITLAB_TOKENS" 2>>"$LOGFILE" | tee .tmp/gitlab_subdomains_psub.txt >/dev/null
		fi
		if [[ $INSCOPE == true ]]; then
			check_inscope .tmp/amass_psub.txt 2>>"$LOGFILE" >/dev/null
			check_inscope .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null
			check_inscope .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
			check_inscope .tmp/gitlab_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
		fi
		NUMOFLINES=$(find .tmp -type f -iname "*_psub.txt" -exec cat {} + | sed "s/*.//" | anew .tmp/passive_subs.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (passive)" ${FUNCNAME[0]}
	else
		if [[ $SUBPASSIVE == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function sub_crt() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBCRT == true ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Crtsh Subdomain Enumeration"
		crt -s -json -l ${CTR_LIMIT} $domain 2>>"$LOGFILE" | jq -r '.[].subdomain' 2>>"$LOGFILE" | sed -e 's/^\*\.//' | anew -q .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" >/dev/null
		[[ $INSCOPE == true ]] && check_inscope .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" | sed 's/\*.//g' | anew .tmp/crtsh_subs.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (cert transparency)" ${FUNCNAME[0]}
	else
		if [[ $SUBCRT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function sub_active() {

	if [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Active Subdomain Enumeration"
		find .tmp -type f -iname "*_subs.txt" -exec cat {} + | anew -q .tmp/subs_no_resolved.txt
		[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/subs_no_resolved.txt
		if [[ $AXIOM != true ]]; then
			resolvers_update_quick_local
			[ -s ".tmp/subs_no_resolved.txt" ] && puredns resolve .tmp/subs_no_resolved.txt -w .tmp/subdomains_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/subs_no_resolved.txt" ] && axiom-scan .tmp/subs_no_resolved.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subdomains_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		echo $domain | dnsx -retry 3 -silent -r $resolvers_trusted 2>>"$LOGFILE" | anew -q .tmp/subdomains_tmp.txt
		if [[ $DEEP == true ]]; then
			cat .tmp/subdomains_tmp.txt | tlsx -san -cn -silent -ro -c $TLSX_THREADS -p $TLS_PORTS | anew -q .tmp/subdomains_tmp.txt
		else
			cat .tmp/subdomains_tmp.txt | tlsx -san -cn -silent -ro -c $TLSX_THREADS | anew -q .tmp/subdomains_tmp.txt
		fi
		[[ $INSCOPE == true ]] && check_inscope .tmp/subdomains_tmp.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/subdomains_tmp.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} subs DNS resolved from passive" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi

}

function sub_noerror() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBNOERROR == true ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Checking NOERROR DNS response"
		if [[ $(echo "${RANDOM}thistotallynotexist${RANDOM}.$domain" | dnsx -r $resolvers -rcode noerror,nxdomain -retry 3 -silent | cut -d' ' -f2) == "[NXDOMAIN]" ]]; then
			resolvers_update_quick_local
			if [[ $DEEP == true ]]; then
				dnsx -d $domain -r $resolvers -silent -rcode noerror -w $subs_wordlist_big | cut -d' ' -f1 | anew -q .tmp/subs_noerror.txt 2>>"$LOGFILE" >/dev/null
			else
				dnsx -d $domain -r $resolvers -silent -rcode noerror -w $subs_wordlist | cut -d' ' -f1 | anew -q .tmp/subs_noerror.txt 2>>"$LOGFILE" >/dev/null
			fi
			[[ $INSCOPE == true ]] && check_inscope .tmp/subs_noerror.txt 2>>"$LOGFILE" >/dev/null
			NUMOFLINES=$(cat .tmp/subs_noerror.txt 2>>"$LOGFILE" | sed "s/*.//" | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
			end_subfunc "${NUMOFLINES} new subs (DNS noerror)" ${FUNCNAME[0]}
		else
			printf "\n${yellow} Detected DNSSEC black lies, skipping this technique ${reset}\n"
		fi
	else
		if [[ $SUBNOERROR == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function sub_dns() {

	if [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : DNS Subdomain Enumeration and PTR search"
		if [[ $AXIOM != true ]]; then
			[ -s "subdomains/subdomains.txt" ] && cat subdomains/subdomains.txt | dnsx -r $resolvers_trusted -a -aaaa -cname -ns -ptr -mx -soa -silent -retry 3 -json -o subdomains/subdomains_dnsregs.json 2>>"$LOGFILE" >/dev/null
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[], try .aaaa[], try .cname[], try .ns[], try .ptr[], try .mx[], try .soa[]' 2>/dev/null | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[]' | sort -u | hakip2host | cut -d' ' -f 3 | unfurl -u domains | sed -e 's/*\.//' -e 's/\.$//' -e '/\./!d' | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try "\(.host) - \(.a[])"' 2>/dev/null | sort -u -k2 | anew -q subdomains/subdomains_ips.txt
			resolvers_update_quick_local
			[ -s ".tmp/subdomains_dns.txt" ] && puredns resolve .tmp/subdomains_dns.txt -w .tmp/subdomains_dns_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			[ -s "subdomains/subdomains.txt" ] && axiom-scan subdomains/subdomains.txt -m dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -json -o subdomains/subdomains_dnsregs.json $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[]' | sort -u | anew -q .tmp/subdomains_dns_a_records.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[]' | sort -u | hakip2host | cut -d' ' -f 3 | unfurl -u domains | sed -e 's/*\.//' -e 's/\.$//' -e '/\./!d' | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[], try .aaaa[], try .cname[], try .ns[], try .ptr[], try .mx[], try .soa[]' 2>/dev/null | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try "\(.host) - \(.a[])"' 2>/dev/null | sort -u -k2 | anew -q subdomains/subdomains_ips.txt
			resolvers_update_quick_axiom
			[ -s ".tmp/subdomains_dns.txt" ] && axiom-scan .tmp/subdomains_dns.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subdomains_dns_resolved.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		[[ $INSCOPE == true ]] && check_inscope .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (dns resolution)" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi

}

function sub_brute() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBBRUTE == true ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Bruteforce Subdomain Enumeration"
		if [[ $AXIOM != true ]]; then
			resolvers_update_quick_local
			if [[ $DEEP == true ]]; then
				puredns bruteforce $subs_wordlist_big $domain -w .tmp/subs_brute.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
			else
				puredns bruteforce $subs_wordlist $domain -w .tmp/subs_brute.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
			fi
			[ -s ".tmp/subs_brute.txt" ] && puredns resolve .tmp/subs_brute.txt -w .tmp/subs_brute_valid.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			resolvers_update_quick_axiom
			if [[ $DEEP == true ]]; then
				axiom-scan $subs_wordlist_big -m puredns-single $domain -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subs_brute.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			else
				axiom-scan $subs_wordlist -m puredns-single $domain -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subs_brute.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
			[ -s ".tmp/subs_brute.txt" ] && axiom-scan .tmp/subs_brute.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subs_brute_valid.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		[[ $INSCOPE == true ]] && check_inscope .tmp/subs_brute_valid.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/subs_brute_valid.txt 2>>"$LOGFILE" | sed "s/*.//" | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (bruteforce)" ${FUNCNAME[0]}
	else
		if [[ $SUBBRUTE == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function sub_scraping() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBSCRAPING == true ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Source code scraping subdomain search"
		touch .tmp/scrap_subs.txt
		if [[ -s "$dir/subdomains/subdomains.txt" ]]; then
			if [[ $(cat subdomains/subdomains.txt | wc -l) -le $DEEP_LIMIT ]] || [[ $DEEP == true ]]; then
				if [[ $AXIOM != true ]]; then
					resolvers_update_quick_local
					cat subdomains/subdomains.txt | httpx -follow-host-redirects -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info1.txt 2>>"$LOGFILE" >/dev/null
					[ -s ".tmp/web_full_info1.txt" ] && cat .tmp/web_full_info1.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
					[ -s ".tmp/probed_tmp_scrap.txt" ] && timeout -k 1m 10m httpx -l .tmp/probed_tmp_scrap.txt -tls-grab -tls-probe -csp-probe -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -no-color -json -o .tmp/web_full_info2.txt 2>>"$LOGFILE" >/dev/null
					[ -s ".tmp/web_full_info2.txt" ] && cat .tmp/web_full_info2.txt | jq -r 'try ."tls-grab"."dns_names"[],try .csp.domains[],try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | sort -u | httpx -silent | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt

					if [[ $DEEP == true ]]; then
						[ -s ".tmp/probed_tmp_scrap.txt" ] && katana -silent -list .tmp/probed_tmp_scrap.txt -jc -kf all -c $KATANA_THREADS -d 3 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" >/dev/null
					else
						[ -s ".tmp/probed_tmp_scrap.txt" ] && katana -silent -list .tmp/probed_tmp_scrap.txt -jc -kf all -c $KATANA_THREADS -d 2 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" >/dev/null
					fi
				else
					resolvers_update_quick_axiom
					axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info1.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					[ -s ".tmp/web_full_info1.txt" ] && cat .tmp/web_full_info1.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
					[ -s ".tmp/probed_tmp_scrap.txt" ] && timeout -k 1m 10m axiom-scan .tmp/probed_tmp_scrap.txt -m httpx -tls-grab -tls-probe -csp-probe -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info2.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					[ -s ".tmp/web_full_info2.txt" ] && cat .tmp/web_full_info2.txt | jq -r 'try ."tls-grab"."dns_names"[],try .csp.domains[],try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | sort -u | httpx -silent | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
					if [[ $DEEP == true ]]; then
						[ -s ".tmp/probed_tmp_scrap.txt" ] && axiom-scan .tmp/probed_tmp_scrap.txt -m katana -jc -kf all -d 3 -fs rdn -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					else
						[ -s ".tmp/probed_tmp_scrap.txt" ] && axiom-scan .tmp/probed_tmp_scrap.txt -m katana -jc -kf all -d 2 -fs rdn -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					fi
				fi
				sed -i '/^.\{2048\}./d' .tmp/katana.txt
				[ -s ".tmp/katana.txt" ] && cat .tmp/katana.txt | unfurl -u domains 2>>"$LOGFILE" | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q .tmp/scrap_subs.txt
				[ -s ".tmp/scrap_subs.txt" ] && puredns resolve .tmp/scrap_subs.txt -w .tmp/scrap_subs_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
				if [[ $INSCOPE == true ]]; then
					check_inscope .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" >/dev/null
				fi
				NUMOFLINES=$(cat .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | tee .tmp/diff_scrap.txt | sed '/^$/d' | wc -l)
				[ -s ".tmp/diff_scrap.txt" ] && cat .tmp/diff_scrap.txt | httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info3.txt 2>>"$LOGFILE" >/dev/null
				[ -s ".tmp/web_full_info3.txt" ] && cat .tmp/web_full_info3.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
				cat .tmp/web_full_info1.txt .tmp/web_full_info2.txt .tmp/web_full_info3.txt 2>>"$LOGFILE" | jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"$LOGFILE" >.tmp/web_full_info.txt
				end_subfunc "${NUMOFLINES} new subs (code scraping)" ${FUNCNAME[0]}
			else
				end_subfunc "Skipping Subdomains Web Scraping: Too Many Subdomains" ${FUNCNAME[0]}
			fi
		else
			end_subfunc "No subdomains to search (code scraping)" ${FUNCNAME[0]}
		fi
	else
		if [[ $SUBSCRAPING == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function sub_analytics() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBANALYTICS == true ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Analytics Subdomain Enumeration"
		if [[ -s ".tmp/probed_tmp_scrap.txt" ]]; then
			mkdir -p .tmp/output_analytics/
			analyticsrelationships -ch <.tmp/probed_tmp_scrap.txt >>.tmp/analytics_subs_tmp.txt 2>>"$LOGFILE"

			[ -s ".tmp/analytics_subs_tmp.txt" ] && cat .tmp/analytics_subs_tmp.txt | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/|__ //" | anew -q .tmp/analytics_subs_clean.txt
			if [[ $AXIOM != true ]]; then
				resolvers_update_quick_local
				[ -s ".tmp/analytics_subs_clean.txt" ] && puredns resolve .tmp/analytics_subs_clean.txt -w .tmp/analytics_subs_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
			else
				resolvers_update_quick_axiom
				[ -s ".tmp/analytics_subs_clean.txt" ] && axiom-scan .tmp/analytics_subs_clean.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/analytics_subs_resolved.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
		fi
		[[ $INSCOPE == true ]] && check_inscope .tmp/analytics_subs_resolved.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/analytics_subs_resolved.txt 2>>"$LOGFILE" | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (analytics relationship)" ${FUNCNAME[0]}
	else
		if [[ $SUBANALYTICS == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function sub_permut() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBPERMUTE == true ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Permutations Subdomain Enumeration"
		if [[ $DEEP == true ]] || [[ "$(cat subdomains/subdomains.txt | wc -l)" -le $DEEP_LIMIT ]]; then
			if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
				[ -s "subdomains/subdomains.txt" ] && gotator -sub subdomains/subdomains.txt -perm ${tools}/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT >.tmp/gotator1.txt
			else
				[ -s "subdomains/subdomains.txt" ] && ripgen -d subdomains/subdomains.txt -w ${tools}/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT >.tmp/gotator1.txt
			fi
		elif [[ "$(cat .tmp/subs_no_resolved.txt | wc -l)" -le $DEEP_LIMIT2 ]]; then
			if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
				[ -s ".tmp/subs_no_resolved.txt" ] && gotator -sub .tmp/subs_no_resolved.txt -perm ${tools}/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT >.tmp/gotator1.txt
			else
				[ -s ".tmp/subs_no_resolved.txt" ] && ripgen -d .tmp/subs_no_resolved.txt -w ${tools}/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT >.tmp/gotator1.txt
			fi
		else
			end_subfunc "Skipping Permutations: Too Many Subdomains" ${FUNCNAME[0]}
			return 1
		fi
		if [[ $AXIOM != true ]]; then
			resolvers_update_quick_local
			[ -s ".tmp/gotator1.txt" ] && puredns resolve .tmp/gotator1.txt -w .tmp/permute1.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/gotator1.txt" ] && axiom-scan .tmp/gotator1.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute1.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi

		if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
			[ -s ".tmp/permute1.txt" ] && gotator -sub .tmp/permute1.txt -perm ${tools}/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT >.tmp/gotator2.txt
		else
			[ -s ".tmp/permute1.txt" ] && ripgen -d .tmp/permute1.txt -w ${tools}/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT >.tmp/gotator2.txt
		fi

		if [[ $AXIOM != true ]]; then
			[ -s ".tmp/gotator2.txt" ] && puredns resolve .tmp/gotator2.txt -w .tmp/permute2.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			[ -s ".tmp/gotator2.txt" ] && axiom-scan .tmp/gotator2.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute2.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		cat .tmp/permute1.txt .tmp/permute2.txt 2>>"$LOGFILE" | anew -q .tmp/permute_subs.txt

		if [[ -s ".tmp/permute_subs.txt" ]]; then
			[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/permute_subs.txt
			[[ $INSCOPE == true ]] && check_inscope .tmp/permute_subs.txt 2>>"$LOGFILE" >/dev/null
			NUMOFLINES=$(cat .tmp/permute_subs.txt 2>>"$LOGFILE" | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		else
			NUMOFLINES=0
		fi
		end_subfunc "${NUMOFLINES} new subs (permutations)" ${FUNCNAME[0]}
	else
		if [[ $SUBPERMUTE == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function sub_regex_permut() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBREGEXPERMUTE == true ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Permutations by regex analysis"

		pushd "${tools}/regulator" >/dev/null || {
			echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"
		}

		python3 main.py -t $domain -f ${dir}/subdomains/subdomains.txt -o ${dir}/.tmp/${domain}.brute

		popd >/dev/null || {
			echo "Failed to popd in ${FUNCNAME[0]} @ line ${LINENO}"
		}

		if [[ $AXIOM != true ]]; then
			resolvers_update_quick_local
			[ -s ".tmp/${domain}.brute" ] && puredns resolve .tmp/${domain}.brute -w .tmp/regulator.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/${domain}.brute" ] && axiom-scan .tmp/${domain}.brute -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/regulator.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi

		if [[ -s ".tmp/regulator.txt" ]]; then
			[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/regulator.txt
			[[ $INSCOPE == true ]] && check_inscope .tmp/regulator.txt 2>>"$LOGFILE" >/dev/null
			NUMOFLINES=$(cat .tmp/regulator.txt 2>>"$LOGFILE" | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		else
			NUMOFLINES=0
		fi
		end_subfunc "${NUMOFLINES} new subs (permutations by regex)" ${FUNCNAME[0]}
	else
		if [[ $SUBREGEXPERMUTE == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function sub_recursive_passive() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUB_RECURSIVE_PASSIVE == true ]] && [[ -s "subdomains/subdomains.txt" ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Subdomains recursive search passive"
		# Passive recursive
		[ -s "subdomains/subdomains.txt" ] && dsieve -if subdomains/subdomains.txt -f 3 -top $DEEP_RECURSIVE_PASSIVE >.tmp/subdomains_recurs_top.txt
		if [[ $AXIOM != true ]]; then
			resolvers_update_quick_local
			[ -s ".tmp/subdomains_recurs_top.txt" ] && timeout -k 1m ${AMASS_ENUM_TIMEOUT}m amass enum -passive -df .tmp/subdomains_recurs_top.txt -nf subdomains/subdomains.txt -config $AMASS_CONFIG -timeout $AMASS_ENUM_TIMEOUT 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
			[ -s ".tmp/passive_recursive.txt" ] && puredns resolve .tmp/passive_recursive.txt -w .tmp/passive_recurs_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/subdomains_recurs_top.txt" ] && axiom-scan .tmp/subdomains_recurs_top.txt -m amass -passive -o .tmp/amass_prec.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			[ -s ".tmp/amass_prec.txt" ] && cat .tmp/amass_prec.txt | anew -q .tmp/passive_recursive.txt
			[ -s ".tmp/passive_recursive.txt" ] && axiom-scan .tmp/passive_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/passive_recurs_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		[[ $INSCOPE == true ]] && check_inscope .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed '/^$/d' | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (recursive)" ${FUNCNAME[0]}
	else
		if [[ $SUB_RECURSIVE_PASSIVE == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function sub_recursive_brute() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUB_RECURSIVE_BRUTE == true ]] && [[ -s "subdomains/subdomains.txt" ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Subdomains recursive search active"
		if [[ $(cat subdomains/subdomains.txt | wc -l) -le $DEEP_LIMIT ]]; then
			[ ! -s ".tmp/subdomains_recurs_top.txt" ] && dsieve -if subdomains/subdomains.txt -f 3 -top $DEEP_RECURSIVE_PASSIVE >.tmp/subdomains_recurs_top.txt
			ripgen -d .tmp/subdomains_recurs_top.txt -w $subs_wordlist >.tmp/brute_recursive_wordlist.txt
			if [[ $AXIOM != true ]]; then
				resolvers_update_quick_local
				[ -s ".tmp/brute_recursive_wordlist.txt" ] && puredns resolve .tmp/brute_recursive_wordlist.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -w .tmp/brute_recursive_result.txt 2>>"$LOGFILE" >/dev/null
			else
				resolvers_update_quick_axiom
				[ -s ".tmp/brute_recursive_wordlist.txt" ] && axiom-scan .tmp/brute_recursive_wordlist.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/brute_recursive_result.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
			[ -s ".tmp/brute_recursive_result.txt" ] && cat .tmp/brute_recursive_result.txt | anew -q .tmp/brute_recursive.txt

			if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
				[ -s ".tmp/brute_recursive.txt" ] && gotator -sub .tmp/brute_recursive.txt -perm ${tools}/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT >.tmp/gotator1_recursive.txt
			else
				[ -s ".tmp/brute_recursive.txt" ] && ripgen -d .tmp/brute_recursive.txt -w ${tools}/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT >.tmp/gotator1_recursive.txt
			fi

			if [[ $AXIOM != true ]]; then
				[ -s ".tmp/gotator1_recursive.txt" ] && puredns resolve .tmp/gotator1_recursive.txt -w .tmp/permute1_recursive.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
			else
				[ -s ".tmp/gotator1_recursive.txt" ] && axiom-scan .tmp/gotator1_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute1_recursive.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi

			if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
				[ -s ".tmp/permute1_recursive.txt" ] && gotator -sub .tmp/permute1_recursive.txt -perm ${tools}/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT >.tmp/gotator2_recursive.txt
			else
				[ -s ".tmp/permute1_recursive.txt" ] && ripgen -d .tmp/permute1_recursive.txt -w ${tools}/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT >.tmp/gotator2_recursive.txt
			fi

			if [[ $AXIOM != true ]]; then
				[ -s ".tmp/gotator2_recursive.txt" ] && puredns resolve .tmp/gotator2_recursive.txt -w .tmp/permute2_recursive.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
			else
				[ -s ".tmp/gotator2_recursive.txt" ] && axiom-scan .tmp/gotator2_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute2_recursive.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
			cat .tmp/permute1_recursive.txt .tmp/permute2_recursive.txt 2>>"$LOGFILE" | anew -q .tmp/permute_recursive.txt
		else
			end_subfunc "skipped in this mode or defined in reconftw.cfg" ${FUNCNAME[0]}
		fi
		if [[ $INSCOPE == true ]]; then
			check_inscope .tmp/permute_recursive.txt 2>>"$LOGFILE" >/dev/null
			check_inscope .tmp/brute_recursive.txt 2>>"$LOGFILE" >/dev/null
		fi

		# Last validation
		cat .tmp/permute_recursive.txt .tmp/brute_recursive.txt 2>>"$LOGFILE" | anew -q .tmp/brute_perm_recursive.txt
		if [[ $AXIOM != true ]]; then
			[ -s ".tmp/brute_recursive.txt" ] && puredns resolve .tmp/brute_perm_recursive.txt -w .tmp/brute_perm_recursive_final.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			[ -s ".tmp/brute_recursive.txt" ] && axiom-scan .tmp/brute_perm_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/brute_perm_recursive_final.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi

		NUMOFLINES=$(cat .tmp/brute_perm_recursive_final.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed '/^$/d' | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (recursive active)" ${FUNCNAME[0]}
	else
		if [[ $SUB_RECURSIVE_BRUTE == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function subtakeover() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBTAKEOVER == true ]]; then
		start_func ${FUNCNAME[0]} "Looking for possible subdomain and DNS takeover"
		touch .tmp/tko.txt
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		if [[ $AXIOM != true ]]; then
			nuclei -update 2>>"$LOGFILE" >/dev/null
			cat subdomains/subdomains.txt webs/webs_all.txt 2>/dev/null | nuclei -silent -nh -tags takeover -severity info,low,medium,high,critical -retries 3 -rl $NUCLEI_RATELIMIT -t ${NUCLEI_TEMPLATES_PATH} -o .tmp/tko.txt
		else
			cat subdomains/subdomains.txt webs/webs_all.txt 2>>"$LOGFILE" | sed '/^$/d' | anew -q .tmp/webs_subs.txt
			[ -s ".tmp/webs_subs.txt" ] && axiom-scan .tmp/webs_subs.txt -m nuclei --nuclei-templates ${NUCLEI_TEMPLATES_PATH} -tags takeover -nh -severity info,low,medium,high,critical -retries 3 -rl $NUCLEI_RATELIMIT -t ${NUCLEI_TEMPLATES_PATH} -o .tmp/tko.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi

		# DNS_TAKEOVER
		cat .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/scrap_subs.txt .tmp/analytics_subs_clean.txt .tmp/passive_recursive.txt 2>/dev/null | anew -q .tmp/subs_dns_tko.txt
		cat .tmp/subs_dns_tko.txt 2>/dev/null | dnstake -c $DNSTAKE_THREADS -s 2>>"$LOGFILE" | sed '/^$/d' | anew -q .tmp/tko.txt

		sed -i '/^$/d' .tmp/tko.txt

		NUMOFLINES=$(cat .tmp/tko.txt 2>>"$LOGFILE" | anew webs/takeover.txt | sed '/^$/d' | wc -l)
		if [[ $NUMOFLINES -gt 0 ]]; then
			notification "${NUMOFLINES} new possible takeovers found" info
		fi
		end_func "Results are saved in $domain/webs/takeover.txt" ${FUNCNAME[0]}
	else
		if [[ $SUBTAKEOVER == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function zonetransfer() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $ZONETRANSFER == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Zone transfer check"
		for ns in $(dig +short ns "$domain"); do dig axfr "$domain" @"$ns" >>subdomains/zonetransfer.txt; done
		if [[ -s "subdomains/zonetransfer.txt" ]]; then
			if ! grep -q "Transfer failed" subdomains/zonetransfer.txt; then notification "Zone transfer found on ${domain}!" info; fi
		fi
		end_func "Results are saved in $domain/subdomains/zonetransfer.txt" ${FUNCNAME[0]}
	else
		if [[ $ZONETRANSFER == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [[ $ZONETRANSFER == false ]]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi

}

function s3buckets() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $S3BUCKETS == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "AWS S3 buckets search"
		# S3Scanner
		if [[ $AXIOM != true ]]; then
			[ -s "subdomains/subdomains.txt" ] && s3scanner scan -f subdomains/subdomains.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt
		else
			axiom-scan subdomains/subdomains.txt -m s3scanner -o .tmp/s3buckets_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			[ -s ".tmp/s3buckets_tmp.txt" ] && cat .tmp/s3buckets_tmp.txt .tmp/s3buckets_tmp2.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt && sed -i '/^$/d' .tmp/s3buckets.txt
		fi
		# Cloudenum
		keyword=${domain%%.*}
		timeout -k 1m 20m python3 ~/Tools/cloud_enum/cloud_enum.py -k $keyword -l .tmp/output_cloud.txt 2>>"$LOGFILE" >/dev/null

		NUMOFLINES1=$(cat .tmp/output_cloud.txt 2>>"$LOGFILE" | sed '/^#/d' | sed '/^$/d' | anew subdomains/cloud_assets.txt | wc -l)
		if [[ $NUMOFLINES1 -gt 0 ]]; then
			notification "${NUMOFLINES1} new cloud assets found" info
		fi
		NUMOFLINES2=$(cat .tmp/s3buckets.txt 2>>"$LOGFILE" | grep -aiv "not_exist" | grep -aiv "Warning:" | grep -aiv "invalid_name" | grep -aiv "^http" | awk 'NF' | anew subdomains/s3buckets.txt | sed '/^$/d' | wc -l)
		if [[ $NUMOFLINES2 -gt 0 ]]; then
			notification "${NUMOFLINES2} new S3 buckets found" info
		fi

		[ -s "subdomains/s3buckets.txt" ] && for i in $(cat subdomains/s3buckets.txt); do trufflehog s3 --bucket="$i" -j | jq -c | anew -q subdomains/s3buckets_trufflehog.txt; done

		end_func "Results are saved in subdomains/s3buckets.txt and subdomains/cloud_assets.txt" ${FUNCNAME[0]}
	else
		if [[ $S3BUCKETS == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [[ $S3BUCKETS == false ]]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi

}
