#!/usr/bin/env bash

###############################################################################################################
############################################# HOST SCAN #######################################################
###############################################################################################################

function favicon() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FAVICON == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Favicon Ip Lookup"
		pushd "${tools}/fav-up" >/dev/null || {
			echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"
		}

		python3 favUp.py -w "$domain" -sc -o favicontest.json 2>>"$LOGFILE" >/dev/null
		if [[ -s "favicontest.json" ]]; then
			cat favicontest.json | jq -r 'try .found_ips' 2>>"$LOGFILE" | grep -v "not-found" >favicontest.txt
			sed -i "s/|/\n/g" favicontest.txt
			cat favicontest.txt 2>>"$LOGFILE"
			mv favicontest.txt $dir/hosts/favicontest.txt 2>>"$LOGFILE"
			rm -f favicontest.json 2>>"$LOGFILE"
		fi

		popd >/dev/null || {
			echo "Failed to popd in ${FUNCNAME[0]} @ line ${LINENO}"
		}
		end_func "Results are saved in hosts/favicontest.txt" ${FUNCNAME[0]}
	else
		if [[ $FAVICON == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [[ $FAVICON == false ]]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi

}

function portscan() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PORTSCANNER == true ]]; then
		start_func ${FUNCNAME[0]} "Port scan"
		if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try . | "\(.host) \(.a[0])"' | anew -q .tmp/subs_ips.txt
			[ -s ".tmp/subs_ips.txt" ] && awk '{ print $2 " " $1}' .tmp/subs_ips.txt | sort -k2 -n | anew -q hosts/subs_ips_vhosts.txt
			[ -s "hosts/subs_ips_vhosts.txt" ] && cat hosts/subs_ips_vhosts.txt | cut -d ' ' -f1 | grep -aEiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q hosts/ips.txt
		else
			echo $domain | grep -aEiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q hosts/ips.txt
		fi
		[ ! -s "hosts/cdn_providers.txt" ] && cat hosts/ips.txt 2>/dev/null | cdncheck -silent -resp -cdn -waf -nc 2>/dev/null >hosts/cdn_providers.txt
		[ -s "hosts/ips.txt" ] && comm -23 <(cat hosts/ips.txt | sort -u) <(cat hosts/cdn_providers.txt | cut -d'[' -f1 | sed 's/[[:space:]]*$//' | sort -u) | grep -aEiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u | anew -q .tmp/ips_nocdn.txt
		printf "${bblue}\n Resolved IP addresses (No CDN) ${reset}\n\n"
		[ -s ".tmp/ips_nocdn.txt" ] && cat .tmp/ips_nocdn.txt | sort
		printf "${bblue}\n Scanning ports... ${reset}\n\n"
		ips_file="${dir}/hosts/ips.txt"
		if [ "$PORTSCAN_PASSIVE" = true ]; then
			if [ ! -f $ips_file ]; then
				echo "File $ips_file does not exist."
			else
				for cip in $(cat "$ips_file"); do
					json_result=$(curl -s https://internetdb.shodan.io/${cip})
					json_array+=("$json_result")
				done
				formatted_json="["
				for ((i = 0; i < ${#json_array[@]}; i++)); do
					formatted_json+="$(echo ${json_array[i]} | tr -d '\n')"
					if [ $i -lt $((${#json_array[@]} - 1)) ]; then
						formatted_json+=", "
					fi
				done
				formatted_json+="]"
				echo "$formatted_json" >"${dir}/hosts/portscan_shodan.txt"
			fi
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
		if [[ $PORTSCAN_PASSIVE == true ]] && [[ ! -f "hosts/portscan_passive.txt" ]] && [[ -s ".tmp/ips_nocdn.txt" ]]; then
			smap -iL .tmp/ips_nocdn.txt >hosts/portscan_passive.txt
		fi
		if [[ $PORTSCAN_ACTIVE == true ]]; then
			if [[ $AXIOM != true ]]; then
				[ -s ".tmp/ips_nocdn.txt" ] && $SUDO nmap ${PORTSCAN_ACTIVE_OPTIONS} -iL .tmp/ips_nocdn.txt -oA hosts/portscan_active 2>>"$LOGFILE" >/dev/null
			else
				[ -s ".tmp/ips_nocdn.txt" ] && axiom-scan .tmp/ips_nocdn.txt -m nmapx ${PORTSCAN_ACTIVE_OPTIONS} -oA hosts/portscan_active $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
		fi

		[ -s "hosts/portscan_active.xml" ] && cat hosts/portscan_active.xml | nmapurls 2>>"$LOGFILE" | anew -q hosts/webs.txt

		if [ -s "hosts/webs.txt" ]; then
			NUMOFLINES=$(cat hosts/webs.txt | wc -l)
			notification "Webs detected from port scan: ${NUMOFLINES} new websites" good
			cat hosts/webs.txt
		fi
		end_func "Results are saved in hosts/portscan_[passive|active|shodan].txt" ${FUNCNAME[0]}
	else
		if [[ $PORTSCANNER == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function cdnprovider() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CDN_IP == true ]]; then
		start_func ${FUNCNAME[0]} "CDN provider check"
		[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try . | .a[]' | grep -aEiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u >.tmp/ips_cdn.txt
		[ -s ".tmp/ips_cdn.txt" ] && cat .tmp/ips_cdn.txt | cdncheck -silent -resp -nc | anew -q $dir/hosts/cdn_providers.txt
		end_func "Results are saved in hosts/cdn_providers.txt" ${FUNCNAME[0]}
	else
		if [[ $CDN_IP == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}
