#!/usr/bin/env bash

source "$1"

###############################################################################################################
########################################### WEB DETECTION #####################################################
###############################################################################################################

function webprobe_simple() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBPROBESIMPLE == true ]]; then
		start_subfunc ${FUNCNAME[0]} "Running : Http probing $domain"
		if [[ $AXIOM != true ]]; then
			cat subdomains/subdomains.txt | httpx ${HTTPX_FLAGS} -no-color -json -random-agent -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -retries 2 -timeout $HTTPX_TIMEOUT -o .tmp/web_full_info_probe.txt 2>>"$LOGFILE" >/dev/null
		else
			axiom-scan subdomains/subdomains.txt -m httpx ${HTTPX_FLAGS} -no-color -json -random-agent -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -retries 2 -timeout $HTTPX_TIMEOUT -o .tmp/web_full_info_probe.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		cat .tmp/web_full_info.txt .tmp/web_full_info_probe.txt webs/web_full_info.txt 2>>"$LOGFILE" | jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"$LOGFILE" >webs/web_full_info.txt
		[ -s "webs/web_full_info.txt" ] && cat webs/web_full_info.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew -q .tmp/probed_tmp.txt
		[ -s "webs/web_full_info.txt" ] && cat webs/web_full_info.txt | jq -r 'try . |"\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' | grep "$domain" | anew -q webs/web_full_info_plain.txt
		[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/probed_tmp.txt
		NUMOFLINES=$(cat .tmp/probed_tmp.txt 2>>"$LOGFILE" | anew webs/webs.txt | sed '/^$/d' | wc -l)
		cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		end_subfunc "${NUMOFLINES} new websites resolved" ${FUNCNAME[0]}
		if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(cat webs/webs.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
			notification "Sending websites to proxy" info
			ffuf -mc all -w webs/webs.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" >/dev/null
		fi
	else
		if [[ $WEBPROBESIMPLE == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function webprobe_full() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBPROBEFULL == true ]]; then
		start_func ${FUNCNAME[0]} "Http probing non standard ports"
		if [[ -s "subdomains/subdomains.txt" ]]; then
			if [[ $AXIOM != true ]]; then
				if [[ -s "subdomains/subdomains.txt" ]]; then
					cat subdomains/subdomains.txt | httpx -follow-host-redirects -random-agent -status-code -p $UNCOMMON_PORTS_WEB -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" >/dev/null
				fi
			else
				if [[ -s "subdomains/subdomains.txt" ]]; then
					axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -H \"${HEADER}\" -status-code -p $UNCOMMON_PORTS_WEB -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info_uncommon.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
				fi
			fi
		fi
		[ -s ".tmp/web_full_info_uncommon.txt" ] && cat .tmp/web_full_info_uncommon.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?' | sed "s/*.//" | anew -q .tmp/probed_uncommon_ports_tmp.txt
		[ -s ".tmp/web_full_info_uncommon.txt" ] && cat .tmp/web_full_info_uncommon.txt | jq -r 'try . |"\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' | anew -q webs/web_full_info_uncommon_plain.txt
		if [[ -s ".tmp/web_full_info_uncommon.txt" ]]; then
			if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
				cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | anew -q webs/web_full_info_uncommon.txt
			else
				cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | grep "$domain" | anew -q webs/web_full_info_uncommon.txt
			fi
		fi
		NUMOFLINES=$(cat .tmp/probed_uncommon_ports_tmp.txt 2>>"$LOGFILE" | anew webs/webs_uncommon_ports.txt | sed '/^$/d' | wc -l)
		notification "Uncommon web ports: ${NUMOFLINES} new websites" good
		[ -s "webs/webs_uncommon_ports.txt" ] && cat webs/webs_uncommon_ports.txt
		cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		end_func "Results are saved in $domain/webs/webs_uncommon_ports.txt" ${FUNCNAME[0]}
		if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(cat webs/webs_uncommon_ports.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
			notification "Sending websites with uncommon ports to proxy" info
			ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" >/dev/null
		fi
	else
		if [[ $WEBPROBEFULL == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function screenshot() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBSCREENSHOT == true ]]; then
		start_func ${FUNCNAME[0]} "Web Screenshots"
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt

		if [[ $AXIOM != true ]]; then
			[ -s "webs/webs_all.txt" ] && cat webs/webs_all.txt | nuclei -headless -id screenshot -V dir='screenshots' 2>>"$LOGFILE"
		else
			[ -s "webs/webs_all.txt" ] && axiom-scan webs/webs_all.txt -m nuclei-screenshots -o screenshots $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		end_func "Results are saved in $domain/screenshots folder" ${FUNCNAME[0]}
	else
		if [[ $WEBSCREENSHOT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function virtualhosts() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $VIRTUALHOSTS == true ]]; then
		start_func ${FUNCNAME[0]} "Virtual Hosts dicovery"
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		if [[ -s "webs/webs_all.txt" ]]; then
			mkdir -p $dir/virtualhosts $dir/.tmp/virtualhosts
			interlace -tL webs/webs_all.txt -threads ${INTERLACE_THREADS} -c "ffuf -ac -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -H \"Host: FUZZ._cleantarget_\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u  _target_ -of json -o _output_/_cleantarget_.json" -o $dir/.tmp/virtualhosts 2>>"$LOGFILE" >/dev/null
			for sub in $(cat webs/webs_all.txt); do
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				[ -s "$dir/.tmp/virtualhosts/${sub_out}.json" ] && cat $dir/.tmp/virtualhosts/${sub_out}.json | jq -r 'try .results[] | "\(.status) \(.length) \(.url)"' | sort | anew -q $dir/virtualhosts/${sub_out}.txt
			done
			find $dir/virtualhosts/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | anew -q $dir/virtualhosts/virtualhosts_full.txt
			end_func "Results are saved in $domain/virtualhosts/*subdomain*.txt" ${FUNCNAME[0]}
		else
			end_func "No $domain/web/webs.txts file found, virtualhosts skipped " ${FUNCNAME[0]}
		fi
	else
		if [[ $VIRTUALHOSTS == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

###############################################################################################################
############################################# WEB SCAN ########################################################
###############################################################################################################

function waf_checks() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WAF_DETECTION == true ]]; then
		start_func ${FUNCNAME[0]} "Website's WAF detection"
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		if [[ -s "webs/webs_all.txt" ]]; then
			if [[ $AXIOM != true ]]; then
				wafw00f -i webs/webs_all.txt -o .tmp/wafs.txt 2>>"$LOGFILE" >/dev/null
			else
				axiom-scan webs/webs_all.txt -m wafw00f -o .tmp/wafs.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
			if [[ -s ".tmp/wafs.txt" ]]; then
				cat .tmp/wafs.txt | sed -e 's/^[ \t]*//' -e 's/ \+ /\t/g' -e '/(None)/d' | tr -s "\t" ";" >webs/webs_wafs.txt
				NUMOFLINES=$(cat webs/webs_wafs.txt 2>>"$LOGFILE" | sed '/^$/d' | wc -l)
				notification "${NUMOFLINES} websites protected by waf" info
				end_func "Results are saved in $domain/webs/webs_wafs.txt" ${FUNCNAME[0]}
			else
				end_func "No results found" ${FUNCNAME[0]}
			fi
		else
			end_func "No websites to scan" ${FUNCNAME[0]}
		fi
	else
		if [[ $WAF_DETECTION == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function nuclei_check() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $NUCLEICHECK == true ]]; then
		start_func ${FUNCNAME[0]} "Templates based web scanner"
		nuclei -update 2>>"$LOGFILE" >/dev/null
		mkdir -p nuclei_output
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		[ ! -s ".tmp/webs_subs.txt" ] && cat subdomains/subdomains.txt webs/webs_all.txt 2>>"$LOGFILE" | anew -q .tmp/webs_subs.txt
		[ -s "$dir/fuzzing/fuzzing_full.txt" ] && cat $dir/fuzzing/fuzzing_full.txt | grep -e "^200" | cut -d " " -f3 | anew -q .tmp/webs_fuzz.txt
		cat .tmp/webs_subs.txt .tmp/webs_fuzz.txt 2>>"$LOGFILE" | anew -q .tmp/webs_nuclei.txt
		if [[ $AXIOM != true ]]; then # avoid globbing (expansion of *).
			IFS=',' read -ra severity_array <<<"$NUCLEI_SEVERITY"
			for crit in "${severity_array[@]}"; do
				printf "${yellow}\n Running : Nuclei $crit ${reset}\n\n"
				cat .tmp/webs_nuclei.txt 2>/dev/null | nuclei $NUCLEI_FLAGS -severity $crit -nh -rl $NUCLEI_RATELIMIT -o nuclei_output/${crit}.txt
			done
			printf "\n\n"
		else
			if [[ -s ".tmp/webs_nuclei.txt" ]]; then
				IFS=',' read -ra severity_array <<<"$NUCLEI_SEVERITY"
				for crit in "${severity_array[@]}"; do
					printf "${yellow}\n Running : Nuclei $crit, check results on nuclei_output folder${reset}\n\n"
					axiom-scan .tmp/webs_nuclei.txt -m nuclei --nuclei-templates ${NUCLEI_TEMPLATES_PATH} -severity ${crit} -nh -rl $NUCLEI_RATELIMIT -o nuclei_output/${crit}.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					[ -s "nuclei_output/${crit}.txt" ] && cat nuclei_output/${crit}.txt
				done
				printf "\n\n"
			fi
		fi
		end_func "Results are saved in $domain/nuclei_output folder" ${FUNCNAME[0]}
	else
		if [[ $NUCLEICHECK == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function fuzz() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FUZZ == true ]]; then
		start_func ${FUNCNAME[0]} "Web directory fuzzing"
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		if [[ -s "webs/webs_all.txt" ]]; then
			mkdir -p $dir/fuzzing $dir/.tmp/fuzzing
			if [[ $AXIOM != true ]]; then
				interlace -tL webs/webs_all.txt -threads ${INTERLACE_THREADS} -c "ffuf ${FFUF_FLAGS} -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u _target_/FUZZ -o _output_/_cleantarget_.json" -o $dir/.tmp/fuzzing 2>>"$LOGFILE" >/dev/null
				for sub in $(cat webs/webs_all.txt); do
					sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
					[ -s "$dir/.tmp/fuzzing/${sub_out}.json" ] && cat $dir/.tmp/fuzzing/${sub_out}.json | jq -r 'try .results[] | "\(.status) \(.length) \(.url)"' | sort -k1 | anew -q $dir/fuzzing/${sub_out}.txt
				done
				find $dir/fuzzing/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | sort -k1 | anew -q $dir/fuzzing/fuzzing_full.txt
			else
				axiom-exec "mkdir -p /home/op/lists/seclists/Discovery/Web-Content/" &>/dev/null
				axiom-exec "wget -q -O - ${fuzzing_remote_list} > /home/op/lists/fuzz_wordlist.txt" &>/dev/null
				axiom-exec "wget -q -O - ${fuzzing_remote_list} > /home/op/lists/seclists/Discovery/Web-Content/big.txt" &>/dev/null
				axiom-scan webs/webs_all.txt -m ffuf_base -H "${HEADER}" $FFUF_FLAGS -s -maxtime $FFUF_MAXTIME -o $dir/.tmp/ffuf-content.json $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
				for sub in $(cat webs/webs_all.txt); do
					sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
					[ -s "$dir/.tmp/ffuf-content.json" ] && cat .tmp/ffuf-content.json | jq -r 'try .results[] | "\(.status) \(.length) \(.url)"' | grep $sub | sort -k1 | anew -q fuzzing/${sub_out}.txt
				done
				find $dir/fuzzing/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | sort -k1 | anew -q $dir/fuzzing/fuzzing_full.txt
			fi
			end_func "Results are saved in $domain/fuzzing/*subdomain*.txt" ${FUNCNAME[0]}
		else
			end_func "No $domain/web/webs.txts file found, fuzzing skipped " ${FUNCNAME[0]}
		fi
	else
		if [[ $FUZZ == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function iishortname() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $IIS_SHORTNAME == true ]]; then
		start_func ${FUNCNAME[0]} "IIS Shortname Scanner"
		[ -s "nuclei_output/info.txt" ] && cat nuclei_output/info.txt | grep "iis-version" | cut -d " " -f4 > .tmp/iis_sites.txt
		if [[ -s ".tmp/iis_sites.txt" ]]; then
			mkdir -p $$dir/vulns/iis-shortname-shortscan/
			mkdir -p $$dir/vulns/iis-shortname-sns/
			interlace -tL .tmp/iis_sites.txt -threads ${INTERLACE_THREADS} -c "shortscan _target_ -F -s -p 1 > _output_/_cleantarget_.txt" -o $dir/vulns/iis-shortname-shortscan/ 2>>"$LOGFILE" >/dev/null
			find $dir/vulns/iis-shortname-shortscan/ -type f -print0 | xargs --null grep -Z -L 'Vulnerable: Yes' | xargs --null rm
			interlace -tL .tmp/iis_sites.txt -threads ${INTERLACE_THREADS} -c "sns -u _target_ > _output_/_cleantarget_.txt" -o $dir/vulns/iis-shortname-sns/ 2>>"$LOGFILE" >/dev/null
			find $dir/vulns/iis-shortname-sns/ -type f -print0 | xargs --null grep -Z 'Target is not vulnerable' | xargs --null rm
			end_func "Results are saved in vulns/iis-shortname/" ${FUNCNAME[0]}
		else
			end_func "No IIS sites detected, iishortname check skipped " ${FUNCNAME[0]}
		fi
	else
		if [[ $IIS_SHORTNAME == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function cms_scanner() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CMS_SCANNER == true ]]; then
		start_func ${FUNCNAME[0]} "CMS Scanner"
		mkdir -p $dir/cms && rm -rf $dir/cms/*
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		if [[ -s "webs/webs_all.txt" ]]; then
			tr '\n' ',' <webs/webs_all.txt >.tmp/cms.txt 2>>"$LOGFILE"
			timeout -k 1m ${CMSSCAN_TIMEOUT}s python3 ${tools}/CMSeeK/cmseek.py -l .tmp/cms.txt --batch -r &>>"$LOGFILE"
			exit_status=$?
			if [[ ${exit_status} -eq 125 ]]; then
				echo "TIMEOUT cmseek.py - investigate manually for $dir" >>"$LOGFILE"
				end_func "TIMEOUT cmseek.py - investigate manually for $dir" ${FUNCNAME[0]}
				return
			elif [[ ${exit_status} -ne 0 ]]; then
				echo "ERROR cmseek.py - investigate manually for $dir" >>"$LOGFILE"
				end_func "ERROR cmseek.py - investigate manually for $dir" ${FUNCNAME[0]}
				return
			fi # otherwise Assume we have a successfully exited cmseek
			for sub in $(cat webs/webs_all.txt); do
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				cms_id=$(cat ${tools}/CMSeeK/Result/${sub_out}/cms.json 2>/dev/null | jq -r 'try .cms_id')
				if [[ -z $cms_id ]]; then
					rm -rf ${tools}/CMSeeK/Result/${sub_out}
				else
					mv -f ${tools}/CMSeeK/Result/${sub_out} $dir/cms/ 2>>"$LOGFILE"
				fi
			done
			end_func "Results are saved in $domain/cms/*subdomain* folder" ${FUNCNAME[0]}
		else
			end_func "No $domain/web/webs.txts file found, cms scanner skipped" ${FUNCNAME[0]}
		fi
	else
		if [[ $CMS_SCANNER == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function urlchecks() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_CHECK == true ]]; then
		start_func ${FUNCNAME[0]} "URL Extraction"
		mkdir -p js
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		if [[ -s "webs/webs_all.txt" ]]; then
			if [[ $AXIOM != true ]]; then
				if [[ $URL_CHECK_PASSIVE == true ]]; then
					if [[ $DEEP == true ]]; then
						cat webs/webs_all.txt | unfurl -u domains >.tmp/waymore_input.txt
						python3 ${tools}/waymore/waymore.py -i .tmp/waymore_input.txt -mode U -f -oU .tmp/url_extract_tmp.txt 2>>"$LOGFILE" >/dev/null
					else
						cat webs/webs_all.txt | gau --threads $GAU_THREADS | anew -q .tmp/url_extract_tmp.txt
					fi
					if [[ -s ${GITHUB_TOKENS} ]]; then
						github-endpoints -q -k -d $domain -t ${GITHUB_TOKENS} -o .tmp/github-endpoints.txt 2>>"$LOGFILE" >/dev/null
						[ -s ".tmp/github-endpoints.txt" ] && cat .tmp/github-endpoints.txt | anew -q .tmp/url_extract_tmp.txt
					fi
				fi
				diff_webs=$(diff <(sort -u .tmp/probed_tmp.txt 2>>"$LOGFILE") <(sort -u webs/webs_all.txt 2>>"$LOGFILE") | wc -l)
				if [[ $diff_webs != "0" ]] || [[ ! -s ".tmp/katana.txt" ]]; then
					if [[ $URL_CHECK_ACTIVE == true ]]; then
						if [[ $DEEP == true ]]; then
							katana -silent -list webs/webs_all.txt -jc -kf all -c $KATANA_THREADS -d 3 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" >/dev/null
						else
							katana -silent -list webs/webs_all.txt -jc -kf all -c $KATANA_THREADS -d 2 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" >/dev/null
						fi
					fi
				fi
			else
				if [[ $URL_CHECK_PASSIVE == true ]]; then
					if [[ $DEEP == true ]]; then
						cat webs/webs_all.txt | unfurl -u domains >.tmp/waymore_input.txt
						axiom-scan .tmp/waymore_input.txt -m waymore -o .tmp/url_extract_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					else
						axiom-scan webs/webs_all.txt -m gau -o .tmp/url_extract_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					fi
					if [[ -s ${GITHUB_TOKENS} ]]; then
						github-endpoints -q -k -d $domain -t ${GITHUB_TOKENS} -o .tmp/github-endpoints.txt 2>>"$LOGFILE" >/dev/null
						[ -s ".tmp/github-endpoints.txt" ] && cat .tmp/github-endpoints.txt | anew -q .tmp/url_extract_tmp.txt
					fi
				fi
				diff_webs=$(diff <(sort -u .tmp/probed_tmp.txt) <(sort -u webs/webs_all.txt) | wc -l)
				if [[ $diff_webs != "0" ]] || [[ ! -s ".tmp/katana.txt" ]]; then
					if [[ $URL_CHECK_ACTIVE == true ]]; then
						if [[ $DEEP == true ]]; then
							axiom-scan webs/webs_all.txt -m katana -jc -kf all -d 3 -fs rdn -fs rdn -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
						else
							axiom-scan webs/webs_all.txt -m katana -jc -kf all -d 2 -fs rdn -fs rdn -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
						fi
					fi
				fi
			fi
			[ -s ".tmp/katana.txt" ] && sed -i '/^.\{2048\}./d' .tmp/katana.txt
			[ -s ".tmp/katana.txt" ] && cat .tmp/katana.txt | anew -q .tmp/url_extract_tmp.txt
			[ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | grep "${domain}" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | grep -aEi "\.(js)" | anew -q .tmp/url_extract_js.txt
			if [[ $DEEP == true ]]; then
				[ -s ".tmp/url_extract_js.txt" ] && interlace -tL .tmp/url_extract_js.txt -threads 10 -c "python3 ${tools}/JSA/jsa.py -f target | anew -q .tmp/url_extract_tmp.txt" &>/dev/null
			fi
			[ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | grep "${domain}" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | grep "=" | qsreplace -a 2>>"$LOGFILE" | grep -aEiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | anew -q .tmp/url_extract_tmp2.txt
			[ -s ".tmp/url_extract_tmp2.txt" ] && cat .tmp/url_extract_tmp2.txt | python3 ${tools}/urless/urless/urless.py | anew -q .tmp/url_extract_uddup.txt 2>>"$LOGFILE" >/dev/null
			NUMOFLINES=$(cat .tmp/url_extract_uddup.txt 2>>"$LOGFILE" | anew webs/url_extract.txt | sed '/^$/d' | wc -l)
			notification "${NUMOFLINES} new urls with params" info
			end_func "Results are saved in $domain/webs/url_extract.txt" ${FUNCNAME[0]}
			if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(cat webs/url_extract.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
				notification "Sending urls to proxy" info
				ffuf -mc all -w webs/url_extract.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" >/dev/null
			fi
		fi
	else
		if [[ $URL_CHECK == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function url_gf() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_GF == true ]]; then
		start_func ${FUNCNAME[0]} "Vulnerable Pattern Search"
		mkdir -p gf
		if [[ -s "webs/url_extract.txt" ]]; then
			gf xss webs/url_extract.txt | anew -q gf/xss.txt
			gf ssti webs/url_extract.txt | anew -q gf/ssti.txt
			gf ssrf webs/url_extract.txt | anew -q gf/ssrf.txt
			gf sqli webs/url_extract.txt | anew -q gf/sqli.txt
			gf redirect webs/url_extract.txt | anew -q gf/redirect.txt
			[ -s "gf/ssrf.txt" ] && cat gf/ssrf.txt | anew -q gf/redirect.txt
			gf rce webs/url_extract.txt | anew -q gf/rce.txt
			gf potential webs/url_extract.txt | cut -d ':' -f3-5 | anew -q gf/potential.txt
			[ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | grep -aEiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | unfurl -u format %s://%d%p 2>>"$LOGFILE" | anew -q gf/endpoints.txt
			gf lfi webs/url_extract.txt | anew -q gf/lfi.txt
		fi
		end_func "Results are saved in $domain/gf folder" ${FUNCNAME[0]}
	else
		if [[ $URL_GF == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function url_ext() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_EXT == true ]]; then
		if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
			start_func ${FUNCNAME[0]} "Urls by extension"
			ext=("7z" "achee" "action" "adr" "apk" "arj" "ascx" "asmx" "asp" "aspx" "axd" "backup" "bak" "bat" "bin" "bkf" "bkp" "bok" "cab" "cer" "cfg" "cfm" "cfml" "cgi" "cnf" "conf" "config" "cpl" "crt" "csr" "csv" "dat" "db" "dbf" "deb" "dmg" "dmp" "doc" "docx" "drv" "email" "eml" "emlx" "env" "exe" "gadget" "gz" "html" "ica" "inf" "ini" "iso" "jar" "java" "jhtml" "json" "jsp" "key" "log" "lst" "mai" "mbox" "mbx" "md" "mdb" "msg" "msi" "nsf" "ods" "oft" "old" "ora" "ost" "pac" "passwd" "pcf" "pdf" "pem" "pgp" "php" "php3" "php4" "php5" "phtm" "phtml" "pkg" "pl" "plist" "pst" "pwd" "py" "rar" "rb" "rdp" "reg" "rpm" "rtf" "sav" "sh" "shtm" "shtml" "skr" "sql" "swf" "sys" "tar" "tar.gz" "tmp" "toast" "tpl" "txt" "url" "vcd" "vcf" "wml" "wpd" "wsdl" "wsf" "xls" "xlsm" "xlsx" "xml" "xsd" "yaml" "yml" "z" "zip")
			#echo "" > webs/url_extract.txt
			for t in "${ext[@]}"; do
				NUMOFLINES=$(cat .tmp/url_extract_tmp.txt | grep -aEi "\.(${t})($|\/|\?)" | sort -u | sed '/^$/d' | wc -l)
				if [[ ${NUMOFLINES} -gt 0 ]]; then
					echo -e "\n############################\n + ${t} + \n############################\n" >>webs/urls_by_ext.txt
					cat .tmp/url_extract_tmp.txt | grep -aEi "\.(${t})($|\/|\?)" >>webs/urls_by_ext.txt
				fi
			done
			end_func "Results are saved in $domain/webs/urls_by_ext.txt" ${FUNCNAME[0]}
		fi
	else
		if [[ $URL_EXT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function jschecks() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $JSCHECKS == true ]]; then
		start_func ${FUNCNAME[0]} "Javascript Scan"
		if [[ -s ".tmp/url_extract_js.txt" ]]; then
			printf "${yellow} Running : Fetching Urls 1/5${reset}\n"
			if [[ $AXIOM != true ]]; then
				cat .tmp/url_extract_js.txt | subjs -ua "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -c 40 | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q .tmp/subjslinks.txt
			else
				axiom-scan .tmp/url_extract_js.txt -m subjs -o .tmp/subjslinks.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
			[ -s ".tmp/subjslinks.txt" ] && cat .tmp/subjslinks.txt | egrep -iv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)" | anew -q js/nojs_links.txt
			[ -s ".tmp/subjslinks.txt" ] && cat .tmp/subjslinks.txt | grep -iE "\.js($|\?)" | anew -q .tmp/url_extract_js.txt
			cat .tmp/url_extract_js.txt | python3 ${tools}/urless/urless/urless.py | anew -q js/url_extract_js.txt 2>>"$LOGFILE" >/dev/null
			printf "${yellow} Running : Resolving JS Urls 2/5${reset}\n"
			if [[ $AXIOM != true ]]; then
				[ -s "js/url_extract_js.txt" ] && cat js/url_extract_js.txt | httpx -follow-redirects -random-agent -silent -timeout $HTTPX_TIMEOUT -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -status-code -content-type -retries 2 -no-color | grep "[200]" | grep "javascript" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
			else
				[ -s "js/url_extract_js.txt" ] && axiom-scan js/url_extract_js.txt -m httpx -follow-host-redirects -H \"${HEADER}\" -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -content-type -retries 2 -no-color -o .tmp/js_livelinks.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
				[ -s ".tmp/js_livelinks.txt" ] && cat .tmp/js_livelinks.txt | anew .tmp/web_full_info.txt | grep "[200]" | grep "javascript" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
			fi
			printf "${yellow} Running : Gathering endpoints 3/5${reset}\n"
			[ -s "js/js_livelinks.txt" ] && python3 ${tools}/xnLinkFinder/xnLinkFinder.py -i js/js_livelinks.txt -sf subdomains/subdomains.txt -d $XNLINKFINDER_DEPTH -o .tmp/js_endpoints.txt 2>>"$LOGFILE" >/dev/null
			[ -s "parameters.txt" ] && rm -f parameters.txt 2>>"$LOGFILE" >/dev/null
			if [[ -s ".tmp/js_endpoints.txt" ]]; then
				sed -i '/^\//!d' .tmp/js_endpoints.txt
				cat .tmp/js_endpoints.txt | anew -q js/js_endpoints.txt
			fi
			printf "${yellow} Running : Gathering secrets 4/5${reset}\n"

			if [[ $AXIOM != true ]]; then
				[ -s "js/js_livelinks.txt" ] && cat js/js_livelinks.txt | mantra -ua ${HEADER} -s | anew -q js/js_secrets.txt
			else
				[ -s "js/js_livelinks.txt" ] && axiom-scan js/js_livelinks.txt -m mantra -ua \"${HEADER}\" -s -o js/js_secrets.txt $AXIOM_EXTRA_ARGS &>/dev/null
				[ -s "js/js_secrets.txt" ] && trufflehog filesystem js/js_secrets.txt -j | jq -c | anew -q js/js_secrets_trufflehog.txt
			fi
			[ -s "js/js_secrets.txt" ] && sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g" -i js/js_secrets.txt
			printf "${yellow} Running : Building wordlist 5/5${reset}\n"
			[ -s "js/js_livelinks.txt" ] && interlace -tL js/js_livelinks.txt -threads ${INTERLACE_THREADS} -c "python3 ${tools}/getjswords.py '_target_' | anew -q webs/dict_words.txt" 2>>"$LOGFILE" >/dev/null
			end_func "Results are saved in $domain/js folder" ${FUNCNAME[0]}
		else
			end_func "No JS urls found for $domain, function skipped" ${FUNCNAME[0]}
		fi
	else
		if [[ $JSCHECKS == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function wordlist_gen() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WORDLIST == true ]]; then
		start_func ${FUNCNAME[0]} "Wordlist generation"
		if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
			cat .tmp/url_extract_tmp.txt | unfurl -u keys 2>>"$LOGFILE" | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q webs/dict_params.txt
			cat .tmp/url_extract_tmp.txt | unfurl -u values 2>>"$LOGFILE" | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q webs/dict_values.txt
			cat .tmp/url_extract_tmp.txt | tr "[:punct:]" "\n" | anew -q webs/dict_words.txt
		fi
		[ -s ".tmp/js_endpoints.txt" ] && cat .tmp/js_endpoints.txt | unfurl -u format %s://%d%p 2>>"$LOGFILE" | anew -q webs/all_paths.txt
		[ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | unfurl -u format %s://%d%p 2>>"$LOGFILE" | anew -q webs/all_paths.txt
		end_func "Results are saved in $domain/webs/dict_[words|paths].txt" ${FUNCNAME[0]}
		if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(cat webs/all_paths.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
			notification "Sending urls to proxy" info
			ffuf -mc all -w webs/all_paths.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" >/dev/null
		fi
	else
		if [[ $WORDLIST == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function wordlist_gen_roboxtractor() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $ROBOTSWORDLIST == true ]]; then
		start_func ${FUNCNAME[0]} "Robots wordlist generation"
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		if [[ -s "webs/webs_all.txt" ]]; then
			cat webs/webs_all.txt | roboxtractor -m 1 -wb 2>/dev/null | anew -q webs/robots_wordlist.txt
		fi
		end_func "Results are saved in $domain/webs/robots_wordlist.txt" ${FUNCNAME[0]}
	else
		if [[ $ROBOTSWORDLIST == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function password_dict() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PASSWORD_DICT == true ]]; then
		start_func ${FUNCNAME[0]} "Password dictionary generation"
		word=${domain%%.*}
		python3 ${tools}/pydictor/pydictor.py -extend $word --leet 0 1 2 11 21 --len ${PASSWORD_MIN_LENGTH} ${PASSWORD_MAX_LENGTH} -o webs/password_dict.txt 2>>"$LOGFILE" >/dev/null
		end_func "Results are saved in $domain/webs/password_dict.txt" ${FUNCNAME[0]}
	else
		if [[ $PASSWORD_DICT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}
