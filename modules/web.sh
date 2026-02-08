#!/bin/bash
# shellcheck disable=SC2154  # Variables defined in reconftw.cfg
# reconFTW - Web analysis module
# Contains: webprobe_simple, webprobe_full, screenshot, virtualhosts, favicon,
#           portscan, cdnprovider, waf_checks, nuclei_check, graphql_scan,
#           param_discovery, grpc_reflection, fuzz, iishortname, cms_scanner,
#           urlchecks, url_gf, url_ext, jschecks, websocket_checks,
#           wordlist_gen, wordlist_gen_roboxtractor, password_dict, brokenLinks
# This file is sourced by reconftw.sh - do not execute directly
[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by reconftw.sh" >&2
    exit 1
}

###############################################################################
# Helper Functions for Web Module
###############################################################################

# Run httpx probe on input file
# Usage: _run_httpx input_file output_file [extra_flags...]
_run_httpx() {
    local input="$1"
    local output="$2"
    shift 2
    local extra_flags=("$@")
    
    if [[ $AXIOM != true ]]; then
        # shellcheck disable=SC2086  # HTTPX_FLAGS intentionally word-split
        httpx $HTTPX_FLAGS -no-color -json -random-agent \
            "${extra_flags[@]}" \
            -o "$output" <"$input" 2>>"$LOGFILE" >/dev/null
    else
        # shellcheck disable=SC2086  # HTTPX_FLAGS intentionally word-split
        axiom-scan "$input" -m httpx $HTTPX_FLAGS -no-color -json -random-agent \
            "${extra_flags[@]}" \
            -o "$output" "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
    fi
}

# Process httpx JSON output: extract URLs and web info
# Usage: _process_httpx_output json_file url_output info_output
_process_httpx_output() {
    local json_file="$1"
    local url_output="$2"
    local info_output="$3"
    
    [[ ! -s "$json_file" ]] && return 0
    
    # Extract URLs
    jq -r 'try .url' "$json_file" 2>/dev/null \
        | grep "$domain" \
        | grep -aEo 'https?://[^ ]+' \
        | sed 's/*.//' \
        | anew -q "$url_output"
    
    # Extract plain web info
    jq -r 'try . | "\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' "$json_file" \
        | grep "$domain" \
        | anew -q "$info_output"
}

# Send URLs to proxy if enabled
# Usage: _send_to_proxy urls_file
_send_to_proxy() {
    local urls_file="$1"
    local max_urls="${2:-$DEEP_LIMIT2}"
    
    if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ -s "$urls_file" ]]; then
        local count
        count=$(wc -l < "$urls_file" | tr -d ' ')
        if [[ $count -le $max_urls ]]; then
            notification "Sending websites to proxy" "info"
            ffuf -mc all -w "$urls_file" -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
        fi
    fi
}

###############################################################################
# Main Web Functions  
###############################################################################

function webprobe_simple() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs subdomains; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBPROBESIMPLE == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: HTTP probing $domain"

        # If in multi mode and subdomains.txt doesn't exist, create it
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
            touch .tmp/web_full_info.txt webs/web_full_info.txt
        fi

        # Run httpx or axiom-scan
        if [[ $AXIOM != true ]]; then
            # shellcheck disable=SC2086  # HTTPX_FLAGS intentionally word-split
            httpx $HTTPX_FLAGS -no-color -json -random-agent -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" \
                -retries 2 -timeout "$HTTPX_TIMEOUT" -o .tmp/web_full_info_probe.txt \
                <subdomains/subdomains.txt 2>>"$LOGFILE" >/dev/null
        else
            # shellcheck disable=SC2086  # HTTPX_FLAGS intentionally word-split
            axiom-scan subdomains/subdomains.txt -m httpx $HTTPX_FLAGS -no-color -json -random-agent \
                -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -retries 2 -timeout "$HTTPX_TIMEOUT" \
                -o .tmp/web_full_info_probe.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
        fi

        # Merge web_full_info files
        cat .tmp/web_full_info.txt 2>>"$LOGFILE" \
            | jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"$LOGFILE" >webs/web_full_info.txt

        # Extract URLs
        if [[ -s "webs/web_full_info.txt" ]]; then
            jq -r 'try .url' webs/web_full_info.txt 2>/dev/null \
                | grep "$domain" \
                | grep -aEo 'https?://[^ ]+' \
                | sed 's/*.//' | anew -q .tmp/probed_tmp.txt
        fi

        # Adaptive throttling heuristics: mark slow hosts (429/403) from httpx
        if [[ -s "webs/web_full_info.txt" ]]; then
            jq -r 'try select(.status_code==403 or .status_code==429) | .url' webs/web_full_info.txt 2>/dev/null \
                | awk -F/ '{print $3}' | sed 's/\:$//' | sort -u >.tmp/slow_hosts.txt
        fi

        # Extract web info to plain text
        if [[ -s "webs/web_full_info.txt" ]]; then
            jq -r 'try . |"\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' webs/web_full_info.txt \
                | grep "$domain" | anew -q webs/web_full_info_plain.txt
        fi

        # Remove out-of-scope entries
        if [[ -s $outOfScope_file ]]; then
            if ! deleteOutScoped "$outOfScope_file" .tmp/probed_tmp.txt; then
                printf "%b[!] Failed to delete out-of-scope entries.%b\n" "$bred" "$reset"
            fi
        fi

        touch .tmp/probed_tmp.txt

        # Count new websites
        if ! NUMOFLINES=$(anew webs/webs.txt <.tmp/probed_tmp.txt 2>/dev/null | sed '/^$/d' | wc -l); then
            printf "%b[!] Failed to count new websites.%b\n" "$bred" "$reset"
            NUMOFLINES=0
        fi

        # Update webs_all.txt
        cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt

        # Asset store: append probed webs
        append_assets_from_file web url webs/webs.txt

        end_subfunc "${NUMOFLINES} new websites resolved" "${FUNCNAME[0]}"

        # Send websites to proxy if conditions met
        if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/webs.txt) -le $DEEP_LIMIT2 ]]; then
            notification "Sending websites to proxy" "info"
            ffuf -mc all -w webs/webs.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
        fi

    else
        if [[ $WEBPROBESIMPLE == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

    # Emit plugin event
    plugins_emit after_webprobe "$domain" "$dir"

}

function webprobe_full() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs subdomains; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBPROBEFULL == true ]]; then
        start_func "${FUNCNAME[0]}" "HTTP Probing Non-Standard Ports"

        # If in multi mode and subdomains.txt doesn't exist, create it
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
            touch webs/webs.txt
        fi

        # Check if subdomains.txt is non-empty
        if [[ -s "subdomains/subdomains.txt" ]]; then
    if [[ $AXIOM != true ]]; then
        # Run httpx on subdomains.txt
        run_command httpx -follow-host-redirects -random-agent -status-code \
            -p "$UNCOMMON_PORTS_WEB" -threads "$HTTPX_UNCOMMONPORTS_THREADS" \
            -timeout "$HTTPX_UNCOMMONPORTS_TIMEOUT" -silent -retries 2 \
            -title -web-server -tech-detect -location -no-color -json \
            -o .tmp/web_full_info_uncommon.txt <subdomains/subdomains.txt 2>>"$LOGFILE" >/dev/null
    else
        # Run axiom-scan with httpx module on subdomains.txt
        run_command axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects \
            -H "${HEADER}" -status-code -p "$UNCOMMON_PORTS_WEB" \
            -threads "$HTTPX_UNCOMMONPORTS_THREADS" -timeout "$HTTPX_UNCOMMONPORTS_TIMEOUT" \
            -silent -retries 2 -title -web-server -tech-detect -location -no-color -json \
            -o .tmp/web_full_info_uncommon.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
    fi
        fi

        # Process web_full_info_uncommon.txt
        if [[ -s ".tmp/web_full_info_uncommon.txt" ]]; then
            # Extract URLs
            jq -r 'try .url' .tmp/web_full_info_uncommon.txt 2>/dev/null \
                | grep "$domain" \
                | grep -aEo 'https?://[^ ]+' \
                | sed 's/*.//' \
                | anew -q .tmp/probed_uncommon_ports_tmp.txt

            # Extract plain web info
            jq -r 'try . | "\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' .tmp/web_full_info_uncommon.txt \
                | grep "$domain" \
                | anew -q webs/web_full_info_uncommon_plain.txt

            # Update webs_full_info_uncommon.txt based on whether domain is IP
            if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | anew -q webs/web_full_info_uncommon.txt
            else
                grep "$domain" .tmp/web_full_info_uncommon.txt | anew -q webs/web_full_info_uncommon.txt
            fi

            # Count new websites
            if ! NUMOFLINES=$(anew webs/webs_uncommon_ports.txt <.tmp/probed_uncommon_ports_tmp.txt | sed '/^$/d' | wc -l); then
                printf "%b[!] Failed to count new websites.%b\n" "$bred" "$reset"
                NUMOFLINES=0
            fi

            # Notify user
            notification "Uncommon web ports: ${NUMOFLINES} new websites" "good"

            # Display new uncommon ports websites
            if [[ -s "webs/webs_uncommon_ports.txt" ]]; then
                cat "webs/webs_uncommon_ports.txt"
            fi

            # Update webs_all.txt
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt

            # Send to proxy if conditions met
            if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/webs_uncommon_ports.txt) -le $DEEP_LIMIT2 ]]; then
                notification "Sending websites with uncommon ports to proxy" "info"
                ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
            fi
        fi
        end_func "Results are saved in $domain/webs/webs_uncommon_ports.txt" "${FUNCNAME[0]}"
    else
        if [[ $WEBPROBEFULL == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function screenshot() {

    # Create necessary directories
    if ! ensure_dirs webs screenshots; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBSCREENSHOT == true ]]; then
        start_func "${FUNCNAME[0]}" "Web Screenshots"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
        fi

        # Run nuclei or axiom-scan based on AXIOM flag
        if [[ $AXIOM != true ]]; then
            if [[ -s "webs/webs_all.txt" ]]; then
                nuclei -headless -id screenshot -V dir='screenshots' <webs/webs_all.txt 2>>"$LOGFILE"
            fi
        else
            if [[ -s "webs/webs_all.txt" ]]; then
                axiom-scan webs/webs_all.txt -m nuclei-screenshots -o screenshots "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi
        fi
        end_func "Results are saved in $domain/screenshots" "${FUNCNAME[0]}"
    else
        if [[ $WEBSCREENSHOT == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function virtualhosts() {

    # Create necessary directories
    if ! ensure_dirs .tmp/virtualhosts virtualhosts webs; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $VIRTUALHOSTS == true ]]; then
        start_func "${FUNCNAME[0]}" "Virtual Hosts Discovery"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
        fi

        # Proceed only if webs_all.txt exists and is non-empty
        if [[ -s "subdomains/subdomains.txt" ]] && [[ -s "hosts/ips.txt" ]]; then
            VhostFinder -ips hosts/ips.txt -wordlist subdomains/subdomains.txt -verify | grep "+" | anew -q "$dir/webs/virtualhosts.txt"
            end_func "Results are saved in $domain/webs/virtualhosts.txt" "${FUNCNAME[0]}"

        else
            end_func "No subdomains or hosts file found, virtualhosts skipped." "${FUNCNAME[0]}"
        fi

        # Optionally send to proxy if conditions are met
        if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/webs_uncommon_ports.txt) -le $DEEP_LIMIT2 ]]; then
            notification "Sending websites with uncommon ports to proxy" "info"
            ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
        fi

    else
        if [[ $VIRTUALHOSTS == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
        fi
    fi

}

###############################################################################################################
############################################# HOST SCAN #######################################################
###############################################################################################################

function favicon() {

    # Create necessary directories
    if ! ensure_dirs hosts .tmp/virtualhosts; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } \
        && [[ $FAVICON == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Favicon IP Lookup"

        # Navigate to the fav-up tool directory
        if ! pushd "${tools}/fav-up" >/dev/null; then
            printf "%b[!] Failed to change directory to %s in %s @ line %s.%b\n" \
                "$bred" "${tools}/fav-up" "${FUNCNAME[0]}" "${LINENO}" "$reset"
            return 1
        fi

        # Run the favicon IP lookup tool
        timeout 10m "${tools}/fav-up/venv/bin/python3" "${tools}/fav-up/favUp.py" -w "$domain" -sc -o favicontest.json 2>>"$LOGFILE" >/dev/null

        # Process the results if favicontest.json exists and is not empty
        if [[ -s "favicontest.json" ]]; then
            jq -r 'try .found_ips' favicontest.json 2>>"$LOGFILE" \
                | grep -v "not-found" >favicontest.txt

            # Replace '|' with newlines
            sed_i "s/|/\n/g" favicontest.txt

            # Move the processed IPs to the hosts directory
            mv favicontest.txt "$dir/hosts/favicontest.txt" 2>>"$LOGFILE"

            # Remove the JSON file
            rm -f favicontest.json 2>>"$LOGFILE"
        fi

        # Return to the original directory
        if ! popd >/dev/null; then
            printf "%b[!] Failed to return to the previous directory in %s @ line %s.%b\n" \
                "$bred" "${FUNCNAME[0]}" "${LINENO}" "$reset"
        fi

        end_func "Results are saved in hosts/favicontest.txt" "${FUNCNAME[0]}"

    else
        if [[ $FAVICON == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Domain is an IP, do nothing
            return
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi

}

function portscan() {

    # Create necessary directories
    if ! ensure_dirs .tmp subdomains hosts webs; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PORTSCANNER == true ]]; then
        start_func "${FUNCNAME[0]}" "Port scan"

        # Determine if domain is IP address or domain name
        if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Not an IP address
            if [[ -s "subdomains/subdomains_ips.txt" ]]; then
                cut -d ' ' -f3 subdomains/subdomains_ips.txt \
                    | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." \
                    | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" \
                    | anew -q hosts/ips.txt
            fi

        else
            # Domain is an IP address
            printf "%b\n" "$domain" \
                | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." \
                | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
                | anew -q hosts/ips.txt || true
        fi

        # Check for CDN providers
        if [[ ! -s "hosts/cdn_providers.txt" ]]; then
            if [[ -s "hosts/ips.txt" ]]; then
                cat hosts/ips.txt | cdncheck -silent -resp -cdn -waf -nc 2>/dev/null | anew -q hosts/cdn_providers.txt || true
            fi
        fi

        if [[ -s "hosts/ips.txt" ]]; then
            # Remove CDN IPs
            comm -23 <(sort -u hosts/ips.txt) <(cut -d'[' -f1 hosts/cdn_providers.txt | sed 's/[[:space:]]*$//' | sort -u) \
                | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
                | sort -u | anew -q .tmp/ips_nocdn.txt || true
        fi

        # Display resolved IPs without CDN
        ips_nocdn_count=0
        if [[ -s ".tmp/ips_nocdn.txt" ]]; then
            ips_nocdn_count=$(sort -u ".tmp/ips_nocdn.txt" | wc -l | tr -d ' ')
        fi

        printf "%b\n[%s] Resolved IP addresses (No CDN): %s%b\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$ips_nocdn_count" "$reset"
        if ((ips_nocdn_count > 0)); then
            sort -u ".tmp/ips_nocdn.txt"
        else
            printf "None\n"
        fi
        printf "\n"

        printf "%b\n[%s] Scanning ports...%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"

        ips_file="${dir}/hosts/ips.txt"

        # Discover IPv6 addresses from DNS JSON if enabled
        if [[ $IPV6_SCAN == true ]]; then
            if [[ -s "subdomains/subdomains_dnsregs.json" ]]; then
                jq -r '.. | strings | select(test("^[0-9a-fA-F:]+$"))' <"subdomains/subdomains_dnsregs.json" \
                    | grep -v '\\.' | sort -u | anew -q hosts/ips_v6.txt || true
            fi
            # Add target if it's an IPv6 literal
            if [[ $domain =~ : ]]; then echo "$domain" | anew -q hosts/ips_v6.txt || true; fi
        fi

        if [[ $PORTSCAN_PASSIVE == true ]]; then
            if [[ ! -f $ips_file ]]; then
                printf "%b[!] File %s does not exist.%b\n" "$bred" "$ips_file" "$reset"
            else
                json_array=()
                while IFS= read -r cip; do
                    if ! json_result=$(curl -s "https://internetdb.shodan.io/${cip}"); then
                        printf "%b[!] Failed to retrieve data for IP %s.%b\n" "$bred" "$cip" "$reset"
                    else
                        json_array+=("$json_result")
                    fi
                done <"$ips_file"
                formatted_json="["
                for ((i = 0; i < ${#json_array[@]}; i++)); do
                    formatted_json+="$(echo "${json_array[i]}" | tr -d '\n')"
                    if [ $i -lt $((${#json_array[@]} - 1)) ]; then
                        formatted_json+=", "
                    fi
                done
                formatted_json+="]"
                if ! echo "$formatted_json" >"${dir}/hosts/portscan_shodan.txt"; then
                    printf "%b[!] Failed to write portscan_shodan.txt.%b\n" "$bred" "$reset"
                fi
            fi
        fi

        if [[ $PORTSCAN_PASSIVE == true ]] && [[ ! -f "hosts/portscan_passive.txt" ]] && [[ -s ".tmp/ips_nocdn.txt" ]]; then
            smap -iL .tmp/ips_nocdn.txt >hosts/portscan_passive.txt
        fi

        if [[ $PORTSCAN_ACTIVE == true ]]; then
            # Split PORTSCAN_ACTIVE_OPTIONS safely even with IFS set to \n\t
            local portscan_opts=()
            if declare -p PORTSCAN_ACTIVE_OPTIONS 2>/dev/null | grep -q 'declare -a'; then
                portscan_opts=("${PORTSCAN_ACTIVE_OPTIONS[@]}")
            elif [[ -n "${PORTSCAN_ACTIVE_OPTIONS:-}" ]]; then
                local _ifs="$IFS"
                IFS=' '
                read -r -a portscan_opts <<<"$PORTSCAN_ACTIVE_OPTIONS"
                IFS="$_ifs"
            fi

            if [[ $AXIOM != true ]]; then
                if [[ -s ".tmp/ips_nocdn.txt" ]]; then
                    run_command $SUDO nmap "${portscan_opts[@]}" -iL .tmp/ips_nocdn.txt -oA hosts/portscan_active 2>>"$LOGFILE" >/dev/null
                fi
                if [[ $IPV6_SCAN == true && -s "hosts/ips_v6.txt" ]]; then
                    run_command $SUDO nmap -6 "${portscan_opts[@]}" -iL hosts/ips_v6.txt -oA hosts/portscan_active_v6 2>>"$LOGFILE" >/dev/null
                fi
            else
                if [[ -s ".tmp/ips_nocdn.txt" ]]; then
                    run_command axiom-scan .tmp/ips_nocdn.txt -m nmapx "${portscan_opts[@]}" \
                        -oA hosts/portscan_active "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
                fi
            fi
        fi

        if [[ -s "hosts/portscan_active.xml" ]]; then
            nmapurls <hosts/portscan_active.xml 2>>"$LOGFILE" | anew -q hosts/webs.txt
        fi
        if [[ -s "hosts/portscan_active_v6.xml" ]]; then
            nmapurls <hosts/portscan_active_v6.xml 2>>"$LOGFILE" | anew -q hosts/webs_v6.txt
            [[ -s hosts/webs_v6.txt ]] && cat hosts/webs_v6.txt | anew -q webs/webs.txt
        fi

        if [[ $FARADAY == true ]]; then
            # Check if the Faraday server is running
            if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
                printf "%b[!] Faraday server is not running. Skipping Faraday integration.%b\n" "$bred" "$reset"
            else
                if [[ -s "hosts/portscan_active.xml" ]]; then
                    faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nmap hosts/portscan_active.xml 2>>"$LOGFILE" >/dev/null
                fi
            fi
        fi

        if [[ -s "hosts/webs.txt" ]]; then
            if ! NUMOFLINES=$(wc -l <hosts/webs.txt); then
                printf "%b[!] Failed to count lines in hosts/webs.txt.%b\n" "$bred" "$reset"
                NUMOFLINES=0
            fi
            notification "Webs detected from port scan: ${NUMOFLINES} new websites" "good"
            cat hosts/webs.txt
            append_assets_from_file web url hosts/webs.txt
        fi

        end_func "Results are saved in hosts/portscan_[passive|active|shodan].[txt|xml]" "${FUNCNAME[0]}"

    else
        if [[ $PORTSCANNER == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
        fi
    fi

}

function cdnprovider() {

    # Create necessary directories
    if ! ensure_dirs .tmp subdomains hosts; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } \
        && [[ $CDN_IP == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "CDN Provider Check"

        # Check if subdomains_dnsregs.json exists and is not empty
        if [[ -s "subdomains/subdomains_ips.txt" ]]; then
            cut -d ' ' -f3 subdomains/subdomains_ips.txt \
                | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." \
                | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" \
                | anew -q hosts/ips.txt
        fi

        # Check if ips_cdn.txt exists and is not empty
        if [[ -s "hosts/ips.txt" ]]; then
            # Run cdncheck on the IPs and save to cdn_providers.txt
            cdncheck -silent -resp -nc <hosts/ips.txt | anew -q "$dir/hosts/cdn_providers.txt"
        fi

        end_func "Results are saved in hosts/cdn_providers.txt" "${FUNCNAME[0]}"

    else
        if [[ $CDN_IP == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Domain is an IP, do nothing
            return
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi

}

###############################################################################################################
############################################# WEB SCAN ########################################################
###############################################################################################################

function waf_checks() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WAF_DETECTION == true ]]; then
        start_func "${FUNCNAME[0]}" "Website's WAF Detection"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
        fi

        # Proceed only if webs_all.txt exists and is non-empty
        if [[ -s "webs/webs_all.txt" ]]; then
            if [[ $AXIOM != true ]]; then
                # Run wafw00f on webs_all.txt
                wafw00f -i "webs/webs_all.txt" -o ".tmp/wafs.txt" 2>>"$LOGFILE" >/dev/null
            else
                # Run axiom-scan with wafw00f module on webs_all.txt
                axiom-scan "webs/webs_all.txt" -m wafw00f -o ".tmp/wafs.txt" "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi

            # Process wafs.txt if it exists and is not empty
            if [[ -s ".tmp/wafs.txt" ]]; then
                # Format the wafs.txt file
                sed -e 's/^[ \t]*//' -e 's/ \+ /\t/g' -e '/(None)/d' ".tmp/wafs.txt" | tr -s "\t" ";" >"webs/webs_wafs.txt"

                # Count the number of websites protected by WAF
                if ! NUMOFLINES=$(sed '/^$/d' "webs/webs_wafs.txt" 2>>"$LOGFILE" | wc -l); then
                    printf "%b[!] Failed to count lines in webs_wafs.txt.%b\n" "$bred" "$reset"
                    NUMOFLINES=0
                fi

                # Send a notification about the number of WAF-protected websites
                notification "${NUMOFLINES} websites protected by WAF" "info"

                # End the function with a success message
                end_func "Results are saved in webs/webs_wafs.txt" "${FUNCNAME[0]}"
            else
                # End the function indicating no results were found
                end_func "No results found" "${FUNCNAME[0]}"
            fi
        else
            # End the function indicating there are no websites to scan
            end_func "No websites to scan" "${FUNCNAME[0]}"
        fi
    else
        # Handle cases where WAF_DETECTION is false or the function has already been processed
        if [[ $WAF_DETECTION == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Domain is an IP address; skip the function
            return
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

# Prepare WAF-aware target lists for nuclei scanning
# Splits webs into WAF-protected and non-WAF lists for rate-limiting
# Sets: WAF_LIST, NOWAF_LIST variables
_nuclei_prepare_waf_lists() {
    WAF_LIST=.tmp/webs_waf.txt
    NOWAF_LIST=.tmp/webs_nowaf.txt

    sort -u .tmp/webs_subs.txt -o .tmp/webs_subs.txt 2>/dev/null || true
    : >"$WAF_LIST"
    : >"$NOWAF_LIST"

    if [[ -s webs/webs_wafs.txt ]]; then
        cut -d';' -f1 webs/webs_wafs.txt | sed 's/https\?:\/\///' | sed 's/\/$//' | sort -u >.tmp/waf_hosts.txt
        awk -F/ '{print $3}' .tmp/webs_subs.txt | sed 's/\:$//' | while read -r host; do
            if grep -Fxq "$host" .tmp/waf_hosts.txt; then
                awk -v h="$host" -F/ '{u=$3; sub(/:.*/,"",u); if (u==h) print $0}' .tmp/webs_subs.txt | anew -q "$WAF_LIST"
            else
                awk -v h="$host" -F/ '{u=$3; sub(/:.*/,"",u); if (u==h) print $0}' .tmp/webs_subs.txt | anew -q "$NOWAF_LIST"
            fi
        done
    else
        cp .tmp/webs_subs.txt "$NOWAF_LIST"
    fi

    # Include slow hosts (429/403) into WAF list as well
    if [[ -s .tmp/slow_hosts.txt ]]; then
        while read -r host; do
            awk -v h="$host" -F/ '{u=$3; sub(/:.*/,"",u); if (u==h) print $0}' .tmp/webs_subs.txt | anew -q "$WAF_LIST"
        done <.tmp/slow_hosts.txt
    fi
}

# Parse nuclei JSON output to human-readable text and display results
# Usage: _nuclei_parse_results severity_level
_nuclei_parse_results() {
    local crit="$1"
    if [[ -s "nuclei_output/${crit}_json.txt" ]]; then
        jq -r '["[" + .["template-id"] + (if .["matcher-name"] != null then ":" + .["matcher-name"] else "" end) + "] [" + .["type"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host) + (if .["extracted-results"] != null then " " + (.["extracted-results"] | @json) else "" end)] | .[]' nuclei_output/${crit}_json.txt >nuclei_output/${crit}.txt
        append_assets_from_file finding value nuclei_output/${crit}.txt
        if [[ -s "nuclei_output/${crit}.txt" ]]; then
            cat "nuclei_output/${crit}.txt"
        fi
    fi
}

# Run nuclei scan locally with WAF-aware rate limiting
# Usage: _nuclei_scan_local
_nuclei_scan_local() {
    IFS=',' read -ra severity_array <<<"$NUCLEI_SEVERITY"

    for crit in "${severity_array[@]}"; do
        printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Nuclei Severity: $crit ${reset}\n\n"
        # Non-WAF at default rate
        if [[ -s $NOWAF_LIST ]]; then
            run_command nuclei -l "$NOWAF_LIST" -severity "$crit" -nh -rl "$NUCLEI_RATELIMIT" -silent -retries 2 ${NUCLEI_EXTRA_ARGS} -t ${NUCLEI_TEMPLATES_PATH} -j -o "nuclei_output/${crit}_json.txt" 2>>"$LOGFILE" >/dev/null
        fi
        # WAF hosts at slower rate
        if [[ -s $WAF_LIST ]]; then
            local slow_rl
            slow_rl=$((NUCLEI_RATELIMIT / 3 + 1))
            run_command nuclei -l "$WAF_LIST" -severity "$crit" -nh -rl "$slow_rl" -silent -retries 2 ${NUCLEI_EXTRA_ARGS} -t ${NUCLEI_TEMPLATES_PATH} -j -o "nuclei_output/${crit}_waf_json.txt" 2>>"$LOGFILE" >/dev/null
            [[ -s nuclei_output/${crit}_waf_json.txt ]] && cat nuclei_output/${crit}_waf_json.txt >>nuclei_output/${crit}_json.txt
        fi
        _nuclei_parse_results "$crit"
    done
    printf "\n\n"
}

# Run nuclei scan via Axiom distributed fleet
# Usage: _nuclei_scan_axiom
_nuclei_scan_axiom() {
    IFS=',' read -ra severity_array <<<"$NUCLEI_SEVERITY"

    for crit in "${severity_array[@]}"; do
        printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Axiom Nuclei Severity: $crit. Check results in nuclei_output folder.${reset}\n\n"
        run_command axiom-scan .tmp/webs_subs.txt -m nuclei \
            --nuclei-templates "$NUCLEI_TEMPLATES_PATH" \
            -severity "$crit" -nh -rl "$NUCLEI_RATELIMIT" \
            -silent -retries 2 "$NUCLEI_EXTRA_ARGS" -j -o "nuclei_output/${crit}_json.txt" "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
        _nuclei_parse_results "$crit"
    done
    printf "\n\n"
}

function nuclei_check() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs subdomains nuclei_output; then return 1; fi

    # Check if the function should run
    if should_run "NUCLEICHECK"; then
        start_func "${FUNCNAME[0]}" "Templates-based Web Scanner"
        maybe_update_nuclei

        # Handle multi mode and initialize subdomains.txt if necessary
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
            touch webs/webs.txt webs/webs_uncommon_ports.txt
        fi

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
        fi

        # Combine webs_all.txt targets (with protocol) - avoid duplicate scans
        if [[ ! -s ".tmp/webs_subs.txt" ]]; then
            cat webs/webs_all.txt 2>>"$LOGFILE" | sort -u >.tmp/webs_subs.txt
        fi

        # Prepare WAF-aware lists and run scans
        _nuclei_prepare_waf_lists

        if [[ $AXIOM != true ]]; then
            _nuclei_scan_local
        else
            _nuclei_scan_axiom
        fi

        # Faraday integration
        if [[ $FARADAY == true ]]; then
            if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
                printf "%b[!] Faraday server is not running. Skipping Faraday integration.%b\n" "$bred" "$reset"
            else
                # Report all severity levels to Faraday
                IFS=',' read -ra severity_array <<<"$NUCLEI_SEVERITY"
                for crit in "${severity_array[@]}"; do
                    if [[ -s "nuclei_output/${crit}_json.txt" ]]; then
                        faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nuclei "nuclei_output/${crit}_json.txt" 2>>"$LOGFILE" >/dev/null
                    fi
                done
            fi
        fi

        end_func "Results are saved in $domain/nuclei_output folder" "${FUNCNAME[0]}"
        plugins_emit after_nuclei "$domain" "$dir"
    else
        if [[ $NUCLEICHECK == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function graphql_scan() {
    # Reuse nuclei_check findings for GraphQL detection and optional introspection
    ensure_dirs .tmp webs nuclei_output vulns/graphql

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GRAPHQL_CHECK == true ]]; then
        start_func "${FUNCNAME[0]}" "GraphQL detection"

        : >nuclei_output/graphql_json.txt
        : >.tmp/graphql_endpoints.txt
        IFS=',' read -ra severity_array <<<"$NUCLEI_SEVERITY"

        for crit in "${severity_array[@]}"; do
            local src_json="nuclei_output/${crit}_json.txt"
            if [[ -s "$src_json" ]]; then
                jq -c 'select(."template-id" == "graphql-detect")' "$src_json" \
                    | tee -a nuclei_output/graphql_json.txt \
                    | jq -r '.["matched-at"] // .host // empty' \
                    | sed '/^$/d' \
                    | sort -u \
                    | anew -q .tmp/graphql_endpoints.txt
            fi
        done

        if [[ -s nuclei_output/graphql_json.txt ]]; then
            jq -r '["[" + .["template-id"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host)] | .[]' nuclei_output/graphql_json.txt >nuclei_output/graphql.txt
        else
            printf "%b[%s] No graphql-detect findings in nuclei_check outputs; skipping GraphQL deep checks.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset" | tee -a "$LOGFILE"
        fi

        # Optionally run GQLSpection on endpoints discovered by nuclei_check (graphql-detect)
        if [[ $GQLSPECTION == true ]] && [[ -s .tmp/graphql_endpoints.txt ]]; then
            while read -r ep; do
                [[ -z $ep ]] && continue
                hostfile="vulns/graphql/$(echo "$ep" | sed 's|^[^/]*//||; s|/.*$||')"
                mkdir -p "$(dirname "$hostfile")" 2>>"$LOGFILE" || true
                gqlspection -t "$ep" -o "${hostfile}.json" 2>>"$LOGFILE" >/dev/null || true
            done <.tmp/graphql_endpoints.txt
        fi
        end_func "Results are saved in nuclei_output/graphql* and vulns/graphql" "${FUNCNAME[0]}"
    else
        if [[ $GRAPHQL_CHECK == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi
}

function param_discovery() {
    ensure_dirs webs .tmp

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PARAM_DISCOVERY == true ]]; then
        start_func "${FUNCNAME[0]}" "Parameter discovery (arjun)"
        local input_file="webs/url_extract_nodupes.txt"
        [[ ! -s $input_file ]] && input_file="webs/webs_all.txt"
        if [[ -s $input_file ]]; then
            arjun -i "$input_file" -t "$ARJUN_THREADS" -oJ .tmp/arjun.json 2>>"$LOGFILE" >/dev/null || true
            if [[ -s .tmp/arjun.json ]]; then
                jq -r '..|.url? // empty' .tmp/arjun.json | sed 's/^/URL: /' | anew -q webs/params_discovered.txt
                jq -r '..|.params? // empty | to_entries[] | .key' .tmp/arjun.json | sed 's/^/PARAM: /' | sort -u | anew -q webs/params_discovered.txt
            fi
        fi
        end_func "Results are saved in webs/params_discovered.txt" "${FUNCNAME[0]}"
    else
        if [[ $PARAM_DISCOVERY == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi
}

function grpc_reflection() {
    ensure_dirs hosts .tmp

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GRPC_SCAN == true ]]; then
        start_func "${FUNCNAME[0]}" "gRPC reflection probing"
        # Build target IP list
        local ips_file="hosts/ips.txt"
        local targets=()
        # shellcheck disable=SC2207  # Word splitting intended for array population
        [[ -s $ips_file ]] && targets+=($(cat "$ips_file"))
        # shellcheck disable=SC2207  # Word splitting intended for array population
        [[ -s "hosts/ips_v6.txt" ]] && targets+=($(cat "hosts/ips_v6.txt"))
        printf "%s\n" "${targets[@]}" | sort -u >.tmp/grpc_ips.txt
        if [[ -s .tmp/grpc_ips.txt ]]; then
            # Probe common plaintext gRPC ports
            while read -r ip; do
                for p in 50051 50052; do
                    grpcurl -plaintext -max-msg-sz 10485760 -d '{}' "$ip:$p" list 2>>"$LOGFILE" | sed "s/^/[$ip:$p] /" | anew -q hosts/grpc_reflection.txt || true
                done
            done <.tmp/grpc_ips.txt
        fi
        end_func "Results are saved in hosts/grpc_reflection.txt" "${FUNCNAME[0]}"
    else
        if [[ $GRPC_SCAN == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi
}

# Classify targets into normal and slow lists for adaptive fuzzing
_fuzz_classify_targets() {
    sort -u webs/webs_all.txt -o webs/webs_all.txt 2>/dev/null || true
    : >.tmp/webs_slow.txt
    : >.tmp/webs_normal.txt
    if [[ -s .tmp/slow_hosts.txt ]]; then
        while read -r host; do
            awk -v h="$host" -F/ '{u=$3; sub(/:.*/,"",u); if (u==h) print $0}' webs/webs_all.txt | anew -q .tmp/webs_slow.txt
        done <.tmp/slow_hosts.txt
        comm -23 <(sort -u webs/webs_all.txt) <(sort -u .tmp/webs_slow.txt) >.tmp/webs_normal.txt
    else
        cp webs/webs_all.txt .tmp/webs_normal.txt
    fi
}

# Run ffuf locally with interlace, handling normal and slow targets separately
_fuzz_run_local() {
    _fuzz_classify_targets

    if [[ -s .tmp/webs_normal.txt ]]; then
        interlace -tL .tmp/webs_normal.txt -threads ${INTERLACE_THREADS} -c "ffuf ${FFUF_FLAGS} -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u _target_/FUZZ -o _output_/_cleantarget_.json" -o "$dir/.tmp/fuzzing" 2>>"$LOGFILE" >/dev/null
    fi

    if [[ -s .tmp/webs_slow.txt ]]; then
        local slow_threads=$((FFUF_THREADS / 3))
        [[ $slow_threads -lt 5 ]] && slow_threads=5
        local slow_rate=$FFUF_RATELIMIT
        [[ ${FFUF_RATELIMIT:-0} -eq 0 ]] && slow_rate=50 || slow_rate=$((FFUF_RATELIMIT / 3 + 1))
        interlace -tL .tmp/webs_slow.txt -threads ${INTERLACE_THREADS} -c "ffuf ${FFUF_FLAGS} -t ${slow_threads} -rate ${slow_rate} -H \"${HEADER}\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u _target_/FUZZ -o _output_/_cleantarget_.json" -o "$dir/.tmp/fuzzing" 2>>"$LOGFILE" >/dev/null
    fi
}

# Run ffuf via axiom-scan and parse per-subdomain results
_fuzz_run_axiom() {
    cached_download_typed "${fuzzing_remote_list}" ".tmp/fuzzing_remote_list.txt" "onelistforallmicro.txt" "wordlists"
    axiom-scan webs/webs_all.txt -m ffuf -wL .tmp/fuzzing_remote_list.txt -H "${HEADER}" $FFUF_FLAGS -s -maxtime $FFUF_MAXTIME -oJ "$dir/.tmp/ffuf-content.json" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null

    while read -r sub; do
        local sub_out
        sub_out=$(echo "$sub" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
        [[ -s "$dir/.tmp/ffuf-content.json" ]] && jq -r 'try .results[] | "\(.status) \(.length) \(.url)"' "$dir/.tmp/ffuf-content.json" | grep "$sub" | sort -k1 | anew -q "fuzzing/${sub_out}.txt"
    done <webs/webs_all.txt
}

# Merge all per-subdomain fuzzing results into fuzzing_full.txt
_fuzz_merge_results() {
    find "$dir/fuzzing/" -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | sort -k1 | anew -q "$dir/fuzzing/fuzzing_full.txt"
}

function fuzz() {

    ensure_dirs .tmp/fuzzing webs fuzzing

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FUZZ == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Web Directory Fuzzing"

        # Handle multi mode initialization
        if [[ -n $multi ]] && [[ ! -f "$dir/webs/webs.txt" ]]; then
            printf "%b\n" "$domain" >"$dir/webs/webs.txt" || printf "%b[!] Failed to create webs.txt.%b\n" "$bred" "$reset"
            touch webs/webs_uncommon_ports.txt 2>>"$LOGFILE" || true
        fi

        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
        fi

        if [[ -s "webs/webs_all.txt" ]]; then
            if [[ $AXIOM != true ]]; then
                _fuzz_run_local
            else
                _fuzz_run_axiom
            fi
            _fuzz_merge_results
            end_func "Results are saved in $domain/fuzzing/*subdomain*.txt" "${FUNCNAME[0]}"
        else
            end_func "No $domain/webs/webs_all.txt file found, fuzzing skipped " "${FUNCNAME[0]}"
        fi

    else
        if [[ $FUZZ == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function iishortname() {

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $IIS_SHORTNAME == true ]]; then
        start_func "${FUNCNAME[0]}" "IIS Shortname Scanner"

        # Ensure nuclei_output/info.txt exists and is not empty
        if [[ -s "nuclei_output/info.txt" ]]; then
            # Extract IIS version information and save to .tmp/iis_sites.txt
            grep "iis-version" "nuclei_output/info.txt" | cut -d " " -f4 >.tmp/iis_sites.txt
        fi

        # Proceed only if iis_sites.txt exists and is non-empty
        if [[ -s ".tmp/iis_sites.txt" ]]; then
            # Create necessary directories
            mkdir -p "$dir/vulns/iis-shortname-shortscan/" "$dir/vulns/iis-shortname-sns/"

            # Run shortscan using interlace
            interlace -tL .tmp/iis_sites.txt -threads "$INTERLACE_THREADS" \
                -c "shortscan _target_ -F -s -p 1 > _output_/_cleantarget_.txt" \
                -o "$dir/vulns/iis-shortname-shortscan/" 2>>"$LOGFILE" >/dev/null

            # Remove non-vulnerable shortscan results
            while IFS= read -r -d '' file; do
                if ! grep -q 'Vulnerable: Yes' "$file" 2>/dev/null; then
                    rm -f "$file" 2>>"$LOGFILE"
                fi
            done < <(find "$dir/vulns/iis-shortname-shortscan/" -type f -iname "*.txt" -print0 2>/dev/null)

            # Run sns using interlace
            interlace -tL .tmp/iis_sites.txt -threads "$INTERLACE_THREADS" \
                -c "sns -u _target_ > _output_/_cleantarget_.txt" \
                -o "$dir/vulns/iis-shortname-sns/" 2>>"$LOGFILE" >/dev/null

            # Remove non-vulnerable sns results
            while IFS= read -r -d '' file; do
                if grep -q 'Target is not vulnerable' "$file" 2>/dev/null; then
                    rm -f "$file" 2>>"$LOGFILE"
                fi
            done < <(find "$dir/vulns/iis-shortname-sns/" -type f -iname "*.txt" -print0 2>/dev/null)

        fi
        end_func "Results are saved in vulns/iis-shortname/" "${FUNCNAME[0]}"
    else
        # Handle cases where IIS_SHORTNAME is false or the function has already been processed
        if [[ $IIS_SHORTNAME == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Domain is an IP address; skip the function
            return
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi

}

function cms_scanner() {

    # Create necessary directories
    if ! mkdir -p .tmp/fuzzing webs cms; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CMS_SCANNER == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "CMS Scanner"

        rm -rf "$dir/cms/"*

        # Handle multi mode and initialize webs.txt if necessary
        if [[ -n $multi ]] && [[ ! -f "$dir/webs/webs.txt" ]]; then
            printf "%b\n" "$domain" >"$dir/webs/webs.txt"
            touch webs/webs_uncommon_ports.txt
        fi

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
        fi

        # Combine webs_all.txt into .tmp/cms.txt as a comma-separated list
        if [[ -s "webs/webs_all.txt" ]]; then
            tr '\n' ',' <webs/webs_all.txt >.tmp/cms.txt 2>>"$LOGFILE"
        else
            end_func "No webs/webs_all.txt file found, cms scanner skipped." "${FUNCNAME[0]}"
            return
        fi

        # Run CMSeeK with timeout
        local cmseek_cmd=(
            timeout -k 1m "${CMSSCAN_TIMEOUT}s"
            "${tools}/CMSeeK/venv/bin/python3" "${tools}/CMSeeK/cmseek.py"
            -l .tmp/cms.txt --batch -r
        )
        local exit_status=0
        local log_start=0
        log_start=$(wc -l <"$LOGFILE" 2>/dev/null || echo 0)
        if ! "${cmseek_cmd[@]}" &>>"$LOGFILE"; then
            exit_status=$?
            # Attempt one-time repair on known CMSeeK index corruption.
            if tail -n +"$((log_start + 1))" "$LOGFILE" 2>/dev/null | grep -q "cmseekdb/createindex.py" \
                && tail -n +"$((log_start + 1))" "$LOGFILE" 2>/dev/null | grep -q "JSONDecodeError"; then
                log_note "cms_scanner: detected CMSeeK index corruption, repairing index and retrying once" "${FUNCNAME[0]}" "${LINENO}"
                find "${tools}/CMSeeK/Result" -type f -name "*.json" -size 0 -delete 2>>"$LOGFILE" || true
                if [[ -f "${tools}/CMSeeK/cmseekdb/createindex.py" ]]; then
                    "${tools}/CMSeeK/venv/bin/python3" "${tools}/CMSeeK/cmseekdb/createindex.py" &>>"$LOGFILE" || true
                fi
                if ! "${cmseek_cmd[@]}" &>>"$LOGFILE"; then
                    exit_status=$?
                else
                    exit_status=0
                fi
            fi

            if [[ ${exit_status} -eq 124 || ${exit_status} -eq 137 ]]; then
                echo "TIMEOUT cmseek.py - investigate manually for $dir" >>"$LOGFILE"
                end_func "TIMEOUT cmseek.py - investigate manually for $dir" "${FUNCNAME[0]}"
                return
            elif [[ ${exit_status} -ne 0 ]]; then
                echo "ERROR cmseek.py - investigate manually for $dir" >>"$LOGFILE"
                end_func "ERROR cmseek.py - investigate manually for $dir" "${FUNCNAME[0]}"
                return
            fi
        fi

        # Process CMSeeK results
        while IFS= read -r sub; do
            sub_out=$(echo "$sub" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
            cms_json_path="${tools}/CMSeeK/Result/${sub_out}/cms.json"

            if [[ -s $cms_json_path ]]; then
                cms_id=$(jq -r 'try .cms_id' "$cms_json_path")
                if [[ -n $cms_id ]]; then
                    mv -f "${tools}/CMSeeK/Result/${sub_out}" "$dir/cms/" 2>>"$LOGFILE"
                else
                    rm -rf "${tools}/CMSeeK/Result/${sub_out}" 2>>"$LOGFILE"
                fi
            fi
        done <"webs/webs_all.txt"

        end_func "Results are saved in $domain/cms/*subdomain* folder" "${FUNCNAME[0]}"
    else
        # Handle cases where CMS_SCANNER is false or the function has already been processed
        if [[ $CMS_SCANNER == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Domain is an IP address; skip the function
            return
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi
}

function urlchecks() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_CHECK == true ]]; then
        start_func "${FUNCNAME[0]}" "URL Extraction"

        # Combine webs.txt and webs_uncommon_ports.txt if webs_all.txt doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
        fi

        if [[ -s "webs/webs_all.txt" ]]; then

            if [[ $URL_CHECK_PASSIVE == true ]]; then
                urlfinder -d $domain -all -o .tmp/url_extract_tmp.txt 2>>"$LOGFILE" >/dev/null
                if command -v waymore &>/dev/null; then
                    if ! "$TIMEOUT_CMD" "${WAYMORE_TIMEOUT:-30m}" waymore -i "$domain" -mode U -oU .tmp/waymore_urls.txt 2>>"$LOGFILE" >/dev/null; then
                        log_note "urlchecks: waymore failed or timed out; continuing with other passive sources" "${FUNCNAME[0]}" "${LINENO}"
                    fi
                    if [[ -s ".tmp/waymore_urls.txt" ]]; then
                        cat .tmp/waymore_urls.txt | anew -q .tmp/url_extract_tmp.txt || true
                    fi
                else
                    log_note "urlchecks: waymore not found; skipping passive waymore collection" "${FUNCNAME[0]}" "${LINENO}"
                fi
                if [[ -s $GITHUB_TOKENS ]]; then
                    github-endpoints -q -k -d "$domain" -t "$GITHUB_TOKENS" -o .tmp/github-endpoints.txt 2>>"$LOGFILE" >/dev/null
                    if [[ -s ".tmp/github-endpoints.txt" ]]; then
                        cat .tmp/github-endpoints.txt | anew -q .tmp/url_extract_tmp.txt || true
                    fi
                fi
            fi

            if [[ $AXIOM != true ]]; then
                if [[ -s ".tmp/probed_tmp.txt" && -s "webs/webs_all.txt" ]]; then
                    diff_webs=$(comm -3 <(sort -u .tmp/probed_tmp.txt 2>>"$LOGFILE") <(sort -u webs/webs_all.txt 2>>"$LOGFILE") | wc -l)
                else
                    log_note "urlchecks: missing .tmp/probed_tmp.txt or webs/webs_all.txt; skipping diff" "${FUNCNAME[0]}" "${LINENO}"
                    diff_webs=1
                fi
                if [[ $diff_webs != "0" ]] || [[ ! -s ".tmp/katana.txt" ]]; then
                    if [[ $URL_CHECK_ACTIVE == true ]]; then
                        # Split slow vs normal targets based on httpx status (403/429)
                        : >.tmp/katana_targets_slow.txt
                        : >.tmp/katana_targets_normal.txt
                        if [[ -s .tmp/slow_hosts.txt ]]; then
                            while read -r host; do
                                grep "://${host}[:/\n]" webs/webs_all.txt | anew -q .tmp/katana_targets_slow.txt
                            done <.tmp/slow_hosts.txt
                            comm -23 <(sort -u webs/webs_all.txt) <(sort -u .tmp/katana_targets_slow.txt) >.tmp/katana_targets_normal.txt
                        else
                            cp webs/webs_all.txt .tmp/katana_targets_normal.txt
                        fi

                        : >.tmp/katana.txt
                        # Normal targets
                        if [[ -s .tmp/katana_targets_normal.txt ]]; then
                            LINES=$(wc -l <.tmp/katana_targets_normal.txt)
                            if [[ $LINES -gt ${CHUNK_LIMIT:-2000} ]]; then
                                if [[ $DEEP == true ]]; then
                                    process_in_chunks .tmp/katana_targets_normal.txt ${CHUNK_LIMIT:-2000} "katana -silent -list _chunk_ -jc -kf all -c $KATANA_THREADS -d 3 -fs rdn >> .tmp/katana.txt 2>>\"$LOGFILE\" >/dev/null"
                                else
                                    process_in_chunks .tmp/katana_targets_normal.txt ${CHUNK_LIMIT:-2000} "katana -silent -list _chunk_ -jc -kf all -c $KATANA_THREADS -d 2 -fs rdn >> .tmp/katana.txt 2>>\"$LOGFILE\""
                                fi
                            else
                                if [[ $DEEP == true ]]; then
                                    timeout 4h katana -silent -list .tmp/katana_targets_normal.txt -jc -kf all -c "$KATANA_THREADS" -d 3 -fs rdn >>.tmp/katana.txt 2>>"$LOGFILE"
                                else
                                    timeout 3h katana -silent -list .tmp/katana_targets_normal.txt -jc -kf all -c "$KATANA_THREADS" -d 2 -fs rdn >>.tmp/katana.txt 2>>"$LOGFILE"
                                fi
                            fi
                        fi

                        # Slow targets with reduced concurrency
                        if [[ -s .tmp/katana_targets_slow.txt ]]; then
                            slow_c=$((KATANA_THREADS / 3))
                            [[ $slow_c -lt 2 ]] && slow_c=2
                            LINES=$(wc -l <.tmp/katana_targets_slow.txt)
                            if [[ $LINES -gt ${CHUNK_LIMIT:-2000} ]]; then
                                if [[ $DEEP == true ]]; then
                                    process_in_chunks .tmp/katana_targets_slow.txt ${CHUNK_LIMIT:-2000} "katana -silent -list _chunk_ -jc -kf all -c $slow_c -d 3 -fs rdn >> .tmp/katana.txt 2>>\"$LOGFILE\""
                                else
                                    process_in_chunks .tmp/katana_targets_slow.txt ${CHUNK_LIMIT:-2000} "katana -silent -list _chunk_ -jc -kf all -c $slow_c -d 2 -fs rdn >> .tmp/katana.txt 2>>\"$LOGFILE\""
                                fi
                            else
                                if [[ $DEEP == true ]]; then
                                    timeout 4h katana -silent -list .tmp/katana_targets_slow.txt -jc -kf all -c "$slow_c" -d 3 -fs rdn >>.tmp/katana.txt 2>>"$LOGFILE"
                                else
                                    timeout 3h katana -silent -list .tmp/katana_targets_slow.txt -jc -kf all -c "$slow_c" -d 2 -fs rdn >>.tmp/katana.txt 2>>"$LOGFILE"
                                fi
                            fi
                        fi
                    fi
                fi
            else
                if [[ -s ".tmp/probed_tmp.txt" && -s "webs/webs_all.txt" ]]; then
                    diff_webs=$(comm -3 <(sort -u .tmp/probed_tmp.txt) <(sort -u webs/webs_all.txt) | wc -l)
                else
                    log_note "urlchecks: missing .tmp/probed_tmp.txt or webs/webs_all.txt; skipping diff" "${FUNCNAME[0]}" "${LINENO}"
                    diff_webs=1
                fi
                if [[ $diff_webs != "0" ]] || [[ ! -s ".tmp/katana.txt" ]]; then
                    if [[ $URL_CHECK_ACTIVE == true ]]; then
                        if [[ $DEEP == true ]]; then
                            axiom-scan webs/webs_all.txt -m katana -jc -kf all -d 3 -fs rdn --max-runtime 4h -o .tmp/katana.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
                        else
                            axiom-scan webs/webs_all.txt -m katana -jc -kf all -d 2 -fs rdn --max-runtime 3h -o .tmp/katana.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
                        fi
                    fi
                fi
            fi

            if [[ -s ".tmp/katana.txt" ]]; then
                sed_i '/^.\{2048\}./d' .tmp/katana.txt
                cat .tmp/katana.txt | anew -q .tmp/url_extract_tmp.txt || true
            fi

            if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
                grep -a "$domain" .tmp/url_extract_tmp.txt | grep -aEo 'https?://[^ ]+' | grep -iE '\.js([?#].*)?$|\.js([/?&].*)' | anew -q .tmp/url_extract_js.txt || true
                grep -a "$domain" .tmp/url_extract_tmp.txt | grep -aEo 'https?://[^ ]+' | grep -iE '\.map([/?#].*)?$' | anew -q .tmp/url_extract_jsmap.txt || true
                if [[ $DEEP == true ]] && [[ -s ".tmp/url_extract_js.txt" ]]; then
                    interlace -tL .tmp/url_extract_js.txt -threads 10 -c "${tools}/JSA/venv/bin/python3 ${tools}/JSA/jsa.py -f _target_ | anew -q .tmp/url_extract_tmp.txt" &>/dev/null
                fi

                grep -a "$domain" .tmp/url_extract_tmp.txt | grep -aEo 'https?://[^ ]+' | grep "=" | qsreplace -a 2>>"$LOGFILE" | grep -aEiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg)$" | anew -q .tmp/url_extract_tmp2.txt || true

                if [[ -s ".tmp/url_extract_tmp2.txt" ]]; then
                    urless <.tmp/url_extract_tmp2.txt | anew -q .tmp/url_extract_uddup.txt 2>>"$LOGFILE" >/dev/null || true
                fi

                if [[ -s ".tmp/url_extract_uddup.txt" ]]; then
                    if ! NUMOFLINES=$(anew webs/url_extract.txt <.tmp/url_extract_uddup.txt | sed '/^$/d' | wc -l); then
                        printf "%b[!] Failed to update url_extract.txt.%b\n" "$bred" "$reset"
                        NUMOFLINES=0
                    fi
                    notification "${NUMOFLINES} new URLs with parameters" "info"
                    # Asset store: append new URLs
                    append_assets_from_file url value webs/url_extract.txt
                else
                    NUMOFLINES=0
                fi

                end_func "Results are saved in $domain/webs/url_extract.txt" "${FUNCNAME[0]}"

                if [[ -s "webs/url_extract.txt" ]]; then
                    p1radup -i webs/url_extract.txt -o webs/url_extract_nodupes.txt -s 2>>"$LOGFILE" >/dev/null || true

                    if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/url_extract.txt) -le $DEEP_LIMIT2 ]]; then
                        notification "Sending URLs to proxy" "info"
                        ffuf -mc all -w webs/url_extract.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
                    fi
                else
                    printf "%b[%s] No URL extraction output generated; skipping p1radup/proxy replay.%b\n" \
                        "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset" | tee -a "$LOGFILE"
                fi
            fi
        fi
    else
        if [[ $URL_CHECK == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function url_gf() {

    # Create necessary directories
    if ! mkdir -p .tmp webs gf; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_GF == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Vulnerable Pattern Search"

        # Ensure webs/url_extract.txt exists and is not empty
        if [[ -s "webs/url_extract.txt" ]]; then
            # Define an array of GF patterns
            declare -A gf_patterns=(
                ["xss"]="gf/xss.txt"
                ["ssti"]="gf/ssti.txt"
                ["ssrf"]="gf/ssrf.txt"
                ["sqli"]="gf/sqli.txt"
                ["redirect"]="gf/redirect.txt"
                ["rce"]="gf/rce.txt"
                ["potential"]="gf/potential.txt"
                ["lfi"]="gf/lfi.txt"
            )

            # Iterate over GF patterns and process each
            for pattern in "${!gf_patterns[@]}"; do
                output_file="${gf_patterns[$pattern]}"
                printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: GF Pattern '$pattern'${reset}\n\n"
                if [[ $pattern == "potential" ]]; then
                    # Special handling for 'potential' pattern
                    gf "$pattern" "webs/url_extract.txt" | cut -d ':' -f3-5 | anew -q "$output_file"
                elif [[ $pattern == "redirect" && -s "gf/ssrf.txt" ]]; then
                    # Append SSFR results to redirect if ssrf.txt exists
                    gf "$pattern" "webs/url_extract.txt" | anew -q "$output_file"
                else
                    # General handling for other patterns
                    gf "$pattern" "webs/url_extract.txt" | anew -q "$output_file"
                fi
            done

            # Process endpoints extraction
            if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
                printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Extracting endpoints...${reset}\n\n"
                grep -aEiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" ".tmp/url_extract_tmp.txt" \
                    | unfurl -u format '%s://%d%p' 2>>"$LOGFILE" | anew -q "gf/endpoints.txt"
            fi

        else
            end_func "No webs/url_extract.txt file found, URL_GF check skipped." "${FUNCNAME[0]}"
            return
        fi

        end_func "Results are saved in $domain/gf folder" "${FUNCNAME[0]}"
    else
        # Handle cases where URL_GF is false or the function has already been processed
        if [[ $URL_GF == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Domain is an IP address; skip the function
            return
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi

}

function url_ext() {

    # Create necessary directories
    if ! mkdir -p .tmp webs gf; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_EXT == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
            start_func "${FUNCNAME[0]}" "Vulnerable Pattern Search"

            # Define an array of file extensions
            ext=("7z" "achee" "action" "adr" "apk" "arj" "ascx" "asmx" "asp" "aspx" "axd" "backup" "bak" "bat" "bin" "bkf" "bkp" "bok" "cab" "cer" "cfg" "cfm" "cnf" "conf" "config" "cpl" "crt" "csr" "csv" "dat" "db" "dbf" "deb" "dmg" "dmp" "doc" "docx" "drv" "email" "eml" "emlx" "env" "exe" "gadget" "gz" "html" "ica" "inf" "ini" "iso" "jar" "java" "jhtml" "json" "jsp" "key" "log" "lst" "mai" "mbox" "mbx" "md" "mdb" "msg" "msi" "nsf" "ods" "oft" "old" "ora" "ost" "pac" "passwd" "pcf" "pdf" "pem" "pgp" "php" "php3" "php4" "php5" "phtm" "phtml" "pkg" "pl" "plist" "pst" "pwd" "py" "rar" "rb" "rdp" "reg" "rpm" "rtf" "sav" "sh" "shtm" "shtml" "skr" "sql" "swf" "sys" "tar" "tar.gz" "tmp" "toast" "tpl" "txt" "url" "vcd" "vcf" "wml" "wpd" "wsdl" "wsf" "xls" "xlsm" "xlsx" "xml" "xsd" "yaml" "yml" "z" "zip")

            # Initialize the output file
            if ! : >webs/urls_by_ext.txt; then
                printf "%b[!] Failed to initialize webs/urls_by_ext.txt.%b\n" "$bred" "$reset"
            fi

            # Iterate over extensions and extract matching URLs
            for t in "${ext[@]}"; do

                # Extract unique matching URLs
                grep -aEi "\.(${t})($|/|\?)" ".tmp/url_extract_tmp.txt" 2>>"$LOGFILE" \
                    | sort -u \
                    | sed '/^$/d' >".tmp/urls_by_ext_${t}.tmp" || true

                NUMOFLINES=$(wc -l <".tmp/urls_by_ext_${t}.tmp" 2>/dev/null || echo 0)

                if [[ $NUMOFLINES -gt 0 ]]; then
                    printf "\n############################\n + %s + \n############################\n" "$t" >>webs/urls_by_ext.txt
                    cat ".tmp/urls_by_ext_${t}.tmp" >>webs/urls_by_ext.txt
                fi
            done

            # Append ssrf.txt to redirect.txt if ssrf.txt exists and is not empty
            if [[ -s "gf/ssrf.txt" ]]; then
                cat "gf/ssrf.txt" | anew -q "gf/redirect.txt" || true
            fi

            end_func "Results are saved in $domain/webs/urls_by_ext.txt" "${FUNCNAME[0]}"

        else
            end_func "No .tmp/url_extract_tmp.txt file found, URL_EXT check skipped." "${FUNCNAME[0]}"
        fi

    else
        # Handle cases where URL_EXT is false or function already processed
        if [[ $URL_EXT == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Domain is an IP address; skip the function
            return
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi

}

function jschecks() {

    # Create necessary directories
    if ! mkdir -p .tmp webs subdomains js; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $JSCHECKS == true ]]; then
        start_func "${FUNCNAME[0]}" "JavaScript Scan"

        # If .tmp/url_extract_js.txt doesn't exist, try to recover from previous run output
        if [[ ! -s ".tmp/url_extract_js.txt" ]] && [[ -s "js/url_extract_js.txt" ]]; then
            cat js/url_extract_js.txt | anew -q .tmp/url_extract_js.txt
        fi

        if [[ -s ".tmp/url_extract_js.txt" ]]; then

            printf "%bRunning: Fetching URLs 1/6%b\n" "$yellow" "$reset"
            if [[ $AXIOM != true ]]; then
                subjs -ua "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -c 40 <.tmp/url_extract_js.txt \
                    | grep -F "$domain" \
                    | grep -aEo 'https?://[^ ]+' | anew -q .tmp/subjslinks.txt || true
            else
                axiom-scan .tmp/url_extract_js.txt -m subjs -o .tmp/subjslinks.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi

                if [[ -s ".tmp/subjslinks.txt" ]]; then
                    grep -Eiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" .tmp/subjslinks.txt \
                        | anew -q js/nojs_links.txt || true
                    grep -iE '\.js([?#].*)?$|\.js([/?&].*)' .tmp/subjslinks.txt | anew -q .tmp/url_extract_js.txt || true
                fi

            urless <.tmp/url_extract_js.txt \
                | anew -q js/url_extract_js.txt 2>>"$LOGFILE" >/dev/null

            printf "%bRunning: Resolving JS URLs 2/6%b\n" "$yellow" "$reset"
            if [[ $AXIOM != true ]]; then
                if [[ -s "js/url_extract_js.txt" ]]; then
                    httpx -follow-redirects -random-agent -silent -timeout "$HTTPX_TIMEOUT" -threads "$HTTPX_THREADS" \
                        -rl "$HTTPX_RATELIMIT" -status-code -content-type -retries 2 -no-color <js/url_extract_js.txt \
                        | grep "[200]" | grep "javascript" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
                fi
            else
                if [[ -s "js/url_extract_js.txt" ]]; then
                    axiom-scan js/url_extract_js.txt -m httpx -follow-host-redirects -H "$HEADER" -status-code \
                        -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" -silent \
                        -content-type -retries 2 -no-color -o .tmp/js_livelinks.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
                    if [[ -s ".tmp/js_livelinks.txt" ]]; then
                        cat .tmp/js_livelinks.txt | anew .tmp/web_full_info.txt \
                            | grep "[200]" | grep "javascript" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt || true
                    fi
                fi
            fi

            printf "%bRunning: Extracting JS from sourcemaps 3/6%b\n" "$yellow" "$reset"
            if ! mkdir -p .tmp/sourcemapper; then
                printf "%b[!] Failed to create sourcemapper directory.%b\n" "$bred" "$reset"
            fi
            if [[ -s "js/js_livelinks.txt" ]]; then
                interlace -tL js/js_livelinks.txt -threads "$INTERLACE_THREADS" \
                    -c "sourcemapper -jsurl '_target_' -output _output_/_cleantarget_" \
                    -o .tmp/sourcemapper 2>>"$LOGFILE" >/dev/null
            fi

            if [[ -s ".tmp/url_extract_jsmap.txt" ]]; then
                interlace -tL .tmp/url_extract_jsmap.txt -threads "$INTERLACE_THREADS" \
                    -c "sourcemapper -url '_target_' -output _output_/_cleantarget_" \
                    -o .tmp/sourcemapper 2>>"$LOGFILE" >/dev/null
            fi

            find .tmp/sourcemapper/ \( -name "*.js" -o -name "*.ts" \) -type f \
                | jsluice urls | jq -r .url | anew -q .tmp/js_endpoints.txt || true

            printf "%bRunning: Gathering endpoints 4/6%b\n" "$yellow" "$reset"
            if [[ -s "js/js_livelinks.txt" ]]; then
                xnLinkFinder -i js/js_livelinks.txt -sf subdomains/subdomains.txt -d "$XNLINKFINDER_DEPTH" \
                    -o .tmp/js_endpoints.txt 2>>"$LOGFILE" >/dev/null
            fi

            if [[ -s ".tmp/js_endpoints.txt" ]]; then
                sed_i '/^\//!d' .tmp/js_endpoints.txt
                cat .tmp/js_endpoints.txt | anew -q js/js_endpoints.txt || true
            fi

            printf "%bRunning: Gathering secrets 5/6%b\n" "$yellow" "$reset"
            if [[ -s "js/js_livelinks.txt" ]]; then
                if [[ $AXIOM != true ]]; then
                    cat js/js_livelinks.txt | mantra -ua \"$HEADER\" -s | anew -q js/js_secrets.txt 2>>"$LOGFILE" >/dev/null || true
                else
                    axiom-exec "go install github.com/Brosck/mantra@latest" 2>>"$LOGFILE" >/dev/null
                    axiom-scan js/js_livelinks.txt -m mantra -ua "$HEADER" -s -o js/js_secrets.txt "$AXIOM_EXTRA_ARGS" &>/dev/null
                fi
                mkdir -p .tmp/sourcemapper/secrets
                if [[ -s "js/js_secrets.txt" ]]; then
                    while IFS= read -r i; do
                        [[ -z "$i" ]] && continue
                        wget -q -P .tmp/sourcemapper/secrets -- "$i" || true
                    done < <(cut -d' ' -f2 js/js_secrets.txt)
                fi
                trufflehog filesystem .tmp/sourcemapper/ -j 2>/dev/null | jq -c | anew -q js/js_secrets_jsmap.txt
                find .tmp/sourcemapper/ -type f -name "*.js" | jsluice secrets -j --patterns="${tools}/jsluice_patterns.json" | anew -q js/js_secrets_jsmap_jsluice.txt
            fi

            printf "%bRunning: Building wordlist 6/6%b\n" "$yellow" "$reset"
            if [[ -s "js/js_livelinks.txt" ]]; then
                if [[ -n "${GETJSWORDS_VENV:-}" ]]; then
                    if [[ -f "${GETJSWORDS_VENV}/bin/activate" ]]; then
                        (
                            # shellcheck source=/dev/null
                            source "${GETJSWORDS_VENV}/bin/activate"
                            if python3 -c "import jsbeautifier, requests" 2>/dev/null; then
                                interlace -tL js/js_livelinks.txt -threads "$INTERLACE_THREADS" \
                                    -c "python3 ${tools}/getjswords.py '_target_' | anew -q webs/dict_words.txt" 2>>"$LOGFILE" >/dev/null
                            else
                                log_note "jschecks: jsbeautifier/requests missing in venv ${GETJSWORDS_VENV}; skipping getjswords wordlist step" "${FUNCNAME[0]}" "${LINENO}"
                            fi
                            deactivate || true
                        )
                    else
                        log_note "GETJSWORDS_VENV invalid: ${GETJSWORDS_VENV}; skipping getjswords wordlist step" "${FUNCNAME[0]}" "${LINENO}"
                    fi
                else
                    local getjs_py="${GETJSWORDS_PYTHON:-python3}"
                    if ! command -v "$getjs_py" >/dev/null 2>&1; then
                        log_note "getjswords python not found: ${getjs_py}; skipping wordlist step" "${FUNCNAME[0]}" "${LINENO}"
                    elif "$getjs_py" -c "import jsbeautifier, requests" 2>/dev/null; then
                        interlace -tL js/js_livelinks.txt -threads "$INTERLACE_THREADS" \
                            -c "${getjs_py} ${tools}/getjswords.py '_target_' | anew -q webs/dict_words.txt" 2>>"$LOGFILE" >/dev/null
                    else
                        log_note "jschecks: jsbeautifier/requests missing in ${getjs_py}; skipping getjswords wordlist step" "${FUNCNAME[0]}" "${LINENO}"
                    fi
                fi
            fi
            end_func "Results are saved in $domain/js folder" "${FUNCNAME[0]}"
        else
            end_func "No JS files to process" "${FUNCNAME[0]}"
        fi
    else
        if [[ $JSCHECKS == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function websocket_checks() {
    mkdir -p webs vulns .tmp

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_CHECK == true ]]; then
        start_func "${FUNCNAME[0]}" "WebSocket discovery and handshake"
        # Collect ws/wss endpoints from JS endpoints and URLs
        touch .tmp/ws_endpoints_raw.txt
        [[ -s js/js_endpoints.txt ]] && grep -aEo 'wss?://[^ ]+' js/js_endpoints.txt | anew -q .tmp/ws_endpoints_raw.txt || true
        [[ -s webs/url_extract.txt ]] && grep -aEo 'wss?://[^ ]+' webs/url_extract.txt | anew -q .tmp/ws_endpoints_raw.txt || true
        if [[ -s .tmp/ws_endpoints_raw.txt ]]; then
            # Normalize and de-dup
            cat .tmp/ws_endpoints_raw.txt | sed 's/\"//g' | sed 's/[\]\[ ]//g' | sort -u >.tmp/ws_endpoints.txt
            # Handshake test and origin check
            while IFS= read -r ws; do
                [[ -z $ws ]] && continue
                url_no_proto=$(echo "$ws" | sed 's|^wss\?://||')
                host=$(echo "$url_no_proto" | cut -d'/' -f1)
                # Prepare Sec-WebSocket headers for accurate handshake
                wskey=$(head -c 16 /dev/urandom | base64 2>/dev/null || echo dGVzdGtleQ==)
                code=$(curl -sk --http1.1 -o /dev/null -w '%{http_code}' \
                    -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
                    -H "Host: $host" \
                    -H "Sec-WebSocket-Key: $wskey" \
                    -H 'Sec-WebSocket-Version: 13' \
                    "$ws" || true)
                if [[ $code == "101" ]]; then
                    printf "HANDSHAKE %s\n" "$ws" | anew -q vulns/websockets.txt || true
                    # Origin test: send a cross-origin header, expect failure ideally
                    wskey2=$(head -c 16 /dev/urandom | base64 2>/dev/null || echo dGVzdGtleQ==)
                    code2=$(curl -sk --http1.1 -o /dev/null -w '%{http_code}' \
                        -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
                        -H "Origin: https://evil.example" -H "Host: $host" \
                        -H "Sec-WebSocket-Key: $wskey2" \
                        -H 'Sec-WebSocket-Version: 13' \
                        "$ws" || true)
                    if [[ $code2 == "101" ]]; then
                        printf "ORIGIN-ALLOWED %s\n" "$ws" | anew -q vulns/websocket_misconfig.txt || true
                    fi
                fi
            done <.tmp/ws_endpoints.txt
        fi
        end_func "Results are saved in vulns/websocket_misconfig.txt" "${FUNCNAME[0]}"
    else
        printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped or already processed.${reset}\n"
    fi
}

function wordlist_gen() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WORDLIST == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Wordlist Generation"

        [[ -s ".tmp/url_extract_tmp.txt" ]] && cat webs/url_extract.txt | anew -q .tmp/url_extract_tmp.txt
        # Ensure url_extract_tmp.txt exists and is not empty
        if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
            # Define patterns for keys and values
            cat ".tmp/url_extract_tmp.txt" | unfurl -u keys 2>>"$LOGFILE" \
                | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' \
                | anew -q webs/dict_keys.txt

            cat ".tmp/url_extract_tmp.txt" | unfurl -u values 2>>"$LOGFILE" \
                | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' \
                | anew -q webs/dict_values.txt

            printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Extracting words...${reset}\n"
            tr "[:punct:]" "\n" <".tmp/url_extract_tmp.txt" | anew -q "webs/dict_words.txt"
        fi

        end_func "Results are saved in $domain/webs/dict_[words|paths].txt" "${FUNCNAME[0]}"

    else
        # Handle cases where WORDLIST is false or function already processed
        if [[ $WORDLIST == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Domain is an IP address; skip the function
            return
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi

}

function wordlist_gen_roboxtractor() {

    # Create necessary directories
    if ! mkdir -p .tmp webs gf; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $ROBOTSWORDLIST == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Robots Wordlist Generation"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Proceed only if webs_all.txt exists and is non-empty
        if [[ -s "webs/webs_all.txt" ]]; then
            # Extract URLs using roboxtractor and append unique entries to robots_wordlist.txt
            printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Roboxtractor for Robots Wordlist${reset}\n\n"
            roboxtractor -m 1 -wb <"webs/webs_all.txt" 2>>"$LOGFILE" | anew -q "webs/robots_wordlist.txt"
        else
            end_func "No webs/webs_all.txt file found, Robots Wordlist generation skipped." "${FUNCNAME[0]}"
            return
        fi

        end_func "Results are saved in $domain/webs/robots_wordlist.txt" "${FUNCNAME[0]}"

        # Handle Proxy if conditions are met
        if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ "$(wc -l <"webs/robots_wordlist.txt")" -le $DEEP_LIMIT2 ]]; then
            notification "Sending URLs to proxy" info
            ffuf -mc all -w "webs/robots_wordlist.txt" -u "FUZZ" -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
        fi

    else
        # Handle cases where ROBOTSWORDLIST is false or function already processed
        if [[ $ROBOTSWORDLIST == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Domain is an IP address; skip the function
            return
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi

}

function password_dict() {

    # Create necessary directories
    if ! mkdir -p "$dir/webs"; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PASSWORD_DICT == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Password Dictionary Generation"

        # Extract the first part of the domain
        word="${domain%%.*}"

        # Run pydictor.py with specified parameters
        python3 "${tools}/pydictor/pydictor.py" -extend "$word" --leet 0 1 2 11 21 --len "$PASSWORD_MIN_LENGTH" "$PASSWORD_MAX_LENGTH" -o "$dir/webs/password_dict.txt" 2>>"$LOGFILE" >/dev/null
        end_func "Results are saved in $domain/webs/password_dict.txt" "${FUNCNAME[0]}"

        # Optionally, create a marker file to indicate the function has been processed
        touch "$called_fn_dir/.${FUNCNAME[0]}"

    else
        # Handle cases where PASSWORD_DICT is false or function already processed
        if [[ $PASSWORD_DICT == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Domain is an IP address; skip the function
            return
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi

}

###############################################################################################################
######################################### VULNERABILITIES #####################################################
###############################################################################################################

function brokenLinks() {

    # Create necessary directories
    if ! mkdir -p .tmp webs vulns; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $BROKENLINKS == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Broken Links Checks"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Check if webs_all.txt exists and is not empty
        if [[ -s "webs/webs_all.txt" ]]; then
            if [[ $AXIOM != true ]]; then
                # Use katana for scanning
                if [[ ! -s ".tmp/katana.txt" ]]; then
                    if [[ $DEEP == true ]]; then
                        timeout 4h katana -silent -list "webs/webs_all.txt" -jc -kf all -c "$KATANA_THREADS" -d 3 -o ".tmp/katana.txt" 2>>"$LOGFILE" >/dev/null
                    else
                        timeout 3h katana -silent -list "webs/webs_all.txt" -jc -kf all -c "$KATANA_THREADS" -d 2 -o ".tmp/katana.txt" 2>>"$LOGFILE" >/dev/null
                    fi
                fi
                # Remove lines longer than 2048 characters
                if [[ -s ".tmp/katana.txt" ]]; then
                    sed_i '/^.\{2048\}./d' ".tmp/katana.txt"
                fi
            else
                # Use axiom-scan for scanning
                if [[ ! -s ".tmp/katana.txt" ]]; then
                    if [[ $DEEP == true ]]; then
                        axiom-scan "webs/webs_all.txt" -m katana -jc -kf all -d 3 --max-runtime 4h -o ".tmp/katana.txt" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
                    else
                        axiom-scan "webs/webs_all.txt" -m katana -jc -kf all -d 2 --max-runtime 3h -o ".tmp/katana.txt" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
                    fi
                    # Remove lines longer than 2048 characters
                    if [[ -s ".tmp/katana.txt" ]]; then
                        sed_i '/^.\{2048\}./d' ".tmp/katana.txt"
                    fi
                fi
            fi

            # Process katana.txt to find broken links
            if [[ -s ".tmp/katana.txt" ]]; then
                httpx -follow-redirects -random-agent -status-code -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" -silent -retries 2 -no-color <".tmp/katana.txt" 2>>"$LOGFILE" \
                    | grep "\[4" | cut -d ' ' -f1 | anew -q ".tmp/brokenLinks_total.txt"
            fi

            # Update brokenLinks.txt with unique entries
            if [[ -s ".tmp/brokenLinks_total.txt" ]]; then
                NUMOFLINES=$(wc -l <".tmp/brokenLinks_total.txt" 2>>"$LOGFILE" | awk '{print $1}')
                cat .tmp/brokenLinks_total.txt | anew -q "vulns/brokenLinks.txt"
                NUMOFLINES=$(sed '/^$/d' "vulns/brokenLinks.txt" | wc -l)
                notification "${NUMOFLINES} new broken links found" info
            fi

            end_func "Results are saved in vulns/brokenLinks.txt" "${FUNCNAME[0]}"
        else
            end_func "No webs/webs_all.txt file found, Broken Links check skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        # Handle cases where BROKENLINKS is false or function already processed
        if [[ $BROKENLINKS == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Domain is an IP address; skip the function
            return
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}
