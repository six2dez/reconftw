#!/bin/bash
# shellcheck disable=SC2154  # Variables defined in reconftw.cfg
# reconFTW - Web analysis module
# Contains: webprobe_simple, webprobe_full, screenshot, virtualhosts,
#           favirecon_tech,
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
        run_command httpx $HTTPX_FLAGS -no-color -json -random-agent \
            "${extra_flags[@]}" \
            -o "$output" <"$input" 2>>"$LOGFILE" >/dev/null
    else
        # shellcheck disable=SC2086  # HTTPX_FLAGS intentionally word-split
        run_command axiom-scan "$input" -m httpx $HTTPX_FLAGS -no-color -json -random-agent \
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
        | anew_q_safe "$url_output"

    # Extract plain web info
    jq -r 'try . | "\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' "$json_file" \
        | grep "$domain" \
        | anew_q_safe "$info_output"
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
            run_command ffuf -mc all -w "$urls_file" -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
        fi
    fi
}

# Display summary of discovered webs
print_webs_summary() {
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    local webs_file="webs/webs_all.txt"
    [[ -s "$webs_file" ]] || webs_file="webs/webs.txt"
    [[ -s "$webs_file" ]] || return 0

    sort -u "$webs_file" -o "$webs_file" 2>/dev/null || true
    local web_count
    web_count=$(wc -l <"$webs_file" | tr -d ' ')
    print_artifacts "${web_count} hosts -> ${webs_file}"
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

	        # Baseline cache files (some modules merge into these).
	        touch .tmp/web_full_info.txt .tmp/web_full_info_probe.txt webs/web_full_info.txt webs/webs.txt 2>/dev/null || true

	        # If in multi mode and subdomains.txt doesn't exist, create it
	        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
	            printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
	            touch .tmp/web_full_info.txt webs/web_full_info.txt
	        fi

        # Run httpx or axiom-scan
        if [[ $AXIOM != true ]]; then
            # shellcheck disable=SC2086  # HTTPX_FLAGS intentionally word-split
            run_command httpx $HTTPX_FLAGS -no-color -json -random-agent -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" \
                -retries 2 -timeout "$HTTPX_TIMEOUT" -o .tmp/web_full_info_probe.txt \
                <subdomains/subdomains.txt 2>>"$LOGFILE" >/dev/null
        else
            # shellcheck disable=SC2086  # HTTPX_FLAGS intentionally word-split
            run_command axiom-scan subdomains/subdomains.txt -m httpx $HTTPX_FLAGS -no-color -json -random-agent \
                -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -retries 2 -timeout "$HTTPX_TIMEOUT" \
                -o .tmp/web_full_info_probe.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
	        fi

		        # webprobe_simple is expected to write JSONL when using httpx -json.
		        # Some runners (or wrappers) may produce a plain URL list instead.
		        # Detect the format early to avoid jq parse errors and missing webs/webs.txt.
		        local probe_first_line probe_is_json
		        probe_first_line="$(awk 'NF {print; exit}' .tmp/web_full_info_probe.txt 2>/dev/null || true)"
		        probe_is_json=false
		        [[ "$probe_first_line" =~ ^[[:space:]]*\\{ ]] && probe_is_json=true

		        # Always start fresh for this run (used by urlchecks diff too).
		        : >.tmp/probed_tmp.txt 2>/dev/null || true

		        if [[ "$probe_is_json" == true ]]; then
		            # Merge current probe output with prior cache/state.
		            touch .tmp/web_full_info_probe.txt .tmp/web_full_info.txt 2>/dev/null || true
		            if ! cat .tmp/web_full_info_probe.txt .tmp/web_full_info.txt 2>>"$LOGFILE" \
		                | jq -cs 'unique_by(.input)[]' 2>>"$LOGFILE" >webs/web_full_info.txt; then
		                log_note "webprobe_simple: failed to merge httpx JSON; falling back to probe-only" "${FUNCNAME[0]}" "${LINENO}"
		                awk 'match($0, /^[[:space:]]*\\{/) {print}' .tmp/web_full_info_probe.txt >.tmp/web_full_info_merge_input.jsonl 2>/dev/null || true
		                if [[ -s ".tmp/web_full_info_merge_input.jsonl" ]]; then
		                    jq -cs 'unique_by(.input)[]' .tmp/web_full_info_merge_input.jsonl 2>>"$LOGFILE" >webs/web_full_info.txt || : >webs/web_full_info.txt
		                else
		                    : >webs/web_full_info.txt
		                fi
		            fi
		            # Keep cache as JSONL for later merges.
		            cp webs/web_full_info.txt .tmp/web_full_info.txt 2>/dev/null || true

		            # Extract URLs from JSONL
		            if [[ -s "webs/web_full_info.txt" ]]; then
		                jq -r 'try (.url // empty)' webs/web_full_info.txt 2>/dev/null \
		                    | awk -v dom="$domain" 'index($0, dom) && $0 ~ /^https?:\\/\\// {print}' \
		                    | sed 's/*.//' | anew_q_safe .tmp/probed_tmp.txt
		            fi
		        else
		            log_note "webprobe_simple: probe output not JSON; treating as URL list" "${FUNCNAME[0]}" "${LINENO}"
		            if [[ -s ".tmp/web_full_info_probe.txt" ]]; then
		                awk -v dom="$domain" 'index($0, dom) && $0 ~ /^https?:\\/\\// {print}' .tmp/web_full_info_probe.txt 2>/dev/null \
		                    | sed 's/*.//' | anew_q_safe .tmp/probed_tmp.txt
		            fi
		        fi

	        # Adaptive throttling heuristics: mark slow hosts (429/403) from httpx
	        if [[ -s "webs/web_full_info.txt" ]]; then
	            jq -r 'try select(.status_code==403 or .status_code==429) | .url' webs/web_full_info.txt 2>/dev/null \
	                | awk -F/ '{print $3}' | sed 's/\:$//' | sort -u >.tmp/slow_hosts.txt
        fi

        # Extract web info to plain text
        if [[ -s "webs/web_full_info.txt" ]]; then
            jq -r 'try . |"\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' webs/web_full_info.txt \
                | grep "$domain" | anew_q_safe webs/web_full_info_plain.txt
        fi

        # Remove out-of-scope entries
        if [[ -s $outOfScope_file ]]; then
            if ! deleteOutScoped "$outOfScope_file" .tmp/probed_tmp.txt; then
                print_warnf "Failed to delete out-of-scope entries."
            fi
	        fi

	        touch .tmp/probed_tmp.txt

	        # Count new websites
	        if ! NUMOFLINES=$(anew_safe webs/webs.txt <.tmp/probed_tmp.txt 2>/dev/null | sed '/^$/d' | wc -l); then
	            print_warnf "Failed to count new websites."
	            NUMOFLINES=0
	        fi

	        # Update webs_all.txt
	        ensure_webs_all || true

	        # Asset store: append probed webs
	        append_assets_from_file web url webs/webs.txt

        end_subfunc "${NUMOFLINES} new websites resolved" "${FUNCNAME[0]}"

        # Send websites to proxy if conditions met
        if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/webs.txt) -le $DEEP_LIMIT2 ]]; then
            notification "Sending websites to proxy" "info"
            run_command ffuf -mc all -w webs/webs.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
        fi

    else
        if [[ $WEBPROBESIMPLE == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
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
                | anew_q_safe .tmp/probed_uncommon_ports_tmp.txt

            # Extract plain web info
            jq -r 'try . | "\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' .tmp/web_full_info_uncommon.txt \
                | grep "$domain" \
                | anew_q_safe webs/web_full_info_uncommon_plain.txt

            # Update webs_full_info_uncommon.txt based on whether domain is IP
            if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | anew_q_safe webs/web_full_info_uncommon.txt
            else
                grep "$domain" .tmp/web_full_info_uncommon.txt | anew_q_safe webs/web_full_info_uncommon.txt
            fi

            # Count new websites
            if ! NUMOFLINES=$(anew_safe webs/webs_uncommon_ports.txt <.tmp/probed_uncommon_ports_tmp.txt | sed '/^$/d' | wc -l); then
                print_warnf "Failed to count new websites."
                NUMOFLINES=0
            fi

            # Notify user
	        notification "Uncommon web ports: ${NUMOFLINES} new websites" "good"

	        # Update webs_all.txt
	        ensure_webs_all || true

	        # Send to proxy if conditions met
	        if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/webs_uncommon_ports.txt) -le $DEEP_LIMIT2 ]]; then
	            notification "Sending websites with uncommon ports to proxy" "info"
	            run_command ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
            fi
        fi
        end_func "Results are saved in $domain/webs/webs_uncommon_ports.txt" "${FUNCNAME[0]}"
        print_webs_summary
    else
        if [[ $WEBPROBEFULL == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi

}

function screenshot() {

    # Create necessary directories
    if ! ensure_dirs webs screenshots; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBSCREENSHOT == true ]]; then
        if [[ $AXIOM != true ]]; then
            if ! command -v nuclei >/dev/null 2>&1; then
                _print_msg WARN "${FUNCNAME[0]}: nuclei binary not found in PATH - install nuclei first"
                return 0
            fi
            if [[ ! -d "${NUCLEI_TEMPLATES_PATH:-}" ]]; then
                _print_msg WARN "${FUNCNAME[0]}: nuclei templates not found at '${NUCLEI_TEMPLATES_PATH}'"
                return 0
            fi
        fi
        start_func "${FUNCNAME[0]}" "Web Screenshots"

	        # Build/refresh webs_all.txt from current web targets.
	        ensure_webs_all || true

	        # Run nuclei or axiom-scan based on AXIOM flag
	        if [[ $AXIOM != true ]]; then
	            if [[ -s "webs/webs_all.txt" ]]; then
	                run_command nuclei -headless -id screenshot -V dir='screenshots' <webs/webs_all.txt 2>>"$LOGFILE" >/dev/null
            fi
        else
            if [[ -s "webs/webs_all.txt" ]]; then
                run_command axiom-scan webs/webs_all.txt -m nuclei-screenshots -o screenshots "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi
        fi
        end_func "Results are saved in $domain/screenshots" "${FUNCNAME[0]}"
    else
        if [[ $WEBSCREENSHOT == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi

}

function virtualhosts() {

    # Create necessary directories
    if ! ensure_dirs .tmp/virtualhosts virtualhosts webs; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $VIRTUALHOSTS == true ]]; then
        if ! command -v VhostFinder >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: VhostFinder not found in PATH"
            return 0
        fi
        start_func "${FUNCNAME[0]}" "Virtual Hosts Discovery"

	        # Build/refresh webs_all.txt from current web targets.
	        ensure_webs_all || true

	        # Proceed only if input files exist
	        if [[ -s "subdomains/subdomains.txt" ]] && [[ -s "hosts/ips.txt" ]]; then
	            VhostFinder -ips hosts/ips.txt -wordlist subdomains/subdomains.txt -verify | grep "+" | anew -q "$dir/webs/virtualhosts.txt"
        fi

        # Optionally send to proxy if conditions are met
        if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/webs_uncommon_ports.txt) -le $DEEP_LIMIT2 ]]; then
            notification "Sending websites with uncommon ports to proxy" "info"
            run_command ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
        fi

        end_func "Results are saved in $domain/webs/virtualhosts.txt" "${FUNCNAME[0]}"

    else
        if [[ $VIRTUALHOSTS == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi

}

###############################################################################################################
############################################# HOST SCAN #######################################################
###############################################################################################################

function favirecon_tech() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } \
        && [[ ${FAVIRECON:-true} == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Favicon Technology Recon"

        ensure_webs_all || true

        if [[ -s "webs/webs_all.txt" ]]; then
            local fav_cmd=(
                favirecon
                -l "webs/webs_all.txt"
                -c "${FAVIRECON_CONCURRENCY:-50}"
                -t "${FAVIRECON_TIMEOUT:-10}"
                -s
                -j
                -o "webs/favirecon.json"
            )

            if [[ -n "${FAVIRECON_PROXY:-}" ]]; then
                fav_cmd+=(-px "${FAVIRECON_PROXY}")
            fi
            if [[ "${FAVIRECON_RATE_LIMIT:-0}" -gt 0 ]]; then
                fav_cmd+=(-rl "${FAVIRECON_RATE_LIMIT}")
            fi

            if ! run_command "${fav_cmd[@]}" 2>>"$LOGFILE" >/dev/null; then
                log_note "favirecon_tech: favirecon command failed" "${FUNCNAME[0]}" "${LINENO}"
            fi

            if [[ -s "webs/favirecon.json" ]]; then
                jq -r '[(.URL // .url // ""), (.Name // .name // "unknown"), (.Hash // .hash // "unknown")] | @tsv' "webs/favirecon.json" 2>/dev/null \
                    | awk -F'\t' 'NF>=1 && $1 ~ /^https?:\/\// {printf "%s [%s] [%s]\n", $1, $2, $3}' \
                    | anew -q "webs/favirecon.txt"
            fi
        else
            log_note "favirecon_tech: no webs/webs_all.txt found" "${FUNCNAME[0]}" "${LINENO}"
        fi

        end_func "Results are saved in webs/favirecon.[json|txt]" "${FUNCNAME[0]}"

    else
        if [[ ${FAVIRECON:-true} == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
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
            # Remove CDN IPs.
            comm -23 <(sort -u hosts/ips.txt) <(cut -d'[' -f1 hosts/cdn_providers.txt | sed 's/[[:space:]]*$//' | sort -u) \
                | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
                | sort -u | anew -q .tmp/ips_nocdn.txt || true
        fi

        # Optional CDN bypass to recover origin IPs.
        if [[ ${CDN_BYPASS:-true} == true ]] && command -v hakoriginfinder >/dev/null 2>&1; then
            : >".tmp/origin_input_hosts.txt"
            if [[ -s "subdomains/subdomains.txt" ]]; then
                cat subdomains/subdomains.txt | anew -q ".tmp/origin_input_hosts.txt"
            elif [[ -s "webs/webs_all.txt" ]]; then
                awk -F/ '{print $3}' webs/webs_all.txt | sed 's/:.*$//' | sed '/^$/d' | sort -u | anew -q ".tmp/origin_input_hosts.txt"
            fi
            if [[ -s ".tmp/origin_input_hosts.txt" ]]; then
                if run_command hakoriginfinder <".tmp/origin_input_hosts.txt" >".tmp/hakoriginfinder_raw.txt" 2>>"$LOGFILE"; then
                    grep -aoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' ".tmp/hakoriginfinder_raw.txt" \
                        | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." \
                        | sort -u >"hosts/origin_ips.txt"
                    if [[ -s "hosts/origin_ips.txt" ]]; then
                        cat hosts/origin_ips.txt | anew -q .tmp/ips_nocdn.txt
                        cat hosts/origin_ips.txt | anew -q hosts/ips.txt
                    fi
                else
                    log_note "portscan: hakoriginfinder failed, skipping CDN bypass origins" "${FUNCNAME[0]}" "${LINENO}"
                fi
            fi
        fi

        # Display resolved IPs without CDN.
        ips_nocdn_count=0
        if [[ -s ".tmp/ips_nocdn.txt" ]]; then
            ips_nocdn_count=$(sort -u ".tmp/ips_nocdn.txt" | wc -l | tr -d ' ')
        fi

        if ((ips_nocdn_count > 0)); then
            _print_msg INFO "Resolved IP addresses (No CDN): ${ips_nocdn_count} (see .tmp/ips_nocdn.txt)"
        else
            _print_msg INFO "Resolved IP addresses (No CDN): none"
        fi
        printf "\n"

        _print_msg INFO "Scanning ports..."

        ips_file="${dir}/hosts/ips.txt"

        # Discover IPv6 addresses from DNS JSON if enabled.
        if [[ $IPV6_SCAN == true ]]; then
            if [[ -s "subdomains/subdomains_dnsregs.json" ]]; then
                jq -r '.. | strings | select(test("^[0-9a-fA-F:]+$"))' <"subdomains/subdomains_dnsregs.json" \
                    | grep -v '\\.' | sort -u | anew -q hosts/ips_v6.txt || true
            fi
            # Add target if it's an IPv6 literal.
            if [[ $domain =~ : ]]; then echo "$domain" | anew -q hosts/ips_v6.txt || true; fi
        fi

        if [[ $PORTSCAN_PASSIVE == true ]]; then
            if [[ ! -f $ips_file ]]; then
                print_warnf "File %s does not exist." "$ips_file"
            else
                json_array=()
                while IFS= read -r cip; do
                    if ! json_result=$(run_command curl -s "https://internetdb.shodan.io/${cip}"); then
                        print_warnf "Failed to retrieve data for IP %s." "$cip"
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
                    print_warnf "Failed to write portscan_shodan.txt."
                fi
            fi
        fi

        if [[ $PORTSCAN_PASSIVE == true ]] && [[ ! -f "hosts/portscan_passive.txt" ]] && [[ -s ".tmp/ips_nocdn.txt" ]]; then
            run_command smap -iL .tmp/ips_nocdn.txt >hosts/portscan_passive.txt
        fi

        if [[ $PORTSCAN_ACTIVE == true ]]; then
            # Resolve active nmap options (deep profile optional).
            local active_opts_raw
            active_opts_raw="${PORTSCAN_ACTIVE_OPTIONS:-}"
            if [[ $DEEP == true ]] && [[ -n "${PORTSCAN_DEEP_OPTIONS:-}" ]]; then
                active_opts_raw="${PORTSCAN_DEEP_OPTIONS}"
            fi
            local portscan_opts=()
            if [[ -n "$active_opts_raw" ]]; then
                local _ifs="$IFS"
                IFS=' '
                read -r -a portscan_opts <<<"$active_opts_raw"
                IFS="$_ifs"
            fi

            local strategy="${PORTSCAN_STRATEGY:-legacy}"
            local used_targeted_output=false

            if [[ "$strategy" == "naabu_nmap" ]] && [[ ${NAABU_ENABLE:-true} == true ]] && [[ $AXIOM != true ]]; then
                if command -v naabu >/dev/null 2>&1; then
                    local naabu_ports_raw="${NAABU_PORTS:---top-ports 1000}"
                    local naabu_opts=()
                    if [[ -n "$naabu_ports_raw" ]]; then
                        local _ifs="$IFS"
                        IFS=' '
                        read -r -a naabu_opts <<<"$naabu_ports_raw"
                        IFS="$_ifs"
                    fi

                    if [[ -s ".tmp/ips_nocdn.txt" ]]; then
                        run_command naabu -list ".tmp/ips_nocdn.txt" -silent -rate "${NAABU_RATE:-1000}" "${naabu_opts[@]}" -o "hosts/naabu_open.txt" 2>>"$LOGFILE" >/dev/null
                    fi

                    if [[ -s "hosts/naabu_open.txt" ]]; then
                        local naabu_ports_csv=""
                        naabu_ports_csv=$(cut -d':' -f2 "hosts/naabu_open.txt" | sed '/^$/d' | sort -un | paste -sd, -)
                        if [[ -n "$naabu_ports_csv" ]]; then
                            run_command "$SUDO" nmap "${portscan_opts[@]}" -p "$naabu_ports_csv" -iL ".tmp/ips_nocdn.txt" -oA "hosts/portscan_active_targeted" 2>>"$LOGFILE" >/dev/null
                            used_targeted_output=true
                        fi
                    fi
                else
                    _print_msg WARN "PORTSCAN_STRATEGY=naabu_nmap requested but naabu is missing. Falling back to legacy nmap."
                fi
            elif [[ "$strategy" == "naabu_nmap" ]] && [[ $AXIOM == true ]]; then
                _print_msg WARN "PORTSCAN_STRATEGY=naabu_nmap is not enabled for AXIOM yet. Falling back to legacy nmapx."
            fi

            # Legacy fallback.
            if [[ "$used_targeted_output" != true ]]; then
                if [[ $AXIOM != true ]]; then
                    if [[ -s ".tmp/ips_nocdn.txt" ]]; then
                        run_command "$SUDO" nmap "${portscan_opts[@]}" -iL .tmp/ips_nocdn.txt -oA hosts/portscan_active 2>>"$LOGFILE" >/dev/null
                    fi
                else
                    if [[ -s ".tmp/ips_nocdn.txt" ]]; then
                        run_command axiom-scan .tmp/ips_nocdn.txt -m nmapx "${portscan_opts[@]}" \
                            -oA hosts/portscan_active "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
                    fi
                fi
            fi

            # Keep compatibility output names if targeted flow ran.
            if [[ "$used_targeted_output" == true ]] && [[ ! -s "hosts/portscan_active.xml" ]] && [[ -s "hosts/portscan_active_targeted.xml" ]]; then
                cp "hosts/portscan_active_targeted.xml" "hosts/portscan_active.xml"
                [[ -s "hosts/portscan_active_targeted.gnmap" ]] && cp "hosts/portscan_active_targeted.gnmap" "hosts/portscan_active.gnmap"
                [[ -s "hosts/portscan_active_targeted.nmap" ]] && cp "hosts/portscan_active_targeted.nmap" "hosts/portscan_active.nmap"
            fi

            if [[ $IPV6_SCAN == true && -s "hosts/ips_v6.txt" ]] && [[ $AXIOM != true ]]; then
                run_command "$SUDO" nmap -6 "${portscan_opts[@]}" -iL hosts/ips_v6.txt -oA hosts/portscan_active_v6 2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Optional UDP top-ports scan (local-only, requires privileges).
        if [[ ${PORTSCAN_UDP:-false} == true ]] && [[ $AXIOM != true ]] && [[ -s ".tmp/ips_nocdn.txt" ]]; then
            local udp_opts_raw="${PORTSCAN_UDP_OPTIONS:---top-ports 20 -sU -sV -n -Pn --open}"
            local udp_opts=()
            if [[ -n "$udp_opts_raw" ]]; then
                local _ifs="$IFS"
                IFS=' '
                read -r -a udp_opts <<<"$udp_opts_raw"
                IFS="$_ifs"
            fi
            run_command "$SUDO" nmap "${udp_opts[@]}" -iL ".tmp/ips_nocdn.txt" -oA "hosts/portscan_active_udp" 2>>"$LOGFILE" >/dev/null
        elif [[ ${PORTSCAN_UDP:-false} == true ]] && [[ $AXIOM == true ]]; then
            _print_msg WARN "PORTSCAN_UDP is local-only for now; skipped in AXIOM mode."
        fi

        if [[ -s "hosts/portscan_active.xml" ]]; then
            nmapurls <hosts/portscan_active.xml 2>>"$LOGFILE" | anew -q hosts/webs.txt
        fi
        if [[ -s "hosts/portscan_active_v6.xml" ]]; then
            nmapurls <hosts/portscan_active_v6.xml 2>>"$LOGFILE" | anew -q hosts/webs_v6.txt
            [[ -s hosts/webs_v6.txt ]] && cat hosts/webs_v6.txt | anew -q webs/webs.txt
        fi

        if [[ $FARADAY == true ]]; then
            # Check if the Faraday server is running.
            if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
                print_warnf "Faraday server is not running. Skipping Faraday integration."
            else
                if [[ -s "hosts/portscan_active.xml" ]]; then
                    faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nmap hosts/portscan_active.xml 2>>"$LOGFILE" >/dev/null
                fi
                if [[ -s "hosts/portscan_active_udp.xml" ]]; then
                    faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nmap hosts/portscan_active_udp.xml 2>>"$LOGFILE" >/dev/null
                fi
            fi
        fi

        if [[ -s "hosts/webs.txt" ]]; then
            if ! NUMOFLINES=$(wc -l <hosts/webs.txt); then
                print_warnf "Failed to count lines in hosts/webs.txt."
                NUMOFLINES=0
            fi
            notification "Webs detected from port scan: ${NUMOFLINES} new websites" "good"
            append_assets_from_file web url hosts/webs.txt
        fi

        service_fingerprint

        end_func "Results are saved in hosts/portscan_[passive|active|active_targeted|active_udp|shodan].*" "${FUNCNAME[0]}"

    else
        if [[ $PORTSCANNER == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi

}

_build_fingerprintx_targets_from_nmap() {
    local nmap_gnmap="$1"
    local out_file="$2"
    [[ ! -s "$nmap_gnmap" ]] && return 0

    awk '
    /^Host: / {
        host = $2
        if (host == "") next
        ports = $0
        sub(/^.*Ports: /, "", ports)
        n = split(ports, arr, ",")
        for (i = 1; i <= n; i++) {
            gsub(/^ +| +$/, "", arr[i])
            split(arr[i], f, "/")
            if (f[2] == "open" && f[1] ~ /^[0-9]+$/) {
                print host ":" f[1]
            }
        }
    }' "$nmap_gnmap" | sort -u | anew -q "$out_file"
}

function service_fingerprint() {
    ensure_dirs hosts .tmp

    if [[ "${SERVICE_FINGERPRINT:-true}" != "true" ]]; then
        return 0
    fi
    if [[ "${SERVICE_FINGERPRINT_ENGINE:-fingerprintx}" != "fingerprintx" ]]; then
        _print_msg WARN "${FUNCNAME[0]}: unsupported SERVICE_FINGERPRINT_ENGINE=${SERVICE_FINGERPRINT_ENGINE}"
        return 0
    fi
    if [[ $AXIOM == true ]]; then
        log_note "service_fingerprint: local-only for now, skipped in AXIOM mode" "${FUNCNAME[0]}" "${LINENO}"
        return 0
    fi
    if ! command -v fingerprintx >/dev/null 2>&1; then
        _print_msg WARN "${FUNCNAME[0]}: fingerprintx not found in PATH"
        return 0
    fi

    start_subfunc "${FUNCNAME[0]}" "Service fingerprinting (fingerprintx)"

    local targets_file=".tmp/fingerprintx_targets.txt"
    : >"$targets_file"

    if [[ -s "hosts/naabu_open.txt" ]]; then
        awk -F: 'NF==2 && $2 ~ /^[0-9]+$/ {print $1 ":" $2}' "hosts/naabu_open.txt" | sort -u | anew -q "$targets_file"
    fi
    if [[ ! -s "$targets_file" ]]; then
        _build_fingerprintx_targets_from_nmap "hosts/portscan_active.gnmap" "$targets_file"
    fi
    if [[ ! -s "$targets_file" ]]; then
        _build_fingerprintx_targets_from_nmap "hosts/portscan_active_targeted.gnmap" "$targets_file"
    fi

    if [[ -s "$targets_file" ]]; then
        local timeout_ms="${SERVICE_FINGERPRINT_TIMEOUT_MS:-2000}"
        run_command fingerprintx --json -l "$targets_file" -w "$timeout_ms" -o "hosts/fingerprintx.jsonl" 2>>"$LOGFILE" >/dev/null || true
        if [[ -s "hosts/fingerprintx.jsonl" ]]; then
            jq -r '[(.host // .ip // .target // "unknown"), (.port // "unknown"), (.protocol // .service // "unknown")] | @tsv' "hosts/fingerprintx.jsonl" 2>/dev/null \
                | awk -F'\t' '{printf "%s:%s [%s]\n", $1, $2, $3}' \
                | anew -q "hosts/fingerprintx.txt"
        fi
    fi

    end_subfunc "Results are saved in hosts/fingerprintx.[jsonl|txt]" "${FUNCNAME[0]}"
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
            run_command cdncheck -silent -resp -nc <hosts/ips.txt | anew -q "$dir/hosts/cdn_providers.txt"
        fi

        end_func "Results are saved in hosts/cdn_providers.txt" "${FUNCNAME[0]}"

    else
        if [[ $CDN_IP == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
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
	        if [[ $AXIOM != true ]] && ! command -v wafw00f >/dev/null 2>&1; then
	            _print_msg WARN "${FUNCNAME[0]}: wafw00f not found in PATH"
	            return 0
	        fi
	        start_func "${FUNCNAME[0]}" "Website's WAF Detection"

	        ensure_webs_all || true

	        # Proceed only if webs_all.txt exists and is non-empty
	        if [[ -s "webs/webs_all.txt" ]]; then
	            if [[ $AXIOM != true ]]; then
	                # Run wafw00f on webs_all.txt
	                run_command wafw00f -i "webs/webs_all.txt" -o ".tmp/wafs.txt" 2>>"$LOGFILE" >/dev/null
	            else
	                # Run axiom-scan with wafw00f module on webs_all.txt
	                run_command axiom-scan "webs/webs_all.txt" -m wafw00f -o ".tmp/wafs.txt" "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
	            fi

	            # Process wafs.txt if it exists and is not empty
	            if [[ -s ".tmp/wafs.txt" ]]; then
	                # Format the wafs.txt file
	                sed -e 's/^[ \t]*//' -e 's/ \+ /\t/g' -e '/(None)/d' ".tmp/wafs.txt" | tr -s "\t" ";" >"webs/webs_wafs.txt"

	                # Count the number of websites protected by WAF
	                if ! NUMOFLINES=$(sed '/^$/d' "webs/webs_wafs.txt" 2>>"$LOGFILE" | wc -l); then
	                    print_warnf "Failed to count lines in webs_wafs.txt."
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
	        if [[ $WAF_DETECTION == false ]]; then
	            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
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
        jq -r '["[" + .["template-id"] + (if .["matcher-name"] != null then ":" + .["matcher-name"] else "" end) + "] [" + .["type"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host) + (if .["extracted-results"] != null then " " + (.["extracted-results"] | @json) else "" end)] | .[]' "nuclei_output/${crit}_json.txt" >"nuclei_output/${crit}.txt"
        append_assets_from_file finding value "nuclei_output/${crit}.txt"
        if [[ -s "nuclei_output/${crit}.txt" ]]; then
            local _count
            _count=$(wc -l <"nuclei_output/${crit}.txt" | tr -d ' ')
            if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
                _print_status OK "nuclei_${crit}" "${_count} findings -> nuclei_output/${crit}.txt"
            fi
        fi
    fi
}

# Run nuclei scan locally with WAF-aware rate limiting
# Usage: _nuclei_scan_local
_nuclei_scan_local() {
    IFS=',' read -ra severity_array <<<"$NUCLEI_SEVERITY"

    for crit in "${severity_array[@]}"; do
        _print_msg INFO "Running: Nuclei Severity: ${crit}"
        # Non-WAF at default rate
        if [[ -s "$NOWAF_LIST" ]]; then
            # shellcheck disable=SC2086  # Intentionally allow user-provided nuclei args
            run_with_heartbeat "nuclei ${crit} (normal targets)" nuclei \
                -l "$NOWAF_LIST" -severity "$crit" -nh -rl "$NUCLEI_RATELIMIT" -silent -retries 2 \
                $NUCLEI_EXTRA_ARGS -t "${NUCLEI_TEMPLATES_PATH}" -j -o "nuclei_output/${crit}_json.txt"
        fi
        # WAF hosts at slower rate
        if [[ -s "$WAF_LIST" ]]; then
            local slow_rl
            slow_rl=$((NUCLEI_RATELIMIT / 3 + 1))
            # shellcheck disable=SC2086  # Intentionally allow user-provided nuclei args
            run_with_heartbeat "nuclei ${crit} (waf targets)" nuclei \
                -l "$WAF_LIST" -severity "$crit" -nh -rl "$slow_rl" -silent -retries 2 \
                $NUCLEI_EXTRA_ARGS -t "${NUCLEI_TEMPLATES_PATH}" -j -o "nuclei_output/${crit}_waf_json.txt"
            [[ -s "nuclei_output/${crit}_waf_json.txt" ]] && cat "nuclei_output/${crit}_waf_json.txt" >>"nuclei_output/${crit}_json.txt"
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
        _print_msg INFO "Running: Axiom Nuclei Severity: ${crit}. Check results in nuclei_output folder."
        # shellcheck disable=SC2086  # Intentionally allow user-provided nuclei args
        run_with_heartbeat "axiom nuclei ${crit}" axiom-scan .tmp/webs_subs.txt -m nuclei \
            --nuclei-templates "$NUCLEI_TEMPLATES_PATH" \
            -severity "$crit" -nh -rl "$NUCLEI_RATELIMIT" \
            -silent -retries 2 $NUCLEI_EXTRA_ARGS -j -o "nuclei_output/${crit}_json.txt" "$AXIOM_EXTRA_ARGS"
        _nuclei_parse_results "$crit"
    done
    printf "\n\n"
}

function nuclei_check() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs subdomains nuclei_output; then return 1; fi

    # Check if the function should run
    if should_run "NUCLEICHECK"; then
        # Verify nuclei binary is available
        if ! command -v nuclei >/dev/null 2>&1; then
            _print_msg WARN "nuclei_check: nuclei binary not found in PATH - install nuclei first"
            return 0
        fi
        # Verify templates directory exists (needed for -t flag)
        if [[ ! -d "${NUCLEI_TEMPLATES_PATH:-}" ]]; then
            _print_msg WARN "nuclei_check: templates directory '${NUCLEI_TEMPLATES_PATH}' not found - run 'nuclei -update-templates' first"
            return 0
        fi
        start_func "${FUNCNAME[0]}" "Templates-based Web Scanner"
        maybe_update_nuclei

        # Handle multi mode and initialize subdomains.txt if necessary
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
            touch webs/webs.txt webs/webs_uncommon_ports.txt
        fi

        ensure_webs_all || true

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
                print_warnf "Faraday server is not running. Skipping Faraday integration."
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
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
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
            _print_msg WARN "No graphql-detect findings in nuclei_check outputs; skipping GraphQL deep checks."
            log_note "No graphql-detect findings in nuclei_check outputs; skipping GraphQL deep checks." "${FUNCNAME[0]}" "${LINENO}"
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
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi
}

function param_discovery() {
    ensure_dirs webs .tmp

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PARAM_DISCOVERY == true ]]; then
        if ! command -v arjun >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: arjun not found in PATH"
            return 0
        fi
        start_func "${FUNCNAME[0]}" "Parameter discovery (arjun)"
        local input_file="webs/url_extract_nodupes.txt"
        [[ ! -s $input_file ]] && input_file="webs/webs_all.txt"
        if [[ -s $input_file ]]; then
            run_command arjun -i "$input_file" -t "$ARJUN_THREADS" -oJ .tmp/arjun.json 2>>"$LOGFILE" >/dev/null || true
            if [[ -s .tmp/arjun.json ]]; then
                jq -r '..|.url? // empty' .tmp/arjun.json | sed 's/^/URL: /' | anew -q webs/params_discovered.txt
                jq -r '..|.params? // empty | to_entries[] | .key' .tmp/arjun.json | sed 's/^/PARAM: /' | sort -u | anew -q webs/params_discovered.txt
            fi
        fi
        end_func "Results are saved in webs/params_discovered.txt" "${FUNCNAME[0]}"
    else
        if [[ $PARAM_DISCOVERY == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi
}

function grpc_reflection() {
    ensure_dirs hosts .tmp

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GRPC_SCAN == true ]]; then
        if ! command -v grpcurl >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: grpcurl not found in PATH"
            return 0
        fi
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
                    run_command grpcurl -plaintext -max-msg-sz 10485760 -d '{}' "$ip:$p" list 2>>"$LOGFILE" | sed "s/^/[$ip:$p] /" | anew -q hosts/grpc_reflection.txt || true
                done
            done <.tmp/grpc_ips.txt
        fi
        end_func "Results are saved in hosts/grpc_reflection.txt" "${FUNCNAME[0]}"
    else
        if [[ $GRPC_SCAN == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi
}

function llm_probe() {
    ensure_dirs webs .tmp

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ "${LLM_PROBE:-false}" == "true" ]]; then
        if ! command -v julius >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: julius not found in PATH"
            return 0
        fi
        if [[ ! -s "webs/webs_all.txt" ]]; then
            skip_notification "noinput"
            return 0
        fi
        start_func "${FUNCNAME[0]}" "LLM service probing (julius)"

        local -a julius_cmd=(julius -o jsonl -q probe -f "webs/webs_all.txt")
        if [[ "${LLM_PROBE_AUGUSTUS:-false}" == "true" ]]; then
            julius_cmd=(julius -o jsonl -q probe --augustus -f "webs/webs_all.txt")
        fi

        run_command "${julius_cmd[@]}" >"webs/llm_probe.jsonl" 2>>"$LOGFILE" || true
        if [[ -s "webs/llm_probe.jsonl" ]]; then
            jq -r '[(.target // .url // "unknown"), (.provider // .service // "unknown"), (.probe // "n/a")] | @tsv' "webs/llm_probe.jsonl" 2>/dev/null \
                | awk -F'\t' '{printf "%s [%s] [%s]\n", $1, $2, $3}' \
                | anew -q "webs/llm_probe.txt"
        fi

        end_func "Results are saved in webs/llm_probe.[jsonl|txt]" "${FUNCNAME[0]}"
    else
        if [[ "${LLM_PROBE:-false}" == "false" ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
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
    local ffuf_recursion_flags=""
    if [[ ${DEEP:-false} == true ]]; then
        ffuf_recursion_flags="-recursion -recursion-depth ${FUZZ_RECURSION_DEPTH:-2}"
    fi

    if [[ -s .tmp/webs_normal.txt ]]; then
        run_with_heartbeat "ffuf normal targets" interlace \
            -tL .tmp/webs_normal.txt -threads "${INTERLACE_THREADS}" \
            -c "ffuf ${FFUF_FLAGS} ${ffuf_recursion_flags} -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u _target_/FUZZ -o _output_/_cleantarget_.json" \
            -o "$dir/.tmp/fuzzing"
    fi

    if [[ -s .tmp/webs_slow.txt ]]; then
        local slow_threads=$((FFUF_THREADS / 3))
        [[ $slow_threads -lt 5 ]] && slow_threads=5
        local slow_rate=$FFUF_RATELIMIT
        [[ ${FFUF_RATELIMIT:-0} -eq 0 ]] && slow_rate=50 || slow_rate=$((FFUF_RATELIMIT / 3 + 1))
        run_with_heartbeat "ffuf slow targets" interlace \
            -tL .tmp/webs_slow.txt -threads "${INTERLACE_THREADS}" \
            -c "ffuf ${FFUF_FLAGS} ${ffuf_recursion_flags} -t ${slow_threads} -rate ${slow_rate} -H \"${HEADER}\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u _target_/FUZZ -o _output_/_cleantarget_.json" \
            -o "$dir/.tmp/fuzzing"
    fi
}

# Run ffuf via axiom-scan and parse per-subdomain results
_fuzz_run_axiom() {
    cached_download_typed "${fuzzing_remote_list}" ".tmp/fuzzing_remote_list.txt" "onelistforallmicro.txt" "wordlists"
    run_with_heartbeat "axiom ffuf" axiom-scan webs/webs_all.txt -m ffuf -wL .tmp/fuzzing_remote_list.txt -H "${HEADER}" "$FFUF_FLAGS" -s -maxtime "$FFUF_MAXTIME" -oJ "$dir/.tmp/ffuf-content.json" "$AXIOM_EXTRA_ARGS"

    while read -r sub; do
        local sub_out
        sub_out=$(echo "$sub" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
        if [[ -s "$dir/.tmp/ffuf-content.json" ]]; then
            local tmp_out=".tmp/ffuf_${sub_out}.txt"
            jq -r --arg sub "$sub" 'try .results[] | select(.url | contains($sub)) | "\(.status) \(.length) \(.url)"' "$dir/.tmp/ffuf-content.json" 2>>"$LOGFILE" \
                | sort -k1 >"$tmp_out" || true
            if [[ -s "$tmp_out" ]]; then
                anew -q "fuzzing/${sub_out}.txt" <"$tmp_out" 2>>"$LOGFILE" || true
            fi
            rm -f "$tmp_out" 2>/dev/null || true
        fi
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
            printf "%b\n" "$domain" >"$dir/webs/webs.txt" || print_warnf "Failed to create webs.txt."
            touch webs/webs_uncommon_ports.txt 2>>"$LOGFILE" || true
        fi

        ensure_webs_all || true

        if [[ -s "webs/webs_all.txt" ]]; then
            if [[ $AXIOM != true ]]; then
                _fuzz_run_local
            else
                _fuzz_run_axiom
            fi
            _fuzz_merge_results
            end_func "Results are saved in $domain/fuzzing/*subdomain*.txt" "${FUNCNAME[0]}"
        else
            end_func "No $domain/webs/webs_all.txt file found, fuzzing skipped " "${FUNCNAME[0]}" "SKIP_NOINPUT"
        fi

    else
        if [[ $FUZZ == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi

}

function iishortname() {

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $IIS_SHORTNAME == true ]]; then
        start_func "${FUNCNAME[0]}" "IIS Shortname Scanner"

        ensure_dirs .tmp || true
        : >.tmp/iis_sites.txt

        # Ensure nuclei_output/info.txt exists and is not empty
        if [[ -s "nuclei_output/info.txt" ]]; then
            # Extract IIS targets (if any) without triggering pipefail on "no matches".
            awk '/iis-version/ {print $4}' "nuclei_output/info.txt" >.tmp/iis_sites.txt
        fi

        # Proceed only if iis_sites.txt exists and is non-empty
        if [[ -s ".tmp/iis_sites.txt" ]]; then
            # Create necessary directory
            mkdir -p "$dir/vulns/iis-shortname-shortscan/"

            # Run shortscan using interlace
            run_command interlace -tL .tmp/iis_sites.txt -threads "$INTERLACE_THREADS" \
                -c "shortscan _target_ -F -s -p 1 > _output_/_cleantarget_.txt" \
                -o "$dir/vulns/iis-shortname-shortscan/" 2>>"$LOGFILE" >/dev/null

            # Remove non-vulnerable shortscan results
            while IFS= read -r -d '' file; do
                if ! grep -q 'Vulnerable: Yes' "$file" 2>/dev/null; then
                    rm -f "$file" 2>>"$LOGFILE"
                fi
            done < <(find "$dir/vulns/iis-shortname-shortscan/" -type f -iname "*.txt" -print0 2>/dev/null)

        fi
        end_func "Results are saved in vulns/iis-shortname/" "${FUNCNAME[0]}"
    else
        if [[ $IIS_SHORTNAME == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi

}

function cms_scanner() {

    # Create necessary directories
    if ! mkdir -p .tmp/fuzzing webs cms; then
        print_warnf "Failed to create directories."
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

        # Ensure webs_all.txt exists
        if [[ ! -s "webs/webs_all.txt" ]]; then
            end_func "No webs/webs_all.txt file found, cms scanner skipped." "${FUNCNAME[0]}" "SKIP_NOINPUT"
            return
        fi

        # Run CMSeeK with timeout
        local cmseek_cmd=(
            timeout -k 1m "${CMSSCAN_TIMEOUT}s"
            "${tools}/CMSeeK/venv/bin/python3" "${tools}/CMSeeK/cmseek.py"
            -l webs/webs_all.txt --batch -r
        )
        run_with_heartbeat "cmseek batch scan" "${cmseek_cmd[@]}"
        local exit_status=$?
        if [[ ${exit_status} -ne 0 ]]; then
            # Attempt one-time repair on known CMSeeK index corruption.
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
            sub_out="${sub_out//$'\r'/}"
            sub_out="${sub_out//:/_}"
            cms_json_path="${tools}/CMSeeK/Result/${sub_out}/cms.json"

            if [[ -s $cms_json_path ]]; then
                cms_id=$(jq -r 'try .cms_id // empty' "$cms_json_path")
                mv -f "${tools}/CMSeeK/Result/${sub_out}" "$dir/cms/" 2>>"$LOGFILE"
                if [[ -z $cms_id ]]; then
                    log_note "cms_scanner: empty cms_id for ${sub_out}, results moved for inspection" "${FUNCNAME[0]}" "${LINENO}"
                fi
            fi
        done <"webs/webs_all.txt"

        end_func "Results are saved in $domain/cms/*subdomain* folder" "${FUNCNAME[0]}"
    else
        if [[ $CMS_SCANNER == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi
}

_katana_headless_flags() {
    local target_count="${1:-0}"
    local profile="${KATANA_HEADLESS_PROFILE:-off}"
    case "$profile" in
        off) echo "" ;;
        full) echo "-headless" ;;
        smart)
            if [[ "$target_count" -le "${KATANA_HEADLESS_SMART_LIMIT:-15}" ]]; then
                echo "-headless"
            else
                echo ""
            fi
            ;;
        *)
            log_note "urlchecks: invalid KATANA_HEADLESS_PROFILE='${profile}', using off" "${FUNCNAME[0]}" "${LINENO}"
            echo ""
            ;;
    esac
}

function urlchecks() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_CHECK == true ]]; then
        start_func "${FUNCNAME[0]}" "URL Extraction"
        local end_message="Results are saved in $domain/webs/url_extract.txt"
        local katana_timeout_cmd="${TIMEOUT_CMD:-timeout}"
        local waymore_timeout_cmd="${TIMEOUT_CMD:-timeout}"
        local katana_headless_flags=""

        ensure_webs_all || true

        if [[ -s "webs/webs_all.txt" ]]; then
            local katana_target_count=0
            katana_target_count=$(wc -l <"webs/webs_all.txt" 2>/dev/null || echo 0)
            katana_headless_flags=$(_katana_headless_flags "$katana_target_count")

            if [[ $URL_CHECK_PASSIVE == true ]]; then
                if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
                    log_note "urlchecks: reusing urlfinder output from sub_scraping" "${FUNCNAME[0]}" "${LINENO}"
                else
                    : >.tmp/url_extract_tmp.txt
                    run_command urlfinder -d "$domain" -all -o .tmp/url_extract_tmp.txt 2>>"$LOGFILE" >/dev/null
                fi
                if command -v waymore &>/dev/null; then
                    if [[ -s ".tmp/waymore_urls_subs.txt" ]]; then
                        log_note "urlchecks: reusing waymore output from sub_scraping" "${FUNCNAME[0]}" "${LINENO}"
                        cat .tmp/waymore_urls_subs.txt | anew -q .tmp/url_extract_tmp.txt || true
                    else
                        if ! run_with_heartbeat "waymore passive urls" "$waymore_timeout_cmd" "${WAYMORE_TIMEOUT:-30m}" waymore -i "$domain" -mode U -oU .tmp/waymore_urls.txt; then
                            log_note "urlchecks: waymore failed or timed out; continuing with other passive sources" "${FUNCNAME[0]}" "${LINENO}"
                        fi
                        if [[ -s ".tmp/waymore_urls.txt" ]]; then
                            cat .tmp/waymore_urls.txt | anew -q .tmp/url_extract_tmp.txt || true
                        fi
                    fi
                else
                    log_note "urlchecks: waymore not found; skipping passive waymore collection" "${FUNCNAME[0]}" "${LINENO}"
                fi
                if [[ -s $GITHUB_TOKENS ]]; then
                    run_command github-endpoints -q -k -d "$domain" -t "$GITHUB_TOKENS" -o .tmp/github-endpoints.txt 2>>"$LOGFILE" >/dev/null
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
                                    process_in_chunks .tmp/katana_targets_normal.txt "${CHUNK_LIMIT:-2000}" "katana -silent -list _chunk_ ${katana_headless_flags} -jc -kf all -c $KATANA_THREADS -d 3 -fs rdn >> .tmp/katana.txt 2>>\"$LOGFILE\" >/dev/null"
                                else
                                    process_in_chunks .tmp/katana_targets_normal.txt "${CHUNK_LIMIT:-2000}" "katana -silent -list _chunk_ ${katana_headless_flags} -jc -kf all -c $KATANA_THREADS -d 2 -fs rdn >> .tmp/katana.txt 2>>\"$LOGFILE\""
                                fi
                            else
                                if [[ $DEEP == true ]]; then
                                    run_with_heartbeat_shell "katana normal targets (deep)" "$katana_timeout_cmd 4h katana -silent -list .tmp/katana_targets_normal.txt ${katana_headless_flags} -jc -kf all -c $KATANA_THREADS -d 3 -fs rdn >> .tmp/katana.txt 2>> \"$LOGFILE\""
                                else
                                    run_with_heartbeat_shell "katana normal targets" "$katana_timeout_cmd 3h katana -silent -list .tmp/katana_targets_normal.txt ${katana_headless_flags} -jc -kf all -c $KATANA_THREADS -d 2 -fs rdn >> .tmp/katana.txt 2>> \"$LOGFILE\""
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
                                    process_in_chunks .tmp/katana_targets_slow.txt "${CHUNK_LIMIT:-2000}" "katana -silent -list _chunk_ ${katana_headless_flags} -jc -kf all -c $slow_c -d 3 -fs rdn >> .tmp/katana.txt 2>>\"$LOGFILE\""
                                else
                                    process_in_chunks .tmp/katana_targets_slow.txt "${CHUNK_LIMIT:-2000}" "katana -silent -list _chunk_ ${katana_headless_flags} -jc -kf all -c $slow_c -d 2 -fs rdn >> .tmp/katana.txt 2>>\"$LOGFILE\""
                                fi
                            else
                                if [[ $DEEP == true ]]; then
                                    run_with_heartbeat_shell "katana slow targets (deep)" "$katana_timeout_cmd 4h katana -silent -list .tmp/katana_targets_slow.txt ${katana_headless_flags} -jc -kf all -c $slow_c -d 3 -fs rdn >> .tmp/katana.txt 2>> \"$LOGFILE\""
                                else
                                    run_with_heartbeat_shell "katana slow targets" "$katana_timeout_cmd 3h katana -silent -list .tmp/katana_targets_slow.txt ${katana_headless_flags} -jc -kf all -c $slow_c -d 2 -fs rdn >> .tmp/katana.txt 2>> \"$LOGFILE\""
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
                            run_with_heartbeat "axiom katana (deep)" axiom-scan webs/webs_all.txt -m katana $katana_headless_flags -jc -kf all -d 3 -fs rdn --max-runtime 4h -o .tmp/katana.txt "$AXIOM_EXTRA_ARGS"
                        else
                            run_with_heartbeat "axiom katana" axiom-scan webs/webs_all.txt -m katana $katana_headless_flags -jc -kf all -d 2 -fs rdn --max-runtime 3h -o .tmp/katana.txt "$AXIOM_EXTRA_ARGS"
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
                    run_command interlace -tL .tmp/url_extract_js.txt -threads 10 -c "${tools}/JSA/venv/bin/python3 ${tools}/JSA/jsa.py -f _target_ | anew -q .tmp/url_extract_tmp.txt" &>/dev/null
                fi

                grep -a "$domain" .tmp/url_extract_tmp.txt | grep -aEo 'https?://[^ ]+' | grep "=" | qsreplace -a 2>>"$LOGFILE" | grep -aEiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg)$" | anew -q .tmp/url_extract_tmp2.txt || true

                if [[ -s ".tmp/url_extract_tmp2.txt" ]]; then
                    urless <.tmp/url_extract_tmp2.txt | anew -q .tmp/url_extract_uddup.txt 2>>"$LOGFILE" >/dev/null || true
                fi

                if [[ -s ".tmp/url_extract_uddup.txt" ]]; then
                    if ! NUMOFLINES=$(anew webs/url_extract.txt <.tmp/url_extract_uddup.txt | sed '/^$/d' | wc -l); then
                        print_warnf "Failed to update url_extract.txt."
                        NUMOFLINES=0
                    fi
                    notification "${NUMOFLINES} new URLs with parameters" "info"
                    # Asset store: append new URLs
                    append_assets_from_file url value webs/url_extract.txt
                else
                    NUMOFLINES=0
                fi

                if [[ -s "webs/url_extract.txt" ]]; then
                    p1radup -i webs/url_extract.txt -o webs/url_extract_nodupes.txt -s 2>>"$LOGFILE" >/dev/null || true

                    if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/url_extract.txt) -le $DEEP_LIMIT2 ]]; then
                        notification "Sending URLs to proxy" "info"
                        run_command ffuf -mc all -w webs/url_extract.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
                    fi
                else
                    _print_msg WARN "No URL extraction output generated; skipping p1radup/proxy replay."
                    log_note "No URL extraction output generated; skipping p1radup/proxy replay." "${FUNCNAME[0]}" "${LINENO}"
                    end_message="No URL extraction output generated."
                fi
            else
                end_message="No URL extraction candidates generated."
                _print_msg WARN "No URL extraction candidates generated."
            fi
        else
            end_message="No web targets available for URL extraction."
            _print_msg WARN "No web targets available for URL extraction."
        fi
        if [[ "$end_message" == No\ * ]]; then
            end_func "${end_message}" "${FUNCNAME[0]}" "SKIP_NOINPUT"
        else
            end_func "${end_message}" "${FUNCNAME[0]}"
        fi
    else
        if [[ $URL_CHECK == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi

}

function url_gf() {

    # Create necessary directories
    if ! mkdir -p .tmp webs gf; then
        print_warnf "Failed to create directories."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_GF == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        if ! command -v gf >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: gf not found in PATH"
            return 0
        fi
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
                _print_msg INFO "Running: GF Pattern '${pattern}'"
                if [[ $pattern == "potential" ]]; then
                    # Special handling for 'potential' pattern
                    run_command gf "$pattern" "webs/url_extract.txt" | cut -d ':' -f3-5 | anew -q "$output_file"
                elif [[ $pattern == "redirect" && -s "gf/ssrf.txt" ]]; then
                    # Append SSFR results to redirect if ssrf.txt exists
                    run_command gf "$pattern" "webs/url_extract.txt" | anew -q "$output_file"
                else
                    # General handling for other patterns
                    run_command gf "$pattern" "webs/url_extract.txt" | anew -q "$output_file"
                fi
            done

            # Process endpoints extraction
            if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
                _print_msg INFO "Extracting endpoints..."
                grep -aEiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" ".tmp/url_extract_tmp.txt" \
                    | unfurl -u format '%s://%d%p' 2>>"$LOGFILE" | anew -q "gf/endpoints.txt"
            fi

        else
            end_func "No webs/url_extract.txt file found, URL_GF check skipped." "${FUNCNAME[0]}"
            return
        fi

        end_func "Results are saved in $domain/gf folder" "${FUNCNAME[0]}"
    else
        if [[ $URL_GF == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi

}

function url_ext() {

    # Create necessary directories
    if ! mkdir -p .tmp webs gf; then
        print_warnf "Failed to create directories."
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
                print_warnf "Failed to initialize webs/urls_by_ext.txt."
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
        if [[ $URL_EXT == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi

}

function jschecks() {

    # Create necessary directories
    if ! mkdir -p .tmp webs subdomains js; then
        print_warnf "Failed to create directories."
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

            [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && printf "%bRunning: Fetching URLs 1/6%b\n" "$yellow" "$reset"
            if [[ $AXIOM != true ]]; then
                subjs -ua "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -c 40 <.tmp/url_extract_js.txt \
                    | grep -F "$domain" \
                    | grep -aEo 'https?://[^ ]+' | anew -q .tmp/subjslinks.txt || true
            else
                run_command axiom-scan .tmp/url_extract_js.txt -m subjs -o .tmp/subjslinks.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi

                if [[ -s ".tmp/subjslinks.txt" ]]; then
                    grep -Eiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" .tmp/subjslinks.txt \
                        | anew -q js/nojs_links.txt || true
                    grep -iE '\.js([?#].*)?$|\.js([/?&].*)' .tmp/subjslinks.txt | anew -q .tmp/url_extract_js.txt || true
                fi

            urless <.tmp/url_extract_js.txt \
                | anew -q js/url_extract_js.txt 2>>"$LOGFILE" >/dev/null

	            [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && printf "%bRunning: Resolving JS URLs 2/6%b\n" "$yellow" "$reset"
	            if [[ $AXIOM != true ]]; then
	                if [[ -s "js/url_extract_js.txt" ]]; then
	                    run_command httpx -follow-redirects -random-agent -silent -timeout "$HTTPX_TIMEOUT" -threads "$HTTPX_THREADS" \
	                        -rl "$HTTPX_RATELIMIT" -status-code -content-type -retries 2 -no-color <js/url_extract_js.txt \
	                        | awk '/\\[200\\]/ && /javascript/ {print $1}' | anew -q js/js_livelinks.txt || true
	                fi
	            else
	                if [[ -s "js/url_extract_js.txt" ]]; then
	                    run_command axiom-scan js/url_extract_js.txt -m httpx -follow-host-redirects -H "$HEADER" -status-code \
	                        -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" -silent \
	                        -content-type -retries 2 -no-color -o .tmp/js_livelinks.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
	                    if [[ -s ".tmp/js_livelinks.txt" ]]; then
	                        awk '/\\[200\\]/ && /javascript/ {print $1}' .tmp/js_livelinks.txt | anew -q js/js_livelinks.txt || true
	                    fi
	                fi
	            fi

            [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && printf "%bRunning: Extracting JS from sourcemaps 3/6%b\n" "$yellow" "$reset"
            if ! mkdir -p .tmp/sourcemapper; then
                print_warnf "Failed to create sourcemapper directory."
            fi
            if [[ -s "js/js_livelinks.txt" ]]; then
                run_command interlace -tL js/js_livelinks.txt -threads "$INTERLACE_THREADS" \
                    -c "sourcemapper -jsurl '_target_' -output _output_/_cleantarget_" \
                    -o .tmp/sourcemapper 2>>"$LOGFILE" >/dev/null
            fi

            if [[ -s ".tmp/url_extract_jsmap.txt" ]]; then
                run_command interlace -tL .tmp/url_extract_jsmap.txt -threads "$INTERLACE_THREADS" \
                    -c "sourcemapper -url '_target_' -output _output_/_cleantarget_" \
                    -o .tmp/sourcemapper 2>>"$LOGFILE" >/dev/null
            fi

            find .tmp/sourcemapper/ \( -name "*.js" -o -name "*.ts" \) -type f \
                | run_command jsluice urls | jq -r .url | anew -q .tmp/js_endpoints.txt || true

            [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && printf "%bRunning: Gathering endpoints 4/6%b\n" "$yellow" "$reset"
            if [[ -s "js/js_livelinks.txt" ]]; then
                xnLinkFinder -i js/js_livelinks.txt -sf subdomains/subdomains.txt -d "$XNLINKFINDER_DEPTH" \
                    -o .tmp/js_endpoints.txt 2>>"$LOGFILE" >/dev/null
            fi

            if [[ -s ".tmp/js_endpoints.txt" ]]; then
                sed_i '/^\//!d' .tmp/js_endpoints.txt
                cat .tmp/js_endpoints.txt | anew -q js/js_endpoints.txt || true
            fi

            [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && printf "%bRunning: Gathering secrets 5/6%b\n" "$yellow" "$reset"
            if [[ -s "js/js_livelinks.txt" ]]; then
                if [[ $AXIOM != true ]]; then
                    cat js/js_livelinks.txt | mantra -ua \"$HEADER\" -s | anew -q js/js_secrets.txt 2>>"$LOGFILE" >/dev/null || true
                else
                    axiom-exec "go install github.com/Brosck/mantra@latest" 2>>"$LOGFILE" >/dev/null
                    run_command axiom-scan js/js_livelinks.txt -m mantra -ua "$HEADER" -s -o js/js_secrets.txt "$AXIOM_EXTRA_ARGS" &>/dev/null
                fi
                mkdir -p .tmp/sourcemapper/secrets
                if [[ -s "js/js_secrets.txt" ]]; then
                    while IFS= read -r i; do
                        [[ -z "$i" ]] && continue
                        run_command wget -q -P .tmp/sourcemapper/secrets -- "$i" || true
                    done < <(cut -d' ' -f2 js/js_secrets.txt)
                fi
                run_command trufflehog filesystem .tmp/sourcemapper/ -j 2>/dev/null | jq -c | anew -q js/js_secrets_jsmap.txt
                find .tmp/sourcemapper/ -type f -name "*.js" | run_command jsluice secrets -j --patterns="${PATTERNS_DIR}/jsluice_patterns.json" | anew -q js/js_secrets_jsmap_jsluice.txt
            fi

            [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && printf "%bRunning: Building wordlist 6/6%b\n" "$yellow" "$reset"
            if [[ -s "js/js_livelinks.txt" ]]; then
                if [[ -n "${GETJSWORDS_VENV:-}" ]]; then
                    if [[ -f "${GETJSWORDS_VENV}/bin/activate" ]]; then
                        (
                            # shellcheck source=/dev/null
                            source "${GETJSWORDS_VENV}/bin/activate"
                            if python3 -c "import jsbeautifier, requests" 2>/dev/null; then
                                run_command interlace -tL js/js_livelinks.txt -threads "$INTERLACE_THREADS" \
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
                        run_command interlace -tL js/js_livelinks.txt -threads "$INTERLACE_THREADS" \
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
            skip_notification "disabled"
        else
            skip_notification "processed"
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
                code=$(run_command curl -sk --http1.1 -o /dev/null -w '%{http_code}' \
                    -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
                    -H "Host: $host" \
                    -H "Sec-WebSocket-Key: $wskey" \
                    -H 'Sec-WebSocket-Version: 13' \
                    "$ws" || true)
                if [[ $code == "101" ]]; then
                    printf "HANDSHAKE %s\n" "$ws" | anew -q vulns/websockets.txt || true
                    # Origin test: send a cross-origin header, expect failure ideally
                    wskey2=$(head -c 16 /dev/urandom | base64 2>/dev/null || echo dGVzdGtleQ==)
                    code2=$(run_command curl -sk --http1.1 -o /dev/null -w '%{http_code}' \
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
        skip_notification "processed"
    fi
}

function wordlist_gen() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WORDLIST == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Wordlist Generation"

        [[ -s ".tmp/url_extract_tmp.txt" ]] && cat webs/url_extract.txt | anew -q .tmp/url_extract_tmp.txt || true
        # Ensure url_extract_tmp.txt exists and is not empty
        if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
            # Define patterns for keys and values
            cat ".tmp/url_extract_tmp.txt" | unfurl -u keys 2>>"$LOGFILE" \
                | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' \
                | anew -q webs/dict_keys.txt || true

            cat ".tmp/url_extract_tmp.txt" | unfurl -u values 2>>"$LOGFILE" \
                | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' \
                | anew -q webs/dict_values.txt || true

            _print_msg INFO "Extracting words..."
            tr "[:punct:]" "\n" <".tmp/url_extract_tmp.txt" | anew -q "webs/dict_words.txt" || true
        fi

        end_func "Results are saved in $domain/webs/dict_[words|paths].txt" "${FUNCNAME[0]}"

    else
        if [[ $WORDLIST == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi

}

function wordlist_gen_roboxtractor() {

    # Create necessary directories
    if ! mkdir -p .tmp webs gf; then
        print_warnf "Failed to create directories."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $ROBOTSWORDLIST == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Robots Wordlist Generation"

        ensure_webs_all || true

        # Proceed only if webs_all.txt exists and is non-empty
        if [[ -s "webs/webs_all.txt" ]]; then
            # Extract URLs using roboxtractor and append unique entries to robots_wordlist.txt
            _print_msg INFO "Running: Roboxtractor for Robots Wordlist"
            roboxtractor -m 1 -wb <"webs/webs_all.txt" 2>>"$LOGFILE" | anew -q "webs/robots_wordlist.txt"
        else
            end_func "No webs/webs_all.txt file found, Robots Wordlist generation skipped." "${FUNCNAME[0]}"
            return
        fi

        end_func "Results are saved in $domain/webs/robots_wordlist.txt" "${FUNCNAME[0]}"

        # Handle Proxy if conditions are met
        if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ "$(wc -l <"webs/robots_wordlist.txt")" -le $DEEP_LIMIT2 ]]; then
            notification "Sending URLs to proxy" info
            run_command ffuf -mc all -w "webs/robots_wordlist.txt" -u "FUZZ" -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
        fi

    else
        if [[ $ROBOTSWORDLIST == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi

}

function password_dict() {

    # Create necessary directories
    if ! mkdir -p "$dir/webs" "$dir/.tmp"; then
        print_warnf "Failed to create directories."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PASSWORD_DICT == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Password Dictionary Generation"

        local dict_engine="${PASSWORD_DICT_ENGINE:-cewler}"
        local dict_output="$dir/webs/password_dict.txt"
        : >"$dict_output"

        # Ensure web targets exist for cewler.
        ensure_webs_all || true

        if [[ "$dict_engine" == "cewler" ]]; then
            local cewler_cmd=()
            if command -v cewler >/dev/null 2>&1; then
                cewler_cmd=(cewler)
            fi

            if [[ ${#cewler_cmd[@]} -gt 0 ]] && [[ -s "webs/webs_all.txt" ]]; then
                local max_targets="${PASSWORD_DICT_MAX_TARGETS:-50}"
                if [[ ${DEEP:-false} == true ]]; then
                    max_targets=0
                fi
                if [[ "$max_targets" -gt 0 ]]; then
                    head -n "$max_targets" "webs/webs_all.txt" >".tmp/password_dict_targets.txt"
                else
                    cp "webs/webs_all.txt" ".tmp/password_dict_targets.txt"
                fi

                : >".tmp/password_dict_raw.txt"
                while IFS= read -r target; do
                    [[ -z "$target" ]] && continue
                    if [[ -n "${TIMEOUT_CMD:-}" ]]; then
                        run_command "$TIMEOUT_CMD" -k 5s "${PASSWORD_DICT_CEWLER_TIMEOUT:-45}" "${cewler_cmd[@]}" \
                            -d "${PASSWORD_DICT_CEWLER_DEPTH:-1}" -m "${PASSWORD_MIN_LENGTH:-5}" \
                            -l -o ".tmp/password_dict_part.txt" "$target" 2>>"$LOGFILE" >/dev/null || true
                    else
                        run_command "${cewler_cmd[@]}" \
                            -d "${PASSWORD_DICT_CEWLER_DEPTH:-1}" -m "${PASSWORD_MIN_LENGTH:-5}" \
                            -l -o ".tmp/password_dict_part.txt" "$target" 2>>"$LOGFILE" >/dev/null || true
                    fi
                    if [[ -s ".tmp/password_dict_part.txt" ]]; then
                        cat ".tmp/password_dict_part.txt" >>".tmp/password_dict_raw.txt"
                        : >".tmp/password_dict_part.txt"
                    fi
                done <".tmp/password_dict_targets.txt"

                if [[ -s ".tmp/password_dict_raw.txt" ]]; then
                    awk -v min="${PASSWORD_MIN_LENGTH:-5}" -v max="${PASSWORD_MAX_LENGTH:-14}" '
                        {
                            w=$0;
                            gsub(/[^a-z0-9._-]/, "", w);
                            if (length(w) >= min && length(w) <= max) print w;
                        }' ".tmp/password_dict_raw.txt" | sort -u >"$dict_output"
                fi
            fi
        fi

        # Fallback to pydictor when cewler is unavailable/empty or explicitly requested.
        if [[ ! -s "$dict_output" ]] || [[ "$dict_engine" == "pydictor" ]]; then
            local word="${domain%%.*}"
            if [[ -s "${tools}/pydictor/pydictor.py" ]]; then
                run_command python3 "${tools}/pydictor/pydictor.py" -extend "$word" --leet 0 1 2 11 21 --len "$PASSWORD_MIN_LENGTH" "$PASSWORD_MAX_LENGTH" -o "$dict_output" 2>>"$LOGFILE" >/dev/null
                [[ "$dict_engine" == "cewler" ]] && log_note "password_dict: cewler unavailable/empty, pydictor fallback used" "${FUNCNAME[0]}" "${LINENO}"
            elif [[ "$dict_engine" == "cewler" ]]; then
                log_note "password_dict: cewler and pydictor unavailable, skipping output generation" "${FUNCNAME[0]}" "${LINENO}"
            fi
        fi

        end_func "Results are saved in $domain/webs/password_dict.txt" "${FUNCNAME[0]}"

        # Optionally, create a marker file to indicate the function has been processed
        touch "$called_fn_dir/.${FUNCNAME[0]}"

    else
        if [[ $PASSWORD_DICT == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi

}

###############################################################################################################
######################################### VULNERABILITIES #####################################################
###############################################################################################################

function brokenLinks() {

    # Create necessary directories
    if ! mkdir -p .tmp webs vulns; then
        print_warnf "Failed to create directories."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $BROKENLINKS == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

	        start_func "${FUNCNAME[0]}" "Broken Links Checks"

	        ensure_webs_all || true

	        # Check if webs_all.txt exists and is not empty
	        if [[ -s "webs/webs_all.txt" ]]; then
	            local bl_engine="${BROKENLINKS_ENGINE:-second-order}"
	            if [[ "$bl_engine" == "second-order" ]]; then
                local so_depth="${SECOND_ORDER_DEPTH:-1}"
                [[ $DEEP == true ]] && so_depth=$((so_depth + 1))

                rm -rf ".tmp/second_order" >/dev/null 2>&1 || true
                mkdir -p ".tmp/second_order"
                : >".tmp/brokenLinks_total.txt"

                while IFS= read -r target; do
                    [[ -z "$target" ]] && continue
                    local safe_target
                    safe_target=$(echo "$target" | sed 's|https\?://||; s|[^A-Za-z0-9._-]|_|g')
                    local out_dir=".tmp/second_order/${safe_target}"
                    mkdir -p "$out_dir"

                    local so_cmd=(
                        second-order
                        -target "$target"
                        -config "${SECOND_ORDER_CONFIG:-${tools}/second-order/config/takeover.json}"
                        -depth "$so_depth"
                        -threads "${SECOND_ORDER_THREADS:-10}"
                        -output "$out_dir"
                    )
                    if [[ ${SECOND_ORDER_INSECURE:-false} == true ]]; then
                        so_cmd+=(-insecure)
                    fi
                    if [[ -n "${HEADER:-}" ]]; then
                        so_cmd+=(-header "${HEADER}")
                    fi

                    run_command "${so_cmd[@]}" 2>>"$LOGFILE" >/dev/null || true

                    if [[ -s "${out_dir}/non-200-url-attributes.json" ]]; then
                        jq -r 'to_entries[]?.value | to_entries[]?.value[]? // empty' "${out_dir}/non-200-url-attributes.json" 2>/dev/null \
                            | grep -aE '^https?://' \
                            | anew -q ".tmp/brokenLinks_total.txt"
                    fi
                done <"webs/webs_all.txt"
            else
                local katana_legacy_headless=""
                katana_legacy_headless=$(_katana_headless_flags "$(wc -l <webs/webs_all.txt 2>/dev/null || echo 0)")
                if [[ $AXIOM != true ]]; then
                    # Use katana for scanning
                    if [[ ! -s ".tmp/katana.txt" ]]; then
                        if [[ $DEEP == true ]]; then
                            timeout 4h katana -silent -list "webs/webs_all.txt" $katana_legacy_headless -jc -kf all -c "$KATANA_THREADS" -d 3 -o ".tmp/katana.txt" 2>>"$LOGFILE" >/dev/null
                        else
                            timeout 3h katana -silent -list "webs/webs_all.txt" $katana_legacy_headless -jc -kf all -c "$KATANA_THREADS" -d 2 -o ".tmp/katana.txt" 2>>"$LOGFILE" >/dev/null
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
                            run_command axiom-scan "webs/webs_all.txt" -m katana $katana_legacy_headless -jc -kf all -d 3 --max-runtime 4h -o ".tmp/katana.txt" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
                        else
                            run_command axiom-scan "webs/webs_all.txt" -m katana $katana_legacy_headless -jc -kf all -d 2 --max-runtime 3h -o ".tmp/katana.txt" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
                        fi
                        # Remove lines longer than 2048 characters
                        if [[ -s ".tmp/katana.txt" ]]; then
                            sed_i '/^.\{2048\}./d' ".tmp/katana.txt"
                        fi
                    fi
                fi

                # Process katana.txt to find broken links
                if [[ -s ".tmp/katana.txt" ]]; then
                    run_command httpx -follow-redirects -random-agent -status-code -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" -silent -retries 2 -no-color <".tmp/katana.txt" 2>>"$LOGFILE" \
                        | grep "\[4" | cut -d ' ' -f1 | anew -q ".tmp/brokenLinks_total.txt"
                fi
            fi

            # Update brokenLinks.txt with unique entries
            if [[ -s ".tmp/brokenLinks_total.txt" ]]; then
                cat ".tmp/brokenLinks_total.txt" | anew -q "vulns/brokenLinks.txt"
                NUMOFLINES=$(sed '/^$/d' "vulns/brokenLinks.txt" | wc -l)
                notification "${NUMOFLINES} broken links found" info
            fi

            end_func "Results are saved in vulns/brokenLinks.txt" "${FUNCNAME[0]}"
        else
            end_func "No webs/webs_all.txt file found, Broken Links check skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        if [[ $BROKENLINKS == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi

}
