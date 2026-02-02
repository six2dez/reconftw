#!/bin/bash
# shellcheck disable=SC2154  # Variables defined in reconftw.cfg
# reconFTW - Mode/workflow orchestration module
# Contains: start, end, build_hotlist, passive, osint, all, vulns,
#           multi_osint, recon, multi_recon, multi_custom,
#           subs_menu, webs_menu, zen_menu, help
# This file is sourced by reconftw.sh - do not execute directly
[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by reconftw.sh" >&2
    exit 1
}

function start() {

    global_start=$(date +%s)

    # Validate configuration before starting
    validate_config || exit $?

    # Check available disk space before starting (require at least 5GB by default)
    local required_space_gb="${MIN_DISK_SPACE_GB:-5}"
    if ! check_disk_space "$required_space_gb" "."; then
        printf "%b[%s] WARNING: Low disk space detected. Continuing anyway...%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
        # Not exiting, just warning - user can set MIN_DISK_SPACE_GB=0 to disable
    fi

    # Raise ulimit for long-running VPS jobs (fail-soft on failure)
    if [[ ${RAISE_ULIMIT:-true} == "true" ]]; then
        ULIMIT_TARGET=${ULIMIT_TARGET:-65535}
        ulimit -n "$ULIMIT_TARGET" 2>>"${LOGFILE:-/dev/null}" >/dev/null || true
    fi

    # Log version and key flags
    {
        printf "[%s] reconFTW version: %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$reconftw_version"
        printf "[%s] Flags: OSINT=%s SUBDOMAINS_GENERAL=%s VULNS_GENERAL=%s DEEP=%s\n" \
            "$(date +'%Y-%m-%d %H:%M:%S')" "$OSINT" "$SUBDOMAINS_GENERAL" "$VULNS_GENERAL" "$DEEP"
    } >>"${LOGFILE:-/dev/null}"
    if [[ $upgrade_before_running == true ]]; then
        ${SCRIPTPATH}/install.sh --tools
    fi
    tools_installed

    # Initialize incremental mode if enabled
    incremental_init

    #[[ -n "$domain" ]] && ipcidr_target $domain

    if [[ -z $domain ]]; then
        if [[ -n $list ]]; then
            if [[ -z $domain ]]; then
                domain="Multi"
                dir="${SCRIPTPATH}/Recon/$domain"
                called_fn_dir="$dir"/.called_fn
            fi
            if [[ $list == /* ]]; then
                mkdir -p "$dir/webs"
                cp "$list" "$dir/webs/webs.txt"
            else
                mkdir -p "$dir/webs"
                cp "${SCRIPTPATH}/${list}" "$dir/webs/webs.txt"
            fi
        fi
    else
        dir="${SCRIPTPATH}/Recon/$domain"
        called_fn_dir="$dir"/.called_fn
    fi

    if [[ -z $domain ]]; then
        notification "${bred} No domain or list provided ${reset}\n\n" error
        exit
    fi

    if [[ ! -d $called_fn_dir ]]; then
        mkdir -p "$called_fn_dir"
    fi
    mkdir -p "$dir"
    cd "$dir" || {
        echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    if [[ $AXIOM == true ]]; then
        if [[ -n $domain ]]; then
            echo "$domain" | anew -q target.txt
            list="${dir}/target.txt"
        fi
    fi
    mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}
    chmod 700 .tmp 2>/dev/null || true

    # Load plugins and emit start event
    plugins_load
    plugins_emit start "$domain" "$dir"

    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
    touch ".log/${NOW}_${NOWT}.txt"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"
    enable_command_trace

    # Rotate old log files
    rotate_logs "${dir}/.log" "${MAX_LOG_FILES:-10}" "${MAX_LOG_AGE_DAYS:-30}"

    # Trap for cleanup on unexpected exit
    trap 'cleanup_on_exit' INT TERM

    # Initialize structured logging if enabled
    log_init

    # Initialize cache for wordlists/resolvers
    cache_init

    # init time saved estimator
    TIME_SAVED_EST=0

    # Non-fatal error trap: log and continue
    trap 'rc=$?; ts=$(date +"%Y-%m-%d %H:%M:%S"); cmd=${BASH_COMMAND}; loc_fn=${FUNCNAME[0]:-main}; loc_ln=${BASH_LINENO[0]:-0}; msg="[$ts] ERR($rc) @ ${loc_fn}:${loc_ln} :: ${cmd}"; if [[ -n "${LOGFILE:-}" ]]; then echo "$msg" >>"$LOGFILE"; else echo "$msg" >&2; fi' ERR

    printf "\n"
    printf "${bred}[$(date +'%Y-%m-%d %H:%M:%S')] Target: ${domain}\n\n"
    printf "%b[LEGAL]%b Authorized testing only. By running this scan you confirm you have explicit permission for the specified targets and will comply with all applicable laws and program rules. Unauthorized use is prohibited.\n\n" "$yellow" "$reset"
}

function end() {

    if [[ $opt_ai ]]; then
        notification "[$(date +'%Y-%m-%d %H:%M:%S')] Sending ${domain} data to AI" info
        mkdir -p "${dir}/ai_result" 2>>"${LOGFILE}"
        "${tools}/reconftw_ai/venv/bin/python3" "${tools}/reconftw_ai/reconftw_ai.py" --results-dir ${dir} --output-dir ${dir}/ai_result --model ${AI_MODEL} --output-format ${AI_REPORT_TYPE} --report-type ${AI_REPORT_PROFILE} --prompts-file ${tools}/reconftw_ai/prompts.json 2>>"${LOGFILE}" >/dev/null
    fi

    find "$dir" -type f -empty -print | grep -v '.called_fn' | grep -v '.log' | grep -v '.tmp' | xargs -r rm -f -- 2>>"$LOGFILE" >/dev/null
    find "$dir" -type d -empty -print -delete 2>>"$LOGFILE" >/dev/null

    echo "[$(date +'%Y-%m-%d %H:%M:%S')] End" >>"${LOGFILE}"

    if [[ $PRESERVE != true ]]; then
        find "$dir" -type f -empty | grep -v "called_fn" | xargs -r rm -f -- 2>>"$LOGFILE" >/dev/null
        find "$dir" -type d -empty | grep -v "called_fn" | xargs -r rm -rf -- 2>>"$LOGFILE" >/dev/null
    fi

    if [[ $REMOVETMP == true ]]; then
        rm -rf -- "$dir/.tmp"
    fi

    if [[ $REMOVELOG == true ]]; then
        rm -rf -- "$dir/.log"
    fi

    if [[ $FARADAY == true ]]; then
        if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
            printf "%b[!] Faraday server is not running. Skipping Faraday integration.%b\n" "$bred" "$reset"
        else
            if [[ -s ".tmp/tko_json.txt" ]]; then
                faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei .tmp/tko_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "hosts/portscan_active.xml" ]]; then
                faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nmap hosts/portscan_active.xml 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s ".tmp/fuzzparams_json.txt" ]]; then
                faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei .tmp/fuzzparams_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "nuclei_output/info_json.txt" ]]; then
                faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei nuclei_output/info_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "nuclei_output/low_json.txt" ]]; then
                faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei nuclei_output/low_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "nuclei_output/medium_json.txt" ]]; then
                faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei nuclei_output/medium_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "nuclei_output/high_json.txt" ]]; then
                faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei nuclei_output/high_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "nuclei_output/critical_json.txt" ]]; then
                faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei nuclei_output/critical_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            notification "Information sent to Faraday" "good"
        fi
    fi

    if [[ -n $dir_output ]]; then
        output
        finaldir=$dir_output
    else
        finaldir=$dir
    fi
    #Zip the output folder and send it via tg/discord/slack
    if [[ $SENDZIPNOTIFY == true ]]; then
        zipSnedOutputFolder
    fi

    # Screenshot diffs (hashing)
    if [[ -d screenshots ]]; then
        if [[ -f screenshots/hashes.txt ]]; then mv screenshots/hashes.txt screenshots/hashes_prev.txt 2>>"$LOGFILE" || true; fi
        find screenshots -type f -name '*.png' -print0 | xargs -0 -I{} sh -c 'sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"' -- {} | sed 's|  ./||' >screenshots/hashes.txt 2>>"$LOGFILE" || true
        if [[ -f screenshots/hashes_prev.txt ]]; then
            comm -3 <(cut -d' ' -f1,2 screenshots/hashes_prev.txt | sort) <(cut -d' ' -f1,2 screenshots/hashes.txt | sort) | awk '{print $2}' | sed '/^$/d' >screenshots/diff_changed.txt 2>>"$LOGFILE" || true
        fi
    fi

    # Emit end plugin event
    plugins_emit end "$domain" "$dir"

    # Build hotlist (risk summary)
    build_hotlist || true

    # Incremental mode report
    incremental_report

    global_end=$(date +%s)
    getElapsedTime $global_start $global_end
    printf "${bgreen}#######################################################################${reset}\n"
    notification "Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" good "$(date +'%Y-%m-%d %H:%M:%S')"
    [ "$SOFT_NOTIFICATION" = true ] && echo "[$(date +'%Y-%m-%d %H:%M:%S')] Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" | notify -silent
    printf "${bgreen}#######################################################################${reset}\n"

    # Print performance timing summary
    print_timing_summary

}

function build_hotlist() {
    mkdir -p .tmp
    declare -A score
    # Nuclei high/critical
    for f in nuclei_output/high_json.txt nuclei_output/critical_json.txt; do
        [[ -s $f ]] || continue
        jq -r '.["matched-at"] // .host' "$f" 2>/dev/null | while read -r h; do
            [[ -z $h ]] && continue
            score["$h"]=$((${score["$h"]:-0} + 10))
        done
    done
    # Takeovers
    [[ -s webs/takeover.txt ]] && while read -r h; do score["$h"]=$((${score["$h"]:-0} + 8)); done <webs/takeover.txt
    # Secrets
    for s in js/js_secrets.txt js/js_secrets_jsmap.txt js/js_secrets_jsmap_jsluice.txt; do
        [[ -s $s ]] || continue
        awk '{print $1}' "$s" | while read -r h; do score["$h"]=$((${score["$h"]:-0} + 6)); done
    done
    # Real IPs via favicon
    if [[ -s hosts/favicontest.txt ]]; then
        while read -r ip; do
            score["$ip"]=$((${score["$ip"]:-0} + 4))
        done <hosts/favicontest.txt
    fi
    # New assets bonus
    for p in .tmp/subs_new_only.txt webs/url_extract.txt; do
        [[ -s $p ]] || continue
        while read -r l; do
            host=$(echo "$l" | unfurl -u domains 2>/dev/null)
            [[ -z $host ]] && continue
            score["$host"]=$((${score["$host"]:-0} + 2))
        done <"$p"
    done
    # Emit hotlist sorted
    {
        for k in "${!score[@]}"; do printf "%s %s\n" "${score[$k]}" "$k"; done | sort -nr | head -n "${HOTLIST_TOP:-50}"
    } >hotlist.txt
    [[ -s hotlist.txt ]] && notification "Hotlist ready (top ${HOTLIST_TOP:-50})" info
}

###############################################################################################################
########################################### MODES & MENUS #####################################################
###############################################################################################################

function passive() {
    start
    domain_info
    ip_info
    emails
    google_dorks
    #github_dorks
    github_repos
    metadata
    apileaks
    third_party_misconfigs
    SUBNOERROR=false
    SUBANALYTICS=false
    SUBBRUTE=false
    SUBSCRAPING=false
    SUBPERMUTE=false
    SUBREGEXPERMUTE=false
    SUB_RECURSIVE_BRUTE=false
    WEBPROBESIMPLE=false
    if [[ $AXIOM == true ]]; then
        axiom_launch
        axiom_selected
    fi

    subdomains_full
    remove_big_files
    favicon
    cdnprovider
    PORTSCAN_ACTIVE=false
    portscan
    geo_info

    if [[ $AXIOM == true ]]; then
        axiom_shutdown
    fi

    end
}

function all() {
    start
    recon
    vulns
    end
}

function osint() {
    domain_info
    ip_info
    emails
    google_dorks
    #github_dorks
    github_repos
    metadata
    apileaks
    third_party_misconfigs
    zonetransfer
    favicon
    mail_hygiene
    cloud_enum_scan
}

function vulns() {
    if [[ $VULNS_GENERAL == true ]]; then
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
        fuzzparams
        4xxbypass
        test_ssl
    fi
}

function multi_osint() {

    global_start=$(date +%s)

    #[[ -n "$domain" ]] && ipcidr_target $domain

    if [[ -s "$list" ]]; then
        sed_i 's/\r$//' "$list"
    else
        notification "Target list not provided" error
        exit
    fi

    workdir="${SCRIPTPATH}/Recon/${multi}"
    mkdir -p "$workdir" || {
        echo "Failed to create directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}

    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
    touch ".log/${NOW}_${NOWT}.txt"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"
    enable_command_trace

    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        dir="$workdir/targets/$domain"
        called_fn_dir="$dir/.called_fn"
        mkdir -p "$dir"
        cd "$dir" || {
            echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }
        mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}
        NOW=$(date +"%F")
        NOWT=$(date +"%T")
        LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
        touch ".log/${NOW}_${NOWT}.txt"
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"
        domain_info
        ip_info
        emails
        google_dorks
        #github_dorks
        github_repos
        metadata
        apileaks
        third_party_misconfigs
        zonetransfer
        favicon
    done <"$list"
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    dir=$workdir
    domain=$multi
    end
}

function recon() {
    domain_info
    ip_info
    emails
    google_dorks
    #github_dorks
    github_repos
    metadata
    apileaks
    third_party_misconfigs
    zonetransfer
    favicon

    if [[ $AXIOM == true ]]; then
        axiom_launch
        axiom_selected
    fi

    subdomains_full
    webprobe_full
    subtakeover
    remove_big_files
    s3buckets
    cloud_extra_providers
    screenshot
    #	virtualhosts
    cdnprovider
    portscan
    geo_info
    # Quick-rescan gating
    subs_new=$(cat .tmp/subs_new_count 2>/dev/null || echo 1)
    webs_new=$(cat .tmp/webs_new_count 2>/dev/null || echo 1)
    if [[ $QUICK_RESCAN == true && $subs_new -eq 0 && $webs_new -eq 0 ]]; then
        notification "Quick rescan: no new subs/webs; skipping heavy web stages" info
        # estimate time saved for skipped modules
        TIME_SAVED_EST=$((${TIME_SAVED_EST:-0} + \
            ${TIME_EST_WAF:-0} + ${TIME_EST_NUCLEI:-600} + ${TIME_EST_API:-300} + ${TIME_EST_GQL:-180} + \
            ${TIME_EST_FUZZ:-900} + ${TIME_EST_IIS:-60} + ${TIME_EST_URLCHECKS:-300} + ${TIME_EST_JSCHECKS:-300} + \
            ${TIME_EST_PARAM:-240} + ${TIME_EST_GRPC:-120}))
    else
        waf_checks
        nuclei_check
        graphql_scan
        fuzz
        iishortname
        urlchecks
        jschecks
        websocket_checks
        param_discovery
        grpc_reflection
    fi

    if [[ $AXIOM == true ]]; then
        axiom_shutdown
    fi

    cms_scanner
    url_gf
    wordlist_gen
    wordlist_gen_roboxtractor
    password_dict
    url_ext
}

function multi_recon() {

    [ "$SOFT_NOTIFICATION" = true ] && echo "$(date +'%Y-%m-%d %H:%M:%S') Recon successfully started on ${multi}" | notify -silent

    global_start=$(date +%s)

    #[[ -n "$domain" ]] && ipcidr_target $domain

    if [[ -s "$list" ]]; then
        sed_i 's/\r$//' "$list"
        mapfile -t targets <"$list"
    else
        notification "Target list not provided" error
        exit
    fi

    workdir="${SCRIPTPATH}/Recon/${multi}"
    mkdir -p "$workdir" || {
        echo "Failed to create directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }

    mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}
    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
    touch ".log/${NOW}_${NOWT}.txt"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"

    [ -n "$flist" ] && LISTTOTAL=$(wc -l <"$flist")

    for domain in "${targets[@]}"; do
        [[ -z "$domain" ]] && continue
        dir="$workdir/targets/$domain"
        called_fn_dir="$dir/.called_fn"

        # Ensure directories exist
        mkdir -p "$dir" || {
            echo "Failed to create directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }
        mkdir -p "$called_fn_dir" || {
            echo "Failed to create directory '$called_fn_dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }

        cd "$dir" || {
            echo "Failed to cd to directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }

        mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}

        NOW=$(date +"%F")
        NOWT=$(date +"%T")
        LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"

        # Ensure the .log directory exists before touching the file
        mkdir -p .log

        touch "$LOGFILE" || {
            echo "Failed to create log file: $LOGFILE"
            exit 1
        }
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"$LOGFILE"
        enable_command_trace
        loopstart=$(date +%s)

        domain_info
        ip_info
        emails
        google_dorks
        #github_dorks
        github_repos
        metadata
        apileaks
        third_party_misconfigs
        zonetransfer
        favicon
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime "$loopstart" "$loopend"
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen}[$(date +'%Y-%m-%d %H:%M:%S')] $domain finished 1st loop in ${runtime} $currently ${reset}\n"
        if [[ -n $flist ]]; then
            POSINLIST=$(grep -nrE "^${domain}$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] $domain is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }

    if [[ $AXIOM == true ]]; then
        axiom_launch
        axiom_selected
    fi

    for domain in "${targets[@]}"; do
        [[ -z "$domain" ]] && continue
        loopstart=$(date +%s)
        dir="$workdir/targets/$domain"
        called_fn_dir="$dir/.called_fn"
        cd "$dir" || {
            echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }
        subdomains_full
        webprobe_full
        subtakeover
        remove_big_files
        screenshot
        #		virtualhosts
        cdnprovider
        portscan
        geo_info
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime "$loopstart" "$loopend"
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen}[$(date +'%Y-%m-%d %H:%M:%S')] $domain finished 2nd loop in ${runtime} $currently ${reset}\n"
        if [[ -n $flist ]]; then
            POSINLIST=$(grep -nrE "^${domain}$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] $domain is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }

    notification "############################# Total data ############################" info
    NUMOFLINES_pwndb_total=$(find . -type f -name 'passwords.txt' -exec cat {} + | anew osint/passwords.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_subs_total=$(find . -type f -name 'subdomains.txt' -exec cat {} + | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_subtko_total=$(find . -type f -name 'takeover.txt' -exec cat {} + | anew webs/takeover.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_webs_total=$(find . -type f -name 'webs.txt' -exec cat {} + | anew webs/webs.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_webs_total_uncommon=$(find . -type f -name 'webs_uncommon_ports.txt' -exec cat {} + | anew webs/webs_uncommon_ports.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_ips_total=$(find . -type f -name 'ips.txt' -exec cat {} + | anew hosts/ips.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_cloudsprov_total=$(find . -type f -name 'cdn_providers.txt' -exec cat {} + | anew hosts/cdn_providers.txt | sed '/^$/d' | wc -l)
    find . -type f -name 'portscan_active.gnmap' -exec cat {} + | tee hosts/portscan_active.gnmap 2>>"$LOGFILE" >/dev/null
    find . -type f -name 'portscan_passive.txt' -exec cat {} + | tee hosts/portscan_passive.txt 2>&1 >>"$LOGFILE" >/dev/null

    notification "- ${NUMOFLINES_pwndb_total} total creds leaked" good
    notification "- ${NUMOFLINES_subs_total} total subdomains" good
    notification "- ${NUMOFLINES_subtko_total} total probably subdomain takeovers" good
    notification "- ${NUMOFLINES_webs_total} total websites" good
    notification "- ${NUMOFLINES_webs_total_uncommon} total websites on uncommon ports" good
    notification "- ${NUMOFLINES_ips_total} total ips" good
    notification "- ${NUMOFLINES_cloudsprov_total} total IPs belongs to cloud" good
    s3buckets
    waf_checks
    nuclei_check
    for domain in "${targets[@]}"; do
        [[ -z "$domain" ]] && continue
        loopstart=$(date +%s)
        dir="$workdir/targets/$domain"
        called_fn_dir="$dir/.called_fn"
        cd "$dir" || {
            echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }
        loopstart=$(date +%s)
        fuzz
        iishortname
        urlchecks
        jschecks
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime "$loopstart" "$loopend"
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen}[$(date +'%Y-%m-%d %H:%M:%S')] $domain finished 3rd loop in ${runtime} $currently ${reset}\n"
        if [[ -n $flist ]]; then
            POSINLIST=$(grep -nrE "^${domain}$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] $domain is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done

    if [[ $AXIOM == true ]]; then
        axiom_shutdown
    fi

    for domain in "${targets[@]}"; do
        [[ -z "$domain" ]] && continue
        loopstart=$(date +%s)
        dir="$workdir/targets/$domain"
        called_fn_dir="$dir/.called_fn"
        cd "$dir" || {
            echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
            exit 1
        }
        cms_scanner
        url_gf
        wordlist_gen
        wordlist_gen_roboxtractor
        password_dict
        url_ext
        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime "$loopstart" "$loopend"
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen}[$(date +'%Y-%m-%d %H:%M:%S')] $domain finished final loop in ${runtime} $currently ${reset}\n"
        if [[ -n $flist ]]; then
            POSINLIST=$(grep -nrE "^${domain}$" "$flist" | cut -f1 -d':')
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] $domain is $POSINLIST of $LISTTOTAL${reset}\n"
        fi
        printf "${bgreen}#######################################################################${reset}\n"
    done
    cd "$workdir" || {
        echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    dir=$workdir
    domain=$multi
    end
    [ "$SOFT_NOTIFICATION" = true ] && echo "$(date +'%Y-%m-%d %H:%M:%S') Finished Recon on: ${multi} in ${runtime}" | notify -silent
}

function multi_custom() {

    global_start=$(date +%s)

    if [[ -s "$list" ]]; then
        sed_i 's/\r$//' "$list"
    else
        notification "Target list not provided" error
        exit
    fi

    dir="${SCRIPTPATH}/Recon/${multi}"
    if [[ -z "$multi" || "$dir" != "${SCRIPTPATH}/Recon/"* ]]; then
        echo "[!] Refusing to remove '$dir' -- safety check failed"
        return 1
    fi
    rm -rf -- "$dir"
    mkdir -p "$dir" || {
        echo "Failed to create directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }
    cd "$dir" || {
        echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
        exit 1
    }

    mkdir -p {.called_fn,.log}
    called_fn_dir="$dir/.called_fn"
    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
    touch ".log/${NOW}_${NOWT}.txt"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"
    enable_command_trace

    [ -n "$flist" ] && entries=$(wc -l <"$flist")

    if [[ $AXIOM == true ]]; then
        axiom_launch
        axiom_selected
    fi

    custom_function_list=$(echo "$custom_function" | tr ',' '\n')
    func_total=$(echo "$custom_function_list" | wc -l)

    func_count=0
    domain=$(cat "$flist")
    for custom_f in $custom_function_list; do
        ((func_count = func_count + 1))

        loopstart=$(date +%s)

        $custom_f

        currently=$(date +"%H:%M:%S")
        loopend=$(date +%s)
        getElapsedTime "$loopstart" "$loopend"
        printf "${bgreen}#######################################################################${reset}\n"
        printf "${bgreen}[$(date +'%Y-%m-%d %H:%M:%S')] Finished $custom_f ($func_count/$func_total) for $entries entries in ${runtime} $currently ${reset}\n"
        printf "${bgreen}#######################################################################${reset}\n"
    done

    if [[ $AXIOM == true ]]; then
        axiom_shutdown
    fi

    end
}

function subs_menu() {
    start

    if [[ $AXIOM == true ]]; then
        axiom_launch
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

    if [[ $AXIOM == true ]]; then
        axiom_shutdown
    fi

    end
}

function webs_menu() {
    subtakeover
    remove_big_files
    screenshot
    #	virtualhosts
    waf_checks
    nuclei_check
    graphql_scan
    fuzz
    cms_scanner
    iishortname
    urlchecks
    jschecks
    websocket_checks
    url_gf
    wordlist_gen
    wordlist_gen_roboxtractor
    password_dict
    url_ext
    param_discovery
    grpc_reflection
    vulns
    end
}

function zen_menu() {
    start
    if [[ $AXIOM == true ]]; then
        axiom_launch
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
    waf_checks
    nuclei_check
    graphql_scan
    fuzz
    iishortname
    if [[ $AXIOM == true ]]; then
        axiom_shutdown
    fi
    cms_scanner
    end
}

function help() {
    pt_header "Usage"
    printf "\n Usage: $0 [-d domain.tld] [-m name] [-l list.txt] [-x oos.txt] [-i in.txt] "
    printf "\n           	      [-r] [-s] [-p] [-a] [-w] [-n] [-z] [-c] [-y] [-h] [-f] [--ai] [--deep] [-o OUTPUT]\n\n"
    printf " ${bblue}TARGET OPTIONS${reset}\n"
    printf "   -d domain.tld     Target domain\n"
    printf "   -m company        Target company name\n"
    printf "   -l list.txt       Targets list (One on each line)\n"
    printf "   -x oos.txt        Excludes subdomains list (Out Of Scope)\n"
    printf "   -i in.txt         Includes subdomains list\n"
    printf " \n"
    printf " ${bblue}MODE OPTIONS${reset}\n"
    printf "   -r, --recon       Recon - Performs full recon process (without attacks)\n"
    printf "   -s, --subdomains  Subdomains - Performs Subdomain Enumeration, Web probing and check for sub-tko\n"
    printf "   -p, --passive     Passive - Performs only passive steps\n"
    printf "   -a, --all         All - Performs all checks and active exploitations\n"
    printf "   -w, --web         Web - Performs web checks from list of subdomains\n"
    printf "   -n, --osint       OSINT - Checks for public intel data\n"
    printf "   -z, --zen         Zen - Performs a recon process covering the basics and some vulns\n"
    printf "   -c, --custom      Custom - Launches specific function against target, u need to know the function name first\n"
    printf "   -y, --ai          AI - Analyzes ReconFTW results using a local LLM\n"
    printf "   -h                Help - Show help section\n"
    printf " \n"
    printf " ${bblue}GENERAL OPTIONS${reset}\n"
    printf "   --deep            Deep scan (Enable some slow options for deeper scan)\n"
    printf "   -f config_file    Alternate reconftw.cfg file\n"
    printf "   -o output/path    Define output folder\n"
    printf "   -v, --vps         Axiom distributed VPS\n"
    printf "   -q                Rate limit in requests per second\n"
    printf "   --check-tools     Exit if one of the tools is missing\n"
    printf "   --health-check    Run system health check and exit\n"
    printf "   --quick-rescan    Skip heavy steps if no new subs/webs this run\n"
    printf "   --incremental     Only scan new findings since last run\n"
    printf "   --adaptive-rate   Automatically adjust rate limits on errors (429/503)\n"
    printf "   --dry-run         Show what would be executed without running commands\n"
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
    printf " ${byellow}Analyze ReconFTW results with AI:${reset}\n"
    printf " ./reconftw.sh -d example.com -r --ai\n"
    printf " \n"
    printf " ${byellow}Run custom function:${reset}\n"
    printf " ./reconftw.sh -d example.com -c nuclei_check \n"
}
