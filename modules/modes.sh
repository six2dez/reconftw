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
    set +m 2>/dev/null || true

    # Validate configuration before starting
    validate_config || exit $?
    apply_performance_profile

    # Check available disk space before starting (require at least 5GB by default)
    local required_space_gb="${MIN_DISK_SPACE_GB:-5}"
    if ! check_disk_space "$required_space_gb" "."; then
        _print_status WARN "Low disk space detected" "Continuing anyway..."
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
        "${SCRIPTPATH}/install.sh" --tools
    fi

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
    if [[ "${FORCE_RESCAN:-false}" == "true" ]]; then
        rm -f "$called_fn_dir"/.* 2>>"${LOGFILE:-/dev/null}" || true
    fi
    mkdir -p "$dir"
    cd "$dir" || {
        print_errorf "Failed to cd directory in %s @ line %s" "${FUNCNAME[0]}" "${LINENO}"
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
    DEBUG_LOG="${dir}/debug.log"
    touch "$DEBUG_LOG"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"
    enable_command_trace

    # Rotate old log files
    rotate_logs "${dir}/.log" "${MAX_LOG_FILES:-10}" "${MAX_LOG_AGE_DAYS:-30}"

    # Trap for cleanup on unexpected exit
    trap 'cleanup_on_exit' INT TERM

    # Initialize structured logging if enabled
    log_init

    # Reset incidents for this run
    INCIDENTS_LEVELS=()
    INCIDENTS_ITEMS=()

    # Initialize cache for wordlists/resolvers
    cache_init
    cache_clean "${CACHE_MAX_AGE_DAYS:-30}" 2>>"${LOGFILE:-/dev/null}" || true
    if [[ "${CACHE_REFRESH:-false}" == "true" ]]; then
        notification "Cache refresh forced for this run" warn
    fi

    # init time saved estimator
    TIME_SAVED_EST=0

    # Non-fatal error trap: log and continue (plus short explanation for common cases)
    trap 'rc=$?; ts=$(date +"%Y-%m-%d %H:%M:%S"); cmd=${BASH_COMMAND}; loc_fn=${FUNCNAME[0]:-main}; loc_ln=${BASH_LINENO[0]:-0}; msg="[$ts] ERR($rc) @ ${loc_fn}:${loc_ln} :: ${cmd}"; if [[ -n "${LOGFILE:-}" ]]; then echo "$msg" >>"$LOGFILE"; else echo "$msg" >&2; fi; explain_err "$rc" "$cmd" "$loc_fn" "$loc_ln"' ERR

    if declare -F ui_header >/dev/null 2>&1; then
        ui_header
    else
        _print_rule
        printf "%b  Target: %s%b\n" "${bred:-}" "$domain" "${reset:-}"
        if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
            printf "%b  Mode:   %s | Parallel: %s | Verbosity: %s%b\n" \
                "${bblue:-}" "${opt_mode:-r}" "${PARALLEL_MODE:-true}" "${OUTPUT_VERBOSITY:-1}" "${reset:-}"
        fi
        _print_rule
    fi

    if [[ "${FORCE_RESCAN:-false}" == "true" ]]; then
        _print_msg WARN "Force rescan enabled: ignoring cached module markers"
    fi
    if [[ "${MONITOR_MODE:-false}" == "true" ]] && [[ "${MONITOR_CYCLE:-1}" -gt 1 ]]; then
        notification "Monitor cycle ${MONITOR_CYCLE}: skipping repeated tools check" info
    else
        tools_installed
    fi

}

function end() {

    if [[ $opt_ai ]]; then
        notification "Sending ${domain} data to AI" info
        mkdir -p "${dir}/ai_result" 2>>"${LOGFILE}"
        local ai_script ai_prompts_file ai_venv_python ai_python ai_json_output ai_redact_flag ai_pull_flag ai_strict_flag
        local -a ai_cmd
        ai_script="${tools}/reconftw_ai/reconftw_ai.py"
        ai_prompts_file="${AI_PROMPTS_FILE:-${tools}/reconftw_ai/prompts.json}"
        ai_venv_python="${tools}/reconftw_ai/venv/bin/python3"
        ai_python="${AI_EXECUTABLE:-python3}"
        ai_json_output="${dir}/ai_result/reconftw_analysis.json"
        ai_redact_flag="--redact"
        ai_pull_flag=""
        ai_strict_flag=""

        if [[ "${AI_REDACT:-true}" != "true" ]]; then
            ai_redact_flag="--no-redact"
        fi
        if [[ "${AI_ALLOW_MODEL_PULL:-false}" == "true" ]]; then
            ai_pull_flag="--allow-model-pull"
        fi
        if [[ "${AI_STRICT:-false}" == "true" ]]; then
            ai_strict_flag="--strict"
        fi

        if [[ -x "${ai_venv_python}" ]]; then
            ai_python="${ai_venv_python}"
        elif ! command -v "${ai_python}" >/dev/null 2>&1; then
            notification "AI skipped: Python executable not found (${ai_python})" warn
            ai_python=""
        fi

        if [[ -n "${ai_python}" && -f "${ai_script}" ]]; then
            ai_cmd=(
                "${ai_python}" "${ai_script}"
                --results-dir "${dir}" \
                --output-dir "${dir}/ai_result" \
                --output-json "${ai_json_output}" \
                --model "${AI_MODEL}" \
                --output-format "${AI_REPORT_TYPE}" \
                --report-type "${AI_REPORT_PROFILE}" \
                --prompts-file "${ai_prompts_file}" \
                --max-chars-per-file "${AI_MAX_CHARS_PER_FILE:-50000}" \
                --max-files-per-category "${AI_MAX_FILES_PER_CATEGORY:-200}" \
                "${ai_redact_flag}"
            )
            if [[ -n "${ai_pull_flag}" ]]; then
                ai_cmd+=("${ai_pull_flag}")
            fi
            if [[ -n "${ai_strict_flag}" ]]; then
                ai_cmd+=("${ai_strict_flag}")
            fi
            if ! "${ai_cmd[@]}" 2>>"${LOGFILE}" >/dev/null; then
                notification "AI report failed; check ${DEBUG_LOG} for details" warn
            fi
        elif [[ -n "${ai_python}" ]]; then
            notification "AI skipped: reconftw_ai script not found at ${ai_script}" warn
        fi
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
            _print_error "Faraday server is not running. Skipping Faraday integration"
        else
            if [[ -s ".tmp/tko_json.txt" ]]; then
                run_command faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nuclei .tmp/tko_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "hosts/portscan_active.xml" ]]; then
                run_command faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nmap hosts/portscan_active.xml 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s ".tmp/fuzzparams_json.txt" ]]; then
                run_command faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nuclei .tmp/fuzzparams_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "nuclei_output/info_json.txt" ]]; then
                run_command faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nuclei nuclei_output/info_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "nuclei_output/low_json.txt" ]]; then
                run_command faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nuclei nuclei_output/low_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "nuclei_output/medium_json.txt" ]]; then
                run_command faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nuclei nuclei_output/medium_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "nuclei_output/high_json.txt" ]]; then
                run_command faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nuclei nuclei_output/high_json.txt 2>>"$LOGFILE" >/dev/null
            fi
            if [[ -s "nuclei_output/critical_json.txt" ]]; then
                run_command faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nuclei nuclei_output/critical_json.txt 2>>"$LOGFILE" >/dev/null
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
        # shellcheck disable=SC2016  # $1 is intentionally for sh -c, not bash
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
    getElapsedTime "$global_start" "$global_end"
    if declare -F ui_summary >/dev/null 2>&1; then
        if [[ "${RECON_PARTIAL_RUN:-false}" == "true" ]]; then
            _print_status WARN "Run completed with non-fatal warnings" "osint_parallel=${RECON_OSINT_PARALLEL_FAILURES:-0}"
        fi
        local subs_count webs_count
        local -A vulns_count=( [critical]=0 [high]=0 [medium]=0 [low]=0 [info]=0 )
        subs_count=$(count_lines "${dir}/subdomains/subdomains.txt")
        webs_count=$(count_lines "${dir}/webs/webs_all.txt")
        
        if [[ -d "${dir}/nuclei_output" ]]; then
            for sev in "${!vulns_count[@]}"; do
                if [[ -s "${dir}/nuclei_output/${sev}.txt" ]]; then
                    vulns_count[$sev]=$(count_lines "${dir}/nuclei_output/${sev}.txt")
                fi
            done
        fi
        local mode_label="FULL"
        case "${opt_mode:-r}" in
            n) mode_label="OSINT-ONLY" ;;
            w) mode_label="WEB" ;;
            s) mode_label="SUBDOMAINS" ;;
            p) mode_label="PASSIVE" ;;
            a) mode_label="ALL" ;;
            z) mode_label="ZEN" ;;
        esac
        if [[ "${opt_mode:-r}" == "n" ]]; then
            subs_count="N/A (OSINT-only)"
            webs_count="N/A (OSINT-only)"
        fi
        ui_summary "$domain" "$runtime" "$finaldir" "$mode_label" "${subs_count:-0}" "${webs_count:-0}" \
            "${vulns_count[critical]}" "${vulns_count[high]}" "${vulns_count[medium]}" \
            "${vulns_count[low]}" "${vulns_count[info]}"
        print_incidents "${DEBUG_LOG:-}"
    else
        _print_section "Scan Complete"
        if [[ "${RECON_PARTIAL_RUN:-false}" == "true" ]]; then
            _print_status WARN "Run completed with non-fatal warnings" "osint_parallel=${RECON_OSINT_PARALLEL_FAILURES:-0}"
        fi
        printf "%b  Target:   %s%b\n" "${bgreen:-}" "$domain" "${reset:-}"
        printf "%b  Duration: %s%b\n" "${bgreen:-}" "$runtime" "${reset:-}"
        printf "%b  Output:   %s%b\n" "${bgreen:-}" "$finaldir" "${reset:-}"
        _print_rule
        print_incidents "${DEBUG_LOG:-}"
    fi
    notification "Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" good "$(date +'%Y-%m-%d %H:%M:%S')"
    [ "$SOFT_NOTIFICATION" = true ] && echo "[$(date +'%Y-%m-%d %H:%M:%S')] Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" | notify -silent

    # Print performance timing summary
    print_timing_summary
    write_perf_summary
    if [[ "${NO_REPORT:-false}" != "true" ]]; then
        generate_consolidated_report || true
        export_reports || true
    fi

}

function build_hotlist() {
    mkdir -p .tmp
    declare -A score
    # Nuclei high/critical
    for f in nuclei_output/high_json.txt nuclei_output/critical_json.txt; do
        [[ -s $f ]] || continue
        while read -r h; do
            [[ -z $h ]] && continue
            score["$h"]=$((${score["$h"]:-0} + 10))
        done < <(jq -r '.["matched-at"] // .host' "$f" 2>/dev/null)
    done
    # Takeovers
    [[ -s webs/takeover.txt ]] && while read -r h; do score["$h"]=$((${score["$h"]:-0} + 8)); done <webs/takeover.txt
    # Secrets
    for s in js/js_secrets.txt js/js_secrets_jsmap.txt js/js_secrets_jsmap_jsluice.txt; do
        [[ -s $s ]] || continue
        while read -r h; do score["$h"]=$((${score["$h"]:-0} + 6)); done < <(awk '{print $1}' "$s")
    done
    # Real IPs via favicon
    if [[ -s hosts/favicontest.txt ]]; then
        while read -r ip; do
            [[ -z $ip ]] && continue
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

    _print_section "OSINT"

    domain_info
    ip_info
    emails
    google_dorks
    #github_dorks
    github_repos
    metadata
    apileaks
    third_party_misconfigs
    # shellcheck disable=SC2034  # These globals are consumed by downstream module functions
    SUBNOERROR=false
    # shellcheck disable=SC2034
    SUBANALYTICS=false
    # shellcheck disable=SC2034
    SUBBRUTE=false
    # shellcheck disable=SC2034
    SUBSCRAPING=false
    # shellcheck disable=SC2034
    SUBPERMUTE=false
    # shellcheck disable=SC2034
    SUBREGEXPERMUTE=false
    # shellcheck disable=SC2034
    SUB_RECURSIVE_BRUTE=false
    # shellcheck disable=SC2034
    WEBPROBESIMPLE=false
    if [[ $AXIOM == true ]]; then
        axiom_launch
        axiom_selected
    fi

    _print_section "Subdomains"

    subdomains_full
    remove_big_files

    _print_section "Web Detection"

    favicon
    cdnprovider
    # shellcheck disable=SC2034  # PORTSCAN_ACTIVE controls scan behavior
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
    _print_section "Vulnerability Checks"
    if [[ $VULNS_GENERAL == true ]]; then
        if [[ "${PARALLEL_MODE:-true}" == "true" ]] && declare -f parallel_funcs &>/dev/null; then
            # Parallel execution - group independent checks
            [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && printf "%b[*] Running vulnerability checks in parallel mode%b\n" "$bblue" "$reset"
            parallel_funcs "${PAR_VULNS_GROUP1_SIZE:-4}" cors open_redirect crlf_checks xss
            local vulns_g1_rc=$?
            if ((vulns_g1_rc > 0)); then
                if [[ "${CONTINUE_ON_TOOL_ERROR:-true}" == "true" ]]; then
                    RECON_PARTIAL_RUN=true
                    notification "Parallel vulns group 1 completed with ${vulns_g1_rc} warning(s); continuing" warn
                else
                    notification "Parallel vulns batch failed (group 1)" error
                    return 1
                fi
            fi
            parallel_funcs "${PAR_VULNS_GROUP2_SIZE:-4}" ssrf_checks lfi ssti sqli
            local vulns_g2_rc=$?
            if ((vulns_g2_rc > 0)); then
                if [[ "${CONTINUE_ON_TOOL_ERROR:-true}" == "true" ]]; then
                    RECON_PARTIAL_RUN=true
                    notification "Parallel vulns group 2 completed with ${vulns_g2_rc} warning(s); continuing" warn
                else
                    notification "Parallel vulns batch failed (group 2)" error
                    return 1
                fi
            fi
            parallel_funcs "${PAR_VULNS_GROUP3_SIZE:-3}" command_injection prototype_pollution smuggling
            local vulns_g3_rc=$?
            if ((vulns_g3_rc > 0)); then
                if [[ "${CONTINUE_ON_TOOL_ERROR:-true}" == "true" ]]; then
                    RECON_PARTIAL_RUN=true
                    notification "Parallel vulns group 3 completed with ${vulns_g3_rc} warning(s); continuing" warn
                else
                    notification "Parallel vulns batch failed (group 3)" error
                    return 1
                fi
            fi
            parallel_funcs "${PAR_VULNS_GROUP4_SIZE:-3}" webcache spraying brokenLinks
            local vulns_g4_rc=$?
            if ((vulns_g4_rc > 0)); then
                if [[ "${CONTINUE_ON_TOOL_ERROR:-true}" == "true" ]]; then
                    RECON_PARTIAL_RUN=true
                    notification "Parallel vulns group 4 completed with ${vulns_g4_rc} warning(s); continuing" warn
                else
                    notification "Parallel vulns batch failed (group 4)" error
                    return 1
                fi
            fi
            fuzzparams
            4xxbypass
            test_ssl
        else
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
        print_errorf "Failed to create directory '%s' in %s @ line %s" "$workdir" "${FUNCNAME[0]}" "${LINENO}"
        exit 1
    }
    if [[ "${FORCE_RESCAN:-false}" == "true" ]]; then
        rm -f "$workdir"/.called_fn/.* 2>>"${LOGFILE:-/dev/null}" || true
    fi
    cd "$workdir" || {
        print_errorf "Failed to cd directory '%s' in %s @ line %s" "$workdir" "${FUNCNAME[0]}" "${LINENO}"
        exit 1
    }
    mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}

    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
    touch ".log/${NOW}_${NOWT}.txt"
    DEBUG_LOG="${workdir}/debug.log"
    touch "$DEBUG_LOG"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"
    enable_command_trace

    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        dir="$workdir/targets/$domain"
        called_fn_dir="$dir/.called_fn"
        mkdir -p "$dir"
        cd "$dir" || {
            print_errorf "Failed to cd directory '%s' in %s @ line %s" "$dir" "${FUNCNAME[0]}" "${LINENO}"
            exit 1
        }
        mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}
        NOW=$(date +"%F")
        NOWT=$(date +"%T")
        LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
        touch ".log/${NOW}_${NOWT}.txt"
        DEBUG_LOG="${dir}/debug.log"
        touch "$DEBUG_LOG"
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
        print_errorf "Failed to cd directory '%s' in %s @ line %s" "$workdir" "${FUNCNAME[0]}" "${LINENO}"
        exit 1
    }
    dir=$workdir
    domain=$multi
    end
}

function recon() {
    RECON_PARTIAL_RUN=false
    RECON_OSINT_PARALLEL_FAILURES=0

    # Initialize module-level progress (7 modules: OSINT, Subdomains, Web Detection, Web Analysis, Finalization, + 2 optional)
    local module_total=5
    progress_module_init "$module_total"

    _print_section "OSINT"

    if [[ "${PARALLEL_MODE:-true}" == "true" ]] && declare -f parallel_funcs &>/dev/null; then
        # Group 1: balanced with third_party_misconfigs (slow) alongside fast ones
        parallel_funcs "${PAR_OSINT_GROUP1_SIZE:-5}" domain_info ip_info emails google_dorks third_party_misconfigs
        local osint_g1_rc=$?
        if ((osint_g1_rc > 0)); then
            RECON_PARTIAL_RUN=true
            RECON_OSINT_PARALLEL_FAILURES=$((RECON_OSINT_PARALLEL_FAILURES + osint_g1_rc))
        fi
        # Group 2: remaining OSINT + zonetransfer + favicon (were sequential, now parallel)
        parallel_funcs "${PAR_OSINT_GROUP2_SIZE:-5}" github_repos metadata apileaks zonetransfer favicon
        local osint_g2_rc=$?
        if ((osint_g2_rc > 0)); then
            RECON_PARTIAL_RUN=true
            RECON_OSINT_PARALLEL_FAILURES=$((RECON_OSINT_PARALLEL_FAILURES + osint_g2_rc))
        fi
    else
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
    fi

    ui_module_end "OSINT" "osint/dorks.txt" "osint/emails.txt" "osint/domain_info.txt"
    progress_module "OSINT"

    if [[ $AXIOM == true ]]; then
        axiom_launch
        axiom_selected
    fi

    _print_section "Subdomains"

    subdomains_full
    subtakeover
    remove_big_files
    s3buckets
    cloud_extra_providers

    ui_module_end "Subdomains" "subdomains/subdomains.txt" "webs/webs.txt"
    progress_module "Subdomains"

    _print_section "Web Detection"
    webprobe_simple
    webprobe_full

    if [[ "${PARALLEL_MODE:-true}" == "true" ]] && declare -f parallel_funcs &>/dev/null; then
        parallel_funcs "${PAR_WEB_DETECT_GROUP_SIZE:-3}" screenshot cdnprovider portscan
        local webhost_rc=$?
        if ((webhost_rc > 0)); then
            if [[ "${CONTINUE_ON_TOOL_ERROR:-true}" == "true" ]]; then
                RECON_PARTIAL_RUN=true
            else
                notification "Parallel web/host batch failed" error
                return 1
            fi
        fi
        geo_info
    else
        screenshot
        #	virtualhosts
        cdnprovider
        portscan
        geo_info
    fi

    ui_module_end "Web Detection" "hosts/ips.txt" "hosts/cdn_providers.txt"
    progress_module "Web Detection"

    # Quick-rescan gating
    subs_new=$(cat .tmp/subs_new_count 2>/dev/null || echo 1)
    webs_new=$(cat .tmp/webs_new_count 2>/dev/null || echo 1)
    if [[ $QUICK_RESCAN == true && $subs_new -eq 0 && $webs_new -eq 0 ]]; then
        _print_status SKIP "Web Analysis" "(no new subs/webs)"
        TIME_SAVED_EST=$((${TIME_SAVED_EST:-0} + \
            ${TIME_EST_WAF:-0} + ${TIME_EST_NUCLEI:-600} + ${TIME_EST_API:-300} + ${TIME_EST_GQL:-180} + \
            ${TIME_EST_FUZZ:-900} + ${TIME_EST_IIS:-60} + ${TIME_EST_URLCHECKS:-300} + ${TIME_EST_JSCHECKS:-300} + \
            ${TIME_EST_PARAM:-240} + ${TIME_EST_GRPC:-120}))
    else
        _print_section "Web Analysis"

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

        ui_module_end "Web Analysis" "vulns/" "nuclei_output/"
        progress_module "Web Analysis"
    fi

    if [[ $AXIOM == true ]]; then
        axiom_shutdown
    fi

    _print_section "Finalization"

    cms_scanner
    url_gf
    wordlist_gen
    wordlist_gen_roboxtractor
    password_dict
    url_ext

    ui_module_end "Finalization" "fuzzing/" "js/"
    progress_module "Finalization"
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
        print_errorf "Failed to create directory '%s' in %s @ line %s" "$workdir" "${FUNCNAME[0]}" "${LINENO}"
        exit 1
    }
    cd "$workdir" || {
        print_errorf "Failed to cd directory '%s' in %s @ line %s" "$workdir" "${FUNCNAME[0]}" "${LINENO}"
        exit 1
    }

    mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}
    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
    touch ".log/${NOW}_${NOWT}.txt"
    DEBUG_LOG="${workdir}/debug.log"
    touch "$DEBUG_LOG"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"

    [ -n "$flist" ] && LISTTOTAL=$(wc -l <"$flist")

    for domain in "${targets[@]}"; do
        [[ -z "$domain" ]] && continue
        dir="$workdir/targets/$domain"
        called_fn_dir="$dir/.called_fn"

        # Ensure directories exist
        mkdir -p "$dir" || {
            print_errorf "Failed to create directory '%s' in %s @ line %s" "$dir" "${FUNCNAME[0]}" "${LINENO}"
            exit 1
        }
        mkdir -p "$called_fn_dir" || {
            print_errorf "Failed to create directory '%s' in %s @ line %s" "$called_fn_dir" "${FUNCNAME[0]}" "${LINENO}"
            exit 1
        }

        cd "$dir" || {
            print_errorf "Failed to cd to directory '%s' in %s @ line %s" "$dir" "${FUNCNAME[0]}" "${LINENO}"
            exit 1
        }

        mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}

        NOW=$(date +"%F")
        NOWT=$(date +"%T")
        LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"

        # Ensure the .log directory exists before touching the file
        mkdir -p .log

        touch "$LOGFILE" || {
            print_errorf "Failed to create log file: %s" "$LOGFILE"
            exit 1
        }
        DEBUG_LOG="${dir}/debug.log"
        touch "$DEBUG_LOG"
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
        if [[ -n $flist ]]; then
            POSINLIST=$(grep -nrE "^${domain}$" "$flist" | cut -f1 -d':')
            _print_status OK "${domain} (OSINT ${POSINLIST}/${LISTTOTAL})" "$runtime"
        else
            _print_status OK "${domain} (OSINT)" "$runtime"
        fi
    done
    cd "$workdir" || {
        print_errorf "Failed to cd directory '%s' in %s @ line %s" "$workdir" "${FUNCNAME[0]}" "${LINENO}"
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
            print_errorf "Failed to cd directory '%s' in %s @ line %s" "$dir" "${FUNCNAME[0]}" "${LINENO}"
            exit 1
        }
        subdomains_full
        webprobe_simple
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
        if [[ -n $flist ]]; then
            POSINLIST=$(grep -nrE "^${domain}$" "$flist" | cut -f1 -d':')
            _print_status OK "${domain} (recon ${POSINLIST}/${LISTTOTAL})" "$runtime"
        else
            _print_status OK "${domain} (recon)" "$runtime"
        fi
    done
    cd "$workdir" || {
        print_errorf "Failed to cd directory '%s' in %s @ line %s" "$workdir" "${FUNCNAME[0]}" "${LINENO}"
        exit 1
    }

    _print_section "Total Data"
    NUMOFLINES_pwndb_total=$(find . -type f -name 'passwords.txt' -exec cat {} + | anew osint/passwords.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_subs_total=$(find . -type f -name 'subdomains.txt' -exec cat {} + | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_subtko_total=$(find . -type f -name 'takeover.txt' -exec cat {} + | anew webs/takeover.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_webs_total=$(find . -type f -name 'webs.txt' -exec cat {} + | anew webs/webs.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_webs_total_uncommon=$(find . -type f -name 'webs_uncommon_ports.txt' -exec cat {} + | anew webs/webs_uncommon_ports.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_ips_total=$(find . -type f -name 'ips.txt' -exec cat {} + | anew hosts/ips.txt | sed '/^$/d' | wc -l)
    NUMOFLINES_cloudsprov_total=$(find . -type f -name 'cdn_providers.txt' -exec cat {} + | anew hosts/cdn_providers.txt | sed '/^$/d' | wc -l)
    find . -type f -name 'portscan_active.gnmap' -exec cat {} + | tee hosts/portscan_active.gnmap 2>>"$LOGFILE" >/dev/null
    find . -type f -name 'portscan_passive.txt' -exec cat {} + | tee hosts/portscan_passive.txt 2>&1 >>"$LOGFILE" >/dev/null

    printf "  Creds: %s │ Subs: %s │ Takeovers: %s │ Webs: %s (+%s uncommon) │ IPs: %s │ Cloud: %s\n" \
        "$NUMOFLINES_pwndb_total" "$NUMOFLINES_subs_total" "$NUMOFLINES_subtko_total" \
        "$NUMOFLINES_webs_total" "$NUMOFLINES_webs_total_uncommon" \
        "$NUMOFLINES_ips_total" "$NUMOFLINES_cloudsprov_total"
    s3buckets
    waf_checks
    nuclei_check
    for domain in "${targets[@]}"; do
        [[ -z "$domain" ]] && continue
        loopstart=$(date +%s)
        dir="$workdir/targets/$domain"
        called_fn_dir="$dir/.called_fn"
        cd "$dir" || {
            print_errorf "Failed to cd directory '%s' in %s @ line %s" "$dir" "${FUNCNAME[0]}" "${LINENO}"
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
        if [[ -n $flist ]]; then
            POSINLIST=$(grep -nrE "^${domain}$" "$flist" | cut -f1 -d':')
            _print_status OK "${domain} (vulns ${POSINLIST}/${LISTTOTAL})" "$runtime"
        else
            _print_status OK "${domain} (vulns)" "$runtime"
        fi
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
            print_errorf "Failed to cd directory '%s' in %s @ line %s" "$dir" "${FUNCNAME[0]}" "${LINENO}"
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
        if [[ -n $flist ]]; then
            POSINLIST=$(grep -nrE "^${domain}$" "$flist" | cut -f1 -d':')
            _print_status OK "${domain} (final ${POSINLIST}/${LISTTOTAL})" "$runtime"
        else
            _print_status OK "${domain} (final)" "$runtime"
        fi
    done
    cd "$workdir" || {
        print_errorf "Failed to cd directory '%s' in %s @ line %s" "$workdir" "${FUNCNAME[0]}" "${LINENO}"
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
        print_errorf "Refusing to remove '%s' -- safety check failed" "$dir"
        return 1
    fi
    rm -rf -- "$dir"
    mkdir -p "$dir" || {
        print_errorf "Failed to create directory '%s' in %s @ line %s" "$dir" "${FUNCNAME[0]}" "${LINENO}"
        exit 1
    }
    cd "$dir" || {
        print_errorf "Failed to cd directory '%s' in %s @ line %s" "$dir" "${FUNCNAME[0]}" "${LINENO}"
        exit 1
    }

    mkdir -p {.called_fn,.log}
    called_fn_dir="$dir/.called_fn"
    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
    touch ".log/${NOW}_${NOWT}.txt"
    DEBUG_LOG="${dir}/debug.log"
    touch "$DEBUG_LOG"
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
        local duration=$((loopend - loopstart))
        _print_status OK "$custom_f" "${duration}s"
        [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
            print_notice INFO "$custom_f" "entries ${entries} (${func_count}/${func_total}) at ${currently}"
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

    _print_section "Subdomains"

    subdomains_full
    subtakeover
    remove_big_files
    zonetransfer
    s3buckets

    _print_section "Web Detection"
    webprobe_simple
    webprobe_full
    screenshot
    #	virtualhosts

    if [[ $AXIOM == true ]]; then
        axiom_shutdown
    fi

    end
}

function webs_menu() {
    _print_section "Web Detection"

    webprobe_simple
    webprobe_full
    subtakeover
    remove_big_files
    screenshot
    #	virtualhosts

    _print_section "Web Analysis"

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

    _print_section "Subdomains"

    subdomains_full
    subtakeover
    remove_big_files
    s3buckets

    _print_section "Web Detection"
    webprobe_simple
    webprobe_full
    screenshot
    #	virtualhosts
    cdnprovider

    _print_section "Web Analysis"

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

function monitor_mode() {
    local selected_mode="${1:-r}"

    if [[ -z "${selected_mode}" ]]; then
        selected_mode="r"
    fi

    if [[ -n "${multi:-}" ]]; then
        notification "Monitor mode does not support -m multi-target runs" error
        return 1
    fi
    if [[ "${selected_mode}" != "w" ]] && [[ -n "${list:-}" ]]; then
        notification "Monitor mode supports -l only with web mode (-w)" error
        return 1
    fi

    if [[ -n "${dir_output:-}" ]]; then
        notification "Monitor mode ignores -o output relocation to preserve incremental state" warn
        unset dir_output
    fi

    if [[ ! "${MONITOR_INTERVAL_MIN:-}" =~ ^[0-9]+$ ]] || [[ "${MONITOR_INTERVAL_MIN:-0}" -lt 1 ]]; then
        MONITOR_INTERVAL_MIN=60
    fi
    if [[ ! "${MONITOR_MAX_CYCLES:-}" =~ ^[0-9]+$ ]]; then
        MONITOR_MAX_CYCLES=0
    fi

    # shellcheck disable=SC2034  # Used by downstream execution functions in monitor cycles
    INCREMENTAL_MODE=true
    QUICK_RESCAN=true
    # shellcheck disable=SC2034  # Used by downstream execution functions in monitor cycles
    DIFF=true
    local interval_sec=$((MONITOR_INTERVAL_MIN * 60))
    local cycle=0

    notification "Monitor mode enabled (mode=${selected_mode}, interval=${MONITOR_INTERVAL_MIN}m, max_cycles=${MONITOR_MAX_CYCLES:-0})" info

    while true; do
        cycle=$((cycle + 1))
        MONITOR_CYCLE=$cycle

        notification "Monitor cycle ${cycle} started" info

        case "$selected_mode" in
            'r')
                start
                recon
                end
                ;;
            's')
                subs_menu
                ;;
            'p')
                passive
                ;;
            'a')
                export VULNS_GENERAL=true
                all
                ;;
            'w')
                if [[ -n $list ]]; then
                    start
                    if [[ $list == /* ]]; then
                        cp "$list" "$dir/webs/webs.txt"
                    else
                        cp "${SCRIPTPATH}/$list" "$dir/webs/webs.txt"
                    fi
                    webs_menu
                else
                    notification "Web mode in monitor requires -l list file" error
                    return 1
                fi
                ;;
            'n')
                PRESERVE=true
                start
                osint
                end
                ;;
            'z')
                zen_menu
                ;;
            *)
                notification "Unsupported mode '${selected_mode}' for monitor. Use one of: r,s,p,a,w,n,z" error
                return 1
                ;;
        esac

        monitor_snapshot || true

        if [[ "${MONITOR_MAX_CYCLES:-0}" -gt 0 ]] && [[ "$cycle" -ge "${MONITOR_MAX_CYCLES}" ]]; then
            notification "Monitor finished after ${cycle} cycle(s)" good
            break
        fi

        notification "Monitor cycle ${cycle} completed, sleeping ${MONITOR_INTERVAL_MIN} minute(s)" info
        sleep "$interval_sec"
    done
}

function report_only_mode() {
    if [[ -z "${domain:-}" ]]; then
        notification "Report-only mode requires -d <domain>" error
        return 1
    fi
    if [[ -n "${list:-}" ]] || [[ -n "${multi:-}" ]]; then
        notification "Report-only mode currently supports single-target only" error
        return 1
    fi

    dir="${SCRIPTPATH}/Recon/$domain"
    called_fn_dir="${dir}/.called_fn"
    if [[ ! -d "$dir" ]]; then
        notification "Target directory not found for report-only mode: $dir" error
        return 1
    fi

    cd "$dir" || {
        notification "Failed to enter target directory: $dir" error
        return 1
    }

    mkdir -p .log report
    NOW=$(date +"%F")
    NOWT=$(date +"%T")
    LOGFILE="${dir}/.log/${NOW}_${NOWT}_report_only.txt"
    touch "$LOGFILE"
    DEBUG_LOG="${dir}/debug.log"
    touch "$DEBUG_LOG"
    runtime="report-only"

    notification "Report-only mode: rebuilding reports from existing artifacts" info
    build_hotlist || true
    write_perf_summary || true
    if [[ "${NO_REPORT:-false}" != "true" ]]; then
        generate_consolidated_report || true
        export_reports || true
    fi
    notification "Report-only rebuild completed for ${domain}" good
}

function help() {
    pt_header "Usage"
    printf "\n Usage: %s [-d domain.tld] [-m name] [-l list.txt] [-x oos.txt] [-i in.txt] " "$0"
    printf "\n           	      [-r] [-s] [-p] [-a] [-w] [-n] [-z] [-c] [-y] [-h] [-f] [--ai] [--deep] [--monitor] [--monitor-interval m] [--monitor-cycles n] [--report-only] [--refresh-cache] [--gen-resolvers] [--force] [--export fmt] [-o OUTPUT]\n\n"
    printf " %bTARGET OPTIONS%b\n" "${bblue}" "${reset}"
    printf "   -d domain.tld     Target domain\n"
    printf "   -m company        Target company name\n"
    printf "   -l list.txt       Targets list (One on each line)\n"
    printf "   -x oos.txt        Excludes subdomains list (Out Of Scope)\n"
    printf "   -i in.txt         Includes subdomains list\n"
    printf " \n"
    printf " %bMODE OPTIONS%b\n" "${bblue}" "${reset}"
    printf "   -r, --recon       Recon - Performs full recon process (includes nuclei and fuzzing)\n"
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
    printf " %bGENERAL OPTIONS%b\n" "${bblue}" "${reset}"
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
    printf "   --quiet           Minimal output (errors and final summary only)\n"
    printf "   --verbose         Extra output (PIDs, debug info)\n"
    printf "   --parallel-log m  Parallel output mode: summary (default), tail, or full\n"
    printf "   --parallel        Run independent functions in parallel (faster but uses more resources)\n"
    printf "   --no-parallel     Force sequential execution\n"
    printf "   --show-cache      Show cached modules lines (default collapses)\n"
    printf "   --no-banner       Disable ASCII banner\n"
    printf "   --legal           Show full legal block\n"
    printf "   --monitor         Continuous monitoring mode (single target; -w supports -l)\n"
    printf "   --monitor-interval Minutes between cycles (default: 60)\n"
    printf "   --monitor-cycles  Stop after N cycles (0 = infinite)\n"
    printf "   --report-only     Rebuild report artifacts from existing Recon/<target>\n"
    printf "   --no-report       Disable report generation and exports\n"
    printf "   --refresh-cache   Force refresh of cached resolvers/wordlists\n"
    printf "   --gen-resolvers   Generate custom resolvers with dnsvalidator\n"
    printf "   --force           Re-run all modules (ignore cached markers)\n"
    printf "   --export fmt      Export artifacts: json|html|csv|all (default: all)\n"
    printf " \n"
    printf " %bUSAGE EXAMPLES%b\n" "${bblue}" "${reset}"
    printf " %bPerform full recon (without attacks):%b\n" "${byellow}" "${reset}"
    printf " ./reconftw.sh -d example.com -r\n"
    printf " \n"
    printf " %bPerform subdomain enumeration on multiple targets:%b\n" "${byellow}" "${reset}"
    printf " ./reconftw.sh -l targets.txt -s\n"
    printf " \n"
    printf " %bPerform Web based scanning on a subdomains list:%b\n" "${byellow}" "${reset}"
    printf " ./reconftw.sh -d example.com -l targets.txt -w\n"
    printf " \n"
    printf " %bMultidomain recon:%b\n" "${byellow}" "${reset}"
    printf " ./reconftw.sh -m company -l domainlist.txt -r\n"
    printf " \n"
    printf " %bPerform full recon (with active attacks) along Out-Of-Scope subdomains list:%b\n" "${byellow}" "${reset}"
    printf " ./reconftw.sh -d example.com -x out.txt -a\n"
    printf " \n"
    printf " %bAnalyze ReconFTW results with AI:%b\n" "${byellow}" "${reset}"
    printf " ./reconftw.sh -d example.com -r --ai\n"
    printf " \n"
    printf " %bRun custom function:%b\n" "${byellow}" "${reset}"
    printf " ./reconftw.sh -d example.com -c nuclei_check \n"
}
