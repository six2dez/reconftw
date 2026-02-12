#!/bin/bash
# shellcheck disable=SC2154  # Variables defined in reconftw.cfg
# reconFTW - Vulnerability scanning module
# Contains: xss, cors, open_redirect, ssrf_checks, crlf_checks, lfi, ssti,
#           sqli, test_ssl, spraying, command_injection, 4xxbypass,
#           prototype_pollution, smuggling, webcache, fuzzparams
# This file is sourced by reconftw.sh - do not execute directly
[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by reconftw.sh" >&2
    exit 1
}

function xss() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $XSS == true ]] && [[ -s "gf/xss.txt" ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "XSS Analysis"

        # Process gf/xss.txt with qsreplace and Gxss
        if [[ -s "gf/xss.txt" ]]; then
            _print_msg INFO "Running: XSS Payload Generation"
            run_command qsreplace FUZZ <"gf/xss.txt" | sed '/FUZZ/!d' | Gxss -c 100 -p Xss | qsreplace FUZZ | sed '/FUZZ/!d' \
                | anew -q ".tmp/xss_reflected.txt"
        fi

        # Determine whether to use Axiom or Katana for scanning
        if [[ $AXIOM != true ]]; then
            # Using Katana
            if [[ $DEEP == true ]]; then
                DEPTH=3
            else
                DEPTH=2
            fi

            if [[ -n $XSS_SERVER ]]; then
                OPTIONS="-b ${XSS_SERVER} -w $DALFOX_THREADS"
            else
                _print_msg WARN "No XSS_SERVER defined, blind XSS skipped"
                OPTIONS="-w $DALFOX_THREADS"
            fi

                # Run Dalfox with Katana output
                if [[ -s ".tmp/xss_reflected.txt" ]]; then
                    _print_msg INFO "Running: Dalfox with Katana"
                    run_command dalfox pipe --silence --no-color --no-spinner --only-poc r --ignore-return 302,404,403 --skip-bav $OPTIONS -d "$DEPTH" <".tmp/xss_reflected.txt" 2>>"$LOGFILE" |
                        anew -q "vulns/xss.txt"
                fi

            
        else
            # Using Axiom
            if [[ $DEEP == true ]]; then
                DEPTH=3
                AXIOM_ARGS="$AXIOM_EXTRA_ARGS"
            else
                DEPTH=2
                AXIOM_ARGS="$AXIOM_EXTRA_ARGS"
            fi

            if [[ -n $XSS_SERVER ]]; then
                OPTIONS="-b ${XSS_SERVER} -w $DALFOX_THREADS"
            else
                _print_msg WARN "No XSS_SERVER defined, blind XSS skipped"
                OPTIONS="-w $DALFOX_THREADS"
            fi

            # Run Dalfox with Axiom-scan output
            if [[ -s ".tmp/xss_reflected.txt" ]]; then
                _print_msg INFO "Running: Dalfox with Axiom"
                run_command axiom-scan ".tmp/xss_reflected.txt" -m dalfox --skip-bav $OPTIONS -d "$DEPTH" -o "vulns/xss.txt" $AXIOM_ARGS 2>>"$LOGFILE" >/dev/null
            fi
        fi

        end_func "Results are saved in vulns/xss.txt" "${FUNCNAME[0]}"
    else
        # Handle cases where XSS is false, no vulnerable URLs, or already processed
        if [[ $XSS == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "gf/xss.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for XSS"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function cors() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CORS == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "CORS Scan"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Proceed only if webs_all.txt exists and is non-empty
        if [[ -s "webs/webs_all.txt" ]]; then
            _print_msg INFO "Running: Corsy for CORS Scan"
            run_command "${tools}/Corsy/venv/bin/python3" "${tools}/Corsy/corsy.py" -i "webs/webs_all.txt" -o "vulns/cors.txt" 2>>"$LOGFILE" >/dev/null
        else
            end_func "No webs/webs_all.txt file found, CORS Scan skipped." "${FUNCNAME[0]}"
            return
        fi

        end_func "Results are saved in vulns/cors.txt" "${FUNCNAME[0]}"

    else
        # Handle cases where CORS is false, no vulnerable URLs, or already processed
        if [[ $CORS == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "gf/xss.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for CORS"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function open_redirect() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $OPEN_REDIRECT == true ]] \
        && [[ -s "gf/redirect.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Open Redirects Checks"

        # Determine whether to proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"gf/redirect.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: Open Redirects Payload Generation"

            # Process redirect.txt with qsreplace and filter lines containing 'FUZZ'
            run_command qsreplace FUZZ <"gf/redirect.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_redirect.txt"

            # Run Oralyzer with the generated payloads
            run_command "${tools}/Oralyzer/venv/bin/python3" "${tools}/Oralyzer/oralyzer.py" -l ".tmp/tmp_redirect.txt" -p "${tools}/Oralyzer/payloads.txt" >"vulns/redirect.txt" 2>>"$LOGFILE"

            # Remove ANSI color codes from the output
            sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "vulns/redirect.txt"

            end_func "Results are saved in vulns/redirect.txt" "${FUNCNAME[0]}"
        else
            end_func "Skipping Open Redirects: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            printf "${bgreen}#######################################################################${reset}\n"
        fi
    else
        # Handle cases where OPEN_REDIRECT is false, no vulnerable URLs, or already processed
        if [[ $OPEN_REDIRECT == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "gf/redirect.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for open redirect"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function ssrf_checks() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSRF_CHECKS == true ]] \
        && [[ -s "gf/ssrf.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "SSRF Checks"

        # Handle COLLAB_SERVER configuration
        if [[ -z $COLLAB_SERVER ]]; then
            interactsh-client &>.tmp/ssrf_callback.txt &
            INTERACTSH_PID=$!
            sleep 2

            # Extract FFUFHASH from interactsh_callback.txt
            COLLAB_SERVER_FIX="FFUFHASH.$(tail -n1 .tmp/ssrf_callback.txt | cut -c 16-)"
            COLLAB_SERVER_URL="http://$COLLAB_SERVER_FIX"
            INTERACT=true
        else
            COLLAB_SERVER_FIX="FFUFHASH.$(echo "$COLLAB_SERVER" | sed -r "s|https?://||")"
            INTERACT=false
        fi

        # Determine whether to proceed based on DEEP flag or URL count
        URL_COUNT=$(wc -l <"gf/ssrf.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: SSRF Payload Generation"

            # Generate temporary SSRF payloads
            run_command qsreplace "$COLLAB_SERVER_FIX" <"gf/ssrf.txt" | anew -q ".tmp/tmp_ssrf.txt"

            run_command qsreplace "$COLLAB_SERVER_URL" <"gf/ssrf.txt" | anew -q ".tmp/tmp_ssrf.txt"

    # Run FFUF to find requested URLs
    _print_msg INFO "Running: FFUF for SSRF Requested URLs"
    run_command ffuf -v -H "${HEADER}" -t "$FFUF_THREADS" -rate "$FFUF_RATELIMIT" -w ".tmp/tmp_ssrf.txt" -u "FUZZ" 2>/dev/null \
        | anew -q "vulns/ssrf_requested.txt"

    # Run FFUF with header injection for SSRF
    _print_msg INFO "Running: FFUF for SSRF Requested Headers with COLLAB_SERVER_FIX"
    run_command ffuf -v -w ".tmp/tmp_ssrf.txt:W1,${tools}/headers_inject.txt:W2" -H "${HEADER}" -H "W2: ${COLLAB_SERVER_FIX}" -t "$FFUF_THREADS" \
        -rate "$FFUF_RATELIMIT" -u "W1" 2>/dev/null | anew -q "vulns/ssrf_requested_headers.txt"

    _print_msg INFO "Running: FFUF for SSRF Requested Headers with COLLAB_SERVER_URL"
    run_command ffuf -v -w ".tmp/tmp_ssrf.txt:W1,${tools}/headers_inject.txt:W2" -H "${HEADER}" -H "W2: ${COLLAB_SERVER_URL}" -t "$FFUF_THREADS" \
        -rate "$FFUF_RATELIMIT" -u "W1" 2>/dev/null | anew -q "vulns/ssrf_requested_headers.txt"

            # Allow time for callbacks to be received
            sleep 5

            # Process SSRF callback results if INTERACT is enabled
            if [[ $INTERACT == true ]] && [[ -s ".tmp/ssrf_callback.txt" ]]; then
                tail -n +11 .tmp/ssrf_callback.txt | anew -q "vulns/ssrf_callback.txt"
                if ! NUMOFLINES=$(tail -n +12 .tmp/ssrf_callback.txt | sed '/^$/d' | wc -l); then
                    NUMOFLINES=0
                fi
                notification "SSRF: ${NUMOFLINES} callbacks received" info
            fi

            end_func "Results are saved in vulns/ssrf_*" "${FUNCNAME[0]}"
        else
            end_func "Skipping SSRF: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            printf "${bgreen}#######################################################################${reset}\n"
        fi

        # Terminate interactsh-client if it was started
        if [[ $INTERACT == true ]] && [[ -n "${INTERACTSH_PID:-}" ]]; then
            kill "$INTERACTSH_PID" 2>/dev/null || true
            unset INTERACTSH_PID
        fi

    else
        # Handle cases where SSRF_CHECKS is false, no vulnerable URLs, or already processed
        if [[ $SSRF_CHECKS == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "gf/ssrf.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for SSRF"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function crlf_checks() {

    # Create necessary directories
    if ! ensure_dirs webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CRLF_CHECKS == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "CRLF Checks"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Determine whether to proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/webs_all.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: CRLF Fuzzing"

            # Run CRLFuzz
            run_command crlfuzz -l "webs/webs_all.txt" -o "vulns/crlf.txt" 2>>"$LOGFILE" >/dev/null

            end_func "Results are saved in vulns/crlf.txt" "${FUNCNAME[0]}"
        else
            end_func "Skipping CRLF: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi
    else
        # Handle cases where CRLF_CHECKS is false, no vulnerable URLs, or already processed
        if [[ $CRLF_CHECKS == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "vulns/crlf.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for CRLF"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function lfi() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $LFI == true ]] \
        && [[ -s "gf/lfi.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "LFI Checks"

        # Ensure gf/lfi.txt is not empty
        if [[ -s "gf/lfi.txt" ]]; then
            _print_msg INFO "Running: LFI Payload Generation"

            # Process lfi.txt with qsreplace and filter lines containing 'FUZZ'
            run_command qsreplace "FUZZ" <"gf/lfi.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_lfi.txt"

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_lfi.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

                _print_msg INFO "Running: LFI Fuzzing with FFUF"

                # Use Interlace to parallelize FFUF scanning
                run_command interlace -tL ".tmp/tmp_lfi.txt" -threads "$INTERLACE_THREADS" -c "ffuf -v -r -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w \"${lfi_wordlist}\" -u \"_target_\" -mr \"root:\" " 2>>"$LOGFILE" \
                    | grep "URL" | sed 's/| URL | //' | anew -q "vulns/lfi.txt"

                end_func "Results are saved in vulns/lfi.txt" "${FUNCNAME[0]}"
            else
                end_func "Skipping LFI: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            fi
        else
            end_func "No gf/lfi.txt file found, LFI Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        # Handle cases where LFI is false, no vulnerable URLs, or already processed
        if [[ $LFI == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "gf/lfi.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for LFI"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function ssti() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSTI == true ]] \
        && [[ -s "gf/ssti.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "SSTI Checks"

        # Ensure gf/ssti.txt is not empty
        if [[ -s "gf/ssti.txt" ]]; then
            _print_msg INFO "Running: SSTI Payload Generation"

            # Process ssti.txt with qsreplace and filter lines containing 'FUZZ'
            run_command qsreplace "FUZZ" <"gf/ssti.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_ssti.txt"

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_ssti.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

                _print_msg INFO "Running: SSTI Fuzzing with FFUF"

                # Use Interlace to parallelize FFUF scanning
                run_command interlace -tL ".tmp/tmp_ssti.txt" -threads "$INTERLACE_THREADS" -c "ffuf -v -r -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w \"${ssti_wordlist}\" -u \"_target_\" -mr \"ssti49\"" 2>>"$LOGFILE" \
                    | grep "URL" | sed 's/| URL | //' | anew -q "vulns/ssti.txt"

                end_func "Results are saved in vulns/ssti.txt" "${FUNCNAME[0]}"
            else
                end_func "Skipping SSTI: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            fi
        else
            end_func "No gf/ssti.txt file found, SSTI Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        # Handle cases where SSTI is false, no vulnerable URLs, or already processed
        if [[ $SSTI == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "gf/ssti.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for SSTI"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function sqli() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SQLI == true ]] \
        && [[ -s "gf/sqli.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "SQLi Checks"

        # Ensure gf/sqli.txt is not empty
        if [[ -s "gf/sqli.txt" ]]; then
            _print_msg INFO "Running: SQLi Payload Generation"

            # Process sqli.txt with qsreplace and filter lines containing 'FUZZ'
            run_command qsreplace "FUZZ" <"gf/sqli.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_sqli.txt"

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_sqli.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

                    # Check if SQLMAP is enabled and run SQLMap
                    if [[ $SQLMAP == true ]]; then
                        _print_msg INFO "Running: SQLMap for SQLi Checks"
                        run_command python3 "${tools}/sqlmap/sqlmap.py" -m ".tmp/tmp_sqli.txt" -b -o --smart \
                            --batch --disable-coloring --random-agent --output-dir="vulns/sqlmap" 2>>"$LOGFILE" >/dev/null
                    fi
                                # Check if GHAURI is enabled and run Ghauri
                if [[ $GHAURI == true ]]; then
                    _print_msg INFO "Running: Ghauri for SQLi Checks"
                    run_command interlace -tL ".tmp/tmp_sqli.txt" -threads "$INTERLACE_THREADS" -c "ghauri -u _target_ --batch -H \"${HEADER}\" --force-ssl >> vulns/ghauri_log.txt" 2>>"$LOGFILE" >/dev/null
                fi

                end_func "Results are saved in vulns/sqlmap folder" "${FUNCNAME[0]}"
            else
                end_func "Skipping SQLi: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            fi
        else
            end_func "No gf/sqli.txt file found, SQLi Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        # Handle cases where SQLI is false, no vulnerable URLs, or already processed
        if [[ $SQLI == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "gf/sqli.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for SQLi"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function test_ssl() {

    # Create necessary directories
    if ! ensure_dirs hosts vulns; then return 1; fi

    # Check if the function should run
    if should_run "TEST_SSL"; then

        start_func "${FUNCNAME[0]}" "SSL Test"

        # Handle multi-domain scenarios
        if [[ -n $multi ]] && [[ ! -f "$dir/hosts/ips.txt" ]]; then
            echo "$domain" >"$dir/hosts/ips.txt"
        fi

        # Run testssl.sh
        _print_msg INFO "Running: SSL Test with testssl.sh"
        run_command "${tools}/testssl.sh/testssl.sh" --quiet --color 0 -U -iL "$dir/hosts/ips.txt" 2>>"$LOGFILE" >"vulns/testssl.txt"

        end_func "Results are saved in vulns/testssl.txt" "${FUNCNAME[0]}"

    else
        # Handle cases where TEST_SSL is false, no vulnerable URLs, or already processed
        if [[ $TEST_SSL == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "vulns/testssl.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate targets for SSL tests"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function spraying() {

    # Create necessary directories
    if ! ensure_dirs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SPRAY == true ]] \
        && [[ -s "$dir/hosts/portscan_active.gnmap" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Password Spraying"

        # Ensure portscan_active.gnmap exists and is not empty
        if [[ ! -s "$dir/hosts/portscan_active.gnmap" ]]; then
            print_warnf "File %s/hosts/portscan_active.gnmap does not exist or is empty." "$dir"
            end_func "Port scan results missing. Password Spraying aborted." "${FUNCNAME[0]}"
            return 1
        fi

        _print_msg INFO "Running: Password Spraying with BruteSpray"

        # Run BruteSpray for password spraying
        brutespray -f "$dir/hosts/portscan_active.gnmap" -T "$BRUTESPRAY_CONCURRENCE" -o "$dir/vulns/brutespray" 2>>"$LOGFILE" >/dev/null

        end_func "Results are saved in vulns/brutespray folder" "${FUNCNAME[0]}"

    else
        # Handle cases where SPRAY is false, required files are missing, or already processed
        if [[ $SPRAY == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "$dir/hosts/portscan_active.gnmap" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: missing active port scan"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function command_injection() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $COMM_INJ == true ]] \
        && [[ -s "gf/rce.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Command Injection Checks"

        # Ensure gf/rce.txt is not empty and process it
        if [[ -s "gf/rce.txt" ]]; then
            _print_msg INFO "Running: Command Injection Payload Generation"

            # Process rce.txt with qsreplace and filter lines containing 'FUZZ'
            run_command qsreplace "FUZZ" <"gf/rce.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_rce.txt"

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_rce.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

    # Run Commix if enabled
    if [[ $COMMIX == true ]]; then
        _print_msg INFO "Running: Commix for Command Injection Checks"
        run_command commix --batch -m ".tmp/tmp_rce.txt" --output-dir "vulns/command_injection" 2>>"$LOGFILE" >/dev/null
    fi

                # Additional tools can be integrated here (e.g., Ghauri, sqlmap)

                end_func "Results are saved in vulns/command_injection folder" "${FUNCNAME[0]}"
            else
                end_func "Skipping Command Injection: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            fi
        else
            end_func "No gf/rce.txt file found, Command Injection Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        # Handle cases where COMM_INJ is false, no vulnerable URLs, or already processed
        if [[ $COMM_INJ == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "gf/rce.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for command injection"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function 4xxbypass() {

    # Create necessary directories
    if ! ensure_dirs .tmp fuzzing vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $BYPASSER4XX == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        # Extract relevant URLs starting with 4xx but not 404
        _print_msg INFO "Running: 403 Bypass"
        grep -E '^4' "fuzzing/fuzzing_full.txt" 2>/dev/null | grep -Ev '^404' | awk '{print $3}' | anew -q ".tmp/403test.txt"

        # Count the number of URLs to process
        URL_COUNT=$(wc -l <".tmp/403test.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            start_func "${FUNCNAME[0]}" "403 Bypass"

            # Navigate to nomore403 tool directory
            if ! pushd "${tools}/nomore403" >/dev/null; then
                print_warnf "Failed to navigate to nomore403 directory."
                end_func "Failed to navigate to nomore403 directory during 403 Bypass." "${FUNCNAME[0]}"
                return 1
            fi

            # Run nomore403 on the processed URLs
            ./nomore403 <"$dir/.tmp/403test.txt" >"$dir/.tmp/4xxbypass.txt" 2>>"$LOGFILE"

            # Return to the original directory
            if ! popd >/dev/null; then
                print_warnf "Failed to return to the original directory."
                end_func "Failed to return to the original directory during 403 Bypass." "${FUNCNAME[0]}"
                return 1
            fi

            # Append unique bypassed URLs to the vulns directory
            if [[ -s "$dir/.tmp/4xxbypass.txt" ]]; then
                cat "$dir/.tmp/4xxbypass.txt" | anew -q "vulns/4xxbypass.txt"
            fi

            end_func "Results are saved in vulns/4xxbypass.txt" "${FUNCNAME[0]}"

        else
            notification "Too many URLs to bypass, skipping" warn
            end_func "Skipping Command Injection: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

    else
        # Handle cases where BYPASSER4XX is false, no vulnerable URLs, or already processed
        if [[ $BYPASSER4XX == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "fuzzing/fuzzing_full.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for 4xx bypass"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function prototype_pollution() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PROTO_POLLUTION == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Prototype Pollution Checks"

        if [[ ! -s "webs/url_extract_nodupes.txt" ]]; then
            _print_msg WARN "File webs/url_extract_nodupes.txt is missing or empty."
            end_func "Skipping prototype pollution: missing URL candidates." "${FUNCNAME[0]}" "SKIP"
            return
        fi

        # Determine whether to proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/url_extract_nodupes.txt" 2>/dev/null || echo 0)
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            # Ensure fuzzing_full.txt exists and has content
            if [[ -s "webs/url_extract_nodupes.txt" ]]; then
                _print_msg INFO "Running: Prototype Pollution Mapping"

                # Process URL list with ppmap and save results
                ppmap <"webs/url_extract_nodupes.txt" >".tmp/prototype_pollution.txt" 2>>"$LOGFILE"

                # Filter and save relevant results
                if [[ -s ".tmp/prototype_pollution.txt" ]]; then
                    grep "EXPL" ".tmp/prototype_pollution.txt" | anew -q "vulns/prototype_pollution.txt"
                fi

                end_func "Results are saved in vulns/prototype_pollution.txt" "${FUNCNAME[0]}"
            else
                end_func "Skipping prototype pollution: missing URL candidates." "${FUNCNAME[0]}" "SKIP"
                return
            fi

        else
            end_func "Skipping Prototype Pollution: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

    else
        # Handle cases where PROTO_POLLUTION is false, no vulnerable URLs, or already processed
        if [[ $PROTO_POLLUTION == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "webs/url_extract_nodupes.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for prototype pollution"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function smuggling() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns/smuggling; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SMUGGLING == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "HTTP Request Smuggling Checks"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat "webs/webs.txt" "webs/webs_uncommon_ports.txt" 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Determine whether to proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/webs_all.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: HTTP Request Smuggling Checks"

            # Run smugglex on the list of URLs
            cat "$dir/webs/webs_all.txt" | smugglex -f plain -o "$dir/.tmp/smuggling.txt" 2>>"$LOGFILE" >/dev/null

            # Append unique smuggling results to vulns directory
            if [[ -s "$dir/.tmp/smuggling.txt" ]]; then
                jq -c < "$dir/.tmp/smuggling.txt" 2>>"$LOGFILE" | anew -q "vulns/smuggling.txt"
            fi

            end_func "Findings are saved in vulns/smuggling.txt" "${FUNCNAME[0]}"

        else
            notification "Too many URLs to bypass, skipping" warn
            end_func "Skipping HTTP Request Smuggling: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

    else
        # Handle cases where SMUGGLING is false, no vulnerable URLs, or already processed
        if [[ $SMUGGLING == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "webs/webs_all.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for HTTP request smuggling"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function webcache() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBCACHE == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Web Cache Poisoning Checks"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Determine whether to proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/webs_all.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: Web Cache Poisoning Checks"

            # Navigate to Web-Cache-Vulnerability-Scanner tool directory
            if ! pushd "${tools}/Web-Cache-Vulnerability-Scanner" >/dev/null; then
                print_warnf "Failed to navigate to Web-Cache-Vulnerability-Scanner directory."
                end_func "Failed to navigate to Web-Cache-Vulnerability-Scanner directory during Web Cache Poisoning Checks." "${FUNCNAME[0]}"
                return 1
            fi

            # Run the Web-Cache-Vulnerability-Scanner
            Web-Cache-Vulnerability-Scanner -u "file:$dir/webs/webs_all.txt" -v 0 2>>"$LOGFILE" \
                | anew -q "$dir/.tmp/webcache.txt"

            # Return to the original directory
            if ! popd >/dev/null; then
                print_warnf "Failed to return to the original directory."
                end_func "Failed to return to the original directory during Web Cache Poisoning Checks." "${FUNCNAME[0]}"
                return 1
            fi

            # Append unique findings to vulns/webcache.txt
            if [[ -s "$dir/.tmp/webcache.txt" ]]; then
                cat "$dir/.tmp/webcache.txt" | anew -q "vulns/webcache.txt"
            fi

            end_func "Results are saved in vulns/webcache.txt" "${FUNCNAME[0]}"

        else
            end_func "Skipping Web Cache Poisoning: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

    else
        # Handle cases where WEBCACHE is false, no vulnerable URLs, or already processed
        if [[ $WEBCACHE == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "fuzzing/fuzzing_full.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for web cache tests"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function fuzzparams() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FUZZPARAMS == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Fuzzing Parameters Values Checks"

        if [[ ! -s "webs/url_extract_nodupes.txt" ]]; then
            _print_msg WARN "File webs/url_extract_nodupes.txt is missing or empty."
            end_func "Skipping fuzzparams: missing URL candidates." "${FUNCNAME[0]}" "SKIP"
            return
        fi

        # Determine if we should proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/url_extract_nodupes.txt" 2>/dev/null || echo 0)
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT2 ]]; then

            #cent update -p ${NUCLEI_TEMPLATES_PATH} &>/dev/null

            if [[ $AXIOM != true ]]; then
                _print_msg INFO "Running: Nuclei Setup and Execution"

                # Update Nuclei once per run
                maybe_update_nuclei

                        # Execute Nuclei with the fuzzing templates

                        run_command nuclei -l webs/url_extract_nodupes.txt -nh -rl "$NUCLEI_RATELIMIT" -silent -retries 2 ${NUCLEI_EXTRA_ARGS} -t ${NUCLEI_TEMPLATES_PATH}/dast -dast -j -o ".tmp/fuzzparams_json.txt" <"webs/url_extract_nodupes.txt" 2>>"$LOGFILE" >/dev/null

                    else

                        _print_msg INFO "Running: Axiom with Nuclei"

                        run_command axiom-scan webs/url_extract_nodupes.txt -m nuclei \
                            -dast -nh -rl "$NUCLEI_RATELIMIT" \
                            -silent -retries 2 "$NUCLEI_EXTRA_ARGS" -dast -j -o ".tmp/fuzzparams_json.txt" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null

                    fi

                

            # Convert JSON output to text
            if [[ -s ".tmp/fuzzparams_json.txt" ]]; then
                jq -r '["[" + .["template-id"] + (if .["matcher-name"] != null then ":" + .["matcher-name"] else "" end) + "] [" + .["type"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host) + (if .["extracted-results"] != null then " " + (.["extracted-results"] | @json) else "" end)] | .[]' .tmp/fuzzparams_json.txt >.tmp/fuzzparams.txt
            else
                : >.tmp/fuzzparams.txt
                log_note "fuzzparams: nuclei produced no JSON output; skipping conversion" "${FUNCNAME[0]}" "${LINENO}"
            fi

            # Append unique results to vulns/fuzzparams.txt
            if [[ -s ".tmp/fuzzparams.txt" ]]; then
                cat ".tmp/fuzzparams.txt" | anew -q "vulns/fuzzparams.txt"
            fi

            # Faraday integration
            if [[ $FARADAY == true ]]; then
                # Check if the Faraday server is running
                if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
                    print_warnf "Faraday server is not running. Skipping Faraday integration."
                else
                    if [[ -s ".tmp/fuzzparams_json.txt" ]]; then
                        faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei .tmp/fuzzparams_json.txt 2>>"$LOGFILE" >/dev/null
                    fi
                fi
            fi

            end_func "Results are saved in vulns/fuzzparams.txt" "${FUNCNAME[0]}"

        else
            end_func "Fuzzing Parameters Values: Too many entries to test, try with --deep flag" "${FUNCNAME[0]}"
        fi

    else
        # Handle cases where FUZZPARAMS is false, no vulnerable URLs, or already processed
        if [[ $FUZZPARAMS == false ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped due to configuration"
        elif [[ ! -s "webs/url_extract_nodupes.txt" ]]; then
            pt_msg_warn "${FUNCNAME[0]} skipped: no candidate URLs for parameter fuzzing"
        else
            pt_msg_warn "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}
