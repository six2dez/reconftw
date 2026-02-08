#!/bin/bash
# shellcheck disable=SC2154  # Variables defined in reconftw.cfg
# reconFTW - OSINT module
# Contains: google_dorks, github_dorks, github_repos, metadata, apileaks,
#           emails, domain_info, third_party_misconfigs, spoof, mail_hygiene,
#           cloud_enum_scan, ip_info
# This file is sourced by reconftw.sh - do not execute directly
[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by reconftw.sh" >&2
    exit 1
}

#####################################################################cc##########################################
################################################### OSINT #####################################################
###############################################################################################################

function google_dorks() {
    ensure_dirs osint

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GOOGLE_DORKS == true ]] && [[ $OSINT == true ]]; then
        start_func "${FUNCNAME[0]}" "Running: Google Dorks in process"

        if ! "${tools}/dorks_hunter/venv/bin/python3" "${tools}/dorks_hunter/dorks_hunter.py" -d "$domain" -o "osint/dorks.txt" 2>>"$LOGFILE"; then
            printf "%b[!] dorks_hunter command failed.%b\n" "$bred" "$reset"
        fi
        end_func "Results are saved in $domain/osint/dorks.txt" "${FUNCNAME[0]}"
    else
        if [[ $GOOGLE_DORKS == false ]] || [[ $OSINT == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi
}

function github_dorks() {
    ensure_dirs osint

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GITHUB_DORKS == true ]] && [[ $OSINT == true ]]; then
        start_func "${FUNCNAME[0]}" "Running: Github Dorks in process"

        if [[ -s $GITHUB_TOKENS ]]; then
            if [[ $DEEP == true ]]; then
                if ! gitdorks_go -gd "${tools}/gitdorks_go/Dorks/medium_dorks.txt" -nws 20 -target "$domain" -tf "$GITHUB_TOKENS" -ew 3 | anew -q osint/gitdorks.txt; then
                    printf "%b[!] gitdorks_go command failed.%b\n" "$bred" "$reset"
                    return 1
                fi
            else
                if ! gitdorks_go -gd "${tools}/gitdorks_go/Dorks/smalldorks.txt" -nws 20 -target "$domain" -tf "$GITHUB_TOKENS" -ew 3 | anew -q osint/gitdorks.txt; then
                    printf "%b[!] gitdorks_go command failed.%b\n" "$bred" "$reset"
                    return 1
                fi
            fi
        else
            printf "\n%b[%s] Required file %s does not exist or is empty.%b\n" "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$GITHUB_TOKENS" "$reset"
            return 1
        fi
        end_func "Results are saved in $domain/osint/gitdorks.txt" "${FUNCNAME[0]}"
    else
        if [[ $GITHUB_DORKS == false ]] || [[ $OSINT == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi
}

function github_repos() {
    ensure_dirs osint

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GITHUB_REPOS == true ]] && [[ $OSINT == true ]]; then
        start_func "${FUNCNAME[0]}" "Github Repos analysis in process"

        if [[ -s $GITHUB_TOKENS ]]; then
            GH_TOKEN=$(head -n 1 "$GITHUB_TOKENS")
            echo "$domain" | unfurl format %r >.tmp/company_name.txt

            if ! enumerepo -token-string "$GH_TOKEN" -usernames .tmp/company_name.txt -o .tmp/company_repos.txt 2>>"$LOGFILE" >/dev/null; then
                printf "%b[!] enumerepo command failed.%b\n" "$bred" "$reset"
            fi

            if [[ -s ".tmp/company_repos.txt" ]]; then
                if ! jq -r '.[].repos[]|.url' <.tmp/company_repos.txt >.tmp/company_repos_url.txt 2>>"$LOGFILE"; then
                    printf "%b[!] jq command failed.%b\n" "$bred" "$reset"
                fi
            fi

            ensure_dirs .tmp/github_repos .tmp/github

            if [[ -s ".tmp/company_repos_url.txt" ]]; then
                if ! interlace -tL .tmp/company_repos_url.txt -threads "$INTERLACE_THREADS" -c "git clone _target_ .tmp/github_repos/_cleantarget_" 2>>"$LOGFILE" >/dev/null; then
                    printf "%b[!] interlace git clone command failed.%b\n" "$bred" "$reset"
                    return 1
                fi
            else
                log_note "No GitHub repos found for ${domain}; continuing" "${FUNCNAME[0]}" "${LINENO}"
                end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
                return 0
            fi

            if [[ -d ".tmp/github_repos/" ]]; then
                ls .tmp/github_repos >.tmp/github_repos_folders.txt
            else
                log_note "GitHub clone directory missing for ${domain}; no repo artifacts to process" "${FUNCNAME[0]}" "${LINENO}"
                end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
                return 0
            fi

            if [[ -s ".tmp/github_repos_folders.txt" ]]; then
                if ! interlace -tL .tmp/github_repos_folders.txt -threads "$INTERLACE_THREADS" -c "gitleaks detect --source .tmp/github_repos/_target_ --no-banner --no-color -r .tmp/github/gh_secret_cleantarget_.json" 2>>"$LOGFILE" >/dev/null; then
                    printf "%b[!] interlace gitleaks command failed.%b\n" "$bred" "$reset"
                    end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
                    return 1
                fi
            else
                log_note "No cloned GitHub repos to scan with gitleaks for ${domain}" "${FUNCNAME[0]}" "${LINENO}"
                end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
                return 0
            fi

            if [[ -s ".tmp/company_repos_url.txt" ]]; then
                if ! interlace -tL .tmp/company_repos_url.txt -threads "$INTERLACE_THREADS" -c "trufflehog git _target_ -j 2>&1 | jq -c > _output_/_cleantarget_" -o .tmp/github/ 2>>"$LOGFILE" >/dev/null; then
                    printf "%b[!] interlace trufflehog command failed.%b\n" "$bred" "$reset"
                    return 1
                fi
            fi

            if [[ -d ".tmp/github/" ]]; then
                if ! cat .tmp/github/* 2>/dev/null | jq -c | jq -r >"osint/github_company_secrets.json" 2>>"$LOGFILE"; then
                    printf "%b[!] Error combining results.%b\n" "$bred" "$reset"
                    return 1
                fi
            else
                log_note "No GitHub scan outputs available to merge for ${domain}" "${FUNCNAME[0]}" "${LINENO}"
                end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
                return 0
            fi

            end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
        else
            printf "\n%s[%s] Required file %s does not exist or is empty.%b\n" "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$GITHUB_TOKENS" "$reset"
            return 1
        fi
    else
        if [[ $GITHUB_REPOS == false ]] || [[ $OSINT == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi
}

function metadata() {
    ensure_dirs osint

    # Check if the function should run
    if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ ${DIFF} == true ]]; } && [[ ${METADATA} == true ]] && [[ ${OSINT} == true ]] && ! [[ ${domain} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        start_func "${FUNCNAME[0]}" "Scanning metadata in public files"

        ensure_dirs ".tmp/metagoofil_${domain}"
        pushd "${tools}/metagoofil" >/dev/null || {
            printf "%b[!] Failed to change directory to %s in %s at line %s.%b\n" "${bred}" "${tools}/metagoofil" "${FUNCNAME[0]}" "${LINENO}" "${reset}"
            return 1
        }
        "${tools}/metagoofil/venv/bin/python3" "${tools}/metagoofil/metagoofil.py" -d "${domain}" -t pdf,docx,xlsx -l 10 -w -o "${dir}/.tmp/metagoofil_${domain}/" 2>>"${LOGFILE}" >/dev/null
        popd >/dev/null || {
            printf "%b[!] Failed to return to the previous directory in %s at line %s.%b\n" "${bred}" "${FUNCNAME[0]}" "${LINENO}" "${reset}"
            return 1
        }

        # Check if exiftool is installed before running
        if command -v exiftool &>/dev/null; then
            exiftool -r .tmp/metagoofil_${domain}/* 2>>"${LOGFILE}" | tee /dev/null | egrep -i "Author|Creator|Email|Producer|Template" | sort -u | anew -q "osint/metadata_results.txt"
        else
            printf "%b[!] exiftool is not installed. Skipping metadata extraction.%b\n" "${bred}" "${reset}"
            printf "exiftool not installed - metadata extraction skipped\n" >>"${LOGFILE}"
        fi

        end_func "Results are saved in ${domain}/osint/metadata_results.txt" "${FUNCNAME[0]}"
    else
        if [[ ${METADATA} == false ]] || [[ ${OSINT} == false ]]; then
            skip_notification "disabled"
        elif [[ ${domain} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi
}

function apileaks() {
    ensure_dirs osint

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } \
        && [[ $API_LEAKS == true ]] && [[ $OSINT == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Scanning for leaks in public API directories"

        # Run porch-pirate (full dump); fallback to light mode if dump fails
        if ! porch-pirate -s "$domain" -l 25 --dump 2>>"$LOGFILE" >"${dir}/osint/postman_leaks.txt"; then
            log_note "porch-pirate --dump failed; retrying without --dump" "${FUNCNAME[0]}" "${LINENO}"
            if ! porch-pirate -s "$domain" -l 25 2>>"$LOGFILE" >"${dir}/osint/postman_leaks.txt"; then
                log_note "porch-pirate failed even without --dump" "${FUNCNAME[0]}" "${LINENO}"
            fi
        fi

        # Change directory to SwaggerSpy
        if ! pushd "${tools}/SwaggerSpy" >/dev/null; then
            printf "%b[!] Failed to change directory to %s in %s at line %s.%b\n" "$bred" "${tools}/SwaggerSpy" "${FUNCNAME[0]}" "$LINENO" "$reset"
            return 1
        fi

        # Run swaggerspy.py and handle errors
        local swag_cmd=("${tools}/SwaggerSpy/venv/bin/python3" "swaggerspy.py" "$domain")
        local swag_timeout="${SWAGGERSPY_TIMEOUT:-5m}"
        [[ -n ${TIMEOUT_CMD:-} ]] && swag_cmd=("$TIMEOUT_CMD" "$swag_timeout" "${swag_cmd[@]}")
        local swagger_rc=0
        {
            "${swag_cmd[@]}" 2>>"$LOGFILE" | grep -i "[*]\|URL" >"${dir}/osint/swagger_leaks.txt"
            swagger_rc=${PIPESTATUS[0]:-0} # ignore grep exit code (no matches is fine)
        } || true
        if ((swagger_rc != 0)); then
            printf "%b[%s] SwaggerSpy failed (exit %s), continuing without swagger results.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$swagger_rc" "$reset" | tee -a "$LOGFILE" >/dev/null
        fi

        # Return to the previous directory
        if ! popd >/dev/null; then
            printf "%b[!] Failed to return to the previous directory in %s at line %s.%b\n" "$bred" "${FUNCNAME[0]}" "$LINENO" "$reset"
            return 1
        fi

            # Analyze leaks with trufflehog
            if [[ -s "${dir}/osint/postman_leaks.txt" ]]; then
                run_command trufflehog filesystem "${dir}/osint/postman_leaks.txt" -j 2>/dev/null | jq -c | anew -q "${dir}/osint/postman_leaks_trufflehog.json"
            fi
        
            if [[ -s "${dir}/osint/swagger_leaks.txt" ]]; then
                run_command trufflehog filesystem "${dir}/osint/swagger_leaks.txt" -j 2>/dev/null | jq -c | anew -q "${dir}/osint/swagger_leaks_trufflehog.json"
            fi
                end_func "Results are saved in $domain/osint/[postman_leaks_trufflehog.json, swagger_leaks_trufflehog.json]" "${FUNCNAME[0]}"
    else
        if [[ $API_LEAKS == false ]] || [[ $OSINT == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s %b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "${FUNCNAME[0]}" "$reset"
        fi
    fi
}

function emails() {
    ensure_dirs .tmp osint

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } \
        && [[ $EMAILS == true ]] && [[ $OSINT == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Searching for emails/users/passwords leaks"

        PYTHONWARNINGS=ignore "${tools}/EmailHarvester/venv/bin/python3" "${tools}/EmailHarvester/EmailHarvester.py" -d ${domain} -e all -l 20 2>>"$LOGFILE" | anew -q .tmp/EmailHarvester.txt || true

        # Process emailfinder results
        if [[ -s ".tmp/EmailHarvester.txt" ]]; then
            grep "@" .tmp/EmailHarvester.txt | anew -q osint/emails.txt || true
        fi

        # Change directory to LeakSearch
        if ! pushd "${tools}/LeakSearch" >/dev/null; then
            printf "%b[!] Failed to change directory to %s in %s at line %s.%b\n" "$bred" "${tools}/LeakSearch" "${FUNCNAME[0]}" "$LINENO" "$reset"
            return 1
        fi

        # Run LeakSearch.py and handle errors
        "${tools}/LeakSearch/venv/bin/python3" LeakSearch.py -k "$domain" -o "${dir}/.tmp/passwords.txt" 1>>"$LOGFILE"

        # Return to the previous directory
        if ! popd >/dev/null; then
            printf "%b[!] Failed to return to the previous directory in %s at line %s.%b\n" "$bred" "${FUNCNAME[0]}" "$LINENO" "$reset"
            return 1
        fi

        # Process passwords.txt
        if [[ -s "${dir}/.tmp/passwords.txt" ]]; then
            anew -q osint/passwords.txt <"${dir}/.tmp/passwords.txt"
        fi

        end_func "Results are saved in $domain/osint/emails.txt and passwords.txt" "${FUNCNAME[0]}"
    else
        if [[ $EMAILS == false ]] || [[ $OSINT == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi
}

function domain_info() {

    ensure_dirs osint

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } \
        && [[ $DOMAIN_INFO == true ]] && [[ $OSINT == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Searching domain info (whois, registrant name/email domains)"

        # Run whois command and check for errors
        whois "$domain" >"osint/domain_info_general.txt"
        "${tools}/msftrecon/venv/bin/python3" "${tools}/msftrecon/msftrecon/msftrecon.py" -d ${domain} 2>>"$LOGFILE" >osint/azure_tenant_domains.txt || true

        company_name=$(unfurl format %r <<<"$domain")
        "${tools}/Scopify/venv/bin/python3" "${tools}/Scopify/scopify.py" -c ${company_name} >osint/scopify.txt

        end_func "Results are saved in ${domain}/osint/domain_info_[general/azure_tenant_domains].txt" "${FUNCNAME[0]}"

    else
        if [[ $DOMAIN_INFO == false ]] || [[ $OSINT == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi
}

function third_party_misconfigs() {
    ensure_dirs osint

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } \
        && [[ $THIRD_PARTIES == true ]] && [[ $OSINT == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Searching for third parties misconfigurations"

        # Extract company name from domain
        company_name=$(unfurl format %r <<<"$domain")

        # Change directory to Spoofy tool
        if ! pushd "${tools}/misconfig-mapper" >/dev/null; then
            printf "%b[!] Failed to change directory to %s in %s at line %s.%b\n" \
                "$bred" "${tools}/misconfig-mapper" "${FUNCNAME[0]}" "$LINENO" "$reset"
            return 1
        fi

        misconfig-mapper -update-templates 1>>"$LOGFILE"
        misconfig-mapper -target visma.com -as-domain true -permutations false -skip-ssl \
            -service "*" -verbose 0 | anew -q "${dir}/osint/3rdparts_misconfigurations.txt"
        misconfig-mapper -target "$company_name" -skip-ssl -verbose 0 -service "*" \
            | anew -q "${dir}/osint/3rdparts_misconfigurations.txt"

        # Return to the previous directory
        if ! popd >/dev/null; then
            printf "%b[!] Failed to return to previous directory in %s at line %s.%b\n" \
                "$bred" "${FUNCNAME[0]}" "$LINENO" "$reset"
            return 1
        fi

        end_func "Results are saved in $domain/osint/3rdparts_misconfigurations.txt" "${FUNCNAME[0]}"

    else
        if [[ $THIRD_PARTIES == false ]] || [[ $OSINT == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi
}

function spoof() {
    ensure_dirs osint

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } \
        && [[ $SPOOF == true ]] && [[ $OSINT == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Searching for spoofable domains"

        # Change directory to Spoofy tool
        if ! pushd "${tools}/Spoofy" >/dev/null; then
            printf "%b[!] Failed to change directory to %s in %s at line %s.%b\n" \
                "$bred" "${tools}/Spoofy" "${FUNCNAME[0]}" "$LINENO" "$reset"
            return 1
        fi

        # Run spoofy.py and handle errors
        "${tools}/Spoofy/venv/bin/python3" spoofy.py -d "$domain" >"${dir}/osint/spoof.txt"

        # Return to the previous directory
        if ! popd >/dev/null; then
            printf "%b[!] Failed to return to previous directory in %s at line %s.%b\n" \
                "$bred" "${FUNCNAME[0]}" "$LINENO" "$reset"
            return 1
        fi

        end_func "Results are saved in $domain/osint/spoof.txt" "${FUNCNAME[0]}"

    else
        if [[ $SPOOF == false ]] || [[ $OSINT == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi
}

function mail_hygiene() {
    ensure_dirs osint

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } \
        && [[ $MAIL_HYGIENE == true ]] && [[ $OSINT == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Mail hygiene (SPF/DMARC)"
        {
            printf "Domain: %s\n" "$domain"
            printf "\nTXT records:\n"
            dig +short TXT "$domain" | sed 's/^/  /'
            printf "\nDMARC record:\n"
            dig +short TXT "_dmarc.$domain" | sed 's/^/  /'
        } >"osint/mail_hygiene.txt" 2>>"$LOGFILE"
        end_func "Results are saved in $domain/osint/mail_hygiene.txt" "${FUNCNAME[0]}"
    else
        if [[ $MAIL_HYGIENE == false ]] || [[ $OSINT == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s %b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "${FUNCNAME[0]}" "$reset"
        fi
    fi
}

function cloud_enum_scan() {
    ensure_dirs osint

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } \
        && [[ $CLOUD_ENUM == true ]] && [[ $OSINT == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Cloud storage enumeration"
        company_name=$(unfurl format %r <<<"$domain")
        cloud_enum -k "$company_name" -k "$domain" -k "${domain%%.*}" 2>>"$LOGFILE" | anew -q osint/cloud_enum.txt
        end_func "Results are saved in $domain/osint/cloud_enum.txt" "${FUNCNAME[0]}"
    else
        if [[ $CLOUD_ENUM == false ]] || [[ $OSINT == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s %b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "${FUNCNAME[0]}" "$reset"
        fi
    fi
}

function ip_info() {

    ensure_dirs osint

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } \
        && [[ $IP_INFO == true ]] && [[ $OSINT == true ]] \
        && [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Searching IP info"

        if [[ -n $WHOISXML_API ]]; then

            # Reverse IP lookup
            curl -s "https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ip=${domain}" \
                | jq -r '.result[].name' 2>>"$LOGFILE" \
                | sed -e "s/$/ ${domain}/" \
                | anew -q "osint/ip_${domain}_relations.txt"

            # WHOIS lookup
            curl -s "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOISXML_API}&domainName=${domain}&outputFormat=json&da=2&registryRawText=1&registrarRawText=1&ignoreRawTexts=1" \
                | jq 2>>"$LOGFILE" \
                | anew -q "osint/ip_${domain}_whois.txt"

            # IP Geolocation
            curl -s "https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ipAddress=${domain}" \
                | jq -r '.ip,.location' 2>>"$LOGFILE" \
                | anew -q "osint/ip_${domain}_location.txt"

            end_func "Results are saved in ${domain}/osint/ip_[domain_relations|whois|location].txt" "${FUNCNAME[0]}"

        else
            printf "\n%s[%s] WHOISXML_API variable is not defined. Skipping function.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
        fi

    else
        if [[ $IP_INFO == false ]] || [[ $OSINT == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi

}
