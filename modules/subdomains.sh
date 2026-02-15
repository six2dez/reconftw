#!/bin/bash
# shellcheck disable=SC2154  # Variables defined in reconftw.cfg
# reconFTW - Subdomain enumeration module
# Contains: subdomains_full, sub_passive, sub_crt, sub_active, sub_tls,
#           sub_noerror, sub_dns, sub_brute, sub_scraping, sub_analytics,
#           sub_permut, sub_regex_permut, sub_ia_permut, sub_recursive_passive,
#           sub_recursive_brute, subtakeover, zonetransfer, s3buckets,
#           geo_info
# Helpers: deep_wildcard_filter, _is_sensitive_domain
# This file is sourced by reconftw.sh - do not execute directly
[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by reconftw.sh" >&2
    exit 1
}

###############################################################################
# Helper Functions for subdomains_full
###############################################################################

# Deep wildcard detection - filters wildcards at all subdomain levels
# Based on DEF CON Subdomain Enumeration techniques
# Usage: deep_wildcard_filter input_file output_file
# Returns: 0 on success, writes filtered results to output_file
deep_wildcard_filter() {
    local input_file="$1"
    local output_file="$2"
    local max_iterations=5
    local iteration=0
    local wildcards_found=1

    if [[ ! -s "$input_file" ]]; then
        touch "$output_file"
        return 0
    fi

    # Copy input to working file
    cp "$input_file" ".tmp/dwf_working.txt"
    : > ".tmp/dwf_wildcards.txt"

    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
        printf "%b[*] Running deep wildcard detection (max %d iterations)%b\n" "$bblue" "$max_iterations" "$reset"

    while [[ $wildcards_found -gt 0 ]] && [[ $iteration -lt $max_iterations ]]; do
        ((iteration++))
        wildcards_found=0

        # Extract unique parent domains at each level
        # e.g., from "a.b.c.example.com" extract "b.c.example.com", "c.example.com"
        : > ".tmp/dwf_parents.txt"
        while IFS= read -r subdomain; do
            # Skip if it's already the base domain or has no subdomain part
            [[ "$subdomain" == "$domain" ]] && continue

            # Extract parent by removing the first label
            local parent
            parent="${subdomain#*.}"

            # Only consider parents that are still subdomains of target domain
            if [[ "$parent" == *".$domain" ]] || [[ "$parent" == "$domain" ]]; then
                echo "$parent" >> ".tmp/dwf_parents.txt"
            fi
        done < ".tmp/dwf_working.txt"

        # Get unique parents
        sort -u ".tmp/dwf_parents.txt" -o ".tmp/dwf_parents_unique.txt"

        # Filter out already known wildcards and base domain
        if [[ -s ".tmp/dwf_wildcards.txt" ]]; then
            grep -v -F -f ".tmp/dwf_wildcards.txt" ".tmp/dwf_parents_unique.txt" 2>/dev/null > ".tmp/dwf_parents_check.txt" || true
        else
            cp ".tmp/dwf_parents_unique.txt" ".tmp/dwf_parents_check.txt"
        fi

        # Remove base domain from check list
        grep -v "^${domain}$" ".tmp/dwf_parents_check.txt" > ".tmp/dwf_parents_final.txt" 2>/dev/null || true

        if [[ ! -s ".tmp/dwf_parents_final.txt" ]]; then
            break
        fi

        # Generate random probe hostnames for each parent
        : > ".tmp/dwf_probes.txt"
        while IFS= read -r parent; do
            # Generate random string (alphanumeric)
            local random_str
            random_str=$(head -c 100 /dev/urandom 2>/dev/null | LC_ALL=C tr -dc 'a-z0-9' | head -c 12)
            echo "${random_str}.${parent}" >> ".tmp/dwf_probes.txt"
        done < ".tmp/dwf_parents_final.txt"

        # Test which random probes resolve (indicating wildcard)
        if [[ -s ".tmp/dwf_probes.txt" ]]; then
            run_command dnsx -silent -retry 2 -r "$resolvers_trusted" < ".tmp/dwf_probes.txt" > ".tmp/dwf_resolved_probes.txt" 2>/dev/null || true

            # Extract parent domains that are wildcards
            if [[ -s ".tmp/dwf_resolved_probes.txt" ]]; then
                while IFS= read -r resolved_probe; do
                    # Extract the parent (remove the random prefix we added)
                    local wildcard_parent
                    wildcard_parent="${resolved_probe#*.}"
                    echo "$wildcard_parent" >> ".tmp/dwf_new_wildcards.txt"
                    ((wildcards_found++))
                done < ".tmp/dwf_resolved_probes.txt"

                if [[ -s ".tmp/dwf_new_wildcards.txt" ]]; then
                    sort -u ".tmp/dwf_new_wildcards.txt" >> ".tmp/dwf_wildcards.txt"
                    sort -u ".tmp/dwf_wildcards.txt" -o ".tmp/dwf_wildcards.txt"
                    rm -f ".tmp/dwf_new_wildcards.txt"

                    # Filter out subdomains under wildcard parents
                    : > ".tmp/dwf_filtered.txt"
                    while IFS= read -r subdomain; do
                        local is_under_wildcard=false
                        while IFS= read -r wildcard; do
                            if [[ "$subdomain" == *".$wildcard" ]] || [[ "$subdomain" == "$wildcard" ]]; then
                                is_under_wildcard=true
                                break
                            fi
                        done < ".tmp/dwf_wildcards.txt"

                        if [[ "$is_under_wildcard" == false ]]; then
                            echo "$subdomain" >> ".tmp/dwf_filtered.txt"
                        fi
                    done < ".tmp/dwf_working.txt"

                    mv ".tmp/dwf_filtered.txt" ".tmp/dwf_working.txt"
                fi
            fi
        fi

        [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
            printf "%b    Iteration %d: found %d new wildcard parent(s)%b\n" "$yellow" "$iteration" "$wildcards_found" "$reset"
    done

    # Copy final results to output
    cp ".tmp/dwf_working.txt" "$output_file"

    # Report statistics
    local original_count filtered_count wildcards_count
    original_count=$(wc -l < "$input_file" | tr -d ' ')
    filtered_count=$(wc -l < "$output_file" | tr -d ' ')
    wildcards_count=$(wc -l < ".tmp/dwf_wildcards.txt" 2>/dev/null | tr -d ' ' || echo 0)
    local removed=$((original_count - filtered_count))

    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
        printf "%b[*] Deep wildcard filter: %d wildcards detected, %d subdomains removed (%d -> %d)%b\n" \
            "$bgreen" "$wildcards_count" "$removed" "$original_count" "$filtered_count" "$reset"

    # Save wildcard list for reference
    if [[ -s ".tmp/dwf_wildcards.txt" ]]; then
        cp ".tmp/dwf_wildcards.txt" "subdomains/wildcards_detected.txt"
    fi

    # Cleanup temp files
    rm -f ".tmp/dwf_"*.txt

    return 0
}

# Check if a domain matches sensitive domain patterns
# Usage: _is_sensitive_domain domain patterns_file
# Returns: 0 if domain is sensitive, 1 if not
_is_sensitive_domain() {
    local check_domain="$1"
    local patterns_file="$2"

    [[ ! -s "$patterns_file" ]] && return 1

    while IFS= read -r pattern; do
        # Skip comments and empty lines
        [[ -z "$pattern" ]] && continue
        [[ "$pattern" =~ ^[[:space:]]*# ]] && continue

        # Remove leading/trailing whitespace
        pattern=$(echo "$pattern" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$pattern" ]] && continue

        # Handle wildcard patterns (*.gov, *.mil, etc.)
        if [[ "$pattern" == \*.* ]]; then
            # Remove leading *. for matching
            local suffix="${pattern#\*.}"
            # Check if domain ends with the pattern
            if [[ "$check_domain" == *".$suffix" ]] || [[ "$check_domain" == "$suffix" ]]; then
                return 0
            fi
        else
            # Exact match or subdomain match
            if [[ "$check_domain" == "$pattern" ]] || [[ "$check_domain" == *".$pattern" ]]; then
                return 0
            fi
        fi
    done < "$patterns_file"

    return 1
}

# Initialize subdomain enumeration environment
# Usage: _subdomains_init
_subdomains_init() {
    if ! ensure_dirs .tmp webs subdomains; then
        return 1
    fi

    # Escape domain for safe use in grep regex (dots are literal, not wildcards)
    DOMAIN_ESCAPED=$(escape_domain_regex "$domain")

    # Check for sensitive domain exclusion
    if [[ "${EXCLUDE_SENSITIVE:-false}" == true ]]; then
        local sensitive_file="${SCRIPTPATH}/config/sensitive_domains.txt"
        if [[ -s "$sensitive_file" ]]; then
            if _is_sensitive_domain "$domain" "$sensitive_file"; then
                _print_status FAIL "Sensitive domain" "0s"
                printf "         Domain '%s' matches sensitive pattern. Set EXCLUDE_SENSITIVE=false to override.\n" "$domain"
                return 1
            fi
        fi
    fi

    # Backup existing files
    safe_backup "subdomains/subdomains.txt" ".tmp/subdomains_old.txt"
    safe_backup "webs/webs.txt" ".tmp/probed_old.txt"

    # Update resolvers if needed
    if { [[ ! -f "$called_fn_dir/.sub_active" ]] || [[ ! -f "$called_fn_dir/.sub_brute" ]] || \
         [[ ! -f "$called_fn_dir/.sub_permut" ]] || [[ ! -f "$called_fn_dir/.sub_recursive_brute" ]]; } || \
       [[ $DIFF == true ]]; then
        resolvers_update || return 1
    fi

    # Add in-scope subdomains
    [[ -s $inScope_file ]] && cat "$inScope_file" | anew -q subdomains/subdomains.txt

    return 0
}

# Run subdomain enumeration functions (sequential or parallel)
# Usage: _subdomains_enumerate [--parallel]
_subdomains_enumerate() {
    local use_parallel="${1:-}"
    
    if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ $SUBDOMAINS_GENERAL != true ]]; then
        notification "IP/CIDR detected, subdomains search skipped" "info"
        printf "%b\n" "$domain" | anew -q subdomains/subdomains.txt
        return 0
    fi
    
    if [[ "$use_parallel" == "--parallel" ]] && declare -f parallel_funcs &>/dev/null; then
        # Parallel execution using lib/parallel.sh
        [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && printf "%b[*] Running subdomain enumeration in parallel mode%b\n" "$bblue" "$reset"
        
        # Phase 0: ASN enumeration (independent)
        sub_asn
        
        # Phase 1: Passive sources (all can run in parallel)
        parallel_funcs "${PAR_SUB_PASSIVE_GROUP_SIZE:-4}" sub_passive sub_crt
        local sub_g1_rc=$?
        if ((sub_g1_rc > 0)); then
            if [[ "${CONTINUE_ON_TOOL_ERROR:-true}" == "true" ]]; then
                notification "Parallel subdomain passive phase completed with ${sub_g1_rc} warning(s); continuing" warn
            else
                notification "Parallel subdomain batch failed (passive)" error
                return 1
            fi
        fi
        
        # Phase 2: Active base list (must complete before dependent phases)
        sub_active
        local sub_g2_rc=$?
        if ((sub_g2_rc > 0)); then
            if [[ "${CONTINUE_ON_TOOL_ERROR:-true}" == "true" ]]; then
                notification "sub_active completed with warning(s); continuing with dependent subdomain phases" warn
            else
                notification "sub_active failed" error
                return 1
            fi
        fi
        
        # Phase 3: Dependent active enrichment (runs after sub_active is ready)
        parallel_funcs "${PAR_SUB_DEP_ACTIVE_GROUP_SIZE:-3}" sub_noerror sub_dns
        local sub_g3_rc=$?
        if ((sub_g3_rc > 0)); then
            if [[ "${CONTINUE_ON_TOOL_ERROR:-true}" == "true" ]]; then
                notification "Parallel subdomain dependent active phase completed with ${sub_g3_rc} warning(s); continuing" warn
            else
                notification "Parallel subdomain batch failed (dependent active)" error
                return 1
            fi
        fi

        # Phase 4: Post-active analysis (depends on active/enrichment results)
        parallel_funcs "${PAR_SUB_POST_ACTIVE_GROUP_SIZE:-2}" sub_tls sub_analytics
        local sub_g4_rc=$?
        if ((sub_g4_rc > 0)); then
            if [[ "${CONTINUE_ON_TOOL_ERROR:-true}" == "true" ]]; then
                notification "Parallel subdomain post-active phase completed with ${sub_g4_rc} warning(s); continuing" warn
            else
                notification "Parallel subdomain batch failed (post-active)" error
                return 1
            fi
        fi
        
        # Phase 5: Brute force (limited parallelism - resource intensive)
        parallel_funcs "${PAR_SUB_BRUTE_GROUP_SIZE:-2}" sub_brute sub_permut sub_regex_permut sub_ia_permut
        local sub_g5_rc=$?
        if ((sub_g5_rc > 0)); then
            if [[ "${CONTINUE_ON_TOOL_ERROR:-true}" == "true" ]]; then
                notification "Parallel subdomain bruteforce/permutations phase completed with ${sub_g5_rc} warning(s); continuing" warn
            else
                notification "Parallel subdomain batch failed (bruteforce/permutations)" error
                return 1
            fi
        fi
        
        # Phase 6: Recursive and scraping (sequential - depends on previous results)
        sub_recursive_passive
        sub_recursive_brute
        sub_scraping
    else
        # Sequential execution (original behavior)
        sub_asn
        sub_passive
        sub_crt
        sub_active
        sub_tls
        sub_noerror
        sub_brute
        sub_permut
        sub_regex_permut
        sub_ia_permut
        sub_recursive_passive
        sub_recursive_brute
        sub_dns
        sub_scraping
        sub_analytics
    fi
}

# Process and finalize subdomain results
# Usage: _subdomains_finalize
_subdomains_finalize() {
    # Remove out-of-scope entries
    if [[ -s "subdomains/subdomains.txt" ]] && [[ -s $outOfScope_file ]]; then
        deleteOutScoped "$outOfScope_file" "subdomains/subdomains.txt"
    fi

    if [[ -s "webs/webs.txt" ]] && [[ -s $outOfScope_file ]]; then
        deleteOutScoped "$outOfScope_file" "webs/webs.txt"
    fi

    # Apply deep wildcard filtering if enabled
    if [[ "${DEEP_WILDCARD_FILTER:-false}" == true ]] && [[ -s "subdomains/subdomains.txt" ]]; then
        deep_wildcard_filter "subdomains/subdomains.txt" "subdomains/subdomains_filtered.txt"
        if [[ -s "subdomains/subdomains_filtered.txt" ]]; then
            mv "subdomains/subdomains_filtered.txt" "subdomains/subdomains.txt"
        fi
    fi

    # Display results
    TOTAL_SUBS=$(sed '/^$/d' "subdomains/subdomains.txt" 2>/dev/null | wc -l | tr -d ' ')

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]]; then
        _print_status OK "subdomains_full" "${TOTAL_SUBS} found -> subdomains/subdomains.txt"
        print_artifacts "subdomains/subdomains.txt"
    fi
    
    # Emit plugin event
    plugins_emit after_subdomains "$domain" "$dir"
    
    # Incremental mode
    incremental_diff "subdomains" "subdomains/subdomains.txt" "subdomains/subdomains_new.txt"
    incremental_save "subdomains" "subdomains/subdomains.txt"
    ensure_dirs webs .tmp subdomains
    if [[ -s "webs/webs.txt" ]]; then
        incremental_diff "webs" "webs/webs.txt" "webs/webs_new.txt"
        incremental_save "webs" "webs/webs.txt"
    else
        : > "webs/webs_new.txt"
    fi
    
    # Persist counts
    [[ -f "subdomains/subdomains_new.txt" ]] || : > "subdomains/subdomains_new.txt"
    wc -l < "subdomains/subdomains_new.txt" 2>/dev/null > .tmp/subs_new_count
    [[ -f "webs/webs_new.txt" ]] || : > "webs/webs_new.txt"
    wc -l < "webs/webs_new.txt" 2>/dev/null > .tmp/webs_new_count
    
    # Asset store
    if [[ -s subdomains/subdomains_new.txt ]]; then
        append_assets_from_file subdomain name subdomains/subdomains_new.txt
    else
        append_assets_from_file subdomain name subdomains/subdomains.txt
    fi
}

###############################################################################
# Main Subdomain Functions
###############################################################################

# Main subdomain enumeration orchestrator
# Usage: subdomains_full
# Uses PARALLEL_MODE global variable if set
function subdomains_full() {
    # Parallel mode is enabled by default; use PARALLEL_MODE=false to disable
    local parallel_flag="--parallel"
    [[ "${PARALLEL_MODE:-true}" == "false" ]] && parallel_flag=""
    
    # Initialize
    _subdomains_init || return 1
    
    # Enumerate
    _subdomains_enumerate "$parallel_flag"
    
    # Finalize
    _subdomains_finalize
}

function sub_asn() {
    ensure_dirs .tmp subdomains hosts

    if should_run "ASN_ENUM"; then
        start_subfunc "${FUNCNAME[0]}" "Running: ASN Enumeration"

        # Discover ASN/CIDR metadata for the current target domain.
        local asn_json pdcp_key asn_rc asn_status
        if command -v asnmap &>/dev/null; then
            asn_json=".tmp/asnmap_${domain}.json"
            pdcp_key="${PDCP_API_KEY:-}"
            asn_rc=0
            asn_status="OK"
            : >"$asn_json"

            if [[ -z "${pdcp_key//[[:space:]]/}" ]]; then
                _print_msg WARN "ASN_ENUM enabled but PDCP_API_KEY is not set. Skipping asnmap ASN enumeration."
                log_note "ASN_ENUM enabled but PDCP_API_KEY is not set. Skipping asnmap ASN enumeration." "${FUNCNAME[0]}" "${LINENO}"
                asn_status="WARN"
            else
                if [[ -n ${TIMEOUT_CMD:-} ]]; then
                    run_command "$TIMEOUT_CMD" -k 10s 120s asnmap -d "$domain" -silent -j 2>>"$LOGFILE" >"$asn_json"
                    asn_rc=$?
                elif run_command asnmap -d "$domain" -silent -j 2>>"$LOGFILE" >"$asn_json"; then
                    asn_rc=0
                else
                    asn_rc=$?
                fi

                if [[ "${DRY_RUN:-false}" == "true" ]]; then
                    _print_msg INFO "Dry-run: asnmap execution recorded, ASN parsing skipped."
                    asn_status="SKIP"
                elif [[ $asn_rc -eq 0 && -s "$asn_json" ]]; then
                    jq -r '.cidr // empty' "$asn_json" | sed '/^$/d' | sort -u >.tmp/asn_cidrs.txt
                    jq -r '.as_number // empty' "$asn_json" | sed '/^$/d' | sort -u >.tmp/asn_numbers.txt

                    if [[ -s .tmp/asn_cidrs.txt ]]; then
                        cp .tmp/asn_cidrs.txt hosts/asn_cidrs.txt
                    fi
                    if [[ -s .tmp/asn_numbers.txt ]]; then
                        cp .tmp/asn_numbers.txt hosts/asn_numbers.txt
                    fi

                    local cidr_count asn_count
                    cidr_count=$(wc -l <.tmp/asn_cidrs.txt 2>/dev/null | tr -d ' ')
                    asn_count=$(wc -l <.tmp/asn_numbers.txt 2>/dev/null | tr -d ' ')

                    _print_msg INFO "ASN enumeration found ${asn_count:-0} ASNs and ${cidr_count:-0} CIDR ranges"

                    # Optional: if asnmap yields discovered domains, feed them into subdomain pipeline.
                    jq -r '.domains[]? // empty' "$asn_json" \
                        | sed '/^$/d' \
                        | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                        | grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" \
                        | sort -u \
                        | anew -q .tmp/subs_no_resolved.txt || true
                    if [[ -s .tmp/subs_no_resolved.txt ]]; then
                        _print_msg INFO "ASN sources added $(wc -l <.tmp/subs_no_resolved.txt | tr -d ' ') in-scope domains"
                    fi
                elif [[ $asn_rc -eq 124 || $asn_rc -eq 137 ]]; then
                    _print_msg WARN "asnmap timed out after 120s. Skipping ASN output for ${domain}."
                    log_note "asnmap timed out after 120s. Skipping ASN output for ${domain}." "${FUNCNAME[0]}" "${LINENO}"
                    asn_status="WARN"
                else
                    _print_msg FAIL "asnmap failed (exit ${asn_rc:-1}). Skipping ASN output for ${domain}."
                    log_note "asnmap failed (exit ${asn_rc:-1}). Skipping ASN output for ${domain}." "${FUNCNAME[0]}" "${LINENO}"
                    asn_status="FAIL"
                fi
            fi
        else
            _print_msg WARN "asnmap not installed, skipping ASN enumeration"
            log_note "asnmap not installed, skipping ASN enumeration" "${FUNCNAME[0]}" "${LINENO}"
            asn_status="WARN"
        fi

        end_subfunc "${FUNCNAME[0]}" "${FUNCNAME[0]}" "${asn_status:-OK}"
    else
        if [[ $ASN_ENUM == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to configuration settings."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi
}

function sub_passive() {

    ensure_dirs .tmp subdomains

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBPASSIVE == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Passive Subdomain Enumeration"

        # Run subfinder and check for errors
        run_command subfinder -all -d "$domain" -max-time "$SUBFINDER_ENUM_TIMEOUT" -silent -o .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null
        run_command curl -s https://ip.thc.org/sb/$domain | grep -v ";;" | anew -q .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null

        # Run github-subdomains if GITHUB_TOKENS is set and file is not empty
        if [[ -s $GITHUB_TOKENS ]]; then
            if [[ $DEEP == true ]]; then
                run_command github-subdomains -d "$domain" -t "$GITHUB_TOKENS" -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
            else
                run_command github-subdomains -d "$domain" -k -q -t "$GITHUB_TOKENS" -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Run gitlab-subdomains if GITLAB_TOKENS is set and file is not empty
        if [[ -s $GITLAB_TOKENS ]]; then
            run_command gitlab-subdomains -d "$domain" -t "$GITLAB_TOKENS" 2>>"$LOGFILE" | tee .tmp/gitlab_subdomains_psub.txt >/dev/null
        fi

        # Check if INSCOPE is true and run check_inscope
        if [[ $INSCOPE == true ]]; then
            check_inscope .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null
            check_inscope .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
            check_inscope .tmp/gitlab_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
        fi

        # Combine results and count new lines
        if ! NUMOFLINES=$(find .tmp -type f -iname "*_psub.txt" -exec cat {} + | sed "s/^\*\.//" | anew .tmp/passive_subs.txt | sed '/^$/d' | wc -l); then
            NUMOFLINES=0
        fi
        end_subfunc "${NUMOFLINES} new subs (passive)" "${FUNCNAME[0]}"

    else
        if [[ $SUBPASSIVE == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or configuration settings."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function sub_crt() {

    ensure_dirs .tmp subdomains

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBCRT == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Crtsh Subdomain Enumeration"

        : >.tmp/crtsh_subdomains.txt
        : >.tmp/crtsh_subs_tmp.txt

        if [[ "${DRY_RUN:-false}" == "true" ]]; then
            run_command crt -s -json -l "${CTR_LIMIT}" "$domain" >/dev/null
            run_command curl -s "https://bgp.he.net/certs/api/list?domain=$domain" >/dev/null
            end_subfunc "0 new subs (cert transparency)" "${FUNCNAME[0]}" "SKIP"
            return
        fi

        # Run crt command and check for errors
        # Apply time fencing if DNS_TIME_FENCE_DAYS is set and > 0
        if [[ ${DNS_TIME_FENCE_DAYS:-0} -gt 0 ]]; then
            local cutoff_date
            cutoff_date=$(date -v-"${DNS_TIME_FENCE_DAYS}"d +%Y-%m-%d 2>/dev/null || date -d "-${DNS_TIME_FENCE_DAYS} days" +%Y-%m-%d 2>/dev/null)
            if [[ -n "$cutoff_date" ]]; then
                if ! run_command crt -s -json -l "${CTR_LIMIT}" "$domain" 2>>"$LOGFILE" \
                    | jq -r --arg cutoff "$cutoff_date" '[.[] | select(.not_before >= $cutoff)] | .[].subdomain' 2>>"$LOGFILE" \
                    | sed -e 's/^\*\.//' >.tmp/crtsh_subdomains.txt; then
                    log_note "sub_crt: crt source returned no valid JSON; continuing with fallback sources" "${FUNCNAME[0]}" "${LINENO}"
                fi
                [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
                    printf "%b[*] Time fencing enabled: filtering crt.sh results to last %d days (since %s)%b\n" \
                        "$bblue" "${DNS_TIME_FENCE_DAYS}" "$cutoff_date" "$reset"
            else
                # Fallback if date calculation fails
                if ! run_command crt -s -json -l "${CTR_LIMIT}" "$domain" 2>>"$LOGFILE" \
                    | jq -r '.[].subdomain' 2>>"$LOGFILE" \
                    | sed -e 's/^\*\.//' >.tmp/crtsh_subdomains.txt; then
                    log_note "sub_crt: crt source returned no valid JSON; continuing with fallback sources" "${FUNCNAME[0]}" "${LINENO}"
                fi
            fi
        else
            if ! run_command crt -s -json -l "${CTR_LIMIT}" "$domain" 2>>"$LOGFILE" \
                | jq -r '.[].subdomain' 2>>"$LOGFILE" \
                | sed -e 's/^\*\.//' >.tmp/crtsh_subdomains.txt; then
                log_note "sub_crt: crt source returned no valid JSON; continuing with fallback sources" "${FUNCNAME[0]}" "${LINENO}"
            fi
        fi

        run_command curl -s "https://bgp.he.net/certs/api/list?domain=$domain" \
            | jq -r 'try .domains[]?.domain // empty' 2>>"$LOGFILE" \
            | sed -e 's/^\*\.//' \
            | anew -q .tmp/crtsh_subdomains.txt || true

        # Use anew to get new subdomains
        if [[ -s ".tmp/crtsh_subdomains.txt" ]]; then
            anew -q .tmp/crtsh_subs_tmp.txt <.tmp/crtsh_subdomains.txt || true
        fi
        # If INSCOPE is true, check inscope
        if [[ $INSCOPE == true ]]; then
            if ! check_inscope .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" >/dev/null; then
                print_warnf "check_inscope command failed."
                return 1
            fi
        fi

        # Process subdomains and append new ones to .tmp/crtsh_subs.txt, count new lines
        if ! NUMOFLINES=$(sed 's/^\*\.//' .tmp/crtsh_subs_tmp.txt | sed '/^$/d' | anew .tmp/crtsh_subs.txt | wc -l); then
            NUMOFLINES=0
        fi

        end_subfunc "${NUMOFLINES} new subs (cert transparency)" "${FUNCNAME[0]}"
    else
        if [[ $SUBCRT == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi
}

function sub_active() {

    ensure_dirs .tmp subdomains

    if [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Active Subdomain Enumeration"

        # Combine subdomain files into subs_no_resolved.txt
        if ! find .tmp -type f -iname "*_subs.txt" -exec cat {} + | anew -q .tmp/subs_no_resolved.txt; then
            print_warnf "Failed to collect subdomains into subs_no_resolved.txt."
            return 1
        fi

        # Delete out-of-scope domains if outOfScope_file exists
        if [[ -s $outOfScope_file ]]; then
            if ! deleteOutScoped "$outOfScope_file" .tmp/subs_no_resolved.txt; then
                print_warnf "deleteOutScoped command failed."
                return 1
            fi
        fi

        if [[ $AXIOM != true ]]; then
            # Update resolvers locally
            [[ $RESOLVER_IQ == true ]] && resolvers_optimize_local

            # Resolve subdomains using puredns
            if [[ -s ".tmp/subs_no_resolved.txt" ]]; then
                _resolve_domains .tmp/subs_no_resolved.txt .tmp/subdomains_tmp.txt
            fi
        else
            # Update resolvers using axiom

            # Resolve subdomains using axiom-scan
            if [[ -s ".tmp/subs_no_resolved.txt" ]]; then
                run_command axiom-scan .tmp/subs_no_resolved.txt -m puredns-resolve \
                    -r ${AXIOM_RESOLVERS_PATH} \
                    --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" \
                    --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/subdomains_tmp.txt $AXIOM_EXTRA_ARGS \
                    2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Add the domain itself to the list if it resolves
        echo "$domain" | dnsx -retry 3 -silent -r "$resolvers_trusted" \
            2>>"$LOGFILE" | anew -q .tmp/subdomains_tmp.txt

        # If INSCOPE is true, check inscope
        if [[ $INSCOPE == true ]] && [[ -s ".tmp/subdomains_tmp.txt" ]]; then
            if ! check_inscope .tmp/subdomains_tmp.txt 2>>"$LOGFILE" >/dev/null; then
                print_warnf "check_inscope command failed."
            fi
        fi

        # Process subdomains and append new ones to subdomains.txt, count new lines
        if [[ -s ".tmp/subdomains_tmp.txt" ]]; then
            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/subdomains_tmp.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
                print_warnf "Failed to process subdomains."
                NUMOFLINES=0
            fi
        else
            NUMOFLINES=0
            _print_msg WARN "No candidate subdomains produced by sub_active; continuing."
        fi

        end_subfunc "${NUMOFLINES} subs DNS resolved from passive" "${FUNCNAME[0]}"
    else
        _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
    fi
}

function sub_tls() {
    ensure_dirs .tmp subdomains

    if [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: TLS Active Subdomain Enumeration"

        if [[ ! -s "subdomains/subdomains.txt" ]]; then
            _print_msg WARN "No subdomains available for TLS enumeration; skipping."
            end_subfunc "0 new subs (tls active enum)" "${FUNCNAME[0]}" "SKIP"
            return
        fi

        # Always reset temp outputs to avoid stale data from previous runs.
        : >".tmp/subdomains_tlsx_clean.txt"
        : >".tmp/subdomains_tlsx_resolved.txt"

        if [[ $DEEP == true ]]; then
            if [[ $AXIOM != true ]]; then
                cat subdomains/subdomains.txt | tlsx -san -cn -silent -ro -c "$TLSX_THREADS" \
                    -p "$TLS_PORTS" -o .tmp/subdomains_tlsx.txt 2>>"$LOGFILE" >/dev/null
            else
                run_command axiom-scan subdomains/subdomains.txt -m tlsx \
                    -san -cn -silent -ro -c "$TLSX_THREADS" -p "$TLS_PORTS" \
                    -o .tmp/subdomains_tlsx.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
            fi
        else
            if [[ $AXIOM != true ]]; then
                cat subdomains/subdomains.txt | tlsx -san -cn -silent -ro -c "$TLSX_THREADS" >.tmp/subdomains_tlsx.txt 2>>"$LOGFILE"
            else
                run_command axiom-scan subdomains/subdomains.txt -m tlsx \
                    -san -cn -silent -ro -c "$TLSX_THREADS" \
                    -o .tmp/subdomains_tlsx.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
            fi
        fi

        if [[ -s ".tmp/subdomains_tlsx.txt" ]]; then
            grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/subdomains_tlsx.txt \
                | grep -aEo 'https?://[^ ]+' \
                | sed "s/|__ //" \
                | sed '/^$/d' \
                | anew -q .tmp/subdomains_tlsx_clean.txt || true
        fi

        if [[ $AXIOM != true ]]; then
            [[ $RESOLVER_IQ == true ]] && resolvers_optimize_local
            if [[ -s ".tmp/subdomains_tlsx_clean.txt" ]]; then
                _resolve_domains .tmp/subdomains_tlsx_clean.txt .tmp/subdomains_tlsx_resolved.txt
            fi
        else
            if [[ -s ".tmp/subdomains_tlsx_clean.txt" ]]; then
                run_command axiom-scan .tmp/subdomains_tlsx_clean.txt -m puredns-resolve \
                    -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/subdomains_tlsx_resolved.txt $AXIOM_EXTRA_ARGS \
                    2>>"$LOGFILE" >/dev/null
            fi
        fi

        if [[ $INSCOPE == true ]]; then
            if ! check_inscope .tmp/subdomains_tlsx_resolved.txt 2>>"$LOGFILE" >/dev/null; then
                print_warnf "check_inscope command failed."
                return 1
            fi
        fi

        touch .tmp/subdomains_tlsx_resolved.txt

        if ! NUMOFLINES=$(anew subdomains/subdomains.txt <.tmp/subdomains_tlsx_resolved.txt | sed '/^$/d' | wc -l); then
            print_warnf "Counting new subdomains failed."
            return 1
        fi

        end_subfunc "${NUMOFLINES} new subs (tls active enum)" "${FUNCNAME[0]}"
    else
        _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
    fi
}

function sub_noerror() {

    ensure_dirs .tmp subdomains

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBNOERROR == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Checking NOERROR DNS response"

        # Check for DNSSEC black lies
        random_subdomain="${RANDOM}thistotallynotexist${RANDOM}.$domain"
        dns_response=$(echo "$random_subdomain" | dnsx -r "$resolvers" -rcode noerror,nxdomain -retry 3 -silent 2>>"$LOGFILE" | cut -d' ' -f2)

        if [[ $dns_response == "[NXDOMAIN]" ]]; then

            # Determine wordlist based on DEEP setting
            if [[ $DEEP == true ]]; then
                wordlist="$subs_wordlist_big"
            else
                wordlist="$subs_wordlist"
            fi

            # Run dnsx and check for errors
            run_command dnsx -d "$domain" -r "$resolvers" -silent \
                -rcode noerror -w "$wordlist" \
                2>>"$LOGFILE" | cut -d' ' -f1 | anew -q .tmp/subs_noerror.txt >/dev/null

            # Check inscope if INSCOPE is true
            if [[ $INSCOPE == true ]]; then
                if ! check_inscope .tmp/subs_noerror.txt 2>>"$LOGFILE" >/dev/null; then
                    print_warnf "check_inscope command failed."
                    return 1
                fi
            fi

            # Process subdomains and append new ones to subdomains.txt, count new lines
            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/subs_noerror.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                | sed 's/^\*\.//' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
                print_warnf "Failed to process subdomains."
                return 1
            fi

            end_subfunc "${NUMOFLINES} new subs (DNS noerror)" "${FUNCNAME[0]}"

        else
            _print_msg WARN "Detected DNSSEC black lies, skipping this technique."
        fi

    else
        if [[ $SUBNOERROR == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function sub_dns() {
    ensure_dirs .tmp subdomains hosts

    if [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: DNS Subdomain Enumeration and PTR search"

        if [[ -s "subdomains/subdomains.txt" ]]; then
            run_command dnsx -r "$resolvers_trusted" -recon -silent -retry 3 -json \
                -o "subdomains/subdomains_dnsregs.json" <"subdomains/subdomains.txt" 2>>"$LOGFILE" >/dev/null
        fi
        if [[ -s "subdomains/subdomains_dnsregs.json" ]]; then
            # Extract various DNS records and process them
            jq -r --arg domain "$domain" '.. | strings | select(test("\\." + $domain + "$"))' <"subdomains/subdomains_dnsregs.json" \
                | grep -E '^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$' \
                | sort -u | anew -q .tmp/subdomains_dns.txt || true

            jq -r '.. | strings | select(test("^(\\d{1,3}\\.){3}\\d{1,3}$|^[0-9a-fA-F:]+$"))' <"subdomains/subdomains_dnsregs.json" \
                | sort -u | run_command hakip2host | awk '{print $3}' | unfurl -u domains \
                | sed -e 's/^\*\.//' -e 's/\.$//' -e '/\./!d' | grep "\.${DOMAIN_ESCAPED}$" \
                | grep -E '^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$' | sort -u \
                | anew -q .tmp/subdomains_dns.txt || true

            jq -r '.. | strings | select(test("^(\\d{1,3}\\.){3}\\d{1,3}$|^[0-9a-fA-F:]+$"))' <"subdomains/subdomains_dnsregs.json" \
                | sort -u \
                | while IFS= read -r ip; do
                    [[ -z "$ip" ]] && continue
                    run_command curl -s "https://ip.thc.org/$ip" 2>>"$LOGFILE" \
                        | grep "\.${DOMAIN_ESCAPED}$" \
                        | grep -E '^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$' \
                        | sort -u \
                        | anew -q .tmp/subdomains_dns.txt || true
                done

            jq -r 'select(.host) |"\(.host) - \((.a // [])[])", "\(.host) - \((.aaaa // [])[])"' <"subdomains/subdomains_dnsregs.json" \
                | grep -E ' - [0-9a-fA-F:.]+$' | sort -u | anew -q "subdomains/subdomains_ips.txt" || true
        fi
        if [[ $AXIOM != true ]]; then

            if [[ -s ".tmp/subdomains_dns.txt" ]]; then
                _resolve_domains .tmp/subdomains_dns.txt .tmp/subdomains_dns_resolved.txt
            fi
        else

            if [[ -s ".tmp/subdomains_dns.txt" ]]; then
                run_command axiom-scan .tmp/subdomains_dns.txt -m puredns-resolve \
                    -r "${AXIOM_RESOLVERS_PATH}" --resolvers-trusted "${AXIOM_RESOLVERS_TRUSTED_PATH}" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/subdomains_dns_resolved.txt "$AXIOM_EXTRA_ARGS" \
                    2>>"$LOGFILE" >/dev/null
            fi
        fi

        if [[ -s "subdomains/subdomains_ips.txt" ]]; then
            cut -d ' ' -f3 subdomains/subdomains_ips.txt \
                | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." \
                | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u | anew -q hosts/ips.txt
        else
            _print_msg WARN "No DNS IP pairs found in sub_dns; skipping hosts/ips enrichment."
            log_note "No DNS IP pairs found in sub_dns; skipping hosts/ips enrichment." "${FUNCNAME[0]}" "${LINENO}"
        fi

        if [[ $INSCOPE == true ]]; then
            if ! check_inscope .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" >/dev/null; then
                print_warnf "check_inscope command failed."
            fi
        fi

        if [[ -s ".tmp/subdomains_dns_resolved.txt" ]]; then
            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}$' \
                | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
                print_warnf "Failed to count new subdomains."
                return 1
            fi
        else
            NUMOFLINES=0
            _print_msg WARN "No DNS-resolved subdomains produced by sub_dns; continuing."
            log_note "No DNS-resolved subdomains produced by sub_dns; continuing." "${FUNCNAME[0]}" "${LINENO}"
        fi

        end_subfunc "${NUMOFLINES} new subs (dns resolution)" "${FUNCNAME[0]}"
    else
        _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
    fi
}

function sub_brute() {

    ensure_dirs .tmp subdomains

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBBRUTE == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Bruteforce Subdomain Enumeration"

        if [[ $AXIOM != true ]]; then

            wordlist="$subs_wordlist"
            [[ $DEEP == true ]] && wordlist="$subs_wordlist_big"

            _bruteforce_domains "$wordlist" "$domain" .tmp/subs_brute.txt

            # Resolve the subdomains
            if [[ -s ".tmp/subs_brute.txt" ]]; then
                _resolve_domains .tmp/subs_brute.txt .tmp/subs_brute_valid.txt
            fi

        else

            wordlist="$subs_wordlist"
            [[ $DEEP == true ]] && wordlist="$subs_wordlist_big"

            # Run axiom-scan with puredns-single
            run_command axiom-scan "$wordlist" -m puredns-single "$domain" -r ${AXIOM_RESOLVERS_PATH} \
                --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                -o .tmp/subs_brute.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null

            # Resolve the subdomains using axiom-scan
            if [[ -s ".tmp/subs_brute.txt" ]]; then
                run_command axiom-scan .tmp/subs_brute.txt -m puredns-resolve -r "${AXIOM_RESOLVERS_PATH}" \
                    --resolvers-trusted "${AXIOM_RESOLVERS_TRUSTED_PATH}" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/subs_brute_valid.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Check inscope if INSCOPE is true
        if [[ $INSCOPE == true ]] && [[ -s ".tmp/subs_brute_valid.txt" ]]; then
            if ! check_inscope .tmp/subs_brute_valid.txt 2>>"$LOGFILE" >/dev/null; then
                print_warnf "check_inscope command failed."
            fi
        fi

        # Process subdomains and append new ones to subdomains.txt, count new lines
        if [[ -s ".tmp/subs_brute_valid.txt" ]]; then
            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/subs_brute_valid.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                | sed 's/^\*\.//' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
                print_warnf "Failed to process subdomains."
                NUMOFLINES=0
            fi
        else
            NUMOFLINES=0
            _print_msg WARN "No candidate subdomains produced by sub_brute; continuing."
        fi

        end_subfunc "${NUMOFLINES} new subs (bruteforce)" "${FUNCNAME[0]}"

    else
        if [[ $SUBBRUTE == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function sub_scraping() {

    # Create necessary directories
    if ! ensure_dirs .tmp subdomains; then
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBSCRAPING == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Source code scraping subdomain search"

        # Initialize scrap_subs.txt
        if ! touch .tmp/scrap_subs.txt; then
            print_warnf "Failed to create .tmp/scrap_subs.txt."
            return 1
        fi

        # If in multi mode and subdomains.txt doesn't exist, create it
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            if ! printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"; then
                print_warnf "Failed to create subdomains.txt."
                return 1
            fi
        fi

        # Check if subdomains.txt exists and is not empty
        if [[ -s "$dir/subdomains/subdomains.txt" ]]; then

            subdomains_count=$(wc -l <"$dir/subdomains/subdomains.txt")
            if [[ $subdomains_count -le $DEEP_LIMIT ]] || [[ $DEEP == true ]]; then

                urlfinder -d $domain -all -o .tmp/url_extract_tmp.txt 2>>"$LOGFILE" >/dev/null

                if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
                    cat .tmp/url_extract_tmp.txt | grep -a "$domain" \
                        | grep -aEo 'https?://[^ ]+' \
                        | sed "s/^\*\.//" | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt || true
                fi

                if command -v waymore &>/dev/null; then
                    if ! "$TIMEOUT_CMD" "${WAYMORE_TIMEOUT:-30m}" waymore -i "$domain" -mode U -oU .tmp/waymore_urls_subs.txt 2>>"$LOGFILE" >/dev/null; then
                        log_note "sub_scraping: waymore failed or timed out; continuing" "${FUNCNAME[0]}" "${LINENO}"
                    fi
                    if [[ -s ".tmp/waymore_urls_subs.txt" ]]; then
                        cat .tmp/waymore_urls_subs.txt | grep -a "$domain" \
                            | grep -aEo 'https?://[^ ]+' \
                            | sed "s/^\*\.//" | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt || true
                    fi
                else
                    log_note "sub_scraping: waymore not found; skipping waymore passive collection" "${FUNCNAME[0]}" "${LINENO}"
                fi

                if [[ $AXIOM != true ]]; then

                    # Run httpx to gather web info
                    run_command httpx -follow-host-redirects -status-code -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" \
                        -timeout "$HTTPX_TIMEOUT" -silent -retries 2 -title -web-server -tech-detect -location \
                        -no-color -json -o .tmp/web_full_info1.txt \
                        <subdomains/subdomains.txt 2>>"$LOGFILE" >/dev/null

                    if [[ -s ".tmp/web_full_info1.txt" ]]; then
                        cat .tmp/web_full_info1.txt | jq -r 'try .url' 2>/dev/null \
                            | grep -a "$domain" \
                            | grep -aEo 'https?://[^ ]+' \
                            | sed "s/^\*\.//" \
                            | anew .tmp/probed_tmp_scrap.txt \
                            | unfurl -u domains 2>>"$LOGFILE" \
                            | anew -q .tmp/scrap_subs.txt || true
                    fi

                    if [[ -s ".tmp/probed_tmp_scrap.txt" ]]; then
                        cat .tmp/probed_tmp_scrap.txt | run_command csprecon -s | grep -a "$domain" | sed "s/^\*\.//" | sort -u \
                            | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt || true
                    fi

                else
                    # AXIOM mode

                    run_command axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -random-agent -status-code \
                        -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" -silent -retries 2 \
                        -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info1.txt \
                        $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null

                    if [[ -s ".tmp/web_full_info1.txt" ]]; then
                        cat .tmp/web_full_info1.txt | jq -r 'try .url' 2>/dev/null \
                            | grep -a "$domain" \
                            | grep -aEo 'https?://[^ ]+' \
                            | sed "s/^\*\.//" \
                            | anew .tmp/probed_tmp_scrap.txt \
                            | unfurl -u domains 2>>"$LOGFILE" \
                            | anew -q .tmp/scrap_subs.txt || true
                    fi

                    if [[ -s ".tmp/probed_tmp_scrap.txt" ]]; then
                        cat .tmp/probed_tmp_scrap.txt | run_command csprecon -s | grep -a "$domain" | sed "s/^\*\.//" | sort -u \
                            | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt || true
                    fi

                fi

                if [[ -s ".tmp/scrap_subs.txt" ]]; then
                    _resolve_domains .tmp/scrap_subs.txt .tmp/scrap_subs_resolved.txt
                fi

                if [[ $INSCOPE == true ]] && [[ -s ".tmp/scrap_subs_resolved.txt" ]]; then
                    if ! check_inscope .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" >/dev/null; then
                        print_warnf "check_inscope command failed."
                    fi
                fi

                if [[ -s ".tmp/scrap_subs_resolved.txt" ]]; then
                    if ! NUMOFLINES=$(cat .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" \
                        | grep -a "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" \
                        | grep -Ea '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                        | anew subdomains/subdomains.txt \
                        | tee .tmp/diff_scrap.txt \
                        | sed '/^$/d' | wc -l); then
                        NUMOFLINES=0
                    fi
                else
                    NUMOFLINES=0
                fi

                if [[ -s ".tmp/diff_scrap.txt" ]]; then
                    run_command httpx -follow-host-redirects -random-agent -status-code -threads "$HTTPX_THREADS" \
                        -rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" -silent -retries 2 -title -web-server \
                        -tech-detect -location -no-color -json -o .tmp/web_full_info3.txt \
                        <.tmp/diff_scrap.txt 2>>"$LOGFILE" >/dev/null

                    if [[ -s ".tmp/web_full_info3.txt" ]]; then
                        cat .tmp/web_full_info3.txt | jq -r 'try .url' 2>/dev/null \
                            | grep -a "$domain" \
                            | grep -aEo 'https?://[^ ]+' \
                            | sed "s/^\*\.//" \
                            | anew .tmp/probed_tmp_scrap.txt \
                            | unfurl -u domains 2>>"$LOGFILE" \
                            | anew -q .tmp/scrap_subs.txt || true
                    fi
                fi

                local webinfo_files=()
                [[ -s ".tmp/web_full_info1.txt" ]] && webinfo_files+=(".tmp/web_full_info1.txt")
                [[ -s ".tmp/web_full_info2.txt" ]] && webinfo_files+=(".tmp/web_full_info2.txt")
                [[ -s ".tmp/web_full_info3.txt" ]] && webinfo_files+=(".tmp/web_full_info3.txt")

                if [[ ${#webinfo_files[@]} -gt 0 ]]; then
                    # Keep .tmp/web_full_info.txt as JSONL (1 JSON object per line) for later merges.
                    : >.tmp/web_full_info.txt
                    if ! cat "${webinfo_files[@]}" 2>>"$LOGFILE" \
                        | jq -cs 'unique_by(.input)[]' 2>>"$LOGFILE" >.tmp/web_full_info.txt; then
                        : >.tmp/web_full_info.txt
                        log_note "sub_scraping: failed to merge web_full_info JSON; continuing without cache" "${FUNCNAME[0]}" "${LINENO}"
                    fi
                else
                    log_note "sub_scraping: web_full_info files missing/empty; skipping merge" "${FUNCNAME[0]}" "${LINENO}"
                fi

                end_subfunc "${NUMOFLINES} new subs (code scraping)" "${FUNCNAME[0]}"

            else
                end_subfunc "Skipping Subdomains Web Scraping: Too Many Subdomains" "${FUNCNAME[0]}"
            fi
        fi

    else
        if [[ $SUBSCRAPING == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function sub_analytics() {

    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        print_warnf "Failed to create directories."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBANALYTICS == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Analytics Subdomain Enumeration"

        if [[ -s ".tmp/probed_tmp_scrap.txt" ]]; then
            # Run analyticsrelationships with timeout; tool may panic on builtwith errors
            if [[ -n ${TIMEOUT_CMD:-} ]]; then
                if ! "$TIMEOUT_CMD" 2m analyticsrelationships -ch <.tmp/probed_tmp_scrap.txt >>.tmp/analytics_subs_tmp.txt 2>>"$LOGFILE"; then
                    log_note "analyticsrelationships failed (builtwith error or panic); skipping" "${FUNCNAME[0]}" "${LINENO}"
                fi
            else
                if ! analyticsrelationships -ch <.tmp/probed_tmp_scrap.txt >>.tmp/analytics_subs_tmp.txt 2>>"$LOGFILE"; then
                    log_note "analyticsrelationships failed (builtwith error or panic); skipping" "${FUNCNAME[0]}" "${LINENO}"
                fi
            fi

            if [[ -s ".tmp/analytics_subs_tmp.txt" ]]; then
                grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/analytics_subs_tmp.txt \
                    | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                    | sed "s/|__ //" | anew -q .tmp/analytics_subs_clean.txt || true

                if [[ $AXIOM != true ]]; then

                    if [[ -s ".tmp/analytics_subs_clean.txt" ]]; then
                        _resolve_domains .tmp/analytics_subs_clean.txt .tmp/analytics_subs_resolved.txt
                    fi
                else

                    if [[ -s ".tmp/analytics_subs_clean.txt" ]]; then
                        run_command axiom-scan .tmp/analytics_subs_clean.txt -m puredns-resolve \
                            -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                            --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                            -o .tmp/analytics_subs_resolved.txt $AXIOM_EXTRA_ARGS \
                            2>>"$LOGFILE" >/dev/null
                    fi
                fi
            fi
        fi

        if [[ $INSCOPE == true ]]; then
            if ! check_inscope .tmp/analytics_subs_resolved.txt 2>>"$LOGFILE" >/dev/null; then
                print_warnf "check_inscope command failed."
            fi
        fi

        if ! NUMOFLINES=$(cat .tmp/analytics_subs_resolved.txt 2>/dev/null | anew subdomains/subdomains.txt 2>/dev/null | sed '/^$/d' | wc -l); then
            NUMOFLINES=0
        fi

        end_subfunc "${NUMOFLINES} new subs (analytics relationship)" "${FUNCNAME[0]}"

    else
        if [[ $SUBANALYTICS == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi
}

_select_permutations_wordlist() {
    local source_file="$1"
    local full_list="${WORDLISTS_DIR}/permutations_list.txt"
    local short_list="${WORDLISTS_DIR}/permutations_list_short.txt"
    local mode="${PERMUTATIONS_WORDLIST_MODE:-auto}"
    local threshold="${PERMUTATIONS_SHORT_THRESHOLD:-100}"

    case "$mode" in
        full)  printf '%s\n' "$full_list" ;;
        short) printf '%s\n' "$short_list" ;;
        auto)
            if [[ "${DEEP:-false}" == true ]]; then
                printf '%s\n' "$full_list"
                return
            fi
            local count=0
            [[ -s "$source_file" ]] && count=$(wc -l < "$source_file" | tr -d ' ')
            if (( count <= threshold )); then
                printf '%s\n' "$full_list"
            else
                printf '%s\n' "$short_list"
            fi
            ;;
        *) printf '%s\n' "$full_list" ;;
    esac
}

_run_permutation_engine() {
    local source_file="$1"
    local wordlist
    wordlist=$(_select_permutations_wordlist "$source_file")
    run_command gotator -sub "$source_file" -perm "$wordlist" $GOTATOR_FLAGS -silent 2>>"$LOGFILE"
}

_generate_permutation_candidates() {
    local source_file="$1"
    local output_file="$2"
    : >"$output_file"
    [[ -s "$source_file" ]] || return 0
    _run_permutation_engine "$source_file" | sed '/^\s*$/d' | head -c "$PERMUTATIONS_LIMIT" >"$output_file"
}

function sub_permut() {

    ensure_dirs .tmp subdomains

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBPERMUTE == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Permutations Subdomain Enumeration"

        # If in multi mode and subdomains.txt doesn't exist, create it with the domain
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            echo "$domain" >"$dir/subdomains/subdomains.txt"
        fi

        # Determine the number of subdomains safely (avoid noisy stderr on dry-run)
        local subdomain_count subs_no_resolved_count
        subdomain_count=0
        subs_no_resolved_count=0
        [[ -s "subdomains/subdomains.txt" ]] && subdomain_count=$(wc -l <subdomains/subdomains.txt 2>/dev/null || echo 0)
        [[ -s ".tmp/subs_no_resolved.txt" ]] && subs_no_resolved_count=$(wc -l <.tmp/subs_no_resolved.txt 2>/dev/null || echo 0)

        if [[ "$subdomain_count" -eq 0 && "$subs_no_resolved_count" -eq 0 ]]; then
            _print_msg WARN "No candidate subdomains available for permutations; skipping."
            end_subfunc "0 new subs (permutations)" "${FUNCNAME[0]}" "SKIP"
            return 0
        fi

        # Check if DEEP mode is enabled or subdomains are within DEEP_LIMIT
        if [[ $DEEP == true ]] || [[ $subdomain_count -le $DEEP_LIMIT ]]; then

            _generate_permutation_candidates "subdomains/subdomains.txt" ".tmp/gotator1.txt"

        elif [[ "$subs_no_resolved_count" -le $DEEP_LIMIT2 ]]; then

            _generate_permutation_candidates ".tmp/subs_no_resolved.txt" ".tmp/gotator1.txt"

        else
            end_subfunc "Skipping Permutations: Too Many Subdomains" "${FUNCNAME[0]}"
            return 0
        fi

        # Resolve the permutations
        if [[ $AXIOM != true ]]; then
            if [[ -s ".tmp/gotator1.txt" ]]; then
                _resolve_domains .tmp/gotator1.txt .tmp/permute1.txt
            fi
        else
            if [[ -s ".tmp/gotator1.txt" ]]; then
                run_command axiom-scan .tmp/gotator1.txt -m puredns-resolve -r "${AXIOM_RESOLVERS_PATH}" \
                    --resolvers-trusted "${AXIOM_RESOLVERS_TRUSTED_PATH}" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/permute1.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Generate second round of permutations
        _generate_permutation_candidates ".tmp/permute1.txt" ".tmp/gotator2.txt"

        # Resolve the second round of permutations
        if [[ $AXIOM != true ]]; then
            if [[ -s ".tmp/gotator2.txt" ]]; then
                _resolve_domains .tmp/gotator2.txt .tmp/permute2.txt
            fi
        else
            if [[ -s ".tmp/gotator2.txt" ]]; then
                run_command axiom-scan .tmp/gotator2.txt -m puredns-resolve -r "${AXIOM_RESOLVERS_PATH}" \
                    --resolvers-trusted "${AXIOM_RESOLVERS_TRUSTED_PATH}" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/permute2.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Combine results
        if [[ -s ".tmp/permute1.txt" ]] || [[ -s ".tmp/permute2.txt" ]]; then
            cat .tmp/permute1.txt .tmp/permute2.txt 2>>"$LOGFILE" | anew -q .tmp/permute_subs.txt

            # Remove out-of-scope domains if applicable
            if [[ -s $outOfScope_file ]]; then
                if ! deleteOutScoped "$outOfScope_file" .tmp/permute_subs.txt; then
                    print_warnf "deleteOutScoped command failed."
                fi
            fi

            # Check inscope if INSCOPE is true
            if [[ $INSCOPE == true ]]; then
                if ! check_inscope .tmp/permute_subs.txt 2>>"$LOGFILE" >/dev/null; then
                    print_warnf "check_inscope command failed."
                fi
            fi

            # Process subdomains and append new ones to subdomains.txt, count new lines
            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/permute_subs.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
                print_warnf "Failed to process subdomains."
                return 1
            fi
        else
            NUMOFLINES=0
        fi

        end_subfunc "${NUMOFLINES} new subs (permutations)" "${FUNCNAME[0]}"

    else
        if [[ $SUBPERMUTE == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function sub_regex_permut() {

    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        print_warnf "Failed to create directories."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBREGEXPERMUTE == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Permutations by regex analysis"

        # Change to the regulator directory
        if ! pushd "${tools}/regulator" >/dev/null; then
            print_warnf "Failed to change directory to %s." "${tools}/regulator"
            return 1
        fi

        # If in multi mode and subdomains.txt doesn't exist, create it
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
        fi

        # Run the main.py script
        run_command "${tools}/regulator/venv/bin/python3" main.py -t "$domain" -f "${dir}/subdomains/subdomains.txt" -o "${dir}/.tmp/${domain}.brute" \
            2>>"$LOGFILE" >/dev/null

        # Return to the previous directory
        if ! popd >/dev/null; then
            print_warnf "Failed to return to previous directory."
            return 1
        fi

        # Resolve the generated domains
        if [[ $AXIOM != true ]]; then

            if [[ -s ".tmp/${domain}.brute" ]]; then
                _resolve_domains ".tmp/${domain}.brute" .tmp/regulator.txt
            fi
        else

            if [[ -s ".tmp/${domain}.brute" ]]; then
                run_command axiom-scan ".tmp/${domain}.brute" -m puredns-resolve \
                    -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/regulator.txt $AXIOM_EXTRA_ARGS \
                    2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Process the resolved domains
        if [[ -s ".tmp/regulator.txt" ]]; then
            if [[ -s $outOfScope_file ]]; then
                if ! deleteOutScoped "$outOfScope_file" .tmp/regulator.txt; then
                    print_warnf "deleteOutScoped command failed."
                fi
            fi

            if [[ $INSCOPE == true ]]; then
                if ! check_inscope .tmp/regulator.txt 2>>"$LOGFILE" >/dev/null; then
                    print_warnf "check_inscope command failed."
                fi
            fi

            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/regulator.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                | anew subdomains/subdomains.txt \
                | sed '/^$/d' \
                | wc -l); then
                NUMOFLINES=0
            fi
        else
            NUMOFLINES=0
        fi

        end_subfunc "${NUMOFLINES} new subs (permutations by regex)" "${FUNCNAME[0]}"

    else
        if [[ $SUBREGEXPERMUTE == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function sub_ia_permut() {

    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        print_warnf "Failed to create directories."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBIAPERMUTE == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Permutations by AI analysis"

        subwiz -i subdomains/subdomains.txt --no-resolve -o .tmp/subwiz.txt 2>>"$LOGFILE" >/dev/null

        # Resolve the generated domains
        if [[ $AXIOM != true ]]; then

            if [[ -s ".tmp/subwiz.txt" ]]; then
                _resolve_domains .tmp/subwiz.txt .tmp/subwiz_resolved.txt
            fi
        else

            if [[ -s ".tmp/subwiz.txt" ]]; then
                run_command axiom-scan ".tmp/subwiz.txt" -m puredns-resolve \
                    -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/subwiz_resolved.txt $AXIOM_EXTRA_ARGS \
                    2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Process the resolved domains
        if [[ -s ".tmp/subwiz_resolved.txt" ]]; then
            if [[ -s $outOfScope_file ]]; then
                if ! deleteOutScoped "$outOfScope_file" .tmp/subwiz_resolved.txt; then
                    print_warnf "deleteOutScoped command failed."
                fi
            fi

            if [[ $INSCOPE == true ]]; then
                if ! check_inscope .tmp/subwiz_resolved.txt 2>>"$LOGFILE" >/dev/null; then
                    print_warnf "check_inscope command failed."
                fi
            fi

            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/subwiz_resolved.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                | anew subdomains/subdomains.txt \
                | sed '/^$/d' \
                | wc -l); then
                NUMOFLINES=0
            fi
        else
            NUMOFLINES=0
        fi

        end_subfunc "${NUMOFLINES} new subs (permutations by IA)" "${FUNCNAME[0]}"

    else
        if [[ $SUBIAPERMUTE == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function sub_recursive_passive() {

    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        print_warnf "Failed to create directories."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUB_RECURSIVE_PASSIVE == true ]] && [[ -s "subdomains/subdomains.txt" ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Subdomains recursive search passive"

        # If in multi mode and subdomains.txt doesn't exist, create it with the domain
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
        fi

        # Passive recursive
        if [[ -s "subdomains/subdomains.txt" ]]; then
            dsieve -if subdomains/subdomains.txt -f 3 -top "$DEEP_RECURSIVE_PASSIVE" >.tmp/subdomains_recurs_top.txt
        fi

        if [[ $AXIOM != true ]]; then

            if [[ -s ".tmp/subdomains_recurs_top.txt" ]]; then
                run_command subfinder -all -dL .tmp/subdomains_recurs_top.txt -max-time "${SUBFINDER_ENUM_TIMEOUT}" \
                    -silent -o .tmp/passive_recursive_tmp.txt 2>>"$LOGFILE"
            else
                return 1
            fi

            if [[ -s ".tmp/passive_recursive_tmp.txt" ]]; then
                cat .tmp/passive_recursive_tmp.txt | anew -q .tmp/passive_recursive.txt
            fi

            if [[ -s ".tmp/passive_recursive.txt" ]]; then
                _resolve_domains .tmp/passive_recursive.txt .tmp/passive_recurs_tmp.txt
            fi

        else

            if [[ -s ".tmp/subdomains_recurs_top.txt" ]]; then
                run_command axiom-scan .tmp/subdomains_recurs_top.txt -m subfinder -all -o .tmp/subfinder_prec.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            else
                return 1
            fi

            if [[ -s ".tmp/subfinder_prec.txt" ]]; then
                cat .tmp/subfinder_prec.txt | anew -q .tmp/passive_recursive.txt
            fi

            if [[ -s ".tmp/passive_recursive.txt" ]]; then
                run_command axiom-scan .tmp/passive_recursive.txt -m puredns-resolve \
                    -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/passive_recurs_tmp.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi
        fi

        if [[ $INSCOPE == true ]]; then
            if ! check_inscope .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" >/dev/null; then
                print_warnf "check_inscope command failed."
            fi
        fi

        if [[ -s ".tmp/passive_recurs_tmp.txt" ]]; then
            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                | sed '/^$/d' \
                | anew subdomains/subdomains.txt \
                | wc -l); then
                NUMOFLINES=0
            fi
        else
            NUMOFLINES=0
        fi

        end_subfunc "${NUMOFLINES} new subs (recursive)" "${FUNCNAME[0]}"

    else
        if [[ $SUB_RECURSIVE_PASSIVE == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        elif [[ ! -s "subdomains/subdomains.txt" ]]; then
            _print_msg WARN "No subdomains to process."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function sub_recursive_brute() {
    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        print_warnf "Failed to create directories."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUB_RECURSIVE_BRUTE == true ]] && [[ -s "subdomains/subdomains.txt" ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Subdomains recursive search active"

        # If in multi mode and subdomains.txt doesn't exist, create it with the domain
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            echo "$domain" >"$dir/subdomains/subdomains.txt"
        fi

        # Check the number of subdomains
        subdomain_count=$(wc -l <subdomains/subdomains.txt)
        if [[ $subdomain_count -le $DEEP_LIMIT ]]; then
            # Generate top subdomains if not already done
            if [[ ! -s ".tmp/subdomains_recurs_top.txt" ]]; then
                dsieve -if subdomains/subdomains.txt -f 3 -top "$DEEP_RECURSIVE_PASSIVE" >.tmp/subdomains_recurs_top.txt
            fi

            for subdomain_top in $(cat .tmp/subdomains_recurs_top.txt); do
                if [[ $AXIOM != true ]]; then
                    _bruteforce_domains "$subs_wordlist" "$subdomain_top" .tmp/brute_recursive_result_part.txt
                    cat .tmp/brute_recursive_result_part.txt | anew -q .tmp/brute_recursive.txt
                else
                    run_command axiom-scan "$subs_wordlist" -m puredns-single "$subdomain_top" \
                        -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                        --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                        -o .tmp/brute_recursive_result_part.txt $AXIOM_EXTRA_ARGS \
                        2>>"$LOGFILE" >/dev/null
                    cat .tmp/brute_recursive_result_part.txt | anew -q .tmp/brute_recursive.txt
                fi
            done

            # Generate permutations
            _generate_permutation_candidates ".tmp/brute_recursive.txt" ".tmp/gotator1_recursive.txt"

            # Resolve permutations
            if [[ $AXIOM != true ]]; then
                if [[ -s ".tmp/gotator1_recursive.txt" ]]; then
                    _resolve_domains .tmp/gotator1_recursive.txt .tmp/permute1_recursive.txt
                fi
            else
                if [[ -s ".tmp/gotator1_recursive.txt" ]]; then
                    run_command axiom-scan .tmp/gotator1_recursive.txt -m puredns-resolve \
                        -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                        --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                        -o .tmp/permute1_recursive.txt $AXIOM_EXTRA_ARGS \
                        2>>"$LOGFILE" >/dev/null
                fi
            fi

            # Second round of permutations
            _generate_permutation_candidates ".tmp/permute1_recursive.txt" ".tmp/gotator2_recursive.txt"

            # Resolve second round of permutations
            if [[ $AXIOM != true ]]; then
                if [[ -s ".tmp/gotator2_recursive.txt" ]]; then
                    _resolve_domains .tmp/gotator2_recursive.txt .tmp/permute2_recursive.txt
                fi
            else
                if [[ -s ".tmp/gotator2_recursive.txt" ]]; then
                    run_command axiom-scan .tmp/gotator2_recursive.txt -m puredns-resolve \
                        -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                        --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                        -o .tmp/permute2_recursive.txt $AXIOM_EXTRA_ARGS \
                        2>>"$LOGFILE" >/dev/null
                fi
            fi

            # Combine permutations
            if [[ -s ".tmp/permute1_recursive.txt" ]] || [[ -s ".tmp/permute2_recursive.txt" ]]; then
                cat .tmp/permute1_recursive.txt .tmp/permute2_recursive.txt 2>>"$LOGFILE" | anew -q .tmp/permute_recursive.txt
            fi
        else
            end_subfunc "Skipping recursive search: Too many subdomains" "${FUNCNAME[0]}"
            return 0
        fi

        # Check inscope if applicable
        if [[ $INSCOPE == true ]]; then
            if [[ -s ".tmp/permute_recursive.txt" ]]; then
                if ! check_inscope .tmp/permute_recursive.txt 2>>"$LOGFILE" >/dev/null; then
                    print_warnf "check_inscope command failed on permute_recursive.txt."
                fi
            fi
            if [[ -s ".tmp/brute_recursive.txt" ]]; then
                if ! check_inscope .tmp/brute_recursive.txt 2>>"$LOGFILE" >/dev/null; then
                    print_warnf "check_inscope command failed on brute_recursive.txt."
                fi
            fi
        fi

        # Combine results for final validation
        if [[ -s ".tmp/permute_recursive.txt" ]] || [[ -s ".tmp/brute_recursive.txt" ]]; then
            if ! cat .tmp/permute_recursive.txt .tmp/brute_recursive.txt 2>>"$LOGFILE" | anew -q .tmp/brute_perm_recursive.txt; then
                print_warnf "Failed to combine final results."
                return 1
            fi
        fi

        # Final resolve
        if [[ $AXIOM != true ]]; then
            if [[ -s ".tmp/brute_perm_recursive.txt" ]]; then
                _resolve_domains .tmp/brute_perm_recursive.txt .tmp/brute_perm_recursive_final.txt
            fi
        else
            if [[ -s ".tmp/brute_perm_recursive.txt" ]]; then
                run_command axiom-scan .tmp/brute_perm_recursive.txt -m puredns-resolve \
                    -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/brute_perm_recursive_final.txt $AXIOM_EXTRA_ARGS \
                    2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Process final results
        if [[ -s ".tmp/brute_perm_recursive_final.txt" ]]; then
            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/brute_perm_recursive_final.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                | sed '/^$/d' \
                | anew subdomains/subdomains.txt \
                | wc -l); then
                NUMOFLINES=0
            fi
        else
            NUMOFLINES=0
        fi

        end_subfunc "${NUMOFLINES} new subs (recursive active)" "${FUNCNAME[0]}"

    else
        if [[ $SUB_RECURSIVE_BRUTE == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        elif [[ ! -s "subdomains/subdomains.txt" ]]; then
            _print_msg WARN "No subdomains to process."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi
}

function subtakeover() {

    # Create necessary directories
    if ! mkdir -p .tmp webs subdomains; then
        print_warnf "Failed to create directories."
        return 1
    fi
    touch subdomains/subdomains.txt webs/webs.txt webs/webs_uncommon_ports.txt webs/webs_all.txt 2>/dev/null || true

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBTAKEOVER == true ]]; then
        start_func "${FUNCNAME[0]}" "Looking for possible subdomain and DNS takeover"

        # Initialize takeover file
        if ! touch .tmp/tko.txt; then
            print_warnf "Failed to create .tmp/tko.txt."
            return 1
        fi

        # Build/refresh webs_all.txt from current web targets.
        ensure_webs_all || true

        #cent update -p ${NUCLEI_TEMPLATES_PATH} &>/dev/null
        if [[ $AXIOM != true ]]; then
            maybe_update_nuclei
            cat subdomains/subdomains.txt webs/webs_all.txt 2>/dev/null | run_command nuclei -silent -nh -tags takeover \
                -severity info,low,medium,high,critical -retries 3 -rl "$NUCLEI_RATELIMIT" \
                -t "${NUCLEI_TEMPLATES_PATH}" -j -o .tmp/tko_json.txt 2>>"$LOGFILE" >/dev/null
        else
            cat subdomains/subdomains.txt webs/webs_all.txt 2>>"$LOGFILE" | sed '/^$/d' | anew -q .tmp/webs_subs.txt
            if [[ -s ".tmp/webs_subs.txt" ]]; then
                run_command axiom-scan .tmp/webs_subs.txt -m nuclei --nuclei-templates "${NUCLEI_TEMPLATES_PATH}" \
                    -tags takeover -nh -severity info,low,medium,high,critical -retries 3 -rl "$NUCLEI_RATELIMIT" \
                    -t "${NUCLEI_TEMPLATES_PATH}" -j -o .tmp/tko_json.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Convert JSON to text
        if [[ -s ".tmp/tko_json.txt" ]]; then
            jq -r '["[" + .["template-id"] + (if .["matcher-name"] != null then ":" + .["matcher-name"] else "" end) + "] [" + .["type"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host) + (if .["extracted-results"] != null then " " + (.["extracted-results"] | @json) else "" end)] | .[]' .tmp/tko_json.txt >.tmp/tko.txt
        fi

        # DNS Takeover
        cat .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/scrap_subs.txt \
            .tmp/analytics_subs_clean.txt .tmp/passive_recursive.txt 2>/dev/null \
            | sed '/^$/d' \
            | anew -q .tmp/subs_dns_tko.txt || true

        if [[ -s ".tmp/subs_dns_tko.txt" ]]; then
            cat .tmp/subs_dns_tko.txt 2>/dev/null | dnstake -c "$DNSTAKE_THREADS" -s 2>>"$LOGFILE" \
                | sed '/^$/d' | anew -q .tmp/tko.txt
        fi

        # Remove empty lines from tko.txt
        sed_i '/^$/d' .tmp/tko.txt

        # Count new takeover entries
        if ! NUMOFLINES=$(cat .tmp/tko.txt 2>>"$LOGFILE" | anew webs/takeover.txt | sed '/^$/d' | wc -l); then
            print_warnf "Failed to count takeover entries."
            NUMOFLINES=0
        fi

        if [[ $NUMOFLINES -gt 0 ]]; then
            notification "${NUMOFLINES} new possible takeovers found" info
        fi

        if [[ $FARADAY == true ]]; then
            if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
                print_warnf "Faraday server is not running. Skipping Faraday integration."
            else
                if [[ -s ".tmp/tko_json.txt" ]]; then
                    faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei .tmp/tko_json.txt 2>>"$LOGFILE" >/dev/null
                fi
            fi
        fi

        end_func "Results are saved in $domain/webs/takeover.txt" "${FUNCNAME[0]}"

    else
        if [[ $SUBTAKEOVER == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function zonetransfer() {

    # Create necessary directories
    if ! mkdir -p subdomains; then
        print_warnf "Failed to create subdomains directory."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $ZONETRANSFER == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        start_func "${FUNCNAME[0]}" "Zone transfer check"

        # Initialize output file
        if ! : >"subdomains/zonetransfer.txt"; then
            print_warnf "Failed to create zonetransfer.txt."
            return 1
        fi

        # Perform zone transfer check
        for ns in $(run_command dig +short ns "$domain" 2>/dev/null); do
            run_command dig axfr "${domain}" @"$ns" 2>>"$LOGFILE" | tee -a "subdomains/zonetransfer.txt" >/dev/null
        done

        # Check if zone transfer was successful
        if [[ -s "subdomains/zonetransfer.txt" ]]; then
            if ! grep -q "Transfer failed" "subdomains/zonetransfer.txt"; then
                notification "Zone transfer found on ${domain}!" "info"
            fi
        fi

        end_func "Results are saved in $domain/subdomains/zonetransfer.txt" "${FUNCNAME[0]}"

    else
        if [[ $ZONETRANSFER == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            _print_msg WARN "Domain is an IP address; skipping zone transfer."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}

function s3buckets() {
    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        print_warnf "Failed to create directories."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $S3BUCKETS == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        start_func "${FUNCNAME[0]}" "AWS S3 buckets search"

        # If in multi mode and subdomains.txt doesn't exist, create it
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            if ! printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"; then
                print_warnf "Failed to create subdomains.txt."
                return 1
            fi
        fi

        # Debug: Print current directory and tools variable
        printf "Current directory: %s\n" "$(pwd)" >>"$LOGFILE"
        printf "Tools directory: %s\n" "$tools" >>"$LOGFILE"

        # S3Scanner
        if [[ $AXIOM != true ]]; then
            if [[ -s "subdomains/subdomains.txt" ]]; then
                run_command s3scanner -bucket-file subdomains/subdomains.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt
            fi
        else
            run_command axiom-scan subdomains/subdomains.txt -m s3scanner -o .tmp/s3buckets_tmp.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null

            if [[ -s ".tmp/s3buckets_tmp.txt" ]]; then
                if ! cat .tmp/s3buckets_tmp.txt .tmp/s3buckets_tmp2.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt; then
                    print_warnf "Failed to process s3buckets_tmp.txt."
                fi
                if ! sed_i '/^$/d' .tmp/s3buckets.txt; then
                    print_warnf "Failed to clean s3buckets.txt."
                fi
            fi
        fi

        # Initialize the output file in the subdomains folder
        if ! : >subdomains/cloudhunter_open_buckets.txt; then
            print_warnf "Failed to initialize cloudhunter_open_buckets.txt."
        fi

        # Determine the CloudHunter permutations flag based on the config
        PERMUTATION_FLAG=""
        permutation_file=""
        case "$CLOUDHUNTER_PERMUTATION" in
            DEEP)
                permutation_file="$tools/CloudHunter/permutations-big.txt"
                ;;
            NORMAL)
                permutation_file="$tools/CloudHunter/permutations.txt"
                ;;
            NONE)
                permutation_file=""
                ;;
            *)
                print_warnf "Invalid value for CLOUDHUNTER_PERMUTATION: %s." "$CLOUDHUNTER_PERMUTATION"
                return 1
                ;;
        esac

        if [[ -n "$permutation_file" ]]; then
            if [[ -f "$permutation_file" ]]; then
                PERMUTATION_FLAG="-p"
            else
                _print_msg WARN "CloudHunter permutations file not found (${permutation_file}); continuing without permutations."
                log_note "CloudHunter permutations file not found (${permutation_file}); continuing without permutations." "${FUNCNAME[0]}" "${LINENO}"
                permutation_file=""
                PERMUTATION_FLAG=""
            fi
        fi

        # Debug: Print the full CloudHunter command
        #printf "CloudHunter command: %s/venv/bin/python3 %s/cloudhunter.py %s -r %s/resolvers.txt -t 50 [URL]\n" "$tools/CloudHunter" "$tools/CloudHunter" "$PERMUTATION_FLAG" "$tools/CloudHunter" >>"$LOGFILE"

        # Debug: Check if files exist
        if [[ -f "$tools/CloudHunter/cloudhunter.py" ]]; then
            printf "cloudhunter.py exists\n" >>"$LOGFILE"
        else
            printf "cloudhunter.py not found\n" >>"$LOGFILE"
        fi

        if [[ -n $permutation_file ]]; then
            if [[ -f $permutation_file ]]; then
                printf "Permutations file exists\n" >>"$LOGFILE"
            else
                printf "Permutations file not found: %s\n" "$permutation_file" >>"$LOGFILE"
            fi
        fi

        if [[ -f "$tools/CloudHunter/resolvers.txt" ]]; then
            printf "resolvers.txt exists\n" >>"$LOGFILE"
        else
            printf "resolvers.txt not found\n" >>"$LOGFILE"
        fi

        printf "Processing domain: %s\n" "$domain" >>"$LOGFILE"
        (
            if ! cd "$tools/CloudHunter"; then
                print_warnf "Failed to cd to %s." "$tools/CloudHunter"
                return 1
            fi
            if [[ -n "$permutation_file" ]]; then
                if ! run_command env PYTHONWARNINGS=ignore "${tools}/CloudHunter/venv/bin/python3" -W ignore ./cloudhunter.py "$PERMUTATION_FLAG" "$permutation_file" -r ./resolvers.txt -t 50 "$domain"; then
                    print_warnf "CloudHunter command failed for domain %s." "$domain"
                fi
            elif ! run_command env PYTHONWARNINGS=ignore "${tools}/CloudHunter/venv/bin/python3" -W ignore ./cloudhunter.py -r ./resolvers.txt -t 50 "$domain"; then
                print_warnf "CloudHunter command failed for domain %s." "$domain"
            fi
        ) >>"$dir/subdomains/cloudhunter_open_buckets.txt" 2>>"$LOGFILE"

        # Process CloudHunter results
        if [[ -s "subdomains/cloudhunter_open_buckets.txt" ]]; then
            if ! NUMOFLINES1=$(cat subdomains/cloudhunter_open_buckets.txt 2>>"$LOGFILE" | anew subdomains/cloud_assets.txt | wc -l); then
                print_warnf "Failed to process cloudhunter_open_buckets.txt."
                NUMOFLINES1=0
            fi
            if [[ $NUMOFLINES1 -gt 0 ]]; then
                notification "${NUMOFLINES1} new cloud assets found" "info"
            fi
        else
            NUMOFLINES1=0
        fi

        # Process s3buckets results
        if [[ -s ".tmp/s3buckets.txt" ]]; then
            if ! NUMOFLINES2=$(cat .tmp/s3buckets.txt 2>>"$LOGFILE" | grep -aiv "not_exist" | grep -aiv "Warning:" | grep -aiv "invalid_name" | grep -aiv "^http" | awk 'NF' | anew subdomains/s3buckets.txt | sed '/^$/d' | wc -l); then
                print_warnf "Failed to process s3buckets.txt."
                NUMOFLINES2=0
            fi
            if [[ $NUMOFLINES2 -gt 0 ]]; then
                notification "${NUMOFLINES2} new S3 buckets found" "info"
            fi
        else
            NUMOFLINES2=0
        fi

        # Run trufflehog for S3 buckets
        if [[ -s "subdomains/s3buckets.txt" ]]; then
            while IFS= read -r bucket; do
                run_command trufflehog s3 --bucket="$bucket" -j 2>/dev/null | jq -c | anew -q subdomains/s3buckets_trufflehog.txt
            done <subdomains/s3buckets.txt
        fi

        # Run trufflehog for open buckets found by CloudHunter
        if [[ -s "subdomains/cloudhunter_open_buckets.txt" ]]; then
            while IFS= read -r line; do
                if echo "$line" | grep -q "Aws Cloud"; then
                    # AWS S3 Bucket
                    bucket_name=$(echo "$line" | awk '{print $3}')
                    run_command trufflehog s3 --bucket="$bucket_name" -j 2>/dev/null | jq -c | anew -q subdomains/cloudhunter_buckets_trufflehog.txt
                elif echo "$line" | grep -q "Google Cloud"; then
                    # Google Cloud Storage
                    bucket_name=$(echo "$line" | awk '{print $3}')
                    run_command trufflehog gcs --project-id="$bucket_name" -j 2>/dev/null | jq -c | anew -q subdomains/cloudhunter_buckets_trufflehog.txt
                fi
            done <subdomains/cloudhunter_open_buckets.txt
        fi

        # Append cloud assets to asset store
        append_assets_from_file cloud asset subdomains/cloudhunter_open_buckets.txt
        append_assets_from_file cloud s3bucket subdomains/s3buckets.txt

        end_func "Results are saved in subdomains/s3buckets.txt, subdomains/cloud_assets.txt, subdomains/s3buckets_trufflehog.txt, and subdomains/cloudhunter_buckets_trufflehog.txt" "${FUNCNAME[0]}"
    else
        if [[ $S3BUCKETS == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            _print_msg WARN "Domain is an IP address; skipping S3 buckets search."
            return 0
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi
}

###############################################################################################################
############################################# GEOLOCALIZATION INFO ############################################
###############################################################################################################

function geo_info() {

    # Create necessary directories
    if ! mkdir -p hosts; then
        print_warnf "Failed to create hosts directory."
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GEO_INFO == true ]]; then
        start_func "${FUNCNAME[0]}" "Running: ipinfo"

        ips_file="${dir}/hosts/ips.txt"

        # Check if ips.txt exists or is empty; if so, attempt to generate it
        if [[ ! -s $ips_file ]]; then
            # Attempt to generate hosts/ips.txt
            if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                if [[ -s "subdomains/subdomains_dnsregs.json" ]]; then
                    jq -r 'select(.host) |"\(.host) - \((.a // [])[])", "\(.host) - \((.aaaa // [])[])"' <"subdomains/subdomains_dnsregs.json" \
                        | grep -E ' - [0-9a-fA-F:.]+$' | sort -u | anew -q "subdomains/subdomains_ips.txt"
                fi

                if [[ -s "subdomains/subdomains_ips.txt" ]]; then
                    cut -d ' ' -f3 subdomains/subdomains_ips.txt \
                        | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." \
                        | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" \
                        | anew -q hosts/ips.txt
                fi
            else
                printf "%b\n" "$domain" \
                    | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." \
                    | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" \
                    | anew -q hosts/ips.txt
            fi
        fi

        if [[ -s $ips_file ]]; then
            if ! touch "${dir}/hosts/ipinfo.txt"; then
                print_warnf "Failed to create ipinfo.txt."
            fi

            while IFS= read -r ip; do
                run_command curl -s "https://ipinfo.io/widget/demo/$ip" >>"${dir}/hosts/ipinfo.txt"
            done <"$ips_file"
        fi

        end_func "Results are saved in hosts/ipinfo.txt" "${FUNCNAME[0]}"
    else
        if [[ $GEO_INFO == false ]]; then
            _print_msg WARN "${FUNCNAME[0]} skipped due to mode or defined in reconftw.cfg."
        else
            _print_msg WARN "${FUNCNAME[0]} already processed. To force execution, delete ${called_fn_dir}/.${FUNCNAME[0]}"
        fi
    fi

}
