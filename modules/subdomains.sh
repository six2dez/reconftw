#!/bin/bash
# shellcheck disable=SC2154  # Variables defined in reconftw.cfg
# reconFTW - Subdomain enumeration module
# Contains: subdomains_full, sub_passive, sub_crt, sub_active, sub_tls,
#           sub_noerror, sub_dns, sub_brute, sub_scraping, sub_analytics,
#           sub_permut, sub_regex_permut, sub_ia_permut, sub_recursive_passive,
#           sub_recursive_brute, subtakeover, zonetransfer, s3buckets,
#           cloud_extra_providers, geo_info
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
            dnsx -silent -retry 2 -r "$resolvers_trusted" < ".tmp/dwf_probes.txt" > ".tmp/dwf_resolved_probes.txt" 2>/dev/null || true

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

    NUMOFLINES_subs="0"
    NUMOFLINES_probed="0"

    # Escape domain for safe use in grep regex (dots are literal, not wildcards)
    DOMAIN_ESCAPED=$(escape_domain_regex "$domain")

    printf "%b#######################################################################%b\n\n" "$bgreen" "$reset"

    if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        printf "%b[%s] Scanning IP %s%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$domain" "$reset"
    else
        printf "%b[%s] Subdomain Enumeration %s%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$domain" "$reset"
    fi

    # Check for sensitive domain exclusion
    if [[ "${EXCLUDE_SENSITIVE:-false}" == true ]]; then
        local sensitive_file="${SCRIPTPATH}/config/sensitive_domains.txt"
        if [[ -s "$sensitive_file" ]]; then
            # Check if target domain matches any sensitive pattern
            if _is_sensitive_domain "$domain" "$sensitive_file"; then
                printf "%b[!] WARNING: Target domain '%s' matches sensitive domain pattern.%b\n" "$bred" "$domain" "$reset"
                printf "%b[!] EXCLUDE_SENSITIVE=true is set. Aborting scan to prevent scanning critical infrastructure.%b\n" "$bred" "$reset"
                printf "%b[!] If this is an authorized engagement, set EXCLUDE_SENSITIVE=false or remove the pattern from config/sensitive_domains.txt%b\n" "$byellow" "$reset"
                return 1
            fi
            printf "%b[*] Sensitive domain exclusion is enabled%b\n" "$bblue" "$reset"
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
        printf "%b[*] Running subdomain enumeration in parallel mode%b\n" "$bblue" "$reset"
        
        # Phase 0: ASN enumeration (independent)
        sub_asn
        
        # Phase 1: Passive sources (all can run in parallel)
        parallel_funcs 4 sub_passive sub_crt
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
        parallel_funcs 3 sub_noerror sub_dns
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
        parallel_funcs 2 sub_tls sub_analytics
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
        parallel_funcs 2 sub_brute sub_permut sub_regex_permut sub_ia_permut
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

    # Count new results
    if [[ -s "subdomains/subdomains.txt" ]]; then
        NUMOFLINES_subs=$(cat "subdomains/subdomains.txt" 2>>"$LOGFILE" | anew ".tmp/subdomains_old.txt" | sed '/^$/d' | wc -l) || NUMOFLINES_subs=0
    fi
    
    if [[ -s "webs/webs.txt" ]]; then
        NUMOFLINES_probed=$(cat "webs/webs.txt" 2>>"$LOGFILE" | anew ".tmp/probed_old.txt" | sed '/^$/d' | wc -l) || NUMOFLINES_probed=0
    fi
    
    # Display results
    TOTAL_SUBS=$(sed '/^$/d' "subdomains/subdomains.txt" 2>/dev/null | wc -l | tr -d ' ')
    TOTAL_WEBS=$(sed '/^$/d' "webs/webs.txt" 2>/dev/null | wc -l | tr -d ' ')
    printf "%b\n[%s] Total subdomains: %s | Total webs: %s%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$TOTAL_SUBS" "$TOTAL_WEBS" "$reset"
    notification "- ${NUMOFLINES_subs} new subs alive" "good"
    if [[ -s "subdomains/subdomains.txt" ]]; then
        sort -o "subdomains/subdomains.txt" "subdomains/subdomains.txt"
        while IFS= read -r sub; do
            printf "%b[%s]   %s%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$sub" "$reset"
        done < "subdomains/subdomains.txt"
    fi

    notification "- ${NUMOFLINES_probed} new web probed" "good"
    if [[ -s "webs/webs.txt" ]]; then
        sort -o "webs/webs.txt" "webs/webs.txt"
        while IFS= read -r web; do
            printf "%b[%s]   %s%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$web" "$reset"
        done < "webs/webs.txt"
    fi
    
    notification "Subdomain Enumeration Finished" "good"
    printf "%b[%s] Results are saved in %s/subdomains/subdomains.txt and webs/webs.txt%b\n" \
        "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$domain" "$reset"
    printf "%b#######################################################################%b\n\n" "$bgreen" "$reset"
    
    # Emit plugin event
    plugins_emit after_subdomains "$domain" "$dir"
    
    # Incremental mode
    incremental_diff "subdomains" "subdomains/subdomains.txt" "subdomains/subdomains_new.txt"
    incremental_save "subdomains" "subdomains/subdomains.txt"
    incremental_diff "webs" "webs/webs.txt" "webs/webs_new.txt"
    incremental_save "webs" "webs/webs.txt"
    
    # Persist counts
    wc -l < "subdomains/subdomains_new.txt" 2>/dev/null > .tmp/subs_new_count
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
    
    # Web probing
    webprobe_simple || printf "%b[!] webprobe_simple failed%b\n" "$bred" "$reset"
    
    # Finalize
    _subdomains_finalize
}

function sub_asn() {
    ensure_dirs .tmp subdomains hosts

    if should_run "ASN_ENUM"; then
        start_subfunc "${FUNCNAME[0]}" "Running: ASN Enumeration"

        # Discover ASN/CIDR metadata for the current target domain.
        if command -v asnmap &>/dev/null; then
            local asn_json pdcp_key timeout_tool asn_rc
            asn_json=".tmp/asnmap_${domain}.json"
            pdcp_key="${PDCP_API_KEY:-}"
            asn_rc=0
            : >"$asn_json"

            if [[ -z "${pdcp_key//[[:space:]]/}" ]]; then
                printf "%b[%s] ASN_ENUM enabled but PDCP_API_KEY is not set. Skipping asnmap ASN enumeration.%b\n" \
                    "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset" | tee -a "$LOGFILE"
            else
                if command -v timeout >/dev/null 2>&1; then
                    timeout_tool="timeout"
                elif command -v gtimeout >/dev/null 2>&1; then
                    timeout_tool="gtimeout"
                else
                    timeout_tool=""
                    printf "%b[%s] timeout/gtimeout not found; running asnmap without timeout guard.%b\n" \
                        "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset" | tee -a "$LOGFILE"
                fi

                if [[ -n "$timeout_tool" ]]; then
                    if PDCP_API_KEY="$pdcp_key" "$timeout_tool" 120 asnmap -d "$domain" -silent -j 2>>"$LOGFILE" >"$asn_json"; then
                        asn_rc=0
                    else
                        asn_rc=$?
                    fi
                else
                    if PDCP_API_KEY="$pdcp_key" asnmap -d "$domain" -silent -j 2>>"$LOGFILE" >"$asn_json"; then
                        asn_rc=0
                    else
                        asn_rc=$?
                    fi
                fi

                if [[ $asn_rc -eq 0 && -s "$asn_json" ]]; then
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

                    printf "%b[%s] ASN enumeration found %s ASNs and %s CIDR ranges%b\n" \
                        "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "${asn_count:-0}" "${cidr_count:-0}" "$reset"

                    # Optional: if asnmap yields discovered domains, feed them into subdomain pipeline.
                    jq -r '.domains[]? // empty' "$asn_json" \
                        | sed '/^$/d' \
                        | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                        | grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" \
                        | sort -u \
                        | anew -q .tmp/subs_no_resolved.txt
                    if [[ -s .tmp/subs_no_resolved.txt ]]; then
                        printf "%b[%s] ASN sources added %s in-scope domains%b\n" \
                            "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$(wc -l <.tmp/subs_no_resolved.txt | tr -d ' ')" "$reset"
                    fi
                elif [[ $asn_rc -eq 124 ]]; then
                    printf "%b[%s] asnmap timed out after 120s. Skipping ASN output for %s.%b\n" \
                        "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$domain" "$reset" | tee -a "$LOGFILE"
                else
                    printf "%b[%s] asnmap failed (exit %s). Skipping ASN output for %s.%b\n" \
                        "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${asn_rc:-1}" "$domain" "$reset" | tee -a "$LOGFILE"
                fi
            fi
        else
            printf "%b[!] asnmap not installed, skipping ASN enumeration%b\n" "$bred" "$reset" | tee -a "$LOGFILE"
        fi

        end_subfunc "${FUNCNAME[0]}" "${FUNCNAME[0]}"
    else
        if [[ $ASN_ENUM == false ]]; then
            printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
        else
            printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} already processed. To force, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
        fi
    fi
}

function sub_passive() {

    ensure_dirs .tmp subdomains

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBPASSIVE == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Passive Subdomain Enumeration"

        # Run subfinder and check for errors
        run_command subfinder -all -d "$domain" -max-time "$SUBFINDER_ENUM_TIMEOUT" -silent -o .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null
        curl -s https://ip.thc.org/sb/$domain | grep -v ";;" | anew -q .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null

        # Run github-subdomains if GITHUB_TOKENS is set and file is not empty
        if [[ -s $GITHUB_TOKENS ]]; then
            if [[ $DEEP == true ]]; then
                github-subdomains -d "$domain" -t "$GITHUB_TOKENS" -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
            else
                github-subdomains -d "$domain" -k -q -t "$GITHUB_TOKENS" -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Run gitlab-subdomains if GITLAB_TOKENS is set and file is not empty
        if [[ -s $GITLAB_TOKENS ]]; then
            gitlab-subdomains -d "$domain" -t "$GITLAB_TOKENS" 2>>"$LOGFILE" | tee .tmp/gitlab_subdomains_psub.txt >/dev/null
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
            printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi

}

function sub_crt() {

    ensure_dirs .tmp subdomains

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBCRT == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Crtsh Subdomain Enumeration"

        # Run crt command and check for errors
        # Apply time fencing if DNS_TIME_FENCE_DAYS is set and > 0
        if [[ ${DNS_TIME_FENCE_DAYS:-0} -gt 0 ]]; then
            local cutoff_date
            cutoff_date=$(date -v-"${DNS_TIME_FENCE_DAYS}"d +%Y-%m-%d 2>/dev/null || date -d "-${DNS_TIME_FENCE_DAYS} days" +%Y-%m-%d 2>/dev/null)
            if [[ -n "$cutoff_date" ]]; then
                run_command crt -s -json -l "${CTR_LIMIT}" "$domain" 2>>"$LOGFILE" \
                    | jq -r --arg cutoff "$cutoff_date" '[.[] | select(.not_before >= $cutoff)] | .[].subdomain' 2>>"$LOGFILE" \
                    | sed -e 's/^\*\.//' >.tmp/crtsh_subdomains.txt
                printf "%b[*] Time fencing enabled: filtering crt.sh results to last %d days (since %s)%b\n" \
                    "$bblue" "${DNS_TIME_FENCE_DAYS}" "$cutoff_date" "$reset"
            else
                # Fallback if date calculation fails
                run_command crt -s -json -l "${CTR_LIMIT}" "$domain" 2>>"$LOGFILE" \
                    | jq -r '.[].subdomain' 2>>"$LOGFILE" \
                    | sed -e 's/^\*\.//' >.tmp/crtsh_subdomains.txt
            fi
        else
            run_command crt -s -json -l "${CTR_LIMIT}" "$domain" 2>>"$LOGFILE" \
                | jq -r '.[].subdomain' 2>>"$LOGFILE" \
                | sed -e 's/^\*\.//' >.tmp/crtsh_subdomains.txt
        fi

        run_command curl -s "https://bgp.he.net/certs/api/list?domain=$domain" | jq -r 'try .domains[].domain' | sed -e 's/^\*\.//' | anew -q .tmp/crtsh_subdomains.txt

        # Use anew to get new subdomains
        cat .tmp/crtsh_subdomains.txt | anew -q .tmp/crtsh_subs_tmp.txt
        # If INSCOPE is true, check inscope
        if [[ $INSCOPE == true ]]; then
            if ! check_inscope .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" >/dev/null; then
                printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
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
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi
}

function sub_active() {

    ensure_dirs .tmp subdomains

    if [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Active Subdomain Enumeration"

        # Combine subdomain files into subs_no_resolved.txt
        if ! find .tmp -type f -iname "*_subs.txt" -exec cat {} + | anew -q .tmp/subs_no_resolved.txt; then
            printf "%b[!] Failed to collect subdomains into subs_no_resolved.txt.%b\n" "$bred" "$reset"
            return 1
        fi

        # Delete out-of-scope domains if outOfScope_file exists
        if [[ -s $outOfScope_file ]]; then
            if ! deleteOutScoped "$outOfScope_file" .tmp/subs_no_resolved.txt; then
                printf "%b[!] deleteOutScoped command failed.%b\n" "$bred" "$reset"
                return 1
            fi
        fi

        if [[ $AXIOM != true ]]; then
            # Update resolvers locally
            if ! resolvers_update_quick_local; then
                printf "%b[!] resolvers_update_quick_local command failed.%b\n" "$bred" "$reset"
                return 1
            fi
            [[ $RESOLVER_IQ == true ]] && resolvers_optimize_local

            # Resolve subdomains using puredns
            if [[ -s ".tmp/subs_no_resolved.txt" ]]; then
                puredns resolve .tmp/subs_no_resolved.txt -w .tmp/subdomains_tmp.txt \
                    -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                    -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" \
                    --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    2>>"$LOGFILE" >/dev/null
            fi
        else
            # Update resolvers using axiom
            if ! resolvers_update_quick_axiom; then
                printf "%b[!] resolvers_update_quick_axiom command failed.%b\n" "$bred" "$reset"
                return 1
            fi

            # Resolve subdomains using axiom-scan
            if [[ -s ".tmp/subs_no_resolved.txt" ]]; then
                axiom-scan .tmp/subs_no_resolved.txt -m puredns-resolve \
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
        if [[ $INSCOPE == true ]]; then
            if ! check_inscope .tmp/subdomains_tmp.txt 2>>"$LOGFILE" >/dev/null; then
                printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
                return 1
            fi
        fi

        # Process subdomains and append new ones to subdomains.txt, count new lines
        if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/subdomains_tmp.txt 2>>"$LOGFILE" \
            | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
            | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
            printf "%b[!] Failed to process subdomains.%b\n" "$bred" "$reset"
            return 1
        fi

        end_subfunc "${NUMOFLINES} subs DNS resolved from passive" "${FUNCNAME[0]}"
    else
        printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
            "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
            "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
    fi
}

function sub_tls() {
    ensure_dirs .tmp subdomains

    if [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: TLS Active Subdomain Enumeration"

        if [[ $DEEP == true ]]; then
            if [[ $AXIOM != true ]]; then
                cat subdomains/subdomains.txt | tlsx -san -cn -silent -ro -c "$TLSX_THREADS" \
                    -p "$TLS_PORTS" -o .tmp/subdomains_tlsx.txt 2>>"$LOGFILE" >/dev/null
            else
                axiom-scan subdomains/subdomains.txt -m tlsx \
                    -san -cn -silent -ro -c "$TLSX_THREADS" -p "$TLS_PORTS" \
                    -o .tmp/subdomains_tlsx.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
            fi
        else
            if [[ $AXIOM != true ]]; then
                cat subdomains/subdomains.txt | tlsx -san -cn -silent -ro -c "$TLSX_THREADS" >.tmp/subdomains_tlsx.txt 2>>"$LOGFILE"
            else
                axiom-scan subdomains/subdomains.txt -m tlsx \
                    -san -cn -silent -ro -c "$TLSX_THREADS" \
                    -o .tmp/subdomains_tlsx.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
            fi
        fi

        if [[ -s ".tmp/subdomains_tlsx.txt" ]]; then
            grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/subdomains_tlsx.txt \
                | grep -aEo 'https?://[^ ]+' \
                | sed "s/|__ //" | anew -q .tmp/subdomains_tlsx_clean.txt
        fi

        if [[ $AXIOM != true ]]; then
            if ! resolvers_update_quick_local; then
                printf "%b[!] resolvers_update_quick_local command failed.%b\n" "$bred" "$reset"
                return 1
            fi
            [[ $RESOLVER_IQ == true ]] && resolvers_optimize_local
            if [[ -s ".tmp/subdomains_tlsx_clean.txt" ]]; then
                puredns resolve .tmp/subdomains_tlsx_clean.txt -w .tmp/subdomains_tlsx_resolved.txt \
                    -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                    -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    2>>"$LOGFILE" >/dev/null
            fi
        else
            if ! resolvers_update_quick_axiom; then
                printf "%b[!] resolvers_update_quick_axiom command failed.%b\n" "$bred" "$reset"
                return 1
            fi
            if [[ -s ".tmp/subdomains_tlsx_clean.txt" ]]; then
                axiom-scan .tmp/subdomains_tlsx_clean.txt -m puredns-resolve \
                    -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/subdomains_tlsx_resolved.txt $AXIOM_EXTRA_ARGS \
                    2>>"$LOGFILE" >/dev/null
            fi
        fi

        if [[ $INSCOPE == true ]]; then
            if ! check_inscope .tmp/subdomains_tlsx_resolved.txt 2>>"$LOGFILE" >/dev/null; then
                printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
                return 1
            fi
        fi

        touch .tmp/subdomains_tlsx_resolved.txt

        if ! NUMOFLINES=$(anew subdomains/subdomains.txt <.tmp/subdomains_tlsx_resolved.txt | sed '/^$/d' | wc -l); then
            printf "%b[!] Counting new subdomains failed.%b\n" "$bred" "$reset"
            return 1
        fi

        end_subfunc "${NUMOFLINES} new subs (tls active enum)" "${FUNCNAME[0]}"
    else
        printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
            "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
            "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
    fi
}

function sub_noerror() {

    ensure_dirs .tmp subdomains

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBNOERROR == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Checking NOERROR DNS response"

        # Check for DNSSEC black lies
        random_subdomain="${RANDOM}thistotallynotexist${RANDOM}.$domain"
        dns_response=$(echo "$random_subdomain" | dnsx -r "$resolvers" -rcode noerror,nxdomain -retry 3 -silent | cut -d' ' -f2)

        if [[ $dns_response == "[NXDOMAIN]" ]]; then
            if ! resolvers_update_quick_local; then
                printf "%b[!] Failed to update resolvers.%b\n" "$bred" "$reset"
                return 1
            fi

            # Determine wordlist based on DEEP setting
            if [[ $DEEP == true ]]; then
                wordlist="$subs_wordlist_big"
            else
                wordlist="$subs_wordlist"
            fi

            # Run dnsx and check for errors
            dnsx -d "$domain" -r "$resolvers" -silent \
                -rcode noerror -w "$wordlist" \
                2>>"$LOGFILE" | cut -d' ' -f1 | anew -q .tmp/subs_noerror.txt >/dev/null

            # Check inscope if INSCOPE is true
            if [[ $INSCOPE == true ]]; then
                if ! check_inscope .tmp/subs_noerror.txt 2>>"$LOGFILE" >/dev/null; then
                    printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
                    return 1
                fi
            fi

            # Process subdomains and append new ones to subdomains.txt, count new lines
            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/subs_noerror.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                | sed 's/^\*\.//' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
                printf "%b[!] Failed to process subdomains.%b\n" "$bred" "$reset"
                return 1
            fi

            end_subfunc "${NUMOFLINES} new subs (DNS noerror)" "${FUNCNAME[0]}"

        else
            printf "\n%s[%s] Detected DNSSEC black lies, skipping this technique.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
        fi

    else
        if [[ $SUBNOERROR == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
                "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi

}

function sub_dns() {
    ensure_dirs .tmp subdomains hosts

    if [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: DNS Subdomain Enumeration and PTR search"

        if [[ -s "subdomains/subdomains.txt" ]]; then
            dnsx -r "$resolvers_trusted" -recon -silent -retry 3 -json \
                -o "subdomains/subdomains_dnsregs.json" <"subdomains/subdomains.txt" 2>>"$LOGFILE" >/dev/null
        fi
        if [[ -s "subdomains/subdomains_dnsregs.json" ]]; then
            # Extract various DNS records and process them
            jq -r --arg domain "$domain" '.. | strings | select(test("\\." + $domain + "$"))' <"subdomains/subdomains_dnsregs.json" \
                | grep -E '^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$' \
                | sort -u | anew -q .tmp/subdomains_dns.txt

            jq -r '.. | strings | select(test("^(\\d{1,3}\\.){3}\\d{1,3}$|^[0-9a-fA-F:]+$"))' <"subdomains/subdomains_dnsregs.json" \
                | sort -u | hakip2host | awk '{print $3}' | unfurl -u domains \
                | sed -e 's/^\*\.//' -e 's/\.$//' -e '/\./!d' | grep "\.${DOMAIN_ESCAPED}$" \
                | grep -E '^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$' | sort -u \
                | anew -q .tmp/subdomains_dns.txt

            for i in $(jq -r '.. | strings | select(test("^(\\d{1,3}\\.){3}\\d{1,3}$|^[0-9a-fA-F:]+$"))' <"subdomains/subdomains_dnsregs.json" | sort -u); do
                curl -s https://ip.thc.org/$i 2>>"$LOGFILE" | grep "\.${DOMAIN_ESCAPED}$" \
                    | grep -E '^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$' | sort -u \
                    | anew -q .tmp/subdomains_dns.txt
            done

            jq -r 'select(.host) |"\(.host) - \((.a // [])[])", "\(.host) - \((.aaaa // [])[])"' <"subdomains/subdomains_dnsregs.json" \
                | grep -E ' - [0-9a-fA-F:.]+$' | sort -u | anew -q "subdomains/subdomains_ips.txt"
        fi
        if [[ $AXIOM != true ]]; then
            if ! resolvers_update_quick_local; then
                printf "%b[!] Failed to update resolvers.%b\n" "$bred" "$reset"
            fi

            if [[ -s ".tmp/subdomains_dns.txt" ]]; then
                puredns resolve .tmp/subdomains_dns.txt -w .tmp/subdomains_dns_resolved.txt \
                    -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                    -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    2>>"$LOGFILE" >/dev/null
            fi
        else
            if ! resolvers_update_quick_axiom; then
                printf "%b[!] Failed to update resolvers.%b\n" "$bred" "$reset"
            fi

            if [[ -s ".tmp/subdomains_dns.txt" ]]; then
                axiom-scan .tmp/subdomains_dns.txt -m puredns-resolve \
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
            printf "%b[%s] No DNS IP pairs found in sub_dns; skipping hosts/ips enrichment.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset" | tee -a "$LOGFILE"
        fi

        if [[ $INSCOPE == true ]]; then
            if ! check_inscope .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" >/dev/null; then
                printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
            fi
        fi

        if [[ -s ".tmp/subdomains_dns_resolved.txt" ]]; then
            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}$' \
                | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
                printf "%b[!] Failed to count new subdomains.%b\n" "$bred" "$reset"
                return 1
            fi
        else
            NUMOFLINES=0
            printf "%b[%s] No DNS-resolved subdomains produced by sub_dns; continuing.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset" | tee -a "$LOGFILE"
        fi

        end_subfunc "${NUMOFLINES} new subs (dns resolution)" "${FUNCNAME[0]}"
    else
        printf "\n%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
            "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
    fi
}

function sub_brute() {

    ensure_dirs .tmp subdomains

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBBRUTE == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Bruteforce Subdomain Enumeration"

        if [[ $AXIOM != true ]]; then
            if ! resolvers_update_quick_local; then
                printf "%b[!] Failed to update resolvers.%b\n" "$bred" "$reset"
                return 1
            fi

            wordlist="$subs_wordlist"
            [[ $DEEP == true ]] && wordlist="$subs_wordlist_big"

            # Run puredns bruteforce
            puredns bruteforce "$wordlist" "$domain" -w .tmp/subs_brute.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                2>>"$LOGFILE" >/dev/null

            # Resolve the subdomains
            if [[ -s ".tmp/subs_brute.txt" ]]; then
                puredns resolve .tmp/subs_brute.txt -w .tmp/subs_brute_valid.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                    -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    2>>"$LOGFILE" >/dev/null
            fi

        else
            if ! resolvers_update_quick_axiom; then
                printf "%b[!] Failed to update resolvers on axiom.%b\n" "$bred" "$reset"
                return 1
            fi

            wordlist="$subs_wordlist"
            [[ $DEEP == true ]] && wordlist="$subs_wordlist_big"

            # Run axiom-scan with puredns-single
            axiom-scan "$wordlist" -m puredns-single "$domain" -r ${AXIOM_RESOLVERS_PATH} \
                --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                -o .tmp/subs_brute.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null

            # Resolve the subdomains using axiom-scan
            if [[ -s ".tmp/subs_brute.txt" ]]; then
                axiom-scan .tmp/subs_brute.txt -m puredns-resolve -r "${AXIOM_RESOLVERS_PATH}" \
                    --resolvers-trusted "${AXIOM_RESOLVERS_TRUSTED_PATH}" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/subs_brute_valid.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Check inscope if INSCOPE is true
        if [[ $INSCOPE == true ]]; then
            if ! check_inscope .tmp/subs_brute_valid.txt 2>>"$LOGFILE" >/dev/null; then
                printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
                return 1
            fi
        fi

        # Process subdomains and append new ones to subdomains.txt, count new lines
        if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/subs_brute_valid.txt 2>>"$LOGFILE" \
            | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
            | sed 's/^\*\.//' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
            printf "%b[!] Failed to process subdomains.%b\n" "$bred" "$reset"
            return 1
        fi

        end_subfunc "${NUMOFLINES} new subs (bruteforce)" "${FUNCNAME[0]}"

    else
        if [[ $SUBBRUTE == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
                "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
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
            printf "%b[!] Failed to create .tmp/scrap_subs.txt.%b\n" "$bred" "$reset"
            return 1
        fi

        # If in multi mode and subdomains.txt doesn't exist, create it
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            if ! printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"; then
                printf "%b[!] Failed to create subdomains.txt.%b\n" "$bred" "$reset"
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
                        | sed "s/^\*\.//" | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
                fi

                if command -v waymore &>/dev/null; then
                    if ! "$TIMEOUT_CMD" "${WAYMORE_TIMEOUT:-30m}" waymore -i "$domain" -mode U -oU .tmp/waymore_urls_subs.txt 2>>"$LOGFILE" >/dev/null; then
                        log_note "sub_scraping: waymore failed or timed out; continuing" "${FUNCNAME[0]}" "${LINENO}"
                    fi
                    if [[ -s ".tmp/waymore_urls_subs.txt" ]]; then
                        cat .tmp/waymore_urls_subs.txt | grep -a "$domain" \
                            | grep -aEo 'https?://[^ ]+' \
                            | sed "s/^\*\.//" | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
                    fi
                else
                    log_note "sub_scraping: waymore not found; skipping waymore passive collection" "${FUNCNAME[0]}" "${LINENO}"
                fi

                if [[ $AXIOM != true ]]; then
                    if ! resolvers_update_quick_local; then
                        printf "%b[!] Failed to update resolvers locally.%b\n" "$bred" "$reset"
                        return 1
                    fi

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
                            | anew -q .tmp/scrap_subs.txt
                    fi

                    if [[ -s ".tmp/probed_tmp_scrap.txt" ]]; then
                        cat .tmp/probed_tmp_scrap.txt | csprecon -s | grep -a "$domain" | sed "s/^\*\.//" | sort -u \
                            | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
                    fi

                else
                    # AXIOM mode
                    if ! resolvers_update_quick_axiom; then
                        printf "%b[!] Failed to update resolvers on axiom.%b\n" "$bred" "$reset"
                        return 1
                    fi

                    axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -random-agent -status-code \
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
                            | anew -q .tmp/scrap_subs.txt
                    fi

                    if [[ -s ".tmp/probed_tmp_scrap.txt" ]]; then
                        cat .tmp/probed_tmp_scrap.txt | csprecon -s | grep -a "$domain" | sed "s/^\*\.//" | sort -u \
                            | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
                    fi

                fi

                if [[ -s ".tmp/scrap_subs.txt" ]]; then
                    puredns resolve .tmp/scrap_subs.txt -w .tmp/scrap_subs_resolved.txt -r "$resolvers" \
                        --resolvers-trusted "$resolvers_trusted" -l "$PUREDNS_PUBLIC_LIMIT" \
                        --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" \
                        --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" 2>>"$LOGFILE" >/dev/null
                fi

                if [[ $INSCOPE == true ]]; then
                    if ! check_inscope .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" >/dev/null; then
                        printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
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
                    httpx -follow-host-redirects -random-agent -status-code -threads "$HTTPX_THREADS" \
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
                            | anew -q .tmp/scrap_subs.txt
                    fi
                fi

                local webinfo_files=()
                [[ -s ".tmp/web_full_info1.txt" ]] && webinfo_files+=(".tmp/web_full_info1.txt")
                [[ -s ".tmp/web_full_info2.txt" ]] && webinfo_files+=(".tmp/web_full_info2.txt")
                [[ -s ".tmp/web_full_info3.txt" ]] && webinfo_files+=(".tmp/web_full_info3.txt")

                if [[ ${#webinfo_files[@]} -gt 0 ]]; then
                    cat "${webinfo_files[@]}" 2>>"$LOGFILE" \
                        | jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"$LOGFILE" >.tmp/web_full_info.txt
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
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
                "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi

}

function sub_analytics() {

    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
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
                    | sed "s/|__ //" | anew -q .tmp/analytics_subs_clean.txt

                if [[ $AXIOM != true ]]; then
                    if ! resolvers_update_quick_local; then
                        printf "%b[!] Failed to update resolvers locally.%b\n" "$bred" "$reset"
                        return 1
                    fi

                    if [[ -s ".tmp/analytics_subs_clean.txt" ]]; then
                        puredns resolve .tmp/analytics_subs_clean.txt -w .tmp/analytics_subs_resolved.txt \
                            -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                            -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                            --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                            2>>"$LOGFILE" >/dev/null
                    fi
                else
                    if ! resolvers_update_quick_axiom; then
                        printf "%b[!] Failed to update resolvers on Axiom.%b\n" "$bred" "$reset"
                        return 1
                    fi

                    if [[ -s ".tmp/analytics_subs_clean.txt" ]]; then
                        axiom-scan .tmp/analytics_subs_clean.txt -m puredns-resolve \
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
                printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
            fi
        fi

        if ! NUMOFLINES=$(cat .tmp/analytics_subs_resolved.txt 2>/dev/null | anew subdomains/subdomains.txt 2>/dev/null | sed '/^$/d' | wc -l); then
            NUMOFLINES=0
        fi

        end_subfunc "${NUMOFLINES} new subs (analytics relationship)" "${FUNCNAME[0]}"

    else
        if [[ $SUBANALYTICS == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi
}

function sub_permut() {

    ensure_dirs .tmp subdomains

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBPERMUTE == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Permutations Subdomain Enumeration"

        # If in multi mode and subdomains.txt doesn't exist, create it with the domain
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            echo "$domain" >"$dir/subdomains/subdomains.txt"
        fi

        # Determine the number of subdomains
        subdomain_count=$(wc -l <subdomains/subdomains.txt)

        # Check if DEEP mode is enabled or subdomains are within DEEP_LIMIT
        if [[ $DEEP == true ]] || [[ $subdomain_count -le $DEEP_LIMIT ]]; then

            # Select the permutations tool
            if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
                if [[ -s "subdomains/subdomains.txt" ]]; then
                    gotator -sub subdomains/subdomains.txt -perm "${tools}/permutations_list.txt" $GOTATOR_FLAGS \
                        -silent 2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1.txt
                fi
            else
                if [[ -s "subdomains/subdomains.txt" ]]; then
                    ripgen -d subdomains/subdomains.txt -w "${tools}/permutations_list.txt" \
                        2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1.txt
                fi
            fi

        elif [[ "$(wc -l <.tmp/subs_no_resolved.txt)" -le $DEEP_LIMIT2 ]]; then

            if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
                if [[ -s ".tmp/subs_no_resolved.txt" ]]; then
                    gotator -sub .tmp/subs_no_resolved.txt -perm "${tools}/permutations_list.txt" $GOTATOR_FLAGS \
                        -silent 2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1.txt
                fi
            else
                if [[ -s ".tmp/subs_no_resolved.txt" ]]; then
                    ripgen -d .tmp/subs_no_resolved.txt -w "${tools}/permutations_list.txt" \
                        2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1.txt
                fi
            fi

        else
            end_subfunc "Skipping Permutations: Too Many Subdomains" "${FUNCNAME[0]}"
            return 0
        fi

        # Resolve the permutations
        if [[ $AXIOM != true ]]; then
            if ! resolvers_update_quick_local; then
                printf "%b[!] Failed to update resolvers.%b\n" "$bred" "$reset"
                return 1
            fi
            if [[ -s ".tmp/gotator1.txt" ]]; then
                puredns resolve .tmp/gotator1.txt -w .tmp/permute1.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                    -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    2>>"$LOGFILE" >/dev/null
            fi
        else
            if ! resolvers_update_quick_axiom; then
                printf "%b[!] Failed to update resolvers on axiom.%b\n" "$bred" "$reset"
                return 1
            fi
            if [[ -s ".tmp/gotator1.txt" ]]; then
                axiom-scan .tmp/gotator1.txt -m puredns-resolve -r "${AXIOM_RESOLVERS_PATH}" \
                    --resolvers-trusted "${AXIOM_RESOLVERS_TRUSTED_PATH}" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/permute1.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi
        fi

        # Generate second round of permutations
        if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
            if [[ -s ".tmp/permute1.txt" ]]; then
                gotator -sub .tmp/permute1.txt -perm "${tools}/permutations_list.txt" \
                    $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator2.txt
            fi
        else
            if [[ -s ".tmp/permute1.txt" ]]; then
                ripgen -d .tmp/permute1.txt -w "${tools}/permutations_list.txt" \
                    2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator2.txt
            fi
        fi

        # Resolve the second round of permutations
        if [[ $AXIOM != true ]]; then
            if [[ -s ".tmp/gotator2.txt" ]]; then
                puredns resolve .tmp/gotator2.txt -w .tmp/permute2.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                    -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    2>>"$LOGFILE" >/dev/null
            fi
        else
            if [[ -s ".tmp/gotator2.txt" ]]; then
                axiom-scan .tmp/gotator2.txt -m puredns-resolve -r "${AXIOM_RESOLVERS_PATH}" \
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
                    printf "%b[!] deleteOutScoped command failed.%b\n" "$bred" "$reset"
                fi
            fi

            # Check inscope if INSCOPE is true
            if [[ $INSCOPE == true ]]; then
                if ! check_inscope .tmp/permute_subs.txt 2>>"$LOGFILE" >/dev/null; then
                    printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
                fi
            fi

            # Process subdomains and append new ones to subdomains.txt, count new lines
            if ! NUMOFLINES=$(grep "\.${DOMAIN_ESCAPED}$\|^${DOMAIN_ESCAPED}$" .tmp/permute_subs.txt 2>>"$LOGFILE" \
                | grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' \
                | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
                printf "%b[!] Failed to process subdomains.%b\n" "$bred" "$reset"
                return 1
            fi
        else
            NUMOFLINES=0
        fi

        end_subfunc "${NUMOFLINES} new subs (permutations)" "${FUNCNAME[0]}"

    else
        if [[ $SUBPERMUTE == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
                "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi

}

function sub_regex_permut() {

    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBREGEXPERMUTE == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Permutations by regex analysis"

        # Change to the regulator directory
        if ! pushd "${tools}/regulator" >/dev/null; then
            printf "%b[!] Failed to change directory to %s.%b\n" "$bred" "${tools}/regulator" "$reset"
            return 1
        fi

        # If in multi mode and subdomains.txt doesn't exist, create it
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
        fi

        # Run the main.py script
        "${tools}/regulator/venv/bin/python3" main.py -t "$domain" -f "${dir}/subdomains/subdomains.txt" -o "${dir}/.tmp/${domain}.brute" \
            2>>"$LOGFILE" >/dev/null

        # Return to the previous directory
        if ! popd >/dev/null; then
            printf "%b[!] Failed to return to previous directory.%b\n" "$bred" "$reset"
            return 1
        fi

        # Resolve the generated domains
        if [[ $AXIOM != true ]]; then
            if ! resolvers_update_quick_local; then
                printf "%b[!] Failed to update resolvers locally.%b\n" "$bred" "$reset"
                return 1
            fi

            if [[ -s ".tmp/${domain}.brute" ]]; then
                puredns resolve ".tmp/${domain}.brute" -w .tmp/regulator.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                    -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    2>>"$LOGFILE" >/dev/null
            fi
        else
            if ! resolvers_update_quick_axiom; then
                printf "%b[!] Failed to update resolvers on Axiom.%b\n" "$bred" "$reset"
                return 1
            fi

            if [[ -s ".tmp/${domain}.brute" ]]; then
                axiom-scan ".tmp/${domain}.brute" -m puredns-resolve \
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
                    printf "%b[!] deleteOutScoped command failed.%b\n" "$bred" "$reset"
                fi
            fi

            if [[ $INSCOPE == true ]]; then
                if ! check_inscope .tmp/regulator.txt 2>>"$LOGFILE" >/dev/null; then
                    printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
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
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi

}

function sub_ia_permut() {

    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBIAPERMUTE == true ]]; then
        start_subfunc "${FUNCNAME[0]}" "Running: Permutations by AI analysis"

        subwiz -i subdomains/subdomains.txt --no-resolve -o .tmp/subwiz.txt 2>>"$LOGFILE" >/dev/null

        # Resolve the generated domains
        if [[ $AXIOM != true ]]; then
            if ! resolvers_update_quick_local; then
                printf "%b[!] Failed to update resolvers locally.%b\n" "$bred" "$reset"
                return 1
            fi

            if [[ -s ".tmp/subwiz.txt" ]]; then
                puredns resolve ".tmp/subwiz.txt" -w .tmp/subwiz_resolved.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                    -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    2>>"$LOGFILE" >/dev/null
            fi
        else
            if ! resolvers_update_quick_axiom; then
                printf "%b[!] Failed to update resolvers on Axiom.%b\n" "$bred" "$reset"
                return 1
            fi

            if [[ -s ".tmp/subwiz.txt" ]]; then
                axiom-scan ".tmp/subwiz.txt" -m puredns-resolve \
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
                    printf "%b[!] deleteOutScoped command failed.%b\n" "$bred" "$reset"
                fi
            fi

            if [[ $INSCOPE == true ]]; then
                if ! check_inscope .tmp/subwiz_resolved.txt 2>>"$LOGFILE" >/dev/null; then
                    printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
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
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi

}

function sub_recursive_passive() {

    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
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
            if ! resolvers_update_quick_local; then
                printf "%b[!] Failed to update resolvers locally.%b\n" "$bred" "$reset"
                return 1
            fi

            if [[ -s ".tmp/subdomains_recurs_top.txt" ]]; then
                subfinder -all -dL .tmp/subdomains_recurs_top.txt -max-time "${SUBFINDER_ENUM_TIMEOUT}" \
                    -silent -o .tmp/passive_recursive_tmp.txt 2>>"$LOGFILE"
            else
                return 1
            fi

            if [[ -s ".tmp/passive_recursive_tmp.txt" ]]; then
                cat .tmp/passive_recursive_tmp.txt | anew -q .tmp/passive_recursive.txt
            fi

            if [[ -s ".tmp/passive_recursive.txt" ]]; then
                puredns resolve .tmp/passive_recursive.txt -w .tmp/passive_recurs_tmp.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                    -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    2>>"$LOGFILE" >/dev/null
            fi

        else
            if ! resolvers_update_quick_axiom; then
                printf "%b[!] Failed to update resolvers on Axiom.%b\n" "$bred" "$reset"
                return 1
            fi

            if [[ -s ".tmp/subdomains_recurs_top.txt" ]]; then
                axiom-scan .tmp/subdomains_recurs_top.txt -m subfinder -all -o .tmp/subfinder_prec.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            else
                return 1
            fi

            if [[ -s ".tmp/subfinder_prec.txt" ]]; then
                cat .tmp/subfinder_prec.txt | anew -q .tmp/passive_recursive.txt
            fi

            if [[ -s ".tmp/passive_recursive.txt" ]]; then
                axiom-scan .tmp/passive_recursive.txt -m puredns-resolve \
                    -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    -o .tmp/passive_recurs_tmp.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
            fi
        fi

        if [[ $INSCOPE == true ]]; then
            if ! check_inscope .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" >/dev/null; then
                printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
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
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif [[ ! -s "subdomains/subdomains.txt" ]]; then
            printf "\n%s[%s] No subdomains to process.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi

}

function sub_recursive_brute() {
    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
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
                    if ! resolvers_update_quick_local; then
                        printf "%b[!] Failed to update resolvers locally.%b\n" "$bred" "$reset"
                        return 1
                    fi
                    puredns bruteforce "$subs_wordlist" "$subdomain_top" -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                        -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                        --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                        -w .tmp/brute_recursive_result_part.txt 2>>"$LOGFILE" >/dev/null
                    cat .tmp/brute_recursive_result_part.txt | anew -q .tmp/brute_recursive.txt
                else
                    if ! resolvers_update_quick_axiom; then
                        printf "%b[!] Failed to update resolvers on axiom.%b\n" "$bred" "$reset"
                        return 1
                    fi
                    axiom-scan "$subs_wordlist" -m puredns-single "$subdomain_top" \
                        -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                        --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                        -o .tmp/brute_recursive_result_part.txt $AXIOM_EXTRA_ARGS \
                        2>>"$LOGFILE" >/dev/null
                    cat .tmp/brute_recursive_result_part.txt | anew -q .tmp/brute_recursive.txt
                fi
            done

            # Generate permutations
            if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
                if [[ -s ".tmp/brute_recursive.txt" ]]; then
                    gotator -sub .tmp/brute_recursive.txt -perm "${tools}/permutations_list.txt" $GOTATOR_FLAGS -silent \
                        2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1_recursive.txt
                fi
            else
                if [[ -s ".tmp/brute_recursive.txt" ]]; then
                    ripgen -d .tmp/brute_recursive.txt -w "${tools}/permutations_list.txt" \
                        2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1_recursive.txt
                fi
            fi

            # Resolve permutations
            if [[ $AXIOM != true ]]; then
                if [[ -s ".tmp/gotator1_recursive.txt" ]]; then
                    puredns resolve .tmp/gotator1_recursive.txt -w .tmp/permute1_recursive.txt \
                        -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                        -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                        --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                        2>>"$LOGFILE" >/dev/null
                fi
            else
                if [[ -s ".tmp/gotator1_recursive.txt" ]]; then
                    axiom-scan .tmp/gotator1_recursive.txt -m puredns-resolve \
                        -r ${AXIOM_RESOLVERS_PATH} --resolvers-trusted ${AXIOM_RESOLVERS_TRUSTED_PATH} \
                        --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                        -o .tmp/permute1_recursive.txt $AXIOM_EXTRA_ARGS \
                        2>>"$LOGFILE" >/dev/null
                fi
            fi

            # Second round of permutations
            if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
                if [[ -s ".tmp/permute1_recursive.txt" ]]; then
                    gotator -sub .tmp/permute1_recursive.txt -perm "${tools}/permutations_list.txt" $GOTATOR_FLAGS -silent \
                        2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator2_recursive.txt
                fi
            else
                if [[ -s ".tmp/permute1_recursive.txt" ]]; then
                    ripgen -d .tmp/permute1_recursive.txt -w "${tools}/permutations_list.txt" \
                        2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator2_recursive.txt
                fi
            fi

            # Resolve second round of permutations
            if [[ $AXIOM != true ]]; then
                if [[ -s ".tmp/gotator2_recursive.txt" ]]; then
                    puredns resolve .tmp/gotator2_recursive.txt -w .tmp/permute2_recursive.txt \
                        -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                        -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                        --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                        2>>"$LOGFILE" >/dev/null
                fi
            else
                if [[ -s ".tmp/gotator2_recursive.txt" ]]; then
                    axiom-scan .tmp/gotator2_recursive.txt -m puredns-resolve \
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
                    printf "%b[!] check_inscope command failed on permute_recursive.txt.%b\n" "$bred" "$reset"
                fi
            fi
            if [[ -s ".tmp/brute_recursive.txt" ]]; then
                if ! check_inscope .tmp/brute_recursive.txt 2>>"$LOGFILE" >/dev/null; then
                    printf "%b[!] check_inscope command failed on brute_recursive.txt.%b\n" "$bred" "$reset"
                fi
            fi
        fi

        # Combine results for final validation
        if [[ -s ".tmp/permute_recursive.txt" ]] || [[ -s ".tmp/brute_recursive.txt" ]]; then
            if ! cat .tmp/permute_recursive.txt .tmp/brute_recursive.txt 2>>"$LOGFILE" | anew -q .tmp/brute_perm_recursive.txt; then
                printf "%b[!] Failed to combine final results.%b\n" "$bred" "$reset"
                return 1
            fi
        fi

        # Final resolve
        if [[ $AXIOM != true ]]; then
            if [[ -s ".tmp/brute_perm_recursive.txt" ]]; then
                puredns resolve .tmp/brute_perm_recursive.txt -w .tmp/brute_perm_recursive_final.txt \
                    -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
                    -l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
                    --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
                    2>>"$LOGFILE" >/dev/null
            fi
        else
            if [[ -s ".tmp/brute_perm_recursive.txt" ]]; then
                axiom-scan .tmp/brute_perm_recursive.txt -m puredns-resolve \
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
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif [[ ! -s "subdomains/subdomains.txt" ]]; then
            printf "\n%s[%s] No subdomains to process.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
                "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
        fi
    fi
}

function subtakeover() {

    # Create necessary directories
    if ! mkdir -p .tmp webs subdomains; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBTAKEOVER == true ]]; then
        start_func "${FUNCNAME[0]}" "Looking for possible subdomain and DNS takeover"

        # Initialize takeover file
        if ! touch .tmp/tko.txt; then
            printf "%b[!] Failed to create .tmp/tko.txt.%b\n" "$bred" "$reset"
            return 1
        fi

        # Combine webs.txt and webs_uncommon_ports.txt if webs_all.txt doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
        fi

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
            .tmp/analytics_subs_clean.txt .tmp/passive_recursive.txt 2>/dev/null | anew -q .tmp/subs_dns_tko.txt

        if [[ -s ".tmp/subs_dns_tko.txt" ]]; then
            cat .tmp/subs_dns_tko.txt 2>/dev/null | dnstake -c "$DNSTAKE_THREADS" -s 2>>"$LOGFILE" \
                | sed '/^$/d' | anew -q .tmp/tko.txt
        fi

        # Remove empty lines from tko.txt
        sed_i '/^$/d' .tmp/tko.txt

        # Count new takeover entries
        if ! NUMOFLINES=$(cat .tmp/tko.txt 2>>"$LOGFILE" | anew webs/takeover.txt | sed '/^$/d' | wc -l); then
            printf "%b[!] Failed to count takeover entries.%b\n" "$bred" "$reset"
            NUMOFLINES=0
        fi

        if [[ $NUMOFLINES -gt 0 ]]; then
            notification "${NUMOFLINES} new possible takeovers found" info
        fi

        if [[ $FARADAY == true ]]; then
            if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
                printf "%b[!] Faraday server is not running. Skipping Faraday integration.%b\n" "$bred" "$reset"
            else
                if [[ -s ".tmp/tko_json.txt" ]]; then
                    faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei .tmp/tko_json.txt 2>>"$LOGFILE" >/dev/null
                fi
            fi
        fi

        end_func "Results are saved in $domain/webs/takeover.txt" "${FUNCNAME[0]}"

    else
        if [[ $SUBTAKEOVER == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s %b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
        fi
    fi

}

function zonetransfer() {

    # Create necessary directories
    if ! mkdir -p subdomains; then
        printf "%b[!] Failed to create subdomains directory.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $ZONETRANSFER == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        start_func "${FUNCNAME[0]}" "Zone transfer check"

        # Initialize output file
        if ! : >"subdomains/zonetransfer.txt"; then
            printf "%b[!] Failed to create zonetransfer.txt.%b\n" "$bred" "$reset"
            return 1
        fi

        # Perform zone transfer check
        for ns in $(dig +short ns "$domain" 2>/dev/null); do
            dig axfr "${domain}" @"$ns" 2>>"$LOGFILE" | tee -a "subdomains/zonetransfer.txt" >/dev/null
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
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            printf "\n%s[%s] Domain is an IP address; skipping zone transfer.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
        fi
    fi

}

function s3buckets() {
    # Create necessary directories
    if ! mkdir -p .tmp subdomains; then
        printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
        return 1
    fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $S3BUCKETS == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        start_func "${FUNCNAME[0]}" "AWS S3 buckets search"

        # If in multi mode and subdomains.txt doesn't exist, create it
        if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
            if ! printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"; then
                printf "%b[!] Failed to create subdomains.txt.%b\n" "$bred" "$reset"
                return 1
            fi
        fi

        # Debug: Print current directory and tools variable
        printf "Current directory: %s\n" "$(pwd)" >>"$LOGFILE"
        printf "Tools directory: %s\n" "$tools" >>"$LOGFILE"

        # S3Scanner
        if [[ $AXIOM != true ]]; then
            if [[ -s "subdomains/subdomains.txt" ]]; then
                s3scanner -bucket-file subdomains/subdomains.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt
            fi
        else
            axiom-scan subdomains/subdomains.txt -m s3scanner -o .tmp/s3buckets_tmp.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null

            if [[ -s ".tmp/s3buckets_tmp.txt" ]]; then
                if ! cat .tmp/s3buckets_tmp.txt .tmp/s3buckets_tmp2.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt; then
                    printf "%b[!] Failed to process s3buckets_tmp.txt.%b\n" "$bred" "$reset"
                fi
                if ! sed_i '/^$/d' .tmp/s3buckets.txt; then
                    printf "%b[!] Failed to clean s3buckets.txt.%b\n" "$bred" "$reset"
                fi
            fi
        fi

        # Initialize the output file in the subdomains folder
        if ! : >subdomains/cloudhunter_open_buckets.txt; then
            printf "%b[!] Failed to initialize cloudhunter_open_buckets.txt.%b\n" "$bred" "$reset"
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
                printf "%b[!] Invalid value for CLOUDHUNTER_PERMUTATION: %s.%b\n" "$bred" "$CLOUDHUNTER_PERMUTATION" "$reset"
                return 1
                ;;
        esac

        if [[ -n "$permutation_file" ]]; then
            if [[ -f "$permutation_file" ]]; then
                PERMUTATION_FLAG="-p"
            else
                printf "%b[%s] CloudHunter permutations file not found (%s); continuing without permutations.%b\n" \
                    "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$permutation_file" "$reset" | tee -a "$LOGFILE"
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
                printf "%b[!] Failed to cd to %s.%b\n" "$bred" "$tools/CloudHunter" "$reset"
                return 1
            fi
            if [[ -n "$permutation_file" ]]; then
                if ! "${tools}/CloudHunter/venv/bin/python3" ./cloudhunter.py "$PERMUTATION_FLAG" "$permutation_file" -r ./resolvers.txt -t 50 "$domain"; then
                    printf "%b[!] CloudHunter command failed for domain %s.%b\n" "$bred" "$domain" "$reset"
                fi
            elif ! "${tools}/CloudHunter/venv/bin/python3" ./cloudhunter.py -r ./resolvers.txt -t 50 "$domain"; then
                printf "%b[!] CloudHunter command failed for domain %s.%b\n" "$bred" "$domain" "$reset"
            fi
        ) >>"$dir/subdomains/cloudhunter_open_buckets.txt" 2>>"$LOGFILE"

        # Process CloudHunter results
        if [[ -s "subdomains/cloudhunter_open_buckets.txt" ]]; then
            if ! NUMOFLINES1=$(cat subdomains/cloudhunter_open_buckets.txt 2>>"$LOGFILE" | anew subdomains/cloud_assets.txt | wc -l); then
                printf "%b[!] Failed to process cloudhunter_open_buckets.txt.%b\n" "$bred" "$reset"
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
                printf "%b[!] Failed to process s3buckets.txt.%b\n" "$bred" "$reset"
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
                trufflehog s3 --bucket="$bucket" -j 2>/dev/null | jq -c | anew -q subdomains/s3buckets_trufflehog.txt
            done <subdomains/s3buckets.txt
        fi

        # Run trufflehog for open buckets found by CloudHunter
        if [[ -s "subdomains/cloudhunter_open_buckets.txt" ]]; then
            while IFS= read -r line; do
                if echo "$line" | grep -q "Aws Cloud"; then
                    # AWS S3 Bucket
                    bucket_name=$(echo "$line" | awk '{print $3}')
                    trufflehog s3 --bucket="$bucket_name" -j 2>/dev/null | jq -c | anew -q subdomains/cloudhunter_buckets_trufflehog.txt
                elif echo "$line" | grep -q "Google Cloud"; then
                    # Google Cloud Storage
                    bucket_name=$(echo "$line" | awk '{print $3}')
                    trufflehog gcs --project-id="$bucket_name" -j 2>/dev/null | jq -c | anew -q subdomains/cloudhunter_buckets_trufflehog.txt
                fi
            done <subdomains/cloudhunter_open_buckets.txt
        fi

        # Append cloud assets to asset store
        append_assets_from_file cloud asset subdomains/cloudhunter_open_buckets.txt
        append_assets_from_file cloud s3bucket subdomains/s3buckets.txt

        end_func "Results are saved in subdomains/s3buckets.txt, subdomains/cloud_assets.txt, subdomains/s3buckets_trufflehog.txt, and subdomains/cloudhunter_buckets_trufflehog.txt" "${FUNCNAME[0]}"
    else
        if [[ $S3BUCKETS == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            printf "\n%s[%s] Domain is an IP address; skipping S3 buckets search.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
            return 0
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
        fi
    fi
}

function cloud_extra_providers() {
    ensure_dirs subdomains .tmp

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        start_func "${FUNCNAME[0]}" "Extra cloud providers checks"
        # Candidate names from domain and subdomains
        company=$(unfurl format %r <<<"$domain")
        printf "%s\n%s\n${domain%%.*}" "$company" "$domain" | sed 's/[^a-zA-Z0-9-]//g' | awk 'length>2' | sort -u >.tmp/cloudnames.txt
        # shellcheck disable=SC2046  # Word splitting intended for awk
        [[ -s subdomains/subdomains.txt ]] && awk -F. -v r="$(echo "$domain" | awk -F. '{print $(NF-1)"."$NF}')" '{print $(NF-2)}' subdomains/subdomains.txt 2>/dev/null | sed 's/[^a-zA-Z0-9-]//g' | awk 'length>2' | sort -u >>.tmp/cloudnames.txt
        sed_i 's/^\///; s/\.$//' .tmp/cloudnames.txt
        sort -u .tmp/cloudnames.txt -o .tmp/cloudnames.txt

        # Common container names for Azure (best-effort)
        printf "public\nstatic\nmedia\nimages\nassets\nbackup\nbackups\nfiles\ncdn" >.tmp/azcontainers.txt

        : >subdomains/cloud_extra.txt

        while IFS= read -r name; do
            # GCS
            for u in \
                "https://storage.googleapis.com/$name/" \
                "https://$name.storage.googleapis.com/"; do
                code=$(curl -sk -o /dev/null -w '%{http_code}' "$u" || true)
                if [[ $code =~ ^20|403$ ]]; then printf "GCS %s %s\n" "$name" "$u" | anew -q subdomains/cloud_extra.txt; fi
            done

            # Azure Blob (requires container; try a few)
            while IFS= read -r c; do
                u="https://$name.blob.core.windows.net/$c?restype=container&comp=list"
                code=$(curl -sk -o /dev/null -w '%{http_code}' "$u" || true)
                if [[ $code =~ ^20|403$ ]]; then printf "AZURE %s %s\n" "$name/$c" "$u" | anew -q subdomains/cloud_extra.txt; fi
            done <.tmp/azcontainers.txt

            # DigitalOcean Spaces (regional)
            for r in ams3 nyc3 sfo3 sgp1 fra1 blr1; do
                u="https://$name.$r.digitaloceanspaces.com/"
                code=$(curl -sk -o /dev/null -w '%{http_code}' "$u" || true)
                if [[ $code =~ ^20|403$ ]]; then printf "DOSPACE %s %s\n" "$name.$r" "$u" | anew -q subdomains/cloud_extra.txt; fi
            done

            # Backblaze B2 (best-effort listing)
            u="https://f000.backblazeb2.com/file/$name/"
            code=$(curl -sk -o /dev/null -w '%{http_code}' "$u" || true)
            if [[ $code =~ ^20|403$ ]]; then printf "B2 %s %s\n" "$name" "$u" | anew -q subdomains/cloud_extra.txt; fi

        done <.tmp/cloudnames.txt

        append_assets_from_file cloud asset subdomains/cloud_extra.txt
        end_func "Results are saved in subdomains/cloud_extra.txt" "${FUNCNAME[0]}"
    else
        printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped or already processed.${reset}\n"
    fi
}

###############################################################################################################
############################################# GEOLOCALIZATION INFO ############################################
###############################################################################################################

function geo_info() {

    # Create necessary directories
    if ! mkdir -p hosts; then
        printf "%b[!] Failed to create hosts directory.%b\n" "$bred" "$reset"
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
                printf "%b[!] Failed to create ipinfo.txt.%b\n" "$bred" "$reset"
            fi

            while IFS= read -r ip; do
                curl -s "https://ipinfo.io/widget/demo/$ip" >>"${dir}/hosts/ipinfo.txt"
            done <"$ips_file"
        fi

        end_func "Results are saved in hosts/ipinfo.txt" "${FUNCNAME[0]}"
    else
        if [[ $GEO_INFO == false ]]; then
            printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
        else
            printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
                "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
        fi
    fi

}
