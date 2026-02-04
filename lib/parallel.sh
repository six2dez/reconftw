#!/usr/bin/env bash
# lib/parallel.sh - Parallel execution utilities for reconFTW
# Part of reconFTW refactoring - Phase 3

# Prevent multiple sourcing
[[ -n "$_PARALLEL_SH_LOADED" ]] && return 0
declare -r _PARALLEL_SH_LOADED=1

###############################################################################
# Configuration
###############################################################################

# Default maximum concurrent jobs (can be overridden)
PARALLEL_MAX_JOBS="${PARALLEL_MAX_JOBS:-4}"

# Track running PIDs for cleanup
declare -a _PARALLEL_PIDS=()

###############################################################################
# Core Parallel Execution
###############################################################################

# Run multiple commands in parallel with a job limit
# Usage: parallel_run max_jobs "cmd1" "cmd2" "cmd3" ...
# Example: parallel_run 4 "subfinder -d $domain" "amass enum -d $domain"
parallel_run() {
    local max_jobs="${1:-$PARALLEL_MAX_JOBS}"
    shift
    
    local -a pids=()
    local cmd
    local running=0
    
    for cmd in "$@"; do
        # Start command in background
        eval "$cmd" &
        pids+=($!)
        ((running++))
        
        # If we've reached max jobs, wait for one to finish
        if ((running >= max_jobs)); then
            wait -n 2>/dev/null || true
            ((running--))
        fi
    done
    
    # Wait for all remaining jobs
    wait "${pids[@]}" 2>/dev/null
}

# Run multiple functions in parallel with a job limit
# Usage: parallel_funcs max_jobs func1 func2 func3 ...
# Example: parallel_funcs 4 sub_passive sub_crt sub_active
parallel_funcs() {
    local max_jobs="${1:-$PARALLEL_MAX_JOBS}"
    shift
    
    local -a pids=()
    local func
    local running=0
    
    for func in "$@"; do
        # Check if function exists
        if ! declare -f "$func" >/dev/null 2>&1; then
            printf "%b[!] Function %s not found, skipping%b\n" "${yellow:-}" "$func" "${reset:-}" >&2
            continue
        fi
        
        # Run function in background subshell
        ( "$func" ) &
        pids+=($!)
        ((running++))
        
        # Log if verbose
        [[ ${VERBOSE:-false} == true ]] && \
            printf "%b[*] Started %s (PID: %d)%b\n" "${cyan:-}" "$func" "${pids[-1]}" "${reset:-}"
        
        # If we've reached max jobs, wait for one to finish
        if ((running >= max_jobs)); then
            wait -n 2>/dev/null || true
            ((running--))
        fi
    done
    
    # Wait for all remaining jobs and collect exit codes
    local failed=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid" 2>/dev/null; then
            ((failed++))
        fi
    done
    
    return $failed
}

# Run functions in groups (batch parallelization)
# Usage: parallel_batch group_size func1 func2 func3 ...
# Example: parallel_batch 3 func1 func2 func3 func4 func5
# Runs func1,func2,func3 in parallel, waits, then func4,func5
parallel_batch() {
    local batch_size="${1:-3}"
    shift
    
    local -a batch=()
    local func
    
    for func in "$@"; do
        batch+=("$func")
        
        if ((${#batch[@]} >= batch_size)); then
            parallel_funcs "$batch_size" "${batch[@]}"
            batch=()
        fi
    done
    
    # Run remaining functions
    if ((${#batch[@]} > 0)); then
        parallel_funcs "${#batch[@]}" "${batch[@]}"
    fi
}

###############################################################################
# Job Control Helpers
###############################################################################

# Wait for all background jobs with timeout
# Usage: wait_for_jobs [timeout_seconds]
wait_for_jobs() {
    local timeout="${1:-0}"
    local start_time=$(date +%s)
    
    while jobs -p | grep -q .; do
        if ((timeout > 0)); then
            local elapsed=$(($(date +%s) - start_time))
            if ((elapsed >= timeout)); then
                printf "%b[!] Timeout reached, killing remaining jobs%b\n" "${bred:-}" "${reset:-}" >&2
                jobs -p | xargs -r kill 2>/dev/null || true
                return 1
            fi
        fi
        sleep 1
    done
    
    return 0
}

# Get count of running background jobs
# Usage: running_jobs=$(get_running_jobs)
get_running_jobs() {
    jobs -p | wc -l | tr -d ' '
}

# Kill all tracked parallel jobs (for cleanup)
# Usage: cleanup_parallel_jobs
cleanup_parallel_jobs() {
    local pid
    for pid in "${_PARALLEL_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    _PARALLEL_PIDS=()
}

###############################################################################
# Subdomain Enumeration Parallelization
###############################################################################

# Run passive subdomain enumeration in parallel
# Usage: parallel_passive_enum
# Runs: sub_passive, sub_crt in parallel (sources that don't need resolved subs)
parallel_passive_enum() {
    local funcs=(
        "sub_passive"
        "sub_crt"
    )
    
    printf "%b[*] Running passive enumeration in parallel (%d functions)%b\n" \
        "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    
    parallel_funcs 2 "${funcs[@]}"
}

# Run active subdomain enumeration in parallel
# Usage: parallel_active_enum
# Runs: sub_active, sub_noerror, sub_dns in parallel
parallel_active_enum() {
    local funcs=(
        "sub_active"
        "sub_noerror"
        "sub_dns"
    )
    
    printf "%b[*] Running active enumeration in parallel (%d functions)%b\n" \
        "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    
    parallel_funcs 3 "${funcs[@]}"
}

# Run post-active subdomain enumeration in parallel
# Usage: parallel_postactive_enum
# Runs: sub_tls, sub_analytics (require resolved subdomains from sub_active)
parallel_postactive_enum() {
    local funcs=(
        "sub_tls"
        "sub_analytics"
    )
    
    printf "%b[*] Running post-active enumeration in parallel (%d functions)%b\n" \
        "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    
    parallel_funcs 2 "${funcs[@]}"
}

# Run brute force enumeration (typically sequential due to resource usage)
# Usage: parallel_brute_enum
parallel_brute_enum() {
    local funcs=(
        "sub_brute"
        "sub_permut"
        "sub_regex_permut"
    )
    
    # Brute force is resource intensive, run with limit of 2
    printf "%b[*] Running brute force enumeration (limited parallelism)%b\n" \
        "${bblue:-}" "${reset:-}"
    
    parallel_funcs 2 "${funcs[@]}"
}

###############################################################################
# Vulnerability Scanning Parallelization
###############################################################################

# Run web vulnerability checks in parallel
# Usage: parallel_web_vulns
parallel_web_vulns() {
    local funcs=(
        "cors"
        "open_redirect"
        "crlf_checks"
        "xss"
    )
    
    printf "%b[*] Running web vulnerability checks in parallel (%d checks)%b\n" \
        "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    
    parallel_funcs 4 "${funcs[@]}"
}

# Run injection vulnerability checks in parallel
# Usage: parallel_injection_vulns
parallel_injection_vulns() {
    local funcs=(
        "sqli"
        "ssti"
        "lfi"
        "command_injection"
    )
    
    printf "%b[*] Running injection vulnerability checks in parallel (%d checks)%b\n" \
        "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    
    parallel_funcs 4 "${funcs[@]}"
}

# Run server-side vulnerability checks in parallel
# Usage: parallel_server_vulns
parallel_server_vulns() {
    local funcs=(
        "ssrf_checks"
        "prototype_pollution"
        "smuggling"
    )
    
    printf "%b[*] Running server-side vulnerability checks in parallel (%d checks)%b\n" \
        "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    
    parallel_funcs 3 "${funcs[@]}"
}

###############################################################################
# OSINT Parallelization
###############################################################################

# Run OSINT gathering in parallel
# Usage: parallel_osint
parallel_osint() {
    local funcs=(
        "google_dorks"
        "github_dorks"
        "metadata"
        "emails"
        "domain_info"
    )
    
    printf "%b[*] Running OSINT gathering in parallel (%d sources)%b\n" \
        "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    
    parallel_funcs 4 "${funcs[@]}"
}

###############################################################################
# Full Pipeline Parallelization
###############################################################################

# Orchestrate full subdomain enumeration with parallelization
# Usage: parallel_subdomains_full
# This replaces the sequential execution in subdomains_full()
parallel_subdomains_full() {
    printf "%b[*] Starting parallelized subdomain enumeration%b\n" \
        "${bblue:-}" "${reset:-}"
    
    # Phase 1: Passive enumeration (parallel - no dependencies)
    parallel_passive_enum
    
    # Merge passive results before active phase
    [[ -s ".tmp/passive_subs.txt" ]] && cat .tmp/passive_subs.txt | anew -q subdomains/subdomains.txt
    [[ -s ".tmp/crtsh_subs.txt" ]] && cat .tmp/crtsh_subs.txt | anew -q subdomains/subdomains.txt
    
    # Phase 2: Active enumeration (parallel - resolves subdomains)
    parallel_active_enum
    
    # Phase 3: Post-active (parallel - requires resolved subdomains)
    parallel_postactive_enum
    
    # Phase 4: Brute force (limited parallel due to resource usage)
    if [[ ${SUBBRUTE:-false} == true ]] || [[ ${SUBPERMUTE:-false} == true ]]; then
        parallel_brute_enum
    fi
    
    # Phase 5: Scraping and recursive (sequential - depends on previous results)
    [[ ${SUBSCRAPING:-false} == true ]] && sub_scraping
    [[ ${SUB_RECURSIVE_BRUTE:-false} == true ]] && sub_recursive_brute
    
    printf "%b[*] Parallelized subdomain enumeration complete%b\n" \
        "${bgreen:-}" "${reset:-}"
}

# Orchestrate full vulnerability scanning with parallelization
# Usage: parallel_vulns_full
parallel_vulns_full() {
    printf "%b[*] Starting parallelized vulnerability scanning%b\n" \
        "${bblue:-}" "${reset:-}"
    
    # Run nuclei first (it's comprehensive)
    nuclei_check
    
    # Then run other checks in parallel batches
    parallel_web_vulns
    parallel_injection_vulns
    parallel_server_vulns
    
    printf "%b[*] Parallelized vulnerability scanning complete%b\n" \
        "${bgreen:-}" "${reset:-}"
}
