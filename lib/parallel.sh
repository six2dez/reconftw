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
_PARALLEL_LAST_BADGE=""

_parallel_effective_max_jobs() {
    local requested="${1:-$PARALLEL_MAX_JOBS}"
    local pressure="${PARALLEL_PRESSURE_LEVEL:-normal}"
    local effective="$requested"

    # Backpressure: shrink concurrency when rate-limit pressure is high.
    if [[ "$pressure" == "high" ]]; then
        effective=$((requested / 2))
        ((effective < 1)) && effective=1
    fi
    echo "$effective"
}

_parallel_compact_list() {
    local max="${2:-6}"
    local list="$1"
    if [[ -z "$list" ]]; then
        printf "none"
        return 0
    fi
    local count
    count=$(awk -F',' 'NF{print NF}' <<<"$list")
    if ((count <= max)); then
        printf "%s" "$list"
    else
        local trimmed
        trimmed=$(echo "$list" | awk -F',' -v m="$max" '{out=""; for(i=1;i<=m;i++){out=out $i (i<m? ",":"")} print out}')
        printf "%s, +%d more" "$trimmed" "$((count - max))"
    fi
}

_parallel_snapshot() {
    local active_list="$1"
    local done_list="$2"
    local queue_count="$3"
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0
    local active_fmt done_fmt
    active_fmt=$(_parallel_compact_list "$active_list" 6)
    done_fmt=$(_parallel_compact_list "$done_list" 6)
    printf "Active: %s\n" "$active_fmt"
    printf "Done:   %s | Queue: %s pending\n" "$done_fmt" "$queue_count"
}

###############################################################################
# Output Helpers
###############################################################################

# Emit output for a single parallel job based on PARALLEL_LOG_MODE
# Usage: _parallel_emit_job_output func_name log_file rc start_ts end_ts
_parallel_emit_job_output() {
    local func_name="$1"
    local log_file="$2"
    local rc="$3"
    local start_ts="$4"
    local end_ts="$5"
    local mode="${PARALLEL_LOG_MODE:-summary}"
    local tail_lines="${PARALLEL_TAIL_LINES:-20}"
    local duration=$((end_ts - start_ts))

    local skip_marker=""
    local cache_marker=""
    local status_marker=""
    if [[ -n "${called_fn_dir:-}" ]]; then
        skip_marker="${called_fn_dir}/.skip_${func_name}"
        cache_marker="${called_fn_dir}/.cache_${func_name}"
        status_marker="${called_fn_dir}/.status_${func_name}"
    fi

    local badge=""
    if [[ -n "$cache_marker" && -f "$cache_marker" ]]; then
        badge="CACHE"
        rm -f "$cache_marker" 2>/dev/null || true
    elif [[ -n "$skip_marker" && -f "$skip_marker" ]]; then
        badge="SKIP"
        rm -f "$skip_marker" 2>/dev/null || true
    elif [[ -n "$status_marker" && -f "$status_marker" ]]; then
        badge=$(head -n 1 "$status_marker" 2>/dev/null | tr -d '\r\n' | tr '[:lower:]' '[:upper:]')
        case "$badge" in
            OK|WARN|FAIL|SKIP|CACHE|INFO) ;;
            *) badge="" ;;
        esac
        rm -f "$status_marker" 2>/dev/null || true
    elif [[ "$rc" -eq 0 ]]; then
        badge="OK"
    else
        badge="FAIL"
    fi

    [[ -z "$badge" ]] && badge=$([[ "$rc" -eq 0 ]] && echo "OK" || echo "FAIL")
    _PARALLEL_LAST_BADGE="$badge"

    # In quiet mode (OUTPUT_VERBOSITY==0), only show failures
    if [[ "${OUTPUT_VERBOSITY:-1}" -eq 0 ]] && [[ "$badge" != "FAIL" ]]; then
        return 0
    fi

    # For failures in quiet mode, print directly since _print_status is gated on verbosity
    local _force_print=false
    [[ "${OUTPUT_VERBOSITY:-1}" -eq 0 ]] && [[ "$badge" == "FAIL" ]] && _force_print=true

    case "$mode" in
        summary)
            if [[ "$_force_print" == true ]]; then
                if declare -F ui_count_inc >/dev/null 2>&1; then
                    ui_count_inc "$badge"
                fi
                (OUTPUT_VERBOSITY=1; print_task "$badge" "$func_name" "$duration" "")
            else
                _print_status "$badge" "$func_name" "${duration}s"
            fi
            if [[ "$badge" == "FAIL" ]] && [[ -s "$log_file" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
                tail -n 5 "$log_file" | while IFS= read -r line; do
                    printf "         %s\n" "$line"
                done
            fi
            ;;
        tail)
            local show_lines="$tail_lines"
            [[ "$rc" -ne 0 ]] && show_lines=$((tail_lines * 2))
            if [[ "$_force_print" == true ]]; then
                if declare -F ui_count_inc >/dev/null 2>&1; then
                    ui_count_inc "$badge"
                fi
                (OUTPUT_VERBOSITY=1; print_task "$badge" "$func_name" "$duration" "")
            else
                _print_status "$badge" "$func_name" "${duration}s"
            fi
            if [[ -s "$log_file" ]]; then
                tail -n "$show_lines" "$log_file"
            fi
            ;;
        full)
            if [[ "$_force_print" == true ]]; then
                if declare -F ui_count_inc >/dev/null 2>&1; then
                    ui_count_inc "$badge"
                fi
                (OUTPUT_VERBOSITY=1; print_task "$badge" "$func_name" "$duration" "")
            else
                _print_status "$badge" "$func_name" "${duration}s"
            fi
            if [[ -s "$log_file" ]]; then
                cat "$log_file"
            fi
            ;;
    esac
}

# Print a summary line for a completed batch
# Usage: _parallel_batch_summary total_jobs failed_count batch_start_ts
_parallel_batch_summary() {
    local ok="$1"
    local warn="$2"
    local fail="$3"
    local skip="$4"
    local cache="$5"
    local batch_start="$6"
    local batch_end
    batch_end=$(date +%s)
    local elapsed=$((batch_end - batch_start))

    # Skip in quiet mode
    [[ "${OUTPUT_VERBOSITY:-1}" -eq 0 ]] && return 0
    # Skip batch envelope in summary mode at normal verbosity
    [[ "${PARALLEL_LOG_MODE:-summary}" == "summary" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -lt 2 ]] && return 0

    if declare -F ui_batch_end >/dev/null 2>&1; then
        ui_batch_end "$ok" "$warn" "$fail" "$elapsed" "$skip" "$cache"
    else
        printf "  --- batch: ok:%d warn:%d fail:%d skip:%d cache:%d, %ds elapsed ---\n" \
            "$ok" "$warn" "$fail" "$skip" "$cache" "$elapsed"
    fi
}

###############################################################################
# Core Parallel Execution
###############################################################################

# Run multiple commands in parallel with a job limit
# Usage: parallel_run max_jobs "cmd1" "cmd2" "cmd3" ...
# Example: parallel_run 4 "subfinder -d $domain" "amass enum -d $domain"
parallel_run() {
    local max_jobs
    max_jobs=$(_parallel_effective_max_jobs "${1:-$PARALLEL_MAX_JOBS}")
    shift

    local -a pids=()
    local cmd
    local running=0

    for cmd in "$@"; do
        # Start command in background (use bash -c to avoid eval injection)
        bash -c "$cmd" &
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
    local max_jobs
    max_jobs=$(_parallel_effective_max_jobs "${1:-$PARALLEL_MAX_JOBS}")
    shift

    local parallel_log_root
    if [[ -n "${dir:-}" ]]; then
        parallel_log_root="${dir}/.tmp/parallel"
    else
        parallel_log_root="/tmp/reconftw_parallel.$$"
    fi
    mkdir -p "$parallel_log_root" 2>/dev/null || true

    local -a batch_pids=()
    local -a batch_funcs=()
    local -a batch_logs=()
    local -a batch_starts=()
    local func
    local failed=0
    local batch_start_ts
    batch_start_ts=$(date +%s)
    local batch_label="${PARALLEL_LABEL:-parallel}"
    local total_funcs=$#
    local queued_count=0
    local done_list=""

    for func in "$@"; do
        # Check if function exists
        if ! declare -f "$func" >/dev/null 2>&1; then
            print_warnf "Function %s not found, skipping" "$func"
            continue
        fi

        if ((${#batch_pids[@]} == 0)); then
            if declare -F ui_batch_start >/dev/null 2>&1; then
                # Skip batch envelope in summary mode at normal verbosity - individual status lines suffice
                if [[ "${PARALLEL_LOG_MODE:-summary}" != "summary" ]] || [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
                    ui_batch_start "$batch_label" "$max_jobs"
                fi
            fi
        fi

        local log_file="${parallel_log_root}/${func}.$$.$RANDOM.log"
        local job_start_ts
        job_start_ts=$(date +%s)

        # Run function in background subshell
        (
            "$func"
        ) >"$log_file" 2>&1 &
        batch_pids+=("$!")
        batch_funcs+=("$func")
        batch_logs+=("$log_file")
        batch_starts+=("$job_start_ts")
        queued_count=$((queued_count + 1))

        # Log if verbose (OUTPUT_VERBOSITY >= 2)
        [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
            printf "%b[*] Started %s (PID: %d)%b\n" "${cyan:-}" "$func" "${batch_pids[${#batch_pids[@]}-1]}" "${reset:-}"

        # If we've reached max jobs, flush the current batch.
        if ((${#batch_pids[@]} >= max_jobs)); then
            if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
                local active_list=""
                local i
                for i in "${batch_funcs[@]}"; do
                    [[ -z "$active_list" ]] && active_list="${i} 00:00" || active_list="${active_list}, ${i} 00:00"
                done
                local queue_count=$((total_funcs - queued_count))
                _parallel_snapshot "$active_list" "$done_list" "$queue_count"
            fi
            local idx rc
            local batch_ok=0 batch_warn=0 batch_fail=0 batch_skip=0 batch_cache=0
            for idx in "${!batch_pids[@]}"; do
                if wait "${batch_pids[$idx]}" 2>/dev/null; then
                    rc=0
                else
                    rc=$?
                fi
                local job_end_ts
                job_end_ts=$(date +%s)
                _parallel_emit_job_output "${batch_funcs[$idx]}" "${batch_logs[$idx]}" "$rc" "${batch_starts[$idx]}" "$job_end_ts"
                case "${_PARALLEL_LAST_BADGE:-OK}" in
                    OK) ((batch_ok++)) ;;
                    WARN) ((batch_warn++)) ;;
                    FAIL) ((batch_fail++)); ((failed++)) ;;
                    SKIP) ((batch_skip++)) ;;
                    CACHE) ((batch_cache++)) ;;
                    *) ((batch_ok++)) ;;
                esac
                local job_dur=$((job_end_ts - batch_starts[$idx]))
                local dur_fmt
                dur_fmt=$(format_duration "$job_dur")
                if [[ -z "$done_list" ]]; then
                    done_list="${batch_funcs[$idx]} ${dur_fmt}"
                else
                    done_list="${done_list}, ${batch_funcs[$idx]} ${dur_fmt}"
                fi
                [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && printf "%b[*] Finished %s (PID: %s, rc=%s)%b\n" "${cyan:-}" "${batch_funcs[$idx]}" "${batch_pids[$idx]}" "$rc" "${reset:-}"
                rm -f "${batch_logs[$idx]}" 2>/dev/null || true
            done
            _parallel_batch_summary "$batch_ok" "$batch_warn" "$batch_fail" "$batch_skip" "$batch_cache" "$batch_start_ts"
            if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
                local queue_count=$((total_funcs - queued_count))
                _parallel_snapshot "none" "$done_list" "$queue_count"
            fi
            batch_pids=()
            batch_funcs=()
            batch_logs=()
            batch_starts=()
            batch_start_ts=$(date +%s)
        fi
    done

    # Wait for all remaining jobs and collect exit codes
    if ((${#batch_pids[@]} > 0)); then
        if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
            local active_list=""
            local i
            for i in "${batch_funcs[@]}"; do
                [[ -z "$active_list" ]] && active_list="${i} 00:00" || active_list="${active_list}, ${i} 00:00"
            done
            local queue_count=$((total_funcs - queued_count))
            _parallel_snapshot "$active_list" "$done_list" "$queue_count"
        fi
        local idx rc
        local batch_ok=0 batch_warn=0 batch_fail=0 batch_skip=0 batch_cache=0
        for idx in "${!batch_pids[@]}"; do
            if wait "${batch_pids[$idx]}" 2>/dev/null; then
                rc=0
            else
                rc=$?
            fi
            local job_end_ts
            job_end_ts=$(date +%s)
            _parallel_emit_job_output "${batch_funcs[$idx]}" "${batch_logs[$idx]}" "$rc" "${batch_starts[$idx]}" "$job_end_ts"
            case "${_PARALLEL_LAST_BADGE:-OK}" in
                OK) ((batch_ok++)) ;;
                WARN) ((batch_warn++)) ;;
                FAIL) ((batch_fail++)); ((failed++)) ;;
                SKIP) ((batch_skip++)) ;;
                CACHE) ((batch_cache++)) ;;
                *) ((batch_ok++)) ;;
            esac
            local job_dur=$((job_end_ts - batch_starts[$idx]))
            local dur_fmt
            dur_fmt=$(format_duration "$job_dur")
            if [[ -z "$done_list" ]]; then
                done_list="${batch_funcs[$idx]} ${dur_fmt}"
            else
                done_list="${done_list}, ${batch_funcs[$idx]} ${dur_fmt}"
            fi
            [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && printf "%b[*] Finished %s (PID: %s, rc=%s)%b\n" "${cyan:-}" "${batch_funcs[$idx]}" "${batch_pids[$idx]}" "$rc" "${reset:-}"
            rm -f "${batch_logs[$idx]}" 2>/dev/null || true
        done
        _parallel_batch_summary "$batch_ok" "$batch_warn" "$batch_fail" "$batch_skip" "$batch_cache" "$batch_start_ts"
        if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
            _parallel_snapshot "none" "$done_list" "0"
        fi
    fi
    rmdir "$parallel_log_root" 2>/dev/null || true

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
    local start_time
    start_time=$(date +%s)
    
    while jobs -p | grep -q .; do
        if ((timeout > 0)); then
            local elapsed
            elapsed=$(($(date +%s) - start_time))
            if ((elapsed >= timeout)); then
                print_warnf "Timeout reached, killing remaining jobs"
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

    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
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

    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
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

    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
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
    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
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
    
    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
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
    
    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
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
    
    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
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
    
    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
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
    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
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
    
    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
        printf "%b[*] Parallelized subdomain enumeration complete%b\n" \
            "${bgreen:-}" "${reset:-}"
}

# Orchestrate full vulnerability scanning with parallelization
# Usage: parallel_vulns_full
parallel_vulns_full() {
    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
        printf "%b[*] Starting parallelized vulnerability scanning%b\n" \
            "${bblue:-}" "${reset:-}"
    
    # Run nuclei first (it's comprehensive)
    nuclei_check
    
    # Then run other checks in parallel batches
    parallel_web_vulns
    parallel_injection_vulns
    parallel_server_vulns
    
    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && \
        printf "%b[*] Parallelized vulnerability scanning complete%b\n" \
            "${bgreen:-}" "${reset:-}"
}
