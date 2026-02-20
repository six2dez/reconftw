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
PARALLEL_HEARTBEAT_SECONDS="${PARALLEL_HEARTBEAT_SECONDS:-20}"
PARALLEL_UI_MODE="${PARALLEL_UI_MODE:-clean}"
PARALLEL_PROGRESS_SHOW_ETA="${PARALLEL_PROGRESS_SHOW_ETA:-true}"
PARALLEL_PROGRESS_SHOW_ACTIVE="${PARALLEL_PROGRESS_SHOW_ACTIVE:-true}"
PARALLEL_PROGRESS_COMPACT_ACTIVE_MAX="${PARALLEL_PROGRESS_COMPACT_ACTIVE_MAX:-4}"
PARALLEL_TRACE_SLOW_SECONDS="${PARALLEL_TRACE_SLOW_SECONDS:-30}"

# Track running PIDs for cleanup
declare -a _PARALLEL_PIDS=()
_PARALLEL_LAST_BADGE=""

_parallel_live_break() {
    if declare -F ui_live_progress_break >/dev/null 2>&1; then
        ui_live_progress_break
    fi
}

_parallel_get_ui_mode() {
    case "${PARALLEL_UI_MODE:-clean}" in
        clean|balanced|trace) printf "%s" "${PARALLEL_UI_MODE:-clean}" ;;
        *) printf "clean" ;;
    esac
}

_parallel_should_show_started() {
    local mode
    mode=$(_parallel_get_ui_mode)
    [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && [[ "$mode" == "trace" ]]
}

_parallel_should_show_finished() {
    local rc="${1:-0}" duration="${2:-0}" badge="${3:-OK}"
    local mode
    mode=$(_parallel_get_ui_mode)
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 2 ]] && return 1
    case "$mode" in
        trace) return 0 ;;
        balanced)
            if [[ "$rc" -ne 0 ]] || [[ "$badge" == "WARN" ]] || [[ "$badge" == "FAIL" ]] || ((duration >= PARALLEL_TRACE_SLOW_SECONDS)); then
                return 0
            fi
            return 1
            ;;
        *) return 1 ;;
    esac
}

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
    local done_count="${4:-0}"
    local total_count="${5:-0}"
    local elapsed_batch="${6:-0}"
    [[ "${OUTPUT_VERBOSITY:-1}" -lt 1 ]] && return 0

    local mode active_max active_fmt done_fmt progress_pct eta="--"
    mode=$(_parallel_get_ui_mode)
    active_max="${PARALLEL_PROGRESS_COMPACT_ACTIVE_MAX:-4}"
    active_fmt=$(_parallel_compact_list "$active_list" "$active_max")
    done_fmt=$(_parallel_compact_list "$done_list" "$active_max")

    if ((total_count > 0)); then
        progress_pct=$((done_count * 100 / total_count))
    else
        progress_pct=0
    fi

    if [[ "${PARALLEL_PROGRESS_SHOW_ETA:-true}" == "true" ]] && ((done_count >= 2)) && ((total_count > done_count)) && ((elapsed_batch >= 60)); then
        local avg remaining eta_seconds
        avg=$((elapsed_batch / done_count))
        remaining=$((total_count - done_count))
        eta_seconds=$((avg * remaining))
        eta=$(format_duration "$eta_seconds")
    fi

    if declare -F ui_is_tty >/dev/null 2>&1 && ui_is_tty && declare -F ui_live_progress_update >/dev/null 2>&1; then
        local line
        line=$(printf "Progress: %d/%d (%d%%) | elapsed %s" \
            "$done_count" "$total_count" "$progress_pct" "$(format_duration "$elapsed_batch")")
        if [[ "${PARALLEL_PROGRESS_SHOW_ETA:-true}" == "true" ]]; then
            line="${line} | ETA: ${eta}"
        fi
        if [[ "${PARALLEL_PROGRESS_SHOW_ACTIVE:-true}" == "true" ]] && [[ "$active_fmt" != "none" || "$mode" == "trace" ]]; then
            line="${line} | Active: ${active_fmt}"
        fi
        if [[ "$mode" == "trace" ]]; then
            line="${line} | Done: ${done_fmt}"
        fi
        if [[ "$mode" != "clean" ]] || ((queue_count > 0)); then
            line="${line} | Queue: ${queue_count}"
        fi
        if declare -F ui_live_progress_begin >/dev/null 2>&1; then
            ui_live_progress_begin
        fi
        ui_live_progress_update "$line"
        if ((total_count > 0)) && ((done_count >= total_count)) && declare -F ui_live_progress_end >/dev/null 2>&1; then
            ui_live_progress_end
        fi
    fi
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
    local reason_marker=""
    if [[ -n "${called_fn_dir:-}" ]]; then
        skip_marker="${called_fn_dir}/.skip_${func_name}"
        cache_marker="${called_fn_dir}/.cache_${func_name}"
        status_marker="${called_fn_dir}/.status_${func_name}"
        reason_marker="${called_fn_dir}/.status_reason_${func_name}"
    fi

    local badge=""
    local reason_code=""
    if [[ -n "$cache_marker" && -f "$cache_marker" ]]; then
        badge="CACHE"
        reason_code="cache"
        rm -f "$cache_marker" 2>/dev/null || true
    elif [[ -n "$skip_marker" && -f "$skip_marker" ]]; then
        badge="SKIP"
        reason_code="config"
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

    if [[ -z "$badge" ]]; then
        if [[ "$rc" -eq 0 ]]; then
            badge="OK"
        else
            badge="FAIL"
        fi
    fi
    if [[ -n "$reason_marker" && -f "$reason_marker" ]]; then
        reason_code=$(head -n 1 "$reason_marker" 2>/dev/null | tr -d '\r\n' | tr '[:upper:]' '[:lower:]')
        rm -f "$reason_marker" 2>/dev/null || true
    fi
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
            if [[ -n "$reason_code" ]] && { [[ "$badge" == "SKIP" ]] || { [[ "$badge" == "CACHE" ]] && [[ "${SHOW_CACHE:-false}" == "true" ]]; }; }; then
                printf "         reason: %s\n" "$reason_code"
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
                tail -n "$show_lines" "$log_file" | strip_ansi_stream
            fi
            if [[ -n "$reason_code" ]] && { [[ "$badge" == "SKIP" ]] || { [[ "$badge" == "CACHE" ]] && [[ "${SHOW_CACHE:-false}" == "true" ]]; }; }; then
                printf "         reason: %s\n" "$reason_code"
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
                cat "$log_file" | strip_ansi_stream
            fi
            if [[ -n "$reason_code" ]] && { [[ "$badge" == "SKIP" ]] || { [[ "$badge" == "CACHE" ]] && [[ "${SHOW_CACHE:-false}" == "true" ]]; }; }; then
                printf "         reason: %s\n" "$reason_code"
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
    local completed="${7:-0}"
    local total="${8:-0}"
    local batch_end
    batch_end=$(date +%s)
    local elapsed=$((batch_end - batch_start))

    # Skip in quiet mode
    [[ "${OUTPUT_VERBOSITY:-1}" -eq 0 ]] && return 0
    # Skip batch envelope in summary mode at normal verbosity
    [[ "${PARALLEL_LOG_MODE:-summary}" == "summary" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -lt 2 ]] && return 0

    if declare -F ui_batch_end >/dev/null 2>&1; then
        ui_batch_end "$ok" "$warn" "$fail" "$elapsed" "$skip" "$cache" "$completed" "$total"
    else
        printf "  --- batch: ok:%d warn:%d fail:%d skip:%d cache:%d, %d/%d completed, %ds elapsed ---\n" \
            "$ok" "$warn" "$fail" "$skip" "$cache" "$completed" "$total" "$elapsed"
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
                if [[ "$(_parallel_get_ui_mode)" != "clean" ]] && { [[ "${PARALLEL_LOG_MODE:-summary}" != "summary" ]] || [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; }; then
                    ui_batch_start "$batch_label" "$max_jobs"
                fi
            fi
        fi

        local log_file="${parallel_log_root}/${func}.$$.$RANDOM.log"
        local job_start_ts
        job_start_ts=$(date +%s)

        # Run function in background subshell; write end timestamp after completion
        (
            local _rc=0
            "$func" || _rc=$?
            date +%s >"${log_file%.log}.endts"
            exit "$_rc"
        ) >"$log_file" 2>&1 &
        batch_pids+=("$!")
        batch_funcs+=("$func")
        batch_logs+=("$log_file")
        batch_starts+=("$job_start_ts")
        queued_count=$((queued_count + 1))

        # Log if verbose (OUTPUT_VERBOSITY >= 2)
        if _parallel_should_show_started; then
            _parallel_live_break
            printf "%b[*] Started %s (PID: %d)%b\n" "${cyan:-}" "$func" "${batch_pids[${#batch_pids[@]}-1]}" "${reset:-}"
        fi

        # If we've reached max jobs, flush the current batch.
        if ((${#batch_pids[@]} >= max_jobs)); then
            if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
                local active_list=""
                local i
                for i in "${batch_funcs[@]}"; do
                    if [[ -z "$active_list" ]]; then
                        active_list="${i} 00:00"
                    else
                        active_list="${active_list}, ${i} 00:00"
                    fi
                done
                local queue_count=$((total_funcs - queued_count))
                _parallel_snapshot "$active_list" "$done_list" "$queue_count" "0" "${#batch_pids[@]}" "0"
            fi

            # Heartbeat while long-running jobs are executing, to avoid "stuck" perception.
            local hb="${PARALLEL_HEARTBEAT_SECONDS:-20}"
            if [[ "${PARALLEL_MODE:-true}" == "true" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]] && [[ "$hb" =~ ^[0-9]+$ ]] && ((hb > 0)); then
                local last_hb now alive hb_active_list job_dur dur_fmt queue_count batch_elapsed hb_done_count
                last_hb=$(date +%s)
                while :; do
                    alive=0
                    hb_done_count=0
                    hb_active_list=""
                    now=$(date +%s)
                    for idx in "${!batch_pids[@]}"; do
                        if kill -0 "${batch_pids[$idx]}" 2>/dev/null; then
                            alive=1
                            job_dur=$((now - batch_starts[$idx]))
                            dur_fmt=$(format_duration "$job_dur")
                            if [[ -z "$hb_active_list" ]]; then
                                hb_active_list="${batch_funcs[$idx]} ${dur_fmt}"
                            else
                                hb_active_list="${hb_active_list}, ${batch_funcs[$idx]} ${dur_fmt}"
                            fi
                        else
                            hb_done_count=$((hb_done_count + 1))
                        fi
                    done
                    ((alive == 0)) && break
                    if ((now - last_hb >= hb)); then
                        queue_count=$((total_funcs - queued_count))
                        batch_elapsed=$((now - batch_start_ts))
                        _parallel_snapshot "${hb_active_list:-none}" "$done_list" "$queue_count" "$hb_done_count" "${#batch_pids[@]}" "$batch_elapsed"
                        last_hb=$now
                    fi
                    sleep 1
                done
            fi

            local idx rc
            local batch_ok=0 batch_warn=0 batch_fail=0 batch_skip=0 batch_cache=0
            for idx in "${!batch_pids[@]}"; do
                if wait "${batch_pids[$idx]}" 2>/dev/null; then
                    rc=0
                else
                    rc=$?
                fi
                local job_end_ts endts_file
                endts_file="${batch_logs[$idx]%.log}.endts"
                if [[ -f "$endts_file" ]]; then
                    job_end_ts=$(< "$endts_file")
                    rm -f "$endts_file" 2>/dev/null || true
                else
                    job_end_ts=$(date +%s)
                fi
                _parallel_emit_job_output "${batch_funcs[$idx]}" "${batch_logs[$idx]}" "$rc" "${batch_starts[$idx]}" "$job_end_ts"
                case "${_PARALLEL_LAST_BADGE:-OK}" in
                    OK) ((batch_ok++)) || true ;;
                    WARN) ((batch_warn++)) || true ;;
                    FAIL) ((batch_fail++)) || true; ((failed++)) || true ;;
                    SKIP) ((batch_skip++)) || true ;;
                    CACHE) ((batch_cache++)) || true ;;
                    *) ((batch_ok++)) || true ;;
                esac
                local job_dur=$((job_end_ts - batch_starts[$idx]))
                local dur_fmt
                dur_fmt=$(format_duration "$job_dur")
                if [[ -z "$done_list" ]]; then
                    done_list="${batch_funcs[$idx]} ${dur_fmt}"
                else
                    done_list="${done_list}, ${batch_funcs[$idx]} ${dur_fmt}"
                fi
                if _parallel_should_show_finished "$rc" "$job_dur" "${_PARALLEL_LAST_BADGE:-OK}"; then
                    _parallel_live_break
                    printf "%b[*] Finished %s (PID: %s, rc=%s)%b\n" "${cyan:-}" "${batch_funcs[$idx]}" "${batch_pids[$idx]}" "$rc" "${reset:-}"
                fi
                rm -f "${batch_logs[$idx]}" 2>/dev/null || true
            done
            _parallel_batch_summary "$batch_ok" "$batch_warn" "$batch_fail" "$batch_skip" "$batch_cache" "$batch_start_ts" "${#batch_pids[@]}" "${#batch_pids[@]}"
            if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
                local queue_count=$((total_funcs - queued_count))
                local now_ts
                now_ts=$(date +%s)
                _parallel_snapshot "none" "$done_list" "$queue_count" "${#batch_pids[@]}" "${#batch_pids[@]}" "$((now_ts - batch_start_ts))"
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
                if [[ -z "$active_list" ]]; then
                    active_list="${i} 00:00"
                else
                    active_list="${active_list}, ${i} 00:00"
                fi
            done
            local queue_count=$((total_funcs - queued_count))
            _parallel_snapshot "$active_list" "$done_list" "$queue_count" "0" "${#batch_pids[@]}" "0"
        fi

        local hb="${PARALLEL_HEARTBEAT_SECONDS:-20}"
        if [[ "${PARALLEL_MODE:-true}" == "true" ]] && [[ "${OUTPUT_VERBOSITY:-1}" -ge 1 ]] && [[ "$hb" =~ ^[0-9]+$ ]] && ((hb > 0)); then
            local last_hb now alive hb_active_list job_dur dur_fmt queue_count batch_elapsed hb_done_count
            last_hb=$(date +%s)
            while :; do
                alive=0
                hb_done_count=0
                hb_active_list=""
                now=$(date +%s)
                for idx in "${!batch_pids[@]}"; do
                    if kill -0 "${batch_pids[$idx]}" 2>/dev/null; then
                        alive=1
                        job_dur=$((now - batch_starts[$idx]))
                        dur_fmt=$(format_duration "$job_dur")
                        if [[ -z "$hb_active_list" ]]; then
                            hb_active_list="${batch_funcs[$idx]} ${dur_fmt}"
                        else
                            hb_active_list="${hb_active_list}, ${batch_funcs[$idx]} ${dur_fmt}"
                        fi
                    else
                        hb_done_count=$((hb_done_count + 1))
                    fi
                done
                ((alive == 0)) && break
                if ((now - last_hb >= hb)); then
                    queue_count=$((total_funcs - queued_count))
                    batch_elapsed=$((now - batch_start_ts))
                    _parallel_snapshot "${hb_active_list:-none}" "$done_list" "$queue_count" "$hb_done_count" "${#batch_pids[@]}" "$batch_elapsed"
                    last_hb=$now
                fi
                sleep 1
            done
        fi

        local idx rc
        local batch_ok=0 batch_warn=0 batch_fail=0 batch_skip=0 batch_cache=0
        for idx in "${!batch_pids[@]}"; do
            if wait "${batch_pids[$idx]}" 2>/dev/null; then
                rc=0
            else
                rc=$?
            fi
            local job_end_ts endts_file
            endts_file="${batch_logs[$idx]%.log}.endts"
            if [[ -f "$endts_file" ]]; then
                job_end_ts=$(< "$endts_file")
                rm -f "$endts_file" 2>/dev/null || true
            else
                job_end_ts=$(date +%s)
            fi
            _parallel_emit_job_output "${batch_funcs[$idx]}" "${batch_logs[$idx]}" "$rc" "${batch_starts[$idx]}" "$job_end_ts"
            case "${_PARALLEL_LAST_BADGE:-OK}" in
                OK) ((batch_ok++)) || true ;;
                WARN) ((batch_warn++)) || true ;;
                FAIL) ((batch_fail++)) || true; ((failed++)) || true ;;
                SKIP) ((batch_skip++)) || true ;;
                CACHE) ((batch_cache++)) || true ;;
                *) ((batch_ok++)) || true ;;
            esac
            local job_dur=$((job_end_ts - batch_starts[$idx]))
            local dur_fmt
            dur_fmt=$(format_duration "$job_dur")
            if [[ -z "$done_list" ]]; then
                done_list="${batch_funcs[$idx]} ${dur_fmt}"
            else
                done_list="${done_list}, ${batch_funcs[$idx]} ${dur_fmt}"
            fi
            if _parallel_should_show_finished "$rc" "$job_dur" "${_PARALLEL_LAST_BADGE:-OK}"; then
                _parallel_live_break
                printf "%b[*] Finished %s (PID: %s, rc=%s)%b\n" "${cyan:-}" "${batch_funcs[$idx]}" "${batch_pids[$idx]}" "$rc" "${reset:-}"
            fi
            rm -f "${batch_logs[$idx]}" 2>/dev/null || true
        done
        _parallel_batch_summary "$batch_ok" "$batch_warn" "$batch_fail" "$batch_skip" "$batch_cache" "$batch_start_ts" "${#batch_pids[@]}" "${#batch_pids[@]}"
        if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
            local now_ts
            now_ts=$(date +%s)
            _parallel_snapshot "none" "$done_list" "0" "${#batch_pids[@]}" "${#batch_pids[@]}" "$((now_ts - batch_start_ts))"
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

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Running passive enumeration in parallel (%d functions)%b\n" \
            "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    fi

    parallel_funcs "${PAR_SUB_PASSIVE_GROUP_SIZE:-2}" "${funcs[@]}"
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

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Running active enumeration in parallel (%d functions)%b\n" \
            "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    fi

    parallel_funcs "${PAR_SUB_DEP_ACTIVE_GROUP_SIZE:-3}" "${funcs[@]}"
}

# Run post-active subdomain enumeration in parallel
# Usage: parallel_postactive_enum
# Runs: sub_tls, sub_analytics (require resolved subdomains from sub_active)
parallel_postactive_enum() {
    local funcs=(
        "sub_tls"
        "sub_analytics"
    )

    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Running post-active enumeration in parallel (%d functions)%b\n" \
            "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    fi

    parallel_funcs "${PAR_SUB_POST_ACTIVE_GROUP_SIZE:-2}" "${funcs[@]}"
}

# Run brute force enumeration sequentially (resource usage and shared artifacts)
# Usage: parallel_brute_enum
parallel_brute_enum() {
    local funcs=(
        "sub_brute"
        "sub_permut"
        "sub_regex_permut"
        "sub_ia_permut"
    )

    # Kept for compatibility with existing helper-based orchestrators.
    # Brute force/permutation stages should not run concurrently.
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Running brute force enumeration sequentially%b\n" \
            "${bblue:-}" "${reset:-}"
    fi

    local func rc failed=0
    for func in "${funcs[@]}"; do
        if ! declare -f "$func" >/dev/null 2>&1; then
            print_warnf "Function %s not found, skipping" "$func"
            continue
        fi

        "$func"
        rc=$?
        if ((rc > 0)); then
            if [[ "${CONTINUE_ON_TOOL_ERROR:-true}" == "true" ]]; then
                print_warnf "Brute phase function %s failed (rc=%d); continuing" "$func" "$rc"
                ((failed++)) || true
            else
                print_errorf "Brute phase function %s failed (rc=%d)" "$func" "$rc"
                return 1
            fi
        fi
    done

    return "$failed"
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
    
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Running web vulnerability checks in parallel (%d checks)%b\n" \
            "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    fi

    parallel_funcs "${PAR_VULNS_GROUP1_SIZE:-4}" "${funcs[@]}"
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
    
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Running injection vulnerability checks in parallel (%d checks)%b\n" \
            "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    fi

    parallel_funcs "${PAR_VULNS_GROUP2_SIZE:-4}" "${funcs[@]}"
}

# Run server-side vulnerability checks in parallel
# Usage: parallel_server_vulns
parallel_server_vulns() {
    local funcs=(
        "crlf_checks"
        "xss"
        "ssrf_checks"
        "lfi"
    )
    
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Running server-side vulnerability checks in parallel (%d checks)%b\n" \
            "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    fi

    parallel_funcs "${PAR_VULNS_GROUP1_SIZE:-4}" "${funcs[@]}"
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
    
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Running OSINT gathering in parallel (%d sources)%b\n" \
            "${bblue:-}" "${#funcs[@]}" "${reset:-}"
    fi

    parallel_funcs "${PAR_OSINT_GROUP1_SIZE:-4}" "${funcs[@]}"
}

###############################################################################
# Full Pipeline Parallelization
###############################################################################

# Orchestrate full subdomain enumeration with parallelization
# Usage: parallel_subdomains_full
# This replaces the sequential execution in subdomains_full()
parallel_subdomains_full() {
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Starting parallelized subdomain enumeration%b\n" \
            "${bblue:-}" "${reset:-}"
    fi
    
    # Phase 1: Passive enumeration (parallel - no dependencies)
    parallel_passive_enum
    
    # Merge passive results before active phase
    if [[ -s ".tmp/passive_subs.txt" ]]; then
        cat .tmp/passive_subs.txt | anew -q subdomains/subdomains.txt
    fi
    if [[ -s ".tmp/crtsh_subs.txt" ]]; then
        cat .tmp/crtsh_subs.txt | anew -q subdomains/subdomains.txt
    fi
    
    # Phase 2: Active enumeration (parallel - resolves subdomains)
    parallel_active_enum
    
    # Phase 3: Post-active (parallel - requires resolved subdomains)
    parallel_postactive_enum
    
    # Phase 4: Brute force (sequential due to resource usage and shared files)
    if [[ ${SUBBRUTE:-false} == true ]] || [[ ${SUBPERMUTE:-false} == true ]]; then
        parallel_brute_enum
    fi
    
    # Phase 5: Scraping and recursive (sequential - depends on previous results)
    if [[ ${SUBSCRAPING:-false} == true ]]; then
        sub_scraping
    fi
    if [[ ${SUB_RECURSIVE_BRUTE:-false} == true ]]; then
        sub_recursive_brute
    fi
    
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Parallelized subdomain enumeration complete%b\n" \
            "${bgreen:-}" "${reset:-}"
    fi
}

# Orchestrate full vulnerability scanning with parallelization
# Usage: parallel_vulns_full
parallel_vulns_full() {
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Starting parallelized vulnerability scanning%b\n" \
            "${bblue:-}" "${reset:-}"
    fi
    
    # Run nuclei first (it's comprehensive)
    nuclei_check
    
    # Then run other checks in parallel batches
    parallel_web_vulns
    parallel_injection_vulns
    parallel_server_vulns
    
    if [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]]; then
        printf "%b[*] Parallelized vulnerability scanning complete%b\n" \
            "${bgreen:-}" "${reset:-}"
    fi
}
