#!/bin/bash
# reconFTW - Axiom/resolver module
# Contains: resolvers_update, resolvers_update_quick_local,
#           resolvers_update_quick_axiom, resolvers_optimize_local,
#           ipcidr_target, axiom_launch, axiom_shutdown, axiom_selected
# This file is sourced by reconftw.sh - do not execute directly

# shellcheck disable=SC2154  # Variables defined in reconftw.cfg
# shellcheck disable=SC2034  # Variables exported for use in other modules

[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by reconftw.sh" >&2
    exit 1
}

function resolvers_update() {
    local need_refresh=false
    local resolvers_stale=false
    local resolvers_trusted_stale=false

    if [[ -s "$resolvers" ]] && [[ -n "$(find "$resolvers" -mtime +1 -print 2>/dev/null)" ]]; then
        resolvers_stale=true
    fi
    if [[ -s "$resolvers_trusted" ]] && [[ -n "$(find "$resolvers_trusted" -mtime +1 -print 2>/dev/null)" ]]; then
        resolvers_trusted_stale=true
    fi
    if [[ ! -s "$resolvers" ]] || [[ ! -s "$resolvers_trusted" ]] || [[ "$resolvers_stale" == true ]] || [[ "$resolvers_trusted_stale" == true ]]; then
        need_refresh=true
    fi

    if [[ $generate_resolvers == true ]]; then
        if [[ $AXIOM != true ]]; then
            if [[ "$need_refresh" == true ]]; then
                _print_msg WARN "Resolvers seem older than 1 day. Generating custom resolvers..."
                {
                    rm -f -- "$resolvers"
                    run_command dnsvalidator -tL https://public-dns.info/nameservers.txt -threads "$DNSVALIDATOR_THREADS" -o "$resolvers" >/dev/null || return 1
                    run_command dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads "$DNSVALIDATOR_THREADS" -o tmp_resolvers >/dev/null
                } 2>>"$LOGFILE"
                [ -s "tmp_resolvers" ] && cat tmp_resolvers | anew -q "$resolvers"
                [ -s "tmp_resolvers" ] && rm -f tmp_resolvers 2>>"$LOGFILE" >/dev/null
                if [[ ! -s "$resolvers" ]] && ! run_command wget -q -O - "${resolvers_url}" >"$resolvers"; then
                    _print_msg WARN "Unable to download resolvers from ${resolvers_url}"
                    return 1
                fi
                if [[ ! -s "$resolvers_trusted" ]] && ! run_command wget -q -O - "${resolvers_trusted_url}" >"$resolvers_trusted"; then
                    _print_msg WARN "Unable to download trusted resolvers from ${resolvers_trusted_url}"
                    return 1
                fi
                if [[ ! -s "$resolvers" ]] || [[ ! -s "$resolvers_trusted" ]]; then
                    _print_msg WARN "Resolver files are missing or empty after update"
                    return 1
                fi
                _print_msg OK "Updated resolvers"
            fi
        else
            _print_msg WARN "Checking resolvers lists. Accurate resolvers are key to good results. This may take around 10 minutes if outdated."
            run_command axiom-exec "([[ \$(find \"${AXIOM_RESOLVERS_PATH}\" -mtime +1 -print) ]] || [[ \$(wc -l < \"${AXIOM_RESOLVERS_PATH}\") -le 40 ]]) && dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o ${AXIOM_RESOLVERS_PATH}" &>/dev/null || return 1
            run_command axiom-exec "wget -q -O - ${resolvers_url} > ${AXIOM_RESOLVERS_PATH}" 2>>"$LOGFILE" >/dev/null || return 1
            run_command axiom-exec "wget -q -O - ${resolvers_trusted_url} > ${AXIOM_RESOLVERS_TRUSTED_PATH}" 2>>"$LOGFILE" >/dev/null || return 1
            _print_msg OK "Updated resolvers"
        fi
        generate_resolvers=false
    else

        if [[ "$need_refresh" == true ]]; then
            _print_msg WARN "Resolvers seem older than 1 day. Downloading new resolvers..."
            cached_download_typed "${resolvers_url}" "$resolvers" "resolvers.txt" "resolvers" || return 1
            cached_download_typed "${resolvers_trusted_url}" "$resolvers_trusted" "resolvers_trusted.txt" "resolvers" || return 1
            if [[ ! -s "$resolvers" ]] || [[ ! -s "$resolvers_trusted" ]]; then
                _print_msg WARN "Resolver files are missing or empty after update"
                return 1
            fi
            _print_msg OK "Resolvers updated"
        fi
    fi

}

function resolvers_update_quick_local() {
    if [[ $update_resolvers == true ]]; then
        cached_download_typed "${resolvers_url}" "$resolvers" "resolvers.txt" "resolvers"
        cached_download_typed "${resolvers_trusted_url}" "$resolvers_trusted" "resolvers_trusted.txt" "resolvers"
    fi
}

function resolvers_update_quick_axiom() {
    run_command axiom-exec "wget -q -O - ${resolvers_url} > ${AXIOM_RESOLVERS_PATH}" 2>>"$LOGFILE" >/dev/null
    run_command axiom-exec "wget -q -O - ${resolvers_trusted_url} > ${AXIOM_RESOLVERS_TRUSTED_PATH}" 2>>"$LOGFILE" >/dev/null
}

function resolvers_optimize_local() {
    # Experimental: dedupe resolvers; prefer faster ones if dnsx available
    sort -u "$resolvers" -o "$resolvers" 2>/dev/null || true
    sort -u "$resolvers_trusted" -o "$resolvers_trusted" 2>/dev/null || true
}

function ipcidr_target() {
    local caller_list="${2:-}"
    local expanded_list="${PWD}/target_reconftw_ipcidr.txt"
    IP_CIDR_REGEX='(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?))(\/([8-9]|[1-2][0-9]|3[0-2]))([^0-9.]|$)|(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$)'
    if [[ $1 =~ ^$IP_CIDR_REGEX ]]; then
        echo "$1" | run_command mapcidr -silent | anew -q "$expanded_list"
        if [[ -s "$expanded_list" ]]; then
            [ "$REVERSE_IP" = true ] && cat "$expanded_list" | run_command hakip2host | cut -d' ' -f 3 | unfurl -u domains 2>/dev/null | sed -e 's/*\.//' -e 's/\.$//' -e '/\./!d' | anew -q "$expanded_list"
            if [[ -z "$caller_list" ]]; then
                if [[ $(wc -l <"$expanded_list") -eq 1 ]]; then
                    domain=$(cat "$expanded_list")
                elif [[ $(wc -l <"$expanded_list") -gt 1 ]]; then
                    unset domain
                    list="$expanded_list"
                fi
            fi
        fi
        if [[ -n "$caller_list" ]]; then
            cat "$expanded_list" | anew -q "$caller_list"
            sed_i '/\/[0-9]*$/d' "$caller_list"
        fi
    fi
}

function axiom_launch() {
    # let's fire up a FLEET!
    if [[ $AXIOM_FLEET_LAUNCH == true ]] && [[ -n $AXIOM_FLEET_NAME ]] && [[ -n $AXIOM_FLEET_COUNT ]]; then
        start_func "${FUNCNAME[0]}" "Launching our Axiom fleet"

        # Check to see if we have a fleet already, if so, SKIP THIS!
        print_notice RUN "axiom_launch" "launching axiom fleet"
        # Count nodes whose name starts with our fleet prefix so we don't
        # mis-count sibling fleets that happen to share this prefix (e.g.
        # "reconftw" vs "reconftw-dev").
        NUMOFNODES=$(timeout 30 axiom-ls 2>>"$LOGFILE" | grep -c "^${AXIOM_FLEET_NAME}" || true)
        if [[ $NUMOFNODES -ge $AXIOM_FLEET_COUNT ]]; then
            if ! axiom-select "$AXIOM_FLEET_NAME*" 2>>"$LOGFILE" >/dev/null; then
                axiom_disable_runtime \
                    "axiom-select failed for existing fleet ${AXIOM_FLEET_NAME}; see ${LOGFILE}" \
                    "axiom-select"
                end_func "Fleet select failed; see ${LOGFILE}" "${FUNCNAME[0]}" error
                return 1
            fi
            end_func "" "${FUNCNAME[0]}"
        else
            if [[ $NUMOFNODES -eq 0 ]]; then
                startcount=$AXIOM_FLEET_COUNT
            else
                startcount=$((AXIOM_FLEET_COUNT - NUMOFNODES))
            fi
            # Build args safely to avoid word-splitting issues
            local -a AXIOM_FLEET_ARGS=(-i "$startcount")
            # Regions intentionally disabled here per original comment
            # To re-enable: [[ -n ${AXIOM_FLEET_REGIONS-} ]] && AXIOM_FLEET_ARGS+=( --regions="${AXIOM_FLEET_REGIONS}" )

            # Route fleet2 output to $LOGFILE so failures (missing provider token,
            # billing issues, quota errors) are visible rather than silently swallowed.
            local fleet_rc=0
            axiom-fleet2 "${AXIOM_FLEET_NAME}" "${AXIOM_FLEET_ARGS[@]}" >>"$LOGFILE" 2>&1 || fleet_rc=$?
            if ! axiom-select "$AXIOM_FLEET_NAME*" 2>>"$LOGFILE" >/dev/null; then
                axiom_disable_runtime \
                    "axiom-select failed after fleet launch (${AXIOM_FLEET_NAME}); see ${LOGFILE}" \
                    "axiom-select"
                end_func "Fleet select failed after launch; see ${LOGFILE}" "${FUNCNAME[0]}" error
                return 1
            fi
            if [[ -n $AXIOM_POST_START ]]; then
                bash -lc "$AXIOM_POST_START" 2>>"$LOGFILE" >/dev/null
            fi

            NUMOFNODES=$(timeout 30 axiom-ls 2>>"$LOGFILE" | grep -c "^${AXIOM_FLEET_NAME}" || true)
            if [[ $fleet_rc -ne 0 ]] || [[ $NUMOFNODES -lt $AXIOM_FLEET_COUNT ]]; then
                axiom_disable_runtime \
                    "fleet launch incomplete (${NUMOFNODES}/${AXIOM_FLEET_COUNT} nodes, rc=${fleet_rc}); see ${LOGFILE}" \
                    "axiom-fleet2"
                end_func "Fleet launch failed; see ${LOGFILE}" "${FUNCNAME[0]}" error
                return 1
            fi
            end_func "" "${FUNCNAME[0]}"
        fi
    fi
}

function axiom_shutdown() {
    if [[ "${AXIOM_RUNTIME_DISABLED:-false}" == "true" ]]; then
        [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && notification "Axiom runtime already disabled; skipping fleet shutdown" info
        return
    fi
    if [[ $AXIOM_FLEET_LAUNCH == true ]] && [[ $AXIOM_FLEET_SHUTDOWN == true ]] && [[ -n $AXIOM_FLEET_NAME ]]; then
        #if [[ "$mode" == "subs_menu" ]] || [[ "$mode" == "list_recon" ]] || [[ "$mode" == "passive" ]] || [[ "$mode" == "all" ]]; then
        if [[ $mode == "subs_menu" ]] || [[ $mode == "passive" ]] || [[ $mode == "all" ]]; then
            notification "Automatic Axiom fleet shutdown is not enabled in this mode" info
            return
        fi
        axiom-rm -f "$AXIOM_FLEET_NAME*" 2>>"$LOGFILE" >/dev/null || true
        axiom-ls 2>>"$LOGFILE" | grep "^${AXIOM_FLEET_NAME}" >>"$LOGFILE" || true
        [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && notification "Axiom fleet $AXIOM_FLEET_NAME shutdown" info
    fi
}

function axiom_selected() {
    start_func "${FUNCNAME[0]}" "Checking Axiom connectivity"

    # Count nodes whose name starts with our fleet prefix. Avoids the fragile
    # `tail -n +2 | sed '$ d'` header/footer stripping which under-counts by one
    # when axiom-ls has no trailing footer line.
    local running_nodes
    running_nodes=$(axiom-ls 2>>"${LOGFILE:-/dev/null}" | grep -c "^${AXIOM_FLEET_NAME}" 2>/dev/null || echo 0)
    if [[ "$running_nodes" -le 0 ]]; then
        end_func "No axiom instances running" "${FUNCNAME[0]}" warn
        axiom_disable_runtime "no axiom instances running" "axiom-ls"
        return 0
    fi

    if [[ ! $(cat ~/.axiom/selected.conf | sed '/^\s*$/d' | wc -l) -gt 0 ]]; then
        end_func "No axiom instances selected" "${FUNCNAME[0]}" warn
        axiom_disable_runtime "no axiom instances selected" "axiom-selected.conf"
        return 0
    fi

    # Probe Axiom connectivity and optionally auto-repair host-key mismatches.
    print_notice RUN "axiom_selected" "checking axiom connectivity"
    local axiom_probe_out axiom_probe_rc
    axiom_probe_out="$(axiom-exec "echo reconftw-axiom-probe" 2>&1)"
    axiom_probe_rc=$?
    if echo "$axiom_probe_out" | grep -q "REMOTE HOST IDENTIFICATION HAS CHANGED"; then
        echo "$axiom_probe_out" >>"${LOGFILE:-/dev/null}"

        if [[ "${AXIOM_AUTO_FIX_HOSTKEY:-true}" == "true" ]]; then
            notification "Axiom host-key mismatch detected; attempting automatic known_hosts repair" warn

            local known_hosts_file
            known_hosts_file="${HOME}/.ssh/known_hosts"
            mkdir -p "${HOME}/.ssh" 2>>"${LOGFILE:-/dev/null}" || true
            touch "$known_hosts_file" 2>>"${LOGFILE:-/dev/null}" || true

            local -a hostports
            mapfile -t hostports < <(printf "%s\n" "$axiom_probe_out" | grep -oE '\[[^]]+\]:[0-9]+' | sort -u)

            local hp host port
            for hp in "${hostports[@]}"; do
                [[ -z "$hp" ]] && continue
                ssh-keygen -f "$known_hosts_file" -R "$hp" >/dev/null 2>>"${LOGFILE:-/dev/null}" || true

                host="${hp%\]:*}"
                host="${host#[}"
                port="${hp##*:}"
                if [[ -n "$host" && -n "$port" ]]; then
                    ssh-keyscan -T 10 -p "$port" "$host" >>"$known_hosts_file" 2>>"${LOGFILE:-/dev/null}" || true
                fi
            done

            axiom_probe_out="$(axiom-exec "echo reconftw-axiom-probe" 2>&1)"
            axiom_probe_rc=$?
            if echo "$axiom_probe_out" | grep -q "REMOTE HOST IDENTIFICATION HAS CHANGED"; then
                echo "$axiom_probe_out" >>"${LOGFILE:-/dev/null}"
                axiom_disable_runtime "host-key mismatch persists after auto-repair" "axiom-exec probe"
            else
                notification "Axiom known_hosts auto-repair completed successfully" good
            fi
        else
            axiom_disable_runtime "host-key mismatch detected" "axiom-exec probe"
        fi
    fi

    if [[ "$axiom_probe_rc" -ne 0 ]] || axiom_transport_error_detected "$axiom_probe_out"; then
        echo "$axiom_probe_out" >>"${LOGFILE:-/dev/null}"
        axiom_disable_runtime "probe connectivity failure" "axiom-exec probe"
    fi

    end_func "" "${FUNCNAME[0]}"
}
