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

    if [[ $generate_resolvers == true ]]; then
        if [[ $AXIOM != true ]]; then
            if [[ ! -s $resolvers ]] || [[ $(find "$resolvers" -mtime +1 -print) ]]; then
                _print_msg WARN "Resolvers seem older than 1 day. Generating custom resolvers..."
                {
                    rm -f -- "$resolvers"
                    run_command dnsvalidator -tL https://public-dns.info/nameservers.txt -threads "$DNSVALIDATOR_THREADS" -o "$resolvers" >/dev/null
                    run_command dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads "$DNSVALIDATOR_THREADS" -o tmp_resolvers >/dev/null
                } 2>>"$LOGFILE"
                [ -s "tmp_resolvers" ] && cat tmp_resolvers | anew -q "$resolvers"
                [ -s "tmp_resolvers" ] && rm -f tmp_resolvers 2>>"$LOGFILE" >/dev/null
                [ ! -s "$resolvers" ] && run_command wget -q -O - "${resolvers_url}" >"$resolvers"
                [ ! -s "$resolvers_trusted" ] && run_command wget -q -O - "${resolvers_trusted_url}" >"$resolvers_trusted"
                _print_msg OK "Updated resolvers"
            fi
        else
            _print_msg WARN "Checking resolvers lists. Accurate resolvers are key to good results. This may take around 10 minutes if outdated."
            run_command axiom-exec "([[ \$(find \"${AXIOM_RESOLVERS_PATH}\" -mtime +1 -print) ]] || [[ \$(wc -l < \"${AXIOM_RESOLVERS_PATH}\") -le 40 ]]) && dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o ${AXIOM_RESOLVERS_PATH}" &>/dev/null
            run_command axiom-exec "wget -q -O - ${resolvers_url} > ${AXIOM_RESOLVERS_PATH}" 2>>"$LOGFILE" >/dev/null
            run_command axiom-exec "wget -q -O - ${resolvers_trusted_url} > ${AXIOM_RESOLVERS_TRUSTED_PATH}" 2>>"$LOGFILE" >/dev/null
            _print_msg OK "Updated resolvers"
        fi
        generate_resolvers=false
    else

        if [[ ! -s $resolvers ]] || [[ $(find "$resolvers" -mtime +1 -print) ]]; then
            _print_msg WARN "Resolvers seem older than 1 day. Downloading new resolvers..."
            cached_download_typed "${resolvers_url}" "$resolvers" "resolvers.txt" "resolvers"
            cached_download_typed "${resolvers_trusted_url}" "$resolvers_trusted" "resolvers_trusted.txt" "resolvers"
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
        NUMOFNODES=$(timeout 30 axiom-ls 2>>"$LOGFILE" | grep -c "$AXIOM_FLEET_NAME" || true)
        if [[ $NUMOFNODES -ge $AXIOM_FLEET_COUNT ]]; then
            axiom-select "$AXIOM_FLEET_NAME*" 2>>"$LOGFILE" >/dev/null
            end_func "Axiom fleet $AXIOM_FLEET_NAME already has $NUMOFNODES instances" info
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

            # Show the exact command with proper quoting
            axiom-fleet2 "${AXIOM_FLEET_NAME}" "${AXIOM_FLEET_ARGS[@]}" >/dev/null 2>&1
            axiom-select "$AXIOM_FLEET_NAME*" 2>>"$LOGFILE" >/dev/null
            if [[ -n $AXIOM_POST_START ]]; then
                bash -lc "$AXIOM_POST_START" 2>>"$LOGFILE" >/dev/null
            fi

            NUMOFNODES=$(timeout 30 axiom-ls 2>>"$LOGFILE" | grep -c "$AXIOM_FLEET_NAME" || true)
            end_func "Axiom fleet $AXIOM_FLEET_NAME launched $NUMOFNODES instances" info
        fi
    fi
}

function axiom_shutdown() {
    if [[ $AXIOM_FLEET_LAUNCH == true ]] && [[ $AXIOM_FLEET_SHUTDOWN == true ]] && [[ -n $AXIOM_FLEET_NAME ]]; then
        #if [[ "$mode" == "subs_menu" ]] || [[ "$mode" == "list_recon" ]] || [[ "$mode" == "passive" ]] || [[ "$mode" == "all" ]]; then
        if [[ $mode == "subs_menu" ]] || [[ $mode == "passive" ]] || [[ $mode == "all" ]]; then
            notification "Automatic Axiom fleet shutdown is not enabled in this mode" info
            return
        fi
        axiom-rm -f "$AXIOM_FLEET_NAME*" 2>>"$LOGFILE" >/dev/null || true
        axiom-ls 2>>"$LOGFILE" | grep "$AXIOM_FLEET_NAME" >>"$LOGFILE" || true
        [[ "${OUTPUT_VERBOSITY:-1}" -ge 2 ]] && notification "Axiom fleet $AXIOM_FLEET_NAME shutdown" info
    fi
}

function axiom_selected() {

    if [[ ! $(axiom-ls 2>>"${LOGFILE:-/dev/null}" | tail -n +2 | sed '$ d' | wc -l) -gt 0 ]]; then
        notification "No axiom instances running ${reset}\n\n" error
        exit
    fi

    if [[ ! $(cat ~/.axiom/selected.conf | sed '/^\s*$/d' | wc -l) -gt 0 ]]; then
        notification "No axiom instances selected ${reset}\n\n" error
        exit
    fi

    # Probe Axiom connectivity and optionally auto-repair host-key mismatches.
    local axiom_probe_out
    axiom_probe_out="$(axiom-exec "echo reconftw-axiom-probe" 2>&1 || true)"
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

            axiom_probe_out="$(axiom-exec "echo reconftw-axiom-probe" 2>&1 || true)"
            if echo "$axiom_probe_out" | grep -q "REMOTE HOST IDENTIFICATION HAS CHANGED"; then
                notification "Axiom host-key mismatch persists after auto-repair; disabling AXIOM for this run and continuing locally" warn
                echo "$axiom_probe_out" >>"${LOGFILE:-/dev/null}"
                AXIOM=false
            else
                notification "Axiom known_hosts auto-repair completed successfully" good
            fi
        else
            notification "Axiom host-key mismatch detected; disabling AXIOM for this run and continuing locally" warn
            AXIOM=false
        fi
    fi
}
