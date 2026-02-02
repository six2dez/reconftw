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
                notification "Resolvers seem older than 1 day\n Generating custom resolvers..." warn
                rm -f -- "$resolvers" 2>>"$LOGFILE"
                dnsvalidator -tL https://public-dns.info/nameservers.txt -threads $DNSVALIDATOR_THREADS -o $resolvers 2>>"$LOGFILE" >/dev/null
                dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads $DNSVALIDATOR_THREADS -o tmp_resolvers 2>>"$LOGFILE" >/dev/null
                [ -s "tmp_resolvers" ] && cat tmp_resolvers | anew -q $resolvers
                [ -s "tmp_resolvers" ] && rm -f tmp_resolvers 2>>"$LOGFILE" >/dev/null
                [ ! -s "$resolvers" ] && wget -q -O - ${resolvers_url} >$resolvers
                [ ! -s "$resolvers_trusted" ] && wget -q -O - ${resolvers_trusted_url} >$resolvers_trusted
                notification "Updated\n" good
            fi
        else
            notification "Checking resolvers lists...\n Accurate resolvers are the key to great results\n This may take around 10 minutes if it's not updated" warn
            axiom-exec "([[ \$(find \"${AXIOM_RESOLVERS_PATH}\" -mtime +1 -print) ]] || [[ \$(wc -l < \"${AXIOM_RESOLVERS_PATH}\") -le 40 ]]) && dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o ${AXIOM_RESOLVERS_PATH}" &>/dev/null
            axiom-exec "wget -q -O - ${resolvers_url} > ${AXIOM_RESOLVERS_PATH}" 2>>"$LOGFILE" >/dev/null
            axiom-exec "wget -q -O - ${resolvers_trusted_url} > ${AXIOM_RESOLVERS_TRUSTED_PATH}" 2>>"$LOGFILE" >/dev/null
            notification "Updated\n" good
        fi
        generate_resolvers=false
    else

        if [[ ! -s $resolvers ]] || [[ $(find "$resolvers" -mtime +1 -print) ]]; then
            notification "Resolvers seem older than 1 day\n Downloading new resolvers..." warn
            cached_download "${resolvers_url}" "$resolvers" "resolvers.txt"
            cached_download "${resolvers_trusted_url}" "$resolvers_trusted" "resolvers_trusted.txt"
            notification "Resolvers updated\n" good
        fi
    fi

}

function resolvers_update_quick_local() {
    if [[ $update_resolvers == true ]]; then
        cached_download "${resolvers_url}" "$resolvers" "resolvers.txt"
        cached_download "${resolvers_trusted_url}" "$resolvers_trusted" "resolvers_trusted.txt"
    fi
}

function resolvers_update_quick_axiom() {
    axiom-exec "wget -q -O - ${resolvers_url} > ${AXIOM_RESOLVERS_PATH}" 2>>"$LOGFILE" >/dev/null
    axiom-exec "wget -q -O - ${resolvers_trusted_url} > ${AXIOM_RESOLVERS_TRUSTED_PATH}" 2>>"$LOGFILE" >/dev/null
}

function resolvers_optimize_local() {
    # Experimental: dedupe resolvers; prefer faster ones if dnsx available
    sort -u "$resolvers" -o "$resolvers" 2>/dev/null || true
    sort -u "$resolvers_trusted" -o "$resolvers_trusted" 2>/dev/null || true
}

function ipcidr_target() {
    IP_CIDR_REGEX='(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?))(\/([8-9]|[1-2][0-9]|3[0-2]))([^0-9.]|$)|(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$)'
    if [[ $1 =~ ^$IP_CIDR_REGEX ]]; then
        echo $1 | mapcidr -silent | anew -q target_reconftw_ipcidr.txt
        if [[ -s "./target_reconftw_ipcidr.txt" ]]; then
            [ "$REVERSE_IP" = true ] && cat ./target_reconftw_ipcidr.txt | hakip2host | cut -d' ' -f 3 | unfurl -u domains 2>/dev/null | sed -e 's/*\.//' -e 's/\.$//' -e '/\./!d' | anew -q ./target_reconftw_ipcidr.txt
            if [[ $(cat ./target_reconftw_ipcidr.txt | wc -l) -eq 1 ]]; then
                domain=$(cat ./target_reconftw_ipcidr.txt)
            elif [[ $(cat ./target_reconftw_ipcidr.txt | wc -l) -gt 1 ]]; then
                unset domain
                list=${PWD}/target_reconftw_ipcidr.txt
            fi
        fi
        if [[ -n $2 ]]; then
            cat $list | anew -q $2
            sed_i '/\/[0-9]*$/d' $2
        fi
    fi
}

function axiom_launch() {
    # let's fire up a FLEET!
    if [[ $AXIOM_FLEET_LAUNCH == true ]] && [[ -n $AXIOM_FLEET_NAME ]] && [[ -n $AXIOM_FLEET_COUNT ]]; then
        start_func ${FUNCNAME[0]} "Launching our Axiom fleet"

        # Check to see if we have a fleet already, if so, SKIP THIS!
        NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME" || true)
        if [[ $NUMOFNODES -ge $AXIOM_FLEET_COUNT ]]; then
            axiom-select "$AXIOM_FLEET_NAME*"
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
            printf 'axiom-fleet %q' "${AXIOM_FLEET_NAME}"
            printf ' %q' "${AXIOM_FLEET_ARGS[@]}"
            echo
            axiom-fleet "${AXIOM_FLEET_NAME}" "${AXIOM_FLEET_ARGS[@]}"
            axiom-select "$AXIOM_FLEET_NAME*"
            if [[ -n $AXIOM_POST_START ]]; then
                bash -lc "$AXIOM_POST_START" 2>>"$LOGFILE" >/dev/null
            fi

            NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME" || true)
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
        axiom-rm -f "$AXIOM_FLEET_NAME*" || true
        axiom-ls | grep "$AXIOM_FLEET_NAME" || true
        notification "Axiom fleet $AXIOM_FLEET_NAME shutdown" info
    fi
}

function axiom_selected() {

    if [[ ! $(axiom-ls | tail -n +2 | sed '$ d' | wc -l) -gt 0 ]]; then
        notification "No axiom instances running ${reset}\n\n" error
        exit
    fi

    if [[ ! $(cat ~/.axiom/selected.conf | sed '/^\s*$/d' | wc -l) -gt 0 ]]; then
        notification "No axiom instances selected ${reset}\n\n" error
        exit
    fi
}
