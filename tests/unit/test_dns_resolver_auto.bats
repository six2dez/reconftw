#!/usr/bin/env bats

setup() {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export tools="$HOME/Tools"
    export LOGFILE="/dev/null"
    export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
    export NOTIFICATION=false
    export AXIOM=false

    source "$project_root/reconftw.cfg" 2>/dev/null || true
    export SCRIPTPATH="$project_root"
    source "$project_root/reconftw.sh" --source-only
}

@test "_ip_is_public_ipv4 identifies public and non-public ranges" {
    run _ip_is_public_ipv4 "8.8.8.8"
    [ "$status" -eq 0 ]

    for ip in "192.168.1.10" "10.0.0.1" "172.16.0.1" "100.64.1.1" "127.0.0.1" "169.254.1.1" "0.1.2.3" "224.0.0.1"; do
        run _ip_is_public_ipv4 "$ip"
        [ "$status" -ne 0 ]
    done
}

@test "_is_behind_nat returns true for RFC1918 and CGNAT and false for public IPv4" {
    _get_local_ip() { echo "192.168.1.10"; }
    run _is_behind_nat
    [ "$status" -eq 0 ]

    _get_local_ip() { echo "100.64.10.20"; }
    run _is_behind_nat
    [ "$status" -eq 0 ]

    _get_local_ip() { echo "8.8.8.8"; }
    run _is_behind_nat
    [ "$status" -ne 0 ]
}

@test "init_dns_resolver caches auto selection (does not re-evaluate on each _select_dns_resolver)" {
    export DNS_RESOLVER="auto"
    _get_local_ip() { echo "192.168.1.10"; }
    init_dns_resolver
    [ "$DNS_RESOLVER_SELECTED" = "dnsx" ]

    # If selection were re-evaluated on each call, this would flip to puredns.
    _get_local_ip() { echo "8.8.8.8"; }
    run _select_dns_resolver
    [ "$status" -eq 0 ]
    [ "$output" = "dnsx" ]
}

@test "DNS_RESOLVER override forces puredns/dnsx regardless of network" {
    _get_local_ip() { echo "192.168.1.10"; }

    export DNS_RESOLVER="puredns"
    init_dns_resolver
    [ "$DNS_RESOLVER_SELECTED" = "puredns" ]
    run _select_dns_resolver
    [ "$output" = "puredns" ]

    export DNS_RESOLVER="dnsx"
    init_dns_resolver
    [ "$DNS_RESOLVER_SELECTED" = "dnsx" ]
    run _select_dns_resolver
    [ "$output" = "dnsx" ]
}

