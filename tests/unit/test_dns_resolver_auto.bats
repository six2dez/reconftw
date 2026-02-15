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

@test "_can_use_puredns returns true for public local IP" {
    _is_cloud_vps() { return 1; }
    _get_external_ipv4() { return 1; }
    run _can_use_puredns "8.8.8.8"
    [ "$status" -eq 0 ]
}

@test "_can_use_puredns returns true for private IP on cloud VPS (metadata)" {
    _is_cloud_vps() { return 0; }
    _get_external_ipv4() { return 1; }
    run _can_use_puredns "10.0.0.5"
    [ "$status" -eq 0 ]
}

@test "_can_use_puredns returns true for private IP with external IPv4 reachable" {
    _is_cloud_vps() { return 1; }
    _get_external_ipv4() { echo "203.0.113.50"; return 0; }
    run _can_use_puredns "10.0.0.5"
    [ "$status" -eq 0 ]
}

@test "_can_use_puredns returns false for private IP without cloud or external" {
    _is_cloud_vps() { return 1; }
    _get_external_ipv4() { return 1; }
    run _can_use_puredns "192.168.1.10"
    [ "$status" -ne 0 ]
}

@test "init_dns_resolver caches auto selection (does not re-evaluate on each _select_dns_resolver)" {
    export DNS_RESOLVER="auto"
    _get_local_ip() { echo "192.168.1.10"; }
    _is_cloud_vps() { return 1; }
    _get_external_ipv4() { return 1; }
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
    _is_cloud_vps() { return 1; }
    _get_external_ipv4() { return 1; }

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

