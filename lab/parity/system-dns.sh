#!/usr/bin/env bash
# lab/parity/system-dns.sh — point the OS resolver at the lab DNS for lab.test only.
#
# The recon engines hand puredns/dnsx the lab resolvers file, but the WEB tools
# (httpx, nuclei, katana, ffuf, tlsx…) resolve through the operating system. This
# script makes *.lab.test resolve via 127.0.0.1:53 (the CoreDNS container) and
# touches nothing else. Needs root; both directions are idempotent.
#
#   sudo lab/parity/system-dns.sh install
#   sudo lab/parity/system-dns.sh remove
#   lab/parity/system-dns.sh check        # no root: does www.lab.test resolve?
#
# Linux (systemd-resolved): resolved refuses per-link DNS on `lo`, so a dummy
#   interface `reconlab0` is created and lab.test is routed to it (~lab.test).
# macOS: /etc/resolver/lab.test with `nameserver 127.0.0.1` (per-domain resolver).
set -uo pipefail

ZONE="lab.test"
IFACE="reconlab0"

die() {
    printf 'system-dns: %s\n' "$1" >&2
    exit 2
}

check() {
    if command -v getent >/dev/null 2>&1 && getent hosts "www.$ZONE" >/dev/null 2>&1; then
        echo "ok: www.$ZONE resolves (getent)"
        return 0
    fi
    if command -v dscacheutil >/dev/null 2>&1 && dscacheutil -q host -a name "www.$ZONE" 2>/dev/null | grep -q ip_address; then
        echo "ok: www.$ZONE resolves (dscacheutil)"
        return 0
    fi
    echo "NOT resolving: www.$ZONE"
    return 1
}

linux_install() {
    command -v resolvectl >/dev/null 2>&1 || die "resolvectl not found — add '127.0.0.1' for $ZONE to your resolver by hand"
    if ! ip link show "$IFACE" >/dev/null 2>&1; then
        ip link add "$IFACE" type dummy || die "cannot create dummy interface $IFACE"
    fi
    ip link set "$IFACE" up || die "cannot bring $IFACE up"
    resolvectl dns "$IFACE" 127.0.0.1 || die "resolvectl dns failed"
    resolvectl domain "$IFACE" "~$ZONE" || die "resolvectl domain failed"
    resolvectl flush-caches 2>/dev/null || true
    echo "installed: $ZONE -> 127.0.0.1 via $IFACE (systemd-resolved routing domain)"
}

linux_remove() {
    if ip link show "$IFACE" >/dev/null 2>&1; then
        ip link delete "$IFACE" || die "cannot delete $IFACE"
    fi
    command -v resolvectl >/dev/null 2>&1 && resolvectl flush-caches 2>/dev/null
    echo "removed: $IFACE"
}

macos_install() {
    mkdir -p /etc/resolver || die "cannot create /etc/resolver"
    printf 'nameserver 127.0.0.1\nport 53\n' >"/etc/resolver/$ZONE" || die "cannot write /etc/resolver/$ZONE"
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
    echo "installed: /etc/resolver/$ZONE -> 127.0.0.1"
}

macos_remove() {
    rm -f "/etc/resolver/$ZONE"
    dscacheutil -flushcache 2>/dev/null || true
    killall -HUP mDNSResponder 2>/dev/null || true
    echo "removed: /etc/resolver/$ZONE"
}

action="${1:-}"
case "$action" in
    check) check ;;
    install | remove)
        [ "$(id -u)" -eq 0 ] || die "$action needs root (sudo)"
        case "$(uname -s)" in
            Linux) "linux_$action" ;;
            Darwin) "macos_$action" ;;
            *) die "unsupported OS $(uname -s)" ;;
        esac
        ;;
    *)
        sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
