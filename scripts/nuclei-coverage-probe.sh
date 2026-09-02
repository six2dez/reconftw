#!/usr/bin/env bash
# scripts/nuclei-coverage-probe.sh — the differential experiment for plan 17-05.
#
# THE QUESTION. On 2026-08-24 `keycloak-openid-config` and `oidc-detect` did not
# fire in v2's full nuclei run against example.com, and fired INSTANTLY in a
# targeted two-template probe from the same box, against the same host, using the
# same template directory. Four benign explanations were each eliminated by an
# observation (16-06-PARITY.md §6.1): both templates are installed, the endpoint
# returns HTTP 200 carrying every matcher word, the host was line 6 of nuclei's
# 12-line input and nuclei exited success with 37 hits on it, and neither
# template is on any .nuclei-ignore. The parity verdict was signed BLOCKED.
#
# What remained were TWO explanations with OPPOSITE remedies:
#
#   H1-class  the templates NEVER EXECUTED — a coverage hole of unknown size
#   H2-class  they EXECUTED AND DID NOT MATCH, because a 150-rps scan over 12
#             hosts drew a different response (WAF, rate limit, 403/429, or the
#             per-host error budget) than an isolated single-URL probe
#
# v2 could not tell them apart. This script can, because it runs both vectors
# against ONE fixture whose responses are known, and turns on nuclei's request
# TRACE — the only evidence that distinguishes "the request was never sent" from
# "the request was sent and the response differed".
#
# ─────────────────────────────────────────────────────────────────────────────
# WHY THE TRACE IS ON HERE AND OFF IN PRODUCTION
# ─────────────────────────────────────────────────────────────────────────────
# `-tlog` writes one JSON line PER REQUEST. Against 12 hosts over ~13,000
# templates that is millions of lines — a real disk and performance cost, and a
# real disclosure surface (T-17-05-03). Against a handful of loopback hosts it is
# a few thousand lines and there is no third-party header in it at all. So
# per-template answerability lives HERE, on the fixture, and the production
# record (internal/modules/web/nuclei_coverage.go) carries the declared aggregate
# proxy instead. That split is deliberate and it is written down in both places.
#
# ─────────────────────────────────────────────────────────────────────────────
# LOOPBACK ONLY
# ─────────────────────────────────────────────────────────────────────────────
# The fixture binds 127.0.0.1 and every arm targets it. A non-loopback target is
# REFUSED unless --force-nonloopback is passed explicitly, because a probe that
# accidentally points at a real host is unauthorised scanning (T-17-05-04). No
# arm here has ever targeted example.com and none may.
#
# ─────────────────────────────────────────────────────────────────────────────
# THE FIXTURE MAKES BOTH OUTCOMES REACHABLE
# ─────────────────────────────────────────────────────────────────────────────
# A fixture that only ever answers 200 could never produce an H1 result, and a
# report that "found no coverage hole" against such a fixture would be worthless.
# So the fixture serves the OIDC discovery document at both paths
# keycloak-openid-config probes AND the run is given extra target hosts on CLOSED
# loopback ports, so nuclei's per-host error budget can actually be reached.
#
# ─────────────────────────────────────────────────────────────────────────────
# USAGE
# ─────────────────────────────────────────────────────────────────────────────
#   scripts/nuclei-coverage-probe.sh --self-check    prove the harness works
#   scripts/nuclei-coverage-probe.sh --fixture-only  run the matrix on loopback
#   scripts/nuclei-coverage-probe.sh --full-tree     add the ~13k-template
#                                                    directory-mode arm (slow)
#   scripts/nuclei-coverage-probe.sh --cost          price the -nmhe remedy: what
#                                                    disabling the per-host error
#                                                    budget costs in wall clock
#                                                    against an UNRESPONSIVE host
#   scripts/nuclei-coverage-probe.sh --help
#
# EXIT: 0 when the matrix ran (a divergence is a RESULT, not an error).
#       2 on a usage or harness fault. 3 when a required binary is absent —
#       SKIPPED is never PASS.
#
# REQUIREMENTS: bash 3.2+ (no associative arrays, no mapfile), python3 for the
# fixture server, GNU or BSD `timeout`/`gtimeout`. Uses `\cp -f` / `\rm -f`
# throughout so an interactive `cp -i` / `rm -i` alias cannot wedge a
# non-interactive run.
#
# NOTE: no `set -e`. A non-zero rc from an arm is the measurement.
set -uo pipefail

SELF_CHECK=0
FIXTURE_ONLY=0
FULL_TREE=0
COST_ONLY=0
FORCE_NONLOOPBACK=0
TARGET=""
TEMPLATES_DIR="${HOME}/nuclei-templates"
SEVERITY="info,low,medium,high,critical"
RATE_LIMIT=150
ARM_BOUND=900

TMPROOT=""
SRV_PID=""
SRV_PORT=""
TIMEOUT_BIN=""
TPL_ISO_DIR=""
TPL_OIDC=""
TPL_KEYCLOAK=""
BH_PID=""
BH_PORT=""

die() {
    printf 'nuclei-coverage-probe: %s\n' "$1" >&2
    cleanup
    exit 2
}

note() { printf '  %s\n' "$1"; }

usage() {
    awk 'NR==1 {next} /^#/ {sub(/^# ?/,""); print; next} {exit}' "$0"
}

cleanup() {
    if [ -n "$SRV_PID" ] && kill -0 "$SRV_PID" 2>/dev/null; then
        kill "$SRV_PID" 2>/dev/null
        wait "$SRV_PID" 2>/dev/null
    fi
    SRV_PID=""
    if [ -n "$BH_PID" ] && kill -0 "$BH_PID" 2>/dev/null; then
        kill "$BH_PID" 2>/dev/null
        wait "$BH_PID" 2>/dev/null
    fi
    BH_PID=""
    if [ -n "$TMPROOT" ] && [ -d "$TMPROOT" ]; then
        \rm -rf "$TMPROOT"
    fi
    TMPROOT=""
}
trap cleanup EXIT INT TERM

pick_timeout() {
    if command -v timeout >/dev/null 2>&1; then
        TIMEOUT_BIN="timeout"
    elif command -v gtimeout >/dev/null 2>&1; then
        TIMEOUT_BIN="gtimeout"
    else
        die "neither timeout nor gtimeout on PATH (macOS: brew install coreutils)"
    fi
}

require_bin() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    fi
    printf 'SKIPPED: %s is not on PATH — %s\n' "$1" "$2" >&2
    return 1
}

free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# assert_loopback refuses any target that is not 127.0.0.1 / ::1 / localhost.
# This is the one guard between a coverage experiment and unauthorised scanning.
assert_loopback() {
    local url="$1" host
    host="$(printf '%s' "$url" | sed -e 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##' -e 's#/.*##' -e 's#^\[##' -e 's#\].*##' -e 's#:[0-9]*$##')"
    case "$host" in
        127.0.0.1 | ::1 | localhost) return 0 ;;
    esac
    if [ "$FORCE_NONLOOPBACK" -eq 1 ]; then
        printf 'nuclei-coverage-probe: WARNING — scanning NON-LOOPBACK host %s because --force-nonloopback was passed.\n' "$host" >&2
        return 0
    fi
    die "refusing to scan non-loopback host '$host'. This probe exists to answer a coverage
  question against a controlled fixture; pointing it at a real host is unauthorised
  scanning (T-17-05-04). Pass --force-nonloopback only with written authorisation."
}

# ─────────────────────────────────────────────────────────────────────────────
# the fixture
# ─────────────────────────────────────────────────────────────────────────────

# fixture_start writes and launches a CONCURRENT loopback HTTP server.
#
# Concurrency is not incidental. python3 -m http.server is single-threaded, and
# under nuclei's default bulk-size of 25 it wedges — producing a hang that looks
# exactly like the coverage bug under investigation and would have been reported
# as one. ThreadingHTTPServer does not.
fixture_start() {
    local root="$TMPROOT/www"
    mkdir -p "$root/.well-known" "$root/auth/realms/master/.well-known"
    cat >"$root/.well-known/openid-configuration" <<'JSON'
{"issuer":"https://fixture.local","authorization_endpoint":"https://fixture.local/auth","token_endpoint":"https://fixture.local/token","userinfo_endpoint":"https://fixture.local/userinfo","jwks_uri":"https://fixture.local/certs"}
JSON
    \cp -f "$root/.well-known/openid-configuration" \
        "$root/auth/realms/master/.well-known/openid-configuration"

    cat >"$TMPROOT/serve.py" <<'PY'
import os, sys
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass


os.chdir(sys.argv[2])
ThreadingHTTPServer.allow_reuse_address = True
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Quiet).serve_forever()
PY

    SRV_PORT="$(free_port)"
    python3 "$TMPROOT/serve.py" "$SRV_PORT" "$root" >"$TMPROOT/serve.log" 2>&1 &
    SRV_PID=$!

    local i code
    for i in 1 2 3 4 5 6 7 8 9 10; do
        code="$(curl -s -o /dev/null -w '%{http_code}' \
            "http://127.0.0.1:$SRV_PORT/.well-known/openid-configuration" 2>/dev/null)"
        [ "$code" = "200" ] && return 0
        sleep 0.3
    done
    return 1
}

# fixture_templates copies the two OIDC templates into an isolated directory, so
# an arm can load exactly two templates and its request budget is knowable.
fixture_templates() {
    TPL_OIDC="$TEMPLATES_DIR/http/technologies/oidc-detect.yaml"
    TPL_KEYCLOAK="$TEMPLATES_DIR/http/exposures/configs/keycloak-openid-config.yaml"
    if [ ! -f "$TPL_OIDC" ] || [ ! -f "$TPL_KEYCLOAK" ]; then
        printf 'SKIPPED: the two OIDC templates are not installed under %s\n' "$TEMPLATES_DIR" >&2
        return 1
    fi
    TPL_ISO_DIR="$TMPROOT/tpl"
    mkdir -p "$TPL_ISO_DIR"
    \cp -f "$TPL_OIDC" "$TPL_KEYCLOAK" "$TPL_ISO_DIR/"
    return 0
}

# closed_targets prints N loopback URLs on ports with nothing listening, one per
# line. These exist so the per-host error budget (H1) is REACHABLE — a fixture
# that only ever answers 200 could never produce an H1 result.
closed_targets() {
    local n="$1" i p
    i=0
    while [ "$i" -lt "$n" ]; do
        p="$(free_port)"
        printf 'http://127.0.0.1:%s\n' "$p"
        i=$((i + 1))
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# arms
# ─────────────────────────────────────────────────────────────────────────────

# run_arm <label> <hostsfile|-u URL> <tplspec> <extra args...>
#
# Writes  $TMPROOT/<label>.{stdout,stderr,out,tlog}  and prints one summary line.
# Sets ARM_RC, ARM_TEMPLATES, ARM_REQUESTS, ARM_TOTAL, ARM_MATCHED, ARM_IDS,
# ARM_SENT_OIDC, ARM_SENT_KEYCLOAK, ARM_ELAPSED.
run_arm() {
    local label="$1"
    shift
    local out="$TMPROOT/$label.out"
    local tlog="$TMPROOT/$label.tlog"
    \rm -f "$out" "$tlog"

    local start end
    start="$(date +%s)"
    "$TIMEOUT_BIN" "$ARM_BOUND" nuclei -duc -ni "$@" \
        -tlog "$tlog" -j -o "$out" \
        >"$TMPROOT/$label.stdout" 2>"$TMPROOT/$label.stderr"
    ARM_RC=$?
    end="$(date +%s)"
    ARM_ELAPSED=$((end - start))

    # The FINAL -sj stats object is the complete account. Arms that do not pass
    # -stats leave these UNKNOWN rather than zero.
    local stats
    stats="$(grep '^{"duration"' "$TMPROOT/$label.stderr" 2>/dev/null | tail -1)"
    if [ -n "$stats" ]; then
        ARM_TEMPLATES="$(printf '%s' "$stats" | sed -n 's/.*"templates":"\([0-9]*\)".*/\1/p')"
        ARM_REQUESTS="$(printf '%s' "$stats" | sed -n 's/.*"requests":"\([0-9]*\)".*/\1/p')"
        ARM_TOTAL="$(printf '%s' "$stats" | sed -n 's/.*"total":"\([0-9]*\)".*/\1/p')"
        ARM_MATCHED="$(printf '%s' "$stats" | sed -n 's/.*"matched":"\([0-9]*\)".*/\1/p')"
    else
        ARM_TEMPLATES="UNKNOWN"
        ARM_REQUESTS="UNKNOWN"
        ARM_TOTAL="UNKNOWN"
        ARM_MATCHED="UNKNOWN"
    fi

    ARM_IDS="$(sed -n 's/.*"template-id":"\([^"]*\)".*/\1/p' "$out" 2>/dev/null | sort -u | tr '\n' ' ')"
    [ -z "$ARM_IDS" ] && ARM_IDS="(none)"

    # THE PER-TEMPLATE ANSWER. A trace line for a template means its request WAS
    # SENT. Its absence means it was not. This is the H1/H2 discriminator and the
    # reason -tlog is on in this script.
    ARM_SENT_OIDC="$(grep -c 'oidc-detect' "$tlog" 2>/dev/null || true)"
    ARM_SENT_KEYCLOAK="$(grep -c 'keycloak-openid-config' "$tlog" 2>/dev/null || true)"
    [ -z "$ARM_SENT_OIDC" ] && ARM_SENT_OIDC=0
    [ -z "$ARM_SENT_KEYCLOAK" ] && ARM_SENT_KEYCLOAK=0

    printf '  %-26s rc=%-3s %5ss  templates=%-6s requests=%s/%s matched=%-6s oidc-req=%s keycloak-req=%s\n' \
        "$label" "$ARM_RC" "$ARM_ELAPSED" "$ARM_TEMPLATES" "$ARM_REQUESTS" "$ARM_TOTAL" \
        "$ARM_MATCHED" "$ARM_SENT_OIDC" "$ARM_SENT_KEYCLOAK"
    printf '  %-26s ids: %s\n' "" "$ARM_IDS"
}

# -----------------------------------------------------------------------------
# cost: what the -nmhe remedy would cost
# -----------------------------------------------------------------------------

# blackhole_start opens a loopback listener that ACCEPTS and then never answers
# and never closes.
#
# A CLOSED port is the wrong instrument for this measurement: connection-refused
# is instant, so disabling the error budget against closed ports costs almost
# nothing and the number would flatter the change. An unresponsive-but-accepting
# host is what a WAF, a drop rule or an overloaded target actually looks like,
# and it is the case where the per-host error budget earns its keep.
blackhole_start() {
    BH_PORT="$(free_port)"
    cat >"$TMPROOT/blackhole.py" <<'PY'
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(512)
held = []
while True:
    c, _ = s.accept()
    held.append(c)
PY
    python3 "$TMPROOT/blackhole.py" "$BH_PORT" >"$TMPROOT/blackhole.log" 2>&1 &
    BH_PID=$!
    sleep 0.5
}

# run_cost prices the H1 remedy plan 17-05 Task 3 asks the operator about:
# disabling nuclei's per-host error budget so a host can never be dropped
# mid-scan. Two arms, identical in every other respect, over the FULL template
# tree against ONE blackholed host.
run_cost() {
    pick_timeout
    require_bin nuclei "the probe measures nuclei own behaviour" || exit 3
    require_bin python3 "the blackhole listener needs it" || exit 3

    TMPROOT="$(mktemp -d)" || die "mktemp -d failed"
    fixture_templates || exit 3
    blackhole_start

    local target="http://127.0.0.1:$BH_PORT"
    assert_loopback "$target"

    local hosts="$TMPROOT/cost.hosts.txt"
    printf '%s\n' "$target" >"$hosts"

    echo "== cost of the -nmhe remedy =="
    echo "   ONE blackholed loopback host (accepts, never answers), full template tree."
    echo "   G1 keeps nuclei default per-host error budget; G2 disables it."
    echo "   Both bounded at ${ARM_BOUND}s: rc=124 means the arm did NOT finish, which"
    echo "   is itself the measurement."
    run_arm "G1-mhe-default" -l "$hosts" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
        -retries 2 -stats -sj -si 15 -t "$TEMPLATES_DIR"
    local g1_elapsed="$ARM_ELAPSED" g1_rc="$ARM_RC" g1_req="$ARM_REQUESTS"
    run_arm "G2-nmhe" -l "$hosts" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
        -retries 2 -stats -sj -si 15 -nmhe -t "$TEMPLATES_DIR"
    local d1 d2
    d1="$(grep -c 'from target list as found unresponsive' "$TMPROOT/G1-mhe-default.stderr" 2>/dev/null || true)"
    d2="$(grep -c 'from target list as found unresponsive' "$TMPROOT/G2-nmhe.stderr" 2>/dev/null || true)"
    [ -z "$d1" ] && d1=0
    [ -z "$d2" ] && d2=0
    echo
    printf '  default budget:  %ss (rc=%s, requests=%s, drop notices=%s)\n' "$g1_elapsed" "$g1_rc" "$g1_req" "$d1"
    printf '  budget disabled: %ss (rc=%s, requests=%s, drop notices=%s)\n' "$ARM_ELAPSED" "$ARM_RC" "$ARM_REQUESTS" "$d2"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# self-check
# ─────────────────────────────────────────────────────────────────────────────

# self_check proves the HARNESS works before any result from it is believed.
#
# It exists because of a precedent in this phase: a checker was built whose
# extraction step produced 0-byte command files, and `sh -c ""` exits 0, so it
# reported PASS having run nothing. Every assertion below therefore checks that
# the thing it measured is NON-EMPTY, not merely that a command succeeded.
#
# PROBE_FORCE_BROKEN=1 breaks the fixture on purpose; assertions 2 and 3 MUST
# then fail. That is the mutation proof for the self-check itself.
self_check() {
    local failures=0
    pick_timeout
    TMPROOT="$(mktemp -d)" || die "mktemp -d failed"

    echo "== self-check =="
    if [ "${PROBE_FORCE_BROKEN:-0}" = "1" ]; then
        echo "  !! PROBE_FORCE_BROKEN=1 — the fixture document is emptied on purpose."
        echo "  !! Assertions 2 and 3 MUST fail below."
    fi

    # 1. The loopback guard refuses a real host, and does so by DYING.
    local rc=0
    (
        FORCE_NONLOOPBACK=0
        assert_loopback "https://example.com:443"
    ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
        note "1. non-loopback target refused ....... PASS (exit $rc)"
    else
        note "1. non-loopback target refused ....... FAIL — the probe would scan a third party"
        failures=$((failures + 1))
    fi

    # 2. The fixture actually serves the document, and it is NON-EMPTY.
    if fixture_start; then
        if [ "${PROBE_FORCE_BROKEN:-0}" = "1" ]; then
            : >"$TMPROOT/www/.well-known/openid-configuration"
        fi
        local body bytes
        body="$(curl -s "http://127.0.0.1:$SRV_PORT/.well-known/openid-configuration")"
        bytes="${#body}"
        if [ "$bytes" -gt 0 ]; then
            note "2. fixture serves a body ............. PASS ($bytes bytes on 127.0.0.1:$SRV_PORT)"
        else
            note "2. fixture serves a body ............. FAIL (0 bytes — an empty fixture makes every arm vacuous)"
            failures=$((failures + 1))
        fi

        # 3. The body carries EVERY word both templates match on. A fixture that
        #    is served but does not match is the silent-vacuous case.
        local missing=""
        local w
        for w in issuer authorization_endpoint token_endpoint userinfo_endpoint jwks_uri; do
            case "$body" in
                *"$w"*) ;;
                *) missing="$missing $w" ;;
            esac
        done
        if [ -z "$missing" ]; then
            note "3. fixture carries every matcher word  PASS"
        else
            note "3. fixture carries every matcher word  FAIL (missing:$missing)"
            failures=$((failures + 1))
        fi

        # 4. The second keycloak path is served too, so its 2-request budget is real.
        local code2
        code2="$(curl -s -o /dev/null -w '%{http_code}' \
            "http://127.0.0.1:$SRV_PORT/auth/realms/master/.well-known/openid-configuration")"
        if [ "$code2" = "200" ]; then
            note "4. keycloak second path served ....... PASS (HTTP $code2)"
        else
            note "4. keycloak second path served ....... FAIL (HTTP $code2)"
            failures=$((failures + 1))
        fi
    else
        note "2. fixture serves a body ............. FAIL (server never came up)"
        note "3. fixture carries every matcher word  FAIL (no fixture)"
        note "4. keycloak second path served ....... FAIL (no fixture)"
        failures=$((failures + 3))
    fi

    # 5. Closed targets really refuse, so the per-host error budget is reachable.
    local closed code
    closed="$(closed_targets 1)"
    if [ -z "$closed" ]; then
        note "5. closed target is reachable-as-closed FAIL (produced no target)"
        failures=$((failures + 1))
    else
        code="$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$closed" 2>/dev/null)"
        if [ "$code" = "000" ]; then
            note "5. closed target refuses ............. PASS ($closed -> no answer)"
        else
            note "5. closed target refuses ............. FAIL ($closed -> HTTP $code; H1 would be untestable)"
            failures=$((failures + 1))
        fi
    fi

    # 6. The timeout bound fires, and rc=124 is what an arm will read.
    rc=0
    "$TIMEOUT_BIN" 1 sleep 5 || rc=$?
    if [ "$rc" -eq 124 ]; then
        note "6. timeout bound fires ............... PASS (rc=$rc)"
    else
        note "6. timeout bound fires ............... FAIL (rc=$rc, expected 124)"
        failures=$((failures + 1))
    fi

    # 7. A missing binary is SKIPPED, never a silent pass.
    if require_bin "definitely-not-a-real-binary-17-05" "self-check" 2>/dev/null; then
        note "7. missing binary is SKIPPED ......... FAIL (require_bin returned success)"
        failures=$((failures + 1))
    else
        note "7. missing binary is SKIPPED ......... PASS"
    fi

    # 8. The trace-log grep — the H1/H2 discriminator — actually discriminates.
    #    Asserted against a hand-built trace, so a broken grep cannot report
    #    "no requests sent" and be read as a coverage hole.
    local fake="$TMPROOT/fake.tlog"
    printf '{"template":"/t/oidc-detect.yaml","input":"http://127.0.0.1/x","error":"none"}\n' >"$fake"
    local hit miss
    hit="$(grep -c 'oidc-detect' "$fake")"
    miss="$(grep -c 'keycloak-openid-config' "$fake" || true)"
    [ -z "$miss" ] && miss=0
    if [ "$hit" -eq 1 ] && [ "$miss" -eq 0 ]; then
        note "8. trace discriminator works ......... PASS (present=1 absent=0)"
    else
        note "8. trace discriminator works ......... FAIL (present=$hit absent=$miss)"
        failures=$((failures + 1))
    fi

    echo
    if [ "$failures" -eq 0 ]; then
        echo "self-check: PASS (8/8)"
        cleanup
        return 0
    fi
    echo "self-check: FAIL ($failures assertion(s))"
    cleanup
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# the matrix
# ─────────────────────────────────────────────────────────────────────────────

run_matrix() {
    pick_timeout
    require_bin nuclei "the probe measures nuclei's own behaviour and cannot be faked" || exit 3
    require_bin python3 "the loopback fixture server needs it" || exit 3
    require_bin curl "the fixture readiness check needs it" || exit 3

    TMPROOT="$(mktemp -d)" || die "mktemp -d failed"
    fixture_templates || exit 3
    fixture_start || die "fixture server never came up (see $TMPROOT/serve.log)"

    TARGET="http://127.0.0.1:$SRV_PORT"
    assert_loopback "$TARGET"

    printf 'nuclei-coverage-probe: %s\n' "$(nuclei -version 2>&1 | sed -n 's/.*Nuclei Engine Version: //p' | head -1)"
    printf '  fixture      %s\n' "$TARGET"
    printf '  templates    %s\n' "$TEMPLATES_DIR"
    printf '  isolated dir %s (2 templates)\n' "$TPL_ISO_DIR"
    echo

    local hosts="$TMPROOT/hosts.txt"
    printf '%s\n' "$TARGET" >"$hosts"

    local hosts_err="$TMPROOT/hosts_err.txt"
    {
        printf '%s\n' "$TARGET"
        closed_targets 3
    } >"$hosts_err"

    echo "== A. the two vectors, identical fixture =="
    echo "   ISO is 16-06-PARITY.md §6.1's targeted probe. PROD is v2's production"
    echo "   vector AS IT STOOD on 2026-08-24 (with -silent, without accounting)."
    run_arm "A1-iso-two-templates" -silent -u "$TARGET" -t "$TPL_OIDC" -t "$TPL_KEYCLOAK"
    run_arm "A2-prod-vector-2024" -l "$hosts" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
        -silent -retries 2 -t "$TPL_ISO_DIR"
    run_arm "A3-prod-plus-stats" -l "$hosts" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
        -retries 2 -stats -sj -si 5 -t "$TPL_ISO_DIR"
    echo

    echo "== B. flag bisect of the production vector (H5) =="
    echo "   One flag removed at a time. A divergence names the flag."
    run_arm "B1-no-nh" -l "$hosts" -severity "$SEVERITY" -rl "$RATE_LIMIT" \
        -retries 2 -stats -sj -si 5 -t "$TPL_ISO_DIR"
    run_arm "B2-no-severity" -l "$hosts" -nh -rl "$RATE_LIMIT" \
        -retries 2 -stats -sj -si 5 -t "$TPL_ISO_DIR"
    run_arm "B3-no-ratelimit" -l "$hosts" -severity "$SEVERITY" -nh \
        -retries 2 -stats -sj -si 5 -t "$TPL_ISO_DIR"
    run_arm "B4-with-silent" -l "$hosts" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
        -silent -retries 2 -stats -sj -si 5 -t "$TPL_ISO_DIR"
    run_arm "B5-u-not-l" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
        -retries 2 -stats -sj -si 5 -u "$TARGET" -t "$TPL_ISO_DIR"
    echo

    echo "== C. the per-host error budget (H1) =="
    echo "   Three of four targets are CLOSED loopback ports, so the budget is reachable."
    run_arm "C1-mhe-default" -l "$hosts_err" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
        -retries 2 -stats -sj -si 5 -t "$TPL_ISO_DIR"
    run_arm "C2-mhe-1" -l "$hosts_err" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
        -retries 2 -stats -sj -si 5 -mhe 1 -t "$TPL_ISO_DIR"
    run_arm "C3-mhe-1-silent" -l "$hosts_err" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
        -silent -retries 2 -stats -sj -si 5 -mhe 1 -t "$TPL_ISO_DIR"
    # THE A/B THAT NAMES THE SUPPRESSION. C2 and C3 are the same run with one
    # flag differing. grep -c exits 1 on zero matches, so `|| true` keeps the
    # count rather than letting the non-zero rc swallow it — an `|| echo 0` here
    # printed BOTH grep's own 0 and the fallback 0, which is exactly the kind of
    # harness artefact that gets read as data.
    local c2_notices c3_notices
    c2_notices="$(grep -c 'from target list as found unresponsive' "$TMPROOT/C2-mhe-1.stderr" 2>/dev/null || true)"
    c3_notices="$(grep -c 'from target list as found unresponsive' "$TMPROOT/C3-mhe-1-silent.stderr" 2>/dev/null || true)"
    [ -z "$c2_notices" ] && c2_notices=0
    [ -z "$c3_notices" ] && c3_notices=0
    printf '  drop notices visible without -silent: %s\n' "$c2_notices"
    printf '  drop notices visible WITH    -silent: %s\n' "$c3_notices"
    echo

    echo "== D. run-to-run stability of the loaded set (H6) =="
    echo "   Two consecutive runs against a STATIC template dir. A differing"
    echo "   templates count would mean the set mutated between runs."
    run_arm "D1-repeat-a" -l "$hosts" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
        -retries 2 -stats -sj -si 5 -t "$TPL_ISO_DIR"
    local d1="$ARM_TEMPLATES"
    run_arm "D2-repeat-b" -l "$hosts" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
        -retries 2 -stats -sj -si 5 -t "$TPL_ISO_DIR"
    if [ "$d1" = "$ARM_TEMPLATES" ]; then
        echo "  loaded count stable across runs: $d1 == $ARM_TEMPLATES"
    else
        echo "  loaded count CHANGED between runs: $d1 -> $ARM_TEMPLATES"
    fi
    echo

    echo "== E. filter-set membership (H3/H4) =="
    echo "   Does the FILTER select the two templates under directory-mode loading?"
    local tl="$TMPROOT/tl.txt"
    "$TIMEOUT_BIN" "$ARM_BOUND" nuclei -duc -tl -severity "$SEVERITY" -t "$TEMPLATES_DIR" \
        >"$tl" 2>/dev/null
    local tl_rc=$? tl_n tl_oidc tl_kc
    tl_n="$(grep -c '\.yaml$' "$tl" 2>/dev/null || true)"
    [ -z "$tl_n" ] && tl_n=0
    tl_oidc="$(grep -c '/oidc-detect\.yaml$' "$tl" 2>/dev/null || true)"
    tl_kc="$(grep -c '/keycloak-openid-config\.yaml$' "$tl" 2>/dev/null || true)"
    [ -z "$tl_oidc" ] && tl_oidc=0
    [ -z "$tl_kc" ] && tl_kc=0
    if [ "$tl_n" -eq 0 ]; then
        echo "  -tl produced NO template paths (rc=$tl_rc) — filter-set membership is UNKNOWN,"
        echo "  not zero. Do not read this as 'the filter selected nothing'."
    else
        printf '  -tl selected %s templates under severity=%s\n' "$tl_n" "$SEVERITY"
        printf '  oidc-detect in filter set:            %s\n' "$tl_oidc"
        printf '  keycloak-openid-config in filter set: %s\n' "$tl_kc"
    fi
    echo

    if [ "$FULL_TREE" -eq 1 ]; then
        echo "== F. directory-mode over the FULL template tree (H3, decisive) =="
        echo "   The production vector's actual -t value is \$HOME/nuclei-templates."
        echo "   The trace answers per template whether each OIDC request was SENT."
        run_arm "F1-full-tree-prod" -l "$hosts" -severity "$SEVERITY" -nh -rl "$RATE_LIMIT" \
            -retries 2 -stats -sj -si 30 -t "$TEMPLATES_DIR"
        echo
    else
        echo "== F. directory-mode over the FULL template tree (H3) — NOT RUN =="
        echo "   Pass --full-tree to run it. It loads ~13k templates and is slow."
        echo
    fi

    echo "== artefacts =="
    echo "   $TMPROOT (removed on exit; re-run with PROBE_KEEP=1 to keep)"
    if [ "${PROBE_KEEP:-0}" = "1" ]; then
        # NOT $(pwd): this script is usually run from the repo root, and dropping
        # a multi-megabyte trace directory into a working tree is how untracked
        # artefacts end up in somebody's commit. Override with PROBE_KEEP_DIR.
        local keepdir keep
        keepdir="${PROBE_KEEP_DIR:-${TMPDIR:-/tmp}}"
        keep="${keepdir%/}/nuclei-coverage-probe-$(date +%Y%m%d-%H%M%S)"
        \cp -Rf "$TMPROOT" "$keep" && echo "   kept at $keep"
    fi
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --self-check) SELF_CHECK=1 ;;
        --fixture-only) FIXTURE_ONLY=1 ;;
        --full-tree)
            FIXTURE_ONLY=1
            FULL_TREE=1
            ;;
        --cost) COST_ONLY=1 ;;
        --force-nonloopback) FORCE_NONLOOPBACK=1 ;;
        --templates)
            shift
            [ $# -gt 0 ] || die "--templates needs a directory"
            TEMPLATES_DIR="$1"
            ;;
        --severity)
            shift
            [ $# -gt 0 ] || die "--severity needs a value"
            SEVERITY="$1"
            ;;
        --bound)
            shift
            [ $# -gt 0 ] || die "--bound needs seconds"
            ARM_BOUND="$1"
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

if [ "$SELF_CHECK" -eq 1 ]; then
    self_check
    exit $?
fi

if [ "$COST_ONLY" -eq 1 ]; then
    run_cost
    exit $?
fi

if [ "$FIXTURE_ONLY" -eq 1 ]; then
    run_matrix
    exit $?
fi

usage
exit 2
