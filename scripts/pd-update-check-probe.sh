#!/usr/bin/env bash
# scripts/pd-update-check-probe.sh — the discriminating experiment for plan 16-03.
#
# THE QUESTION. On 2026-08-20 the real web.httpx arg vector, run by hand without
# the update-check flag, returned rc=124 at a 120 s bound and again at 240 s and
# never created its output file. On 2026-08-21 the same argv returned rc=0 with
# records intact. One observation says the tool can block; the next says it
# cannot. Nobody could arbitrate, because the evidence existed only in one
# operator's terminal history on one box.
#
# This script is the arbitration. It is self-contained and needs no ssh access to
# reconbox3: it starts its own blackhole listener, builds its own throwaway config
# directories, and runs a five-plus-one arm matrix over three controlled
# variables. Anyone can re-run it and get comparable evidence.
#
# ─────────────────────────────────────────────────────────────────────────────
# THE THREE CONTROLLED VARIABLES
# ─────────────────────────────────────────────────────────────────────────────
#   1. NETWORK REACHABILITY of the tool's startup dependency
#        reachable   — the ambient network
#        refused     — HTTP(S)_PROXY at a port with nothing listening; a
#                      connection attempt fails IMMEDIATELY
#        blackholed  — HTTP(S)_PROXY at a listener that ACCEPTS and then never
#                      responds and never closes
#      The refused/blackholed distinction is the whole experiment. A refusing
#      port cannot tell "the check has no timeout" from "the check fails fast" —
#      both are fast. Only a blackhole can, because only a blackhole makes a
#      client WITHOUT a timeout block forever.
#   2. CONFIG-CACHE STATE — a freshly created HOME + XDG_CONFIG_HOME versus one
#      warmed by an immediately preceding successful run.
#   3. THE UPDATE-CHECK FLAG — present or absent.
#
# ─────────────────────────────────────────────────────────────────────────────
# THE ARMS
# ─────────────────────────────────────────────────────────────────────────────
#   A  reachable   fresh  no flag    the baseline the operator observed twice,
#                                    with opposite results
#   B  refused     fresh  no flag    does the check tolerate a fast failure
#   C  blackholed  fresh  no flag    THE DECISIVE ARM. A hang here means the
#                                    startup check has no timeout.
#   D  blackholed  fresh  -duc       must be fast if the flag disables that check
#   E  reachable   warm   no flag    does a warm cache make a slow start fast
#   F  blackholed  fresh  no flag    the asymmetry arm, run against a SECOND PD
#                                    tool that ran fine in the failing scan
#
# ─────────────────────────────────────────────────────────────────────────────
# WHY NO_PROXY IS SET, AND WHY IT MATTERS
# ─────────────────────────────────────────────────────────────────────────────
# Every arm probes a LOCAL, closed port and sets NO_PROXY for loopback, so the
# tool's actual work fails fast and does not traverse the blackhole. Without
# that, arm D would hang too — on its probe traffic rather than its startup
# check — and the arm that is supposed to discriminate would discriminate
# nothing.
#
# The blackhole COUNTS the connections it accepts, per arm. An arm that hangs
# having accepted zero connections did not hang on the proxied dependency, and
# the script says so instead of crediting the result to the mechanism under
# test. An arm whose count is zero proves nothing about M1 either way.
#
# ─────────────────────────────────────────────────────────────────────────────
# NEVER TOUCHES THE REAL HOME
# ─────────────────────────────────────────────────────────────────────────────
# A test that writes into $HOME changes its own next result. Every arm runs with
# HOME and XDG_CONFIG_HOME pointed inside a `mktemp -d` root, and the script
# ASSERTS that before each invocation (assert_isolated). If the assertion ever
# fails the script dies rather than running the arm.
#
# ─────────────────────────────────────────────────────────────────────────────
# USAGE
# ─────────────────────────────────────────────────────────────────────────────
#   scripts/pd-update-check-probe.sh --self-check     prove the harness works; no PD binary needed
#   scripts/pd-update-check-probe.sh                  run the full matrix
#   scripts/pd-update-check-probe.sh --runs 5         more samples per arm
#   scripts/pd-update-check-probe.sh --arms C,D       only these arms
#   scripts/pd-update-check-probe.sh --no-silent      drop -silent from the argv
#   scripts/pd-update-check-probe.sh --tool httpx --second-tool dnsx
#   scripts/pd-update-check-probe.sh --help
#
# EXIT: 0 when the matrix ran (a hang is a RESULT, not an error). 2 on a usage or
# harness fault. 3 when a required binary is absent — SKIPPED is never PASS.
#
# NOTE: no `set -e`. rc=124 from `timeout` is the measurement; aborting on it
# would discard the finding.
set -uo pipefail

TOOL="httpx"
SECOND_TOOL="dnsx"
RUNS=3
ARMS="A,B,C,D,E,F"
SELF_CHECK=0
BOUND=60
SILENT=1

TMPROOT=""
BH_PID=""
BH_PORT=""
BH_LOG=""
REFUSED_PORT=""
REAL_HOME="$HOME"

die() {
    printf 'pd-update-check-probe: %s\n' "$1" >&2
    cleanup
    exit 2
}

note() { printf '  %s\n' "$1"; }

usage() {
    awk 'NR==1 {next} /^#/ {sub(/^# ?/,""); print; next} {exit}' "$0"
}

cleanup() {
    if [ -n "$BH_PID" ] && kill -0 "$BH_PID" 2>/dev/null; then
        kill "$BH_PID" 2>/dev/null
        wait "$BH_PID" 2>/dev/null
    fi
    BH_PID=""
    [ -n "$TMPROOT" ] && [ -d "$TMPROOT" ] && rm -rf "$TMPROOT"
    TMPROOT=""
}
trap cleanup EXIT INT TERM

# ── portable timeout ────────────────────────────────────────────────────────
TIMEOUT_BIN=""
pick_timeout() {
    if command -v timeout >/dev/null 2>&1; then
        TIMEOUT_BIN="timeout"
    elif command -v gtimeout >/dev/null 2>&1; then
        TIMEOUT_BIN="gtimeout"
    else
        die "neither timeout nor gtimeout on PATH (macOS: brew install coreutils)"
    fi
}

# free_port — a TCP port nothing is listening on right now.
free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# ── the blackhole ───────────────────────────────────────────────────────────
#
# Accepts, records the accept, and then holds the connection open forever without
# writing a byte. The held sockets are kept referenced so the interpreter cannot
# close them behind our back — a closed socket is an EOF, and an EOF is not a
# blackhole.
blackhole_start() {
    BH_PORT="$(free_port)"
    BH_LOG="$TMPROOT/blackhole.accepts"
    : >"$BH_LOG"
    python3 - "$BH_PORT" "$BH_LOG" <<'PY' &
import socket, sys
port, logpath = int(sys.argv[1]), sys.argv[2]
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(128)
held = []
while True:
    conn, _ = srv.accept()
    held.append(conn)          # never respond, never close
    with open(logpath, "a") as fh:
        fh.write("accept\n")
        fh.flush()
PY
    BH_PID=$!
    # Wait for the bind to take effect before anything depends on it.
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if python3 - "$BH_PORT" <<'PY' >/dev/null 2>&1; then
import socket, sys
s = socket.socket()
s.settimeout(0.3)
s.connect(("127.0.0.1", int(sys.argv[1])))
s.close()
PY
            return 0
        fi
        sleep 0.2
    done
    die "blackhole listener never came up on 127.0.0.1:$BH_PORT"
}

bh_accepts() {
    if [ ! -f "$BH_LOG" ]; then
        echo 0
        return
    fi
    # `grep -c` prints 0 AND exits non-zero on no match, so a `|| echo 0`
    # fallback emits the count twice. wc -l has one output and one exit code.
    local n
    n="$(wc -l <"$BH_LOG" 2>/dev/null)"
    echo "${n:-0}" | tr -d ' '
}

# probe_socket_state — the load-bearing harness observation.
#
# Opens a connection, sends a request line, and tries to read a reply under a
# short bound. A blackhole must produce TIMEOUT: not a refusal, not an EOF, not a
# response. If that cannot be demonstrated, arm C proves nothing and the whole
# experiment is void — so it is checked before the matrix runs, not assumed.
probe_socket_state() {
    # Prints one of: TIMEOUT | REFUSED | EOF | RESPONDED:<bytes>
    python3 - "$1" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
s.settimeout(2.0)
try:
    s.connect(("127.0.0.1", port))
except ConnectionRefusedError:
    print("REFUSED")
    sys.exit(0)
except OSError as e:
    print("ERROR:%s" % e)
    sys.exit(0)
try:
    s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
    data = s.recv(64)
except socket.timeout:
    print("TIMEOUT")
    sys.exit(0)
except OSError as e:
    print("ERROR:%s" % e)
    sys.exit(0)
if data == b"":
    print("EOF")
else:
    print("RESPONDED:%d" % len(data))
PY
}

# ── isolation ───────────────────────────────────────────────────────────────
#
# Enforced, not documented. An arm whose HOME is not inside TMPROOT is a bug that
# would silently corrupt every later result, so it dies instead of running.
assert_isolated() {
    local h="$1" x="$2"
    case "$h" in
        "$TMPROOT"/*) ;;
        *) die "arm HOME ($h) is not inside the temp root ($TMPROOT) — refusing to run" ;;
    esac
    case "$x" in
        "$TMPROOT"/*) ;;
        *) die "arm XDG_CONFIG_HOME ($x) is not inside the temp root ($TMPROOT) — refusing to run" ;;
    esac
    [ "$h" != "$REAL_HOME" ] || die "arm HOME equals the real HOME — refusing to run"
}

# ── one measurement ─────────────────────────────────────────────────────────
#
# run_once <arm> <run-no> <tool> <net> <cache-dir> <flag?>
#   net: reachable | refused | blackholed
# Emits one TSV row: arm run tool net flag secs rc outfile records accepts
run_once() {
    local arm="$1" runno="$2" tool="$3" net="$4" cachedir="$5" flag="$6"
    local home="$cachedir/home" xdg="$cachedir/xdg"
    mkdir -p "$home" "$xdg"
    assert_isolated "$home" "$xdg"

    local workdir="$TMPROOT/work/$arm-$runno"
    mkdir -p "$workdir"
    local outfile="$workdir/out.jsonl"
    local inputfile="$workdir/in.txt"
    # A local, CLOSED port: the tool's real work fails fast and never traverses
    # the proxy, so anything slow is the STARTUP dependency.
    printf '127.0.0.1:%s\n' "$REFUSED_PORT" >"$inputfile"

    local -a env_args=()
    case "$net" in
        reachable) ;;
        refused)
            env_args+=("HTTP_PROXY=http://127.0.0.1:$REFUSED_PORT" "HTTPS_PROXY=http://127.0.0.1:$REFUSED_PORT")
            ;;
        blackholed)
            env_args+=("HTTP_PROXY=http://127.0.0.1:$BH_PORT" "HTTPS_PROXY=http://127.0.0.1:$BH_PORT")
            ;;
        *) die "unknown network state: $net" ;;
    esac

    local -a argv
    argv=("$tool")
    [ "$flag" = "flag" ] && argv+=("-duc")
    # -silent is a CONTROLLED VARIABLE, not decoration. Dropping it flips arm C
    # from "recovers in ~5 s" to "runs until the bound" on httpx v1.9.0, and
    # flips arm D too — with the update-check flag present and ZERO connections
    # to the blackhole. See --no-silent and 16-03-FINDINGS.md §4.4.
    [ "$SILENT" -eq 1 ] && argv+=(-silent)
    if [ "$tool" = "httpx" ]; then
        # The REAL web.httpx arg vector (internal/modules/web/httpx.go), minus the
        # config-derived -p/-threads/-rl/-timeout. An approximate argv would prove
        # nothing about the real invocation.
        argv+=(-follow-host-redirects -random-agent -status-code
            -retries 2 -title -web-server -tech-detect
            -location -no-color -json -o "$outfile" -l "$inputfile")
    else
        argv+=(-json -o "$outfile" -l "$inputfile")
    fi

    local before after
    before="$(bh_accepts)"
    local start end secs rc
    start="$(date +%s)"
    env HOME="$home" XDG_CONFIG_HOME="$xdg" NO_PROXY="127.0.0.1,localhost,::1" \
        no_proxy="127.0.0.1,localhost,::1" "${env_args[@]}" \
        "$TIMEOUT_BIN" "$BOUND" "${argv[@]}" >"$workdir/stdout" 2>"$workdir/stderr"
    rc=$?
    end="$(date +%s)"
    secs=$((end - start))
    after="$(bh_accepts)"

    local created="no" records=0
    if [ -f "$outfile" ]; then
        created="yes"
        records="$(wc -l <"$outfile" 2>/dev/null | tr -d ' ')"
        records="${records:-0}"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%ss\t%s\t%s\t%s\t%s\n' \
        "$arm" "$runno" "$tool" "$net" "$flag" "$secs" "$rc" "$created" "$records" \
        "$((after - before))"
}

arm_selected() {
    case ",$ARMS," in
        *",$1,"*) return 0 ;;
        *) return 1 ;;
    esac
}

require_bin() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    fi
    printf 'SKIPPED: %s is not on PATH — %s\n' "$1" "$2" >&2
    return 1
}

# ── self-check ──────────────────────────────────────────────────────────────
#
# Proves the harness itself works, without any PD binary. A harness whose own
# logic is unverified cannot arbitrate a contradiction.
#
# MUTATION KNOB: PROBE_FORCE_REFUSING=1 points the "blackhole" arm at a closed
# port instead. Assertion 1 MUST then fail. That is the mutation proof required
# by the plan, kept runnable instead of requiring a source edit.
self_check() {
    local failures=0
    pick_timeout
    TMPROOT="$(mktemp -d)" || die "mktemp -d failed"
    REFUSED_PORT="$(free_port)"

    echo "== self-check =="
    if [ "${PROBE_FORCE_REFUSING:-0}" = "1" ]; then
        echo "  !! PROBE_FORCE_REFUSING=1 — the blackhole is replaced by a CLOSED port."
        echo "  !! This is the mutation proof. Assertion 1 MUST fail below."
    fi

    # 1. The blackhole really blackholes.
    local target state
    if [ "${PROBE_FORCE_REFUSING:-0}" = "1" ]; then
        target="$REFUSED_PORT"
        BH_LOG="$TMPROOT/none"
    else
        blackhole_start
        target="$BH_PORT"
    fi
    state="$(probe_socket_state "$target")"
    if [ "$state" = "TIMEOUT" ]; then
        note "1. blackhole blocks .................. PASS (127.0.0.1:$target -> $state)"
    else
        note "1. blackhole blocks .................. FAIL (127.0.0.1:$target -> $state)"
        note "   A port that refuses or answers cannot tell 'no timeout' from 'fails fast'."
        note "   Arm C would prove nothing; the experiment would be void."
        failures=$((failures + 1))
    fi

    # 2. A refusing port is distinguishable from the blackhole.
    state="$(probe_socket_state "$REFUSED_PORT")"
    if [ "$state" = "REFUSED" ] || [ "${state#ERROR:}" != "$state" ]; then
        note "2. refusing port is fast ............. PASS (127.0.0.1:$REFUSED_PORT -> $state)"
    else
        note "2. refusing port is fast ............. FAIL (expected REFUSED, got $state)"
        failures=$((failures + 1))
    fi

    # 3. The timeout bound actually fires, and rc=124 is what we will read.
    local rc=0
    "$TIMEOUT_BIN" 1 sleep 5 || rc=$?
    if [ "$rc" -eq 124 ]; then
        note "3. timeout bound fires ............... PASS (rc=$rc)"
    else
        note "3. timeout bound fires ............... FAIL (rc=$rc, expected 124)"
        failures=$((failures + 1))
    fi

    # 4. A missing binary is SKIPPED, never a silent pass.
    if require_bin "definitely-not-a-real-binary-16-03" "self-check" 2>/dev/null; then
        note "4. missing binary is SKIPPED ......... FAIL (require_bin returned success)"
        failures=$((failures + 1))
    else
        note "4. missing binary is SKIPPED ......... PASS (require_bin returned non-zero)"
    fi

    # 5. Isolation is enforced by dying, not by convention. Checked in a subshell
    #    because a real violation must terminate the run.
    if (assert_isolated "$REAL_HOME" "$TMPROOT/xdg") 2>/dev/null; then
        note "5. real HOME is refused .............. FAIL (assert_isolated admitted the real HOME)"
        failures=$((failures + 1))
    else
        note "5. real HOME is refused .............. PASS (assert_isolated died)"
    fi

    echo
    if [ "$failures" -eq 0 ]; then
        echo "self-check: PASS (5/5)"
        cleanup
        return 0
    fi
    echo "self-check: FAIL ($failures assertion(s) failed)"
    cleanup
    return 1
}

# ── the matrix ──────────────────────────────────────────────────────────────
run_matrix() {
    pick_timeout
    TMPROOT="$(mktemp -d)" || die "mktemp -d failed"
    REFUSED_PORT="$(free_port)"

    require_bin "$TOOL" "arms A-E measure it; nothing can be concluded without it" || exit 3
    local have_second=1
    require_bin "$SECOND_TOOL" "arm F (the asymmetry arm) will be recorded as NOT RUN" || have_second=0

    blackhole_start
    local state
    state="$(probe_socket_state "$BH_PORT")"
    if [ "$state" != "TIMEOUT" ]; then
        die "the blackhole on 127.0.0.1:$BH_PORT reports '$state', not TIMEOUT — arm C would prove nothing"
    fi

    echo "pd-update-check-probe"
    echo "  tool ......... $TOOL   (second: $SECOND_TOOL)"
    echo "  runs per arm . $RUNS"
    echo "  arms ......... $ARMS"
    echo "  bound ........ ${BOUND}s per invocation"
    if [ "$SILENT" -eq 1 ]; then
        echo "  -silent ...... present (the real web.httpx argv)"
    else
        echo "  -silent ...... ABSENT (--no-silent)"
    fi
    echo "  blackhole .... 127.0.0.1:$BH_PORT (verified: $state)"
    echo "  refused port . 127.0.0.1:$REFUSED_PORT"
    echo "  temp root .... $TMPROOT"
    echo
    printf 'arm\trun\ttool\tnet\tflag\tsecs\trc\toutfile\trecords\taccepts\n'

    local i
    if arm_selected A; then
        for i in $(seq 1 "$RUNS"); do
            run_once A "$i" "$TOOL" reachable "$TMPROOT/cache/A-$i" noflag
        done
    fi
    if arm_selected B; then
        for i in $(seq 1 "$RUNS"); do
            run_once B "$i" "$TOOL" refused "$TMPROOT/cache/B-$i" noflag
        done
    fi
    if arm_selected C; then
        for i in $(seq 1 "$RUNS"); do
            run_once C "$i" "$TOOL" blackholed "$TMPROOT/cache/C-$i" noflag
        done
    fi
    if arm_selected D; then
        for i in $(seq 1 "$RUNS"); do
            run_once D "$i" "$TOOL" blackholed "$TMPROOT/cache/D-$i" flag
        done
    fi
    if arm_selected E; then
        # ONE cache dir, primed by a reachable run, then reused. The point of the
        # arm is the second and later runs.
        mkdir -p "$TMPROOT/cache/E"
        for i in $(seq 1 "$RUNS"); do
            run_once E "$i" "$TOOL" reachable "$TMPROOT/cache/E" noflag
        done
    fi
    if arm_selected F; then
        if [ "$have_second" -eq 1 ]; then
            for i in $(seq 1 "$RUNS"); do
                run_once F "$i" "$SECOND_TOOL" blackholed "$TMPROOT/cache/F-$i" noflag
            done
        else
            printf 'F\t-\t%s\t-\t-\t-\t-\t-\t-\tNOT RUN: %s absent\n' "$SECOND_TOOL" "$SECOND_TOOL"
        fi
    fi

    echo
    echo "reading the table:"
    echo "  rc=124 means the bound fired — the tool was still running. A hang IS the measurement."
    echo "  accepts is how many connections the blackhole took during that run. An arm that"
    echo "  hung with accepts=0 did NOT hang on the proxied dependency and says nothing about M1."
    cleanup
    return 0
}

# ── arguments ───────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --self-check) SELF_CHECK=1 ;;
        --no-silent) SILENT=0 ;;
        --tool)
            shift
            TOOL="${1:-}"
            ;;
        --second-tool)
            shift
            SECOND_TOOL="${1:-}"
            ;;
        --runs)
            shift
            RUNS="${1:-3}"
            ;;
        --arms)
            shift
            ARMS="${1:-A,B,C,D,E,F}"
            ;;
        --bound)
            shift
            BOUND="${1:-60}"
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH (required for the blackhole listener)"

if [ "$SELF_CHECK" -eq 1 ]; then
    self_check
    exit $?
fi
run_matrix
exit $?
