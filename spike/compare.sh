#!/usr/bin/env bash
# spike/compare.sh — runs both spikes against same target, emits spike/comparison.json
# with all 6 metrics from .planning/phases/01-language-adr-spike/01-RESEARCH.md §2.1
# (M1 LoC, M2 hours-from-sessions-log, M3 packaging bytes, M4 kill-tree pass/fail,
# M5 RSS kB, M6 cross-platform ordinal).
#
# Usage: ./spike/compare.sh [TARGET]      # default: example.com
# Output: spike/comparison.json
# Exit codes: 0 = both spikes ran cleanly; 1 = at least one spike missing or failed.
#
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-PLAN.md Task 3

set -euo pipefail

TARGET="${1:-example.com}"
OUT="spike/comparison.json"
SESSIONS_LOG="spike/.spike_sessions.log"

# OS-aware /usr/bin/time invocation: macOS uses -l (BSD), Linux uses -v (GNU).
if [[ "$(uname -s)" == "Darwin" ]]; then
    TIME_FLAG="-l"
    RSS_GREP_KEY="maximum resident set size"
    RSS_FIELD=1       # awk field for BSD time -l (bytes -- convert to kB later)
    RSS_UNIT="bytes"
else
    TIME_FLAG="-v"
    RSS_GREP_KEY="Maximum resident set size"
    RSS_FIELD=6       # awk field for GNU time -v (kB)
    RSS_UNIT="kb"
fi

GO_BIN="spike/go/bin/spike"
# PY_BIN points at the PyInstaller --onefile binary per OQ3 INCLUDE (shape-parity with Go's single binary).
# Measuring against this path is the canonical M5 RSS measurement target -- measuring against the
# .venv wrapper script would systematically under-measure Python's actual process RSS.
PY_BIN="spike/python/dist/spike"

# Initialize metric vars to "NA" so absent measurements render cleanly in JSON.
GO_LOC="NA"
GO_HOURS="NA"
GO_BINSIZE="NA"
GO_KILLTREE="NA"
GO_RSS="NA"
GO_XPLAT="NA"
PY_LOC="NA"
PY_HOURS="NA"
PY_VENV_KB="NA"
PY_PYINSTALLER_BIN="NA"
PY_KILLTREE="NA"
PY_RSS="NA"
PY_XPLAT="NA"
SUB_DIFF_LINES="NA"

# M1: LoC (tokei preferred, cloc fallback) ────────────────────────────────────
extract_loc() {
    local dir="$1"
    local lang="$2"
    if command -v tokei >/dev/null 2>&1; then
        tokei "$dir" --output json 2>/dev/null | jq -r ".${lang}.code // \"NA\""
    elif command -v cloc >/dev/null 2>&1; then
        cloc "$dir" --json 2>/dev/null | jq -r ".${lang}.code // \"NA\""
    else
        printf "NA"
    fi
}
[[ -d spike/go ]] && GO_LOC=$(extract_loc spike/go Go | head -1)
[[ -d spike/python ]] && PY_LOC=$(extract_loc spike/python Python | head -1)

# M2: Hours (sum from .spike_sessions.log; format: "<lang> <minutes>" per line) ─
if [[ -f "$SESSIONS_LOG" ]]; then
    GO_HOURS=$(awk '$1=="go"     {s+=$2} END {if (s>0) print s/60; else print "NA"}' "$SESSIONS_LOG")
    PY_HOURS=$(awk '$1=="python" {s+=$2} END {if (s>0) print s/60; else print "NA"}' "$SESSIONS_LOG")
fi

# Run Go spike (if binary present) ────────────────────────────────────────────
if [[ -x "$GO_BIN" ]]; then
    mkdir -p spike/go/out
    /usr/bin/time "$TIME_FLAG" "$GO_BIN" --target "$TARGET" \
        >spike/go/out/run.log 2>spike/go/out/run.err || echo "[WARN] go spike exited non-zero" >&2
    GO_RSS=$(grep -m1 "$RSS_GREP_KEY" spike/go/out/run.err 2>/dev/null | awk -v f="$RSS_FIELD" '{print $f}' || echo "NA")
    [[ "$RSS_UNIT" == "bytes" && "$GO_RSS" != "NA" ]] && GO_RSS=$((GO_RSS / 1024))
    GO_BINSIZE=$(stat -f%z "$GO_BIN" 2>/dev/null || stat -c%s "$GO_BIN" 2>/dev/null || echo "NA")
    # M4: kill-tree pass/fail from test suite (Plan 01-02 writes spike/go/out/.killtree_result = PASS|FAIL).
    [[ -f spike/go/out/.killtree_result ]] && GO_KILLTREE=$(cat spike/go/out/.killtree_result)
    # M6: cross-platform ordinal (Plan 01-02 writes spike/go/out/.xplat_ordinal = 1|2|3).
    [[ -f spike/go/out/.xplat_ordinal ]] && GO_XPLAT=$(cat spike/go/out/.xplat_ordinal)
else
    echo "[SKIP] $GO_BIN not built -- run: make -C spike/go build" >&2
fi

# Run Python spike (if binary present) ────────────────────────────────────────
# PY_BIN is spike/python/dist/spike (PyInstaller --onefile per OQ3) -- shape-parity with Go binary.
if [[ -x "$PY_BIN" ]]; then
    mkdir -p spike/python/out
    /usr/bin/time "$TIME_FLAG" "$PY_BIN" --target "$TARGET" \
        >spike/python/out/run.log 2>spike/python/out/run.err || echo "[WARN] python spike exited non-zero" >&2
    PY_RSS=$(grep -m1 "$RSS_GREP_KEY" spike/python/out/run.err 2>/dev/null | awk -v f="$RSS_FIELD" '{print $f}' || echo "NA")
    [[ "$RSS_UNIT" == "bytes" && "$PY_RSS" != "NA" ]] && PY_RSS=$((PY_RSS / 1024))
    # M3a: venv size (kB) -- reference only, NOT the apples-to-apples M5 measurement target
    [[ -d spike/python/.venv ]] && PY_VENV_KB=$(du -sk spike/python/.venv 2>/dev/null | awk '{print $1}' || echo "NA")
    # M3b: PyInstaller single-binary size (bytes) -- OQ3 locked INCLUDE -- same binary as PY_BIN above.
    [[ -f spike/python/dist/spike ]] && PY_PYINSTALLER_BIN=$(stat -f%z spike/python/dist/spike 2>/dev/null || stat -c%s spike/python/dist/spike 2>/dev/null || echo "NA")
    # M4
    [[ -f spike/python/out/.killtree_result ]] && PY_KILLTREE=$(cat spike/python/out/.killtree_result)
    # M6
    [[ -f spike/python/out/.xplat_ordinal ]] && PY_XPLAT=$(cat spike/python/out/.xplat_ordinal)
else
    echo "[SKIP] $PY_BIN not built -- run: make -C spike/python build (PyInstaller --onefile)" >&2
fi

# Subdomain-set diff (advisory): both spikes' subs.jsonl vs baseline ──────────
if [[ -f spike/go/out/subs.jsonl && -f spike/python/out/subs.jsonl ]]; then
    GO_SUBS=$(jq -r '.subdomain // empty' spike/go/out/subs.jsonl 2>/dev/null | sort -u)
    PY_SUBS=$(jq -r '.subdomain // empty' spike/python/out/subs.jsonl 2>/dev/null | sort -u)
    SUB_DIFF_LINES=$(diff <(echo "$GO_SUBS") <(echo "$PY_SUBS") 2>/dev/null | wc -l | awk '{print $1}')
fi

# Emit comparison.json ────────────────────────────────────────────────────────
cat >"$OUT" <<EOF
{
  "target":    "$TARGET",
  "timestamp": "$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')",
  "platform":  "$(uname -srm)",
  "go": {
    "loc":             $( [[ "$GO_LOC" == "NA" ]] && echo "null" || echo "$GO_LOC" ),
    "hours":           $( [[ "$GO_HOURS" == "NA" ]] && echo "null" || echo "$GO_HOURS" ),
    "binary_bytes":    $( [[ "$GO_BINSIZE" == "NA" ]] && echo "null" || echo "$GO_BINSIZE" ),
    "killtree":        "$GO_KILLTREE",
    "rss_kb":          $( [[ "$GO_RSS" == "NA" ]] && echo "null" || echo "$GO_RSS" ),
    "xplat_ordinal":   $( [[ "$GO_XPLAT" == "NA" ]] && echo "null" || echo "$GO_XPLAT" )
  },
  "python": {
    "loc":             $( [[ "$PY_LOC" == "NA" ]] && echo "null" || echo "$PY_LOC" ),
    "hours":           $( [[ "$PY_HOURS" == "NA" ]] && echo "null" || echo "$PY_HOURS" ),
    "venv_kb":         $( [[ "$PY_VENV_KB" == "NA" ]] && echo "null" || echo "$PY_VENV_KB" ),
    "pyinstaller_bin": $( [[ "$PY_PYINSTALLER_BIN" == "NA" ]] && echo "null" || echo "$PY_PYINSTALLER_BIN" ),
    "killtree":        "$PY_KILLTREE",
    "rss_kb":          $( [[ "$PY_RSS" == "NA" ]] && echo "null" || echo "$PY_RSS" ),
    "xplat_ordinal":   $( [[ "$PY_XPLAT" == "NA" ]] && echo "null" || echo "$PY_XPLAT" )
  },
  "mcp_lib_support": { "go": 1, "python": 1, "note": "Both v1.x stable per RESEARCH.md §5; not a tie-breaker" },
  "subdomain_set_diff_lines": $( [[ "$SUB_DIFF_LINES" == "NA" ]] && echo "null" || echo "$SUB_DIFF_LINES" )
}
EOF

echo "Wrote $OUT"

# Exit 1 if either spike binary missing -- Plan 01-04 (ADR draft) gates on both being present.
if [[ ! -x "$GO_BIN" || ! -x "$PY_BIN" ]]; then
    exit 1
fi
exit 0
