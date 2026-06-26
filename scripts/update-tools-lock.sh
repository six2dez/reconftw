#!/usr/bin/env bash
#
# update-tools-lock.sh — XCUT-08 supply-chain quarantine workflow helper.
#
# reconFTW v2 pins every orchestrated Go/Python tool to a specific version in
# internal/core/backend/tools.lock. Bumping a pin is a SUPPLY-CHAIN action: a
# compromised upstream release could ship malware. The XCUT-08 policy therefore
# requires a QUARANTINE WINDOW of 24-72h between a new upstream version
# appearing and updating the lockfile, during which the maintainer watches for
# yanks / advisories / community reports.
#
# This script is documentation AND automation. By default it only REPORTS
# candidate updates (resolves @latest for each pinned tool and diffs against the
# current pin). It NEVER edits tools.lock unless `--apply` is passed explicitly,
# which must happen only AFTER the quarantine window has been observed manually.
#
# Usage:
#   scripts/update-tools-lock.sh --all                       # list all Go-tool candidates
#   scripts/update-tools-lock.sh --tool subfinder            # one tool
#   scripts/update-tools-lock.sh --tool subfinder --apply    # bump the pin (post-quarantine)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TOOLS_LOCK="${REPO_ROOT}/internal/core/backend/tools.lock"

ALL=false
APPLY=false
ONE_TOOL=""

usage() {
	grep '^#' "${BASH_SOURCE[0]}" | sed 's/^#//; s/^ //'
	exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--all) ALL=true ;;
	--tool)
		shift
		ONE_TOOL="${1:-}"
		[[ -n "$ONE_TOOL" ]] || {
			echo "ERROR: --tool requires a tool name" >&2
			exit 2
		}
		;;
	--apply) APPLY=true ;;
	-h | --help) usage 0 ;;
	*)
		echo "ERROR: unknown argument: $1" >&2
		usage 2
		;;
	esac
	shift
done

if [[ "$ALL" == false && -z "$ONE_TOOL" ]]; then
	echo "ERROR: pass --all or --tool <name>" >&2
	usage 2
fi

[[ -f "$TOOLS_LOCK" ]] || {
	echo "ERROR: tools.lock not found at $TOOLS_LOCK" >&2
	exit 1
}
command -v go >/dev/null 2>&1 || {
	echo "ERROR: 'go' is required to resolve @latest versions" >&2
	exit 1
}

# emit "name|go_module|version" for every kind=go tool block in tools.lock.
go_tools() {
	awk '
		/^\[\[tools\]\]/ { name=""; kind=""; mod=""; ver="" }
		/^name[ \t]*=/   { gsub(/.*"([^"]*)".*/, "\\1"); name=$0 }
		/^kind[ \t]*=/   { gsub(/.*"([^"]*)".*/, "\\1"); kind=$0 }
		/^go_module[ \t]*=/ { gsub(/.*"([^"]*)".*/, "\\1"); mod=$0 }
		/^version[ \t]*=/ { gsub(/.*"([^"]*)".*/, "\\1"); ver=$0 }
		/^$/ { if (kind=="go" && mod!="") print name "|" mod "|" ver }
		END  { if (kind=="go" && mod!="") print name "|" mod "|" ver }
	' "$TOOLS_LOCK"
}

candidates=0
while IFS='|' read -r name mod current; do
	[[ -n "$name" ]] || continue
	if [[ -n "$ONE_TOOL" && "$name" != "$ONE_TOOL" ]]; then
		continue
	fi
	latest="$(go list -m -versions -json "${mod}@latest" 2>/dev/null | grep -o '"Version": *"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/' || true)"
	if [[ -z "$latest" ]]; then
		echo "WARN: could not resolve latest for ${name} (${mod})" >&2
		continue
	fi
	if [[ "$current" == "$latest" ]]; then
		continue
	fi
	candidates=$((candidates + 1))
	echo "CANDIDATE: ${name}  ${current:-<unpinned>} -> ${latest}"
	if [[ "$APPLY" == true && -n "$ONE_TOOL" && "$name" == "$ONE_TOOL" ]]; then
		# Bump only the version line that belongs to this tool's block.
		awk -v t="$name" -v new="$latest" '
			/^\[\[tools\]\]/ { inblk=0 }
			$0 ~ "^name[ \t]*=[ \t]*\"" t "\"" { inblk=1 }
			inblk==1 && /^version[ \t]*=/ { sub(/"[^"]*"/, "\"" new "\""); inblk=2 }
			{ print }
		' "$TOOLS_LOCK" >"${TOOLS_LOCK}.tmp"
		mv "${TOOLS_LOCK}.tmp" "$TOOLS_LOCK"
		echo "APPLIED: ${name} pinned to ${latest} in tools.lock"
	fi
done < <(go_tools)

echo ""
echo "--- QUARANTINE REQUIRED (XCUT-08): wait 24-72h before bumping a pin. ---"
echo "    During the window, watch for upstream yanks / security advisories."
echo "    Verify a candidate before --apply:  go install <module>@<new-version>"
if [[ "$APPLY" == true ]]; then
	echo ""
	echo "Pin(s) updated. Re-validate the manifest:  go test ./internal/core/backend/..."
elif [[ "$candidates" -eq 0 ]]; then
	echo ""
	echo "No candidate updates — all pinned Go tools are current."
fi
