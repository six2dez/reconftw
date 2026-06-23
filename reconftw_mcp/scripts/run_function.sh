#!/usr/bin/env bash
# Run a single reconFTW module function with minimal workspace init.
# Usage: run_function.sh <domain> <function_name>
set -euo pipefail

DOMAIN="${1:?domain required}"
FUNC="${2:?function required}"
ROOT="${RECONFTW_ROOT:?RECONFTW_ROOT must be set}"

cd "$ROOT"
export domain="$DOMAIN"
export NOW="${NOW:-$(date +"%F")}"
export NOWT="${NOWT:-$(date +"%T")}"
export dir="${ROOT}/Recon/${DOMAIN}"
export called_fn_dir="${dir}/.called_fn"
export LOGFILE="${dir}/.log/mcp_${NOW}_${NOWT}.txt"
export DEBUG_LOG="${dir}/debug.log"

mkdir -p "${dir}/.called_fn" "${dir}/.log" "${dir}/.tmp"
touch "$LOGFILE" "$DEBUG_LOG"

# shellcheck source=/dev/null
source "${ROOT}/reconftw.sh" --source-only

# Same config chain as main CLI (reconftw.cfg → secrets.cfg → MCP profile → exports)
# shellcheck source=/dev/null
source "${ROOT}/lib/config.sh"
load_reconftw_config "$ROOT"
load_mcp_profile
export AXIOM="${AXIOM:-false}"

cd "$dir"
init_dns_resolver 2>>"$LOGFILE" || true
run_module_with_axiom_failover "$FUNC"
