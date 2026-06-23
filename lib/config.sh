#!/bin/bash
# reconFTW configuration loader — reconftw.cfg, secrets.cfg, runtime exports.
# Sourced by reconftw.sh and MCP run_function.sh. Do not execute directly.

[[ -n "${_RECONFTW_CONFIG_SH_LOADED:-}" ]] && return 0
_RECONFTW_CONFIG_SH_LOADED=1

# Variables from secrets.cfg / reconftw.cfg that child processes (Python AI, tools) need.
_RECONFTW_EXPORT_VARS=(
    AI_BASE_URL AI_API_KEY AI_PROVIDER AI_MODEL AI_REMOTE_ONLY AI_SKIP_HEALTHCHECK
    AI_INTEGRATOR AI_REPORT_TYPE AI_REPORT_PROFILE AI_TIMEOUT_SECONDS AI_ALLOW_MODEL_PULL
    AI_MAX_CHARS_PER_FILE AI_MAX_FILES_PER_CATEGORY AI_REDACT AI_STRICT AI_PROMPTS_FILE
    OPENAI_API_KEY ANTHROPIC_API_KEY
    RECONFTW_ROOT RECONFTW_TOOLS SCRIPTPATH tools
    SHODAN_API_KEY WHOISXML_API PDCP_API_KEY VIRUSTOTAL_API_KEY
    GITHUB_TOKEN GITLAB_TOKEN GITHUB_TOKENS GITLAB_TOKENS
    XSS_SERVER COLLAB_SERVER slack_channel slack_auth
    SLACK_WEBHOOK_URL DISCORD_WEBHOOK_URL
)

# Export non-empty runtime variables for subprocesses (Python CLI, axiom-scan, etc.).
export_reconftw_runtime_env() {
    local v
    for v in "${_RECONFTW_EXPORT_VARS[@]}"; do
        [[ -n "${!v:-}" ]] && export "$v"
    done
    # Default RECONFTW_ROOT for MCP / Python when only SCRIPTPATH is set.
    if [[ -z "${RECONFTW_ROOT:-}" && -n "${SCRIPTPATH:-}" ]]; then
        export RECONFTW_ROOT="${SCRIPTPATH}"
    fi
}

# Load reconftw.cfg + secrets.cfg from repo root.
# Usage: load_reconftw_config [root_dir]
load_reconftw_config() {
    local root="${1:-${SCRIPTPATH:-}}"
    if [[ -z "$root" ]]; then
        echo "load_reconftw_config: root directory required" >&2
        return 1
    fi
    export SCRIPTPATH="$root"
    . "${root}/reconftw.cfg" || return 1
    if [[ -f "${root}/secrets.cfg" ]]; then
        # shellcheck source=/dev/null
        . "${root}/secrets.cfg"
    fi
    export_reconftw_runtime_env
    return 0
}

# Optional MCP profile overlay (after load_reconftw_config).
load_mcp_profile() {
    if [[ -n "${RECONFTW_MCP_PROFILE:-}" && -f "${RECONFTW_MCP_PROFILE}" ]]; then
        # shellcheck source=/dev/null
        . "${RECONFTW_MCP_PROFILE}"
    fi
}
