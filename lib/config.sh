#!/bin/bash
# reconFTW Configuration Loader
# Loads configuration from hierarchical config directory
# Priority (low to high): defaults → config/*.conf → secrets.conf → environment variables
#
# NOTE: This module is NOT currently active. Configuration is loaded from reconftw.cfg.
# This modular config system is preparatory code for future improvements when we want
# to split the monolithic reconftw.cfg into organized sections under config/*.conf.
# To activate: source this file from reconftw.sh instead of directly sourcing reconftw.cfg.

set -o pipefail

# Base configuration directory
RECONFTW_CONFIG_DIR="${RECONFTW_CONFIG_DIR:-${SCRIPTPATH}/config}"

# Error codes
readonly E_CONFIG_NOT_FOUND=10
readonly E_CONFIG_INVALID=11
readonly E_CONFIG_SYNTAX=12

# Configuration sections and their files
# Order matters - loaded in this sequence
declare -a CONFIG_SECTIONS=(
	"00-global.conf"        # Global settings, paths, defaults
	"10-osint.conf"         # OSINT module configuration
	"20-subdomains.conf"    # Subdomain enumeration settings
	"30-web.conf"           # Web analysis settings
	"40-vulns.conf"         # Vulnerability scanning settings
	"50-performance.conf"   # Performance and threading
	"60-notifications.conf" # Notification settings
	"70-advanced.conf"      # Advanced features
	"90-secrets.conf"       # API keys and secrets (gitignored)
)

# load_config_hierarchical()
# Description: Loads all configuration files in order
# Arguments: None
# Returns: 0 on success, exits on critical error
# Side effects: Sets global configuration variables
function load_config_hierarchical() {
	local config_dir="${1:-$RECONFTW_CONFIG_DIR}"
	local errors=0
	local warnings=0

	# Validate config directory exists
	if [[ ! -d "$config_dir" ]]; then
		printf "[ERROR] Configuration directory not found: %s\n" "$config_dir" >&2
		exit $E_CONFIG_NOT_FOUND
	fi

	# Load each configuration section in order
	for section in "${CONFIG_SECTIONS[@]}"; do
		local conf_file="${config_dir}/${section}"
		if [[ -f "$conf_file" ]]; then
			if ! _load_config_file "$conf_file"; then
				errors=$((errors + 1))
			fi
		fi
	done

	# Apply environment variable overrides
	_apply_env_overrides

	# Validate loaded configuration
	if ! validate_config; then
		printf "[ERROR] Configuration validation failed\n" >&2
		errors=$((errors + 1))
	fi

	if [[ $errors -gt 0 ]]; then
		printf "[WARN] %d configuration errors detected\n" "$errors" >&2
		return 1
	fi

	return 0
}

# _load_config_file()
# Description: Safely loads a single configuration file
# Arguments: $1 - Path to config file
# Returns: 0 on success, 1 on failure
function _load_config_file() {
	local conf_file="$1"

	# Security: Check file permissions
	local perms
	perms=$(stat -c "%a" "$conf_file" 2>/dev/null || stat -f "%Lp" "$conf_file" 2>/dev/null)
	if [[ -n "$perms" && "$perms" -gt 644 ]]; then
		printf "[WARN] Config file has overly permissive permissions (%s): %s\n" "$perms" "$conf_file" >&2
	fi

	# Check for dangerous patterns before sourcing
	if grep -qE '(eval[[:space:]]|\$\(.*\)|`.*`|rm[[:space:]]+-rf)' "$conf_file" 2>/dev/null; then
		printf "[ERROR] Config file contains potentially dangerous commands: %s\n" "$conf_file" >&2
		return $E_CONFIG_INVALID
	fi

	# Source the file with error handling
	if ! source "$conf_file" 2>/dev/null; then
		printf "[ERROR] Failed to load config file: %s\n" "$conf_file" >&2
		return $E_CONFIG_SYNTAX
	fi

	return 0
}

# _apply_env_overrides()
# Description: Overrides config values with environment variables
# Arguments: None
# Returns: 0
function _apply_env_overrides() {
	# List of variables that can be overridden via environment
	local -a override_vars=(
		"tools"
		"dir_output"
		"SHOW_COMMANDS"
		"MIN_DISK_SPACE_GB"
		"SHODAN_API_KEY"
		"WHOISXML_API"
		"XSS_SERVER"
		"COLLAB_SERVER"
		"slack_channel"
		"slack_auth"
		"OSINT"
		"SUBDOMAINS_GENERAL"
		"VULNS_GENERAL"
		"DEEP"
		"AXIOM"
		"NOTIFICATION"
		"FARADAY"
		"FFUF_THREADS"
		"HTTPX_THREADS"
		"HTTPX_RATELIMIT"
		"NUCLEI_RATELIMIT"
		"INCREMENTAL_MODE"
		"ADAPTIVE_RATE_LIMIT"
		"STRUCTURED_LOGGING"
		"ASSET_STORE"
		"QUICK_RESCAN"
	)

	for var in "${override_vars[@]}"; do
		local env_val
		env_val=$(printenv "$var" 2>/dev/null)
		if [[ -n "$env_val" ]]; then
			if _validate_config_var "$var" "$env_val"; then
				declare -g "$var=$env_val"
			fi
		fi
	done
}

# _validate_config_var()
# Description: Validates a configuration variable value
# Arguments: $1 - Variable name, $2 - Value
# Returns: 0 if valid, 1 if invalid
function _validate_config_var() {
	local var="$1"
	local value="$2"

	# Boolean validation
	if [[ "$var" =~ ^(OSINT|SUBDOMAINS_GENERAL|VULNS_GENERAL|DEEP|AXIOM|NOTIFICATION|FARADAY|INCREMENTAL_MODE|ADAPTIVE_RATE_LIMIT|STRUCTURED_LOGGING|ASSET_STORE|QUICK_RESCAN)$ ]]; then
		if [[ ! "$value" =~ ^(true|false)$ ]]; then
			printf "[WARN] Invalid boolean value for %s: %s (expected true/false)\n" "$var" "$value" >&2
			return 1
		fi
	fi

	# Numeric validation
	if [[ "$var" =~ _THREADS$|_RATELIMIT$|_TIMEOUT$ ]]; then
		if [[ ! "$value" =~ ^[0-9]+$ ]]; then
			printf "[WARN] Invalid numeric value for %s: %s\n" "$var" "$value" >&2
			return 1
		fi
	fi

	return 0
}

# validate_config()
# Description: Performs comprehensive configuration validation
# Arguments: None
# Returns: 0 if valid, 1 if errors found
function validate_config() {
	local warnings=0
	local errors=0

	# Check conflicting configurations
	if [[ "${VULNS_GENERAL:-false}" == true && "${SUBDOMAINS_GENERAL:-false}" == false ]]; then
		printf "[WARN] VULNS_GENERAL=true but SUBDOMAINS_GENERAL=false\n" >&2
		warnings=$((warnings + 1))
	fi

	# Validate numeric variables
	local -a numeric_vars=(
		"FFUF_THREADS"
		"HTTPX_THREADS"
		"DALFOX_THREADS"
		"HTTPX_RATELIMIT"
		"NUCLEI_RATELIMIT"
		"MIN_RATE_LIMIT"
		"MAX_RATE_LIMIT"
	)

	for var in "${numeric_vars[@]}"; do
		local var_value
		var_value="${!var:-}"
		if [[ -n "$var_value" && ! "$var_value" =~ ^[0-9]+$ ]]; then
			printf "[ERROR] %s must be numeric, got: %s\n" "$var" "$var_value" >&2
			errors=$((errors + 1))
		fi
	done

	# Check rate limit configuration
	if [[ "${ADAPTIVE_RATE_LIMIT:-false}" == true ]]; then
		if [[ -n "${MIN_RATE_LIMIT:-}" && -n "${MAX_RATE_LIMIT:-}" ]]; then
			if [[ $MIN_RATE_LIMIT -gt $MAX_RATE_LIMIT ]]; then
				printf "[ERROR] MIN_RATE_LIMIT > MAX_RATE_LIMIT\n" >&2
				errors=$((errors + 1))
			fi
		fi
	fi

	# Validate Axiom configuration
	if [[ "${AXIOM:-false}" == true ]]; then
		if ! command -v axiom-scan &>/dev/null; then
			printf "[WARN] AXIOM=true but axiom-scan not found\n" >&2
			warnings=$((warnings + 1))
		fi
	fi

	if [[ $errors -gt 0 ]]; then
		printf "[ERROR] Configuration validation failed\n" >&2
		return 1
	fi

	return 0
}

# config_get()
# Description: Safely retrieves a configuration value
# Arguments: $1 - Variable name, $2 - Default value (optional)
# Returns: Echoes the value
function config_get() {
	local var="$1"
	local default="${2:-}"
	local value

	value="${!var:-$default}"
	printf '%s' "$value"
}

# migrate_legacy_config()
# Description: Migrates old reconftw.cfg to new hierarchical format
# Arguments: $1 - Path to old config file, $2 - New config dir (optional)
# Returns: 0 on success, 1 on failure
function migrate_legacy_config() {
	local old_config="$1"
	local new_config_dir="${2:-$RECONFTW_CONFIG_DIR}"

	if [[ ! -f "$old_config" ]]; then
		printf "[ERROR] Legacy config file not found: %s\n" "$old_config" >&2
		return 1
	fi

	printf "[INFO] Migrating legacy config...\n"
	mkdir -p "$new_config_dir"

	# Create new config files
	# This is a simplified migration - creates basic structure
	cat >"$new_config_dir/00-global.conf" <<'EOF'
#############################################
#           reconFTW Global Config          #
#############################################

tools="$HOME/Tools"
SCRIPTPATH="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"

# Version info
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    reconftw_version="$(git rev-parse --abbrev-ref HEAD)-$(git describe --tags 2>/dev/null || git rev-parse --short HEAD)"
else
    reconftw_version="standalone"
fi

# Resolvers
generate_resolvers=false
update_resolvers=true
resolvers_url="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
resolvers_trusted_url="https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw/trusted_resolvers.txt"

# General options
proxy_url="http://127.0.0.1:8080/"
install_golang=true
upgrade_tools=true
upgrade_before_running=false
SHOW_COMMANDS=false
MIN_DISK_SPACE_GB=5

# Debug output
DEBUG_STD="&>/dev/null"
DEBUG_ERROR="2>/dev/null"
EOF

	printf "[INFO] Migration complete to: %s\n" "$new_config_dir"
	return 0
}
