#!/bin/bash
# reconFTW Validation Library
# Provides type checking and input validation functions

set -o pipefail

# Error codes
readonly E_INVALID_DOMAIN=20
readonly E_INVALID_IP=21
readonly E_INVALID_PATH=22
readonly E_INVALID_URL=23
readonly E_INVALID_EMAIL=24

# validate_domain()
# Description: Validates a domain name format
# Arguments: $1 - Domain string to validate
# Returns: 0 if valid, 1 if invalid
function validate_domain() {
	local domain="$1"

	# Check if empty
	if [[ -z "$domain" ]]; then
		return $E_INVALID_DOMAIN
	fi

	# Check for command injection characters
	if echo "$domain" | grep -qE '[;|&$`\\(){}]'; then
		return $E_INVALID_DOMAIN
	fi

	# Check if it's an IP address (valid for scanning)
	if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		# Validate IP octets
		local IFS='.'
		local -a octets
		read -ra octets <<<"$domain"
		for octet in "${octets[@]}"; do
			if [[ "$octet" -lt 0 || "$octet" -gt 255 ]]; then
				return $E_INVALID_DOMAIN
			fi
		done
		return 0
	fi

	# Validate domain name format (simplified RFC check)
	if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
		return $E_INVALID_DOMAIN
	fi

	# Check total length
	if [[ ${#domain} -gt 253 ]]; then
		return $E_INVALID_DOMAIN
	fi

	return 0
}

# NOTE: sanitize_domain() is defined in modules/utils.sh
# This avoids duplication and ensures consistent behavior

# validate_ipv4()
# Description: Validates an IPv4 address
# Arguments: $1 - IP string to validate
# Returns: 0 if valid, 1 if invalid
function validate_ipv4() {
	local ip="$1"

	if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		return $E_INVALID_IP
	fi

	local IFS='.'
	local -a octets
	read -ra octets <<<"$ip"

	if [[ ${#octets[@]} -ne 4 ]]; then
		return $E_INVALID_IP
	fi

	for octet in "${octets[@]}"; do
		if [[ ! "$octet" =~ ^[0-9]+$ ]]; then
			return $E_INVALID_IP
		fi
		if [[ "$octet" -lt 0 || "$octet" -gt 255 ]]; then
			return $E_INVALID_IP
		fi
	done

	return 0
}

# validate_boolean()
# Description: Validates a boolean value
# Arguments: $1 - Value to validate
# Returns: 0 if valid boolean, 1 otherwise
function validate_boolean() {
	local value="$1"

	if [[ "$value" =~ ^(true|false|1|0|yes|no)$ ]]; then
		return 0
	fi

	return 1
}

# validate_integer()
# Description: Validates an integer within optional range
# Arguments: $1 - Value, $2 - Min (optional), $3 - Max (optional)
# Returns: 0 if valid, 1 if invalid
function validate_integer() {
	local value="$1"
	local min="${2:-}"
	local max="${3:-}"

	if [[ ! "$value" =~ ^-?[0-9]+$ ]]; then
		return 1
	fi

	if [[ -n "$min" && "$value" -lt "$min" ]]; then
		return 1
	fi

	if [[ -n "$max" && "$value" -gt "$max" ]]; then
		return 1
	fi

	return 0
}

# validate_port()
# Description: Validates a TCP/UDP port number
# Arguments: $1 - Port number
# Returns: 0 if valid port (1-65535), 1 otherwise
function validate_port() {
	local port="$1"
	validate_integer "$port" 1 65535
}

# sanitize_path()
# Description: Sanitizes a file path
# Arguments: $1 - Path to sanitize
# Returns: Echoes sanitized path
function sanitize_path() {
	local path="$1"

	# Remove control characters
	path=$(printf '%s' "$path" | tr -d '\000-\037')

	# Remove trailing slashes (except root)
	if [[ "$path" != "/" ]]; then
		path=$(printf '%s' "$path" | sed 's:/*$::')
	fi

	# Normalize path
	path=$(printf '%s' "$path" | sed 's://*:/:g')

	printf '%s' "$path"
}

# sanitize_interlace_input()
# Description: Sanitizes input for interlace tool
# Arguments: $1 - Input file, $2 - Output file (optional)
# Returns: 0 on success
function sanitize_interlace_input() {
	local infile="$1"
	local outfile="${2:-$1}"

	# Remove lines containing shell metacharacters
	local pattern='[;|&$`\(){}]'

	if [[ "$infile" == "$outfile" ]]; then
		local tmpfile
		tmpfile=$(mktemp)
		grep -v "$pattern" "$infile" >"$tmpfile" 2>/dev/null || true
		mv "$tmpfile" "$outfile"
	else
		grep -v "$pattern" "$infile" >"$outfile" 2>/dev/null || true
	fi

	return 0
}

# is_empty()
# Description: Checks if a value is empty
# Arguments: $1 - Value to check
# Returns: 0 if empty, 1 if not empty
function is_empty() {
	local value="$1"

	if [[ -z "${value// /}" ]]; then
		return 0
	fi

	return 1
}

# is_numeric()
# Description: Checks if a value is numeric
# Arguments: $1 - Value to check
# Returns: 0 if numeric, 1 if not
function is_numeric() {
	local value="$1"

	if [[ "$value" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
		return 0
	fi

	return 1
}
