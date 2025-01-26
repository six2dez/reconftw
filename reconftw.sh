#!/usr/bin/env bash

# Welcome to reconFTW main script
#	 ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █   █████▒▄▄▄█████▓ █     █░
#	▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▓██   ▒ ▓  ██▒ ▓▒▓█░ █ ░█░
#	▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒▒████ ░ ▒ ▓██░ ▒░▒█░ █ ░█
#	▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒░▓█▒  ░ ░ ▓██▓ ░ ░█░ █ ░█
#	░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░░▒█░      ▒██▒ ░ ░░██▒██▓
#	░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒  ▒ ░      ▒ ░░   ░ ▓░▒ ▒
#	  ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░ ░          ░      ▒ ░ ░
#	  ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░  ░ ░      ░        ░   ░
#	   ░        ░  ░░ ░          ░ ░           ░                      ░
#

function banner_grabber() {
	local banner_file="${SCRIPTPATH}/banners.txt"

	# Check if the banner file exists
	if [[ ! -f $banner_file ]]; then
		echo "Banner file not found: $banner_file" >&2
		return 1
	fi

	# Source the banner file
	source "$banner_file"

	# Collect all banner variable names
	mapfile -t banner_vars < <(compgen -A variable | grep '^banner[0-9]\+$')

	# Check if any banners are available
	if [[ ${#banner_vars[@]} -eq 0 ]]; then
		echo "No banners found in $banner_file" >&2
		return 1
	fi

	# Select a random banner
	local rand_index=$((RANDOM % ${#banner_vars[@]}))
	local banner_var="${banner_vars[$rand_index]}"
	local banner_code="${!banner_var}"

	# Output the banner code
	printf "%b\n" "$banner_code"
}

function banner() {
	local banner_code
	if banner_code=$(banner_grabber); then
		printf "\n%b%s" "$bgreen" "$banner_code"
		printf "\n %s                                 by @six2dez%b\n" "$reconftw_version" "$reset"
	else
		printf "\n%bFailed to load banner.%b\n" "$bgreen" "$reset"
	fi
}

###############################################################################################################
################################################### TOOLS #####################################################
###############################################################################################################

function check_version() {

	# Check if git is installed
	if ! command -v git >/dev/null 2>&1; then
		printf "\n%bGit is not installed. Cannot check for updates.%b\n\n" "$bred" "$reset"
		return 1
	fi

	# Check if current directory is a git repository
	if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		printf "\n%bCurrent directory is not a git repository. Cannot check for updates.%b\n\n" "$bred" "$reset"
		return 1
	fi

	# Fetch updates with a timeout
	if ! timeout 10 git fetch >/dev/null 2>&1; then
		printf "\n%bUnable to check updates (git fetch timed out).%b\n\n" "$bred" "$reset"
		return 1
	fi

	# Get current branch name
	local BRANCH
	BRANCH=$(git rev-parse --abbrev-ref HEAD)

	# Get upstream branch
	local UPSTREAM
	UPSTREAM=$(git rev-parse --abbrev-ref --symbolic-full-name "@{u}" 2>/dev/null)
	if [[ -z $UPSTREAM ]]; then
		printf "\n%bNo upstream branch set for '%s'. Cannot check for updates.%b\n\n" "$bred" "$BRANCH" "$reset"
		return 1
	fi

	# Get local and remote commit hashes
	local LOCAL REMOTE
	LOCAL=$(git rev-parse HEAD)
	REMOTE=$(git rev-parse "$UPSTREAM")

	# Compare local and remote hashes
	if [[ $LOCAL != "$REMOTE" ]]; then
		printf "\n%bThere is a new version available. Run ./install.sh to get the latest version.%b\n\n" "$yellow" "$reset"
	fi
}

function tools_installed() {
	# Check if all tools are installed
	printf "\n\n%b#######################################################################%b\n" "$bgreen" "$reset"
	printf "%b[%s] Checking installed tools %b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"

	local all_installed=true
	local missing_tools=()

	# Check environment variables
	local env_vars=("GOPATH" "GOROOT" "PATH")
	for var in "${env_vars[@]}"; do
		if [[ -z ${!var} ]]; then
			printf "%b [*] %s variable\t\t[NO]%b\n" "$bred" "$var" "$reset"
			all_installed=false
			missing_tools+=("$var environment variable")
		fi
	done

	# Define tools and their paths/commands
	declare -A tools_files=(
		["dorks_hunter"]="${tools}/dorks_hunter/dorks_hunter.py"
		["dorks_hunter_python"]="${tools}/dorks_hunter/venv/bin/python3"
		["fav-up"]="${tools}/fav-up/favUp.py"
		["fav-up_python"]="${tools}/fav-up/venv/bin/python3"
		["Corsy"]="${tools}/Corsy/corsy.py"
		["Corsy_python"]="${tools}/Corsy/venv/bin/python3"
		["testssl.sh"]="${tools}/testssl.sh/testssl.sh"
		["CMSeeK"]="${tools}/CMSeeK/cmseek.py"
		["CMSeeK_python"]="${tools}/CMSeeK/venv/bin/python3"
		["OneListForAll"]="$fuzz_wordlist"
		["lfi_wordlist"]="$lfi_wordlist"
		["ssti_wordlist"]="$ssti_wordlist"
		["subs_wordlist"]="$subs_wordlist"
		["subs_wordlist_big"]="$subs_wordlist_big"
		["resolvers"]="$resolvers"
		["resolvers_trusted"]="$resolvers_trusted"
		["getjswords"]="${tools}/getjswords.py"
		["JSA"]="${tools}/JSA/jsa.py"
		["JSA_python"]="${tools}/JSA/venv/bin/python3"
		["CloudHunter"]="${tools}/CloudHunter/cloudhunter.py"
		["CloudHunter_python"]="${tools}/CloudHunter/venv/bin/python3"
		["nmap-parse-output"]="${tools}/ultimate-nmap-parser/ultimate-nmap-parser.sh"
		["pydictor"]="${tools}/pydictor/pydictor.py"
		["smuggler"]="${tools}/smuggler/smuggler.py"
		["regulator"]="${tools}/regulator/main.py"
		["regulator_python"]="${tools}/regulator/venv/bin/python3"
		["nomore403"]="${tools}/nomore403/nomore403"
		["ffufPostprocessing"]="${tools}/ffufPostprocessing/ffufPostprocessing"
		["misconfig-mapper"]="${tools}/misconfig-mapper/misconfig-mapper"
		["spoofy"]="${tools}/Spoofy/spoofy.py"
		["spoofy_python"]="${tools}/Spoofy/venv/bin/python3"
		["swaggerspy"]="${tools}/SwaggerSpy/swaggerspy.py"
		["swaggerspy_python"]="${tools}/SwaggerSpy/venv/bin/python3"
		["LeakSearch"]="${tools}/LeakSearch/LeakSearch.py"
		["LeakSearch_python"]="${tools}/LeakSearch/venv/bin/python3"
		["Oralyzer"]="${tools}/Oralyzer/oralyzer.py"
		["Oralyzer_python"]="${tools}/Oralyzer/venv/bin/python3"
	)

	declare -A tools_folders=(
		["NUCLEI_TEMPLATES_PATH"]="${NUCLEI_TEMPLATES_PATH}"
		["NUCLEI_FUZZING_TEMPLATES_PATH"]="${NUCLEI_FUZZING_TEMPLATES_PATH}"
	)

	declare -A tools_commands=(
		["python3"]="python3"
		["curl"]="curl"
		["wget"]="wget"
		["zip"]="zip"
		["nmap"]="nmap"
		["dig"]="dig"
		["timeout"]="timeout"
		["brutespray"]="brutespray"
		["xnLinkFinder"]="xnLinkFinder"
		["urlfinder"]="urlfinder"
		["github-endpoints"]="github-endpoints"
		["github-subdomains"]="github-subdomains"
		["gitlab-subdomains"]="gitlab-subdomains"
		["katana"]="katana"
		["wafw00f"]="wafw00f"
		["dnsvalidator"]="dnsvalidator"
		["metafinder"]="metafinder"
		["whois"]="whois"
		["dnsx"]="dnsx"
		["gotator"]="gotator"
		["Nuclei"]="nuclei"
		["gf"]="gf"
		["Gxss"]="Gxss"
		["subjs"]="subjs"
		["ffuf"]="ffuf"
		["Massdns"]="massdns"
		["qsreplace"]="qsreplace"
		["interlace"]="interlace"
		["Anew"]="anew"
		["unfurl"]="unfurl"
		["crlfuzz"]="crlfuzz"
		["Httpx"]="httpx"
		["jq"]="jq"
		["notify"]="notify"
		["dalfox"]="dalfox"
		["puredns"]="puredns"
		["emailfinder"]="emailfinder"
		["analyticsrelationships"]="analyticsrelationships"
		["mapcidr"]="mapcidr"
		["ppmap"]="ppmap"
		["cdncheck"]="cdncheck"
		["interactsh-client"]="interactsh-client"
		["tlsx"]="tlsx"
		["smap"]="smap"
		["gitdorks_go"]="gitdorks_go"
		["ripgen"]="ripgen"
		["dsieve"]="dsieve"
		["inscope"]="inscope"
		["enumerepo"]="enumerepo"
		["Web-Cache-Vulnerability-Scanner"]="Web-Cache-Vulnerability-Scanner"
		["subfinder"]="subfinder"
		["ghauri"]="ghauri"
		["hakip2host"]="hakip2host"
		["gau"]="gau"
		["crt"]="crt"
		["gitleaks"]="gitleaks"
		["trufflehog"]="trufflehog"
		["s3scanner"]="s3scanner"
		["mantra"]="mantra"
		["nmapurls"]="nmapurls"
		["porch-pirate"]="porch-pirate"
		["shortscan"]="shortscan"
		["sns"]="sns"
		["sourcemapper"]="sourcemapper"
		["jsluice"]="jsluice"
		["commix"]="commix"
		["urless"]="urless"
		["dnstake"]="dnstake"
	)

	# Check for tool files
	for tool in "${!tools_files[@]}"; do
		if [[ ! -f ${tools_files[$tool]} ]]; then
			#			printf "%b [*] %s\t\t[NO]%b\n" "$bred" "$tool" "$reset"
			all_installed=false
			missing_tools+=("$tool")
		fi
	done

	# Check for tool folders
	for folder in "${!tools_folders[@]}"; do
		if [[ ! -d ${tools_folders[$folder]} ]]; then
			# printf "%b [*] %s\t\t[NO]%b\n" "$bred" "$folder" "$reset"
			all_installed=false
			missing_tools+=("$folder") # Correctly pushing the folder name
		fi
	done

	# Check for tool commands
	for tool in "${!tools_commands[@]}"; do
		if ! command -v "${tools_commands[$tool]}" >/dev/null 2>&1; then
			#			printf "%b [*] %s\t\t[NO]%b\n" "$bred" "$tool" "$reset"
			all_installed=false
			missing_tools+=("$tool")
		fi
	done

	if [[ $all_installed == true ]]; then
		printf "%b\n Good! All tools are installed! %b\n\n" "$bgreen" "$reset"
	else
		printf "\n%bSome tools or directories are missing:%b\n\n" "$yellow" "$reset"
		for tool in "${missing_tools[@]}"; do
			printf "%b - %s %b\n" "$bred" "$tool" "$reset"
		done
		printf "\n%bTry running the installer script again: ./install.sh%b\n" "$yellow" "$reset"
		printf "%bIf it fails, try installing the missing tools manually.%b\n" "$yellow" "$reset"
		printf "%bEnsure that the %b\$tools%b variable is correctly set at the start of this script.%b\n" "$yellow" "$bred" "$yellow" "$reset"
		printf "%bIf you need assistance, feel free to contact me! :D%b\n\n" "$yellow" "$reset"
	fi

	printf "%b[%s] Tools check finished%b\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
	printf "%b#######################################################################\n%b" "$bgreen" "$reset"

	if [[ $CHECK_TOOLS_OR_EXIT == true && $all_installed != true ]]; then
		exit 2
	fi
}

#####################################################################cc##########################################
################################################### OSINT #####################################################
###############################################################################################################

function google_dorks() {
	mkdir -p osint

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GOOGLE_DORKS == true ]] && [[ $OSINT == true ]]; then
		start_func "${FUNCNAME[0]}" "Running: Google Dorks in process"

		"${tools}/dorks_hunter/venv/bin/python3" "${tools}/dorks_hunter/dorks_hunter.py" -d "$domain" -o "osint/dorks.txt"
		end_func "Results are saved in $domain/osint/dorks.txt" "${FUNCNAME[0]}"
	else
		if [[ $GOOGLE_DORKS == false ]] || [[ $OSINT == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s %b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "${FUNCNAME[0]}" "$reset"
		fi
	fi
}

function github_dorks() {
	mkdir -p osint

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GITHUB_DORKS == true ]] && [[ $OSINT == true ]]; then
		start_func "${FUNCNAME[0]}" "Running: Github Dorks in process"

		if [[ -s $GITHUB_TOKENS ]]; then
			if [[ $DEEP == true ]]; then
				if ! gitdorks_go -gd "${tools}/gitdorks_go/Dorks/medium_dorks.txt" -nws 20 -target "$domain" -tf "$GITHUB_TOKENS" -ew 3 | anew -q osint/gitdorks.txt; then
					printf "%b[!] gitdorks_go command failed.%b\n" "$bred" "$reset"
					return 1
				fi
			else
				if ! gitdorks_go -gd "${tools}/gitdorks_go/Dorks/smalldorks.txt" -nws 20 -target "$domain" -tf "$GITHUB_TOKENS" -ew 3 | anew -q osint/gitdorks.txt; then
					printf "%b[!] gitdorks_go command failed.%b\n" "$bred" "$reset"
					return 1
				fi
			fi
		else
			printf "\n%b[%s] Required file %s does not exist or is empty.%b\n" "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$GITHUB_TOKENS" "$reset"
			return 1
		fi
		end_func "Results are saved in $domain/osint/gitdorks.txt" "${FUNCNAME[0]}"
	else
		if [[ $GITHUB_DORKS == false ]] || [[ $OSINT == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s %b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "${FUNCNAME[0]}" "$reset"
		fi
	fi
}

function github_repos() {
	mkdir -p .tmp

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GITHUB_REPOS == true ]] && [[ $OSINT == true ]]; then
		start_func "${FUNCNAME[0]}" "Github Repos analysis in process"

		if [[ -s $GITHUB_TOKENS ]]; then
			GH_TOKEN=$(head -n 1 "$GITHUB_TOKENS")
			echo "$domain" | unfurl format %r >.tmp/company_name.txt

			if ! enumerepo -token-string "$GH_TOKEN" -usernames .tmp/company_name.txt -o .tmp/company_repos.txt 2>>"$LOGFILE" >/dev/null; then
				printf "%b[!] enumerepo command failed.%b\n" "$bred" "$reset"
			fi

			if [[ -s ".tmp/company_repos.txt" ]]; then
				if ! jq -r '.[].repos[]|.url' <.tmp/company_repos.txt >.tmp/company_repos_url.txt 2>>"$LOGFILE"; then
					printf "%b[!] jq command failed.%b\n" "$bred" "$reset"
				fi
			fi

			mkdir -p .tmp/github_repos 2>>"$LOGFILE"
			mkdir -p .tmp/github 2>>"$LOGFILE"

			if [[ -s ".tmp/company_repos_url.txt" ]]; then
				if ! interlace -tL .tmp/company_repos_url.txt -threads "$INTERLACE_THREADS" -c "git clone _target_ .tmp/github_repos/_cleantarget_" 2>>"$LOGFILE" >/dev/null; then
					printf "%b[!] interlace git clone command failed.%b\n" "$bred" "$reset"
					return 1
				fi
			else
				end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
				return 1
			fi

			if [[ -d ".tmp/github_repos/" ]]; then
				ls .tmp/github_repos >.tmp/github_repos_folders.txt
			else
				end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
				return 1
			fi

			if [[ -s ".tmp/github_repos_folders.txt" ]]; then
				if ! interlace -tL .tmp/github_repos_folders.txt -threads "$INTERLACE_THREADS" -c "gitleaks detect --source .tmp/github_repos/_target_ --no-banner --no-color -r .tmp/github/gh_secret_cleantarget_.json" 2>>"$LOGFILE" >/dev/null; then
					printf "%b[!] interlace gitleaks command failed.%b\n" "$bred" "$reset"
					end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
					return 1
				fi
			else
				end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
				return 1
			fi

			if [[ -s ".tmp/company_repos_url.txt" ]]; then
				if ! interlace -tL .tmp/company_repos_url.txt -threads "$INTERLACE_THREADS" -c "trufflehog git _target_ -j 2>&1 | jq -c > _output_/_cleantarget_" -o .tmp/github/ 2>>"$LOGFILE" >/dev/null; then
					printf "%b[!] interlace trufflehog command failed.%b\n" "$bred" "$reset"
					return 1
				fi
			fi

			if [[ -d ".tmp/github/" ]]; then
				if ! cat .tmp/github/* 2>/dev/null | jq -c | jq -r >"osint/github_company_secrets.json" 2>>"$LOGFILE"; then
					printf "%b[!] Error combining results.%b\n" "$bred" "$reset"
					return 1
				fi
			else
				end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
				return 1
			fi

			end_func "Results are saved in $domain/osint/github_company_secrets.json" "${FUNCNAME[0]}"
		else
			printf "\n%s[%s] Required file %s does not exist or is empty.%b\n" "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$GITHUB_TOKENS" "$reset"
			return 1
		fi
	else
		if [[ $GITHUB_REPOS == false ]] || [[ $OSINT == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s %b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "${FUNCNAME[0]}" "$reset"
		fi
	fi
}

function metadata() {
	mkdir -p osint

	# Check if the function should run
	if { [[ ! -f "${called_fn_dir}/.${FUNCNAME[0]}" ]] || [[ ${DIFF} == true ]]; } && [[ ${METADATA} == true ]] && [[ ${OSINT} == true ]] && ! [[ ${domain} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		start_func "${FUNCNAME[0]}" "Scanning metadata in public files"

		# Run metafinder and check for errors
		if ! metafinder -d "${domain}" -l "${METAFINDER_LIMIT}" -o osint -go -bi &>>"${LOGFILE}"; then
			printf "%b[!] metafinder command failed.%b\n" "${bred}" "${reset}"
			return 1
		fi

		# Move result files and check for errors
		if [ -d "osint/${domain}" ] && [ "$(ls -A "osint/${domain}")" ]; then
			if ! mv "osint/${domain}/"*.txt "osint/" 2>>"${LOGFILE}"; then
				printf "%b[!] Failed to move metadata files.%b\n" "${bred}" "${reset}"
				return 1
			fi
		fi

		# Remove temporary directory and check for errors
		if ! rm -rf "osint/${domain}" 2>>"${LOGFILE}"; then
			printf "%b[!] Failed to remove temporary directory.%b\n" "${bred}" "${reset}"
			return 1
		fi

		end_func "Results are saved in ${domain}/osint/[software/authors/metadata_results].txt" "${FUNCNAME[0]}"
	else
		if [[ ${METADATA} == false ]] || [[ ${OSINT} == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "${yellow}" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "${reset}"
		elif [[ ${domain} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			return
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s %b\n\n" "${yellow}" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "${called_fn_dir}" "${FUNCNAME[0]}" "${reset}"
		fi
	fi
}

function apileaks() {
	mkdir -p osint

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } &&
		[[ $API_LEAKS == true ]] && [[ $OSINT == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Scanning for leaks in public API directories"

		# Run porch-pirate and handle errors
		porch-pirate -s "$domain" --dump 2>>"$LOGFILE" >"${dir}/osint/postman_leaks.txt"

		# Change directory to SwaggerSpy
		if ! pushd "${tools}/SwaggerSpy" >/dev/null; then
			printf "%b[!] Failed to change directory to %s in %s at line %s.%b\n" "$bred" "${tools}/SwaggerSpy" "${FUNCNAME[0]}" "$LINENO" "$reset"
			return 1
		fi

		# Run swaggerspy.py and handle errors
		"${tools}/SwaggerSpy/venv/bin/python3" swaggerspy.py "$domain" 2>>"$LOGFILE" | grep -i "[*]\|URL" >"${dir}/osint/swagger_leaks.txt"

		# Return to the previous directory
		if ! popd >/dev/null; then
			printf "%b[!] Failed to return to the previous directory in %s at line %s.%b\n" "$bred" "${FUNCNAME[0]}" "$LINENO" "$reset"
			return 1
		fi

		# Analyze leaks with trufflehog
		if [[ -s "${dir}/osint/postman_leaks.txt" ]]; then
			trufflehog filesystem "${dir}/osint/postman_leaks.txt" -j 2>/dev/null | jq -c | anew -q "${dir}/osint/postman_leaks_trufflehog.json"
		fi

		if [[ -s "${dir}/osint/swagger_leaks.txt" ]]; then
			trufflehog filesystem "${dir}/osint/swagger_leaks.txt" -j 2>/dev/null | jq -c | anew -q "${dir}/osint/swagger_leaks_trufflehog.json"
		fi

		end_func "Results are saved in $domain/osint/[postman_leaks_trufflehog.json, swagger_leaks_trufflehog.json]" "${FUNCNAME[0]}"
	else
		if [[ $API_LEAKS == false ]] || [[ $OSINT == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			return
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s %b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "${FUNCNAME[0]}" "$reset"
		fi
	fi
}

function emails() {
	mkdir -p .tmp osint

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } &&
		[[ $EMAILS == true ]] && [[ $OSINT == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Searching for emails/users/passwords leaks"

		# Run emailfinder and handle errors
		emailfinder -d "$domain" 2>>"$LOGFILE" | anew -q .tmp/emailfinder.txt

		# Process emailfinder results
		if [[ -s ".tmp/emailfinder.txt" ]]; then
			grep "@" .tmp/emailfinder.txt | grep -iv "|_" | anew -q osint/emails.txt
		fi

		# Change directory to LeakSearch
		if ! pushd "${tools}/LeakSearch" >/dev/null; then
			printf "%b[!] Failed to change directory to %s in %s at line %s.%b\n" "$bred" "${tools}/LeakSearch" "${FUNCNAME[0]}" "$LINENO" "$reset"
			return 1
		fi

		# Run LeakSearch.py and handle errors
		"${tools}/LeakSearch/venv/bin/python3" LeakSearch.py -k "$domain" -o "${dir}/.tmp/passwords.txt" 1>>"$LOGFILE"

		# Return to the previous directory
		if ! popd >/dev/null; then
			printf "%b[!] Failed to return to the previous directory in %s at line %s.%b\n" "$bred" "${FUNCNAME[0]}" "$LINENO" "$reset"
			return 1
		fi

		# Process passwords.txt
		if [[ -s "${dir}/.tmp/passwords.txt" ]]; then
			anew -q osint/passwords.txt <"${dir}/.tmp/passwords.txt"
		fi

		end_func "Results are saved in $domain/osint/emails.txt and passwords.txt" "${FUNCNAME[0]}"
	else
		if [[ $EMAILS == false ]] || [[ $OSINT == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			return
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi
}

function domain_info() {

	mkdir -p osint

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } &&
		[[ $DOMAIN_INFO == true ]] && [[ $OSINT == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Searching domain info (whois, registrant name/email domains)"

		# Run whois command and check for errors
		whois -H "$domain" >"osint/domain_info_general.txt"

		# Fetch tenant info using curl and check for errors
		curl -s "https://aadinternals.azurewebsites.net/api/tenantinfo?domainName=${domain}" \
			-H "Origin: https://aadinternals.com" \
			-H "Referer: https://aadinternals.com/" \
			-H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" |
			jq -r '.domains[].name' >"osint/azure_tenant_domains.txt"

		end_func "Results are saved in ${domain}/osint/domain_info_[general/azure_tenant_domains].txt" "${FUNCNAME[0]}"

	else
		if [[ $DOMAIN_INFO == false ]] || [[ $OSINT == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			return
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi
}

function third_party_misconfigs() {
	mkdir -p osint

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } &&
		[[ $THIRD_PARTIES == true ]] && [[ $OSINT == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Searching for third parties misconfigurations"

		# Extract company name from domain
		company_name=$(unfurl format %r <<<"$domain")

		# Change directory to misconfig-mapper tool
		if ! pushd "${tools}/misconfig-mapper" >/dev/null; then
			printf "%b[!] Failed to change directory to %s in %s at line %s.%b\n" \
				"$bred" "${tools}/misconfig-mapper" "${FUNCNAME[0]}" "$LINENO" "$reset"
			return 1
		fi

		# Run misconfig-mapper and handle errors
		./misconfig-mapper -target "$company_name" -service "*" 2>&1 | grep -v "\-\]" | grep -v "Failed" >"${dir}/osint/3rdparts_misconfigurations.txt"

		# Return to the previous directory
		if ! popd >/dev/null; then
			printf "%b[!] Failed to return to previous directory in %s at line %s.%b\n" \
				"$bred" "${FUNCNAME[0]}" "$LINENO" "$reset"
			return 1
		fi

		end_func "Results are saved in $domain/osint/3rdparts_misconfigurations.txt" "${FUNCNAME[0]}"

	else
		if [[ $THIRD_PARTIES == false ]] || [[ $OSINT == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			return
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi
}

function spoof() {
	mkdir -p osint

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } &&
		[[ $SPOOF == true ]] && [[ $OSINT == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Searching for spoofable domains"

		# Change directory to Spoofy tool
		if ! pushd "${tools}/Spoofy" >/dev/null; then
			printf "%b[!] Failed to change directory to %s in %s at line %s.%b\n" \
				"$bred" "${tools}/Spoofy" "${FUNCNAME[0]}" "$LINENO" "$reset"
			return 1
		fi

		# Run spoofy.py and handle errors
		"${tools}/Spoofy/venv/bin/python3" spoofy.py -d "$domain" >"${dir}/osint/spoof.txt"

		# Return to the previous directory
		if ! popd >/dev/null; then
			printf "%b[!] Failed to return to previous directory in %s at line %s.%b\n" \
				"$bred" "${FUNCNAME[0]}" "$LINENO" "$reset"
			return 1
		fi

		end_func "Results are saved in $domain/osint/spoof.txt" "${FUNCNAME[0]}"

	else
		if [[ $SPOOF == false ]] || [[ $OSINT == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			return
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi
}

function ip_info() {

	mkdir -p osint

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } &&
		[[ $IP_INFO == true ]] && [[ $OSINT == true ]] &&
		[[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Searching IP info"

		if [[ -n $WHOISXML_API ]]; then

			# Reverse IP lookup
			curl -s "https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ip=${domain}" |
				jq -r '.result[].name' 2>>"$LOGFILE" |
				sed -e "s/$/ ${domain}/" |
				anew -q "osint/ip_${domain}_relations.txt"

			# WHOIS lookup
			curl -s "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOISXML_API}&domainName=${domain}&outputFormat=json&da=2&registryRawText=1&registrarRawText=1&ignoreRawTexts=1" |
				jq 2>>"$LOGFILE" |
				anew -q "osint/ip_${domain}_whois.txt"

			# IP Geolocation
			curl -s "https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ipAddress=${domain}" |
				jq -r '.ip,.location' 2>>"$LOGFILE" |
				anew -q "osint/ip_${domain}_location.txt"

			end_func "Results are saved in ${domain}/osint/ip_[domain_relations|whois|location].txt" "${FUNCNAME[0]}"

		else
			printf "\n%s[%s] WHOISXML_API variable is not defined. Skipping function.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
		fi

	else
		if [[ $IP_INFO == false ]] || [[ $OSINT == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		elif ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			return
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi

}

###############################################################################################################
############################################### SUBDOMAINS ####################################################
###############################################################################################################

function subdomains_full() {

	# Create necessary directories
	if ! mkdir -p .tmp webs subdomains; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	NUMOFLINES_subs="0"
	NUMOFLINES_probed="0"

	printf "%b#######################################################################%b\n\n" "$bgreen" "$reset"

	# Check if domain is an IP address
	if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		printf "%b[%s] Scanning IP %s%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$domain" "$reset"
	else
		printf "%b[%s] Subdomain Enumeration %s%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$domain" "$reset"
	fi

	# Backup existing subdomains and webs
	if [[ -s "subdomains/subdomains.txt" ]]; then
		if ! cp "subdomains/subdomains.txt" ".tmp/subdomains_old.txt"; then
			printf "%b[!] Failed to backup subdomains.txt.%b\n" "$bred" "$reset"
		fi
	fi

	if [[ -s "webs/webs.txt" ]]; then
		if ! cp "webs/webs.txt" ".tmp/probed_old.txt"; then
			printf "%b[!] Failed to backup webs.txt.%b\n" "$bred" "$reset"
		fi
	fi

	# Update resolvers if necessary
	if { [[ ! -f "$called_fn_dir/.sub_active" ]] || [[ ! -f "$called_fn_dir/.sub_brute" ]] || [[ ! -f "$called_fn_dir/.sub_permut" ]] || [[ ! -f "$called_fn_dir/.sub_recursive_brute" ]]; } || [[ $DIFF == true ]]; then
		if ! resolvers_update; then
			printf "%b[!] Failed to update resolvers.%b\n" "$bred" "$reset"
			return 1
		fi
	fi

	# Add in-scope subdomains
	if [[ -s $inScope_file ]]; then
		if ! cat "$inScope_file" | anew -q subdomains/subdomains.txt; then
			printf "%b[!] Failed to update subdomains.txt with in-scope domains.%b\n" "$bred" "$reset"
		fi
	fi

	# Subdomain enumeration
	if [[ ! $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ $SUBDOMAINS_GENERAL == true ]]; then
		sub_passive
		sub_crt
		sub_active
		sub_tls
		sub_noerror
		sub_brute
		sub_permut
		sub_regex_permut
		# sub_gpt (commented out)
		sub_recursive_passive
		sub_recursive_brute
		sub_dns
		sub_scraping
		sub_analytics
	else
		notification "IP/CIDR detected, subdomains search skipped" "info"
		if ! printf "%b\n" "$domain" | anew -q subdomains/subdomains.txt; then
			printf "%b[!] Failed to add domain to subdomains.txt.%b\n" "$bred" "$reset"
		fi
	fi

	# Web probing
	if ! webprobe_simple; then
		printf "%b[!] webprobe_simple function failed.%b\n" "$bred" "$reset"
	fi

	# Process subdomains
	if [[ -s "subdomains/subdomains.txt" ]]; then
		if [[ -s $outOfScope_file ]]; then
			if ! deleteOutScoped "$outOfScope_file" "subdomains/subdomains.txt"; then
				printf "%b[!] Failed to remove out-of-scope subdomains.%b\n" "$bred" "$reset"
			fi
		fi
		if ! NUMOFLINES_subs=$(cat "subdomains/subdomains.txt" 2>>"$LOGFILE" | anew ".tmp/subdomains_old.txt" | sed '/^$/d' | wc -l); then
			printf "%b[!] Failed to count new subdomains.%b\n" "$bred" "$reset"
			NUMOFLINES_subs="0"
		fi
	fi

	# Process webs
	if [[ -s "webs/webs.txt" ]]; then
		if [[ -s $outOfScope_file ]]; then
			if ! deleteOutScoped "$outOfScope_file" "webs/webs.txt"; then
				printf "%b[!] Failed to remove out-of-scope webs.%b\n" "$bred" "$reset"
			fi
		fi
		if ! NUMOFLINES_probed=$(cat "webs/webs.txt" 2>>"$LOGFILE" | anew ".tmp/probed_old.txt" | sed '/^$/d' | wc -l); then
			printf "%b[!] Failed to count new probed webs.%b\n" "$bred" "$reset"
			NUMOFLINES_probed="0"
		fi
	fi

	# Display results
	printf "%b\n[%s] Total subdomains:%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
	notification "- ${NUMOFLINES_subs} alive" "good"

	if [[ -s "subdomains/subdomains.txt" ]]; then
		if ! sort "subdomains/subdomains.txt"; then
			printf "%b[!] Failed to sort subdomains.txt.%b\n" "$bred" "$reset"
		fi
	fi

	notification "- ${NUMOFLINES_probed} new web probed" "good"

	if [[ -s "webs/webs.txt" ]]; then
		if ! sort "webs/webs.txt"; then
			printf "%b[!] Failed to sort webs.txt.%b\n" "$bred" "$reset"
		fi
	fi

	notification "Subdomain Enumeration Finished" "good"
	printf "%b[%s] Results are saved in %s/subdomains/subdomains.txt and webs/webs.txt%b\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$domain" "$reset"
	printf "%b#######################################################################%b\n\n" "$bgreen" "$reset"

}

function sub_passive() {

	mkdir -p .tmp

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBPASSIVE == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: Passive Subdomain Enumeration"

		# Run subfinder and check for errors
		subfinder -all -d "$domain" -max-time "$SUBFINDER_ENUM_TIMEOUT" -silent -o .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null
		merklemap-cli search $domain 2>/dev/null | awk -F' ' '{for(i=1;i<=NF;i++) if($i ~ /^domain=/) {split($i,a,"="); print a[2]}}' | anew -q .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null

		# Run github-subdomains if GITHUB_TOKENS is set and file is not empty
		if [[ -s $GITHUB_TOKENS ]]; then
			if [[ $DEEP == true ]]; then
				github-subdomains -d "$domain" -t "$GITHUB_TOKENS" -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
			else
				github-subdomains -d "$domain" -k -q -t "$GITHUB_TOKENS" -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
			fi
		fi

		# Run gitlab-subdomains if GITLAB_TOKENS is set and file is not empty
		if [[ -s $GITLAB_TOKENS ]]; then
			gitlab-subdomains -d "$domain" -t "$GITLAB_TOKENS" 2>>"$LOGFILE" | tee .tmp/gitlab_subdomains_psub.txt >/dev/null
		fi

		# Check if INSCOPE is true and run check_inscope
		if [[ $INSCOPE == true ]]; then
			check_inscope .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null
			check_inscope .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
			check_inscope .tmp/gitlab_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
		fi

		# Combine results and count new lines
		NUMOFLINES=$(find .tmp -type f -iname "*_psub.txt" -exec cat {} + | sed "s/^\*\.//" | anew .tmp/passive_subs.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (passive)" "${FUNCNAME[0]}"

	else
		if [[ $SUBPASSIVE == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or configuration settings.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function sub_crt() {

	mkdir -p .tmp subdomains

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBCRT == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: Crtsh Subdomain Enumeration"

		# Run crt command and check for errors
		crt -s -json -l "${CTR_LIMIT}" "$domain" 2>>"$LOGFILE" |
			jq -r '.[].subdomain' 2>>"$LOGFILE" |
			sed -e 's/^\*\.//' >.tmp/crtsh_subdomains.txt

		# Use anew to get new subdomains
		cat .tmp/crtsh_subdomains.txt | anew -q .tmp/crtsh_subs_tmp.txt

		# If INSCOPE is true, check inscope
		if [[ $INSCOPE == true ]]; then
			if ! check_inscope .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" >/dev/null; then
				printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
				return 1
			fi
		fi

		# Process subdomains and append new ones to .tmp/crtsh_subs.txt, count new lines
		NUMOFLINES=$(sed 's/^\*\.//' .tmp/crtsh_subs_tmp.txt | sed '/^$/d' | anew .tmp/crtsh_subs.txt | wc -l)

		end_subfunc "${NUMOFLINES} new subs (cert transparency)" "${FUNCNAME[0]}"
	else
		if [[ $SUBCRT == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi
}

function sub_active() {

	mkdir -p .tmp subdomains

	if [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: Active Subdomain Enumeration"

		# Combine subdomain files into subs_no_resolved.txt
		if ! find .tmp -type f -iname "*_subs.txt" -exec cat {} + | anew -q .tmp/subs_no_resolved.txt; then
			printf "%b[!] Failed to collect subdomains into subs_no_resolved.txt.%b\n" "$bred" "$reset"
			return 1
		fi

		# Delete out-of-scope domains if outOfScope_file exists
		if [[ -s $outOfScope_file ]]; then
			if ! deleteOutScoped "$outOfScope_file" .tmp/subs_no_resolved.txt; then
				printf "%b[!] deleteOutScoped command failed.%b\n" "$bred" "$reset"
				return 1
			fi
		fi

		if [[ $AXIOM != true ]]; then
			# Update resolvers locally
			if ! resolvers_update_quick_local; then
				printf "%b[!] resolvers_update_quick_local command failed.%b\n" "$bred" "$reset"
				return 1
			fi

			# Resolve subdomains using puredns
			if [[ -s ".tmp/subs_no_resolved.txt" ]]; then
				puredns resolve .tmp/subs_no_resolved.txt -w .tmp/subdomains_tmp.txt \
					-r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
					-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" \
					--wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					2>>"$LOGFILE" >/dev/null
			fi
		else
			# Update resolvers using axiom
			if ! resolvers_update_quick_axiom; then
				printf "%b[!] resolvers_update_quick_axiom command failed.%b\n" "$bred" "$reset"
				return 1
			fi

			# Resolve subdomains using axiom-scan
			if [[ -s ".tmp/subs_no_resolved.txt" ]]; then
				axiom-scan .tmp/subs_no_resolved.txt -m puredns-resolve \
					-r /home/op/lists/resolvers.txt \
					--resolvers-trusted /home/op/lists/resolvers_trusted.txt \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" \
					--wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					-o .tmp/subdomains_tmp.txt $AXIOM_EXTRA_ARGS \
					2>>"$LOGFILE" >/dev/null
			fi
		fi

		# Add the domain itself to the list if it resolves
		echo "$domain" | dnsx -retry 3 -silent -r "$resolvers_trusted" \
			2>>"$LOGFILE" | anew -q .tmp/subdomains_tmp.txt

		# If INSCOPE is true, check inscope
		if [[ $INSCOPE == true ]]; then
			if ! check_inscope .tmp/subdomains_tmp.txt 2>>"$LOGFILE" >/dev/null; then
				printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
				return 1
			fi
		fi

		# Process subdomains and append new ones to subdomains.txt, count new lines
		if ! NUMOFLINES=$(grep "\.$domain$\|^$domain$" .tmp/subdomains_tmp.txt 2>>"$LOGFILE" |
			grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' |
			anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
			printf "%b[!] Failed to process subdomains.%b\n" "$bred" "$reset"
			return 1
		fi

		end_subfunc "${NUMOFLINES} subs DNS resolved from passive" "${FUNCNAME[0]}"
	else
		printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
			"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
			"$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
	fi
}

function sub_tls() {
	mkdir -p .tmp subdomains

	if [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: TLS Active Subdomain Enumeration"

		if [[ $DEEP == true ]]; then
			if [[ $AXIOM != true ]]; then
				tlsx -san -cn -silent -ro -c "$TLSX_THREADS" \
					-p "$TLS_PORTS" -o .tmp/subdomains_tlsx.txt <subdomains/subdomains.txt \
					2>>"$LOGFILE" >/dev/null
			else
				axiom-scan subdomains/subdomains.txt -m tlsx \
					-san -cn -silent -ro -c "$TLSX_THREADS" -p "$TLS_PORTS" \
					-o .tmp/subdomains_tlsx.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
		else
			if [[ $AXIOM != true ]]; then
				tlsx -san -cn -silent -ro -c "$TLSX_THREADS" <subdomains/subdomains.txt >.tmp/subdomains_tlsx.txt 2>>"$LOGFILE"
			else
				axiom-scan subdomains/subdomains.txt -m tlsx \
					-san -cn -silent -ro -c "$TLSX_THREADS" \
					-o .tmp/subdomains_tlsx.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
		fi

		if [[ -s ".tmp/subdomains_tlsx.txt" ]]; then
			grep "\.$domain$\|^$domain$" .tmp/subdomains_tlsx.txt |
				grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' |
				sed "s/|__ //" | anew -q .tmp/subdomains_tlsx_clean.txt
		fi

		if [[ $AXIOM != true ]]; then
			if ! resolvers_update_quick_local; then
				printf "%b[!] resolvers_update_quick_local command failed.%b\n" "$bred" "$reset"
				return 1
			fi
			if [[ -s ".tmp/subdomains_tlsx_clean.txt" ]]; then
				puredns resolve .tmp/subdomains_tlsx_clean.txt -w .tmp/subdomains_tlsx_resolved.txt \
					-r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
					-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					2>>"$LOGFILE" >/dev/null
			fi
		else
			if ! resolvers_update_quick_axiom; then
				printf "%b[!] resolvers_update_quick_axiom command failed.%b\n" "$bred" "$reset"
				return 1
			fi
			if [[ -s ".tmp/subdomains_tlsx_clean.txt" ]]; then
				axiom-scan .tmp/subdomains_tlsx_clean.txt -m puredns-resolve \
					-r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					-o .tmp/subdomains_tlsx_resolved.txt $AXIOM_EXTRA_ARGS \
					2>>"$LOGFILE" >/dev/null
			fi
		fi

		if [[ $INSCOPE == true ]]; then
			if ! check_inscope .tmp/subdomains_tlsx_resolved.txt 2>>"$LOGFILE" >/dev/null; then
				printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
				return 1
			fi
		fi

		if ! NUMOFLINES=$(anew subdomains/subdomains.txt <.tmp/subdomains_tlsx_resolved.txt | sed '/^$/d' | wc -l); then
			printf "%b[!] Counting new subdomains failed.%b\n" "$bred" "$reset"
			return 1
		fi

		end_subfunc "${NUMOFLINES} new subs (tls active enum)" "${FUNCNAME[0]}"
	else
		printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
			"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
			"$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
	fi
}

function sub_noerror() {

	mkdir -p .tmp subdomains

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBNOERROR == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: Checking NOERROR DNS response"

		# Check for DNSSEC black lies
		random_subdomain="${RANDOM}thistotallynotexist${RANDOM}.$domain"
		dns_response=$(echo "$random_subdomain" | dnsx -r "$resolvers" -rcode noerror,nxdomain -retry 3 -silent | cut -d' ' -f2)

		if [[ $dns_response == "[NXDOMAIN]" ]]; then
			if ! resolvers_update_quick_local; then
				printf "%b[!] Failed to update resolvers.%b\n" "$bred" "$reset"
				return 1
			fi

			# Determine wordlist based on DEEP setting
			if [[ $DEEP == true ]]; then
				wordlist="$subs_wordlist_big"
			else
				wordlist="$subs_wordlist"
			fi

			# Run dnsx and check for errors
			dnsx -d "$domain" -r "$resolvers" -silent \
				-rcode noerror -w "$wordlist" \
				2>>"$LOGFILE" | cut -d' ' -f1 | anew -q .tmp/subs_noerror.txt >/dev/null

			# Check inscope if INSCOPE is true
			if [[ $INSCOPE == true ]]; then
				if ! check_inscope .tmp/subs_noerror.txt 2>>"$LOGFILE" >/dev/null; then
					printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
					return 1
				fi
			fi

			# Process subdomains and append new ones to subdomains.txt, count new lines
			if ! NUMOFLINES=$(grep "\.$domain$\|^$domain$" .tmp/subs_noerror.txt 2>>"$LOGFILE" |
				grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' |
				sed 's/^\*\.//' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
				printf "%b[!] Failed to process subdomains.%b\n" "$bred" "$reset"
				return 1
			fi

			end_subfunc "${NUMOFLINES} new subs (DNS noerror)" "${FUNCNAME[0]}"

		else
			printf "\n%s[%s] Detected DNSSEC black lies, skipping this technique.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
		fi

	else
		if [[ $SUBNOERROR == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
				"$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function sub_dns() {
	mkdir -p .tmp subdomains

	if [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: DNS Subdomain Enumeration and PTR search"

		if [[ $AXIOM != true ]]; then
			if [[ -s "subdomains/subdomains.txt" ]]; then
				dnsx -r "$resolvers_trusted" -a -aaaa -cname -ns -ptr -mx -soa -silent -retry 3 -json \
					-o "subdomains/subdomains_dnsregs.json" <"subdomains/subdomains.txt" 2>>"$LOGFILE" >/dev/null
			fi

			if [[ -s "subdomains/subdomains_dnsregs.json" ]]; then
				# Extract various DNS records and process them
				jq -r 'try .a[], try .aaaa[], try .cname[], try .ns[], try .ptr[], try .mx[], try .soa[]' \
					<"subdomains/subdomains_dnsregs.json" 2>/dev/null |
					grep "\.$domain$" |
					grep -E '^([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}$' |
					anew -q .tmp/subdomains_dns.txt

				jq -r 'try .a[]' <"subdomains/subdomains_dnsregs.json" | sort -u |
					hakip2host | awk '{print $3}' | unfurl -u domains |
					sed -e 's/^\*\.//' -e 's/\.$//' -e '/\./!d' |
					grep "\.$domain$" |
					grep -E '^([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}$' |
					anew -q .tmp/subdomains_dns.txt

				jq -r 'try "\(.host) - \(.a[])"' <"subdomains/subdomains_dnsregs.json" 2>/dev/null |
					sort -u -k2 | anew -q "subdomains/subdomains_ips.txt"
			fi

			if ! resolvers_update_quick_local; then
				printf "%b[!] Failed to update resolvers.%b\n" "$bred" "$reset"
			fi

			if [[ -s ".tmp/subdomains_dns.txt" ]]; then
				puredns resolve .tmp/subdomains_dns.txt -w .tmp/subdomains_dns_resolved.txt \
					-r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
					-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					2>>"$LOGFILE" >/dev/null
			fi
		else
			if [[ -s "subdomains/subdomains.txt" ]]; then
				axiom-scan "subdomains/subdomains.txt" -m dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -json \
					-o "subdomains/subdomains_dnsregs.json" "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
			fi

			if [[ -s "subdomains/subdomains_dnsregs.json" ]]; then
				jq -r 'try .a[]' <"subdomains/subdomains_dnsregs.json" | sort -u |
					anew -q .tmp/subdomains_dns_a_records.txt

				jq -r 'try .a[]' <"subdomains/subdomains_dnsregs.json" | sort -u |
					hakip2host | awk '{print $3}' | unfurl -u domains |
					sed -e 's/^\*\.//' -e 's/\.$//' -e '/\./!d' |
					grep "\.$domain$" |
					grep -E '^([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}$' |
					anew -q .tmp/subdomains_dns.txt

				jq -r 'try .a[], try .aaaa[], try .cname[], try .ns[], try .ptr[], try .mx[], try .soa[]' \
					<"subdomains/subdomains_dnsregs.json" 2>/dev/null |
					grep "\.$domain$" |
					grep -E '^([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}$' |
					anew -q .tmp/subdomains_dns.txt

				jq -r 'try "\(.host) - \(.a[])"' <"subdomains/subdomains_dnsregs.json" 2>/dev/null |
					sort -u -k2 | anew -q "subdomains/subdomains_ips.txt"
			fi

			if ! resolvers_update_quick_axiom; then
				printf "%b[!] Failed to update resolvers.%b\n" "$bred" "$reset"
			fi

			if [[ -s ".tmp/subdomains_dns.txt" ]]; then
				axiom-scan .tmp/subdomains_dns.txt -m puredns-resolve \
					-r "/home/op/lists/resolvers.txt" --resolvers-trusted "/home/op/lists/resolvers_trusted.txt" \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					-o .tmp/subdomains_dns_resolved.txt "$AXIOM_EXTRA_ARGS" \
					2>>"$LOGFILE" >/dev/null
			fi
		fi

		if [[ $INSCOPE == true ]]; then
			if ! check_inscope .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" >/dev/null; then
				printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
			fi
		fi

		if ! NUMOFLINES=$(grep "\.$domain$\|^$domain$" .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" |
			grep -E '^([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}$' |
			anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
			printf "%b[!] Failed to count new subdomains.%b\n" "$bred" "$reset"
			return 1
		fi

		end_subfunc "${NUMOFLINES} new subs (dns resolution)" "${FUNCNAME[0]}"
	else
		printf "\n%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
			"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
	fi
}

function sub_brute() {

	mkdir -p .tmp subdomains

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBBRUTE == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: Bruteforce Subdomain Enumeration"

		if [[ $AXIOM != true ]]; then
			if ! resolvers_update_quick_local; then
				printf "%b[!] Failed to update resolvers.%b\n" "$bred" "$reset"
				return 1
			fi

			wordlist="$subs_wordlist"
			[[ $DEEP == true ]] && wordlist="$subs_wordlist_big"

			# Run puredns bruteforce
			puredns bruteforce "$wordlist" "$domain" -w .tmp/subs_brute.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
				-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
				--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
				2>>"$LOGFILE" >/dev/null

			# Resolve the subdomains
			if [[ -s ".tmp/subs_brute.txt" ]]; then
				puredns resolve .tmp/subs_brute.txt -w .tmp/subs_brute_valid.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
					-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					2>>"$LOGFILE" >/dev/null
			fi

		else
			if ! resolvers_update_quick_axiom; then
				printf "%b[!] Failed to update resolvers on axiom.%b\n" "$bred" "$reset"
				return 1
			fi

			wordlist="$subs_wordlist"
			[[ $DEEP == true ]] && wordlist="$subs_wordlist_big"

			# Run axiom-scan with puredns-single
			axiom-scan "$wordlist" -m puredns-single "$domain" -r /home/op/lists/resolvers.txt \
				--resolvers-trusted /home/op/lists/resolvers_trusted.txt \
				--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
				-o .tmp/subs_brute.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null

			# Resolve the subdomains using axiom-scan
			if [[ -s ".tmp/subs_brute.txt" ]]; then
				axiom-scan .tmp/subs_brute.txt -m puredns-resolve -r /home/op/lists/resolvers.txt \
					--resolvers-trusted /home/op/lists/resolvers_trusted.txt \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					-o .tmp/subs_brute_valid.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
			fi
		fi

		# Check inscope if INSCOPE is true
		if [[ $INSCOPE == true ]]; then
			if ! check_inscope .tmp/subs_brute_valid.txt 2>>"$LOGFILE" >/dev/null; then
				printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
				return 1
			fi
		fi

		# Process subdomains and append new ones to subdomains.txt, count new lines
		if ! NUMOFLINES=$(grep "\.$domain$\|^$domain$" .tmp/subs_brute_valid.txt 2>>"$LOGFILE" |
			grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' |
			sed 's/^\*\.//' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
			printf "%b[!] Failed to process subdomains.%b\n" "$bred" "$reset"
			return 1
		fi

		end_subfunc "${NUMOFLINES} new subs (bruteforce)" "${FUNCNAME[0]}"

	else
		if [[ $SUBBRUTE == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
				"$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function sub_scraping() {

	# Create necessary directories
	if ! mkdir -p .tmp subdomains; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBSCRAPING == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: Source code scraping subdomain search"

		# Initialize scrap_subs.txt
		if ! touch .tmp/scrap_subs.txt; then
			printf "%b[!] Failed to create .tmp/scrap_subs.txt.%b\n" "$bred" "$reset"
			return 1
		fi

		# If in multi mode and subdomains.txt doesn't exist, create it
		if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
			if ! printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"; then
				printf "%b[!] Failed to create subdomains.txt.%b\n" "$bred" "$reset"
				return 1
			fi
		fi

		# Check if subdomains.txt exists and is not empty
		if [[ -s "$dir/subdomains/subdomains.txt" ]]; then

			subdomains_count=$(wc -l <"$dir/subdomains/subdomains.txt")
			if [[ $subdomains_count -le $DEEP_LIMIT ]] || [[ $DEEP == true ]]; then

				if [[ $AXIOM != true ]]; then
					if ! resolvers_update_quick_local; then
						printf "%b[!] Failed to update resolvers locally.%b\n" "$bred" "$reset"
						return 1
					fi

					# Run httpx to gather web info
					httpx -follow-host-redirects -status-code -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" \
						-timeout "$HTTPX_TIMEOUT" -silent -retries 2 -title -web-server -tech-detect -location \
						-no-color -json -o .tmp/web_full_info1.txt \
						<subdomains/subdomains.txt 2>>"$LOGFILE" >/dev/null

					if [[ -s ".tmp/web_full_info1.txt" ]]; then
						cat .tmp/web_full_info1.txt | jq -r 'try .url' 2>/dev/null |
							grep "$domain" |
							grep -E '^((http|https):\/\/)?([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}(\/.*)?$' |
							sed "s/^\*\.//" |
							anew .tmp/probed_tmp_scrap.txt |
							unfurl -u domains 2>>"$LOGFILE" |
							anew -q .tmp/scrap_subs.txt
					fi

					if [[ -s ".tmp/probed_tmp_scrap.txt" ]]; then
						timeout -k 1m 10m httpx -l .tmp/probed_tmp_scrap.txt -tls-grab -tls-probe -csp-probe \
							-status-code -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" \
							-silent -retries 2 -no-color -json -o .tmp/web_full_info2.txt \
							2>>"$LOGFILE" >/dev/null
					fi

					if [[ -s ".tmp/web_full_info2.txt" ]]; then
						cat .tmp/web_full_info2.txt | jq -r 'try ."tls-grab"."dns_names"[], try .csp.domains[], try .url' 2>/dev/null |
							grep "$domain" |
							grep -E '^((http|https):\/\/)?([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}(\/.*)?$' |
							sed "s/^\*\.//" |
							sort -u |
							httpx -silent |
							anew .tmp/probed_tmp_scrap.txt |
							unfurl -u domains 2>>"$LOGFILE" |
							anew -q .tmp/scrap_subs.txt
					fi

					if [[ -s ".tmp/probed_tmp_scrap.txt" ]]; then
						if [[ $DEEP == true ]]; then
							katana_depth=3
						else
							katana_depth=2
						fi

						katana -silent -list .tmp/probed_tmp_scrap.txt -jc -kf all -c "$KATANA_THREADS" -d "$katana_depth" \
							-fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" >/dev/null
					fi

				else
					# AXIOM mode
					if ! resolvers_update_quick_axiom; then
						printf "%b[!] Failed to update resolvers on axiom.%b\n" "$bred" "$reset"
						return 1
					fi

					axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -random-agent -status-code \
						-threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" -silent -retries 2 \
						-title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info1.txt \
						$AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null

					if [[ -s ".tmp/web_full_info1.txt" ]]; then
						cat .tmp/web_full_info1.txt | jq -r 'try .url' 2>/dev/null |
							grep "$domain" |
							grep -E '^((http|https):\/\/)?([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}(\/.*)?$' |
							sed "s/^\*\.//" |
							anew .tmp/probed_tmp_scrap.txt |
							unfurl -u domains 2>>"$LOGFILE" |
							anew -q .tmp/scrap_subs.txt
					fi

					if [[ -s ".tmp/probed_tmp_scrap.txt" ]]; then
						timeout -k 1m 10m axiom-scan .tmp/probed_tmp_scrap.txt -m httpx -tls-grab -tls-probe -csp-probe \
							-random-agent -status-code -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" \
							-silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info2.txt \
							$AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					fi

					if [[ -s ".tmp/web_full_info2.txt" ]]; then
						cat .tmp/web_full_info2.txt | jq -r 'try ."tls-grab"."dns_names"[], try .csp.domains[], try .url' 2>/dev/null |
							grep "$domain" |
							grep -E '^((http|https):\/\/)?([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}(\/.*)?$' |
							sed "s/^\*\.//" |
							sort -u |
							httpx -silent |
							anew .tmp/probed_tmp_scrap.txt |
							unfurl -u domains 2>>"$LOGFILE" |
							anew -q .tmp/scrap_subs.txt
					fi

					if [[ -s ".tmp/probed_tmp_scrap.txt" ]]; then
						if [[ $DEEP == true ]]; then
							katana_depth=3
						else
							katana_depth=2
						fi

						axiom-scan .tmp/probed_tmp_scrap.txt -m katana -jc -kf all -d "$katana_depth" -fs rdn \
							-o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					fi
				fi

				if [[ -s ".tmp/katana.txt" ]]; then
					sed -i '/^.\{2048\}./d' .tmp/katana.txt

					cat .tmp/katana.txt | unfurl -u domains 2>>"$LOGFILE" |
						grep "\.$domain$" |
						grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' |
						anew -q .tmp/scrap_subs.txt
				fi

				if [[ -s ".tmp/scrap_subs.txt" ]]; then
					puredns resolve .tmp/scrap_subs.txt -w .tmp/scrap_subs_resolved.txt -r "$resolvers" \
						--resolvers-trusted "$resolvers_trusted" -l "$PUREDNS_PUBLIC_LIMIT" \
						--rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" --wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" \
						--wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" 2>>"$LOGFILE" >/dev/null
				fi

				if [[ $INSCOPE == true ]]; then
					if ! check_inscope .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" >/dev/null; then
						printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
					fi
				fi

				if [[ -s ".tmp/scrap_subs_resolved.txt" ]]; then
					if ! NUMOFLINES=$(cat .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" |
						grep "\.$domain$\|^$domain$" |
						grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' |
						anew subdomains/subdomains.txt |
						tee .tmp/diff_scrap.txt |
						sed '/^$/d' | wc -l); then
						printf "%b[!] Failed to count new subdomains.%b\n" "$bred" "$reset"
						NUMOFLINES=0
					fi
				else
					NUMOFLINES=0
				fi

				if [[ -s ".tmp/diff_scrap.txt" ]]; then
					httpx -follow-host-redirects -random-agent -status-code -threads "$HTTPX_THREADS" \
						-rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" -silent -retries 2 -title -web-server \
						-tech-detect -location -no-color -json -o .tmp/web_full_info3.txt \
						<.tmp/diff_scrap.txt 2>>"$LOGFILE" >/dev/null

					if [[ -s ".tmp/web_full_info3.txt" ]]; then
						cat .tmp/web_full_info3.txt | jq -r 'try .url' 2>/dev/null |
							grep "$domain" |
							grep -E '^((http|https):\/\/)?([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}(\/.*)?$' |
							sed "s/^\*\.//" |
							anew .tmp/probed_tmp_scrap.txt |
							unfurl -u domains 2>>"$LOGFILE" |
							anew -q .tmp/scrap_subs.txt
					fi
				fi

				cat .tmp/web_full_info1.txt .tmp/web_full_info2.txt .tmp/web_full_info3.txt 2>>"$LOGFILE" |
					jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"$LOGFILE" >.tmp/web_full_info.txt

				end_subfunc "${NUMOFLINES} new subs (code scraping)" "${FUNCNAME[0]}"

			else
				end_subfunc "Skipping Subdomains Web Scraping: Too Many Subdomains" "${FUNCNAME[0]}"
			fi
		fi

	else
		if [[ $SUBSCRAPING == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
				"$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function sub_analytics() {

	# Create necessary directories
	if ! mkdir -p .tmp subdomains; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBANALYTICS == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: Analytics Subdomain Enumeration"

		if [[ -s ".tmp/probed_tmp_scrap.txt" ]]; then
			# Run analyticsrelationships and check for errors
			analyticsrelationships -ch <.tmp/probed_tmp_scrap.txt >>.tmp/analytics_subs_tmp.txt 2>>"$LOGFILE"

			if [[ -s ".tmp/analytics_subs_tmp.txt" ]]; then
				grep "\.$domain$\|^$domain$" .tmp/analytics_subs_tmp.txt |
					grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' |
					sed "s/|__ //" | anew -q .tmp/analytics_subs_clean.txt

				if [[ $AXIOM != true ]]; then
					if ! resolvers_update_quick_local; then
						printf "%b[!] Failed to update resolvers locally.%b\n" "$bred" "$reset"
						return 1
					fi

					if [[ -s ".tmp/analytics_subs_clean.txt" ]]; then
						puredns resolve .tmp/analytics_subs_clean.txt -w .tmp/analytics_subs_resolved.txt \
							-r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
							-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
							--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
							2>>"$LOGFILE" >/dev/null
					fi
				else
					if ! resolvers_update_quick_axiom; then
						printf "%b[!] Failed to update resolvers on Axiom.%b\n" "$bred" "$reset"
						return 1
					fi

					if [[ -s ".tmp/analytics_subs_clean.txt" ]]; then
						axiom-scan .tmp/analytics_subs_clean.txt -m puredns-resolve \
							-r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt \
							--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
							-o .tmp/analytics_subs_resolved.txt $AXIOM_EXTRA_ARGS \
							2>>"$LOGFILE" >/dev/null
					fi
				fi
			fi
		fi

		if [[ $INSCOPE == true ]]; then
			if ! check_inscope .tmp/analytics_subs_resolved.txt 2>>"$LOGFILE" >/dev/null; then
				printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
			fi
		fi

		if ! NUMOFLINES=$(anew subdomains/subdomains.txt 2>/dev/null <.tmp/analytics_subs_resolved.txt 2>/dev/null | sed '/^$/d' | wc -l); then
			printf "%b[!] Failed to count new subdomains.%b\n" "$bred" "$reset"
			NUMOFLINES=0
		fi

		end_subfunc "${NUMOFLINES} new subs (analytics relationship)" "${FUNCNAME[0]}"

	else
		if [[ $SUBANALYTICS == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi
}

function sub_permut() {

	mkdir -p .tmp subdomains

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBPERMUTE == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: Permutations Subdomain Enumeration"

		# If in multi mode and subdomains.txt doesn't exist, create it with the domain
		if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
			echo "$domain" >"$dir/subdomains/subdomains.txt"
		fi

		# Determine the number of subdomains
		subdomain_count=$(wc -l <subdomains/subdomains.txt)

		# Check if DEEP mode is enabled or subdomains are within DEEP_LIMIT
		if [[ $DEEP == true ]] || [[ $subdomain_count -le $DEEP_LIMIT ]]; then

			# Select the permutations tool
			if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
				if [[ -s "subdomains/subdomains.txt" ]]; then
					gotator -sub subdomains/subdomains.txt -perm "${tools}/permutations_list.txt" $GOTATOR_FLAGS \
						-silent 2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1.txt
				fi
			else
				if [[ -s "subdomains/subdomains.txt" ]]; then
					ripgen -d subdomains/subdomains.txt -w "${tools}/permutations_list.txt" \
						2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1.txt
				fi
			fi

		elif [[ "$(wc -l <.tmp/subs_no_resolved.txt)" -le $DEEP_LIMIT2 ]]; then

			if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
				if [[ -s ".tmp/subs_no_resolved.txt" ]]; then
					gotator -sub .tmp/subs_no_resolved.txt -perm "${tools}/permutations_list.txt" $GOTATOR_FLAGS \
						-silent 2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1.txt
				fi
			else
				if [[ -s ".tmp/subs_no_resolved.txt" ]]; then
					ripgen -d .tmp/subs_no_resolved.txt -w "${tools}/permutations_list.txt" \
						2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1.txt
				fi
			fi

		else
			end_subfunc "Skipping Permutations: Too Many Subdomains" "${FUNCNAME[0]}"
			return 0
		fi

		# Resolve the permutations
		if [[ $AXIOM != true ]]; then
			if ! resolvers_update_quick_local; then
				printf "%b[!] Failed to update resolvers.%b\n" "$bred" "$reset"
				return 1
			fi
			if [[ -s ".tmp/gotator1.txt" ]]; then
				puredns resolve .tmp/gotator1.txt -w .tmp/permute1.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
					-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					2>>"$LOGFILE" >/dev/null
			fi
		else
			if ! resolvers_update_quick_axiom; then
				printf "%b[!] Failed to update resolvers on axiom.%b\n" "$bred" "$reset"
				return 1
			fi
			if [[ -s ".tmp/gotator1.txt" ]]; then
				axiom-scan .tmp/gotator1.txt -m puredns-resolve -r /home/op/lists/resolvers.txt \
					--resolvers-trusted /home/op/lists/resolvers_trusted.txt \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					-o .tmp/permute1.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
		fi

		# Generate second round of permutations
		if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
			if [[ -s ".tmp/permute1.txt" ]]; then
				gotator -sub .tmp/permute1.txt -perm "${tools}/permutations_list.txt" \
					$GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator2.txt
			fi
		else
			if [[ -s ".tmp/permute1.txt" ]]; then
				ripgen -d .tmp/permute1.txt -w "${tools}/permutations_list.txt" \
					2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator2.txt
			fi
		fi

		# Resolve the second round of permutations
		if [[ $AXIOM != true ]]; then
			if [[ -s ".tmp/gotator2.txt" ]]; then
				puredns resolve .tmp/gotator2.txt -w .tmp/permute2.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
					-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					2>>"$LOGFILE" >/dev/null
			fi
		else
			if [[ -s ".tmp/gotator2.txt" ]]; then
				axiom-scan .tmp/gotator2.txt -m puredns-resolve -r /home/op/lists/resolvers.txt \
					--resolvers-trusted /home/op/lists/resolvers_trusted.txt \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					-o .tmp/permute2.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
		fi

		# Combine results
		if [[ -s ".tmp/permute1.txt" ]] || [[ -s ".tmp/permute2.txt" ]]; then
			cat .tmp/permute1.txt .tmp/permute2.txt 2>>"$LOGFILE" | anew -q .tmp/permute_subs.txt

			# Remove out-of-scope domains if applicable
			if [[ -s $outOfScope_file ]]; then
				if ! deleteOutScoped "$outOfScope_file" .tmp/permute_subs.txt; then
					printf "%b[!] deleteOutScoped command failed.%b\n" "$bred" "$reset"
				fi
			fi

			# Check inscope if INSCOPE is true
			if [[ $INSCOPE == true ]]; then
				if ! check_inscope .tmp/permute_subs.txt 2>>"$LOGFILE" >/dev/null; then
					printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
				fi
			fi

			# Process subdomains and append new ones to subdomains.txt, count new lines
			if ! NUMOFLINES=$(grep "\.$domain$\|^$domain$" .tmp/permute_subs.txt 2>>"$LOGFILE" |
				grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' |
				anew subdomains/subdomains.txt | sed '/^$/d' | wc -l); then
				printf "%b[!] Failed to process subdomains.%b\n" "$bred" "$reset"
				return 1
			fi
		else
			NUMOFLINES=0
		fi

		end_subfunc "${NUMOFLINES} new subs (permutations)" "${FUNCNAME[0]}"

	else
		if [[ $SUBPERMUTE == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
				"$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function sub_regex_permut() {

	# Create necessary directories
	if ! mkdir -p .tmp subdomains; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBREGEXPERMUTE == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: Permutations by regex analysis"

		# Change to the regulator directory
		if ! pushd "${tools}/regulator" >/dev/null; then
			printf "%b[!] Failed to change directory to %s.%b\n" "$bred" "${tools}/regulator" "$reset"
			return 1
		fi

		# If in multi mode and subdomains.txt doesn't exist, create it
		if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
			printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
		fi

		# Run the main.py script
		"${tools}/regulator/venv/bin/python3" main.py -t "$domain" -f "${dir}/subdomains/subdomains.txt" -o "${dir}/.tmp/${domain}.brute" \
			2>>"$LOGFILE" >/dev/null

		# Return to the previous directory
		if ! popd >/dev/null; then
			printf "%b[!] Failed to return to previous directory.%b\n" "$bred" "$reset"
			return 1
		fi

		# Resolve the generated domains
		if [[ $AXIOM != true ]]; then
			if ! resolvers_update_quick_local; then
				printf "%b[!] Failed to update resolvers locally.%b\n" "$bred" "$reset"
				return 1
			fi

			if [[ -s ".tmp/${domain}.brute" ]]; then
				puredns resolve ".tmp/${domain}.brute" -w .tmp/regulator.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
					-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					2>>"$LOGFILE" >/dev/null
			fi
		else
			if ! resolvers_update_quick_axiom; then
				printf "%b[!] Failed to update resolvers on Axiom.%b\n" "$bred" "$reset"
				return 1
			fi

			if [[ -s ".tmp/${domain}.brute" ]]; then
				axiom-scan ".tmp/${domain}.brute" -m puredns-resolve \
					-r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					-o .tmp/regulator.txt $AXIOM_EXTRA_ARGS \
					2>>"$LOGFILE" >/dev/null
			fi
		fi

		# Process the resolved domains
		if [[ -s ".tmp/regulator.txt" ]]; then
			if [[ -s $outOfScope_file ]]; then
				if ! deleteOutScoped "$outOfScope_file" .tmp/regulator.txt; then
					printf "%b[!] deleteOutScoped command failed.%b\n" "$bred" "$reset"
				fi
			fi

			if [[ $INSCOPE == true ]]; then
				if ! check_inscope .tmp/regulator.txt 2>>"$LOGFILE" >/dev/null; then
					printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
				fi
			fi

			if ! NUMOFLINES=$(grep "\.$domain$\|^$domain$" .tmp/regulator.txt 2>>"$LOGFILE" |
				grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' |
				anew subdomains/subdomains.txt |
				sed '/^$/d' |
				wc -l); then
				printf "%b[!] Failed to count new subdomains.%b\n" "$bred" "$reset"
				NUMOFLINES=0
			fi
		else
			NUMOFLINES=0
		fi

		end_subfunc "${NUMOFLINES} new subs (permutations by regex)" "${FUNCNAME[0]}"

	else
		if [[ $SUBREGEXPERMUTE == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function sub_recursive_passive() {

	# Create necessary directories
	if ! mkdir -p .tmp subdomains; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUB_RECURSIVE_PASSIVE == true ]] && [[ -s "subdomains/subdomains.txt" ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: Subdomains recursive search passive"

		# If in multi mode and subdomains.txt doesn't exist, create it with the domain
		if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
			printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
		fi

		# Passive recursive
		if [[ -s "subdomains/subdomains.txt" ]]; then
			dsieve -if subdomains/subdomains.txt -f 3 -top "$DEEP_RECURSIVE_PASSIVE" >.tmp/subdomains_recurs_top.txt
		fi

		if [[ $AXIOM != true ]]; then
			if ! resolvers_update_quick_local; then
				printf "%b[!] Failed to update resolvers locally.%b\n" "$bred" "$reset"
				return 1
			fi

			if [[ -s ".tmp/subdomains_recurs_top.txt" ]]; then
				subfinder -all -dL .tmp/subdomains_recurs_top.txt -max-time "${SUBFINDER_ENUM_TIMEOUT}" \
					-silent -o .tmp/passive_recursive_tmp.txt 2>>"$LOGFILE"
			else
				return 1
			fi

			if [[ -s ".tmp/passive_recursive_tmp.txt" ]]; then
				cat .tmp/passive_recursive_tmp.txt | anew -q .tmp/passive_recursive.txt
			fi

			if [[ -s ".tmp/passive_recursive.txt" ]]; then
				puredns resolve .tmp/passive_recursive.txt -w .tmp/passive_recurs_tmp.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
					-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					2>>"$LOGFILE" >/dev/null
			fi

		else
			if ! resolvers_update_quick_axiom; then
				printf "%b[!] Failed to update resolvers on Axiom.%b\n" "$bred" "$reset"
				return 1
			fi

			if [[ -s ".tmp/subdomains_recurs_top.txt" ]]; then
				axiom-scan .tmp/subdomains_recurs_top.txt -m subfinder -all -o .tmp/subfinder_prec.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
			else
				return 1
			fi

			if [[ -s ".tmp/subfinder_prec.txt" ]]; then
				cat .tmp/subfinder_prec.txt | anew -q .tmp/passive_recursive.txt
			fi

			if [[ -s ".tmp/passive_recursive.txt" ]]; then
				axiom-scan .tmp/passive_recursive.txt -m puredns-resolve \
					-r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					-o .tmp/passive_recurs_tmp.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
			fi
		fi

		if [[ $INSCOPE == true ]]; then
			if ! check_inscope .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" >/dev/null; then
				printf "%b[!] check_inscope command failed.%b\n" "$bred" "$reset"
			fi
		fi

		if [[ -s ".tmp/passive_recurs_tmp.txt" ]]; then
			if ! NUMOFLINES=$(grep "\.$domain$\|^$domain$" .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" |
				grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' |
				sed '/^$/d' |
				anew subdomains/subdomains.txt |
				wc -l); then
				printf "%b[!] Failed to count new subdomains.%b\n" "$bred" "$reset"
				NUMOFLINES=0
			fi
		else
			NUMOFLINES=0
		fi

		end_subfunc "${NUMOFLINES} new subs (recursive)" "${FUNCNAME[0]}"

	else
		if [[ $SUB_RECURSIVE_PASSIVE == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		elif [[ ! -s "subdomains/subdomains.txt" ]]; then
			printf "\n%s[%s] No subdomains to process.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function sub_recursive_brute() {
	# Create necessary directories
	if ! mkdir -p .tmp subdomains; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUB_RECURSIVE_BRUTE == true ]] && [[ -s "subdomains/subdomains.txt" ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: Subdomains recursive search active"

		# If in multi mode and subdomains.txt doesn't exist, create it with the domain
		if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
			echo "$domain" >"$dir/subdomains/subdomains.txt"
		fi

		# Check the number of subdomains
		subdomain_count=$(wc -l <subdomains/subdomains.txt)
		if [[ $subdomain_count -le $DEEP_LIMIT ]]; then
			# Generate top subdomains if not already done
			if [[ ! -s ".tmp/subdomains_recurs_top.txt" ]]; then
				dsieve -if subdomains/subdomains.txt -f 3 -top "$DEEP_RECURSIVE_PASSIVE" >.tmp/subdomains_recurs_top.txt
			fi

			# Generate brute recursive wordlist
			ripgen -d .tmp/subdomains_recurs_top.txt -w "$subs_wordlist" >.tmp/brute_recursive_wordlist.txt

			if [[ $AXIOM != true ]]; then
				if ! resolvers_update_quick_local; then
					printf "%b[!] Failed to update resolvers locally.%b\n" "$bred" "$reset"
					return 1
				fi

				if [[ -s ".tmp/brute_recursive_wordlist.txt" ]]; then
					puredns resolve .tmp/brute_recursive_wordlist.txt -r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
						-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
						--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
						-w .tmp/brute_recursive_result.txt 2>>"$LOGFILE" >/dev/null
				fi
			else
				if ! resolvers_update_quick_axiom; then
					printf "%b[!] Failed to update resolvers on axiom.%b\n" "$bred" "$reset"
					return 1
				fi

				if [[ -s ".tmp/brute_recursive_wordlist.txt" ]]; then
					axiom-scan .tmp/brute_recursive_wordlist.txt -m puredns-resolve \
						-r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt \
						--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
						-o .tmp/brute_recursive_result.txt $AXIOM_EXTRA_ARGS \
						2>>"$LOGFILE" >/dev/null
				fi
			fi

			if [[ -s ".tmp/brute_recursive_result.txt" ]]; then
				cat .tmp/brute_recursive_result.txt | anew -q .tmp/brute_recursive.txt
			fi

			# Generate permutations
			if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
				if [[ -s ".tmp/brute_recursive.txt" ]]; then
					gotator -sub .tmp/brute_recursive.txt -perm "${tools}/permutations_list.txt" $GOTATOR_FLAGS -silent \
						2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1_recursive.txt
				fi
			else
				if [[ -s ".tmp/brute_recursive.txt" ]]; then
					ripgen -d .tmp/brute_recursive.txt -w "${tools}/permutations_list.txt" \
						2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator1_recursive.txt
				fi
			fi

			# Resolve permutations
			if [[ $AXIOM != true ]]; then
				if [[ -s ".tmp/gotator1_recursive.txt" ]]; then
					puredns resolve .tmp/gotator1_recursive.txt -w .tmp/permute1_recursive.txt \
						-r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
						-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
						--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
						2>>"$LOGFILE" >/dev/null
				fi
			else
				if [[ -s ".tmp/gotator1_recursive.txt" ]]; then
					axiom-scan .tmp/gotator1_recursive.txt -m puredns-resolve \
						-r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt \
						--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
						-o .tmp/permute1_recursive.txt $AXIOM_EXTRA_ARGS \
						2>>"$LOGFILE" >/dev/null
				fi
			fi

			# Second round of permutations
			if [[ $PERMUTATIONS_OPTION == "gotator" ]]; then
				if [[ -s ".tmp/permute1_recursive.txt" ]]; then
					gotator -sub .tmp/permute1_recursive.txt -perm "${tools}/permutations_list.txt" $GOTATOR_FLAGS -silent \
						2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator2_recursive.txt
				fi
			else
				if [[ -s ".tmp/permute1_recursive.txt" ]]; then
					ripgen -d .tmp/permute1_recursive.txt -w "${tools}/permutations_list.txt" \
						2>>"$LOGFILE" | head -c "$PERMUTATIONS_LIMIT" >.tmp/gotator2_recursive.txt
				fi
			fi

			# Resolve second round of permutations
			if [[ $AXIOM != true ]]; then
				if [[ -s ".tmp/gotator2_recursive.txt" ]]; then
					puredns resolve .tmp/gotator2_recursive.txt -w .tmp/permute2_recursive.txt \
						-r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
						-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
						--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
						2>>"$LOGFILE" >/dev/null
				fi
			else
				if [[ -s ".tmp/gotator2_recursive.txt" ]]; then
					axiom-scan .tmp/gotator2_recursive.txt -m puredns-resolve \
						-r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt \
						--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
						-o .tmp/permute2_recursive.txt $AXIOM_EXTRA_ARGS \
						2>>"$LOGFILE" >/dev/null
				fi
			fi

			# Combine permutations
			if [[ -s ".tmp/permute1_recursive.txt" ]] || [[ -s ".tmp/permute2_recursive.txt" ]]; then
				cat .tmp/permute1_recursive.txt .tmp/permute2_recursive.txt 2>>"$LOGFILE" | anew -q .tmp/permute_recursive.txt
			fi
		else
			end_subfunc "Skipping recursive search: Too many subdomains" "${FUNCNAME[0]}"
			return 0
		fi

		# Check inscope if applicable
		if [[ $INSCOPE == true ]]; then
			if [[ -s ".tmp/permute_recursive.txt" ]]; then
				if ! check_inscope .tmp/permute_recursive.txt 2>>"$LOGFILE" >/dev/null; then
					printf "%b[!] check_inscope command failed on permute_recursive.txt.%b\n" "$bred" "$reset"
				fi
			fi
			if [[ -s ".tmp/brute_recursive.txt" ]]; then
				if ! check_inscope .tmp/brute_recursive.txt 2>>"$LOGFILE" >/dev/null; then
					printf "%b[!] check_inscope command failed on brute_recursive.txt.%b\n" "$bred" "$reset"
				fi
			fi
		fi

		# Combine results for final validation
		if [[ -s ".tmp/permute_recursive.txt" ]] || [[ -s ".tmp/brute_recursive.txt" ]]; then
			if ! cat .tmp/permute_recursive.txt .tmp/brute_recursive.txt 2>>"$LOGFILE" | anew -q .tmp/brute_perm_recursive.txt; then
				printf "%b[!] Failed to combine final results.%b\n" "$bred" "$reset"
				return 1
			fi
		fi

		# Final resolve
		if [[ $AXIOM != true ]]; then
			if [[ -s ".tmp/brute_perm_recursive.txt" ]]; then
				puredns resolve .tmp/brute_perm_recursive.txt -w .tmp/brute_perm_recursive_final.txt \
					-r "$resolvers" --resolvers-trusted "$resolvers_trusted" \
					-l "$PUREDNS_PUBLIC_LIMIT" --rate-limit-trusted "$PUREDNS_TRUSTED_LIMIT" \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					2>>"$LOGFILE" >/dev/null
			fi
		else
			if [[ -s ".tmp/brute_perm_recursive.txt" ]]; then
				axiom-scan .tmp/brute_perm_recursive.txt -m puredns-resolve \
					-r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt \
					--wildcard-tests "$PUREDNS_WILDCARDTEST_LIMIT" --wildcard-batch "$PUREDNS_WILDCARDBATCH_LIMIT" \
					-o .tmp/brute_perm_recursive_final.txt $AXIOM_EXTRA_ARGS \
					2>>"$LOGFILE" >/dev/null
			fi
		fi

		# Process final results
		if [[ -s ".tmp/brute_perm_recursive_final.txt" ]]; then
			if ! NUMOFLINES=$(grep "\.$domain$\|^$domain$" .tmp/brute_perm_recursive_final.txt 2>>"$LOGFILE" |
				grep -E '^([a-zA-Z0-9\.\-]+\.)+[a-zA-Z]{1,}$' |
				sed '/^$/d' |
				anew subdomains/subdomains.txt |
				wc -l); then
				printf "%b[!] Failed to count new subdomains.%b\n" "$bred" "$reset"
				NUMOFLINES=0
			fi
		else
			NUMOFLINES=0
		fi

		end_subfunc "${NUMOFLINES} new subs (recursive active)" "${FUNCNAME[0]}"

	else
		if [[ $SUB_RECURSIVE_BRUTE == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		elif [[ ! -s "subdomains/subdomains.txt" ]]; then
			printf "\n%s[%s] No subdomains to process.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" \
				"$called_fn_dir" "/.${FUNCNAME[0]}" "$reset"
		fi
	fi
}

function subtakeover() {

	# Create necessary directories
	if ! mkdir -p .tmp webs subdomains; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SUBTAKEOVER == true ]]; then
		start_func "${FUNCNAME[0]}" "Looking for possible subdomain and DNS takeover"

		# Initialize takeover file
		if ! touch .tmp/tko.txt; then
			printf "%b[!] Failed to create .tmp/tko.txt.%b\n" "$bred" "$reset"
			return 1
		fi

		# Combine webs.txt and webs_uncommon_ports.txt if webs_all.txt doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		fi

		if [[ $AXIOM != true ]]; then
			if ! nuclei -update 2>>"$LOGFILE" >/dev/null; then
				printf "%b[!] Failed to update nuclei.%b\n" "$bred" "$reset"
			fi
			cat subdomains/subdomains.txt webs/webs_all.txt 2>/dev/null | nuclei -silent -nh -tags takeover \
				-severity info,low,medium,high,critical -retries 3 -rl "$NUCLEI_RATELIMIT" \
				-t "${NUCLEI_TEMPLATES_PATH}" -j -o .tmp/tko_json.txt 2>>"$LOGFILE" >/dev/null
		else
			cat subdomains/subdomains.txt webs/webs_all.txt 2>>"$LOGFILE" | sed '/^$/d' | anew -q .tmp/webs_subs.txt
			if [[ -s ".tmp/webs_subs.txt" ]]; then
				axiom-scan .tmp/webs_subs.txt -m nuclei --nuclei-templates "${NUCLEI_TEMPLATES_PATH}" \
					-tags takeover -nh -severity info,low,medium,high,critical -retries 3 -rl "$NUCLEI_RATELIMIT" \
					-t "${NUCLEI_TEMPLATES_PATH}" -j -o .tmp/tko_json.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
		fi

		# Convert JSON to text
		if [[ -s ".tmp/tko_json.txt" ]]; then
			jq -r '["[" + .["template-id"] + (if .["matcher-name"] != null then ":" + .["matcher-name"] else "" end) + "] [" + .["type"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host) + (if .["extracted-results"] != null then " " + (.["extracted-results"] | @json) else "" end)] | .[]' .tmp/tko_json.txt > .tmp/tko.txt
		fi

		# DNS Takeover
		cat .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/scrap_subs.txt \
			.tmp/analytics_subs_clean.txt .tmp/passive_recursive.txt 2>/dev/null | anew -q .tmp/subs_dns_tko.txt

		if [[ -s ".tmp/subs_dns_tko.txt" ]]; then
			cat .tmp/subs_dns_tko.txt 2>/dev/null | dnstake -c "$DNSTAKE_THREADS" -s 2>>"$LOGFILE" |
				sed '/^$/d' | anew -q .tmp/tko.txt
		fi

		# Remove empty lines from tko.txt
		sed -i '/^$/d' .tmp/tko.txt

		# Count new takeover entries
		if ! NUMOFLINES=$(cat .tmp/tko.txt 2>>"$LOGFILE" | anew webs/takeover.txt | sed '/^$/d' | wc -l); then
			printf "%b[!] Failed to count takeover entries.%b\n" "$bred" "$reset"
			NUMOFLINES=0
		fi

		if [[ $NUMOFLINES -gt 0 ]]; then
			notification "${NUMOFLINES} new possible takeovers found" info
		fi

		if [[ $FARADAY == true ]]; then
			if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
				printf "%b[!] Faraday server is not running. Skipping Faraday integration.%b\n" "$bred" "$reset"
			else
				if [[ -s ".tmp/tko_json.txt" ]]; then
					faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei .tmp/tko_json.txt 2>>"$LOGFILE" >/dev/null
				fi
			fi
		fi

		end_func "Results are saved in $domain/webs/takeover.txt" "${FUNCNAME[0]}"

	else
		if [[ $SUBTAKEOVER == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s %b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function zonetransfer() {

	# Create necessary directories
	if ! mkdir -p subdomains; then
		printf "%b[!] Failed to create subdomains directory.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $ZONETRANSFER == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		start_func "${FUNCNAME[0]}" "Zone transfer check"

		# Initialize output file
		if ! : >"subdomains/zonetransfer.txt"; then
			printf "%b[!] Failed to create zonetransfer.txt.%b\n" "$bred" "$reset"
			return 1
		fi

		# Perform zone transfer check
		for ns in $(dig +short ns "$domain"); do
			dig axfr "$domain" @"$ns" >>"subdomains/zonetransfer.txt" 2>>"$LOGFILE"
		done

		# Check if zone transfer was successful
		if [[ -s "subdomains/zonetransfer.txt" ]]; then
			if ! grep -q "Transfer failed" "subdomains/zonetransfer.txt"; then
				notification "Zone transfer found on ${domain}!" "info"
			fi
		fi

		end_func "Results are saved in $domain/subdomains/zonetransfer.txt" "${FUNCNAME[0]}"

	else
		if [[ $ZONETRANSFER == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			printf "\n%s[%s] Domain is an IP address; skipping zone transfer.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function s3buckets() {
	# Create necessary directories
	if ! mkdir -p .tmp subdomains; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $S3BUCKETS == true ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		start_func "${FUNCNAME[0]}" "AWS S3 buckets search"

		# If in multi mode and subdomains.txt doesn't exist, create it
		if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
			if ! printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"; then
				printf "%b[!] Failed to create subdomains.txt.%b\n" "$bred" "$reset"
				return 1
			fi
		fi

		# Debug: Print current directory and tools variable
		printf "Current directory: %s\n" "$(pwd)" >>"$LOGFILE"
		printf "Tools directory: %s\n" "$tools" >>"$LOGFILE"

		# S3Scanner
		if [[ $AXIOM != true ]]; then
			if [[ -s "subdomains/subdomains.txt" ]]; then
				s3scanner scan -f subdomains/subdomains.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt
			fi
		else
			axiom-scan subdomains/subdomains.txt -m s3scanner -o .tmp/s3buckets_tmp.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null

			if [[ -s ".tmp/s3buckets_tmp.txt" ]]; then
				if ! cat .tmp/s3buckets_tmp.txt .tmp/s3buckets_tmp2.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt; then
					printf "%b[!] Failed to process s3buckets_tmp.txt.%b\n" "$bred" "$reset"
				fi
				if ! sed -i '/^$/d' .tmp/s3buckets.txt; then
					printf "%b[!] Failed to clean s3buckets.txt.%b\n" "$bred" "$reset"
				fi
			fi
		fi

		# Include root domain in the process
		if ! printf "%b\n" "$domain" >webs/full_webs.txt; then
			printf "%b[!] Failed to create webs/full_webs.txt.%b\n" "$bred" "$reset"
		fi

		if [[ -s "webs/webs_all.txt" ]]; then
			if ! cat webs/webs_all.txt >>webs/full_webs.txt; then
				printf "%b[!] Failed to append webs_all.txt to full_webs.txt.%b\n" "$bred" "$reset"
			fi
		fi

		# Initialize the output file in the subdomains folder
		if ! : >subdomains/cloudhunter_open_buckets.txt; then
			printf "%b[!] Failed to initialize cloudhunter_open_buckets.txt.%b\n" "$bred" "$reset"
		fi

		# Determine the CloudHunter permutations flag based on the config
		PERMUTATION_FLAG=""
		case "$CLOUDHUNTER_PERMUTATION" in
		DEEP)
			PERMUTATION_FLAG="-p $tools/CloudHunter/permutations-big.txt"
			;;
		NORMAL)
			PERMUTATION_FLAG="-p $tools/CloudHunter/permutations.txt"
			;;
		NONE)
			PERMUTATION_FLAG=""
			;;
		*)
			printf "%b[!] Invalid value for CLOUDHUNTER_PERMUTATION: %s.%b\n" "$bred" "$CLOUDHUNTER_PERMUTATION" "$reset"
			return 1
			;;
		esac

		# Debug: Print the full CloudHunter command
		printf "CloudHunter command: %s/venv/bin/python3 %s/cloudhunter.py %s -r %s/resolvers.txt -t 50 [URL]\n" "$tools/CloudHunter" "$tools/CloudHunter" "$PERMUTATION_FLAG" "$tools/CloudHunter" >>"$LOGFILE"

		# Debug: Check if files exist
		if [[ -f "$tools/CloudHunter/cloudhunter.py" ]]; then
			printf "cloudhunter.py exists\n" >>"$LOGFILE"
		else
			printf "cloudhunter.py not found\n" >>"$LOGFILE"
		fi

		if [[ -n $PERMUTATION_FLAG ]]; then
			permutation_file="${PERMUTATION_FLAG#-p }"
			if [[ -f $permutation_file ]]; then
				printf "Permutations file exists\n" >>"$LOGFILE"
			else
				printf "Permutations file not found: %s\n" "$permutation_file" >>"$LOGFILE"
			fi
		fi

		if [[ -f "$tools/CloudHunter/resolvers.txt" ]]; then
			printf "resolvers.txt exists\n" >>"$LOGFILE"
		else
			printf "resolvers.txt not found\n" >>"$LOGFILE"
		fi

		# Run CloudHunter on each URL in webs/full_webs.txt and append the output to the file in the subdomains folder
		while IFS= read -r url; do
			printf "Processing URL: %s\n" "$url" >>"$LOGFILE"
			(
				if ! cd "$tools/CloudHunter"; then
					printf "%b[!] Failed to cd to %s.%b\n" "$bred" "$tools/CloudHunter" "$reset"
					return 1
				fi
				if ! "${tools}/CloudHunter/venv/bin/python3" ./cloudhunter.py ${PERMUTATION_FLAG#-p } -r ./resolvers.txt -t 50 "$url"; then
					printf "%b[!] CloudHunter command failed for URL %s.%b\n" "$bred" "$url" "$reset"
				fi
			) >>"$dir/subdomains/cloudhunter_open_buckets.txt" 2>>"$LOGFILE"
		done <webs/full_webs.txt

		# Remove the full_webs.txt file after CloudHunter processing
		if ! rm webs/full_webs.txt; then
			printf "%b[!] Failed to remove webs/full_webs.txt.%b\n" "$bred" "$reset"
		fi

		# Process CloudHunter results
		if [[ -s "subdomains/cloudhunter_open_buckets.txt" ]]; then
			if ! NUMOFLINES1=$(cat subdomains/cloudhunter_open_buckets.txt 2>>"$LOGFILE" | anew subdomains/cloud_assets.txt | wc -l); then
				printf "%b[!] Failed to process cloudhunter_open_buckets.txt.%b\n" "$bred" "$reset"
				NUMOFLINES1=0
			fi
			if [[ $NUMOFLINES1 -gt 0 ]]; then
				notification "${NUMOFLINES1} new cloud assets found" "info"
			fi
		else
			NUMOFLINES1=0
		fi

		# Process s3buckets results
		if [[ -s ".tmp/s3buckets.txt" ]]; then
			if ! NUMOFLINES2=$(cat .tmp/s3buckets.txt 2>>"$LOGFILE" | grep -aiv "not_exist" | grep -aiv "Warning:" | grep -aiv "invalid_name" | grep -aiv "^http" | awk 'NF' | anew subdomains/s3buckets.txt | sed '/^$/d' | wc -l); then
				printf "%b[!] Failed to process s3buckets.txt.%b\n" "$bred" "$reset"
				NUMOFLINES2=0
			fi
			if [[ $NUMOFLINES2 -gt 0 ]]; then
				notification "${NUMOFLINES2} new S3 buckets found" "info"
			fi
		else
			NUMOFLINES2=0
		fi

		# Run trufflehog for S3 buckets
		if [[ -s "subdomains/s3buckets.txt" ]]; then
			while IFS= read -r bucket; do
				trufflehog s3 --bucket="$bucket" -j 2>/dev/null | jq -c | anew -q subdomains/s3buckets_trufflehog.txt
			done <subdomains/s3buckets.txt
		fi

		# Run trufflehog for open buckets found by CloudHunter
		if [[ -s "subdomains/cloudhunter_open_buckets.txt" ]]; then
			while IFS= read -r line; do
				if echo "$line" | grep -q "Aws Cloud"; then
					# AWS S3 Bucket
					bucket_name=$(echo "$line" | awk '{print $3}')
					trufflehog s3 --bucket="$bucket_name" -j 2>/dev/null | jq -c | anew -q subdomains/cloudhunter_buckets_trufflehog.txt
				elif echo "$line" | grep -q "Google Cloud"; then
					# Google Cloud Storage
					bucket_name=$(echo "$line" | awk '{print $3}')
					trufflehog gcs --bucket="$bucket_name" -j 2>/dev/null | jq -c | anew -q subdomains/cloudhunter_buckets_trufflehog.txt
				fi
			done <subdomains/cloudhunter_open_buckets.txt
		fi

		end_func "Results are saved in subdomains/s3buckets.txt, subdomains/cloud_assets.txt, subdomains/s3buckets_trufflehog.txt, and subdomains/cloudhunter_buckets_trufflehog.txt" "${FUNCNAME[0]}"
	else
		if [[ $S3BUCKETS == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			printf "\n%s[%s] Domain is an IP address; skipping S3 buckets search.%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
			return 0
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
		fi
	fi
}

###############################################################################################################
############################################# GEOLOCALIZATION INFO ############################################
###############################################################################################################

function geo_info() {

	# Create necessary directories
	if ! mkdir -p hosts; then
		printf "%b[!] Failed to create hosts directory.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GEO_INFO == true ]]; then
		start_func "${FUNCNAME[0]}" "Running: ipinfo"

		ips_file="${dir}/hosts/ips.txt"

		# Check if ips.txt exists or is empty; if so, attempt to generate it
		if [[ ! -s $ips_file ]]; then
			# Attempt to generate hosts/ips.txt
			if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
				if [[ -s "subdomains/subdomains_dnsregs.json" ]]; then
					jq -r 'try . | "\(.host) \(.a[0])"' "subdomains/subdomains_dnsregs.json" | anew -q .tmp/subs_ips.txt
				fi
				if [[ -s ".tmp/subs_ips.txt" ]]; then
					awk '{ print $2 " " $1}' .tmp/subs_ips.txt | sort -k2 -n | anew -q hosts/subs_ips_vhosts.txt
				fi
				if [[ -s "hosts/subs_ips_vhosts.txt" ]]; then
					cut -d ' ' -f1 hosts/subs_ips_vhosts.txt |
						grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." |
						grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" |
						anew -q hosts/ips.txt
				fi
			else
				printf "%b\n" "$domain" |
					grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." |
					grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" |
					anew -q hosts/ips.txt
			fi
		fi

		if [[ -s $ips_file ]]; then
			if ! touch "${dir}/hosts/ipinfo.txt"; then
				printf "%b[!] Failed to create ipinfo.txt.%b\n" "$bred" "$reset"
			fi

			while IFS= read -r ip; do
				curl -s "https://ipinfo.io/widget/demo/$ip" >>"${dir}/hosts/ipinfo.txt"
			done <"$ips_file"
		fi

		end_func "Results are saved in hosts/ipinfo.txt" "${FUNCNAME[0]}"
	else
		if [[ $GEO_INFO == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
		fi
	fi

}

###############################################################################################################
########################################### WEB DETECTION #####################################################
###############################################################################################################

function webprobe_simple() {

	# Create necessary directories
	if ! mkdir -p .tmp webs subdomains; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBPROBESIMPLE == true ]]; then
		start_subfunc "${FUNCNAME[0]}" "Running: HTTP probing $domain"

		# If in multi mode and subdomains.txt doesn't exist, create it
		if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
			printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
			touch .tmp/web_full_info.txt webs/web_full_info.txt
		fi

		# Run httpx or axiom-scan
		if [[ $AXIOM != true ]]; then
			httpx ${HTTPX_FLAGS} -no-color -json -random-agent -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" \
				-retries 2 -timeout "$HTTPX_TIMEOUT" -o .tmp/web_full_info_probe.txt \
				<subdomains/subdomains.txt 2>>"$LOGFILE" >/dev/null
		else
			axiom-scan subdomains/subdomains.txt -m httpx ${HTTPX_FLAGS} -no-color -json -random-agent \
				-threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -retries 2 -timeout "$HTTPX_TIMEOUT" \
				-o .tmp/web_full_info_probe.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
		fi

		# Merge web_full_info files
		cat .tmp/web_full_info.txt .tmp/web_full_info_probe.txt webs/web_full_info.txt 2>>"$LOGFILE" |
			jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"$LOGFILE" >webs/web_full_info.txt

		# Extract URLs
		if [[ -s "webs/web_full_info.txt" ]]; then
			jq -r 'try .url' webs/web_full_info.txt 2>/dev/null |
				grep "$domain" |
				grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' |
				sed 's/*.//' | anew -q .tmp/probed_tmp.txt
		fi

		# Extract web info to plain text
		if [[ -s "webs/web_full_info.txt" ]]; then
			jq -r 'try . |"\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' webs/web_full_info.txt |
				grep "$domain" | anew -q webs/web_full_info_plain.txt
		fi

		# Remove out-of-scope entries
		if [[ -s $outOfScope_file ]]; then
			if ! deleteOutScoped "$outOfScope_file" .tmp/probed_tmp.txt; then
				printf "%b[!] Failed to delete out-of-scope entries.%b\n" "$bred" "$reset"
			fi
		fi

		# Count new websites
		if ! NUMOFLINES=$(anew webs/webs.txt <.tmp/probed_tmp.txt 2>/dev/null | sed '/^$/d' | wc -l); then
			printf "%b[!] Failed to count new websites.%b\n" "$bred" "$reset"
			NUMOFLINES=0
		fi

		# Update webs_all.txt
		cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt

		end_subfunc "${NUMOFLINES} new websites resolved" "${FUNCNAME[0]}"

		# Send websites to proxy if conditions met
		if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/webs.txt) -le $DEEP_LIMIT2 ]]; then
			notification "Sending websites to proxy" "info"
			ffuf -mc all -w webs/webs.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
		fi

	else
		if [[ $WEBPROBESIMPLE == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function webprobe_full() {

	# Create necessary directories
	if ! mkdir -p .tmp webs subdomains; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBPROBEFULL == true ]]; then
		start_func "${FUNCNAME[0]}" "HTTP Probing Non-Standard Ports"

		# If in multi mode and subdomains.txt doesn't exist, create it
		if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
			printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
			touch webs/webs.txt
		fi

		# Check if subdomains.txt is non-empty
		if [[ -s "subdomains/subdomains.txt" ]]; then
			if [[ $AXIOM != true ]]; then
				# Run httpx on subdomains.txt
				httpx -follow-host-redirects -random-agent -status-code \
					-p "$UNCOMMON_PORTS_WEB" -threads "$HTTPX_UNCOMMONPORTS_THREADS" \
					-timeout "$HTTPX_UNCOMMONPORTS_TIMEOUT" -silent -retries 2 \
					-title -web-server -tech-detect -location -no-color -json \
					-o .tmp/web_full_info_uncommon.txt <subdomains/subdomains.txt 2>>"$LOGFILE" >/dev/null
			else
				# Run axiom-scan with httpx module on subdomains.txt
				axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects \
					-H "${HEADER}" -status-code -p "$UNCOMMON_PORTS_WEB" \
					-threads "$HTTPX_UNCOMMONPORTS_THREADS" -timeout "$HTTPX_UNCOMMONPORTS_TIMEOUT" \
					-silent -retries 2 -title -web-server -tech-detect -location -no-color -json \
					-o .tmp/web_full_info_uncommon.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
			fi
		fi

		# Process web_full_info_uncommon.txt
		if [[ -s ".tmp/web_full_info_uncommon.txt" ]]; then
			# Extract URLs
			jq -r 'try .url' .tmp/web_full_info_uncommon.txt 2>/dev/null |
				grep "$domain" |
				grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?' |
				sed 's/*.//' |
				anew -q .tmp/probed_uncommon_ports_tmp.txt

			# Extract plain web info
			jq -r 'try . | "\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' .tmp/web_full_info_uncommon.txt |
				grep "$domain" |
				anew -q webs/web_full_info_uncommon_plain.txt

			# Update webs_full_info_uncommon.txt based on whether domain is IP
			if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
				cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | anew -q webs/web_full_info_uncommon.txt
			else
				grep "$domain" .tmp/web_full_info_uncommon.txt | anew -q webs/web_full_info_uncommon.txt
			fi

			# Count new websites
			if ! NUMOFLINES=$(anew webs/webs_uncommon_ports.txt <.tmp/probed_uncommon_ports_tmp.txt | sed '/^$/d' | wc -l); then
				printf "%b[!] Failed to count new websites.%b\n" "$bred" "$reset"
				NUMOFLINES=0
			fi

			# Notify user
			notification "Uncommon web ports: ${NUMOFLINES} new websites" "good"

			# Display new uncommon ports websites
			if [[ -s "webs/webs_uncommon_ports.txt" ]]; then
				cat "webs/webs_uncommon_ports.txt"
			fi

			# Update webs_all.txt
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt

			end_func "Results are saved in $domain/webs/webs_uncommon_ports.txt" "${FUNCNAME[0]}"

			# Send to proxy if conditions met
			if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/webs_uncommon_ports.txt) -le $DEEP_LIMIT2 ]]; then
				notification "Sending websites with uncommon ports to proxy" "info"
				ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
			fi
		fi
	else
		if [[ $WEBPROBEFULL == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function screenshot() {

	# Create necessary directories
	if ! mkdir -p webs screenshots; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBSCREENSHOT == true ]]; then
		start_func "${FUNCNAME[0]}" "Web Screenshots"

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		fi

		# Run nuclei or axiom-scan based on AXIOM flag
		if [[ $AXIOM != true ]]; then
			if [[ -s "webs/webs_all.txt" ]]; then
				nuclei -headless -id screenshot -V dir='screenshots' <webs/webs_all.txt 2>>"$LOGFILE"
			fi
		else
			if [[ -s "webs/webs_all.txt" ]]; then
				axiom-scan webs/webs_all.txt -m nuclei-screenshots -o screenshots "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
			fi
		fi

		# Extract and process URLs from web_full_info_uncommon.txt
		if [[ -s ".tmp/web_full_info_uncommon.txt" ]]; then
			jq -r 'try .url' .tmp/web_full_info_uncommon.txt 2>/dev/null |
				grep "$domain" |
				grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?' |
				sed 's/*.//' |
				anew -q .tmp/probed_uncommon_ports_tmp.txt

			jq -r 'try . | "\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' .tmp/web_full_info_uncommon.txt |
				grep "$domain" |
				anew -q webs/web_full_info_uncommon_plain.txt

			# Update webs_full_info_uncommon.txt based on whether domain is IP
			if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
				cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | anew -q webs/web_full_info_uncommon.txt
			else
				grep "$domain" .tmp/web_full_info_uncommon.txt | anew -q webs/web_full_info_uncommon.txt
			fi

			# Count new websites
			if ! NUMOFLINES=$(anew webs/webs_uncommon_ports.txt <.tmp/probed_uncommon_ports_tmp.txt 2>>"$LOGFILE" | sed '/^$/d' | wc -l); then
				printf "%b[!] Failed to count new websites.%b\n" "$bred" "$reset"
				NUMOFLINES=0
			fi

			# Notify user
			notification "Uncommon web ports: ${NUMOFLINES} new websites" "good"

			# Display new uncommon ports websites
			if [[ -s "webs/webs_uncommon_ports.txt" ]]; then
				cat "webs/webs_uncommon_ports.txt"
			fi

			# Update webs_all.txt
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt

			end_func "Results are saved in $domain/screenshots folder" "${FUNCNAME[0]}"

			# Send to proxy if conditions met
			if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/webs_uncommon_ports.txt) -le $DEEP_LIMIT2 ]]; then
				notification "Sending websites with uncommon ports to proxy" "info"
				ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
			fi
		fi
	else
		if [[ $WEBSCREENSHOT == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function virtualhosts() {

	# Create necessary directories
	if ! mkdir -p .tmp/virtualhosts virtualhosts webs; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $VIRTUALHOSTS == true ]]; then
		start_func "${FUNCNAME[0]}" "Virtual Hosts Discovery"

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		fi

		# Proceed only if webs_all.txt exists and is non-empty
		if [[ -s "webs/webs_all.txt" ]]; then
			if [[ $AXIOM != true ]]; then
				# Run ffuf using interlace
				interlace -tL webs/webs_all.txt -threads "$INTERLACE_THREADS" \
					-c "ffuf -ac -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} \
					-H \"${HEADER}\" -H \"Host: FUZZ._cleantarget_\" \
					-w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} \
					-u _target_ -of json -o _output_/_cleantarget_.json" \
					-o .tmp/virtualhosts 2>>"$LOGFILE" >/dev/null
			else
				# Run axiom-scan with ffuf module
				axiom-scan webs/webs_all.txt -m ffuf -ac -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} \
					-H "${HEADER}" -H "Host: FUZZ._cleantarget_" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} \
					-o .tmp/virtualhosts "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
			fi

			# Process ffuf output
			while IFS= read -r sub; do
				sub_out=$(echo "$sub" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				json_file="$dir/.tmp/virtualhosts/${sub_out}.json"
				txt_file="$dir/virtualhosts/${sub_out}.txt"

				if [[ -s $json_file ]]; then
					jq -r 'try .results[] | "\(.status) \(.length) \(.url)"' "$json_file" | sort | anew -q "$txt_file"
				fi
			done

			# Merge all virtual host txt files into virtualhosts_full.txt
			find "$dir/virtualhosts/" -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | anew -q "$dir/virtualhosts/virtualhosts_full.txt"

			end_func "Results are saved in $domain/virtualhosts/*subdomain*.txt" "${FUNCNAME[0]}"

		else
			end_func "No webs/webs_all.txt file found, virtualhosts skipped." "${FUNCNAME[0]}"
		fi

		# Optionally send to proxy if conditions are met
		if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/webs_uncommon_ports.txt) -le $DEEP_LIMIT2 ]]; then
			notification "Sending websites with uncommon ports to proxy" "info"
			ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
		fi

	else
		if [[ $VIRTUALHOSTS == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

###############################################################################################################
############################################# HOST SCAN #######################################################
###############################################################################################################

function favicon() {

	# Create necessary directories
	if ! mkdir -p hosts .tmp/virtualhosts; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } &&
		[[ $FAVICON == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Favicon IP Lookup"

		# Navigate to the fav-up tool directory
		if ! pushd "${tools}/fav-up" >/dev/null; then
			printf "%b[!] Failed to change directory to %s in %s @ line %s.%b\n" \
				"$bred" "${tools}/fav-up" "${FUNCNAME[0]}" "${LINENO}" "$reset"
			return 1
		fi

		# Run the favicon IP lookup tool
		"${tools}/fav-up/venv/bin/python3" "${tools}/fav-up/favUp.py" -w "$domain" -sc -o favicontest.json 2>>"$LOGFILE" >/dev/null

		# Process the results if favicontest.json exists and is not empty
		if [[ -s "favicontest.json" ]]; then
			jq -r 'try .found_ips' favicontest.json 2>>"$LOGFILE" |
				grep -v "not-found" >favicontest.txt

			# Replace '|' with newlines
			sed -i "s/|/\n/g" favicontest.txt

			# Move the processed IPs to the hosts directory
			mv favicontest.txt "$dir/hosts/favicontest.txt" 2>>"$LOGFILE"

			# Remove the JSON file
			rm -f favicontest.json 2>>"$LOGFILE"
		fi

		# Return to the original directory
		if ! popd >/dev/null; then
			printf "%b[!] Failed to return to the previous directory in %s @ line %s.%b\n" \
				"$bred" "${FUNCNAME[0]}" "${LINENO}" "$reset"
		fi

		end_func "Results are saved in hosts/favicontest.txt" "${FUNCNAME[0]}"

	else
		if [[ $FAVICON == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP, do nothing
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi

}

function portscan() {

	# Create necessary directories
	if ! mkdir -p .tmp subdomains hosts; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PORTSCANNER == true ]]; then
		start_func "${FUNCNAME[0]}" "Port scan"

		# Determine if domain is IP address or domain name
		if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Not an IP address
			if [[ -s "subdomains/subdomains_dnsregs.json" ]]; then
				# Extract host and IP from JSON
				jq -r 'try . | "\(.host) \(.a[0])"' "subdomains/subdomains_dnsregs.json" | anew -q .tmp/subs_ips.txt
			fi

			if [[ -s ".tmp/subs_ips.txt" ]]; then
				# Reorder fields and sort
				awk '{ print $2 " " $1}' ".tmp/subs_ips.txt" | sort -k2 -n | anew -q hosts/subs_ips_vhosts.txt
			fi

			if [[ -s "hosts/subs_ips_vhosts.txt" ]]; then
				# Extract IPs, filter out private ranges
				awk '{print $1}' "hosts/subs_ips_vhosts.txt" | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | anew -q hosts/ips.txt
			fi

		else
			# Domain is an IP address
			printf "%b\n" "$domain" | grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | anew -q hosts/ips.txt
		fi

		# Check for CDN providers
		if [[ ! -s "hosts/cdn_providers.txt" ]]; then
			if [[ -s "hosts/ips.txt" ]]; then
				cdncheck -silent -resp -cdn -waf -nc <hosts/ips.txt 2>/dev/null >hosts/cdn_providers.txt
			fi
		fi

		if [[ -s "hosts/ips.txt" ]]; then
			# Remove CDN IPs
			comm -23 <(sort -u hosts/ips.txt) <(cut -d'[' -f1 hosts/cdn_providers.txt | sed 's/[[:space:]]*$//' | sort -u) |
				grep -aEiv "^(127|10|169\.254|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]|192\.168)\." | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' |
				sort -u | anew -q .tmp/ips_nocdn.txt
		fi

		# Display resolved IPs without CDN
		printf "%b\n[%s] Resolved IP addresses (No CDN):%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
		if [[ -s ".tmp/ips_nocdn.txt" ]]; then
			sort ".tmp/ips_nocdn.txt"
		fi

		printf "%b\n[%s] Scanning ports...%b\n\n" "$bblue" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"

		ips_file="${dir}/hosts/ips.txt"

		if [[ $PORTSCAN_PASSIVE == true ]]; then
			if [[ ! -f $ips_file ]]; then
				printf "%b[!] File %s does not exist.%b\n" "$bred" "$ips_file" "$reset"
			else
				json_array=()
				while IFS= read -r cip; do
					if ! json_result=$(curl -s "https://internetdb.shodan.io/${cip}"); then
						printf "%b[!] Failed to retrieve data for IP %s.%b\n" "$bred" "$cip" "$reset"
					else
						json_array+=("$json_result")
					fi
				done <"$ips_file"
				formatted_json="["
				for ((i = 0; i < ${#json_array[@]}; i++)); do
					formatted_json+="$(echo "${json_array[i]}" | tr -d '\n')"
					if [ $i -lt $((${#json_array[@]} - 1)) ]; then
						formatted_json+=", "
					fi
				done
				formatted_json+="]"
				if ! echo "$formatted_json" >"${dir}/hosts/portscan_shodan.txt"; then
					printf "%b[!] Failed to write portscan_shodan.txt.%b\n" "$bred" "$reset"
				fi
			fi
		fi

		if [[ $PORTSCAN_PASSIVE == true ]] && [[ ! -f "hosts/portscan_passive.txt" ]] && [[ -s ".tmp/ips_nocdn.txt" ]]; then
			smap -iL .tmp/ips_nocdn.txt >hosts/portscan_passive.txt
		fi

		if [[ $PORTSCAN_ACTIVE == true ]]; then
			if [[ $AXIOM != true ]]; then
				if [[ -s ".tmp/ips_nocdn.txt" ]]; then
					$SUDO nmap $PORTSCAN_ACTIVE_OPTIONS -iL .tmp/ips_nocdn.txt -oA hosts/portscan_active 2>>"$LOGFILE" >/dev/null
				fi
			else
				if [[ -s ".tmp/ips_nocdn.txt" ]]; then
					axiom-scan .tmp/ips_nocdn.txt -m nmapx $PORTSCAN_ACTIVE_OPTIONS \
						-oA hosts/portscan_active $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
				fi
			fi
		fi

		if [[ -s "hosts/portscan_active.xml" ]]; then
			nmapurls <hosts/portscan_active.xml 2>>"$LOGFILE" | anew -q hosts/webs.txt
		fi


		if [[ $FARADAY == true ]]; then
			# Check if the Faraday server is running
			if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
				printf "%b[!] Faraday server is not running. Skipping Faraday integration.%b\n" "$bred" "$reset"
			else
				if [[ -s "hosts/portscan_active.xml" ]]; then
					faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nmap hosts/portscan_active.xml 2>>"$LOGFILE" >/dev/null
				fi
			fi
		fi


		if [[ -s "hosts/webs.txt" ]]; then
			if ! NUMOFLINES=$(wc -l <hosts/webs.txt); then
				printf "%b[!] Failed to count lines in hosts/webs.txt.%b\n" "$bred" "$reset"
				NUMOFLINES=0
			fi
			notification "Webs detected from port scan: ${NUMOFLINES} new websites" "good"
			cat hosts/webs.txt
		fi

		end_func "Results are saved in hosts/portscan_[passive|active|shodan].[txt|xml]" "${FUNCNAME[0]}"

	else
		if [[ $PORTSCANNER == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function cdnprovider() {

	# Create necessary directories
	if ! mkdir -p .tmp subdomains hosts; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } &&
		[[ $CDN_IP == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "CDN Provider Check"

		# Check if subdomains_dnsregs.json exists and is not empty
		if [[ -s "subdomains/subdomains_dnsregs.json" ]]; then
			# Extract IPs from .a[] fields, exclude private IPs, extract IPs, sort uniquely
			jq -r 'try . | .a[]' "subdomains/subdomains_dnsregs.json" |
				grep -aEiv "^(127|10|169\.254|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\." |
				grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" |
				sort -u >.tmp/ips_cdn.txt
		fi

		# Check if ips_cdn.txt exists and is not empty
		if [[ -s ".tmp/ips_cdn.txt" ]]; then
			# Run cdncheck on the IPs and save to cdn_providers.txt
			cdncheck -silent -resp -nc <.tmp/ips_cdn.txt | anew -q "$dir/hosts/cdn_providers.txt"
		fi

		end_func "Results are saved in hosts/cdn_providers.txt" "${FUNCNAME[0]}"

	else
		if [[ $CDN_IP == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP, do nothing
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi

}

###############################################################################################################
############################################# WEB SCAN ########################################################
###############################################################################################################

function waf_checks() {

	# Create necessary directories
	if ! mkdir -p .tmp webs; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WAF_DETECTION == true ]]; then
		start_func "${FUNCNAME[0]}" "Website's WAF Detection"

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		fi

		# Proceed only if webs_all.txt exists and is non-empty
		if [[ -s "webs/webs_all.txt" ]]; then
			if [[ $AXIOM != true ]]; then
				# Run wafw00f on webs_all.txt
				wafw00f -i "webs/webs_all.txt" -o ".tmp/wafs.txt" 2>>"$LOGFILE" >/dev/null
			else
				# Run axiom-scan with wafw00f module on webs_all.txt
				axiom-scan "webs/webs_all.txt" -m wafw00f -o ".tmp/wafs.txt" "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
			fi

			# Process wafs.txt if it exists and is not empty
			if [[ -s ".tmp/wafs.txt" ]]; then
				# Format the wafs.txt file
				sed -e 's/^[ \t]*//' -e 's/ \+ /\t/g' -e '/(None)/d' ".tmp/wafs.txt" | tr -s "\t" ";" >"webs/webs_wafs.txt"

				# Count the number of websites protected by WAF
				if ! NUMOFLINES=$(sed '/^$/d' "webs/webs_wafs.txt" 2>>"$LOGFILE" | wc -l); then
					printf "%b[!] Failed to count lines in webs_wafs.txt.%b\n" "$bred" "$reset"
					NUMOFLINES=0
				fi

				# Send a notification about the number of WAF-protected websites
				notification "${NUMOFLINES} websites protected by WAF" "info"

				# End the function with a success message
				end_func "Results are saved in webs/webs_wafs.txt" "${FUNCNAME[0]}"
			else
				# End the function indicating no results were found
				end_func "No results found" "${FUNCNAME[0]}"
			fi
		else
			# End the function indicating there are no websites to scan
			end_func "No websites to scan" "${FUNCNAME[0]}"
		fi
	else
		# Handle cases where WAF_DETECTION is false or the function has already been processed
		if [[ $WAF_DETECTION == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP address; skip the function
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi

}

function nuclei_check() {

	# Create necessary directories
	if ! mkdir -p .tmp webs subdomains nuclei_output; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $NUCLEICHECK == true ]]; then
		start_func "${FUNCNAME[0]}" "Templates-based Web Scanner"

		# Update nuclei templates
		nuclei -update 2>>"$LOGFILE" >/dev/null

		# Handle multi mode and initialize subdomains.txt if necessary
		if [[ -n $multi ]] && [[ ! -f "$dir/subdomains/subdomains.txt" ]]; then
			printf "%b\n" "$domain" >"$dir/subdomains/subdomains.txt"
			touch webs/webs.txt webs/webs_uncommon_ports.txt
		fi

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		fi

		# Combine url_extract_nodupes.txt, subdomains.txt, and webs_all.txt into webs_subs.txt if it doesn't exist
		if [[ ! -s ".tmp/webs_subs.txt" ]]; then
			cat webs/url_extract_nodupes.txt subdomains/subdomains.txt webs/webs_all.txt 2>>"$LOGFILE" | anew -q .tmp/webs_subs.txt
		fi

		# If fuzzing_full.txt exists, process it and create webs_fuzz.txt
		if [[ -s "$dir/fuzzing/fuzzing_full.txt" ]]; then
			grep "^200" "$dir/fuzzing/fuzzing_full.txt" | cut -d " " -f3 | anew -q .tmp/webs_fuzz.txt
		fi

		# Combine webs_subs.txt and webs_fuzz.txt into webs_nuclei.txt and duplicate it
		cat .tmp/webs_subs.txt .tmp/webs_fuzz.txt 2>>"$LOGFILE" | anew -q .tmp/webs_nuclei.txt | tee -a webs/webs_nuclei.txt

		# Check if AXIOM is enabled
		if [[ $AXIOM != true ]]; then
			# Split severity levels into an array
			IFS=',' read -ra severity_array <<<"$NUCLEI_SEVERITY"

			for crit in "${severity_array[@]}"; do
				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Nuclei Severity: $crit ${reset}\n\n"

				# Run nuclei for each severity level
				nuclei $NUCLEI_FLAGS -severity "$crit" -nh -rl "$NUCLEI_RATELIMIT" "$NUCLEI_EXTRA_ARGS" -j -o "nuclei_output/${crit}_json.txt" <.tmp/webs_nuclei.txt
			done
			printf "\n\n"
		else
			# Check if webs_nuclei.txt exists and is not empty
			if [[ -s ".tmp/webs_nuclei.txt" ]]; then
				# Split severity levels into an array
				IFS=',' read -ra severity_array <<<"$NUCLEI_SEVERITY"

				for crit in "${severity_array[@]}"; do
					printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Axiom Nuclei Severity: $crit. Check results in nuclei_output folder.${reset}\n\n"
					# Run axiom-scan with nuclei module for each severity level
					axiom-scan .tmp/webs_nuclei.txt -m nuclei \
						--nuclei-templates "$NUCLEI_TEMPLATES_PATH" \
						-severity "$crit" -nh -rl "$NUCLEI_RATELIMIT" \
						"$NUCLEI_EXTRA_ARGS" -j -o "nuclei_output/${crit}_json.txt" "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null

					# Parse the JSON output and save the results to a text file
					jq -r '["[" + .["template-id"] + (if .["matcher-name"] != null then ":" + .["matcher-name"] else "" end) + "] [" + .["type"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host) + (if .["extracted-results"] != null then " " + (.["extracted-results"] | @json) else "" end)] | .[]' nuclei_output/${crit}_json.txt > nuclei_output/${crit}.txt

					# Display the results if the output file exists and is not empty
					if [[ -s "nuclei_output/${crit}.txt" ]]; then
						cat "nuclei_output/${crit}.txt"
					fi

					# Faraday integration
					if [[ $FARADAY == true ]]; then
						# Check if the Faraday server is running
						if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
							printf "%b[!] Faraday server is not running. Skipping Faraday integration.%b\n" "$bred" "$reset"
						else
							if [[ -s "nuclei_output/${crit}_json.txt" ]]; then
								faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei nuclei_output/${crit}_json.txt 2>>"$LOGFILE" >/dev/null
							fi
						fi
					fi

				done
				printf "\n\n"
			fi
		fi

		end_func "Results are saved in $domain/nuclei_output folder" "${FUNCNAME[0]}"
	else
		# Handle cases where NUCLEICHECK is false or the function has already been processed
		if [[ $NUCLEICHECK == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP address; skip the function
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi

}

function fuzz() {

	# Create necessary directories
	mkdir -p .tmp/fuzzing webs fuzzing

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FUZZ == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Web Directory Fuzzing"

		# Handle multi mode and initialize subdomains.txt if necessary
		if [[ -n $multi ]] && [[ ! -f "$dir/webs/webs.txt" ]]; then
			if ! printf "%b\n" "$domain" >"$dir/webs/webs.txt"; then
				printf "%b[!] Failed to create webs.txt.%b\n" "$bred" "$reset"
			fi
			if ! touch webs/webs_uncommon_ports.txt; then
				printf "%b[!] Failed to initialize webs_uncommon_ports.txt.%b\n" "$bred" "$reset"
			fi
		fi

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		fi

		if [[ -s "webs/webs_all.txt" ]]; then
			if [[ $AXIOM != true ]]; then
				interlace -tL webs/webs_all.txt -threads ${INTERLACE_THREADS} -c "ffuf ${FFUF_FLAGS} -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u _target_/FUZZ -o _output_/_cleantarget_.json" -o $dir/.tmp/fuzzing 2>>"$LOGFILE" >/dev/null
				for sub in $(cat webs/webs_all.txt); do
					sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')

					pushd "${tools}/ffufPostprocessing" >/dev/null || {
						echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"
					}
					./ffufPostprocessing -result-file $dir/.tmp/fuzzing/${sub_out}.json -overwrite-result-file 2>>"$LOGFILE" >/dev/null
					popd >/dev/null || {
						echo "Failed to popd in ${FUNCNAME[0]} @ line ${LINENO}"
					}

					[ -s "$dir/.tmp/fuzzing/${sub_out}.json" ] && cat $dir/.tmp/fuzzing/${sub_out}.json | jq -r 'try .results[] | "\(.status) \(.length) \(.url)"' | sort -k1 | anew -q $dir/fuzzing/${sub_out}.txt
				done
				find $dir/fuzzing/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | sort -k1 | anew -q $dir/fuzzing/fuzzing_full.txt
			else
				axiom-exec "mkdir -p /home/op/lists/seclists/Discovery/Web-Content/" &>/dev/null
				axiom-exec "wget -q -O - ${fuzzing_remote_list} > /home/op/lists/fuzz_wordlist.txt" &>/dev/null
				axiom-exec "wget -q -O - ${fuzzing_remote_list} > /home/op/lists/seclists/Discovery/Web-Content/big.txt" &>/dev/null
				axiom-scan webs/webs_all.txt -m ffuf_base -H "${HEADER}" $FFUF_FLAGS -s -maxtime $FFUF_MAXTIME -o $dir/.tmp/ffuf-content.json $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
				pushd "${tools}/ffufPostprocessing" >/dev/null || {
					echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"
				}
				[ -s "$dir/.tmp/ffuf-content.json" ] && ./ffufPostprocessing -result-file $dir/.tmp/ffuf-content.json -overwrite-result-file 2>>"$LOGFILE" >/dev/null
				popd >/dev/null || {
					echo "Failed to popd in ${FUNCNAME[0]} @ line ${LINENO}"
				}
				for sub in $(cat webs/webs_all.txt); do
					sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
					[ -s "$dir/.tmp/ffuf-content.json" ] && cat .tmp/ffuf-content.json | jq -r 'try .results[] | "\(.status) \(.length) \(.url)"' | grep $sub | sort -k1 | anew -q fuzzing/${sub_out}.txt
				done
				find $dir/fuzzing/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | sort -k1 | anew -q $dir/fuzzing/fuzzing_full.txt
			fi
			end_func "Results are saved in $domain/fuzzing/*subdomain*.txt" ${FUNCNAME[0]}
		else
			end_func "No $domain/web/webs.txts file found, fuzzing skipped " ${FUNCNAME[0]}
		fi

		end_func "Results are saved in $domain/fuzzing folder" "${FUNCNAME[0]}"
	else
		if [[ $FUZZ == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function iishortname() {

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $IIS_SHORTNAME == true ]]; then
		start_func "${FUNCNAME[0]}" "IIS Shortname Scanner"

		# Ensure nuclei_output/info.txt exists and is not empty
		if [[ -s "nuclei_output/info.txt" ]]; then
			# Extract IIS version information and save to .tmp/iis_sites.txt
			grep "iis-version" "nuclei_output/info.txt" | cut -d " " -f4 >.tmp/iis_sites.txt
		fi

		# Proceed only if iis_sites.txt exists and is non-empty
		if [[ -s ".tmp/iis_sites.txt" ]]; then
			# Create necessary directories
			mkdir -p "$dir/vulns/iis-shortname-shortscan/" "$dir/vulns/iis-shortname-sns/"

			# Run shortscan using interlace
			interlace -tL .tmp/iis_sites.txt -threads "$INTERLACE_THREADS" \
				-c "shortscan _target_ -F -s -p 1 > _output_/_cleantarget_.txt" \
				-o "$dir/vulns/iis-shortname-shortscan/" 2>>"$LOGFILE" >/dev/null

			# Remove non-vulnerable shortscan results
			find "$dir/vulns/iis-shortname-shortscan/" -type f -iname "*.txt" -print0 |
				xargs --null grep -Z -L 'Vulnerable: Yes' |
				xargs --null rm 2>>"$LOGFILE" >/dev/null

			# Run sns using interlace
			interlace -tL .tmp/iis_sites.txt -threads "$INTERLACE_THREADS" \
				-c "sns -u _target_ > _output_/_cleantarget_.txt" \
				-o "$dir/vulns/iis-shortname-sns/" 2>>"$LOGFILE" >/dev/null

			# Remove non-vulnerable sns results
			find "$dir/vulns/iis-shortname-sns/" -type f -iname "*.txt" -print0 |
				xargs --null grep -Z 'Target is not vulnerable' |
				xargs --null rm 2>>"$LOGFILE" >/dev/null

		fi
		end_func "Results are saved in vulns/iis-shortname/" "${FUNCNAME[0]}"
	else
		# Handle cases where IIS_SHORTNAME is false or the function has already been processed
		if [[ $IIS_SHORTNAME == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP address; skip the function
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi

}

function cms_scanner() {

	# Create necessary directories
	if ! mkdir -p .tmp/fuzzing webs cms; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CMS_SCANNER == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "CMS Scanner"

		rm -rf "$dir/cms/"*

		# Handle multi mode and initialize webs.txt if necessary
		if [[ -n $multi ]] && [[ ! -f "$dir/webs/webs.txt" ]]; then
			printf "%b\n" "$domain" >"$dir/webs/webs.txt"
			touch webs/webs_uncommon_ports.txt
		fi

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		fi

		# Combine webs_all.txt into .tmp/cms.txt as a comma-separated list
		if [[ -s "webs/webs_all.txt" ]]; then
			tr '\n' ',' <webs/webs_all.txt >.tmp/cms.txt 2>>"$LOGFILE"
		else
			end_func "No webs/webs_all.txt file found, cms scanner skipped." "${FUNCNAME[0]}"
			return
		fi

		# Run CMSeeK with timeout
		if ! timeout -k 1m "${CMSSCAN_TIMEOUT}s" "${tools}/CMSeeK/venv/bin/python3" "${tools}/CMSeeK/cmseek.py" -l .tmp/cms.txt --batch -r &>>"$LOGFILE"; then
			exit_status=$?
			if [[ ${exit_status} -eq 124 || ${exit_status} -eq 137 ]]; then
				echo "TIMEOUT cmseek.py - investigate manually for $dir" >>"$LOGFILE"
				end_func "TIMEOUT cmseek.py - investigate manually for $dir" "${FUNCNAME[0]}"
				return
			elif [[ ${exit_status} -ne 0 ]]; then
				echo "ERROR cmseek.py - investigate manually for $dir" >>"$LOGFILE"
				end_func "ERROR cmseek.py - investigate manually for $dir" "${FUNCNAME[0]}"
				return
			fi
		fi

		# Process CMSeeK results
		while IFS= read -r sub; do
			sub_out=$(echo "$sub" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
			cms_json_path="${tools}/CMSeeK/Result/${sub_out}/cms.json"

			if [[ -s $cms_json_path ]]; then
				cms_id=$(jq -r 'try .cms_id' "$cms_json_path")
				if [[ -n $cms_id ]]; then
					mv -f "${tools}/CMSeeK/Result/${sub_out}" "$dir/cms/" 2>>"$LOGFILE"
				else
					rm -rf "${tools}/CMSeeK/Result/${sub_out}" 2>>"$LOGFILE"
				fi
			fi
		done <"webs/webs_all.txt"

		end_func "Results are saved in $domain/cms/*subdomain* folder" "${FUNCNAME[0]}"
	else
		# Handle cases where CMS_SCANNER is false or the function has already been processed
		if [[ $CMS_SCANNER == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP address; skip the function
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi
}

function urlchecks() {

	# Create necessary directories
	if ! mkdir -p .tmp webs; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_CHECK == true ]]; then
		start_func "${FUNCNAME[0]}" "URL Extraction"

		# Combine webs.txt and webs_uncommon_ports.txt if webs_all.txt doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		fi

		if [[ -s "webs/webs_all.txt" ]]; then

			if [[ $URL_CHECK_PASSIVE == true ]]; then
				urlfinder -d $domain -o .tmp/url_extract_tmp.txt 2>>"$LOGFILE" >/dev/null
				if [[ -s $GITHUB_TOKENS ]]; then
					github-endpoints -q -k -d "$domain" -t "$GITHUB_TOKENS" -o .tmp/github-endpoints.txt 2>>"$LOGFILE" >/dev/null
					if [[ -s ".tmp/github-endpoints.txt" ]]; then
						cat .tmp/github-endpoints.txt | anew -q .tmp/url_extract_tmp.txt
					fi
				fi
			fi

			if [[ $AXIOM != true ]]; then
				diff_webs=$(diff <(sort -u .tmp/probed_tmp.txt 2>>"$LOGFILE") <(sort -u webs/webs_all.txt 2>>"$LOGFILE") | wc -l)
				if [[ $diff_webs != "0" ]] || [[ ! -s ".tmp/katana.txt" ]]; then
					if [[ $URL_CHECK_ACTIVE == true ]]; then
						if [[ $DEEP == true ]]; then
							katana -silent -list webs/webs_all.txt -jc -kf all -c "$KATANA_THREADS" -d 3 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" >/dev/null
						else
							katana -silent -list webs/webs_all.txt -jc -kf all -c "$KATANA_THREADS" -d 2 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" >/dev/null
						fi
					fi
				fi
			else
				diff_webs=$(diff <(sort -u .tmp/probed_tmp.txt) <(sort -u webs/webs_all.txt) | wc -l)
				if [[ $diff_webs != "0" ]] || [[ ! -s ".tmp/katana.txt" ]]; then
					if [[ $URL_CHECK_ACTIVE == true ]]; then
						if [[ $DEEP == true ]]; then
							axiom-scan webs/webs_all.txt -m katana -jc -kf all -d 3 -fs rdn -o .tmp/katana.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
						else
							axiom-scan webs/webs_all.txt -m katana -jc -kf all -d 2 -fs rdn -o .tmp/katana.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
						fi
					fi
				fi
			fi

			if [[ -s ".tmp/katana.txt" ]]; then
				sed -i '/^.\{2048\}./d' .tmp/katana.txt
				cat .tmp/katana.txt | anew -q .tmp/url_extract_tmp.txt
			fi

			if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
				grep "$domain" .tmp/url_extract_tmp.txt | grep -E '^((http|https):\/\/)?([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}(\/.*)?$' | grep -aEi "\.js$" | anew -q .tmp/url_extract_js.txt
				grep "$domain" .tmp/url_extract_tmp.txt | grep -E '^((http|https):\/\/)?([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}(\/.*)?$' | grep -aEi "\.js\.map$" | anew -q .tmp/url_extract_jsmap.txt
				if [[ $DEEP == true ]] && [[ -s ".tmp/url_extract_js.txt" ]]; then
					interlace -tL .tmp/url_extract_js.txt -threads 10 -c "${tools}/JSA/venv/bin/python3 ${tools}/JSA/jsa.py -f _target_ | anew -q .tmp/url_extract_tmp.txt" &>/dev/null
				fi

				grep "$domain" .tmp/url_extract_tmp.txt | grep -E '^((http|https):\/\/)?([a-zA-Z0-9\-\.]+\.)+[a-zA-Z]{1,}(\/.*)?$' | grep "=" | qsreplace -a 2>>"$LOGFILE" | grep -aEiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | anew -q .tmp/url_extract_tmp2.txt

				if [[ -s ".tmp/url_extract_tmp2.txt" ]]; then
					urless <.tmp/url_extract_tmp2.txt | anew -q .tmp/url_extract_uddup.txt 2>>"$LOGFILE" >/dev/null
				fi

				if [[ -s ".tmp/url_extract_uddup.txt" ]]; then
					if ! NUMOFLINES=$(anew webs/url_extract.txt <.tmp/url_extract_uddup.txt | sed '/^$/d' | wc -l); then
						printf "%b[!] Failed to update url_extract.txt.%b\n" "$bred" "$reset"
						NUMOFLINES=0
					fi
					notification "${NUMOFLINES} new URLs with parameters" "info"
				else
					NUMOFLINES=0
				fi

				end_func "Results are saved in $domain/webs/url_extract.txt" "${FUNCNAME[0]}"

				p1radup -i webs/url_extract.txt -o webs/url_extract_nodupes.txt -s 2>>"$LOGFILE" >/dev/null

				if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ $(wc -l <webs/url_extract.txt) -le $DEEP_LIMIT2 ]]; then
					notification "Sending URLs to proxy" "info"
					ffuf -mc all -w webs/url_extract.txt -u FUZZ -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
				fi
			fi
		fi
	else
		if [[ $URL_CHECK == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function url_gf() {

	# Create necessary directories
	if ! mkdir -p .tmp webs gf; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_GF == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Vulnerable Pattern Search"

		# Ensure webs_nuclei.txt exists and is not empty
		if [[ -s "webs/webs_nuclei.txt" ]]; then
			# Define an array of GF patterns
			declare -A gf_patterns=(
				["xss"]="gf/xss.txt"
				["ssti"]="gf/ssti.txt"
				["ssrf"]="gf/ssrf.txt"
				["sqli"]="gf/sqli.txt"
				["redirect"]="gf/redirect.txt"
				["rce"]="gf/rce.txt"
				["potential"]="gf/potential.txt"
				["lfi"]="gf/lfi.txt"
			)

			# Iterate over GF patterns and process each
			for pattern in "${!gf_patterns[@]}"; do
				output_file="${gf_patterns[$pattern]}"
				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: GF Pattern '$pattern'${reset}\n\n"
				if [[ $pattern == "potential" ]]; then
					# Special handling for 'potential' pattern
					gf "$pattern" "webs/webs_nuclei.txt" | cut -d ':' -f3-5 | anew -q "$output_file"
				elif [[ $pattern == "redirect" && -s "gf/ssrf.txt" ]]; then
					# Append SSFR results to redirect if ssrf.txt exists
					gf "$pattern" "webs/webs_nuclei.txt" | anew -q "$output_file"
				else
					# General handling for other patterns
					gf "$pattern" "webs/webs_nuclei.txt" | anew -q "$output_file"
				fi
			done

			# Process endpoints extraction
			if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Extracting endpoints...${reset}\n\n"
				grep -aEiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" ".tmp/url_extract_tmp.txt" |
					unfurl -u format '%s://%d%p' 2>>"$LOGFILE" | anew -q "gf/endpoints.txt"
			fi

		else
			end_func "No webs/webs_nuclei.txt file found, URL_GF check skipped." "${FUNCNAME[0]}"
			return
		fi

		end_func "Results are saved in $domain/gf folder" "${FUNCNAME[0]}"
	else
		# Handle cases where URL_GF is false or the function has already been processed
		if [[ $URL_GF == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP address; skip the function
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi

}

function url_ext() {

	# Create necessary directories
	if ! mkdir -p .tmp webs gf; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $URL_EXT == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
			start_func "${FUNCNAME[0]}" "Vulnerable Pattern Search"

			# Define an array of file extensions
			ext=("7z" "achee" "action" "adr" "apk" "arj" "ascx" "asmx" "asp" "aspx" "axd" "backup" "bak" "bat" "bin" "bkf" "bkp" "bok" "cab" "cer" "cfg" "cfm" "cnf" "conf" "config" "cpl" "crt" "csr" "csv" "dat" "db" "dbf" "deb" "dmg" "dmp" "doc" "docx" "drv" "email" "eml" "emlx" "env" "exe" "gadget" "gz" "html" "ica" "inf" "ini" "iso" "jar" "java" "jhtml" "json" "jsp" "key" "log" "lst" "mai" "mbox" "mbx" "md" "mdb" "msg" "msi" "nsf" "ods" "oft" "old" "ora" "ost" "pac" "passwd" "pcf" "pdf" "pem" "pgp" "php" "php3" "php4" "php5" "phtm" "phtml" "pkg" "pl" "plist" "pst" "pwd" "py" "rar" "rb" "rdp" "reg" "rpm" "rtf" "sav" "sh" "shtm" "shtml" "skr" "sql" "swf" "sys" "tar" "tar.gz" "tmp" "toast" "tpl" "txt" "url" "vcd" "vcf" "wml" "wpd" "wsdl" "wsf" "xls" "xlsm" "xlsx" "xml" "xsd" "yaml" "yml" "z" "zip")

			# Initialize the output file
			if ! : >webs/urls_by_ext.txt; then
				printf "%b[!] Failed to initialize webs/urls_by_ext.txt.%b\n" "$bred" "$reset"
			fi

			# Iterate over extensions and extract matching URLs
			for t in "${ext[@]}"; do

				# Extract unique matching URLs
				matches=$(grep -aEi "\.(${t})($|/|\?)" ".tmp/url_extract_tmp.txt" | sort -u | sed '/^$/d')

				NUMOFLINES=$(echo "$matches" | wc -l)

				if [[ $NUMOFLINES -gt 0 ]]; then
					printf "\n############################\n + %s + \n############################\n" "$t" >>webs/urls_by_ext.txt
					echo "$matches" >>webs/urls_by_ext.txt
				fi
			done

			# Append ssrf.txt to redirect.txt if ssrf.txt exists and is not empty
			if [[ -s "gf/ssrf.txt" ]]; then
				cat "gf/ssrf.txt" | anew -q "gf/redirect.txt"
			fi

			end_func "Results are saved in $domain/webs/urls_by_ext.txt" "${FUNCNAME[0]}"

		else
			end_func "No .tmp/url_extract_tmp.txt file found, URL_EXT check skipped." "${FUNCNAME[0]}"
		fi

	else
		# Handle cases where URL_EXT is false or function already processed
		if [[ $URL_EXT == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP address; skip the function
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi

}

function jschecks() {

	# Create necessary directories
	if ! mkdir -p .tmp webs subdomains js; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $JSCHECKS == true ]]; then
		start_func "${FUNCNAME[0]}" "JavaScript Scan"

		if [[ -s ".tmp/url_extract_js.txt" ]]; then

			printf "%bRunning: Fetching URLs 1/6%b\n" "$yellow" "$reset"
			if [[ $AXIOM != true ]]; then
				subjs -ua "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -c 40 <.tmp/url_extract_js.txt |
					grep "$domain" |
					grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' |
					anew -q .tmp/subjslinks.txt
			else
				axiom-scan .tmp/url_extract_js.txt -m subjs -o .tmp/subjslinks.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
			fi

			if [[ -s ".tmp/subjslinks.txt" ]]; then
				grep -Eiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" .tmp/subjslinks.txt |
					anew -q js/nojs_links.txt
				grep -iE "\.js($|\?)" .tmp/subjslinks.txt | anew -q .tmp/url_extract_js.txt
			fi

			urless <.tmp/url_extract_js.txt |
				anew -q js/url_extract_js.txt 2>>"$LOGFILE" >/dev/null

			printf "%bRunning: Resolving JS URLs 2/6%b\n" "$yellow" "$reset"
			if [[ $AXIOM != true ]]; then
				if [[ -s "js/url_extract_js.txt" ]]; then
					httpx -follow-redirects -random-agent -silent -timeout "$HTTPX_TIMEOUT" -threads "$HTTPX_THREADS" \
						-rl "$HTTPX_RATELIMIT" -status-code -content-type -retries 2 -no-color <js/url_extract_js.txt |
						grep "[200]" | grep "javascript" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
				fi
			else
				if [[ -s "js/url_extract_js.txt" ]]; then
					axiom-scan js/url_extract_js.txt -m httpx -follow-host-redirects -H "$HEADER" -status-code \
						-threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" -silent \
						-content-type -retries 2 -no-color -o .tmp/js_livelinks.txt "$AXIOM_EXTRA_ARGS" 2>>"$LOGFILE" >/dev/null
					if [[ -s ".tmp/js_livelinks.txt" ]]; then
						cat .tmp/js_livelinks.txt | anew .tmp/web_full_info.txt |
							grep "[200]" | grep "javascript" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
					fi
				fi
			fi

			printf "%bRunning: Extracting JS from sourcemaps 3/6%b\n" "$yellow" "$reset"
			if ! mkdir -p .tmp/sourcemapper; then
				printf "%b[!] Failed to create sourcemapper directory.%b\n" "$bred" "$reset"
			fi
			if [[ -s "js/js_livelinks.txt" ]]; then
				interlace -tL js/js_livelinks.txt -threads "$INTERLACE_THREADS" \
					-c "sourcemapper -jsurl '_target_' -output _output_/_cleantarget_" \
					-o .tmp/sourcemapper 2>>"$LOGFILE" >/dev/null
			fi

			if [[ -s ".tmp/url_extract_jsmap.txt" ]]; then
				interlace -tL js/js_livelinks.txt -threads "$INTERLACE_THREADS" \
					-c "sourcemapper -url '_target_' -output _output_/_cleantarget_" \
					-o .tmp/sourcemapper 2>>"$LOGFILE" >/dev/null
			fi

			find .tmp/sourcemapper/ \( -name "*.js" -o -name "*.ts" \) -type f |
				jsluice urls | jq -r .url | anew -q .tmp/js_endpoints.txt

			printf "%bRunning: Gathering endpoints 4/6%b\n" "$yellow" "$reset"
			if [[ -s "js/js_livelinks.txt" ]]; then
				xnLinkFinder -i js/js_livelinks.txt -sf subdomains/subdomains.txt -d "$XNLINKFINDER_DEPTH" \
					-o .tmp/js_endpoints.txt 2>>"$LOGFILE" >/dev/null
			fi

			if [[ -s ".tmp/js_endpoints.txt" ]]; then
				sed -i '/^\//!d' .tmp/js_endpoints.txt
				cat .tmp/js_endpoints.txt | anew -q js/js_endpoints.txt
			fi

			printf "%bRunning: Gathering secrets 5/6%b\n" "$yellow" "$reset"
			if [[ -s "js/js_livelinks.txt" ]]; then
				if [[ $AXIOM != true ]]; then
					cat js/js_livelinks.txt | mantra -ua "$HEADER" -s -o js/js_secrets.txt 2>>"$LOGFILE" >/dev/null
				else
					axiom-scan js/js_livelinks.txt -m mantra -ua "$HEADER" -s -o js/js_secrets.txt "$AXIOM_EXTRA_ARGS" &>/dev/null
				fi
				if [[ -s "js/js_secrets.txt" ]]; then
					trufflehog filesystem js/js_secrets.txt -j 2>/dev/null |
						jq -c | anew -q js/js_secrets_trufflehog.txt
					trufflehog filesystem .tmp/sourcemapper/ -j 2>/dev/null |
						jq -c | anew -q js/js_secrets_trufflehog.txt
					sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g" -i js/js_secrets.txt
				fi
			fi

			printf "%bRunning: Building wordlist 6/6%b\n" "$yellow" "$reset"
			if [[ -s "js/js_livelinks.txt" ]]; then
				interlace -tL js/js_livelinks.txt -threads "$INTERLACE_THREADS" \
					-c "python3 ${tools}/getjswords.py '_target_' | anew -q webs/dict_words.txt" 2>>"$LOGFILE" >/dev/null
			fi
			end_func "Results are saved in $domain/js folder" "${FUNCNAME[0]}"
		fi
	else
		if [[ $JSCHECKS == false ]]; then
			printf "\n%b[%s] %s skipped due to mode or defined in reconftw.cfg.%b\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$reset"
		else
			printf "%b[%s] %s has already been processed. To force execution, delete:\n    %s/.%s%b\n\n" \
				"$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "${FUNCNAME[0]}" "$called_fn_dir" ".${FUNCNAME[0]}" "$reset"
		fi
	fi

}

function wordlist_gen() {

	# Create necessary directories
	if ! mkdir -p .tmp webs; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WORDLIST == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Wordlist Generation"

		# Ensure url_extract_tmp.txt exists and is not empty
		if [[ -s ".tmp/url_extract_tmp.txt" ]]; then
			# Define patterns for keys and values
			patterns=("keys" "values")

			for pattern in "${patterns[@]}"; do
				output_file="webs/dict_${pattern}.txt"
				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Extracting ${pattern}...${reset}\n"

				if [[ $pattern == "keys" || $pattern == "values" ]]; then
					unfurl -u "$pattern" ".tmp/url_extract_tmp.txt" 2>>"$LOGFILE" |
						sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' |
						anew -q "$output_file"
				fi
			done

			# Extract words by removing punctuation
			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Extracting words...${reset}\n"
			tr "[:punct:]" "\n" <".tmp/url_extract_tmp.txt" | anew -q "webs/dict_words.txt"
		fi

		end_func "Results are saved in $domain/webs/dict_[words|paths].txt" "${FUNCNAME[0]}"

	else
		# Handle cases where WORDLIST is false or function already processed
		if [[ $WORDLIST == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP address; skip the function
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi

}

function wordlist_gen_roboxtractor() {

	# Create necessary directories
	if ! mkdir -p .tmp webs gf; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $ROBOTSWORDLIST == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Robots Wordlist Generation"

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
		fi

		# Proceed only if webs_all.txt exists and is non-empty
		if [[ -s "webs/webs_all.txt" ]]; then
			# Extract URLs using roboxtractor and append unique entries to robots_wordlist.txt
			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Roboxtractor for Robots Wordlist${reset}\n\n"
			roboxtractor -m 1 -wb <"webs/webs_all.txt" 2>>"$LOGFILE" | anew -q "webs/robots_wordlist.txt"
		else
			end_func "No webs/webs_all.txt file found, Robots Wordlist generation skipped." "${FUNCNAME[0]}"
			return
		fi

		end_func "Results are saved in $domain/webs/robots_wordlist.txt" "${FUNCNAME[0]}"

		# Handle Proxy if conditions are met
		if [[ $PROXY == true ]] && [[ -n $proxy_url ]] && [[ "$(wc -l <"webs/robots_wordlist.txt")" -le $DEEP_LIMIT2 ]]; then
			notification "Sending URLs to proxy" info
			ffuf -mc all -w "webs/robots_wordlist.txt" -u "FUZZ" -replay-proxy "$proxy_url" 2>>"$LOGFILE" >/dev/null
		fi

	else
		# Handle cases where ROBOTSWORDLIST is false or function already processed
		if [[ $ROBOTSWORDLIST == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP address; skip the function
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi

}

function password_dict() {

	# Create necessary directories
	if ! mkdir -p "$dir/webs"; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PASSWORD_DICT == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Password Dictionary Generation"

		# Extract the first part of the domain
		word="${domain%%.*}"

		# Run pydictor.py with specified parameters
		python3 "${tools}/pydictor/pydictor.py" -extend "$word" --leet 0 1 2 11 21 --len "$PASSWORD_MIN_LENGTH" "$PASSWORD_MAX_LENGTH" -o "$dir/webs/password_dict.txt" 2>>"$LOGFILE" >/dev/null
		end_func "Results are saved in $domain/webs/password_dict.txt" "${FUNCNAME[0]}"

		# Optionally, create a marker file to indicate the function has been processed
		touch "$called_fn_dir/.${FUNCNAME[0]}"

	else
		# Handle cases where PASSWORD_DICT is false or function already processed
		if [[ $PASSWORD_DICT == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP address; skip the function
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi

}

###############################################################################################################
######################################### VULNERABILITIES #####################################################
###############################################################################################################

function brokenLinks() {

	# Create necessary directories
	if ! mkdir -p .tmp webs vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $BROKENLINKS == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Broken Links Checks"

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
		fi

		# Check if webs_all.txt exists and is not empty
		if [[ -s "webs/webs_all.txt" ]]; then
			if [[ $AXIOM != true ]]; then
				# Use katana for scanning
				if [[ ! -s ".tmp/katana.txt" ]]; then
					if [[ $DEEP == true ]]; then
						katana -silent -list "webs/webs_all.txt" -jc -kf all -c "$KATANA_THREADS" -d 3 -o ".tmp/katana.txt" 2>>"$LOGFILE" >/dev/null
					else
						katana -silent -list "webs/webs_all.txt" -jc -kf all -c "$KATANA_THREADS" -d 2 -o ".tmp/katana.txt" 2>>"$LOGFILE" >/dev/null
					fi
				fi
				# Remove lines longer than 2048 characters
				if [[ -s ".tmp/katana.txt" ]]; then
					sed -i '/^.\{2048\}./d' ".tmp/katana.txt"
				fi
			else
				# Use axiom-scan for scanning
				if [[ ! -s ".tmp/katana.txt" ]]; then
					if [[ $DEEP == true ]]; then
						axiom-scan "webs/webs_all.txt" -m katana -jc -kf all -d 3 -o ".tmp/katana.txt" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					else
						axiom-scan "webs/webs_all.txt" -m katana -jc -kf all -d 2 -o ".tmp/katana.txt" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					fi
					# Remove lines longer than 2048 characters
					if [[ -s ".tmp/katana.txt" ]]; then
						sed -i '/^.\{2048\}./d' ".tmp/katana.txt"
					fi
				fi
			fi

			# Process katana.txt to find broken links
			if [[ -s ".tmp/katana.txt" ]]; then
				httpx -follow-redirects -random-agent -status-code -threads "$HTTPX_THREADS" -rl "$HTTPX_RATELIMIT" -timeout "$HTTPX_TIMEOUT" -silent -retries 2 -no-color <".tmp/katana.txt" 2>>"$LOGFILE" |
					grep "\[4" | cut -d ' ' -f1 | anew -q ".tmp/brokenLinks_total.txt"
			fi

			# Update brokenLinks.txt with unique entries
			if [[ -s ".tmp/brokenLinks_total.txt" ]]; then
				NUMOFLINES=$(wc -l <".tmp/brokenLinks_total.txt" 2>>"$LOGFILE" | awk '{print $1}')
				cat .tmp/brokenLinks_total.txt | anew -q "vulns/brokenLinks.txt"
				NUMOFLINES=$(sed '/^$/d' "vulns/brokenLinks.txt" | wc -l)
				notification "${NUMOFLINES} new broken links found" info
			fi

			end_func "Results are saved in vulns/brokenLinks.txt" "${FUNCNAME[0]}"
		else
			end_func "No webs/webs_all.txt file found, Broken Links check skipped." "${FUNCNAME[0]}"
			return
		fi
	else
		# Handle cases where BROKENLINKS is false or function already processed
		if [[ $BROKENLINKS == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			# Domain is an IP address; skip the function
			return
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]}${reset}\n\n"
		fi
	fi

}

function xss() {

	# Create necessary directories
	if ! mkdir -p .tmp webs vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $XSS == true ]] && [[ -s "gf/xss.txt" ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "XSS Analysis"

		# Process gf/xss.txt with qsreplace and Gxss
		if [[ -s "gf/xss.txt" ]]; then
			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: XSS Payload Generation${reset}\n\n"
			qsreplace FUZZ <"gf/xss.txt" | sed '/FUZZ/!d' | Gxss -c 100 -p Xss | qsreplace FUZZ | sed '/FUZZ/!d' |
				anew -q ".tmp/xss_reflected.txt"
		fi

		# Determine whether to use Axiom or Katana for scanning
		if [[ $AXIOM != true ]]; then
			# Using Katana
			if [[ $DEEP == true ]]; then
				DEPTH=3
			else
				DEPTH=2
			fi

			if [[ -n $XSS_SERVER ]]; then
				OPTIONS="-b ${XSS_SERVER} -w $DALFOX_THREADS"
			else
				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] No XSS_SERVER defined, blind XSS skipped\n\n"
				OPTIONS="-w $DALFOX_THREADS"
			fi

			# Run Dalfox with Katana output
			if [[ -s ".tmp/xss_reflected.txt" ]]; then
				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Dalfox with Katana${reset}\n\n"
				dalfox pipe --silence --no-color --no-spinner --only-poc r --ignore-return 302,404,403 --skip-bav $OPTIONS -d "$DEPTH" <".tmp/xss_reflected.txt" 2>>"$LOGFILE" |
					anew -q "vulns/xss.txt"
			fi
		else
			# Using Axiom
			if [[ $DEEP == true ]]; then
				DEPTH=3
				AXIOM_ARGS="$AXIOM_EXTRA_ARGS"
			else
				DEPTH=2
				AXIOM_ARGS="$AXIOM_EXTRA_ARGS"
			fi

			if [[ -n $XSS_SERVER ]]; then
				OPTIONS="-b ${XSS_SERVER} -w $DALFOX_THREADS"
			else
				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] No XSS_SERVER defined, blind XSS skipped\n\n"
				OPTIONS="-w $DALFOX_THREADS"
			fi

			# Run Dalfox with Axiom-scan output
			if [[ -s ".tmp/xss_reflected.txt" ]]; then
				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Dalfox with Axiom${reset}\n\n"
				axiom-scan ".tmp/xss_reflected.txt" -m dalfox --skip-bav $OPTIONS -d "$DEPTH" -o "vulns/xss.txt" $AXIOM_ARGS 2>>"$LOGFILE" >/dev/null
			fi
		fi

		end_func "Results are saved in vulns/xss.txt" "${FUNCNAME[0]}"
	else
		# Handle cases where XSS is false, no vulnerable URLs, or already processed
		if [[ $XSS == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! -s "gf/xss.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to XSS ${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function cors() {

	# Create necessary directories
	if ! mkdir -p .tmp webs vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CORS == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "CORS Scan"

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
		fi

		# Proceed only if webs_all.txt exists and is non-empty
		if [[ -s "webs/webs_all.txt" ]]; then
			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Corsy for CORS Scan${reset}\n\n"
			"${tools}/Corsy/venv/bin/python3" "${tools}/Corsy/corsy.py" -i "webs/webs_all.txt" -o "vulns/cors.txt" 2>>"$LOGFILE" >/dev/null
		else
			end_func "No webs/webs_all.txt file found, CORS Scan skipped." "${FUNCNAME[0]}"
			return
		fi

		end_func "Results are saved in vulns/cors.txt" "${FUNCNAME[0]}"

	else
		# Handle cases where CORS is false, no vulnerable URLs, or already processed
		if [[ $CORS == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "gf/xss.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs available for CORS Scan.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function open_redirect() {

	# Create necessary directories
	if ! mkdir -p .tmp webs vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $OPEN_REDIRECT == true ]] &&
		[[ -s "gf/redirect.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Open Redirects Checks"

		# Determine whether to proceed based on DEEP flag or number of URLs
		URL_COUNT=$(wc -l <"gf/redirect.txt")
		if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Open Redirects Payload Generation${reset}\n\n"

			# Process redirect.txt with qsreplace and filter lines containing 'FUZZ'
			qsreplace FUZZ <"gf/redirect.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_redirect.txt"

			# Run Oralyzer with the generated payloads
			"${tools}/Oralyzer/venv/bin/python3" "${tools}/Oralyzer/oralyzer.py" -l ".tmp/tmp_redirect.txt" -p "${tools}/Oralyzer/payloads.txt" >"vulns/redirect.txt" 2>>"$LOGFILE" >/dev/null

			# Remove ANSI color codes from the output
			sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "vulns/redirect.txt"

			end_func "Results are saved in vulns/redirect.txt" "${FUNCNAME[0]}"
		else
			end_func "Skipping Open Redirects: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
			printf "${bgreen}#######################################################################${reset}\n"
		fi
	else
		# Handle cases where OPEN_REDIRECT is false, no vulnerable URLs, or already processed
		if [[ $OPEN_REDIRECT == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "gf/redirect.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to Open Redirect.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function ssrf_checks() {

	# Create necessary directories
	if ! mkdir -p .tmp gf vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSRF_CHECKS == true ]] &&
		[[ -s "gf/ssrf.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "SSRF Checks"

		# Handle COLLAB_SERVER configuration
		if [[ -z $COLLAB_SERVER ]]; then
			interactsh-client &>.tmp/ssrf_callback.txt &
			sleep 2

			# Extract FFUFHASH from interactsh_callback.txt
			COLLAB_SERVER_FIX="FFUFHASH.$(tail -n1 .tmp/ssrf_callback.txt | cut -c 16-)"
			COLLAB_SERVER_URL="http://$COLLAB_SERVER_FIX"
			INTERACT=true
		else
			COLLAB_SERVER_FIX="FFUFHASH.$(echo "$COLLAB_SERVER" | sed -r "s|https?://||")"
			INTERACT=false
		fi

		# Determine whether to proceed based on DEEP flag or URL count
		URL_COUNT=$(wc -l <"gf/ssrf.txt")
		if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: SSRF Payload Generation${reset}\n\n"

			# Generate temporary SSRF payloads
			qsreplace "$COLLAB_SERVER_FIX" <"gf/ssrf.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_ssrf.txt"

			qsreplace "$COLLAB_SERVER_URL" <"gf/ssrf.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_ssrf.txt"

			# Run FFUF to find requested URLs
			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: FFUF for SSRF Requested URLs${reset}\n\n"
			ffuf -v -H "${HEADER}" -t "$FFUF_THREADS" -rate "$FFUF_RATELIMIT" -w ".tmp/tmp_ssrf.txt" -u "FUZZ" 2>/dev/null |
				grep "URL" | sed 's/| URL | //' | anew -q "vulns/ssrf_requested_url.txt"

			# Run FFUF with header injection for SSRF
			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: FFUF for SSRF Requested Headers with COLLAB_SERVER_FIX${reset}\n\n"
			ffuf -v -w ".tmp/tmp_ssrf.txt:W1,${tools}/headers_inject.txt:W2" -H "${HEADER}" -H "W2: ${COLLAB_SERVER_FIX}" -t "$FFUF_THREADS" \
				-rate "$FFUF_RATELIMIT" -u "W1" 2>/dev/null | anew -q "vulns/ssrf_requested_headers.txt"

			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: FFUF for SSRF Requested Headers with COLLAB_SERVER_URL${reset}\n\n"
			ffuf -v -w ".tmp/tmp_ssrf.txt:W1,${tools}/headers_inject.txt:W2" -H "${HEADER}" -H "W2: ${COLLAB_SERVER_URL}" -t "$FFUF_THREADS" \
				-rate "$FFUF_RATELIMIT" -u "W1" 2>/dev/null | anew -q "vulns/ssrf_requested_headers.txt"

			# Allow time for callbacks to be received
			sleep 5

			# Process SSRF callback results if INTERACT is enabled
			if [[ $INTERACT == true ]] && [[ -s ".tmp/ssrf_callback.txt" ]]; then
				tail -n +11 .tmp/ssrf_callback.txt | anew -q "vulns/ssrf_callback.txt"
				NUMOFLINES=$(tail -n +12 .tmp/ssrf_callback.txt | sed '/^$/d' | wc -l)
				notification "SSRF: ${NUMOFLINES} callbacks received" info
			fi

			end_func "Results are saved in vulns/ssrf_*" "${FUNCNAME[0]}"
		else
			end_func "Skipping SSRF: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
			printf "${bgreen}#######################################################################${reset}\n"
		fi

		# Terminate interactsh-client if it was started
		if [[ $INTERACT == true ]]; then
			pkill -f interactsh-client &
		fi

	else
		# Handle cases where SSRF_CHECKS is false, no vulnerable URLs, or already processed
		if [[ $SSRF_CHECKS == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! -s "gf/ssrf.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to SSRF.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function crlf_checks() {

	# Create necessary directories
	if ! mkdir -p webs vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CRLF_CHECKS == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "CRLF Checks"

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
		fi

		# Determine whether to proceed based on DEEP flag or number of URLs
		URL_COUNT=$(wc -l <"webs/webs_all.txt")
		if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: CRLF Fuzzing${reset}\n\n"

			# Run CRLFuzz
			crlfuzz -l "webs/webs_all.txt" -o "vulns/crlf.txt" 2>>"$LOGFILE" >/dev/null

			end_func "Results are saved in vulns/crlf.txt" "${FUNCNAME[0]}"
		else
			end_func "Skipping CRLF: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
		fi
	else
		# Handle cases where CRLF_CHECKS is false, no vulnerable URLs, or already processed
		if [[ $CRLF_CHECKS == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "gf/crlf.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to CRLF.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function lfi() {

	# Create necessary directories
	if ! mkdir -p .tmp gf vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $LFI == true ]] &&
		[[ -s "gf/lfi.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "LFI Checks"

		# Ensure gf/lfi.txt is not empty
		if [[ -s "gf/lfi.txt" ]]; then
			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: LFI Payload Generation${reset}\n\n"

			# Process lfi.txt with qsreplace and filter lines containing 'FUZZ'
			qsreplace "FUZZ" <"gf/lfi.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_lfi.txt"

			# Determine whether to proceed based on DEEP flag or number of URLs
			URL_COUNT=$(wc -l <".tmp/tmp_lfi.txt")
			if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: LFI Fuzzing with FFUF${reset}\n\n"

				# Use Interlace to parallelize FFUF scanning
				interlace -tL ".tmp/tmp_lfi.txt" -threads "$INTERLACE_THREADS" -c "ffuf -v -r -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w \"${lfi_wordlist}\" -u \"_target_\" -mr \"root:\" " 2>>"$LOGFILE" |
					grep "URL" | sed 's/| URL | //' | anew -q "vulns/lfi.txt"

				end_func "Results are saved in vulns/lfi.txt" "${FUNCNAME[0]}"
			else
				end_func "Skipping LFI: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
			fi
		else
			end_func "No gf/lfi.txt file found, LFI Checks skipped." "${FUNCNAME[0]}"
			return
		fi
	else
		# Handle cases where LFI is false, no vulnerable URLs, or already processed
		if [[ $LFI == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "gf/lfi.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to LFI.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function ssti() {

	# Create necessary directories
	if ! mkdir -p .tmp gf vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSTI == true ]] &&
		[[ -s "gf/ssti.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "SSTI Checks"

		# Ensure gf/ssti.txt is not empty
		if [[ -s "gf/ssti.txt" ]]; then
			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: SSTI Payload Generation${reset}\n\n"

			# Process ssti.txt with qsreplace and filter lines containing 'FUZZ'
			qsreplace "FUZZ" <"gf/ssti.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_ssti.txt"

			# Determine whether to proceed based on DEEP flag or number of URLs
			URL_COUNT=$(wc -l <".tmp/tmp_ssti.txt")
			if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: SSTI Fuzzing with FFUF${reset}\n\n"

				# Use Interlace to parallelize FFUF scanning
				interlace -tL ".tmp/tmp_ssti.txt" -threads "$INTERLACE_THREADS" -c "ffuf -v -r -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w \"${ssti_wordlist}\" -u \"_target_\" -mr \"ssti49\"" 2>>"$LOGFILE" |
					grep "URL" | sed 's/| URL | //' | anew -q "vulns/ssti.txt"

				end_func "Results are saved in vulns/ssti.txt" "${FUNCNAME[0]}"
			else
				end_func "Skipping SSTI: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
			fi
		else
			end_func "No gf/ssti.txt file found, SSTI Checks skipped." "${FUNCNAME[0]}"
			return
		fi
	else
		# Handle cases where SSTI is false, no vulnerable URLs, or already processed
		if [[ $SSTI == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "gf/ssti.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to SSTI.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function sqli() {

	# Create necessary directories
	if ! mkdir -p .tmp gf vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SQLI == true ]] &&
		[[ -s "gf/sqli.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "SQLi Checks"

		# Ensure gf/sqli.txt is not empty
		if [[ -s "gf/sqli.txt" ]]; then
			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: SQLi Payload Generation${reset}\n\n"

			# Process sqli.txt with qsreplace and filter lines containing 'FUZZ'
			qsreplace "FUZZ" <"gf/sqli.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_sqli.txt"

			# Determine whether to proceed based on DEEP flag or number of URLs
			URL_COUNT=$(wc -l <".tmp/tmp_sqli.txt")
			if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

				# Check if SQLMAP is enabled and run SQLMap
				if [[ $SQLMAP == true ]]; then
					printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: SQLMap for SQLi Checks${reset}\n\n"
					python3 "${tools}/sqlmap/sqlmap.py" -m ".tmp/tmp_sqli.txt" -b -o --smart \
						--batch --disable-coloring --random-agent --output-dir="vulns/sqlmap" 2>>"$LOGFILE" >/dev/null
				fi

				# Check if GHAURI is enabled and run Ghauri
				if [[ $GHAURI == true ]]; then
					printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Ghauri for SQLi Checks${reset}\n\n"
					interlace -tL ".tmp/tmp_sqli.txt" -threads "$INTERLACE_THREADS" -c "ghauri -u _target_ --batch -H \"${HEADER}\" --force-ssl >> vulns/ghauri_log.txt" 2>>"$LOGFILE" >/dev/null
				fi

				end_func "Results are saved in vulns/sqlmap folder" "${FUNCNAME[0]}"
			else
				end_func "Skipping SQLi: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
			fi
		else
			end_func "No gf/sqli.txt file found, SQLi Checks skipped." "${FUNCNAME[0]}"
			return
		fi
	else
		# Handle cases where SQLI is false, no vulnerable URLs, or already processed
		if [[ $SQLI == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "gf/sqli.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to SQLi.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function test_ssl() {

	# Create necessary directories
	if ! mkdir -p hosts vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $TEST_SSL == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "SSL Test"

		# Handle multi-domain scenarios
		if [[ -n $multi ]] && [[ ! -f "$dir/hosts/ips.txt" ]]; then
			echo "$domain" >"$dir/hosts/ips.txt"
		fi

		# Run testssl.sh
		printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: SSL Test with testssl.sh${reset}\n\n"
		"${tools}/testssl.sh/testssl.sh" --quiet --color 0 -U -iL "hosts/ips.txt" 2>>"$LOGFILE" >"vulns/testssl.txt"

		end_func "Results are saved in vulns/testssl.txt" "${FUNCNAME[0]}"

	else
		# Handle cases where TEST_SSL is false, no vulnerable URLs, or already processed
		if [[ $TEST_SSL == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "gf/testssl.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to SSL issues.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function spraying() {

	# Create necessary directories
	if ! mkdir -p "vulns"; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SPRAY == true ]] &&
		[[ -s "$dir/hosts/portscan_active.gnmap" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Password Spraying"

		# Ensure portscan_active.gnmap exists and is not empty
		if [[ ! -s "$dir/hosts/portscan_active.gnmap" ]]; then
			printf "%b[!] File $dir/hosts/portscan_active.gnmap does not exist or is empty.%b\n" "$bred" "$reset"
			end_func "Port scan results missing. Password Spraying aborted." "${FUNCNAME[0]}"
			return 1
		fi

		printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Password Spraying with BruteSpray${reset}\n\n"

		# Run BruteSpray for password spraying
		brutespray -f "$dir/hosts/portscan_active.gnmap" -T "$BRUTESPRAY_CONCURRENCE" -o "$dir/vulns/brutespray" 2>>"$LOGFILE" >/dev/null

		end_func "Results are saved in vulns/brutespray folder" "${FUNCNAME[0]}"

	else
		# Handle cases where SPRAY is false, required files are missing, or already processed
		if [[ $SPRAY == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "$dir/hosts/portscan_active.gnmap" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No active port scan results found.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function command_injection() {

	# Create necessary directories
	if ! mkdir -p .tmp gf vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $COMM_INJ == true ]] &&
		[[ -s "gf/rce.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Command Injection Checks"

		# Ensure gf/rce.txt is not empty and process it
		if [[ -s "gf/rce.txt" ]]; then
			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Command Injection Payload Generation${reset}\n\n"

			# Process rce.txt with qsreplace and filter lines containing 'FUZZ'
			qsreplace "FUZZ" <"gf/rce.txt" | sed '/FUZZ/!d' | anew -q ".tmp/tmp_rce.txt"

			# Determine whether to proceed based on DEEP flag or number of URLs
			URL_COUNT=$(wc -l <".tmp/tmp_rce.txt")
			if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

				# Run Commix if enabled
				if [[ $SQLMAP == true ]]; then
					printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Commix for Command Injection Checks${reset}\n\n"
					commix --batch -m ".tmp/tmp_rce.txt" --output-dir "vulns/command_injection" 2>>"$LOGFILE" >/dev/null
				fi

				# Additional tools can be integrated here (e.g., Ghauri, sqlmap)

				end_func "Results are saved in vulns/command_injection folder" "${FUNCNAME[0]}"
			else
				end_func "Skipping Command Injection: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
			fi
		else
			end_func "No gf/rce.txt file found, Command Injection Checks skipped." "${FUNCNAME[0]}"
			return
		fi
	else
		# Handle cases where COMM_INJ is false, no vulnerable URLs, or already processed
		if [[ $COMM_INJ == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "gf/rce.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to Command Injection.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function 4xxbypass() {

	# Create necessary directories
	if ! mkdir -p .tmp fuzzing vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $BYPASSER4XX == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		# Extract relevant URLs starting with 4xx but not 404
		printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: 403 Bypass${reset}\n\n"
		grep -E '^4' "fuzzing/fuzzing_full.txt" 2>/dev/null | grep -Ev '^404' | awk '{print $3}' | anew -q ".tmp/403test.txt"

		# Count the number of URLs to process
		URL_COUNT=$(wc -l <".tmp/403test.txt")
		if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

			start_func "${FUNCNAME[0]}" "403 Bypass"

			# Navigate to nomore403 tool directory
			if ! pushd "${tools}/nomore403" >/dev/null; then
				printf "%b[!] Failed to navigate to nomore403 directory.%b\n" "$bred" "$reset"
				end_func "Failed to navigate to nomore403 directory during 403 Bypass." "${FUNCNAME[0]}"
				return 1
			fi

			# Run nomore403 on the processed URLs
			./nomore403 <"$dir/.tmp/403test.txt" >"$dir/.tmp/4xxbypass.txt" 2>>"$LOGFILE"

			# Return to the original directory
			if ! popd >/dev/null; then
				printf "%b[!] Failed to return to the original directory.%b\n" "$bred" "$reset"
				end_func "Failed to return to the original directory during 403 Bypass." "${FUNCNAME[0]}"
				return 1
			fi

			# Append unique bypassed URLs to the vulns directory
			if [[ -s "$dir/.tmp/4xxbypass.txt" ]]; then
				cat "$dir/.tmp/4xxbypass.txt" | anew -q "vulns/4xxbypass.txt"
			fi

			end_func "Results are saved in vulns/4xxbypass.txt" "${FUNCNAME[0]}"

		else
			notification "Too many URLs to bypass, skipping" warn
			end_func "Skipping Command Injection: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
		fi

	else
		# Handle cases where BYPASSER4XX is false, no vulnerable URLs, or already processed
		if [[ $BYPASSER4XX == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "fuzzing/fuzzing_full.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to 4xx bypass.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function prototype_pollution() {

	# Create necessary directories
	if ! mkdir -p .tmp webs vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PROTO_POLLUTION == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Prototype Pollution Checks"

		# Determine whether to proceed based on DEEP flag or number of URLs
		URL_COUNT=$(wc -l <"webs/url_extract_nodupes.txt" 2>/dev/null)
		if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

			# Ensure fuzzing_full.txt exists and has content
			if [[ -s "webs/url_extract_nodupes.txt" ]]; then
				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Prototype Pollution Mapping${reset}\n\n"

				# Process URL list with ppmap and save results
				ppmap <"webs/url_extract_nodupes.txt" >".tmp/prototype_pollution.txt" 2>>"$LOGFILE"

				# Filter and save relevant results
				if [[ -s ".tmp/prototype_pollution.txt" ]]; then
					grep "EXPL" ".tmp/prototype_pollution.txt" | anew -q "vulns/prototype_pollution.txt"
				fi

				end_func "Results are saved in vulns/prototype_pollution.txt" "${FUNCNAME[0]}"
			else
				printf "%b[!] File webs/url_extract_nodupes.txt is missing or empty.%b\n" "$bred" "$reset"
				end_func "File webs/url_extract_nodupes.txt is missing or empty." "${FUNCNAME[0]}"
				return 1
			fi

		else
			end_func "Skipping Prototype Pollution: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
		fi

	else
		# Handle cases where PROTO_POLLUTION is false, no vulnerable URLs, or already processed
		if [[ $PROTO_POLLUTION == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "webs/url_extract_nodupes.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to Prototype Pollution.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function smuggling() {

	# Create necessary directories
	if ! mkdir -p .tmp webs vulns/smuggling; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SMUGGLING == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "HTTP Request Smuggling Checks"

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat "webs/webs.txt" "webs/webs_uncommon_ports.txt" 2>/dev/null | anew -q "webs/webs_all.txt"
		fi

		# Determine whether to proceed based on DEEP flag or number of URLs
		URL_COUNT=$(wc -l <"webs/webs_all.txt")
		if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: HTTP Request Smuggling Checks${reset}\n\n"

			# Navigate to smuggler tool directory
			if ! pushd "${tools}/smuggler" >/dev/null; then
				printf "%b[!] Failed to navigate to smuggler directory.%b\n" "$bred" "$reset"
				end_func "Failed to navigate to smuggler directory during HTTP Request Smuggling Checks." "${FUNCNAME[0]}"
				return 1
			fi

			# Run smuggler.py on the list of URLs
			python3 "smuggler.py" -f "$dir/webs/webs_all.txt" -o "$dir/.tmp/smuggling.txt" 2>>"$LOGFILE" >/dev/null

			# Move payload files to vulns/smuggling/
			find "payloads" -type f ! -name "README*" -exec mv {} "$dir/vulns/smuggling/" \;

			# Return to the original directory
			if ! popd >/dev/null; then
				printf "%b[!] Failed to return to the original directory.%b\n" "$bred" "$reset"
				end_func "Failed to return to the original directory during HTTP Request Smuggling Checks." "${FUNCNAME[0]}"
				return 1
			fi

			# Append unique smuggling results to vulns directory
			if [[ -s "$dir/.tmp/smuggling.txt" ]]; then
				cat "$dir/.tmp/smuggling.txt" | grep "EXPL" | anew -q "vulns/prototype_pollution.txt"
			fi

			end_func "Results are saved in vulns/smuggling_log.txt and findings in vulns/smuggling/" "${FUNCNAME[0]}"

		else
			notification "Too many URLs to bypass, skipping" warn
			end_func "Skipping HTTP Request Smuggling: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
		fi

	else
		# Handle cases where SMUGGLING is false, no vulnerable URLs, or already processed
		if [[ $SMUGGLING == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! -s "webs/webs_all.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to HTTP Request Smuggling.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function webcache() {

	# Create necessary directories
	if ! mkdir -p .tmp webs vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBCACHE == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Web Cache Poisoning Checks"

		# Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
		if [[ ! -s "webs/webs_all.txt" ]]; then
			cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
		fi

		# Determine whether to proceed based on DEEP flag or number of URLs
		URL_COUNT=$(wc -l <"webs/webs_all.txt")
		if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

			printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Web Cache Poisoning Checks${reset}\n\n"

			# Navigate to Web-Cache-Vulnerability-Scanner tool directory
			if ! pushd "${tools}/Web-Cache-Vulnerability-Scanner" >/dev/null; then
				printf "%b[!] Failed to navigate to Web-Cache-Vulnerability-Scanner directory.%b\n" "$bred" "$reset"
				end_func "Failed to navigate to Web-Cache-Vulnerability-Scanner directory during Web Cache Poisoning Checks." "${FUNCNAME[0]}"
				return 1
			fi

			# Run the Web-Cache-Vulnerability-Scanner
			./Web-Cache-Vulnerability-Scanner -u "file:$dir/webs/webs_all.txt" -v 0 2>>"$LOGFILE" |
				anew -q "$dir/.tmp/webcache.txt"

			# Return to the original directory
			if ! popd >/dev/null; then
				printf "%b[!] Failed to return to the original directory.%b\n" "$bred" "$reset"
				end_func "Failed to return to the original directory during Web Cache Poisoning Checks." "${FUNCNAME[0]}"
				return 1
			fi

			# Append unique findings to vulns/webcache.txt
			if [[ -s "$dir/.tmp/webcache.txt" ]]; then
				cat "$dir/.tmp/webcache.txt" | anew -q "vulns/webcache.txt"
			fi

			end_func "Results are saved in vulns/webcache.txt" "${FUNCNAME[0]}"

		else
			end_func "Skipping Web Cache Poisoning: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
		fi

	else
		# Handle cases where WEBCACHE is false, no vulnerable URLs, or already processed
		if [[ $WEBCACHE == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "fuzzing/fuzzing_full.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to Web Cache Poisoning.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function fuzzparams() {

	# Create necessary directories
	if ! mkdir -p .tmp webs vulns; then
		printf "%b[!] Failed to create directories.%b\n" "$bred" "$reset"
		return 1
	fi

	# Check if the function should run
	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FUZZPARAMS == true ]] &&
		! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

		start_func "${FUNCNAME[0]}" "Fuzzing Parameters Values Checks"

		# Determine if we should proceed based on DEEP flag or number of URLs
		URL_COUNT=$(wc -l <"webs/url_extract_nodupes.txt")
		if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT2 ]]; then

			if [[ $AXIOM != true ]]; then
				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Nuclei Setup and Execution${reset}\n\n"

				# Update Nuclei
				if ! nuclei -update 2>>"$LOGFILE" >/dev/null; then
					printf "%b[!] Nuclei update failed.%b\n" "$bred" "$reset"
					end_func "Nuclei update failed." "${FUNCNAME[0]}"
					return 1
				fi

				# Pull latest fuzzing templates
				if ! git -C ${NUCLEI_FUZZING_TEMPLATES_PATH} pull 2>>"$LOGFILE"; then
					printf "%b[!] Failed to pull latest fuzzing templates.%b\n" "$bred" "$reset"
					end_func "Failed to pull latest fuzzing templates." "${FUNCNAME[0]}"
					return 1
				fi

				# Execute Nuclei with the fuzzing templates
				nuclei -silent -retries 3 -rl "$NUCLEI_RATELIMIT" -t ${NUCLEI_FUZZING_TEMPLATES_PATH} -dast -j -o ".tmp/fuzzparams_json.txt" <"webs/url_extract_nodupes.txt" 2>>"$LOGFILE"

			else
				printf "${yellow}\n[$(date +'%Y-%m-%d %H:%M:%S')] Running: Axiom with Nuclei${reset}\n\n"

				# Clone fuzzing-templates if not already present
				if [[ ! -d "/home/op/fuzzing-templates" ]]; then
					axiom-exec "git clone https://github.com/projectdiscovery/fuzzing-templates /home/op/fuzzing-templates" &>/dev/null
				fi

				# Execute Axiom scan with Nuclei
				axiom-scan "webs/url_extract_nodupes.txt" -m nuclei -nh -retries 3 -w "/home/op/fuzzing-templates" -rl "$NUCLEI_RATELIMIT" -dast -j -o ".tmp/fuzzparams_json.txt" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi

			# Convert JSON output to text
			jq -r '["[" + .["template-id"] + (if .["matcher-name"] != null then ":" + .["matcher-name"] else "" end) + "] [" + .["type"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host) + (if .["extracted-results"] != null then " " + (.["extracted-results"] | @json) else "" end)] | .[]' .tmp/fuzzparams_json.txt > .tmp/fuzzparams.txt

			# Append unique results to vulns/fuzzparams.txt
			if [[ -s ".tmp/fuzzparams.txt" ]]; then
				cat ".tmp/fuzzparams.txt" | anew -q "vulns/fuzzparams.txt"
			fi

			# Faraday integration
			if [[ $FARADAY == true ]]; then
				# Check if the Faraday server is running
				if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
					printf "%b[!] Faraday server is not running. Skipping Faraday integration.%b\n" "$bred" "$reset"
				else
					if [[ -s ".tmp/fuzzparams_json.txt" ]]; then
						faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei .tmp/fuzzparams_json.txt 2>>"$LOGFILE" >/dev/null
					fi
				fi
			fi

			end_func "Results are saved in vulns/fuzzparams.txt" "${FUNCNAME[0]}"

		else
			end_func "Fuzzing Parameters Values: Too many entries to test, try with --deep flag" "${FUNCNAME[0]}"
		fi

	else
		# Handle cases where FUZZPARAMS is false, no vulnerable URLs, or already processed
		if [[ $FUZZPARAMS == false ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped due to configuration settings.${reset}\n"
		elif [[ ! -s "webs/url_extract_nodupes.txt" ]]; then
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} skipped: No URLs potentially vulnerable to Fuzzing Parameters.${reset}\n\n"
		else
			printf "${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] ${FUNCNAME[0]} has already been processed. To force execution, delete:\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

###############################################################################################################
########################################## OPTIONS & MGMT #####################################################
###############################################################################################################

function deleteOutScoped() {
	if [[ -s $1 ]]; then
		cat $1 | while read outscoped; do
			if grep -q "^[*]" <<<$outscoped; then
				outscoped="${outscoped:1}"
				sed -i /"$outscoped$"/d $2
			else
				sed -i /$outscoped/d $2
			fi
		done
	fi
}

function getElapsedTime {
	runtime=""
	local T=$2-$1
	local D=$((T / 60 / 60 / 24))
	local H=$((T / 60 / 60 % 24))
	local M=$((T / 60 % 60))
	local S=$((T % 60))
	((D > 0)) && runtime="$runtime$D days, "
	((H > 0)) && runtime="$runtime$H hours, "
	((M > 0)) && runtime="$runtime$M minutes, "
	runtime="$runtime$S seconds."
}

function zipSnedOutputFolder {
	zip_name1=$(date +"%Y_%m_%d-%H.%M.%S")
	zip_name="${zip_name1}_${domain}.zip" 2>>"$LOGFILE" >/dev/null
	(cd "$dir" && zip -r "$zip_name" .) 2>>"$LOGFILE" >/dev/null
	echo "Sending zip file "${dir}/${zip_name}""
	if [[ -s "${dir}/$zip_name" ]]; then
		sendToNotify "$dir/$zip_name"
		rm -f "${dir}/$zip_name"
	else
		notification "No Zip file to send" warn
	fi
}

function isAsciiText {
	IS_ASCII="False"
	if [[ $(file $1 | grep -o 'ASCII text$') == "ASCII text" ]]; then
		IS_ASCII="True"
	else
		IS_ASCII="False"
	fi
}

function output() {
	mkdir -p $dir_output
	cp -r $dir $dir_output
	[[ "$(dirname $dir)" != "$dir_output" ]] && rm -rf "$dir"
}

function remove_big_files() {
	eval rm -rf .tmp/gotator*.txt 2>>"$LOGFILE"
	eval rm -rf .tmp/brute_recursive_wordlist.txt 2>>"$LOGFILE"
	eval rm -rf .tmp/subs_dns_tko.txt 2>>"$LOGFILE"
	eval rm -rf .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/brute_dns_tko.txt .tmp/scrap_subs.txt .tmp/analytics_subs_clean.txt .tmp/gotator1.txt .tmp/gotator2.txt .tmp/passive_recursive.txt .tmp/brute_recursive_wordlist.txt .tmp/gotator1_recursive.txt .tmp/gotator2_recursive.txt 2>>"$LOGFILE"
	eval find .tmp -type f -size +200M -exec rm -f {} + 2>>"$LOGFILE"
}

function notification() {
	if [[ -n $1 ]] && [[ -n $2 ]]; then
		if [[ $NOTIFICATION == true ]]; then
			NOTIFY="notify -silent"
		else
			NOTIFY=""
		fi
		if [[ -z $3 ]]; then
			current_date=$(date +'%Y-%m-%d %H:%M:%S')
		else
			current_date="$3"
		fi

		case $2 in
		info)
			text="\n${bblue}[$current_date] ${1} ${reset}"
			;;
		warn)
			text="\n${yellow}[$current_date] ${1} ${reset}"
			;;
		error)
			text="\n${bred}[$current_date] ${1} ${reset}"
			;;
		good)
			text="\n${bgreen}[$current_date] ${1} ${reset}"
			;;
		esac

		# Print to terminal
		printf "${text}\n"

		# Send to notify if notifications are enabled
		if [[ -n $NOTIFY ]]; then
			# Remove color codes for the notification
			clean_text=$(echo -e "${text} - ${domain}" | sed 's/\x1B\[[0-9;]*[JKmsu]//g')
			echo -e "${clean_text}" | $NOTIFY >/dev/null 2>&1
		fi
	fi
}

function transfer {
	if [[ $# -eq 0 ]]; then
		echo "No arguments specified.\nUsage:\n transfer <file|directory>\n ... | transfer <file_name>" >&2
		return 1
	fi
	if tty -s; then
		file="$1"
		file_name=$(basename "$file")
		if [[ ! -e $file ]]; then
			echo "$file: No such file or directory" >&2
			return 1
		fi
		if [[ -d $file ]]; then
			file_name="$file_name.zip"
			(cd "$file" && zip -r -q - .) | curl --progress-bar --upload-file "-" "https://oshi.at/${file_name}" | tee /dev/null
		else
			cat "$file" | curl --progress-bar --upload-file "-" "https://oshi.at/${file_name}" | tee /dev/null
		fi
	else
		file_name=$1
		curl --progress-bar --upload-file "-" "https://oshi.at/${file_name}" | tee /dev/null
	fi
}

function sendToNotify {
	if [[ -z $1 ]]; then
		printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] No file provided to send ${reset}\n"
	else
		if [[ -z $NOTIFY_CONFIG ]]; then
			NOTIFY_CONFIG=~/.config/notify/provider-config.yaml
		fi
		if [[ -n "$(find "${1}" -prune -size +8000000c)" ]]; then
			printf '%s is larger than 8MB, sending over oshi.at\n' "${1}"
			transfer "${1}" | notify -silent
			return 0
		fi
		if grep -q '^ telegram\|^telegram\|^    telegram' $NOTIFY_CONFIG; then
			notification "[$(date +'%Y-%m-%d %H:%M:%S')] Sending ${domain} data over Telegram" info
			telegram_chat_id=$(sed -n '/^telegram:/,/^[^ ]/p' ${NOTIFY_CONFIG} | sed -n 's/^[ ]*telegram_chat_id:[ ]*"\([^"]*\)".*/\1/p')
			telegram_key=$(sed -n '/^telegram:/,/^[^ ]/p' ${NOTIFY_CONFIG} | sed -n 's/^[ ]*telegram_api_key:[ ]*"\([^"]*\)".*/\1/p')
			curl -F "chat_id=${telegram_chat_id}" -F "document=@${1}" https://api.telegram.org/bot${telegram_key}/sendDocument 2>>"$LOGFILE" >/dev/null
		fi
		if grep -q '^ discord\|^discord\|^    discord' $NOTIFY_CONFIG; then
			notification "[$(date +'%Y-%m-%d %H:%M:%S')] Sending ${domain} data over Discord" info
			discord_url=$(sed -n '/^discord:/,/^[^ ]/p' ${NOTIFY_CONFIG} | sed -n 's/^[ ]*discord_webhook_url:[ ]*"\([^"]*\)".*/\1/p')
			curl -v -i -H "Accept: application/json" -H "Content-Type: multipart/form-data" -X POST -F 'payload_json={"username": "test", "content": "hello"}' -F file1=@${1} $discord_url 2>>"$LOGFILE" >/dev/null
		fi
		if [[ -n $slack_channel ]] && [[ -n $slack_auth ]]; then
			notification "[$(date +'%Y-%m-%d %H:%M:%S')] Sending ${domain} data over Slack" info
			curl -F file=@${1} -F "initial_comment=reconftw zip file" -F channels=${slack_channel} -H "Authorization: Bearer ${slack_auth}" https://slack.com/api/files.upload 2>>"$LOGFILE" >/dev/null
		fi
	fi
}

function start_func() {
	printf "${bgreen}#######################################################################"
	notification "${2}" info
	echo "[$current_date] Start function: ${1} " >>"${LOGFILE}"
	start=$(date +%s)
}

function end_func() {
	touch $called_fn_dir/.${2}
	end=$(date +%s)
	getElapsedTime $start $end
	notification "${2} Finished in ${runtime}" info
	echo "[$current_date] End function: ${2} " >>"${LOGFILE}"
	printf "${bblue}[$current_date] ${1} ${reset}\n"
	printf "${bgreen}#######################################################################${reset}\n"
}

function start_subfunc() {
	notification "     ${2}" info
	echo "[$current_date] Start subfunction: ${1} " >>"${LOGFILE}"
	start_sub=$(date +%s)
}

function end_subfunc() {
	touch $called_fn_dir/.${2}
	end_sub=$(date +%s)
	getElapsedTime $start_sub $end_sub
	notification "     ${1} in ${runtime}" good
	echo "[$current_date] End subfunction: ${1} " >>"${LOGFILE}"
}

function check_inscope() {
	cat $1 | inscope >$1_tmp && cp $1_tmp $1 && rm -f $1_tmp
}

function resolvers_update() {

	if [[ $generate_resolvers == true ]]; then
		if [[ $AXIOM != true ]]; then
			if [[ ! -s $resolvers ]] || [[ $(find "$resolvers" -mtime +1 -print) ]]; then
				notification "Resolvers seem older than 1 day\n Generating custom resolvers..." warn
				eval rm -f $resolvers 2>>"$LOGFILE"
				dnsvalidator -tL https://public-dns.info/nameservers.txt -threads $DNSVALIDATOR_THREADS -o $resolvers 2>>"$LOGFILE" >/dev/null
				dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads $DNSVALIDATOR_THREADS -o tmp_resolvers 2>>"$LOGFILE" >/dev/null
				[ -s "tmp_resolvers" ] && cat tmp_resolvers | anew -q $resolvers
				[ -s "tmp_resolvers" ] && rm -f tmp_resolvers 2>>"$LOGFILE" >/dev/null
				[ ! -s "$resolvers" ] && wget -q -O - ${resolvers_url} >$resolvers
				[ ! -s "$resolvers_trusted" ] && wget -q -O - ${resolvers_trusted_url} >$resolvers_trusted
				notification "Updated\n" good
			fi
		else
			notification "Checking resolvers lists...\n Accurate resolvers are the key to great results\n This may take around 10 minutes if it's not updated" warn
			# shellcheck disable=SC2016
			axiom-exec 'if [[ $(find "/home/op/lists/resolvers.txt" -mtime +1 -print) ]] || [[ $(cat /home/op/lists/resolvers.txt | wc -l) -le 40 ] ; then dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o /home/op/lists/resolvers.txt ; fi' &>/dev/null
			axiom-exec "wget -q -O - ${resolvers_url} > /home/op/lists/resolvers.txt" 2>>"$LOGFILE" >/dev/null
			axiom-exec "wget -q -O - ${resolvers_trusted_url} > /home/op/lists/resolvers_trusted.txt" 2>>"$LOGFILE" >/dev/null
			notification "Updated\n" good
		fi
		generate_resolvers=false
	else

		if [[ ! -s $resolvers ]] || [[ $(find "$resolvers" -mtime +1 -print) ]]; then
			notification "Resolvers seem older than 1 day\n Downloading new resolvers..." warn
			wget -q -O - ${resolvers_url} >$resolvers
			wget -q -O - ${resolvers_trusted_url} >$resolvers_trusted
			notification "Resolvers updated\n" good
		fi
	fi

}

function resolvers_update_quick_local() {
	if [[ $update_resolvers == true ]]; then
		wget -q -O - ${resolvers_url} >$resolvers
		wget -q -O - ${resolvers_trusted_url} >$resolvers_trusted
	fi
}

function resolvers_update_quick_axiom() {
	axiom-exec "wget -q -O - ${resolvers_url} > /home/op/lists/resolvers.txt" 2>>"$LOGFILE" >/dev/null
	axiom-exec "wget -q -O - ${resolvers_trusted_url} > /home/op/lists/resolvers_trusted.txt" 2>>"$LOGFILE" >/dev/null
}

function ipcidr_target() {
	IP_CIDR_REGEX='(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?))(\/([8-9]|[1-2][0-9]|3[0-2]))([^0-9.]|$)|(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$)'
	if [[ $1 =~ ^$IP_CIDR_REGEX ]]; then
		echo $1 | mapcidr -silent | anew -q target_reconftw_ipcidr.txt
		if [[ -s "./target_reconftw_ipcidr.txt" ]]; then
			[ "$REVERSE_IP" = true ] && cat ./target_reconftw_ipcidr.txt | hakip2host | cut -d' ' -f 3 | unfurl -u domains 2>/dev/null | sed -e 's/*\.//' -e 's/\.$//' -e '/\./!d' | anew -q ./target_reconftw_ipcidr.txt
			if [[ $(cat ./target_reconftw_ipcidr.txt | wc -l) -eq 1 ]]; then
				domain=$(cat ./target_reconftw_ipcidr.txt)
			elif [[ $(cat ./target_reconftw_ipcidr.txt | wc -l) -gt 1 ]]; then
				unset domain
				list=${PWD}/target_reconftw_ipcidr.txt
			fi
		fi
		if [[ -n $2 ]]; then
			cat $list | anew -q $2
			sed -i '/\/[0-9]*$/d' $2
		fi
	fi
}

function axiom_launch() {
	# let's fire up a FLEET!
	if [[ $AXIOM_FLEET_LAUNCH == true ]] && [[ -n $AXIOM_FLEET_NAME ]] && [[ -n $AXIOM_FLEET_COUNT ]]; then
		start_func ${FUNCNAME[0]} "Launching our Axiom fleet"

		# Check to see if we have a fleet already, if so, SKIP THIS!
		NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME" || true)
		if [[ $NUMOFNODES -ge $AXIOM_FLEET_COUNT ]]; then
			axiom-select "$AXIOM_FLEET_NAME*"
			end_func "Axiom fleet $AXIOM_FLEET_NAME already has $NUMOFNODES instances" info
		else
			if [[ $NUMOFNODES -eq 0 ]]; then
				startcount=$AXIOM_FLEET_COUNT
			else
				startcount=$((AXIOM_FLEET_COUNT - NUMOFNODES))
			fi
			AXIOM_ARGS=" -i $startcount"
			# Temporarily disabled multiple axiom regions
			# [ -n "$AXIOM_FLEET_REGIONS" ] && axiom_args="$axiom_args --regions=\"$AXIOM_FLEET_REGIONS\" "

			echo "axiom-fleet ${AXIOM_FLEET_NAME} ${AXIOM_ARGS}"
			axiom-fleet ${AXIOM_FLEET_NAME} ${AXIOM_ARGS}
			axiom-select "$AXIOM_FLEET_NAME*"
			if [[ -n $AXIOM_POST_START ]]; then
				eval "$AXIOM_POST_START" 2>>"$LOGFILE" >/dev/null
			fi

			NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME" || true)
			end_func "Axiom fleet $AXIOM_FLEET_NAME launched $NUMOFNODES instances" info
		fi
	fi
}

function axiom_shutdown() {
	if [[ $AXIOM_FLEET_LAUNCH == true ]] && [[ $AXIOM_FLEET_SHUTDOWN == true ]] && [[ -n $AXIOM_FLEET_NAME ]]; then
		#if [[ "$mode" == "subs_menu" ]] || [[ "$mode" == "list_recon" ]] || [[ "$mode" == "passive" ]] || [[ "$mode" == "all" ]]; then
		if [[ $mode == "subs_menu" ]] || [[ $mode == "passive" ]] || [[ $mode == "all" ]]; then
			notification "Automatic Axiom fleet shutdown is not enabled in this mode" info
			return
		fi
		eval axiom-rm -f "$AXIOM_FLEET_NAME*" || true
		axiom-ls | grep "$AXIOM_FLEET_NAME" || true
		notification "Axiom fleet $AXIOM_FLEET_NAME shutdown" info
	fi
}

function axiom_selected() {

	if [[ ! $(axiom-ls | tail -n +2 | sed '$ d' | wc -l) -gt 0 ]]; then
		notification "No axiom instances running ${reset}\n\n" error
		exit
	fi

	if [[ ! $(cat ~/.axiom/selected.conf | sed '/^\s*$/d' | wc -l) -gt 0 ]]; then
		notification "No axiom instances selected ${reset}\n\n" error
		exit
	fi
}

function start() {

	global_start=$(date +%s)

	printf "\n${bgreen}#######################################################################${reset}"
	notification "Recon succesfully started on ${domain}" "good" "$(date +'%Y-%m-%d %H:%M:%S')"
	[ "$SOFT_NOTIFICATION" = true ] && echo "$(date +'%Y-%m-%d %H:%M:%S') Recon succesfully started on ${domain}" | notify -silent
	printf "${bgreen}#######################################################################${reset}\n"
	if [[ $upgrade_before_running == true ]]; then
		${SCRIPTPATH}/install.sh --tools
	fi
	tools_installed

	#[[ -n "$domain" ]] && ipcidr_target $domain

	if [[ -z $domain ]]; then
		if [[ -n $list ]]; then
			if [[ -z $domain ]]; then
				domain="Multi"
				dir="${SCRIPTPATH}/Recon/$domain"
				called_fn_dir="$dir"/.called_fn
			fi
			if [[ $list == /* ]]; then
				install -D "$list" "$dir"/webs/webs.txt
			else
				install -D "${SCRIPTPATH}"/"$list" "$dir"/webs/webs.txt
			fi
		fi
	else
		dir="${SCRIPTPATH}/Recon/$domain"
		called_fn_dir="$dir"/.called_fn
	fi

	if [[ -z $domain ]]; then
		notification "${bred} No domain or list provided ${reset}\n\n" error
		exit
	fi

	if [[ ! -d $called_fn_dir ]]; then
		mkdir -p "$called_fn_dir"
	fi
	mkdir -p "$dir"
	cd "$dir" || {
		echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}
	if [[ $AXIOM == true ]]; then
		if [[ -n $domain ]]; then
			echo "$domain" | anew -q target.txt
			list="${dir}/target.txt"
		fi
	fi
	mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}

	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"

	printf "\n"
	printf "${bred}[$(date +'%Y-%m-%d %H:%M:%S')] Target: ${domain}\n\n"
}

function end() {

	find $dir -type f -empty -print | grep -v '.called_fn' | grep -v '.log' | grep -v '.tmp' | xargs rm -f 2>>"$LOGFILE" >/dev/null
	find $dir -type d -empty -print -delete 2>>"$LOGFILE" >/dev/null

	echo "[$(date +'%Y-%m-%d %H:%M:%S')] End" >>"${LOGFILE}"

	if [[ $PRESERVE != true ]]; then
		find $dir -type f -empty | grep -v "called_fn" | xargs rm -f 2>>"$LOGFILE" >/dev/null
		find $dir -type d -empty | grep -v "called_fn" | xargs rm -rf 2>>"$LOGFILE" >/dev/null
	fi

	if [[ $REMOVETMP == true ]]; then
		rm -rf $dir/.tmp
	fi

	if [[ $REMOVELOG == true ]]; then
		rm -rf $dir/.log
	fi

	if [[ -n $dir_output ]]; then
		output
		finaldir=$dir_output
	else
		finaldir=$dir
	fi
	#Zip the output folder and send it via tg/discord/slack
	if [[ $SENDZIPNOTIFY == true ]]; then
		zipSnedOutputFolder
	fi
	global_end=$(date +%s)
	getElapsedTime $global_start $global_end
	printf "${bgreen}#######################################################################${reset}\n"
	notification "Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" good "$(date +'%Y-%m-%d %H:%M:%S')"
	[ "$SOFT_NOTIFICATION" = true ] && echo "[$(date +'%Y-%m-%d %H:%M:%S')] Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" | notify -silent
	printf "${bgreen}#######################################################################${reset}\n"
	#Separator for more clear messges in telegram_Bot
	notification echo "[$(date +'%Y-%m-%d %H:%M:%S')] ******  Stay safe 🦠 and secure 🔐  ******" info

}

###############################################################################################################
########################################### MODES & MENUS #####################################################
###############################################################################################################

function passive() {
	start
	domain_info
	ip_info
	emails
	google_dorks
	#github_dorks
	github_repos
	metadata
	apileaks
	third_party_misconfigs
	SUBNOERROR=false
	SUBANALYTICS=false
	SUBBRUTE=false
	SUBSCRAPING=false
	SUBPERMUTE=false
	SUBREGEXPERMUTE=false
	SUB_RECURSIVE_BRUTE=false
	WEBPROBESIMPLE=false
	if [[ $AXIOM == true ]]; then
		axiom_launch
		axiom_selected
	fi

	subdomains_full
	remove_big_files
	favicon
	cdnprovider
	PORTSCAN_ACTIVE=false
	portscan
	geo_info

	if [[ $AXIOM == true ]]; then
		axiom_shutdown
	fi

	end
}

function all() {
	start
	recon
	vulns
	end
}

function osint() {
	domain_info
	ip_info
	emails
	google_dorks
	#github_dorks
	github_repos
	metadata
	apileaks
	third_party_misconfigs
	zonetransfer
	favicon
}

function vulns() {
	if [[ $VULNS_GENERAL == true ]]; then
		cors
		open_redirect
		ssrf_checks
		crlf_checks
		lfi
		ssti
		sqli
		xss
		command_injection
		prototype_pollution
		smuggling
		webcache
		spraying
		brokenLinks
		fuzzparams
		4xxbypass
		test_ssl
	fi
}

function multi_osint() {

	global_start=$(date +%s)

	#[[ -n "$domain" ]] && ipcidr_target $domain

	if [[ -s $list ]]; then
		sed -i 's/\r$//' $list
		targets=$(cat $list)
	else
		notification "Target list not provided" error
		exit
	fi

	workdir=${SCRIPTPATH}/Recon/$multi
	mkdir -p $workdir || {
		echo "Failed to create directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}
	cd "$workdir" || {
		echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}
	mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}

	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"

	for domain in $targets; do
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		mkdir -p $dir
		cd "$dir" || {
			echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
			exit 1
		}
		mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}
		NOW=$(date +"%F")
		NOWT=$(date +"%T")
		LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
		touch .log/${NOW}_${NOWT}.txt
		echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"
		domain_info
		ip_info
		emails
		google_dorks
		#github_dorks
		github_repos
		metadata
		apileaks
		third_party_misconfigs
		zonetransfer
		favicon
	done
	cd "$workdir" || {
		echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}
	dir=$workdir
	domain=$multi
	end
}

function recon() {
	domain_info
	ip_info
	emails
	google_dorks
	#github_dorks
	github_repos
	metadata
	apileaks
	third_party_misconfigs
	zonetransfer
	favicon

	if [[ $AXIOM == true ]]; then
		axiom_launch
		axiom_selected
	fi

	subdomains_full
	webprobe_full
	subtakeover
	remove_big_files
	s3buckets
	screenshot
	#	virtualhosts
	cdnprovider
	portscan
	geo_info
	waf_checks
	fuzz
	iishortname
	urlchecks
	jschecks
	nuclei_check

	if [[ $AXIOM == true ]]; then
		axiom_shutdown
	fi

	cms_scanner
	url_gf
	wordlist_gen
	wordlist_gen_roboxtractor
	password_dict
	url_ext
}

function multi_recon() {

	[ "$SOFT_NOTIFICATION" = true ] && echo "$(date +'%Y-%m-%d %H:%M:%S') Recon successfully started on ${multi}" | notify -silent

	global_start=$(date +%s)

	#[[ -n "$domain" ]] && ipcidr_target $domain

	if [[ -s $list ]]; then
		sed -i 's/\r$//' $list
		targets=$(cat $list)
	else
		notification "Target list not provided" error
		exit
	fi

	workdir=${SCRIPTPATH}/Recon/$multi
	mkdir -p $workdir || {
		echo "Failed to create directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}
	cd "$workdir" || {
		echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}

	mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}
	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"

	[ -n "$flist" ] && LISTTOTAL=$(cat "$flist" | wc -l)

	for domain in $targets; do
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn

		# Ensure directories exist
		mkdir -p "$dir" || {
			echo "Failed to create directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
			exit 1
		}
		mkdir -p "$called_fn_dir" || {
			echo "Failed to create directory '$called_fn_dir' in ${FUNCNAME[0]} @ line ${LINENO}"
			exit 1
		}

		cd "$dir" || {
			echo "Failed to cd to directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
			exit 1
		}

		mkdir -p {.log,.tmp,webs,hosts,vulns,osint,screenshots,subdomains}

		NOW=$(date +"%F")
		NOWT=$(date +"%T")
		LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"

		# Ensure the .log directory exists before touching the file
		mkdir -p .log

		touch "$LOGFILE" || {
			echo "Failed to create log file: $LOGFILE"
			exit 1
		}
		echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"$LOGFILE"
		loopstart=$(date +%s)

		domain_info
		ip_info
		emails
		google_dorks
		#github_dorks
		github_repos
		metadata
		apileaks
		third_party_misconfigs
		zonetransfer
		favicon
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen}[$(date +'%Y-%m-%d %H:%M:%S')] $domain finished 1st loop in ${runtime} $currently ${reset}\n"
		if [[ -n $flist ]]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done
	cd "$workdir" || {
		echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}

	if [[ $AXIOM == true ]]; then
		axiom_launch
		axiom_selected
	fi

	for domain in $targets; do
		loopstart=$(date +%s)
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		cd "$dir" || {
			echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
			exit 1
		}
		subdomains_full
		webprobe_full
		subtakeover
		remove_big_files
		screenshot
		#		virtualhosts
		cdnprovider
		portscan
		geo_info
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen}[$(date +'%Y-%m-%d %H:%M:%S')] $domain finished 2nd loop in ${runtime} $currently ${reset}\n"
		if [[ -n $flist ]]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done
	cd "$workdir" || {
		echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}

	notification "############################# Total data ############################" info
	NUMOFLINES_users_total=$(find . -type f -name 'users.txt' -exec cat {} + | anew osint/users.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_pwndb_total=$(find . -type f -name 'passwords.txt' -exec cat {} + | anew osint/passwords.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_software_total=$(find . -type f -name 'software.txt' -exec cat {} + | anew osint/software.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_authors_total=$(find . -type f -name 'authors.txt' -exec cat {} + | anew osint/authors.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_subs_total=$(find . -type f -name 'subdomains.txt' -exec cat {} + | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_subtko_total=$(find . -type f -name 'takeover.txt' -exec cat {} + | anew webs/takeover.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_webs_total=$(find . -type f -name 'webs.txt' -exec cat {} + | anew webs/webs.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_webs_total=$(find . -type f -name 'webs_uncommon_ports.txt' -exec cat {} + | anew webs/webs_uncommon_ports.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_ips_total=$(find . -type f -name 'ips.txt' -exec cat {} + | anew hosts/ips.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_cloudsprov_total=$(find . -type f -name 'cdn_providers.txt' -exec cat {} + | anew hosts/cdn_providers.txt | sed '/^$/d' | wc -l)
	find . -type f -name 'portscan_active.txt' -exec cat {} + | tee -a hosts/portscan_active.txt >>"$LOGFILE" 2>&1 >/dev/null
	find . -type f -name 'portscan_active.gnmap' -exec cat {} + | tee hosts/portscan_active.gnmap 2>>"$LOGFILE" >/dev/null
	find . -type f -name 'portscan_passive.txt' -exec cat {} + | tee hosts/portscan_passive.txt 2>&1 >>"$LOGFILE" >/dev/null

	notification "- ${NUMOFLINES_users_total} total users found" good
	notification "- ${NUMOFLINES_pwndb_total} total creds leaked" good
	notification "- ${NUMOFLINES_software_total} total software found" good
	notification "- ${NUMOFLINES_authors_total} total authors found" good
	notification "- ${NUMOFLINES_subs_total} total subdomains" good
	notification "- ${NUMOFLINES_subtko_total} total probably subdomain takeovers" good
	notification "- ${NUMOFLINES_webs_total} total websites" good
	notification "- ${NUMOFLINES_ips_total} total ips" good
	notification "- ${NUMOFLINES_cloudsprov_total} total IPs belongs to cloud" good
	s3buckets
	waf_checks
	for domain in $targets; do
		loopstart=$(date +%s)
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		cd "$dir" || {
			echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
			exit 1
		}
		loopstart=$(date +%s)
		fuzz
		iishortname
		urlchecks
		jschecks
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen}[$(date +'%Y-%m-%d %H:%M:%S')] $domain finished 3rd loop in ${runtime} $currently ${reset}\n"
		if [[ -n $flist ]]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done
	nuclei_check
	if [[ $AXIOM == true ]]; then
		axiom_shutdown
	fi

	for domain in $targets; do
		loopstart=$(date +%s)
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		cd "$dir" || {
			echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
			exit 1
		}
		cms_scanner
		url_gf
		wordlist_gen
		wordlist_gen_roboxtractor
		password_dict
		url_ext
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen}[$(date +'%Y-%m-%d %H:%M:%S')] $domain finished final loop in ${runtime} $currently ${reset}\n"
		if [[ -n $flist ]]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}[$(date +'%Y-%m-%d %H:%M:%S')] $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done
	cd "$workdir" || {
		echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}
	dir=$workdir
	domain=$multi
	end
	[ "$SOFT_NOTIFICATION" = true ] && echo "$(date +'%Y-%m-%d %H:%M:%S') Finished Recon on: ${multi} in ${runtime}" | notify -silent
}

function multi_custom() {

	global_start=$(date +%s)

	if [[ -s $list ]]; then
		sed -i 's/\r$//' $list
		targets=$(cat $list)
	else
		notification "Target list not provided" error
		exit
	fi

	dir=${SCRIPTPATH}/Recon/$multi
	rm -rf $dir
	mkdir -p $dir || {
		echo "Failed to create directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}
	cd "$dir" || {
		echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}

	mkdir -p {.called_fn,.log}
	called_fn_dir=$dir/.called_fn
	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "[$(date +'%Y-%m-%d %H:%M:%S')] Start ${NOW} ${NOWT}" >"${LOGFILE}"

	[ -n "$flist" ] && entries=$(cat "$flist" | wc -l)

	if [[ $AXIOM == true ]]; then
		axiom_launch
		axiom_selected
	fi

	custom_function_list=$(echo $custom_function | tr ',' '\n')
	func_total=$(echo "$custom_function_list" | wc -l)

	func_count=0
	domain=$(cat $flist)
	for custom_f in $custom_function_list; do
		((func_count = func_count + 1))

		loopstart=$(date +%s)

		$custom_f

		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen}[$(date +'%Y-%m-%d %H:%M:%S')] Finished $custom_f ($func_count/$func_total) for $entries entries in ${runtime} $currently ${reset}\n"
		printf "${bgreen}#######################################################################${reset}\n"
	done

	if [[ $AXIOM == true ]]; then
		axiom_shutdown
	fi

	end
}

function subs_menu() {
	start

	if [[ $AXIOM == true ]]; then
		axiom_launch
		axiom_selected
	fi

	subdomains_full
	webprobe_full
	subtakeover
	remove_big_files
	screenshot
	#	virtualhosts
	zonetransfer
	s3buckets

	if [[ $AXIOM == true ]]; then
		axiom_shutdown
	fi

	end
}

function webs_menu() {
	subtakeover
	remove_big_files
	screenshot
	#	virtualhosts
	waf_checks
	fuzz
	cms_scanner
	iishortname
	urlchecks
	jschecks
	url_gf
	nuclei_check
	wordlist_gen
	wordlist_gen_roboxtractor
	password_dict
	url_ext
	vulns
	end
}

function zen_menu() {
	start
	if [[ $AXIOM == true ]]; then
		axiom_launch
		axiom_selected
	fi
	subdomains_full
	webprobe_full
	subtakeover
	remove_big_files
	s3buckets
	screenshot
	#	virtualhosts
	cdnprovider
	waf_checks
	fuzz
	iishortname
	nuclei_check

	if [[ $AXIOM == true ]]; then
		axiom_shutdown
	fi
	cms_scanner
	end
}

function help() {
	printf "\n Usage: $0 [-d domain.tld] [-m name] [-l list.txt] [-x oos.txt] [-i in.txt] "
	printf "\n           	      [-r] [-s] [-p] [-a] [-w] [-n] [-i] [-h] [-f] [--deep] [-o OUTPUT]\n\n"
	printf " ${bblue}TARGET OPTIONS${reset}\n"
	printf "   -d domain.tld     Target domain\n"
	printf "   -m company        Target company name\n"
	printf "   -l list.txt       Targets list (One on each line)\n"
	printf "   -x oos.txt        Excludes subdomains list (Out Of Scope)\n"
	printf "   -i in.txt         Includes subdomains list\n"
	printf " \n"
	printf " ${bblue}MODE OPTIONS${reset}\n"
	printf "   -r, --recon       Recon - Performs full recon process (without attacks)\n"
	printf "   -s, --subdomains  Subdomains - Performs Subdomain Enumeration, Web probing and check for sub-tko\n"
	printf "   -p, --passive     Passive - Performs only passive steps\n"
	printf "   -a, --all         All - Performs all checks and active exploitations\n"
	printf "   -w, --web         Web - Performs web checks from list of subdomains\n"
	printf "   -n, --osint       OSINT - Checks for public intel data\n"
	printf "   -z, --zen         Zen - Performs a recon process covering the basics and some vulns \n"
	printf "   -c, --custom      Custom - Launches specific function against target, u need to know the function name first\n"
	printf "   -h                Help - Show help section\n"
	printf " \n"
	printf " ${bblue}GENERAL OPTIONS${reset}\n"
	printf "   --deep            Deep scan (Enable some slow options for deeper scan)\n"
	printf "   -f config_file    Alternate reconftw.cfg file\n"
	printf "   -o output/path    Define output folder\n"
	printf "   -v, --vps         Axiom distributed VPS \n"
	printf "   -q                Rate limit in requests per second \n"
	printf "   --check-tools     Exit if one of the tools is missing\n"
	printf " \n"
	printf " ${bblue}USAGE EXAMPLES${reset}\n"
	printf " ${byellow}Perform full recon (without attacks):${reset}\n"
	printf " ./reconftw.sh -d example.com -r\n"
	printf " \n"
	printf " ${byellow}Perform subdomain enumeration on multiple targets:${reset}\n"
	printf " ./reconftw.sh -l targets.txt -s\n"
	printf " \n"
	printf " ${byellow}Perform Web based scanning on a subdomains list:${reset}\n"
	printf " ./reconftw.sh -d example.com -l targets.txt -w\n"
	printf " \n"
	printf " ${byellow}Multidomain recon:${reset}\n"
	printf " ./reconftw.sh -m company -l domainlist.txt -r\n"
	printf " \n"
	printf " ${byellow}Perform full recon (with active attacks) along Out-Of-Scope subdomains list:${reset}\n"
	printf " ./reconftw.sh -d example.com -x out.txt -a\n"
	printf " \n"
	printf " ${byellow}Perform full recon and store output to specified directory:${reset}\n"
	printf " ./reconftw.sh -d example.com -r -o custom/path\n"
	printf " \n"
	printf " ${byellow}Run custom function:${reset}\n"
	printf " ./reconftw.sh -d example.com -c nuclei_check \n"
}

###############################################################################################################
########################################### START SCRIPT  #####################################################
###############################################################################################################

# macOS PATH initialization, thanks @0xtavian <3
if [[ $OSTYPE == "darwin"* ]]; then
	if ! command -v brew &> /dev/null; then
		printf "\n%bBrew is not installed or not in the PATH.%b\n\n" "$bred" "$reset"
		exit 1
	fi
	if [[ ! -x "$(brew --prefix gnu-getopt)/bin/getopt" ]]; then
		printf "\n%bBrew formula gnu-getopt is not installed.%b\n\n" "$bred" "$reset"
		exit 1
	fi
	if [[ ! -d "$(brew --prefix coreutils)/libexec/gnubin" ]]; then
		printf "\n%bBrew formula coreutils is not installed.%b\n\n" "$bred" "$reset"
		exit 1
	fi
	# Prefix is different depending on Intel vs Apple Silicon
	PATH="$(brew --prefix gnu-getopt)/bin:$PATH"
	PATH="$(brew --prefix coreutils)/libexec/gnubin:$PATH"
fi

PROGARGS=$(getopt -o 'd:m:l:x:i:o:f:q:c:z:rspanwvh::' --long 'domain:,list:,recon,subdomains,passive,all,web,osint,zen,deep,help,vps,check-tools' -n 'reconFTW' -- "$@")

exit_status=$?
if [[ $exit_status -ne 0 ]]; then
	UNKNOWN_ARGUMENT=true
fi

# Note the quotes around "$PROGARGS": they are essential!
eval set -- "$PROGARGS"
unset PROGARGS

while true; do
	case "$1" in
	'-d' | '--domain')
		domain=$2
		ipcidr_target $2
		shift 2
		continue
		;;
	'-m')
		multi=$2
		shift 2
		continue
		;;
	'-l' | '--list')
		list=$2
		for t in $(cat $list); do
			ipcidr_target $t $list
		done
		shift 2
		continue
		;;
	'-x')
		outOfScope_file=$2
		shift 2
		continue
		;;
	'-i')
		inScope_file=$2
		shift 2
		continue
		;;
	# modes
	'-r' | '--recon')
		opt_mode='r'
		shift
		continue
		;;
	'-s' | '--subdomains')
		opt_mode='s'
		shift
		continue
		;;
	'-p' | '--passive')
		opt_mode='p'
		shift
		continue
		;;
	'-a' | '--all')
		opt_mode='a'
		shift
		continue
		;;
	'-w' | '--web')
		opt_mode='w'
		shift
		continue
		;;
	'-n' | '--osint')
		opt_mode='n'
		shift
		continue
		;;
	'-c' | '--custom')
		custom_function=$2
		opt_mode='c'
		shift 2
		continue
		;;
	'-z' | '--zen')
		opt_mode='z'
		shift
		continue
		;;
	# extra stuff
	'-o')
		if [[ $2 != /* ]]; then
			dir_output=$PWD/$2
		else
			dir_output=$2
		fi
		shift 2
		continue
		;;
	'-v' | '--vps')
		command -v axiom-ls &>/dev/null || {
			printf "\n Axiom is needed for this mode and is not installed \n You have to install it manually \n" && exit
		}
		AXIOM=true
		shift
		continue
		;;
	'-f')
		CUSTOM_CONFIG=$2
		shift 2
		continue
		;;
	'-q')
		rate_limit=$2
		shift 2
		continue
		;;
	'--deep')
		opt_deep=true
		shift
		continue
		;;

	'--')
		shift
		break
		;;
	'--check-tools')
		CHECK_TOOLS_OR_EXIT=true
		shift
		continue
		;;
	'--help' | '-h')
		break
		;;
	*)
		# echo "Unknown argument: $1"
		UNKNOWN_ARGUMENT=true
		break
		;;
	esac
done

# Initialize some variables
#opt_deep="${opt_deep:=false}"
#rate_limit="${rate_limit:=0}"
#outOfScope_file="${outOfScope_file:=}"
#inScope_file="${inScope_file:=}"
#domain="${domain:=}"
#multi="${multi:=}"
#list="${list:=}"
#opt_mode="${opt_mode:=}"
#custom_function="${custom_function:=}"
#AXIOM="${AXIOM:=false}"
#AXIOM_POST_START="${AXIOM_POST_START:=}"
#CUSTOM_CONFIG="${CUSTOM_CONFIG:=}"

# This is the first thing to do to read in alternate config
SCRIPTPATH="$(
	cd "$(dirname "$0")" >/dev/null 2>&1 || exit
	pwd -P
)"
. "${SCRIPTPATH}"/reconftw.cfg || {
	echo "Error importing reconftw.ctg"
	exit 1
}

if [[ -s $CUSTOM_CONFIG ]]; then
	# shellcheck source=/home/six2dez/Tools/reconftw/custom_config.cfg
	. "${CUSTOM_CONFIG}" || {
		echo "Error importing reconftw.ctg"
		exit 1
	}
fi

if [[ $opt_deep ]]; then
	DEEP=true
fi

if [[ $rate_limit ]]; then
	NUCLEI_RATELIMIT=$rate_limit
	FFUF_RATELIMIT=$rate_limit
	HTTPX_RATELIMIT=$rate_limit
fi

if [[ -n $outOfScope_file ]]; then
	isAsciiText $outOfScope_file
	if [[ "False" == "$IS_ASCII" ]]; then
		printf "\n\n${bred} Out of Scope file is not a text file${reset}\n\n"
		exit
	fi
fi

if [[ -n $inScope_file ]]; then
	isAsciiText $inScope_file
	if [[ "False" == "$IS_ASCII" ]]; then
		printf "\n\n${bred} In Scope file is not a text file${reset}\n\n"
		exit
	fi
fi

if [[ $(id -u | grep -o '^0$') == "0" ]]; then
	SUDO=" "
else
	SUDO="sudo"
fi

startdir=${PWD}

banner

check_version

startdir=${PWD}
if [[ -n $list ]]; then
	if [[ $list == ./* ]]; then
		flist="${startdir}/${list:2}"
	elif [[ $list == ~* ]]; then
		flist="${HOME}/${list:2}"
	elif [[ $list == /* ]]; then
		flist=$list
	else
		flist="$startdir/$list"
	fi
else
	flist=''
fi

case $opt_mode in
'r')
	if [[ -n $multi ]]; then
		if [[ $AXIOM == true ]]; then
			mode="multi_recon"
		fi
		multi_recon
		exit
	fi
	if [[ -n $list ]]; then
		if [[ $AXIOM == true ]]; then
			mode="list_recon"
		fi
		sed -i 's/\r$//' $list
		for domain in $(cat $list); do
			start
			recon
			end
		done
	else
		if [[ $AXIOM == true ]]; then
			mode="recon"
		fi
		start
		recon
		end
	fi
	;;
's')
	if [[ -n $list ]]; then
		if [[ $AXIOM == true ]]; then
			mode="subs_menu"
		fi
		sed -i 's/\r$//' $list
		for domain in $(cat $list); do
			subs_menu
		done
	else
		subs_menu
	fi
	;;
'p')
	if [[ -n $list ]]; then
		if [[ $AXIOM == true ]]; then
			mode="passive"
		fi
		sed -i 's/\r$//' $list
		for domain in $(cat $list); do
			passive
		done
	else
		passive
	fi
	;;
'a')
	export VULNS_GENERAL=true
	if [[ -n $list ]]; then
		if [[ $AXIOM == true ]]; then
			mode="all"
		fi
		sed -i 's/\r$//' $list
		for domain in $(cat $list); do
			all
		done
	else
		all
	fi
	;;
'w')
	if [[ -n $list ]]; then
		start
		if [[ $list == /* ]]; then
			cp $list $dir/webs/webs.txt
		else
			cp ${SCRIPTPATH}/$list $dir/webs/webs.txt
		fi
	else
		printf "\n\n${bred} Web mode needs a website list file as target (./reconftw.sh -l target.txt -w) ${reset}\n\n"
		exit
	fi
	webs_menu
	exit
	;;
'n')
	PRESERVE=true
	if [[ -n $multi ]]; then
		multi_osint
		exit
	fi
	if [[ -n $list ]]; then
		sed -i 's/\r$//' $list
		while IFS= read -r domain; do
			start
			osint
			end
		done
	else
		start
		osint
		end
	fi
	;;
'z')
	if [[ -n $list ]]; then
		if [[ $AXIOM == true ]]; then
			mode="zen_menu"
		fi
		sed -i 's/\r$//' $list
		for domain in $(cat $list); do
			zen_menu
		done
	else
		zen_menu
	fi
	;;
'c')
	if [[ -n $multi ]]; then
		if [[ $AXIOM == true ]]; then
			mode="multi_custom"
		fi
		multi_custom
	else
		export DIFF=true
		dir="${SCRIPTPATH}/Recon/$domain"
		cd $dir || {
			echo "Failed to cd directory '$dir'"
			exit 1
		}
		LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
		called_fn_dir=$dir/.called_fn
		$custom_function
		cd ${SCRIPTPATH} || {
			echo "Failed to cd directory '$dir'"
			exit 1
		}
	fi
	exit
	;;
	# No mode selected.  EXIT!
*)
	help
	tools_installed
	if [[ $UNKNOWN_ARGUMENT == true ]]; then
		exit 1
	fi
	;;
esac
