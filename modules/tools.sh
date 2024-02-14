#!/usr/bin/env bash

source "$1/reconftw.cfg"

###############################################################################################################
################################################### TOOLS #####################################################
###############################################################################################################

function check_version() {
	timeout 10 git fetch
	exit_status=$?
	if [[ ${exit_status} -eq 0 ]]; then
		BRANCH=$(git rev-parse --abbrev-ref HEAD)
		HEADHASH=$(git rev-parse HEAD)
		UPSTREAMHASH=$(git rev-parse "${BRANCH}"@\{upstream\})
		if [[ ${HEADHASH} != "${UPSTREAMHASH}" ]]; then
			printf "\n${yellow} There is a new version, run ./install.sh to get latest version${reset}\n\n"
		fi
	else
		printf "\n${bred} Unable to check updates ${reset}\n\n"
	fi
}

function tools_installed() {

	printf "\n\n${bgreen}#######################################################################${reset}\n"
	printf "${bblue} Checking installed tools ${reset}\n\n"

	allinstalled=true

	[ -n "$GOPATH" ] || {
		printf "${bred} [*] GOPATH var			[NO]${reset}\n"
		allinstalled=false
	}
	[ -n "$GOROOT" ] || {
		printf "${bred} [*] GOROOT var			[NO]${reset}\n"
		allinstalled=false
	}
	[ -n "$PATH" ] || {
		printf "${bred} [*] PATH var			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/dorks_hunter/dorks_hunter.py" ] || {
		printf "${bred} [*] dorks_hunter		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/brutespray/brutespray.py" ] || {
		printf "${bred} [*] brutespray			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/fav-up/favUp.py" ] || {
		printf "${bred} [*] fav-up			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/Corsy/corsy.py" ] || {
		printf "${bred} [*] Corsy			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/testssl.sh/testssl.sh" ] || {
		printf "${bred} [*] testssl			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/CMSeeK/cmseek.py" ] || {
		printf "${bred} [*] CMSeeK			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${fuzz_wordlist}" ] || {
		printf "${bred} [*] OneListForAll		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${lfi_wordlist}" ] || {
		printf "${bred} [*] lfi_wordlist		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${ssti_wordlist}" ] || {
		printf "${bred} [*] ssti_wordlist		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${subs_wordlist}" ] || {
		printf "${bred} [*] subs_wordlist		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${subs_wordlist_big}" ] || {
		printf "${bred} [*] subs_wordlist_big		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${resolvers}" ] || {
		printf "${bred} [*] resolvers		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${resolvers_trusted}" ] || {
		printf "${bred} [*] resolvers_trusted		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/xnLinkFinder/xnLinkFinder.py" ] || {
		printf "${bred} [*] xnLinkFinder		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/waymore/waymore.py" ] || {
		printf "${bred} [*] waymore		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/commix/commix.py" ] || {
		printf "${bred} [*] commix			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/getjswords.py" ] || {
		printf "${bred} [*] getjswords   		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/JSA/jsa.py" ] || {
		printf "${bred} [*] JSA			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/cloud_enum/cloud_enum.py" ] || {
		printf "${bred} [*] cloud_enum			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/ultimate-nmap-parser/ultimate-nmap-parser.sh" ] || {
		printf "${bred} [*] nmap-parse-output		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/pydictor/pydictor.py" ] || {
		printf "${bred} [*] pydictor   		[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/urless/urless/urless.py" ] || {
		printf "${bred} [*] urless			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/smuggler/smuggler.py" ] || {
		printf "${bred} [*] smuggler			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/regulator/main.py" ] || {
		printf "${bred} [*] regulator			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/dontgo403/dontgo403" ] || {
		printf "${bred} [*] dontgo403			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/SwaggerSpy/swaggerspy.py" ] || {
		printf "${bred} [*] swaggerspy			[NO]${reset}\n"
		allinstalled=false
	}
	[ -f "${tools}/LeakSearch/LeakSearch.py" ] || {
		printf "${bred} [*] LeakSearch			[NO]${reset}\n"
		allinstalled=false
	}
	command -v github-endpoints &>/dev/null || {
		printf "${bred} [*] github-endpoints		[NO]${reset}\n"
		allinstalled=false
	}
	command -v github-subdomains &>/dev/null || {
		printf "${bred} [*] github-subdomains		[NO]${reset}\n"
		allinstalled=false
	}
	command -v gitlab-subdomains &>/dev/null || {
		printf "${bred} [*] gitlab-subdomains		[NO]${reset}\n"
		allinstalled=false
	}
	command -v katana &>/dev/null || {
		printf "${bred} [*] katana			[NO]${reset}\n"
		allinstalled=false
	}
	command -v wafw00f &>/dev/null || {
		printf "${bred} [*] wafw00f			[NO]${reset}\n"
		allinstalled=false
	}
	command -v dnsvalidator &>/dev/null || {
		printf "${bred} [*] dnsvalidator		[NO]${reset}\n"
		allinstalled=false
	}
	command -v amass &>/dev/null || {
		printf "${bred} [*] Amass			[NO]${reset}\n"
		allinstalled=false
	}
	command -v dnsx &>/dev/null || {
		printf "${bred} [*] dnsx			[NO]${reset}\n"
		allinstalled=false
	}
	command -v gotator &>/dev/null || {
		printf "${bred} [*] gotator			[NO]${reset}\n"
		allinstalled=false
	}
	command -v nuclei &>/dev/null || {
		printf "${bred} [*] Nuclei			[NO]${reset}\n"
		allinstalled=false
	}
	[ -d ${NUCLEI_TEMPLATES_PATH} ] || {
		printf "${bred} [*] Nuclei templates	[NO]${reset}\n"
		allinstalled=false
	}
	[ -d ${tools}/fuzzing-templates ] || {
		printf "${bred} [*] Fuzzing templates	[NO]${reset}\n"
		allinstalled=false
	}
	command -v gf &>/dev/null || {
		printf "${bred} [*] Gf				[NO]${reset}\n"
		allinstalled=false
	}
	command -v Gxss &>/dev/null || {
		printf "${bred} [*] Gxss			[NO]${reset}\n"
		allinstalled=false
	}
	command -v subjs &>/dev/null || {
		printf "${bred} [*] subjs			[NO]${reset}\n"
		allinstalled=false
	}
	command -v ffuf &>/dev/null || {
		printf "${bred} [*] ffuf			[NO]${reset}\n"
		allinstalled=false
	}
	command -v massdns &>/dev/null || {
		printf "${bred} [*] Massdns			[NO]${reset}\n"
		allinstalled=false
	}
	command -v qsreplace &>/dev/null || {
		printf "${bred} [*] qsreplace			[NO]${reset}\n"
		allinstalled=false
	}
	command -v interlace &>/dev/null || {
		printf "${bred} [*] interlace			[NO]${reset}\n"
		allinstalled=false
	}
	command -v anew &>/dev/null || {
		printf "${bred} [*] Anew			[NO]${reset}\n"
		allinstalled=false
	}
	command -v unfurl &>/dev/null || {
		printf "${bred} [*] unfurl			[NO]${reset}\n"
		allinstalled=false
	}
	command -v crlfuzz &>/dev/null || {
		printf "${bred} [*] crlfuzz			[NO]${reset}\n"
		allinstalled=false
	}
	command -v httpx &>/dev/null || {
		printf "${bred} [*] Httpx			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v jq &>/dev/null || {
		printf "${bred} [*] jq				[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v notify &>/dev/null || {
		printf "${bred} [*] notify			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v dalfox &>/dev/null || {
		printf "${bred} [*] dalfox			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v puredns &>/dev/null || {
		printf "${bred} [*] puredns			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v emailfinder &>/dev/null || {
		printf "${bred} [*] emailfinder		[NO]${reset}\n"
		allinstalled=false
	}
	command -v analyticsrelationships &>/dev/null || {
		printf "${bred} [*] analyticsrelationships	[NO]${reset}\n"
		allinstalled=false
	}
	command -v mapcidr &>/dev/null || {
		printf "${bred} [*] mapcidr			[NO]${reset}\n"
		allinstalled=false
	}
	command -v ppmap &>/dev/null || {
		printf "${bred} [*] ppmap			[NO]${reset}\n"
		allinstalled=false
	}
	command -v cdncheck &>/dev/null || {
		printf "${bred} [*] cdncheck			[NO]${reset}\n"
		allinstalled=false
	}
	command -v interactsh-client &>/dev/null || {
		printf "${bred} [*] interactsh-client		[NO]${reset}\n"
		allinstalled=false
	}
	command -v tlsx &>/dev/null || {
		printf "${bred} [*] tlsx			[NO]${reset}\n"
		allinstalled=false
	}
	command -v smap &>/dev/null || {
		printf "${bred} [*] smap			[NO]${reset}\n"
		allinstalled=false
	}
	command -v gitdorks_go &>/dev/null || {
		printf "${bred} [*] gitdorks_go		[NO]${reset}\n"
		allinstalled=false
	}
	command -v ripgen &>/dev/null || {
		printf "${bred} [*] ripgen			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v dsieve &>/dev/null || {
		printf "${bred} [*] dsieve			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v inscope &>/dev/null || {
		printf "${bred} [*] inscope			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v enumerepo &>/dev/null || {
		printf "${bred} [*] enumerepo			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v Web-Cache-Vulnerability-Scanner &>/dev/null || {
		printf "${bred} [*] Web-Cache-Vulnerability-Scanner [NO]${reset}\n"
		allinstalled=false
	}
	command -v subfinder &>/dev/null || {
		printf "${bred} [*] subfinder			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v ghauri &>/dev/null || {
		printf "${bred} [*] ghauri			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v hakip2host &>/dev/null || {
		printf "${bred} [*] hakip2host			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v gau &>/dev/null || {
		printf "${bred} [*] gau			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v crt &>/dev/null || {
		printf "${bred}  [*] crt			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v gitleaks &>/dev/null || {
		printf "${bred} [*] gitleaks			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v trufflehog &>/dev/null || {
		printf "${bred} [*] trufflehog			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v s3scanner &>/dev/null || {
		printf "${bred} [*] s3scanner			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v mantra &>/dev/null || {
		printf "${bred} [*] mantra			[NO]${reset}\n${reset}"
		allinstalled=false
	}
	command -v nmapurls &>/dev/null || {
		printf "${bred} [*] nmapurls			[NO]${reset}\n"
		allinstalled=false
	}
	command -v porch-pirate &>/dev/null || {
		printf "${bred} [*] porch-pirate			[NO]${reset}\n"
		allinstalled=false
	}
	command -v shortscan &>/dev/null || {
		printf "${bred} [*] shortscan			[NO]${reset}\n"
		allinstalled=false
	}
	command -v sns &>/dev/null || {
		printf "${bred} [*] sns			[NO]${reset}\n"
		allinstalled=false
	}
	if [[ ${allinstalled} == true ]]; then
		printf "${bgreen} Good! All installed! ${reset}\n\n"
	else
		printf "\n${yellow} Try running the installer script again ./install.sh"
		printf "\n${yellow} If it fails for any reason try to install manually the tools missed"
		printf "\n${yellow} Finally remember to set the ${bred}\${tools}${yellow} variable at the start of this script"
		printf "\n${yellow} If nothing works and the world is gonna end you can always ping me :D ${reset}\n\n"
	fi

	printf "${bblue} Tools check finished\n"
	printf "${bgreen}#######################################################################\n${reset}"
}
