#!/usr/bin/env bash

RECONFTW_DIR="$(
	cd "$(dirname "$0")" >/dev/null 2>&1 || exit
	pwd -P
)"

source ./modules/extras.sh "$RECONFTW_DIR/reconftw.cfg"
source ./modules/hosts.sh "$RECONFTW_DIR/reconftw.cfg"
source ./modules/osint.sh "$RECONFTW_DIR/reconftw.cfg"
source ./modules/subdomains.sh "$RECONFTW_DIR/reconftw.cfg"
source ./modules/tools.sh "$RECONFTW_DIR/reconftw.cfg"
source ./modules/vulns.sh "$RECONFTW_DIR/reconftw.cfg"
source ./modules/webs.sh "$RECONFTW_DIR/reconftw.cfg"

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

function banner_graber() {
	source "${SCRIPTPATH}"/banners.txt
	randx=$(shuf -i 1-23 -n 1)
	tmp="banner${randx}"
	banner_code=${!tmp}
	echo -e "${banner_code}"
}
function banner() {
	banner_code=$(banner_graber)
	printf "\n${bgreen}${banner_code}"
	printf "\n ${reconftw_version}                                 by @six2dez${reset}\n"
}

function test_connectivity() {
	if nc -zw1 google.com 443 2>/dev/null; then
		echo -e "Connection: ${bgreen}OK${reset}"
	else
		echo -e "${bred}[!] Please check your internet connection and then try again...${reset}"
		exit 1
	fi
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
	github_dorks
	github_repos
	metadata
	apileaks
	SUBNOERROR=false
	SUBANALYTICS=false
	SUBBRUTE=false
	SUBSCRAPING=false
	SUBPERMUTE=false
	SUBREGEXPERMUTE=false
	SUB_RECURSIVE_BRUTE=false
	WEBPROBESIMPLE=false
	if [[ $AXIOM == true ]]; then
		axiom_lauch
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
	github_dorks
	github_repos
	metadata
	apileaks
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

	if [[ $NOTIFICATION == true ]]; then
		NOTIFY="notify -silent"
	else
		NOTIFY=""
	fi

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
	mkdir -p .tmp .called_fn osint subdomains webs hosts vulns

	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "Start ${NOW} ${NOWT}" >"${LOGFILE}"

	for domain in $targets; do
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		mkdir -p $dir
		cd "$dir" || {
			echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
			exit 1
		}
		mkdir -p .tmp .called_fn osint subdomains webs hosts vulns
		NOW=$(date +"%F")
		NOWT=$(date +"%T")
		LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
		touch .log/${NOW}_${NOWT}.txt
		echo "Start ${NOW} ${NOWT}" >"${LOGFILE}"
		domain_info
		ip_info
		emails
		google_dorks
		github_dorks
		github_repos
		metadata
		apileaks
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
	github_dorks
	github_repos
	metadata
	apileaks
	zonetransfer
	favicon

	if [[ $AXIOM == true ]]; then
		axiom_lauch
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
	nuclei_check
	iishortname
	urlchecks
	jschecks

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

	global_start=$(date +%s)

	if [[ $NOTIFICATION == true ]]; then
		NOTIFY="notify -silent"
	else
		NOTIFY=""
	fi

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

	mkdir -p .tmp .log .called_fn osint subdomains webs hosts vulns
	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "Start ${NOW} ${NOWT}" >"${LOGFILE}"

	[ -n "$flist" ] && LISTTOTAL=$(cat "$flist" | wc -l)

	for domain in $targets; do
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		mkdir -p $dir
		cd "$dir" || {
			echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"
			exit 1
		}
		mkdir -p .tmp .log .called_fn osint subdomains webs hosts vulns

		NOW=$(date +"%F")
		NOWT=$(date +"%T")
		LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
		touch .log/${NOW}_${NOWT}.txt
		echo "Start ${NOW} ${NOWT}" >"${LOGFILE}"
		loopstart=$(date +%s)

		domain_info
		ip_info
		emails
		google_dorks
		github_dorks
		github_repos
		metadata
		apileaks
		zonetransfer
		favicon
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen} $domain finished 1st loop in ${runtime}  $currently ${reset}\n"
		if [[ -n $flist ]]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done
	cd "$workdir" || {
		echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"
		exit 1
	}

	if [[ $AXIOM == true ]]; then
		axiom_lauch
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
		printf "${bgreen} $domain finished 2nd loop in ${runtime}  $currently ${reset}\n"
		if [[ -n $flist ]]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
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
	nuclei_check
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
		printf "${bgreen} $domain finished 3rd loop in ${runtime}  $currently ${reset}\n"
		if [[ -n $flist ]]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done

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
		printf "${bgreen} $domain finished final loop in ${runtime}  $currently ${reset}\n"
		if [[ -n $flist ]]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
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
}

function subs_menu() {
	start

	if [[ $AXIOM == true ]]; then
		axiom_lauch
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
	nuclei_check
	cms_scanner
	iishortname
	urlchecks
	jschecks
	url_gf
	wordlist_gen
	wordlist_gen_roboxtractor
	password_dict
	url_ext
	vulns
	end
}

function help() {
	printf "\n Usage: $0 [-d domain.tld] [-m name] [-l list.txt] [-x oos.txt] [-i in.txt] "
	printf "\n           	      [-r] [-s] [-p] [-a] [-w] [-n] [-i] [-h] [-f] [--deep] [-o OUTPUT]\n\n"
	printf " ${bblue}TARGET OPTIONS${reset}\n"
	printf "   -d domain.tld     Target domain\n"
	printf "   -m company        Target company name\n"
	printf "   -l list.txt       Targets list (One on each line)\n"
	printf "   -x oos.txt        Exclude subdomains list (Out Of Scope)\n"
	printf "   -i in.txt         Include subdomains list\n"
	printf " \n"
	printf " ${bblue}MODE OPTIONS${reset}\n"
	printf "   -r, --recon       Recon - Perform full recon process (without attacks)\n"
	printf "   -s, --subdomains  Subdomains - Perform Subdomain Enumeration, Web probing and check for sub-tko\n"
	printf "   -p, --passive     Passive - Perform only passive steps\n"
	printf "   -a, --all         All - Perform all checks and active exploitations\n"
	printf "   -w, --web         Web - Perform web checks from list of subdomains\n"
	printf "   -n, --osint       OSINT - Check for public intel data\n"
	printf "   -c, --custom      Custom - Launches specific function against target, u need to know the function name first\n"
	printf "   -h                Help - Show help section\n"
	printf " \n"
	printf " ${bblue}GENERAL OPTIONS${reset}\n"
	printf "   --deep            Deep scan (Enable some slow options for deeper scan)\n"
	printf "   -f config_file    Alternate reconftw.cfg file\n"
	printf "   -o output/path    Define output folder\n"
	printf "   -v, --vps         Axiom distributed VPS \n"
	printf "   -q                Rate limit in requests per second \n"
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
	PATH="/usr/local/opt/gnu-getopt/bin:$PATH"
	PATH="/usr/local/opt/coreutils/libexec/gnubin:$PATH"
fi

PROGARGS=$(getopt -o 'd:m:l:x:i:o:f:q:c:rspanwvh::' --long 'domain:,list:,recon,subdomains,passive,all,web,osint,deep,help,vps' -n 'reconFTW' -- "$@")

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
			allinstalled=false
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
	'--help' | '-h' | *)
		# echo "Unknown argument: $1"
		. ./reconftw.cfg
		banner
		help
		tools_installed
		exit 1
		;;
	esac
done

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
'c')
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
	exit
	;;
	# No mode selected.  EXIT!
*)
	help
	tools_installed
	exit 1
	;;
esac
