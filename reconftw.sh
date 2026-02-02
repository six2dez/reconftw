#!/bin/bash

# Defaults aimed at unattended execution (fail-soft)
set -o pipefail
set -E
set +e
IFS=$'\n\t'

# Standard exit/return codes (guard for re-source in test harnesses)
if [[ -z "${E_SUCCESS+x}" ]]; then
    readonly E_SUCCESS=0
    readonly E_GENERAL=1
    readonly E_MISSING_DEP=2
    readonly E_INVALID_INPUT=3
    readonly E_NETWORK=4
    readonly E_DISK_SPACE=5
    readonly E_PERMISSION=6
    readonly E_TIMEOUT=7
    readonly E_CONFIG=8
fi

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

# Detect if the script is being run (not sourced) in MacOS with Homebrew Bash
if [[ "${BASH_SOURCE[0]}" == "${0}" && $OSTYPE == "darwin"* && $BASH != "/opt/homebrew/bin/bash" ]]; then
    exec /opt/homebrew/bin/bash "$0" "$@"
fi

# timeout/gtimeout compatibility
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
else
    TIMEOUT_CMD=""
fi

# Ensure a safe default for early log redirections
# If LOGFILE is unset or empty, send logs to /dev/null until later initialization
: "${LOGFILE:=/dev/null}"

###############################################################################################################
############################################## MODULE LOADING #################################################
###############################################################################################################

# Determine script path for module loading
# (full SCRIPTPATH is set later during config phase; use a temporary value here)
_INIT_SCRIPTPATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
SCRIPTPATH="${_INIT_SCRIPTPATH}"

# Source libraries first (pure utilities)
source "${_INIT_SCRIPTPATH}/lib/validation.sh"

# Source all modules in dependency order
source "${_INIT_SCRIPTPATH}/modules/utils.sh"
source "${_INIT_SCRIPTPATH}/modules/core.sh"
source "${_INIT_SCRIPTPATH}/modules/osint.sh"
source "${_INIT_SCRIPTPATH}/modules/subdomains.sh"
source "${_INIT_SCRIPTPATH}/modules/web.sh"
source "${_INIT_SCRIPTPATH}/modules/vulns.sh"
source "${_INIT_SCRIPTPATH}/modules/axiom.sh"
source "${_INIT_SCRIPTPATH}/modules/modes.sh"

# Allow sourcing functions without execution (for testing)
# Must be checked before argument parsing to avoid side effects
if [[ "${1:-}" == "--source-only" ]]; then
    return 0 2>/dev/null || exit 0
fi

###############################################################################################################
########################################### START SCRIPT  #####################################################
###############################################################################################################

# macOS PATH initialization, thanks @0xtavian <3
if [[ $OSTYPE == "darwin"* ]]; then
    if ! command -v brew &>/dev/null; then
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
    if [[ ! -d "$(brew --prefix gnu-sed)/libexec/gnubin" ]]; then
        printf "\n%bBrew formula gnu-sed is not installed.%b\n\n" "$bred" "$reset"
        exit 1
    fi
    # Prefix is different depending on Intel vs Apple Silicon
    PATH="$(brew --prefix gnu-getopt)/bin:$PATH"
    PATH="$(brew --prefix coreutils)/libexec/gnubin:$PATH"
    PATH="$(brew --prefix gnu-sed)/libexec/gnubin:$PATH"
fi

PROGARGS=$(getopt -o 'd:m:l:x:i:o:f:q:c:zrspanwvyh' --long 'domain:,list:,recon,subdomains,passive,all,web,osint,zen,deep,help,vps,ai,check-tools,health-check,quick-rescan,incremental,adaptive-rate,dry-run' -n 'reconFTW' -- "$@")

exit_status=$?
if [[ $exit_status -ne 0 ]]; then
    UNKNOWN_ARGUMENT=true
fi

# Note the quotes around "$PROGARGS": they are essential!
# shellcheck disable=SC2086
eval set -- "$PROGARGS"
unset PROGARGS

while true; do
    case "$1" in
        '-d' | '--domain')
            # Sanitize target input to prevent command injection
            target_input="$2"
            if [[ "$target_input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
                if ! domain=$(sanitize_ip "$target_input"); then
                    printf "%b[%s] ERROR: Invalid IP/CIDR provided: '%s'%b\n" \
                        "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$target_input" "$reset"
                    exit 1
                fi
            else
                if ! domain=$(sanitize_domain "$target_input"); then
                    printf "%b[%s] ERROR: Invalid domain provided: '%s'%b\n" \
                        "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$target_input" "$reset"
                    exit 1
                fi
            fi
            ipcidr_target "$domain"
            shift 2
            continue
            ;;
        '-m')
            multi=$2
            shift 2
            continue
            ;;
        '-l' | '--list')
            list="$2"
            if ! validate_file_readable "$list"; then
                printf "%b[%s] ERROR: List file not found or not readable: '%s'%b\n" \
                    "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$list" "$reset" >&2
                printf "%bUsage: -l <file> where file contains one target per line%b\n" \
                    "$yellow" "$reset" >&2
                exit 1
            fi
            while IFS= read -r t; do
                [[ -z "$t" ]] && continue
                ipcidr_target "$t" "$list"
            done <"$list"
            shift 2
            continue
            ;;
        '-x')
            outOfScope_file=$2
            if [[ -n "$outOfScope_file" ]] && ! validate_file_readable "$outOfScope_file"; then
                printf "%b[%s] ERROR: Out-of-scope file not found or not readable: '%s'%b\n" \
                    "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$outOfScope_file" "$reset" >&2
                exit 1
            fi
            shift 2
            continue
            ;;
        '-i')
            inScope_file=$2
            if [[ -n "$inScope_file" ]] && ! validate_file_readable "$inScope_file"; then
                printf "%b[%s] ERROR: In-scope file not found or not readable: '%s'%b\n" \
                    "$bred" "$(date +'%Y-%m-%d %H:%M:%S')" "$inScope_file" "$reset" >&2
                exit 1
            fi
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
        '-y' | '--ai')
            opt_ai=true
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
        '--health-check')
            HEALTH_CHECK=true
            shift
            continue
            ;;
        '--quick-rescan')
            QUICK_RESCAN=true
            shift
            continue
            ;;
        '--incremental')
            INCREMENTAL_MODE=true
            shift
            continue
            ;;
        '--adaptive-rate')
            ADAPTIVE_RATE_LIMIT=true
            shift
            continue
            ;;
        '--dry-run')
            DRY_RUN=true
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
    echo "Error importing reconftw.cfg"
    exit 1
}

# Source optional secrets file (gitignored, for API keys and tokens)
[[ -f "${SCRIPTPATH}/secrets.cfg" ]] && . "${SCRIPTPATH}/secrets.cfg"

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

# Check critical dependencies before proceeding
if [[ "${SKIP_CRITICAL_CHECK:-false}" != "true" ]]; then
    check_critical_dependencies
fi

# Run health check if requested and exit
if [[ "${HEALTH_CHECK:-false}" == "true" ]]; then
    health_check
    exit $?
fi

# Show DRY_RUN mode warning if enabled
if [[ "${DRY_RUN:-false}" == "true" ]]; then
    printf "\n%b#######################################################################%b\n" "$bgreen" "$reset"
    printf "%b[%s] DRY-RUN MODE ENABLED - Commands will be shown but not executed%b\n" "$yellow" "$(date +'%Y-%m-%d %H:%M:%S')" "$reset"
    printf "%b#######################################################################%b\n\n" "$bgreen" "$reset"
fi

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
            sed_i 's/\r$//' "$list"
            while IFS= read -r domain; do
                [[ -z "$domain" ]] && continue
                start
                recon
                end
            done <"$list"
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
            sed_i 's/\r$//' "$list"
            while IFS= read -r domain; do
                [[ -z "$domain" ]] && continue
                subs_menu
            done <"$list"
        else
            subs_menu
        fi
        ;;
    'p')
        if [[ -n $list ]]; then
            if [[ $AXIOM == true ]]; then
                mode="passive"
            fi
            sed_i 's/\r$//' "$list"
            while IFS= read -r domain; do
                [[ -z "$domain" ]] && continue
                passive
            done <"$list"
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
            sed_i 's/\r$//' "$list"
            while IFS= read -r domain; do
                [[ -z "$domain" ]] && continue
                all
            done <"$list"
        else
            all
        fi
        ;;
    'w')
        if [[ -n $list ]]; then
            start
            if [[ $list == /* ]]; then
                cp "$list" "$dir/webs/webs.txt"
            else
                cp "${SCRIPTPATH}/$list" "$dir/webs/webs.txt"
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
            sed_i 's/\r$//' "$list"
            while IFS= read -r domain; do
                [[ -z "$domain" ]] && continue
                start
                osint
                end
            done <"$list"
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
            sed_i 's/\r$//' "$list"
            while IFS= read -r domain; do
                [[ -z "$domain" ]] && continue
                zen_menu
            done <"$list"
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
