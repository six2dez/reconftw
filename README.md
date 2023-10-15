<h1 align="center">
  <br>
  <a href="https://github.com/six2dez/reconftw"><img src="https://github.com/six2dez/reconftw/blob/main/images/banner.png" alt="reconftw"></a>
  <br>
  reconFTW
  <br>
</h1>

<p align="center">
  <a href="https://github.com/six2dez/reconftw/releases/tag/v2.7">
    <img src="https://img.shields.io/badge/release-v2.7-green">
  </a>
   </a>
  <a href="https://opensource.org/licenses/MIT">
      <img src="https://img.shields.io/badge/License-MIT-yellow.svg">
  </a>
  <a href="https://twitter.com/Six2dez1">
    <img src="https://img.shields.io/badge/twitter-%40Six2dez1-blue">
  </a>
    <a href="https://github.com/six2dez/reconftw/issues?q=is%3Aissue+is%3Aclosed">
    <img src="https://img.shields.io/github/issues-closed-raw/six2dez/reconftw.svg">
  </a>
  <a href="https://github.com/six2dez/reconftw/wiki">
    <img src="https://img.shields.io/badge/doc-wiki-blue.svg">
  </a>
  <a href="https://t.me/joinchat/H5bAaw3YbzzmI5co">
    <img src="https://img.shields.io/badge/telegram-@ReconFTW-blue.svg">
  </a>
  <a href="https://discord.gg/R5DdXVEdTy">
    <img src="https://img.shields.io/discord/1048623782912340038.svg?logo=discord">
  </a>
</p>

<h3 align="center">Summary</h3>

**reconFTW** automates the entire process of reconnaissance for you. It outperforms the work of subdomain enumeration along with various vulnerability checks and obtaining maximum information about your target.

reconFTW uses a lot of techniques (passive, bruteforce, permutations, certificate transparency, source code scraping, analytics, DNS records...) for subdomain enumeration which helps you to get the maximum and the most interesting subdomains so that you be ahead of the competition.

It also performs various vulnerability checks like XSS, Open Redirects, SSRF, CRLF, LFI, SQLi, SSL tests, SSTI, DNS zone transfers, and much more. Along with these, it performs OSINT techniques, directory fuzzing, dorking, ports scanning, screenshots, nuclei scan on your target.

So, what are you waiting for? Go! Go! Go! :boom:

## 📔 Table of Contents

-----------------

- [⚙️ Config file](#️-config-file)
- [Usage](#usage)
  - [TARGET OPTIONS](#target-options)
  - [MODE OPTIONS](#mode-options)
  - [GENERAL OPTIONS](#general-options)
  - [Example Usage](#example-usage)
    - [To perform a full recon on single target](#to-perform-a-full-recon-on-single-target)
    - [To perform a full recon on a list of targets](#to-perform-a-full-recon-on-a-list-of-targets)
    - [Perform full recon with more time intense tasks *(VPS intended only)*](#perform-full-recon-with-more-time-intense-tasks-vps-intended-only)
    - [Perform recon in a multi domain target](#perform-recon-in-a-multi-domain-target)
    - [Perform recon with axiom integration](#perform-recon-with-axiom-integration)
    - [Perform all steps (whole recon + all attacks) a.k.a. YOLO mode](#perform-all-steps-whole-recon--all-attacks-aka-yolo-mode)
    - [Show help section](#show-help-section)
- [Axiom Support :cloud:](#axiom-support-cloud)
- [Sample video](#sample-video)
- [:fire: Features :fire:](#fire-features-fire)
  - [Osint](#osint)
  - [Subdomains](#subdomains)
  - [Hosts](#hosts)
  - [Webs](#webs)
  - [Vulnerability checks](#vulnerability-checks)
  - [Extras](#extras)
  - [Mindmap/Workflow](#mindmapworkflow)
  - [Data Keep](#data-keep)
    - [Makefile](#makefile)
    - [Manual](#manual)
    - [Main commands](#main-commands)
  - [How to contribute](#how-to-contribute)
  - [Need help? :information\_source:](#need-help-information_source)
  - [Support this project](#support-this-project)
    - [Buymeacoffee](#buymeacoffee)
    - [DigitalOcean referral link](#digitalocean-referral-link)
    - [GitHub sponsorship](#github-sponsorship)
  - [Thanks :pray:](#thanks-pray)
  - [Disclaimer](#disclaimer)

-----------------

## 💿 Installation

## a) Using a PC/VPS/VM

> You can check out our wiki for the installation guide [Installation Guide](https://github.com/six2dez/reconftw/wiki/0.-Installation-Guide) :book:

- Requires [Golang](https://golang.org/dl/) > **1.15.0+** installed and paths correctly set (**$GOPATH**, **$GOROOT**)

Important: if you are not running reconftw as root, run `sudo echo "${USERNAME}  ALL=(ALL:ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers.d/reconFTW`, to make sure no sudo prompts are required to run the tool and to avoid any permission issues.

```bash
git clone https://github.com/six2dez/reconftw
cd reconftw/
./install.sh
./reconftw.sh -d target.com -r
```

## b) Docker Image 🐳 (3 options)

- Pull the image

```bash
docker pull six2dez/reconftw:main
```

- Run the container

```bash
docker run -it --rm \
-v "${PWD}/OutputFolder/":'/reconftw/Recon/' \
six2dez/reconftw:main -d example.com -r
```

- View results (they're NOT in the Docker container)

  - As the folder you cloned earlier (named `reconftw`) is being renamed to `OutputFolder`, you'll have to go to that folder to view results.

If you wish to:

1. Dynamically modify the behaviour & function of the image
2. Build your own container
3. Build an Axiom Controller on top of the official image

Please refer to the [Docker](https://github.com/six2dez/reconftw/wiki/4.-Docker) documentation.

## c) Terraform + Ansible

Yes! reconFTW can also be easily deployed with Terraform and Ansible to AWS, if you want to know how to do it, you can check the guide [here](Terraform/README.md)

# ⚙️ Config file
>
> You can find a detailed explanation of the configuration file [here](https://github.com/six2dez/reconftw/wiki/3.-Configuration-file) :book:

- Through ```reconftw.cfg``` file the whole execution of the tool can be controlled.
- Hunters can set various scanning modes, execution preferences, tools, config files, APIs/TOKENS, personalized wordlists and much more.

<details>
 <br><br>
 <summary> :point_right: Click here to view default config file :point_left: </summary>

```yaml
#################################################################
#			reconFTW config file			#
#################################################################

# General values
tools=~/Tools   # Path installed tools
SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )" # Get current script's path
profile_shell=".$(basename $(echo $SHELL))rc" # Get current shell profile
reconftw_version=$(git rev-parse --abbrev-ref HEAD)-$(git describe --tags) # Fetch current reconftw version
generate_resolvers=false # Generate custom resolvers with dnsvalidator
update_resolvers=true # Fetch and rewrite resolvers from trickest/resolvers before DNS resolution
resolvers_url="https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
resolvers_trusted_url="https://raw.githubusercontent.com/six2dez/resolvers_reconftw/main/resolvers_trusted.txt"
fuzzing_remote_list="https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt" # Used to send to axiom(if used) on fuzzing 
proxy_url="http://127.0.0.1:8080/" # Proxy url
install_golang=true # Set it to false if you already have Golang configured and ready
upgrade_tools=true
#dir_output=/custom/output/path

# Golang Vars (Comment or change on your own)
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH

# Tools config files
#NOTIFY_CONFIG=~/.config/notify/provider-config.yaml # No need to define
AMASS_CONFIG=~/.config/amass/config.ini
GITHUB_TOKENS=${tools}/.github_tokens
GITLAB_TOKENS=${tools}/.gitlab_tokens
SUBGPT_COOKIE=${tools}/subgpt_cookies.json
#CUSTOM_CONFIG=custom_config_path.txt # In case you use a custom config file, uncomment this line and set your files path

# APIs/TOKENS - Uncomment the lines you want removing the '#' at the beginning of the line
#SHODAN_API_KEY="XXXXXXXXXXXXX"
#WHOISXML_API="XXXXXXXXXX"
#XSS_SERVER="XXXXXXXXXXXXXXXXX"
#COLLAB_SERVER="XXXXXXXXXXXXXXXXX"
#slack_channel="XXXXXXXX"
#slack_auth="xoXX-XXX-XXX-XXX"

# File descriptors
DEBUG_STD="&>/dev/null" # Skips STD output on installer
DEBUG_ERROR="2>/dev/null" # Skips ERR output on installer

# Osint
OSINT=true # Enable or disable the whole OSINT module
GOOGLE_DORKS=true
GITHUB_DORKS=true
GITHUB_REPOS=true
METADATA=true # Fetch metadata from indexed office documents
EMAILS=true # Fetch emails from differents sites 
DOMAIN_INFO=true # whois info
REVERSE_WHOIS=true # amass intel reverse whois info, takes some time
IP_INFO=true    # Reverse IP search, geolocation and whois
METAFINDER_LIMIT=20 # Max 250

# Subdomains
RUNAMASS=true
RUNSUBFINDER=true
SUBDOMAINS_GENERAL=true # Enable or disable the whole Subdomains module
SUBPASSIVE=true # Passive subdomains search
SUBCRT=true # crtsh search
SUBNOERROR=true # Check DNS NOERROR response and BF on them
SUBANALYTICS=true # Google Analytics search
SUBBRUTE=true # DNS bruteforcing
SUBSCRAPING=true # Subdomains extraction from web crawling
SUBPERMUTE=true # DNS permutations
SUBREGEXPERMUTE=true # Permutations by regex analysis
SUBGPT=true # Permutations by BingGPT prediction
PERMUTATIONS_OPTION=gotator # The alternative is "ripgen" (faster, not deeper)
GOTATOR_FLAGS=" -depth 1 -numbers 3 -mindup -adv -md" # Flags for gotator
SUBTAKEOVER=false # Check subdomain takeovers, false by default cuz nuclei already check this
SUB_RECURSIVE_PASSIVE=false # Uses a lot of API keys queries
DEEP_RECURSIVE_PASSIVE=10 # Number of top subdomains for recursion
SUB_RECURSIVE_BRUTE=false # Needs big disk space and time to resolve
ZONETRANSFER=true # Check zone transfer
S3BUCKETS=true # Check S3 buckets misconfigs
REVERSE_IP=false # Check reverse IP subdomain search (set True if your target is CIDR/IP)
TLS_PORTS="21,22,25,80,110,135,143,261,271,324,443,448,465,563,614,631,636,664,684,695,832,853,854,990,993,989,992,994,995,1129,1131,1184,2083,2087,2089,2096,2221,2252,2376,2381,2478,2479,2482,2484,2679,2762,3077,3078,3183,3191,3220,3269,3306,3410,3424,3471,3496,3509,3529,3539,3535,3660,36611,3713,3747,3766,3864,3885,3995,3896,4031,4036,4062,4064,4081,4083,4116,4335,4336,4536,4590,4740,4843,4849,5443,5007,5061,5321,5349,5671,5783,5868,5986,5989,5990,6209,6251,6443,6513,6514,6619,6697,6771,7202,7443,7673,7674,7677,7775,8243,8443,8991,8989,9089,9295,9318,9443,9444,9614,9802,10161,10162,11751,12013,12109,14143,15002,16995,41230,16993,20003"
INSCOPE=false # Uses inscope tool to filter the scope, requires .scope file in reconftw folder 

# Web detection
WEBPROBESIMPLE=true # Web probing on 80/443
WEBPROBEFULL=true # Web probing in a large port list
WEBSCREENSHOT=true # Webs screenshooting
VIRTUALHOSTS=false # Check virtualhosts by fuzzing HOST header
UNCOMMON_PORTS_WEB="81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3001,3002,3003,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672"

# Host
FAVICON=true # Check Favicon domain discovery
PORTSCANNER=true # Enable or disable the whole Port scanner module 
PORTSCAN_PASSIVE=true # Port scanner with Shodan
PORTSCAN_ACTIVE=true # Port scanner with nmap
CDN_IP=true # Check which IPs belongs to CDN

# Web analysis
WAF_DETECTION=true # Detect WAFs
NUCLEICHECK=true # Enable or disable nuclei
NUCLEI_SEVERITY="info,low,medium,high,critical" # Set templates criticity
NUCLEI_FLAGS=" -silent -t $HOME/nuclei-templates/ -retries 2" # Additional nuclei extra flags, don't set the severity here but the exclusions like " -etags openssh"
NUCLEI_FLAGS_JS=" -silent -tags exposure,token -severity info,low,medium,high,critical" # Additional nuclei extra flags for js secrets
URL_CHECK=true # Enable or disable URL collection
URL_CHECK_PASSIVE=true # Search for urls, passive methods from Archive, OTX, CommonCrawl, etc
URL_CHECK_ACTIVE=true # Search for urls by crawling the websites
URL_GF=true # Url patterns classification
URL_EXT=true # Returns a list of files divided by extension
JSCHECKS=true # JS analysis
FUZZ=true # Web fuzzing
CMS_SCANNER=true # CMS scanner
WORDLIST=true # Wordlist generation
ROBOTSWORDLIST=true # Check historic disallow entries on waybackMachine
PASSWORD_DICT=true # Generate password dictionary
PASSWORD_MIN_LENGTH=5 # Min password length
PASSWORD_MAX_LENGTH=14 # Max password length

# Vulns
VULNS_GENERAL=false # Enable or disable the vulnerability module (very intrusive and slow)
XSS=true # Check for xss with dalfox
CORS=true # CORS misconfigs
TEST_SSL=true # SSL misconfigs
OPEN_REDIRECT=true # Check open redirects
SSRF_CHECKS=true # SSRF checks
CRLF_CHECKS=true # CRLF checks
LFI=true # LFI by fuzzing
SSTI=true # SSTI by fuzzing
SQLI=true # Check SQLI
SQLMAP=true # Check SQLI with sqlmap
GHAURI=false # Check SQLI with ghauri
BROKENLINKS=true # Check for brokenlinks
SPRAY=true # Performs password spraying
COMM_INJ=true # Check for command injections with commix
PROTO_POLLUTION=true # Check for prototype pollution flaws
SMUGGLING=true # Check for HTTP request smuggling flaws
WEBCACHE=true # Check for Web Cache issues
BYPASSER4XX=true # Check for 4XX bypasses

# Extra features
NOTIFICATION=false # Notification for every function
SOFT_NOTIFICATION=false # Only for start/end
DEEP=false # DEEP mode, really slow and don't care about the number of results
DEEP_LIMIT=500 # First limit to not run unless you run DEEP
DEEP_LIMIT2=1500 # Second limit to not run unless you run DEEP
DIFF=false # Diff function, run every module over an already scanned target, printing only new findings (but save everything)
REMOVETMP=false # Delete temporary files after execution (to free up space)
REMOVELOG=false # Delete logs after execution
PROXY=false # Send to proxy the websites found
SENDZIPNOTIFY=false # Send to zip the results (over notify)
PRESERVE=true      # set to true to avoid deleting the .called_fn files on really large scans
FFUF_FLAGS=" -mc all -fc 404 -ach -sf -of json" # Ffuf flags
HTTPX_FLAGS=" -follow-redirects -random-agent -status-code -silent -title -web-server -tech-detect -location -content-length" # Httpx flags for simple web probing
GOWITNESS_FLAGS=" --disable-logging --timeout 5"

# HTTP options
HEADER="User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" # Default header

# Threads
FFUF_THREADS=40
HTTPX_THREADS=50
HTTPX_UNCOMMONPORTS_THREADS=100
KATANA_THREADS=20
BRUTESPRAY_THREADS=20
BRUTESPRAY_CONCURRENCE=10
GAU_THREADS=10
DNSTAKE_THREADS=100
DALFOX_THREADS=200
PUREDNS_PUBLIC_LIMIT=0 # Set between 2000 - 10000 if your router blows up, 0 means unlimited
PUREDNS_TRUSTED_LIMIT=400
PUREDNS_WILDCARDTEST_LIMIT=30
PUREDNS_WILDCARDBATCH_LIMIT=1500000
GOWITNESS_THREADS=20
RESOLVE_DOMAINS_THREADS=150
PPFUZZ_THREADS=30
DNSVALIDATOR_THREADS=200
INTERLACE_THREADS=10
TLSX_THREADS=1000
XNLINKFINDER_DEPTH=3
BYP4XX_THREADS=20

# Rate limits
HTTPX_RATELIMIT=150
NUCLEI_RATELIMIT=150
FFUF_RATELIMIT=0

# Timeouts
AMASS_INTEL_TIMEOUT=15          # Minutes
AMASS_ENUM_TIMEOUT=180          # Minutes
CMSSCAN_TIMEOUT=3600            # Seconds
FFUF_MAXTIME=900                # Seconds
HTTPX_TIMEOUT=10                # Seconds
HTTPX_UNCOMMONPORTS_TIMEOUT=10  # Seconds
PERMUTATIONS_LIMIT=21474836480  # Bytes, default is 20 GB

# lists
fuzz_wordlist=${tools}/fuzz_wordlist.txt
lfi_wordlist=${tools}/lfi_wordlist.txt
ssti_wordlist=${tools}/ssti_wordlist.txt
subs_wordlist=${tools}/subdomains.txt
subs_wordlist_big=${tools}/subdomains_n0kovo_big.txt
resolvers=${tools}/resolvers.txt
resolvers_trusted=${tools}/resolvers_trusted.txt

# Axiom Fleet
# Will not start a new fleet if one exist w/ same name and size (or larger)
# AXIOM=false Uncomment only to overwrite command line flags
AXIOM_FLEET_LAUNCH=true # Enable or disable spin up a new fleet, if false it will use the current fleet with the AXIOM_FLEET_NAME prefix
AXIOM_FLEET_NAME="reconFTW" # Fleet's prefix name
AXIOM_FLEET_COUNT=10 # Fleet's number
AXIOM_FLEET_REGIONS="eu-central" # Fleet's region
AXIOM_FLEET_SHUTDOWN=true # # Enable or disable delete the fleet after the execution
# This is a script on your reconftw host that might prep things your way...
#AXIOM_POST_START="~/Tools/axiom_config.sh" # Useful  to send your config files to the fleet
AXIOM_EXTRA_ARGS="" # Leave empty if you don't want to add extra arguments
#AXIOM_EXTRA_ARGS=" --rm-logs" # Example

# TERM COLORS
bred='\033[1;31m'
bblue='\033[1;34m'
bgreen='\033[1;32m'
byellow='\033[1;33m'
red='\033[0;31m'
blue='\033[0;34m'
green='\033[0;32m'
yellow='\033[0;33m'
reset='\033[0m'

```

</details>

# Usage

> Check out the wiki section to know which flag performs what all steps/attacks [Usage Guide](https://github.com/six2dez/reconftw/wiki/2.-Usage-Guide) :book:

## TARGET OPTIONS

| Flag | Description |
|------|-------------|
| -d | Single Target domain *(example.com)*  |
| -l | List of targets *(one per line)* |
| -m | Multiple domain target *(companyName)*  |
| -x | Exclude subdomains list *(Out Of Scope)* |
| -i | Include subdomains list *(In Scope)* |

## MODE OPTIONS

| Flag | Description |
|------|-------------|
| -r | Recon - Full recon process (without attacks like sqli,ssrf,xss,ssti,lfi etc.) |
| -s | Subdomains - Perform only subdomain enumeration, web probing, subdomain takeovers |
| -p | Passive - Perform only passive steps |
| -a | All - Perform whole recon and all active attacks |
| -w | Web - Perform only vulnerability checks/attacks on particular target |
| -n | OSINT - Performs an OSINT scan (no subdomain enumeration and attacks) |
| -c | Custom - Launches specific function against target |
| -h | Help - Show this help menu |

## GENERAL OPTIONS

| Flag | Description |
|------|-------------|
| --deep | Deep scan (Enable some slow options for deeper scan, *vps intended mode*) |
| -f | Custom config file path |
| -o | Output directory |
| -v | Axiom distributed VPS |
| -q | Rate limit in requests per second |

## Example Usage

**NOTE: this is applicable when you've installed reconFTW on the host (e.g. VM/VPS/cloud) and not in a Docker container.**

### To perform a full recon on single target

```bash
./reconftw.sh -d target.com -r
```

### To perform a full recon on a list of targets

```bash
./reconftw.sh -l sites.txt -r -o /output/directory/
```

### Perform full recon with more time intense tasks *(VPS intended only)*

```bash
./reconftw.sh -d target.com -r --deep -o /output/directory/
```

### Perform recon in a multi domain target

```bash
./reconftw.sh -m company -l domains_list.txt -r
```

### Perform recon with axiom integration

```bash
./reconftw.sh -d target.com -r -v
```

### Perform all steps (whole recon + all attacks) a.k.a. YOLO mode

```bash
./reconftw.sh -d target.com -a
```

### Show help section

```bash
./reconftw.sh -h
```

# Axiom Support :cloud:

![](https://i.ibb.co/Jzrgkqt/axiom-readme.png)
> Check out the wiki section for more info [Axiom Support](https://github.com/six2dez/reconftw/wiki/5.-Axiom-version)

- As reconFTW actively hits the target with a lot of web traffic, hence there was a need to move to Axiom distributing the work load among various instances leading to reduction of execution time.
- During the configuration of axiom you need to select `reconftw` as provisoner.
- You can create your own axiom's fleet before running reconFTW or let reconFTW to create and destroy it automatically just modifying reconftw.cfg file.

# Sample video

![Video](images/reconFTW.gif)

# :fire: Features :fire:

## Osint

- Domain information ([whois](https://github.com/rfc1036/whois) and [amass](https://github.com/OWASP/Amass))
- Emails addresses and users ([emailfinder](https://github.com/Josue87/EmailFinder))
- Metadata finder ([MetaFinder](https://github.com/Josue87/MetaFinder))
- Google Dorks ([dorks_hunter](https://github.com/six2dez/dorks_hunter))
- Github Dorks ([gitdorks_go](https://github.com/damit5/gitdorks_go))
- GitHub org analysis ([enumerepo](https://github.com/trickest/enumerepo), [trufflehog](https://github.com/trufflesecurity/trufflehog) and [gitleaks](https://github.com/gitleaks/gitleaks))

## Subdomains

- Passive ([amass](https://github.com/OWASP/Amass), [subfinder](https://github.com/projectdiscovery/subfinder) and [github-subdomains](https://github.com/gwen001/github-subdomains))
- Certificate transparency ([crt](https://github.com/cemulus/crt))
- NOERROR subdomain discovery ([dnsx](https://github.com/projectdiscovery/dnsx), more info [here](https://www.securesystems.de/blog/enhancing-subdomain-enumeration-ents-and-noerror/))
- Bruteforce ([puredns](https://github.com/d3mondev/puredns))
- Permutations ([Gotator](https://github.com/Josue87/gotator), [ripgen](https://github.com/resyncgg/ripgen) and [regulator](https://github.com/cramppet/regulator))
- JS files & Source Code Scraping ([katana](https://github.com/projectdiscovery/katana))
- DNS Records ([dnsx](https://github.com/projectdiscovery/dnsx))
- Google Analytics ID ([AnalyticsRelationships](https://github.com/Josue87/AnalyticsRelationships))
- TLS handshake ([tlsx](https://github.com/projectdiscovery/tlsx))
- Recursive search ([dsieve](https://github.com/trickest/dsieve)).
- Subdomains takeover ([nuclei](https://github.com/projectdiscovery/nuclei))
- DNS takeover ([dnstake](https://github.com/pwnesia/dnstake))
- DNS Zone Transfer ([dig](https://linux.die.net/man/1/dig))
- Cloud checkers ([S3Scanner](https://github.com/sa7mon/S3Scanner) and [cloud_enum](https://github.com/initstring/cloud_enum))

## Hosts

- IP info ([whoisxmlapi API](https://www.whoisxmlapi.com/))
- CDN checker ([ipcdn](https://github.com/six2dez/ipcdn))
- WAF checker ([wafw00f](https://github.com/EnableSecurity/wafw00f))
- Port Scanner (Active with [nmap](https://github.com/nmap/nmap) and passive with [smap](https://github.com/s0md3v/Smap))
- Port services vulnerability checks ([vulners](https://github.com/vulnersCom/nmap-vulners))
- Password spraying ([brutespray](https://github.com/x90skysn3k/brutespray))

## Webs

- Web Prober ([httpx](https://github.com/projectdiscovery/httpx))
- Web screenshoting ([webscreenshot](https://github.com/maaaaz/webscreenshot) or [gowitness](https://github.com/sensepost/gowitness))
- Web templates scanner ([nuclei](https://github.com/projectdiscovery/nuclei) and [nuclei geeknik](https://github.com/geeknik/the-nuclei-templates.git))
- CMS Scanner ([CMSeeK](https://github.com/Tuhinshubhra/CMSeeK))
- Url extraction ([gau](https://github.com/lc/gau),[waymore](https://github.com/xnl-h4ck3r/waymore), [katana](https://github.com/projectdiscovery/katana), [github-endpoints](https://gist.github.com/six2dez/d1d516b606557526e9a78d7dd49cacd3) and [JSA](https://github.com/w9w/JSA))
- URL patterns Search and filtering ([urless](https://github.com/xnl-h4ck3r/urless), [gf](https://github.com/tomnomnom/gf) and [gf-patterns](https://github.com/1ndianl33t/Gf-Patterns))
- Favicon Real IP ([fav-up](https://github.com/pielco11/fav-up))
- Javascript analysis ([subjs](https://github.com/lc/subjs), [JSA](https://github.com/w9w/JSA), [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder), [getjswords](https://github.com/m4ll0k/BBTz), [Mantra](https://github.com/MrEmpy/Mantra))
- Fuzzing ([ffuf](https://github.com/ffuf/ffuf))
- URL sorting by extension
- Wordlist generation
- Passwords dictionary creation ([pydictor](https://github.com/LandGrey/pydictor))

## Vulnerability checks

- XSS ([dalfox](https://github.com/hahwul/dalfox))
- Open redirect ([Oralyzer](https://github.com/r0075h3ll/Oralyzer))
- SSRF (headers [interactsh](https://github.com/projectdiscovery/interactsh) and param values with [ffuf](https://github.com/ffuf/ffuf))
- CRLF ([crlfuzz](https://github.com/dwisiswant0/crlfuzz))
- Cors ([Corsy](https://github.com/s0md3v/Corsy))
- LFI Checks ([ffuf](https://github.com/ffuf/ffuf))
- SQLi Check ([SQLMap](https://github.com/sqlmapproject/sqlmap) and [ghauri](https://github.com/r0oth3x49/ghauri))
- SSTI ([ffuf](https://github.com/ffuf/ffuf))
- SSL tests ([testssl](https://github.com/drwetter/testssl.sh))
- Broken Links Checker ([katana](https://github.com/projectdiscovery/katana))
- Prototype Pollution ([ppfuzz](https://github.com/dwisiswant0/ppfuzz))
- Web Cache Vulnerabilities ([Web-Cache-Vulnerability-Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner))
- 4XX Bypasser ([byp4xx](https://github.com/lobuhi/byp4xx))

## Extras

- Multithreading ([Interlace](https://github.com/codingo/Interlace))
- Custom resolvers generated list ([dnsvalidator](https://github.com/vortexau/dnsvalidator))
- Docker container included and [DockerHub](https://hub.docker.com/r/six2dez/reconftw) integration
- Ansible + Terraform deployment over AWS
- Allows IP/CIDR as target
- Resume the scan from last performed step
- Custom output folder option
- All in one installer/updater script compatible with most distros
- Diff support for continuous running (cron mode)
- Support for targets with multiple domains
- Raspberry Pi/ARM support
- 6 modes (recon, passive, subdomains, web, osint and all)
- Out of Scope Support + optional [inscope](https://github.com/tomnomnom/hacks/tree/master/inscope) support
- Notification system with Slack, Discord and Telegram ([notify](https://github.com/projectdiscovery/notify)) and sending zipped results support

## Mindmap/Workflow

![Mindmap](images/mindmap_obsidian.png)

## Data Keep

Follow these simple steps to end up with a private repository with your `API Keys` and `/Recon` data.

### Makefile

A `Makefile` is provided to quickly bootstrap a private repo. To use it, you'll need the [Github CLI](https://cli.github.com/) installed.

Once done, just run:

```bash
# below line is optional, the default is ~/reconftw-data
export PRIV_REPO="$HOME/reconftw-data"
make bootstrap
```

To sync your private repo with upstream:

```bash
make sync
```

To upload juicy recon data:

```bash
make upload
```

### Manual

- Create a private **blank** repository on `Git(Hub|Lab)` (Take into account size limits regarding Recon data upload)

- Clone your project: `git clone https://gitlab.com/example/reconftw-data`
- Get inside the cloned repository: `cd reconftw-data`
- Create a new branch with an empty commit: `git commit --allow-empty -m "Empty commit"`
- Add the official repo as a new remote: `git remote add upstream https://github.com/six2dez/reconftw` (`upstream` is an example)
- Update upstream's repo: `git fetch upstream`
- Rebase current branch with the official one: `git rebase upstream/main master`

### Main commands

- Upload changes to your personal repo: `git add . && git commit -m "Data upload" && git push origin master`
- Update tool anytime: `git fetch upstream && git rebase upstream/main master`

## How to contribute

If you want to contribute to this project, you can do it in multiple ways:

- Submitting an [issue](https://github.com/six2dez/reconftw/issues/new/choose) if you have found a bug or you have any suggestion or request.
- Making a Pull Request from [dev](https://github.com/six2dez/reconftw/tree/dev) branch if you want to improve the code or add something to the script.

## Need help? :information_source:

- Take a look at the [wiki](https://github.com/six2dez/reconftw/wiki) section.
- Check [FAQ](https://github.com/six2dez/reconftw/wiki/7.-FAQs) for commonly asked questions.
- Join our [Discord server](https://discord.gg/R5DdXVEdTy)
- Ask for help in the [Telegram group](https://t.me/joinchat/TO_R8NYFhhbmI5co)

## Support this project

### Buymeacoffee

[<img src="https://cdn.buymeacoffee.com/buttons/v2/default-green.png">](https://www.buymeacoffee.com/six2dez)

### DigitalOcean referral link

<a href="https://www.digitalocean.com/?refcode=f362a6e193a1&utm_campaign=Referral_Invite&utm_medium=Referral_Program&utm_source=badge"><img src="https://web-platforms.sfo2.cdn.digitaloceanspaces.com/WWW/Badge%201.svg" alt="DigitalOcean Referral Badge" /></a>

### GitHub sponsorship

[Sponsor](https://github.com/sponsors/six2dez)

## Thanks :pray:

- Thank you for contributing to the project's development!

- [C99](https://api.c99.nl/)
- [CIRCL](https://www.circl.lu/)
- [NetworksDB](https://networksdb.io/)
- [ipinfo](https://ipinfo.io/)
- [hackertarget](https://hackertarget.com/)
- [Censys](https://censys.io/)
- [Fofa](https://fofa.info/)
- [intelx](https://intelx.io/)
- [Whoxy](https://www.whoxy.com/)

## Disclaimer

Usage of this program for attacking targets without consent is illegal. It is the user's responsibility to obey all applicable laws. The developer assumes no liability and is not responsible for any misuse or damage caused by this program. Please use responsibly.

The material contained in this repository is licensed under MIT.
