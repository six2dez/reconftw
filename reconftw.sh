#!/bin/bash

bred='\033[1;31m'
bgreen='\033[1;32m'
yellow='\033[0;33m'
red='\033[0;31m'
green='\033[0;32m'
reset='\033[0m'

tools=~/Tools

banner(){
	printf "\n${bgreen}"
	printf "  ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █   █████▒▄▄▄█████▓ █     █░\n"
	printf " ▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▓██   ▒ ▓  ██▒ ▓▒▓█░ █ ░█░\n"
	printf " ▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒▒████ ░ ▒ ▓██░ ▒░▒█░ █ ░█ \n"
	printf " ▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒░▓█▒  ░ ░ ▓██▓ ░ ░█░ █ ░█ \n"
	printf " ░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░░▒█░      ▒██▒ ░ ░░██▒██▓ \n"
	printf " ░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒  ▒ ░      ▒ ░░   ░ ▓░▒ ▒  \n"
	printf "   ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░ ░          ░      ▒ ░ ░  \n"
	printf "   ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░  ░ ░      ░        ░   ░  \n"
	printf "    ░        ░  ░░ ░          ░ ░           ░                      ░    \n"
	printf "                 ░                                                      \n"
	printf "			                        by @six2dez1(Twitter)${reset}\n"
}

start(){
	tools_installed
	dir=$PWD/Recon/$domain
	mkdir -p $dir
	if [ -n "$list" ]
	then
		cp $list $dir/${domain}_probed.txt
	fi
	cd $dir
	printf "\n"
	nuclei -update-templates &>/dev/null
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Target: ${domain}\n\n"
}

function tools_installed(){

	printf "\n\n${bgreen}#######################################################################\n"
	printf "${bred} Pre-Step : ${bgreen} Checking installed tools ${reset}\n\n"

	[ -f $tools/degoogle_hunter/degoogle.py ] && printf "${bgreen}[*] degoogle		[YES]\n" || printf "${bred}[*] degoogle		[NO]\n"
	[ -f $tools/ParamSpider/paramspider.py ] && printf "${bgreen}[*] Paramspider		[YES]\n" || printf "${bred}[*] Paramspider		[NO]\n"
	[ -f $tools/Arjun/arjun.py ] && printf "${bgreen}[*] Arjun		[YES]\n" || printf "${bred}[*] Arjun		[NO]\n"
	[ -f $tools/fav-up/favUp.py ] && printf "${bgreen}[*] fav-up		[YES]\n" || printf "${bred}[*] fav-up		[NO]\n"
	[ -f $tools/Corsy/corsy.py ] && printf "${bgreen}[*] Corsy		[YES]\n" || printf "${bred}[*] Corsy		[NO]\n"
	[ -f $tools/testssl.sh/testssl.sh ] && printf "${bgreen}[*] testssl		[YES]\n" || printf "${bred}[*] testssl		[NO]\n"
	[ -f $tools/SubDomainizer/SubDomainizer.py ] && printf "${bgreen}[*] SubDomainizer	[YES]\n" || printf "${bred}[*] SubDomainizer	[NO]\n"
	[ -f $tools/SecretFinder/SecretFinder.py ] && printf "${bgreen}[*] SecretFinder	[YES]\n" || printf "${bred}[*] SecretFinder	[NO]\n"
	[ -f $tools/OneListForAll/onelistforallmicro.txt ] && printf "${bgreen}[*] OneListForAll	[YES]\n" || printf "${bred}[*] OneListForAll	[NO]\n"
	[ -f $tools/LinkFinder/linkfinder.py ] && printf "${bgreen}[*] LinkFinder	        [YES]\n" || printf "${bred}[*] LinkFinder	        [NO]\n"
	[ -f $tools/github-endpoints.py ] && printf "${bgreen}[*] github-endpoints.py	[YES]\n" || printf "${bred}[*] github-endpoints.py	[NO]\n"
	[ -f $tools/github-search/github-endpoints.py ] && printf "${bgreen}[*] github-search	[YES]\n" || printf "${bred}[*] github-search	[NO]\n"
	[ -f $tools/getjswords.py ] && printf "${bgreen}[*] getjswords.py	[YES]\n" || printf "${bred}[*] getjswords.py	[NO]\n"
	[ -f $tools/subdomains.txt ] && printf "${bgreen}[*] subdomains.txt	[YES]\n" || printf "${bred}[*] subdomains.txt	[NO]\n"
	[ -f $tools/resolvers.txt ] && printf "${bgreen}[*] resolvers.txt	[YES]\n" || printf "${bred}[*] resolvers.txt	[NO]\n"
	type -P hakrawler &>/dev/null && printf "${bgreen}[*] hakrawler		[YES]\n" || { printf "${bred}[*] hakrawler		[NO]\n"; }
	type -P subfinder &>/dev/null && printf "${bgreen}[*] Subfinder		[YES]\n" || { printf "${bred}[*] Subfinder		[NO]\n"; }
	type -P assetfinder &>/dev/null && printf "${bgreen}[*] Assetfinder		[YES]\n" || { printf "${bred}[*] Assetfinder		[NO]\n"; }
	type -P findomain &>/dev/null && printf "${bgreen}[*] Findomain		[YES]\n" || { printf "${bred}[*] Findomain		[NO]\n"; }
	type -P amass &>/dev/null && printf "${bgreen}[*] Amass		[YES]\n" || { printf "${bred}[*] Amass		[NO]\n"; }
	type -P crobat &>/dev/null && printf "${bgreen}[*] Crobat		[YES]\n" || { printf "${bred}[*] Crobat		[NO]\n"; }
	type -P waybackurls &>/dev/null && printf "${bgreen}[*] Waybackurls		[YES]\n" || { printf "${bred}[*] Waybackurls		[NO]\n"; }
	type -P gau &>/dev/null && printf "${bgreen}[*] Gau		        [YES]\n" || { printf "${bred}[*] Gau		[NO]\n"; }
	type -P shuffledns &>/dev/null && printf "${bgreen}[*] ShuffleDns		[YES]\n" || { printf "${bred}[*] ShuffleDns		[NO]\n"; }
	type -P subjack &>/dev/null && printf "${bgreen}[*] Subjack		[YES]\n" || { printf "${bred}[*] Subjack		[NO]\n"; }
	[ -f $tools/subjack/fingerprints.json ] && printf "${bgreen}[*] Subjack fingerprints[YES]\n" || printf "${bred}[*] Subjack fingerprints[NO]\n"
	type -P nuclei &>/dev/null && printf "${bgreen}[*] Nuclei		[YES]\n" || { printf "${bred}[*] Nuclei		[NO]\n"; }
	[ -d ~/nuclei-templates ] && printf "${bgreen}[*] Nuclei templates    [YES]\n" || printf "${bred}[*] Nuclei templates    [NO]\n"
	type -P aquatone &>/dev/null && printf "${bgreen}[*] Aquatone		[YES]\n" || { printf "${bred}[*] Aquatone		[NO]\n"; }
	type -P naabu &>/dev/null && printf "${bgreen}[*] Naabu		[YES]\n" || { printf "${bred}[*] Naabu		[NO]\n"; }
	type -P gf &>/dev/null && printf "${bgreen}[*] Gf		        [YES]\n" || { printf "${bred}[*] Gf		[NO]\n"; }
	type -P Gxss &>/dev/null && printf "${bgreen}[*] Gxss		[YES]\n" || { printf "${bred}[*] Gxss		[NO]\n"; }
	type -P subjs &>/dev/null && printf "${bgreen}[*] subjs		[YES]\n" || { printf "${bred}[*] subjs		[NO]\n"; }
	type -P dalfox &>/dev/null && printf "${bgreen}[*] dalfox		[YES]\n" || { printf "${bred}[*] dalfox		[NO]\n"; }
	type -P git-hound &>/dev/null && printf "${bgreen}[*] git-hound		[YES]\n" || { printf "${bred}[*] git-hound		[NO]\n"; }
	type -P ffuf &>/dev/null && printf "${bgreen}[*] ffuf		[YES]\n" || { printf "${bred}[*] ffuf		[NO]\n"; }
	type -P massdns &>/dev/null && printf "${bgreen}[*] Massdns		[YES]\n" || { printf "${bred}[*] Massdns		[NO]\n"; }
	type -P interlace &>/dev/null && printf "${bgreen}[*] interlace		[YES]\n" || { printf "${bred}[*] interlace		[NO]\n"; }
	type -P dnsgen &>/dev/null && printf "${bgreen}[*] DnsGen		[YES]\n" || { printf "${bred}[*] DnsGen		[NO]\n"; }
	type -P anew &>/dev/null && printf "${bgreen}[*] Anew		[YES]\n" || { printf "${bred}[*] Anew		[NO]\n"; }
	type -P unfurl &>/dev/null && printf "${bgreen}[*] unfurl		[YES]\n" || { printf "${bred}[*] unfurl		[NO]\n"; }
	type -P httpx &>/dev/null && printf "${bgreen}[*] Httpx		[YES]\n${reset}" || { printf "${bred}[*] Httpx		[NO]\n${reset}"; }

	printf "\n${yellow} If any tool is not installed under $tools, I trust in your ability to install it :D\n Also remember to set the ${bred}\$tools${yellow} variable on line 10 of this script.\n If you have any problem you can always ping me ;) ${reset}\n\n"
	printf "${bred} Tools check finished\n"
	printf "${bgreen}#######################################################################\n"
}

dorks(){
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 1/17 : ${bgreen} Performing Google Dorks ${reset}\n\n"
	printf "${yellow} This will take a long, meanwhile check this dorks: ${reset}\n\n"

	hostname=$domain
	target=${hostname%%.*}

	declare -A dorks

	dorks["# Other 3rd parties sites (https://www.google.com/search?q=site%3Agitter.im%20%7C%20site%3Apapaly.com%20%7C%20site%3Aproductforums.google.com%20%7C%20site%3Acoggle.it%20%7C%20site%3Areplt.it%20%7C%20site%3Aycombinator.com%20%7C%20site%3Alibraries.io%20%7C%20site%3Anpm.runkit.com%20%7C%20site%3Anpmjs.com%20%7C%20site%3Ascribd.com%20%22$target%22)"]="site:gitter.im | site:papaly.com | site:productforums.google.com | site:coggle.it | site:replt.it | site:ycombinator.com | site:libraries.io | site:npm.runkit.com | site:npmjs.com | site:scribd.com \"$target\""
	dorks["# Code share sites (https://www.google.com/search?q=site%3Asharecode.io%20%7C%20site%3Acontrolc.com%20%7C%20site%3Acodepad.co%20%7Csite%3Aideone.com%20%7C%20site%3Acodebeautify.org%20%7C%20site%3Ajsdelivr.com%20%7C%20site%3Acodeshare.io%20%7C%20site%3Acodepen.io%20%7C%20site%3Arepl.it%20%7C%20site%3Ajsfiddle.net%20%22$target%22)"]="site:sharecode.io | site:controlc.com | site:codepad.co |site:ideone.com | site:codebeautify.org | site:jsdelivr.com | site:codeshare.io | site:codepen.io | site:repl.it | site:jsfiddle.net \"$target\""
	dorks["# GitLab/GitHub/Bitbucket (https://www.google.com/search?q=site%3Agithub.com%20%7C%20site%3Agitlab.com%20%7C%20site%3Abitbucket.org%20%22$target%22)"]="site:github.com | site:gitlab.com | site:bitbucket.org \"$target\""
	dorks["# Stackoverflow (https://www.google.com/search?q=site%3Astackoverflow.com%20%22$domain%22)"]="site:stackoverflow.com \"$domain\""
	dorks["# Project management sites (https://www.google.com/search?q=site%3Atrello.com%20%7C%20site%3A*.atlassian.net%20%22$target%22)"]="site:trello.com | site:*.atlassian.net \"$target\""
	dorks["# Pastebin-like sites (https://www.google.com/search?q=site%3Ajustpaste.it%20%7C%20site%3Aheypasteit.com%20%7C%20site%3Apastebin.com%20%22$target%22)"]="site:justpaste.it | site:heypasteit.com | site:pastebin.com \"$target\""
	dorks["# Config files (https://www.google.com/search?q=site%3A$domain%20ext%3Axml%20%7C%20ext%3Aconf%20%7C%20ext%3Acnf%20%7C%20ext%3Areg%20%7C%20ext%3Ainf%20%7C%20ext%3Ardp%20%7C%20ext%3Acfg%20%7C%20ext%3Atxt%20%7C%20ext%3Aora%20%7C%20ext%3Aenv%20%7C%20ext%3Aini)"]="site:$domain ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:env | ext:ini"
	dorks["# Database files (https://www.google.com/search?q=site%3A$domain%20ext%3Asql%20%7C%20ext%3Adbf%20%7C%20ext%3Amdb)"]="site:$domain ext:sql | ext:dbf | ext:mdb"
	dorks["# Backup files (https://www.google.com/search?q=site%3A$domain%20ext%3Abkf%20%7C%20ext%3Abkp%20%7C%20ext%3Abak%20%7C%20ext%3Aold%20%7C%20ext%3Abackup)"]="site:$domain ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"
	dorks["# .git folder (https://www.google.com/search?q=inurl%3A%5C%22%2F.git%5C%22%20$domain%20-github)"]="inurl:\"/.git\" $domain -github"
	dorks["# Exposed documents (https://www.google.com/search?q=site%3A$domain%20ext%3Adoc%20%7C%20ext%3Adocx%20%7C%20ext%3Aodt%20%7C%20ext%3Apdf%20%7C%20ext%3Artf%20%7C%20ext%3Asxw%20%7C%20ext%3Apsw%20%7C%20ext%3Appt%20%7C%20ext%3Apptx%20%7C%20ext%3Apps%20%7C%20ext%3Acsv)"]="site:$domain ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"
	dorks["# Other files (https://www.google.com/search?q=site%3A$domain%20intitle%3Aindex.of%20%7C%20ext%3Alog%20%7C%20ext%3Aphp%20intitle%3Aphpinfo%20%5C%22published%20by%20the%20PHP%20Group%5C%22%20%7C%20inurl%3Ashell%20%7C%20inurl%3Abackdoor%20%7C%20inurl%3Awso%20%7C%20inurl%3Acmd%20%7C%20shadow%20%7C%20passwd%20%7C%20boot.ini%20%7C%20inurl%3Abackdoor%20%7C%20inurl%3Areadme%20%7C%20inurl%3Alicense%20%7C%20inurl%3Ainstall%20%7C%20inurl%3Asetup%20%7C%20inurl%3Aconfig%20%7C%20inurl%3A%5C%22%2Fphpinfo.php%5C%22%20%7C%20inurl%3A%5C%22.htaccess%5C%22%20%7C%20ext%3Aswf)"]="site:$domain intitle:index.of | ext:log | ext:php intitle:phpinfo \"published by the PHP Group\" | inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor | inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config | inurl:\"/phpinfo.php\" | inurl:\".htaccess\" | ext:swf"
	dorks["# SQL errors (https://www.google.com/search?q=site%3A$domain%20intext%3A%5C%22sql%20syntax%20near%5C%22%20%7C%20intext%3A%5C%22syntax%20error%20has%20occurred%5C%22%20%7C%20intext%3A%5C%22incorrect%20syntax%20near%5C%22%20%7C%20intext%3A%5C%22unexpected%20end%20of%20SQL%20command%5C%22%20%7C%20intext%3A%5C%22Warning%3A%20mysql_connect()%5C%22%20%7C%20intext%3A%5C%22Warning%3A%20mysql_query()%5C%22%20%7C%20intext%3A%5C%22Warning%3A%20pg_connect()%5C%22)"]="site:$domain intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: mysql_query()\" | intext:\"Warning: pg_connect()\""
	dorks["# PHP errors (https://www.google.com/search?q=site%3A$domain%20%5C%22PHP%20Parse%20error%5C%22%20%7C%20%5C%22PHP%20Warning%5C%22%20%7C%20%5C%22PHP%20Error%5C%22)"]="site:$domain \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\""
	dorks["# Login pages (https://www.google.com/search?q=site%3A$domain%20inurl%3Asignup%20%7C%20inurl%3Aregister%20%7C%20intitle%3ASignup)"]="site:$domain inurl:signup | inurl:register | intitle:Signup"
	dorks["# Open redirects (https://www.google.com/search?q=site%3A$domain%20inurl%3Aredir%20%7C%20inurl%3Aurl%20%7C%20inurl%3Aredirect%20%7C%20inurl%3Areturn%20%7C%20inurl%3Asrc%3Dhttp%20%7C%20inurl%3Ar%3Dhttp)"]="site:$domain inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http"
	dorks["# Apache Struts RCE (https://www.google.com/search?q=site%3A$domain%20ext%3Aaction%20%7C%20ext%3Astruts%20%7C%20ext%3Ado)"]="site:$domain ext:action | ext:struts | ext:do"
	dorks["# Linkedin employees (https://www.google.com/search?q=site%3Alinkedin.com%20employees%20$domain)"]="site:linkedin.com employees $domain"
	dorks["# Wordpress files (https://www.google.com/search?q=site%3A$domain%20inurl%3Awp-content%20%7C%20inurl%3Awp-includes)"]="site:$domain inurl:wp-content | inurl:wp-includes"
	dorks["# Subdomains (https://www.google.com/search?q=site%3A*.$domain)"]="site:*.$domain"
	dorks["# Sub-subdomains (https://www.google.com/search?q=site%3A*.*.$domain)"]="site:*.*.$domain"
	dorks["# Cloud buckets S3/GCP (https://www.google.com/search?q=site%3A.s3.amazonaws.com%20%7C%20site%3Astorage.googleapis.com%20%7C%20site%3Aamazonaws.com%20%22$target%22)"]="site:.s3.amazonaws.com | site:storage.googleapis.com | site:amazonaws.com \"$target\""
	dorks["# Traefik (https://www.google.com/search?q=intitle%3Atraefik%20inurl%3A8080%2Fdashboard%20%22$target%22)"]="intitle:traefik inurl:8080/dashboard \"$target\""
	dorks["# Jenkins (https://www.google.com/search?q=intitle%3A%5C%22Dashboard%20%5BJenkins%5D%5C%22%20%22$target%22)"]="intitle:\"Dashboard [Jenkins]\" \"$target\""

	for c in "${!dorks[@]}"; do
		printf "\n\e[32m"%s"\e[0m\n" "$c" && python3 $tools/degoogle_hunter/degoogle.py -j "${dorks[$c]}"
	done
	printf "${bred} Finished : ${bgreen} Happy hunting! ${reset}\n"
	printf "${bgreen}#######################################################################\n"
}

subdomains(){
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 2/17 : Subdomain Enumeration\n\n"
	# Passive scan
	printf "${yellow} Running : Passive Subdomain Enumeration 1/6${reset}\n"
	subfinder -d $domain -o subfinder.txt &>/dev/null
	assetfinder --subs-only $domain | anew -q assetfinder.txt
	amass enum -passive -d $domain -o amass.txt &>/dev/null
	findomain --quiet -t $domain -u findomain.txt &>/dev/null
	crobat -s $domain | anew -q crobat.txt &>/dev/null
	timeout 5m waybackurls $domain | unfurl -u domains | anew -q waybackurls.txt &>/dev/null
	cat subfinder.txt assetfinder.txt amass.txt findomain.txt crobat.txt waybackurls.txt 2>/dev/null | sed "s/*.//" | anew -q passive.txt
	rm subfinder.txt assetfinder.txt amass.txt findomain.txt crobat.txt waybackurls.txt 2>/dev/null
	NUMOFLINES=$(wc -l < passive.txt)
	printf "${green} Passive subdomains found: ${NUMOFLINES}${reset}\n\n"

	# Bruteforce
	printf "${yellow} Running : Bruteforce Subdomain Enumeration 2/6${reset}\n"
	shuffledns -d $domain -w $tools/subdomains.txt -r $tools/resolvers.txt -o active_tmp.txt &>/dev/null
	cat active_tmp.txt | sed "s/*.//" | anew -q active.txt
	rm active_tmp.txt 2>/dev/null
	NUMOFLINES=$(wc -l < active.txt)
	printf "${green} Bruteforce subdomains found: ${NUMOFLINES}${reset}\n\n"

	# Active
	printf "${yellow} Running : Active Subdomain Enumeration 3/6${reset}\n"
	cat active.txt passive.txt > active_passive_tmp.txt
	shuffledns -d $domain -list active_passive_tmp.txt -r $tools/resolvers.txt -o active_passive.txt &>/dev/null
	rm active.txt passive.txt active_passive_tmp.txt 2>/dev/null
	NUMOFLINES=$(wc -l < active_passive.txt)
	printf "${green} Active subdomains found: ${NUMOFLINES}${reset}\n\n"

	# Permutations
	printf "${yellow} Running : Permutations Subdomain Enumeration 4/6${reset}\n"
	if [[ $(cat active_passive.txt | wc -l) -le 50 ]]
		then
			dnsgen active_passive.txt --wordlist $tools/permutations_list.txt 2>/dev/null | shuffledns -d $domain -r $tools/resolvers.txt -o permute1_tmp.txt 2>/dev/null
			cat permute1_tmp.txt | anew -q permute1.txt
			dnsgen permute1.txt --wordlist $tools/permutations_list.txt 2>/dev/null | shuffledns -d $domain -r $tools/resolvers.txt -o permute2_tmp.txt 2>/dev/null
			cat permute2_tmp.txt | anew -q permute2.txt
			cat permute1.txt permute2.txt | anew -q permute.txt
			rm permute1.txt permute1_tmp.txt permute2.txt permute2_tmp.txt 2>/dev/null
		elif [[ $(cat active_passive.txt | wc -l) -le 100 ]]
		then
			dnsgen active_passive.txt --wordlist $tools/permutations_list.txt 2>/dev/null | shuffledns -d $domain -r $tools/resolvers.txt -o permute_tmp.txt 2>/dev/null
			cat permute_tmp.txt | anew -q permute.txt
			rm permute_tmp.txt 2>/dev/null
	fi
	NUMOFLINES=$(wc -l < permute.txt)
	printf "${green} Permutation subdomains found: ${NUMOFLINES}${reset}\n\n"

	# SubDomainizer
	printf "${yellow} Running : SubDomainizer 5/6${reset}\n"
	domain_probed=$(echo $domain | httpx -threads 100 -silent)
	python3 $tools/SubDomainizer/SubDomainizer.py -u $domain_probed -o SubDomainizer_subdomains.txt -k &>/dev/null
	NUMOFLINES=$(wc -l < SubDomainizer_subdomains.txt)
	printf "${green} SubDomainizer: ${NUMOFLINES}${reset}\n\n"

	# Final subdomains
	printf "${yellow} Running : Final DNS Resolution 6/6${reset}\n"
	cat active_passive.txt permute.txt SubDomainizer_subdomains.txt > final_subdomains.txt 2>/dev/null
	shuffledns -d $domain -list final_subdomains.txt -r $tools/resolvers.txt -o ${domain}_subdomains.txt &>/dev/null
	rm active_passive.txt permute.txt SubDomainizer_subdomains.txt final_subdomains.txt 2>/dev/null
	NUMOFLINES=$(wc -l < ${domain}_subdomains.txt)
	printf "${bgreen} Total active subdomains found: ${NUMOFLINES}${reset}\n\n"

	cat ${domain}_subdomains.txt 2>/dev/null
	printf "${bred}\n Finished : Results are saved in ${domain}_subdomains.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n\n"
	# Finished Subdomain Enumeration
}

subtakeover(){
	# Performing Subdomain Takeover
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 3/17 : ${bgreen} Subdomain Takeover ${reset}\n\n"
	subjack -w ${domain}_subdomains.txt -a -ssl -t 50 -v -c $tools/subjack/fingerprints.json -ssl -o ${domain}_all-takeover-checks.txt &>/dev/null;
	grep -v "Not Vulnerable" <${domain}_all-takeover-checks.txt > ${domain}_subjack.txt
	rm ${domain}_all-takeover-checks.txt
	cat ${domain}_subdomains.txt | nuclei -silent -l ${domain}_subdomains.txt -t ~/nuclei-templates/takeovers/ -o ${domain}_nuclei_subtko.txt;
	cat ${domain}_nuclei_subtko.txt ${domain}_subjack.txt | anew -q ${domain}_takeover.txt 2>/dev/null
	cat ${domain}_takeover.txt 2>/dev/null
	rm ${domain}_nuclei_subtko.txt ${domain}_subjack.txt 2>/dev/null
	printf "${bred}\n Finished : ${bgreen} Results are saved in ${domain}_takeover.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n\n"
	# Finished Subdomain Takeover
}

webprobe(){
	# Performing Probing
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 4/17 : ${bgreen} Probing ${reset}\n\n"
	printf "${yellow} Running : Http probing${reset}\n\n"
	cat ${domain}_subdomains.txt | httpx -follow-redirects -status-code -vhost -threads 100 -silent | sort -u | grep "[200]" | cut -d [ -f1 | sort -u | sed 's/[[:blank:]]*$//' > ${domain}_probed.txt
	printf "${yellow} Running : Http probing non standard ports${reset}\n\n"
	cat ${domain}_subdomains.txt | httpx -ports 81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55672 -follow-redirects -status-code -vhost -threads 100 -silent | sort -u | grep "[200]" | cut -d [ -f1 | sort -u | sed 's/[[:blank:]]*$//' > ${domain}_probed_uncommon_ports.txt
	cat ${domain}_probed.txt 2>/dev/null
	printf "\n"
	cat ${domain}_probed_uncommon_ports.txt 2>/dev/null
	printf "${bred}\n Finished : ${bgreen} Results are saved in ${domain}_probed_uncommon_ports.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished Probing

	# Performing webscreenshot
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 5/17 : ${bgreen} Web Screenshot ${reset}\n\n"
	cat ${domain}_probed.txt | aquatone -out screenshots -threads 16 -silent
	printf "${bred}\n Finished : ${bgreen} Check results in screenshots/aquatone_report.html folder ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished webscreenshot
}

portscan(){
	# Performing Port Scanning with Naabu
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 6/17 : ${bgreen} Port Scanning with Naabu ${reset}\n\n"
	naabu -top-ports 1000 -silent -exclude-cdn -nmap-cli 'nmap -sV --script /usr/share/nmap/scripts/vulners.nse,http-title.nse --min-rate 40000 -T4 --max-retries 2' -iL ${domain}_subdomains.txt > ${domain}_portscan.txt;
	cat ${domain}_portscan.txt 2>/dev/null
	printf "\n\n"
	printf "${bred} Finished : ${bgreen} Results are saved in ${domain}_portscan.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished Port Scanning with Naabu
}

nuclei_check(){
	# Performing Template Scanning with Nuclei
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 7/17 : ${bgreen} Template Scanning with Nuclei ${reset}\n\n"
	printf "${yellow} Running : Nuclei Technologies${reset}\n\n"
	cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/technologies/ -o ${domain}_nuclei_technologies.txt;
	printf "${yellow}\n\n Running : Nuclei Tokens${reset}\n\n"
	cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/exposed-tokens/ -o ${domain}_nuclei_tokens.txt;
	printf "${yellow}\n\n Running : Nuclei Exposures${reset}\n\n"
	cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/exposures/ -o ${domain}_nuclei_exposures.txt;
	printf "${yellow}\n\n Running : Nuclei CVEs ${reset}\n\n"
	cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/cves/ -o ${domain}_nuclei_cves.txt;
	printf "${yellow}\n\n Running : Nuclei Default Creds ${reset}\n\n"
	cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/default-logins/ -o ${domain}_nuclei_default_creds.txt;
	printf "${yellow}\n\n Running : Nuclei DNS ${reset}\n\n"
	cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/dns/ -o ${domain}_nuclei_dns.txt;
	printf "${yellow}\n\n Running : Nuclei Panels ${reset}\n\n"
	cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/exposed-panels/ -o ${domain}_nuclei_panels.txt;
	printf "${yellow}\n\n Running : Nuclei Security Misconfiguration ${reset}\n\n"
	cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/misconfiguration/ -o ${domain}_nuclei_misconfigurations.txt;
	printf "${yellow}\n\n Running : Nuclei Generic detections ${reset}\n\n"
	cat ${domain}_probed.txt | nuclei -silent -t ~/nuclei-templates/vulnerabilities/ -o ${domain}_nuclei_vulnerabilities.txt;
	printf "\n\n"
	printf "${bred} Finished : ${bgreen} Results are saved in ${domain}_nuclei_*.txt files ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished Template Scanning with Nuclei
}

urlcheks(){
	# Performing URL Extraction
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 8/17 : ${bgreen} URL Extraction ${reset}\n\n"
	waybackurls $domain > ${domain}_url_extract.txt
	gau $domain | anew -q ${domain}_url_extract.txt
	hakrawler -url $domain -depth 2 -scope subs -plain -insecure | anew -q ${domain}_url_extract.txt
	if [ -n "$GITHUB_TOKEN" ]; then
		python3 $tools/github-endpoints.py -d $domain -t $GITHUB_TOKEN | anew -q ${domain}_url_extract.txt
	else
		python3 $tools/github-endpoints.py -d $domain | anew -q ${domain}_url_extract.txt
	fi
	printf "${bred} Finished : ${bgreen} Results are saved in ${domain}_url_extract.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished URL Extraction

	# Performing Vulnerable Pattern Search
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 9/17 : ${bgreen} Vulnerable Pattern Search ${reset}\n\n"
	gf xss ${domain}_url_extract.txt | anew -q ${domain}_xss.txt;
	gf ssti ${domain}_url_extract.txt | anew -q ${domain}_ssti.txt;
	gf ssrf ${domain}_url_extract.txt | anew -q ${domain}_ssrf.txt;
	gf sqli ${domain}_url_extract.txt | anew -q ${domain}_sqli.txt;
	gf redirect ${domain}_url_extract.txt | anew -q ${domain}_redirect.txt;
	gf rce ${domain}_url_extract.txt | anew -q ${domain}_rce.txt;
	gf potential ${domain}_url_extract.txt | anew -q ${domain}_potential.txt;
	gf lfi ${domain}_url_extract.txt | anew -q ${domain}_lfi.txt;
	cat ${domain}_url_extract.txt | unfurl -u format %s://%d%p > ${domain}_url_endpoints.txt
	printf "${bred} Finished : ${bgreen} Results are saved in ${domain}_*gfpattern*.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished Vulnerable Pattern Search
}

jschecks(){
	# Performing Javascript Scan
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 10/17 : ${bgreen} Javascript Scan ${reset}\n\n"
	printf "${yellow} Running : Fetching Urls${reset}\n"
	# Gather JSFilesUrls
	cat ${domain}_url_extract.txt | grep -iE "\.js$" | anew -q ${domain}_jsfile_links.txt;
	cat ${domain}_url_extract.txt | subjs >> ${domain}_jsfile_links.txt;
	#Open JSUrlFiles
	cat ${domain}_jsfile_links.txt | httpx -follow-redirects -silent -status-code | grep "[200]" | cut -d ' ' -f1 | anew -q ${domain}_js_livelinks.txt;
	#Gather Endpoints From JsFiles
	interlace -tL ${domain}_js_livelinks.txt -threads 5 -c "python3 $tools/LinkFinder/linkfinder.py -d -i _target_ -o cli >> ${domain}_js_endpoints.txt" &>/dev/null
	#Gather Secrets From Js Files
	interlace -tL ${domain}_js_livelinks.txt -threads 5 -c "python3 $tools/SecretFinder/SecretFinder.py -i _target_ -o cli >> ${domain}_js_linksecret.txt" &>/dev/null
	#Gather JSFilesWordlist
	cat ${domain}_js_livelinks.txt | python3 $tools/getjswords.py | anew -q ${domain}_js_Wordlist.txt;
	# Finished Javascript Scan
	printf "${bred} Finished : ${bgreen} Results are saved in ${domain}_js_*.txt files ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished Secret Finder
}

params(){
	# Performing Parameter Discovery
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 11/17 : ${bgreen} Parameter Discovery ${reset}\n"
	printf "${yellow}\n\n Running : Finding params with paramspider${reset}\n"
	interlace -tL ${domain}_probed.txt -threads 5 -c "python3 $tools/ParamSpider/paramspider.py -d _target_ -l high -q --exclude jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,js &>/dev/null" &>/dev/null
	find output/ -name '*.txt' -exec cat {} \; | anew -q ${domain}_param.txt
	sed '/^FUZZ/d' -i ${domain}_param.txt
	rm -rf output/
	printf "${yellow}\n\n Running : Checking ${domain} with Arjun${reset}\n"
	python3 $tools/Arjun/arjun.py -i ${domain}_param.txt -t 20 -o ${domain}_arjun.json &>/dev/null
	printf "${bred} Finished : ${bgreen} Results are saved in ${domain}_param.txt and ${domain}_arjun.json under ${dir} ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished Parameter Discovery
}

xss(){
	# Performing XSS Automation
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 12/17 : ${bgreen} XSS Automation ${reset}\n\n"
	# Set your own blind xss server, I will not advice you if I receive some data in my server :P
	cat ${domain}_xss.txt | Gxss -c 100 -p Xss | sort -u | dalfox -b six2dez.xss.ht pipe -o ${domain}_dalfox_xss.txt &>/dev/null
	printf "${bred} Finished : ${bgreen} Results are saved in ${domain}_dalfox_xss.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished XSS Automation
}

github(){
	# Performing GitHub Scanning
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 13/17 : ${bgreen} GitHub Scanning ${reset}\n\n"
	cat ${domain}_probed.txt | git-hound --dig-files --dig-commits --threads 100 | tee ${domain}_gitrecon.txt
	printf "${bred} Finished : ${bgreen} Results are saved in ${domain}_gitrecon.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished GitHub Scanning
}

favicon(){
	# Performing FavIcon Hash Extraction
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 14/17 : ${bgreen} Performing FavIcon Hash Extraction ${reset}\n\n"
	cd $tools/fav-up && python3 favUp.py -w $domain -sc > ${dir}/${domain}_favicontest.txt && cd ${dir} && cat ${domain}_favicontest.txt | grep found_ips
	printf "${bred} Finished : ${bgreen} Results are saved in ${dir}/${domain}_favicontest.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished FavIcon Hash Extraction
}

fuzz(){
	# Performing Directory Fuzzing
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 15/17 : ${bgreen} Performing Directory Fuzzing ${reset}\n"
	printf "${yellow}\n\n Running : Running ffuf in every subdomain with onelistforallmicro.txt${reset}\n"
	mkdir -p $dir/fuzzing
	for sub in $(cat ${domain}_probed.txt); do
		printf "${yellow}\n\n Running : Running ffuf in ${sub} with onelistforallmicro.txt${reset}\n"
		sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
		ffuf -mc all -ac -w $tools/OneListForAll/onelistforallmicro.txt -maxtime 900 -u $sub/FUZZ -or -of md -o $dir/fuzzing/${sub_out}.md &>/dev/null
	done
	printf "${bred} Finished : ${bgreen} Results are saved in *subdomain*_ffuf.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished Directory Fuzzing
}

cors(){
	# Performing CORS Scan
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 16/17 : ${bgreen} Performing CORS Scan ${reset}\n\n"
	python3 $tools/Corsy/corsy.py -i ${domain}_probed.txt -t 200 > ${domain}_cors.txt &>/dev/null
	cat ${domain}_cors.txt 2>/dev/null
	printf "${bred} Finished : ${bgreen} Results are saved in ${domain}_cors.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished CORS Scan
}

testssl(){
	# Performing testssl Scan
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Step 17/17 : ${bgreen} Performing SSL test ${reset}\n"
	$tools/testssl.sh/testssl.sh --quiet -U -iL ${domain}_subdomains.txt > ${domain}_testssl.txt
	printf "${bred} Finished : ${bgreen} Results are saved in ${domain}_testssl.txt ${reset}\n"
	printf "${bgreen}#######################################################################\n"
	# Finished testssl Scan
}

end(){
	# Finished Recon
	if [ -n "$dir_output" ]
	then
		output
		finaldir=$dir_output
	fi
	printf "${bgreen}#######################################################################\n"
	printf "${bred} Finished Recon on: ${bgreen} ${domain} under ${finaldir} ${reset}\n"
	printf "${bgreen}#######################################################################\n"
}

all(){
	start
	if [ -n "$list" ]
	then
		for domain in $(cat $list); do
			start
			dorks
			subdomains
			subtakeover
			webprobe
			portscan
			nuclei_check
			urlcheks
			jschecks
			params
			xss
			github
			favicon
			fuzz
			cors
			testssl
			end
		done
	else
		start
		dorks
		subdomains
		subtakeover
		webprobe
		portscan
		nuclei_check
		urlcheks
		jschecks
		params
		xss
		github
		favicon
		fuzz
		cors
		testssl
		end
	fi
}

help(){
	printf "\n Params ${yellow}(-d always required)${reset}:\n";
	printf "        $0 -d target.com    Target domain ${yellow}(required always)${reset}\n";
	printf "        $0 -l targets.txt   Target list ${yellow}(required only with -w or -t, optional for -a)${reset}\n";
	printf "\n Flags ${yellow}(1 required)${reset}: \n";
	printf "        $0 -a   All checks ${bgreen}(default and recommended)${reset}\n";
	printf "        $0 -s   Only subdomains\n";
	printf "        $0 -g   Only Google Dorks\n";
	printf "        $0 -w   Only web scan\n";
	printf "        $0 -t   Only web scan\n";
	printf "        $0 -o   Output folder\n";
	printf "        $0 -h   Show this help\n";
	printf "\n Examples: \n\n";
	printf " ./reconftw.sh -d target.com -a -> All checks\n";
	printf " ./reconftw.sh -d target.com -l domainslist.txt -a -> All checks against target list\n";
	printf " ./reconftw.sh -d target.com -s -> Only subdomains\n";
	printf " ./reconftw.sh -d target.com -s -o my/path -> Only subdomains with custom output\n";
	printf " ./reconftw.sh -d target.com -g -> Only Google Dorks\n";
	printf " ./reconftw.sh -d target.com -l weblist.txt -w -> Only Web Scan (Web list required)\n";
	printf " ./reconftw.sh -d target.com -l weblist.txt -t -> Check SubTko (Domain list required)\n";
}

output(){
	mkdir -p $dir_output
	mv $dir $dir_output
}

banner

if [ -z "$1" ]
then
   help
   tools_installed
   exit
fi

while getopts ":hd:-:l:aswgto:" opt; do
	case ${opt} in
		d ) domain=$OPTARG
			;;
		l ) list=$OPTARG
			;;
		s ) if [ -n "$list" ]
			then
				for domain in $(cat $list); do
					start
					subdomains
					subtakeover
					webprobe
					end
				done
			else
				start
				subdomains
				subtakeover
				webprobe
				end
			fi
			;;
		a ) all
			;;
		w ) start
			if [ -n "$list" ]
			then
				cp $list $dir/${domain}_probed.txt
			fi
			nuclei_check
			urlcheks
			jschecks
			params
			xss
			fuzz
			cors
			testssl
			end
			;;
		t ) start
			if [ -n "$list" ]
			then
				cp $list $dir/${domain}_subdomains.txt
			fi
			subtakeover
			end
			;;
		g ) start
			dorks
			end
			;;
		o ) dir_output=$OPTARG
			output
			;;
		\? | h | : | * )
			help
			;;
	esac
done
shift $((OPTIND -1))
