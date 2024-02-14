#!/usr/bin/env bash

source "$1"

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
		case $2 in
		info)
			text="\n${bblue} ${1} ${reset}"
			printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
		warn)
			text="\n${yellow} ${1} ${reset}"
			printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
		error)
			text="\n${bred} ${1} ${reset}"
			printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
		good)
			text="\n${bgreen} ${1} ${reset}"
			printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
		esac
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
			(cd "$file" && zip -r -q - .) | curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
		else
			cat "$file" | curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
		fi
	else
		file_name=$1
		curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
	fi
}

function sendToNotify {
	if [[ -z $1 ]]; then
		printf "\n${yellow} no file provided to send ${reset}\n"
	else
		if [[ -z $NOTIFY_CONFIG ]]; then
			NOTIFY_CONFIG=~/.config/notify/provider-config.yaml
		fi
		if [[ -n "$(find "${1}" -prune -size +8000000c)" ]]; then
			printf '%s is larger than 8MB, sending over transfer.sh\n' "${1}"
			transfer "${1}" | notify
			return 0
		fi
		if grep -q '^ telegram\|^telegram\|^    telegram' $NOTIFY_CONFIG; then
			notification "Sending ${domain} data over Telegram" info
			telegram_chat_id=$(cat ${NOTIFY_CONFIG} | grep '^    telegram_chat_id\|^telegram_chat_id\|^    telegram_chat_id' | xargs | cut -d' ' -f2)
			telegram_key=$(cat ${NOTIFY_CONFIG} | grep '^    telegram_api_key\|^telegram_api_key\|^    telegram_apikey' | xargs | cut -d' ' -f2)
			curl -F document=@${1} "https://api.telegram.org/bot${telegram_key}/sendDocument?chat_id=${telegram_chat_id}" 2>>"$LOGFILE" >/dev/null
		fi
		if grep -q '^ discord\|^discord\|^    discord' $NOTIFY_CONFIG; then
			notification "Sending ${domain} data over Discord" info
			discord_url=$(cat ${NOTIFY_CONFIG} | grep '^ discord_webhook_url\|^discord_webhook_url\|^    discord_webhook_url' | xargs | cut -d' ' -f2)
			curl -v -i -H "Accept: application/json" -H "Content-Type: multipart/form-data" -X POST -F file1=@${1} $discord_url 2>>"$LOGFILE" >/dev/null
		fi
		if [[ -n $slack_channel ]] && [[ -n $slack_auth ]]; then
			notification "Sending ${domain} data over Slack" info
			curl -F file=@${1} -F "initial_comment=reconftw zip file" -F channels=${slack_channel} -H "Authorization: Bearer ${slack_auth}" https://slack.com/api/files.upload 2>>"$LOGFILE" >/dev/null
		fi
	fi
}

function start_func() {
	printf "${bgreen}#######################################################################"
	notification "${2}" info
	echo "[ $(date +"%F %T") ] Start function : ${1} " >>"${LOGFILE}"
	start=$(date +%s)
}

function end_func() {
	touch $called_fn_dir/.${2}
	end=$(date +%s)
	getElapsedTime $start $end
	notification "${2} Finished in ${runtime}" info
	echo "[ $(date +"%F %T") ] End function : ${2} " >>"${LOGFILE}"
	printf "${bblue} ${1} ${reset}\n"
	printf "${bgreen}#######################################################################${reset}\n"
}

function start_subfunc() {
	notification "${2}" warn
	echo "[ $(date +"%F %T") ] Start subfunction : ${1} " >>"${LOGFILE}"
	start_sub=$(date +%s)
}

function end_subfunc() {
	touch $called_fn_dir/.${2}
	end_sub=$(date +%s)
	getElapsedTime $start_sub $end_sub
	notification "${1} in ${runtime}" good
	echo "[ $(date +"%F %T") ] End subfunction : ${1} " >>"${LOGFILE}"
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

function axiom_lauch() {
	# let's fire up a FLEET!
	if [[ $AXIOM_FLEET_LAUNCH == true ]] && [[ -n $AXIOM_FLEET_NAME ]] && [[ -n $AXIOM_FLEET_COUNT ]]; then
		start_func ${FUNCNAME[0]} "Launching our Axiom fleet"
		python3 -m pip install --upgrade linode-cli 2>>"$LOGFILE" >/dev/null
		# Check to see if we have a fleet already, if so, SKIP THIS!
		NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME")
		if [[ $NUMOFNODES -ge $AXIOM_FLEET_COUNT ]]; then
			axiom-select "$AXIOM_FLEET_NAME*"
			end_func "Axiom fleet $AXIOM_FLEET_NAME already has $NUMOFNODES instances"
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

			NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME")
			echo "Axiom fleet $AXIOM_FLEET_NAME launched w/ $NUMOFNODES instances" | $NOTIFY
			end_func "Axiom fleet $AXIOM_FLEET_NAME launched w/ $NUMOFNODES instances"
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
		eval axiom-rm -f "$AXIOM_FLEET_NAME*"
		echo "Axiom fleet $AXIOM_FLEET_NAME shutdown" | $NOTIFY
		notification "Axiom fleet $AXIOM_FLEET_NAME shutdown" info
	fi
}

function axiom_selected() {

	if [[ ! $(axiom-ls | tail -n +2 | sed '$ d' | wc -l) -gt 0 ]]; then
		notification "\n\n${bred} No axiom instances running ${reset}\n\n" error
		exit
	fi

	if [[ ! $(cat ~/.axiom/selected.conf | sed '/^\s*$/d' | wc -l) -gt 0 ]]; then
		notification "\n\n${bred} No axiom instances selected ${reset}\n\n" error
		exit
	fi
}

function start() {

	global_start=$(date +%s)

	if [[ $NOTIFICATION == true ]]; then
		NOTIFY="notify -silent"
	else
		NOTIFY=""
	fi

	printf "\n${bgreen}#######################################################################${reset}"
	notification "Recon succesfully started on ${domain}" good
	[ "$SOFT_NOTIFICATION" = true ] && echo "Recon succesfully started on ${domain}" | notify -silent
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
		notification "\n\n${bred} No domain or list provided ${reset}\n\n" error
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
	mkdir -p .tmp .log osint subdomains webs hosts vulns

	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "Start ${NOW} ${NOWT}" >"${LOGFILE}"

	printf "\n"
	printf "${bred} Target: ${domain}\n\n"
}

function end() {

	find $dir -type f -empty -print | grep -v '.called_fn' | grep -v '.log' | grep -v '.tmp' | xargs rm -f 2>>"$LOGFILE" >/dev/null
	find $dir -type d -empty -print -delete 2>>"$LOGFILE" >/dev/null

	echo "End $(date +"%F") $(date +"%T")" >>"${LOGFILE}"

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
	notification "Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" good
	[ "$SOFT_NOTIFICATION" = true ] && echo "Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" | notify -silent
	printf "${bgreen}#######################################################################${reset}\n"
	#Seperator for more clear messges in telegram_Bot
	echo "******  Stay safe 🦠 and secure 🔐  ******" | $NOTIFY

}


###############################################################################################################
############################################# GEOLOCALIZATION INFO #######################################################
###############################################################################################################

function geo_info() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $GEO_INFO == true ]]; then
		start_func ${FUNCNAME[0]} "Running: ipinfo and geoinfo"
		ips_file="${dir}/hosts/ips.txt"
		if [ ! -f $ips_file ]; then
			echo "File ${dir}/hosts/ips.txt does not exist."
		else
			for ip in $(cat "$ips_file"); do
				json_output=$(curl -s https://ipapi.co/$ip/json)
				echo $json_output >>${dir}/hosts/geoip.json
				ip=$(echo $json_output | jq '.ip' | tr -d '''"''')
				network=$(echo $json_output | jq '.network' | tr -d '''"''')
				city=$(echo $json_output | jq '.city' | tr -d '''"''')
				region=$(echo $json_output | jq '.region' | tr -d '''"''')
				country=$(echo $json_output | jq '.country' | tr -d '''"''')
				country_name=$(echo $json_output | jq '.country_name' | tr -d '''"''')
				country_code=$(echo $json_output | jq '.country_code' | tr -d '''"''')
				country_code_iso3=$(echo $json_output | jq '.country_code_iso3' | tr -d '''"''')
				country_tld=$(echo $json_output | jq '.country_tld' | tr -d '''"''')
				continent_code=$(echo $json_output | jq '.continent_code' | tr -d '''"''')
				latitude=$(echo $json_output | jq '.latitude' | tr -d '''"''')
				longitude=$(echo $json_output | jq '.longitude' | tr -d '''"''')
				timezone=$(echo $json_output | jq '.timezone' | tr -d '''"''')
				utc_offset=$(echo $json_output | jq '.utc_offset' | tr -d '''"''')
				asn=$(echo $json_output | jq '.asn' | tr -d '''"''')
				org=$(echo $json_output | jq '.org' | tr -d '''"''')

				echo "IP: $ip" >>${dir}/hosts/geoip.txt
				echo "Network: $network" >>${dir}/hosts/geoip.txt
				echo "City: $city" >>${dir}/hosts/geoip.txt
				echo "Region: $region" >>${dir}/hosts/geoip.txt
				echo "Country: $country" >>${dir}/hosts/geoip.txt
				echo "Country Name: $country_name" >>${dir}/hosts/geoip.txt
				echo "Country Code: $country_code" >>${dir}/hosts/geoip.txt
				echo "Country Code ISO3: $country_code_iso3" >>${dir}/hosts/geoip.txt
				echo "Country tld: $country_tld" >>${dir}/hosts/geoip.txt
				echo "Continent Code: $continent_code" >>${dir}/hosts/geoip.txt
				echo "Latitude: $latitude" >>${dir}/hosts/geoip.txt
				echo "Longitude: $longitude" >>${dir}/hosts/geoip.txt
				echo "Timezone: $timezone" >>${dir}/hosts/geoip.txt
				echo "UTC Offset: $utc_offset" >>${dir}/hosts/geoip.txt
				echo "ASN: $asn" >>${dir}/hosts/geoip.txt
				echo "ORG: $org" >>${dir}/hosts/geoip.txt
				echo -e "------------------------------\n" >>${dir}/hosts/geoip.txt
			done
		fi
		end_func "Results are saved in hosts/geoip.txt and hosts/geoip.json" ${FUNCNAME[0]}
	else
		if [[ $GEO_INFO == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}
