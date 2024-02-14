#!/usr/bin/env bash

source "$1/reconftw.cfg"

###############################################################################################################
######################################### VULNERABILITIES #####################################################
###############################################################################################################

function brokenLinks() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $BROKENLINKS == true ]]; then
		start_func ${FUNCNAME[0]} "Broken links checks"
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		if [[ $AXIOM != true ]]; then
			if [[ ! -s ".tmp/katana.txt" ]]; then
				if [[ $DEEP == true ]]; then
					[ -s "webs/webs_all.txt" ] && katana -silent -list webs/webs_all.txt -jc -kf all -c $KATANA_THREADS -d 3 -o .tmp/katana.txt 2>>"$LOGFILE" >/dev/null
				else
					[ -s "webs/webs_all.txt" ] && katana -silent -list webs/webs_all.txt -jc -kf all -c $KATANA_THREADS -d 2 -o .tmp/katana.txt 2>>"$LOGFILE" >/dev/null
				fi
			fi
			[ -s ".tmp/katana.txt" ] && sed -i '/^.\{2048\}./d' .tmp/katana.txt
		else
			if [[ ! -s ".tmp/katana.txt" ]]; then
				if [[ $DEEP == true ]]; then
					[ -s "webs/webs_all.txt" ] && axiom-scan webs/webs_all.txt -m katana -jc -kf all -d 3 -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
				else
					[ -s "webs/webs_all.txt" ] && axiom-scan webs/webs_all.txt -m katana -jc -kf all -d 2 -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
				fi
				[ -s ".tmp/katana.txt" ] && sed -i '/^.\{2048\}./d' .tmp/katana.txt
			fi
		fi
		[ -s ".tmp/katana.txt" ] && cat .tmp/katana.txt | sort -u | httpx -follow-redirects -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -no-color | grep "\[4" | cut -d ' ' -f1 | anew -q .tmp/brokenLinks_total.txt
		NUMOFLINES=$(cat .tmp/brokenLinks_total.txt 2>>"$LOGFILE" | anew vulns/brokenLinks.txt | sed '/^$/d' | wc -l)
		notification "${NUMOFLINES} new broken links found" info
		end_func "Results are saved in vulns/brokenLinks.txt" ${FUNCNAME[0]}
	else
		if [[ $BROKENLINKS == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function xss() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $XSS == true ]] && [[ -s "gf/xss.txt" ]]; then
		start_func ${FUNCNAME[0]} "XSS Analysis"
		[ -s "gf/xss.txt" ] && cat gf/xss.txt | qsreplace FUZZ | sed '/FUZZ/!d' | Gxss -c 100 -p Xss | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/xss_reflected.txt
		if [[ $AXIOM != true ]]; then
			if [[ $DEEP == true ]]; then
				if [[ -n $XSS_SERVER ]]; then
					[ -s ".tmp/xss_reflected.txt" ] && cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --only-poc r --ignore-return 302,404,403 --skip-bav -b ${XSS_SERVER} -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
				else
					printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
					[ -s ".tmp/xss_reflected.txt" ] && cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --only-poc r --ignore-return 302,404,403 --skip-bav -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
				fi
			else
				if [[ $(cat .tmp/xss_reflected.txt | wc -l) -le $DEEP_LIMIT ]]; then
					if [[ -n $XSS_SERVER ]]; then
						cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --skip-bav --skip-mining-dom --skip-mining-dict --only-poc r --ignore-return 302,404,403 -b ${XSS_SERVER} -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
					else
						printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
						cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --skip-bav --skip-mining-dom --skip-mining-dict --only-poc r --ignore-return 302,404,403 -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
					fi
				else
					printf "${bred} Skipping XSS: Too many URLs to test, try with --deep flag${reset}\n"
				fi
			fi
		else
			if [[ $DEEP == true ]]; then
				if [[ -n $XSS_SERVER ]]; then
					[ -s ".tmp/xss_reflected.txt" ] && axiom-scan .tmp/xss_reflected.txt -m dalfox --skip-bav -b ${XSS_SERVER} -w $DALFOX_THREADS -o vulns/xss.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
				else
					printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
					[ -s ".tmp/xss_reflected.txt" ] && axiom-scan .tmp/xss_reflected.txt -m dalfox --skip-bav -w $DALFOX_THREADS -o vulns/xss.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
				fi
			else
				if [[ $(cat .tmp/xss_reflected.txt | wc -l) -le $DEEP_LIMIT ]]; then
					if [[ -n $XSS_SERVER ]]; then
						axiom-scan .tmp/xss_reflected.txt -m dalfox --skip-bav --skip-grepping --skip-mining-all --skip-mining-dict -b ${XSS_SERVER} -w $DALFOX_THREADS -o vulns/xss.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					else
						printf "${yellow}\n No XSS_SERVER defined, blind xss skipped\n\n"
						axiom-scan .tmp/xss_reflected.txt -m dalfox --skip-bav --skip-grepping --skip-mining-all --skip-mining-dict -w $DALFOX_THREADS -o vulns/xss.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					fi
				else
					printf "${bred} Skipping XSS: Too many URLs to test, try with --deep flag${reset}\n"
				fi
			fi
		fi
		end_func "Results are saved in vulns/xss.txt" ${FUNCNAME[0]}
	else
		if [[ $XSS == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! -s "gf/xss.txt" ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to XSS ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function cors() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CORS == true ]]; then
		start_func ${FUNCNAME[0]} "CORS Scan"
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		[ -s "webs/webs_all.txt" ] && python3 ${tools}/Corsy/corsy.py -i webs/webs_all.txt -o vulns/cors.txt 2>>"$LOGFILE" >/dev/null
		end_func "Results are saved in vulns/cors.txt" ${FUNCNAME[0]}
	else
		if [[ $CORS == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function open_redirect() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $OPEN_REDIRECT == true ]] && [[ -s "gf/redirect.txt" ]]; then
		start_func ${FUNCNAME[0]} "Open redirects checks"
		if [[ $DEEP == true ]] || [[ $(cat gf/redirect.txt | wc -l) -le $DEEP_LIMIT ]]; then
			cat gf/redirect.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_redirect.txt
			python3 ${tools}/Oralyzer/oralyzer.py -l .tmp/tmp_redirect.txt -p ${tools}/Oralyzer/payloads.txt >vulns/redirect.txt
			sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" vulns/redirect.txt
			end_func "Results are saved in vulns/redirect.txt" ${FUNCNAME[0]}
		else
			end_func "Skipping Open redirects: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
			printf "${bgreen}#######################################################################${reset}\n"
		fi
	else
		if [[ $OPEN_REDIRECT == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! -s "gf/redirect.txt" ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to Open Redirect ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function ssrf_checks() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSRF_CHECKS == true ]] && [[ -s "gf/ssrf.txt" ]]; then
		start_func ${FUNCNAME[0]} "SSRF checks"
		if [[ -z $COLLAB_SERVER ]]; then
			interactsh-client &>.tmp/ssrf_callback.txt &
			sleep 2
			COLLAB_SERVER_FIX="FFUFHASH.$(cat .tmp/ssrf_callback.txt | tail -n1 | cut -c 16-)"
			COLLAB_SERVER_URL="http://$COLLAB_SERVER_FIX"
			INTERACT=true
		else
			COLLAB_SERVER_FIX="FFUFHASH.$(echo ${COLLAB_SERVER} | sed -r "s/https?:\/\///")"
			INTERACT=false
		fi
		if [[ $DEEP == true ]] || [[ $(cat gf/ssrf.txt | wc -l) -le $DEEP_LIMIT ]]; then
			cat gf/ssrf.txt | qsreplace ${COLLAB_SERVER_FIX} | anew -q .tmp/tmp_ssrf.txt
			cat gf/ssrf.txt | qsreplace ${COLLAB_SERVER_URL} | anew -q .tmp/tmp_ssrf.txt
			ffuf -v -H "${HEADER}" -t $FFUF_THREADS -rate $FFUF_RATELIMIT -w .tmp/tmp_ssrf.txt -u FUZZ 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssrf_requested_url.txt
			ffuf -v -w .tmp/tmp_ssrf.txt:W1,${tools}/headers_inject.txt:W2 -H "${HEADER}" -H "W2: ${COLLAB_SERVER_FIX}" -t $FFUF_THREADS -rate $FFUF_RATELIMIT -u W1 2>/dev/null | anew -q vulns/ssrf_requested_headers.txt
			ffuf -v -w .tmp/tmp_ssrf.txt:W1,${tools}/headers_inject.txt:W2 -H "${HEADER}" -H "W2: ${COLLAB_SERVER_URL}" -t $FFUF_THREADS -rate $FFUF_RATELIMIT -u W1 2>/dev/null | anew -q vulns/ssrf_requested_headers.txt
			sleep 5
			[ -s ".tmp/ssrf_callback.txt" ] && cat .tmp/ssrf_callback.txt | tail -n+11 | anew -q vulns/ssrf_callback.txt && NUMOFLINES=$(cat .tmp/ssrf_callback.txt | tail -n+12 | sed '/^$/d' | wc -l)
			[ "$INTERACT" = true ] && notification "SSRF: ${NUMOFLINES} callbacks received" info
			end_func "Results are saved in vulns/ssrf_*" ${FUNCNAME[0]}
		else
			end_func "Skipping SSRF: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
		pkill -f interactsh-client &
	else
		if [[ $SSRF_CHECKS == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! -s "gf/ssrf.txt" ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SSRF ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function crlf_checks() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CRLF_CHECKS == true ]]; then
		start_func ${FUNCNAME[0]} "CRLF checks"
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		if [[ $DEEP == true ]] || [[ $(cat webs/webs_all.txt | wc -l) -le $DEEP_LIMIT ]]; then
			crlfuzz -l webs/webs_all.txt -o vulns/crlf.txt 2>>"$LOGFILE" >/dev/null
			end_func "Results are saved in vulns/crlf.txt" ${FUNCNAME[0]}
		else
			end_func "Skipping CRLF: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [[ $CRLF_CHECKS == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function lfi() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $LFI == true ]] && [[ -s "gf/lfi.txt" ]]; then
		start_func ${FUNCNAME[0]} "LFI checks"
		if [[ -s "gf/lfi.txt" ]]; then
			cat gf/lfi.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_lfi.txt
			if [[ $DEEP == true ]] || [[ $(cat .tmp/tmp_lfi.txt | wc -l) -le $DEEP_LIMIT ]]; then
				interlace -tL .tmp/tmp_lfi.txt -threads ${INTERLACE_THREADS} -c "ffuf -v -r -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w ${lfi_wordlist} -u \"_target_\" -mr \"root:\" " 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/lfi.txt
				end_func "Results are saved in vulns/lfi.txt" ${FUNCNAME[0]}
			else
				end_func "Skipping LFI: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
			fi
		fi
	else
		if [[ $LFI == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! -s "gf/lfi.txt" ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to LFI ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function ssti() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSTI == true ]] && [[ -s "gf/ssti.txt" ]]; then
		start_func ${FUNCNAME[0]} "SSTI checks"
		if [[ -s "gf/ssti.txt" ]]; then
			cat gf/ssti.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_ssti.txt
			if [[ $DEEP == true ]] || [[ $(cat .tmp/tmp_ssti.txt | wc -l) -le $DEEP_LIMIT ]]; then
				#TInjA url -u "file://.tmp/tmp_ssti.txt" --csti --reportpath "vulns/"
				interlace -tL .tmp/tmp_ssti.txt -threads ${INTERLACE_THREADS} -c "ffuf -v -r -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w ${ssti_wordlist} -u \"_target_\" -mr \"ssti49\" " 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssti.txt
				end_func "Results are saved in vulns/ssti.txt" ${FUNCNAME[0]}
			else
				end_func "Skipping SSTI: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
			fi
		fi
	else
		if [[ $SSTI == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! -s "gf/ssti.txt" ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SSTI ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function sqli() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SQLI == true ]] && [[ -s "gf/sqli.txt" ]]; then
		start_func ${FUNCNAME[0]} "SQLi checks"

		cat gf/sqli.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_sqli.txt
		if [[ $DEEP == true ]] || [[ $(cat .tmp/tmp_sqli.txt | wc -l) -le $DEEP_LIMIT ]]; then
			if [[ $SQLMAP == true ]]; then
				python3 ${tools}/sqlmap/sqlmap.py -m .tmp/tmp_sqli.txt -b -o --smart --batch --disable-coloring --random-agent --output-dir=vulns/sqlmap 2>>"$LOGFILE" >/dev/null
			fi
			if [[ $GHAURI == true ]]; then
				interlace -tL .tmp/tmp_sqli.txt -threads ${INTERLACE_THREADS} -c "ghauri -u _target_ --batch -H \"${HEADER}\" --force-ssl >> vulns/ghauri_log.txt" 2>>"$LOGFILE" >/dev/null
			fi
			end_func "Results are saved in vulns/sqlmap folder" ${FUNCNAME[0]}
		else
			end_func "Skipping SQLi: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [[ $SQLI == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! -s "gf/sqli.txt" ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SQLi ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function test_ssl() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $TEST_SSL == true ]]; then
		start_func ${FUNCNAME[0]} "SSL Test"
		${tools}/testssl.sh/testssl.sh --quiet --color 0 -U -iL hosts/ips.txt 2>>"$LOGFILE" >vulns/testssl.txt
		end_func "Results are saved in vulns/testssl.txt" ${FUNCNAME[0]}
	else
		if [[ $TEST_SSL == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function spraying() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SPRAY == true ]]; then
		start_func ${FUNCNAME[0]} "Password spraying"

		pushd "${tools}/brutespray" >/dev/null || {
			echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"
		}

		python3 brutespray.py --file $dir/hosts/portscan_active.gnmap --threads $BRUTESPRAY_THREADS --hosts $BRUTESPRAY_CONCURRENCE -o $dir/vulns/brutespray 2>>"$LOGFILE" >/dev/null
		popd >/dev/null || {
			echo "Failed to popd in ${FUNCNAME[0]} @ line ${LINENO}"
		}
		end_func "Results are saved in vulns/brutespray folder" ${FUNCNAME[0]}
	else
		if [[ $SPRAY == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function command_injection() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $COMM_INJ == true ]] && [[ -s "gf/rce.txt" ]]; then
		start_func ${FUNCNAME[0]} "Command Injection checks"
		[ -s "gf/rce.txt" ] && cat gf/rce.txt | qsreplace FUZZ | sed '/FUZZ/!d' | anew -q .tmp/tmp_rce.txt
		if [[ $DEEP == true ]] || [[ $(cat .tmp/tmp_rce.txt | wc -l) -le $DEEP_LIMIT ]]; then
			[ -s ".tmp/tmp_rce.txt" ] && python3 ${tools}/commix/commix.py --batch -m .tmp/tmp_rce.txt --output-dir vulns/command_injection.txt 2>>"$LOGFILE" >/dev/null
			end_func "Results are saved in vulns/command_injection folder" ${FUNCNAME[0]}
		else
			end_func "Skipping Command injection: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [[ $COMM_INJ == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ ! -s "gf/rce.txt" ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to Command Injection ${reset}\n\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function 4xxbypass() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $BYPASSER4XX == true ]]; then
		if [[ $(cat fuzzing/fuzzing_full.txt 2>/dev/null | grep -E '^4' | grep -Ev '^404' | cut -d ' ' -f3 | wc -l) -le 1000 ]] || [[ $DEEP == true ]]; then
			start_func "403 bypass"
			cat $dir/fuzzing/fuzzing_full.txt 2>/dev/null | grep -E '^4' | grep -Ev '^404' | cut -d ' ' -f3 >$dir/.tmp/403test.txt

			pushd "${tools}/dontgo403" >/dev/null || {
				echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"
			}

			cat $dir/.tmp/403test.txt | ./dontgo403 >$dir/.tmp/4xxbypass.txt
			popd >/dev/null || {
				echo "Failed to popd in ${FUNCNAME[0]} @ line ${LINENO}"
			}
			[ -s ".tmp/4xxbypass.txt" ] && cat .tmp/4xxbypass.txt | anew -q vulns/4xxbypass.txt
			end_func "Results are saved in vulns/4xxbypass.txt" ${FUNCNAME[0]}
		else
			notification "Too many urls to bypass, skipping" warn
		fi
	else
		if [[ $BYPASSER4XX == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function prototype_pollution() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $PROTO_POLLUTION == true ]]; then
		start_func ${FUNCNAME[0]} "Prototype Pollution checks"
		if [[ $DEEP == true ]] || [[ $(cat webs/url_extract.txt | wc -l) -le $DEEP_LIMIT ]]; then
			[ -s "webs/url_extract.txt" ] && cat webs/url_extract.txt | ppmap &> .tmp/prototype_pollution.txt
			[ -s ".tmp/prototype_pollution.txt" ] && cat .tmp/prototype_pollution.txt | grep "EXPL" | anew -q vulns/prototype_pollution.txt
			end_func "Results are saved in vulns/prototype_pollution.txt" ${FUNCNAME[0]}
		else
			end_func "Skipping Prototype Pollution: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [[ $PROTO_POLLUTION == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function smuggling() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SMUGGLING == true ]]; then
		start_func ${FUNCNAME[0]} "HTTP Request Smuggling checks"
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		if [[ $DEEP == true ]] || [[ $(cat webs/webs_all.txt | wc -l) -le $DEEP_LIMIT ]]; then
			pushd "${tools}/smuggler" >/dev/null || {
				echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"
			}
			cat $dir/webs/webs_all.txt | python3 smuggler.py -q --no-color 2>/dev/null | anew -q $dir/.tmp/smuggling.txt
			mkdir -p $dir/vulns/smuggling/
			find payloads -type f ! -name "README*" -exec mv {} $dir/vulns/smuggling/ \;
			popd >/dev/null || {
				echo "Failed to popd in ${FUNCNAME[0]} @ line ${LINENO}"
			}
			[ -s ".tmp/smuggling.txt" ] && cat .tmp/smuggling.txt | anew -q vulns/smuggling_log.txt
			end_func "Results are saved in vulns/smuggling_log.txt and findings in vulns/smuggling/" ${FUNCNAME[0]}
		else
			end_func "Skipping Request Smuggling: Too many webs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [[ $SMUGGLING == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function webcache() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBCACHE == true ]]; then
		start_func ${FUNCNAME[0]} "Web Cache Poisoning checks"
		[ ! -s "webs/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q webs/webs_all.txt
		if [[ $DEEP == true ]] || [[ $(cat webs/webs_all.txt | wc -l) -le $DEEP_LIMIT ]]; then
			pushd "${tools}/Web-Cache-Vulnerability-Scanner" >/dev/null || {
				echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"
			}

			Web-Cache-Vulnerability-Scanner -u file:$dir/webs/webs_all.txt -v 0 2>/dev/null | anew -q $dir/.tmp/webcache.txt
			popd >/dev/null || {
				echo "Failed to popd in ${FUNCNAME[0]} @ line ${LINENO}"
			}
			[ -s ".tmp/webcache.txt" ] && cat .tmp/webcache.txt | anew -q vulns/webcache.txt
			end_func "Results are saved in vulns/webcache.txt" ${FUNCNAME[0]}
		else
			end_func "Web Cache Poisoning: Too many webs to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [[ $WEBCACHE == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

function fuzzparams() {

	if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FUZZPARAMS == true ]]; then
		start_func ${FUNCNAME[0]} "Fuzzing params values checks"
		if [[ $DEEP == true ]] || [[ $(cat webs/url_extract.txt | wc -l) -le $DEEP_LIMIT2 ]]; then
			if [[ $AXIOM != true ]]; then
				nuclei -update 2>>"$LOGFILE" >/dev/null
				git -C ${tools}/fuzzing-templates pull
				cat webs/url_extract.txt 2>/dev/null | nuclei -silent -retries 3 -rl $NUCLEI_RATELIMIT -t ${tools}/fuzzing-templates -o .tmp/fuzzparams.txt
			else
				axiom-exec "git clone https://github.com/projectdiscovery/fuzzing-templates /home/op/fuzzing-templates" &>/dev/null
				axiom-scan webs/url_extract.txt -m nuclei -nh -retries 3 -w /home/op/fuzzing-templates -rl $NUCLEI_RATELIMIT -o .tmp/fuzzparams.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
			[ -s ".tmp/fuzzparams.txt" ] && cat .tmp/fuzzparams.txt | anew -q vulns/fuzzparams.txt
			end_func "Results are saved in vulns/fuzzparams.txt" ${FUNCNAME[0]}
		else
			end_func "Fuzzing params values: Too many entries to test, try with --deep flag" ${FUNCNAME[0]}
		fi
	else
		if [[ $FUZZPARAMS == false ]]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi

}

