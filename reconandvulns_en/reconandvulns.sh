#!/bin/bash

if [[ -z $1 ]]; then
	 echo "$(tput setab 5) [+] Usage: $0 domain$(tput sgr 0)"
     exit
else
 	if [[ $1 != http?(s)://* ]]; then
 		echo "$(tput setab 5) [+] The argument must be an URL: https://www.test.com$(tput sgr 0)"
 		exit
 	else
		WEB=${1}
		#DOMAIN=`echo "${WEB}" | sed -e 's/^http:\/\///g' -e 's/^https:\/\///g' -e 's/:.*//g'`
		DOMAIN=`echo "${WEB}" | awk -F/ '{print $3}'`
		DAY=`date +"%Y%m%d"`
		MYDIR=~/tools/Bounties/VULNS/${DAY}
		TELEAPI="1XXXXXX"
		CHATID="1XXXXXX"
		BXSS="https://X1XXXXX.xss.ht"
		FFUFDIC=~/tools/reconandvulns/dicc.txt
		ARONDIC=~/tools/reconandvulns/dictfull.txt
		if [[ ${TELEAPI} = "XXXXXX" ]] || [[ ${CHATID} = "XXXXXX" ]] || [[ ${BXSS} = "XXXXXX.xss.ht" ]]; then
			echo "$(tput setab 5) [+] Modify the following variables in order to get the script working:$(tput sgr 0)"
			echo "$(tput setab 5)  [-] MIDIR => linea 15$(tput sgr 0)"
 			echo "$(tput setab 5)  [-] TELEAPI => line 16$(tput sgr 0)"
 			echo "$(tput setab 5)  [-] CHATID => line 17$(tput sgr 0)"
 			echo "$(tput setab 5)  [-] BXSS => line 18$(tput sgr 0)"
 			exit
 		else
 			echo "$(tput setab 7)[+] $DOMAIN$(tput sgr 0)"
			mkdir -p ${MYDIR}/${DOMAIN}
			mkdir -p ${MYDIR}/${DOMAIN}/naabu
			mkdir -p ${MYDIR}/${DOMAIN}/js
			mkdir -p ${MYDIR}/${DOMAIN}/js/js
			mkdir -p ${MYDIR}/${DOMAIN}/waybackurls
			mkdir -p ${MYDIR}/${DOMAIN}/hakrawler
			mkdir -p ${MYDIR}/${DOMAIN}/urls_interesting
			mkdir -p ${MYDIR}/${DOMAIN}/linkFinder
			mkdir -p ${MYDIR}/${DOMAIN}/arjun
			mkdir -p ${MYDIR}/${DOMAIN}/eyewitness
			mkdir -p ${MYDIR}/${DOMAIN}/github
			mkdir -p ${MYDIR}/${DOMAIN}/XSStrike
			mkdir -p ${MYDIR}/${DOMAIN}/dalfox
			mkdir -p ${MYDIR}/${DOMAIN}/ffuf
			mkdir -p ${MYDIR}/${DOMAIN}/urlsfull
			mkdir -p ${MYDIR}/${DOMAIN}/gau
			mkdir -p ${MYDIR}/${DOMAIN}/kxss
			mkdir -p ${MYDIR}/${DOMAIN}/paramspider
			mkdir -p ${MYDIR}/${DOMAIN}/aron
			mkdir -p ${MYDIR}/${DOMAIN}/hinject
			mkdir -p ${MYDIR}/${DOMAIN}/xssb
			mkdir -p ${MYDIR}/${DOMAIN}/sqli
			mkdir -p ${MYDIR}/${DOMAIN}/sratarun
			mkdir -p ${MYDIR}/${DOMAIN}/SecretFinder
			mkdir -p ${MYDIR}/${DOMAIN}/smuggler


			function_notifications_start () {
				curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="Starting => ${WEB} `date +"%Y-%m-%d %H:%M"`" >/dev/null 2>/dev/null
			}

			function_smuggler () {
				cd ${MYDIR}/${DOMAIN}/smuggler
				python3 ~/tools/smuggler/smuggler.py -u ${WEB} -l ${DOMAIN}_smuggler.txt >/dev/null 2>/dev/null
				cat ${DOMAIN}_smuggler.txt | ansi2html > ${DOMAIN}_smuggler.html
				rm ${DOMAIN}_smuggler.txt
			}

			function_zile () {
				cd ${MIDIR}/${DOMINIO}/zile
				cat ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros.txt | python3 ~/tools/zile/zile.py --request --colored >> ${DOMINIO}_zile.txt 2>/dev/null
				cat ${DOMINIO}_zile.txt | ansi2html > ${DOMINIO}_zile.html
				rm ${DOMINIO}_zile.txt
			}

			function_xssbb() {
				echo "$(tput setab 1) [-] xssb$(tput sgr 0)"
				### xssb ###
				cd ${MYDIR}/${DOMAIN}/xssb
				if [ -f ${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt ]; then
					cat ${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt | qsreplace -a | dalfox pipe -b ${BXSS} -o ${DOMAIN}_xssb.txt >/dev/null 2>/dev/null 
					cat ${DOMAIN}_xssb.txt | ansi2html > ${DOMAIN}_xssb.html
					rm ${DOMAIN}_xssb.txt
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				else
					echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
				fi
			}


			function_sqli() {
				echo "$(tput setab 1) [-] sqli$(tput sgr 0)"
				### sqli ###
				cd ${MYDIR}/${DOMAIN}/sqli
				if [ -f ${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt ]; then
					for i in $(cat ${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt | qsreplace -a) ; do python3 ~/tools/DSSS/dsss.py -u ${i} >> ${DOMAIN}_sqli.txt 2>/dev/null ; done
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				else
					echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
				fi
			}



			function_hostheader () {
				echo "$(tput setab 1) [-] hinject$(tput sgr 0)"
				### hinject ###
				cd ${MYDIR}/${DOMAIN}/hinject
				echo "${WEB}" | hinject >> ${DOMAIN}_hinject.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}


			function_paramspider () {
				echo "$(tput setab 1) [-] paramspider$(tput sgr 0)"
				### paramspider ###
				cd ${MYDIR}/${DOMAIN}/paramspider
				python3 ~/tools/ParamSpider/paramspider.py --domain ${DOMAIN} --quiet --subs False --exclude jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,bmp,eot,ico,js --output ${DOMAIN}_paramspider.txt --level high >/dev/null 2>/dev/null
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				if [ -f ${MYDIR}/${DOMAIN}/paramspider/output/${DOMAIN}_paramspider.txt ]; then
					cat output/${DOMAIN}_paramspider.txt | ansi2html > ${DOMAIN}_paramspider.html
				fi
			}


			function_github () {
				echo "$(tput setab 1) [-] github$(tput sgr 0)"
				### github ###
				cd ${MYDIR}/${DOMAIN}/github
				touch github_secret.txt
				touch github_endpoints.txt
				python3 ~/tools/github-search/github-secrets.py -s "$DOMAIN" >/dev/null 2>/dev/null
				cat github_secret.txt | ansi2html > github_secret.html
				python3 ~/tools/github-search/github-endpoints.py -d "$DOMAIN" >/dev/null 2>/dev/null
				cat github_endpoints.txt | ansi2html > github_endpoints.html
				rm github_secret.txt
				rm github_endpoints.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}

			function_naabu () {
				echo "$(tput setab 1) [-] naabu$(tput sgr 0)"
				cd ${MYDIR}/${DOMAIN}/naabu
				naabu -silent -ports full -host ${DOMAIN} -exclude-ports 2000,5060 -o ${DOMAIN}_naabu.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			} 

			function_sratarun() {
				echo "$(tput setab 1) [-] sratarun (Xss Possible)$(tput sgr 0)"
				### sratarun ###
				cd ${MYDIR}/${DOMAIN}/sratarun
				if [ -f ${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt ]; then
					grep '=' ${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt | qsreplace hack\" -a | while read url;do target=$(curl -s -l $url | egrep -o '(hack"|hack\\")'); echo -e "Target:\e[1;33m $url\e[0m" "$target" "\n-------"; done | sed 's/hack"/[Xss Possible] Reflection Found/g' >> ${DOMAIN}_sratarun.txt
					cat ${DOMAIN}_sratarun.txt | ansi2html > ${DOMAIN}_sratarun.html
					rm ${DOMAIN}_sratarun.txt
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				else
					echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
				fi
			}


			function_gau () {
				echo "$(tput setab 1) [-] gau$(tput sgr 0)"
				### gau (web crawler) ###
				cd ${MYDIR}/${DOMAIN}/gau
				gau ${DOMAIN} > ${DOMAIN}_gau.txt 2>/dev/null
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}

			function_hakrawler () {
				### hakrawler (web crawler) ###
				echo "$(tput setab 1) [-] hakrawler$(tput sgr 0)"
				cd ${MYDIR}/${DOMAIN}/hakrawler
				hakrawler -plain -url "${WEB}" -depth 3 -outdir "${DOMAIN}_hakrawler" >> ${DOMAIN}_hakrawler.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}


			function_ffuf () {
				### ffuf (busco dirs) ###
				echo "$(tput setab 1) [-] ffuf$(tput sgr 0)"
				cd ${MYDIR}/${DOMAIN}/ffuf
				ffuf -mc all -c -H "X-Forwarded-For: 127.0.0.1" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -u "${WEB}"/FUZZ -w ${FFUFDIC} -D -e js,php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config,save,rsa,ppk -ac -s -o ${DOMAIN}_ffuf_partial.txt >/dev/null 2>/dev/null
				if [ -f "${DOMAIN}_ffuf_partial.txt" ]; then
					cat ${DOMAIN}_ffuf_partial.txt| jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' | sed 's/\"//g' > ${DOMAIN}_ffuf_final.txt
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				fi
			}

			function_dalfox () {
				cd ${MYDIR}/${DOMAIN}/dalfox
				echo "$(tput setab 1) [-] dalfox (busco xss)$(tput sgr 0)"
				if [ -f "${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt" ]; then
					capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt")
					if [ $capacidad0 == 0 ]; then
						echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
					else
						cat ${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt | qsreplace -a | dalfox pipe -o ${DOMAIN}_dalfox.txt >/dev/null 2>/dev/null
						cat ${DOMAIN}_dalfox.txt | ansi2html > ${DOMAIN}_dalfox.html
						rm ${DOMAIN}_dalfox.txt 
						echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
					fi
				else
					echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
				fi	
			}


			function_XSStrike() {
				echo "$(tput setab 1) [-] XSStrike$(tput sgr 0)"
				### XSStrike ###
				cd ${MYDIR}/${DOMAIN}/XSStrike
				python3 ~/tools/XSStrike/xsstrike.py -u "${WEB}" -d 2 -t 10 --crawl -l 3 --params --file-log-level VULN --seeds ${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt --log-file ${DOMAIN}_xsstrike.txt >/dev/null 2>/dev/null
				if [ -f ${MYDIR}/${DOMAIN}/XSStrike/${DOMAIN}_xsstrike.txt ]; then
					cat ${MYDIR}/${DOMAIN}/XSStrike/${DOMAIN}_xsstrike.txt | ansi2html > ${DOMAIN}_xsstrike.html
					rm ${DOMAIN}_xsstrike.txt
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				else
					echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
				fi
			}


			function_kxss() {
				echo "$(tput setab 1) [-] kxss$(tput sgr 0)"
				### kxss ###
				cd ${MYDIR}/${DOMAIN}/kxss
				if [ -f ${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt ]; then
					cat ${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt | kxss >> ${DOMAIN}_urlsfull_kxss.txt >/dev/null 2>/dev/null	
					cat ${DOMAIN}_urlsfull_kxss.txt| ansi2html > ${DOMAIN}_urlsfull_kxss.html
					rm ${DOMAIN}_urlsfull_kxss.txt
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				else
					echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
				fi
			}

			function_waybackurls () {
				echo "$(tput setab 1) [-] waybackurls (JS)$(tput sgr 0)"
				### waybackurls (Wayback Machine) ###
				cd ${MYDIR}/${DOMAIN}/waybackurls
				echo "${DOMAIN}" | waybackurls | grep "\.js" | uniq | sort > ${DOMAIN}_waybackurls.txt
				cat ${DOMAIN}_waybackurls.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g' >> ${DOMAIN}_waybackurls_alive.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}

			function_downloadjs () {
				echo "$(tput setab 1) [-] Download all JS$(tput sgr 0)"
				cd ${MYDIR}/${DOMAIN}/js
				cat ${MYDIR}/${DOMAIN}/waybackurls/${DOMAIN}_waybackurls.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g' >> ${DOMAIN}_hakcheckurl.txt
				cut -d " " -f2 ${MYDIR}/${DOMAIN}/js/${DOMAIN}_hakcheckurl.txt  >> ${DOMAIN}_hakcheckurl_final.txt
				cd ${MYDIR}/${DOMAIN}/js/js

				capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/js/${DOMAIN}_hakcheckurl_final.txt")

				if [ $capacidad0 == 0 ]; then
					echo "$(tput setab 5)   [-] [Without JS]$(tput sgr 0)"
				else
		            WithJS=`grep -i js ${MYDIR}/${DOMAIN}/js/${DOMAIN}_hakcheckurl_final.txt -c`
					if [ ${WithJS} -ne 0 ]; then
		                wget –quiet -i ${MYDIR}/${DOMAIN}/js/${DOMAIN}_hakcheckurl_final.txt >/dev/null 2>/dev/null
		                grep -i --color=always -n -E 'document.URL|document.documentURI|location|location.href|location.search|location.hash|document.referrer|window.name|eval|setTimeout|setInterval|document.write|document.writeIn|innerHTML|outerHTML' *.js* | ansi2html > dom_xss.html
		                grep -i --color=always -n -E '[ht|f]tp[s]*:\/\/\w+' *.js* | ansi2html > possible_webs.html
		                grep -i --color=always -n -E 'pass|contrase|key|clave|code|phrase|b64|base64|hash|md5' *.js* | ansi2html > possible_claves_hashs.html
		                grep -i --color=always -n -E 'usuario|user|dni|acceso|admin|Desa|prueba|test|demo|guest|rut' *.js* | ansi2html > possible_users_dni.html
		                grep -i --color=always -n -E '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' *.js* | ansi2html > possible_ip.html
		                grep -i --color=always -n -E '(callback=|jsonp=|api_key=|api=|password=|email=|emailto=|token=|username=|csrf_token=|unsubscribe_token=|p=|q=|query=|search=|id=|item=|page_id=|secret=|url=|from_url=|load_url=|file_url=|page_url=|)' *.js* | ansi2html > general.html
		                echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
		                function_analyzejs
					fi
				fi
			}


			function_analyzejs () {
				echo "$(tput setab 1) [-] Analyze JS (linkFinder)$(tput sgr 0)"
				### Analyze JS ###
				cd ${MYDIR}/${DOMAIN}/linkFinder
				python ~/tools/LinkFinder/linkfinder.py -i "${MYDIR}/${DOMAIN}/js/js/*.js" -o ${MYDIR}/${DOMAIN}/linkFinder/linkFinder.html >/dev/null 2>/dev/null
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}


			function_SecretFinder () {
				echo "$(tput setab 1) [-] SecretFinder$(tput sgr 0)"
				### Analyze JS ###
				cd ${MYDIR}/${DOMAIN}/SecretFinder
				python ~/tools/secretfinder/SecretFinder.py -i "${WEB}/" -e -o ${MYDIR}/${DOMAIN}/secretfinder/SecretFinder.html >/dev/null 2>/dev/null
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}


			function_urlsfull () {
				echo "$(tput setab 1) [-] Merge URLs$(tput sgr 0)"
				### unifico utls ###
				cd ${MYDIR}/${DOMAIN}/urlsfull

				if [ -f ${MYDIR}/${DOMAIN}/hakrawler/${DOMAIN}_hakrawler.txt ]; then
					cat ${MYDIR}/${DOMAIN}/hakrawler/${DOMAIN}_hakrawler.txt >> ${DOMAIN}_urlsfull_partial.txt
				fi

				if [ -f ${MYDIR}/${DOMAIN}/waybackurls/${DOMAIN}_waybackurls_alive.txt ]; then
					cat ${MYDIR}/${DOMAIN}/waybackurls/${DOMAIN}_waybackurls_alive.txt >> ${DOMAIN}_urlsfull_partial.txt
				fi

				if [ -f ${MYDIR}/${DOMAIN}/urls_interesting/${DOMAIN}_urls_interesting_alive.txt ]; then
					cat ${MYDIR}/${DOMAIN}/urls_interesting/${DOMAIN}_urls_interesting_alive.txt >> ${DOMAIN}_urlsfull_partial.txt
				fi

				if [ -f ${MYDIR}/${DOMAIN}/ffuf/${DOMAIN}_ffuf_final.txt ]; then
					cat ${MYDIR}/${DOMAIN}/ffuf/${DOMAIN}_ffuf_final.txt | grep '^200' | awk '{print $3}' >> ${DOMAIN}_urlsfull_partial.txt
				fi

				if [ -f ${MYDIR}/${DOMAIN}/gau/${DOMAIN}_gau.txt ]; then
					cat ${MYDIR}/${DOMAIN}/gau/${DOMAIN}_gau.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g'>> ${DOMAIN}_urlsfull_partial.txt
				fi

				if [ -f ${MYDIR}/${DOMAIN}/paramspider/output/${DOMAIN}_paramspider.txt ]; then
					cat ${MYDIR}/${DOMAIN}/paramspider/output/${DOMAIN}_paramspider.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g'>> ${DOMAIN}_urlsfull_partial.txt
				fi

				sort ${DOMAIN}_urlsfull_partial.txt | uniq >> ${DOMAIN}_urlsfull_final.txt

				egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|bmp|eot|ico|js)" ${DOMAIN}_urlsfull_final.txt >> ${DOMAIN}_urlsfull_final_for_arjun_pre.txt
				cat ${DOMAIN}_urlsfull_final_for_arjun_pre.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g' >> ${DOMAIN}_urlsfull_final_for_arjun_pre_alive.txt
				grep "?" ${DOMAIN}_urlsfull_final_for_arjun_pre_alive.txt | grep -v '%EF%BF%BD' >> ${DOMAIN}_urlsfull_final_parameters.txt
				grep -Ei '(\.php|\.asp|\.aspx|\.jsp|\.jsf|\.do|\.html|\.htm|\.xhtml)' ${DOMAIN}_urlsfull_final_for_arjun_pre_alive.txt >> ${DOMAIN}_urlsfull_final_for_arjun.txt
				rm ${DOMAIN}_urlsfull_final_for_arjun_pre.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}


			function_screenshots () {
				echo "$(tput setab 1) [-] screenshots$(tput sgr 0)"
				capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final.txt")
				if [ $capacidad0 == 0 ]; then
					echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
				else
					cd ${MYDIR}/${DOMAIN}/eyewitness
					python3 ~/tools/EyeWitness/Python/EyeWitness.py --web --timeout 20 --delay 3 --threads 2 -f ${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_for_arjun_pre_alive.txt --no-prompt -d screens >/dev/null 2>/dev/null
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				fi
			}

			function_arjun () {
				echo "$(tput setab 1) [-] arjun$(tput sgr 0)"
				if [ -f "${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_for_arjun.txt" ]; then
					capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_for_arjun.txt")

					if [ $capacidad0 == 0 ]; then
						echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
					else
						cd ~/tools/Arjun
						python3 arjun.py -t 2 -d 2 --get --stable --urls "${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_for_arjun.txt" -o "${MYDIR}/${DOMAIN}/arjun/${DOMAIN}_arjun.txt" >> "${MYDIR}/${DOMAIN}/arjun/${DOMAIN}_arjun_2.txt" 2>/dev/null
						echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
					fi
				fi	
			}


			function_aron () {
				echo "$(tput setab 1) [-] Aron$(tput sgr 0)"
				cd ${MYDIR}/${DOMAIN}/aron
				if [ -f "${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_for_arjun.txt" ]; then
					capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_for_arjun.txt")

					if [ $capacidad0 == 0 ]; then
						echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
					else

						for DOM in $(cat "${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_for_arjun.txt"); do
							Aron -u ${DOM} -g -w ${ARONDIC} >> ${DOMAIN}_aron.txt >/dev/null 2>/dev/null ;done
						echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
					fi
				fi	
			}


			function_urlsfull_y_arjun () {
				cd ${MYDIR}/${DOMAIN}/urlsfull
				echo "$(tput setab 1) [-] urlsfull_y_arjun (merge urls)$(tput sgr 0)"
				if [ -f "${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters.txt" ]; then
					capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters.txt")
					if [ $capacidad0 == 0 ]; then
						echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
					else
						cp "${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters.txt" ${DOMAIN}_urlsfull_final_parameters_final.txt
						if [ -f "${MYDIR}/${DOMAIN}/arjun/${DOMAIN}_arjun.txt" ]; then
							capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/arjun/${DOMAIN}_arjun.txt")
							if [ $capacidad0 != 0 ]; then
								cat "${MYDIR}/${DOMAIN}/arjun/${DOMAIN}_arjun.txt" >> "${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters.txt"
							fi
						fi

						if [ -f "${MYDIR}/${DOMAIN}/aron/${DOMAIN}_aron.txt" ]; then
							capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/aron/${DOMAIN}_aron.txt")
							if [ $capacidad0 != 0 ]; then
								grep 'URL =>' "${MYDIR}/${DOMAIN}/aron/${DOMAIN}_aron.txt" | cut -d '>' -f2 | sed 's/ //g' >> "${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters.txt"
							fi
						fi

						sort "${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters.txt" | uniq >> "${MYDIR}/${DOMAIN}/urlsfull/${DOMAIN}_urlsfull_final_parameters_final.txt"

						echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
					fi
				fi	


			}



			function_urls_interesting () {
				echo "$(tput setab 1) [-] Urls interesting (Urls interesting)$(tput sgr 0)"
				cd ${MYDIR}/${DOMAIN}/urls_interesting/
				## de https://twitter.com/ArthusuxD
				curl -s -k "http://arthusu.com/crawler/controllers/procesar_urls_interesting.php?DOMAIN=${DOMAIN}" -o ${DOMAIN}.txt
				if [ -f "${DOMAIN}.txt" ]; then
					capacidad0=$(wc -c <"${DOMAIN}.txt")
					if [ $capacidad0 == 0 ]; then
						echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
					else	
						grep -Eio '(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]' ${DOMAIN}.txt | sort | uniq| egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|bmp|eot|ico)" >> ${DOMAIN}_lo_que_quiero.txt
						grep -Ei '(\.txt|\.zip|\.rar|\.tar|\.php|\.asp|\.aspx|\.sql|\.dump|\.gz|\.log|\.xml|\.jsp|\.jsf|\.html|\.htm|\.db|\.do|\.db3|\.pl|\.py\.json)' ${DOMAIN}_lo_que_quiero.txt >> ${DOMAIN}_archivos_interesting_full.txt
						grep -i -E "(^https?://${DOMAIN})" ${DOMAIN}_archivos_interesting_full.txt >> ${DOMAIN}_archivos_interesting.txt
						capacidad0=$(wc -c <"${DOMAIN}_archivos_interesting.txt")
						if [ $capacidad0 == 0 ]; then
							echo "$(tput setab 5)   [-] [Without URL]$(tput sgr 0)"
						else
							echo "$(tput setab 2)   [-] [With URL]$(tput sgr 0)"
							cat ${MYDIR}/${DOMAIN}/urls_interesting/${DOMAIN}_archivos_interesting.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g' >> ${DOMAIN}_urls_interesting_alive.txt
						fi
					fi
				fi		
			}


			function_notifications_end () {
				echo "$(tput setab 1) [-] Notifications$(tput sgr 0)"
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"

				
				#xsstrike
				if [ -f "${MYDIR}/${DOMAIN}/XSStrike/${DOMAIN}_xsstrike.html" ]; then
					grep -i VULN -c "${MYDIR}/${DOMAIN}/XSStrike/${DOMAIN}_xsstrike.html">/dev/null 2>/dev/null
					if [ $? -eq 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With XSStrike" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [With XSStrike]$(tput sgr 0)"
					fi
				fi


				#sratarun
				if [ -f "${MYDIR}/${DOMAIN}/sratarun/${DOMAIN}_sratarun.html" ]; then
					grep -i 'Reflection Found' -c "${MYDIR}/${DOMAIN}/sratarun/${DOMAIN}_sratarun.html">/dev/null 2>/dev/null
					if [ $? -eq 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With sratarun" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [With sratarun]$(tput sgr 0)"
					fi
				fi


				#kxss
				if [ -f "${MYDIR}/${DOMAIN}/kxss/${DOMAIN}_urlsfull_kxss.html" ]; then
					capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/kxss/${DOMAIN}_urlsfull_kxss.html")
					if [ $capacidad0 != 1183 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With kxss" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [With kxss]$(tput sgr 0)"
					fi
				fi

				#js
				ls ${MYDIR}/${DOMAIN}/js/js/ | grep -i js -c >/dev/null 2>/dev/null
				if [ $? -eq 0 ]; then
					curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With JS" >/dev/null 2>/dev/null
					echo "$(tput setab 2)   [-] [With JS]$(tput sgr 0)"
				fi

				#github
				if [ -f "${MYDIR}/${DOMAIN}/github/github_secret.html" ]; then
					capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/github/github_secret.html")
					if [ $capacidad0 != 1183 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With GITSECRET" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [With GITSECRET]$(tput sgr 0)"
					fi
				fi

				if [ -f "${MYDIR}/${MYDIR}/${DOMAIN}/github/github_endpoints.html" ]; then
					capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/github/github_endpoints.html")
					if [ $capacidad0 != 1183 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With GITENDPOINTS" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [With GITENDPOINTS]$(tput sgr 0)"
					fi
				fi

				#eyewitness
				ls "${MYDIR}/${DOMAIN}/eyewitness/screens/report.html" >/dev/null 2>/dev/null
				if [ $? -eq 0 ]; then
					curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With SCREENSHOTS" >/dev/null 2>/dev/null
					echo "$(tput setab 2)   [-] [With SCREENSHOTS]$(tput sgr 0)"
				fi

				#dalfox
				if [ -f "${MYDIR}/${DOMAIN}/dalfox/${DOMAIN}_dalfox.html" ]; then
					grep -i found -c "${MYDIR}/${DOMAIN}/dalfox/${DOMAIN}_dalfox.html">/dev/null 2>/dev/null
					if [ $? -eq 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With DALFOX" >/dev/null 2>/dev/null
					fi
				fi

					#dalfoxB
				if [ -f "${MYDIR}/${DOMAIN}/xssb/${DOMAIN}_xssb.html" ]; then
					grep -i found -c "${MYDIR}/${DOMAIN}/xssb/${DOMAIN}_xssb.html">/dev/null 2>/dev/null
					if [ $? -eq 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With DALFOX XSSB" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [With DALFOX XSSB]$(tput sgr 0)"
					fi
				fi



				#ffuf
				if [ -f "${MYDIR}/${DOMAIN}/ffuf/${DOMAIN}_ffuf_final.txt" ]; then
					capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/ffuf/${DOMAIN}_ffuf_final.txt")
					if [ $capacidad0 != 0 ]; then
						capacidad1=$(grep -c 200 <"${MYDIR}/${DOMAIN}/ffuf/${DOMAIN}_ffuf_final.txt")
						if [ $capacidad1 != 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With FFUF" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [With FFUF]$(tput sgr 0)"
						fi
					fi
			    fi


			   	#aron
				if [ -f "${MYDIR}/${DOMAIN}/aron/${DOMAIN}_aron.txt" ]; then
					capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/aron/${DOMAIN}_aron.txt")
					if [ $capacidad0 != 0 ]; then
						capacidad1=$(grep -c 'URL =>' <"${MYDIR}/${DOMAIN}/aron/${DOMAIN}_aron.txt")
						if [ $capacidad1 != 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With ARON" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [With ARON]$(tput sgr 0)"
						fi
					fi
			    fi

			    #zile
				if [ -f "${MYDIR}/${DOMAIN}/zile/${DOMAIN}_zile.html" ]; then
						capacidad1=$(grep -v '[+] ' -c <"${MYDIR}/${DOMAIN}/zile/${DOMAIN}_zile.html")
						if [ $capacidad1 != 0 ]; then
							curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With ZILE" >/dev/null 2>/dev/null
							echo "$(tput setab 2)   [-] [With ZILE]$(tput sgr 0)"
						fi
					fi
			    fi


			    #smuggler
				if [ -f "${MYDIR}/${DOMAIN}/smuggler/${DOMAIN}_smuggler.html" ]; then
						capacidad1=$(grep -c '[CRITICAL]' <"{MYDIR}/${DOMAIN}/smuggler/${DOMAIN}_smuggler.html")
						if [ $capacidad1 != 0 ]; then
							curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With SMUGGLER" >/dev/null 2>/dev/null
							echo "$(tput setab 2)   [-] [With SMUGGLER]$(tput sgr 0)"
						fi
			    fi

			    #paramspider
				if [ -f "${MYDIR}/${DOMAIN}/paramspider/${DOMAIN}_paramspider.html" ]; then
					#paramspider
					curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMAIN} => With PARAMSPIDER" >/dev/null 2>/dev/null
					echo "$(tput setab 2)   [-] [With PARAMSPIDER]$(tput sgr 0)"
				fi

				curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="End => ${DOMAIN} `date +"%Y-%m-%d %H:%M"`" >/dev/null 2>/dev/null
			}

			function_notifications_start
			#function_naabu
			function_ffuf
			function_hakrawler
			function_gau
			function_waybackurls
			function_urls_interesting
			function_github
			function_paramspider
			function_urlsfull
			function_aron
			function_arjun
			function_urlsfull_y_arjun
			function_dalfox
			function_screenshots
			function_downloadjs
			function_XSStrike
			function_SecretFinder
			function_kxss
			function_xssbb
			function_sqli
			function_sratarun
			function_smuggler
			function_zile
			function_notifications_end
		fi
	fi
fi
