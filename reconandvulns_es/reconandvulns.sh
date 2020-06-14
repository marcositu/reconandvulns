#!/bin/bash

if [[ -z $1 ]]; then
	 echo "$(tput setab 5) [+] Uso: $0 dominio$(tput sgr 0)"
     exit
else
 	if [[ $1 != http?(s)://* ]]; then
 		echo "$(tput setab 5) [+] El argumento debe ser una url: https://test.com$(tput sgr 0)"
 		exit
 	else
		WEB=${1}
		#DOMINIO=`echo "${WEB}" | sed -e 's/^http:\/\///g' -e 's/^https:\/\///g' -e 's/:.*//g'`
		DOMINIO=`echo "${WEB}" | awk -F/ '{print $3}'`
		FECHA=`date +"%Y%m%d"`
		MIDIR=~/tools/Bounties/VULNS/${FECHA}
		TELEAPI="XXXXXX"
		CHATID="XXXXXX"
		BXSS="XXXXXX.xss.ht"
		FFUFDIC=~/tools/reconandvunls/dicc.txt
		ARONDIC=~/tools/reconandvunls/dictfull.txt

		if [[ ${TELEAPI} = "XXXXXX" ]] || [[ ${CHATID} = "XXXXXX" ]] || [[ ${BXSS} = "XXXXXX.xss.ht" ]]; then
			echo "$(tput setab 5) [+] Modificar las siguientes variables para el funcionamiento del script$(tput sgr 0)"
			echo "$(tput setab 5)  [-] MIDIR => linea 15$(tput sgr 0)"
 			echo "$(tput setab 5)  [-] TELEAPI => linea 16$(tput sgr 0)"
 			echo "$(tput setab 5)  [-] CHATID => linea 17$(tput sgr 0)"
 			echo "$(tput setab 5)  [-] BXSS => linea 18$(tput sgr 0)"
 			exit
 		else
			echo "$(tput setab 7)[+] $DOMINIO$(tput sgr 0)"
			mkdir -p ${MIDIR}/${DOMINIO}
			mkdir -p ${MIDIR}/${DOMINIO}/naabu
			mkdir -p ${MIDIR}/${DOMINIO}/js
			mkdir -p ${MIDIR}/${DOMINIO}/js/js
			mkdir -p ${MIDIR}/${DOMINIO}/waybackurls
			mkdir -p ${MIDIR}/${DOMINIO}/hakrawler
			mkdir -p ${MIDIR}/${DOMINIO}/urls_interesantes
			mkdir -p ${MIDIR}/${DOMINIO}/linkFinder
			mkdir -p ${MIDIR}/${DOMINIO}/arjun
			mkdir -p ${MIDIR}/${DOMINIO}/eyewitness
			mkdir -p ${MIDIR}/${DOMINIO}/github
			mkdir -p ${MIDIR}/${DOMINIO}/XSStrike
			mkdir -p ${MIDIR}/${DOMINIO}/dalfox
			mkdir -p ${MIDIR}/${DOMINIO}/ffuf
			mkdir -p ${MIDIR}/${DOMINIO}/urlsfull
			mkdir -p ${MIDIR}/${DOMINIO}/gau
			mkdir -p ${MIDIR}/${DOMINIO}/kxss
			mkdir -p ${MIDIR}/${DOMINIO}/paramspider
			mkdir -p ${MIDIR}/${DOMINIO}/aron
			mkdir -p ${MIDIR}/${DOMINIO}/hinject
			mkdir -p ${MIDIR}/${DOMINIO}/xssb
			mkdir -p ${MIDIR}/${DOMINIO}/sqli
			mkdir -p ${MIDIR}/${DOMINIO}/sratarun
			mkdir -p ${MIDIR}/${DOMINIO}/SecretFinder
			mkdir -p ${MIDIR}/${DOMINIO}/smuggler
			mkdir -p ${MIDIR}/${DOMINIO}/zile


			funcion_notificaciones_comienzo () {
				curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="Comenzando => ${WEB} `date +"%Y-%m-%d %H:%M"`" >/dev/null 2>/dev/null
			}

			funcion_smuggler () {
				cd ${MIDIR}/${DOMINIO}/smuggler
				python3 ~/tools/smuggler/smuggler.py -u ${WEB} -l ${DOMINIO}_smuggler.txt >/dev/null 2>/dev/null
				cat ${DOMINIO}_smuggler.txt | ansi2html > ${DOMINIO}_smuggler.html
				rm ${DOMINIO}_smuggler.txt
			}

			funcion_zile () {
				cd ${MIDIR}/${DOMINIO}/zile
				cat ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros.txt | python3 ~/tools/zile/zile.py --request --colored >> ${DOMINIO}_zile.txt 2>/dev/null
				cat ${DOMINIO}_zile.txt | ansi2html > ${DOMINIO}_zile.html
				rm ${DOMINIO}_zile.txt
			}

			funcion_xssbb() {
				echo "$(tput setab 1) [-] xssb$(tput sgr 0)"
				### xssb ###
				cd ${MIDIR}/${DOMINIO}/xssb
				if [ -f ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt ]; then
					cat ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt | qsreplace -a | dalfox pipe -b ${BXSS} -o ${DOMINIO}_xssb.txt >/dev/null 2>/dev/null 
					cat ${DOMINIO}_xssb.txt | ansi2html > ${DOMINIO}_xssb.html
					rm ${DOMINIO}_xssb.txt
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				else
					echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
				fi
			}


			funcion_sqli() {
				echo "$(tput setab 1) [-] sqli$(tput sgr 0)"
				### sqli ###
				cd ${MIDIR}/${DOMINIO}/sqli
				if [ -f ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt ]; then
					for i in $(cat ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt | qsreplace -a) ; do python3 ~/tools/DSSS/dsss.py -u ${i} >> ${DOMINIO}_sqli.txt 2>/dev/null ; done
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				else
					echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
				fi
			}



			funcion_hostheader () {
				echo "$(tput setab 1) [-] hinject$(tput sgr 0)"
				### hinject ###
				cd ${MIDIR}/${DOMINIO}/hinject
				echo "${WEB}" | hinject >> ${DOMINIO}_hinject.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}


			funcion_paramspider () {
				echo "$(tput setab 1) [-] paramspider$(tput sgr 0)"
				### paramspider ###
				cd ${MIDIR}/${DOMINIO}/paramspider
				python3 ~/tools/ParamSpider/paramspider.py --domain ${DOMINIO} --quiet --subs False --exclude jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,bmp,eot,ico,js --output ${DOMINIO}_paramspider.txt --level high >/dev/null 2>/dev/null
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				if [ -f ${MIDIR}/${DOMINIO}/paramspider/output/${DOMINIO}_paramspider.txt ]; then
					cat output/${DOMINIO}_paramspider.txt | ansi2html > ${DOMINIO}_paramspider.html
				fi
			}


			funcion_github () {
				echo "$(tput setab 1) [-] github$(tput sgr 0)"
				### github ###
				cd ${MIDIR}/${DOMINIO}/github
				touch github_secret.txt
				touch github_endpoints.txt
				python3 ~/tools/github-search/github-secrets.py -s "$DOMINIO" >/dev/null 2>/dev/null
				cat github_secret.txt | ansi2html > github_secret.html
				python3 ~/tools/github-search/github-endpoints.py -d "$DOMINIO" >/dev/null 2>/dev/null
				cat github_endpoints.txt | ansi2html > github_endpoints.html
				rm github_secret.txt
				rm github_endpoints.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}

			funcion_naabu () {
				echo "$(tput setab 1) [-] naabu (Scanner TCP)$(tput sgr 0)"
				cd ${MIDIR}/${DOMINIO}/naabu
				naabu -silent -ports full -host ${DOMINIO} -exclude-ports 2000,5060 -o ${DOMINIO}_naabu.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			} 

			funcion_sratarun() {
				echo "$(tput setab 1) [-] sratarun (posible xss)$(tput sgr 0)"
				### sratarun ###
				cd ${MIDIR}/${DOMINIO}/sratarun
				if [ -f ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt ]; then
					grep '=' ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt | qsreplace hack\" -a | while read url;do target=$(curl -s -l $url | egrep -o '(hack"|hack\\")'); echo -e "Target:\e[1;33m $url\e[0m" "$target" "\n-------"; done | sed 's/hack"/[Xss Possible] Reflection Found/g' >> ${DOMINIO}_sratarun.txt
					cat ${DOMINIO}_sratarun.txt | ansi2html > ${DOMINIO}_sratarun.html
					rm ${DOMINIO}_sratarun.txt
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				else
					echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
				fi
			}


			funcion_gau () {
				echo "$(tput setab 1) [-] gau (web crawler)$(tput sgr 0)"
				### gau (web crawler) ###
				cd ${MIDIR}/${DOMINIO}/gau
				gau ${DOMINIO} > ${DOMINIO}_gau.txt 2>/dev/null
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}

			funcion_hakrawler () {
				### hakrawler (web crawler) ###
				echo "$(tput setab 1) [-] hakrawler (web crawler)$(tput sgr 0)"
				cd ${MIDIR}/${DOMINIO}/hakrawler
				hakrawler -plain -url "${WEB}" -depth 3 -outdir "${DOMINIO}_hakrawler" >> ${DOMINIO}_hakrawler.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}


			funcion_ffuf () {
				### ffuf (busco dirs) ###
				echo "$(tput setab 1) [-] ffuf (busco dirs)$(tput sgr 0)"
				cd ${MIDIR}/${DOMINIO}/ffuf
				ffuf -mc all -c -H "X-Forwarded-For: 127.0.0.1" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -u "${WEB}"/FUZZ -w ${FFUFDIC} -D -e js,php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config,save,rsa,ppk -ac -s -o ${DOMINIO}_ffuf_parcial.txt >/dev/null 2>/dev/null
				if [ -f "${DOMINIO}_ffuf_parcial.txt" ]; then
					cat ${DOMINIO}_ffuf_parcial.txt| jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' | sed 's/\"//g' > ${DOMINIO}_ffuf_final.txt
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				fi
			}

			funcion_dalfox () {
				cd ${MIDIR}/${DOMINIO}/dalfox
				echo "$(tput setab 1) [-] dalfox (busco xss)$(tput sgr 0)"
				if [ -f "${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt" ]; then
					capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt")
					if [ $capacidad0 == 0 ]; then
						echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
					else
						cat ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt | qsreplace -a | dalfox pipe -o ${DOMINIO}_dalfox.txt >/dev/null 2>/dev/null
						cat ${DOMINIO}_dalfox.txt | ansi2html > ${DOMINIO}_dalfox.html
						rm ${DOMINIO}_dalfox.txt 
						echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
					fi
				else
					echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
				fi	
			}


			funcion_XSStrike() {
				echo "$(tput setab 1) [-] XSStrike$(tput sgr 0)"
				### XSStrike ###
				cd ${MIDIR}/${DOMINIO}/XSStrike
				python3 ~/tools/XSStrike/xsstrike.py -u "${WEB}" -d 2 -t 10 --crawl -l 3 --params --file-log-level VULN --seeds ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt --log-file ${DOMINIO}_xsstrike.txt >/dev/null 2>/dev/null
				if [ -f ${MIDIR}/${DOMINIO}/XSStrike/${DOMINIO}_xsstrike.txt ]; then
					cat ${MIDIR}/${DOMINIO}/XSStrike/${DOMINIO}_xsstrike.txt | ansi2html > ${DOMINIO}_xsstrike.html
					rm ${DOMINIO}_xsstrike.txt
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				else
					echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
				fi
			}


			funcion_kxss() {
				echo "$(tput setab 1) [-] kxss$(tput sgr 0)"
				### kxss ###
				cd ${MIDIR}/${DOMINIO}/kxss
				if [ -f ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt ]; then
					cat ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt | kxss >> ${DOMINIO}_urlsfull_kxss.txt >/dev/null 2>/dev/null	
					cat ${DOMINIO}_urlsfull_kxss.txt| ansi2html > ${DOMINIO}_urlsfull_kxss.html
					rm ${DOMINIO}_urlsfull_kxss.txt
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				else
					echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
				fi
			}

			funcion_waybackurls () {
				echo "$(tput setab 1) [-] waybackurls (Wayback Machine solo JS)$(tput sgr 0)"
				### waybackurls (Wayback Machine) ###
				cd ${MIDIR}/${DOMINIO}/waybackurls
				echo "${DOMINIO}" | waybackurls | grep "\.js" | uniq | sort > ${DOMINIO}_waybackurls.txt
				cat ${DOMINIO}_waybackurls.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g' >> ${DOMINIO}_waybackurls_vivas.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}

			funcion_descargojs () {
				echo "$(tput setab 1) [-] Descargo todos los JS$(tput sgr 0)"
				### Descargo todos los JS ###
				cd ${MIDIR}/${DOMINIO}/js
				cat ${MIDIR}/${DOMINIO}/waybackurls/${DOMINIO}_waybackurls.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g' >> ${DOMINIO}_hakcheckurl.txt
				cut -d " " -f2 ${MIDIR}/${DOMINIO}/js/${DOMINIO}_hakcheckurl.txt  >> ${DOMINIO}_hakcheckurl_final.txt
				cd ${MIDIR}/${DOMINIO}/js/js

				capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/js/${DOMINIO}_hakcheckurl_final.txt")

				if [ $capacidad0 == 0 ]; then
					echo "$(tput setab 5)   [-] [NO hay JS]$(tput sgr 0)"
				else
		            TIENEJS=`grep -i js ${MIDIR}/${DOMINIO}/js/${DOMINIO}_hakcheckurl_final.txt -c`
					if [ ${TIENEJS} -ne 0 ]; then
		                wget –quiet -i ${MIDIR}/${DOMINIO}/js/${DOMINIO}_hakcheckurl_final.txt >/dev/null 2>/dev/null
		                grep -i --color=always -n -E 'document.URL|document.documentURI|location|location.href|location.search|location.hash|document.referrer|window.name|eval|setTimeout|setInterval|document.write|document.writeIn|innerHTML|outerHTML' *.js* | ansi2html > dom_xss.html
		                grep -i --color=always -n -E '[ht|f]tp[s]*:\/\/\w+' *.js* | ansi2html > posibles_webs.html
		                grep -i --color=always -n -E 'pass|contrase|key|clave|code|phrase|b64|base64|hash|md5' *.js* | ansi2html > posibles_claves_hashs.html
		                grep -i --color=always -n -E 'usuario|user|dni|acceso|admin|Desa|prueba|test|demo|guest|rut' *.js* | ansi2html > posibles_users_dni.html
		                grep -i --color=always -n -E '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' *.js* | ansi2html > posibles_ip.html
		                grep -i --color=always -n -E '(callback=|jsonp=|api_key=|api=|password=|email=|emailto=|token=|username=|csrf_token=|unsubscribe_token=|p=|q=|query=|search=|id=|item=|page_id=|secret=|url=|from_url=|load_url=|file_url=|page_url=|)' *.js* | ansi2html > general.html
		                echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
		                funcion_analizojs
					fi
				fi
			}


			funcion_analizojs () {
				echo "$(tput setab 1) [-] Analizo JS (linkFinder)$(tput sgr 0)"
				### Analizo JS ###
				cd ${MIDIR}/${DOMINIO}/linkFinder
				python ~/tools/LinkFinder/linkfinder.py -i "${MIDIR}/${DOMINIO}/js/js/*.js" -o ${MIDIR}/${DOMINIO}/linkFinder/linkFinder.html >/dev/null 2>/dev/null
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}


			funcion_SecretFinder () {
				echo "$(tput setab 1) [-] Analizo JS (SecretFinder)$(tput sgr 0)"
				### Analizo JS ###
				cd ${MIDIR}/${DOMINIO}/SecretFinder
				python ~/tools/secretfinder/SecretFinder.py -i "${WEB}/" -e -o ${MIDIR}/${DOMINIO}/secretfinder/SecretFinder.html >/dev/null 2>/dev/null
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}


			funcion_urlsfull () {
				echo "$(tput setab 1) [-] Unifico URLS$(tput sgr 0)"
				### unifico utls ###
				cd ${MIDIR}/${DOMINIO}/urlsfull

				if [ -f ${MIDIR}/${DOMINIO}/hakrawler/${DOMINIO}_hakrawler.txt ]; then
					cat ${MIDIR}/${DOMINIO}/hakrawler/${DOMINIO}_hakrawler.txt >> ${DOMINIO}_urlsfull_parcial.txt
				fi

				if [ -f ${MIDIR}/${DOMINIO}/waybackurls/${DOMINIO}_waybackurls_vivas.txt ]; then
					cat ${MIDIR}/${DOMINIO}/waybackurls/${DOMINIO}_waybackurls_vivas.txt >> ${DOMINIO}_urlsfull_parcial.txt
				fi

				if [ -f ${MIDIR}/${DOMINIO}/urls_interesantes/${DOMINIO}_urls_interesantes_vivas.txt ]; then
					cat ${MIDIR}/${DOMINIO}/urls_interesantes/${DOMINIO}_urls_interesantes_vivas.txt >> ${DOMINIO}_urlsfull_parcial.txt
				fi

				if [ -f ${MIDIR}/${DOMINIO}/ffuf/${DOMINIO}_ffuf_final.txt ]; then
					cat ${MIDIR}/${DOMINIO}/ffuf/${DOMINIO}_ffuf_final.txt | grep '^200' | awk '{print $3}' >> ${DOMINIO}_urlsfull_parcial.txt
				fi

				if [ -f ${MIDIR}/${DOMINIO}/gau/${DOMINIO}_gau.txt ]; then
					cat ${MIDIR}/${DOMINIO}/gau/${DOMINIO}_gau.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g'>> ${DOMINIO}_urlsfull_parcial.txt
				fi

				if [ -f ${MIDIR}/${DOMINIO}/paramspider/output/${DOMINIO}_paramspider.txt ]; then
					cat ${MIDIR}/${DOMINIO}/paramspider/output/${DOMINIO}_paramspider.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g'>> ${DOMINIO}_urlsfull_parcial.txt
				fi

				sort ${DOMINIO}_urlsfull_parcial.txt | uniq >> ${DOMINIO}_urlsfull_final.txt

				# estas van para arjun
				egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|bmp|eot|ico|js)" ${DOMINIO}_urlsfull_final.txt >> ${DOMINIO}_urlsfull_final_para_arjun_pre.txt
				cat ${DOMINIO}_urlsfull_final_para_arjun_pre.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g' >> ${DOMINIO}_urlsfull_final_para_arjun_pre_vivas.txt
				grep "?" ${DOMINIO}_urlsfull_final_para_arjun_pre_vivas.txt | grep -v '%EF%BF%BD' >> ${DOMINIO}_urlsfull_final_parametros.txt
				grep -Ei '(\.php|\.asp|\.aspx|\.jsp|\.jsf|\.do|\.html|\.htm|\.xhtml)' ${DOMINIO}_urlsfull_final_para_arjun_pre_vivas.txt >> ${DOMINIO}_urlsfull_final_para_arjun.txt
				rm ${DOMINIO}_urlsfull_final_para_arjun_pre.txt
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
			}


			funcion_screenshots () {
				### capturando imagenes ###
				echo "$(tput setab 1) [-] screenshots$(tput sgr 0)"
				capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final.txt")
				if [ $capacidad0 == 0 ]; then
					echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
				else
					cd ${MIDIR}/${DOMINIO}/eyewitness
					python3 ~/tools/EyeWitness/Python/EyeWitness.py --web --timeout 20 --delay 3 --threads 2 -f ${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_para_arjun_pre_vivas.txt --no-prompt -d screens >/dev/null 2>/dev/null
					echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
				fi
			}

			funcion_arjun () {
				### busco parametros ###
				echo "$(tput setab 1) [-] arjun$(tput sgr 0)"
				if [ -f "${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_para_arjun.txt" ]; then
					capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_para_arjun.txt")

					if [ $capacidad0 == 0 ]; then
						echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
					else
						cd ~/tools/Arjun
						python3 arjun.py -t 2 -d 2 --get --stable --urls "${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_para_arjun.txt" -o "${MIDIR}/${DOMINIO}/arjun/${DOMINIO}_arjun.txt" >> "${MIDIR}/${DOMINIO}/arjun/${DOMINIO}_arjun_2.txt" 2>/dev/null
						echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
					fi
				fi	
			}


			funcion_aron () {
				### busco parametros ###
				echo "$(tput setab 1) [-] Aron$(tput sgr 0)"
				cd ${MIDIR}/${DOMINIO}/aron
				if [ -f "${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_para_arjun.txt" ]; then
					capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_para_arjun.txt")

					if [ $capacidad0 == 0 ]; then
						echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
					else

						for DOM in $(cat "${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_para_arjun.txt"); do
							Aron -u ${DOM} -g -w ${ARONDIC} >> ${DOMINIO}_aron.txt >/dev/null 2>/dev/null ;done
						echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
					fi
				fi	
			}


			funcion_urlsfull_y_arjun () {
				cd ${MIDIR}/${DOMINIO}/urlsfull
				echo "$(tput setab 1) [-] urlsfull_y_arjun (merge urls)$(tput sgr 0)"
				if [ -f "${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros.txt" ]; then
					capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros.txt")
					if [ $capacidad0 == 0 ]; then
						echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
					else
						cp "${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros.txt" ${DOMINIO}_urlsfull_final_parametros_final.txt
						if [ -f "${MIDIR}/${DOMINIO}/arjun/${DOMINIO}_arjun.txt" ]; then
							capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/arjun/${DOMINIO}_arjun.txt")
							if [ $capacidad0 != 0 ]; then
								cat "${MIDIR}/${DOMINIO}/arjun/${DOMINIO}_arjun.txt" >> "${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros.txt"
							fi
						fi

						if [ -f "${MIDIR}/${DOMINIO}/aron/${DOMINIO}_aron.txt" ]; then
							capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/aron/${DOMINIO}_aron.txt")
							if [ $capacidad0 != 0 ]; then
								grep 'URL =>' "${MIDIR}/${DOMINIO}/aron/${DOMINIO}_aron.txt" | cut -d '>' -f2 | sed 's/ //g' >> "${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros.txt"
							fi
						fi

						sort "${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros.txt" | uniq >> "${MIDIR}/${DOMINIO}/urlsfull/${DOMINIO}_urlsfull_final_parametros_final.txt"

						echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
					fi
				fi	


			}



			funcion_urls_interesantes () {
				echo "$(tput setab 1) [-] Urls interesantes (Urls interesantes)$(tput sgr 0)"
				### urls_interesantes ###
				cd ${MIDIR}/${DOMINIO}/urls_interesantes/
				## Servicio de https://twitter.com/ArthusuxD
				curl -s -k "http://arthusu.com/crawler/controllers/procesar_urls_interesantes.php?dominio=${DOMINIO}" -o ${DOMINIO}.txt
				if [ -f "${DOMINIO}.txt" ]; then
					capacidad0=$(wc -c <"${DOMINIO}.txt")
					if [ $capacidad0 == 0 ]; then
						echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
					else	
						grep -Eio '(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]' ${DOMINIO}.txt | sort | uniq| egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|bmp|eot|ico)" >> ${DOMINIO}_lo_que_quiero.txt
						grep -Ei '(\.txt|\.zip|\.rar|\.tar|\.php|\.asp|\.aspx|\.sql|\.dump|\.gz|\.log|\.xml|\.jsp|\.jsf|\.html|\.htm|\.db|\.do|\.db3|\.pl|\.py\.json)' ${DOMINIO}_lo_que_quiero.txt >> ${DOMINIO}_archivos_interesantes_full.txt
						grep -i -E "(^https?://${DOMINIO})" ${DOMINIO}_archivos_interesantes_full.txt >> ${DOMINIO}_archivos_interesantes.txt
						capacidad0=$(wc -c <"${DOMINIO}_archivos_interesantes.txt")
						if [ $capacidad0 == 0 ]; then
							echo "$(tput setab 5)   [-] [NO hay URLs]$(tput sgr 0)"
						else
							echo "$(tput setab 2)   [-] [Hay URLs]$(tput sgr 0)"
							cat ${MIDIR}/${DOMINIO}/urls_interesantes/${DOMINIO}_archivos_interesantes.txt | hakcheckurl 2>/dev/null | grep '^200' | sed 's/200 //g' >> ${DOMINIO}_urls_interesantes_vivas.txt
						fi
					fi
				fi		
			}


			funcion_notificaciones_fin () {
				echo "$(tput setab 1) [-] Notificaciones$(tput sgr 0)"
				echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"

				
				#xsstrike
				if [ -f "${MIDIR}/${DOMINIO}/XSStrike/${DOMINIO}_xsstrike.html" ]; then
					grep -i VULN -c "${MIDIR}/${DOMINIO}/XSStrike/${DOMINIO}_xsstrike.html">/dev/null 2>/dev/null
					if [ $? -eq 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE XSStrike" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [TIENE XSStrike]$(tput sgr 0)"
					fi
				fi


				#sratarun
				if [ -f "${MIDIR}/${DOMINIO}/sratarun/${DOMINIO}_sratarun.html" ]; then
					grep -i 'Reflection Found' -c "${MIDIR}/${DOMINIO}/sratarun/${DOMINIO}_sratarun.html">/dev/null 2>/dev/null
					if [ $? -eq 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE sratarun" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [TIENE sratarun]$(tput sgr 0)"
					fi
				fi


				#kxss
				if [ -f "${MIDIR}/${DOMINIO}/kxss/${DOMINIO}_urlsfull_kxss.html" ]; then
					capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/kxss/${DOMINIO}_urlsfull_kxss.html")
					if [ $capacidad0 != 1183 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE kxss" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [TIENE kxss]$(tput sgr 0)"
					fi
				fi

				#js
				ls ${MIDIR}/${DOMINIO}/js/js/ | grep -i js -c >/dev/null 2>/dev/null
				if [ $? -eq 0 ]; then
					curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE JS" >/dev/null 2>/dev/null
					echo "$(tput setab 2)   [-] [TIENE JS]$(tput sgr 0)"
				fi

				#github
				if [ -f "${MIDIR}/${DOMINIO}/github/github_secret.html" ]; then
					capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/github/github_secret.html")
					if [ $capacidad0 != 1183 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE GITSECRET" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [TIENE GITSECRET]$(tput sgr 0)"
					fi
				fi

				if [ -f "${MIDIR}/${MIDIR}/${DOMINIO}/github/github_endpoints.html" ]; then
					capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/github/github_endpoints.html")
					if [ $capacidad0 != 1183 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE GITENDPOINTS" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [TIENE GITENDPOINTS]$(tput sgr 0)"
					fi
				fi

				#eyewitness
				ls "${MIDIR}/${DOMINIO}/eyewitness/screens/report.html" >/dev/null 2>/dev/null
				if [ $? -eq 0 ]; then
					curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE SCREENSHOTS" >/dev/null 2>/dev/null
					echo "$(tput setab 2)   [-] [TIENE SCREENSHOTS]$(tput sgr 0)"
				fi

				#dalfox
				if [ -f "${MIDIR}/${DOMINIO}/dalfox/${DOMINIO}_dalfox.html" ]; then
					grep -i found -c "${MIDIR}/${DOMINIO}/dalfox/${DOMINIO}_dalfox.html">/dev/null 2>/dev/null
					if [ $? -eq 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE DALFOX" >/dev/null 2>/dev/null
					fi
				fi

					#dalfoxB
				if [ -f "${MIDIR}/${DOMINIO}/xssb/${DOMINIO}_xssb.html" ]; then
					grep -i found -c "${MIDIR}/${DOMINIO}/xssb/${DOMINIO}_xssb.html">/dev/null 2>/dev/null
					if [ $? -eq 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE DALFOX XSSB" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [TIENE DALFOX XSSB]$(tput sgr 0)"
					fi
				fi



				#ffuf
				if [ -f "${MIDIR}/${DOMINIO}/ffuf/${DOMINIO}_ffuf_final.txt" ]; then
					capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/ffuf/${DOMINIO}_ffuf_final.txt")
					if [ $capacidad0 != 0 ]; then
						capacidad1=$(grep -c 200 <"${MIDIR}/${DOMINIO}/ffuf/${DOMINIO}_ffuf_final.txt")
						if [ $capacidad1 != 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE FFUF" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [TIENE FFUF]$(tput sgr 0)"
						fi
					fi
			    fi


			   	#aron
				if [ -f "${MIDIR}/${DOMINIO}/aron/${DOMINIO}_aron.txt" ]; then
					capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/aron/${DOMINIO}_aron.txt")
					if [ $capacidad0 != 0 ]; then
						capacidad1=$(grep -c 'URL =>' <"${MIDIR}/${DOMINIO}/aron/${DOMINIO}_aron.txt")
						if [ $capacidad1 != 0 ]; then
						curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE ARON" >/dev/null 2>/dev/null
						echo "$(tput setab 2)   [-] [TIENE ARON]$(tput sgr 0)"
						fi
					fi
			    fi


				#zile
				if [ -f "${MIDIR}/${DOMINIO}/zile/${DOMINIO}_zile.html" ]; then
						capacidad1=$(grep -v '[+] ' -c <"${MIDIR}/${DOMINIO}/zile/${DOMINIO}_zile.html")
						if [ $capacidad1 != 0 ]; then
								curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE ZILE" >/dev/null 2>/dev/null
								echo "$(tput setab 2)   [-] [TIENE ZILE]$(tput sgr 0)"
						fi
			    fi


			    #smuggler
				if [ -f "${MIDIR}/${DOMINIO}/smuggler/${DOMINIO}_smuggler.html" ]; then
						capacidad1=$(grep -c '[CRITICAL]' <"{MIDIR}/${DOMINIO}/smuggler/${DOMINIO}_smuggler.html")
						if [ $capacidad1 != 0 ]; then
							curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE SMUGGLER" >/dev/null 2>/dev/null
							echo "$(tput setab 2)   [-] [TIENE SMUGGLER]$(tput sgr 0)"
						fi
			    fi


			    #paramspider
				if [ -f "${MIDIR}/${DOMINIO}/paramspider/${DOMINIO}_paramspider.html" ]; then
					#paramspider
					curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="${DOMINIO} => TIENE PARAMSPIDER" >/dev/null 2>/dev/null
					echo "$(tput setab 2)   [-] [TIENE PARAMSPIDER]$(tput sgr 0)"
				fi

				curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="Finalizado => ${DOMINIO} `date +"%Y-%m-%d %H:%M"`" >/dev/null 2>/dev/null
			}

			funcion_notificaciones_comienzo
			#funcion_naabu
			funcion_ffuf
			funcion_hakrawler
			funcion_gau
			funcion_waybackurls
			funcion_urls_interesantes
			funcion_github
			funcion_paramspider
			funcion_urlsfull
			funcion_aron
			funcion_arjun
			funcion_urlsfull_y_arjun
			funcion_dalfox
			funcion_screenshots
			funcion_descargojs
			funcion_XSStrike
			funcion_SecretFinder
			funcion_kxss
			funcion_xssbb
			funcion_sqli
			funcion_sratarun
			funcion_smuggler
			funcion_zile
			funcion_notificaciones_fin
		fi
	fi
fi
