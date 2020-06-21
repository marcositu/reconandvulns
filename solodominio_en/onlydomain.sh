#!/bin/bash

if [[ -z $1 ]]; then
     echo "Usage: $0 domain"
 else

	DOMAIN=${1}
	DAY=`date +"%Y%m%d"`
	MYDIR=~/tools/Bounties/DOMAINS/${DAY}
	TELEAPI="botXXXXXX"
	CHATID="-XXX"
	findomain_virustotal_token="XXXX"
        findomain_spyse_token="XXXXX"
        findomain_securitytrails_token="XXXXX"

	mkdir -p ${MYDIR}/${DOMAIN}
	mkdir -p ${MYDIR}/${DOMAIN}/amass
	mkdir -p ${MYDIR}/${DOMAIN}/assetfinder
	mkdir -p ${MYDIR}/${DOMAIN}/sublist3r
	mkdir -p ${MYDIR}/${DOMAIN}/knockpy
	mkdir -p ${MYDIR}/${DOMAIN}/eyewitness
	mkdir -p ${MYDIR}/${DOMAIN}/naabu
	mkdir -p ${MYDIR}/${DOMAIN}/findomain
	mkdir -p ${MYDIR}/${DOMAIN}/shodan

	echo "$(tput setab 7)[+] $DOMAIN$(tput sgr 0)"

	function_notifications_start () {
		curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="Starting => ${DOMAIN} `date +"%Y-%m-%d %H:%M"`" >/dev/null 2>/dev/null
	}

	function_findomain () {
		echo "$(tput setab 1) [-] findomain$(tput sgr 0)"
		findomain-linux -o -t ${DOMAIN} -r
		mv ${DOMAIN}.txt ${MYDIR}/${DOMAIN}/findomain/${DOMAIN}.txt
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}


	function_securitytrails () {
		echo "$(tput setab 1) [-] securitytrails$(tput sgr 0)"
		curl -s "https://api.securitytrails.com/v1/domain/${DOMAIN}/subdomains?apikey=${findomain_securitytrails_token}" | jq -r '.subdomains[]' | awk '{print $0"'."$DOMAIN"'"}' | tee ${MYDIR}/${DOMAIN}/${DOMAIN}.txt
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}


	function_amass () {
	echo "$(tput setab 1) [-] amass$(tput sgr 0)"
	amass enum -d ${DOMAIN} -p 9002,27015,81,8443,8888,8843,60443,10443,4443,80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017 -o ${MYDIR}/${DOMAIN}/amass/amass_${DOMAIN}.txt
	cat ${MYDIR}/${DOMAIN}/amass/amass_${DOMAIN}.txt >> ${MYDIR}/${DOMAIN}/${DOMAIN}.txt
	echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}

	function_assetfinder () {
	echo "$(tput setab 1) [-] assetfinder$(tput sgr 0)"
	assetfinder -subs-only ${DOMAIN} >> ${MYDIR}/${DOMAIN}/assetfinder/assetfinder_${DOMAIN}.txt
	echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}

	function_sublist3r () {
	echo "$(tput setab 1) [-] sublist3r$(tput sgr 0)"
	python3 ~/tools/Sublist3r/sublist3r.py -d ${DOMAIN} -o ${MYDIR}/${DOMAIN}/sublist3r/sublist3r_${DOMAIN}.txt
	echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}  

	function_merge () {
		echo "$(tput setab 1) [-] merge$(tput sgr 0)"
		cd ${MYDIR}/${DOMAIN}/
		cat ${MYDIR}/${DOMAIN}/sublist3r/sublist3r_${DOMAIN}.txt >> ${MYDIR}/${DOMAIN}/${DOMAIN}.txt
		cat ${MYDIR}/${DOMAIN}/assetfinder/assetfinder_${DOMAIN}.txt >> ${MYDIR}/${DOMAIN}/${DOMAIN}.txt
		cat ${MYDIR}/${DOMAIN}/findomain/${DOMAIN}.txt >> ${MYDIR}/${DOMAIN}/${DOMAIN}.txt
		sort ${MYDIR}/${DOMAIN}/${DOMAIN}.txt | sed 's/[[:blank:]]//g' | uniq >> ${MYDIR}/${DOMAIN}/${DOMAIN}_pre1_final.txt
		cat ${MYDIR}/${DOMAIN}/${DOMAIN}_pre1_final.txt | fprobe -p xlarge >> ${MIDIR}/${DOMINIO}/${DOMINIO}_pre2_final.txt
		sort -u ${MYDIR}/${DOMAIN}/${DOMAIN}_pre2_final.txt >> ${MYDIR}/${DOMAIN}/${DOMAIN}_final.txt
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"

	}

	function_knockpy () {
		echo "$(tput setab 1) [-] knockpy$(tput sgr 0)"
		cd ${MYDIR}/${DOMAIN}/knockpy
		knockpy -c ${DOMAIN}
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
		cat *.csv | cut -d , -f4 >> ${MYDIR}/${DOMAIN}/${DOMAIN}_final.txt
	}

	function_naabu () {
		echo "$(tput setab 1) [-] naabu$(tput sgr 0)"
		cd ${MYDIR}/${DOMAIN}/naabu
		naabu -ports full -hL ${MYDIR}/${DOMAIN}/${DOMAIN}_final.txt -exclude-ports 2000,5060 -o ${DOMAIN}_naabu.txt -silent
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	} 

	function_eyewitness () {
		echo "$(tput setab 1) [-] eyewitness$(tput sgr 0)"
		cd ${MYDIR}/${DOMAIN}/eyewitness
		python3 ~/tools/EyeWitness/Python/EyeWitness.py --web --timeout 20 --delay 3 --threads 2 -f ${MYDIR}/${DOMAIN}/${DOMAIN}_final.txt --no-prompt -d screens >/dev/null 2>/dev/null
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}

	function_shodan () {
		echo "$(tput setab 1) [-] shodan$(tput sgr 0)"
		capacidad0=$(wc -c <"${MYDIR}/${DOMAIN}/eyewitness/screens/open_ports.csv")
		if [ $capacidad0 == 0 ]; then
				echo "$(tput setab 5)   [-] [Aquatone without IPs]$(tput sgr 0)"
		else
		cd ${MYDIR}/${DOMAIN}/shodan

		for i in $(awk -F/ '{print $3}' ${MYDIR}/${DOMAIN}/eyewitness/screens/open_ports.csv | cut -d : -f1 | cut -d , -f1 |  sed '/^$/d' | sort -u | xargs -l dig -t a +short | sort  -u | cf-check) ; do
		python3 ~/tools/Shodanfy.py/shodanfy.py ${i} --getvuln --getports --getinfo --getbanner >> ${MYDIR}/${DOMAIN}/shodan/${i}.txt 2>/dev/null; done
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
		fi
	} 

	function_notifications_end () {
		curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="End => ${DOMAIN} `date +"%Y-%m-%d %H:%M"`" >/dev/null 2>/dev/null
	}

	function_notifications_start
	function_securitytrails
	function_amass
	function_assetfinder
	function_sublist3r
	function_knockpy
	function_findomain
	function_merge
	#function_naabu
	function_eyewitness
	function_shodan
	function_notifications_end
fi
