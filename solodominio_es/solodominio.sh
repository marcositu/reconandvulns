	#!/bin/bash

if [[ -z $1 ]]; then
     echo "Uso: $0 dominio"
 else

	DOMINIO=${1}
	FECHA=`date +"%Y%m%d"`
	MIDIR=~/tools/Bounties/DOMINIOS/${FECHA}
	TELEAPI="botXXXX"
	CHATID="-XXXXX"
	findomain_virustotal_token="XXXXX"
    findomain_spyse_token="XXXXXXX"
    findomain_securitytrails_token="XXXXX"

	mkdir -p ${MIDIR}/${DOMINIO}
	mkdir -p ${MIDIR}/${DOMINIO}/amass
	mkdir -p ${MIDIR}/${DOMINIO}/assetfinder
	mkdir -p ${MIDIR}/${DOMINIO}/sublist3r
	mkdir -p ${MIDIR}/${DOMINIO}/knockpy
	mkdir -p ${MIDIR}/${DOMINIO}/eyewitness
	mkdir -p ${MIDIR}/${DOMINIO}/naabu
	mkdir -p ${MIDIR}/${DOMINIO}/findomain
	mkdir -p ${MIDIR}/${DOMINIO}/shodan

	echo "$(tput setab 7)[+] $DOMINIO$(tput sgr 0)"

	funcion_notificaciones_comienzo () {
		curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="Comenzando => ${DOMINIO} `date +"%Y-%m-%d %H:%M"`" >/dev/null 2>/dev/null
	}

	funcion_findomain () {
		echo "$(tput setab 1) [-] findomain$(tput sgr 0)"
		findomain-linux -o -t ${DOMINIO} -r
		mv ${DOMINIO}.txt ${MIDIR}/${DOMINIO}/findomain/${DOMINIO}.txt
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}


	funcion_securitytrails () {
		echo "$(tput setab 1) [-] securitytrails$(tput sgr 0)"
		curl -s "https://api.securitytrails.com/v1/domain/${DOMINIO}/subdomains?apikey=${findomain_securitytrails_token}" | jq -r '.subdomains[]' | awk '{print $0"'."$DOMINIO"'"}' | tee ${MIDIR}/${DOMINIO}/${DOMINIO}.txt
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}


	funcion_amass () {
	echo "$(tput setab 1) [-] amass$(tput sgr 0)"
	amass enum -d ${DOMINIO} -p 9002,27015,81,8443,8888,8843,60443,10443,4443,80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017 -o ${MIDIR}/${DOMINIO}/amass/amass_${DOMINIO}.txt
	cat ${MIDIR}/${DOMINIO}/amass/amass_${DOMINIO}.txt >> ${MIDIR}/${DOMINIO}/${DOMINIO}.txt
	echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}

	funcion_assetfinder () {
	echo "$(tput setab 1) [-] assetfinder$(tput sgr 0)"
	assetfinder -subs-only ${DOMINIO} >> ${MIDIR}/${DOMINIO}/assetfinder/assetfinder_${DOMINIO}.txt
	echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}

	funcion_sublist3r () {
	echo "$(tput setab 1) [-] sublist3r$(tput sgr 0)"
	python3 ~/tools/Sublist3r/sublist3r.py -d ${DOMINIO} -o ${MIDIR}/${DOMINIO}/sublist3r/sublist3r_${DOMINIO}.txt
	echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}  

	funcion_merge () {
		echo "$(tput setab 1) [-] merge$(tput sgr 0)"
		cd ${MIDIR}/${DOMINIO}/
		cat ${MIDIR}/${DOMINIO}/sublist3r/sublist3r_${DOMINIO}.txt >> ${MIDIR}/${DOMINIO}/${DOMINIO}.txt
		cat ${MIDIR}/${DOMINIO}/assetfinder/assetfinder_${DOMINIO}.txt >> ${MIDIR}/${DOMINIO}/${DOMINIO}.txt
		cat ${MIDIR}/${DOMINIO}/findomain/${DOMINIO}.txt >> ${MIDIR}/${DOMINIO}/${DOMINIO}.txt
		sort ${MIDIR}/${DOMINIO}/${DOMINIO}.txt | sed 's/[[:blank:]]//g' | uniq >> ${MIDIR}/${DOMINIO}/${DOMINIO}_ultimo.txt
		cat ${MIDIR}/${DOMINIO}/${DOMINIO}_ultimo.txt | fprobe -p xlarge >> ${MIDIR}/${DOMINIO}/${DOMINIO}_pre_final.txt
		sort -u ${MIDIR}/${DOMINIO}/${DOMINIO}_pre_final.txt >> ${MIDIR}/${DOMINIO}/${DOMINIO}_final.txt
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"

	}

	funcion_knockpy () {
		echo "$(tput setab 1) [-] knockpy$(tput sgr 0)"
		cd ${MIDIR}/${DOMINIO}/knockpy
		knockpy -c ${DOMINIO}
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
		cat *.csv | cut -d , -f4 >> ${MIDIR}/${DOMINIO}/${DOMINIO}_ultimo.txt
	}

	funcion_naabu () {
		echo "$(tput setab 1) [-] naabu$(tput sgr 0)"
		cd ${MIDIR}/${DOMINIO}/naabu
		naabu -ports full -hL ${MIDIR}/${DOMINIO}/${DOMINIO}_final.txt -exclude-ports 2000,5060 -o ${DOMINIO}_naabu.txt -silent
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	} 

	funcion_eyewitness () {
		echo "$(tput setab 1) [-] eyewitness$(tput sgr 0)"
		cd ${MIDIR}/${DOMINIO}/eyewitness
		python3 ~/tools/EyeWitness/Python/EyeWitness.py --web --timeout 20 --delay 3 --threads 2 -f ${MIDIR}/${DOMINIO}/${DOMINIO}_final.txt --no-prompt -d screens >/dev/null 2>/dev/null
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
	}

	funcion_shodan () {
		echo "$(tput setab 1) [-] shodan$(tput sgr 0)"
		capacidad0=$(wc -c <"${MIDIR}/${DOMINIO}/eyewitness/screens/open_ports.csv")
		if [ $capacidad0 == 0 ]; then
				echo "$(tput setab 5)   [-] [NO HAY IP]$(tput sgr 0)"
		else
		cd ${MIDIR}/${DOMINIO}/shodan

		for i in $(awk -F/ '{print $3}' ${MIDIR}/${DOMINIO}/eyewitness/screens/open_ports.csv | cut -d : -f1 | cut -d , -f1 | sed '/^$/d' | sort -u | xargs -l dig -t a +short | sort  -u | cf-check) ; do
		python3 ~/tools/Shodanfy.py/shodanfy.py ${i} --getvuln --getports --getinfo --getbanner >> ${MIDIR}/${DOMINIO}/shodan/${i}.txt 2>/dev/null; done
		echo "$(tput setab 2)   [-] [OK]$(tput sgr 0)"
		fi
	} 

	funcion_notificaciones_fin () {
		curl -s -X POST "https://api.telegram.org/${TELEAPI}/sendMessage" -d chat_id="${CHATID}" -d text="Finalizado => ${DOMINIO} `date +"%Y-%m-%d %H:%M"`" >/dev/null 2>/dev/null
	}

	funcion_notificaciones_comienzo
	funcion_securitytrails
	funcion_amass
	funcion_assetfinder
	funcion_sublist3r
	funcion_knockpy
	funcion_findomain
	funcion_merge
	#funcion_naabu
	funcion_eyewitness
	#funcion_shodan
	funcion_notificaciones_fin
fi
