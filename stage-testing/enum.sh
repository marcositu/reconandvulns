#!/bin/bash

# Basic ReC0n -> Tools -> assetfinder | findomain | httprobe 
# https://github.com/Edu4rdSHL/findomain# 
# https://github.com/tomnomnom/assetfinder
# https://github.com/tomnomnom/httprobe

# argument parser
if [ $# -lt "1" ]; then
        echo "Usage:  $0 domain.tld"
        exit 1;
fi


# delete existing files
rm -rf alive.txt
rm -rf domains.txt


#running assetfinder
echo "[+] Checking for subdomains.. [assetfinder]"
~/go/bin/assetfinder --subs-only $1 | tee -a domains.txt  > /dev/null
wc -l domains.txt

#starting findomain
echo "[+] Checking for subdomains.. [findomain]"
findomain -t $1 -q >> domains.txt
wc -l domains.txt

#removing duplicate entries
sort -u domains.txt -o domains.txt 

#checking for alive domains + adding some interesting ports
echo "[+] Checking for alive domains.. [httprobe]"
cat domains.txt | ~/go/bin/httprobe -c 50 -p 8080,8081,8089 | tee -a alive.txt > /dev/null

echo "[domains.txt]: `wc -l domains.txt`";
echo "[alive.txt]: `wc -l alive.txt`";
