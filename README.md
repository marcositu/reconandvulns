# reconandvulns
[![bash](https://img.shields.io/badge/-bash-bash)](https://github.com/marcositu/reconandvulns/tree/master/)

As a first step we try to obtain as many subdomains as possible (***onlydomain.sh***) and by using diferent tools, we run an analysis on each one separately (***reconandvulns.sh***).

To run these scripts, you must install the tools. The procedure to install the tools is on the ***tools.txt*** file.

It should be noted that the scripts are not linked, so the 2nd part must be executed manually.

I apologize for the code, but it's not my strong 😕

#  Setting Up the Container
docker pull marcositu/reconandvulns:v1

docker run -it --name reconandvulns -v ~/tools/Bounties/:/root/tools/Bounties/ marcositu/reconandvulns:v2 bash
