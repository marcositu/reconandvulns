#!/bin/bash
# parallel + curl + oneliner
# https://asciinema.org/a/4V7b4fojnDqVt6hrAub71ryNk

cat alive-subdomains.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t  Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk
