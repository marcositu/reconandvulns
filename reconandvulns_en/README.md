# reconandvulns.sh
* The idea of this tools is to identify URLs, parameters, JS files among other information about a domain.
* This tool needs to load various APIs.
* Modify working and tools directories.
* This tool sends notifications using Telegram Groups, which must be configured adding the ChatID and the API.


# Considerations
* You can use the file ***tools.txt*** to install the necessary tools and configure the APIs:
  * dirb, naabu, waybackurls, hakrawler, linkFinder, arjun, eyewitness, XSStrike, dalfox, ffuf, gau, kxss, paramspider, aron, hinject, colorized-logs, github-search, screen, curl, zile, smuggler and DSSS.
  * You must have a Telegram Group or Chat for notifications
  * o	You must modify the following variables:
    * **MIDIR**: Work Directory
    * **TELEAPI**: Telegram API
    * **CHATID**: Telegram Chat ID or Group ID
    * **BXSS**: Our URL from “xss.ht” for testing Blind XSS
    * **FFUFDIC**: Dictionary that will be used for the tool “ffuf”.
    * **DIRBLISTA**: Dictionary that will be used for the tool “dirb”

```
Usage: ./reconandvulns.sh http://testphp.vulnweb.com
```

<img src="https://i.ibb.co/1Mj7Fn5/2020-06-07-14-29.png" width="60%" height="60%">

We have several functions on this tool:

## funcion_notificaciones_comienzo ##
This function sends a notification at the beginning of the tests.

## funcion_naabu ##
This function realizes a TCP Port Scan
https://github.com/projectdiscovery/naabu

## funcion_ffuf ##
This function search URLs with defined extension to begin with the URLs harvesting. 
https://github.com/ffuf/ffuf

## funcion_hakrawler ## 
This function makes a Crawler of the URL
https://github.com/hakluke/hakrawler

## funcion_gau ## 
This function makes a Crawler of the URL
https://github.com/lc/gau

## funcion_waybackurls ## 
This function searches .js files in Wayback Machine
https://github.com/tomnomnom/waybackurls

## funcion_urls_interesantes ## 
This function searches URLs in Arthusu web, which is in charge of making a massive URL haversting
http://arthusu.com/

## funcion_github ##
This function searches sensitive information of the domain on Github
https://github.com/gwen001/github-search

## funcion_paramspider ## 
This function searches parameters in the URLs using the tool Paramspider
https://github.com/devanshbatham/ParamSpider

## funcion_urlsfull ##
This function realizes a sort|uniq of everything we had collected

## funcion_aron ##
This function searches parameters in the URLs using the tool Aron
https://github.com/m4ll0k/Aron

## funcion_arjun ##
This function searches parameters in the URLs using the tool Arjun
https://github.com/s0md3v/Arjun

## funcion_dalfox ## 
This function searches for XSS vulnerabilities using the tool Dalfox
https://github.com/hahwul/dalfox

## funcion_screenshots ## 
This function takes screenshots of every URLs we have collected so far
https://github.com/FortyNorthSecurity/EyeWitness

## funcion_hinject ##
This function search if it’s possible to inject the Host Header using the tool Hinject
https://github.com/dwisiswant0/hinject

## funcion_descargojs ##
This function download and analyze all the JS files
https://github.com/GerbenJavado/LinkFinder

## funcion_XSStrike ##
This function searches for XSS vulnerabilities using the tool XSStrike
https://github.com/s0md3v/XSStrike

## funcion_kxss ##
This function searches for XSS vulnerabilities using the tool Kxss
https://github.com/tomnomnom/hacks/kxss

## funcion_xssb ##
This function searches for XSS vulnerabilities using the tool Dalfox.

## funcion_sqli ##
This function searches SQLi vulnerabilities using the tool DSSS
https://github.com/stamparm/DSSS

## funcion_sratarun ##
This function searches XSS vulnerabilities using the command https://twitter.com/sratarun/status/1268137973427527680?s=20

## funcion_notificaciones_fin ## 
This function sends a notification with all the results to the Telegram Group

<img src="https://i.ibb.co/NmLjX4K/2020-06-07-14-53.png" width="60%" height="60%">
