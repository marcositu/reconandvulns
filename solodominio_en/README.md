# onlydomain.sh
* The idea of this tools is to identify URLs, parameters, JS files among other information about a domain.
* This tool needs to load various APIs.
* Modify working and tools directories.
* This tool sends notifications using Telegram Groups, which must be configured adding the ChatID and the API.


# Considerations
* You can use the file ***tools.txt*** to install the necessary tools and configure the APIs:
  * amass, assetfinder, sublist3r, knockpy, aquatone, naabu, findomain y shodanfy.
  * You must have a Telegram Group or Chat for notifications.
  * o	You must modify the following variables:
    * **MYDIR**: Work Directory.
    * **TELEAPI**: Telegram API.
    * **CHATID**: Telegram Chat ID or Group ID
    * **findomain_virustotal_token**: Token from Virus Total
    * **findomain_spyse_token**: Token from Spyse
    * **findomain_securitytrails_token**: Token from securitytrails

```Usage: ./onlydomain.sh testphp.vulnweb.com```

We have several functions on this tool:

## funcion_notificaciones_comienzo ##
This function sends a notification at the beginning of the tests.

## funcion_securitytrails ##
This function search on securitytrails
https://api.securitytrails.com/

## funcion_amass ##
This function search on amass
https://github.com/OWASP/Amass

## funcion_assetfinder ## 
This function search on assetfinder
https://github.com/tomnomnom/assetfinder

## funcion_sublist3r ## 
This function search on sublist3r
https://github.com/aboul3la/Sublist3r

## funcion_knockpy ## 
This function search on knockpy
https://github.com/guelfoweb/knock

## funcion_findomain ## 
This function search on findomain
https://github.com/Edu4rdSHL/findomain

## funcion_merge ##
This function merge all the results.

## funcion_naabu ## 
This function makes a TCP Scan Port.
https://github.com/projectdiscovery/naabu

## funcion_aquatone ##
This function use aquatone to get screenshots.
https://github.com/michenriksen/aquatone

## funcion_notificaciones_fin ## 
This function sends notifications to the Telegram Group when the analysis finished.
