# reconandvulns.sh
* La idea es identificar urls, parametros, archivos javascript entre otra información de un dominio.
* Para el funcionamiento se necesitan cargar varias API
* Modificar directorios de tools y de trabajo.
* Se envian notificaciones mediante un grupo de telegram, por lo cual se debe agregar el CHATID y la API

# Consideraciones
* Se puede utilizar el archivo **tools.txt** para instalar las **herramientas** necesarias y configurar las **API**:
  * naabu, waybackurls, hakrawler, linkFinder, arjun, eyewitness, XSStrike, dalfox, ffuf, gau, kxss, paramspider, hinject, colorized-logs, github-search, screen, curl, zile, smuggler y DSSS.
  * Se debe tener un grupo o chat de telegram para que funcionen las notificaciones.
  * Se deben modificar las siguientes variables:
    * **MIDIR**: Directorio de trabajo
    * **TELEAPI**: Api de telegram
    * **CHATID**: ID del chat y/o grupo de telegram
    * **BXSS**: Nuestra URL de xss.ht para probar Blind XSS
    * **FFUFDIC**: Diccionario que se usará para la herramienta ffuf

```
Uso: ./reconandvulns.sh http://testphp.vulnweb.com
```

<img src="https://i.ibb.co/1Mj7Fn5/2020-06-07-14-29.png" width="60%" height="60%">

Tenemos varias funciones armadas:

## funcion_notificaciones_comienzo ##
Enviamos la notificación de comienzo de las pruebas

## funcion_naabu ##
Se encarga de realizar un scan port TCP
https://github.com/projectdiscovery/naabu

## funcion_ffuf ##
Se encarga de buscar URL con extensiones definidas para comenzar con la recolección de URLs.
https://github.com/ffuf/ffuf

## funcion_hakrawler ## 
Hacemos crawler de la URL
https://github.com/hakluke/hakrawler

## funcion_gau ## 
Hacemos crawler de la URL
https://github.com/lc/gau

## funcion_waybackurls ## 
Buscamos archivos .js en Wayback Machine
https://github.com/tomnomnom/waybackurls

## funcion_urls_interesantes ## 
Buscamos URLS en la web de Arthusu, la cual se encarga de hacer una recoleccin masiva de URLs
http://arthusu.com/

## funcion_github ##
Buscamos información sensible del dominio en Github
https://github.com/gwen001/github-search

## funcion_paramspider ## 
Buscamos parámtetros en las URLs mediante la herramienta Paramspider
https://github.com/devanshbatham/ParamSpider

## funcion_urlsfull ##
Se realiza un sort|uniq de todo lo recolectado

## funcion_arjun ##
Buscamos parámtetros en las URLs mediante la herramienta Arjun
https://github.com/s0md3v/Arjun

## funcion_dalfox ## 
Buscamos XSS mediante la herramienta Dalfox
https://github.com/hahwul/dalfox

## funcion_screenshots ## 
Sacamos screenshots de todas las URLs vivas que recolectamos
https://github.com/FortyNorthSecurity/EyeWitness

## funcion_hinject ##
Buscamos si se puede injectar el hostheader mediante la herramienta Hinject
https://github.com/dwisiswant0/hinject

## funcion_descargojs ##
Descargamos y analizamos todos los JS
https://github.com/GerbenJavado/LinkFinder

## funcion_XSStrike ##
Buscamos XSS mediante la herramienta XSStrike
https://github.com/s0md3v/XSStrike

## funcion_kxss ##
Buscamos XSS mediante la herramienta Kxss
https://github.com/tomnomnom/hacks/kxss

## funcion_xssb ##
Buscamos Blind XSS mediante la herramienta Dalfox

## funcion_sqli ##
Buscamos SQLi mediante la herramienta DSSS
https://github.com/stamparm/DSSS

## funcion_sratarun ##
Buscamos XSS, se uso el comando de https://twitter.com/sratarun/status/1268137973427527680?s=20

## funcion_notificaciones_fin ## 
Enviamos notificaciones de lo encontrado a un grupo de telegram

<img src="https://i.ibb.co/NmLjX4K/2020-06-07-14-53.png" width="60%" height="60%">
