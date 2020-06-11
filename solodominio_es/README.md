# solodominio.sh
* La idea es identificar subdominios, mediante el uso de varias herramientas.
* Para el funcionamiento se necesitan cargar varias API
* Modificar directorios de tools y de trabajo.
* Se envian notificaciones mediante un grupo de telegram, por lo cual se debe agregar el CHATID y la API 

# Consideraciones
* Se puede utilizar el archivo **tools.txt** para instalar las **herramientas** necesarias:
  * amass, assetfinder, sublist3r, knockpy, aquatone, naabu, findomain y shodanfy.
  * Se debe tener un grupo o chat de telegram para que funcionen las notificaciones.
  * Se deben modificar las siguientes variables:
    * **MIDIR**: Directorio de trabajo
    * **TELEAPI**: Api de telegram
    * **CHATID**: ID del chat y/o grupo de telegram
    * **findomain_virustotal_token**: Token de Virus Total
    * **findomain_spyse_token**: Token de Spyse
    * **findomain_securitytrails_token**: Token de securitytrails

```Uso: ./solodiminio.sh testphp.vulnweb.com```

Tenemos varias funciones armadas:

## funcion_notificaciones_comienzo ##
Enviamos la notificación de comienzo de las pruebas

## funcion_securitytrails ##
Buscamos en securitytrails
https://api.securitytrails.com/

## funcion_amass ##
Buscamos en amass
https://github.com/OWASP/Amass

## funcion_assetfinder ## 
Buscamos en assetfinder
https://github.com/tomnomnom/assetfinder

## funcion_sublist3r ## 
Buscamos en sublist3r
https://github.com/aboul3la/Sublist3r

## funcion_knockpy ## 
Buscamos en knockpy
https://github.com/guelfoweb/knock

## funcion_findomain ## 
Buscamos en findomain
https://github.com/Edu4rdSHL/findomain

## funcion_merge ##
Hacemos un merge de todos los resultados

## funcion_naabu ## 
Hacemos un scan TCP
https://github.com/projectdiscovery/naabu

## funcion_aquatone ##
Usamos aquatone para obtener captura de pantalla 
https://github.com/michenriksen/aquatone

## funcion_notificaciones_fin ## 
Enviamos notificaciones cuando termina el análisis a un grupo de telegram.
