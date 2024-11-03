## Escaner de red
scip es una herramienta que integra OSINT para redes informaticas , escaneos de red de forma activa utilizando socket , busquedas de ips de forma aleatorias con sus respectivos puertos y geolocalizacion.
El objetivo de esto es crear una herramienta muy versatil en el campo de las redes informaticas.

## uso:

el script se usa en linea de comandos y su escritura es la siguiente:

scip -ip [ip objetivo] (puede ser un dominio)  [parametro]

ejemplos:

scip -ip www.google.com -s ---> esto busca automaticamente en shodan, busca su geolocalizacion y su reputacion

scip -ip www.google.com -a ---> realiza un escaneo "agresivo". Se trata de un escaneo en multihilo lo cual lo hace muy rapido pero no siempre funciona

scip -ip www.google.com -n ---> es un escaneo mas lento pero mas fiable, hace ping a la ip y se basa en dicha latencia para regular la velocidad del escaneo, puede usarse con -i para obtener encabezados de paginas web, tambien puede usarse con -t para proporcionar manualmente un timeout

### parametros:
  -h, --ayuda                             *muestra este mensaje

  -s, --shodan                            *busqueda automatica en shodan, si no encuentra nada busca en fofa

  -n, --normal                            *escaneo de puertos con el metodo normal

  -a, --agresivo                          *escaneo agresivo: escanea todos los puertos en simultaneo.
                                            Desventaja/s: puede fallar
                                            Ventaja/s: extremadamente rapido

  -p SELECTIVO, --selectivo SELECTIVO     *para escanear puertos puntuales

  -ip IP, --ip IP                         *ip objetivo para el ataque

  -b BUSCAR, --buscar BUSCA               *Uso: este parametro se utiliza solo, su uso es -b [numero]
                                           funcion: busqueda de ips, puede utilizarse junto con -g para guardar

  -g, --guardar                           *Uso: este parametro se combina con el parametro -b
                                           funcion: guardar ips en lista

  -i, --info                              *Uso: este parametro se combina con -a y -n
                                           funcion: muestra informacion de los encabezados en caso de encontrarse un puerto que apunta a un html

  -l, --lectura                           *lee el archivo scannerip.txt y muestra su contenido

  -t, --timeout                           *setea un timeout especifico cuando se utiliza el parametro -n

  -m, --masivo                            *Uso: este parametro se combina con los parametros -a y -n
                                           funcion: escanea TODOS los puertos existentes. 
                                           Desventaja/s: escaneo mucho mas lento, puede ser de alta carga para el pc si se lo combina con -a
                                           Ventaja/s: permite escanear todos los puertos

  -cls, --borrar                           *borra el contenido del archivo .txt donde se guardan las ips encontradas
 
  -abrir, --abrir                          *lee el archivo .txt donde se guardan las ips encontradas
