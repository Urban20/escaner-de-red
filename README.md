[![logo.png](https://i.postimg.cc/59Y21Y3Y/logo.png)](https://postimg.cc/Thx6JPBf)

> [!IMPORTANT]
antes de ejecutar la herramienta se debe abrir un terminal en el directorio y ejecutar el comando:
`pip install -r requirements.txt`
esto instala todas las librerias necesarias para la ejecucion del codigo

## Escaner de red
scip es una herramienta que integra OSINT para redes informaticas , escaneos de red de forma activa utilizando socket , busquedas de ips de forma aleatorias con sus respectivos puertos y geolocalizacion.
El objetivo de esto es crear una herramienta muy versatil en el campo de las redes informaticas.

## Uso:

el script se usa en linea de comandos y su escritura es la siguiente:

python scip3.py -ip [ip objetivo] (puede ser un dominio)  [parametro]



ejemplos:

scip -ip www.google.com -s ---> esto busca automaticamente en shodan, busca su geolocalizacion y su reputacion

scip -ip www.google.com -a ---> realiza un escaneo "agresivo". Se trata de un escaneo en multihilo lo cual lo hace muy rapido pero no siempre funciona

scip -ip www.google.com -n ---> es un escaneo mas lento pero mas fiable, hace ping a la ip y se basa en dicha latencia para regular la velocidad del escaneo, puede usarse con -i para obtener encabezados de paginas web, tambien puede usarse con -t para proporcionar manualmente un timeout

--> para el caso de python scip3.py es igual solo que se reemplaza la palabra scip

### parametros:
  -h, --ayuda                             *muestra este mensaje

  -s, --shodan                            *busqueda automatica en shodan

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

  -d, --descubrir                          *se utiliza para descubrir ips privadas dentro de la red.
                                            ejemplo de uso:
                                           -ip 192.168.0.x (ip con "x" para buscar variaciones de la ip en ese sitio) -d (parametro para usar la funcion) 
    
  -hl, --hilo                              *se utiliza con -a 
                                            setea la cantidad de hilos en paralelo (16 hilos por defecto)

> **algunas demostraciones graficas de como se usa el script:**

[![demo1.png](https://i.postimg.cc/90ZVN27C/demo1.png)](https://postimg.cc/BPSdXdpV)

[![demo2.png](https://i.postimg.cc/pXQRf2vB/demo2.png)](https://postimg.cc/w7BCHY7t)

[![demo3.png](https://i.postimg.cc/FH9mG2sX/demo3.png)](https://postimg.cc/pp1gLcFs)

> [!WARNING]
no se recomienda poner un numero muy alto para el parametro b ya que esta funcion consume APIS con un numero finito de solicitudes por minuto, si se excede el limite se debe esperar una hora para que tu ip sea desbloqueada
