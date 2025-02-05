[![logo.png](https://i.postimg.cc/59Y21Y3Y/logo.png)](https://postimg.cc/Thx6JPBf)

> [!IMPORTANT]
antes de ejecutar la herramienta se debe abrir un terminal en el directorio y ejecutar el comando:
`pip install -r requirements.txt`
esto instala todas las librerias necesarias para la ejecucion del codigo

## Escaner de red
scip es una herramienta que integra OSINT para redes informaticas , escaneos de red de forma activa utilizando socket , busquedas de ips de forma aleatorias con sus respectivos puertos y geolocalizacion.
El objetivo de esto es crear una herramienta muy versatil en el campo de las redes informaticas.

## Caracteristicas:

-recopilacion de informacion de una ip (geolocalizacion,isp,region,puertos abiertos registrados por shodan)

-tiene varias estrategias para obtener puertos abiertos

-descubre ips dentro de una red privada e intenta obtener informacion de los dispositivos conectados ( esta ultima funcion esta disponible en Linux y termux)

-busqueda aleatoria de ips con gran posibilidad de encontrar puertos abiertos

## Uso:

el script se usa en linea de comandos y su escritura es la siguiente:

python scip3.py -ip [ip objetivo] (puede ser un dominio)  [parametro]



ejemplos:

scip -ip www.google.com -s ---> esto busca automaticamente en shodan, busca su geolocalizacion y su reputacion

scip -ip www.google.com -a ---> realiza un escaneo "agresivo". Se trata de un escaneo en multihilo lo cual lo hace muy rapido pero no siempre funciona

scip -ip www.google.com -n ---> es un escaneo mas lento pero mas fiable, hace ping a la ip y se basa en dicha latencia para regular la velocidad del escaneo, puede usarse con -i para obtener encabezados de paginas web, tambien puede usarse con -t para proporcionar manualmente un timeout

--> para el caso de python scip3.py es igual solo que se reemplaza la palabra scip

### parametros:
  
[![parametros.png](https://i.postimg.cc/50xb85xw/parametros.png)](https://postimg.cc/sB0krhGX)

> **algunas demostraciones graficas de como se usa el script:**

[![demo1.png](https://i.postimg.cc/90ZVN27C/demo1.png)](https://postimg.cc/BPSdXdpV)

[![demo2.png](https://i.postimg.cc/pXQRf2vB/demo2.png)](https://postimg.cc/w7BCHY7t)

[![demo3.png](https://i.postimg.cc/FH9mG2sX/demo3.png)](https://postimg.cc/pp1gLcFs)

> [!WARNING]
no se recomienda poner un numero muy alto para el parametro b ya que esta funcion consume APIS con un numero finito de solicitudes por minuto, si se excede el limite se debe esperar una hora para que tu ip sea desbloqueada
