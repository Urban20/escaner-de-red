Instrucciones Generales:
El script incluye un menú interactivo que permite ejecutar comandos desde la consola. Al iniciar el script, verás un logo y las opciones de comandos disponibles:

____________________comandos__________________________
| -cls: borrar consola                                  |
| -salir: cerrar el programa                            |
| -insertar ip: busca en Shodan o Fofa                  |
| -b [numero]: buscar IPs                               |
| -scan: descubre puertos de una IP privada o pública   |
|______________________________________________________ |
CSección 1: Comandos Básicos
Estos comandos son útiles para interactuar con el programa de manera general.

cls: Limpia la consola y vuelve a mostrar el logo y los comandos disponibles. Es útil para reiniciar la vista si la consola está saturada.
salir: Finaliza la ejecución del programa.
Sección 2: Escaneos de Puertos
El script ofrece tres tipos de escaneos para IPs privadas o públicas. Dependiendo del escenario, podés elegir entre las siguientes opciones:

Escaneo Normal
Este tipo de escaneo revisa los puertos más comunes de la IP seleccionada. Utiliza un método lineal y ajusta el timeout según la latencia de la red.

Uso: scan [IP]
Ejemplo: scan 192.168.1.1
Si la IP corresponde a la puerta de enlace (por ejemplo, tu router), el script ajusta el tiempo de espera (timeout) según la latencia de la red local. Es un método confiable para redes rápidas.

Escaneo Agresivo
El escaneo agresivo es más rápido porque utiliza múltiples hilos para revisar los puertos en paralelo. Está pensado para obtener resultados rápidamente, pero puede que algunos puertos no respondan si la red es lenta.

Uso: scan [IP]
Ejemplo: scan 192.168.1.10
En este caso, el script revisa una lista extensa de puertos predefinidos. Si no se encuentran puertos abiertos, podés forzar un escaneo normal utilizando el siguiente método.

Forzar Escaneo Normal con la opción -n
Si el escaneo agresivo no da resultados, se puede forzar el escaneo normal para tener mayor precisión, aunque sea un poco más lento.

Uso: scan [IP] -n
Ejemplo: scan 192.168.1.10 -n
Este método también ajusta el timeout según la latencia, similar al escaneo normal, pero está pensado para situaciones donde la red es más lenta o los puertos no responden al escaneo agresivo.

Escaneo Selectivo
Si querés escanear puertos específicos en lugar de escanear todos, podés usar la opción p seguida de los números de puerto, separados por comas.

Uso: scan [IP]p[puertos]
Ejemplo: scan 192.168.1.10p80,443
Este tipo de escaneo te permite ahorrar tiempo si solo estás interesado en puertos concretos.

Guardar Resultados
En cualquiera de los escaneos, si se encuentran puertos abiertos, el script te va a preguntar si querés guardar los resultados en un informe. Si seleccionás la opción, te pedirá que ingreses un título y los datos se guardarán en el archivo scannerip.txt.

Sección 3: Búsquedas de IPs Aleatorias
Podés usar el script para buscar IPs públicas aleatorias, obteniendo información como su ubicación geográfica y los puertos abiertos.

Uso: b [número de IPs]
Ejemplo: b 3 buscará 3 IPs públicas aleatorias.
El script mostrará información detallada sobre cada IP, incluyendo:

País y región.
Puertos abiertos (basados en Shodan).
Información del dispositivo, si está disponible.
Después de la búsqueda, podés optar por guardar los resultados en el archivo busqueda_ips.txt.

Sección 4: Búsquedas en Shodan y FOFA
El script permite buscar información detallada de una IP o un dominio utilizando servicios como Shodan y FOFA. Esto incluye:

Puertos abiertos.
Servicios detectados (SSH, HTTP, etc.).
Información geográfica (país, ciudad, ISP).
Búsqueda en Shodan
Si ingresás una IP o dominio válido, el script hace una consulta a Shodan para obtener información:

Uso: Ingresá directamente una IP o dominio.
Ejemplo: 8.8.8.8
Te mostrará detalles como los puertos abiertos, servicios detectados, y una geolocalización básica. También intentará detectar si el puerto está relacionado con servicios como SSH o HTTP.

Búsqueda en FOFA
Si Shodan no ofrece resultados, el script automáticamente hace una consulta a FOFA (otro servicio similar). Los resultados también incluyen puertos abiertos y servicios asociados, pero con un enfoque más global.

Sección 5: Informes
El script te permite generar informes automáticos sobre los puertos encontrados, ya sea a través de un escaneo o una búsqueda de IPs.

Informe de escaneos: Si encontrás puertos abiertos durante un escaneo, el script te preguntará si querés guardar un informe. Si aceptás, los detalles se guardarán en scannerip.txt.
Informe de búsqueda de IPs: Las búsquedas de IPs aleatorias también pueden guardarse en busqueda_ips.txt si elegís la opción de guardar.
