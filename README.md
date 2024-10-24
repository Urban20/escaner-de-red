esta es una herramienta pensada para escanear ips en busca de puertos abiertos.
la herramienta cuenta con varios tipos de escaneos, los cuales son:

1-escaneo normal

2-escaneo agresivo

3-escaneo selectivo

Ademas el script realiza busquedas automaticas en shodan con el objetivo de respaldar informacion que pueda ser de utilidad,tambien cuenta con geolocalizacion de la ip en cuestion,reputacion de la ip, entre otras cosas 
los parametros son:

-h o --ayuda : muestra el mensaje de ayuda

-s: busca en shodan o en fofa dependiendo de la informacion que encuentre de la ip

-n: sirve para informar al script que se desea hacer un escaneo normal,(se escanean los puertos uno por uno con un tiempo de espera el cual depende de la latencia que existe a la ip a escanear)

-a : escaneo agresivo (escaneo de puertos de forma repentina el cual utiliza varios hilos en paralelo , es un escaneo extremadamente rapido pero suele fallar en redes publicas)

-p, seguido de los puertos que se desean escanear (escaneo selectivo)

-i: sirve para mostrar encabezados de las paginas en caso de que un puerto este relacionado a un sitio web 

-b, seguido de un numero entero: sirve para buscar direcciones ips aleatorias con el objetivo de escanear sus puertos

-t sirve para setear un timeout especifico al utilizarse con -n

-g (guardar) se utiliza con el parametro -b, si el parametro -g esta siendo utilizado, se creara un txt donde se guardaran las ips que se encuentren en el script
