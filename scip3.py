import requests,ipaddress,socket,random,subprocess,threading,pandas,argparse,keyboard,pprint,time
from bs4 import BeautifulSoup
from colorama import init,Fore
import base64

#elementos -------------

status = {
    100: "Continue: El servidor ha recibido los encabezados de la solicitud y el cliente puede continuar enviando el cuerpo de la solicitud.",
    101: "Switching Protocols: El servidor acepta cambiar el protocolo de comunicación (como de HTTP a WebSocket).",
    102: "Processing: El servidor ha recibido la solicitud, pero aún no ha terminado de procesarla (utilizado en WebDAV).",
    200: "OK: La solicitud ha sido procesada con éxito y el servidor devuelve los datos solicitados.",
    201: "Created: La solicitud ha tenido éxito y ha resultado en la creación de un recurso.",
    202: "Accepted: La solicitud ha sido aceptada, pero aún no se ha completado el procesamiento.",
    203: "Non-Authoritative Information: La respuesta contiene información no verificada proveniente de un tercero.",
    204: "No Content: La solicitud ha tenido éxito, pero el servidor no devuelve ningún contenido.",
    205: "Reset Content: Similar a 204, pero indica al cliente que debe reiniciar la vista o formulario.",
    206: "Partial Content: El servidor devuelve parte del contenido solicitado, generalmente en respuesta a solicitudes de rango.",
    300: "Multiple Choices: Hay varias opciones para el recurso solicitado y el cliente debe elegir una.",
    301: "Moved Permanently: El recurso solicitado ha sido movido de manera permanente a una nueva URL.",
    302: "Found: El recurso ha sido movido temporalmente a otra URL (usualmente se utiliza para redirecciones).",
    303: "See Other: El servidor sugiere al cliente una nueva URL para obtener el recurso usando el método GET.",
    304: "Not Modified: El recurso no ha cambiado desde la última solicitud, por lo que el cliente puede usar una versión en caché.",
    305: "Use Proxy: El recurso solicitado solo está disponible a través de un proxy.",
    307: "Temporary Redirect: Similar a 302, pero el método de la solicitud no debe cambiar (se debe usar el método original).",
    308: "Permanent Redirect: Similar a 301, pero garantiza que el método no cambie (usado en redirecciones permanentes).",
    400: "Bad Request: La solicitud contiene sintaxis incorrecta o no puede ser procesada por el servidor.",
    401: "Unauthorized: La solicitud requiere autenticación. El cliente debe autenticarse para obtener la respuesta.",
    402: "Payment Required: Este código es reservado para usos futuros (originalmente pensado para sistemas de pago).",
    403: "Forbidden: El cliente no tiene permiso para acceder al recurso solicitado, incluso si ha sido autenticado.",
    404: "Not Found: El recurso solicitado no ha sido encontrado en el servidor.",
    405: "Method Not Allowed: El método HTTP utilizado no está permitido para el recurso solicitado.",
    406: "Not Acceptable: El recurso no está disponible en el formato solicitado.",
    407: "Proxy Authentication Required: Similar a 401, pero requiere autenticación a través de un proxy.",
    408: "Request Timeout: El servidor agotó el tiempo de espera antes de recibir la solicitud completa.",
    409: "Conflict: Hay un conflicto con el estado actual del recurso (usualmente relacionado con solicitudes PUT).",
    410: "Gone: El recurso solicitado ya no está disponible y no se espera que vuelva a estarlo.",
    411: "Length Required: El servidor requiere que la solicitud incluya el encabezado Content-Length.",
    412: "Precondition Failed: Una condición en los encabezados de la solicitud no ha sido cumplida por el servidor.",
    413: "Payload Too Large: El servidor rechaza la solicitud porque el cuerpo es demasiado grande.",
    414: "URI Too Long: La URI solicitada es demasiado larga para ser procesada por el servidor.",
    415: "Unsupported Media Type: El servidor no puede manejar el tipo de medio solicitado en la solicitud.",
    416: "Range Not Satisfiable: El cliente ha solicitado una porción de un archivo que el servidor no puede proporcionar (usualmente en solicitudes de rango).",
    417: "Expectation Failed: El servidor no puede cumplir con los requisitos del encabezado Expect de la solicitud.",
    500: "Internal Server Error: El servidor encontró una condición inesperada que le impidió completar la solicitud.",
    501: "Not Implemented: El servidor no tiene soporte para la funcionalidad requerida para procesar la solicitud.",
    502: "Bad Gateway: El servidor recibió una respuesta inválida de un servidor upstream mientras actuaba como gateway o proxy.",
    503: "Service Unavailable: El servidor no está disponible, generalmente debido a sobrecarga o mantenimiento.",
    504: "Gateway Timeout: El servidor acting como gateway no recibió una respuesta a tiempo de un servidor upstream.",
    505: "HTTP Version Not Supported: El servidor no soporta la versión del protocolo HTTP utilizada en la solicitud."
}

descripciones = {
    20: 'Transferencia de datos.',
    21: 'transferencia de archivos.',
    22: 'SSH (Secure Shell)',
    23: 'Telnet ',
    25: 'SMTP – Envío de correos electrónicos.',
    53: 'Resolución de nombres de dominio.',
    67: 'Asignación de direcciones IP en redes.',
    68: 'asignación de direcciones IP.',
    69: 'Transferencia de archivos simple.',
    80: 'Navegación web sin cifrar.',
    110: 'Recepción de correos electrónicos.',
    115: 'Transferencia simple de archivos (obsoleto).',
    135: 'Comunicación entre procesos en redes Windows.',
    137: 'Uso en redes locales de Windows para compartir archivos.',
    138: 'NetBIOS Datagram Service.',
    139: 'Uso en redes locales de Windows para compartir archivos.',
    143: 'Recepción de correos con acceso remoto a buzón.',
    161: 'Administración de red.',
    162: 'Notificaciones de SNMP.',
    443: 'HTTPS - Navegación web cifrada.',
    445: 'compartición de archivos en Windows.',
    465: 'Envío de correos electrónicos cifrados.',
    514: 'Envío de logs de sistema a servidores remotos.',
    587: 'Envío de correos electrónicos cifrados con seguridad adicional.',
    631: 'Protocolo de impresión en red.',
    993: 'IMAPS (IMAP over SSL) – IMAP cifrado.',
    995: 'POP3S (POP3 over SSL) – POP3 cifrado.',
    3306: 'MySQL – Conexión a bases de datos MySQL.',
    3389: 'Acceso remoto a escritorio de Windows.',
    5432: 'Conexión a bases de datos PostgreSQL.',
    5900: 'Acceso remoto a escritorios.',
    6379: 'Redis – Base de datos en memoria',
    1194: 'OpenVPN – Servicio de VPN seguro.',
    1433: 'Base de datos SQL de Microsoft.',
    1434: 'Monitoreo de SQL Server.',
    1521: 'Oracle DB – Conexión a bases de datos Oracle.',
    1723: 'VPN menos segura.',
    2049: 'compartición de archivos',
    2082: 'Acceso al panel de control web cPanel.',
    2083: 'cPanel con cifrado SSL.',
    8080: 'HTTP alternativo',
    8443: 'HTTPS alternativo',
    8888: 'HTTP alternativo',
    7547: 'Gestión remota de dispositivos',
    119: 'Transferencia de artículos de noticias Usenet.',
    515: 'Servicio de impresión en red.',
    6667: 'Comunicación en tiempo real mediante chat.'
}
#----------------------------------
init()
 
#funciones----------------------------------------------------------------------------

def ayuda():
    logo =Fore.RED+r'''
    
┌────────────────────────────────────────────────────────────────────────────┐
│ ________  ________  ________  ________   ________   _______   ________     │
│|\   ____\|\   ____\|\   __  \|\   ___  \|\   ___  \|\  ___ \ |\   __  \    │
│\ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \ \  \\ \  \ \   __/|\ \  \|\  \   │
│ \ \_____  \ \  \    \ \   __  \ \  \\ \  \ \  \\ \  \ \  \_|/_\ \   _  _\  │
│  \|____|\  \ \  \____\ \  \ \  \ \  \\ \  \ \  \\ \  \ \  \_|\ \ \  \\  \| │
│    ____\_\  \ \_______\ \__\ \__\ \__\\ \__\ \__\\ \__\ \_______\ \__\\ _\ │
│   |\_________\|_______|\|__|\|__|\|__| \|__|\|__| \|__|\|_______|\|__|\|__|│
│   \|_________|                                                             │
│                                                                            │
│                                                                            │
│              ___  ________                                                 │
│             |\  \|\   __  \                                                │
│ ____________\ \  \ \  \|\  \                                               │
│|\____________\ \  \ \   ____\                                              │
│\|____________|\ \  \ \  \___|                                              │
│                \ \__\ \__\                                                 │
│                 \|__|\|__|     hecho por Urb@n                             │
└────────────────────────────────────────────────────────────────────────────┘
    Version 3.0   
    
    '''
    h = Fore.WHITE+'''
scip 3.0 es una herramienta de reconocimiento de redes desarrollada por Urb@n con busqueda en shodan y escaneo de redes, entre otras cosas

parametros:
  -h, --ayuda                             *muestra este mensaje
  -s, --shodan                            *busqueda automatica en shodan, si no encuentra nada busca en fofa

  -n, --normal                            *escaneo de puertos con el metodo normal

  -a, --agresivo                          *escaneo agresivo: escanea todos los puertos en simultaneo (puede fallar)
  -p SELECTIVO, --selectivo SELECTIVO     *para escanear puertos puntuales
  -ip IP, --ip IP                         *ip objetivo para el ataque
  -b BUSCAR, --buscar BUSCA               *busqueda de ips, puede utilizarse junto con -g para guardar
  -g, --guardar                           *guardar ips en lista
  -i, --info                              *muestra informacion de los encabezados en caso de encontrarse un puerto que apunta a un html
  -l, --lectura                           *lee el archivo scannerip.txt y muestra su contenido
  -t, --timeout                           *setea un timeout especifico cuando se utiliza el parametro -n
    '''
    print('''
##################################################################################################''')
    print(logo)
    print(h)
    print('''
##################################################################################################''')

def informacion(ip,puerto):

    dic = None
    
   
    for x in ['https','http']:

        try: 
            dic=dict(requests.get(f'{x}://{ip}:{str(puerto)}',timeout=5).headers)
        except:
            pass
            
        finally:
            if dic != None:
                    print(Fore.WHITE+f'''
#################################################
puerto:{puerto}                 ''')
                    pprint.pp(dic)
                    print('''
#################################################
                    ''') 

deten = False            
q = 0


def puerta_de_enlace():
    return str(subprocess.check_output('ipconfig')).split(':')[-1][:-5].strip()

def confiabilidad_ip(ip):
    url = 'https://barracudacentral.org/lookups/lookup-reputation'
    if requests.get(url).status_code == 200:
        print(Fore.WHITE+'confiabilidad de la ip:')
        try:
            dir_ = ipaddress.ip_address(ip) 

            if dir_.is_global:
                valores = []
                
                with requests.session() as s:

                    html = BeautifulSoup(s.get(url).text,'html.parser')

                    for x in html.find_all('input'):
                        
                        valores.append(x.get('value'))
                    key = str(valores[1])


                    datos_post ={'lookup_entry':ip,
                            'submit':'Check Reputation',
                            'cid':key}
                    
                    
                    for i in ['success-message','failure-message']:
                        try:
                            html_post= BeautifulSoup(s.post(url,data=datos_post).text,'html.parser')

                            html_post.find('p',class_=i).text.strip()
                            return i
                        except AttributeError:
                            continue
            else:
                return 'no valida'
        except  ValueError:
            return 'no valida' 
    
def rastreo(url):
    try:
        datos = {'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'}
        solicitud= requests.get(url,timeout=5,headers=datos)
        if solicitud.status_code == 200:
            return Fore.GREEN+'* responde'
            
        else:
            return Fore.YELLOW+f'* {status[solicitud.status_code]}'
    
    except requests.Timeout:
        return Fore.RED+'* no responde: tiempo agotado'
    except Exception :
        return Fore.RED+'* no responde'

def shodan(arg_ip):   
    ip = socket.gethostbyname(arg_ip)
    if ipaddress.ip_address(ip).is_global:
        

        try:
            ip_api= requests.get(f'http://ip-api.com/json/{ip}')
            shodan= requests.get(f'https://internetdb.shodan.io/{ip}')
            geo = requests.get(f'http://www.geoplugin.net/json.gp?ip={ip}')
            
            if shodan.status_code == 200:
                print(Fore.GREEN+f'''
                    
 ____                             
|info|
|____|

#################################################                                                       
-ip:{shodan.json()['ip']}
-puertos: {shodan.json()['ports']}
-nombre de host:{shodan.json()['hostnames']}
-tipo de dispositivo:{shodan.json()['tags']}
#################################################''')

                if geo.status_code == 200 and ip_api.status_code == 200:
                    print(
    f'''
 _________________ 
| geolocalizacion:|
|_________________|

#################################################
-pais:{geo.json()['geoplugin_countryName']}
-ciudad:{geo.json()['geoplugin_city']}
-estado/prov:{geo.json()['geoplugin_regionName']}
-ISP:{ip_api.json()['isp']}
-org:{ip_api.json()['org']}
#################################################''')

                    
            
        except Exception as e:
            print(f'ocurrio un error: {e}')
        finally:        

            fiabilidad = confiabilidad_ip(arg_ip)
            if fiabilidad != None:
                
                if fiabilidad == 'failure-message':
                    print(Fore.RED+'en la lista negra')
                elif fiabilidad == 'no valida':
                    print(Fore.YELLOW+'no se puede documentar la confiabilidad de la ip')
                elif fiabilidad == 'success-message':
                    print(Fore.CYAN+'ip sin rastros maliciosos')

    #bloque del webscrapping a shodan
    print(Fore.RED+'''
        
###########                      
shodan
###########        ''')
    try:
        #fecha de cada escaneo de cada puerto
        scan = []
        #protocolos que se maneja /udp o tcp
        proto = []
        #informacion del puerto en cuestion
        info = []
        
        html = BeautifulSoup(requests.get(f'https://www.shodan.io/host/{ip}').content,'html.parser')
        contenido= html.find('div',class_='container u-full-width card-padding')
        links = contenido.find_all('a',class_='link')
        protocolos = contenido.findAll('span')
        informacion = contenido.find_all('div',class_='card card-padding banner')
        fecha_scan = html.find_all(class_='u-pull-right text-secondary')

        for x in fecha_scan:
            scan.append(x.text.split('T')[0].split('|')[1].strip())



        for protocolo in protocolos: 
            if 'tcp' in str(protocolo.get_text()) or 'udp' in str(protocolo.get_text()):

                proto.append(protocolo.get_text().strip())
            elif 'Last Seen' in str(protocolo.get_text()):
                print(Fore.WHITE+f'ultimo scaneo de shodan: {protocolo.get_text().strip()[10:]}')

        for info_ in informacion:
            
            
            if 'html'in str(info_.get_text()) in str(info_.get_text()) and len(info_.get_text()) > 650:
                info.append('posible pagina web')
                    
            elif 'ssh' in str(info_.get_text()).lower() and len(info_.get_text()) > 650:
                info.append('posible servicio ssh')
                
            else:
                
                info.append(info_.get_text().strip())
                    
        for protocol,infor,fecha_scaneo in zip(proto,info,scan):
            print(f'''
#################################################''')
            print(Fore.GREEN+f'''
fecha del puerto escaneado: {fecha_scaneo}''')   
            print(Fore.WHITE+f'''                    
 _________                    
|protocolo|
|_________|
                
{protocol[:-5].strip()} {protocol[-4:]}
 ____________________
|servicio involucrado|
|____________________|

    {infor}
#################################################''')
        if links:       
            print('''
            
 _______________    
|     links     |
|_______________|
            ''')
        
            for link in links:
                url = link.get('href')
                print(Fore.WHITE+str(url))
                print(rastreo(url))

    except AttributeError:
        try:
            if ipaddress.ip_address(param.ip).is_global:

                print(Fore.RED+'ningun puerto ni servicio encontrado')
                print(Fore.RED+'''
#################################################                

###########
fofa
###########
                ''')

                puerto_list= []
                banners= []

                codificiacion = base64.b64encode(arg_ip.encode())
                html_f= BeautifulSoup(requests.get(f'https://en.fofa.info/result?qbase64={codificiacion.decode()}').content,'html.parser')
                banner = html_f.find_all('div',class_='el-scrollbar__view')
                puerto = html_f.find_all('a',class_='hsxa-port')
                


                for x in banner:
                    banners.append(x.text)
                for y in puerto:
                    puerto_list.append(y.get_text().strip())


                for puert,ban in zip(puerto_list,banners):
                    print(Fore.WHITE+f'''
#################################################
puerto:
{puert}                    

servicio:   

{ban} ''')                   

                print(Fore.WHITE+'''
#################################################''')
        except:
            pass        
    except Exception as e:
        print(f'ocurrio un error: {e}')



def crear_informe(ip,puerto,titulo):
    try:
        informe=f'''
##############################
titulo : {titulo}
ip: {ip}

puertos por defecto abiertos:
{puerto}
##############################
        '''


        with open(nombre_arch,'a') as arch:
            arch.write(informe)
    except Exception as e:
        print(f'ocurrio un error: {e}')

def detener():
    global q,n,deten
   
    tamaño_list_i = len(puertos)
    tiempo = time.time()
    if param.buscar == None:
        while not deten:
            

            if keyboard.is_pressed('esc'):
                print(Fore.RED+'deteniendo')
                
                deten = True

            val_prog = (q/tamaño_list_i) * 100
            porcentaje =f'{str(val_prog)[:5]}%'
                
            if time.time() - tiempo > 5:
                print(Fore.CYAN+f'progreso: {porcentaje}')
                tiempo = time.time()
            if porcentaje == '100.0%':
                print(Fore.GREEN+'script finalizado')
                deten= True
    else:
        while n < param.buscar and not deten:
            if keyboard.is_pressed('esc'):
                print(Fore.RED+'deteniendo')
                deten = True
                
def latencia(ip):
    
    try:
        output= str(subprocess.run(f'ping {ip} -w 1000',capture_output=True)).split('=')
        min_ = int(output[-2].split('m')[0])
        med_ = int(output[-3].split('m')[0])
        max_= int(output[-4].split('m')[0])
        
        
        #latencia de la conexion en seg
        if ((min_ + med_ + max_) / 3) /1000 != 0:
            return ((min_ + med_ + max_) / 3) /1000
        else:
            return 0.01
    except ValueError:
        return 1

def scan_normal(ip,timeout):
    global q
    global deten
    print(Fore.WHITE+f'escaneando puertos TCP de la ip: {ip}')
    try:
        for x in puertos :
            if not deten:
                s = socket.socket()
                    
                s.settimeout(timeout)

                try:
                    s.connect((ip.strip(),x))
                    print(Fore.GREEN+f'abierto: {x}')

                    print(f'uso mas comun: {descripciones[x]}')
                    
                    p_abiertos.append(x)
                except KeyError:
                    print(f'uso mas comun: [desconocido]')
                    p_abiertos.append(x)
                    
                except TimeoutError:
                        
                        
                    continue
                except PermissionError:
                    print(Fore.RED+f'sin permisos para escanear el puerto: {x}')
                except ConnectionRefusedError:
                    continue
                except Exception as e:
                    print(Fore.RED+f'ocurrio un error:{e}')
                
                finally:
                    s.close()
                    q+=1
        
            else:
                
                break
    except Exception as e:
        print(Fore.RED+f'ocurrio un error:{e}')

    finally:
    
        if p_abiertos:
            if param.info:
                for x in p_abiertos:
                    informacion(param.ip,x)
           
            time.sleep(1)
            preg = str(input(Fore.WHITE+'[1]guardar informe ').strip())
            if preg == '1':
                titulo = str(input('titulo: '))
                crear_informe(param.ip,p_abiertos,titulo)
                  
        p_abiertos.clear()

def scan_selectivo(ip,timeout,puertos):
    
    eleccion = list(puertos.split(','))
    for x in eleccion:

        s = socket.socket()
                
        s.settimeout(timeout)

        try:
            s.connect((ip,int(x)))
            print(Fore.GREEN+f'abierto: {x}')

            print(f'uso mas comun: {descripciones[int(x)]}')
            p_abiertos.append(int(x))
        except KeyError:
            print(f'uso mas comun: [desconocido]')
            p_abiertos.append(int(x))
        except TimeoutError:
            print(Fore.RED + f'tiempo agotado, puerto: {x}')
            continue
        except PermissionError:
            print(Fore.RED+f'sin permisos para escanear el puerto: {x}')
                
        except Exception as e:
            print(Fore.RED+f'ocurrio un error:{e}')
        finally:
            s.close()

def dataf():
    
    dataf = pandas.DataFrame({
    'puertos:':p_abiertos,
    'uso mas común:':descrip
    }).to_string()
    
    return dataf

def scan_agresivo(ip,puerto):
    timeout = 3
    
    try:  
        ipaddress.ip_address(ip)    
         
        s = socket.socket()       
        s.settimeout(timeout)

        try:
            s.connect((ip.strip(),puerto))
            with cerradura:
                descrip.append(descripciones[puerto])
                p_abiertos.append(puerto)
                
                
            
        except KeyError:
            with cerradura:
                descrip.append('[desconocido]')
                p_abiertos.append(puerto)

                
        except TimeoutError:
                      
            pass
        except PermissionError:
            print(Fore.RED+f'sin permisos para escanear el puerto: {puerto}')
        except OSError:
            pass      
        except Exception as e:
            print(Fore.RED+f'ocurrio un error:{e}')
		    
        finally:
            s.close()
               
    except ValueError:
        pass
         
def buscar():
    
    try:
        

        for x in range(4):
            elementos.append(str(random.randint(0,255)))

        ip = ipaddress.ip_address('.'.join(elementos))
        if ip.is_global:
            geo= requests.get(f'http://www.geoplugin.net/json.gp?ip={ip}').json()
            shodan= requests.get(f'https://internetdb.shodan.io/{ip}').json()
        
            if list(shodan['ports']):

                info_b= f'''
    ip:{geo['geoplugin_request']}
    pais:{geo['geoplugin_countryName']}
    estado/prov:{geo['geoplugin_region']}
    puertos:{shodan['ports']}

    '''
            if param.guardar:      
                with open('ips_encontradas.txt','a') as ip_lista:
                    ip_lista.write(info_b)

            return info_b
        
    except:
        pass

def timeout(latencia_prom):

    print(f'latencia promedio:{latencia_prom} seg')
    #para redes relativamente rapidas
    if latencia_prom >= 0.015 and latencia_prom <= 0.3:
        timeout = latencia_prom * 2
#para redes muy lentas
    elif latencia_prom > 0.3:
        timeout = latencia_prom * 1.5
    else:
        #timeout minimo para redes locales
        timeout = 0.1
    return timeout
#funciones----------------------------------------------------------------------------


if __name__ == '__main__':
    puertos = [
        1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 
        85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222,
        254, 255, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481,
        497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648,
        666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880,
        888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1007, 1009, 1010, 1011, 1021, 
        1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041,
        1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061,
        1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081,
        1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102,
        1104, 1105, 1106, 1107, 1108, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154,
        1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233,
        1234, 1236, 1244, 1247, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417,
        1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666,
        1687, 1688, 1700, 1717, 1718, 1720, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875,
        1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999,2000, 2001,2002,2003,2004,2005,2006,2007,2008,2009,
        2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065,
        2068,2082,2083,2099,2100,2103,2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196,
        2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601,
        2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2920, 2967, 2998,
        3000, 3001, 3003, 3005, 3006, 3011, 3013, 3017, 3030, 3050, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3268, 3283,
        3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517,
        3527, 3546, 3551, 3580, 3659, 3689, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871,
        3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4045, 4111,
        4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998,
        5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5120, 5190, 5200,
        5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431,5432, 5440, 5500, 5544, 5550, 5555, 5560, 5566, 5631,
        5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901,
        5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5987, 5988, 5989, 5998,
        5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346,6379,
        6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789,
        6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435,
        7443, 7496, 7512, 7547, 7624, 7627, 7676, 7741, 7777, 7778, 7800, 7801, 7900, 7901, 7902, 7903, 7911, 7920, 7921, 7937, 7938,
        7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085,
        8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300,
        8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8880, 8883, 8888, 8899, 8994, 9000,
        9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200,
        9207, 9220, 9290, 9415, 9418, 9443, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9943,
        9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 
        10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722,
        13724, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016,
        16018, 17988, 18040, 18181, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800,
        25793, 25826, 25900, 25901, 27444, 27500, 27715, 28201, 30000, 30718, 31038, 31337, 32768, 32769, 32770, 32771, 32772,
        32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572,
        34573, 35500, 38292, 40193, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
        49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493,
        51494, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443,
        61532, 61900, 62078, 63331, 65129, 65389
    ]

    descrip = []
    elementos=[]
    cerradura = threading.Lock()
    nombre_arch = 'scannerip.txt'

    p_abiertos= []
    args = argparse.ArgumentParser(description='scip2 es una herramienta de reconocimiento de redes desarrollada por Urb@n con busqueda en shodan y escaneo de redes, entre otras cosas',
        usage='escribir el parametro -h o --ayuda para ver las funciones disponibles',add_help=False)

    args.add_argument('-s','--shodan',action=argparse.BooleanOptionalAction)
    args.add_argument('-n','--normal',action=argparse.BooleanOptionalAction)
    args.add_argument('-a','--agresivo',action=argparse.BooleanOptionalAction)
    args.add_argument('-p','--selectivo',type=str)
    args.add_argument('-ip','--ip',type=str)
    args.add_argument('-b','--buscar',type=int)
    args.add_argument('-g','--guardar',action=argparse.BooleanOptionalAction)
    args.add_argument('-i','--info',action=argparse.BooleanOptionalAction)
    args.add_argument('-h','--ayuda',action=argparse.BooleanOptionalAction)
    args.add_argument('-l','--lectura',action=argparse.BooleanOptionalAction)
    args.add_argument('-t','--timeout',type=float)
    
    param = args.parse_args()


    #acciones de los parametros-----------------
    if param.shodan:
        try:
            if param.ip != None:
                print(Fore.WHITE+'''
#################################################''')
                print(Fore.RED+'iniciando inteligencia en shodan')
                shodan(param.ip)
            else:
                print(Fore.RED+'especificar parametro [-ip]')
        except Exception as e:
            print(f'''error al buscar en shodan:
    {e}
    ''')

    if param.agresivo:
        try:
            if param.ip != None:
                print(Fore.WHITE+'''
#################################################''')
                print(Fore.WHITE+'escaneo agresivo en curso...')
                for x in puertos:
                    hilo = threading.Thread(target=scan_agresivo,args=(param.ip,x))
                    hilo.start()
                if p_abiertos:

                    print(dataf())
                    if param.info:
                        for x in p_abiertos:
                            informacion(param.ip,x)

                    preg = str(input(Fore.WHITE+'[1]guardar informe ').strip())
                    if preg == '1':
                        titulo = str(input('titulo: '))
                        crear_informe(param.ip,p_abiertos,titulo)
                else:
                    print(Fore.RED+'no se encontro ningun puerto')
                

            else:
                print(Fore.RED+'especificar parametro [-ip]')        
        except Exception as e:
            print(Fore.RED+f'''error al escanear con metodo agresivo:
    {e}''')
        finally:
            p_abiertos.clear()
            
    elif param.normal and param.buscar == None:
        if param.ip != None:
    
            hilo3 = threading.Thread(target=detener)
            
            print(Fore.WHITE+f'''
#################################################''')
            print(Fore.WHITE+'escaneo normal en curso...')
            
            if param.timeout == None:
                lat_prom= latencia(param.ip)
                tim = timeout(lat_prom)
            else:
                tim = param.timeout
            print(f'timeout: {tim}')
            hilo3.start()   
            scan_normal(param.ip,tim)   
            
        else:
            print(Fore.RED+'especificar parametro [-ip]') 

    elif param.selectivo:
        if param.ip != None:
            print(Fore.WHITE+'''
#################################################''')
            print(Fore.WHITE+'escaneo selectivo en curso...')
            lat_sel_prom = latencia(param.ip)
            tim_sel = timeout(lat_sel_prom)
            print(f'timeout: {tim_sel}')
            scan_selectivo(param.ip,tim_sel,param.selectivo)
            if param.info:
                for x in p_abiertos:
                    informacion(param.ip,x)

        else:
            print(Fore.RED+'especificar parametro [-ip]')

    if param.buscar != None and not param.normal:
        try:
            n = 0
            hilo2 = threading.Thread(target=detener)
            hilo2.start()
            while n < param.buscar:
                if not deten:
                    busq = buscar()
                    elementos.clear()
                    if busq != None:
                        print(busq)
                        n+=1
                else:
                    break
        except Exception as e:
            print(f'''ocurrio un error:
    {e}''')

    if param.ayuda:
        ayuda()

    if param.lectura:
        try:
            with open(nombre_arch,'r') as registro:
                print(Fore.CYAN+registro.read())
        except FileNotFoundError:
            print(Fore.RED+'registro no encontrado')
                
    #acciones de los parametros-----------------