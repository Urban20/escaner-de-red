import requests
from colorama import Fore
import socket
import ipaddress
from random import randint
import params
import data
from time import time,sleep
from bs4 import BeautifulSoup
from ping3 import ping
from threading import Lock
from platform import system
if system() == 'Windows':
    import keyboard

deten = False   
q = 0
n = 0

def fingerprint_no_HTTP(ip,puerto):
    try:
        data = 'test'

        s = socket.socket()

        s.settimeout(3)
        s.connect((ip,puerto))
        s.send(data.encode())
        return str(f'[{s.recv(1024).decode()}]')
    
    except UnicodeDecodeError:
        return str(f'[{s.recv(1024)}]')
    except:
        return None

def fingerprint_HTTP(ip,puerto):
    for x in ['https','http']:
        try: 
            dic=dict(requests.get(f'{x}://{ip}:{str(puerto)}',timeout=5).headers)
            break
        except requests.exceptions.SSLError:
            dic = None
            continue
        except:
            dic = None
    return dic

def preg_informe(ip,lista):
    preg = str(input(Fore.WHITE+'[1]guardar informe ').strip())
    if preg == '1':
        titulo = str(input('titulo: '))
        crear_informe(params.param.ip,data.p_abiertos,titulo)

def cuerpo_scan(lista,ip,timeout):
    #para el escaneo selectivo y normal: este es el formato para estos dos tipos de escaneos
    global q
    # q solo se utiliza con normal
    global deten

    for x in lista:
        if not deten:
            s = socket.socket()
                    
            s.settimeout(timeout)

            try:
                s.connect((ip,int(x)))
                print(Fore.GREEN+f'[►] abierto: {x}')

                print(f'uso mas comun: {data.descripciones[int(x)]}')
                data.p_abiertos.append(int(x))
            except KeyError:
                print(f'uso mas comun: [desconocido]')
                data.p_abiertos.append(int(x))
            except TimeoutError:

                continue
            except PermissionError:
                print(Fore.RED+f'[X] sin permisos para escanear el puerto: {x}')
                continue  
            except socket.gaierror as e:
                print(Fore.RED+f'[X] error: {e}')
                deten = True
            except ConnectionRefusedError:
                pass
           
            except Exception as e:
                print(Fore.RED+f'[X] ocurrio un error:{e}')
                
            finally:
                s.close()
                q+=1
        else:
            break

def abrir_arch():
    try:
        with open(data.nombre_b,'r') as arch:
            print(arch.read())
        
    except FileNotFoundError:
        print(Fore.RED+'no se pudo encontrar el archivo')

def borrar_arch():
    with open(data.nombre_b,'w') as arch:
        arch.write('')
        
def ayuda():
    
    h = Fore.WHITE+'''
scip 3.0 es una herramienta de reconocimiento de redes desarrollada por Urb@n con busqueda en shodan y escaneo de redes, entre otras cosas

parametros:
  -h, --ayuda                             *muestra este mensaje

  -s, --shodan                            *busqueda automatica en shodan

  -n, --normal                            *escaneo de puertos con el metodo normal

  -a, --agresivo                          *escaneo agresivo: escanea todos los puertos en simultaneo
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
    
    '''
    print('''
##################################################################################################''')
    print(data.logo)
    print(h)
    print('''
##################################################################################################''')
    print(data.autor)

def informacion(ip,puerto):
    #fing1 ---> fingerprint n 1: se encarga de conexiones de tranf. de hipertexto
    # fing2 ---> fingerprint n 2: si fing1 falla se hace envia un msg al puerto para intentar obtener info
    fing1= fingerprint_HTTP(ip,puerto)
    fing2=fingerprint_no_HTTP(ip,puerto)

    print(Fore.WHITE+f'''
#################################################
puerto:{puerto}\n''')
    if fing1 != None:
        for x in fing1:
            print(Fore.GREEN+f' {x}:{fing1[x]}')
    
    elif fing2 != None:
        print(Fore.GREEN+' '+fing2)
    
    if fing2 == None and fing1 == None:
        print(Fore.RED+' sin informacion')

    print(Fore.WHITE+'''
#################################################
            ''') 

def confiabilidad_ip(ip):
    url = 'https://barracudacentral.org/lookups/lookup-reputation'
    if requests.get(url).status_code == 200:
        print(Fore.WHITE+'''
confiabilidad de la ip:''')
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
            return Fore.YELLOW+f'* {data.status[solicitud.status_code]}'
    
    except requests.Timeout:
        return Fore.RED+'* no responde: tiempo agotado'
    except Exception :
        return Fore.RED+'* no responde'
    
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


        with open(data.nombre_arch,'a') as arch:
            arch.write(informe)
    except Exception as e:
        print(f'ocurrio un error: {e}')

def detener():
    global q,n,deten
   
    tamaño_list_i = len(data.puertos)
    tiempo = time()
    if params.param.buscar == None:
        while not deten:
            
            try:
                if system() == 'Windows':
                    if keyboard.is_pressed('esc'):
                        print(Fore.RED+'deteniendo')
                        
                        deten = True
            except AttributeError:
                pass

            finally:
                
                val_prog = (q/tamaño_list_i) * 100
                porcentaje =f'{str(val_prog)[:5]}%'
                    
                if time() - tiempo > 5:
                    print(Fore.CYAN+f'progreso: {porcentaje}')
                    tiempo = time()
                if porcentaje == '100.0%':
                    print(Fore.GREEN+'script finalizado')
                    deten= True
            
    else:
        try:
            while n < params.param.buscar and not deten:
                if keyboard.is_pressed('esc'):
                    print(Fore.RED+'deteniendo')
                    deten = True
        except AttributeError:
            pass
def latencia(ip):
    try:
        latencias = []
        ping_ = 0

        for i in range(3):
            latencias.append(ping(ip))
        
        for x in latencias:
            ping_+=x
            
        return ping_/3
    except TypeError:
        return 1
    
def scan_normal(ip,timeout):
    
    print(Fore.WHITE+f'escaneando puertos TCP de la ip: {ip}')
    try:
        for x in data.puertos :
            
            cuerpo_scan(ip=ip,timeout=timeout,lista=data.puertos)

       
    except Exception as e:
        print(Fore.RED+f'ocurrio un error:{e}')

    finally:
    
        if data.p_abiertos:
            if params.param.info:
                for x in data.p_abiertos:
                    informacion(params.param.ip,x)
           
            sleep(1)
            
            preg_informe(ip=params.param.ip,lista=data.p_abiertos)
                  
        data.p_abiertos.clear()

def scan_selectivo(ip,timeout,puertos):
    
    eleccion = list(puertos.split(','))
    cuerpo_scan(ip=ip,lista=eleccion,timeout=timeout)


def scan_agresivo(ip,puerto):
    timeout = 3
    
    try:  
        ipaddress.ip_address(ip)    
         
        s = socket.socket()       
        s.settimeout(timeout)

        try:
            s.connect((ip.strip(),puerto))
            print(Fore.GREEN+f'[►] abierto: {puerto}\n servicio mas probable: {data.descripciones.get(puerto)}')
            with data.cerradura:
                data.p_abiertos.append(puerto)
                
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
            data.elementos.append(str(randint(0,255)))

        ip = ipaddress.ip_address('.'.join(data.elementos))
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
            if params.param.guardar:      
                with open(data.nombre_b,'a') as ip_lista:
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

ipv4= []
lock = Lock()  
def descubrir_red(ip,i,timeout):
    try:
        direc = ip.replace('x',str(i))
        ping_=ping(direc,timeout=timeout)
        if ping_ != None and ping_ != False:
            print(Fore.WHITE+direc)
            with lock:
                ipv4.append(direc)
    
    except:
        pass