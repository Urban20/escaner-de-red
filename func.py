import requests
from colorama import Fore
import socket
from subprocess import check_output,run
import ipaddress
from pprint import pp
from bs4 import BeautifulSoup
import keyboard
from random import randint
from base64 import b64encode
import params
import data
from time import time,sleep
from pandas import DataFrame


deten = False   
q = 0
n = 0

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
                    pp(dic)
                    print('''
#################################################
                    ''') 

def puerta_de_enlace():
    return str(check_output('ipconfig')).split(':')[-1][:-5].strip()

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
            return Fore.YELLOW+f'* {data.status[solicitud.status_code]}'
    
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
            
            fiabilidad = confiabilidad_ip(socket.gethostbyname(arg_ip))
            if fiabilidad != None:
                
                match fiabilidad:
                    case 'failure-message':
                        print(Fore.RED+'en la lista negra')
                    case 'no valida':
                        print(Fore.YELLOW+'no se puede documentar la confiabilidad de la ip')
                    case 'success-message':
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
            
            print(Fore.RED+'ningun puerto ni servicio encontrado')
            if ipaddress.ip_address(params.param.ip).is_global:    
                print(Fore.RED+'''
#################################################                

###########
fofa
###########
                ''')

                puerto_list= []
                banners= []

                codificiacion = b64encode(arg_ip.encode())
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
            

            if keyboard.is_pressed('esc'):
                print(Fore.RED+'deteniendo')
                
                deten = True

            val_prog = (q/tamaño_list_i) * 100
            porcentaje =f'{str(val_prog)[:5]}%'
                
            if time() - tiempo > 5:
                print(Fore.CYAN+f'progreso: {porcentaje}')
                tiempo = time()
            if porcentaje == '100.0%':
                print(Fore.GREEN+'script finalizado')
                deten= True
    else:
        while n < params.param.buscar and not deten:
            if keyboard.is_pressed('esc'):
                print(Fore.RED+'deteniendo')
                deten = True
                
def latencia(ip):
    
    try:
        output= str(run(f'ping {ip} -w 1000',capture_output=True)).split('=')
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
        for x in data.puertos :
            if not deten:
                s = socket.socket()
                    
                s.settimeout(timeout)

                try:
                    s.connect((ip.strip(),x))
                    print(Fore.GREEN+f'[►] abierto: {x}')

                    print(f'uso mas comun: {data.descripciones[x]}')
                    
                    data.p_abiertos.append(x)
                except KeyError:
                    print(f'uso mas comun: [desconocido]')
                    data.p_abiertos.append(x)
                    
                except TimeoutError:                      
                    continue
                except PermissionError:
                    print(Fore.RED+f'[X] sin permisos para escanear el puerto: {x}')
                except ConnectionRefusedError:
                    continue
                except Exception as e:
                    print(Fore.RED+f'[X]ocurrio un error:{e}')
                
                finally:
                    s.close()
                    q+=1
        
            else:
                
                break
    except Exception as e:
        print(Fore.RED+f'ocurrio un error:{e}')

    finally:
    
        if data.p_abiertos:
            if params.param.info:
                for x in data.p_abiertos:
                    informacion(params.param.ip,x)
           
            sleep(1)
            preg = str(input(Fore.WHITE+'[1]guardar informe ').strip())
            if preg == '1':
                titulo = str(input('titulo: '))
                crear_informe(params.param.ip,data.p_abiertos,titulo)
                  
        data.p_abiertos.clear()

def scan_selectivo(ip,timeout,puertos):
    
    eleccion = list(puertos.split(','))
    for x in eleccion:

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
            print(Fore.RED + f'tiempo agotado, puerto: {x}')
            continue
        except PermissionError:
            print(Fore.RED+f'sin permisos para escanear el puerto: {x}')
                
        except Exception as e:
            print(Fore.RED+f'ocurrio un error:{e}')
        finally:
            s.close()

def dataf():
    
    dataf = DataFrame({
    'puertos:':data.p_abiertos,
    'uso mas común:':data.descrip
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
            with data.cerradura:
                data.descrip.append(data.descripciones[puerto])
                data.p_abiertos.append(puerto)
                
                
            
        except KeyError:
            with data.cerradura:
                data.descrip.append('[desconocido]')
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
