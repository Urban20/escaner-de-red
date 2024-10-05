import requests,os,ipaddress,socket,random,subprocess,threading,time,pandas
from bs4 import BeautifulSoup
from colorama import init,Fore
import base64


init()
n = 0

logo =Fore.RED + r'''

 ██▓ ██▓███    ██████  ▄████▄   ▄▄▄       ███▄    █  ███▄    █ ▓█████  ██▀███  
▓██▒▓██░  ██▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █  ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒
▒██▒▓██░ ██▓▒░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒
░██░▒██▄█▓▒ ▒  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄  
░██░▒██▒ ░  ░▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░▒██░   ▓██░░▒████▒░██▓ ▒██▒
░▓  ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
 ▒ ░░▒ ░     ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
 ▒ ░░░       ░  ░  ░  ░          ░   ▒      ░   ░ ░    ░   ░ ░    ░     ░░   ░ 
 ░                 ░  ░ ░            ░  ░         ░          ░    ░  ░   ░    
 Version 2.0
 por Urb@n
 '''
coman_inst =r'''
 ____________________comandos__________________________
| -cls:borrar consola                                  |
| -salir                                               |
| -insertar ip: busca en shodan o fofa                 |
| -b [numero]:buscar ips                               |
| -scan: descubre puertos de una ip privada o publica  |
|______________________________________________________|'''



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


def dataf():
    
    dataf = pandas.DataFrame({
    'puertos:':p_abiertos,
    'uso mas común:':descrip
    }).to_string()
    
    return dataf

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

def puerta_de_enlace():
    return str(subprocess.check_output('ipconfig')).split(':')[-1][:-5].strip()

def scan_agresivo(ip,puerto):
    timeout = 3
    #puertos mas comunes por default
    try:  
        ipaddress.ip_address(ip.split('p')[0].strip())    
         
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
   
def scan_selectivo(ip,timeout):
    eleccion = list(ip.split('p')[-1].split(','))
    for x in eleccion:

        s = socket.socket()
                
        s.settimeout(timeout)

        try:
            s.connect((ip.split('p')[0].strip(),int(x)))
            print(Fore.GREEN+f'abierto: {x}')

            print(f'uso mas comun: {descripciones[int(x)]}')
        except KeyError:
            print(f'uso mas comun: [desconocido]')
        except TimeoutError:
            print(Fore.RED + f'tiempo agotado, puerto: {x}')
            continue
        except PermissionError:
            print(Fore.RED+f'sin permisos para escanear el puerto: {x}')
                
        except Exception as e:
            print(Fore.RED+f'ocurrio un error:{e}')
        finally:
            s.close()

def scan_normal(ip,timeout):
    
        print(Fore.MAGENTA+f'escaneando puertos TCP de la ip: {ip}')
        for x in puertos:
            s = socket.socket()
                
            s.settimeout(timeout)

            try:
                s.connect((ip.strip(),x))
                print(Fore.GREEN+f'abierto: {x}')

                print(f'uso mas comun: {descripciones[x]}')
                with cerradura:
                    p_abiertos.append(x)
            except KeyError:
                print(f'uso mas comun: [desconocido]')
                p_abiertos.append(x)
            except TimeoutError:
                    
                    
                continue
            except PermissionError:
                print(Fore.RED+f'sin permisos para escanear el puerto: {x}')
                
            except Exception as e:
                print(Fore.RED+f'ocurrio un error:{e}')
		    
            finally:
                s.close()

def buscar(entrada):
    global n
    while n < int(entrada[-1]):
        elementos=[]

        for x in range(4):
            elementos.append(str(random.randint(0,255)))

        ip = ipaddress.ip_address('.'.join(elementos))
        if ip.is_global:
                geo= requests.get(f'http://www.geoplugin.net/json.gp?ip={ip}').json()
                shodan= requests.get(f'https://internetdb.shodan.io/{ip}').json()
                try:
                    if list(shodan['ports']):

                        n+=1

                        info_b= f'''
ip:{geo['geoplugin_request']}
pais:{geo['geoplugin_countryName']}
estado/prov:{geo['geoplugin_region']}
puertos:{shodan['ports']}

'''
                        
                        return info_b           
                except KeyError:
        
                    continue

def rastreo(url):
    try:
        solicitud= requests.get(url,timeout=5)
        if solicitud.status_code == 200:
            return Fore.GREEN+'* responde'
            
        else:
            return Fore.YELLOW+'* no se pudo establecer comunicacion: requiere autenticacion o no es accesible'
    
    except requests.Timeout:
        return Fore.RED+'* no responde: tiempo agotado'
    except Exception as e:
        return Fore.RED+f'''* no responde,msg error:
{e}'''

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


        with open('scannerip.txt','a') as arch:
            arch.write(informe)
    except Exception as e:
        print(f'ocurrio un error: {e}')

def informe_busqueda(informacion):
    with open('busqueda_ips.txt','a') as archivo:
        archivo.write(informacion)


#flujo principal del script
if __name__ == '__main__':
     
    cerradura = threading.Lock()
    
    print(logo)
    print(coman_inst)
    while True:
        try:   
                busqueda_ = []
                p_abiertos = []
                descrip = []

                comando = str(input(Fore.WHITE + 'comando: ').strip())

                #borrar consola------------------------------
                if comando == 'cls':
                    os.system('cls')
                    print(logo)
                    print(coman_inst)
                    continue
                #---------------------------------------------
                #salir----------------------------------------
                elif comando == 'salir':
                    break
                #busquedas de ips aleatorias
                elif comando[:2] == 'b ' and len(comando) == 3:
                    try:
                        for x in range(int(comando[-1])):
                            busqueda= buscar(comando)
                            
                            busqueda_.append(busqueda)
                            
                            print(busqueda)
                        n = 0
                        p_busq = int(input('[1] para guardar busqueda ').strip())
                        if p_busq == 1:
                            for x in busqueda_:
                                informe_busqueda(x)
                        
                        continue
                    except ValueError:
                        
                        continue
                #----------------------------------------------
                # escanear los puertos ------------------------

                #metodo 1 ---------------- escaner agresivo y normal
                elif comando[:4] == 'scan' and comando[4:] != '':
                    if not 'p' in comando[4:]:
                        # escaner normal para escanear los routers
                        if comando[4:].strip() == puerta_de_enlace():
                            
                            latencia_prom = latencia(comando[4:].split('p')[0].strip())
                            
                            scan_normal(ip=comando[4:].strip(),timeout=0.1)
                            if p_abiertos:
                                preg= int(input(Fore.MAGENTA+'[1] guardar informe '))

                                if preg == 1:
                                    titulo= (str(input('titulo del informe: ')))
                                    crear_informe(ip=comando[4:].strip(),puerto=str(p_abiertos),titulo=titulo)
                            else:
                                print(Fore.WHITE+'no se encontraron puertos abiertos con este metodo')
                           
                            continue
                    #forzar a utilizar un escaneo normal
                        elif ' -n' in comando[4:]:
                            latencia_prom = latencia(comando[4:].split('-')[0].strip())
                            
                            timeout_= timeout(latencia_prom=latencia_prom)
                            print(f'timeout: {timeout_}')

                            scan_normal(ip=comando[4:].split('-')[0].strip(),timeout=timeout_)
                
                            if p_abiertos:
                                preg= int(input(Fore.MAGENTA+'[1] guardar informe '))

                                if preg == 1:
                                    titulo= (str(input('titulo del informe: ')))
                                    crear_informe(ip=comando[4:].split('-')[0].strip(),puerto=str(p_abiertos),titulo=titulo)
                            else:
                                print(Fore.WHITE+'no se encontraron puertos abiertos con el metodo normal')
                            
                            continue
                        else:
                            #escaner agresivo para el resto
                            #se crea un hilo para cada puerto en la lista
                            
                            for x in puertos:
                                hilo = threading.Thread(target=scan_agresivo,args=(comando[4:].strip(),x))
                
                                hilo.start()
                            time.sleep(2)
                            
                            
                            if p_abiertos:
                                print(dataf())
                                preg= int(input(Fore.MAGENTA+'[1] guardar informe '))
                                if preg == 1:
                                    titulo= (str(input('titulo del informe: ')))
                                    crear_informe(ip=comando[4:].strip(),puerto=str(p_abiertos),titulo=titulo)
                            else:
                                print(Fore.YELLOW+'no se encontraron puertos por defecto con el metodo agresivo')
                            continue
                    
                #metodo 2 ------------------- escaner selectivo
                    else:
                        latencia_prom = latencia(comando[4:].split('p')[0])
                        
                        
                        timeout_= timeout(latencia_prom=latencia_prom)
                        scan_selectivo(ip=comando[4:].strip(),timeout=timeout_)
                    continue
                #--------------------------------------------------



                #-----------hacer inteligencia buscando en internet--------------
                else:
                    try:
                        ip = socket.gethostbyname(comando)
                        if ipaddress.ip_address(ip).is_global:
                            

                            try:
                                ip_api= requests.get(f'http://ip-api.com/json/{ip}').json()
                                shodan= requests.get(f'https://internetdb.shodan.io/{ip}').json()
                                geo = requests.get(f'http://www.geoplugin.net/json.gp?ip={ip}').json()

                                print(Fore.GREEN+f'''
                                    
 ____                             
|info|
|____|

#####################################                                                         
-ip:{shodan['ip']}
-puertos: {shodan['ports']}
-nombre de host:{shodan['hostnames']}
-tipo de dispositivo:{shodan['tags']}
######################################''')


                                print(
        f'''
 _________________ 
| geolocalizacion:|
|_________________|

####################################
-pais:{geo['geoplugin_countryName']}
-ciudad:{geo['geoplugin_city']}
-estado/prov:{geo['geoplugin_regionName']}
-ISP:{ip_api['isp']}
-org:{ip_api['org']}
####################################''')

                                
                            except KeyError:
                                print(
        Fore.GREEN+f'''
 _________________
| geolocalizacion:|
|_________________|

###################################         
-pais:{geo['geoplugin_countryName']}
-ciudad:{geo['geoplugin_city']}
-estado/prov:{geo['geoplugin_regionName']}
-ISP:{ip_api['isp']}
-org:{ip_api['org']}
####################################''')
                                
                            
                            except Exception as e:
                                print(f'ocurrio un error: {e}')
                                
                        else:
                            continue
                    except ValueError:
                        continue
                    except socket.gaierror:
                        print('ip/dominio invalido o no encontrado')
                        continue
        #bloque del webscrapping a shodan
                print(Fore.MAGENTA+'''
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
#########################################''')
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
###########################################''')
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
                    print(Fore.RED+'ningun puerto ni servicio encontrado')
                    print(Fore.MAGENTA+'''
#####################################################                 

###########
fofa
###########
                    ''')
            
                    puerto_list= []
                    banners= []
                
                    codificiacion = base64.b64encode(ip.encode())
                    html_f= BeautifulSoup(requests.get(f'https://en.fofa.info/result?qbase64={codificiacion.decode()}').content,'html.parser')
                    banner = html_f.find_all('div',class_='el-scrollbar__view')
                    puerto = html_f.find_all('a',class_='hsxa-port')
                    

                
                    for x in banner:
                        banners.append(x.text)
                    for y in puerto:
                        puerto_list.append(y.get_text().strip())
                

                    for puert,ban in zip(puerto_list,banners):
                        print(Fore.WHITE+f'''
################################################
puerto:{puert}                    

servicio:   

{ban} ''')                   

                    print(Fore.WHITE+'################################################')
                    
                except Exception as e:
                    print(f'ocurrio un error: {e}')
        except:
            continue