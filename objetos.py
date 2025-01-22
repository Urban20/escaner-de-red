import socket
import ipaddress
from platform import system
from colorama import Fore,init
import requests
import func 
from bs4 import BeautifulSoup
from subprocess import run
from re import search

'este modulo contiene las clases que se utilizan en el script'

init()

#objeto ip que solo se utiliza con el crawler
class Ip():
    def __init__(self):
        self.ip = None
        self.validado = False
    
    def validacion(self,ip):
        try:
            ip_ =socket.gethostbyname(ip)
            if ipaddress.ip_address(ip_).is_global:
                self.validado = True
                self.ip = ip_
                return ip_
            else:
                print('debe ser una ip global')
            
        except socket.gaierror:

            print(Fore.RED+'el dominio/ip proporcionado es incorrecto')

        except Exception as e:
            print(Fore.RED+f'ocurrio el siguiente error: {e}')

    def informacion(self):
        try:
            if self.validado and self.ip != None:
                ip_api = requests.get(f'http://ip-api.com/json/{self.ip}')
                shodan_api = requests.get(f'https://internetdb.shodan.io/{self.ip}')
                geo = requests.get(f'http://www.geoplugin.net/json.gp?ip={self.ip}')
                if shodan_api.status_code == 200:
                    print(Fore.GREEN+f'''
                        
    INFO:''')
                    print(Fore.WHITE+f'''
#################################################                                                       
    -ip:{shodan_api.json().get('ip')}
    -puertos: {shodan_api.json().get('ports')}
    -nombre de host:{shodan_api.json().get('hostnames')}
    -tipo de dispositivo:{shodan_api.json().get('tags')}
#################################################''')
                if geo.status_code == 200 and ip_api.status_code == 200:
                    print(Fore.GREEN+f'''
    GEOLOCALIZACION:''')
                    print(Fore.WHITE+f'''
#################################################
    -pais:{geo.json().get('geoplugin_countryName')}
    -ciudad:{geo.json().get('geoplugin_city')}
    -estado/prov:{geo.json().get('geoplugin_regionName')}
    -ISP:{ip_api.json().get('isp')}
    -org:{ip_api.json().get('org')}
#################################################''')

        except Exception as e:
            print(Fore.RED+f'ocurrio un error en el apartado de apis: {e}')

    def reputacion(self):
        try:
            if self.validado:
                rep = func.confiabilidad_ip(self.ip)
                if rep != None:
                    match rep:
                        case 'failure-message':
                            print(Fore.RED+'en la lista negra')
                        case 'no valida':
                            print(Fore.YELLOW+'no se puede obtener la reputacion')
                        case 'success-message':
                            print(Fore.CYAN+'fuera de la lista negra')
            else:
                print(Fore.RED+'no se pudo obtener la reputacion: ip no validada')
        except Exception as e:
            print(Fore.RED+f'hubo un error en reputacion: {e}')

ip = Ip()

class Bot_Crawler():

    def __init__(self,ip):
        self.ip = ip
        self.html = BeautifulSoup(requests.get(f'https://www.shodan.io/host/{self.ip}').text,'html.parser')
        self.contenido = self.html.find('div',class_='container u-full-width card-padding')
        self.status = requests.get('https://www.shodan.io/').status_code



    def scrapping_shodan(self):

        if  self.status == 200 and ip.validado and self.ip != None:
            print(Fore.RED+'\n###########\nshodan\n###########\n')
            try:
                #fecha de cada escaneo de cada puerto
                scan = []
                #protocolos que se maneja /udp o tcp
                proto = []
                #informacion del puerto en cuestion
                info = []
                
                protocolos = self.contenido.findAll('span')
                informacion = self.contenido.find_all('div',class_='card card-padding banner')
                fecha_scan = self.html.find_all(class_='u-pull-right text-secondary')

                for x in fecha_scan:
                    scan.append(x.text.split('T')[0].split('|')[1].strip())



                for protocolo in protocolos: 
                    if search('tcp',str(protocolo.get_text()).lower()) != None or search('udp',str(protocolo.get_text()).lower()) != None:
                        
                        proto.append(protocolo.get_text().strip())
                        
                    elif search('last seen',str(protocolo.get_text()).lower()) != None:

                        print(Fore.WHITE+f'ultimo scaneo de shodan: {protocolo.get_text().strip()[10:]}')

                for info_ in informacion:
                    
                    
                    if search('html',str(info_.get_text()).lower()) != None and len(info_.get_text()) > 650:
                        info.append('posible pagina web')
                            
                    elif search('ssh',str(info_.get_text()).lower()) != None and len(info_.get_text()) > 650:
                        info.append('posible servicio ssh')
                        
                    else:
                        
                        info.append(info_.get_text())
                            
                for protocol,infor,fecha_scaneo in zip(proto,info,scan):
                    print(f'''
#################################################''')
                    print(Fore.GREEN+f'\nfecha del puerto escaneado: {fecha_scaneo}')   
                    print(Fore.GREEN+f'\n\nPROTOCOLO:')
                    print(Fore.WHITE+f'''                
{protocol[:-5].strip()}
{protocol[-4:]}
                    ''')
                    print(Fore.GREEN+'\nSERVICIO EN ESCUCHA: ')
                    print(Fore.WHITE+f'\n{infor}\n#################################################')
            except AttributeError:
                print(Fore.RED+'ningun puerto ni servicio encontrado')

    def obtener_links(self):
        status = func.cargar_json('status.json')
        if ip.validado and self.status == 200:
            try:
                links = self.contenido.find_all('a',class_='link')
                if links:
                    print(Fore.GREEN+'''URLS RELACIONADAS:
                          ''')
                    for link in links:
                        url = link.get('href')
                        print(Fore.WHITE+str(url))
                        print(func.rastreo(url,status))
            except AttributeError:
                pass
            except Exception as e:
                print(Fore.RED+f'ocurrio un error en obtener_links: {e}')

class Ipv4():
    def __init__(self,ip):
        self.ipv4 = ip
        self.nombre = None
        self.mac = None
        self.compania = None

    def ttl(self):
        
        out= str(run(args=['ping','-c','1',self.ipv4],capture_output=True,text=True)).split()
        for x in out:
            if 'ttl' in x:
                return int(x.split('=')[-1].strip())

    def obtener_mac(self):
        
        for el in str(run(['ip','neigh','show',self.ipv4],text=True,capture_output=True)).split():
            if ':' in el:
                self.mac = el

        return self.mac
            
    def obtener_nombre(self):
        try:
            self.nombre = socket.gethostbyaddr(self.ipv4)[0].split('.')[0].strip()
        except:
            self.nombre = '[desconocido]'
        return(self.nombre)
    
    def obtener_compania(self):
        try:
            api= requests.get(f'https://www.macvendorlookup.com/api/v2/{self.mac}').json()
            for el in api:
                self.compania = str(el['company'])
                return self.compania

        except:
            return None