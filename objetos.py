import socket
import ipaddress
from colorama import Fore,init
import requests
import func
from bs4 import BeautifulSoup

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
    -ip:{shodan_api.json()['ip']}
    -puertos: {shodan_api.json()['ports']}
    -nombre de host:{shodan_api.json()['hostnames']}
    -tipo de dispositivo:{shodan_api.json()['tags']}
#################################################''')
                if geo.status_code == 200 and ip_api.status_code == 200:
                    print(Fore.GREEN+f'''
    GEOLOCALIZACION:''')
                    print(Fore.WHITE+f'''
#################################################
    -pais:{geo.json()['geoplugin_countryName']}
    -ciudad:{geo.json()['geoplugin_city']}
    -estado/prov:{geo.json()['geoplugin_regionName']}
    -ISP:{ip_api.json()['isp']}
    -org:{ip_api.json()['org']}
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
        self.html = BeautifulSoup(requests.get(f'https://www.shodan.io/host/{self.ip}').content,'html.parser')
        self.contenido = self.html.find('div',class_='container u-full-width card-padding')
        self.status = requests.get('https://www.shodan.io/').status_code



    def scrapping_shodan(self):

        if  self.status == 200 and ip.validado and self.ip != None:
            print(Fore.RED+'''
            
###########                      
 shodan
###########  ''')
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
                        
                        info.append(info_.get_text())
                            
                for protocol,infor,fecha_scaneo in zip(proto,info,scan):
                    print(f'''
#################################################''')
                    print(Fore.GREEN+f'''
 fecha del puerto escaneado: {fecha_scaneo}''')   
                    print(Fore.GREEN+f'''                    
                    
 PROTOCOLO:
            ''')
                    print(Fore.WHITE+f'''                
{protocol[:-5].strip()}
{protocol[-4:]}
                    ''')
                    print(Fore.GREEN+'''
 SERVICIO EN ESCUCHA: ''')
                    print(Fore.WHITE+f'''
 {infor}
#################################################''')
            except AttributeError:
                print(Fore.RED+'ningun puerto ni servicio encontrado')

    def obtener_links(self):
        if ip.validado and self.status == 200:
            try:
                links = self.contenido.find_all('a',class_='link')
                if links:
                    print(Fore.GREEN+'''URLS RELACIONADAS:
                          ''')
                    for link in links:
                        url = link.get('href')
                        print(Fore.WHITE+str(url))
                        print(func.rastreo(url))
            except AttributeError:
                pass
            except Exception as e:
                print(Fore.RED+f'ocurrio un error en obtener_links: {e}')

