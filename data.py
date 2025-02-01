from threading import Lock
import params
from colorama import Fore

'este modulo contiene algunas de las variables que se utilizan en el script'

cerradura = Lock()

#nombre del archivo que se crea al ingresar 1 en los escaneos
nombre_arch = 'scannerip.txt'

#nombre del archivo perteneciente a el parametro -b
nombre_b='ips_encontradas.txt'
p_abiertos= []

descrip = []

lista_ips = []

logo =Fore.RED+r'''
 
███████  ██████  █████  ███    ██ ███    ██ ███████ ██████  ██ ██████      
██      ██      ██   ██ ████   ██ ████   ██ ██      ██   ██ ██ ██   ██     
███████ ██      ███████ ██ ██  ██ ██ ██  ██ █████   ██████  ██ ██████      
     ██ ██      ██   ██ ██  ██ ██ ██  ██ ██ ██      ██   ██ ██ ██          
███████  ██████ ██   ██ ██   ████ ██   ████ ███████ ██   ██ ██ ██
          
version 4.0                                                              
    '''
autor =Fore.GREEN+'''
propiedad de:

██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ██╗
██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
██║   ██║██████╔╝██████╔╝██║██╗██║██╔██╗ ██║
██║   ██║██╔══██╗██╔══██╗██║██║██║██║╚██╗██║
╚██████╔╝██║  ██║██████╔╝╚█║████╔╝██║ ╚████║
 ╚═════╝ ╚═╝  ╚═╝╚═════╝  ╚╝╚═══╝ ╚═╝  ╚═══╝                                      
'''
