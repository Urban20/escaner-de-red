from scapy.all import *
import re
from colorama import init,Fore
import logging
from params import *

init()

#ajustar el timeout
# agregar escaneos udp
# revisar los reintentos
#intentar ajustar el tiempo

if param.reintento != None:
    reintento = param.reintento
else:
    reintento = 3

def escaneo_syn(ip,puerto,timeout_):
    #s_syn --> escaneo syn --> variable
    try:
       
        conf.verb = 0
        s_syn =  sr1(IP(dst=ip)/TCP(dport=puerto,flags='S'),timeout=timeout_,retry=reintento)
        if s_syn != None:
            print(Fore.GREEN+f'\n[*] puerto abierto >> {puerto}\n')
    except AttributeError:
        pass
    except:
        logging.error('error en escaneo syn')
    
