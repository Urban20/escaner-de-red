from scapy.all import *
import re
from colorama import init,Fore
import logging
from params import *

init()


# agregar escaneos udp
# revisar los reintentos
#intentar ajustar el tiempo

if param.reintento != None:
    reintento = param.reintento
else:
    reintento = 3

def escaneo_syn(ip,puerto):
    #s_syn --> escaneo syn --> variable
    try:
        #timeout especifico para escaneo syn (silencioso)
        if param.timeout != None:
            t = param.timeout
        else:
            t = 1.25

        conf.verb = 0
        s_syn =  sr1(IP(dst=ip)/TCP(dport=puerto,flags='S'),timeout=t,retry=reintento)#type: ignore
        if re.search('SA',str(s_syn)):
            print(Fore.GREEN+f'\n[*] puerto abierto >> {puerto}\n')
    except AttributeError:
        pass
    except:
        logging.error('error en escaneo syn')
    
def escaneo_ack(ip,puerto,timeout_):
    conf.verb = 0
    s_ack = sr1(IP(dst=ip)/TCP(dport=puerto,flags='A'),timeout=timeout_,retry=reintento)#type: ignore
    
    if re.search('ICMP',str(s_ack).upper()):
        print(Fore.YELLOW+f'\n[*] puerto filtrado explicitamente >> {puerto}\n')
    elif s_ack == None:
        print(Fore.YELLOW+f'\n[*] sin respuesta (None) >> {puerto}\n')
    elif re.search('R',str(s_ack).upper()):
        print(f'\n[*] puerto no filtrado >> {puerto}\n')