from scapy.all import *
import re
from colorama import init,Fore

init()

def escaneo_syn(ip,puerto,timeout_):
    #s_syn --> escaneo syn --> variable
    try:
        conf.verb = 0
        s_syn =  sr1(IP(dst=ip)/TCP(dport=puerto,flags='S'),timeout=timeout_,retry=5)
        if re.search('SA',s_syn.show(dump=True)):
            print(Fore.GREEN+f'[*] puerto abierto >> {puerto}')
    except AttributeError:
        pass
    
def escaneo_udp():
    pass