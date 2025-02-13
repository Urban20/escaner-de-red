from scapy.all import *
import re



class Escaner_scapy():
    def __init__(self,ip,puerto,timeout):
        self.ip = ip
        self.puerto = puerto
        self.timeout = timeout
    
    def escaneo_syn(self):
        #s_syn --> escaneo syn 
        try:
            s_syn =  sr1(IP(dst=self.ip)/TCP(dport=self.puerto,flags='S'),timeout=self.timeout)
            if re.search('SA',s_syn.show2(dump=True)):
                print(f'puerto-abierto >> {self.puerto}')
        except AttributeError:
            pass