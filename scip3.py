import threading
import func 
from colorama import init,Fore
import params 
import data 
import objetos as objs
from concurrent.futures import ThreadPoolExecutor
from platform import system
from socket import gethostbyname
from logging import info,critical

'este modulo contiene el script principal el cual llama a todos los modulos necesarios para su funcionamiento'

init()

def inicio_scan(msg):
    #solo se llama cuando son escaneos normales o selectivos 
    print(Fore.WHITE+f'\n\n#################################################')
    print(Fore.WHITE+msg)
    print('\n"esc" para salir\n')
    if params.param.timeout == None:
        lat_prom= func.latencia(params.param.ip)
        tim = func.timeout(lat_prom)
    else:
        tim = params.param.timeout
    print(f'timeout: {tim}')
    return tim


def crear_crawler(ip):
    #solo se llama al realizar OSINT con shodan
    info('creando objeto crawler...')
    
    print(Fore.RED+'\niniciando crawler')
    
    #ip_num = ip numerica
    ip_num = objs.ip.validacion(ip)
    objs.ip.informacion()
    objs.ip.reputacion()

    #crawler
    crawler = objs.Bot_Crawler(ip=ip_num)
    crawler.scrapping_shodan()
    crawler.obtener_links()


if params.param.hilo == None:
    hilo_= 100
else:
    hilo_ = params.param.hilo


try:
    #acciones de los parametros-----------------
    if params.param.shodan:
        try:
            if params.param.ip != None:
                if ',' in params.param.ip:
                    for x in params.param.ip.split(','):
                        crear_crawler(x)   
                else:       
                    crear_crawler(params.param.ip)
            else:
                print(Fore.RED+'especificar parametro [-ip]')
                
        except AttributeError:
            print(Fore.RED+'\nsin informacion al respecto\n')
            
        
    if params.param.agresivo:
        #t es el timeout para los escaneos agresivos
        if params.param.timeout == None:
            t = 0.5
        else:
            t = params.param.timeout

        
        
        if params.param.ip != None:
            print(Fore.WHITE+'''\n\n#################################################''')
            info('escaneo agresivo iniciado...')
            print(Fore.WHITE+'escaneo agresivo en curso...')
            json = func.cargar_json('data_puertos.json')
            print(f'num de hilos: {hilo_}\n\rtimeout:{t}')
            with ThreadPoolExecutor(max_workers=hilo_) as ejec:
                ip = gethostbyname(params.param.ip)
                for x in func.puertos:
                    
                    ejec.submit(func.scan_agresivo,ip,x,t,json)

            if not data.p_abiertos:
                print(Fore.RED+'\nningun puerto encontrado\n')        
                
            if params.param.info:
                for x in data.p_abiertos:
                    func.informacion(ip,x)

            func.preg_informe(ip=ip,lista=data.p_abiertos)
        
        else:
            print(Fore.RED+'\nespecificar parametro [-ip]\n')        
    
    
    #escaneo normal
    elif params.param.normal and params.param.buscar == None:
        if params.param.ip != None:
            
            scan= inicio_scan(msg='escaneo normal en curso...')

            threading.Thread(target=func.detener).start()
            func.scan_normal(params.param.ip,scan)   
            
        else:
            print(Fore.RED+'especificar parametro [-ip]') 

    #escaneo selectivo
    elif params.param.selectivo:
        if params.param.ip != None:
            
        
            scan= inicio_scan(msg='escaneo selectivo en curso...')

            func.scan_selectivo(params.param.ip,scan,params.param.selectivo)
            if params.param.info:
                for x in data.p_abiertos:
                    func.informacion(params.param.ip,x)

        else:
            print(Fore.RED+'\nespecificar parametro [-ip]\n')
    
    #para descubrir ips privadas
    elif params.param.ip != None and params.param.descubrir:
        
        
        if params.param.timeout != None:
            timeout_ = params.param.timeout
        else:
            timeout_ = 4
    
        print(Fore.GREEN+'rastreando ips privadas: ')
        for x in range(1,255):
            try:
            
                ejec= threading.Thread(target=func.descubrir_red,args=(params.param.ip,x,timeout_))
                if 'x' in params.param.ip:
                    ejec.start()
                else:
                    print(Fore.RED+'la ip debe contener una x al final, ejemplo "192.168.0.x"')
                    break
                
            except: pass
            
        ejec.join()

        if system() == 'Linux':
            for ip in func.ipv4:
            
                ipv4 = objs.Ipv4(ip=ip)
                codigo = ipv4.ttl()
                nombre = ipv4.obtener_nombre()
                mac  = ipv4.obtener_mac()
                compania = ipv4.obtener_compania()
                json = func.cargar_json('ttl.json')
                if codigo != None:
                    print(Fore.GREEN+f'\n{ip}:\n')
                    print(json.get(str(codigo)))
                    print(Fore.CYAN+f'nombre de disp. en la red: {nombre}')
                    print(Fore.CYAN+f'direccion mac: {mac}')
                    print(Fore.CYAN+f'compania: {compania}')
                
        
        #buscar ips publicas
    elif params.param.buscar != None and not params.param.normal and params.param.ip == None:
    
        print(Fore.GREEN+'\n* rastreando ips publicas...\n')
        threading.Thread(target=func.detener).start()
    
        while func.n < params.param.buscar and not func.deten:
            
            busq = func.buscar()
            
            if busq != None:
                print(Fore.WHITE+busq)
                func.n+=1
            
        if not params.param.guardar:
            if str(input(Fore.WHITE+'[1] guardar informacion >> ')).strip() == '1':
                for ip in data.lista_ips:
                    func.agregar_arch(ip)
                print(Fore.GREEN+'\nla informacion fue guardada\n')
            else:
                print(Fore.RED+'\nla informacion no fue guardada\n')

    

    if params.param.ayuda:
        func.ayuda()

    if params.param.borrar:
        func.borrar_arch()

    elif params.param.abrir:
        func.abrir_arch()

    if params.param.lectura:
        try:
            with open(data.nombre_arch,'r') as registro:
                print(Fore.CYAN+registro.read())
        except FileNotFoundError:
            print(Fore.RED+'registro no encontrado')       
except KeyboardInterrupt:
    func.deten = True
    exit(1)
except: critical('error critico desconocido en el flujo principal')
finally:
    info('la herramienta finalizo con exito')