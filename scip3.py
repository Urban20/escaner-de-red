import threading
import func
from colorama import init,Fore
import params
import data
import objetos as objs
from concurrent.futures import ThreadPoolExecutor
from platform import system

init()

def inicio_scan(msg):
    print(Fore.WHITE+f'''\n
#################################################''')
    print(Fore.WHITE+msg)

    if params.param.timeout == None:
        lat_prom= func.latencia(params.param.ip)
        tim = func.timeout(lat_prom)
    else:
        tim = params.param.timeout
    print(f'timeout: {tim}')
    return tim


def crear_crawler(ip):
    print(Fore.WHITE+'''\n\n
#################################################''')
    print(Fore.RED+'iniciando crawler')
    
    #ip_num = ip numerica
    ip_num = objs.ip.validacion(ip)
    objs.ip.informacion()
    objs.ip.reputacion()

    #crawler
    crawler = objs.Bot_Crawler(ip=ip_num)
    crawler.scrapping_shodan()
    crawler.obtener_links()


if params.param.masivo:
    puertos = list(range(1,65535))
else:
    puertos = data.puertos
    
if params.param.hilo == None:
    hilo_=16
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
        except Exception as e:
            print(f'''error al buscar en shodan:
    {e}
    ''')


    if params.param.agresivo:
        try:
            if params.param.ip != None:
                print(Fore.WHITE+'''\n
#################################################''')
                print(Fore.WHITE+'escaneo agresivo en curso...')
                print(f'num de hilos: {hilo_}')
                with ThreadPoolExecutor(max_workers=hilo_) as ejec:

                    for x in puertos:
                        
                        ejec.submit(func.scan_agresivo,params.param.ip,x)

                
                if params.param.info:
                    for x in data.p_abiertos:
                        func.informacion(params.param.ip,x)

                func.preg_informe(ip=params.param.ip,lista=data.p_abiertos)
           
                

            else:
                print(Fore.RED+'especificar parametro [-ip]')        
        except Exception as e:
            print(Fore.RED+f'''error al escanear con metodo agresivo:
    {e}''')
        finally:
            data.p_abiertos.clear()
            
    elif params.param.normal and params.param.buscar == None:
        if params.param.ip != None:
            
        
            
            
            scan= inicio_scan(msg='escaneo normal en curso...')

            threading.Thread(target=func.detener).start()
            func.scan_normal(params.param.ip,scan)   
            
        else:
            print(Fore.RED+'especificar parametro [-ip]') 

    elif params.param.selectivo:
        if params.param.ip != None:
            
        
            scan= inicio_scan(msg='escaneo selectivo en curso...')

            func.scan_selectivo(params.param.ip,scan,params.param.selectivo)
            if params.param.info:
                for x in data.p_abiertos:
                    func.informacion(params.param.ip,x)

        else:
            print(Fore.RED+'especificar parametro [-ip]')
    elif params.param.ip != None and params.param.descubrir:
        try:
        
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
                except:
                    pass
            ejec.join()

            if system() == 'Linux':
                for ip in func.ipv4:
                
                    ipv4 = objs.Ipv4(ip=ip)
                    codigo = ipv4.ttl()
                    nombre = ipv4.obtener_nombre()
                    mac  = ipv4.obtener_mac()
                    compania = ipv4.obtener_compania()
                    if codigo != None:
                        print(Fore.GREEN+f'\n{ip}:\n')
                        print(data.data_ttl.get(codigo))
                        print(Fore.CYAN+f'nombre de disp. en la red: {nombre}')
                        print(Fore.CYAN+f'direccion mac: {mac}')
                        print(Fore.CYAN+f'compania: {compania}')
                    
        except:
            pass
    if params.param.buscar != None and not params.param.normal:
        try:
            
            threading.Thread(target=func.detener).start()
        
            while func.n < params.param.buscar:
                if not func.deten:
                    busq = func.buscar()
                    data.elementos.clear()
                    if busq != None:
                        print(busq)
                        func.n+=1
                else:
                    break
        except Exception as e:
            print(f'''ocurrio un error:
    {e}''')

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
    exit()