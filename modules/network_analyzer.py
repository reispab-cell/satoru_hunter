import psutil

def es_ip_privada(ip):
    """Filtra IPs locales (127.0.0.1, 192.168.x.x, etc.) para enfocar el análisis."""
    # IPv4 privadas
    if ip.startswith(('127.', '10.', '172.16.', '192.168.')):
        return True
    
    # IPv6 privadas y locales (::1, fe80::/10, fd00::/8)
    if ip.startswith(('::1', 'fe80:', 'fd00:')) or ip == '::1':
        return True
    
    return False

def escanear_conexiones_c2():
    """Analiza conexiones sospechosas establecidas hacia el exterior."""
    hallazgos = []
    
    try:
        # Obtenemos los sockets activos del sistema
        conexiones = psutil.net_connections(kind='inet')
        
        if not conexiones:
            print("[!] Advertencia: No se encontraron conexiones activas en el sistema.")
            return hallazgos
            
    except (psutil.AccessDenied, PermissionError):
        print("[!] Error: Se requieren privilegios de Administrador para auditar los sockets.")
        return hallazgos
    except Exception as e:
        print(f"[!] Error inesperado al escanear conexiones: {e}")
        return hallazgos

    for conn in conexiones:
        # Solo nos interesan conexiones activas que tengan una IP de destino
        if conn.status == 'ESTABLISHED' and conn.raddr:
            ip_remota = conn.raddr.ip
            puerto_remoto = conn.raddr.port
            
            # Aplicamos el filtro: si es externa, la investigamos
            if not es_ip_privada(ip_remota):
                try:
                    proceso = psutil.Process(conn.pid)
                    nombre_proc = proceso.name()
                    ruta_ejecutable = proceso.exe()
                    
                    hallazgos.append({
                        "proceso": nombre_proc,
                        "pid": conn.pid,
                        "destino": f"{ip_remota}:{puerto_remoto}",
                        "ruta": ruta_ejecutable
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Si el proceso se cierra rápido o el OS bloquea el PID, saltamos al siguiente
                    continue
                    
    return hallazgos
