import psutil

def es_ip_privada(ip):
    """Filtra IPs locales (127.0.0.1, 192.168.x.x, etc.) para enfocar el análisis."""
    if ip.startswith(('127.', '10.', '172.16.', '192.168.')) or ip == '::1':
        return True
    return False

def escanear_conexiones_c2():
    """Analiza conexiones sospechosas establecidas hacia el exterior."""
    hallazgos = []
    
    try:
        # Obtenemos los sockets activos del sistema
        conexiones = psutil.net_connections(kind='inet')
    except (psutil.AccessDenied, PermissionError):
        print("[!] Error: Se requieren privilegios de Administrador para auditar los sockets.")
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