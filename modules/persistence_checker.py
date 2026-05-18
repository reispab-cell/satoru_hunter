import winreg
import os

def revisar_llave_registro(ruta_raiz, sub_llave):
    """Escanea una subllave específica del registro buscando programas de inicio."""
    programas_autostart = []
    
    # Mapeo de la constante raíz a texto legible para nuestro reporte
    nombre_raiz = "HKLM" if ruta_raiz == winreg.HKEY_LOCAL_MACHINE else "HKCU"
    
    try:
        # Abrimos la llave del registro en modo lectura
        conector = winreg.OpenKey(ruta_raiz, sub_llave, 0, winreg.KEY_READ)
        
        # Consultamos la cantidad de valores guardados en esa ruta
        cantidad_valores, _, _ = winreg.QueryInfoKey(conector)
        
        for i in range(cantidad_valores):
            # Enumeramos cada entrada (Nombre del registro, Comando/Ruta del binario, Tipo de dato)
            nombre, comando, _ = winreg.EnumValue(conector, i)
            
            # Limpiamos las comillas comunes en las rutas del registro
            ruta_limpia = comando.replace('"', '').strip()
            
            # Extraemos solo el ejecutable principal por si el registro tiene argumentos (ej: /background)
            if ruta_limpia.lower().endswith(".exe") or " " in ruta_limpia:
                partes = ruta_limpia.split(".exe")
                if len(partes) > 1:
                    ruta_limpia = partes[0] + ".exe"
            
            programas_autostart.append({
                "origen": f"{nombre_raiz}\\{sub_llave.split('\\')[-1]}",
                "nombre_registro": nombre,
                "comando": comando,
                "existe_archivo": os.path.exists(ruta_limpia) # Alerta si el binario ya no está o se borró
            })
            
        winreg.CloseKey(conector)
    except WindowsError:
        # Si la llave no existe o no hay permisos, saltamos de forma segura
        pass
        
    return programas_autostart

def analizar_persistencia_sistema():
    """Punto de entrada modular que revisa las rutas Run críticas de Windows."""
    rutas_criticas = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]
    
    todos_los_hallazgos = []
    for raiz, sub_llave in rutas_criticas:
        hallazgos = revisar_llave_registro(raiz, sub_llave)
        todos_los_hallazgos.extend(hallazgos)
        
    return todos_los_hallazgos