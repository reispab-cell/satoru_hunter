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
            
            # Mejorado: extraer ejecutable principal con mejor lógica
            if " " in ruta_limpia:
                # Si hay espacios, asumir que lo antes del primer espacio es el ejecutable
                # Esto maneja "C:\Program Files\App\service.exe /background"
                ruta_limpia = ruta_limpia.split()[0]
            
            # Validar que sea ejecutable válido (.exe, .bat, .cmd, .com, etc)
            extensiones_validas = ('.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js')
            if not ruta_limpia.lower().endswith(extensiones_validas):
                # Si no termina en ejecutable, intentar hasta .exe
                if '.exe' in ruta_limpia.lower():
                    idx = ruta_limpia.lower().find('.exe')
                    ruta_limpia = ruta_limpia[:idx + 4]
                else:
                    # Si no tiene extensión válida, saltamos este registro
                    continue
            
            programas_autostart.append({
                "origen": f"{nombre_raiz}\\{sub_llave.split('\\')[-1]}",
                "nombre_registro": nombre,
                "comando": comando,
                "existe_archivo": os.path.exists(ruta_limpia)  # Alerta si el binario ya no está o se borró
            })
            
        winreg.CloseKey(conector)
    except OSError:
        # WindowsError es alias de OSError en Python 3
        # Si la llave no existe o no hay permisos, saltamos de forma segura
        pass
    except Exception as e:
        # Capturar otros errores inesperados
        print(f"[!] Error al revisar registro {nombre_raiz}: {e}")
        
    return programas_autostart

def analizar_persistencia_sistema():
    """Punto de entrada modular que revisa las rutas Run críticas de Windows."""
    rutas_criticas = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]
    
    todos_los_hallazgos = []
    for raiz, sub_llave in rutas_criticas:
        try:
            hallazgos = revisar_llave_registro(raiz, sub_llave)
            todos_los_hallazgos.extend(hallazgos)
        except Exception as e:
            print(f"[!] Error crítico en análisis de persistencia: {e}")
            continue
        
    return todos_los_hallazgos
