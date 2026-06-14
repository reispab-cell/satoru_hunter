import sys
import os
from modules.network_analyzer import escanear_conexiones_c2
from modules.persistence_checker import analizar_persistencia_sistema
from utils.report_generator import mostrar_reporte_comunidad, mostrar_reporte_persistencia

def verificar_privilegios_admin():
    """Verifica si el script se ejecuta con privilegios de Administrador."""
    try:
        return os.getuid() == 0  # Linux/Mac
    except AttributeError:
        # Windows
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

def ejecutar_auditoria():
    """Orquestador principal de SatoruHunter - Escaneo Integral."""
    
    # Validar privilegios de administrador en Windows
    if not verificar_privilegios_admin():
        print("[!] ⚠️  ADVERTENCIA: Este script requiere privilegios de Administrador para funcionar correctamente.")
        print("[!] Por favor, ejecuta en PowerShell/CMD con 'Ejecutar como administrador'.\n")
    
    print("[*] Iniciando SatoruHunter - Buscador de Amenazas Comunitario...")
    print("-" * 70)
    
    try:
        # ================= FASE 1: AUDITORÍA DE RED =================
        print("[*] Ejecutando Fase 1: Analizando sockets activos en memoria...")
        hallazgos_red = escanear_conexiones_c2()
        
        if hallazgos_red:
            mostrar_reporte_comunidad(hallazgos_red)
        else:
            print("[✓] Primera fase completada: No se detectaron conexiones externas sospechosas.\n")
        
        print("-" * 70)
        
        # ================= FASE 2: AUDITORÍA DE REGISTRO =================
        print("[*] Ejecutando Fase 2: Escaneando llaves Run de persistencia...")
        hallazgos_persistencia = analizar_persistencia_sistema()
        
        if hallazgos_persistencia:
            mostrar_reporte_persistencia(hallazgos_persistencia)
        else:
            print("[✓] Segunda fase completada: No se detectaron entradas de persistencia sospechosas.\n")
        
        print("-" * 70)
        print("[✓] Análisis completado exitosamente.")
        
    except KeyboardInterrupt:
        print("\n[!] Análisis cancelado de manera segura por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error inesperado durante el análisis: {e}")
        print("[!] Por favor, verifica que ejecutas como Administrador y que las dependencias están instaladas.")
        sys.exit(1)

if __name__ == "__main__":
    ejecutar_auditoria()
