import sys
from modules.network_analyzer import escanear_conexiones_c2
from modules.persistence_checker import analizar_persistencia_sistema
from utils.report_generator import mostrar_reporte_comunidad, mostrar_reporte_persistencia

def ejecutar_auditoria():
    """Orquestador principal de SatoruHunter - Escaneo Integral."""
    print("[*] Iniciando SatoruHunter - Buscador de Amenazas Comunitario...")
    print("-" * 70)
    
    # ================= FASE 1: AUDITORÍA DE RED =================
    print("[*] Ejecutando Fase 1: Analizando sockets activos en memoria...")
    hallazgos_red = escanear_conexiones_c2()
    mostrar_reporte_comunidad(hallazgos_red)
    
    print("-" * 70)
    
    # ================= FASE 2: AUDITORÍA DE REGISTRO =================
    print("[*] Ejecutando Fase 2: Escaneando llaves Run de persistencia...")
    hallazgos_persistencia = analizar_persistencia_sistema()
    mostrar_reporte_persistencia(hallazgos_persistencia)

if __name__ == "__main__":
    try:
        ejecutar_auditoria()
    except KeyboardInterrupt:
        print("\n[!] Análisis cancelado de manera segura por el usuario.")
        sys.exit(0)