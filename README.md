# SatoruHunter 🎯

**SatoruHunter** es un buscador y cazador de amenazas ligero diseñado para entornos Windows. Permite auditar en tiempo real los sockets de red activos orientados al exterior y analizar las llaves de persistencia críticas en el Registro de Windows.

## 🚀 Características
* **Auditoría de Red:** Captura conexiones activas (`ESTABLISHED`) filtrando automáticamente el tráfico local para mitigar falsos positivos.
* **Análisis de Persistencia:** Inspecciona de forma automática las llaves `Run` de `HKCU` y `HKLM` en busca de binarios anómalos.
* **Interfaz Elegante:** Renderizado tabular de alta fidelidad en consola mediante la librería `Rich`.

## 🛠️ Requisitos e Instalación

> ⚠️ **Nota:** Se requieren privilegios de **Administrador** en PowerShell para que el script pueda inspeccionar los identificadores de procesos (PIDs) en memoria.

1. Clona el repositorio:
   ```bash
   git clone [https://github.com/reispab-cell /satoru_hunter.git](https://github.com/reispab-cell/satoru_hunter.git)