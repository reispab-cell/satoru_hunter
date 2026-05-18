from rich.console import Console
from rich.table import Table

def mostrar_reporte_comunidad(hallazgos):
    console = Console()
    
    if not hallazgos:
        console.print("\n[bold green][✓] No se detectaron conexiones sospechosas salientes.[/bold green]\n")
        return

    table = Table(title="[bold red]⚠️ Alerta: Conexiones Externas Activas[/bold red]", title_style="bold")
    
    table.add_column("Proceso", justify="left", style="cyan")
    table.add_column("PID", justify="center", style="magenta")
    table.add_column("Dirección C2 Potencial", justify="left", style="yellow")
    table.add_column("Ruta del Binario", justify="left", style="green")

    for h in hallazgos:
        table.add_row(h["proceso"], str(h["pid"]), h["destino"], h["ruta"])

    console.print(table)


def mostrar_reporte_persistencia(hallazgos):
    console = Console()
    
    if not hallazgos:
        console.print("\n[bold green][✓] No se encontraron elementos de persistencia en las llaves Run.[/bold green]\n")
        return

    table = Table(title="[bold yellow]🔍 Análisis de Persistencia: Llaves Run de Windows[/bold yellow]", title_style="bold")
    
    table.add_column("Ubicación (Registro)", justify="left", style="magenta")
    table.add_column("Nombre Entrada", justify="left", style="cyan")
    table.add_column("Comando Ejecutado", justify="left", style="white")
    table.add_column("Estado Archivo", justify="center", style="green")

    for h in hallazgos:
        # Marcamos en rojo si el archivo referenciado en el registro no existe en el disco
        estado = "[green]OK[/green]" if h["existe_archivo"] else "[bold red]No Encontrado[/bold red]"
        table.add_row(h["origen"], h["nombre_registro"], h["comando"], estado)

    console.print(table)