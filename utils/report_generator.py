from rich.console import Console
from rich.table import Table

def mostrar_reporte_comunidad(hallazgos):
    """Genera reporte visual de conexiones externas detectadas."""
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
        try:
            table.add_row(
                h.get("proceso", "N/A"),
                str(h.get("pid", "N/A")),
                h.get("destino", "N/A"),
                h.get("ruta", "N/A")
            )
        except KeyError as e:
            console.print(f"[bold red][!] Error: Campo faltante en hallazgo: {e}[/bold red]")
            continue

    console.print(table)
    console.print(f"\n[bold]Total de conexiones sospechosas detectadas: {len(hallazgos)}[/bold]\n")


def mostrar_reporte_persistencia(hallazgos):
    """Genera reporte visual de elementos de persistencia detectados."""
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
        try:
            # Marcamos en rojo si el archivo referenciado en el registro no existe en el disco
            estado = "[green]✓ OK[/green]" if h.get("existe_archivo", False) else "[bold red]✗ No Encontrado[/bold red]"
            table.add_row(
                h.get("origen", "N/A"),
                h.get("nombre_registro", "N/A"),
                h.get("comando", "N/A"),
                estado
            )
        except KeyError as e:
            console.print(f"[bold red][!] Error: Campo faltante en hallazgo: {e}[/bold red]")
            continue

    console.print(table)
    console.print(f"\n[bold]Total de entradas de persistencia detectadas: {len(hallazgos)}[/bold]\n")
