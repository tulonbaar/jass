"""
JASS - Just Another System Sniffer
Interfejs wiersza poleceń (CLI)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich import box

from jass.analyzers.zabbix_analyzer import ZabbixAnalyzer
from jass.core.client import ZabbixAPIException, ZabbixAuthException
from jass.core.models import HostAnalysisPayload
from jass.core.prompt_builder import LLMPromptBuilder

console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Konfiguracja formatowania logów za pomocą Rich."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )


def print_banner() -> None:
    """Wyświetla nagłówek powitalny JASS."""
    banner = """[bold cyan]
     ██╗ █████╗ ███████╗███████╗
     ██║██╔══██╗██╔════╝██╔════╝
     ██║███████║███████╗███████╗
██   ██║██╔══██║╚════██║╚════██║
╚█████╔╝██║  ██║███████║███████║
 ╚════╝ ╚═╝  ╚═╝╚══════╝╚══════╝[/bold cyan]
[bold white]JASS - Just Another System Sniffer[/bold white] [dim]v1.0.0[/dim]
[italic green]Windows Server & Hyper-V Telemetry Sniffer for LLM Analysis[/italic green]
"""
    console.print(banner)


def display_host_summary(payload: HostAnalysisPayload) -> None:
    """Wyświetla estetyczne podsumowanie zebranych danych w konsoli."""
    # Tabela Główna
    grid = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta", title=f"🎯 Host: {payload.host_name} ({payload.visible_name})")
    grid.add_column("Kategoria", style="cyan", width=22)
    grid.add_column("Szczegóły / Wartości", style="white")

    # Inwentarz
    grid.add_row("Status monitorowania", f"[green]{payload.status}[/green]" if payload.status == "Monitored" else f"[red]{payload.status}[/red]")
    grid.add_row("System Operacyjny (OS)", f"{payload.inventory.os or 'Nieznany'} ({payload.inventory.os_full or ''})")
    grid.add_row("Grupy Zabbix", ", ".join(payload.host_groups) if payload.host_groups else "-")
    grid.add_row("Adresy IP", ", ".join(payload.inventory.ip_addresses) if payload.inventory.ip_addresses else "-")
    grid.add_row("Sprzęt / Wirtualizacja", f"{payload.inventory.hardware or payload.inventory.vendor or 'N/A'}")

    # Metryki
    cpu_str = f"{payload.metrics.cpu_utilization_percent}%" if payload.metrics.cpu_utilization_percent is not None else "N/A"
    if payload.metrics.cpu_cores:
        cpu_str += f" ({payload.metrics.cpu_cores} cores)"
    grid.add_row("CPU Utilization", cpu_str)

    ram_str = f"{payload.metrics.memory_used_formatted or '?'} / {payload.metrics.memory_total_formatted or '?'}"
    if payload.metrics.memory_utilization_percent is not None:
        ram_str += f" ({payload.metrics.memory_utilization_percent}%)"
    grid.add_row("RAM (Used / Total)", ram_str)

    grid.add_row("Uptime systemu", payload.metrics.uptime_formatted or "N/A")

    # Dyski
    drives_info = []
    for d in payload.metrics.drives:
        d_str = f"{d.fs_name} [{d.used_formatted or '?'}/{d.total_formatted or '?'}] ({d.used_percent or '?'}% zajęte)"
        drives_info.append(d_str)
    grid.add_row("Dyski / Wolumeny", "\n".join(drives_info) if drives_info else "Brak danych o dyskach")

    # Usługi
    running_svc = [s.name for s in payload.windows_services if s.state == "Running"]
    grid.add_row("Aktywne usługi Windows", f"{len(running_svc)} usług (np. {', '.join(running_svc[:5])}...)" if running_svc else "Brak")

    # Hyper-V
    if payload.hyperv.is_hyperv_host:
        vms = [f"{v.vm_name} ({v.state})" for v in payload.hyperv.guest_vms]
        grid.add_row("[bold yellow]Rola Hyper-V[/bold yellow]", f"[yellow]Wykryto hypervisor[/yellow] | Maszyny ({len(vms)}): {', '.join(vms[:6])}")

    # Wykryte sygnatury ról
    detected = payload.llm_context_hints.get("detected_signatures", [])
    if detected:
        grid.add_row("[bold green]Wykryte role/sygnatury[/bold green]", "\n".join([f"• [bold]{r}[/bold]" for r in detected]))

    # Remote Execution
    if payload.remote_execution:
        r_status = "[green]Sukces[/green]" if payload.remote_execution.success else f"[red]Błąd: {payload.remote_execution.error_message}[/red]"
        grid.add_row("Zdalna sonda (script.execute)", f"{payload.remote_execution.script_name} -> {r_status}")

    console.print(grid)


def build_parser() -> argparse.ArgumentParser:
    """Konstrukcja parsera argumentów CLI."""
    parser = argparse.ArgumentParser(
        prog="jass",
        description="JASS - Just Another System Sniffer: Narzędzie telemetryczne dla Windows/Hyper-V i Zabbix API pod kątem analizy LLM.",
    )

    # Grupa: Autentykacja i połączenie
    conn_group = parser.add_argument_group("Opcje połączenia z Zabbix API")
    conn_group.add_argument("--url", default=os.getenv("ZABBIX_URL"), help="Adres URL instancji Zabbix (np. http://zabbix.local lub env ZABBIX_URL)")
    conn_group.add_argument("--token", default=os.getenv("ZABBIX_API_TOKEN") or os.getenv("ZABBIX_TOKEN"), help="API Token Zabbix (zalecany, env ZABBIX_API_TOKEN)")
    conn_group.add_argument("--user", default=os.getenv("ZABBIX_USER") or os.getenv("ZABBIX_USERNAME"), help="Użytkownik Zabbix (fallback login, env ZABBIX_USER)")
    conn_group.add_argument("--password", default=os.getenv("ZABBIX_PASSWORD"), help="Hasło użytkownika Zabbix (fallback login, env ZABBIX_PASSWORD)")
    conn_group.add_argument("--insecure", action="store_true", help="Wyłącz weryfikację certyfikatów SSL")
    conn_group.add_argument("--timeout", type=int, default=15, help="Limit czasu zapytań w sekundach (domyślnie: 15)")

    # Grupa: Zakres zbierania
    target_group = parser.add_argument_group("Wybór celu badania (Target)")
    target_group.add_argument("-H", "--host", help="Nazwa hosta (lub widoczna nazwa / hostid) do zbadania")
    target_group.add_argument("-G", "--hostgroup", help="Nazwa grupy hostów (lub groupid) do zbadania")
    target_group.add_argument("--list-hosts", action="store_true", help="Wypisz listę dostępnych hostów w Zabbixie")
    target_group.add_argument("--list-groups", action="store_true", help="Wypisz listę grup hostów w Zabbixie")

    # Grupa: Opcje zaawansowane & Output
    exec_group = parser.add_argument_group("Wykonanie sond i zapis wyników")
    exec_group.add_argument("-o", "--output-dir", default=".", help="Katalog zapisu pliku [nazwa_hosta]_analysis.json (domyślnie: bieżący katalog)")
    exec_group.add_argument("--remote-probe", action="store_true", help="Uruchom zdalną sondę PowerShell/script.execute na agencie Zabbix")
    exec_group.add_argument("--script", help="Nazwa konkretnego skryptu Zabbix do wykonania podczas zdalnej sondy")
    exec_group.add_argument("--prompt", action="store_true", help="Zapisz także gotowy plik promptu dla LLM ([nazwa_hosta]_prompt.md)")
    exec_group.add_argument("--print-prompt", action="store_true", help="Wypisz wygenerowany prompt LLM bezpośrednio w konsoli")

    # Grupa: Web UI
    ui_group = parser.add_argument_group("Interfejs Graficzny (Web GUI)")
    ui_group.add_argument("--serve", "--ui", action="store_true", help="Uruchom interfejs graficzny Web Dashboard")
    ui_group.add_argument("--host-bind", default="127.0.0.1", help="Adres IP dla serwera Web UI (domyślnie: 127.0.0.1)")
    ui_group.add_argument("--port", type=int, default=8080, help="Port serwera Web UI (domyślnie: 8080)")

    parser.add_argument("-v", "--verbose", action="store_true", help="Włącz szczegółowe logowanie diagnostyczne (DEBUG)")

    return parser


def run_cli(args: Optional[List[str]] = None) -> int:
    """Główna funkcja wykonawcza CLI."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    setup_logging(verbose=parsed_args.verbose)
    print_banner()

    # Obsługa trybu Web UI
    if parsed_args.serve:
        from jass.ui.app import start_ui_server
        console.print(f"[bold green]Uruchamianie JASS Web Dashboard na http://{parsed_args.host_bind}:{parsed_args.port}...[/bold green]")
        start_ui_server(
            host=parsed_args.host_bind,
            port=parsed_args.port,
            default_url=parsed_args.url,
            default_token=parsed_args.token,
            default_user=parsed_args.user,
            default_password=parsed_args.password,
            verify_ssl=not parsed_args.insecure,
        )
        return 0

    # Sprawdzenie parametrów połączenia
    if not parsed_args.url:
        console.print("[bold red]Błąd:[/bold red] Nie podano adresu URL Zabbixa. Użyj parametru [yellow]--url[/yellow] lub ustaw zmienną środowiskową [yellow]ZABBIX_URL[/yellow].")
        return 1

    if not parsed_args.token and not (parsed_args.user and parsed_args.password):
        console.print("[bold red]Błąd:[/bold red] Wymagany jest API Token ([yellow]--token[/yellow]) lub para login/hasło ([yellow]--user[/yellow] i [yellow]--password[/yellow]).")
        return 1

    try:
        with ZabbixAnalyzer(
            url=parsed_args.url,
            api_token=parsed_args.token,
            username=parsed_args.user,
            password=parsed_args.password,
            timeout=parsed_args.timeout,
            verify_ssl=not parsed_args.insecure,
        ) as analyzer:
            
            # 1. Wypisanie grup
            if parsed_args.list_groups:
                groups = analyzer.list_hostgroups()
                table = Table(title="Dostępne grupy hostów Zabbix", box=box.SIMPLE_HEAVY)
                table.add_column("ID", style="cyan")
                table.add_column("Nazwa grupy", style="green")
                for g in groups:
                    table.add_row(g["groupid"], g["name"])
                console.print(table)
                return 0

            # 2. Wypisanie hostów
            if parsed_args.list_hosts:
                hosts = analyzer.list_hosts()
                table = Table(title="Dostępne hosty Zabbix", box=box.SIMPLE_HEAVY)
                table.add_column("HostID", style="cyan")
                table.add_column("Nazwa techniczna (Host)", style="bold white")
                table.add_column("Widoczna nazwa", style="yellow")
                table.add_column("IP", style="green")
                table.add_column("Status", style="magenta")
                for h in hosts:
                    ips = [i["ip"] for i in h.get("interfaces", []) if i.get("ip")]
                    status_str = "Monitored" if str(h.get("status")) == "0" else "Unmonitored"
                    table.add_row(h["hostid"], h["host"], h.get("name", ""), ", ".join(ips), status_str)
                console.print(table)
                return 0

            # 3. Badanie pojedynczego hosta
            if parsed_args.host:
                with console.status(f"[bold yellow]Sniffing hosta '{parsed_args.host}'...[/bold yellow]", spinner="dots"):
                    payload = analyzer.analyze_host(
                        host_identifier=parsed_args.host,
                        run_remote_probe=parsed_args.remote_probe,
                        script_name=parsed_args.script,
                    )

                display_host_summary(payload)
                saved_path = analyzer.save_analysis_json(payload, output_dir=parsed_args.output_dir)
                console.print(f"\n[bold green]✔ Zapisano plik analizy JSON:[/bold green] [cyan]{saved_path}[/cyan]")

                if parsed_args.prompt:
                    prompt_text = analyzer.generate_llm_prompt(payload)
                    prompt_file = Path(parsed_args.output_dir) / f"{payload.host_name}_prompt.md"
                    prompt_file.write_text(prompt_text, encoding="utf-8")
                    console.print(f"[bold green]✔ Zapisano plik promptu dla LLM:[/bold green] [cyan]{prompt_file.resolve()}[/cyan]")

                if parsed_args.print_prompt:
                    console.print(Panel(analyzer.generate_llm_prompt(payload), title="Wygenerowany Prompt dla LLM", border_style="green"))

                return 0

            # 4. Badanie grupy hostów
            if parsed_args.hostgroup:
                with console.status(f"[bold yellow]Sniffing grupy hostów '{parsed_args.hostgroup}'...[/bold yellow]", spinner="dots"):
                    payloads = analyzer.analyze_hostgroup(
                        group_identifier=parsed_args.hostgroup,
                        run_remote_probe=parsed_args.remote_probe,
                        script_name=parsed_args.script,
                    )

                console.print(f"\n[bold green]Zakończono badanie {len(payloads)} hostów z grupy '{parsed_args.hostgroup}'.[/bold green]\n")
                for p in payloads:
                    display_host_summary(p)

                saved_files = analyzer.save_group_analysis_json(payloads, output_dir=parsed_args.output_dir)
                console.print(f"[bold green]✔ Zapisano {len(saved_files)} plików analizy w katalogu:[/bold green] [cyan]{Path(parsed_args.output_dir).resolve()}[/cyan]")
                return 0

            # Brak określonego celu
            console.print("[bold yellow]Uwaga:[/bold yellow] Nie wskazano celu. Użyj [cyan]--host <nazwa>[/cyan] lub [cyan]--hostgroup <grupa>[/cyan] lub [cyan]--serve[/cyan] dla Web UI.")
            console.print("Użyj [cyan]jass --help[/cyan], aby zobaczyć pełną listę opcji.")
            return 1

    except ZabbixAuthException as auth_err:
        console.print(f"[bold red]Błąd uwierzytelnienia w Zabbix:[/bold red] {auth_err}")
        return 2
    except ZabbixAPIException as api_err:
        console.print(f"[bold red]Błąd Zabbix API:[/bold red] {api_err}")
        return 3
    except Exception as exc:
        console.print(f"[bold red]Nieoczekiwany błąd:[/bold red] {exc}")
        if parsed_args.verbose:
            console.print_exception()
        return 4


if __name__ == "__main__":
    sys.exit(run_cli())
