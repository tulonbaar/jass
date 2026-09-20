"""
JASS - Just Another System Sniffer
Command Line Interface (CLI)
"""

from __future__ import annotations

import argparse
import logging
import os
from jass.core.settings import get_setting
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
    """Configure Rich logging handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )


def print_banner() -> None:
    """Displays the JASS welcome banner."""
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
    """Renders an aesthetic summary table of collected telemetry in console."""
    grid = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta", title=f"🎯 Host: {payload.host_name} ({payload.visible_name})")
    grid.add_column("Category", style="cyan", width=24)
    grid.add_column("Details / Values", style="white")

    # Inventory
    status_style = "[green]Monitored[/green]" if payload.status == "Monitored" else "[red]Unmonitored[/red]"
    grid.add_row("Monitoring Status", status_style)
    grid.add_row("Operating System (OS)", f"{payload.inventory.os or 'Unknown'} ({payload.inventory.os_full or ''})")
    grid.add_row("Zabbix Host Groups", ", ".join(payload.host_groups) if payload.host_groups else "-")
    grid.add_row("IP Addresses", ", ".join(payload.inventory.ip_addresses) if payload.inventory.ip_addresses else "-")
    grid.add_row("Hardware / Platform", f"{payload.inventory.hardware or payload.inventory.vendor or 'N/A'}")

    # Metrics
    cpu_str = f"{payload.metrics.cpu_utilization_percent}%" if payload.metrics.cpu_utilization_percent is not None else "N/A"
    if payload.metrics.cpu_cores:
        cpu_str += f" ({payload.metrics.cpu_cores} cores)"
    grid.add_row("CPU Utilization", cpu_str)

    ram_str = f"{payload.metrics.memory_used_formatted or '?'} / {payload.metrics.memory_total_formatted or '?'}"
    if payload.metrics.memory_utilization_percent is not None:
        ram_str += f" ({payload.metrics.memory_utilization_percent}%)"
    grid.add_row("RAM (Used / Total)", ram_str)

    grid.add_row("System Uptime", payload.metrics.uptime_formatted or "N/A")

    # Disks
    drives_info = []
    for d in payload.metrics.drives:
        d_str = f"{d.fs_name} [{d.used_formatted or '?'}/{d.total_formatted or '?'}] ({d.used_percent or '?'}% used)"
        drives_info.append(d_str)
    grid.add_row("Disks / Volumes", "\n".join(drives_info) if drives_info else "No drive data")

    # Services
    running_svc = [s.name for s in payload.windows_services if s.state == "Running"]
    grid.add_row("Active Windows Services", f"{len(running_svc)} running (e.g. {', '.join(running_svc[:5])}...)" if running_svc else "None")

    # Hyper-V
    if payload.hyperv.is_hyperv_host:
        vms = [f"{v.vm_name} ({v.state})" for v in payload.hyperv.guest_vms]
        grid.add_row("[bold yellow]Hyper-V Role[/bold yellow]", f"[yellow]Hypervisor active[/yellow] | VMs ({len(vms)}): {', '.join(vms[:6])}")

    # Detected role signatures
    detected = payload.llm_context_hints.get("detected_signatures", [])
    if detected:
        grid.add_row("[bold green]Detected Roles / Signatures[/bold green]", "\n".join([f"• [bold]{r}[/bold]" for r in detected]))

    # Remote Execution
    if payload.remote_execution:
        r_status = "[green]Success[/green]" if payload.remote_execution.success else f"[red]Error: {payload.remote_execution.error_message}[/red]"
        grid.add_row("Remote Probe (script.execute)", f"{payload.remote_execution.script_name} -> {r_status}")

    console.print(grid)


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="jass",
        description="JASS - Just Another System Sniffer: Telemetry extractor for Windows/Hyper-V and Zabbix API tailored for LLM analysis.",
    )

    # Connection Group
    conn_group = parser.add_argument_group("Zabbix API Connection Options")
    conn_group.add_argument("--url", default=get_setting("ZABBIX_URL"), help="Zabbix URL (e.g. http://zabbix.local or env ZABBIX_URL)")
    conn_group.add_argument("--token", default=get_setting("ZABBIX_API_TOKEN") or os.getenv("ZABBIX_TOKEN"), help="Zabbix API Token (recommended, env ZABBIX_API_TOKEN)")
    conn_group.add_argument("--user", default=get_setting("ZABBIX_USER") or os.getenv("ZABBIX_USERNAME"), help="Zabbix Username (fallback login, env ZABBIX_USER)")
    conn_group.add_argument("--password", default=get_setting("ZABBIX_PASSWORD"), help="Zabbix Password (fallback login, env ZABBIX_PASSWORD)")
    conn_group.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")
    conn_group.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")

    # Target Group
    target_group = parser.add_argument_group("Target Selection")
    target_group.add_argument("-H", "--host", help="Host name (or visible name / hostid) to inspect")
    target_group.add_argument("-G", "--hostgroup", help="Host group name (or groupid) to inspect")
    target_group.add_argument("--list-hosts", action="store_true", help="List all available hosts in Zabbix")
    target_group.add_argument("--list-groups", action="store_true", help="List all available host groups in Zabbix")

    # Execution & Output Group
    exec_group = parser.add_argument_group("Probe Execution & Output")
    exec_group.add_argument("-o", "--output-dir", default=".", help="Output directory for [host_name]_analysis.json (default: current directory)")
    exec_group.add_argument("--remote-probe", action="store_true", help="Execute remote probe (PowerShell / script.execute) on Zabbix agent")
    exec_group.add_argument("--script", help="Specific Zabbix script name to execute during remote probe")
    exec_group.add_argument(
        "--probe",
        help="Built-in probe to run (runs ProberTask from DB). Takes precedence over --script.",
    )
    exec_group.add_argument("--list-probes", action="store_true", help="List built-in probes from the JASS probe catalog and exit")
    exec_group.add_argument("--prompt", action="store_true", help="Also generate LLM prompt markdown file ([host_name]_prompt.md)")
    exec_group.add_argument("--print-prompt", action="store_true", help="Print generated LLM prompt directly to console")

    # Web UI Group
    ui_group = parser.add_argument_group("Web Dashboard (GUI)")
    ui_group.add_argument("--serve", "--ui", action="store_true", help="Launch Web Dashboard interface")
    ui_group.add_argument("--host-bind", default="127.0.0.1", help="Host address to bind Web UI (default: 127.0.0.1)")
    ui_group.add_argument("--port", type=int, default=8080, help="Port for Web UI server (default: 8080)")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose diagnostic logging (DEBUG)")

    return parser


def run_cli(args: Optional[List[str]] = None) -> int:
    """Main CLI execution handler."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    setup_logging(verbose=parsed_args.verbose)
    print_banner()

    if parsed_args.list_probes:
        from jass.db.database import SessionLocal
        from jass.db.models import ProberTask
        db = SessionLocal()
        try:
            tasks = db.query(ProberTask).all()
            table = Table(title="JASS Built-in Prober Tasks", box=box.SIMPLE_HEAVY)
            table.add_column("Task Name", style="cyan")
            table.add_column("Description", style="white")
            for t in sorted(tasks, key=lambda x: x.name):
                table.add_row(t.name, t.description or "")
            console.print(table)
            console.print("\nRun with [cyan]--remote-probe --probe <name>[/cyan] to execute one against a host.")
        finally:
            db.close()
        return 0

    # Web UI mode
    if parsed_args.serve:
        from jass.ui.app import start_ui_server
        console.print(f"[bold green]Starting JASS Web Dashboard on http://{parsed_args.host_bind}:{parsed_args.port}...[/bold green]")
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

    # Connection parameters validation
    if not parsed_args.url:
        console.print("[bold red]Error:[/bold red] Missing Zabbix URL. Provide [yellow]--url[/yellow] or set [yellow]ZABBIX_URL[/yellow] environment variable.")
        return 1

    if not parsed_args.token and not (parsed_args.user and parsed_args.password):
        console.print("[bold red]Error:[/bold red] Missing authentication. Provide API Token ([yellow]--token[/yellow]) or credentials ([yellow]--user[/yellow] & [yellow]--password[/yellow]).")
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
            
            # 1. List groups
            if parsed_args.list_groups:
                groups = analyzer.list_hostgroups()
                table = Table(title="Available Zabbix Host Groups", box=box.SIMPLE_HEAVY)
                table.add_column("ID", style="cyan")
                table.add_column("Group Name", style="green")
                for g in groups:
                    table.add_row(g["groupid"], g["name"])
                console.print(table)
                return 0

            # 2. List hosts
            if parsed_args.list_hosts:
                hosts = analyzer.list_hosts()
                table = Table(title="Available Zabbix Hosts", box=box.SIMPLE_HEAVY)
                table.add_column("HostID", style="cyan")
                table.add_column("Technical Host Name", style="bold white")
                table.add_column("Visible Name", style="yellow")
                table.add_column("IP Address", style="green")
                table.add_column("Status", style="magenta")
                for h in hosts:
                    ips = [i["ip"] for i in h.get("interfaces", []) if i.get("ip")]
                    status_str = "Monitored" if str(h.get("status")) == "0" else "Unmonitored"
                    table.add_row(h["hostid"], h["host"], h.get("name", ""), ", ".join(ips), status_str)
                console.print(table)
                return 0

            # 3. Analyze single host
            if parsed_args.host:
                with console.status(f"[bold yellow]Sniffing host '{parsed_args.host}'...[/bold yellow]", spinner="dots"):
                    payload = analyzer.analyze_host(
                        host_identifier=parsed_args.host,
                        run_remote_probe=parsed_args.remote_probe,
                        script_name=parsed_args.script,
                        probe_key=parsed_args.probe,
                    )

                display_host_summary(payload)
                saved_path = analyzer.save_analysis_json(payload, output_dir=parsed_args.output_dir)
                console.print(f"\n[bold green]✔ Saved analysis JSON:[/bold green] [cyan]{saved_path}[/cyan]")

                if parsed_args.prompt:
                    prompt_text = analyzer.generate_llm_prompt(payload)
                    prompt_file = Path(parsed_args.output_dir) / f"{payload.host_name}_prompt.md"
                    prompt_file.write_text(prompt_text, encoding="utf-8")
                    console.print(f"[bold green]✔ Saved LLM prompt:[/bold green] [cyan]{prompt_file.resolve()}[/cyan]")

                if parsed_args.print_prompt:
                    console.print(Panel(analyzer.generate_llm_prompt(payload), title="Generated Prompt for LLM", border_style="green"))

                return 0

            # 4. Analyze host group
            if parsed_args.hostgroup:
                with console.status(f"[bold yellow]Sniffing host group '{parsed_args.hostgroup}'...[/bold yellow]", spinner="dots"):
                    payloads = analyzer.analyze_hostgroup(
                        group_identifier=parsed_args.hostgroup,
                        run_remote_probe=parsed_args.remote_probe,
                        script_name=parsed_args.script,
                        probe_key=parsed_args.probe,
                    )

                console.print(f"\n[bold green]Completed inspection for {len(payloads)} hosts in group '{parsed_args.hostgroup}'.[/bold green]\n")
                for p in payloads:
                    display_host_summary(p)

                saved_files = analyzer.save_group_analysis_json(payloads, output_dir=parsed_args.output_dir)
                console.print(f"[bold green]✔ Saved {len(saved_files)} analysis files in:[/bold green] [cyan]{Path(parsed_args.output_dir).resolve()}[/cyan]")
                return 0

            # No target specified
            console.print("[bold yellow]Notice:[/bold yellow] No target specified. Use [cyan]--host <name>[/cyan], [cyan]--hostgroup <group>[/cyan], or [cyan]--serve[/cyan] for Web UI.")
            console.print("Run [cyan]jass --help[/cyan] for full command line reference.")
            return 1

    except ZabbixAuthException as auth_err:
        console.print(f"[bold red]Zabbix Authentication Error:[/bold red] {auth_err}")
        return 2
    except ZabbixAPIException as api_err:
        console.print(f"[bold red]Zabbix API Error:[/bold red] {api_err}")
        return 3
    except Exception as exc:
        console.print(f"[bold red]Unexpected Error:[/bold red] {exc}")
        if parsed_args.verbose:
            console.print_exception()
        return 4


if __name__ == "__main__":
    sys.exit(run_cli())
