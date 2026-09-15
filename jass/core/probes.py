"""
JASS - Just Another System Sniffer
Probe catalog: named, ready-to-run PowerShell diagnostics that JASS knows how to
provision into Zabbix (via `script.create`) and how to parse (via `script.execute`).

Design rationale
-----------------
Zabbix's `script.execute` API can only run scripts that already exist as Zabbix
"Script" objects (Data collection -> Scripts, scope "Manual host action"). JASS
cannot send arbitrary ad-hoc code straight to an agent - that is a Zabbix/agent
security boundary, not a JASS limitation.

To keep script *deployment* centralized in Zabbix (reusing its existing agent
connectivity/permissions/audit trail) while keeping *parsing and analysis logic*
inside JASS (so new telemetry can be added without touching Zabbix templates),
JASS ships a catalog of well-known probes below. Each entry defines:

- the PowerShell one-liner to run on the Windows agent,
- the exact name JASS will look for / create in Zabbix, and
- a parser turning the raw ``script.execute`` output into structured data.

`WindowsSniffer.execute_remote_probe()` will auto-create the corresponding
Zabbix script (via `script.create`) the first time a given probe is used on an
instance, if a script with that name does not already exist. Administrators are
free to edit the auto-created script's command later directly in Zabbix - JASS
matches by name, not by content.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

# Common PowerShell preamble: suppress progress bars (they otherwise pollute
# stdout captured by the Zabbix agent) and force compact/deep JSON output.
_PS_PREAMBLE = "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='SilentlyContinue';"


def _extract_json_fragment(text: str) -> Optional[str]:
    """Extracts the first top-level JSON object/array from noisy script output."""
    text = text.strip()
    if not text:
        return None
    start_candidates = [i for i in (text.find("{"), text.find("[")) if i != -1]
    if not start_candidates:
        return None
    start = min(start_candidates)
    end_obj, end_arr = text.rfind("}"), text.rfind("]")
    end = max(end_obj, end_arr)
    if end == -1 or end < start:
        return None
    return text[start : end + 1]


def _safe_json_loads(text: str) -> Any:
    """Best-effort JSON parsing that tolerates leading/trailing PowerShell noise."""
    fragment = _extract_json_fragment(text)
    if fragment is None:
        return None
    try:
        return json.loads(fragment)
    except (json.JSONDecodeError, ValueError):
        return None


def parse_listening_ports(output: str) -> Any:
    """Parses `Get-NetTCPConnection`/netstat-style output into a list of listeners."""
    parsed = _safe_json_loads(output)
    if parsed is not None:
        rows = parsed if isinstance(parsed, list) else [parsed]
        return [
            {
                "address": row.get("LocalAddress"),
                "port": row.get("LocalPort"),
                "owning_pid": row.get("OwningProcess"),
            }
            for row in rows
            if isinstance(row, dict)
        ]

    # Fallback: plain-text netstat/table output.
    ports = []
    for line in output.strip().splitlines():
        match = re.search(r"(?:TCP|UDP)?\s*([0-9.\*]+|\[::\]|::):(\d+)", line.strip(), re.IGNORECASE)
        if match:
            ports.append({"address": match.group(1), "port": int(match.group(2)), "raw_entry": line.strip()})
    return ports


def parse_hardware_inventory(output: str) -> Any:
    """Parses BIOS serial number / manufacturer / model / MAC addresses payload."""
    parsed = _safe_json_loads(output)
    if not isinstance(parsed, dict):
        return {"raw": output.strip()}
    macs = parsed.get("MacAddresses") or []
    if isinstance(macs, str):
        macs = [macs]
    return {
        "serial_number": parsed.get("SerialNumber"),
        "manufacturer": parsed.get("Manufacturer"),
        "model": parsed.get("Model"),
        "mac_addresses": [m for m in macs if m],
    }


def parse_installed_applications(output: str) -> Any:
    """Parses installed application inventory (Uninstall registry keys)."""
    parsed = _safe_json_loads(output)
    if parsed is None:
        return []
    rows = parsed if isinstance(parsed, list) else [parsed]
    return [
        {
            "name": row.get("DisplayName"),
            "version": row.get("DisplayVersion"),
            "publisher": row.get("Publisher"),
            "install_date": row.get("InstallDate"),
        }
        for row in rows
        if isinstance(row, dict) and row.get("DisplayName")
    ]


def parse_event_log_errors(output: str) -> Any:
    """Parses recent Windows Event Log warning/error entries."""
    parsed = _safe_json_loads(output)
    if parsed is None:
        return []
    rows = parsed if isinstance(parsed, list) else [parsed]
    return [
        {
            "time": row.get("TimeCreated"),
            "log_name": row.get("LogName"),
            "event_id": row.get("Id"),
            "level": row.get("LevelDisplayName"),
            "source": row.get("ProviderName"),
            "message": (row.get("Message") or "")[:500],
        }
        for row in rows
        if isinstance(row, dict)
    ]


def parse_disk_content_scan(output: str) -> Any:
    """Parses top-level folder listing per drive, flagging non-standard folders."""
    parsed = _safe_json_loads(output)
    if parsed is None:
        return []
    rows = parsed if isinstance(parsed, list) else [parsed]
    folders = [
        {
            "drive": row.get("Drive"),
            "folder": row.get("Folder"),
            "is_standard": bool(row.get("Standard")),
        }
        for row in rows
        if isinstance(row, dict) and row.get("Folder")
    ]
    non_standard = [f for f in folders if not f["is_standard"]]
    return {"all_folders": folders, "non_standard_folders": non_standard}


@dataclass(frozen=True)
class ProbeDefinition:
    """A named, reusable remote diagnostic probe."""

    key: str
    zabbix_script_name: str
    description: str
    command: str
    parser: Callable[[str], Any]


# Registry of built-in probes. Extend this dict to add new diagnostic
# capabilities without touching WindowsSniffer's execution logic.
PROBE_CATALOG: dict[str, ProbeDefinition] = {
    "listening_ports": ProbeDefinition(
        key="listening_ports",
        zabbix_script_name="JASS - Listening TCP Ports",
        description="Lists TCP ports in LISTEN state and the owning process id.",
        command=(
            f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "{_PS_PREAMBLE} '
            "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess "
            '| ConvertTo-Json -Compress"'
        ),
        parser=parse_listening_ports,
    ),
    "hardware_inventory": ProbeDefinition(
        key="hardware_inventory",
        zabbix_script_name="JASS - Hardware Inventory (Serial/MAC)",
        description="Retrieves BIOS serial number, manufacturer/model and MAC addresses via WMI/CIM.",
        command=(
            f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "{_PS_PREAMBLE} '
            "$bios = Get-CimInstance Win32_BIOS; $cs = Get-CimInstance Win32_ComputerSystem; "
            "$nics = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True'; "
            "[PSCustomObject]@{SerialNumber=$bios.SerialNumber;Manufacturer=$cs.Manufacturer;Model=$cs.Model;"
            'MacAddresses=@($nics | ForEach-Object { $_.MACAddress })} | ConvertTo-Json -Compress"'
        ),
        parser=parse_hardware_inventory,
    ),
    "installed_applications": ProbeDefinition(
        key="installed_applications",
        zabbix_script_name="JASS - Installed Applications",
        description="Enumerates installed applications from the Windows Uninstall registry keys.",
        command=(
            f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "{_PS_PREAMBLE} '
            "$paths = 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; "
            "Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | "
            "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Sort-Object DisplayName "
            '| ConvertTo-Json -Compress"'
        ),
        parser=parse_installed_applications,
    ),
    "event_log_errors": ProbeDefinition(
        key="event_log_errors",
        zabbix_script_name="JASS - Event Log Errors (24h)",
        description="Collects Warning/Error entries from System and Application logs from the last 24 hours.",
        command=(
            f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "{_PS_PREAMBLE} '
            "Get-WinEvent -FilterHashtable @{LogName='System','Application';Level=1,2;"
            "StartTime=(Get-Date).AddHours(-24)} -MaxEvents 50 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated,LogName,Id,LevelDisplayName,ProviderName,Message "
            '| ConvertTo-Json -Compress -Depth 3"'
        ),
        parser=parse_event_log_errors,
    ),
    "disk_content_scan": ProbeDefinition(
        key="disk_content_scan",
        zabbix_script_name="JASS - Disk Content Scan",
        description="Lists top-level folders on every fixed drive and flags non-standard (non-OS) folders.",
        command=(
            f'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "{_PS_PREAMBLE} '
            "$known = 'Windows','Program Files','Program Files (x86)','Users','ProgramData',"
            "'$Recycle.Bin','System Volume Information','PerfLogs'; "
            "Get-PSDrive -PSProvider FileSystem | ForEach-Object { $d = $_.Root; "
            "Get-ChildItem -Path $d -Directory -ErrorAction SilentlyContinue | ForEach-Object { "
            "[PSCustomObject]@{Drive=$d;Folder=$_.Name;Standard=($known -contains $_.Name)} } } "
            '| ConvertTo-Json -Compress"'
        ),
        parser=parse_disk_content_scan,
    ),
}


def get_probe(key: str) -> Optional[ProbeDefinition]:
    """Looks up a probe definition by its catalog key (case-insensitive)."""
    return PROBE_CATALOG.get(key.lower())


def list_probe_keys() -> list[str]:
    """Returns all available probe catalog keys."""
    return sorted(PROBE_CATALOG.keys())
